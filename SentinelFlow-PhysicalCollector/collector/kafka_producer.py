"""
kafka_producer.py
Thin wrapper around kafka-python's KafkaProducer, publishing canonical
SentinelFlow events to the EXISTING raw event topic using the EXISTING
wire format: a plain JSON string, keyed by eventId - compatible with the
Spring Boot side's StringSerializer/StringDeserializer as-is. No new
topic, no new serialization, no schema registry.

ONE producer, for the whole collector's lifetime. It is created once in
CollectorApp and owned by the single publisher worker thread - never one
producer per event, per worker, or per retry (kafka-python's producer is
itself a connection pool plus a background I/O thread; creating them per
event would leak both).

Broker outages: a failed event is kept in a small in-memory pending
buffer and re-sent, in order, once the broker is back (retry_pending()).
Re-sending is safe: the event keeps its original eventId and the backend
ledger is idempotent on eventId. While the broker is down, publishing
backs off instead of blocking the caller on every event - kafka-python
otherwise blocks up to 60s per send with no reachable broker.

Collector 2.0 changes:
  - The CENTRAL bounded queue (event_queue.py) is now the real outage
    buffer. The publisher worker stops draining it while this class is
    backing off (see is_backing_off/seconds_until_retry), so this
    pending buffer normally holds 0-1 events - just whatever was in
    flight when a send failed. Its bound remains as a second safety net.
  - Backoff bounds are configurable (retry_base_delay/retry_max_delay).
    The defaults are unchanged from 1.x (5s doubling to 60s) because
    they are this project's existing convention and its tests encode
    them; config.py exposes both ends.
  - Optional HealthRegistry reporting, so Kafka state, consecutive
    failures and retry counts show up in the heartbeat and in health
    snapshots.
  - producer_factory injection for tests/stress runs. Defaults to the
    real KafkaProducer.

Logging: operational metadata only (eventId/eventType/entityId/partition/
offset) - never the payload body, which for NETWORK_CONNECTION contains
real remote IP addresses.
"""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, Optional

from kafka import KafkaProducer
from kafka.errors import KafkaError

logger = logging.getLogger("sentinelflow.collector.kafka_producer")

# Bounds memory during a long outage; the oldest unsent event is dropped first.
MAX_PENDING_EVENTS = 1000

# Longest a single send may block waiting for broker metadata
# (kafka-python's own default is 60s).
_MAX_BLOCK_MS = 5000

_INITIAL_BACKOFF_SECONDS = 5.0
_MAX_BACKOFF_SECONDS = 60.0

# Longest a single send's acknowledgement is awaited.
_SEND_ACK_TIMEOUT_SECONDS = 10


class EventPublisher:
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        max_pending: int = MAX_PENDING_EVENTS,
        clock: Callable[[], float] = time.monotonic,
        retry_base_delay: float = _INITIAL_BACKOFF_SECONDS,
        retry_max_delay: float = _MAX_BACKOFF_SECONDS,
        health: Optional[Any] = None,
        producer_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._topic = topic
        factory = producer_factory or KafkaProducer
        self._producer = factory(
            bootstrap_servers=bootstrap_servers,
            key_serializer=lambda k: k.encode("utf-8"),
            value_serializer=lambda v: v.encode("utf-8"),
            retries=5,
            linger_ms=50,
            max_block_ms=_MAX_BLOCK_MS,
        )
        self._pending: Deque[Dict[str, Any]] = deque()
        self._max_pending = max_pending
        self._clock = clock
        self._retry_base_delay = retry_base_delay
        self._retry_max_delay = max(retry_max_delay, retry_base_delay)
        self._health = health
        self._backoff_seconds = 0.0
        self._retry_at = 0.0
        self._dropped = 0
        self._closed = False
        logger.info(
            "Kafka producer initialized bootstrap_servers=%s topic=%s",
            bootstrap_servers,
            topic,
        )

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def dropped_count(self) -> int:
        return self._dropped

    def is_backing_off(self) -> bool:
        """True while a previous failure's backoff window is still open.
        The publisher worker uses this to stop draining the central queue
        - that is what makes the central queue, not this buffer, the
        thing that absorbs an outage."""
        return self._backoff_seconds > 0 and self._clock() < self._retry_at

    def seconds_until_retry(self) -> float:
        """How long until the next send attempt is allowed. 0.0 when a
        send may be attempted right now."""
        if self._backoff_seconds <= 0:
            return 0.0
        return max(0.0, self._retry_at - self._clock())

    def publish(self, event: Dict[str, Any]) -> bool:
        """Publish one canonical event, or queue it for retry if the broker
        is unavailable. Never raises for broker errors.

        Returns True if the event was acknowledged by the broker, False if
        it is now queued for retry."""
        json.dumps(event)  # fail fast on an unserializable event, before queueing it
        self._enqueue(event)
        self.retry_pending()
        return not self._pending

    def retry_pending(self) -> None:
        """Send queued events in order until one fails. A no-op while
        backing off after a failure, so it is cheap to call every tick."""
        if not self._pending or self._clock() < self._retry_at:
            return

        recovered_from_outage = self._backoff_seconds > 0
        if recovered_from_outage and self._health is not None:
            self._health.mark_kafka_retry()

        while self._pending:
            event = self._pending[0]
            if not self._send(event):
                self._back_off()
                return
            self._pending.popleft()

        if recovered_from_outage:
            logger.info("Kafka publishing recovered - all queued events sent")
        self._backoff_seconds = 0.0

    def close(self) -> None:
        """Idempotent: a second call (e.g. shutdown racing a failed
        startup) must not raise or double-close the underlying producer."""
        if self._closed:
            return
        self._closed = True

        # One last attempt regardless of backoff, so a broker that has just
        # come back still receives what was queued.
        self._retry_at = 0.0
        self.retry_pending()
        if self._pending or self._dropped:
            logger.warning(
                "Collector stopping with %d event(s) unsent (%d dropped earlier because the queue was full)",
                len(self._pending),
                self._dropped,
            )
        try:
            self._producer.flush(timeout=10)
        except Exception:
            logger.warning("Kafka producer flush failed during shutdown", exc_info=True)
        try:
            self._producer.close(timeout=10)
        except Exception:
            logger.warning("Kafka producer close failed during shutdown", exc_info=True)
        if self._health is not None:
            self._health.mark_kafka_stopped()

    def _enqueue(self, event: Dict[str, Any]) -> None:
        if len(self._pending) >= self._max_pending:
            dropped = self._pending.popleft()
            self._dropped += 1
            logger.warning(
                "Retry queue full (%d events) - dropping oldest unsent event eventId=%s eventType=%s",
                self._max_pending,
                dropped.get("eventId"),
                dropped.get("eventType"),
            )
        self._pending.append(event)

    def _send(self, event: Dict[str, Any]) -> bool:
        event_id = event["eventId"]
        try:
            future = self._producer.send(self._topic, key=event_id, value=json.dumps(event))
            record_metadata = future.get(timeout=_SEND_ACK_TIMEOUT_SECONDS)
        except KafkaError as error:
            logger.warning(
                "Failed to publish event to Kafka eventId=%s eventType=%s error=%s",
                event_id,
                event.get("eventType"),
                error,
            )
            if self._health is not None:
                self._health.mark_publish_failed(error)
            return False
        except Exception as error:  # noqa: BLE001 - a publisher must never die
            # kafka-python can surface non-KafkaError failures (e.g. a
            # socket/DNS error raised from its I/O thread). Treating them
            # as a transient publish failure keeps the agent alive and
            # retrying instead of taking the publisher worker down.
            logger.warning(
                "Unexpected error publishing event eventId=%s eventType=%s error=%s",
                event_id,
                event.get("eventType"),
                error,
            )
            if self._health is not None:
                self._health.mark_publish_failed(error)
            return False

        logger.debug(
            "Event published eventId=%s eventType=%s entityId=%s partition=%s offset=%s",
            event_id,
            event.get("eventType"),
            event.get("entityId"),
            record_metadata.partition,
            record_metadata.offset,
        )
        if self._health is not None:
            self._health.mark_publish_succeeded()
        return True

    def _back_off(self) -> None:
        self._backoff_seconds = min(
            self._retry_max_delay,
            self._backoff_seconds * 2 if self._backoff_seconds else self._retry_base_delay,
        )
        self._retry_at = self._clock() + self._backoff_seconds
        logger.warning(
            "Kafka unavailable - %d event(s) queued here, next retry in %.0fs",
            len(self._pending),
            self._backoff_seconds,
        )
