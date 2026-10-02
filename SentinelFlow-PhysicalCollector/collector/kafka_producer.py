"""
kafka_producer.py
Thin wrapper around kafka-python's KafkaProducer, publishing canonical
SentinelFlow events to the EXISTING raw event topic using the EXISTING
wire format: a plain JSON string, keyed by eventId - compatible with the
Spring Boot side's StringSerializer/StringDeserializer as-is. No new
topic, no new serialization, no schema registry.

Broker outages: the pollers only report each transition once, so an event
that fails to publish is never produced again. Instead of dropping it, a
failed event is kept in a bounded in-memory queue and re-sent, in order,
once the broker is back (retry_pending(), called from the main loop).
Re-sending is safe: the event keeps its original eventId and the backend
ledger is idempotent on eventId. While the broker is down, publishing
backs off instead of blocking the poll loop on every event - kafka-python
otherwise blocks up to 60s per send with no reachable broker.
"""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from typing import Any, Callable, Deque, Dict

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


class EventPublisher:
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        max_pending: int = MAX_PENDING_EVENTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._topic = topic
        self._producer = KafkaProducer(
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
        self._backoff_seconds = 0.0
        self._retry_at = 0.0
        self._dropped = 0
        logger.info(
            "Kafka producer initialized bootstrap_servers=%s topic=%s",
            bootstrap_servers,
            topic,
        )

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def publish(self, event: Dict[str, Any]) -> None:
        """Publish one canonical event, or queue it for retry if the broker
        is unavailable. Never raises for broker errors. Logs operational
        metadata only (eventId/eventType/entityId/partition/offset) - never
        the payload body, so nothing telemetry-shaped ever reaches the logs
        even though this phase's own payload contains no secrets."""
        json.dumps(event)  # fail fast on an unserializable event, before queueing it
        self._enqueue(event)
        self.retry_pending()

    def retry_pending(self) -> None:
        """Send queued events in order until one fails. A no-op while
        backing off after a failure, so it is cheap to call every tick."""
        if not self._pending or self._clock() < self._retry_at:
            return

        recovered_from_outage = self._backoff_seconds > 0
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
        self._producer.flush(timeout=10)
        self._producer.close(timeout=10)

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
            record_metadata = future.get(timeout=10)
        except KafkaError as error:
            logger.warning(
                "Failed to publish event to Kafka eventId=%s eventType=%s error=%s",
                event_id,
                event.get("eventType"),
                error,
            )
            return False

        logger.info(
            "Event published eventId=%s eventType=%s entityId=%s partition=%s offset=%s",
            event_id,
            event.get("eventType"),
            event.get("entityId"),
            record_metadata.partition,
            record_metadata.offset,
        )
        return True

    def _back_off(self) -> None:
        self._backoff_seconds = min(
            _MAX_BACKOFF_SECONDS,
            self._backoff_seconds * 2 if self._backoff_seconds else _INITIAL_BACKOFF_SECONDS,
        )
        self._retry_at = self._clock() + self._backoff_seconds
        logger.warning(
            "Kafka unavailable - %d event(s) queued, next retry in %.0fs",
            len(self._pending),
            self._backoff_seconds,
        )
