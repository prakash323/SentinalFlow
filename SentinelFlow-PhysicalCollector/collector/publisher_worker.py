"""
publisher_worker.py
The single dedicated Kafka publisher worker (PHASES K and L).

                  Bounded Queue
                        |
                        v
                 PublisherWorker            <- exactly one thread
                        |
                  EventPublisher            <- exactly one KafkaProducer
                        |
                  +-----+------+
                  |            |
                 ACK        failure
                  |            |
            drop from      requeue at the
            the queue      FRONT, back off

THE KEY RULE: while the publisher is backing off, it does NOT drain the
queue. That is what makes the central bounded queue - not the producer's
small internal buffer - the thing that absorbs a broker outage, with one
documented overflow policy and one dropped-event counter instead of two
competing buffers silently dropping events at different thresholds.

Backoff itself lives in EventPublisher (unchanged bounded exponential
backoff, base -> doubling -> cap, configurable). This worker does not
implement a second retry mechanism on top: it asks is_backing_off() and
sleeps on the stop event for seconds_until_retry(), so it also wakes
instantly on shutdown instead of sitting in a sleep.

DRAINING AFTER RECOVERY is deliberately paced rather than a burst: the
worker takes at most _DRAIN_BATCH events per iteration and publishes
them one at a time, each awaiting its acknowledgement. A recovered broker
therefore sees a steady stream, not several thousand records at once.

STARTUP WITH NO BROKER: kafka-python raises NoBrokersAvailable from the
KafkaProducer CONSTRUCTOR when nothing answers at the bootstrap address.
An endpoint agent must not refuse to start just because its collection
point is down - it should start collecting and buffer. So the publisher
object can be built lazily here, with the same bounded backoff, while the
telemetry workers are already running and filling the bounded queue.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from event_queue import BoundedEventQueue
from health import HealthRegistry
from kafka_producer import EventPublisher
from logging_utils import RateLimitedLogger

logger = logging.getLogger("sentinelflow.collector.publisher")

PUBLISHER_WORKER = "kafka-publisher"

# How many events are taken from the queue per iteration. Small enough to
# re-check the stop event and the backoff state often; large enough that
# a backlog drains without one lock acquisition per event.
_DRAIN_BATCH = 50

# How long the worker blocks waiting for the queue to produce something.
# Bounds shutdown latency and keeps the health/queue-depth gauge fresh on
# a quiet machine.
_QUEUE_WAIT_SECONDS = 0.5


class PublisherWorker:
    """Consumes the bounded queue and publishes to Kafka. One instance,
    one thread, one producer."""

    def __init__(
        self,
        queue: BoundedEventQueue,
        publisher: Optional[EventPublisher],
        health: HealthRegistry,
        rate_limited_logger: Optional[RateLimitedLogger] = None,
        drain_batch: int = _DRAIN_BATCH,
        queue_wait_seconds: float = _QUEUE_WAIT_SECONDS,
        publisher_factory: Optional[Callable[[], EventPublisher]] = None,
        connect_retry_base_seconds: float = 5.0,
        connect_retry_max_seconds: float = 60.0,
    ) -> None:
        if publisher is None and publisher_factory is None:
            raise ValueError("publisher or publisher_factory is required")
        self.name = PUBLISHER_WORKER
        self._queue = queue
        self._publisher = publisher
        self._publisher_factory = publisher_factory
        self._connect_retry_base = connect_retry_base_seconds
        self._connect_retry_max = max(connect_retry_max_seconds, connect_retry_base_seconds)
        self._health = health
        self._rate_logger = rate_limited_logger or RateLimitedLogger(logger)
        self._drain_batch = drain_batch
        self._queue_wait = queue_wait_seconds
        self._was_backing_off = False
        self._health.register_worker(PUBLISHER_WORKER)

    @property
    def publisher(self) -> Optional[EventPublisher]:
        return self._publisher

    def reset(self) -> None:
        """Supervisor hook. The producer itself is deliberately NOT
        rebuilt on a restart: it is a single long-lived connection pool,
        and recreating it would both leak the old one's I/O thread and
        throw away the events it is still holding."""

    def run(self, stop_event: threading.Event) -> None:
        logger.info("Kafka publisher worker started")
        self._health.mark_worker_running(PUBLISHER_WORKER)

        if not self._ensure_publisher(stop_event):
            return
        self._health.mark_kafka_running()

        try:
            while not stop_event.is_set():
                self._iteration(stop_event)
        finally:
            self._health.mark_worker_stopped(PUBLISHER_WORKER)
            logger.info("Kafka publisher worker stopped")

    def _ensure_publisher(self, stop_event: threading.Event) -> bool:
        """Build the publisher if it does not exist yet, retrying with
        bounded backoff while the broker is unreachable. Returns False
        only if shutdown was requested first."""
        if self._publisher is not None:
            return True

        backoff = 0.0
        while not stop_event.is_set():
            try:
                self._publisher = self._publisher_factory()
                return True
            except Exception as error:  # noqa: BLE001 - must not kill the agent
                self._health.mark_publish_failed(error)
                backoff = min(
                    self._connect_retry_max,
                    backoff * 2 if backoff else self._connect_retry_base,
                )
                self._rate_logger.warning(
                    "kafka-connect-failed",
                    "Cannot connect to Kafka (%s) - telemetry keeps buffering "
                    "(queue depth=%d/%d); retrying in %.0fs",
                    error, self._queue.depth, self._queue.capacity, backoff,
                )
                if stop_event.wait(backoff):
                    return False
        return False

    # -- one pass ----------------------------------------------------------

    def _iteration(self, stop_event: threading.Event) -> None:
        # 1. Anything the producer is still holding from a failed send
        #    goes first, so ordering is preserved.
        if self._publisher.pending_count:
            self._publisher.retry_pending()

        # 2. While backing off, leave the queue alone and sleep exactly
        #    until the next attempt is due (or until shutdown).
        if self._publisher.is_backing_off():
            if not self._was_backing_off:
                self._was_backing_off = True
                self._rate_logger.warning(
                    "kafka-unavailable",
                    "Kafka unavailable - buffering telemetry in the bounded queue "
                    "(depth=%d/%d); publishing retries with backoff",
                    self._queue.depth, self._queue.capacity,
                )
            self._health.record_queue_depth(self._queue.depth)
            stop_event.wait(max(0.05, min(self._publisher.seconds_until_retry(), self._queue_wait)))
            return

        if self._was_backing_off:
            self._was_backing_off = False
            self._rate_logger.reset("kafka-unavailable")
            logger.info(
                "Kafka connection recovered - draining %d buffered event(s)",
                self._queue.depth,
            )

        # 3. Normal path: take a bounded batch and publish it.
        batch = self._queue.get_batch(self._drain_batch, timeout=self._queue_wait)
        if not batch:
            self._health.record_queue_depth(self._queue.depth)
            return

        for index, event in enumerate(batch):
            if not self._publisher.publish(event):
                # The failed event is held by the publisher's pending
                # buffer; everything after it in this batch goes back to
                # the FRONT of the queue, in order, so nothing is lost
                # and nothing is reordered.
                for leftover in reversed(batch[index + 1:]):
                    self._queue.requeue_front(leftover)
                break

        self._health.record_queue_depth(self._queue.depth)

    # -- shutdown ----------------------------------------------------------

    def drain(self, deadline_seconds: float, stop_event: threading.Event) -> int:
        """Publish what is still queued, for at most deadline_seconds.
        Returns how many events remain unpublished.

        Used during graceful shutdown AFTER the telemetry workers have
        stopped and the queue has been closed to new events, so this
        terminates: the queue can only shrink."""
        if self._publisher is None:
            # Never managed to connect; nothing can be drained.
            return self._queue.depth

        deadline = time.monotonic() + max(0.0, deadline_seconds)
        while time.monotonic() < deadline:
            if self._queue.depth == 0 and self._publisher.pending_count == 0:
                break
            if self._publisher.is_backing_off():
                # The broker is down; waiting out a full backoff would
                # burn the whole shutdown budget for nothing.
                remaining = deadline - time.monotonic()
                if self._publisher.seconds_until_retry() > remaining:
                    break
                stop_event.wait(min(self._publisher.seconds_until_retry(), remaining))
                continue
            if self._publisher.pending_count:
                self._publisher.retry_pending()
                continue
            batch = self._queue.get_batch(self._drain_batch, timeout=0)
            if not batch:
                break
            for index, event in enumerate(batch):
                if not self._publisher.publish(event):
                    for leftover in reversed(batch[index + 1:]):
                        self._queue.requeue_front(leftover)
                    break

        remaining_events = self._queue.depth + self._publisher.pending_count
        self._health.record_queue_depth(self._queue.depth)
        return remaining_events
