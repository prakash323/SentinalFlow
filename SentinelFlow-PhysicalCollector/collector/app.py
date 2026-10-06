"""
app.py
CollectorApp - the composition root of the continuous collector.

                      Windows Host
                           |
         +-----------------+-----------------+
         |                 |                 |
      Process           Network           Session        <- one thread each,
      Worker            Worker            Worker            own interval
         |                 |                 |
         +-----------------+-----------------+
                           |
                     Event Pipeline            normalize -> validate ->
                           |                   dedup -> enqueue
                     Bounded Queue
                           |
                    Kafka Publisher             <- one thread, one producer
                           |
                         Kafka

Everything is constructed here and nowhere else: one queue, one dedup
cache, one correlation cache, one health registry, one pipeline, one
Kafka producer. There is no module-level mutable state anywhere in the
collector, so a test (or a restart-in-the-same-process) gets a genuinely
fresh collector every time - which is what makes PHASE W's repeated
start/stop/start cycles clean.

TWO SUPERVISORS, on purpose: the telemetry workers and the Kafka
publisher are supervised separately so shutdown can stop telemetry
generation FIRST and keep the publisher alive to drain the queue
afterwards. Both are real supervisors - the publisher is restarted on a
crash exactly like a telemetry worker.

MAIN THREAD: run() blocks in a heartbeat loop. It owns nothing except
the periodic summary log line, so a slow or stuck log sink cannot affect
telemetry or publishing.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from config import Config
from correlation import ProcessMetadataCache
from dedup import BoundedDedupCache
from event_queue import BoundedEventQueue
from health import HealthRegistry
from kafka_producer import EventPublisher
from logging_utils import RateLimitedLogger
from pipeline import EventPipeline
from publisher_worker import PublisherWorker
from supervisor import Supervisor
from workers import NetworkWorker, ProcessWorker, SessionWorker

logger = logging.getLogger("sentinelflow.collector")


class CollectorApp:
    """The whole agent. start() -> run() -> stop(), or use it as a
    context manager."""

    def __init__(
        self,
        config: Config,
        publisher_factory: Optional[Callable[[], EventPublisher]] = None,
        worker_factories: Optional[List[Callable[["CollectorApp"], Any]]] = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._clock = clock

        self.health = HealthRegistry(clock=clock)
        self.queue = BoundedEventQueue(config.queue_max_size)
        self.health.set_queue_capacity(config.queue_max_size)

        self.dedup_cache = BoundedDedupCache(
            ttl_seconds=config.dedup_ttl_seconds,
            max_entries=config.dedup_max_entries,
            clock=clock,
        )
        self.process_cache = ProcessMetadataCache(
            ttl_seconds=config.correlation_ttl_seconds,
            max_entries=config.correlation_max_entries,
            clock=clock,
        )
        self._rate_logger = RateLimitedLogger(logger, interval_seconds=60.0, clock=clock)

        self.pipeline = EventPipeline(
            entity_id=config.entity_id,
            queue=self.queue,
            dedup_cache=self.dedup_cache,
            health=self.health,
            process_cache=self.process_cache,
            rate_limited_logger=self._rate_logger,
            clock=wall_clock,
        )

        self._publisher_factory = publisher_factory or self._default_publisher_factory
        self.publisher: Optional[EventPublisher] = None
        self.publisher_worker = PublisherWorker(
            queue=self.queue,
            publisher=None,
            health=self.health,
            rate_limited_logger=self._rate_logger,
            publisher_factory=self._build_publisher,
            connect_retry_base_seconds=config.kafka_retry_base_delay_seconds,
            connect_retry_max_seconds=config.kafka_retry_max_delay_seconds,
        )

        self.telemetry_supervisor = Supervisor(
            health=self.health,
            restart_base_delay=config.worker_restart_base_delay_seconds,
            restart_max_delay=config.worker_restart_max_delay_seconds,
            healthy_reset_seconds=config.worker_healthy_reset_seconds,
            clock=clock,
        )
        self.publisher_supervisor = Supervisor(
            health=self.health,
            restart_base_delay=config.worker_restart_base_delay_seconds,
            restart_max_delay=config.worker_restart_max_delay_seconds,
            healthy_reset_seconds=config.worker_healthy_reset_seconds,
            clock=clock,
        )

        self.workers: List[Any] = (
            [factory(self) for factory in worker_factories]
            if worker_factories is not None
            else self._default_workers()
        )
        for worker in self.workers:
            self.telemetry_supervisor.add_worker(worker)
        self.publisher_supervisor.add_worker(self.publisher_worker)

        self._shutdown_requested = threading.Event()
        self._force_stop = threading.Event()
        self._started = False
        self._stopped = False

    # -- construction helpers ----------------------------------------------

    def _default_workers(self) -> List[Any]:
        return [
            ProcessWorker(
                poll_interval_seconds=self.config.process_poll_interval_seconds,
                pipeline=self.pipeline,
                health=self.health,
                process_cache=self.process_cache,
                clock=self._clock,
                rate_limited_logger=self._rate_logger,
            ),
            NetworkWorker(
                poll_interval_seconds=self.config.network_poll_interval_seconds,
                pipeline=self.pipeline,
                health=self.health,
                clock=self._clock,
                rate_limited_logger=self._rate_logger,
            ),
            SessionWorker(
                poll_interval_seconds=self.config.poll_interval_seconds,
                pipeline=self.pipeline,
                health=self.health,
                clock=self._clock,
                rate_limited_logger=self._rate_logger,
            ),
        ]

    def _default_publisher_factory(self) -> EventPublisher:
        return EventPublisher(
            bootstrap_servers=self.config.kafka_bootstrap_servers,
            topic=self.config.topic,
            max_pending=self.config.kafka_max_pending_events,
            retry_base_delay=self.config.kafka_retry_base_delay_seconds,
            retry_max_delay=self.config.kafka_retry_max_delay_seconds,
            health=self.health,
        )

    def _build_publisher(self) -> EventPublisher:
        """Built on the publisher thread, retried there if the broker is
        down. Kept on self so stop() can close the one real producer."""
        publisher = self._publisher_factory()
        self.publisher = publisher
        return publisher

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._started:
            raise RuntimeError("CollectorApp is already started")
        self._started = True

        self.health.mark_collector_starting()
        logger.info(
            "SentinelFlow physical telemetry collector starting entityId=%s topic=%s "
            "bootstrap=%s sessionInterval=%.1fs processInterval=%.1fs networkInterval=%.1fs "
            "queueMax=%d dedupTtl=%.0fs dedupMax=%d",
            self.config.entity_id,
            self.config.topic,
            self.config.kafka_bootstrap_servers,
            self.config.poll_interval_seconds,
            self.config.process_poll_interval_seconds,
            self.config.network_poll_interval_seconds,
            self.config.queue_max_size,
            self.config.dedup_ttl_seconds,
            self.config.dedup_max_entries,
        )
        logger.info(
            "REQUIRED: entityId '%s' must already be registered via POST /api/v1/entities "
            "before published events will be accepted by the SentinelFlow pipeline (see README.md).",
            self.config.entity_id,
        )

        self.publisher_supervisor.start()
        self.telemetry_supervisor.start()
        self.health.mark_collector_running()
        logger.info("Collector running - %d telemetry worker(s) supervised", len(self.workers))

    def run(self) -> None:
        """Block until stop() is requested, logging the periodic
        heartbeat. The heartbeat is the ONLY thing this thread does."""
        interval = self.config.heartbeat_interval_seconds
        while not self._shutdown_requested.is_set():
            if self._shutdown_requested.wait(interval):
                break
            self.health.record_queue_depth(self.queue.depth)
            logger.info("%s", self.health.heartbeat_line())

    def request_stop(self) -> None:
        """Signal-handler safe: sets an Event and returns immediately.
        A second call escalates - it releases the shutdown drain early so
        a second Ctrl+C is not ignored."""
        if self._shutdown_requested.is_set():
            self._force_stop.set()
            return
        self._shutdown_requested.set()

    def stop(self) -> Dict[str, Any]:
        """Graceful shutdown (PHASE P). Returns a small result dict with
        what actually happened, so callers and tests do not have to parse
        logs. Idempotent."""
        if self._stopped:
            return {"already_stopped": True}
        self._stopped = True

        self._shutdown_requested.set()
        self.health.mark_collector_stopping()
        logger.info("Shutdown requested - stopping telemetry workers")

        timeout = self.config.shutdown_timeout_seconds

        # 1. Stop producing telemetry. Workers wake instantly from their
        #    interval wait, so this returns in milliseconds in practice.
        stuck_workers = self.telemetry_supervisor.stop(timeout_seconds=timeout)

        # 2. No new events may enter the queue from here on. Already
        #    queued events stay queued.
        self.queue.close()

        # 3. Stop the publisher THREAD, then drain from this thread, so
        #    nothing competes for the queue during the drain.
        stuck_publisher = self.publisher_supervisor.stop(timeout_seconds=timeout)

        if stuck_publisher:
            # Its thread is still alive and still owns the producer.
            # Draining from here as well would use one EventPublisher
            # from two threads at once, so it is skipped deliberately and
            # the queue depth is reported instead.
            logger.warning(
                "Kafka publisher thread did not stop - skipping the shutdown drain; "
                "%d event(s) remain queued",
                self.queue.depth,
            )
            remaining = self.queue.depth
        else:
            logger.info(
                "Draining remaining %d queued event(s), up to %.0fs", self.queue.depth, timeout
            )
            remaining = self.publisher_worker.drain(timeout, self._force_stop)

            # 4. Close the producer (which makes one last attempt of its own).
            if self.publisher is not None:
                self.publisher.close()
        self.health.mark_kafka_stopped()

        if remaining:
            logger.warning(
                "Shutdown complete with %d event(s) still unpublished - these are lost "
                "(the queue is in-memory and is not persisted across restarts)",
                remaining,
            )
        else:
            logger.info("Shutdown complete - queue fully drained")

        self.health.mark_collector_stopped()
        snapshot = self.health.snapshot()
        logger.info("Final counters: %s", self.health.heartbeat_line())

        return {
            "remaining_events": remaining,
            "stuck_workers": stuck_workers + stuck_publisher,
            "health": snapshot,
        }

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> "CollectorApp":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
