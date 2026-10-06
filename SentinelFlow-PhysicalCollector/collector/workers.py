"""
workers.py
The continuous telemetry workers (PHASES D, E, F).

Each worker owns ONE stateful poller and runs it on its OWN cadence in
its OWN thread, forever, until it is told to stop. Workers never touch
Kafka: every observation goes into the shared EventPipeline, which is the
only path to the queue and from there to the broker.

CONCURRENCY MODEL - threads, deliberately:
  psutil is a blocking C-backed library and so is kafka-python. There is
  no async I/O to overlap, so asyncio would add an event loop, executor
  juggling and a second mental model for exactly zero benefit.
  multiprocessing would add process management and IPC to share a queue
  that threads share for free. Three long-lived threads plus a
  threading.Event is the simplest model that satisfies every requirement
  here, and it is what the existing code's blocking style already
  implies.

NO BUSY LOOPS: a worker never spins. Between polls it blocks in
stop_event.wait(remaining_seconds), which wakes IMMEDIATELY on shutdown
and otherwise sleeps exactly until the next poll is due. A worker with a
30s interval wakes 2 times a minute, not 600.

FAILURE SEMANTICS - two distinct levels, on purpose:
  1. One poll raised (a transient psutil AccessDenied, a momentarily
     unreadable connection table). The worker logs it rate-limited, marks
     itself DEGRADED, and tries again at its next interval. The other
     workers are completely unaffected - that is the whole point of
     giving each source its own thread.
  2. The same poll keeps failing (max_consecutive_failures in a row), or
     the worker loop itself escapes. The worker raises WorkerFailure,
     which the supervisor catches: it restarts the worker with a FRESH
     poller after a backoff. A persistently broken poller is more likely
     to be fixed by rebuilding its state than by polling it again.

RESTART AND BASELINES: a restarted worker builds a fresh poller, so that
poller re-establishes its silent baseline (see process_poller.py /
network_poller.py). That means observations made during the restart gap
are not retroactively reported - which is honest - and that nothing is
re-reported as "new" merely because the collector's internal state was
rebuilt, because the pipeline's deduplication cache still remembers what
was already published (dedup.py). The session poller is the one that
DOES report its baseline (an active session is genuinely true right now);
dedup suppresses that repeat for the same reason.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, List, Optional

from correlation import ProcessMetadataCache
from health import HealthRegistry
from logging_utils import RateLimitedLogger
from network_poller import NetworkPoller
from pipeline import EventPipeline
from process_poller import ProcessPoller
from session_poller import SessionPoller

logger = logging.getLogger("sentinelflow.collector.workers")

PROCESS_WORKER = "process"
NETWORK_WORKER = "network"
SESSION_WORKER = "session"

# A worker that fails this many polls in a row stops trying to limp along
# and asks the supervisor for a clean restart with fresh poller state.
DEFAULT_MAX_CONSECUTIVE_FAILURES = 5


class WorkerFailure(RuntimeError):
    """Raised by a worker that wants the supervisor to restart it."""


class TelemetryWorker:
    """Base class: the poll loop, the failure policy and the health
    reporting. Subclasses supply the poller and the per-observation hook."""

    def __init__(
        self,
        name: str,
        poll_interval_seconds: float,
        pipeline: EventPipeline,
        health: HealthRegistry,
        poller_factory: Callable[[], Any],
        max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
        clock: Callable[[], float] = time.monotonic,
        rate_limited_logger: Optional[RateLimitedLogger] = None,
    ) -> None:
        self.name = name
        self._interval = poll_interval_seconds
        self._pipeline = pipeline
        self._health = health
        self._poller_factory = poller_factory
        self._max_consecutive_failures = max_consecutive_failures
        self._clock = clock
        self._rate_logger = rate_limited_logger or RateLimitedLogger(logger)
        self._poller = poller_factory()
        self._consecutive_failures = 0
        self._health.register_worker(name)

    # -- lifecycle ---------------------------------------------------------

    @property
    def poller(self) -> Any:
        return self._poller

    def reset(self) -> None:
        """Rebuild poller state before a supervised restart."""
        self._poller = self._poller_factory()
        self._consecutive_failures = 0

    def tracked_count(self) -> int:
        """How many things this worker's poller currently remembers -
        used by the resource-safety tests to prove the state stays
        bounded over a long run."""
        return int(getattr(self._poller, "tracked_count", 0) or 0)

    # -- the loop ----------------------------------------------------------

    def run(self, stop_event: threading.Event) -> None:
        """Poll until stop_event is set. Raises WorkerFailure if it wants
        to be restarted; returns normally on a clean stop."""
        logger.info("%s worker started (interval=%.1fs)", self.name.capitalize(), self._interval)
        self._health.mark_worker_running(self.name)

        next_due = self._clock()
        try:
            while not stop_event.is_set():
                now = self._clock()
                if now >= next_due:
                    self._poll_cycle()
                    next_due = self._clock() + self._interval

                remaining = next_due - self._clock()
                if remaining > 0:
                    # Blocks here; wakes instantly on shutdown. No spin.
                    stop_event.wait(remaining)
        finally:
            self._health.mark_worker_stopped(self.name)
            logger.info("%s worker stopped", self.name.capitalize())

    def _poll_cycle(self) -> None:
        was_degraded = self._consecutive_failures > 0
        try:
            observations = self.poll()
        except Exception as error:  # noqa: BLE001 - one bad poll must not kill the worker
            self._consecutive_failures += 1
            self._health.mark_worker_poll_failed(self.name, error)
            self._rate_logger.error(
                f"{self.name}-poll-failed",
                "%s poll failed (%d consecutive) - worker stays alive and will retry: %s",
                self.name, self._consecutive_failures, error,
            )
            if self._consecutive_failures >= self._max_consecutive_failures:
                raise WorkerFailure(
                    f"{self.name} worker failed {self._consecutive_failures} polls in a row"
                ) from error
            return

        self._consecutive_failures = 0
        self._health.mark_worker_poll_succeeded(self.name)
        if was_degraded:
            self._rate_logger.reset(f"{self.name}-poll-failed")
            logger.info("%s worker recovered - polling succeeded again", self.name.capitalize())

        for observation in observations:
            try:
                self.on_observation(observation)
            except Exception:
                # A correlation-cache hiccup must not cost us the event.
                logger.exception("%s worker: observation hook failed", self.name)
            self._pipeline.submit(observation)

    # -- subclass hooks -----------------------------------------------------

    def poll(self) -> List[Any]:
        return self._poller.poll_once()

    def on_observation(self, observation: Any) -> None:
        """Called once per observation BEFORE it enters the pipeline."""


class ProcessWorker(TelemetryWorker):
    """Continuous process telemetry (PHASE D). Emits PROCESS_START for
    processes that appear after the poller's baseline, and feeds the
    process-metadata cache that lets NETWORK_CONNECTION events correlate
    to a process that has already exited (PHASE G)."""

    def __init__(
        self,
        poll_interval_seconds: float,
        pipeline: EventPipeline,
        health: HealthRegistry,
        process_cache: Optional[ProcessMetadataCache] = None,
        poller_factory: Callable[[], ProcessPoller] = ProcessPoller,
        **kwargs,
    ) -> None:
        super().__init__(
            PROCESS_WORKER, poll_interval_seconds, pipeline, health, poller_factory, **kwargs
        )
        self._process_cache = process_cache

    def on_observation(self, observation: Any) -> None:
        if self._process_cache is None:
            return
        # Recording REPLACES any previous entry for this pid, which is
        # exactly the PID-reuse invalidation correlation.py documents: a
        # newly observed process with the same pid has a different
        # create_time, and the stale metadata must not survive.
        self._process_cache.record(
            pid=observation.pid,
            name=observation.name,
            create_time=observation.create_time,
        )
        logger.info(
            "New process detected pid=%s name=%s", observation.pid, observation.name
        )


class NetworkWorker(TelemetryWorker):
    """Continuous network telemetry (PHASE E). Emits NETWORK_CONNECTION
    for ESTABLISHED, non-loopback connections that are new since the
    previous poll."""

    def __init__(
        self,
        poll_interval_seconds: float,
        pipeline: EventPipeline,
        health: HealthRegistry,
        poller_factory: Callable[[], NetworkPoller] = NetworkPoller,
        **kwargs,
    ) -> None:
        super().__init__(
            NETWORK_WORKER, poll_interval_seconds, pipeline, health, poller_factory, **kwargs
        )

    def on_observation(self, observation: Any) -> None:
        logger.info(
            "New connection detected pid=%s process=%s remote=%s:%s",
            observation.pid,
            observation.process_name,
            observation.remote_address,
            observation.remote_port,
        )


class SessionWorker(TelemetryWorker):
    """Continuous session telemetry (PHASE F). Emits LOGIN/LOGOUT for
    real session transitions.

    Degradation, not death: psutil.users() is a normal non-admin call,
    but on a locked-down or unusual Windows configuration it can fail or
    return nothing. The base class's failure policy already covers that -
    this worker goes DEGRADED (and eventually gets restarted) while
    process and network telemetry keep running untouched."""

    def __init__(
        self,
        poll_interval_seconds: float,
        pipeline: EventPipeline,
        health: HealthRegistry,
        poller_factory: Callable[[], SessionPoller] = SessionPoller,
        **kwargs,
    ) -> None:
        super().__init__(
            SESSION_WORKER, poll_interval_seconds, pipeline, health, poller_factory, **kwargs
        )

    def on_observation(self, observation: Any) -> None:
        logger.info(
            "Session transition detected kind=%s username=%s",
            observation.kind,
            observation.username,
        )
