"""
supervisor.py
Worker isolation, restart and backoff (PHASE M).

                        Supervisor
                   /        |        \\
            Process     Network     Session        (+ the Kafka publisher)
                   \\        |        /
                       one thread each

One supervised thread per worker. A worker that escapes its own loop is
caught HERE - never allowed to kill the process and never allowed to
affect the other workers:

    Process worker crashes  ->  Process = FAILED -> restarting
                                Network = RUNNING
                                Session = RUNNING
                                Kafka   = RUNNING

RESTART POLICY
  - Bounded exponential backoff: base (1s) doubling to max (30s), both
    configurable. No infinite tight restart loop is possible, because a
    crash that recurs immediately keeps doubling until it is only
    retrying every 30s.
  - The backoff resets to base only after the worker has run healthily
    for worker_healthy_reset_seconds (default 120s). Resetting on every
    restart would turn a crash-loop into a 1s-interval crash-loop.
  - NO DUPLICATE WORKERS, structurally: each worker has exactly one
    supervisor thread for the collector's whole lifetime, and that thread
    runs the worker in a loop. A "restart" is the next iteration of that
    same loop - it never spawns a second thread, so there is no window in
    which two instances of a worker can exist.
  - A worker is never restarted for being idle. Only an actual escaped
    exception (including the WorkerFailure a worker raises for itself
    after repeated poll failures) triggers a restart.
  - On restart, the worker's poller state is rebuilt via worker.reset().

SHUTDOWN: stop() sets the shared stop event, which every worker's own
wait() returns from immediately; the supervisor then joins each thread
within a bounded timeout and reports any that did not finish, rather than
hanging forever.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from health import HealthRegistry

logger = logging.getLogger("sentinelflow.collector.supervisor")


class _SupervisedWorker:
    """One worker plus its thread and restart state."""

    def __init__(self, worker: Any) -> None:
        self.worker = worker
        self.name = worker.name
        self.thread: Optional[threading.Thread] = None
        self.backoff_seconds = 0.0
        self.started_at: Optional[float] = None


class Supervisor:
    """Starts, watches and restarts the collector's worker threads."""

    def __init__(
        self,
        health: HealthRegistry,
        restart_base_delay: float = 1.0,
        restart_max_delay: float = 30.0,
        healthy_reset_seconds: float = 120.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._health = health
        self._base_delay = restart_base_delay
        self._max_delay = max(restart_max_delay, restart_base_delay)
        self._healthy_reset_seconds = healthy_reset_seconds
        self._clock = clock
        self._stop_event = threading.Event()
        self._supervised: Dict[str, _SupervisedWorker] = {}
        self._lock = threading.Lock()

    # -- registration / lifecycle -------------------------------------------

    def add_worker(self, worker: Any) -> None:
        """Register a worker. Must be called before start()."""
        with self._lock:
            if worker.name in self._supervised:
                raise ValueError(f"worker '{worker.name}' is already registered")
            self._supervised[worker.name] = _SupervisedWorker(worker)

    def start(self) -> None:
        """Start one supervising thread per registered worker. Idempotent
        per worker: a worker that already has a live thread is not
        started again (no duplicate workers)."""
        self._stop_event.clear()
        with self._lock:
            supervised = list(self._supervised.values())

        for entry in supervised:
            if entry.thread is not None and entry.thread.is_alive():
                logger.debug("Worker %s already running - not started again", entry.name)
                continue
            # daemon=True is a deliberate safety net ONLY: stop() joins
            # every thread explicitly, so a normal shutdown never relies
            # on it. It exists so a hung poller in a C call cannot leave
            # the process unkillable after the main thread is done.
            entry.thread = threading.Thread(
                target=self._supervise,
                args=(entry,),
                name=f"sentinelflow-{entry.name}",
                daemon=True,
            )
            entry.started_at = self._clock()
            entry.thread.start()

    def stop(self, timeout_seconds: float = 10.0) -> List[str]:
        """Signal every worker to stop and join the threads within the
        given total budget. Returns the names of workers that did not
        finish in time (empty list on a clean shutdown)."""
        self._stop_event.set()

        with self._lock:
            supervised = list(self._supervised.values())

        deadline = self._clock() + max(0.0, timeout_seconds)
        still_running: List[str] = []
        for entry in supervised:
            thread = entry.thread
            if thread is None:
                continue
            remaining = max(0.0, deadline - self._clock())
            thread.join(timeout=remaining)
            if thread.is_alive():
                still_running.append(entry.name)

        if still_running:
            logger.warning(
                "Worker thread(s) did not stop within the shutdown budget: %s",
                ", ".join(still_running),
            )
        return still_running

    @property
    def stop_event(self) -> threading.Event:
        return self._stop_event

    def is_running(self, name: str) -> bool:
        with self._lock:
            entry = self._supervised.get(name)
        return bool(entry and entry.thread and entry.thread.is_alive())

    def live_thread_count(self) -> int:
        with self._lock:
            entries = list(self._supervised.values())
        return sum(1 for e in entries if e.thread is not None and e.thread.is_alive())

    def restart_counts(self) -> Dict[str, int]:
        snapshot = self._health.snapshot()
        return {
            name: info.get("restart_count", 0)
            for name, info in snapshot.get("workers", {}).items()
        }

    # -- the supervising loop -----------------------------------------------

    def _supervise(self, entry: _SupervisedWorker) -> None:
        """Runs in the worker's own thread for the collector's lifetime.
        Each iteration runs the worker once; the worker only returns when
        it is stopping or when it has crashed."""
        while not self._stop_event.is_set():
            started_at = self._clock()
            try:
                entry.worker.run(self._stop_event)
            except Exception as error:  # noqa: BLE001 - isolation is the point
                ran_for = self._clock() - started_at
                self._health.mark_worker_crashed(entry.name, error)
                logger.error(
                    "%s worker crashed after %.1fs - other workers are unaffected",
                    entry.name.capitalize(), ran_for, exc_info=True,
                )

                if self._stop_event.is_set():
                    break

                if ran_for >= self._healthy_reset_seconds:
                    # It was healthy for a long while before failing -
                    # treat this as a fresh incident, not a crash loop.
                    entry.backoff_seconds = 0.0

                delay = self._next_backoff(entry)
                logger.warning(
                    "Restarting %s worker in %.0fs (restart #%d)",
                    entry.name, delay, self._restart_count(entry.name) + 1,
                )
                if self._stop_event.wait(delay):
                    break

                self._health.mark_worker_restarted(entry.name)
                try:
                    entry.worker.reset()
                except Exception:
                    logger.exception(
                        "%s worker reset failed - restarting with existing state",
                        entry.name,
                    )
                logger.info("%s worker restarted", entry.name.capitalize())
                continue
            else:
                # Clean return: the worker stopped because it was asked to.
                break

    def _next_backoff(self, entry: _SupervisedWorker) -> float:
        entry.backoff_seconds = min(
            self._max_delay,
            entry.backoff_seconds * 2 if entry.backoff_seconds else self._base_delay,
        )
        return entry.backoff_seconds

    def _restart_count(self, name: str) -> int:
        return self.restart_counts().get(name, 0)
