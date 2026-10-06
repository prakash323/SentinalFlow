"""
health.py
The collector's internal, thread-safe health model.

Every subsystem (each telemetry worker, the Kafka publisher, the queue,
the pipeline) reports into one HealthRegistry. The registry holds only
COUNTERS and SMALL FIXED-SIZE STATE - never a list of events, never a
history of samples - so it cannot grow over a 24-hour run no matter how
much telemetry passes through it.

Deliberately NOT a web API in this phase: exposing an HTTP endpoint from
the collector would be real scope expansion (a new listening port on an
endpoint agent, plus its own auth question). Health is observable through
(a) the periodic heartbeat log line, (b) snapshot() for programmatic/test
use. snapshot() returns a plain dict of plain values so it can be logged,
asserted on, or later served by whatever exposes it.

Thread safety: one RLock guards every mutation and the whole snapshot.
Callers never hold a reference into the registry's internals - snapshot()
deep-copies into plain dicts.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# Collector-level states
STARTING = "STARTING"
RUNNING = "RUNNING"
STOPPING = "STOPPING"
STOPPED = "STOPPED"

# Subsystem states
DEGRADED = "DEGRADED"
FAILED = "FAILED"


@dataclass
class WorkerHealth:
    """Per-telemetry-worker health. Fixed size: five scalars."""
    name: str
    state: str = STARTING
    last_success: Optional[float] = None
    last_error: Optional[str] = None
    error_count: int = 0
    restart_count: int = 0
    poll_count: int = 0


@dataclass
class KafkaHealth:
    state: str = STARTING
    last_successful_publish: Optional[float] = None
    consecutive_failures: int = 0
    retry_count: int = 0
    last_error: Optional[str] = None


@dataclass
class QueueHealth:
    current_depth: int = 0
    max_depth: int = 0
    capacity: int = 0
    dropped_events: int = 0
    total_enqueued: int = 0
    total_published: int = 0


@dataclass
class EventCounters:
    generated: int = 0
    normalized: int = 0
    validated: int = 0
    published: int = 0
    failed: int = 0
    dropped: int = 0
    deduplicated: int = 0
    invalid: int = 0


@dataclass
class _State:
    collector_state: str = STARTING
    started_at: Optional[float] = None
    workers: Dict[str, WorkerHealth] = field(default_factory=dict)
    kafka: KafkaHealth = field(default_factory=KafkaHealth)
    queue: QueueHealth = field(default_factory=QueueHealth)
    events: EventCounters = field(default_factory=EventCounters)


class HealthRegistry:
    """Thread-safe aggregate health. All methods are cheap and
    non-blocking; none of them can fail in a way that would take down a
    telemetry worker."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.RLock()
        self._clock = clock
        self._state = _State()

    # -- collector lifecycle ---------------------------------------------

    def mark_collector_starting(self) -> None:
        with self._lock:
            self._state.collector_state = STARTING
            self._state.started_at = self._clock()

    def mark_collector_running(self) -> None:
        with self._lock:
            self._state.collector_state = RUNNING

    def mark_collector_stopping(self) -> None:
        with self._lock:
            self._state.collector_state = STOPPING

    def mark_collector_stopped(self) -> None:
        with self._lock:
            self._state.collector_state = STOPPED

    @property
    def collector_state(self) -> str:
        with self._lock:
            return self._state.collector_state

    def uptime_seconds(self) -> float:
        with self._lock:
            if self._state.started_at is None:
                return 0.0
            return max(0.0, self._clock() - self._state.started_at)

    # -- workers ----------------------------------------------------------

    def register_worker(self, name: str) -> None:
        with self._lock:
            self._state.workers.setdefault(name, WorkerHealth(name=name))

    def worker_state(self, name: str) -> Optional[str]:
        with self._lock:
            worker = self._state.workers.get(name)
            return worker.state if worker else None

    def mark_worker_running(self, name: str) -> None:
        with self._lock:
            worker = self._worker(name)
            worker.state = RUNNING

    def mark_worker_poll_succeeded(self, name: str) -> None:
        with self._lock:
            worker = self._worker(name)
            worker.poll_count += 1
            worker.last_success = self._clock()
            # A worker that polls successfully again is healthy again,
            # even if a previous poll raised - that is exactly what
            # DEGRADED -> RUNNING means here.
            worker.state = RUNNING

    def mark_worker_poll_failed(self, name: str, error: BaseException) -> None:
        """A single poll raised but the worker's own loop survived it:
        DEGRADED, not FAILED. The worker keeps running and will try
        again at its next interval."""
        with self._lock:
            worker = self._worker(name)
            worker.error_count += 1
            worker.last_error = _short_error(error)
            worker.state = DEGRADED

    def mark_worker_crashed(self, name: str, error: BaseException) -> None:
        """The worker's own loop escaped - the supervisor will restart it."""
        with self._lock:
            worker = self._worker(name)
            worker.error_count += 1
            worker.last_error = _short_error(error)
            worker.state = FAILED

    def mark_worker_restarted(self, name: str) -> None:
        with self._lock:
            worker = self._worker(name)
            worker.restart_count += 1
            worker.state = STARTING

    def mark_worker_stopped(self, name: str) -> None:
        with self._lock:
            self._worker(name).state = STOPPED

    def _worker(self, name: str) -> WorkerHealth:
        worker = self._state.workers.get(name)
        if worker is None:
            worker = WorkerHealth(name=name)
            self._state.workers[name] = worker
        return worker

    # -- kafka ------------------------------------------------------------

    def mark_kafka_running(self) -> None:
        with self._lock:
            self._state.kafka.state = RUNNING

    def mark_publish_succeeded(self, count: int = 1) -> None:
        with self._lock:
            kafka = self._state.kafka
            kafka.state = RUNNING
            kafka.consecutive_failures = 0
            kafka.last_successful_publish = self._clock()
            self._state.events.published += count
            self._state.queue.total_published += count

    def mark_publish_failed(self, error: Optional[BaseException] = None) -> None:
        with self._lock:
            kafka = self._state.kafka
            kafka.consecutive_failures += 1
            kafka.state = DEGRADED
            if error is not None:
                kafka.last_error = _short_error(error)
            self._state.events.failed += 1

    def mark_kafka_retry(self) -> None:
        with self._lock:
            self._state.kafka.retry_count += 1

    def mark_kafka_stopped(self) -> None:
        with self._lock:
            self._state.kafka.state = STOPPED

    # -- queue ------------------------------------------------------------

    def set_queue_capacity(self, capacity: int) -> None:
        with self._lock:
            self._state.queue.capacity = capacity

    def record_queue_depth(self, depth: int) -> None:
        with self._lock:
            queue = self._state.queue
            queue.current_depth = depth
            if depth > queue.max_depth:
                queue.max_depth = depth

    def mark_event_enqueued(self) -> None:
        with self._lock:
            self._state.queue.total_enqueued += 1

    def mark_event_dropped(self, count: int = 1) -> None:
        with self._lock:
            self._state.queue.dropped_events += count
            self._state.events.dropped += count

    # -- pipeline counters -------------------------------------------------

    def mark_event_generated(self) -> None:
        with self._lock:
            self._state.events.generated += 1

    def mark_event_normalized(self) -> None:
        with self._lock:
            self._state.events.normalized += 1

    def mark_event_validated(self) -> None:
        with self._lock:
            self._state.events.validated += 1

    def mark_event_invalid(self) -> None:
        with self._lock:
            self._state.events.invalid += 1

    def mark_event_deduplicated(self) -> None:
        with self._lock:
            self._state.events.deduplicated += 1

    # -- snapshot ----------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """A plain-dict, point-in-time copy. Safe to log, assert on, or
        serialize; holds no reference into the registry."""
        with self._lock:
            state = self._state
            return {
                "collector": {
                    "state": state.collector_state,
                    "started_at": state.started_at,
                    "uptime_seconds": self.uptime_seconds(),
                },
                "workers": {
                    name: {
                        "state": worker.state,
                        "last_success": worker.last_success,
                        "last_error": worker.last_error,
                        "error_count": worker.error_count,
                        "restart_count": worker.restart_count,
                        "poll_count": worker.poll_count,
                    }
                    for name, worker in state.workers.items()
                },
                "kafka": {
                    "state": state.kafka.state,
                    "last_successful_publish": state.kafka.last_successful_publish,
                    "consecutive_failures": state.kafka.consecutive_failures,
                    "retry_count": state.kafka.retry_count,
                    "last_error": state.kafka.last_error,
                },
                "queue": {
                    "current_depth": state.queue.current_depth,
                    "max_depth": state.queue.max_depth,
                    "capacity": state.queue.capacity,
                    "dropped_events": state.queue.dropped_events,
                    "total_enqueued": state.queue.total_enqueued,
                    "total_published": state.queue.total_published,
                },
                "events": {
                    "generated": state.events.generated,
                    "normalized": state.events.normalized,
                    "validated": state.events.validated,
                    "published": state.events.published,
                    "failed": state.events.failed,
                    "dropped": state.events.dropped,
                    "deduplicated": state.events.deduplicated,
                    "invalid": state.events.invalid,
                },
            }

    def heartbeat_line(self) -> str:
        """The periodic one-line operational summary. Counters and states
        only - never an event payload (see PHASE O / README logging)."""
        snapshot = self.snapshot()
        worker_states = " ".join(
            f"{name}={info['state']}" for name, info in sorted(snapshot["workers"].items())
        )
        return (
            "Collector heartbeat state=%s uptime=%.0fs queue=%d/%d maxDepth=%d "
            "generated=%d published=%d deduplicated=%d dropped=%d failed=%d "
            "kafka=%s kafkaFailures=%d workers[%s]"
            % (
                snapshot["collector"]["state"],
                snapshot["collector"]["uptime_seconds"],
                snapshot["queue"]["current_depth"],
                snapshot["queue"]["capacity"],
                snapshot["queue"]["max_depth"],
                snapshot["events"]["generated"],
                snapshot["events"]["published"],
                snapshot["events"]["deduplicated"],
                snapshot["events"]["dropped"],
                snapshot["events"]["failed"],
                snapshot["kafka"]["state"],
                snapshot["kafka"]["consecutive_failures"],
                worker_states,
            )
        )


def _short_error(error: BaseException) -> str:
    """One bounded line. An unbounded exception string stored forever on
    a long-running agent is exactly the kind of slow leak this module
    exists to avoid."""
    text = f"{type(error).__name__}: {error}"
    return text if len(text) <= 200 else text[:197] + "..."


def unhealthy_workers(snapshot: Dict[str, Any]) -> List[str]:
    """Convenience for tests and the heartbeat: worker names that are not
    currently RUNNING."""
    return sorted(
        name for name, info in snapshot.get("workers", {}).items()
        if info.get("state") != RUNNING
    )
