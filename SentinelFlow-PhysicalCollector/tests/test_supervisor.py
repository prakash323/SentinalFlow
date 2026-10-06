"""
Worker supervision tests (PHASE S items 37-41, 56).

These use REAL threads, because thread isolation and "no duplicate
workers" are exactly the properties a synchronous test cannot prove. The
restart backoff is driven by a VirtualClock, and the only real waiting is
a bounded poll for a condition to become true - so the suite stays fast
and does not depend on sleep timing to pass.
"""
import threading
import time

import pytest

from fakes import VirtualClock
from health import DEGRADED, FAILED, RUNNING, STOPPED, HealthRegistry
from supervisor import Supervisor


def wait_until(predicate, timeout=5.0, interval=0.005):
    """Poll a condition instead of sleeping a guessed duration."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class ScriptedWorker:
    """A worker whose run() does exactly what the test tells it to.

    `crash_times` is how many of the first runs raise; after that it runs
    until it is stopped. Every run is recorded so a test can prove a
    worker was never started twice concurrently.
    """

    def __init__(self, name="scripted", crash_times=0, health=None, hold=True):
        self.name = name
        self.crash_times = crash_times
        self.health = health
        self.hold = hold
        self.runs = 0
        self.resets = 0
        self.concurrent = 0
        self.max_concurrent = 0
        self.started = threading.Event()
        self.lock = threading.Lock()
        if health is not None:
            health.register_worker(name)

    def reset(self):
        self.resets += 1

    def run(self, stop_event):
        with self.lock:
            self.runs += 1
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
            run_index = self.runs
        self.started.set()
        try:
            if self.health is not None:
                self.health.mark_worker_running(self.name)
            if run_index <= self.crash_times:
                raise RuntimeError(f"scripted crash #{run_index}")
            if self.hold:
                stop_event.wait()
        finally:
            with self.lock:
                self.concurrent -= 1
            if self.health is not None:
                self.health.mark_worker_stopped(self.name)


def _supervisor(clock=None, base=1.0, maximum=30.0, healthy_reset=120.0):
    return Supervisor(
        health=HealthRegistry(clock=clock or VirtualClock()),
        restart_base_delay=base,
        restart_max_delay=maximum,
        healthy_reset_seconds=healthy_reset,
        clock=clock or VirtualClock(),
    )


# --------------------------------------------------------------------------
# Start / stop basics
# --------------------------------------------------------------------------

def test_start_runs_every_registered_worker_in_its_own_thread():
    supervisor = _supervisor()
    workers = [ScriptedWorker(name=f"w{n}", health=supervisor._health) for n in range(3)]
    for worker in workers:
        supervisor.add_worker(worker)

    supervisor.start()
    try:
        assert all(worker.started.wait(timeout=5) for worker in workers)
        assert supervisor.live_thread_count() == 3
        assert all(supervisor.is_running(worker.name) for worker in workers)
    finally:
        assert supervisor.stop(timeout_seconds=5) == []

    assert supervisor.live_thread_count() == 0


def test_threads_are_named_so_they_are_identifiable_in_a_dump():
    supervisor = _supervisor()
    worker = ScriptedWorker(name="process", health=supervisor._health)
    supervisor.add_worker(worker)
    supervisor.start()
    try:
        assert worker.started.wait(timeout=5)
        names = [t.name for t in threading.enumerate()]
        assert "sentinelflow-process" in names
    finally:
        supervisor.stop(timeout_seconds=5)


def test_stop_is_immediate_because_workers_wait_on_the_stop_event():
    supervisor = _supervisor()
    worker = ScriptedWorker(health=supervisor._health)
    supervisor.add_worker(worker)
    supervisor.start()
    assert worker.started.wait(timeout=5)

    began = time.monotonic()
    stuck = supervisor.stop(timeout_seconds=5)

    assert stuck == []
    assert time.monotonic() - began < 2.0


def test_stop_reports_a_worker_that_refuses_to_finish():
    supervisor = _supervisor()

    class Stubborn:
        name = "stubborn"

        def reset(self):
            pass

        def run(self, stop_event):
            # Ignores the stop event entirely - the pathological case.
            time.sleep(3)

    supervisor.add_worker(Stubborn())
    supervisor.start()
    time.sleep(0.05)

    stuck = supervisor.stop(timeout_seconds=0.2)
    assert stuck == ["stubborn"]


def test_registering_the_same_worker_name_twice_is_refused():
    supervisor = _supervisor()
    supervisor.add_worker(ScriptedWorker(name="dup"))
    with pytest.raises(ValueError, match="already registered"):
        supervisor.add_worker(ScriptedWorker(name="dup"))


# --------------------------------------------------------------------------
# 37. worker failure isolation
# --------------------------------------------------------------------------

def test_one_crashing_worker_leaves_the_others_running():
    clock = VirtualClock()
    supervisor = Supervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=600.0,
        restart_max_delay=600.0, clock=clock,
    )
    health = supervisor._health

    crasher = ScriptedWorker(name="process", crash_times=1, health=health)
    survivors = [
        ScriptedWorker(name="network", health=health),
        ScriptedWorker(name="session", health=health),
    ]
    for worker in [crasher] + survivors:
        supervisor.add_worker(worker)

    supervisor.start()
    try:
        assert wait_until(lambda: health.worker_state("process") == FAILED)

        states = health.snapshot()["workers"]
        assert states["process"]["state"] == FAILED
        assert states["network"]["state"] == RUNNING
        assert states["session"]["state"] == RUNNING
        assert supervisor.is_running("network")
        assert supervisor.is_running("session")
    finally:
        supervisor.stop(timeout_seconds=5)


def test_a_crash_is_logged_with_its_traceback(caplog):
    import logging

    supervisor = _supervisor(base=600.0, maximum=600.0)
    supervisor.add_worker(ScriptedWorker(name="process", crash_times=1, health=supervisor._health))

    with caplog.at_level(logging.ERROR, logger="sentinelflow.collector.supervisor"):
        supervisor.start()
        assert wait_until(lambda: supervisor._health.worker_state("process") == FAILED)
        supervisor.stop(timeout_seconds=5)

    messages = [record.getMessage() for record in caplog.records]
    assert any("crashed" in message for message in messages)
    assert any(record.exc_info for record in caplog.records)


# --------------------------------------------------------------------------
# 38/39/41. restart, backoff, recovery
# --------------------------------------------------------------------------

def test_a_crashed_worker_is_restarted_and_recovers():
    clock = VirtualClock()
    supervisor = Supervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=0.01,
        restart_max_delay=0.01, clock=clock,
    )
    worker = ScriptedWorker(name="process", crash_times=2, health=supervisor._health)
    supervisor.add_worker(worker)

    supervisor.start()
    try:
        assert wait_until(lambda: worker.runs >= 3)
        assert wait_until(lambda: supervisor._health.worker_state("process") == RUNNING)

        health = supervisor._health.snapshot()["workers"]["process"]
        assert health["restart_count"] == 2
        assert health["error_count"] == 2
        assert worker.resets == 2, "poller state was rebuilt before each restart"
    finally:
        supervisor.stop(timeout_seconds=5)


def test_the_restart_backoff_grows_exponentially_and_is_capped():
    clock = VirtualClock()
    delays = []

    class RecordingSupervisor(Supervisor):
        def _next_backoff(self, entry):
            delay = super()._next_backoff(entry)
            delays.append(delay)
            return delay

    supervisor = RecordingSupervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=1.0,
        restart_max_delay=8.0, clock=clock,
    )
    # The stop event's wait() does the real sleeping, so keep the real
    # delays out of the test by making the worker crash immediately and
    # patching the wait to advance the virtual clock instead.
    original_wait = supervisor.stop_event.wait
    supervisor.stop_event.wait = lambda timeout=None: (
        clock.advance(timeout or 0) and False if timeout else original_wait(0)
    )

    worker = ScriptedWorker(name="process", crash_times=6, health=supervisor._health, hold=True)
    supervisor.add_worker(worker)
    supervisor.start()
    try:
        assert wait_until(lambda: len(delays) >= 6, timeout=10)
    finally:
        supervisor.stop_event.wait = original_wait
        supervisor.stop(timeout_seconds=5)

    assert delays[:6] == [1.0, 2.0, 4.0, 8.0, 8.0, 8.0]


def test_the_backoff_resets_after_sustained_healthy_operation():
    clock = VirtualClock()
    delays = []

    class RecordingSupervisor(Supervisor):
        def _next_backoff(self, entry):
            delay = super()._next_backoff(entry)
            delays.append(delay)
            return delay

    supervisor = RecordingSupervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=1.0,
        restart_max_delay=8.0, healthy_reset_seconds=100.0, clock=clock,
    )

    class LongLivedCrasher:
        """Crashes after a long healthy run every time, so the backoff
        must never escalate."""
        name = "process"

        def __init__(self):
            self.runs = 0

        def reset(self):
            pass

        def run(self, stop_event):
            self.runs += 1
            if self.runs > 4:
                stop_event.wait()
                return
            clock.advance(500)  # ran healthily for 500 virtual seconds
            raise RuntimeError("crash after a long healthy run")

    supervisor.stop_event.wait = lambda timeout=None: (clock.advance(timeout or 0), False)[1]
    supervisor.add_worker(LongLivedCrasher())
    supervisor.start()
    try:
        assert wait_until(lambda: len(delays) >= 4, timeout=10)
    finally:
        supervisor.stop(timeout_seconds=5)

    assert delays[:4] == [1.0, 1.0, 1.0, 1.0], "a long healthy run resets the backoff"


def test_a_crash_during_shutdown_does_not_trigger_a_restart():
    clock = VirtualClock()
    supervisor = Supervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=0.01,
        restart_max_delay=0.01, clock=clock,
    )

    class CrashOnStop:
        name = "process"

        def __init__(self):
            self.runs = 0

        def reset(self):
            pass

        def run(self, stop_event):
            self.runs += 1
            stop_event.wait()
            raise RuntimeError("crashed while shutting down")

    worker = CrashOnStop()
    supervisor.add_worker(worker)
    supervisor.start()
    time.sleep(0.05)
    supervisor.stop(timeout_seconds=5)
    time.sleep(0.1)

    assert worker.runs == 1, "no restart was attempted after stop was requested"


def test_a_failing_reset_does_not_stop_the_restart():
    clock = VirtualClock()
    supervisor = Supervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=0.01,
        restart_max_delay=0.01, clock=clock,
    )

    class BadReset(ScriptedWorker):
        def reset(self):
            raise RuntimeError("reset exploded")

    worker = BadReset(name="process", crash_times=1, health=supervisor._health)
    supervisor.add_worker(worker)
    supervisor.start()
    try:
        assert wait_until(lambda: worker.runs >= 2)
    finally:
        supervisor.stop(timeout_seconds=5)


# --------------------------------------------------------------------------
# 40/56. no duplicate workers, no thread leak
# --------------------------------------------------------------------------

def test_a_restart_never_produces_two_concurrent_instances():
    clock = VirtualClock()
    supervisor = Supervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=0.001,
        restart_max_delay=0.001, clock=clock,
    )
    worker = ScriptedWorker(name="process", crash_times=10, health=supervisor._health)
    supervisor.add_worker(worker)

    supervisor.start()
    try:
        assert wait_until(lambda: worker.runs >= 11, timeout=10)
    finally:
        supervisor.stop(timeout_seconds=5)

    assert worker.max_concurrent == 1, "a restart must reuse the worker's own thread"
    assert supervisor.live_thread_count() == 0


def test_calling_start_twice_does_not_double_the_threads():
    supervisor = _supervisor()
    worker = ScriptedWorker(name="process", health=supervisor._health)
    supervisor.add_worker(worker)

    supervisor.start()
    assert worker.started.wait(timeout=5)
    supervisor.start()  # idempotent
    try:
        assert supervisor.live_thread_count() == 1
        assert worker.runs == 1
    finally:
        supervisor.stop(timeout_seconds=5)


def test_repeated_start_stop_cycles_leak_no_threads():
    before = threading.active_count()

    for _ in range(5):
        supervisor = _supervisor()
        workers = [ScriptedWorker(name=f"w{n}", health=supervisor._health) for n in range(3)]
        for worker in workers:
            supervisor.add_worker(worker)
        supervisor.start()
        assert all(worker.started.wait(timeout=5) for worker in workers)
        assert supervisor.stop(timeout_seconds=5) == []

    assert wait_until(lambda: threading.active_count() <= before)


def test_a_worker_that_returns_cleanly_is_not_restarted():
    # "Do not restart a worker because it is merely idle" - a worker that
    # finishes normally has stopped on purpose.
    supervisor = _supervisor()

    class FinishesImmediately:
        name = "process"

        def __init__(self):
            self.runs = 0

        def reset(self):
            pass

        def run(self, stop_event):
            self.runs += 1

    worker = FinishesImmediately()
    supervisor.add_worker(worker)
    supervisor.start()
    time.sleep(0.2)
    supervisor.stop(timeout_seconds=5)

    assert worker.runs == 1


def test_stop_before_start_is_harmless():
    supervisor = _supervisor()
    supervisor.add_worker(ScriptedWorker(name="process"))
    assert supervisor.stop(timeout_seconds=1) == []


def test_restart_counts_are_reported_per_worker():
    clock = VirtualClock()
    supervisor = Supervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=0.001,
        restart_max_delay=0.001, clock=clock,
    )
    crasher = ScriptedWorker(name="process", crash_times=2, health=supervisor._health)
    steady = ScriptedWorker(name="network", health=supervisor._health)
    supervisor.add_worker(crasher)
    supervisor.add_worker(steady)

    supervisor.start()
    try:
        assert wait_until(lambda: crasher.runs >= 3)
        counts = supervisor.restart_counts()
        assert counts["process"] == 2
        assert counts["network"] == 0
    finally:
        supervisor.stop(timeout_seconds=5)
    assert supervisor._health.worker_state("network") == STOPPED


def test_a_degraded_worker_is_not_restarted():
    # DEGRADED means a poll failed but the worker's loop survived; only
    # an escaped exception is a restart trigger.
    clock = VirtualClock()
    supervisor = Supervisor(
        health=HealthRegistry(clock=clock), restart_base_delay=0.001,
        restart_max_delay=0.001, clock=clock,
    )

    class Degrading:
        name = "network"

        def __init__(self, health):
            self.runs = 0
            self.health = health
            health.register_worker("network")

        def reset(self):
            pass

        def run(self, stop_event):
            self.runs += 1
            self.health.mark_worker_poll_failed("network", OSError("transient"))
            stop_event.wait()

    worker = Degrading(supervisor._health)
    supervisor.add_worker(worker)
    supervisor.start()
    try:
        assert wait_until(lambda: supervisor._health.worker_state("network") == DEGRADED)
        time.sleep(0.2)
        assert worker.runs == 1
    finally:
        supervisor.stop(timeout_seconds=5)
