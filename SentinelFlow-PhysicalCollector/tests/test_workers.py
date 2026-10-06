"""
Continuous telemetry worker tests (PHASE S items 5-18 and 52-56).

The workers are driven SYNCHRONOUSLY here - _poll_cycle() is called
directly against a virtual clock and a fake OS source - so every test is
deterministic and nothing sleeps. The threaded run() loop is covered
separately in test_supervisor.py and test_app_lifecycle.py.
"""
import psutil
import pytest

from correlation import ProcessMetadataCache
from dedup import BoundedDedupCache
from event_queue import BoundedEventQueue
from fakes import (
    FakeNetworkSource,
    FakeProcessSource,
    FakeSessionSource,
    NonSleepingEvent,
    VirtualClock,
    VirtualStopEvent,
)
from health import DEGRADED, RUNNING, HealthRegistry
from network_poller import NetworkPoller
from pipeline import EventPipeline
from process_poller import ProcessPoller
from session_poller import SessionPoller
from workers import NetworkWorker, ProcessWorker, SessionWorker, WorkerFailure


class Harness:
    """A pipeline plus the three real pollers wired to fake OS sources."""

    def __init__(self, max_consecutive_failures=5, queue_size=1000):
        self.clock = VirtualClock()
        self.queue = BoundedEventQueue(max_size=queue_size)
        self.health = HealthRegistry(clock=self.clock)
        self.health.set_queue_capacity(queue_size)
        self.dedup = BoundedDedupCache(ttl_seconds=3600, max_entries=10_000, clock=self.clock)
        self.process_cache = ProcessMetadataCache(ttl_seconds=300, max_entries=500, clock=self.clock)
        self.pipeline = EventPipeline(
            entity_id="HOST-TEST", queue=self.queue, dedup_cache=self.dedup,
            health=self.health, process_cache=self.process_cache, clock=self.clock,
        )

        self.process_source = FakeProcessSource()
        self.network_source = FakeNetworkSource()
        self.session_source = FakeSessionSource()

        self.process_worker = ProcessWorker(
            poll_interval_seconds=15.0, pipeline=self.pipeline, health=self.health,
            process_cache=self.process_cache, clock=self.clock,
            max_consecutive_failures=max_consecutive_failures,
            poller_factory=lambda: ProcessPoller(
                snapshot_fn=self.process_source.snapshot,
                executable_lookup=self.process_source.executable_lookup,
            ),
        )
        self.network_worker = NetworkWorker(
            poll_interval_seconds=30.0, pipeline=self.pipeline, health=self.health,
            clock=self.clock, max_consecutive_failures=max_consecutive_failures,
            poller_factory=lambda: NetworkPoller(
                snapshot_fn=self.network_source.snapshot,
                process_info_lookup=self.network_source.lookup,
            ),
        )
        self.session_worker = SessionWorker(
            poll_interval_seconds=5.0, pipeline=self.pipeline, health=self.health,
            clock=self.clock, max_consecutive_failures=max_consecutive_failures,
            poller_factory=lambda: SessionPoller(
                snapshot_fn=self.session_source.snapshot, clock=self.clock,
            ),
        )

    def queued(self):
        return self.queue.get_batch(10_000, timeout=0)

    def queued_types(self):
        return [event["eventType"] for event in self.queued()]


@pytest.fixture
def harness():
    return Harness()


# --------------------------------------------------------------------------
# 5/6/7. process baseline, new process detection, duplicate suppression
# --------------------------------------------------------------------------

def test_the_first_process_poll_is_a_silent_baseline(harness):
    for pid in (100, 200, 300):
        harness.process_source.add(pid=pid, create_time=1000.0 + pid)

    harness.process_worker._poll_cycle()

    assert harness.queue.depth == 0, "pre-existing processes are not PROCESS_START"
    assert harness.health.worker_state("process") == RUNNING


def test_only_a_newly_appeared_process_is_emitted(harness):
    harness.process_source.add(pid=100, name="chrome.exe", create_time=1100.0)
    harness.process_source.add(pid=200, name="cmd.exe", create_time=1200.0)
    harness.process_worker._poll_cycle()

    harness.process_source.add(pid=500, name="python.exe", create_time=1500.0)
    harness.process_worker._poll_cycle()

    events = harness.queued()
    assert len(events) == 1
    assert events[0]["eventType"] == "PROCESS_START"
    assert events[0]["payload"]["pid"] == 500
    assert events[0]["payload"]["processName"] == "python.exe"


def test_a_process_that_keeps_running_is_not_re_emitted(harness):
    harness.process_worker._poll_cycle()
    harness.process_source.add(pid=500, create_time=1500.0)

    for _ in range(10):
        harness.process_worker._poll_cycle()
        harness.clock.advance(15)

    assert len(harness.queued()) == 1


# --------------------------------------------------------------------------
# 8. process metadata extraction
# --------------------------------------------------------------------------

def test_process_metadata_is_carried_into_the_payload(harness):
    harness.process_worker._poll_cycle()
    harness.process_source.add(
        pid=900, name="powershell.exe", ppid=4120, create_time=1_800_000_000.0,
        username="HOST\\praka",
    )
    harness.process_worker._poll_cycle()

    payload = harness.queued()[0]["payload"]
    assert payload == {
        "pid": 900,
        "processName": "powershell.exe",
        "parentPid": 4120,
        "username": "HOST\\praka",
        "executablePath": "C:\\fake\\900.exe",
    }
    assert "cmdline" not in payload, "command lines are never collected"


def test_the_executable_lookup_runs_only_for_newly_detected_processes(harness):
    calls = []
    harness.process_worker = ProcessWorker(
        poll_interval_seconds=15.0, pipeline=harness.pipeline, health=harness.health,
        process_cache=harness.process_cache, clock=harness.clock,
        poller_factory=lambda: ProcessPoller(
            snapshot_fn=harness.process_source.snapshot,
            executable_lookup=lambda pid: calls.append(pid) or "C:\\x.exe",
        ),
    )
    for pid in range(50):
        harness.process_source.add(pid=pid, create_time=float(pid))

    harness.process_worker._poll_cycle()
    assert calls == [], "the baseline must not trigger 50 expensive lookups"

    harness.process_source.add(pid=999, create_time=999.0)
    harness.process_worker._poll_cycle()
    assert calls == [999]


# --------------------------------------------------------------------------
# 9/10. disappearing processes and bounded process state
# --------------------------------------------------------------------------

def test_a_disappearing_process_emits_nothing_and_is_forgotten(harness):
    # PROCESS_END is not part of the SentinelFlow event contract, so no
    # termination event is invented - but the state must still shrink.
    harness.process_worker._poll_cycle()
    harness.process_source.add(pid=500, create_time=1500.0)
    harness.process_worker._poll_cycle()
    assert harness.process_worker.tracked_count() == 1

    harness.process_source.remove(pid=500)
    harness.process_worker._poll_cycle()

    assert harness.queued_types() == ["PROCESS_START"], "no PROCESS_END was emitted"
    assert harness.process_worker.tracked_count() == 0


def test_process_state_stays_proportional_to_the_live_process_table(harness):
    harness.process_worker._poll_cycle()

    # 2000 processes start and exit over time; only ~20 are ever live.
    for generation in range(100):
        harness.process_source.clear()
        for n in range(20):
            harness.process_source.add(pid=10_000 + n, create_time=float(generation * 100 + n))
        harness.process_worker._poll_cycle()
        harness.clock.advance(15)
        harness.queued()  # drain so the queue is not what bounds this

    assert harness.process_worker.tracked_count() == 20


def test_a_reused_pid_is_treated_as_a_new_process(harness):
    harness.process_worker._poll_cycle()
    harness.process_source.add(pid=500, name="first.exe", create_time=1000.0)
    harness.process_worker._poll_cycle()

    harness.process_source.remove(pid=500)
    harness.process_source.add(pid=500, name="second.exe", create_time=2000.0)
    harness.process_worker._poll_cycle()

    names = [event["payload"]["processName"] for event in harness.queued()]
    assert names == ["first.exe", "second.exe"]


# --------------------------------------------------------------------------
# 11/12/13/14. network detection, duplicates, bounded cache
# --------------------------------------------------------------------------

def test_the_first_network_poll_is_a_silent_baseline(harness):
    harness.network_source.add(pid=1, remote_ip="1.1.1.1")
    harness.network_worker._poll_cycle()
    assert harness.queue.depth == 0


def test_only_a_new_connection_is_emitted(harness):
    harness.network_source.add(pid=1, local_port=1000, remote_ip="1.1.1.1")
    harness.network_worker._poll_cycle()

    harness.network_source.add(pid=2, local_port=2000, remote_ip="8.8.8.8")
    harness.network_worker._poll_cycle()

    events = harness.queued()
    assert len(events) == 1
    assert events[0]["payload"]["remoteAddress"] == "8.8.8.8"


def test_a_persistent_connection_is_not_re_emitted(harness):
    harness.network_worker._poll_cycle()
    harness.network_source.add(pid=1, local_port=1000)

    for _ in range(20):
        harness.network_worker._poll_cycle()
        harness.clock.advance(30)

    assert len(harness.queued()) == 1


def test_network_state_stays_proportional_to_the_live_connection_table(harness):
    harness.network_worker._poll_cycle()

    for generation in range(100):
        harness.network_source.clear()
        for n in range(10):
            harness.network_source.add(pid=n, local_port=40_000 + generation * 10 + n)
        harness.network_worker._poll_cycle()
        harness.clock.advance(30)
        harness.queued()

    assert harness.network_worker.tracked_count() == 10


def test_a_closed_and_reopened_connection_is_reportable_again_after_the_dedup_ttl(harness):
    harness.network_worker._poll_cycle()
    key = harness.network_source.add(pid=1, local_port=1000)
    harness.network_worker._poll_cycle()
    assert len(harness.queued()) == 1

    harness.network_source.remove(key)
    harness.network_worker._poll_cycle()

    harness.clock.advance(3601)  # past the pipeline dedup TTL
    harness.network_source.add(pid=1, local_port=1000)
    harness.network_worker._poll_cycle()

    assert len(harness.queued()) == 1


def test_an_exact_repeat_inside_the_dedup_ttl_is_suppressed(harness):
    # The documented limitation: without a connection-level create_time
    # there is no way to tell a genuine repeat from the original
    # persisting, so dedup suppresses it. Asserted rather than left
    # implicit.
    harness.network_worker._poll_cycle()
    key = harness.network_source.add(pid=1, local_port=1000)
    harness.network_worker._poll_cycle()
    harness.queued()

    harness.network_source.remove(key)
    harness.network_worker._poll_cycle()
    harness.clock.advance(60)
    harness.network_source.add(pid=1, local_port=1000)
    harness.network_worker._poll_cycle()

    assert harness.queue.depth == 0
    assert harness.health.snapshot()["events"]["deduplicated"] == 1


# --------------------------------------------------------------------------
# 15. process / network correlation through the workers
# --------------------------------------------------------------------------

def test_the_process_worker_feeds_the_correlation_cache(harness):
    harness.process_worker._poll_cycle()
    harness.process_source.add(pid=8420, name="powershell.exe", create_time=1_800_000_000.0)
    harness.process_worker._poll_cycle()

    entry = harness.process_cache.lookup(8420)
    assert entry is not None
    assert entry.name == "powershell.exe"
    assert entry.create_time == 1_800_000_000.0


def test_a_connection_from_an_exited_process_is_still_correlated(harness):
    # The process starts, is observed, connects, and exits before the
    # network worker can resolve it live - the exact case the backend's
    # NEW_PROCESS_EXTERNAL_CONNECTION rule is about.
    harness.process_worker._poll_cycle()
    harness.network_worker._poll_cycle()

    harness.process_source.add(pid=8420, name="python.exe", create_time=1_800_000_000.0)
    harness.process_worker._poll_cycle()
    process_start = harness.queued()[0]

    harness.network_source.add(pid=8420, local_port=55555)
    harness.network_source.process_info = {}  # live lookup finds nothing
    harness.network_worker._poll_cycle()

    connection = harness.queued()[0]
    assert connection["payload"]["processName"] == "python.exe"
    assert connection["payload"]["processCreateTime"] == process_start["occurredAt"]


# --------------------------------------------------------------------------
# 16/17/18. session baseline, change, duplicate suppression
# --------------------------------------------------------------------------

def test_the_session_baseline_reports_the_active_session_as_a_login(harness):
    harness.session_source.login(name="praka", started=1_800_000_000.0)
    harness.session_worker._poll_cycle()

    events = harness.queued()
    assert len(events) == 1
    assert events[0]["eventType"] == "LOGIN"
    assert events[0]["occurredAt"] == "2027-01-15T08:00:00Z"


def test_a_new_login_and_a_logout_are_both_reported(harness):
    harness.session_source.login(name="praka", started=1_800_000_000.0)
    harness.session_worker._poll_cycle()
    harness.queued()

    harness.clock.advance(60)
    harness.session_source.login(name="guest", started=1_800_000_060.0)
    harness.session_worker._poll_cycle()
    assert harness.queued_types() == ["LOGIN"]

    harness.clock.advance(60)
    harness.session_source.logout(name="guest", started=1_800_000_060.0)
    harness.session_worker._poll_cycle()

    events = harness.queued()
    assert [e["eventType"] for e in events] == ["LOGOUT"]
    assert events[0]["payload"]["sessionDurationMinutes"] == pytest.approx(1.0)


def test_an_unchanged_session_is_not_re_reported(harness):
    harness.session_source.login(name="praka", started=1_800_000_000.0)

    for _ in range(50):
        harness.session_worker._poll_cycle()
        harness.clock.advance(5)

    assert len(harness.queued()) == 1


def test_a_restarted_session_worker_does_not_republish_its_baseline(harness):
    harness.session_source.login(name="praka", started=1_800_000_000.0)
    harness.session_worker._poll_cycle()
    assert len(harness.queued()) == 1

    harness.session_worker.reset()  # what the supervisor does on a restart
    harness.session_worker._poll_cycle()

    assert harness.queue.depth == 0, "dedup suppressed the re-baselined LOGIN"
    assert harness.health.snapshot()["events"]["deduplicated"] == 1


def test_session_state_stays_bounded(harness):
    harness.session_worker._poll_cycle()
    for n in range(200):
        harness.session_source.login(name=f"user{n % 3}", started=float(n))
        harness.session_worker._poll_cycle()
        harness.session_source.logout(name=f"user{n % 3}", started=float(n))
        harness.clock.advance(5)
        harness.queued()

    harness.session_worker._poll_cycle()
    assert harness.session_worker.tracked_count() == 0


# --------------------------------------------------------------------------
# 37. worker failure isolation and degradation
# --------------------------------------------------------------------------

def test_a_failed_poll_degrades_only_that_worker(harness):
    harness.process_worker._poll_cycle()
    harness.network_worker._poll_cycle()
    harness.session_worker._poll_cycle()

    harness.network_source.raise_next = psutil.AccessDenied("connection table")
    harness.network_worker._poll_cycle()

    workers = harness.health.snapshot()["workers"]
    assert workers["network"]["state"] == DEGRADED
    assert workers["process"]["state"] == RUNNING
    assert workers["session"]["state"] == RUNNING


def test_a_degraded_worker_recovers_on_its_next_good_poll(harness):
    harness.network_worker._poll_cycle()
    harness.network_source.raise_next = OSError("transient")
    harness.network_worker._poll_cycle()
    assert harness.health.worker_state("network") == DEGRADED

    harness.network_worker._poll_cycle()
    assert harness.health.worker_state("network") == RUNNING


def test_an_unavailable_session_source_degrades_the_subsystem_not_the_collector(harness):
    # PHASE F: "a limitation must degrade the subsystem, not kill the
    # collector."
    harness.session_source.always_raise = psutil.AccessDenied("WTS enumeration")
    harness.process_source.add(pid=500, create_time=500.0)
    harness.process_worker._poll_cycle()

    for _ in range(4):
        harness.session_worker._poll_cycle()

    assert harness.health.worker_state("session") == DEGRADED

    harness.process_source.add(pid=600, create_time=600.0)
    harness.process_worker._poll_cycle()
    assert harness.health.worker_state("process") == RUNNING
    assert harness.queued_types() == ["PROCESS_START"]


def test_repeated_failures_escalate_to_a_restart_request(harness):
    harness.network_worker._poll_cycle()
    harness.network_source.always_raise = OSError("permanently broken")

    for _ in range(4):
        harness.network_worker._poll_cycle()

    with pytest.raises(WorkerFailure, match="network"):
        harness.network_worker._poll_cycle()  # the 5th consecutive failure


def test_the_failure_counter_resets_after_a_successful_poll():
    harness = Harness(max_consecutive_failures=3)
    harness.network_worker._poll_cycle()

    for _ in range(2):
        harness.network_source.raise_next = OSError("transient")
        harness.network_worker._poll_cycle()
        harness.network_worker._poll_cycle()  # succeeds, resetting the counter

    harness.network_source.raise_next = OSError("transient")
    harness.network_worker._poll_cycle()  # must not raise - counter was reset


def test_a_reset_worker_rebuilds_its_poller_state(harness):
    harness.process_source.add(pid=100, create_time=100.0)
    harness.process_worker._poll_cycle()
    poller_before = harness.process_worker.poller

    harness.process_worker.reset()

    assert harness.process_worker.poller is not poller_before
    harness.process_worker._poll_cycle()
    assert harness.queue.depth == 0, "the fresh poller re-baselined silently"


def test_an_observation_hook_failure_does_not_lose_the_event(harness, monkeypatch):
    harness.process_worker._poll_cycle()
    monkeypatch.setattr(
        harness.process_cache, "record",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("cache exploded")),
    )
    harness.process_source.add(pid=500, create_time=500.0)

    harness.process_worker._poll_cycle()

    assert harness.queued_types() == ["PROCESS_START"]


# --------------------------------------------------------------------------
# The threaded loop: it polls on its interval and stops instantly
# --------------------------------------------------------------------------

def test_the_run_loop_polls_once_per_interval_against_a_virtual_clock(harness):
    # VirtualStopEvent turns the loop's "wait until the next poll is
    # due" into a virtual-clock jump, so this exercises the real run()
    # loop with zero real delay - and would hang if the loop busy-spun
    # instead of waiting.
    stop = VirtualStopEvent(harness.clock)
    source = harness.process_source

    polls = []
    real_snapshot = source.snapshot

    def counting_snapshot():
        polls.append(harness.clock.now)
        if len(polls) >= 4:
            stop.set()
        harness.clock.advance(1.0)
        return real_snapshot()

    worker = ProcessWorker(
        poll_interval_seconds=15.0, pipeline=harness.pipeline, health=harness.health,
        clock=harness.clock,
        poller_factory=lambda: ProcessPoller(
            snapshot_fn=counting_snapshot, executable_lookup=source.executable_lookup
        ),
    )
    worker.run(stop)

    assert len(polls) == 4
    # Each poll happens one interval after the previous one finished
    # (+1s of simulated poll duration).
    gaps = [round(b - a) for a, b in zip(polls, polls[1:])]
    assert gaps == [16, 16, 16]


def test_the_run_loop_exits_immediately_when_already_stopped(harness):
    stop = NonSleepingEvent()
    stop.set()
    harness.process_worker.run(stop)
    assert harness.process_source.snapshot_calls == 0
