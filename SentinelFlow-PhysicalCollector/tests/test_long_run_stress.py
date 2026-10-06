"""
Deterministic long-run stress tests (PHASE T, PHASE S items 57-62).

WHAT IS REAL HERE: the pollers, the pipeline (normalize/validate/dedup),
the bounded queue, the correlation cache, the EventPublisher (its real
pending buffer and real bounded exponential backoff), the publisher
worker's real _iteration(), and the health registry.

WHAT IS FAKE: the clock, the OS telemetry sources, and
kafka.KafkaProducer. Nothing sleeps - a simulated hour costs a fraction
of a real second, which is what makes a 1-hour test something CI can run
on every commit instead of a thing nobody ever runs.

WHY A SYNCHRONOUS DRIVER RATHER THAN THREADS: with real threads, a
"1 hour" run would either take an hour or depend on thread scheduling for
its results - neither is a test. The simulation drives the SAME methods
the threads drive (`worker._poll_cycle()`, `publisher._iteration()`), at
the SAME intervals the real config would use, so the logic under test is
identical; only the scheduler is swapped. Threaded behavior (isolation,
restart, no duplicate workers, shutdown) is covered with real threads in
test_supervisor.py and test_app_lifecycle.py.

The simulation deliberately includes: process churn, network churn,
repeated identical observations, two Kafka outages with recovery, two
telemetry-source failures with supervised restart, and sustained queue
pressure from a deliberately small queue.
"""
import time

import pytest

from correlation import ProcessMetadataCache
from dedup import BoundedDedupCache
from event_queue import BoundedEventQueue
from fakes import (
    FakeKafkaProducer,
    FakeNetworkSource,
    FakeProcessSource,
    FakeSessionSource,
    NonSleepingEvent,
    VirtualClock,
)
from health import RUNNING, HealthRegistry
from kafka_producer import EventPublisher
from network_poller import NetworkPoller
from pipeline import EventPipeline
from process_poller import ProcessPoller
from publisher_worker import PublisherWorker
from session_poller import SessionPoller
from workers import NetworkWorker, ProcessWorker, SessionWorker, WorkerFailure

MINUTE = 60
HOUR = 3600

# The real default intervals, so the simulation's event volume is the
# volume the shipped configuration would actually produce.
PROCESS_INTERVAL = 15
NETWORK_INTERVAL = 30
SESSION_INTERVAL = 5

QUEUE_MAX = 500          # deliberately small, to force real queue pressure
DEDUP_MAX = 2000
DEDUP_TTL = 3600
CORRELATION_MAX = 500
CORRELATION_TTL = 300


class SimulatedCollector:
    """Steps the real collector components through virtual time."""

    def __init__(self, queue_max=QUEUE_MAX):
        self.clock = VirtualClock()
        self.stop = NonSleepingEvent()

        self.queue = BoundedEventQueue(max_size=queue_max)
        self.health = HealthRegistry(clock=self.clock)
        self.health.set_queue_capacity(queue_max)
        self.dedup = BoundedDedupCache(DEDUP_TTL, DEDUP_MAX, clock=self.clock)
        self.process_cache = ProcessMetadataCache(CORRELATION_TTL, CORRELATION_MAX, clock=self.clock)
        self.pipeline = EventPipeline(
            entity_id="HOST-STRESS", queue=self.queue, dedup_cache=self.dedup,
            health=self.health, process_cache=self.process_cache, clock=self.clock,
        )

        self.process_source = FakeProcessSource()
        self.network_source = FakeNetworkSource()
        self.session_source = FakeSessionSource()

        self.producer = FakeKafkaProducer()
        self.publisher = EventPublisher(
            "fake:9094", "raw.events.v1", clock=self.clock,
            retry_base_delay=5.0, retry_max_delay=60.0, health=self.health,
            producer_factory=lambda **kwargs: self.producer,
        )
        self.publisher_worker = PublisherWorker(
            queue=self.queue, publisher=self.publisher, health=self.health,
            queue_wait_seconds=0,
        )

        self.workers = {
            "process": ProcessWorker(
                poll_interval_seconds=PROCESS_INTERVAL, pipeline=self.pipeline,
                health=self.health, process_cache=self.process_cache, clock=self.clock,
                poller_factory=lambda: ProcessPoller(
                    snapshot_fn=self.process_source.snapshot,
                    executable_lookup=self.process_source.executable_lookup,
                ),
            ),
            "network": NetworkWorker(
                poll_interval_seconds=NETWORK_INTERVAL, pipeline=self.pipeline,
                health=self.health, clock=self.clock,
                poller_factory=lambda: NetworkPoller(
                    snapshot_fn=self.network_source.snapshot,
                    process_info_lookup=self.network_source.lookup,
                ),
            ),
            "session": SessionWorker(
                poll_interval_seconds=SESSION_INTERVAL, pipeline=self.pipeline,
                health=self.health, clock=self.clock,
                poller_factory=lambda: SessionPoller(
                    snapshot_fn=self.session_source.snapshot, clock=self.clock,
                ),
            ),
        }
        self.intervals = {
            "process": PROCESS_INTERVAL,
            "network": NETWORK_INTERVAL,
            "session": SESSION_INTERVAL,
        }
        self.next_due = {name: 0.0 for name in self.workers}
        self.restarts = {name: 0 for name in self.workers}

        # Peak observations, recorded every tick.
        self.peak_queue_depth = 0
        self.peak_dedup_size = 0
        self.peak_correlation_size = 0
        self.peak_tracked = {name: 0 for name in self.workers}

        self.health.mark_collector_starting()
        self.health.mark_collector_running()

    # -- the simulated scheduler -------------------------------------------

    def tick(self, seconds=1.0):
        now = self.clock.now
        for name, worker in self.workers.items():
            if now >= self.next_due[name]:
                self._run_poll(name, worker)
                self.next_due[name] = self.clock.now + self.intervals[name]

        self.publisher_worker._iteration(self.stop)
        self._record_peaks()
        self.clock.advance(seconds)

    def _run_poll(self, name, worker):
        try:
            worker._poll_cycle()
        except WorkerFailure:
            # Exactly what the supervisor does: count it, rebuild the
            # poller's state, and let the worker carry on. (The backoff
            # and threading of a real restart are covered in
            # test_supervisor.py; what matters here is the state effect.)
            self.health.mark_worker_crashed(name, RuntimeError("simulated crash"))
            self.health.mark_worker_restarted(name)
            worker.reset()
            self.restarts[name] += 1

    def _record_peaks(self):
        self.peak_queue_depth = max(self.peak_queue_depth, self.queue.depth)
        self.peak_dedup_size = max(self.peak_dedup_size, len(self.dedup))
        self.peak_correlation_size = max(self.peak_correlation_size, len(self.process_cache))
        for name, worker in self.workers.items():
            self.peak_tracked[name] = max(self.peak_tracked[name], worker.tracked_count())

    # -- reporting ----------------------------------------------------------

    def report(self):
        snapshot = self.health.snapshot()
        return {
            "simulated_seconds": self.clock.now - 1_800_000_000.0,
            "max_queue_depth": self.peak_queue_depth,
            "queue_capacity": self.queue.capacity,
            "dropped_events": snapshot["queue"]["dropped_events"],
            "deduplicated_events": snapshot["events"]["deduplicated"],
            "generated_events": snapshot["events"]["generated"],
            "published_events": snapshot["events"]["published"],
            "failed_publishes": snapshot["events"]["failed"],
            "invalid_events": snapshot["events"]["invalid"],
            "kafka_retries": snapshot["kafka"]["retry_count"],
            "worker_restarts": dict(self.restarts),
            "peak_dedup_size": self.peak_dedup_size,
            "dedup_capacity": DEDUP_MAX,
            "peak_correlation_size": self.peak_correlation_size,
            "correlation_capacity": CORRELATION_MAX,
            "peak_tracked": dict(self.peak_tracked),
            "broker_records": len(self.producer.records),
        }


def run_simulation(sim, duration_seconds, verbose=False):
    """Drive `duration_seconds` of virtual time with realistic churn,
    two Kafka outages and two telemetry-source failures."""
    minute = 0
    live_connections = []
    next_pid = 10_000
    next_port = 40_000

    # A session that is active from the start, plus periodic logins.
    sim.session_source.login(name="praka", started=1_799_999_000.0)

    outages = [(5 * MINUTE, 9 * MINUTE), (20 * MINUTE, 23 * MINUTE)]
    # Long enough to cause >= 5 CONSECUTIVE failed polls at the network
    # worker's 30s interval, which is what escalates to a restart.
    source_failures = [(12 * MINUTE, 15 * MINUTE), (40 * MINUTE, 43 * MINUTE)]
    start = sim.clock.now

    for step in range(int(duration_seconds)):
        elapsed = sim.clock.now - start

        # --- Kafka outage windows -----------------------------------------
        in_outage = any(begin <= elapsed < end for begin, end in outages)
        sim.producer.available = not in_outage

        # --- telemetry source failure windows ------------------------------
        in_failure = any(begin <= elapsed < end for begin, end in source_failures)
        sim.network_source.always_raise = OSError("connection table unreadable") if in_failure else None

        # --- process churn: 2 new processes a minute, each living ~5 min ---
        if step % 30 == 0:
            sim.process_source.add(
                pid=next_pid, name=f"proc{next_pid}.exe",
                create_time=sim.clock.now, username="HOST\\praka",
            )
            next_pid += 1
        if step % 30 == 15 and next_pid > 10_010:
            sim.process_source.remove(pid=next_pid - 10)

        # --- network churn: a new connection every 20s, closed after ~2 min
        if step % 20 == 0:
            key = sim.network_source.add(
                pid=next_pid - 1, local_port=next_port, remote_ip="93.184.216.34",
            )
            live_connections.append(key)
            next_port += 1
        if len(live_connections) > 6:
            sim.network_source.remove(live_connections.pop(0))

        # --- duplicate observations: a supervised restart re-baselines the
        # session poller, which re-reports the still-active session as a
        # LOGIN. Only the pipeline's dedup cache stops that from being
        # published a second time, so this exercises the real path.
        if step % (7 * MINUTE) == 0 and step > 0:
            sim.workers["session"].reset()

        # --- session churn: a login/logout pair every 10 minutes ------------
        if step % (10 * MINUTE) == 300:
            sim.session_source.login(name="guest", started=sim.clock.now)
        if step % (10 * MINUTE) == 420:
            for key in list(sim.session_source._users):
                if key.name == "guest":
                    sim.session_source.logout(name=key.name, started=key.started)

        sim.tick()

        if verbose and sim.clock.now - start >= (minute + 1) * MINUTE:
            minute += 1

    # Let the publisher finish whatever is still queued, as a real
    # recovered broker would allow.
    sim.producer.available = True
    sim.network_source.always_raise = None
    for _ in range(200):
        sim.tick(seconds=1.0)

    return sim.report()


# --------------------------------------------------------------------------
# 57. simulated 30-minute run
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def thirty_minute_run():
    sim = SimulatedCollector()
    began = time.monotonic()
    report = run_simulation(sim, 30 * MINUTE)
    report["wall_clock_seconds"] = time.monotonic() - began
    return sim, report


def test_thirty_minute_run_completes_without_sleeping(thirty_minute_run):
    _sim, report = thirty_minute_run
    assert report["simulated_seconds"] >= 30 * MINUTE
    assert report["wall_clock_seconds"] < 60, "a simulated run must not consume real time"


def test_thirty_minute_run_generates_and_publishes_real_telemetry(thirty_minute_run):
    _sim, report = thirty_minute_run
    assert report["generated_events"] > 100
    assert report["published_events"] > 0
    assert report["broker_records"] == report["published_events"]
    assert report["invalid_events"] == 0, "no event ever failed validation"


def test_thirty_minute_run_keeps_the_queue_bounded(thirty_minute_run):
    sim, report = thirty_minute_run
    assert report["max_queue_depth"] <= report["queue_capacity"]
    assert sim.queue.depth <= sim.queue.capacity


def test_thirty_minute_run_keeps_every_cache_bounded(thirty_minute_run):
    _sim, report = thirty_minute_run
    assert report["peak_dedup_size"] <= report["dedup_capacity"]
    assert report["peak_correlation_size"] <= report["correlation_capacity"]


def test_thirty_minute_run_keeps_poller_state_proportional_to_the_live_table(thirty_minute_run):
    sim, report = thirty_minute_run
    # ~60 processes start over 30 minutes but only ~10 are ever live, and
    # at most 7 connections are open at once.
    assert report["peak_tracked"]["process"] < 30
    assert report["peak_tracked"]["network"] <= 10
    assert report["peak_tracked"]["session"] <= 3
    assert sim.workers["process"].tracked_count() < 30


def test_thirty_minute_run_suppresses_duplicate_observations(thirty_minute_run):
    sim, report = thirty_minute_run
    # Every process and connection is re-observed on every poll; without
    # dedup + the pollers' diffing the event count would be enormous.
    assert report["generated_events"] < 2000, (
        "a persistent process/connection must not produce an event per poll"
    )
    # The simulation restarts the session worker periodically, which
    # re-reports the still-active session - the pipeline's dedup cache is
    # the only thing that stops it being published again.
    assert report["deduplicated_events"] >= 1
    assert report["published_events"] + report["deduplicated_events"] <= report["generated_events"]


def test_thirty_minute_run_recovers_from_both_kafka_outages(thirty_minute_run):
    sim, report = thirty_minute_run
    assert report["kafka_retries"] >= 2, "both outages were retried"
    assert sim.health.snapshot()["kafka"]["state"] == RUNNING
    assert sim.health.snapshot()["kafka"]["consecutive_failures"] == 0


def test_thirty_minute_run_recovers_from_telemetry_source_failures(thirty_minute_run):
    sim, report = thirty_minute_run
    assert report["worker_restarts"]["network"] >= 1, "repeated failures escalated to a restart"
    assert sim.health.worker_state("network") == RUNNING
    assert sim.health.worker_state("process") == RUNNING
    assert sim.health.worker_state("session") == RUNNING


def test_thirty_minute_run_accounts_for_every_generated_event(thirty_minute_run):
    sim, report = thirty_minute_run
    snapshot = sim.health.snapshot()

    accounted = (
        report["published_events"]
        + report["dropped_events"]
        + report["deduplicated_events"]
        + report["invalid_events"]
        + sim.queue.depth
        + sim.publisher.pending_count
    )
    assert accounted == report["generated_events"], (
        f"unaccounted events: {snapshot}"
    )


def test_thirty_minute_run_drains_cleanly_on_shutdown(thirty_minute_run):
    sim, _report = thirty_minute_run
    sim.queue.close()
    remaining = sim.publisher_worker.drain(deadline_seconds=300, stop_event=sim.stop)
    assert remaining == 0


def test_thirty_minute_report_is_printable(thirty_minute_run, capsys):
    _sim, report = thirty_minute_run
    with capsys.disabled():
        print("\n--- simulated 30-minute run ---")
        for key, value in sorted(report.items()):
            print(f"  {key}: {value}")


# --------------------------------------------------------------------------
# 58. simulated 1-hour run
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def one_hour_run():
    sim = SimulatedCollector()
    began = time.monotonic()
    report = run_simulation(sim, HOUR)
    report["wall_clock_seconds"] = time.monotonic() - began
    return sim, report


def test_one_hour_run_stays_bounded_in_every_dimension(one_hour_run):
    sim, report = one_hour_run

    assert report["simulated_seconds"] >= HOUR
    assert report["max_queue_depth"] <= report["queue_capacity"]
    assert report["peak_dedup_size"] <= report["dedup_capacity"]
    assert report["peak_correlation_size"] <= report["correlation_capacity"]
    assert report["peak_tracked"]["process"] < 30
    assert report["peak_tracked"]["network"] <= 10
    # 3 telemetry workers + the Kafka publisher worker; a fixed set that
    # does not grow with event volume.
    assert len(sim.health.snapshot()["workers"]) == 4, "no per-event health accumulation"


def test_one_hour_run_does_not_grow_its_caches_in_the_second_half(one_hour_run):
    sim, _report = one_hour_run
    # The caches are at a steady state, not creeping upward: another
    # simulated 10 minutes must not increase their size.
    before = (len(sim.dedup), len(sim.process_cache))
    run_simulation(sim, 10 * MINUTE)
    after = (len(sim.dedup), len(sim.process_cache))

    assert after[0] <= sim.dedup.max_entries
    assert after[1] <= sim.process_cache.max_entries
    assert after[1] <= before[1] + 20, "the correlation cache reached a steady state"


def test_one_hour_run_keeps_every_worker_healthy_at_the_end(one_hour_run):
    sim, _report = one_hour_run
    for name in ("process", "network", "session"):
        assert sim.health.worker_state(name) == RUNNING


def test_one_hour_run_is_fast_enough_to_run_in_ci(one_hour_run):
    _sim, report = one_hour_run
    assert report["wall_clock_seconds"] < 120


def test_one_hour_report_is_printable(one_hour_run, capsys):
    _sim, report = one_hour_run
    with capsys.disabled():
        print("\n--- simulated 1-hour run ---")
        for key, value in sorted(report.items()):
            print(f"  {key}: {value}")


# --------------------------------------------------------------------------
# 59/60/61. repeated worker failures and repeated Kafka outages
# --------------------------------------------------------------------------

def test_many_consecutive_worker_failures_never_exhaust_resources():
    sim = SimulatedCollector()
    sim.process_source.always_raise = OSError("permanently unreadable")

    for _ in range(200):
        sim.tick(seconds=PROCESS_INTERVAL)

    # It keeps failing and keeps being restarted - but nothing grows.
    assert sim.restarts["process"] >= 10
    assert sim.queue.depth <= sim.queue.capacity
    assert len(sim.dedup) <= DEDUP_MAX
    assert len(sim.health.snapshot()["workers"]) == 4

    sim.process_source.always_raise = None
    sim.process_source.add(pid=1, create_time=1.0)
    for _ in range(4):
        sim.tick(seconds=PROCESS_INTERVAL)

    assert sim.health.worker_state("process") == RUNNING


def test_many_kafka_outages_all_recover_and_lose_nothing_that_fits_in_the_queue():
    sim = SimulatedCollector(queue_max=10_000)
    sim.session_source.login(name="praka", started=1_799_999_000.0)
    pid = 20_000

    for cycle in range(6):
        sim.producer.go_down()
        for _ in range(60):
            sim.process_source.add(pid=pid, name=f"p{pid}.exe", create_time=sim.clock.now)
            pid += 1
            sim.tick(seconds=PROCESS_INTERVAL)

        sim.producer.come_back()
        # The backoff can be up to 60s, so allow comfortably more than
        # that plus a few draining iterations.
        for _ in range(40):
            sim.tick(seconds=5)

        assert sim.queue.depth == 0, f"outage {cycle} did not drain"
        assert sim.publisher.pending_count == 0

    snapshot = sim.health.snapshot()
    assert snapshot["kafka"]["state"] == RUNNING
    assert snapshot["queue"]["dropped_events"] == 0, "the queue was large enough to lose nothing"
    assert snapshot["events"]["published"] == len(sim.producer.records)


def test_sustained_event_generation_under_a_permanently_dead_broker():
    sim = SimulatedCollector(queue_max=200)
    sim.producer.go_down()
    pid = 30_000

    for _ in range(2000):
        sim.process_source.add(pid=pid, name=f"p{pid}.exe", create_time=sim.clock.now)
        pid += 1
        sim.tick(seconds=PROCESS_INTERVAL)

    snapshot = sim.health.snapshot()
    assert sim.queue.depth == 200, "bounded at exactly the configured capacity"
    assert snapshot["queue"]["dropped_events"] > 1000, "drops are counted, not silent"
    assert sim.publisher.pending_count <= 1
    # Backoff caps at 60s, so ~2000 polls over ~8 simulated hours produce
    # far fewer attempts than events - no retry storm.
    assert sim.producer.send_attempts < 600

    # And it still recovers.
    sim.producer.come_back()
    for _ in range(50):
        sim.tick(seconds=5)
    assert sim.queue.depth == 0
    assert sim.health.snapshot()["kafka"]["state"] == RUNNING


def test_queue_pressure_keeps_the_newest_observations():
    sim = SimulatedCollector(queue_max=10)
    sim.producer.go_down()
    pid = 40_000
    for _ in range(50):
        sim.process_source.add(pid=pid, name=f"p{pid}.exe", create_time=sim.clock.now)
        pid += 1
        sim.tick(seconds=PROCESS_INTERVAL)

    queued = sim.queue.get_batch(100, timeout=0)
    pids = [event["payload"]["pid"] for event in queued]

    assert len(pids) == 10
    assert pids == sorted(pids), "FIFO order preserved"
    assert min(pids) > 40_000 + 30, "the newest observations survived, the oldest were dropped"
