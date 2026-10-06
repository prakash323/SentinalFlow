"""
Collector lifecycle tests (PHASE S items 47-51 and 56, PHASE W
start/stop repeatability).

These run the REAL CollectorApp with real threads, real supervisors, the
real pipeline/queue and the real EventPublisher - only the OS telemetry
sources and kafka.KafkaProducer are faked. Intervals are set to
milliseconds so the suite stays fast without sleeping on guesses:
conditions are polled with wait_until().
"""
import threading
import time

import pytest

from app import CollectorApp
from config import Config
from fakes import FakeKafkaProducer, FakeNetworkSource, FakeProcessSource, FakeSessionSource
from health import RUNNING, STOPPED, STOPPING
from kafka_producer import EventPublisher
from network_poller import NetworkPoller
from process_poller import ProcessPoller
from session_poller import SessionPoller
from workers import NetworkWorker, ProcessWorker, SessionWorker


def wait_until(predicate, timeout=5.0, interval=0.005):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class Rig:
    """A CollectorApp whose telemetry sources and broker are fakes."""

    def __init__(self, broker_available=True, queue_max_size=1000,
                 shutdown_timeout=5.0, interval=0.01, **config_overrides):
        self.process_source = FakeProcessSource()
        self.network_source = FakeNetworkSource()
        self.session_source = FakeSessionSource()
        self.producer = FakeKafkaProducer(available=broker_available)
        self.producers_created = 0

        self.config = Config(
            entity_id="HOST-TEST",
            poll_interval_seconds=interval,
            process_poll_interval_seconds=interval,
            network_poll_interval_seconds=interval,
            queue_max_size=queue_max_size,
            shutdown_timeout_seconds=shutdown_timeout,
            heartbeat_interval_seconds=0.05,
            kafka_retry_base_delay_seconds=0.05,
            kafka_retry_max_delay_seconds=0.2,
            worker_restart_base_delay_seconds=0.01,
            worker_restart_max_delay_seconds=0.05,
            **config_overrides,
        ).validate()

        self.app = CollectorApp(
            self.config,
            publisher_factory=self._publisher_factory,
            worker_factories=[
                self._process_worker, self._network_worker, self._session_worker,
            ],
        )

    # -- injected pieces ----------------------------------------------------

    def _publisher_factory(self):
        self.producers_created += 1
        return EventPublisher(
            bootstrap_servers="fake:9094",
            topic=self.config.topic,
            retry_base_delay=self.config.kafka_retry_base_delay_seconds,
            retry_max_delay=self.config.kafka_retry_max_delay_seconds,
            health=self.app.health,
            producer_factory=lambda **kwargs: self.producer,
        )

    def _process_worker(self, app):
        return ProcessWorker(
            poll_interval_seconds=app.config.process_poll_interval_seconds,
            pipeline=app.pipeline, health=app.health, process_cache=app.process_cache,
            poller_factory=lambda: ProcessPoller(
                snapshot_fn=self.process_source.snapshot,
                executable_lookup=self.process_source.executable_lookup,
            ),
        )

    def _network_worker(self, app):
        return NetworkWorker(
            poll_interval_seconds=app.config.network_poll_interval_seconds,
            pipeline=app.pipeline, health=app.health,
            poller_factory=lambda: NetworkPoller(
                snapshot_fn=self.network_source.snapshot,
                process_info_lookup=self.network_source.lookup,
            ),
        )

    def _session_worker(self, app):
        return SessionWorker(
            poll_interval_seconds=app.config.poll_interval_seconds,
            pipeline=app.pipeline, health=app.health,
            poller_factory=lambda: SessionPoller(snapshot_fn=self.session_source.snapshot),
        )

    # -- helpers ------------------------------------------------------------

    def published_event_types(self):
        import json
        return [json.loads(value)["eventType"] for _key, value in self.producer.records]


@pytest.fixture
def rig():
    rig = Rig()
    yield rig
    if not rig.app._stopped:
        rig.app.stop()


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------

def test_start_brings_every_subsystem_up(rig):
    rig.app.start()

    assert wait_until(lambda: rig.app.health.collector_state == RUNNING)
    assert wait_until(lambda: all(
        info["state"] == RUNNING
        for info in rig.app.health.snapshot()["workers"].values()
    ))

    workers = rig.app.health.snapshot()["workers"]
    assert set(workers) == {"process", "network", "session", "kafka-publisher"}
    assert rig.app.telemetry_supervisor.live_thread_count() == 3
    assert rig.app.publisher_supervisor.live_thread_count() == 1


def test_real_telemetry_flows_from_source_to_broker(rig):
    rig.session_source.login(name="praka", started=1_800_000_000.0)
    rig.app.start()

    assert wait_until(lambda: rig.producer.published_keys)
    rig.process_source.add(pid=4242, name="notepad.exe", create_time=1_800_000_100.0)

    assert wait_until(lambda: "PROCESS_START" in rig.published_event_types())
    assert "LOGIN" in rig.published_event_types()

    events = rig.app.health.snapshot()["events"]
    assert events["generated"] >= 2
    assert events["published"] >= 2


def test_starting_twice_is_refused(rig):
    rig.app.start()
    with pytest.raises(RuntimeError, match="already started"):
        rig.app.start()


def test_one_producer_is_created_for_the_whole_run(rig):
    rig.app.start()
    assert wait_until(lambda: rig.producers_created == 1)

    rig.process_source.add(pid=1, create_time=1.0)
    assert wait_until(lambda: rig.producer.published_keys)
    time.sleep(0.1)

    assert rig.producers_created == 1, "no duplicate Kafka producer connections"


def test_the_collector_starts_even_when_the_broker_is_unreachable():
    rig = Rig(broker_available=False)
    rig.session_source.login()
    rig.app.start()
    try:
        assert wait_until(lambda: rig.app.health.collector_state == RUNNING)
        assert wait_until(lambda: rig.app.health.snapshot()["events"]["generated"] >= 1)
        assert rig.producer.published_keys == []
        assert wait_until(lambda: rig.app.queue.depth >= 1 or
                          rig.app.publisher.pending_count >= 1)
    finally:
        rig.app.stop()


def test_a_producer_that_cannot_be_constructed_does_not_stop_telemetry():
    rig = Rig()
    attempts = {"n": 0}
    real_factory = rig._publisher_factory

    def flaky_factory():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise OSError("NoBrokersAvailable")
        return real_factory()

    rig.app = CollectorApp(
        rig.config, publisher_factory=flaky_factory,
        worker_factories=[rig._process_worker, rig._network_worker, rig._session_worker],
    )
    rig.session_source.login()
    rig.app.start()
    try:
        assert wait_until(lambda: rig.app.health.snapshot()["events"]["generated"] >= 1)
        assert wait_until(lambda: rig.producer.published_keys, timeout=10)
        assert attempts["n"] >= 3
    finally:
        rig.app.stop()


# --------------------------------------------------------------------------
# 47/48/49/50/51. shutdown
# --------------------------------------------------------------------------

def test_request_stop_releases_the_run_loop(rig):
    rig.app.start()
    finished = threading.Event()

    def run():
        rig.app.run()
        finished.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    rig.app.request_stop()  # what the SIGINT handler does

    assert finished.wait(timeout=5), "run() did not return after request_stop()"
    thread.join(timeout=5)
    rig.app.stop()


def test_shutdown_stops_every_worker_thread(rig):
    rig.app.start()
    assert wait_until(lambda: rig.app.telemetry_supervisor.live_thread_count() == 3)

    result = rig.app.stop()

    assert result["stuck_workers"] == []
    assert rig.app.telemetry_supervisor.live_thread_count() == 0
    assert rig.app.publisher_supervisor.live_thread_count() == 0
    assert rig.app.health.collector_state == STOPPED
    assert all(
        info["state"] == STOPPED
        for info in rig.app.health.snapshot()["workers"].values()
    )


def test_shutdown_drains_the_queue_and_closes_the_producer(rig):
    rig.app.start()
    assert wait_until(lambda: rig.app.health.collector_state == RUNNING)

    for pid in range(200):
        rig.process_source.add(pid=pid, create_time=float(pid))
    assert wait_until(lambda: rig.app.health.snapshot()["events"]["generated"] >= 150)

    result = rig.app.stop()

    assert result["remaining_events"] == 0
    assert rig.app.queue.depth == 0
    assert rig.producer.flush_calls == 1
    assert rig.producer.close_calls == 1


def test_shutdown_stops_new_telemetry_from_being_queued(rig):
    rig.app.start()
    assert wait_until(lambda: rig.app.health.collector_state == RUNNING)
    rig.app.stop()

    enqueued_before = rig.app.health.snapshot()["queue"]["total_enqueued"]
    rig.app.pipeline.submit.__self__  # the pipeline object still exists
    from process_poller import ProcessEvent
    rig.app.pipeline.submit(ProcessEvent(
        pid=99999, name="late.exe", ppid=1, create_time=9999.0,
        username=None, executable_path=None,
    ))

    assert rig.app.queue.closed is True
    assert rig.app.health.snapshot()["queue"]["total_enqueued"] == enqueued_before


def test_shutdown_reports_events_it_could_not_publish():
    rig = Rig(broker_available=False, queue_max_size=50, shutdown_timeout=0.1)
    rig.session_source.login()
    rig.app.start()
    try:
        assert wait_until(lambda: rig.app.health.snapshot()["events"]["generated"] >= 1)
        result = rig.app.stop()
        assert result["remaining_events"] >= 1, "the loss is reported, not hidden"
    finally:
        if not rig.app._stopped:
            rig.app.stop()


def test_shutdown_never_exceeds_its_timeout_budget():
    rig = Rig(broker_available=False, shutdown_timeout=0.2)
    rig.session_source.login()
    rig.app.start()
    assert wait_until(lambda: rig.app.health.snapshot()["events"]["generated"] >= 1)

    began = time.monotonic()
    rig.app.stop()
    elapsed = time.monotonic() - began

    # Three bounded phases (worker join, publisher join, drain), each
    # capped by the same budget - never unbounded.
    assert elapsed < 0.2 * 3 + 2.0


def test_stop_is_idempotent(rig):
    rig.app.start()
    rig.app.stop()
    assert rig.app.stop() == {"already_stopped": True}
    assert rig.producer.close_calls == 1


def test_stop_without_start_does_not_raise(rig):
    result = rig.app.stop()
    assert result["remaining_events"] == 0


def test_the_collector_marks_itself_stopping_before_stopped(rig):
    states = []
    rig.app.start()
    original = rig.app.health.mark_collector_stopped

    def record():
        states.append(rig.app.health.collector_state)
        original()

    rig.app.health.mark_collector_stopped = record
    rig.app.stop()

    assert states == [STOPPING]


def test_a_second_stop_request_escalates_the_drain(rig):
    rig.app.start()
    rig.app.request_stop()
    assert rig.app._force_stop.is_set() is False
    rig.app.request_stop()
    assert rig.app._force_stop.is_set() is True


def test_context_manager_starts_and_stops(rig):
    with rig.app as app:
        assert wait_until(lambda: app.health.collector_state == RUNNING)
    assert rig.app.health.collector_state == STOPPED
    assert rig.app.telemetry_supervisor.live_thread_count() == 0


# --------------------------------------------------------------------------
# PHASE W. start / run / shutdown repeatability
# --------------------------------------------------------------------------

def test_repeated_start_and_shutdown_cycles_are_clean():
    threads_before = threading.active_count()

    for cycle in range(4):
        rig = Rig()
        rig.session_source.login(name="praka", started=1_800_000_000.0 + cycle)
        rig.app.start()
        assert wait_until(lambda: rig.app.health.collector_state == RUNNING)
        rig.process_source.add(pid=1000 + cycle, create_time=float(cycle))
        assert wait_until(lambda: rig.producer.published_keys)

        result = rig.app.stop()

        assert result["stuck_workers"] == []
        assert result["remaining_events"] == 0
        assert rig.app.telemetry_supervisor.live_thread_count() == 0
        assert rig.producers_created == 1
        assert rig.producer.close_calls == 1

    assert wait_until(lambda: threading.active_count() <= threads_before + 1), (
        "threads leaked across start/stop cycles"
    )


def test_a_failed_startup_then_a_clean_restart():
    # Startup failure: the broker never comes up during the first run.
    failed = Rig(broker_available=False, shutdown_timeout=0.1)
    failed.session_source.login()
    failed.app.start()
    assert wait_until(lambda: failed.app.health.snapshot()["events"]["generated"] >= 1)
    failed.app.stop()
    assert failed.app.telemetry_supervisor.live_thread_count() == 0

    # A fresh collector in the same process starts cleanly.
    healthy = Rig()
    healthy.session_source.login(name="praka", started=1_800_000_500.0)
    healthy.app.start()
    try:
        assert wait_until(lambda: healthy.app.health.collector_state == RUNNING)
        assert wait_until(lambda: healthy.producer.published_keys)
    finally:
        healthy.app.stop()


def test_two_collectors_in_one_process_do_not_share_state():
    # Proves there is no module-level mutable state anywhere.
    first = Rig()
    second = Rig()
    first.session_source.login(name="first", started=1.0)
    second.session_source.login(name="second", started=2.0)

    first.app.start()
    second.app.start()
    try:
        assert wait_until(lambda: first.producer.published_keys and second.producer.published_keys)
        assert first.app.queue is not second.app.queue
        assert first.app.health is not second.app.health
        assert len(first.producer.records) == 1
        assert len(second.producer.records) == 1
    finally:
        first.app.stop()
        second.app.stop()


# --------------------------------------------------------------------------
# Worker crash recovery inside the real app
# --------------------------------------------------------------------------

def test_a_crashing_telemetry_worker_is_restarted_while_the_rest_keep_running():
    rig = Rig()
    rig.process_source.always_raise = OSError("process table unreadable")
    rig.session_source.login(name="praka", started=1_800_000_000.0)
    rig.app.start()
    try:
        # 5 consecutive poll failures escalate to a supervised restart.
        assert wait_until(
            lambda: rig.app.health.snapshot()["workers"]["process"]["restart_count"] >= 1,
            timeout=10,
        )
        assert wait_until(lambda: rig.producer.published_keys, timeout=10)

        workers = rig.app.health.snapshot()["workers"]
        assert workers["network"]["state"] == RUNNING
        assert workers["session"]["state"] == RUNNING
        assert rig.app.telemetry_supervisor.live_thread_count() == 3

        # Once the OS source recovers, so does the worker.
        rig.process_source.always_raise = None
        rig.process_source.add(pid=777, create_time=777.0)
        assert wait_until(
            lambda: rig.app.health.worker_state("process") == RUNNING, timeout=10
        )
    finally:
        rig.app.stop()


def test_heartbeat_logs_a_summary_without_payloads(caplog):
    import logging

    rig = Rig()
    rig.session_source.login()
    rig.app.start()
    try:
        with caplog.at_level(logging.INFO, logger="sentinelflow.collector"):
            runner = threading.Thread(target=rig.app.run, daemon=True)
            runner.start()
            assert wait_until(
                lambda: any("Collector heartbeat" in r.getMessage() for r in caplog.records),
                timeout=5,
            )
            rig.app.request_stop()
            runner.join(timeout=5)

        heartbeats = [r.getMessage() for r in caplog.records if "Collector heartbeat" in r.getMessage()]
        assert heartbeats
        assert "state=RUNNING" in heartbeats[0]
        assert "loginSuccess" not in heartbeats[0]
    finally:
        rig.app.stop()
