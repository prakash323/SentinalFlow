"""
Health model tests (PHASE S items 42-46).

Health is how this collector is observable without a web API, so the
state machine (RUNNING -> DEGRADED -> RUNNING, FAILED -> STARTING) and
the counters are tested directly, including that the snapshot is a copy
and that the whole registry stays a fixed size over a long run.
"""
import threading

from fakes import VirtualClock
from health import (
    DEGRADED,
    FAILED,
    RUNNING,
    STARTING,
    STOPPED,
    STOPPING,
    HealthRegistry,
    unhealthy_workers,
)


def _registry():
    clock = VirtualClock()
    return HealthRegistry(clock=clock), clock


# --------------------------------------------------------------------------
# 42. worker health
# --------------------------------------------------------------------------

def test_a_registered_worker_starts_in_starting():
    registry, _clock = _registry()
    registry.register_worker("process")
    assert registry.worker_state("process") == STARTING


def test_a_successful_poll_marks_the_worker_running_and_counts_it():
    registry, clock = _registry()
    registry.register_worker("process")
    clock.advance(10)
    registry.mark_worker_poll_succeeded("process")

    worker = registry.snapshot()["workers"]["process"]
    assert worker["state"] == RUNNING
    assert worker["poll_count"] == 1
    assert worker["last_success"] == clock.now


def test_a_failed_poll_degrades_the_worker_without_failing_it():
    registry, _clock = _registry()
    registry.register_worker("network")
    registry.mark_worker_poll_failed("network", OSError("access denied"))

    worker = registry.snapshot()["workers"]["network"]
    assert worker["state"] == DEGRADED
    assert worker["error_count"] == 1
    assert "OSError" in worker["last_error"]


def test_a_crash_marks_the_worker_failed():
    registry, _clock = _registry()
    registry.register_worker("session")
    registry.mark_worker_crashed("session", RuntimeError("boom"))

    assert registry.worker_state("session") == FAILED


def test_a_restart_counts_and_returns_the_worker_to_starting():
    registry, _clock = _registry()
    registry.register_worker("process")
    registry.mark_worker_crashed("process", RuntimeError("boom"))
    registry.mark_worker_restarted("process")

    worker = registry.snapshot()["workers"]["process"]
    assert worker["state"] == STARTING
    assert worker["restart_count"] == 1


def test_worker_failure_is_isolated_in_the_health_model():
    registry, _clock = _registry()
    for name in ("process", "network", "session"):
        registry.register_worker(name)
        registry.mark_worker_poll_succeeded(name)

    registry.mark_worker_crashed("process", RuntimeError("boom"))

    workers = registry.snapshot()["workers"]
    assert workers["process"]["state"] == FAILED
    assert workers["network"]["state"] == RUNNING
    assert workers["session"]["state"] == RUNNING


# --------------------------------------------------------------------------
# 46. health transitions
# --------------------------------------------------------------------------

def test_a_degraded_worker_recovers_on_its_next_successful_poll():
    registry, _clock = _registry()
    registry.register_worker("network")
    registry.mark_worker_poll_succeeded("network")
    registry.mark_worker_poll_failed("network", OSError("transient"))
    assert registry.worker_state("network") == DEGRADED

    registry.mark_worker_poll_succeeded("network")
    assert registry.worker_state("network") == RUNNING

    # The error history is kept - recovery does not erase the evidence.
    assert registry.snapshot()["workers"]["network"]["error_count"] == 1


def test_collector_lifecycle_states():
    registry, clock = _registry()
    registry.mark_collector_starting()
    assert registry.collector_state == STARTING

    registry.mark_collector_running()
    assert registry.collector_state == RUNNING

    clock.advance(120)
    assert registry.uptime_seconds() == 120

    registry.mark_collector_stopping()
    assert registry.collector_state == STOPPING
    registry.mark_collector_stopped()
    assert registry.collector_state == STOPPED


def test_uptime_is_zero_before_the_collector_starts():
    registry, _clock = _registry()
    assert registry.uptime_seconds() == 0.0


def test_unhealthy_workers_lists_everything_not_running():
    registry, _clock = _registry()
    registry.register_worker("process")
    registry.register_worker("network")
    registry.mark_worker_poll_succeeded("network")

    assert unhealthy_workers(registry.snapshot()) == ["process"]


# --------------------------------------------------------------------------
# 43. Kafka health
# --------------------------------------------------------------------------

def test_a_successful_publish_clears_consecutive_failures():
    registry, clock = _registry()
    registry.mark_publish_failed(OSError("broker down"))
    registry.mark_publish_failed(OSError("broker down"))
    assert registry.snapshot()["kafka"]["consecutive_failures"] == 2
    assert registry.snapshot()["kafka"]["state"] == DEGRADED

    clock.advance(5)
    registry.mark_publish_succeeded()

    kafka = registry.snapshot()["kafka"]
    assert kafka["state"] == RUNNING
    assert kafka["consecutive_failures"] == 0
    assert kafka["last_successful_publish"] == clock.now


def test_publish_failures_are_counted_as_failed_events():
    registry, _clock = _registry()
    registry.mark_publish_failed(OSError("x"))
    assert registry.snapshot()["events"]["failed"] == 1


def test_retries_are_counted():
    registry, _clock = _registry()
    registry.mark_kafka_retry()
    registry.mark_kafka_retry()
    assert registry.snapshot()["kafka"]["retry_count"] == 2


def test_a_batch_publish_increments_published_by_the_batch_size():
    registry, _clock = _registry()
    registry.mark_publish_succeeded(count=10)
    assert registry.snapshot()["events"]["published"] == 10
    assert registry.snapshot()["queue"]["total_published"] == 10


# --------------------------------------------------------------------------
# 44. queue health
# --------------------------------------------------------------------------

def test_queue_depth_tracks_the_running_maximum():
    registry, _clock = _registry()
    registry.set_queue_capacity(100)
    registry.record_queue_depth(10)
    registry.record_queue_depth(75)
    registry.record_queue_depth(3)

    queue = registry.snapshot()["queue"]
    assert queue["current_depth"] == 3
    assert queue["max_depth"] == 75
    assert queue["capacity"] == 100


def test_dropped_events_are_counted_in_both_places():
    registry, _clock = _registry()
    registry.mark_event_dropped(count=4)

    assert registry.snapshot()["queue"]["dropped_events"] == 4
    assert registry.snapshot()["events"]["dropped"] == 4


# --------------------------------------------------------------------------
# 45. event counters
# --------------------------------------------------------------------------

def test_every_pipeline_counter_increments_independently():
    registry, _clock = _registry()
    registry.mark_event_generated()
    registry.mark_event_normalized()
    registry.mark_event_validated()
    registry.mark_event_deduplicated()
    registry.mark_event_invalid()
    registry.mark_event_enqueued()

    events = registry.snapshot()["events"]
    assert events["generated"] == 1
    assert events["normalized"] == 1
    assert events["validated"] == 1
    assert events["deduplicated"] == 1
    assert events["invalid"] == 1
    assert registry.snapshot()["queue"]["total_enqueued"] == 1


# --------------------------------------------------------------------------
# Snapshot and resource properties
# --------------------------------------------------------------------------

def test_the_snapshot_is_a_copy_not_a_live_view():
    registry, _clock = _registry()
    registry.register_worker("process")
    snapshot = registry.snapshot()

    registry.mark_worker_poll_succeeded("process")
    registry.mark_event_generated()

    assert snapshot["workers"]["process"]["state"] == STARTING
    assert snapshot["events"]["generated"] == 0


def test_the_registry_stays_a_fixed_size_over_a_long_run():
    registry, clock = _registry()
    registry.register_worker("process")

    for n in range(100_000):
        registry.mark_event_generated()
        registry.mark_worker_poll_succeeded("process")
        registry.record_queue_depth(n % 50)
        clock.advance(0.1)

    snapshot = registry.snapshot()
    assert len(snapshot["workers"]) == 1, "no per-event or per-sample accumulation"
    assert snapshot["events"]["generated"] == 100_000
    assert snapshot["workers"]["process"]["poll_count"] == 100_000


def test_a_long_error_message_is_truncated_rather_than_stored_whole():
    registry, _clock = _registry()
    registry.register_worker("process")
    registry.mark_worker_poll_failed("process", RuntimeError("x" * 5000))

    stored = registry.snapshot()["workers"]["process"]["last_error"]
    assert len(stored) <= 200
    assert stored.endswith("...")


def test_reporting_for_an_unregistered_worker_does_not_raise():
    registry, _clock = _registry()
    registry.mark_worker_poll_succeeded("surprise")
    assert registry.worker_state("surprise") == RUNNING


def test_heartbeat_line_summarizes_without_any_payload():
    registry, _clock = _registry()
    registry.mark_collector_starting()
    registry.mark_collector_running()
    registry.set_queue_capacity(5000)
    registry.register_worker("process")
    registry.mark_worker_poll_succeeded("process")
    registry.record_queue_depth(12)
    registry.mark_publish_succeeded(count=3)

    line = registry.heartbeat_line()

    assert "state=RUNNING" in line
    assert "queue=12/5000" in line
    assert "published=3" in line
    assert "process=RUNNING" in line
    assert "payload" not in line


def test_concurrent_reporting_is_thread_safe():
    registry, _clock = _registry()
    registry.register_worker("process")
    errors = []

    def hammer():
        try:
            for _ in range(2000):
                registry.mark_event_generated()
                registry.mark_worker_poll_succeeded("process")
                registry.snapshot()
        except Exception as error:  # pragma: no cover
            errors.append(error)

    threads = [threading.Thread(target=hammer) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors
    assert registry.snapshot()["events"]["generated"] == 12_000
