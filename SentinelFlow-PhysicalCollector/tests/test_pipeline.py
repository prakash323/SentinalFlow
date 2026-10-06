"""
Common event pipeline tests (PHASE S items 19-23, plus deduplication
keys and process/network correlation).

The pipeline is the only path from a raw observation to the queue, so
these tests cover the contract the rest of SentinelFlow depends on:
envelope shape, eventType allowlist, timestamp format, dedup identity,
and the correlation enrichment the backend's
NEW_PROCESS_EXTERNAL_CONNECTION rule relies on.
"""
import json

import pytest

from correlation import ProcessMetadataCache
from dedup import BoundedDedupCache
from event_queue import BoundedEventQueue
from fakes import VirtualClock
from health import HealthRegistry
from network_poller import NetworkConnectionEvent
from pipeline import (
    KNOWN_EVENT_TYPES,
    MAX_EVENT_BYTES,
    EventPipeline,
    EventValidationError,
    dedup_key,
    validate_event,
)
from process_poller import ProcessEvent
from session_poller import SessionEvent

ENTITY = "HOST-TEST"


@pytest.fixture
def harness():
    clock = VirtualClock()

    class Harness:
        def __init__(self):
            self.clock = clock
            self.queue = BoundedEventQueue(max_size=100)
            self.health = HealthRegistry(clock=clock)
            self.health.set_queue_capacity(100)
            self.dedup = BoundedDedupCache(ttl_seconds=3600, max_entries=1000, clock=clock)
            self.process_cache = ProcessMetadataCache(ttl_seconds=300, max_entries=100, clock=clock)
            self.pipeline = EventPipeline(
                entity_id=ENTITY,
                queue=self.queue,
                dedup_cache=self.dedup,
                health=self.health,
                process_cache=self.process_cache,
                clock=clock,
            )

        def queued(self):
            return self.queue.get_batch(100, timeout=0)

    return Harness()


def _process(pid=500, name="python.exe", create_time=1_700_000_000.0):
    return ProcessEvent(
        pid=pid, name=name, ppid=4, create_time=create_time,
        username="HOST\\user", executable_path="C:\\python.exe",
    )


def _connection(pid=500, process_name="python.exe", process_create_time=1_700_000_000.0,
                remote_ip="93.184.216.34", local_port=50000):
    return NetworkConnectionEvent(
        protocol="TCP", local_address="192.168.1.2", local_port=local_port,
        remote_address=remote_ip, remote_port=443, status="ESTABLISHED",
        pid=pid, process_name=process_name, process_create_time=process_create_time,
    )


def _session(kind="LOGIN", username="praka", started=1_700_000_000.0, observed=1_700_000_060.0):
    return SessionEvent(
        kind=kind, username=username, started_epoch=started,
        observed_epoch=observed, host=None, terminal=None,
    )


# --------------------------------------------------------------------------
# 19. normalization - every source converges into the same envelope
# --------------------------------------------------------------------------

@pytest.mark.parametrize("observation,expected_type", [
    (_process(), "PROCESS_START"),
    (_connection(), "NETWORK_CONNECTION"),
    (_session("LOGIN"), "LOGIN"),
    (_session("LOGOUT"), "LOGOUT"),
])
def test_every_source_produces_the_canonical_envelope(harness, observation, expected_type):
    event = harness.pipeline.submit(observation)

    assert event is not None
    assert event["eventType"] == expected_type
    assert event["entityId"] == ENTITY
    assert event["eventVersion"] == "v1"
    assert event["source"] == "physical-collector"
    assert isinstance(event["payload"], dict)
    assert set(event) == {
        "eventId", "entityId", "eventType", "eventVersion",
        "occurredAt", "source", "payload",
    }


def test_a_queued_event_is_the_event_that_was_returned(harness):
    event = harness.pipeline.submit(_process())
    assert harness.queued() == [event]


def test_unsupported_observation_types_are_rejected_not_crashed(harness):
    assert harness.pipeline.submit(object()) is None
    assert harness.health.snapshot()["events"]["invalid"] == 1
    assert harness.queue.depth == 0


# --------------------------------------------------------------------------
# 20/21. validation + invalid event rejection
# --------------------------------------------------------------------------

def _valid_event():
    return {
        "eventId": "EV-PHYS-1-aaaaaa",
        "entityId": ENTITY,
        "eventType": "PROCESS_START",
        "eventVersion": "v1",
        "occurredAt": "2026-01-31T12:00:00Z",
        "source": "physical-collector",
        "payload": {"pid": 1},
    }


def test_a_well_formed_event_validates():
    validate_event(_valid_event())  # must not raise


@pytest.mark.parametrize("missing", [
    "eventId", "entityId", "eventType", "eventVersion", "occurredAt", "source", "payload",
])
def test_every_envelope_key_is_required(missing):
    event = _valid_event()
    del event[missing]
    with pytest.raises(EventValidationError, match=missing):
        validate_event(event)


@pytest.mark.parametrize("key", ["eventId", "entityId", "eventType", "eventVersion", "source"])
def test_blank_envelope_strings_are_rejected(key):
    event = _valid_event()
    event[key] = "   "
    with pytest.raises(EventValidationError):
        validate_event(event)


def test_an_unknown_event_type_is_rejected():
    event = _valid_event()
    event["eventType"] = "PROCESS_END"
    with pytest.raises(EventValidationError, match="unknown eventType"):
        validate_event(event)


def test_the_event_type_allowlist_is_exactly_the_documented_contract():
    assert KNOWN_EVENT_TYPES == {"LOGIN", "LOGOUT", "PROCESS_START", "NETWORK_CONNECTION"}


@pytest.mark.parametrize("bad_timestamp", [
    "2026-01-31 12:00:00", "2026-01-31T12:00:00", "2026-01-31T12:00:00.500Z",
    "not-a-time", 1_700_000_000, None,
])
def test_non_canonical_timestamps_are_rejected(bad_timestamp):
    event = _valid_event()
    event["occurredAt"] = bad_timestamp
    with pytest.raises(EventValidationError, match="occurredAt"):
        validate_event(event)


def test_a_non_object_payload_is_rejected():
    event = _valid_event()
    event["payload"] = ["not", "an", "object"]
    with pytest.raises(EventValidationError, match="payload"):
        validate_event(event)


def test_an_unserializable_event_is_rejected():
    event = _valid_event()
    event["payload"] = {"bad": object()}
    with pytest.raises(EventValidationError, match="JSON"):
        validate_event(event)


def test_an_oversized_event_is_rejected_before_it_is_queued():
    event = _valid_event()
    event["payload"] = {"blob": "x" * (MAX_EVENT_BYTES + 1)}
    with pytest.raises(EventValidationError, match="limit"):
        validate_event(event)


def test_a_non_dict_is_rejected():
    with pytest.raises(EventValidationError, match="dict"):
        validate_event("not an event")


def test_an_event_that_fails_validation_never_reaches_the_queue(harness, monkeypatch):
    import pipeline as pipeline_module

    monkeypatch.setattr(
        pipeline_module, "build_process_start_event",
        lambda process, entity_id: {"eventId": "EV-BAD", "eventType": "NOPE"},
    )

    assert harness.pipeline.submit(_process()) is None
    assert harness.queue.depth == 0
    assert harness.health.snapshot()["events"]["invalid"] == 1


# --------------------------------------------------------------------------
# 22. event ID consistency
# --------------------------------------------------------------------------

def test_event_ids_are_unique_across_events(harness):
    events = [
        harness.pipeline.submit(_process(pid=pid, create_time=1000.0 + pid))
        for pid in range(50)
    ]
    ids = [event["eventId"] for event in events]

    assert len(set(ids)) == 50
    assert all(event_id.startswith("EV-PHYS-") for event_id in ids)


def test_the_queued_event_keeps_the_id_it_was_given(harness):
    event = harness.pipeline.submit(_process())
    queued = harness.queued()[0]
    assert queued["eventId"] == event["eventId"]
    assert queued is event, "the pipeline must not re-serialize or copy the event"


# --------------------------------------------------------------------------
# 23. timestamp correctness
# --------------------------------------------------------------------------

def test_process_occurred_at_is_the_real_process_create_time(harness):
    event = harness.pipeline.submit(_process(create_time=1_800_000_000.0))
    assert event["occurredAt"] == "2027-01-15T08:00:00Z"


def test_login_occurred_at_is_the_real_session_start(harness):
    event = harness.pipeline.submit(_session("LOGIN", started=1_800_000_000.0))
    assert event["occurredAt"] == "2027-01-15T08:00:00Z"


def test_network_occurred_at_is_the_detection_instant_from_the_injected_clock(harness):
    harness.clock.advance(0)  # clock starts at 1_800_000_000.0
    event = harness.pipeline.submit(_connection())
    assert event["occurredAt"] == "2027-01-15T08:00:00Z"

    harness.clock.advance(3600)
    event = harness.pipeline.submit(_connection(local_port=50001))
    assert event["occurredAt"] == "2027-01-15T09:00:00Z"


# --------------------------------------------------------------------------
# Deduplication through the pipeline
# --------------------------------------------------------------------------

def test_the_same_process_observation_is_published_once(harness):
    assert harness.pipeline.submit(_process()) is not None
    assert harness.pipeline.submit(_process()) is None

    assert harness.queue.depth == 1
    assert harness.health.snapshot()["events"]["deduplicated"] == 1


def test_a_reused_pid_with_a_new_create_time_is_not_a_duplicate(harness):
    harness.pipeline.submit(_process(pid=500, create_time=1000.0))
    assert harness.pipeline.submit(_process(pid=500, create_time=2000.0)) is not None
    assert harness.queue.depth == 2


def test_the_same_connection_observation_is_published_once(harness):
    assert harness.pipeline.submit(_connection()) is not None
    assert harness.pipeline.submit(_connection()) is None
    assert harness.queue.depth == 1


def test_a_connection_status_change_is_not_a_new_connection(harness):
    first = _connection()
    harness.pipeline.submit(first)

    changed = NetworkConnectionEvent(
        protocol=first.protocol, local_address=first.local_address,
        local_port=first.local_port, remote_address=first.remote_address,
        remote_port=first.remote_port, status="CLOSE_WAIT",
        pid=first.pid, process_name=first.process_name,
        process_create_time=first.process_create_time,
    )
    assert harness.pipeline.submit(changed) is None


def test_a_logout_is_not_suppressed_as_a_duplicate_of_its_login(harness):
    harness.pipeline.submit(_session("LOGIN", started=1000.0))
    assert harness.pipeline.submit(_session("LOGOUT", started=1000.0)) is not None
    assert harness.queue.depth == 2


def test_a_repeated_session_baseline_is_suppressed(harness):
    # A restarted session worker re-reports the active session as a
    # LOGIN; dedup is what keeps that from being published twice.
    harness.pipeline.submit(_session("LOGIN", started=1000.0))
    assert harness.pipeline.submit(_session("LOGIN", started=1000.0)) is None


@pytest.mark.parametrize("observation,expected_prefix", [
    (_process(), "PROCESS_START"),
    (_connection(), "NETWORK_CONNECTION"),
    (_session("LOGIN"), "LOGIN"),
])
def test_dedup_keys_are_tagged_by_kind_so_they_cannot_collide(observation, expected_prefix):
    assert dedup_key(observation)[0] == expected_prefix


def test_dedup_key_rejects_an_unknown_observation():
    with pytest.raises(TypeError):
        dedup_key(object())


# --------------------------------------------------------------------------
# Process / network correlation (PHASE G)
# --------------------------------------------------------------------------

def test_a_connection_with_no_live_process_info_is_enriched_from_the_cache(harness):
    harness.process_cache.record(pid=8420, name="powershell.exe", create_time=1_800_000_000.0)

    event = harness.pipeline.submit(
        _connection(pid=8420, process_name=None, process_create_time=None)
    )

    assert event["payload"]["processName"] == "powershell.exe"
    assert event["payload"]["processCreateTime"] == "2027-01-15T08:00:00Z"


def test_the_enriched_create_time_matches_process_start_occurred_at_exactly(harness):
    # This exact-string equality is what the backend's
    # NEW_PROCESS_EXTERNAL_CONNECTION rule correlates on.
    process_start = harness.pipeline.submit(_process(pid=8420, create_time=1_800_000_123.0))
    harness.process_cache.record(pid=8420, name="python.exe", create_time=1_800_000_123.0)

    connection = harness.pipeline.submit(
        _connection(pid=8420, process_name=None, process_create_time=None)
    )

    assert connection["payload"]["processCreateTime"] == process_start["occurredAt"]


def test_live_process_info_is_never_overwritten_by_the_cache(harness):
    harness.process_cache.record(pid=8420, name="stale.exe", create_time=1.0)

    event = harness.pipeline.submit(
        _connection(pid=8420, process_name="live.exe", process_create_time=1_800_000_000.0)
    )

    assert event["payload"]["processName"] == "live.exe"
    assert event["payload"]["processCreateTime"] == "2027-01-15T08:00:00Z"


def test_a_disagreeing_create_time_means_pid_reuse_and_blocks_enrichment(harness):
    harness.process_cache.record(pid=8420, name="old.exe", create_time=1_700_000_000.0)

    event = harness.pipeline.submit(
        _connection(pid=8420, process_name=None, process_create_time=1_800_000_000.0)
    )

    assert "processName" not in event["payload"], "the cached name belongs to a different process"
    assert event["payload"]["processCreateTime"] == "2027-01-15T08:00:00Z"


def test_an_expired_cache_entry_is_not_used(harness):
    harness.process_cache.record(pid=8420, name="powershell.exe", create_time=1_800_000_000.0)
    harness.clock.advance(301)  # correlation TTL is 300s in this harness

    event = harness.pipeline.submit(
        _connection(pid=8420, process_name=None, process_create_time=None)
    )

    assert "processName" not in event["payload"]
    assert "processCreateTime" not in event["payload"]


def test_a_connection_without_a_pid_is_left_alone(harness):
    event = harness.pipeline.submit(
        _connection(pid=None, process_name=None, process_create_time=None)
    )
    assert "pid" not in event["payload"]
    assert "processName" not in event["payload"]


def test_the_pipeline_works_without_a_correlation_cache():
    clock = VirtualClock()
    health = HealthRegistry(clock=clock)
    pipeline = EventPipeline(
        entity_id=ENTITY,
        queue=BoundedEventQueue(max_size=10),
        dedup_cache=BoundedDedupCache(ttl_seconds=60, max_entries=10, clock=clock),
        health=health,
        process_cache=None,
        clock=clock,
    )
    assert pipeline.submit(_connection()) is not None


# --------------------------------------------------------------------------
# Queue interaction + counters
# --------------------------------------------------------------------------

def test_counters_follow_an_event_through_every_stage(harness):
    harness.pipeline.submit(_process())
    harness.pipeline.submit(_process())  # duplicate

    events = harness.health.snapshot()["events"]
    assert events["generated"] == 2
    assert events["normalized"] == 1
    assert events["validated"] == 1
    assert events["deduplicated"] == 1
    assert events["invalid"] == 0


def test_queue_overflow_is_counted_as_a_drop(harness):
    small_queue = BoundedEventQueue(max_size=2)
    harness.health.set_queue_capacity(2)
    pipeline = EventPipeline(
        entity_id=ENTITY, queue=small_queue, dedup_cache=harness.dedup,
        health=harness.health, clock=harness.clock,
    )

    for pid in range(5):
        pipeline.submit(_process(pid=pid, create_time=1000.0 + pid))

    assert small_queue.depth == 2
    assert harness.health.snapshot()["queue"]["dropped_events"] == 3
    assert harness.health.snapshot()["events"]["dropped"] == 3


def test_a_closed_queue_stops_accepting_telemetry(harness):
    harness.queue.close()
    event = harness.pipeline.submit(_process())

    assert event is not None, "the event was still normalized and validated"
    assert harness.queue.depth == 0
    assert harness.health.snapshot()["queue"]["total_enqueued"] == 0


def test_every_queued_event_is_json_serializable_for_kafka(harness):
    for observation in (_process(), _connection(), _session("LOGIN"), _session("LOGOUT")):
        harness.pipeline.submit(observation)

    for event in harness.queued():
        assert json.loads(json.dumps(event)) == event
