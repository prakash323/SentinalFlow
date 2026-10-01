"""
Live integration test: publishes one real canonical event to the actual
raw.events.v1 topic on a real broker and reads it back with a plain
KafkaConsumer, proving the wire format really is compatible end to end -
not just "the mock was called correctly".

Skips (does not fail) if no broker is reachable at
KAFKA_BOOTSTRAP_SERVERS (default localhost:9094) - Kafka is optional
local infrastructure, not something this test suite should require.
"""
import json
import os
import socket
import uuid

import pytest

from kafka_producer import EventPublisher
from normalizer import build_login_event, build_network_connection_event, build_process_start_event
from network_poller import NetworkConnectionEvent
from process_poller import ProcessEvent
from session_poller import SessionEvent

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")
TOPIC = "raw.events.v1"


def _broker_reachable(bootstrap: str) -> bool:
    host, _, port = bootstrap.partition(":")
    try:
        with socket.create_connection((host, int(port) if port else 9094), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _broker_reachable(BOOTSTRAP),
    reason=f"No Kafka broker reachable at {BOOTSTRAP} - skipping live integration test",
)


def _round_trip(event: dict) -> None:
    from kafka import KafkaConsumer

    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=BOOTSTRAP,
        auto_offset_reset="latest",
        consumer_timeout_ms=15000,
        key_deserializer=lambda k: k.decode("utf-8") if k else None,
        value_deserializer=lambda v: v.decode("utf-8"),
    )
    # Force the consumer group assignment to settle before we publish,
    # otherwise "latest" can miss the message entirely.
    consumer.poll(timeout_ms=1000)

    publisher = EventPublisher(BOOTSTRAP, TOPIC)
    try:
        publisher.publish(event)
    finally:
        publisher.close()

    found = None
    for message in consumer:
        if message.key == event["eventId"]:
            found = message
            break

    consumer.close()

    assert found is not None, "Published event was not observed on raw.events.v1"
    assert found.key == event["eventId"]
    decoded = json.loads(found.value)
    assert decoded == event


def test_published_login_event_round_trips_through_real_kafka():
    unique_entity_id = f"HOST-INTEGRATION-TEST-{uuid.uuid4().hex[:8]}"
    session = SessionEvent(
        kind="LOGIN",
        username="integration-test",
        started_epoch=1_800_000_000.0,
        observed_epoch=1_800_000_000.0,
        host=None,
        terminal=None,
    )
    event = build_login_event(session, unique_entity_id)
    _round_trip(event)


def test_published_process_start_event_round_trips_through_real_kafka():
    # Physical Telemetry P2 - proves PROCESS_START uses the exact same
    # wire format/topic as LOGIN/LOGOUT, nothing special-cased for it.
    unique_entity_id = f"HOST-INTEGRATION-TEST-{uuid.uuid4().hex[:8]}"
    process = ProcessEvent(
        pid=99999,
        name="integration-test.exe",
        ppid=1,
        create_time=1_800_000_000.0,
        username="integration-test",
        executable_path="C:\\integration-test.exe",
    )
    event = build_process_start_event(process, unique_entity_id)
    _round_trip(event)


def test_published_network_connection_event_round_trips_through_real_kafka():
    # Physical Telemetry P3 - proves NETWORK_CONNECTION uses the exact
    # same wire format/topic as LOGIN/LOGOUT/PROCESS_START.
    unique_entity_id = f"HOST-INTEGRATION-TEST-{uuid.uuid4().hex[:8]}"
    connection = NetworkConnectionEvent(
        protocol="TCP",
        local_address="192.168.1.2",
        local_port=54321,
        remote_address="93.184.216.34",
        remote_port=443,
        status="ESTABLISHED",
        pid=99999,
        process_name="integration-test.exe",
        process_create_time=1_800_000_000.0,
    )
    event = build_network_connection_event(connection, unique_entity_id)
    _round_trip(event)
