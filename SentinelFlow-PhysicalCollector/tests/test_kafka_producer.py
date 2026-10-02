"""
Unit tests for the producer wrapper against a mocked kafka.KafkaProducer -
no real broker required. The live integration test is in
test_integration_kafka.py.
"""
import json
from unittest.mock import MagicMock

import pytest

import kafka_producer


class _FakeFuture:
    def __init__(self, record_metadata):
        self._record_metadata = record_metadata

    def get(self, timeout=None):
        return self._record_metadata


class _FakeRecordMetadata:
    def __init__(self, partition, offset):
        self.partition = partition
        self.offset = offset


@pytest.fixture
def fake_kafka_producer(monkeypatch):
    instance = MagicMock()
    instance.send.return_value = _FakeFuture(_FakeRecordMetadata(partition=0, offset=42))

    factory = MagicMock(return_value=instance)
    monkeypatch.setattr(kafka_producer, "KafkaProducer", factory)
    return factory, instance


def test_publish_sends_json_string_keyed_by_event_id(fake_kafka_producer):
    factory, instance = fake_kafka_producer
    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1")

    event = {
        "eventId": "EV-PHYS-123-abcdef",
        "entityId": "HOST-TEST",
        "eventType": "LOGIN",
        "eventVersion": "v1",
        "occurredAt": "2026-09-30T08:00:00Z",
        "source": "physical-collector",
        "payload": {"loginSuccess": True},
    }

    publisher.publish(event)

    instance.send.assert_called_once()
    args, kwargs = instance.send.call_args
    assert args[0] == "raw.events.v1"
    assert kwargs["key"] == "EV-PHYS-123-abcdef"
    assert json.loads(kwargs["value"]) == event


def test_key_and_value_serializers_produce_bytes(fake_kafka_producer):
    factory, _instance = fake_kafka_producer
    kafka_producer.EventPublisher("localhost:9094", "raw.events.v1")

    _, kwargs = factory.call_args
    assert kwargs["key_serializer"]("abc") == b"abc"
    assert kwargs["value_serializer"]("{}") == b"{}"


class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _event(n):
    return {"eventId": f"EV-PHYS-{n}-aaaaaa", "eventType": "LOGIN", "entityId": "HOST-TEST"}


def _sent_event_ids(instance):
    return [call.kwargs["key"] for call in instance.send.call_args_list]


def test_publish_does_not_raise_and_queues_the_event_when_kafka_fails(fake_kafka_producer):
    _factory, instance = fake_kafka_producer
    instance.send.side_effect = kafka_producer.KafkaError("boom")

    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1", clock=_FakeClock())
    publisher.publish(_event(1))

    assert publisher.pending_count == 1


def test_queued_events_are_resent_in_order_once_kafka_recovers(fake_kafka_producer):
    _factory, instance = fake_kafka_producer
    clock = _FakeClock()
    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1", clock=clock)

    instance.send.side_effect = kafka_producer.KafkaError("broker down")
    publisher.publish(_event(1))
    publisher.publish(_event(2))
    publisher.publish(_event(3))
    assert publisher.pending_count == 3

    instance.send.side_effect = None
    instance.send.reset_mock()
    clock.now += 60
    publisher.retry_pending()

    assert publisher.pending_count == 0
    assert _sent_event_ids(instance) == [
        "EV-PHYS-1-aaaaaa", "EV-PHYS-2-aaaaaa", "EV-PHYS-3-aaaaaa",
    ]


def test_no_send_is_attempted_while_backing_off_after_a_failure(fake_kafka_producer):
    # Each attempt against a dead broker blocks, so events published during
    # the backoff window must be queued without touching the producer.
    _factory, instance = fake_kafka_producer
    clock = _FakeClock()
    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1", clock=clock)

    instance.send.side_effect = kafka_producer.KafkaError("broker down")
    publisher.publish(_event(1))
    assert instance.send.call_count == 1

    clock.now += 1
    publisher.publish(_event(2))
    publisher.retry_pending()

    assert instance.send.call_count == 1
    assert publisher.pending_count == 2


def test_backoff_grows_after_repeated_failures(fake_kafka_producer):
    _factory, instance = fake_kafka_producer
    clock = _FakeClock()
    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1", clock=clock)
    instance.send.side_effect = kafka_producer.KafkaError("broker down")

    publisher.publish(_event(1))          # fails -> retry in 5s
    clock.now += 5
    publisher.retry_pending()             # fails -> retry in 10s
    assert instance.send.call_count == 2

    clock.now += 5
    publisher.retry_pending()             # still backing off
    assert instance.send.call_count == 2

    clock.now += 5
    publisher.retry_pending()
    assert instance.send.call_count == 3


def test_queue_is_bounded_and_drops_the_oldest_event(fake_kafka_producer):
    _factory, instance = fake_kafka_producer
    clock = _FakeClock()
    publisher = kafka_producer.EventPublisher(
        "localhost:9094", "raw.events.v1", max_pending=2, clock=clock
    )

    instance.send.side_effect = kafka_producer.KafkaError("broker down")
    for n in (1, 2, 3):
        publisher.publish(_event(n))
    assert publisher.pending_count == 2

    instance.send.side_effect = None
    instance.send.reset_mock()
    clock.now += 60
    publisher.retry_pending()

    assert _sent_event_ids(instance) == ["EV-PHYS-2-aaaaaa", "EV-PHYS-3-aaaaaa"]


def test_close_makes_a_final_attempt_to_send_queued_events(fake_kafka_producer):
    _factory, instance = fake_kafka_producer
    clock = _FakeClock()
    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1", clock=clock)

    instance.send.side_effect = kafka_producer.KafkaError("broker down")
    publisher.publish(_event(1))

    instance.send.side_effect = None
    publisher.close()  # still inside the backoff window

    assert publisher.pending_count == 0
    assert _sent_event_ids(instance)[-1] == "EV-PHYS-1-aaaaaa"


def test_send_blocking_is_capped_below_kafka_pythons_60s_default(fake_kafka_producer):
    factory, _instance = fake_kafka_producer
    kafka_producer.EventPublisher("localhost:9094", "raw.events.v1")

    _, kwargs = factory.call_args
    assert kwargs["max_block_ms"] <= 10000


def test_close_flushes_and_closes_producer(fake_kafka_producer):
    _factory, instance = fake_kafka_producer
    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1")

    publisher.close()

    instance.flush.assert_called_once()
    instance.close.assert_called_once()
