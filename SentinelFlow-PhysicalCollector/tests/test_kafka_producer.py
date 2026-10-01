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


def test_publish_reraises_on_kafka_error(fake_kafka_producer):
    _factory, instance = fake_kafka_producer
    instance.send.side_effect = kafka_producer.KafkaError("boom")

    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1")
    event = {"eventId": "EV-PHYS-1-aaaaaa", "eventType": "LOGIN"}

    with pytest.raises(kafka_producer.KafkaError):
        publisher.publish(event)


def test_close_flushes_and_closes_producer(fake_kafka_producer):
    _factory, instance = fake_kafka_producer
    publisher = kafka_producer.EventPublisher("localhost:9094", "raw.events.v1")

    publisher.close()

    instance.flush.assert_called_once()
    instance.close.assert_called_once()
