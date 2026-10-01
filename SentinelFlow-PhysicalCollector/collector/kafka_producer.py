"""
kafka_producer.py
Thin wrapper around kafka-python's KafkaProducer, publishing canonical
SentinelFlow events to the EXISTING raw event topic using the EXISTING
wire format: a plain JSON string, keyed by eventId - compatible with the
Spring Boot side's StringSerializer/StringDeserializer as-is. No new
topic, no new serialization, no schema registry.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

from kafka import KafkaProducer
from kafka.errors import KafkaError

logger = logging.getLogger("sentinelflow.collector.kafka_producer")


class EventPublisher:
    def __init__(self, bootstrap_servers: str, topic: str) -> None:
        self._topic = topic
        self._producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            key_serializer=lambda k: k.encode("utf-8"),
            value_serializer=lambda v: v.encode("utf-8"),
            retries=5,
            linger_ms=50,
        )
        logger.info(
            "Kafka producer initialized bootstrap_servers=%s topic=%s",
            bootstrap_servers,
            topic,
        )

    def publish(self, event: Dict[str, Any]) -> None:
        """Publish one canonical event. Logs operational metadata only
        (eventId/eventType/entityId/partition/offset) - never the payload
        body, so nothing telemetry-shaped ever reaches the logs even
        though this phase's own payload contains no secrets."""
        event_id = event["eventId"]
        event_json = json.dumps(event)

        try:
            future = self._producer.send(self._topic, key=event_id, value=event_json)
            record_metadata = future.get(timeout=10)
            logger.info(
                "Event published eventId=%s eventType=%s entityId=%s partition=%s offset=%s",
                event_id,
                event.get("eventType"),
                event.get("entityId"),
                record_metadata.partition,
                record_metadata.offset,
            )
        except KafkaError:
            logger.exception(
                "Failed to publish event to Kafka eventId=%s eventType=%s",
                event_id,
                event.get("eventType"),
            )
            raise

    def close(self) -> None:
        self._producer.flush(timeout=10)
        self._producer.close(timeout=10)
