package com.anomaly.platform.kafka;

import java.time.OffsetDateTime;
import java.util.Map;

public record KafkaEvent(
        String eventId,
        String entityId,
        String eventType,
        String eventVersion,
        OffsetDateTime occurredAt,
        String source,
        Map<String, Object> payload
) {
}