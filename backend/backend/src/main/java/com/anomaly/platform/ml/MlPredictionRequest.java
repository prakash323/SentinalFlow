package com.anomaly.platform.ml;

import java.time.OffsetDateTime;
import java.util.Map;

/*
 * Mirrors api.py's EventRequest (SentinelFlow ML service) field-for-field.
 * Do not add fields here that the ML service does not actually read.
 */
public record MlPredictionRequest(
        String eventId,
        String entityId,
        String eventType,
        String eventVersion,
        OffsetDateTime occurredAt,
        String source,
        Map<String, Object> payload
) {
}
