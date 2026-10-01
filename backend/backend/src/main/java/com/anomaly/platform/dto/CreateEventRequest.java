package com.anomaly.platform.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.OffsetDateTime;
import java.util.Map;

public record CreateEventRequest(

        @NotBlank(message = "eventId is required")
        String eventId,

        @NotBlank(message = "entityId is required")
        String entityId,

        @NotBlank(message = "eventType is required")
        String eventType,

        @NotBlank(message = "eventVersion is required")
        String eventVersion,

        @NotNull(message = "occurredAt is required")
        OffsetDateTime occurredAt,

        @NotBlank(message = "source is required")
        String source,

        @NotNull(message = "payload is required")
        Map<String, Object> payload

) {
}