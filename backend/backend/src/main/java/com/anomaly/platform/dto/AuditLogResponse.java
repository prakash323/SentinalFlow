package com.anomaly.platform.dto;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

public record AuditLogResponse(
        UUID id,
        String actor,
        String action,
        String resourceType,
        UUID resourceId,
        String correlationId,
        Map<String, Object> details,
        OffsetDateTime createdAt
) {
}
