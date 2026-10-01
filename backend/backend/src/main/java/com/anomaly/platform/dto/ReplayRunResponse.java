package com.anomaly.platform.dto;

import com.anomaly.platform.entity.ReplayStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record ReplayRunResponse(
        UUID id,
        String runKey,
        String sourceName,
        ReplayStatus status,
        int totalEvents,
        int processedEvents,
        int failedEvents,
        OffsetDateTime startedAt,
        OffsetDateTime completedAt,
        OffsetDateTime createdAt
) {
}