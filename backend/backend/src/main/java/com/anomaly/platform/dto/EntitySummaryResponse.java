package com.anomaly.platform.dto;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.UUID;

/*
 * A monitored entity plus the activity rollup shown on the entities page.
 */
public record EntitySummaryResponse(
        UUID id,
        String entityId,
        String entityType,
        String displayName,
        OffsetDateTime createdAt,
        long eventCount,
        long alertCount,
        long openAlertCount,
        BigDecimal maxScore,
        OffsetDateTime lastEventAt
) {
}
