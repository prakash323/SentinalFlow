package com.anomaly.platform.dto;

import java.math.BigDecimal;
import java.time.OffsetDateTime;

/*
 * One row of the dashboard's "highest-risk entities" list.
 */
public record EntityRiskResponse(
        String entityId,
        long alertCount,
        BigDecimal maxScore,
        OffsetDateTime lastAlertAt
) {
}
