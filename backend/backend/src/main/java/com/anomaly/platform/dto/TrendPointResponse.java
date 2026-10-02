package com.anomaly.platform.dto;

import java.time.OffsetDateTime;
import java.util.Map;

/*
 * One UTC hour of the dashboard trend. `alerts` counts alerts by their
 * createdAt; `alertsBySeverity` splits that same count by severity (every
 * severity present, zero-filled), so the two always agree.
 */
public record TrendPointResponse(
        String label,
        long events,
        long alerts,
        OffsetDateTime bucketStart,
        Map<String, Long> alertsBySeverity
) {
}
