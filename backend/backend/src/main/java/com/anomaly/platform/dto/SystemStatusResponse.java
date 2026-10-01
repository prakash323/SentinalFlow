package com.anomaly.platform.dto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/*
 * Live dependency and pipeline health for the operations console.
 *
 * overall: UP when every component is UP, DEGRADED when some are DOWN,
 * DOWN when the database itself is unreachable.
 */
public record SystemStatusResponse(
        String overall,
        OffsetDateTime checkedAt,
        List<Component> components,
        Map<String, Long> pipeline,
        Policy policy
) {

    public record Component(
            String name,
            String status,
            Long latencyMs,
            String detail
    ) {
    }

    public record Policy(
            String version,
            double alertThreshold,
            double medium,
            double high,
            double critical
    ) {
    }
}
