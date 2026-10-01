package com.anomaly.platform.dto;

import java.time.OffsetDateTime;

public record TrendPointResponse(
        String label,
        long events,
        long alerts,
        OffsetDateTime bucketStart
) {
}
