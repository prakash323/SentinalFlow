package com.anomaly.platform.ai;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;

/*
 * One alert's worth of structured, already-computed SentinelFlow evidence.
 * Every field here is a direct read of an existing value - nothing is
 * recalculated or inferred. attackType/mlReason come from the real ML
 * service's own output (Prediction.features, written in Phase 4), not
 * from anything Spring AI produces.
 */
public record AlertEvidence(
        String alertId,
        String eventId,
        String eventType,
        OffsetDateTime eventOccurredAt,
        String decision,
        String severity,
        String status,
        BigDecimal anomalyScore,
        BigDecimal confidence,
        BigDecimal fusedScore,
        String policyVersion,
        List<String> factors,
        String attackType,
        String mlReason,
        OffsetDateTime createdAt
) {
}
