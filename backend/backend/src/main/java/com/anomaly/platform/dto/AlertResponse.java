package com.anomaly.platform.dto;

import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.Severity;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record AlertResponse(
        UUID id,
        String entityId,
        String eventId,
        String source,
        DecisionState decision,
        Severity severity,
        AlertStatus status,
        BigDecimal anomalyScore,
        BigDecimal confidence,
        BigDecimal fusedScore,
        String policyVersion,
        List<String> factors,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt,
        UUID incidentId,
        // Independent deterministic detection (P1). detectionType is derived
        // (never stored): "RULE" when ruleId is present, "ML" otherwise -
        // an ML-driven alert always has ruleId/ruleName null.
        String ruleId,
        String ruleName,
        String detectionType
) {
}
