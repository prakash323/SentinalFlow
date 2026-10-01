package com.anomaly.platform.dto;

import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.Severity;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.UUID;

public record IncidentAlertResponse(
        UUID id,
        String eventId,
        String entityId,
        DecisionState decision,
        Severity severity,
        AlertStatus status,
        BigDecimal anomalyScore,
        BigDecimal confidence,
        BigDecimal fusedScore,
        String policyVersion,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt,
        String ruleId,
        String ruleName,
        String detectionType
) {
}