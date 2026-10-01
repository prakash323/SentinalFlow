package com.anomaly.platform.dto;

import com.anomaly.platform.entity.DecisionState;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

public record PredictionResponse(
        UUID id,
        String eventId,
        String entityId,
        String modelName,
        String modelVersion,
        BigDecimal anomalyScore,
        BigDecimal confidence,
        BigDecimal fusedScore,
        DecisionState decision,
        Map<String, Object> features,
        OffsetDateTime createdAt
) {
}