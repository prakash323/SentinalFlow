package com.anomaly.platform.dto;

import com.anomaly.platform.entity.DecisionState;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.math.BigDecimal;
import java.util.Map;
import java.util.UUID;

public record CreatePredictionRequest(
        @NotNull(message = "eventId is required")
        UUID eventId,
        @NotBlank(message = "modelName is required")
        String modelName,
        @NotBlank(message = "modelVersion is required")
        String modelVersion,
        @NotNull(message = "anomalyScore is required")
        BigDecimal anomalyScore,
        BigDecimal confidence,
        BigDecimal fusedScore,
        @NotNull(message = "decision is required")
        DecisionState decision,
        Map<String, Object> features
) {
}