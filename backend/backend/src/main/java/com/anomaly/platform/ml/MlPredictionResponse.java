package com.anomaly.platform.ml;

import java.math.BigDecimal;
import java.util.List;

/*
 * Mirrors api.py's /predict response field-for-field. Only fields the real
 * model actually produces are here - confidence/attackType/reason are null
 * and factors is empty when the ML service itself returns decision=NORMAL
 * (no alert fired), exactly as api.py returns them. Nothing here is
 * fabricated on the Java side.
 */
public record MlPredictionResponse(
        String eventId,
        String entityId,
        BigDecimal anomalyScore,
        BigDecimal riskScore,
        BigDecimal confidence,
        String decision,
        String modelName,
        String modelVersion,
        String attackType,
        String reason,
        List<String> factors
) {
}
