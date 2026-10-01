package com.anomaly.platform.dto;

import com.anomaly.platform.entity.EventProcessingStatus;

import java.time.OffsetDateTime;

/*
 * Everything the detection pipeline produced for one event: its
 * processing outcome, the model prediction (if scoring succeeded) and the
 * alert (if the score crossed the alert policy). Either of the last two
 * can be null - a NORMAL event has no alert, and a PENDING/FAILED event
 * has no prediction.
 */
public record EventTrailResponse(
        String eventId,
        EventProcessingStatus processingStatus,
        int processingAttempts,
        String lastProcessingError,
        OffsetDateTime processedAt,
        PredictionResponse prediction,
        AlertResponse alert
) {
}
