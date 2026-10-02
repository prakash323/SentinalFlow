package com.anomaly.platform.dto;

import com.anomaly.platform.entity.EventProcessingStatus;

import java.time.OffsetDateTime;
import java.util.List;

/*
 * Everything the detection pipeline produced for one event: its
 * processing outcome, the model prediction (if scoring succeeded) and the
 * alert (if the score crossed the alert policy). Either of the last two
 * can be null - a NORMAL event has no alert, and a PENDING/FAILED event
 * has no prediction.
 *
 * One event can raise more than one alert - a deterministic rule alert
 * (e.g. AUTH_BURST) and an ML alert. `alerts` lists all of them, newest
 * first; `alert` is kept for existing clients and is the newest one.
 */
public record EventTrailResponse(
        String eventId,
        EventProcessingStatus processingStatus,
        int processingAttempts,
        String lastProcessingError,
        OffsetDateTime processedAt,
        PredictionResponse prediction,
        AlertResponse alert,
        List<AlertResponse> alerts
) {
}
