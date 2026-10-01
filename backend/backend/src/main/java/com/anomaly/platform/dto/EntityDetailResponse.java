package com.anomaly.platform.dto;

import com.anomaly.platform.entity.DecisionState;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

/*
 * Rich single-entity view (GET /api/v1/entities/{entityId}).
 *
 * Identity fields mirror EntityResponse. Rollup fields (eventCount,
 * alertCount, openAlertCount, maxScore, lastEventAt) mirror
 * EntitySummaryResponse exactly - same names, same meaning - so a
 * frontend consuming both the list and detail endpoints never has to
 * reconcile two vocabularies for the same concept.
 *
 * maxScore is this entity's PEAK ALERT score (max fusedScore across its
 * alerts - "the highest score that ever crossed the alert threshold").
 * It is NOT a live/current risk score - that distinction is the reason
 * latestPrediction* exists below: the most recent ML prediction for this
 * entity, regardless of whether it ever crossed the alert threshold. The
 * two can legitimately differ (e.g. recent activity looks normal even
 * though the entity triggered a high alert last week) - that is
 * intentional, not a bug, and nothing here invents a new combined
 * "entity risk score".
 */
public record EntityDetailResponse(
        UUID id,
        String entityId,
        String entityType,
        String displayName,
        Map<String, Object> metadata,
        OffsetDateTime createdAt,

        long eventCount,
        long alertCount,
        long openAlertCount,
        BigDecimal maxScore,
        OffsetDateTime lastEventAt,

        long openIncidentCount,

        BigDecimal latestPredictionAnomalyScore,
        DecisionState latestPredictionDecision,
        OffsetDateTime latestPredictionCreatedAt
) {
}
