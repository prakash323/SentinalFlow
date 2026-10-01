package com.anomaly.platform.dto;

import com.anomaly.platform.entity.IncidentStatus;
import com.anomaly.platform.entity.Severity;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/*
 * sources: every distinct source among this incident's alerts' events,
 * NOT a single value - an incident has no source column of its own (see
 * Incident entity) and its correlation key (entityId:eventType) does not
 * guarantee a single source. Confirmed against live data: some incidents
 * genuinely have alerts from more than one source. Empty list when the
 * incident has no alerts yet (should not normally happen, but never
 * fabricated as a placeholder).
 */
public record IncidentResponse(
        UUID id,
        String incidentKey,
        String entityId,
        IncidentStatus status,
        String summary,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt,
        OffsetDateTime closedAt,
        long alertCount,
        Severity maxSeverity,
        BigDecimal maxScore,
        List<String> sources
) {
}
