package com.anomaly.platform.ai;

import java.time.OffsetDateTime;
import java.util.List;

/*
 * The complete, structured evidence set for one incident, handed to
 * IncidentAiService. This is the ONLY thing the AI layer sees - it has no
 * repository access and cannot query the database itself (see
 * IncidentEvidenceService, which is the sole assembler of this object).
 */
public record IncidentEvidence(
        String incidentId,
        String incidentKey,
        String entityId,
        String incidentStatus,
        String summary,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt,
        OffsetDateTime closedAt,
        List<AlertEvidence> alerts
) {
}
