package com.anomaly.platform.ai;

import java.time.OffsetDateTime;
import java.util.UUID;

/*
 * Shared response shape for all three analyst-assistance endpoints.
 * Generated fresh on every call - nothing here is persisted (Phase 6
 * deliberately prefers stateless generation; there is no existing
 * persistence model that clearly fits free-form AI text yet).
 */
public record IncidentAiResponse(
        UUID incidentId,
        String kind,
        String content,
        String model,
        OffsetDateTime generatedAt
) {
}
