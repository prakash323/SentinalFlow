package com.anomaly.platform.ai;

import java.time.OffsetDateTime;
import java.util.UUID;

/*
 * Response shape of the alert analyst-assistance endpoint. Same fields as
 * IncidentAiResponse but keyed by alertId - reusing the incident record
 * would mislabel the identifier. Generated fresh on every call; nothing is
 * persisted.
 */
public record AlertAiResponse(
        UUID alertId,
        String kind,
        String content,
        String model,
        OffsetDateTime generatedAt
) {
}
