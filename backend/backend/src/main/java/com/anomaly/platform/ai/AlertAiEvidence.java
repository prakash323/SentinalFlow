package com.anomaly.platform.ai;

/*
 * The complete, structured evidence set for one alert, handed to
 * AlertAiService. Like IncidentEvidence, this is the ONLY thing the alert
 * assistant sees - it has no repository access and cannot look anything up
 * itself (see AlertAiEvidenceService, the sole assembler of this object).
 *
 * `alert` carries the authoritative ML/policy output (decision, severity,
 * anomalyScore, confidence, fusedScore, ranked factors, attackType,
 * mlReason) plus the event's id/type/time. The remaining fields add the
 * entity, the event's source and - only when the alert is grouped into one -
 * the incident it belongs to. Every field is a direct read of a value
 * SentinelFlow already stored; nothing is recomputed. The raw event payload
 * is deliberately NOT included: it is free-form, attacker-controlled input
 * that may hold personal data, and the ML factors/reason already carry what
 * the model found in it.
 */
public record AlertAiEvidence(
        AlertEvidence alert,
        String entityId,
        String eventSource,
        String incidentId,
        String incidentKey,
        String incidentStatus,
        String incidentSummary,
        Integer incidentAlertCount
) {
}
