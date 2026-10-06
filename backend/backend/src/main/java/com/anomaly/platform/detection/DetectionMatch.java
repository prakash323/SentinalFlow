package com.anomaly.platform.detection;

import com.anomaly.platform.entity.Severity;

/*
 * What a rule returns from one evaluation: either a match carrying its severity
 * and its evidence, or "no match" with the reason.
 *
 * `suppressionKey` is the identity the engine suppresses and deduplicates on
 * WITHIN a rule. For most rules the rule plus the entity is the whole identity.
 * NEW_PROCESS_EXTERNAL_CONNECTION needs more: a second connection from the same
 * process is the same finding, but a different process on the same host is a new
 * one, so that rule returns a key including the process identity. The engine
 * never guesses this - the rule states it.
 */
public record DetectionMatch(
        boolean matched,
        DetectionOutcome noMatchReason,
        Severity severity,
        DetectionEvidence evidence,
        String suppressionKey,
        /** The clause the alert message opens with; the quantified tail is generated from the evidence. */
        String leadClause
) {

    /** No match because the rule's threshold was not met. */
    public static DetectionMatch insufficient() {
        return new DetectionMatch(false, DetectionOutcome.INSUFFICIENT_EVIDENCE, null, null, null, null);
    }

    /** No match because the rule does not apply to this event at all. */
    public static DetectionMatch notApplicable() {
        return new DetectionMatch(false, DetectionOutcome.NOT_APPLICABLE, null, null, null, null);
    }

    /** A match suppressed and deduplicated per rule and entity. */
    public static DetectionMatch of(Severity severity, DetectionEvidence evidence, String leadClause) {
        return new DetectionMatch(true, null, severity, evidence, null, leadClause);
    }

    /** A match with a narrower suppression identity than "the whole entity". */
    public static DetectionMatch of(Severity severity, DetectionEvidence evidence, String leadClause, String suppressionKey) {
        return new DetectionMatch(true, null, severity, evidence, suppressionKey, leadClause);
    }

    /** The generated, operator-facing explanation of this match. */
    public String message() {
        return evidence.summary(leadClause);
    }
}
