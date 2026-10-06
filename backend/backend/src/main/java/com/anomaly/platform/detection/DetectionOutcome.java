package com.anomaly.platform.detection;

/*
 * Why a rule did, or did not, produce an alert for one event.
 *
 * Every evaluation ends in exactly one of these, and every one of them that is
 * not NOT_APPLICABLE / INSUFFICIENT_EVIDENCE is written to the audit log. That
 * is what makes "why did this alert fire?" and "why was this suppressed?"
 * answerable after the fact rather than a matter of reading the code.
 */
public enum DetectionOutcome {

    /** The rule matched and a new alert was raised. */
    DETECTED,

    /**
     * The rule matched, an alert for this rule and entity is still active, and
     * the new evidence is more severe - so the ACTIVE alert was raised to the
     * higher severity instead of a second alert being created.
     */
    ESCALATED,

    /**
     * The rule matched but an alert for this rule and entity is still open,
     * acknowledged or investigating. A continuing condition raises one alert,
     * not one per qualifying event.
     */
    SUPPRESSED_ACTIVE_ALERT,

    /**
     * The rule matched but the last alert for this rule and entity closed too
     * recently (inside the rule's configured cooldown) to raise another.
     */
    SUPPRESSED_COOLDOWN,

    /**
     * This exact triggering event has already produced this rule's alert - a
     * Kafka redelivery or an admin replay, not new activity.
     */
    DUPLICATE,

    /** The rule applies to this event type but the evidence did not meet its threshold. */
    INSUFFICIENT_EVIDENCE,

    /** The rule does not consume this event type, or it is disabled by configuration. */
    NOT_APPLICABLE;

    /** Did this outcome change alert state? */
    public boolean raisedOrChangedAnAlert() {
        return this == DETECTED || this == ESCALATED;
    }

    /** Was the rule's match deliberately held back? */
    public boolean isSuppression() {
        return this == SUPPRESSED_ACTIVE_ALERT || this == SUPPRESSED_COOLDOWN || this == DUPLICATE;
    }
}
