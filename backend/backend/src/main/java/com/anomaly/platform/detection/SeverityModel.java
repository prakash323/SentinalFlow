package com.anomaly.platform.detection;

import com.anomaly.platform.entity.Severity;

/*
 * ============================================================
 * DETERMINISTIC SEVERITY
 * ============================================================
 *
 * Severity is a function of the evidence and the configured thresholds, and
 * nothing else. No ML score reaches this class - a deterministic alert must stay
 * explainable from its own evidence alone, which is the whole reason the rule
 * path exists independently of the model.
 *
 * The ladder: a value at or above `criticalAt` is CRITICAL, at or above `highAt`
 * is HIGH, at or above `mediumAt` is MEDIUM, otherwise LOW. A threshold of 0 (or
 * less) disables that rung, so a rule can offer only the levels it can justify -
 * AUTH_BURST, for example, has no CRITICAL rung because nothing in its evidence
 * would distinguish one.
 */
public final class SeverityModel {

    private SeverityModel() {
    }

    /** A disabled rung. Configured as 0 in application.yml. */
    public static final long DISABLED = 0L;

    public static boolean enabled(long threshold) {
        return threshold > DISABLED;
    }

    /**
     * The rung `value` reaches. `reason` text for the alert comes from
     * {@link #reason}, so the number that decided the severity is always the
     * number quoted to the operator.
     */
    public static Severity fromThresholds(long value, long mediumAt, long highAt, long criticalAt) {
        if (enabled(criticalAt) && value >= criticalAt) {
            return Severity.CRITICAL;
        }
        if (enabled(highAt) && value >= highAt) {
            return Severity.HIGH;
        }
        if (enabled(mediumAt) && value >= mediumAt) {
            return Severity.MEDIUM;
        }
        return Severity.LOW;
    }

    /** Why that rung, in the operator's words, citing the value and the bar it crossed. */
    public static String reason(String measure, long value, long mediumAt, long highAt, long criticalAt) {
        Severity s = fromThresholds(value, mediumAt, highAt, criticalAt);
        long crossed = switch (s) {
            case CRITICAL -> criticalAt;
            case HIGH -> highAt;
            case MEDIUM -> mediumAt;
            case LOW -> mediumAt;
        };
        if (s == Severity.LOW) {
            return "Severity LOW: " + measure + " " + value + " is below the MEDIUM threshold of " + crossed;
        }
        String next = nextRungText(s, highAt, criticalAt);
        return "Severity " + s + ": " + measure + " " + value + " reached the " + s + " threshold of " + crossed + next;
    }

    private static String nextRungText(Severity current, long highAt, long criticalAt) {
        if (current == Severity.MEDIUM && enabled(highAt)) {
            return " (escalates to HIGH at " + highAt + ")";
        }
        if (current == Severity.HIGH && enabled(criticalAt)) {
            return " (escalates to CRITICAL at " + criticalAt + ")";
        }
        return "";
    }

    /** Rank for comparing two severities; higher is worse. */
    public static int rank(Severity s) {
        if (s == null) {
            return -1;
        }
        return switch (s) {
            case LOW -> 0;
            case MEDIUM -> 1;
            case HIGH -> 2;
            case CRITICAL -> 3;
        };
    }

    /**
     * Whether `candidate` is strictly worse than `current`, which is the only
     * condition under which an already-active alert is escalated rather than
     * suppressed. A null `current` (an alert row with no severity) is NOT
     * treated as the lowest rung: an unknown severity is not evidence that
     * things got worse, so it suppresses rather than escalates.
     */
    public static boolean isEscalation(Severity current, Severity candidate) {
        if (current == null || candidate == null) {
            return false;
        }
        return rank(candidate) > rank(current);
    }
}
