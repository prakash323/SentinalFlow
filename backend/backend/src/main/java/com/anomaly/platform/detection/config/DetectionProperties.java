package com.anomaly.platform.detection.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/*
 * ============================================================
 * DETECTION CONFIGURATION
 * ============================================================
 *
 * Every operational threshold the deterministic rules use, in one place, bound
 * from `detection.*` in application.yml. No rule reads a magic number from its
 * own source: a rule that wants a number asks its settings object for it.
 *
 * Validated at startup (@Validated on the owning configuration class), so a
 * misconfigured window or a negative threshold fails the application fast
 * rather than silently disabling detection in production.
 *
 * The two pre-existing rules keep their historical values as defaults here, so
 * an application.yml that says nothing about detection behaves exactly as it did
 * before this configuration existed:
 *   auth-burst                        window 5m, medium 5, high 10
 *   new-process-external-connection   window 5m (recency bound)
 * Their cooldown and escalation default to OFF for the same reason.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "detection")
public class DetectionProperties {

    /** Master switch. False disables every rule without removing a bean. */
    private boolean enabled = true;

    /**
     * Hard ceiling on rows ANY correlation query may load, whatever a rule's
     * window is. The correlation state is the events table (see
     * CorrelationWindowService), so this is what keeps a single evaluation's
     * memory and query cost bounded no matter how busy an entity is.
     */
    @Min(1)
    private int maxCorrelationEvents = 500;

    @Valid
    @NotNull
    private Rules rules = new Rules();

    /* ------------------------------------------------------------------ shared shape */

    /**
     * What every rule has: a switch, a correlation window, a cooldown and
     * whether an active alert may be escalated by worse evidence.
     */
    @Getter
    @Setter
    public static class RuleSettings {

        private boolean enabled = true;

        /** How far back the rule correlates. Must be positive. */
        @NotNull
        private Duration window = Duration.ofMinutes(5);

        /**
         * After the last alert for this rule and entity CLOSED, how long before
         * another may be raised. ZERO disables the cooldown, which is the
         * historical behaviour of the two original rules.
         */
        @NotNull
        private Duration cooldown = Duration.ZERO;

        /**
         * Whether evidence more severe than an already-active alert for this
         * rule and entity raises that alert's severity instead of being
         * suppressed. OFF for the original rules so their behaviour is
         * unchanged; ON where a rising count genuinely means a worse incident.
         */
        private boolean escalate = false;

        void validate(String name) {
            if (window == null || window.isZero() || window.isNegative()) {
                throw new IllegalStateException(
                        "detection.rules." + name + ".window must be a positive duration (got " + window + ")");
            }
            if (cooldown == null || cooldown.isNegative()) {
                throw new IllegalStateException(
                        "detection.rules." + name + ".cooldown must not be negative (got " + cooldown + ")");
            }
        }

        /** A severity ladder must not go downwards; a 0 rung is "disabled", not "zero". */
        static void requireAscending(String name, String a, long av, String b, long bv) {
            if (av > 0 && bv > 0 && bv < av) {
                throw new IllegalStateException("detection.rules." + name + "." + b + " (" + bv
                        + ") must not be below " + a + " (" + av + ")");
            }
        }

        static void requirePositive(String name, String field, long value) {
            if (value <= 0) {
                throw new IllegalStateException(
                        "detection.rules." + name + "." + field + " must be greater than 0 (got " + value + ")");
            }
        }
    }

    /* ------------------------------------------------------------------ per-rule settings */

    /** R001. Historical defaults: >=5 failures in 5 minutes is MEDIUM, >=10 is HIGH. */
    @Getter
    @Setter
    public static class AuthBurst extends RuleSettings {
        private long mediumThreshold = 5;
        private long highThreshold = 10;
        /** No CRITICAL rung: nothing in this rule's evidence would justify one. */
        private long criticalThreshold = 0;

        public AuthBurst() {
            setWindow(Duration.ofMinutes(5));
        }

        void validate() {
            super.validate("auth-burst");
            requirePositive("auth-burst", "medium-threshold", mediumThreshold);
            requireAscending("auth-burst", "medium-threshold", mediumThreshold, "high-threshold", highThreshold);
            requireAscending("auth-burst", "high-threshold", highThreshold, "critical-threshold", criticalThreshold);
        }
    }

    /** R002. `window` is the rule's recency bound between process creation and the connection. */
    @Getter
    @Setter
    public static class NewProcessExternalConnection extends RuleSettings {
        public NewProcessExternalConnection() {
            setWindow(Duration.ofMinutes(5));
        }

        void validate() {
            super.validate("new-process-external-connection");
        }
    }

    /** R003. One source address, failures against many distinct entities. */
    @Getter
    @Setter
    public static class PasswordSpray extends RuleSettings {
        private long distinctTargetThreshold = 5;
        private long highThreshold = 10;
        private long criticalThreshold = 20;

        public PasswordSpray() {
            setWindow(Duration.ofMinutes(10));
            setCooldown(Duration.ofMinutes(10));
            setEscalate(true);
        }

        void validate() {
            super.validate("password-spray");
            requirePositive("password-spray", "distinct-target-threshold", distinctTargetThreshold);
            requireAscending("password-spray", "distinct-target-threshold", distinctTargetThreshold,
                    "high-threshold", highThreshold);
            requireAscending("password-spray", "high-threshold", highThreshold,
                    "critical-threshold", criticalThreshold);
        }
    }

    /**
     * R004. Broader and slower than a spray: more attempts across more
     * identities, and overwhelmingly unsuccessful.
     */
    @Getter
    @Setter
    public static class AccountEnumeration extends RuleSettings {
        private long distinctTargetThreshold = 10;
        private long attemptThreshold = 15;
        /** Above this success ratio the activity looks like use, not enumeration. */
        private double maxSuccessRatio = 0.2;
        private long highThreshold = 20;
        private long criticalThreshold = 40;

        public AccountEnumeration() {
            setWindow(Duration.ofMinutes(15));
            setCooldown(Duration.ofMinutes(15));
            setEscalate(true);
        }

        void validate() {
            super.validate("account-enumeration");
            requirePositive("account-enumeration", "distinct-target-threshold", distinctTargetThreshold);
            requirePositive("account-enumeration", "attempt-threshold", attemptThreshold);
            if (maxSuccessRatio < 0.0 || maxSuccessRatio > 1.0) {
                throw new IllegalStateException(
                        "detection.rules.account-enumeration.max-success-ratio must be between 0 and 1 (got "
                                + maxSuccessRatio + ")");
            }
            requireAscending("account-enumeration", "distinct-target-threshold", distinctTargetThreshold,
                    "high-threshold", highThreshold);
            requireAscending("account-enumeration", "high-threshold", highThreshold,
                    "critical-threshold", criticalThreshold);
        }
    }

    /** R005. Repeated failures and then a success - possible compromise, not just an attempt. */
    @Getter
    @Setter
    public static class BruteForceSuccess extends RuleSettings {
        private long failureThreshold = 5;
        /** The success must follow the last failure within this gap to be the same episode. */
        @NotNull
        private Duration maxGapToSuccess = Duration.ofMinutes(2);
        private long criticalThreshold = 10;

        public BruteForceSuccess() {
            setWindow(Duration.ofMinutes(10));
        }

        void validate() {
            super.validate("brute-force-success");
            requirePositive("brute-force-success", "failure-threshold", failureThreshold);
            if (maxGapToSuccess == null || maxGapToSuccess.isNegative()) {
                throw new IllegalStateException(
                        "detection.rules.brute-force-success.max-gap-to-success must not be negative");
            }
        }
    }

    /** R006. Only ever evaluated on events that actually carry a parseable `location`. */
    @Getter
    @Setter
    public static class ImpossibleTravel extends RuleSettings {
        /** Faster than commercial flight: the implied speed that makes the pair impossible. */
        private double minSpeedKmph = 900.0;
        /** Below this distance, clock skew and coarse city coordinates dominate. */
        private double minDistanceKm = 500.0;
        private double criticalSpeedKmph = 3000.0;

        public ImpossibleTravel() {
            setWindow(Duration.ofHours(2));
            setCooldown(Duration.ofHours(1));
        }

        void validate() {
            super.validate("impossible-travel");
            if (minSpeedKmph <= 0 || minDistanceKm <= 0) {
                throw new IllegalStateException(
                        "detection.rules.impossible-travel.min-speed-kmph and min-distance-km must be greater than 0");
            }
        }
    }

    /** R007. Process creation, privileged activity and egress, in that order. */
    @Getter
    @Setter
    public static class PrivilegeEscalationChain extends RuleSettings {
        public PrivilegeEscalationChain() {
            setWindow(Duration.ofMinutes(10));
            setCooldown(Duration.ofMinutes(10));
            setEscalate(true);
        }

        void validate() {
            super.validate("privilege-escalation-chain");
        }
    }

    /** R008. One new process, repeated egress. */
    @Getter
    @Setter
    public static class ProcessNetworkBurst extends RuleSettings {
        private long connectionThreshold = 5;
        private long highThreshold = 10;
        private long criticalThreshold = 20;

        public ProcessNetworkBurst() {
            setWindow(Duration.ofSeconds(60));
            setCooldown(Duration.ofMinutes(5));
            setEscalate(true);
        }

        void validate() {
            super.validate("process-network-burst");
            requirePositive("process-network-burst", "connection-threshold", connectionThreshold);
            requireAscending("process-network-burst", "connection-threshold", connectionThreshold,
                    "high-threshold", highThreshold);
            requireAscending("process-network-burst", "high-threshold", highThreshold,
                    "critical-threshold", criticalThreshold);
        }
    }

    /**
     * R009. Entity-wide egress volume. Needs BOTH a connection count and a
     * distinct-destination count, so a chatty client reconnecting to one server
     * does not look like a scan.
     */
    @Getter
    @Setter
    public static class NetworkConnectionBurst extends RuleSettings {
        private long connectionThreshold = 20;
        private long distinctDestinationThreshold = 10;
        private long highThreshold = 40;
        private long criticalThreshold = 80;

        public NetworkConnectionBurst() {
            setWindow(Duration.ofSeconds(60));
            setCooldown(Duration.ofMinutes(5));
            setEscalate(true);
        }

        void validate() {
            super.validate("network-connection-burst");
            requirePositive("network-connection-burst", "connection-threshold", connectionThreshold);
            requirePositive("network-connection-burst", "distinct-destination-threshold",
                    distinctDestinationThreshold);
            requireAscending("network-connection-burst", "connection-threshold", connectionThreshold,
                    "high-threshold", highThreshold);
            requireAscending("network-connection-burst", "high-threshold", highThreshold,
                    "critical-threshold", criticalThreshold);
        }
    }

    /** R010. Independent stages observed together; adds a correlation alert, replaces none. */
    @Getter
    @Setter
    public static class MultiStageAttackChain extends RuleSettings {
        /** Stages required before the chain fires. Two is a pair, three is a chain. */
        private long minStages = 3;
        private long criticalStages = 4;

        public MultiStageAttackChain() {
            setWindow(Duration.ofMinutes(30));
            setCooldown(Duration.ofMinutes(30));
        }

        void validate() {
            super.validate("multi-stage-attack-chain");
            requirePositive("multi-stage-attack-chain", "min-stages", minStages);
            requireAscending("multi-stage-attack-chain", "min-stages", minStages,
                    "critical-stages", criticalStages);
        }
    }

    /* ------------------------------------------------------------------ the catalog */

    @Getter
    @Setter
    public static class Rules {
        @Valid @NotNull private AuthBurst authBurst = new AuthBurst();
        @Valid @NotNull private NewProcessExternalConnection newProcessExternalConnection = new NewProcessExternalConnection();
        @Valid @NotNull private PasswordSpray passwordSpray = new PasswordSpray();
        @Valid @NotNull private AccountEnumeration accountEnumeration = new AccountEnumeration();
        @Valid @NotNull private BruteForceSuccess bruteForceSuccess = new BruteForceSuccess();
        @Valid @NotNull private ImpossibleTravel impossibleTravel = new ImpossibleTravel();
        @Valid @NotNull private PrivilegeEscalationChain privilegeEscalationChain = new PrivilegeEscalationChain();
        @Valid @NotNull private ProcessNetworkBurst processNetworkBurst = new ProcessNetworkBurst();
        @Valid @NotNull private NetworkConnectionBurst networkConnectionBurst = new NetworkConnectionBurst();
        @Valid @NotNull private MultiStageAttackChain multiStageAttackChain = new MultiStageAttackChain();
    }

    /**
     * Startup validation. Called from an @EventListener so a bad threshold fails
     * the application immediately with the offending property named, rather than
     * producing a detector that silently never fires.
     */
    public void validate() {
        if (maxCorrelationEvents < 1) {
            throw new IllegalStateException(
                    "detection.max-correlation-events must be at least 1 (got " + maxCorrelationEvents + ")");
        }
        rules.authBurst.validate();
        rules.newProcessExternalConnection.validate();
        rules.passwordSpray.validate();
        rules.accountEnumeration.validate();
        rules.bruteForceSuccess.validate();
        rules.impossibleTravel.validate();
        rules.privilegeEscalationChain.validate();
        rules.processNetworkBurst.validate();
        rules.networkConnectionBurst.validate();
        rules.multiStageAttackChain.validate();
    }

    /** The historical defaults, for tests and for the backward-compatible entry point. */
    public static DetectionProperties defaults() {
        return new DetectionProperties();
    }
}
