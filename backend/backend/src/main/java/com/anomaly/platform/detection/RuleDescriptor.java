package com.anomaly.platform.detection;

import com.anomaly.platform.detection.config.DetectionProperties;

import java.util.List;

/*
 * One rule, as data: what it is, what it reads and whether it is on.
 *
 * Deliberately carries NO threshold values. The catalog is readable by an
 * analyst, and a threshold is operational configuration - publishing "this rule
 * fires at 5 failures in 5 minutes" tells anyone who can read it exactly how far
 * to stay under the bar. The window is included because it describes the rule's
 * shape rather than its sensitivity, and the documentation (not the API) carries
 * the full threshold table for operators.
 */
public record RuleDescriptor(
        String id,
        String name,
        String description,
        boolean enabled,
        List<String> eventTypes,
        /** The severities this rule can produce, worst first. */
        List<String> severities,
        String tactic,
        String technique,
        long windowSeconds
) {

    static RuleDescriptor of(DetectionRule rule, DetectionProperties properties) {
        return new RuleDescriptor(
                rule.id(),
                rule.name(),
                rule.description(),
                rule.isEnabled(properties),
                rule.consumedEventTypes().stream().sorted().toList(),
                severitiesOf(rule, properties),
                rule.tactic(),
                rule.technique(),
                rule.window(properties).getSeconds()
        );
    }

    /**
     * Which rungs of the severity ladder this rule can actually reach, derived
     * from its configured thresholds rather than listed by hand - so a rule with
     * its CRITICAL rung disabled never advertises CRITICAL.
     */
    private static List<String> severitiesOf(DetectionRule rule, DetectionProperties properties) {
        DetectionProperties.RuleSettings s = rule.settings(properties);
        List<String> out = new java.util.ArrayList<>();
        if (s instanceof DetectionProperties.AuthBurst a) {
            addLadder(out, a.getMediumThreshold(), a.getHighThreshold(), a.getCriticalThreshold());
        } else if (s instanceof DetectionProperties.PasswordSpray a) {
            addLadder(out, a.getDistinctTargetThreshold(), a.getHighThreshold(), a.getCriticalThreshold());
        } else if (s instanceof DetectionProperties.AccountEnumeration a) {
            addLadder(out, a.getDistinctTargetThreshold(), a.getHighThreshold(), a.getCriticalThreshold());
        } else if (s instanceof DetectionProperties.ProcessNetworkBurst a) {
            addLadder(out, a.getConnectionThreshold(), a.getHighThreshold(), a.getCriticalThreshold());
        } else if (s instanceof DetectionProperties.NetworkConnectionBurst a) {
            addLadder(out, a.getConnectionThreshold(), a.getHighThreshold(), a.getCriticalThreshold());
        } else if (s instanceof DetectionProperties.MultiStageAttackChain a) {
            addLadder(out, a.getMinStages(), 0, a.getCriticalStages());
        } else if (s instanceof DetectionProperties.BruteForceSuccess a) {
            addLadder(out, a.getFailureThreshold(), 0, a.getCriticalThreshold());
        } else if (s instanceof DetectionProperties.ImpossibleTravel) {
            out.add("CRITICAL");
            out.add("HIGH");
        } else {
            // A rule with a single fixed severity (R002, R007).
            out.add("MEDIUM");
        }
        return List.copyOf(out);
    }

    private static void addLadder(List<String> out, long mediumAt, long highAt, long criticalAt) {
        if (SeverityModel.enabled(criticalAt)) {
            out.add("CRITICAL");
        }
        if (SeverityModel.enabled(highAt)) {
            out.add("HIGH");
        }
        if (SeverityModel.enabled(mediumAt)) {
            out.add("MEDIUM");
        }
    }
}
