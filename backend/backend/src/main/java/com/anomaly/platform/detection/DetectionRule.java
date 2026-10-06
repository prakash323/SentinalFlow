package com.anomaly.platform.detection;

import com.anomaly.platform.detection.config.DetectionProperties;

import java.time.Duration;
import java.util.Set;

/*
 * ============================================================
 * ONE DETERMINISTIC RULE
 * ============================================================
 *
 * Adding rule N+1 means writing one class that implements this interface and
 * declaring it as a bean in DetectionConfig. Nothing else changes: no switch
 * statement grows, no existing rule is touched, no registry is edited by hand
 * and nothing is discovered by reflection or classpath scanning.
 *
 * A rule is a PURE DECISION. It reads the triggering event and a bounded window
 * around it, and returns either a match with its severity and structured
 * evidence, or a reason it did not match. It cannot write, raise, suppress or
 * audit anything - the engine does all of that, identically for every rule,
 * which is what makes suppression and audit behaviour impossible to get wrong
 * per rule.
 *
 * Implementations must be stateless and therefore thread-safe: the only state a
 * rule ever sees is the window it is handed.
 */
public interface DetectionRule {

    /**
     * Stable, never-changing identifier. It is persisted on every alert this
     * rule raises (alerts.rule_id) and is the deduplication key behind the
     * uk_alerts_event_rule unique index, so renaming one would orphan history.
     */
    String id();

    /** Operator-facing name, persisted on the alert (alerts.rule_name, VARCHAR(200)). */
    String name();

    /** What the rule looks for, for the rule catalog and the documentation table. */
    String description();

    /**
     * Event types this rule is evaluated for. The engine skips the rule entirely
     * for anything else, so an unrelated event type costs no query and takes no
     * row lock.
     */
    Set<String> consumedEventTypes();

    /** MITRE ATT&CK tactic this rule's behaviour sits in, or null when none maps cleanly. */
    default String tactic() {
        return null;
    }

    /** MITRE ATT&CK technique id (e.g. "T1110"), or null. */
    default String technique() {
        return null;
    }

    /** This rule's settings, pulled from the one configuration object. */
    DetectionProperties.RuleSettings settings(DetectionProperties properties);

    /** The correlation window this rule uses, for the catalog and the docs. */
    default Duration window(DetectionProperties properties) {
        return settings(properties).getWindow();
    }

    default boolean isEnabled(DetectionProperties properties) {
        return properties.isEnabled() && settings(properties).isEnabled();
    }

    /**
     * Evaluate the triggering event. Must never throw: a rule that cannot decide
     * returns {@link DetectionMatch#insufficient()} or
     * {@link DetectionMatch#notApplicable()}. The engine guards this anyway, but
     * a rule that relies on that guard is a rule with a bug.
     */
    DetectionMatch evaluate(RuleContext context);
}
