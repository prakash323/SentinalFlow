package com.anomaly.platform.detection;

import com.anomaly.platform.detection.config.DetectionProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/*
 * ============================================================
 * THE RULE CATALOG
 * ============================================================
 *
 * The explicit, ordered list of rules this deployment runs, built from the beans
 * declared in DetectionConfig. No classpath scanning, no reflection, no
 * annotation magic: the set of active rules is a list a reader can see.
 *
 * Construction fails loudly on a duplicate rule id, because two rules sharing an
 * id would collide on alerts.rule_id - the column that drives deduplication, the
 * uk_alerts_event_rule unique index, suppression lookups and the frontend's
 * RULE/ML distinction.
 *
 * Rule ORDER here has no effect on outcome: every rule is evaluated
 * independently against the same event and window, and none can see another's
 * result. The order is purely the order the catalog lists them in (R001..R010),
 * and RuleOrderInvarianceTest holds that property down.
 */
public class RuleRegistry {

    private final List<DetectionRule> rules;
    private final Map<String, DetectionRule> byId;

    public RuleRegistry(List<DetectionRule> rules) {
        List<DetectionRule> ordered = List.copyOf(rules == null ? List.of() : rules);
        Map<String, DetectionRule> index = new LinkedHashMap<>();
        for (DetectionRule rule : ordered) {
            DetectionRule clash = index.putIfAbsent(rule.id(), rule);
            if (clash != null) {
                throw new IllegalStateException(
                        "Duplicate detection rule id '" + rule.id() + "': "
                                + clash.getClass().getName() + " and " + rule.getClass().getName()
                                + ". Rule ids are persisted on alerts and must be unique.");
            }
        }
        this.rules = ordered;
        this.byId = Map.copyOf(index);
    }

    public List<DetectionRule> all() {
        return rules;
    }

    public DetectionRule byId(String ruleId) {
        return byId.get(ruleId);
    }

    public int size() {
        return rules.size();
    }

    /**
     * Rules that consume this event type. Everything else is skipped before any
     * query or row lock, so an event type no rule cares about costs nothing.
     */
    public List<DetectionRule> forEventType(String eventType) {
        if (eventType == null) {
            return List.of();
        }
        List<DetectionRule> matching = new ArrayList<>();
        for (DetectionRule rule : rules) {
            if (rule.consumedEventTypes().contains(eventType)) {
                matching.add(rule);
            }
        }
        return matching;
    }

    /** Every event type any rule consumes. */
    public Set<String> consumedEventTypes() {
        return rules.stream()
                .flatMap(r -> r.consumedEventTypes().stream())
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    /** The catalog as data, for the admin endpoint and the documentation. Exposes no thresholds. */
    public List<RuleDescriptor> describe(DetectionProperties properties) {
        List<RuleDescriptor> out = new ArrayList<>(rules.size());
        for (DetectionRule rule : rules) {
            out.add(RuleDescriptor.of(rule, properties));
        }
        return List.copyOf(out);
    }
}
