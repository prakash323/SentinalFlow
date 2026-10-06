package com.anomaly.platform.detection;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/*
 * ============================================================
 * STRUCTURED DETECTION EVIDENCE
 * ============================================================
 *
 * What a rule actually observed, as data rather than a sentence. The
 * human-readable alert message is GENERATED from this (see summary()), so the
 * text and the structure can never disagree, and no number in a message exists
 * without a field behind it.
 *
 * Every field is optional and left null/empty when the event schema does not
 * carry it. A rule never populates a field it cannot support: there is no
 * placeholder, no zero standing in for "unknown" and nothing inferred. That is
 * the whole point - the evidence is the audit trail.
 */
public final class DetectionEvidence {

    private final String ruleId;
    private final String ruleName;
    private final String entityId;
    /** The correlating source when the rule correlates by source rather than by entity (e.g. a login source IP). */
    private final String source;
    private final List<String> eventIds;
    private final List<String> eventTypes;
    private final OffsetDateTime firstObservedAt;
    private final OffsetDateTime lastObservedAt;
    private final Long windowSeconds;
    private final Long count;
    private final Long distinctTargets;
    private final Long processId;
    private final String processName;
    private final String processCreateTime;
    private final List<String> destinations;
    private final List<String> contributingSignals;
    private final String severityReason;
    private final Long threshold;
    private final Map<String, Object> attributes;

    private DetectionEvidence(Builder b) {
        this.ruleId = b.ruleId;
        this.ruleName = b.ruleName;
        this.entityId = b.entityId;
        this.source = b.source;
        this.eventIds = List.copyOf(b.eventIds);
        this.eventTypes = List.copyOf(b.eventTypes);
        this.firstObservedAt = b.firstObservedAt;
        this.lastObservedAt = b.lastObservedAt;
        this.windowSeconds = b.windowSeconds;
        this.count = b.count;
        this.distinctTargets = b.distinctTargets;
        this.processId = b.processId;
        this.processName = b.processName;
        this.processCreateTime = b.processCreateTime;
        this.destinations = List.copyOf(b.destinations);
        this.contributingSignals = List.copyOf(b.contributingSignals);
        this.severityReason = b.severityReason;
        this.threshold = b.threshold;
        this.attributes = Map.copyOf(b.attributes);
    }

    public static Builder builder(String ruleId, String ruleName) {
        return new Builder(ruleId, ruleName);
    }

    public String ruleId() { return ruleId; }
    public String ruleName() { return ruleName; }
    public String entityId() { return entityId; }
    public String source() { return source; }
    public List<String> eventIds() { return eventIds; }
    public List<String> eventTypes() { return eventTypes; }
    public OffsetDateTime firstObservedAt() { return firstObservedAt; }
    public OffsetDateTime lastObservedAt() { return lastObservedAt; }
    public Long windowSeconds() { return windowSeconds; }
    public Long count() { return count; }
    public Long distinctTargets() { return distinctTargets; }
    public Long processId() { return processId; }
    public String processName() { return processName; }
    public String processCreateTime() { return processCreateTime; }
    public List<String> destinations() { return destinations; }
    public List<String> contributingSignals() { return contributingSignals; }
    public String severityReason() { return severityReason; }
    public Long threshold() { return threshold; }
    public Map<String, Object> attributes() { return attributes; }

    /** The observed span of the evidence, when both ends are known. */
    public Duration observedSpan() {
        if (firstObservedAt == null || lastObservedAt == null) {
            return null;
        }
        Duration d = Duration.between(firstObservedAt, lastObservedAt);
        return d.isNegative() ? Duration.ZERO : d;
    }

    /*
     * ============================================================
     * THE ALERT MESSAGE, GENERATED FROM THE EVIDENCE
     * ============================================================
     *
     * One sentence, built only from fields that are actually populated. The
     * leading clause is supplied by the rule (it knows what it detected); the
     * quantified tail is assembled here so every rule reads the same way and no
     * rule can quietly stop citing its numbers.
     */
    public String summary(String leadClause) {
        StringBuilder sb = new StringBuilder(ruleId).append(" detected: ").append(leadClause);

        List<String> tail = new ArrayList<>();
        if (entityId != null) {
            tail.add("entity " + entityId);
        }
        if (source != null) {
            tail.add("source " + source);
        }
        Duration span = observedSpan();
        if (span != null) {
            tail.add("within " + humanDuration(span));
        }
        if (threshold != null) {
            tail.add("threshold " + threshold);
        }
        if (!tail.isEmpty()) {
            sb.append(" for ").append(String.join(", ", tail));
        }
        if (severityReason != null) {
            sb.append(". ").append(severityReason);
        }
        return sb.append('.').toString();
    }

    /** "56s", "4m 12s", "2h 05m" - never a raw ISO-8601 duration in operator-facing text. */
    public static String humanDuration(Duration d) {
        long seconds = Math.max(0, d.getSeconds());
        if (seconds < 60) {
            return seconds + "s";
        }
        if (seconds < 3600) {
            return (seconds / 60) + "m " + String.format("%02ds", seconds % 60);
        }
        return (seconds / 3600) + "h " + String.format("%02dm", (seconds % 3600) / 60);
    }

    /**
     * The evidence as a flat map for the audit log's JSONB `details` column.
     * Null and empty fields are omitted rather than written as nulls, so an
     * audit row shows exactly what was known and nothing else.
     */
    public Map<String, Object> toAuditDetails() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ruleId", ruleId);
        m.put("ruleName", ruleName);
        putIfPresent(m, "entityId", entityId);
        putIfPresent(m, "source", source);
        if (!eventIds.isEmpty()) {
            m.put("eventIds", eventIds);
        }
        if (!eventTypes.isEmpty()) {
            m.put("eventTypes", eventTypes);
        }
        putIfPresent(m, "firstObservedAt", firstObservedAt == null ? null : firstObservedAt.toString());
        putIfPresent(m, "lastObservedAt", lastObservedAt == null ? null : lastObservedAt.toString());
        putIfPresent(m, "windowSeconds", windowSeconds);
        putIfPresent(m, "count", count);
        putIfPresent(m, "distinctTargets", distinctTargets);
        putIfPresent(m, "threshold", threshold);
        putIfPresent(m, "processId", processId);
        putIfPresent(m, "processName", processName);
        putIfPresent(m, "processCreateTime", processCreateTime);
        if (!destinations.isEmpty()) {
            m.put("destinations", destinations);
        }
        if (!contributingSignals.isEmpty()) {
            m.put("contributingSignals", contributingSignals);
        }
        putIfPresent(m, "severityReason", severityReason);
        m.putAll(attributes);
        return m;
    }

    private static void putIfPresent(Map<String, Object> m, String key, Object value) {
        if (value != null) {
            m.put(key, value);
        }
    }

    public static final class Builder {
        private final String ruleId;
        private final String ruleName;
        private String entityId;
        private String source;
        private final List<String> eventIds = new ArrayList<>();
        private final List<String> eventTypes = new ArrayList<>();
        private OffsetDateTime firstObservedAt;
        private OffsetDateTime lastObservedAt;
        private Long windowSeconds;
        private Long count;
        private Long distinctTargets;
        private Long processId;
        private String processName;
        private String processCreateTime;
        private final List<String> destinations = new ArrayList<>();
        private final List<String> contributingSignals = new ArrayList<>();
        private String severityReason;
        private Long threshold;
        private final Map<String, Object> attributes = new LinkedHashMap<>();

        /** Contributing event ids kept on one alert. Enough to investigate, bounded so a burst cannot bloat a row. */
        public static final int MAX_EVENT_IDS = 25;
        /** Distinct destinations listed on one alert. */
        public static final int MAX_DESTINATIONS = 15;

        private Builder(String ruleId, String ruleName) {
            this.ruleId = ruleId;
            this.ruleName = ruleName;
        }

        public Builder entityId(String v) { this.entityId = v; return this; }
        public Builder source(String v) { this.source = v; return this; }

        public Builder eventId(String v) {
            if (v != null && !eventIds.contains(v) && eventIds.size() < MAX_EVENT_IDS) {
                eventIds.add(v);
            }
            return this;
        }

        public Builder eventIds(List<String> v) {
            if (v != null) {
                v.forEach(this::eventId);
            }
            return this;
        }

        public Builder eventType(String v) {
            if (v != null && !eventTypes.contains(v)) {
                eventTypes.add(v);
            }
            return this;
        }

        public Builder observed(OffsetDateTime first, OffsetDateTime last) {
            this.firstObservedAt = first;
            this.lastObservedAt = last;
            return this;
        }

        public Builder window(Duration v) {
            this.windowSeconds = v == null ? null : v.getSeconds();
            return this;
        }

        public Builder count(long v) { this.count = v; return this; }
        public Builder distinctTargets(long v) { this.distinctTargets = v; return this; }
        public Builder threshold(long v) { this.threshold = v; return this; }
        public Builder processId(Long v) { this.processId = v; return this; }
        public Builder processName(String v) { this.processName = v; return this; }
        public Builder processCreateTime(String v) { this.processCreateTime = v; return this; }

        public Builder destination(String v) {
            if (v != null && !destinations.contains(v) && destinations.size() < MAX_DESTINATIONS) {
                destinations.add(v);
            }
            return this;
        }

        public Builder destinations(List<String> v) {
            if (v != null) {
                v.forEach(this::destination);
            }
            return this;
        }

        public Builder signal(String v) {
            if (v != null && !contributingSignals.contains(v)) {
                contributingSignals.add(v);
            }
            return this;
        }

        public Builder severityReason(String v) { this.severityReason = v; return this; }

        public Builder attribute(String key, Object value) {
            if (key != null && value != null) {
                attributes.put(key, value);
            }
            return this;
        }

        public DetectionEvidence build() {
            return new DetectionEvidence(this);
        }
    }
}
