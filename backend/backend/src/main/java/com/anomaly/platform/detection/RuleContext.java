package com.anomaly.platform.detection;

import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Event;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Collection;

/*
 * ============================================================
 * WHAT A RULE IS GIVEN
 * ============================================================
 *
 * One triggering event, and bounded read access to the correlation window around
 * it. A rule gets nothing else: no repositories, no alert service, no incident
 * service and no way to write anything. A rule's only job is to decide whether
 * its evidence is met and to describe it; raising, suppressing, escalating and
 * auditing all belong to the DetectionEngine.
 *
 * That separation is what keeps rules small, independently testable and safe to
 * add to - a new rule cannot accidentally create an alert, bypass suppression or
 * corrupt anything, because it holds no reference that would let it.
 *
 * Every correlation accessor is bounded by `maxEvents` (detection.max-correlation-events)
 * and by the window the rule passes in. "Now" is always the triggering event's
 * own occurredAt, never wall-clock time, so evaluation is deterministic and
 * replay-safe: re-processing an old event reproduces exactly the same window.
 */
public final class RuleContext {

    private final Event event;
    private final CorrelationWindowService correlation;
    private final DetectionProperties properties;

    public RuleContext(Event event, CorrelationWindowService correlation, DetectionProperties properties) {
        this.event = event;
        this.correlation = correlation;
        this.properties = properties;
    }

    public Event event() {
        return event;
    }

    public String eventType() {
        return event.getEventType();
    }

    public String entityId() {
        return event.getEntity() == null ? null : event.getEntity().getEntityId();
    }

    /**
     * The reference instant for every window: the triggering event's own
     * occurredAt. Deterministic by construction - a replay of the same event a
     * week later evaluates exactly the same window it did the first time.
     */
    public OffsetDateTime at() {
        return event.getOccurredAt();
    }

    public DetectionProperties properties() {
        return properties;
    }

    public int maxEvents() {
        return properties.getMaxCorrelationEvents();
    }

    /* ------------------------------------------------------------------ bounded correlation */

    /** Events of one type for the triggering entity, within `window` before the trigger. */
    public CorrelationWindowService.WindowResult sameEntity(String eventType, Duration window) {
        return correlation.byEntityAndType(entityId(), eventType, at(), window, maxEvents());
    }

    /** Events of several types for the triggering entity, within `window`. */
    public CorrelationWindowService.WindowResult sameEntity(Collection<String> eventTypes, Duration window) {
        return correlation.byEntityAndTypes(entityId(), eventTypes, at(), window, maxEvents());
    }

    /**
     * Events of one type from the SAME SOURCE ADDRESS as the triggering event,
     * across entities. Empty when the triggering event carries no source address -
     * the rules that use this simply do not apply to such an event.
     */
    public CorrelationWindowService.WindowResult sameSourceIp(String eventType, Duration window) {
        return EventPayloads.sourceIp(event)
                .map(ip -> correlation.bySourceIpAndType(ip, eventType, at(), window, maxEvents()))
                .orElseGet(CorrelationWindowService.WindowResult::empty);
    }
}
