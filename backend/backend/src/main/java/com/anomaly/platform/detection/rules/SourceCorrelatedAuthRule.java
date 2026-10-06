package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.CorrelationWindowService;
import com.anomaly.platform.detection.DetectionEngine;
import com.anomaly.platform.detection.DetectionRule;
import com.anomaly.platform.detection.EventPayloads;
import com.anomaly.platform.detection.RuleContext;
import com.anomaly.platform.entity.Event;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/*
 * ============================================================
 * SHARED BASIS FOR THE SOURCE-CORRELATED AUTH RULES
 * ============================================================
 *
 * R003 (PASSWORD_SPRAY) and R004 (ACCOUNT_ENUMERATION) ask the same question -
 * "what did THIS SOURCE do across MANY identities?" - and differ only in what
 * shape of answer they call a detection. Everything they share lives here so the
 * two rules contain only what makes them different, and so neither can drift
 * from the other on how a target identity is derived.
 *
 * ------------------------------------------------------------
 * SCHEMA REALITY, STATED HONESTLY
 * ------------------------------------------------------------
 * These rules need two things the event must actually carry:
 *
 *   SOURCE    `payload.ip`. This is the ONLY source-side identity in the LOGIN
 *             schema. There is no session id, no device id that survives across
 *             accounts, and no authentication-server identifier. A LOGIN without
 *             an ip cannot be correlated this way, and these rules simply do not
 *             apply to it rather than guessing one.
 *
 *   TARGET    the identity being authenticated to. `payload.username` when the
 *             producer supplies it (the physical collector does), otherwise the
 *             event's own entityId, which is what the platform models as the
 *             thing being authenticated to.
 *
 * Nothing here is fabricated: a target is a field that was present, and a source
 * is a field that was present. The limitation this leaves is documented on each
 * rule and in the detection documentation.
 */
abstract class SourceCorrelatedAuthRule implements DetectionRule, DetectionEngine.KeyedSuppression {

    @Override
    public Set<String> consumedEventTypes() {
        return Set.of(EventPayloads.LOGIN);
    }

    /**
     * The finding is about the SOURCE, not the entity the triggering event
     * happened to belong to - so suppression must look across entities. Without
     * this, one spray against twenty accounts would raise twenty alerts.
     */
    @Override
    public boolean entityScoped() {
        return false;
    }

    @Override
    public String suppressionKeyOf(Event triggeringEvent) {
        return EventPayloads.sourceIp(triggeringEvent).orElse(null);
    }

    /**
     * The identity an authentication event was aimed at: the stated username, or
     * the entity it belongs to. Never null for a persisted event, because an
     * event always has an entity.
     */
    static String targetOf(Event event) {
        return EventPayloads.username(event)
                .orElseGet(() -> event.getEntity() == null ? null : event.getEntity().getEntityId());
    }

    static Set<String> distinctTargets(List<Event> events) {
        Set<String> targets = new LinkedHashSet<>();
        for (Event e : events) {
            String target = targetOf(e);
            if (target != null) {
                targets.add(target);
            }
        }
        return targets;
    }

    /** The window of LOGIN events from the triggering event's own source address. */
    CorrelationWindowService.WindowResult sourceWindow(RuleContext context, java.time.Duration window) {
        return context.sameSourceIp(EventPayloads.LOGIN, window);
    }

    /** Whether this event can be source-correlated at all. */
    static boolean hasSource(Event event) {
        return EventPayloads.sourceIp(event).isPresent();
    }
}
