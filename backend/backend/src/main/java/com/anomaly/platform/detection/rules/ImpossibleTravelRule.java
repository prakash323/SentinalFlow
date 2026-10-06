package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.CorrelationWindowService;
import com.anomaly.platform.detection.DetectionEvidence;
import com.anomaly.platform.detection.DetectionMatch;
import com.anomaly.platform.detection.DetectionRule;
import com.anomaly.platform.detection.EventPayloads;
import com.anomaly.platform.detection.GeoPoint;
import com.anomaly.platform.detection.RuleContext;
import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/*
 * ============================================================
 * R006 - IMPOSSIBLE_TRAVEL
 * ============================================================
 *
 * Two authentications by one identity from places too far apart for the time
 * between them.
 *
 * ------------------------------------------------------------
 * IMPLEMENTED, BUT ONLY WHERE THE DATA IS REAL
 * ------------------------------------------------------------
 * This rule was conditional on the schema actually carrying reliable location,
 * so the honest position has to be stated precisely:
 *
 *   WHAT EXISTS   the LOGIN payload's `location` field, in the form
 *                 `City|lat|lon`, with coordinates the ML service's own contract
 *                 already validates. Both simulators populate it.
 *
 *   WHAT DOES NOT The physical collector performs NO geo-IP lookup and omits the
 *                 field entirely (normalizer.py: "Never included: location (no
 *                 geo-IP lookup performed in this phase)"). There is no GeoIP
 *                 database in this platform and none is invented here.
 *
 * So `location` is the EVENT SOURCE'S OWN CLAIM about where it was, not a lookup
 * this platform performed. The rule therefore:
 *
 *   - evaluates ONLY events that actually carry a parseable location; an event
 *     without one is NOT_APPLICABLE, never assumed to be "the usual place";
 *   - records in its evidence that the location was self-reported, so nobody
 *     reading the alert mistakes it for a geolocated fact;
 *   - never fires on an entity whose events have no location - which, today,
 *     means it never fires on physical-collector telemetry at all.
 *
 * No GPS data is fabricated and no address is geocoded. Adding a real GeoIP
 * lookup is the documented next step; until then this detects exactly what the
 * data supports and says so.
 *
 * ------------------------------------------------------------
 * HOW IMPOSSIBILITY IS DECIDED
 * ------------------------------------------------------------
 * Great-circle distance (haversine) over the elapsed time gives an implied
 * average speed. Two guards keep it honest:
 *
 *   min-distance-km   below this, city-level coordinates and clock skew dominate
 *                     and a high implied speed means nothing.
 *   min-speed-kmph    above commercial flight speed, so a genuine fast journey
 *                     is not flagged.
 *
 * Both comparisons use the events' own occurredAt, so the rule is deterministic
 * and replay-safe.
 */
public class ImpossibleTravelRule implements DetectionRule {

    public static final String ID = "IMPOSSIBLE_TRAVEL";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Authentication from geographically incompatible locations";
    }

    @Override
    public String description() {
        return "Compares the self-reported locations of consecutive authentications for one entity and "
                + "alerts when the implied travel speed is physically impossible. Only evaluated for "
                + "events that carry a parseable location.";
    }

    @Override
    public Set<String> consumedEventTypes() {
        return Set.of(EventPayloads.LOGIN);
    }

    @Override
    public String tactic() {
        return "Initial Access";
    }

    @Override
    public String technique() {
        return "T1078";
    }

    @Override
    public DetectionProperties.ImpossibleTravel settings(DetectionProperties properties) {
        return properties.getRules().getImpossibleTravel();
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event trigger = context.event();

        // Only a login that actually happened, and actually says where from.
        if (!EventPayloads.isAuthSuccess(trigger)) {
            return DetectionMatch.notApplicable();
        }
        Optional<GeoPoint> here = EventPayloads.location(trigger).flatMap(GeoPoint::parse);
        if (here.isEmpty()) {
            // No location on this event: nothing to compare. Never assumed.
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.ImpossibleTravel cfg = settings(context.properties());
        Duration window = cfg.getWindow();

        CorrelationWindowService.WindowResult recent = context.sameEntity(EventPayloads.LOGIN, window);

        // The most recent earlier successful login that also stated a location.
        Event previous = null;
        GeoPoint there = null;
        for (Event candidate : recent.events()) {
            if (candidate.getId() != null && candidate.getId().equals(trigger.getId())) {
                continue;
            }
            if (!EventPayloads.isAuthSuccess(candidate)) {
                continue;
            }
            if (candidate.getOccurredAt().isAfter(trigger.getOccurredAt())) {
                continue;
            }
            Optional<GeoPoint> point = EventPayloads.location(candidate).flatMap(GeoPoint::parse);
            if (point.isEmpty()) {
                continue;
            }
            // The window is newest-first, so the first match is the closest in time.
            previous = candidate;
            there = point.get();
            break;
        }

        if (previous == null) {
            return DetectionMatch.insufficient();
        }

        long seconds = Duration.between(previous.getOccurredAt(), trigger.getOccurredAt()).getSeconds();
        double distanceKm = there.distanceKmTo(here.get());

        if (distanceKm < cfg.getMinDistanceKm()) {
            return DetectionMatch.insufficient();
        }

        Optional<Double> speed = there.impliedSpeedKmph(here.get(), seconds);
        if (speed.isEmpty() || speed.get() < cfg.getMinSpeedKmph()) {
            return DetectionMatch.insufficient();
        }

        double impliedKmph = speed.get();
        Severity severity = impliedKmph >= cfg.getCriticalSpeedKmph() ? Severity.CRITICAL : Severity.HIGH;

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .eventType(EventPayloads.LOGIN)
                .eventId(previous.getEventId())
                .eventId(trigger.getEventId())
                .observed(previous.getOccurredAt(), trigger.getOccurredAt())
                .window(window)
                .count(2)
                .severityReason("Severity " + severity + ": an implied " + round(impliedKmph)
                        + " km/h exceeds the impossibility threshold of " + round(cfg.getMinSpeedKmph()) + " km/h")
                .attribute("fromCity", there.city())
                .attribute("toCity", here.get().city())
                .attribute("distanceKm", round(distanceKm))
                .attribute("elapsedSeconds", seconds)
                .attribute("impliedSpeedKmph", round(impliedKmph))
                .attribute("minSpeedKmph", cfg.getMinSpeedKmph())
                .attribute("minDistanceKm", cfg.getMinDistanceKm())
                // Stated on every alert this rule raises, so the basis is never overstated.
                .attribute("locationSource", "self-reported in the event payload; no geo-IP lookup is performed");

        EventPayloads.sourceIp(previous).ifPresent(ip -> evidence.attribute("fromSourceAddress", ip));
        EventPayloads.sourceIp(trigger).ifPresent(ip -> evidence.attribute("toSourceAddress", ip));

        String lead = "a login from " + there.city() + " followed by one from " + here.get().city()
                + " " + DetectionEvidence.humanDuration(Duration.ofSeconds(seconds)) + " later, implying "
                + round(impliedKmph) + " km/h over " + round(distanceKm) + " km";

        return DetectionMatch.of(severity, evidence.build(), lead);
    }

    private static double round(double v) {
        return Math.round(v * 10.0) / 10.0;
    }

    /** Whether this rule can say anything at all about an event. Used by the docs and tests. */
    public static boolean hasUsableLocation(Event event) {
        return EventPayloads.location(event).flatMap(GeoPoint::parse).isPresent();
    }
}
