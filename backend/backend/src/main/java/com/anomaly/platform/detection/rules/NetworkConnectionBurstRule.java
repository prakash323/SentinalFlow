package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.CorrelationWindowService;
import com.anomaly.platform.detection.DetectionEvidence;
import com.anomaly.platform.detection.DetectionMatch;
import com.anomaly.platform.detection.DetectionRule;
import com.anomaly.platform.detection.EventPayloads;
import com.anomaly.platform.detection.RuleContext;
import com.anomaly.platform.detection.SeverityModel;
import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/*
 * ============================================================
 * R009 - NETWORK_CONNECTION_BURST
 * ============================================================
 *
 * An ENTITY generating an unusually high volume of external connections in a
 * short window, whatever process they came from.
 *
 * Where R008 asks "is this ONE process talking out too much?", R009 asks "is
 * this HOST talking out too much?" - which catches activity spread across
 * several processes, and activity whose connections never correlated to a
 * PROCESS_START at all (the collector omits pid for some connection states, and
 * the frontend simulator's port-scan scenario deliberately sends none).
 *
 * ------------------------------------------------------------
 * NOT FLAGGING ORDINARY TRAFFIC
 * ------------------------------------------------------------
 * Raw connection count alone is a bad signal: a chatty client reconnecting to one
 * server, a long poll loop or a busy API integration all produce high counts and
 * none of them are interesting. So this rule requires BOTH:
 *
 *   connection-threshold            total external connections in the window;
 *   distinct-destination-threshold  how many DIFFERENT destinations they reached.
 *
 * Fan-out is what separates a scan or a beacon-hunting process from a busy but
 * ordinary client. A host that made 200 connections to one address does not fire;
 * one that made 25 across 15 addresses does.
 *
 * ------------------------------------------------------------
 * HONEST LIMITATION
 * ------------------------------------------------------------
 * "External" here means NON-LOOPBACK, because that is the only distinction the
 * event schema supports - the payload carries no routing or interface data, so a
 * LAN peer and an internet host are indistinguishable. The distinct-destination
 * requirement is what keeps that definition usable rather than noisy. Classifying
 * private ranges would be a schema change, and is listed as future work rather
 * than guessed at here.
 */
public class NetworkConnectionBurstRule implements DetectionRule {

    public static final String ID = "NETWORK_CONNECTION_BURST";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Entity generated a burst of external connections";
    }

    @Override
    public String description() {
        return "Counts external NETWORK_CONNECTION events for one entity in a short window and alerts "
                + "only when both the connection count and the distinct-destination count are exceeded.";
    }

    @Override
    public Set<String> consumedEventTypes() {
        return Set.of(EventPayloads.NETWORK_CONNECTION);
    }

    @Override
    public String tactic() {
        return "Discovery";
    }

    @Override
    public String technique() {
        return "T1046";
    }

    @Override
    public DetectionProperties.NetworkConnectionBurst settings(DetectionProperties properties) {
        return properties.getRules().getNetworkConnectionBurst();
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event trigger = context.event();

        if (!EventPayloads.isExternalDestination(trigger)) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.NetworkConnectionBurst cfg = settings(context.properties());
        Duration window = cfg.getWindow();

        CorrelationWindowService.WindowResult recent =
                context.sameEntity(EventPayloads.NETWORK_CONNECTION, window);

        List<Event> external = recent.events().stream()
                .filter(EventPayloads::isExternalDestination)
                .toList();

        long count = external.size();
        if (count < cfg.getConnectionThreshold()) {
            return DetectionMatch.insufficient();
        }

        List<String> destinations = external.stream()
                .map(EventPayloads::remoteAddress)
                .flatMap(Optional::stream)
                .distinct()
                .toList();

        long distinct = destinations.size();
        if (distinct < cfg.getDistinctDestinationThreshold()) {
            // High volume to few destinations is ordinary traffic, not fan-out.
            return DetectionMatch.insufficient();
        }

        OffsetDateTime first = external.stream().map(Event::getOccurredAt).min(OffsetDateTime::compareTo).orElseThrow();
        OffsetDateTime last = external.stream().map(Event::getOccurredAt).max(OffsetDateTime::compareTo).orElseThrow();

        Severity severity = SeverityModel.fromThresholds(
                count, cfg.getConnectionThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold());

        // Port fan-out as well as address fan-out, where the events state ports.
        long distinctPorts = external.stream()
                .map(EventPayloads::remotePort)
                .flatMap(Optional::stream)
                .distinct()
                .count();

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .eventType(EventPayloads.NETWORK_CONNECTION)
                .eventIds(external.stream().map(Event::getEventId).toList())
                .observed(first, last)
                .window(window)
                .count(count)
                .distinctTargets(distinct)
                .threshold(cfg.getConnectionThreshold())
                .destinations(destinations)
                .severityReason(SeverityModel.reason("external connections", count,
                        cfg.getConnectionThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold()))
                .attribute("distinctDestinations", distinct)
                .attribute("distinctDestinationThreshold", cfg.getDistinctDestinationThreshold())
                .attribute("externalMeans", "non-loopback; the event schema carries no routing information");

        if (distinctPorts > 0) {
            evidence.attribute("distinctRemotePorts", distinctPorts);
        }
        if (recent.truncated()) {
            evidence.attribute("windowTruncated", true);
        }

        String lead = count + " external connections to " + distinct + " distinct destinations";

        return DetectionMatch.of(severity, evidence.build(), lead);
    }
}
