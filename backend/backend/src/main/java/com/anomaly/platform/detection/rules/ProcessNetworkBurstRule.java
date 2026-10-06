package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.CorrelationWindowService;
import com.anomaly.platform.detection.DetectionEngine;
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
 * R008 - PROCESS_NETWORK_BURST
 * ============================================================
 *
 * ONE newly created process making MANY external connections in quick succession.
 *
 *     PROCESS_START              pid 8100
 *     NETWORK_CONNECTION  external
 *     NETWORK_CONNECTION  external
 *     NETWORK_CONNECTION  external
 *     NETWORK_CONNECTION  external
 *     NETWORK_CONNECTION  external
 *
 * ------------------------------------------------------------
 * THIS IS NOT R002
 * ------------------------------------------------------------
 *   R002  a new process makes ONE external connection. A single correlated
 *         pair. MEDIUM. It deliberately suppresses the second connection from
 *         the same process, because a browser opening thirty sockets is not
 *         thirty findings.
 *   R008  that same process making MANY of them inside a tight window. The
 *         VOLUME is the finding - beaconing, scanning or exfiltration shape -
 *         and it is exactly what R002's suppression hides.
 *
 * So the two are complementary by design: R002 says "this new process talked
 * out", R008 says "and it would not stop". Both can fire for one process, and
 * when they do they are two different statements, each with its own evidence.
 *
 * Correlation is the SAME exact process identity R002 uses - entity, pid, and a
 * processCreateTime matching the PROCESS_START to the second. No tolerance, and
 * a reused pid is a different process.
 *
 * Suppression is keyed on that process identity, so a different process bursting
 * on the same host still raises its own alert.
 */
public class ProcessNetworkBurstRule implements DetectionRule, DetectionEngine.KeyedSuppression {

    public static final String ID = "PROCESS_NETWORK_BURST";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "New process made repeated external connections";
    }

    @Override
    public String description() {
        return "Counts external NETWORK_CONNECTION events belonging to one newly created process "
                + "(exact pid and processCreateTime identity) inside a short window.";
    }

    @Override
    public Set<String> consumedEventTypes() {
        return Set.of(EventPayloads.NETWORK_CONNECTION);
    }

    @Override
    public String tactic() {
        return "Command and Control";
    }

    @Override
    public String technique() {
        return "T1071";
    }

    @Override
    public DetectionProperties.ProcessNetworkBurst settings(DetectionProperties properties) {
        return properties.getRules().getProcessNetworkBurst();
    }

    @Override
    public String suppressionKeyOf(Event networkConnection) {
        return EventPayloads.processIdentity(networkConnection).orElse(null);
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event trigger = context.event();

        Optional<Long> pid = EventPayloads.pid(trigger);
        Optional<String> createTime = EventPayloads.processCreateTime(trigger);
        if (pid.isEmpty() || createTime.isEmpty() || !EventPayloads.isExternalDestination(trigger)) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.ProcessNetworkBurst cfg = settings(context.properties());
        Duration window = cfg.getWindow();

        // Every external connection in the window belonging to THIS process.
        CorrelationWindowService.WindowResult connections =
                context.sameEntity(EventPayloads.NETWORK_CONNECTION, window);

        List<Event> mine = connections.events().stream()
                .filter(EventPayloads::isExternalDestination)
                .filter(e -> pid.equals(EventPayloads.pid(e)))
                .filter(e -> createTime.equals(EventPayloads.processCreateTime(e)))
                .toList();

        long count = mine.size();
        if (count < cfg.getConnectionThreshold()) {
            return DetectionMatch.insufficient();
        }

        // The process must genuinely be one this entity started, by the same
        // identity test R002 uses - not merely a pid that claims a create time.
        //
        // The PROCESS_START can be older than this rule's own burst window (the
        // burst is 60s of connections; the process may have started before it), so
        // the lookback is this window PLUS the recency bound R002 already defines
        // for "newly created". Taken from that rule's configuration rather than
        // written here, so the two cannot drift apart.
        Duration processLookback = window.plus(
                context.properties().getRules().getNewProcessExternalConnection().getWindow());

        Event processStart = context
                .sameEntity(EventPayloads.PROCESS_START, processLookback)
                .events().stream()
                .filter(start -> EventPayloads.sameProcess(trigger, start))
                .findFirst()
                .orElse(null);

        if (processStart == null) {
            return DetectionMatch.insufficient();
        }

        OffsetDateTime first = mine.stream().map(Event::getOccurredAt).min(OffsetDateTime::compareTo).orElseThrow();
        OffsetDateTime last = mine.stream().map(Event::getOccurredAt).max(OffsetDateTime::compareTo).orElseThrow();

        List<String> destinations = mine.stream()
                .map(EventPayloads::remoteAddress)
                .flatMap(Optional::stream)
                .distinct()
                .toList();

        Severity severity = SeverityModel.fromThresholds(
                count, cfg.getConnectionThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold());

        String processName = EventPayloads.processName(processStart)
                .or(() -> EventPayloads.processName(trigger))
                .orElse(null);

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .eventType(EventPayloads.PROCESS_START)
                .eventType(EventPayloads.NETWORK_CONNECTION)
                .eventId(processStart.getEventId())
                .eventIds(mine.stream().map(Event::getEventId).toList())
                .observed(first, last)
                .window(window)
                .count(count)
                .distinctTargets(destinations.size())
                .threshold(cfg.getConnectionThreshold())
                .processId(pid.get())
                .processName(processName)
                .processCreateTime(createTime.get())
                .destinations(destinations)
                .severityReason(SeverityModel.reason("external connections from one process", count,
                        cfg.getConnectionThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold()))
                .attribute("secondsFromProcessStartToLastConnection",
                        Duration.between(processStart.getOccurredAt(), last).getSeconds())
                .attribute("distinctDestinations", (long) destinations.size());

        if (connections.truncated()) {
            evidence.attribute("windowTruncated", true);
        }

        String lead = (processName == null ? "pid " + pid.get() : processName + " (pid " + pid.get() + ")")
                + " opened " + count + " external connections to " + destinations.size() + " destinations";

        return DetectionMatch.of(severity, evidence.build(), lead, suppressionKeyOf(trigger));
    }
}
