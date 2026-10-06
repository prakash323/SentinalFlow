package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.DetectionEngine;
import com.anomaly.platform.detection.DetectionEvidence;
import com.anomaly.platform.detection.DetectionMatch;
import com.anomaly.platform.detection.DetectionRule;
import com.anomaly.platform.detection.EventPayloads;
import com.anomaly.platform.detection.RuleContext;
import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/*
 * ============================================================
 * R002 - NEW_PROCESS_EXTERNAL_CONNECTION
 * ============================================================
 *
 * A freshly created process that opens a non-loopback connection.
 *
 * ------------------------------------------------------------
 * THE MATCHING CONTRACT IS UNCHANGED, DELIBERATELY
 * ------------------------------------------------------------
 * The correlation is an EXACT identity match with NO time tolerance:
 *
 *   - the same entity;
 *   - the same numeric pid;
 *   - a processCreateTime equal, character for character, to the PROCESS_START's
 *     occurredAt in UTC truncated to whole seconds;
 *   - a non-loopback remoteAddress;
 *   - the connection at or after process creation, and within the recency bound.
 *
 * The recency bound is what makes "newly created" mean anything: without it,
 * any process's connection would qualify and the rule would say nothing.
 *
 * pid alone is NOT identity - operating systems reuse pids. The createTime match
 * is what distinguishes "this process" from "a later, unrelated process that
 * happened to get the same pid", and weakening it to a tolerance window would
 * silently reintroduce that false positive. It is not relaxed here.
 *
 * ------------------------------------------------------------
 * SUPPRESSION IS KEYED ON THE PROCESS, NOT THE HOST
 * ------------------------------------------------------------
 * One alert per process identity, not per connection: a freshly started browser
 * or updater routinely opens dozens of connections in its first minutes, and each
 * one used to raise its own alert (27 OPEN alerts for a single pid were observed
 * on the physical host). A DIFFERENT new process on the same host still raises
 * its own alert - which is why this rule supplies a suppression key rather than
 * letting the engine suppress per entity.
 *
 * ------------------------------------------------------------
 * WHAT IS NEW
 * ------------------------------------------------------------
 * The evidence now spells out the whole correlation chain - process, pid,
 * destination and the time delta between creation and connection - rather than
 * one sentence. R008 covers the repeated-connection case this rule deliberately
 * suppresses.
 */
public class NewProcessExternalConnectionRule implements DetectionRule, DetectionEngine.KeyedSuppression {

    public static final String ID = "NEW_PROCESS_EXTERNAL_CONNECTION";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "New process established a non-loopback network connection";
    }

    @Override
    public String description() {
        return "Correlates a NETWORK_CONNECTION to a PROCESS_START by exact pid and processCreateTime "
                + "identity, and alerts when a process connects outside loopback shortly after being created.";
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
    public DetectionProperties.NewProcessExternalConnection settings(DetectionProperties properties) {
        return properties.getRules().getNewProcessExternalConnection();
    }

    /**
     * The process this connection belongs to. Rebuilt identically from a stored
     * alert's own triggering NETWORK_CONNECTION, so the engine compares like with
     * like when deciding whether an active alert already covers this process.
     */
    @Override
    public String suppressionKeyOf(Event networkConnection) {
        return EventPayloads.processIdentity(networkConnection).orElse(null);
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event connection = context.event();

        // The rule needs a numeric pid, a stated processCreateTime and a
        // destination. Anything else is not this rule's business - and a payload
        // missing one of them must never crash processing.
        Optional<Long> pid = EventPayloads.pid(connection);
        Optional<String> createTime = EventPayloads.processCreateTime(connection);
        Optional<String> remote = EventPayloads.remoteAddress(connection);
        if (pid.isEmpty() || createTime.isEmpty() || remote.isEmpty()) {
            return DetectionMatch.notApplicable();
        }

        // Loopback is not egress.
        if (EventPayloads.isLoopback(remote.get())) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.NewProcessExternalConnection cfg = settings(context.properties());
        Duration recency = cfg.getWindow();

        Event processStart = context.sameEntity(EventPayloads.PROCESS_START, recency)
                .events().stream()
                .filter(start -> EventPayloads.sameProcess(connection, start))
                .findFirst()
                .orElse(null);

        if (processStart == null) {
            return DetectionMatch.insufficient();
        }

        Duration sinceCreation = Duration.between(processStart.getOccurredAt(), connection.getOccurredAt());
        if (sinceCreation.isNegative() || sinceCreation.compareTo(recency) > 0) {
            return DetectionMatch.insufficient();
        }

        String processName = EventPayloads.processName(processStart)
                .or(() -> EventPayloads.processName(connection))
                .orElse(null);

        DetectionEvidence evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .eventType(EventPayloads.PROCESS_START)
                .eventType(EventPayloads.NETWORK_CONNECTION)
                .eventId(processStart.getEventId())
                .eventId(connection.getEventId())
                .observed(processStart.getOccurredAt(), connection.getOccurredAt())
                .window(recency)
                .processId(pid.get())
                .processName(processName)
                .processCreateTime(createTime.get())
                .destination(remote.get() + EventPayloads.remotePort(connection).map(p -> ":" + p).orElse(""))
                .severityReason("Severity MEDIUM: a single correlated process-to-external-connection pair. "
                        + "Repeated egress from one process is " + ProcessNetworkBurstRule.ID + ".")
                .attribute("secondsAfterProcessCreation", sinceCreation.getSeconds())
                .build();

        // PROCESS -> PID -> DESTINATION -> TIME DELTA, in the operator's words.
        String lead = (processName == null ? "pid " + pid.get() : processName + " (pid " + pid.get() + ")")
                + " connected to " + remote.get()
                + EventPayloads.remotePort(connection).map(p -> ":" + p).orElse("")
                + " " + DetectionEvidence.humanDuration(sinceCreation) + " after it was created";

        return DetectionMatch.of(Severity.MEDIUM, evidence, lead, suppressionKeyOf(connection));
    }
}
