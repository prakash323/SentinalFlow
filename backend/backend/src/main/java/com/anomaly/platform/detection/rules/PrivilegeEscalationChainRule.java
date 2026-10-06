package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.DetectionEvidence;
import com.anomaly.platform.detection.DetectionMatch;
import com.anomaly.platform.detection.DetectionRule;
import com.anomaly.platform.detection.EventPayloads;
import com.anomaly.platform.detection.RuleContext;
import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/*
 * ============================================================
 * R007 - PRIVILEGE_ESCALATION_CHAIN
 * ============================================================
 *
 *     PROCESS_START  ->  privileged activity  ->  external connection
 *
 * ------------------------------------------------------------
 * SCHEMA-DRIVEN, NOT WISHED-FOR
 * ------------------------------------------------------------
 * The canonical shape of this rule wants a PRIVILEGE_CHANGE event. THERE IS NO
 * SUCH EVENT TYPE IN THIS PLATFORM, and none is invented here. The full set this
 * system produces is LOGIN, LOGOUT, FILE_ACCESS, API_ACCESS, TRANSACTION,
 * PASSWORD_CHANGE, PROCESS_START and NETWORK_CONNECTION - there is no privilege
 * field on any of them.
 *
 * So the middle stage is detected from what DOES exist, and only that:
 *
 *   - a FILE_ACCESS whose `commandSequence` names a privilege-elevation command
 *     (sudo, su, runas, doas, pkexec, setuid), matched on word boundaries so
 *     "sudo" does not fire on "pseudonym"; or
 *   - a PROCESS_START that IS such a binary, by processName or executablePath.
 *
 * Both are real fields carried by real producers (the frontend simulator's
 * privilege-escalation scenario populates commandSequence; the collector
 * populates processName and executablePath). Neither is a proxy invented to make
 * the rule look implementable.
 *
 * WHAT THIS MEANS HONESTLY: this rule detects a plausible privilege-elevation
 * SEQUENCE, not a confirmed privilege change. A process that elevated without
 * going through one of those commands is invisible to it. That limitation is
 * stated in the evidence of every alert it raises, and adding a real
 * PRIVILEGE_CHANGE event type is the documented next step.
 *
 * ------------------------------------------------------------
 * ORDERING IS REQUIRED
 * ------------------------------------------------------------
 * The three stages must be observed IN ORDER within the window - creation, then
 * elevation, then egress. Three unordered events on a busy host would be a
 * coincidence; this sequence is the finding. The rule triggers on the final
 * stage, the external connection, because that is the event that completes it.
 */
public class PrivilegeEscalationChainRule implements DetectionRule {

    public static final String ID = "PRIVILEGE_ESCALATION_CHAIN";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Process creation, privileged activity and external connection in sequence";
    }

    @Override
    public String description() {
        return "Detects an ordered PROCESS_START, privilege-elevation command and external "
                + "NETWORK_CONNECTION for one entity inside a window. Privilege is inferred from "
                + "commandSequence and process name, the only privilege signals the event schema carries.";
    }

    @Override
    public Set<String> consumedEventTypes() {
        return Set.of(EventPayloads.NETWORK_CONNECTION);
    }

    @Override
    public String tactic() {
        return "Privilege Escalation";
    }

    @Override
    public String technique() {
        return "T1548";
    }

    @Override
    public DetectionProperties.PrivilegeEscalationChain settings(DetectionProperties properties) {
        return properties.getRules().getPrivilegeEscalationChain();
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event connection = context.event();

        // Stage 3 is the trigger: egress completes the chain.
        if (!EventPayloads.isExternalDestination(connection)) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.PrivilegeEscalationChain cfg = settings(context.properties());
        Duration window = cfg.getWindow();

        // Stage 2: the most recent privileged activity before this connection.
        Event elevation = context
                .sameEntity(List.of(EventPayloads.FILE_ACCESS, EventPayloads.PROCESS_START), window)
                .events().stream()
                .filter(PrivilegeEscalationChainRule::isPrivilegedActivity)
                .filter(e -> !e.getOccurredAt().isAfter(connection.getOccurredAt()))
                .findFirst()
                .orElse(null);

        if (elevation == null) {
            return DetectionMatch.insufficient();
        }

        // Stage 1: a process created at or before that elevation, inside the window.
        //
        // The elevation itself is excluded: when the privilege signal IS a
        // PROCESS_START (a `sudo` binary), that one event cannot also serve as the
        // process-creation stage - two stages from one event is not a chain. The
        // window is newest-first, so this picks the latest qualifying creation,
        // which is the one that plausibly went on to elevate.
        Event processStart = context
                .sameEntity(EventPayloads.PROCESS_START, window)
                .events().stream()
                .filter(e -> e.getId() == null || !e.getId().equals(elevation.getId()))
                .filter(e -> !e.getOccurredAt().isAfter(elevation.getOccurredAt()))
                .findFirst()
                .orElse(null);

        if (processStart == null) {
            return DetectionMatch.insufficient();
        }

        String remote = EventPayloads.remoteAddress(connection).orElseThrow();
        String elevationDetail = EventPayloads.commandSequence(elevation)
                .or(() -> EventPayloads.processName(elevation))
                .orElse(elevation.getEventType());

        Duration span = Duration.between(processStart.getOccurredAt(), connection.getOccurredAt());

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .eventType(EventPayloads.PROCESS_START)
                .eventType(elevation.getEventType())
                .eventType(EventPayloads.NETWORK_CONNECTION)
                .eventId(processStart.getEventId())
                .eventId(elevation.getEventId())
                .eventId(connection.getEventId())
                .observed(processStart.getOccurredAt(), connection.getOccurredAt())
                .window(window)
                .count(3)
                .destination(remote + EventPayloads.remotePort(connection).map(p -> ":" + p).orElse(""))
                .signal("PROCESS_START " + EventPayloads.processName(processStart).orElse("(unnamed)"))
                .signal("PRIVILEGED " + elevationDetail)
                .signal("EXTERNAL_CONNECTION " + remote)
                .severityReason("Severity MEDIUM: the three stages were observed in order, but the schema "
                        + "carries no privilege-change event, so elevation is inferred rather than confirmed")
                // Never let this alert be read as a confirmed privilege change.
                .attribute("privilegeSignal", elevationDetail)
                .attribute("privilegeSignalSource", elevation.getEventType() + "."
                        + (EventPayloads.commandSequence(elevation).isPresent() ? "commandSequence" : "processName"))
                .attribute("privilegeInferred", true)
                .attribute("chainSeconds", span.getSeconds());

        EventPayloads.pid(processStart).ifPresent(evidence::processId);
        EventPayloads.processName(processStart).ifPresent(evidence::processName);

        String lead = "a process was created, ran " + elevationDetail
                + ", and connected to " + remote + " within " + DetectionEvidence.humanDuration(span);

        return DetectionMatch.of(Severity.MEDIUM, evidence.build(), lead);
    }

    /** The middle stage, from the only two fields that can carry a privilege signal. */
    static boolean isPrivilegedActivity(Event event) {
        if (EventPayloads.FILE_ACCESS.equals(event.getEventType())) {
            return EventPayloads.hasPrivilegedCommand(event);
        }
        if (EventPayloads.PROCESS_START.equals(event.getEventType())) {
            return EventPayloads.isPrivilegedProcess(event);
        }
        return false;
    }

    /** Exposed for the documentation and tests: what "privileged" can mean here at all. */
    public static Optional<String> privilegeSignalOf(Event event) {
        if (!isPrivilegedActivity(event)) {
            return Optional.empty();
        }
        return EventPayloads.commandSequence(event).or(() -> EventPayloads.processName(event));
    }
}
