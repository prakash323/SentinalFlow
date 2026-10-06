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
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/*
 * ============================================================
 * R010 - MULTI_STAGE_ATTACK_CHAIN
 * ============================================================
 *
 *     authentication anomaly  +  suspicious process  +  external connection
 *
 * The only rule here that is ABOUT other findings. Each low-level signal below
 * is, on its own, something a busy environment produces every day. Observed
 * together on one entity inside one window, in order, they are a campaign shape -
 * and that is a different, higher-level statement than any of them alone.
 *
 * ------------------------------------------------------------
 * IT ADDS, IT NEVER REPLACES
 * ------------------------------------------------------------
 * This rule raises an ADDITIONAL correlation alert. It does not suppress,
 * consume, resolve or supersede the underlying alerts - AUTH_BURST and
 * NEW_PROCESS_EXTERNAL_CONNECTION still fire exactly as they would have, and an
 * analyst still has each stage's own evidence. The engine treats this rule like
 * any other, so nothing special happens to the others because it fired.
 *
 * ------------------------------------------------------------
 * STAGES ARE READ FROM EVENTS, NOT FROM ALERTS
 * ------------------------------------------------------------
 * A deliberate choice. Deriving the stages from whether other RULES fired would
 * make this rule's behaviour depend on their suppression state: a continuing
 * burst that was correctly suppressed would silently remove a stage, and the
 * chain would not be detected precisely when activity was most sustained.
 *
 * Reading the underlying EVENTS instead makes it deterministic, independent of
 * alert lifecycle, and replay-safe. The evidence still names the rule that covers
 * each stage, so an analyst can pivot straight to those alerts.
 *
 * ------------------------------------------------------------
 * ORDER MATTERS
 * ------------------------------------------------------------
 * Stages must be observed in sequence: credential activity, then process
 * creation, then egress. Unordered co-occurrence on a busy host is a
 * coincidence. The rule fires on the final external connection, the event that
 * completes the chain, and only when at least `min-stages` are present.
 */
public class MultiStageAttackChainRule implements DetectionRule {

    public static final String ID = "MULTI_STAGE_ATTACK_CHAIN";

    /** One observed stage of the chain: what it was, when, and which rule covers it. */
    private record Stage(String label, OffsetDateTime at, String eventId, String coveringRule) {
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Multi-stage behaviour chain observed for one entity";
    }

    @Override
    public String description() {
        return "Correlates independent low-level signals - repeated authentication failure, process "
                + "creation and external connection - observed in order for one entity inside a window. "
                + "Raises an additional correlation alert; the underlying alerts are unaffected.";
    }

    @Override
    public Set<String> consumedEventTypes() {
        return Set.of(EventPayloads.NETWORK_CONNECTION);
    }

    @Override
    public String tactic() {
        return "Multiple";
    }

    @Override
    public String technique() {
        return "T1110, T1543, T1071";
    }

    @Override
    public DetectionProperties.MultiStageAttackChain settings(DetectionProperties properties) {
        return properties.getRules().getMultiStageAttackChain();
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event connection = context.event();

        // The chain completes on egress.
        if (!EventPayloads.isExternalDestination(connection)) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.MultiStageAttackChain cfg = settings(context.properties());
        Duration window = cfg.getWindow();
        DetectionProperties.AuthBurst authCfg = context.properties().getRules().getAuthBurst();

        List<Stage> stages = new ArrayList<>();

        /* ---- stage 1: repeated authentication failure (what AUTH_BURST covers) ---- */
        List<Event> authFailures = context.sameEntity(EventPayloads.LOGIN, window)
                .events().stream()
                .filter(EventPayloads::isAuthFailure)
                .filter(e -> !e.getOccurredAt().isAfter(connection.getOccurredAt()))
                .toList();

        if (authFailures.size() >= authCfg.getMediumThreshold()) {
            OffsetDateTime at = authFailures.stream()
                    .map(Event::getOccurredAt).min(OffsetDateTime::compareTo).orElseThrow();
            stages.add(new Stage(
                    authFailures.size() + " failed logins",
                    at,
                    authFailures.get(authFailures.size() - 1).getEventId(),
                    AuthBurstRule.ID));
        }

        /* ---- stage 2: a successful login right after those failures (BRUTE_FORCE_SUCCESS) ---- */
        Optional<Event> compromise = context.sameEntity(EventPayloads.LOGIN, window)
                .events().stream()
                .filter(EventPayloads::isAuthSuccess)
                .filter(e -> !e.getOccurredAt().isAfter(connection.getOccurredAt()))
                .filter(e -> authFailures.stream().anyMatch(f -> f.getOccurredAt().isBefore(e.getOccurredAt())))
                .findFirst();

        compromise.ifPresent(e -> stages.add(new Stage(
                "successful login after failures", e.getOccurredAt(), e.getEventId(), BruteForceSuccessRule.ID)));

        /* ---- stage 3: process creation ---- */
        Optional<Event> processStart = context.sameEntity(EventPayloads.PROCESS_START, window)
                .events().stream()
                .filter(e -> !e.getOccurredAt().isAfter(connection.getOccurredAt()))
                .reduce((first, second) -> second);   // the window is newest-first; take the earliest

        processStart.ifPresent(e -> stages.add(new Stage(
                "process " + EventPayloads.processName(e).orElse("(unnamed)") + " started",
                e.getOccurredAt(), e.getEventId(), NewProcessExternalConnectionRule.ID)));

        /* ---- stage 4: the external connection that triggered this evaluation ---- */
        String remote = EventPayloads.remoteAddress(connection).orElseThrow();
        stages.add(new Stage("external connection to " + remote,
                connection.getOccurredAt(), connection.getEventId(), NewProcessExternalConnectionRule.ID));

        if (stages.size() < cfg.getMinStages()) {
            return DetectionMatch.insufficient();
        }

        // Stages must be in chronological order to be a chain rather than a coincidence.
        List<Stage> ordered = stages.stream()
                .sorted(java.util.Comparator.comparing(Stage::at))
                .toList();

        OffsetDateTime first = ordered.get(0).at();
        OffsetDateTime last = ordered.get(ordered.size() - 1).at();
        Duration span = Duration.between(first, last);

        long stageCount = ordered.size();
        Severity severity = stageCount >= cfg.getCriticalStages() ? Severity.CRITICAL : Severity.HIGH;

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .eventType(EventPayloads.LOGIN)
                .eventType(EventPayloads.PROCESS_START)
                .eventType(EventPayloads.NETWORK_CONNECTION)
                .observed(first, last)
                .window(window)
                .count(stageCount)
                .threshold(cfg.getMinStages())
                .destination(remote)
                .severityReason("Severity " + severity + ": " + stageCount + " chain stages were observed in order"
                        + (severity == Severity.CRITICAL
                                ? ", reaching the CRITICAL threshold of " + cfg.getCriticalStages()
                                : " (escalates to CRITICAL at " + cfg.getCriticalStages() + ")"))
                .attribute("stageCount", stageCount)
                .attribute("chainSeconds", span.getSeconds())
                // Which rule owns each stage, so the analyst can pivot to those alerts.
                .attribute("coveringRules", ordered.stream().map(Stage::coveringRule).distinct().toList())
                .attribute("correlationOnly",
                        "this alert is additional; the underlying rule alerts are raised independently");

        for (Stage stage : ordered) {
            evidence.signal(stage.label());
            evidence.eventId(stage.eventId());
        }

        String lead = String.join(" -> ", ordered.stream().map(Stage::label).toList());

        return DetectionMatch.of(severity, evidence.build(), lead);
    }
}
