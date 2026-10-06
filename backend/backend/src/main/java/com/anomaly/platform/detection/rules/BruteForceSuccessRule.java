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
import java.util.Set;

/*
 * ============================================================
 * R005 - BRUTE_FORCE_SUCCESS
 * ============================================================
 *
 * FAIL, FAIL, FAIL, FAIL, FAIL ... SUCCESS.
 *
 * This is the most consequential rule in the set, and the reason it exists
 * separately from AUTH_BURST: AUTH_BURST tells you someone was ATTACKING an
 * account. This tells you they may have GOT IN. The first is an attack signal;
 * the second is a possible compromise, and they warrant different responses.
 *
 * It fires on the SUCCESS, not on the failures - the success is the event that
 * changes what the finding means. AUTH_BURST has almost certainly already fired
 * on the failures; this rule does not replace that alert and does not suppress
 * it. They are two different statements and both belong in the incident.
 *
 * ------------------------------------------------------------
 * WHAT IT CAPTURES
 * ------------------------------------------------------------
 *   - how many failures preceded the success, in the window;
 *   - when the successful login happened;
 *   - the entity, and the source address of the success;
 *   - THE GAP between the last failure and the success - the number an analyst
 *     looks at first, because a success seconds after a run of failures reads
 *     very differently from one twenty minutes later.
 *
 * `max-gap-to-success` is what stops an unrelated legitimate login hours later
 * from being presented as the end of a brute-force run. Beyond that gap the
 * failures and the success are not treated as one episode.
 *
 * Severity is HIGH by default because a possible compromise is not a MEDIUM
 * finding, and CRITICAL once the failure count passes the configured bar.
 */
public class BruteForceSuccessRule implements DetectionRule {

    public static final String ID = "BRUTE_FORCE_SUCCESS";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Successful login after repeated failures";
    }

    @Override
    public String description() {
        return "Alerts when a successful LOGIN closely follows a run of failed LOGIN events for the same "
                + "entity - possible account compromise rather than merely attempted access.";
    }

    @Override
    public Set<String> consumedEventTypes() {
        return Set.of(EventPayloads.LOGIN);
    }

    @Override
    public String tactic() {
        return "Credential Access";
    }

    @Override
    public String technique() {
        return "T1110";
    }

    @Override
    public DetectionProperties.BruteForceSuccess settings(DetectionProperties properties) {
        return properties.getRules().getBruteForceSuccess();
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event trigger = context.event();

        // The SUCCESS is the trigger. Failures alone are AUTH_BURST's business.
        if (!EventPayloads.isAuthSuccess(trigger)) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.BruteForceSuccess cfg = settings(context.properties());
        Duration window = cfg.getWindow();

        CorrelationWindowService.WindowResult recent = context.sameEntity(EventPayloads.LOGIN, window);

        // Only failures that happened BEFORE this success count towards it.
        List<Event> failures = recent.events().stream()
                .filter(EventPayloads::isAuthFailure)
                .filter(e -> !e.getOccurredAt().isAfter(trigger.getOccurredAt()))
                .toList();

        long count = failures.size();
        if (count < cfg.getFailureThreshold()) {
            return DetectionMatch.insufficient();
        }

        OffsetDateTime firstFailure = failures.stream().map(Event::getOccurredAt).min(OffsetDateTime::compareTo).orElseThrow();
        OffsetDateTime lastFailure = failures.stream().map(Event::getOccurredAt).max(OffsetDateTime::compareTo).orElseThrow();

        Duration gap = Duration.between(lastFailure, trigger.getOccurredAt());
        if (gap.isNegative() || gap.compareTo(cfg.getMaxGapToSuccess()) > 0) {
            // Too far after the last failure to call it the same episode.
            return DetectionMatch.insufficient();
        }

        Severity severity = SeverityModel.enabled(cfg.getCriticalThreshold()) && count >= cfg.getCriticalThreshold()
                ? Severity.CRITICAL
                : Severity.HIGH;

        String severityReason = severity == Severity.CRITICAL
                ? "Severity CRITICAL: " + count + " failures preceded the success, reaching the CRITICAL threshold of "
                        + cfg.getCriticalThreshold()
                : "Severity HIGH: a successful authentication following " + count
                        + " failures is a possible compromise, not merely an attempt";

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .eventType(EventPayloads.LOGIN)
                .eventIds(failures.stream().map(Event::getEventId).toList())
                .eventId(trigger.getEventId())
                .observed(firstFailure, trigger.getOccurredAt())
                .window(window)
                .count(count)
                .threshold(cfg.getFailureThreshold())
                .severityReason(severityReason)
                .attribute("successAt", trigger.getOccurredAt().toString())
                .attribute("lastFailureAt", lastFailure.toString())
                .attribute("secondsFromLastFailureToSuccess", gap.getSeconds())
                .attribute("successEventId", trigger.getEventId());

        EventPayloads.sourceIp(trigger).ifPresent(ip -> evidence.source(ip).attribute("successSourceAddress", ip));
        EventPayloads.authMethod(trigger).ifPresent(m -> evidence.attribute("successAuthMethod", m));

        // Whether the success came from the same place as the failures is the
        // single most useful extra fact here, and it is derivable from the events.
        List<String> failureSources = failures.stream()
                .map(EventPayloads::sourceIp)
                .flatMap(java.util.Optional::stream)
                .distinct()
                .limit(5)
                .toList();
        if (!failureSources.isEmpty()) {
            evidence.attribute("failureSourceAddresses", failureSources);
            EventPayloads.sourceIp(trigger).ifPresent(ip ->
                    evidence.attribute("successFromSameSourceAsFailures", failureSources.contains(ip)));
        }
        if (recent.truncated()) {
            evidence.attribute("windowTruncated", true);
        }

        String lead = "a successful login " + DetectionEvidence.humanDuration(gap)
                + " after " + count + " failed attempts";

        return DetectionMatch.of(severity, evidence.build(), lead);
    }
}
