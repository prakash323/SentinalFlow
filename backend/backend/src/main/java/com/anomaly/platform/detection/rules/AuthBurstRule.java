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
 * R001 - AUTH_BURST
 * ============================================================
 *
 * Repeated failed authentication against ONE entity.
 *
 * Contrast with R003/R004, which correlate the other way round: AUTH_BURST is
 * many failures against one identity; PASSWORD_SPRAY is one source against many
 * identities. An attacker doing both trips both rules, and they are genuinely
 * different findings.
 *
 * ------------------------------------------------------------
 * BEHAVIOUR PRESERVED EXACTLY
 * ------------------------------------------------------------
 * This is a re-implementation of the original rule on the new framework, not a
 * change to it. Every decision it made, it still makes:
 *
 *   - fires on a LOGIN whose OWN payload reports loginSuccess == false
 *     (strictly false - a missing result is never read as a failure);
 *   - counts failed LOGINs for the same ENTITY in the five minutes up to and
 *     including the triggering event, ignoring the source address entirely;
 *   - MEDIUM at >= 5 failures, HIGH at >= 10;
 *   - suppressed while an earlier AUTH_BURST alert for the entity is still
 *     open/acknowledged/investigating, so a continuing burst raises one alert
 *     rather than one per attempt (the engine does this; escalation is OFF by
 *     default for this rule, so the historical behaviour is unchanged).
 *
 * The original 20 DeterministicRuleService tests run against this implementation
 * unchanged, which is the proof.
 *
 * ------------------------------------------------------------
 * WHAT IS NEW
 * ------------------------------------------------------------
 * The evidence. The alert used to carry one sentence with a count in it; it now
 * carries the count, the first and last failure timestamps, the real observed
 * span, the window, the threshold that was crossed, the contributing event ids
 * and the authentication context (source addresses and auth methods seen), all
 * as structured data the message is generated from.
 */
public class AuthBurstRule implements DetectionRule {

    public static final String ID = "AUTH_BURST";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Repeated failed login attempts";
    }

    @Override
    public String description() {
        return "Counts failed LOGIN events for one entity inside a sliding window and alerts once the "
                + "count reaches the configured threshold. Source-address independent.";
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
    public DetectionProperties.AuthBurst settings(DetectionProperties properties) {
        return properties.getRules().getAuthBurst();
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event trigger = context.event();

        // Only a reported FAILURE can start this. A success, or a LOGIN with no
        // stated result, is not evidence of anything here.
        if (!EventPayloads.isAuthFailure(trigger)) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.AuthBurst cfg = settings(context.properties());
        Duration window = cfg.getWindow();

        CorrelationWindowService.WindowResult recent = context.sameEntity(EventPayloads.LOGIN, window);
        List<Event> failures = recent.events().stream()
                .filter(EventPayloads::isAuthFailure)
                .toList();

        long count = failures.size();
        if (count < cfg.getMediumThreshold()) {
            return DetectionMatch.insufficient();
        }

        OffsetDateTime first = failures.stream()
                .map(Event::getOccurredAt)
                .min(OffsetDateTime::compareTo)
                .orElse(trigger.getOccurredAt());
        OffsetDateTime last = failures.stream()
                .map(Event::getOccurredAt)
                .max(OffsetDateTime::compareTo)
                .orElse(trigger.getOccurredAt());

        Severity severity = SeverityModel.fromThresholds(
                count, cfg.getMediumThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold());

        // The authentication context the window actually showed. Only fields the
        // events carried - a payload without them contributes nothing.
        List<String> sources = failures.stream()
                .map(EventPayloads::sourceIp)
                .flatMap(java.util.Optional::stream)
                .distinct()
                .limit(5)
                .toList();
        List<String> methods = failures.stream()
                .map(EventPayloads::authMethod)
                .flatMap(java.util.Optional::stream)
                .distinct()
                .limit(3)
                .toList();

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .eventType(EventPayloads.LOGIN)
                .eventIds(failures.stream().map(Event::getEventId).toList())
                .observed(first, last)
                .window(window)
                .count(count)
                .threshold(cfg.getMediumThreshold())
                .severityReason(SeverityModel.reason("failed login attempts", count,
                        cfg.getMediumThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold()));

        if (!sources.isEmpty()) {
            evidence.attribute("sourceAddresses", sources);
            // One source is a single-origin burst; several is a distributed one.
            evidence.attribute("distinctSourceAddresses", (long) sources.size());
        }
        if (!methods.isEmpty()) {
            evidence.attribute("authMethods", methods);
        }
        if (recent.truncated()) {
            // Honesty about a capped window: the count is a floor, not an exact figure.
            evidence.attribute("windowTruncated", true);
        }

        String lead = count + " failed login attempts";
        return DetectionMatch.of(severity, evidence.build(), lead);
    }
}
