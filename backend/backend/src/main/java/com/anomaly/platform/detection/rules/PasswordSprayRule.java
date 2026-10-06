package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.CorrelationWindowService;
import com.anomaly.platform.detection.DetectionEvidence;
import com.anomaly.platform.detection.DetectionMatch;
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
 * R003 - PASSWORD_SPRAY
 * ============================================================
 *
 * ONE SOURCE, MANY IDENTITIES, FEW ATTEMPTS EACH.
 *
 * The defining shape of a spray is breadth without depth: an attacker tries one
 * or two common passwords against a long list of accounts, deliberately staying
 * under any per-account lockout. Measured per account it looks like nothing;
 * measured per source it is obvious.
 *
 *     source 203.0.113.9  ->  user1 FAIL
 *                         ->  user2 FAIL
 *                         ->  user3 FAIL
 *                         ->  user4 FAIL
 *                         ->  user5 FAIL
 *
 * ------------------------------------------------------------
 * THIS IS NOT AUTH_BURST
 * ------------------------------------------------------------
 *   AUTH_BURST (R001)    many failures against ONE entity. Depth.
 *   PASSWORD_SPRAY (R003) one source against MANY entities. Breadth.
 *
 * They correlate on different axes and neither subsumes the other. A spray that
 * also hammers one account trips both, and that is correct: they are two true
 * statements about the same activity. The evidence of each says which axis it
 * measured, so an analyst reading both is not seeing a duplicate.
 *
 * R004 (ACCOUNT_ENUMERATION) is the slower, broader cousin - see that rule for
 * exactly how the two are kept apart.
 *
 * ------------------------------------------------------------
 * LIMITATION
 * ------------------------------------------------------------
 * Correlation is by `payload.ip`, the only source identity the LOGIN schema
 * carries. An attacker rotating source addresses defeats it, and a shared
 * egress NAT can make many legitimate users look like one source. Both are
 * properties of the available data, not of this implementation; neither is
 * papered over by inferring a source that was not in the event.
 */
public class PasswordSprayRule extends SourceCorrelatedAuthRule {

    public static final String ID = "PASSWORD_SPRAY";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Single source attempting authentication against many identities";
    }

    @Override
    public String description() {
        return "Correlates failed LOGIN events by source address rather than by entity, and alerts when "
                + "one source fails against more distinct identities than the configured threshold.";
    }

    @Override
    public String tactic() {
        return "Credential Access";
    }

    @Override
    public String technique() {
        return "T1110.003";
    }

    @Override
    public DetectionProperties.PasswordSpray settings(DetectionProperties properties) {
        return properties.getRules().getPasswordSpray();
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event trigger = context.event();

        // A spray is made of failures, and it can only be correlated if the event
        // says where it came from.
        if (!EventPayloads.isAuthFailure(trigger) || !hasSource(trigger)) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.PasswordSpray cfg = settings(context.properties());
        Duration window = cfg.getWindow();

        CorrelationWindowService.WindowResult fromSource = sourceWindow(context, window);
        List<Event> failures = fromSource.events().stream()
                .filter(EventPayloads::isAuthFailure)
                .toList();

        Set<String> targets = distinctTargets(failures);
        long distinct = targets.size();

        if (distinct < cfg.getDistinctTargetThreshold()) {
            return DetectionMatch.insufficient();
        }

        String sourceIp = EventPayloads.sourceIp(trigger).orElseThrow();
        OffsetDateTime first = failures.stream().map(Event::getOccurredAt).min(OffsetDateTime::compareTo).orElse(trigger.getOccurredAt());
        OffsetDateTime last = failures.stream().map(Event::getOccurredAt).max(OffsetDateTime::compareTo).orElse(trigger.getOccurredAt());

        Severity severity = SeverityModel.fromThresholds(
                distinct, cfg.getDistinctTargetThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold());

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .source(sourceIp)
                .eventType(EventPayloads.LOGIN)
                .eventIds(failures.stream().map(Event::getEventId).toList())
                .observed(first, last)
                .window(window)
                .count(failures.size())
                .distinctTargets(distinct)
                .threshold(cfg.getDistinctTargetThreshold())
                .severityReason(SeverityModel.reason("distinct identities", distinct,
                        cfg.getDistinctTargetThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold()))
                // The breadth-not-depth signature, as a number an analyst can check.
                .attribute("attemptsPerTarget", round2((double) failures.size() / distinct))
                .attribute("targets", targets.stream().limit(20).toList());

        if (fromSource.truncated()) {
            evidence.attribute("windowTruncated", true);
        }

        String lead = failures.size() + " failed logins from one source against "
                + distinct + " distinct identities";

        return DetectionMatch.of(severity, evidence.build(), lead, sourceIp);
    }

    private static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }
}
