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
 * R004 - ACCOUNT_ENUMERATION
 * ============================================================
 *
 * ONE SOURCE PROBING WHICH IDENTITIES EXIST.
 *
 * Enumeration is reconnaissance, not credential theft: the attacker is learning
 * which accounts are real, so the activity is broad, sustained, and almost
 * entirely unsuccessful. The near-total absence of successes is the signature -
 * a source that touches many identities and succeeds against a healthy share of
 * them is a batch job or an integration, not an attacker mapping a directory.
 *
 * ------------------------------------------------------------
 * HOW IT IS KEPT DISTINCT FROM R003
 * ------------------------------------------------------------
 * Both correlate failures by source address, so overlapping alerts would be a
 * real risk. Three separate conditions keep them apart, and all three must hold
 * here:
 *
 *   1. BREADTH      more distinct identities than a spray needs
 *                   (default 10 vs 5).
 *   2. VOLUME       a minimum total attempt count (default 15), which a spray's
 *                   deliberately shallow one-or-two-per-account pattern does not
 *                   reach at its own threshold.
 *   3. OUTCOME      the success ratio across the window must stay at or below
 *                   max-success-ratio. R003 does not look at successes at all.
 *
 * and they run over a longer window (15m vs 10m), because enumeration is paced
 * to stay quiet.
 *
 * When activity genuinely satisfies both rules, both fire - and that is the
 * correct outcome, not a duplicate: one says "this source is guessing passwords
 * broadly", the other says "this source is mapping the directory". Their evidence
 * states which measurement each made, so neither is mistaken for the other.
 *
 * ------------------------------------------------------------
 * LIMITATION
 * ------------------------------------------------------------
 * The schema carries no "user does not exist" signal - the only authentication
 * outcome is `loginSuccess`. True enumeration detection would distinguish
 * "wrong password" from "no such user"; this rule cannot, and does not pretend
 * to. It infers enumeration from breadth, volume and a near-zero success rate,
 * which is what the available data supports.
 */
public class AccountEnumerationRule extends SourceCorrelatedAuthRule {

    public static final String ID = "ACCOUNT_ENUMERATION";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Single source probing many distinct identities";
    }

    @Override
    public String description() {
        return "Correlates authentication attempts by source address and alerts on sustained, broad, "
                + "overwhelmingly unsuccessful activity against many distinct identities.";
    }

    @Override
    public String tactic() {
        return "Reconnaissance";
    }

    @Override
    public String technique() {
        return "T1589.002";
    }

    @Override
    public DetectionProperties.AccountEnumeration settings(DetectionProperties properties) {
        return properties.getRules().getAccountEnumeration();
    }

    @Override
    public DetectionMatch evaluate(RuleContext context) {

        Event trigger = context.event();

        if (!EventPayloads.isAuthFailure(trigger) || !hasSource(trigger)) {
            return DetectionMatch.notApplicable();
        }

        DetectionProperties.AccountEnumeration cfg = settings(context.properties());
        Duration window = cfg.getWindow();

        CorrelationWindowService.WindowResult fromSource = sourceWindow(context, window);

        // Only events that stated an outcome count towards the ratio: a LOGIN with
        // no loginSuccess field is neither a success nor a failure here.
        List<Event> decided = fromSource.events().stream()
                .filter(EventPayloads::hasAuthResult)
                .toList();
        List<Event> failures = decided.stream().filter(EventPayloads::isAuthFailure).toList();
        long successes = decided.stream().filter(EventPayloads::isAuthSuccess).count();

        long attempts = decided.size();
        Set<String> targets = distinctTargets(failures);
        long distinct = targets.size();

        if (attempts < cfg.getAttemptThreshold() || distinct < cfg.getDistinctTargetThreshold()) {
            return DetectionMatch.insufficient();
        }

        double successRatio = attempts == 0 ? 0.0 : (double) successes / attempts;
        if (successRatio > cfg.getMaxSuccessRatio()) {
            // Broad AND largely succeeding is use, not enumeration.
            return DetectionMatch.insufficient();
        }

        String sourceIp = EventPayloads.sourceIp(trigger).orElseThrow();
        OffsetDateTime first = decided.stream().map(Event::getOccurredAt).min(OffsetDateTime::compareTo).orElse(trigger.getOccurredAt());
        OffsetDateTime last = decided.stream().map(Event::getOccurredAt).max(OffsetDateTime::compareTo).orElse(trigger.getOccurredAt());

        Severity severity = SeverityModel.fromThresholds(
                distinct, cfg.getDistinctTargetThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold());

        DetectionEvidence.Builder evidence = DetectionEvidence.builder(ID, name())
                .entityId(context.entityId())
                .source(sourceIp)
                .eventType(EventPayloads.LOGIN)
                .eventIds(failures.stream().map(Event::getEventId).toList())
                .observed(first, last)
                .window(window)
                .count(attempts)
                .distinctTargets(distinct)
                .threshold(cfg.getDistinctTargetThreshold())
                .severityReason(SeverityModel.reason("distinct identities probed", distinct,
                        cfg.getDistinctTargetThreshold(), cfg.getHighThreshold(), cfg.getCriticalThreshold()))
                // The three measurements that distinguish this from a spray.
                .attribute("failedAttempts", (long) failures.size())
                .attribute("successfulAttempts", successes)
                .attribute("successRatio", Math.round(successRatio * 1000.0) / 1000.0)
                .attribute("maxSuccessRatio", cfg.getMaxSuccessRatio())
                .attribute("attemptThreshold", cfg.getAttemptThreshold())
                .attribute("targets", targets.stream().limit(20).toList());

        if (fromSource.truncated()) {
            evidence.attribute("windowTruncated", true);
        }

        String lead = attempts + " authentication attempts from one source against "
                + distinct + " distinct identities with " + successes + " successes";

        return DetectionMatch.of(severity, evidence.build(), lead, sourceIp);
    }
}
