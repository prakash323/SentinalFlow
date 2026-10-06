package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.DetectionEngine;
import com.anomaly.platform.detection.DetectionOutcome;
import com.anomaly.platform.detection.DetectionTestHarness;
import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static com.anomaly.platform.detection.DetectionTestHarness.NOW;
import static com.anomaly.platform.detection.DetectionTestHarness.login;
import static org.assertj.core.api.Assertions.assertThat;

/*
 * R001 AUTH_BURST: threshold behaviour, window boundaries, severity escalation
 * and the evidence the alert must be able to justify itself with.
 *
 * The historical contract (>=5 in 5m is MEDIUM, >=10 is HIGH, suppressed while
 * active) is also covered by DeterministicRuleServiceTest, which runs unchanged
 * against this implementation. These tests cover the boundaries and the evidence
 * that test never asserted.
 */
class AuthBurstRuleTest {

    private DetectionTestHarness harness() {
        return DetectionTestHarness.with(new AuthBurstRule());
    }

    /** `count` failures ending at NOW, one minute apart, for one entity. */
    private Event failures(DetectionTestHarness h, String entityId, int count) {
        Event last = null;
        for (int i = count - 1; i >= 0; i--) {
            last = h.store(entityId, "LOGIN", NOW.minusSeconds(i * 10L), login(false, "203.0.113.9"));
        }
        return last;
    }

    /* ---------------- exact threshold, and either side of it ---------------- */

    @Test
    @DisplayName("threshold - 1 failures: no alert")
    void belowThreshold() {
        DetectionTestHarness h = harness();
        Event trigger = failures(h, "HOST-1", 4);

        var results = h.evaluate(trigger);

        assertThat(DetectionTestHarness.outcomeOf(results, AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        assertThat(h.alerts.stored).isEmpty();
    }

    @Test
    @DisplayName("exactly the threshold: MEDIUM alert")
    void atThreshold() {
        DetectionTestHarness h = harness();
        Event trigger = failures(h, "HOST-1", 5);

        var results = h.evaluate(trigger);

        assertThat(DetectionTestHarness.outcomeOf(results, AuthBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(DetectionTestHarness.severityOf(results, AuthBurstRule.ID)).isEqualTo(Severity.MEDIUM);
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
    }

    @Test
    @DisplayName("threshold + 1 failures: still MEDIUM until the HIGH bar")
    void justAboveThreshold() {
        DetectionTestHarness h = harness();
        Event trigger = failures(h, "HOST-1", 6);

        assertThat(DetectionTestHarness.severityOf(h.evaluate(trigger), AuthBurstRule.ID)).isEqualTo(Severity.MEDIUM);
    }

    @Test
    @DisplayName("HIGH threshold - 1: MEDIUM; exactly HIGH threshold: HIGH")
    void highThresholdBoundary() {
        DetectionTestHarness nine = harness();
        assertThat(DetectionTestHarness.severityOf(nine.evaluate(failures(nine, "HOST-9", 9)), AuthBurstRule.ID))
                .isEqualTo(Severity.MEDIUM);

        DetectionTestHarness ten = harness();
        assertThat(DetectionTestHarness.severityOf(ten.evaluate(failures(ten, "HOST-10", 10)), AuthBurstRule.ID))
                .isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("no CRITICAL rung: however many failures, AUTH_BURST stops at HIGH")
    void neverCritical() {
        DetectionTestHarness h = harness();
        assertThat(DetectionTestHarness.severityOf(h.evaluate(failures(h, "HOST-X", 60)), AuthBurstRule.ID))
                .isEqualTo(Severity.HIGH);
    }

    /* ---------------- the time window ---------------- */

    @Test
    @DisplayName("a failure exactly on the window boundary still counts")
    void windowBoundaryInclusive() {
        DetectionTestHarness h = harness();
        // Four inside, one exactly 5 minutes before the trigger.
        h.store("HOST-W", "LOGIN", NOW.minusMinutes(5), login(false, "203.0.113.9"));
        for (int i = 3; i >= 1; i--) {
            h.store("HOST-W", "LOGIN", NOW.minusSeconds(i * 10L), login(false, "203.0.113.9"));
        }
        Event trigger = h.store("HOST-W", "LOGIN", NOW, login(false, "203.0.113.9"));

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.DETECTED);
    }

    @Test
    @DisplayName("a failure one second outside the window does not count")
    void outsideWindowExcluded() {
        DetectionTestHarness h = harness();
        h.store("HOST-W", "LOGIN", NOW.minusMinutes(5).minusSeconds(1), login(false, "203.0.113.9"));
        for (int i = 3; i >= 1; i--) {
            h.store("HOST-W", "LOGIN", NOW.minusSeconds(i * 10L), login(false, "203.0.113.9"));
        }
        Event trigger = h.store("HOST-W", "LOGIN", NOW, login(false, "203.0.113.9"));

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
    }

    @Test
    @DisplayName("events after the triggering event are never counted towards it")
    void futureEventsExcluded() {
        DetectionTestHarness h = harness();
        Event trigger = failures(h, "HOST-F", 4);
        // Out-of-order arrival: a later failure is stored but must not justify an
        // alert on an earlier event.
        h.store("HOST-F", "LOGIN", NOW.plusMinutes(1), login(false, "203.0.113.9"));

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
    }

    /* ---------------- what counts as a failure ---------------- */

    @Test
    @DisplayName("successes never count, and a LOGIN with no stated result counts as neither")
    void onlyExplicitFailuresCount() {
        DetectionTestHarness h = harness();
        for (int i = 0; i < 4; i++) {
            h.store("HOST-M", "LOGIN", NOW.minusSeconds(60 - i), login(false, "203.0.113.9"));
        }
        h.store("HOST-M", "LOGIN", NOW.minusSeconds(20), login(true, "203.0.113.9"));
        h.store("HOST-M", "LOGIN", NOW.minusSeconds(15), Map.of("ip", "203.0.113.9"));   // no result stated
        Event trigger = h.store("HOST-M", "LOGIN", NOW, login(false, "203.0.113.9"));

        // 5 failures total (4 + the trigger); the success and the silent event add nothing.
        var results = h.evaluate(trigger);
        assertThat(DetectionTestHarness.outcomeOf(results, AuthBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED).get("count")).isEqualTo(5L);
    }

    @Test
    @DisplayName("a successful trigger is not this rule's business at all")
    void successTriggerIsNotApplicable() {
        DetectionTestHarness h = harness();
        failures(h, "HOST-S", 9);
        Event success = h.store("HOST-S", "LOGIN", NOW, login(true, "203.0.113.9"));

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(success), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
    }

    @Test
    @DisplayName("failures against a different entity are a different finding")
    void entitiesAreIndependent() {
        DetectionTestHarness h = harness();
        for (int i = 0; i < 4; i++) {
            h.store("HOST-A", "LOGIN", NOW.minusSeconds(60 - i), login(false, "203.0.113.9"));
        }
        for (int i = 0; i < 4; i++) {
            h.store("HOST-B", "LOGIN", NOW.minusSeconds(60 - i), login(false, "203.0.113.9"));
        }
        Event trigger = h.store("HOST-A", "LOGIN", NOW, login(false, "203.0.113.9"));

        // 5 for HOST-A, so it fires; HOST-B's four never contributed.
        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.DETECTED);
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
        assertThat(h.alertsFor(AuthBurstRule.ID).get(0).getEntity().getEntityId()).isEqualTo("HOST-A");
    }

    /* ---------------- malformed and missing data ---------------- */

    @Test
    @DisplayName("a malformed payload never crashes processing")
    void malformedPayloadIsSafe() {
        DetectionTestHarness h = harness();
        for (int i = 0; i < 5; i++) {
            h.store("HOST-BAD", "LOGIN", NOW.minusSeconds(60 - i), login(false, "203.0.113.9"));
        }
        Map<String, Object> nonsense = new java.util.HashMap<>();
        nonsense.put("loginSuccess", "false");      // a string, not a boolean
        nonsense.put("ip", 12345);                   // a number, not an address
        Event trigger = h.store("HOST-BAD", "LOGIN", NOW, nonsense);

        // "false" the string is not a failure, so the trigger does not apply - and
        // nothing throws.
        assertThat(h.evaluate(trigger)).isNotNull();
        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
    }

    @Test
    @DisplayName("an empty payload is safe")
    void emptyPayloadIsSafe() {
        DetectionTestHarness h = harness();
        Event trigger = h.store("HOST-E", "LOGIN", NOW, Map.of());
        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
    }

    @Test
    @DisplayName("a failing correlation query never propagates out of the engine")
    void queryFailureIsContained() {
        DetectionTestHarness h = harness();
        Event trigger = h.store("HOST-Q", "LOGIN", NOW, login(false, "203.0.113.9"));
        h.events.failQueriesWith = new RuntimeException("simulated database failure");

        assertThat(h.evaluate(trigger)).isNotNull();
        assertThat(h.alerts.stored).isEmpty();
    }

    /* ---------------- evidence: why did this fire? ---------------- */

    @Test
    @DisplayName("the alert can justify itself: count, window, threshold, timestamps and sources")
    void evidenceAnswersWhyItFired() {
        DetectionTestHarness h = harness();
        Event trigger = failures(h, "HOST-EV", 8);

        h.evaluate(trigger);

        Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
        assertThat(audit).isNotNull();
        assertThat(audit.get("ruleId")).isEqualTo(AuthBurstRule.ID);
        assertThat(audit.get("entityId")).isEqualTo("HOST-EV");
        assertThat(audit.get("count")).isEqualTo(8L);
        assertThat(audit.get("threshold")).isEqualTo(5L);
        assertThat(audit.get("windowSeconds")).isEqualTo(300L);
        assertThat(audit.get("severity")).isEqualTo("MEDIUM");
        assertThat(audit).containsKeys("firstObservedAt", "lastObservedAt", "eventIds", "severityReason");
        assertThat((List<?>) audit.get("eventIds")).isNotEmpty();
        assertThat(audit.get("sourceAddresses")).isEqualTo(List.of("203.0.113.9"));

        // The message is generated from that evidence, and quotes it.
        String message = String.valueOf(audit.get("message"));
        assertThat(message)
                .contains("AUTH_BURST detected")
                .contains("8 failed login attempts")
                .contains("HOST-EV")
                .contains("threshold 5");
        assertThat(message).doesNotContain("Suspicious activity");
    }

    @Test
    @DisplayName("the severity reason names the number and the bar it crossed")
    void severityReasonIsExplicit() {
        DetectionTestHarness h = harness();
        h.evaluate(failures(h, "HOST-SR", 12));

        String reason = String.valueOf(h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED).get("severityReason"));
        assertThat(reason).isEqualTo("Severity HIGH: failed login attempts 12 reached the HIGH threshold of 10");
    }

    @Test
    @DisplayName("evidence is stored as ranked alert factors, each inside the column limit")
    void evidenceIsStoredAsFactors() {
        DetectionTestHarness h = harness();
        h.evaluate(failures(h, "HOST-FA", 7));

        Alert alert = h.alertsFor(AuthBurstRule.ID).get(0);
        List<String> factors = h.factorsOf(alert);
        assertThat(factors).isNotEmpty();
        assertThat(factors).allSatisfy(f -> assertThat(f.length()).isLessThanOrEqualTo(128));
        assertThat(factors.get(0)).contains("AUTH_BURST detected");
        assertThat(factors).anySatisfy(f -> assertThat(f).contains("Observed 7 against a threshold of 5"));
    }

    /* ---------------- configuration ---------------- */

    @Test
    @DisplayName("a disabled rule produces no detection at all")
    void disabledRuleDoesNothing() {
        DetectionProperties props = DetectionProperties.defaults();
        props.getRules().getAuthBurst().setEnabled(false);
        DetectionTestHarness h = DetectionTestHarness.with(props, new AuthBurstRule());

        Event trigger = failures(h, "HOST-D", 20);

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
        assertThat(h.alerts.stored).isEmpty();
    }

    @Test
    @DisplayName("the master switch disables every rule")
    void masterSwitchDisablesEverything() {
        DetectionProperties props = DetectionProperties.defaults();
        props.setEnabled(false);
        DetectionTestHarness h = DetectionTestHarness.with(props, new AuthBurstRule());

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(failures(h, "HOST-D", 20)), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
    }

    @Test
    @DisplayName("changed thresholds change the outcome, with nothing hard-coded in Java")
    void thresholdsAreConfigurable() {
        DetectionProperties props = DetectionProperties.defaults();
        props.getRules().getAuthBurst().setMediumThreshold(3);
        props.getRules().getAuthBurst().setHighThreshold(4);
        DetectionTestHarness h = DetectionTestHarness.with(props, new AuthBurstRule());

        Event trigger = failures(h, "HOST-C", 4);

        assertThat(DetectionTestHarness.severityOf(h.evaluate(trigger), AuthBurstRule.ID)).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("a changed window changes which failures count")
    void windowIsConfigurable() {
        DetectionProperties props = DetectionProperties.defaults();
        props.getRules().getAuthBurst().setWindow(Duration.ofSeconds(30));
        DetectionTestHarness h = DetectionTestHarness.with(props, new AuthBurstRule());

        for (int i = 0; i < 4; i++) {
            h.store("HOST-TW", "LOGIN", NOW.minusMinutes(2).plusSeconds(i), login(false, "203.0.113.9"));
        }
        Event trigger = h.store("HOST-TW", "LOGIN", NOW, login(false, "203.0.113.9"));

        // Only the trigger is inside the 30s window.
        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
    }

    /* ---------------- suppression, duplication and escalation ---------------- */

    @Test
    @DisplayName("a redelivery of the same event is a DUPLICATE, not a second alert")
    void duplicateDelivery() {
        DetectionTestHarness h = harness();
        Event trigger = failures(h, "HOST-DUP", 6);

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID)).isEqualTo(DetectionOutcome.DUPLICATE);
        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(trigger), AuthBurstRule.ID)).isEqualTo(DetectionOutcome.DUPLICATE);

        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
        assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_CREATED)).isEqualTo(1);
    }

    @Test
    @DisplayName("a continuing burst is suppressed while the first alert is still active")
    void suppressedWhileActive() {
        DetectionTestHarness h = harness();
        Event first = failures(h, "HOST-SUP", 6);
        h.evaluate(first);

        Event next = h.store("HOST-SUP", "LOGIN", NOW.plusSeconds(5), login(false, "203.0.113.9"));
        var results = h.evaluate(next);

        assertThat(DetectionTestHarness.outcomeOf(results, AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.SUPPRESSED_ACTIVE_ALERT);
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);

        Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_SUPPRESSED);
        assertThat(audit.get("outcome")).isEqualTo("SUPPRESSED_ACTIVE_ALERT");
        assertThat(String.valueOf(audit.get("suppressionReason")))
                .contains("still active for this entity")
                .contains("no new alert was raised");
    }

    @Test
    @DisplayName("suppression is recorded once per triggering event, however often it is retried")
    void suppressionRecordedOncePerEvent() {
        DetectionTestHarness h = harness();
        h.evaluate(failures(h, "HOST-R", 6));

        Event next = h.store("HOST-R", "LOGIN", NOW.plusSeconds(5), login(false, "203.0.113.9"));
        h.evaluate(next);
        h.evaluate(next);
        h.evaluate(next);

        assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_SUPPRESSED)).isEqualTo(1);
    }

    @Test
    @DisplayName("once the first alert is resolved, new activity raises a new alert")
    void resolvedAlertDoesNotSuppress() {
        DetectionTestHarness h = harness();
        h.evaluate(failures(h, "HOST-RES", 6));
        Alert first = h.alertsFor(AuthBurstRule.ID).get(0);
        first.setStatus(AlertStatus.RESOLVED);

        Event next = h.store("HOST-RES", "LOGIN", NOW.plusSeconds(5), login(false, "203.0.113.9"));

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(next), AuthBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(2);
    }

    @Test
    @DisplayName("escalation is OFF by default, preserving the original behaviour exactly")
    void escalationOffByDefault() {
        DetectionTestHarness h = harness();
        h.evaluate(failures(h, "HOST-NOESC", 5));
        Alert alert = h.alertsFor(AuthBurstRule.ID).get(0);
        assertThat(alert.getSeverity()).isEqualTo(Severity.MEDIUM);

        // Activity rises past the HIGH bar; without escalate=true it is simply suppressed.
        for (int i = 0; i < 8; i++) {
            h.store("HOST-NOESC", "LOGIN", NOW.plusSeconds(i + 1L), login(false, "203.0.113.9"));
        }
        Event later = h.store("HOST-NOESC", "LOGIN", NOW.plusSeconds(20), login(false, "203.0.113.9"));

        assertThat(DetectionTestHarness.outcomeOf(h.evaluate(later), AuthBurstRule.ID))
                .isEqualTo(DetectionOutcome.SUPPRESSED_ACTIVE_ALERT);
        assertThat(alert.getSeverity()).isEqualTo(Severity.MEDIUM);
        assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_ESCALATED)).isZero();
    }

    @Test
    @DisplayName("with escalation on, worse evidence raises the ACTIVE alert instead of creating a second one")
    void escalatesWhenEnabled() {
        DetectionProperties props = DetectionProperties.defaults();
        props.getRules().getAuthBurst().setEscalate(true);
        DetectionTestHarness h = DetectionTestHarness.with(props, new AuthBurstRule());

        for (int i = 0; i < 4; i++) {
            h.store("HOST-ESC", "LOGIN", NOW.minusSeconds(60 - i), login(false, "203.0.113.9"));
        }
        Event first = h.store("HOST-ESC", "LOGIN", NOW, login(false, "203.0.113.9"));
        h.evaluate(first);

        Alert alert = h.alertsFor(AuthBurstRule.ID).get(0);
        assertThat(alert.getSeverity()).isEqualTo(Severity.MEDIUM);

        for (int i = 0; i < 4; i++) {
            h.store("HOST-ESC", "LOGIN", NOW.plusSeconds(i + 1L), login(false, "203.0.113.9"));
        }
        Event tenth = h.store("HOST-ESC", "LOGIN", NOW.plusSeconds(10), login(false, "203.0.113.9"));

        var results = h.evaluate(tenth);

        assertThat(DetectionTestHarness.outcomeOf(results, AuthBurstRule.ID)).isEqualTo(DetectionOutcome.ESCALATED);
        assertThat(alert.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);

        Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_ESCALATED);
        assertThat(audit.get("severityFrom")).isEqualTo("MEDIUM");
        assertThat(audit.get("severityTo")).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("escalation never lowers a severity")
    void escalationIsOneWay() {
        DetectionProperties props = DetectionProperties.defaults();
        props.getRules().getAuthBurst().setEscalate(true);
        DetectionTestHarness h = DetectionTestHarness.with(props, new AuthBurstRule());

        h.evaluate(failures(h, "HOST-DOWN", 12));
        Alert alert = h.alertsFor(AuthBurstRule.ID).get(0);
        assertThat(alert.getSeverity()).isEqualTo(Severity.HIGH);

        // A later, smaller burst inside the window still evaluates to HIGH because
        // the earlier failures are still in it - but never to anything lower.
        Event later = h.store("HOST-DOWN", "LOGIN", NOW.plusSeconds(5), login(false, "203.0.113.9"));
        h.evaluate(later);

        assertThat(alert.getSeverity()).isEqualTo(Severity.HIGH);
    }

    /* ---------------- locking ---------------- */

    @Test
    @DisplayName("the triggering event is locked before any alert state is read")
    void locksBeforeReadingAlertState() {
        DetectionTestHarness h = harness();
        Event trigger = failures(h, "HOST-L", 6);

        h.evaluate(trigger);

        assertThat(h.events.locks).containsExactly(trigger.getId());
    }

    @Test
    @DisplayName("an event type no rule consumes takes no lock and costs no query")
    void noLockForUnconsumedEventTypes() {
        DetectionTestHarness h = harness();
        Event logout = h.store("HOST-L", "LOGOUT", NOW, Map.of());

        h.evaluate(logout);

        assertThat(h.events.locks).isEmpty();
    }
}
