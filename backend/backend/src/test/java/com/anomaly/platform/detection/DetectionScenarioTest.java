package com.anomaly.platform.detection;

import com.anomaly.platform.detection.rules.AuthBurstRule;
import com.anomaly.platform.detection.rules.BruteForceSuccessRule;
import com.anomaly.platform.detection.rules.MultiStageAttackChainRule;
import com.anomaly.platform.detection.rules.NewProcessExternalConnectionRule;
import com.anomaly.platform.detection.rules.PasswordSprayRule;
import com.anomaly.platform.detection.rules.ProcessNetworkBurstRule;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertStatus;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.anomaly.platform.detection.DetectionTestHarness.NOW;
import static com.anomaly.platform.detection.DetectionTestHarness.connection;
import static com.anomaly.platform.detection.DetectionTestHarness.login;
import static com.anomaly.platform.detection.DetectionTestHarness.outcomeOf;
import static com.anomaly.platform.detection.DetectionTestHarness.processStart;
import static com.anomaly.platform.detection.DetectionTestHarness.severityOf;
import static org.assertj.core.api.Assertions.assertThat;

/*
 * ============================================================
 * END-TO-END DETECTION SCENARIOS
 * ============================================================
 *
 * The behaviours above are tested rule by rule; these are the scenarios a reader
 * would describe out loud, run through the FULL production rule set exactly as
 * DetectionConfig wires it. They are the ones to read first, and the ones that
 * would catch a regression caused by two rules interacting badly rather than by
 * either rule being wrong on its own.
 */
class DetectionScenarioTest {

    private static final String SOURCE = "203.0.113.77";
    private static final String EXTERNAL = "198.51.100.23";

    /* ---------------------------------------------------------------- AUTH */

    @Test
    @DisplayName("AUTH: FAIL x4 => no alert")
    void fourFailuresNoAlert() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        Event last = null;
        for (int i = 0; i < 4; i++) {
            last = h.store("HOST-A", "LOGIN", NOW.minusSeconds(40 - i * 10L), login(false, SOURCE));
        }

        h.evaluate(last);

        assertThat(h.alerts.stored).isEmpty();
    }

    @Test
    @DisplayName("AUTH: FAIL x5 => AUTH_BURST alert, MEDIUM")
    void fiveFailuresAlert() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        Event last = null;
        for (int i = 0; i < 5; i++) {
            last = h.store("HOST-A", "LOGIN", NOW.minusSeconds(50 - i * 10L), login(false, SOURCE));
        }

        var results = h.evaluate(last);

        assertThat(outcomeOf(results, AuthBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(severityOf(results, AuthBurstRule.ID)).isEqualTo(Severity.MEDIUM);
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
    }

    @Test
    @DisplayName("AUTH: FAIL x10 => AUTH_BURST alert, HIGH")
    void tenFailuresHigh() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        Event last = null;
        for (int i = 0; i < 10; i++) {
            last = h.store("HOST-A", "LOGIN", NOW.minusSeconds(100 - i * 10L), login(false, SOURCE));
        }

        assertThat(severityOf(h.evaluate(last), AuthBurstRule.ID)).isEqualTo(Severity.HIGH);
    }

    /* ---------------------------------------------------------------- BRUTE FORCE */

    @Test
    @DisplayName("BRUTE FORCE: FAIL x5 then SUCCESS => BRUTE_FORCE_SUCCESS, HIGH")
    void bruteForceSuccess() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        Event lastFailure = null;
        for (int i = 0; i < 5; i++) {
            lastFailure = h.store("HOST-B", "LOGIN", NOW.minusSeconds(70 - i * 10L), login(false, SOURCE));
        }
        // AUTH_BURST fires on the failures first, as it would in production.
        h.evaluate(lastFailure);
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);

        Event success = h.store("HOST-B", "LOGIN", NOW, login(true, SOURCE));
        var results = h.evaluate(success);

        assertThat(outcomeOf(results, BruteForceSuccessRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(severityOf(results, BruteForceSuccessRule.ID)).isEqualTo(Severity.HIGH);

        // Two distinct findings: the attack, and the possible compromise.
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
        assertThat(h.alertsFor(BruteForceSuccessRule.ID)).hasSize(1);
    }

    /* ---------------------------------------------------------------- SPRAY */

    @Test
    @DisplayName("SPRAY: one source, 5 identities, 1 failure each => PASSWORD_SPRAY, not AUTH_BURST")
    void passwordSpray() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        Event last = null;
        for (int i = 0; i < 5; i++) {
            last = h.store("USER-" + i, "LOGIN", NOW.minusSeconds(5 - i), login(false, SOURCE));
        }

        var results = h.evaluate(last);

        assertThat(outcomeOf(results, PasswordSprayRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        // No single identity saw enough failures for AUTH_BURST - that is the point.
        assertThat(outcomeOf(results, AuthBurstRule.ID)).isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        assertThat(h.alertsFor(AuthBurstRule.ID)).isEmpty();
    }

    /* ---------------------------------------------------------------- PROCESS */

    @Test
    @DisplayName("PROCESS: PROCESS_START then one external connection => R002")
    void processThenConnection() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        OffsetDateTime started = NOW.minusSeconds(20);
        h.store("HOST-P", "PROCESS_START", started, processStart(8100, "curl"));
        Event conn = h.store("HOST-P", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

        var results = h.evaluate(conn);

        assertThat(outcomeOf(results, NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(severityOf(results, NewProcessExternalConnectionRule.ID)).isEqualTo(Severity.MEDIUM);
        // One connection is not a burst.
        assertThat(outcomeOf(results, ProcessNetworkBurstRule.ID)).isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
    }

    @Test
    @DisplayName("PROCESS BURST: PROCESS_START then external x5 => R008, alongside R002")
    void processBurst() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        OffsetDateTime started = NOW.minusSeconds(30);
        h.store("HOST-PB", "PROCESS_START", started, processStart(8100, "curl"));
        Event last = null;
        for (int i = 0; i < 5; i++) {
            last = h.store("HOST-PB", "NETWORK_CONNECTION", started.plusSeconds(i + 1L),
                    connection(8100, started, "198.51.100." + (10 + i)));
        }

        var results = h.evaluate(last);

        assertThat(outcomeOf(results, ProcessNetworkBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(outcomeOf(results, NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(h.alertsFor(ProcessNetworkBurstRule.ID)).hasSize(1);
        assertThat(h.alertsFor(NewProcessExternalConnectionRule.ID)).hasSize(1);
    }

    /* ---------------------------------------------------------------- MULTI-STAGE */

    @Test
    @DisplayName("MULTI-STAGE: AUTH_BURST then PROCESS_START then external connection => R010")
    void multiStageChain() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();

        OffsetDateTime base = NOW.minusMinutes(6);
        Event lastFailure = null;
        for (int i = 0; i < 6; i++) {
            lastFailure = h.store("HOST-M", "LOGIN", base.plusSeconds(i * 5L), login(false, SOURCE));
        }
        h.evaluate(lastFailure);
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);

        OffsetDateTime started = NOW.minusMinutes(2);
        h.store("HOST-M", "PROCESS_START", started, processStart(8100, "curl"));
        Event conn = h.store("HOST-M", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

        var results = h.evaluate(conn);

        assertThat(outcomeOf(results, MultiStageAttackChainRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        assertThat(severityOf(results, MultiStageAttackChainRule.ID)).isEqualTo(Severity.HIGH);

        // The chain is an ADDITIONAL finding; the stage alerts stand on their own.
        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
        assertThat(h.alertsFor(NewProcessExternalConnectionRule.ID)).hasSize(1);
        assertThat(h.alertsFor(MultiStageAttackChainRule.ID)).hasSize(1);
    }

    /* ---------------------------------------------------------------- incident reuse */

    @Test
    @DisplayName("alerts of the same entity and event type join one incident; a resolved incident starts a new one")
    void incidentReuseAndRecreation() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();

        Event first = null;
        for (int i = 0; i < 6; i++) {
            first = h.store("HOST-I", "LOGIN", NOW.minusSeconds(60 - i * 5L), login(false, SOURCE));
        }
        h.evaluate(first);
        assertThat(h.incidents.created).hasSize(1);

        // Resolve the first alert and the incident, then produce the same finding again.
        h.alertsFor(AuthBurstRule.ID).get(0).setStatus(AlertStatus.RESOLVED);
        h.incidents.created.get(0).setStatus(com.anomaly.platform.entity.IncidentStatus.RESOLVED);

        Event again = h.store("HOST-I", "LOGIN", NOW.plusSeconds(5), login(false, SOURCE));
        h.evaluate(again);

        assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(2);
        assertThat(h.incidents.created).hasSize(2);
        assertThat(h.incidents.created.get(1).getIncidentKey()).isNotEqualTo(h.incidents.created.get(0).getIncidentKey());
    }

    @Test
    @DisplayName("two rules firing on the same event share that event's incident")
    void multipleRulesShareAnIncident() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        OffsetDateTime started = NOW.minusSeconds(30);
        h.store("HOST-SH", "PROCESS_START", started, processStart(8100, "curl"));
        Event last = null;
        for (int i = 0; i < 6; i++) {
            last = h.store("HOST-SH", "NETWORK_CONNECTION", started.plusSeconds(i + 1L),
                    connection(8100, started, "198.51.100." + (10 + i)));
        }

        h.evaluate(last);

        // Both R002 and R008 fired on one NETWORK_CONNECTION for one entity, so the
        // incident key (entityId:eventType) is the same for both.
        assertThat(h.alertsFor(NewProcessExternalConnectionRule.ID)).hasSize(1);
        assertThat(h.alertsFor(ProcessNetworkBurstRule.ID)).hasSize(1);
        assertThat(h.incidents.created).hasSize(1);
        assertThat(h.alertsFor(NewProcessExternalConnectionRule.ID).get(0).getIncident())
                .isSameAs(h.alertsFor(ProcessNetworkBurstRule.ID).get(0).getIncident());
    }

    /* ---------------------------------------------------------------- ML coexistence */

    @Test
    @DisplayName("a rule alert and an ML alert on the same event coexist and stay distinguishable")
    void ruleAndMlAlertsCoexist() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        Event last = null;
        for (int i = 0; i < 6; i++) {
            last = h.store("HOST-ML", "LOGIN", NOW.minusSeconds(60 - i * 5L), login(false, SOURCE));
        }
        h.evaluate(last);

        // An ML-driven alert for the SAME event, as PredictionService would create it:
        // no ruleId, a score, and a different policy version.
        Alert mlAlert = new Alert();
        mlAlert.setEvent(last);
        mlAlert.setEntity(last.getEntity());
        mlAlert.setDecision(com.anomaly.platform.entity.DecisionState.UNKNOWN_ANOMALY);
        mlAlert.setSeverity(Severity.HIGH);
        mlAlert.setStatus(AlertStatus.OPEN);
        mlAlert.setPolicyVersion("v2-ml-ensemble");
        mlAlert.setAnomalyScore(new java.math.BigDecimal("0.99700"));
        h.alerts.save(mlAlert);

        // The uk_alerts_event_rule index only constrains rule alerts, so this is allowed.
        assertThat(h.alerts.stored).hasSize(2);

        Alert ruleAlert = h.alertsFor(AuthBurstRule.ID).get(0);
        assertThat(ruleAlert.getRuleId()).isNotNull();
        assertThat(ruleAlert.getAnomalyScore()).isNull();
        assertThat(mlAlert.getRuleId()).isNull();
        assertThat(mlAlert.getAnomalyScore()).isNotNull();

        // Re-evaluating the event does not let the ML alert suppress the rule, nor
        // the rule create a second alert.
        assertThat(outcomeOf(h.evaluate(last), AuthBurstRule.ID)).isEqualTo(DetectionOutcome.DUPLICATE);
        assertThat(h.alerts.stored).hasSize(2);
    }

    @Test
    @DisplayName("no rule ever reads a prediction or a score")
    void rulesNeverReadMlOutput() {
        // Structural, not behavioural: the detection package must not even be able
        // to see the ML types.
        for (Class<?> type : List.of(DetectionEngine.class, RuleContext.class, DetectionMatch.class,
                CorrelationWindowService.class, DetectionEvidence.class)) {
            for (java.lang.reflect.Field field : type.getDeclaredFields()) {
                assertThat(field.getType().getName())
                        .as("%s.%s", type.getSimpleName(), field.getName())
                        .doesNotContain("Prediction")
                        .doesNotContain(".ml.");
            }
        }
    }

    /* ---------------------------------------------------------------- malformed input */

    @Test
    @DisplayName("a malformed event never produces an alert and never fails the pipeline")
    void malformedEventIsSafe() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();

        Map<String, Object> garbage = new HashMap<>();
        garbage.put("pid", "not-a-pid");
        garbage.put("processCreateTime", List.of(1, 2));
        garbage.put("remoteAddress", Map.of());
        garbage.put("loginSuccess", 1);

        for (String type : List.of("LOGIN", "NETWORK_CONNECTION", "PROCESS_START")) {
            Event e = h.store("HOST-BAD", type, NOW, garbage);
            assertThat(h.evaluate(e)).isNotNull();
        }

        assertThat(h.alerts.stored).isEmpty();
    }

    @Test
    @DisplayName("an event with no entity is ignored rather than crashing")
    void eventWithoutEntityIsIgnored() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        Event orphan = new Event();
        orphan.setId(java.util.UUID.randomUUID());
        orphan.setEventId("EV-ORPHAN");
        orphan.setEventType("LOGIN");
        orphan.setOccurredAt(NOW);
        orphan.setPayload(Map.of("loginSuccess", false));

        assertThat(h.evaluate(orphan)).isEmpty();
        assertThat(h.alerts.stored).isEmpty();
    }
}
