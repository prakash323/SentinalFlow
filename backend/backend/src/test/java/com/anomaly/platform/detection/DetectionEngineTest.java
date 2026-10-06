package com.anomaly.platform.detection;

import com.anomaly.platform.detection.config.DetectionConfig;
import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.detection.rules.AuthBurstRule;
import com.anomaly.platform.detection.rules.BruteForceSuccessRule;
import com.anomaly.platform.detection.rules.MultiStageAttackChainRule;
import com.anomaly.platform.detection.rules.NewProcessExternalConnectionRule;
import com.anomaly.platform.detection.rules.PasswordSprayRule;
import com.anomaly.platform.detection.rules.ProcessNetworkBurstRule;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static com.anomaly.platform.detection.DetectionTestHarness.NOW;
import static com.anomaly.platform.detection.DetectionTestHarness.connection;
import static com.anomaly.platform.detection.DetectionTestHarness.login;
import static com.anomaly.platform.detection.DetectionTestHarness.outcomeOf;
import static com.anomaly.platform.detection.DetectionTestHarness.processStart;
import static com.anomaly.platform.detection.DetectionTestHarness.severityOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*
 * The engine itself, R010, and the invariants that must hold for EVERY rule -
 * the properties that stop a future rule quietly breaking the system.
 */
class DetectionEngineTest {

    private static final String EXTERNAL = "198.51.100.23";

    /* ================================================================ R010 */

    @Nested
    @DisplayName("R010 MULTI_STAGE_ATTACK_CHAIN")
    class MultiStage {

        /** Failures, a success, a process start and an external connection, in order. */
        private Event fullChain(DetectionTestHarness h, String entity) {
            OffsetDateTime base = NOW.minusMinutes(10);
            for (int i = 0; i < 6; i++) {
                h.store(entity, "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            h.store(entity, "LOGIN", base.plusSeconds(30), login(true, "203.0.113.5"));
            OffsetDateTime started = base.plusMinutes(2);
            h.store(entity, "PROCESS_START", started, processStart(8100, "curl"));
            return h.store(entity, "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));
        }

        @Test
        @DisplayName("all four stages in order: CRITICAL correlation alert")
        void firesOnTheFullChain() {
            DetectionTestHarness h = DetectionTestHarness.with(new MultiStageAttackChainRule());
            var results = h.evaluate(fullChain(h, "HOST-CHAIN"));

            assertThat(outcomeOf(results, MultiStageAttackChainRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, MultiStageAttackChainRule.ID)).isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("three stages: HIGH")
        void threeStagesIsHigh() {
            DetectionTestHarness h = DetectionTestHarness.with(new MultiStageAttackChainRule());
            OffsetDateTime base = NOW.minusMinutes(10);
            for (int i = 0; i < 6; i++) {
                h.store("HOST-3", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            OffsetDateTime started = base.plusMinutes(2);
            h.store("HOST-3", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-3", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            var results = h.evaluate(conn);
            assertThat(outcomeOf(results, MultiStageAttackChainRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, MultiStageAttackChainRule.ID)).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("an external connection with no preceding stages is not a chain")
        void connectionAloneIsNotAChain() {
            DetectionTestHarness h = DetectionTestHarness.with(new MultiStageAttackChainRule());
            Map<String, Object> p = new HashMap<>();
            p.put("remoteAddress", EXTERNAL);
            Event conn = h.store("HOST-ALONE", "NETWORK_CONNECTION", NOW, p);

            assertThat(outcomeOf(h.evaluate(conn), MultiStageAttackChainRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("authentication failures below the AUTH_BURST bar do not count as a stage")
        void weakAuthStageDoesNotCount() {
            DetectionTestHarness h = DetectionTestHarness.with(new MultiStageAttackChainRule());
            OffsetDateTime base = NOW.minusMinutes(5);
            for (int i = 0; i < 2; i++) {
                h.store("HOST-W", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            OffsetDateTime started = base.plusMinutes(1);
            h.store("HOST-W", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-W", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            // Only process + connection = 2 stages, below min-stages of 3.
            assertThat(outcomeOf(h.evaluate(conn), MultiStageAttackChainRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("it ADDS an alert: the underlying rule alerts are raised and untouched")
        void doesNotReplaceUnderlyingAlerts() {
            DetectionTestHarness h = DetectionTestHarness.with(
                    new AuthBurstRule(), new BruteForceSuccessRule(),
                    new NewProcessExternalConnectionRule(), new MultiStageAttackChainRule());

            OffsetDateTime base = NOW.minusMinutes(10);
            Event lastFailure = null;
            for (int i = 0; i < 6; i++) {
                lastFailure = h.store("HOST-ADD", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            h.evaluate(lastFailure);
            assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);

            Event success = h.store("HOST-ADD", "LOGIN", base.plusSeconds(30), login(true, "203.0.113.5"));
            h.evaluate(success);
            assertThat(h.alertsFor(BruteForceSuccessRule.ID)).hasSize(1);

            // Inside R002's own five-minute recency bound, so this scenario exercises
            // all four rules rather than silently dropping one.
            OffsetDateTime started = NOW.minusMinutes(2);
            h.store("HOST-ADD", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-ADD", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));
            var results = h.evaluate(conn);

            // Four separate findings, each with its own alert. The chain adds one.
            assertThat(outcomeOf(results, NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(outcomeOf(results, MultiStageAttackChainRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
            assertThat(h.alertsFor(BruteForceSuccessRule.ID)).hasSize(1);
            assertThat(h.alertsFor(NewProcessExternalConnectionRule.ID)).hasSize(1);
            assertThat(h.alertsFor(MultiStageAttackChainRule.ID)).hasSize(1);
        }

        @Test
        @DisplayName("the stages are suppressed-independent: a suppressed AUTH_BURST still counts as a stage")
        void stagesComeFromEventsNotAlerts() {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule(), new MultiStageAttackChainRule());

            OffsetDateTime base = NOW.minusMinutes(10);
            Event lastFailure = null;
            for (int i = 0; i < 6; i++) {
                lastFailure = h.store("HOST-SUP", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            // AUTH_BURST fires, so any further burst is suppressed from here on.
            h.evaluate(lastFailure);
            Event another = h.store("HOST-SUP", "LOGIN", base.plusSeconds(40), login(false, "203.0.113.5"));
            assertThat(outcomeOf(h.evaluate(another), AuthBurstRule.ID))
                    .isEqualTo(DetectionOutcome.SUPPRESSED_ACTIVE_ALERT);

            OffsetDateTime started = base.plusMinutes(2);
            h.store("HOST-SUP", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-SUP", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            // The chain still sees the authentication stage, because it reads the
            // EVENTS - a suppressed alert must not hide a stage.
            assertThat(outcomeOf(h.evaluate(conn), MultiStageAttackChainRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        }

        @Test
        @DisplayName("the evidence lists the contributing signals in order and names the covering rules")
        void evidenceListsTheStages() {
            DetectionTestHarness h = DetectionTestHarness.with(new MultiStageAttackChainRule());
            h.evaluate(fullChain(h, "HOST-EV"));

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            List<?> signals = (List<?>) audit.get("contributingSignals");
            assertThat(signals).hasSize(4);
            assertThat(String.valueOf(signals.get(0))).contains("failed logins");
            assertThat(String.valueOf(signals.get(1))).contains("successful login after failures");
            assertThat(String.valueOf(signals.get(2))).contains("process curl started");
            assertThat(String.valueOf(signals.get(3))).contains("external connection to " + EXTERNAL);

            assertThat(audit.get("coveringRules").toString())
                    .contains(AuthBurstRule.ID)
                    .contains(BruteForceSuccessRule.ID)
                    .contains(NewProcessExternalConnectionRule.ID);
            assertThat(String.valueOf(audit.get("correlationOnly")))
                    .contains("additional")
                    .contains("raised independently");
            assertThat(String.valueOf(audit.get("message")))
                    .contains("MULTI_STAGE_ATTACK_CHAIN detected")
                    .contains(" -> ");
        }

        @Test
        @DisplayName("min-stages is configurable")
        void minStagesConfigurable() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getMultiStageAttackChain().setMinStages(5);
            props.getRules().getMultiStageAttackChain().setCriticalStages(6);
            DetectionTestHarness h = DetectionTestHarness.with(props, new MultiStageAttackChainRule());

            assertThat(outcomeOf(h.evaluate(fullChain(h, "HOST-CFG")), MultiStageAttackChainRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }
    }

    /* ================================================================ invariants */

    @Nested
    @DisplayName("Invariants that must hold for every rule")
    class Invariants {

        private final List<DetectionRule> allRules = new DetectionConfig().ruleRegistry().all();

        @Test
        @DisplayName("rule ids are unique, stable and short enough for the alerts.rule_id column")
        void ruleIdsAreValid() {
            Set<String> ids = new java.util.HashSet<>();
            for (DetectionRule rule : allRules) {
                assertThat(rule.id()).isNotBlank();
                assertThat(rule.id().length()).as(rule.id()).isLessThanOrEqualTo(64);
                assertThat(rule.name().length()).as(rule.id()).isLessThanOrEqualTo(200);
                assertThat(rule.description()).isNotBlank();
                assertThat(rule.consumedEventTypes()).as(rule.id()).isNotEmpty();
                assertThat(ids.add(rule.id())).as("duplicate id %s", rule.id()).isTrue();
            }
            assertThat(allRules).hasSize(10);
        }

        @Test
        @DisplayName("a duplicate rule id is rejected at construction, not discovered in production")
        void duplicateIdsAreRejected() {
            assertThatThrownBy(() -> new RuleRegistry(List.of(new AuthBurstRule(), new AuthBurstRule())))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Duplicate detection rule id")
                    .hasMessageContaining(AuthBurstRule.ID);
        }

        @Test
        @DisplayName("rule ORDER never changes the outcome")
        void ruleOrderDoesNotMatter() {
            List<DetectionOutcome> firstPass = outcomesForChain(allRules);

            List<DetectionRule> reversed = new ArrayList<>(allRules);
            Collections.reverse(reversed);
            List<DetectionOutcome> reversedPass = outcomesForChain(reversed);

            List<DetectionRule> shuffled = new ArrayList<>(allRules);
            Collections.shuffle(shuffled, new java.util.Random(42));
            List<DetectionOutcome> shuffledPass = outcomesForChain(shuffled);

            assertThat(reversedPass).containsExactlyInAnyOrderElementsOf(firstPass);
            assertThat(shuffledPass).containsExactlyInAnyOrderElementsOf(firstPass);
        }

        /** Build the same world and return each rule's outcome, keyed by rule id. */
        private List<DetectionOutcome> outcomesForChain(List<DetectionRule> rules) {
            DetectionTestHarness h = new DetectionTestHarness(DetectionProperties.defaults(), rules);
            OffsetDateTime base = NOW.minusMinutes(10);
            for (int i = 0; i < 6; i++) {
                h.store("HOST-ORD", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            OffsetDateTime started = base.plusMinutes(2);
            h.store("HOST-ORD", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-ORD", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            return h.evaluate(conn).stream()
                    .sorted(java.util.Comparator.comparing(DetectionEngine.RuleEvaluation::ruleId))
                    .map(DetectionEngine.RuleEvaluation::outcome)
                    .toList();
        }

        @Test
        @DisplayName("no rule ever raises an alert without evidence - an empty world produces nothing")
        void noAlertWithoutEvidence() {
            DetectionTestHarness h = DetectionTestHarness.withAllRules();

            for (String type : List.of("LOGIN", "LOGOUT", "FILE_ACCESS", "API_ACCESS",
                    "TRANSACTION", "PASSWORD_CHANGE", "PROCESS_START", "NETWORK_CONNECTION")) {
                h.evaluate(h.store("HOST-EMPTY", type, NOW, Map.of()));
            }

            assertThat(h.alerts.stored).isEmpty();
            assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_CREATED)).isZero();
        }

        @Test
        @DisplayName("missing optional fields never crash processing, for any event type")
        void missingFieldsNeverCrash() {
            DetectionTestHarness h = DetectionTestHarness.withAllRules();

            List<Map<String, Object>> payloads = List.of(
                    Map.of(),
                    Map.of("loginSuccess", "not-a-boolean"),
                    Map.of("pid", "not-a-number"),
                    Map.of("remoteAddress", ""),
                    Map.of("location", "garbage"),
                    Map.of("ip", List.of(1, 2, 3)),
                    Map.of("processCreateTime", 12345),
                    Map.of("commandSequence", Map.of("nested", "object"))
            );

            for (String type : List.of("LOGIN", "PROCESS_START", "NETWORK_CONNECTION", "FILE_ACCESS")) {
                for (Map<String, Object> payload : payloads) {
                    Event e = h.store("HOST-NULL", type, NOW, payload);
                    assertThatCode(() -> h.evaluate(e)).as("%s %s", type, payload).doesNotThrowAnyException();
                }
            }
        }

        @Test
        @DisplayName("a rule that throws never stops the other rules or the event")
        void aThrowingRuleIsContained() {
            DetectionRule exploding = new DetectionRule() {
                @Override public String id() { return "EXPLODING_RULE"; }
                @Override public String name() { return "Always throws"; }
                @Override public String description() { return "A rule with a bug."; }
                @Override public Set<String> consumedEventTypes() { return Set.of("LOGIN"); }
                @Override public DetectionProperties.RuleSettings settings(DetectionProperties p) {
                    return p.getRules().getAuthBurst();
                }
                @Override public DetectionMatch evaluate(RuleContext context) {
                    throw new IllegalStateException("rule bug");
                }
            };

            DetectionTestHarness h = new DetectionTestHarness(
                    DetectionProperties.defaults(), List.of(exploding, new AuthBurstRule()));

            Event last = null;
            for (int i = 0; i < 6; i++) {
                last = h.store("HOST-BOOM", "LOGIN", NOW.minusSeconds(10 - i), login(false, "203.0.113.5"));
            }
            final Event trigger = last;

            assertThatCode(() -> h.evaluate(trigger)).doesNotThrowAnyException();
            // The working rule still fired.
            assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
        }

        @Test
        @DisplayName("evaluating the same event twice produces the same final state (idempotent replay)")
        void replayIsIdempotent() {
            DetectionTestHarness h = DetectionTestHarness.withAllRules();
            OffsetDateTime base = NOW.minusMinutes(10);
            for (int i = 0; i < 6; i++) {
                h.store("HOST-REPLAY", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            OffsetDateTime started = base.plusMinutes(2);
            h.store("HOST-REPLAY", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-REPLAY", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            h.evaluate(conn);
            int alertsAfterFirst = h.alerts.stored.size();
            int factorsAfterFirst = h.factors.stored.size();

            // Replayed many times, as an admin replay or a Kafka redelivery would.
            for (int i = 0; i < 5; i++) {
                h.evaluate(conn);
            }

            assertThat(h.alerts.stored).hasSize(alertsAfterFirst);
            assertThat(h.factors.stored).hasSize(factorsAfterFirst);
            assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_CREATED)).isEqualTo(alertsAfterFirst);
        }

        @Test
        @DisplayName("evaluation is deterministic: the same world always gives the same answer")
        void evaluationIsDeterministic() {
            List<String> runs = new ArrayList<>();
            for (int run = 0; run < 5; run++) {
                DetectionTestHarness h = DetectionTestHarness.withAllRules();
                OffsetDateTime base = NOW.minusMinutes(10);
                for (int i = 0; i < 7; i++) {
                    h.store("HOST-DET", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
                }
                OffsetDateTime started = base.plusMinutes(2);
                h.store("HOST-DET", "PROCESS_START", started, processStart(8100, "curl"));
                Event conn = h.store("HOST-DET", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

                runs.add(h.evaluate(conn).stream()
                        .sorted(java.util.Comparator.comparing(DetectionEngine.RuleEvaluation::ruleId))
                        .map(r -> r.ruleId() + "=" + r.outcome() + "/" + r.severity())
                        .reduce("", (a, b) -> a + ";" + b));
            }
            assertThat(new java.util.HashSet<>(runs)).hasSize(1);
        }

        @Test
        @DisplayName("a disabled rule produces no detection, whatever the evidence")
        void disabledRulesProduceNothing() {
            DetectionProperties props = DetectionProperties.defaults();
            props.setEnabled(false);
            DetectionTestHarness h = new DetectionTestHarness(props, allRules);

            OffsetDateTime base = NOW.minusMinutes(10);
            for (int i = 0; i < 20; i++) {
                h.store("HOST-OFF", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            OffsetDateTime started = base.plusMinutes(2);
            h.store("HOST-OFF", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-OFF", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            h.evaluate(conn);

            assertThat(h.alerts.stored).isEmpty();
            assertThat(h.events.locks).isEmpty();
        }

        @Test
        @DisplayName("evidence factors always fit the alert_factors column, for every rule")
        void evidenceAlwaysFitsTheColumn() {
            DetectionTestHarness h = DetectionTestHarness.withAllRules();
            String longEntity = "HOST-" + "x".repeat(80);
            OffsetDateTime base = NOW.minusMinutes(10);
            for (int i = 0; i < 12; i++) {
                h.store(longEntity, "LOGIN", base.plusSeconds(i), login(false, "2606:4700:0010:0000:0000:0000:6814:179a"));
            }
            h.evaluate(h.store(longEntity, "LOGIN", NOW.minusMinutes(5), login(false, "2606:4700:0010:0000:0000:0000:6814:179a")));

            OffsetDateTime started = base.plusMinutes(2);
            h.store(longEntity, "PROCESS_START", started, processStart(8100, "a".repeat(100)));
            for (int i = 0; i < 25; i++) {
                h.store(longEntity, "NETWORK_CONNECTION", started.plusSeconds(i + 1L),
                        connection(8100, started, "2606:4700:0010:0000:0000:0000:6814:" + String.format("%04x", i)));
            }
            h.evaluate(h.store(longEntity, "NETWORK_CONNECTION", NOW,
                    connection(8100, started, "2606:4700:0010:0000:0000:0000:6814:ffff")));

            assertThat(h.factors.stored).isNotEmpty();
            assertThat(h.factors.stored).allSatisfy(f ->
                    assertThat(f.getFactor().length()).as(f.getFactor()).isLessThanOrEqualTo(128));
        }

        @Test
        @DisplayName("every alert raised is explainable: rule, evidence and a generated message")
        void everyAlertIsExplainable() {
            DetectionTestHarness h = DetectionTestHarness.withAllRules();
            OffsetDateTime base = NOW.minusMinutes(10);
            for (int i = 0; i < 12; i++) {
                h.store("HOST-EXP", "LOGIN", base.plusSeconds(i), login(false, "203.0.113.5"));
            }
            h.evaluate(h.store("HOST-EXP", "LOGIN", base.plusSeconds(20), login(false, "203.0.113.5")));

            List<Map<String, Object>> created = h.audit.rows.stream()
                    .filter(r -> r.action().equals(DetectionEngine.AUDIT_DETECTION_CREATED))
                    .map(DetectionTestHarness.RecordingAuditLogService.Row::details)
                    .toList();

            assertThat(created).isNotEmpty();
            assertThat(created).allSatisfy(details -> {
                assertThat(details).containsKeys("ruleId", "ruleName", "severity", "message", "evidence", "outcome");
                assertThat(String.valueOf(details.get("message"))).isNotBlank();
                // The message is generated from the evidence and names the rule.
                assertThat(String.valueOf(details.get("message")))
                        .startsWith(String.valueOf(details.get("ruleId")) + " detected:");
                assertThat(String.valueOf(details.get("message"))).doesNotContain("Suspicious activity detected");
            });
        }

        @Test
        @DisplayName("every suppression is explainable too")
        void everySuppressionIsExplainable() {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule());
            for (int i = 0; i < 6; i++) {
                h.store("HOST-SX", "LOGIN", NOW.minusSeconds(60 - i), login(false, "203.0.113.5"));
            }
            h.evaluate(h.store("HOST-SX", "LOGIN", NOW.minusSeconds(30), login(false, "203.0.113.5")));
            h.evaluate(h.store("HOST-SX", "LOGIN", NOW, login(false, "203.0.113.5")));

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_SUPPRESSED);
            assertThat(audit).containsKeys("ruleId", "outcome", "suppressedBecauseAlertId",
                    "suppressionReason", "candidateSeverity", "triggeringEventId", "entityId");
            assertThat(String.valueOf(audit.get("suppressionReason"))).isNotBlank();
        }
    }

    /* ================================================================ concurrency */

    @Nested
    @DisplayName("Concurrency and correlation safety")
    class Concurrency {

        @Test
        @DisplayName("the triggering event is locked once, before any alert state is read")
        void eventIsLockedFirst() {
            DetectionTestHarness h = DetectionTestHarness.withAllRules();
            for (int i = 0; i < 6; i++) {
                h.store("HOST-LOCK", "LOGIN", NOW.minusSeconds(10 - i), login(false, "203.0.113.5"));
            }
            Event trigger = h.store("HOST-LOCK", "LOGIN", NOW, login(false, "203.0.113.5"));

            h.evaluate(trigger);

            // One lock for the whole evaluation, not one per rule.
            assertThat(h.events.locks).containsExactly(trigger.getId());
        }

        @Test
        @DisplayName("concurrent evaluation of the same event creates exactly one alert per rule")
        void concurrentEvaluationCreatesOneAlert() throws Exception {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule());
            for (int i = 0; i < 6; i++) {
                h.store("HOST-RACE", "LOGIN", NOW.minusSeconds(10 - i), login(false, "203.0.113.5"));
            }
            Event trigger = h.store("HOST-RACE", "LOGIN", NOW, login(false, "203.0.113.5"));

            int threads = 8;
            var latch = new java.util.concurrent.CountDownLatch(1);
            var failures = ConcurrentHashMap.<String>newKeySet();
            List<Thread> workers = new ArrayList<>();

            for (int i = 0; i < threads; i++) {
                Thread t = new Thread(() -> {
                    try {
                        latch.await();
                        // The engine serialises on the event row lock in production; here
                        // the point is that no path creates a second alert even when the
                        // application-level check is raced.
                        synchronized (h.engine) {
                            h.evaluate(trigger);
                        }
                    } catch (Exception e) {
                        failures.add(e.toString());
                    }
                });
                workers.add(t);
                t.start();
            }
            latch.countDown();
            for (Thread t : workers) {
                t.join();
            }

            assertThat(failures).isEmpty();
            assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
            assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_CREATED)).isEqualTo(1);
        }

        @Test
        @DisplayName("the database unique constraint is the real guarantee, and it is enforced")
        void uniqueConstraintIsEnforced() {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule());
            for (int i = 0; i < 6; i++) {
                h.store("HOST-UK", "LOGIN", NOW.minusSeconds(10 - i), login(false, "203.0.113.5"));
            }
            Event trigger = h.store("HOST-UK", "LOGIN", NOW, login(false, "203.0.113.5"));
            h.evaluate(trigger);

            // A second alert for the same (event, rule) is rejected by the store, the
            // way uk_alerts_event_rule rejects it in PostgreSQL.
            Alert duplicate = new Alert();
            duplicate.setEvent(trigger);
            duplicate.setEntity(trigger.getEntity());
            duplicate.setRuleId(AuthBurstRule.ID);
            duplicate.setSeverity(Severity.MEDIUM);
            duplicate.setStatus(com.anomaly.platform.entity.AlertStatus.OPEN);
            duplicate.setDecision(com.anomaly.platform.entity.DecisionState.SUSPICIOUS);
            duplicate.setPolicyVersion(DetectionEngine.RULE_POLICY_VERSION);

            assertThatThrownBy(() -> h.alerts.save(duplicate))
                    .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class)
                    .hasMessageContaining("uk_alerts_event_rule");
        }

        @Test
        @DisplayName("out-of-order arrival never justifies an alert with future evidence")
        void outOfOrderArrivalIsSafe() {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule());

            // The later events arrive first.
            for (int i = 0; i < 10; i++) {
                h.store("HOST-OOO", "LOGIN", NOW.plusSeconds(i), login(false, "203.0.113.5"));
            }
            // Then an older one is processed.
            Event old = h.store("HOST-OOO", "LOGIN", NOW.minusMinutes(30), login(false, "203.0.113.5"));

            assertThat(outcomeOf(h.evaluate(old), AuthBurstRule.ID)).isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
            assertThat(h.alerts.stored).isEmpty();
        }
    }

    /* ================================================================ bounded state */

    @Nested
    @DisplayName("Correlation state is bounded")
    class BoundedState {

        @Test
        @DisplayName("every correlation query is capped by detection.max-correlation-events")
        void queriesAreCapped() {
            DetectionProperties props = DetectionProperties.defaults();
            props.setMaxCorrelationEvents(50);
            DetectionTestHarness h = DetectionTestHarness.with(props, new AuthBurstRule());

            // Ten thousand failures for one entity.
            Event last = null;
            for (int i = 0; i < 10_000; i++) {
                last = h.store("HOST-BIG", "LOGIN", NOW.minusSeconds(200 - (i % 200)), login(false, "203.0.113.5"));
            }

            h.evaluate(last);

            // The rule fires, and its count is bounded by the cap - it never loaded
            // ten thousand rows into memory to decide.
            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat((Long) audit.get("count")).isLessThanOrEqualTo(50L);
            assertThat(audit.get("windowTruncated")).isEqualTo(true);
        }

        @Test
        @DisplayName("a truncated window is declared in the evidence, never presented as exact")
        void truncationIsDeclared() {
            DetectionProperties props = DetectionProperties.defaults();
            props.setMaxCorrelationEvents(10);
            DetectionTestHarness h = DetectionTestHarness.with(props, new AuthBurstRule());

            Event last = null;
            for (int i = 0; i < 200; i++) {
                last = h.store("HOST-TR", "LOGIN", NOW.minusSeconds(100 - (i % 100)), login(false, "203.0.113.5"));
            }
            h.evaluate(last);

            assertThat(h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED).get("windowTruncated")).isEqualTo(true);
        }

        @Test
        @DisplayName("the evidence's own collections are bounded, so one alert cannot bloat a row")
        void evidenceCollectionsAreBounded() {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule());
            Event last = null;
            for (int i = 0; i < 400; i++) {
                last = h.store("HOST-EVB", "LOGIN", NOW.minusSeconds(250 - (i % 250)), login(false, "203.0.113.5"));
            }
            h.evaluate(last);

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat((List<?>) audit.get("eventIds"))
                    .hasSizeLessThanOrEqualTo(DetectionEvidence.Builder.MAX_EVENT_IDS);
        }

        @Test
        @DisplayName("stress: 10,000 events across many entities stay bounded and deterministic")
        void stressTenThousandEvents() {
            DetectionTestHarness h = DetectionTestHarness.withAllRules();

            long start = System.nanoTime();
            int entities = 50;
            for (int i = 0; i < 10_000; i++) {
                String entity = "HOST-" + (i % entities);
                h.store(entity, "LOGIN", NOW.minusSeconds(600 - (i % 600)),
                        login(i % 3 != 0, "203.0.113." + (i % 25)));
            }

            // Evaluate one trigger per entity.
            for (int e = 0; e < entities; e++) {
                Event trigger = h.store("HOST-" + e, "LOGIN", NOW, login(false, "203.0.113.1"));
                h.evaluate(trigger);
            }
            long millis = (System.nanoTime() - start) / 1_000_000;

            // Nothing unbounded: the alert count is bounded by entities x rules, and
            // suppression keeps it far below that.
            assertThat(h.alerts.stored.size()).isLessThan(entities * 10);
            assertThat(h.factors.stored).allSatisfy(f ->
                    assertThat(f.getFactor().length()).isLessThanOrEqualTo(128));
            // A generous ceiling: this is a regression guard against an accidental
            // O(n^2), not a benchmark.
            assertThat(millis).isLessThan(120_000);
        }

        @Test
        @DisplayName("repeated evaluation of many duplicates never grows alert state")
        void duplicatesDoNotGrowState() {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule());
            for (int i = 0; i < 8; i++) {
                h.store("HOST-DUP", "LOGIN", NOW.minusSeconds(20 - i), login(false, "203.0.113.5"));
            }
            Event trigger = h.store("HOST-DUP", "LOGIN", NOW, login(false, "203.0.113.5"));

            for (int i = 0; i < 500; i++) {
                h.evaluate(trigger);
            }

            assertThat(h.alerts.stored).hasSize(1);
            assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_CREATED)).isEqualTo(1);
            // A duplicate is not even recorded as a suppression - it is not new activity.
            assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_SUPPRESSED)).isZero();
        }
    }

    /* ================================================================ the catalog */

    @Nested
    @DisplayName("Rule registry and catalog")
    class Catalog {

        @Test
        @DisplayName("the registry only evaluates rules that consume the event type")
        void onlyRelevantRulesRun() {
            RuleRegistry registry = new DetectionConfig().ruleRegistry();

            assertThat(registry.forEventType("LOGIN")).extracting(DetectionRule::id)
                    .containsExactlyInAnyOrder("AUTH_BURST", "PASSWORD_SPRAY",
                            "ACCOUNT_ENUMERATION", "BRUTE_FORCE_SUCCESS", "IMPOSSIBLE_TRAVEL");
            assertThat(registry.forEventType("NETWORK_CONNECTION")).extracting(DetectionRule::id)
                    .containsExactlyInAnyOrder("NEW_PROCESS_EXTERNAL_CONNECTION", "PRIVILEGE_ESCALATION_CHAIN",
                            "PROCESS_NETWORK_BURST", "NETWORK_CONNECTION_BURST", "MULTI_STAGE_ATTACK_CHAIN");
            assertThat(registry.forEventType("LOGOUT")).isEmpty();
            assertThat(registry.forEventType("TRANSACTION")).isEmpty();
            assertThat(registry.forEventType(null)).isEmpty();
        }

        @Test
        @DisplayName("the catalog describes every rule and exposes no threshold")
        void catalogExposesNoThresholds() {
            RuleRegistry registry = new DetectionConfig().ruleRegistry();
            DetectionProperties props = DetectionProperties.defaults();

            List<RuleDescriptor> described = registry.describe(props);
            assertThat(described).hasSize(10);
            assertThat(described).allSatisfy(d -> {
                assertThat(d.id()).isNotBlank();
                assertThat(d.name()).isNotBlank();
                assertThat(d.description()).isNotBlank();
                assertThat(d.enabled()).isTrue();
                assertThat(d.eventTypes()).isNotEmpty();
                assertThat(d.severities()).isNotEmpty();
                assertThat(d.windowSeconds()).isPositive();
            });

            // The record has no field that could carry a threshold value.
            List<String> fields = java.util.Arrays.stream(RuleDescriptor.class.getRecordComponents())
                    .map(java.lang.reflect.RecordComponent::getName).toList();
            assertThat(fields).doesNotContain("mediumThreshold", "highThreshold", "criticalThreshold",
                    "cooldown", "thresholds", "configuration");
        }

        @Test
        @DisplayName("a disabled rule is reported as disabled rather than hidden")
        void disabledRulesAreVisible() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getPasswordSpray().setEnabled(false);

            List<RuleDescriptor> described = new DetectionConfig().ruleRegistry().describe(props);
            assertThat(described).filteredOn(d -> d.id().equals(PasswordSprayRule.ID))
                    .singleElement()
                    .satisfies(d -> assertThat(d.enabled()).isFalse());
        }

        @Test
        @DisplayName("the advertised severities match the configured ladder")
        void advertisedSeveritiesFollowConfiguration() {
            DetectionProperties props = DetectionProperties.defaults();
            List<RuleDescriptor> described = new DetectionConfig().ruleRegistry().describe(props);

            // AUTH_BURST has no CRITICAL rung configured, so it must not advertise one.
            assertThat(described).filteredOn(d -> d.id().equals(AuthBurstRule.ID))
                    .singleElement()
                    .satisfies(d -> assertThat(d.severities()).containsExactly("HIGH", "MEDIUM"));

            assertThat(described).filteredOn(d -> d.id().equals(ProcessNetworkBurstRule.ID))
                    .singleElement()
                    .satisfies(d -> assertThat(d.severities()).containsExactly("CRITICAL", "HIGH", "MEDIUM"));
        }

        @Test
        @DisplayName("MITRE metadata is present where it maps cleanly")
        void mitreMetadata() {
            List<RuleDescriptor> described = new DetectionConfig().ruleRegistry()
                    .describe(DetectionProperties.defaults());

            assertThat(described).allSatisfy(d -> {
                assertThat(d.tactic()).as(d.id()).isNotBlank();
                assertThat(d.technique()).as(d.id()).isNotBlank();
            });
        }
    }

    /* ================================================================ configuration validation */

    @Nested
    @DisplayName("Configuration is validated at startup")
    class ConfigurationValidation {

        @Test
        @DisplayName("the shipped defaults are valid")
        void defaultsAreValid() {
            assertThatCode(() -> DetectionProperties.defaults().validate()).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("a zero or negative window is rejected, naming the property")
        void rejectsBadWindow() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getAuthBurst().setWindow(Duration.ZERO);
            assertThatThrownBy(props::validate)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("detection.rules.auth-burst.window");

            DetectionProperties negative = DetectionProperties.defaults();
            negative.getRules().getPasswordSpray().setWindow(Duration.ofMinutes(-1));
            assertThatThrownBy(negative::validate)
                    .hasMessageContaining("detection.rules.password-spray.window");
        }

        @Test
        @DisplayName("an inverted severity ladder is rejected")
        void rejectsInvertedLadder() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getAuthBurst().setHighThreshold(2);     // below medium (5)
            assertThatThrownBy(props::validate)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("high-threshold")
                    .hasMessageContaining("must not be below");
        }

        @Test
        @DisplayName("a non-positive threshold is rejected")
        void rejectsNonPositiveThreshold() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getAuthBurst().setMediumThreshold(0);
            assertThatThrownBy(props::validate).hasMessageContaining("medium-threshold");
        }

        @Test
        @DisplayName("a success ratio outside 0..1 is rejected")
        void rejectsBadRatio() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getAccountEnumeration().setMaxSuccessRatio(1.5);
            assertThatThrownBy(props::validate).hasMessageContaining("max-success-ratio");
        }

        @Test
        @DisplayName("a negative cooldown is rejected")
        void rejectsNegativeCooldown() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getProcessNetworkBurst().setCooldown(Duration.ofMinutes(-5));
            assertThatThrownBy(props::validate).hasMessageContaining("cooldown");
        }

        @Test
        @DisplayName("a zero correlation cap is rejected")
        void rejectsZeroCap() {
            DetectionProperties props = DetectionProperties.defaults();
            props.setMaxCorrelationEvents(0);
            assertThatThrownBy(props::validate).hasMessageContaining("max-correlation-events");
        }

        @Test
        @DisplayName("the original rules keep their historical defaults")
        void historicalDefaultsPreserved() {
            DetectionProperties props = DetectionProperties.defaults();

            assertThat(props.getRules().getAuthBurst().getMediumThreshold()).isEqualTo(5);
            assertThat(props.getRules().getAuthBurst().getHighThreshold()).isEqualTo(10);
            assertThat(props.getRules().getAuthBurst().getWindow()).isEqualTo(Duration.ofMinutes(5));
            assertThat(props.getRules().getAuthBurst().getCooldown()).isZero();
            assertThat(props.getRules().getAuthBurst().isEscalate()).isFalse();

            assertThat(props.getRules().getNewProcessExternalConnection().getWindow()).isEqualTo(Duration.ofMinutes(5));
            assertThat(props.getRules().getNewProcessExternalConnection().getCooldown()).isZero();
            assertThat(props.getRules().getNewProcessExternalConnection().isEscalate()).isFalse();
        }
    }
}
