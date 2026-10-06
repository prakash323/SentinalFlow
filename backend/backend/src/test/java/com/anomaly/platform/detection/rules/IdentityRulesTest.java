package com.anomaly.platform.detection.rules;

import com.anomaly.platform.detection.DetectionEngine;
import com.anomaly.platform.detection.DetectionOutcome;
import com.anomaly.platform.detection.DetectionTestHarness;
import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Severity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.anomaly.platform.detection.DetectionTestHarness.NOW;
import static com.anomaly.platform.detection.DetectionTestHarness.login;
import static com.anomaly.platform.detection.DetectionTestHarness.outcomeOf;
import static com.anomaly.platform.detection.DetectionTestHarness.severityOf;
import static org.assertj.core.api.Assertions.assertThat;

/*
 * R003 PASSWORD_SPRAY, R004 ACCOUNT_ENUMERATION, R005 BRUTE_FORCE_SUCCESS and
 * R006 IMPOSSIBLE_TRAVEL.
 *
 * The most important tests here are the ones proving R003 and R004 are genuinely
 * different detections rather than two names for one query, and the ones proving
 * R006 refuses to say anything about an event with no location rather than
 * assuming one.
 */
class IdentityRulesTest {

    private static final String SPRAY_SOURCE = "198.51.100.77";

    /* ================================================================ R003 */

    @Nested
    @DisplayName("R003 PASSWORD_SPRAY - one source, many identities")
    class PasswordSpray {

        private DetectionTestHarness harness() {
            return DetectionTestHarness.with(new PasswordSprayRule());
        }

        /** One failed login against each of `targets` accounts, from one source. */
        private Event spray(DetectionTestHarness h, int targets, String source) {
            Event last = null;
            for (int i = 0; i < targets; i++) {
                last = h.store("USER-" + i, "LOGIN", NOW.minusSeconds(targets - i), login(false, source));
            }
            return last;
        }

        @Test
        @DisplayName("threshold - 1 distinct identities: no alert")
        void belowThreshold() {
            DetectionTestHarness h = harness();
            assertThat(outcomeOf(h.evaluate(spray(h, 4, SPRAY_SOURCE)), PasswordSprayRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("exactly the threshold: MEDIUM alert")
        void atThreshold() {
            DetectionTestHarness h = harness();
            var results = h.evaluate(spray(h, 5, SPRAY_SOURCE));
            assertThat(outcomeOf(results, PasswordSprayRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, PasswordSprayRule.ID)).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("severity rises with breadth: 10 identities HIGH, 20 CRITICAL")
        void severityLadder() {
            DetectionTestHarness ten = harness();
            assertThat(severityOf(ten.evaluate(spray(ten, 10, SPRAY_SOURCE)), PasswordSprayRule.ID))
                    .isEqualTo(Severity.HIGH);

            DetectionTestHarness twenty = harness();
            assertThat(severityOf(twenty.evaluate(spray(twenty, 20, SPRAY_SOURCE)), PasswordSprayRule.ID))
                    .isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("many failures against ONE identity is not a spray - that is AUTH_BURST's finding")
        void depthIsNotBreadth() {
            DetectionTestHarness h = harness();
            Event last = null;
            for (int i = 0; i < 30; i++) {
                last = h.store("USER-ONLY", "LOGIN", NOW.minusSeconds(30 - i), login(false, SPRAY_SOURCE));
            }
            assertThat(outcomeOf(h.evaluate(last), PasswordSprayRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("failures from DIFFERENT sources do not add up to one spray")
        void sourcesAreIndependent() {
            DetectionTestHarness h = harness();
            Event last = null;
            for (int i = 0; i < 10; i++) {
                last = h.store("USER-" + i, "LOGIN", NOW.minusSeconds(10 - i), login(false, "10.0.0." + i));
            }
            assertThat(outcomeOf(h.evaluate(last), PasswordSprayRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("a login with no source address cannot be source-correlated at all")
        void noSourceIsNotApplicable() {
            DetectionTestHarness h = harness();
            for (int i = 0; i < 9; i++) {
                h.store("USER-" + i, "LOGIN", NOW.minusSeconds(10 - i), login(false, SPRAY_SOURCE));
            }
            Event trigger = h.store("USER-X", "LOGIN", NOW, login(false, null));

            assertThat(outcomeOf(h.evaluate(trigger), PasswordSprayRule.ID))
                    .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
        }

        @Test
        @DisplayName("one spray raises ONE alert across every entity it touched")
        void suppressedAcrossEntities() {
            DetectionTestHarness h = harness();
            Event first = spray(h, 6, SPRAY_SOURCE);
            assertThat(outcomeOf(h.evaluate(first), PasswordSprayRule.ID)).isEqualTo(DetectionOutcome.DETECTED);

            // The same spray continues against yet another account.
            Event next = h.store("USER-NEW", "LOGIN", NOW.plusSeconds(1), login(false, SPRAY_SOURCE));

            assertThat(outcomeOf(h.evaluate(next), PasswordSprayRule.ID))
                    .isEqualTo(DetectionOutcome.SUPPRESSED_ACTIVE_ALERT);
            assertThat(h.alertsFor(PasswordSprayRule.ID)).hasSize(1);
        }

        @Test
        @DisplayName("a DIFFERENT source still raises its own alert")
        void differentSourceStillFires() {
            DetectionTestHarness h = harness();
            h.evaluate(spray(h, 6, SPRAY_SOURCE));

            Event other = null;
            for (int i = 0; i < 6; i++) {
                other = h.store("OTHER-" + i, "LOGIN", NOW.plusSeconds(i + 1L), login(false, "203.0.113.200"));
            }

            assertThat(outcomeOf(h.evaluate(other), PasswordSprayRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(h.alertsFor(PasswordSprayRule.ID)).hasSize(2);
        }

        @Test
        @DisplayName("the evidence names the source, the breadth and the attempts-per-target shape")
        void evidenceExplainsTheSprayShape() {
            DetectionTestHarness h = harness();
            h.evaluate(spray(h, 7, SPRAY_SOURCE));

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat(audit.get("ruleId")).isEqualTo(PasswordSprayRule.ID);
            assertThat(audit.get("source")).isEqualTo(SPRAY_SOURCE);
            assertThat(audit.get("distinctTargets")).isEqualTo(7L);
            assertThat(audit.get("attemptsPerTarget")).isEqualTo(1.0);
            assertThat((List<?>) audit.get("targets")).hasSize(7);
            assertThat(String.valueOf(audit.get("message")))
                    .contains("PASSWORD_SPRAY detected")
                    .contains("7 distinct identities")
                    .contains(SPRAY_SOURCE);
        }

        @Test
        @DisplayName("disabled: no detection")
        void disabled() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getPasswordSpray().setEnabled(false);
            DetectionTestHarness h = DetectionTestHarness.with(props, new PasswordSprayRule());
            assertThat(outcomeOf(h.evaluate(spray(h, 20, SPRAY_SOURCE)), PasswordSprayRule.ID))
                    .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
        }
    }

    /* ================================================================ R004 */

    @Nested
    @DisplayName("R004 ACCOUNT_ENUMERATION - broad, sustained, unsuccessful")
    class AccountEnumeration {

        private DetectionTestHarness harness() {
            return DetectionTestHarness.with(new AccountEnumerationRule());
        }

        /** `targets` identities, `each` attempts apiece, all failures, from one source. */
        private Event enumerate(DetectionTestHarness h, int targets, int each, String source) {
            Event last = null;
            int t = 0;
            for (int i = 0; i < targets; i++) {
                for (int j = 0; j < each; j++) {
                    last = h.store("ACC-" + i, "LOGIN", NOW.minusSeconds(200 - (t++)), login(false, source));
                }
            }
            return last;
        }

        @Test
        @DisplayName("broad but too few attempts: no alert")
        void needsVolumeAsWellAsBreadth() {
            DetectionTestHarness h = harness();
            // 12 identities, one attempt each = 12 attempts, below the 15 bar.
            assertThat(outcomeOf(h.evaluate(enumerate(h, 12, 1, SPRAY_SOURCE)), AccountEnumerationRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("high volume but too few identities: no alert")
        void needsBreadthAsWellAsVolume() {
            DetectionTestHarness h = harness();
            // 5 identities, 6 attempts each = 30 attempts but only 5 identities.
            assertThat(outcomeOf(h.evaluate(enumerate(h, 5, 6, SPRAY_SOURCE)), AccountEnumerationRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("broad, sustained and unsuccessful: alert")
        void fires() {
            DetectionTestHarness h = harness();
            var results = h.evaluate(enumerate(h, 10, 2, SPRAY_SOURCE));
            assertThat(outcomeOf(results, AccountEnumerationRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, AccountEnumerationRule.ID)).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("mostly SUCCESSFUL broad activity is use, not enumeration")
        void successRatioExcludesLegitimateUse() {
            DetectionTestHarness h = harness();
            // 12 identities, mostly succeeding: an integration, not an attacker.
            Event last = null;
            for (int i = 0; i < 12; i++) {
                last = h.store("SVC-" + i, "LOGIN", NOW.minusSeconds(60 - i), login(true, SPRAY_SOURCE));
            }
            for (int i = 0; i < 4; i++) {
                last = h.store("SVC-F" + i, "LOGIN", NOW.minusSeconds(20 - i), login(false, SPRAY_SOURCE));
            }

            assertThat(outcomeOf(h.evaluate(last), AccountEnumerationRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("the success ratio bar is configurable and is what makes the decision")
        void successRatioIsConfigurable() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getAccountEnumeration().setMaxSuccessRatio(1.0);   // accept any ratio
            DetectionTestHarness h = DetectionTestHarness.with(props, new AccountEnumerationRule());

            Event last = null;
            for (int i = 0; i < 12; i++) {
                last = h.store("SVC-" + i, "LOGIN", NOW.minusSeconds(60 - i), login(true, SPRAY_SOURCE));
            }
            for (int i = 0; i < 10; i++) {
                last = h.store("SVC-F" + i, "LOGIN", NOW.minusSeconds(20 - i), login(false, SPRAY_SOURCE));
            }

            assertThat(outcomeOf(h.evaluate(last), AccountEnumerationRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
        }

        @Test
        @DisplayName("the evidence records attempts, successes and the ratio that decided it")
        void evidenceRecordsTheRatio() {
            DetectionTestHarness h = harness();
            h.evaluate(enumerate(h, 10, 2, SPRAY_SOURCE));

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat(audit.get("count")).isEqualTo(20L);
            assertThat(audit.get("distinctTargets")).isEqualTo(10L);
            assertThat(audit.get("successfulAttempts")).isEqualTo(0L);
            assertThat(audit.get("successRatio")).isEqualTo(0.0);
            assertThat(audit.get("maxSuccessRatio")).isEqualTo(0.2);
            assertThat(String.valueOf(audit.get("message"))).contains("0 successes");
        }
    }

    /* ================================================================ R003 vs R004 */

    @Nested
    @DisplayName("R003 and R004 are different detections, not duplicates")
    class SprayVersusEnumeration {

        @Test
        @DisplayName("a shallow spray trips R003 only - it never reaches R004's volume bar")
        void shallowSprayIsSprayOnly() {
            DetectionTestHarness h = DetectionTestHarness.with(new PasswordSprayRule(), new AccountEnumerationRule());

            Event last = null;
            for (int i = 0; i < 6; i++) {
                last = h.store("U-" + i, "LOGIN", NOW.minusSeconds(10 - i), login(false, SPRAY_SOURCE));
            }
            var results = h.evaluate(last);

            assertThat(outcomeOf(results, PasswordSprayRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(outcomeOf(results, AccountEnumerationRule.ID)).isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("broad sustained probing trips BOTH, and both are true statements with different evidence")
        void broadProbingTripsBothLegitimately() {
            DetectionTestHarness h = DetectionTestHarness.with(new PasswordSprayRule(), new AccountEnumerationRule());

            Event last = null;
            int t = 0;
            for (int i = 0; i < 12; i++) {
                for (int j = 0; j < 2; j++) {
                    last = h.store("U-" + i, "LOGIN", NOW.minusSeconds(100 - (t++)), login(false, SPRAY_SOURCE));
                }
            }
            var results = h.evaluate(last);

            assertThat(outcomeOf(results, PasswordSprayRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(outcomeOf(results, AccountEnumerationRule.ID)).isEqualTo(DetectionOutcome.DETECTED);

            // Two alerts, each stating which measurement it made - not one finding twice.
            assertThat(h.alertsFor(PasswordSprayRule.ID)).hasSize(1);
            assertThat(h.alertsFor(AccountEnumerationRule.ID)).hasSize(1);

            List<Map<String, Object>> created = h.audit.rows.stream()
                    .filter(r -> r.action().equals(DetectionEngine.AUDIT_DETECTION_CREATED))
                    .map(DetectionTestHarness.RecordingAuditLogService.Row::details)
                    .toList();
            assertThat(created).hasSize(2);
            // The spray cites breadth; the enumeration additionally cites volume and outcome.
            assertThat(created.get(0)).containsKey("attemptsPerTarget");
            assertThat(created.get(1)).containsKeys("successRatio", "attemptThreshold");
        }
    }

    /* ================================================================ R005 */

    @Nested
    @DisplayName("R005 BRUTE_FORCE_SUCCESS - possible compromise, not just an attempt")
    class BruteForceSuccess {

        private DetectionTestHarness harness() {
            return DetectionTestHarness.with(new BruteForceSuccessRule());
        }

        private void failures(DetectionTestHarness h, String entity, int count, String ip) {
            for (int i = count; i >= 1; i--) {
                h.store(entity, "LOGIN", NOW.minusSeconds(60L + i), login(false, ip));
            }
        }

        @Test
        @DisplayName("FAIL x4 then SUCCESS: below the failure threshold, no alert")
        void belowFailureThreshold() {
            DetectionTestHarness h = harness();
            failures(h, "HOST-B", 4, "203.0.113.5");
            Event success = h.store("HOST-B", "LOGIN", NOW, login(true, "203.0.113.5"));

            assertThat(outcomeOf(h.evaluate(success), BruteForceSuccessRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("FAIL x5 then SUCCESS: HIGH alert")
        void firesAtThreshold() {
            DetectionTestHarness h = harness();
            failures(h, "HOST-B", 5, "203.0.113.5");
            Event success = h.store("HOST-B", "LOGIN", NOW, login(true, "203.0.113.5"));

            var results = h.evaluate(success);
            assertThat(outcomeOf(results, BruteForceSuccessRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, BruteForceSuccessRule.ID)).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("FAIL x10 then SUCCESS: CRITICAL")
        void criticalAtHighFailureCount() {
            DetectionTestHarness h = harness();
            failures(h, "HOST-B", 10, "203.0.113.5");
            Event success = h.store("HOST-B", "LOGIN", NOW, login(true, "203.0.113.5"));

            assertThat(severityOf(h.evaluate(success), BruteForceSuccessRule.ID)).isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("failures alone never fire this rule - the success is the finding")
        void failuresAloneDoNotFire() {
            DetectionTestHarness h = harness();
            Event lastFailure = null;
            for (int i = 10; i >= 1; i--) {
                lastFailure = h.store("HOST-B", "LOGIN", NOW.minusSeconds(i), login(false, "203.0.113.5"));
            }
            assertThat(outcomeOf(h.evaluate(lastFailure), BruteForceSuccessRule.ID))
                    .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
        }

        @Test
        @DisplayName("a success far after the last failure is not the same episode")
        void gapBoundary() {
            DetectionTestHarness inside = harness();
            failures(inside, "HOST-G", 6, "203.0.113.5");
            // Last failure is at NOW-61s; a success 2m later is still inside max-gap.
            Event near = inside.store("HOST-G", "LOGIN", NOW.minusSeconds(61).plusMinutes(2), login(true, "203.0.113.5"));
            assertThat(outcomeOf(inside.evaluate(near), BruteForceSuccessRule.ID)).isEqualTo(DetectionOutcome.DETECTED);

            DetectionTestHarness outside = harness();
            failures(outside, "HOST-G", 6, "203.0.113.5");
            Event far = outside.store("HOST-G", "LOGIN", NOW.minusSeconds(61).plusMinutes(3), login(true, "203.0.113.5"));
            assertThat(outcomeOf(outside.evaluate(far), BruteForceSuccessRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("the evidence captures the failure count, the gap and whether the source matched")
        void evidenceCapturesTheCompromiseShape() {
            DetectionTestHarness h = harness();
            failures(h, "HOST-EV", 6, "203.0.113.5");
            Event success = h.store("HOST-EV", "LOGIN", NOW, login(true, "203.0.113.5"));

            h.evaluate(success);

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat(audit.get("count")).isEqualTo(6L);
            assertThat(audit.get("threshold")).isEqualTo(5L);
            assertThat(audit.get("successEventId")).isEqualTo(success.getEventId());
            assertThat(audit.get("secondsFromLastFailureToSuccess")).isEqualTo(61L);
            assertThat(audit.get("successFromSameSourceAsFailures")).isEqualTo(true);
            assertThat(audit).containsKeys("successAt", "lastFailureAt");
            assertThat(String.valueOf(audit.get("message")))
                    .contains("BRUTE_FORCE_SUCCESS detected")
                    .contains("after 6 failed attempts");
        }

        @Test
        @DisplayName("a success from a DIFFERENT source than the failures is recorded as such")
        void differentSourceIsRecorded() {
            DetectionTestHarness h = harness();
            failures(h, "HOST-DS", 6, "203.0.113.5");
            Event success = h.store("HOST-DS", "LOGIN", NOW, login(true, "10.0.0.9"));

            h.evaluate(success);

            assertThat(h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED).get("successFromSameSourceAsFailures"))
                    .isEqualTo(false);
        }

        @Test
        @DisplayName("AUTH_BURST and BRUTE_FORCE_SUCCESS coexist: two statements, two alerts")
        void coexistsWithAuthBurst() {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule(), new BruteForceSuccessRule());

            Event lastFailure = null;
            for (int i = 6; i >= 1; i--) {
                lastFailure = h.store("HOST-C", "LOGIN", NOW.minusSeconds(60L + i), login(false, "203.0.113.5"));
            }
            h.evaluate(lastFailure);
            assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);

            Event success = h.store("HOST-C", "LOGIN", NOW, login(true, "203.0.113.5"));
            var results = h.evaluate(success);

            assertThat(outcomeOf(results, BruteForceSuccessRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            // AUTH_BURST does not fire on a success, and its own alert is untouched.
            assertThat(outcomeOf(results, AuthBurstRule.ID)).isEqualTo(DetectionOutcome.NOT_APPLICABLE);
            assertThat(h.alertsFor(AuthBurstRule.ID)).hasSize(1);
            assertThat(h.alertsFor(BruteForceSuccessRule.ID)).hasSize(1);
        }
    }

    /* ================================================================ R006 */

    @Nested
    @DisplayName("R006 IMPOSSIBLE_TRAVEL - only where the data is real")
    class ImpossibleTravel {

        private static final String PUNE = "Pune|18.52|73.86";
        private static final String LAGOS = "Lagos|6.52|3.37";
        private static final String MUMBAI = "Mumbai|19.08|72.88";

        private DetectionTestHarness harness() {
            return DetectionTestHarness.with(new ImpossibleTravelRule());
        }

        @Test
        @DisplayName("Pune then Lagos five minutes later: impossible, CRITICAL")
        void impossiblePair() {
            DetectionTestHarness h = harness();
            h.store("USER-T", "LOGIN", NOW.minusMinutes(5), login(true, "10.24.7.18", PUNE));
            Event trigger = h.store("USER-T", "LOGIN", NOW, login(true, "102.89.34.7", LAGOS));

            var results = h.evaluate(trigger);
            assertThat(outcomeOf(results, ImpossibleTravelRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, ImpossibleTravelRule.ID)).isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("the same journey over two days is perfectly possible")
        void possibleOverEnoughTime() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getImpossibleTravel().setWindow(Duration.ofDays(5));
            DetectionTestHarness h = DetectionTestHarness.with(props, new ImpossibleTravelRule());

            h.store("USER-T", "LOGIN", NOW.minusDays(2), login(true, "10.24.7.18", PUNE));
            Event trigger = h.store("USER-T", "LOGIN", NOW, login(true, "102.89.34.7", LAGOS));

            assertThat(outcomeOf(h.evaluate(trigger), ImpossibleTravelRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("a short hop is below the distance floor, where coordinates and clocks are noise")
        void shortDistanceIsIgnored() {
            DetectionTestHarness h = harness();
            h.store("USER-T", "LOGIN", NOW.minusMinutes(1), login(true, "10.24.7.18", PUNE));
            Event trigger = h.store("USER-T", "LOGIN", NOW, login(true, "10.24.7.19", MUMBAI));

            assertThat(outcomeOf(h.evaluate(trigger), ImpossibleTravelRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("an event with NO location is never assumed to be anywhere")
        void missingLocationIsNotApplicable() {
            DetectionTestHarness h = harness();
            h.store("USER-N", "LOGIN", NOW.minusMinutes(5), login(true, "10.24.7.18", PUNE));
            Event trigger = h.store("USER-N", "LOGIN", NOW, login(true, "102.89.34.7"));   // collector-shaped

            assertThat(outcomeOf(h.evaluate(trigger), ImpossibleTravelRule.ID))
                    .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
            assertThat(h.alerts.stored).isEmpty();
        }

        @Test
        @DisplayName("a malformed location is ignored, never guessed at")
        void malformedLocationIsIgnored() {
            DetectionTestHarness h = harness();
            h.store("USER-M", "LOGIN", NOW.minusMinutes(5), login(true, "10.24.7.18", PUNE));

            for (String bad : List.of("Nowhere", "Nowhere|abc|def", "|18.5|73.8", "X|999|999", "a|b")) {
                Event trigger = h.store("USER-M", "LOGIN", NOW, login(true, "102.89.34.7", bad));
                assertThat(outcomeOf(h.evaluate(trigger), ImpossibleTravelRule.ID))
                        .as("location %s", bad)
                        .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
            }
            assertThat(h.alerts.stored).isEmpty();
        }

        @Test
        @DisplayName("only a previous SUCCESS is compared against - a failed login proves no presence")
        void onlySuccessesAreCompared() {
            DetectionTestHarness h = harness();
            h.store("USER-F", "LOGIN", NOW.minusMinutes(5), login(false, "10.24.7.18", PUNE));
            Event trigger = h.store("USER-F", "LOGIN", NOW, login(true, "102.89.34.7", LAGOS));

            assertThat(outcomeOf(h.evaluate(trigger), ImpossibleTravelRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("the alert states that the location was self-reported, never claiming a geo-IP lookup")
        void evidenceStatesTheLimitation() {
            DetectionTestHarness h = harness();
            h.store("USER-E", "LOGIN", NOW.minusMinutes(5), login(true, "10.24.7.18", PUNE));
            Event trigger = h.store("USER-E", "LOGIN", NOW, login(true, "102.89.34.7", LAGOS));

            h.evaluate(trigger);

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat(String.valueOf(audit.get("locationSource")))
                    .contains("self-reported")
                    .contains("no geo-IP lookup is performed");
            assertThat(audit.get("fromCity")).isEqualTo("Pune");
            assertThat(audit.get("toCity")).isEqualTo("Lagos");
            assertThat(audit).containsKeys("distanceKm", "impliedSpeedKmph", "elapsedSeconds");
            assertThat(String.valueOf(audit.get("message")))
                    .contains("IMPOSSIBLE_TRAVEL detected")
                    .contains("Pune")
                    .contains("Lagos")
                    .contains("km/h");
        }

        @Test
        @DisplayName("the speed bar is configurable")
        void speedThresholdIsConfigurable() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getImpossibleTravel().setMinSpeedKmph(100_000);
            DetectionTestHarness h = DetectionTestHarness.with(props, new ImpossibleTravelRule());

            h.store("USER-C", "LOGIN", NOW.minusMinutes(5), login(true, "10.24.7.18", PUNE));
            Event trigger = h.store("USER-C", "LOGIN", NOW, login(true, "102.89.34.7", LAGOS));

            assertThat(outcomeOf(h.evaluate(trigger), ImpossibleTravelRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }
    }

    /* ================================================================ shared robustness */

    @Nested
    @DisplayName("Shared robustness across every identity rule")
    class SharedRobustness {


        @Test
        @DisplayName("every identity rule survives an event with an entirely unexpected payload")
        void allIdentityRulesSurviveGarbage() {
            DetectionTestHarness h = DetectionTestHarness.with(
                    new AuthBurstRule(), new PasswordSprayRule(), new AccountEnumerationRule(),
                    new BruteForceSuccessRule(), new ImpossibleTravelRule());

            Map<String, Object> garbage = new HashMap<>();
            garbage.put("loginSuccess", List.of("not", "a", "boolean"));
            garbage.put("ip", Map.of("nested", "object"));
            garbage.put("location", 42);
            garbage.put("username", true);

            Event trigger = h.store("HOST-GARBAGE", "LOGIN", NOW, garbage);

            assertThat(h.evaluate(trigger)).hasSize(5);
            assertThat(h.alerts.stored).isEmpty();
        }

        @Test
        @DisplayName("no rule ever raises an alert without evidence that meets its own threshold")
        void noAlertWithoutSufficientEvidence() {
            DetectionTestHarness h = DetectionTestHarness.with(
                    new AuthBurstRule(), new PasswordSprayRule(), new AccountEnumerationRule(),
                    new BruteForceSuccessRule(), new ImpossibleTravelRule());

            // One lonely failed login: not enough for anything.
            Event trigger = h.store("HOST-ONE", "LOGIN", NOW, login(false, "203.0.113.1"));
            h.evaluate(trigger);

            assertThat(h.alerts.stored).isEmpty();
            assertThat(h.auditCount(DetectionEngine.AUDIT_DETECTION_CREATED)).isZero();
        }

        @Test
        @DisplayName("every raised alert carries the rule id, SUSPICIOUS, the rules policy version and no prediction")
        void ruleAlertsAreDistinguishableFromMlAlerts() {
            DetectionTestHarness h = DetectionTestHarness.with(new AuthBurstRule());
            for (int i = 6; i >= 1; i--) {
                h.store("HOST-ML", "LOGIN", NOW.minusSeconds(i), login(false, "203.0.113.1"));
            }
            h.evaluate(h.store("HOST-ML", "LOGIN", NOW, login(false, "203.0.113.1")));

            Alert alert = h.alertsFor(AuthBurstRule.ID).get(0);
            assertThat(alert.getRuleId()).isEqualTo(AuthBurstRule.ID);
            assertThat(alert.getRuleName()).isNotBlank();
            assertThat(alert.getDecision().name()).isEqualTo("SUSPICIOUS");
            assertThat(alert.getPolicyVersion()).isEqualTo(DetectionEngine.RULE_POLICY_VERSION);
            assertThat(alert.getPrediction()).isNull();
            assertThat(alert.getAnomalyScore()).isNull();
            assertThat(alert.getFusedScore()).isNull();
        }
    }
}
