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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.anomaly.platform.detection.DetectionTestHarness.NOW;
import static com.anomaly.platform.detection.DetectionTestHarness.connection;
import static com.anomaly.platform.detection.DetectionTestHarness.fileAccess;
import static com.anomaly.platform.detection.DetectionTestHarness.outcomeOf;
import static com.anomaly.platform.detection.DetectionTestHarness.processStart;
import static com.anomaly.platform.detection.DetectionTestHarness.severityOf;
import static org.assertj.core.api.Assertions.assertThat;

/*
 * R002 NEW_PROCESS_EXTERNAL_CONNECTION, R007 PRIVILEGE_ESCALATION_CHAIN,
 * R008 PROCESS_NETWORK_BURST and R009 NETWORK_CONNECTION_BURST.
 *
 * The correlation contract these share - exact pid AND processCreateTime, with no
 * tolerance - is the thing most at risk of being quietly weakened by a later
 * change, so it is tested from every angle: a different pid, a different create
 * time, a reused pid, a missing field and a loopback destination.
 */
class EndpointRulesTest {

    private static final String EXTERNAL = "198.51.100.23";

    /* ================================================================ R002 */

    @Nested
    @DisplayName("R002 NEW_PROCESS_EXTERNAL_CONNECTION - exact process identity")
    class NewProcessExternalConnection {

        private DetectionTestHarness harness() {
            return DetectionTestHarness.with(new NewProcessExternalConnectionRule());
        }

        @Test
        @DisplayName("a correlated process and connection: MEDIUM alert")
        void fires() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            h.store("HOST-1", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-1", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            var results = h.evaluate(conn);
            assertThat(outcomeOf(results, NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, NewProcessExternalConnectionRule.ID)).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("a DIFFERENT pid does not correlate")
        void differentPid() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            h.store("HOST-1", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-1", "NETWORK_CONNECTION", NOW, connection(9999, started, EXTERNAL));

            assertThat(outcomeOf(h.evaluate(conn), NewProcessExternalConnectionRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("the same pid with a DIFFERENT create time is a different process - pid reuse")
        void pidReuseDoesNotCorrelate() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            h.store("HOST-1", "PROCESS_START", started, processStart(8100, "curl"));
            // Same pid, a create time one second off: a later, unrelated process.
            Event conn = h.store("HOST-1", "NETWORK_CONNECTION", NOW,
                    connection(8100, started.plusSeconds(1), EXTERNAL));

            assertThat(outcomeOf(h.evaluate(conn), NewProcessExternalConnectionRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("the create-time match has NO tolerance, not even a second")
        void noTimeTolerance() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            h.store("HOST-1", "PROCESS_START", started, processStart(8100, "curl"));

            for (int offset : new int[]{-2, -1, 1, 2}) {
                Event conn = h.store("HOST-1", "NETWORK_CONNECTION", NOW,
                        connection(8100, started.plusSeconds(offset), EXTERNAL));
                assertThat(outcomeOf(h.evaluate(conn), NewProcessExternalConnectionRule.ID))
                        .as("offset %ds", offset)
                        .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
            }
            assertThat(h.alerts.stored).isEmpty();
        }

        @Test
        @DisplayName("loopback is not egress")
        void loopbackExcluded() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            h.store("HOST-1", "PROCESS_START", started, processStart(8100, "curl"));

            for (String loopback : List.of("127.0.0.1", "127.1.2.3", "::1", "localhost", "LOCALHOST")) {
                Event conn = h.store("HOST-1", "NETWORK_CONNECTION", NOW, connection(8100, started, loopback));
                assertThat(outcomeOf(h.evaluate(conn), NewProcessExternalConnectionRule.ID))
                        .as(loopback)
                        .isEqualTo(DetectionOutcome.NOT_APPLICABLE);
            }
            assertThat(h.alerts.stored).isEmpty();
        }

        @Test
        @DisplayName("the recency bound: on the boundary it fires, past it it does not")
        void recencyBoundary() {
            DetectionTestHarness onBoundary = harness();
            OffsetDateTime started = NOW.minusMinutes(5);
            onBoundary.store("HOST-R", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = onBoundary.store("HOST-R", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));
            assertThat(outcomeOf(onBoundary.evaluate(conn), NewProcessExternalConnectionRule.ID))
                    .isEqualTo(DetectionOutcome.DETECTED);

            DetectionTestHarness past = harness();
            OffsetDateTime older = NOW.minusMinutes(5).minusSeconds(1);
            past.store("HOST-R", "PROCESS_START", older, processStart(8100, "curl"));
            Event late = past.store("HOST-R", "NETWORK_CONNECTION", NOW, connection(8100, older, EXTERNAL));
            assertThat(outcomeOf(past.evaluate(late), NewProcessExternalConnectionRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("a missing pid or create time is not this rule's business")
        void missingFields() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            h.store("HOST-1", "PROCESS_START", started, processStart(8100, "curl"));

            Map<String, Object> noPid = new HashMap<>();
            noPid.put("processCreateTime", DetectionTestHarness.iso(started));
            noPid.put("remoteAddress", EXTERNAL);
            assertThat(outcomeOf(h.evaluate(h.store("HOST-1", "NETWORK_CONNECTION", NOW, noPid)),
                    NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.NOT_APPLICABLE);

            Map<String, Object> noCreateTime = new HashMap<>();
            noCreateTime.put("pid", 8100);
            noCreateTime.put("remoteAddress", EXTERNAL);
            assertThat(outcomeOf(h.evaluate(h.store("HOST-1", "NETWORK_CONNECTION", NOW, noCreateTime)),
                    NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.NOT_APPLICABLE);

            Map<String, Object> noRemote = new HashMap<>();
            noRemote.put("pid", 8100);
            noRemote.put("processCreateTime", DetectionTestHarness.iso(started));
            assertThat(outcomeOf(h.evaluate(h.store("HOST-1", "NETWORK_CONNECTION", NOW, noRemote)),
                    NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.NOT_APPLICABLE);
        }

        @Test
        @DisplayName("a PROCESS_START on a DIFFERENT entity never correlates")
        void entitiesAreIndependent() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            h.store("HOST-OTHER", "PROCESS_START", started, processStart(8100, "curl"));
            Event conn = h.store("HOST-1", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            assertThat(outcomeOf(h.evaluate(conn), NewProcessExternalConnectionRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("a second connection from the SAME process is suppressed")
        void suppressedForSameProcess() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(30);
            h.store("HOST-S", "PROCESS_START", started, processStart(8100, "curl"));
            h.evaluate(h.store("HOST-S", "NETWORK_CONNECTION", NOW.minusSeconds(10), connection(8100, started, EXTERNAL)));

            Event second = h.store("HOST-S", "NETWORK_CONNECTION", NOW, connection(8100, started, "203.0.113.9"));

            assertThat(outcomeOf(h.evaluate(second), NewProcessExternalConnectionRule.ID))
                    .isEqualTo(DetectionOutcome.SUPPRESSED_ACTIVE_ALERT);
            assertThat(h.alertsFor(NewProcessExternalConnectionRule.ID)).hasSize(1);
        }

        @Test
        @DisplayName("a DIFFERENT process on the same host still raises its own alert")
        void differentProcessStillFires() {
            DetectionTestHarness h = harness();
            OffsetDateTime firstStart = NOW.minusSeconds(40);
            OffsetDateTime secondStart = NOW.minusSeconds(20);
            h.store("HOST-D", "PROCESS_START", firstStart, processStart(8100, "curl"));
            h.store("HOST-D", "PROCESS_START", secondStart, processStart(8101, "wget"));

            h.evaluate(h.store("HOST-D", "NETWORK_CONNECTION", NOW.minusSeconds(10), connection(8100, firstStart, EXTERNAL)));
            Event other = h.store("HOST-D", "NETWORK_CONNECTION", NOW, connection(8101, secondStart, EXTERNAL));

            assertThat(outcomeOf(h.evaluate(other), NewProcessExternalConnectionRule.ID))
                    .isEqualTo(DetectionOutcome.DETECTED);
            assertThat(h.alertsFor(NewProcessExternalConnectionRule.ID)).hasSize(2);
        }

        @Test
        @DisplayName("the evidence explains PROCESS -> PID -> DESTINATION -> TIME DELTA")
        void evidenceExplainsTheChain() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            h.store("HOST-EV", "PROCESS_START", started, processStart(8100, "curl"));
            Map<String, Object> payload = connection(8100, started, EXTERNAL);
            payload.put("remotePort", 443);
            Event conn = h.store("HOST-EV", "NETWORK_CONNECTION", NOW, payload);

            h.evaluate(conn);

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat(audit.get("processId")).isEqualTo(8100L);
            assertThat(audit.get("processName")).isEqualTo("curl");
            assertThat(audit.get("processCreateTime")).isEqualTo(DetectionTestHarness.iso(started));
            assertThat(audit.get("secondsAfterProcessCreation")).isEqualTo(20L);
            assertThat(audit.get("destinations")).isEqualTo(List.of(EXTERNAL + ":443"));
            assertThat(String.valueOf(audit.get("message")))
                    .contains("NEW_PROCESS_EXTERNAL_CONNECTION detected")
                    .contains("curl (pid 8100)")
                    .contains(EXTERNAL + ":443")
                    .contains("20s after it was created");
        }

        @Test
        @DisplayName("a long entity name and an IPv6 destination still fit the factor column")
        void evidenceFitsTheColumn() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(20);
            String entity = "HOST-with-a-really-rather-long-entity-identifier-string-for-testing";
            h.store(entity, "PROCESS_START", started,
                    processStart(5216, "some-unusually-long-executable-name-for-a-background-worker.exe"));
            Event conn = h.store(entity, "NETWORK_CONNECTION", NOW,
                    connection(5216, started, "2606:4700:0010:0000:0000:0000:6814:179a"));

            h.evaluate(conn);

            Alert alert = h.alertsFor(NewProcessExternalConnectionRule.ID).get(0);
            assertThat(h.factorsOf(alert)).isNotEmpty();
            assertThat(h.factorsOf(alert)).allSatisfy(f -> assertThat(f.length()).isLessThanOrEqualTo(128));
        }
    }

    /* ================================================================ R008 */

    @Nested
    @DisplayName("R008 PROCESS_NETWORK_BURST - one process, repeated egress")
    class ProcessNetworkBurst {

        private DetectionTestHarness harness() {
            return DetectionTestHarness.with(new ProcessNetworkBurstRule());
        }

        private Event burst(DetectionTestHarness h, String entity, int connections, OffsetDateTime started) {
            h.store(entity, "PROCESS_START", started, processStart(8100, "curl"));
            Event last = null;
            for (int i = 0; i < connections; i++) {
                last = h.store(entity, "NETWORK_CONNECTION", started.plusSeconds(i + 1L),
                        connection(8100, started, "198.51.100." + (10 + i)));
            }
            return last;
        }

        @Test
        @DisplayName("threshold - 1 connections: no alert")
        void belowThreshold() {
            DetectionTestHarness h = harness();
            Event last = burst(h, "HOST-B", 4, NOW.minusSeconds(30));
            assertThat(outcomeOf(h.evaluate(last), ProcessNetworkBurstRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("exactly the threshold: MEDIUM")
        void atThreshold() {
            DetectionTestHarness h = harness();
            Event last = burst(h, "HOST-B", 5, NOW.minusSeconds(30));
            var results = h.evaluate(last);
            assertThat(outcomeOf(results, ProcessNetworkBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, ProcessNetworkBurstRule.ID)).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("severity rises with volume: 10 HIGH, 20 CRITICAL")
        void severityLadder() {
            DetectionTestHarness ten = harness();
            assertThat(severityOf(ten.evaluate(burst(ten, "H", 10, NOW.minusSeconds(40))), ProcessNetworkBurstRule.ID))
                    .isEqualTo(Severity.HIGH);

            DetectionTestHarness twenty = harness();
            assertThat(severityOf(twenty.evaluate(burst(twenty, "H", 20, NOW.minusSeconds(50))), ProcessNetworkBurstRule.ID))
                    .isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("connections from a DIFFERENT process do not add to this one's count")
        void otherProcessesDoNotCount() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(30);
            h.store("HOST-M", "PROCESS_START", started, processStart(8100, "curl"));
            h.store("HOST-M", "PROCESS_START", started, processStart(9999, "wget"));
            for (int i = 0; i < 3; i++) {
                h.store("HOST-M", "NETWORK_CONNECTION", started.plusSeconds(i + 1L),
                        connection(8100, started, "198.51.100." + i));
            }
            for (int i = 0; i < 10; i++) {
                h.store("HOST-M", "NETWORK_CONNECTION", started.plusSeconds(i + 5L),
                        connection(9999, started, "203.0.113." + i));
            }
            Event last = h.store("HOST-M", "NETWORK_CONNECTION", NOW, connection(8100, started, "198.51.100.99"));

            // Only 4 belong to pid 8100.
            assertThat(outcomeOf(h.evaluate(last), ProcessNetworkBurstRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("without a correlated PROCESS_START, volume alone is not this rule's finding")
        void needsARealProcessStart() {
            DetectionTestHarness h = harness();
            OffsetDateTime started = NOW.minusSeconds(30);
            Event last = null;
            for (int i = 0; i < 10; i++) {
                last = h.store("HOST-N", "NETWORK_CONNECTION", started.plusSeconds(i + 1L),
                        connection(8100, started, "198.51.100." + i));
            }
            assertThat(outcomeOf(h.evaluate(last), ProcessNetworkBurstRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("R002 and R008 are complementary: one pair fires R002 only, a burst fires both")
        void complementsR002() {
            DetectionTestHarness single = DetectionTestHarness.with(
                    new NewProcessExternalConnectionRule(), new ProcessNetworkBurstRule());
            OffsetDateTime started = NOW.minusSeconds(20);
            single.store("HOST-C", "PROCESS_START", started, processStart(8100, "curl"));
            Event one = single.store("HOST-C", "NETWORK_CONNECTION", NOW, connection(8100, started, EXTERNAL));

            var oneResult = single.evaluate(one);
            assertThat(outcomeOf(oneResult, NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(outcomeOf(oneResult, ProcessNetworkBurstRule.ID)).isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);

            DetectionTestHarness many = DetectionTestHarness.with(
                    new NewProcessExternalConnectionRule(), new ProcessNetworkBurstRule());
            OffsetDateTime start2 = NOW.minusSeconds(40);
            many.store("HOST-C", "PROCESS_START", start2, processStart(8100, "curl"));
            Event last = null;
            for (int i = 0; i < 6; i++) {
                last = many.store("HOST-C", "NETWORK_CONNECTION", start2.plusSeconds(i + 1L),
                        connection(8100, start2, "198.51.100." + i));
            }
            var manyResult = many.evaluate(last);

            // R002 fires on the first connection it sees; R008 fires on the volume.
            assertThat(outcomeOf(manyResult, NewProcessExternalConnectionRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(outcomeOf(manyResult, ProcessNetworkBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(many.alertsFor(NewProcessExternalConnectionRule.ID)).hasSize(1);
            assertThat(many.alertsFor(ProcessNetworkBurstRule.ID)).hasSize(1);
        }

        @Test
        @DisplayName("the evidence lists the destinations and the fan-out")
        void evidenceListsDestinations() {
            DetectionTestHarness h = harness();
            h.evaluate(burst(h, "HOST-EV", 6, NOW.minusSeconds(30)));

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat(audit.get("count")).isEqualTo(6L);
            assertThat(audit.get("distinctDestinations")).isEqualTo(6L);
            assertThat(audit.get("processId")).isEqualTo(8100L);
            assertThat((List<?>) audit.get("destinations")).hasSize(6);
            assertThat(String.valueOf(audit.get("message")))
                    .contains("PROCESS_NETWORK_BURST detected")
                    .contains("curl (pid 8100)")
                    .contains("6 external connections");
        }
    }

    /* ================================================================ R009 */

    @Nested
    @DisplayName("R009 NETWORK_CONNECTION_BURST - entity-wide fan-out")
    class NetworkConnectionBurst {

        private DetectionTestHarness harness() {
            return DetectionTestHarness.with(new NetworkConnectionBurstRule());
        }

        private Event connections(DetectionTestHarness h, String entity, int count, int distinctDestinations) {
            Event last = null;
            for (int i = 0; i < count; i++) {
                Map<String, Object> p = new HashMap<>();
                p.put("remoteAddress", "198.51.100." + (i % distinctDestinations));
                p.put("remotePort", 1000 + i);
                last = h.store(entity, "NETWORK_CONNECTION", NOW.minusSeconds(count - i), p);
            }
            return last;
        }

        @Test
        @DisplayName("high volume to FEW destinations is ordinary traffic, not a burst")
        void volumeAloneDoesNotFire() {
            DetectionTestHarness h = harness();
            Event last = connections(h, "HOST-CHATTY", 60, 2);
            assertThat(outcomeOf(h.evaluate(last), NetworkConnectionBurstRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("wide fan-out below the volume bar does not fire either")
        void fanOutAloneDoesNotFire() {
            DetectionTestHarness h = harness();
            Event last = connections(h, "HOST-FEW", 15, 15);
            assertThat(outcomeOf(h.evaluate(last), NetworkConnectionBurstRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("volume AND fan-out together: alert")
        void bothConditionsFire() {
            DetectionTestHarness h = harness();
            Event last = connections(h, "HOST-SCAN", 25, 15);
            var results = h.evaluate(last);
            assertThat(outcomeOf(results, NetworkConnectionBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, NetworkConnectionBurstRule.ID)).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("loopback connections never count towards the burst")
        void loopbackNeverCounts() {
            DetectionTestHarness h = harness();
            for (int i = 0; i < 40; i++) {
                Map<String, Object> p = new HashMap<>();
                p.put("remoteAddress", "127.0.0.1");
                h.store("HOST-LB", "NETWORK_CONNECTION", NOW.minusSeconds(40 - i), p);
            }
            Map<String, Object> external = new HashMap<>();
            external.put("remoteAddress", EXTERNAL);
            Event last = h.store("HOST-LB", "NETWORK_CONNECTION", NOW, external);

            assertThat(outcomeOf(h.evaluate(last), NetworkConnectionBurstRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("the evidence states what 'external' means here, so it is not overstated")
        void evidenceStatesTheDefinition() {
            DetectionTestHarness h = harness();
            h.evaluate(connections(h, "HOST-EV", 25, 15));

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat(audit.get("count")).isEqualTo(25L);
            assertThat(audit.get("distinctDestinations")).isEqualTo(15L);
            assertThat(audit.get("distinctRemotePorts")).isEqualTo(25L);
            assertThat(String.valueOf(audit.get("externalMeans")))
                    .contains("non-loopback")
                    .contains("no routing information");
        }

        @Test
        @DisplayName("the distinct-destination bar is configurable")
        void fanOutThresholdIsConfigurable() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getNetworkConnectionBurst().setDistinctDestinationThreshold(2);
            DetectionTestHarness h = DetectionTestHarness.with(props, new NetworkConnectionBurstRule());

            assertThat(outcomeOf(h.evaluate(connections(h, "HOST-T", 25, 2)), NetworkConnectionBurstRule.ID))
                    .isEqualTo(DetectionOutcome.DETECTED);
        }
    }

    /* ================================================================ R007 */

    @Nested
    @DisplayName("R007 PRIVILEGE_ESCALATION_CHAIN - schema-driven, inference stated")
    class PrivilegeEscalationChain {

        private DetectionTestHarness harness() {
            return DetectionTestHarness.with(new PrivilegeEscalationChainRule());
        }

        @Test
        @DisplayName("process start, sudo command, then egress: alert")
        void firesOnTheOrderedChain() {
            DetectionTestHarness h = harness();
            h.store("HOST-P", "PROCESS_START", NOW.minusMinutes(3), processStart(4242, "bash"));
            h.store("HOST-P", "FILE_ACCESS", NOW.minusMinutes(2), fileAccess("/etc/shadow", "sudo cat"));
            Map<String, Object> conn = new HashMap<>();
            conn.put("remoteAddress", EXTERNAL);
            Event egress = h.store("HOST-P", "NETWORK_CONNECTION", NOW, conn);

            var results = h.evaluate(egress);
            assertThat(outcomeOf(results, PrivilegeEscalationChainRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(severityOf(results, PrivilegeEscalationChainRule.ID)).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("without a privilege signal there is no chain")
        void noPrivilegeSignal() {
            DetectionTestHarness h = harness();
            h.store("HOST-P", "PROCESS_START", NOW.minusMinutes(3), processStart(4242, "bash"));
            h.store("HOST-P", "FILE_ACCESS", NOW.minusMinutes(2), fileAccess("/docs/readme.md", "read"));
            Map<String, Object> conn = new HashMap<>();
            conn.put("remoteAddress", EXTERNAL);
            Event egress = h.store("HOST-P", "NETWORK_CONNECTION", NOW, conn);

            assertThat(outcomeOf(h.evaluate(egress), PrivilegeEscalationChainRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("ORDER matters: elevation before the process start is not a chain")
        void orderMatters() {
            DetectionTestHarness h = harness();
            h.store("HOST-O", "FILE_ACCESS", NOW.minusMinutes(5), fileAccess("/etc/shadow", "sudo cat"));
            h.store("HOST-O", "PROCESS_START", NOW.minusMinutes(2), processStart(4242, "bash"));
            Map<String, Object> conn = new HashMap<>();
            conn.put("remoteAddress", EXTERNAL);
            Event egress = h.store("HOST-O", "NETWORK_CONNECTION", NOW, conn);

            // The only PROCESS_START is AFTER the elevation, so stage 1 is missing.
            assertThat(outcomeOf(h.evaluate(egress), PrivilegeEscalationChainRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("a privileged binary counts as the elevation stage")
        void privilegedProcessCounts() {
            DetectionTestHarness h = harness();
            h.store("HOST-B", "PROCESS_START", NOW.minusMinutes(3), processStart(4242, "bash"));
            h.store("HOST-B", "PROCESS_START", NOW.minusMinutes(2), processStart(4243, "sudo"));
            Map<String, Object> conn = new HashMap<>();
            conn.put("remoteAddress", EXTERNAL);
            Event egress = h.store("HOST-B", "NETWORK_CONNECTION", NOW, conn);

            assertThat(outcomeOf(h.evaluate(egress), PrivilegeEscalationChainRule.ID))
                    .isEqualTo(DetectionOutcome.DETECTED);
        }

        @Test
        @DisplayName("privilege tokens match on word boundaries, not substrings")
        void wordBoundaryMatching() {
            DetectionTestHarness h = harness();
            h.store("HOST-W", "PROCESS_START", NOW.minusMinutes(3), processStart(4242, "bash"));
            // "pseudonym" and "sudoku" contain "sudo" but are not privilege elevation.
            h.store("HOST-W", "FILE_ACCESS", NOW.minusMinutes(2), fileAccess("/docs/pseudonymisation.md", "read pseudonym sudoku"));
            Map<String, Object> conn = new HashMap<>();
            conn.put("remoteAddress", EXTERNAL);
            Event egress = h.store("HOST-W", "NETWORK_CONNECTION", NOW, conn);

            assertThat(outcomeOf(h.evaluate(egress), PrivilegeEscalationChainRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }

        @Test
        @DisplayName("the alert states that privilege was INFERRED, never claiming a privilege-change event")
        void evidenceStatesTheInference() {
            DetectionTestHarness h = harness();
            h.store("HOST-EV", "PROCESS_START", NOW.minusMinutes(3), processStart(4242, "bash"));
            h.store("HOST-EV", "FILE_ACCESS", NOW.minusMinutes(2), fileAccess("/etc/shadow", "sudo exec download"));
            Map<String, Object> conn = new HashMap<>();
            conn.put("remoteAddress", EXTERNAL);
            Event egress = h.store("HOST-EV", "NETWORK_CONNECTION", NOW, conn);

            h.evaluate(egress);

            Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
            assertThat(audit.get("privilegeInferred")).isEqualTo(true);
            assertThat(audit.get("privilegeSignal")).isEqualTo("sudo exec download");
            assertThat(audit.get("privilegeSignalSource")).isEqualTo("FILE_ACCESS.commandSequence");
            assertThat(String.valueOf(audit.get("severityReason")))
                    .contains("no privilege-change event")
                    .contains("inferred rather than confirmed");
            assertThat((List<?>) audit.get("contributingSignals")).hasSize(3);
            assertThat(String.valueOf(audit.get("message"))).contains("PRIVILEGE_ESCALATION_CHAIN detected");
        }

        @Test
        @DisplayName("one PROCESS_START cannot be both stage 1 and stage 2")
        void oneEventCannotBeTwoStages() {
            DetectionTestHarness h = harness();
            // The ONLY process start is itself the privileged binary.
            h.store("HOST-1", "PROCESS_START", NOW.minusMinutes(2), processStart(4243, "sudo"));
            Map<String, Object> conn = new HashMap<>();
            conn.put("remoteAddress", EXTERNAL);
            Event egress = h.store("HOST-1", "NETWORK_CONNECTION", NOW, conn);

            assertThat(outcomeOf(h.evaluate(egress), PrivilegeEscalationChainRule.ID))
                    .isEqualTo(DetectionOutcome.INSUFFICIENT_EVIDENCE);
        }
    }

    /* ================================================================ cooldown */

    @Nested
    @DisplayName("Cooldown suppression after an alert closes")
    class Cooldown {


        @Test
        @DisplayName("a rule with a cooldown does not immediately re-alert after its alert closes")
        void cooldownSuppressesAfterClose() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getNetworkConnectionBurst().setCooldown(Duration.ofMinutes(5));
            DetectionTestHarness h = DetectionTestHarness.with(props, new NetworkConnectionBurstRule());

            Event first = null;
            for (int i = 0; i < 25; i++) {
                Map<String, Object> p = new HashMap<>();
                p.put("remoteAddress", "198.51.100." + (i % 15));
                first = h.store("HOST-CD", "NETWORK_CONNECTION", NOW.minusSeconds(30 - i % 30), p);
            }
            h.evaluate(first);
            assertThat(h.alertsFor(NetworkConnectionBurstRule.ID)).hasSize(1);

            // The alert is resolved a moment later.
            Alert alert = h.alertsFor(NetworkConnectionBurstRule.ID).get(0);
            alert.setStatus(AlertStatus.RESOLVED);
            alert.setResolvedAt(NOW);

            // The same activity continues inside the cooldown.
            Event again = null;
            for (int i = 0; i < 25; i++) {
                Map<String, Object> p = new HashMap<>();
                p.put("remoteAddress", "198.51.100." + (i % 15));
                again = h.store("HOST-CD", "NETWORK_CONNECTION", NOW.plusSeconds(i + 1L), p);
            }

            assertThat(outcomeOf(h.evaluate(again), NetworkConnectionBurstRule.ID))
                    .isEqualTo(DetectionOutcome.SUPPRESSED_COOLDOWN);
            assertThat(h.alertsFor(NetworkConnectionBurstRule.ID)).hasSize(1);
            assertThat(String.valueOf(h.lastAudit(DetectionEngine.AUDIT_DETECTION_SUPPRESSED).get("suppressionReason")))
                    .contains("inside its configured cooldown");
        }

        @Test
        @DisplayName("past the cooldown, the same activity alerts again")
        void cooldownExpires() {
            DetectionProperties props = DetectionProperties.defaults();
            props.getRules().getNetworkConnectionBurst().setCooldown(Duration.ofMinutes(5));
            DetectionTestHarness h = DetectionTestHarness.with(props, new NetworkConnectionBurstRule());

            Event first = null;
            for (int i = 0; i < 25; i++) {
                Map<String, Object> p = new HashMap<>();
                p.put("remoteAddress", "198.51.100." + (i % 15));
                first = h.store("HOST-CE", "NETWORK_CONNECTION", NOW.minusSeconds(30 - i % 30), p);
            }
            h.evaluate(first);

            Alert alert = h.alertsFor(NetworkConnectionBurstRule.ID).get(0);
            alert.setStatus(AlertStatus.RESOLVED);
            alert.setResolvedAt(NOW);

            // An hour later the cooldown is long over.
            OffsetDateTime later = NOW.plusHours(1);
            Event again = null;
            for (int i = 0; i < 25; i++) {
                Map<String, Object> p = new HashMap<>();
                p.put("remoteAddress", "198.51.100." + (i % 15));
                again = h.store("HOST-CE", "NETWORK_CONNECTION", later.minusSeconds(30 - i % 30), p);
            }

            assertThat(outcomeOf(h.evaluate(again), NetworkConnectionBurstRule.ID)).isEqualTo(DetectionOutcome.DETECTED);
            assertThat(h.alertsFor(NetworkConnectionBurstRule.ID)).hasSize(2);
        }
    }
}
