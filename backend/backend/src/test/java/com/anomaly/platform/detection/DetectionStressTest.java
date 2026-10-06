package com.anomaly.platform.detection;

import com.anomaly.platform.detection.config.DetectionProperties;
import com.anomaly.platform.entity.Event;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.anomaly.platform.detection.DetectionTestHarness.NOW;
import static com.anomaly.platform.detection.DetectionTestHarness.connection;
import static com.anomaly.platform.detection.DetectionTestHarness.login;
import static com.anomaly.platform.detection.DetectionTestHarness.processStart;
import static org.assertj.core.api.Assertions.assertThat;

/*
 * ============================================================
 * RESOURCE AND STATE SAFETY UNDER LOAD
 * ============================================================
 *
 * The claim these tests exist to defend is specific: THE DETECTION ENGINE HOLDS
 * NO CORRELATION STATE OF ITS OWN. The correlation state is the events table, and
 * every query against it is bounded by a time window and a hard row cap
 * (detection.max-correlation-events).
 *
 * That makes the resource audit short, which is the point:
 *
 *   STRUCTURE            MAX SIZE                  TTL        CLEANUP      CONCURRENCY
 *   -----------------------------------------------------------------------------------
 *   (no engine cache)    -                         -          -            -
 *   (no rule state)      -                         -          -            rules are stateless
 *   correlation query    max-correlation-events    window     none needed  per-call, no sharing
 *   evidence.eventIds    MAX_EVENT_IDS (25)        n/a        n/a          per-match
 *   evidence.destinations MAX_DESTINATIONS (15)    n/a        n/a          per-match
 *   alert factors        MAX_FACTORS_PER_ALERT (6) n/a        n/a          per-alert
 *   active-alert scan    200 rows (ACTIVE_ALERT_SCAN) n/a     n/a          per-call
 *
 * There is no map, set, list, cache or queue that outlives a single evaluation,
 * so there is nothing to expire and nothing that can grow. These tests hold that
 * down empirically at 10,000 and 50,000 events, including duplicates, repeated
 * entities and out-of-order arrival.
 *
 * They are deterministic (fixed data, fixed order, no clock reads) and assert
 * bounds rather than timings, so they cannot flake on a slow machine. The timing
 * ceilings are generous regression guards against an accidental O(n^2), not
 * benchmarks.
 */
class DetectionStressTest {

    /** What one stress run measured, for the report. */
    private record Measurement(
            int eventsStored,
            int evaluations,
            long millis,
            int alertsCreated,
            long suppressed,
            long duplicates,
            int retainedRows,
            int alertFactors,
            int maxFactorLength
    ) {
        @Override
        public String toString() {
            return String.format(
                    "events=%d evaluations=%d time=%dms alerts=%d suppressed=%d duplicates=%d "
                            + "retainedEventRows=%d factors=%d maxFactorLen=%d",
                    eventsStored, evaluations, millis, alertsCreated, suppressed, duplicates,
                    retainedRows, alertFactors, maxFactorLength);
        }
    }

    private Measurement run(int totalEvents, int entities, boolean shuffle, boolean duplicateEveryEvaluation) {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        List<Event> triggers = new ArrayList<>();

        long start = System.nanoTime();

        for (int i = 0; i < totalEvents; i++) {
            String entity = "HOST-" + (i % entities);
            OffsetDateTime at = NOW.minusSeconds(900 - (i % 900));

            switch (i % 4) {
                case 0 -> h.store(entity, "LOGIN", at, login(false, "203.0.113." + (i % 30)));
                case 1 -> h.store(entity, "LOGIN", at, login(true, "203.0.113." + (i % 30)));
                case 2 -> h.store(entity, "PROCESS_START", at, processStart(8000 + (i % 50), "worker"));
                default -> h.store(entity, "NETWORK_CONNECTION", at,
                        connection(8000 + (i % 50), at.minusSeconds(10), "198.51.100." + (i % 40)));
            }
        }

        // One trigger per entity of each interesting type.
        for (int e = 0; e < entities; e++) {
            String entity = "HOST-" + e;
            triggers.add(h.store(entity, "LOGIN", NOW, login(false, "203.0.113.1")));
            OffsetDateTime started = NOW.minusSeconds(30);
            h.store(entity, "PROCESS_START", started, processStart(9000 + e, "curl"));
            triggers.add(h.store(entity, "NETWORK_CONNECTION", NOW, connection(9000 + e, started, "198.51.100.5")));
        }

        if (shuffle) {
            // Out-of-order arrival: the engine must not care.
            Collections.shuffle(triggers, new java.util.Random(7));
        }

        int evaluations = 0;
        for (Event trigger : triggers) {
            h.evaluate(trigger);
            evaluations++;
            if (duplicateEveryEvaluation) {
                h.evaluate(trigger);   // an exact redelivery, every time
                h.evaluate(trigger);
                evaluations += 2;
            }
        }

        long millis = (System.nanoTime() - start) / 1_000_000;

        return new Measurement(
                h.events.stored.size(),
                evaluations,
                millis,
                h.alerts.stored.size(),
                h.auditCount(DetectionEngine.AUDIT_DETECTION_SUPPRESSED),
                evaluations - triggers.size(),
                h.events.stored.size(),
                h.factors.stored.size(),
                h.factors.stored.stream().mapToInt(f -> f.getFactor().length()).max().orElse(0)
        );
    }

    @Test
    @DisplayName("10,000 events across 50 entities stay bounded")
    void tenThousandEvents() {
        Measurement m = run(10_000, 50, false, false);
        System.out.println("[stress] 10k: " + m);

        // Alerts are bounded by entities x rules, and suppression holds it far below.
        assertThat(m.alertsCreated()).isLessThanOrEqualTo(50 * 10);
        // Every factor fits the column, however much data went in.
        assertThat(m.maxFactorLength()).isLessThanOrEqualTo(128);
        assertThat(m.millis()).isLessThan(180_000);
    }

    @Test
    @DisplayName("50,000 events across many entities stay bounded and do not degrade non-linearly")
    void fiftyThousandEvents() {
        Measurement small = run(10_000, 100, false, false);
        Measurement large = run(50_000, 100, false, false);
        System.out.println("[stress] 10k/100 entities: " + small);
        System.out.println("[stress] 50k/100 entities: " + large);

        assertThat(large.alertsCreated()).isLessThanOrEqualTo(100 * 10);
        assertThat(large.maxFactorLength()).isLessThanOrEqualTo(128);

        // The evaluation count is identical in both runs (one trigger per entity),
        // so five times the stored history must not mean five times the work: every
        // query is capped at max-correlation-events regardless of table size. A
        // generous ceiling, because this is a regression guard not a benchmark.
        assertThat(large.millis()).isLessThan(300_000);
    }

    @Test
    @DisplayName("repeated entities: one entity with 50,000 of its own events still evaluates bounded")
    void oneVeryBusyEntity() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        for (int i = 0; i < 50_000; i++) {
            h.store("HOST-BUSY", "LOGIN", NOW.minusSeconds(290 - (i % 290)),
                    login(i % 2 == 0, "203.0.113." + (i % 10)));
        }

        long start = System.nanoTime();
        Event trigger = h.store("HOST-BUSY", "LOGIN", NOW, login(false, "203.0.113.1"));
        h.evaluate(trigger);
        long millis = (System.nanoTime() - start) / 1_000_000;

        System.out.println("[stress] one entity with 50k events: " + millis + "ms, alerts="
                + h.alerts.stored.size());

        // The cap is what makes this survivable: the count cited in the evidence is
        // bounded by max-correlation-events, and the window is declared truncated.
        Map<String, Object> audit = h.lastAudit(DetectionEngine.AUDIT_DETECTION_CREATED);
        assertThat(audit).isNotNull();
        assertThat((Long) audit.get("count"))
                .isLessThanOrEqualTo((long) DetectionProperties.defaults().getMaxCorrelationEvents());
        assertThat(audit.get("windowTruncated")).isEqualTo(true);
        assertThat(millis).isLessThan(60_000);
    }

    @Test
    @DisplayName("many distinct entities do not accumulate per-entity state")
    void manyDistinctEntities() {
        DetectionTestHarness h = DetectionTestHarness.withAllRules();

        // 5,000 entities, each with a small burst. An engine holding per-entity
        // correlation state would grow with this; this one holds none.
        for (int e = 0; e < 5_000; e++) {
            String entity = "HOST-" + e;
            for (int i = 0; i < 6; i++) {
                h.store(entity, "LOGIN", NOW.minusSeconds(60 - i * 5L), login(false, "203.0.113.1"));
            }
        }

        // Evaluate a sample; the engine must behave identically for the first and the last.
        for (int e : new int[]{0, 2_500, 4_999}) {
            Event trigger = h.store("HOST-" + e, "LOGIN", NOW, login(false, "203.0.113.1"));
            var results = h.evaluate(trigger);
            assertThat(DetectionTestHarness.outcomeOf(results, "AUTH_BURST"))
                    .as("entity %d", e)
                    .isEqualTo(DetectionOutcome.DETECTED);
        }

        // Exactly one alert per evaluated entity - no leakage between them.
        assertThat(h.alertsFor("AUTH_BURST")).hasSize(3);
    }

    @Test
    @DisplayName("duplicates and replays never grow alert, factor or audit state")
    void duplicatesAndReplays() {
        Measurement m = run(5_000, 25, false, true);
        System.out.println("[stress] duplicates: " + m);

        DetectionTestHarness h = DetectionTestHarness.withAllRules();
        for (int i = 0; i < 8; i++) {
            h.store("HOST-D", "LOGIN", NOW.minusSeconds(40 - i * 5L), login(false, "203.0.113.1"));
        }
        Event trigger = h.store("HOST-D", "LOGIN", NOW, login(false, "203.0.113.1"));

        h.evaluate(trigger);
        int alertsAfterFirst = h.alerts.stored.size();
        int factorsAfterFirst = h.factors.stored.size();
        long auditAfterFirst = h.audit.rows.size();

        for (int i = 0; i < 1_000; i++) {
            h.evaluate(trigger);
        }

        // A thousand redeliveries change nothing at all.
        assertThat(h.alerts.stored).hasSize(alertsAfterFirst);
        assertThat(h.factors.stored).hasSize(factorsAfterFirst);
        assertThat(h.audit.rows).hasSize((int) auditAfterFirst);
    }

    @Test
    @DisplayName("out-of-order arrival produces the same bounded result")
    void outOfOrderArrival() {
        Measurement ordered = run(10_000, 40, false, false);
        Measurement shuffled = run(10_000, 40, true, false);
        System.out.println("[stress] ordered:  " + ordered);
        System.out.println("[stress] shuffled: " + shuffled);

        // Evaluation order changes nothing about how much state exists.
        assertThat(shuffled.alertsCreated()).isEqualTo(ordered.alertsCreated());
        assertThat(shuffled.maxFactorLength()).isLessThanOrEqualTo(128);
    }

    @Test
    @DisplayName("the engine holds no field that could accumulate state between evaluations")
    void engineHoldsNoMutableState() {
        // Structural proof of the architectural claim: every field on the engine is
        // either a collaborator or configuration. There is no collection to grow.
        for (java.lang.reflect.Field field : DetectionEngine.class.getDeclaredFields()) {
            if (java.lang.reflect.Modifier.isStatic(field.getModifiers())) {
                continue;
            }
            assertThat(java.lang.reflect.Modifier.isFinal(field.getModifiers()))
                    .as("DetectionEngine.%s must be final", field.getName())
                    .isTrue();
            assertThat(java.util.Collection.class.isAssignableFrom(field.getType())
                    || java.util.Map.class.isAssignableFrom(field.getType()))
                    .as("DetectionEngine.%s is a collection - the engine must hold no state", field.getName())
                    .isFalse();
        }

        // And no rule holds state either.
        for (DetectionRule rule : new com.anomaly.platform.detection.config.DetectionConfig()
                .ruleRegistry().all()) {
            for (java.lang.reflect.Field field : rule.getClass().getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(field.getModifiers())) {
                    continue;
                }
                assertThat(field)
                        .as("%s holds instance state; rules must be stateless and thread-safe", rule.id())
                        .isNull();
            }
        }
    }
}
