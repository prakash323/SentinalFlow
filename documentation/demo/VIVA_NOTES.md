# SentinelFlow — Viva / Architecture Notes

Concise, source-grounded answers to likely review questions.

## 1. Why Kafka?

The event bus decouples every telemetry producer from the detection pipeline's own pace and availability. Three different producers (Python simulator, physical collector, in-console simulator) can publish without knowing anything about Spring Boot's processing state, and `KafkaErrorHandlingConfig`'s retry + dead-letter-topic (`raw.events.v1.DLT`) handling means a transient processing failure retries automatically before falling back to a durable, inspectable dead-letter record — instead of a failure silently dropping the event.

## 2. Why PostgreSQL?

Strong relational integrity (foreign keys between entities/events/predictions/alerts/incidents/alert-factors), `jsonb` columns where the schema is genuinely variable (event `payload`, prediction `features`, audit-log `details`), and native `CHECK` constraints bounding score columns to `[0,1]` at the database level, not just in application code. Flyway-managed migrations (`V1`–`V14`) give an exact, auditable schema history.

## 3. Why Spring Boot?

Mature, well-integrated stack for exactly what this project needs simultaneously: a REST API, a Kafka consumer/producer, JPA persistence, Spring Security, and Spring AI, all in one dependency-injected application — no separate framework needed for any of those five concerns.

## 4. Why ML?

Rule-based thresholds alone cannot capture genuinely novel, behaviorally-anomalous activity — the ML ensemble (`ml-service/anomaly-detection`, baseline + isolation forest + sequence autoencoder) learns per-entity behavioral baselines and can flag activity that looks statistically unusual even when it does not match any hand-written rule.

## 5. Why deterministic rules in addition to ML?

Because an ML service is an external, independently-deployed process that can be unreachable, slow, or wrong — and before `DeterministicRuleService` existed, an ML outage meant **zero** detection capability, regardless of how obviously suspicious the raw telemetry was. The rule engine is a small, explicit, ML-free backstop (`AUTH_BURST`, `NEW_PROCESS_EXTERNAL_CONNECTION`) verified live to keep firing independent of ML availability. It is deliberately not a general rules framework or DSL — two rules, directly evidenced by real ingested data, kept simple by design.

## 6. Why Spring AI?

To turn already-computed evidence (scores, decisions, ranked factors, rule evidence) into plain-English text a human analyst can act on faster — not to add a second detection mechanism. It is structurally incapable of mutating state (no repository/service dependency in its constructors — see `../ai/spring-ai.md` §3, §8), which matters because an LLM's output should never be trusted as an authoritative system action.

## 7. Why a separate physical collector?

To demonstrate the platform against *genuinely observed* telemetry, not only synthetic data — real login sessions, real process starts, and real network connections from an actual Windows host, gathered via the same non-admin `psutil` mechanisms any endpoint-monitoring tool would use, explicitly avoiding the Windows Security Event Log to sidestep an elevated audit-policy requirement out of scope for this project.

## 8. Why idempotency?

Because Kafka's own delivery semantics do not guarantee exactly-once processing on the consumer side, and a REST-originated event is deliberately persisted before it is even published to Kafka (so its `201 Created` response is real) — meaning the same logical event can legitimately be seen twice by the pipeline. `EventProcessingLedgerService.persistOrLoad` (keyed on `eventId`), `PredictionService.create`'s existing-prediction check (keyed on `event_id, model_name, model_version`), and `DeterministicRuleService`'s `existsByEvent_IdAndRuleId` check all exist specifically so a duplicate delivery never creates a duplicate row or a duplicate alert.

## 9. Why retry / dead-letter?

Before this existed, `EventKafkaConsumer` caught every exception itself, which meant Spring Kafka's container never saw a failure — no retry ever happened, and the Kafka offset committed as if the record had processed successfully. A transient DB hiccup would silently and permanently drop that event from detection. `KafkaErrorHandlingConfig` now retries transient failures (2 retries, 1s backoff) and, once exhausted (or immediately for a known-non-retryable error like bad JSON), publishes the original record to `raw.events.v1.DLT` instead — the failure becomes a durable, inspectable fact instead of a silent loss.

## 10. Why Flyway?

An exact, version-controlled, sequentially-numbered record of every schema change (`V1__create_entities.sql` through `V14__add_optimistic_locking.sql`), each with an inline comment explaining *why* the change was made — combined with `hibernate.ddl-auto: validate`, so Hibernate can never silently drift the schema out from under Flyway's own record of it.

## 11. How does alert → incident work?

`IncidentService.findOrCreateIncident` keys an incident on `entityId:eventType`. An active (`OPEN`/`INVESTIGATING`) incident under that key absorbs the new alert; once that incident is resolved/closed, a new alert opens (or joins) a timestamp-suffixed follow-up incident under the same base key, so a later, genuinely new burst of activity does not silently reopen an already-closed investigation. See `../architecture/detection-engine.md` §F.

## 12. How does correlation work?

Two layers exist, and they answer different questions. **Incident correlation** (backend, persisted) groups *alerts* by entity + event type — a security triage grouping. **Related-activity correlation** (frontend, `utils/relatedActivity.ts`, computed at read time, never persisted) links individual *events* by two exact-match rules: `PROCESS_START ↔ NETWORK_CONNECTION` via `(pid, processCreateTime)`, and `LOGIN ↔ PROCESS_START` via matching username within a session's time window. The second is explicitly a presentation-layer convenience, not a second source of truth — see `../telemetry/physical-telemetry.md` §9 for its one known real-data limitation (username format mismatch between LOGIN and PROCESS_START on this platform).

## 13. How is security implemented?

HTTP Basic auth over a stateless filter chain, two in-memory roles (`ADMIN`, `ANALYST`), BCrypt-hashed passwords, least-privilege endpoint tiers (public / analyst-or-admin / admin-only), and a dedicated `RestSecurityErrorHandler` so 401/403 responses use the same structured JSON shape as every other API error. `POST /api/v1/events` is the one deliberate exception to "everything requires auth" — see `../security/security-design.md` §8 for why, and what it would take to close that gap in a real deployment.

## 14. How does the system handle ML failure?

`MlPredictionClient.predict` has no try/catch of its own — any failure propagates unchanged to `EventProcessingService`, which records it via `EventProcessingLedgerService.markFailed` (the event becomes durably `FAILED` with the real error message) and rethrows so Kafka's retry/dead-letter handling can act on it. Crucially, the deterministic rule path already ran earlier in the same call and is completely unaffected — an ML outage degrades detection coverage, it does not eliminate it.

## 15. What happens when Kafka is unavailable?

For the REST path, verified from source (`EventKafkaProducer.java`) rather than assumed: `publish()` defers the actual send until **after** the enclosing database transaction commits (`TransactionSynchronization.afterCommit`) — specifically so Kafka can never deliver the message before PostgreSQL has the `Event` row, which would otherwise make the consumer try to insert it again. The send itself, `kafkaTemplate.send(...).whenComplete(...)`, is asynchronous: a broker-connectivity failure is only logged (`log.error(...)`) inside the `whenComplete` callback, not thrown back to the caller. Net effect: if Kafka is down, `POST /api/v1/events` still returns `201 Created` and the event is durably persisted (`processingStatus` stays `PENDING`), but it is never actually published to Kafka, so it is **never picked up by the detection pipeline** until Kafka recovers and the event is manually replayed (`POST /api/v1/replay-runs`) — a silent-looking `PENDING` event, not an HTTP-visible error. The direct-Kafka path (physical collector) fails differently: `kafka-python`'s own producer has `retries=5`; a sustained outage surfaces as a Python-side `KafkaError` raised from `EventPublisher.publish`, logged and propagated by the collector itself.

## 16. What are the physical telemetry limitations?

See `../telemetry/physical-telemetry.md` §13 in full: hostname collisions across machines, no geo-IP enrichment, network-connection identity cannot distinguish a truly new connection from an exact repeat of a since-closed one, and — most significantly for a demo — `LOGIN`↔`PROCESS_START` username correlation does not currently match on this project's real Windows data because of a bare-username vs. domain-qualified-username format mismatch, which was deliberately left unnormalized rather than inventing an undocumented rule.

## 17. What are the ML limitations?

The model's `anomalyScore` is a percentile rank against its own training distribution, not a calibrated probability, and runs "hot" by nature — normal events commonly land at 0.95–0.99. The alert-policy thresholds are tuned to track this calibration but are explicitly documented (in `application.yml`'s own comment) as a starting point, not a final, re-tuned-against-real-traffic value. Additionally, ML-3 through ML-5 are evaluation-only work — no candidate from those phases is deployed; the only model the live system ever uses is `models/pipeline.joblib`. See `../ml/ml-integration.md` §10–11.

## 18. What would you improve in production?

Candidates, in the spirit of "future work, not currently implemented" (see `FUTURE-ROADMAP.md`): close the public `POST /api/v1/events` gap with a producer-level credential; add a proper secrets manager instead of environment variables; add TLS termination in front of the API; normalize the LOGIN/PROCESS_START username-format mismatch (with an explicit, documented rule, once a real need justifies it); move the large ML evaluation artifacts to Git LFS or external artifact storage before the project's first commit; and add CI so the 190+97 automated tests run on every change rather than only on demand.
