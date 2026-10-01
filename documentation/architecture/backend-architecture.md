# SentinelFlow — Backend Architecture

Spring Boot 3.3, Java 21. Root package: `com.anomaly.platform` (under `backend/backend/src/main/java/com/anomaly/platform/`).

## 1. Package structure (as it exists in source)

```
com.anomaly.platform/
├── AnomalyPlatformApplication.java     entry point
├── ai/          Spring AI analyst-assistance layer (no state-mutation dependency)
├── config/      SecurityConfig, AppConfig, AlertPolicyProperties, KafkaErrorHandlingConfig,
│                CorrelationIdFilter, SecurityUsersProperties
├── controller/  REST controllers (one per resource, plus two AI controllers)
├── dto/         Request/response records
├── entity/      JPA entities + enums
├── exception/   Custom exceptions + GlobalExceptionHandler
├── kafka/       KafkaEvent, KafkaTopics, EventKafkaProducer, EventKafkaConsumer
├── ml/          MlPredictionClient, MlClientConfig, request/response records, MlServiceProperties
├── repository/  Spring Data JPA repositories
├── security/    CurrentActor, RestSecurityErrorHandler
└── service/     Business logic (event processing, rules, alerts, incidents, entities, audit, dashboard, replay, system status)
```

## 2. Controllers

Each controller is a thin adapter over exactly one service; no controller contains business logic. See `../api/api-reference.md` for the full endpoint list. Two controllers are dedicated to Spring AI (`AlertAiController`, `IncidentAiController`) and are deliberately separate from `AlertController`/`IncidentController` — nothing that can mutate an alert or incident is reachable from an AI controller.

## 3. Services

| Service | Responsibility |
|---|---|
| `EventService` | `POST/GET /events`, event listing/filtering, event processing "trail" (prediction + alert for one event); persists the event and publishes it to Kafka |
| `EventProcessingService` | The core pipeline entry point invoked by the Kafka consumer: persist-or-load → deterministic rules → ML call → prediction/alert creation. Deliberately **not** `@Transactional` at this level (see its own doc comment) |
| `EventProcessingLedgerService` | Owns the durable "was this event received / processed / failed" facts, each in its own transaction, independent of whether detection itself succeeds |
| `DeterministicRuleService` | Independent, ML-free detection: `AUTH_BURST`, `NEW_PROCESS_EXTERNAL_CONNECTION` |
| `PredictionService` | Persists ML predictions (idempotent on event+model+version), applies the alert-policy threshold, creates alerts + alert factors for the ML path |
| `AlertService` | Alert listing/filtering, single-alert reads, status-transition validation, `saveAndFlush` for optimistic-lock detection |
| `IncidentService` | Incident correlation (`findOrCreateIncident`), listing/filtering (including a source-aware EXISTS subquery), status transitions, and alert/incident status synchronization |
| `EntityService` | Entity CRUD (create is ADMIN-only) and per-entity rollups (event/alert counts, max score, latest prediction) |
| `AuditLogService` | Appends immutable audit records; read via `AuditLogController` (ADMIN only) |
| `DashboardService` | Aggregates counts, trends, severity/status/type/source breakdowns, and top-risk entities for the dashboard |
| `SystemStatusService` | Live dependency probes (DB, Kafka, ML) for `GET /system/status` |
| `ReplayRunService` | Bulk reprocessing of stored events (ADMIN only) |

## 4. Entities, enums, DTOs

See `../database/database-design.md` for the full schema. DTOs are plain Java records (`dto/` package); every response DTO has a single, explicit mapping method inside its owning service (e.g. `AlertService.to(Alert)`), so list/detail/dashboard views can never disagree about field shape.

## 5. Configuration

- `config/SecurityConfig` — HTTP Basic, stateless session, CORS, endpoint tiering (see `../security/security-design.md`).
- `config/AlertPolicyProperties` — `anomaly.alert-policy.*`: `alert-threshold` and per-severity thresholds (`medium`/`high`/`critical`), bound from `application.yml`.
- `config/KafkaErrorHandlingConfig` — retry (2 retries, 1s backoff) + dead-letter publishing to `raw.events.v1.DLT`; `NotFoundException`/`IllegalArgumentException` skip straight to dead-letter (not retried).
- `config/CorrelationIdFilter` — puts an `X-Correlation-Id` into MDC/response headers for cross-request tracing, echoed in `ErrorResponse.requestId` and the log pattern.
- `config/SecurityUsersProperties` — binds `security.users.admin/analyst` (username/password, BCrypt-encoded at startup).
- `ml/MlClientConfig` / `ml/MlServiceProperties` — builds the `RestClient` bean used by `MlPredictionClient`, bound from `ml.service.url` / timeouts.

## 6. Kafka layer

- `kafka/KafkaTopics` — single source of truth for topic names: `raw.events.v1`, `raw.events.v1.DLT`.
- `kafka/EventKafkaProducer` — publishes a `CreateEventRequest`-shaped event as a JSON string (String key/value serializers), called by `EventService.create` after the REST-originated event is persisted.
- `kafka/EventKafkaConsumer` — `@KafkaListener` on `raw.events.v1`; deserializes into `KafkaEvent` and calls `EventProcessingService.process`. Exceptions are deliberately **not** caught here so `KafkaErrorHandlingConfig`'s retry/DLT machinery can act on them.
- `kafka/KafkaEvent` — the canonical envelope record deserialized from the wire JSON (`eventId`, `entityId`, `eventType`, `eventVersion`, `occurredAt`, `source`, `payload`).

## 7. ML client

`ml/MlPredictionClient` is a thin `RestClient` wrapper around `POST {ml.service.url}/predict`, deliberately with no try/catch of its own — any failure (timeout, connection refused, 503 while the model warms up, 500 internal error) propagates as an unchecked `RestClientException`, which `EventProcessingService` records via the ledger and lets the Kafka retry/DLT handling take over. See `../ml/ml-integration.md` for the full request/response contract.

## 8. AI layer

`ai/AiPromptSupport` holds the shared system prompt, untrusted-field sanitizer, and provider-call wrapper used by both `AlertAiService` and `IncidentAiService`. Neither service has a repository, ML client, or mutation dependency — see `../ai/spring-ai.md` for the full design and prompt-injection protections.

## 9. Security

`config/SecurityConfig` configures HTTP Basic over a stateless filter chain with two in-memory roles (`ADMIN`, `ANALYST`), least-privilege endpoint tiers, and BCrypt password hashing. `security/CurrentActor` reads the authenticated principal's username for audit attribution. `security/RestSecurityErrorHandler` returns a structured `ErrorResponse` (not Spring Security's default HTML/plain-text) for both authentication failures and access-denied cases. See `../security/security-design.md`.

## 10. Exception handling

`exception/GlobalExceptionHandler` is a single `@RestControllerAdvice` mapping every exception type the application actually throws to a specific HTTP status and a structured `ErrorResponse` (`code`, `message`, `details`, `requestId`, `timestamp`) — including `404 NOT_FOUND`, `409 RESOURCE_CONFLICT` / `INVALID_STATUS_TRANSITION` / `DATA_CONFLICT` / `CONCURRENT_MODIFICATION`, `400` validation/parameter/JSON errors, `405 METHOD_NOT_ALLOWED`, `503 AI_PROVIDER_UNAVAILABLE`, and a logged `500 INTERNAL_ERROR` fallback. See `../api/api-reference.md` for the exact codes per endpoint.

## 11. Audit

`AuditLogService.log(actor, action, resourceType, resourceId, correlationId, details)` writes an immutable `audit_logs` row for every alert/incident status change, every deterministic-rule detection (`DETECTION_CREATED`) or suppression (`DETECTION_SUPPRESSED`), every incident creation, and every event-processing failure. Read via `GET /api/v1/audit-logs` (ADMIN only).

## 12. Processing / idempotency

- **Event idempotency**: `EventProcessingLedgerService.persistOrLoad` is keyed on `eventId` (unique DB constraint) — a duplicate Kafka delivery loads the existing row rather than creating a second one.
- **Prediction idempotency**: `PredictionService.create` checks for an existing prediction on `(eventId, modelName, modelVersion)` before creating a new one (`V11__add_prediction_idempotency.sql`'s unique constraint backs this).
- **Rule idempotency**: `AlertRepository.existsByEvent_IdAndRuleId` prevents a rule from firing twice for the same event.
- **Incident race safety**: `IncidentService.findOrCreateIncident` relies on the DB-level unique constraint on `incident_key` plus a `REQUIRES_NEW` inner transaction — a losing concurrent insert re-reads the winner's row rather than failing the whole request.
- **Optimistic locking**: `Alert.version` / `Incident.version` (`@Version`) plus `saveAndFlush` on every status mutation surface a genuine concurrent-modification conflict as `409 CONCURRENT_MODIFICATION` instead of silently losing an update (see `V14__add_optimistic_locking.sql`'s own comment for the confirmed-live bug this fixes).

## 13. Rule engine

`service/DeterministicRuleService` — see `detection-engine.md` for the full per-rule design (`AUTH_BURST`, `NEW_PROCESS_EXTERNAL_CONNECTION`), including trigger conditions, thresholds, severity, evidence, suppression, and audit behavior.

## 14. Event processing lifecycle (summary)

`EventKafkaConsumer.consume` → `EventProcessingService.process`:

1. `validate(event)` — rejects a malformed envelope with `IllegalArgumentException` (non-retryable, routed straight to DLT).
2. `ledger.persistOrLoad(event)` — idempotent persist; on failure, `ledger.recordUnresolvableFailure` logs it (no event row exists yet) and rethrows.
3. `deterministicRuleService.evaluate(databaseEvent)` — unconditional, never throws out of this call.
4. `mlPredictionClient.predict(...)` → `createPrediction(...)` → `ledger.markProcessed(...)`. On any failure in this block, `ledger.markFailed(...)` records the reason and rethrows, letting Kafka's retry/DLT handler take over.

See `event-flow.md` for the full field-level trace and sequence diagram.
