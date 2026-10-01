# SentinelFlow — API Reference

Base path for every endpoint below (unless noted): `/api/v1`. Authentication: HTTP Basic (see `../security/security-design.md`). All request/response bodies are JSON.

Legend for **Auth**: `PUBLIC` = no credentials required · `ANALYST+` = ANALYST or ADMIN · `ADMIN` = ADMIN only.

## Auth

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/auth/me` | ANALYST+ | Returns the caller's identity: `{ username, roles, admin }`. Used by the frontend to validate a login and gate admin-only screens. |

## Health / System

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/health` | PUBLIC | Minimal liveness check: `{ status: "UP", timestamp }`. Deliberately does not check dependencies. |
| GET | `/actuator/health` | PUBLIC | Actuator liveness probe (`livenessState`). |
| GET | `/actuator/health/**` | PUBLIC | Actuator sub-probes. |
| GET | `/actuator/**` (other) | ADMIN | Metrics/info; readiness group includes `db`. |
| GET | `/api/v1/system/status` | ANALYST+ | Live dependency status (DB/Kafka/ML component checks), pipeline counts, and the current alert-policy configuration. |

## Events

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/events` | **PUBLIC** | Create + persist an event, then publish it to Kafka. Body: `CreateEventRequest` (`eventId`, `entityId`, `eventType`, `eventVersion`, `occurredAt`, `source`, `payload` — all required, `@NotBlank`/`@NotNull`). Returns `201` + `EventResponse`. Public because the simulator and physical collector have no auth support (see `../security/security-design.md`). |
| GET | `/api/v1/events` | ANALYST+ | Paged list. Query params: `entityId`, `eventType`, `source` (all optional, AND-combined), `page` (default 0), `size` (default 20, capped to 100). Sorted `occurredAt DESC`. |
| GET | `/api/v1/events/{eventId}` | ANALYST+ | Single event by business `eventId`. `404` if not found. |
| GET | `/api/v1/events/{eventId}/trail` | ANALYST+ | Processing outcome for one event: `processingStatus`, `processingAttempts`, `lastProcessingError`, `processedAt`, plus the resulting `Prediction`/`Alert` if they exist. |

## Predictions

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/predictions` | ANALYST+ | Paged list. Query params: `entityId`, `decision` (`DecisionState`), `page`, `size` (capped to 100). Sorted `createdAt DESC`. |
| GET | `/api/v1/predictions/{id}` | ANALYST+ | Single prediction by UUID. |
| POST | `/api/v1/predictions` | **ADMIN** | Direct/manual prediction insertion — bypasses the real ML pipeline entirely. Idempotent on `(eventId, modelName, modelVersion)`; may create an alert if the policy threshold is crossed. Returns `201`. |

## Alerts

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/alerts` | ANALYST+ | Paged list. Query params: `status` (`AlertStatus`), `severity` (`Severity`), `decision` (`DecisionState`), `entityId`, `source`, `page`, `size` (capped to 100), all AND-combined. Sorted `createdAt DESC`. |
| GET | `/api/v1/alerts/{id}` | ANALYST+ | Single alert by UUID, including ranked `factors`, `ruleId`/`ruleName`/`detectionType` (`"ML"` or `"RULE"`). |
| PATCH | `/api/v1/alerts/{id}/status` | ANALYST+ | Body: `{ "status": "<AlertStatus>" }`. Validated against the allowed-transition graph (see `../architecture/detection-engine.md`); same-status is a no-op (no new audit entry). `409 INVALID_STATUS_TRANSITION` on an illegal move; `409 CONCURRENT_MODIFICATION` on a version conflict. |
| POST | `/api/v1/alerts/{id}/ai/explanation` | ANALYST+ | Generates a plain-English explanation from stored evidence. Optional query param `detail=detailed` for the longer form (default: concise). Read-only — never mutates the alert. `503 AI_PROVIDER_UNAVAILABLE` if the provider fails or is unconfigured. |

## Incidents

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/incidents` | ANALYST+ | Paged list. Query params: `status` (`IncidentStatus`), `entityId`, `source` (matches incidents with at least one alert from that source), `page`, `size` (capped to 100). Sorted `createdAt DESC`. Each row includes a rolled-up `alertCount`, `maxSeverity`, `maxScore`, and `sources`. |
| GET | `/api/v1/incidents/{id}` | ANALYST+ | Single incident with the same rollup fields. |
| GET | `/api/v1/incidents/{id}/alerts` | ANALYST+ | Every alert linked to this incident, newest first. |
| PATCH | `/api/v1/incidents/{id}/status` | ANALYST+ | Body: `{ "status": "<IncidentStatus>" }`. Validated transitions; on `RESOLVED`/`CLOSED`/`INVESTIGATING`, synchronizes every linked alert's status accordingly (see `../architecture/detection-engine.md`). `409` on illegal transition or version conflict. |
| POST | `/api/v1/incidents/{id}/ai/explanation` | ANALYST+ | Concise (default) or detailed (`?detail=detailed`) incident summary. Read-only. |
| POST | `/api/v1/incidents/{id}/ai/evidence-summary` | ANALYST+ | Fact-only summary of the evidence, no interpretation. Read-only. |
| POST | `/api/v1/incidents/{id}/ai/investigation` | ANALYST+ | Advisory, numbered investigation recommendations. Read-only; never recommends destructive/automated action. |

## Entities

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/entities` | ANALYST+ | Paged, searchable (`q`) list of monitored entities with summary rollups. |
| POST | `/api/v1/entities` | **ADMIN** | Body: `CreateEntityRequest` (`entityId`, `entityType` required; `displayName`, `metadata` optional). Returns `201`. Must be called before any event referencing that `entityId` will be accepted. |
| GET | `/api/v1/entities/{entityId}` | ANALYST+ | Rich single-entity view: identity, `eventCount`, `alertCount`, `openAlertCount`, `maxScore` (peak alert score, not a live risk score), `lastEventAt`, `openIncidentCount`, and the latest ML prediction's score/decision/timestamp. |

## Dashboard

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/dashboard/summary` | ANALYST+ | Query param `hours` (default 8) — window for the trend series. Returns totals, recent events/alerts, a time-bucketed trend, breakdowns by severity/status/type/processing-status/source, top-risk entities, and average/max anomaly score. |

## Replay runs (ADMIN only)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/replay-runs` | **ADMIN** | Creates and starts a bulk reprocessing run over stored events. |
| GET | `/api/v1/replay-runs` | **ADMIN** | Paged list of replay runs. |
| GET | `/api/v1/replay-runs/{runKey}` | **ADMIN** | Single run's progress/status. |

## Audit logs (ADMIN only)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/audit-logs` | **ADMIN** | Paged, newest-first audit trail across the whole platform. |

## Error response shape

Every non-2xx response — both from `GlobalExceptionHandler` and from `RestSecurityErrorHandler` (401/403, thrown inside the security filter chain before a controller is reached) — uses the same shape:

```json
{
  "code": "NOT_FOUND",
  "message": "Alert not found: <uuid>",
  "details": [],
  "requestId": "<X-Correlation-Id, if present>",
  "timestamp": "2026-09-30T12:00:00Z"
}
```

| HTTP status | `code` | Thrown when |
|---|---|---|
| 400 | `VALIDATION_ERROR` | `@Valid` bean-validation failure (`details` lists each field) |
| 400 | `INVALID_PARAMETER` / `INVALID_ENUM` | Bad path/query parameter type, or an invalid enum value |
| 400 | `MALFORMED_REQUEST` | Unparsable JSON body |
| 400 | `BAD_REQUEST` | An `IllegalArgumentException` from business logic |
| 401 | `UNAUTHORIZED` | Missing/invalid Basic credentials (`RestSecurityErrorHandler.commence`) |
| 403 | `FORBIDDEN` | Authenticated but lacking the required role (`RestSecurityErrorHandler.handle`) |
| 404 | `NOT_FOUND` | Referenced resource does not exist |
| 405 | `METHOD_NOT_ALLOWED` | HTTP verb not supported on that path |
| 409 | `RESOURCE_CONFLICT` | Duplicate-resource conflict |
| 409 | `INVALID_STATUS_TRANSITION` | Alert/incident status move not in the allowed graph |
| 409 | `DATA_CONFLICT` | DB constraint violation |
| 409 | `CONCURRENT_MODIFICATION` | Optimistic-lock version conflict (see `../database/database-design.md` §5) |
| 503 | `AI_PROVIDER_UNAVAILABLE` | The configured AI provider failed, timed out, or returned empty |
| 500 | `INTERNAL_ERROR` | Unexpected exception (logged server-side with the request ID) |

## Notes

- Every paged list endpoint clamps `size` to `[1, 100]` and `page` to `>= 0` server-side, regardless of what the client requests.
- No endpoint returns a real secret, credential, or API key — `GET /api/v1/auth/me` returns only username/roles.
- Swagger UI (`/swagger-ui.html`, `/v3/api-docs/**`) is mounted but restricted to `ADMIN` (API-surface disclosure is treated as a privileged operation).
