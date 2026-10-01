# SentinelFlow — Event Flow

## 1. Canonical event envelope

Every event, from every source, is exactly this shape (`CreateEventRequest.java` / `KafkaEvent.java` / the collector's and simulator's own event builders all agree on it):

| Field | Type | Notes |
|---|---|---|
| `eventId` | string | Unique per event. Simulator: `EV-SIM-<run_id>-<n>`. Physical collector: `EV-PHYS-<epoch_ms>-<random hex6>`. In-console simulator: `<SCENARIO>-<n>` under a per-run prefix. |
| `entityId` | string | Must already exist as a registered `EntityProfile` (`POST /api/v1/entities`, ADMIN) — no producer auto-creates entities. |
| `eventType` | string | e.g. `LOGIN`, `LOGOUT`, `PROCESS_START`, `NETWORK_CONNECTION`, `API_ACCESS`, `FILE_ACCESS`, `TRANSACTION`, `PASSWORD_CHANGE`. |
| `eventVersion` | string | `"v1"` everywhere in this codebase today. |
| `occurredAt` | ISO-8601 datetime, UTC, `Z` suffix | The real observed/originating instant — never "now" when a more accurate timestamp is available (e.g. a process's own `create_time`). |
| `source` | string | `python-simulator`, `physical-collector`, or `simulator` (in-console) — see `system-architecture.md` §10. |
| `payload` | JSON object | Event-type-specific fields; a field is included only when genuinely known, never fabricated as a placeholder. |

## 2. Two ingestion transports

```mermaid
sequenceDiagram
    participant Sim as Simulator / In-console Simulator
    participant Col as Physical Collector
    participant API as EventController / EventService
    participant Kafka as Kafka (raw.events.v1)
    participant Consumer as EventKafkaConsumer
    participant Pipe as EventProcessingService
    participant Ledger as EventProcessingLedgerService
    participant Rules as DeterministicRuleService
    participant ML as ML service (FastAPI)
    participant Pred as PredictionService
    participant Inc as IncidentService

    Sim->>API: POST /api/v1/events
    API->>API: persist Event row (PENDING)
    API->>Kafka: publish(event JSON)
    Col->>Kafka: publish(event JSON) directly (no REST call)

    Kafka->>Consumer: consume(eventJson)
    Consumer->>Pipe: process(event)
    Pipe->>Ledger: persistOrLoad(event)
    Note over Ledger: idempotent on eventId -\nREST path: loads the already-persisted row.\nCollector path: creates it here for the first time.
    Pipe->>Rules: evaluate(databaseEvent)
    Note over Rules: never throws; independent of ML
    Rules-->>Pipe: (alert raised or not - logged only)
    Pipe->>ML: POST /predict
    ML-->>Pipe: anomalyScore, decision, attackType, factors...
    Pipe->>Pred: createPrediction(...)
    Pred->>Pred: shouldCreateAlert? (fusedScore >= alert-threshold)
    alt threshold crossed
        Pred->>Inc: findOrCreateIncident(alert)
    end
    Pipe->>Ledger: markProcessed(eventId) / markFailed(eventId, error)
```

- **REST path** (`POST /api/v1/events`, used by the Python simulator and the in-console Simulator page): `EventService.create` persists the `Event` row **and** publishes it to Kafka in the same call. The Kafka consumer then finds the row already exists (`persistOrLoad`'s "already exists" branch) — this is deliberate, documented redundancy, not a bug: the REST path stores the event before publishing so a caller's `201 Created` response reflects a real, durably persisted row, while Kafka remains the single trigger for the detection pipeline.
- **Direct-Kafka path** (physical collector only): the collector never calls the REST API. `EventProcessingLedgerService.persistOrLoad` creates the `Event` row for the first time when the Kafka consumer picks up the message — this is exactly the scenario that comment in `EventProcessingLedgerService` anticipates ("defends against a future producer publishing directly to Kafka without going through the REST API first").

## 3. Processing status, retry, and dead-lettering

- `Event.processingStatus` (`EventProcessingStatus`: `PENDING` → `PROCESSED` | `FAILED`) is the durable, queryable record of pipeline outcome — never only a log line.
- `processingAttempts` and `lastProcessingError` accumulate across retries; `markProcessed` clears a stale error message from an earlier failed attempt (the attempt count itself is left untouched as a legitimate historical fact).
- Kafka-level: `KafkaErrorHandlingConfig` retries a transient failure twice (1s fixed backoff, 3 attempts total) before publishing the original record to `raw.events.v1.DLT`. `NotFoundException` and `IllegalArgumentException` (bad data — retrying will not help) skip straight to the dead-letter topic.
- `GET /api/v1/events/{eventId}/trail` returns the processing status, attempt count, last error, and (if they exist) the resulting `Prediction`/`Alert` for one event — the primary way to inspect what the pipeline did with a specific event.

## 4. Idempotency

- **Event**: unique on `event_id` (`events.event_id`), enforced by `persistOrLoad`'s existing-row check.
- **Prediction**: unique on `(event_id, model_name, model_version)` (`V11__add_prediction_idempotency.sql`), enforced in application code by `PredictionService.create`'s existing-prediction check before any insert.
- **Rule alert**: `AlertRepository.existsByEvent_IdAndRuleId` — a given rule fires at most once per event.

## 5. From detection to SOC

Once an `Alert` exists (ML or rule path) and is linked to an `Incident`, both are immediately visible through the standard REST endpoints (`GET /api/v1/alerts`, `GET /api/v1/incidents`) with no further processing step — the React SOC polls/queries these endpoints directly; there is no separate "publish to UI" step.
