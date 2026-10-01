# SentinelFlow — ML Integration

Source: `ml-service/anomaly-detection/api.py`, `config.py`; `backend/backend/.../ml/MlPredictionClient.java`, `MlPredictionResponse.java`; `backend/backend/.../service/EventProcessingService.java`, `PredictionService.java`.

## 1. ML service is an external dependency

The production ML service is a separately-run FastAPI process (`python api.py`, port 8000 by default) that Spring Boot calls over HTTP. It is not embedded in the backend and is not part of the same deployable artifact — it is versioned, run, and evaluated independently under `ml-service/anomaly-detection/`.

## 2. Service boundary

Two endpoints, both defined in `api.py`:

- `GET /health` → `{ status, ready, service, detail? }`. Always returns HTTP 200 (even while the model is still warming up) so a liveness probe passes; a caller that needs a *ready* model checks `ready === true` / `status === "ok"`. `status: "warming"` while the model is loading (loading + warm-up replays ~100k events and takes a couple of minutes, done on a background thread); `status: "error"` with `detail` if loading failed.
- `POST /predict` → scores one event. `503` if the scorer has not finished loading; `500` with the exception text if scoring itself throws.

## 3. Request contract

Spring Boot's `MlPredictionRequest` is sent field-for-field the same as the canonical `KafkaEvent` — no translation happens on the Java side (`EventProcessingService.toMlRequest`). The ML side's own `EventRequest` (Pydantic model in `api.py`) accepts `eventId`, `entityId`, `eventType`, `eventVersion`, `occurredAt`, `source`, `payload`, and adapts this into its internal canonical schema itself (`_canonical_event`): it maps `loginSuccess`/`ip`/`location`/`resource`/`authMethod`/`sessionDurationMinutes`/`commandSequence`/`deviceFingerprint` (with several alternate key names tolerated, e.g. `sourceIp/source_ip` for `ip`) into the feature-extraction pipeline's own field names, defaulting anything genuinely missing rather than requiring it.

## 4. Response contract

`api.py`'s `/predict` response, mirrored field-for-field by `MlPredictionResponse.java`:

| Field | Meaning |
|---|---|
| `anomalyScore` | `riskScore / 100`, i.e. a `[0,1]` normalization of the model's own 0–100 risk score |
| `riskScore` | The model's raw 0–100 score — a **percentile rank against its own training distribution**, not a calibrated probability (see §6) |
| `confidence` | `null` unless an alert fired, in which case the classifier's own class-confidence |
| `decision` | Strictly binary: `"ANOMALOUS"` or `"NORMAL"` — there is no third state on the ML side |
| `modelName` | `"behavioral-anomaly-ensemble"` (fixed string returned by `api.py`) |
| `modelVersion` | `"pipeline-joblib"` (fixed string) |
| `attackType` | `null` unless an alert fired; otherwise the classifier's predicted attack class |
| `reason` | `null` unless an alert fired; otherwise a human-readable narrative from the model's own explainability layer (`src/explain.py`) |
| `factors` | `[]` unless an alert fired; otherwise a list of human-readable top-factor strings |

Only fields the real model actually produces are ever populated — nothing is fabricated on the Java side when the ML service itself returns `decision: "NORMAL"`.

## 5. Spring Boot interpretation

`EventProcessingService.mapDecision` maps the ML response into SentinelFlow's own `DecisionState`:

- `decision != "ANOMALOUS"` → `NORMAL`
- `decision == "ANOMALOUS"` and `attackType` is a real class → `KNOWN_ANOMALY`
- `decision == "ANOMALOUS"` and `attackType` is null/blank/`"unclassified"` → `UNKNOWN_ANOMALY`

`DecisionState.SUSPICIOUS` and `DecisionState.ERROR` are **never** produced by this mapping — `SUSPICIOUS` is reserved exclusively for the deterministic-rule path (see `../architecture/detection-engine.md`), and a call failure never reaches `mapDecision` at all (it is recorded via the ledger and rethrown before `createPrediction` is called, so no `Prediction` row — and therefore no `ERROR`-decision row — is ever created for a failed call).

Whether an **alert** is actually raised is entirely Spring Boot's own decision, independent of the ML model's binary `decision` field: `PredictionService.shouldCreateAlert` compares `fusedScore` against `anomaly.alert-policy.alert-threshold` (`0.99`, `application.yml`), and severity is banded by `medium`/`high`/`critical` thresholds (`0.99`/`0.995`/`0.999`). The ML ensemble already fuses its three internal signals (baseline + isolation forest + sequence autoencoder) into one `anomalyScore`, so that single score is used directly as `fusedScore` — Spring Boot does not combine multiple independent model outputs itself.

## 6. Why the thresholds are set where they are

`application.yml`'s own comment records the reasoning: the ML service's `anomalyScore` is a percentile rank against its training distribution, not a calibrated probability — it runs "hot" (even behaviorally-normal events commonly land at 0.95–0.99), and the ML service's own internal alert bar is `ALERT_BUDGET = 0.01` (top ~1%, `config.py`). The thresholds above are set to track that calibration, explicitly documented as a reasonable starting point rather than a final tuned value — the ML project's own `../../ml-service/anomaly-detection/ASSUMPTIONS.md` notes live-streaming score calibration is still an open item there.

## 7. ML failure handling

`MlPredictionClient.predict` has no try/catch of its own — any failure (connection refused, timeout, a `503` while the model is warming up, a `500` internal scoring error) propagates as an unchecked `RestClientException`. `EventProcessingService.process` catches it at the outer level, records the failure via `EventProcessingLedgerService.markFailed` (durable, queryable — `events.processing_status = FAILED`, with the real error message), and rethrows so Kafka's retry/dead-letter handling (`KafkaErrorHandlingConfig`) can act on it. Critically, this failure **never suppresses** the deterministic rule path, which already ran earlier in the same `process()` call, independent of the ML call's outcome.

## 8. Prediction persistence

A successful ML call becomes a `Prediction` row (`predictions` table) via `PredictionService.create`, idempotent on `(eventId, modelName, modelVersion)`. The full ML explainability output (`mlDecision`, `riskScore`, `attackType`, `reason`, `factors`) is stored in `Prediction.features` (a `jsonb` map) rather than requiring a schema migration for fields the existing column can already hold.

## 9. How ML alerts differ from rule alerts

| | ML-raised alert | Rule-raised alert |
|---|---|---|
| `alerts.prediction_id` | Set | Always `null` |
| `alerts.decision` | `KNOWN_ANOMALY` or `UNKNOWN_ANOMALY` | Always `SUSPICIOUS` |
| `alerts.rule_id` / `rule_name` | Always `null` | Set |
| `AlertResponse.detectionType` (derived, never stored) | `"ML"` | `"RULE"` |
| Gating | `fusedScore >= alert-threshold` | Rule-specific condition (see `../architecture/detection-engine.md`) |

Both paths reuse the identical `Alert → Incident → AlertFactor → AuditLog` machinery — see `../architecture/detection-engine.md`.

## 10. ML research/evaluation history — high level only

The following summarizes the phased evaluation work under `ml-service/anomaly-detection/` at a high level. Detailed numeric results are intentionally **not** reproduced here (per this documentation pass's own instructions not to re-run or re-litigate expensive ML research); consult each phase's own report files for specifics.

| Phase | What it covered | Deployed? |
|---|---|---|
| ML-1 | Initial model/pipeline development (baseline + isolation forest + sequence autoencoder ensemble, `src/detect.py`) | — |
| ML-2 | Evaluation harness and train/validation/test split protocol (`eval_ml2/`, `reports/ml2_evaluation.md`) | No — evaluation only |
| ML-3 | Model training runs and candidate comparison (`reports/ml3_training.md`, `reports/ml3_runs/`, `models/candidates/ml3/`) | No — candidates only |
| ML-4 | Data evaluation and a frozen candidate model (`reports/ml4_data_evaluation.md`, `reports/ml4_runs/`, `models/candidates/ml4/ml4_global.joblib`) | No — candidate only |
| ML-5 | Serving-parity fix, per-deployment threshold study, and probability calibration (`eval_ml5/README.md`) — explicitly evaluation code only | No — `eval_ml5/README.md` states directly: *"Nothing here is loaded by `api.py`, `run_pipeline.py` or `run_realtime.py`; nothing is deployed. `models/pipeline.joblib` is untouched."* |

## 11. Production model vs. candidates vs. evaluation artifacts

- **Production model**: `ml-service/anomaly-detection/models/pipeline.joblib`, loaded by `api.py` (`_load_scorer`, `C.MODELS / "pipeline.joblib"`) and served by the live `/predict` endpoint. This is the **only** artifact the running ML service ever reads.
- **Candidate models**: `models/candidates/ml3/`, `models/candidates/ml4/` — outputs of the ML-3/ML-4 evaluation phases, never loaded by `api.py`.
- **Evaluation artifacts**: `reports/` (run logs, per-phase metrics), `eval_ml2/`, `eval_ml4/`, `eval_ml5/` (evaluation code and outputs), `final_ml_package/` and `final_ml_package.zip` (a packaged snapshot of the ML-3/ML-4 deliverable) — none of these are read by the running service.

**No ML-3, ML-4, or ML-5 candidate is production.** The only model this platform's live detection path uses is `models/pipeline.joblib`, and every prediction returned by `POST /predict` today comes from it, verified directly in `api.py`.

## 12. Not modified or regenerated during this documentation pass

No file under `ml-service/anomaly-detection/` was modified, and no ML artifact was regenerated, retrained, or re-evaluated while writing this documentation.
