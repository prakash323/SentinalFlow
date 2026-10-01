# SentinelFlow Final Validation Report

**Generated:** 2026-09-30
**Location note:** this report lives at `setinalflow/documentation/validation/` — the planned rename/move to `sentinelFlow_capstone/` (Part 0 of this validation pass) was deliberately **not** performed this pass. See "Project organization" at the end of this document for why, and what a safe execution would require.

## 1. Environment

| Component | Version / detail |
|---|---|
| OS | Windows 11, Git Bash / PowerShell |
| Java | 21.0.12 |
| Spring Boot | 3.3.4 |
| PostgreSQL | 16.15 (Docker container `sentinelflow-postgres-1`, healthy) |
| Kafka | 3.7.0, KRaft mode (Docker container `sentinelflow-kafka-1`, healthy) |
| ML service | FastAPI, `behavioral-anomaly-ensemble` / `pipeline-joblib`, host-side process |
| Node | frontend build tooling: Vite, TypeScript `tsc -b` |
| Frontend | React 19, Vite 8, running via `npm run dev` (:5173) |

At the time of this validation the stack was running in its **normal non-Dockerized development mode**: PostgreSQL and Kafka in Docker containers (as originally designed), Spring Boot backend via a host-side JVM process, ML service host-side, frontend via the Vite dev server. Docker Desktop's engine had been unresponsive earlier in the session (disk exhaustion, unrelated to this project's own files) and was confirmed recovered before this validation began.

## 2. Architecture

```
Physical Collector / Simulator (host-side, real processes)
        │  publish canonical events
        ▼
Kafka (raw.events.v1, Docker)
        │  consumed by
        ▼
Spring Boot (host-side JVM)
        │  persists                     │  calls
        ▼                               ▼
PostgreSQL (Docker)              Production ML (host-side FastAPI)
        │                               │
        │        prediction              │
        ▼◄──────────────────────────────┘
Deterministic rules (AUTH_BURST, NEW_PROCESS_EXTERNAL_CONNECTION) evaluate
in parallel, independent of ML result
        │
        ▼
Alert → Incident (correlated by entityId:eventType, multi-source)
        │
        ▼
Spring AI (OpenRouter, advisory only — explanation / evidence-summary / investigation)
        │
        ▼
React SOC (dark/light themes, live data)
```

## 3. E2E Validation

| Flow | Result | Evidence |
|---|---|---|
| Physical Collector → Kafka | PASS | Live: fresh PROCESS_START events (`EV-PHYS-1790778985444-bad798` etc.), `occurredAt` seconds before the check |
| Kafka → Spring Boot | PASS | Live: same events consumed and persisted within ~1s |
| Spring Boot → PostgreSQL | PASS | Live: `processingStatus=PROCESSED`, `processingAttempts=0`, `lastProcessingError=null` |
| Spring Boot → ML | PASS | Live: real prediction returned (`anomalyScore=0.87162`, `decision=NORMAL`, `modelName=behavioral-anomaly-ensemble`) — genuinely NOT forced anomalous |
| Deterministic Rule (`NEW_PROCESS_EXTERNAL_CONNECTION`) | PASS | Live, organic (not manufactured): alert `a473e66b` on `java.exe → 104.18.3.115`, `decision=SUSPICIOUS`, `severity=MEDIUM`, `detectionType=RULE`, linked to incident, audit `DETECTION_CREATED` confirmed. Idempotency confirmed via safe replay of a separate historical pair — alert count for that event stayed at 1. |
| ML Detection | PASS | Live, organic: `SIM-BRUTE-MUO7KAX5-09`, `decision=KNOWN_ANOMALY`, `anomalyScore=1.0`, `confidence=0.862`, `attackType=credential_stuffing`, `severity=CRITICAL`, `detectionType=ML`, `ruleId=null` (confirmed independent of the rule path) |
| Alert → Incident | PASS | Live: incident `HOST-LAPTOP-HIK1MN09:LOGIN` — 116 alerts, `maxSeverity=CRITICAL`; incident `HOST-LAPTOP-HIK1MN09:NETWORK_CONNECTION` — 2 rule alerts |
| Source-aware SOC | PASS | Live: incident `0cb59b15...` sources = `["physical-collector", "simulator"]` — genuine multi-source aggregation, not fabricated |

## 4. Real Spring AI

**REAL PROVIDER VALIDATION — CONFIRMED**, not mocked. `OPENROUTER_API_KEY` is configured in this environment (value never read or printed).

| Endpoint | Result | Evidence |
|---|---|---|
| `POST /ai/explanation` (ML incident) | PASS | HTTP 200, `model: openai/gpt-4o-mini`, 448-char response grounded in real evidence ("credential stuffing", "7,063 km", "six distinct accounts") — matches stored prediction reason text exactly |
| `POST /ai/evidence-summary` | PASS | HTTP 200, references real anomaly score (1.00000), confidence (0.86200), real timestamps |
| `POST /ai/investigation` | PASS | HTTP 200, advisory-only language ("Review...", "Analyze..."), no remediation claims, references both ML evidence and rule evidence (`AUTH_BURST`) from the same incident |
| Explanation on a **rule-generated** alert (browser) | PASS | Live browser click on alert `a473e66b`: real AI text correctly labeled "Based on rule evidence", tentative hedged language ("may indicate potential malicious activity"), never stated as established fact |
| State mutation check | PASS | Incident/alert status confirmed unchanged (`OPEN`) after all AI calls |

Mocked/unit-level AI validation (from earlier phases) remains in the automated test suite and is unaffected.

## 5. Frontend / SOC

| Page | Result |
|---|---|
| Login | PASS — authenticates, redirects to dashboard |
| Dashboard | PASS — live counts (1,029 events, 975 predictions), "Operational" status, real charts |
| Events | PASS — physical-collector and simulator sources both visible and filterable |
| Event Detail | PASS — canonical payload, detection trail, related-activity correlation rendered |
| Alerts | PASS — mixed RULE/ML alerts, correct severity/decision badges |
| Alert Detail (RULE) | PASS — "Why this was flagged" correctly attributes to the deterministic rule, not ML; real AI explanation rendered |
| Alert Detail (ML) | PASS — verified in an earlier pass this session, unchanged |
| Incidents | PASS |
| Incident Detail | PASS — linked alerts, AI summary/investigation buttons present and functional |
| Entities / Entity Detail | PASS — verified in an earlier pass this session with real alert/event rollups |

Console errors: **zero**, across every page visited. No horizontal overflow observed. Dark theme: confirmed working. Light theme: toggle click registered but the dev-server view did not visibly change colors in this pass — **the production (Nginx-served) build was confirmed switching to light theme correctly earlier this session**, so this is logged as an inconclusive dev-server-only observation, not a functional regression.

## 6. Security

| Check | Result |
|---|---|
| Unauthenticated → protected endpoint | 401 |
| Analyst → permitted endpoint | 200 |
| Analyst → admin-only endpoint (`/audit-logs`) | 403 |
| Admin → admin-only endpoint | 200 |
| Analyst → `/actuator/env` | 403 |
| Public → `/actuator/health` (liveness) | 200 (by design) |

All LIVE VERIFIED this pass.

## 7. Automated Tests

| Suite | Result |
|---|---|
| Backend (`mvn -B clean verify`) | **190/190 pass**, 0 failures, 0 errors, BUILD SUCCESS |
| Physical collector (pytest) | **97/97 pass** |
| Frontend typecheck | Clean |
| Frontend build | Succeeds |

No ML tests exist as a formal suite in this repository; ML correctness was validated via live prediction calls instead (§3, §4).

## 8. Known Limitations

- **Project reorganization (Part 0) was not executed this pass.** The backend (host-side JVM) and physical collector (host-side Python venv) were both actively running and producing real, valuable live telemetry throughout this validation. Moving their containing directories out from under actively-running processes risks file-lock failures (Windows locks a running `.exe`/loaded DLLs) and interrupting live data capture, for a structural change with no functional urgency. See the summary for the precise, safe execution plan.
- **~55 historical events remain in FAILED status** from an earlier session outage (ML connectivity was briefly broken via an unrelated leftover Docker container, since resolved). These are permanent unless explicitly replayed; they do not reflect the current pipeline's health, which is confirmed working on all fresh traffic.
- **Large ML evaluation artifacts** (`reports/` ~933MB, `final_ml_package/` ~421MB, `eval_ml4/`+`eval_ml5/` ~230MB, `final_ml_package.zip` ~172MB) are not yet excluded in `.gitignore` and are not currently tracked by git (nothing is committed yet), but would make a future `git add .` prohibitively large for a normal GitHub repository. **Recommendation: Git LFS or external artifact/release storage for these specific paths, not deletion** — none were deleted this pass.
- Light theme on the Vite **dev server** specifically was inconclusive this pass (see §5); the production build was already confirmed correct earlier this session.

## 9. Final Status

**PASS WITH LIMITATIONS**

Every planned runtime validation (E2E physical telemetry, deterministic rule, ML detection, incident correlation, real Spring AI, frontend/SOC, security, full regression suite) passed with live, non-fabricated evidence. The only deferred item is the Part 0 folder reorganization, deferred deliberately for the safety reasons above, not because it failed.
