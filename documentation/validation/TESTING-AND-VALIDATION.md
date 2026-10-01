# SentinelFlow — Testing & Validation Summary

This document summarizes verified test/validation results. It draws on two sources: the automated test suites (re-run during the project-organization move to the current `sentinelFlow_capstone/` root) and the prior full end-to-end validation pass recorded in `../validation/FINAL_VALIDATION_REPORT.md`. No new test counts are invented here — see that report for the original live/manual verification narrative in full.

## 1. Automated tests

| Suite | Command | Result | Type |
|---|---|---|---|
| Backend | `cd backend/backend && mvn -B clean verify` | **190 / 190 passed**, 0 failures, 0 errors | Unit, service, security-slice, and embedded-Kafka integration tests (JUnit 5 / Surefire) |
| Physical collector | `python -m pytest tests/` (from `SentinelFlow-PhysicalCollector/`) | **97 / 97 passed** | Unit tests plus live Kafka round-trip integration tests (`test_integration_kafka.py`, against a real local Kafka broker) |
| Frontend typecheck | `npx tsc -b` (from `frontend/`) | Clean, no errors | Strict TypeScript compilation |
| Frontend build | `npm run build` (from `frontend/`) | Succeeds | Production Vite build (one non-blocking chunk-size advisory, not an error) |

These counts were re-verified from the current `sentinelFlow_capstone/` project root as part of the project-organization move, confirming the move itself introduced no regression.

## 2. Physical telemetry end-to-end (from `FINAL_VALIDATION_REPORT.md`)

Verified live: fresh `PROCESS_START` events from the real physical collector reached Kafka and were persisted within ~1 second, with `processingStatus=PROCESSED`, `processingAttempts=0`, `lastProcessingError=null`.

## 3. Deterministic rule end-to-end (from `FINAL_VALIDATION_REPORT.md`)

Verified live, organically (not manufactured): a `NEW_PROCESS_EXTERNAL_CONNECTION` alert fired on a real `java.exe` → external-IP connection, with `decision=SUSPICIOUS`, `severity=MEDIUM`, `detectionType=RULE`, correctly linked to an incident, with a `DETECTION_CREATED` audit entry. Idempotency was confirmed by safely replaying a separate historical event pair and observing the alert count for that event stay at 1.

## 4. ML detection end-to-end (from `FINAL_VALIDATION_REPORT.md`)

Verified live, organically: a simulator-sourced event scored `decision=KNOWN_ANOMALY`, `anomalyScore=1.0`, `confidence=0.862`, `attackType=credential_stuffing`, `severity=CRITICAL`, `detectionType=ML`, `ruleId=null` — confirming the ML path is independent of the rule path, exactly as designed.

## 5. Alert → incident correlation (from `FINAL_VALIDATION_REPORT.md`)

Verified live: a real incident accumulated 116 alerts with `maxSeverity=CRITICAL` for one entity/event-type key; a separate incident showed genuine multi-source aggregation (`sources: ["physical-collector", "simulator"]`), confirming correlation is keyed on `entityId:eventType`, not source.

## 6. Real Spring AI validation (from `FINAL_VALIDATION_REPORT.md`)

Confirmed against the real OpenRouter provider (not mocked), covering all three incident AI endpoints plus the alert explanation endpoint. Responses were grounded in real stored evidence (specific scores, timestamps, attack-type text matching the stored prediction reason), and a rule-generated alert's explanation was correctly labeled as based on rule evidence rather than ML evidence. Alert/incident status was confirmed unchanged after every AI call (state-mutation check).

Separately, mocked/unit-level AI tests exist in the automated suite (§1) and are unaffected by the above live pass.

## 7. Frontend / SOC manual verification (from `FINAL_VALIDATION_REPORT.md`)

Every page (Login, Dashboard, Events, Event Detail, Alerts, Alert Detail for both RULE and ML alerts, Incidents, Incident Detail, Entities, Entity Detail) was manually verified in a real browser session against live data, with zero console errors observed. Dark theme was confirmed working directly; light theme was confirmed correct on the production (Nginx-served) build in an earlier pass, with one inconclusive dev-server-only observation noted (not a functional regression) — see the original report for the exact caveat.

## 8. Security validation (from `FINAL_VALIDATION_REPORT.md`)

Live-verified: unauthenticated access to a protected endpoint → `401`; an ANALYST account on a permitted endpoint → `200`; an ANALYST account on an admin-only endpoint (`/audit-logs`) → `403`; an ADMIN account on the same endpoint → `200`; an ANALYST account on `/actuator/env` → `403`; a public caller on `/actuator/health` → `200` (by design).

## 9. Distinguishing evidence type

| Type | Meaning | Where used above |
|---|---|---|
| **Automated test** | Runs unattended as part of the build (`mvn verify`, `pytest`, `tsc`) | §1 |
| **Live integration test** | Exercised against real, running dependencies (real Kafka, real Postgres, real ML service, real OpenRouter) during a manual validation pass, with fresh timestamps/IDs as evidence | §2–6, §8 |
| **Manual browser verification** | A human-driven browser session against the live frontend, checked for console errors and correct rendering | §7 |

## 10. Known limitations carried over from the original validation pass

- A handful of historical events (from an earlier, since-resolved ML-connectivity outage) remain permanently in `FAILED` status unless explicitly replayed — this does not reflect current pipeline health.
- Large ML evaluation artifacts (`reports/`, `final_ml_package/`, `eval_ml4/`, `eval_ml5/`, `final_ml_package.zip`) are not yet tracked by Git and were audited, not deleted — see the project-organization report for the size/classification breakdown and the Git LFS recommendation.
