# SentinelFlow — real-time anomaly detection platform

A streaming behavioural-analytics platform: events are ingested over REST or directly to Kafka, stored in PostgreSQL, scored independently by a Python ML ensemble **and** a deterministic rule engine, graded by an alert policy, grouped into incidents, and triaged in a React operations console with optional AI-assisted explanations.

```
 React console ──► Spring Boot API ──► PostgreSQL
   (5173)            (8080)    │
                               ├──► Kafka  raw.events.v1 ──► consumer ──► ML service (FastAPI, 8000)
                               │                                │              │
                               │                                └► deterministic rules (ML-independent)
                               └◄──────── prediction/rule → alert → incident ◄──┘
```

| Component | Path | Stack | Port |
|---|---|---|---|
| Console (UI) | `frontend/` | React 19, TypeScript, Vite, TanStack Query, Recharts, Motion | 5173 |
| API + pipeline | `backend/backend/` | Spring Boot 3.3, Java 21, JPA/Flyway, Spring Kafka, Spring Security, Spring AI | 8080 |
| ML service | `ml-service/anomaly-detection/` | FastAPI, scikit-learn, PyTorch, LightGBM | 8000 |
| Physical telemetry collector | `SentinelFlow-PhysicalCollector/` | Python, psutil — real Windows host login/process/network telemetry | — |
| Synthetic event simulator | `simulator/` | Python — scenario-driven synthetic event generator (`--scenario` presets) | — |
| Infrastructure | `docker-compose.yml` | PostgreSQL 16, Kafka 3.7 (KRaft) | 5432 / 9094 |

**Full technical documentation:** [`documentation/`](documentation/) — architecture, API reference, database schema, security design, physical telemetry, ML integration, Spring AI design, the detection engine, testing/validation results, a demo runbook, viva notes, and the future roadmap. Start with [`documentation/architecture/system-architecture.md`](documentation/architecture/system-architecture.md).

## Quick start

Prerequisites: Docker Desktop, JDK 21, Maven, Node 20+, Python 3.11+.

```bash
# 1. Infrastructure (re-attaches to the existing sentinelflow_* volumes)
docker compose up -d

# 2. ML service — first run creates the venv; warm-up takes ~2 minutes,
#    /health reports "warming" until the model is ready.
cd ml-service/anomaly-detection
start_ml_windows.bat            # or: python api.py  (inside the venv)

# 3. Backend
cd backend/backend
mvn spring-boot:run             # or: mvn package && java -jar target/*.jar

# 4. Console
cd frontend
npm install
npm run dev                     # http://localhost:5173
```

`start-dev.bat` (Windows) opens steps 2–4 in separate windows.

Optional — real physical telemetry from this machine (register the entity first via **Entities → Create**, ADMIN only):

```bash
cd SentinelFlow-PhysicalCollector
python main.py --entity-id HOST-DEMO
```

Optional — synthetic event generation from the command line (the in-console **Simulator** page covers most demo needs without this):

```bash
cd simulator/simulator
python simulator.py --scenario critical --events 20
```

### Sign in

Two in-memory HTTP Basic accounts are configured in `application.yml`. The defaults are **development placeholders only** — override them with environment variables for anything else:

| Role | Env vars | Can do |
|---|---|---|
| Analyst | `SECURITY_ANALYST_USERNAME` / `SECURITY_ANALYST_PASSWORD` | Everything except the admin-only items below |
| Administrator | `SECURITY_ADMIN_USERNAME` / `SECURITY_ADMIN_PASSWORD` | Plus: replay runs, audit log, creating entities, direct prediction insertion |

`POST /api/v1/events` is public on purpose (the external event simulator cannot authenticate).

## The console

| Page | What it does |
|---|---|
| **Dashboard** | KPIs with sparklines, event/alert timeline (8h/24h/3d), severity distribution, live dependency health, pipeline progress, top-risk entities, recent alerts/incidents/events |
| **Events** | Filter by entity/type, live tail, side-drawer payload; **event detail** shows the real detection trail (Kafka → ML score & explanation → alert → incident) |
| **Predictions** | Every model score with decision, attack type, confidence and raw features |
| **Alerts** | Combined filters (status, severity, decision, entity); alerts from the ML ensemble and from the independent deterministic rule engine (`AUTH_BURST`, `NEW_PROCESS_EXTERNAL_CONNECTION`) side by side, clearly labeled; detail page with explainability, a triage workflow that only offers legal transitions, and an on-demand, concise AI explanation of why the alert fired |
| **Incidents** | Auto-grouped investigations; detail with lifecycle, linked alerts and on-demand AI summary / investigation guidance (concise by default, detailed on request) |
| **Entities** | Monitored users/devices with activity + risk rollups; per-entity alerts/incidents/events |
| **Simulator** | Six attack scenarios (brute force, impossible travel, exfiltration…) sent through the real pipeline, with live outcome tracking |
| **Replay runs** *(admin)* | Reprocess stored events through the pipeline |
| **Audit logs** *(admin)* | Who did what — now attributed to the signed-in user |
| **System** | Live PostgreSQL / Kafka / ML probes, pipeline counts, alert-policy thresholds |

`Ctrl/⌘ + K` opens a command palette (pages, entities, or paste an event ID). Light and dark themes are supported.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9094` | Host-side Kafka listener published by `docker-compose.yml` |
| `DB_URL` / `DB_USERNAME` / `DB_PASSWORD` | local Postgres / `anomaly` | Database |
| `ML_SERVICE_URL` | `http://127.0.0.1:8000` | ML service |
| `APP_CORS_ALLOWED_ORIGINS` | `http://localhost:5173,http://localhost:4173` | Only needed if the UI is hosted on another origin |
| `OPENROUTER_API_KEY` | *(unset)* | Enables the alert and incident AI assistants (read-only, concise by default) via [OpenRouter](https://openrouter.ai) (through the Spring AI OpenAI client). Without a key the endpoints answer a controlled `503 AI_PROVIDER_UNAVAILABLE`; nothing else is affected. Never commit it — set it in the environment |
| `OPENROUTER_MODEL` | `openai/gpt-4o-mini` | Any OpenRouter chat model id (`<vendor>/<model>`) |
| `OPENROUTER_BASE_URL` / `OPENROUTER_TEMPERATURE` | `https://openrouter.ai/api` (the client appends `/v1/chat/completions`) / `0.2` | Endpoint and sampling temperature |
| `VITE_API_BASE_URL` | `/` | Frontend: API origin when not using the Vite proxy |

## Testing

```bash
cd backend/backend && mvn test                          # 190 tests (unit, security slice, embedded-Kafka integration)
cd SentinelFlow-PhysicalCollector && python -m pytest    # 97 tests (unit + live Kafka integration)
cd frontend && npm run build                             # strict TypeScript + production bundle
```

See [`documentation/validation/TESTING-AND-VALIDATION.md`](documentation/validation/TESTING-AND-VALIDATION.md) for the full breakdown, including live end-to-end and manual browser verification results.

With everything running, the full path can be exercised from the **Simulator** page, or:

```bash
curl -X POST localhost:8080/api/v1/events -H 'Content-Type: application/json' -d '{
  "eventId":"DEMO-1","entityId":"USER-001","eventType":"LOGIN","eventVersion":"v1",
  "occurredAt":"2026-01-01T03:00:00Z","source":"curl",
  "payload":{"ip":"185.220.101.4","location":"Moscow|55.75|37.61","loginSuccess":false}}'
```

## Notes and known behaviour

- **Windows `localhost` delay.** The ML server binds IPv4 only; on Windows `localhost` resolves to `::1` first and every call pays a ~2 s fallback. All defaults therefore use `127.0.0.1`.
- **Time zone.** The JVM default zone is pinned to UTC at startup; PostgreSQL rejects legacy zone aliases (e.g. `Asia/Calcutta`) that some machines report.
- **Model calibration.** The ML score is a percentile rank against its training distribution, so it runs high; the alert thresholds (`anomaly.alert-policy`) are tuned to that. The model also learns per-entity baselines, so brand-new entities start from a peer-group prior (its explanation says so) and detection sharpens as history accumulates.
- **Pre-existing data.** Events stored before the ML integration show as `PENDING` — they were never run through the pipeline. Use a replay run to score them.
- **Validation status.** [`documentation/validation/FINAL_VALIDATION_REPORT.md`](documentation/validation/FINAL_VALIDATION_REPORT.md) records the platform's last full end-to-end validation pass as **PASS WITH LIMITATIONS** — see that report and [`documentation/validation/TESTING-AND-VALIDATION.md`](documentation/validation/TESTING-AND-VALIDATION.md) for specifics.
