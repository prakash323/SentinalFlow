# SentinelFlow — Demo Runbook

A practical 10–15 minute walkthrough. Every step below uses a real, running instance of the platform — nothing is mocked or pre-recorded.

## Pre-demo

### Required services (in startup order)

1. **Infrastructure** — PostgreSQL + Kafka (Docker):
   ```
   docker compose up -d
   ```
2. **ML service** (from `ml-service/anomaly-detection/`):
   ```
   python api.py
   ```
   First boot takes a couple of minutes (loads and warms the model). Check readiness before continuing:
   ```
   curl http://127.0.0.1:8000/health
   ```
   Wait for `"status": "ok", "ready": true`.
3. **Backend** (from `backend/backend/`):
   ```
   mvn spring-boot:run
   ```
   Check: `curl http://localhost:8080/api/v1/health` → `{"status":"UP", ...}`.
4. **Frontend** (from `frontend/`):
   ```
   npm run dev
   ```
   Open `http://localhost:5173`.
5. *(Optional, for Demo 2 only)* **Physical collector** (from `SentinelFlow-PhysicalCollector/`, inside its own venv):
   ```
   python main.py --entity-id HOST-DEMO
   ```
   The `--entity-id` used **must already exist** — create it first (see Demo 2 below) or it will be rejected.

`start-dev.bat` (Windows, repo root) opens steps 2–4 in separate windows.

### Credentials

Two development-only accounts are pre-configured in `application.yml` (override via environment variables for anything beyond a local demo — see `../../README.md`):

| Role | Username | Password |
|---|---|---|
| Analyst | `analyst` | `analyst-dev-only-change-me` |
| Administrator | `admin` | `admin-dev-only-change-me` |

These are placeholders explicitly labeled as dev-only in source — never present them as production credentials.

### Health checks before starting

- `GET http://localhost:8080/api/v1/health` → `UP`
- `GET http://127.0.0.1:8000/health` → `ready: true`
- `docker compose ps` → `postgres` and `kafka` both healthy

---

## Demo 1 — Dashboard

**Do:** Sign in as `analyst`. Land on `/dashboard`.

**Expect:** KPI cards (total events, predictions, alerts, open incidents), a time-bucketed trend chart, severity/status breakdowns, and a top-risk-entities list — all reading live data from `GET /api/v1/dashboard/summary`.

**Say:** "Every number on this page is a real aggregate query against PostgreSQL — nothing here is hard-coded or cached beyond a 10-second client-side stale window."

## Demo 2 — Real physical telemetry

**Do:**
1. If not already present, create an entity for the demo machine: sign in as `admin`, go to **Entities → Create** (or `POST /api/v1/entities` with `{"entityId":"HOST-DEMO","entityType":"host"}`).
2. Start the physical collector: `python main.py --entity-id HOST-DEMO` (from its own directory/venv).
3. Open **Events**, filter `source = physical-collector`.

**Expect:** Within the default poll intervals (session: 5s, process: 15s, network: 30s), real `LOGIN`/`PROCESS_START`/`NETWORK_CONNECTION` events from the actual demo machine appear — genuinely observed via `psutil`, not synthetic.

**Say:** "This is not simulated data — these are real processes and real connections on this machine, picked up by three independent psutil-based pollers and published straight to Kafka, with no REST call in between."

## Demo 3 — Deterministic rule detection (AUTH_BURST)

**Do:** Go to **Simulator**, pick a target entity, run the **"Brute-force login burst"** scenario (eight rapid failed logins from one foreign IP, ending in a success).

**Expect:** Within seconds, an alert appears for that entity with **`detectionType: RULE`**, `ruleId: AUTH_BURST`, `decision: SUSPICIOUS`, severity `MEDIUM` or `HIGH`. Open it — Alert Detail correctly attributes it to *"Evidence recorded by the deterministic rule 'Repeated failed login attempts' — not an ML prediction."*

**Say:** "This alert did not involve the ML model at all — it fired from a small, independent rule engine that keeps working even if the ML service is completely down. Watch the ruleId and the wording on this page: it never claims to be an ML result."

## Demo 4 — ML scoring on the same event stream

**Do:** From the same run, open **Events**, find one of the `LOGIN` events just sent, open its detail page and look at the **Processing Trail**, or check **Predictions** filtered to that entity.

**Expect:** A real `Prediction` row: a numeric `anomalyScore`/`riskScore`, a `decision` (`NORMAL` or `ANOMALOUS` depending on the live model's actual behavioral history for that entity), and — if it crossed the alert threshold — its own separate, independent alert with `detectionType: ML`. **Do not promise a specific `attackType` in advance** — the model's classification depends on real-time behavioral state that a presenter cannot fully control; describe whatever the live run actually returns.

**Say:** "Same event stream, second independent judgment. The rule alert you just saw and this ML prediction were computed completely separately — one never depends on the other being available or correct."

## Demo 5 — Incident investigation

**Do:** Go to **Incidents**, find the incident that now groups the Demo 3/4 alert(s) for that entity (keyed on `entityId:eventType`). Open it.

**Expect:** Linked alerts (possibly both the rule alert and an ML alert, if both fired), a status-transition control (`OPEN → INVESTIGATING → RESOLVED → CLOSED`), and rollup fields (alert count, max severity, sources).

**Say:** "Alerts from different detection paths — and potentially different telemetry sources — land in the same incident automatically, because correlation is keyed on the entity and event type, not on which detector or producer raised the alert."

Move the incident to `INVESTIGATING` and point out that this also moved every linked alert's own status (visible on the Alerts page) — one action, synchronized state.

## Demo 6 — Spring AI explanation / evidence / investigation

**Do:** On the same incident, click **Explanation**, then **Evidence summary**, then **Investigation** (or the "Show detailed analysis" toggle for a longer form).

**Expect:** Three distinct, real LLM-generated responses (via OpenRouter), each grounded in the exact stored evidence — attributed language ("the model classified this as…"), never a claim that an action was taken, and never a recommendation beyond "a human analyst should review…".

**Say:** "This is a real API call to a real language model — not a template. But notice it never says it fixed anything, blocked anything, or closed anything. It's advisory text over evidence the platform already computed, nothing more — that's enforced in the code, not just in the wording."

*(If `OPENROUTER_API_KEY` is not configured in this environment, this will correctly return a `503 AI_PROVIDER_UNAVAILABLE` — that is the intended, controlled failure mode, not a bug. Mention this rather than treating it as broken.)*

## Demo 7 — Security / role behavior

**Do:**
1. Open a private/incognito window, hit `http://localhost:8080/api/v1/alerts` directly (no credentials) → expect `401`.
2. Sign in as `analyst` in the main app, try to navigate to **Audit Logs** or **Replay Runs** → expect the page to correctly refuse/hide the admin-only screen.
3. Sign out, sign in as `admin`, open the same admin-only pages → expect them to work.

**Say:** "The frontend hides these screens for an analyst, but that's just UX — the real enforcement is server-side, in Spring Security. Even if you forged the URL, the API itself returns 403 for an analyst account on an admin-only endpoint."

---

## Wrap-up talking points

- Two independent detection paths (ML + deterministic rules) on every event, verified to survive an ML outage.
- Three distinct, honestly-labeled telemetry sources feeding one correlation engine.
- An AI layer that is structurally incapable of mutating state — not just told not to.
- Role-based security enforced at the API, not only in the UI.
