# SentinelFlow Python Event Simulator

A local development tool that generates synthetic security events and
sends them to the SentinelFlow Spring Boot event API
(`POST /api/v1/events`), so the full pipeline — ingestion, prediction,
alerting, incidents, dashboard — can be exercised without hand-entering
events through Swagger UI.

The simulator is a **synthetic event source only**. It does not decide
final severity or replace the ML model — see [Design notes](#design-notes).

## Install

```bash
pip install -r requirements.txt
```

Requires Python 3.9+.

## Quick start

```bash
# Basic run against a local backend
python simulator.py --events 100 --interval 2

# Recommended dashboard test: realistic mix of behavior
python simulator.py --scenario mixed --events 200 --interval 1

# Individual scenarios
python simulator.py --scenario normal --events 100
python simulator.py --scenario suspicious --events 50
python simulator.py --scenario high --events 30
python simulator.py --scenario critical --events 20

# Load / trend / pagination testing
python simulator.py --scenario burst --events 1000

# Backfill data spread across past days
python simulator.py --scenario historical --events 200

# Reproducible run, no network calls (prints/logs only)
python simulator.py --scenario mixed --events 100 --seed 42 --dry-run

# Point at a non-default backend
python simulator.py --base-url http://localhost:8080 --events 50
```

## CLI reference

| Flag | Default | Description |
|---|---|---|
| `--events` | 100 | Number of events to generate |
| `--interval` | 2.0 | Seconds between sends (jittered by `--jitter`) |
| `--scenario` | mixed | `normal`, `suspicious`, `high`, `critical`, `mixed`, `burst`, `historical` |
| `--base-url` | http://localhost:8080 | Backend base URL (`/api/v1/events` is appended) |
| `--users` | USER-001..USER-010 | Comma-separated entity IDs. IDs starting with `SVC-` are treated as service accounts |
| `--seed` | none | RNG seed for reproducible runs |
| `--dry-run` | off | Generate events but skip the HTTP call |
| `--historical-days` | 3 | Window for the `historical` scenario |
| `--burst-window-seconds` | 60 | Clustering window for the `burst` scenario |
| `--timeout` | 5.0 | HTTP request timeout (seconds) |
| `--max-retries` | 3 | Retries on connection errors / 502/503/504 |
| `--jitter` | 0.15 | Fractional jitter applied to `--interval` (0 disables) |
| `--output-file` | none | Write every generated event to this file as JSONL |
| `--log-file` | none | Also write logs to this file |
| `--verbose` | off | Debug-level logging (shows entity pool assignment, etc.) |

Exit code is `0` on full success, `1` if any event failed to send (dry runs
always exit `0` on valid config), `2` on a configuration error.

## Event contract

Every event matches the existing `CreateEventRequest` contract exactly —
the simulator never invents a second event format:

```json
{
  "eventId": "EV-SIM-a3f9c2d1-000001",
  "entityId": "USER-001",
  "eventType": "LOGIN",
  "eventVersion": "v1",
  "occurredAt": "2026-08-21T08:40:00Z",
  "source": "python-simulator",
  "payload": {
    "ip": "10.10.10.50",
    "location": "India",
    "loginSuccess": true
  }
}
```

`eventId` is `EV-SIM-<run_id>-<NNNNNN>`: `run_id` is a random 8-character
token generated once per simulator invocation (`Config.run_id`), and the
6-digit suffix is a plain sequential counter within that run, starting at
`000001`. The run_id segment is what lets repeated runs be sent to the
same backend without colliding on its unique `eventId` constraint; the
suffix alone is only unique *within* a single run, exactly as before. Note
this segment is not affected by `--seed` - two `--seed`-matched runs
reproduce identical event content/order but still get different run_ids,
intentionally, since reproducible IDs would reintroduce the same
cross-run collision this format exists to avoid.

If the backend's contract changes, update the payload builders in
`event_generator.py` rather than adding a parallel format.

## Design notes

- **Correlated sequences, not independent randomness.** `suspicious`,
  `high`, and `critical` scenarios play out as a single entity's session —
  e.g. `LOGIN(fail) → LOGIN(fail) → LOGIN(fail) → PASSWORD_CHANGE →
  API_ACCESS(sensitive) → FILE_ACCESS(sensitive) → TRANSACTION(high)` —
  because that's what gives an eventual ML model realistic temporal
  structure to learn from. See `scenarios.py`.
- **Entity profiles carry state.** Each entity (`normal`, `remote`,
  `risky`, `compromised`, `service_account`) has its own known IP/location
  pool, generated once per run. Anomalous events for that entity draw from
  a separate "unfamiliar" pool instead of fully random values, so
  IP/location/outcome stay correlated instead of independently randomized.
  See `entities.py`.
- **Severity is not forced.** The simulator only generates behavior that
  is *intended* to look suspicious; it never tells the backend what
  severity to assign. That decision stays with the ML/policy layer.
- **Timestamps follow scenario intent** (`scenarios.py`):
  - Live scenarios (`normal`/`suspicious`/`high`/`critical`/`mixed`):
    timestamps are generated backwards from an anchor 0–30s behind the current
    clock, so even multi-event sequences can never produce future timestamps.
  - `historical`: timestamps spread across `--historical-days`, oldest
    events first.
  - `burst`: timestamps clustered within `--burst-window-seconds`.
  - `occurredAt` is always sent in UTC; the frontend can render local time.
  - The simulator validates the outgoing event contract, duplicate IDs, and
    future timestamps before sending. Run summaries report timestamp safety.
- **Resilience.** HTTP calls run through a pooled `requests.Session` with
  automatic retry/backoff on connection errors and 502/503/504, so a
  momentarily-busy local server doesn't abort a long run. Ctrl+C stops
  cleanly and still prints a summary of what was sent so far.
- **Reproducibility.** All randomness flows through one seeded
  `random.Random` instance (never the global `random` module), so
  `--seed 42` reproduces an identical event stream — useful for regression
  tests against the backend.

## Project structure

```
simulator/
├── simulator.py        # CLI entry point, orchestration, logging, summary
├── config.py            # Config dataclass, defaults, weights, validation
├── entities.py           # Entity profile modeling (Section 10)
├── event_generator.py    # Per-event-type payload builders (contract-compliant)
├── scenarios.py           # Scenario sequences + timestamp strategy
├── http_client.py         # Retrying HTTP client, dry-run support
├── requirements.txt
└── README.md
```

## Extending

- **New event type:** add a payload builder to `PAYLOAD_BUILDERS` in
  `event_generator.py` and a weight in `config.EVENT_TYPE_WEIGHTS`.
- **New scenario:** add a sequence to `SEQUENCES` in `scenarios.py` (or a
  branch in `_plan_steps` for non-sequence scenarios like `burst`), then
  add it to `config.VALID_SCENARIOS`.
- **New entity profile:** add to `entities.PROFILE_WEIGHTS` and teach
  `build_entity_pool` how to seed its known IP/location pool.
