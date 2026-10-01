# SentinelFlow — Physical Telemetry Collector

Source: `SentinelFlow-PhysicalCollector/collector/` (`config.py`, `host_identity.py`, `session_poller.py`, `process_poller.py`, `network_poller.py`, `normalizer.py`, `kafka_producer.py`, `main.py`).

## 1. Architecture

The collector is a single long-running Python process (`main.py`) that runs three independent pollers on three independent cadences, each producing SentinelFlow canonical events published **directly to Kafka** (topic `raw.events.v1`) — it never calls the REST API. A single `0.1s` base tick drives responsive shutdown handling; each poller only actually runs when its own interval has elapsed (no threads/asyncio/scheduler framework).

| Poller | Cadence (default) | Produces |
|---|---|---|
| `SessionPoller` | `--poll-interval`, 5.0s | `LOGIN` / `LOGOUT` |
| `ProcessPoller` | `--process-poll-interval`, 15.0s | `PROCESS_START` |
| `NetworkPoller` | `--network-poll-interval`, 30.0s | `NETWORK_CONNECTION` |

## 2. psutil usage

All telemetry is gathered through `psutil`, a normal, cross-platform, non-admin mechanism — deliberately **not** the Windows Security Event Log (event IDs 4624/4634/4688), which would require an elevated audit-policy change this project avoids.

- **Sessions**: `psutil.users()` (WTS session enumeration on Windows). Verified empirically on the actual development machine: it returns exactly one local interactive session with `terminal=None`, `host=None`, `pid=None`, and a real `started` epoch — that is the genuine ceiling of what this mechanism can see on this platform.
- **Processes**: a cheap bulk `psutil.process_iter(['pid','name','ppid','create_time','username'])` call for detection (~40ms over ~300 processes, measured), plus a separate, targeted `psutil.Process(pid).exe()` lookup **only for newly detected processes** (measured at ~3.1s for the same ~300 processes if requested in bulk — isolated as the expensive field, which is why it is never requested in bulk).
- **Network**: `psutil.net_connections(kind='inet')`, filtered to `ESTABLISHED` status and non-loopback remote addresses (~1.4ms for ~200 connections, measured).

## 3. Kafka producer

`kafka_producer.py`'s `EventPublisher` wraps `kafka.KafkaProducer` with string key/value serializers (matching Spring Boot's `StringSerializer`/`StringDeserializer` exactly — same topic, same wire format, no schema registry), `retries=5`, `linger_ms=50`. It logs only operational metadata (`eventId`, `eventType`, `entityId`, partition, offset) — never the payload body.

## 4. Configuration

`config.py` / CLI (`main.py --help`): `--entity-id` (default derived, see below), `--kafka-bootstrap-servers` (default `localhost:9094`, matching the backend's own default), `--topic` (default `raw.events.v1`), `--poll-interval`, `--process-poll-interval`, `--network-poll-interval`, `--verbose`, `--log-file`. Each interval is also overridable via environment variable (`COLLECTOR_ENTITY_ID`, `KAFKA_BOOTSTRAP_SERVERS`, `PROCESS_POLL_INTERVAL_SECONDS`, `NETWORK_POLL_INTERVAL_SECONDS`).

## 5. Host identity

`host_identity.default_entity_id()` derives `HOST-<HOSTNAME>` (uppercased `socket.gethostname()`) — deterministic across restarts on the same machine, contains no secrets, and matches the existing simulator's simple `NAME-suffix` entity-id convention. **Known, documented limitation**: two physical machines sharing an OS hostname would collapse to the same `entityId` — accepted for this project's single-demo-machine scope; `--entity-id` is the escape hatch.

The collector's `entityId` **must already be registered** via `POST /api/v1/entities` (ADMIN) before the collector is started — it never creates entities itself.

## 6. Session polling → LOGIN / LOGOUT

`SessionPoller.poll_once()` is stateful: it snapshots active sessions each call and diffs against the previous snapshot. Sessions are identified by `(username, started)` rather than a session id, because psutil reports no stable per-session id on this platform (`pid=None`). **The very first call establishes a baseline and reports every already-active session as a `LOGIN`** — a deliberate, documented choice: `started_epoch` on that event is still the real OS-reported login time, so nothing is fabricated; the collector is reporting a login it discovered rather than one it watched happen live.

## 7. Process polling → PROCESS_START

`ProcessPoller.poll_once()` is deliberately the opposite of session polling on its first call: it establishes a **silent** baseline and returns an empty list, because reporting every already-running process as "just started" would be misleading (most system/OS processes have been running since boot) and would flood the pipeline at every collector restart. Only processes whose `(pid, create_time)` identity was not present in the previous snapshot are ever reported — process identity is `(pid, create_time)`, not `pid` alone, precisely because Windows reuses PIDs after a process exits (a reused PID has a different `create_time`, so it is correctly treated as a distinct process).

## 8. Network polling → NETWORK_CONNECTION

`NetworkPoller.poll_once()` follows the same silent-first-baseline pattern as process polling. Scope is deliberately narrowed: **`ESTABLISHED` connections only** (`LISTEN` sockets are standing configuration, not activity; `TIME_WAIT` connections were empirically confirmed during development to always report `pid=0` on this platform, making them both low-value and unreliable to identify) and **non-loopback remote address only** (a `127.0.0.0/8`/`::1` remote address is local-machine-to-itself traffic — e.g. the backend talking to its own Dockerized Postgres/Kafka — excluded as noise). Private/LAN addresses (`10.x`, `192.168.x`, etc.) are explicitly **kept**, by design — this collector does not restrict itself to public-Internet connections.

**Known, documented limitation**: connection identity is `(protocol, localAddress, localPort, remoteAddress, remotePort, pid)`, deliberately excluding `status` (a tracked connection's status can legitimately change between polls without being a new connection). psutil's connection table carries no equivalent of a process's `create_time`, so there is no way to distinguish a genuinely new connection from a coincidental exact repeat of the same 6-tuple after the original one closed — investigated and accepted as the correct trade-off, not an oversight.

## 9. Event correlation foundation

Both `PROCESS_START` and `NETWORK_CONNECTION` payloads carry fields specifically so a downstream consumer can correlate them without any extra collector-side logic:

- `NETWORK_CONNECTION.payload.processCreateTime` is the **owning process's real `create_time`**, read from the same `psutil.Process` handle already opened for the process-name lookup (no extra expensive call) — it is *not* the connection's own start time (psutil has no such field). Formatted identically to every other timestamp (`iso_utc`), so it can be string-compared directly against `PROCESS_START.occurredAt`.
- This is exactly what `DeterministicRuleService.evaluateNewProcessExternalConnection` (backend) and `relatedActivity.ts` (frontend "Related activity") both use for exact-match correlation: `NETWORK_CONNECTION.pid == PROCESS_START.payload.pid AND NETWORK_CONNECTION.payload.processCreateTime == PROCESS_START.occurredAt`, string equality, no time tolerance.
- `LOGIN.payload.username` (bare OS username from `psutil.users()`, e.g. `praka`) and `PROCESS_START.payload.username` (fully-qualified Windows account name from `psutil.Process.username()`, e.g. `LAPTOP-HIK1MN09\praka`) are **different string formats for the same real person**, confirmed against real stored data. Neither the backend rule engine nor the frontend correlation logic normalizes this — a strict string match is used exactly as specified, which means a LOGIN↔PROCESS_START username correlation will not currently be found on this project's own real data. This is a known, reported limitation, not a bug.

## 10. Canonical event structure

The collector reuses the platform's existing, unchanged canonical envelope (`eventId`, `entityId`, `eventType`, `eventVersion`, `occurredAt`, `source`, `payload`) — `SOURCE = "physical-collector"`, `EVENT_VERSION = "v1"`. `eventId` format: `EV-PHYS-<epoch_ms>-<6 random hex chars>` — unique by construction across restarts (no in-process counter to reset, unlike the simulator's own per-run counter).

**LOGIN payload**: `loginSuccess` (always `true` — session polling can only observe an already-active session; a failed local login attempt produces no session and is invisible to this mechanism, never fabricated as a separate event), `ip` (only if psutil reports a genuine remote host — `None`/omitted for a local interactive session on this dev machine, verified not assumed), `username`. `location` is never included (no geo-IP lookup performed).

**LOGOUT payload**: `sessionDurationMinutes` (a genuine measurement: real OS session-start time subtracted from the moment the collector observed the session end, bounded only by poll granularity), `ip` (same rule as LOGIN).

**PROCESS_START payload**: `pid` (always present), `processName`/`parentPid`/`username` (from the cheap bulk poll — `username` omitted for a handful of protected system processes, e.g. `csrss.exe`, verified empirically), `executablePath` (only when the targeted per-process lookup succeeded; omitted, never replaced with a placeholder, if the process exited before the lookup ran). **Never included, anywhere in this collector**: `cmdline` (command-line arguments) — not merely excluded from the payload, but never fetched from the OS at all.

**NETWORK_CONNECTION payload**: `protocol`/`localAddress`/`localPort`/`remoteAddress`/`remotePort`/`status` (read directly from the OS connection table), `pid` (when reported — every `ESTABLISHED` connection had a real non-zero pid in testing), `processName` (targeted lookup, omitted if the owning process already exited), `processCreateTime` (see §9). `occurredAt` is the moment the collector **detected** the connection, not a fabricated "connection start time" (psutil exposes no such field). **Never included**: packet contents, DNS contents, HTTP/TLS internals, command lines, credentials/tokens/secrets — psutil's connection table exposes none of these, so there is nothing to deliberately strip.

## 11. What is intentionally not collected

Command-line arguments (`cmdline`) for any process, at any point — a deliberate scope decision recorded directly in `process_poller.py`'s own module docstring and the collector's `../../SentinelFlow-PhysicalCollector/README.md`.

## 12. What the collector observes vs. what Spring Boot / ML determine

The collector **only observes and reports facts** — it never classifies, scores, or labels anything as anomalous, suspicious, or malicious. Specifically:

- The collector does not know what "normal" looks like for any entity — that judgment belongs entirely to the ML service (`behavioral-anomaly-ensemble`) and the deterministic rule engine (`DeterministicRuleService`), both running inside Spring Boot, after the event has been ingested.
- The collector does not decide severity, does not create alerts, and does not correlate events with each other beyond attaching the raw fields (`processCreateTime`, `username`) that let a downstream consumer do so.
- Every judgment call visible anywhere in the SOC (anomaly score, decision, attack type, rule-fired evidence, severity) is produced entirely after ingestion, by `EventProcessingService` → ML service and/or `DeterministicRuleService` — never by the collector itself.

## 13. Known limitations (summary)

- Hostname collisions collapse two machines to the same `entityId` (see §5).
- No geo-IP lookup — `location` is never populated on collector-sourced `LOGIN`/`LOGOUT` events.
- `NETWORK_CONNECTION` identity cannot distinguish a genuinely new connection from an exact repeat of a closed one (see §8).
- `LOGIN`↔`PROCESS_START` username correlation does not currently match on this project's real Windows data, due to the bare-username vs. domain-qualified-username format mismatch (see §9) — not normalized, by explicit decision, since no existing documented normalization rule justifies inventing one.
- A failed local login attempt is invisible to session polling (no session is ever created for it) — `AUTH_BURST` (the deterministic rule keyed on `loginSuccess=false`) will never fire from physical-collector telemetry today; it only fires from simulator-sourced events, which do report failed-login attempts.
