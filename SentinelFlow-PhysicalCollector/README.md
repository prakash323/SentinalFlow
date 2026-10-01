# SentinelFlow Physical Telemetry Collector

A small, independent sibling project that publishes **real local host
telemetry** - login/logout sessions (P1), newly-started processes (P2),
and established network connections (P3) - into the existing SentinelFlow
pipeline, using the exact same canonical event contract and the exact
same Kafka topic the Python simulator already uses. It does not depend on
Spring Boot, the frontend, the ML service, or the simulator project - it
only needs Kafka reachable at the configured bootstrap address.

**This collector only collects and normalizes telemetry. It does not
detect anomalies, calculate risk, classify attacks, or generate alerts -
that is Spring Boot + ML's job, unchanged.**

```
Physical Telemetry Collector
        |
   raw.events.v1   (existing topic, existing wire format)
        |
Existing Kafka Consumer -> Spring Boot -> ML -> Risk/Policy -> Alert -> Incident -> React SOC
```

## What this collects (and what it deliberately does not)

### Session telemetry (LOGIN/LOGOUT, P1)

Telemetry source: local interactive login sessions, polled via
`psutil.users()` (cross-platform, no admin rights required - this
project intentionally does NOT read the Windows Security Event Log).

| Field | LOGIN | LOGOUT | Notes |
|---|---|---|---|
| `loginSuccess` | always `true` | - | session polling can only see a session that IS active; a failed login attempt is invisible to this mechanism and is never fabricated |
| `sessionDurationMinutes` | - | real measurement | `(observed - started) / 60`, both real OS-reported/collector-observed timestamps |
| `ip` | only if psutil reports a genuine remote host | only if psutil reports a genuine remote host | on this project's own dev machine this is `None` for the local console session (verified, not assumed) - most runs will omit it entirely |
| `location` | never included | never included | no geo-IP lookup is performed in this phase |

### Process telemetry (PROCESS_START, P2)

Telemetry source: newly-started local processes, polled via
`psutil.process_iter()`/`psutil.Process` (cross-platform, no admin rights
required - verified empirically on the development machine: 317
processes enumerated, zero `AccessDenied` errors).

| Field | Included when | Notes |
|---|---|---|
| `pid` | always | |
| `processName` | when psutil reports a non-empty name | a small number of special/kernel processes report an empty name; omitted rather than sent as `""` |
| `parentPid` | when available (including `0`, a legitimate root-level value) | |
| `username` | when psutil can resolve it | `None`/omitted for a handful of protected system processes (e.g. `csrss.exe`, `smss.exe` - verified empirically, not an error) |
| `executablePath` | only when a **targeted, per-process** lookup succeeds | see "Two-phase polling" below for why this is looked up separately rather than in the bulk poll; omitted (not fabricated) if the process already exited before the lookup ran - a real, benign race |

**Never collected, in either P1 or P2:** passwords, secrets, tokens, API
keys, environment variables, file contents, memory contents, or
**command-line arguments (`cmdline`)** - `cmdline` is never even
requested from the OS anywhere in this codebase, not merely left out of
the payload. Command-line arguments can and do carry embedded secrets in
real-world processes (e.g. a credential passed as a literal argument),
so this collector treats them as out of scope entirely for this phase,
not just "not sent."

Nothing is ever set to a placeholder string like `"unknown"` or
`"not_provided"` - a field either carries a real value or is omitted
from `payload`, exactly like the existing simulator's own payload
builders already do, and exactly like the ML adapter's existing
key-alias defaults already expect.

### Two-phase polling for process telemetry (why, not just what)

Measured empirically on the development machine, not assumed:
`psutil.process_iter(['pid','name','ppid','create_time','username'])`
over ~300 processes costs **~40ms**. Adding `exe` (executable path) to
that *same* bulk call costs **~3,100ms** for the same ~300 processes -
isolated and confirmed as the expensive field (each path resolution is a
separate, costlier OS call than the other fields combined). So:

1. Every `--process-poll-interval` tick, the collector does the **cheap**
   bulk poll (no `exe`) to detect which `(pid, create_time)` pairs are
   new since the previous poll.
2. `executablePath` is then looked up with **one targeted
   `psutil.Process(pid).exe()` call per newly-detected process only** -
   cost stays proportional to how many processes actually just started,
   never to the size of the whole process table.

### Process identity and PID reuse

A process is identified by **`(pid, create_time)`**, not `pid` alone.
The OS reuses PIDs after a process exits; a reused PID gets a new
`create_time`, so a later, unrelated process that happens to receive the
same PID is correctly treated as a *different* process - never merged
with, or confused with, the one that previously held that PID.

### Startup baseline (no historical process flood)

Unlike session polling (where an already-active LOGIN session is
genuinely true right now and is reported), the collector's **first**
process poll establishes a **silent baseline** of already-running
processes and reports nothing. Reporting hundreds of already-running
system/OS processes as "PROCESS_START" merely because the collector
itself restarted would be misleading (most have been running since boot,
not "just now") and would flood Kafka/Postgres with a one-time,
non-actionable burst every time the collector starts. Only processes
that appear **after** that baseline are ever reported.

### PROCESS_END - explicitly out of scope for this phase

Only `PROCESS_START` is implemented. Tracking process exits would need
additional lifecycle bookkeeping this phase does not add; nothing here
prevents adding it later.

### Network telemetry (NETWORK_CONNECTION, P3)

Telemetry source: **`ESTABLISHED` TCP/UDP connections only**, polled via
`psutil.net_connections(kind='inet')` (cross-platform, no admin rights
required - verified empirically: 183-210 connections enumerated
repeatedly, zero `AccessDenied` errors, even for a SYSTEM-owned process's
own connections).

| Field | Included when | Notes |
|---|---|---|
| `protocol` | always | `"TCP"`/`"UDP"`, derived from the socket type |
| `localAddress` / `localPort` | always | |
| `remoteAddress` / `remotePort` | always (connections with no remote endpoint are excluded entirely - see scope below) | |
| `status` | always | for this phase's scope this is always `"ESTABLISHED"` (see below) |
| `pid` | when psutil reports a non-zero owning pid | empirically confirmed: **every** `ESTABLISHED` connection sampled had a real pid; it is the excluded `TIME_WAIT` connections that lose it (see below) |
| `processName` | only when a **targeted** `psutil.Process(pid).name()` lookup succeeds | omitted (not fabricated) if the owning process already exited, or - rarer - if the pid has since been reused by an unresolvable process |

**Scope, deliberately narrow (see the phase audit for the full empirical
reasoning):**
- **`ESTABLISHED` only.** `LISTEN` sockets are long-lived standing
  configuration (observed: Windows `System` SMB ports, print spooler,
  Docker's backend, a remote-access tool) - not "activity," excluded.
  `TIME_WAIT` connections were empirically confirmed to **always** report
  `pid=0` on this platform - both low-value and unreliable to identify -
  excluded. UDP sockets report status `"NONE"` (no connection concept) -
  excluded by the same `ESTABLISHED`-only filter.
- **Non-loopback remote address only.** A connection whose remote address
  is `127.0.0.0/8` or `::1` is local-machine-to-itself traffic (observed:
  Docker's backend talking to its own Postgres/Kafka containers on
  `127.0.0.1`) - excluded as noise. **Private/LAN addresses
  (`10.x`/`192.168.x`/etc.) are NOT loopback and ARE kept** - this
  collector deliberately does not restrict itself to public-Internet
  connections.
- No packet contents, DNS contents, HTTP/TLS internals, command lines, or
  credentials/tokens/secrets - none of these are exposed by
  `psutil.net_connections()` in the first place, so there is nothing to
  deliberately strip; this collector simply never asks the OS for any of
  them (no packet capture, no DPI).

### Two-phase polling for network telemetry (cost is NOT the reason for the interval)

Measured empirically, not assumed: `psutil.net_connections(kind='inet')`
costs **~1.4ms for ~200 connections** (5 repeated calls: 1.16-1.62ms) -
roughly 2,000x cheaper than P2's `exe` lookup, and negligible CPU
overhead at any reasonable interval. **`--network-poll-interval`
(default 30s) exists to bound EVENT VOLUME, not CPU cost** - see "Known
limitations" for the measured volume that drove this default.

### Connection identity and its limitation

A connection is identified by **`(protocol, localAddress, localPort,
remoteAddress, remotePort, pid)`** - deliberately excluding `status`,
since a tracked connection's status can legitimately change between polls
without that being a new connection. Unlike a process (which has
`create_time` to disambiguate PID reuse), **psutil's connection table has
no equivalent timestamp** - a coincidental exact repeat of the same
6-tuple after the original connection closed would not be distinguishable
from the original persisting. This was investigated during the audit and
accepted as the correct trade-off for this phase's scope, not an
oversight.

### Startup baseline (same policy as PROCESS_START, for the same reason)

The collector's **first** network poll establishes a **silent baseline**
of already-`ESTABLISHED` (non-loopback) connections and reports nothing.
A collector restart re-establishes the baseline silently and does not
replay existing connections - reporting every already-open connection as
"new" merely because the collector restarted would be exactly as
misleading here as it would be for already-running processes (P2).

## Stable entity identity

`entityId` defaults to `HOST-<hostname>` (uppercased OS hostname via
`socket.gethostname()`), computed fresh every process start but always
identical on the same machine - see `collector/host_identity.py` for the
full derivation and its documented limitation (two machines sharing an
OS hostname would collapse to the same id; not solved here, deliberately
out of scope for a single demo machine). Override with `--entity-id` or
the `COLLECTOR_ENTITY_ID` environment variable.

**This entityId must already be registered in SentinelFlow
(`POST /api/v1/entities`, ADMIN) before the collector is started.** The
collector does not create entities itself - the existing project has no
safe auto-create mechanism for entities (only for the Event row itself,
via `EventProcessingLedgerService.persistOrLoad`), so none is added here.

## Install

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```
python collector\main.py
python collector\main.py --entity-id HOST-MYMACHINE --poll-interval 3 --process-poll-interval 15 --network-poll-interval 30 --verbose
```

`--poll-interval` (default 5s) controls session/LOGIN-LOGOUT polling.
`--process-poll-interval` (default **15s**, also settable via
`PROCESS_POLL_INTERVAL_SECONDS`) controls process polling independently -
it defaults higher because of the executable-path lookup cost described
above. `--network-poll-interval` (default **30s**, also settable via
`NETWORK_POLL_INTERVAL_SECONDS`) controls network polling independently -
it defaults higher to bound **event volume**, not CPU cost (the poll
itself is cheap - see above). All three pollers run on independent
cadences within the same process; there is no need to run separate
collector instances.

## Test

```
pytest tests\ -v
```

The Kafka integration test (`tests/test_integration_kafka.py`) skips
itself automatically if no broker is reachable at
`KAFKA_BOOTSTRAP_SERVERS` (default `localhost:9094`) - it is not required
for the rest of the suite to pass.

## Manual demo (Windows CMD)

Prerequisites: the SentinelFlow stack's Postgres+Kafka+backend+ML are up
(see the main project's `start-dev.bat` / `docker compose up -d`).

```cmd
rem 1. Register the physical entity (one-time; use the id collector\main.py
rem    will actually print on first run if you are not sure what your
rem    machine's hostname-derived id is).
curl -u admin:admin-dev-only-change-me ^
  -X POST http://localhost:8080/api/v1/entities ^
  -H "Content-Type: application/json" ^
  -d "{\"entityId\":\"HOST-YOURHOSTNAME\",\"entityType\":\"host\",\"displayName\":\"Physical collector demo host\"}"

rem 2. Confirm Kafka is reachable (already started by the main project's
rem    docker compose up -d; this just checks the container is healthy).
docker compose ps

rem 3. Start the physical collector (own window; leave running).
cd SentinelFlow-PhysicalCollector
.venv\Scripts\activate
python collector\main.py --verbose

rem 4. In a second window: observe published events directly from Kafka.
docker exec -it sentinelflow-kafka-1 /opt/kafka/bin/kafka-console-consumer.sh ^
  --bootstrap-server localhost:9092 --topic raw.events.v1 --from-beginning

rem 5. In a third window: run the simulator SIMULTANEOUSLY (unchanged,
rem    still source=python-simulator, still its own REST path).
cd ..\SentinelFlow-Python-Simulator-9.2\simulator
python simulator.py --scenario mixed --events 20 --interval 2

rem 6. Verify both sources landed in SentinelFlow (basic auth: analyst /
rem    analyst-dev-only-change-me, or admin as above).
curl -u analyst:analyst-dev-only-change-me "http://localhost:8080/api/v1/events?entityId=HOST-YOURHOSTNAME"
curl -u analyst:analyst-dev-only-change-me "http://localhost:8080/api/v1/events/<eventId>/trail"

rem 7. To see PROCESS_START telemetry specifically: start a harmless
rem    process while the collector is running (e.g. `notepad.exe`, then
rem    close it), wait up to --process-poll-interval seconds, and check:
curl -u analyst:analyst-dev-only-change-me "http://localhost:8080/api/v1/events?entityId=HOST-YOURHOSTNAME&eventType=PROCESS_START"

rem 8. To see NETWORK_CONNECTION telemetry specifically: establish a
rem    harmless outbound connection while the collector is running (e.g.
rem    curl an external site), wait up to --network-poll-interval
rem    seconds, and check:
curl -u analyst:analyst-dev-only-change-me "http://localhost:8080/api/v1/events?entityId=HOST-YOURHOSTNAME&eventType=NETWORK_CONNECTION"
```

Stop the collector with Ctrl+C - it finishes its current cycle, flushes
the Kafka producer, and exits cleanly (SIGINT/SIGTERM handled explicitly
in `collector/main.py`).

## Known limitations

- LOGOUT is only detected on the *next* poll after the OS session
  actually ends - precision is bounded by `--poll-interval`, not
  fabricated.
- The very first poll after the collector starts reports every
  already-active session as a LOGIN. This is a deliberate, documented
  choice (see `session_poller.py`): the reported `occurredAt` is still
  the real OS session-start time (which may be well before the collector
  itself started), not "now" - the collector is reporting a login it
  discovered, not one it fabricated as happening live. Process telemetry
  makes the opposite choice on purpose - see "Startup baseline" above.
- `ip`/`location` are essentially always absent for a local interactive
  session on Windows (verified empirically on the development machine:
  `psutil.users()` reports `host=None`, `terminal=None` for the local
  console session) - this is the genuine ceiling of this telemetry
  mechanism, not a bug.
- Two physical machines sharing the same OS hostname would collapse to
  the same default `entityId` - use `--entity-id` to disambiguate if this
  ever matters for a real multi-host deployment.
- PROCESS_START detection lags the real process start by up to
  `--process-poll-interval` (default 15s) - a fast-lived process that
  starts and exits entirely within one polling interval may never be
  observed. This is a real, accepted gap for this phase, not a bug to
  silently work around by polling more aggressively (which would
  reintroduce the CPU cost this design avoids).
- `executablePath` can be briefly unavailable for a process that exits
  between the cheap detection poll and the targeted lookup - omitted,
  not fabricated (see "Two-phase polling" above).
- The ML service currently does not understand any process-specific
  payload fields - `pid`/`processName`/`parentPid`/`username`/
  `executablePath` are not mapped into its canonical schema
  (`ml-service/anomaly-detection/api.py:_canonical_event`). A
  `PROCESS_START` event is still accepted and scored (confirmed: no
  event-type allowlist/enum exists anywhere in the backend or that
  adapter), just with every ML-side field at its generic default - the
  telemetry is safely preserved in PostgreSQL for future ML work, but
  does not yet influence risk scoring meaningfully. This is intentional
  for this phase, not an oversight - see the phase report for why no
  feature aliasing was added.
- Windows-specific: field availability (especially `username` for
  protected system processes) was verified only on this development
  machine's Windows build; behavior on other OS versions/permission
  configurations may differ, though the code path degrades gracefully
  (omits rather than errors) either way.
- Connection identity has no create_time-equivalent disambiguator (see
  "Connection identity and its limitation" above) - an exact repeat of
  the same 6-tuple after the original connection closed is
  indistinguishable from it persisting. Accepted trade-off for this
  phase's scope, not a bug.
- **Very short-lived connections can be missed entirely** - confirmed
  live during this phase's verification: a quick single-request HTTPS
  connection (connect, fetch, close) completed and left the `ESTABLISHED`
  state faster than a 5-second test interval could observe it, while an
  intentionally held-open connection was caught reliably. This is the
  same class of limitation as P2's fast-lived-process gap - bounded by
  `--network-poll-interval`, not silently worked around by polling more
  aggressively.
- **Event volume is real and was measured live on this machine, not
  assumed - and it varies a lot with actual activity:**
  - Quiet/background real activity (default 30s interval, ~90s window,
    genuinely idle-ish machine): **1 new `NETWORK_CONNECTION` in 90s**
    (≈40/hour extrapolated) - one background app reconnecting.
  - Deliberately-generated active-browsing burst (3 outbound HTTPS
    requests in a short window): **7 new `ESTABLISHED` connections in
    ~15s** (≈1,680/hour extrapolated).
  - The real number for any given machine depends entirely on how much
    it's actively doing - `ESTABLISHED`+non-loopback scope and the 30s
    default interval both exist specifically to keep this bounded rather
    than reporting every raw state transition, but a genuinely busy
    machine (many browser tabs, chat apps, continuous cloud sync) will
    still produce meaningfully more events than an idle one. Increase
    `--network-poll-interval` if this matters for a specific deployment.
- ML does not understand any network-specific payload fields, the same
  documented limitation pattern as P2's process fields -
  `protocol`/`localAddress`/`localPort`/`remoteAddress`/`remotePort`/
  `status`/`pid`/`processName` are not aliased into `_canonical_event`'s
  existing generic fields (`source_ip`, `resource_accessed`, etc.) -
  confirmed deliberately NOT done, per explicit instruction not to make
  the ML model appear to understand network telemetry it does not.
- **Privacy**: remote IP addresses reveal which external hosts/services a
  machine talks to. This is not a credential/secret, but it is real,
  potentially identifying metadata (which cloud providers, which
  DNS/VPN/chat/AI services) - documented here explicitly rather than
  treated as harmless. The event payload legitimately carries real IPs
  (that is the telemetry's purpose); collector logs never dump full
  payload bodies (only eventId/eventType/pid - existing
  `kafka_producer.py` behavior, unchanged in this phase).
