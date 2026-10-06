# SentinelFlow Physical Telemetry Collector 2.0

A small, independent **continuously running Windows endpoint telemetry
agent**. It observes this machine's login sessions, newly started
processes and newly established network connections, normalizes them into
the existing SentinelFlow canonical event contract, and publishes them to
the same Kafka topic the Python simulator already uses.

It does not depend on Spring Boot, the frontend, the ML service or the
simulator - it only needs Kafka reachable at the configured bootstrap
address, and it keeps collecting even when Kafka is not.

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

### What "real-time" means here, precisely

**Continuous near-real-time collection at each worker's configured
polling interval.** Each telemetry worker re-reads the OS's own tables
(processes, connections, sessions) on its own cadence and emits only what
changed since its previous read.

This is **not** kernel-level event capture. There is no ETW provider, no
kernel driver, no Windows Security Event Log subscription, and no packet
capture. The detection lag for any observation is bounded by that
worker's polling interval, and anything that begins and ends entirely
within one interval can be missed. That is a real, documented property of
this design - see "Known limitations".

---

## 1. Architecture

```
                      Windows Host
                           |
         +-----------------+-----------------+
         |                 |                 |
      Process           Network           Session        one thread each,
      Worker            Worker            Worker         own interval
         |                 |                 |
         +-----------------+-----------------+
                           |
                     Event Pipeline       normalize -> validate ->
                           |              deduplicate -> enqueue
                     Bounded Queue        (drop-oldest on overflow)
                           |
                    Kafka Publisher       one thread, one producer,
                           |              bounded exponential backoff
                         Kafka
```

and, around the workers:

```
                        Supervisor
                   /        |        \
            Process     Network     Session        (+ Kafka Publisher)
```

| Module | Responsibility |
|---|---|
| `collector/main.py` | CLI entry point: parse config, configure logging, install signal handlers, run the app. Nothing else. |
| `collector/app.py` | `CollectorApp` - the composition root. Builds every component exactly once and owns start/run/stop. |
| `collector/config.py` | All runtime configuration, from env + CLI, validated at startup. |
| `collector/workers.py` | `ProcessWorker` / `NetworkWorker` / `SessionWorker` - the continuous poll loops. |
| `collector/process_poller.py`<br>`collector/network_poller.py`<br>`collector/session_poller.py` | The stateful OS-diffing pollers (unchanged telemetry semantics from 1.x). |
| `collector/pipeline.py` | The one common path: enrich -> deduplicate -> normalize -> validate -> enqueue. |
| `collector/normalizer.py` | Raw observation -> canonical SentinelFlow event envelope. |
| `collector/dedup.py` | Bounded, TTL'd duplicate-suppression cache. |
| `collector/correlation.py` | Bounded, TTL'd process-metadata cache for process/network correlation. |
| `collector/event_queue.py` | The single bounded queue between telemetry and Kafka. |
| `collector/publisher_worker.py` | The single Kafka publisher worker. |
| `collector/kafka_producer.py` | `EventPublisher` - one `KafkaProducer`, retry/backoff, wire format. |
| `collector/supervisor.py` | Worker isolation, crash detection, restart with backoff. |
| `collector/health.py` | Thread-safe health snapshot and counters. |
| `collector/logging_utils.py` | Logging configuration and rate-limited warnings. |
| `collector/host_identity.py` | The stable `entityId` derivation. |

**Concurrency model: threads.** `psutil` and `kafka-python` are blocking
libraries, so there is no async I/O to overlap - `asyncio` would add an
event loop and a second mental model for no benefit, and
`multiprocessing` would add IPC to share a queue that threads share for
free. The collector runs 4 long-lived threads (3 telemetry + 1 publisher)
plus the main thread, which does nothing but log the periodic heartbeat.
**No worker ever busy-spins**: between polls each one blocks in
`stop_event.wait(seconds_until_next_poll)`, which also means shutdown is
instantaneous rather than waiting out an interval.

---

## 2. Requirements

- Windows 10/11 (the collector is cross-platform in principle; only
  Windows is verified - see "Windows permissions")
- Python 3.11+ (verified on 3.14)
- A reachable Kafka broker for events to actually land anywhere (the
  collector starts and buffers without one)
- **No administrator rights.** The collector deliberately does not read
  the Windows Security Event Log (event IDs 4624/4634/4688), which would
  need an elevated audit-policy change.

Dependencies (`requirements.txt`) - unchanged in 2.0, nothing new added:

```
psutil==7.2.2
kafka-python==3.0.11
pytest==9.1.1
```

## 3. Installation

```cmd
cd SentinelFlow-PhysicalCollector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 4. Running

```cmd
.venv\Scripts\activate
python collector\main.py
```

With explicit settings:

```cmd
python collector\main.py --entity-id HOST-MYMACHINE ^
    --poll-interval 5 --process-poll-interval 15 --network-poll-interval 30 ^
    --heartbeat-interval 60 --log-file collector.log --verbose
```

Stop it with **Ctrl+C**. See "Graceful shutdown" for exactly what happens.

> **Running it detached?** Send the output somewhere that is actually
> read - `--log-file`, or a shell redirect. A process whose stdout is a
> pipe nobody reads will eventually block on a full pipe buffer, which
> stalls logging and therefore every thread that logs. That is true of
> any program, not just this one, but it looks exactly like a hang.

### Register the entity first (one time)

**The collector's `entityId` must already exist in SentinelFlow before
published events will be accepted.** The collector does not create
entities itself - the project has no safe auto-create for entities (only
for the Event row, via `EventProcessingLedgerService.persistOrLoad`).

```cmd
rem The collector prints the id it will use on its first line.
curl -u admin:admin-dev-only-change-me ^
  -X POST http://localhost:8080/api/v1/entities ^
  -H "Content-Type: application/json" ^
  -d "{\"entityId\":\"HOST-YOURHOSTNAME\",\"entityType\":\"host\",\"displayName\":\"Physical collector host\"}"
```

## 5. Configuration

Every setting is resolvable from the environment **or** the command line,
with a validated default. You never have to edit Python source.

Resolution order, first non-empty wins: **CLI flag -> environment
variable -> default**. Invalid configuration raises a clear error and
exits with code `2` **before** any thread, socket or producer is created.

### Identity and Kafka

| Variable | CLI flag | Default | Meaning |
|---|---|---|---|
| `COLLECTOR_ENTITY_ID` | `--entity-id` | `HOST-<HOSTNAME>` | The SentinelFlow entity these events belong to. |
| `KAFKA_BOOTSTRAP_SERVERS` | `--kafka-bootstrap-servers` | `localhost:9094` | Same address Spring Boot uses. |
| `KAFKA_TOPIC` | `--topic` | `raw.events.v1` | The existing raw-event topic. Do not change unless the platform's topic changes. |

### Polling intervals

| Variable | CLI flag | Default | Meaning |
|---|---|---|---|
| `SESSION_POLL_INTERVAL` | `--poll-interval` | `5` s | Session/LOGIN-LOGOUT polling. |
| `PROCESS_POLL_INTERVAL` | `--process-poll-interval` | `15` s | Process/PROCESS_START polling. Higher because of the executable-path lookup cost (see below). |
| `NETWORK_POLL_INTERVAL` | `--network-poll-interval` | `30` s | Network/NETWORK_CONNECTION polling. Higher to bound **event volume**, not CPU. |

The pre-2.0 names `PROCESS_POLL_INTERVAL_SECONDS` and
`NETWORK_POLL_INTERVAL_SECONDS` are still accepted as fallbacks.

### Queue, deduplication and correlation

| Variable | CLI flag | Default | Meaning |
|---|---|---|---|
| `QUEUE_MAX_SIZE` | `--queue-max-size` | `5000` | Central bounded queue capacity. |
| `DEDUP_TTL_SECONDS` | `--dedup-ttl` | `3600` | How long a deduplication key is remembered. |
| `DEDUP_MAX_ENTRIES` | `--dedup-max-entries` | `10000` | Maximum deduplication keys retained. |
| `CORRELATION_TTL_SECONDS` | - | `300` | How long process metadata is kept for correlation. |
| `CORRELATION_MAX_ENTRIES` | - | `2000` | Maximum cached process-metadata entries. |

### Kafka reliability

| Variable | CLI flag | Default | Meaning |
|---|---|---|---|
| `KAFKA_RETRY_BASE_DELAY` | `--kafka-retry-base-delay` | `5` s | First retry delay after a publish failure. |
| `KAFKA_RETRY_MAX_DELAY` | `--kafka-retry-max-delay` | `60` s | Upper bound on the retry backoff. |
| `KAFKA_MAX_PENDING_EVENTS` | - | `1000` | The publisher's own in-flight buffer bound. |

### Supervision, shutdown and logging

| Variable | CLI flag | Default | Meaning |
|---|---|---|---|
| `WORKER_RESTART_BASE_DELAY` | `--worker-restart-base-delay` | `1` s | First delay before restarting a crashed worker. |
| `WORKER_RESTART_MAX_DELAY` | `--worker-restart-max-delay` | `30` s | Upper bound on the restart backoff. |
| `WORKER_HEALTHY_RESET_SECONDS` | - | `120` s | How long a worker must stay healthy before its restart backoff resets. |
| `SHUTDOWN_TIMEOUT_SECONDS` | `--shutdown-timeout` | `15` s | Budget for draining the queue during shutdown. |
| `HEARTBEAT_INTERVAL_SECONDS` | `--heartbeat-interval` | `60` s | Interval between one-line health summaries. |
| `LOG_LEVEL` | `--log-level` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL`. |
| `LOG_FILE` | `--log-file` | - | Also write logs to this file. |
| - | `--verbose` | off | Forces `DEBUG`, overriding `LOG_LEVEL`. |

**No secrets are read, held, or logged anywhere in this collector.** The
bootstrap address is logged because it is operational topology, not a
credential.

---

## 6. Telemetry sources

### Session telemetry (LOGIN / LOGOUT)

Source: local interactive login sessions via `psutil.users()` -
cross-platform, no admin rights.

| Field | LOGIN | LOGOUT | Notes |
|---|---|---|---|
| `loginSuccess` | always `true` | - | session polling can only see a session that IS active; a failed login attempt is invisible to this mechanism and is never fabricated |
| `sessionDurationMinutes` | - | real measurement | `(observed - started) / 60`, both real timestamps |
| `username` | when reported | - | |
| `ip` | only if psutil reports a genuine remote host | same | on a local console session this is `None` (verified) - most runs omit it |
| `location` | never | never | no geo-IP lookup is performed |

The **first** session poll reports every already-active session as a
LOGIN. That is deliberate: `occurredAt` is still the real OS session-start
time, so the collector is reporting a login it *discovered*, not one it
fabricated as happening live.

### Process telemetry (PROCESS_START)

Source: `psutil.process_iter()` / `psutil.Process` - no admin rights
(verified empirically: ~300 processes enumerated, zero `AccessDenied`).

| Field | Included when | Notes |
|---|---|---|
| `pid` | always | |
| `processName` | psutil reports a non-empty name | omitted rather than sent as `""` |
| `parentPid` | available (including `0`, a legitimate root value) | |
| `username` | psutil can resolve it | omitted for protected system processes (e.g. `csrss.exe`) |
| `executablePath` | a targeted per-process lookup succeeds | omitted, never fabricated, if the process exited first |

**Two-phase polling (why the interval defaults higher).** Measured on the
development machine, not assumed:
`psutil.process_iter(['pid','name','ppid','create_time','username'])` over
~300 processes costs **~40ms**; adding `exe` to that *same* bulk call costs
**~3,100ms**. So the bulk detection poll never requests `exe`, and
`executablePath` is looked up with **one targeted call per genuinely new
process only** - cost scales with how many processes just started, never
with the size of the process table.

**Process identity is `(pid, create_time)`,** never `pid` alone. The OS
reuses PIDs; a reused PID gets a new `create_time` and is correctly
treated as a different process.

**Startup baseline:** the first process poll establishes a **silent**
baseline and reports nothing. Reporting hundreds of already-running
system processes as "PROCESS_START" because the collector restarted would
be misleading and would flood Kafka/Postgres on every start.

### Network telemetry (NETWORK_CONNECTION)

Source: `psutil.net_connections(kind='inet')` - no admin rights (verified:
183-210 connections enumerated repeatedly, zero `AccessDenied`).

| Field | Included when | Notes |
|---|---|---|
| `protocol`, `localAddress`, `localPort`, `remoteAddress`, `remotePort`, `status` | always | `status` is always `ESTABLISHED` in this scope |
| `pid` | psutil reports a non-zero owning pid | |
| `processName` | a live lookup succeeds, **or** the correlation cache can fill it | see "Process / network correlation" |
| `processCreateTime` | same | the owning process's real `create_time`, ISO-8601 |

**Scope, deliberately narrow:**
- **`ESTABLISHED` only.** `LISTEN` sockets are standing configuration, not
  activity. `TIME_WAIT` connections were empirically confirmed to always
  report `pid=0` on this platform. UDP reports status `NONE`.
- **Non-loopback remote address only.** `127.0.0.0/8` and `::1` are
  machine-to-itself traffic (e.g. Docker's own containers) - excluded as
  noise. **Private/LAN addresses (`10.x`, `192.168.x`) are kept** - this
  collector is not restricted to public-Internet connections.
- No packet contents, DNS contents, TLS internals, or credentials - none
  of these are exposed by `psutil.net_connections()` in the first place,
  so there is nothing to strip; the collector simply never asks.

**Collection cost:** `net_connections()` costs ~1.4ms for ~200
connections. The 30s default interval exists to bound **event volume**,
not CPU.

### What is never collected, from any source

Passwords, secrets, tokens, API keys, environment variables, file
contents, memory contents, packet payloads, and **command-line arguments
(`cmdline`)**. `cmdline` is never even *requested* from the OS anywhere in
this codebase - command lines routinely carry embedded credentials in the
real world, so they are out of scope entirely, not merely "not sent".

Nothing is ever set to a placeholder like `"unknown"`. A field either
carries a real value or is **omitted** from `payload`, matching the
simulator's own payload builders and the ML adapter's existing defaults.

### PROCESS_END - deliberately not emitted

The collector detects when a process disappears (and drops it from its
state immediately), but **emits no event for it**. `PROCESS_END` does not
exist anywhere in the SentinelFlow contract - not in the backend, the
frontend's simulator types, the deterministic rules, or the ML adapter -
and inventing an event type the platform has no definition for would be
worse than the gap. If the contract gains one, `workers.py` is the single
place that would need to emit it.

---

## 7. Event types and the canonical envelope

Every event, from every source, has exactly this shape:

```json
{
  "eventId":      "EV-PHYS-1791318284370-7e952b",
  "entityId":     "HOST-LAPTOP-HIK1MN09",
  "eventType":    "NETWORK_CONNECTION",
  "eventVersion": "v1",
  "occurredAt":   "2026-10-06T20:24:44Z",
  "source":       "physical-collector",
  "payload":      { }
}
```

The collector emits exactly four event types: **`LOGIN`**, **`LOGOUT`**,
**`PROCESS_START`**, **`NETWORK_CONNECTION`**. Anything else is rejected
by the pipeline's validator rather than published.

**`occurredAt` is the real instant, not "now"**, wherever the OS gives
one: a process's real `create_time`, a session's real start time. Only
`NETWORK_CONNECTION` uses the detection instant, because psutil's
connection table carries no equivalent timestamp.

Wire format: a plain JSON string keyed by `eventId`, compatible with the
Spring Boot side's `StringSerializer`/`StringDeserializer` as-is. No new
topic, no new serialization, no schema registry.

---

## 8. Deduplication

Continuous polling makes duplicate suppression mandatory. There are two
independent layers:

1. **The pollers' own diffing** - each poller compares the current OS
   snapshot against its previous one and yields only what changed. Its
   state is *replaced* by the current snapshot on every poll, so it is
   bounded by the size of the live OS table and forgets things that go
   away.
2. **The pipeline's deduplication cache** - a second layer that survives
   a poller being rebuilt (which is what a supervised worker restart
   does). Without it, a restarted session worker would re-publish the
   active session's LOGIN with a *new* `eventId`, which the backend's
   `eventId`-based idempotency could not catch.

| Event | Deduplication key | Why |
|---|---|---|
| `PROCESS_START` | `(pid, create_time)` | The OS's own process identity. `create_time` is what makes a reused PID a different process. |
| `NETWORK_CONNECTION` | `(protocol, localAddress, localPort, remoteAddress, remotePort, pid)` | The connection 6-tuple. **`status` is excluded** - a tracked connection's status can change (`ESTABLISHED` -> `CLOSE_WAIT`) without being a new connection. |
| `LOGIN` / `LOGOUT` | `(kind, username, started_epoch)` | One real login instant per `(username, started)` pair. `kind` is included so a session's LOGOUT is not suppressed as a duplicate of its LOGIN. |

**Bounds (this is not a `set()` that grows forever):** entries expire
after `DEDUP_TTL_SECONDS` (default 1h) and the cache holds at most
`DEDUP_MAX_ENTRIES` (default 10,000), evicting oldest-first. A duplicate
hit deliberately does **not** refresh the TTL - otherwise a persistent
connection re-observed every poll would suppress itself forever.

---

## 9. Process / network correlation

The backend's `NEW_PROCESS_EXTERNAL_CONNECTION` rule correlates a
`NETWORK_CONNECTION` to a `PROCESS_START` by exactly:

```
NETWORK_CONNECTION.payload.pid               == PROCESS_START.payload.pid
NETWORK_CONNECTION.payload.processCreateTime == PROCESS_START.occurredAt   (exact string)
```

The live `psutil` lookup fails precisely when it matters most - a
short-lived process that connects and then exits. So the process worker
feeds a **bounded, TTL'd process-metadata cache**, and the pipeline uses
it to fill `processName`/`processCreateTime` when the live lookup
returned nothing.

Safety rules, because a pid-keyed cache can mislabel on PID reuse:

1. The cache is consulted **only** when the live lookup produced nothing.
   Live truth always wins.
2. An entry is used only within `CORRELATION_TTL_SECONDS` (default 300s),
   which also matches the backend rule's own 5-minute recency window.
3. If the live lookup *did* return a `create_time` and it disagrees with
   the cached one, the pid was reused - the cached name is discarded.
4. Re-observing a pid replaces its entry outright.

**This is telemetry enrichment only.** No rule, no score and no alert is
ever evaluated in the collector; detection stays entirely in the backend.

---

## 10. Queue and backpressure

One central bounded queue sits between the telemetry workers and the
Kafka publisher.

- **Capacity:** `QUEUE_MAX_SIZE` (default 5000 events, roughly 2-3 MB at
  this project's real event sizes).
- **Overflow policy: DROP OLDEST.** A full queue means Kafka has been
  unreachable long enough to accumulate 5000 events. At that point the
  *newest* observations are the ones worth keeping - they describe what
  the host is doing now, which is what an analyst responding to an
  incident needs. Every drop is counted and logged (rate-limited), never
  silently discarded.
- **It never blocks.** A telemetry worker enqueuing into a full queue
  returns immediately. Blocking would freeze the host observation itself,
  which is the single worst failure mode for a security agent.
- **Pressure warning** at 80% capacity, rate-limited to one message per
  minute.
- **Requeue preserves order:** an event the publisher could not send goes
  back to the *front*.

---

## 11. Kafka reliability

- **Exactly one `KafkaProducer`** for the collector's lifetime, owned by
  exactly one publisher thread. Never one per event, per worker or per
  retry.
- **The publisher stops draining the queue while it is backing off.**
  This is what makes the central bounded queue the real outage buffer,
  with one overflow policy and one dropped-event counter, instead of two
  competing buffers dropping events at different thresholds.
- **Bounded exponential backoff:** `KAFKA_RETRY_BASE_DELAY` doubling to
  `KAFKA_RETRY_MAX_DELAY` (default 5s -> 10s -> 20s -> 40s -> 60s, then
  capped). No busy loops - the publisher sleeps on the stop event, so it
  still wakes instantly on shutdown.
- **Retries are safe:** a re-sent event keeps its original `eventId`, and
  the backend ledger is idempotent on `eventId`.
- **Draining is paced,** not dumped: at most 50 events per iteration,
  each awaiting its acknowledgement, so a recovered broker sees a steady
  stream rather than several thousand records at once.
- **Starting without a broker is fine.** `kafka-python` raises from the
  producer *constructor* when nothing answers; the publisher worker
  retries construction with the same backoff while telemetry collection
  is already running and buffering.

---

## 12. Worker supervision and recovery

Each worker runs under a supervisor, with two distinct failure levels:

| Level | What happened | Result |
|---|---|---|
| **DEGRADED** | One poll raised (transient `AccessDenied`, a momentarily unreadable table) | Logged (rate-limited), the worker stays alive and retries at its next interval. Other workers are untouched. |
| **FAILED -> restart** | 5 consecutive polls failed, or the worker loop itself escaped | The supervisor logs it with a traceback, waits with backoff, rebuilds the worker's poller state, and runs it again. |

- Restart backoff: `WORKER_RESTART_BASE_DELAY` doubling to
  `WORKER_RESTART_MAX_DELAY` (default 1s -> 2s -> 4s -> ... -> 30s). It
  resets to the base delay only after the worker has run healthily for
  `WORKER_HEALTHY_RESET_SECONDS` - resetting on every restart would turn
  a crash loop into a 1-second crash loop.
- **No duplicate workers, structurally:** each worker has exactly one
  supervisor thread for the collector's whole life, and a "restart" is
  the next iteration of that same thread's loop. There is no window in
  which two instances can exist.
- A worker is **never** restarted for being idle - only an actual escaped
  exception triggers a restart.
- A worker crash is isolated: `Process = FAILED` while
  `Network = Session = Kafka = RUNNING`.

---

## 13. Health and logging

### Health

The collector maintains a thread-safe health snapshot containing only
counters and small fixed-size state - never a list of events or a history
of samples, so it cannot grow over a 24-hour run.

```
collector : state, started_at, uptime
per worker: state, last_success, last_error, error_count, restart_count, poll_count
kafka     : state, last_successful_publish, consecutive_failures, retry_count
queue     : current_depth, max_depth, capacity, dropped_events, total_enqueued, total_published
events    : generated, normalized, validated, published, failed, dropped, deduplicated, invalid
```

It is exposed through the heartbeat log line and programmatically via
`app.health.snapshot()`. **There is deliberately no HTTP endpoint** -
opening a listening port on an endpoint agent is a real scope (and
security) decision, not a free addition.

### Logging

| Level | Used for |
|---|---|
| `DEBUG` | Per-event publish confirmations, dedup suppressions, correlation hits |
| `INFO` | Lifecycle (start/stop/restart/recovery), one line per *detected* event, the periodic heartbeat |
| `WARNING` | Kafka unavailable, queue pressure, dropped events, poll failures |
| `ERROR` | Worker crashes (with traceback), events rejected by validation |

```
Collector heartbeat state=RUNNING uptime=120s queue=0/5000 maxDepth=6 generated=26
  published=26 deduplicated=0 dropped=0 failed=0 kafka=RUNNING kafkaFailures=0
  workers[kafka-publisher=RUNNING network=RUNNING process=RUNNING session=RUNNING]
```

- **Event payload bodies are never logged.** Only
  `eventId`/`eventType`/`entityId`/`pid`-shaped operational metadata. This
  matters because a `NETWORK_CONNECTION` payload carries real remote IPs.
- **Repetitive warnings are rate-limited** to one per minute per
  condition, and the next one says how many were suppressed.
- **There is no message per poll cycle** - continuous counters are
  reported in the periodic heartbeat instead.
- `kafka-python`'s own very chatty `INFO` connection/metadata logging is
  suppressed to `WARNING` unless `--verbose` is used.

---

## 14. Graceful shutdown

On **Ctrl+C**, `SIGINT`, `SIGTERM` or `SIGBREAK` (whichever the platform
has), the handler does the minimum legal work - it sets an `Event` and
returns - and the shutdown then runs on the main thread:

1. Mark the collector `STOPPING`.
2. Signal the telemetry workers and join them. They wake instantly from
   their interval wait, so this takes milliseconds.
3. Close the queue to **new** telemetry. Already-queued events stay.
4. Stop the publisher thread, so nothing competes for the queue.
5. Drain the queue for at most `SHUTDOWN_TIMEOUT_SECONDS`.
6. Close the Kafka producer (which makes one final send attempt
   regardless of backoff, then flushes and closes).
7. Log the final counters.

**Nothing waits forever**, and if the queue could not fully drain the
remaining count is logged explicitly as a `WARNING` - the loss is
reported, never silently discarded. A second Ctrl+C cuts the drain short.

---

## 15. Testing

```cmd
.venv\Scripts\activate
pytest tests\ -v
```

**394 tests**, covering configuration, every poller, the pipeline,
deduplication, correlation, the queue, the publisher, supervision,
health, shutdown, resource bounds and long-run stability.

Normal unit tests never require a real broker, real Windows processes,
real network connections or real credentials. The only test that touches
real infrastructure is `tests/test_integration_kafka.py`, which **skips
itself automatically** if no broker is reachable.

### Deterministic long-run stress tests

`tests/test_long_run_stress.py` simulates **30 minutes and 1 hour** of
continuous operation - with process churn, network churn, duplicate
observations, two Kafka outages, two telemetry-source failures with
supervised restart, and sustained queue pressure - **without sleeping**.
A simulated hour costs about 0.05 seconds of real time, so it runs on
every commit instead of being a thing nobody ever runs. It drives the
*same* methods the real threads drive; only the scheduler and the clock
are swapped.

---

## 16. Manual end-to-end demo (Windows CMD)

Prerequisites: the main stack is up (`docker compose up -d`).

```cmd
rem 1. Register the entity (one time) - see "Register the entity first".

rem 2. Start the collector; leave it running.
cd SentinelFlow-PhysicalCollector
.venv\Scripts\activate
python collector\main.py --verbose

rem 3. In a second window: watch events arrive on Kafka directly.
docker exec -it sentinelflow-kafka-1 /opt/kafka/bin/kafka-console-consumer.sh ^
  --bootstrap-server localhost:9092 --topic raw.events.v1

rem 4. Generate harmless real telemetry: open and close Notepad, visit a
rem    website. Wait up to one polling interval.

rem 5. Verify it landed in SentinelFlow.
curl -u analyst:analyst-dev-only-change-me ^
  "http://localhost:8080/api/v1/events?entityId=HOST-YOURHOSTNAME&eventType=PROCESS_START"
curl -u analyst:analyst-dev-only-change-me ^
  "http://localhost:8080/api/v1/events?entityId=HOST-YOURHOSTNAME&eventType=NETWORK_CONNECTION"
```

To see outage behavior: `docker compose stop kafka`, watch the collector
keep collecting and buffering, then `docker compose start kafka` and watch
it drain.

---

## 17. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Invalid collector configuration: ...` and exit code 2 | A setting is out of range or unparseable. The message names the setting. |
| `Cannot connect to Kafka ... retrying in Ns` | The broker is unreachable. The collector is still collecting and buffering; it will connect by itself. Check `KAFKA_BOOTSTRAP_SERVERS` and `docker compose ps`. |
| `Kafka unavailable - buffering telemetry in the bounded queue` | The broker went away mid-run. Expected behavior; it recovers automatically. |
| `Event queue at 80% capacity` | Kafka is slow or down for a while. If it happens with a healthy broker, raise `QUEUE_MAX_SIZE`. |
| `Event queue full ... dropped the oldest queued event` | A long outage. Raise `QUEUE_MAX_SIZE` if the host must survive longer outages without loss. |
| Events published but not visible via the API | The `entityId` is probably not registered - see "Register the entity first". The collector publishes regardless; the backend rejects events for unknown entities. |
| `<worker> poll failed (N consecutive)` | A transient OS error. The worker stays alive; after 5 in a row it is restarted with fresh state. |
| No `PROCESS_START` for a process you just ran | It may have started *and exited* within one `--process-poll-interval`. Lower the interval (at the documented CPU cost) or accept the gap. |
| Nothing is logged at all, process appears hung | Its stdout is a pipe nobody is reading. Use `--log-file` or redirect to a file. |
| The collector seems to "re-report" things after a restart | It does not - the dedup cache suppresses re-baselined observations for `DEDUP_TTL_SECONDS`. After that TTL, a still-present thing can legitimately be reported again. |

---

## 18. Windows permissions

- **No administrator rights are required** and none are requested.
- `psutil.users()`, `psutil.process_iter()` and `psutil.net_connections()`
  all work for a normal interactive user on Windows 10/11 (verified
  empirically: ~300 processes and ~200 connections enumerated repeatedly
  with zero `AccessDenied` errors, including a SYSTEM-owned process's own
  connections).
- `username` is `None` for a handful of protected system processes (e.g.
  `csrss.exe`, `smss.exe`) - that is expected, and the field is omitted.
- If a telemetry source *is* restricted on some locked-down configuration,
  that subsystem degrades (and is restarted) while the others keep
  running. A permission limitation never takes the collector down.

---

## 19. Known limitations

**Collection semantics**

- **Polling, not kernel events.** Detection lags the real event by up to
  that worker's interval, and anything starting and ending entirely
  within one interval can be missed. Confirmed live: a quick single
  HTTPS request completed and left `ESTABLISHED` faster than a 5-second
  test interval could observe it, while a held-open connection was caught
  reliably.
- **`PROCESS_END` is not emitted** - see above.
- **Connection identity has no `create_time` equivalent.** An exact
  repeat of the same 6-tuple after the original closed is
  indistinguishable from the original persisting, and is suppressed as a
  duplicate within the dedup TTL.
- **The first session poll reports already-active sessions as LOGIN** (a
  deliberate, documented choice - process and network telemetry make the
  opposite choice for their own documented reason).
- **`ip`/`location` are essentially always absent** for a local
  interactive Windows session - the genuine ceiling of `psutil.users()`,
  not a bug.
- **Two machines sharing an OS hostname** collapse to the same default
  `entityId`. Use `--entity-id` to disambiguate.

**Durability**

- **The queue is in-memory and is not persisted.** Events still queued
  when the collector itself stops are lost; the shutdown log says how
  many. Surviving a collector restart would need an on-disk spool, which
  is a deliberate non-goal here.
- **A long enough outage drops the oldest events.** Bounded memory was
  chosen over unbounded retention; the count is always reported.

**Event volume** (measured live, and it varies a lot with real activity)

- Quiet machine, default intervals: ~1 new `NETWORK_CONNECTION` per 90s
  (~40/hour).
- Active browsing burst: 7 new connections in ~15s (~1,680/hour
  extrapolated).
- A busy machine (many tabs, chat apps, cloud sync) will produce
  meaningfully more. Raise `--network-poll-interval` if that matters.

**Downstream**

- **The ML service does not understand process- or network-specific
  payload fields.** `pid`/`processName`/`parentPid`/`executablePath`/
  `protocol`/`remoteAddress`/... are not mapped into
  `ml-service/anomaly-detection/api.py:_canonical_event`. Such events are
  still accepted, persisted and scored, just with every ML-side field at
  its generic default. This is intentional - no feature aliasing was
  added that would make the model *appear* to understand telemetry it
  does not. The deterministic rule
  `NEW_PROCESS_EXTERNAL_CONNECTION` **does** use this telemetry fully.

**Verification scope**

- Field availability was verified on one Windows 11 machine. Behavior on
  other OS versions or permission configurations may differ, though every
  code path degrades gracefully (omit rather than error).

---

## 20. Security considerations

- **No credentials are read, held or logged** by this collector.
- **Command-line arguments are never collected** - not merely omitted
  from the payload, but never requested from the OS - because they
  routinely carry embedded secrets in real deployments.
- **Remote IP addresses are real, identifying metadata.** The payload
  legitimately carries them (that is the telemetry's purpose), but they
  reveal which external services a machine talks to. Collector logs never
  dump payload bodies.
- **No packet capture, no DPI, no DNS inspection.**
- **No listening port.** The collector opens outbound connections to
  Kafka only; it exposes no API, so it adds no attack surface to the host.
- **The published event stream is as sensitive as the host it runs on.**
  Treat `raw.events.v1` and the collector's log file accordingly.
- **Detection logic lives in the backend, never here.** The collector
  cannot raise an alert, so a compromised or misconfigured collector can
  degrade or falsify *telemetry*, but cannot by itself suppress or
  fabricate a *verdict*.
