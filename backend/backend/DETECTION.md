# Deterministic Detection Engine

How SentinelFlow's rule-based detection works: its architecture, its rules, the
thresholds behind them, what it guarantees and — just as importantly — what it
does not.

This covers the **deterministic** path only. The **ML** path is separate and is
described at the end, under [Two independent detection paths](#two-independent-detection-paths).

---

## 1. Why this exists

SentinelFlow's original detection path was `EventProcessingService →
MlPredictionClient → PredictionService`. If the ML service is down, times out or
returns an error, **no alert is possible on that path for that event**, however
obviously suspicious the raw telemetry is.

The deterministic engine is a second, independent path. It never calls the ML
client, is unaffected by its availability, and reaches its verdict from the event
data alone. Both paths share only the `Alert → Incident → AlertFactor →
AuditLog` machinery.

---

## 2. Architecture

```
          Event (persisted, from the Kafka consumer or an admin replay)
                                   │
                         DeterministicRuleService          ← thin entry point, never throws
                                   │
                            DetectionEngine                ← the only place that decides
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
        RuleRegistry         RuleContext        CorrelationWindowService
      (explicit catalog)   (what a rule sees)   (bounded reads of `events`)
              │                    │
              └──────► DetectionRule.evaluate() ──────► DetectionMatch
                       (pure, stateless)                 │ severity
                                                         │ DetectionEvidence
                                                         │ suppression key
                                   ┌─────────────────────┘
                                   ▼
                       deduplicate → suppress → cooldown → escalate → raise
                                   │
                    AlertRepository / IncidentService / AlertFactor / AuditLog
```

### The pieces

| Type | Responsibility |
|---|---|
| `DetectionRule` | One rule. A **pure decision**: reads the event and a bounded window, returns a match or a reason. Holds no repository and cannot write anything. |
| `RuleContext` | What a rule is given: the triggering event plus bounded correlation accessors. "Now" is always the **event's own `occurredAt`**, never wall-clock time. |
| `DetectionMatch` | Severity, structured evidence, the message's lead clause, and optionally a suppression key. |
| `DetectionEvidence` | Structured evidence. The human-readable message is **generated from it**, so text and data can never disagree. |
| `DetectionEngine` | The single place that deduplicates, suppresses, escalates, raises, attaches incidents and audits. Every rule gets identical treatment. |
| `RuleRegistry` | The explicit, ordered catalog. No classpath scanning, no reflection. |
| `CorrelationWindowService` | Every read of correlation state, bounded by a window **and** a hard row cap. |
| `SeverityModel` | Severity from evidence and configured thresholds. No ML score ever reaches it. |
| `DetectionProperties` | Every operational threshold, bound from `detection.*`, validated at startup. |

### Adding rule N+1

1. Write a class implementing `DetectionRule`.
2. Add one line to `DetectionConfig.ruleRegistry()`.
3. Add its settings class to `DetectionProperties.Rules` and its block to `application.yml`.

Nothing else changes. No switch statement grows, no existing rule is touched, and
the new rule inherits deduplication, suppression, cooldown, escalation, incident
attachment and audit behaviour automatically — it cannot get them wrong, because
it never implements them.

---

## 3. Correlation state

**The correlation state is the `events` table.** There is no in-memory window, no
cache, no singleton map and nothing to expire.

This is a deliberate architectural choice, and it is what makes the resource
story short:

| Property | Why it follows |
|---|---|
| **Multi-instance correct** | Two application instances see the same window. An in-JVM map would give each a different, partial view, and detection would depend on which instance consumed the event. |
| **No unbounded growth to manage** | Nothing accumulates in the JVM. No TTL to tune, no eviction policy to get wrong, no cleanup task to fail. |
| **Restart and replay safe** | State cannot be lost on restart or diverge during a replay, because it is never a second copy of anything. |
| **Auditable** | Every event an alert cites can still be fetched and read. |

What *is* bounded, in one place:

* a **time window** — the rule's own configured window, backwards from the
  triggering event;
* a **hard row cap** — `detection.max-correlation-events` (default 500), applied
  to every query regardless of window;
* **newest-first ordering**, so when the cap truncates, what survives is the
  recent part a short-window rule cares about.

Truncation is **visible, not silent**: `WindowResult.truncated` is surfaced as
`windowTruncated: true` in the evidence, and a rule never presents a count from a
truncated window as exact.

### Resource audit

| Structure | Max size | TTL | Cleanup | Concurrency |
|---|---|---|---|---|
| Engine cache | *does not exist* | – | – | – |
| Per-rule state | *does not exist* | – | – | rules are stateless |
| Correlation query result | `max-correlation-events` (500) | the rule's window | none needed | per-call, never shared |
| `evidence.eventIds` | 25 | n/a | n/a | per-match |
| `evidence.destinations` | 15 | n/a | n/a | per-match |
| Alert factors per alert | 6 | n/a | n/a | per-alert |
| Active-alert scan (source-scoped rules) | 200 rows | n/a | n/a | per-call |

`DetectionStressTest` holds this down empirically: at 10,000 and at 50,000 stored
events the engine produced **identical** alert and factor counts (151 alerts, 604
factors), because five times the history does not mean five times the state.

---

## 4. The rules

| ID | Rule | Input events | Correlates by | Threshold (default) | Severity | MITRE | Expected output |
|---|---|---|---|---|---|---|---|
| **R001** | `AUTH_BURST` | `LOGIN` | entity | ≥5 failures / 5m | MEDIUM; HIGH at ≥10 | Credential Access · T1110 | One alert per burst, per entity |
| **R002** | `NEW_PROCESS_EXTERNAL_CONNECTION` | `NETWORK_CONNECTION`, `PROCESS_START` | entity + pid + `processCreateTime` | connection ≤5m after creation | MEDIUM | Command and Control · T1071 | One alert **per process identity** |
| **R003** | `PASSWORD_SPRAY` | `LOGIN` | **source address** | ≥5 distinct identities / 10m | MEDIUM; HIGH ≥10; CRITICAL ≥20 | Credential Access · T1110.003 | One alert per source, across entities |
| **R004** | `ACCOUNT_ENUMERATION` | `LOGIN` | **source address** | ≥10 identities **and** ≥15 attempts **and** success ratio ≤0.2 / 15m | MEDIUM; HIGH ≥20; CRITICAL ≥40 | Reconnaissance · T1589.002 | One alert per source |
| **R005** | `BRUTE_FORCE_SUCCESS` | `LOGIN` | entity | ≥5 failures then a success within 2m / 10m | **HIGH**; CRITICAL ≥10 failures | Credential Access · T1110 | Possible **compromise**, not just an attempt |
| **R006** | `IMPOSSIBLE_TRAVEL` | `LOGIN` | entity | ≥500 km **and** ≥900 km/h implied / 2h | HIGH; CRITICAL ≥3000 km/h | Initial Access · T1078 | Only where `location` is present |
| **R007** | `PRIVILEGE_ESCALATION_CHAIN` | `NETWORK_CONNECTION`, `FILE_ACCESS`, `PROCESS_START` | entity, **ordered** | all three stages in order / 10m | MEDIUM | Privilege Escalation · T1548 | Plausible sequence, **inferred** privilege |
| **R008** | `PROCESS_NETWORK_BURST` | `NETWORK_CONNECTION`, `PROCESS_START` | entity + pid + `processCreateTime` | ≥5 external connections / 60s | MEDIUM; HIGH ≥10; CRITICAL ≥20 | Command and Control · T1071 | One alert per process identity |
| **R009** | `NETWORK_CONNECTION_BURST` | `NETWORK_CONNECTION` | entity | ≥20 connections **and** ≥10 distinct destinations / 60s | MEDIUM; HIGH ≥40; CRITICAL ≥80 | Discovery · T1046 | Entity-wide fan-out |
| **R010** | `MULTI_STAGE_ATTACK_CHAIN` | `LOGIN`, `PROCESS_START`, `NETWORK_CONNECTION` | entity, **ordered** | ≥3 stages / 30m | HIGH; CRITICAL ≥4 stages | Multiple · T1110, T1543, T1071 | **Additional** correlation alert |

### Rules that look similar but are not

**R001 vs R003** — opposite axes.
`AUTH_BURST` is many failures against **one identity** (depth).
`PASSWORD_SPRAY` is one source against **many identities** (breadth).
Neither subsumes the other; activity that is both trips both, and that is correct.

**R003 vs R004** — three separate conditions keep them apart, and all three must
hold for R004: more breadth (10 vs 5 identities), a minimum volume (15 attempts,
which a spray's deliberately shallow pattern does not reach), and a success ratio
at or below 0.2 (R003 does not look at successes at all). R004 also runs over a
longer window, because enumeration is paced to stay quiet.

**R002 vs R008** — R002 is a new process making **one** external connection, and
it deliberately suppresses the rest (a freshly started browser opens dozens;
27 OPEN alerts for one pid were observed on the physical host before this
suppression existed). R008 is exactly the case R002 hides: that same process
making **many**. Both can fire for one process; they are two statements.

**R010 vs everything** — R010 **adds** an alert. It never suppresses, consumes or
supersedes the underlying ones. Its stages are read from **events, not alerts**,
so a correctly-suppressed `AUTH_BURST` does not silently remove a stage.

---

## 5. Severity

Severity is a function of the evidence and the configured thresholds, and nothing
else. **No ML score reaches `SeverityModel`** — a deterministic alert must stay
explainable from its own evidence alone.

The ladder: at or above `critical-threshold` → CRITICAL; at or above
`high-threshold` → HIGH; at or above `medium-threshold` → MEDIUM; otherwise LOW.
A threshold of `0` **disables that rung**, so a rule offers only the levels it can
justify. `AUTH_BURST` has no CRITICAL rung, because nothing in its evidence would
distinguish one.

Every alert carries a `severityReason` naming the number and the bar it crossed:

```
Severity HIGH: failed login attempts 12 reached the HIGH threshold of 10
```

---

## 6. Evidence

Every match produces structured `DetectionEvidence`; the message is **generated
from it**. A field is populated only when the event schema actually carried it —
there is no placeholder and no zero standing in for "unknown".

```
AUTH_BURST detected: 8 failed login attempts for entity HOST-07, within 56s,
threshold 5. Severity MEDIUM: failed login attempts 8 reached the MEDIUM
threshold of 5.
```

```
MULTI_STAGE_ATTACK_CHAIN detected: 6 failed logins -> successful login after
failures -> process curl started -> external connection to 198.51.100.23 for
entity HOST-07, within 4m 12s, threshold 3.
```

Evidence reaches three places: the generated message, up to six ranked
`alert_factors` rows (each truncated to the column's 128 characters **by
construction**), and the `DETECTION_CREATED` audit row's JSONB `details`.

---

## 7. Suppression, cooldown, deduplication and escalation

Checked in this order, and the order matters:

| Outcome | When |
|---|---|
| `DUPLICATE` | This exact event already raised this rule's alert. Checked **first**: a redelivery is not new activity and is not even recorded as a suppression. |
| `ESCALATED` | An alert is active, the new evidence is **strictly more severe**, and the rule has `escalate: true`. The active alert's severity is raised; no second alert. |
| `SUPPRESSED_ACTIVE_ALERT` | An alert for this rule and suppression key is still OPEN / ACKNOWLEDGED / INVESTIGATING. |
| `SUPPRESSED_COOLDOWN` | The last alert for this rule and key closed inside the configured cooldown. |
| `DETECTED` | None of the above — a new alert is raised. |
| `INSUFFICIENT_EVIDENCE` | The rule applies but its threshold was not met. |
| `NOT_APPLICABLE` | The rule does not consume this event type, or it is disabled. |

**Suppression keys.** Most rules suppress per (rule, entity). Two kinds differ:

* `R002` / `R008` key on the **process identity** (`pid@processCreateTime`), so a
  different process on the same host still raises its own alert;
* `R003` / `R004` key on the **source address** and search **across entities**,
  because their finding is about a source — without this, one spray against
  twenty accounts would raise twenty alerts.

**Escalation is off for R001 and R002**, which is why their behaviour is
unchanged from before this engine existed.

Every suppression is auditable: a `DETECTION_SUPPRESSED` row records the rule, the
absorbing alert, the candidate severity and a plain-English
`suppressionReason`. Suppression is recorded **once per (alert, rule, triggering
event)**, not once per processing attempt, so a retried event does not spam the
audit log.

---

## 8. Concurrency

Unchanged from the original implementation, and none of it depends on a
`synchronized` block or any in-JVM state — so it holds across multiple instances.

1. **Row lock.** The triggering event is locked `FOR UPDATE` **once per
   evaluation**, before any rule reads alert state. Two threads processing the
   same event (Kafka consumer and an admin replay) serialise here instead of both
   concluding "no alert yet".
2. **Application check.** `existsByEvent_IdAndRuleId`.
3. **Database guarantee.** `uk_alerts_event_rule` — `UNIQUE (event_id, rule_id)
   WHERE rule_id IS NOT NULL` (V15). Even if the lock were bypassed, the second
   insert fails rather than creating a duplicate. ML alerts (`rule_id IS NULL`)
   are unaffected.
4. **Incidents.** `IncidentService.findOrCreateIncident` relies on the
   `incident_key` unique constraint for the same reason.

A disabled rule set takes **no lock at all** — turning detection off costs
nothing rather than still serialising every event.

**Failure containment.** `evaluate()` never throws. Each rule runs in its own
try/catch, the whole evaluation has an outer one, and `EventProcessingService`
wraps the call as a third layer (the engine method is `@Transactional`, so a
failed repository call inside it can still throw at commit).

---

## 9. Configuration

Everything lives under `detection.*` in `application.yml`. **No rule reads a magic
number from its own source.** The application **refuses to start** if any of it is
inconsistent — a rule that silently never fires because its window is zero is
worse than one that is explicitly disabled.

```yaml
detection:
  enabled: true
  max-correlation-events: 500
  rules:
    auth-burst:
      enabled: true
      window: 5m
      medium-threshold: 5
      high-threshold: 10
      critical-threshold: 0      # 0 = rung disabled
      cooldown: 0s
      escalate: false
```

Validation rejects: a zero or negative window, a negative cooldown, a
non-positive primary threshold, an inverted severity ladder, a success ratio
outside 0–1, and a correlation cap below 1 — each naming the offending property.

`DetectionPropertiesBindingTest` binds the **real shipped block** and reads every
value back, so a typo'd property name (which Spring would otherwise ignore,
silently leaving the Java default) fails the build.

---

## 10. API

```
GET /api/v1/detection/rules      → ADMIN or ANALYST
```

Returns each rule's id, name, description, enabled flag, consumed event types,
reachable severities, MITRE tactic/technique and window.

It deliberately returns **no thresholds and no cooldowns**. Publishing
"`AUTH_BURST` fires at 5 failures in 5 minutes" tells anyone who can read it
exactly how far to stay under the bar; the operator-facing threshold table is
this document, not an API. The window is included because it describes the rule's
shape rather than its sensitivity.

The endpoint is read-only by construction — there is no way to enable, disable or
retune a rule through the API. Detection changes go through `application.yml` and
a restart, where they are reviewable.

---

## 11. Two independent detection paths

| | Deterministic rules | ML |
|---|---|---|
| Decides from | event data and configured thresholds | a model score |
| Guaranteed? | yes — satisfied by construction | no — score-dependent |
| Explainable from evidence alone? | yes | via factors and reason |
| Survives an ML outage? | **yes** | no |
| `alerts.rule_id` | set | `NULL` |
| `alerts.decision` | `SUSPICIOUS` | `NORMAL` / `KNOWN_ANOMALY` / `UNKNOWN_ANOMALY` |
| `alerts.policy_version` | `rules-v1` | `v2-ml-ensemble` |
| `prediction` | always `NULL` | set |
| `AlertResponse.detectionType` | `RULE` | `ML` |

The engine never reads a prediction, a score or a model decision;
`PredictionService` never reads a rule. `DetectionScenarioTest` asserts this
structurally — no type in the detection package may hold a field referencing the
ML package.

---

## 12. Limitations

Stated plainly, because a detection engine that overstates itself is worse than
one that detects less.

1. **No `PRIVILEGE_CHANGE` event type exists.** R007 infers elevation from
   `FILE_ACCESS.commandSequence` and process names (`sudo`, `su`, `runas`,
   `doas`, `pkexec`, `setuid`), matched on word boundaries. It detects a
   plausible *sequence*, not a confirmed privilege change, and every alert it
   raises carries `privilegeInferred: true`.

2. **`location` is self-reported.** It comes from the event payload; the physical
   collector performs **no geo-IP lookup** and omits the field entirely. R006
   therefore never fires on collector telemetry, only evaluates events that carry
   a parseable location, and states `locationSource` on every alert.

3. **`payload.ip` is the only source identity.** R003/R004 are defeated by source
   rotation, and a shared egress NAT can make many legitimate users look like one
   source. Both are properties of the available data.

4. **No "user does not exist" signal.** The only authentication outcome is
   `loginSuccess`, so R004 infers enumeration from breadth, volume and a near-zero
   success rate rather than from directory responses.

5. **"External" means non-loopback.** The payload carries no routing or interface
   information, so a LAN peer and an internet host are indistinguishable. R009's
   distinct-destination requirement is what keeps that definition usable.

6. **A truncated window under-counts.** Past `max-correlation-events`, a count is
   a floor rather than an exact figure — which the evidence declares rather than
   hiding.

7. **Severity thresholds are lab starting values**, not figures tuned against
   production traffic.

---

## 13. Future work

* A real `PRIVILEGE_CHANGE` event type, which would turn R007's inference into a fact.
* A GeoIP lookup at ingestion, which would make R006 apply to collector telemetry.
* Private-range classification for destinations, sharpening R008/R009.
* A stable source identity beyond `payload.ip` (session or device), hardening R003/R004 against rotation.
* Threshold tuning against real traffic, with false-positive measurement.

---

## 14. Tests

| Suite | Covers |
|---|---|
| `DeterministicRuleServiceTest` | **The original 20 tests, unchanged**, running against the re-implemented R001/R002. The backward-compatibility proof. |
| `AuthBurstRuleTest` | R001 thresholds, window boundaries, severity, evidence, config, suppression, escalation, locking |
| `IdentityRulesTest` | R003–R006, including spray-vs-enumeration separation and R006's refusal to assume a location |
| `EndpointRulesTest` | R002, R007–R009, including the no-tolerance correlation contract and cooldown |
| `DetectionEngineTest` | R010, rule-order invariance, replay idempotency, determinism, concurrency, bounded state, the catalog, config validation |
| `DetectionScenarioTest` | The end-to-end scenarios, through the full production rule set |
| `DetectionStressTest` | 10k and 50k events, one very busy entity, 5,000 entities, duplicates, out-of-order arrival |
| `DetectionPropertiesBindingTest` | The shipped `application.yml` block binds to the values it states |
| `DetectionRuleControllerTest` | The catalog endpoint leaks no configuration and is read-only |
