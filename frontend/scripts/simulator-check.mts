// Self-check for src/simulator (no test framework: plain Node + assert).
// Run: npm run check:simulator   (Node 22.18+ strips the TypeScript types itself)
//
// LEGACY below is a verbatim copy of the scenario builders as they were in pages/Simulator.tsx
// before they moved to src/simulator/builders.ts. It is the frozen reference the extracted
// builders must reproduce exactly.
import assert from 'node:assert/strict';

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { eventCount, eventGroups, ORIGINAL_SCENARIO_IDS, scenarioById, scenarioGroups, SCENARIOS } from '../src/simulator/scenarioRegistry.ts';
import { validateEvents } from '../src/simulator/validation.ts';
import {
  AUTH_BURST_HIGH_THRESHOLD,
  AUTH_BURST_THRESHOLD,
  DURATION_PRESETS,
  INTENSITIES,
  MAX_CUSTOM_DURATION_SEC,
  MAX_EVENT_BYTES,
  MAX_EVENT_RATE,
  MAX_TARGETS,
  MIN_CUSTOM_DURATION_SEC,
  NOISE_OPTIONS,
  PATTERNS,
  PROCESS_CREATE_TIME,
  RATE_OPTIONS,
  RULE_WINDOW_MINUTES,
} from '../src/simulator/types.ts';
import { canTransition, clampRate, describeError, SimulationEngine } from '../src/simulator/engine.ts';
import {
  buildPreview,
  canStart,
  DEFAULT_CONFIG,
  detectionSummary,
  needsConfirmation,
  newRunId,
  resolveDurationMs,
  resolveTargets,
  segmentShifts,
  sendsWithin,
  toRunPlan,
  validateConfig,
} from '../src/simulator/planner.ts';
import { buildNoise, noiseCount, processCreateTime } from '../src/simulator/advancedBuilders.ts';
import { completionSummary, filterRows, LiveConsole } from '../src/simulator/liveConsole.ts';
import { currentSegment, planInfo, segmentProgress } from '../src/simulator/planner.ts';
import {
  buildHistoryEntry,
  detectionVerdict,
  filterHistory,
  HISTORY_KEY,
  HISTORY_VERSION,
  MAX_HISTORY_ENTRIES,
  observationQuality,
  observedFromEntry,
  observedTerminal,
  parseHistory,
  RunHistoryStore,
  serializeHistory,
  shouldPersist,
} from '../src/simulator/runHistory.ts';
import {
  applyPreset,
  ARCHITECTURE_FLOW,
  assessDemo,
  DEMO_CHECKLIST,
  DEMO_PRESETS,
  DETECTION_LABEL,
  DETECTION_LEGEND,
  demoById,
  expectedLines,
  formatScore,
  observedLines,
  presetCategory,
  presetLimitations,
  presetScenario,
  presetScenarioEventCount,
  scoreBand,
} from '../src/simulator/demoPresets.ts';
import type { DemoPreset } from '../src/simulator/demoPresets.ts';
import { ALERT_THRESHOLD, SEVERITY_BANDS } from '../src/simulator/types.ts';
import {
  ACTIVITY_LIMIT,
  LIVE_ROW_HARD_LIMIT,
  LIVE_ROW_LIMIT,
  TRAIL_MAX_ATTEMPTS,
  TRAIL_OBSERVATION_MS,
  TRAIL_POLL_BATCH,
  TRAIL_POLL_INTERVAL_MS,
} from '../src/simulator/types.ts';

type CreateEventRequest = {
  eventId: string; entityId: string; eventType: string; eventVersion: string; occurredAt: string; source: string; payload: Record<string, unknown>;
};

/* ---------------- frozen reference: original pages/Simulator.tsx code ---------------- */
type Ctx = { entityId: string; prefix: string; now: number; intensity?: string };
const HOME = 'Pune|18.52|73.86';
const HOME_IP = '10.24.7.18';
const HOME_DEVICE = 'Ubuntu 22.04|b0:17:7e:e2:b5:c2|TLS1.2';
const ev = (c: Ctx, i: number, offsetSec: number, eventType: string, payload: Record<string, unknown>): CreateEventRequest => ({
  eventId: `${c.prefix}-${String(i + 1).padStart(2, '0')}`,
  entityId: c.entityId,
  eventType,
  eventVersion: 'v1',
  occurredAt: new Date(c.now + offsetSec * 1000).toISOString(),
  source: 'simulator',
  payload,
});
const LEGACY: Record<string, (c: Ctx) => CreateEventRequest[]> = {
  routine: (c) => [
    ev(c, 0, -240, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'password', deviceFingerprint: HOME_DEVICE }),
    ev(c, 1, -120, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/docs/handbook.pdf', action: 'read', deviceFingerprint: HOME_DEVICE }),
    ev(c, 2, 0, 'LOGOUT', { ip: HOME_IP, location: HOME, sessionDurationMinutes: 38, deviceFingerprint: HOME_DEVICE }),
  ],
  brute: (c) => [
    ...Array.from({ length: 8 }, (_, i) =>
      ev(c, i, -80 + i * 8, 'LOGIN', { ip: '185.220.101.44', location: 'Moscow|55.75|37.61', loginSuccess: false, authMethod: 'password', deviceFingerprint: 'Unknown|00:00:00:00:00:00|TLS1.0' }),
    ),
    ev(c, 8, 0, 'LOGIN', { ip: '185.220.101.44', location: 'Moscow|55.75|37.61', loginSuccess: true, authMethod: 'password', deviceFingerprint: 'Unknown|00:00:00:00:00:00|TLS1.0' }),
  ],
  travel: (c) => [
    ev(c, 0, -300, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'password', deviceFingerprint: HOME_DEVICE }),
    ev(c, 1, 0, 'LOGIN', { ip: '102.89.34.7', location: 'Lagos|6.52|3.37', loginSuccess: true, authMethod: 'password', deviceFingerprint: 'Windows 11|3c:22:fb:10:9a:77|TLS1.3' }),
  ],
  privesc: (c) => [
    ev(c, 0, -150, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'token', deviceFingerprint: HOME_DEVICE }),
    ev(c, 1, -60, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/etc/shadow', commandSequence: 'sudo exec download', sessionDurationMinutes: 210, deviceFingerprint: HOME_DEVICE }),
    ev(c, 2, 0, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/var/backups/db.sql', commandSequence: 'sudo exec download delete', sessionDurationMinutes: 240, deviceFingerprint: HOME_DEVICE }),
  ],
  exfil: (c) =>
    Array.from({ length: 6 }, (_, i) =>
      ev(c, i, -50 + i * 10, 'FILE_ACCESS', {
        ip: HOME_IP, location: HOME, resource: `/finance/payroll/2026-0${i + 1}.xlsx`, action: 'download',
        commandSequence: 'download download', sessionDurationMinutes: 300, deviceFingerprint: HOME_DEVICE,
      }),
    ),
  device: (c) => [
    ev(c, 0, 0, 'LOGIN', { ip: '203.0.113.77', location: 'Singapore|1.35|103.82', loginSuccess: true, authMethod: 'certificate', deviceFingerprint: 'Kali 2026.2|de:ad:be:ef:00:01|TLS1.3' }),
  ],
};
/* ------------------------------------------------------------------------------------- */

let checks = 0;
const check = (name: string, fn: () => void) => {
  fn();
  checks++;
  console.log(`ok - ${name}`);
};

const NOW = Date.UTC(2026, 9, 6, 12, 0, 0, 123);
const ctx = (id: string, intensity = 'MEDIUM'): Ctx => ({ entityId: 'HOST-FIXTURE-01', prefix: `SIM-${id.toUpperCase()}-FIXTURE`, now: NOW, intensity } as Ctx);

check('registry still starts with the six original scenarios, in the original order', () => {
  assert.deepEqual(ORIGINAL_SCENARIO_IDS, ['routine', 'brute', 'travel', 'privesc', 'exfil', 'device']);
  assert.deepEqual(SCENARIOS.slice(0, 6).map((s) => s.id), ORIGINAL_SCENARIO_IDS);
});

for (const id of Object.keys(LEGACY)) {
  check(`${id}: extracted builder reproduces the original events exactly`, () => {
    const s = scenarioById(id)!;
    // deepEqual covers type, payload, order, entity, eventId, occurredAt (relative timing), source, version
    assert.deepEqual(s.build(ctx(id)), LEGACY[id](ctx(id)));
    // and the payload key order, which JSON on the wire preserves
    assert.equal(JSON.stringify(s.build(ctx(id))), JSON.stringify(LEGACY[id](ctx(id))));
  });
}

check('event counts match the original cards (3, 9, 2, 3, 6, 1)', () => {
  assert.deepEqual(SCENARIOS.slice(0, 6).map((s) => eventCount(s)), [3, 9, 2, 3, 6, 1]);
});

check('every scenario passes validation as generated', () => {
  for (const s of SCENARIOS) assert.deepEqual(validateEvents(s.build(ctx(s.id)), NOW), [], s.id);
});

check('brute: its AUTH_BURST claim holds - at least 5 failed logins inside 5 minutes', () => {
  const failures = scenarioById('brute')!.build(ctx('brute')).filter((e) => e.eventType === 'LOGIN' && e.payload.loginSuccess === false);
  const t = failures.map((e) => Date.parse(e.occurredAt));
  assert.ok(failures.length >= 5 && Math.max(...t) - Math.min(...t) <= 5 * 60_000);
});

check('of the original six, only brute claims a rule; routine claims no detector', () => {
  for (const s of SCENARIOS.slice(0, 6)) assert.deepEqual(s.detector.rules, s.id === 'brute' ? ['AUTH_BURST'] : [], s.id);
  assert.equal(scenarioById('routine')!.detector.ml, false);
});

/* ---------------- validation catches each contract violation ---------------- */
const good = (): CreateEventRequest => scenarioById('device')!.build(ctx('device'))[0];
const errorsOf = (events: CreateEventRequest[]) => validateEvents(events, NOW).filter((i) => i.level === 'error').map((i) => i.message);
const expectError = (events: CreateEventRequest[], pattern: RegExp) => {
  const errs = errorsOf(events);
  assert.ok(errs.some((m) => pattern.test(m)), `expected ${pattern}, got ${JSON.stringify(errs)}`);
};

check('validation: empty run', () => expectError([], /no events/));
check('validation: missing eventId', () => expectError([{ ...good(), eventId: '' }], /eventId is required/));
check('validation: missing entityId / eventType', () => {
  expectError([{ ...good(), entityId: '  ' }], /entityId is required/);
  expectError([{ ...good(), eventType: '' }], /eventType is required/);
});
check('validation: field longer than VARCHAR(128)', () => expectError([{ ...good(), eventId: 'X'.repeat(129) }], /longer than 128/));
check('validation: duplicate eventId', () => expectError([good(), good()], /duplicate eventId/));
check('validation: source must be simulator', () => expectError([{ ...good(), source: 'python-simulator' }], /source must be "simulator"/));
check('validation: occurredAt in the future / not a timestamp', () => {
  expectError([{ ...good(), occurredAt: new Date(NOW + 60_000).toISOString() }], /in the future/);
  expectError([{ ...good(), occurredAt: 'yesterday' }], /not a valid ISO-8601/);
  assert.deepEqual(errorsOf([{ ...good(), occurredAt: new Date(NOW + 1000).toISOString() }]), []); // inside the skew
});
check('validation: LOGIN needs a boolean loginSuccess (missing, or the string "false")', () => {
  const { loginSuccess: _drop, ...rest } = good().payload;
  expectError([{ ...good(), payload: rest }], /boolean loginSuccess/);
  expectError([{ ...good(), payload: { ...good().payload, loginSuccess: 'false' } }], /boolean loginSuccess/);
});
check('validation: processCreateTime format matches the rule (yyyy-MM-ddTHH:mm:ssZ)', () => {
  const conn = (pct: unknown): CreateEventRequest => ({ ...good(), eventType: 'NETWORK_CONNECTION', payload: { pid: 4242, remoteAddress: '198.51.100.7', remotePort: 443, processCreateTime: pct } });
  assert.deepEqual(errorsOf([conn('2026-10-06T11:59:30Z')]), []);
  expectError([conn('2026-10-06T11:59:30.000Z')], /processCreateTime must be formatted/); // toISOString() keeps millis: would never match
  expectError([conn('2026-10-06 11:59:30')], /processCreateTime must be formatted/);
  expectError([conn(1791000000)], /processCreateTime must be formatted/);
});
check('validation: payload over the backend limit', () => {
  expectError([{ ...good(), payload: { ...good().payload, blob: 'x'.repeat(MAX_EVENT_BYTES) } }], /backend limit/);
});
check('validation: undefined or non-finite values that JSON would silently drop or null', () => {
  expectError([{ ...good(), payload: { ...good().payload, ip: undefined } }], /event\.payload\.ip is undefined/);
  expectError([{ ...good(), payload: { ...good().payload, sessionDurationMinutes: Number.NaN } }], /not a finite number/);
});
check('validation: payload must be an object', () => expectError([{ ...good(), payload: [] as unknown as Record<string, unknown> }], /payload must be an object/));

/* ======================================================================================
 * Run engine - driven by a fake clock and a mock transport. Nothing is sent anywhere.
 * ==================================================================================== */

class FakeClock {
  t = 0;
  private seq = 0;
  timers = new Map<number, { at: number; fn: () => void }>();
  now = () => this.t;
  setTimer = (fn: () => void, ms: number) => {
    const id = ++this.seq;
    this.timers.set(id, { at: this.t + Math.max(0, ms), fn });
    return id;
  };
  clearTimer = (h: unknown) => {
    this.timers.delete(h as number);
  };
  /** Run every timer due within `ms`, in time order, letting promise callbacks settle between them. */
  async advance(ms: number) {
    const end = this.t + ms;
    for (;;) {
      await flush();
      const due = [...this.timers.entries()].filter(([, x]) => x.at <= end).sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
      if (!due) break;
      this.timers.delete(due[0]);
      this.t = due[1].at;
      due[1].fn();
    }
    this.t = end;
    await flush();
  }
}
const flush = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

type Outcome = 'ok' | 'defer' | { status?: number; message: string };
/** Records every call, how many were in flight at once, and answers per `script(call#)`. */
function mockTransport(clock: FakeClock, script: (n: number) => Outcome = () => 'ok') {
  const calls: { eventId: string; at: number }[] = [];
  const deferred: { resolve: () => void; reject: (e: unknown) => void }[] = [];
  let inFlight = 0;
  let maxInFlight = 0;
  const send = (event: CreateEventRequest) => {
    const n = calls.length;
    calls.push({ eventId: event.eventId, at: clock.now() });
    inFlight++;
    maxInFlight = Math.max(maxInFlight, inFlight);
    const outcome = script(n);
    const done = <T,>(p: Promise<T>) => p.finally(() => inFlight--);
    if (outcome === 'ok') return done(Promise.resolve());
    if (outcome === 'defer') return done(new Promise<void>((resolve, reject) => deferred.push({ resolve, reject })));
    return done(Promise.reject({ code: `HTTP_${outcome.status}`, message: outcome.message, details: [], status: outcome.status }));
  };
  return { send, calls, deferred, get maxInFlight() { return maxInFlight; } };
}

const plan = (n: number, runId = 'SIM-TEST-RUN1') => ({
  runId,
  label: 'Test scenario',
  events: Array.from({ length: n }, (_, i) => ({ ...good(), eventId: `${runId}-${String(i + 1).padStart(2, '0')}` })),
});

function setup(script?: (n: number) => Outcome) {
  const clock = new FakeClock();
  const t = mockTransport(clock, script);
  const engine = new SimulationEngine({ send: t.send, now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  const states: string[] = [];
  engine.subscribe(() => {
    const s = engine.getSnapshot().state;
    if (states[states.length - 1] !== s) states.push(s);
  });
  return { clock, t, engine, states, snap: () => engine.getSnapshot() };
}

let asyncChecks = 0;
const acheck = async (name: string, fn: () => Promise<void>) => {
  await fn();
  asyncChecks++;
  console.log(`ok - ${name}`);
};

await acheck('engine: IDLE -> RUNNING on start; counters reset; start time recorded', async () => {
  const { engine, clock, snap } = setup();
  assert.equal(snap().state, 'IDLE');
  clock.t = 1000;
  engine.start(plan(3), { eventRate: 2 });
  assert.equal(snap().state, 'RUNNING');
  assert.equal(snap().startedAt, 1000);
  assert.deepEqual([snap().generated, snap().accepted, snap().failed, snap().totalEvents], [0, 0, 0, 3]);
  assert.equal(snap().runId, 'SIM-TEST-RUN1');
});

await acheck('engine: normal completion, strict order, pacing at 2/s (sends 500 ms apart), no payloads kept', async () => {
  const { engine, clock, t, snap, states } = setup();
  engine.start(plan(4), { eventRate: 2 });
  await clock.advance(10_000);
  assert.deepEqual(t.calls.map((c) => c.eventId), plan(4).events.map((e) => e.eventId));
  assert.deepEqual(t.calls.map((c) => c.at), [0, 500, 1000, 1500]);
  assert.equal(snap().state, 'COMPLETED');
  assert.equal(snap().finishedAt, 1500);
  assert.deepEqual([snap().generated, snap().accepted, snap().failed, snap().nextEventIndex], [4, 4, 0, 4]);
  assert.deepEqual(states, ['RUNNING', 'COMPLETED']);
  assert.deepEqual(snap().results.map((r) => r.index), [0, 1, 2, 3]);
  assert.ok(snap().results.every((r) => r.status === 'ACCEPTED' && !('payload' in r)));
});

await acheck('engine: never two sends at once - the next send waits for the previous to settle', async () => {
  const { engine, clock, t, snap } = setup(() => 'defer');
  engine.start(plan(3), { eventRate: 5 });
  await clock.advance(5000);
  assert.equal(t.calls.length, 1, 'still waiting on the first POST');
  assert.equal(snap().currentEventIndex, 0);
  t.deferred[0].resolve();
  await clock.advance(0); // interval long since elapsed -> next send right away, not a catch-up burst
  assert.equal(t.calls.length, 2);
  t.deferred[1].resolve();
  await clock.advance(199);
  assert.equal(t.calls.length, 2, 'pacing still applies: 200 ms after the previous send started');
  await clock.advance(1);
  t.deferred[2].resolve();
  await clock.advance(1000);
  assert.equal(t.maxInFlight, 1);
  assert.equal(snap().state, 'COMPLETED');
});

await acheck('engine: rate is hard-capped at 5/s and floored at 0.5/s; callers cannot bypass it', async () => {
  for (const [asked, effective, gap] of [[100, 5, 200], [5, 5, 200], [0, 0.5, 2000], [Number.NaN, 0.5, 2000], [-3, 0.5, 2000]] as const) {
    const { engine, clock, t, snap } = setup();
    engine.start(plan(3), { eventRate: asked });
    await clock.advance(10_000);
    assert.equal(snap().eventRate, effective, String(asked));
    assert.deepEqual(t.calls.map((c) => c.at), [0, gap, 2 * gap], String(asked));
  }
  assert.equal(clampRate(Infinity), 0.5);
});

await acheck('engine: RUNNING -> PAUSED prevents new sends; PAUSED -> RUNNING resumes at the next index, no skips or repeats', async () => {
  const { engine, clock, t, snap, states } = setup();
  engine.start(plan(5), { eventRate: 2 });
  await clock.advance(600); // sends at 0 and 500
  engine.pause();
  assert.equal(snap().state, 'PAUSED');
  assert.equal(engine.pendingTimers(), 0, 'pause releases the pacing timer at once');
  assert.equal(clock.timers.size, 0);
  await clock.advance(60_000);
  assert.equal(t.calls.length, 2, 'nothing sent while paused');
  assert.equal(snap().nextEventIndex, 2);
  assert.equal(engine.pendingTimers(), 0, 'no pacing timer held while paused');
  engine.resume();
  await clock.advance(10_000);
  assert.deepEqual(t.calls.map((c) => c.eventId), plan(5).events.map((e) => e.eventId));
  assert.equal(new Set(t.calls.map((c) => c.eventId)).size, 5);
  assert.deepEqual(states, ['RUNNING', 'PAUSED', 'RUNNING', 'COMPLETED']);
});

await acheck('engine: pause during an in-flight POST lets it settle but schedules nothing after it', async () => {
  const { engine, clock, t, snap } = setup(() => 'defer');
  engine.start(plan(3), { eventRate: 5 });
  await clock.advance(0);
  engine.pause();
  t.deferred[0].resolve();
  await clock.advance(10_000);
  assert.equal(snap().state, 'PAUSED');
  assert.equal(snap().accepted, 1);
  assert.equal(t.calls.length, 1);
  engine.resume();
  await clock.advance(0);
  assert.equal(t.calls.length, 2, 'resume continues with event #2');
});

await acheck('engine: stop with nothing in flight -> STOPPING -> STOPPED at once; no further sends', async () => {
  const { engine, clock, t, snap, states } = setup();
  engine.start(plan(5), { eventRate: 2 });
  await clock.advance(600);
  engine.stop();
  await clock.advance(60_000);
  assert.equal(snap().state, 'STOPPED');
  assert.equal(snap().stopReason, 'USER');
  assert.equal(t.calls.length, 2);
  assert.deepEqual(states, ['RUNNING', 'STOPPING', 'STOPPED']);
});

await acheck('engine: stop while a POST is in flight stays STOPPING until it settles, then STOPPED; its result is kept', async () => {
  const { engine, clock, t, snap } = setup(() => 'defer');
  engine.start(plan(3), { eventRate: 5 });
  await clock.advance(0);
  engine.stop();
  assert.equal(snap().state, 'STOPPING');
  await clock.advance(10_000);
  assert.equal(snap().state, 'STOPPING');
  t.deferred[0].resolve();
  await clock.advance(0);
  assert.equal(snap().state, 'STOPPED');
  assert.equal(snap().accepted, 1);
  assert.equal(t.calls.length, 1);
});

await acheck('engine: stop from PAUSED', async () => {
  const { engine, clock, t, snap, states } = setup();
  engine.start(plan(4), { eventRate: 2 });
  await clock.advance(100);
  engine.pause();
  engine.stop();
  await clock.advance(10_000);
  assert.equal(snap().state, 'STOPPED');
  assert.equal(t.calls.length, 1);
  assert.deepEqual(states, ['RUNNING', 'PAUSED', 'STOPPING', 'STOPPED']);
});

await acheck('engine: invalid transitions are rejected and leave the state unchanged', async () => {
  const { engine, clock, snap } = setup();
  assert.throws(() => engine.pause(), /not valid while IDLE/);
  assert.throws(() => engine.resume(), /only valid while PAUSED/);
  assert.throws(() => engine.stop(), /not valid while IDLE/);
  assert.throws(() => engine.reset(), /not valid while IDLE/);
  assert.throws(() => engine.start(plan(0), { eventRate: 1 }), /at least one event/);
  engine.start(plan(2), { eventRate: 5 });
  assert.throws(() => engine.start(plan(2), { eventRate: 5 }), /RUNNING/);
  assert.throws(() => engine.resume(), /only valid while PAUSED/);
  assert.throws(() => engine.reset(), /not valid while RUNNING/);
  engine.pause();
  assert.throws(() => engine.pause(), /not valid while PAUSED/);
  engine.stop();
  assert.equal(snap().state, 'STOPPED');
  for (const cmd of [() => engine.pause(), () => engine.resume(), () => engine.stop(), () => engine.start(plan(1), { eventRate: 1 })]) assert.throws(cmd);
  assert.equal(snap().state, 'STOPPED');
  await clock.advance(1000);
  assert.ok(canTransition('STOPPING', 'STOPPED') && !canTransition('STOPPING', 'RUNNING') && !canTransition('COMPLETED', 'RUNNING'));
});

await acheck('engine: a rejected event is recorded with its error and the run continues to COMPLETED', async () => {
  const { engine, clock, snap } = setup((n) => (n === 1 ? { status: 404, message: 'Entity not found: X' } : 'ok'));
  engine.start(plan(3), { eventRate: 5 });
  await clock.advance(5000);
  assert.equal(snap().state, 'COMPLETED');
  assert.deepEqual([snap().accepted, snap().failed], [2, 1]);
  const bad = snap().results[1];
  assert.equal(bad.status, 'FAILED');
  assert.deepEqual(bad.error, { status: 404, code: 'HTTP_404', message: 'Entity not found: X', systemic: false });
});

await acheck('engine: many per-event failures keep the counters consistent', async () => {
  const codes = [400, 0, 409, 0, 413, 422, 0, 400];
  const { engine, clock, snap } = setup((n) => (codes[n] ? { status: codes[n], message: `HTTP ${codes[n]}` } : 'ok'));
  engine.start(plan(codes.length), { eventRate: 5 });
  await clock.advance(10_000);
  const s = snap();
  assert.equal(s.state, 'COMPLETED');
  assert.deepEqual([s.accepted, s.failed, s.generated], [3, 5, 8]);
  assert.equal(s.results.filter((r) => r.status === 'FAILED').length, s.failed);
  assert.equal(s.results.filter((r) => r.status === 'ACCEPTED').length, s.accepted);
});

await acheck('engine: an isolated network/5xx failure continues; 3 in a row end the run FAILED and the rest is not sent', async () => {
  const blip = setup((n) => (n === 0 || n === 1 ? { message: 'Unable to reach the backend' } : 'ok'));
  blip.engine.start(plan(4), { eventRate: 5 });
  await blip.clock.advance(5000);
  assert.equal(blip.snap().state, 'COMPLETED', 'two in a row then a success: keep going');

  const down = setup((n) => (n >= 1 ? { status: 503, message: 'The backend is not responding (HTTP 503)' } : 'ok'));
  down.engine.start(plan(10), { eventRate: 5 });
  await down.clock.advance(10_000);
  assert.equal(down.snap().state, 'FAILED');
  assert.equal(down.t.calls.length, 4, '1 ok + 3 systemic failures, then nothing more');
  assert.match(down.snap().failureReason ?? '', /3 submissions in a row failed/);
  assert.equal(down.engine.pendingTimers(), 0);
});

await acheck('engine: 401/403 ends the run FAILED immediately', async () => {
  const { engine, clock, t, snap } = setup(() => ({ status: 401, message: 'Unauthorized' }));
  engine.start(plan(5), { eventRate: 5 });
  await clock.advance(5000);
  assert.equal(snap().state, 'FAILED');
  assert.equal(t.calls.length, 1);
  assert.match(snap().failureReason ?? '', /Not authorised/);
});

await acheck('engine: a transport that throws synchronously is recorded as a failure, not a crash', async () => {
  const clock = new FakeClock();
  const engine = new SimulationEngine({ send: () => { throw new TypeError('boom'); }, now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  engine.start(plan(1), { eventRate: 5 });
  await clock.advance(1000);
  assert.equal(engine.getSnapshot().failed, 1);
  assert.equal(engine.getSnapshot().results[0].error?.message, 'boom');
});

await acheck('engine: duration cap stops new sends -> STOPPED (stopReason DURATION); pauses count toward it', async () => {
  const { engine, clock, t, snap, states } = setup();
  engine.start(plan(10), { eventRate: 2, maxDurationMs: 1200 });
  await clock.advance(10_000);
  assert.deepEqual(t.calls.map((c) => c.at), [0, 500, 1000]);
  assert.equal(snap().state, 'STOPPED');
  assert.equal(snap().stopReason, 'DURATION');
  assert.equal(snap().finishedAt, 1200);
  assert.deepEqual(states, ['RUNNING', 'STOPPING', 'STOPPED']);

  const paused = setup();
  paused.engine.start(plan(10), { eventRate: 2, maxDurationMs: 2000 });
  await paused.clock.advance(100);
  paused.engine.pause();
  await paused.clock.advance(5000);
  assert.equal(paused.snap().state, 'STOPPED', 'the cap is wall-clock, so it also ends a paused run');
  assert.equal(paused.snap().stopReason, 'DURATION');
});

await acheck('engine: duration expiring during an in-flight POST waits for it (STOPPING), then STOPPED', async () => {
  const { engine, clock, t, snap } = setup(() => 'defer');
  engine.start(plan(5), { eventRate: 5, maxDurationMs: 300 });
  await clock.advance(1000);
  assert.equal(snap().state, 'STOPPING');
  t.deferred[0].resolve();
  await clock.advance(0);
  assert.equal(snap().state, 'STOPPED');
  assert.equal(t.calls.length, 1);
});

await acheck('engine: no timers survive COMPLETED, STOPPED or FAILED', async () => {
  const ends: [string, (e: SimulationEngine, c: FakeClock) => Promise<void>, ((n: number) => Outcome)?][] = [
    ['COMPLETED', async (_e, c) => c.advance(10_000)],
    ['STOPPED', async (e, c) => { await c.advance(300); e.stop(); }],
    ['FAILED', async (_e, c) => c.advance(10_000), () => ({ message: 'down' })],
  ];
  for (const [state, drive, script] of ends) {
    const { engine, clock, snap } = setup(script);
    engine.start(plan(4), { eventRate: 5, maxDurationMs: 60_000 });
    await drive(engine, clock);
    assert.equal(snap().state, state);
    assert.equal(engine.pendingTimers(), 0, `${state}: engine holds no timer`);
    assert.equal(clock.timers.size, 0, `${state}: no timer left on the clock (pacing or duration)`);
  }
});

await acheck('engine: reset() returns a finished engine to IDLE and it runs a new plan cleanly', async () => {
  const { engine, clock, t, snap } = setup();
  engine.start(plan(2, 'SIM-A'), { eventRate: 5 });
  await clock.advance(5000);
  assert.equal(snap().state, 'COMPLETED');
  engine.reset();
  assert.equal(snap().state, 'IDLE');
  assert.deepEqual([snap().runId, snap().generated, snap().results.length], [null, 0, 0]);
  engine.start(plan(3, 'SIM-B'), { eventRate: 1 });
  await clock.advance(10_000);
  assert.equal(snap().state, 'COMPLETED');
  assert.equal(snap().runId, 'SIM-B');
  assert.deepEqual([snap().accepted, snap().totalEvents], [3, 3]);
  assert.equal(t.calls.length, 5);
});

await acheck('engine: snapshot is stable between changes (useSyncExternalStore-safe) and unsubscribe works', async () => {
  const { engine, clock } = setup();
  assert.equal(engine.getSnapshot(), engine.getSnapshot());
  let hits = 0;
  const off = engine.subscribe(() => hits++);
  engine.start(plan(1), { eventRate: 5 });
  await clock.advance(1000);
  const seen = hits;
  assert.ok(seen > 0);
  off();
  engine.reset();
  assert.equal(hits, seen);
});

await acheck('engine: describeError classifies systemic vs per-event failures', async () => {
  assert.equal(describeError({ status: 400, message: 'bad' }).systemic, false);
  assert.equal(describeError({ status: 409, message: 'dup' }).systemic, false);
  assert.equal(describeError({ status: 429, message: 'slow down' }).systemic, true);
  assert.equal(describeError({ status: 502, message: 'gw' }).systemic, true);
  assert.equal(describeError({ code: 'NETWORK_ERROR', message: 'Unable to reach the backend' }).systemic, true);
  assert.equal(describeError({ status: 400, message: 'Validation failed', details: ['eventId: required'] }).message, 'Validation failed: eventId: required');
  assert.equal(describeError(undefined).message, 'The event could not be submitted');
});

check('the six scenario plans still pass validation (after the engine refactor)', () => {
  for (const s of SCENARIOS) assert.deepEqual(validateEvents(s.build(ctx(s.id)), NOW), [], s.id);
});
/* ======================================================================================
 * PHASE 3 - scenario library, configuration, planning and the dry-run preview.
 * Still nothing is sent anywhere: the planner is pure and the engine runs on a mock transport.
 * ==================================================================================== */

const AVAIL = ['HOST-A', 'HOST-B', 'HOST-C', 'HOST-D'];
const NEW_IDS = ['credstuff', 'procconn', 'portscan', 'suspproc', 'lateral', 'mixed'];
const cfg = (patch: Record<string, unknown> = {}) => ({
  ...DEFAULT_CONFIG,
  entityId: 'HOST-A',
  entityIds: ['HOST-A', 'HOST-B'],
  ...patch,
}) as Parameters<typeof buildPreview>[0];
const plan1 = (patch: Record<string, unknown> = {}, runId = 'SIM-RUN-FIXTURE') =>
  buildPreview(cfg(patch), { runId, now: NOW, available: AVAIL });
const ids = (events: { eventId: string }[]) => events.map((e) => e.eventId);
const times = (events: { occurredAt: string }[]) => events.map((e) => Date.parse(e.occurredAt));

/* ---------------- the compatibility baseline is still frozen ---------------- */

check('builders.ts is byte-identical to the Phase 2 file (the six original builders are untouched)', () => {
  // Phase 3 put every new builder in advancedBuilders.ts precisely so this file never has to change.
  const source = readFileSync(new URL('../src/simulator/builders.ts', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  assert.equal(
    createHash('sha256').update(source, 'utf8').digest('hex'),
    '15dd8873c758658927266f459ecb2c53b5c204a7ee10d4c0a0131b6d06d4010a',
    'src/simulator/builders.ts changed - the original six builders must stay byte-identical',
  );
});

check('all twelve scenarios exist: the six originals plus the six Phase 3 additions', () => {
  assert.deepEqual(SCENARIOS.map((s) => s.id), [...ORIGINAL_SCENARIO_IDS, ...NEW_IDS]);
  assert.equal(new Set(SCENARIOS.map((s) => s.id)).size, SCENARIOS.length, 'duplicate scenario id');
  assert.equal(new Set(SCENARIOS.map((s) => s.name)).size, SCENARIOS.length, 'duplicate scenario name');
});

check('a single-target run with no noise produces exactly the plan Phase 2 produced', () => {
  for (const s of SCENARIOS) {
    const runId = `SIM-${s.id.toUpperCase()}-FROZEN`;
    const p = buildPreview(cfg({ scenarioId: s.id }), { runId, now: NOW, available: AVAIL });
    const direct = s.build({ entityId: 'HOST-A', prefix: runId, now: NOW, intensity: 'MEDIUM' });
    // Same events, same order, same payload key order, same eventId scheme - the planner adds nothing.
    assert.equal(JSON.stringify(p.events), JSON.stringify(direct), s.id);
    assert.equal(p.segments.length, 1, s.id);
    assert.equal(p.segments[0].shiftSec, 0, s.id);
  }
});

/* ---------------- the library ---------------- */

check('the library groups every scenario, in the documented group order, with no scenario lost', () => {
  const groups = scenarioGroups();
  assert.deepEqual(groups.map((g) => g.label), ['Identity', 'Endpoint', 'Network', 'Data', 'Attack chains', 'Control']);
  assert.deepEqual(groups.flatMap((g) => g.scenarios.map((s) => s.id)).sort(), SCENARIOS.map((s) => s.id).sort());
  for (const g of groups) for (const s of g.scenarios) assert.equal(s.category, g.category);
});

check('every scenario declares its Phase 3 metadata, and a coverage gap always carries a limitation', () => {
  for (const s of SCENARIOS) {
    assert.equal(typeof s.scales, 'boolean', s.id);
    assert.equal(typeof s.splittable, 'boolean', s.id);
    assert.ok(['ALL', 'PAIR', 'EACH'].includes(s.groupMode), s.id);
    assert.ok(s.limitations.length > 0, `${s.id} states no limitation`);
    assert.ok(s.detector.note.length > 20, s.id);
    // A scenario no detector covers must say so rather than imply detection.
    if (!s.detector.rules.length && !s.detector.ml && s.category !== 'BASELINE') {
      assert.match(s.detector.note, /COVERAGE GAP/, s.id);
      assert.ok(s.limitations.some((l) => /COVERAGE GAP/.test(l)), s.id);
    }
    assert.ok(!s.splittable || s.groupMode !== 'ALL', `${s.id}: splittable but indivisible`);
  }
  assert.deepEqual(SCENARIOS.filter((s) => s.scales).map((s) => s.id), NEW_IDS, 'only the Phase 3 scenarios scale');
});

check('detectionSummary never promises detection a scenario does not have', () => {
  assert.match(detectionSummary(scenarioById('credstuff')!), /^Deterministic: AUTH_BURST/);
  assert.match(detectionSummary(scenarioById('procconn')!), /^Deterministic: NEW_PROCESS_EXTERNAL_CONNECTION$/);
  assert.match(detectionSummary(scenarioById('lateral')!), /ML-dependent only/);
  assert.match(detectionSummary(scenarioById('portscan')!), /No detector/);
  assert.match(detectionSummary(scenarioById('suspproc')!), /No detector/);
});

/* ---------------- the new builders ---------------- */

check('every scenario at every intensity generates valid events with unique eventIds', () => {
  for (const s of SCENARIOS) {
    for (const intensity of INTENSITIES) {
      const events = s.build(ctx(s.id, intensity) as never);
      assert.ok(events.length > 0, `${s.id}/${intensity}`);
      assert.deepEqual(validateEvents(events, NOW), [], `${s.id}/${intensity}`);
      assert.equal(new Set(ids(events)).size, events.length, `${s.id}/${intensity}: duplicate eventId`);
      // the planner relies on this: the last event of a segment sits at the time anchor
      assert.equal(Math.max(...times(events)), NOW, `${s.id}/${intensity}: the last event is not at the anchor`);
    }
  }
});

check('credential stuffing satisfies AUTH_BURST at every intensity, and only HIGH reaches the rule HIGH severity', () => {
  const expected: Record<string, string> = { LOW: 'MEDIUM', MEDIUM: 'MEDIUM', HIGH: 'HIGH' };
  for (const intensity of INTENSITIES) {
    const events = scenarioById('credstuff')!.build(ctx('credstuff', intensity) as never);
    const failures = events.filter((e) => e.eventType === 'LOGIN' && e.payload.loginSuccess === false);
    const t = failures.map((e) => Date.parse(e.occurredAt));
    assert.ok(failures.length >= AUTH_BURST_THRESHOLD, `${intensity}: only ${failures.length} failures`);
    assert.ok(Math.max(...t) - Math.min(...t) <= RULE_WINDOW_MINUTES * 60_000, `${intensity}: failures outside the rule window`);
    const severity = failures.length >= AUTH_BURST_HIGH_THRESHOLD ? 'HIGH' : 'MEDIUM';
    assert.equal(severity, expected[intensity], intensity);
    // every LOGIN carries an explicit boolean, which both AUTH_BURST and the ML adapter require
    assert.ok(events.every((e) => typeof e.payload.loginSuccess === 'boolean'));
    // the whole attempt sequence ends in exactly one success
    assert.equal(events.filter((e) => e.payload.loginSuccess === true).length, 1, intensity);
  }
  assert.deepEqual(scenarioById('credstuff')!.detector.rules, ['AUTH_BURST']);
});

check('process + external connection meets the NEW_PROCESS_EXTERNAL_CONNECTION contract exactly', () => {
  for (const intensity of INTENSITIES) {
    const events = scenarioById('procconn')!.build(ctx('procconn', intensity) as never);
    const conns = events.filter((e) => e.eventType === 'NETWORK_CONNECTION');
    const starts = events.filter((e) => e.eventType === 'PROCESS_START');
    assert.equal(conns.length, starts.length, intensity);
    assert.ok(conns.length >= 1, intensity);
    // one alert per process identity, so every pair needs its own pid
    assert.equal(new Set(starts.map((e) => e.payload.pid)).size, starts.length, `${intensity}: a pid is reused`);

    for (const conn of conns) {
      const i = events.indexOf(conn);
      const start = events.find((e) => e.eventType === 'PROCESS_START' && e.payload.pid === conn.payload.pid)!;
      assert.ok(events.indexOf(start) < i, `${intensity}: the connection precedes its PROCESS_START`);
      assert.equal(typeof conn.payload.pid, 'number', 'the rule needs a numeric pid');
      // no time tolerance: processCreateTime must equal PROCESS_START.occurredAt truncated to seconds
      assert.equal(conn.payload.processCreateTime, processCreateTime(Date.parse(start.occurredAt)), intensity);
      assert.match(String(conn.payload.processCreateTime), PROCESS_CREATE_TIME);
      const address = String(conn.payload.remoteAddress);
      assert.ok(address && !address.startsWith('127.') && address !== '::1' && address.toLowerCase() !== 'localhost', `${intensity}: loopback destination`);
      const delta = Date.parse(conn.occurredAt) - Date.parse(start.occurredAt);
      assert.ok(delta > 0 && delta <= RULE_WINDOW_MINUTES * 60_000, `${intensity}: outside the recency bound (${delta} ms)`);
    }
  }
  assert.deepEqual(scenarioById('procconn')!.detector.rules, ['NEW_PROCESS_EXTERNAL_CONNECTION']);
});

check('port scan and suspicious process deliberately satisfy no rule, and say so', () => {
  for (const intensity of INTENSITIES) {
    const scan = scenarioById('portscan')!.build(ctx('portscan', intensity) as never);
    assert.ok(scan.every((e) => e.eventType === 'NETWORK_CONNECTION'), intensity);
    // NEW_PROCESS_EXTERNAL_CONNECTION needs processCreateTime; without it the rule returns early
    assert.ok(scan.every((e) => !('processCreateTime' in e.payload)), `${intensity}: a scan event would satisfy the endpoint rule`);
    assert.ok(scan.every((e) => !String(e.payload.remoteAddress).startsWith('127.')), intensity);
    assert.ok(new Set(scan.map((e) => e.payload.remotePort)).size >= Math.min(scan.length, 8), `${intensity}: the ports do not fan out`);

    const proc = scenarioById('suspproc')!.build(ctx('suspproc', intensity) as never);
    assert.ok(proc.every((e) => e.eventType === 'PROCESS_START'), intensity);
    // no NETWORK_CONNECTION at all, so the only endpoint rule cannot fire
    assert.equal(proc.filter((e) => e.eventType === 'NETWORK_CONNECTION').length, 0, intensity);
    assert.equal(new Set(proc.map((e) => e.payload.pid)).size, proc.length, intensity);
  }
  for (const id of ['portscan', 'suspproc']) {
    assert.deepEqual(scenarioById(id)!.detector.rules, [], id);
    assert.equal(scenarioById(id)!.detector.ml, false, id);
  }
});

check('lateral movement claims no rule and is marked ML-dependent with its coverage gap stated', () => {
  const s = scenarioById('lateral')!;
  assert.deepEqual(s.detector.rules, []);
  assert.equal(s.detector.ml, true);
  assert.ok(s.limitations.some((l) => /COVERAGE GAP/.test(l)));
  for (const intensity of INTENSITIES) {
    const events = s.build(ctx('lateral', intensity) as never);
    // only event types and payload fields the live ML adapter actually reads
    assert.deepEqual([...new Set(events.map((e) => e.eventType))].sort(), ['FILE_ACCESS', 'LOGIN']);
    assert.ok(events.every((e) => typeof e.payload.ip === 'string' && typeof e.payload.location === 'string'), intensity);
    assert.deepEqual(times(events), [...times(events)].sort((a, b) => a - b), `${intensity}: the hops are out of order`);
  }
});

check('mixed attack composes three scenarios in chronological order with unique ids and both rules satisfied', () => {
  const s = scenarioById('mixed')!;
  assert.deepEqual(s.detector.rules, ['AUTH_BURST', 'NEW_PROCESS_EXTERNAL_CONNECTION']);
  for (const intensity of INTENSITIES) {
    const events = s.build(ctx('mixed', intensity) as never);
    assert.equal(new Set(ids(events)).size, events.length, intensity);
    assert.deepEqual(times(events), [...times(events)].sort((a, b) => a - b), `${intensity}: the stages interleave`);
    assert.deepEqual(validateEvents(events, NOW), [], intensity);
    // stage A still meets AUTH_BURST on its own
    const failures = events.filter((e) => e.eventType === 'LOGIN' && e.payload.loginSuccess === false);
    assert.ok(failures.length >= AUTH_BURST_THRESHOLD, intensity);
    const ft = failures.map((e) => Date.parse(e.occurredAt));
    assert.ok(Math.max(...ft) - Math.min(...ft) <= RULE_WINDOW_MINUTES * 60_000, intensity);
    // stage B still meets the endpoint rule
    const conn = events.find((e) => e.eventType === 'NETWORK_CONNECTION')!;
    const start = events.find((e) => e.eventType === 'PROCESS_START' && e.payload.pid === conn.payload.pid)!;
    assert.equal(conn.payload.processCreateTime, processCreateTime(Date.parse(start.occurredAt)), intensity);
    // stage C is the unchanged Phase 1 exfiltration sequence
    assert.equal(events.filter((e) => e.eventType === 'FILE_ACCESS').length, 6, intensity);
    // each stage has its own eventId namespace
    for (const suffix of ['-A-', '-B-', '-C-']) assert.ok(ids(events).some((id) => id.includes(suffix)), `${intensity}: stage ${suffix} is missing`);
  }
});

/* ---------------- intensity ---------------- */

check('intensity changes the sequence of every scaling scenario and nothing else', () => {
  for (const s of SCENARIOS) {
    const counts = INTENSITIES.map((i) => eventCount(s, i));
    if (s.scales) {
      assert.ok(counts[0] < counts[1] && counts[1] < counts[2], `${s.id}: ${counts.join('/')} does not grow`);
    } else {
      assert.equal(new Set(counts).size, 1, `${s.id}: a fixed scenario changed with intensity`);
      // and the events themselves are identical, not merely as many
      const low = JSON.stringify(s.build(ctx(s.id, 'LOW') as never));
      assert.equal(low, JSON.stringify(s.build(ctx(s.id, 'HIGH') as never)), s.id);
    }
  }
});

check('a fixed scenario reports its fixed contract in the plan notes; a scaling one does not', () => {
  const fixedNote = /fixed event contract/;
  assert.ok(plan1({ scenarioId: 'routine' }).notes.some((n) => fixedNote.test(n)));
  assert.ok(!plan1({ scenarioId: 'portscan' }).notes.some((n) => fixedNote.test(n)));
});

/* ---------------- target selection ---------------- */

check('target selection: single, random (deterministic), multiple and distributed', () => {
  assert.deepEqual(resolveTargets(cfg({ targetMode: 'SINGLE', entityId: 'HOST-C' }), AVAIL, 'R'), ['HOST-C']);
  // RANDOM is derived from the run ID, so a preview and the run it starts agree
  const a = resolveTargets(cfg({ targetMode: 'RANDOM' }), AVAIL, 'SIM-X-1');
  assert.equal(a.length, 1);
  assert.ok(AVAIL.includes(a[0]));
  assert.deepEqual(resolveTargets(cfg({ targetMode: 'RANDOM' }), AVAIL, 'SIM-X-1'), a, 'RANDOM is not reproducible');
  const spread = new Set(AVAIL.map((_, i) => resolveTargets(cfg({ targetMode: 'RANDOM' }), AVAIL, `SIM-X-${i}`)[0]));
  assert.ok(spread.size > 1, 'RANDOM always picks the same entity');
  // MULTI / DISTRIBUTED keep the console order, drop duplicates and unknowns, and cap at MAX_TARGETS
  assert.deepEqual(resolveTargets(cfg({ targetMode: 'MULTI', entityIds: ['HOST-C', 'HOST-A', 'HOST-A', 'GHOST'] }), AVAIL, 'R'), ['HOST-A', 'HOST-C']);
  const many = Array.from({ length: 20 }, (_, i) => `H${i}`);
  assert.equal(resolveTargets(cfg({ targetMode: 'DISTRIBUTED', entityIds: many }), many, 'R').length, MAX_TARGETS);
  assert.deepEqual(resolveTargets(cfg({ targetMode: 'SINGLE', entityId: '' }), AVAIL, 'R'), []);
});

check('multiple targets replay the whole scenario per entity, in plan order, with unique ids', () => {
  const p = plan1({ scenarioId: 'brute', targetMode: 'MULTI', entityIds: ['HOST-A', 'HOST-C'] });
  assert.deepEqual(p.targets.slice().sort(), ['HOST-A', 'HOST-C']);
  assert.equal(p.eventCount, 18);
  assert.deepEqual(p.distribution.map((d) => d.count), [9, 9]);
  assert.equal(new Set(ids(p.events)).size, 18);
  // each entity gets its own eventId namespace
  assert.ok(ids(p.events).every((id) => /-T[12]-\d\d$/.test(id)), ids(p.events).join(','));
  // each campaign stays internally ordered, and SEQUENTIAL keeps the two apart in time
  for (const entityId of p.targets) {
    const own = p.events.filter((e) => e.entityId === entityId);
    assert.equal(own.length, 9, entityId);
    assert.deepEqual(times(own), [...times(own)].sort((a, b) => a - b), entityId);
  }
  const first = p.events[0].entityId;
  assert.ok(Math.max(...times(p.events.filter((e) => e.entityId === first))) < Math.min(...times(p.events.filter((e) => e.entityId !== first))));
  assert.ok(p.notes.some((n) => /satisfied independently for each/.test(n)));
});

check('distributed targets split a splittable scenario across entities without breaking a correlation', () => {
  const p = plan1({ scenarioId: 'procconn', targetMode: 'DISTRIBUTED', entityIds: ['HOST-A', 'HOST-B'], intensity: 'HIGH' });
  assert.equal(p.eventCount, 8, 'splitting must not duplicate the campaign');
  assert.deepEqual(p.distribution.map((d) => d.count), [4, 4]);
  assert.equal(new Set(ids(p.events)).size, 8);
  for (const conn of p.events.filter((e) => e.eventType === 'NETWORK_CONNECTION')) {
    const start = p.events.find((e) => e.eventType === 'PROCESS_START' && e.payload.pid === conn.payload.pid)!;
    assert.equal(start.entityId, conn.entityId, 'a correlated pair was split across entities');
    assert.ok(p.events.indexOf(start) < p.events.indexOf(conn), 'the connection is submitted before its process start');
    assert.equal(conn.payload.processCreateTime, processCreateTime(Date.parse(start.occurredAt)));
  }
  assert.deepEqual(validateEvents(p.events, NOW), []);
  assert.ok(p.notes.some((n) => /handed out round-robin/.test(n)));

  // splitting is a partition of the event list, never a filter that drops events
  assert.deepEqual(eventGroups(scenarioById('procconn')!, 8), [[0, 1], [2, 3], [4, 5], [6, 7]]);
  assert.deepEqual(eventGroups(scenarioById('portscan')!, 3), [[0], [1], [2]]);
  assert.deepEqual(eventGroups(scenarioById('brute')!, 3), [[0, 1, 2]]);
  assert.deepEqual(eventGroups(scenarioById('procconn')!, 3), [[0, 1], [2]]);
});

check('distributed targets fall back to replication for an indivisible scenario, and say so', () => {
  const p = plan1({ scenarioId: 'credstuff', targetMode: 'DISTRIBUTED', entityIds: ['HOST-A', 'HOST-B'], intensity: 'LOW' });
  assert.equal(p.eventCount, 14, 'an indivisible scenario is replicated, not cut up');
  assert.deepEqual(p.distribution.map((d) => d.count), [7, 7]);
  assert.ok(p.notes.some((n) => /replicate it on each/.test(n)));
  // which is the point: AUTH_BURST counts per entity, so every entity must keep its whole burst
  for (const entityId of p.targets) {
    const failures = p.events.filter((e) => e.entityId === entityId && e.payload.loginSuccess === false);
    assert.ok(failures.length >= AUTH_BURST_THRESHOLD, entityId);
  }
});

/* ---------------- benign noise ---------------- */

check('noise percentages add the documented number of benign events, through the same validator', () => {
  for (const percent of NOISE_OPTIONS) {
    const p = plan1({ scenarioId: 'brute', noisePercent: percent });
    assert.equal(p.scenarioEventCount, 9, String(percent));
    assert.equal(p.noiseEventCount, noiseCount(9, percent), String(percent));
    assert.equal(p.eventCount, 9 + p.noiseEventCount, String(percent));
    assert.deepEqual(validateEvents(p.events, NOW), [], String(percent));
    assert.equal(new Set(ids(p.events)).size, p.eventCount, String(percent));
    if (percent > 0) assert.ok(p.notes.some((n) => /not a guarantee of no alerts/.test(n)), String(percent));
  }
  assert.deepEqual(NOISE_OPTIONS, [0, 10, 20, 30]);
  assert.deepEqual([0, 10, 20, 30].map((n) => noiseCount(10, n)), [0, 1, 2, 3]);
});

check('noise events are ordinary, valid, benign activity - never an intentionally invalid event', () => {
  const nctx = { entityId: 'HOST-A', prefix: 'SIM-N', now: NOW, intensity: 'MEDIUM' } as never;
  const events = buildNoise(nctx, 8);
  assert.equal(events.length, 8);
  assert.deepEqual(validateEvents(events, NOW), []);
  assert.deepEqual([...new Set(events.map((e) => e.eventType))].sort(), ['FILE_ACCESS', 'LOGIN', 'LOGOUT']);
  // a benign LOGIN still carries the explicit boolean the ML adapter and AUTH_BURST both need
  assert.ok(events.filter((e) => e.eventType === 'LOGIN').every((e) => e.payload.loginSuccess === true));
  assert.equal(buildNoise(nctx, 0).length, 0);
  // noise shares the entity but never the scenario's eventId namespace
  const p = plan1({ scenarioId: 'brute', noisePercent: 30 });
  const noise = p.segments.filter((s) => s.kind === 'NOISE');
  assert.equal(noise.length, 1);
  assert.ok(noise[0].prefix.endsWith('-Z1'));
  assert.ok(noise[0].events.every((e) => !/-\d\d$/.test(e.eventId.replace(/-Z1-\d\d$/, ''))));
});

/* ---------------- attack pattern planning ---------------- */

check('pattern planning places segments: sequential separates, burst overlaps, progressive escalates, distributed staggers', () => {
  const spans = [10, 20, 30];
  assert.deepEqual(segmentShifts(spans, 'SEQUENTIAL'), [-70, -40, 0]);
  assert.deepEqual(segmentShifts(spans, 'BURST'), [0, 0, 0]);
  assert.deepEqual(segmentShifts(spans, 'PROGRESSIVE'), [-74, -38, 0]);
  assert.deepEqual(segmentShifts(spans, 'DISTRIBUTED'), [-40, -20, 0]);
  // PROGRESSIVE's gaps shrink toward the end; SEQUENTIAL's never change
  const gaps = (p: 'SEQUENTIAL' | 'PROGRESSIVE') => {
    const s = segmentShifts([0, 0, 0, 0], p);
    return [s[1] - s[0], s[2] - s[1], s[3] - s[2]];
  };
  assert.deepEqual(gaps('SEQUENTIAL'), [10, 10, 10]);
  assert.deepEqual(gaps('PROGRESSIVE'), [32, 16, 8]);
  // the last segment always ends at the time anchor, and nothing is ever placed in the future
  for (const pattern of PATTERNS) {
    const shifts = segmentShifts(spans, pattern);
    assert.equal(Math.max(...shifts), 0, pattern);
    assert.ok(shifts.every((x) => x <= 0), pattern);
  }
  assert.deepEqual(segmentShifts([5], 'PROGRESSIVE'), [0]);
  assert.deepEqual(segmentShifts([], 'BURST'), []);
});

check('every pattern keeps each segment internally ordered; separation and interleaving are the patterns own', () => {
  for (const pattern of PATTERNS) {
    const p = plan1({ scenarioId: 'brute', targetMode: 'MULTI', entityIds: ['HOST-A', 'HOST-B'], pattern });
    assert.equal(p.eventCount, 18, pattern);
    assert.equal(new Set(ids(p.events)).size, 18, pattern);
    assert.deepEqual(validateEvents(p.events, NOW), [], pattern);
    for (const entityId of p.targets) {
      const own = p.events.filter((e) => e.entityId === entityId);
      assert.deepEqual(ids(own), ids(own).slice().sort(), `${pattern}/${entityId}: the plan reordered a segment`);
      assert.deepEqual(times(own), [...times(own)].sort((a, b) => a - b), `${pattern}/${entityId}`);
    }
    // How often the plan hands the transport a different entity than the previous event.
    const alternations = p.events.filter((e, i) => i > 0 && e.entityId !== p.events[i - 1].entityId).length;
    if (pattern === 'DISTRIBUTED') assert.equal(alternations, 17, 'DISTRIBUTED must alternate on every submission');
    // BURST anchors both campaigns to the same instant, so they fully overlap by construction
    else if (pattern === 'BURST') assert.ok(alternations >= 8, `BURST should interleave, got ${alternations}`);
    // SEQUENTIAL and PROGRESSIVE separate the campaigns in time, so the plan finishes one before the next
    else assert.equal(alternations, 1, `${pattern}: ${alternations} alternations`);
  }
});

check('BURST compresses the run into one window; SEQUENTIAL spreads it out', () => {
  const multi = { scenarioId: 'brute', targetMode: 'MULTI', entityIds: ['HOST-A', 'HOST-B'] };
  const burst = plan1({ ...multi, pattern: 'BURST' });
  const seq = plan1({ ...multi, pattern: 'SEQUENTIAL' });
  assert.ok(burst.spanSec < seq.spanSec, `${burst.spanSec} vs ${seq.spanSec}`);
  assert.equal(burst.spanSec, 80, 'BURST is one segment span wide');
  assert.ok(plan1({ scenarioId: 'routine' }).notes.some((n) => /every attack pattern produces the same plan/.test(n)), 'a one-segment plan should say patterns coincide');
});

/* ---------------- duration ---------------- */

check('duration presets and a valid custom value resolve; an invalid custom value does not', () => {
  assert.deepEqual(DURATION_PRESETS, [15, 30, 60]);
  for (const seconds of DURATION_PRESETS) assert.equal(resolveDurationMs(cfg({ duration: seconds })), seconds * 1000);
  assert.equal(resolveDurationMs(cfg({ duration: 'CUSTOM', customDurationSec: ' 45 ' })), 45_000);
  assert.equal(resolveDurationMs(cfg({ duration: 'CUSTOM', customDurationSec: String(MIN_CUSTOM_DURATION_SEC) })), MIN_CUSTOM_DURATION_SEC * 1000);
  assert.equal(resolveDurationMs(cfg({ duration: 'CUSTOM', customDurationSec: String(MAX_CUSTOM_DURATION_SEC) })), MAX_CUSTOM_DURATION_SEC * 1000);
  for (const bad of ['', '0', '4', '601', '-5', '12.5', 'abc', '1e3', '30s', ' ']) {
    assert.equal(resolveDurationMs(cfg({ duration: 'CUSTOM', customDurationSec: bad })), null, JSON.stringify(bad));
  }
});

check('an invalid custom duration blocks the run and explains itself', () => {
  const p = plan1({ scenarioId: 'routine', duration: 'CUSTOM', customDurationSec: '9999' });
  assert.equal(canStart(p), false);
  assert.equal(p.maxDurationMs, null);
  assert.match(p.configIssues[0].message, /whole seconds between 5 and 600/);
  assert.ok(p.events.length > 0, 'the plan is still previewable, it just cannot start');
  const blank = plan1({ scenarioId: 'routine', duration: 'CUSTOM', customDurationSec: '' });
  assert.match(blank.configIssues[0].message, /Enter a custom duration/);
  assert.equal(canStart(plan1({ scenarioId: 'routine', duration: 'CUSTOM', customDurationSec: '45' })), true);
});

check('a duration cap that truncates the plan is called out in the preview', () => {
  const p = plan1({ scenarioId: 'mixed', intensity: 'HIGH', duration: 15, eventRate: 1 });
  assert.equal(p.eventCount, 29);
  assert.equal(p.plannedSends, 15);
  assert.ok(p.notes.some((n) => /duration cap stops the run after about 15 of 29/.test(n)));
  assert.equal(plan1({ scenarioId: 'mixed', intensity: 'HIGH', duration: 60, eventRate: 5 }).plannedSends, 29);
});

/* ---------------- rate ---------------- */

check('the console offers only 1, 2 and 5 events/sec, defaults to 2, and can never exceed the engine cap', () => {
  assert.deepEqual(RATE_OPTIONS, [1, 2, 5]);
  assert.equal(DEFAULT_CONFIG.eventRate, 2);
  assert.equal(MAX_EVENT_RATE, 5);
  assert.ok(RATE_OPTIONS.every((r) => r <= MAX_EVENT_RATE));
  // anything else is a configuration error, and the engine clamps on top of that
  for (const rate of [0, 6, 10, 100, Number.NaN, -1]) {
    assert.ok(validateConfig(cfg({ eventRate: rate }), AVAIL).some((i) => i.level === 'error'), String(rate));
    assert.equal(canStart(plan1({ eventRate: rate })), false, String(rate));
    assert.ok(clampRate(rate) <= MAX_EVENT_RATE, String(rate));
  }
});

/* ---------------- configuration gates ---------------- */

check('an invalid configuration can never start', () => {
  const bad: [string, Record<string, unknown>, RegExp][] = [
    ['unknown scenario', { scenarioId: 'nope' }, /Unknown scenario/],
    ['no entity chosen', { entityId: '' }, /Choose a target entity/],
    ['unknown entity', { entityId: 'GHOST' }, /not one of the monitored entities/],
    ['one entity for MULTI', { targetMode: 'MULTI', entityIds: ['HOST-A'] }, /at least two/],
    ['no entity for DISTRIBUTED', { targetMode: 'DISTRIBUTED', entityIds: [] }, /at least two/],
    ['too many entities', { targetMode: 'MULTI', entityIds: ['H0', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6'] }, /At most 6 entities/],
    ['bad rate', { eventRate: 3 }, /Event rate must be one of/],
    ['bad duration', { duration: 'CUSTOM', customDurationSec: 'x' }, /not a usable duration/],
    ['bad noise', { noisePercent: 55 }, /Benign noise must be one of/],
    ['bad intensity', { intensity: 'EXTREME' }, /Unknown intensity/],
    ['bad pattern', { pattern: 'PARALLEL' }, /Unknown attack pattern/],
  ];
  for (const [name, patch, pattern] of bad) {
    const available = name === 'too many entities' ? ['H0', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6'] : AVAIL;
    const p = buildPreview(cfg(patch), { runId: 'SIM-BAD', now: NOW, available });
    assert.equal(canStart(p), false, name);
    assert.match(p.issues.map((i) => i.message).join(' | '), pattern, name);
  }
  // with no entity at all nothing is startable, whatever else is configured
  const none = buildPreview(cfg(), { runId: 'SIM-NONE', now: NOW, available: [] });
  assert.equal(canStart(none), false);
  assert.match(none.issues.map((i) => i.message).join(' '), /No monitored entity is available/);
  // and with nothing to target the plan is empty rather than guessed at
  const nothing = buildPreview(cfg({ entityId: '' }), { runId: 'SIM-NONE', now: NOW, available: [] });
  assert.equal(nothing.eventCount, 0);
  assert.deepEqual(nothing.events, []);
  assert.equal(canStart(nothing), false);
  // a well-formed default configuration is startable
  assert.equal(canStart(plan1()), true);
  assert.deepEqual(validateConfig(cfg(), AVAIL), []);
});

check('confirmation is asked for a substantial run and skipped for a small default one', () => {
  assert.equal(needsConfirmation(plan1({ scenarioId: 'routine' })), false, '3 events on one entity');
  assert.equal(needsConfirmation(plan1({ scenarioId: 'device' })), false);
  assert.equal(needsConfirmation(plan1({ scenarioId: 'brute' })), false, '9 events is still small');
  assert.equal(needsConfirmation(plan1({ scenarioId: 'portscan', intensity: 'HIGH' })), true, '20 events');
  assert.equal(needsConfirmation(plan1({ scenarioId: 'routine', noisePercent: 10 })), true, 'noise changes what is sent');
  assert.equal(needsConfirmation(plan1({ scenarioId: 'routine', targetMode: 'MULTI', entityIds: ['HOST-A', 'HOST-B'] })), true, 'more than one entity');
});

/* ---------------- the dry run touches nothing ---------------- */

check('the planner imports no transport at all', () => {
  for (const file of ['planner.ts', 'advancedBuilders.ts', 'scenarioRegistry.ts', 'builders.ts', 'validation.ts']) {
    const source = readFileSync(new URL(`../src/simulator/${file}`, import.meta.url), 'utf8');
    for (const forbidden of ['api/endpoints', 'eventsApi', 'axios', 'fetch(', 'XMLHttpRequest', 'sendBeacon']) {
      assert.ok(!source.includes(forbidden), `${file} references ${forbidden}`);
    }
  }
});

check('previewing never performs a request, however the run is configured', () => {
  // Any real transport would have to go through one of these; count every attempt.
  let attempts = 0;
  const g = globalThis as unknown as Record<string, unknown>;
  const saved = { fetch: g.fetch, XMLHttpRequest: g.XMLHttpRequest };
  g.fetch = (...a: unknown[]) => {
    attempts++;
    return Promise.reject(new Error(`the preview tried to reach ${String(a[0])}`));
  };
  g.XMLHttpRequest = class {
    constructor() {
      attempts++;
    }
  };
  try {
    let built = 0;
    for (const s of SCENARIOS) {
      for (const pattern of PATTERNS) {
        for (const intensity of INTENSITIES) {
          for (const percent of NOISE_OPTIONS) {
            for (const targetMode of ['SINGLE', 'RANDOM', 'MULTI', 'DISTRIBUTED']) {
              const p = plan1({ scenarioId: s.id, pattern, intensity, noisePercent: percent, targetMode });
              assert.ok(p.eventCount > 0, `${s.id}/${pattern}/${intensity}/${percent}/${targetMode}`);
              built++;
            }
          }
        }
      }
    }
    assert.equal(built, SCENARIOS.length * PATTERNS.length * INTENSITIES.length * NOISE_OPTIONS.length * 4);
    assert.equal(attempts, 0, `${attempts} request attempt(s) during preview`);
  } finally {
    g.fetch = saved.fetch;
    g.XMLHttpRequest = saved.XMLHttpRequest;
  }
});

check('every plan of every configuration is valid, uniquely identified and never in the future', () => {
  let plans = 0;
  for (const s of SCENARIOS) {
    for (const pattern of PATTERNS) {
      for (const intensity of INTENSITIES) {
        for (const percent of NOISE_OPTIONS) {
          for (const targetMode of ['SINGLE', 'RANDOM', 'MULTI', 'DISTRIBUTED']) {
            const label = `${s.id}/${pattern}/${intensity}/${percent}%/${targetMode}`;
            const p = plan1({ scenarioId: s.id, pattern, intensity, noisePercent: percent, targetMode });
            assert.deepEqual(validateEvents(p.events, NOW), [], label);
            assert.equal(new Set(ids(p.events)).size, p.eventCount, `${label}: duplicate eventId`);
            assert.ok(p.events.every((e) => Date.parse(e.occurredAt) <= NOW), `${label}: an event in the future`);
            assert.ok(p.events.every((e) => e.source === 'simulator' && e.eventVersion === 'v1'), label);
            assert.ok(p.events.every((e) => e.eventId.startsWith(p.runId)), `${label}: an eventId outside the run namespace`);
            assert.ok(p.events.every((e) => e.eventId.length <= 128), label);
            assert.equal(p.scenarioEventCount + p.noiseEventCount, p.eventCount, label);
            assert.equal(p.eventTypes.reduce((n, x) => n + x.count, 0), p.eventCount, label);
            assert.equal(p.distribution.reduce((n, x) => n + x.count, 0), p.eventCount, label);
            assert.equal(canStart(p), true, label);
            plans++;
          }
        }
      }
    }
  }
  assert.equal(plans, SCENARIOS.length * PATTERNS.length * INTENSITIES.length * NOISE_OPTIONS.length * 4);
  assert.equal(plans, 2304);
});

await acheck('the engine submits exactly the previewed events, in exactly the previewed order', async () => {
  const cases: [string, Record<string, unknown>][] = [
    ['mixed', { intensity: 'HIGH' }],
    ['procconn', { targetMode: 'DISTRIBUTED', pattern: 'DISTRIBUTED', intensity: 'HIGH', noisePercent: 20 }],
    ['brute', { targetMode: 'MULTI', pattern: 'BURST', noisePercent: 30 }],
    ['portscan', { pattern: 'PROGRESSIVE', intensity: 'HIGH' }],
  ];
  for (const [scenarioId, patch] of cases) {
    const p = plan1({ scenarioId, ...patch });
    const { engine, clock, t, snap } = setup();
    engine.start(toRunPlan(p), { eventRate: p.config.eventRate, maxDurationMs: null });
    await clock.advance(600_000);
    assert.equal(snap().state, 'COMPLETED', scenarioId);
    assert.deepEqual(t.calls.map((c) => c.eventId), ids(p.events), scenarioId);
    assert.equal(t.maxInFlight, 1, `${scenarioId}: the planner must not break one-POST-at-a-time`);
    assert.equal(snap().accepted, p.eventCount, scenarioId);
  }
});

await acheck('the previewed duration cut-off matches what the engine really sends', async () => {
  for (const [events, rate, durationSec] of [[10, 2, 15], [10, 2, 2], [20, 5, 3], [6, 1, 60], [8, 1, 4]] as const) {
    const predicted = sendsWithin(events, rate, durationSec * 1000);
    const { engine, clock, t } = setup();
    engine.start(plan(events), { eventRate: rate, maxDurationMs: durationSec * 1000 });
    await clock.advance(600_000);
    assert.equal(t.calls.length, predicted, `${events}@${rate}/s for ${durationSec}s: the engine sent ${t.calls.length}, the preview said ${predicted}`);
  }
  assert.equal(sendsWithin(10, 2, null), 10, 'no cap means the whole plan');
});

await acheck('no plan can ask the engine for more than 5 events/sec', async () => {
  // the only rate a plan can carry is one of RATE_OPTIONS, and the engine honours it exactly
  for (const rate of RATE_OPTIONS) {
    const p = plan1({ scenarioId: 'brute', eventRate: rate });
    assert.equal(canStart(p), true, String(rate));
    const { engine, clock, t, snap } = setup();
    engine.start(toRunPlan(p), { eventRate: p.config.eventRate });
    await clock.advance(600_000);
    assert.ok(snap().eventRate <= MAX_EVENT_RATE, String(rate));
    const gaps = t.calls.slice(1).map((c, i) => c.at - t.calls[i].at);
    assert.ok(gaps.every((g) => g >= 1000 / MAX_EVENT_RATE), `${rate}: a gap under ${1000 / MAX_EVENT_RATE} ms`);
    assert.ok(gaps.every((g) => g === 1000 / rate), `${rate}: ${gaps.join(',')}`);
  }
});
/* P4 */
/* ======================================================================================
 * PHASE 4 - the live execution console: bounded observation on top of the Phase 2 engine.
 * The console is driven by the same fake clock as the engine and a fake trail/incident
 * transport. Nothing here reaches a real backend, and the console never sends an event.
 * ==================================================================================== */

type FakeTrail = {
  eventId: string;
  processingStatus: 'PENDING' | 'PROCESSED' | 'FAILED';
  processingAttempts: number;
  lastProcessingError?: string | null;
  prediction: { fusedScore?: number; anomalyScore: number; decision: string } | null;
  alert: null;
  alerts: { id: string; severity: string; status: string; ruleId?: string | null; detectionType?: string; incidentId?: string | null }[];
};

const trailOf = (eventId: string, patch: Partial<FakeTrail> = {}): FakeTrail => ({
  eventId,
  processingStatus: 'PROCESSED',
  processingAttempts: 1,
  prediction: null,
  alert: null,
  alerts: [],
  ...patch,
});

/** A RunSnapshot with `done` results already settled, as the engine would have emitted it. */
function snapOf(done: number, total: number, opts: { runId?: string; state?: string; failEvery?: number; step?: number; stopReason?: string | null } = {}) {
  const runId = opts.runId ?? 'SIM-LIVE-RUN';
  const step = opts.step ?? 500;
  const results = Array.from({ length: done }, (_, i) => {
    const failed = opts.failEvery ? (i + 1) % opts.failEvery === 0 : false;
    return {
      index: i,
      eventId: `${runId}-${String(i + 1).padStart(3, '0')}`,
      eventType: i % 2 === 0 ? 'LOGIN' : 'FILE_ACCESS',
      entityId: i % 3 === 0 ? 'HOST-A' : 'HOST-B',
      occurredAt: new Date(NOW + i * 1000).toISOString(),
      status: failed ? 'FAILED' : 'ACCEPTED',
      submittedAt: NOW + i * step,
      settledAt: NOW + i * step + 5,
      error: failed ? { status: 409, code: 'HTTP_409', message: 'Duplicate event', systemic: false } : undefined,
    };
  });
  const failed = results.filter((r) => r.status === 'FAILED').length;
  return {
    runId,
    label: 'Live fixture',
    state: opts.state ?? (done >= total ? 'COMPLETED' : 'RUNNING'),
    stopReason: opts.stopReason ?? null,
    failureReason: null,
    totalEvents: total,
    nextEventIndex: done,
    currentEventIndex: -1,
    generated: done,
    accepted: done - failed,
    failed,
    startedAt: NOW,
    finishedAt: done >= total ? NOW + done * step : null,
    eventRate: 2,
    maxDurationMs: null,
    results,
  } as never;
}

/** A console on the shared fake clock, with a scripted trail/incident transport. */
function liveSetup(opts: {
  clock?: FakeClock;
  trail?: (eventId: string, call: number) => FakeTrail | 'defer' | 'error';
  incident?: (id: string) => unknown | 'defer' | 'error';
} = {}) {
  // Align with the NOW the fixture snapshots use, so the observation window is meaningful here.
  const clock = opts.clock ?? Object.assign(new FakeClock(), { t: NOW });
  const trailCalls: string[] = [];
  const incidentCalls: string[] = [];
  const perEvent = new Map<string, number>();
  const deferred: { resolve: (v: unknown) => void; reject: (e: unknown) => void }[] = [];
  let inFlight = 0;
  let maxInFlight = 0;

  const wrap = <T,>(p: Promise<T>) => p.then(
    (v) => { inFlight--; return v; },
    (e) => { inFlight--; throw e; },
  );

  const console_ = new LiveConsole({
    now: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    fetchTrail: (eventId) => {
      trailCalls.push(eventId);
      const n = (perEvent.get(eventId) ?? 0) + 1;
      perEvent.set(eventId, n);
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      const out = opts.trail ? opts.trail(eventId, n) : trailOf(eventId);
      if (out === 'defer') return wrap(new Promise((resolve, reject) => deferred.push({ resolve, reject }))) as never;
      if (out === 'error') return wrap(Promise.reject(new Error('trail unavailable'))) as never;
      return wrap(Promise.resolve(out)) as never;
    },
    fetchIncident: (id) => {
      incidentCalls.push(id);
      inFlight++;
      const out = opts.incident ? opts.incident(id) : { id, incidentKey: 'k', entityId: 'HOST-A', status: 'OPEN', summary: 'Observed', createdAt: '', updatedAt: '', alertCount: 1, maxSeverity: 'HIGH' };
      if (out === 'defer') return wrap(new Promise((resolve, reject) => deferred.push({ resolve, reject }))) as never;
      if (out === 'error') return wrap(Promise.reject(new Error('incident unavailable'))) as never;
      return wrap(Promise.resolve(out)) as never;
    },
  });

  return {
    clock,
    console: console_,
    trailCalls,
    incidentCalls,
    perEvent,
    deferred,
    get maxInFlight() { return maxInFlight; },
    snap: () => console_.getSnapshot(),
  };
}

/* ---------------- bounded memory ---------------- */

await acheck('the live event collection is bounded, and its cumulative counters survive trimming', async () => {
  const L = liveSetup();
  const detach = L.console.attach();
  const TOTAL = 900; // far past LIVE_ROW_HARD_LIMIT, and past anything a plan can produce
  for (let i = 1; i <= TOTAL; i++) L.console.ingest(snapOf(i, TOTAL));

  const s = L.snap();
  assert.equal(s.rows.length, LIVE_ROW_HARD_LIMIT, 'the retained row set must stay bounded');
  assert.ok(LIVE_ROW_LIMIT <= LIVE_ROW_HARD_LIMIT);
  // counters are cumulative: trimming a row never loses a submission
  assert.equal(s.totals.rowsSeen, TOTAL);
  assert.equal(s.totals.trimmed, TOTAL - LIVE_ROW_HARD_LIMIT);
  assert.equal(s.totals.rowsSeen - s.totals.trimmed, s.rows.length);
  // the newest rows are the ones kept, newest first, with stable unique keys
  assert.equal(s.rows[0].seq, TOTAL);
  assert.equal(s.rows[s.rows.length - 1].seq, TOTAL - LIVE_ROW_HARD_LIMIT + 1);
  assert.deepEqual(s.rows.map((r) => r.seq), [...s.rows.map((r) => r.seq)].sort((a, b) => b - a));
  assert.equal(new Set(s.rows.map((r) => r.eventId)).size, s.rows.length, 'row keys must be unique');
  detach();
});

await acheck('the activity timeline is bounded too', async () => {
  const L = liveSetup();
  const detach = L.console.attach();
  for (let i = 1; i <= 400; i++) L.console.ingest(snapOf(i, 400, { failEvery: 3 }));
  const s = L.snap();
  assert.equal(s.activity.length, ACTIVITY_LIMIT, 'the feed must not grow with the run');
  assert.equal(new Set(s.activity.map((a) => a.id)).size, s.activity.length, 'activity keys must be unique');
  // newest first
  assert.deepEqual(s.activity.map((a) => a.id), [...s.activity.map((a) => a.id)].sort((a, b) => b - a));
  detach();
});

/* ---------------- counters ---------------- */

await acheck('accepted and failed counters follow the engine, including HTTP status on a rejection', async () => {
  const L = liveSetup();
  const detach = L.console.attach();
  for (let i = 1; i <= 10; i++) L.console.ingest(snapOf(i, 10, { failEvery: 5 }));
  const s = L.snap();
  const failedRows = s.rows.filter((r) => r.status === 'FAILED');
  assert.equal(failedRows.length, 2, 'events 5 and 10 were rejected');
  assert.equal(failedRows[0].httpStatus, 409);
  assert.match(failedRows[0].sendError ?? '', /Duplicate event/);
  assert.ok(failedRows.every((r) => r.resolved), 'a rejected POST stored nothing, so there is no trail to wait for');
  assert.equal(s.rows.filter((r) => r.status === 'ACCEPTED').length, 8);
  // a failed submission is never polled
  await L.clock.advance(60_000);
  assert.ok(L.trailCalls.every((id) => !failedRows.some((r) => r.eventId === id)), 'a rejected event must never be polled');
  detach();
});

await acheck('the actual event rate comes from real submission timestamps, not the configured rate', async () => {
  for (const [stepMs, expected] of [[500, 2], [1000, 1], [200, 5]] as const) {
    const L = liveSetup();
    const detach = L.console.attach();
    for (let i = 1; i <= 12; i++) L.console.ingest(snapOf(i, 12, { step: stepMs }));
    const actual = L.snap().actualRate;
    assert.ok(actual !== null && Math.abs(actual - expected) < 1e-9, `${stepMs} ms apart should read ${expected}/s, got ${actual}`);
    detach();
  }
  // a single submission cannot define a rate, and the console says so rather than guessing
  const one = liveSetup();
  const off = one.console.attach();
  one.console.ingest(snapOf(1, 4));
  assert.equal(one.snap().actualRate, null);
  off();
});

await acheck('peak score, alert aggregation and incident aggregation count DISTINCT observations', async () => {
  const L = liveSetup({
    trail: (eventId) => {
      const n = Number(eventId.slice(-3));
      if (n === 1) return trailOf(eventId, { prediction: { anomalyScore: 0.42, decision: 'NORMAL' } });
      if (n === 2) return trailOf(eventId, { prediction: { anomalyScore: 0.3, fusedScore: 0.91, decision: 'ANOMALOUS' }, alerts: [{ id: 'AL-1', severity: 'HIGH', status: 'OPEN', detectionType: 'ML', incidentId: 'INC-1' }] });
      // two different events belonging to the SAME incident, and one alert seen twice
      if (n === 3) return trailOf(eventId, { alerts: [{ id: 'AL-2', severity: 'MEDIUM', status: 'OPEN', ruleId: 'AUTH_BURST', detectionType: 'RULE', incidentId: 'INC-1' }] });
      if (n === 4) return trailOf(eventId, { alerts: [{ id: 'AL-2', severity: 'MEDIUM', status: 'OPEN', ruleId: 'AUTH_BURST', detectionType: 'RULE', incidentId: 'INC-1' }] });
      return trailOf(eventId);
    },
  });
  const detach = L.console.attach();
  for (let i = 1; i <= 5; i++) L.console.ingest(snapOf(i, 5));
  await L.clock.advance(60_000);

  const s = L.snap();
  assert.equal(s.totals.peakScore, 0.91, 'the fused score wins over the anomaly score, and the peak is the maximum');
  assert.equal(s.totals.alerts, 2, 'AL-2 appears on two events but is one alert');
  assert.equal(s.totals.incidents, 1, 'three alerts, one incident');
  assert.deepEqual(s.totals.severity, { HIGH: 1, MEDIUM: 1 });
  assert.deepEqual(s.totals.detectors, { ML: 1, AUTH_BURST: 1 });
  assert.equal(s.totals.observed, 5);
  assert.equal(s.totals.processed, 5);
  // the incident was looked up once, through the existing incidents API
  assert.deepEqual(L.incidentCalls, ['INC-1']);
  assert.deepEqual(s.incidents.map((i) => `${i.id}:${i.status}`), ['INC-1:OPEN']);
  // and the derived row status reflects what was observed, never the scenario it came from
  const byId = new Map(s.rows.map((r) => [r.eventId, r]));
  assert.equal(byId.get('SIM-LIVE-RUN-001')!.status, 'PROCESSED');
  assert.equal(byId.get('SIM-LIVE-RUN-002')!.status, 'INCIDENT');
  assert.equal(byId.get('SIM-LIVE-RUN-005')!.status, 'PROCESSED');
  detach();
});

await acheck('an unobserved event is never reported as "no alert"', async () => {
  // The trail never answers, so nothing may be concluded about detection.
  const L = liveSetup({ trail: () => 'error' });
  const detach = L.console.attach();
  L.console.ingest(snapOf(3, 3));
  await L.clock.advance(TRAIL_POLL_INTERVAL_MS * (TRAIL_MAX_ATTEMPTS + 4));
  const s = L.snap();
  for (const row of s.rows) {
    assert.equal(row.observed, false, 'nothing was observed');
    assert.equal(row.processing, null);
    assert.deepEqual(row.alerts, []);
    assert.equal(row.status, 'ACCEPTED', 'still just accepted - never PROCESSED, never "no alert"');
    assert.equal(row.gaveUp, true);
  }
  assert.equal(s.totals.observed, 0);
  assert.equal(s.totals.processed, 0);
  assert.equal(s.totals.alerts, 0);
  assert.equal(s.totals.unobserved, 3);
  assert.equal(s.totals.peakScore, null, 'a peak score is never invented');
  detach();
});

/* ---------------- polling architecture ---------------- */

await acheck('polling is one shared timer with a bounded batch - never one loop per event', async () => {
  const L = liveSetup({ trail: () => 'defer' });
  const detach = L.console.attach();
  L.console.ingest(snapOf(120, 120));

  assert.equal(L.console.pendingTimers(), 1, 'exactly one shared timer, whatever the row count');
  await L.clock.advance(TRAIL_POLL_INTERVAL_MS);
  assert.equal(L.trailCalls.length, TRAIL_POLL_BATCH, 'the first tick fires one bounded batch');

  // Later ticks must not stack on top of an unsettled batch. With the batch budget full there is
  // nothing a tick could do, so the timer is released and a settlement re-arms it - which is the
  // only reason the console can never accumulate timers or requests.
  await L.clock.advance(TRAIL_POLL_INTERVAL_MS * 20);
  assert.equal(L.trailCalls.length, TRAIL_POLL_BATCH, 'no further requests while the batch is in flight');
  assert.equal(L.console.inFlightCount(), TRAIL_POLL_BATCH);
  assert.ok(L.maxInFlight <= TRAIL_POLL_BATCH, `concurrency reached ${L.maxInFlight}`);
  assert.equal(L.console.pendingTimers(), 0, 'the budget is full, so no timer is held');

  // settle the batch: the next tick may take the next batch, and only the next batch
  for (const d of L.deferred.splice(0)) d.resolve(trailOf('x', { processingStatus: 'PENDING' }));
  await L.clock.advance(TRAIL_POLL_INTERVAL_MS);
  assert.equal(L.trailCalls.length, TRAIL_POLL_BATCH * 2, 'exactly one more batch');
  assert.ok(L.maxInFlight <= TRAIL_POLL_BATCH, `concurrency reached ${L.maxInFlight}`);
  assert.equal(L.console.pendingTimers(), 0);
  // the 120 rows never produced 120 timers or 120 requests
  assert.ok(L.trailCalls.length <= TRAIL_POLL_BATCH * 2);
  detach();
});

await acheck('one event never has two trail requests in flight at once', async () => {
  const L = liveSetup({ trail: () => 'defer' });
  const detach = L.console.attach();
  L.console.ingest(snapOf(3, 3));
  await L.clock.advance(TRAIL_POLL_INTERVAL_MS * 30);
  assert.equal(L.trailCalls.length, 3, 'three events, three in-flight requests, and no duplicates');
  assert.equal(new Set(L.trailCalls).size, 3);
  for (const [, n] of L.perEvent) assert.equal(n, 1, 'an event with a request in flight is not a candidate again');
  detach();
});

await acheck('polling stops for an event the backend has finished with, and the timer disarms', async () => {
  for (const terminal of ['PROCESSED', 'FAILED'] as const) {
    const L = liveSetup({ trail: (id, n) => trailOf(id, n === 1 ? { processingStatus: 'PENDING' } : { processingStatus: terminal, lastProcessingError: terminal === 'FAILED' ? 'ML service unavailable' : null }) });
    const detach = L.console.attach();
    L.console.ingest(snapOf(4, 4));
    await L.clock.advance(TRAIL_POLL_INTERVAL_MS * 3);

    assert.equal(L.trailCalls.length, 8, `${terminal}: exactly two polls per event - PENDING then terminal`);
    assert.ok(L.snap().rows.every((r) => r.resolved), terminal);
    assert.equal(L.snap().pending, 0, terminal);
    assert.equal(L.console.pendingTimers(), 0, `${terminal}: nothing left to poll, so no timer is held`);

    // and it stays stopped
    await L.clock.advance(600_000);
    assert.equal(L.trailCalls.length, 8, `${terminal}: no polling after every event reached a terminal state`);
    assert.equal(L.snap().totals[terminal === 'PROCESSED' ? 'processed' : 'processingFailed'], 4, terminal);
    detach();
  }
});

await acheck('polling gives up at the attempt cap and after the observation window, and says so', async () => {
  // Always PENDING: the backend never finishes, so the attempt cap is what ends it.
  const capped = liveSetup({ trail: (id) => trailOf(id, { processingStatus: 'PENDING' }) });
  const offCap = capped.console.attach();
  capped.console.ingest(snapOf(2, 2, { state: 'RUNNING' }));
  await capped.clock.advance(TRAIL_POLL_INTERVAL_MS * (TRAIL_MAX_ATTEMPTS + 5));
  assert.equal(capped.trailCalls.length, 2 * TRAIL_MAX_ATTEMPTS, 'at most TRAIL_MAX_ATTEMPTS polls per event');
  assert.equal(capped.console.pendingTimers(), 0);
  assert.ok(capped.snap().rows.every((r) => r.observed && r.resolved));
  offCap();

  // A finished run is observed for TRAIL_OBSERVATION_MS and no longer - including across a page
  // that was closed and reopened later, which is the case the attempt cap alone cannot cover.
  const windowed = liveSetup({ trail: (id) => trailOf(id, { processingStatus: 'PENDING' }) });
  const offWin = windowed.console.attach();
  windowed.console.ingest(snapOf(2, 2)); // COMPLETED, so finishedAt is set
  await windowed.clock.advance(TRAIL_POLL_INTERVAL_MS);
  const during = windowed.trailCalls.length;
  assert.ok(during > 0, 'inside the window the run is observed');
  assert.ok(windowed.snap().rows.every((r) => r.observed && !r.resolved), 'still PENDING, so still being observed');

  offWin(); // the page was closed
  windowed.clock.t += TRAIL_OBSERVATION_MS * 3; // ... and reopened much later
  const backWin = windowed.console.attach();
  await windowed.clock.advance(600_000);
  assert.equal(windowed.trailCalls.length, during, 'nothing is polled past the observation window');
  assert.equal(windowed.console.pendingTimers(), 0, 'the window closed, so no timer is held');
  assert.ok(windowed.snap().rows.every((r) => r.resolved), 'and the rows stop waiting for an answer that cannot come');
  assert.ok(windowed.snap().rows.every((r) => r.processing === 'PENDING'), 'their last known state is kept, not upgraded');
  assert.equal(windowed.snap().pending, 0, 'nothing is left awaiting a trail');
  backWin();
});

await acheck('polling stops on reset and on unmount, and a stale answer can never mutate the new state', async () => {
  // --- reset
  const onReset = liveSetup({ trail: () => 'defer' });
  const detach = onReset.console.attach();
  onReset.console.ingest(snapOf(5, 5));
  await onReset.clock.advance(TRAIL_POLL_INTERVAL_MS);
  assert.equal(onReset.console.inFlightCount(), 5);

  onReset.console.reset();
  assert.equal(onReset.console.pendingTimers(), 0, 'reset releases the shared timer');
  assert.deepEqual(onReset.snap().rows, []);
  assert.equal(onReset.snap().runId, null);

  // the requests that were in flight now settle - with an alert, a score and an incident
  for (const d of onReset.deferred.splice(0)) {
    d.resolve(trailOf('SIM-LIVE-RUN-001', { prediction: { anomalyScore: 0.99, decision: 'ANOMALOUS' }, alerts: [{ id: 'AL-STALE', severity: 'CRITICAL', status: 'OPEN', incidentId: 'INC-STALE' }] }));
  }
  await onReset.clock.advance(60_000);
  const s = onReset.snap();
  assert.deepEqual(s.rows, [], 'a stale answer must not resurrect a row');
  assert.equal(s.totals.alerts, 0, 'a stale answer must not add an alert');
  assert.equal(s.totals.incidents, 0);
  assert.equal(s.totals.observed, 0);
  assert.equal(s.totals.peakScore, null);
  assert.equal(onReset.incidentCalls.length, 0, 'and must not trigger an incident look-up');
  assert.equal(onReset.console.pendingTimers(), 0);
  detach();

  // --- unmount
  const onUnmount = liveSetup({ trail: (id) => trailOf(id, { processingStatus: 'PENDING' }) });
  const off = onUnmount.console.attach();
  onUnmount.console.ingest(snapOf(4, 4, { state: 'RUNNING' }));
  await onUnmount.clock.advance(TRAIL_POLL_INTERVAL_MS * 2);
  const before = onUnmount.trailCalls.length;
  assert.ok(before > 0);

  off(); // the page unmounted
  assert.equal(onUnmount.console.pendingTimers(), 0, 'an unmounted console holds no timer');
  await onUnmount.clock.advance(600_000);
  assert.equal(onUnmount.trailCalls.length, before, 'and polls nothing while unmounted');

  // remounting picks the observation back up without losing what was already counted
  const back = onUnmount.console.attach();
  onUnmount.console.ingest(snapOf(4, 4, { state: 'RUNNING' }));
  await onUnmount.clock.advance(TRAIL_POLL_INTERVAL_MS);
  assert.ok(onUnmount.trailCalls.length > before, 'remounting resumes observation');
  back();
});

await acheck('a detached console never arms a timer, however much it is fed', async () => {
  const L = liveSetup({ trail: () => 'defer' });
  for (let i = 1; i <= 50; i++) L.console.ingest(snapOf(i, 50));
  assert.equal(L.console.pendingTimers(), 0);
  await L.clock.advance(600_000);
  assert.equal(L.trailCalls.length, 0, 'no mount, no polling');
  assert.equal(L.snap().rows.length, 50, 'but the rows are still observed from the engine snapshot');
});

/* ---------------- lifecycle ---------------- */

await acheck('pause and resume never reset a counter, and stop schedules nothing new', async () => {
  const clock = new FakeClock();
  const t = mockTransport(clock);
  const engine = new SimulationEngine({ send: t.send, now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  const L = liveSetup({ clock, trail: (id) => trailOf(id, { processingStatus: 'PENDING' }) });
  const detach = L.console.attach();
  engine.subscribe(() => L.console.ingest(engine.getSnapshot()));

  engine.start(plan(12), { eventRate: 2 });
  await clock.advance(1100); // events at 0, 500, 1000
  const atPause = { rows: L.snap().rows.length, seen: L.snap().totals.rowsSeen };
  assert.equal(atPause.rows, 3);

  engine.pause();
  await clock.advance(30_000);
  assert.equal(engine.getSnapshot().state, 'PAUSED');
  assert.equal(L.snap().totals.rowsSeen, atPause.seen, 'pausing does not change what was already counted');
  assert.equal(L.snap().rows.length, atPause.rows, 'and does not drop a row');
  assert.ok(L.snap().activity.some((a) => a.kind === 'PAUSED'), 'the pause is in the feed');

  engine.resume();
  await clock.advance(1100);
  assert.ok(L.snap().totals.rowsSeen > atPause.seen, 'resuming continues the same plan');
  assert.ok(L.snap().activity.some((a) => a.kind === 'RESUMED'));
  const atStop = L.snap().totals.rowsSeen;

  engine.stop();
  await clock.advance(600_000);
  assert.equal(engine.getSnapshot().state, 'STOPPED');
  assert.equal(L.snap().totals.rowsSeen, atStop, 'stop schedules no further event');
  assert.equal(t.calls.length, atStop, 'and the transport saw exactly as many submissions');
  assert.ok(L.snap().activity.some((a) => a.label === 'RUN STOPPED'));
  detach();
});

await acheck('the completion summary reports the engine outcome and the observed totals, never a guess', async () => {
  // COMPLETED
  const done = liveSetup();
  const offDone = done.console.attach();
  for (let i = 1; i <= 6; i++) done.console.ingest(snapOf(i, 6));
  await done.clock.advance(60_000);
  const sDone = completionSummary(snapOf(6, 6) as never, done.snap())!;
  assert.equal(sDone.outcome, 'COMPLETED');
  assert.equal(sDone.generated, 6);
  assert.equal(sDone.accepted, 6);
  assert.equal(sDone.failed, 0);
  assert.equal(sDone.totalEvents, 6);
  assert.equal(sDone.durationMs, 6 * 500);
  assert.equal(sDone.averageRate, 2, 'the average rate is submissions over wall-clock, not the configured rate');
  assert.equal(sDone.observed, 6);
  assert.equal(sDone.processed, 6);
  assert.equal(sDone.alerts, 0);
  assert.equal(sDone.peakScore, null, 'no prediction was observed, so there is no peak score');
  offDone();

  // the engine's own vocabulary, and nothing outside it
  assert.equal(completionSummary(snapOf(3, 9, { state: 'STOPPED', stopReason: 'USER' }) as never, done.snap())!.outcome, 'STOPPED');
  assert.equal(completionSummary(snapOf(3, 9, { state: 'STOPPED', stopReason: 'DURATION' }) as never, done.snap())!.outcome, 'DURATION');
  assert.equal(completionSummary(snapOf(3, 9, { state: 'FAILED' }) as never, done.snap())!.outcome, 'FAILED');
  // and no summary at all while the run is still going
  for (const state of ['IDLE', 'RUNNING', 'PAUSED', 'STOPPING']) {
    assert.equal(completionSummary(snapOf(2, 9, { state }) as never, done.snap()), null, state);
  }
});

await acheck('reset clears every piece of live state; a new run id starts a fresh console', async () => {
  const L = liveSetup({
    trail: (id) => trailOf(id, { prediction: { anomalyScore: 0.7, decision: 'ANOMALOUS' }, alerts: [{ id: `AL-${id}`, severity: 'HIGH', status: 'OPEN', incidentId: 'INC-9' }] }),
  });
  const detach = L.console.attach();
  for (let i = 1; i <= 4; i++) L.console.ingest(snapOf(i, 4));
  await L.clock.advance(60_000);
  const before = L.snap();
  assert.ok(before.rows.length === 4 && before.totals.alerts === 4 && before.totals.incidents === 1 && before.activity.length > 0);

  L.console.reset();
  const cleared = L.snap();
  assert.deepEqual(cleared.rows, []);
  assert.deepEqual(cleared.activity, []);
  assert.deepEqual(cleared.incidents, []);
  assert.equal(cleared.runId, null);
  assert.equal(cleared.plan, null);
  assert.equal(cleared.actualRate, null);
  assert.equal(cleared.pending, 0);
  assert.equal(cleared.polling, 0);
  assert.deepEqual(cleared.totals, {
    rowsSeen: 0, trimmed: 0, observed: 0, processed: 0, processingFailed: 0, unobserved: 0,
    alerts: 0, incidents: 0, peakScore: null, severity: {}, detectors: {},
  });

  // "Run again": a new run id, so the console starts clean rather than mixing two runs together
  for (let i = 1; i <= 3; i++) L.console.ingest(snapOf(i, 3, { runId: 'SIM-LIVE-RUN2' }));
  await L.clock.advance(60_000);
  const second = L.snap();
  assert.equal(second.runId, 'SIM-LIVE-RUN2');
  assert.equal(second.totals.rowsSeen, 3, 'the first run is not counted again');
  assert.ok(second.rows.every((r) => r.eventId.startsWith('SIM-LIVE-RUN2')));
  assert.ok(second.activity.some((a) => a.kind === 'RUN_STARTED'));

  // and so does a new run arriving without an explicit reset first
  for (let i = 1; i <= 2; i++) L.console.ingest(snapOf(i, 2, { runId: 'SIM-LIVE-RUN3' }));
  assert.equal(L.snap().runId, 'SIM-LIVE-RUN3');
  assert.equal(L.snap().totals.rowsSeen, 2);
  detach();
});

/* ---------------- filtering ---------------- */

await acheck('filtering works on the bounded client-side rows only', async () => {
  const L = liveSetup({
    trail: (id) => {
      const n = Number(id.slice(-3));
      if (n === 1) return trailOf(id, { alerts: [{ id: 'AL-1', severity: 'HIGH', status: 'OPEN', incidentId: 'INC-1' }] });
      if (n === 2) return trailOf(id, { alerts: [{ id: 'AL-2', severity: 'LOW', status: 'OPEN' }] });
      if (n === 3) return trailOf(id, { processingStatus: 'FAILED', lastProcessingError: 'ML timeout' });
      if (n === 6) return trailOf(id, { processingStatus: 'PENDING' });
      return trailOf(id);
    },
  });
  const detach = L.console.attach();
  for (let i = 1; i <= 8; i++) L.console.ingest(snapOf(i, 8, { failEvery: 8 })); // event 8 is rejected
  await L.clock.advance(TRAIL_POLL_INTERVAL_MS * 3);

  const rows = L.snap().rows;
  const n = (f: Parameters<typeof filterRows>[1], type?: string) => filterRows(rows, f, type).length;
  assert.equal(rows.length, 8);
  assert.equal(n('ALL'), 8);
  assert.equal(n('ACCEPTED'), 7, 'one POST was rejected');
  assert.equal(n('FAILED'), 2, 'one rejected POST and one processing failure');
  assert.equal(n('ALERTS'), 2);
  assert.equal(n('INCIDENTS'), 1);
  assert.equal(n('PENDING'), 1, 'event 6 is still PENDING and still being polled');
  // the event-type filter composes with the status filter and refetches nothing
  assert.equal(n('ALL', 'LOGIN'), 4);
  assert.equal(n('ALL', 'FILE_ACCESS'), 4);
  assert.equal(n('ALERTS', 'LOGIN'), 1);
  assert.equal(n('ALL', 'NOPE'), 0);
  const trailsBefore = L.trailCalls.length;
  for (const f of ['ALL', 'ACCEPTED', 'FAILED', 'ALERTS', 'INCIDENTS', 'PENDING'] as const) filterRows(rows, f);
  assert.equal(L.trailCalls.length, trailsBefore, 'filtering must never trigger a request');
  detach();
});

/* ---------------- plan progress ---------------- */

check('plan progress is counted against the engine own position, with every event attributed exactly once', () => {
  for (const patch of [
    { scenarioId: 'procconn', intensity: 'HIGH', noisePercent: 20 },
    { scenarioId: 'brute', targetMode: 'MULTI', entityIds: ['HOST-A', 'HOST-B'], noisePercent: 30 },
    { scenarioId: 'routine' },
  ]) {
    const p = plan1(patch);
    const info = planInfo(p);
    assert.equal(info.segmentOfEvent.length, p.eventCount, JSON.stringify(patch));
    // longest-prefix attribution: a noise event must never be claimed by the scenario segment
    assert.ok(info.segmentOfEvent.every((i) => i >= 0), `${JSON.stringify(patch)}: an event was attributed to no segment`);
    const tally = info.segments.map((_, i) => info.segmentOfEvent.filter((x) => x === i).length);
    assert.deepEqual(tally, info.segments.map((s) => s.count), JSON.stringify(patch));
    assert.equal(tally.reduce((a, b) => a + b, 0), p.eventCount);

    // progress at the start, in the middle and at the end
    assert.deepEqual(segmentProgress(info, 0).map((s) => s.submitted), info.segments.map(() => 0));
    assert.deepEqual(segmentProgress(info, p.eventCount).map((s) => s.submitted), info.segments.map((s) => s.count));
    const mid = segmentProgress(info, Math.floor(p.eventCount / 2));
    assert.equal(mid.reduce((n, s) => n + s.submitted, 0), Math.floor(p.eventCount / 2));
    assert.ok(mid.every((s) => s.submitted <= s.count));
    // the current segment is the one the next event belongs to
    const cur = currentSegment(info, 0);
    assert.equal(cur!.index, info.segmentOfEvent[0]);
  }
});

/* ---------------- nothing is sent, nothing else changed ---------------- */

await acheck('observing never submits an event, and the console wires only read endpoints', async () => {
  // The console is given no send of any kind: it cannot submit even if it tried.
  let posts = 0;
  const g = globalThis as unknown as Record<string, unknown>;
  const saved = { fetch: g.fetch, XMLHttpRequest: g.XMLHttpRequest };
  g.fetch = (...a: unknown[]) => {
    posts++;
    return Promise.reject(new Error(`the console tried to reach ${String(a[0])}`));
  };
  g.XMLHttpRequest = class {
    constructor() {
      posts++;
    }
  };
  try {
    const L = liveSetup();
    const detach = L.console.attach();
    L.console.setPlan(planInfo(plan1({ scenarioId: 'mixed', intensity: 'HIGH' })));
    for (let i = 1; i <= 30; i++) L.console.ingest(snapOf(i, 30, { failEvery: 7 }));
    await L.clock.advance(120_000);
    assert.ok(L.snap().rows.length > 0);
    assert.equal(posts, 0, 'the console reached the network directly');
  } finally {
    g.fetch = saved.fetch;
    g.XMLHttpRequest = saved.XMLHttpRequest;
  }

  // liveConsole.ts stays framework-free and transport-free; only the React binding names an endpoint,
  // and only the two READ calls Phase 4 documents.
  const store = readFileSync(new URL('../src/simulator/liveConsole.ts', import.meta.url), 'utf8');
  for (const forbidden of ['api/endpoints', 'eventsApi', 'axios', 'fetch(', 'XMLHttpRequest', 'sendBeacon', 'from \'react\'']) {
    assert.ok(!store.includes(forbidden), `liveConsole.ts references ${forbidden}`);
  }
  const binding = readFileSync(new URL('../src/simulator/useLiveConsole.ts', import.meta.url), 'utf8');
  assert.ok(binding.includes('eventsApi.trail('), 'the console reads the event trail');
  assert.ok(binding.includes('incidentsApi.get('), 'the console reads incident status');
  for (const write of ['.create(', '.updateStatus(', '.post(', 'api.patch', 'eventsApi.create']) {
    assert.ok(!binding.includes(write), `useLiveConsole.ts wires a write call: ${write}`);
  }
});

check('the simulator reaches nothing outside the frontend, and the console hard-codes no detection', () => {
  // Every module under src/simulator may only import a sibling or the shared domain types. That is
  // what keeps the whole phase frontend-only: there is no path by which it could touch the backend,
  // the ML service, Kafka, the database or Docker, whatever a comment happens to mention.
  const NEWLINE = String.fromCharCode(10);
  const importsOf = (source: string): string[] =>
    source.split(NEWLINE)
      .filter((line) => line.trimStart().startsWith('import '))
      .map((line) => line.split("'")[1])
      .filter((spec): spec is string => Boolean(spec));

  const files = ['liveConsole.ts', 'planner.ts', 'advancedBuilders.ts', 'builders.ts', 'engine.ts', 'validation.ts', 'types.ts', 'scenarioRegistry.ts', 'runHistory.ts', 'demoPresets.ts'];
  for (const file of files) {
    const source = readFileSync(new URL(`../src/simulator/${file}`, import.meta.url), 'utf8');
    for (const spec of importsOf(source)) {
      assert.ok(spec.startsWith('./') || spec === '../types/domain', `${file} imports ${spec}`);
    }
    assert.ok(!/require\s*\(/.test(source), `${file} uses require()`);
  }

  // The React binding is the only file that names an endpoint, and it reads two of them.
  const binding = readFileSync(new URL('../src/simulator/useLiveConsole.ts', import.meta.url), 'utf8');
  assert.deepEqual(importsOf(binding).sort(), ['../api/endpoints', './liveConsole', 'react']);

  // And the console derives a row's status from what was observed - it is never told one by the
  // scenario that produced the event, which is why no detector name appears in it at all.
  const store = readFileSync(new URL('../src/simulator/liveConsole.ts', import.meta.url), 'utf8');
  assert.ok(store.includes('private deriveStatus('), 'row status must be derived from observed data');
  for (const name of ['AUTH_BURST', 'NEW_PROCESS_EXTERNAL_CONNECTION', 'scenarioRegistry']) {
    assert.ok(!store.includes(name), `the console must not hard-code ${name}`);
  }
});
/* P5 */
/* ======================================================================================
 * PHASE 5 - run history and the investigation workflow.
 * A fake localStorage, a fake clock and a fake transport throughout: nothing touches real
 * browser storage, nothing reaches a backend, and no event is ever sent.
 * ==================================================================================== */

/** A localStorage stand-in that can be made to fail the way a real one does. */
function fakeStorage(opts: { seed?: string; failWrite?: boolean; failRead?: boolean } = {}) {
  const map = new Map<string, string>();
  if (opts.seed !== undefined) map.set(HISTORY_KEY, opts.seed);
  return {
    map,
    getItem: (k: string) => {
      if (opts.failRead) throw new Error('SecurityError: storage is blocked');
      return map.get(k) ?? null;
    },
    setItem: (k: string, v: string) => {
      if (opts.failWrite) throw new Error('QuotaExceededError');
      map.set(k, v);
    },
    removeItem: (k: string) => void map.delete(k),
  };
}

const HIST_PLAN = planInfo(plan1({ scenarioId: 'mixed', intensity: 'HIGH', eventRate: 5, duration: 60 }));

const histSummary = (patch: Record<string, unknown> = {}) => ({
  runId: 'SIM-MIXED-H1',
  label: 'Mixed attack',
  outcome: 'COMPLETED',
  reason: null,
  durationMs: 62_000,
  generated: 29,
  accepted: 28,
  failed: 1,
  totalEvents: 29,
  averageRate: 0.47,
  observed: 28,
  processed: 27,
  processingFailed: 1,
  unobserved: 0,
  alerts: 3,
  incidents: 1,
  peakScore: 0.997,
  severity: { HIGH: 2, MEDIUM: 1 },
  detectors: { AUTH_BURST: 1, ML: 2 },
  ...patch,
}) as never;

const histTotals = (patch: Record<string, unknown> = {}) => ({
  rowsSeen: 29, trimmed: 0, observed: 28, processed: 27, processingFailed: 1, unobserved: 0,
  alerts: 3, incidents: 1, peakScore: 0.997, severity: {}, detectors: {}, ...patch,
}) as never;

const entryOf = (patch: Record<string, unknown> = {}, totals: Record<string, unknown> = {}) =>
  buildHistoryEntry(histSummary(patch), HIST_PLAN, histTotals(totals), NOW)!;

/* ---------------- the record itself ---------------- */

check('a finished run becomes a compact record of its summary and its configuration', () => {
  const e = entryOf();
  assert.equal(e.runId, 'SIM-MIXED-H1');
  assert.equal(e.outcome, 'COMPLETED');
  assert.equal(e.createdAt, NOW);
  assert.equal(e.completedAt, NOW + 62_000);
  assert.equal(e.scenarioId, 'mixed');
  assert.equal(e.scenarioName, 'Mixed attack');
  assert.deepEqual([e.generated, e.accepted, e.failed, e.totalEvents], [29, 28, 1, 29]);
  assert.deepEqual([e.observed, e.processed, e.processingFailed, e.unobserved], [28, 27, 1, 0]);
  assert.deepEqual([e.alerts, e.incidents], [3, 1]);
  assert.equal(e.peakScore, 0.997);
  assert.equal(e.observation, 'COMPLETE');
  assert.equal(e.observationWindowMs, TRAIL_OBSERVATION_MS);
  assert.equal(e.droppedRows, 0);
  // the detector claim travels with the run, so a record never has to be re-derived from the library
  assert.match(e.detection, /AUTH_BURST/);
});

check('every terminal outcome is recorded, and a run still in flight is not', () => {
  for (const outcome of ['COMPLETED', 'STOPPED', 'DURATION', 'FAILED']) {
    const e = entryOf({ outcome, reason: outcome === 'FAILED' ? '3 submissions in a row failed' : null });
    assert.equal(e.outcome, outcome);
    assert.equal(e.reason, outcome === 'FAILED' ? '3 submissions in a row failed' : null);
  }
  // completionSummary is what gates this upstream: there is no summary before a terminal state,
  // so a preview, a pause or a navigation can never produce a record.
  const live = { totals: histTotals(), rows: [], activity: [], incidents: [], runId: null, plan: null, polling: 0, pending: 0, actualRate: null, pollerArmed: false } as never;
  for (const state of ['IDLE', 'RUNNING', 'PAUSED', 'STOPPING']) {
    assert.equal(completionSummary(snapOf(2, 9, { state }) as never, live), null, state);
  }
  // and without the plan metadata there is no configuration to be honest about, so no record
  assert.equal(buildHistoryEntry(histSummary(), null, histTotals(), NOW), null);
  assert.equal(buildHistoryEntry(histSummary({ runId: null }), HIST_PLAN, histTotals(), NOW), null);
});

check('the write rule is at most two per run: on finishing, and once observation settles', () => {
  // not finished, whatever else is true
  assert.equal(shouldPersist(null, 'R1', false, false), 'SKIP');
  assert.equal(shouldPersist(null, 'R1', false, true), 'SKIP');
  assert.equal(shouldPersist(null, null, true, true), 'SKIP');

  // a new run: write it the moment it finishes, even while trails are still being read
  assert.equal(shouldPersist(null, 'R1', true, false), 'SAVE');
  // ... then once more when observation has settled, and never again
  let mark: Parameters<typeof shouldPersist>[0] = { runId: 'R1', finalized: false };
  assert.equal(shouldPersist(mark, 'R1', true, false), 'SKIP', 'no write per trail answer');
  assert.equal(shouldPersist(mark, 'R1', true, true), 'FINALIZE');
  mark = { runId: 'R1', finalized: true };
  assert.equal(shouldPersist(mark, 'R1', true, true), 'SKIP');
  assert.equal(shouldPersist(mark, 'R1', true, false), 'SKIP');

  // a run that had already settled when it finished is written once, finalized
  assert.equal(shouldPersist(null, 'R2', true, true), 'FINALIZE');
  // a different run id is a different record
  assert.equal(shouldPersist({ runId: 'R1', finalized: true }, 'R2', true, false), 'SAVE');
});

check('resetting after a run does not write a second record; running again does', () => {
  const storage = fakeStorage();
  const store = new RunHistoryStore(storage);
  let mark: Parameters<typeof shouldPersist>[0] = null;
  let writes = 0;
  const tick = (runId: string | null, finished: boolean, settled: boolean) => {
    const decision = shouldPersist(mark, runId, finished, settled);
    if (decision === 'SKIP') return;
    store.add(entryOf({ runId }));
    writes++;
    mark = { runId: runId!, finalized: decision === 'FINALIZE' };
  };

  tick('SIM-A', true, false);           // the run finished
  tick('SIM-A', true, false);           // a trail answered: still the same record
  tick('SIM-A', true, true);            // observation settled: the final form
  tick('SIM-A', true, true);            // nothing further
  assert.equal(writes, 2, 'at most two writes per run');
  assert.equal(store.list().length, 1, 'one run, one entry');

  // Reset puts the engine back to IDLE, so `finished` is false and nothing is written.
  tick(null, false, true);
  tick('SIM-A', false, true);
  assert.equal(store.list().length, 1, 'reset must not duplicate the entry');
  assert.equal(writes, 2);

  // Run again is a new run id, so it is a new record - the first one is untouched.
  tick('SIM-B', true, true);
  assert.equal(store.list().length, 2);
  assert.deepEqual(store.list().map((e) => e.runId).sort(), ['SIM-A', 'SIM-B']);
  assert.equal(writes, 3, 'the new run cost exactly one more write');
});

/* ---------------- the configuration snapshot ---------------- */

check('a record keeps the configuration that produced it, whatever the console does afterwards', () => {
  const preview = plan1({ scenarioId: 'brute', eventRate: 5, intensity: 'HIGH', noisePercent: 30, targetMode: 'MULTI', entityIds: ['HOST-A', 'HOST-B'] });
  const info = planInfo(preview);
  const e = buildHistoryEntry(histSummary(), info, histTotals(), NOW)!;

  assert.equal(e.config.eventRate, 5);
  assert.equal(e.config.intensity, 'HIGH');
  assert.equal(e.config.noisePercent, 30);
  assert.equal(e.config.targetMode, 'MULTI');
  assert.deepEqual(e.config.entityIds, ['HOST-A', 'HOST-B']);
  assert.equal(e.configuredRate, 5);

  // Mutating the configuration the console is holding must not reach a plan that already ran:
  // the snapshot is a copy at every level that matters, not a reference.
  preview.config.eventRate = 1;
  preview.config.intensity = 'LOW';
  preview.config.entityIds.push('HOST-C');
  assert.equal(e.config.eventRate, 5, 'the historical rate changed with the current configuration');
  assert.equal(e.config.intensity, 'HIGH');
  assert.deepEqual(e.config.entityIds, ['HOST-A', 'HOST-B']);
  assert.equal(info.config.eventRate, 5, 'the plan metadata is a snapshot too');

  // and the same holds once it has been through storage
  const store = new RunHistoryStore(fakeStorage());
  store.add(e);
  assert.equal(store.get(e.runId)!.config.eventRate, 5);
  assert.equal(store.get(e.runId)!.config.intensity, 'HIGH');
});

check('"Run again" from history reuses the configuration but never the run id or the results', () => {
  const e = entryOf();
  // What the page does with an entry: load its configuration, nothing else.
  const loaded: Record<string, unknown> = { ...e.config, entityIds: [...e.config.entityIds] };
  assert.deepEqual(loaded, e.config);
  assert.ok(!('runId' in loaded), 'a configuration carries no run id');
  for (const field of ['alerts', 'incidents', 'accepted', 'peakScore', 'observation', 'outcome']) {
    assert.ok(!(field in loaded), `a configuration must not carry ${field}`);
  }
  // A fresh run id is minted per run, so starting from a loaded configuration cannot collide.
  const a = newRunId(e.config.scenarioId, NOW);
  const b = newRunId(e.config.scenarioId, NOW + 1);
  assert.notEqual(a, e.runId);
  assert.notEqual(a, b);
  assert.ok(a.startsWith('SIM-MIXED-'));
});

/* ---------------- observation honesty ---------------- */

check('observation quality is derived from terminal answers, not from how many trails were read', () => {
  assert.equal(observationQuality(0, 0, 0), 'NONE', 'nothing accepted, nothing to observe');
  assert.equal(observationQuality(10, 0, 0), 'NONE');
  assert.equal(observationQuality(10, 4, 0), 'PARTIAL');
  assert.equal(observationQuality(10, 9, 1), 'COMPLETE');
  assert.equal(observationQuality(10, 10, 0), 'COMPLETE');
  assert.equal(observationQuality(10, 12, 0), 'COMPLETE', 'more terminal answers than accepted is still complete');
  // an event whose trail only ever said PENDING was read, but its outcome is still unknown
  const partial = entryOf({ accepted: 10, processed: 6, processingFailed: 0, observed: 10, unobserved: 0 });
  assert.equal(partial.observed, 10, 'ten trails were read');
  assert.equal(observedTerminal(partial), 6, 'but only six reached a known outcome');
  assert.equal(partial.observation, 'PARTIAL');
});

check('zero alerts is never presented as a clean run when observation was incomplete', () => {
  const clean = entryOf({ alerts: 0, incidents: 0, accepted: 20, processed: 20, processingFailed: 0, unobserved: 0 });
  const cleanVerdict = detectionVerdict(clean);
  assert.equal(cleanVerdict.conclusive, true);
  assert.equal(cleanVerdict.caveat, null);
  assert.match(cleanVerdict.headline, /No alert was raised/);

  // the case this check exists for
  const partial = entryOf({ alerts: 0, incidents: 0, accepted: 45, processed: 42, processingFailed: 0, unobserved: 3 });
  const v = detectionVerdict(partial);
  assert.equal(v.conclusive, false);
  assert.equal(v.observedCount, 42);
  assert.equal(v.acceptedCount, 45);
  assert.equal(v.headline, '0 observed alerts', 'the count must be qualified, not stated bare');
  assert.match(v.caveat ?? '', /42 of 45/);
  assert.match(v.caveat ?? '', /incomplete, not a clean run/);
  // and the reassuring words must not appear anywhere in an inconclusive verdict
  const text = `${v.headline} ${v.caveat}`.toLowerCase();
  for (const word of ['safe', 'clean run was', 'no alerts', 'all clear', 'nothing detected', 'secure']) {
    assert.ok(!text.includes(word), `an inconclusive verdict said "${word}"`);
  }

  // nothing observed at all is the strongest version of the same point
  const none = entryOf({ alerts: 0, incidents: 0, accepted: 12, processed: 0, processingFailed: 0, unobserved: 12 });
  const n = detectionVerdict(none);
  assert.equal(n.observation, 'NONE');
  assert.equal(n.conclusive, false);
  assert.match(n.caveat ?? '', /says nothing about detection/);

  // an alert count is reported plainly whether or not coverage was complete
  const found = detectionVerdict(entryOf({ alerts: 3, incidents: 1 }));
  assert.match(found.headline, /3 observed alerts, 1 incident/);
});

/* ---------------- persistence ---------------- */

check('an entry survives serialization, and carries no event data of any kind', () => {
  const e = entryOf();
  const json = serializeHistory([e]);
  assert.deepEqual(parseHistory(json), [e], 'a round trip must be lossless');
  assert.deepEqual(JSON.parse(json).version, HISTORY_VERSION);

  // Nothing from an event, a payload or a session may ever reach local storage.
  for (const forbidden of ['payload', 'occurredAt', 'eventVersion', 'loginSuccess', 'deviceFingerprint', 'processCreateTime', 'remoteAddress', 'commandSequence', 'token', 'password', 'authorization', 'apiKey']) {
    assert.ok(!json.toLowerCase().includes(forbidden.toLowerCase()), `the stored record contains ${forbidden}`);
  }
  for (const field of ['events', 'rows', 'results', 'activity', 'payload']) {
    assert.ok(!(field in e), `an entry must not hold ${field}`);
  }
  // a record stays small, so fifty of them stay small
  assert.ok(json.length < 4000, `one entry serialised to ${json.length} bytes`);
  assert.ok(serializeHistory(Array.from({ length: MAX_HISTORY_ENTRIES }, (_, i) => entryOf({ runId: `R${i}` }))).length < 250_000);
});

check('unreadable, wrong-version and partly broken history all recover instead of throwing', () => {
  assert.deepEqual(parseHistory(null), []);
  assert.deepEqual(parseHistory(''), []);
  assert.deepEqual(parseHistory('not json at all'), [], 'malformed JSON recovers to an empty history');
  assert.deepEqual(parseHistory('{"version":1,'), []);
  assert.deepEqual(parseHistory('[]'), [], 'an array is not an envelope');
  assert.deepEqual(parseHistory('"a string"'), []);
  assert.deepEqual(parseHistory(JSON.stringify({ version: 1, entries: 'nope' })), []);
  // a payload from another schema version is ignored rather than guessed at
  assert.deepEqual(parseHistory(JSON.stringify({ version: 0, entries: [entryOf()] })), []);
  assert.deepEqual(parseHistory(JSON.stringify({ version: HISTORY_VERSION + 1, entries: [entryOf()] })), []);
  assert.deepEqual(parseHistory(JSON.stringify({ entries: [entryOf()] })), [], 'no version at all');

  // one broken record does not discard the good ones beside it
  const mixed = JSON.stringify({
    version: HISTORY_VERSION,
    entries: [entryOf({ runId: 'GOOD-1' }), null, 42, { runId: '' }, { runId: 'X', outcome: 'NONSENSE' }, { runId: 'Y', outcome: 'COMPLETED' }, entryOf({ runId: 'GOOD-2' })],
  });
  const revived = parseHistory(mixed);
  assert.deepEqual(revived.map((e) => e.runId).sort(), ['GOOD-1', 'GOOD-2'], 'a record without a configuration cannot be trusted');

  // a truncated-but-plausible record is repaired field by field rather than trusted wholesale
  const thin = parseHistory(JSON.stringify({ version: HISTORY_VERSION, entries: [{ runId: 'THIN', outcome: 'STOPPED', config: { scenarioId: 'brute' }, accepted: 8, processed: 3 }] }));
  assert.equal(thin.length, 1);
  assert.equal(thin[0].config.eventRate, 2, 'a missing field falls back to a documented default');
  assert.equal(thin[0].peakScore, null);
  assert.deepEqual(thin[0].severity, {});
  assert.equal(thin[0].observation, 'PARTIAL', 'and a missing quality is recomputed, not assumed');
});

check('retention keeps the newest 50 runs and drops only the oldest', () => {
  const store = new RunHistoryStore(fakeStorage());
  for (let i = 0; i < MAX_HISTORY_ENTRIES + 17; i++) {
    store.add(entryOf({ runId: `R${String(i).padStart(3, '0')}`, durationMs: i * 1000 }));
  }
  const list = store.list();
  assert.equal(MAX_HISTORY_ENTRIES, 50);
  assert.equal(list.length, MAX_HISTORY_ENTRIES);
  // newest first, by completion
  assert.deepEqual(list.map((e) => e.completedAt), [...list.map((e) => e.completedAt)].sort((a, b) => b - a));
  assert.equal(list[0].runId, 'R066');
  assert.equal(list[list.length - 1].runId, 'R017');
  // exactly the oldest 17 went, and nothing else
  const kept = new Set(list.map((e) => e.runId));
  for (let i = 0; i < 17; i++) assert.ok(!kept.has(`R${String(i).padStart(3, '0')}`), `R${i} should have been dropped`);
  for (let i = 17; i < MAX_HISTORY_ENTRIES + 17; i++) assert.ok(kept.has(`R${String(i).padStart(3, '0')}`), `R${i} should have been kept`);
});

check('the same run id updates its record instead of adding a second one', () => {
  const store = new RunHistoryStore(fakeStorage());
  store.add(entryOf({ runId: 'SIM-DUP', alerts: 0, processed: 10, accepted: 28 }));
  assert.equal(store.list().length, 1);
  assert.equal(store.get('SIM-DUP')!.observation, 'PARTIAL');

  // the finalizing write, once observation settled
  store.add(entryOf({ runId: 'SIM-DUP', alerts: 2, processed: 28, accepted: 28 }));
  assert.equal(store.list().length, 1, 'still one record for one run');
  assert.equal(store.get('SIM-DUP')!.alerts, 2, 'the record was updated in place');
  assert.equal(store.get('SIM-DUP')!.observation, 'COMPLETE');
});

check('history survives a page reload, and a blocked or failing storage never breaks the console', () => {
  // --- reload: a new store over the same storage sees the same runs
  const storage = fakeStorage();
  const first = new RunHistoryStore(storage);
  first.add(entryOf({ runId: 'SIM-KEEP-1' }));
  first.add(entryOf({ runId: 'SIM-KEEP-2', durationMs: 90_000 }));
  assert.equal(storage.map.has(HISTORY_KEY), true);

  const afterReload = new RunHistoryStore(storage);
  assert.deepEqual(afterReload.list().map((e) => e.runId), ['SIM-KEEP-2', 'SIM-KEEP-1']);
  assert.equal(afterReload.get('SIM-KEEP-1')!.config.eventRate, HIST_PLAN.config.eventRate, 'the configuration snapshot survives too');
  assert.equal(afterReload.getSnapshot().storageError, null);

  // --- a write that fails keeps working in memory and says so
  const failing = new RunHistoryStore(fakeStorage({ failWrite: true }));
  failing.add(entryOf({ runId: 'SIM-MEM' }));
  assert.equal(failing.list().length, 1, 'the entry is not lost when the write fails');
  assert.match(failing.getSnapshot().storageError ?? '', /QuotaExceededError/);
  assert.match(failing.getSnapshot().storageError ?? '', /this session only/);

  // --- a read that throws recovers to an empty history rather than propagating
  const blocked = new RunHistoryStore(fakeStorage({ failRead: true }));
  assert.deepEqual(blocked.list(), []);
  assert.match(blocked.getSnapshot().storageError ?? '', /could not be read/);
  blocked.add(entryOf({ runId: 'SIM-BLOCKED' }));
  assert.equal(blocked.list().length, 1);

  // --- no storage at all (private mode, a browser that denies it)
  const none = new RunHistoryStore(null);
  assert.match(none.getSnapshot().storageError ?? '', /does not allow local storage/);
  none.add(entryOf({ runId: 'SIM-NOSTORE' }));
  assert.equal(none.list().length, 1, 'history still works, just not across a reload');
  none.remove('SIM-NOSTORE');
  assert.equal(none.list().length, 0);

  // --- corrupt stored data recovers, and the next write repairs the key
  const corrupt = fakeStorage({ seed: '{{{ not json' });
  const recovered = new RunHistoryStore(corrupt);
  assert.deepEqual(recovered.list(), []);
  recovered.add(entryOf({ runId: 'SIM-FRESH' }));
  assert.deepEqual(new RunHistoryStore(corrupt).list().map((e) => e.runId), ['SIM-FRESH']);
});

check('deleting one entry and clearing all affect local history only', () => {
  const storage = fakeStorage();
  const store = new RunHistoryStore(storage);
  for (const id of ['A', 'B', 'C']) store.add(entryOf({ runId: id, durationMs: id.charCodeAt(0) * 1000 }));
  assert.equal(store.list().length, 3);

  store.remove('B');
  assert.deepEqual(store.list().map((e) => e.runId).sort(), ['A', 'C']);
  assert.equal(new RunHistoryStore(storage).list().length, 2, 'the deletion was persisted');
  store.remove('NOT-THERE');
  assert.equal(store.list().length, 2, 'removing an unknown run id is a no-op');

  store.clear();
  assert.deepEqual(store.list(), []);
  assert.equal(storage.map.has(HISTORY_KEY), false, 'clearing removes the key, it does not leave an empty one');
  assert.deepEqual(new RunHistoryStore(storage).list(), []);
  // and clearing an already-empty history is harmless
  store.clear();
  assert.deepEqual(store.list(), []);
});

check('history filtering is a pure client-side read', () => {
  const entries = [
    entryOf({ runId: 'C1', outcome: 'COMPLETED' }),
    entryOf({ runId: 'S1', outcome: 'STOPPED' }),
    entryOf({ runId: 'D1', outcome: 'DURATION' }),
    entryOf({ runId: 'F1', outcome: 'FAILED' }),
    entryOf({ runId: 'C2', outcome: 'COMPLETED' }),
  ];
  assert.equal(filterHistory(entries, 'ALL').length, 5);
  assert.equal(filterHistory(entries, 'COMPLETED').length, 2);
  assert.equal(filterHistory(entries, 'STOPPED').length, 1);
  assert.equal(filterHistory(entries, 'DURATION').length, 1);
  assert.equal(filterHistory(entries, 'FAILED').length, 1);
  assert.equal(filterHistory(entries, 'COMPLETED', 'mixed').length, 2);
  assert.equal(filterHistory(entries, 'ALL', 'brute').length, 0);
  // filtering returns the same objects, so it can never be an expensive clone
  assert.equal(filterHistory(entries, 'ALL')[0], entries[0]);
});

/* ---------------- nothing reaches the network, nothing disturbs the live run ---------------- */

await acheck('no history operation makes a request, and none of them disturb a run in progress', async () => {
  let attempts = 0;
  const g = globalThis as unknown as Record<string, unknown>;
  const saved = { fetch: g.fetch, XMLHttpRequest: g.XMLHttpRequest };
  g.fetch = (...a: unknown[]) => {
    attempts++;
    return Promise.reject(new Error(`run history tried to reach ${String(a[0])}`));
  };
  g.XMLHttpRequest = class {
    constructor() {
      attempts++;
    }
  };

  const clock = new FakeClock();
  const t = mockTransport(clock);
  const engine = new SimulationEngine({ send: t.send, now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  const L = liveSetup({ clock, trail: (id) => trailOf(id, { processingStatus: 'PENDING' }) });
  const detach = L.console.attach();
  engine.subscribe(() => L.console.ingest(engine.getSnapshot()));

  try {
    engine.start(plan(12), { eventRate: 2 });
    await clock.advance(1600); // mid-run: events at 0, 500, 1000, 1500
    const before = {
      state: engine.getSnapshot().state,
      generated: engine.getSnapshot().generated,
      next: engine.getSnapshot().nextEventIndex,
      sends: t.calls.length,
      rows: L.snap().rows.length,
      runId: L.snap().runId,
    };
    assert.equal(before.state, 'RUNNING');

    // Everything the history UI can do, done while the run is live.
    const storage = fakeStorage();
    const store = new RunHistoryStore(storage);
    store.add(entryOf({ runId: 'OLD-1' }));
    store.add(entryOf({ runId: 'OLD-2' }));
    store.list();
    store.get('OLD-1');
    filterHistory(store.list(), 'COMPLETED');
    detectionVerdict(store.get('OLD-1')!);
    // "Run again" from history: load the configuration, and nothing else
    const loadedConfig = { ...store.get('OLD-1')!.config, entityIds: [...store.get('OLD-1')!.config.entityIds] };
    assert.equal(loadedConfig.scenarioId, 'mixed');
    store.remove('OLD-2');
    store.clear();

    const after = engine.getSnapshot();
    assert.equal(after.state, before.state, 'history must not change the run state');
    assert.equal(after.generated, before.generated);
    assert.equal(after.nextEventIndex, before.next);
    assert.equal(t.calls.length, before.sends, 'history must not cause a submission');
    assert.equal(L.snap().rows.length, before.rows, 'history must not touch the live console');
    assert.equal(L.snap().runId, before.runId);
    assert.equal(attempts, 0, 'a history operation reached the network');

    // the run then finishes normally, untouched by any of it
    await clock.advance(600_000);
    assert.equal(engine.getSnapshot().state, 'COMPLETED');
    assert.equal(t.calls.length, 12);
    assert.equal(attempts, 0);
  } finally {
    detach();
    g.fetch = saved.fetch;
    g.XMLHttpRequest = saved.XMLHttpRequest;
  }
});

check('the history module is local-only by construction', () => {
  const NEWLINE2 = String.fromCharCode(10);
  // Deduped: a module legitimately has both a value import and an `import type` from one sibling.
  const importsOf = (source: string): string[] => [...new Set(
    source.split(NEWLINE2)
      .filter((line) => line.trimStart().startsWith('import '))
      .map((line) => line.split("'")[1])
      .filter((spec): spec is string => Boolean(spec)),
  )];

  const store = readFileSync(new URL('../src/simulator/runHistory.ts', import.meta.url), 'utf8');
  for (const spec of importsOf(store)) assert.ok(spec.startsWith('./'), `runHistory.ts imports ${spec}`);
  for (const forbidden of ['api/endpoints', 'axios', 'fetch(', 'XMLHttpRequest', 'sendBeacon', "from 'react'"]) {
    assert.ok(!store.includes(forbidden), `runHistory.ts references ${forbidden}`);
  }
  // storage is injected, so the module itself never reaches for a global
  assert.ok(!store.includes('window.localStorage') && !store.includes('globalThis.localStorage'), 'storage must be injected');
  assert.ok(store.includes('export type StorageLike'), 'storage is injected through StorageLike');

  // the React binding is the only place that names the browser API, and it guards even reaching it
  const binding = readFileSync(new URL('../src/simulator/useRunHistory.ts', import.meta.url), 'utf8');
  assert.deepEqual(importsOf(binding).sort(), ['./runHistory', 'react']);
  assert.ok(binding.includes('globalThis.localStorage'), 'the binding supplies real storage');
  assert.ok(binding.includes('catch'), 'reaching for localStorage is itself guarded');

  // the key follows the project's existing sentinelflow.<area> convention, and is versioned in the payload
  assert.equal(HISTORY_KEY, 'sentinelflow.simulator.history');
  assert.equal(HISTORY_VERSION, 1);
});
/* P6 */
/* ======================================================================================
 * PHASE 6 - demo & evaluation mode.
 * Presets are configuration shortcuts, nothing more: every one is resolved against the real
 * registry, validated by the real planner and (where a run is involved) driven through the real
 * engine on a fake clock and a fake transport. No event is sent and no request is made.
 * ==================================================================================== */

/** A demo preset applied to a usable configuration, exactly as the page applies it. */
const demoConfig = (d: DemoPreset) => applyPreset(cfg(), d);
const demoPlan = (d: DemoPreset, runId = `SIM-DEMO-${d.id.toUpperCase()}`) =>
  buildPreview(demoConfig(d), { runId, now: NOW, available: AVAIL });

/** An observed run with nothing in it, to be patched per case. Recorded values only. */
const observed = (patch: Record<string, unknown> = {}) => ({
  accepted: 10,
  observedTerminal: 10,
  observation: 'COMPLETE',
  alerts: 0,
  incidents: 0,
  peakScore: null,
  severity: {},
  detectors: {},
  ...patch,
}) as never;

const byId = (id: string) => {
  const d = demoById(id);
  assert.ok(d, `preset ${id} is missing`);
  return d!;
};

/* ---------------- presets are real configurations ---------------- */

check('every demo preset resolves to an existing scenario and covers all five detection types', () => {
  assert.ok(DEMO_PRESETS.length >= 5, 'at least the five recommended demos');
  assert.equal(new Set(DEMO_PRESETS.map((d) => d.id)).size, DEMO_PRESETS.length, 'duplicate preset id');
  assert.equal(new Set(DEMO_PRESETS.map((d) => d.name)).size, DEMO_PRESETS.length, 'duplicate preset name');

  for (const d of DEMO_PRESETS) {
    const s = presetScenario(d);
    assert.ok(s, `${d.id} names scenario "${d.scenarioId}", which is not in the registry`);
    assert.equal(s!.id, d.scenarioId);
    assert.equal(d.config.scenarioId, d.scenarioId, `${d.id}: the preset configuration must select its own scenario`);
    assert.equal(d.detectionType, d.expectation.detectionType, `${d.id}: the card and the expectation must agree`);
    assert.ok(presetCategory(d), `${d.id} has no category`);
  }

  // the recommended five, plus a control so every legend entry has a working demo behind it
  const types = DEMO_PRESETS.map((d) => d.detectionType);
  for (const required of ['RULE', 'ML', 'RULE_AND_ML', 'CONTROL', 'COVERAGE_GAP']) {
    assert.ok(types.includes(required as never), `no preset demonstrates ${required}`);
  }
  assert.deepEqual(DETECTION_LEGEND.map((l) => l.type), ['RULE', 'ML', 'RULE_AND_ML', 'CONTROL', 'COVERAGE_GAP']);
  assert.equal(DETECTION_LABEL.RULE_AND_ML, 'RULE + ML');
  assert.equal(DETECTION_LABEL.COVERAGE_GAP, 'COVERAGE GAP');
});

check('every demo preset produces a valid, startable plan through the normal planner', () => {
  for (const d of DEMO_PRESETS) {
    const config = demoConfig(d);
    assert.deepEqual(validateConfig(config, AVAIL), [], `${d.id}: invalid configuration`);
    const p = demoPlan(d);
    assert.deepEqual(p.issues, [], `${d.id}: ${JSON.stringify(p.issues)}`);
    assert.equal(canStart(p), true, d.id);
    assert.deepEqual(validateEvents(p.events, NOW), [], `${d.id}: generated events break the backend contract`);
    assert.equal(new Set(p.events.map((e) => e.eventId)).size, p.eventCount, `${d.id}: duplicate eventId`);
    // a preset may not raise the rate past what the console offers, let alone the engine's cap
    assert.ok(RATE_OPTIONS.includes(config.eventRate), `${d.id}: rate ${config.eventRate}`);
    assert.ok(config.eventRate <= MAX_EVENT_RATE, d.id);
    // and it leaves target selection to the user
    assert.equal(config.entityId, cfg().entityId, `${d.id}: a preset must not choose the target entity`);
  }
});

/* ---------------- expectations are declarative, and true ---------------- */

check('declared expectations match what the plan really generates - no over-claiming', () => {
  for (const d of DEMO_PRESETS) {
    const p = demoPlan(d);
    const e = d.expectation;
    assert.equal(e.expectedEvents, p.eventCount, `${d.id}: declared ${e.expectedEvents} events, the plan builds ${p.eventCount}`);
    assert.deepEqual(
      e.expectedEventTypes.slice().sort(),
      p.eventTypes.map((x) => x.type).sort(),
      `${d.id}: declared event types do not match the plan`,
    );
    // a demo may only claim a rule the scenario library itself claims
    const claimed = presetScenario(d)!.detector.rules;
    for (const rule of e.expectedRules) {
      assert.ok(claimed.includes(rule), `${d.id} expects ${rule}, which ${d.scenarioId} does not claim`);
    }
    // guaranteed is reserved for deterministic rules satisfied by construction
    assert.equal(e.guaranteed, e.expectedRules.length > 0, `${d.id}: guaranteed must mean "a rule is satisfied by construction"`);
    assert.ok(e.statement.length > 20, `${d.id}: no expectation statement`);
    assert.ok(presetLimitations(d).length > 0, `${d.id}: no limitations stated`);
  }
});

check('expectation metadata is correct per detection type, and holds no observed result', () => {
  // RULE: a deterministic rule, guaranteed by construction, no ML bar
  const rule = byId('auth').expectation;
  assert.equal(rule.detectionType, 'RULE');
  assert.deepEqual(rule.expectedRules, ['AUTH_BURST']);
  assert.equal(rule.guaranteed, true);
  assert.equal(rule.mlThreshold, null);
  const procconn = byId('procconn').expectation;
  assert.deepEqual(procconn.expectedRules, ['NEW_PROCESS_EXTERNAL_CONNECTION']);
  assert.deepEqual(procconn.expectedEventTypes.slice().sort(), ['NETWORK_CONNECTION', 'PROCESS_START']);

  // ML: no rule, never guaranteed, and the policy threshold is stated
  const ml = byId('exfil').expectation;
  assert.equal(ml.detectionType, 'ML');
  assert.deepEqual(ml.expectedRules, []);
  assert.equal(ml.guaranteed, false, 'ML is never guaranteed');
  assert.equal(ml.mlThreshold, ALERT_THRESHOLD);

  // RULE + ML: both rules, guaranteed for the rules, with the ML bar also stated
  const both = byId('mixed').expectation;
  assert.equal(both.detectionType, 'RULE_AND_ML');
  assert.deepEqual(both.expectedRules.slice().sort(), ['AUTH_BURST', 'NEW_PROCESS_EXTERNAL_CONNECTION']);
  assert.equal(both.guaranteed, true);
  assert.equal(both.mlThreshold, ALERT_THRESHOLD);

  // CONTROL: nothing expected, and explicitly not a promise of silence
  const control = byId('control').expectation;
  assert.equal(control.detectionType, 'CONTROL');
  assert.deepEqual(control.expectedRules, []);
  assert.equal(control.guaranteed, false);
  assert.ok(presetLimitations(byId('control')).some((l) => /not a promise of silence/i.test(l)));

  // COVERAGE GAP: no detector at all, and it says so in those words
  const gap = byId('gap').expectation;
  assert.equal(gap.detectionType, 'COVERAGE_GAP');
  assert.deepEqual(gap.expectedRules, []);
  assert.equal(gap.guaranteed, false);
  assert.equal(gap.mlThreshold, null);
  assert.match(gap.statement, /No deterministic backend detector/i);
  assert.ok(presetLimitations(byId('gap')).some((l) => /deliberately/i.test(l)));

  // No expectation anywhere may carry a result field - that is what keeps the two apart.
  for (const d of DEMO_PRESETS) {
    for (const field of ['alerts', 'incidents', 'observed', 'peakScore', 'severity', 'detectors', 'accepted', 'verdict']) {
      assert.ok(!(field in d.expectation), `${d.id}: the expectation holds an observed field "${field}"`);
    }
  }
});

/* ---------------- an anomaly score is a score, never a probability ---------------- */

check('an anomaly score is printed as a score, never as a probability or a percentage', () => {
  assert.equal(formatScore(0.997), '0.997');
  assert.equal(formatScore(0.81), '0.810');
  assert.equal(formatScore(1), '1.000');
  assert.equal(formatScore(null), 'not observed');
  assert.ok(!formatScore(0.997).includes('%'));

  // the policy bands are mirrored from the backend, not invented, and nothing here changes them
  assert.equal(ALERT_THRESHOLD, 0.99);
  assert.deepEqual(SEVERITY_BANDS.map((b) => b.from), [0.999, 0.995, 0.99]);
  assert.equal(scoreBand(0.9992), 'CRITICAL');
  assert.equal(scoreBand(0.996), 'HIGH');
  assert.equal(scoreBand(0.991), 'MEDIUM');
  assert.equal(scoreBand(0.81), null, 'below the alert threshold there is no band');
  assert.equal(scoreBand(null), null);

  // No demo text may describe a score as a probability or a percentage chance.
  const demoText = [
    ...DEMO_PRESETS.flatMap((d) => [d.purpose, d.description, d.expectation.statement, ...d.expectation.limitations, ...Object.values(d.explain)]),
    ...DETECTION_LEGEND.map((l) => l.meaning),
    ...ARCHITECTURE_FLOW.flatMap((a) => [a.label, a.detail]),
    ...DEMO_PRESETS.flatMap((d) => expectedLines(d.expectation)),
    ...observedLines(observed({ peakScore: 0.997, alerts: 1, detectors: { ML: 1 } })),
  ].join(' ').toLowerCase();
  for (const banned of ['% probability', 'probability of attack', 'confidence that', '99.7%', 'percent chance', 'likelihood of attack']) {
    assert.ok(!demoText.includes(banned), `demo text says "${banned}"`);
  }
  // and at least one place states plainly what the score actually is
  assert.ok(demoText.includes('percentile rank'), 'the score is never explained as a percentile rank');
});

/* ---------------- expected versus observed ---------------- */

check('a deterministic rule that fires is reported as the expected result', () => {
  const a = assessDemo(byId('auth').expectation, observed({ accepted: 15, observedTerminal: 15, alerts: 1, incidents: 1, detectors: { AUTH_BURST: 1 }, severity: { HIGH: 1 } }));
  assert.equal(a.verdict, 'EXPECTED_OBSERVED');
  assert.equal(a.failure, false);
  assert.match(a.detail, /AUTH_BURST/);
  assert.match(a.detail, /reproducible/);
  // both sides are present and derived from their own source only
  assert.ok(a.expectedLines.some((l) => l.includes('AUTH_BURST')));
  assert.ok(a.observedLines.some((l) => l.includes('AUTH_BURST x1')));
  assert.ok(a.observedLines.some((l) => /Alerts: 1/.test(l)));

  // a mixed demo needs BOTH rules before it may claim the expected result
  const mixed = byId('mixed').expectation;
  const half = assessDemo(mixed, observed({ accepted: 22, observedTerminal: 22, alerts: 1, detectors: { AUTH_BURST: 1 } }));
  assert.equal(half.verdict, 'EXPECTED_NOT_OBSERVED');
  assert.match(half.label, /NEW_PROCESS_EXTERNAL_CONNECTION/);
  const full = assessDemo(mixed, observed({ accepted: 22, observedTerminal: 22, alerts: 2, incidents: 2, detectors: { AUTH_BURST: 1, NEW_PROCESS_EXTERNAL_CONNECTION: 1 } }));
  assert.equal(full.verdict, 'EXPECTED_OBSERVED');
  assert.equal(full.failure, false);
});

check('an ML scenario that does not cross the threshold is never called a failure', () => {
  const a = assessDemo(byId('exfil').expectation, observed({ accepted: 6, observedTerminal: 6, peakScore: 0.81 }));
  assert.equal(a.verdict, 'EXPECTED_NOT_OBSERVED');
  assert.equal(a.failure, false, 'an ML non-alert is a valid outcome, not a defect');
  assert.match(a.label, /did not cross the alert threshold/i);
  assert.match(a.detail, /0\.810/);
  assert.match(a.detail, /0\.99/);
  assert.match(a.detail, /not a platform defect/i);
  // the words a reviewer must never see here
  const text = `${a.label} ${a.detail}`.toLowerCase();
  for (const banned of ['unexpected failure', 'failed to detect', 'missed the attack', 'broken', 'bug']) {
    assert.ok(!text.includes(banned), `an ML non-alert was described as "${banned}"`);
  }

  // and when it does cross, it is the expected result
  const hit = assessDemo(byId('exfil').expectation, observed({ accepted: 6, observedTerminal: 6, alerts: 1, peakScore: 0.997, detectors: { ML: 1 } }));
  assert.equal(hit.verdict, 'EXPECTED_OBSERVED');
  assert.equal(hit.failure, false);
  assert.match(hit.detail, /percentile rank, not a probability/);
});

check('a coverage gap with no alert is the expected result, not a platform failure', () => {
  const a = assessDemo(byId('gap').expectation, observed({ accepted: 14, observedTerminal: 14 }));
  assert.equal(a.verdict, 'EXPECTED_NO_DETECTION');
  assert.equal(a.failure, false);
  assert.match(a.label, /Coverage gap/i);
  assert.match(a.detail, /not a platform failure/i);
  assert.match(a.detail, /ingested and processed normally/i, 'ingestion worked; only detection is absent');

  // an ML score crossing the bar on gap events is explained for what it is, still not a failure
  const noisy = assessDemo(byId('gap').expectation, observed({ accepted: 14, observedTerminal: 14, alerts: 1, peakScore: 0.9992, detectors: { ML: 1 } }));
  assert.equal(noisy.verdict, 'EXPECTED_NOT_OBSERVED');
  assert.equal(noisy.failure, false);
  assert.match(noisy.detail, /not detection of the simulated behaviour/i);

  // the control behaves the same way in both directions
  const quiet = assessDemo(byId('control').expectation, observed({ accepted: 3, observedTerminal: 3 }));
  assert.equal(quiet.verdict, 'EXPECTED_NO_DETECTION');
  assert.equal(quiet.failure, false);
  const drifted = assessDemo(byId('control').expectation, observed({ accepted: 3, observedTerminal: 3, alerts: 1, peakScore: 0.996, detectors: { ML: 1 } }));
  assert.equal(drifted.verdict, 'EXPECTED_NOT_OBSERVED');
  assert.equal(drifted.failure, false);
  assert.match(drifted.detail, /profile has drifted/i);
});

check('an incomplete observation is inconclusive, whatever was expected', () => {
  for (const id of ['auth', 'procconn', 'exfil', 'mixed', 'gap', 'control']) {
    const a = assessDemo(byId(id).expectation, observed({ accepted: 20, observedTerminal: 7, observation: 'PARTIAL' }));
    assert.equal(a.verdict, 'INCONCLUSIVE', id);
    assert.equal(a.failure, false, id);
    assert.match(a.label, /observation window was incomplete/i, id);
    assert.match(a.detail, /7 of 20 accepted events/, id);
  }
  // nothing observed at all says so plainly
  const none = assessDemo(byId('auth').expectation, observed({ accepted: 0, observedTerminal: 0, observation: 'NONE' }));
  assert.equal(none.verdict, 'INCONCLUSIVE');
  assert.match(none.detail, /nothing to observe/i);

  // BUT a rule that did fire is self-evidencing: a positive observation is not weakened by
  // incomplete coverage elsewhere in the run.
  const positive = assessDemo(byId('auth').expectation, observed({ accepted: 15, observedTerminal: 6, observation: 'PARTIAL', alerts: 1, detectors: { AUTH_BURST: 1 } }));
  assert.equal(positive.verdict, 'EXPECTED_OBSERVED');
  assert.equal(positive.failure, false);
});

check('the only outcome marked as a failure is a deterministic rule that should have fired', () => {
  const a = assessDemo(byId('auth').expectation, observed({ accepted: 15, observedTerminal: 15 }));
  assert.equal(a.verdict, 'EXPECTED_NOT_OBSERVED');
  assert.equal(a.failure, true, 'a guaranteed rule that did not fire is worth flagging');
  // and the documented cause is offered rather than left as a mystery
  assert.match(a.detail, /suppression/i);
  assert.match(a.detail, /still open, acknowledged or investigating/i);

  // every other shape of outcome is not a failure
  const notFailures = [
    assessDemo(byId('exfil').expectation, observed({ peakScore: 0.5 })),
    assessDemo(byId('gap').expectation, observed()),
    assessDemo(byId('control').expectation, observed()),
    assessDemo(byId('auth').expectation, observed({ observation: 'PARTIAL', observedTerminal: 2 })),
    assessDemo(byId('auth').expectation, observed({ alerts: 1, detectors: { AUTH_BURST: 1 } })),
  ];
  for (const x of notFailures) assert.equal(x.failure, false, x.label);
});

/* ---------------- a demo run is an ordinary run ---------------- */

await acheck('a demo run goes through the normal planner and engine, with no extra transport', async () => {
  for (const d of DEMO_PRESETS) {
    const p = demoPlan(d);
    const info = planInfo(p, { demoId: d.id, demoName: d.name, detectionType: d.detectionType });
    assert.equal(info.demo!.demoId, d.id);
    assert.equal(info.config.scenarioId, d.scenarioId, 'the plan carries the preset configuration verbatim');

    const { engine, clock, t, snap } = setup();
    engine.start(toRunPlan(p), { eventRate: p.config.eventRate, maxDurationMs: null });
    await clock.advance(600_000);

    assert.equal(snap().state, 'COMPLETED', d.id);
    // exactly one submission per planned event, in plan order, one at a time
    assert.deepEqual(t.calls.map((c) => c.eventId), p.events.map((e) => e.eventId), d.id);
    assert.equal(t.calls.length, p.eventCount, `${d.id}: a demo must not duplicate transport`);
    assert.equal(t.maxInFlight, 1, `${d.id}: a demo must not break one-POST-at-a-time`);
    // and the pacing is the preset's rate, never faster than the engine's cap
    const gaps = t.calls.slice(1).map((c, i) => c.at - t.calls[i].at);
    assert.ok(gaps.every((g) => g === 1000 / p.config.eventRate), `${d.id}: ${gaps.join(',')}`);
    assert.ok(gaps.every((g) => g >= 1000 / MAX_EVENT_RATE), d.id);
  }
});

check('demo mode only ever adds the confirmation step, it never removes one', () => {
  // The page computes: needsConfirmation(preview) || (demoMode && a preset is selected).
  const gate = (p: ReturnType<typeof buildPreview>, demoMode: boolean, hasPreset: boolean) =>
    needsConfirmation(p) || (demoMode && hasPreset);

  for (const d of DEMO_PRESETS) {
    const p = demoPlan(d);
    assert.equal(gate(p, true, true), true, `${d.id}: a demo run must be confirmed`);
    // and the underlying rule is untouched: whatever it said without demo mode, it still says
    assert.equal(gate(p, false, false), needsConfirmation(p), d.id);
    assert.ok(gate(p, true, true) || !needsConfirmation(p), 'demo mode must never turn a confirmation off');
  }
  // a small run outside demo mode is still allowed to skip confirmation - the rule did not change
  assert.equal(needsConfirmation(plan1({ scenarioId: 'routine' })), false);
  assert.equal(gate(plan1({ scenarioId: 'routine' }), false, false), false);
});

check('opening demo mode performs no transport and no request of any kind', () => {
  let attempts = 0;
  const g = globalThis as unknown as Record<string, unknown>;
  const savedGlobals = { fetch: g.fetch, XMLHttpRequest: g.XMLHttpRequest };
  g.fetch = (...a: unknown[]) => {
    attempts++;
    return Promise.reject(new Error(`demo mode tried to reach ${String(a[0])}`));
  };
  g.XMLHttpRequest = class {
    constructor() {
      attempts++;
    }
  };
  try {
    // Everything opening demo mode and clicking through every preset does.
    let built = 0;
    for (const d of DEMO_PRESETS) {
      const config = applyPreset(cfg(), d);
      validateConfig(config, AVAIL);
      const p = buildPreview(config, { runId: `SIM-DEMO-${d.id}`, now: NOW, available: AVAIL });
      expectedLines(d.expectation);
      observedLines(observed());
      assessDemo(d.expectation, observed());
      presetLimitations(d);
      presetScenarioEventCount(d);
      planInfo(p, { demoId: d.id, demoName: d.name, detectionType: d.detectionType });
      built++;
    }
    assert.equal(built, DEMO_PRESETS.length);
    // the checklist and the legend are plain data: reading them cannot do anything
    assert.ok(DEMO_CHECKLIST.length >= 8);
    assert.equal(new Set(DEMO_CHECKLIST.map((c) => c.id)).size, DEMO_CHECKLIST.length);
    for (const item of DEMO_CHECKLIST) {
      assert.equal(typeof item.label, 'string');
      assert.ok(!(('action' in item) || ('run' in item) || ('onSelect' in item)), 'a checklist item must not carry behaviour');
    }
    assert.equal(attempts, 0, `demo mode made ${attempts} request attempt(s)`);
  } finally {
    g.fetch = savedGlobals.fetch;
    g.XMLHttpRequest = savedGlobals.XMLHttpRequest;
  }
});

/* ---------------- architecture explanation ---------------- */

check('the architecture view lists only components that exist, and marks the conditional ones', () => {
  const ids = ARCHITECTURE_FLOW.map((a) => a.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate architecture step');
  // the real path, in order
  assert.deepEqual(ids, ['simulator', 'rest', 'api', 'db', 'kafka', 'processing', 'rules', 'ml', 'policy', 'alert', 'incident', 'dashboard']);

  // an alert is not guaranteed, so those steps must be marked conditional
  const conditional = ARCHITECTURE_FLOW.filter((a) => a.conditional).map((a) => a.id);
  assert.deepEqual(conditional, ['alert', 'incident', 'dashboard'], 'a run that raises no alert must not look broken');

  // the Simulator must never be shown as talking to the ML service directly
  const simulator = ARCHITECTURE_FLOW.find((a) => a.id === 'simulator')!;
  assert.ok(!/ml/i.test(simulator.detail), 'the Simulator does not call the ML service');
  const ml = ARCHITECTURE_FLOW.find((a) => a.id === 'ml')!;
  assert.match(ml.detail, /Spring Boot calls the ML service/i);
  assert.match(ml.detail, /never contacts it directly/i);

  // only the transport the Simulator actually uses is named
  assert.equal(ARCHITECTURE_FLOW.find((a) => a.id === 'rest')!.label, 'POST /api/v1/events');
  const text = ARCHITECTURE_FLOW.map((a) => `${a.label} ${a.detail}`).join(' ').toLowerCase();
  for (const absent of ['websocket', 'graphql', 'grpc', 'redis', 'elasticsearch', 'siem connector', 'soar']) {
    assert.ok(!text.includes(absent), `the architecture view claims a component that does not exist: ${absent}`);
  }
  // and it names the real detectors and the real policy value
  assert.match(ARCHITECTURE_FLOW.find((a) => a.id === 'rules')!.detail, /AUTH_BURST and NEW_PROCESS_EXTERNAL_CONNECTION/);
  assert.ok(ARCHITECTURE_FLOW.find((a) => a.id === 'policy')!.detail.includes(String(ALERT_THRESHOLD)));
});

/* ---------------- history integration ---------------- */

check('a demo run records three fields of metadata and no expectation or assessment', () => {
  const d = byId('auth');
  const p = demoPlan(d);
  const info = planInfo(p, { demoId: d.id, demoName: d.name, detectionType: d.detectionType });
  const e = buildHistoryEntry(histSummary(), info, histTotals(), NOW)!;

  assert.deepEqual(e.demo, { demoId: 'auth', demoName: 'Authentication attack', detectionType: 'RULE' });
  assert.equal(Object.keys(e.demo!).length, 3, 'exactly three fields of demo metadata');
  for (const field of ['expectation', 'assessment', 'verdict', 'expectedRules', 'explain', 'events', 'activity']) {
    assert.ok(!(field in e), `a record must not store ${field}`);
    assert.ok(!(field in (e.demo as Record<string, unknown>)), `demo metadata must not store ${field}`);
  }

  // it survives storage, and nothing from an event comes with it
  const json = serializeHistory([e]);
  assert.deepEqual(parseHistory(json), [e]);
  for (const forbidden of ['payload', 'occurredAt', 'loginSuccess', 'processCreateTime', 'deviceFingerprint']) {
    assert.ok(!json.toLowerCase().includes(forbidden.toLowerCase()), `the stored demo record contains ${forbidden}`);
  }

  // a run that was not a demo simply has none, and records written before Phase 6 revive the same way
  const plain = buildHistoryEntry(histSummary({ runId: 'SIM-PLAIN' }), planInfo(p), histTotals(), NOW)!;
  assert.equal(plain.demo, null);
  const legacy = parseHistory(JSON.stringify({ version: HISTORY_VERSION, entries: [{ ...e, demo: undefined }] }));
  assert.equal(legacy.length, 1, 'an entry written before demo mode is still readable');
  assert.equal(legacy[0].demo, null);
  // and a malformed demo block is dropped rather than half-trusted
  for (const bad of [{ demoId: 'auth' }, { demoId: 'auth', detectionType: 'NONSENSE' }, { detectionType: 'RULE' }, 'auth', 42, null]) {
    const revived = parseHistory(JSON.stringify({ version: HISTORY_VERSION, entries: [{ ...e, demo: bad }] }));
    assert.equal(revived[0].demo, null, JSON.stringify(bad));
  }
});

check('a historical demo is assessed from its stored results against the preset it names', () => {
  const d = byId('gap');
  const info = planInfo(demoPlan(d), { demoId: d.id, demoName: d.name, detectionType: d.detectionType });
  const e = buildHistoryEntry(
    histSummary({ runId: 'SIM-GAP-1', accepted: 14, processed: 14, processingFailed: 0, unobserved: 0, alerts: 0, incidents: 0, peakScore: 0.42, severity: {}, detectors: {} }),
    info,
    histTotals(),
    NOW,
  )!;

  const o = observedFromEntry(e);
  assert.equal(o.accepted, 14);
  assert.equal(o.observedTerminal, 14);
  assert.equal(o.observation, 'COMPLETE');
  assert.equal(o.alerts, 0);
  assert.equal(o.peakScore, 0.42);

  const a = assessDemo(demoById(e.demo!.demoId)!.expectation, o);
  assert.equal(a.verdict, 'EXPECTED_NO_DETECTION');
  assert.equal(a.failure, false);

  // the same record under a partial observation is inconclusive instead - the stored coverage decides
  const partial = { ...e, processed: 5, processingFailed: 0, observation: 'PARTIAL' as const };
  assert.equal(assessDemo(demoById('gap')!.expectation, observedFromEntry(partial)).verdict, 'INCONCLUSIVE');
});

/* ---------------- module isolation ---------------- */

check('demo mode is declarative data: it owns no transport, no engine and no timer', () => {
  const NEWLINE6 = String.fromCharCode(10);
  const importsOf = (source: string): string[] => [...new Set(
    source.split(NEWLINE6)
      .filter((line) => line.trimStart().startsWith('import '))
      .map((line) => line.split("'")[1])
      .filter((spec): spec is string => Boolean(spec)),
  )];

  const mod = readFileSync(new URL('../src/simulator/demoPresets.ts', import.meta.url), 'utf8');
  for (const spec of importsOf(mod)) assert.ok(spec.startsWith('./'), `demoPresets.ts imports ${spec}`);
  for (const forbidden of ['api/endpoints', 'axios', 'fetch(', 'XMLHttpRequest', 'sendBeacon', "from 'react'", 'setTimeout', 'setInterval', 'SimulationEngine', 'localStorage']) {
    assert.ok(!mod.includes(forbidden), `demoPresets.ts references ${forbidden}`);
  }
  // it may not reach into the live console or the history store either: a preset is only configuration
  assert.ok(!mod.includes('liveConsole') && !mod.includes('runHistory'), 'a preset must not reach into run state');
  // and it must not hard-code a detection outcome
  assert.ok(!mod.includes('toFixed(1)') && !mod.includes('%'), 'a score must never be formatted as a percentage');
});

console.log(`\n${checks + asyncChecks} checks passed`);
