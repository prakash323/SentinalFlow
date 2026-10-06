/*
 * Live execution console: the observation layer on top of the Phase 2 run engine.
 *
 * The engine stays the ONLY authority for transport, pacing, pause/resume/stop, the duration cap and
 * the run lifecycle. This store never sends an event and never schedules one. It does two things:
 *
 *  1. OBSERVES. ingest(RunSnapshot) folds the engine's own results into a BOUNDED set of console
 *     rows, a bounded activity feed and CUMULATIVE counters that survive trimming.
 *  2. ASKS THE BACKEND WHAT HAPPENED NEXT. One shared poller - one timer for the whole page, never
 *     one per event - reads GET /api/v1/events/{id}/trail for a bounded batch of events that still
 *     have something to learn, and GET /api/v1/incidents/{id} for the few incident ids those trails
 *     mention (incident status is not on the trail).
 *
 * Bounded by construction
 * -----------------------
 *   rows        at most LIVE_ROW_HARD_LIMIT; the oldest are dropped and counted in totals.trimmed
 *   activity    at most ACTIVITY_LIMIT
 *   rate window at most RATE_WINDOW_SAMPLES submission timestamps
 *   polling     at most TRAIL_POLL_BATCH requests in flight, at most one per event, at most
 *               TRAIL_MAX_ATTEMPTS per event, and only until TRAIL_OBSERVATION_MS after the run ends
 *   ids         at most OBSERVED_ID_LIMIT alert/incident ids retained for de-duplication
 *
 * Honesty
 * -------
 * A row says PROCESSED, ALERT or INCIDENT only once a trail response said so. Until then it is
 * ACCEPTED with observed=false, which the UI renders as "not observed" rather than "no alert".
 * Nothing here infers a detection from the scenario that produced the event.
 *
 * Framework-free and fully injected (clock, timers, both fetches), so scripts/simulator-check.mts
 * drives it with a fake clock and a fake transport and nothing reaches a real backend.
 */
import type { Alert, EventTrail, Incident, ProcessingStatus } from '../types/domain';
import {
  ACTIVITY_LIMIT,
  INCIDENT_FETCH_PER_TICK,
  LIVE_ROW_HARD_LIMIT,
  OBSERVED_ID_LIMIT,
  RATE_WINDOW_SAMPLES,
  TRAIL_MAX_ATTEMPTS,
  TRAIL_OBSERVATION_MS,
  TRAIL_POLL_BATCH,
  TRAIL_POLL_INTERVAL_MS,
} from './types.ts';
import type { DemoRunMeta } from './demoPresets.ts';
import type { RunSnapshot, RunState, SimulatorConfig } from './types.ts';

export type TimerHandle = unknown;

/**
 * What a console row can say. Every value is backed by data the console actually holds:
 *  SENDING     the engine has this event in flight
 *  ACCEPTED    POST answered 2xx; nothing is known about processing yet
 *  FAILED      the POST failed, or the trail reported processingStatus FAILED
 *  PROCESSING  a trail response said PENDING
 *  PROCESSED   a trail response said PROCESSED and carried no alert
 *  ALERT       a trail response carried at least one alert
 *  INCIDENT    one of those alerts belongs to an incident
 * There is deliberately no QUEUED row: an event the engine has not submitted yet has no result to
 * show, so the Run Progress panel reports the queued COUNT from the plan instead.
 */
export type LiveStatus = 'SENDING' | 'ACCEPTED' | 'FAILED' | 'PROCESSING' | 'PROCESSED' | 'ALERT' | 'INCIDENT';

/** The part of an observed alert the console shows. All of it comes from the trail response. */
export type RowAlert = {
  id: string;
  severity: string;
  status: string;
  detectionType: string;
  /** The deterministic rule that raised it, when it was a rule and not the ML path. */
  ruleId: string | null;
  incidentId: string | null;
};

export type LiveRow = {
  /** 1-based submission order within the run (the engine's result index + 1). */
  seq: number;
  eventId: string;
  eventType: string;
  entityId: string;
  scenario: string;
  occurredAt: string;
  submittedAt: number;
  settledAt: number | null;
  status: LiveStatus;
  /** Message of a failed POST. */
  sendError: string | null;
  /** HTTP status of a failed POST, when the transport reported one. */
  httpStatus: number | null;
  /** processingStatus from the trail, or null while nothing has been observed. */
  processing: ProcessingStatus | null;
  /** The backend's own processing error, when the trail reported one. */
  processingError: string | null;
  score: number | null;
  decision: string | null;
  alerts: RowAlert[];
  incidentIds: string[];
  /** True once a trail response was received: the difference between "no alert" and "not observed". */
  observed: boolean;
  /** Trail polls spent on this row. */
  attempts: number;
  /** No more polling: terminal processing state, attempt cap reached, or the window closed. */
  resolved: boolean;
  /** Polling stopped without ever observing a trail. */
  gaveUp: boolean;
};

export type ActivityKind =
  | 'RUN_STARTED' | 'PAUSED' | 'RESUMED' | 'STOPPING'
  | 'ACCEPTED' | 'SEND_FAILED' | 'PROCESSED' | 'PROCESSING_FAILED'
  | 'ALERT' | 'INCIDENT' | 'RUN_ENDED';

export type ActivityEntry = {
  /** Monotonic within a run, so React keys are stable. */
  id: number;
  at: number;
  kind: ActivityKind;
  label: string;
  detail: string;
};

/** Counters that are CUMULATIVE for the run: trimming a row never decreases one. */
export type LiveTotals = {
  /** Rows ever added for this run. */
  rowsSeen: number;
  /** Rows dropped from the bounded display. */
  trimmed: number;
  /** Events whose trail was successfully read at least once. */
  observed: number;
  /** Events the backend reported as PROCESSED. */
  processed: number;
  /** Events the backend reported as processing FAILED. */
  processingFailed: number;
  /** Events polling gave up on without an answer. */
  unobserved: number;
  /** Distinct alert ids seen on this run's trails. */
  alerts: number;
  /** Distinct incident ids seen on this run's trails. */
  incidents: number;
  peakScore: number | null;
  /** Observed alert severities, e.g. { HIGH: 2, MEDIUM: 1 }. */
  severity: Record<string, number>;
  /** Observed detectors: a ruleId, or "ML" for a prediction-driven alert. */
  detectors: Record<string, number>;
};

/**
 * What the Run Progress panel needs about the plan that is RUNNING (not the plan the configuration
 * panel currently describes, which the user may have changed since). The page hands this over at
 * start; it lives here so it survives navigating away and back, like the run itself.
 *
 * `segmentOfEvent[i]` is the segment index of plan position i, so generation progress per segment is
 * an exact count against the engine's own nextEventIndex - never an estimate.
 */
export type PlanSegmentInfo = { kind: 'SCENARIO' | 'NOISE'; entityId: string; prefix: string; count: number };

export type RunPlanInfo = {
  runId: string;
  scenarioId: string;
  label: string;
  /**
   * The exact configuration this run was built from, kept verbatim. Run History copies it, so a
   * historical run stays accurate however the console's current configuration is changed afterwards.
   */
  config: SimulatorConfig;
  /** The demo preset this run was started from, when it was started from one. Metadata only. */
  demo: DemoRunMeta | null;
  phases: string[];
  targets: string[];
  segments: PlanSegmentInfo[];
  segmentOfEvent: number[];
  totalEvents: number;
  eventRate: number;
  maxDurationMs: number | null;
  intensity: string;
  pattern: string;
  targetMode: string;
  noisePercent: number;
  detection: string;
};

export type ObservedIncident = { id: string; status: string; summary: string; alertCount: number; maxSeverity: string | null };

export type LiveSnapshot = {
  runId: string | null;
  /** The plan that is running, when the page handed it over. */
  plan: RunPlanInfo | null;
  /** Newest first - the order the console renders. */
  rows: LiveRow[];
  activity: ActivityEntry[];
  totals: LiveTotals;
  incidents: ObservedIncident[];
  /** Events the poller currently has a request in flight for. */
  polling: number;
  /** Rows still waiting for a trail answer. */
  pending: number;
  /** Actual recent submission throughput in events/sec, or null with too few samples. */
  actualRate: number | null;
  /** Whether the shared poll timer is armed. */
  pollerArmed: boolean;
};

export type LiveDeps = {
  fetchTrail: (eventId: string) => Promise<EventTrail>;
  /** Incident status is not part of the trail, so it is read once per distinct incident id. */
  fetchIncident?: (incidentId: string) => Promise<Incident>;
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => TimerHandle;
  clearTimer?: (handle: TimerHandle) => void;
};

const TERMINAL_PROCESSING: ProcessingStatus[] = ['PROCESSED', 'FAILED'];
const ENGINE_ACTIVE: RunState[] = ['RUNNING', 'PAUSED', 'STOPPING'];

const emptyTotals = (): LiveTotals => ({
  rowsSeen: 0,
  trimmed: 0,
  observed: 0,
  processed: 0,
  processingFailed: 0,
  unobserved: 0,
  alerts: 0,
  incidents: 0,
  peakScore: null,
  severity: {},
  detectors: {},
});

const str = (v: unknown, fallback: string) => (typeof v === 'string' && v ? v : fallback);
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null);

/** The alert fields the console shows, normalised from whatever the backend returned. */
const toRowAlert = (a: Alert): RowAlert => ({
  id: String(a.id),
  severity: str(a.severity, 'UNKNOWN'),
  status: str(a.status, 'UNKNOWN'),
  detectionType: str(a.detectionType, a.ruleId ? 'RULE' : 'ML'),
  ruleId: typeof a.ruleId === 'string' && a.ruleId ? a.ruleId : null,
  incidentId: typeof a.incidentId === 'string' && a.incidentId ? a.incidentId : null,
});

/** All alerts on a trail, tolerating the older single-`alert` shape. */
const alertsOf = (t: EventTrail): Alert[] => t.alerts ?? (t.alert ? [t.alert] : []);

export class LiveConsole {
  private readonly deps: LiveDeps;
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => TimerHandle;
  private readonly clearTimer: (handle: TimerHandle) => void;

  /* ---------------- run-scoped state (all of it cleared by reset/newRun) */
  private runId: string | null = null;
  private plan: RunPlanInfo | null = null;
  private rows: LiveRow[] = [];
  private byId = new Map<string, LiveRow>();
  private activity: ActivityEntry[] = [];
  private totals: LiveTotals = emptyTotals();
  private alertIds = new Set<string>();
  private incidentIds = new Set<string>();
  private incidents = new Map<string, ObservedIncident>();
  private incidentsWanted = new Set<string>();
  private rateSamples: number[] = [];
  private activitySeq = 0;
  /** How far into the engine's results array every entry is already settled. */
  private cursor = 0;
  private lastState: RunState = 'IDLE';
  private runActive = false;
  private finishedAt: number | null = null;

  /* ---------------- poller state */
  private inFlightTrails = new Set<string>();
  private inFlightIncidents = new Set<string>();
  private pollTimer: TimerHandle | null = null;
  private attached = 0;
  /** Bumped by reset() and by a new run, so a settling request from before it is dropped. */
  private generation = 0;

  private listeners = new Set<() => void>();
  private snapshot: LiveSnapshot;

  constructor(deps: LiveDeps) {
    this.deps = deps;
    this.now = deps.now ?? Date.now;
    this.setTimer = deps.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.clearTimer = deps.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
    this.snapshot = this.build();
  }

  /* ---------------------------------------------------------------- subscription */

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /** Stable between changes (safe for useSyncExternalStore). */
  getSnapshot = (): LiveSnapshot => this.snapshot;

  /**
   * Mount the console. The returned teardown stops the shared poll timer once the last mount goes
   * away, so an unmounted page never keeps polling; the engine's own run is untouched either way.
   */
  attach = (): (() => void) => {
    this.attached++;
    // A console detached across the end of the observation window has nothing left to learn:
    // arm() retires those rows rather than leaving them "awaiting" an answer that cannot come.
    this.arm();
    this.emit();
    return () => {
      this.attached = Math.max(0, this.attached - 1);
      if (this.attached === 0) this.disarm();
    };
  };

  /** Timers the console holds (0 whenever it is detached or has nothing left to poll). */
  pendingTimers(): number {
    return this.pollTimer === null ? 0 : 1;
  }

  /** Requests in flight right now (trail reads plus incident look-ups). */
  inFlightCount(): number {
    return this.inFlightTrails.size + this.inFlightIncidents.size;
  }

  /* ---------------------------------------------------------------- observation */

  /**
   * Fold one engine snapshot into the console. Safe to call with the same snapshot repeatedly: it
   * only ever advances, and a run id it has not seen starts a fresh console.
   */
  ingest(snap: RunSnapshot): void {
    if (snap.runId === null && this.runId === null && snap.state === 'IDLE') return;

    if (snap.runId !== null && snap.runId !== this.runId) this.startRun(snap);

    this.runActive = ENGINE_ACTIVE.includes(snap.state);
    this.finishedAt = snap.finishedAt;

    for (let i = this.cursor; i < snap.results.length; i++) {
      const r = snap.results[i];
      this.upsert(i, r, snap.label ?? '');
      // The engine settles strictly in order, so a settled prefix is never revisited.
      if (r.status !== 'SUBMITTED') this.cursor = i + 1;
    }

    this.noteStateChange(snap);
    this.arm();
    this.emit();
  }

  /** Clear the live console. The engine is not touched - the page resets that separately. */
  reset(): void {
    this.generation++;
    this.runId = null;
    this.plan = null;
    this.rows = [];
    this.byId = new Map();
    this.activity = [];
    this.totals = emptyTotals();
    this.alertIds = new Set();
    this.incidentIds = new Set();
    this.incidents = new Map();
    this.incidentsWanted = new Set();
    this.rateSamples = [];
    this.activitySeq = 0;
    this.cursor = 0;
    this.lastState = 'IDLE';
    this.runActive = false;
    this.finishedAt = null;
    this.inFlightTrails = new Set();
    this.inFlightIncidents = new Set();
    this.disarm();
    this.emit();
  }

  /**
   * Record the plan the page is about to start. Called BEFORE engine.start(), so the first ingest
   * already has it; a plan for a different run id is kept until that run's first snapshot arrives.
   */
  setPlan(plan: RunPlanInfo): void {
    this.plan = plan;
    this.emit();
  }

  private startRun(snap: RunSnapshot) {
    const incoming = this.plan && this.plan.runId === snap.runId ? this.plan : null;
    this.reset();
    this.plan = incoming;
    this.runId = snap.runId;
    this.lastState = 'IDLE';
    this.push('RUN_STARTED', 'RUN STARTED', `${snap.label ?? 'Run'} — ${snap.totalEvents} events at ${snap.eventRate}/s`, snap.startedAt ?? this.now());
  }

  private upsert(index: number, r: RunSnapshot['results'][number], scenario: string) {
    const existing = this.byId.get(r.eventId);
    if (!existing) {
      const row: LiveRow = {
        seq: index + 1,
        eventId: r.eventId,
        eventType: r.eventType,
        entityId: r.entityId,
        scenario,
        occurredAt: r.occurredAt,
        submittedAt: r.submittedAt,
        settledAt: r.settledAt ?? null,
        status: 'SENDING',
        sendError: null,
        httpStatus: null,
        processing: null,
        processingError: null,
        score: null,
        decision: null,
        alerts: [],
        incidentIds: [],
        observed: false,
        attempts: 0,
        resolved: false,
        gaveUp: false,
      };
      this.rows.unshift(row);
      this.byId.set(row.eventId, row);
      this.totals.rowsSeen++;
      this.sampleRate(r.submittedAt);
      this.trim();
      this.applySubmission(row, r);
      return;
    }
    this.applySubmission(existing, r);
  }

  /** Reflect the engine's own verdict on the submission. Transport truth, nothing inferred. */
  private applySubmission(row: LiveRow, r: RunSnapshot['results'][number]) {
    if (r.status === 'SUBMITTED') return;
    const wasPending = row.status === 'SENDING';
    row.settledAt = r.settledAt ?? row.settledAt;

    if (r.status === 'FAILED') {
      row.sendError = r.error?.message ?? 'The event could not be submitted';
      row.httpStatus = typeof r.error?.status === 'number' ? r.error.status : null;
      row.status = 'FAILED';
      // A rejected POST stored nothing, so there is no trail to wait for.
      row.resolved = true;
      if (wasPending) this.push('SEND_FAILED', 'SEND FAILED', `${row.eventId} — ${row.httpStatus ? `HTTP ${row.httpStatus}: ` : ''}${row.sendError}`, row.settledAt ?? this.now());
      return;
    }

    if (wasPending) {
      row.status = 'ACCEPTED';
      this.push('ACCEPTED', 'EVENT ACCEPTED', `${row.eventId} — ${row.eventType} on ${row.entityId}`, row.settledAt ?? this.now());
    }
  }

  private noteStateChange(snap: RunSnapshot) {
    if (snap.state === this.lastState) return;
    const at = this.now();
    if (snap.state === 'PAUSED') this.push('PAUSED', 'RUN PAUSED', `${snap.generated} of ${snap.totalEvents} submitted`, at);
    else if (snap.state === 'RUNNING' && this.lastState === 'PAUSED') this.push('RESUMED', 'RUN RESUMED', `continuing from event ${snap.nextEventIndex + 1}`, at);
    else if (snap.state === 'STOPPING') this.push('STOPPING', 'STOPPING', 'no further events will be submitted', at);
    else if (snap.state === 'COMPLETED') this.push('RUN_ENDED', 'RUN COMPLETED', `${snap.accepted} accepted, ${snap.failed} failed`, snap.finishedAt ?? at);
    else if (snap.state === 'STOPPED') this.push('RUN_ENDED', snap.stopReason === 'DURATION' ? 'RUN STOPPED (DURATION)' : 'RUN STOPPED', `${snap.accepted} of ${snap.totalEvents} accepted`, snap.finishedAt ?? at);
    else if (snap.state === 'FAILED') this.push('RUN_ENDED', 'RUN FAILED', snap.failureReason ?? 'the run ended in failure', snap.finishedAt ?? at);
    this.lastState = snap.state;
  }

  /* ---------------------------------------------------------------- bounded collections */

  /** Drop the oldest rows past the hard limit. Cumulative totals are untouched by design. */
  private trim() {
    while (this.rows.length > LIVE_ROW_HARD_LIMIT) {
      const dropped = this.rows.pop()!;
      this.byId.delete(dropped.eventId);
      this.inFlightTrails.delete(dropped.eventId);
      this.totals.trimmed++;
    }
  }

  private push(kind: ActivityKind, label: string, detail: string, at: number) {
    this.activity.unshift({ id: ++this.activitySeq, at, kind, label, detail });
    if (this.activity.length > ACTIVITY_LIMIT) this.activity.length = ACTIVITY_LIMIT;
  }

  private sampleRate(at: number) {
    this.rateSamples.push(at);
    if (this.rateSamples.length > RATE_WINDOW_SAMPLES) this.rateSamples.shift();
  }

  /** Actual recent throughput from the engine's own submission timestamps. */
  private computeRate(): number | null {
    const s = this.rateSamples;
    if (s.length < 2) return null;
    const span = s[s.length - 1] - s[0];
    if (span <= 0) return null;
    return ((s.length - 1) * 1000) / span;
  }

  /* ---------------------------------------------------------------- the shared poller */

  /**
   * Rows that still have something to learn, newest first - at most as many as the batch has room
   * for RIGHT NOW. The budget counts requests already in flight, so ticks cannot stack up and the
   * console never has more than TRAIL_POLL_BATCH trail requests outstanding, however long it runs.
   */
  private candidates(): LiveRow[] {
    const budget = TRAIL_POLL_BATCH - this.inFlightTrails.size;
    if (budget <= 0 || !this.withinWindow()) return [];
    const out: LiveRow[] = [];
    for (const row of this.rows) {
      if (row.resolved || row.sendError || row.status === 'SENDING') continue;
      if (this.inFlightTrails.has(row.eventId)) continue;
      if (row.attempts >= TRAIL_MAX_ATTEMPTS) continue;
      out.push(row);
      if (out.length >= budget) break;
    }
    return out;
  }

  private pendingCount(): number {
    let n = 0;
    for (const row of this.rows) if (!row.resolved && !row.sendError && row.status !== 'SENDING') n++;
    return n;
  }

  /** Observation stops TRAIL_OBSERVATION_MS after the run finished; it never stops while it runs. */
  private withinWindow(): boolean {
    if (this.runActive) return true;
    if (this.finishedAt === null) return this.runId !== null;
    return this.now() <= this.finishedAt + TRAIL_OBSERVATION_MS;
  }

  /**
   * The one place that decides whether a timer is needed. It first retires rows there is nothing
   * left to learn about (attempt cap, closed window), then arms the single shared timer only while
   * the console is mounted and only when there is actually work for it.
   */
  private arm() {
    if (this.attached === 0) return;
    this.sweep();
    if (this.pollTimer !== null) return;
    if (!this.candidates().length && !this.incidentsToFetch().length) return;
    const gen = this.generation;
    this.pollTimer = this.setTimer(() => {
      this.pollTimer = null;
      if (gen === this.generation) this.tick();
    }, TRAIL_POLL_INTERVAL_MS);
  }

  private disarm() {
    if (this.pollTimer !== null) {
      this.clearTimer(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private incidentsToFetch(): string[] {
    if (!this.deps.fetchIncident) return [];
    const budget = INCIDENT_FETCH_PER_TICK - this.inFlightIncidents.size;
    if (budget <= 0) return [];
    const out: string[] = [];
    for (const id of this.incidentsWanted) {
      if (this.inFlightIncidents.has(id)) continue;
      out.push(id);
      if (out.length >= budget) break;
    }
    return out;
  }

  /**
   * One tick: a bounded batch of trail reads plus a couple of incident lookups. A row with a request
   * in flight is not a candidate, so concurrency can never exceed TRAIL_POLL_BATCH.
   */
  private tick() {
    const gen = this.generation;
    const batch = this.candidates();
    const incidents = this.incidentsToFetch();

    for (const row of batch) {
      this.inFlightTrails.add(row.eventId);
      row.attempts++;
      let p: Promise<EventTrail>;
      try {
        p = Promise.resolve(this.deps.fetchTrail(row.eventId));
      } catch (e) {
        p = Promise.reject(e);
      }
      p.then(
        (trail) => this.settleTrail(gen, row.eventId, trail),
        () => this.settleTrail(gen, row.eventId, null),
      );
    }

    for (const id of incidents) {
      this.inFlightIncidents.add(id);
      let p: Promise<Incident>;
      try {
        p = Promise.resolve(this.deps.fetchIncident!(id));
      } catch (e) {
        p = Promise.reject(e);
      }
      p.then(
        (incident) => this.settleIncident(gen, id, incident),
        () => this.settleIncident(gen, id, null),
      );
    }

    this.arm();
    this.emit();
  }

  /**
   * Stop observing rows that have run out of attempts or outlived the observation window. A row with
   * a request still in flight is left alone - its own settlement decides.
   */
  private sweep() {
    const closed = !this.withinWindow();
    for (const row of this.rows) {
      if (this.inFlightTrails.has(row.eventId)) continue;
      if (row.attempts >= TRAIL_MAX_ATTEMPTS || closed) this.giveUp(row);
    }
  }

  /** Idempotent: a row is only ever counted as unobserved once. */
  private giveUp(row: LiveRow) {
    if (row.resolved || row.sendError) return;
    row.resolved = true;
    if (!row.observed) {
      row.gaveUp = true;
      this.totals.unobserved++;
    }
  }

  private settleTrail(gen: number, eventId: string, trail: EventTrail | null) {
    // A reset (or a new run) happened while this request was in flight: its answer is stale.
    if (gen !== this.generation) return;
    this.inFlightTrails.delete(eventId);
    const row = this.byId.get(eventId);
    if (row) {
      if (trail === null) {
        // A failed trail read tells us nothing; the attempt cap is what ends the attempts.
        if (row.attempts >= TRAIL_MAX_ATTEMPTS || !this.withinWindow()) this.giveUp(row);
      } else {
        this.applyTrail(row, trail);
      }
    }
    this.arm();
    this.emit();
  }

  /** Everything a row knows about processing and detection comes from here, and only from here. */
  private applyTrail(row: LiveRow, trail: EventTrail) {
    const first = !row.observed;
    row.observed = true;
    if (first) this.totals.observed++;

    const status = trail.processingStatus;
    const changed = row.processing !== status;
    row.processing = status;
    row.processingError = typeof trail.lastProcessingError === 'string' ? trail.lastProcessingError : null;

    if (trail.prediction) {
      row.score = num(trail.prediction.fusedScore) ?? num(trail.prediction.anomalyScore);
      row.decision = str(trail.prediction.decision, '') || null;
      if (row.score !== null && (this.totals.peakScore === null || row.score > this.totals.peakScore)) {
        this.totals.peakScore = row.score;
      }
    }

    for (const alert of alertsOf(trail)) {
      const info = toRowAlert(alert);
      if (!row.alerts.some((a) => a.id === info.id)) row.alerts.push(info);
      if (!this.alertIds.has(info.id)) {
        if (this.alertIds.size < OBSERVED_ID_LIMIT) this.alertIds.add(info.id);
        this.totals.alerts++;
        this.totals.severity[info.severity] = (this.totals.severity[info.severity] ?? 0) + 1;
        const detector = info.ruleId ?? (info.detectionType === 'RULE' ? 'RULE' : 'ML');
        this.totals.detectors[detector] = (this.totals.detectors[detector] ?? 0) + 1;
        this.push('ALERT', 'ALERT CREATED', `${info.severity} — ${info.ruleId ?? 'ML anomaly'} on ${row.entityId}`, this.now());
      }
      if (info.incidentId) {
        if (!row.incidentIds.includes(info.incidentId)) row.incidentIds.push(info.incidentId);
        if (!this.incidentIds.has(info.incidentId)) {
          if (this.incidentIds.size < OBSERVED_ID_LIMIT) this.incidentIds.add(info.incidentId);
          this.totals.incidents++;
          this.incidentsWanted.add(info.incidentId);
          this.push('INCIDENT', 'INCIDENT OPENED', `${info.incidentId} — from a ${info.severity} alert on ${row.entityId}`, this.now());
        }
      }
    }

    if (changed && status === 'PROCESSED') {
      this.totals.processed++;
      if (!row.alerts.length) this.push('PROCESSED', 'PROCESSED', `${row.eventId} — no alert raised`, this.now());
    } else if (changed && status === 'FAILED') {
      this.totals.processingFailed++;
      this.push('PROCESSING_FAILED', 'PROCESSING FAILED', `${row.eventId} — ${row.processingError ?? 'the backend could not process this event'}`, this.now());
    }

    row.status = this.deriveStatus(row);
    // PROCESSED and FAILED are the backend's terminal states: there is nothing further to observe.
    if (TERMINAL_PROCESSING.includes(status)) row.resolved = true;
  }

  private deriveStatus(row: LiveRow): LiveStatus {
    if (row.sendError) return 'FAILED';
    if (row.processing === 'FAILED') return 'FAILED';
    if (row.incidentIds.length) return 'INCIDENT';
    if (row.alerts.length) return 'ALERT';
    if (row.processing === 'PROCESSED') return 'PROCESSED';
    if (row.processing === 'PENDING') return 'PROCESSING';
    return 'ACCEPTED';
  }

  private settleIncident(gen: number, id: string, incident: Incident | null) {
    if (gen !== this.generation) return;
    this.inFlightIncidents.delete(id);
    // Either way the lookup is done: a failure is not retried, so it cannot loop.
    this.incidentsWanted.delete(id);
    if (incident) {
      this.incidents.set(id, {
        id,
        status: str(incident.status, 'UNKNOWN'),
        summary: str(incident.summary, ''),
        alertCount: typeof incident.alertCount === 'number' ? incident.alertCount : 0,
        maxSeverity: typeof incident.maxSeverity === 'string' ? incident.maxSeverity : null,
      });
    }
    this.arm();
    this.emit();
  }

  /* ---------------------------------------------------------------- snapshot */

  private emit() {
    this.snapshot = this.build();
    for (const l of [...this.listeners]) l();
  }

  private build(): LiveSnapshot {
    return {
      runId: this.runId,
      plan: this.plan,
      rows: this.rows.map((r) => ({ ...r, alerts: r.alerts.slice(), incidentIds: r.incidentIds.slice() })),
      activity: this.activity.slice(),
      totals: { ...this.totals, severity: { ...this.totals.severity }, detectors: { ...this.totals.detectors } },
      incidents: [...this.incidents.values()],
      polling: this.inFlightTrails.size + this.inFlightIncidents.size,
      pending: this.pendingCount(),
      actualRate: this.computeRate(),
      pollerArmed: this.pollTimer !== null,
    };
  }
}

/* ------------------------------------------------------------------ filtering (pure) */

export type RowFilter = 'ALL' | 'ACCEPTED' | 'FAILED' | 'ALERTS' | 'INCIDENTS' | 'PENDING';

/** Filtering runs on the bounded client-side rows only - it never refetches anything. */
export function filterRows(rows: LiveRow[], filter: RowFilter, eventType = 'ALL'): LiveRow[] {
  return rows.filter((r) => {
    if (eventType !== 'ALL' && r.eventType !== eventType) return false;
    switch (filter) {
      case 'ACCEPTED': return !r.sendError;
      case 'FAILED': return Boolean(r.sendError) || r.processing === 'FAILED';
      case 'ALERTS': return r.alerts.length > 0;
      case 'INCIDENTS': return r.incidentIds.length > 0;
      case 'PENDING': return !r.sendError && !r.resolved;
      default: return true;
    }
  });
}

/* ------------------------------------------------------------------ completion summary (pure) */

export type RunOutcome = 'COMPLETED' | 'STOPPED' | 'DURATION' | 'FAILED';

export type CompletionSummary = {
  runId: string | null;
  label: string | null;
  outcome: RunOutcome;
  reason: string | null;
  durationMs: number;
  generated: number;
  accepted: number;
  failed: number;
  totalEvents: number;
  /** Submissions per second over the whole run, not the configured rate. */
  averageRate: number | null;
  observed: number;
  processed: number;
  processingFailed: number;
  unobserved: number;
  alerts: number;
  incidents: number;
  peakScore: number | null;
  severity: Record<string, number>;
  detectors: Record<string, number>;
};

/**
 * The completion summary, built only from the engine snapshot and observed totals. `outcome` uses
 * the engine's own vocabulary: DURATION is a STOPPED run whose stopReason was the duration cap.
 */
export function completionSummary(snap: RunSnapshot, live: LiveSnapshot): CompletionSummary | null {
  if (snap.state !== 'COMPLETED' && snap.state !== 'STOPPED' && snap.state !== 'FAILED') return null;
  const durationMs = snap.startedAt === null ? 0 : (snap.finishedAt ?? snap.startedAt) - snap.startedAt;
  const submissions = snap.accepted + snap.failed;
  return {
    runId: snap.runId,
    label: snap.label,
    outcome: snap.state === 'STOPPED' && snap.stopReason === 'DURATION' ? 'DURATION' : snap.state,
    reason: snap.failureReason,
    durationMs,
    generated: snap.generated,
    accepted: snap.accepted,
    failed: snap.failed,
    totalEvents: snap.totalEvents,
    averageRate: durationMs > 0 && submissions > 0 ? (submissions * 1000) / durationMs : null,
    observed: live.totals.observed,
    processed: live.totals.processed,
    processingFailed: live.totals.processingFailed,
    unobserved: live.totals.unobserved,
    alerts: live.totals.alerts,
    incidents: live.totals.incidents,
    peakScore: live.totals.peakScore,
    severity: { ...live.totals.severity },
    detectors: { ...live.totals.detectors },
  };
}
