/*
 * Simulator run engine: submits a prepared list of events strictly one at a time, paced, with
 * pause / resume / stop and an optional duration cap. Framework-free; the transport and the clock
 * are injected so scripts/simulator-check.mts can drive it with a fake clock.
 *
 * Responsibility ends at submission. "ACCEPTED" means POST /api/v1/events answered 2xx - it is NOT
 * "processed"; processing status comes from the trail API, polled separately by the page.
 *
 * Mechanics: one pump. At most one timer is pending and at most one send is in flight; the next
 * send is only ever scheduled from the previous send's settlement (or from start/resume), so sends
 * can never overlap and ordering is the plan's order.
 *
 * State machine (anything else is rejected):
 *   IDLE      -> RUNNING                        start()
 *   RUNNING   -> PAUSED                         pause()
 *   PAUSED    -> RUNNING                        resume()
 *   RUNNING   -> STOPPING                       stop(), or the duration cap expiring
 *   PAUSED    -> STOPPING                       stop(), or the duration cap expiring
 *   STOPPING  -> STOPPED                        once no send is in flight
 *   RUNNING   -> COMPLETED                      every planned event has been attempted
 *   RUNNING   -> FAILED                         systemic failure (see below)
 *   PAUSED    -> FAILED                         systemic failure reported by the send still in flight
 *   COMPLETED | STOPPED | FAILED -> IDLE        reset(), so the engine can run again
 *
 * Errors: a per-event rejection (400 validation, 404 entity, 409 duplicate, 413 too large, 422...)
 * is recorded and the run continues - the next event is independent and the old console did the
 * same. A systemic failure (no response, 5xx, 429) also continues unless SYSTEMIC_FAILURE_LIMIT of
 * them happen in a row, which means the backend is down: the run ends FAILED and the rest of the
 * plan is not sent. 401/403 end it FAILED at once (the session cannot send anything). Nothing is
 * retried: re-sending a POST whose response was lost could store the event twice.
 *
 * Duration: a wall-clock cap from start, pauses included. When it expires the run stops exactly as
 * if stop() had been called (-> STOPPING -> STOPPED) with stopReason "DURATION".
 */
import { MAX_EVENT_RATE, MIN_EVENT_RATE, SYSTEMIC_FAILURE_LIMIT } from './types.ts';
import type { EventResult, RunOptions, RunPlan, RunSnapshot, RunState, SendError } from './types.ts';
import type { CreateEventRequest } from '../types/domain';

export type TimerHandle = unknown;

export type EngineDeps = {
  send: (event: CreateEventRequest) => Promise<unknown>;
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => TimerHandle;
  clearTimer?: (handle: TimerHandle) => void;
};

const TRANSITIONS: Record<RunState, readonly RunState[]> = {
  IDLE: ['RUNNING'],
  RUNNING: ['PAUSED', 'STOPPING', 'COMPLETED', 'FAILED'],
  PAUSED: ['RUNNING', 'STOPPING', 'FAILED'],
  STOPPING: ['STOPPED'],
  COMPLETED: ['IDLE'],
  STOPPED: ['IDLE'],
  FAILED: ['IDLE'],
};

export const canTransition = (from: RunState, to: RunState) => TRANSITIONS[from].includes(to);

/** Clamp any requested rate into the supported range; non-numbers fall back to the minimum. */
export const clampRate = (rate: number) =>
  Number.isFinite(rate) ? Math.min(MAX_EVENT_RATE, Math.max(MIN_EVENT_RATE, rate)) : MIN_EVENT_RATE;

/** Normalise whatever the transport threw (the API client rejects with ApiError) into a SendError. */
export function describeError(e: unknown): SendError {
  const err = (e ?? {}) as { status?: unknown; code?: unknown; message?: unknown; details?: unknown };
  const status = typeof err.status === 'number' ? err.status : undefined;
  const code = typeof err.code === 'string' ? err.code : undefined;
  const base = typeof err.message === 'string' && err.message ? err.message : 'The event could not be submitted';
  const details = Array.isArray(err.details) ? err.details.filter((d) => typeof d === 'string') : [];
  const message = details.length ? `${base}: ${details.join('; ')}` : base;
  const systemic = status === undefined || status >= 500 || status === 429;
  return { status, code, message, systemic };
}

const isAuthFailure = (e: SendError) => e.status === 401 || e.status === 403;

export const TERMINAL: readonly RunState[] = ['COMPLETED', 'STOPPED', 'FAILED'];
export const ACTIVE: readonly RunState[] = ['RUNNING', 'PAUSED', 'STOPPING'];

/** Elapsed run time at `now` (live while running, frozen once finished). */
export const elapsedMs = (s: RunSnapshot, now: number) => (s.startedAt === null ? 0 : (s.finishedAt ?? now) - s.startedAt);

export class SimulationEngine {
  private readonly send: EngineDeps['send'];
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => TimerHandle;
  private readonly clearTimer: (handle: TimerHandle) => void;

  private state: RunState = 'IDLE';
  private plan: RunPlan | null = null;
  private results: EventResult[] = [];
  private next = 0;
  private inFlight = -1;
  private accepted = 0;
  private failed = 0;
  private consecutiveSystemic = 0;
  private rate = MIN_EVENT_RATE;
  private maxDurationMs: number | null = null;
  private startedAt: number | null = null;
  private finishedAt: number | null = null;
  private lastSendAt = 0;
  private stopReason: RunSnapshot['stopReason'] = null;
  private failureReason: string | null = null;

  private pumpTimer: TimerHandle | null = null;
  private durationTimer: TimerHandle | null = null;
  /** Bumped on every start/reset so a settlement from an earlier run is ignored. */
  private generation = 0;

  private listeners = new Set<() => void>();
  private snapshot: RunSnapshot;

  constructor(deps: EngineDeps) {
    this.send = deps.send;
    this.now = deps.now ?? Date.now;
    this.setTimer = deps.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.clearTimer = deps.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
    this.snapshot = this.buildSnapshot();
  }

  /* ---------------------------------------------------------------- subscription */

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /** Stable between changes (safe for useSyncExternalStore). */
  getSnapshot = (): RunSnapshot => this.snapshot;

  /** Timers the engine currently holds (0 whenever the run is not RUNNING/PAUSED). */
  pendingTimers(): number {
    return (this.pumpTimer === null ? 0 : 1) + (this.durationTimer === null ? 0 : 1);
  }

  /* ---------------------------------------------------------------- commands */

  start(plan: RunPlan, options: RunOptions): void {
    this.assertTransition('RUNNING', 'start');
    if (this.state !== 'IDLE') throw new Error(`start() needs an IDLE engine (state is ${this.state})`);
    if (!plan.events.length) throw new Error('start() needs at least one event');

    this.generation++;
    this.plan = plan;
    this.results = [];
    this.next = 0;
    this.inFlight = -1;
    this.accepted = 0;
    this.failed = 0;
    this.consecutiveSystemic = 0;
    this.rate = clampRate(options.eventRate);
    this.maxDurationMs = options.maxDurationMs && options.maxDurationMs > 0 ? options.maxDurationMs : null;
    this.startedAt = this.now();
    this.finishedAt = null;
    this.lastSendAt = 0;
    this.stopReason = null;
    this.failureReason = null;
    this.state = 'RUNNING';

    if (this.maxDurationMs !== null) {
      const gen = this.generation;
      this.durationTimer = this.setTimer(() => {
        this.durationTimer = null;
        if (gen === this.generation && (this.state === 'RUNNING' || this.state === 'PAUSED')) this.halt('DURATION');
      }, this.maxDurationMs);
    }
    this.emit();
    this.schedule(0);
  }

  pause(): void {
    this.assertTransition('PAUSED', 'pause');
    this.state = 'PAUSED';
    this.cancelPump();
    // the send in flight (if any) settles normally and does not schedule the next one
    this.emit();
  }

  resume(): void {
    if (this.state !== 'PAUSED') throw new Error(`resume() is only valid while PAUSED (state is ${this.state})`);
    this.state = 'RUNNING';
    this.emit();
    if (this.inFlight < 0) this.advance();
  }

  stop(): void {
    this.assertTransition('STOPPING', 'stop');
    this.halt('USER');
  }

  /** Back to IDLE after a finished run, so the same engine can run again. */
  reset(): void {
    this.assertTransition('IDLE', 'reset');
    this.generation++;
    this.state = 'IDLE';
    this.plan = null;
    this.results = [];
    this.next = 0;
    this.inFlight = -1;
    this.accepted = 0;
    this.failed = 0;
    this.startedAt = null;
    this.finishedAt = null;
    this.stopReason = null;
    this.failureReason = null;
    this.emit();
  }

  /* ---------------------------------------------------------------- internals */

  private assertTransition(to: RunState, command: string) {
    if (!canTransition(this.state, to)) throw new Error(`${command}() is not valid while ${this.state}`);
  }

  private halt(reason: 'USER' | 'DURATION') {
    this.state = 'STOPPING';
    this.stopReason = reason;
    this.cancelPump();
    this.emit();
    if (this.inFlight < 0) this.finish('STOPPED');
  }

  private finish(state: 'COMPLETED' | 'STOPPED' | 'FAILED', failureReason: string | null = null) {
    this.state = state;
    this.failureReason = failureReason;
    this.finishedAt = this.now();
    this.cancelPump();
    if (this.durationTimer !== null) {
      this.clearTimer(this.durationTimer);
      this.durationTimer = null;
    }
    this.emit();
  }

  private cancelPump() {
    if (this.pumpTimer !== null) {
      this.clearTimer(this.pumpTimer);
      this.pumpTimer = null;
    }
  }

  private schedule(delayMs: number) {
    this.cancelPump();
    const gen = this.generation;
    this.pumpTimer = this.setTimer(() => {
      this.pumpTimer = null;
      if (gen === this.generation) this.pump();
    }, Math.max(0, delayMs));
  }

  /** After a settlement or a resume: complete, or schedule the next send respecting the rate. */
  private advance() {
    if (this.state !== 'RUNNING') return;
    if (!this.plan || this.next >= this.plan.events.length) {
      this.finish('COMPLETED');
      return;
    }
    const interval = 1000 / this.rate;
    this.schedule(this.lastSendAt + interval - this.now());
  }

  private pump() {
    if (this.state !== 'RUNNING' || this.inFlight >= 0 || !this.plan) return;
    if (this.next >= this.plan.events.length) {
      this.finish('COMPLETED');
      return;
    }

    const index = this.next++;
    const event = this.plan.events[index];
    const gen = this.generation;
    this.inFlight = index;
    this.lastSendAt = this.now();
    this.results.push({
      index,
      eventId: event.eventId,
      eventType: event.eventType,
      entityId: event.entityId,
      occurredAt: event.occurredAt,
      status: 'SUBMITTED',
      submittedAt: this.lastSendAt,
    });
    this.emit();

    let sending: Promise<unknown>;
    try {
      sending = Promise.resolve(this.send(event));
    } catch (e) {
      sending = Promise.reject(e);
    }
    sending.then(
      () => this.settle(gen, index, null),
      (e) => this.settle(gen, index, describeError(e)),
    );
  }

  private settle(gen: number, index: number, error: SendError | null) {
    if (gen !== this.generation) return; // a reset() happened while this send was in flight
    this.inFlight = -1;
    this.results[index] = { ...this.results[index], status: error ? 'FAILED' : 'ACCEPTED', settledAt: this.now(), error: error ?? undefined };
    if (error) {
      this.failed++;
      this.consecutiveSystemic = error.systemic ? this.consecutiveSystemic + 1 : 0;
    } else {
      this.accepted++;
      this.consecutiveSystemic = 0;
    }

    const fatal = error && (isAuthFailure(error)
      ? `Not authorised to submit events (HTTP ${error.status}); the run was ended.`
      : this.consecutiveSystemic >= SYSTEMIC_FAILURE_LIMIT
        ? `${this.consecutiveSystemic} submissions in a row failed (${error.message}); the backend looks unavailable, so the remaining events were not sent.`
        : null);

    if (this.state === 'STOPPING') {
      this.emit();
      this.finish('STOPPED');
    } else if (fatal && (this.state === 'RUNNING' || this.state === 'PAUSED')) {
      this.finish('FAILED', fatal);
    } else {
      this.emit();
      this.advance(); // no-op unless RUNNING
    }
  }

  private emit() {
    this.snapshot = this.buildSnapshot();
    for (const l of [...this.listeners]) l();
  }

  private buildSnapshot(): RunSnapshot {
    return {
      runId: this.plan?.runId ?? null,
      label: this.plan?.label ?? null,
      state: this.state,
      stopReason: this.stopReason,
      failureReason: this.failureReason,
      totalEvents: this.plan?.events.length ?? 0,
      nextEventIndex: this.next,
      currentEventIndex: this.inFlight,
      generated: this.results.length,
      accepted: this.accepted,
      failed: this.failed,
      startedAt: this.startedAt,
      finishedAt: this.finishedAt,
      eventRate: this.rate,
      maxDurationMs: this.maxDurationMs,
      results: this.results.slice(),
    };
  }
}
