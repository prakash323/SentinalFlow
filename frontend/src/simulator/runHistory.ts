/*
 * Run history: a compact, local investigation record of finished simulator runs.
 *
 * Entirely client-side. There is no backend run table, no new endpoint and no network call anywhere
 * in this file - history is written to localStorage when a run reaches a terminal state and read
 * back from there. Everything else about a run (the events themselves, their trails, the alerts and
 * incidents they raised) already lives in the backend and is reached by the links in the UI, so
 * nothing is duplicated here.
 *
 * What is stored
 * --------------
 * A summary and the configuration that produced it: counts, rates, the observed detection totals and
 * the exact SimulatorConfig. NEVER an event payload, an event row, a credential, a token or anything
 * else from the session - see the shape of RunHistoryEntry, which has no field for any of them. The
 * only identifiers are the simulator's own run id and the entity ids the user already chose.
 *
 * Honesty about observation
 * -------------------------
 * The hard part of a run record is not the alert count, it is knowing whether that count means
 * anything. Trail polling is bounded (see liveConsole.ts), so a run can finish with events whose
 * pipeline outcome was never seen. An entry therefore carries BOTH the detection totals and the
 * observation coverage, and `detectionVerdict` refuses to present "0 alerts" as a clean result when
 * coverage was partial. "Nothing was detected" and "nothing was looked at" are different findings.
 *
 * Robustness
 * ----------
 * Storage is injected and may be null or throw at any moment (private mode, a full quota, a browser
 * that denies access). Every path is wrapped: a malformed or wrong-version payload recovers to an
 * empty history, a failed write is recorded in `storageError` and the store keeps working purely in
 * memory. Nothing here can throw into the Simulator page.
 */
import type { DemoRunMeta, DetectionType, ObservedRun } from './demoPresets.ts';
import type { CompletionSummary, LiveTotals, RunOutcome, RunPlanInfo } from './liveConsole.ts';
import type { AttackPattern, Intensity, NoisePercent, ObservationQuality, SimulatorConfig, TargetMode } from './types.ts';
import { TRAIL_OBSERVATION_MS } from './types.ts';

/** Same `sentinelflow.<area>` convention as sentinelflow.theme and sentinelflow.sidebar.collapsed. */
export const HISTORY_KEY = 'sentinelflow.simulator.history';
/** Bumped whenever the entry shape changes; an older or newer payload is ignored, never guessed at. */
export const HISTORY_VERSION = 1;
/** Runs kept. Adding the 51st drops the oldest, so the key cannot grow without bound. */
export const MAX_HISTORY_ENTRIES = 50;

// Lives in types.ts with the other shared unions, so a module can reason about observation quality
// without importing this store.
export type { ObservationQuality } from './types.ts';

export type RunHistoryEntry = {
  /** The simulator run id, which is also the event-ID prefix of every event in the run. */
  runId: string;
  /** When the engine started the run. */
  createdAt: number;
  /** When the engine finished it. */
  completedAt: number;
  outcome: RunOutcome;
  /** The engine's own failure text, when it had one. */
  reason: string | null;

  scenarioId: string;
  scenarioName: string;
  /** The honest detector statement for the scenario, as the library states it. */
  detection: string;

  /** The configuration that produced this run, verbatim. Never rebuilt from the current console. */
  config: SimulatorConfig;
  /** Denormalised for the history card, so rendering a list needs no lookups. */
  targets: string[];
  targetMode: TargetMode;
  intensity: Intensity;
  pattern: AttackPattern;
  noisePercent: NoisePercent;
  configuredRate: number;
  maxDurationMs: number | null;

  durationMs: number;
  /** Submissions per second over the whole run; null when it is not derivable. */
  actualRate: number | null;
  totalEvents: number;
  generated: number;
  accepted: number;
  failed: number;

  observed: number;
  processed: number;
  processingFailed: number;
  unobserved: number;
  alerts: number;
  incidents: number;
  peakScore: number | null;
  severity: Record<string, number>;
  detectors: Record<string, number>;

  /**
   * The demo preset the run was started from, when it was one: three fields and nothing else. No
   * expectation and no assessment are stored - both are derived from the preset on read, so a
   * historical record can never disagree with the preset it names.
   */
  demo: DemoRunMeta | null;

  /** Live console rows dropped to stay bounded - a display fact, not a data loss. */
  droppedRows: number;
  observation: ObservationQuality;
  /** How long after the run observation continued, so a partial result can be explained. */
  observationWindowMs: number;
};

/* ------------------------------------------------------------------ building an entry */

/**
 * Accepted events that reached a terminal processing state. An event whose trail only ever said
 * PENDING is NOT counted: it was looked at, but its outcome is still unknown.
 */
export const observedTerminal = (e: Pick<RunHistoryEntry, 'processed' | 'processingFailed'>): number =>
  e.processed + e.processingFailed;

export function observationQuality(accepted: number, processed: number, processingFailed: number): ObservationQuality {
  if (accepted <= 0) return 'NONE';
  const terminal = processed + processingFailed;
  if (terminal <= 0) return 'NONE';
  return terminal >= accepted ? 'COMPLETE' : 'PARTIAL';
}

/**
 * Turn a finished run into its history record. Returns null without the plan metadata, because an
 * entry without the configuration that produced it would be a guess - and section 8 of this phase
 * exists precisely so a historical run is never reconstructed from the console's current settings.
 */
export function buildHistoryEntry(
  summary: CompletionSummary,
  plan: RunPlanInfo | null,
  totals: LiveTotals,
  startedAt: number,
): RunHistoryEntry | null {
  if (!plan || !summary.runId) return null;
  return {
    runId: summary.runId,
    createdAt: startedAt,
    completedAt: startedAt + summary.durationMs,
    outcome: summary.outcome,
    reason: summary.reason,

    scenarioId: plan.scenarioId,
    scenarioName: summary.label ?? plan.label,
    detection: plan.detection,

    config: { ...plan.config, entityIds: [...plan.config.entityIds] },
    targets: [...plan.targets],
    targetMode: plan.config.targetMode,
    intensity: plan.config.intensity,
    pattern: plan.config.pattern,
    noisePercent: plan.config.noisePercent,
    configuredRate: plan.eventRate,
    maxDurationMs: plan.maxDurationMs,

    durationMs: summary.durationMs,
    actualRate: summary.averageRate,
    totalEvents: summary.totalEvents,
    generated: summary.generated,
    accepted: summary.accepted,
    failed: summary.failed,

    observed: summary.observed,
    processed: summary.processed,
    processingFailed: summary.processingFailed,
    unobserved: summary.unobserved,
    alerts: summary.alerts,
    incidents: summary.incidents,
    peakScore: summary.peakScore,
    severity: { ...summary.severity },
    detectors: { ...summary.detectors },

    demo: plan.demo ? { ...plan.demo } : null,
    droppedRows: totals.trimmed,
    observation: observationQuality(summary.accepted, summary.processed, summary.processingFailed),
    observationWindowMs: TRAIL_OBSERVATION_MS,
  };
}

/* ------------------------------------------------------------------ when to persist */

/** What the page has already written for the run it is watching. */
export type SaveMark = { runId: string; finalized: boolean } | null;

/**
 * Whether a finished run still needs writing, and whether this is its final form.
 *
 * The rule, in one place so it is testable rather than buried in an effect: a run is written once
 * the moment it reaches a terminal state - so navigating away cannot lose it - and once more when
 * trail polling has settled, so the record carries its final observation coverage. That is at most
 * two writes per run, never one per event. Everything else is SKIP:
 *
 *   not finished (IDLE, RUNNING, PAUSED, STOPPING, or reset back to IDLE)  -> SKIP
 *   already written and finalized                                          -> SKIP
 *   already written, still observing                                       -> SKIP until settled
 *   a run id that has not been written yet                                 -> SAVE (or FINALIZE)
 */
export function shouldPersist(mark: SaveMark, runId: string | null, finished: boolean, settled: boolean): 'SKIP' | 'SAVE' | 'FINALIZE' {
  if (!finished || !runId) return 'SKIP';
  if (!mark || mark.runId !== runId) return settled ? 'FINALIZE' : 'SAVE';
  if (mark.finalized) return 'SKIP';
  return settled ? 'FINALIZE' : 'SKIP';
}

/* ------------------------------------------------------------------ the SOC reading of an entry */

export type DetectionVerdict = {
  alerts: number;
  incidents: number;
  observation: ObservationQuality;
  /** Accepted events whose pipeline outcome was actually seen. */
  observedCount: number;
  acceptedCount: number;
  /** True only when the alert count can be relied on, i.e. every accepted event was observed. */
  conclusive: boolean;
  /** What the detection result is, phrased so it cannot be misread. */
  headline: string;
  /** Why it may not be the whole story. Null only when the result IS the whole story. */
  caveat: string | null;
};

/**
 * The one place that phrases a run's detection result.
 *
 * The rule it enforces: zero alerts is only ever reported as a clean result when observation was
 * COMPLETE. With partial coverage it stays "0 observed alerts" with the coverage spelled out, and
 * the words "safe", "clean" and "no alerts" are deliberately never produced. An analyst reading a
 * run record must be able to tell "we saw nothing happen" from "we did not see".
 */
export function detectionVerdict(e: RunHistoryEntry): DetectionVerdict {
  const observedCount = observedTerminal(e);
  const conclusive = e.observation === 'COMPLETE';
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

  const headline = e.alerts > 0
    ? `${plural(e.alerts, 'observed alert', 'observed alerts')}${e.incidents > 0 ? `, ${plural(e.incidents, 'incident', 'incidents')}` : ''}`
    : conclusive
      ? 'No alert was raised for any event in this run'
      : '0 observed alerts';

  const caveat = conclusive
    ? null
    : e.accepted === 0
      ? 'No event was accepted, so there was nothing to observe.'
      : observedCount === 0
        ? `None of the ${e.accepted} accepted events were observed before polling stopped, so this run says nothing about detection.`
        : `Only ${observedCount} of ${e.accepted} accepted events were observed before polling stopped${e.alerts === 0 ? ' - a result of 0 is incomplete, not a clean run' : ''}.`;

  return {
    alerts: e.alerts,
    incidents: e.incidents,
    observation: e.observation,
    observedCount,
    acceptedCount: e.accepted,
    conclusive,
    headline,
    caveat,
  };
}

/**
 * The observed side of a stored run, in the shape a demo assessment reads. Pure projection: it
 * copies recorded values and derives nothing, so a historical demo is assessed from what was seen at
 * the time against the preset's expectation as it stands now.
 */
export function observedFromEntry(e: RunHistoryEntry): ObservedRun {
  return {
    accepted: e.accepted,
    observedTerminal: observedTerminal(e),
    observation: e.observation,
    alerts: e.alerts,
    incidents: e.incidents,
    peakScore: e.peakScore,
    severity: { ...e.severity },
    detectors: { ...e.detectors },
  };
}

/* ------------------------------------------------------------------ filtering (pure) */

export type HistoryFilter = 'ALL' | 'COMPLETED' | 'STOPPED' | 'DURATION' | 'FAILED';

/** Client-side only: history never leaves the browser, so a filter can never cost a request. */
export function filterHistory(entries: RunHistoryEntry[], filter: HistoryFilter, scenarioId = 'ALL'): RunHistoryEntry[] {
  return entries.filter((e) => (filter === 'ALL' || e.outcome === filter) && (scenarioId === 'ALL' || e.scenarioId === scenarioId));
}

/* ------------------------------------------------------------------ persistence */

/** The slice of the Storage API this store uses, so tests can hand it a fake one. */
export type StorageLike = {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
};

type Envelope = { version: number; entries: unknown };

export type HistorySnapshot = {
  /** Newest run first. */
  entries: RunHistoryEntry[];
  /** Set when persistence is unavailable or a write failed; history then lives in memory only. */
  storageError: string | null;
  /** Whether the initial read has happened. */
  loaded: boolean;
};

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const numberOr = (v: unknown, fallback: number) => (typeof v === 'number' && Number.isFinite(v) ? v : fallback);
const stringOr = (v: unknown, fallback: string) => (typeof v === 'string' ? v : fallback);
const tally = (v: unknown): Record<string, number> => {
  if (!isObject(v)) return {};
  const out: Record<string, number> = {};
  for (const [k, n] of Object.entries(v)) if (typeof n === 'number' && Number.isFinite(n)) out[k] = n;
  return out;
};

const DETECTION_TYPES: DetectionType[] = ['RULE', 'ML', 'RULE_AND_ML', 'CONTROL', 'COVERAGE_GAP'];

/** Demo metadata, or null. Three known fields; anything else in the stored object is dropped. */
const reviveDemo = (raw: unknown): DemoRunMeta | null => {
  if (!isObject(raw)) return null;
  if (typeof raw.demoId !== 'string' || !raw.demoId) return null;
  if (!DETECTION_TYPES.includes(raw.detectionType as DetectionType)) return null;
  return {
    demoId: raw.demoId,
    demoName: stringOr(raw.demoName, raw.demoId),
    detectionType: raw.detectionType as DetectionType,
  };
};

const OUTCOMES: RunOutcome[] = ['COMPLETED', 'STOPPED', 'DURATION', 'FAILED'];
const QUALITIES: ObservationQuality[] = ['COMPLETE', 'PARTIAL', 'NONE'];

/**
 * Rebuild one entry from whatever was in storage, or return null. Field by field rather than a cast:
 * a hand-edited, truncated or half-migrated record must never reach the UI as a half-typed object.
 */
export function reviveEntry(raw: unknown): RunHistoryEntry | null {
  if (!isObject(raw)) return null;
  const runId = raw.runId;
  if (typeof runId !== 'string' || !runId) return null;
  const outcome = OUTCOMES.includes(raw.outcome as RunOutcome) ? (raw.outcome as RunOutcome) : null;
  if (!outcome) return null;
  const config = raw.config;
  if (!isObject(config) || typeof config.scenarioId !== 'string') return null;

  const accepted = numberOr(raw.accepted, 0);
  const processed = numberOr(raw.processed, 0);
  const processingFailed = numberOr(raw.processingFailed, 0);

  return {
    runId,
    createdAt: numberOr(raw.createdAt, 0),
    completedAt: numberOr(raw.completedAt, numberOr(raw.createdAt, 0)),
    outcome,
    reason: typeof raw.reason === 'string' ? raw.reason : null,

    scenarioId: stringOr(raw.scenarioId, String(config.scenarioId)),
    scenarioName: stringOr(raw.scenarioName, stringOr(raw.scenarioId, 'Unknown scenario')),
    detection: stringOr(raw.detection, 'unknown'),

    config: {
      scenarioId: String(config.scenarioId),
      targetMode: stringOr(config.targetMode, 'SINGLE') as TargetMode,
      entityId: stringOr(config.entityId, ''),
      entityIds: Array.isArray(config.entityIds) ? config.entityIds.filter((x): x is string => typeof x === 'string') : [],
      eventRate: numberOr(config.eventRate, 2),
      duration: typeof config.duration === 'number' || config.duration === 'CUSTOM' ? config.duration : 30,
      customDurationSec: stringOr(config.customDurationSec, ''),
      intensity: stringOr(config.intensity, 'MEDIUM') as Intensity,
      noisePercent: numberOr(config.noisePercent, 0) as NoisePercent,
      pattern: stringOr(config.pattern, 'SEQUENTIAL') as AttackPattern,
    },
    targets: Array.isArray(raw.targets) ? raw.targets.filter((x): x is string => typeof x === 'string') : [],
    targetMode: stringOr(raw.targetMode, stringOr(config.targetMode, 'SINGLE')) as TargetMode,
    intensity: stringOr(raw.intensity, stringOr(config.intensity, 'MEDIUM')) as Intensity,
    pattern: stringOr(raw.pattern, stringOr(config.pattern, 'SEQUENTIAL')) as AttackPattern,
    noisePercent: numberOr(raw.noisePercent, numberOr(config.noisePercent, 0)) as NoisePercent,
    configuredRate: numberOr(raw.configuredRate, numberOr(config.eventRate, 2)),
    maxDurationMs: typeof raw.maxDurationMs === 'number' && Number.isFinite(raw.maxDurationMs) ? raw.maxDurationMs : null,

    durationMs: numberOr(raw.durationMs, 0),
    actualRate: typeof raw.actualRate === 'number' && Number.isFinite(raw.actualRate) ? raw.actualRate : null,
    totalEvents: numberOr(raw.totalEvents, 0),
    generated: numberOr(raw.generated, 0),
    accepted,
    failed: numberOr(raw.failed, 0),

    observed: numberOr(raw.observed, 0),
    processed,
    processingFailed,
    unobserved: numberOr(raw.unobserved, 0),
    alerts: numberOr(raw.alerts, 0),
    incidents: numberOr(raw.incidents, 0),
    peakScore: typeof raw.peakScore === 'number' && Number.isFinite(raw.peakScore) ? raw.peakScore : null,
    severity: tally(raw.severity),
    detectors: tally(raw.detectors),

    // A record written before demo mode existed simply has no demo, which is not an error: the field
    // is additive, so HISTORY_VERSION stays at 1 and existing history is kept rather than discarded.
    demo: reviveDemo(raw.demo),
    droppedRows: numberOr(raw.droppedRows, 0),
    // A stored quality is trusted only if it is one of ours; otherwise it is recomputed.
    observation: QUALITIES.includes(raw.observation as ObservationQuality)
      ? (raw.observation as ObservationQuality)
      : observationQuality(accepted, processed, processingFailed),
    observationWindowMs: numberOr(raw.observationWindowMs, TRAIL_OBSERVATION_MS),
  };
}

/** Parse a stored payload into entries. Anything unreadable recovers to an empty history. */
export function parseHistory(raw: string | null): RunHistoryEntry[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return []; // malformed JSON: start over rather than crash the console
  }
  if (!isObject(parsed)) return [];
  const envelope = parsed as unknown as Envelope;
  // A payload from a different schema version is not guessed at - it is ignored, and the next write
  // replaces it. There is nothing here worth a risky migration: it is a local convenience record.
  if (envelope.version !== HISTORY_VERSION) return [];
  if (!Array.isArray(envelope.entries)) return [];
  const out: RunHistoryEntry[] = [];
  // One bad record does not discard the rest.
  for (const item of envelope.entries) {
    const entry = reviveEntry(item);
    if (entry) out.push(entry);
  }
  return sortNewestFirst(out).slice(0, MAX_HISTORY_ENTRIES);
}

/** Newest completion first. Done once on load and once per mutation, never per render. */
export const sortNewestFirst = (entries: RunHistoryEntry[]): RunHistoryEntry[] =>
  [...entries].sort((a, b) => b.completedAt - a.completedAt || b.createdAt - a.createdAt);

export const serializeHistory = (entries: RunHistoryEntry[]): string =>
  JSON.stringify({ version: HISTORY_VERSION, entries });

/**
 * The history store. Mutations update memory first and then try to persist, so a storage failure
 * degrades to an in-memory session rather than losing the operation the user just asked for.
 */
export class RunHistoryStore {
  private storage: StorageLike | null;
  private entries: RunHistoryEntry[] = [];
  private storageError: string | null = null;
  private loaded = false;
  private listeners = new Set<() => void>();
  private snapshot: HistorySnapshot;

  constructor(storage: StorageLike | null) {
    this.storage = storage;
    if (!storage) this.storageError = 'This browser does not allow local storage, so run history is kept for this session only.';
    this.snapshot = this.build();
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /** Stable between changes (safe for useSyncExternalStore). */
  getSnapshot = (): HistorySnapshot => this.snapshot;

  /** Read storage once. Repeat calls are no-ops, so mounting the page again costs nothing. */
  load(force = false): RunHistoryEntry[] {
    if (this.loaded && !force) return this.entries;
    this.loaded = true;
    if (this.storage) {
      try {
        this.entries = parseHistory(this.storage.getItem(HISTORY_KEY));
      } catch (e) {
        // getItem itself can throw when storage is blocked by policy.
        this.entries = [];
        this.storageError = `Run history could not be read (${message(e)}); it is kept for this session only.`;
      }
    }
    this.emit();
    return this.entries;
  }

  list(): RunHistoryEntry[] {
    return this.load();
  }

  /**
   * Record one finished run. A run id already present is REPLACED, never duplicated, so saving the
   * same run again as late observations arrive updates it in place.
   */
  add(entry: RunHistoryEntry): void {
    this.load();
    const without = this.entries.filter((e) => e.runId !== entry.runId);
    // Oldest out first once the cap is reached.
    this.entries = sortNewestFirst([entry, ...without]).slice(0, MAX_HISTORY_ENTRIES);
    this.persist();
    this.emit();
  }

  remove(runId: string): void {
    this.load();
    const next = this.entries.filter((e) => e.runId !== runId);
    if (next.length === this.entries.length) return;
    this.entries = next;
    this.persist();
    this.emit();
  }

  /** Clears the LOCAL record only. Events already submitted, and everything the backend stored for
   *  them, are untouched - this store has no way to reach them. */
  clear(): void {
    this.load();
    this.entries = [];
    if (this.storage) {
      try {
        this.storage.removeItem(HISTORY_KEY);
        this.storageError = null;
      } catch (e) {
        this.storageError = `Run history could not be cleared from local storage (${message(e)}).`;
      }
    }
    this.emit();
  }

  get(runId: string): RunHistoryEntry | undefined {
    return this.load().find((e) => e.runId === runId);
  }

  private persist() {
    if (!this.storage) return;
    try {
      this.storage.setItem(HISTORY_KEY, serializeHistory(this.entries));
      this.storageError = null;
    } catch (e) {
      // A full quota or a denied write must never lose the entry the caller just added: it stays in
      // memory for this session and the console says so.
      this.storageError = `Run history could not be saved (${message(e)}); it is kept for this session only.`;
    }
  }

  private emit() {
    this.snapshot = this.build();
    for (const l of [...this.listeners]) l();
  }

  private build(): HistorySnapshot {
    return { entries: this.entries, storageError: this.storageError, loaded: this.loaded };
  }
}

const message = (e: unknown) => (e instanceof Error && e.message ? e.message : 'unknown error');
