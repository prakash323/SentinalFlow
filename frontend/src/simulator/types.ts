/*
 * Simulator - shared types and limits.
 *
 * src/simulator/*.ts is framework-free (no React, no axios) so scripts/simulator-check.mts can run it
 * directly with Node's type stripping: string-literal unions only, no TS enums or namespaces.
 */
import type { CreateEventRequest } from '../types/domain';

/** What a scenario builder receives: the target entity, an event-ID prefix and the time anchor. */
export type ScenarioContext = { entityId: string; prefix: string; now: number };

export type ScenarioCategory = 'BASELINE' | 'IDENTITY' | 'ENDPOINT' | 'NETWORK' | 'DATA' | 'CHAIN';

/**
 * Detection the CURRENT backend actually provides for a scenario.
 *  rules  deterministic rules the events satisfy by construction (they still may be suppressed
 *         while an earlier alert from the same rule is active)
 *  ml     only the ML score can raise an alert - score-dependent, never guaranteed
 *  none   a control: no alert is expected
 */
export type DetectorInfo = { rules: string[]; ml: boolean; note: string };

/* ------------------------------------------------------------------ Phase 3 configuration */

export type Intensity = 'LOW' | 'MEDIUM' | 'HIGH';

/**
 * How many entities a run touches, and how.
 *  SINGLE       one chosen entity
 *  RANDOM       one entity picked from the available list (deterministically, from the run ID)
 *  MULTI        the full scenario replayed on each selected entity
 *  DISTRIBUTED  one campaign split across the selected entities (see GroupMode / splittable)
 */
export type TargetMode = 'SINGLE' | 'RANDOM' | 'MULTI' | 'DISTRIBUTED';

/**
 * Simulator PLANNING modes - never transport. HTTP submission is always strictly sequential
 * (the Phase 2 engine keeps one POST in flight); a pattern only decides how the run's segments are
 * placed in time and in what order the plan lists them.
 *  SEQUENTIAL   segments back-to-back, no overlap in time
 *  BURST        every segment anchored to the same instant: maximum overlap, one tight window
 *  PROGRESSIVE  back-to-back with gaps that halve toward the end: a slow build into a climax
 *  DISTRIBUTED  segments staggered by a fixed stride and the plan interleaved round-robin, so
 *               consecutive submissions alternate between entities
 */
export type AttackPattern = 'SEQUENTIAL' | 'BURST' | 'PROGRESSIVE' | 'DISTRIBUTED';

export type NoisePercent = 0 | 10 | 20 | 30;

/**
 * The smallest set of consecutive events that must stay on ONE entity, which is what DISTRIBUTED
 * targets hand out round-robin.
 *  ALL   the whole scenario is one indivisible behavioural story
 *  PAIR  consecutive pairs (a PROCESS_START and the NETWORK_CONNECTION that correlates to it)
 *  EACH  every event stands alone
 */
export type GroupMode = 'ALL' | 'PAIR' | 'EACH';

/** `15 | 30 | 60` seconds, or a free-text custom value. */
export type DurationChoice = number | 'CUSTOM';

/** Everything the console's configuration panel decides. One run is built from exactly one of these. */
export type SimulatorConfig = {
  scenarioId: string;
  targetMode: TargetMode;
  /** The chosen entity for SINGLE. */
  entityId: string;
  /** The chosen entities for MULTI and DISTRIBUTED. */
  entityIds: string[];
  eventRate: number;
  duration: DurationChoice;
  /** Raw custom-duration input, in seconds, exactly as typed. */
  customDurationSec: string;
  intensity: Intensity;
  noisePercent: NoisePercent;
  pattern: AttackPattern;
};

/**
 * How much of a run's pipeline outcome was actually seen. Trail polling is bounded, so a run can
 * finish with events whose outcome was never read - and "nothing was detected" must stay
 * distinguishable from "nothing was looked at".
 *  COMPLETE  every accepted event reached a terminal processing state on its trail
 *  PARTIAL   some did; the rest were never answered before polling stopped
 *  NONE      nothing was observed at all (or nothing was accepted)
 */
export type ObservationQuality = 'COMPLETE' | 'PARTIAL' | 'NONE';

/* ------------------------------------------------------------------ alert policy (read-only mirror) */

/*
 * The backend's own alert policy, mirrored here so the console can SAY what the bar is without
 * guessing - see backend application.yml `alert-policy` and utils/tone.ts scoreTone, which already
 * encode the same bands. Nothing here changes a threshold; these values are for display only.
 *
 * anomalyScore is a PERCENTILE RANK against the model's training distribution (ml-service
 * src/detect.py Detector.to_risk_100), NOT a calibrated probability: the model runs hot and
 * behaviourally normal events commonly land at 0.95-0.99. It must never be shown as a percentage
 * chance of attack.
 */
export const ALERT_THRESHOLD = 0.99;
export const SEVERITY_BANDS: { severity: string; from: number }[] = [
  { severity: 'CRITICAL', from: 0.999 },
  { severity: 'HIGH', from: 0.995 },
  { severity: 'MEDIUM', from: 0.99 },
];

/** What a Phase 3 builder receives. The Phase 1/2 builders ignore the extra field. */
export type PlanContext = ScenarioContext & { intensity: Intensity };

export type ScenarioDef = {
  id: string;
  name: string;
  description: string;
  category: ScenarioCategory;
  /** What the scenario exercises (the card's "Exercises" line). */
  exercises: string;
  detector: DetectorInfo;
  phases: string[];
  /** Does the intensity setting change the generated sequence? The original six do not. */
  scales: boolean;
  /** Can DISTRIBUTED targets split this scenario across entities, or must it be replicated? */
  splittable: boolean;
  /** How the event list partitions for DISTRIBUTED targets. */
  groupMode: GroupMode;
  /** Honest coverage gaps and caveats - never a detection promise the backend does not make. */
  limitations: string[];
  build: (c: PlanContext) => CreateEventRequest[];
};

export type Issue = { level: 'error' | 'warning'; message: string; eventId?: string };

/* ------------------------------------------------------------------ run engine */

export type RunState = 'IDLE' | 'RUNNING' | 'PAUSED' | 'STOPPING' | 'COMPLETED' | 'STOPPED' | 'FAILED';

/** What the engine runs. runId is the event-ID prefix every event of the run already carries. */
export type RunPlan = { runId: string; label: string; events: CreateEventRequest[] };

export type RunOptions = {
  /** Events per second; clamped to [MIN_EVENT_RATE, MAX_EVENT_RATE]. */
  eventRate: number;
  /** Wall-clock cap from start (pauses included); null = none. */
  maxDurationMs?: number | null;
};

export type SendError = { status?: number; code?: string; message: string; systemic: boolean };

/** One submission. Payloads are not kept; processing status comes from the trail API, not from here. */
export type EventResult = {
  index: number;
  eventId: string;
  eventType: string;
  entityId: string;
  occurredAt: string;
  status: 'SUBMITTED' | 'ACCEPTED' | 'FAILED';
  submittedAt: number;
  settledAt?: number;
  error?: SendError;
};

export type RunSnapshot = {
  runId: string | null;
  label: string | null;
  state: RunState;
  /** Why a STOPPED run stopped. */
  stopReason: 'USER' | 'DURATION' | null;
  /** Why a FAILED run failed. */
  failureReason: string | null;
  totalEvents: number;
  /** Index of the next event to submit. */
  nextEventIndex: number;
  /** Index of the event in flight, or -1. */
  currentEventIndex: number;
  /** Events handed to the transport (accepted + failed + in flight). */
  generated: number;
  accepted: number;
  failed: number;
  startedAt: number | null;
  finishedAt: number | null;
  eventRate: number;
  maxDurationMs: number | null;
  results: EventResult[];
};

export const MIN_EVENT_RATE = 0.5;
export const MAX_EVENT_RATE = 5;
export const DEFAULT_EVENT_RATE = 2;
/** Consecutive systemic failures (network, 5xx, 429) that end a run as FAILED. */
export const SYSTEMIC_FAILURE_LIMIT = 3;

/** The backend's own limit on one serialised event (EventKafkaProducer.MAX_EVENT_BYTES). */
export const MAX_EVENT_BYTES = 512 * 1024;
/** events.event_id / event_type / source are VARCHAR(128) (V2__create_events.sql). */
export const MAX_ID_LENGTH = 128;
/** Tolerance for "occurredAt is not in the future" (build time vs. validation time). */
export const FUTURE_SKEW_MS = 2000;
/** processCreateTime must equal PROCESS_START.occurredAt in this exact form (DeterministicRuleService.formatOccurredAt). */
export const PROCESS_CREATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/* ------------------------------------------------------------------ Phase 3 limits */

/** The only rates the console offers; MAX_EVENT_RATE is the engine's own hard cap. */
export const RATE_OPTIONS: number[] = [1, DEFAULT_EVENT_RATE, MAX_EVENT_RATE];
/** Duration presets, in seconds. */
export const DURATION_PRESETS: number[] = [15, 30, 60];
export const DEFAULT_DURATION_SEC = 30;
export const MIN_CUSTOM_DURATION_SEC = 5;
export const MAX_CUSTOM_DURATION_SEC = 600;
export const NOISE_OPTIONS: NoisePercent[] = [0, 10, 20, 30];
export const INTENSITIES: Intensity[] = ['LOW', 'MEDIUM', 'HIGH'];
export const PATTERNS: AttackPattern[] = ['SEQUENTIAL', 'BURST', 'PROGRESSIVE', 'DISTRIBUTED'];
/** Entities one run may touch at once (keeps a plan reviewable). */
export const MAX_TARGETS = 6;

/** Seconds of dead air the SEQUENTIAL pattern leaves between two segments. */
export const SEGMENT_GAP_SEC = 10;
/** PROGRESSIVE's smallest (last) gap; every earlier gap doubles it. */
export const PROGRESSIVE_BASE_GAP_SEC = 8;
/** DISTRIBUTED's fixed per-segment stagger. */
export const DISTRIBUTED_STRIDE_SEC = 20;

/** Above this many events - or with more than one target - Start asks for a confirmation first. */
export const CONFIRM_EVENT_THRESHOLD = 12;

/** Failed LOGINs inside RULE_WINDOW_MINUTES that make AUTH_BURST fire (DeterministicRuleService). */
export const AUTH_BURST_THRESHOLD = 5;
/** Failures at or above which AUTH_BURST raises HIGH rather than MEDIUM. */
export const AUTH_BURST_HIGH_THRESHOLD = 10;
/** AUTH_BURST's window, and NEW_PROCESS_EXTERNAL_CONNECTION's recency bound. */
export const RULE_WINDOW_MINUTES = 5;

/* ------------------------------------------------------------------ Phase 4 live console */

/** Rows the live console SHOWS at once (the newest of the filtered set). */
export const LIVE_ROW_LIMIT = 100;
/** Rows the store RETAINS at most; older rows are dropped, cumulative counters are not. */
export const LIVE_ROW_HARD_LIMIT = 250;
/** Entries the recent-activity feed keeps. */
export const ACTIVITY_LIMIT = 60;
/** Submission timestamps kept to compute the actual (recent) events/sec. */
export const RATE_WINDOW_SAMPLES = 20;

/** One shared trail-polling tick for the whole console - never one timer per event. */
export const TRAIL_POLL_INTERVAL_MS = 1500;
/** Trail requests one tick may have in flight at once. */
export const TRAIL_POLL_BATCH = 6;
/** Trail polls one event may cost before the console gives up on observing it. */
export const TRAIL_MAX_ATTEMPTS = 20;
/** How long after a run finishes the console keeps observing its events. */
export const TRAIL_OBSERVATION_MS = 90_000;
/** Incident lookups one tick may start (incident status is not on the trail). */
export const INCIDENT_FETCH_PER_TICK = 2;
/** Hard ceiling on the distinct alert/incident ids held for de-duplication. */
export const OBSERVED_ID_LIMIT = 2000;
