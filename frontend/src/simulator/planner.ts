/*
 * Simulator planner: turns a console configuration into the exact RunPlan the Phase 2 engine will
 * submit, plus everything the Preview / Confirm steps display.
 *
 * Pure and framework-free. It imports no transport of any kind - building or previewing a plan can
 * never reach the backend, Kafka or the database. The page hands the SAME object this returns to
 * runEngine.start(), so a preview shows the events that are actually submitted, not an estimate.
 *
 * Mechanics
 * ---------
 * A plan is a list of SEGMENTS. A segment is one scenario (or one block of benign noise) built for
 * one entity, with its own event-ID prefix and its own time anchor. Because every builder's last
 * event sits at offset 0, a segment is placed in time by moving its `now` alone - which keeps
 * everything derived from a timestamp consistent, including a NETWORK_CONNECTION's processCreateTime
 * string. Shifts are always <= 0, so no generated event is ever in the future.
 *
 * A single-target run with no noise produces ONE segment at shift 0 and prefix = runId, which is
 * byte-for-byte the plan Phase 2 produced for the same scenario (the self-check asserts this).
 *
 * Attack patterns are segment PLACEMENT and plan ORDER only. Transport stays strictly sequential:
 * the engine keeps one POST in flight and follows the plan's order, which is what makes the
 * database-backed rules (AUTH_BURST, NEW_PROCESS_EXTERNAL_CONNECTION) correlate at all.
 */
import type { CreateEventRequest } from '../types/domain';
import { buildNoise, noiseCount } from './advancedBuilders.ts';
import { eventGroups, scenarioById } from './scenarioRegistry.ts';
import {
  CONFIRM_EVENT_THRESHOLD,
  DISTRIBUTED_STRIDE_SEC,
  DURATION_PRESETS,
  INTENSITIES,
  MAX_CUSTOM_DURATION_SEC,
  MAX_EVENT_RATE,
  MAX_TARGETS,
  MIN_CUSTOM_DURATION_SEC,
  NOISE_OPTIONS,
  PATTERNS,
  PROGRESSIVE_BASE_GAP_SEC,
  RATE_OPTIONS,
  SEGMENT_GAP_SEC,
} from './types.ts';
import type {
  AttackPattern,
  Intensity,
  Issue,
  SimulatorConfig,
  NoisePercent,
  PlanContext,
  RunPlan,
  ScenarioDef,
  TargetMode,
} from './types.ts';
import { validateEvents } from './validation.ts';
import type { PlanSegmentInfo, RunPlanInfo } from './liveConsole.ts';
import type { DemoRunMeta } from './demoPresets.ts';

// The configuration shape lives in types.ts, next to the limits it has to respect, so the live
// console can keep a verbatim snapshot of it without importing the planner.
export type { DurationChoice, SimulatorConfig } from './types.ts';

export type PlanSegment = {
  kind: 'SCENARIO' | 'NOISE';
  entityId: string;
  prefix: string;
  /** Seconds this segment was moved into the past (<= 0). */
  shiftSec: number;
  events: CreateEventRequest[];
};

export type PlanPreview = {
  runId: string;
  label: string;
  scenario: ScenarioDef | null;
  config: SimulatorConfig;
  /** Entities the plan actually touches, in plan order of first appearance. */
  targets: string[];
  segments: PlanSegment[];
  /** The exact events a Start would submit, in submission order. */
  events: CreateEventRequest[];
  eventCount: number;
  scenarioEventCount: number;
  noiseEventCount: number;
  eventTypes: { type: string; count: number }[];
  distribution: { entityId: string; count: number }[];
  /** Seconds between the earliest and latest generated occurredAt. */
  spanSec: number;
  /** The resolved duration cap in ms, or null when the custom value is unusable. */
  maxDurationMs: number | null;
  /** Wall-clock time the engine needs to submit every event at this rate. */
  estimatedDurationMs: number;
  /** Events the duration cap allows the engine to submit, when that is fewer than all of them. */
  plannedSends: number;
  configIssues: Issue[];
  eventIssues: Issue[];
  /** Everything blocking or worth knowing, config issues first. */
  issues: Issue[];
  /** Honest planning and coverage notes for the preview and the confirmation. */
  notes: string[];
};

/* ------------------------------------------------------------------ defaults */

export const DEFAULT_CONFIG: SimulatorConfig = {
  scenarioId: 'routine',
  targetMode: 'SINGLE',
  entityId: '',
  entityIds: [],
  eventRate: RATE_OPTIONS[1],
  duration: DURATION_PRESETS[1],
  customDurationSec: '',
  intensity: 'MEDIUM',
  noisePercent: 0,
  pattern: 'SEQUENTIAL',
};

/** A run ID that is also the event-ID prefix of every event in the run. */
export const newRunId = (scenarioId: string, at = Date.now()): string =>
  `SIM-${scenarioId.toUpperCase()}-${at.toString(36).toUpperCase()}`;

/* ------------------------------------------------------------------ duration */

/** The duration cap in ms, or null when a custom value is missing or out of range. */
export function resolveDurationMs(config: SimulatorConfig): number | null {
  if (config.duration !== 'CUSTOM') return config.duration * 1000;
  const raw = config.customDurationSec.trim();
  if (!/^\d+$/.test(raw)) return null;
  const seconds = Number(raw);
  if (seconds < MIN_CUSTOM_DURATION_SEC || seconds > MAX_CUSTOM_DURATION_SEC) return null;
  return seconds * 1000;
}

/**
 * Events the engine gets to submit inside a duration cap. It sends event k at k * interval and the
 * cap fires at exactly maxDurationMs, before a send scheduled for that same instant.
 */
export const sendsWithin = (events: number, eventRate: number, maxDurationMs: number | null): number => {
  if (maxDurationMs === null || maxDurationMs <= 0) return events;
  return Math.max(0, Math.min(events, Math.ceil(maxDurationMs / (1000 / eventRate))));
};

/* ------------------------------------------------------------------ configuration validation */

const err = (message: string): Issue => ({ level: 'error', message });

/** Everything that must hold before a run may start. Errors block Start; warnings never do. */
export function validateConfig(config: SimulatorConfig, available: string[]): Issue[] {
  const issues: Issue[] = [];
  const scenario = scenarioById(config.scenarioId);

  if (!scenario) issues.push(err(`Unknown scenario "${config.scenarioId}".`));

  if (!available.length) {
    issues.push(err('No monitored entity is available. Events must belong to an entity that already exists.'));
  }

  const chosen = config.entityIds.filter((id) => available.includes(id));
  if (config.targetMode === 'SINGLE') {
    if (!config.entityId) issues.push(err('Choose a target entity.'));
    else if (available.length && !available.includes(config.entityId)) issues.push(err(`"${config.entityId}" is not one of the monitored entities.`));
  } else if (config.targetMode === 'MULTI' || config.targetMode === 'DISTRIBUTED') {
    if (chosen.length < 2) issues.push(err(`${config.targetMode === 'MULTI' ? 'Multiple' : 'Distributed'} targets need at least two monitored entities selected.`));
    if (chosen.length > MAX_TARGETS) issues.push(err(`At most ${MAX_TARGETS} entities can be targeted in one run (${chosen.length} selected).`));
  }

  if (!RATE_OPTIONS.includes(config.eventRate)) {
    issues.push(err(`Event rate must be one of ${RATE_OPTIONS.join(', ')} events/sec.`));
  }
  if (config.eventRate > MAX_EVENT_RATE) {
    issues.push(err(`The event rate cannot exceed ${MAX_EVENT_RATE} events/sec.`));
  }

  if (config.duration === 'CUSTOM' && resolveDurationMs(config) === null) {
    const raw = config.customDurationSec.trim();
    issues.push(err(
      raw === ''
        ? `Enter a custom duration in whole seconds (${MIN_CUSTOM_DURATION_SEC}-${MAX_CUSTOM_DURATION_SEC}).`
        : `"${raw}" is not a usable duration: enter whole seconds between ${MIN_CUSTOM_DURATION_SEC} and ${MAX_CUSTOM_DURATION_SEC}.`,
    ));
  }

  if (!NOISE_OPTIONS.includes(config.noisePercent)) issues.push(err(`Benign noise must be one of ${NOISE_OPTIONS.map((n) => `${n}%`).join(', ')}.`));
  if (!INTENSITIES.includes(config.intensity)) issues.push(err(`Unknown intensity "${config.intensity}".`));
  if (!PATTERNS.includes(config.pattern)) issues.push(err(`Unknown attack pattern "${config.pattern}".`));

  return issues;
}

/* ------------------------------------------------------------------ targets */

/** Stable, non-cryptographic hash, so RANDOM is reproducible from a run ID. */
const hash = (s: string): number => {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
};

/** Which entities a configuration touches. RANDOM derives its pick from the run ID, not Math.random. */
export function resolveTargets(config: SimulatorConfig, available: string[], runId: string): string[] {
  const dedupe = (ids: string[]) => [...new Set(ids)];
  if (config.targetMode === 'SINGLE') return config.entityId ? [config.entityId] : [];
  if (config.targetMode === 'RANDOM') return available.length ? [available[hash(runId) % available.length]] : [];
  const chosen = dedupe(config.entityIds.filter((id) => available.includes(id)));
  // Keep the console's own order so a plan reads the way the list does.
  const ordered = available.filter((id) => chosen.includes(id));
  return ordered.slice(0, MAX_TARGETS);
}

/* ------------------------------------------------------------------ pattern placement */

/**
 * Seconds to move each segment into the past, given each segment's span. The last segment always
 * ends at `now` (shift 0); every other shift is negative.
 */
export function segmentShifts(spans: number[], pattern: AttackPattern): number[] {
  const n = spans.length;
  const shifts = new Array<number>(n).fill(0);
  if (n <= 1) return shifts;

  if (pattern === 'BURST') return shifts; // one instant, maximum overlap
  if (pattern === 'DISTRIBUTED') {
    for (let i = 0; i < n; i++) shifts[i] = -(n - 1 - i) * DISTRIBUTED_STRIDE_SEC || 0;
    return shifts;
  }
  // SEQUENTIAL and PROGRESSIVE: back-to-back. PROGRESSIVE's gaps halve toward the end.
  for (let i = n - 2; i >= 0; i--) {
    const gap = pattern === 'PROGRESSIVE' ? PROGRESSIVE_BASE_GAP_SEC * 2 ** (n - 2 - i) : SEGMENT_GAP_SEC;
    shifts[i] = shifts[i + 1] - spans[i + 1] - gap;
  }
  return shifts;
}

const spanOf = (events: CreateEventRequest[]): number => {
  if (!events.length) return 0;
  const t = events.map((e) => Date.parse(e.occurredAt));
  return Math.round((Math.max(...t) - Math.min(...t)) / 1000);
};

/** Round-robin interleave: one event from each segment in turn, each segment's order preserved. */
const interleave = (lists: CreateEventRequest[][]): CreateEventRequest[] => {
  const out: CreateEventRequest[] = [];
  const longest = Math.max(0, ...lists.map((l) => l.length));
  for (let i = 0; i < longest; i++) for (const l of lists) if (i < l.length) out.push(l[i]);
  return out;
};

/** Stable sort by occurredAt; equal timestamps keep the incoming order. */
const byTime = (events: CreateEventRequest[]): CreateEventRequest[] =>
  events
    .map((e, i) => ({ e, i, t: Date.parse(e.occurredAt) }))
    .sort((a, b) => a.t - b.t || a.i - b.i)
    .map((x) => x.e);

/* ------------------------------------------------------------------ plan assembly */

/** Prefix for scenario segment `i` of `total`. A single target keeps the Phase 2 prefix exactly. */
const scenarioPrefix = (runId: string, i: number, total: number) => (total === 1 ? runId : `${runId}-T${i + 1}`);
const noisePrefix = (runId: string, i: number) => `${runId}-Z${i + 1}`;

/** The slice of a scenario's events entity `ei` of `total` keeps when DISTRIBUTED splits groups. */
const keptIndices = (scenario: ScenarioDef, count: number, ei: number, total: number): Set<number> => {
  const groups = eventGroups(scenario, count);
  const keep = new Set<number>();
  groups.forEach((g, gi) => {
    if (gi % total === ei) for (const i of g) keep.add(i);
  });
  return keep;
};

/**
 * Build the plan a configuration describes, and everything the Preview and Confirm steps show.
 * `now` is the time anchor; `available` is the entity list the console offers.
 */
export function buildPreview(
  config: SimulatorConfig,
  opts: { runId: string; now: number; available: string[] },
): PlanPreview {
  const { runId, now, available } = opts;
  const scenario = scenarioById(config.scenarioId) ?? null;
  const configIssues = validateConfig(config, available);
  const targets = resolveTargets(config, available, runId);
  const notes: string[] = [];
  const maxDurationMs = resolveDurationMs(config);

  const empty: PlanPreview = {
    runId,
    label: scenario?.name ?? config.scenarioId,
    scenario,
    config,
    targets,
    segments: [],
    events: [],
    eventCount: 0,
    scenarioEventCount: 0,
    noiseEventCount: 0,
    eventTypes: [],
    distribution: [],
    spanSec: 0,
    maxDurationMs,
    estimatedDurationMs: 0,
    plannedSends: 0,
    configIssues,
    eventIssues: [],
    issues: configIssues,
    notes,
  };
  if (!scenario || !targets.length) return empty;

  const ctx = (entityId: string, prefix: string, at: number): PlanContext => ({ entityId, prefix, now: at, intensity: config.intensity });

  // DISTRIBUTED targets split one campaign across the entities - but only for a scenario whose
  // event groups can be separated without breaking what the backend correlates.
  const split = config.targetMode === 'DISTRIBUTED' && targets.length > 1 && scenario.splittable;
  if (config.targetMode === 'DISTRIBUTED' && targets.length > 1 && !scenario.splittable) {
    notes.push(`${scenario.name} is one indivisible behavioural sequence, so Distributed targets replicate it on each of the ${targets.length} entities instead of splitting it.`);
  }
  if (split) {
    notes.push(`Distributed targets: the scenario's ${scenario.groupMode === 'EACH' ? 'events' : 'event pairs'} are handed out round-robin, so no single entity receives the whole sequence.`);
  }

  /* 1. build every segment at shift 0, to measure its span */
  type Draft = { kind: PlanSegment['kind']; entityId: string; prefix: string; events: CreateEventRequest[] };
  const draftScenario = (entityId: string, i: number, at: number): Draft => {
    const prefix = scenarioPrefix(runId, i, targets.length);
    const all = scenario.build(ctx(entityId, prefix, at));
    if (!split) return { kind: 'SCENARIO', entityId, prefix, events: all };
    const keep = keptIndices(scenario, all.length, i, targets.length);
    return { kind: 'SCENARIO', entityId, prefix, events: all.filter((_, idx) => keep.has(idx)) };
  };

  const perTarget = scenario.build(ctx(targets[0], runId, now)).length;
  // A noise percentage is relative to the whole run's scenario volume, not to one target's share.
  const noiseTotal = noiseCount(split ? perTarget : perTarget * targets.length, config.noisePercent);
  const noisePerTarget = targets.map((_, i) => Math.floor(noiseTotal / targets.length) + (i < noiseTotal % targets.length ? 1 : 0));

  const draftNoise = (entityId: string, i: number, at: number): Draft => ({
    kind: 'NOISE',
    entityId,
    prefix: noisePrefix(runId, i),
    events: buildNoise(ctx(entityId, noisePrefix(runId, i), at), noisePerTarget[i]),
  });

  // Benign noise is planned as baseline activity ahead of the scenario, so it comes first in the
  // segment list; the pattern then decides how far ahead, and DISTRIBUTED interleaves it into the plan.
  const order: { kind: Draft['kind']; entityId: string; index: number }[] = [
    ...targets.map((entityId, index) => ({ kind: 'NOISE' as const, entityId, index })).filter((s) => noisePerTarget[s.index] > 0),
    ...targets.map((entityId, index) => ({ kind: 'SCENARIO' as const, entityId, index })),
  ];

  const drafts = order.map((s) => (s.kind === 'NOISE' ? draftNoise(s.entityId, s.index, now) : draftScenario(s.entityId, s.index, now)));

  /* 2. place the segments in time and rebuild them at their real anchor */
  const shifts = segmentShifts(drafts.map((d) => spanOf(d.events)), config.pattern);
  const segments: PlanSegment[] = order.map((s, i) => {
    const at = now + shifts[i] * 1000;
    const d = s.kind === 'NOISE' ? draftNoise(s.entityId, s.index, at) : draftScenario(s.entityId, s.index, at);
    return { kind: d.kind, entityId: d.entityId, prefix: d.prefix, shiftSec: shifts[i], events: d.events };
  }).filter((s) => s.events.length > 0);

  /* 3. submission order */
  const lists = segments.map((s) => s.events);
  const events = config.pattern === 'DISTRIBUTED' ? interleave(lists) : byTime(lists.flat());

  /* 4. summary */
  const typeCounts = new Map<string, number>();
  const entityCounts = new Map<string, number>();
  for (const e of events) {
    typeCounts.set(e.eventType, (typeCounts.get(e.eventType) ?? 0) + 1);
    entityCounts.set(e.entityId, (entityCounts.get(e.entityId) ?? 0) + 1);
  }

  const eventIssues = validateEvents(events, now);
  const eventCount = events.length;
  const estimatedDurationMs = eventCount ? Math.round(((eventCount - 1) * 1000) / config.eventRate) : 0;
  const plannedSends = sendsWithin(eventCount, config.eventRate, maxDurationMs);

  if (plannedSends < eventCount) {
    notes.push(`The duration cap stops the run after about ${plannedSends} of ${eventCount} events; raise the duration or the rate to send the whole plan.`);
  }
  if (segments.length === 1) {
    notes.push('With one segment every attack pattern produces the same plan - patterns place segments relative to each other, and there is only one.');
  }
  if (!scenario.scales) {
    notes.push(`${scenario.name} has a fixed event contract, so the intensity setting does not change what it generates.`);
  }
  if (config.noisePercent > 0) {
    notes.push('Benign noise is valid, ordinary activity - it is not a guarantee of no alerts: the ML ensemble scores it like any other event, and the deterministic rules still see the scenario events.');
  }
  if (config.targetMode === 'MULTI' && targets.length > 1 && scenario.detector.rules.length) {
    notes.push(`Multiple targets replay the whole scenario per entity, so ${scenario.detector.rules.join(' and ')} is satisfied independently for each of the ${targets.length} entities.`);
  }
  if (split && scenario.detector.rules.includes('AUTH_BURST')) {
    notes.push('AUTH_BURST counts failed logins per entity, so splitting them across entities lowers each count and the threshold may no longer be reached.');
  }

  return {
    runId,
    label: scenario.name,
    scenario,
    config,
    targets: [...new Set(events.map((e) => e.entityId))],
    segments,
    events,
    eventCount,
    scenarioEventCount: segments.filter((s) => s.kind === 'SCENARIO').reduce((n, s) => n + s.events.length, 0),
    noiseEventCount: segments.filter((s) => s.kind === 'NOISE').reduce((n, s) => n + s.events.length, 0),
    eventTypes: [...typeCounts.entries()].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count || a.type.localeCompare(b.type)),
    distribution: [...entityCounts.entries()].map(([entityId, count]) => ({ entityId, count })).sort((a, b) => b.count - a.count || a.entityId.localeCompare(b.entityId)),
    spanSec: spanOf(events),
    maxDurationMs,
    estimatedDurationMs,
    plannedSends,
    configIssues,
    eventIssues,
    issues: [...configIssues, ...eventIssues],
    notes,
  };
}

/* ------------------------------------------------------------------ gates */

/** A run may start only when nothing is wrong with the configuration or the generated events. */
export const canStart = (p: PlanPreview): boolean =>
  p.eventCount > 0 && !p.issues.some((i) => i.level === 'error');

/** Substantial runs get a confirmation step; a small default run does not. */
export const needsConfirmation = (p: PlanPreview): boolean =>
  p.eventCount > CONFIRM_EVENT_THRESHOLD || p.targets.length > 1 || p.noiseEventCount > 0;

/** The plan object handed to the engine - the very events the preview showed. */
export const toRunPlan = (p: PlanPreview): RunPlan => ({ runId: p.runId, label: p.label, events: p.events });

/** "Rule-backed" vs "ML-dependent" vs "no detector", for the confirmation summary. */
export const detectionSummary = (s: ScenarioDef): string => {
  if (s.detector.rules.length) return `Deterministic: ${s.detector.rules.join(', ')}${s.detector.ml ? ' (ML may also score)' : ''}`;
  if (s.detector.ml) return 'ML-dependent only - an alert is not guaranteed';
  return 'No detector covers this scenario - expect no alert';
};

/* ------------------------------------------------------------------ Phase 4: plan metadata */

/**
 * The plan facts the live console's Run Progress panel needs, derived from the preview the page is
 * about to start. Pure: it reads the plan it is given and invents nothing.
 *
 * Every event is attributed to its segment by LONGEST matching event-ID prefix, because a
 * single-target scenario segment uses the run ID itself as its prefix while a noise segment uses
 * `${runId}-Z1` - a plain startsWith would put the noise events in the scenario segment.
 */
export function planInfo(p: PlanPreview, demo: DemoRunMeta | null = null): RunPlanInfo {
  const segments: PlanSegmentInfo[] = p.segments.map((s) => ({ kind: s.kind, entityId: s.entityId, prefix: s.prefix, count: s.events.length }));
  // Longest prefix first, so the most specific segment claims an event.
  const ranked = segments.map((s, i) => ({ i, prefix: s.prefix })).sort((a, b) => b.prefix.length - a.prefix.length);
  const segmentOfEvent = p.events.map((e) => ranked.find((r) => e.eventId.startsWith(r.prefix))?.i ?? -1);

  return {
    runId: p.runId,
    scenarioId: p.config.scenarioId,
    label: p.label,
    // A verbatim copy, not a reference: later edits to the console's configuration must not reach
    // back into a plan that has already run.
    config: { ...p.config, entityIds: [...p.config.entityIds] },
    demo,
    phases: p.scenario?.phases ?? [],
    targets: p.targets,
    segments,
    segmentOfEvent,
    totalEvents: p.eventCount,
    eventRate: p.config.eventRate,
    maxDurationMs: p.maxDurationMs,
    intensity: p.config.intensity,
    pattern: p.config.pattern,
    targetMode: p.config.targetMode,
    noisePercent: p.config.noisePercent,
    detection: p.scenario ? detectionSummary(p.scenario) : 'unknown',
  };
}

export type SegmentProgress = PlanSegmentInfo & { index: number; submitted: number };

/**
 * Per-segment generation progress at the engine's current position. `submitted` counts plan
 * positions the engine has already handed to the transport - engine truth, not an estimate.
 */
export function segmentProgress(plan: RunPlanInfo, nextEventIndex: number): SegmentProgress[] {
  const submitted = plan.segments.map(() => 0);
  const upto = Math.min(nextEventIndex, plan.segmentOfEvent.length);
  for (let i = 0; i < upto; i++) {
    const seg = plan.segmentOfEvent[i];
    if (seg >= 0) submitted[seg]++;
  }
  return plan.segments.map((s, index) => ({ ...s, index, submitted: submitted[index] }));
}

/** The segment the engine is generating right now, or null once the plan is exhausted. */
export function currentSegment(plan: RunPlanInfo, nextEventIndex: number): SegmentProgress | null {
  const at = Math.min(nextEventIndex, plan.segmentOfEvent.length - 1);
  if (at < 0) return null;
  const index = plan.segmentOfEvent[at];
  if (index < 0) return null;
  return segmentProgress(plan, nextEventIndex)[index] ?? null;
}
