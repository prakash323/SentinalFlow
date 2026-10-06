/*
 * Demo & evaluation mode: curated walkthroughs of what SentinelFlow can and cannot detect.
 *
 * A preset is ONLY a shortcut for configuration. It names an existing scenario and a set of
 * configuration values, and the run it starts goes through exactly the same path as any other:
 * planner -> validation -> preview -> confirmation -> the Phase 2 engine -> the existing transport ->
 * the Phase 4 observation layer. There is no demo execution path, no demo transport and nothing here
 * sends an event.
 *
 * Expected and observed are kept strictly apart
 * --------------------------------------------
 * `DemoExpectation` is DECLARATIVE metadata: what the current implementation should do, written down
 * ahead of the run. It never holds a result. `assessDemo` compares it against an `ObservedRun`,
 * which only ever carries values the backend actually reported. Mixing the two is the one way a
 * demonstration can lie, so the types make it impossible.
 *
 * Honesty rules this module enforces
 * ----------------------------------
 *  - A deterministic rule the events satisfy by construction is `guaranteed`. ML never is.
 *  - An anomaly score is a percentile rank against the model's training distribution, not a
 *    probability. `formatScore` prints "0.997"; there is no percentage formatting anywhere here.
 *  - An ML scenario that raises no alert is NOT a failure - `assessDemo` says the score did not
 *    cross the alert-policy threshold, and sets `failure: false`.
 *  - A coverage gap raising no alert is the EXPECTED result, not a platform failure.
 *  - A negative result (no alert) is only reported at all when observation was complete; otherwise
 *    the verdict is INCONCLUSIVE.
 */
import { eventCount, scenarioById } from './scenarioRegistry.ts';
import { ALERT_THRESHOLD, DEFAULT_DURATION_SEC, SEVERITY_BANDS } from './types.ts';
import type { Intensity, ObservationQuality, ScenarioCategory, SimulatorConfig } from './types.ts';

/**
 * How a scenario is covered by the CURRENT implementation.
 *  RULE          a deterministic backend rule the events satisfy by construction
 *  ML            only the ML score can raise an alert - score-dependent, never guaranteed
 *  RULE_AND_ML   the run exercises both paths
 *  CONTROL       baseline behaviour; no alert is expected
 *  COVERAGE_GAP  no deterministic detector covers this behaviour at all
 */
export type DetectionType = 'RULE' | 'ML' | 'RULE_AND_ML' | 'CONTROL' | 'COVERAGE_GAP';

export const DETECTION_LABEL: Record<DetectionType, string> = {
  RULE: 'RULE',
  ML: 'ML',
  RULE_AND_ML: 'RULE + ML',
  CONTROL: 'CONTROL',
  COVERAGE_GAP: 'COVERAGE GAP',
};

/** The legend, used verbatim wherever a detection type is shown. */
export const DETECTION_LEGEND: { type: DetectionType; label: string; meaning: string }[] = [
  { type: 'RULE', label: 'RULE', meaning: 'Deterministic backend rule. The generated events satisfy it by construction.' },
  { type: 'ML', label: 'ML', meaning: 'Score-dependent machine-learning detection. An alert is possible, never guaranteed.' },
  { type: 'RULE_AND_ML', label: 'RULE + ML', meaning: 'The run exercises both detection paths in one sequence.' },
  { type: 'CONTROL', label: 'CONTROL', meaning: 'Baseline behaviour. No alert is expected, though the ML path still scores every event.' },
  { type: 'COVERAGE_GAP', label: 'COVERAGE GAP', meaning: 'No deterministic detector currently covers this behaviour. The absence of an alert is the expected result.' },
];

/* ------------------------------------------------------------------ declarative expectation */

/**
 * What the current implementation should do, written down BEFORE the run. This type has no field for
 * an observed value, deliberately: an expectation can never be contaminated by a result.
 */
export type DemoExpectation = {
  detectionType: DetectionType;
  /** Rule ids the events satisfy by construction; empty for ML, control and coverage-gap demos. */
  expectedRules: string[];
  expectedEventTypes: string[];
  /** Events the preset's configuration generates. */
  expectedEvents: number;
  /** True only for a deterministic rule the events satisfy by construction. Never true for ML. */
  guaranteed: boolean;
  /** The alert-policy threshold an ML score must cross, when ML is a path for this demo. */
  mlThreshold: number | null;
  /** One sentence: what should be seen. */
  statement: string;
  /** Honest caveats. The scenario's own limitations are added to these at read time. */
  limitations: string[];
};

/** The five questions a viva answer needs, kept short enough to read aloud during a demo. */
export type DemoExplanation = {
  /** 1. What behaviour is being simulated? */
  behaviour: string;
  /** 2. Which SentinelFlow component processes it? */
  component: string;
  /** 3. Is detection deterministic or ML-dependent? */
  determinism: string;
  /** 4. What result should we expect? */
  expected: string;
  /** 5. What limitation exists? */
  limitation: string;
};

export type DemoPreset = {
  id: string;
  name: string;
  /** Must be an id in SCENARIOS - presetScenario() resolves it and the self-check asserts it. */
  scenarioId: string;
  purpose: string;
  description: string;
  detectionType: DetectionType;
  /** The configuration this preset applies. The target entity is still the user's own choice. */
  config: Omit<Partial<SimulatorConfig>, 'entityId' | 'entityIds'>;
  expectation: DemoExpectation;
  explain: DemoExplanation;
};

/** Minimal demo metadata a history record keeps. Deliberately three fields, no results. */
export type DemoRunMeta = { demoId: string; demoName: string; detectionType: DetectionType };

/* ------------------------------------------------------------------ score formatting */

/**
 * The ONLY way this console prints an anomaly score. It is a percentile rank against the model's
 * training distribution, not a probability, so it is never rendered as a percentage and never
 * described as a chance of attack.
 */
export const formatScore = (score: number | null): string => (score === null ? 'not observed' : score.toFixed(3));

/** The severity band a score falls in under the backend's alert policy, for display only. */
export const scoreBand = (score: number | null): string | null => {
  if (score === null || score < ALERT_THRESHOLD) return null;
  return SEVERITY_BANDS.find((b) => score >= b.from)?.severity ?? null;
};

/* ------------------------------------------------------------------ the presets */

const AUTH_BURST_LIMIT = 'AUTH_BURST raises no second alert while an earlier AUTH_BURST alert for the same entity is still open, acknowledged or investigating. For a repeat demonstration, pick a different entity.';
const ML_NOT_A_PROBABILITY = `An anomaly score is a percentile rank against the model's training distribution, not a probability. The alert policy's bar is ${ALERT_THRESHOLD}.`;
const PROFILE_DRIFT = 'The ML profiler keeps per-entity behavioural state, so repeated runs against one entity gradually change what counts as normal for it.';

export const DEMO_PRESETS: DemoPreset[] = [
  {
    id: 'auth',
    name: 'Authentication attack',
    scenarioId: 'credstuff',
    purpose: 'Demonstrate the AUTH_BURST deterministic rule end to end.',
    description: 'Fourteen failed logins against one account from a rotating pool of source IPs, ending in a success.',
    detectionType: 'RULE',
    config: { scenarioId: 'credstuff', intensity: 'HIGH', eventRate: 2, duration: 30, noisePercent: 0, pattern: 'SEQUENTIAL', targetMode: 'SINGLE' },
    expectation: {
      detectionType: 'RULE',
      expectedRules: ['AUTH_BURST'],
      expectedEventTypes: ['LOGIN'],
      expectedEvents: 15,
      guaranteed: true,
      mlThreshold: null,
      statement: 'AUTH_BURST should raise one alert at HIGH severity: 14 failed logins for one entity inside five minutes meets its threshold of 5, and 14 is past its HIGH bar of 10.',
      limitations: [AUTH_BURST_LIMIT],
    },
    explain: {
      behaviour: 'Credential stuffing: one account tried repeatedly from many source addresses, then a successful login.',
      component: 'The events are POSTed to Spring Boot, stored, published to Kafka, and evaluated by DeterministicRuleService as each one is processed.',
      determinism: 'Deterministic. AUTH_BURST counts failed LOGIN events per entity in a five-minute window and ignores the source IP entirely.',
      expected: 'One AUTH_BURST alert, severity HIGH, attached to an incident for the entity.',
      limitation: AUTH_BURST_LIMIT,
    },
  },
  {
    id: 'procconn',
    name: 'Process + external connection',
    scenarioId: 'procconn',
    purpose: 'Demonstrate deterministic correlation across two event types.',
    description: 'A freshly started process that opens a non-loopback connection, correlated by pid and processCreateTime.',
    detectionType: 'RULE',
    config: { scenarioId: 'procconn', intensity: 'MEDIUM', eventRate: 1, duration: 30, noisePercent: 0, pattern: 'SEQUENTIAL', targetMode: 'SINGLE' },
    expectation: {
      detectionType: 'RULE',
      expectedRules: ['NEW_PROCESS_EXTERNAL_CONNECTION'],
      expectedEventTypes: ['PROCESS_START', 'NETWORK_CONNECTION'],
      expectedEvents: 4,
      guaranteed: true,
      mlThreshold: null,
      statement: 'Each PROCESS_START / NETWORK_CONNECTION pair should raise one NEW_PROCESS_EXTERNAL_CONNECTION alert at MEDIUM severity: same pid, processCreateTime equal to the PROCESS_START timestamp to the second, a non-loopback destination, and 20 s apart.',
      limitations: [
        'The rule reads the PROCESS_START back from the database, so the pair only correlates because the engine submits strictly in plan order and waits for each POST to settle.',
        'One alert per process identity: a second connection from the same pid is recorded as suppressed, which is why each pair uses its own pid.',
      ],
    },
    explain: {
      behaviour: 'A process is created and, twenty seconds later, connects out to an external address.',
      component: 'DeterministicRuleService evaluates the NETWORK_CONNECTION, looks the PROCESS_START up in PostgreSQL by pid and processCreateTime, and checks it was created within the last five minutes.',
      determinism: 'Deterministic. The correlation is an exact match on pid and on the creation timestamp formatted to the second - there is no time tolerance.',
      expected: 'One MEDIUM alert per pid, each attached to an incident.',
      limitation: 'The ML feature set reads no process or network fields, so these events reach the model almost empty: any score it returns is not evidence of process or network detection.',
    },
  },
  {
    id: 'exfil',
    name: 'Data exfiltration',
    scenarioId: 'exfil',
    purpose: 'Demonstrate an ML-dependent scenario, where an alert is possible but not guaranteed.',
    description: 'Six back-to-back downloads of sensitive finance documents inside one very long session.',
    detectionType: 'ML',
    config: { scenarioId: 'exfil', intensity: 'MEDIUM', eventRate: 2, duration: 30, noisePercent: 0, pattern: 'SEQUENTIAL', targetMode: 'SINGLE' },
    expectation: {
      detectionType: 'ML',
      expectedRules: [],
      expectedEventTypes: ['FILE_ACCESS'],
      expectedEvents: 6,
      guaranteed: false,
      mlThreshold: ALERT_THRESHOLD,
      statement: `No rule covers this pattern. An alert depends entirely on the ML ensemble scoring an event at or above the alert policy's threshold of ${ALERT_THRESHOLD}, so it is possible but not guaranteed.`,
      limitations: [
        ML_NOT_A_PROBABILITY,
        PROFILE_DRIFT,
        'There is no byte count in the event schema, so "exfiltration" here is download count and resource novelty only.',
      ],
    },
    explain: {
      behaviour: 'Bulk download of finance documents the entity has not touched before, in an unusually long session.',
      component: 'Spring Boot calls the ML service over HTTP during event processing; PredictionService then applies the alert policy to the returned score.',
      determinism: 'ML-dependent. No deterministic rule exists for data volume or resource novelty.',
      expected: `An anomaly score per event. An alert only if one reaches ${ALERT_THRESHOLD} or above; a lower score is a valid outcome, not a failure.`,
      limitation: ML_NOT_A_PROBABILITY,
    },
  },
  {
    id: 'mixed',
    name: 'Mixed attack',
    scenarioId: 'mixed',
    purpose: 'Demonstrate both detection paths in one run, and the difference between them.',
    description: 'Credential stuffing, then a process with an outbound connection, then the bulk download sequence - fifteen and seven minutes apart in event time.',
    detectionType: 'RULE_AND_ML',
    config: { scenarioId: 'mixed', intensity: 'MEDIUM', eventRate: 2, duration: 60, noisePercent: 10, pattern: 'SEQUENTIAL', targetMode: 'SINGLE' },
    expectation: {
      detectionType: 'RULE_AND_ML',
      expectedRules: ['AUTH_BURST', 'NEW_PROCESS_EXTERNAL_CONNECTION'],
      expectedEventTypes: ['LOGIN', 'PROCESS_START', 'NETWORK_CONNECTION', 'FILE_ACCESS'],
      expectedEvents: 22,
      guaranteed: true,
      mlThreshold: ALERT_THRESHOLD,
      statement: 'Both deterministic rules should fire - AUTH_BURST from the credential stage and NEW_PROCESS_EXTERNAL_CONNECTION from the execution stage. The exfiltration stage is ML-only, so an alert from it is possible but not guaranteed.',
      limitations: [
        AUTH_BURST_LIMIT,
        'The three stages are separated in event time so each rule window stays clean. That is not a claim that the backend correlates the stages into one campaign beyond the normal per-entity incident grouping.',
        ML_NOT_A_PROBABILITY,
      ],
    },
    explain: {
      behaviour: 'A three-stage campaign against one entity: credential access, execution with egress, then bulk collection.',
      component: 'Both paths run on every event: DeterministicRuleService in its own transaction, and the ML service through PredictionService. A rule alert and an ML alert are distinguishable by detectionType.',
      determinism: 'Both. The first two stages are deterministic; the third is ML-dependent.',
      expected: 'At least two rule alerts, grouped into incidents per entity and event type. ML scores on every event, with an alert only if one crosses the policy threshold.',
      limitation: 'Benign noise is included to make the run realistic. It is not a guarantee of quiet: the ML ensemble scores it like any other event.',
    },
  },
  {
    id: 'gap',
    name: 'Coverage gap',
    scenarioId: 'portscan',
    purpose: 'Demonstrate, explicitly, a behaviour SentinelFlow does not detect today.',
    description: 'Fourteen short-lived connection attempts to consecutive ports on one internal host from a single process.',
    detectionType: 'COVERAGE_GAP',
    config: { scenarioId: 'portscan', intensity: 'MEDIUM', eventRate: 5, duration: 15, noisePercent: 0, pattern: 'SEQUENTIAL', targetMode: 'SINGLE' },
    expectation: {
      detectionType: 'COVERAGE_GAP',
      expectedRules: [],
      expectedEventTypes: ['NETWORK_CONNECTION'],
      expectedEvents: 14,
      guaranteed: false,
      mlThreshold: null,
      statement: 'No deterministic backend detector currently covers this behaviour, so no alert is the expected result. The events are still ingested, stored and visible - this demonstrates a detection gap, not an ingestion failure.',
      limitations: [
        'The only NETWORK_CONNECTION rule is NEW_PROCESS_EXTERNAL_CONNECTION, which needs a correlated PROCESS_START and a processCreateTime. This scenario deliberately sends neither, so the rule cannot fire.',
        'The ML feature set reads no network fields, so the model sees these events almost empty.',
        'Closing this gap would mean a new backend rule. Phase 6 deliberately does not add one.',
      ],
    },
    explain: {
      behaviour: 'A port sweep: one process opening connections to many ports on one host in quick succession.',
      component: 'Ingestion works normally - the events are stored in PostgreSQL and published to Kafka, and appear on the Events page. Only detection is absent.',
      determinism: 'Neither. No rule covers port scanning, and the ML feature set has no network fields to read.',
      expected: 'No alert. That is the correct, documented outcome for the current implementation.',
      limitation: 'Absence of an alert here says nothing about whether the behaviour is benign. It says SentinelFlow does not look for it yet.',
    },
  },
  {
    id: 'control',
    name: 'Baseline control',
    scenarioId: 'routine',
    purpose: 'Establish what normal looks like before demonstrating an attack.',
    description: 'A normal login, a file open and a logout from the usual place and device.',
    detectionType: 'CONTROL',
    config: { scenarioId: 'routine', intensity: 'MEDIUM', eventRate: 1, duration: 15, noisePercent: 0, pattern: 'SEQUENTIAL', targetMode: 'SINGLE' },
    expectation: {
      detectionType: 'CONTROL',
      expectedRules: [],
      expectedEventTypes: ['LOGIN', 'FILE_ACCESS', 'LOGOUT'],
      expectedEvents: 3,
      guaranteed: false,
      mlThreshold: ALERT_THRESHOLD,
      statement: 'No alert is expected. Run this first so the audience can see the difference an attack sequence makes.',
      limitations: [
        'A control is not a promise of silence: the ML ensemble still scores every event, and an entity whose profile has been reshaped by earlier runs can score a routine session high.',
        PROFILE_DRIFT,
      ],
    },
    explain: {
      behaviour: 'An ordinary workday session from the usual address and device.',
      component: 'The same pipeline as every other demo: REST, PostgreSQL, Kafka, then both detection paths.',
      determinism: 'Neither path should react. No rule matches, and the behaviour is what the model was trained to consider normal.',
      expected: 'Three processed events, low scores and no alert.',
      limitation: 'If this control does alert, the entity\'s learned profile has drifted - pick a different entity for a clean baseline.',
    },
  },
];

export const demoById = (id: string): DemoPreset | undefined => DEMO_PRESETS.find((d) => d.id === id);

/** The scenario a preset runs. Undefined would mean a preset naming a scenario that does not exist. */
export const presetScenario = (d: DemoPreset) => scenarioById(d.scenarioId);

/** The scenario's category, so a demo card never has to restate it. */
export const presetCategory = (d: DemoPreset): ScenarioCategory | null => presetScenario(d)?.category ?? null;

/**
 * Events the preset's SCENARIO generates at its intensity, read from the registry. The plan can hold
 * more than this once benign noise is added, which is why a demo card shows the preview's own count
 * and `expectation.expectedEvents` is asserted against the plan, not against this.
 */
export const presetScenarioEventCount = (d: DemoPreset): number => {
  const s = presetScenario(d);
  return s ? eventCount(s, (d.config.intensity ?? 'MEDIUM') as Intensity) : 0;
};

/** A preset applied to the user's own configuration. Target selection stays theirs. */
export const applyPreset = (current: SimulatorConfig, d: DemoPreset): SimulatorConfig => ({
  ...current,
  ...d.config,
  scenarioId: d.scenarioId,
  duration: d.config.duration ?? DEFAULT_DURATION_SEC,
  customDurationSec: '',
});

/** Everything the expectation says, plus the scenario library's own limitations. One list, no duplicates. */
export const presetLimitations = (d: DemoPreset): string[] => {
  const own = presetScenario(d)?.limitations ?? [];
  return [...new Set([...d.expectation.limitations, ...own])];
};

/* ------------------------------------------------------------------ observed, and the assessment */

/** Only values the backend actually reported. No expectation may be folded in here. */
export type ObservedRun = {
  accepted: number;
  /** Accepted events that reached a terminal processing state. */
  observedTerminal: number;
  observation: ObservationQuality;
  alerts: number;
  incidents: number;
  peakScore: number | null;
  severity: Record<string, number>;
  /** Detector id -> alert count, as the trails reported it ("ML" for a prediction-driven alert). */
  detectors: Record<string, number>;
};

export type DemoVerdict =
  /** What the expectation described was observed. */
  | 'EXPECTED_OBSERVED'
  /** Observation was complete and what the expectation described did not happen. */
  | 'EXPECTED_NOT_OBSERVED'
  /** Observation was too incomplete to conclude anything. */
  | 'INCONCLUSIVE'
  /** No detection was expected, and none happened - the correct result. */
  | 'EXPECTED_NO_DETECTION';

export type DemoAssessment = {
  verdict: DemoVerdict;
  /** The headline. Never says "failure" for an ML or coverage-gap outcome. */
  label: string;
  detail: string;
  /**
   * Whether this outcome means something is wrong with the platform. False for every ML non-alert,
   * every coverage gap and every inconclusive run - which is the whole point of having this field.
   */
  failure: boolean;
  expectedLines: string[];
  observedLines: string[];
};

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`;
const observedRules = (o: ObservedRun, rules: string[]) => rules.filter((r) => (o.detectors[r] ?? 0) > 0);

const coverageLine = (o: ObservedRun) =>
  `Observation: ${o.observedTerminal} of ${plural(o.accepted, 'accepted event')} reached a known pipeline outcome`;

const scoreLine = (o: ObservedRun) =>
  o.peakScore === null
    ? 'Peak anomaly score: not observed'
    : `Peak anomaly score: ${formatScore(o.peakScore)}${scoreBand(o.peakScore) ? ` (${scoreBand(o.peakScore)} band)` : ` (below the ${ALERT_THRESHOLD} alert threshold)`}`;

/** The declarative side, as display lines. Derived only from the expectation. */
export function expectedLines(e: DemoExpectation): string[] {
  const lines = [`Detection type: ${DETECTION_LABEL[e.detectionType]}`];
  if (e.expectedRules.length) lines.push(`Deterministic rule${e.expectedRules.length > 1 ? 's' : ''}: ${e.expectedRules.join(', ')}`);
  else lines.push(e.detectionType === 'COVERAGE_GAP' ? 'No deterministic detector exists for this behaviour' : 'No deterministic rule covers this pattern');
  if (e.mlThreshold !== null) lines.push(`ML path: an alert needs an anomaly score of at least ${e.mlThreshold}`);
  lines.push(`Event types: ${e.expectedEventTypes.join(', ')}`);
  lines.push(`Events: ${e.expectedEvents}`);
  lines.push(e.guaranteed ? 'Guaranteed by construction, subject to the limitations below' : 'Not guaranteed');
  return lines;
}

/** The observed side, as display lines. Derived only from what the backend reported. */
export function observedLines(o: ObservedRun): string[] {
  const detectors = Object.entries(o.detectors);
  const severities = Object.entries(o.severity);
  return [
    detectors.length ? `Detectors that fired: ${detectors.map(([d, n]) => `${d} x${n}`).join(', ')}` : 'No detector fired on any observed event',
    severities.length ? `Severities: ${severities.map(([s, n]) => `${s} x${n}`).join(', ')}` : 'No alert severity observed',
    `Alerts: ${o.alerts} · Incidents: ${o.incidents}`,
    scoreLine(o),
    coverageLine(o),
  ];
}

/**
 * Compare the declared expectation against the observed run.
 *
 * Order matters, and it is the order a SOC analyst would use:
 *  1. A POSITIVE observation is self-evidencing. If the expected rule fired, we saw it, and partial
 *     coverage elsewhere does not weaken that.
 *  2. Otherwise a NEGATIVE result is only meaningful with complete coverage. Partial -> INCONCLUSIVE.
 *  3. Only then is the absence judged, against what was actually expected.
 */
export function assessDemo(e: DemoExpectation, o: ObservedRun): DemoAssessment {
  const lines = { expectedLines: expectedLines(e), observedLines: observedLines(o) };
  const hit = observedRules(o, e.expectedRules);
  const complete = o.observation === 'COMPLETE';

  // 1. the expected deterministic rules all fired
  if (e.expectedRules.length && hit.length === e.expectedRules.length) {
    return {
      verdict: 'EXPECTED_OBSERVED',
      label: 'Expected result observed',
      detail: `${hit.join(' and ')} raised ${plural(o.alerts, 'alert')}${o.incidents > 0 ? `, grouped into ${plural(o.incidents, 'incident')}` : ''}. This is the deterministic path, so the result is reproducible.`,
      failure: false,
      ...lines,
    };
  }

  // 1b. an ML-only or mixed-ML demo that did produce an alert
  if (!e.expectedRules.length && e.mlThreshold !== null && o.alerts > 0 && e.detectionType !== 'CONTROL' && e.detectionType !== 'COVERAGE_GAP') {
    return {
      verdict: 'EXPECTED_OBSERVED',
      label: 'Expected result observed',
      detail: `The ML path raised ${plural(o.alerts, 'alert')}: the peak anomaly score of ${formatScore(o.peakScore)} reached the alert policy's threshold of ${e.mlThreshold}. An anomaly score is a percentile rank, not a probability.`,
      failure: false,
      ...lines,
    };
  }

  // 2. nothing positive to report, so coverage decides whether anything can be concluded
  if (!complete) {
    return {
      verdict: 'INCONCLUSIVE',
      label: 'Inconclusive — observation window was incomplete',
      detail: o.accepted === 0
        ? 'No event was accepted, so there was nothing to observe.'
        : `Only ${o.observedTerminal} of ${plural(o.accepted, 'accepted event')} reached a known outcome before trail polling stopped. ${hit.length ? `${hit.join(' and ')} did fire, but the rest of the run was not observed.` : 'A result of "no alert" cannot be read from a partial observation.'}`,
      failure: false,
      ...lines,
    };
  }

  // 3a. no detection was expected, and none happened
  if ((e.detectionType === 'COVERAGE_GAP' || e.detectionType === 'CONTROL') && o.alerts === 0) {
    return {
      verdict: 'EXPECTED_NO_DETECTION',
      label: e.detectionType === 'COVERAGE_GAP' ? 'Coverage gap — no detection expected, none observed' : 'Control — no detection expected, none observed',
      detail: e.detectionType === 'COVERAGE_GAP'
        ? `No deterministic backend detector currently covers this behaviour, so the absence of an alert is the expected result, not a platform failure. All ${plural(o.accepted, 'event')} were ingested and processed normally and are visible on the Events page.`
        : `The baseline behaved as a baseline: ${plural(o.accepted, 'event')} processed, no alert. This is the reference point for the attack demos.`,
      failure: false,
      ...lines,
    };
  }

  // 3b. an alert appeared where none was expected - a finding, not a platform failure
  if ((e.detectionType === 'COVERAGE_GAP' || e.detectionType === 'CONTROL') && o.alerts > 0) {
    return {
      verdict: 'EXPECTED_NOT_OBSERVED',
      label: 'An alert was raised although none was expected',
      detail: `${plural(o.alerts, 'alert')} appeared with a peak anomaly score of ${formatScore(o.peakScore)}. ${e.detectionType === 'COVERAGE_GAP'
        ? 'No deterministic detector covers this behaviour, so this came from the ML path scoring events it has no features for - it is an ML score result, not detection of the simulated behaviour.'
        : 'The ML ensemble scores every event, and an entity whose learned profile has drifted from repeated runs can score a routine session high. Pick a fresh entity for a clean baseline.'}`,
      failure: false,
      ...lines,
    };
  }

  // 3c. an ML-dependent demo that did not cross the threshold - explicitly NOT a failure
  if (!e.guaranteed && e.mlThreshold !== null) {
    return {
      verdict: 'EXPECTED_NOT_OBSERVED',
      label: 'ML outcome did not cross the alert threshold',
      detail: `The ML path is score-dependent: the peak observed anomaly score was ${formatScore(o.peakScore)}, below the alert policy's threshold of ${e.mlThreshold}. For an ML-dependent scenario this is a valid outcome and not a platform defect - the expectation itself was never a guarantee.`,
      failure: false,
      ...lines,
    };
  }

  // 3d. a deterministic rule was expected and did not fire. The documented cause comes first.
  const missing = e.expectedRules.filter((r) => !hit.includes(r));
  return {
    verdict: 'EXPECTED_NOT_OBSERVED',
    label: `Expected rule did not raise an alert: ${missing.join(', ') || 'none observed'}`,
    detail: `${hit.length ? `${hit.join(' and ')} fired, but ` : ''}${missing.join(' and ')} did not. The usual reason is suppression: a rule raises no second alert while an earlier alert of the same rule for the same entity is still open, acknowledged or investigating. Check the entity's existing alerts, or run the demo against a different entity.`,
    failure: true,
    ...lines,
  };
}

/* ------------------------------------------------------------------ architecture (explanatory only) */

/**
 * The path an event really takes. Every step below exists in this codebase; nothing is aspirational,
 * and the Simulator deliberately does NOT appear next to the ML service - it never talks to it.
 * `conditional` marks a step that only happens for some runs, so the diagram cannot imply that every
 * scenario ends in an alert.
 */
export type ArchitectureStep = { id: string; label: string; detail: string; conditional: boolean };

export const ARCHITECTURE_FLOW: ArchitectureStep[] = [
  { id: 'simulator', label: 'Simulator (this page)', detail: 'Builds and validates the events, then submits them one at a time, paced, in plan order.', conditional: false },
  { id: 'rest', label: 'POST /api/v1/events', detail: 'The only endpoint the Simulator calls to submit an event. One request per event, never concurrent.', conditional: false },
  { id: 'api', label: 'Spring Boot', detail: 'Validates the request against the event contract and rejects anything that does not meet it.', conditional: false },
  { id: 'db', label: 'PostgreSQL', detail: 'The event row is stored first, which is what later lets a rule read an earlier event back.', conditional: false },
  { id: 'kafka', label: 'Kafka', detail: 'The stored event is published for asynchronous processing.', conditional: false },
  { id: 'processing', label: 'Event processing', detail: 'The consumer processes each event and records its processing status, which the Simulator reads back from the event trail.', conditional: false },
  { id: 'rules', label: 'Deterministic rules', detail: 'AUTH_BURST and NEW_PROCESS_EXTERNAL_CONNECTION are evaluated here, independently of the ML service and unaffected by its availability.', conditional: false },
  { id: 'ml', label: 'ML service', detail: 'Spring Boot calls the ML service over HTTP and stores the returned anomaly score as a prediction. The Simulator never contacts it directly.', conditional: false },
  { id: 'policy', label: 'Alert policy', detail: `Turns a score into an alert only at or above the configured threshold of ${ALERT_THRESHOLD}, with severity bands at ${SEVERITY_BANDS.map((b) => b.from).join(', ')}.`, conditional: false },
  { id: 'alert', label: 'Alert', detail: 'Raised by a rule or by the alert policy. Many runs produce none - that is a valid outcome, not a missing step.', conditional: true },
  { id: 'incident', label: 'Incident', detail: 'An alert is grouped into an incident per entity and event type.', conditional: true },
  { id: 'dashboard', label: 'SOC dashboard', detail: 'Where the resulting alerts and incidents are triaged.', conditional: true },
];

/* ------------------------------------------------------------------ presenter checklist */

/** Informational only. Nothing here performs an action or touches the network. */
export const DEMO_CHECKLIST: { id: string; label: string }[] = [
  { id: 'select', label: 'Select a demo and read what it demonstrates' },
  { id: 'expect', label: 'Review the expected behaviour and its limitations' },
  { id: 'target', label: 'Choose a target entity with no open alerts' },
  { id: 'preview', label: 'Preview the events that will be submitted' },
  { id: 'confirm', label: 'Confirm the configuration' },
  { id: 'start', label: 'Start the simulation' },
  { id: 'watch', label: 'Watch the live console and the KPI strip' },
  { id: 'alert', label: 'Open an alert and show its evidence' },
  { id: 'incident', label: 'Open the incident the alert was grouped into' },
  { id: 'history', label: 'Open Run History and investigate the completed run' },
  { id: 'explain', label: 'Explain expected versus observed, including what was not detected' },
];
