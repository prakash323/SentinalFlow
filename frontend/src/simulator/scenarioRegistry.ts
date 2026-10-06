/*
 * Scenario library: the metadata the console shows, plus each scenario's builder.
 *
 * The six original scenarios come FIRST and in their original order - their titles, descriptions,
 * "exercises" lines, detector claims and builders are untouched, and scripts/simulator-check.mts
 * still compares them against a frozen copy of the original page code.
 *
 * Every `detector` and `limitations` entry describes what DeterministicRuleService and the live ML
 * adapter actually do today. A scenario that no rule covers says so; none of them claims a
 * guarantee the backend does not make.
 */
import { buildBrute, buildDevice, buildExfil, buildPrivesc, buildRoutine, buildTravel } from './builders.ts';
import {
  buildCredentialStuffing,
  buildLateralMovement,
  buildMixedAttack,
  buildPortScan,
  buildProcessConnection,
  buildSuspiciousProcess,
  CONNECTION_PAIRS,
  LATERAL_HOPS,
  SCAN_PORTS,
  STUFFING_FAILURES,
  SUSPICIOUS_PROCESSES,
} from './advancedBuilders.ts';
import { AUTH_BURST_HIGH_THRESHOLD, AUTH_BURST_THRESHOLD, RULE_WINDOW_MINUTES } from './types.ts';
import type { Intensity, ScenarioCategory, ScenarioDef } from './types.ts';

const ML_ONLY = 'No rule covers this pattern; an alert depends on the ML score crossing the live alert threshold, so it is not guaranteed.';

/**
 * PROCESS_START and NETWORK_CONNECTION reach the ML service through the same adapter as every other
 * event, but api.py's _canonical_event reads only ip / location / resource / authMethod /
 * loginSuccess / sessionDurationMinutes / commandSequence / deviceFingerprint. None of those is part
 * of a process or connection payload, so the model sees an almost empty event: a score it returns is
 * not evidence of process or network detection.
 */
const NO_ML_FEATURES =
  'The ML feature set reads no process or network fields (api.py _canonical_event), so these events reach the model almost empty - any score it returns is not evidence of process or network detection.';

const AUTH_BURST_SUPPRESSION =
  'AUTH_BURST raises no second alert while an earlier AUTH_BURST alert for the same entity is still open, acknowledged or investigating - a repeat run against the same entity is recorded as suppressed, not as a new alert.';

const RULE_WINDOW_NOTE =
  `AUTH_BURST counts failed LOGINs per ENTITY inside ${RULE_WINDOW_MINUTES} minutes and ignores the source IP entirely.`;

/** Human labels for the library's groups. */
export const CATEGORY_LABEL: Record<ScenarioCategory, string> = {
  BASELINE: 'Control',
  IDENTITY: 'Identity',
  ENDPOINT: 'Endpoint',
  NETWORK: 'Network',
  DATA: 'Data',
  CHAIN: 'Attack chains',
};

/** The order the library renders its groups in. */
export const CATEGORY_ORDER: ScenarioCategory[] = ['IDENTITY', 'ENDPOINT', 'NETWORK', 'DATA', 'CHAIN', 'BASELINE'];

/** The six scenarios that existed before Phase 3, in their original order. */
export const ORIGINAL_SCENARIO_IDS = ['routine', 'brute', 'travel', 'privesc', 'exfil', 'device'];

export const SCENARIOS: ScenarioDef[] = [
  /* ---------------------------------------------------------------- the original six */
  {
    id: 'routine',
    name: 'Routine workday',
    description: 'A normal login, a file open and a logout from the usual place and device.',
    category: 'BASELINE',
    exercises: 'Low scores, no alert',
    detector: { rules: [], ml: false, note: 'Control scenario: no alert is expected.' },
    phases: ['Routine session'],
    scales: false,
    splittable: false,
    groupMode: 'ALL',
    limitations: ['A control is not a promise of silence: the ML ensemble still scores every event, and an entity whose profile has been reshaped by earlier runs can score a routine session high.'],
    build: buildRoutine,
  },
  {
    id: 'brute',
    name: 'Brute-force login burst',
    description: 'Eight rapid failed logins from one foreign IP, ending in a successful login.',
    category: 'IDENTITY',
    exercises: 'Failure-rate spike from a single source IP',
    detector: {
      rules: ['AUTH_BURST'],
      ml: true,
      note: 'Eight failed logins inside five minutes meet the AUTH_BURST threshold (5). The rule raises no new alert while an earlier AUTH_BURST alert for the same entity is still open. ML is score-dependent.',
    },
    phases: ['Password guessing', 'Initial access'],
    scales: false,
    splittable: false,
    groupMode: 'ALL',
    limitations: [AUTH_BURST_SUPPRESSION],
    build: buildBrute,
  },
  {
    id: 'travel',
    name: 'Impossible travel',
    description: 'A login in Pune followed five minutes later by a login from Lagos.',
    category: 'NETWORK',
    exercises: 'Implausible geo-velocity between logins',
    detector: { rules: [], ml: true, note: ML_ONLY },
    phases: ['Home login', 'Foreign login'],
    scales: false,
    splittable: false,
    groupMode: 'ALL',
    limitations: ['No geo-velocity rule exists; the pair of logins is only meaningful to the ML profiler, which must have enough history for this entity to treat Lagos as novel.'],
    build: buildTravel,
  },
  {
    id: 'privesc',
    name: 'Privilege escalation',
    description: 'A session that runs sudo/exec/download/delete against sensitive system files.',
    category: 'ENDPOINT',
    exercises: 'Unusual command sequence on a sensitive resource',
    detector: { rules: [], ml: true, note: ML_ONLY },
    phases: ['Session start', 'Privileged commands'],
    scales: false,
    splittable: false,
    groupMode: 'ALL',
    limitations: ['No command-sequence rule exists; the sudo/exec chain is a FILE_ACCESS payload field the ML profiler reads, nothing more.'],
    build: buildPrivesc,
  },
  {
    id: 'exfil',
    name: 'Data exfiltration',
    description: 'Six back-to-back downloads of sensitive finance documents in a very long session.',
    category: 'DATA',
    exercises: 'Resource novelty + sensitive-access volume',
    detector: { rules: [], ml: true, note: ML_ONLY },
    phases: ['Bulk download'],
    scales: false,
    splittable: false,
    groupMode: 'ALL',
    limitations: ['No volume or data-loss rule exists; there is no byte count in the event schema, so "exfiltration" here is download count and resource novelty only.'],
    build: buildExfil,
  },
  {
    id: 'device',
    name: 'Unknown device',
    description: 'A login from a never-seen device and browser fingerprint using an unusual auth method.',
    category: 'IDENTITY',
    exercises: 'Device-fingerprint novelty',
    detector: { rules: [], ml: true, note: ML_ONLY },
    phases: ['New device login'],
    scales: false,
    splittable: false,
    groupMode: 'ALL',
    limitations: ['No device-allowlist rule exists; novelty is only what the ML profiler has learned for this entity, and a single event rarely moves the score far.'],
    build: buildDevice,
  },

  /* ---------------------------------------------------------------- Phase 3 additions */
  {
    id: 'credstuff',
    name: 'Credential stuffing',
    description: 'Failed logins against one account from a rotating pool of source IPs, ending in a success.',
    category: 'IDENTITY',
    exercises: 'Per-entity failure volume from many sources',
    detector: {
      rules: ['AUTH_BURST'],
      ml: true,
      note:
        `Every intensity generates at least ${AUTH_BURST_THRESHOLD} failed logins inside ${RULE_WINDOW_MINUTES} minutes, so AUTH_BURST is satisfied by construction. ` +
        `${STUFFING_FAILURES.HIGH} failures (HIGH intensity) reach the rule's own HIGH severity threshold of ${AUTH_BURST_HIGH_THRESHOLD}; LOW and MEDIUM stay MEDIUM. ML is score-dependent.`,
    },
    phases: ['Credential replay', 'Initial access'],
    scales: true,
    splittable: false,
    groupMode: 'ALL',
    limitations: [
      RULE_WINDOW_NOTE + ' The rotating source IPs are realism, not a second detection signal.',
      AUTH_BURST_SUPPRESSION,
      `Splitting the attempts across entities (Distributed targets) can leave every entity below ${AUTH_BURST_THRESHOLD}, which is why this scenario is not splittable.`,
    ],
    build: buildCredentialStuffing,
  },
  {
    id: 'procconn',
    name: 'Process + external connection',
    description: 'A freshly started process that immediately opens a non-loopback connection, one pair per pid.',
    category: 'ENDPOINT',
    exercises: 'pid + processCreateTime correlation across two event types',
    detector: {
      rules: ['NEW_PROCESS_EXTERNAL_CONNECTION'],
      ml: false,
      note:
        `Built to the rule's exact contract: PROCESS_START first, then a NETWORK_CONNECTION with the same pid, a processCreateTime equal to that PROCESS_START's occurredAt truncated to whole seconds, a non-loopback remoteAddress, and 20 s between them (the rule's recency bound is ${RULE_WINDOW_MINUTES} minutes).`,
    },
    phases: ['Process creation', 'Outbound connection'],
    scales: true,
    splittable: true,
    groupMode: 'PAIR',
    limitations: [
      NO_ML_FEATURES,
      'The rule reads the PROCESS_START back from the database, so the pair only correlates because the engine submits strictly in plan order and waits for each POST to settle.',
      'One alert per process identity: a second connection from the same pid is recorded as suppressed, which is why each pair uses its own pid.',
    ],
    build: buildProcessConnection,
  },
  {
    id: 'portscan',
    name: 'Port scan',
    description: 'Short-lived connection attempts to consecutive ports on one internal host from a single process.',
    category: 'NETWORK',
    exercises: 'Connection fan-out across ports (telemetry only)',
    detector: {
      rules: [],
      ml: false,
      note: 'COVERAGE GAP: no port-scan detector exists. The only NETWORK_CONNECTION rule is NEW_PROCESS_EXTERNAL_CONNECTION, which needs a correlated PROCESS_START and a processCreateTime - deliberately absent here, so no rule fires.',
    },
    phases: ['Port sweep'],
    scales: true,
    splittable: true,
    groupMode: 'EACH',
    limitations: [
      'COVERAGE GAP: expect no alert. This scenario exists to produce realistic network telemetry for the event and correlation views, not to trigger detection.',
      NO_ML_FEATURES,
    ],
    build: buildPortScan,
  },
  {
    id: 'suspproc',
    name: 'Suspicious process',
    description: 'A download/decode/execute/persist chain of process starts with a plausible parent lineage.',
    category: 'ENDPOINT',
    exercises: 'Process lineage (telemetry only)',
    detector: {
      rules: [],
      ml: false,
      note: 'COVERAGE GAP: no suspicious-process rule exists. NEW_PROCESS_EXTERNAL_CONNECTION fires on a NETWORK_CONNECTION, and this scenario deliberately sends none, so no rule fires.',
    },
    phases: ['Process chain'],
    scales: true,
    splittable: true,
    groupMode: 'EACH',
    limitations: [
      'COVERAGE GAP: expect no alert. Add the Process + external connection scenario if you want the endpoint rule to fire.',
      NO_ML_FEATURES,
    ],
    build: buildSuspiciousProcess,
  },
  {
    id: 'lateral',
    name: 'Lateral movement',
    description: 'A hop chain: an internal login then an administrative share write, repeated across hosts.',
    category: 'CHAIN',
    exercises: 'Repeated internal access to administrative shares',
    detector: { rules: [], ml: true, note: ML_ONLY },
    phases: ['Internal login', 'Admin share write'],
    scales: true,
    splittable: false,
    groupMode: 'ALL',
    limitations: [
      'COVERAGE GAP: no lateral-movement rule exists. Detection is ML-dependent and therefore never guaranteed.',
      'Real lateral movement spans hosts; SentinelFlow profiles behaviour per entity, so a chain run against one entity is an approximation - the hop hosts are payload IPs, not separate entities.',
    ],
    build: buildLateralMovement,
  },
  {
    id: 'mixed',
    name: 'Mixed attack',
    description: 'Credential stuffing, then a process with an outbound connection, then the bulk download sequence.',
    category: 'CHAIN',
    exercises: 'A full chain across two rules and the ML path',
    detector: {
      rules: ['AUTH_BURST', 'NEW_PROCESS_EXTERNAL_CONNECTION'],
      ml: true,
      note: 'Composes three existing scenarios in chronological order, 15 minutes apart, so both deterministic rules are satisfied by construction and the exfiltration stage is scored by the ML path unchanged.',
    },
    phases: ['Credential replay', 'Execution and egress', 'Bulk download'],
    scales: true,
    splittable: false,
    groupMode: 'ALL',
    limitations: [
      AUTH_BURST_SUPPRESSION,
      'The three stages are 15 and 7 minutes apart in event time so each rule window stays clean; they are not a claim that the backend correlates the stages into one incident beyond the normal per-entity incident grouping.',
    ],
    build: buildMixedAttack,
  },
];

export const scenarioById = (id: string): ScenarioDef | undefined => SCENARIOS.find((s) => s.id === id);

/** Events a scenario sends at a given intensity. Every builder has a fixed count per intensity. */
export const eventCount = (s: ScenarioDef, intensity: Intensity = 'MEDIUM'): number =>
  s.build({ entityId: 'x', prefix: 'x', now: 0, intensity }).length;

/** The library, grouped for display in CATEGORY_ORDER. Empty groups are dropped. */
export const scenarioGroups = (): { category: ScenarioCategory; label: string; scenarios: ScenarioDef[] }[] =>
  CATEGORY_ORDER.map((category) => ({
    category,
    label: CATEGORY_LABEL[category],
    scenarios: SCENARIOS.filter((s) => s.category === category),
  })).filter((g) => g.scenarios.length > 0);

/** How a scenario's `n` events partition into the groups DISTRIBUTED targets hand out round-robin. */
export const eventGroups = (s: ScenarioDef, n: number): number[][] => {
  if (s.groupMode === 'EACH') return Array.from({ length: n }, (_, i) => [i]);
  if (s.groupMode === 'PAIR') {
    const out: number[][] = [];
    for (let i = 0; i < n; i += 2) out.push(i + 1 < n ? [i, i + 1] : [i]);
    return out;
  }
  return n ? [Array.from({ length: n }, (_, i) => i)] : [];
};

/** Reference counts used by the console and the self-check. */
export const INTENSITY_COUNTS: Record<string, Record<Intensity, number>> = {
  credstuff: { LOW: STUFFING_FAILURES.LOW + 1, MEDIUM: STUFFING_FAILURES.MEDIUM + 1, HIGH: STUFFING_FAILURES.HIGH + 1 },
  procconn: { LOW: CONNECTION_PAIRS.LOW * 2, MEDIUM: CONNECTION_PAIRS.MEDIUM * 2, HIGH: CONNECTION_PAIRS.HIGH * 2 },
  portscan: SCAN_PORTS,
  suspproc: SUSPICIOUS_PROCESSES,
  lateral: { LOW: LATERAL_HOPS.LOW * 2, MEDIUM: LATERAL_HOPS.MEDIUM * 2, HIGH: LATERAL_HOPS.HIGH * 2 },
};
