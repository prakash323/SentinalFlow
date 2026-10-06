/*
 * Phase 3 scenario builders, and the benign-noise builder.
 *
 * Every payload field used here already exists in this platform's own event vocabulary:
 *   LOGIN / LOGOUT / FILE_ACCESS   ip, location, loginSuccess, authMethod, deviceFingerprint,
 *                                  resource, action, commandSequence, sessionDurationMinutes
 *                                  (CreateEvent.tsx TEMPLATES, api.py _canonical_event)
 *   PROCESS_START                  pid, processName, parentPid, username, executablePath
 *                                  (SentinelFlow-PhysicalCollector normalizer.build_process_event)
 *   NETWORK_CONNECTION             protocol, localAddress, localPort, remoteAddress, remotePort,
 *                                  status, pid, processName, processCreateTime
 *                                  (normalizer.build_network_connection_event)
 * Nothing is invented, and no backend detector is claimed that DeterministicRuleService does not
 * implement - see scenarioRegistry.ts for each scenario's honest detector/limitation statement.
 *
 * Builders reuse builders.ts's `ev` unchanged, so eventIds stay `${prefix}-NN` and timestamps stay
 * `now + offsetSec`. Every builder's LAST event sits at offset 0, which is what planner.ts relies on
 * to place a segment in time by moving its `now` alone.
 */
import type { CreateEventRequest } from '../types/domain';
import { buildExfil, ev, HOME, HOME_DEVICE, HOME_IP } from './builders.ts';
import type { Intensity, PlanContext } from './types.ts';

/**
 * The exact form DeterministicRuleService.formatOccurredAt produces for a PROCESS_START, which a
 * NETWORK_CONNECTION's processCreateTime must equal character for character (no time tolerance).
 * toISOString() keeps milliseconds, so they are dropped here rather than hoped away.
 */
export const processCreateTime = (atMs: number): string =>
  new Date(atMs).toISOString().replace(/\.\d{3}Z$/, 'Z');

/** A sub-context for one stage of a composed scenario: own event-ID namespace, own time anchor. */
const stage = (c: PlanContext, suffix: string, shiftSec: number): PlanContext => ({
  ...c,
  prefix: `${c.prefix}-${suffix}`,
  now: c.now + shiftSec * 1000,
});

/* ------------------------------------------------------------------ A. credential stuffing */

/**
 * One account, many source IPs: the shape that distinguishes credential stuffing from the
 * single-IP `brute` scenario. Detection-wise it leans on the SAME rule - AUTH_BURST counts failed
 * LOGINs per ENTITY inside a five-minute window and ignores the source IP entirely - so the
 * failures are generated well inside that window at every intensity.
 */
const STUFFING_IPS = ['45.83.64.12', '91.219.237.9', '185.220.101.44', '103.149.26.88', '194.26.229.17'];

export const STUFFING_FAILURES: Record<Intensity, number> = { LOW: 6, MEDIUM: 9, HIGH: 14 };

export const buildCredentialStuffing = (c: PlanContext): CreateEventRequest[] => {
  const failures = STUFFING_FAILURES[c.intensity];
  return [
    ...Array.from({ length: failures }, (_, i) =>
      ev(c, i, -(failures - i) * 14 - 6, 'LOGIN', {
        ip: STUFFING_IPS[i % STUFFING_IPS.length],
        location: 'Amsterdam|52.37|4.89',
        loginSuccess: false,
        authMethod: 'password',
        deviceFingerprint: 'Unknown|00:00:00:00:00:00|TLS1.2',
      }),
    ),
    ev(c, failures, 0, 'LOGIN', {
      ip: STUFFING_IPS[failures % STUFFING_IPS.length],
      location: 'Amsterdam|52.37|4.89',
      loginSuccess: true,
      authMethod: 'password',
      deviceFingerprint: 'Unknown|00:00:00:00:00:00|TLS1.2',
    }),
  ];
};

/* ------------------------------------------------------------------ B. process + external connection */

/**
 * The only shape NEW_PROCESS_EXTERNAL_CONNECTION accepts, built to its exact contract:
 *   - a PROCESS_START, then a NETWORK_CONNECTION, in that plan order (the rule looks the
 *     PROCESS_START up in the database, so it must be submitted - and persisted - first)
 *   - the same numeric pid in both
 *   - processCreateTime equal to the PROCESS_START's occurredAt truncated to whole seconds
 *   - a non-loopback remoteAddress (198.51.100.0/24, RFC 5737 documentation space)
 *   - the connection inside the rule's five-minute recency bound (20 s here)
 * Each pair uses its own pid, so the rule's one-alert-per-process suppression does not fold a
 * higher intensity back into a single alert.
 */
export const CONNECTION_PAIRS: Record<Intensity, number> = { LOW: 1, MEDIUM: 2, HIGH: 4 };

export const buildProcessConnection = (c: PlanContext): CreateEventRequest[] => {
  const pairs = CONNECTION_PAIRS[c.intensity];
  const out: CreateEventRequest[] = [];
  for (let k = 0; k < pairs; k++) {
    const base = -(pairs - 1 - k) * 60;
    const startOffset = base - 20;
    const pid = 8100 + k;
    out.push(
      ev(c, out.length, startOffset, 'PROCESS_START', {
        pid,
        processName: 'curl',
        parentPid: 1412,
        username: 'svc-deploy',
        executablePath: '/usr/bin/curl',
      }),
      ev(c, out.length + 1, base, 'NETWORK_CONNECTION', {
        protocol: 'tcp',
        localAddress: HOME_IP,
        localPort: 51000 + k,
        remoteAddress: '198.51.100.23',
        remotePort: 443,
        status: 'ESTABLISHED',
        pid,
        processName: 'curl',
        processCreateTime: processCreateTime(c.now + startOffset * 1000),
      }),
    );
  }
  return out;
};

/* ------------------------------------------------------------------ C. lateral movement */

/**
 * A hop chain: an internal LOGIN followed by an administrative share read, repeated. Both event
 * types are fully covered by the ML feature set (ip, location, resource, commandSequence,
 * deviceFingerprint), which is the only detector that can react - no lateral-movement rule exists.
 */
export const LATERAL_HOPS: Record<Intensity, number> = { LOW: 2, MEDIUM: 3, HIGH: 4 };

export const buildLateralMovement = (c: PlanContext): CreateEventRequest[] => {
  const hops = LATERAL_HOPS[c.intensity];
  const out: CreateEventRequest[] = [];
  for (let h = 0; h < hops; h++) {
    const base = -(hops - 1 - h) * 90;
    const host = `10.24.7.${40 + h}`;
    out.push(
      ev(c, out.length, base - 30, 'LOGIN', {
        ip: host,
        location: HOME,
        loginSuccess: true,
        authMethod: 'token',
        deviceFingerprint: HOME_DEVICE,
      }),
      ev(c, out.length + 1, base, 'FILE_ACCESS', {
        ip: host,
        location: HOME,
        resource: `//fileserver-0${h + 1}/admin$/scheduled-task.xml`,
        action: 'write',
        commandSequence: 'exec copy schtasks',
        sessionDurationMinutes: 4 + h,
        deviceFingerprint: HOME_DEVICE,
      }),
    );
  }
  return out;
};

/* ------------------------------------------------------------------ D. mixed attack */

/**
 * Three existing scenarios composed into one chronological campaign: credential stuffing (access),
 * process + external connection (execution and egress), then the unchanged Phase 1 exfiltration
 * sequence. Each stage gets its own event-ID namespace and its own time anchor, so IDs stay unique
 * and the stages cannot interleave.
 */
export const buildMixedAttack = (c: PlanContext): CreateEventRequest[] => [
  ...buildCredentialStuffing(stage(c, 'A', -900)),
  ...buildProcessConnection(stage(c, 'B', -420)),
  ...buildExfil(stage(c, 'C', 0)),
];

/* ------------------------------------------------------------------ E. port scan */

/**
 * Many short-lived connection attempts from one process to consecutive ports on one internal host.
 * processCreateTime is deliberately ABSENT: NEW_PROCESS_EXTERNAL_CONNECTION requires it (and a
 * correlated PROCESS_START), so this scenario is honestly outside every rule the backend has.
 */
export const SCAN_PORTS: Record<Intensity, number> = { LOW: 8, MEDIUM: 14, HIGH: 20 };

const SCAN_TARGET_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 1433, 3306, 3389, 5432, 5900, 8080];

export const buildPortScan = (c: PlanContext): CreateEventRequest[] => {
  const count = SCAN_PORTS[c.intensity];
  return Array.from({ length: count }, (_, i) =>
    ev(c, i, -(count - 1 - i) * 2, 'NETWORK_CONNECTION', {
      protocol: 'tcp',
      localAddress: HOME_IP,
      localPort: 40000 + i,
      remoteAddress: '10.24.7.60',
      remotePort: SCAN_TARGET_PORTS[i % SCAN_TARGET_PORTS.length],
      status: 'SYN_SENT',
      pid: 9123,
      processName: 'nmap',
    }),
  );
};

/* ------------------------------------------------------------------ F. suspicious process */

/**
 * A download-decode-execute chain of PROCESS_START events with a plausible parent/child lineage.
 * No NETWORK_CONNECTION follows, so NEW_PROCESS_EXTERNAL_CONNECTION cannot fire - and the ML
 * feature set reads none of these fields. Pure telemetry for correlation and triage practice.
 */
export const SUSPICIOUS_PROCESSES: Record<Intensity, number> = { LOW: 2, MEDIUM: 4, HIGH: 6 };

const PROCESS_CHAIN = [
  { processName: 'sh', executablePath: '/bin/sh' },
  { processName: 'curl', executablePath: '/usr/bin/curl' },
  { processName: 'base64', executablePath: '/usr/bin/base64' },
  { processName: 'chmod', executablePath: '/usr/bin/chmod' },
  { processName: 'python3', executablePath: '/usr/bin/python3' },
  { processName: 'crontab', executablePath: '/usr/bin/crontab' },
];

export const buildSuspiciousProcess = (c: PlanContext): CreateEventRequest[] => {
  const count = SUSPICIOUS_PROCESSES[c.intensity];
  return Array.from({ length: count }, (_, i) => {
    const step = PROCESS_CHAIN[i % PROCESS_CHAIN.length];
    return ev(c, i, -(count - 1 - i) * 12, 'PROCESS_START', {
      pid: 7200 + i,
      processName: step.processName,
      parentPid: i === 0 ? 1412 : 7200 + i - 1,
      username: 'svc-deploy',
      executablePath: step.executablePath,
    });
  });
};

/* ------------------------------------------------------------------ benign noise */

/**
 * Ordinary workday activity from the usual place and device, used to pad a run. It goes through the
 * same builder, the same validator and the same engine as every other event. It is NOT a guarantee
 * of silence: the ML ensemble scores these events like any other, and repeated runs shift an
 * entity's own behavioural profile.
 */
const NOISE_SHAPES: ((c: PlanContext, i: number, offsetSec: number) => CreateEventRequest)[] = [
  (c, i, o) => ev(c, i, o, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'password', deviceFingerprint: HOME_DEVICE }),
  (c, i, o) => ev(c, i, o, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/docs/team/standup-notes.md', action: 'read', deviceFingerprint: HOME_DEVICE }),
  (c, i, o) => ev(c, i, o, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/projects/sentinelflow/README.md', action: 'read', deviceFingerprint: HOME_DEVICE }),
  (c, i, o) => ev(c, i, o, 'LOGOUT', { ip: HOME_IP, location: HOME, sessionDurationMinutes: 26, deviceFingerprint: HOME_DEVICE }),
];

export const buildNoise = (c: PlanContext, count: number): CreateEventRequest[] =>
  Array.from({ length: Math.max(0, count) }, (_, i) =>
    NOISE_SHAPES[i % NOISE_SHAPES.length](c, i, -(count - 1 - i) * 7),
  );

/** Benign events a noise percentage adds to a scenario of `scenarioEvents` events. */
export const noiseCount = (scenarioEvents: number, percent: number): number =>
  percent <= 0 ? 0 : Math.max(1, Math.round((scenarioEvents * percent) / 100));
