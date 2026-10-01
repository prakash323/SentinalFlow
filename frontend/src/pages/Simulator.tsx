import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import {
  Bug,
  DatabaseZap,
  FlaskConical,
  KeyRound,
  Laptop,
  Play,
  Plane,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { eventsApi } from '../api/endpoints';
import { useEntities } from '../components/EntitySelect';
import { useToast } from '../components/feedback';
import {
  Button,
  Card,
  CardHead,
  DecisionBadge,
  EmptyState,
  LinkButton,
  PageHeader,
  ProcessingBadge,
  ScoreMeter,
  SeverityBadge,
} from '../components/ui';
import { formatApiError, fmtTimeSec } from '../utils/format';
import type { CreateEventRequest, EventTrail } from '../types/domain';

/* ------------------------------------------------------------------ */
/* Scenarios                                                           */
/* ------------------------------------------------------------------ */

type Ctx = { entityId: string; prefix: string; now: number };

type Scenario = {
  id: string;
  title: string;
  blurb: string;
  icon: LucideIcon;
  tone: string;
  expect: string;
  build: (c: Ctx) => CreateEventRequest[];
};

const HOME = 'Pune|18.52|73.86';
const HOME_IP = '10.24.7.18';
const HOME_DEVICE = 'Ubuntu 22.04|b0:17:7e:e2:b5:c2|TLS1.2';

const ev = (
  c: Ctx,
  i: number,
  offsetSec: number,
  eventType: string,
  payload: Record<string, unknown>,
): CreateEventRequest => ({
  eventId: `${c.prefix}-${String(i + 1).padStart(2, '0')}`,
  entityId: c.entityId,
  eventType,
  eventVersion: 'v1',
  occurredAt: new Date(c.now + offsetSec * 1000).toISOString(),
  source: 'simulator',
  payload,
});

const SCENARIOS: Scenario[] = [
  {
    id: 'routine',
    title: 'Routine workday',
    blurb: 'A normal login, a file open and a logout from the usual place and device.',
    icon: ShieldCheck,
    tone: 'ok',
    expect: 'Low scores, no alert',
    build: (c) => [
      ev(c, 0, -240, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'password', deviceFingerprint: HOME_DEVICE }),
      ev(c, 1, -120, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/docs/handbook.pdf', action: 'read', deviceFingerprint: HOME_DEVICE }),
      ev(c, 2, 0, 'LOGOUT', { ip: HOME_IP, location: HOME, sessionDurationMinutes: 38, deviceFingerprint: HOME_DEVICE }),
    ],
  },
  {
    id: 'brute',
    title: 'Brute-force login burst',
    blurb: 'Eight rapid failed logins from one foreign IP, ending in a successful login.',
    icon: KeyRound,
    tone: 'critical',
    expect: 'Failure-rate spike from a single source IP',
    build: (c) => [
      ...Array.from({ length: 8 }, (_, i) =>
        ev(c, i, -80 + i * 8, 'LOGIN', { ip: '185.220.101.44', location: 'Moscow|55.75|37.61', loginSuccess: false, authMethod: 'password', deviceFingerprint: 'Unknown|00:00:00:00:00:00|TLS1.0' }),
      ),
      ev(c, 8, 0, 'LOGIN', { ip: '185.220.101.44', location: 'Moscow|55.75|37.61', loginSuccess: true, authMethod: 'password', deviceFingerprint: 'Unknown|00:00:00:00:00:00|TLS1.0' }),
    ],
  },
  {
    id: 'travel',
    title: 'Impossible travel',
    blurb: 'A login in Pune followed five minutes later by a login from Lagos.',
    icon: Plane,
    tone: 'high',
    expect: 'Implausible geo-velocity between logins',
    build: (c) => [
      ev(c, 0, -300, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'password', deviceFingerprint: HOME_DEVICE }),
      ev(c, 1, 0, 'LOGIN', { ip: '102.89.34.7', location: 'Lagos|6.52|3.37', loginSuccess: true, authMethod: 'password', deviceFingerprint: 'Windows 11|3c:22:fb:10:9a:77|TLS1.3' }),
    ],
  },
  {
    id: 'privesc',
    title: 'Privilege escalation',
    blurb: 'A session that runs sudo/exec/download/delete against sensitive system files.',
    icon: Bug,
    tone: 'high',
    expect: 'Unusual command sequence on a sensitive resource',
    build: (c) => [
      ev(c, 0, -150, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'token', deviceFingerprint: HOME_DEVICE }),
      ev(c, 1, -60, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/etc/shadow', commandSequence: 'sudo exec download', sessionDurationMinutes: 210, deviceFingerprint: HOME_DEVICE }),
      ev(c, 2, 0, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/var/backups/db.sql', commandSequence: 'sudo exec download delete', sessionDurationMinutes: 240, deviceFingerprint: HOME_DEVICE }),
    ],
  },
  {
    id: 'exfil',
    title: 'Data exfiltration',
    blurb: 'Six back-to-back downloads of sensitive finance documents in a very long session.',
    icon: DatabaseZap,
    tone: 'critical',
    expect: 'Resource novelty + sensitive-access volume',
    build: (c) =>
      Array.from({ length: 6 }, (_, i) =>
        ev(c, i, -50 + i * 10, 'FILE_ACCESS', {
          ip: HOME_IP,
          location: HOME,
          resource: `/finance/payroll/2026-0${i + 1}.xlsx`,
          action: 'download',
          commandSequence: 'download download',
          sessionDurationMinutes: 300,
          deviceFingerprint: HOME_DEVICE,
        }),
      ),
  },
  {
    id: 'device',
    title: 'Unknown device',
    blurb: 'A login from a never-seen device and browser fingerprint using an unusual auth method.',
    icon: Laptop,
    tone: 'medium',
    expect: 'Device-fingerprint novelty',
    build: (c) => [
      ev(c, 0, 0, 'LOGIN', { ip: '203.0.113.77', location: 'Singapore|1.35|103.82', loginSuccess: true, authMethod: 'certificate', deviceFingerprint: 'Kali 2026.2|de:ad:be:ef:00:01|TLS1.3' }),
    ],
  },
];

/* ------------------------------------------------------------------ */
/* Run tracking                                                        */
/* ------------------------------------------------------------------ */

type Row = {
  request: CreateEventRequest;
  sendError?: string;
  trail?: EventTrail;
  scenario: string;
};

const MAX_WAIT_MS = 90000;

export default function Simulator() {
  const toast = useToast();
  const entities = useEntities();
  const [entityId, setEntityId] = useState('');
  const [rows, setRows] = useState<Row[]>([]);
  const [sending, setSending] = useState<string | null>(null);
  const startedAt = useRef(0);

  const list = entities.data?.content ?? [];
  useEffect(() => {
    if (!entityId && list.length) setEntityId(list[0].entityId);
  }, [list, entityId]);

  // Poll the pipeline trail of every event that has not reached a terminal state.
  useEffect(() => {
    const open = rows.filter((r) => !r.sendError && r.trail?.processingStatus !== 'PROCESSED' && r.trail?.processingStatus !== 'FAILED');
    if (!open.length || Date.now() - startedAt.current > MAX_WAIT_MS) return;

    const t = setTimeout(async () => {
      const updates = await Promise.all(
        open.map(async (r) => {
          try {
            return [r.request.eventId, await eventsApi.trail(r.request.eventId)] as const;
          } catch {
            return null;
          }
        }),
      );
      setRows((cur) =>
        cur.map((r) => {
          const hit = updates.find((u) => u && u[0] === r.request.eventId);
          return hit ? { ...r, trail: hit[1] } : r;
        }),
      );
    }, 1400);

    return () => clearTimeout(t);
  }, [rows]);

  const run = async (scenario: Scenario) => {
    if (!entityId) return;
    setSending(scenario.id);
    startedAt.current = Date.now();

    const ctx: Ctx = { entityId, prefix: `SIM-${scenario.id.toUpperCase()}-${Date.now().toString(36).toUpperCase()}`, now: Date.now() };
    const requests = scenario.build(ctx);
    const added: Row[] = [];

    // Sent strictly in order: the detector's per-entity state is time-ordered.
    for (const request of requests) {
      try {
        await eventsApi.create(request);
        added.push({ request, scenario: scenario.title });
      } catch (e) {
        added.push({ request, scenario: scenario.title, sendError: formatApiError(e, 'Rejected') });
      }
      setRows((cur) => [...added.slice(-1), ...cur.filter((r) => r.request.eventId !== request.eventId)]);
    }

    const failed = added.filter((r) => r.sendError).length;
    if (failed) toast.error(`${failed} of ${requests.length} events were rejected`, added.find((r) => r.sendError)?.sendError);
    else toast.success(`${scenario.title}: ${requests.length} event${requests.length === 1 ? '' : 's'} sent`, 'Tracking their pipeline outcome below.');
    setSending(null);
  };

  const summary = useMemo(() => {
    const valid = rows.filter((r) => !r.sendError);
    const done = valid.filter((r) => r.trail && r.trail.processingStatus !== 'PENDING');
    const scores = done.map((r) => r.trail!.prediction?.fusedScore ?? r.trail!.prediction?.anomalyScore ?? 0);
    return {
      sent: valid.length,
      processed: done.length,
      alerts: done.filter((r) => r.trail!.alert).length,
      max: scores.length ? Math.max(...scores) : null,
    };
  }, [rows]);

  return (
    <>
      <PageHeader
        eyebrow="Workspace"
        title="Simulator"
        description="Replay realistic behaviour through the real pipeline — REST → PostgreSQL → Kafka → ML ensemble → alert policy → incident. Nothing is faked: every result below comes from the live backend."
        actions={<LinkButton to="/events/new" icon={FlaskConical}>Custom event</LinkButton>}
      />

      <Card>
        <div className="sim-target">
          <label className="field" style={{ maxWidth: 360 }}>
            <span>Target entity</span>
            <select value={entityId} onChange={(e) => setEntityId(e.target.value)} disabled={!list.length}>
              {!list.length && <option value="">No entities available</option>}
              {list.map((e) => <option key={e.entityId} value={e.entityId}>{e.entityId}{e.displayName ? ` — ${e.displayName}` : ''}</option>)}
            </select>
          </label>
          <p className="muted sim-note">
            The detector keeps per-entity behavioural state, so repeated runs against the same entity gradually change what counts as “normal”.
            Pick a different entity for a clean baseline.
          </p>
        </div>
      </Card>

      {!list.length && !entities.isLoading ? (
        <Card style={{ marginTop: 12 }}>
          <EmptyState
            title="Create an entity first"
            text="Events must belong to a monitored entity. An administrator can add one from the Entities page."
            action={<LinkButton to="/entities" variant="primary" size="sm">Go to entities</LinkButton>}
          />
        </Card>
      ) : (
        <div className="scenario-grid">
          {SCENARIOS.map((s, i) => (
            <motion.div key={s.id} initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
              <div className={`card scenario tone-${s.tone}`}>
                <div className="scenario-top">
                  <span className="scenario-icon"><s.icon size={20} /></span>
                  <span className="scenario-count">{s.build({ entityId: 'x', prefix: 'x', now: 0 }).length} events</span>
                </div>
                <h2>{s.title}</h2>
                <p>{s.blurb}</p>
                <div className="scenario-expect"><span>Exercises</span>{s.expect}</div>
                <Button
                  variant={s.tone === 'ok' ? 'secondary' : 'primary'}
                  icon={Play}
                  loading={sending === s.id}
                  disabled={!!sending || !entityId}
                  onClick={() => run(s)}
                  block
                >
                  {sending === s.id ? 'Sending…' : 'Run scenario'}
                </Button>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      <Card flush style={{ marginTop: 12 }}>
        <div className="card-section">
          <CardHead
            kicker="Results"
            kickerIcon={FlaskConical}
            title="Pipeline outcomes"
            description="Each event is tracked until the pipeline finishes processing it."
            actions={rows.length > 0 && <Button variant="ghost" size="sm" icon={Trash2} onClick={() => setRows([])}>Clear</Button>}
          />
          {rows.length > 0 && (
            <div className="sim-summary">
              <div><span>Sent</span><b>{summary.sent}</b></div>
              <div><span>Processed</span><b>{summary.processed}</b></div>
              <div><span>Alerts raised</span><b>{summary.alerts}</b></div>
              <div><span>Peak score</span><b className="mono">{summary.max != null ? summary.max.toFixed(3) : '—'}</b></div>
            </div>
          )}
        </div>

        {rows.length === 0 ? (
          <EmptyState title="No runs yet" text="Choose a scenario above to send events through the detection pipeline." icon={FlaskConical} />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Time</th><th>Event</th><th>Scenario</th><th>Pipeline</th><th>Score</th><th>Decision</th><th>Alert</th></tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const p = r.trail?.prediction;
                  return (
                    <tr key={r.request.eventId}>
                      <td className="mono muted">{fmtTimeSec(r.request.occurredAt)}</td>
                      <td>
                        {r.sendError ? <span className="mono">{r.request.eventId}</span> : <Link className="mono link" to={`/events/${encodeURIComponent(r.request.eventId)}`}>{r.request.eventId}</Link>}
                        <div className="muted" style={{ fontSize: 11.5 }}>{r.request.eventType}</div>
                      </td>
                      <td>{r.scenario}</td>
                      <td>
                        {r.sendError ? <span className="field-error" title={r.sendError}>Rejected — {r.sendError}</span> : <ProcessingBadge value={r.trail?.processingStatus ?? 'PENDING'} />}
                      </td>
                      <td>{p ? <ScoreMeter value={p.fusedScore ?? p.anomalyScore} /> : <span className="muted">—</span>}</td>
                      <td>{p ? <DecisionBadge value={p.decision} /> : <span className="muted">—</span>}</td>
                      <td>{r.trail?.alert ? <Link to={`/alerts/${r.trail.alert.id}`}><SeverityBadge value={r.trail.alert.severity} /></Link> : <span className="muted">—</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
