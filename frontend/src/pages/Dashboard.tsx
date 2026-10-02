import { useMemo, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  BellRing,
  CheckCircle2,
  Cpu,
  Radar,
  RefreshCw,
  Search,
  ShieldAlert,
  XCircle,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { alertsApi, dashboardApi, entitiesApi, incidentsApi, systemApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import {
  AlertStatusBadge,
  Button,
  DecisionBadge,
  EmptyState,
  ErrorState,
  IncidentStatusBadge,
  LinkButton,
  ProcessingBadge,
  ScoreMeter,
  Segmented,
  SeverityBadge,
  Skeleton,
} from '../components/ui';
import { NAV_GROUPS } from '../layouts/nav';
import { useAiProviderState } from '../utils/aiProviderStatus';
import { fmtDate, fmtTimeSec, formatApiError, humanize, num, timeAgo } from '../utils/format';
import { SEVERITY_ORDER, scoreTone, severityTone, toneColor } from '../utils/tone';
import type { Tone } from '../utils/tone';
import type { DashboardSummary, Incident } from '../types/domain';
import '../styles/dashboard.css';

const RANGES = [
  { value: 8, label: '8h' },
  { value: 24, label: '24h' },
  { value: 72, label: '3d' },
];

const HEALTH_NAMES: Record<string, string> = {
  'Spring Boot API': 'API',
  'ML service': 'ML',
  PostgreSQL: 'Postgres',
};

const tone = (t: Tone) => ({ ['--tone' as string]: toneColor(t) }) as CSSProperties;
const pad = (n: number) => String(n).padStart(2, '0');
const pct = (n: number, total: number) => (total ? `${Math.round((n / total) * 100)}%` : '—');

const dayMonth = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' });
const dayMonthYear = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: '2-digit' });

/** Relative time for the last week ("17 hr ago"), then a short date ("21 Aug") so narrow panels never overflow. */
function when(iso?: string | null) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  if (Date.now() - d.getTime() < 7 * 86400000) return timeAgo(iso);
  return (d.getFullYear() === new Date().getFullYear() ? dayMonth : dayMonthYear).format(d);
}

/** Axis label in the viewer's local time (24h), so it matches what the tooltip shows. */
function tickLabel(bucketStart: string, hours: number, fallback: string) {
  const d = new Date(bucketStart);
  if (Number.isNaN(d.getTime())) return fallback;
  const hh = `${pad(d.getHours())}:00`;
  return hours > 24 ? `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hh}` : hh;
}

const cellError = (e: unknown, what: string) => formatApiError(e, `Unable to load ${what}`);

/* ---------- building blocks ---------- */

function Panel({
  className,
  title,
  description,
  actions,
  children,
}: {
  className: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className={`soc-panel ${className}`}>
      <header className="soc-panel-head">
        <div>
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {actions && <div className="soc-panel-actions">{actions}</div>}
      </header>
      <div className="soc-panel-body">{children}</div>
    </section>
  );
}

const PanelLink = ({ to, children }: { to: string; children: ReactNode }) => (
  <Link className="soc-link" to={to}>{children} <ArrowUpRight size={13} /></Link>
);

/** Headline number card: a real backend total plus a small real visual underneath. */
function MetricCard({
  className,
  label,
  value,
  valueTone,
  sub,
  to,
  children,
}: {
  className: string;
  label: string;
  value: ReactNode;
  valueTone: Tone;
  sub: ReactNode;
  to: string;
  children: ReactNode;
}) {
  return (
    <section className={`soc-panel soc-metric ${className}`} style={tone(valueTone)}>
      <header className="soc-metric-head">
        <h2>{label}</h2>
        <Link className="soc-link" to={to} aria-label={`Open ${label}`}><ArrowUpRight size={14} /></Link>
      </header>
      <div className="soc-metric-value">{value}</div>
      <div className="soc-metric-sub">{sub}</div>
      <div className="soc-metric-visual">{children}</div>
    </section>
  );
}

type TipProps = { active?: boolean; payload?: { dataKey: string; value: number; payload: { bucketStart: string } }[] };

function ChartTip({ active, payload }: TipProps) {
  if (!active || !payload?.length) return null;
  const events = payload.find((p) => p.dataKey === 'events')?.value;
  const alerts = payload.find((p) => p.dataKey === 'alerts')?.value;
  return (
    <div className="soc-tip">
      <strong>{fmtDate(payload[0].payload.bucketStart)}</strong>
      {events != null && <div><i style={{ background: 'var(--c-info)' }} />Events <b>{events}</b></div>}
      {alerts != null && <div><i style={{ background: 'var(--accent-strong)' }} />Alerts <b>{alerts}</b></div>}
    </div>
  );
}

/** One tile per trend bucket, shaded by its event count relative to the busiest bucket. */
function EventTiles({ trend, hours }: { trend: DashboardSummary['trend']; hours: number }) {
  const max = Math.max(1, ...trend.map((t) => t.events));
  return (
    <div className="soc-tiles" data-buckets={trend.length} role="img" aria-label={`Events per hour over the last ${hours} hours`}>
      {trend.map((t) => (
        <span
          key={t.bucketStart}
          className={t.events ? undefined : 'is-empty'}
          style={{ ['--level' as string]: t.events / max } as CSSProperties}
          title={`${tickLabel(t.bucketStart, hours, t.label)} · ${t.events} events`}
        />
      ))}
    </div>
  );
}

const INCIDENT_ICON: Record<string, LucideIcon> = {
  OPEN: ShieldAlert,
  INVESTIGATING: Search,
  RESOLVED: CheckCircle2,
  CLOSED: CheckCircle2,
};

function IncidentItem({ incident }: { incident: Incident }) {
  const Icon = INCIDENT_ICON[String(incident.status).toUpperCase()] ?? ShieldAlert;
  const active = incident.status === 'OPEN' || incident.status === 'INVESTIGATING';
  return (
    <Link
      to={`/incidents/${incident.id}`}
      className={`soc-incident${active ? '' : ' is-done'}`}
      style={tone(active ? severityTone(incident.maxSeverity) : 'ok')}
      title={incident.summary}
    >
      <span className="soc-incident-icon"><Icon size={15} /></span>
      <span className="soc-incident-text">
        <strong className="mono">{incident.incidentKey}</strong>
        <span>{incident.entityId} · {incident.alertCount} alert{incident.alertCount === 1 ? '' : 's'} · {when(incident.updatedAt)}</span>
      </span>
      <span className="soc-incident-badges">
        {incident.maxSeverity && <SeverityBadge value={incident.maxSeverity} />}
        <IncidentStatusBadge value={incident.status} />
      </span>
    </Link>
  );
}

/* ---------- page ---------- */

export default function Dashboard() {
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const [hours, setHours] = useState(8);

  // The summary is the one aggregate call (shared with the shell's open-alert badge);
  // everything else is a small, server-filtered query.
  const summary = useQuery({
    queryKey: ['dashboard', hours],
    queryFn: () => dashboardApi.summary(hours),
    refetchInterval: 30000,
    staleTime: 10000,
    placeholderData: (prev) => prev,
  });

  const status = useQuery({ queryKey: ['system-status'], queryFn: systemApi.status, refetchInterval: 20000, retry: false });

  // Newest first (the API sorts by createdAt desc).
  const critical = useQuery({
    queryKey: ['alerts', 'dashboard-critical'],
    queryFn: () => alertsApi.list({ severity: 'CRITICAL', size: 10 }),
    refetchInterval: 30000,
  });

  // Newest first, every status, so resolved work is visible next to open work.
  const incidents = useQuery({
    queryKey: ['incidents', 'dashboard-recent'],
    queryFn: () => incidentsApi.list({ size: 5 }),
    refetchInterval: 30000,
  });

  // Not on the summary: read the total from a one-row page.
  const entityCount = useQuery({
    queryKey: ['entities', 'count'],
    queryFn: () => entitiesApi.list({ size: 1 }),
    staleTime: 60000,
  });

  const ai = useAiProviderState();
  const data = summary.data;

  const derived = useMemo(() => {
    if (!data) return null;
    const bySeverity = data.alertsBySeverity ?? {};
    const sev = SEVERITY_ORDER.map((s) => ({ key: s, label: humanize(s), value: bySeverity[s] ?? 0, tone: severityTone(s) }));
    const processed = data.eventsByProcessingStatus?.PROCESSED ?? 0;
    const pending = data.eventsByProcessingStatus?.PENDING ?? 0;
    const failed = data.eventsByProcessingStatus?.FAILED ?? 0;
    return {
      sev,
      sevTotal: sev.reduce((a, s) => a + s.value, 0),
      windowEvents: data.trend.reduce((a, t) => a + t.events, 0),
      windowAlerts: data.trend.reduce((a, t) => a + t.alerts, 0),
      openAlerts: data.alertsByStatus?.OPEN ?? 0,
      critical: bySeverity.CRITICAL ?? 0,
      high: bySeverity.HIGH ?? 0,
      processed,
      pending,
      failed,
      pipeTotal: processed + pending + failed,
      chart: data.trend.map((t) => ({ ...t, tick: tickLabel(t.bucketStart, hours, t.label) })),
      types: Object.entries(data.eventsByType ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8),
    };
  }, [data, hours]);

  const refreshAll = () => {
    summary.refetch();
    status.refetch();
    critical.refetch();
    incidents.refetch();
    entityCount.refetch();
  };
  const refreshing = summary.isFetching || status.isFetching || critical.isFetching || incidents.isFetching;

  const severityPills = derived && (
    <nav className="soc-sevbar" aria-label="Alerts by severity">
      <Link to="/alerts" className="is-all">All alerts <b>{num(data?.alertCount)}</b></Link>
      {derived.sev.map((s) => (
        <Link key={s.key} to={`/alerts?severity=${s.key}`} style={tone(s.tone)}>
          <i />{s.label} <b>{num(s.value)}</b>
        </Link>
      ))}
    </nav>
  );

  const header = (
    <header className="soc-head">
      <div className="soc-head-title">
        <h1>Security Operations Center</h1>
        <p>
          {status.data?.overall === 'UP'
            ? 'All monitored services are operational.'
            : status.data
              ? `Platform status: ${humanize(status.data.overall)} — see System Status.`
              : status.isError
                ? 'System status is unavailable.'
                : 'Checking system status…'}
          {data && ` ${num(data.totalEvents)} events analysed, ${num(derived?.openAlerts)} alerts open, ${num(data.openIncidentCount)} incidents open.`}
        </p>
      </div>
      <div className="soc-head-actions">
        {severityPills}
        <Segmented value={hours} onChange={setHours} options={RANGES} />
        <Button variant="secondary" size="sm" icon={RefreshCw} loading={refreshing} onClick={refreshAll}>Refresh</Button>
      </div>
    </header>
  );

  if (summary.isLoading) {
    return (
      <>
        {header}
        <div className="soc-grid" aria-busy="true">
          {['soc-alerts', 'soc-events', 'soc-health', 'soc-incidents'].map((c) => (
            <section className={`soc-panel ${c}`} key={c}><Skeleton h={170} /></section>
          ))}
          <section className="soc-panel soc-pipeline"><Skeleton h={70} /></section>
          <section className="soc-panel soc-activity"><Skeleton h={240} /></section>
        </div>
      </>
    );
  }

  if (summary.isError || !data || !derived) {
    return (
      <>
        {header}
        <section className="soc-panel"><ErrorState message={formatApiError(summary.error, 'Unable to reach the platform API.')} onRetry={() => summary.refetch()} /></section>
      </>
    );
  }

  const note =
    derived.failed > 0
      ? { tone: 'critical' as Tone, icon: XCircle, text: `${derived.failed} event${derived.failed === 1 ? '' : 's'} failed processing`, sub: 'Check System Status and the Kafka dead-letter topic.', to: '/system' }
      : derived.critical + derived.high > 0
        ? { tone: 'high' as Tone, icon: AlertTriangle, text: `${derived.critical} critical and ${derived.high} high-severity alerts on record`, sub: `${derived.openAlerts} still open`, to: '/alerts?severity=CRITICAL' }
        : derived.openAlerts > 0
          ? { tone: 'medium' as Tone, icon: BellRing, text: `${derived.openAlerts} open alerts awaiting triage`, sub: 'No critical or high-severity alerts on record.', to: '/alerts?status=OPEN' }
          : { tone: 'ok' as Tone, icon: CheckCircle2, text: 'No open alerts', sub: 'The investigation queue is clear.', to: '/alerts' };
  const NoteIcon = note.icon;

  const components = status.data?.components ?? [];
  const upCount = components.filter((c) => c.status === 'UP').length;
  const healthTone: Tone = status.isError ? 'critical' : !status.data ? 'neutral' : upCount === components.length ? 'ok' : 'critical';

  // Quick navigation reuses the sidebar's routes, labels, icons and admin-only rules.
  const navCounts: Record<string, string> = {
    '/events': `${num(data.totalEvents)} stored`,
    '/predictions': `${num(data.predictionCount)} scored`,
    '/alerts': `${num(derived.openAlerts)} open`,
    '/incidents': `${num(data.openIncidentCount)} open`,
    '/entities': entityCount.data ? `${num(entityCount.data.totalElements)} monitored` : '—',
    '/system': status.data ? humanize(status.data.overall) : status.isError ? 'Unavailable' : 'Checking…',
  };
  const quickNav = NAV_GROUPS.flatMap((g) => g.items).filter((i) => i.to !== '/dashboard' && (!i.adminOnly || isAdmin));

  return (
    <>
      {header}

      <Link to={note.to} className={`soc-note tone-${note.tone}`}>
        <NoteIcon size={15} />
        <span className="soc-note-text"><strong>{note.text}</strong><span>{note.sub}</span></span>
        <ArrowUpRight size={14} />
      </Link>

      <div className="soc-grid">
        {/* ---- headline metrics: every value is a backend number ---- */}
        <MetricCard
          className="soc-alerts"
          label="Alerts raised"
          value={num(data.alertCount)}
          valueTone="critical"
          sub={<><b>{num(derived.windowAlerts)}</b> in the last {hours}h · {num(derived.openAlerts)} open</>}
          to="/alerts"
        >
          {derived.windowAlerts === 0 ? (
            <div className="soc-metric-empty">No alerts in this window</div>
          ) : (
            <div className="soc-spark" role="img" aria-label={`Alerts per hour over the last ${hours} hours`}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={derived.chart} margin={{ top: 4, right: 2, left: 2, bottom: 0 }}>
                  <defs>
                    <linearGradient id="soc-alert-fill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--c-critical)" stopOpacity={0.45} />
                      <stop offset="100%" stopColor="var(--c-critical)" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <Tooltip content={<ChartTip />} cursor={{ stroke: 'var(--border-strong)' }} isAnimationActive={false} />
                  <Area type="monotone" dataKey="alerts" stroke="var(--c-critical)" strokeWidth={2} fill="url(#soc-alert-fill)" dot={false} activeDot={{ r: 3 }} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </MetricCard>

        <MetricCard
          className="soc-events"
          label="Security events"
          value={num(data.totalEvents)}
          valueTone="info"
          sub={<><b>{num(derived.windowEvents)}</b> in the last {hours}h · {num(data.predictionCount)} scored</>}
          to="/events"
        >
          <EventTiles trend={data.trend} hours={hours} />
        </MetricCard>

        <MetricCard
          className={`soc-health${healthTone === 'critical' ? ' is-alarm' : ''}`}
          label="System health"
          value={status.data ? `${upCount}/${components.length}` : status.isError ? 'Down' : '…'}
          valueTone={healthTone}
          sub={status.data ? <>services up · checked {fmtTimeSec(status.data.checkedAt)}</> : status.isError ? 'The status endpoint did not respond' : 'Checking…'}
          to="/system"
        >
          {status.isLoading ? (
            <Skeleton h={88} />
          ) : status.isError ? (
            <ErrorState title="Status unavailable" message="The system status endpoint did not respond." onRetry={() => status.refetch()} />
          ) : (
            <>
              <div className="soc-health-bars">
                {components.map((c) => {
                  const up = c.status === 'UP';
                  return (
                    <div key={c.name} className="soc-health-bar" style={tone(up ? 'ok' : 'critical')} title={`${c.name}: ${c.status}${c.detail ? ` — ${c.detail}` : ''}`}>
                      <span className="bar" />
                      <span className="name">{HEALTH_NAMES[c.name] ?? c.name}</span>
                      {/* the API reports 0 ms for the Spring Boot row (it is answering the request), so only show real probe latencies */}
                      <span className="val">{!up ? 'Down' : c.latencyMs ? `${c.latencyMs} ms` : 'Up'}</span>
                    </div>
                  );
                })}
              </div>
              <p className="soc-health-note" title="There is no AI health probe. This only reflects the outcome of the most recent AI request in this session.">
                AI provider: {ai.state === 'unavailable' ? `last request returned 503 (${timeAgo(new Date(ai.at).toISOString())})` : 'not probed, used on demand'}
              </p>
            </>
          )}
        </MetricCard>

        {/* ---- recent incidents ---- */}
        <Panel className="soc-incidents" title="Recent security incidents" description="Newest first, all statuses">
          {incidents.isLoading ? (
            <Skeleton h={260} />
          ) : incidents.isError ? (
            <ErrorState title="Couldn’t load incidents" message={cellError(incidents.error, 'incidents')} onRetry={() => incidents.refetch()} />
          ) : !incidents.data?.content.length ? (
            <EmptyState title="No incidents yet" text="Correlated alerts will appear here." icon={ShieldAlert} />
          ) : (
            <div className="soc-incident-list">
              {incidents.data.content.map((i) => <IncidentItem key={i.id} incident={i} />)}
            </div>
          )}
          <Link className="soc-panel-foot" to="/incidents">View all incidents <ArrowRight size={14} /></Link>
        </Panel>

        {/* ---- processing pipeline (real counts) ---- */}
        <section className="soc-panel soc-pipeline">
          <div className="soc-pipe-main">
            <div className="soc-pipe-top">
              <h2>Processing pipeline</h2>
              <span className="soc-pipe-share">{pct(derived.processed, derived.pipeTotal)} processed</span>
            </div>
            <div className="soc-pipe-value">
              <b>{num(derived.processed)}</b>
              <span>/ {num(derived.pipeTotal)} events</span>
            </div>
            <div className="soc-stack" role="img" aria-label={`Processed ${derived.processed}, pending ${derived.pending}, failed ${derived.failed}`}>
              {derived.processed > 0 && <div style={{ flex: derived.processed, background: 'var(--c-ok)' }} />}
              {derived.pending > 0 && <div style={{ flex: derived.pending, background: 'var(--c-medium)' }} />}
              {derived.failed > 0 && <div style={{ flex: derived.failed, background: 'var(--c-critical)' }} />}
            </div>
            <div className="soc-pipe-legend">
              <span style={tone('ok')}><i />Processed <b>{num(derived.processed)}</b></span>
              <span style={tone('medium')}><i />Pending <b>{num(derived.pending)}</b></span>
              <span style={tone('critical')}><i />Failed <b>{num(derived.failed)}</b></span>
            </div>
          </div>
          <div className="soc-pipe-side">
            <p>
              {derived.failed > 0
                ? `${num(derived.failed)} event${derived.failed === 1 ? '' : 's'} failed processing and ${num(derived.pending)} are pending.`
                : derived.pending > 0
                  ? `${num(derived.pending)} event${derived.pending === 1 ? ' is' : 's are'} still pending.`
                  : 'Every stored event has been processed.'}
            </p>
            <LinkButton to="/system" variant="primary" icon={Cpu}>Open system status</LinkButton>
          </div>
        </section>

        {/* ---- quick navigation ---- */}
        <Panel className="soc-nav" title="Operations" description="Jump to a workspace">
          <div className="soc-nav-grid">
            {quickNav.map(({ to, label, icon: Icon }) => (
              <Link key={to} to={to} className="soc-nav-tile">
                <span className="soc-nav-icon"><Icon size={16} /></span>
                <strong>{label}</strong>
                <span>{navCounts[to] ?? 'Open'}</span>
              </Link>
            ))}
          </div>
        </Panel>

        {/* ---- severity distribution ---- */}
        <Panel className="soc-severity" title="Alert severity" description="All alerts on record" actions={<PanelLink to="/alerts">Alerts</PanelLink>}>
          {derived.sevTotal === 0 ? (
            <EmptyState title="No alerts yet" text="Alerts appear here once the pipeline raises one." icon={BellRing} />
          ) : (
            <>
              <div className="soc-sev-chart" role="img" aria-label={derived.sev.map((s) => `${s.label} ${s.value}`).join(', ')}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={derived.sev} margin={{ top: 6, right: 4, left: 0, bottom: 0 }} barCategoryGap="28%">
                    <CartesianGrid vertical={false} stroke="var(--grid-line)" />
                    <XAxis dataKey="label" tickLine={false} axisLine={{ stroke: 'var(--border-strong)' }} tick={{ fontSize: 11, fill: 'var(--muted)' }} />
                    <YAxis allowDecimals={false} width={36} tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: 'var(--muted)' }} />
                    <Tooltip cursor={{ fill: 'var(--panel-hover)' }} isAnimationActive={false} contentStyle={{ background: 'var(--panel-3)', border: '1px solid var(--border-strong)', borderRadius: 6, fontSize: 12 }} labelStyle={{ color: 'var(--text)' }} itemStyle={{ color: 'var(--text-2)' }} />
                    <Bar dataKey="value" name="Alerts" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                      {derived.sev.map((s) => <Cell key={s.key} fill={toneColor(s.tone)} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="soc-stats">
                <div><span>Open</span><b>{num(derived.openAlerts)}</b></div>
                <div><span>Critical share</span><b>{pct(derived.critical, derived.sevTotal)}</b></div>
                <div><span>Policy</span><b title={status.data?.policy.version}>{status.data?.policy.version ?? '—'}</b></div>
              </div>
            </>
          )}
        </Panel>

        {/* ---- activity timeline ---- */}
        <Panel
          className="soc-activity"
          title="Threat activity timeline"
          description={`Events and alerts per hour, last ${hours}h (local time)`}
          actions={
            <div className="soc-legend">
              <span><i style={{ background: 'var(--c-info)' }} />Events<b>{num(derived.windowEvents)}</b></span>
              <span><i style={{ background: 'var(--accent-strong)' }} />Alerts<b>{num(derived.windowAlerts)}</b></span>
            </div>
          }
        >
          {derived.windowEvents + derived.windowAlerts === 0 ? (
            <EmptyState title="No activity in this window" text="No events or alerts were recorded in the selected range." />
          ) : (
            <div className="soc-chart" role="img" aria-label={`Events and alerts per hour over the last ${hours} hours`}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={derived.chart} margin={{ top: 6, right: 4, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="soc-events-fill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--c-info)" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="var(--c-info)" stopOpacity={0.08} />
                    </linearGradient>
                    <linearGradient id="soc-alerts-fill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--accent-strong)" stopOpacity={0.6} />
                      <stop offset="100%" stopColor="var(--accent-strong)" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} stroke="var(--grid-line)" />
                  <XAxis dataKey="tick" tickLine={false} axisLine={{ stroke: 'var(--border-strong)' }} tick={{ fontSize: 11, fill: 'var(--muted)' }} interval="preserveStartEnd" minTickGap={36} />
                  <YAxis allowDecimals={false} width={36} tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: 'var(--muted)' }} />
                  <Tooltip content={<ChartTip />} cursor={{ stroke: 'var(--border-strong)' }} isAnimationActive={false} />
                  <Area type="monotone" dataKey="events" stroke="var(--c-info)" strokeWidth={2} fill="url(#soc-events-fill)" dot={false} activeDot={{ r: 3 }} isAnimationActive={false} />
                  <Area type="monotone" dataKey="alerts" stroke="var(--accent-strong)" strokeWidth={2} fill="url(#soc-alerts-fill)" dot={false} activeDot={{ r: 3 }} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        {/* ---- compact stats (all from the summary) ---- */}
        <div className="soc-statstack">
          <Link to="/alerts?status=OPEN" className="soc-panel soc-stat" style={tone(derived.openAlerts ? 'high' : 'ok')}>
            <span className="soc-stat-label"><BellRing size={14} />Open alerts</span>
            <b>{num(derived.openAlerts)}</b>
            <span className="soc-stat-sub">of {num(data.alertCount)} raised</span>
          </Link>
          <Link to="/incidents?status=OPEN" className="soc-panel soc-stat" style={tone(data.openIncidentCount ? 'critical' : 'ok')}>
            <span className="soc-stat-label"><ShieldAlert size={14} />Open incidents</span>
            <b>{num(data.openIncidentCount)}</b>
            <span className="soc-stat-sub">status OPEN</span>
          </Link>
          <Link to="/predictions" className="soc-panel soc-stat" style={tone(data.averageAnomalyScore != null ? scoreTone(data.averageAnomalyScore) : 'neutral')}>
            <span className="soc-stat-label"><Radar size={14} />Average anomaly score</span>
            <b>{data.averageAnomalyScore != null ? data.averageAnomalyScore.toFixed(3) : '—'}</b>
            <span className="soc-stat-sub">peak {data.maxAnomalyScore != null ? data.maxAnomalyScore.toFixed(3) : '—'} · {num(data.predictionCount)} predictions</span>
          </Link>
        </div>

        {/* ---- recent critical alerts ---- */}
        <Panel className="soc-critical" title="Recent critical alerts" description="Newest first" actions={<PanelLink to="/alerts?severity=CRITICAL">All critical</PanelLink>}>
          {critical.isLoading ? (
            <Skeleton h={180} />
          ) : critical.isError ? (
            <ErrorState title="Couldn’t load critical alerts" message={cellError(critical.error, 'critical alerts')} onRetry={() => critical.refetch()} />
          ) : !critical.data?.content.length ? (
            <EmptyState title="No critical alerts" text="No alerts with critical severity are on record." icon={BellRing} />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Time</th><th>Entity</th><th>Source</th><th>Decision</th><th title="Anomaly score">Score</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {critical.data.content.map((a) => (
                    <tr key={a.id} className="clickable row-accent" style={tone('critical')} onClick={() => navigate(`/alerts/${a.id}`)}>
                      <td className="nowrap" title={`${fmtDate(a.createdAt)} · ${timeAgo(a.createdAt)}`}>
                        <Link className="mono link" to={`/alerts/${a.id}`} onClick={(e) => e.stopPropagation()}>{fmtTimeSec(a.createdAt)}</Link>
                      </td>
                      <td><Link className="mono link" to={`/entities/${encodeURIComponent(a.entityId)}`} onClick={(e) => e.stopPropagation()}>{a.entityId}</Link></td>
                      <td className="muted">{a.ruleId ?? 'ML'}</td>
                      <td><DecisionBadge value={a.decision} /></td>
                      <td><ScoreMeter value={a.anomalyScore} /></td>
                      <td><AlertStatusBadge value={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* ---- recent event feed (summary.recentEvents, newest first) ---- */}
        <Panel className="soc-feed" title="Security activity" description="Latest ingested events" actions={<PanelLink to="/events">Events</PanelLink>}>
          {!data.recentEvents.length ? (
            <EmptyState title="No events yet" text="Ingest an event or run a simulator scenario." />
          ) : (
            <ol className="soc-feed-list">
              {data.recentEvents.map((e) => (
                <li key={e.eventId}>
                  <Link to={`/events/${encodeURIComponent(e.eventId)}`} className="soc-feed-item">
                    <span className="soc-feed-type">{e.eventType}</span>
                    <span className="soc-feed-text">
                      <strong className="mono">{e.entityId}</strong>
                      <span>{e.source} · {when(e.occurredAt)}</span>
                    </span>
                    <ProcessingBadge value={e.processingStatus} />
                  </Link>
                </li>
              ))}
            </ol>
          )}
        </Panel>

        {/* ---- top affected entities ---- */}
        <Panel className="soc-entities" title="Top affected entities" description="Most alerts on record" actions={<PanelLink to="/entities">Entities</PanelLink>}>
          {!data.topEntities.length ? (
            <EmptyState title="No affected entities" text="No entity has raised an alert yet." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Entity</th><th className="num">Alerts</th><th className="num">Max score</th><th>Last alert</th></tr>
                </thead>
                <tbody>
                  {data.topEntities.map((e) => (
                    <tr key={e.entityId}>
                      <td><Link className="mono link" to={`/entities/${encodeURIComponent(e.entityId)}`}>{e.entityId}</Link></td>
                      <td className="num mono">{num(e.alertCount)}</td>
                      <td className="num mono" style={{ color: e.maxScore != null ? toneColor(scoreTone(e.maxScore)) : undefined }}>{e.maxScore != null ? e.maxScore.toFixed(3) : '—'}</td>
                      <td className="muted" title={fmtDate(e.lastAlertAt)}>{when(e.lastAlertAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* ---- event types (all-time, from the summary) ---- */}
        <Panel className="soc-types" title="Events by type" description="All time" actions={<PanelLink to="/events">Events</PanelLink>}>
          {!derived.types.length ? (
            <EmptyState title="No events yet" text="Ingest an event to see the type breakdown." />
          ) : (
            <div className="soc-bars">
              {derived.types.map(([type, count]) => (
                <Link key={type} to={`/events?eventType=${encodeURIComponent(type)}`} className="soc-bar">
                  <div className="soc-bar-top"><span>{type}</span><b>{num(count)}</b></div>
                  <div className="soc-bar-track"><div style={{ width: `${(count / derived.types[0][1]) * 100}%` }} /></div>
                </Link>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
