import { useMemo, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, ArrowUpRight, BellRing, CheckCircle2, RefreshCw, ShieldAlert, XCircle } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { alertsApi, dashboardApi, entitiesApi, incidentsApi, systemApi } from '../api/endpoints';
import {
  AlertStatusBadge,
  Button,
  Card,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  IncidentStatusBadge,
  PageHeader,
  ScoreMeter,
  Segmented,
  SeverityBadge,
  Skeleton,
} from '../components/ui';
import { useAiProviderState } from '../utils/aiProviderStatus';
import { fmtDate, fmtTimeSec, formatApiError, humanize, num, timeAgo } from '../utils/format';
import { SEVERITY_ORDER, scoreTone, severityTone, toneColor } from '../utils/tone';
import type { Tone } from '../utils/tone';
import '../styles/dashboard.css';

const RANGES = [
  { value: 8, label: '8h' },
  { value: 24, label: '24h' },
  { value: 72, label: '3d' },
];

const HEALTH_NAMES: Record<string, string> = {
  'Spring Boot API': 'Spring Boot',
  'ML service': 'ML Service',
};

const tone = (t: Tone) => ({ ['--tone' as string]: toneColor(t) }) as CSSProperties;
const pad = (n: number) => String(n).padStart(2, '0');

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

/* ---------- building blocks ---------- */

function Kpi({ label, value, sub, to, critical }: { label: string; value?: number | null; sub?: string; to: string; critical?: boolean }) {
  const hot = critical && (value ?? 0) > 0;
  return (
    <Link to={to} className={`dash-kpi${hot ? ' tone-critical' : ''}`} aria-label={`${label}: ${value ?? 'unavailable'}`}>
      <span className="dash-kpi-label">{label}</span>
      <span className="dash-kpi-value">{num(value)}</span>
      <span className="dash-kpi-sub">{sub ?? ' '}</span>
    </Link>
  );
}

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
    <Card flush className={`dash-panel ${className}`}>
      <div className="card-section">
        <CardHead title={title} description={description} actions={actions} />
      </div>
      <div className="dash-body">{children}</div>
    </Card>
  );
}

const PanelLink = ({ to, children }: { to: string; children: ReactNode }) => (
  <Link className="link inline" to={to}>{children} <ArrowUpRight size={13} /></Link>
);

type TipProps = { active?: boolean; payload?: { dataKey: string; value: number; payload: { bucketStart: string } }[] };

function ChartTip({ active, payload }: TipProps) {
  if (!active || !payload?.length) return null;
  const events = payload.find((p) => p.dataKey === 'events')?.value ?? 0;
  const alerts = payload.find((p) => p.dataKey === 'alerts')?.value ?? 0;
  return (
    <div className="dash-tip">
      <strong>{fmtDate(payload[0].payload.bucketStart)}</strong>
      <div><i style={{ background: 'var(--c-info)' }} />Events <b>{events}</b></div>
      <div><i style={{ background: 'var(--c-high)' }} />Alerts <b>{alerts}</b></div>
    </div>
  );
}

const cellError = (e: unknown, what: string) => formatApiError(e, `Unable to load ${what}`);

/* ---------- page ---------- */

export default function Dashboard() {
  const navigate = useNavigate();
  const [hours, setHours] = useState(8);

  // The summary is the one aggregate call; everything below it is a small,
  // server-filtered query (no client-side filtering of partial pages).
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
    queryFn: () => alertsApi.list({ severity: 'CRITICAL', size: 6 }),
    refetchInterval: 30000,
  });

  // openIncidentCount on the summary is OPEN only, so "active" = OPEN + INVESTIGATING.
  const openIncidents = useQuery({
    queryKey: ['incidents', 'dashboard', 'OPEN'],
    queryFn: () => incidentsApi.list({ status: 'OPEN', size: 6 }),
    refetchInterval: 30000,
  });
  const investigating = useQuery({
    queryKey: ['incidents', 'dashboard', 'INVESTIGATING'],
    queryFn: () => incidentsApi.list({ status: 'INVESTIGATING', size: 6 }),
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
    const sevTotal = sev.reduce((a, s) => a + s.value, 0);
    const processed = data.eventsByProcessingStatus?.PROCESSED ?? 0;
    const pending = data.eventsByProcessingStatus?.PENDING ?? 0;
    const failed = data.eventsByProcessingStatus?.FAILED ?? 0;
    return {
      sev,
      sevTotal,
      windowEvents: data.trend.reduce((a, t) => a + t.events, 0),
      windowAlerts: data.trend.reduce((a, t) => a + t.alerts, 0),
      openAlerts: data.alertsByStatus?.OPEN ?? 0,
      critical: bySeverity.CRITICAL ?? 0,
      high: bySeverity.HIGH ?? 0,
      processed,
      pending,
      failed,
      chart: data.trend.map((t) => ({ ...t, tick: tickLabel(t.bucketStart, hours, t.label) })),
      types: Object.entries(data.eventsByType ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8),
    };
  }, [data, hours]);

  const refreshAll = () => {
    summary.refetch();
    status.refetch();
    critical.refetch();
    openIncidents.refetch();
    investigating.refetch();
    entityCount.refetch();
  };
  const refreshing = summary.isFetching || status.isFetching || critical.isFetching || openIncidents.isFetching || investigating.isFetching;

  const header = (
    <PageHeader
      title="Dashboard"
      description="Security operations overview"
      actions={
        <>
          <Segmented value={hours} onChange={setHours} options={RANGES} />
          <Button variant="secondary" size="sm" icon={RefreshCw} loading={refreshing} onClick={refreshAll}>Refresh</Button>
        </>
      }
    />
  );

  if (summary.isLoading) {
    return (
      <>
        {header}
        <div className="dash-grid" aria-busy="true">
          <div className="dash-kpis">{Array.from({ length: 6 }, (_, i) => <div className="dash-kpi" key={i}><Skeleton h={54} /></div>)}</div>
          <Card className="dash-activity"><Skeleton h={250} /></Card>
          <Card className="dash-severity"><Skeleton h={250} /></Card>
        </div>
      </>
    );
  }

  if (summary.isError || !data || !derived) {
    return (
      <>
        {header}
        <Card><ErrorState message={formatApiError(summary.error, 'Unable to reach the platform API.')} onRetry={() => summary.refetch()} /></Card>
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
  const pipeTotal = derived.processed + derived.pending + derived.failed;
  const share = (n: number) => (pipeTotal ? `${Math.round((n / pipeTotal) * 100)}%` : '—');

  const incidentRows = [...(openIncidents.data?.content ?? []), ...(investigating.data?.content ?? [])].slice(0, 6);
  const incidentsLoading = openIncidents.isLoading || investigating.isLoading;
  const incidentsError = openIncidents.error ?? investigating.error;

  return (
    <>
      {header}

      <Link to={note.to} className={`dash-note tone-${note.tone}`}>
        <NoteIcon size={15} />
        <span className="dash-note-text"><strong>{note.text}</strong><span>{note.sub}</span></span>
        <ArrowUpRight size={14} />
      </Link>

      <div className="dash-grid">
        {/* ---- KPI strip: every value is a backend number ---- */}
        <div className="dash-kpis">
          <Kpi label="Total events" value={data.totalEvents} sub={`${num(derived.windowEvents)} in last ${hours}h`} to="/events" />
          <Kpi label="Predictions" value={data.predictionCount} sub={data.averageAnomalyScore != null ? `avg score ${data.averageAnomalyScore.toFixed(2)}` : undefined} to="/predictions" />
          <Kpi label="Open alerts" value={derived.openAlerts} sub={`of ${num(data.alertCount)} total`} to="/alerts?status=OPEN" />
          <Kpi label="Open incidents" value={data.openIncidentCount} to="/incidents?status=OPEN" />
          <Kpi label="Critical alerts" value={derived.critical} sub="all statuses" to="/alerts?severity=CRITICAL" critical />
          <Kpi label="Entities monitored" value={entityCount.data?.totalElements} to="/entities" />
        </div>

        {/* ---- primary activity chart ---- */}
        <Panel
          className="dash-activity"
          title="Events vs alerts over time"
          description={`Per hour, last ${hours}h (local time)`}
          actions={
            <div className="dash-legend">
              <span><i style={{ background: 'var(--c-info)' }} />Events<b>{num(derived.windowEvents)}</b></span>
              <span><i style={{ background: 'var(--c-high)' }} />Alerts<b>{num(derived.windowAlerts)}</b></span>
            </div>
          }
        >
          {derived.windowEvents + derived.windowAlerts === 0 ? (
            <EmptyState title="No activity in this window" text="No events or alerts were recorded in the selected range." />
          ) : (
            <div className="dash-chart" role="img" aria-label={`Events and alerts per hour over the last ${hours} hours`}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={derived.chart} margin={{ top: 6, right: 4, left: 0, bottom: 0 }}>
                  <CartesianGrid vertical={false} stroke="var(--grid-line)" />
                  <XAxis dataKey="tick" tickLine={false} axisLine={{ stroke: 'var(--border-strong)' }} tick={{ fontSize: 11, fill: 'var(--muted)' }} interval="preserveStartEnd" minTickGap={36} />
                  <YAxis allowDecimals={false} width={32} tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: 'var(--muted)' }} />
                  <Tooltip content={<ChartTip />} cursor={{ stroke: 'var(--border-strong)' }} isAnimationActive={false} />
                  <Area type="linear" dataKey="events" stroke="var(--c-info)" strokeWidth={1.5} fill="var(--c-info)" fillOpacity={0.1} dot={false} activeDot={{ r: 3 }} isAnimationActive={false} />
                  <Area type="linear" dataKey="alerts" stroke="var(--c-high)" strokeWidth={1.5} fill="var(--c-high)" fillOpacity={0.14} dot={false} activeDot={{ r: 3 }} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        {/* ---- severity distribution ---- */}
        <Panel className="dash-severity" title="Alert severity" description="All alerts on record" actions={<PanelLink to="/alerts">Alerts</PanelLink>}>
          <div className="dash-sev">
            <div className="dash-stack" role="img" aria-label={derived.sev.map((s) => `${s.label} ${s.value}`).join(', ')}>
              {derived.sev.map((s) => s.value > 0 && <div key={s.key} style={{ flex: s.value, background: toneColor(s.tone) }} title={`${s.label}: ${s.value}`} />)}
            </div>
            <div className="dash-rows">
              {derived.sev.map((s) => (
                <Link key={s.key} to={`/alerts?severity=${s.key}`} className={`dash-row${s.key === 'CRITICAL' ? ' is-critical' : ''}`} style={tone(s.tone)}>
                  <i />
                  <span>{s.label}</span>
                  <b>{num(s.value)}</b>
                  <small>{derived.sevTotal ? `${Math.round((s.value / derived.sevTotal) * 100)}%` : '—'}</small>
                </Link>
              ))}
            </div>
          </div>
          <div className="dash-stats">
            <div className="dash-stat"><span>Open</span><b>{num(derived.openAlerts)}</b></div>
            <div className="dash-stat"><span>Peak score</span><b>{data.maxAnomalyScore != null ? data.maxAnomalyScore.toFixed(3) : '—'}</b></div>
            <div className="dash-stat"><span>Policy</span><b title={status.data?.policy.version}>{status.data?.policy.version ?? '—'}</b></div>
          </div>
        </Panel>

        {/* ---- recent critical alerts ---- */}
        <Panel className="dash-alerts" title="Recent critical alerts" description="Newest first" actions={<PanelLink to="/alerts?severity=CRITICAL">All critical</PanelLink>}>
          {critical.isLoading ? (
            <div className="dash-sev"><Skeleton h={150} /></div>
          ) : critical.isError ? (
            <ErrorState title="Couldn’t load critical alerts" message={cellError(critical.error, 'critical alerts')} onRetry={() => critical.refetch()} />
          ) : !critical.data?.content.length ? (
            <EmptyState title="No critical alerts" text="No alerts with critical severity are on record." icon={BellRing} />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Time</th><th>Entity</th><th>Decision</th><th title="Anomaly score">Score</th><th>Severity</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {critical.data.content.map((a) => (
                    <tr key={a.id} className="clickable row-accent" style={tone('critical')} onClick={() => navigate(`/alerts/${a.id}`)}>
                      <td title={fmtDate(a.createdAt)}>
                        <Link className="mono link" to={`/alerts/${a.id}`} onClick={(e) => e.stopPropagation()}>{fmtTimeSec(a.createdAt)}</Link>
                        <span className="muted"> · {timeAgo(a.createdAt)}</span>
                      </td>
                      <td><Link className="mono link" to={`/entities/${encodeURIComponent(a.entityId)}`} onClick={(e) => e.stopPropagation()}>{a.entityId}</Link></td>
                      <td><DecisionBadge value={a.decision} /></td>
                      <td><ScoreMeter value={a.anomalyScore} /></td>
                      <td><SeverityBadge value={a.severity} /></td>
                      <td><AlertStatusBadge value={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* ---- top affected entities ---- */}
        <Panel className="dash-entities" title="Top affected entities" description="Most alerts on record" actions={<PanelLink to="/entities">Entities</PanelLink>}>
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

        {/* ---- active incidents ---- */}
        <Panel className="dash-incidents" title="Active incidents" description="Open and investigating" actions={<PanelLink to="/incidents">Incidents</PanelLink>}>
          {incidentsLoading ? (
            <div className="dash-sev"><Skeleton h={150} /></div>
          ) : incidentsError ? (
            <ErrorState
              title="Couldn’t load incidents"
              message={cellError(incidentsError, 'incidents')}
              onRetry={() => { openIncidents.refetch(); investigating.refetch(); }}
            />
          ) : !incidentRows.length ? (
            <EmptyState title="No active incidents" text="The investigation queue is clear." icon={ShieldAlert} />
          ) : (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>Incident</th><th>Entity</th><th>Status</th><th className="num">Alerts</th><th>Updated</th></tr>
                  </thead>
                  <tbody>
                    {incidentRows.map((i) => (
                      <tr key={i.id} className="clickable row-accent" style={tone(severityTone(i.maxSeverity))} onClick={() => navigate(`/incidents/${i.id}`)}>
                        <td><Link className="mono link" to={`/incidents/${i.id}`} onClick={(e) => e.stopPropagation()} title={i.summary}>{i.incidentKey}</Link></td>
                        <td><Link className="mono link" to={`/entities/${encodeURIComponent(i.entityId)}`} onClick={(e) => e.stopPropagation()}>{i.entityId}</Link></td>
                        <td><IncidentStatusBadge value={i.status} /></td>
                        <td className="num mono">{i.alertCount}</td>
                        <td className="muted" title={fmtDate(i.updatedAt)}>{when(i.updatedAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="dash-foot">
                <span>{num(openIncidents.data?.totalElements)} open · {num(investigating.data?.totalElements)} investigating</span>
              </div>
            </>
          )}
        </Panel>

        {/* ---- event types (all-time, from the summary) ---- */}
        <Panel className="dash-types" title="Events by type" description="All time" actions={<PanelLink to="/events">Events</PanelLink>}>
          {!derived.types.length ? (
            <EmptyState title="No events yet" text="Ingest an event to see the type breakdown." />
          ) : (
            <div className="dash-bars">
              {derived.types.map(([type, count]) => (
                <Link key={type} to={`/events?eventType=${encodeURIComponent(type)}`} className="dash-bar">
                  <div className="dash-bar-top"><span className="dash-bar-name">{type}</span><b>{num(count)}</b></div>
                  <div className="dash-bar-track"><div className="dash-bar-fill" style={{ width: `${(count / derived.types[0][1]) * 100}%` }} /></div>
                </Link>
              ))}
            </div>
          )}
        </Panel>

        {/* ---- system health ---- */}
        <Panel
          className="dash-health"
          title="System health"
          description={status.data ? `Checked ${fmtTimeSec(status.data.checkedAt)}` : undefined}
          actions={<PanelLink to="/system">System status</PanelLink>}
        >
          {status.isLoading ? (
            <div className="dash-sev"><Skeleton h={150} /></div>
          ) : status.isError ? (
            <ErrorState title="Status unavailable" message="The system status endpoint did not respond." onRetry={() => status.refetch()} />
          ) : (
            <div>
              {status.data!.components.map((c) => {
                const up = c.status === 'UP';
                return (
                  <div className="dash-health-row" key={c.name} style={tone(up ? 'ok' : 'critical')}>
                    <span className="dash-dot" />
                    <span className="dash-health-name">{HEALTH_NAMES[c.name] ?? c.name}</span>
                    <span className="dash-health-detail" title={c.detail ?? undefined}>{c.detail}</span>
                    {/* the API reports 0 ms for the Spring Boot row (it is answering the request), so only show real probe latencies */}
                    <span className="dash-health-val">{!up ? 'Down' : c.latencyMs ? `${c.latencyMs} ms` : '—'}</span>
                  </div>
                );
              })}
              <div className="dash-health-row" style={tone(ai.state === 'unavailable' ? 'medium' : 'neutral')}>
                <span className="dash-dot" />
                <span className="dash-health-name">AI Provider</span>
                <span
                  className="dash-health-detail"
                  title="There is no AI health probe. This only reflects the outcome of the most recent AI request in this session."
                >
                  {ai.state === 'unavailable'
                    ? `Most recent AI request returned 503 (${timeAgo(new Date(ai.at).toISOString())}) — not a health check`
                    : 'Not probed — used only when an AI action runs'}
                </span>
                <span className="dash-health-val">{ai.state === 'unavailable' ? 'Provider unavailable' : 'On demand'}</span>
              </div>
            </div>
          )}
        </Panel>

        {/* ---- processing pipeline (real counts) ---- */}
        <Panel className="dash-pipeline" title="Processing pipeline" description="All stored events" actions={<PanelLink to="/system">Details</PanelLink>}>
          <div className="dash-pipe">
            <div className="dash-stack tall" role="img" aria-label={`Processed ${derived.processed}, pending ${derived.pending}, failed ${derived.failed}`}>
              {derived.processed > 0 && <div style={{ flex: derived.processed, background: 'var(--c-ok)' }} />}
              {derived.pending > 0 && <div style={{ flex: derived.pending, background: 'var(--c-medium)' }} />}
              {derived.failed > 0 && <div style={{ flex: derived.failed, background: 'var(--c-critical)' }} />}
            </div>
            <div className="dash-rows">
              <div className="dash-row" style={tone('ok')}><i /><span>Processed</span><b>{num(derived.processed)}</b><small>{share(derived.processed)}</small></div>
              <div className="dash-row" style={tone('medium')}><i /><span>Pending</span><b>{num(derived.pending)}</b><small>{share(derived.pending)}</small></div>
              <div className="dash-row" style={tone('critical')}><i /><span>Failed</span><b>{num(derived.failed)}</b><small>{share(derived.failed)}</small></div>
            </div>
          </div>
        </Panel>
      </div>
    </>
  );
}
