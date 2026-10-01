import type { CSSProperties } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ShieldAlert } from 'lucide-react';

import { dashboardApi, incidentsApi } from '../api/endpoints';
import EntitySelect from '../components/EntitySelect';
import {
  Card,
  ClearFilters,
  EmptyState,
  ErrorState,
  IncidentStatusBadge,
  PageHeader,
  Pagination,
  ScoreMeter,
  Select,
  SeverityBadge,
  TableSkeleton,
} from '../components/ui';
import { useUrlState } from '../hooks/useUrlState';
import { INCIDENT_STATUSES } from '../types/domain';
import { fmtDate, formatApiError, humanize, timeAgo } from '../utils/format';
import { severityTone, toneColor } from '../utils/tone';

const DEFAULTS = { status: '', entityId: '', source: '' };

export default function Incidents() {
  const { state, set, reset, activeCount } = useUrlState(DEFAULTS);

  const q = useQuery({
    queryKey: ['incidents', state.status, state.entityId, state.source, state.page],
    queryFn: () =>
      incidentsApi.list({ status: state.status, entityId: state.entityId, source: state.source, page: state.page, size: 20 }),
    placeholderData: (prev) => prev,
    refetchInterval: 20000,
  });

  const summary = useQuery({ queryKey: ['dashboard', 8], queryFn: () => dashboardApi.summary(8), staleTime: 15000 });
  // An incident matches source=X when at least one of its alerts came
  // from an event with that source (an incident can genuinely span more
  // than one source - see IncidentResponse.sources).
  const sourceOptions = Object.keys(summary.data?.eventsBySource ?? {}).sort();
  if (state.source && !sourceOptions.includes(state.source)) sourceOptions.unshift(state.source);

  return (
    <>
      <PageHeader
        eyebrow="Detection"
        title="Incidents"
        description="Investigations grouped automatically from alert activity per entity and event type."
      />

      <div className="chip-row status-chips">
        <button className={`chip${state.status === '' ? ' active' : ''}`} onClick={() => set({ status: '' })}>All</button>
        {INCIDENT_STATUSES.map((s) => (
          <button key={s} className={`chip${state.status === s ? ' active' : ''}`} onClick={() => set({ status: state.status === s ? '' : s })}>
            {humanize(s)}
            {s === 'OPEN' && summary.data && <span className="chip-count">{summary.data.openIncidentCount}</span>}
          </button>
        ))}
      </div>

      <Card flush style={{ marginTop: 12 }}>
        <div className="filters">
          <EntitySelect value={state.entityId} onChange={(v) => set({ entityId: v })} />
          <Select value={state.source} onChange={(v) => set({ source: v })} options={sourceOptions} placeholder="All sources" />
          {activeCount > 0 && <ClearFilters onClick={reset} />}
        </div>

        {q.isLoading ? (
          <TableSkeleton />
        ) : q.isError ? (
          <ErrorState message={formatApiError(q.error, 'Unable to load incidents')} onRetry={() => q.refetch()} />
        ) : !q.data?.content.length ? (
          <EmptyState title="No incidents" text={activeCount ? 'No incidents match these filters.' : 'Incidents are created automatically when alerts are raised.'} icon={ShieldAlert} action={activeCount ? <ClearFilters onClick={reset} /> : undefined} />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Severity</th><th>Incident</th><th>Entity</th><th>Source</th><th className="num">Alerts</th><th>Peak score</th><th>Status</th><th>Opened</th></tr>
                </thead>
                <tbody>
                  {q.data.content.map((i) => (
                    // same rule as the Alerts table: an edge for critical/high, the badge says it in words
                    <tr key={i.id} className={i.maxSeverity === 'CRITICAL' || i.maxSeverity === 'HIGH' ? 'row-accent' : undefined} style={{ ['--tone' as string]: toneColor(severityTone(i.maxSeverity)) } as CSSProperties}>
                      <td>{i.maxSeverity ? <SeverityBadge value={i.maxSeverity} /> : <span className="muted">—</span>}</td>
                      <td>
                        <div className="cell-stack">
                          <Link className="link" to={`/incidents/${i.id}`}>{i.summary}</Link>
                          <small className="mono">{i.incidentKey}</small>
                        </div>
                      </td>
                      <td><Link className="mono link" to={`/entities/${encodeURIComponent(i.entityId)}`}>{i.entityId}</Link></td>
                      <td className="muted" title={i.sources?.join(', ')}>
                        {i.sources?.length ? `${i.sources[0]}${i.sources.length > 1 ? ` +${i.sources.length - 1}` : ''}` : '—'}
                      </td>
                      <td className="num mono">{i.alertCount}</td>
                      <td><ScoreMeter value={i.maxScore} /></td>
                      <td><IncidentStatusBadge value={i.status} /></td>
                      <td title={fmtDate(i.createdAt)}>{timeAgo(i.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={state.page} totalPages={q.data.totalPages} totalElements={q.data.totalElements} itemLabel="incidents" onPageChange={(p) => set({ page: p })} />
          </>
        )}
      </Card>
    </>
  );
}
