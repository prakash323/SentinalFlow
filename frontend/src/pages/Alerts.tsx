import type { CSSProperties } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { BellRing } from 'lucide-react';

import { alertsApi, dashboardApi } from '../api/endpoints';
import EntitySelect from '../components/EntitySelect';
import {
  AlertStatusBadge,
  Card,
  ClearFilters,
  DecisionBadge,
  EmptyState,
  ErrorState,
  PageHeader,
  Pagination,
  ScoreMeter,
  Select,
  SeverityBadge,
  TableSkeleton,
} from '../components/ui';
import { useUrlState } from '../hooks/useUrlState';
import { ALERT_STATUSES, DECISIONS, SEVERITIES } from '../types/domain';
import { fmtDate, formatApiError, humanize, timeAgo } from '../utils/format';
import { severityTone, toneColor } from '../utils/tone';

const DEFAULTS = { status: '', severity: '', decision: '', entityId: '', source: '' };

export default function Alerts() {
  const { state, set, reset, activeCount } = useUrlState(DEFAULTS);

  const q = useQuery({
    queryKey: ['alerts', state.status, state.severity, state.decision, state.entityId, state.source, state.page],
    queryFn: () =>
      alertsApi.list({
        status: state.status,
        severity: state.severity,
        decision: state.decision,
        entityId: state.entityId,
        source: state.source,
        page: state.page,
        size: 20,
      }),
    placeholderData: (prev) => prev,
    refetchInterval: 15000,
  });

  // Status counts double as one-click filters.
  const summary = useQuery({ queryKey: ['dashboard', 8], queryFn: () => dashboardApi.summary(8), staleTime: 15000 });
  const byStatus = summary.data?.alertsByStatus ?? {};
  // Sources seen so far, taken from the dashboard's event aggregate - an
  // alert's source can only ever be a subset of event sources, since
  // every alert originates from an event.
  const sourceOptions = Object.keys(summary.data?.eventsBySource ?? {}).sort();
  if (state.source && !sourceOptions.includes(state.source)) sourceOptions.unshift(state.source);

  return (
    <>
      <PageHeader
        eyebrow="Detection"
        title="Alerts"
        description="Anomaly signals graded by the alert policy. Triage from the top: highest severity and score first."
      />

      <div className="chip-row status-chips">
        <button className={`chip${state.status === '' ? ' active' : ''}`} onClick={() => set({ status: '' })}>All</button>
        {ALERT_STATUSES.map((s) => (
          <button key={s} className={`chip${state.status === s ? ' active' : ''}`} onClick={() => set({ status: state.status === s ? '' : s })}>
            {humanize(s)} <span className="chip-count">{byStatus[s] ?? 0}</span>
          </button>
        ))}
      </div>

      <Card flush style={{ marginTop: 12 }}>
        <div className="filters">
          <Select value={state.severity} onChange={(v) => set({ severity: v })} options={SEVERITIES} placeholder="All severities" />
          <Select value={state.decision} onChange={(v) => set({ decision: v })} options={DECISIONS} placeholder="All decisions" />
          <EntitySelect value={state.entityId} onChange={(v) => set({ entityId: v })} />
          <Select value={state.source} onChange={(v) => set({ source: v })} options={sourceOptions} placeholder="All sources" />
          {activeCount > 0 && <ClearFilters onClick={reset} />}
          <span className="spacer" />
          {q.isFetching && !q.isLoading && <span className="muted" style={{ fontSize: 12 }}>Updating…</span>}
        </div>

        {q.isLoading ? (
          <TableSkeleton />
        ) : q.isError ? (
          <ErrorState message={formatApiError(q.error, 'Unable to load alerts')} onRetry={() => q.refetch()} />
        ) : !q.data?.content.length ? (
          <EmptyState
            title={activeCount ? 'No alerts match these filters' : 'No alerts'}
            text={activeCount ? 'Try widening the filters.' : 'The platform has not raised any alerts yet.'}
            icon={BellRing}
            action={activeCount ? <ClearFilters onClick={reset} /> : undefined}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Severity</th><th>Entity</th><th>Event</th><th>Source</th><th>Score</th><th>Decision</th><th>Status</th><th>Raised</th></tr>
                </thead>
                <tbody>
                  {q.data.content.map((a) => (
                    // Critical and high alerts get a left edge in the severity colour; the badge in the
                    // first cell still says the severity in words, so colour is never the only signal.
                    <tr key={a.id} className={a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'row-accent' : undefined} style={{ ['--tone' as string]: toneColor(severityTone(a.severity)) } as CSSProperties}>
                      <td>
                        <Link to={`/alerts/${a.id}`} className="row-link">
                          <SeverityBadge value={a.severity} />
                        </Link>
                      </td>
                      <td><Link className="mono link" to={`/entities/${encodeURIComponent(a.entityId)}`}>{a.entityId}</Link></td>
                      <td>
                        {a.eventId ? <Link className="mono link" to={`/alerts/${a.id}`}>{a.eventId}</Link> : <span className="muted">—</span>}
                        <div className="muted truncate" style={{ fontSize: 11.5, maxWidth: 260 }}>{a.factors?.[0] ?? ''}</div>
                      </td>
                      <td className="muted">{a.source ?? '—'}</td>
                      <td><ScoreMeter value={a.anomalyScore} /></td>
                      <td><DecisionBadge value={a.decision} /></td>
                      <td><AlertStatusBadge value={a.status} /></td>
                      <td title={fmtDate(a.createdAt)}>{timeAgo(a.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={state.page} totalPages={q.data.totalPages} totalElements={q.data.totalElements} itemLabel="alerts" onPageChange={(p) => set({ page: p })} />
          </>
        )}
      </Card>
    </>
  );
}
