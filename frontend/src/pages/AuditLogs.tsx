import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ClipboardList } from 'lucide-react';

import { auditApi } from '../api/endpoints';
import { Drawer } from '../components/feedback';
import {
  Badge,
  Card,
  CopyButton,
  EmptyState,
  ErrorState,
  JsonViewer,
  KV,
  PageHeader,
  Pagination,
  Select,
  TableSkeleton,
} from '../components/ui';
import { useUrlState } from '../hooks/useUrlState';
import type { AuditLog } from '../types/domain';
import { fmtDate, formatApiError, humanize, timeAgo } from '../utils/format';
import type { Tone } from '../utils/tone';

const actionTone = (a: string): Tone =>
  a.includes('CREATED') ? 'ok' : a.includes('STATUS') ? 'info' : a.includes('FAIL') ? 'critical' : 'neutral';

// The audit endpoint pages server-side; type/action filters narrow the loaded page.
export default function AuditLogs() {
  const { state, set } = useUrlState({});
  const [resource, setResource] = useState('');
  const [selected, setSelected] = useState<AuditLog | null>(null);

  const q = useQuery({
    queryKey: ['audit', state.page],
    queryFn: () => auditApi.list({ page: state.page, size: 25 }),
    placeholderData: (prev) => prev,
  });

  const rows = useMemo(() => (q.data?.content ?? []).filter((r) => !resource || r.resourceType === resource), [q.data, resource]);
  const resourceTypes = useMemo(() => Array.from(new Set((q.data?.content ?? []).map((r) => r.resourceType))).sort(), [q.data]);

  const resourceLink = (r: AuditLog) =>
    r.resourceId && r.resourceType === 'ALERT' ? `/alerts/${r.resourceId}` : r.resourceId && r.resourceType === 'INCIDENT' ? `/incidents/${r.resourceId}` : null;

  return (
    <>
      <PageHeader
        eyebrow="Administration"
        title="Audit logs"
        description="Append-only history of state-changing actions — who did what, to which resource, and when."
      />

      <Card flush>
        <div className="filters">
          <Select value={resource} onChange={setResource} options={resourceTypes} placeholder="All resource types" />
          <span className="spacer" />
          <span className="muted" style={{ fontSize: 12 }}>Filter applies to the current page</span>
        </div>

        {q.isLoading ? (
          <TableSkeleton />
        ) : q.isError ? (
          <ErrorState message={formatApiError(q.error, 'Unable to load audit logs')} onRetry={() => q.refetch()} />
        ) : !rows.length ? (
          <EmptyState title="No audit entries" text={resource ? 'Nothing on this page matches the filter.' : 'Actions will be recorded here.'} icon={ClipboardList} />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Resource</th><th>Correlation</th></tr></thead>
                <tbody>
                  {rows.map((r) => {
                    const link = resourceLink(r);
                    return (
                      <tr
                        key={r.id}
                        className="clickable"
                        tabIndex={0}
                        aria-label={`Open audit entry: ${humanize(r.action)}`}
                        onClick={() => setSelected(r)}
                        onKeyDown={(ev) => {
                          if (ev.target === ev.currentTarget && (ev.key === 'Enter' || ev.key === ' ')) {
                            ev.preventDefault();
                            setSelected(r);
                          }
                        }}
                      >
                        <td><div className="cell-stack"><span>{timeAgo(r.createdAt)}</span><small>{fmtDate(r.createdAt)}</small></div></td>
                        <td><Badge tone={r.actor === 'system' || !r.actor ? 'neutral' : 'info'} plain>{r.actor || 'system'}</Badge></td>
                        <td><Badge tone={actionTone(r.action)}>{humanize(r.action)}</Badge></td>
                        <td>
                          <div className="cell-stack">
                            <span>{humanize(r.resourceType)}</span>
                            {link ? <Link className="mono link" to={link} onClick={(e) => e.stopPropagation()}>{r.resourceId?.slice(0, 8)}…</Link> : <small className="mono">{r.resourceId ? `${r.resourceId.slice(0, 8)}…` : '—'}</small>}
                          </div>
                        </td>
                        <td className="mono muted">{r.correlationId ? r.correlationId.slice(0, 8) + '…' : '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <Pagination page={state.page} totalPages={q.data!.totalPages} totalElements={q.data!.totalElements} itemLabel="entries" onPageChange={(p) => set({ page: p })} />
          </>
        )}
      </Card>

      <Drawer open={!!selected} onClose={() => setSelected(null)} title={selected ? humanize(selected.action) : ''} subtitle={selected ? fmtDate(selected.createdAt) : undefined}>
        {selected && (
          <>
            <div className="kv-grid">
              <KV label="Actor">{selected.actor || 'system'}</KV>
              <KV label="Resource">{humanize(selected.resourceType)}</KV>
              <KV label="Resource ID" mono copy={selected.resourceId ?? undefined}>{selected.resourceId ?? '—'}</KV>
              <KV label="Correlation ID" mono copy={selected.correlationId ?? undefined}>{selected.correlationId ?? '—'}</KV>
            </div>
            <div>
              <h3 className="drawer-h" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>Details <CopyButton value={JSON.stringify(selected.details, null, 2)} /></h3>
              <JsonViewer value={selected.details} />
            </div>
          </>
        )}
      </Drawer>
    </>
  );
}
