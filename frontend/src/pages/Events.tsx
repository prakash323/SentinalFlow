import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Database, ExternalLink, Plus, Radio } from 'lucide-react';

import { dashboardApi, eventsApi } from '../api/endpoints';
import EntitySelect from '../components/EntitySelect';
import { Drawer } from '../components/feedback';
import {
  Card,
  ClearFilters,
  CopyButton,
  EmptyState,
  ErrorState,
  JsonViewer,
  KV,
  LinkButton,
  PageHeader,
  Pagination,
  ProcessingBadge,
  Select,
  TableSkeleton,
  TypeBadge,
} from '../components/ui';
import { useUrlState } from '../hooks/useUrlState';
import { fmtDate, fmtTimeSec, formatApiError, timeAgo } from '../utils/format';
import type { EventRecord } from '../types/domain';

const DEFAULTS = { entityId: '', eventType: '', source: '' };

export default function Events() {
  const navigate = useNavigate();
  const { state, set, reset, activeCount } = useUrlState(DEFAULTS);
  const [live, setLive] = useState(false);
  const [selected, setSelected] = useState<EventRecord | null>(null);

  const q = useQuery({
    queryKey: ['events', state.entityId, state.eventType, state.source, state.page],
    queryFn: () =>
      eventsApi.list({ entityId: state.entityId, eventType: state.eventType, source: state.source, page: state.page, size: 20 }),
    placeholderData: (prev) => prev,
    refetchInterval: live ? 4000 : false,
  });

  // Event types/sources seen so far, taken from the dashboard aggregate -
  // never hardcoded, so a future source (windows-collector, etc.) shows
  // up here automatically the first time it sends an event.
  const types = useQuery({ queryKey: ['dashboard', 8], queryFn: () => dashboardApi.summary(8), staleTime: 30000 });
  const typeOptions = Object.keys(types.data?.eventsByType ?? {}).sort();
  if (state.eventType && !typeOptions.includes(state.eventType)) typeOptions.unshift(state.eventType);
  const sourceOptions = Object.keys(types.data?.eventsBySource ?? {}).sort();
  if (state.source && !sourceOptions.includes(state.source)) sourceOptions.unshift(state.source);

  return (
    <>
      <PageHeader
        eyebrow="Detection"
        title="Events"
        description="Raw events accepted by the platform, and what the detection pipeline did with each one."
        actions={
          <>
            <button className={`chip live-chip${live ? ' active' : ''}`} onClick={() => setLive((l) => !l)} aria-pressed={live}>
              <Radio size={13} /> {live ? 'Live tail on' : 'Live tail'}
            </button>
            <LinkButton to="/events/new" variant="primary" icon={Plus}>Create event</LinkButton>
          </>
        }
      />

      <Card flush>
        <div className="filters">
          <EntitySelect value={state.entityId} onChange={(v) => set({ entityId: v })} />
          <Select value={state.eventType} onChange={(v) => set({ eventType: v })} options={typeOptions} placeholder="All event types" />
          <Select value={state.source} onChange={(v) => set({ source: v })} options={sourceOptions} placeholder="All sources" />
          {activeCount > 0 && <ClearFilters onClick={reset} />}
          <span className="spacer" />
          {q.isFetching && !q.isLoading && <span className="muted" style={{ fontSize: 12 }}>Updating…</span>}
        </div>

        {q.isLoading ? (
          <TableSkeleton />
        ) : q.isError ? (
          <ErrorState message={formatApiError(q.error, 'Unable to load events')} onRetry={() => q.refetch()} />
        ) : !q.data?.content.length ? (
          <EmptyState
            title="No events found"
            text={activeCount ? 'No events match these filters.' : 'Create an event or run a simulator scenario to get started.'}
            icon={Database}
            action={activeCount ? <ClearFilters onClick={reset} /> : <LinkButton to="/simulator" variant="primary" size="sm">Open simulator</LinkButton>}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Occurred</th><th>Event ID</th><th>Entity</th><th>Type</th><th>Source</th><th>Pipeline</th></tr>
                </thead>
                <tbody>
                  {q.data.content.map((e) => (
                    <tr
                      key={e.id}
                      className="clickable"
                      tabIndex={0}
                      aria-label={`Open details for event ${e.eventId}`}
                      onClick={() => setSelected(e)}
                      onDoubleClick={() => navigate(`/events/${encodeURIComponent(e.eventId)}`)}
                      onKeyDown={(ev) => {
                        // only when the row itself has focus, so Enter on the links inside still follows them
                        if (ev.target === ev.currentTarget && (ev.key === 'Enter' || ev.key === ' ')) {
                          ev.preventDefault();
                          setSelected(e);
                        }
                      }}
                    >
                      <td>
                        <div className="cell-stack"><span>{fmtTimeSec(e.occurredAt)}</span><small>{timeAgo(e.occurredAt)}</small></div>
                      </td>
                      <td><Link className="mono link" to={`/events/${encodeURIComponent(e.eventId)}`} onClick={(ev) => ev.stopPropagation()}>{e.eventId}</Link></td>
                      <td><Link className="mono link" to={`/entities/${encodeURIComponent(e.entityId)}`} onClick={(ev) => ev.stopPropagation()}>{e.entityId}</Link></td>
                      <td><TypeBadge value={e.eventType} /></td>
                      <td className="muted">{e.source ?? '—'}</td>
                      <td><ProcessingBadge value={e.processingStatus} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={state.page} totalPages={q.data.totalPages} totalElements={q.data.totalElements} itemLabel="events" onPageChange={(p) => set({ page: p })} />
          </>
        )}
      </Card>

      <Drawer
        open={!!selected}
        onClose={() => setSelected(null)}
        title={selected?.eventId ?? ''}
        subtitle={selected ? `${selected.eventType} · ${fmtDate(selected.occurredAt)}` : undefined}
        footer={
          selected && <LinkButton to={`/events/${encodeURIComponent(selected.eventId)}`} variant="primary" icon={ExternalLink}>Open detection trail</LinkButton>
        }
      >
        {selected && (
          <>
            <div className="kv-grid">
              <KV label="Entity" mono><Link className="link" to={`/entities/${encodeURIComponent(selected.entityId)}`}>{selected.entityId}</Link></KV>
              <KV label="Type">{selected.eventType}</KV>
              <KV label="Source">{selected.source ?? '—'}</KV>
              <KV label="Version">{selected.eventVersion}</KV>
              <KV label="Pipeline"><ProcessingBadge value={selected.processingStatus} /></KV>
              <KV label="Event UUID" mono copy={selected.id}>{selected.id.slice(0, 8)}…</KV>
            </div>
            {selected.lastProcessingError && <div className="form-error">{selected.lastProcessingError}</div>}
            <div>
              <h3 style={{ marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>Payload <CopyButton value={JSON.stringify(selected.payload, null, 2)} /></h3>
              <JsonViewer value={selected.payload} />
            </div>
          </>
        )}
      </Drawer>
    </>
  );
}
