import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Activity, ExternalLink } from 'lucide-react';

import { predictionsApi } from '../api/endpoints';
import { ScoreRing } from '../components/charts';
import EntitySelect from '../components/EntitySelect';
import { Drawer } from '../components/feedback';
import {
  Card,
  ClearFilters,
  DecisionBadge,
  EmptyState,
  ErrorState,
  JsonViewer,
  KV,
  LinkButton,
  PageHeader,
  Pagination,
  ScoreMeter,
  Select,
  TableSkeleton,
} from '../components/ui';
import { useUrlState } from '../hooks/useUrlState';
import { DECISIONS } from '../types/domain';
import type { Prediction } from '../types/domain';
import { fmtDate, formatApiError, humanize, pct, timeAgo } from '../utils/format';

const DEFAULTS = { entityId: '', decision: '' };

export default function Predictions() {
  const { state, set, reset, activeCount } = useUrlState(DEFAULTS);
  const [selected, setSelected] = useState<Prediction | null>(null);

  const q = useQuery({
    queryKey: ['predictions', state.entityId, state.decision, state.page],
    queryFn: () => predictionsApi.list({ entityId: state.entityId, decision: state.decision, page: state.page, size: 20 }),
    placeholderData: (prev) => prev,
  });

  const f = selected?.features ?? {};

  return (
    <>
      <PageHeader
        eyebrow="Detection"
        title="Predictions"
        description="Every score produced by the ML ensemble, with the decision the platform mapped it to."
      />

      <Card flush>
        <div className="filters">
          <EntitySelect value={state.entityId} onChange={(v) => set({ entityId: v })} />
          <Select value={state.decision} onChange={(v) => set({ decision: v })} options={DECISIONS} placeholder="All decisions" />
          {activeCount > 0 && <ClearFilters onClick={reset} />}
        </div>

        {q.isLoading ? (
          <TableSkeleton />
        ) : q.isError ? (
          <ErrorState message={formatApiError(q.error, 'Unable to load predictions')} onRetry={() => q.refetch()} />
        ) : !q.data?.content.length ? (
          <EmptyState title="No predictions" text={activeCount ? 'No predictions match these filters.' : 'Predictions appear once events have been scored.'} icon={Activity} />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Scored</th><th>Event</th><th>Entity</th><th>Anomaly score</th><th className="num">Confidence</th><th>Decision</th><th>Attack type</th></tr>
                </thead>
                <tbody>
                  {q.data.content.map((p) => (
                    <tr
                      key={p.id}
                      className="clickable"
                      tabIndex={0}
                      aria-label={`Open prediction details for event ${p.eventId}`}
                      onClick={() => setSelected(p)}
                      onKeyDown={(ev) => {
                        if (ev.target === ev.currentTarget && (ev.key === 'Enter' || ev.key === ' ')) {
                          ev.preventDefault();
                          setSelected(p);
                        }
                      }}
                    >
                      <td><div className="cell-stack"><span>{timeAgo(p.createdAt)}</span><small>{fmtDate(p.createdAt)}</small></div></td>
                      <td><Link className="mono link" to={`/events/${encodeURIComponent(p.eventId)}`} onClick={(e) => e.stopPropagation()}>{p.eventId}</Link></td>
                      <td className="mono">{p.entityId}</td>
                      <td><ScoreMeter value={p.anomalyScore} /></td>
                      <td className="num mono">{pct(p.confidence ?? undefined)}</td>
                      <td><DecisionBadge value={p.decision} /></td>
                      <td className="muted">{p.features?.attackType ? humanize(String(p.features.attackType)) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={state.page} totalPages={q.data.totalPages} totalElements={q.data.totalElements} itemLabel="predictions" onPageChange={(p) => set({ page: p })} />
          </>
        )}
      </Card>

      <Drawer
        open={!!selected}
        onClose={() => setSelected(null)}
        title={selected ? `Prediction for ${selected.eventId}` : ''}
        subtitle={selected ? `${selected.modelName} · ${selected.modelVersion}` : undefined}
        footer={selected && <LinkButton to={`/events/${encodeURIComponent(selected.eventId)}`} variant="primary" icon={ExternalLink}>Open event trail</LinkButton>}
      >
        {selected && (
          <>
            <div className="drawer-hero">
              <ScoreRing value={selected.fusedScore ?? selected.anomalyScore} size={124} />
              <div className="kv-grid tight">
                <KV label="Decision"><DecisionBadge value={selected.decision} /></KV>
                <KV label="ML verdict">{humanize(f.mlDecision)}</KV>
                <KV label="Risk (0–100)"><span className="mono">{typeof f.riskScore === 'number' ? f.riskScore.toFixed(1) : '—'}</span></KV>
                <KV label="Confidence">{pct(selected.confidence ?? undefined)}</KV>
                <KV label="Entity" mono>{selected.entityId}</KV>
                <KV label="Scored">{fmtDate(selected.createdAt)}</KV>
              </div>
            </div>
            {f.reason && (
              <div>
                <h3 className="drawer-h">Why the model scored it this way</h3>
                <p className="trail-reason">{String(f.reason)}</p>
              </div>
            )}
            {!!f.factors?.length && (
              <div>
                <h3 className="drawer-h">Top factors</h3>
                <div className="factor-list">{f.factors.map((x, i) => <span className="factor" key={i}><b>{i + 1}</b>{x}</span>)}</div>
              </div>
            )}
            <div>
              <h3 className="drawer-h">Raw features</h3>
              <JsonViewer value={selected.features} />
            </div>
          </>
        )}
      </Drawer>
    </>
  );
}
