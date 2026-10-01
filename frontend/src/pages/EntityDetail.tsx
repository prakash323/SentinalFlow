import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, BellRing, Database, ShieldAlert } from 'lucide-react';

import { alertsApi, entitiesApi, eventsApi, incidentsApi } from '../api/endpoints';
import {
  AlertStatusBadge,
  Badge,
  Card,
  DecisionBadge,
  EmptyState,
  ErrorState,
  IncidentStatusBadge,
  KV,
  LinkButton,
  Loading,
  PageHeader,
  ProcessingBadge,
  ScoreMeter,
  SeverityBadge,
  Skeleton,
  Tabs,
  TypeBadge,
} from '../components/ui';
import { fmtDate, formatApiError, num, timeAgo } from '../utils/format';

type Tab = 'events' | 'alerts' | 'incidents';

export default function EntityDetail() {
  const { entityId = '' } = useParams();
  const [tab, setTab] = useState<Tab>('alerts');

  const entity = useQuery({
    queryKey: ['entity', entityId],
    queryFn: () => entitiesApi.get(entityId),
    retry: false,
  });

  const events = useQuery({ queryKey: ['events', 'entity', entityId], queryFn: () => eventsApi.list({ entityId, size: 10 }), enabled: tab === 'events' });
  const alerts = useQuery({ queryKey: ['alerts', 'entity', entityId], queryFn: () => alertsApi.list({ entityId, size: 10 }), enabled: tab === 'alerts' });
  const incidents = useQuery({ queryKey: ['incidents', 'entity', entityId], queryFn: () => incidentsApi.list({ entityId, size: 10 }), enabled: tab === 'incidents' });

  if (entity.isLoading) return <Loading />;
  if (entity.isError || !entity.data) {
    return (
      <>
        <PageHeader eyebrow="Entity" title="Entity not found" actions={<LinkButton to="/entities" icon={ArrowLeft}>All entities</LinkButton>} />
        <Card><ErrorState title="Couldn’t load this entity" message={formatApiError(entity.error, 'Entity not found')} onRetry={() => entity.refetch()} /></Card>
      </>
    );
  }

  const e = entity.data;
  const filterQs = `entityId=${encodeURIComponent(e.entityId)}`;

  return (
    <>
      <PageHeader
        eyebrow="Entity"
        title={<span className="mono">{e.entityId}</span>}
        description={e.displayName || 'Monitored entity'}
        actions={<LinkButton to="/entities" icon={ArrowLeft}>All entities</LinkButton>}
      />

      <Card>
        <div className="kv-grid">
          <KV label="Type"><Badge tone="info" plain>{e.entityType}</Badge></KV>
          <KV label="Events"><span className="mono">{num(e.eventCount)}</span></KV>
          <KV label="Alerts"><span className="mono">{num(e.alertCount)}</span></KV>
          <KV label="Open alerts"><span className="mono" style={{ color: e.openAlertCount ? 'var(--c-critical)' : undefined }}>{num(e.openAlertCount)}</span></KV>
          <KV label="Open incidents"><span className="mono" style={{ color: e.openIncidentCount ? 'var(--c-critical)' : undefined }}>{num(e.openIncidentCount)}</span></KV>
          {/* Peak alert score: the highest score that ever crossed the alert
              threshold - distinct from "Latest decision"/"Latest score" below,
              which reflect the most recent prediction regardless of whether
              it triggered an alert. Neither is a new combined "risk score". */}
          <KV label="Peak alert score"><ScoreMeter value={e.maxScore} /></KV>
          <KV label="Latest decision">{e.latestPredictionDecision ? <DecisionBadge value={e.latestPredictionDecision} /> : '—'}</KV>
          <KV label="Latest score">{e.latestPredictionCreatedAt ? <ScoreMeter value={e.latestPredictionAnomalyScore} /> : '—'}</KV>
          <KV label="Latest prediction">{e.latestPredictionCreatedAt ? `${timeAgo(e.latestPredictionCreatedAt)} · ${fmtDate(e.latestPredictionCreatedAt)}` : '—'}</KV>
          <KV label="Last activity">{e.lastEventAt ? `${timeAgo(e.lastEventAt)} · ${fmtDate(e.lastEventAt)}` : '—'}</KV>
          <KV label="Monitored since">{fmtDate(e.createdAt)}</KV>
        </div>
      </Card>

      <div style={{ height: 12 }} />

      <Card flush>
        <div className="card-section" style={{ paddingBottom: 0 }}>
          <Tabs
            value={tab}
            onChange={setTab}
            tabs={[
              { value: 'alerts', label: 'Alerts', icon: BellRing, count: e.alertCount },
              { value: 'incidents', label: 'Incidents', icon: ShieldAlert },
              { value: 'events', label: 'Events', icon: Database, count: e.eventCount },
            ]}
          />
        </div>

        {tab === 'alerts' && (
          alerts.isLoading ? <div className="card-section"><Skeleton h={120} /></div>
          : alerts.isError ? <ErrorState message={formatApiError(alerts.error)} onRetry={() => alerts.refetch()} />
          : !alerts.data?.content.length ? <EmptyState title="No alerts" text="This entity has not triggered any alerts." icon={BellRing} />
          : (
            <>
              <div className="table-wrap"><table>
                <thead><tr><th>Severity</th><th>Event</th><th>Source</th><th>Score</th><th>Decision</th><th>Status</th><th>Raised</th></tr></thead>
                <tbody>{alerts.data.content.map((a) => (
                  <tr key={a.id}>
                    <td><SeverityBadge value={a.severity} /></td>
                    <td><Link className="mono link" to={`/alerts/${a.id}`}>{a.eventId ?? a.id.slice(0, 8)}</Link></td>
                    <td className="muted">{a.source ?? '—'}</td>
                    <td><ScoreMeter value={a.anomalyScore} /></td>
                    <td><DecisionBadge value={a.decision} /></td>
                    <td><AlertStatusBadge value={a.status} /></td>
                    <td>{timeAgo(a.createdAt)}</td>
                  </tr>
                ))}</tbody>
              </table></div>
              <div className="pagination"><span>Showing latest {alerts.data.content.length} of {alerts.data.totalElements}</span><Link className="link" to={`/alerts?${filterQs}`}>View all →</Link></div>
            </>
          )
        )}

        {tab === 'incidents' && (
          incidents.isLoading ? <div className="card-section"><Skeleton h={120} /></div>
          : incidents.isError ? <ErrorState message={formatApiError(incidents.error)} onRetry={() => incidents.refetch()} />
          : !incidents.data?.content.length ? <EmptyState title="No incidents" text="No incidents have been opened for this entity." icon={ShieldAlert} />
          : (
            <>
              <div className="table-wrap"><table>
                <thead><tr><th>Severity</th><th>Incident</th><th>Source</th><th>Alerts</th><th>Status</th><th>Opened</th></tr></thead>
                <tbody>{incidents.data.content.map((i) => (
                  <tr key={i.id}>
                    <td>{i.maxSeverity ? <SeverityBadge value={i.maxSeverity} /> : '—'}</td>
                    <td><Link className="link" to={`/incidents/${i.id}`}>{i.summary}</Link></td>
                    <td className="muted" title={i.sources?.join(', ')}>
                      {i.sources?.length ? `${i.sources[0]}${i.sources.length > 1 ? ` +${i.sources.length - 1}` : ''}` : '—'}
                    </td>
                    <td className="mono">{i.alertCount}</td>
                    <td><IncidentStatusBadge value={i.status} /></td>
                    <td>{timeAgo(i.createdAt)}</td>
                  </tr>
                ))}</tbody>
              </table></div>
              <div className="pagination"><span>Showing latest {incidents.data.content.length} of {incidents.data.totalElements}</span><Link className="link" to={`/incidents?${filterQs}`}>View all →</Link></div>
            </>
          )
        )}

        {tab === 'events' && (
          events.isLoading ? <div className="card-section"><Skeleton h={120} /></div>
          : events.isError ? <ErrorState message={formatApiError(events.error)} onRetry={() => events.refetch()} />
          : !events.data?.content.length ? <EmptyState title="No events" text="No events have been ingested for this entity." icon={Database} />
          : (
            <>
              <div className="table-wrap"><table>
                <thead><tr><th>Occurred</th><th>Event</th><th>Type</th><th>Source</th><th>Pipeline</th></tr></thead>
                <tbody>{events.data.content.map((ev) => (
                  <tr key={ev.id}>
                    <td>{timeAgo(ev.occurredAt)}</td>
                    <td><Link className="mono link" to={`/events/${encodeURIComponent(ev.eventId)}`}>{ev.eventId}</Link></td>
                    <td><TypeBadge value={ev.eventType} /></td>
                    <td className="muted">{ev.source ?? '—'}</td>
                    <td><ProcessingBadge value={ev.processingStatus} /></td>
                  </tr>
                ))}</tbody>
              </table></div>
              <div className="pagination"><span>Showing latest {events.data.content.length} of {events.data.totalElements}</span><Link className="link" to={`/events?${filterQs}`}>View all →</Link></div>
            </>
          )
        )}
      </Card>
    </>
  );
}
