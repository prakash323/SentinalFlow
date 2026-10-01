import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, BellRing, BrainCircuit, CheckCircle2, Database, GitBranch, Hourglass, Link2, ShieldAlert, XCircle } from 'lucide-react';

import { eventsApi } from '../api/endpoints';
import { ScoreRing } from '../components/charts';
import {
  Badge,
  Card,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  JsonViewer,
  KV,
  LinkButton,
  Loading,
  PageHeader,
  ProcessingBadge,
  SeverityBadge,
  Skeleton,
  TypeBadge,
} from '../components/ui';
import { fmtDate, formatApiError, humanize, pct } from '../utils/format';
import { findRelatedActivity, type RelatedActivityMatch } from '../utils/relatedActivity';
import type { EventRecord, EventTrail } from '../types/domain';

// Neutral, non-causal wording only - see relatedActivity.ts. Never
// "caused by" / "responsible for" / "performed by".
function reasonLabel(reason: RelatedActivityMatch['reason']): string {
  if (reason.kind === 'pid-process-create-time') return 'Associated by pid + process creation time';
  return 'Associated by username';
}

function reasonDetail(reason: RelatedActivityMatch['reason']): string {
  if (reason.kind === 'pid-process-create-time') return `pid: ${reason.pid}`;
  return `username: ${reason.username}`;
}

// Correlation Consumption v2: the backend hard-caps page size at 100
// (EventService.list), so a single page-0 fetch silently misses real
// correlations once an entity accumulates more than 100 events (verified
// live against HOST-LAPTOP-HIK1MN09, which already exceeds this). This
// walks a small, fixed budget of pages through the SAME existing
// entity-scoped endpoint - no new API, no schema change - and reports
// honestly whether the whole entity was actually covered.
const RELATED_ACTIVITY_MAX_PAGES = 3; // 3 x 100 = 300 events per entity, ceiling

type RelatedActivityPool = {
  events: EventRecord[];
  // true only when every event for this entity was fetched (the backend
  // reported no further pages within the budget) - false means the pool
  // is a bounded window, not the whole history, and a "no match" result
  // must say so rather than implying completeness it cannot prove.
  exhausted: boolean;
};

async function fetchRelatedActivityPool(entityId: string): Promise<RelatedActivityPool> {
  const events: EventRecord[] = [];

  for (let page = 0; page < RELATED_ACTIVITY_MAX_PAGES; page += 1) {
    const response = await eventsApi.list({ entityId, size: 100, page });
    events.push(...response.content);
    if (page + 1 >= response.totalPages) {
      return { events, exhausted: true };
    }
  }

  return { events, exhausted: false };
}

type Step = {
  tone: 'ok' | 'info' | 'medium' | 'critical' | 'neutral';
  icon: typeof Database;
  title: string;
  meta: string;
  body?: React.ReactNode;
};

function buildSteps(trail: EventTrail, createdAt?: string | null): Step[] {
  const steps: Step[] = [
    { tone: 'ok', icon: Database, title: 'Event persisted', meta: fmtDate(createdAt) },
  ];

  if (trail.processingStatus === 'PENDING') {
    steps.push({
      tone: 'medium',
      icon: Hourglass,
      title: 'Waiting for the detection pipeline',
      meta: 'Published to Kafka (raw.events.v1) — this page refreshes automatically',
    });
    return steps;
  }

  steps.push({ tone: 'ok', icon: GitBranch, title: 'Consumed from Kafka', meta: 'Delivered to the event processing service' });

  if (trail.processingStatus === 'FAILED') {
    steps.push({
      tone: 'critical',
      icon: XCircle,
      title: 'Processing failed',
      meta: `After ${trail.processingAttempts} attempt${trail.processingAttempts === 1 ? '' : 's'}`,
      body: trail.lastProcessingError ? <div className="form-error">{trail.lastProcessingError}</div> : undefined,
    });
    return steps;
  }

  const p = trail.prediction;
  if (p) {
    const f = p.features ?? {};
    steps.push({
      tone: 'info',
      icon: BrainCircuit,
      title: 'Scored by the ML ensemble',
      meta: `${p.modelName} · ${p.modelVersion}`,
      body: (
        <div className="trail-score">
          <ScoreRing value={p.fusedScore ?? p.anomalyScore} size={116} stroke={10} />
          <div className="trail-score-body">
            <div className="kv-grid tight">
              <KV label="Decision"><DecisionBadge value={p.decision} /></KV>
              <KV label="ML verdict">{humanize(f.mlDecision)}</KV>
              <KV label="Risk (0–100)"><span className="mono">{typeof f.riskScore === 'number' ? f.riskScore.toFixed(1) : '—'}</span></KV>
              <KV label="Attack type">{f.attackType ? humanize(String(f.attackType)) : '—'}</KV>
              <KV label="Confidence">{pct(p.confidence ?? undefined)}</KV>
            </div>
            {f.reason && <p className="trail-reason">{String(f.reason)}</p>}
            {!!f.factors?.length && (
              <div className="factor-list">
                {f.factors.map((x, i) => (
                  <span className="factor" key={i}><b>{i + 1}</b>{x}</span>
                ))}
              </div>
            )}
          </div>
        </div>
      ),
    });
  }

  if (trail.alert) {
    steps.push({
      tone: 'critical',
      icon: BellRing,
      title: 'Alert raised',
      meta: `Policy ${trail.alert.policyVersion}`,
      body: (
        <div className="row-gap">
          <SeverityBadge value={trail.alert.severity} />
          <Link className="link" to={`/alerts/${trail.alert.id}`}>Open alert</Link>
          {trail.alert.incidentId && <Link className="link inline" to={`/incidents/${trail.alert.incidentId}`}><ShieldAlert size={14} />Incident</Link>}
        </div>
      ),
    });
  } else if (p) {
    steps.push({
      tone: 'ok',
      icon: CheckCircle2,
      title: 'No alert raised',
      meta: 'The score stayed below the alert policy threshold',
    });
  }

  return steps;
}

export default function EventDetail() {
  const { eventId = '' } = useParams();

  const event = useQuery({ queryKey: ['event', eventId], queryFn: () => eventsApi.get(eventId), retry: false });
  const trail = useQuery({
    queryKey: ['event-trail', eventId],
    queryFn: () => eventsApi.trail(eventId),
    retry: false,
    // Keep polling until the pipeline reaches a terminal state.
    refetchInterval: (query) => (query.state.data?.processingStatus === 'PENDING' ? 2500 : false),
  });

  // Correlation Consumption v1/v2: fetch this event's entity's own event
  // history (existing endpoint, no new API) and match at read time only
  // - see utils/relatedActivity.ts. Walks up to RELATED_ACTIVITY_MAX_PAGES
  // pages (see fetchRelatedActivityPool above) rather than only page 0.
  const entityId = event.data?.entityId;
  const related = useQuery({
    queryKey: ['event-related-pool', entityId],
    queryFn: () => fetchRelatedActivityPool(entityId!),
    enabled: !!entityId,
    retry: false,
  });

  if (event.isLoading) return <Loading />;
  if (event.isError) {
    return (
      <>
        <PageHeader eyebrow="Event" title="Event not found" />
        <Card>
          <ErrorState title="Couldn’t load this event" message={formatApiError(event.error, 'Event not found')} onRetry={() => event.refetch()} />
        </Card>
      </>
    );
  }

  const e = event.data!;
  const steps = trail.data ? buildSteps(trail.data, e.createdAt) : [];
  const relatedMatches = related.data ? findRelatedActivity(e, related.data.events) : [];
  // exhausted alone would already imply the anchor was swept up (it shares
  // this same entityId, so a fully-fetched entity necessarily includes it)
  // - the explicit membership check is kept anyway so a "complete" claim
  // can never be made without the anchor itself actually being present.
  const anchorInFetchedPool = related.data ? related.data.events.some((ev) => ev.eventId === e.eventId) : false;
  const relatedSearchComplete = !!related.data && related.data.exhausted && anchorInFetchedPool;

  return (
    <>
      <PageHeader
        eyebrow="Event"
        title={<span className="mono">{e.eventId}</span>}
        description={`${e.eventType} from ${e.source ?? 'unknown source'} for ${e.entityId}`}
        actions={<LinkButton to="/events" icon={ArrowLeft}>Back to events</LinkButton>}
      />

      <div className="grid-2">
        <Card>
          <CardHead title="Overview" description="Canonical event metadata" actions={<ProcessingBadge value={e.processingStatus} />} />
          <div className="kv-grid">
            <KV label="Event ID" mono copy={e.eventId}>{e.eventId}</KV>
            <KV label="Entity" mono><Link className="link" to={`/entities/${encodeURIComponent(e.entityId)}`}>{e.entityId}</Link></KV>
            <KV label="Type"><Badge tone="info" plain>{e.eventType}</Badge></KV>
            <KV label="Version">{e.eventVersion}</KV>
            <KV label="Source">{e.source ?? '—'}</KV>
            <KV label="Occurred at">{fmtDate(e.occurredAt)}</KV>
            <KV label="Persisted at">{fmtDate(e.createdAt)}</KV>
            <KV label="Processed at">{fmtDate(e.processedAt)}</KV>
            <KV label="Database ID" mono copy={e.id}>{e.id.slice(0, 13)}…</KV>
          </div>
        </Card>

        <Card>
          <CardHead title="Payload" description="Read-only JSON exactly as ingested" />
          <JsonViewer value={e.payload} />
        </Card>
      </div>

      <Card>
        <CardHead kicker="Detection trail" kickerIcon={GitBranch} title="What the pipeline did with this event" description="Event → Kafka → ML scoring → alert policy → incident." />
        {trail.isLoading ? (
          <Loading label="Reading the pipeline trail…" />
        ) : trail.isError ? (
          <ErrorState message={formatApiError(trail.error)} onRetry={() => trail.refetch()} />
        ) : (
          <div className="timeline">
            {steps.map((s, i) => (
              <div className={`tl-item${i < steps.length - 1 ? ' done' : ''}`} key={i} style={{ ['--tone' as string]: `var(--c-${s.tone})` }}>
                <span className="tl-dot"><s.icon size={16} /></span>
                <div className="tl-body">
                  <strong>{s.title}</strong>
                  <span>{s.meta}</span>
                  {s.body && <div className="tl-extra">{s.body}</div>}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <CardHead
          kicker="Related activity"
          kickerIcon={Link2}
          title="Other records associated with this event"
          description="Matched by shared identifiers observed in the telemetry (pid, process creation time, username) - this is an association, not a security conclusion or a claim about causality."
        />
        {!entityId || related.isLoading ? (
          <Skeleton h={100} />
        ) : related.isError ? (
          <ErrorState message={formatApiError(related.error)} onRetry={() => related.refetch()} />
        ) : relatedMatches.length === 0 ? (
          <EmptyState
            title="No related activity"
            text={
              relatedSearchComplete
                ? 'No related activity found in the available events for this entity.'
                : 'No related activity found in the events searched so far. Related activity may exist outside the current search window.'
            }
            icon={Link2}
          />
        ) : (
          <>
            {relatedMatches.length > 1 && (
              <p className="muted" style={{ marginBottom: 10 }}>
                {relatedMatches.length} matching records — shown individually, not reduced to one.
              </p>
            )}
            <div className="table-wrap">
              <table>
                <thead><tr><th>Type</th><th>Event</th><th>Occurred</th><th>Source</th><th>Associated by</th></tr></thead>
                <tbody>
                  {relatedMatches.map((m) => (
                    <tr key={m.event.eventId}>
                      <td><TypeBadge value={m.event.eventType} /></td>
                      <td><Link className="mono link" to={`/events/${encodeURIComponent(m.event.eventId)}`}>{m.event.eventId}</Link></td>
                      <td>{fmtDate(m.event.occurredAt)}</td>
                      <td className="muted">{m.event.source ?? '—'}</td>
                      <td>
                        <div className="cell-stack">
                          <span>{reasonLabel(m.reason)}</span>
                          <small className="mono muted">{reasonDetail(m.reason)}</small>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Card>
    </>
  );
}
