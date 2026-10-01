import { Link, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, BellRing, ClipboardList, Sparkles } from 'lucide-react';

import { incidentsApi } from '../api/endpoints';
import { AiAssist } from '../components/AiAssist';
import type { AiAction } from '../components/AiAssist';
import { useToast } from '../components/feedback';
import {
  AlertStatusBadge,
  Card,
  CardHead,
  EmptyState,
  ErrorState,
  IncidentStatusBadge,
  KV,
  LinkButton,
  Loading,
  PageHeader,
  ScoreMeter,
  SeverityBadge,
  Skeleton,
} from '../components/ui';
import { LifecycleStepper, TransitionButtons } from '../components/Workflow';
import { fmtDate, formatApiError, humanize, timeAgo } from '../utils/format';
import { INCIDENT_LIFECYCLE, nextIncidentStatuses } from '../utils/workflow';
import type { IncidentStatusValue } from '../types/domain';

// Concise by default. The evidence-summary endpoint still exists on the API; the summary here already
// covers what it returned, so it is not offered as a third, overlapping button.
const AI_ACTIONS: AiAction[] = [
  { id: 'explanation', label: 'Summarize', resultLabel: 'Summary', icon: Sparkles },
  { id: 'investigation', label: 'Investigation guidance', icon: ClipboardList },
];

export default function IncidentDetail() {
  const { id = '' } = useParams();
  const qc = useQueryClient();
  const toast = useToast();

  const incident = useQuery({ queryKey: ['incident', id], queryFn: () => incidentsApi.get(id), retry: false });
  const alerts = useQuery({ queryKey: ['incident-alerts', id], queryFn: () => incidentsApi.alerts(id), retry: false });

  const update = useMutation({
    mutationFn: (status: IncidentStatusValue) => incidentsApi.updateStatus(id, status),
    onSuccess: (updated) => {
      qc.setQueryData(['incident', id], updated);
      // Changing an incident also synchronizes its alerts server-side.
      qc.invalidateQueries({ queryKey: ['incident-alerts', id] });
      qc.invalidateQueries({ queryKey: ['incidents'] });
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['dashboard'] });
      toast.success('Incident updated', `Status is now ${humanize(updated.status)}; linked alerts were synchronized.`);
    },
    onError: (e) => toast.error('Status change rejected', formatApiError(e)),
  });

  if (incident.isLoading) return <Loading />;
  if (incident.isError || !incident.data) {
    return (
      <>
        <PageHeader eyebrow="Incident" title="Incident not found" />
        <Card><ErrorState title="Couldn’t load this incident" message={formatApiError(incident.error, 'Incident not found')} onRetry={() => incident.refetch()} /></Card>
      </>
    );
  }

  const i = incident.data;

  return (
    <>
      <PageHeader
        eyebrow="Incident"
        title={i.summary}
        description={<span className="mono">{i.incidentKey}</span>}
        actions={<LinkButton to="/incidents" icon={ArrowLeft}>Back to incidents</LinkButton>}
      />

      <div className="grid-main">
        <Card>
          <CardHead title="Overview" actions={<IncidentStatusBadge value={i.status} />} />
          <div className="kv-grid">
            <KV label="Entity" mono><Link className="link" to={`/entities/${encodeURIComponent(i.entityId)}`}>{i.entityId}</Link></KV>
            <KV label="Peak severity">{i.maxSeverity ? <SeverityBadge value={i.maxSeverity} /> : '—'}</KV>
            <KV label="Peak score"><ScoreMeter value={i.maxScore} /></KV>
            <KV label="Linked alerts"><span className="mono">{i.alertCount}</span></KV>
            <KV label="Opened">{fmtDate(i.createdAt)}</KV>
            <KV label="Last update">{timeAgo(i.updatedAt)}</KV>
            <KV label="Closed">{fmtDate(i.closedAt)}</KV>
          </div>
        </Card>

        <Card>
          <CardHead kicker="Workflow" title="Investigation status" description="Resolving or closing an incident also resolves or closes its still-active alerts." />
          <LifecycleStepper steps={INCIDENT_LIFECYCLE} current={i.status} />
          <div className="divider" style={{ margin: '12px 0' }} />
          <TransitionButtons options={nextIncidentStatuses(i.status)} pending={update.isPending ? (update.variables ?? null) : null} onPick={(s) => update.mutate(s as IncidentStatusValue)} />
        </Card>
      </div>

      <Card flush>
        <div className="card-section">
          <CardHead kicker="Evidence" kickerIcon={BellRing} title="Linked alerts" description="Every alert grouped into this incident, newest first." />
        </div>
        {alerts.isLoading ? (
          <div className="card-section"><Skeleton h={100} /></div>
        ) : alerts.isError ? (
          <ErrorState message={formatApiError(alerts.error)} onRetry={() => alerts.refetch()} />
        ) : !alerts.data?.length ? (
          <EmptyState title="No linked alerts" text="No alerts have been attached to this incident." icon={BellRing} />
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Severity</th><th>Event</th><th>Score</th><th>Status</th><th>Raised</th></tr></thead>
              <tbody>
                {alerts.data.map((a) => (
                  <tr key={a.id}>
                    <td><SeverityBadge value={a.severity} /></td>
                    <td><Link className="mono link" to={`/alerts/${a.id}`}>{a.eventId ?? a.id.slice(0, 8)}</Link></td>
                    <td><ScoreMeter value={a.fusedScore ?? a.anomalyScore} /></td>
                    <td><AlertStatusBadge value={a.status} /></td>
                    <td title={fmtDate(a.createdAt)}>{timeAgo(a.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <AiAssist
        title="AI summary"
        description="Generated on demand from evidence the platform already computed. It can summarize and recommend — it cannot change severity, decisions or status."
        basis="Based on ML evidence and linked alerts"
        unavailableText="The AI investigation service is currently unavailable. The incident and its ML evidence remain available."
        actions={AI_ACTIONS}
        request={(kind, detail) => incidentsApi.ai(id, kind as 'explanation' | 'investigation', detail)}
        resetKey={`${i.status}|${i.updatedAt}|${i.alertCount}`}
      />
    </>
  );
}
