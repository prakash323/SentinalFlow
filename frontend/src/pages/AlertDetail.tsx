import { Link, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, BrainCircuit, GitBranch, ShieldAlert, Sparkles } from 'lucide-react';

import { alertsApi, eventsApi } from '../api/endpoints';
import { AiAssist } from '../components/AiAssist';
import type { AiAction } from '../components/AiAssist';
import { ScoreRing } from '../components/charts';
import { useToast } from '../components/feedback';
import {
  AlertStatusBadge,
  Card,
  CardHead,
  DecisionBadge,
  ErrorState,
  KV,
  LinkButton,
  Loading,
  PageHeader,
  SeverityBadge,
  Skeleton,
} from '../components/ui';
import { LifecycleStepper, TransitionButtons } from '../components/Workflow';
import { fmtDate, formatApiError, humanize, pct } from '../utils/format';
import { ALERT_LIFECYCLE, nextAlertStatuses } from '../utils/workflow';
import type { AlertStatusValue } from '../types/domain';

const AI_ACTIONS: AiAction[] = [{ id: 'explanation', label: 'Explain alert', icon: Sparkles }];

export default function AlertDetail() {
  const { id = '' } = useParams();
  const qc = useQueryClient();
  const toast = useToast();

  const alert = useQuery({ queryKey: ['alert', id], queryFn: () => alertsApi.get(id), retry: false });
  const a = alert.data;

  // The ML reasoning (attack type, explanation) lives on the prediction of the alert's event.
  const trail = useQuery({
    queryKey: ['event-trail', a?.eventId],
    queryFn: () => eventsApi.trail(a!.eventId!),
    enabled: !!a?.eventId,
    retry: false,
  });

  const update = useMutation({
    mutationFn: (status: AlertStatusValue) => alertsApi.updateStatus(id, status),
    onSuccess: (updated) => {
      qc.setQueryData(['alert', id], updated);
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['dashboard'] });
      toast.success('Alert updated', `Status is now ${humanize(updated.status)}.`);
    },
    onError: (e) => toast.error('Status change rejected', formatApiError(e)),
  });

  if (alert.isLoading) return <Loading />;
  if (alert.isError || !a) {
    return (
      <>
        <PageHeader eyebrow="Alert" title="Alert not found" />
        <Card><ErrorState title="Couldn’t load this alert" message={formatApiError(alert.error, 'Alert not found')} onRetry={() => alert.refetch()} /></Card>
      </>
    );
  }

  const f = trail.data?.prediction?.features ?? {};
  const score = a.fusedScore ?? a.anomalyScore;
  // Independent deterministic detection (P1): this alert's own trigger is
  // either a platform rule (a.ruleId set, no prediction) or the ML
  // ensemble - never both. The event's ML narrative below is a separate,
  // real fact about the same event, not this alert's own cause, so it must
  // never be presented as "why this was flagged" for a rule-raised alert.
  const isRuleDetection = a.detectionType === 'RULE';

  return (
    <>
      <PageHeader
        eyebrow="Alert"
        title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>{a.entityId} <SeverityBadge value={a.severity} /> <AlertStatusBadge value={a.status} /></span>}
        description={a.factors?.length ? a.factors.join(' · ') : 'Anomalous activity detected by the detection pipeline.'}
        actions={<LinkButton to="/alerts" icon={ArrowLeft}>Back to alerts</LinkButton>}
      />

      <div className="grid-main">
        <Card>
          <CardHead title="Signal" description="What the model saw and how the alert policy graded it." />
          <div className="drawer-hero">
            <ScoreRing value={score} size={150} stroke={12} label="fused score" />
            <div className="kv-grid tight" style={{ flex: 1 }}>
              <KV label="Severity"><SeverityBadge value={a.severity} /></KV>
              <KV label="Decision"><DecisionBadge value={a.decision} /></KV>
              <KV label="Anomaly score"><span className="mono">{a.anomalyScore?.toFixed(4) ?? '—'}</span></KV>
              <KV label="Confidence">{pct(a.confidence ?? undefined)}</KV>
              <KV label="Entity" mono><Link className="link" to={`/entities/${encodeURIComponent(a.entityId)}`}>{a.entityId}</Link></KV>
              <KV label="Event" mono>{a.eventId ? <Link className="link" to={`/events/${encodeURIComponent(a.eventId)}`}>{a.eventId}</Link> : '—'}</KV>
              <KV label="Policy" mono>{a.policyVersion}</KV>
              <KV label="Raised">{fmtDate(a.createdAt)}</KV>
              <KV label="Updated">{fmtDate(a.updatedAt)}</KV>
            </div>
          </div>
          {a.incidentId && (
            <Link to={`/incidents/${a.incidentId}`} className="linked-card">
              <ShieldAlert size={18} />
              <div><strong>Part of an incident</strong><span>This alert is grouped with related activity for {a.entityId}.</span></div>
              <span className="link">Open incident →</span>
            </Link>
          )}
        </Card>

        <Card>
          <CardHead kicker="Workflow" title="Triage" description="Move this alert through its lifecycle. The backend enforces the allowed transitions and records every change in the audit log." />
          {a.status === 'FALSE_POSITIVE' ? (
            <div className="form-error" style={{ color: 'var(--text-2)', background: 'var(--panel-2)', borderColor: 'var(--border)' }}>Marked as a false positive.</div>
          ) : (
            <LifecycleStepper steps={ALERT_LIFECYCLE} current={a.status} />
          )}
          <div className="divider" style={{ margin: '12px 0' }} />
          <TransitionButtons options={nextAlertStatuses(a.status)} pending={update.isPending ? (update.variables ?? null) : null} onPick={(s) => update.mutate(s as AlertStatusValue)} />
        </Card>
      </div>

      <Card>
        <CardHead
          kicker="Explainability"
          kickerIcon={BrainCircuit}
          title="Why this was flagged"
          description={
            isRuleDetection
              ? `Evidence recorded by the deterministic rule "${a.ruleName ?? a.ruleId}" - not an ML prediction.`
              : 'Evidence the ML ensemble attached to the prediction.'
          }
        />
        <div className="grid-2 flat">
          <div>
            <h3 className="drawer-h">Ranked factors</h3>
            {a.factors?.length ? (
              <div className="factor-list vertical">{a.factors.map((x, i) => <span className="factor" key={i}><b>{i + 1}</b>{x}</span>)}</div>
            ) : (
              <p className="muted">No explanation factors were attached to this alert.</p>
            )}
          </div>
          <div>
            <h3 className="drawer-h">Model narrative</h3>
            {isRuleDetection ? (
              <p className="muted">
                This alert was raised by a deterministic rule, not the ML model - see Ranked factors. Any ML
                assessment of the same underlying event is independent of this alert and appears in the detection
                trail below, not here.
              </p>
            ) : trail.isLoading ? (
              <Skeleton h={90} />
            ) : f.reason ? (
              <>
                <p className="trail-reason">{String(f.reason)}</p>
                <div className="row-gap" style={{ marginTop: 12 }}>
                  {f.attackType && <span className="badge tone-high plain">Predicted: {humanize(String(f.attackType))}</span>}
                  {typeof f.riskScore === 'number' && <span className="badge tone-info plain">Risk {f.riskScore.toFixed(1)} / 100</span>}
                </div>
              </>
            ) : (
              <p className="muted">The model did not attach a narrative — this alert was raised by the policy threshold on a score the model itself classed as normal.</p>
            )}
            {a.eventId && (
              <p style={{ marginTop: 12 }}>
                <Link className="link inline" to={`/events/${encodeURIComponent(a.eventId)}`}><GitBranch size={14} />See the full detection trail</Link>
              </p>
            )}
          </div>
        </div>
      </Card>

      <AiAssist
        title="AI explanation"
        description={
          isRuleDetection
            ? "Generated on demand from the alert's stored rule evidence. It explains why the alert fired — it cannot change severity, decision or status."
            : "Generated on demand from the alert's stored ML evidence. It explains why the alert fired — it cannot change severity, decision or status."
        }
        basis={isRuleDetection ? 'Based on rule evidence' : 'Based on ML evidence'}
        unavailableText="The AI explanation service is currently unavailable. The alert and its stored evidence remain available."
        actions={AI_ACTIONS}
        request={(_, detail) => alertsApi.ai(id, detail)}
        resetKey={`${a.status}|${a.updatedAt}|${a.incidentId ?? ''}`}
      />
    </>
  );
}
