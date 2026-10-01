import { useQuery } from '@tanstack/react-query';
import { motion } from 'motion/react';
import { CheckCircle2, Cpu, Database, GitBranch, RefreshCw, Server, XCircle } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { systemApi } from '../api/endpoints';
import { Badge, Button, Card, CardHead, ErrorState, PageHeader, Skeleton } from '../components/ui';
import { fmtTimeSec, formatApiError, num } from '../utils/format';
import type { Tone } from '../utils/tone';

const ICONS: Record<string, LucideIcon> = {
  'Spring Boot API': Server,
  PostgreSQL: Database,
  Kafka: GitBranch,
  'ML service': Cpu,
};

const overallMeta: Record<string, { tone: Tone; text: string }> = {
  UP: { tone: 'ok', text: 'All systems operational' },
  DEGRADED: { tone: 'medium', text: 'Degraded — a dependency is down' },
  DOWN: { tone: 'critical', text: 'Database unreachable' },
};

export default function System() {
  const q = useQuery({ queryKey: ['system-status'], queryFn: systemApi.status, refetchInterval: 15000, retry: false });

  if (q.isLoading) {
    return (
      <>
        <PageHeader eyebrow="Administration" title="System status" />
        <div className="grid-4">{[0, 1, 2, 3].map((i) => <Card key={i}><Skeleton h={90} /></Card>)}</div>
      </>
    );
  }

  if (q.isError || !q.data) {
    return (
      <>
        <PageHeader eyebrow="Administration" title="System status" />
        <Card><ErrorState title="Status unavailable" message={formatApiError(q.error, 'The backend did not answer the status probe.')} onRetry={() => q.refetch()} /></Card>
      </>
    );
  }

  const s = q.data;
  const meta = overallMeta[s.overall] ?? { tone: 'neutral' as Tone, text: s.overall };
  const total = Object.values(s.pipeline).reduce((a, b) => a + b, 0);
  const p = s.policy;

  // Alert-policy scale runs 0.98 → 1.0 so the three severity bands are visible.
  const min = 0.98;
  const at = (v: number) => `${Math.max(0, Math.min(100, ((v - min) / (1 - min)) * 100))}%`;

  return (
    <>
      <PageHeader
        eyebrow="Administration"
        title="System status"
        description="Live health of every dependency in the detection pipeline, probed on each refresh."
        actions={
          <>
            <Badge tone={meta.tone} dot>{meta.text}</Badge>
            <Button variant="secondary" icon={RefreshCw} loading={q.isFetching} onClick={() => q.refetch()}>Re-check</Button>
          </>
        }
      />

      <div className="grid-4">
        {s.components.map((c, i) => {
          const Icon = ICONS[c.name] ?? Server;
          const up = c.status === 'UP';
          return (
            <Card key={c.name} delay={i * 0.05} className={`sys-card ${up ? 'up' : 'down'}`}>
              <div className="kpi-top">
                <span className="kpi-icon" style={{ color: up ? 'var(--c-ok)' : 'var(--c-critical)', background: `color-mix(in srgb, ${up ? 'var(--c-ok)' : 'var(--c-critical)'} 14%, transparent)` }}><Icon size={18} /></span>
                <span className="kpi-label">{c.name}</span>
                {up ? <CheckCircle2 size={17} color="var(--c-ok)" style={{ marginLeft: 'auto' }} /> : <XCircle size={17} color="var(--c-critical)" style={{ marginLeft: 'auto' }} />}
              </div>
              <div className="sys-status">{up ? 'Operational' : 'Unavailable'}</div>
              <div className="sys-detail">{c.detail}</div>
              <div className="sys-latency mono">{c.latencyMs != null ? `${c.latencyMs} ms` : '—'}</div>
            </Card>
          );
        })}
      </div>

      <div className="grid-2">
        <Card>
          <CardHead kicker="Throughput" title="Event processing pipeline" description="Where every stored event currently stands." />
          <div className="stack-bar tall">
            {(['PROCESSED', 'PENDING', 'FAILED'] as const).map((k) => (
              <motion.div
                key={k}
                initial={{ flexGrow: 0 }}
                animate={{ flexGrow: s.pipeline[k] ?? 0 }}
                style={{ background: k === 'PROCESSED' ? 'var(--c-ok)' : k === 'PENDING' ? 'var(--c-medium)' : 'var(--c-critical)' }}
                title={`${k} ${s.pipeline[k] ?? 0}`}
              />
            ))}
          </div>
          <div className="sim-summary" style={{ marginTop: 12 }}>
            <div><span>Total</span><b>{num(total)}</b></div>
            <div><span>Processed</span><b style={{ color: 'var(--c-ok)' }}>{num(s.pipeline.PROCESSED ?? 0)}</b></div>
            <div><span>Pending</span><b style={{ color: 'var(--c-medium)' }}>{num(s.pipeline.PENDING ?? 0)}</b></div>
            <div><span>Failed</span><b style={{ color: 'var(--c-critical)' }}>{num(s.pipeline.FAILED ?? 0)}</b></div>
          </div>
          <p className="muted" style={{ marginTop: 10, fontSize: 12.5 }}>
            “Pending” includes events stored before the ML integration existed and events still in flight; failed events are retried by Kafka and dead-lettered to <span className="mono">raw.events.v1.DLT</span>.
          </p>
        </Card>

        <Card>
          <CardHead kicker="Policy" title="Alert policy" description={<>Version <span className="mono">{p.version}</span> — scores at or above the threshold raise an alert.</>} />
          <div className="policy-scale">
            <div className="policy-track">
              <div className="policy-band" style={{ left: at(p.medium), width: `calc(${at(p.high)} - ${at(p.medium)})`, background: 'var(--c-medium)' }} />
              <div className="policy-band" style={{ left: at(p.high), width: `calc(${at(p.critical)} - ${at(p.high)})`, background: 'var(--c-high)' }} />
              <div className="policy-band" style={{ left: at(p.critical), right: 0, background: 'var(--c-critical)' }} />
            </div>
            <div className="policy-ticks">
              <span style={{ left: at(p.medium) }}><b>{p.medium}</b>Medium</span>
              <span style={{ left: at(p.high) }}><b>{p.high}</b>High</span>
              <span style={{ left: at(p.critical) }}><b>{p.critical}</b>Critical</span>
            </div>
          </div>
          <p className="muted" style={{ marginTop: 24, fontSize: 12.5 }}>
            The ML score is a percentile rank against its training distribution, so it runs high; these thresholds are tuned to that calibration. Alert threshold: <span className="mono">{p.alertThreshold}</span>.
          </p>
        </Card>
      </div>

      <p className="muted" style={{ fontSize: 12 }}>Last checked {fmtTimeSec(s.checkedAt)} · refreshes every 15 s</p>
    </>
  );
}
