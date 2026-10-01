import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'motion/react';
import { ArrowLeft, CheckCircle2, ListChecks, XCircle } from 'lucide-react';

import { replayApi } from '../api/endpoints';
import { Card, CardHead, ErrorState, KV, LinkButton, Loading, PageHeader, StatusBadge } from '../components/ui';
import { fmtDate, formatApiError, num } from '../utils/format';

export default function ReplayDetail() {
  const { runKey = '' } = useParams();

  const q = useQuery({
    queryKey: ['replay-run', runKey],
    queryFn: () => replayApi.get(runKey),
    retry: false,
    refetchInterval: (query) => (['RUNNING', 'CREATED'].includes(query.state.data?.status ?? '') ? 2500 : false),
  });

  if (q.isLoading) return <Loading />;
  if (q.isError || !q.data) {
    return (
      <>
        <PageHeader eyebrow="Replay run" title="Replay run not found" actions={<LinkButton to="/replay-runs" icon={ArrowLeft}>All runs</LinkButton>} />
        <Card><ErrorState title="Couldn’t load this run" message={formatApiError(q.error, 'Replay run not found')} onRetry={() => q.refetch()} /></Card>
      </>
    );
  }

  const r = q.data;
  const done = r.processedEvents + r.failedEvents;
  const progress = r.totalEvents ? (done / r.totalEvents) * 100 : 0;

  const stats = [
    { icon: ListChecks, label: 'Total', value: r.totalEvents, tone: 'var(--accent)' },
    { icon: CheckCircle2, label: 'Processed', value: r.processedEvents, tone: 'var(--c-ok)' },
    { icon: XCircle, label: 'Failed', value: r.failedEvents, tone: 'var(--c-critical)' },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Replay run"
        title={<span className="mono">{r.runKey}</span>}
        description={r.sourceName || 'Replay execution'}
        actions={<LinkButton to="/replay-runs" icon={ArrowLeft}>All runs</LinkButton>}
      />

      <div className="grid-4">
        {stats.map((s, i) => (
          <Card key={s.label} delay={i * 0.04}>
            <div className="kpi-top">
              <span className="kpi-icon" style={{ color: s.tone, background: `color-mix(in srgb, ${s.tone} 14%, transparent)` }}><s.icon size={17} /></span>
              <span className="kpi-label">{s.label}</span>
            </div>
            <div className="kpi-value">{num(s.value)}</div>
          </Card>
        ))}
        <Card delay={0.12}>
          <div className="kpi-top"><span className="kpi-label">Status</span></div>
          <div style={{ marginTop: 8 }}><StatusBadge value={r.status} /></div>
        </Card>
      </div>

      <Card>
        <CardHead title="Progress" description={`${Math.round(progress)}% of events reached a terminal result.`} />
        <div className={`progress${r.failedEvents ? ' bad' : r.status === 'COMPLETED' ? ' ok' : ''}`}>
          <motion.div initial={{ width: 0 }} animate={{ width: `${progress}%` }} transition={{ duration: 0.8 }} />
        </div>
        <div className="kv-grid" style={{ marginTop: 12 }}>
          <KV label="Created">{fmtDate(r.createdAt)}</KV>
          <KV label="Started">{fmtDate(r.startedAt)}</KV>
          <KV label="Completed">{fmtDate(r.completedAt)}</KV>
        </div>
      </Card>
    </>
  );
}
