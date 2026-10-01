import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Plus, Repeat2 } from 'lucide-react';

import { replayApi } from '../api/endpoints';
import { Modal, useToast } from '../components/feedback';
import { Button, Card, EmptyState, ErrorState, PageHeader, Pagination, StatusBadge, TableSkeleton } from '../components/ui';
import { useUrlState } from '../hooks/useUrlState';
import { fmtDate, formatApiError, timeAgo } from '../utils/format';

const schema = z.object({
  runKey: z.string().trim().min(1, 'Run key is required'),
  sourceName: z.string().trim().optional(),
  eventIds: z.string().trim().min(1, 'Add at least one event ID'),
});
type Form = z.infer<typeof schema>;

function NewReplayModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const [error, setError] = useState('');
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<Form>({
    resolver: zodResolver(schema),
    defaultValues: { runKey: `REPLAY-${Date.now().toString(36).toUpperCase()}`, sourceName: 'console', eventIds: '' },
  });

  const start = useMutation({
    mutationFn: replayApi.create,
    onSuccess: (run) => {
      qc.invalidateQueries({ queryKey: ['replay-runs'] });
      toast.success('Replay finished', `${run.processedEvents} processed, ${run.failedEvents} failed.`);
      onClose();
      navigate(`/replay-runs/${encodeURIComponent(run.runKey)}`);
    },
    onError: (e) => setError(formatApiError(e, 'Unable to start the replay')),
  });

  return (
    <Modal open={open} onClose={onClose} title="New replay run" description="Reprocess stored events through the detection pipeline.">
      <form
        className="form"
        noValidate
        onSubmit={handleSubmit((v) =>
          start.mutate({
            runKey: v.runKey,
            sourceName: v.sourceName || undefined,
            eventIds: v.eventIds.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean),
          }),
        )}
      >
        <div className="form-grid">
          <label className="field"><span>Run key</span><input {...register('runKey')} />{errors.runKey && <small className="field-error">{errors.runKey.message}</small>}</label>
          <label className="field"><span>Source name</span><input {...register('sourceName')} /></label>
        </div>
        <label className="field">
          <span>Event IDs</span>
          <textarea className="json-input" rows={5} placeholder={'EV-KAFKA-012\nEV-VERIFY-002'} {...register('eventIds')} />
          <small className="hint">One per line, or comma-separated. Events must already exist.</small>
          {errors.eventIds && <small className="field-error">{errors.eventIds.message}</small>}
        </label>
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="form-actions">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={start.isPending}>Start replay</Button>
        </div>
      </form>
    </Modal>
  );
}

export default function ReplayRuns() {
  const { state, set } = useUrlState({});
  const [creating, setCreating] = useState(false);

  const q = useQuery({
    queryKey: ['replay-runs', state.page],
    queryFn: () => replayApi.list({ page: state.page, size: 15 }),
    placeholderData: (prev) => prev,
  });

  return (
    <>
      <PageHeader
        eyebrow="Workspace"
        title="Replay runs"
        description="Re-run stored events through the normal detection pipeline — useful after a model or policy change."
        actions={<Button icon={Plus} onClick={() => setCreating(true)}>New replay</Button>}
      />

      <Card flush>
        {q.isLoading ? (
          <TableSkeleton />
        ) : q.isError ? (
          <ErrorState message={formatApiError(q.error, 'Unable to load replay runs')} onRetry={() => q.refetch()} />
        ) : !q.data?.content.length ? (
          <EmptyState title="No replay runs yet" text="Start one from stored event IDs." icon={Repeat2} action={<Button size="sm" icon={Plus} onClick={() => setCreating(true)}>New replay</Button>} />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Run</th><th>Source</th><th>Status</th><th>Progress</th><th>Started</th></tr></thead>
                <tbody>
                  {q.data.content.map((r) => {
                    const done = r.processedEvents + r.failedEvents;
                    const pct = r.totalEvents ? (done / r.totalEvents) * 100 : 0;
                    return (
                      <tr key={r.id}>
                        <td><Link className="mono link" to={`/replay-runs/${encodeURIComponent(r.runKey)}`}>{r.runKey}</Link></td>
                        <td className="muted">{r.sourceName ?? '—'}</td>
                        <td><StatusBadge value={r.status} /></td>
                        <td style={{ minWidth: 190 }}>
                          <div className={`progress${r.failedEvents ? ' bad' : ''}`}><div style={{ width: `${pct}%` }} /></div>
                          <small className="muted">{r.processedEvents} ok · {r.failedEvents} failed · {r.totalEvents} total</small>
                        </td>
                        <td title={fmtDate(r.startedAt ?? r.createdAt)}>{timeAgo(r.startedAt ?? r.createdAt)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <Pagination page={state.page} totalPages={q.data.totalPages} totalElements={q.data.totalElements} itemLabel="runs" onPageChange={(p) => set({ page: p })} />
          </>
        )}
      </Card>

      <NewReplayModal open={creating} onClose={() => setCreating(false)} />
    </>
  );
}
