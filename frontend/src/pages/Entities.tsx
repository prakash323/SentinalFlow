import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Boxes, Plus } from 'lucide-react';

import { entitiesApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { Modal, useToast } from '../components/feedback';
import { Badge, Button, Card, EmptyState, ErrorState, PageHeader, Pagination, ScoreMeter, SearchBox, TableSkeleton } from '../components/ui';
import { useDebounced } from '../hooks/useDebounced';
import { useUrlState } from '../hooks/useUrlState';
import { fmtDate, formatApiError, num, timeAgo } from '../utils/format';

const ENTITY_TYPES = ['USER', 'SERVICE_ACCOUNT', 'DEVICE', 'SERVICE'];

const schema = z.object({
  entityId: z.string().trim().min(1, 'Entity ID is required').max(128),
  entityType: z.string().trim().min(1, 'Type is required'),
  displayName: z.string().trim().max(200).optional(),
});
type Form = z.infer<typeof schema>;

function CreateEntityModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [error, setError] = useState('');
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<Form>({ resolver: zodResolver(schema), defaultValues: { entityType: 'USER' } });

  const create = useMutation({
    mutationFn: entitiesApi.create,
    onSuccess: (_, v) => {
      qc.invalidateQueries({ queryKey: ['entities'] });
      qc.invalidateQueries({ queryKey: ['palette-entities'] });
      toast.success('Entity created', `${v.entityId} is now monitored.`);
      reset({ entityType: 'USER', entityId: '', displayName: '' });
      setError('');
      onClose();
    },
    onError: (e) => setError(formatApiError(e, 'Unable to create entity')),
  });

  return (
    <Modal open={open} onClose={onClose} title="Add monitored entity" description="Events can only be ingested for entities that already exist.">
      <form className="form" noValidate onSubmit={handleSubmit((v) => create.mutate({ ...v, displayName: v.displayName || undefined }))}>
        <label className="field">
          <span>Entity ID</span>
          <input placeholder="USER-011" autoFocus {...register('entityId')} />
          {errors.entityId && <small className="field-error">{errors.entityId.message}</small>}
        </label>
        <label className="field">
          <span>Type</span>
          <select {...register('entityType')}>{ENTITY_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
        </label>
        <label className="field">
          <span>Display name <em className="muted" style={{ fontWeight: 400 }}>(optional)</em></span>
          <input placeholder="Jordan Lee" {...register('displayName')} />
        </label>
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="form-actions">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={create.isPending}>Create entity</Button>
        </div>
      </form>
    </Modal>
  );
}

export default function Entities() {
  const { isAdmin } = useAuth();
  const { state, set } = useUrlState({ q: '' });
  const [term, setTerm] = useState(state.q);
  const debounced = useDebounced(term, 300);
  const [creating, setCreating] = useState(false);
  const navigate = useNavigate();

  // Push the debounced term into the URL (resets to page 0).
  useEffect(() => {
    if (debounced !== state.q) set({ q: debounced });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  const q = useQuery({
    queryKey: ['entities', 'list', state.q, state.page],
    queryFn: () => entitiesApi.list({ q: state.q, page: state.page, size: 12 }),
    placeholderData: (prev) => prev,
  });

  return (
    <>
      <PageHeader
        eyebrow="Workspace"
        title="Entities"
        description="The users, accounts and devices being monitored, with their activity and risk at a glance."
        actions={isAdmin && <Button icon={Plus} onClick={() => setCreating(true)}>Add entity</Button>}
      />

      <Card flush>
        <div className="filters">
          <SearchBox value={term} onChange={setTerm} placeholder="Search by ID or name…" />
        </div>

        {q.isLoading ? (
          <TableSkeleton />
        ) : q.isError ? (
          <ErrorState message={formatApiError(q.error, 'Unable to load entities')} onRetry={() => q.refetch()} />
        ) : !q.data?.content.length ? (
          <EmptyState title="No entities" text={state.q ? 'No entity matches that search.' : 'Add an entity to start ingesting events for it.'} icon={Boxes} />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Entity</th><th>Type</th><th>Display name</th>
                    <th className="num">Events</th><th className="num">Alerts</th><th className="num">Open</th>
                    <th>Peak score</th><th>Last event</th>
                  </tr>
                </thead>
                <tbody>
                  {q.data.content.map((e) => (
                    <tr key={e.id} className="clickable" onClick={() => navigate(`/entities/${encodeURIComponent(e.entityId)}`)}>
                      <td><Link className="mono link" to={`/entities/${encodeURIComponent(e.entityId)}`} onClick={(ev) => ev.stopPropagation()}>{e.entityId}</Link></td>
                      <td><Badge tone="info" plain>{e.entityType}</Badge></td>
                      <td className="muted">{e.displayName || '—'}</td>
                      <td className="num mono">{num(e.eventCount)}</td>
                      <td className="num mono">{num(e.alertCount)}</td>
                      {/* the count is always printed; red is only emphasis */}
                      <td className="num mono" style={e.openAlertCount ? { color: 'var(--c-critical)', fontWeight: 600 } : undefined}>{num(e.openAlertCount)}</td>
                      <td><ScoreMeter value={e.maxScore} /></td>
                      <td className="muted" title={fmtDate(e.lastEventAt)}>{e.lastEventAt ? timeAgo(e.lastEventAt) : 'No activity'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={state.page} totalPages={q.data.totalPages} totalElements={q.data.totalElements} itemLabel="entities" onPageChange={(p) => set({ page: p })} />
          </>
        )}
      </Card>

      {isAdmin && <CreateEntityModal open={creating} onClose={() => setCreating(false)} />}
    </>
  );
}
