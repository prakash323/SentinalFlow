import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { ArrowLeft, Send, Wand2 } from 'lucide-react';

import { eventsApi } from '../api/endpoints';
import { useEntities } from '../components/EntitySelect';
import { useToast } from '../components/feedback';
import { Button, Card, CardHead, LinkButton, PageHeader } from '../components/ui';
import { formatApiError, toLocalInput } from '../utils/format';

const EVENT_TYPES = ['LOGIN', 'LOGOUT', 'FILE_ACCESS', 'API_ACCESS', 'TRANSACTION', 'PASSWORD_CHANGE'];

// Payload keys are the ones the ML service adapter understands (api.py:_canonical_event).
const TEMPLATES: Record<string, Record<string, unknown>> = {
  LOGIN: { ip: '10.0.0.5', location: 'Pune|18.52|73.86', loginSuccess: true, authMethod: 'password' },
  LOGOUT: { ip: '10.0.0.5', location: 'Pune|18.52|73.86', sessionDurationMinutes: 42 },
  FILE_ACCESS: { ip: '10.0.0.5', location: 'Pune|18.52|73.86', resource: '/finance/reports/q3.xlsx', action: 'download' },
  API_ACCESS: { ip: '10.0.0.5', endpoint: '/api/v1/orders', authMethod: 'token' },
  TRANSACTION: { ip: '10.0.0.5', location: 'Pune|18.52|73.86', resource: 'transaction', amount: 250 },
  PASSWORD_CHANGE: { ip: '10.0.0.5', location: 'Pune|18.52|73.86', authMethod: 'password' },
};

const pretty = (o: unknown) => JSON.stringify(o, null, 2);
const newEventId = () => `EV-${Date.now().toString(36).toUpperCase()}`;

const isJsonObject = (v: string) => {
  try {
    const parsed = JSON.parse(v);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed);
  } catch {
    return false;
  }
};

const schema = z.object({
  eventId: z.string().trim().min(1, 'Event ID is required'),
  entityId: z.string().trim().min(1, 'Choose an entity'),
  eventType: z.string().trim().min(1, 'Event type is required'),
  eventVersion: z.string().trim().min(1, 'Event version is required'),
  occurredAt: z.string().min(1, 'Occurred at is required'),
  source: z.string().trim().min(1, 'Source is required'),
  payload: z.string().min(1, 'Payload is required').refine(isJsonObject, 'Payload must be a valid JSON object'),
});
type Form = z.infer<typeof schema>;

export default function CreateEvent() {
  const navigate = useNavigate();
  const toast = useToast();
  const entities = useEntities();
  const [error, setError] = useState('');

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<Form>({
    resolver: zodResolver(schema),
    defaultValues: {
      eventId: newEventId(),
      entityId: '',
      eventType: 'LOGIN',
      eventVersion: 'v1',
      source: 'console',
      occurredAt: toLocalInput(),
      payload: pretty(TEMPLATES.LOGIN),
    },
  });

  const eventType = watch('eventType');

  const submit = async (v: Form) => {
    setError('');
    try {
      const created = await eventsApi.create({
        ...v,
        occurredAt: new Date(v.occurredAt).toISOString(),
        payload: JSON.parse(v.payload),
      });
      toast.success('Event accepted', `${created.eventId} is queued for detection.`);
      navigate(`/events/${encodeURIComponent(created.eventId)}`);
    } catch (e) {
      setError(formatApiError(e, 'Unable to create event'));
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Detection"
        title="Create event"
        description="Publish an event through the normal ingestion flow: REST → PostgreSQL → Kafka → ML scoring."
        actions={<LinkButton to="/events" icon={ArrowLeft}>Back to events</LinkButton>}
      />

      <Card>
        <CardHead title="Event envelope" description="The entity must already exist — the backend answers 404 for unknown entities." />
        <form onSubmit={handleSubmit(submit)} className="form" noValidate>
          <div className="form-grid">
            <label className="field">
              <span>Event ID</span>
              <div className="input-action">
                <input {...register('eventId')} />
                <button type="button" className="icon-btn bordered" title="Generate a new ID" aria-label="Generate a new ID" onClick={() => setValue('eventId', newEventId(), { shouldValidate: true })}>
                  <Wand2 size={15} />
                </button>
              </div>
              {errors.eventId && <small className="field-error">{errors.eventId.message}</small>}
            </label>

            <label className="field">
              <span>Entity</span>
              <select {...register('entityId')}>
                <option value="">Select an entity…</option>
                {(entities.data?.content ?? []).map((e) => (
                  <option key={e.entityId} value={e.entityId}>{e.entityId}{e.displayName ? ` — ${e.displayName}` : ''}</option>
                ))}
              </select>
              {errors.entityId && <small className="field-error">{errors.entityId.message}</small>}
            </label>

            <label className="field">
              <span>Event type</span>
              <select
                {...register('eventType', {
                  onChange: (e) => {
                    const t = TEMPLATES[e.target.value];
                    if (t) setValue('payload', pretty(t), { shouldValidate: true });
                  },
                })}
              >
                {EVENT_TYPES.map((t) => <option key={t}>{t}</option>)}
                {!EVENT_TYPES.includes(eventType) && <option>{eventType}</option>}
              </select>
              {errors.eventType && <small className="field-error">{errors.eventType.message}</small>}
            </label>

            <label className="field">
              <span>Occurred at</span>
              <input type="datetime-local" {...register('occurredAt')} />
              {errors.occurredAt && <small className="field-error">{errors.occurredAt.message}</small>}
            </label>

            <label className="field">
              <span>Source</span>
              <input {...register('source')} />
              {errors.source && <small className="field-error">{errors.source.message}</small>}
            </label>

            <label className="field">
              <span>Event version</span>
              <input {...register('eventVersion')} />
              {errors.eventVersion && <small className="field-error">{errors.eventVersion.message}</small>}
            </label>
          </div>

          <label className="field">
            <span>Payload (JSON)</span>
            <textarea className="json-input" rows={9} spellCheck={false} {...register('payload')} />
            <small className="hint">Keys the ML adapter reads: ip, location (“City|lat|lon”), loginSuccess, authMethod, resource, sessionDurationMinutes, commandSequence, deviceFingerprint.</small>
            {errors.payload && <small className="field-error">{errors.payload.message}</small>}
          </label>

          {error && <div className="form-error" role="alert">{error}</div>}

          <div className="form-actions">
            <Button variant="secondary" onClick={() => navigate('/events')}>Cancel</Button>
            <Button type="submit" icon={Send} loading={isSubmitting}>{isSubmitting ? 'Publishing…' : 'Publish event'}</Button>
          </div>
        </form>
      </Card>
    </>
  );
}
