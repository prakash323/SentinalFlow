import { api } from './client';
import type {
  Alert,
  AlertStatusValue,
  AuditLog,
  CreateEntityRequest,
  CreateEventRequest,
  CreateReplayRunRequest,
  DashboardSummary,
  EntityDetail,
  EntitySummary,
  EventRecord,
  EventTrail,
  Incident,
  IncidentAiResponse,
  AlertAiResponse,
  AiDetail,
  IncidentAlert,
  IncidentStatusValue,
  Me,
  PageResponse,
  Prediction,
  ReplayRun,
  SystemStatus,
} from '../types/domain';

type Params = Record<string, string | number | boolean | undefined | null>;

// Drop empty filters so they never reach the query string as "?status=".
const clean = (p?: Params): Params | undefined =>
  p ? Object.fromEntries(Object.entries(p).filter(([, v]) => v !== undefined && v !== null && v !== '')) : undefined;

const enc = encodeURIComponent;

// Concise is the server default, so the parameter is only sent for the explicit opt-in.
const aiParams = (detail?: AiDetail) => (detail === 'detailed' ? { params: { detail } } : undefined);

export const authApi = {
  me: async () => (await api.get<Me>('/api/v1/auth/me')).data,
};

export const dashboardApi = {
  summary: async (hours = 8) => (await api.get<DashboardSummary>('/api/v1/dashboard/summary', { params: { hours } })).data,
};

export const systemApi = {
  status: async () => (await api.get<SystemStatus>('/api/v1/system/status')).data,
};

export const eventsApi = {
  list: async (p?: Params) => (await api.get<PageResponse<EventRecord>>('/api/v1/events', { params: clean(p) })).data,
  get: async (id: string) => (await api.get<EventRecord>(`/api/v1/events/${enc(id)}`)).data,
  trail: async (id: string) => (await api.get<EventTrail>(`/api/v1/events/${enc(id)}/trail`)).data,
  create: async (body: CreateEventRequest) => (await api.post<EventRecord>('/api/v1/events', body)).data,
};

export const predictionsApi = {
  list: async (p?: Params) => (await api.get<PageResponse<Prediction>>('/api/v1/predictions', { params: clean(p) })).data,
  get: async (id: string) => (await api.get<Prediction>(`/api/v1/predictions/${enc(id)}`)).data,
};

export const alertsApi = {
  list: async (p?: Params) => (await api.get<PageResponse<Alert>>('/api/v1/alerts', { params: clean(p) })).data,
  get: async (id: string) => (await api.get<Alert>(`/api/v1/alerts/${enc(id)}`)).data,
  updateStatus: async (id: string, status: AlertStatusValue) =>
    (await api.patch<Alert>(`/api/v1/alerts/${enc(id)}/status`, { status })).data,
  // Read-only: generates text from stored evidence and never changes the alert.
  ai: async (id: string, detail?: AiDetail) =>
    (await api.post<AlertAiResponse>(`/api/v1/alerts/${enc(id)}/ai/explanation`, undefined, aiParams(detail))).data,
};

export const incidentsApi = {
  list: async (p?: Params) => (await api.get<PageResponse<Incident>>('/api/v1/incidents', { params: clean(p) })).data,
  get: async (id: string) => (await api.get<Incident>(`/api/v1/incidents/${enc(id)}`)).data,
  alerts: async (id: string) => (await api.get<IncidentAlert[]>(`/api/v1/incidents/${enc(id)}/alerts`)).data,
  updateStatus: async (id: string, status: IncidentStatusValue) =>
    (await api.patch<Incident>(`/api/v1/incidents/${enc(id)}/status`, { status })).data,
  ai: async (id: string, kind: 'explanation' | 'evidence-summary' | 'investigation', detail?: AiDetail) =>
    (await api.post<IncidentAiResponse>(`/api/v1/incidents/${enc(id)}/ai/${kind}`, undefined, aiParams(detail))).data,
};

export const entitiesApi = {
  list: async (p?: Params) => (await api.get<PageResponse<EntitySummary>>('/api/v1/entities', { params: clean(p) })).data,
  get: async (entityId: string) => (await api.get<EntityDetail>(`/api/v1/entities/${enc(entityId)}`)).data,
  create: async (body: CreateEntityRequest) => (await api.post('/api/v1/entities', body)).data,
};

export const replayApi = {
  list: async (p?: Params) => (await api.get<PageResponse<ReplayRun>>('/api/v1/replay-runs', { params: clean(p) })).data,
  get: async (key: string) => (await api.get<ReplayRun>(`/api/v1/replay-runs/${enc(key)}`)).data,
  create: async (body: CreateReplayRunRequest) => (await api.post<ReplayRun>('/api/v1/replay-runs', body)).data,
};

export const auditApi = {
  list: async (p?: Params) => (await api.get<PageResponse<AuditLog>>('/api/v1/audit-logs', { params: clean(p) })).data,
};
