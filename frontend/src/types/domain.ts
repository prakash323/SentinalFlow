// Mirrors the Spring Boot DTOs. Keep in sync with com.anomaly.platform.dto.*

export type PageResponse<T> = {
  content: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
};

/* ---------- enums (mirror com.anomaly.platform.entity.*) ---------- */

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
export type SeverityValue = (typeof SEVERITIES)[number];

export const ALERT_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'CLOSED'] as const;
export type AlertStatusValue = (typeof ALERT_STATUSES)[number];

export const INCIDENT_STATUSES = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'] as const;
export type IncidentStatusValue = (typeof INCIDENT_STATUSES)[number];

export const DECISIONS = ['NORMAL', 'SUSPICIOUS', 'KNOWN_ANOMALY', 'UNKNOWN_ANOMALY', 'ERROR'] as const;
export type DecisionValue = (typeof DECISIONS)[number];

export type ProcessingStatus = 'PENDING' | 'PROCESSED' | 'FAILED';

/* ---------- resources ---------- */

export type EventRecord = {
  id: string;
  eventId: string;
  entityId: string;
  eventType: string;
  eventVersion: string;
  occurredAt: string;
  createdAt?: string;
  source?: string;
  payload: Record<string, unknown>;
  processingStatus: ProcessingStatus;
  processingAttempts: number;
  lastProcessingError?: string | null;
  processedAt?: string | null;
};

export type Prediction = {
  id: string;
  eventId: string;
  entityId: string;
  modelName: string;
  modelVersion: string;
  anomalyScore: number;
  confidence?: number | null;
  fusedScore?: number | null;
  decision: DecisionValue | string;
  features: {
    mlDecision?: string;
    riskScore?: number;
    attackType?: string | null;
    reason?: string | null;
    factors?: string[];
    [key: string]: unknown;
  };
  createdAt: string;
};

export type Alert = {
  id: string;
  entityId: string;
  eventId?: string | null;
  source?: string | null;
  decision: DecisionValue | string;
  severity: SeverityValue | string;
  status: AlertStatusValue | string;
  anomalyScore?: number | null;
  confidence?: number | null;
  fusedScore?: number | null;
  policyVersion: string;
  factors: string[];
  createdAt: string;
  updatedAt: string;
  incidentId?: string | null;
  // Independent deterministic detection (P1). ruleId/ruleName are present
  // only when this alert was raised by a platform rule, not an ML
  // prediction. detectionType is always one of "ML" | "RULE".
  ruleId?: string | null;
  ruleName?: string | null;
  detectionType?: 'ML' | 'RULE' | string;
};

export type Incident = {
  id: string;
  incidentKey: string;
  entityId: string;
  status: IncidentStatusValue | string;
  summary: string;
  createdAt: string;
  updatedAt: string;
  closedAt?: string | null;
  alertCount: number;
  maxSeverity?: SeverityValue | string | null;
  maxScore?: number | null;
  // Every distinct source among this incident's alerts - not a single
  // value, since an incident's correlation key is entityId:eventType,
  // not source (an incident CAN genuinely span more than one source).
  sources?: string[];
};

// Same shape as Alert but without the factors list and incidentId.
export type IncidentAlert = Omit<Alert, 'factors' | 'incidentId'>;

export type EntitySummary = {
  id: string;
  entityId: string;
  entityType: string;
  displayName?: string | null;
  createdAt: string;
  eventCount: number;
  alertCount: number;
  openAlertCount: number;
  maxScore?: number | null;
  lastEventAt?: string | null;
};

// GET /api/v1/entities/{entityId} - same rollup as EntitySummary (maxScore
// here is still the PEAK ALERT score, not a live risk score) plus open
// incident count and the most recent prediction ("current risk",
// deliberately separate from maxScore - see backend EntityDetailResponse).
export type EntityDetail = EntitySummary & {
  metadata?: Record<string, unknown> | null;
  openIncidentCount: number;
  latestPredictionAnomalyScore?: number | null;
  latestPredictionDecision?: DecisionValue | string | null;
  latestPredictionCreatedAt?: string | null;
};

export type EventTrail = {
  eventId: string;
  processingStatus: ProcessingStatus;
  processingAttempts: number;
  lastProcessingError?: string | null;
  processedAt?: string | null;
  prediction: Prediction | null;
  /** The newest alert, kept for compatibility - see `alerts`. */
  alert: Alert | null;
  /** Every alert raised for this event (rule and ML), newest first. */
  alerts?: Alert[];
};

/** All alerts on a trail; falls back to `alert` for an older backend. */
export const trailAlerts = (t?: EventTrail | null): Alert[] =>
  t?.alerts ?? (t?.alert ? [t.alert] : []);

export type ReplayRun = {
  id: string;
  runKey: string;
  sourceName?: string | null;
  status: string;
  totalEvents: number;
  processedEvents: number;
  failedEvents: number;
  startedAt?: string | null;
  completedAt?: string | null;
  createdAt: string;
};

export type AuditLog = {
  id: string;
  actor?: string | null;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  correlationId?: string | null;
  details: Record<string, unknown>;
  createdAt: string;
};

export type TrendPoint = {
  label: string;
  events: number;
  /** alerts raised in this UTC hour (by alert createdAt), all severities */
  alerts: number;
  bucketStart: string;
  /** the same alerts split by severity, zero-filled. Absent on older backends. */
  alertsBySeverity?: Record<string, number>;
};

export type EntityRisk = {
  entityId: string;
  alertCount: number;
  maxScore?: number | null;
  lastAlertAt?: string | null;
};

export type DashboardSummary = {
  totalEvents: number;
  predictionCount: number;
  alertCount: number;
  openIncidentCount: number;
  recentEvents: EventRecord[];
  recentAlerts: Alert[];
  trend: TrendPoint[];
  alertsBySeverity: Record<string, number>;
  alertsByStatus: Record<string, number>;
  eventsByType: Record<string, number>;
  eventsByProcessingStatus: Record<string, number>;
  eventsBySource: Record<string, number>;
  topEntities: EntityRisk[];
  averageAnomalyScore?: number | null;
  maxAnomalyScore?: number | null;
  trendHours: number;
};

export type SystemComponent = {
  name: string;
  status: 'UP' | 'DOWN' | string;
  latencyMs?: number | null;
  detail?: string | null;
};

export type SystemStatus = {
  overall: 'UP' | 'DEGRADED' | 'DOWN' | string;
  checkedAt: string;
  components: SystemComponent[];
  pipeline: Record<string, number>;
  policy: {
    version: string;
    alertThreshold: number;
    medium: number;
    high: number;
    critical: number;
  };
};

export type Me = {
  username: string;
  roles: string[];
  admin: boolean;
};

export type ApiError = {
  code: string;
  message: string;
  details: string[];
  requestId?: string;
  timestamp?: string;
  status?: number;
};

/* ---------- requests ---------- */

export type CreateEventRequest = {
  eventId: string;
  entityId: string;
  eventType: string;
  eventVersion: string;
  occurredAt: string;
  source: string;
  payload: Record<string, unknown>;
};

export type CreateEntityRequest = {
  entityId: string;
  entityType: string;
  displayName?: string;
  metadata?: Record<string, unknown>;
};

export type CreateReplayRunRequest = {
  runKey: string;
  sourceName?: string;
  eventIds: string[];
};

// Mirrors com.anomaly.platform.ai.IncidentAiResponse
export type IncidentAiResponse = {
  incidentId: string;
  kind: string;
  content: string;
  model: string;
  generatedAt: string;
};

// Mirrors com.anomaly.platform.ai.AlertAiResponse
export type AlertAiResponse = {
  alertId: string;
  kind: string;
  content: string;
  model: string;
  generatedAt: string;
};

// The optional `detail` query parameter of the AI endpoints. Concise is the server default.
export type AiDetail = 'concise' | 'detailed';
