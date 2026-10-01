// Maps backend enum values to a visual tone (a CSS class suffix `tone-*`).

export type Tone = 'critical' | 'high' | 'medium' | 'low' | 'ok' | 'unknown' | 'info' | 'neutral';

const SEVERITY: Record<string, Tone> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

const ALERT_STATUS: Record<string, Tone> = {
  OPEN: 'critical',
  ACKNOWLEDGED: 'medium',
  INVESTIGATING: 'info',
  RESOLVED: 'ok',
  FALSE_POSITIVE: 'neutral',
  CLOSED: 'neutral',
};

const INCIDENT_STATUS: Record<string, Tone> = {
  OPEN: 'critical',
  INVESTIGATING: 'info',
  RESOLVED: 'ok',
  CLOSED: 'neutral',
};

const DECISION: Record<string, Tone> = {
  NORMAL: 'ok',
  SUSPICIOUS: 'medium',
  KNOWN_ANOMALY: 'high',
  UNKNOWN_ANOMALY: 'unknown',
  ERROR: 'neutral',
};

const PROCESSING: Record<string, Tone> = {
  PENDING: 'medium',
  PROCESSED: 'ok',
  FAILED: 'critical',
};

const REPLAY: Record<string, Tone> = {
  CREATED: 'neutral',
  RUNNING: 'info',
  COMPLETED: 'ok',
  FAILED: 'critical',
};

const GENERIC: Record<string, Tone> = {
  UP: 'ok',
  DOWN: 'critical',
  DEGRADED: 'medium',
  ...ALERT_STATUS,
  ...PROCESSING,
  ...REPLAY,
};

export const severityTone = (v?: string | null): Tone => (v && SEVERITY[v.toUpperCase()]) || 'neutral';
export const alertStatusTone = (v?: string | null): Tone => (v && ALERT_STATUS[v.toUpperCase()]) || 'neutral';
export const incidentStatusTone = (v?: string | null): Tone => (v && INCIDENT_STATUS[v.toUpperCase()]) || 'neutral';
export const decisionTone = (v?: string | null): Tone => (v && DECISION[v.toUpperCase()]) || 'neutral';
export const processingTone = (v?: string | null): Tone => (v && PROCESSING[v.toUpperCase()]) || 'neutral';
export const replayTone = (v?: string | null): Tone => (v && REPLAY[v.toUpperCase()]) || 'neutral';
export const genericTone = (v?: string | null): Tone => (v && GENERIC[v.toUpperCase()]) || 'neutral';

/** Tone for a 0..1 anomaly score, aligned with the backend severity bands. */
export function scoreTone(value?: number | null): Tone {
  const n = value ?? 0;
  if (n >= 0.999) return 'critical';
  if (n >= 0.995) return 'high';
  if (n >= 0.99) return 'medium';
  if (n >= 0.9) return 'low';
  return 'ok';
}

/** CSS custom-property colour for a tone, usable in inline styles and SVG. */
export const toneColor = (t: Tone) => `var(--c-${t})`;

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
