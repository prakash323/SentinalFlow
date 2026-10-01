import type { AlertStatusValue, IncidentStatusValue } from '../types/domain';

// Mirrors the transition rules enforced server-side in
// AlertService.allowed / IncidentService.allowed. The backend remains the
// source of truth (it answers 409 for an illegal move); these maps only stop
// the UI from offering moves that are certain to be rejected.
export const ALERT_TRANSITIONS: Record<AlertStatusValue, AlertStatusValue[]> = {
  OPEN: ['ACKNOWLEDGED', 'INVESTIGATING', 'FALSE_POSITIVE', 'CLOSED'],
  ACKNOWLEDGED: ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'CLOSED'],
  INVESTIGATING: ['RESOLVED', 'FALSE_POSITIVE', 'CLOSED'],
  RESOLVED: ['CLOSED'],
  FALSE_POSITIVE: [],
  CLOSED: [],
};

export const INCIDENT_TRANSITIONS: Record<IncidentStatusValue, IncidentStatusValue[]> = {
  OPEN: ['INVESTIGATING', 'RESOLVED', 'CLOSED'],
  INVESTIGATING: ['RESOLVED', 'CLOSED'],
  RESOLVED: ['CLOSED'],
  CLOSED: [],
};

/** The happy-path lifecycle shown as a stepper (FALSE_POSITIVE is a side exit). */
export const ALERT_LIFECYCLE: AlertStatusValue[] = ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'CLOSED'];
export const INCIDENT_LIFECYCLE: IncidentStatusValue[] = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'];

export const nextAlertStatuses = (s: string): AlertStatusValue[] => ALERT_TRANSITIONS[s as AlertStatusValue] ?? [];
export const nextIncidentStatuses = (s: string): IncidentStatusValue[] => INCIDENT_TRANSITIONS[s as IncidentStatusValue] ?? [];

export type ActionStyle = 'primary' | 'secondary' | 'danger' | 'success';

/** Button style + verb for moving to a given status. */
export const STATUS_ACTIONS: Record<string, { label: string; variant: ActionStyle }> = {
  ACKNOWLEDGED: { label: 'Acknowledge', variant: 'primary' },
  INVESTIGATING: { label: 'Start investigating', variant: 'primary' },
  RESOLVED: { label: 'Mark resolved', variant: 'success' },
  FALSE_POSITIVE: { label: 'False positive', variant: 'secondary' },
  CLOSED: { label: 'Close', variant: 'secondary' },
};
