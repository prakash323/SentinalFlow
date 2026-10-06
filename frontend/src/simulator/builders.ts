/*
 * The six console scenarios, moved out of pages/Simulator.tsx unchanged: same event types,
 * payloads, order, relative offsets, eventId scheme and source. scripts/simulator-check.mts
 * compares every builder against a verbatim copy of the original page code.
 */
import type { CreateEventRequest } from '../types/domain';
import type { ScenarioContext } from './types.ts';

export const HOME = 'Pune|18.52|73.86';
export const HOME_IP = '10.24.7.18';
export const HOME_DEVICE = 'Ubuntu 22.04|b0:17:7e:e2:b5:c2|TLS1.2';

export const ev = (
  c: ScenarioContext,
  i: number,
  offsetSec: number,
  eventType: string,
  payload: Record<string, unknown>,
): CreateEventRequest => ({
  eventId: `${c.prefix}-${String(i + 1).padStart(2, '0')}`,
  entityId: c.entityId,
  eventType,
  eventVersion: 'v1',
  occurredAt: new Date(c.now + offsetSec * 1000).toISOString(),
  source: 'simulator',
  payload,
});

export const buildRoutine = (c: ScenarioContext): CreateEventRequest[] => [
  ev(c, 0, -240, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'password', deviceFingerprint: HOME_DEVICE }),
  ev(c, 1, -120, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/docs/handbook.pdf', action: 'read', deviceFingerprint: HOME_DEVICE }),
  ev(c, 2, 0, 'LOGOUT', { ip: HOME_IP, location: HOME, sessionDurationMinutes: 38, deviceFingerprint: HOME_DEVICE }),
];

export const buildBrute = (c: ScenarioContext): CreateEventRequest[] => [
  ...Array.from({ length: 8 }, (_, i) =>
    ev(c, i, -80 + i * 8, 'LOGIN', { ip: '185.220.101.44', location: 'Moscow|55.75|37.61', loginSuccess: false, authMethod: 'password', deviceFingerprint: 'Unknown|00:00:00:00:00:00|TLS1.0' }),
  ),
  ev(c, 8, 0, 'LOGIN', { ip: '185.220.101.44', location: 'Moscow|55.75|37.61', loginSuccess: true, authMethod: 'password', deviceFingerprint: 'Unknown|00:00:00:00:00:00|TLS1.0' }),
];

export const buildTravel = (c: ScenarioContext): CreateEventRequest[] => [
  ev(c, 0, -300, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'password', deviceFingerprint: HOME_DEVICE }),
  ev(c, 1, 0, 'LOGIN', { ip: '102.89.34.7', location: 'Lagos|6.52|3.37', loginSuccess: true, authMethod: 'password', deviceFingerprint: 'Windows 11|3c:22:fb:10:9a:77|TLS1.3' }),
];

export const buildPrivesc = (c: ScenarioContext): CreateEventRequest[] => [
  ev(c, 0, -150, 'LOGIN', { ip: HOME_IP, location: HOME, loginSuccess: true, authMethod: 'token', deviceFingerprint: HOME_DEVICE }),
  ev(c, 1, -60, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/etc/shadow', commandSequence: 'sudo exec download', sessionDurationMinutes: 210, deviceFingerprint: HOME_DEVICE }),
  ev(c, 2, 0, 'FILE_ACCESS', { ip: HOME_IP, location: HOME, resource: '/var/backups/db.sql', commandSequence: 'sudo exec download delete', sessionDurationMinutes: 240, deviceFingerprint: HOME_DEVICE }),
];

export const buildExfil = (c: ScenarioContext): CreateEventRequest[] =>
  Array.from({ length: 6 }, (_, i) =>
    ev(c, i, -50 + i * 10, 'FILE_ACCESS', {
      ip: HOME_IP,
      location: HOME,
      resource: `/finance/payroll/2026-0${i + 1}.xlsx`,
      action: 'download',
      commandSequence: 'download download',
      sessionDurationMinutes: 300,
      deviceFingerprint: HOME_DEVICE,
    }),
  );

export const buildDevice = (c: ScenarioContext): CreateEventRequest[] => [
  ev(c, 0, 0, 'LOGIN', { ip: '203.0.113.77', location: 'Singapore|1.35|103.82', loginSuccess: true, authMethod: 'certificate', deviceFingerprint: 'Kali 2026.2|de:ad:be:ef:00:01|TLS1.3' }),
];
