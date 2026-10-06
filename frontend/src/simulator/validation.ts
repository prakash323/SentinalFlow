/*
 * Pre-send validation of generated events against the backend's actual contract
 * (CreateEventRequest @NotBlank/@NotNull, VARCHAR(128) columns, the 512 KiB publish limit, the ML
 * service's strict LOGIN result, and the NEW_PROCESS_EXTERNAL_CONNECTION correlation format).
 * Errors block sending; warnings are informational.
 */
import type { CreateEventRequest } from '../types/domain';
import { FUTURE_SKEW_MS, MAX_EVENT_BYTES, MAX_ID_LENGTH, PROCESS_CREATE_TIME } from './types.ts';
import type { Issue } from './types.ts';

const REQUIRED = ['eventId', 'entityId', 'eventType', 'eventVersion', 'occurredAt', 'source'] as const;

/** Path of the first `undefined` (JSON.stringify would silently drop it) or non-finite number. */
function badValue(v: unknown, path: string): string | null {
  if (v === undefined) return path;
  if (typeof v === 'number' && !Number.isFinite(v)) return path;
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) {
      const p = badValue(v[i], `${path}[${i}]`);
      if (p) return p;
    }
  } else if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      const p = badValue(x, `${path}.${k}`);
      if (p) return p;
    }
  }
  return null;
}

export function validateEvents(events: CreateEventRequest[], now = Date.now()): Issue[] {
  const issues: Issue[] = [];
  const err = (message: string, eventId?: string) => issues.push({ level: 'error', message, eventId });
  const seen = new Set<string>();

  if (!events.length) err('The scenario generated no events.');

  events.forEach((e, i) => {
    const id = typeof e.eventId === 'string' && e.eventId ? e.eventId : `#${i + 1}`;

    for (const f of REQUIRED) {
      const v = e[f];
      if (typeof v !== 'string' || !v.trim()) err(`${id}: ${f} is required`, id);
      else if (v.length > MAX_ID_LENGTH) err(`${id}: ${f} is longer than ${MAX_ID_LENGTH} characters`, id);
    }
    if (!e.payload || typeof e.payload !== 'object' || Array.isArray(e.payload)) err(`${id}: payload must be an object`, id);

    if (seen.has(e.eventId)) err(`${id}: duplicate eventId in this run`, id);
    seen.add(e.eventId);

    if (e.source !== 'simulator') err(`${id}: source must be "simulator" (got "${e.source}")`, id);
    if (e.eventVersion !== 'v1') err(`${id}: eventVersion must be "v1"`, id);

    const t = Date.parse(e.occurredAt);
    if (Number.isNaN(t)) err(`${id}: occurredAt "${e.occurredAt}" is not a valid ISO-8601 timestamp`, id);
    else if (t > now + FUTURE_SKEW_MS) err(`${id}: occurredAt is in the future`, id);

    const bad = badValue(e, 'event');
    if (bad) err(`${id}: ${bad} is undefined or not a finite number`, id);

    const p = (e.payload ?? {}) as Record<string, unknown>;
    // The ML service answers 422 MISSING_AUTH_RESULT for a LOGIN without an explicit boolean result,
    // and AUTH_BURST only counts loginSuccess === false.
    if (e.eventType === 'LOGIN' && typeof p.loginSuccess !== 'boolean') err(`${id}: LOGIN needs a boolean loginSuccess`, id);

    if ('processCreateTime' in p && (typeof p.processCreateTime !== 'string' || !PROCESS_CREATE_TIME.test(p.processCreateTime))) {
      err(`${id}: processCreateTime must be formatted yyyy-MM-ddTHH:mm:ssZ (got "${String(p.processCreateTime)}")`, id);
    }

    const bytes = new TextEncoder().encode(JSON.stringify(e)).length;
    if (bytes > MAX_EVENT_BYTES) err(`${id}: event is ${bytes} bytes; the backend limit is ${MAX_EVENT_BYTES}`, id);
  });

  return issues;
}
