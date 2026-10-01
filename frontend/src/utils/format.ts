import type { ApiError } from '../types/domain';

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const dateOnly = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const timeOnly = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
const timeSeconds = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

const valid = (v?: string | null): v is string => !!v && !Number.isNaN(new Date(v).getTime());

export const fmtDate = (v?: string | null) => (valid(v) ? dateTime.format(new Date(v)) : '—');
export const fmtDay = (v?: string | null) => (valid(v) ? dateOnly.format(new Date(v)) : '—');
export const fmtTime = (v?: string | null) => (valid(v) ? timeOnly.format(new Date(v)) : '—');
export const fmtTimeSec = (v?: string | null) => (valid(v) ? timeSeconds.format(new Date(v)) : '—');

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'narrow' });

/** "3m ago", "in 2h", "yesterday" - falls back to an absolute date past a week. */
export function timeAgo(v?: string | null, now = Date.now()): string {
  if (!valid(v)) return '—';
  const diffSec = Math.round((new Date(v).getTime() - now) / 1000);
  const abs = Math.abs(diffSec);
  if (abs < 45) return 'just now';
  if (abs < 3600) return rtf.format(Math.round(diffSec / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(diffSec / 3600), 'hour');
  if (abs < 7 * 86400) return rtf.format(Math.round(diffSec / 86400), 'day');
  return fmtDay(v);
}

export const pct = (v?: number | null, digits = 0) =>
  typeof v === 'number' ? `${(v * 100).toFixed(digits)}%` : '—';

export const score = (v?: number | null, digits = 3) => (typeof v === 'number' ? v.toFixed(digits) : '—');

export const num = (v?: number | null) => (typeof v === 'number' ? v.toLocaleString() : '—');

export const compact = (v: number) =>
  new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(v);

export const truncate = (v: string, n = 18) => (v.length > n ? `${v.slice(0, n)}…` : v);

/** SNAKE_CASE / kebab -> "Title case". */
export const humanize = (v?: string | null) =>
  v ? v.replace(/[_-]+/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase()) : '—';

export const initials = (v?: string | null) => (v ? v.slice(0, 2).toUpperCase() : '··');

/** Short avatar text for an entity id: its trailing number ("USER-007" -> "07"), else the first two letters. */
export const entityBadge = (id?: string | null) => {
  if (!id) return '··';
  const digits = /(\d{1,3})$/.exec(id);
  return digits ? digits[1].slice(-2).padStart(2, '0') : id.replace(/[^a-z0-9]/gi, '').slice(0, 2).toUpperCase();
};

/** Backend validation errors carry per-field `details`; surface them with the message. */
export function formatApiError(e: unknown, fallback = 'Something went wrong'): string {
  const err = e as Partial<ApiError> | undefined;
  const message = err?.message || fallback;
  const details = Array.isArray(err?.details) ? err!.details : [];
  return details.length ? `${message}: ${details.join('; ')}` : message;
}

/** `datetime-local` value ("YYYY-MM-DDTHH:mm") for a Date, in local time. */
export function toLocalInput(d = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
