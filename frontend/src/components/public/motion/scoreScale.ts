import type { Tone } from '../../../utils/tone';

/**
 * SentinelFlow anomaly scores live in 0..1 and every alert threshold sits in the last few percent
 * (utils/tone.ts: >= 0.99 medium, >= 0.995 high, >= 0.999 critical). On a linear axis all of that would be squashed into one
 * pixel, so the landing visuals use a two-part axis: scores below 0.9 (normal behavior) are linear and take the lower third;
 * from 0.9 up the axis is -log10(1 - score), so 0.99 and 0.999 are a full step apart. Illustrative scores only.
 */
const LINEAR_SHARE = 0.36; // share of the axis used by scores 0 .. 0.9
const X_TOP = 3.4; // -log10(1 - score) at the very top of the axis

/** 0..1 position along the axis for a score. */
export const scorePos = (s: number) => {
  if (s < 0.9) return (LINEAR_SHARE * Math.max(s, 0)) / 0.9;
  const x = -Math.log10(Math.max(1 - s, 1e-4));
  return Math.min(1, LINEAR_SHARE + ((1 - LINEAR_SHARE) * (x - 1)) / (X_TOP - 1));
};

export type Band = { key: string; label: string; tone: Tone; from: number; to: number; min?: string };

/** Alert policy bands (lower bound inclusive). `normal` is anything under the lowest band. */
export const BANDS: readonly Band[] = [
  { key: 'normal', label: 'Normal', tone: 'ok', from: 0, to: 0.9 },
  { key: 'low', label: 'Low', tone: 'low', from: 0.9, to: 0.99, min: '0.900' },
  { key: 'medium', label: 'Medium', tone: 'medium', from: 0.99, to: 0.995, min: '0.990' },
  { key: 'high', label: 'High', tone: 'high', from: 0.995, to: 0.999, min: '0.995' },
  { key: 'critical', label: 'Critical', tone: 'critical', from: 0.999, to: 1, min: '0.999' },
];

export const bandOf = (s: number) => [...BANDS].reverse().find((b) => s >= b.from) ?? BANDS[0];
