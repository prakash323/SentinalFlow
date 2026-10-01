import { scoreTone, toneColor } from '../utils/tone';

/* ------------------------------------------------------------------ */
/* Score ring (gauge)                                                  */
/* ------------------------------------------------------------------ */

export function ScoreRing({
  value,
  size = 132,
  stroke = 11,
  label = 'anomaly',
}: {
  value?: number | null;
  size?: number;
  stroke?: number;
  label?: string;
}) {
  const v = typeof value === 'number' ? Math.max(0, Math.min(1, value)) : 0;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = toneColor(scoreTone(value));

  return (
    <div style={{ position: 'relative', width: size, height: size, flex: 'none' }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--panel-hover)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={c}
          strokeDashoffset={c * (1 - v)}
        />
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'grid', placeContent: 'center', textAlign: 'center' }}>
        <div style={{ fontSize: size * 0.24, fontWeight: 700, letterSpacing: '-0.03em', lineHeight: 1, color }}>
          {typeof value === 'number' ? value.toFixed(2) : '—'}
        </div>
        <div style={{ fontSize: 10.5, letterSpacing: '0.09em', textTransform: 'uppercase', color: 'var(--muted)', marginTop: 5 }}>
          {label}
        </div>
      </div>
    </div>
  );
}
