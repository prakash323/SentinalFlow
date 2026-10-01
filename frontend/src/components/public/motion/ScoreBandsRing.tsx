import type { CSSProperties } from 'react';

import { BANDS, bandOf, scorePos } from './scoreScale';
import { vars } from './util';

const CX = 120;
const R = 96;
const START = 135; // degrees, SVG orientation (0 = 3 o'clock, clockwise): starts bottom-left ...
const SWEEP = 270; // ... and sweeps to bottom-right, leaving the gap at the bottom
const GAP = 0.008; // visual gap between band arcs, in ring units

const rad = (d: number) => (d * Math.PI) / 180;
const point = (u: number, r = R) => {
  const a = rad(START + SWEEP * u);
  return [CX + r * Math.cos(a), CX + r * Math.sin(a)] as const;
};

function arc(u0: number, u1: number) {
  const [x0, y0] = point(u0);
  const [x1, y1] = point(u1);
  return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${R} ${R} 0 ${(u1 - u0) * SWEEP > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

/**
 * Anomaly-score ring for the landing page: the five alert-policy bands are drawn one after another,
 * a marker lands on the score, then the score and its band are revealed. It plays once when the
 * enclosing <Reveal> comes into view (all motion is CSS, keyed to `.is-in`) and never spins.
 *
 * Above 0.9 the scale is -log10(1 - score) (see scoreScale.ts), which is why "Critical" takes a tenth of the ring
 * even though it covers only the last 0.1% of the score range.
 */
export default function ScoreBandsRing({ score, size = 240 }: { score: number; size?: number }) {
  const band = bandOf(score);
  const [mx, my] = point(scorePos(score));
  const label = `Anomaly score ${score.toFixed(3)}, ${band.label} band`;

  return (
    <div className="an-ring" style={{ width: size, height: size } as CSSProperties} role="img" aria-label={label}>
      <svg viewBox="0 0 240 240" width="100%" height="100%" aria-hidden="true" focusable="false">
        <path d={arc(0, 1)} fill="none" stroke="var(--panel-hover)" strokeWidth="16" strokeLinecap="round" />
        {BANDS.map((b, i) => {
          const u0 = scorePos(b.from) + (i === 0 ? 0 : GAP);
          const u1 = (b.to >= 1 ? 1 : scorePos(b.to)) - GAP;
          return (
            <path
              key={b.key}
              d={arc(u0, u1)}
              pathLength={1}
              className="sf-draw an-seg"
              data-active={b.key === band.key || undefined}
              style={vars({ '--i': i * 3, '--sf-base': '150ms', '--c': `var(--c-${b.tone})` })}
              fill="none"
              strokeWidth="16"
              strokeLinecap="butt"
            />
          );
        })}
        <g className="sf-scale-in" style={vars({ '--i': 15, '--sf-base': '150ms' })}>
          <circle cx={mx} cy={my} r="15" fill="var(--panel-3)" stroke="var(--c-critical)" strokeWidth="3" />
          <circle cx={mx} cy={my} r="5.5" fill="var(--c-critical)" />
        </g>
      </svg>
      <div className="an-ring-center">
        <span className="an-ring-label sf-in" style={vars({ '--i': 17, '--sf-base': '150ms' })}>Anomaly score</span>
        <strong className="an-ring-score sf-in" style={vars({ '--i': 18, '--sf-base': '150ms', '--c': `var(--c-${band.tone})` })}>{score.toFixed(3)}</strong>
        <span className="an-ring-band sf-in" style={vars({ '--i': 20, '--sf-base': '150ms', '--c': `var(--c-${band.tone})` })}>{band.label}</span>
      </div>
    </div>
  );
}
