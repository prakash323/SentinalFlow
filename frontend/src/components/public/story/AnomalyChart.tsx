import { Badge } from '../../ui';
import { Illustrative } from '../visuals';
import { bandOf, scorePos } from '../motion/scoreScale';
import { vars } from '../motion/util';
import { DEMO } from './demo';

/*
 * Anomaly-score-per-event chart, drawn by hand in SVG. Above 0.9 the y axis is -log10(1 - score) (see scoreScale.ts):
 * on a linear axis every alert threshold (0.99, 0.995, 0.999) would sit on the top edge. Normal events
 * (illustrative) stay well below the alert threshold; one event does not.
 *
 * Sequence, all CSS keyed to the enclosing <Reveal> (no timers): frame -> baseline draws -> event points
 * appear -> the anomaly appears with a single ripple -> its score -> the alert.
 */

const W = 640;
const H = 320;
const L = 58;
const R = 18;
const T = 18;
const B = 40;
const PW = W - L - R;
const PH = H - T - B;
const N = 36;
const ANOMALY = 27;

const x = (i: number) => L + (PW * i) / (N - 1);
const y = (s: number) => T + PH * (1 - scorePos(s));

/** Deterministic normal behavior: no Math.random, so it never differs between renders. */
const normal = (i: number) => Math.min(0.85, Math.max(0.06, 0.32 + 0.26 * Math.sin(i * 0.6) + 0.09 * Math.sin(i * 1.7)));
const SCORES = Array.from({ length: N }, (_, i) => (i === ANOMALY ? DEMO.score : i === 10 ? 0.93 : i === 19 ? 0.985 : normal(i)));

const baseline = Array.from({ length: N }, (_, i) => `${i ? 'L' : 'M'} ${x(i).toFixed(1)} ${y(0.32 + 0.1 * Math.sin(i * 0.6)).toFixed(1)}`).join(' ');

const TICKS: { s: number; label: string }[] = [
  { s: 0.5, label: '0.5' },
  { s: 0.9, label: '0.9' },
  { s: 0.99, label: '0.99' },
  { s: 0.999, label: '0.999' },
];

export default function AnomalyChart() {
  const band = bandOf(DEMO.score);
  const ax = x(ANOMALY);
  const ay = y(DEMO.score);

  return (
    <div className="an-chart pub-elevated" role="group" aria-label="Illustrative example: one event stands out from normal behavior and raises an alert">
      <div className="an-head"><span className="pub-label">Anomaly score per event</span><Illustrative /></div>

      <div className="an-plot">
        <svg viewBox={`0 0 ${W} ${H}`} className="an-svg" role="img" aria-label="Anomaly scores of 36 events. Normal events stay far below the alert threshold; one event exceeds it.">
          {/* grid + axis (theme tokens only) */}
          <g className="sf-fade" style={vars({ '--sf-base': '0ms' })}>
            {TICKS.map((t) => (
              <g key={t.label}>
                <line x1={L} x2={W - R} y1={y(t.s)} y2={y(t.s)} stroke="var(--grid-line)" strokeWidth="1" />
                <text x={L - 10} y={y(t.s) + 4} textAnchor="end" className="an-tick">{t.label}</text>
              </g>
            ))}
            <line x1={L} x2={W - R} y1={T + PH} y2={T + PH} stroke="var(--border-strong)" strokeWidth="1" />
            <text x={L - 10} y={T + PH + 4} textAnchor="end" className="an-tick">0</text>
            <text x={L} y={H - 12} className="an-tick">Events over time</text>
            <text x={W - R} y={H - 12} textAnchor="end" className="an-tick">score, log scale above 0.9</text>
          </g>

          {/* the zone where this entity's events normally fall */}
          <rect x={L} y={y(0.85)} width={PW} height={T + PH - y(0.85)} rx="4" fill="var(--c-ok)" className="an-zone sf-fade" style={vars({ '--sf-base': '150ms' })} />
          <path d={baseline} pathLength={1} fill="none" stroke="var(--c-ok)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="sf-draw" style={vars({ '--sf-base': '250ms' })} />

          {/* alert threshold */}
          <line x1={L} x2={W - R} y1={y(0.99)} y2={y(0.99)} stroke="var(--c-medium)" strokeWidth="1.5" strokeDasharray="5 5" className="sf-fade" style={vars({ '--sf-base': '1000ms' })} />
          <text x={W - R} y={y(0.99) - 8} textAnchor="end" className="an-threshold sf-fade" style={vars({ '--sf-base': '1100ms' })}>Alert threshold 0.99</text>

          {/* events: normal ones first, then the outlier */}
          {SCORES.map((s, i) =>
            i === ANOMALY ? null : (
              <circle key={i} cx={x(i)} cy={y(s)} r="3.6" className="sf-scale-in an-pt" style={vars({ '--i': i * 0.28, '--sf-base': '1050ms' })} />
            ),
          )}
          <g>
            <circle cx={ax} cy={ay} r="9" className="an-ripple" />
            <circle cx={ax} cy={ay} r="6.5" className="sf-scale-in an-pt-hot" style={vars({ '--sf-base': '2100ms' })} />
          </g>
        </svg>

        {/* labels are HTML so they wrap and scale like text. The outer span only positions (viewBox percentages); the inner one animates. */}
        <span className="an-pos" style={{ left: `${(ax / W) * 100}%`, top: `${(ay / H) * 100}%` }}>
          <span className="an-tag sf-in" style={vars({ '--sf-base': '2400ms', '--c': `var(--c-${band.tone})` })}>
            <strong>{DEMO.score.toFixed(3)}</strong><em>{band.label}</em>
          </span>
        </span>
        <span className="an-pos an-pos-alert" style={{ left: `${(ax / W) * 100}%`, top: `${((ay + 40) / H) * 100}%` }}>
          <span className="an-alert sf-in" style={vars({ '--sf-base': '2800ms' })}>
            <Badge tone="critical" dot>Alert raised</Badge>
          </span>
        </span>
      </div>

      <ul className="an-legend">
        <li><i className="an-key an-key-ok" />Normal events</li>
        <li><i className="an-key an-key-hot" />Anomaly</li>
        <li><i className="an-key an-key-thr" />Alert threshold</li>
      </ul>
    </div>
  );
}
