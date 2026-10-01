import { BellRing, Check } from 'lucide-react';

import { Badge } from '../../ui';
import { Illustrative } from '../visuals';
import { bandOf } from '../motion/scoreScale';
import { stagger, vars } from '../motion/util';
import { DEMO } from './demo';

const STEPS = [
  ['Anomaly detected', 'The score rises above the alert threshold.'],
  ['Decision engine', 'The alert policy compares the score with severity thresholds.'],
  ['Alert created', 'The alert keeps the score and the factors behind it.'],
  ['Severity assigned', 'Critical starts at a score of 0.999.'],
  ['Investigation available', 'Related alerts group into one incident to work from.'],
] as const;

/**
 * Left: the decision steps light up one after another. Right: the alert they produce, built from the same badge, meter and
 * tone system as the SOC, assembling in the same order. Plays once (CSS keyed to the enclosing <Reveal>).
 */
export default function AlertStory() {
  const band = bandOf(DEMO.score);
  return (
    <div className="al">
      <ol className="al-steps">
        {STEPS.map(([title, text], i) => (
          <li key={title} className="al-step sf-in" style={stagger(i, 100)}>
            <span className="al-check" style={vars({ '--i': i })}><Check size={13} aria-hidden="true" /></span>
            <span><strong>{title}</strong><em>{text}</em></span>
          </li>
        ))}
      </ol>

      <div className="al-card pub-elevated sf-slide" style={vars({ '--sf-base': '500ms', '--sf-x': '36px' })} role="group" aria-label="Illustrative example: a critical alert">
        <div className="al-head">
          <span className="al-icon"><BellRing size={16} aria-hidden="true" /></span>
          <strong>Alert</strong>
          <span className="al-badges sf-scale-in" style={vars({ '--sf-base': '1300ms' })}>
            <Badge tone={band.tone} dot>{band.label}</Badge>
            <Badge tone="critical">Open</Badge>
          </span>
        </div>
        <div className="al-meta">
          <code className="t-code">{DEMO.entity}</code>
          <code className="t-code">{DEMO.event}</code>
          <span className="t-meta">{DEMO.time}</span>
        </div>
        <div className="al-score">
          <span className="t-meta">Anomaly score</span>
          <span className="pub-meter" style={vars({ '--tone': `var(--c-${band.tone})`, '--w': '99.9%', '--sf-base': '1400ms' })} aria-hidden="true"><i /></span>
          <code className="t-code">{DEMO.score.toFixed(3)}</code>
        </div>
        <div className="t-line"><Badge tone="high" dot>Known anomaly</Badge></div>
        <ul className="al-factors">
          {DEMO.factors.map((f, i) => <li key={f} className="sf-in" style={stagger(i, 1600)}>{f}</li>)}
        </ul>
        <div className="al-foot">
          <span className="t-meta">Raised from the prediction</span>
          <span className="al-cta sf-in" style={vars({ '--sf-base': '2200ms' })} aria-hidden="true">Investigate</span>
        </div>
        <Illustrative />
      </div>
    </div>
  );
}
