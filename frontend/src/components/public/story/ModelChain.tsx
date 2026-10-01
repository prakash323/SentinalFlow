import { Boxes, Cpu, Gauge, Radio, Scale } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { stagger } from '../motion/util';
import { DEMO } from './demo';

const STEPS: { icon: LucideIcon; title: string; text: string }[] = [
  { icon: Radio, title: 'Signals', text: 'Security events from your systems.' },
  { icon: Boxes, title: 'Features', text: 'Behavioral features computed for each event.' },
  { icon: Cpu, title: 'Model', text: 'An ML ensemble compares behavior with baselines.' },
  { icon: Gauge, title: 'Score', text: 'An anomaly score between 0 and 1.' },
  { icon: Scale, title: 'Decision', text: 'The alert policy grades the score into a severity.' },
];

/**
 * Signals -> features -> model -> score -> decision, revealed left to right. The model name and version are the
 * strings the ML service really returns with every prediction. No accuracy or performance claims are made.
 */
export default function ModelChain() {
  return (
    <div className="md">
      <ol className="md-steps">
        {STEPS.map((s, i) => (
          <li key={s.title} className="md-step sf-in" style={stagger(i, 200)}>
            <span className="md-icon"><s.icon size={18} aria-hidden="true" /></span>
            <strong>{s.title}</strong>
            <span>{s.text}</span>
          </li>
        ))}
      </ol>
      <p className="md-model sf-in" style={stagger(0, 1100)}>
        <span className="pub-label">Model on every prediction</span>
        <code className="t-code">{DEMO.model.name}</code>
        <code className="t-code">{DEMO.model.version}</code>
      </p>
    </div>
  );
}
