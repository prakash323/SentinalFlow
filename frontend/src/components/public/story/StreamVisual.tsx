import { Boxes, Workflow } from 'lucide-react';

import { Illustrative } from '../visuals';
import { stagger, vars } from '../motion/util';

const EVENTS = [
  { t: '10:42:01', who: 'USER-004', type: 'LOGIN' },
  { t: '10:42:02', who: 'SVC-012', type: 'FILE_ACCESS' },
  { t: '10:42:04', who: 'USER-009', type: 'LOGIN' },
  { t: '10:42:05', who: 'USER-021', type: 'FILE_ACCESS' },
  { t: '10:42:06', who: 'USER-017', type: 'LOGOUT' },
] as const;

/** Plain-language names for real extractor features (src/features.py: hour_zscore, fingerprint_mismatch, ...). */
const FEATURES = ['Sign-in hour', 'Device match', 'Location change', 'Failed attempts', 'Resource novelty', 'Activity rate'] as const;

/**
 * "Every event becomes a signal." Events enter the pipeline one after another, the Kafka topic takes them
 * in, and feature chips appear on the far side. One-shot: everything is CSS keyed to the enclosing
 * <Reveal> (motion.css utilities), nothing loops and no script runs after the reveal.
 */
export default function StreamVisual() {
  return (
    <div className="st pub-elevated" role="group" aria-label="Illustrative example: security events enter the pipeline through Kafka and become behavioral features">
      <div className="st-head"><span className="pub-label">Event stream</span><Illustrative /></div>

      <div className="st-grid">
        <ul className="st-events" aria-hidden="true">
          {EVENTS.map((e, i) => (
            <li key={e.t} className="st-event sf-slide" style={vars({ '--i': i, '--sf-x': '-28px' })}>
              <code>{e.t}</code>
              <strong>{e.who}</strong>
              <span>{e.type}</span>
            </li>
          ))}
        </ul>

        <span className="st-link st-link-a sf-line" style={vars({ '--sf-base': '450ms' })} aria-hidden="true" />

        <div className="st-node st-kafka sf-scale-in" style={vars({ '--sf-base': '500ms' })}>
          <span className="st-node-icon"><Workflow size={18} aria-hidden="true" /></span>
          <strong>Kafka</strong>
          <code className="t-code">raw.events.v1</code>
          <span className="st-parts" aria-hidden="true">
            {[0, 1, 2, 3].map((k) => <i key={k} className="sf-fade" style={vars({ '--i': k, '--sf-base': '850ms' })} />)}
          </span>
        </div>

        <span className="st-link st-link-b sf-line" style={vars({ '--sf-base': '1000ms' })} aria-hidden="true" />

        <div className="st-node st-feats sf-scale-in" style={vars({ '--sf-base': '1100ms' })}>
          <span className="st-node-icon"><Boxes size={18} aria-hidden="true" /></span>
          <strong>Feature extraction</strong>
          <ul className="st-chips">
            {FEATURES.map((f, i) => <li key={f} className="sf-in" style={stagger(i, 1350)}>{f}</li>)}
          </ul>
        </div>
      </div>

      <p className="pub-fineprint">Each event is stored, streamed through Kafka and turned into behavioral features before it is scored.</p>
    </div>
  );
}
