import { Illustrative } from '../visuals';
import ScoreBandsRing from '../motion/ScoreBandsRing';
import { BANDS, bandOf } from '../motion/scoreScale';
import { stagger } from '../motion/util';
import { DEMO } from './demo';

const ORDER = [...BANDS].filter((b) => b.key !== 'normal').reverse(); // critical first

/**
 * The anomaly-score ring with the alert-policy bands beside it. The bands are the real thresholds used by the product
 * (utils/tone.ts scoreTone): critical >= 0.999, high >= 0.995, medium >= 0.99, low >= 0.9. The ring plays once.
 */
export default function RingPanel() {
  const current = bandOf(DEMO.score);
  return (
    <div className="an-ringpanel pub-elevated" role="group" aria-label="Illustrative example: an anomaly score in the critical band">
      <div className="an-head"><span className="pub-label">Anomaly score</span><Illustrative /></div>
      <div className="an-ringbody">
        <ScoreBandsRing score={DEMO.score} />
        <ul className="an-bands">
          {ORDER.map((b, i) => (
            <li key={b.key} className={`sf-in${b.key === current.key ? ' is-current' : ''}`} style={{ ...stagger(i, 700), ['--c' as string]: `var(--c-${b.tone})` }}>
              <i aria-hidden="true" />
              <strong>{b.label}</strong>
              <code>≥ {b.min}</code>
            </li>
          ))}
        </ul>
      </div>
      <p className="pub-fineprint">Bands follow the alert policy thresholds. Above 0.9 the ring is scaled logarithmically toward 1, so the last fractions of a point stay readable.</p>
    </div>
  );
}
