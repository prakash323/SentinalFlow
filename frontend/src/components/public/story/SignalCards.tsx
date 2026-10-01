import { Activity, Fingerprint, KeyRound, MapPin, Clock, FileSearch } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { Illustrative } from '../visuals';
import { stagger, vars } from '../motion/util';

type Card = {
  icon: LucideIcon;
  label: string;
  feature: string; // the real extractor feature name
  value: string;
  /** baseline band (0..1 along the rail) */
  band: [number, number];
  /** where the event sits before / after it is compared with the baseline */
  from: number;
  to: number;
  flag?: boolean;
};

/**
 * Real behavioral features from the ML extractor (src/features.py FEATURE_NAMES). The values are an
 * illustrative case: three features leave their entity's baseline, three stay inside it.
 */
const CARDS: Card[] = [
  { icon: Clock, label: 'Sign-in time', feature: 'hour_zscore', value: '+3.1σ', band: [0.28, 0.64], from: 0.46, to: 0.93, flag: true },
  { icon: Fingerprint, label: 'Device', feature: 'fingerprint_mismatch', value: 'New device', band: [0.05, 0.3], from: 0.14, to: 0.9, flag: true },
  { icon: MapPin, label: 'Location', feature: 'is_new_city', value: 'New city', band: [0.05, 0.34], from: 0.2, to: 0.86, flag: true },
  { icon: KeyRound, label: 'Failed attempts (5 min)', feature: 'failed_auth_5min_entity', value: '0', band: [0.04, 0.4], from: 0.1, to: 0.1 },
  { icon: FileSearch, label: 'Resource novelty', feature: 'resource_novelty_ratio', value: '0.08', band: [0.1, 0.5], from: 0.3, to: 0.3 },
  { icon: Activity, label: 'Activity (1 h)', feature: 'events_last_1h', value: '6 events', band: [0.25, 0.7], from: 0.5, to: 0.5 },
];

/**
 * Feature cards appear one after another; then the cards whose value leaves the entity's baseline slide
 * their marker out of the band and take the alert tone. The comparison is the whole point, so it is the
 * one thing that moves after the entrance. Plays once (CSS, keyed to the enclosing <Reveal>).
 */
export default function SignalCards() {
  return (
    <div className="sg" role="group" aria-label="Illustrative example: behavioral features compared with the entity baseline">
      <div className="sg-head"><span className="pub-label">USER-009 · LOGIN</span><Illustrative /></div>
      <ul className="sg-grid">
        {CARDS.map((c, i) => (
          <li key={c.feature} className="sg-card sf-in" data-flag={c.flag || undefined} style={{ ...stagger(i), ...vars({ '--flag-delay': `${1500 + i * 160}ms` }) }}>
            <div className="sg-top">
              <span className="sg-icon"><c.icon size={16} aria-hidden="true" /></span>
              <span className="sg-name">{c.label}</span>
            </div>
            <div className="sg-rail" aria-hidden="true">
              <i className="sg-band" style={vars({ '--a': c.band[0], '--b': c.band[1] })} />
              <i className="sg-mover" style={vars({ '--from': c.from, '--to': c.to })} />
            </div>
            <div className="sg-foot">
              <code>{c.feature}</code>
              <strong>{c.value}</strong>
            </div>
          </li>
        ))}
      </ul>
      <p className="pub-fineprint">The shaded band is what is normal for this entity. A marker outside it is a deviation the model can score.</p>
    </div>
  );
}
