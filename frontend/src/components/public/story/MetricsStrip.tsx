import { Illustrative } from '../visuals';
import CountUp from '../motion/CountUp';
import { stagger } from '../motion/util';

/** DEMO values only (the strip says so). SentinelFlow publishes no accuracy, volume or customer figures on this page. */
const METRICS = [
  { value: 1284906, label: 'Events processed', text: 'Security events scored by the ML service' },
  { value: 3412, label: 'Anomalies detected', text: 'Events scored above the alert threshold' },
  { value: 27, label: 'Active alerts', text: 'Open, acknowledged or being investigated' },
  { value: 1204, label: 'Entities monitored', text: 'Users, service accounts and devices' },
] as const;

/** Big numbers that count up once when the strip scrolls into view (tabular figures, one short rAF run each). */
export default function MetricsStrip() {
  return (
    <div className="mt" role="group" aria-label="Illustrative example: demo platform totals">
      <div className="mt-head"><Illustrative /><span className="t-meta">Demo values, shown only to illustrate the console.</span></div>
      <ul className="mt-grid">
        {METRICS.map((m, i) => (
          <li key={m.label} className="mt-tile sf-in" style={stagger(i)}>
            <CountUp to={m.value} className="mt-num" duration={1400 + i * 120} />
            <strong>{m.label}</strong>
            <span>{m.text}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
