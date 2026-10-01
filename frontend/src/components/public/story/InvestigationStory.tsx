import { ArrowRight, BellRing, Clock, Cpu, Fingerprint, Globe, MapPin, ShieldAlert, Sparkles, Activity } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

import { Badge } from '../../ui';
import { Illustrative } from '../visuals';
import { stagger, vars } from '../motion/util';
import { DEMO } from './demo';

const EVIDENCE: { icon: LucideIcon; label: string; value: string; w: number }[] = [
  { icon: Fingerprint, label: 'Device', value: 'New device', w: 1 },
  { icon: MapPin, label: 'Location', value: 'New city', w: 0.86 },
  { icon: Globe, label: 'IP address', value: 'Unseen IP', w: 0.8 },
  { icon: Clock, label: 'Sign-in hour', value: '+3.1σ', w: 0.7 },
];

const TIMELINE = [
  { t: '09:12', text: 'LOGIN from a known device', hot: false },
  { t: '09:58', text: 'FILE_ACCESS /reports/q3', hot: false },
  { t: '10:31', text: 'LOGOUT', hot: false },
  { t: DEMO.time, text: 'LOGIN from a new device, new city', hot: true },
] as const;

const RELATED = [
  { t: '10:39:51', text: 'LOGIN failed', tone: 'medium' },
  { t: '10:44:20', text: 'FILE_ACCESS from the unseen IP', tone: 'high' },
] as const;

/** One workspace panel: a skeleton first, then the real content fades in (both are stacked, so nothing moves). */
function Panel({ title, i, children }: { title: string; i: number; children: ReactNode }) {
  return (
    <section className="iv-panel">
      <span className="pub-label">{title}</span>
      <div className="iv-stack">
        <div className="iv-skel sf-fade-out" aria-hidden="true">
          <i style={{ width: '82%' }} /><i style={{ width: '64%' }} /><i style={{ width: '74%' }} /><i style={{ width: '48%' }} />
        </div>
        <div className="iv-content sf-in" style={stagger(i, 1350)}>{children}</div>
      </div>
    </section>
  );
}

/**
 * The alert-to-investigation moment. It plays once after it scrolls into view, as a pure CSS timeline:
 *   0 ms alert strip -> ~1000 ms "Investigate" is pressed -> ~1300 ms the workspace panels load (skeleton -> content).
 * The strip becomes the incident header; the panels are the evidence, the timeline and the related events, with the
 * model name and version the ML service returns for every prediction. The height never changes.
 */
export default function InvestigationStory() {
  return (
    <div className="iv pub-elevated" role="group" aria-label="Illustrative example: from an alert to an investigation workspace">
      <div className="iv-head">
        <div className="iv-strip sf-in" style={vars({ '--sf-base': '150ms' })}>
          <span className="iv-strip-l">
            <span className="iv-icon"><BellRing size={15} aria-hidden="true" /></span>
            <strong>Alert</strong>
            <Badge tone="critical" dot>Critical</Badge>
            <code className="t-code">{DEMO.entity}</code>
            <code className="t-code">{DEMO.score.toFixed(3)}</code>
          </span>
          <span className="iv-open" aria-hidden="true">Investigate <ArrowRight size={14} /></span>
        </div>
        <div className="iv-incident sf-in" style={vars({ '--sf-base': '1250ms' })}>
          <span className="iv-incident-l">
            <span className="iv-icon iv-icon-inc"><ShieldAlert size={15} aria-hidden="true" /></span>
            <strong>Incident</strong>
            <code className="t-code">{DEMO.incident}</code>
            <Badge tone="critical">Open</Badge>
          </span>
          <span className="iv-model"><Cpu size={13} aria-hidden="true" />{DEMO.model.name} · {DEMO.model.version}</span>
        </div>
      </div>

      <div className="iv-grid">
        <Panel title="Evidence" i={0}>
          <ul className="iv-evidence">
            {EVIDENCE.map((e) => (
              <li key={e.label}>
                <e.icon size={14} aria-hidden="true" />
                <span>{e.label}</span>
                <i className="iv-bar"><b style={vars({ '--w': e.w })} /></i>
                <code>{e.value}</code>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Timeline" i={1}>
          <ol className="iv-timeline">
            {TIMELINE.map((e) => (
              <li key={e.t} className={e.hot ? 'is-hot' : undefined}>
                <code>{e.t}</code>
                <span>{e.text}</span>
              </li>
            ))}
          </ol>
        </Panel>

        <Panel title="Related events" i={2}>
          <ul className="iv-related">
            {RELATED.map((r) => (
              <li key={r.t}><Activity size={13} aria-hidden="true" style={{ color: `var(--c-${r.tone})` }} /><code>{r.t}</code><span>{r.text}</span></li>
            ))}
          </ul>
          <span className="iv-ai"><Sparkles size={13} aria-hidden="true" />Explain with AI<em>advisory only</em></span>
        </Panel>
      </div>

      <div className="iv-foot"><Illustrative /></div>
    </div>
  );
}
