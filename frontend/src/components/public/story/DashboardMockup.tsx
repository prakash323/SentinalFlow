import { useState } from 'react';
import { Activity, BellRing, Cpu, Fingerprint, Globe, LayoutDashboard, MapPin, ShieldAlert, Sparkles, Users } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { useLoopStage } from '../../../hooks/useLoopStage';
import { useReducedMotion } from '../../../hooks/useReducedMotion';
import { useOnScreen, usePageVisible } from '../../../hooks/useSceneActive';
import { Badge } from '../../ui';
import { Illustrative } from '../visuals';
import PlaybackToggle from '../motion/PlaybackToggle';
import { vars } from '../motion/util';
import { DEMO } from './demo';

/*
 * A SentinelFlow console mockup that moves through three states: overview -> anomaly detected -> investigation.
 * Built from the product's own vocabulary (events processed, anomalies, active alerts, entities, recent detections,
 * top anomalous entities, incident, model). Values are DEMO values and the mockup says so.
 *
 * `stage` picks the state; every element is a pure function of it and CSS transitions (transform / opacity only) do the
 * moving. The autoplay only runs while on screen, in a visible tab, not paused and not under reduced motion; the three
 * tabs always work, and choosing one pauses the autoplay.
 */

const TABS = ['Overview', 'Anomaly detected', 'Investigation'] as const;
const DURATIONS = [3400, 3800, 4600] as const;
const TITLES = ['Overview', 'Alerts', `Incident ${DEMO.incident}`] as const;
const DESCRIPTIONS = [
  'Overview: event volume is steady, a few earlier anomalies are marked, and 27 alerts are active.',
  'Anomaly detected: a new critical detection for USER-009 appears at the top of recent detections and the alert count rises to 28.',
  'Investigation: an incident panel opens with the evidence for USER-009, the model that scored it, and an option to explain it with AI.',
] as const;

const N = 48;
const W = 480;
const H = 150;
const px = (i: number) => (W * i) / (N - 1);
const vol = (i: number) => 0.52 + 0.17 * Math.sin(i * 0.35) + 0.07 * Math.sin(i * 1.3);
const py = (v: number) => H - 14 - v * (H - 34);
const LINE = Array.from({ length: N }, (_, i) => `${i ? 'L' : 'M'} ${px(i).toFixed(1)} ${py(vol(i)).toFixed(1)}`).join(' ');
const AREA = `${LINE} L ${W} ${H} L 0 ${H} Z`;
const MARKS = [8, 21, 30];
const HOT = 41;

const NAV: LucideIcon[] = [LayoutDashboard, Activity, BellRing, ShieldAlert, Users];
const NAV_ACTIVE = [0, 2, 3] as const;

const KPIS = [
  { label: 'Events processed', a: '1,284,906', b: '1,284,906' },
  { label: 'Anomalies detected', a: '3,412', b: '3,413' },
  { label: 'Active alerts', a: '27', b: '28' },
  { label: 'Entities monitored', a: '1,204', b: '1,204' },
] as const;

const ROWS = [
  { key: 'new', who: DEMO.entity, type: DEMO.event, tone: 'critical', label: 'Critical', score: '0.999', slots: [-1, 0, 0] },
  { key: 'a', who: 'SVC-012', type: 'FILE_ACCESS', tone: 'medium', label: 'Medium', score: '0.991', slots: [0, 1, 1] },
  { key: 'b', who: 'USER-031', type: 'LOGIN', tone: 'high', label: 'High', score: '0.996', slots: [1, 2, 2] },
  { key: 'c', who: 'USER-004', type: 'LOGIN', tone: 'low', label: 'Low', score: '0.912', slots: [2, 3, 3] },
  { key: 'd', who: 'SVC-019', type: 'FILE_ACCESS', tone: 'medium', label: 'Medium', score: '0.992', slots: [3, 4, 4] },
] as const;

const ENTITIES = [
  { who: DEMO.entity, w0: 0.22, w1: 0.94, hot: true },
  { who: 'SVC-012', w0: 0.58, w1: 0.58 },
  { who: 'USER-031', w0: 0.44, w1: 0.44 },
] as const;

const EVIDENCE: [LucideIcon, string][] = [
  [Fingerprint, 'Rare device'],
  [MapPin, 'Unusual location'],
  [Globe, 'Unseen IP'],
];

export default function DashboardMockup() {
  const reduced = useReducedMotion();
  const visible = usePageVisible();
  const [ref, onScreen] = useOnScreen<HTMLDivElement>();
  const [paused, setPaused] = useState(false);
  const { stage, goTo } = useLoopStage(DURATIONS, !reduced && !paused && visible && onScreen, reduced ? 1 : 0);

  return (
    <div ref={ref} className="db" data-stage={stage}>
      <div className="db-tabs">
        <div role="tablist" aria-label="Dashboard states" className="db-tablist">
          {TABS.map((t, i) => (
            <button
              key={t}
              type="button"
              role="tab"
              id={`db-tab-${i}`}
              aria-selected={stage === i}
              aria-controls="db-panel"
              className={`db-tab${stage === i ? ' is-on' : ''}`}
              onClick={() => {
                goTo(i);
                setPaused(true);
              }}
            >
              <b>{i + 1}</b>{t}
            </button>
          ))}
        </div>
        {!reduced && <PlaybackToggle playing={!paused} onToggle={() => setPaused((p) => !p)} label="dashboard animation" />}
      </div>

      <div id="db-panel" role="tabpanel" aria-labelledby={`db-tab-${stage}`} className="db-window pub-elevated">
        <p className="sr-only">{DESCRIPTIONS[stage]} This is an illustrative example with demo values.</p>
        <div className="db-shell" aria-hidden="true">
          <aside className="db-nav">
            <span className="db-logo" />
            {NAV.map((Icon, i) => (
              <span key={i} className={`db-nav-i sf-product-transition${i === NAV_ACTIVE[stage] ? ' is-on' : ''}`}><Icon size={15} /></span>
            ))}
          </aside>

          <div className="db-main">
            <header className="db-top">
              <div className="db-title sf-crossfade">
                {TITLES.map((t, i) => <strong key={t} data-on={stage === i}>{t}</strong>)}
              </div>
              <Illustrative />
            </header>

            <div className="db-kpis">
              {KPIS.map((k, i) => (
                <div key={k.label} className={`db-kpi sf-product-transition${i === 2 && stage >= 1 ? ' is-hot' : ''}`}>
                  <span>{k.label}</span>
                  <div className="db-num sf-crossfade">
                    <strong data-on={stage === 0}>{k.a}</strong>
                    <strong data-on={stage >= 1}>{k.b}</strong>
                  </div>
                </div>
              ))}
            </div>

            <div className="db-cols">
              <section className="db-card db-chart">
                <span className="pub-label">Event volume and anomalies</span>
                <svg viewBox={`0 0 ${W} ${H}`} className="db-svg" focusable="false">
                  <path d={AREA} fill="var(--accent)" className="db-area" />
                  <path d={LINE} fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
                  {MARKS.map((i) => <circle key={i} cx={px(i)} cy={py(vol(i))} r="4" fill="var(--c-medium)" />)}
                  <line x1={px(HOT)} x2={px(HOT)} y1="0" y2={H} stroke="var(--c-critical)" strokeWidth="1.5" strokeDasharray="4 4" className={`db-hotline sf-product-transition${stage >= 1 ? ' is-on' : ''}`} vectorEffect="non-scaling-stroke" />
                  <circle cx={px(HOT)} cy={py(vol(HOT))} r="6" fill="var(--c-critical)" className={`db-hotdot sf-product-transition${stage >= 1 ? ' is-on' : ''}`} />
                </svg>
              </section>

              <div className="db-right">
                <section className="db-card db-list">
                  <span className="pub-label">Recent detections</span>
                  <div className="db-rows">
                    {ROWS.map((r) => (
                      <div key={r.key} className={`db-row sf-product-transition${r.key === 'new' && stage >= 1 ? ' is-new' : ''}${r.slots[stage] < 0 || r.slots[stage] > 3 ? ' is-off' : ''}`} style={vars({ '--slot': r.slots[stage] })}>
                        <strong>{r.who}</strong><span>{r.type}</span><Badge tone={r.tone}>{r.label}</Badge><code>{r.score}</code>
                      </div>
                    ))}
                  </div>
                </section>
                <section className="db-card db-ents">
                  <span className="pub-label">Top anomalous entities</span>
                  {ENTITIES.map((e) => (
                    <div key={e.who} className="db-ent">
                      <span>{e.who}</span>
                      <i className="db-ent-track"><b className={`sf-product-transition${'hot' in e && e.hot && stage >= 1 ? ' is-hot' : ''}`} style={vars({ '--w': stage >= 1 ? e.w1 : e.w0 })} /></i>
                    </div>
                  ))}
                </section>
              </div>
            </div>
          </div>

          <div className={`db-scrim sf-product-transition${stage === 2 ? ' is-on' : ''}`} />
          <aside className={`db-drawer sf-product-transition${stage === 2 ? ' is-on' : ''}`}>
            <div className="db-drawer-head"><ShieldAlert size={15} /><strong>Incident</strong><code className="t-code">{DEMO.incident}</code><Badge tone="critical">Open</Badge></div>
            <span className="pub-label">Evidence</span>
            <ul className="db-evid">
              {EVIDENCE.map(([Icon, text], i) => (
                <li key={text} className="sf-product-transition" style={vars({ '--i': i })}><Icon size={14} />{text}</li>
              ))}
            </ul>
            <span className="db-model"><Cpu size={13} />{DEMO.model.name}</span>
            <span className="hs-ai"><Sparkles size={13} />Explain with AI<em>advisory only</em></span>
          </aside>
        </div>
      </div>
    </div>
  );
}
