import { useState } from 'react';
import { BellRing, Boxes, Check, Cpu, Fingerprint, Gauge, MapPin, Radio, ShieldAlert, ShieldCheck, Sparkles } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { useLoopStage } from '../../../hooks/useLoopStage';
import { useReducedMotion } from '../../../hooks/useReducedMotion';
import { useOnScreen, usePageVisible } from '../../../hooks/useSceneActive';
import { Badge } from '../../ui';
import { Illustrative } from '../visuals';
import PlaybackToggle from '../motion/PlaybackToggle';
import { stagger, vars } from '../motion/util';

/*
 * Hero product visualization: one continuous story played on a loop.
 *
 *   0 normal stream  1 events flow  2 features appear  3 score rises  4 anomaly indicator
 *   5 alert raised   6 investigation opens             7 fade back to 0
 *
 * A single timeline hook drives `stage`; every visual is a pure function of it (CSS transitions do the
 * motion). It only advances while on screen, in a visible tab, not paused and not under reduced motion,
 * where it rests on stage 6 (everything visible). All numbers are ILLUSTRATIVE and labelled as such.
 */

const DURATIONS = [1500, 1500, 1800, 1900, 1400, 1900, 3200, 700] as const;
const REST_STAGE = 6;

const EVENTS = [
  { t: '10:42:01', who: 'USER-004', type: 'LOGIN' },
  { t: '10:42:02', who: 'SVC-012', type: 'FILE_ACCESS' },
  { t: '10:42:04', who: 'USER-009', type: 'LOGIN', target: true },
  { t: '10:42:05', who: 'USER-021', type: 'FILE_ACCESS' },
  { t: '10:42:06', who: 'USER-017', type: 'LOGOUT' },
] as const;

const PIPE: { icon: LucideIcon; label: string; litAt: number; hotAt?: number }[] = [
  { icon: Radio, label: 'Kafka', litAt: 0 },
  { icon: Boxes, label: 'Features', litAt: 2 },
  { icon: Cpu, label: 'Inference', litAt: 3 },
  { icon: Gauge, label: 'Score', litAt: 3, hotAt: 4 },
  { icon: BellRing, label: 'Alert', litAt: 5, hotAt: 5 },
  { icon: ShieldAlert, label: 'Investigate', litAt: 6 },
];

const CAPTIONS = [
  'Events arrive from your systems',
  'Streamed through Kafka to the pipeline',
  'Turned into behavioral features',
  'Scored by the ML ensemble',
  'One event deviates from its baseline',
  'An alert is raised with the factors behind it',
  'Ready to investigate: evidence, not just a number',
  'Back to watching the stream',
] as const;

/** stage -> which panel layer is on screen */
const LAYER = [0, 0, 1, 1, 1, 2, 3, 0] as const;

const FEATURES = [
  { icon: Fingerprint, label: 'Device', value: 'New', w: 1 },
  { icon: MapPin, label: 'Location', value: 'New city', w: 0.86 },
  { icon: Radio, label: 'Sign-in hour', value: '+3.1σ', w: 0.72 },
] as const;

export default function HeroStage() {
  const reduced = useReducedMotion();
  const visible = usePageVisible();
  const [ref, onScreen] = useOnScreen<HTMLElement>();
  const [paused, setPaused] = useState(false);
  const { stage } = useLoopStage(DURATIONS, !reduced && !paused && visible && onScreen);
  const s = reduced ? REST_STAGE : stage;
  const layer = LAYER[s];

  return (
    <figure
      ref={ref}
      className="hs"
      data-stage={s}
      aria-label="Illustrative example: how one login becomes an investigated incident"
    >
      <div className="hs-window pub-elevated" aria-hidden="true">
        <div className="hs-bar">
          <span className="hs-brand"><ShieldCheck size={14} />Live pipeline</span>
          <Illustrative />
        </div>

        {/* pipeline strip: chips light up as the event moves through */}
        <ol className="hs-pipe">
          {PIPE.map((p, i) => (
            <li
              key={p.label}
              className={`hs-chip sf-product-transition${s >= p.litAt && s !== 7 ? ' is-lit' : ''}${p.hotAt !== undefined && s >= p.hotAt && s !== 7 ? ' is-hot' : ''}`}
              style={stagger(i)}
            >
              <p.icon size={13} />
              <span>{p.label}</span>
            </li>
          ))}
        </ol>

        <div className="hs-body">
          {/* left: the event stream */}
          <section className="hs-col">
            <span className="pub-label">Event stream</span>
            <ul className={`hs-events${s === 1 ? ' is-scan' : ''}`}>
              {EVENTS.map((e, i) => {
                const hot = 'target' in e && e.target && s >= 4 && s !== 7;
                return (
                  <li key={e.t} className={`hs-event sf-product-transition${hot ? ' is-hot' : ''}${'target' in e && e.target && s === 3 ? ' is-scoring' : ''}`} style={stagger(i)}>
                    <code>{e.t}</code>
                    <strong>{e.who}</strong>
                    <span className="hs-type">{e.type}</span>
                    <i className="hs-dot" />
                  </li>
                );
              })}
            </ul>
          </section>

          {/* right: one panel, four layers that cross-fade with the story */}
          <section className="hs-col hs-panel sf-crossfade" style={vars({ '--tone': 'var(--c-critical)' })}>
            <div data-on={layer === 0}>
              <span className="pub-label">Behavioral baselines</span>
              <ul className="hs-checks">
                {['Known devices', 'Usual locations', 'Activity pattern'].map((t) => (
                  <li key={t}><Check size={14} />{t}<em>normal</em></li>
                ))}
              </ul>
            </div>

            <div data-on={layer === 1}>
              <div className="hs-panel-head"><span className="pub-label">Features</span><code className="t-code">USER-009</code></div>
              <ul className="hs-feats">
                {FEATURES.map((f, i) => (
                  <li key={f.label} className={`sf-product-transition${s >= 2 && s <= 4 ? ' is-on' : ''}`} style={stagger(i)}>
                    <f.icon size={14} />
                    <span>{f.label}</span>
                    <i className="hs-bar-track"><b style={vars({ '--w': f.w })} /></i>
                    <code>{f.value}</code>
                  </li>
                ))}
              </ul>
              <div className={`hs-score sf-product-transition${s >= 3 ? ' is-on' : ''}${s === 4 ? ' is-hot' : ''}`}>
                <span className="t-meta">Anomaly score</span>
                <i className="hs-meter"><b /></i>
                <code className="hs-score-num">0.999</code>
                {s === 4 && <span className="hs-ripple" />}
              </div>
            </div>

            <div data-on={layer === 2}>
              <div className="hs-alert">
                <div className="hs-alert-head">
                  <span className="hs-alert-icon"><BellRing size={15} /></span>
                  <strong>Alert</strong>
                  <Badge tone="critical" dot>Critical</Badge>
                </div>
                <div className="t-line"><code className="t-code">USER-009</code><code className="t-code">LOGIN</code><span className="t-meta">10:42:04</span></div>
                <div className="t-line"><Badge tone="high" dot>Known anomaly</Badge><code className="t-code">0.999</code></div>
                <div className="hs-factors"><span>Rare device</span><span>Unusual location</span><span>Unseen IP</span></div>
              </div>
            </div>

            <div data-on={layer === 3}>
              <div className="hs-panel-head"><span className="pub-label">Investigation</span><code className="t-code">USER-009:LOGIN</code></div>
              <ul className="hs-evidence">
                {[
                  [Fingerprint, 'Rare device', 'Not seen on this account before'],
                  [MapPin, 'Unusual location', 'Different from the usual pattern'],
                  [Radio, 'Unseen IP', 'First time this address appears'],
                ].map(([Icon, title, sub], i) => {
                  const I = Icon as LucideIcon;
                  return (
                    <li key={title as string} className={`sf-product-transition${s === 6 ? ' is-on' : ''}`} style={stagger(i)}>
                      <I size={14} /><span><strong>{title as string}</strong><em>{sub as string}</em></span>
                    </li>
                  );
                })}
              </ul>
              <span className="hs-ai"><Sparkles size={13} />Explain with AI</span>
            </div>
          </section>
        </div>

        {/* story caption + progress ticks */}
        <div className="hs-foot">
          <div className="hs-caption sf-crossfade">
            {CAPTIONS.map((c, i) => <span key={c} data-on={i === s}>{c}</span>)}
          </div>
          <div className="hs-ticks">
            {CAPTIONS.slice(0, 7).map((c, i) => <i key={c} className={i <= Math.min(s, 6) && s !== 7 ? 'is-done' : ''} />)}
          </div>
        </div>
      </div>

      <figcaption className="hs-meta">
        <span className="sr-only">
          Illustrative sequence: events stream through Kafka, features are computed, the ML ensemble scores each event, one login from a new device
          receives an elevated anomaly score, a critical alert is raised with its factors, and an investigation view opens with the evidence.
        </span>
        {!reduced && <PlaybackToggle playing={!paused} onToggle={() => setPaused((p) => !p)} label="hero animation" />}
      </figcaption>
    </figure>
  );
}
