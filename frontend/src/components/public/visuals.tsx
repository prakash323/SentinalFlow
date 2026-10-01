import type { CSSProperties, ReactNode } from 'react';
import {
  Activity,
  ArrowDown,
  ArrowRight,
  BellRing,
  Boxes,
  Check,
  ClipboardList,
  Cpu,
  Database,
  Fingerprint,
  Globe,
  Info,
  Layers,
  MapPin,
  Radar,
  Radio,
  Scale,
  Server,
  ShieldAlert,
  Sparkles,
  Workflow,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { Badge } from '../ui';
import type { Tone } from '../../utils/tone';

/*
 * Original SentinelFlow product visuals for the public Home page. They are built from the same
 * tokens, badges and semantic colours as the SOC so the two read as one product. Every number on
 * them (USER-009, 0.998 ...) is an ILLUSTRATIVE EXAMPLE, not live or measured data, and each
 * visual says so.
 */

const toneVars = (t: Tone) => ({ ['--tone' as string]: `var(--c-${t})` }) as CSSProperties;

export const Illustrative = () => (
  <span className="pub-illus"><Info size={13} aria-hidden="true" />Illustrative example</span>
);

function Meter({ value, tone = 'high' }: { value: number; tone?: Tone }) {
  return (
    <span className="pub-meter" style={{ ...toneVars(tone), ['--w' as string]: `${value * 100}%` } as CSSProperties} aria-hidden="true">
      <i />
    </span>
  );
}

const Node = ({ icon: Icon, tone }: { icon: LucideIcon; tone?: Tone }) => (
  <span className="pub-node" style={tone ? toneVars(tone) : undefined}><Icon size={16} aria-hidden="true" /></span>
);

/* ---------------------------------------------------------------- hero */

export function HeroPreview() {
  return (
    <figure className="pub-preview" aria-label="Illustrative example: how one login becomes an investigated incident">
      <div className="pub-preview-head">
        <span className="pub-entity"><i aria-hidden="true" />USER-009</span>
        <Illustrative />
      </div>

      <ol className="pub-trace">
        <li>
          <Node icon={Radio} />
          <div>
            <div className="t-line"><strong className="t-title">Security event</strong><code className="t-code">LOGIN</code></div>
            <p className="t-meta">Sign-in from a device the account has not used before</p>
          </div>
        </li>
        <li>
          <Node icon={Fingerprint} />
          <div>
            <strong className="t-title">Behavioral analysis</strong>
            <p className="t-meta">Compared with the entity and peer-group baseline</p>
          </div>
        </li>
        <li>
          <Node icon={Radar} tone="high" />
          <div>
            <div className="t-line"><strong className="t-title">Prediction</strong><Badge tone="high" dot>Known anomaly</Badge></div>
            <div className="t-score">
              <span className="t-meta">Anomaly score</span>
              <Meter value={0.998} />
              <code className="t-code">0.998</code>
            </div>
          </div>
        </li>
        <li>
          <Node icon={BellRing} tone="critical" />
          <div>
            <div className="t-line"><strong className="t-title">Alert</strong><Badge tone="critical" dot>Critical</Badge></div>
            <p className="t-meta">Graded by the alert policy, with the factors behind it</p>
          </div>
        </li>
        <li>
          <Node icon={ShieldAlert} />
          <div>
            <div className="t-line"><strong className="t-title">Incident created</strong><code className="t-code">USER-009:LOGIN</code></div>
            <p className="t-meta">Related alerts grouped into one investigation</p>
          </div>
        </li>
        <li>
          <Node icon={Sparkles} />
          <div>
            <strong className="t-title">AI investigation</strong>
            <p className="t-meta">Evidence-grounded explanation and suggested next steps</p>
          </div>
        </li>
      </ol>
    </figure>
  );
}

/* ---------------------------------------------------- product pipeline */

const STAGES: { icon: LucideIcon; title: string; text: string }[] = [
  { icon: Radio, title: 'Security events', text: 'Logins, API and file access, transactions and more.' },
  { icon: Fingerprint, title: 'Behavior', text: 'Baselines for each entity and its peer group.' },
  { icon: Radar, title: 'Prediction', text: 'An ML ensemble scores every event.' },
  { icon: Scale, title: 'Risk / policy', text: 'Score thresholds decide alert severity.' },
  { icon: BellRing, title: 'Alert', text: 'Severity, decision and the factors behind it.' },
  { icon: ShieldAlert, title: 'Incident', text: 'Related alerts grouped per entity and event type.' },
  { icon: Sparkles, title: 'Investigation', text: 'Evidence-grounded AI explanations.' },
];

export function PipelineVisual() {
  return (
    <ol className="pub-pipeline">
      {STAGES.map((s, i) => (
        <li key={s.title} className="pub-stage" style={{ ['--i' as string]: i } as CSSProperties}>
          <span className="pub-stage-icon"><s.icon size={22} aria-hidden="true" /></span>
          <h3>{s.title}</h3>
          <p>{s.text}</p>
        </li>
      ))}
    </ol>
  );
}

/* --------------------------------------------------------- detection */

const Check1 = ({ children }: { children: ReactNode }) => (
  <li><Check size={14} aria-hidden="true" />{children}</li>
);

export function BehaviorVisual() {
  return (
    <div className="pub-behavior pub-elevated" role="group" aria-label="Illustrative example: normal behavior versus a detected anomaly">
      <div className="pub-panel-top"><span className="pub-label">Behavioral baseline</span><Illustrative /></div>

      <section className="pub-b-block">
        <div className="pub-b-head"><span className="pub-label">Normal behavior</span><code className="t-code">USER-009</code></div>
        <ul className="pub-checks tone-ok">
          <Check1>Known device</Check1>
          <Check1>Normal location</Check1>
          <Check1>Expected activity</Check1>
        </ul>
      </section>

      <ArrowDown className="pub-b-arrow" size={18} aria-hidden="true" />

      <section className="pub-b-block">
        <span className="pub-label">New signals</span>
        <div className="pub-chips">
          {['New device', 'Unusual location', 'Unseen IP', 'Abnormal pattern'].map((c) => (
            <span key={c} className="pub-chip"><i aria-hidden="true" />{c}</span>
          ))}
        </div>
      </section>

      <ArrowDown className="pub-b-arrow" size={18} aria-hidden="true" />

      <section className="pub-b-block pub-b-result">
        <div>
          <span className="pub-label">Anomaly</span>
          <div className="t-line"><Badge tone="high" dot>Known anomaly</Badge></div>
        </div>
        <div className="pub-b-score">
          <code>0.998</code>
          <Meter value={0.998} />
        </div>
        <div>
          <span className="pub-label">Alert</span>
          <div className="t-line"><Badge tone="critical" dot>Critical</Badge></div>
        </div>
      </section>

      <p className="pub-fineprint">
        A visual example only. Alert severity is decided by the alert policy thresholds; not every anomaly becomes critical.
      </p>
    </div>
  );
}

/* --------------------------------------------- event -> incident workflow */

export function WorkflowVisual() {
  return (
    <div className="pub-workflow-wrap">
      <div className="pub-workflow-note"><Illustrative /></div>
      <ol className="pub-workflow">
        <li className="pub-step">
          <span className="pub-step-no">01</span>
          <span className="pub-label">Event</span>
          <strong className="pub-step-main">LOGIN</strong>
          <code className="t-code">USER-009</code>
          <p className="t-meta">A raw security event, stored and streamed for analysis.</p>
        </li>
        <li className="pub-step">
          <span className="pub-step-no">02</span>
          <span className="pub-label">Prediction</span>
          <div className="t-line"><Badge tone="high" dot>Known anomaly</Badge></div>
          <div className="t-score"><span className="t-meta">Anomaly score</span><code className="t-code">0.998</code></div>
          <p className="t-meta pub-from">Scored from the LOGIN event</p>
        </li>
        <li className="pub-step">
          <span className="pub-step-no">03</span>
          <span className="pub-label">Alert</span>
          <div className="t-line"><Badge tone="critical" dot>Critical</Badge></div>
          <ul className="pub-factors">
            <li>Rare device</li>
            <li>Unusual location</li>
            <li>Unseen IP</li>
          </ul>
          <p className="t-meta pub-from">Raised from the prediction</p>
        </li>
        <li className="pub-step pub-step-last">
          <span className="pub-step-no">04</span>
          <span className="pub-label">Incident</span>
          <code className="t-code pub-key">USER-009:LOGIN</code>
          <div className="t-line"><Badge tone="critical">Open</Badge></div>
          <p className="t-meta pub-from">Groups the alerts for this entity and event type</p>
        </li>
      </ol>
    </div>
  );
}

/* --------------------------------------------------- AI investigation */

export function AiVisual() {
  return (
    <div className="pub-ai-grid" role="group" aria-label="Illustrative example: observed evidence and AI investigation">
      <div className="pub-ai-panel">
        <div className="pub-panel-top"><span className="pub-label">Observed evidence</span><span className="pub-tag">Computed by the ML pipeline</span></div>
        <ul className="pub-evidence">
          <li><Fingerprint size={16} aria-hidden="true" /><span><strong>Rare device</strong><em>Not seen on this account before</em></span></li>
          <li><MapPin size={16} aria-hidden="true" /><span><strong>Unusual location</strong><em>Different from the usual pattern</em></span></li>
          <li><Globe size={16} aria-hidden="true" /><span><strong>Unseen IP</strong><em>First time this address appears</em></span></li>
          <li><Activity size={16} aria-hidden="true" /><span><strong>Behavioral anomaly</strong><em>Deviates from the baseline</em></span></li>
        </ul>
      </div>

      <div className="pub-ai-arrow" aria-hidden="true"><ArrowRight size={20} /></div>

      <div className="pub-ai-panel pub-ai-out">
        <div className="pub-panel-top"><span className="pub-label">AI investigation</span><span className="pub-tag pub-tag-accent">Advisory only</span></div>
        <div className="pub-ai-block">
          <h3>Potential explanation</h3>
          <p>A sign-in from a new device and an unseen IP in an unusual location. This is consistent with compromised credentials, but also with legitimate travel or a new laptop.</p>
        </div>
        <div className="pub-ai-block">
          <h3>Evidence summary</h3>
          <p>Four independent signals point the same way, and the alert was graded critical by the alert policy.</p>
        </div>
        <div className="pub-ai-block">
          <h3>Recommended investigation steps</h3>
          <ol>
            <li>Confirm the sign-in with the account owner.</li>
            <li>Review other sessions and devices for the same account.</li>
            <li>Check further activity from the unseen IP.</li>
          </ol>
        </div>
      </div>
      <div className="pub-ai-illus"><Illustrative /></div>
    </div>
  );
}

export const AI_LIMITS = [
  'Determine the primary anomaly score',
  'Override ML decisions',
  'Override alert severity',
  'Change alert state on its own',
  'Change incident state on its own',
];

export function AiBoundary() {
  return (
    <div className="pub-bounds">
      <div>
        <h3 className="pub-bounds-title">AI assists investigation.</h3>
        <p className="pub-bounds-text">The detection, the score, the severity and every status change stay with the ML pipeline, the alert policy and your analysts.</p>
      </div>
      <div>
        <p className="pub-label">AI does not</p>
        <ul className="pub-nots">
          {AI_LIMITS.map((l) => (
            <li key={l}><X size={15} aria-hidden="true" />{l}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/* ------------------------------------------------------- architecture */

type ArchNode = { icon: LucideIcon; title: string; text: string };

const INGEST: ArchNode[] = [
  { icon: Radio, title: 'Security events', text: 'REST API today' },
  { icon: Server, title: 'Spring Boot', text: 'Validates and stores events' },
  { icon: Database, title: 'PostgreSQL', text: 'Events, predictions, alerts, incidents' },
  { icon: Workflow, title: 'Kafka', text: 'Event stream (raw.events.v1)' },
];

const RESPOND: ArchNode[] = [
  { icon: Cpu, title: 'ML detection', text: 'Scores each event' },
  { icon: Scale, title: 'Risk / policy', text: 'Grades scores into alerts' },
  { icon: BellRing, title: 'Alert', text: 'Severity, decision, factors' },
  { icon: ShieldAlert, title: 'Incident', text: 'Grouped per entity' },
  { icon: Sparkles, title: 'AI investigation', text: 'Spring AI, on demand' },
];

function Lane({ label, nodes, offset = 0 }: { label: string; nodes: ArchNode[]; offset?: number }) {
  return (
    <div className="pub-lane">
      <span className="pub-label pub-lane-label">{label}</span>
      <ol className="pub-lane-nodes">
        {nodes.map((n, i) => (
          <li key={n.title} className="pub-arch-node" style={{ ['--i' as string]: i + offset } as CSSProperties}>
            <span className="pub-arch-icon"><n.icon size={18} aria-hidden="true" /></span>
            <strong>{n.title}</strong>
            <span>{n.text}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function ArchitectureVisual() {
  return (
    <div className="pub-arch">
      <Lane label="Ingestion" nodes={INGEST} />
      <div className="pub-arch-link">
        <ArrowDown size={16} aria-hidden="true" />
        <span>A Kafka consumer in Spring Boot sends each event to the ML service</span>
      </div>
      <Lane label="Detection and response" nodes={RESPOND} offset={INGEST.length + 1} />
    </div>
  );
}

/* ----------------------------------------------------------- features */

export const FEATURES: { icon: LucideIcon; title: string; text: string }[] = [
  { icon: Radar, title: 'Behavioral Anomaly Detection', text: 'Scores each event against entity and peer-group baselines to surface unusual behavior.' },
  { icon: Layers, title: 'Attack Classification', text: 'Labels suspicious activity with a known attack type when the classifier recognizes one.' },
  { icon: BellRing, title: 'Risk-Based Alerting', text: 'An alert policy grades scores into medium, high and critical severities.' },
  { icon: Boxes, title: 'Incident Correlation', text: 'Groups related alerts per entity and event type into a single incident.' },
  { icon: Workflow, title: 'Security Event Streaming', text: 'Events flow through Kafka to the detection pipeline.' },
  { icon: Sparkles, title: 'AI-Assisted Investigation', text: 'Evidence-grounded explanations and next steps. Advisory only.' },
  { icon: ClipboardList, title: 'Auditability', text: 'Status changes and administrative actions are recorded in an audit log.' },
  { icon: Activity, title: 'SOC Dashboard', text: 'Events, predictions, alerts, incidents and system health in one console.' },
];
