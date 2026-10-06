import { memo, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Bug,
  CheckCircle2,
  ChevronDown,
  DatabaseZap,
  Eye,
  FlaskConical,
  Gauge,
  GitBranch,
  Info,
  KeyRound,
  Laptop,
  Layers,
  ListChecks,
  Network,
  Pause,
  Play,
  Plane,
  Radar,
  RotateCcw,
  History,
  BookOpen,
  GraduationCap,
  Workflow,
  ShieldCheck,
  Square,
  Terminal,
  Trash2,
  Users,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { useEntities } from '../components/EntitySelect';
import { Drawer, Modal, useToast } from '../components/feedback';
import {
  Badge,
  Button,
  Card,
  CardHead,
  EmptyState,
  LinkButton,
  PageHeader,
  ScoreMeter,
  Segmented,
  SeverityBadge,
  Tabs,
} from '../components/ui';
import { fmtTimeSec } from '../utils/format';
import type { Tone } from '../utils/tone';
import { ACTIVE, elapsedMs, TERMINAL } from '../simulator/engine';
import { completionSummary, filterRows } from '../simulator/liveConsole';
import type { ActivityEntry, CompletionSummary, LiveRow, LiveSnapshot, LiveStatus, RowFilter, RunPlanInfo } from '../simulator/liveConsole';
import {
  buildPreview,
  canStart,
  currentSegment,
  DEFAULT_CONFIG,
  detectionSummary,
  needsConfirmation,
  newRunId,
  planInfo,
  segmentProgress,
  toRunPlan,
} from '../simulator/planner';
import type { PlanPreview, SimulatorConfig } from '../simulator/planner';
import { eventCount, scenarioById, scenarioGroups } from '../simulator/scenarioRegistry';
import {
  ALERT_THRESHOLD,
  DURATION_PRESETS,
  INTENSITIES,
  LIVE_ROW_HARD_LIMIT,
  LIVE_ROW_LIMIT,
  MAX_CUSTOM_DURATION_SEC,
  MAX_EVENT_RATE,
  MAX_TARGETS,
  MIN_CUSTOM_DURATION_SEC,
  NOISE_OPTIONS,
  PATTERNS,
  RATE_OPTIONS,
  TRAIL_OBSERVATION_MS,
} from '../simulator/types';
import type { ObservationQuality, RunSnapshot, RunState, ScenarioCategory, ScenarioDef } from '../simulator/types';
import { runEngine, useRunSnapshot } from '../simulator/useRunEngine';
import { liveConsole, useLiveSnapshot } from '../simulator/useLiveConsole';
import {
  buildHistoryEntry,
  detectionVerdict,
  filterHistory,
  MAX_HISTORY_ENTRIES,
  observedFromEntry,
  observedTerminal,
  shouldPersist,
} from '../simulator/runHistory';
import {
  applyPreset,
  ARCHITECTURE_FLOW,
  assessDemo,
  DEMO_CHECKLIST,
  DEMO_PRESETS,
  DETECTION_LABEL,
  DETECTION_LEGEND,
  demoById,
  expectedLines,
  formatScore,
  observedLines,
  presetLimitations,
} from '../simulator/demoPresets';
import type { DemoAssessment, DemoPreset, DetectionType, ObservedRun } from '../simulator/demoPresets';
import type { HistoryFilter, RunHistoryEntry, SaveMark } from '../simulator/runHistory';
import { runHistory, useRunHistory } from '../simulator/useRunHistory';

/* ------------------------------------------------------------------ */
/* Presentation of the library (definitions live in src/simulator)      */
/* ------------------------------------------------------------------ */

const LOOK: Record<string, { icon: LucideIcon; tone: Tone }> = {
  routine: { icon: ShieldCheck, tone: 'ok' },
  brute: { icon: KeyRound, tone: 'critical' },
  travel: { icon: Plane, tone: 'high' },
  privesc: { icon: Bug, tone: 'high' },
  exfil: { icon: DatabaseZap, tone: 'critical' },
  device: { icon: Laptop, tone: 'medium' },
  credstuff: { icon: Users, tone: 'critical' },
  procconn: { icon: Network, tone: 'high' },
  portscan: { icon: Radar, tone: 'info' },
  suspproc: { icon: Terminal, tone: 'medium' },
  lateral: { icon: GitBranch, tone: 'high' },
  mixed: { icon: Layers, tone: 'critical' },
};

const PATTERN_HINT: Record<string, string> = {
  SEQUENTIAL: 'Segments back-to-back, no overlap in event time.',
  BURST: 'Every segment anchored to the same instant: one tight window.',
  PROGRESSIVE: 'Back-to-back with gaps that halve toward the end.',
  DISTRIBUTED: 'Segments staggered and the plan interleaved, so submissions alternate between entities.',
};

const TARGET_HINT: Record<string, string> = {
  SINGLE: 'One chosen entity.',
  RANDOM: 'One entity picked from the list, derived from the run ID so the preview and the run agree.',
  MULTI: 'The whole scenario replayed on each selected entity.',
  DISTRIBUTED: 'One campaign split across the selected entities where the scenario allows it.',
};

const STATE_TONE: Record<RunState, Tone> = {
  IDLE: 'neutral',
  RUNNING: 'info',
  PAUSED: 'medium',
  STOPPING: 'medium',
  COMPLETED: 'ok',
  STOPPED: 'neutral',
  FAILED: 'critical',
};

const STATUS_TONE: Record<LiveStatus, Tone> = {
  SENDING: 'info',
  ACCEPTED: 'neutral',
  FAILED: 'critical',
  PROCESSING: 'medium',
  PROCESSED: 'ok',
  ALERT: 'high',
  INCIDENT: 'critical',
};

const ACTIVITY_TONE: Record<ActivityEntry['kind'], Tone> = {
  RUN_STARTED: 'info',
  PAUSED: 'medium',
  RESUMED: 'info',
  STOPPING: 'medium',
  ACCEPTED: 'neutral',
  SEND_FAILED: 'critical',
  PROCESSED: 'ok',
  PROCESSING_FAILED: 'critical',
  ALERT: 'high',
  INCIDENT: 'critical',
  RUN_ENDED: 'neutral',
};

/** Detector coverage, said the way the backend actually behaves. */
function DetectorBadges({ s }: { s: ScenarioDef }) {
  return (
    <span className="sim-badges">
      {s.detector.rules.map((r) => <Badge key={r} tone="info" plain title={s.detector.note}>{r}</Badge>)}
      {s.detector.ml && <Badge tone="medium" plain title={s.detector.note}>ML-dependent</Badge>}
      {!s.detector.rules.length && !s.detector.ml && (
        <Badge tone={s.category === 'BASELINE' ? 'ok' : 'neutral'} plain title={s.detector.note}>
          {s.category === 'BASELINE' ? 'Control' : 'No detector'}
        </Badge>
      )}
      {s.scales && <Badge tone="neutral" plain title="The intensity setting changes how many events this scenario generates.">Scales</Badge>}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Small presentational pieces                                         */
/* ------------------------------------------------------------------ */

const secs = (ms: number) => `${Math.round(ms / 1000)}s`;
const clock = (ms: number) => {
  const total = Math.max(0, Math.round(ms / 1000));
  return `${String(Math.floor(total / 60)).padStart(2, '0')}:${String(total % 60).padStart(2, '0')}`;
};
const pct = (done: number, total: number) => (total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0);
const rate = (v: number | null) => (v === null ? '—' : v.toFixed(2));

/**
 * The only thing on the page that ticks. It owns its own interval so the once-a-second elapsed
 * readout never rerenders the live console, the KPI strip or the scenario library.
 */
function Elapsed({ snap }: { snap: RunSnapshot }) {
  const live = ACTIVE.includes(snap.state);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!live) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [live]);
  return <span className="mono">{clock(elapsedMs(snap, now))}</span>;
}

function Kpi({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: Tone }) {
  return (
    <div className="card sim-kpi">
      <span className="kpi-label">{label}</span>
      <b className={`kpi-value${tone ? ` toned tone-${tone}` : ''}`}>{value}</b>
      <span className="hint">{hint ?? ' '}</span>
    </div>
  );
}

function Bar({ label, done, total, tone, note }: { label: string; done: number; total: number; tone: Tone; note?: string }) {
  const value = pct(done, total);
  return (
    <div className="sim-bar">
      <div className="sim-bar-top">
        <span>{label}</span>
        <span className="mono">{done}/{total} · {value}%</span>
      </div>
      <div
        className="sim-bar-track"
        role="progressbar"
        aria-label={label}
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className={`sim-bar-fill tone-${tone}`} style={{ width: `${value}%` }} />
      </div>
      {note && <span className="hint">{note}</span>}
    </div>
  );
}

/** Alert / incident information, which is only ever shown once a trail response established it. */
function Detection({ row }: { row: LiveRow }) {
  if (row.sendError) return <span className="muted">—</span>;
  // The distinction that matters: nothing observed yet is NOT the same as no alert.
  if (!row.observed) return <span className="muted" title="No trail response has been received for this event yet.">Not observed</span>;
  if (!row.alerts.length) {
    return row.processing === 'PROCESSED'
      ? <Badge tone="ok" plain>No alert</Badge>
      : <span className="muted">Not observed</span>;
  }
  return (
    <span className="sim-badges">
      {row.alerts.map((a) => (
        <Link key={a.id} to={`/alerts/${a.id}`} title={`${a.detectionType}${a.ruleId ? ` · ${a.ruleId}` : ''} · ${a.status}`}>
          <SeverityBadge value={a.severity} />
        </Link>
      ))}
      {row.alerts[0].ruleId && <span className="mono muted sim-rule">{row.alerts[0].ruleId}</span>}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Live event console (memoised: it is the heaviest part of the page)   */
/* ------------------------------------------------------------------ */

const EventConsole = memo(function EventConsole({ rows, trimmed }: { rows: LiveRow[]; trimmed: number }) {
  const shown = rows.slice(0, LIVE_ROW_LIMIT);
  return (
    <>
      <div className="table-wrap scroll">
        <table className="sim-console">
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Event</th>
              <th scope="col">Entity</th>
              <th scope="col">Status</th>
              <th scope="col">Processing</th>
              <th scope="col">Score</th>
              <th scope="col">Detection</th>
              <th scope="col">Incident</th>
              <th scope="col">Submitted</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.eventId}>
                <td className="muted mono">{r.seq}</td>
                <td>
                  {r.sendError
                    ? <span className="mono">{r.eventId}</span>
                    : <Link className="mono link" to={`/events/${encodeURIComponent(r.eventId)}`}>{r.eventId}</Link>}
                  <div className="muted sim-sub">{r.eventType} · {r.scenario}</div>
                </td>
                <td className="mono">{r.entityId}</td>
                <td>
                  <Badge tone={STATUS_TONE[r.status]} dot>{r.status}</Badge>
                  {r.sendError && (
                    <div className="field-error sim-sub" title={r.sendError}>
                      {r.httpStatus ? `HTTP ${r.httpStatus}` : 'Transport'} — {r.sendError}
                    </div>
                  )}
                </td>
                <td>
                  {r.processing
                    ? <span className={r.processing === 'FAILED' ? 'field-error' : ''}>{r.processing}</span>
                    : <span className="muted" title="No trail response has been received for this event yet.">Not observed</span>}
                  {r.processingError && <div className="field-error sim-sub">{r.processingError}</div>}
                </td>
                <td>{r.score !== null ? <ScoreMeter value={r.score} /> : <span className="muted">—</span>}</td>
                <td><Detection row={r} /></td>
                <td>
                  {r.incidentIds.length
                    ? r.incidentIds.map((id) => <Link key={id} className="mono link" to={`/incidents/${id}`}>{id.slice(0, 8)}</Link>)
                    : <span className="muted">—</span>}
                </td>
                <td className="mono muted">{fmtTimeSec(new Date(r.submittedAt).toISOString())}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {(rows.length > LIVE_ROW_LIMIT || trimmed > 0) && (
        <p className="muted sim-note">
          Showing the newest {shown.length} of {rows.length} retained rows.
          {trimmed > 0 && ` ${trimmed} older row${trimmed === 1 ? '' : 's'} were dropped from the display to keep it bounded (at most ${LIVE_ROW_HARD_LIMIT}); the counters above stay cumulative.`}
        </p>
      )}
    </>
  );
});

const ActivityFeed = memo(function ActivityFeed({ entries }: { entries: ActivityEntry[] }) {
  if (!entries.length) return <p className="muted">Nothing yet.</p>;
  return (
    <ol className="sim-activity">
      {entries.map((e) => (
        <li key={e.id}>
          <span className="mono muted">{fmtTimeSec(new Date(e.at).toISOString())}</span>
          <Badge tone={ACTIVITY_TONE[e.kind]} plain>{e.label}</Badge>
          <span className="sim-activity-detail">{e.detail}</span>
        </li>
      ))}
    </ol>
  );
});

/* ------------------------------------------------------------------ */
/* Run progress                                                        */
/* ------------------------------------------------------------------ */

const STEPS = ['Scenario', 'Targets', 'Generation', 'Processing', 'Detection', 'Complete'] as const;

function RunProgress({ snap, live, plan }: { snap: RunSnapshot; live: LiveSnapshot; plan: RunPlanInfo | null }) {
  const finished = TERMINAL.includes(snap.state);
  const total = snap.totalEvents;
  const queued = Math.max(0, total - snap.nextEventIndex);
  const observed = live.totals.observed;
  const current = plan ? currentSegment(plan, snap.nextEventIndex) : null;
  const segments = plan ? segmentProgress(plan, snap.nextEventIndex) : [];

  // A step is "done" only when the data says so - detection is never marked done on a guess.
  const done: Record<string, boolean> = {
    Scenario: Boolean(plan ?? snap.label),
    Targets: Boolean(plan?.targets.length) || snap.totalEvents > 0,
    Generation: total > 0 && snap.nextEventIndex >= total,
    Processing: snap.accepted > 0 && observed >= snap.accepted,
    Detection: snap.accepted > 0 && live.totals.processed + live.totals.processingFailed >= snap.accepted,
    Complete: finished && live.pending === 0,
  };

  return (
    <>
      <ol className="sim-steps">
        {STEPS.map((s) => (
          <li key={s} className={done[s] ? 'on' : ''}>
            <span className="sim-step-dot" aria-hidden="true" />
            <span>{s}</span>
            <span className="sr-only">{done[s] ? ' (done)' : ' (pending)'}</span>
          </li>
        ))}
      </ol>

      <Bar label="Generation (submitted by the engine)" done={snap.generated} total={total} tone="info" note={queued > 0 ? `${queued} still queued in the plan` : undefined} />
      <Bar
        label="Backend processing (observed on the trail)"
        done={observed}
        total={snap.accepted}
        tone="ok"
        note={
          live.totals.unobserved > 0
            ? `${live.totals.unobserved} event${live.totals.unobserved === 1 ? '' : 's'} were never observed — polling stopped after ${secs(TRAIL_OBSERVATION_MS)} past the run, or at the attempt cap.`
            : live.pending > 0 ? `${live.pending} awaiting a trail answer (${live.polling} request${live.polling === 1 ? '' : 's'} in flight)` : undefined
        }
      />

      {plan && plan.phases.length > 0 && (
        <div className="sim-phases">
          <h3 className="drawer-h">Scenario phases</h3>
          <div className="sim-badges">{plan.phases.map((p) => <Badge key={p} tone="neutral" plain>{p}</Badge>)}</div>
        </div>
      )}

      {segments.length > 1 && (
        <div className="sim-phases">
          <h3 className="drawer-h">Plan segments{current && !finished ? ` — generating ${current.kind === 'NOISE' ? 'benign noise' : 'scenario'} on ${current.entityId}` : ''}</h3>
          <ul className="sim-list">
            {segments.map((s) => (
              <li key={s.prefix} className={current && current.index === s.index && !finished ? 'on' : ''}>
                <span className="mono">{s.entityId}{s.kind === 'NOISE' ? ' · noise' : ''}</span>
                <b>{s.submitted}/{s.count}</b>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

function DetectionPanel({ live, snap }: { live: LiveSnapshot; snap: RunSnapshot }) {
  const t = live.totals;
  const severities = Object.entries(t.severity).sort((a, b) => b[1] - a[1]);
  const detectors = Object.entries(t.detectors).sort((a, b) => b[1] - a[1]);
  const unknown = Math.max(0, snap.accepted - t.observed);

  if (!snap.accepted) return <p className="muted">Nothing submitted yet.</p>;
  return (
    <>
      <div className="sim-facts">
        <div>
          <h3 className="drawer-h">Severities observed</h3>
          {severities.length
            ? <div className="sim-badges">{severities.map(([s, n]) => <span key={s} className="sim-sev">
                <SeverityBadge value={s} /><b>×{n}</b>
              </span>)}</div>
            : <p className="muted">{t.observed ? 'No alert on any observed event.' : 'Not observed yet.'}</p>}
        </div>
        <div>
          <h3 className="drawer-h">Detectors that fired</h3>
          {detectors.length
            ? <ul className="sim-list">{detectors.map(([d, n]) => <li key={d}><span className="mono">{d}</span><b>{n}</b></li>)}</ul>
            : <p className="muted">{t.observed ? 'None.' : 'Not observed yet.'}</p>}
        </div>
      </div>

      {live.incidents.length > 0 && (
        <div className="sim-phases">
          <h3 className="drawer-h">Incidents</h3>
          <ul className="sim-list">
            {live.incidents.map((i) => (
              <li key={i.id}>
                <Link className="mono link" to={`/incidents/${i.id}`}>{i.id.slice(0, 8)}</Link>
                <span>{i.status} · {i.alertCount} alert{i.alertCount === 1 ? '' : 's'}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {unknown > 0 && (
        <p className="muted sim-note">
          {unknown} accepted event{unknown === 1 ? '' : 's'} have no trail answer yet, so detection for {unknown === 1 ? 'it' : 'them'} is <b>not observed</b> rather than &ldquo;no alert&rdquo;.
        </p>
      )}
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Completion summary                                                  */
/* ------------------------------------------------------------------ */

const OUTCOME_TONE: Record<CompletionSummary['outcome'], Tone> = {
  COMPLETED: 'ok',
  STOPPED: 'neutral',
  DURATION: 'medium',
  FAILED: 'critical',
};

const OUTCOME_TEXT: Record<CompletionSummary['outcome'], string> = {
  COMPLETED: 'Every planned event was attempted.',
  STOPPED: 'Stopped on request before the plan finished.',
  DURATION: 'The wall-clock duration cap expired before the plan finished.',
  FAILED: 'The engine ended the run; the remaining events were not sent.',
};

function CompletionCard({ s, onRunAgain, onReset, busy }: { s: CompletionSummary; onRunAgain: () => void; onReset: () => void; busy: boolean }) {
  const fields: [string, string][] = [
    ['Run ID', s.runId ?? '—'],
    ['Scenario', s.label ?? '—'],
    ['Duration', clock(s.durationMs)],
    ['Generated', `${s.generated} of ${s.totalEvents}`],
    ['Accepted', String(s.accepted)],
    ['Failed', String(s.failed)],
    ['Average rate', `${rate(s.averageRate)}/s`],
    ['Observed', `${s.observed} of ${s.accepted} accepted`],
    ['Processed', String(s.processed)],
    ['Alerts', String(s.alerts)],
    ['Incidents', String(s.incidents)],
    ['Peak score', s.peakScore === null ? 'not observed' : s.peakScore.toFixed(3)],
  ];
  return (
    <Card className="sim-complete" style={{ marginTop: 12 }}>
      <CardHead
        kicker="Summary"
        kickerIcon={ListChecks}
        title={<span className="row-gap">Run finished <Badge tone={OUTCOME_TONE[s.outcome]} dot>{s.outcome}</Badge></span>}
        description={s.reason ?? OUTCOME_TEXT[s.outcome]}
        actions={
          <div className="row-gap">
            <Button variant="primary" size="sm" icon={Play} onClick={onRunAgain} disabled={busy}>Run again</Button>
            <Button variant="secondary" size="sm" icon={RotateCcw} onClick={onReset}>Reset</Button>
          </div>
        }
      />
      <dl className="sim-confirm-grid">
        {fields.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className={k === 'Run ID' ? 'mono' : undefined}>{v}</dd></div>)}
      </dl>
      {s.unobserved > 0 && (
        <p className="muted sim-note">
          {s.unobserved} accepted event{s.unobserved === 1 ? '' : 's'} were never observed: trail polling stops {secs(TRAIL_OBSERVATION_MS)} after a run ends. Their pipeline outcome is unknown here, not absent — open an event to check it.
        </p>
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Demo mode (presets and expectations; see src/simulator/demoPresets) */
/* ------------------------------------------------------------------ */

const DETECTION_TONE: Record<DetectionType, Tone> = {
  RULE: 'info',
  ML: 'medium',
  RULE_AND_ML: 'high',
  CONTROL: 'ok',
  COVERAGE_GAP: 'neutral',
};

const VERDICT_TONE: Record<DemoAssessment['verdict'], Tone> = {
  EXPECTED_OBSERVED: 'ok',
  EXPECTED_NOT_OBSERVED: 'medium',
  INCONCLUSIVE: 'neutral',
  EXPECTED_NO_DETECTION: 'ok',
};

/** The detection-type chip. Always a text label, never colour alone. */
const DetectionChip = ({ type, title }: { type: DetectionType; title?: string }) => (
  <Badge tone={DETECTION_TONE[type]} plain title={title}>{DETECTION_LABEL[type]}</Badge>
);

/** Build the observed side of an assessment from live run state. Recorded values only. */
const observedFromLive = (snap: RunSnapshot, live: LiveSnapshot, observation: ObservationQuality): ObservedRun => ({
  accepted: snap.accepted,
  observedTerminal: live.totals.processed + live.totals.processingFailed,
  observation,
  alerts: live.totals.alerts,
  incidents: live.totals.incidents,
  peakScore: live.totals.peakScore,
  severity: { ...live.totals.severity },
  detectors: { ...live.totals.detectors },
});

/** Expected beside observed, which is the comparison the whole demo mode exists for. */
function ExpectedVsObserved({ a }: { a: DemoAssessment }) {
  return (
    <div className="sim-vs">
      <div>
        <h3 className="drawer-h">Expected</h3>
        <ul className="sim-notes-list">{a.expectedLines.map((l) => <li key={l}>{l}</li>)}</ul>
      </div>
      <div>
        <h3 className="drawer-h">Observed</h3>
        <ul className="sim-notes-list">{a.observedLines.map((l) => <li key={l}>{l}</li>)}</ul>
      </div>
    </div>
  );
}

function Assessment({ a }: { a: DemoAssessment }) {
  return (
    <>
      <p className="row-gap">
        <Badge tone={VERDICT_TONE[a.verdict]} dot>{a.verdict.replace(/_/g, ' ')}</Badge>
        <b>{a.label}</b>
      </p>
      <p className="muted sim-note">{a.detail}</p>
    </>
  );
}

/** One demo card. Selecting it only loads a configuration - nothing is sent. */
const DemoCard = memo(function DemoCard({ d, on, events, onPick }: { d: DemoPreset; on: boolean; events: number; onPick: (id: string) => void }) {
  return (
    <label className={`card scenario pick tone-${DETECTION_TONE[d.detectionType]}${on ? ' on' : ''}`}>
      <input type="radio" className="sr-only" name="sim-demo" value={d.id} checked={on} onChange={() => onPick(d.id)} />
      <div className="scenario-top">
        <DetectionChip type={d.detectionType} />
        <span className="scenario-count">{events} events</span>
      </div>
      <h2>{d.name}</h2>
      <p>{d.purpose}</p>
      <div className="scenario-expect"><span>Demonstrates</span>{d.expectation.statement}</div>
    </label>
  );
});

/** The architecture an event really travels. Conditional steps are marked as such. */
const ArchitectureFlow = memo(function ArchitectureFlow() {
  return (
    <ol className="sim-arch">
      {ARCHITECTURE_FLOW.map((step) => (
        <li key={step.id} className={step.conditional ? 'cond' : ''}>
          <span className="sim-arch-label">
            {step.label}
            {step.conditional && <Badge tone="neutral" plain>only for some runs</Badge>}
          </span>
          <span className="muted">{step.detail}</span>
        </li>
      ))}
    </ol>
  );
});

/** The five viva questions, answered for the selected demo. */
function ExplainPanel({ d }: { d: DemoPreset }) {
  const rows: [string, string][] = [
    ['What behaviour is simulated?', d.explain.behaviour],
    ['Which component processes it?', d.explain.component],
    ['Deterministic or ML-dependent?', d.explain.determinism],
    ['What should we expect?', d.explain.expected],
    ['What limitation exists?', d.explain.limitation],
  ];
  return (
    <dl className="sim-explain">
      {rows.map(([q, a]) => <div key={q}><dt>{q}</dt><dd>{a}</dd></div>)}
    </dl>
  );
}

/* ------------------------------------------------------------------ */
/* Run history (local record; see src/simulator/runHistory.ts)         */
/* ------------------------------------------------------------------ */

const HISTORY_FILTERS: { value: HistoryFilter; label: string }[] = [
  { value: 'ALL', label: 'All' },
  { value: 'COMPLETED', label: 'Completed' },
  { value: 'STOPPED', label: 'Stopped' },
  { value: 'DURATION', label: 'Duration' },
  { value: 'FAILED', label: 'Failed' },
];

const OBSERVATION_TONE: Record<RunHistoryEntry['observation'], Tone> = {
  COMPLETE: 'ok',
  PARTIAL: 'medium',
  NONE: 'critical',
};

const OBSERVATION_LABEL: Record<RunHistoryEntry['observation'], string> = {
  COMPLETE: 'Fully observed',
  PARTIAL: 'Partially observed',
  NONE: 'Not observed',
};

const stamp = (ms: number) => new Date(ms).toLocaleString();

/** One compact row in the history list. Deliberately small: the detail view holds the rest. */
const HistoryCard = memo(function HistoryCard({ e, onOpen }: { e: RunHistoryEntry; onOpen: (runId: string) => void }) {
  return (
    <button type="button" className="card sim-history-card" onClick={() => onOpen(e.runId)}>
      <div className="sim-history-top">
        <span className="mono">{e.runId}</span>
        <Badge tone={OUTCOME_TONE[e.outcome]} dot>{e.outcome}</Badge>
      </div>
      <h3>{e.scenarioName}</h3>
      {/* Three fields of demo metadata are all a record keeps - no expectation, no assessment. */}
      {e.demo && (
        <span className="sim-badges">
          <Badge tone="info" plain>DEMO</Badge>
          <DetectionChip type={e.demo.detectionType} />
          <span className="muted">{e.demo.demoName}</span>
        </span>
      )}
      <div className="sim-history-stats">
        <span>{e.generated} events · {e.accepted} accepted{e.failed > 0 ? ` · ${e.failed} failed` : ''}</span>
        <span>
          {e.alerts} alert{e.alerts === 1 ? '' : 's'} · {e.incidents} incident{e.incidents === 1 ? '' : 's'}
          {/* A count alone would mislead when coverage was partial, so the quality travels with it. */}
          {e.observation !== 'COMPLETE' && <span className="muted"> ({OBSERVATION_LABEL[e.observation].toLowerCase()})</span>}
        </span>
        <span>Peak {e.peakScore === null ? 'not observed' : e.peakScore.toFixed(3)} · {clock(e.durationMs)}</span>
      </div>
      <span className="sim-history-when muted">{stamp(e.completedAt)}</span>
    </button>
  );
});

/** The investigation view. It reads one stored record and never touches the live run. */
function HistoryDetail({ e, onRunAgain, onDelete, runActive }: { e: RunHistoryEntry; onRunAgain: (e: RunHistoryEntry) => void; onDelete: (e: RunHistoryEntry) => void; runActive: boolean }) {
  const verdict = detectionVerdict(e);
  const observedCount = observedTerminal(e);
  // The preset is looked up by id and its expectation re-read now; the record stores no expectation
  // of its own, so a historical demo can never disagree with the preset it names.
  const preset = e.demo ? demoById(e.demo.demoId) ?? null : null;
  const historyAssessment = preset ? assessDemo(preset.expectation, observedFromEntry(e)) : null;
  const section = (title: string, fields: [string, string][]) => (
    <div>
      <h3 className="drawer-h">{title}</h3>
      <dl className="sim-confirm-grid">
        {fields.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className={k === 'Run ID' ? 'mono' : undefined}>{v}</dd></div>)}
      </dl>
    </div>
  );

  return (
    <>
      {e.demo && (
        <div>
          <h3 className="drawer-h">Demo</h3>
          <p className="row-gap">
            <Badge tone="info" plain>DEMO</Badge>
            <b>{e.demo.demoName}</b>
            <DetectionChip type={e.demo.detectionType} />
          </p>
          {historyAssessment ? (
            <>
              <Assessment a={historyAssessment} />
              <ExpectedVsObserved a={historyAssessment} />
            </>
          ) : (
            <p className="muted sim-note">
              This run names a demo preset that no longer exists, so its expectation cannot be shown. The
              recorded results below are unaffected.
            </p>
          )}
        </div>
      )}

      {section('Run identity', [
        ['Run ID', e.runId],
        ['Started', stamp(e.createdAt)],
        ['Finished', stamp(e.completedAt)],
        ['Outcome', e.outcome],
        ['Reason', e.reason ?? OUTCOME_TEXT[e.outcome]],
      ])}

      {section('Configuration at the time of the run', [
        ['Scenario', `${e.scenarioName} (${e.scenarioId})`],
        ['Targets', e.targets.join(', ') || '—'],
        ['Target mode', e.targetMode],
        ['Rate', `${e.configuredRate}/s configured`],
        ['Duration cap', e.maxDurationMs === null ? 'none' : secs(e.maxDurationMs)],
        ['Intensity', e.intensity],
        ['Benign noise', `${e.noisePercent}%`],
        ['Attack pattern', e.pattern],
      ])}

      {section('Generation', [
        ['Generated', `${e.generated} of ${e.totalEvents} planned`],
        ['Accepted', String(e.accepted)],
        ['Failed', String(e.failed)],
        ['Actual rate', `${rate(e.actualRate)}/s`],
        ['Wall-clock', clock(e.durationMs)],
      ])}

      <div>
        <h3 className="drawer-h">Detection</h3>
        <p className={`sim-verdict${verdict.conclusive ? ' on' : ''}`}>
          {verdict.conclusive ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
          <span>{verdict.headline}</span>
        </p>
        {verdict.caveat && <p className="muted sim-note">{verdict.caveat}</p>}
        <dl className="sim-confirm-grid">
          <div><dt>Observed alerts</dt><dd>{e.alerts}</dd></div>
          <div><dt>Observed incidents</dt><dd>{e.incidents}</dd></div>
          <div><dt>Peak score</dt><dd>{e.peakScore === null ? 'not observed' : e.peakScore.toFixed(3)}</dd></div>
          <div><dt>Detector claim</dt><dd>{e.detection}</dd></div>
        </dl>
        {Object.keys(e.severity).length > 0 && (
          <div className="sim-badges">
            {Object.entries(e.severity).map(([sev, n]) => (
              <span key={sev} className="sim-sev"><SeverityBadge value={sev} /><b>×{n}</b></span>
            ))}
          </div>
        )}
        {Object.keys(e.detectors).length > 0 && (
          <ul className="sim-list" style={{ marginTop: 8 }}>
            {Object.entries(e.detectors).map(([d, n]) => <li key={d}><span className="mono">{d}</span><b>{n}</b></li>)}
          </ul>
        )}
      </div>

      <div>
        <h3 className="drawer-h">Observation quality</h3>
        <p className="row-gap">
          <Badge tone={OBSERVATION_TONE[e.observation]} dot>{OBSERVATION_LABEL[e.observation]}</Badge>
          <span className="muted">{observedCount} of {e.accepted} accepted events reached a known pipeline outcome</span>
        </p>
        <dl className="sim-confirm-grid">
          <div><dt>Trails read</dt><dd>{e.observed}</dd></div>
          <div><dt>Processed</dt><dd>{e.processed}</dd></div>
          <div><dt>Processing failed</dt><dd>{e.processingFailed}</dd></div>
          <div><dt>Never observed</dt><dd>{e.unobserved}</dd></div>
          <div><dt>Observation window</dt><dd>{secs(e.observationWindowMs)} after the run</dd></div>
          <div><dt>Live rows dropped</dt><dd>{e.droppedRows} (display only)</dd></div>
        </dl>
        {e.observation !== 'COMPLETE' && (
          <p className="muted sim-note">
            Polling stops {secs(e.observationWindowMs)} after a run ends, so some outcomes may simply never have been
            read here. The events themselves are still in the backend — open one from the Events page to see its trail.
          </p>
        )}
      </div>

      <div className="sim-history-actions">
        <Button variant="primary" icon={Play} onClick={() => onRunAgain(e)}>Run again</Button>
        <Button variant="danger" icon={Trash2} onClick={() => onDelete(e)}>Delete entry</Button>
        <p className="hint">
          Run again loads this configuration into the Simulator. Nothing is sent until you press Start
          {runActive ? ', and the run in progress is left alone.' : '.'}
        </p>
      </div>
    </>
  );
}

const FILTERS: { value: RowFilter; label: string }[] = [
  { value: 'ALL', label: 'All' },
  { value: 'ACCEPTED', label: 'Accepted' },
  { value: 'FAILED', label: 'Failed' },
  { value: 'PENDING', label: 'Pending' },
  { value: 'ALERTS', label: 'Alerts' },
  { value: 'INCIDENTS', label: 'Incidents' },
];

export default function Simulator() {
  const toast = useToast();
  const entities = useEntities();

  const [config, setConfig] = useState<SimulatorConfig>(DEFAULT_CONFIG);
  const [category, setCategory] = useState<ScenarioCategory | 'ALL'>('ALL');
  const [showEvents, setShowEvents] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [configOpen, setConfigOpen] = useState(true);
  const [filter, setFilter] = useState<RowFilter>('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  /** Bumped to force a brand-new run ID for the same configuration (Run again). */
  const [nonce, setNonce] = useState(0);
  /** Demo mode changes presets and presentation only; it never touches the engine or the transport. */
  const [demoMode, setDemoMode] = useState(false);
  const [demoId, setDemoId] = useState<string | null>(null);
  const [demoOpen, setDemoOpen] = useState(true);
  /** Checklist ticks, for this session only. Nothing is persisted and nothing is performed. */
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  const [historyFilter, setHistoryFilter] = useState<HistoryFilter>('ALL');
  const [openRunId, setOpenRunId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<RunHistoryEntry | null>(null);
  const [clearing, setClearing] = useState(false);

  const snap = useRunSnapshot();
  const live = useLiveSnapshot();
  const history = useRunHistory();
  const active = ACTIVE.includes(snap.state);
  const finished = TERMINAL.includes(snap.state);

  const list = entities.data?.content ?? [];
  const available = useMemo(() => list.map((e) => e.entityId), [list]);
  const set = (patch: Partial<SimulatorConfig>) => {
    setConfirming(false);
    setConfig((c) => ({ ...c, ...patch }));
  };

  useEffect(() => {
    if (!config.entityId && available.length) set({ entityId: available[0] });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [available, config.entityId]);

  /*
   * The plan is built once per configuration and the SAME object is handed to the engine on Start,
   * so a preview shows the events that are really submitted rather than an estimate of them. The
   * time anchor and run ID are part of that plan, so they are regenerated with it - and `nonce`
   * regenerates them for an unchanged configuration, which is what "Run again" needs.
   */
  const configKey = JSON.stringify(config);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const seed = useMemo(() => ({ runId: newRunId(config.scenarioId), now: Date.now() }), [configKey, nonce]);
  const preview = useMemo(
    () => buildPreview(config, { runId: seed.runId, now: seed.now, available }),
    [config, seed, available],
  );
  const startable = canStart(preview);
  const errors = preview.issues.filter((i) => i.level === 'error');
  const scenario = scenarioById(config.scenarioId);

  /* ---------------------------------------------------------------- the live console */

  // One mount, one shared poller. The teardown stops it, so an unmounted page never keeps polling
  // (the engine's own run is deliberately untouched - that is the Phase 2 contract).
  useEffect(() => liveConsole.attach(), []);

  // Fold every engine snapshot into the bounded console. The console owns no transport of its own.
  useEffect(() => {
    liveConsole.ingest(snap);
  }, [snap]);

  // Collapse the configuration once a run starts; reopen it when the console is cleared.
  useEffect(() => {
    if (snap.state === 'RUNNING') {
      setConfigOpen(false);
      // Keep the live console the primary thing on screen once events start moving.
      setDemoOpen(false);
    } else if (snap.state === 'IDLE' && live.runId === null) {
      setConfigOpen(true);
      setDemoOpen(true);
    }
  }, [snap.state, live.runId]);

  /*
   * Persist a finished run, at most twice and never more: once the moment it reaches a terminal
   * state (so navigating away cannot lose it), and once more when trail polling has settled (so the
   * record carries the final observation coverage). add() replaces by run id, so neither a reset nor
   * a remount can produce a second entry for the same run.
   */
  const saved = useRef<SaveMark>(null);
  useEffect(() => {
    if (!finished || !summaryRef.current || !live.plan || !snap.runId || snap.startedAt === null) return;
    const settled = live.pending === 0 && !live.pollerArmed;
    const decision = shouldPersist(saved.current, snap.runId, finished, settled);
    if (decision === 'SKIP') return;
    const entry = buildHistoryEntry(summaryRef.current, live.plan, live.totals, snap.startedAt);
    if (!entry) return;
    runHistory.add(entry);
    saved.current = { runId: snap.runId, finalized: decision === 'FINALIZE' };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finished, snap, live]);

  // One toast when a run ends - not again for a run that had already ended before this mount.
  const announced = useRef(`${snap.runId}:${snap.state}`);
  useEffect(() => {
    const key = `${snap.runId}:${snap.state}`;
    if (!TERMINAL.includes(snap.state) || announced.current === key) return;
    announced.current = key;
    const label = snap.label ?? 'Run';
    const firstError = snap.results.find((r) => r.error)?.error?.message;
    if (snap.state === 'FAILED') toast.error(`${label}: run failed`, snap.failureReason ?? undefined);
    else if (snap.state === 'STOPPED') toast.info(`${label}: stopped${snap.stopReason === 'DURATION' ? ' (duration reached)' : ''}`, `${snap.accepted} of ${snap.totalEvents} events were accepted before the stop.`);
    else if (snap.failed) toast.error(`${snap.failed} of ${snap.totalEvents} events were rejected`, firstError);
    else toast.success(`${label}: ${snap.totalEvents} event${snap.totalEvents === 1 ? '' : 's'} sent`, 'Tracking their pipeline outcome below.');
  }, [snap, toast]);

  /* ---------------------------------------------------------------- commands */

  /*
   * The engine owns the run: the page only builds the plan and hands it over. It submits strictly in
   * plan order, one POST at a time, paced, with the wall-clock duration cap - which is what makes
   * the database-backed rules correlate. Nothing here schedules, retries or re-sends anything.
   */
  const start = (p: PlanPreview) => {
    if (!canStart(p)) return;
    setConfirming(false);
    try {
      if (TERMINAL.includes(runEngine.getSnapshot().state)) runEngine.reset();
      liveConsole.reset();
      liveConsole.setPlan(planInfo(p, demoMeta));
      runEngine.start(toRunPlan(p), { eventRate: p.config.eventRate, maxDurationMs: p.maxDurationMs });
      setFilter('ALL');
      setTypeFilter('ALL');
    } catch (e) {
      toast.error(`${p.label}: could not start`, e instanceof Error ? e.message : String(e));
    }
  };

  // Run again: same configuration, a brand-new run ID and time anchor. Bumping the nonce rebuilds
  // the preview; this one-shot flag then starts THAT preview, so the plan and the run still match.
  const restart = useRef(false);
  const runAgain = () => {
    restart.current = true;
    setNonce((n) => n + 1);
  };
  useEffect(() => {
    if (!restart.current) return;
    restart.current = false;
    start(preview);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preview]);

  const resetAll = () => {
    try {
      if (TERMINAL.includes(runEngine.getSnapshot().state)) runEngine.reset();
    } catch {
      /* the run already moved on */
    }
    liveConsole.reset();
  };

  /*
   * Run again, from a history entry: load the configuration that produced it and stop there. No
   * event is built, nothing is sent and the engine is not touched - a run in progress keeps running
   * and stays in control of the page. Starting is the user's explicit next step.
   */
  const loadFromHistory = (e: RunHistoryEntry) => {
    setConfig({ ...e.config, entityIds: [...e.config.entityIds] });
    setConfirming(false);
    setConfigOpen(true);
    setOpenRunId(null);
    toast.info(`Configuration from ${e.runId} loaded`, active
      ? 'The run in progress was not affected. Press Start when it finishes to run this configuration as a new run.'
      : 'Review the preview and press Start to run it as a new run with a new run ID.');
  };

  const confirmDelete = () => {
    if (!deleting) return;
    runHistory.remove(deleting.runId);
    if (openRunId === deleting.runId) setOpenRunId(null);
    toast.info(`${deleting.runId} removed from local history`, 'The events it submitted are untouched.');
    setDeleting(null);
  };

  const confirmClear = () => {
    runHistory.clear();
    setOpenRunId(null);
    setClearing(false);
    toast.info('Local Simulator history cleared', 'Nothing was deleted from the backend.');
  };

  // A command can race the run ending on its own; the engine then rejects it, which is harmless here.
  const command = (fn: () => void) => () => {
    try {
      fn();
    } catch {
      /* the run already moved on */
    }
  };

  /* ---------------------------------------------------------------- derived view data */

  const summary = useMemo(() => completionSummary(snap, live), [snap, live]);
  // The persistence effect needs the summary without depending on its identity.
  const summaryRef = useRef(summary);
  summaryRef.current = summary;
  const historyEntries = useMemo(() => filterHistory(history.entries, historyFilter), [history.entries, historyFilter]);
  const openEntry = useMemo(() => history.entries.find((e) => e.runId === openRunId) ?? null, [history.entries, openRunId]);
  const eventTypes = useMemo(() => [...new Set(live.rows.map((r) => r.eventType))].sort(), [live.rows]);
  const rows = useMemo(() => filterRows(live.rows, filter, typeFilter), [live.rows, filter, typeFilter]);

  const groups = scenarioGroups().filter((g) => category === 'ALL' || g.category === category);
  const multi = config.targetMode === 'MULTI' || config.targetMode === 'DISTRIBUTED';
  const hasRun = live.runId !== null || snap.runId !== null;
  const toggleEntity = (id: string) =>
    set({ entityIds: config.entityIds.includes(id) ? config.entityIds.filter((x) => x !== id) : [...config.entityIds, id] });

  const t = live.totals;
  const configuredDuration = snap.state === 'IDLE' ? preview.maxDurationMs : snap.maxDurationMs;

  /* ---------------------------------------------------------------- demo mode */

  const demo = demoId ? demoById(demoId) ?? null : null;
  /** The demo metadata a run started now would carry. Three fields, never a result. */
  const demoMeta = demoMode && demo ? { demoId: demo.id, demoName: demo.name, detectionType: demo.detectionType } : null;
  /**
   * Demo mode always shows the confirmation step: the walkthrough is meant to include it, and the
   * normal gate still applies on its own outside demo mode. This only ever ADDS a confirmation.
   */
  const mustConfirm = needsConfirmation(preview) || (demoMode && demo !== null);

  // The demo the FINISHED run came from, which may not be the one currently selected.
  const ranDemo = live.plan?.demo ? demoById(live.plan.demo.demoId) ?? null : null;
  const liveObservation: ObservationQuality =
    snap.accepted <= 0 ? 'NONE'
      : t.processed + t.processingFailed >= snap.accepted ? 'COMPLETE'
        : t.processed + t.processingFailed > 0 ? 'PARTIAL' : 'NONE';
  const liveAssessment = useMemo(
    () => (finished && ranDemo ? assessDemo(ranDemo.expectation, observedFromLive(snap, live, liveObservation)) : null),
    [finished, ranDemo, snap, live, liveObservation],
  );

  const pickDemo = (id: string) => {
    const preset = demoById(id);
    if (!preset) return;
    setDemoId(id);
    // A preset is a shortcut for configuration and nothing else: it goes through the same planner,
    // validation, preview and confirmation as any hand-made configuration.
    setConfig((c) => applyPreset(c, preset));
    setConfirming(false);
  };

  const toggleDemoMode = () => {
    setDemoMode((on) => {
      if (on) setDemoId(null);
      return !on;
    });
    setConfirming(false);
  };

  /* ---------------------------------------------------------------- blocks */

  const configBlock = (
    <Card flush className="sim-config-card">
      <div className="card-section">
        <CardHead
          kicker="Setup"
          kickerIcon={FlaskConical}
          title="Scenario and configuration"
          description={scenario ? `${scenario.name} — ${detectionSummary(scenario)}` : undefined}
          actions={
            <Button
              variant="ghost"
              size="sm"
              icon={ChevronDown}
              aria-expanded={configOpen}
              onClick={() => setConfigOpen((v) => !v)}
            >
              {configOpen ? 'Collapse' : 'Edit configuration'}
            </Button>
          }
        />
      </div>

      {configOpen && (
        <div className="card-section">
          <div className="sim-layout">
            {/* ------------------------------------------------------ library */}
            <div>
              <Tabs
                value={category}
                onChange={setCategory}
                tabs={[
                  { value: 'ALL' as const, label: 'All', count: scenarioGroups().reduce((n, g) => n + g.scenarios.length, 0) },
                  ...scenarioGroups().map((g) => ({ value: g.category, label: g.label, count: g.scenarios.length })),
                ]}
              />
              {groups.map((g) => (
                <section key={g.category} className="sim-group" aria-label={`${g.label} scenarios`}>
                  {category === 'ALL' && <h3 className="drawer-h">{g.label}</h3>}
                  <div className="scenario-grid tight">
                    {g.scenarios.map((s) => {
                      const { icon: Icon, tone } = LOOK[s.id] ?? { icon: FlaskConical, tone: 'neutral' as Tone };
                      const on = s.id === config.scenarioId;
                      return (
                        // A real radio group: one scenario is picked, the keyboard works, and the
                        // card stays valid markup (a <button> may not contain a heading).
                        <label key={s.id} className={`card scenario pick tone-${tone}${on ? ' on' : ''}`}>
                          <input
                            type="radio"
                            className="sr-only"
                            name="sim-scenario"
                            value={s.id}
                            checked={on}
                            onChange={() => set({ scenarioId: s.id })}
                          />
                          <div className="scenario-top">
                            <span className="scenario-icon"><Icon size={18} /></span>
                            <span className="scenario-count">{eventCount(s, config.intensity)} events</span>
                          </div>
                          <h2>{s.name}</h2>
                          <p>{s.description}</p>
                          <DetectorBadges s={s} />
                          <div className="scenario-expect"><span>Exercises</span>{s.exercises}</div>
                        </label>
                      );
                    })}
                  </div>
                </section>
              ))}
            </div>

            {/* ------------------------------------------------------ configuration + preview */}
            <div className="sim-side">
              <div className="sim-config">
                <div className="field">
                  <span>Targets</span>
                  <Segmented
                    value={config.targetMode}
                    onChange={(v) => set({ targetMode: v })}
                    options={[
                      { value: 'SINGLE' as const, label: 'Single' },
                      { value: 'RANDOM' as const, label: 'Random' },
                      { value: 'MULTI' as const, label: 'Multiple' },
                      { value: 'DISTRIBUTED' as const, label: 'Distributed' },
                    ]}
                  />
                  <span className="hint">{TARGET_HINT[config.targetMode]}</span>
                </div>

                {config.targetMode === 'SINGLE' && (
                  <label className="field">
                    <span>Target entity</span>
                    <select value={config.entityId} onChange={(e) => set({ entityId: e.target.value })} disabled={!available.length}>
                      {!available.length && <option value="">No entities available</option>}
                      {list.map((e) => <option key={e.entityId} value={e.entityId}>{e.entityId}{e.displayName ? ` — ${e.displayName}` : ''}</option>)}
                    </select>
                  </label>
                )}

                {config.targetMode === 'RANDOM' && (
                  <div className="field">
                    <span>Target entity</span>
                    <p className="hint">{preview.targets[0] ? <span className="mono">{preview.targets[0]}</span> : 'None available'} — chosen for run {preview.runId}.</p>
                  </div>
                )}

                {multi && (
                  <div className="field">
                    <span>Target entities ({config.entityIds.length} of max {MAX_TARGETS})</span>
                    <div className="sim-entity-list">
                      {list.map((e) => (
                        <label key={e.entityId} className="sim-check">
                          <input type="checkbox" checked={config.entityIds.includes(e.entityId)} onChange={() => toggleEntity(e.entityId)} />
                          <span className="mono">{e.entityId}</span>
                        </label>
                      ))}
                    </div>
                    <span className="hint">Select at least two.</span>
                  </div>
                )}

                <div className="field">
                  <span>Event rate</span>
                  <Segmented value={config.eventRate} onChange={(v) => set({ eventRate: v })} options={RATE_OPTIONS.map((value) => ({ value, label: `${value}/s` }))} />
                  <span className="hint">The engine&rsquo;s own hard cap is {MAX_EVENT_RATE} events/sec.</span>
                </div>

                <div className="field">
                  <span>Duration</span>
                  <Segmented
                    value={config.duration}
                    onChange={(v) => set({ duration: v })}
                    options={[...DURATION_PRESETS.map((value) => ({ value: value as number | 'CUSTOM', label: `${value}s` })), { value: 'CUSTOM' as const, label: 'Custom' }]}
                  />
                  {config.duration === 'CUSTOM' && (
                    <input
                      type="text"
                      inputMode="numeric"
                      placeholder={`${MIN_CUSTOM_DURATION_SEC}–${MAX_CUSTOM_DURATION_SEC} seconds`}
                      value={config.customDurationSec}
                      onChange={(e) => set({ customDurationSec: e.target.value })}
                      aria-label="Custom duration in seconds"
                    />
                  )}
                  <span className="hint">A wall-clock cap from Start, pauses included. The run stops when it expires.</span>
                </div>

                <div className="field">
                  <span>Intensity</span>
                  <Segmented value={config.intensity} onChange={(v) => set({ intensity: v })} options={INTENSITIES.map((value) => ({ value, label: value[0] + value.slice(1).toLowerCase() }))} />
                  <span className="hint">{scenario?.scales ? 'Changes how long this scenario’s sequence is.' : 'This scenario has a fixed event contract — intensity does not change it.'}</span>
                </div>

                <div className="field">
                  <span>Benign noise</span>
                  <Segmented value={config.noisePercent} onChange={(v) => set({ noisePercent: v })} options={NOISE_OPTIONS.map((value) => ({ value, label: `${value}%` }))} />
                  <span className="hint">Ordinary activity added through the same builder, validator and engine. Not a promise of no alerts.</span>
                </div>

                <div className="field">
                  <span>Attack pattern</span>
                  <Segmented value={config.pattern} onChange={(v) => set({ pattern: v })} options={PATTERNS.map((value) => ({ value, label: value[0] + value.slice(1).toLowerCase() }))} />
                  <span className="hint">{PATTERN_HINT[config.pattern]} Submission itself stays strictly sequential.</span>
                </div>
              </div>

              {/* ---------------------------------------------- dry run */}
              <div className="sim-preview">
                <CardHead
                  kicker="Dry run"
                  kickerIcon={Eye}
                  title="Preview and validation"
                  description="Built from the plan itself — no request is made and nothing reaches the backend until you start."
                  actions={preview.eventCount > 0 && (
                    <Button variant="ghost" size="sm" icon={Eye} onClick={() => setShowEvents((v) => !v)}>
                      {showEvents ? 'Hide events' : 'Show events'}
                    </Button>
                  )}
                />

                <div className="sim-summary">
                  <div><span>Events</span><b>{preview.eventCount}</b></div>
                  <div><span>Scenario / noise</span><b>{preview.scenarioEventCount} / {preview.noiseEventCount}</b></div>
                  <div><span>Entities</span><b>{preview.targets.length}</b></div>
                  <div><span>At {config.eventRate}/s</span><b>{secs(preview.estimatedDurationMs)}</b></div>
                  <div><span>Duration cap</span><b>{preview.maxDurationMs === null ? '—' : secs(preview.maxDurationMs)}</b></div>
                </div>

                <div className="sim-facts">
                  <div>
                    <h3 className="drawer-h">Event types</h3>
                    {preview.eventTypes.length
                      ? <ul className="sim-list">{preview.eventTypes.map((x) => <li key={x.type}><span className="mono">{x.type}</span><b>{x.count}</b></li>)}</ul>
                      : <p className="muted">—</p>}
                  </div>
                  <div>
                    <h3 className="drawer-h">Entity distribution</h3>
                    {preview.distribution.length
                      ? <ul className="sim-list">{preview.distribution.map((d) => <li key={d.entityId}><span className="mono">{d.entityId}</span><b>{d.count}</b></li>)}</ul>
                      : <p className="muted">—</p>}
                  </div>
                </div>

                <div className="sim-validation">
                  {errors.length === 0 ? (
                    <p className="sim-ok"><CheckCircle2 size={14} /> {preview.eventCount} event{preview.eventCount === 1 ? '' : 's'} pass every backend contract check.</p>
                  ) : (
                    <ul className="sim-issues">
                      {errors.slice(0, 6).map((i, n) => <li key={n}><AlertTriangle size={14} /> {i.message}</li>)}
                      {errors.length > 6 && <li className="muted">+{errors.length - 6} more</li>}
                    </ul>
                  )}
                </div>

                {showEvents && preview.events.length > 0 && (
                  <div className="table-wrap scroll">
                    <table>
                      <thead><tr><th scope="col">#</th><th scope="col">Event ID</th><th scope="col">Type</th><th scope="col">Entity</th><th scope="col">Occurred</th></tr></thead>
                      <tbody>
                        {preview.events.slice(0, 40).map((e, i) => (
                          <tr key={e.eventId}>
                            <td className="muted">{i + 1}</td>
                            <td className="mono">{e.eventId}</td>
                            <td>{e.eventType}</td>
                            <td className="mono">{e.entityId}</td>
                            <td className="mono muted">{fmtTimeSec(e.occurredAt)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {preview.events.length > 40 && <p className="muted sim-note">Showing the first 40 of {preview.events.length} planned events.</p>}
                  </div>
                )}

                {(preview.notes.length > 0 || (scenario?.limitations.length ?? 0) > 0) && (
                  <div className="sim-notes">
                    <h3 className="drawer-h"><Info size={13} /> Planning notes and coverage gaps</h3>
                    <ul>
                      {preview.notes.map((n, i) => <li key={`n${i}`}>{n}</li>)}
                      {scenario?.limitations.map((n, i) => <li key={`l${i}`}>{n}</li>)}
                    </ul>
                  </div>
                )}

                {confirming ? (
                  <div className="sim-confirm">
                    <h3 className="drawer-h">Confirm this run</h3>
                    <dl className="sim-confirm-grid">
                      <div><dt>Scenario</dt><dd>{preview.label}</dd></div>
                      <div><dt>Targets</dt><dd>{preview.targets.join(', ') || '—'}</dd></div>
                      <div><dt>Rate</dt><dd>{config.eventRate}/s</dd></div>
                      <div><dt>Duration</dt><dd>{preview.maxDurationMs === null ? 'none' : secs(preview.maxDurationMs)}</dd></div>
                      <div><dt>Intensity</dt><dd>{config.intensity}</dd></div>
                      <div><dt>Noise</dt><dd>{config.noisePercent}% ({preview.noiseEventCount} events)</dd></div>
                      <div><dt>Pattern</dt><dd>{config.pattern}</dd></div>
                      <div><dt>Events</dt><dd>{preview.eventCount}{preview.plannedSends < preview.eventCount ? ` (about ${preview.plannedSends} before the cap)` : ''}</dd></div>
                      {demoMode && demo && <div><dt>Demo</dt><dd>{demo.name}</dd></div>}
                      <div className="wide"><dt>Detection</dt><dd>{scenario ? detectionSummary(scenario) : '—'}</dd></div>
                    </dl>
                    <div className="row-gap">
                      <Button variant="primary" icon={Play} onClick={() => start(preview)}>Confirm and start</Button>
                      <Button variant="ghost" onClick={() => setConfirming(false)}>Back</Button>
                    </div>
                  </div>
                ) : (
                  <div className="sim-actions">
                    <Button
                      variant="primary"
                      icon={Play}
                      block
                      disabled={!startable || active}
                      loading={active}
                      onClick={() => (mustConfirm ? setConfirming(true) : start(preview))}
                    >
                      {active ? 'Run in progress…' : mustConfirm ? `Review and start ${preview.eventCount} events` : `Start ${preview.eventCount} event${preview.eventCount === 1 ? '' : 's'}`}
                    </Button>
                    {!startable && <p className="hint">Fix the issues above to start.</p>}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </Card>
  );

  const liveBlock = hasRun ? (
    <div className="sim-live">
      <Card flush>
        <div className="card-section">
          <CardHead
            kicker="Live"
            kickerIcon={Activity}
            title="Event console"
            description={`Per-event transport and pipeline outcome. The newest ${LIVE_ROW_LIMIT} of at most ${LIVE_ROW_HARD_LIMIT} retained rows.`}
          />
          <div className="sim-filters">
            <Segmented value={filter} onChange={setFilter} options={FILTERS} />
            <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} aria-label="Filter by event type" className="sim-type-filter">
              <option value="ALL">All event types</option>
              {eventTypes.map((x) => <option key={x} value={x}>{x}</option>)}
            </select>
            <span className="muted sim-filter-count">{rows.length} of {live.rows.length} rows</span>
          </div>
        </div>
        {rows.length === 0 ? (
          <EmptyState title="No matching events" text="No retained row matches this filter." icon={ListChecks} />
        ) : (
          <EventConsole rows={rows} trimmed={t.trimmed} />
        )}
      </Card>

      <div className="sim-side">
        <Card>
          <CardHead kicker="Progress" kickerIcon={Gauge} title="Run progress" description="Generation is the engine's own position in the plan; processing is what the backend has told us." />
          <RunProgress snap={snap} live={live} plan={live.plan} />
        </Card>

        <Card style={{ marginTop: 12 }}>
          <CardHead kicker="Detection" kickerIcon={ShieldCheck} title="Detection summary" description="Only what a trail response actually reported." />
          <DetectionPanel live={live} snap={snap} />
        </Card>

        <Card style={{ marginTop: 12 }}>
          <CardHead kicker="Feed" kickerIcon={Activity} title="Recent activity" description={`The newest ${live.activity.length} entries.`} />
          <ActivityFeed entries={live.activity} />
        </Card>
      </div>
    </div>
  ) : null;

  const demoBlock = demoMode && (
    <>
      {/* The banner has to be literally true: a preset changes configuration, nothing else. */}
      <div className="sim-demo-banner" role="note">
        <GraduationCap size={15} />
        <span>
          <b>Demo Mode</b> changes presentation and presets only. It does not bypass validation, the
          preview, the confirmation step, the event rate limit or the run engine. Events are sent only
          after you explicitly press Start.
        </span>
      </div>

      <Card flush className="sim-demo-card">
        <div className="card-section">
          <CardHead
            kicker="Demonstrate"
            kickerIcon={GraduationCap}
            title="Demo presets"
            description="Curated walkthroughs built from the existing scenarios. Each one states what the current implementation should do — including where it detects nothing."
            actions={(
              <Button variant="ghost" size="sm" icon={ChevronDown} aria-expanded={demoOpen} onClick={() => setDemoOpen((v) => !v)}>
                {demoOpen ? 'Collapse' : 'Expand'}
              </Button>
            )}
          />
        </div>

        {demoOpen && (
          <>
            <div className="card-section">
              <div className="scenario-grid tight" role="radiogroup" aria-label="Demo preset">
                {DEMO_PRESETS.map((d) => (
                  <DemoCard key={d.id} d={d} on={d.id === demoId} events={d.expectation.expectedEvents} onPick={pickDemo} />
                ))}
              </div>
              <div className="sim-legend">
                <h3 className="drawer-h">Detection types</h3>
                <ul>
                  {DETECTION_LEGEND.map((l) => (
                    <li key={l.type}><DetectionChip type={l.type} /><span className="muted">{l.meaning}</span></li>
                  ))}
                </ul>
              </div>
            </div>

            {demo && (
              <div className="card-section">
                <div className="sim-demo-detail">
                  <div>
                    <CardHead kicker="Expected" kickerIcon={ListChecks} title={demo.name} description={demo.description} />
                    <p className="sim-note">{demo.expectation.statement}</p>
                    <ul className="sim-notes-list">{expectedLines(demo.expectation).map((l) => <li key={l}>{l}</li>)}</ul>
                    <div className="sim-notes">
                      <h3 className="drawer-h"><Info size={13} /> Limitations and coverage gaps</h3>
                      <ul>{presetLimitations(demo).map((l) => <li key={l}>{l}</li>)}</ul>
                    </div>
                  </div>
                  <div>
                    <CardHead kicker="Explain" kickerIcon={BookOpen} title="For the walkthrough" description="Short answers to the five questions a reviewer asks." />
                    <ExplainPanel d={demo} />
                    <CardHead kicker="Architecture" kickerIcon={Workflow} title="The path an event takes" description="Only components that exist in this codebase. The Simulator never calls the ML service directly." />
                    <ArchitectureFlow />
                  </div>
                </div>
              </div>
            )}

            <div className="card-section">
              <CardHead
                kicker="Presenter"
                kickerIcon={ListChecks}
                title="Walkthrough checklist"
                description="Informational only — ticking an item performs nothing. Ticks are kept for this session."
                actions={Object.values(checked).some(Boolean) && (
                  <Button variant="ghost" size="sm" onClick={() => setChecked({})}>Clear ticks</Button>
                )}
              />
              <ul className="sim-checklist">
                {DEMO_CHECKLIST.map((item, i) => (
                  <li key={item.id}>
                    <label className="sim-check">
                      <input
                        type="checkbox"
                        checked={Boolean(checked[item.id])}
                        onChange={() => setChecked((c) => ({ ...c, [item.id]: !c[item.id] }))}
                      />
                      <span><span className="muted mono">{i + 1}.</span> {item.label}</span>
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}
      </Card>
    </>
  );

  const assessmentBlock = finished && ranDemo && liveAssessment && (
    <Card className="sim-assess">
      <CardHead
        kicker="Evaluation"
        kickerIcon={GraduationCap}
        title={<span className="row-gap">{ranDemo.name} <DetectionChip type={ranDemo.detectionType} /></span>}
        description="What this demo said it would do, beside what the backend actually reported."
      />
      <Assessment a={liveAssessment} />
      <ExpectedVsObserved a={liveAssessment} />
      {t.peakScore !== null && (
        <p className="muted sim-note">
          Peak anomaly score {formatScore(t.peakScore)} — a percentile rank against the model&rsquo;s training
          distribution, not a probability. The alert policy raises an alert at {ALERT_THRESHOLD} and above.
        </p>
      )}
    </Card>
  );

  /*
   * Run History is a LOCAL record: it reads from localStorage and makes no request, so it stays
   * available (and openable) while a run is in progress, after a reset and after a hard refresh.
   */
  const historyBlock = (
    <Card flush className="sim-history-card-wrap">
      <div className="card-section">
        <CardHead
          kicker="Investigate"
          kickerIcon={History}
          title="Run history"
          description={`The last ${MAX_HISTORY_ENTRIES} finished runs, kept in this browser only. Opening one never touches the run in progress.`}
          actions={history.entries.length > 0 && (
            <Button variant="ghost" size="sm" icon={Trash2} onClick={() => setClearing(true)}>Clear history</Button>
          )}
        />
        {history.entries.length > 0 && (
          <div className="sim-filters">
            <Segmented value={historyFilter} onChange={setHistoryFilter} options={HISTORY_FILTERS} />
            <span className="muted sim-filter-count">{historyEntries.length} of {history.entries.length} runs</span>
          </div>
        )}
        {history.storageError && <p className="muted sim-note">{history.storageError}</p>}
      </div>

      {history.entries.length === 0 ? (
        <EmptyState
          title="No finished runs yet"
          text="A run is recorded here when it completes, is stopped, hits its duration cap or fails. Nothing is sent anywhere — the record stays in this browser."
          icon={History}
        />
      ) : historyEntries.length === 0 ? (
        <EmptyState title="No matching runs" text="No stored run matches this filter." icon={History} />
      ) : (
        <div className="card-section">
          <div className="sim-history-grid">
            {historyEntries.map((e) => <HistoryCard key={e.runId} e={e} onOpen={setOpenRunId} />)}
          </div>
        </div>
      )}
    </Card>
  );

  return (
    <>
      <PageHeader
        eyebrow="Workspace"
        title="Simulator"
        description="Replay realistic behaviour through the real pipeline — REST → PostgreSQL → Kafka → ML ensemble → alert policy → incident. Nothing is faked: every result below comes from the live backend."
        actions={(
          <div className="row-gap">
            <Button
              variant={demoMode ? 'primary' : 'secondary'}
              icon={GraduationCap}
              aria-pressed={demoMode}
              onClick={toggleDemoMode}
            >
              Demo Mode{demoMode ? ': on' : ''}
            </Button>
            <LinkButton to="/events/new" icon={FlaskConical}>Custom event</LinkButton>
          </div>
        )}
      />
      {demoBlock}

      {/* ---------------------------------------------------------------- 1. live run header */}
      <Card className="sim-header">
        <div className="sim-run">
          <span className={`sim-state${snap.state === 'RUNNING' ? ' live' : ''}`} role="status" aria-live="polite">
            <Badge tone={STATE_TONE[snap.state]} dot>
              {snap.state === 'RUNNING' ? 'LIVE · RUNNING' : snap.state === 'STOPPED' && snap.stopReason === 'DURATION' ? 'STOPPED (duration)' : snap.state}
            </Badge>
          </span>
          <span className="mono muted" title="Run ID (the event-ID prefix of this run)">{snap.runId ?? preview.runId}</span>
          <span className="sim-run-stats">
            <Elapsed snap={snap} />
            {configuredDuration !== null && <> / {secs(configuredDuration)}</>}
            {' · '}
            {snap.state === 'IDLE'
              ? `${preview.eventCount} event${preview.eventCount === 1 ? '' : 's'} planned at ${config.eventRate}/s`
              : `${snap.generated}/${snap.totalEvents} submitted · ${snap.eventRate}/s configured · ${rate(live.actualRate)}/s actual`}
          </span>
          {snap.state === 'RUNNING' && <Button variant="secondary" size="sm" icon={Pause} onClick={command(() => runEngine.pause())}>Pause run</Button>}
          {snap.state === 'PAUSED' && <Button variant="secondary" size="sm" icon={Play} onClick={command(() => runEngine.resume())}>Resume run</Button>}
          {(snap.state === 'RUNNING' || snap.state === 'PAUSED') && <Button variant="danger" size="sm" icon={Square} onClick={command(() => runEngine.stop())}>Stop run</Button>}
          {finished && <Button variant="primary" size="sm" icon={Play} onClick={runAgain} disabled={!startable}>Run again</Button>}
          {(finished || (snap.state === 'IDLE' && hasRun)) && <Button variant="secondary" size="sm" icon={RotateCcw} onClick={resetAll}>Reset console</Button>}
        </div>
        {snap.state === 'FAILED' && snap.failureReason && <p className="field-error sim-note">{snap.failureReason}</p>}
      </Card>

      {/* ---------------------------------------------------------------- 2. KPI strip */}
      {hasRun && (
        <div className="sim-kpis">
          <Kpi label="Generated" value={String(snap.generated)} hint={`of ${snap.totalEvents} planned`} />
          <Kpi label="Accepted" value={String(snap.accepted)} hint="HTTP 2xx" tone="ok" />
          <Kpi label="Failed" value={String(snap.failed)} hint="transport or rejected" tone={snap.failed ? 'critical' : undefined} />
          <Kpi label="Events/sec" value={rate(live.actualRate)} hint={`actual · ${snap.eventRate}/s configured`} />
          <Kpi label="Processed" value={String(t.processed)} hint={`of ${snap.accepted} accepted · ${t.observed} observed`} />
          <Kpi label="Alerts" value={String(t.alerts)} hint="observed on trails" tone={t.alerts ? 'high' : undefined} />
          <Kpi label="Incidents" value={String(t.incidents)} hint="observed on trails" tone={t.incidents ? 'critical' : undefined} />
          <Kpi label="Peak score" value={t.peakScore === null ? '—' : t.peakScore.toFixed(3)} hint={t.peakScore === null ? 'not observed' : 'highest observed'} />
        </div>
      )}

      {/* ------------------------------------------------- state-led ordering (14) */}
      {!available.length && !entities.isLoading ? (
        <Card style={{ marginTop: 12 }}>
          <EmptyState
            title="Create an entity first"
            text="Events must belong to a monitored entity. An administrator can add one from the Entities page."
            action={<LinkButton to="/entities" variant="primary" size="sm">Go to entities</LinkButton>}
          />
        </Card>
      ) : finished && summary ? (
        <>
          <CompletionCard s={summary} onRunAgain={runAgain} onReset={resetAll} busy={!startable} />
          {assessmentBlock}
          {liveBlock}
          {historyBlock}
          {configBlock}
        </>
      ) : active ? (
        <>
          {liveBlock}
          {configBlock}
          {historyBlock}
        </>
      ) : (
        <>
          {configBlock}
          {liveBlock}
          {historyBlock}
        </>
      )}

      {/* ------------------------------------------------ investigation (never replaces live state) */}
      <Drawer
        open={Boolean(openEntry)}
        onClose={() => setOpenRunId(null)}
        title={openEntry ? openEntry.scenarioName : 'Run'}
        subtitle={openEntry ? <span className="mono">{openEntry.runId}</span> : undefined}
      >
        {openEntry && (
          <HistoryDetail e={openEntry} onRunAgain={loadFromHistory} onDelete={setDeleting} runActive={active} />
        )}
      </Drawer>

      <Modal
        open={Boolean(deleting)}
        onClose={() => setDeleting(null)}
        title="Delete this history entry?"
        description="This only removes the local record of the run. The events it submitted, and any alerts or incidents they raised, stay in the backend."
      >
        <p className="mono muted">{deleting?.runId}</p>
        <div className="row-gap" style={{ marginTop: 12, justifyContent: 'flex-end' }}>
          <Button variant="ghost" onClick={() => setDeleting(null)}>Cancel</Button>
          <Button variant="danger" icon={Trash2} onClick={confirmDelete}>Delete entry</Button>
        </div>
      </Modal>

      <Modal
        open={clearing}
        onClose={() => setClearing(false)}
        title="Clear run history?"
        description="This only clears local Simulator history. It does not affect the run in progress, the events already submitted, or anything stored in the backend."
      >
        <p className="muted">{history.entries.length} stored run{history.entries.length === 1 ? '' : 's'} will be removed from this browser.</p>
        <div className="row-gap" style={{ marginTop: 12, justifyContent: 'flex-end' }}>
          <Button variant="ghost" onClick={() => setClearing(false)}>Cancel</Button>
          <Button variant="danger" icon={Trash2} onClick={confirmClear}>Clear history</Button>
        </div>
      </Modal>
    </>
  );
}
