import { CheckCircle2 } from 'lucide-react';

import { Button } from './ui';
import { humanize } from '../utils/format';
import { STATUS_ACTIONS } from '../utils/workflow';

/** Horizontal lifecycle indicator: done / current / upcoming. */
export function LifecycleStepper({ steps, current }: { steps: readonly string[]; current: string }) {
  // A status outside the happy path (e.g. FALSE_POSITIVE) is shown as a terminal marker instead.
  const idx = steps.indexOf(current);
  return (
    <div className="stepper" aria-label="Lifecycle">
      {steps.map((s, i) => {
        const cls = idx === -1 ? '' : i < idx ? 'done' : i === idx ? 'current' : '';
        return (
          <div key={s} style={{ display: 'contents' }}>
            <span className={`step ${cls}`}>
              {cls === 'done' ? <CheckCircle2 size={14} color="var(--c-ok)" /> : <i className="step-dot" />}
              {humanize(s)}
            </span>
            {i < steps.length - 1 && <span className={`step-line${idx !== -1 && i < idx ? ' done' : ''}`} />}
          </div>
        );
      })}
    </div>
  );
}

/** One button per legal next status. Renders nothing actionable for terminal states. */
export function TransitionButtons({
  options,
  pending,
  onPick,
}: {
  options: string[];
  pending: string | null;
  onPick: (status: string) => void;
}) {
  if (!options.length) {
    return <p className="muted" style={{ fontSize: 13 }}>This is a terminal status — no further transitions are allowed.</p>;
  }
  return (
    <div className="row-gap">
      {options.map((s) => {
        const a = STATUS_ACTIONS[s] ?? { label: humanize(s), variant: 'secondary' as const };
        return (
          <Button key={s} variant={a.variant} loading={pending === s} disabled={!!pending} onClick={() => onPick(s)}>
            {a.label}
          </Button>
        );
      })}
    </div>
  );
}
