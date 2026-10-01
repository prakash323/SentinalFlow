import { useEffect, useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { RefreshCw, Sparkles } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import type { AiDetail } from '../types/domain';
import { AI_MUTATION_KEY } from '../utils/aiProviderStatus';
import { fmtDate, formatApiError } from '../utils/format';
import { Button, Card, CardHead, RichText, Skeleton } from './ui';

export type AiAction = { id: string; label: string; /** heading of the result block; defaults to the button label */ resultLabel?: string; icon?: LucideIcon };
export type AiResult = { content: string; model: string; generatedAt: string };

type Props = {
  /** Card title, e.g. "AI explanation". */
  title: string;
  /** One line that says what this is and that it cannot change anything. */
  description: string;
  /** Footer text naming the evidence the answer is based on, e.g. "Based on ML evidence". */
  basis: string;
  /** Shown in place of the provider error when the AI service is down. */
  unavailableText: string;
  actions: AiAction[];
  /** Performs the request. Read-only: it must only call the AI endpoints. */
  request: (action: string, detail: AiDetail) => Promise<AiResult>;
  /** Changes when the alert/incident changes, so an answer about the old state is never kept. */
  resetKey: string;
};

const key = (action: string, detail: AiDetail) => `${action}:${detail}`;

// The provider being down or unreachable (503 from the API, a gateway error, or no response at all).
const providerDown = (e: unknown) => {
  const s = (e as { status?: number } | null)?.status;
  return s === undefined || s === 502 || s === 503 || s === 504;
};

/**
 * Compact analyst-assistance panel. The concise answer is always the default; "Show detailed
 * analysis" asks the same endpoint for the longer form and is never required. Nothing here writes
 * to the alert or incident, and a failed request only changes this panel.
 */
export function AiAssist({ title, description, basis, unavailableText, actions, request, resetKey }: Props) {
  const [active, setActive] = useState<{ action: string; detail: AiDetail } | null>(null);
  const [cache, setCache] = useState<Record<string, AiResult>>({});
  // bumped whenever the subject changes; a response that started before that is dropped
  const generation = useRef(0);

  const run = useMutation({
    mutationKey: AI_MUTATION_KEY,
    mutationFn: (v: { action: string; detail: AiDetail; gen: number }) => request(v.action, v.detail),
    onMutate: (v) => setActive({ action: v.action, detail: v.detail }),
    onSuccess: (data, v) => {
      if (v.gen === generation.current) setCache((c) => ({ ...c, [key(v.action, v.detail)]: data }));
    },
  });
  const { reset } = run;

  useEffect(() => {
    generation.current += 1;
    setCache({});
    setActive(null);
    reset();
  }, [resetKey, reset]);

  const start = (action: string, detail: AiDetail, force = false) => {
    if (!force && cache[key(action, detail)]) {
      reset();
      setActive({ action, detail });
      return;
    }
    run.mutate({ action, detail, gen: generation.current });
  };

  const pending = run.isPending;
  const shown = active && !pending && !run.isError ? cache[key(active.action, active.detail)] : undefined;
  const activeAction = actions.find((a) => a.id === active?.action);
  const activeLabel = activeAction?.resultLabel ?? activeAction?.label;

  return (
    <Card className="ai-assist">
      <CardHead
        kicker="Analyst assistance"
        kickerIcon={Sparkles}
        title={title}
        description={description}
        actions={actions.map((a, i) => (
          <Button
            key={a.id}
            size="sm"
            variant={!active && i === 0 ? 'primary' : 'secondary'}
            icon={a.icon}
            disabled={pending}
            onClick={() => start(a.id, 'concise')}
          >
            {a.label}
          </Button>
        ))}
      />

      <div className="ai-body" aria-live="polite">
        {pending && (
          <div className="ai-lines" role="status" aria-busy="true" aria-label="Generating">
            <Skeleton h={13} w="92%" />
            <Skeleton h={13} w="78%" />
            {active?.detail === 'detailed' && <><Skeleton h={13} w="86%" /><Skeleton h={13} w="64%" /></>}
          </div>
        )}

        {run.isError && !pending && (
          <div className="form-error" role="alert">
            {providerDown(run.error) ? unavailableText : formatApiError(run.error, 'AI analyst assistance is unavailable right now.')}
            {active && (
              <>
                {' '}
                <button type="button" className="link inline" onClick={() => start(active.action, active.detail, true)}>Try again</button>
              </>
            )}
          </div>
        )}

        {shown && active && (
          <>
            <div className="ai-result">
              {actions.length > 1 && <div className="ai-result-label">{activeLabel}{active.detail === 'detailed' ? ' · detailed' : ''}</div>}
              <RichText text={shown.content} />
            </div>
            <div className="ai-foot">
              <span className="ai-tag">AI-generated</span>
              <span>{basis}</span>
              <span className="mono" title="Model">{shown.model}</span>
              <span>{fmtDate(shown.generatedAt)}</span>
              <span className="spacer" />
              <Button
                variant="ghost"
                size="sm"
                onClick={() => start(active.action, active.detail === 'detailed' ? 'concise' : 'detailed')}
              >
                {active.detail === 'detailed' ? 'Show concise' : 'Show detailed analysis'}
              </Button>
              <Button variant="ghost" size="sm" icon={RefreshCw} onClick={() => start(active.action, active.detail, true)}>
                Regenerate
              </Button>
            </div>
          </>
        )}
      </div>
    </Card>
  );
}
