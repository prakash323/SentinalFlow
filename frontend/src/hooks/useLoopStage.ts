import { useCallback, useEffect, useState } from 'react';

/**
 * A small timeline: stage 0 → 1 → … → n-1 → 0, each stage lasting `durations[stage]` ms.
 * One setTimeout at a time (no rAF, no interval); it stops while `running` is false, so a scene that is
 * off screen, in a hidden tab, paused by the user or under reduced motion costs nothing.
 */
export function useLoopStage(durations: readonly number[], running: boolean, initial = 0) {
  const [stage, setStage] = useState(initial);

  useEffect(() => {
    if (!running) return;
    const t = window.setTimeout(() => setStage((s) => (s + 1) % durations.length), durations[stage]);
    return () => window.clearTimeout(t);
  }, [stage, running, durations]);

  const goTo = useCallback((s: number) => setStage(s), []);
  return { stage, goTo };
}
