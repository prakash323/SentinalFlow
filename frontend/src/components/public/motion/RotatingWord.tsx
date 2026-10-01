import { useEffect, useState } from 'react';

import { useReducedMotion } from '../../../hooks/useReducedMotion';
import { useOnScreen, usePageVisible } from '../../../hooks/useSceneActive';

/**
 * The changing word in the hero headline. All words sit in ONE grid cell, so the box is always as
 * wide/tall as the longest word: nothing around it moves. Only the highlighted word fades and slides.
 * It rotates only while it is on screen and the tab is visible; under reduced motion it stays on the
 * first word. Purely decorative (aria-hidden): the headline carries a static sentence for assistive tech.
 */
export default function RotatingWord({ words, interval = 2600 }: { words: readonly string[]; interval?: number }) {
  const reduced = useReducedMotion();
  const visible = usePageVisible();
  const [ref, onScreen] = useOnScreen<HTMLSpanElement>();
  const [i, setI] = useState(0);
  const n = words.length;

  useEffect(() => {
    if (reduced || !visible || !onScreen || n < 2) return;
    const t = window.setInterval(() => setI((x) => (x + 1) % n), interval);
    return () => window.clearInterval(t);
  }, [reduced, visible, onScreen, n, interval]);

  return (
    <span ref={ref} className="sf-rotor" aria-hidden="true">
      {words.map((w, k) => (
        <span key={w} className={k === i ? 'is-active' : k === (i - 1 + n) % n ? 'is-past' : undefined}>
          {w}
        </span>
      ))}
    </span>
  );
}
