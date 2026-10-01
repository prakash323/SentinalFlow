import { useEffect, useRef, useState } from 'react';

import { useReducedMotion } from '../../../hooks/useReducedMotion';

const easeOut = (t: number) => 1 - Math.pow(1 - t, 3);

/**
 * Counts from 0 to `to` once, the first time it is visible (one short rAF run, then it stops).
 * Tabular figures keep the width steady. Shows the final value immediately under reduced motion or
 * when IntersectionObserver is unavailable. Screen readers get the final value only.
 */
export default function CountUp({
  to,
  duration = 1300,
  decimals = 0,
  prefix = '',
  suffix = '',
  className = '',
}: {
  to: number;
  duration?: number;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const ref = useRef<HTMLSpanElement>(null);
  const instant = reduced || typeof IntersectionObserver === 'undefined' || document.hidden;
  const [value, setValue] = useState(instant ? to : 0);

  useEffect(() => {
    if (instant) {
      setValue(to);
      return;
    }
    const el = ref.current;
    if (!el) return;
    let raf = 0;
    const io = new IntersectionObserver(
      (entries) => {
        if (!entries.some((e) => e.isIntersecting)) return;
        io.disconnect();
        const t0 = performance.now();
        const tick = (now: number) => {
          const p = Math.min(1, (now - t0) / duration);
          setValue(to * easeOut(p));
          if (p < 1) raf = requestAnimationFrame(tick);
        };
        raf = requestAnimationFrame(tick);
      },
      { threshold: 0.4 },
    );
    io.observe(el);
    return () => {
      io.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [instant, to, duration]);

  const fmt = (n: number) => `${prefix}${n.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}${suffix}`;

  return (
    <span ref={ref} className={`sf-count ${className}`.trim()}>
      <span aria-hidden="true">{fmt(value)}</span>
      <span className="sr-only">{fmt(to)}</span>
    </span>
  );
}
