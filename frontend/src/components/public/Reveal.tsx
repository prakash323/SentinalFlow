import { useEffect, useRef, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';

export type RevealVariant = 'up' | 'fade' | 'scale' | 'left' | 'right' | 'scope';

/**
 * Marks a block as an animation scene. The first time it scrolls into view it gets `.is-in`; CSS
 * (motion.css) owns everything that happens next, and switches it off under prefers-reduced-motion.
 *
 * - `variant` chooses how the block itself enters. `scope` keeps the block still and only lets its
 *   descendants (`.sf-in`, `.sf-stagger`, `.sf-draw` ...) animate.
 * - `delay` (ms) staggers sibling blocks. It is dropped once the block has settled so hover
 *   transitions on the same element are never delayed.
 *
 * Content is shown immediately (never left invisible) when IntersectionObserver is missing or the
 * page is loaded in a hidden tab, where the browser does not deliver observer callbacks.
 */
export default function Reveal({
  children,
  className = '',
  delay = 0,
  variant = 'up',
  threshold = 0.06,
}: {
  children: ReactNode;
  className?: string;
  /** ms, for staggering siblings */
  delay?: number;
  variant?: RevealVariant;
  /** share of the block that must be visible before it plays */
  threshold?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(() => typeof IntersectionObserver === 'undefined' || document.hidden);
  const [settled, setSettled] = useState(false);

  useEffect(() => {
    if (shown) return;
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setShown(true);
          io.disconnect();
        }
      },
      { rootMargin: '0px 0px -6% 0px', threshold },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [shown, threshold]);

  useEffect(() => {
    if (!shown || !delay) return;
    const t = window.setTimeout(() => setSettled(true), delay + 1000);
    return () => window.clearTimeout(t);
  }, [shown, delay]);

  const style = delay && !settled ? ({ ['--sf-delay' as string]: `${delay}ms` } as CSSProperties) : undefined;

  return (
    <div
      ref={ref}
      className={`pub-reveal sf-reveal${shown ? ' is-in' : ''}${className ? ` ${className}` : ''}`}
      data-variant={variant === 'up' ? undefined : variant}
      style={style}
    >
      {children}
    </div>
  );
}
