import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import type { RefObject } from 'react';

function subscribeVisibility(onChange: () => void) {
  document.addEventListener('visibilitychange', onChange);
  return () => document.removeEventListener('visibilitychange', onChange);
}

/** True while the browser tab is visible. Timers that only matter on screen should stop when it is not. */
export function usePageVisible(): boolean {
  return useSyncExternalStore(
    subscribeVisibility,
    () => !document.hidden,
    () => true,
  );
}

/**
 * Live (not one-shot) "is this element on screen" flag. Falls back to `true` when IntersectionObserver
 * is missing, so nothing is ever left frozen.
 */
export function useOnScreen<T extends Element>(rootMargin = '0px'): [RefObject<T | null>, boolean] {
  const ref = useRef<T>(null);
  const [on, setOn] = useState(() => typeof IntersectionObserver === 'undefined');

  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver === 'undefined') return;
    const io = new IntersectionObserver((entries) => setOn(entries.some((e) => e.isIntersecting)), { rootMargin, threshold: 0.15 });
    io.observe(el);
    return () => io.disconnect();
  }, [rootMargin]);

  return [ref, on];
}
