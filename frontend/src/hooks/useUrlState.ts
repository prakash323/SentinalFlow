import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';

/**
 * Filter/pagination state that lives in the URL, so a filtered view can be
 * bookmarked, shared and survives a reload / back-navigation.
 *
 * Changing any filter (anything except `page`) resets `page` to 0.
 */
export function useUrlState<T extends Record<string, string>>(defaults: T) {
  const [params, setParams] = useSearchParams();

  const state = { ...defaults } as T & { page: number };
  (Object.keys(defaults) as (keyof T)[]).forEach((k) => {
    const v = params.get(k as string);
    if (v !== null) (state as Record<string, unknown>)[k as string] = v;
  });
  state.page = Math.max(0, Number(params.get('page') || 0) || 0);

  const set = useCallback(
    (patch: Partial<T> & { page?: number }) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          const touchesFilter = Object.keys(patch).some((k) => k !== 'page');
          Object.entries(patch).forEach(([k, v]) => {
            if (v === undefined || v === '' || v === null || (k === 'page' && Number(v) === 0)) next.delete(k);
            else next.set(k, String(v));
          });
          if (touchesFilter && !('page' in patch)) next.delete('page');
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  const reset = useCallback(() => setParams({}, { replace: true }), [setParams]);

  const activeCount = (Object.keys(defaults) as (keyof T)[]).filter((k) => state[k] !== defaults[k]).length;

  return { state, set, reset, activeCount };
}
