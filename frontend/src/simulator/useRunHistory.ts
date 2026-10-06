import { useSyncExternalStore } from 'react';

import { RunHistoryStore } from './runHistory';
import type { StorageLike } from './runHistory';

/**
 * localStorage, or null where the browser denies it. Touching `window.localStorage` can itself throw
 * (Safari private mode, a blocked third-party context), so even reaching for it is guarded - the
 * store then runs in memory and says so instead of breaking the Simulator.
 */
function browserStorage(): StorageLike | null {
  try {
    const s = globalThis.localStorage;
    return s ? s : null;
  } catch {
    return null;
  }
}

/**
 * One history store for the whole app, alongside the one engine and the one live console. It is
 * read-only as far as the backend is concerned: nothing in this module or its store makes a request.
 */
export const runHistory = new RunHistoryStore(browserStorage());

export const useRunHistory = () => useSyncExternalStore(runHistory.subscribe, runHistory.getSnapshot);
