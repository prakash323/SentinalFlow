import { useSyncExternalStore } from 'react';

import { eventsApi } from '../api/endpoints';
import { SimulationEngine } from './engine';

/**
 * One engine for the whole app. It lives at module scope, not in the page, so a run keeps going -
 * and is picked up again - when the user navigates away from the Simulator and back, and there can
 * never be two send loops.
 */
export const runEngine = new SimulationEngine({ send: (event) => eventsApi.create(event) });

export const useRunSnapshot = () => useSyncExternalStore(runEngine.subscribe, runEngine.getSnapshot);
