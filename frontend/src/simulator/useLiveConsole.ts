import { useSyncExternalStore } from 'react';

import { eventsApi, incidentsApi } from '../api/endpoints';
import { LiveConsole } from './liveConsole';

/**
 * One console for the whole app, next to the one engine in useRunEngine.ts and for the same reason:
 * a run keeps going when the user navigates away from the Simulator, so its observations must too,
 * and there can never be two polling loops.
 *
 * Only reads are wired here. The console never submits an event - that is the engine's job alone.
 */
export const liveConsole = new LiveConsole({
  fetchTrail: (eventId) => eventsApi.trail(eventId),
  fetchIncident: (incidentId) => incidentsApi.get(incidentId),
});

export const useLiveSnapshot = () => useSyncExternalStore(liveConsole.subscribe, liveConsole.getSnapshot);
