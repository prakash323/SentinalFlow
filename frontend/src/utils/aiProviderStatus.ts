import { useCallback, useSyncExternalStore } from 'react';
import { useQueryClient } from '@tanstack/react-query';

/**
 * Shared key for the incident AI mutations (explanation / evidence-summary /
 * investigation). IncidentDetail tags its mutation with this so other screens
 * can see how the most recent AI request ended.
 */
export const AI_MUTATION_KEY = ['incident-ai'] as const;

export type AiProviderState =
  | { state: 'on-demand' }
  | { state: 'unavailable'; at: number };

/**
 * NOT a health probe. There is no backend endpoint that checks the AI provider;
 * the only signal is the outcome of an AI request a user actually made. This
 * reports "unavailable" when the most recent AI request in this session failed
 * with HTTP 503, and "on-demand" otherwise (including when no AI request has been
 * made, or once React Query has discarded the finished request from its cache).
 *
 * Uses useSyncExternalStore with a primitive snapshot on purpose: the mutation
 * cache also emits events while *other* components render (creating a
 * mutation observer notifies it), and a plain setState in a subscription
 * would then update this component mid-render of another one. With a snapshot,
 * React re-renders only when the value actually changes.
 */
export function useAiProviderState(): AiProviderState {
  const queryClient = useQueryClient();

  const subscribe = useCallback(
    (onChange: () => void) => queryClient.getMutationCache().subscribe(onChange),
    [queryClient],
  );

  // '' = on demand; otherwise the timestamp of the most recent AI request, which ended in a 503.
  const getSnapshot = useCallback(() => {
    const last = queryClient
      .getMutationCache()
      .findAll({ mutationKey: AI_MUTATION_KEY })
      .filter((m) => m.state.status === 'success' || m.state.status === 'error')
      .sort((a, b) => b.state.submittedAt - a.state.submittedAt)[0];
    const unavailable =
      !!last && last.state.status === 'error' && (last.state.error as { status?: number } | null)?.status === 503;
    return unavailable ? String(last.state.submittedAt) : '';
  }, [queryClient]);

  const at = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  return at ? { state: 'unavailable', at: Number(at) } : { state: 'on-demand' };
}
