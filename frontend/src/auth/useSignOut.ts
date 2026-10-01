import { useCallback } from 'react';

import { useAuth } from './AuthContext';
import { noteDeliberateSignOut } from './signOutSignal';

/**
 * Deliberate sign-out: clear the session (AuthContext.logout, unchanged) and
 * land on the public home page. RequireAuth performs that redirect: it is the
 * component that reacts to the session ending, and it must know this one was
 * on purpose. A session that ends on its own (401) has no such marker, so it
 * goes to /login and remembers the page.
 */
export function useSignOut() {
  const { logout } = useAuth();
  return useCallback(() => {
    noteDeliberateSignOut();
    logout();
  }, [logout]);
}
