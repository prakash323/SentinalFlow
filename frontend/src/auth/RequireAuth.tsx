import { Navigate, useLocation } from 'react-router-dom';

import AppShell from '../layouts/AppShell';
import { useAuth } from './AuthContext';
import { justSignedOut } from './signOutSignal';

/**
 * Route guard for the whole authenticated application.
 *
 * Signed out (session expired / 401, or a direct visit) -> /login, remembering where the
 * user was going so they land there after signing in.
 * Signed out on purpose (Sign out button) -> the public home page, and nothing is remembered,
 * so the next person to sign in does not inherit this user's last page.
 * Signed in -> the SOC shell, which renders the matched child route.
 *
 * This only reads AuthContext; it does not change how credentials, sessions,
 * 401 handling or roles work. Admin-only pages are still guarded by AdminOnly
 * (and, authoritatively, by the API).
 */
export default function RequireAuth() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    if (justSignedOut()) return <Navigate to="/" replace />;
    return <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}` }} />;
  }
  return <AppShell />;
}

/** Where to send a user after a successful sign-in: the page they asked for, else the dashboard. */
export function postLoginTarget(state: unknown): string {
  const from = (state as { from?: unknown } | null)?.from;
  // in-app absolute paths only: never protocol-relative (//host) or back to /login itself
  if (typeof from === 'string' && from.startsWith('/') && !from.startsWith('//') && !from.startsWith('/login')) {
    return from;
  }
  return '/dashboard';
}
