import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { clearAuthCredentials, setAuthCredentials, setUnauthorizedHandler } from '../api/client';
import { authApi } from '../api/endpoints';
import type { Me } from '../types/domain';

// HTTP Basic auth against the Spring Boot API. Credentials are validated by
// calling the real GET /api/v1/auth/me (which also returns the caller's
// roles) - nothing is checked against a hard-coded value here. sessionStorage
// (not localStorage) keeps credentials from outliving the browser tab.
type Session = { username: string; password: string; me: Me };

const STORAGE_KEY = 'sentinelflow.session';

function readStoredSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (typeof parsed?.username === 'string' && typeof parsed?.password === 'string' && parsed?.me?.username) {
      return parsed as Session;
    }
    return null;
  } catch {
    return null;
  }
}

// Applied at module scope so a request fired before the first render
// already carries the stored credentials instead of racing an effect.
const initialSession = readStoredSession();
if (initialSession) {
  setAuthCredentials(initialSession.username, initialSession.password);
}

type AuthContextValue = {
  username: string | null;
  roles: string[];
  isAdmin: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(initialSession);
  const queryClient = useQueryClient();

  const logout = useCallback(() => {
    clearAuthCredentials();
    setSession(null);
    // Never leave one user's cached data around for the next login.
    queryClient.clear();
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      // in-memory credentials are already cleared, which is what matters
    }
  }, [queryClient]);

  // A 401 on an established session (rotated/revoked credentials) returns to login.
  useEffect(() => {
    setUnauthorizedHandler(logout);
  }, [logout]);

  const login = useCallback(async (username: string, password: string) => {
    setAuthCredentials(username, password);

    let me: Me;
    try {
      me = await authApi.me();
    } catch (error) {
      clearAuthCredentials();
      throw error;
    }

    const next: Session = { username, password, me };
    setSession(next);

    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // non-fatal: works for this page load, just won't survive a reload
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      username: session?.me.username ?? null,
      roles: session?.me.roles ?? [],
      isAdmin: !!session?.me.admin,
      isAuthenticated: !!session,
      login,
      logout,
    }),
    [session, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
