import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

export type Theme = 'dark' | 'light';
/** What the user chose. 'system' follows the OS setting, live. */
export type ThemePreference = Theme | 'system';

const KEY = 'sentinelflow.theme';
const LIGHT_QUERY = '(prefers-color-scheme: light)';

const osTheme = (): Theme => (window.matchMedia?.(LIGHT_QUERY).matches ? 'light' : 'dark');

// index.html applies the same rule before first paint: anything other than
// 'dark'/'light' (including 'system' or nothing stored) follows the OS.
function initialPreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(KEY);
    if (stored === 'dark' || stored === 'light' || stored === 'system') return stored;
  } catch {
    // storage unavailable - fall through to the OS preference
  }
  return 'system';
}

type ThemeContextValue = {
  /** The theme actually applied. */
  theme: Theme;
  preference: ThemePreference;
  /** Switches to the opposite explicit theme. */
  toggle: () => void;
  setTheme: (t: Theme) => void;
  setPreference: (p: ThemePreference) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(initialPreference);
  const [system, setSystem] = useState<Theme>(osTheme);

  useEffect(() => {
    const mq = window.matchMedia?.(LIGHT_QUERY);
    if (!mq) return;
    const onChange = () => setSystem(mq.matches ? 'light' : 'dark');
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const theme: Theme = preference === 'system' ? system : preference;

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    // browser chrome (mobile address bar) follows the page background token
    const bg = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim();
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', bg || (theme === 'dark' ? '#0b0d10' : '#f5f5f7'));
  }, [theme]);

  useEffect(() => {
    try {
      localStorage.setItem(KEY, preference);
    } catch {
      // ignore - the theme still applies for this page load
    }
  }, [preference]);

  const setPreference = useCallback((p: ThemePreference) => setPreferenceState(p), []);
  const setTheme = useCallback((t: Theme) => setPreferenceState(t), []);
  const toggle = useCallback(() => setPreferenceState(theme === 'dark' ? 'light' : 'dark'), [theme]);
  const value = useMemo(
    () => ({ theme, preference, toggle, setTheme, setPreference }),
    [theme, preference, toggle, setTheme, setPreference],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used inside ThemeProvider');
  return ctx;
}
