import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useIsFetching, useQuery, useQueryClient } from '@tanstack/react-query';
import { MotionConfig } from 'motion/react';
import { ChevronsLeft, ChevronsRight, LogOut, Menu, Monitor, Moon, RefreshCw, Search, ShieldCheck, Sun } from 'lucide-react';

import { dashboardApi, systemApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { useSignOut } from '../auth/useSignOut';
import { IconButton } from '../components/ui';
import { useTheme } from '../hooks/useTheme';
import type { ThemePreference } from '../hooks/useTheme';
import type { Incident } from '../types/domain';
import { initials } from '../utils/format';
import { NAV_GROUPS, navItemFor } from './nav';
import CommandPalette from './CommandPalette';

const COLLAPSE_KEY = 'sentinelflow.sidebar.collapsed';
// Between the mobile drawer and full desktop the sidebar is always the 56px rail.
const RAIL_QUERY = '(min-width: 861px) and (max-width: 1100px)';

function statusMeta(overall?: string) {
  if (overall === 'UP') return { cls: '', short: 'Operational', text: 'All systems operational' };
  if (overall === 'DEGRADED') return { cls: 'warn', short: 'Degraded', text: 'Degraded — check System Status' };
  if (overall === 'DOWN') return { cls: 'down', short: 'Unavailable', text: 'Backend unavailable' };
  return { cls: 'idle', short: 'Checking…', text: 'Checking status…' };
}

const THEME_OPTIONS: { value: ThemePreference; label: string; icon: typeof Sun }[] = [
  { value: 'light', label: 'Light theme', icon: Sun },
  { value: 'dark', label: 'Dark theme', icon: Moon },
  { value: 'system', label: 'Match system theme', icon: Monitor },
];

function ThemeSwitch() {
  const { preference, setPreference } = useTheme();
  return (
    <div className="theme-switch" role="group" aria-label="Theme">
      {THEME_OPTIONS.map(({ value, label, icon: Icon }) => (
        <button key={value} type="button" aria-pressed={preference === value} aria-label={label} title={label} onClick={() => setPreference(value)}>
          <Icon size={13} />
        </button>
      ))}
    </div>
  );
}

const safeDecode = (s: string) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

// Alert and incident URLs carry a UUID; show a short form rather than 36 characters.
const shortId = (s: string) => (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(s) ? s.slice(0, 8) : s);

/**
 * `SentinelFlow / Monitor / Alerts` on a list page, and
 * `SentinelFlow / Incidents / INC-USER-001-LOGIN` on a detail page.
 */
function Breadcrumb({ pathname }: { pathname: string }) {
  const item = navItemFor(pathname);
  const segs = pathname.split('/').filter(Boolean);
  const detail = segs[1] ? safeDecode(segs[1]) : undefined;

  // Incident detail is addressed by UUID; borrow the human key from the page's own
  // cached query. This only *reads* the cache (and re-renders when that entry
  // changes): it never creates a query or a request, so it cannot affect the page's data.
  const queryClient = useQueryClient();
  const incidentId = segs[0] === 'incidents' ? segs[1] : undefined;
  const [, bump] = useState(0);
  useEffect(() => {
    if (!incidentId) return;
    return queryClient.getQueryCache().subscribe((event) => {
      const key = event.query.queryKey;
      if (key[0] === 'incident' && key[1] === incidentId) bump((n) => n + 1);
    });
  }, [queryClient, incidentId]);
  const incidentKey = incidentId ? queryClient.getQueryData<Incident>(['incident', incidentId])?.incidentKey : undefined;

  const detailLabel =
    detail === 'new' ? 'New event'
      : segs[0] === 'incidents' ? incidentKey ?? (detail && shortId(detail))
        : detail && shortId(detail);

  return (
    <nav className="crumb" aria-label="Breadcrumb">
      <Link to="/dashboard" className="crumb-root">SentinelFlow</Link>
      <span className="crumb-sep" aria-hidden="true">/</span>
      {!item ? (
        <strong aria-current="page">Not found</strong>
      ) : detailLabel ? (
        <>
          <Link to={item.to} className="crumb-mid">{item.label}</Link>
          <span className="crumb-sep" aria-hidden="true">/</span>
          <strong className="mono crumb-id" aria-current="page" title={detailLabel}>{detailLabel}</strong>
        </>
      ) : (
        <>
          <span className="crumb-group">{item.group}</span>
          <span className="crumb-sep" aria-hidden="true">/</span>
          <strong aria-current="page">{item.label}</strong>
        </>
      )}
    </nav>
  );
}

export default function AppShell() {
  const { username, isAdmin } = useAuth();
  const signOut = useSignOut();
  const location = useLocation();
  const queryClient = useQueryClient();
  const fetching = useIsFetching();

  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSE_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [railWidth, setRailWidth] = useState(() => window.matchMedia(RAIL_QUERY).matches);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const railed = collapsed || railWidth;

  // The SOC palette in tokens.css is scoped to html.soc, so the public site and
  // login keep their own look; it also reaches portaled drawers and modals.
  useEffect(() => {
    document.documentElement.classList.add('soc');
    return () => document.documentElement.classList.remove('soc');
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(COLLAPSE_KEY, collapsed ? '1' : '0');
    } catch {
      // ignore
    }
  }, [collapsed]);

  useEffect(() => {
    const mq = window.matchMedia(RAIL_QUERY);
    const onChange = () => setRailWidth(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  // Close the mobile drawer on navigation.
  useEffect(() => setMobileOpen(false), [location.pathname]);

  // Esc closes the mobile drawer.
  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setMobileOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mobileOpen]);

  // Ctrl/Cmd+K opens the command palette from anywhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const status = useQuery({
    queryKey: ['system-status'],
    queryFn: systemApi.status,
    refetchInterval: 20000,
    retry: false,
  });

  // Same key as the dashboard so this is free when the dashboard is open.
  const summary = useQuery({
    queryKey: ['dashboard', 8],
    queryFn: () => dashboardApi.summary(8),
    refetchInterval: 30000,
    staleTime: 10000,
  });

  const openAlerts = summary.data?.alertsByStatus?.OPEN ?? 0;
  const meta = statusMeta(status.isError ? 'DOWN' : status.data?.overall);

  return (
    // reducedMotion="user": drawers, modals and the AI/progress transitions honour the OS setting
    <MotionConfig reducedMotion="user">
    <div className={`shell${railed ? ' collapsed' : ''}${mobileOpen ? ' mobile-open' : ''}`}>
      {mobileOpen && <div className="shell-scrim" onClick={() => setMobileOpen(false)} />}

      <aside className="sidebar" aria-label="Sidebar">
        <Link to="/dashboard" className="sb-brand" aria-label="SentinelFlow dashboard">
          <span className="brand-mark"><ShieldCheck size={15} /></span>
          <span className="brand-text">
            <strong>SentinelFlow</strong>
            <em>Security Operations</em>
          </span>
        </Link>

        <nav className="sb-nav" aria-label="Primary">
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter((i) => !i.adminOnly || isAdmin);
            if (!items.length) return null;
            return (
              <div className="sb-group" key={group.title}>
                <div className="sb-group-title">{group.title}</div>
                {items.map(({ to, label, icon: Icon, end }) => {
                  const count = to === '/alerts' && openAlerts > 0 ? (openAlerts > 99 ? '99+' : String(openAlerts)) : null;
                  return (
                    <NavLink
                      key={to}
                      to={to}
                      end={end}
                      className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                      title={railed ? (count ? `${label} (${count} open)` : label) : undefined}
                      aria-label={railed ? (count ? `${label}, ${count} open` : label) : undefined}
                    >
                      <Icon size={15} />
                      <span className="nav-label">{label}</span>
                      {count && <span className="nav-count">{count}</span>}
                    </NavLink>
                  );
                })}
              </div>
            );
          })}
        </nav>

        {!railWidth && (
          <div className="sb-foot">
            <button
              className="sb-collapse"
              onClick={() => setCollapsed((c) => !c)}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {collapsed ? <ChevronsRight size={15} /> : <ChevronsLeft size={15} />}
              <span className="nav-label">Collapse</span>
            </button>
          </div>
        )}
      </aside>

      <div className="shell-main">
        <header className="topbar">
          <button
            className="icon-btn bordered mobile-only"
            aria-label="Open navigation"
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen(true)}
          >
            <Menu size={16} />
          </button>

          <Breadcrumb pathname={location.pathname} />

          <div className="topbar-actions">
            <button className="palette-trigger" onClick={() => setPaletteOpen(true)} aria-label="Open command palette">
              <Search size={14} />
              <span className="palette-trigger-text">Search or jump to…</span>
              <span className="kbd">Ctrl</span><span className="kbd">K</span>
            </button>

            <Link to="/system" className={`status-pill ${meta.cls}`} title={meta.text} aria-label={`System status: ${meta.text}`}>
              <span className={`live-dot ${meta.cls}`} />
              <span className="status-pill-text">{meta.short}</span>
            </Link>

            <button
              className="icon-btn bordered topbar-refresh"
              aria-label="Refresh data"
              title="Refresh data"
              onClick={() => queryClient.invalidateQueries()}
            >
              <RefreshCw size={14} className={fetching ? 'spin' : undefined} />
            </button>

            <ThemeSwitch />

            <span className="tb-sep" aria-hidden="true" />

            <div className="tb-user" title={`${username} · ${isAdmin ? 'Administrator' : 'Analyst'}`}>
              <span className="avatar">{initials(username)}</span>
              <span className="tb-user-text">
                <strong>{username}</strong>
                <em>{isAdmin ? 'Administrator' : 'Analyst'}</em>
              </span>
            </div>
            <IconButton icon={LogOut} label="Sign out" bordered onClick={signOut} />
          </div>
        </header>

        {/* The plain wrapper div is load-bearing: pages.css spaces cards with `.content > div > .card + …`. */}
        <main className="content" id="main">
          <div>
            <Outlet />
          </div>
        </main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
    </MotionConfig>
  );
}
