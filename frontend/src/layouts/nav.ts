import {
  Activity,
  BellRing,
  Boxes,
  ClipboardList,
  Cpu,
  Database,
  FlaskConical,
  LayoutDashboard,
  Repeat2,
  ShieldAlert,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export type NavItem = {
  to: string;
  label: string;
  icon: LucideIcon;
  /** hint shown in the command palette */
  keywords?: string;
  adminOnly?: boolean;
  end?: boolean;
  /** title of the group this item sits in (filled in below, used by breadcrumbs) */
  group?: string;
};

export type NavGroup = { title: string; items: NavItem[] };

export const NAV_GROUPS: NavGroup[] = [
  {
    title: 'Overview',
    items: [{ to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, end: true, keywords: 'home overview summary' }],
  },
  {
    title: 'Monitor',
    items: [
      { to: '/events', label: 'Events', icon: Database, keywords: 'ingest raw logs stream' },
      { to: '/predictions', label: 'Predictions', icon: Activity, keywords: 'model scores ml' },
      { to: '/alerts', label: 'Alerts', icon: BellRing, keywords: 'signals triage severity' },
      { to: '/incidents', label: 'Incidents', icon: ShieldAlert, keywords: 'cases investigation' },
      { to: '/entities', label: 'Entities', icon: Boxes, keywords: 'users accounts assets' },
    ],
  },
  {
    title: 'Operations',
    items: [
      { to: '/simulator', label: 'Simulator', icon: FlaskConical, keywords: 'attack lab scenarios generate test' },
      { to: '/replay-runs', label: 'Replay Runs', icon: Repeat2, adminOnly: true, keywords: 'reprocess batch' },
      { to: '/audit-logs', label: 'Audit Logs', icon: ClipboardList, adminOnly: true, keywords: 'history trail compliance' },
    ],
  },
  {
    title: 'System',
    items: [{ to: '/system', label: 'System Status', icon: Cpu, keywords: 'health status kafka database ml' }],
  },
];

export const ALL_NAV: NavItem[] = NAV_GROUPS.flatMap((g) => g.items.map((i) => ({ ...i, group: g.title })));

/**
 * The nav item a pathname belongs to, matched on whole path segments so
 * `/events/EV-1` resolves to Events. `/` is the public home page and is not a nav item.
 */
export function navItemFor(pathname: string): NavItem | undefined {
  return ALL_NAV.find((n) => pathname === n.to || pathname.startsWith(`${n.to}/`));
}
