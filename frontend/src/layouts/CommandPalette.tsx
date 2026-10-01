import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, Boxes, CornerDownLeft, LogOut, Moon, Plus, Search, Sun, User } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { entitiesApi } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { useSignOut } from '../auth/useSignOut';
import { useTheme } from '../hooks/useTheme';
import { ALL_NAV } from './nav';

type Command = {
  id: string;
  group: string;
  label: string;
  hint?: string;
  icon: LucideIcon;
  keywords?: string;
  run: () => void;
};

export default function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const signOut = useSignOut();
  const { theme, toggle } = useTheme();
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Entities are only fetched once the palette is first opened.
  const entities = useQuery({
    queryKey: ['palette-entities'],
    queryFn: () => entitiesApi.list({ size: 100 }),
    enabled: open,
    staleTime: 60000,
    retry: false,
  });

  useEffect(() => {
    if (open) {
      setQuery('');
      setActive(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  const go = (to: string) => () => {
    navigate(to);
    onClose();
  };

  const commands = useMemo<Command[]>(() => {
    const list: Command[] = [];

    ALL_NAV.filter((n) => !n.adminOnly || isAdmin).forEach((n) =>
      list.push({ id: `nav:${n.to}`, group: 'Go to', label: n.label, icon: n.icon, keywords: n.keywords, run: go(n.to) }),
    );

    list.push(
      { id: 'act:event', group: 'Actions', label: 'Create an event', icon: Plus, keywords: 'new ingest post', run: go('/events/new') },
      {
        id: 'act:theme',
        group: 'Actions',
        label: theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
        icon: theme === 'dark' ? Sun : Moon,
        keywords: 'appearance dark light',
        run: () => { toggle(); onClose(); },
      },
      { id: 'act:logout', group: 'Actions', label: 'Sign out', icon: LogOut, run: () => { onClose(); signOut(); } },
    );

    (entities.data?.content ?? []).forEach((e) =>
      list.push({
        id: `ent:${e.entityId}`,
        group: 'Entities',
        label: e.entityId,
        hint: e.displayName || e.entityType,
        icon: User,
        keywords: `${e.displayName ?? ''} ${e.entityType}`,
        run: go(`/entities/${encodeURIComponent(e.entityId)}`),
      }),
    );

    return list;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin, theme, entities.data]);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = q
      ? commands.filter((c) => `${c.label} ${c.hint ?? ''} ${c.keywords ?? ''} ${c.group}`.toLowerCase().includes(q))
      : commands.filter((c) => c.group !== 'Entities');

    const dynamic: Command[] = [];
    if (q.length >= 2) {
      const raw = query.trim();
      dynamic.push(
        { id: 'dyn:event', group: 'Look up', label: `Open event “${raw}”`, icon: ArrowRight, run: go(`/events/${encodeURIComponent(raw)}`) },
        { id: 'dyn:alerts', group: 'Look up', label: `Alerts for entity “${raw}”`, icon: Boxes, run: go(`/alerts?entityId=${encodeURIComponent(raw)}`) },
      );
    }
    return [...filtered.slice(0, 40), ...dynamic];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [commands, query]);

  useEffect(() => setActive(0), [query]);

  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>('[data-active="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') onClose();
    else if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); results[active]?.run(); }
  };

  let lastGroup = '';

  return createPortal(
    <AnimatePresence>
      {open && (
        <>
          <motion.div className="overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <div className="palette-wrap">
            <motion.div
              className="palette"
              role="dialog"
              aria-modal="true"
              aria-label="Command palette"
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.12 }}
              onKeyDown={onKeyDown}
            >
              <div className="palette-input">
                <Search size={15} />
                <input
                  ref={inputRef}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search pages, entities, or paste an event ID…"
                  aria-label="Search commands"
                />
                <span className="kbd">Esc</span>
              </div>

              <div className="palette-list" ref={listRef} role="listbox">
                {results.length === 0 && <div className="palette-empty">No matches</div>}
                {results.map((r, i) => {
                  const header = r.group !== lastGroup ? r.group : null;
                  lastGroup = r.group;
                  return (
                    <div key={r.id}>
                      {header && <div className="palette-group">{header}</div>}
                      <button
                        role="option"
                        aria-selected={i === active}
                        data-active={i === active}
                        className={`palette-item${i === active ? ' active' : ''}`}
                        onMouseEnter={() => setActive(i)}
                        onClick={r.run}
                      >
                        <r.icon size={14} />
                        <span className="palette-label">{r.label}</span>
                        {r.hint && <span className="palette-hint">{r.hint}</span>}
                        {i === active && <CornerDownLeft size={13} className="palette-enter" />}
                      </button>
                    </div>
                  );
                })}
              </div>

              <div className="palette-foot">
                <span><span className="kbd">↑</span><span className="kbd">↓</span> navigate</span>
                <span><span className="kbd">↵</span> select</span>
                <span><span className="kbd">Esc</span> close</span>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  );
}
