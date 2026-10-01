import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState } from 'react';
import type { ReactNode, RefObject } from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion } from 'motion/react';
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';

import { IconButton } from './ui';

/* ------------------------------------------------------------------ */
/* Toasts                                                              */
/* ------------------------------------------------------------------ */

type ToastKind = 'success' | 'error' | 'info';
type ToastItem = { id: number; kind: ToastKind; title: string; message?: string };

type ToastApi = {
  success: (title: string, message?: string) => void;
  error: (title: string, message?: string) => void;
  info: (title: string, message?: string) => void;
};

const ToastContext = createContext<ToastApi | null>(null);

const ICONS = { success: CheckCircle2, error: AlertCircle, info: Info } as const;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => setItems((cur) => cur.filter((t) => t.id !== id)), []);

  const push = useCallback(
    (kind: ToastKind, title: string, message?: string) => {
      const id = nextId.current++;
      setItems((cur) => [...cur.slice(-3), { id, kind, title, message }]);
      setTimeout(() => dismiss(id), kind === 'error' ? 7000 : 4200);
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (t, m) => push('success', t, m),
      error: (t, m) => push('error', t, m),
      info: (t, m) => push('info', t, m),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      {createPortal(
        <div className="toaster" aria-live="polite">
          <AnimatePresence initial={false}>
            {items.map((t) => {
              const Icon = ICONS[t.kind];
              return (
                <motion.div
                  key={t.id}
                  layout
                  initial={{ opacity: 0, y: 16, scale: 0.96 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, x: 40 }}
                  transition={{ type: 'spring', stiffness: 420, damping: 32 }}
                  className={`toast ${t.kind}`}
                  role={t.kind === 'error' ? 'alert' : 'status'}
                >
                  <Icon size={18} />
                  <div>
                    <strong>{t.title}</strong>
                    {t.message && <p>{t.message}</p>}
                  </div>
                  <IconButton icon={X} label="Dismiss" small onClick={() => dismiss(t.id)} />
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside ToastProvider');
  return ctx;
}

/* ------------------------------------------------------------------ */
/* Overlays                                                            */
/* ------------------------------------------------------------------ */

function useEscape(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Keyboard behaviour shared by the drawer and the modal: focus moves into the dialog when it opens,
 * Tab stays inside it, and focus returns to whatever opened it when it closes.
 */
function useDialogFocus(open: boolean, ref: RefObject<HTMLElement | null>) {
  // Read while the dialog is still unmounted: by the time an effect runs, a field with `autoFocus`
  // inside the dialog already holds focus and would be mistaken for the element that opened it.
  const opener = useRef<HTMLElement | null>(null);
  const wasOpen = useRef(false);
  if (open && !wasOpen.current) opener.current = document.activeElement as HTMLElement | null;
  wasOpen.current = open;

  useEffect(() => {
    if (!open) return;
    const node = ref.current;
    // an autofocused field keeps focus; otherwise the dialog itself takes it
    if (node && !node.contains(document.activeElement)) node.focus({ preventScroll: true });

    const onKey = (e: KeyboardEvent) => {
      const node = ref.current;
      if (e.key !== 'Tab' || !node) return;
      const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => el.offsetParent !== null);
      if (!items.length) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === first || active === node)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      } else if (!node.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      const o = opener.current;
      if (o && document.contains(o)) o.focus({ preventScroll: true });
    };
  }, [open, ref]);
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEscape(open, onClose);
  const ref = useRef<HTMLElement>(null);
  const titleId = useId();
  useDialogFocus(open, ref);

  return createPortal(
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <motion.aside
            ref={ref}
            className="drawer"
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            tabIndex={-1}
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 380, damping: 40 }}
          >
            <div className="drawer-head">
              <div>
                <h2 id={titleId}>{title}</h2>
                {subtitle && <p className="muted" style={{ marginTop: 4, fontSize: 12.5 }}>{subtitle}</p>}
              </div>
              <IconButton icon={X} label="Close" bordered onClick={onClose} />
            </div>
            <div className="drawer-body">{children}</div>
            {footer && <div className="drawer-foot">{footer}</div>}
          </motion.aside>
        </>
      )}
    </AnimatePresence>,
    document.body,
  );
}

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
}) {
  useEscape(open, onClose);
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useDialogFocus(open, ref);

  return createPortal(
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <div className="modal-wrap">
            <motion.div
              ref={ref}
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby={titleId}
              tabIndex={-1}
              initial={{ opacity: 0, y: 18, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 12, scale: 0.98 }}
              transition={{ type: 'spring', stiffness: 420, damping: 36 }}
            >
              <div className="modal-head">
                <div>
                  <h2 id={titleId}>{title}</h2>
                  {description && <p className="muted" style={{ marginTop: 4, fontSize: 12.5 }}>{description}</p>}
                </div>
                <IconButton icon={X} label="Close" bordered onClick={onClose} />
              </div>
              <div className="modal-body">{children}</div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  );
}
