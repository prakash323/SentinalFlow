import { useState } from 'react';
import type { ButtonHTMLAttributes, CSSProperties, ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { LinkProps } from 'react-router-dom';
import {
  AlertTriangle,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Inbox,
  Loader2,
  RefreshCw,
  Search,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { humanize } from '../utils/format';
import {
  alertStatusTone,
  decisionTone,
  genericTone,
  incidentStatusTone,
  processingTone,
  scoreTone,
  severityTone,
  toneColor,
} from '../utils/tone';
import type { Tone } from '../utils/tone';

/* ------------------------------------------------------------------ */
/* Buttons                                                             */
/* ------------------------------------------------------------------ */

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success';
type Size = 'sm' | 'md' | 'lg';

const btnClass = (variant: Variant, size: Size, block?: boolean, extra = '') =>
  `btn btn-${variant}${size === 'md' ? '' : ` btn-${size}`}${block ? ' btn-block' : ''} ${extra}`.trim();

type ButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className'> & {
  variant?: Variant;
  size?: Size;
  block?: boolean;
  loading?: boolean;
  icon?: LucideIcon;
  className?: string;
};

export function Button({
  variant = 'primary',
  size = 'md',
  block,
  loading,
  icon: Icon,
  className,
  children,
  disabled,
  type = 'button',
  ...rest
}: ButtonProps) {
  return (
    <button type={type} className={btnClass(variant, size, block, className)} disabled={disabled || loading} {...rest}>
      {loading ? <Loader2 size={15} className="spin" /> : Icon ? <Icon size={15} /> : null}
      {children}
    </button>
  );
}

export function LinkButton({
  variant = 'secondary',
  size = 'md',
  icon: Icon,
  className,
  children,
  ...rest
}: Omit<LinkProps, 'className'> & { variant?: Variant; size?: Size; icon?: LucideIcon; className?: string }) {
  return (
    <Link className={btnClass(variant, size, false, className)} {...rest}>
      {Icon && <Icon size={15} />}
      {children}
    </Link>
  );
}

export function IconButton({
  icon: Icon,
  label,
  bordered,
  small,
  ...rest
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className'> & {
  icon: LucideIcon;
  label: string;
  bordered?: boolean;
  small?: boolean;
}) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      className={`icon-btn${bordered ? ' bordered' : ''}${small ? ' sm' : ''}`}
      {...rest}
    >
      <Icon size={small ? 14 : 16} />
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Layout primitives                                                   */
/* ------------------------------------------------------------------ */

export function Card({
  children,
  className = '',
  flush,
  interactive,
  style,
}: {
  children: ReactNode;
  className?: string;
  /** @deprecated entrance animations were removed; accepted so existing call sites keep compiling */
  delay?: number;
  flush?: boolean;
  interactive?: boolean;
  style?: CSSProperties;
}) {
  return (
    <section className={`card${flush ? ' flush' : ''}${interactive ? ' interactive' : ''} ${className}`.trim()} style={style}>
      {children}
    </section>
  );
}

export function CardHead({
  kicker,
  kickerIcon: KickerIcon,
  title,
  description,
  actions,
}: {
  kicker?: string;
  kickerIcon?: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="card-head">
      <div>
        {kicker && (
          <div className="card-kicker">
            {KickerIcon && <KickerIcon size={12} />}
            {kicker}
          </div>
        )}
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="header-actions">{actions}</div>}
    </div>
  );
}

export function PageHeader({
  eyebrow = 'Operations',
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="header-actions">{actions}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Badges                                                              */
/* ------------------------------------------------------------------ */

export function Badge({
  tone = 'neutral',
  dot,
  plain,
  children,
  title,
}: {
  tone?: Tone;
  dot?: boolean;
  plain?: boolean;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span className={`badge tone-${tone}${plain ? ' plain' : ''}`} title={title}>
      {dot && <i className="dot" />}
      {children}
    </span>
  );
}

const label = (v?: string | null) => (v ? humanize(v) : 'Unknown');

export const SeverityBadge = ({ value }: { value?: string | null }) => (
  <Badge tone={severityTone(value)} dot>{label(value)}</Badge>
);
export const AlertStatusBadge = ({ value }: { value?: string | null }) => (
  <Badge tone={alertStatusTone(value)}>{label(value)}</Badge>
);
export const IncidentStatusBadge = ({ value }: { value?: string | null }) => (
  <Badge tone={incidentStatusTone(value)}>{label(value)}</Badge>
);
export const DecisionBadge = ({ value }: { value?: string | null }) => (
  <Badge tone={decisionTone(value)} dot>{label(value)}</Badge>
);
export const ProcessingBadge = ({ value }: { value?: string | null }) => (
  <Badge tone={processingTone(value)} dot>{label(value)}</Badge>
);
export const StatusBadge = ({ value }: { value?: string | null }) => (
  <Badge tone={genericTone(value)}>{label(value)}</Badge>
);
export const TypeBadge = ({ value }: { value?: string | null }) => (
  <Badge tone="info" plain>{value || '—'}</Badge>
);

/* ------------------------------------------------------------------ */
/* Score meter                                                         */
/* ------------------------------------------------------------------ */

export function ScoreMeter({ value }: { value?: number | null }) {
  if (typeof value !== 'number') return <span className="muted">—</span>;
  const tone = scoreTone(value);
  return (
    <span className="score-meter" style={{ ['--tone' as string]: toneColor(tone) }} title={`Anomaly score ${value}`}>
      <span className="track">
        <span className="fill" style={{ width: `${Math.max(2, Math.min(100, value * 100))}%` }} />
      </span>
      <span className="num">{value.toFixed(3)}</span>
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* States                                                              */
/* ------------------------------------------------------------------ */

export const Spinner = ({ size = 18 }: { size?: number }) => <Loader2 className="spin" size={size} />;

export function Loading({ label: text = 'Loading…' }: { label?: string }) {
  return (
    <div className="state" role="status">
      <Spinner />
      <span>{text}</span>
    </div>
  );
}

export function Skeleton({ h = 14, w = '100%' }: { h?: number; w?: number | string }) {
  return <div className="skeleton" style={{ height: h, width: w }} />;
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="skeleton-rows" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} h={18} w={`${92 - (i % 3) * 9}%`} />
      ))}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  title = 'Couldn’t load this data',
}: {
  message: string;
  onRetry?: () => void;
  title?: string;
}) {
  return (
    <div className="state error-state column" role="alert">
      <div className="state-icon"><AlertTriangle size={20} /></div>
      <div>
        <strong>{title}</strong>
        <p>{message}</p>
        {onRetry && (
          <div className="state-actions">
            <Button variant="secondary" size="sm" icon={RefreshCw} onClick={onRetry}>Retry</Button>
          </div>
        )}
      </div>
    </div>
  );
}

export function EmptyState({
  title = 'Nothing here yet',
  text = 'There is no data matching the current view.',
  icon: Icon = Inbox,
  action,
}: {
  title?: string;
  text?: string;
  icon?: LucideIcon;
  action?: ReactNode;
}) {
  return (
    <div className="state column">
      <div className="state-icon"><Icon size={20} /></div>
      <div>
        <strong>{title}</strong>
        <p>{text}</p>
        {action && <div className="state-actions">{action}</div>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

export function SearchBox({
  value,
  onChange,
  placeholder = 'Search…',
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="search">
      <Search size={15} />
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder} />
    </label>
  );
}

export function Select({
  value,
  onChange,
  options,
  placeholder,
  ariaLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label?: string }[] | readonly string[];
  placeholder: string;
  ariaLabel?: string;
}) {
  return (
    <select className="input" value={value} onChange={(e) => onChange(e.target.value)} aria-label={ariaLabel || placeholder}>
      <option value="">{placeholder}</option>
      {options.map((o) => {
        const opt = typeof o === 'string' ? { value: o, label: humanize(o) } : { value: o.value, label: o.label ?? humanize(o.value) };
        return <option key={opt.value} value={opt.value}>{opt.label}</option>;
      })}
    </select>
  );
}

export function Segmented<T extends string | number>({
  value,
  onChange,
  options,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string }[];
}) {
  return (
    <div className="segmented" role="tablist">
      {options.map((o) => (
        <button
          key={String(o.value)}
          type="button"
          role="tab"
          aria-selected={o.value === value}
          className={o.value === value ? 'active' : ''}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Tabs<T extends string>({
  value,
  onChange,
  tabs,
}: {
  value: T;
  onChange: (v: T) => void;
  tabs: { value: T; label: string; count?: number; icon?: LucideIcon }[];
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.value}
          type="button"
          role="tab"
          aria-selected={t.value === value}
          className={`tab${t.value === value ? ' active' : ''}`}
          onClick={() => onChange(t.value)}
        >
          {t.icon && <t.icon size={15} />}
          {t.label}
          {typeof t.count === 'number' && <span className="count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Copy, KV, JSON                                                      */
/* ------------------------------------------------------------------ */

export function CopyButton({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="icon-btn sm copy-btn"
      title="Copy"
      aria-label="Copy to clipboard"
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          // clipboard blocked (insecure context / permissions) - nothing useful to do
        }
      }}
    >
      {done ? <Check size={13} /> : <Copy size={13} />}
    </button>
  );
}

export function KV({
  label: text,
  children,
  copy,
  mono,
}: {
  label: string;
  children: ReactNode;
  copy?: string;
  mono?: boolean;
}) {
  return (
    <div className="kv">
      <span>{text}</span>
      <div className={mono ? 'mono' : ''}>
        {children}
        {copy && <CopyButton value={copy} />}
      </div>
    </div>
  );
}

const JSON_TOKEN = /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

function highlight(json: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let i = 0;
  for (const m of json.matchAll(JSON_TOKEN)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push(json.slice(last, idx));
    const tok = m[0];
    const cls = tok.startsWith('"') ? (tok.endsWith(':') ? 'j-key' : 'j-str') : /true|false/.test(tok) ? 'j-bool' : tok === 'null' ? 'j-null' : 'j-num';
    out.push(<span key={i++} className={cls}>{tok}</span>);
    last = idx + tok.length;
  }
  if (last < json.length) out.push(json.slice(last));
  return out;
}

export function JsonViewer({ value }: { value: unknown }) {
  const text = JSON.stringify(value, null, 2) ?? 'null';
  return <pre className="json">{highlight(text)}</pre>;
}

/** Renders the plain-text/lightweight-markdown an LLM returns: paragraphs, "- " bullets, "1." lists, **bold**. */
export function RichText({ text }: { text: string }) {
  const inline = (s: string): ReactNode[] =>
    s.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, i) =>
      part.startsWith('**') ? <strong key={i}>{part.slice(2, -2)}</strong>
        : part.startsWith('`') ? <code key={i}>{part.slice(1, -1)}</code>
        : part,
    );

  const blocks: ReactNode[] = [];
  const lines = text.replace(/\r/g, '').split('\n');
  let list: { ordered: boolean; items: string[] } | null = null;
  let para: string[] = [];
  let key = 0;

  const flushPara = () => {
    if (para.length) blocks.push(<p key={key++}>{inline(para.join(' '))}</p>);
    para = [];
  };
  const flushList = () => {
    if (!list) return;
    const Tag = list.ordered ? 'ol' : 'ul';
    blocks.push(<Tag key={key++}>{list.items.map((it, i) => <li key={i}>{inline(it)}</li>)}</Tag>);
    list = null;
  };

  for (const raw of lines) {
    const line = raw.trim();
    const bullet = /^[-*•]\s+(.*)$/.exec(line);
    const numbered = /^\d+[.)]\s+(.*)$/.exec(line);
    const heading = /^#{1,4}\s+(.*)$/.exec(line);
    if (!line) { flushPara(); flushList(); continue; }
    if (heading) { flushPara(); flushList(); blocks.push(<h4 key={key++}>{heading[1]}</h4>); continue; }
    if (bullet || numbered) {
      flushPara();
      const ordered = !!numbered;
      if (!list || list.ordered !== ordered) { flushList(); list = { ordered, items: [] }; }
      list.items.push((bullet || numbered)![1]);
      continue;
    }
    flushList();
    para.push(line);
  }
  flushPara();
  flushList();

  return <div className="markdown">{blocks}</div>;
}

/* ------------------------------------------------------------------ */
/* Pagination                                                          */
/* ------------------------------------------------------------------ */

export function Pagination({
  page,
  totalPages,
  totalElements,
  itemLabel,
  onPageChange,
}: {
  page: number;
  totalPages: number;
  totalElements: number;
  itemLabel: string;
  onPageChange: (page: number) => void;
}) {
  return (
    <div className="pagination">
      <span>{totalElements.toLocaleString()} {itemLabel}</span>
      <div className="pager">
        <Button variant="secondary" size="sm" icon={ChevronLeft} disabled={page === 0} onClick={() => onPageChange(page - 1)} aria-label="Previous page">
          Prev
        </Button>
        <strong>{page + 1} / {Math.max(1, totalPages)}</strong>
        <Button variant="secondary" size="sm" disabled={page + 1 >= totalPages} onClick={() => onPageChange(page + 1)} aria-label="Next page">
          Next <ChevronRight size={15} />
        </Button>
      </div>
    </div>
  );
}

export function ClearFilters({ onClick }: { onClick: () => void }) {
  return (
    <Button variant="ghost" size="sm" icon={X} onClick={onClick}>Clear</Button>
  );
}
