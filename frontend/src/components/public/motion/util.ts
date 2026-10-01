import type { CSSProperties } from 'react';

/** Typed inline CSS custom properties, e.g. style={vars({ '--i': 2 })}. */
export const vars = (v: Record<string, string | number>) => v as unknown as CSSProperties;

/** Stagger index (and optional group offset in ms) consumed by the .sf-* utilities in motion.css. */
export const stagger = (i: number, baseMs = 0) => vars(baseMs ? { '--i': i, '--sf-base': `${baseMs}ms` } : { '--i': i });
