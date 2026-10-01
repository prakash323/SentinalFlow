import { useEffect, useState } from 'react';
import { Link, Outlet } from 'react-router-dom';
import { Menu, Moon, ShieldCheck, Sun, X } from 'lucide-react';

import { useAuth } from '../auth/AuthContext';
import { IconButton, LinkButton } from '../components/ui';
import { useTheme } from '../hooks/useTheme';
import '../styles/public.css';
import '../styles/story.css';

// Real in-page anchors only: every id below exists on the Home page.
const NAV = [
  { href: '#product', label: 'Product' },
  { href: '#detection', label: 'Detection' },
  { href: '#investigation', label: 'Investigation' },
  { href: '#platform', label: 'Platform' },
  { href: '#architecture', label: 'Architecture' },
  { href: '#how-it-works', label: 'How It Works' },
];

function Brand({ large }: { large?: boolean }) {
  return (
    <Link to="/" className={`pub-brand${large ? ' pub-brand-lg' : ''}`} aria-label="SentinelFlow home">
      <span className="brand-mark"><ShieldCheck size={large ? 20 : 16} /></span>
      <span className="brand-text">
        <strong>SentinelFlow</strong>
        <em>Security Operations</em>
      </span>
    </Link>
  );
}

/**
 * Layout for the public site (/). Deliberately separate from AppShell: same tokens, components
 * and theme switch, but spacious/editorial instead of dense. All public styling is scoped under
 * `.pub` so it cannot leak into the SOC.
 */
export default function PublicLayout() {
  const { isAuthenticated } = useAuth();
  const { theme, toggle } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);

  // Esc closes the mobile menu.
  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setMenuOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [menuOpen]);

  const themeLabel = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';

  return (
    <div className="pub" id="top">
      <a className="pub-skip" href="#main">Skip to content</a>

      <header className="pub-header">
        <div className="pub-container pub-header-inner">
          <Brand />

          <nav className="pub-nav" aria-label="Primary">
            {NAV.map((n) => <a key={n.href} href={n.href}>{n.label}</a>)}
          </nav>

          <div className="pub-actions">
            <button
              type="button"
              className="icon-btn pub-menu-btn"
              aria-label={menuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={menuOpen}
              aria-controls="pub-mobile-menu"
              onClick={() => setMenuOpen((o) => !o)}
            >
              {menuOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
            <span className="pub-theme-desktop">
              <IconButton icon={theme === 'dark' ? Sun : Moon} label={themeLabel} onClick={toggle} />
            </span>
            {isAuthenticated ? (
              <LinkButton to="/dashboard" variant="primary">Open Dashboard</LinkButton>
            ) : (
              <>
                <LinkButton to="/login" variant="ghost">Sign In</LinkButton>
                <LinkButton to="/login" variant="primary" className="pub-get-started">Get Started</LinkButton>
              </>
            )}
          </div>
        </div>

        {menuOpen && (
          <nav id="pub-mobile-menu" className="pub-mobile-menu" aria-label="Mobile">
            <div className="pub-container">
              {NAV.map((n) => (
                <a key={n.href} href={n.href} onClick={() => setMenuOpen(false)}>{n.label}</a>
              ))}
              {!isAuthenticated && (
                <LinkButton to="/login" variant="primary" size="lg" className="pub-menu-cta">Get Started</LinkButton>
              )}
              <button type="button" className="pub-menu-theme" onClick={toggle}>
                {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
                {themeLabel}
              </button>
            </div>
          </nav>
        )}
      </header>

      <main id="main">
        <Outlet />
      </main>

      <footer className="pub-footer">
        <div className="pub-container pub-footer-top">
          <div className="pub-footer-brand">
            <Brand large />
            <p className="pub-footer-tag">Smarter detection. Clearer investigations.</p>
            <p className="pub-footer-copy">© {new Date().getFullYear()} SentinelFlow. All rights reserved.</p>
          </div>

          {/* Only destinations that exist: in-page anchors and the two app routes. There are no
              documentation, company, legal, contact or social pages yet, so none are linked. */}
          <nav className="pub-footer-cols" aria-label="Footer">
            <div>
              <h3>Product</h3>
              <ul>
                <li><a href="#top">Overview</a></li>
                <li><a href="#detection">Detection</a></li>
                <li><a href="#platform">Platform</a></li>
                <li><a href="#architecture">Architecture</a></li>
              </ul>
            </div>
            <div>
              <h3>Resources</h3>
              <ul>
                <li><a href="#how-it-works">How It Works</a></li>
              </ul>
            </div>
            <div>
              <h3>Account</h3>
              <ul>
                {!isAuthenticated && <li><Link to="/login">Sign In</Link></li>}
                <li><Link to="/dashboard">Open Dashboard</Link></li>
              </ul>
            </div>
          </nav>
        </div>

        {/* Decorative brand wordmark: not content, so it is hidden from assistive tech and unselectable. */}
        <div className="pub-watermark" aria-hidden="true">
          <span>SentinelFlow</span>
        </div>
      </footer>
    </div>
  );
}
