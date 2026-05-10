import { useEffect, useRef, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { Logo } from '../ui/Logo';
import { LinkButton } from '../ui/Button';
import { MenuIcon, MoonIcon, SunIcon, XCloseIcon } from '../ui/Icon';
import { type ThemeMode } from '../../lib/theme';
import { PRIMARY_NAV } from '../../siteConfig';

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])'
].join(', ');

/**
 * Site header.
 *
 * Reads primary nav and brand from siteConfig. The optional props are
 * preserved as a back-compat shim for any caller that still passes
 * `navLinks` / `githubRepo` from the legacy App.tsx — they are ignored.
 */
export function Header({
  theme,
  onToggleTheme
}: {
  theme: ThemeMode;
  onToggleTheme: () => void;
  navLinks?: ReadonlyArray<{ to: string; label: string }>;
  githubRepo?: string;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const location = useLocation();
  const mobileMenuRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const toggleLabel = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
  const ThemeIcon = theme === 'dark' ? SunIcon : MoonIcon;

  // Close menu on route change.
  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  // Lock body scroll while the mobile menu is open.
  useEffect(() => {
    if (!menuOpen) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previous;
    };
  }, [menuOpen]);

  // Escape closes the menu; Tab is trapped inside the dialog while open.
  useEffect(() => {
    if (!menuOpen) return;

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setMenuOpen(false);
        return;
      }

      if (e.key !== 'Tab' || !mobileMenuRef.current) return;

      const focusables = Array.from(
        mobileMenuRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
      ).filter((el) => !el.hasAttribute('disabled'));

      if (focusables.length === 0) return;

      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement as HTMLElement | null;

      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [menuOpen]);

  // Focus management: when the menu opens, move focus inside it; when it
  // closes (after having been open), restore focus to the trigger.
  //
  // We track the previous open state in a ref so that the initial mount
  // (menuOpen === false from the start) doesn't trigger a focus-restore —
  // otherwise we'd steal focus to the menu button on every page load.
  const wasOpenRef = useRef(false);
  useEffect(() => {
    if (menuOpen) {
      wasOpenRef.current = true;
      const node = mobileMenuRef.current;
      const firstFocusable = node?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
      firstFocusable?.focus();
      return;
    }

    // Closed: only restore focus if we just transitioned from open → closed.
    if (wasOpenRef.current) {
      wasOpenRef.current = false;
      triggerRef.current?.focus();
    }
  }, [menuOpen]);

  // Sticky header gets a hairline border once the page has scrolled.
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <>
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <header className={['site-header', scrolled ? 'is-scrolled' : ''].filter(Boolean).join(' ')}>
        <div className="site-header-inner">
          <Logo />

          <nav className="site-nav" aria-label="Primary">
            {PRIMARY_NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => (isActive ? 'is-active' : '')}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="site-header-cta">
            <button
              type="button"
              className="site-theme-toggle is-desktop"
              onClick={onToggleTheme}
              aria-label={toggleLabel}
              title={toggleLabel}
            >
              <ThemeIcon />
            </button>
            <Link to="/app/login" className="btn btn-ghost btn-sm is-desktop">
              Sign in
            </Link>
            <LinkButton to="/demo" variant="primary" size="sm">
              Book a demo
            </LinkButton>
            <button
              ref={triggerRef}
              type="button"
              className="site-header-mobile-toggle"
              onClick={() => setMenuOpen(true)}
              aria-expanded={menuOpen}
              aria-controls="mobile-menu"
              aria-label="Open menu"
            >
              <MenuIcon />
            </button>
          </div>
        </div>
      </header>

      {menuOpen ? (
        <div
          ref={mobileMenuRef}
          className="site-mobile-menu"
          id="mobile-menu"
          role="dialog"
          aria-modal="true"
          aria-label="Menu"
        >
          <div className="site-mobile-menu-head">
            <Logo />
            <button
              type="button"
              className="site-header-mobile-toggle"
              onClick={() => setMenuOpen(false)}
              aria-label="Close menu"
              style={{ display: 'inline-flex' }}
            >
              <XCloseIcon />
            </button>
          </div>
          <nav aria-label="Primary mobile">
            {PRIMARY_NAV.map((item) => (
              <Link key={item.to} to={item.to} onClick={() => setMenuOpen(false)}>
                {item.label}
              </Link>
            ))}
            <Link to="/app/login" onClick={() => setMenuOpen(false)}>
              Sign in
            </Link>
          </nav>
          <div className="site-mobile-menu-foot">
            <button type="button" className="site-theme-toggle" onClick={onToggleTheme} aria-label={toggleLabel}>
              <ThemeIcon />
              <span>{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span>
            </button>
            <LinkButton to="/demo" variant="primary" size="lg" block>
              Book a demo
            </LinkButton>
          </div>
        </div>
      ) : null}
    </>
  );
}
