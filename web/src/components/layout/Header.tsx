import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { siteLinks } from '../../siteConfig';
import { SafeLink } from '../SafeLink';

type NavLinkItem = {
  to: string;
  label: string;
};

export function Header({
  navLinks,
  githubRepo,
  theme,
  onToggleTheme
}: {
  navLinks: readonly NavLinkItem[];
  githubRepo: string;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!menuOpen) {
      return;
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
      }
    };

    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [menuOpen]);

  return (
    <header className="idt-header">
      <div className="idt-shell idt-header-row">
        <Link to="/" className="idt-brand" aria-label="Identrail homepage">
          <img src="/identrail-logo.png" width="32" height="32" alt="Identrail" decoding="async" />
          <span>
            Identrail
            <small>Machine Identity Security</small>
          </span>
        </Link>

        <button
          className="idt-menu-toggle"
          type="button"
          onClick={() => setMenuOpen((prev) => !prev)}
          aria-expanded={menuOpen}
          aria-controls="primary-nav"
          aria-label={menuOpen ? 'Close primary navigation' : 'Open primary navigation'}
        >
          <span className="idt-menu-toggle-icon" aria-hidden="true" />
          <span className="idt-menu-toggle-label">{menuOpen ? 'Close' : 'Menu'}</span>
        </button>

        <nav id="primary-nav" className={`idt-nav ${menuOpen ? 'is-open' : ''}`} aria-label="Primary">
          {navLinks.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => (isActive ? 'is-active' : '')}
              onClick={() => setMenuOpen(false)}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="idt-header-actions">
          <Link to="/read-only-scan" className="idt-btn idt-btn-primary" data-ab-slot="header_primary_cta">
            Start Free Risk Scan
          </Link>
          <Link to="/demo" className="idt-btn idt-btn-dark">
            Book Demo
          </Link>
          <div className="idt-header-utility-group">
            <Link to={siteLinks.signIn} className="idt-header-utility">
              Sign in
            </Link>
            <SafeLink href={githubRepo} className="idt-header-utility">
              GitHub
            </SafeLink>
            <button
              type="button"
              className={`idt-theme-toggle ${theme === 'light' ? 'is-light' : ''}`}
              onClick={onToggleTheme}
              aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {theme === 'dark' ? (
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    fill="currentColor"
                    d="M12 4.5a1 1 0 0 1 1 1V7a1 1 0 1 1-2 0V5.5a1 1 0 0 1 1-1Zm0 12a1 1 0 0 1 1 1v1.5a1 1 0 1 1-2 0V17.5a1 1 0 0 1 1-1ZM6.34 6.34a1 1 0 0 1 1.41 0L8.8 7.39A1 1 0 0 1 7.39 8.8L6.34 7.75a1 1 0 0 1 0-1.41Zm8.86 8.86a1 1 0 0 1 1.41 0l1.05 1.05a1 1 0 0 1-1.41 1.41L15.2 16.6a1 1 0 0 1 0-1.4ZM4.5 12a1 1 0 0 1 1-1H7a1 1 0 0 1 0 2H5.5a1 1 0 0 1-1-1Zm12.5 0a1 1 0 0 1 1-1h1.5a1 1 0 1 1 0 2H18a1 1 0 0 1-1-1ZM7.39 15.2A1 1 0 1 1 8.8 16.6l-1.05 1.06a1 1 0 0 1-1.41-1.42l1.05-1.05Zm8.86-8.86a1 1 0 1 1 1.42 1.41L16.6 8.8a1 1 0 1 1-1.4-1.41l1.05-1.05ZM12 8.5a3.5 3.5 0 1 1 0 7 3.5 3.5 0 0 1 0-7Z"
                  />
                </svg>
              ) : (
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    fill="currentColor"
                    d="M21.2 14.97A8.94 8.94 0 0 1 9.03 2.8a.75.75 0 0 0-.92-.95A10.5 10.5 0 1 0 22.15 15.9a.75.75 0 0 0-.95-.92Z"
                  />
                </svg>
              )}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
