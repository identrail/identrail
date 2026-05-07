import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { siteLinks } from '../../siteConfig';

type NavLinkItem = {
  to: string;
  label: string;
};

export function Header({
  navLinks
}: {
  navLinks: readonly NavLinkItem[];
  githubRepo: string;
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
          <span>IDENTRAIL</span>
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
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className={`idt-header-actions ${menuOpen ? 'is-open' : ''}`}>
          <Link to={siteLinks.signIn} className="idt-header-utility">
            Login
          </Link>
          <Link to={siteLinks.app} className="idt-header-utility idt-header-signup" data-ab-slot="header_primary_cta">
            Sign up
          </Link>
          <Link to={siteLinks.requestDemo} className="idt-header-demo">
            Book Demo
          </Link>
        </div>
      </div>
    </header>
  );
}
