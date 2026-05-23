import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { preloadAuthConfig } from '../../authConfigCache';
import { siteLinks } from '../../siteConfig';

type NavLinkItem = {
  to: string;
  label: string;
};

function isEditableShortcutTarget(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  if (target.closest('input, textarea, select')) {
    return true;
  }

  const editableHost = target.closest('[contenteditable]');
  if (editableHost instanceof HTMLElement && editableHost.contentEditable !== 'false') {
    return true;
  }

  return Boolean(target.closest('[role="textbox"], [role="searchbox"], [role="combobox"], [role="spinbutton"]'));
}

export function Header({
  navLinks
}: {
  navLinks: readonly NavLinkItem[];
  githubRepo: string;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

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

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey || event.repeat) {
        return;
      }

      const target = event.target;
      if (isEditableShortcutTarget(target)) {
        return;
      }

      const key = event.key.toLowerCase();
      if (key !== 'l' && key !== 's') {
        return;
      }

      event.preventDefault();
      setMenuOpen(false);
      preloadAuthConfig();
      navigate(key === 'l' ? siteLinks.signIn : '/signup');
    };

    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [navigate]);

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
          <Link
            to={siteLinks.signIn}
            className="idt-header-utility idt-header-auth-chip"
            onFocus={preloadAuthConfig}
            onMouseEnter={preloadAuthConfig}
            onPointerDown={preloadAuthConfig}
          >
            <span>Log in</span>
            <span className="idt-header-keycap" aria-hidden="true">
              L
            </span>
          </Link>
          <Link
            to="/signup"
            className="idt-header-utility idt-header-signup idt-header-auth-chip is-primary"
            data-ab-slot="header_primary_cta"
            onFocus={preloadAuthConfig}
            onMouseEnter={preloadAuthConfig}
            onPointerDown={preloadAuthConfig}
          >
            <span>Sign up</span>
            <span className="idt-header-keycap" aria-hidden="true">
              S
            </span>
          </Link>
        </div>
      </div>
    </header>
  );
}
