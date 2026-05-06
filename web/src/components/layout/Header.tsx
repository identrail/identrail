import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { githubRepo as githubRepoConfig, siteLinks } from '../../siteConfig';
import { SafeLink } from '../SafeLink';

type NavLinkItem = {
  to: string;
  label: string;
};

function formatGitHubStars(count: number): string {
  return String(count);
}

export function Header({
  navLinks,
  githubRepo
}: {
  navLinks: readonly NavLinkItem[];
  githubRepo: string;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [starCount, setStarCount] = useState<number | null>(null);
  const location = useLocation();

  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const controller = new AbortController();

    fetch(`https://api.github.com/repos/${githubRepoConfig.owner}/${githubRepoConfig.name}`, {
      signal: controller.signal,
      headers: { Accept: 'application/vnd.github+json' }
    })
      .then(async (response) => {
        if (!response.ok) return null;
        const payload = (await response.json()) as { stargazers_count?: number };
        return typeof payload.stargazers_count === 'number' ? payload.stargazers_count : null;
      })
      .then((count) => {
        if (count !== null) setStarCount(count);
      })
      .catch(() => undefined);

    return () => controller.abort();
  }, []);

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
          <SafeLink href={githubRepo} className="idt-github-star" aria-label="Star Identrail on GitHub">
            <span className="idt-github-star-action">
              <svg viewBox="0 0 16 16" aria-hidden="true">
                <path
                  fill="currentColor"
                  d="M8 0C3.58 0 0 3.67 0 8.2c0 3.63 2.29 6.71 5.47 7.8.4.08.55-.18.55-.4 0-.2-.01-.86-.01-1.56-2.01.38-2.53-.5-2.69-.95-.09-.23-.48-.95-.82-1.14-.28-.16-.68-.55-.01-.56.63-.01 1.08.59 1.23.83.72 1.24 1.87.89 2.33.68.07-.53.28-.89.51-1.1-1.78-.21-3.64-.91-3.64-4.04 0-.89.31-1.62.82-2.2-.08-.2-.36-1.03.08-2.16 0 0 .67-.22 2.2.84A7.43 7.43 0 0 1 8 3.96c.68 0 1.36.09 2 .28 1.53-1.06 2.2-.84 2.2-.84.44 1.13.16 1.96.08 2.16.51.58.82 1.31.82 2.2 0 3.14-1.87 3.83-3.65 4.04.29.25.54.74.54 1.5 0 1.1-.01 1.98-.01 2.25 0 .22.15.49.55.4A8.12 8.12 0 0 0 16 8.2C16 3.67 12.42 0 8 0Z"
                />
              </svg>
              Star
            </span>
            {starCount !== null ? (
              <span className="idt-github-star-count" aria-label={`${formatGitHubStars(starCount)} GitHub stars`}>
                {formatGitHubStars(starCount)}
              </span>
            ) : null}
          </SafeLink>
          <Link to={siteLinks.signIn} className="idt-header-utility">
            Login
          </Link>
          <Link to={siteLinks.app} className="idt-btn idt-btn-primary" data-ab-slot="header_primary_cta">
            Sign up
          </Link>
        </div>
      </div>
    </header>
  );
}
