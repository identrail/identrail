import { Link } from 'react-router-dom';
import { Logo } from '../ui/Logo';
import { DiscordIcon, GitHubIcon, LinkedInIcon, XIcon } from '../ui/Icon';
import {
  DISCORD_URL,
  FOOTER_NAV,
  GITHUB_REPO,
  LINKEDIN_URL,
  SHORT_DESCRIPTION,
  X_URL
} from '../../siteConfig';

const SOCIAL_LINKS = [
  { href: GITHUB_REPO, label: 'GitHub', icon: <GitHubIcon size={16} /> },
  { href: X_URL, label: 'X (Twitter)', icon: <XIcon size={14} /> },
  { href: LINKEDIN_URL, label: 'LinkedIn', icon: <LinkedInIcon size={16} /> },
  { href: DISCORD_URL, label: 'Discord', icon: <DiscordIcon size={16} /> }
] as const;

export function Footer() {
  const year = new Date().getFullYear();
  return (
    <footer className="site-footer" role="contentinfo">
      <div className="container">
        <div className="site-footer-grid">
          <div className="site-footer-brand">
            <Logo />
            <p>{SHORT_DESCRIPTION}</p>
          </div>
          {FOOTER_NAV.map((col) => (
            <div className="site-footer-col" key={col.heading}>
              <h4>{col.heading}</h4>
              <ul>
                {col.links.map((link) =>
                  link.external ? (
                    <li key={link.to}>
                      <a href={link.to} target="_blank" rel="noopener noreferrer">
                        {link.label}
                      </a>
                    </li>
                  ) : (
                    <li key={link.to}>
                      <Link to={link.to}>{link.label}</Link>
                    </li>
                  )
                )}
              </ul>
            </div>
          ))}
        </div>

        <div className="site-footer-bottom">
          <div>
            © {year} Identrail, Inc. · Apache 2.0 open core ·{' '}
            <Link to="/responsible-disclosure">Responsible disclosure</Link>
          </div>
          <ul className="site-footer-social" aria-label="Social media">
            {SOCIAL_LINKS.map((s) => (
              <li key={s.href} style={{ listStyle: 'none' }}>
                <a href={s.href} target="_blank" rel="noopener noreferrer" aria-label={s.label}>
                  {s.icon}
                </a>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </footer>
  );
}
