import { Link } from 'react-router-dom';
import { SafeLink } from '../SafeLink';

function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 2C6.48 2 2 6.59 2 12.25c0 4.52 2.87 8.35 6.84 9.7.5.1.68-.22.68-.49 0-.24-.01-.89-.01-1.75-2.78.62-3.37-1.37-3.37-1.37-.46-1.2-1.12-1.51-1.12-1.51-.92-.64.07-.63.07-.63 1.02.08 1.55 1.07 1.55 1.07.9 1.59 2.37 1.13 2.95.87.09-.67.35-1.13.64-1.39-2.22-.26-4.56-1.14-4.56-5.08 0-1.12.39-2.03 1.03-2.74-.1-.26-.45-1.31.1-2.73 0 0 .84-.27 2.75 1.05A9.4 9.4 0 0 1 12 6.8c.85 0 1.7.12 2.5.36 1.9-1.32 2.74-1.05 2.74-1.05.56 1.42.21 2.47.11 2.73.64.71 1.02 1.62 1.02 2.74 0 3.95-2.35 4.82-4.58 5.08.36.32.67.95.67 1.91 0 1.38-.01 2.49-.01 2.83 0 .27.18.6.69.49A10.25 10.25 0 0 0 22 12.25C22 6.59 17.52 2 12 2Z"
      />
    </svg>
  );
}

function LinkedInIcon() {
  return (
    <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
      <path
        fill="currentColor"
        d="M22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003ZM7.119 20.452H3.555V9h3.564v11.452ZM5.337 7.433a2.063 2.063 0 1 1 0-4.126 2.063 2.063 0 0 1 0 4.126ZM20.452 20.452H16.89V14.89c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.94v5.659H9.344V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286Z"
      />
    </svg>
  );
}

function DiscordIcon() {
  return (
    <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
      <path
        fill="currentColor"
        d="M19.79 5.59A15.66 15.66 0 0 0 15.9 4.4l-.19.4a14.54 14.54 0 0 1 3.71 1.19 11.77 11.77 0 0 0-3.62-1.13c-2.39-.26-4.79-.26-7.18 0A11.7 11.7 0 0 0 5 6a14.56 14.56 0 0 1 3.71-1.19l-.19-.4a15.7 15.7 0 0 0-3.88 1.18C2.2 9.24 1.52 12.79 1.86 16.29a15.95 15.95 0 0 0 4.77 2.42l.95-1.58c-.52-.2-1.01-.45-1.49-.73.13.1.27.19.41.28 2.06 1.15 4.35 1.52 6.5 1.52 2.15 0 4.44-.37 6.49-1.52.14-.09.28-.18.41-.28-.47.28-.97.53-1.49.73l.95 1.58a15.92 15.92 0 0 0 4.77-2.42c.4-4.06-.68-7.58-2.53-10.7ZM9.54 14.14c-.76 0-1.39-.72-1.39-1.61s.61-1.6 1.39-1.6c.78 0 1.4.72 1.39 1.6 0 .9-.61 1.61-1.39 1.61Zm4.93 0c-.76 0-1.39-.72-1.39-1.61s.61-1.6 1.39-1.6c.78 0 1.4.72 1.39 1.6 0 .9-.61 1.61-1.39 1.61Z"
      />
    </svg>
  );
}

function XIcon() {
  return (
    <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
      <path
        fill="currentColor"
        d="M18.901 1.153h3.68l-8.04 9.19 9.46 12.504H16.62l-5.778-7.553-6.607 7.553H.552l8.603-9.834L0 1.154h7.57l5.215 6.882 6.116-6.883Zm-1.291 19.496h2.039L6.463 3.237H4.276L17.61 20.649Z"
      />
    </svg>
  );
}

type FooterProps = {
  xUrl: string;
  linkedInUrl: string;
  githubRepo: string;
  discordUrl: string;
};

export const FOOTER_TRUST_LINKS = [
  { label: 'FAQ', to: '/faq', external: false },
  { label: 'Privacy', to: '/privacy', external: false },
  { label: 'Terms', to: '/terms', external: false },
  { label: 'Responsible Disclosure', to: '/responsible-disclosure', external: false },
  { label: 'Changelog', to: 'https://github.com/identrail/identrail/releases', external: true }
] as const;

export function Footer({ xUrl, linkedInUrl, githubRepo, discordUrl }: FooterProps) {
  return (
    <footer className="idt-footer">
      <div className="idt-footer-bar">
        <div className="idt-shell idt-footer-bar-row">
          <div className="idt-footer-meta">
            <small>© {new Date().getFullYear()} Identrail. All rights reserved.</small>
          </div>
          <div className="idt-footer-trust-links">
            {FOOTER_TRUST_LINKS.map((item) =>
              item.external ? (
                <SafeLink key={item.label} href={item.to}>
                  {item.label}
                </SafeLink>
              ) : (
                <Link key={item.label} to={item.to}>
                  {item.label}
                </Link>
              )
            )}
          </div>
          <div className="idt-footer-socials">
            <SafeLink href={xUrl} aria-label="X" className="idt-social-link">
              <XIcon />
            </SafeLink>
            <SafeLink href={linkedInUrl} aria-label="LinkedIn" className="idt-social-link">
              <LinkedInIcon />
            </SafeLink>
            <SafeLink href={githubRepo} aria-label="GitHub" className="idt-social-link">
              <GitHubIcon />
            </SafeLink>
            <SafeLink href={discordUrl} aria-label="Discord" className="idt-social-link">
              <DiscordIcon />
            </SafeLink>
          </div>
        </div>
      </div>
    </footer>
  );
}
