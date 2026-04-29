import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

// TODO: Oluwatobi will update real URL paths later.
const footerColumns = [
  {
    title: 'Platform',
    links: [
      { label: 'Access Graph', href: '/features/trust-graph' },
      { label: 'Risk Intelligence', href: '/features/aws' },
      { label: 'Exposure Scanning', href: '/features/git-scanner' },
      { label: 'Authorization', href: '/solutions/platform-engineering' }
    ]
  },
  {
    title: 'Use Cases',
    links: [
      { label: 'Machine Identity Posture', href: '/solutions/security-teams' },
      { label: 'Cloud Trust Paths', href: '/solutions/aws' },
      { label: 'Repo Exposure Monitoring', href: '/features' },
      { label: 'Agentic AI Governance', href: '/security' }
    ]
  },
  {
    title: 'Resources',
    links: [
      { label: 'Docs', href: siteLinks.docs },
      { label: 'Blog', href: siteLinks.blog },
      { label: 'Quickstart (Docker)', href: siteLinks.quickstartDocker },
      { label: 'Contact', href: siteLinks.contact }
    ]
  },
  {
    title: 'Open Source',
    links: [
      { label: 'GitHub', href: siteLinks.github },
      { label: 'Star on GitHub', href: siteLinks.starOnGithub },
      { label: 'Contribute', href: siteLinks.contribute },
      { label: 'Discord', href: siteLinks.discord }
    ]
  }
] as const;

export function Footer() {
  return (
    <footer className="site-footer" aria-labelledby="footer-brand">
      <div className="footer-main">
        <div>
          <div className="footer-brand-lockup">
            <img
              src="/identrail-logo.png"
              alt=""
              className="footer-brand-logo"
              width={30}
              height={30}
              loading="lazy"
              decoding="async"
            />
            <p id="footer-brand" className="footer-brand">
              Identrail
            </p>
          </div>
          <p className="footer-text">
            Open-source machine identity security for AWS + Kubernetes workloads.
          </p>
        </div>

        <div className="footer-columns">
          {footerColumns.map((column) => (
            <section key={column.title}>
              <h2>{column.title}</h2>
              <ul>
                {column.links.map((link) => (
                  <li key={link.label}>
                    <SafeLink href={link.href}>{link.label}</SafeLink>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </div>

      <div className="footer-legal">
        <p>© 2026 Identrail. All rights reserved.</p>
        <nav aria-label="Legal links">
          <SafeLink href={siteLinks.legalPrivacy}>Privacy policy</SafeLink>
          <SafeLink href={siteLinks.legalTerms}>Terms of use</SafeLink>
          <SafeLink href={siteLinks.legalCookies}>Your privacy choices</SafeLink>
        </nav>
        <div className="footer-social" aria-label="Social links">
          <SafeLink href={siteLinks.x} aria-label="Identrail on X">
            X
          </SafeLink>
          <SafeLink href={siteLinks.linkedin} aria-label="Identrail on LinkedIn">
            LinkedIn
          </SafeLink>
          <SafeLink href={siteLinks.discord} aria-label="Identrail on Discord">
            Discord
          </SafeLink>
        </div>
      </div>
    </footer>
  );
}
