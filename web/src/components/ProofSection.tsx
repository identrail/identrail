import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const logos = ['Global Bank', 'InfraCo', 'Cloud Retail', 'FinServe', 'HealthOps', 'ScaleWare'] as const;

export function ProofSection() {
  return (
    <section className="mk-section" aria-labelledby="mk-proof-title">
      <div className="mk-shell">
        <div className="mk-section-head centered">
          <p className="mk-eyebrow">Customer Proof</p>
          <h2 id="mk-proof-title">Trusted by teams securing production machine identities</h2>
        </div>

        <div className="mk-logo-row" role="list" aria-label="Customer logos">
          {logos.map((logo) => (
            <span key={logo} role="listitem">
              {logo}
            </span>
          ))}
        </div>

        <div className="mk-proof-grid">
          <blockquote>
            <p>
              “Identrail gave us one source of truth for machine identity risk and cut remediation
              cycles from weeks to days.”
            </p>
            <footer>
              <strong>Director of Cloud Security</strong>
              <span>Fortune 500 Financial Services</span>
            </footer>
          </blockquote>

          <article className="mk-video-placeholder" aria-label="Customer video placeholder">
            <p>Customer story walkthrough (placeholder)</p>
            <SafeLink className="mk-btn mk-btn-secondary" href={siteLinks.watchDemo}>
              Watch Demo
            </SafeLink>
          </article>
        </div>
      </div>
    </section>
  );
}
