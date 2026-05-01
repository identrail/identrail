import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

export function CtaBannerSection() {
  return (
    <section className="section" aria-labelledby="ready-title">
      <div className="cta-banner">
        <h2 id="ready-title">Ready to get started?</h2>
        <p>
          Legacy identity tooling leaves machine trust paths open for attackers. Identrail helps you
          close those paths with visibility-first security and rollout-safe authorization.
        </p>
        <div className="cta-banner-actions">
          <SafeLink className="btn btn-ghost" href={siteLinks.getStarted}>
            Open App
          </SafeLink>
          <SafeLink className="btn btn-secondary" href={siteLinks.requestDemo}>
            Request a Demo
          </SafeLink>
        </div>
      </div>
    </section>
  );
}
