import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const impactResults = [
  {
    metric: 'Reduced machine identity risk by 87%',
    title: 'Machine identity blast-radius reduction',
    quote: '“We replaced reactive IAM cleanups with continuous trust-path controls across 300+ workloads.”',
    persona: 'VP Security Engineering, Fortune 500 retailer'
  },
  {
    metric: 'Saved 42 hours/week on policy reviews',
    title: 'Policy validation acceleration',
    quote: '“Identity and platform teams now validate policy impact in minutes, not in weekly review cycles.”',
    persona: 'Head of Cloud Governance, Global payments group'
  },
  {
    metric: 'Blocked 14 high-severity NHI exposures in Kubernetes',
    title: 'Runtime trust-path intervention',
    quote: '“Dormant service-account trust chains were caught before they reached production blast radius.”',
    persona: 'Director of Platform Security, Enterprise SaaS'
  },
  {
    metric: 'Cut secret-rotation effort by 35%',
    title: 'Credential lifecycle simplification',
    quote: '“Automation removed repetitive key-rotation workflows and tightened compliance evidence.”',
    persona: 'Principal IAM Architect, Fortune 100 manufacturer'
  }
] as const;

const trustedBy = [
  'Northbank Group',
  'Apex Retail',
  'Mercury Health',
  'Nova Payments',
  'Atlas Cloud',
  'Frontline Logistics'
] as const;

export function ImpactProductionSection() {
  const trustedByRail = [...trustedBy, ...trustedBy];

  return (
    <section className="section reveal-on-scroll" aria-labelledby="impact-production-title">
      <div className="section-card impact-production">
        <div className="trusted-by-block" aria-label="Trusted by organizations">
          <p>Trusted by</p>
          <div className="trusted-by-rail">
            <div className="trusted-by-track">
              {trustedByRail.map((logo, index) => (
                <span key={`${logo}-${index}`}>{logo}</span>
              ))}
            </div>
          </div>
        </div>

        <div className="section-header">
          <p className="eyebrow eyebrow-dark">Identrail Impact in Production</p>
          <h2 id="impact-production-title">Measured outcomes from machine identity programs</h2>
          <p>
            Built from trust-graph analysis, policy simulation, and exposure scanning outcomes
            reported by enterprise teams running Identrail in production.
          </p>
        </div>

        <div className="impact-production-grid">
          {impactResults.map((result) => (
            <article key={result.title} className="impact-production-card">
              <div className="impact-production-graph" aria-hidden="true">
                <span />
                <span />
                <span />
                <span />
              </div>
              <p className="impact-production-metric">{result.metric}</p>
              <h3>{result.title}</h3>
              <p>{result.quote}</p>
              <p className="impact-production-persona">{result.persona}</p>
            </article>
          ))}
        </div>

        <SafeLink className="btn btn-text" href={siteLinks.impactQueries}>
          See the open-source queries that power these results → GitHub
        </SafeLink>
      </div>
    </section>
  );
}
