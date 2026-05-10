import { ArrowLink } from '../ui/Button';
import { SectionHeader } from '../ui/Section';

const CAPABILITIES = [
  {
    eyebrow: '01 · Discover',
    title: 'Every identity, every path, in one graph.',
    body:
      'Connect read-only to AWS, Kubernetes, GitHub Actions and your OIDC providers. Identrail builds a single trust graph that links every machine identity to every resource it can reach - including the hops in between.',
    cta: { label: 'See the connectors', to: '/integrations' }
  },
  {
    eyebrow: '02 · Detect',
    title: 'Severity tied to actual blast radius.',
    body:
      'Findings are scored on the data they can reach, not on signature counts. A trust path to your billing database is not the same as a path to a feature flag - and Identrail tells you which is which.',
    cta: { label: 'Threat model', to: '/security' }
  },
  {
    eyebrow: '03 · Remediate',
    title: 'Simulate the smallest safe fix first.',
    body:
      'Every recommendation is run through a policy simulator before you see it. Identrail shows the smallest IAM or RBAC change that closes the path without breaking the workloads that legitimately depended on it.',
    cta: { label: 'How it works', to: '/product' }
  }
];

export function Capabilities() {
  return (
    <section className="section">
      <div className="container">
        <SectionHeader
          eyebrow="What Identrail does"
          title={
            <h2 className="t-h2">
              Discover. Detect. Remediate.<br />
              <span style={{ color: 'var(--text-muted)' }}>One platform, no hand-offs.</span>
            </h2>
          }
          lede="The same trust graph that surfaces a finding is the surface a platform engineer uses to fix it. No exporting CSVs to a different tool to actually do the work."
        />
        <div className="grid grid-3">
          {CAPABILITIES.map((c) => (
            <article key={c.eyebrow} className="card card-loose">
              <div className="card-eyebrow">{c.eyebrow}</div>
              <h3>{c.title}</h3>
              <p>{c.body}</p>
              <div className="u-mt-6">
                <ArrowLink to={c.cta.to}>{c.cta.label}</ArrowLink>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
