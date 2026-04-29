import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const integrations = [
  'AWS',
  'Kubernetes',
  'EKS',
  'IAM',
  'GitHub',
  'Terraform',
  'ArgoCD',
  'Helm',
  'Vault',
  'Datadog'
] as const;

const awards = [
  'Cloud Security Innovation 2026',
  'Top Open Source Identity Project',
  'Best DevSecOps Graph Platform',
  'Machine Identity Leadership Award'
] as const;

export function EntroIntegrationSection() {
  const integrationRail = [...integrations, ...integrations];
  const awardsRail = [...awards, ...awards];

  return (
    <section className="section reveal-on-scroll" aria-labelledby="entro-integration-title">
      <div className="section-card entro-shell">
        <div className="section-header centered">
          <p className="eyebrow eyebrow-dark">Seamless Integration Layer</p>
          <h2 id="entro-integration-title">Integrates with the stack you already run</h2>
        </div>

        <div className="entro-logos-rail" aria-label="Integration logos marquee">
          <div className="entro-logos-track">
            {integrationRail.map((item, index) => (
              <span key={`${item}-${index}`}>{item}</span>
            ))}
          </div>
        </div>

        <div className="entro-awards-rail" aria-label="Awards carousel">
          <div className="entro-awards-track">
            {awardsRail.map((item, index) => (
              <article key={`${item}-${index}`}>
                <p>{item}</p>
                <span>4.8/5 analyst rating</span>
              </article>
            ))}
          </div>
        </div>

        <SafeLink className="btn btn-text" href={siteLinks.docs}>
          Read the Docs for all integrations
        </SafeLink>
      </div>
    </section>
  );
}
