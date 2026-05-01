import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const integrations = [
  'AWS IAM',
  'Kubernetes',
  'GitHub',
  'Terraform',
  'HashiCorp Vault',
  'Datadog',
  'OpenID Connect',
  'Prometheus'
] as const;

export function IntegrationsCtaSection() {
  return (
    <section className="mk-section mk-integrations" aria-labelledby="mk-integrations-title">
      <div className="mk-shell">
        <div className="mk-section-head centered">
          <h2 id="mk-integrations-title">Integrations that fit your current stack</h2>
          <p>Deploy without re-platforming identity, security, or developer workflows.</p>
        </div>

        <div className="mk-integration-grid" role="list" aria-label="Integration list">
          {integrations.map((integration) => (
            <span key={integration} role="listitem">
              {integration}
            </span>
          ))}
        </div>

        <div className="mk-final-cta">
          <h3>Secure machine identity paths before they become incidents.</h3>
          <div>
            <SafeLink className="mk-btn mk-btn-primary" href={siteLinks.getStarted}>
              Open App
            </SafeLink>
            <SafeLink className="mk-btn mk-btn-secondary" href={siteLinks.requestDemo}>
              Request Demo
            </SafeLink>
          </div>
        </div>
      </div>
    </section>
  );
}
