import { SafeLink } from '../SafeLink';

/** Illustrative policy evidence, never presented as a connected customer workspace. */
export function HeroProductReveal() {
  return (
    <section className="idt-finding-preview" aria-labelledby="hero-finding-title">
      <div className="idt-finding-preview-bar">
        <span>Example finding</span>
        <span className="idt-finding-severity">High risk</span>
      </div>
      <div className="idt-finding-preview-body">
        <p className="idt-finding-kicker">GitHub Actions / AWS IAM</p>
        <h2 id="hero-finding-title">A workflow can assume a privileged role.</h2>
        <p className="idt-finding-summary">
          Broad OIDC trust lets more workflow contexts request access than intended.
        </p>

        <ol className="idt-finding-path" aria-label="Example identity access path">
          <li>
            <img src="/brand-logos/github.svg" alt="" aria-hidden="true" />
            <div><span>01 / Identity</span><strong>GitHub Actions</strong><small>payments-api</small></div>
          </li>
          <li>
            <img src="/brand-logos/aws.svg" alt="" aria-hidden="true" />
            <div><span>02 / Role</span><strong>billing-prod</strong><small>OIDC federation</small></div>
          </li>
          <li>
            <img src="/brand-logos/aws.svg" alt="" aria-hidden="true" />
            <div><span>03 / Permission</span><strong>s3:GetObject</strong><small>billing exports</small></div>
          </li>
        </ol>

        <div className="idt-finding-evidence">
          <h3>Why it needs review</h3>
          <p>The trust policy accepts any subject from this repository.</p>
          <code>sub: repo:acme/payments-api:*</code>
        </div>
        <div className="idt-finding-action">
          <h3>Recommended action</h3>
          <p>Restrict the subject to the approved branch or environment. Review the affected workflows before applying.</p>
        </div>
      </div>
      <div className="idt-finding-preview-footer">
        <span>Illustrative policy data</span>
        <SafeLink href="/features/trust-graph">Explore the trust graph <span aria-hidden="true">→</span></SafeLink>
      </div>
    </section>
  );
}
