import type { ReactNode } from 'react';

const pathSteps = [
  { label: 'Source', name: 'GitHub OIDC', meta: 'repo: payments-api' },
  { label: 'Bridge', name: 'AWS role', meta: 'AssumeRole trusted' },
  { label: 'Workload', name: 'billing-prod', meta: 'owner matched' },
  { label: 'Target', name: 'PostgreSQL', meta: 'contains customer data' }
] as const;

const evidenceSignals = ['JWT claims verified', 'Trust policy matched', 'Safe fix simulated'] as const;

function WindowChrome({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="hero-visual-window" aria-label={label}>
      <div className="hero-visual-window-bar" aria-hidden="true">
        <span />
        <span />
        <span />
      </div>
      {children}
    </div>
  );
}

export function ProductHeroVisual() {
  return (
    <div className="hero-visual hero-visual-product">
      <WindowChrome label="Product trust graph preview">
        <div className="hero-visual-product-stage">
          <div className="hero-visual-row hero-visual-product-top">
            <div>
              <span className="hero-visual-kicker">Resolved trust path</span>
              <h3>billing-prod is reachable</h3>
            </div>
            <span className="hero-visual-badge is-danger">Critical path</span>
          </div>
          <div className="hero-visual-meta hero-visual-meta-product" aria-label="Risk path summary">
            <span>4 hops</span>
            <span>Owner matched</span>
            <span>Fix simulated</span>
          </div>
          <div className="hero-path hero-path-product" aria-label="Resolved trust path">
            {pathSteps.map((step, index) => (
              <div className="hero-path-node hero-path-node-product" key={step.name}>
                <span>{step.label}</span>
                <strong>{step.name}</strong>
                <small>{step.meta}</small>
                {index === 1 ? <i className="hero-path-pulse" aria-hidden="true" /> : null}
              </div>
            ))}
          </div>
          <div className="hero-product-summary">
            <article className="hero-product-summary-card">
              <span>Owner</span>
              <strong>payments-api</strong>
              <small>Platform team · production</small>
            </article>
            <article className="hero-product-summary-card">
              <span>Safe fix</span>
              <strong>Restrict subject claim</strong>
              <small>Contains the path without workload breakage</small>
            </article>
          </div>
          <div className="hero-product-proof" aria-label="Evidence signals">
            <span>Evidence</span>
            <div>
              {evidenceSignals.map((signal) => (
                <b key={signal}>{signal}</b>
              ))}
            </div>
          </div>
        </div>
      </WindowChrome>
    </div>
  );
}

export function PricingHeroVisual() {
  return (
    <div className="hero-visual hero-visual-pricing">
      <WindowChrome label="Pricing comparison preview">
        <div className="hero-visual-row">
          <div>
            <span className="hero-visual-kicker">Plan calculator</span>
            <h3>Choose the deployment path</h3>
          </div>
          <span className="hero-visual-badge">Open core</span>
        </div>
        <div className="hero-pricing-bars" aria-hidden="true">
          <span style={{ height: '42%' }} />
          <span className="is-active" style={{ height: '78%' }} />
          <span style={{ height: '58%' }} />
        </div>
        <div className="hero-visual-grid-3">
          <div>
            <strong>$0</strong>
            <span>Self-host</span>
          </div>
          <div>
            <strong>$15</strong>
            <span>Team annual</span>
          </div>
          <div>
            <strong>Custom</strong>
            <span>Private tenant</span>
          </div>
        </div>
      </WindowChrome>
    </div>
  );
}

export function DocsHeroVisual() {
  return (
    <div className="hero-visual hero-visual-docs">
      <WindowChrome label="Documentation search preview">
        <div className="hero-doc-search">Search docs: deploy AWS connector</div>
        <div className="hero-doc-results">
          <article>
            <span>Quickstart</span>
            <strong>Run Identrail with Docker</strong>
          </article>
          <article>
            <span>Connector</span>
            <strong>AWS IAM read-only role</strong>
          </article>
          <article>
            <span>Operations</span>
            <strong>Export an evidence packet</strong>
          </article>
        </div>
      </WindowChrome>
    </div>
  );
}

export function DemoHeroVisual() {
  return (
    <div className="hero-visual hero-visual-demo">
      <WindowChrome label="Demo scan preview">
        <div className="hero-visual-row">
          <div>
            <span className="hero-visual-kicker">Free scan</span>
            <h3>Report assembled</h3>
          </div>
          <span className="hero-visual-badge is-success">Ready</span>
        </div>
        <ol className="hero-timeline">
          <li>Read-only connector verified</li>
          <li>Trust path resolved across four hops</li>
          <li>Owner-ready fix simulated</li>
        </ol>
      </WindowChrome>
    </div>
  );
}

export function BlogHeroVisual() {
  return (
    <div className="hero-visual hero-visual-blog">
      <WindowChrome label="Blog editorial preview">
        <div className="hero-editorial-feature">
          <span>Field note</span>
          <strong>Why service accounts become attack paths</strong>
        </div>
        <div className="hero-editorial-grid">
          <span>IAM</span>
          <span>Kubernetes</span>
          <span>OIDC</span>
          <span>Least privilege</span>
        </div>
      </WindowChrome>
    </div>
  );
}

export function CompanyHeroVisual() {
  return (
    <div className="hero-visual hero-visual-company">
      <WindowChrome label="Company operating principles preview">
        <div className="hero-principle-ledger">
          <div>
            <span>01</span>
            <strong>The graph is the surface.</strong>
          </div>
          <div>
            <span>02</span>
            <strong>Read-only until proven otherwise.</strong>
          </div>
          <div>
            <span>03</span>
            <strong>Open beats opaque.</strong>
          </div>
        </div>
      </WindowChrome>
    </div>
  );
}
