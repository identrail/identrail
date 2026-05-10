import type { ReactNode } from 'react';

const pathSteps = ['GitHub OIDC', 'AWS IAM IdP', 'billing-prod role', 'PostgreSQL ledger'];
const evidenceRows = [
  {
    label: '01',
    title: 'GitHub OIDC token verified',
    detail: 'repo: payments-api / deploy-production.yml'
  },
  {
    label: '02',
    title: 'AssumeRole path detected',
    detail: 'sts:AssumeRole reaches billing-prod in 4 hops'
  },
  {
    label: '03',
    title: 'Safe fix simulated',
    detail: 'Restrict subject claim without workload breakage'
  }
];

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
        <div className="hero-visual-product-grid">
          <aside className="hero-visual-nav" aria-hidden="true">
            <span className="is-active">Trust graph</span>
            <span>Evidence</span>
            <span>Policies</span>
          </aside>
          <div className="hero-visual-main">
            <div className="hero-visual-row">
              <div>
                <span className="hero-visual-kicker">Live trust path</span>
                <h3>billing-prod is reachable</h3>
              </div>
              <span className="hero-visual-badge is-danger">Critical</span>
            </div>
            <div className="hero-visual-meta" aria-label="Risk path summary">
              <span>4 hops</span>
              <span>Owner matched</span>
              <span>Fix simulated</span>
            </div>
            <div className="hero-path" aria-label="Resolved trust path">
              {pathSteps.map((step, index) => (
                <div className="hero-path-node" key={step}>
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <strong>{step}</strong>
                </div>
              ))}
            </div>
            <div className="hero-visual-grid-2">
              <div className="hero-visual-metric">
                <span>Owner</span>
                <strong>payments-api</strong>
                <small>Platform / production</small>
              </div>
              <div className="hero-visual-metric">
                <span>Fix</span>
                <strong>Restrict subject claim</strong>
                <small>Safe in simulation</small>
              </div>
            </div>
            <div className="hero-evidence-list" aria-label="Evidence trail">
              {evidenceRows.map((row) => (
                <article key={row.label}>
                  <span>{row.label}</span>
                  <div>
                    <strong>{row.title}</strong>
                    <small>{row.detail}</small>
                  </div>
                </article>
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
