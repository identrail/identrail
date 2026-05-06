import { Link } from 'react-router-dom';

const PATH_STEPS = ['GitHub OIDC', 'AWS role', 'K8s service account', 'Billing datastore'] as const;
const EVIDENCE_EVENTS = [
  'Trust policy wildcard detected',
  'Namespace binding reviewed',
  'Production resource reached'
] as const;

export function HeroProductReveal() {
  return (
    <div className="idt-hero-product-stage" aria-label="Identrail product preview">
      <div className="idt-hero-backdrop-panel" aria-hidden="true" />

      <section className="idt-hero-admin-window" aria-label="Machine identity posture dashboard preview">
        <div className="idt-window-bar">
          <span />
          <span />
          <span />
        </div>
        <div className="idt-admin-layout">
          <nav aria-label="Preview navigation">
            <strong>Trust graph</strong>
            <span>Sources</span>
            <span>Findings</span>
            <span>Reports</span>
          </nav>
          <div className="idt-admin-main">
            <div className="idt-admin-profile-row">
              <div className="idt-admin-avatar">ID</div>
              <div>
                <p>Production workspace</p>
                <strong>Risk review ready</strong>
              </div>
            </div>
            <div className="idt-admin-field-grid">
              <div>
                Source identity
                <span>GitHub Actions OIDC</span>
              </div>
              <div>
                Privilege boundary
                <span>AWS role assumption</span>
              </div>
              <div>
                Workload
                <span>payments-api service account</span>
              </div>
              <div>
                Target resource
                <span>billing-ledger datastore</span>
              </div>
            </div>
            <ol className="idt-admin-activity" aria-label="Preview activity">
              {EVIDENCE_EVENTS.map((event, index) => (
                <li key={event}>
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  {event}
                </li>
              ))}
            </ol>
          </div>
        </div>
      </section>

      <aside className="idt-hero-login-card" aria-label="Selected trust path preview">
        <div className="idt-login-cloud-mark" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <h3>Trust path review</h3>
        <p>High-risk chain with source evidence and a safe first fix.</p>
        <div className="idt-path-input" aria-label="Source identity">
          <span>GH</span>
          github.com/org/repo
        </div>
        <div className="idt-path-input" aria-label="Finding state">
          <span>HI</span>
          High severity
        </div>
        <ol className="idt-mini-path" aria-label="Trust path steps">
          {PATH_STEPS.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
        <div className="idt-login-actions">
          <Link to="/demo">Inspect</Link>
          <Link to="/read-only-scan">Simulate fix</Link>
        </div>
      </aside>
    </div>
  );
}
