import { Link } from 'react-router-dom';

const PATH_STEPS = ['Kubernetes service account', 'OIDC federation', 'AWS IAM role', 'PostgreSQL ledger'] as const;
const EVIDENCE_EVENTS = [
  'Service account token mapped to AWS trust',
  'Wildcard subject condition detected',
  'Production PostgreSQL ledger reachable'
] as const;

function ProviderMark({ provider }: { provider: 'aws' | 'kubernetes' }) {
  if (provider === 'kubernetes') {
    return (
      <span className="idt-provider-mark is-kubernetes" aria-hidden="true">
        <svg viewBox="0 0 40 40" focusable="false">
          <circle cx="20" cy="20" r="15.5" />
          <path d="M20 9.5v4.8M20 25.7v4.8M9.5 20h4.8M25.7 20h4.8M12.6 12.6l3.4 3.4M24 24l3.4 3.4M27.4 12.6 24 16M16 24l-3.4 3.4" />
          <circle cx="20" cy="20" r="5.4" />
        </svg>
      </span>
    );
  }

  return (
    <span className="idt-provider-mark is-aws" aria-hidden="true">
      <svg viewBox="0 0 48 34" focusable="false">
        <path d="M9.5 16.8c0-3 2.1-5.1 5-5.1 2.1 0 3.6 0.9 4.6 2.7 0.9-1.8 2.5-2.7 4.8-2.7 3.2 0 5.4 2.1 5.4 5.2v8.4h-4.1v-8.1c0-1.4-0.8-2.1-2-2.1-1.4 0-2.2 0.9-2.2 2.5v7.7h-4v-7.9c0-1.5-0.7-2.3-2-2.3s-2.1 0.9-2.1 2.5v7.7H9.5v-8.5Z" />
        <path d="M31.1 20.4c1.2 1 2.9 1.6 4.5 1.6 1.2 0 2-0.3 2-1.1 0-0.7-0.6-0.9-2.7-1.3-3.4-0.6-5-1.7-5-4 0-2.5 2.2-4.1 5.8-4.1 2.1 0 4.1 0.5 5.6 1.5l-1.3 2.9c-1.2-0.8-2.7-1.2-4.1-1.2-1.2 0-1.8 0.3-1.8 0.9 0 0.7 0.6 0.9 2.7 1.3 3.4 0.6 5 1.8 5 4.2 0 2.6-2.2 4.2-6.2 4.2-2.5 0-4.8-0.7-6.3-1.8l1.8-3.1Z" />
        <path d="M7.2 27.4c8.9 5.2 20.5 5.2 31.1 0.1" />
        <path d="M34.7 26.2c2.8-0.1 5.2 0.2 7.2 1.1-1.2 1.5-2.7 2.8-4.6 4" />
      </svg>
    </span>
  );
}

export function HeroProductReveal() {
  return (
    <div className="idt-hero-product-stage" aria-label="Identrail product preview">
      <div className="idt-hero-backdrop-panel" aria-hidden="true" />
      <div className="idt-hero-security-signal is-one" aria-hidden="true" />
      <div className="idt-hero-security-signal is-two" aria-hidden="true" />
      <div className="idt-hero-security-signal is-three" aria-hidden="true" />

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
              <img
                className="idt-admin-avatar"
                src="/assets/security-operator-portrait.png"
                alt="Cloud security reviewer"
                width="52"
                height="52"
              />
              <div>
                <p>Maya Chen - Cloud Security</p>
                <strong>Kubernetes risk review ready</strong>
              </div>
            </div>
            <div className="idt-admin-field-grid">
              <div>
                Source identity
                <span className="idt-field-with-mark">
                  <ProviderMark provider="kubernetes" />
                  prod/payments-api service account
                </span>
              </div>
              <div>
                Privilege boundary
                <span className="idt-field-with-mark">
                  <ProviderMark provider="aws" />
                  AWS role assumption
                </span>
              </div>
              <div>
                Workload
                <span>payments-api deployment</span>
              </div>
              <div>
                Target resource
                <span>PostgreSQL billing ledger</span>
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
        <div className="idt-login-provider-lockup">
          <ProviderMark provider="aws" />
          <span>AWS IAM</span>
        </div>
        <h3>AWS IAM path review</h3>
        <p>Kubernetes workload can assume a broad production role.</p>
        <div className="idt-path-input" aria-label="Source identity">
          <span>IAM</span>
          <strong>arn:aws:iam::123456789012:role/payments-prod</strong>
        </div>
        <div className="idt-path-input" aria-label="Finding state">
          <span>HI</span>
          <strong>High severity</strong>
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
