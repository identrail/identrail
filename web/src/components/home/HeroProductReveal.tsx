import { useEffect, useEffectEvent, useState } from 'react';

const AWS_PATH_SEGMENTS = [
  'GitHub Actions OIDC',
  'AWS IAM IdP',
  'billing-prod role',
  'PostgreSQL ledger'
] as const;

const AWS_ACTIVITY = [
  {
    title: 'GitHub Actions OIDC token verified',
    detail: 'repo: payments-api / deploy-production.yml',
    state: 'Verified'
  },
  {
    title: 'AssumeRole path detected',
    detail: 'sts:AssumeRole reaches billing-prod in 4 hops',
    state: 'Active'
  },
  {
    title: 'Privilege boundary inherited',
    detail: 'aws:PrincipalTag condition allows broad namespace reuse',
    state: 'Review'
  },
  {
    title: 'Evidence packet assembled',
    detail: 'JWT claims, trust policy, and API call proof attached',
    state: 'Ready'
  }
] as const;

const KUBERNETES_STEPS = [
  {
    title: 'Cluster signal received',
    detail: 'prod-eu-1 / payments namespace'
  },
  {
    title: 'Service account discovered',
    detail: 'payments-api service account linked to runtime'
  },
  {
    title: 'Workload identity confirmed',
    detail: 'OIDC federation routes into billing-prod'
  },
  {
    title: 'Evidence ready',
    detail: 'Owner note drafted with first safe fix'
  }
] as const;
const MOBILE_REVIEW_STEPS = KUBERNETES_STEPS.slice(0, 3);

const LOOP_INTERVAL_MS = 1800;

function usePrefersReducedMotion() {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }

    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setPrefersReducedMotion(media.matches);
    update();

    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', update);
      return () => media.removeEventListener('change', update);
    }

    media.addListener(update);
    return () => media.removeListener(update);
  }, []);

  return prefersReducedMotion;
}

export function HeroProductReveal() {
  const prefersReducedMotion = usePrefersReducedMotion();
  const [awsActiveIndex, setAwsActiveIndex] = useState(1);
  const [kubernetesActiveIndex, setKubernetesActiveIndex] = useState(2);
  const advanceActivity = useEffectEvent(() => {
    setAwsActiveIndex((current) => (current + 1) % AWS_ACTIVITY.length);
    setKubernetesActiveIndex((current) => (current + 1) % KUBERNETES_STEPS.length);
  });

  useEffect(() => {
    if (prefersReducedMotion) {
      return;
    }

    const timer = window.setInterval(() => {
      advanceActivity();
    }, LOOP_INTERVAL_MS);

    return () => window.clearInterval(timer);
  }, [advanceActivity, prefersReducedMotion]);

  const awsHeadline = AWS_ACTIVITY[awsActiveIndex];
  const completedKubernetesSteps = kubernetesActiveIndex + 1;

  return (
    <div className="idt-hero-product-stage" aria-label="Identrail product preview">
      <div className="idt-hero-backdrop-panel" aria-hidden="true">
        <span className="idt-hero-backdrop-node is-primary" />
        <span className="idt-hero-backdrop-node is-secondary" />
        <span className="idt-hero-backdrop-node is-tertiary" />
        <span className="idt-hero-backdrop-trace is-primary" />
        <span className="idt-hero-backdrop-trace is-secondary" />
      </div>

      <section className="idt-hero-admin-window" aria-label="AWS IAM trust path analysis preview">
        <div className="idt-window-bar">
          <span />
          <span />
          <span />
          <div className="idt-window-status">
            <span className="idt-window-pill is-live">AWS IAM live</span>
            <span className="idt-window-pill">Evidence ready</span>
          </div>
        </div>

        <div className="idt-admin-layout">
          <nav aria-label="Preview navigation">
            <strong>Trust graph</strong>
            <span>Evidence</span>
            <span>Policies</span>
            <span>Owners</span>
          </nav>

          <div className="idt-admin-main">
            <div className="idt-admin-profile-row">
              <div className="idt-admin-avatar is-logo">
                <img src="/brand-logos/amazoniam.svg" alt="" aria-hidden="true" />
              </div>
              <div>
                <p>Production workspace / AWS IAM</p>
                <strong>{awsHeadline.title}</strong>
              </div>
              <span className="idt-admin-severity">Critical path</span>
            </div>

            <div className="idt-admin-field-grid">
              <div>
                Source identity
                <span>GitHub Actions OIDC</span>
                <small>payments-api / deploy-production.yml</small>
              </div>
              <div>
                Privilege boundary
                <span>AWS IAM role: billing-prod</span>
                <small>Boundary allows shared namespace assumption</small>
              </div>
              <div>
                Target resource
                <span>PostgreSQL billing ledger</span>
                <small>prod-billing / read-write eligible path</small>
              </div>
              <div>
                Owner-ready fix
                <span>Restrict `sub` and namespace tags</span>
                <small>Simulation reports no workload breakage</small>
              </div>
            </div>

            <div className="idt-admin-path-strip" aria-label="Detected AWS IAM trust path">
              {AWS_PATH_SEGMENTS.map((segment, index) => (
                <span key={segment} className={index <= awsActiveIndex ? 'is-active' : ''}>
                  {segment}
                </span>
              ))}
            </div>

            <ol className="idt-admin-activity" aria-label="AWS IAM activity timeline">
              {AWS_ACTIVITY.map((event, index) => {
                const stateClass =
                  index < awsActiveIndex ? 'is-complete' : index === awsActiveIndex ? 'is-active' : 'is-pending';

                return (
                  <li key={event.title} className={stateClass}>
                    <span>{String(index + 1).padStart(2, '0')}</span>
                    <div>
                      <strong>{event.title}</strong>
                      <small>{event.detail}</small>
                    </div>
                    <b>{event.state}</b>
                  </li>
                );
              })}
            </ol>
          </div>
        </div>
      </section>

      <aside className="idt-hero-login-card" aria-label="Kubernetes identity activity preview">
        <div className="idt-mobile-live-row">
          <span className="idt-mobile-live-dot" aria-hidden="true" />
          Kubernetes scan live
          <strong>{completedKubernetesSteps}/4</strong>
        </div>

        <div className="idt-mobile-header">
          <div className="idt-mobile-logo">
            <img src="/brand-logos/kubernetes.svg" alt="" aria-hidden="true" />
          </div>
          <div>
            <h3>Namespace trust review</h3>
            <p>prod-eu-1 / payments-api workload identity</p>
          </div>
        </div>

        <div className="idt-mobile-summary">
          <div>
            <span>Severity</span>
            <strong>High</strong>
          </div>
          <div>
            <span>Status</span>
            <strong>{kubernetesActiveIndex >= 3 ? 'Evidence ready' : 'Scan active'}</strong>
          </div>
        </div>

        <div className="idt-path-input" aria-label="Detected service account">
          <span>SA</span>
          payments-api service account
        </div>
        <div className="idt-path-input" aria-label="Detected workload identity">
          <span>OIDC</span>
          Workload identity reaches billing-prod
        </div>

        <ol className="idt-mini-path" aria-label="Kubernetes review steps">
          {MOBILE_REVIEW_STEPS.map((step, index) => {
            const stateClass =
              index < kubernetesActiveIndex ? 'is-complete' : index === kubernetesActiveIndex ? 'is-active' : 'is-pending';

            return (
              <li key={step.title} className={stateClass}>
                <strong>{step.title}</strong>
                <span>{step.detail}</span>
              </li>
            );
          })}
        </ol>
      </aside>
    </div>
  );
}
