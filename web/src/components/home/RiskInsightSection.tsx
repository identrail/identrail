import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

const SCENARIOS = [
  {
    id: 'oidc-prod',
    name: 'CI OIDC to prod DB',
    severity: 'High',
    path: 'GitHub Actions OIDC → AWS Role → K8s SA → RDS billing-ledger',
    impact: 'Compromised CI workflow token can reach production billing data in one chain.',
    signal: '11 reachable resources',
    blastRadius: 'Cross-account read and write permissions on billing systems',
    firstAction: 'Tighten trust policy subject claims and reduce role action scope.'
  },
  {
    id: 'k8s-pivot',
    name: 'K8s service-account pivot',
    severity: 'High',
    path: 'K8s ServiceAccount → ClusterRoleBinding → IAM role assumption → Artifact bucket',
    impact: 'Overprivileged service account can pivot across namespace boundary into cloud resources.',
    signal: '7 cross-namespace privilege links',
    blastRadius: 'Build artifact tampering and namespace privilege escalation',
    firstAction: 'Split SA identity by workload and enforce namespace-scoped RBAC.'
  },
  {
    id: 'repo-secret',
    name: 'Leaked deploy token chain',
    severity: 'Medium',
    path: 'Repo secret leak → Bot identity replay → AssumeRole → Container registry push',
    impact: 'Leaked token can ship unauthorized container images into production path.',
    signal: '4 privileged registry actions exposed',
    blastRadius: 'Unauthorized image promotion through production CI path',
    firstAction: 'Rotate credentials and enforce short-lived workload identity tokens.'
  }
] as const;

export function RiskInsightSection() {
  const [activeScenarioId, setActiveScenarioId] = useState<(typeof SCENARIOS)[number]['id']>('oidc-prod');

  const activeScenario = useMemo(
    () => SCENARIOS.find((scenario) => scenario.id === activeScenarioId) ?? SCENARIOS[0],
    [activeScenarioId]
  );

  return (
    <section className="idt-section idt-shell" aria-labelledby="risk-insight-title">
      <div className="idt-section-title">
        <p className="idt-eyebrow">Product proof</p>
        <h2 id="risk-insight-title">See evidence for a high-risk trust path, not just a score</h2>
        <p>
          Identrail explains how a machine identity reaches production resources, why it matters, and what to change first without
          breaking workloads.
        </p>
      </div>

      <div className="idt-risk-insight-grid">
        <div className="idt-risk-scenario-list" role="tablist" aria-label="Risk path scenarios">
          {SCENARIOS.map((scenario) => {
            const isActive = scenario.id === activeScenario.id;
            const tabId = `risk-scenario-tab-${scenario.id}`;
            return (
              <button
                key={scenario.id}
                id={tabId}
                type="button"
                role="tab"
                aria-controls="risk-scenario-panel"
                aria-selected={isActive}
                className={`idt-risk-scenario-item ${isActive ? 'is-active' : ''}`}
                onClick={() => setActiveScenarioId(scenario.id)}
              >
                <span>{scenario.name}</span>
                <small>{scenario.severity} severity</small>
                <p>{scenario.signal}</p>
              </button>
            );
          })}
        </div>

        <article
          id="risk-scenario-panel"
          className="idt-card idt-risk-evidence-card"
          role="tabpanel"
          aria-labelledby={`risk-scenario-tab-${activeScenario.id}`}
          aria-live="polite"
        >
          <p className="idt-finding-label">Selected path</p>
          <h3>Risk: {activeScenario.name}</h3>
          <ol className="idt-risk-path-list" aria-label="Trust path sequence">
            {activeScenario.path.split(' → ').map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <p>
            <strong>Impact:</strong> {activeScenario.impact}
          </p>
          <p>
            <strong>Blast radius:</strong> {activeScenario.blastRadius}
          </p>
          <p>
            <strong>Evidence signal:</strong> {activeScenario.signal}
          </p>
          <p>
            <strong>Recommended first fix:</strong> {activeScenario.firstAction}
          </p>
          <p className="idt-risk-follow-up">
            Need deeper context?{' '}
            <Link to="/demo" className="idt-inline-link">
              Inspect this path in the interactive demo
            </Link>
            .
          </p>
        </article>
      </div>
    </section>
  );
}
