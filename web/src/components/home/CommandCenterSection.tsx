import { useMemo, useState } from 'react';

const COMMAND_VIEWS = [
  {
    id: 'triage',
    label: 'Triage',
    eyebrow: 'Exposure triage',
    title: 'Turn scattered identity signals into one owner-ready queue.',
    metricLabel: 'Primary risk path',
    metricValue: 'Production database reachable',
    secondaryLabel: 'Signal match',
    secondaryValue: 'AWS role + K8s service account + OIDC claim drift',
    confidence: 'High confidence',
    evidence: [
      'Trust policy allows broad workflow subject claims',
      'ClusterRoleBinding grants namespace-spanning workload access',
      'Reachable resource is tagged production and regulated'
    ],
    playbook: ['Confirm owner', 'Review evidence bundle', 'Prioritize first fix']
  },
  {
    id: 'simulate',
    label: 'Simulate',
    eyebrow: 'Policy simulation',
    title: 'Preview access hardening before anything changes in production.',
    metricLabel: 'Projected breakage',
    metricValue: 'No critical workload impact',
    secondaryLabel: 'Recommended change',
    secondaryValue: 'Scope OIDC subject claims and split shared platform role',
    confidence: 'Simulation ready',
    evidence: [
      'No active workloads require the broad subject wildcard',
      'Two service accounts can move to namespace-scoped bindings',
      'Rollback path preserves current role until validation passes'
    ],
    playbook: ['Model policy change', 'Review affected workloads', 'Stage rollout']
  },
  {
    id: 'report',
    label: 'Report',
    eyebrow: 'Executive report',
    title: 'Package remediation progress for security, platform, and leadership.',
    metricLabel: 'Risk narrative',
    metricValue: 'Clear path from source to sensitive target',
    secondaryLabel: 'Artifacts',
    secondaryValue: 'Evidence export, timeline, owner notes, and residual risk',
    confidence: 'Audit ready',
    evidence: [
      'Every finding keeps source system evidence attached',
      'Owner handoff includes first action and expected outcome',
      'Remediation timeline captures decisions and exceptions'
    ],
    playbook: ['Export packet', 'Share owner plan', 'Track closure']
  }
] as const;

export function CommandCenterSection() {
  const [activeViewId, setActiveViewId] = useState<(typeof COMMAND_VIEWS)[number]['id']>('triage');

  const activeView = useMemo(
    () => COMMAND_VIEWS.find((view) => view.id === activeViewId) ?? COMMAND_VIEWS[0],
    [activeViewId]
  );

  return (
    <section className="idt-section idt-command-center" aria-labelledby="command-center-title">
      <div className="idt-shell idt-command-center-grid">
        <div className="idt-command-copy">
          <p className="idt-eyebrow">Trust operations layer</p>
          <h2 id="command-center-title">A premium control room for machine identity risk.</h2>
          <p>
            Identrail gives security and platform teams the same operating picture: live trust paths, policy evidence,
            blast-radius context, and a practical next step for each owner.
          </p>

          <div className="idt-command-tabs" role="tablist" aria-label="Command center views">
            {COMMAND_VIEWS.map((view) => {
              const isActive = view.id === activeView.id;
              return (
                <button
                  key={view.id}
                  id={`command-tab-${view.id}`}
                  type="button"
                  role="tab"
                  aria-controls="command-panel"
                  aria-selected={isActive}
                  className={isActive ? 'is-active' : ''}
                  onClick={() => setActiveViewId(view.id)}
                >
                  <span aria-hidden="true" />
                  {view.label}
                </button>
              );
            })}
          </div>
        </div>

        <article
          id="command-panel"
          className="idt-command-surface"
          role="tabpanel"
          aria-labelledby={`command-tab-${activeView.id}`}
          aria-live="polite"
        >
          <div className="idt-command-surface-head">
            <div>
              <p>{activeView.eyebrow}</p>
              <h3>{activeView.title}</h3>
            </div>
            <span>{activeView.confidence}</span>
          </div>

          <div className="idt-command-metrics" aria-label="Selected command center metrics">
            <div>
              <small>{activeView.metricLabel}</small>
              <strong>{activeView.metricValue}</strong>
            </div>
            <div>
              <small>{activeView.secondaryLabel}</small>
              <strong>{activeView.secondaryValue}</strong>
            </div>
          </div>

          <div className="idt-command-detail-grid">
            <div>
              <p className="idt-command-label">Evidence</p>
              <ul className="idt-command-list">
                {activeView.evidence.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
            <div>
              <p className="idt-command-label">Operator playbook</p>
              <ol className="idt-command-playbook">
                {activeView.playbook.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </div>
          </div>
        </article>
      </div>
    </section>
  );
}
