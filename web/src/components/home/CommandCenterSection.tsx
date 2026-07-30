import { useMemo, useState } from 'react';

const COMMAND_VIEWS = [
  {
    id: 'triage',
    label: 'Triage',
    eyebrow: 'Findings queue',
    title: 'Start with the path that matters most.',
    metricLabel: 'Reachable target',
    metricValue: 'Production database',
    secondaryLabel: 'Connected signals',
    secondaryValue: 'GitHub workflow + AWS role + Kubernetes workload',
    confidence: 'High confidence',
    evidence: [
      'AWS trust policy accepts a broad workflow subject claim',
      'Kubernetes binding reaches the workload namespace',
      'The target is tagged production and regulated'
    ],
    playbook: ['Confirm owner', 'Review evidence', 'Choose first fix']
  },
  {
    id: 'simulate',
    label: 'Evidence',
    eyebrow: 'Explain the finding',
    title: 'Show why the path is risky before asking for a change.',
    metricLabel: 'Evidence attached',
    metricValue: 'Trust policy + workload context',
    secondaryLabel: 'Decision context',
    secondaryValue: 'Identity, relationship, target, and owner',
    confidence: 'Evidence ready',
    evidence: [
      'Workflow subject claim is wider than the repository scope',
      'Workload binding crosses the expected namespace boundary',
      'The affected resource and owner are attached to the finding'
    ],
    playbook: ['Review source proof', 'Confirm affected workload', 'Choose next action']
  },
  {
    id: 'report',
    label: 'Review',
    eyebrow: 'Review package',
    title: 'Give the next team enough context to act.',
    metricLabel: 'Source proof',
    metricValue: 'Affected resource and owner',
    secondaryLabel: 'Handoff',
    secondaryValue: 'Evidence, decision, and next remediation step',
    confidence: 'Ready to share',
    evidence: [
      'Every finding keeps source system evidence attached',
      'Owner handoff includes the first action and expected outcome',
      'The review record keeps the decision and exception context'
    ],
    playbook: ['Export evidence', 'Assign owner', 'Track next decision']
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
      <div className="idt-command-center-grid">
        <div className="idt-command-copy">
          <p className="idt-eyebrow">Product proof</p>
          <h2 id="command-center-title">One finding, with the whole path attached.</h2>
          <p>
            Identrail joins identity signals, reachable resources, evidence, and owner context so security and platform
            teams can work from the same finding.
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
