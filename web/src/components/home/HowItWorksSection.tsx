const WORKFLOW_STEPS = [
  {
    stage: 'Discover',
    title: 'Build the trust graph',
    description: 'Collect AWS IAM, Kubernetes, GitHub, and OIDC identity metadata in read-only mode.',
    output: 'Identity graph snapshot with source evidence links'
  },
  {
    stage: 'Prioritize',
    title: 'Rank reachable risk paths',
    description: 'Score findings by severity, confidence, and production blast radius.',
    output: 'Ranked findings queue with owner-ready context'
  },
  {
    stage: 'Simulate',
    title: 'Preview hardening safely',
    description: 'Preview trust-policy changes and estimate affected workloads before approval.',
    output: 'Remediation plan with expected impact summary'
  },
  {
    stage: 'Operate',
    title: 'Roll out with controls',
    description: 'Stage approved changes with rollback options and track resolution outcomes.',
    output: 'Audit-ready remediation timeline and status history'
  }
] as const;

export function HowItWorksSection() {
  return (
    <section className="idt-section idt-workflow-section" aria-labelledby="workflow-title">
      <div className="idt-section-title">
        <p className="idt-eyebrow">Operational Workflow</p>
        <h2 id="workflow-title">From evidence to the first safe fix</h2>
        <p>Each stage produces a reviewable artifact before any change is approved.</p>
      </div>

      <ol className="idt-steps idt-workflow-track">
        {WORKFLOW_STEPS.map((step, index) => (
          <li key={step.title}>
            <span className="idt-workflow-stage">
              {String(index + 1).padStart(2, '0')} / {step.stage}
            </span>
            <h3>{step.title}</h3>
            <p>{step.description}</p>
            <p className="idt-workflow-output">{step.output}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
