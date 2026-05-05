const WORKFLOW_STEPS = [
  {
    stage: 'Discover',
    title: 'Build the trust graph',
    description: 'Collect AWS IAM, Kubernetes, GitHub, and OIDC identity metadata in read-only mode.',
    output: 'Output: identity graph snapshot with source evidence links'
  },
  {
    stage: 'Prioritize',
    title: 'Rank reachable risk paths',
    description: 'Score findings by severity, privilege depth, and production blast-radius potential.',
    output: 'Output: ranked findings queue with owner-ready context'
  },
  {
    stage: 'Simulate',
    title: 'Preview hardening safely',
    description: 'Preview trust-policy changes and estimate affected workloads before enforcement.',
    output: 'Output: remediation plan with expected impact summary'
  },
  {
    stage: 'Operate',
    title: 'Roll out with controls',
    description: 'Deploy in stages with rollback options and track resolution outcomes.',
    output: 'Output: audit-ready remediation timeline and status history'
  }
] as const;

export function HowItWorksSection() {
  return (
    <section className="idt-section idt-shell idt-workflow-section" aria-labelledby="workflow-title">
      <div className="idt-section-title">
        <p className="idt-eyebrow">Operational Workflow</p>
        <h2 id="workflow-title">From read-only discovery to safe enforcement</h2>
        <p>Each stage produces a concrete artifact security and platform teams can review before taking action.</p>
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
