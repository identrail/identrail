const WORKFLOW_STEPS = [
  {
    stage: 'Connect',
    title: 'Link the sources you own',
    description: 'Start with a read-only GitHub, AWS, or Kubernetes connection.',
    output: 'Output: source inventory and identity metadata'
  },
  {
    stage: 'Investigate',
    title: 'See the path behind the finding',
    description: 'Trace identities, relationships, and reachable resources with source evidence attached.',
    output: 'Output: prioritized finding with owner context'
  },
  {
    stage: 'Act',
    title: 'Hand off a fix people can explain',
    description: 'Assign ownership, share evidence, and track the next remediation decision.',
    output: 'Output: review package and decision history'
  }
] as const;

export function HowItWorksSection() {
  return (
    <section className="idt-section idt-workflow-section" aria-labelledby="workflow-title">
      <div className="idt-section-title">
        <p className="idt-eyebrow">How it works</p>
        <h2 id="workflow-title">From source connection to owner-ready evidence</h2>
        <p>Every step leaves a useful artifact for the next person in the review.</p>
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
