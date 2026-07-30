const identitySignals = [
  {
    name: 'AWS IAM',
    detail: 'role assumptions and policy edges',
    icon: '/brand-logos/aws.svg'
  },
  {
    name: 'Kubernetes',
    detail: 'service accounts, RBAC, namespaces',
    icon: '/brand-logos/kubernetes.svg'
  },
  {
    name: 'GitHub/OIDC',
    detail: 'workflow identity and token claims',
    icon: '/brand-logos/github.svg'
  }
];

const storyStages = [
  {
    label: 'Separate findings',
    title: 'Each system reports its own permissions',
    detail: 'The path between a repository, workload, role, and sensitive resource stays hidden.'
  },
  {
    label: 'Evidence connected',
    title: 'Join the identity signals',
    detail: 'Identrail correlates GitHub, AWS, and Kubernetes evidence into one machine identity path.'
  },
  {
    label: 'A fix you can explain',
    title: 'Hand off the next decision',
    detail: 'Owners get the affected resource, source evidence, and a clear remediation starting point.'
  }
];

export function ProblemFramingSection() {
  return (
    <section className="idt-section idt-problem-frame" aria-labelledby="problem-frame-title">
      <div className="idt-problem-frame-grid">
        <div className="idt-problem-copy">
          <p className="idt-eyebrow">The problem</p>
          <h2 id="problem-frame-title">A role, repo, or service account is only part of the story.</h2>
          <p>
            Identrail connects GitHub workflow exposure, AWS IAM relationships, and Kubernetes RBAC so teams can see
            which machine identity paths reach sensitive resources. Start with evidence, then decide what to fix.
          </p>
        </div>

        <div className="idt-problem-path-visual" role="group" aria-label="Identity signals converge into the Identrail trust graph">
          <div className="idt-problem-source-stack" aria-label="Source systems">
            {identitySignals.map((signal) => (
              <article className="idt-problem-source-card" key={signal.name}>
                <span className="idt-problem-source-icon">
                  <img src={signal.icon} alt="" aria-hidden="true" loading="lazy" />
                </span>
                <span>{signal.name}</span>
                <small>{signal.detail}</small>
              </article>
            ))}
          </div>

          <div className="idt-problem-path-spine" aria-hidden="true">
            <span />
          </div>

          <div className="idt-problem-map-core">
            <p>Identrail trust graph</p>
            <strong>One connected machine identity path</strong>
            <div aria-label="Trust graph outputs">
              <span>Source evidence</span>
              <span>Blast radius</span>
              <span>First safe fix</span>
            </div>
          </div>
        </div>
      </div>

      <div className="idt-problem-timeline" role="list" aria-label="Risk evidence workflow">
        {storyStages.map((stage, index) => (
          <article role="listitem" key={stage.title}>
            <span>{String(index + 1).padStart(2, '0')}</span>
            <small>{stage.label}</small>
            <h3>{stage.title}</h3>
            <p>{stage.detail}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
