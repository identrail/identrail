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
    label: 'Before',
    title: 'Isolated alerts',
    detail: 'Each control plane looks acceptable until the machine identity path crosses boundaries.'
  },
  {
    label: 'During',
    title: 'Evidence stitching',
    detail: 'Read-only collection joins IAM, Kubernetes, repository, and OIDC proof into one chain.'
  },
  {
    label: 'After',
    title: 'Safe remediation',
    detail: 'Owners get the affected workload, blast-radius context, and the first low-risk fix.'
  }
];

export function ProblemFramingSection() {
  return (
    <section className="idt-section idt-problem-frame" aria-labelledby="problem-frame-title">
      <div className="idt-problem-frame-grid">
        <div className="idt-problem-copy">
          <p className="idt-eyebrow">Why teams miss machine identity risk</p>
          <h2 id="problem-frame-title">Signals only matter when they reveal the path.</h2>
          <p>
            IAM policies, Kubernetes RBAC, repository exposure, and OIDC workflow identities are reviewed in separate
            tools. Identrail connects them into one trust path, then shows the proof, blast radius, and safest first
            fix.
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
              <span>Evidence packet</span>
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
