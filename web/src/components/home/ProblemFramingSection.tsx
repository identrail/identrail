export function ProblemFramingSection() {
  return (
    <section className="idt-section idt-shell idt-problem-frame" aria-labelledby="problem-frame-title">
      <div className="idt-problem-frame-grid">
        <div>
          <p className="idt-eyebrow">Why teams miss machine identity risk</p>
          <h2 id="problem-frame-title">Cloud, cluster, and CI evidence rarely arrives as one story.</h2>
          <p>
            IAM policies, Kubernetes RBAC, repository exposure, and OIDC workflow identities are reviewed in separate
            tools. Attack paths are not. Identrail closes that gap by turning each signal into a connected trust path
            with source evidence.
          </p>
        </div>

        <div className="idt-problem-map" aria-label="Identity signals converge into the Identrail trust graph">
          <div className="idt-problem-map-source">
            <span>AWS IAM</span>
            <small>roles, policies, assumptions</small>
          </div>
          <div className="idt-problem-map-source">
            <span>Kubernetes</span>
            <small>service accounts, RBAC, namespaces</small>
          </div>
          <div className="idt-problem-map-source">
            <span>GitHub/OIDC</span>
            <small>workflow identity, claims, exposure</small>
          </div>
          <div className="idt-problem-map-core">
            <span>Identrail trust graph</span>
            <small>path evidence, blast radius, first safe fix</small>
          </div>
        </div>
      </div>

      <div className="idt-problem-signals" role="list" aria-label="Fragmentation signals">
        <article role="listitem">
          <h3>Before: isolated alerts</h3>
          <p>Each system can look acceptable on its own while the combined path is risky.</p>
        </article>
        <article role="listitem">
          <h3>During: evidence stitching</h3>
          <p>Read-only collection normalizes source evidence into a single chain from identity to resource.</p>
        </article>
        <article role="listitem">
          <h3>After: safe remediation</h3>
          <p>Owners receive the policy context, affected workload view, and first action to reduce blast radius.</p>
        </article>
      </div>
    </section>
  );
}
