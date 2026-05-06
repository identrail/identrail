const SIGNATURE_LAYERS = [
  {
    label: 'Trust graph paths',
    title: 'Routes instead of isolated alerts',
    detail: 'Source identities, role assumptions, RBAC bindings, and target resources stay connected in one path.'
  },
  {
    label: 'Evidence packets',
    title: 'Proof travels with every finding',
    detail: 'Each risk keeps its policy snippet, source system, timestamp, owner hint, and collection scope attached.'
  },
  {
    label: 'Blast-radius routes',
    title: 'Reachability becomes visible',
    detail: 'Identrail highlights what a compromised workload can actually touch across accounts and namespaces.'
  },
  {
    label: 'Policy diffs',
    title: 'The first fix is concrete',
    detail: 'Teams see the safer trust-policy or RBAC change before anything is applied to production.'
  }
] as const;

const SCOPE_ROWS = [
  ['AWS IAM', 'roles, trust policies, assumptions'],
  ['Kubernetes', 'service accounts, RBAC, namespaces'],
  ['GitHub/OIDC', 'workflow identities, claims, repo exposure'],
  ['Outputs', 'evidence packet, blast radius, first safe fix']
] as const;

export function HomeSignatureSection() {
  return (
    <section className="idt-section idt-home-signature" aria-labelledby="home-signature-title">
      <div className="idt-shell idt-home-signature-grid">
        <div className="idt-home-signature-copy">
          <p className="idt-eyebrow">Identrail visual signature</p>
          <h2 id="home-signature-title">A security map for machine identity, not another generic SaaS dashboard.</h2>
          <p>
            The homepage now leads with the product metaphors Identrail owns: connected trust routes, evidence packets,
            blast-radius reachability, and safe policy diffs that platform owners can act on.
          </p>
        </div>

        <div className="idt-home-scope-matrix" aria-label="Connector scope to output matrix">
          {SCOPE_ROWS.map(([source, signal], index) => (
            <div key={source} className={index === SCOPE_ROWS.length - 1 ? 'is-output' : undefined}>
              <span>{String(index + 1).padStart(2, '0')}</span>
              <strong>{source}</strong>
              <small>{signal}</small>
            </div>
          ))}
        </div>
      </div>

      <div className="idt-shell idt-signature-layer-grid">
        {SIGNATURE_LAYERS.map((layer) => (
          <article key={layer.label} className="idt-signature-layer">
            <span>{layer.label}</span>
            <h3>{layer.title}</h3>
            <p>{layer.detail}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
