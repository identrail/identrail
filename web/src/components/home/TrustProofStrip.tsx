const SIGNAL_SURFACES = [
  ['AWS IAM', 'trust policies, role assumptions'],
  ['Kubernetes', 'service accounts, RBAC bindings'],
  ['GitHub OIDC', 'workflow claims, repository context'],
  ['Sensitive targets', 'datastores, buckets, registries']
] as const;

export function TrustProofStrip() {
  return (
    <section className="idt-trust-strip" aria-label="Identity signal surfaces">
      <div className="idt-shell idt-signal-strip-grid">
        {SIGNAL_SURFACES.map(([surface, evidence]) => (
          <article key={surface}>
            <span>{surface}</span>
            <strong>{evidence}</strong>
          </article>
        ))}
      </div>
    </section>
  );
}
