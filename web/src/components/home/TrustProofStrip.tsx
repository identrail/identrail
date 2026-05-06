const TRUST_LOGOS = [
  'AWS IAM',
  'Kubernetes',
  'GitHub',
  'OpenID Connect',
  'Prometheus'
] as const;

export function TrustProofStrip() {
  return (
    <section className="idt-trust-strip" aria-label="Identity ecosystem signals">
      <div className="idt-logo-cloud">
        <div className="idt-logo-cloud-track">
          {[...TRUST_LOGOS, ...TRUST_LOGOS].map((name, index) => (
            <span key={`${name}-${index}`}>{name}</span>
          ))}
        </div>
      </div>
    </section>
  );
}
