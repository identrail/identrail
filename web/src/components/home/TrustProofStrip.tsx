const TRUST_LOGOS = [
  {
    name: 'AWS IAM',
    icon: '/brand-logos/aws.svg'
  },
  {
    name: 'Kubernetes',
    icon: '/brand-logos/kubernetes.svg'
  },
  {
    name: 'GitHub',
    icon: '/brand-logos/github.svg'
  }
] as const;

export function TrustProofStrip() {
  return (
    <section className="idt-trust-strip" aria-label="Identity ecosystem signals">
      <p className="idt-logo-cloud-label">Connect the sources that matter</p>
      <ul className="idt-logo-cloud-accessible">
        {TRUST_LOGOS.map((logo) => (
          <li key={logo.name}>{logo.name}</li>
        ))}
      </ul>
      <div className="idt-logo-cloud" aria-hidden="true">
        <div className="idt-logo-cloud-track">
          <div className="idt-logo-cloud-group">
            {TRUST_LOGOS.map((logo) => (
              <span className="idt-logo-cloud-item" key={logo.name}>
                <img src={logo.icon} alt="" aria-hidden="true" loading="lazy" />
                <span>{logo.name}</span>
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
