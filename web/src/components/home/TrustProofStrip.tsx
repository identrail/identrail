const IDENTITY_SOURCES = [
  { name: 'AWS IAM', icon: '/brand-logos/aws.svg' },
  { name: 'Kubernetes', icon: '/brand-logos/kubernetes.svg' },
  { name: 'GitHub', icon: '/brand-logos/github.svg' },
  { name: 'OpenID Connect', icon: '/brand-logos/openid.svg' }
] as const;

export function TrustProofStrip() {
  return (
    <section className="idt-trust-strip idt-source-strip" aria-label="Supported identity sources">
      <p>Connect your identity sources</p>
      <ul>
        {IDENTITY_SOURCES.map((source) => (
          <li key={source.name}>
            <img src={source.icon} alt="" aria-hidden="true" loading="lazy" />
            <span>{source.name}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
