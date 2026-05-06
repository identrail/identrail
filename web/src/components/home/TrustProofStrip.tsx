const TRUST_LOGOS = [
  {
    name: 'AWS IAM',
    icon: 'https://cdn.jsdelivr.net/npm/simple-icons@15.15.0/icons/amazoniam.svg'
  },
  {
    name: 'Kubernetes',
    icon: 'https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/kubernetes.svg'
  },
  {
    name: 'GitHub',
    icon: 'https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/github.svg'
  },
  {
    name: 'OpenID',
    icon: 'https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/openid.svg'
  },
  {
    name: 'Terraform',
    icon: 'https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/terraform.svg'
  },
  {
    name: 'Docker',
    icon: 'https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/docker.svg'
  },
  {
    name: 'PostgreSQL',
    icon: 'https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/postgresql.svg'
  },
  {
    name: 'Prometheus',
    icon: 'https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/prometheus.svg'
  }
] as const;

export function TrustProofStrip() {
  const logos = [...TRUST_LOGOS, ...TRUST_LOGOS];

  return (
    <section className="idt-trust-strip" aria-label="Identity ecosystem signals">
      <p className="idt-logo-cloud-label">Reviewed across your tech stack</p>
      <div className="idt-logo-cloud">
        <div className="idt-logo-cloud-track">
          {logos.map((logo, index) => (
            <span className="idt-logo-cloud-item" key={`${logo.name}-${index}`}>
              <img src={logo.icon} alt="" aria-hidden="true" loading="lazy" />
              <span>{logo.name}</span>
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
