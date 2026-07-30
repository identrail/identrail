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
  },
  {
    name: 'OpenID',
    icon: '/brand-logos/openid.svg'
  },
  {
    name: 'Terraform',
    icon: '/brand-logos/terraform.svg'
  },
  {
    name: 'Docker',
    icon: '/brand-logos/docker.svg'
  },
  {
    name: 'PostgreSQL',
    icon: '/brand-logos/postgresql.svg'
  },
  {
    name: 'Prometheus',
    icon: '/brand-logos/prometheus.svg'
  }
] as const;

export function TrustProofStrip() {
  const logoGroups = [0, 1] as const;

  return (
    <section className="idt-trust-strip" aria-label="Identity ecosystem signals">
      <p className="idt-logo-cloud-label">Reviewed across your identity stack</p>
      <ul className="idt-logo-cloud-accessible">
        {TRUST_LOGOS.map((logo) => (
          <li key={logo.name}>{logo.name}</li>
        ))}
      </ul>
      <div className="idt-logo-cloud" aria-hidden="true">
        <div className="idt-logo-cloud-track">
          {logoGroups.map((group) => (
            <div className="idt-logo-cloud-group" key={group}>
              {TRUST_LOGOS.map((logo) => (
                <span className="idt-logo-cloud-item" key={`${logo.name}-${group}`}>
                  <img src={logo.icon} alt="" aria-hidden="true" loading="lazy" />
                  <span>{logo.name}</span>
                </span>
              ))}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
