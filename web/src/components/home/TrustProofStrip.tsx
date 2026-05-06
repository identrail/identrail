const CONNECTOR_LOGOS = [
  { label: 'AWS IAM', mark: 'aws' },
  { label: 'Kubernetes', mark: 'kubernetes' },
  { label: 'GitHub', mark: 'github' },
  { label: 'OpenID', mark: 'openid' },
  { label: 'Terraform', mark: 'terraform' },
  { label: 'Docker', mark: 'docker' },
  { label: 'PostgreSQL', mark: 'postgresql' }
] as const;

type ConnectorMark = (typeof CONNECTOR_LOGOS)[number]['mark'];

function ConnectorLogo({ mark, label }: { mark: ConnectorMark; label: string }) {
  return (
    <span className={`idt-connector-logo is-${mark}`}>
      <span className="idt-connector-icon" aria-hidden="true">
        <ConnectorIcon mark={mark} />
      </span>
      <strong>{label}</strong>
    </span>
  );
}

function ConnectorIcon({ mark }: { mark: ConnectorMark }) {
  switch (mark) {
    case 'aws':
      return (
        <svg viewBox="0 0 64 42" focusable="false">
          <path d="M11 21.1c0-4.1 2.9-7 6.9-7 2.9 0 5 1.3 6.3 3.7 1.2-2.5 3.5-3.7 6.6-3.7 4.4 0 7.4 2.9 7.4 7.1v11.5h-5.6V21.6c0-1.9-1-2.9-2.8-2.9-1.9 0-3 1.2-3 3.4v10.6h-5.5V21.8c0-2.1-1-3.1-2.7-3.1-1.8 0-2.9 1.2-2.9 3.4v10.6H11V21.1Z" />
          <path d="M40.5 26.1c1.8 1.3 4.1 2.1 6.4 2.1 1.7 0 2.8-0.5 2.8-1.5 0-1-0.8-1.3-3.8-1.8-4.8-0.8-7.1-2.4-7.1-5.6 0-3.5 3.1-5.7 8.1-5.7 3 0 5.7 0.7 7.8 2.1L52.9 20c-1.7-1-3.7-1.6-5.8-1.6-1.7 0-2.6 0.4-2.6 1.3 0 1 0.9 1.3 3.8 1.8 4.8 0.9 7.1 2.5 7.1 5.9 0 3.6-3.1 5.8-8.7 5.8-3.5 0-6.7-0.9-8.9-2.5l2.7-4.6Z" />
          <path d="M8.9 35.3c12.4 6.9 28.6 6.8 43.3 0.1" />
          <path d="M47.4 33.8c3.8-0.2 7.2 0.3 10 1.5-1.6 2.1-3.8 4-6.3 5.7" />
        </svg>
      );
    case 'kubernetes':
      return (
        <svg viewBox="0 0 48 48" focusable="false">
          <circle cx="24" cy="24" r="18.2" />
          <path d="M24 10.5v6M24 31.5v6M10.5 24h6M31.5 24h6M14.5 14.5l4.2 4.2M29.3 29.3l4.2 4.2M33.5 14.5l-4.2 4.2M18.7 29.3l-4.2 4.2" />
          <circle cx="24" cy="24" r="6.4" />
        </svg>
      );
    case 'github':
      return (
        <svg viewBox="0 0 48 48" focusable="false">
          <path d="M24 5.5c-10.5 0-19 8.5-19 19 0 8.4 5.4 15.5 12.9 18 0.9 0.2 1.2-0.4 1.2-0.9v-3.2c-5.2 1.1-6.3-2.2-6.3-2.2-0.9-2.2-2.1-2.8-2.1-2.8-1.7-1.2 0.1-1.1 0.1-1.1 1.9 0.1 2.9 2 2.9 2 1.7 2.9 4.5 2.1 5.5 1.6 0.2-1.2 0.7-2.1 1.2-2.6-4.2-0.5-8.6-2.1-8.6-9.3 0-2.1 0.7-3.8 2-5.1-0.2-0.5-0.9-2.5 0.2-5 0 0 1.6-0.5 5.2 2 1.5-0.4 3.1-0.6 4.8-0.6 1.6 0 3.2 0.2 4.8 0.6 3.6-2.5 5.2-2 5.2-2 1 2.5 0.4 4.5 0.2 5 1.2 1.3 2 3 2 5.1 0 7.2-4.4 8.8-8.6 9.3 0.7 0.6 1.3 1.7 1.3 3.5v5.2c0 0.5 0.3 1.1 1.3 0.9 7.5-2.5 12.9-9.6 12.9-18 0-10.5-8.5-19-19-19Z" />
        </svg>
      );
    case 'openid':
      return (
        <svg viewBox="0 0 48 48" focusable="false">
          <path d="M22.3 8.1v29.8l-5.8 2.5V11.1l5.8-3Z" />
          <path d="M26 16.6c6.9 0 12.9 2.1 15.8 5.3l-4 2.2 9.2 3.1-1.7-9.7-3.7 2.1c-4.1-4.1-10.9-6.6-18.1-6.6-10.7 0-19.4 5.3-19.4 11.8 0 4.9 4.9 9.1 11.9 10.9v-3.4c-4.6-1.5-7.6-4.3-7.6-7.5 0-4.5 7.9-8.2 17.6-8.2Z" />
        </svg>
      );
    case 'terraform':
      return (
        <svg viewBox="0 0 48 48" focusable="false">
          <path d="M7 8.6 18.9 15.4v13.3L7 21.9V8.6Z" />
          <path d="M20.8 15.4 32.7 8.6v13.3l-11.9 6.8V15.4Z" />
          <path d="M20.8 30.8 32.7 24v13.4l-11.9 6.8V30.8Z" />
          <path d="M34.6 8.6 46 15.1v13.4L34.6 22V8.6Z" />
        </svg>
      );
    case 'docker':
      return (
        <svg viewBox="0 0 54 42" focusable="false">
          <path d="M18 10h6v6h-6v-6ZM25 10h6v6h-6v-6ZM32 10h6v6h-6v-6ZM11 17h6v6h-6v-6ZM18 17h6v6h-6v-6ZM25 17h6v6h-6v-6ZM32 17h6v6h-6v-6Z" />
          <path d="M5 24.2h39.5c-1.4 4.7-5.4 8.7-10.8 10.6-5.3 1.9-12.2 1.9-17.4 0C10.7 32.7 6.7 28.9 5 24.2Z" />
          <path d="M43.1 18.5c2.2-0.2 4.3 0.5 5.9 2.2-1.3 2-3.1 3.2-5.4 3.4-0.2-2-0.4-3.8-0.5-5.6Z" />
        </svg>
      );
    case 'postgresql':
      return (
        <svg viewBox="0 0 48 48" focusable="false">
          <path d="M13.4 8.2c4.1-3.1 12.7-3 17.3-0.1 5.5 3.5 7.8 11.6 5.3 19-1.1 3.2-3.3 6.2-6.1 8.2-0.3 2.4-1.6 5.5-4.1 6.1-2.5 0.6-3.9-1.1-4.1-3.5-3.8 0.7-7.8-0.1-10.9-2.5-4.9-3.9-6.3-12.4-3.3-19.7 1.1-2.8 3-5.4 6-7.5Z" />
          <path d="M21.2 34.2c-1.8 0.3-3.6 0.1-5-0.7M29.8 35.2c2.2-1.8 3.7-4.4 4.4-7.5" />
          <path d="M18.3 18.4h0.1M29.2 18.4h0.1" />
          <path d="M24 21.6c-0.2 4.5-0.3 8.3-0.9 14.1-0.2 2.2 0.5 3.6 2.1 3.2 1.8-0.4 2.3-3.7 2.4-6.1" />
        </svg>
      );
  }
}

export function TrustProofStrip() {
  return (
    <section
      className="idt-trust-strip"
      aria-label="Connects to AWS IAM, Kubernetes, GitHub, OpenID, Terraform, Docker, and PostgreSQL"
    >
      <p>Connects to your machine identity stack</p>
      <div className="idt-logo-cloud">
        <div className="idt-logo-cloud-track" aria-hidden="true">
          {[...CONNECTOR_LOGOS, ...CONNECTOR_LOGOS].map(({ label, mark }, index) => (
            <ConnectorLogo key={`${label}-${index}`} label={label} mark={mark} />
          ))}
        </div>
      </div>
    </section>
  );
}
