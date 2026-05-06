import { useMemo, useState } from 'react';

const trustNodes = ['EKS SA', 'OIDC', 'IAM Role', 'KMS', 'S3', 'Build Token'] as const;

const baseLog = [
  'Simulation: Would revoke access to arn:aws:iam::prod:role/ci-runner at 12:31 UTC',
  'Simulation: Would revoke access to arn:aws:iam::prod:role/eks-default at 12:31 UTC',
  'Simulation: Would revoke access to arn:aws:iam::shared:role/oidc-federation at 12:31 UTC',
  'Simulation: Would revoke access to arn:aws:iam::data:role/s3-replication at 12:31 UTC',
  'Simulation: Would revoke access to arn:aws:iam::prod:role/secrets-reader at 12:31 UTC'
] as const;

export function KillSwitchSection() {
  const [revoked, setRevoked] = useState(false);
  const logs = useMemo(() => [...baseLog, ...baseLog], []);

  return (
    <section className="idt-section idt-shell" aria-labelledby="kill-switch-title">
      <div className="idt-card-grid two-col">
        <article className={`idt-card ${revoked ? 'idt-card' : ''}`}>
          <p className="idt-eyebrow">Policy Simulation + Response Planning</p>
          <h2 id="kill-switch-title">Revocation Impact Simulation</h2>
          <p>
            Simulate revocation impact for risky machine identity paths in open-source, self-hosted environments.
            Use the preview to plan safe operator-driven response steps and audit follow-through.
          </p>
          <div className="idt-inline-actions">
            <button
              type="button"
              className="idt-btn idt-btn-dark"
              aria-pressed={revoked}
              onClick={() => setRevoked((value) => !value)}
            >
              SIMULATE REVOKE IMPACT
            </button>
          </div>
          <p>
            Hover or click to simulate revocation impact across AWS and Kubernetes trust paths.
          </p>
        </article>

        <article className="idt-card" aria-label="Live revocation log">
          <p className="idt-eyebrow">Trust simulation log</p>
          <div className="idt-command-list">
            {trustNodes.map((node) => (
              <p key={node}>Node: {node}</p>
            ))}
          </div>
          <p className="idt-card-subtle">Live audit stream</p>
          <div className="idt-command-list">
            {logs.map((line, index) => (
              <p key={`${line}-${index}`}>{line}</p>
            ))}
          </div>
        </article>
        </div>
    </section>
  );
}
