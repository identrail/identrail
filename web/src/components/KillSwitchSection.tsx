import { useMemo, useState } from 'react';

const trustNodes = ['EKS SA', 'OIDC', 'IAM Role', 'KMS', 'S3', 'Build Token'] as const;

const baseLog = [
  'Revoked access to arn:aws:iam::prod:role/ci-runner at 12:31 UTC',
  'Revoked access to arn:aws:iam::prod:role/eks-default at 12:31 UTC',
  'Revoked access to arn:aws:iam::shared:role/oidc-federation at 12:31 UTC',
  'Revoked access to arn:aws:iam::data:role/s3-replication at 12:31 UTC',
  'Revoked access to arn:aws:iam::prod:role/secrets-reader at 12:31 UTC'
] as const;

export function KillSwitchSection() {
  const [revoked, setRevoked] = useState(false);
  const logs = useMemo(() => [...baseLog, ...baseLog], []);

  return (
    <section className="section reveal-on-scroll" aria-labelledby="kill-switch-title">
      <div className={`section-card kill-switch-shell ${revoked ? 'is-revoked' : ''}`}>
        <div className="kill-switch-copy">
          <p className="eyebrow eyebrow-dark">Policy Simulation + Response Planning</p>
          <h2 id="kill-switch-title">Revocation Impact Simulation</h2>
          <p>
            Simulate revocation impact for risky machine identity paths in open-source, self-hosted environments.
            Use the preview to plan safe operator-driven response steps and audit follow-through.
          </p>
          <button
            type="button"
            className="kill-switch-button"
            aria-pressed={revoked}
            onClick={() => setRevoked((value) => !value)}
          >
            SIMULATE REVOKE IMPACT
          </button>
          <p className="kill-switch-note">
            Hover or click to simulate revocation impact across AWS and Kubernetes trust paths.
          </p>
        </div>

        <div className="kill-switch-visuals">
          <div className="kill-switch-graph" role="img" aria-label="Revocation graph simulation">
            {trustNodes.map((node) => (
              <span key={node} className="kill-node">
                {node}
              </span>
            ))}
          </div>

          <div className="kill-switch-log" aria-label="Live revocation log">
            <p>Live audit stream</p>
            <div className="kill-switch-log-track">
              {logs.map((line, index) => (
                <span key={`${line}-${index}`}>{line}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
