import { CheckIcon } from '../ui/Icon';

type Node = {
  glyph?: string;
  glyphAlt?: string;
  label: string;
  meta: string;
  variant?: 'source' | 'target' | 'hop';
  hop?: string;
};

const NODES: Node[] = [
  {
    glyph: '/brand-logos/github.svg',
    glyphAlt: 'GitHub Actions',
    label: 'GitHub Actions OIDC',
    meta: 'identity',
    variant: 'source'
  },
  {
    glyph: '/brand-logos/aws.svg',
    glyphAlt: 'AWS IAM',
    label: 'sts:AssumeRole → billing-prod',
    meta: 'privilege',
    variant: 'hop',
    hop: '4 hops · trust policy allows shared namespace'
  },
  {
    glyph: '/brand-logos/kubernetes.svg',
    glyphAlt: 'Kubernetes',
    label: 'payments-api service account',
    meta: 'workload',
    variant: 'hop',
    hop: 'workload identity federated via OIDC'
  },
  {
    glyph: '/brand-logos/postgresql.svg',
    glyphAlt: 'PostgreSQL',
    label: 'billing.ledger (read · write)',
    meta: 'resource',
    variant: 'target'
  }
];

const EVIDENCE = [
  { label: 'JWT claims', badge: 'verified' },
  { label: 'IAM trust policy', badge: 'attached' },
  { label: 'Last seen', badge: '2 min ago' }
];

/**
 * Static, designed product illustration. Not a screenshot — clearly framed
 * with "Illustrative" badge inside. Renders a single trust path with
 * evidence bullets so a visitor can read the product story in one screenful
 * without watching an animation loop.
 */
export function TrustPathIllustration() {
  return (
    <div className="illu" aria-label="Identrail trust-path illustration">
      <div className="illu-frame">
        <span className="illu-label">Illustrative</span>
        <div className="illu-bar">
          <span className="illu-bar-path">production · workspace / aws-iam</span>
        </div>

        <div className="trail" aria-label="Trust path from source identity to target resource">
          {NODES.map((node, i) => (
            <div key={node.label}>
              {i > 0 && node.hop ? <div className="trail-link">{node.hop}</div> : null}
              <div
                className={[
                  'trail-node',
                  node.variant === 'source' ? 'is-source' : '',
                  node.variant === 'target' ? 'is-target' : ''
                ]
                  .filter(Boolean)
                  .join(' ')}
              >
                {node.glyph ? (
                  <span className="glyph" aria-hidden="true">
                    <img src={node.glyph} alt="" />
                  </span>
                ) : (
                  <span className="glyph" />
                )}
                <span>
                  <strong style={{ color: 'rgba(255,255,255,0.95)', fontWeight: 600 }}>{node.label}</strong>
                </span>
                <span className="meta">{node.meta}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="illu-evidence" aria-label="Evidence attached to this path">
          {EVIDENCE.map((e) => (
            <div className="illu-evidence-item" key={e.label}>
              <span className="check">
                <CheckIcon size={11} />
              </span>
              <span>{e.label}</span>
              <span className="badge">{e.badge}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
