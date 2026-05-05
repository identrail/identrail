import { useId } from 'react';

type TrustGraphIllustrationProps = {
  className?: string;
  label: string;
};

const nodes = [
  { id: 'n1', label: 'K8s SA', x: 14, y: 50, tone: 'blue' },
  { id: 'n2', label: 'OIDC', x: 34, y: 26, tone: 'blue' },
  { id: 'n3', label: 'AWS Role', x: 55, y: 48, tone: 'purple' },
  { id: 'n4', label: 'Vault', x: 70, y: 24, tone: 'purple' },
  { id: 'n5', label: 'S3', x: 84, y: 54, tone: 'blue' },
  { id: 'n6', label: 'CI Token', x: 33, y: 72, tone: 'purple' },
  { id: 'n7', label: 'Policy', x: 57, y: 74, tone: 'blue' }
] as const;

const edges = [
  ['n1', 'n2'],
  ['n2', 'n3'],
  ['n3', 'n4'],
  ['n3', 'n5'],
  ['n1', 'n6'],
  ['n6', 'n7'],
  ['n7', 'n5']
] as const;

export function TrustGraphIllustration({ className, label }: TrustGraphIllustrationProps) {
  const classes = className ? `trust-graph ${className}` : 'trust-graph';
  const gradientID = useId().replace(/:/g, '-');

  return (
    <div className={classes} role="img" aria-label={label}>
      <svg className="trust-graph-lines" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        {edges.map(([from, to]) => {
          const start = nodes.find((node) => node.id === from);
          const end = nodes.find((node) => node.id === to);
          if (!start || !end) return null;

          return (
            <line
              key={`${from}-${to}`}
              x1={start.x}
              y1={start.y}
              x2={end.x}
              y2={end.y}
              stroke={`url(#${gradientID})`}
              strokeWidth="0.7"
              strokeLinecap="round"
            />
          );
        })}
        <defs>
          <linearGradient id={gradientID} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#933aeb" />
          </linearGradient>
        </defs>
      </svg>

      {nodes.map((node) => (
        <span
          key={node.id}
          className={`trust-node ${node.tone} trust-node-${node.id}`}
        >
          <span>{node.label}</span>
        </span>
      ))}
    </div>
  );
}
