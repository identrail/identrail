import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

type HeroNode = {
  id: string;
  label: string;
  x: number;
  y: number;
  tone: 'source' | 'broker' | 'workload' | 'privilege' | 'resource';
};

type HeroEdge = {
  from: string;
  to: string;
  emphasis?: 'high' | 'medium';
};

type HeroScene = {
  id: string;
  label: string;
  findingTitle: string;
  findingSummary: string;
  severity: 'High severity' | 'Medium severity';
  hopsLabel: string;
  modeLabel: string;
  steps: readonly string[];
  capabilities: readonly string[];
  nodes: readonly HeroNode[];
  edges: readonly HeroEdge[];
};

const SCENES: readonly HeroScene[] = [
  {
    id: 'oidc-chain',
    label: 'CI/CD OIDC chain',
    findingTitle: 'High-risk production trust path',
    findingSummary: 'GitHub Actions OIDC → AWS Role → K8s Service Account → RDS Billing Resource',
    severity: 'High severity',
    hopsLabel: '4-hop chain',
    modeLabel: 'Read-only analysis',
    steps: [
      'Source: GitHub Actions workflow identity',
      'Broker: OIDC trust relationship',
      'Privilege boundary: AWS IAM role assumption',
      'Target: production billing datastore'
    ],
    capabilities: ['Correlates identity chain', 'Calculates blast radius', 'Prioritizes safe first fix'],
    nodes: [
      { id: 'src-gha', label: 'GitHub Actions OIDC', x: 18, y: 20, tone: 'source' },
      { id: 'broker-oidc', label: 'OIDC Provider', x: 50, y: 31, tone: 'broker' },
      { id: 'role-aws', label: 'AWS Role: billing-prod', x: 72, y: 47, tone: 'privilege' },
      { id: 'k8s-sa', label: 'K8s SA: payments-api', x: 42, y: 64, tone: 'workload' },
      { id: 'rds', label: 'RDS: billing-ledger', x: 73, y: 76, tone: 'resource' }
    ],
    edges: [
      { from: 'src-gha', to: 'broker-oidc', emphasis: 'medium' },
      { from: 'broker-oidc', to: 'role-aws', emphasis: 'high' },
      { from: 'role-aws', to: 'k8s-sa', emphasis: 'high' },
      { from: 'k8s-sa', to: 'rds', emphasis: 'high' }
    ]
  },
  {
    id: 'k8s-drift',
    label: 'K8s service account drift',
    findingTitle: 'Cross-boundary service account drift',
    findingSummary: 'K8s SA → AssumeRole policy → Shared IAM role → S3 Config bucket',
    severity: 'High severity',
    hopsLabel: '4-hop chain',
    modeLabel: 'Policy simulation',
    steps: [
      'Source: payments-api service account token',
      'Broker: IAM trust condition mismatch',
      'Privilege boundary: shared platform role reuse',
      'Target: config artifact bucket with broad read'
    ],
    capabilities: ['Detects trust drift', 'Explains policy evidence', 'Simulates non-breaking remediation'],
    nodes: [
      { id: 'k8s-sa', label: 'K8s SA: payments-api', x: 22, y: 25, tone: 'workload' },
      { id: 'iam-trust', label: 'IAM Trust Policy', x: 48, y: 38, tone: 'broker' },
      { id: 'platform-role', label: 'AWS Role: shared-platform', x: 74, y: 45, tone: 'privilege' },
      { id: 'config-store', label: 'S3: prod-config-artifacts', x: 64, y: 76, tone: 'resource' },
      { id: 'runtime', label: 'Prod namespace runtime', x: 29, y: 70, tone: 'source' }
    ],
    edges: [
      { from: 'k8s-sa', to: 'iam-trust', emphasis: 'medium' },
      { from: 'iam-trust', to: 'platform-role', emphasis: 'high' },
      { from: 'platform-role', to: 'config-store', emphasis: 'high' },
      { from: 'k8s-sa', to: 'runtime', emphasis: 'medium' }
    ]
  },
  {
    id: 'token-leak',
    label: 'Leaked deploy token path',
    findingTitle: 'Leaked token expands blast radius',
    findingSummary: 'Git repo secret → CI runner token → ECR push role → ECS production task',
    severity: 'Medium severity',
    hopsLabel: '4-hop chain',
    modeLabel: 'Containment workflow',
    steps: [
      'Source: repository secret exposure event',
      'Broker: CI runner token replay path',
      'Privilege boundary: ECR push role assumptions',
      'Target: production task image deployment path'
    ],
    capabilities: ['Links repo event to cloud reachability', 'Scores real production impact', 'Outputs containment sequence'],
    nodes: [
      { id: 'repo-secret', label: 'Repo Secret Event', x: 20, y: 23, tone: 'source' },
      { id: 'runner-token', label: 'CI Runner Token', x: 44, y: 36, tone: 'broker' },
      { id: 'ecr-role', label: 'AWS Role: ecr-push-prod', x: 70, y: 44, tone: 'privilege' },
      { id: 'ecr-repo', label: 'ECR: payments-api', x: 53, y: 66, tone: 'resource' },
      { id: 'ecs-task', label: 'ECS Task: prod-payments', x: 77, y: 76, tone: 'workload' }
    ],
    edges: [
      { from: 'repo-secret', to: 'runner-token', emphasis: 'medium' },
      { from: 'runner-token', to: 'ecr-role', emphasis: 'high' },
      { from: 'ecr-role', to: 'ecr-repo', emphasis: 'high' },
      { from: 'ecr-repo', to: 'ecs-task', emphasis: 'medium' }
    ]
  }
];

const LOOP_INTERVAL_MS = 4400;

function usePrefersReducedMotion() {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }

    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setPrefersReducedMotion(media.matches);
    update();

    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', update);
      return () => media.removeEventListener('change', update);
    }

    media.addListener(update);
    return () => media.removeListener(update);
  }, []);

  return prefersReducedMotion;
}

function findNode(nodes: readonly HeroNode[], id: string) {
  return nodes.find((node) => node.id === id);
}

function edgePath(from: HeroNode, to: HeroNode) {
  const startX = from.x;
  const startY = from.y;
  const endX = to.x;
  const endY = to.y;
  const dx = endX - startX;
  const dy = endY - startY;
  const bend = Math.min(14, Math.max(6, Math.abs(dx) * 0.18 + Math.abs(dy) * 0.1));
  const c1x = startX + dx * 0.32;
  const c1y = startY + dy * 0.14 - bend;
  const c2x = endX - dx * 0.26;
  const c2y = endY - dy * 0.12 + bend * 0.25;
  return `M ${startX} ${startY} C ${c1x} ${c1y} ${c2x} ${c2y} ${endX} ${endY}`;
}

export function HeroProductReveal() {
  const reducedMotion = usePrefersReducedMotion();
  const [activeSceneIndex, setActiveSceneIndex] = useState(0);
  const activeScene = SCENES[activeSceneIndex];

  useEffect(() => {
    if (reducedMotion) {
      return;
    }

    const timer = window.setInterval(() => {
      setActiveSceneIndex((current) => (current + 1) % SCENES.length);
    }, LOOP_INTERVAL_MS);

    return () => window.clearInterval(timer);
  }, [reducedMotion]);

  const sceneLayer = useMemo(() => {
    const scene = activeScene;
    return (
      <div key={scene.id} className="idt-hero-layer is-active">
        <svg className="idt-hero-arrows" viewBox="0 0 100 100" preserveAspectRatio="none">
          <defs>
            <filter id={`idt-edge-glow-${scene.id}`} x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="0.26" result="blurred" />
              <feMerge>
                <feMergeNode in="blurred" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {scene.edges.map((edge, edgeIndex) => {
            const from = findNode(scene.nodes, edge.from);
            const to = findNode(scene.nodes, edge.to);
            if (!from || !to) {
              return null;
            }

            const path = edgePath(from, to);

            return (
              <g key={`${scene.id}-${edge.from}-${edge.to}`}>
                <path className={`idt-hero-arrow-base ${edge.emphasis === 'high' ? 'is-high' : ''}`} d={path} />
                <path
                  className={`idt-hero-arrow-flow idt-hero-edge-delay-${edgeIndex} ${edge.emphasis === 'high' ? 'is-high' : ''}`}
                  d={path}
                  filter={`url(#idt-edge-glow-${scene.id})`}
                />
                <circle
                  className={`idt-hero-arrow-end ${edge.emphasis === 'high' ? 'is-high' : ''}`}
                  cx={to.x}
                  cy={to.y}
                  r={edge.emphasis === 'high' ? 0.9 : 0.7}
                />
              </g>
            );
          })}
        </svg>

        {scene.nodes.map((node) => (
          <div
            key={`${scene.id}-${node.id}`}
            className={`idt-node idt-node-${node.tone} idt-node-${scene.id}-${node.id}`}
          >
            {node.label}
          </div>
        ))}
      </div>
    );
  }, [activeScene, reducedMotion]);

  return (
    <div className="idt-graph-visual idt-graph-visual-live" aria-label="Live trust path product preview">
      <div className="idt-hero-live-layout">
        <div className="idt-hero-graph-canvas" aria-hidden="true">
          <div className="idt-graph-grid" />
          <div className="idt-hero-graph-plane idt-hero-graph-plane-back" />
          <div className="idt-hero-graph-plane idt-hero-graph-plane-mid" />
          {sceneLayer}
        </div>

        <aside className="idt-hero-graph-caption idt-hero-proof-card">
          <div className="idt-hero-layer-head">
            <p className="idt-hero-graph-title">Live finding layer</p>
            <div className="idt-hero-layer-dots" aria-label="Live scene steps">
              {SCENES.map((scene, index) => (
                <button
                  key={scene.id}
                  type="button"
                  className={index === activeSceneIndex ? 'is-active' : ''}
                  onClick={() => setActiveSceneIndex(index)}
                  aria-label={`Show ${scene.label}`}
                />
              ))}
            </div>
          </div>

          <h3>{activeScene.findingTitle}</h3>
          <p className="idt-hero-path">{activeScene.findingSummary}</p>

          <div className="idt-hero-proof-meta">
            <span className="idt-severity-pill">{activeScene.severity}</span>
            <span>{activeScene.hopsLabel}</span>
            <span>{activeScene.modeLabel}</span>
          </div>

          <ol className="idt-hero-path-steps">
            {activeScene.steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>

          <ul className="idt-hero-capability-list">
            {activeScene.capabilities.map((capability) => (
              <li key={capability}>{capability}</li>
            ))}
          </ul>

          <Link to="/demo" className="idt-inline-link">
            Inspect this path in demo
          </Link>
        </aside>
      </div>
    </div>
  );
}
