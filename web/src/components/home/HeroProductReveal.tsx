const GRAPH_NODES = [
  {
    className: 'is-source',
    label: 'GitHub Actions OIDC',
    meta: 'workflow identity',
    initials: 'GH'
  },
  {
    className: 'is-role',
    label: 'AWS role',
    meta: 'assume-role trust',
    initials: 'AWS'
  },
  {
    className: 'is-workload',
    label: 'K8s service account',
    meta: 'namespace binding',
    initials: 'K8s'
  },
  {
    className: 'is-target',
    label: 'Billing datastore',
    meta: 'regulated resource',
    initials: 'DB'
  }
] as const;

const EVIDENCE_PACKETS = [
  {
    code: 'E-014',
    title: 'OIDC subject wildcard',
    meta: 'github/org/* can assume production role',
    tone: 'warning'
  },
  {
    code: 'E-029',
    title: 'Namespace bridge',
    meta: 'payments-api reaches shared platform role',
    tone: 'neutral'
  },
  {
    code: 'E-041',
    title: 'Sensitive target reached',
    meta: 'billing-ledger tagged production',
    tone: 'critical'
  }
] as const;

const POLICY_DIFF = [
  { marker: '-', value: 'repo:org/*:ref:*' },
  { marker: '+', value: 'repo:org/payments:ref:refs/heads/main' },
  { marker: '+', value: 'aud: sts.amazonaws.com' }
] as const;

const CONNECTOR_SCOPES = [
  ['AWS', 'iam:GetRole, iam:ListPolicies'],
  ['K8s', 'rbac.authorization.k8s.io read'],
  ['GitHub', 'actions:read, contents:read'],
  ['OIDC', 'issuer, audience, subject claims']
] as const;

export function HeroProductReveal() {
  return (
    <div className="idt-hero-product-stage" aria-label="Identrail product preview">
      <section className="idt-hero-atlas" aria-label="Machine identity trust graph preview">
        <div className="idt-hero-atlas-panel">
          <div className="idt-atlas-toolbar">
            <div>
              <span>Production workspace</span>
              <strong>Trust graph path MITG-204</strong>
            </div>
            <span className="idt-atlas-state">Risk review ready</span>
          </div>

          <div className="idt-atlas-map">
            <svg className="idt-atlas-routes" viewBox="0 0 760 420" role="img" aria-label="Highlighted trust path">
              <path className="idt-route-shadow" d="M112 116 C246 78 286 220 378 202 C492 180 500 76 638 104" />
              <path className="idt-route-main" d="M112 116 C246 78 286 220 378 202 C492 180 500 76 638 104" />
              <path className="idt-route-secondary" d="M104 316 C242 276 332 342 446 308 C550 276 574 220 664 246" />
              <path className="idt-route-secondary" d="M178 164 C232 238 268 282 358 292" />
              <circle className="idt-route-pulse" cx="378" cy="202" r="9" />
            </svg>

            {GRAPH_NODES.map((node) => (
              <article key={node.label} className={`idt-atlas-node ${node.className}`}>
                <span>{node.initials}</span>
                <strong>{node.label}</strong>
                <small>{node.meta}</small>
              </article>
            ))}

          </div>
        </div>

        <aside className="idt-evidence-stack" aria-label="Evidence packets">
          <div className="idt-evidence-stack-head">
            <span>Evidence packets</span>
            <strong>3 attached</strong>
          </div>
          <div className="idt-blast-radius-card" aria-label="Blast radius summary">
            <span>Blast radius</span>
            <strong>14 production resources</strong>
            <small>2 accounts, 3 namespaces, 1 regulated datastore</small>
          </div>
          {EVIDENCE_PACKETS.map((packet) => (
            <article key={packet.code} className={`idt-evidence-packet is-${packet.tone}`}>
              <span>{packet.code}</span>
              <div>
                <strong>{packet.title}</strong>
                <small>{packet.meta}</small>
              </div>
            </article>
          ))}
        </aside>

        <aside className="idt-policy-diff-card" aria-label="Policy diff preview">
          <div>
            <span>First safe fix</span>
            <strong>OIDC trust policy diff</strong>
          </div>
          <code>
            {POLICY_DIFF.map((line) => (
              <span key={`${line.marker}-${line.value}`} className={line.marker === '-' ? 'is-remove' : 'is-add'}>
                <b>{line.marker}</b>
                {line.value}
              </span>
            ))}
          </code>
        </aside>

        <div className="idt-connector-scope-rail" aria-label="Read-only connector scopes">
          {CONNECTOR_SCOPES.map(([name, scope]) => (
            <span key={name}>
              <strong>{name}</strong>
              {scope}
            </span>
          ))}
        </div>
      </section>
    </div>
  );
}
