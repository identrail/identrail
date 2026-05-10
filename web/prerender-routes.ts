/**
 * Routes to render to static HTML at build time.
 *
 * Keep in sync with web/src/lib/seoMap.ts. Legacy paths
 * (/features/*, /solutions/*, /roi-assessment, /read-only-scan,
 * /deployment-models) intentionally do not appear here — they redirect
 * via vercel.json and we don't want to ship empty redirect HTML to
 * search indexers.
 */
export const PRERENDER_ROUTES = [
  '/',
  '/product',
  '/integrations',
  '/pricing',
  '/demo',
  '/about',
  '/security',
  '/responsible-disclosure',
  '/enterprise',
  '/faq',
  '/docs',
  '/blog',
  '/blog/machine-identity-security-operating-model-2026',
  '/blog/aws-nhi-security-misconfigurations',
  '/blog/kubernetes-machine-identity-rbac-risk-paths',
  '/blog/repo-exposure-program-machine-identities',
  '/blog/open-core-vs-closed-machine-identity-security',
  '/blog/least-privilege-evidence-for-non-human-identities',
  '/blog/rollout-safe-authorization-controls',
  '/blog/trust-graph-metrics-for-security-leaders',
  '/for/security-teams',
  '/for/platform-engineering',
  '/privacy',
  '/terms',
  '/privacy-choices'
] as const;
