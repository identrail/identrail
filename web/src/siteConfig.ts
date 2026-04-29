// TODO: Oluwatobi will update real URL later.
export const siteLinks = {
  platform: '/platform',
  useCases: '/solutions',
  solutions: '/solutions',
  resources: '/resources',
  company: '/about',
  pricing: '/pricing',
  docs: '/docs',
  github: 'https://github.com/identrail/identrail',
  blog: '/blog',
  discord: 'https://discord.gg/7jSUSnQC',
  starOnGithub: 'https://github.com/identrail/identrail',
  requestDemo: '/demo',
  getStarted: 'https://github.com/identrail/identrail',
  watchDemo: '/demo',
  contribute: '/contribute',
  quickstartDocker: 'https://github.com/identrail/identrail/blob/main/deploy/docker/README.md',
  webSource: 'https://github.com/identrail/identrail/tree/main/web',
  reportDownload: '/resources/2026-state-of-machine-identity',
  accessGraph: '/features/trust-graph',
  platformOverview: '/platform',
  howWeDoIt: '/product',
  impactQueries: 'https://github.com/identrail/identrail',
  detectionEngine: 'https://github.com/identrail/identrail/tree/main/internal/detection',
  interactiveDemo: '/demo',
  agentRelease: 'https://github.com/identrail/identrail',
  technicalDocs: '/docs/technical-console',
  findingsDocs: '/docs/findings-queue',
  policyDocs: '/docs',
  repoScannerDocs: '/docs/repo-scanner',
  whyIdentrail: '/platform/why-identrail',
  platformDemo: '/request-demo',
  blogInsights: '/blog',
  agenticAi: '/use-cases/agentic-ai-security',
  integrations: '/integrations',
  legalPrivacy: '/privacy',
  legalTerms: '/terms',
  legalCookies: '/privacy-choices',
  security: '/security',
  trustCenter: '/trust-center',
  contact: '/contact',
  linkedin: 'https://www.linkedin.com/company/identrail',
  x: 'https://x.com/identrail'
} as const;

export const githubRepo = {
  owner: 'identrail',
  name: 'identrail'
} as const;

// TODO: Oluwatobi will update real Docker Hub repos later if namespace changes.
export const projectMetricsSource = {
  github: githubRepo,
  dockerHubRepos: ['identrail/api', 'identrail/worker', 'identrail/web']
} as const;
