export const siteLinks = {
  app: '/app',
  signIn: '/signin',
  platform: '/product',
  useCases: '/solutions',
  solutions: '/solutions',
  resources: '/docs',
  company: '/about',
  pricing: '/pricing',
  docs: '/docs',
  github: 'https://github.com/identrail/identrail',
  blog: '/blog',
  discord: 'https://discord.gg/7jSUSnQC',
  starOnGithub: 'https://github.com/identrail/identrail',
  requestDemo: '/demo',
  getStarted: '/signup',
  watchDemo: '/demo',
  contribute: 'https://github.com/identrail/identrail/blob/dev/CONTRIBUTING.md',
  quickstartDocker: 'https://github.com/identrail/identrail/blob/dev/deploy/docker/README.md',
  webSource: 'https://github.com/identrail/identrail/tree/dev/web',
  reportDownload: '/blog/machine-identity-security-operating-model-2026',
  accessGraph: '/features/trust-graph',
  platformOverview: '/product',
  howWeDoIt: '/product',
  impactQueries: 'https://github.com/identrail/identrail',
  detectionEngine: 'https://github.com/identrail/identrail/tree/dev/internal/providers',
  interactiveDemo: '/demo',
  agentRelease: 'https://github.com/identrail/identrail',
  technicalDocs: '/docs',
  findingsDocs: '/docs',
  policyDocs: '/docs',
  repoScannerDocs: '/docs',
  whyIdentrail: '/product',
  platformDemo: '/demo',
  blogInsights: '/blog',
  agenticAiRoadmap: '/blog/machine-identity-security-operating-model-2026',
  agenticAi: '/security',
  integrations: '/integrations',
  legalPrivacy: '/privacy',
  legalTerms: '/terms',
  legalCookies: '/privacy-choices',
  security: '/security',
  trustCenter: '/security', // TODO: add dedicated /trust-center route later.
  contact: '/responsible-disclosure',
  changelog: 'https://github.com/identrail/identrail/blob/dev/CHANGELOG.md',
  linkedin: 'https://www.linkedin.com/company/identrail',
  x: 'https://x.com/identrail'
} as const;

export const githubRepo = {
  owner: 'identrail',
  name: 'identrail'
} as const;

export const projectMetricsSource = {
  github: githubRepo,
  dockerHubRepos: [
    'identrail/identrail',
    'identrail/identrail-api',
    'identrail/identrail-worker',
    'identrail/identrail-web',
    'identrail/identrail-agent'
  ]
} as const;
