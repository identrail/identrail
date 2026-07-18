export const siteEmails = {
  contact: 'contact@identrail.com',
  support: 'support@identrail.com',
  security: 'security@identrail.com',
  marketing: 'marketing@identrail.com',
  founder: 'founder@identrail.com'
} as const;

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
  requestDemo: '/product',
  getStarted: '/signup',
  watchDemo: '/product',
  contribute: 'https://github.com/identrail/identrail/blob/dev/CONTRIBUTING.md',
  quickstartDocker: 'https://github.com/identrail/identrail/blob/dev/deploy/docker/README.md',
  webSource: 'https://github.com/identrail/identrail/tree/dev/web',
  reportDownload: '/blog/machine-identity-security-operating-model-2026',
  accessGraph: '/features/trust-graph',
  platformOverview: '/product',
  howWeDoIt: '/product',
  impactQueries: 'https://github.com/identrail/identrail',
  detectionEngine: 'https://github.com/identrail/identrail/tree/dev/internal/providers',
  interactiveDemo: '/product',
  agentRelease: 'https://github.com/identrail/identrail',
  technicalDocs: '/docs',
  findingsDocs: '/docs',
  policyDocs: '/docs',
  repoScannerDocs: '/docs',
  whyIdentrail: '/product',
  platformDemo: '/product',
  blogInsights: '/blog',
  agenticAiRoadmap: '/blog/machine-identity-security-operating-model-2026',
  agenticAi: '/security',
  integrations: '/integrations',
  legalPrivacy: '/privacy',
  legalTerms: '/terms',
  legalCookies: '/privacy-choices',
  security: '/security',
  trustCenter: '/security', // TODO: add dedicated /trust-center route later.
  contact: `mailto:${siteEmails.contact}`,
  changelog: 'https://github.com/identrail/identrail/blob/dev/CHANGELOG.md',
  linkedin: 'https://www.linkedin.com/company/identrail',
  x: 'https://x.com/identrail'
} as const;

export const projectMetricsSource = {
  dockerHubRepos: ['identrail/identrail']
} as const;
