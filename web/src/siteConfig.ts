/**
 * Centralized site configuration.
 *
 * Anything referenced from multiple pages (URLs, nav structure, brand
 * identity, social links) lives here. Per-page copy lives next to the page
 * component.
 */

export const SITE_URL = 'https://www.identrail.com';
export const SITE_NAME = 'Identrail';

export const TAGLINE = 'See every machine identity path. Fix the risky ones safely.';
export const SHORT_DESCRIPTION =
  'Identrail shows how AWS IAM, Kubernetes, and GitHub OIDC paths reach sensitive systems, then gives teams the safest fix.';

export const GITHUB_ORG = 'https://github.com/identrail';
export const GITHUB_REPO = 'https://github.com/identrail/identrail';
export const GITHUB_REPO_OWNER = 'identrail';
export const GITHUB_REPO_NAME = 'identrail';
export const DOCS_REPO = 'https://github.com/identrail/identrail/tree/dev/docs';
export const RELEASES_URL = 'https://github.com/identrail/identrail/releases';
export const DOCKER_REPO_URL = 'https://github.com/identrail/identrail/blob/dev/deploy/docker/README.md';
export const CONTRIBUTING_URL = 'https://github.com/identrail/identrail/blob/dev/CONTRIBUTING.md';

export const DISCORD_URL = 'https://discord.gg/7jSUSnQC';
export const LINKEDIN_URL = 'https://www.linkedin.com/company/identrail/';
export const X_URL = 'https://x.com/identrail';

export const CALENDLY_URL = 'https://calendly.com/identrail/15min';

export const FOUNDER = {
  name: 'Oluwatobi Mustapha',
  shortName: 'Oluwatobi',
  initials: 'OM',
  portrait: '/founders/oluwatobi-mustapha.jpeg',
  title: 'Founder & CEO',
  pitch: 'Cloud IAM Security Engineer · Non-Human Identity · OSS Contributor',
  linkedin: 'https://www.linkedin.com/in/oluwatobimustapha',
  bio: [
    'I build and secure IAM systems across cloud and distributed environments, with a focus on least-privilege architecture for both human and machine identities.',
    'I am a member of the AWS Community Builders program and of The Identity Underground, the Silver Fort–backed community for identity-security practitioners.'
  ]
} as const;

export const COMPANY = {
  founded: 2025,
  legalName: 'Identrail, Inc.',
  registered: 'Delaware, USA',
  contactEmail: 'hello@identrail.com',
  securityEmail: 'security@identrail.com'
} as const;

export type NavLink = { to: string; label: string; external?: boolean };

export const PRIMARY_NAV: readonly NavLink[] = [
  { to: '/product', label: 'Product' },
  { to: '/docs', label: 'Docs' },
  { to: '/about', label: 'Company' },
  { to: '/pricing', label: 'Pricing' },
  { to: '/blog', label: 'Blog' }
] as const;

export const FOOTER_NAV: readonly { heading: string; links: readonly NavLink[] }[] = [
  {
    heading: 'Product',
    links: [
      { to: '/product', label: 'Product' },
      { to: '/integrations', label: 'Integrations' },
      { to: '/pricing', label: 'Pricing' },
      { to: '/demo', label: 'Book a demo' },
      { to: '/security', label: 'Security' }
    ]
  },
  {
    heading: 'Solutions',
    links: [
      { to: '/for/security-teams', label: 'Security teams' },
      { to: '/for/platform-engineering', label: 'Platform engineering' },
      { to: '/enterprise', label: 'Enterprise' }
    ]
  },
  {
    heading: 'Open source',
    links: [
      { to: GITHUB_REPO, label: 'GitHub repo', external: true },
      { to: DOCS_REPO, label: 'Documentation', external: true },
      { to: RELEASES_URL, label: 'Changelog', external: true },
      { to: '/responsible-disclosure', label: 'Responsible disclosure' }
    ]
  },
  {
    heading: 'Company',
    links: [
      { to: '/about', label: 'About' },
      { to: '/blog', label: 'Blog' },
      { to: '/faq', label: 'FAQ' },
      { to: '/privacy', label: 'Privacy' },
      { to: '/terms', label: 'Terms' }
    ]
  }
] as const;

/**
 * Canonical list of stack integrations Identrail covers. The order also drives
 * the home-page "Reviewed across your identity stack" strip and the
 * /integrations page.
 *
 * Logo files live in /public/brand-logos. New stacks need an SVG dropped there
 * and a row added here.
 */
export type StackEntry = {
  id: string;
  name: string;
  logo: string;
  href: string;
  category:
    | 'Cloud IAM'
    | 'Container & orchestration'
    | 'CI/CD & SCM'
    | 'Identity provider'
    | 'Infrastructure-as-code'
    | 'Data store'
    | 'Observability';
};

export const STACK: readonly StackEntry[] = [
  { id: 'aws',         name: 'AWS IAM',         logo: '/brand-logos/aws.svg',         href: 'https://aws.amazon.com/iam/',         category: 'Cloud IAM' },
  { id: 'kubernetes',  name: 'Kubernetes',      logo: '/brand-logos/kubernetes.svg',  href: 'https://kubernetes.io',               category: 'Container & orchestration' },
  { id: 'github',      name: 'GitHub Actions',  logo: '/brand-logos/github.svg',      href: 'https://github.com/features/actions', category: 'CI/CD & SCM' },
  { id: 'oidc',        name: 'OpenID Connect',  logo: '/brand-logos/openid.svg',      href: 'https://openid.net/connect/',         category: 'Identity provider' },
  { id: 'terraform',   name: 'Terraform',       logo: '/brand-logos/terraform.svg',   href: 'https://www.terraform.io',            category: 'Infrastructure-as-code' },
  { id: 'docker',      name: 'Docker',          logo: '/brand-logos/docker.svg',      href: 'https://www.docker.com',              category: 'Container & orchestration' },
  { id: 'postgres',    name: 'PostgreSQL',      logo: '/brand-logos/postgresql.svg',  href: 'https://www.postgresql.org',          category: 'Data store' },
  { id: 'prometheus',  name: 'Prometheus',      logo: '/brand-logos/prometheus.svg',  href: 'https://prometheus.io',               category: 'Observability' }
] as const;

/**
 * Legacy alias map. Existing pages and tests still import { siteLinks }.
 * Keeping a small alias preserves them while we move callers to the named
 * exports above.
 */
export const siteLinks = {
  app: '/app',
  signIn: '/app/login',
  platform: '/product',
  useCases: '/for/security-teams',
  solutions: '/for/security-teams',
  resources: '/docs',
  company: '/about',
  pricing: '/pricing',
  docs: '/docs',
  github: GITHUB_REPO,
  blog: '/blog',
  discord: DISCORD_URL,
  starOnGithub: GITHUB_REPO,
  requestDemo: '/demo',
  getStarted: '/app',
  watchDemo: '/demo',
  contribute: CONTRIBUTING_URL,
  quickstartDocker: DOCKER_REPO_URL,
  webSource: 'https://github.com/identrail/identrail/tree/dev/web',
  integrations: '/integrations',
  legalPrivacy: '/privacy',
  legalTerms: '/terms',
  legalCookies: '/privacy-choices',
  security: '/security',
  trustCenter: '/security',
  contact: '/responsible-disclosure',
  linkedin: LINKEDIN_URL,
  x: X_URL
} as const;

export const githubRepo = {
  owner: GITHUB_REPO_OWNER,
  name: GITHUB_REPO_NAME
} as const;

export const projectMetricsSource = {
  github: githubRepo,
  dockerHubRepos: ['identrail/api', 'identrail/worker', 'identrail/web']
} as const;
