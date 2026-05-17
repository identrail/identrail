import { FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { BrowserRouter, Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { SafeLink } from './components/SafeLink';
import { HeroProductReveal } from './components/home/HeroProductReveal';
import { HeroOpenSourceProofPills } from './components/home/HeroOpenSourceProofPills';
import { HowItWorksSection } from './components/home/HowItWorksSection';
import { CommandCenterSection } from './components/home/CommandCenterSection';
import { ProblemFramingSection } from './components/home/ProblemFramingSection';
import { TrustProofStrip } from './components/home/TrustProofStrip';
import { Footer } from './components/layout/Footer';
import { Header } from './components/layout/Header';
import { apiClient } from './api/client';
import { BLOG_POSTS, DOC_ENTRIES, HOME_FAQ_ITEMS } from './content/resources';
import { AccountSecurityPage } from './pages/AccountSecurityPage';
import { AuthCallbackPage } from './pages/AuthCallbackPage';
import { SignInPage } from './pages/SignInPage';
import { SignUpPage } from './pages/SignUpPage';
import { WorkOSMFAPage } from './pages/WorkOSMFAPage';
import { WhyNoPasswordsPage } from './pages/WhyNoPasswordsPage';
import { ConnectPage } from './pages/onboarding/ConnectPage';
import { InvitePage } from './pages/onboarding/InvitePage';
import { OrgPage } from './pages/onboarding/OrgPage';
import { ScanPage } from './pages/onboarding/ScanPage';
import { WorkspacePage } from './pages/onboarding/WorkspacePage';
import { RequireOnboardingBackend } from './components/onboarding/OnboardingAvailability';
import {
  ProductAppIndexRedirect,
  ProductAuthCallbackRedirectPage,
  ProductExecutiveReportPage,
  ProductFindingsPage,
  ProductGitHubCallbackPage,
  ProductLoginPage,
  ProductLogoutPage,
  ProductOverviewPage,
  ProductProjectDetailPage,
  ProductProjectsPage,
  RequireProductAuth,
  ProductSettingsPage,
  ProductShellLayout,
  ProductWorkspacesPage
} from './productShell';

type SeoConfig = {
  title: string;
  description: string;
  path: string;
  keywords?: string;
  schemaType?: 'WebPage' | 'Product' | 'Article' | 'AboutPage';
};

declare global {
  interface Window {
    gtag?: (...args: unknown[]) => void;
    posthog?: {
      capture: (event: string, properties?: Record<string, unknown>) => void;
    };
  }
}

const SITE_URL = 'https://www.identrail.com';
const GITHUB_REPO = 'https://github.com/identrail/identrail';
const DOCS_REPO = 'https://github.com/identrail/identrail/tree/dev/docs';
const DISCORD_URL = 'https://discord.gg/7jSUSnQC';
const LINKEDIN_URL = 'https://www.linkedin.com/company/identrail/';
const X_URL = 'https://x.com/identrail';
const CALENDLY_URL = 'https://calendly.com/identrail/15min';
const THEME_STORAGE_KEY = 'identrail-theme';
let activeModalLocks = 0;
let bodyOverflowBeforeModal = '';

const NAV_LINKS = [
  { to: '/product', label: 'Product' },
  { to: '/docs', label: 'Docs' },
  { to: '/about', label: 'Company' },
  { to: '/pricing', label: 'Pricing' },
  { to: '/blog', label: 'Blog' }
] as const;

const HOME_FAQ_PREVIEW = HOME_FAQ_ITEMS.slice(0, 4);

const DIFFERENTIATION_ROWS = [
  {
    area: 'Trust-path explainability',
    identrail: 'Shows full identity chain with policy evidence and affected resources',
    closed: 'Often returns abstract risk findings without chain-level context'
  },
  {
    area: 'Rollout safety',
    identrail: 'Read-only collection, simulation-first remediation, staged enforcement',
    closed: 'Policy hardening usually relies on external tooling and manual checks'
  },
  {
    area: 'Open-core transparency',
    identrail: 'Public repository, documentation, and release history',
    closed: 'Limited implementation visibility and slower verification by engineers'
  },
  {
    area: 'Developer and platform fit',
    identrail: 'Built for security + platform collaboration with inspectable outputs',
    closed: 'Security-only workflows can be harder for platform teams to operationalize'
  }
] as const;

const PRODUCT_TOUR_STEPS = [
  {
    step: '01',
    title: 'Connect read-only sources',
    detail: 'Validate AWS IAM, Kubernetes, GitHub Actions, and OIDC claims without write permissions.',
    proof: 'Connector scope',
    active: true
  },
  {
    step: '02',
    title: 'Trace reachable risk paths',
    detail: 'Show the identity, workload, role, and resource in one chain with severity context.',
    proof: 'Reachable path',
    active: false
  },
  {
    step: '03',
    title: 'Simulate the first safe fix',
    detail: 'Preview trust-policy and RBAC edits before anything touches production.',
    proof: 'Policy simulation',
    active: false
  },
  {
    step: '04',
    title: 'Export the evidence packet',
    detail: 'Package the source proof, owner note, policy diff, and residual risk for review.',
    proof: 'Evidence packet',
    active: false
  }
] as const;

const PRODUCT_TOUR_CONNECTORS = [
  {
    name: 'AWS IAM',
    status: 'Read-only',
    icon: '/brand-logos/aws.svg'
  },
  {
    name: 'Kubernetes',
    status: 'Namespace scope',
    icon: '/brand-logos/kubernetes.svg'
  },
  {
    name: 'GitHub/OIDC',
    status: 'Claims only',
    icon: '/brand-logos/github.svg'
  }
] as const;

const PRODUCT_TOUR_PATH = [
  {
    label: 'Identity',
    value: 'GitHub Actions OIDC'
  },
  {
    label: 'Privilege',
    value: 'AWS IAM role: billing-prod'
  },
  {
    label: 'Workload',
    value: 'payments-api namespace'
  },
  {
    label: 'Resource',
    value: 'PostgreSQL billing ledger'
  }
] as const;

const PRODUCT_TOUR_PACKET = ['Source proof', 'Policy diff', 'Affected workload', 'Owner timeline'] as const;

const FEATURE_ROWS = [
  {
    capability: 'AWS IAM role discovery',
    openSource: 'Included',
    pro: 'Included',
    enterprise: 'Included'
  },
  {
    capability: 'Kubernetes RBAC and service account mapping',
    openSource: 'Included',
    pro: 'Included',
    enterprise: 'Included'
  },
  {
    capability: 'Git repository credential exposure scanning',
    openSource: 'Basic detectors',
    pro: 'Advanced signatures + workflows',
    enterprise: 'Advanced + custom signatures'
  },
  {
    capability: 'Trust graph explorer',
    openSource: 'Included',
    pro: 'Included + hosted query acceleration',
    enterprise: 'Included + custom graph retention'
  },
  {
    capability: 'Hosted SaaS',
    openSource: 'No',
    pro: 'Yes',
    enterprise: 'Yes'
  },
  {
    capability: 'SSO/SAML + SCIM',
    openSource: 'No',
    pro: 'SAML',
    enterprise: 'SAML + SCIM + advanced controls'
  },
  {
    capability: 'Data residency options',
    openSource: 'Self-host control',
    pro: 'US + EU',
    enterprise: 'Regional + private tenancy'
  },
  {
    capability: 'Support and SLAs',
    openSource: 'Community',
    pro: 'Business-hour support',
    enterprise: '24/7, named TAM, custom SLA'
  }
] as const;

const INTEGRATION_ROWS = [
  {
    source: 'AWS IAM',
    signals: 'Roles, trust policies, assumptions, account paths',
    depth: 'Deep',
    status: 'GA'
  },
  {
    source: 'Kubernetes',
    signals: 'Service accounts, RBAC bindings, namespace privilege paths',
    depth: 'Deep',
    status: 'GA'
  },
  {
    source: 'GitHub',
    signals: 'Workflow identities, OIDC trust, repository exposure telemetry',
    depth: 'Deep',
    status: 'GA'
  },
  {
    source: 'OpenID Connect',
    signals: 'Provider trust boundaries and subject claim controls',
    depth: 'Focused',
    status: 'GA'
  },
  {
    source: 'Prometheus',
    signals: 'Operational metrics for scans, workers, and authz policy telemetry',
    depth: 'Focused',
    status: 'GA'
  }
] as const;

const READ_ONLY_CONTROL_ROWS = [
  {
    area: 'Identity metadata collection',
    access: 'Read-only API calls for identity, policy, and relationship metadata',
    excluded: 'No secret material ingestion, no credential writeback'
  },
  {
    area: 'Policy simulation',
    access: 'Simulation engine evaluates proposed changes against collected graph state',
    excluded: 'No direct policy mutation during simulation'
  },
  {
    area: 'Remediation workflow',
    access: 'Action plans and exportable recommendations',
    excluded: 'No automatic enforcement without explicit operator action'
  }
] as const;

const FEATURE_DEEP_PAGES = [
  {
    slug: 'aws',
    navLabel: 'AWS',
    heroTitle: 'AWS IAM security with path-level explainability',
    description:
      'Discover roles, trust policies, and cross-account assumptions in one graph so teams can reduce IAM blast radius with confidence.',
    bullets: [
      'Map every role assumption chain and transitive trust path across accounts',
      'Prioritize overprivileged IAM paths by reachable sensitive resources',
      'Preview trust-policy hardening before production rollout'
    ],
    outcomes: [
      'Faster IAM triage for security engineering teams',
      'Clear remediation stories for platform owners',
      'Reduced high-risk cross-account pathways'
    ]
  },
  {
    slug: 'kubernetes',
    navLabel: 'Kubernetes',
    heroTitle: 'Kubernetes machine identity visibility beyond RBAC tables',
    description:
      'Correlate service accounts, tokens, roles, and bindings with cloud federation context to find exploitable privilege paths.',
    bullets: [
      'Trace namespace and cluster-level escalation paths from service accounts',
      'Understand cluster-to-cloud trust bridges through OIDC federation',
      'Simulate RBAC hardening changes to avoid workload breakage'
    ],
    outcomes: [
      'Lower RBAC drift and accidental privilege growth',
      'Safer service account governance in production clusters',
      'Faster root-cause analysis during identity incidents'
    ]
  },
  {
    slug: 'git-scanner',
    navLabel: 'Git Scanner',
    heroTitle: 'Repository exposure scanning tied directly to machine identity risk',
    description:
      'Catch leaked credentials and dangerous identity patterns in repositories, then connect each finding to live trust-path impact.',
    bullets: [
      'Scan historical and incoming commits for credentials and risky configs',
      'Tune detection signatures for organization-specific token patterns',
      'Link findings to trust graph nodes for prioritized remediation'
    ],
    outcomes: [
      'Earlier credential leak detection and containment',
      'Lower false-priority triage load for security teams',
      'Stronger software-to-cloud identity governance'
    ]
  },
  {
    slug: 'trust-graph',
    navLabel: 'Trust Graph',
    heroTitle: 'Interactive Trust Graph for machine identity attack-path analysis',
    description:
      'Visualize identity relationships end-to-end, inspect every edge, and answer exactly how a machine principal can reach sensitive resources.',
    bullets: [
      'Inspect path evidence with policy, principal, and resource context',
      'Highlight blast-radius expansion from any identity node',
      'Export remediation stories for engineering execution'
    ],
    outcomes: [
      'Common operating picture across security and platform teams',
      'Higher-confidence prioritization of real exposure chains',
      'Faster decision-making for authorization change control'
    ]
  }
] as const;

const SOLUTION_DEEP_PAGES = [
  {
    slug: 'aws',
    navLabel: 'AWS',
    heroTitle: 'Solution for AWS security teams',
    description:
      'Reduce IAM blast radius with explainable trust paths, prioritized exposure queues, and rollout-safe least-privilege workflows.',
    bullets: [
      'Continuously discover machine identities and trust relationships in AWS',
      'Detect high-impact assumption chains and overprivileged role paths',
      'Coordinate remediation with platform teams through shared graph evidence'
    ],
    outcomes: [
      '60-90% reduction in overprivileged IAM role exposure',
      'Faster incident-response triage for identity pathways',
      'Audit-ready visibility into trust policy changes'
    ]
  },
  {
    slug: 'kubernetes',
    navLabel: 'Kubernetes',
    heroTitle: 'Solution for Kubernetes platform teams',
    description:
      'Control service-account and RBAC risk in production clusters without slowing down release velocity.',
    bullets: [
      'Expose hidden service-account privilege escalation paths',
      'Correlate RBAC risk with cloud permissions and federated trust',
      'Roll out safer RBAC policy controls with staged validation'
    ],
    outcomes: [
      'Reduced cluster authorization incidents',
      'More predictable least-privilege rollouts',
      'Clear ownership of identity remediation tasks'
    ]
  },
  {
    slug: 'multi-cloud',
    navLabel: 'Multi-cloud',
    heroTitle: 'Solution for multi-cloud machine identity operations',
    description:
      'Unify fragmented identity posture and trust-path analysis across cloud and cluster boundaries with one operating model.',
    bullets: [
      'Normalize machine identity telemetry into one graph-backed workflow',
      'Apply consistent triage criteria across environments',
      'Track policy and exposure changes with centralized evidence'
    ],
    outcomes: [
      'Unified identity risk visibility across environments',
      'Lower operational overhead for security operations',
      'Improved governance consistency for compliance programs'
    ]
  },
  {
    slug: 'platform-engineering',
    navLabel: 'Platform Engineering',
    heroTitle: 'Solution for platform engineering organizations',
    description:
      'Ship authorization changes faster with simulation and staged rollout controls that protect production reliability.',
    bullets: [
      'Preview policy impact before enforcement',
      'Run controlled rollouts with rollback safety rails',
      'Share remediation context directly with service owners'
    ],
    outcomes: [
      'Faster delivery of least-privilege controls',
      'Lower risk of authorization-related outages',
      'Higher trust between security and platform teams'
    ]
  },
  {
    slug: 'security-teams',
    navLabel: 'Security Teams',
    heroTitle: 'Solution for security operations and detection teams',
    description:
      'Prioritize machine identity findings by exploitability and business impact, not by alert volume.',
    bullets: [
      'Surface high-signal findings tied to reachable critical assets',
      'Reduce queue noise with trust-path context and path scoring',
      'Route ownership quickly to teams that can execute remediation'
    ],
    outcomes: [
      'Lower mean time to remediation for identity findings',
      'Improved signal-to-noise in security queues',
      'Stronger executive reporting on identity risk reduction'
    ]
  }
] as const;

function upsertMetaByName(name: string, content: string) {
  let tag = document.querySelector(`meta[name="${name}"]`) as HTMLMetaElement | null;
  if (!tag) {
    tag = document.createElement('meta');
    tag.setAttribute('name', name);
    document.head.appendChild(tag);
  }
  tag.setAttribute('content', content);
}

function upsertMetaByProperty(property: string, content: string) {
  let tag = document.querySelector(`meta[property="${property}"]`) as HTMLMetaElement | null;
  if (!tag) {
    tag = document.createElement('meta');
    tag.setAttribute('property', property);
    document.head.appendChild(tag);
  }
  tag.setAttribute('content', content);
}

function upsertCanonical(path: string) {
  let link = document.querySelector('link[rel="canonical"]') as HTMLLinkElement | null;
  if (!link) {
    link = document.createElement('link');
    link.setAttribute('rel', 'canonical');
    document.head.appendChild(link);
  }
  link.setAttribute('href', `${SITE_URL}${path}`);
}

function upsertSchema(config: SeoConfig) {
  let tag = document.getElementById('identrail-schema') as HTMLScriptElement | null;
  if (!tag) {
    tag = document.createElement('script');
    tag.id = 'identrail-schema';
    tag.type = 'application/ld+json';
    document.head.appendChild(tag);
  }

  const schema = {
    '@context': 'https://schema.org',
    '@type': config.schemaType ?? 'WebPage',
    name: config.title,
    description: config.description,
    url: `${SITE_URL}${config.path}`,
    isPartOf: {
      '@type': 'WebSite',
      name: 'Identrail',
      url: SITE_URL,
      potentialAction: {
        '@type': 'SearchAction',
        target: `${SITE_URL}/blog?query={search_term_string}`,
        'query-input': 'required name=search_term_string'
      }
    },
    publisher: {
      '@type': 'Organization',
      name: 'Identrail',
      url: SITE_URL,
      sameAs: [GITHUB_REPO, DISCORD_URL]
    }
  };

  tag.textContent = JSON.stringify(schema);
}

function useSeo(config: SeoConfig) {
  useEffect(() => {
    document.title = config.title;
    upsertMetaByName('description', config.description);
    upsertMetaByName(
      'keywords',
      config.keywords ??
        'machine identity security, AWS IAM security, Kubernetes RBAC security, non-human identity management, trust graph security'
    );
    upsertMetaByProperty('og:title', config.title);
    upsertMetaByProperty('og:description', config.description);
    upsertMetaByProperty('og:type', 'website');
    upsertMetaByProperty('og:url', `${SITE_URL}${config.path}`);
    upsertMetaByProperty('og:image', `${SITE_URL}/identrail-logo.png`);
    upsertMetaByProperty('twitter:card', 'summary_large_image');
    upsertMetaByProperty('twitter:title', config.title);
    upsertMetaByProperty('twitter:description', config.description);
    upsertCanonical(config.path);
    upsertSchema(config);
  }, [config.title, config.description, config.path, config.keywords, config.schemaType]);
}

function useAnalytics() {
  const location = useLocation();

  useEffect(() => {
    const url = `${location.pathname}${location.search}${location.hash}`;

    if (window.gtag) {
      window.gtag('event', 'page_view', {
        page_path: url,
        page_title: document.title
      });
    }

    if (window.posthog) {
      window.posthog.capture('$pageview', {
        path: location.pathname,
        search: location.search,
        hash: location.hash
      });
    }
  }, [location]);
}

function SectionTitle({
  eyebrow,
  title,
  body
}: {
  eyebrow?: string;
  title: string;
  body?: string;
}) {
  return (
    <div className="idt-section-title">
      {eyebrow ? <p className="idt-eyebrow">{eyebrow}</p> : null}
      <h2>{title}</h2>
      {body ? <p>{body}</p> : null}
    </div>
  );
}

type PageHeroVariant = 'product' | 'pricing' | 'docs' | 'blog' | 'about' | 'enterprise';

function PageHero({
  eyebrow,
  title,
  body,
  actions,
  visual,
  variant
}: {
  eyebrow: string;
  title: string;
  body?: ReactNode;
  actions?: ReactNode;
  visual: ReactNode;
  variant: PageHeroVariant;
}) {
  return (
    <section className={`idt-page-hero idt-page-hero-rich idt-shell is-${variant}`}>
      <div className="idt-page-hero-copy">
        <p className="idt-eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {body ? <p>{body}</p> : null}
        {actions ? <div className="idt-inline-actions">{actions}</div> : null}
      </div>
      <div className="idt-page-hero-visual" aria-hidden="true">
        {visual}
      </div>
    </section>
  );
}

function ProductHeroVisual() {
  return (
    <div className="idt-product-hero-visual" aria-hidden="true">
      <div className="idt-product-hero-window">
        <div className="idt-visual-window-bar">
          <span />
          <span />
          <span />
          <strong>Trust graph</strong>
        </div>
        <div className="idt-product-hero-body">
          <div className="idt-product-hero-sidebar">
            <span className="is-active">Paths</span>
            <span>Evidence</span>
            <span>Fixes</span>
          </div>
          <div className="idt-product-hero-graph">
            <svg viewBox="0 0 720 420" aria-hidden="true" focusable="false">
              <path className="is-muted" d="M118 118 C236 82 316 154 430 132 S600 92 658 166" />
              <path className="is-risk" d="M310 236 C400 236 450 296 520 330 S620 358 675 318" />
              <path className="is-safe" d="M196 330 C274 286 354 264 452 258" />
              <circle className="idt-graph-node is-risk" cx="118" cy="118" r="6" />
              <circle className="idt-graph-node is-risk" cx="452" cy="258" r="6" />
              <circle className="idt-graph-node is-risk" cx="675" cy="318" r="6" />
            </svg>
            <div className="idt-graph-pill is-github">
              <strong>GitHub OIDC</strong>
              <span>Verified</span>
            </div>
            <div className="idt-graph-pill is-aws">
              <strong>AWS Role</strong>
              <span>High risk</span>
            </div>
            <div className="idt-graph-pill is-k8s">
              <strong>K8s service account</strong>
              <span>Namespace bridge</span>
            </div>
            <div className="idt-graph-pill is-data">
              <strong>Billing datastore</strong>
              <span>Critical target</span>
            </div>
            <aside className="idt-product-evidence-card">
              <span>Evidence packet</span>
              <strong>OIDC wildcard can reach production data</strong>
              <p>JWT claims, trust policy, API call proof</p>
            </aside>
          </div>
        </div>
      </div>
      <div className="idt-product-hero-queue">
        <span>Live queue</span>
        <strong>37 risky paths</strong>
        <p>12 have owner-ready fixes</p>
      </div>
    </div>
  );
}

function PricingHeroVisual() {
  const plans = [
    ['OSS', '$0', 'Self-hosted'],
    ['Pro', '$59', 'Hosted trial'],
    ['Enterprise', '$50k+', 'Private tenancy']
  ] as const;

  return (
    <div className="idt-pricing-hero-visual">
      <div className="idt-pricing-hero-toggle">
        <span>Monthly</span>
        <strong>Annual - save 25%</strong>
      </div>
      <div className="idt-pricing-hero-plans">
        {plans.map(([name, price, note]) => (
          <div key={name} className={name === 'Pro' ? 'is-featured' : ''}>
            <span>{name}</span>
            <strong>{price}</strong>
            <p>{note}</p>
          </div>
        ))}
      </div>
      <div className="idt-pricing-hero-matrix">
        <span>Capability</span>
        <span>OSS</span>
        <span>Pro</span>
        <span>Ent</span>
        <strong>Trust graph</strong>
        <b>Yes</b>
        <b>Yes</b>
        <b>Yes</b>
        <strong>SSO / SCIM</strong>
        <b>-</b>
        <b>SSO</b>
        <b>Full</b>
        <strong>Support SLA</strong>
        <b>-</b>
        <b>Biz</b>
        <b>24/7</b>
      </div>
      <div className="idt-pricing-hero-procurement">
        <strong>Procurement ready</strong>
        <span>SOC 2 roadmap</span>
        <span>Security review</span>
        <span>Data residency</span>
      </div>
    </div>
  );
}

function DocsHeroVisual() {
  return (
    <div className="idt-docs-hero-visual">
      <div className="idt-docs-search-preview">
        <span>Search docs topics</span>
        <strong>kubernetes connector hardening</strong>
      </div>
      <div className="idt-docs-preview-shell">
        <nav>
          <span className="is-active">Quickstart</span>
          <span>Connectors</span>
          <span>Architecture</span>
          <span>Operations</span>
        </nav>
        <article>
          <p>Runbook</p>
          <h3>Deploy read-only source collection</h3>
          <ul>
            <li>Validate connector scope</li>
            <li>Import trust-path evidence</li>
            <li>Review first risk queue</li>
          </ul>
          <code>identrail scan --source kubernetes --read-only</code>
        </article>
      </div>
    </div>
  );
}

function BlogHeroVisual() {
  const [featured, ...secondary] = BLOG_POSTS.slice(0, 3);

  return (
    <div className="idt-blog-hero-visual">
      {featured ? (
        <article className="idt-blog-hero-featured">
          <span>{featured.category}</span>
          <h3>{featured.title}</h3>
          <p>{featured.readTime}</p>
        </article>
      ) : null}
      <div className="idt-blog-hero-stack">
        {secondary.map((post) => (
          <article key={post.slug}>
            <span>{post.category}</span>
            <strong>{post.title}</strong>
            <p>{post.readTime}</p>
          </article>
        ))}
      </div>
      <div className="idt-blog-hero-radar">
        <span>Editorial focus</span>
        <strong>Attack paths</strong>
        <strong>Open core</strong>
        <strong>Cloud identity</strong>
      </div>
    </div>
  );
}

function AboutHeroVisual() {
  return (
    <div className="idt-about-hero-visual">
      <div className="idt-about-orbit">
        <span className="is-core">Identrail</span>
        <span className="is-one">Open core</span>
        <span className="is-two">Evidence</span>
        <span className="is-three">Operators</span>
      </div>
      <ol className="idt-about-timeline">
        <li>
          <span>01</span>
          <strong>Make risk visible</strong>
        </li>
        <li>
          <span>02</span>
          <strong>Keep control transparent</strong>
        </li>
        <li>
          <span>03</span>
          <strong>Help teams ship safer fixes</strong>
        </li>
      </ol>
    </div>
  );
}

function EnterpriseHeroVisual() {
  return (
    <div className="idt-enterprise-hero-visual">
      <div className="idt-enterprise-form-preview">
        <span>Enterprise intake</span>
        <label>
          Environment scope
          <strong>Multi-cloud, 12 clusters, 340 repos</strong>
        </label>
        <label>
          Buying motion
          <strong>Security review + private tenancy</strong>
        </label>
        <span className="idt-enterprise-form-action">Generate rollout blueprint</span>
      </div>
      <div className="idt-enterprise-blueprint">
        <span>Deployment blueprint</span>
        <p>Private tenancy</p>
        <p>SAML + SCIM</p>
        <p>Regional data boundary</p>
        <p>Named TAM + SLA</p>
      </div>
    </div>
  );
}

function LeadCaptureForm({
  id,
  title,
  caption,
  ctaLabel,
  compact = false,
  variant = 'full'
}: {
  id?: string;
  title: string;
  caption: string;
  ctaLabel: string;
  compact?: boolean;
  variant?: 'full' | 'short';
}) {
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const email = String(formData.get('email') ?? '').trim();
    const environment = String(formData.get('environment') ?? '').trim();
    const company = String(formData.get('company') ?? '').trim();
    const challenge = String(formData.get('challenge') ?? '').trim();
    const website = String(formData.get('website') ?? '').trim();

    setSubmitting(true);
    setError(null);

    try {
      await apiClient.submitLeadCapture({
        email,
        environment,
        company: company || undefined,
        challenge: challenge || undefined,
        website: website || undefined,
        source: title,
        page_path: window.location.pathname
      });
      setSubmitted(true);
      form.reset();
    } catch (submissionError) {
      const message = submissionError instanceof Error ? submissionError.message : 'Unable to submit request.';
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section id={id} className={`idt-lead-form ${compact ? 'is-compact' : ''}`} aria-label={title}>
      <h3>{title}</h3>
      <p>{caption}</p>
      <p className="idt-form-trust-note">Read-only onboarding. No production writes during evaluation.</p>

      {!submitted ? (
        <form onSubmit={handleSubmit} className={`idt-form-grid ${variant === 'short' ? 'is-short' : ''}`}>
          <input
            className="idt-honeypot"
            type="text"
            name="website"
            tabIndex={-1}
            autoComplete="off"
            aria-hidden="true"
          />
          <label>
            Work email
            <input required type="email" name="email" autoComplete="email" placeholder="you@company.com" />
          </label>
          <label>
            Primary environment
            <select name="environment" defaultValue="AWS IAM + Kubernetes">
              <option>AWS IAM + Kubernetes</option>
              <option>AWS IAM</option>
              <option>Kubernetes</option>
              <option>GitHub/GitOps pipelines</option>
              <option>Hybrid cloud</option>
            </select>
          </label>
          {variant === 'full' ? (
            <>
              <label>
                Company (optional)
                <input type="text" name="company" autoComplete="organization" placeholder="Acme Corp" />
              </label>
              <label>
                Biggest challenge
                <select name="challenge" defaultValue="Trust path visibility">
                  <option>Trust path visibility</option>
                  <option>Overprivileged service accounts</option>
                  <option>Credential leak response</option>
                  <option>Authorization rollout safety</option>
                </select>
              </label>
            </>
          ) : null}
          <button type="submit" className="idt-btn idt-btn-primary" disabled={submitting}>
            {submitting ? 'Submitting...' : ctaLabel}
          </button>
          {error ? <p className="idt-form-error">{error} If urgent, use Book Demo.</p> : null}
          <p className="idt-form-note">Receive a practical 30-day machine identity risk reduction plan.</p>
        </form>
      ) : (
        <p className="idt-form-success">Thanks. We will send your machine identity risk reduction plan within one business day.</p>
      )}
    </section>
  );
}

function ModalShell({
  titleId,
  onClose,
  children
}: {
  titleId: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const modalRef = useRef<HTMLDivElement | null>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previouslyFocusedRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;

    if (activeModalLocks === 0) {
      bodyOverflowBeforeModal = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
    }
    activeModalLocks += 1;

    const getFocusableElements = () =>
      modalRef.current?.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      ) ?? [];

    getFocusableElements()[0]?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
        return;
      }

      if (event.key !== 'Tab') {
        return;
      }

      const focusableElements = getFocusableElements();
      if (focusableElements.length === 0) {
        return;
      }

      const first = focusableElements[0];
      const last = focusableElements[focusableElements.length - 1];
      const active = document.activeElement;

      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown);

    return () => {
      activeModalLocks = Math.max(0, activeModalLocks - 1);
      if (activeModalLocks === 0) {
        document.body.style.overflow = bodyOverflowBeforeModal;
      }
      document.removeEventListener('keydown', onKeyDown);
      previouslyFocusedRef.current?.focus();
    };
  }, [onClose]);

  return (
    <div className="idt-modal-backdrop" role="presentation" onClick={onClose}>
      <div
        ref={modalRef}
        className="idt-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(event) => event.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
}

function CalendlyEmbed() {
  return (
    <section className="idt-calendly">
      <SectionTitle
        eyebrow="Book Demo"
        title="Walk through your trust graph in 15 minutes"
        body="Bring one AWS account or Kubernetes namespace, and we will map live trust paths and top risk chains."
      />
      <div className="idt-calendly-shell">
        <article className="idt-calendly-card">
          <p className="idt-calendly-note">
            Choose a slot and we will review trust-path evidence, blast radius, and rollout-safe remediation priorities.
          </p>
          <ul className="idt-calendly-checklist">
            <li>Read-only onboarding review</li>
            <li>Live trust graph walkthrough</li>
            <li>First remediation sequence</li>
          </ul>
          <div className="idt-inline-actions">
            <SafeLink href={CALENDLY_URL} className="idt-btn idt-btn-primary">
              Open Booking Calendar
            </SafeLink>
            <Link to="/enterprise" className="idt-btn idt-btn-dark">
              Talk to Sales
            </Link>
          </div>
          <p className="idt-inline-link-note">
            Need async scheduling?{' '}
            <SafeLink href="mailto:sales@identrail.com" className="idt-inline-link">
              Email sales
            </SafeLink>
          </p>
        </article>
        <aside className="idt-calendly-preview" aria-label="Demo agenda preview">
          <p className="idt-eyebrow">Sample agenda</p>
          <ol>
            <li>Scope environment and trust boundaries</li>
            <li>Inspect one high-risk path with evidence</li>
            <li>Review safe remediation plan and rollout options</li>
          </ol>
          <div className="idt-calendly-slot-row" aria-hidden="true">
            <span>Tue · 10:00</span>
            <span>Wed · 14:30</span>
            <span>Fri · 09:00</span>
          </div>
        </aside>
      </div>
    </section>
  );
}

function TrustGraphDemo({ variant = 'compact' }: { variant?: 'compact' | 'full' }) {
  const scenarios = [
    {
      id: 'cicd',
      label: 'CI/CD OIDC chain',
      severity: 'High',
      path: 'GitHub Actions → OIDC Provider → AWS Role → RDS Billing Resource',
      impact: 'Compromise of CI workflow token could reach production billing data.',
      remediation: 'Constrain trust policy subject claims and narrow role permissions to required actions only.'
    },
    {
      id: 'k8s',
      label: 'K8s service account drift',
      severity: 'High',
      path: 'K8s ServiceAccount → ClusterRoleBinding → AWS Role → S3 Artifact Bucket',
      impact: 'Overprivileged service account can pivot into cloud resources outside intended namespace scope.',
      remediation: 'Split service accounts by workload boundary and apply namespace-scoped RBAC + IAM condition keys.'
    },
    {
      id: 'repo',
      label: 'Leaked deploy token path',
      severity: 'Medium',
      path: 'Git Repository Secret Leak → Bot Identity → IAM AssumeRole → ECR Registry Push',
      impact: 'Leaked token can be replayed to ship unauthorized container images.',
      remediation: 'Rotate credentials, enforce short-lived identity tokens, and tighten registry write access.'
    }
  ] as const;

  const [scenarioId, setScenarioId] = useState<(typeof scenarios)[number]['id']>('cicd');
  const [viewMode, setViewMode] = useState<'graph' | 'list'>('graph');
  const nodes = [
    {
      id: 'oidc',
      type: 'Broker',
      title: 'OIDC Provider',
      detail: 'Federated identity provider trusted by CI/CD and cluster workloads.',
      x: 14,
      y: 12
    },
    {
      id: 'role',
      type: 'Privilege',
      title: 'AWS Role: payments-prod',
      detail: 'Role assumed by automation workloads with cross-account permissions.',
      x: 58,
      y: 32
    },
    {
      id: 'sa',
      type: 'Workload',
      title: 'K8s ServiceAccount: api-gateway',
      detail: 'Service account with namespace-level and cloud trust-path reachability.',
      x: 28,
      y: 58
    },
    {
      id: 'repo',
      type: 'Source',
      title: 'Git Repo: infra-live',
      detail: 'Repository contains deployment workflows and secrets exposure history.',
      x: 54,
      y: 80
    },
    {
      id: 'db',
      type: 'Resource',
      title: 'RDS Resource: billing-ledger',
      detail: 'Sensitive resource reachable through chained assumptions in current policy state.',
      x: 30,
      y: 92
    }
  ] as const;

  const edges = [
    { id: 'e-oidc-role', from: 'oidc', to: 'role' },
    { id: 'e-oidc-sa', from: 'oidc', to: 'sa' },
    { id: 'e-sa-role', from: 'sa', to: 'role' },
    { id: 'e-sa-repo', from: 'sa', to: 'repo' },
    { id: 'e-repo-db', from: 'repo', to: 'db' }
  ] as const;

  const [selectedId, setSelectedId] = useState<string>('role');
  const selected = nodes.find((item) => item.id === selectedId) ?? nodes[1];
  const scenario = scenarios.find((item) => item.id === scenarioId) ?? scenarios[0];
  const graphTabId = `trust-graph-tab-${variant}`;
  const listTabId = `trust-list-tab-${variant}`;
  const graphPanelId = `trust-graph-panel-${variant}`;
  const listPanelId = `trust-list-panel-${variant}`;

  const getNode = (id: (typeof nodes)[number]['id']) => nodes.find((node) => node.id === id);
  const edgePath = (fromId: (typeof nodes)[number]['id'], toId: (typeof nodes)[number]['id']) => {
    const from = getNode(fromId);
    const to = getNode(toId);
    if (!from || !to) {
      return '';
    }

    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const bend = Math.min(12, Math.max(4.5, Math.abs(dx) * 0.14 + Math.abs(dy) * 0.06));
    const c1x = from.x + dx * 0.32;
    const c1y = from.y + dy * 0.16 - bend;
    const c2x = to.x - dx * 0.26;
    const c2y = to.y - dy * 0.12 + bend * 0.16;
    return `M ${from.x} ${from.y} C ${c1x} ${c1y} ${c2x} ${c2y} ${to.x} ${to.y}`;
  };

  const connectedEdges = edges.filter((edge) => edge.from === selected.id || edge.to === selected.id);

  return (
    <section className={`idt-demo-surface ${variant === 'full' ? 'is-full' : ''}`}>
      <div className="idt-demo-toolbar" role="group" aria-label="Demo scenarios">
        <p>Scenario</p>
        <div className="idt-demo-scenario-row">
          {scenarios.map((item) => (
            <button key={item.id} type="button" className={item.id === scenarioId ? 'is-active' : ''} onClick={() => setScenarioId(item.id)}>
              {item.label}
            </button>
          ))}
        </div>
      </div>

      <div className="idt-demo-view-toggle" role="tablist" aria-label="Trust path explorer view">
        <button
          id={graphTabId}
          type="button"
          role="tab"
          aria-controls={graphPanelId}
          aria-selected={viewMode === 'graph'}
          className={viewMode === 'graph' ? 'is-active' : ''}
          onClick={() => setViewMode('graph')}
        >
          Graph
        </button>
        <button
          id={listTabId}
          type="button"
          role="tab"
          aria-controls={listPanelId}
          aria-selected={viewMode === 'list'}
          className={viewMode === 'list' ? 'is-active' : ''}
          onClick={() => setViewMode('list')}
        >
          List
        </button>
      </div>

      {viewMode === 'graph' ? (
        <div id={graphPanelId} role="tabpanel" aria-labelledby={graphTabId} className="idt-demo-graph" aria-label="Interactive trust graph simulation">
          <svg className="idt-demo-edges" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
            <defs>
              <linearGradient id={`idt-demo-edge-base-gradient-${variant}`} x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="rgba(124, 153, 212, 0.16)" />
                <stop offset="55%" stopColor="rgba(141, 172, 228, 0.42)" />
                <stop offset="100%" stopColor="rgba(119, 151, 210, 0.15)" />
              </linearGradient>
              <linearGradient id={`idt-demo-edge-flow-gradient-${variant}`} x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="rgba(170, 197, 255, 0.52)" />
                <stop offset="55%" stopColor="rgba(203, 222, 255, 0.95)" />
                <stop offset="100%" stopColor="rgba(154, 184, 238, 0.42)" />
              </linearGradient>
            </defs>
            {edges.map((edge, index) => {
              const path = edgePath(edge.from, edge.to);
              const toNode = getNode(edge.to);
              if (!path || !toNode) {
                return null;
              }

              const isConnected = connectedEdges.some((item) => item.id === edge.id);
              const edgeClass = isConnected ? 'is-connected' : '';
              return (
                <g key={edge.id} className={edgeClass}>
                  <path className="idt-demo-edge-base" d={path} stroke={`url(#idt-demo-edge-base-gradient-${variant})`} />
                  <path
                    className={`idt-demo-edge-flow idt-demo-edge-delay-${index}`}
                    d={path}
                    stroke={`url(#idt-demo-edge-flow-gradient-${variant})`}
                  />
                  <circle className="idt-demo-edge-end" cx={toNode.x} cy={toNode.y} r={isConnected ? 0.72 : 0.56} />
                </g>
              );
            })}
          </svg>
          {nodes.map((node) => (
            <button
              key={node.id}
              type="button"
              className={`idt-demo-node idt-demo-node-${node.type.toLowerCase()} idt-demo-node-${node.id} ${selected.id === node.id ? 'is-active' : ''}`}
              onClick={() => setSelectedId(node.id)}
            >
              <small>{node.type}</small>
              <span>{node.title}</span>
            </button>
          ))}
        </div>
      ) : (
        <div id={listPanelId} role="tabpanel" aria-labelledby={listTabId} className="idt-demo-list-view" aria-label="Trust path nodes">
          {nodes.map((node) => (
            <button key={node.id} type="button" className={`idt-demo-list-row ${selected.id === node.id ? 'is-active' : ''}`} onClick={() => setSelectedId(node.id)}>
              <span>{node.title}</span>
              <strong>{node.type}</strong>
              <small>{node.detail}</small>
            </button>
          ))}
        </div>
      )}

      <aside className="idt-demo-sidebar" aria-live="polite">
        <p className="idt-finding-label">{selected.type}</p>
        <h3>{selected.title}</h3>
        <p>{selected.detail}</p>
        <ul>
          <li>Risk score impact: {scenario.severity}</li>
          <li>Reachable resources: 18 sensitive nodes</li>
          <li>Policy confidence: 96% edge evidence coverage</li>
        </ul>
        {variant === 'full' ? (
          <article className="idt-demo-evidence">
            <p className="idt-finding-label">Active finding</p>
            <p>
              <strong>Path:</strong> {scenario.path}
            </p>
            <p>
              <strong>Why it matters:</strong> {scenario.impact}
            </p>
            <p>
              <strong>Recommended fix:</strong> {scenario.remediation}
            </p>
          </article>
        ) : null}
        <p className="idt-demo-follow-up">
          Explore the full investigation workflow on the{' '}
          <Link to="/demo" className="idt-inline-link">
            interactive demo page
          </Link>
          .
        </p>
      </aside>
    </section>
  );
}

type RoiNumberFieldProps = {
  id: string;
  label: string;
  value: number;
  min: number;
  step: number;
  onChange: (value: number) => void;
};

function RoiNumberField({ id, label, value, min, step, onChange }: RoiNumberFieldProps) {
  const updateValue = (next: number) => {
    const safe = Math.max(min, Math.round(next));
    onChange(safe);
  };

  return (
    <label htmlFor={id} className="idt-roi-field">
      <span>{label}</span>
      <div className="idt-roi-input-wrap">
        <input
          id={id}
          className="idt-roi-number-input"
          type="number"
          min={min}
          step={step}
          inputMode="numeric"
          value={value}
          onChange={(event) => {
            const parsed = Number(event.target.value);
            if (Number.isNaN(parsed)) {
              return;
            }
            updateValue(parsed);
          }}
          onBlur={() => updateValue(value)}
        />
      </div>
    </label>
  );
}

function RoiCalculator() {
  const profiles = [
    {
      id: 'startup',
      label: 'Startup cloud-native',
      identities: 900,
      incidentCost: 95000,
      hoursPerWeek: 16
    },
    {
      id: 'midmarket',
      label: 'Mid-market platform team',
      identities: 3200,
      incidentCost: 195000,
      hoursPerWeek: 44
    },
    {
      id: 'enterprise',
      label: 'Enterprise multi-account AWS',
      identities: 9800,
      incidentCost: 420000,
      hoursPerWeek: 88
    }
  ] as const;

  const [activeProfileId, setActiveProfileId] = useState<(typeof profiles)[number]['id']>('midmarket');
  const [identities, setIdentities] = useState(3200);
  const [incidentCost, setIncidentCost] = useState(195000);
  const [hoursPerWeek, setHoursPerWeek] = useState(44);

  const output = useMemo(() => {
    const annualHours = hoursPerWeek * 52;
    const laborSavings = annualHours * 110;
    const expectedIncidentReduction = incidentCost * 0.87;
    const identityRiskDelta = Math.round(identities * 0.32);

    return {
      laborSavings,
      expectedIncidentReduction,
      identityRiskDelta,
      estimatedTotal: laborSavings + expectedIncidentReduction
    };
  }, [hoursPerWeek, incidentCost, identities]);

  return (
    <section className="idt-roi" aria-label="ROI calculator">
      <SectionTitle
        eyebrow="ROI Calculator"
        title="Model impact with conservative assumptions"
        body="Use a planning model to estimate labor savings and reduced incident exposure from better trust-path visibility."
      />
      <div className="idt-roi-profiles" role="tablist" aria-label="ROI profiles">
        {profiles.map((profile) => (
          <button
            key={profile.id}
            type="button"
            role="tab"
            aria-selected={activeProfileId === profile.id}
            className={activeProfileId === profile.id ? 'is-active' : ''}
            onClick={() => {
              setActiveProfileId(profile.id);
              setIdentities(profile.identities);
              setIncidentCost(profile.incidentCost);
              setHoursPerWeek(profile.hoursPerWeek);
            }}
          >
            {profile.label}
          </button>
        ))}
      </div>
      <div className="idt-roi-grid">
        <RoiNumberField
          id="roi-identities"
          label="Number of machine identities"
          value={identities}
          min={100}
          step={100}
          onChange={setIdentities}
        />
        <RoiNumberField
          id="roi-incident-cost"
          label="Average machine-identity incident cost (USD)"
          value={incidentCost}
          min={10000}
          step={5000}
          onChange={setIncidentCost}
        />
        <RoiNumberField
          id="roi-triage-hours"
          label="Weekly hours spent on identity triage"
          value={hoursPerWeek}
          min={1}
          step={1}
          onChange={setHoursPerWeek}
        />

        <div className="idt-roi-output" aria-live="polite">
          <p>
            Annual labor savings: <strong>${output.laborSavings.toLocaleString()}</strong>
          </p>
          <p>
            Reduced incident exposure: <strong>${output.expectedIncidentReduction.toLocaleString()}</strong>
          </p>
          <p>
            High-risk identities reduced: <strong>{output.identityRiskDelta.toLocaleString()}</strong>
          </p>
          <p className="idt-roi-total">
            Estimated annual impact: <strong>${output.estimatedTotal.toLocaleString()}</strong>
          </p>
          <p className="idt-roi-note">
            Model assumptions: labor hour rate $110/hr, incident reduction coefficient 0.87, high-risk identity reduction
            coefficient 0.32.
          </p>
        </div>
      </div>
    </section>
  );
}

function DeploymentPathBanner() {
  return (
    <section className="idt-section idt-shell idt-deployment-bridge" aria-label="Adoption paths">
      <div className="idt-deployment-panel">
        <p className="idt-eyebrow">Adoption Paths</p>
        <h2>Choose the deployment model that fits your operating constraints.</h2>
        <div className="idt-adoption-grid">
          <article className="idt-adoption-card">
            <h3>Open Source</h3>
            <p className="idt-muted-strong">Best for: self-hosted evaluation and internal control.</p>
            <dl>
              <div>
                <dt>Time to value</dt>
                <dd>Same day with Docker/Kubernetes setup</dd>
              </div>
              <div>
                <dt>Control level</dt>
                <dd>Full infrastructure and data ownership</dd>
              </div>
              <div>
                <dt>Support model</dt>
                <dd>Community and docs-led</dd>
              </div>
            </dl>
            <SafeLink href={GITHUB_REPO} className="idt-inline-link">
              View open-source setup →
            </SafeLink>
          </article>
          <article className="idt-adoption-card is-featured">
            <h3>Hosted SaaS</h3>
            <p className="idt-muted-strong">Best for: fastest onboarding and operational simplicity.</p>
            <dl>
              <div>
                <dt>Time to value</dt>
                <dd>Minutes to first trust-path scan</dd>
              </div>
              <div>
                <dt>Control level</dt>
                <dd>Managed platform with guided rollout</dd>
              </div>
              <div>
                <dt>Support model</dt>
                <dd>Product support and assisted onboarding</dd>
              </div>
            </dl>
            <p className="idt-adoption-note">Recommended for teams that need the fastest first scan.</p>
          </article>
          <article className="idt-adoption-card">
            <h3>Enterprise</h3>
            <p className="idt-muted-strong">Best for: private tenancy, procurement, and compliance control.</p>
            <dl>
              <div>
                <dt>Time to value</dt>
                <dd>Planned onboarding with architecture review</dd>
              </div>
              <div>
                <dt>Control level</dt>
                <dd>Private deployment and regional controls</dd>
              </div>
              <div>
                <dt>Support model</dt>
                <dd>Enterprise SLA and named partner team</dd>
              </div>
            </dl>
            <Link to="/enterprise" className="idt-inline-link">
              Contact enterprise team →
            </Link>
          </article>
        </div>
        <div className="idt-inline-actions idt-adoption-actions">
          <Link to="/pricing" className="idt-btn idt-btn-ghost">
            Compare plan details
          </Link>
        </div>
      </div>
    </section>
  );
}

function ProductTourSection() {
  return (
    <section className="idt-section idt-shell idt-product-tour" aria-labelledby="product-tour-title">
      <div className="idt-product-tour-copy">
        <p className="idt-eyebrow">Product tour</p>
        <h2 id="product-tour-title">From connector setup to evidence-ready remediation.</h2>
        <p>
          Connect read-only sources, trace the path to sensitive resources, test the safest fix, and hand owners one
          evidence packet they can act on.
        </p>
      </div>

      <div className="idt-product-tour-shell" aria-label="Identrail product workflow preview">
        <div className="idt-tour-rail">
          {PRODUCT_TOUR_STEPS.map((item) => (
            <article
              key={item.step}
              aria-current={item.active ? 'step' : undefined}
              className={`idt-tour-step${item.active ? ' is-active' : ''}`}
            >
              <span className="idt-tour-step-index">{item.step}</span>
              <div>
                <small>{item.proof}</small>
                <h3>{item.title}</h3>
                <p>{item.detail}</p>
              </div>
            </article>
          ))}
        </div>

        <div className="idt-tour-screen">
          <div className="idt-tour-screen-head">
            <div className="idt-tour-window-dots" aria-hidden="true">
              <span />
              <span />
              <span />
            </div>
            <div>
              <p>Production workspace</p>
              <h3>Owner-ready risk path</h3>
            </div>
            <span>Evidence ready</span>
          </div>

          <div className="idt-tour-product-preview">
            <aside className="idt-tour-connector-scope" aria-label="Read-only connector scope">
              <p>Connector scope</p>
              {PRODUCT_TOUR_CONNECTORS.map((connector) => (
                <article key={connector.name}>
                  <img src={connector.icon} alt="" aria-hidden="true" loading="lazy" />
                  <div>
                    <strong>{connector.name}</strong>
                    <span>{connector.status}</span>
                  </div>
                </article>
              ))}
            </aside>

            <div className="idt-tour-path-panel">
              <div className="idt-tour-path-head">
                <div>
                  <p>Reachable path</p>
                  <h4>GitHub workflow can reach billing data through AWS role trust.</h4>
                </div>
                <span>High</span>
              </div>

              <div className="idt-tour-path-chain" aria-label="Machine identity path">
                {PRODUCT_TOUR_PATH.map((node) => (
                  <article key={node.label}>
                    <small>{node.label}</small>
                    <strong>{node.value}</strong>
                  </article>
                ))}
              </div>
            </div>

            <div className="idt-tour-simulation">
              <div>
                <p>Safe fix simulation</p>
                <strong>Restrict subject claim and namespace tags</strong>
              </div>
              <code>
                <span className="is-remove">- sub = "*"</span>
                <span className="is-add">+ sub = "repo:payments-api:prod"</span>
                <span className="is-add">+ namespace = "payments-api"</span>
              </code>
            </div>

            <div className="idt-tour-evidence-packet">
              <div>
                <p>Evidence packet</p>
                <strong>Ready for owner review</strong>
              </div>
              <ul aria-label="Evidence packet contents">
                {PRODUCT_TOUR_PACKET.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function HomeFaqSection() {
  const groups = [
    {
      title: 'Security and access',
      items: HOME_FAQ_PREVIEW.slice(0, 2)
    },
    {
      title: 'Rollout and operations',
      items: HOME_FAQ_PREVIEW.slice(2, 4)
    }
  ] as const;

  return (
    <section className="idt-section idt-shell">
      <SectionTitle
        eyebrow="FAQ"
        title="Answers to the first questions security teams ask"
        body="Clear answers on read-only access, deployment options, and rollout safety."
      />
      <div className="idt-faq-groups">
        {groups.map((group) => (
          <article key={group.title} className="idt-faq-group">
            <h3>{group.title}</h3>
            <dl>
              {group.items.map((item) => (
                <div key={item.question}>
                  <dt>{item.question}</dt>
                  <dd>{item.answer}</dd>
                </div>
              ))}
            </dl>
          </article>
        ))}
      </div>
      <div className="idt-inline-actions">
        <Link to="/faq" className="idt-btn idt-btn-ghost">
          View Full FAQ
        </Link>
      </div>
    </section>
  );
}

function FaqPage() {
  useSeo({
    title: 'FAQ | Identrail Machine Identity Security',
    description:
      'Detailed answers for machine identity security adoption including read-only model, data handling, deployment options, and rollout safety.',
    path: '/faq'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">FAQ</p>
        <h1>Technical and operational questions teams ask before rollout</h1>
        <p>Answers focus on read-only collection boundaries, deployment models, and safe remediation workflows.</p>
      </section>
      <section className="idt-section idt-shell">
        <div className="idt-faq-list">
          {HOME_FAQ_ITEMS.map((item) => (
            <details key={item.question} className="idt-faq-item">
              <summary>{item.question}</summary>
              <p>{item.answer}</p>
            </details>
          ))}
        </div>
      </section>
    </>
  );
}

function HomePage() {
  const seo: SeoConfig = {
    title: 'Machine Identity Trust Graph | AWS IAM, Kubernetes, OIDC | Identrail',
    description:
      'Identrail is the trust graph for machine identity security across AWS IAM, Kubernetes, GitHub/OIDC, and repository exposure signals with read-only evidence and safe remediation.',
    path: '/',
    keywords:
      'machine identity security, AWS IAM trust path analysis, Kubernetes service account risk, OIDC security, cloud identity blast radius reduction, GitHub trust path risk',
    schemaType: 'WebPage'
  };
  useSeo(seo);

  return (
    <>
      <section className="idt-hero">
        <div className="idt-shell idt-hero-grid">
          <div className="idt-hero-copy">
            <p className="idt-eyebrow">Machine identity trust graph</p>
            <h1>
              Every machine identity path, clear to <span>you</span>.
            </h1>
            <p className="idt-lead idt-lead-body">
              Identrail traces how AWS IAM roles, Kubernetes service accounts, GitHub Actions, and OIDC claims can reach
              sensitive resources, then packages the proof and safest first fix for the owner.
            </p>
            <div className="idt-inline-actions" data-ab-slot="hero_primary_cta">
              <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
                Start Free Risk Scan
              </Link>
              <HeroOpenSourceProofPills />
            </div>
            <dl className="idt-hero-metrics" aria-label="Product assurances">
              <div>
                <dt>Collection</dt>
                <dd>Read-only by default</dd>
              </div>
              <div>
                <dt>Coverage</dt>
                <dd>AWS, K8s, GitHub, OIDC</dd>
              </div>
              <div>
                <dt>Output</dt>
                <dd>Evidence and first fix</dd>
              </div>
            </dl>
            <ul className="idt-hero-trust-cues" aria-label="Evaluation trust cues">
              <li>Open-core under Apache-2.0</li>
              <li>Read-only onboarding model</li>
              <li>Self-hosted and hosted paths</li>
              <li>Public docs and release history</li>
            </ul>
          </div>
          <HeroProductReveal />
        </div>
      </section>

      <TrustProofStrip />

      <ProblemFramingSection />

      <CommandCenterSection />

      <ProductTourSection />

      <HowItWorksSection />

      <DeploymentPathBanner />

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Comparison"
          title="Why teams choose Identrail over closed black-box workflows"
          body="Compare on explainability, rollout safety, and day-two operability."
        />
        <div className="idt-table-wrap idt-home-compare">
          <table className="idt-compare-table">
            <thead>
              <tr>
                <th scope="col">Category</th>
                <th scope="col">Identrail</th>
                <th scope="col">Typical closed alternatives</th>
              </tr>
            </thead>
            <tbody>
              {DIFFERENTIATION_ROWS.map((row) => (
                <tr key={row.area}>
                  <th scope="row">{row.area}</th>
                  <td>{row.identrail}</td>
                  <td>{row.closed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="idt-section idt-shell idt-final-cta" id="risk-scan-form">
        <SectionTitle
          eyebrow="Ready to evaluate"
          title="Map your first production trust path in minutes"
          body="Start with a read-only scan, review evidence, then decide whether to self-host, use hosted SaaS, or move to enterprise deployment."
        />
        <div className="idt-inline-actions">
          <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
            Start Free Risk Scan
          </Link>
          <Link to="/enterprise" className="idt-final-cta-link">
            Need enterprise procurement? Contact Sales →
          </Link>
        </div>
      </section>
    </>
  );
}

function ReadOnlyScanPage() {
  const [step, setStep] = useState(1);
  const [email, setEmail] = useState('');
  const [environment, setEnvironment] = useState('AWS IAM + Kubernetes');
  const [deployment, setDeployment] = useState('Hosted SaaS');
  const [challenge, setChallenge] = useState('Trust path visibility');
  const [urgency, setUrgency] = useState('This quarter');
  const [teamSize, setTeamSize] = useState('6-20');
  const [company, setCompany] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useSeo({
    title: 'Start Free Risk Scan | Identrail',
    description:
      'Start a read-only machine identity risk scan with Identrail. Share planning context and receive a prioritized trust path report with rollout-safe remediation guidance.',
    path: '/read-only-scan'
  });

  const submitIntake = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submitting) {
      return;
    }
    const formData = new FormData(event.currentTarget);
    const website = String(formData.get('website') ?? '').trim();

    setSubmitting(true);
    setError(null);

    try {
      await apiClient.submitLeadCapture({
        email: email.trim(),
        environment,
        company: company.trim() || undefined,
        challenge: challenge,
        website: website || undefined,
        deployment_model: deployment,
        urgency,
        team_size: teamSize,
        scan_goal: `${environment} trust path risk reduction`,
        source: 'Read-Only Scan Intake',
        page_path: '/read-only-scan'
      });
      setSubmitted(true);
    } catch (submissionError) {
      const message = submissionError instanceof Error ? submissionError.message : 'Unable to submit request.';
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <section className="idt-scan-hero">
        <div className="idt-scan-hero-copy">
          <p className="idt-eyebrow">Read-only scan</p>
          <h1>Start a read-only identity risk scan</h1>
          <p>
            Share planning context only. We never ask for environment credentials here, and your first report focuses on machine
            identity trust paths, reachable blast radius, and rollout-safe next steps.
          </p>
          <ul className="idt-scan-assurances" aria-label="Read-only scan assurances">
            <li>No credentials requested</li>
            <li>Prioritized trust path findings</li>
            <li>Deployment-safe remediation plan</li>
          </ul>
        </div>
        <div className="idt-scan-visual" aria-hidden="true">
          <div className="idt-scan-visual-heading">
            <span>Identity trust path</span>
            <strong>Preview report</strong>
          </div>
          <div className="idt-scan-path">
            <span className="is-source">GitHub runner</span>
            <span className="is-hop">OIDC trust</span>
            <span className="is-risk">AWS admin role</span>
          </div>
          <dl className="idt-scan-risk-metrics">
            <div>
              <dt>Exposure</dt>
              <dd>High</dd>
            </div>
            <div>
              <dt>Action</dt>
              <dd>Sequence safely</dd>
            </div>
          </dl>
        </div>
      </section>

      <section className="idt-scan-intake" aria-labelledby="scan-intake-title">
        <form className="idt-scan-form" onSubmit={submitIntake}>
          <input
            className="idt-honeypot"
            type="text"
            name="website"
            tabIndex={-1}
            autoComplete="off"
            aria-hidden="true"
          />
          <div className="idt-scan-form-header">
            <p className="idt-intake-step">Step {submitted ? 3 : step} of 3</p>
            <h2 id="scan-intake-title">{submitted ? 'Request received' : 'Tell us where to start'}</h2>
            <p>
              A short intake keeps the first scan focused. You can refine environment details with the team after we respond.
            </p>
          </div>
          {!submitted ? (
            <>
              {step === 1 ? (
                <div className="idt-intake-grid">
                  <label>
                    Work email
                    <input
                      required
                      type="email"
                      value={email}
                      onChange={(event) => setEmail(event.target.value)}
                      placeholder="you@company.com"
                      autoComplete="email"
                    />
                  </label>
                  <label>
                    Company (optional)
                    <input
                      type="text"
                      value={company}
                      onChange={(event) => setCompany(event.target.value)}
                      placeholder="Acme Corp"
                      autoComplete="organization"
                    />
                  </label>
                </div>
              ) : null}

              {step === 2 ? (
                <div className="idt-intake-grid">
                  <label>
                    Primary environment
                    <select value={environment} onChange={(event) => setEnvironment(event.target.value)}>
                      <option>AWS IAM + Kubernetes</option>
                      <option>AWS IAM</option>
                      <option>Kubernetes</option>
                      <option>GitHub/GitOps pipelines</option>
                      <option>Hybrid cloud</option>
                    </select>
                  </label>
                  <label>
                    Preferred deployment
                    <select value={deployment} onChange={(event) => setDeployment(event.target.value)}>
                      <option>Hosted SaaS</option>
                      <option>Self-hosted open-core</option>
                      <option>Enterprise private tenancy</option>
                    </select>
                  </label>
                </div>
              ) : null}

              {step === 3 ? (
                <div className="idt-intake-grid">
                  <label>
                    Biggest challenge
                    <select value={challenge} onChange={(event) => setChallenge(event.target.value)}>
                      <option>Trust path visibility</option>
                      <option>Overprivileged service accounts</option>
                      <option>Credential leak response</option>
                      <option>Authorization rollout safety</option>
                    </select>
                  </label>
                  <label>
                    Urgency
                    <select value={urgency} onChange={(event) => setUrgency(event.target.value)}>
                      <option>This quarter</option>
                      <option>This month</option>
                      <option>Immediate</option>
                    </select>
                  </label>
                  <label>
                    Team size
                    <select value={teamSize} onChange={(event) => setTeamSize(event.target.value)}>
                      <option>1-5</option>
                      <option>6-20</option>
                      <option>21-50</option>
                      <option>50+</option>
                    </select>
                  </label>
                  <article className="idt-intake-summary">
                    <h3>What you receive</h3>
                    <ul>
                      <li>Prioritized trust path findings with severity and impact context</li>
                      <li>Reachable blast-radius summary for your selected environment</li>
                      <li>Rollout-safe remediation sequence for first actions</li>
                    </ul>
                  </article>
                </div>
              ) : null}

              {error ? <p className="idt-form-error">{error}</p> : null}

              <div className="idt-inline-actions">
                {step > 1 ? (
                  <button type="button" className="idt-btn idt-btn-ghost" onClick={() => setStep((value) => Math.max(1, value - 1))}>
                    Back
                  </button>
                ) : null}
                {step < 3 ? (
                  <button
                    type="button"
                    className="idt-btn idt-btn-primary"
                    onClick={(event) => {
                      const form = event.currentTarget.form;
                      if (step === 1 && form && !form.reportValidity()) {
                        return;
                      }
                      setStep((value) => Math.min(3, value + 1));
                    }}
                  >
                    Continue
                  </button>
                ) : (
                  <button type="submit" className="idt-btn idt-btn-primary" disabled={submitting || !email.trim()}>
                    {submitting ? 'Submitting...' : 'Start Free Risk Scan'}
                  </button>
                )}
              </div>
            </>
          ) : (
            <div className="idt-intake-confirmation">
              <h3>Intake submitted</h3>
              <p>Thanks. We will send your first read-only scan onboarding response within one business day.</p>
              <div className="idt-inline-actions">
                <Link to="/demo" className="idt-btn idt-btn-dark">
                  Book Demo
                </Link>
                <Link to="/docs" className="idt-btn idt-btn-ghost">
                  Review Documentation
                </Link>
              </div>
            </div>
          )}
        </form>
      </section>
    </>
  );
}

function ProductPage() {
  useSeo({
    title: 'Product | Identrail Machine Identity Security Platform',
    description:
      'Discover machine identities across AWS and Kubernetes, map trust paths, detect risk, and enforce safer authorization controls with Identrail.',
    path: '/product',
    schemaType: 'Product'
  });

  return (
    <div className="idt-product-page">
      <section className="idt-product-hero-full">
        <div className="idt-product-hero-copy">
          <p className="idt-eyebrow">Product</p>
          <h1>Machine identity risk, mapped end to end</h1>
          <p>
            Identrail unifies IAM graph discovery, repository exposure scanning, and rollout-safe authorization
            workflows into one operator-grade platform.
          </p>
          <div className="idt-inline-actions">
            <Link to="/demo" className="idt-btn idt-btn-primary">
              Explore Product Demo
            </Link>
            <Link to="/read-only-scan" className="idt-btn idt-btn-dark">
              Start Free Risk Scan
            </Link>
          </div>
        </div>
        <ProductHeroVisual />
      </section>

      <section className="idt-product-capability-band" aria-labelledby="product-capabilities-title">
        <div className="idt-product-section-heading">
          <p className="idt-eyebrow">Platform map</p>
          <h2 id="product-capabilities-title">Four connected surfaces, spread across one workflow.</h2>
        </div>
        <div className="idt-product-capability-grid">
          <article>
            <span>01</span>
            <h2>Trust Graph Explorer</h2>
            <p>Interactive mapping of principals, assumptions, actions, and reachable resources across cloud and Kubernetes.</p>
            <ul>
              <li>Trace blast radius from any machine identity</li>
              <li>Explain each trust edge with source policy evidence</li>
              <li>Compare current and proposed policy states</li>
            </ul>
          </article>
          <article>
            <span>02</span>
            <h2>Detection and Triage Engine</h2>
            <p>High-signal detections for overprivileged paths, stale credentials, and risky identity chains.</p>
            <ul>
              <li>Risk scoring with business context</li>
              <li>Actionable remediation guidance</li>
              <li>Ticket and workflow integrations</li>
            </ul>
          </article>
          <article>
            <span>03</span>
            <h2>Repo Exposure Scanner</h2>
            <p>Continuously scan source repositories and CI artifacts for leaked credentials and unsafe patterns.</p>
            <ul>
              <li>Built-in and custom detectors</li>
              <li>Git-aware triage with finding history</li>
              <li>Correlates secret leaks to trust paths</li>
            </ul>
          </article>
          <article>
            <span>04</span>
            <h2>Rollout-Safe Authorization Controls</h2>
            <p>Enforce least privilege with policy simulation, staged rollout, and fast rollback safety rails.</p>
            <ul>
              <li>Policy impact simulation before deploy</li>
              <li>Progressive rollout controls</li>
              <li>Kill switch and audit trail support</li>
            </ul>
          </article>
        </div>
      </section>

      <section className="idt-product-graph-band">
        <div className="idt-product-section-heading">
          <p className="idt-eyebrow">Hero feature</p>
          <h2>The Trust Graph is the control plane for machine identity risk.</h2>
          <p>
            Investigate every risky path from source identity to sensitive resource with explainable graph evidence and
            owner-ready remediation.
          </p>
        </div>
        <TrustGraphDemo variant="full" />
      </section>

      <section className="idt-product-workflow-band" aria-labelledby="product-workflow-title">
        <div className="idt-product-section-heading">
          <p className="idt-eyebrow">Workflow</p>
          <h2 id="product-workflow-title">From discovery to fix without collapsing the context.</h2>
        </div>
        <div className="idt-product-workflow-grid">
          <article>
            <span>Discover</span>
            <strong>Map the reachable identity graph across repositories, cloud roles, and Kubernetes workloads.</strong>
          </article>
          <article>
            <span>Prioritize</span>
            <strong>Separate noisy permissions from the paths that can actually reach sensitive resources.</strong>
          </article>
          <article>
            <span>Control</span>
            <strong>Ship least-privilege fixes with simulation, audit history, and rollback-ready guardrails.</strong>
          </article>
        </div>
        <div className="idt-product-cta-row">
          <div>
            <p className="idt-eyebrow">Technical walkthrough</p>
            <h2>Bring one risky path. Leave with the evidence and rollout plan.</h2>
          </div>
          <div className="idt-inline-actions">
            <Link to="/demo" className="idt-btn idt-btn-primary">
              Book Demo
            </Link>
            <Link to="/docs" className="idt-btn idt-btn-dark">
              Review Docs
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}

function FeaturesPage() {
  useSeo({
    title: 'Features | AWS IAM, Kubernetes RBAC, Git Scanner, Trust Graph',
    description:
      'Explore Identrail features for AWS machine identities, Kubernetes RBAC visibility, Git exposure scanning, and interactive trust graph analysis.',
    path: '/features'
  });

  const featureSummaries = [
    {
      id: 'aws',
      title: 'AWS IAM Security',
      body: 'Discover roles, policies, trust relationships, and cross-account assumptions in one explainable graph.',
      href: '/features/aws',
      bullets: [
        'Map role assumption chains and transitive trust paths',
        'Detect wildcard trust and overprivileged action sets',
        'Prioritize exposure by reachable resource sensitivity'
      ]
    },
    {
      id: 'kubernetes',
      title: 'Kubernetes Machine Identity',
      body: 'Correlate service accounts, tokens, RBAC bindings, and workload privileges with cluster context.',
      href: '/features/kubernetes',
      bullets: [
        'Identify namespace and cluster-level privilege escalation paths',
        'Trace service account to cloud-role federation',
        'Simulate RBAC control tightening before rollout'
      ]
    },
    {
      id: 'git-scanner',
      title: 'Git Scanner',
      body: 'Scan repositories for machine credential leaks and risky identity configuration patterns.',
      href: '/features/git-scanner',
      bullets: [
        'Continuous and historical scan support',
        'Policy-backed detector tuning',
        'Findings linked directly to trust graph context'
      ]
    },
    {
      id: 'trust-graph',
      title: 'Interactive Trust Graph',
      body: 'Visualize how identities reach resources and why a detection matters, with actionable remediation paths.',
      href: '/features/trust-graph',
      bullets: [
        'Path-based impact previews',
        'Evidence snapshots for audits',
        'Exportable remediation stories for engineering teams'
      ]
    }
  ] as const;

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Features</p>
        <h1>Built for cloud-native machine identity security at scale</h1>
        <p>Deep technical workflows for security and platform teams, from discovery to rollout-safe control.</p>
      </section>

      {featureSummaries.map((feature) => (
        <section key={feature.id} className="idt-section idt-shell" id={feature.id}>
          <article className="idt-card idt-feature-callout">
            <h2>{feature.title}</h2>
            <p>{feature.body}</p>
            <ul>
              {feature.bullets.map((bullet) => (
                <li key={bullet}>{bullet}</li>
              ))}
            </ul>
            <div className="idt-inline-actions idt-inline-actions-tight">
              <Link to={feature.href} className="idt-btn idt-btn-primary">
                Explore {feature.title}
              </Link>
              <Link to="/demo" className="idt-btn idt-btn-ghost">
                Open Demo
              </Link>
            </div>
          </article>
        </section>
      ))}
    </>
  );
}

function FeatureDetailPage({ page }: { page: (typeof FEATURE_DEEP_PAGES)[number] }) {
  useSeo({
    title: `${page.heroTitle} | Identrail Features`,
    description: page.description,
    path: `/features/${page.slug}`
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Feature: {page.navLabel}</p>
        <h1>{page.heroTitle}</h1>
        <p>{page.description}</p>
        <div className="idt-inline-actions">
          <Link to="/demo" className="idt-btn idt-btn-primary">
            Open Interactive Demo
          </Link>
          <Link to="/read-only-scan" className="idt-btn idt-btn-dark">
            Start Free Risk Scan
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Star on GitHub
          </SafeLink>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col idt-feature-detail-grid">
          <article className="idt-card">
            <h2>What this feature gives you</h2>
            <ul>
              {page.bullets.map((bullet) => (
                <li key={bullet}>{bullet}</li>
              ))}
            </ul>
          </article>
          <article className="idt-card">
            <h2>Expected outcomes</h2>
            <ul>
              {page.outcomes.map((outcome) => (
                <li key={outcome}>{outcome}</li>
              ))}
            </ul>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <LeadCaptureForm
          title={`Get a ${page.navLabel} workflow walkthrough`}
          caption="Share your environment goals and we will tailor a practical machine identity rollout plan."
          ctaLabel="Start Free Risk Scan"
        />
      </section>
    </>
  );
}

function SolutionsPage() {
  useSeo({
    title: 'Solutions | AWS, Kubernetes, Multi-cloud, Security and Platform Teams',
    description:
      'Solution patterns for AWS IAM, Kubernetes RBAC, multi-cloud identities, platform engineering teams, and security operations.',
    path: '/solutions'
  });

  const solutions = [
    {
      title: 'AWS Security Teams',
      body: 'Reduce IAM blast radius with trust path evidence, role chain analysis, and policy simulations.',
      metric: 'Cut overprivileged role exposure by 60-90%',
      href: '/solutions/aws'
    },
    {
      title: 'Kubernetes Platform Teams',
      body: 'Gain visibility into service account privileges and prevent RBAC drift before incidents happen.',
      metric: 'Reduce cluster authz incidents with staged controls',
      href: '/solutions/kubernetes'
    },
    {
      title: 'Multi-cloud Environments',
      body: 'Normalize machine identity data across providers with one operational control layer.',
      metric: 'Unify remediation workflows across clouds',
      href: '/solutions/multi-cloud'
    },
    {
      title: 'Platform Engineering',
      body: 'Ship authorization changes faster with simulation, rollout safety, and clear policy traceability.',
      metric: 'Deliver identity controls without release friction',
      href: '/solutions/platform-engineering'
    },
    {
      title: 'Security Operations',
      body: 'Prioritize detections with high exploitability and route to owners using trust graph context.',
      metric: 'Lower mean time to remediation',
      href: '/solutions/security-teams'
    }
  ] as const;

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Solutions</p>
        <h1>Deployment-ready outcomes for every team responsible for machine identity risk</h1>
      </section>
      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col idt-solutions-grid">
          {solutions.map((solution) => (
            <article key={solution.title} className="idt-card">
              <h2>{solution.title}</h2>
              <p>{solution.body}</p>
              <p className="idt-muted-strong">{solution.metric}</p>
              <div className="idt-inline-actions idt-inline-actions-tight">
                <Link to={solution.href} className="idt-btn idt-btn-primary">
                  Explore solution
                </Link>
              </div>
            </article>
          ))}
        </div>
      </section>
      <section className="idt-section idt-shell">
        <CalendlyEmbed />
      </section>
    </>
  );
}

function SolutionDetailPage({ page }: { page: (typeof SOLUTION_DEEP_PAGES)[number] }) {
  useSeo({
    title: `${page.heroTitle} | Identrail Solutions`,
    description: page.description,
    path: `/solutions/${page.slug}`
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Solution: {page.navLabel}</p>
        <h1>{page.heroTitle}</h1>
        <p>{page.description}</p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col idt-solution-detail-grid">
          <article className="idt-card">
            <h2>How teams use this solution</h2>
            <ul>
              {page.bullets.map((bullet) => (
                <li key={bullet}>{bullet}</li>
              ))}
            </ul>
          </article>
          <article className="idt-card">
            <h2>Business outcomes</h2>
            <ul>
              {page.outcomes.map((outcome) => (
                <li key={outcome}>{outcome}</li>
              ))}
            </ul>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-inline-actions">
          <Link to="/enterprise" className="idt-btn idt-btn-primary">
            Book Demo
          </Link>
          <Link to="/pricing" className="idt-btn idt-btn-dark">
            Compare Plans
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Deploy Self-Hosted
          </SafeLink>
        </div>
      </section>
    </>
  );
}

function PricingPage() {
  useSeo({
    title: 'Pricing | Open Source, Pro SaaS, and Enterprise',
    description:
      'Compare Identrail pricing plans: open source self-hosted, Pro hosted SaaS, and Enterprise machine identity security.',
    path: '/pricing',
    schemaType: 'Product'
  });

  const [annual, setAnnual] = useState(true);
  const [salesModalOpen, setSalesModalOpen] = useState(false);

  const proPrice = annual ? 59 : 79;

  return (
    <>
      <PageHero
        eyebrow="Pricing"
        title="Pricing aligned to how teams adopt machine identity security"
        body="Start with open source, move to hosted Pro for speed, then scale to enterprise controls when needed."
        variant="pricing"
        visual={<PricingHeroVisual />}
        actions={
          <>
            <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
              Start Free Risk Scan
            </Link>
            <button type="button" className="idt-btn idt-btn-dark" onClick={() => setSalesModalOpen(true)}>
              Talk to Enterprise
            </button>
          </>
        }
      />

      <section className="idt-section idt-shell">
        <div className="idt-pricing-toggle" role="group" aria-label="Pricing cadence">
          <button type="button" className={!annual ? 'is-active' : ''} onClick={() => setAnnual(false)}>
            Monthly
          </button>
          <button type="button" className={annual ? 'is-active' : ''} onClick={() => setAnnual(true)}>
            Annual <span>Save 25%</span>
          </button>
        </div>
        <p className="idt-pricing-note">
          Pro pricing is billed per user per month. All plans support read-only onboarding before any enforcement changes.
        </p>

        <div className="idt-pricing-grid idt-pricing-section">
          <article className="idt-pricing-card">
            <h2>Open Source</h2>
            <p className="idt-price">$0</p>
            <p className="idt-plan-fit">
              <strong>Best for:</strong> Self-hosted evaluation and internal platform control.
            </p>
            <p>Self-hosted core platform for AWS + Kubernetes machine identity workflows.</p>
            <ul>
              <li>Trust graph + exposure detections</li>
              <li>Community support</li>
              <li>API and docs access</li>
            </ul>
            <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
              Deploy Self-Hosted
            </SafeLink>
          </article>

          <article className="idt-pricing-card is-featured">
            <p className="idt-badge">Most Popular</p>
            <h2>Pro</h2>
            <p className="idt-price">
              ${proPrice}
              <span>/user/mo</span>
            </p>
            <p className="idt-plan-fit">
              <strong>Best for:</strong> Fast time-to-value without managing infrastructure.
            </p>
            <p>Hosted SaaS with advanced detections, collaboration workflows, and managed operations.</p>
            <ul>
              <li>Everything in Open Source</li>
              <li>Hosted trust graph and accelerated queries</li>
              <li>SAML SSO, alerts, and workflow integrations</li>
              <li>14-day hosted trial with guided setup</li>
            </ul>
            <Link to="/enterprise" className="idt-btn idt-btn-primary">
              Start Free Risk Scan
            </Link>
          </article>

          <article className="idt-pricing-card">
            <h2>Enterprise</h2>
            <p className="idt-price">Starting at $50k/yr</p>
            <p className="idt-plan-fit">
              <strong>Best for:</strong> Private deployment, procurement workflows, and advanced governance.
            </p>
            <p>Advanced governance, private deployment options, and enterprise-grade support.</p>
            <ul>
              <li>Everything in Pro</li>
              <li>SCIM, regional controls, and private tenancy</li>
              <li>24/7 support, SLA, TAM, and onboarding program</li>
            </ul>
            <button type="button" className="idt-btn idt-btn-dark" onClick={() => setSalesModalOpen(true)}>
              Contact Sales
            </button>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Feature Matrix"
          title="Compare plan capabilities"
          body="Move from OSS to enterprise without replacing your workflows."
        />
        <div className="idt-table-wrap">
          <table className="idt-compare-table">
            <thead>
              <tr>
                <th scope="col">Capability</th>
                <th scope="col">Open Source</th>
                <th scope="col">Pro</th>
                <th scope="col">Enterprise</th>
              </tr>
            </thead>
            <tbody>
              {FEATURE_ROWS.map((row) => (
                <tr key={row.capability}>
                  <th scope="row">{row.capability}</th>
                  <td>{row.openSource}</td>
                  <td>{row.pro}</td>
                  <td>{row.enterprise}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="idt-section idt-shell idt-pricing-roi">
        <SectionTitle
          eyebrow="Impact Model"
          title="Need ROI modeling before procurement?"
          body="Use the dedicated ROI assessment page with transparent assumptions and editable parameters."
        />
        <div className="idt-inline-actions">
          <Link to="/roi-assessment" className="idt-btn idt-btn-primary">
            Open ROI Assessment
          </Link>
          <Link to="/read-only-scan" className="idt-btn idt-btn-dark">
            Start Free Risk Scan
          </Link>
        </div>
      </section>

      {salesModalOpen ? (
        <ModalShell titleId="sales-modal-title" onClose={() => setSalesModalOpen(false)}>
          <button
            type="button"
            className="idt-modal-close"
            aria-label="Close"
            onClick={() => setSalesModalOpen(false)}
          >
            x
          </button>
          <h3 id="sales-modal-title">Contact Enterprise Sales</h3>
          <p>Tell us your environment size and compliance goals. We will tailor a deployment and pricing plan.</p>
          <LeadCaptureForm
            compact
            title="Enterprise Sales"
            caption="Expected response time: under 1 business day."
            ctaLabel="Contact Sales"
          />
        </ModalShell>
      ) : null}
    </>
  );
}

function RoiAssessmentPage() {
  useSeo({
    title: 'ROI Assessment | Machine Identity Security Impact Model',
    description:
      'Run a transparent ROI assessment for machine identity security risk reduction with editable assumptions and impact calculations.',
    path: '/roi-assessment'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">ROI Assessment</p>
        <h1>Model risk-reduction impact with transparent assumptions</h1>
        <p>
          This tool is a planning model, not a guarantee. Adjust each input to match your environment and validate assumptions with
          your security and finance stakeholders.
        </p>
      </section>

      <section className="idt-section idt-shell">
        <RoiCalculator />
        <p className="idt-roi-disclaimer">
          Assumptions: labor savings = weekly triage hours × 52 × $110; incident exposure reduction coefficient = 0.87; high-risk
          identity reduction coefficient = 0.32.
        </p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-inline-actions">
          <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
            Start Free Risk Scan
          </Link>
          <Link to="/pricing" className="idt-btn idt-btn-dark">
            Compare Pricing Plans
          </Link>
        </div>
      </section>
    </>
  );
}

function DeploymentModelsPage() {
  useSeo({
    title: 'Deployment Models | Open-Core, Hosted, and Enterprise',
    description:
      'Compare Identrail deployment models for machine identity security: self-hosted open-core, hosted SaaS, and enterprise private deployment.',
    path: '/deployment-models'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Deployment Models</p>
        <h1>Choose your control boundary without changing operating model</h1>
        <p>
          Identrail keeps the same trust-path workflow across open-core, hosted SaaS, and enterprise deployments. Choose based on
          control, speed, and governance requirements.
        </p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid three-col">
          <article className="idt-card">
            <h2>Open-Core</h2>
            <p>
              <strong>Best for:</strong> teams that require self-hosted control and deep platform customization.
            </p>
            <ul>
              <li>Run in your infrastructure</li>
              <li>Community support and docs</li>
              <li>Transparent architecture and source</li>
            </ul>
            <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
              View Open Source
            </SafeLink>
          </article>
          <article className="idt-card">
            <h2>Hosted SaaS</h2>
            <p>
              <strong>Best for:</strong> fastest time-to-value with managed operations.
            </p>
            <ul>
              <li>Managed platform operations</li>
              <li>Read-only onboarding for first scan</li>
              <li>Accelerated query and collaboration workflows</li>
            </ul>
            <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
              Start Free Risk Scan
            </Link>
          </article>
          <article className="idt-card">
            <h2>Enterprise Private</h2>
            <p>
              <strong>Best for:</strong> private tenancy, procurement controls, and advanced support programs.
            </p>
            <ul>
              <li>Private deployment options</li>
              <li>SCIM and advanced governance controls</li>
              <li>24/7 support and named TAM</li>
            </ul>
            <Link to="/enterprise" className="idt-btn idt-btn-dark">
              Book Demo
            </Link>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Capability Matrix"
          title="Deployment differences by capability"
          body="Use this matrix to align your deployment choice with security controls, data residency, and support needs."
        />
        <div className="idt-table-wrap">
          <table className="idt-compare-table">
            <thead>
              <tr>
                <th scope="col">Capability</th>
                <th scope="col">Open-Core</th>
                <th scope="col">Hosted SaaS</th>
                <th scope="col">Enterprise</th>
              </tr>
            </thead>
            <tbody>
              {FEATURE_ROWS.map((row) => (
                <tr key={row.capability}>
                  <th scope="row">{row.capability}</th>
                  <td>{row.openSource}</td>
                  <td>{row.pro}</td>
                  <td>{row.enterprise}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function IntegrationsPage() {
  useSeo({
    title: 'Integrations | Machine Identity Signal Coverage',
    description:
      'Review Identrail integration coverage across AWS IAM, Kubernetes, GitHub, OpenID Connect, and Prometheus with depth and signal details.',
    path: '/integrations'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Integrations</p>
        <h1>Identity signal coverage across cloud, cluster, and code workflows</h1>
        <p>
          Identrail unifies machine identity telemetry into one trust-path analysis model. Use this page to verify connector depth
          before rollout.
        </p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-table-wrap">
          <table className="idt-compare-table">
            <thead>
              <tr>
                <th scope="col">Integration</th>
                <th scope="col">Signals captured</th>
                <th scope="col">Depth</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {INTEGRATION_ROWS.map((row) => (
                <tr key={row.source}>
                  <th scope="row">{row.source}</th>
                  <td>{row.signals}</td>
                  <td>{row.depth}</td>
                  <td>{row.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>Integration onboarding workflow</h2>
            <ul>
              <li>Start with read-only connector setup and source validation</li>
              <li>Confirm trust-path ingestion and evidence mapping</li>
              <li>Review first prioritized findings with platform owners</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Technical bridge</h2>
            <p>Need implementation details first? Review docs, then run your first guided scan intake.</p>
            <div className="idt-inline-actions">
              <SafeLink href={DOCS_REPO} className="idt-btn idt-btn-ghost">
                Open Documentation
              </SafeLink>
              <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
                Start Free Risk Scan
              </Link>
            </div>
          </article>
        </div>
      </section>
    </>
  );
}

function DemoPage() {
  useSeo({
    title: 'Demo | Interactive Trust Graph',
    description:
      'Explore the Identrail interactive trust graph demo for AWS IAM and Kubernetes machine identities.',
    path: '/demo'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Interactive Demo</p>
        <h1>Simulate real trust-path investigation in a production-style environment</h1>
        <p>Explore node relationships, inspect risk context, and test rollout-safe controls from one console.</p>
      </section>

      <section className="idt-section idt-shell">
        <TrustGraphDemo variant="full" />
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>What this demo includes</h2>
            <ul>
              <li>Machine identity sources across AWS IAM, Kubernetes, and Git workflows</li>
              <li>Risk severity and blast-radius context for each trust path</li>
              <li>Explainable remediation guidance before policy changes are enforced</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>What to do next</h2>
            <p>Run a free risk scan to map your own trust paths, or book a guided walkthrough with security engineering.</p>
            <div className="idt-inline-actions">
              <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
                Start Free Risk Scan
              </Link>
              <Link to="/enterprise" className="idt-btn idt-btn-dark">
                Book Demo
              </Link>
            </div>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell idt-connect-cloud">
        <SectionTitle
          eyebrow="Next Step"
          title="One-click connect your cloud"
          body="Start in hosted SaaS or self-host OSS and import your first AWS account or Kubernetes cluster."
        />
        <div className="idt-inline-actions">
          <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
            Start Free Risk Scan
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Run Self-Hosted
          </SafeLink>
        </div>
      </section>
    </>
  );
}

function DocsPage() {
  useSeo({
    title: 'Docs | Identrail Documentation',
    description:
      'Developer-first machine identity documentation with quickstarts, architecture, deployment runbooks, and API guides.',
    path: '/docs'
  });

  const [query, setQuery] = useState('');
  const normalized = query.trim().toLowerCase();

  const filtered = DOC_ENTRIES.filter((entry) => {
    if (!normalized) return true;
    return (
      entry.title.toLowerCase().includes(normalized) ||
      entry.description.toLowerCase().includes(normalized) ||
      entry.tags.some((tag) => tag.toLowerCase().includes(normalized))
    );
  });

  return (
    <>
      <PageHero
        eyebrow="Docs"
        title="Deploy, connect, and operate Identrail in production"
        body="Fast search, practical runbooks, and source-linked operator docs for production rollouts."
        variant="docs"
        visual={<DocsHeroVisual />}
        actions={
          <SafeLink href={DOCS_REPO} className="idt-btn idt-btn-primary">
            Open Full GitHub Docs
          </SafeLink>
        }
      />

      <section className="idt-section idt-shell">
        <div className="idt-card-grid three-col">
          {DOC_ENTRIES.slice(0, 3).map((entry) => (
            <article key={entry.href} className="idt-card idt-doc-highlight-card">
              <p className="idt-eyebrow">Quickstart</p>
              <h2>{entry.title}</h2>
              <p>{entry.description}</p>
              <SafeLink href={entry.href} className="idt-inline-link">
                Open guide
              </SafeLink>
            </article>
          ))}
        </div>
      </section>

      <section className="idt-section idt-shell">
        <label className="idt-search" htmlFor="docs-query">
          Search docs topics
          <input
            id="docs-query"
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Try: kubernetes, hardening, quickstart"
          />
        </label>

        {filtered.length > 0 ? (
          <div className="idt-card-grid two-col idt-docs-grid">
            {filtered.map((entry) => (
              <article key={entry.href} className="idt-card">
                <h2>{entry.title}</h2>
                <p>{entry.description}</p>
                <p className="idt-doc-tags">{entry.tags.join(' / ')}</p>
                <SafeLink href={entry.href} className="idt-btn idt-btn-ghost">
                  Read guide
                </SafeLink>
              </article>
            ))}
          </div>
        ) : (
          <article className="idt-card idt-empty-state">
            <h2>No docs match that query</h2>
            <p>Try a broader search term such as aws, kubernetes, deployment, or security.</p>
            <SafeLink href={DOCS_REPO} className="idt-btn idt-btn-ghost">
              Browse full docs index
            </SafeLink>
          </article>
        )}
      </section>

      <section className="idt-section idt-shell">
        <CalendlyEmbed />
      </section>
    </>
  );
}

function BlogPage() {
  useSeo({
    title: 'Blog & Resources | Machine Identity Security Insights',
    description:
      'SEO-optimized resources on machine identity security, Kubernetes machine identity, AWS NHI security, and non-human identity management.',
    path: '/blog',
    schemaType: 'Article'
  });

  return (
    <>
      <PageHero
        eyebrow="Blog & Resources"
        title="Actionable content for security and platform teams operating machine identities"
        body="Educational deep dives, implementation playbooks, and strategic guidance for enterprise buyers."
        variant="blog"
        visual={<BlogHeroVisual />}
        actions={
          <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
            Start Free Risk Scan
          </Link>
        }
      />

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col idt-blog-grid">
          {BLOG_POSTS.map((post) => (
            <article key={post.slug} className="idt-card">
              <p className="idt-chip-row">
                <span>{post.category}</span>
                <span>{post.readTime}</span>
              </p>
              <h2>{post.title}</h2>
              <p>{post.description}</p>
              <Link to={`/blog/${post.slug}`} className="idt-btn idt-btn-ghost">
                Read article
              </Link>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}

function BlogArticlePage() {
  const { slug } = useParams<{ slug: string }>();
  const post = BLOG_POSTS.find((entry) => entry.slug === slug);
  const seoTitle = post ? `${post.title} | Identrail Blog` : 'Blog Article | Identrail';
  const seoDescription = post ? post.description : 'Explore machine identity security guidance from Identrail.';
  const seoPath = post ? `/blog/${post.slug}` : '/blog';

  useSeo({
    title: seoTitle,
    description: seoDescription,
    path: seoPath,
    schemaType: 'Article'
  });

  if (!post) {
    return <NotFoundPage />;
  }

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">{post.category}</p>
        <h1>{post.title}</h1>
        <p>{post.description}</p>
      </section>

      <section className="idt-section idt-shell">
        <article className="idt-card idt-blog-article">
          <p className="idt-chip-row">
            <span>{post.category}</span>
            <span>{post.readTime}</span>
          </p>
          {post.intro.map((paragraph) => (
            <p key={paragraph} className="idt-blog-lead">
              {paragraph}
            </p>
          ))}
          {post.sections.map((section) => (
            <section key={section.heading} className="idt-blog-section">
              <h2>{section.heading}</h2>
              {section.paragraphs.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
              {section.bullets ? (
                <ul>
                  {section.bullets.map((bullet) => (
                    <li key={bullet}>{bullet}</li>
                  ))}
                </ul>
              ) : null}
            </section>
          ))}
          <section className="idt-blog-section">
            <h2>References and further reading</h2>
            <ul className="idt-blog-reference-list">
              {post.references.map((reference) => (
                <li key={reference.href}>
                  <SafeLink href={reference.href} className="idt-inline-link">
                    {reference.label}
                  </SafeLink>
                </li>
              ))}
            </ul>
          </section>
          <div className="idt-inline-actions">
            <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
              Start Free Risk Scan
            </Link>
            <Link to="/blog" className="idt-btn idt-btn-ghost">
              Back to Blog
            </Link>
          </div>
        </article>
      </section>
    </>
  );
}

function SecurityPage() {
  useSeo({
    title: 'Security & Compliance | Identrail',
    description:
      'Security, compliance, and trust information for Identrail including SOC 2 roadmap, ISO 27001 controls, bug bounty, and data residency.',
    path: '/security'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Security & Compliance</p>
        <h1>Security-first architecture with transparent compliance posture</h1>
        <p>Built for teams that need hardening depth, audit evidence, and enterprise trust controls.</p>
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Read-Only Model"
          title="Collection boundaries and control guarantees"
          body="Use this matrix to validate how Identrail collects trust data and where write actions are intentionally excluded."
        />
        <div className="idt-table-wrap">
          <table className="idt-compare-table">
            <thead>
              <tr>
                <th scope="col">Control area</th>
                <th scope="col">What Identrail does</th>
                <th scope="col">What Identrail does not do</th>
              </tr>
            </thead>
            <tbody>
              {READ_ONLY_CONTROL_ROWS.map((row) => (
                <tr key={row.area}>
                  <th scope="row">{row.area}</th>
                  <td>{row.access}</td>
                  <td>{row.excluded}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col idt-security-grid">
          <article className="idt-card">
            <h2>Compliance roadmap</h2>
            <ul>
              <li>SOC 2 Type II: In progress, target completion Q4 2026</li>
              <li>ISO 27001: Control framework in implementation</li>
              <li>Customer security questionnaires: Supported</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Security program</h2>
            <ul>
              <li>Vulnerability disclosure via security.txt</li>
              <li>Third-party penetration testing summary available under NDA</li>
              <li>Secure SDLC with code scanning and dependency management</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Data residency</h2>
            <ul>
              <li>Hosted SaaS regions: US and EU</li>
              <li>Enterprise private tenancy options</li>
              <li>Self-hosted deployment for full data control</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Trust center operations</h2>
            <ul>
              <li>Documented incident response runbook</li>
              <li>Encryption in transit and at rest</li>
              <li>Role-based access and least-privilege internal controls</li>
            </ul>
          </article>
        </div>
      </section>
      <section className="idt-section idt-shell">
        <div className="idt-inline-actions">
          <Link to="/responsible-disclosure" className="idt-btn idt-btn-dark">
            Responsible Disclosure
          </Link>
          <Link to="/read-only-scan" className="idt-btn idt-btn-primary">
            Start Free Risk Scan
          </Link>
          <SafeLink href={DOCS_REPO} className="idt-btn idt-btn-ghost">
            Review Security Docs
          </SafeLink>
        </div>
      </section>
    </>
  );
}

function ResponsibleDisclosurePage() {
  useSeo({
    title: 'Responsible Disclosure | Identrail Security',
    description:
      'Report potential vulnerabilities to Identrail using our responsible disclosure process and coordinated response workflow.',
    path: '/responsible-disclosure'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Responsible Disclosure</p>
        <h1>Report security issues through a coordinated disclosure process</h1>
        <p>We investigate security reports promptly and coordinate remediation and communication with reporters.</p>
      </section>
      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>How to report</h2>
            <ul>
              <li>
                Email <a href="mailto:security@identrail.com">security@identrail.com</a> with detailed findings and
                proof-of-concept steps
              </li>
              <li>Include reproduction steps, affected components, and potential impact</li>
              <li>
                Reference our security.txt policy at <code>/.well-known/security.txt</code> for reporting scope and expectations
              </li>
              <li>Avoid public disclosure until coordinated remediation is completed</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Response expectations</h2>
            <ul>
              <li>Initial acknowledgement within one business day</li>
              <li>Triage and severity classification with engineering review</li>
              <li>Status updates at least every three business days until remediation is complete</li>
              <li>Coordinated disclosure timeline after remediation is validated</li>
            </ul>
          </article>
        </div>
      </section>
    </>
  );
}

function AboutPage() {
  useSeo({
    title: 'About Identrail | Open-Core Machine Identity Company',
    description:
      'Learn about Identrail, the open-core machine identity security platform built for AWS, Kubernetes, and modern platform teams.',
    path: '/about',
    schemaType: 'AboutPage'
  });

  return (
    <>
      <PageHero
        eyebrow="Company"
        title="Building the future control plane for machine identity security"
        body="Identrail exists to make machine identity risk understandable, operable, and controllable for every engineering-driven organization."
        variant="about"
        visual={<AboutHeroVisual />}
        actions={
          <>
            <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-primary">
              View Open Source
            </SafeLink>
            <Link to="/enterprise" className="idt-btn idt-btn-dark">
              Partner with Us
            </Link>
          </>
        }
      />

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col idt-about-grid">
          <article className="idt-card">
            <h2>Mission</h2>
            <p>Help teams discover and control non-human identity risk before it becomes incident-level blast radius.</p>
          </article>
          <article className="idt-card">
            <h2>Model</h2>
            <p>Open-source core for speed and transparency, plus hosted and enterprise options for scale.</p>
          </article>
          <article className="idt-card">
            <h2>Community</h2>
            <p>Developer-first collaboration through GitHub, docs, contributor guides, and Discord.</p>
          </article>
          <article className="idt-card">
            <h2>Enterprise partnership</h2>
            <p>Support for procurement, compliance, and strategic deployment in regulated environments.</p>
          </article>
        </div>
      </section>
    </>
  );
}

function EnterprisePage() {
  useSeo({
    title: 'Enterprise Sales | Identrail',
    description:
      'Talk to Identrail enterprise sales for machine identity security programs spanning AWS, Kubernetes, and software supply chain risk.',
    path: '/enterprise'
  });

  return (
    <>
      <PageHero
        eyebrow="Enterprise"
        title="Enterprise machine identity programs that satisfy security, platform, and procurement stakeholders"
        body="Standard deal range: $50k-$500k+ ACV with tailored rollout plans, architecture support, and compliance alignment."
        variant="enterprise"
        visual={<EnterpriseHeroVisual />}
        actions={
          <>
            <Link to="/demo" className="idt-btn idt-btn-primary">
              Book Demo
            </Link>
            <Link to="/security" className="idt-btn idt-btn-dark">
              Review Security
            </Link>
          </>
        }
      />

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col idt-enterprise-grid">
          <article className="idt-card">
            <h2>What enterprise buyers get</h2>
            <ul>
              <li>Private tenancy and data residency options</li>
              <li>SSO/SAML, SCIM, and granular access controls</li>
              <li>24/7 support with named technical account manager</li>
              <li>Joint rollout plan for high-impact environments</li>
            </ul>
          </article>
          <LeadCaptureForm
            title="Talk to Enterprise Sales"
            caption="Share environment scope and business goals to get a deployment blueprint and pricing proposal."
            ctaLabel="Book Demo"
          />
        </div>
      </section>

      <section className="idt-section idt-shell">
        <CalendlyEmbed />
      </section>
    </>
  );
}

function LegalPage({ title, body }: { title: string; body: string }) {
  useSeo({
    title: `${title} | Identrail`,
    description: `${title} policy for Identrail website and platform experiences.`,
    path: `/${title.toLowerCase().replace(/\s+/g, '-')}`
  });

  return (
    <section className="idt-page-hero idt-shell">
      <h1>{title}</h1>
      <p>{body}</p>
    </section>
  );
}

const PRIVACY_POLICY_SECTIONS = [
  {
    title: 'Google sign-in data accessed',
    body: [
      'When you choose Continue with Google, Identrail uses Google OAuth/OpenID Connect only to authenticate you and create or access your Identrail account. The Google user data we may receive is your Google account subject identifier, email address, email verification status, display name, profile image URL, locale, and the technical tokens or claims required to complete sign-in.',
      'Identrail does not use Google sign-in to access Gmail, Google Drive, Google Calendar, Google Contacts, Google Photos, or other Google Workspace content.'
    ]
  },
  {
    title: 'How Google user data is used',
    body: [
      'We use Google user data to verify your identity, create and maintain your Identrail account, establish secure sessions, prevent account takeover, match pending invitations to the email address you authenticated with, display basic account information, and keep audit records needed for security and abuse prevention.',
      'We do not use Google user data for advertising, retargeting, personalized ads, credit decisions, data brokerage, or sale to third parties.'
    ]
  },
  {
    title: 'How Google user data is shared',
    body: [
      'Identrail does not sell Google user data. We share it only with service providers that help operate the product, such as authentication infrastructure, cloud hosting, database, observability, security, and customer-support providers, and only for the purpose of providing, securing, or supporting Identrail.',
      'We may also disclose limited information if required by law, to protect users or the service, or as part of a merger, acquisition, or sale of assets subject to appropriate user notice or consent where required.'
    ]
  },
  {
    title: 'Storage and protection',
    body: [
      'Google-derived account identifiers and profile fields are stored in Identrail account and identity records. Sessions are protected with secure, HttpOnly cookies. Production data is protected with encryption in transit, access controls, least-privilege operational access, monitoring, and environment-specific secret management.',
      'Human access to account data is limited to personnel or processors who need it to operate, secure, troubleshoot, or support the service.'
    ]
  },
  {
    title: 'Retention and deletion',
    body: [
      'We retain Google-derived account data while your Identrail account is active or as needed to provide the service, comply with legal obligations, resolve disputes, enforce agreements, preserve security logs, and maintain backups.',
      'You can request deletion of your account or Google-derived user data by emailing security@identrail.com with the subject Privacy Request. After verifying the request, we delete or de-identify applicable account data unless retention is required for security, legal, or operational reasons. Backup and log copies expire under our normal retention schedules.'
    ]
  },
  {
    title: 'Google API limited use',
    body: [
      'Identrail uses information received from Google APIs in accordance with the Google API Services User Data Policy, including the Limited Use requirements.'
    ]
  }
] as const;

const TERMS_OF_USE_SECTIONS = [
  {
    title: 'Acceptance and scope',
    body: [
      'These Terms of Use govern access to Identrail websites, documentation, hosted product experiences, public demos, and related services. By using Identrail, you agree to follow these terms and all applicable laws.',
      'Separate written agreements, order forms, data-processing terms, or open-source licenses may apply to specific paid services, enterprise deployments, or repository code. If those terms conflict with this page, the more specific written terms control for that scope.'
    ]
  },
  {
    title: 'Accounts and access',
    body: [
      'You are responsible for keeping account credentials, single sign-on access, API keys, and authorized sessions secure. You must provide accurate account information and promptly revoke access for users who no longer need it.',
      'Identrail may suspend or limit access when needed to protect the service, investigate abuse, comply with law, or address security or operational risk.'
    ]
  },
  {
    title: 'Acceptable use',
    body: [
      'You may not use Identrail to attack, disrupt, overload, reverse engineer, or bypass security controls of Identrail or third-party systems. You may not upload unlawful content, malware, secrets you are not authorized to process, or data that violates another party\'s rights.',
      'Security testing of Identrail must follow the Responsible Disclosure policy and avoid privacy violations, data destruction, social engineering, or service disruption.'
    ]
  },
  {
    title: 'Customer data and integrations',
    body: [
      'You retain ownership of data you submit, connect, or authorize Identrail to process. You grant Identrail the limited rights needed to provide, secure, troubleshoot, improve, and support the service.',
      'You are responsible for ensuring that connector credentials, cloud permissions, repository access, and identity-provider scopes you authorize are appropriate for your organization and permitted under your own policies.'
    ]
  },
  {
    title: 'Intellectual property',
    body: [
      'Identrail and its licensors retain all rights in the Identrail service, brand, website, product design, documentation, and related materials except where an open-source license expressly grants rights in repository code.',
      'Feedback may be used to improve Identrail without obligation to you, while preserving any confidentiality obligations that apply under separate written terms.'
    ]
  },
  {
    title: 'Third-party services',
    body: [
      'Identrail may integrate with third-party identity providers, source-code hosts, cloud platforms, payment providers, analytics, observability, and support tools. Your use of those services may be governed by their own terms and policies.',
      'Identrail is not responsible for third-party services outside our control, but we design integrations to use scoped permissions and operational safeguards appropriate to the feature.'
    ]
  },
  {
    title: 'Disclaimers and liability',
    body: [
      'Identrail is provided as available unless a separate written agreement says otherwise. We do not guarantee uninterrupted availability, error-free operation, or that every identity, permission, exposure, or risk will be detected.',
      'To the fullest extent permitted by law, Identrail disclaims implied warranties and limits liability for indirect, incidental, consequential, special, exemplary, or punitive damages.'
    ]
  },
  {
    title: 'Changes and contact',
    body: [
      'We may update these terms as the product, legal requirements, or operating model changes. Material changes will be reflected on this page or communicated through appropriate product or account channels.',
      'Questions about these Terms of Use can be sent to security@identrail.com.'
    ]
  }
] as const;

function PrivacyPage() {
  useSeo({
    title: 'Privacy Policy | Identrail',
    description:
      'Read how Identrail accesses, uses, stores, protects, shares, retains, and deletes Google sign-in data and other account information.',
    path: '/privacy'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <h1>Privacy Policy</h1>
        <p>
          Identrail handles personal data with a security-first posture. This policy explains how we process
          website, account, and Google sign-in data for Identrail users.
        </p>
      </section>

      <section className="idt-section idt-shell idt-legal-policy" aria-labelledby="google-user-data">
        <div className="idt-section-title">
          <h2 id="google-user-data">Google user data disclosure</h2>
          <p>
            This section documents how Identrail interacts with Google user data when users sign in or sign up
            with Google.
          </p>
        </div>

        <div className="idt-card-grid two-col">
          {PRIVACY_POLICY_SECTIONS.map((section) => (
            <article key={section.title} className="idt-card">
              <h3>{section.title}</h3>
              {section.body.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
            </article>
          ))}
        </div>
      </section>

      <section className="idt-section idt-shell idt-section-tight">
        <div className="idt-card">
          <h2>Questions and requests</h2>
          <p>
            For privacy questions, account deletion requests, or requests about Google-derived user data, email{' '}
            <a href="mailto:security@identrail.com?subject=Privacy%20Request">security@identrail.com</a> with
            the subject Privacy Request.
          </p>
        </div>
      </section>
    </>
  );
}

function TermsPage() {
  useSeo({
    title: 'Terms of Use | Identrail',
    description:
      'Review the terms governing Identrail websites, hosted product experiences, documentation, accounts, integrations, and acceptable use.',
    path: '/terms'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <h1>Terms of Use</h1>
        <p>
          These terms set the baseline for using Identrail websites, product experiences, documentation,
          public resources, accounts, and integrations.
        </p>
      </section>

      <section className="idt-section idt-shell idt-legal-policy" aria-labelledby="terms-sections">
        <div className="idt-section-title">
          <h2 id="terms-sections">Standard terms</h2>
          <p>
            This page summarizes the obligations, restrictions, and operational expectations that apply when
            you use Identrail.
          </p>
        </div>

        <div className="idt-card-grid two-col">
          {TERMS_OF_USE_SECTIONS.map((section) => (
            <article key={section.title} className="idt-card">
              <h3>{section.title}</h3>
              {section.body.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
            </article>
          ))}
        </div>
      </section>
    </>
  );
}

function NotFoundPage() {
  useSeo({
    title: 'Page Not Found | Identrail',
    description: 'The page you requested could not be found.',
    path: '/404'
  });

  return (
    <section className="idt-page-hero idt-shell">
      <h1>404: Page not found</h1>
      <p>The page may have moved. Use the links below to continue.</p>
      <div className="idt-inline-actions">
        <Link to="/" className="idt-btn idt-btn-primary">
          Go to Homepage
        </Link>
        <Link to="/docs" className="idt-btn idt-btn-ghost">
          Open Docs
        </Link>
      </div>
    </section>
  );
}

export function RoutedSite() {
  useAnalytics();
  const location = useLocation();
  const isProductShellRoute = location.pathname.startsWith('/app') || location.pathname.startsWith('/reports');
  const isOnboardingRoute = location.pathname.startsWith('/onboarding');
  const normalizedPath = location.pathname.replace(/\/+$/, '') || '/';
  const isAuthChoiceRoute = normalizedPath === '/signin' || normalizedPath === '/signup' || normalizedPath === '/auth/mfa';

  useEffect(() => {
    document.documentElement.dataset.theme = 'light';
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, 'light');
    } catch {
      // Ignore storage write failures (blocked/disabled storage).
    }
  }, []);

  return (
    <div className={`idt-site ${isAuthChoiceRoute ? 'idt-site-auth' : ''}`}>
      <a className="idt-skip" href="#main-content">
        Skip to content
      </a>

      {!isProductShellRoute && !isOnboardingRoute && !isAuthChoiceRoute ? (
        <Header
          navLinks={NAV_LINKS}
          githubRepo={GITHUB_REPO}
        />
      ) : null}

      <main id="main-content">
        <Routes>
          <Route path="/signin" element={<SignInPage />} />
          <Route path="/signup" element={<SignUpPage />} />
          <Route path="/auth/callback" element={<AuthCallbackPage />} />
          <Route path="/auth/mfa" element={<WorkOSMFAPage />} />
          <Route path="/why-no-passwords" element={<WhyNoPasswordsPage />} />
          <Route path="/app/login" element={<ProductLoginPage />} />
          <Route path="/app/callback" element={<ProductAuthCallbackRedirectPage />} />
          <Route
            path="/app/github/callback"
            element={
              <RequireProductAuth>
                <ProductGitHubCallbackPage />
              </RequireProductAuth>
            }
          />
          <Route path="/app/logout" element={<ProductLogoutPage />} />
          <Route
            path="/reports/executive"
            element={
              <RequireProductAuth>
                <ProductExecutiveReportPage />
              </RequireProductAuth>
            }
          />
          <Route
            path="/onboarding/org"
            element={
              <RequireProductAuth>
                <RequireOnboardingBackend fallback={<ProductAppIndexRedirect />}>
                  <OrgPage />
                </RequireOnboardingBackend>
              </RequireProductAuth>
            }
          />
          <Route
            path="/onboarding/workspace"
            element={
              <RequireProductAuth>
                <RequireOnboardingBackend fallback={<ProductAppIndexRedirect />}>
                  <WorkspacePage />
                </RequireOnboardingBackend>
              </RequireProductAuth>
            }
          />
          <Route
            path="/onboarding/connect"
            element={
              <RequireProductAuth>
                <RequireOnboardingBackend fallback={<ProductAppIndexRedirect />}>
                  <ConnectPage />
                </RequireOnboardingBackend>
              </RequireProductAuth>
            }
          />
          <Route
            path="/onboarding/scan"
            element={
              <RequireProductAuth>
                <RequireOnboardingBackend fallback={<ProductAppIndexRedirect />}>
                  <ScanPage />
                </RequireOnboardingBackend>
              </RequireProductAuth>
            }
          />
          <Route
            path="/onboarding/invite"
            element={
              <RequireProductAuth>
                <RequireOnboardingBackend fallback={<ProductAppIndexRedirect />}>
                  <InvitePage />
                </RequireOnboardingBackend>
              </RequireProductAuth>
            }
          />
          <Route
            path="/app/account/security"
            element={
              <RequireProductAuth>
                <AccountSecurityPage />
              </RequireProductAuth>
            }
          />
          <Route
            path="/app"
            element={
              <RequireProductAuth>
                <ProductAppIndexRedirect />
              </RequireProductAuth>
            }
          />
          <Route
            path="/app/:tenantID/:workspaceID"
            element={
              <RequireProductAuth>
                <ProductShellLayout />
              </RequireProductAuth>
            }
          >
            <Route index element={<ProductOverviewPage />} />
            <Route path="workspaces" element={<ProductWorkspacesPage />} />
            <Route path="projects" element={<ProductProjectsPage />} />
            <Route path="projects/:projectID" element={<ProductProjectDetailPage />} />
            <Route path="findings" element={<ProductFindingsPage />} />
            <Route path="settings" element={<ProductSettingsPage />} />
          </Route>
          <Route path="/" element={<HomePage />} />
          <Route path="/product" element={<ProductPage />} />
          <Route path="/features" element={<FeaturesPage />} />
          <Route path="/integrations" element={<IntegrationsPage />} />
          {FEATURE_DEEP_PAGES.map((page) => (
            <Route key={page.slug} path={`/features/${page.slug}`} element={<FeatureDetailPage page={page} />} />
          ))}
          <Route path="/solutions" element={<SolutionsPage />} />
          {SOLUTION_DEEP_PAGES.map((page) => (
            <Route key={page.slug} path={`/solutions/${page.slug}`} element={<SolutionDetailPage page={page} />} />
          ))}
          <Route path="/pricing" element={<PricingPage />} />
          <Route path="/roi-assessment" element={<RoiAssessmentPage />} />
          <Route path="/read-only-scan" element={<ReadOnlyScanPage />} />
          <Route path="/deployment-models" element={<DeploymentModelsPage />} />
          <Route path="/demo" element={<DemoPage />} />
          <Route path="/docs" element={<DocsPage />} />
          <Route path="/faq" element={<FaqPage />} />
          <Route path="/blog" element={<BlogPage />} />
          <Route path="/blog/:slug" element={<BlogArticlePage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/responsible-disclosure" element={<ResponsibleDisclosurePage />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="/enterprise" element={<EnterprisePage />} />
          <Route path="/terms" element={<TermsPage />} />
          <Route path="/privacy" element={<PrivacyPage />} />
          <Route path="/privacy-choices" element={<LegalPage title="Privacy Choices" body="Manage analytics, communications, and data usage preferences for Identrail web experiences." />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>

      {!isProductShellRoute && !isOnboardingRoute && !isAuthChoiceRoute ? (
        <>
          <Footer xUrl={X_URL} linkedInUrl={LINKEDIN_URL} githubRepo={GITHUB_REPO} discordUrl={DISCORD_URL} />
        </>
      ) : null}
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <RoutedSite />
    </BrowserRouter>
  );
}
