import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { prerender } from '../src/prerender';
import { PRERENDER_ROUTES } from '../prerender-routes';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '..');
const distDir = path.join(webRoot, 'dist');
const templatePath = path.join(distDir, 'index.html');
const rootMarker = '<div id="root"></div>';
const SITE_URL = 'https://www.identrail.com';
const DEFAULT_KEYWORDS =
  'machine identity security, AWS IAM trust path analysis, Kubernetes service account risk, OIDC security, cloud identity blast radius reduction';

type RouteMeta = {
  title: string;
  description: string;
  keywords?: string;
  schemaType?: 'WebPage' | 'Product' | 'Article' | 'AboutPage';
};

const ROUTE_META: Record<string, RouteMeta> = {
  '/': {
    title: 'Machine Identity Security | AWS IAM Trust Path Analysis | Identrail',
    description:
      'Identify risky AWS IAM, Kubernetes, and GitHub trust paths before attackers use them with machine identity security built for security and platform teams.',
    keywords: DEFAULT_KEYWORDS
  },
  '/product': {
    title: 'Product | Identrail Machine Identity Security Platform',
    description:
      'Discover machine identities, map trust paths, prioritize risky access, and roll out safer authorization controls with Identrail.',
    schemaType: 'Product'
  },
  '/features': {
    title: 'Features | AWS IAM, Kubernetes RBAC, Git Scanner, Trust Graph',
    description:
      'Explore Identrail features for AWS IAM trust path analysis, Kubernetes service account risk detection, Git scanner workflows, and trust graph visibility.'
  },
  '/features/aws': {
    title: 'AWS IAM Security Feature | Identrail',
    description:
      'Map IAM role chains, cross-account trust paths, and high-risk access patterns with explainable machine identity evidence.'
  },
  '/features/kubernetes': {
    title: 'Kubernetes Machine Identity Feature | Identrail',
    description:
      'Correlate service accounts, RBAC privileges, and cloud federation paths to reduce Kubernetes machine identity risk safely.'
  },
  '/features/git-scanner': {
    title: 'Git Scanner Feature | Identrail',
    description:
      'Scan repositories for credential leaks and risky machine identity patterns, then connect findings to trust-path impact.'
  },
  '/features/trust-graph': {
    title: 'Interactive Trust Graph Feature | Identrail',
    description:
      'Visualize trust paths from source identity to sensitive resources and prioritize blast-radius reduction with explainable graph evidence.'
  },
  '/solutions': {
    title: 'Solutions | AWS, Kubernetes, Multi-cloud, Security and Platform Teams',
    description:
      'Solution patterns for cloud security, platform engineering, and identity teams managing machine trust paths across AWS and Kubernetes.'
  },
  '/solutions/aws': {
    title: 'AWS Security Teams Solution | Identrail',
    description:
      'Reduce AWS IAM blast radius with trust-path evidence, policy simulation, and rollout-safe least-privilege workflows.'
  },
  '/solutions/kubernetes': {
    title: 'Kubernetes Platform Teams Solution | Identrail',
    description:
      'Control Kubernetes service account and RBAC risk with end-to-end trust-path visibility and safer rollout workflows.'
  },
  '/solutions/multi-cloud': {
    title: 'Multi-cloud Machine Identity Solution | Identrail',
    description:
      'Unify fragmented machine identity posture across cloud environments with consistent trust-path analysis and remediation workflows.'
  },
  '/solutions/platform-engineering': {
    title: 'Platform Engineering Solution | Identrail',
    description:
      'Ship safer authorization changes with policy simulation, staged rollout controls, and rollback guardrails.'
  },
  '/solutions/security-teams': {
    title: 'Security Teams Solution | Identrail',
    description:
      'Prioritize machine identity findings by exploitability and impact to reduce queue noise and remediation time.'
  },
  '/pricing': {
    title: 'Pricing | Identrail Open Source, Hosted SaaS, and Enterprise',
    description:
      'Compare Open Source, Hosted SaaS, and Enterprise machine identity security plans based on team size, deployment needs, and controls.'
  },
  '/roi-assessment': {
    title: 'ROI Assessment | Quantify Machine Identity Risk Reduction',
    description:
      'Estimate expected risk reduction and operational impact from machine identity hardening with an ROI-first assessment workflow.'
  },
  '/read-only-scan': {
    title: 'Read-Only Risk Scan | Safe Machine Identity Discovery',
    description:
      'Run a read-only machine identity risk scan across AWS and Kubernetes trust paths without making policy changes in your environment.'
  },
  '/deployment-models': {
    title: 'Deployment Models | Self-Hosted, SaaS, and Enterprise Options',
    description:
      'Compare Identrail deployment models across self-hosted, hosted SaaS, and enterprise rollout patterns with security and control tradeoffs.'
  },
  '/demo': {
    title: 'Demo | Interactive Trust Graph and Risk Workflows',
    description:
      'Explore an interactive trust graph demo showing machine identity attack-path evidence, risk scoring, and recommended controls.'
  },
  '/integrations': {
    title: 'Integrations | AWS, Kubernetes, GitHub, OIDC, and Observability',
    description:
      'Review current integrations and telemetry sources used to build machine identity trust paths and prioritized risk evidence.'
  },
  '/docs': {
    title: 'Docs | Identrail Documentation Hub',
    description:
      'Read deployment, integration, and operational documentation for Identrail machine identity security workflows.'
  },
  '/faq': {
    title: 'FAQ | Machine Identity Security and Product Operations',
    description:
      'Answers to common questions on read-only scanning, trust-path analysis, deployment models, and rollout-safe remediation.'
  },
  '/blog': {
    title: 'Blog | Machine Identity Security Guides and Insights',
    description:
      'Learn practical machine identity security tactics for AWS IAM, Kubernetes service accounts, OIDC trust paths, and blast-radius reduction.'
  },
  '/blog/machine-identity-security-operating-model-2026': {
    title: 'Machine Identity Security in 2026: A Practical Operating Model | Identrail',
    description:
      'A practical operating model for discovering, prioritizing, and controlling machine trust paths in production.'
  },
  '/blog/aws-nhi-security-misconfigurations': {
    title: 'AWS NHI Security: 14 Misconfigurations That Expand Blast Radius | Identrail',
    description:
      'A field guide to high-impact IAM role-chain misconfigurations and practical remediation sequencing.'
  },
  '/blog/kubernetes-machine-identity-rbac-risk-paths': {
    title: 'Kubernetes Machine Identity: RBAC Risk Paths You Can Actually Fix | Identrail',
    description:
      'How to map Kubernetes service-account escalation paths and tighten RBAC safely in production.'
  },
  '/blog/repo-exposure-program-machine-identities': {
    title: 'From Secrets Sprawl to Signal: Building a Repo Exposure Program | Identrail',
    description:
      'Build a repo exposure program that prioritizes real credential risk and speeds containment.'
  },
  '/blog/open-core-vs-closed-machine-identity-security': {
    title: 'Open-Core vs Closed Platforms in Machine Identity Security | Identrail',
    description:
      'A practical buyer guide for evaluating architecture control, portability, and TCO tradeoffs.'
  },
  '/blog/least-privilege-evidence-for-non-human-identities': {
    title: 'How to Prove Least Privilege for Non-Human Identities to Auditors | Identrail',
    description:
      'Generate audit-ready least-privilege evidence for SOC 2 and ISO 27001 using trust-path data.'
  },
  '/blog/rollout-safe-authorization-controls': {
    title: 'Designing Rollout-Safe Authorization Controls for Platform Teams | Identrail',
    description:
      'Use simulation, canary gates, and rollback controls to harden authorization without outages.'
  },
  '/blog/trust-graph-metrics-for-security-leaders': {
    title: 'Trust Graphs for Security Leaders: What to Measure and Why | Identrail',
    description:
      'Metrics that connect machine identity posture improvements to incident reduction and business risk.'
  },
  '/security': {
    title: 'Security and Compliance | Identrail',
    description:
      'Review Identrail security controls, compliance roadmap, disclosure process, and deployment safeguards.'
  },
  '/responsible-disclosure': {
    title: 'Responsible Disclosure | Report Security Issues to Identrail',
    description:
      'Report security vulnerabilities privately and review disclosure expectations, triage timelines, and coordination policy.'
  },
  '/about': {
    title: 'About | Identrail',
    description:
      'Meet Identrail, the open-core machine identity security platform built for cloud security and platform teams.',
    schemaType: 'AboutPage'
  },
  '/enterprise': {
    title: 'Enterprise | Private Deployment and Advanced Controls',
    description:
      'Plan enterprise machine identity security rollout with private deployment options, advanced controls, and support.'
  },
  '/privacy': {
    title: 'Privacy Policy | Identrail',
    description:
      'Read how Identrail accesses, uses, stores, protects, shares, retains, and deletes Google sign-in data and other account information.'
  },
  '/terms': {
    title: 'Terms of Use | Identrail',
    description:
      'Review the terms governing Identrail websites, hosted product experiences, documentation, accounts, integrations, and acceptable use.'
  },
  '/privacy-choices': {
    title: 'Privacy Choices | Identrail',
    description: 'Manage your privacy choices and communication preferences for Identrail.'
  }
};

function getRouteMeta(route: string): RouteMeta {
  const fallback = ROUTE_META['/'];
  return ROUTE_META[route] ?? {
    title: fallback.title,
    description: fallback.description,
    keywords: fallback.keywords
  };
}

function escapeAttribute(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function replaceOrAppend(headHtml: string, pattern: RegExp, replacement: string): string {
  if (pattern.test(headHtml)) {
    return headHtml.replace(pattern, replacement);
  }

  return headHtml.replace('</head>', `    ${replacement}\n  </head>`);
}

function withRouteHead(template: string, route: string): string {
  const meta = getRouteMeta(route);
  const canonicalPath = route === '/' ? '/' : route;
  const canonicalUrl = `${SITE_URL}${canonicalPath}`;
  const title = escapeAttribute(meta.title);
  const description = escapeAttribute(meta.description);
  const keywords = escapeAttribute(meta.keywords ?? DEFAULT_KEYWORDS);

  let html = template;
  html = replaceOrAppend(html, /<title>[\s\S]*?<\/title>/i, `<title>${title}</title>`);
  html = replaceOrAppend(
    html,
    /<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i,
    `<meta name="description" content="${description}" />`
  );
  html = replaceOrAppend(
    html,
    /<meta\s+name="keywords"\s+content="[^"]*"\s*\/?>/i,
    `<meta name="keywords" content="${keywords}" />`
  );
  html = replaceOrAppend(
    html,
    /<link\s+rel="canonical"\s+href="[^"]*"\s*\/?>/i,
    `<link rel="canonical" href="${canonicalUrl}" />`
  );
  html = replaceOrAppend(
    html,
    /<meta\s+property="og:title"\s+content="[^"]*"\s*\/?>/i,
    `<meta property="og:title" content="${title}" />`
  );
  html = replaceOrAppend(
    html,
    /<meta\s+property="og:description"\s+content="[^"]*"\s*\/?>/i,
    `<meta property="og:description" content="${description}" />`
  );
  html = replaceOrAppend(
    html,
    /<meta\s+property="og:type"\s+content="[^"]*"\s*\/?>/i,
    '<meta property="og:type" content="website" />'
  );
  html = replaceOrAppend(
    html,
    /<meta\s+property="og:url"\s+content="[^"]*"\s*\/?>/i,
    `<meta property="og:url" content="${canonicalUrl}" />`
  );
  html = replaceOrAppend(
    html,
    /<meta\s+property="og:image"\s+content="[^"]*"\s*\/?>/i,
    `<meta property="og:image" content="${SITE_URL}/identrail-logo.png" />`
  );
  html = replaceOrAppend(
    html,
    /<meta\s+name="twitter:card"\s+content="[^"]*"\s*\/?>/i,
    '<meta name="twitter:card" content="summary_large_image" />'
  );
  html = replaceOrAppend(
    html,
    /<meta\s+name="twitter:title"\s+content="[^"]*"\s*\/?>/i,
    `<meta name="twitter:title" content="${title}" />`
  );
  html = replaceOrAppend(
    html,
    /<meta\s+name="twitter:description"\s+content="[^"]*"\s*\/?>/i,
    `<meta name="twitter:description" content="${description}" />`
  );

  const schema = {
    '@context': 'https://schema.org',
    '@type': meta.schemaType ?? 'WebPage',
    name: meta.title,
    description: meta.description,
    url: canonicalUrl,
    isPartOf: {
      '@type': 'WebSite',
      name: 'Identrail',
      url: SITE_URL
    }
  };

  const schemaJson = JSON.stringify(schema).replaceAll('</script', '<\\/script');
  html = replaceOrAppend(
    html,
    /<script\s+id="identrail-schema"\s+type="application\/ld\+json">[\s\S]*?<\/script>/i,
    `<script id="identrail-schema" type="application/ld+json">${schemaJson}</script>`
  );

  return html;
}

function outputDirForRoute(route: string): string {
  if (route === '/') {
    return distDir;
  }

  return path.join(distDir, route.replace(/^\//, ''));
}

async function main() {
  const template = await readFile(templatePath, 'utf8');

  if (!template.includes(rootMarker)) {
    throw new Error(`Could not find ${rootMarker} in ${templatePath}`);
  }

  for (const route of PRERENDER_ROUTES) {
    const rendered = await prerender({ url: route });
    const baseHtml = template.replace(rootMarker, `<div id="root">${rendered.html}</div>`);
    const html = withRouteHead(baseHtml, route);
    const outputDir = outputDirForRoute(route);

    await mkdir(outputDir, { recursive: true });
    await writeFile(path.join(outputDir, 'index.html'), html, 'utf8');
  }

  console.log(`Prerendered ${PRERENDER_ROUTES.length} routes.`);
}

await main();
