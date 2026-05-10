/**
 * Route → meta map.
 *
 * Used by:
 * - web/scripts/prerender-routes.ts (build-time, source of truth for static HTML)
 * - web/src/lib/useRouteSeo.ts      (runtime, updates title/meta on SPA navigation)
 *
 * Keep entries in sync with web/prerender-routes.ts. Untracked routes fall
 * back to the entry for "/".
 */

import { BLOG_POSTS } from '../content/resources';

export type RouteMeta = {
  title: string;
  description: string;
  keywords?: string;
  schemaType?: 'WebPage' | 'Product' | 'Article' | 'AboutPage';
};

export const DEFAULT_KEYWORDS =
  'machine identity security, non-human identity, NHI security, AWS IAM, Kubernetes RBAC, OIDC, trust graph, least privilege';

export const ROUTE_META: Record<string, RouteMeta> = {
  '/': {
    title: 'Identrail - Trace every machine identity. Close the dangerous paths safely.',
    description:
      'Identrail traces how AWS roles, Kubernetes service accounts, GitHub OIDC and trust policies can reach your data - and shows the smallest, safest fix. Open core under Apache 2.0.',
    keywords: DEFAULT_KEYWORDS
  },
  '/product': {
    title: 'Product - One platform for machine identity discovery, detection, and rollout-safe control | Identrail',
    description:
      'Discover every machine identity, detect the paths that matter, and remediate without breaking production. Trust graph, simulator, operator surface - explained.',
    schemaType: 'Product'
  },
  '/integrations': {
    title: 'Integrations - AWS, Kubernetes, GitHub, OIDC, Terraform | Identrail',
    description:
      'Every system Identrail watches today, with status (GA, Beta, Roadmap) and a one-line summary of what each connector resolves into the trust graph.'
  },
  '/for/security-teams': {
    title: 'For Security Teams - Triage by what an identity can actually reach | Identrail',
    description:
      'A trust-graph-grounded queue, evidence-shipped findings, and exportable proof of least privilege. Built for the people who own the security backlog.'
  },
  '/for/platform-engineering': {
    title: 'For Platform Engineering - Tighten machine identity without breaking production | Identrail',
    description:
      'Policy simulation against the last 30 days of activity, named blast radius, three rollout gates and one-click rollback. Built to be operated by the team that owns the resource.'
  },
  '/pricing': {
    title: 'Pricing - Open source, Team, Enterprise | Identrail',
    description:
      'Free if you self-host. $19/user/mo for hosted Team. Custom for Enterprise. Honest pricing for an open-core security tool.'
  },
  '/demo': {
    title: 'Demo - See your first trust path in under ten minutes | Identrail',
    description:
      'Two ways in: free read-only risk scan or a 15-minute walkthrough with the founder. No card, no agent, no write access.'
  },
  '/docs': {
    title: 'Docs - Identrail documentation hub',
    description:
      'Quickstart, deployment, integrations, and operational documentation for the Identrail open-core machine identity platform.'
  },
  '/blog': {
    title: 'Blog - Field notes on machine identity | Identrail',
    description:
      'Practical guides and operating-model essays for security and platform engineers responsible for non-human identities.'
  },
  '/security': {
    title: 'Security & compliance | Identrail',
    description:
      'A complete read on how Identrail handles your data, what we have certified, what we are working on, and what we have not done yet.'
  },
  '/responsible-disclosure': {
    title: 'Responsible disclosure | Identrail',
    description:
      'Find a security issue? Tell us privately at security@identrail.com. We acknowledge in 72 hours, fix on a defined window, and publicly credit reporters.'
  },
  '/about': {
    title: 'About - Identrail',
    description:
      'Why Identrail exists, what we build under, and an honest read on where we are today. Founder note from Oluwatobi Mustapha.',
    schemaType: 'AboutPage'
  },
  '/enterprise': {
    title: 'Enterprise - Private deployment, procurement, named support | Identrail',
    description:
      'Identrail for organisations with procurement, audit, and air-gap requirements. Three deployment models, full security review, named TAM.'
  },
  '/faq': {
    title: 'FAQ - Identrail',
    description:
      'Straight answers on the product, security posture, compliance, and pricing. No marketing hedge.'
  },
  '/privacy': {
    title: 'Privacy policy | Identrail',
    description:
      'How Identrail collects and processes personal data when you visit our website or use our hosted product.'
  },
  '/terms': {
    title: 'Terms of service | Identrail',
    description: 'The terms governing use of identrail.com and the hosted Identrail service.'
  },
  '/privacy-choices': {
    title: 'Privacy choices | Identrail',
    description: 'Adjust how Identrail processes your personal data, including analytics and marketing email.'
  }
};

/**
 * Per-article blog metadata, generated from BLOG_POSTS so each post gets a
 * distinct title and description in <head>, OG tags and JSON-LD. Without
 * this, every prerendered /blog/<slug>/index.html shipped the same generic
 * fallback.
 */
const BLOG_ROUTE_META: Record<string, RouteMeta> = Object.fromEntries(
  BLOG_POSTS.map((post) => [
    `/blog/${post.slug}`,
    {
      title: `${post.title} | Identrail`,
      description: post.description,
      schemaType: 'Article' as const
    }
  ])
);

/**
 * Strip a trailing slash so callers can pass either `/product` or
 * `/product/` and hit the same metadata entry. Without this, the
 * trailing-slash variant fell through to the homepage default and
 * overwrote the prerendered <title>/description on hydration.
 */
function normalizePath(path: string): string {
  if (path.length > 1 && path.endsWith('/')) {
    return path.replace(/\/+$/, '') || '/';
  }
  return path;
}

export function metaForPath(path: string): RouteMeta {
  const normalized = normalizePath(path);

  if (ROUTE_META[normalized]) return ROUTE_META[normalized];
  if (BLOG_ROUTE_META[normalized]) return BLOG_ROUTE_META[normalized];

  // Unknown blog post (e.g., a slug that doesn't match a published article):
  // ship a sensible Article-typed fallback rather than a homepage tag.
  if (normalized.startsWith('/blog/')) {
    return {
      title: 'Blog post | Identrail',
      description: 'Field notes on machine identity from the Identrail team.',
      schemaType: 'Article'
    };
  }

  return ROUTE_META['/'];
}
