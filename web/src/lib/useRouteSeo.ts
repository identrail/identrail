import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { SITE_URL } from '../siteConfig';
import { DEFAULT_KEYWORDS, metaForPath } from './seoMap';

declare global {
  interface Window {
    gtag?: (...args: unknown[]) => void;
    posthog?: {
      capture: (event: string, properties?: Record<string, unknown>) => void;
    };
  }
}

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

/**
 * Apply route-specific document title and meta tags on SPA navigation.
 * The first paint is already handled by the build-time prerenderer
 * (web/scripts/prerender-routes.ts) — this hook only fires on subsequent
 * client-side route changes.
 *
 * Dashboard routes (/app/*) are intentionally skipped: they have their own
 * title management inside productShell, and we don't want a stale marketing
 * title bleeding into authenticated views.
 */
export function useRouteSeo() {
  const location = useLocation();

  useEffect(() => {
    const isDashboard = location.pathname === '/app' || location.pathname.startsWith('/app/');

    // Pick a stable title for analytics:
    //  - marketing routes: lookup from the SEO map (and also sync the DOM
    //    <title>/meta tags below)
    //  - dashboard routes: a fixed string. We can't use document.title here
    //    because it might still hold the previous marketing page's title
    //    (we deliberately don't update <title> for /app/* — productShell
    //    can manage its own).
    let analyticsTitle: string;

    if (isDashboard) {
      analyticsTitle = 'Identrail App';
    } else {
      const meta = metaForPath(location.pathname);
      document.title = meta.title;
      upsertMetaByName('description', meta.description);
      upsertMetaByName('keywords', meta.keywords ?? DEFAULT_KEYWORDS);
      upsertMetaByProperty('og:title', meta.title);
      upsertMetaByProperty('og:description', meta.description);
      upsertMetaByProperty('og:url', `${SITE_URL}${location.pathname}`);
      upsertCanonical(location.pathname);
      analyticsTitle = meta.title;
    }

    // Analytics fires for every navigation, dashboard included.
    const url = `${location.pathname}${location.search}${location.hash}`;
    if (typeof window.gtag === 'function') {
      window.gtag('event', 'page_view', { page_path: url, page_title: analyticsTitle });
    }
    if (window.posthog && typeof window.posthog.capture === 'function') {
      window.posthog.capture('$pageview', {
        path: location.pathname,
        search: location.search,
        hash: location.hash,
        title: analyticsTitle
      });
    }
  }, [location.pathname, location.search, location.hash]);
}
