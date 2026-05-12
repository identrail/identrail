#!/usr/bin/env bash
set -euo pipefail

node <<'NODE'
const fs = require('fs');
const path = require('path');

const repoRoot = process.cwd();

function read(rel) {
  return fs.readFileSync(path.join(repoRoot, rel), 'utf8');
}

function parseAppRoutes(src) {
  const routes = new Set();
  const runtimeOnlyRoutes = new Set(['/auth/callback']);

  // Identify routes that exist purely to 301-redirect a legacy URL
  // (`element={<Navigate ... />}`). These should NOT appear in
  // PRERENDER_ROUTES — they are handled by static 301 rules in
  // web/vercel.json so we don't ship empty redirect HTML to indexers.
  const redirectPaths = new Set();
  const redirectRegex = /<Route\s+path="([^"]+)"\s+element=\{<Navigate\b/g;
  let r;
  while ((r = redirectRegex.exec(src)) !== null) {
    redirectPaths.add(r[1]);
  }

  const routeRegex = /<Route\s+path="([^"]+)"/g;
  let m;
  while ((m = routeRegex.exec(src)) !== null) {
    const route = m[1];
    if (route.includes('*') || route.includes(':')) {
      continue;
    }
    if (!route.startsWith('/')) {
      continue;
    }
    if (route === '/app' || route.startsWith('/app/')) {
      continue;
    }
    if (runtimeOnlyRoutes.has(route)) {
      continue;
    }
    if (redirectPaths.has(route)) {
      continue;
    }
    routes.add(route);
  }
  // Include static routes generated from mapped slug collections, e.g.
  // path={`/features/${page.slug}`} inside FEATURE_DEEP_PAGES.map(...)
  const mappedRouteRegex = /\{([A-Z0-9_]+)\.map\(\(page\)\s*=>\s*\([\s\S]*?<Route[^>]*\s+path=\{`([^`]*)\$\{page\.slug\}([^`]*)`\}/g;
  while ((m = mappedRouteRegex.exec(src)) !== null) {
    const collectionName = m[1];
    const prefix = m[2];
    const suffix = m[3];
    for (const slug of parseSlugCollection(src, collectionName)) {
      const route = `${prefix}${slug}${suffix}`;
      if (route.includes('*') || route.includes(':')) {
        continue;
      }
      routes.add(route);
    }
  }

  return routes;
}

function parseSlugCollection(src, collectionName) {
  const collectionRegex = /const\s+([A-Z0-9_]+)\s*=\s*\[([\s\S]*?)\]\s*as const;/g;
  const slugRegex = /slug:\s*'([^']+)'/g;
  let m;
  while ((m = collectionRegex.exec(src)) !== null) {
    if (m[1] !== collectionName) {
      continue;
    }
    const block = m[2];
    const slugs = [];
    let slugMatch;
    while ((slugMatch = slugRegex.exec(block)) !== null) {
      slugs.push(slugMatch[1]);
    }
    return slugs;
  }
  return [];
}

function parsePrerenderRoutes(src) {
  const blockMatch = src.match(/export const PRERENDER_ROUTES\s*=\s*\[([\s\S]*?)\]\s*as const;/);
  if (!blockMatch) throw new Error('Unable to parse PRERENDER_ROUTES block');
  const block = blockMatch[1];
  const routes = new Set();
  const routeRegex = /'([^']+)'/g;
  let m;
  while ((m = routeRegex.exec(block)) !== null) {
    routes.add(m[1]);
  }
  return routes;
}

function parseRouteMetaKeys(src) {
  const blockMatch = src.match(/const ROUTE_META:\s*Record<string, RouteMeta>\s*=\s*\{([\s\S]*?)\n\};/);
  if (!blockMatch) throw new Error('Unable to parse ROUTE_META block');
  const block = blockMatch[1];
  const routes = new Set();
  const routeRegex = /'([^']+)'\s*:\s*\{/g;
  let m;
  while ((m = routeRegex.exec(block)) !== null) {
    routes.add(m[1]);
  }
  return routes;
}

function parseSitemapRoutes(src) {
  const routes = new Set();
  const locRegex = /<loc>https:\/\/www\.identrail\.com([^<]*)<\/loc>/g;
  let m;
  while ((m = locRegex.exec(src)) !== null) {
    const suffix = m[1] || '/';
    routes.add(suffix === '' ? '/' : suffix);
  }
  return routes;
}

function diff(a, b) {
  return [...a].filter((x) => !b.has(x));
}

const appRoutes = parseAppRoutes(read('web/src/App.tsx'));
const prerenderRoutes = parsePrerenderRoutes(read('web/prerender-routes.ts'));
const sitemapRoutes = parseSitemapRoutes(read('web/public/sitemap.xml'));

const missingInPrerender = diff(appRoutes, prerenderRoutes);
const missingInSitemap = diff(prerenderRoutes, sitemapRoutes);

let hasError = false;

if (missingInPrerender.length) {
  hasError = true;
  console.error('Routes present in App.tsx but missing from PRERENDER_ROUTES:');
  for (const route of missingInPrerender.sort()) console.error(`  - ${route}`);
}
if (missingInSitemap.length) {
  hasError = true;
  console.error('Routes present in PRERENDER_ROUTES but missing from sitemap.xml:');
  for (const route of missingInSitemap.sort()) console.error(`  - ${route}`);
}

if (hasError) {
  process.exit(1);
}

console.log('OK: web route integrity checks passed');
NODE
