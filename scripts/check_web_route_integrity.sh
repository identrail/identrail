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
  const routeRegex = /<Route\s+path="([^"]+)"/g;
  let m;
  while ((m = routeRegex.exec(src)) !== null) {
    const route = m[1];
    if (route.includes('*') || route.includes(':')) {
      continue;
    }
    routes.add(route);
  }
  return routes;
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
