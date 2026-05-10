import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { prerender } from '../src/prerender';
import { PRERENDER_ROUTES } from '../prerender-routes';
import { DEFAULT_KEYWORDS, ROUTE_META, metaForPath } from '../src/lib/seoMap';
import {
  DISCORD_URL,
  GITHUB_REPO,
  LINKEDIN_URL,
  SITE_NAME,
  SITE_URL
} from '../src/siteConfig';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '..');
const distDir = path.join(webRoot, 'dist');
const templatePath = path.join(distDir, 'index.html');
const rootMarker = '<div id="root"></div>';

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
  const meta = metaForPath(route);
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

  // JSON-LD: Organization for the home page (in addition to the per-route
  // WebPage / Article schema below). The Organization snippet helps Google
  // attach knowledge-graph data and the open-source repo as sameAs.
  if (route === '/') {
    const orgSchema = {
      '@context': 'https://schema.org',
      '@type': 'Organization',
      name: SITE_NAME,
      url: SITE_URL,
      logo: `${SITE_URL}/identrail-logo.png`,
      sameAs: [GITHUB_REPO, DISCORD_URL, LINKEDIN_URL]
    };
    const orgJson = JSON.stringify(orgSchema).replaceAll('</script', '<\\/script');
    html = replaceOrAppend(
      html,
      /<script\s+id="identrail-org-schema"\s+type="application\/ld\+json">[\s\S]*?<\/script>/i,
      `<script id="identrail-org-schema" type="application/ld+json">${orgJson}</script>`
    );
  }

  const schema = {
    '@context': 'https://schema.org',
    '@type': meta.schemaType ?? 'WebPage',
    name: meta.title,
    description: meta.description,
    url: canonicalUrl,
    isPartOf: {
      '@type': 'WebSite',
      name: SITE_NAME,
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

  const knownRouteCount = Object.keys(ROUTE_META).length;
  const renderedCount = PRERENDER_ROUTES.length;

  for (const route of PRERENDER_ROUTES) {
    const rendered = await prerender({ url: route });
    const baseHtml = template.replace(rootMarker, `<div id="root">${rendered.html}</div>`);
    const html = withRouteHead(baseHtml, route);
    const outputDir = outputDirForRoute(route);

    await mkdir(outputDir, { recursive: true });
    await writeFile(path.join(outputDir, 'index.html'), html, 'utf8');
  }

  console.log(`Prerendered ${renderedCount} routes (${knownRouteCount} have meta entries).`);
}

await main();
