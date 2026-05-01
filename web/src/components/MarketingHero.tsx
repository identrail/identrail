import { useEffect, useState } from 'react';
import { projectMetricsSource, siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';
import { TrustGraphIllustration } from './TrustGraphIllustration';

type StatKey = 'stars' | 'pulls' | 'contributors';

type HeroStats = Record<StatKey, number>;

const CACHE_KEY = 'identrail_hero_live_stats_v1';
const CACHE_TTL_MS = 30 * 60 * 1000;
const EMPTY_STATS: HeroStats = { stars: 0, pulls: 0, contributors: 0 };

function formatMetric(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1).replace('.0', '')}B+`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace('.0', '')}M+`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1).replace('.0', '')}k+`;
  return `${value}`;
}

function parseCompactMetric(metric: string): number | null {
  const normalized = metric.trim().toUpperCase();
  if (!normalized || normalized.includes('NOT FOUND') || normalized.includes('BADGE NOT FOUND')) {
    return null;
  }
  const suffix = normalized.charAt(normalized.length - 1);
  const scale = suffix === 'K' ? 1_000 : suffix === 'M' ? 1_000_000 : suffix === 'B' ? 1_000_000_000 : 1;
  const numberPart = scale === 1 ? normalized : normalized.slice(0, -1);
  const parsed = Number.parseFloat(numberPart);
  if (!Number.isFinite(parsed)) return null;
  return Math.round(parsed * scale);
}

function getCachedStats(): HeroStats | null {
  try {
    const raw = window.localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { at?: number; stats?: HeroStats };
    if (!parsed.at || !parsed.stats) return null;
    if (Date.now() - parsed.at > CACHE_TTL_MS) return null;
    return parsed.stats;
  } catch {
    return null;
  }
}

function cacheStats(stats: HeroStats) {
  try {
    window.localStorage.setItem(CACHE_KEY, JSON.stringify({ at: Date.now(), stats }));
  } catch {
    // no-op
  }
}

async function fetchContributorCount(owner: string, repo: string): Promise<number> {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contributors?per_page=1&anon=1`,
    { headers: { Accept: 'application/vnd.github+json' } }
  );
  if (!response.ok) return 0;
  const link = response.headers.get('link');
  const lastPageMatch = link?.match(/[?&]page=(\d+)>;\s*rel="last"/i);
  if (lastPageMatch) return Number.parseInt(lastPageMatch[1], 10);
  const body = (await response.json()) as Array<unknown>;
  return Array.isArray(body) ? body.length : 0;
}

async function fetchDockerPulls(repoPath: string): Promise<number | null> {
  const response = await fetch(`https://img.shields.io/docker/pulls/${repoPath}.json`);
  if (!response.ok) return null;
  const body = (await response.json()) as { message?: string; value?: string };
  return parseCompactMetric(body.message ?? body.value ?? '');
}

async function fetchLiveStats(): Promise<HeroStats> {
  const { owner, name } = projectMetricsSource.github;
  const repoResponse = await fetch(`https://api.github.com/repos/${owner}/${name}`, {
    headers: { Accept: 'application/vnd.github+json' }
  });
  const repoJson = repoResponse.ok
    ? ((await repoResponse.json()) as { stargazers_count?: number })
    : {};
  const stars = Number.isFinite(repoJson.stargazers_count) ? repoJson.stargazers_count ?? 0 : 0;

  const [contributors, dockerPullResults] = await Promise.all([
    fetchContributorCount(owner, name),
    Promise.all(projectMetricsSource.dockerHubRepos.map((repoPath) => fetchDockerPulls(repoPath)))
  ]);

  const pulls = dockerPullResults.reduce<number>((total, current) => total + (current ?? 0), 0);
  return { stars, pulls, contributors };
}

export function MarketingHero() {
  const [stats, setStats] = useState<HeroStats>(EMPTY_STATS);

  useEffect(() => {
    let cancelled = false;
    const cached = getCachedStats();
    if (cached) setStats(cached);

    void fetchLiveStats()
      .then((liveStats) => {
        if (cancelled) return;
        setStats(liveStats);
        cacheStats(liveStats);
      })
      .catch(() => {
        // no-op: keep cached/default values
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const statItems = [
    { value: formatMetric(stats.stars), label: 'GitHub Stars' },
    { value: formatMetric(stats.pulls), label: 'Docker Pulls' },
    { value: formatMetric(stats.contributors), label: 'Contributors' }
  ] as const;

  return (
    <section className="mk-hero" aria-labelledby="mk-hero-title">
      <div className="mk-shell mk-hero-grid">
        <div className="mk-hero-copy">
          <p className="mk-eyebrow">Open Source • Enterprise Ready</p>
          <h1 id="mk-hero-title">Machine Identity Reimagined</h1>
          <p className="mk-hero-subhead">
            Discover, visualize, and secure every machine identity and trust path across AWS and
            Kubernetes without slowing engineering teams down.
          </p>

          <div className="mk-hero-cta mk-hero-cta-single">
            <SafeLink className="mk-btn mk-btn-primary" href={siteLinks.getStarted}>
              Open App
            </SafeLink>
          </div>

          <dl className="mk-stat-grid mk-stat-grid-refined" aria-label="Open source momentum">
            {statItems.map((item) => (
              <div key={item.label} className="mk-stat-item">
                <dt>{item.label}</dt>
                <dd>{item.value}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="mk-hero-visual" aria-hidden="true">
          <TrustGraphIllustration
            className="trust-graph-hero"
            label="Abstract machine identity trust graph"
          />
        </div>
      </div>
    </section>
  );
}
