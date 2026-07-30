import { useEffect, useState } from 'react';
import { projectMetricsSource, siteLinks } from '../../siteConfig';
import { SafeLink } from '../SafeLink';

type HeroProofStats = {
  pulls: number | null;
};

const CACHE_KEY = 'identrail_hero_proof_stats_v3';
const CACHE_TTL_MS = 30 * 60 * 1000;
const EMPTY_STATS: HeroProofStats = { pulls: null };

function formatMetric(value: number | null): string {
  if (value === null) return 'Live';
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace('.0', '')}M+`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1).replace('.0', '')}k+`;
  return `${value}`;
}

function parseCompactMetric(metric: string): number | null {
  const normalized = metric.trim().toUpperCase();
  if (!normalized || normalized.includes('NOT FOUND') || normalized.includes('BADGE NOT FOUND')) return null;

  const suffix = normalized.charAt(normalized.length - 1);
  const scale = suffix === 'K' ? 1_000 : suffix === 'M' ? 1_000_000 : suffix === 'B' ? 1_000_000_000 : 1;
  const parsed = Number.parseFloat(scale === 1 ? normalized : normalized.slice(0, -1));
  return Number.isFinite(parsed) ? Math.round(parsed * scale) : null;
}

function readCachedStats(): HeroProofStats | null {
  try {
    const raw = window.localStorage.getItem(CACHE_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw) as { at?: number; stats?: HeroProofStats };
    if (!parsed.at || !parsed.stats || Date.now() - parsed.at > CACHE_TTL_MS) return null;
    return parsed.stats;
  } catch {
    return null;
  }
}

function cacheStats(stats: HeroProofStats) {
  try {
    window.localStorage.setItem(CACHE_KEY, JSON.stringify({ at: Date.now(), stats }));
  } catch {
    // Local storage can be disabled; live metrics remain non-blocking.
  }
}

async function fetchDockerPulls(repoPath: string, signal: AbortSignal): Promise<number | null> {
  try {
    const response = await fetch(`https://img.shields.io/docker/pulls/${repoPath}.json`, { signal });
    if (!response.ok) return null;

    const body = (await response.json()) as { message?: string; value?: string };
    return parseCompactMetric(body.message ?? body.value ?? '');
  } catch (error) {
    if (signal.aborted) throw error;
    return null;
  }
}

async function fetchHeroProofStats(signal: AbortSignal): Promise<HeroProofStats> {
  const pullResults = await Promise.all(
    projectMetricsSource.dockerHubRepos.map((repoPath) => fetchDockerPulls(repoPath, signal))
  );
  const availablePulls = pullResults.filter((current): current is number => current !== null);
  const pulls = availablePulls.length > 0 ? availablePulls.reduce((total, current) => total + current, 0) : null;
  return { pulls };
}

export function HeroOpenSourceProofPills() {
  const [stats, setStats] = useState<HeroProofStats>(EMPTY_STATS);

  useEffect(() => {
    if (typeof fetch !== 'function') return;

    const cached = readCachedStats();
    if (cached) setStats(cached);

    const controller = new AbortController();
    void fetchHeroProofStats(controller.signal)
      .then((liveStats) => {
        setStats((current) => {
          const next = { pulls: liveStats.pulls ?? current.pulls };
          cacheStats(next);
          return next;
        });
      })
      .catch(() => undefined);

    return () => controller.abort();
  }, []);

  return (
    <div className="idt-hero-proof-pills" aria-label="Open source project activity">
      <SafeLink className="idt-hero-proof-pill" href={siteLinks.quickstartDocker}>
        <img src="/brand-logos/docker.svg" alt="" aria-hidden="true" loading="lazy" />
        <span>
          <strong>{formatMetric(stats.pulls)}</strong>
          <small>Docker pulls</small>
        </span>
      </SafeLink>
      <SafeLink
        className="idt-hero-proof-github"
        href={siteLinks.github}
        aria-label="View Identrail on GitHub"
        title="View Identrail on GitHub"
      >
        <img src="/brand-logos/github.svg" alt="" aria-hidden="true" loading="lazy" />
      </SafeLink>
    </div>
  );
}
