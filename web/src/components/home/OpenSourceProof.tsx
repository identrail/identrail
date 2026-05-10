import { useEffect, useState } from 'react';
import { ArrowLink } from '../ui/Button';
import { GitHubIcon, StarIcon } from '../ui/Icon';
import { CONTRIBUTING_URL, GITHUB_REPO, GITHUB_REPO_NAME, GITHUB_REPO_OWNER, RELEASES_URL } from '../../siteConfig';

type GitHubMeta = {
  stars: number | null;
  forks: number | null;
  updated: string | null;
};

const STORAGE_KEY = 'identrail-github-meta-v1';
const FRESHNESS_MS = 12 * 60 * 60 * 1000; // 12h cache so we don't burn the rate limit

function fmt(n: number | null): string {
  if (n === null) return 'N/A';
  if (n < 1000) return String(n);
  return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k`;
}

function readCache(): GitHubMeta | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { fetchedAt: number; data: GitHubMeta };
    if (Date.now() - parsed.fetchedAt > FRESHNESS_MS) return null;
    return parsed.data;
  } catch {
    return null;
  }
}

function writeCache(data: GitHubMeta) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ fetchedAt: Date.now(), data }));
  } catch {
    // ignored: private mode or quota
  }
}

/**
 * Open-source proof bar.
 *
 * No fabricated logos, no fabricated quotes - instead, the strongest honest
 * proof we have today: the public repo metrics, the deployment posture,
 * and the review surface (source, releases and contribution checks). Falls
 * back gracefully when the GitHub API is unavailable.
 */
export function OpenSourceProof() {
  const [meta, setMeta] = useState<GitHubMeta>({ stars: null, forks: null, updated: null });

  useEffect(() => {
    const cached = readCache();
    if (cached) {
      setMeta(cached);
      return;
    }

    let cancelled = false;
    fetch(`https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}`, {
      headers: { Accept: 'application/vnd.github+json' }
    })
      .then(async (res) => {
        if (!res.ok) throw new Error('github api error');
        const data = (await res.json()) as { stargazers_count: number; forks_count: number; pushed_at: string };
        const next: GitHubMeta = {
          stars: data.stargazers_count,
          forks: data.forks_count,
          updated: data.pushed_at
        };
        if (!cancelled) setMeta(next);
        writeCache(next);
      })
      .catch(() => {
        // Silent - cells will render as " - " and the proof bar still works.
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section className="section-tight">
      <div className="container">
        <div
          className="open-source-proof"
        >
          <div className="row-between" style={{ marginBottom: 'var(--space-8)' }}>
            <div>
              <span className="t-eyebrow">Built in the open</span>
              <h2 className="t-h3 u-mt-3" style={{ maxWidth: '24ch' }}>
                Public source, public releases, inspectable controls.
              </h2>
              <p className="t-body u-mt-3" style={{ maxWidth: '52ch' }}>
                The platform is Apache 2.0 on GitHub: connectors, graph engine, policy simulator and deployment
                assets. Buyers can inspect the control plane instead of trusting a black box.
              </p>
            </div>
            <div className="row" style={{ gap: 'var(--space-3)' }}>
              <ArrowLink to={GITHUB_REPO} external>
                <GitHubIcon size={14} /> View the repo
              </ArrowLink>
              <ArrowLink to={RELEASES_URL} external>
                Releases
              </ArrowLink>
            </div>
          </div>

          <dl className="stats">
            <div className="stat">
              <dt>GitHub stars</dt>
              <dd>
                <StarIcon size={20} style={{ color: 'var(--c-warning)', verticalAlign: '-2px', marginRight: 6 }} />
                {fmt(meta.stars)}
              </dd>
            </div>
            <div className="stat">
              <dt>Forks</dt>
              <dd>{fmt(meta.forks)}</dd>
            </div>
            <div className="stat">
              <dt>License</dt>
              <dd style={{ fontSize: 'clamp(1.4rem, 1rem + 1vw, 2rem)' }}>Apache 2.0</dd>
            </div>
            <div className="stat">
              <dt>Merge checks</dt>
              <dd style={{ fontSize: 'clamp(1.4rem, 1rem + 1vw, 2rem)' }}>DCO + CI</dd>
            </div>
          </dl>

          <div className="open-source-checks" aria-label="Open-source proof checks">
            <a href={GITHUB_REPO} target="_blank" rel="noopener noreferrer">
              Source available
            </a>
            <a href={CONTRIBUTING_URL} target="_blank" rel="noopener noreferrer">
              Signed commits
            </a>
            <a href={RELEASES_URL} target="_blank" rel="noopener noreferrer">
              Versioned releases
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
