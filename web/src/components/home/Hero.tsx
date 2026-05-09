import { LinkButton } from '../ui/Button';
import { ArrowRightIcon, GitHubIcon } from '../ui/Icon';
import { Pill } from '../ui/Pill';
import { GITHUB_REPO } from '../../siteConfig';
import { TrustPathIllustration } from './TrustPathIllustration';

/**
 * Marketing hero. Light-first, editorial. The headline does the work — we
 * intentionally avoid a screenful of competing UI mocks. The illustration
 * to the right is a designed product surface (clearly framed by the
 * "Illustrative" label inside it).
 */
export function HomeHero() {
  return (
    <section className="home-hero">
      <div className="container">
        <div className="home-hero-grid">
          <div>
            <Pill variant="accent" dot>
              Open core · Apache 2.0
            </Pill>
            <h1 className="u-mt-4">
              Trace every machine identity.<br />
              <em>Close the dangerous paths</em> safely.
            </h1>
            <p className="t-lede">
              Identrail follows how AWS roles, Kubernetes service accounts, GitHub OIDC and trust
              policies can reach your data — and shows the smallest, safest fix for the people who
              own each step of the path.
            </p>
            <div className="home-hero-actions">
              <LinkButton to="/demo" variant="primary" size="lg">
                Start a free risk scan <ArrowRightIcon />
              </LinkButton>
              <LinkButton to={GITHUB_REPO} variant="secondary" size="lg" external>
                <GitHubIcon size={16} /> Read the source
              </LinkButton>
            </div>
            <dl className="home-hero-meta">
              <div>
                <dt>Read-only by default</dt>
                <dd>No write scopes</dd>
              </div>
              <div>
                <dt>Self-hosted or hosted</dt>
                <dd>Your choice</dd>
              </div>
              <div>
                <dt>Time to first finding</dt>
                <dd>Under 10 min</dd>
              </div>
            </dl>
          </div>
          <TrustPathIllustration />
        </div>
      </div>
    </section>
  );
}
