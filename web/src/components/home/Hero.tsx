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
              See every machine identity path.<br />
              <em>Fix the risky ones</em> safely.
            </h1>
            <p className="t-lede">
              Identrail shows how AWS IAM, Kubernetes, and GitHub OIDC paths reach sensitive
              systems, then gives each team the safest fix.
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
