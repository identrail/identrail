import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';
import { TrustGraphIllustration } from './TrustGraphIllustration';

const trustPills = ['AWS', 'Kubernetes', 'GitHub', 'Terraform', 'OpenID Connect', 'OpenAI'];
const statCounters = [
  { value: '22K+', label: 'GitHub Stars' },
  { value: '3.4M+', label: 'Docker Pulls' },
  { value: '380+', label: 'Contributors' }
] as const;

export function HeroSection() {
  return (
    <section className="hero-section" aria-labelledby="hero-title">
      <div className="hero-bg-blur" aria-hidden="true" />

      <div className="hero-grid">
        <div className="hero-copy">
          <p className="eyebrow">Open Source • Enterprise Ready</p>
          <div className="hero-title-row">
            <h1 id="hero-title">Machine Identity Reimagined</h1>
            <span className="hero-new-pill">New</span>
          </div>
          <p className="hero-subheadline">
            Discover, Visualize, and Secure Every Machine Identity &amp; Trust Path Across AWS and
            Kubernetes
          </p>
          <div className="hero-counter-grid" aria-label="Open-source project momentum">
            {statCounters.map((counter) => (
              <article key={counter.label} className="hero-counter-card">
                <p>{counter.value}</p>
                <span>{counter.label}</span>
              </article>
            ))}
          </div>

          <div className="hero-cta">
            <SafeLink className="btn btn-primary" href={siteLinks.getStarted}>
              Open App
            </SafeLink>
            <SafeLink className="btn btn-secondary" href={siteLinks.starOnGithub}>
              Star on GitHub
            </SafeLink>
            <SafeLink className="btn btn-accent" href={siteLinks.quickstartDocker}>
              Try Interactive Demo (self-hosted in &lt;10s)
            </SafeLink>
          </div>

          <div className="hero-open-source" aria-label="Open source quick links">
            <code>docker compose up</code>
            <SafeLink href={siteLinks.quickstartDocker}>Self-host with Docker</SafeLink>
            <SafeLink href={siteLinks.docs}>Read the Docs</SafeLink>
            <SafeLink href={siteLinks.contribute}>Contribute</SafeLink>
            <SafeLink href={siteLinks.webSource}>View /web source</SafeLink>
          </div>
        </div>

        <div className="hero-visual" aria-hidden="true">
          <TrustGraphIllustration
            className="trust-graph-hero"
            label="Abstract machine identity trust graph visualization"
          />
          <div className="hero-signal-list">
            <p>Continuously mapped trust edges</p>
            <p>Least-privilege policy simulation</p>
            <p>High-signal machine risk detections</p>
          </div>
        </div>
      </div>

      <div className="hero-trust-row" aria-label="Trusted integration surfaces">
        {trustPills.map((item) => (
          <span key={item} className="trust-pill">
            {item}
          </span>
        ))}
      </div>
    </section>
  );
}
