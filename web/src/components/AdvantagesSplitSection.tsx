import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const operationalAdvantages = [
  'Continuously map machine trust paths across AWS and Kubernetes.',
  'Prioritize high-signal findings that map to real blast radius.',
  'Shorten policy review cycles with simulation before rollout.'
] as const;

const technicalAdvantages = [
  'Graph-first architecture with explainable node-to-node access paths.',
  'Repository scanning for secret exposure and risky trust patterns.',
  'Self-hosted deployment with docker compose and open contribution model.'
] as const;

export function AdvantagesSplitSection() {
  return (
    <section className="section reveal-on-scroll" aria-labelledby="advantages-split-title">
      <div className="section-card advantages-shell">
        <blockquote className="advantages-quote">
          <span aria-hidden="true">“</span>
          <div className="advantages-quote-avatar" aria-hidden="true" />
          <p>
            Identrail gave us board-level confidence in machine identity risk because every finding
            came with a clear trust path and safe remediation plan.
          </p>
          <footer>
            <strong>CISO, Fortune 500 infrastructure group</strong>
            <span>Scaled across cloud + Kubernetes in one quarter</span>
          </footer>
        </blockquote>

        <div className="advantages-columns">
          <div>
            <h2 id="advantages-split-title">Operational Advantages</h2>
            <div className="advantages-divider" aria-hidden="true" />
            <ul>
              {operationalAdvantages.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          <div>
            <h3>Technical Advantages</h3>
            <div className="advantages-divider" aria-hidden="true" />
            <ul>
              {technicalAdvantages.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          <SafeLink className="btn btn-secondary" href={siteLinks.contribute}>
            Contribute to these capabilities
          </SafeLink>
        </div>
      </div>
    </section>
  );
}
