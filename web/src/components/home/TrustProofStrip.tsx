import { Link } from 'react-router-dom';
import { SafeLink } from '../SafeLink';
import { TRUST_PROOF_LINKS } from '../../content/proofArtifacts';

const TRUST_SUMMARY_ITEMS = TRUST_PROOF_LINKS.slice(0, 4);
const TRUST_METRICS = [
  { value: 'Apache-2.0', label: 'open-core license' },
  { value: '37', label: 'public routes and docs paths' },
  { value: '4', label: 'production signal families' }
] as const;

export function TrustProofStrip() {
  return (
    <section className="idt-trust-strip" aria-label="Credibility and proof">
      <div className="idt-shell idt-proof-architecture">
        <div className="idt-proof-strip-head">
          <p className="idt-proof-heading">Built in the open with verifiable trust controls.</p>
          <dl className="idt-proof-metrics" aria-label="Identrail trust signals">
            {TRUST_METRICS.map((metric) => (
              <div key={metric.label}>
                <dt>{metric.value}</dt>
                <dd>{metric.label}</dd>
              </div>
            ))}
          </dl>
        </div>
        <div className="idt-proof-architecture-list">
          {TRUST_SUMMARY_ITEMS.map((entry) => (
            <article key={entry.label} className="idt-proof-architecture-item">
              <p className="idt-proof-item-title">{entry.label}</p>
              <p>{entry.description}</p>
              {entry.external ? (
                <SafeLink href={entry.href} className="idt-proof-link">
                  Review
                </SafeLink>
              ) : (
                <Link to={entry.href} className="idt-proof-link">
                  Review
                </Link>
              )}
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
