import { ArrowLink } from '../ui/Button';
import { FOUNDER } from '../../siteConfig';

/**
 * Founder pull-quote.
 *
 * In the absence of customer testimonials, the next-best honest signal is
 * the founder telling you exactly why he built this. The line below is the
 * thesis Identrail is being built around.
 */
export function FounderQuote() {
  return (
    <section className="section">
      <div className="container">
        <div className="founder-card">
          <div>
            <span className="t-eyebrow">Why we built this</span>
            <blockquote className="pull-quote u-mt-6">
              Most identity tools tell you a service account is risky. Almost none tell you what it can
              actually reach, or how to take that reach away without breaking production. That gap is where
              breaches happen. That gap is what Identrail closes.
            </blockquote>
            <div className="quote-attribution">
              <div>
                <div className="quote-attribution-name">{FOUNDER.name}</div>
                <div>
                  {FOUNDER.title} · {FOUNDER.pitch}
                </div>
              </div>
            </div>
            <div className="row u-mt-6">
              <ArrowLink to="/about">Read the founder letter</ArrowLink>
              <ArrowLink to={FOUNDER.linkedin} external>
                Connect on LinkedIn
              </ArrowLink>
            </div>
          </div>
          <div className="founder-portrait" aria-hidden="true">
            {FOUNDER.initials}
          </div>
        </div>
      </div>
    </section>
  );
}
