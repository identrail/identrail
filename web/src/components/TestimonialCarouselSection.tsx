import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const testimonials = [
  {
    quote: 'The trust graph gave us immediate clarity on machine identity risk and blast radius.',
    author: 'Principal Security Engineer',
    org: 'Global FinTech'
  },
  {
    quote: 'Findings and policy simulation helped us remediate safely without downtime.',
    author: 'Director, Cloud Platform',
    org: 'Enterprise Healthcare'
  },
  {
    quote: 'Repo scanning and runtime trust analysis finally live in one workflow.',
    author: 'Head of Application Security',
    org: 'Retail Infrastructure'
  },
  {
    quote: 'Open-source plus production-grade controls made adoption frictionless.',
    author: 'Identity Program Lead',
    org: 'Fortune 100 Manufacturer'
  }
] as const;

export function TestimonialCarouselSection() {
  const rail = [...testimonials, ...testimonials];

  return (
    <section className="section reveal-on-scroll" aria-labelledby="testimonial-carousel-title">
      <div className="section-card testimonial-carousel-shell">
        <div className="section-header centered">
          <h2 id="testimonial-carousel-title">Trusted by practitioners building secure platforms</h2>
          <p className="testimonial-score">4.8/5 average rating from machine identity teams</p>
        </div>

        <div className="testimonial-carousel" aria-label="Customer testimonial carousel">
          <div className="testimonial-track">
            {rail.map((item, index) => (
              <article key={`${item.author}-${index}`} className="testimonial-card">
                <div className="testimonial-avatar" aria-hidden="true" />
                <p>{item.quote}</p>
                <footer>
                  <strong>{item.author}</strong>
                  <span>{item.org}</span>
                </footer>
              </article>
            ))}
          </div>
        </div>

        <SafeLink className="btn btn-text" href={siteLinks.starOnGithub}>
          Star on GitHub to join the next release cohort
        </SafeLink>
      </div>
    </section>
  );
}
