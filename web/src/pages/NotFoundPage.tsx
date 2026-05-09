import { Link } from 'react-router-dom';
import { LinkButton } from '../components/ui/Button';
import { Pill } from '../components/ui/Pill';

export function NotFoundPage() {
  return (
    <section className="container" style={{ padding: 'var(--space-32) 0' }}>
      <Pill variant="accent">404</Pill>
      <h1 className="t-display-2 u-mt-4" style={{ maxWidth: '20ch' }}>
        That page took a trust path we don't recognise.
      </h1>
      <p className="t-lede u-mt-4" style={{ maxWidth: '52ch' }}>
        The URL you followed isn't here — it may have moved during the redesign. Try one of the entry points
        below, or head home.
      </p>
      <div className="row u-mt-8">
        <LinkButton to="/" variant="primary" size="lg">
          Back to home
        </LinkButton>
        <LinkButton to="/product" variant="secondary" size="lg">
          Read about the product
        </LinkButton>
      </div>

      <ul
        className="grid grid-3 u-mt-16"
        style={{ listStyle: 'none', padding: 0 }}
        aria-label="Suggested pages"
      >
        {[
          { to: '/pricing', label: 'Pricing', desc: 'Open source, Team, Enterprise.' },
          { to: '/security', label: 'Security', desc: 'How we handle your data.' },
          { to: '/blog', label: 'Blog', desc: 'Field notes on machine identity.' }
        ].map((s) => (
          <li key={s.to}>
            <Link to={s.to} className="card">
              <h3>{s.label}</h3>
              <p>{s.desc}</p>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
