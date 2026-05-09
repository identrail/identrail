import { STACK } from '../../siteConfig';

/**
 * "Reviewed across your identity stack" — replaces the conventional
 * "trusted by" customer-logo wall. The user has no customers to name yet,
 * so we lead with the *stacks* Identrail covers, using each vendor's
 * official logo. This is honest and still gives the page a credible
 * recognition row.
 */
export function StackStrip() {
  return (
    <section className="section-tight">
      <div className="container">
        <div className="logo-strip">
          <div className="logo-strip-eyebrow">Reviewed across your identity stack</div>
          <ul className="logo-grid" aria-label="Stacks Identrail covers">
            {STACK.map((s) => (
              <li key={s.id}>
                <a
                  href={s.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={`${s.name} — ${s.category}`}
                >
                  <img src={s.logo} alt={s.name} loading="lazy" />
                </a>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
