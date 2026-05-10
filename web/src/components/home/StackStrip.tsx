import { STACK } from '../../siteConfig';

/**
 * "Reviewed across your identity stack" — replaces the conventional
 * "trusted by" customer-logo wall. The user has no customers to name yet,
 * so we lead with the *stacks* Identrail covers, using each vendor's
 * official logo. This is honest and still gives the page a credible
 * recognition row.
 */
export function StackStrip() {
  const rail = [...STACK, ...STACK, ...STACK];

  return (
    <section className="section-tight stack-strip-section">
      <div className="logo-strip">
        <div className="logo-strip-eyebrow">Reviewed across your identity stack</div>
        <div className="logo-rail" aria-label="Stacks Identrail covers">
          <ul className="logo-rail-track">
            {rail.map((s, index) => (
              <li key={`${s.id}-${index}`} aria-hidden={index >= STACK.length}>
                <a
                  href={s.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  tabIndex={index >= STACK.length ? -1 : undefined}
                  title={`${s.name} - ${s.category}`}
                >
                  <img src={s.logo} alt={index < STACK.length ? s.name : ''} loading="lazy" />
                  <span>{s.name}</span>
                </a>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
