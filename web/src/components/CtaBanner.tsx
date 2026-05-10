import { LinkButton } from './ui/Button';

type CtaBannerProps = {
  eyebrow?: string;
  title: string;
  body?: string;
  primary: { label: string; to: string };
  secondary?: { label: string; to: string };
};

/**
 * Closing CTA banner. Used at the foot of most marketing pages, so the
 * markup stays here and gets a single style treatment in styles.css.
 */
export function CtaBanner({ eyebrow, title, body, primary, secondary }: CtaBannerProps) {
  return (
    <section className="section-tight">
      <div className="container">
        <div className="cta-banner">
          <div>
            {eyebrow ? <span className="t-eyebrow">{eyebrow}</span> : null}
            <h2 className="u-mt-3">{title}</h2>
            {body ? <p>{body}</p> : null}
          </div>
          <div className="cta-banner-actions row">
            <LinkButton to={primary.to} variant="primary" size="lg">
              {primary.label}
            </LinkButton>
            {secondary ? (
              <LinkButton to={secondary.to} variant="secondary" size="lg">
                {secondary.label}
              </LinkButton>
            ) : null}
          </div>
        </div>
      </div>
    </section>
  );
}
