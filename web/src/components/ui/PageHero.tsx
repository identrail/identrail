import { ReactNode } from 'react';

type PageHeroProps = {
  eyebrow?: string;
  title: ReactNode;
  lede?: ReactNode;
  actions?: ReactNode;
  visual?: ReactNode;
};

/**
 * Page hero used at the top of marketing pages other than `/`.
 * Distinguished from the Home hero by being more restrained and
 * left-aligned by default, with no decorative gradient.
 */
export function PageHero({ eyebrow, title, lede, actions, visual }: PageHeroProps) {
  return (
    <section className={['page-hero', visual ? 'has-visual' : ''].filter(Boolean).join(' ')}>
      <div className="container">
        <div className="page-hero-inner">
          <div className="page-hero-copy">
            {eyebrow ? <span className="t-eyebrow">{eyebrow}</span> : null}
            {typeof title === 'string' ? <h1>{title}</h1> : title}
            {/*
             * <div>, not <p>: lede accepts any ReactNode and some callers pass
             * richer content. A <div> avoids accidental block-in-p invalidity.
             */}
            {lede ? <div className="t-lede">{lede}</div> : null}
            {actions ? <div className="page-hero-actions">{actions}</div> : null}
          </div>
          {visual ? <div className="page-hero-visual">{visual}</div> : null}
        </div>
      </div>
    </section>
  );
}
