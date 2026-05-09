import { PageHero } from '../components/ui/PageHero';
import { DocsHeroVisual } from '../components/ui/HeroVisuals';
import { LinkButton } from '../components/ui/Button';
import { Section, SectionHeader } from '../components/ui/Section';
import { Pill } from '../components/ui/Pill';
import { CtaBanner } from '../components/CtaBanner';
import { DOCS_REPO, DOCKER_REPO_URL, GITHUB_REPO } from '../siteConfig';
import { DOC_ENTRIES } from '../content/resources';

export function DocsPage() {
  return (
    <>
      <PageHero
        eyebrow="Documentation"
        title="Documentation lives next to the code."
        lede="Until docs.identrail.com lands, the source of truth is the docs/ folder of the public repo. Below is the curated entry-point list — start with Quickstart and work down."
        visual={<DocsHeroVisual />}
        actions={
          <>
            <LinkButton to={DOCKER_REPO_URL} variant="primary" size="lg" external>
              Quickstart with Docker
            </LinkButton>
            <LinkButton to={DOCS_REPO} variant="secondary" size="lg" external>
              Browse all docs
            </LinkButton>
          </>
        }
      />

      <Section variant="tight">
        <SectionHeader
          eyebrow="Start here"
          title="Curated entry points."
          lede="Each link goes to the canonical version on GitHub so you always read the same content the engineering team does."
        />
        <div className="grid grid-2">
          {DOC_ENTRIES.map((doc) => (
            <a
              key={doc.href}
              href={doc.href}
              target="_blank"
              rel="noopener noreferrer"
              className="card card-loose"
            >
              <div className="row-tight">
                {doc.tags.map((t) => (
                  <Pill key={t}>{t}</Pill>
                ))}
              </div>
              <h3 className="t-h3 u-mt-4">{doc.title}</h3>
              <p className="t-body u-mt-3">{doc.description}</p>
              <div className="card-foot">
                {/*
                 * The whole card is the link target, so we render the foot
                 * as styled text + arrow rather than a nested anchor (which
                 * would be invalid HTML).
                 */}
                <span className="btn-arrow" aria-hidden="true">
                  Open on GitHub
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                    <path
                      d="M3.5 8h9M9 4.5L12.5 8 9 11.5"
                      stroke="currentColor"
                      strokeWidth="1.4"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </span>
              </div>
            </a>
          ))}
        </div>
      </Section>

      <CtaBanner
        title="A real docs site is on the way."
        body="docs.identrail.com is coming together. In the meantime, the GitHub README and docs/ folder are the source of truth — they always reflect what's actually in the latest release."
        primary={{ label: 'View the repo', to: GITHUB_REPO }}
        secondary={{ label: 'Talk to us', to: '/demo' }}
      />
    </>
  );
}
