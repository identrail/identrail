import { PageHero } from '../components/ui/PageHero';
import { CompanyHeroVisual } from '../components/ui/HeroVisuals';
import { ArrowLink } from '../components/ui/Button';
import { Section, SectionHeader } from '../components/ui/Section';
import { CtaBanner } from '../components/CtaBanner';
import { FOUNDER, COMPANY } from '../siteConfig';

const PRINCIPLES = [
  {
    title: 'The graph is the surface.',
    body:
      'You should never have to leave the trust graph to do anything important. Find a finding, click into the path, simulate the fix, route it to an owner - same surface, no exports.'
  },
  {
    title: 'Read-only until proven otherwise.',
    body:
      'Every connector is read-only by default. Enforcement is a separate, opt-in surface. We will never ship a feature that requires write access without naming exactly what it writes and why.'
  },
  {
    title: 'Open beats opaque.',
    body:
      'The detection logic, the simulator, the connectors - all of it is in the public repo. If a buyer cannot read the source of a security tool, they cannot trust it. We chose Apache 2.0 on purpose.'
  },
  {
    title: 'Severity must be earned.',
    body:
      'A finding is "high" only when the path resolves to data, money, or control. We refuse to ship a tool that floods you with theoretical risk. The point is to surface what matters and stay quiet otherwise.'
  }
];

export function AboutPage() {
  return (
    <>
      <PageHero
        eyebrow="Company"
        title={
          <h1>
            Identrail exists because identity is the new perimeter,
            <br />
            <span style={{ color: 'var(--text-muted)' }}>and most teams are securing it blind.</span>
          </h1>
        }
        lede="A founder note, the principles we build under, and an honest read on where we are today."
        visual={<CompanyHeroVisual />}
      />

      <Section>
        <div className="founder-card">
          <div>
            <span className="t-eyebrow">A note from the founder</span>
            <p className="t-body-lg u-mt-6" style={{ maxWidth: '60ch' }}>
              I have spent my career inside cloud IAM systems - at the level where you debug an
              `sts:AssumeRole` chain by hand and still wonder if you missed a hop. The honest truth is
              that almost nobody knows what their non-human identities can reach. They have signals, they
              have detections, they have queues full of findings. What they do not have is a clear,
              evidence-grounded answer to the only question that matters: <em>what can this identity touch,
              and what would actually break if I took that reach away?</em>
            </p>
            <p className="t-body-lg u-mt-4" style={{ maxWidth: '60ch' }}>
              That gap is where the breaches happen. That gap is what Identrail closes. Open core, because
              security tools you cannot read are security tools you cannot trust. Read-only by default,
              because the right way to start is by looking. Path-grounded severity, because nobody has the
              attention budget for theoretical risk anymore.
            </p>
            <p className="t-body-lg u-mt-4" style={{ maxWidth: '60ch' }}>
              We are early. We are building in public. If any of this resonates, talk to us - by email, on
              Discord, or on the repo. The product gets better when the people who care about it tell us
              where it is wrong.
            </p>
            <div className="quote-attribution u-mt-8">
              <div>
                <div className="quote-attribution-name">{FOUNDER.name}</div>
                <div>{FOUNDER.title} · Identrail</div>
              </div>
            </div>
            <div className="row u-mt-6">
              <ArrowLink to={FOUNDER.linkedin} external>
                Connect on LinkedIn
              </ArrowLink>
              <ArrowLink to={`mailto:${COMPANY.contactEmail}`} external>
                {COMPANY.contactEmail}
              </ArrowLink>
            </div>
          </div>
          <img className="founder-portrait" src={FOUNDER.portrait} alt={FOUNDER.name} loading="lazy" decoding="async" />
        </div>
      </Section>

      <Section variant="tight">
        <SectionHeader
          eyebrow="The team"
          title="Founder-led, building in the open."
          lede="Identrail is currently a small founding team - disciplined, opinionated, and shipping. We will name the next hires here as they join."
        />
        <div className="grid grid-2">
          <article className="card card-loose">
            <Pill />
            <h3 className="t-h3">{FOUNDER.name}</h3>
            <p className="t-muted" style={{ fontSize: 'var(--text-sm)', marginTop: 'var(--space-1)' }}>
              {FOUNDER.title}
            </p>
            <p className="t-body u-mt-4">{FOUNDER.bio[0]}</p>
            <p className="t-body u-mt-3">{FOUNDER.bio[1]}</p>
            <div className="card-foot">
              <ArrowLink to={FOUNDER.linkedin} external>
                {FOUNDER.pitch}
              </ArrowLink>
            </div>
          </article>
          <article className="card card-loose" style={{ background: 'var(--bg-soft)' }}>
            <span className="t-eyebrow">We're hiring</span>
            <h3 className="t-h3 u-mt-3">Looking for early teammates.</h3>
            <p className="t-body u-mt-4">
              Founding engineers (graph, detection, simulator), founding designer, and a security lead.
              Remote-friendly. Equity-meaningful. Send a note to{' '}
              <a href={`mailto:${COMPANY.contactEmail}`}>{COMPANY.contactEmail}</a>.
            </p>
          </article>
        </div>
      </Section>

      <Section>
        <SectionHeader
          eyebrow="What we build under"
          title="Four principles."
          lede="These are the rules we use to decide what ships and what does not. They predate the product and they will outlive every release."
        />
        <div className="grid grid-2">
          {PRINCIPLES.map((p) => (
            <article key={p.title} className="card card-loose">
              <h3>{p.title}</h3>
              <p className="t-body u-mt-3">{p.body}</p>
            </article>
          ))}
        </div>
      </Section>

      <Section variant="tight">
        <div className="grid grid-2">
          <div>
            <span className="t-eyebrow">Where we are</span>
            <h3 className="t-h3 u-mt-3">Honest status today.</h3>
            <ul className="stack stack-3 u-mt-6" style={{ listStyle: 'none', padding: 0, color: 'var(--text-secondary)' }}>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Funding:</strong> backed by private investors;
                names withheld until a public announcement.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Customers:</strong> in design-partner stage with a
                small group of platform-security teams.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Compliance:</strong> SOC 2 Type I in progress; no
                pen-test history yet, public when it lands.
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Code review:</strong> every PR must pass signed
                commits, tests, security checks, and human review before merge.
              </li>
            </ul>
          </div>
          <div>
            <span className="t-eyebrow">Company</span>
            <h3 className="t-h3 u-mt-3">Logistics.</h3>
            <dl
              className="stack stack-4 u-mt-6"
              style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 'var(--space-4) var(--space-6)' }}
            >
              <dt className="t-eyebrow is-plain">Legal name</dt>
              <dd>{COMPANY.legalName}</dd>
              <dt className="t-eyebrow is-plain">Registered</dt>
              <dd>{COMPANY.registered}</dd>
              <dt className="t-eyebrow is-plain">Founded</dt>
              <dd>{COMPANY.founded}</dd>
              <dt className="t-eyebrow is-plain">Contact</dt>
              <dd>
                <a href={`mailto:${COMPANY.contactEmail}`}>{COMPANY.contactEmail}</a>
              </dd>
              <dt className="t-eyebrow is-plain">Security</dt>
              <dd>
                <a href={`mailto:${COMPANY.securityEmail}`}>{COMPANY.securityEmail}</a>
              </dd>
            </dl>
          </div>
        </div>
      </Section>

      <CtaBanner
        title="Talk to the founder."
        body="If you are a security or platform engineer dealing with machine-identity sprawl, we want to hear from you - even if you are not buying."
        primary={{ label: 'Book 15 minutes', to: '/demo' }}
        secondary={{ label: 'Email Oluwatobi', to: `mailto:${COMPANY.contactEmail}` }}
      />
    </>
  );
}

// Tiny inline placeholder so we can render the team card with a soft icon spot.
function Pill() {
  return (
    <span
      className="t-eyebrow"
      style={{ color: 'var(--accent)' }}
    >
      Founder
    </span>
  );
}
