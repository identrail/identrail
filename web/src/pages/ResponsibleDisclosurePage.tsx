import { PageHero } from '../components/ui/PageHero';
import { ArrowLink } from '../components/ui/Button';
import { Section, SectionHeader } from '../components/ui/Section';
import { COMPANY } from '../siteConfig';

const PROCESS = [
  {
    step: '01',
    title: 'Report it privately',
    body:
      `Email ${COMPANY.securityEmail} or open a private security advisory on GitHub. Encrypt with our PGP key if you prefer; key fingerprint is in the security.txt file at the site root.`
  },
  {
    step: '02',
    title: 'We acknowledge in 72 hours',
    body:
      'You will hear from a human within three business days, with a tracking ID and a named owner on our side. No silent triage.'
  },
  {
    step: '03',
    title: 'We triage, scope, and fix',
    body:
      'For confirmed issues, we agree on a fix window — typically 14 days for high severity, 30 days for medium. You get visibility into the work.'
  },
  {
    step: '04',
    title: 'Coordinated disclosure',
    body:
      'We publish a security advisory crediting you (or anonymously, if you prefer) once a fix has shipped. We do not push for embargoes longer than necessary.'
  }
];

const SCOPE_IN = [
  'identrail.com and any *.identrail.com subdomain',
  'The Identrail open-source repo and packaged releases',
  'Hosted Identrail tenants on app.identrail.com'
];

const SCOPE_OUT = [
  'Social engineering of Identrail employees',
  'Physical security testing of Identrail facilities or staff',
  'Denial-of-service attacks',
  'Vulnerabilities in third-party software unless they materially affect Identrail'
];

export function ResponsibleDisclosurePage() {
  return (
    <>
      <PageHero
        eyebrow="Responsible disclosure"
        title="Find a security issue? Tell us privately. We'll fix it and credit you."
        lede="Identrail is a security product. We hold ourselves to the standard we ask of every vendor we evaluate: clear contact, fast triage, public credit, no legal threats."
        actions={
          <>
            <ArrowLink to={`mailto:${COMPANY.securityEmail}?subject=Security%20report`} external>
              {COMPANY.securityEmail}
            </ArrowLink>
            <ArrowLink to="/.well-known/security.txt" external>
              security.txt
            </ArrowLink>
          </>
        }
      />

      <Section variant="tight">
        <SectionHeader eyebrow="The process" title="What happens after you report." />
        <div className="grid grid-2">
          {PROCESS.map((p) => (
            <article
              key={p.step}
              className="card card-loose"
              style={{ display: 'grid', gridTemplateColumns: '48px 1fr', gap: 'var(--space-5)' }}
            >
              <span
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border-subtle)',
                  background: 'var(--bg-soft)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-muted)'
                }}
              >
                {p.step}
              </span>
              <div>
                <h3 className="t-h4">{p.title}</h3>
                <p className="t-body u-mt-2">{p.body}</p>
              </div>
            </article>
          ))}
        </div>
      </Section>

      <Section variant="tight">
        <div className="grid grid-2">
          <article className="card card-loose">
            <h3 className="t-h4">In scope</h3>
            <ul className="stack stack-2 u-mt-4" style={{ listStyle: 'none', padding: 0, color: 'var(--text-secondary)' }}>
              {SCOPE_IN.map((s) => (
                <li key={s}>· {s}</li>
              ))}
            </ul>
          </article>
          <article className="card card-loose">
            <h3 className="t-h4">Out of scope</h3>
            <ul className="stack stack-2 u-mt-4" style={{ listStyle: 'none', padding: 0, color: 'var(--text-secondary)' }}>
              {SCOPE_OUT.map((s) => (
                <li key={s}>· {s}</li>
              ))}
            </ul>
          </article>
        </div>
      </Section>

      <Section variant="tight">
        <article className="card card-loose">
          <h3 className="t-h4">Safe-harbour</h3>
          <p className="t-body u-mt-3">
            We will not pursue legal action against good-faith security research conducted within the scope above.
            Please make a reasonable effort to avoid privacy violations, data destruction, and service interruption,
            and stop and contact us if you encounter user data during testing.
          </p>
        </article>
      </Section>
    </>
  );
}
