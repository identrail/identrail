import { PageHero } from '../components/ui/PageHero';
import { ArrowLink } from '../components/ui/Button';
import { CheckIcon, ShieldIcon } from '../components/ui/Icon';
import { Pill } from '../components/ui/Pill';
import { Section, SectionHeader } from '../components/ui/Section';
import { COMPANY, GITHUB_REPO } from '../siteConfig';

const POSTURE = [
  {
    eyebrow: 'Data handling',
    title: 'Identrail does not store the contents of your secrets.',
    bullets: [
      'Scans hash credential material at the edge - the secret value never leaves your environment.',
      'Connector credentials are encrypted at rest with AES-256 and rotated on a 90-day cadence.',
      'Findings, evidence, and metadata are deleted on request within 30 days; immediately for hosted Team customers via the in-app control.'
    ]
  },
  {
    eyebrow: 'Access',
    title: 'Read-only by default; enforcement is a separate, opt-in surface.',
    bullets: [
      'Connector setup uses least-privilege read scopes; suggested IAM policies are public in the repo.',
      'Policy enforcement requires named operators and an approval gate distinct from setup.',
      'No long-running agent. Scans complete and tear down their connection.'
    ]
  },
  {
    eyebrow: 'Infrastructure',
    title: 'Hosted Identrail runs on hardened, well-known cloud primitives.',
    bullets: [
      'Hosted on AWS in our customer’s choice of US or EU region (Team), or a private region (Enterprise).',
      'All inter-service traffic is mTLS. All data at rest is encrypted with envelope encryption.',
      'Infrastructure-as-code; every change passes signed-commit, test, security, and human-review gates before merge.'
    ]
  }
];

const COMPLIANCE = [
  { name: 'SOC 2 Type I', status: 'In progress', detail: 'Audit underway with Drata; expected H2 2026.' },
  { name: 'SOC 2 Type II', status: 'Roadmap', detail: 'Following Type I, on a 12-month observation window.' },
  { name: 'ISO 27001', status: 'Considered', detail: 'Will follow SOC 2 Type II depending on customer demand.' },
  { name: 'GDPR', status: 'Aligned', detail: 'EU data residency available; DPA available on request.' },
  { name: 'HIPAA', status: 'Not yet', detail: 'No PHI is processed today; not in current scope.' },
  { name: 'Pen test', status: 'Scheduled', detail: 'First third-party pen test scheduled before Type I close.' }
];

export function SecurityPage() {
  return (
    <>
      <PageHero
        eyebrow="Security & compliance"
        title="We sell to security teams. We don't dodge questions."
        lede="A complete read on how Identrail handles your data, what we have certified, what we are working on, and what we have not done yet. No vague language, no aspirational claims."
        actions={
          <>
            <ArrowLink to={`mailto:${COMPANY.securityEmail}`} external>
              Email {COMPANY.securityEmail}
            </ArrowLink>
            <ArrowLink to="/responsible-disclosure">Responsible disclosure</ArrowLink>
          </>
        }
      />

      <Section variant="tight">
        <SectionHeader
          eyebrow="Compliance posture"
          title="Honest status, by line item."
          lede="If a status here matters to a buyer in your org and is not where they need it to be, talk to us - we'd rather hear that early than late."
        />
        <table className="compare">
          <thead>
            <tr>
              <th scope="col">Standard</th>
              <th scope="col">Status</th>
              <th scope="col">Detail</th>
            </tr>
          </thead>
          <tbody>
            {COMPLIANCE.map((c) => (
              <tr key={c.name}>
                <th scope="row">{c.name}</th>
                <td data-col="Status" className="v-strong">
                  {c.status}
                </td>
                <td data-col="Detail">{c.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section>
        <SectionHeader
          eyebrow="Security posture"
          title="What we do, in the order it matters."
        />
        <div className="stack stack-12">
          {POSTURE.map((p) => (
            <article key={p.eyebrow} className="card card-loose">
              <Pill variant="accent">
                <ShieldIcon size={12} /> {p.eyebrow}
              </Pill>
              <h2 className="t-h3 u-mt-4">{p.title}</h2>
              <ul
                className="stack stack-3 u-mt-6"
                style={{ listStyle: 'none', padding: 0 }}
              >
                {p.bullets.map((b) => (
                  <li
                    key={b}
                    style={{ display: 'grid', gridTemplateColumns: '20px 1fr', gap: 'var(--space-3)' }}
                  >
                    <span style={{ color: 'var(--accent)', marginTop: 4 }}>
                      <CheckIcon size={16} />
                    </span>
                    <span style={{ color: 'var(--text-primary)' }}>{b}</span>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </Section>

      <Section variant="tight">
        <div className="grid grid-2">
          <article className="card card-loose">
            <span className="t-eyebrow">Read the source</span>
            <h3 className="t-h3 u-mt-3">Every detection is in the open repo.</h3>
            <p className="t-body u-mt-3">
              Closed-source security tools ask you to trust their detections. We ask you to read them. The full
              detection surface - connectors, rules, simulator - is on GitHub.
            </p>
            <div className="card-foot">
              <ArrowLink to={GITHUB_REPO} external>
                Repo
              </ArrowLink>
            </div>
          </article>
          <article className="card card-loose">
            <span className="t-eyebrow">Vulnerability handling</span>
            <h3 className="t-h3 u-mt-3">Disclose privately, get triage in 72h.</h3>
            <p className="t-body u-mt-3">
              We coordinate disclosure publicly and credit reporters. The full process - triage, fix, advisory - is on the responsible-disclosure page.
            </p>
            <div className="card-foot">
              <ArrowLink to="/responsible-disclosure">Responsible disclosure</ArrowLink>
            </div>
          </article>
        </div>
      </Section>
    </>
  );
}
