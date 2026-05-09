import { PageHero } from '../components/ui/PageHero';
import { LinkButton, ArrowLink } from '../components/ui/Button';
import { CheckIcon, ShieldIcon } from '../components/ui/Icon';
import { Section, SectionHeader } from '../components/ui/Section';
import { Pill } from '../components/ui/Pill';
import { CtaBanner } from '../components/CtaBanner';
import { COMPANY } from '../siteConfig';

const PROCUREMENT = [
  {
    title: 'Mutual NDA',
    body: 'Standard MNDA template, or yours — we sign first round same week.'
  },
  {
    title: 'Security review',
    body:
      'Comprehensive security questionnaire, threat model walkthrough, infra-as-code review on request.'
  },
  {
    title: 'Custom data residency',
    body: 'Run a private single-tenant deployment in any AWS region. Data never leaves your chosen region.'
  },
  {
    title: 'MSA / DPA / SLA',
    body: 'Custom contracting on commercial, data processing, and uptime terms — drafted by counsel both sides can read.'
  },
  {
    title: 'Insurance',
    body: 'Cyber and E&O coverage in line with mid-market enterprise expectations; certificate available on request.'
  },
  {
    title: 'Audit log streaming',
    body: 'S3, Splunk, Datadog, or Elastic. Full event schema documented.'
  }
];

const DEPLOY = [
  {
    name: 'Hosted single-tenant',
    pitch:
      'We run the service for you in a dedicated VPC in your chosen region. You see the dashboard; we see only operational health. Common pick.'
  },
  {
    name: 'Private tenancy in your account',
    pitch:
      'Identrail deployed inside your own AWS account via Terraform. We never touch your data plane. You control IAM and network egress.'
  },
  {
    name: 'Air-gapped self-host',
    pitch:
      'For environments with no public-internet connectivity. Identrail ships as a versioned image with offline detection updates.'
  }
];

export function EnterprisePage() {
  return (
    <>
      <PageHero
        eyebrow="Enterprise"
        title="Identrail for organisations with procurement, audit, and air-gap requirements."
        lede="Same engine as the open-source edition, with the deployment options, contracting, and support structure that mid-to-large security organisations need."
        actions={
          <>
            <LinkButton to={`mailto:${COMPANY.contactEmail}?subject=Enterprise%20enquiry`} variant="primary" size="lg" external>
              Talk to us
            </LinkButton>
            <LinkButton to="/demo" variant="secondary" size="lg">
              Book a walkthrough
            </LinkButton>
          </>
        }
      />

      <Section variant="tight">
        <SectionHeader
          eyebrow="Deployment models"
          title="Three options. You pick the trade you want to make."
        />
        <div className="grid grid-3">
          {DEPLOY.map((d) => (
            <article key={d.name} className="card card-loose">
              <Pill variant="accent">
                <ShieldIcon size={12} /> Available
              </Pill>
              <h3 className="t-h3 u-mt-4">{d.name}</h3>
              <p className="t-body u-mt-3">{d.pitch}</p>
            </article>
          ))}
        </div>
      </Section>

      <Section>
        <SectionHeader
          eyebrow="Procurement"
          title="What we'll have ready when you ask."
          lede="None of this should be a surprise. The faster you tell us what your security review needs, the faster we get it to you."
        />
        <div className="grid grid-2">
          {PROCUREMENT.map((p) => (
            <article
              key={p.title}
              className="card"
              style={{ display: 'grid', gridTemplateColumns: '24px 1fr', gap: 'var(--space-4)' }}
            >
              <span style={{ color: 'var(--accent)', marginTop: 4 }}>
                <CheckIcon size={20} />
              </span>
              <div>
                <strong style={{ fontSize: 'var(--text-md)' }}>{p.title}</strong>
                <p className="t-muted u-mt-1" style={{ fontSize: 'var(--text-sm)' }}>
                  {p.body}
                </p>
              </div>
            </article>
          ))}
        </div>
      </Section>

      <Section variant="tight">
        <div className="grid grid-2" style={{ alignItems: 'start' }}>
          <article className="card card-loose">
            <span className="t-eyebrow">Pilot</span>
            <h3 className="t-h3 u-mt-3">A 30-day scoped pilot.</h3>
            <p className="t-body u-mt-3">
              We agree on the in-scope environment (a single account, a single cluster, a defined repo set), the
              success criteria, and the out criteria. Findings stay yours regardless of outcome.
            </p>
            <div className="card-foot">
              <ArrowLink to={`mailto:${COMPANY.contactEmail}?subject=Pilot%20interest`} external>
                Start a pilot conversation
              </ArrowLink>
            </div>
          </article>
          <article className="card card-loose" style={{ background: 'var(--bg-soft)' }}>
            <span className="t-eyebrow">Support</span>
            <h3 className="t-h3 u-mt-3">Named TAM and 24/7 paging.</h3>
            <p className="t-body u-mt-3">
              Enterprise customers get a named technical account manager, an onboarding program scoped to your
              stack, and a paging tier with custom SLA. Real human, real phone number.
            </p>
          </article>
        </div>
      </Section>

      <CtaBanner
        title="Bring procurement in early."
        body="If you're starting an evaluation, send us your security questionnaire and the scope you want to pilot — we'll come back inside one business day."
        primary={{ label: 'Email Enterprise', to: `mailto:${COMPANY.contactEmail}?subject=Enterprise%20enquiry` }}
        secondary={{ label: 'Read security posture', to: '/security' }}
      />
    </>
  );
}
