import { useState } from 'react';
import { PageHero } from '../components/ui/PageHero';
import { PricingHeroVisual } from '../components/ui/HeroVisuals';
import { LinkButton } from '../components/ui/Button';
import { Section, SectionHeader } from '../components/ui/Section';
import { CtaBanner } from '../components/CtaBanner';
import { GITHUB_REPO } from '../siteConfig';

type Billing = 'monthly' | 'annual';

type Plan = {
  id: string;
  name: string;
  tagline: string;
  monthly: number | null;
  annual: number | null;
  unit?: string;
  startNote?: string;
  cta: { label: string; to: string; external?: boolean };
  variant: 'primary' | 'secondary';
  featured?: boolean;
  features: string[];
};

const PLANS: Plan[] = [
  {
    id: 'oss',
    name: 'Open source',
    tagline: 'Self-host the full platform under Apache 2.0. The binary the hosted plan runs is the same one you do.',
    monthly: 0,
    annual: 0,
    unit: 'forever',
    cta: { label: 'Deploy from GitHub', to: GITHUB_REPO, external: true },
    variant: 'secondary',
    features: [
      'Trust graph + path resolution',
      'AWS, Kubernetes, GitHub OIDC connectors',
      'Repo exposure scanning',
      'Policy simulator (read-only)',
      'Community support on Discord',
      'No usage limits, no hidden detections'
    ]
  },
  {
    id: 'team',
    name: 'Team',
    tagline: 'Hosted Identrail for teams who want time-to-value over infrastructure ownership. SAML SSO, scheduled scans, alerting.',
    monthly: 19,
    annual: 15,
    unit: '/user/mo',
    startNote: '3-user minimum · billed monthly or annually',
    cta: { label: 'Start a free risk scan', to: '/demo' },
    variant: 'primary',
    featured: true,
    features: [
      'Everything in Open source',
      'Hosted in the US or EU',
      'SAML SSO included from day one',
      'Scheduled scans and Slack alerting',
      'Path-grounded severity scoring',
      '14-day hosted trial, no card required'
    ]
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    tagline: 'Private tenancy, regional controls, named support, and the procurement surface large security organisations expect.',
    monthly: null,
    annual: null,
    cta: { label: 'Talk to us', to: '/enterprise' },
    variant: 'secondary',
    features: [
      'Everything in Team',
      'Private single-tenant deployment',
      'SCIM, audit log streaming',
      'Custom data residency',
      'Named TAM and onboarding program',
      'Custom SLA, security review, MNDA'
    ]
  }
];

const COMPARISON = [
  {
    capability: 'AWS IAM trust-path resolution',
    oss: 'Included',
    team: 'Included',
    enterprise: 'Included'
  },
  {
    capability: 'Kubernetes RBAC + workload identity',
    oss: 'Included',
    team: 'Included',
    enterprise: 'Included'
  },
  {
    capability: 'GitHub Actions OIDC stitching',
    oss: 'Included',
    team: 'Included',
    enterprise: 'Included'
  },
  {
    capability: 'Repo credential exposure scanning',
    oss: 'Core detectors',
    team: 'Extended detectors + auto-revoke playbooks',
    enterprise: 'Custom detectors per workspace'
  },
  {
    capability: 'Policy simulator',
    oss: 'Read-only',
    team: 'Read-only + dry-run + canary',
    enterprise: 'All gates + scoped enforcement windows'
  },
  {
    capability: 'Hosted in our cloud',
    oss: 'No (self-host)',
    team: 'US or EU',
    enterprise: 'US, EU, or your region'
  },
  {
    capability: 'SAML SSO',
    oss: 'Self-host any IdP',
    team: 'Included',
    enterprise: 'Included + SCIM'
  },
  {
    capability: 'Audit log streaming',
    oss: 'Local log',
    team: 'Webhook',
    enterprise: 'S3, Splunk, Datadog, Elastic'
  },
  {
    capability: 'Support',
    oss: 'Community Discord',
    team: 'Email, business hours',
    enterprise: '24/7 with named TAM and custom SLA'
  }
];

const FAQ = [
  {
    q: 'Why is the hosted plan cheaper than other security tools?',
    a:
      'Because the engine is open source. We are not amortising a private platform investment over every seat — we are charging for the part you genuinely benefit from outsourcing: hosting, hardening, scheduled scans, alerting, support. If you do not need any of those, the OSS edition is the same code, free.'
  },
  {
    q: 'Is there a free trial?',
    a: 'The Open source edition is free forever. The hosted Team plan includes a 14-day trial with no card required. Enterprise pilots are scoped per engagement.'
  },
  {
    q: 'Do you require write access to my cloud?',
    a:
      'No. Connector setup uses read-only credentials. Policy enforcement is a separate, opt-in surface that requires explicit approval and named operators. You can run Identrail in read-only mode forever.'
  },
  {
    q: 'What about data residency?',
    a:
      'Hosted Team customers pick US or EU. Enterprise customers pick a region or run a private single-tenant deployment in a region of their choice. Self-host gives you complete control.'
  },
  {
    q: 'Is Identrail SOC 2 compliant?',
    a:
      'Honest answer: not yet. SOC 2 Type I is in progress and on a public roadmap on the /security page. Enterprise customers can review our security posture and receive an MNDA-protected security questionnaire on request.'
  }
];

function priceLabel(plan: Plan, billing: Billing): { value: string; per?: string; note?: string } {
  const amount = billing === 'annual' ? plan.annual : plan.monthly;
  if (amount === null) {
    return { value: 'Custom', per: 'tailored to scope' };
  }
  if (amount === 0) {
    return { value: '$0', per: plan.unit ?? 'forever' };
  }
  return { value: `$${amount}`, per: plan.unit, note: plan.startNote };
}

export function PricingPage() {
  const [billing, setBilling] = useState<Billing>('annual');

  return (
    <>
      <PageHero
        eyebrow="Pricing"
        title="Honest pricing for an open-core security tool."
        lede="Free if you self-host. Cheap if you don't. Custom only when scope genuinely requires it."
        visual={<PricingHeroVisual />}
        actions={
          <div className="row" style={{ gap: 'var(--space-4)' }}>
            {/*
             * Radio-group (not tablist): there are no tab panels here, the
             * control just toggles a price label. Radio semantics convey
             * "pick one of two" correctly to assistive tech.
             */}
            <div className="billing-toggle" role="radiogroup" aria-label="Billing cadence">
              <button
                type="button"
                role="radio"
                aria-checked={billing === 'monthly'}
                className={billing === 'monthly' ? 'is-active' : ''}
                onClick={() => setBilling('monthly')}
              >
                Monthly
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={billing === 'annual'}
                className={billing === 'annual' ? 'is-active' : ''}
                onClick={() => setBilling('annual')}
              >
                Annual <span className="billing-save">Save 20%</span>
              </button>
            </div>
          </div>
        }
      />

      <Section variant="tight">
        <div className="pricing-grid">
          {PLANS.map((plan) => {
            const price = priceLabel(plan, billing);
            return (
              <article key={plan.id} className={['plan', plan.featured ? 'is-featured' : ''].join(' ')}>
                {plan.featured ? <span className="plan-flag">Most teams pick this</span> : null}
                <div className="plan-name">{plan.name}</div>
                <p className="plan-tag">{plan.tagline}</p>

                <div className="plan-price">
                  {price.value}
                  {price.per ? <small>{price.per}</small> : null}
                </div>
                {price.note ? <div className="plan-price-note">{price.note}</div> : null}

                <div className="plan-cta">
                  <LinkButton
                    to={plan.cta.to}
                    variant={plan.variant}
                    size="lg"
                    block
                    external={plan.cta.external}
                  >
                    {plan.cta.label}
                  </LinkButton>
                </div>

                <ul className="plan-features">
                  {plan.features.map((f) => (
                    <li key={f}>{f}</li>
                  ))}
                </ul>
              </article>
            );
          })}
        </div>
      </Section>

      <Section>
        <SectionHeader
          eyebrow="Compare in detail"
          title="What's in each plan, line by line."
          lede="If a row matters to you and is missing here, ask — we'll either explain or add it."
        />
        <table className="compare">
          <thead>
            <tr>
              <th scope="col">Capability</th>
              <th scope="col">Open source</th>
              <th scope="col">Team</th>
              <th scope="col">Enterprise</th>
            </tr>
          </thead>
          <tbody>
            {COMPARISON.map((row) => (
              <tr key={row.capability}>
                <th scope="row">{row.capability}</th>
                <td data-col="Open source">{row.oss}</td>
                <td data-col="Team" className="v-strong">
                  {row.team}
                </td>
                <td data-col="Enterprise">{row.enterprise}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section variant="tight">
        <SectionHeader title="Pricing FAQ" />
        <div className="faq-list">
          {FAQ.map((item) => (
            <div className="faq-item" key={item.q}>
              <details>
                <summary>{item.q}</summary>
                <div className="faq-answer">
                  <p>{item.a}</p>
                </div>
              </details>
            </div>
          ))}
        </div>
      </Section>

      <CtaBanner
        title="Start free. Upgrade when the team grows."
        body="The fastest way to evaluate Identrail is the free risk scan — read-only, ten minutes, real findings against your environment."
        primary={{ label: 'Start a free risk scan', to: '/demo' }}
        secondary={{ label: 'Talk to us about Enterprise', to: '/enterprise' }}
      />
    </>
  );
}
