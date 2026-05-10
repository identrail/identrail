import { PageHero } from '../components/ui/PageHero';
import { Section } from '../components/ui/Section';
import { CtaBanner } from '../components/CtaBanner';

type Question = { q: string; a: string };
type Group = { heading: string; items: Question[] };

const GROUPS: Group[] = [
  {
    heading: 'Product basics',
    items: [
      {
        q: 'What does Identrail actually do?',
        a:
          'Identrail builds a single trust graph of every machine identity in your environment — across AWS IAM, Kubernetes, GitHub Actions OIDC, and the data stores those identities can reach. It then surfaces the paths that resolve to sensitive data, ranks them by reachable impact, and shows the smallest safe fix for each one.'
      },
      {
        q: 'Is it open source?',
        a:
          'Yes. The full platform — connectors, graph engine, detection rules, policy simulator — is Apache 2.0 on GitHub. There is no closed core. The hosted Team and Enterprise plans run the same image you can self-host.'
      },
      {
        q: 'How long does the first scan take?',
        a:
          'Under ten minutes for a single AWS account or Kubernetes cluster. First scan returns real findings; we do not require a multi-week onboarding before you see value.'
      }
    ]
  },
  {
    heading: 'Data and security',
    items: [
      {
        q: 'Is the scan really read-only?',
        a:
          'Yes. Connector setup uses scoped read credentials only — you can audit the exact IAM policies in the repo. Policy enforcement is a separate, opt-in surface that you have to deliberately turn on.'
      },
      {
        q: 'What data do you store?',
        a:
          'Trust-graph metadata (identities, role chains, RBAC bindings, resource ARNs), findings, and remediation history. Secret values are hashed at the edge — Identrail never stores raw credential material.'
      },
      {
        q: 'Where is hosted data stored?',
        a:
          'Hosted Team customers pick US (us-east-1) or EU (eu-west-1). Enterprise customers pick a region or run a private single-tenant deployment in any region. Self-host puts the data in your own environment.'
      },
      {
        q: 'How do we delete our data?',
        a:
          'In-app for Team customers, or a single email to security@identrail.com. Deletion completes within 30 days; audit log remains for compliance reasons.'
      }
    ]
  },
  {
    heading: 'Compliance',
    items: [
      {
        q: 'Are you SOC 2 compliant?',
        a:
          'Type I is in progress with Drata, expected to close in H2 2026. Type II follows on the standard observation window. Until then, we are happy to walk through current controls under MNDA.'
      },
      {
        q: 'GDPR?',
        a:
          'EU data residency available; standard contractual clauses and a DPA are available on request.'
      },
      {
        q: 'Have you done a third-party penetration test?',
        a:
          'First test is scheduled before SOC 2 Type I closes. Past code review history is maintained internally and visible to enterprise prospects under MNDA.'
      }
    ]
  },
  {
    heading: 'Pricing and adoption',
    items: [
      {
        q: 'How much does it cost?',
        a:
          'Open-source self-host is free forever. Hosted Team is $19/user/mo (or $15 annual) with a three-user minimum. Enterprise is custom-scoped — see /pricing.'
      },
      {
        q: 'Why is it cheaper than other security tools?',
        a:
          'Because we do not amortise a private platform investment over every seat. The engine is open source. Hosted pricing reflects the genuine ongoing cost of running it for you, not a sales-led ceiling.'
      },
      {
        q: 'Can we start on Open source and migrate to Team later?',
        a:
          'Yes. The data shape is identical — your graph, findings, and history move forward without re-platforming.'
      }
    ]
  }
];

export function FaqPage() {
  return (
    <>
      <PageHero
        eyebrow="FAQ"
        title="Straight answers, no marketing hedge."
        lede="If a question you care about is not here, send it to hello@identrail.com — we will answer and add it."
      />
      <Section variant="tight">
        <div className="stack stack-12">
          {GROUPS.map((group) => (
            <section key={group.heading}>
              <h2 className="t-h3" style={{ marginBottom: 'var(--space-6)' }}>
                {group.heading}
              </h2>
              <div className="faq-list">
                {group.items.map((item) => (
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
            </section>
          ))}
        </div>
      </Section>
      <CtaBanner
        title="Still have questions?"
        primary={{ label: 'Talk to the founder', to: '/demo' }}
        secondary={{ label: 'Email us', to: 'mailto:hello@identrail.com' }}
      />
    </>
  );
}
