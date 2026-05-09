import { Navigate, useParams } from 'react-router-dom';
import { PageHero } from '../components/ui/PageHero';
import { LinkButton, ArrowLink } from '../components/ui/Button';
import { Section, SectionHeader } from '../components/ui/Section';
import { Pill } from '../components/ui/Pill';
import { ArrowRightIcon, CheckIcon, GitHubIcon, GraphIcon, ShieldIcon } from '../components/ui/Icon';
import { CtaBanner } from '../components/CtaBanner';
import { GITHUB_REPO } from '../siteConfig';

type Solution = {
  audience: string;
  hero: { eyebrow: string; title: string; lede: string };
  pain: { title: string; before: string[]; after: string[] };
  capabilities: { eyebrow: string; title: string; body: string }[];
  closingPrompt: string;
};

const SOLUTIONS: Record<'security-teams' | 'platform-engineering', Solution> = {
  'security-teams': {
    audience: 'Security teams',
    hero: {
      eyebrow: 'For security teams',
      title: 'Spend the queue on what can actually reach something.',
      lede:
        'Identrail gives security teams a single, evidence-grounded view of every machine identity in the environment — and ranks findings by what they can actually reach, not by signature volume.'
    },
    pain: {
      title: 'Before vs. after Identrail.',
      before: [
        'Three dashboards (cloud, K8s, repo) and a CSV export to make them speak.',
        'Findings dropped into a queue with no automatic owner mapping.',
        'No fast answer to "what would break if I tightened this trust policy?"',
        'No way to prove least privilege to an auditor without a screenshot collage.'
      ],
      after: [
        'One trust graph, one severity scoring, one queue with named owners.',
        'Path-grounded severity — "high" means it can reach data, money, or control.',
        'Policy simulator answers blast-radius questions in seconds, with workload names.',
        'Audit-ready evidence packets export with one click.'
      ]
    },
    capabilities: [
      {
        eyebrow: 'Triage',
        title: 'Queue ranked by reachable impact.',
        body:
          'Findings are sorted by what each identity can actually reach — sensitive data, billing, control planes — not by raw detection counts. Most teams cut their open queue by 60–80% in the first week.'
      },
      {
        eyebrow: 'Evidence',
        title: 'Every finding ships with the chain.',
        body:
          'Trust path, JWT claims, IAM trust policy, RBAC binding, last-seen activity. Forwardable to the resource owner without a single follow-up question.'
      },
      {
        eyebrow: 'Audit',
        title: 'Exportable proof of least privilege.',
        body:
          'SOC 2 and ISO auditors want continuous evidence. Identrail emits per-identity entitlement snapshots with a stable schema, ready for evidence collection workflows.'
      }
    ],
    closingPrompt:
      'See your queue ranked by reachable impact. Free read-only scan against one account or cluster, no card.'
  },
  'platform-engineering': {
    audience: 'Platform engineering',
    hero: {
      eyebrow: 'For platform engineering',
      title: 'Tighten machine identity without breaking production.',
      lede:
        'Identrail is built to be operated by the people who actually own the resource — with policy simulation, named blast radius, and rollout gates. So security can ask for the change, and platform can ship it safely.'
    },
    pain: {
      title: 'Before vs. after Identrail.',
      before: [
        'Security tickets land with no context on which workloads will break.',
        'Trust-policy changes get rolled back at 3am because nobody simulated them.',
        'Manual chase to find "who actually owns this role" before changing anything.',
        'Hardening lives in a spreadsheet and slips quarter after quarter.'
      ],
      after: [
        'Every recommendation is pre-simulated against the last 30 days of activity.',
        'Workloads that would lose access are named, not counted.',
        'Ownership is auto-derived from tags, repos, namespaces — no chase.',
        'Dry-run, canary, enforce — three rollout gates with one-click rollback.'
      ]
    },
    capabilities: [
      {
        eyebrow: 'Simulate',
        title: 'See the diff and the impact before you ship.',
        body:
          'Policy diff with annotated impact: which principals would lose which permissions, which workloads would be affected, by name. Scope the change down until the impact is exactly what you intend.'
      },
      {
        eyebrow: 'Stage',
        title: 'Three gates, one rollback button.',
        body:
          'Dry-run records what *would* have happened. Canary applies to a scoped subset. Enforce ships everywhere. Every gate is reversible in one click and reverses cleanly.'
      },
      {
        eyebrow: 'Own',
        title: 'The same trust graph, available to your team.',
        body:
          'Findings route to the resource owner with the safe fix pre-staged. Operators see the same surface security sees — the conversation is "we both look at the same path", not "let me forward you a CSV".'
      }
    ],
    closingPrompt:
      'See how policy simulation behaves on your own workloads. Free read-only scan, no agent, no write scopes.'
  }
};

export function SolutionDetailPage({ slug }: { slug?: string }) {
  const params = useParams<{ audience?: string }>();
  const key = (slug ?? params.audience) as keyof typeof SOLUTIONS | undefined;

  if (!key || !SOLUTIONS[key]) {
    return <Navigate to="/for/security-teams" replace />;
  }

  const s = SOLUTIONS[key];

  return (
    <>
      <PageHero
        eyebrow={s.hero.eyebrow}
        title={s.hero.title}
        lede={s.hero.lede}
        actions={
          <>
            <LinkButton to="/demo" variant="primary" size="lg">
              Start a free risk scan <ArrowRightIcon />
            </LinkButton>
            <LinkButton to={GITHUB_REPO} variant="secondary" size="lg" external>
              <GitHubIcon size={16} /> Read the source
            </LinkButton>
          </>
        }
      />

      <Section>
        <SectionHeader eyebrow="The shift" title={s.pain.title} />
        <div className="grid grid-2">
          <article className="card card-loose">
            <Pill>Before</Pill>
            <ul className="stack stack-3 u-mt-6" style={{ listStyle: 'none', padding: 0 }}>
              {s.pain.before.map((b) => (
                <li
                  key={b}
                  style={{ display: 'grid', gridTemplateColumns: '20px 1fr', gap: 'var(--space-3)' }}
                >
                  <span style={{ color: 'var(--text-faint)', marginTop: 4 }}>—</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{b}</span>
                </li>
              ))}
            </ul>
          </article>
          <article className="card card-loose" style={{ background: 'var(--bg-soft)' }}>
            <Pill variant="accent">After</Pill>
            <ul className="stack stack-3 u-mt-6" style={{ listStyle: 'none', padding: 0 }}>
              {s.pain.after.map((b) => (
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
        </div>
      </Section>

      <Section variant="tight">
        <SectionHeader
          eyebrow="What changes day-to-day"
          title="The three capabilities that matter for this audience."
        />
        <div className="grid grid-3">
          {s.capabilities.map((c, i) => (
            <article key={c.eyebrow} className="card card-loose">
              <Pill variant="accent">
                {i === 0 ? <GraphIcon size={12} /> : i === 1 ? <ShieldIcon size={12} /> : <CheckIcon size={12} />}
                {c.eyebrow}
              </Pill>
              <h3 className="t-h3 u-mt-4">{c.title}</h3>
              <p className="t-body u-mt-3">{c.body}</p>
            </article>
          ))}
        </div>
      </Section>

      <Section variant="tight">
        <div
          className="row-between"
          style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 'var(--space-8)' }}
        >
          <span className="t-eyebrow">Other audiences</span>
          <div className="row">
            {(['security-teams', 'platform-engineering'] as const)
              .filter((k) => k !== key)
              .map((other) => (
                <ArrowLink key={other} to={`/for/${other}`}>
                  For {SOLUTIONS[other].audience.toLowerCase()}
                </ArrowLink>
              ))}
          </div>
        </div>
      </Section>

      <CtaBanner
        title={s.closingPrompt}
        primary={{ label: 'Start a free risk scan', to: '/demo' }}
        secondary={{ label: 'Compare plans', to: '/pricing' }}
      />
    </>
  );
}
