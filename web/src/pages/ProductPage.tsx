import { PageHero } from '../components/ui/PageHero';
import { ProductHeroVisual } from '../components/ui/HeroVisuals';
import { LinkButton, ArrowLink } from '../components/ui/Button';
import { ArrowRightIcon, GitHubIcon, GraphIcon, ShieldIcon, CheckIcon } from '../components/ui/Icon';
import { Pill } from '../components/ui/Pill';
import { Section, SectionHeader } from '../components/ui/Section';
import { CtaBanner } from '../components/CtaBanner';
import { GITHUB_REPO, STACK } from '../siteConfig';

const PILLARS = [
  {
    eyebrow: 'Trust graph',
    title: 'A single graph of every machine identity and every path it can take.',
    body:
      'Identrail ingests IAM principals, role chains, OIDC trust policies, Kubernetes service accounts, RBAC bindings and resource ACLs across every environment you connect, then resolves the closure: who can reach what, through which hops, under which conditions.',
    bullets: [
      'Cross-account AssumeRole resolution',
      'OIDC federation through GitHub Actions, EKS, GKE',
      'Conditional policies (PrincipalTag, source IP, MFA) honoured',
      'Workload identity → cloud identity stitching'
    ]
  },
  {
    eyebrow: 'Detection',
    title: 'Severity tied to what an identity can actually reach.',
    body:
      'A "high severity" finding only counts when the path resolves to data, money or control. Identrail prioritises by reachable resource sensitivity, not by signature counts, and explains each score with the exact chain it scored.',
    bullets: [
      'Path-grounded severity, not heuristic',
      'Detections shipped as inspectable rules in OSS repo',
      'False-positive feedback closes the loop in the same UI',
      'Suppression rules scoped to identity + path, not detection ID'
    ]
  },
  {
    eyebrow: 'Simulation',
    title: 'See the smallest safe fix before you ship it.',
    body:
      'Every recommendation runs through a policy simulator that replays recent activity against the proposed change. You see exactly which workloads — by name — would have lost access, and you can scope the fix down until none do.',
    bullets: [
      'Policy diff with annotated impact',
      'Workload-named blast radius, not just resource counts',
      'Dry-run, canary, enforce — three rollout gates',
      'Rollback is one click and reverses cleanly'
    ]
  },
  {
    eyebrow: 'Operator surface',
    title: 'A console designed for the people who actually own the resource.',
    body:
      'Findings route to the resource owner, not into a security queue. The operator surface is the same trust graph the security team sees — so the conversation is "we both look at the same path" instead of "let me forward you a CSV."',
    bullets: [
      'Auto-derived ownership from tags, repos, namespaces',
      'Per-finding playbook with the safe fix pre-staged',
      'Slack, email, GitHub PR — no extra dashboard to learn',
      'Audit trail of who saw what, who fixed what, when'
    ]
  }
];

export function ProductPage() {
  return (
    <>
      <PageHero
        eyebrow="Product"
        title={
          <h1>
            One platform for machine identity
            <br />
            <span style={{ color: 'var(--text-muted)' }}>discovery, detection and rollout-safe control.</span>
          </h1>
        }
        lede="Identrail does the three things every team is currently stitching together with scripts and CSVs: see every identity, prioritise the ones that can reach something dangerous, and remediate without breaking production."
        visual={<ProductHeroVisual />}
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
        <SectionHeader
          eyebrow="The four pillars"
          title="What's actually inside Identrail."
          lede="Each pillar maps to a real subsystem in the open-source repo. Click through to the source if you want to see how a specific control is implemented."
        />
        <div className="stack stack-12">
          {PILLARS.map((p, i) => (
            <article
              key={p.eyebrow}
              className="card card-loose split-card"
            >
              <div>
                <Pill variant="accent">{`0${i + 1} · ${p.eyebrow}`}</Pill>
                <h2 className="t-h3 u-mt-4">{p.title}</h2>
                <p className="t-body u-mt-4">{p.body}</p>
                <div className="u-mt-6">
                  <ArrowLink to={GITHUB_REPO} external>
                    See the implementation
                  </ArrowLink>
                </div>
              </div>
              <ul style={{ listStyle: 'none', padding: 0, display: 'grid', gap: 'var(--space-3)' }}>
                {p.bullets.map((b) => (
                  <li
                    key={b}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '20px 1fr',
                      gap: 'var(--space-3)',
                      alignItems: 'start',
                      paddingBottom: 'var(--space-3)',
                      borderBottom: '1px solid var(--border-subtle)'
                    }}
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
        <SectionHeader
          eyebrow="Stack coverage"
          title="The systems Identrail watches today."
          lede="Each connector is read-only by default. New stacks land in the open-source repo before they ship in the hosted product."
        />
        <div className="grid grid-4">
          {STACK.map((s) => (
            <a
              key={s.id}
              href={s.href}
              target="_blank"
              rel="noopener noreferrer"
              className="card card-tight"
              style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}
            >
              <img src={s.logo} alt="" style={{ width: 28, height: 28, objectFit: 'contain' }} />
              <div>
                <strong>{s.name}</strong>
                <div className="t-muted" style={{ fontSize: 'var(--text-xs)' }}>
                  {s.category}
                </div>
              </div>
            </a>
          ))}
        </div>
      </Section>

      <Section>
        <div className="grid grid-2" style={{ alignItems: 'start' }}>
          <article className="card card-loose">
            <Pill variant="accent">
              <ShieldIcon size={12} /> Read-only by default
            </Pill>
            <h3 className="t-h3 u-mt-4">No write scopes until you explicitly opt in.</h3>
            <p className="t-body u-mt-3">
              Connector setup uses scoped read-only credentials. Policy enforcement is gated behind a separate
              opt-in with named approvers. We can't change something we can't write to.
            </p>
          </article>
          <article className="card card-loose">
            <Pill variant="accent">
              <GraphIcon size={12} /> Self-host the same binary
            </Pill>
            <h3 className="t-h3 u-mt-4">Identical artifact for OSS, hosted, and private tenancy.</h3>
            <p className="t-body u-mt-3">
              We don't run a separate "enterprise" fork. The hosted plan and the self-host run the same image,
              with the same detections, the same simulator, and the same audit log.
            </p>
          </article>
        </div>
      </Section>

      <CtaBanner
        eyebrow="See it on your data"
        title="Connect once. See your first trust path in minutes."
        body="A free scan covers a single AWS account or Kubernetes cluster, returns findings in under ten minutes, and writes nothing back."
        primary={{ label: 'Start a free risk scan', to: '/demo' }}
        secondary={{ label: 'Compare plans', to: '/pricing' }}
      />
    </>
  );
}
