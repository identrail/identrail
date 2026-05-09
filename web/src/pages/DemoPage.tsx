import { FormEvent, useState } from 'react';
import { PageHero } from '../components/ui/PageHero';
import { DemoHeroVisual } from '../components/ui/HeroVisuals';
import { ArrowLink, LinkButton } from '../components/ui/Button';
import { Section } from '../components/ui/Section';
import { CheckIcon } from '../components/ui/Icon';
import { Pill } from '../components/ui/Pill';
import { apiClient } from '../api/client';
import { CALENDLY_URL, CONTRIBUTING_URL, FOUNDER, GITHUB_REPO } from '../siteConfig';

type SubmitState = { kind: 'idle' } | { kind: 'submitting' } | { kind: 'ok' } | { kind: 'error'; message: string };

const SCAN_STEPS = [
  {
    title: 'Connect read-only credentials',
    body:
      'Pick AWS, Kubernetes, or GitHub Actions. We auto-generate a least-privilege IAM role or kubeconfig context. No write scopes are ever requested.'
  },
  {
    title: 'Identrail builds the trust graph',
    body:
      'Identities, role chains, OIDC trust policies, RBAC bindings and resource ACLs are resolved into a single graph. Average scan time: under ten minutes for a single account or cluster.'
  },
  {
    title: 'Get the report',
    body:
      'Findings sorted by reachable resource sensitivity. Each finding includes the path, the evidence, the named owner, and the smallest safe fix — simulated against your last 30 days of activity.'
  }
];

export function DemoPage() {
  const [state, setState] = useState<SubmitState>({ kind: 'idle' });

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setState({ kind: 'submitting' });

    const formData = new FormData(e.currentTarget);
    const email = String(formData.get('email') ?? '').trim();
    const name = String(formData.get('name') ?? '').trim();
    const company = String(formData.get('company') ?? '').trim();
    const role = String(formData.get('role') ?? '').trim();
    const context = String(formData.get('context') ?? '').trim();

    if (!email || !email.includes('@')) {
      setState({ kind: 'error', message: 'Please enter a valid work email address.' });
      return;
    }

    // The visitor's name + role + free-text context goes into `scan_goal`
    // (a real, forwarded lead field). Critically: we do NOT touch the
    // `challenge` field — web/api/leads.ts treats any non-empty `challenge`
    // as a honeypot/bot submission and short-circuits with HTTP 202 without
    // forwarding the lead to the webhook (web/api/leads.ts ~line 228, PR #895).
    //
    // Capped at 600 chars to match server-side MAX_SCAN_GOAL_LENGTH.
    const scanGoal = [
      name ? `From: ${name}${role ? ` (${role})` : ''}` : null,
      context || null
    ]
      .filter(Boolean)
      .join('\n')
      .slice(0, 600);

    try {
      await apiClient.submitLeadCapture({
        email,
        environment: 'demo-form',
        company: company || undefined,
        scan_goal: scanGoal || undefined,
        source: 'demo-page',
        page_path: typeof window !== 'undefined' ? window.location.pathname : '/demo'
      });

      // Best-effort analytics — never block the success state on these.
      if (typeof window !== 'undefined' && typeof window.posthog?.capture === 'function') {
        window.posthog.capture('demo_request_submitted', { source: 'demo-page' });
      }
      if (typeof window !== 'undefined' && typeof window.gtag === 'function') {
        window.gtag('event', 'generate_lead', { method: 'demo_form' });
      }

      setState({ kind: 'ok' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Could not submit just now. Please try again.';
      setState({ kind: 'error', message });
    }
  }

  return (
    <>
      <PageHero
        eyebrow="Demo · Free risk scan"
        title={
          <h1>
            See your first machine-identity trust path
            <br />
            <span style={{ color: 'var(--text-muted)' }}>in under ten minutes.</span>
          </h1>
        }
        lede="Two ways in. Talk to the founder for a guided walkthrough, or run a free read-only scan against your environment and skip the meeting."
        visual={<DemoHeroVisual />}
      />

      <Section variant="tight">
        <div className="grid grid-2" style={{ alignItems: 'start' }}>
          <article className="card card-loose">
            <Pill variant="accent" dot>
              Self-serve · Free
            </Pill>
            <h2 className="t-h3 u-mt-4">Run a free risk scan.</h2>
            <p className="t-body u-mt-3">
              No card. No demo call required. Read-only scan of one AWS account or one Kubernetes cluster, returns
              a real finding report you can share with your team.
            </p>
            <ol className="stack stack-6 u-mt-8" style={{ listStyle: 'none', padding: 0 }}>
              {SCAN_STEPS.map((s, i) => (
                <li
                  key={s.title}
                  style={{ display: 'grid', gridTemplateColumns: '36px 1fr', gap: 'var(--space-4)' }}
                >
                  <span
                    style={{
                      width: 36,
                      height: 36,
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
                    0{i + 1}
                  </span>
                  <div>
                    <strong>{s.title}</strong>
                    <p className="t-muted u-mt-2" style={{ fontSize: 'var(--text-sm)' }}>
                      {s.body}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
            <div className="card-foot">
              <p>
                Prefer self-host? The same scan ships in the{' '}
                <a href={GITHUB_REPO} target="_blank" rel="noopener noreferrer">
                  open-source
                </a>{' '}
                repo. <a href={CONTRIBUTING_URL} target="_blank" rel="noopener noreferrer">Contributing</a>.
              </p>
            </div>
          </article>

          <div>
            <article className="form-card">
              <span className="t-eyebrow">Talk to the founder</span>
              <h2 className="t-h3 u-mt-3">Book a 15-minute walkthrough.</h2>
              <p className="t-body u-mt-3">
                {FOUNDER.shortName} runs every demo personally right now. Bring a stack diagram if you have
                one — we'll use it.
              </p>

              <form className="form u-mt-8" onSubmit={onSubmit}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="name">Name</label>
                    <input id="name" name="name" type="text" autoComplete="name" required />
                  </div>
                  <div className="field">
                    <label htmlFor="email">Work email</label>
                    <input id="email" name="email" type="email" autoComplete="email" required />
                  </div>
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="company">Company</label>
                    <input id="company" name="company" type="text" autoComplete="organization" required />
                  </div>
                  <div className="field">
                    <label htmlFor="role">Role</label>
                    <input
                      id="role"
                      name="role"
                      type="text"
                      placeholder="Platform eng, security, …"
                      required
                    />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="context">What are you trying to figure out?</label>
                  <textarea id="context" name="context" placeholder="One or two sentences is plenty." />
                </div>
                <div className="form-foot">
                  <p className="field-help">We reply within one business day.</p>
                  <LinkButton to={CALENDLY_URL} variant="ghost" size="sm" external>
                    Or pick a slot directly
                  </LinkButton>
                </div>
                <button
                  className="btn btn-primary btn-lg btn-block"
                  type="submit"
                  disabled={state.kind === 'submitting' || state.kind === 'ok'}
                >
                  {state.kind === 'submitting' ? 'Sending…' : state.kind === 'ok' ? 'Got it — talk soon' : 'Request a demo'}
                </button>
                {state.kind === 'ok' ? (
                  <div className="form-status" role="status">
                    <CheckIcon size={14} /> Thanks — we'll be in touch shortly.
                  </div>
                ) : null}
                {state.kind === 'error' ? (
                  <div className="form-status is-error" role="status">
                    {state.message}
                  </div>
                ) : null}
              </form>
            </article>
          </div>
        </div>
      </Section>

      <Section variant="tight">
        <div className="grid grid-3">
          <article className="tile">
            <strong>Read-only by design</strong>
            <p className="t-muted u-mt-2" style={{ fontSize: 'var(--text-sm)' }}>
              Connector setup uses scoped read credentials. Nothing is mutated unless you explicitly enable
              enforcement later.
            </p>
          </article>
          <article className="tile">
            <strong>No agent</strong>
            <p className="t-muted u-mt-2" style={{ fontSize: 'var(--text-sm)' }}>
              No long-running daemon in your environment. Scans run from our infrastructure or from your own
              when you self-host.
            </p>
          </article>
          <article className="tile">
            <strong>Your data stays yours</strong>
            <p className="t-muted u-mt-2" style={{ fontSize: 'var(--text-sm)' }}>
              You can revoke connector access at any moment. Findings export cleanly and can be deleted on
              request.
            </p>
          </article>
        </div>
        <div className="u-mt-8 row">
          <ArrowLink to="/security">Read the security and compliance posture</ArrowLink>
        </div>
      </Section>
    </>
  );
}
