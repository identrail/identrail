import { PageHero } from '../components/ui/PageHero';
import { ArrowLink, LinkButton } from '../components/ui/Button';
import { ArrowRightIcon } from '../components/ui/Icon';
import { Pill } from '../components/ui/Pill';
import { Section, SectionHeader } from '../components/ui/Section';
import { CtaBanner } from '../components/CtaBanner';
import { GITHUB_REPO, STACK, type StackEntry } from '../siteConfig';

type Integration = StackEntry & {
  status: 'GA' | 'Beta' | 'Roadmap';
  notes: string;
};

const INTEGRATIONS: Integration[] = [
  ...STACK.map((s): Integration => {
    switch (s.id) {
      case 'aws':
        return {
          ...s,
          status: 'GA',
          notes: 'IAM roles, policies, trust relationships, AssumeRole chains, Identity Center, federated principals.'
        };
      case 'kubernetes':
        return {
          ...s,
          status: 'GA',
          notes: 'Service accounts, role/clusterrole bindings, pod-to-SA mapping, workload identity federation (EKS/GKE).'
        };
      case 'github':
        return {
          ...s,
          status: 'GA',
          notes: 'GitHub Actions OIDC stitching, environment trust policies, repo-level permission graphs.'
        };
      case 'oidc':
        return {
          ...s,
          status: 'GA',
          notes: 'Generic OIDC issuer ingestion. JWT claim resolution into target trust policies.'
        };
      case 'terraform':
        return {
          ...s,
          status: 'Beta',
          notes: 'Plan-time analysis: identifies trust-policy diffs against the live graph before apply.'
        };
      case 'docker':
        return {
          ...s,
          status: 'GA',
          notes: 'Image registry credentials, build-time identity resolution, Docker Hub OIDC.'
        };
      case 'postgres':
        return {
          ...s,
          status: 'GA',
          notes: 'Resource-side reachability: catalogs tables/schemas reachable through resolved identity paths.'
        };
      case 'prometheus':
        return {
          ...s,
          status: 'GA',
          notes: 'Emits scan timing, finding counts, severity distribution, and connector health metrics.'
        };
      default:
        return { ...s, status: 'GA', notes: 'Stack integration.' };
    }
  }),
  {
    id: 'gcp',
    name: 'Google Cloud IAM',
    logo: '/brand-logos/aws.svg', // placeholder until a GCP logo is added
    href: 'https://cloud.google.com/iam',
    category: 'Cloud IAM',
    status: 'Roadmap',
    notes: 'Service accounts, workload identity federation, organisation policy resolution. Tracking issue in repo.'
  },
  {
    id: 'azure',
    name: 'Azure AD / Entra',
    logo: '/brand-logos/aws.svg', // placeholder until an Entra logo is added
    href: 'https://learn.microsoft.com/entra/identity/',
    category: 'Cloud IAM',
    status: 'Roadmap',
    notes: 'Managed identities, federated credentials, role assignments, conditional access for service principals.'
  },
  {
    id: 'vault',
    name: 'HashiCorp Vault',
    logo: '/brand-logos/aws.svg', // placeholder until a Vault logo is added
    href: 'https://www.vaultproject.io/',
    category: 'Identity provider',
    status: 'Roadmap',
    notes: 'AWS auth backend mapping, Kubernetes auth backend mapping, dynamic credential issuance into the graph.'
  }
];

const STATUS_VARIANT: Record<Integration['status'], 'success' | 'warning' | 'neutral'> = {
  GA: 'success',
  Beta: 'warning',
  Roadmap: 'neutral'
};

export function IntegrationsPage() {
  return (
    <>
      <PageHero
        eyebrow="Integrations"
        title="Every system Identrail watches today."
        lede="Each connector is read-only by default. New integrations land in the open-source repo first, then in the hosted product. Need a stack we don't list yet? Open an issue or talk to us - we prioritise based on real demand."
        actions={
          <>
            <LinkButton to="/demo" variant="primary" size="lg">
              Start a free risk scan <ArrowRightIcon />
            </LinkButton>
            <LinkButton to={GITHUB_REPO} variant="secondary" size="lg" external>
              View connectors on GitHub
            </LinkButton>
          </>
        }
      />

      <Section variant="tight">
        <div className="grid grid-2">
          {INTEGRATIONS.map((i) => (
            <article key={i.id} className="card card-loose">
              <div
                className="row-between"
                style={{ alignItems: 'flex-start', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}
              >
                <div
                  className="row"
                  style={{ gap: 'var(--space-3)', flexWrap: 'nowrap' }}
                >
                  <img
                    src={i.logo}
                    alt=""
                    style={{
                      width: 36,
                      height: 36,
                      objectFit: 'contain',
                      padding: 4,
                      background: 'var(--bg-soft)',
                      borderRadius: 'var(--radius-sm)'
                    }}
                  />
                  <div>
                    <strong style={{ fontSize: 'var(--text-lg)' }}>{i.name}</strong>
                    <div className="t-muted" style={{ fontSize: 'var(--text-xs)' }}>
                      {i.category}
                    </div>
                  </div>
                </div>
                <Pill variant={STATUS_VARIANT[i.status]} dot>
                  {i.status}
                </Pill>
              </div>
              <p className="t-body" style={{ fontSize: 'var(--text-sm)' }}>
                {i.notes}
              </p>
              <div className="card-foot">
                <ArrowLink to={i.href} external>
                  Vendor docs
                </ArrowLink>
              </div>
            </article>
          ))}
        </div>
      </Section>

      <Section variant="tight">
        <SectionHeader
          eyebrow="Don't see your stack?"
          title="Tell us what to build next."
          lede="Connector priority is set publicly in the repo. Upvote what you need or open a new issue with your use case."
        />
        <div className="row">
          <LinkButton to={`${GITHUB_REPO}/issues`} variant="secondary" external>
            Browse / open issues
          </LinkButton>
          <LinkButton to="/demo" variant="ghost">
            Talk to the founder
          </LinkButton>
        </div>
      </Section>

      <CtaBanner
        title="See the connector graph for your environment."
        body="A free read-only scan returns the trust paths your stack actually exposes today, not what a brochure claims."
        primary={{ label: 'Start a free risk scan', to: '/demo' }}
      />
    </>
  );
}
