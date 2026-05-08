export type TextCard = {
  title: string;
  body: string;
};

export type UseCaseCard = {
  id: string;
  title: string;
  body: string;
  href: string;
};

export type QuoteCard = {
  quote: string;
  author: string;
  role: string;
};

export const heroRailItems = [
  'AWS IAM Roles',
  'Kubernetes Service Accounts',
  'OIDC Trust Policies',
  'CI/CD Machine Tokens',
  'Cross-Account Trust Paths',
  'Repo Secret Exposure',
  'Authorization Rollout Previews',
  'Identity Risk Detections'
];

export const platformCapabilities: TextCard[] = [
  {
    title: 'Identity Discovery Engine',
    body: 'Discover machine identities and trust paths across AWS and Kubernetes in one continuously updated graph.'
  },
  {
    title: 'Risk Intelligence',
    body: 'Detect high-signal machine identity findings with contextual evidence and practical remediation guidance.'
  },
  {
    title: 'Exposure Scanning',
    body: 'Scan repositories and configuration assets for leaked credentials and dangerous trust relationships.'
  },
  {
    title: 'Rollout-Safe Authorization',
    body: 'Apply centralized authorization policies with staged rollout controls to reduce production blast radius.'
  }
];

export const whatWeDoCards: TextCard[] = [
  {
    title: 'Fast, complete machine identity visibility',
    body: 'Identrail maps service accounts, roles, policies, and workload trust paths so teams can quickly understand effective access.'
  },
  {
    title: 'Transform machine identity operations',
    body: 'Unify cloud IAM, Kubernetes, and repository risk workflows in one open-source platform built for security and platform teams.'
  },
  {
    title: 'Continuously enforce least privilege',
    body: 'Prevent access drift with actionable findings and policy rollout controls that are safe for production environments.'
  }
];

export const howWeDoCards: TextCard[] = [
  {
    title: 'Collect identity telemetry',
    body: 'Pull machine identity metadata from AWS, Kubernetes, and source repositories with deterministic ingestion pipelines.'
  },
  {
    title: 'Correlate trust paths',
    body: 'Build an explainable machine identity graph that links principals, policies, actions, resources, and reachable paths.'
  },
  {
    title: 'Control safely',
    body: 'Enforce centralized authorization and remediation playbooks using staged rollout controls to avoid production disruption.'
  }
];

export const impactCards: TextCard[] = [
  {
    title: 'Streamline compliance',
    body: 'Automate machine identity evidence and access attestations so teams can stay audit-ready with less manual work.'
  },
  {
    title: 'Reduce identity risk',
    body: 'Prioritize high-signal findings tied to real machine trust-path exposure and eliminate hidden privilege pathways faster.'
  },
  {
    title: 'Transform identity',
    body: 'Move from fragmented tooling to one open platform for discovery, detection, authorization, and rollout-safe policy controls.'
  }
];

export const useCases: UseCaseCard[] = [
  { id: '01', title: 'Machine Identity Posture Management', body: 'Reveal overprivileged service identities, stale credentials, and risky trust relationships before they are exploited.', href: '/solutions/security-teams' },
  { id: '02', title: 'Cloud Trust Path Analysis', body: 'See exactly who can assume what across AWS accounts and Kubernetes clusters with end-to-end trust path mapping.', href: '/features/trust-graph' },
  { id: '03', title: 'Repository Exposure Monitoring', body: 'Continuously scan source repositories and CI artifacts to catch leaked credentials and machine identity exposure risks.', href: '/features/git-scanner' },
  { id: '04', title: 'Centralized Authorization', body: 'Define authorization intent once and propagate safely across services, cloud resources, and platform control points.', href: '/solutions/platform-engineering' },
  { id: '05', title: 'Agentic AI Identity Governance (Roadmap)', body: 'Define future controls for AI agent access to models, tools, secrets, and infrastructure with delegated-path visibility goals.', href: '/security' },
  { id: '06', title: 'Compliance Evidence Automation', body: 'Generate machine identity access evidence for audits with continuously updated entitlement and policy snapshots.', href: '/docs' }
];

export const whoWeHelpCards: TextCard[] = [
  { title: 'Security Teams', body: 'Triage machine identity attack paths, enforce least privilege, and reduce exposure across hybrid infrastructure.' },
  { title: 'Identity Teams', body: 'Operate machine identity governance with centralized policies and explainable entitlement mapping.' },
  { title: 'Platform Teams', body: 'Roll out safer authorization controls for cloud services and Kubernetes workloads without breaking production.' },
  { title: 'Compliance Teams', body: 'Generate audit-ready machine identity evidence with continuously updated trust path records.' }
];

export const customerLogos = ['FinTech Co', 'Global Bank', 'Cloud Retail', 'Health Systems', 'Payments Group', 'Enterprise SaaS'];

export const customerQuotes: QuoteCard[] = [
  {
    quote: 'Identrail gave us end-to-end visibility across cloud and Kubernetes machine access in under two weeks.',
    author: 'Head of Cloud Security',
    role: 'Global payments company'
  },
  {
    quote: 'We cut machine identity triage time and finally had one reliable graph for trust path decisions.',
    author: 'Director of Identity Engineering',
    role: 'Enterprise software provider'
  },
  {
    quote: 'The rollout-safe policy controls let us move fast without introducing avoidable authorization outages.',
    author: 'Platform Security Lead',
    role: 'Multi-cloud infrastructure team'
  }
];

export const integrations = [
  'AWS',
  'Kubernetes',
  'GitHub',
  'OpenID Connect',
  'Prometheus'
];
