export const DOMAIN_ASSET_ORDER = ['aws', 'github', 'kubernetes'] as const;

export type DomainAssetKey = (typeof DOMAIN_ASSET_ORDER)[number];

export type DomainAsset = {
  key: DomainAssetKey;
  label: string;
  shortLabel: string;
  logoSrc: string;
  logoAlt: string;
  officialSourceLabel: string;
  officialSourceUrl: string;
  brandGuidanceUrl: string;
  description: string;
  primaryTone: string;
  darkPanelTone: string;
  accentTone: string;
};

export const DOMAIN_ASSETS: Record<DomainAssetKey, DomainAsset> = {
  aws: {
    key: 'aws',
    label: 'AWS',
    shortLabel: 'AWS',
    logoSrc: '/brand-logos/aws.svg',
    logoAlt: 'AWS logo',
    officialSourceLabel: 'AWS Architecture Icons',
    officialSourceUrl: 'https://aws.amazon.com/architecture/icons/',
    brandGuidanceUrl: 'https://aws.amazon.com/trademark-guidelines/',
    description: 'Cloud accounts, regions, resources, workloads, and machine identities.',
    primaryTone: '#ff9900',
    darkPanelTone: '#080809',
    accentTone: '#f5c451'
  },
  github: {
    key: 'github',
    label: 'GitHub',
    shortLabel: 'GitHub',
    logoSrc: '/brand-logos/github.svg',
    logoAlt: 'GitHub Octomark',
    officialSourceLabel: 'GitHub Brand Toolkit',
    officialSourceUrl: 'https://brand.github.com/foundations/logo',
    brandGuidanceUrl: 'https://docs.github.com/articles/github-logo-policy',
    description: 'Repositories, workflows, code security, agent surfaces, and remediation flow.',
    primaryTone: '#f5f5f5',
    darkPanelTone: '#080809',
    accentTone: '#8b949e'
  },
  kubernetes: {
    key: 'kubernetes',
    label: 'Kubernetes',
    shortLabel: 'K8s',
    logoSrc: '/brand-logos/kubernetes.svg',
    logoAlt: 'Kubernetes logo',
    officialSourceLabel: 'CNCF Kubernetes Artwork',
    officialSourceUrl: 'https://github.com/cncf/artwork/tree/main/projects/kubernetes',
    brandGuidanceUrl: 'https://www.cncf.io/brand-guidelines/',
    description: 'Clusters, service accounts, RBAC, workloads, and runtime identity posture.',
    primaryTone: '#326ce5',
    darkPanelTone: '#080809',
    accentTone: '#7aa2ff'
  }
};

export function getDomainAsset(key: DomainAssetKey): DomainAsset {
  return DOMAIN_ASSETS[key];
}

export function isDomainAssetKey(value: string): value is DomainAssetKey {
  return DOMAIN_ASSET_ORDER.includes(value as DomainAssetKey);
}
