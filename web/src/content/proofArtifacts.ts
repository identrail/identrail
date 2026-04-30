export type ProofArtifact = {
  label: string;
  href: string;
  external: boolean;
  description: string;
  freshness: string;
};

export const TRUST_PROOF_LINKS: readonly ProofArtifact[] = [
  {
    label: 'Architecture Docs',
    href: 'https://github.com/identrail/identrail/tree/dev/docs',
    external: true,
    description: 'System architecture, deployment patterns, and control boundaries.',
    freshness: 'Updated monthly'
  },
  {
    label: 'Read-Only Scan Model',
    href: '/docs',
    external: false,
    description: 'Permission scope and data access constraints for collection connectors.',
    freshness: 'Policy tracked'
  },
  {
    label: 'Sample Risk Report',
    href: '/demo',
    external: false,
    description: 'Example findings with path evidence, severity, and remediation sequence.',
    freshness: 'Redacted sample'
  },
  {
    label: 'Changelog',
    href: 'https://github.com/identrail/identrail/releases',
    external: true,
    description: 'Release cadence and shipped platform improvements.',
    freshness: 'Versioned'
  },
  {
    label: 'Responsible Disclosure',
    href: '/security',
    external: false,
    description: 'Security issue reporting process and response expectations.',
    freshness: 'Maintained'
  }
] as const;
