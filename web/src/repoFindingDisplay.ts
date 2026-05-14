import type { Finding as ApiFinding } from './api/client';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const;

export type RepoFindingSortField = 'severity' | 'created_at' | 'type' | 'title';

export type RepoFindingDisplayGroup = {
  key: string;
  label: string | null;
  findings: ApiFinding[];
};

function normalizeSeverityBucket(value: string): (typeof SEVERITY_ORDER)[number] {
  const normalized = value.trim().toLowerCase();
  if (SEVERITY_ORDER.includes(normalized as (typeof SEVERITY_ORDER)[number])) {
    return normalized as (typeof SEVERITY_ORDER)[number];
  }
  return 'unknown';
}

export function groupRepoFindingsForDisplay(
  findings: ApiFinding[],
  sortBy: RepoFindingSortField
): RepoFindingDisplayGroup[] {
  if (findings.length === 0) {
    return [];
  }
  if (sortBy !== 'severity') {
    return [{ key: sortBy, label: null, findings }];
  }

  const buckets: Partial<Record<(typeof SEVERITY_ORDER)[number], ApiFinding[]>> = {};
  for (const finding of findings) {
    const bucket = normalizeSeverityBucket(finding.severity);
    const bucketFindings = buckets[bucket] ?? [];
    bucketFindings.push(finding);
    buckets[bucket] = bucketFindings;
  }

  return SEVERITY_ORDER.reduce<RepoFindingDisplayGroup[]>((groups, severity) => {
    const bucketFindings = buckets[severity];
    if (bucketFindings && bucketFindings.length > 0) {
      groups.push({
        key: severity,
        label: severity,
        findings: bucketFindings
      });
    }
    return groups;
  }, []);
}
