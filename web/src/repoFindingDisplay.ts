import type { Finding as ApiFinding } from './api/client';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const;

export type RepoFindingSortField = 'severity' | 'created_at' | 'type' | 'title';
export type RepoFindingSortOrder = 'asc' | 'desc';

export type RepoFindingDisplayGroup = {
  key: string;
  label: string | null;
  findings: ApiFinding[];
};

export type RepoFindingSelection = Partial<Pick<ApiFinding, 'id' | 'scan_id'>>;

function normalizeDisplayValue(value: unknown): string {
  if (typeof value === 'string') {
    return value.trim();
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value).trim();
  }
  return '';
}

function normalizeSeverityBucket(value: unknown): (typeof SEVERITY_ORDER)[number] {
  const normalized = normalizeDisplayValue(value).toLowerCase();
  if (SEVERITY_ORDER.includes(normalized as (typeof SEVERITY_ORDER)[number])) {
    return normalized as (typeof SEVERITY_ORDER)[number];
  }
  return 'unknown';
}

export function groupRepoFindingsForDisplay(
  findings: ApiFinding[],
  sortBy: RepoFindingSortField,
  sortOrder: RepoFindingSortOrder = 'desc'
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

  const severityBuckets = sortOrder === 'asc' ? [...SEVERITY_ORDER].reverse() : [...SEVERITY_ORDER];

  return severityBuckets.reduce<RepoFindingDisplayGroup[]>((groups, severity) => {
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

export function buildRepoFindingSelectionKey(finding: RepoFindingSelection): string {
  return `${normalizeDisplayValue(finding.scan_id)}::${normalizeDisplayValue(finding.id)}`;
}

export function findRepoFindingBySelectionKey(findings: ApiFinding[], selectionKey: string): ApiFinding | null {
  if (!selectionKey) {
    return null;
  }
  return findings.find((finding) => buildRepoFindingSelectionKey(finding) === selectionKey) ?? null;
}

export function mergeUpdatedRepoFinding(findings: ApiFinding[], updatedFinding: ApiFinding): ApiFinding[] {
  const updatedKey = buildRepoFindingSelectionKey(updatedFinding);
  return findings.map((finding) =>
    buildRepoFindingSelectionKey(finding) === updatedKey ? { ...finding, ...updatedFinding } : finding
  );
}
