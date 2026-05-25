import type { Finding as ApiFinding } from './api/client';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const;

export type RepoFindingSortField = 'severity' | 'created_at' | 'type' | 'title';
export type RepoFindingSortOrder = 'asc' | 'desc';

export type RepoFindingDisplayGroup = {
  key: string;
  label: string | null;
  findings: ApiFinding[];
};

export type RepoFindingDisplaySeverityGroup = {
  key: string;
  label: string;
  findings: ApiFinding[];
};

export type RepoFindingDisplayScanGroup = {
  key: string;
  label: string;
  sortValue: number;
  findings: ApiFinding[];
  severityGroups: RepoFindingDisplaySeverityGroup[];
};

export type RepoFindingDisplayRepositoryGroup = {
  key: string;
  label: string;
  findings: ApiFinding[];
  scanGroups: RepoFindingDisplayScanGroup[];
};

type RepoFindingHierarchyOptions = {
  repositoryForFinding?: (finding: ApiFinding) => string;
  scanDateForFinding?: (finding: ApiFinding) => string;
  scanSortValueForFinding?: (finding: ApiFinding) => number;
  sortBy?: RepoFindingSortField;
  sortOrder?: RepoFindingSortOrder;
};

export type RepoFindingSelection = Partial<
  Pick<
    ApiFinding,
    | 'id'
    | 'scan_id'
    | 'created_at'
    | 'repository'
    | 'type'
    | 'title'
    | 'source_url'
    | 'lifecycle_key'
    | 'file_path'
    | 'line_number'
    | 'detector'
    | 'commit'
    | 'human_summary'
    | 'remediation'
  >
>;

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

function severityRank(value: unknown): number {
  const rank = SEVERITY_ORDER.indexOf(normalizeSeverityBucket(value));
  return rank === -1 ? SEVERITY_ORDER.length : rank;
}

function evidenceRepositoryValue(finding: ApiFinding): string {
  const repository = finding.evidence?.repository;
  return typeof repository === 'string' ? normalizeDisplayValue(repository) : '';
}

function fallbackRepositoryLabel(finding: ApiFinding): string {
  return normalizeDisplayValue(finding.repository) || evidenceRepositoryValue(finding) || 'Repository unavailable';
}

function fallbackScanDateLabel(finding: ApiFinding): string {
  const timestamp =
    normalizeDisplayValue(finding.first_seen_at) ||
    normalizeDisplayValue(finding.created_at) ||
    'Scan date unavailable';
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) {
    return timestamp;
  }
  return parsed.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });
}

function fallbackScanSortValue(finding: ApiFinding): number {
  const timestamp = normalizeDisplayValue(finding.first_seen_at) || normalizeDisplayValue(finding.created_at);
  const parsed = new Date(timestamp);
  return Number.isNaN(parsed.getTime()) ? 0 : parsed.getTime();
}

function findingCreatedAtSortValue(finding: ApiFinding): number {
  const timestamp =
    normalizeDisplayValue(finding.created_at) ||
    normalizeDisplayValue(finding.first_seen_at) ||
    normalizeDisplayValue(finding.last_seen_at);
  const parsed = new Date(timestamp);
  return Number.isNaN(parsed.getTime()) ? 0 : parsed.getTime();
}

function compareTextValue(left: string, right: string, sortOrder: RepoFindingSortOrder): number {
  const leftValue = left.toLowerCase();
  const rightValue = right.toLowerCase();
  if (!leftValue && rightValue) return 1;
  if (leftValue && !rightValue) return -1;
  const compared = leftValue.localeCompare(rightValue);
  return sortOrder === 'asc' ? compared : compared * -1;
}

function compareNumberValue(left: number, right: number, sortOrder: RepoFindingSortOrder): number {
  const compared = left - right;
  return sortOrder === 'asc' ? compared : compared * -1;
}

function compareFindingsBySortField(
  left: ApiFinding,
  right: ApiFinding,
  sortBy: RepoFindingSortField,
  sortOrder: RepoFindingSortOrder
): number {
  if (sortBy === 'severity') {
    const compared = severityRank(left.severity) - severityRank(right.severity);
    if (compared !== 0) {
      return sortOrder === 'asc' ? compared * -1 : compared;
    }
  }

  if (sortBy === 'created_at') {
    const compared = compareNumberValue(findingCreatedAtSortValue(left), findingCreatedAtSortValue(right), sortOrder);
    if (compared !== 0) return compared;
  }

  if (sortBy === 'type') {
    const compared = compareTextValue(normalizeDisplayValue(left.type), normalizeDisplayValue(right.type), sortOrder);
    if (compared !== 0) return compared;
  }

  if (sortBy === 'title') {
    const compared = compareTextValue(normalizeDisplayValue(left.title), normalizeDisplayValue(right.title), sortOrder);
    if (compared !== 0) return compared;
  }

  const severityCompared = severityRank(left.severity) - severityRank(right.severity);
  if (severityCompared !== 0) return severityCompared;

  const createdCompared = compareNumberValue(findingCreatedAtSortValue(left), findingCreatedAtSortValue(right), 'desc');
  if (createdCompared !== 0) return createdCompared;

  const titleCompared = compareTextValue(normalizeDisplayValue(left.title), normalizeDisplayValue(right.title), 'asc');
  if (titleCompared !== 0) return titleCompared;

  return compareTextValue(normalizeDisplayValue(left.id), normalizeDisplayValue(right.id), 'asc');
}

function compareFindingGroupOrder(
  leftFindings: ApiFinding[],
  rightFindings: ApiFinding[],
  compareFindings: (left: ApiFinding, right: ApiFinding) => number
): number {
  const leftTopFinding = leftFindings[0];
  const rightTopFinding = rightFindings[0];
  if (!leftTopFinding && rightTopFinding) return 1;
  if (leftTopFinding && !rightTopFinding) return -1;
  if (!leftTopFinding || !rightTopFinding) return 0;
  return compareFindings(leftTopFinding, rightTopFinding);
}

function stableFallbackFingerprint(values: string[]): string {
  const source = values.join('\u001f');
  let hash = 0x811c9dc5;
  for (let index = 0; index < source.length; index += 1) {
    hash ^= source.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36);
}

export function groupRepoFindingsByRepositoryDateSeverity(
  findings: ApiFinding[],
  options: RepoFindingHierarchyOptions = {}
): RepoFindingDisplayRepositoryGroup[] {
  if (findings.length === 0) {
    return [];
  }

  const sortBy = options.sortBy ?? 'created_at';
  const sortOrder = options.sortOrder ?? 'desc';
  const severityBuckets = sortBy === 'severity' && sortOrder === 'asc' ? [...SEVERITY_ORDER].reverse() : [...SEVERITY_ORDER];
  const compareFindings = (left: ApiFinding, right: ApiFinding) =>
    compareFindingsBySortField(left, right, sortBy, sortOrder);
  const sortDirection = sortOrder === 'asc' ? 1 : -1;
  const repositories = new Map<string, RepoFindingDisplayRepositoryGroup>();
  const scansByRepository = new Map<string, Map<string, RepoFindingDisplayScanGroup>>();

  for (const finding of findings) {
    const repositoryLabel =
      normalizeDisplayValue(options.repositoryForFinding?.(finding)) || fallbackRepositoryLabel(finding);
    const repositoryKey = `repo:${repositoryLabel.toLowerCase()}`;
    let repositoryGroup = repositories.get(repositoryKey);
    if (!repositoryGroup) {
      repositoryGroup = {
        key: repositoryKey,
        label: repositoryLabel,
        findings: [],
        scanGroups: []
      };
      repositories.set(repositoryKey, repositoryGroup);
      scansByRepository.set(repositoryKey, new Map());
    }

    repositoryGroup.findings.push(finding);

    const scanLabel = normalizeDisplayValue(options.scanDateForFinding?.(finding)) || fallbackScanDateLabel(finding);
    const scanSortValue = options.scanSortValueForFinding?.(finding) ?? fallbackScanSortValue(finding);
    const scanKey = `scan:${scanLabel.toLowerCase()}`;
    const repositoryScans = scansByRepository.get(repositoryKey) ?? new Map<string, RepoFindingDisplayScanGroup>();
    let scanGroup = repositoryScans.get(scanKey);
    if (!scanGroup) {
      scanGroup = {
        key: `${repositoryKey}:${scanKey}`,
        label: scanLabel,
        sortValue: scanSortValue,
        findings: [],
        severityGroups: []
      };
      repositoryScans.set(scanKey, scanGroup);
      scansByRepository.set(repositoryKey, repositoryScans);
      repositoryGroup.scanGroups.push(scanGroup);
    }

    scanGroup.sortValue =
      sortOrder === 'asc'
        ? Math.min(scanGroup.sortValue, scanSortValue)
        : Math.max(scanGroup.sortValue, scanSortValue);
    scanGroup.findings.push(finding);
  }

  for (const repositoryGroup of repositories.values()) {
    repositoryGroup.findings.sort(compareFindings);

    for (const scanGroup of repositoryGroup.scanGroups) {
      scanGroup.findings.sort(compareFindings);
    }

    repositoryGroup.scanGroups.sort((left, right) => {
      const findingCompared = compareFindingGroupOrder(left.findings, right.findings, compareFindings);
      if (findingCompared !== 0) {
        return findingCompared;
      }
      if (left.sortValue !== right.sortValue) {
        return (left.sortValue - right.sortValue) * sortDirection;
      }
      return left.label.localeCompare(right.label);
    });

    for (const scanGroup of repositoryGroup.scanGroups) {
      const severityMap = new Map<string, ApiFinding[]>();
      for (const finding of scanGroup.findings) {
        const severity = normalizeSeverityBucket(finding.severity);
        severityMap.set(severity, [...(severityMap.get(severity) ?? []), finding]);
      }
      scanGroup.severityGroups = severityBuckets.reduce<RepoFindingDisplaySeverityGroup[]>((groups, severity) => {
        const severityFindings = severityMap.get(severity);
        if (severityFindings && severityFindings.length > 0) {
          groups.push({
            key: `${scanGroup.key}:severity:${severity}`,
            label: severity,
            findings: severityFindings
          });
        }
        return groups;
      }, []);
    }
  }

  return [...repositories.values()].sort((left, right) => {
    if (left.label === 'Repository unavailable') return 1;
    if (right.label === 'Repository unavailable') return -1;
    const findingCompared = compareFindingGroupOrder(left.findings, right.findings, compareFindings);
    if (findingCompared !== 0) {
      return findingCompared;
    }
    const leftScanSortValue =
      sortOrder === 'asc'
        ? Math.min(...left.scanGroups.map((group) => group.sortValue))
        : Math.max(...left.scanGroups.map((group) => group.sortValue));
    const rightScanSortValue =
      sortOrder === 'asc'
        ? Math.min(...right.scanGroups.map((group) => group.sortValue))
        : Math.max(...right.scanGroups.map((group) => group.sortValue));
    if (leftScanSortValue !== rightScanSortValue) {
      return (leftScanSortValue - rightScanSortValue) * sortDirection;
    }
    const leftHighestSeverity = Math.min(...left.findings.map((finding) => severityRank(finding.severity)));
    const rightHighestSeverity = Math.min(...right.findings.map((finding) => severityRank(finding.severity)));
    if (leftHighestSeverity !== rightHighestSeverity) {
      return leftHighestSeverity - rightHighestSeverity;
    }
    return left.label.localeCompare(right.label);
  });
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
  const scanID = normalizeDisplayValue(finding.scan_id);
  const findingID = normalizeDisplayValue(finding.id);
  if (scanID && findingID) {
    return `${scanID}::${findingID}`;
  }

  const fallbackParts = [
    scanID,
    findingID,
    normalizeDisplayValue(finding.lifecycle_key),
    normalizeDisplayValue(finding.repository),
    normalizeDisplayValue(finding.type),
    normalizeDisplayValue(finding.title),
    normalizeDisplayValue(finding.created_at),
    normalizeDisplayValue(finding.source_url),
    normalizeDisplayValue(finding.file_path),
    normalizeDisplayValue(finding.line_number),
    normalizeDisplayValue(finding.detector),
    normalizeDisplayValue(finding.commit),
    normalizeDisplayValue(finding.human_summary),
    normalizeDisplayValue(finding.remediation)
  ];
  return `partial::${stableFallbackFingerprint(fallbackParts)}`;
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
