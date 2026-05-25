import { describe, expect, it } from 'vitest';
import type { Finding as ApiFinding } from './api/client';
import {
  buildRepoFindingSelectionKey,
  findRepoFindingBySelectionKey,
  groupRepoFindingsByRepositoryDateSeverity,
  groupRepoFindingsForDisplay,
  mergeUpdatedRepoFinding
} from './repoFindingDisplay';

function finding(id: string, severity: string): ApiFinding {
  return {
    id,
    scan_id: 'scan-1',
    type: 'secret_exposure',
    severity,
    title: id,
    human_summary: `${id} summary`,
    remediation: 'rotate the secret',
    created_at: '2026-05-14T00:00:00Z'
  };
}

describe('groupRepoFindingsForDisplay', () => {
  it('preserves API order for non-severity sorts', () => {
    const findings = [finding('medium-newest', 'medium'), finding('critical-older', 'critical'), finding('low-oldest', 'low')];

    const groups = groupRepoFindingsForDisplay(findings, 'created_at');

    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({ key: 'created_at', label: null });
    expect(groups[0].findings.map((item) => item.id)).toEqual(['medium-newest', 'critical-older', 'low-oldest']);
  });

  it('groups severity sort in descending severity buckets', () => {
    const findings = [finding('medium-item', 'medium'), finding('unknown-item', 'unexpected'), finding('critical-item', 'critical')];

    const groups = groupRepoFindingsForDisplay(findings, 'severity');

    expect(groups.map((group) => group.key)).toEqual(['critical', 'medium', 'unknown']);
    expect(groups[0].findings.map((item) => item.id)).toEqual(['critical-item']);
    expect(groups[1].findings.map((item) => item.id)).toEqual(['medium-item']);
    expect(groups[2].findings.map((item) => item.id)).toEqual(['unknown-item']);
  });

  it('groups severity sort in ascending severity buckets when requested', () => {
    const findings = [finding('medium-item', 'medium'), finding('unknown-item', 'unexpected'), finding('critical-item', 'critical')];

    const groups = groupRepoFindingsForDisplay(findings, 'severity', 'asc');

    expect(groups.map((group) => group.key)).toEqual(['unknown', 'medium', 'critical']);
    expect(groups[0].findings.map((item) => item.id)).toEqual(['unknown-item']);
    expect(groups[1].findings.map((item) => item.id)).toEqual(['medium-item']);
    expect(groups[2].findings.map((item) => item.id)).toEqual(['critical-item']);
  });

  it('keeps partial finding records in the unknown severity bucket', () => {
    const partialFinding = { ...finding('missing-severity', 'high'), severity: undefined } as unknown as ApiFinding;

    const groups = groupRepoFindingsForDisplay([partialFinding], 'severity');

    expect(groups.map((group) => group.key)).toEqual(['unknown']);
    expect(groups[0].findings.map((item) => item.id)).toEqual(['missing-severity']);
  });

  it('creates stable and unique fallback keys when selection identifiers are missing', () => {
    const firstPartialFinding = {
      ...finding('placeholder-1', 'high'),
      id: undefined,
      scan_id: undefined,
      title: 'Partial finding one',
      created_at: '2026-01-01T00:00:00Z'
    } as unknown as ApiFinding;
    const secondPartialFinding = {
      ...finding('placeholder-2', 'medium'),
      id: undefined,
      scan_id: undefined,
      title: 'Partial finding two',
      created_at: '2026-01-02T00:00:00Z'
    } as unknown as ApiFinding;

    const firstKey = buildRepoFindingSelectionKey(firstPartialFinding);
    const secondKey = buildRepoFindingSelectionKey(secondPartialFinding);
    const refreshedFirstKey = buildRepoFindingSelectionKey({ ...firstPartialFinding });

    expect(firstKey).toBe(buildRepoFindingSelectionKey(firstPartialFinding));
    expect(refreshedFirstKey).toBe(firstKey);
    expect(secondKey).toBe(buildRepoFindingSelectionKey(secondPartialFinding));
    expect(firstKey).not.toBe(secondKey);
  });

  it('finds refreshed fallback records by deterministic selection key', () => {
    const partialFinding = {
      ...finding('placeholder-1', 'high'),
      id: undefined,
      scan_id: undefined,
      title: 'Partial finding one',
      repository: 'owner/repo',
      file_path: '.github/workflows/deploy.yml',
      line_number: 42,
      created_at: '2026-01-01T00:00:00Z'
    } as unknown as ApiFinding;

    const selectionKey = buildRepoFindingSelectionKey(partialFinding);
    const refreshedFinding = { ...partialFinding };

    expect(buildRepoFindingSelectionKey(refreshedFinding)).toBe(selectionKey);
    expect(findRepoFindingBySelectionKey([refreshedFinding], selectionKey)?.title).toBe('Partial finding one');
  });

  it('selects findings by scan id and finding id together', () => {
    const first = finding('shared-id', 'high');
    const second = { ...finding('shared-id', 'low'), scan_id: 'scan-2', title: 'scan-2 finding' };
    const findings = [first, second];

    const selected = findRepoFindingBySelectionKey(findings, buildRepoFindingSelectionKey(second));

    expect(selected?.scan_id).toBe('scan-2');
    expect(selected?.title).toBe('scan-2 finding');
  });

  it('merges workflow updates only into the matching scan and finding pair', () => {
    const first = finding('shared-id', 'high');
    const second = { ...finding('shared-id', 'low'), scan_id: 'scan-2', title: 'scan-2 finding' };

    const merged = mergeUpdatedRepoFinding([first, second], {
      ...second,
      title: 'updated second finding',
      repository: 'owner/repo-b'
    });

    expect(merged[0].title).toBe(first.title);
    expect(merged[0].scan_id).toBe(first.scan_id);
    expect(merged[1].title).toBe('updated second finding');
    expect(merged[1].repository).toBe('owner/repo-b');
    expect(merged[1].scan_id).toBe('scan-2');
  });
});

describe('groupRepoFindingsByRepositoryDateSeverity', () => {
  it('groups findings by repository, scan date, and severity', () => {
    const findings = [
      {
        ...finding('repo-b-medium', 'medium'),
        repository: 'owner/repo-b',
        created_at: '2026-05-14T00:00:00Z'
      },
      {
        ...finding('repo-a-critical', 'critical'),
        repository: 'owner/repo-a',
        created_at: '2026-05-15T00:00:00Z'
      },
      {
        ...finding('repo-a-high', 'high'),
        repository: 'owner/repo-a',
        created_at: '2026-05-15T01:00:00Z'
      }
    ];

    const groups = groupRepoFindingsByRepositoryDateSeverity(findings, {
      scanDateForFinding: (item) => (item.repository === 'owner/repo-b' ? 'May 14, 2026' : 'May 15, 2026'),
      scanSortValueForFinding: (item) => new Date(item.created_at).getTime(),
      sortBy: 'severity'
    });

    expect(groups.map((group) => group.label)).toEqual(['owner/repo-a', 'owner/repo-b']);
    expect(groups[0].findings.map((item) => item.id)).toEqual(['repo-a-critical', 'repo-a-high']);
    expect(groups[0].scanGroups).toHaveLength(1);
    expect(groups[0].scanGroups[0].label).toBe('May 15, 2026');
    expect(groups[0].scanGroups[0].severityGroups.map((group) => group.label)).toEqual(['critical', 'high']);
    expect(groups[1].scanGroups[0].severityGroups.map((group) => group.label)).toEqual(['medium']);
  });

  it('keeps unknown severities last for descending triage order', () => {
    const groups = groupRepoFindingsByRepositoryDateSeverity(
      [
        { ...finding('unknown-item', 'unexpected'), repository: 'owner/repo' },
        { ...finding('critical-item', 'critical'), repository: 'owner/repo' }
      ],
      {
        scanDateForFinding: () => 'May 15, 2026',
        scanSortValueForFinding: () => 1
      }
    );

    expect(groups[0].scanGroups[0].severityGroups.map((group) => group.label)).toEqual(['critical', 'unknown']);
  });

  it('puts repositories with the newest scans before alphabetic order', () => {
    const groups = groupRepoFindingsByRepositoryDateSeverity(
      [
        { ...finding('alpha-older', 'critical'), repository: 'alpha/repo', created_at: '2026-05-24T00:00:00Z' },
        { ...finding('zeta-newer', 'high'), repository: 'zeta/repo', created_at: '2026-05-25T00:00:00Z' }
      ],
      {
        scanDateForFinding: (item) => (item.repository === 'alpha/repo' ? 'May 24, 2026' : 'May 25, 2026'),
        scanSortValueForFinding: (item) => new Date(item.created_at).getTime()
      }
    );

    expect(groups.map((group) => group.label)).toEqual(['zeta/repo', 'alpha/repo']);
  });

  it('honors ascending order when ranking repositories by scan date', () => {
    const groups = groupRepoFindingsByRepositoryDateSeverity(
      [
        { ...finding('alpha-older', 'critical'), repository: 'alpha/repo', created_at: '2026-05-24T00:00:00Z' },
        { ...finding('zeta-newer', 'high'), repository: 'zeta/repo', created_at: '2026-05-25T00:00:00Z' }
      ],
      {
        scanDateForFinding: (item) => (item.repository === 'alpha/repo' ? 'May 24, 2026' : 'May 25, 2026'),
        scanSortValueForFinding: (item) => new Date(item.created_at).getTime(),
        sortOrder: 'asc'
      }
    );

    expect(groups.map((group) => group.label)).toEqual(['alpha/repo', 'zeta/repo']);
  });

  it('honors ascending order when ranking scan groups inside a repository', () => {
    const groups = groupRepoFindingsByRepositoryDateSeverity(
      [
        { ...finding('newer-scan', 'critical'), repository: 'owner/repo', created_at: '2026-05-25T00:00:00Z' },
        { ...finding('older-scan', 'high'), repository: 'owner/repo', created_at: '2026-05-24T00:00:00Z' }
      ],
      {
        scanDateForFinding: (item) => (item.id === 'older-scan' ? 'May 24, 2026' : 'May 25, 2026'),
        scanSortValueForFinding: (item) => new Date(item.created_at).getTime(),
        sortOrder: 'asc'
      }
    );

    expect(groups[0].scanGroups.map((group) => group.label)).toEqual(['May 24, 2026', 'May 25, 2026']);
  });

  it('honors severity sort when ranking repository groups', () => {
    const groups = groupRepoFindingsByRepositoryDateSeverity(
      [
        { ...finding('newer-high', 'high'), repository: 'alpha/repo', created_at: '2026-05-25T00:00:00Z' },
        { ...finding('older-critical', 'critical'), repository: 'zeta/repo', created_at: '2026-05-24T00:00:00Z' }
      ],
      {
        scanDateForFinding: (item) => (item.repository === 'alpha/repo' ? 'May 25, 2026' : 'May 24, 2026'),
        scanSortValueForFinding: (item) => new Date(item.created_at).getTime(),
        sortBy: 'severity',
        sortOrder: 'desc'
      }
    );

    expect(groups.map((group) => group.label)).toEqual(['zeta/repo', 'alpha/repo']);
  });

  it('honors title sort when ranking repository and scan groups', () => {
    const groups = groupRepoFindingsByRepositoryDateSeverity(
      [
        {
          ...finding('newer-zulu', 'critical'),
          repository: 'zeta/repo',
          title: 'Zulu workflow issue',
          created_at: '2026-05-25T00:00:00Z'
        },
        {
          ...finding('older-alpha', 'high'),
          repository: 'alpha/repo',
          title: 'Alpha token exposure',
          created_at: '2026-05-24T00:00:00Z'
        },
        {
          ...finding('same-repo-beta', 'medium'),
          repository: 'alpha/repo',
          title: 'Beta database secret',
          created_at: '2026-05-23T00:00:00Z'
        }
      ],
      {
        scanDateForFinding: (item) => {
          if (item.id === 'same-repo-beta') return 'May 23, 2026';
          return item.repository === 'alpha/repo' ? 'May 24, 2026' : 'May 25, 2026';
        },
        scanSortValueForFinding: (item) => new Date(item.created_at).getTime(),
        sortBy: 'title',
        sortOrder: 'asc'
      }
    );

    expect(groups.map((group) => group.label)).toEqual(['alpha/repo', 'zeta/repo']);
    expect(groups[0].scanGroups.map((group) => group.label)).toEqual(['May 24, 2026', 'May 23, 2026']);
  });

  it('sorts findings inside severity lanes by the selected field', () => {
    const groups = groupRepoFindingsByRepositoryDateSeverity(
      [
        { ...finding('zulu-item', 'high'), repository: 'owner/repo', title: 'Zulu secret' },
        { ...finding('alpha-item', 'high'), repository: 'owner/repo', title: 'Alpha secret' }
      ],
      {
        scanDateForFinding: () => 'May 25, 2026',
        scanSortValueForFinding: () => 1,
        sortBy: 'title',
        sortOrder: 'asc'
      }
    );

    expect(groups[0].scanGroups[0].severityGroups[0].findings.map((item) => item.id)).toEqual([
      'alpha-item',
      'zulu-item'
    ]);
  });
});
