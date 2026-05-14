import { describe, expect, it } from 'vitest';
import type { Finding as ApiFinding } from './api/client';
import { buildRepoFindingSelectionKey, findRepoFindingBySelectionKey, groupRepoFindingsForDisplay } from './repoFindingDisplay';

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

  it('selects findings by scan id and finding id together', () => {
    const first = finding('shared-id', 'high');
    const second = { ...finding('shared-id', 'low'), scan_id: 'scan-2', title: 'scan-2 finding' };
    const findings = [first, second];

    const selected = findRepoFindingBySelectionKey(findings, buildRepoFindingSelectionKey(second));

    expect(selected?.scan_id).toBe('scan-2');
    expect(selected?.title).toBe('scan-2 finding');
  });
});
