import { afterEach, describe, expect, it, vi } from 'vitest';
import { IDENTRAIL_CLOUD_API_URL, apiClient, buildQuery, mergeRequestHeaders, resolveAPIBaseURL } from './client';

describe('buildQuery', () => {
  it('encodes defined query params only', () => {
    const query = buildQuery({
      scan_id: 'scan-1',
      severity: 'high',
      include_archived: true,
      empty: '',
      missing: undefined
    });
    expect(query).toBe('?scan_id=scan-1&severity=high&include_archived=true');
  });
});

describe('resolveAPIBaseURL', () => {
  it('uses the configured API URL when one is provided', () => {
    expect(resolveAPIBaseURL(' https://api.example.com ', true, 'identrail.com')).toBe('https://api.example.com');
  });

  it('uses the Identrail Cloud API default for canonical production hosts', () => {
    for (const hostname of ['identrail.com', 'www.identrail.com', 'app.identrail.com']) {
      expect(resolveAPIBaseURL(undefined, true, hostname)).toBe(IDENTRAIL_CLOUD_API_URL);
    }
  });

  it('requires explicit configuration for custom production hosts', () => {
    expect(resolveAPIBaseURL(undefined, true, 'customer.example.com')).toBe('');
  });

  it('uses localhost for unconfigured development builds', () => {
    expect(resolveAPIBaseURL(undefined, false, 'localhost')).toBe('http://localhost:8080');
  });
});

describe('apiClient', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('builds findings URL with filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listFindings(
      {
        scan_id: 'scan-1',
        severity: 'high',
        type: 'risky_trust_policy',
        lifecycle_status: 'ack',
        assignee: 'platform'
      },
      { apiKey: 'reader' }
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/findings?scan_id=scan-1&severity=high&type=risky_trust_policy&lifecycle_status=ack&assignee=platform'
    );
    const headers = new Headers(options.headers);
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('x-api-key')).toBe('reader');
  });

  it('uses default scan listing sort contract', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listScans({ apiKey: 'reader' });
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/scans?sort_by=started_at&sort_order=desc');
  });

  it('uses default repo scan listing sort contract', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listRepoScans({}, { apiKey: 'reader' });
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/repo-scans?sort_by=started_at&sort_order=desc');
  });

  it('encodes scan id for diff URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({})
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getScanDiff('scan/id with space', 20, { apiKey: 'reader' });
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/scans/scan%2Fid%20with%20space/diff?limit=20');
  });

  it('adds baseline scan query when provided', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({})
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getScanDiff('scan-2', 20, { apiKey: 'reader' }, 'scan-1');
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/scans/scan-2/diff?limit=20&previous_scan_id=scan-1');
  });

  it('sends enterprise tenant/workspace scope headers when configured', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listScans({
      apiKey: ' reader ',
      tenantID: ' tenant-a ',
      workspaceID: ' workspace-a '
    });

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(options.headers);
    expect(headers.get('x-api-key')).toBe('reader');
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace-a');
  });

  it('merges override headers from tuple arrays and Headers', () => {
    const tupleMerged = mergeRequestHeaders({ apiKey: 'reader' }, [['X-Trace-ID', 'trace-1']]);
    expect(tupleMerged.get('x-api-key')).toBe('reader');
    expect(tupleMerged.get('x-trace-id')).toBe('trace-1');

    const headerOverrides = new Headers({ Authorization: 'Bearer test-token', 'X-API-Key': 'override' });
    const headersMerged = mergeRequestHeaders({ apiKey: 'reader' }, headerOverrides);
    expect(headersMerged.get('authorization')).toBe('Bearer test-token');
    expect(headersMerged.get('x-api-key')).toBe('override');
  });

  it('surfaces backend error envelope message', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: 'unauthorized' })
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiClient.getFindingsSummary({ apiKey: 'reader' })).rejects.toThrow('unauthorized');
  });

  it('requests finding triage history with scan scope', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listFindingHistory('finding-1', 'scan-1', 15, { apiKey: 'reader' });

    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/findings/finding-1/history?scan_id=scan-1&limit=15');
  });

  it('builds repo findings URL with filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listRepoFindings(
      {
        repo_scan_id: 'repo-scan-1',
        severity: 'high',
        type: 'secret_exposure'
      },
      { apiKey: 'reader' }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/repo-findings?sort_by=created_at&sort_order=desc&repo_scan_id=repo-scan-1&severity=high&type=secret_exposure');
    const headers = new Headers(options.headers);
    expect(headers.get('x-api-key')).toBe('reader');
  });

  it('sends triage patch payload for finding workflow actions', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ finding: { id: 'finding-1' } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.triageFinding(
      'finding-1',
      { status: 'ack', assignee: 'platform', comment: 'acknowledged' },
      'scan-1',
      { apiKey: 'writer' }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/findings/finding-1/triage?scan_id=scan-1');
    expect(options.method).toBe('PATCH');
    expect(options.body).toBe(JSON.stringify({ status: 'ack', assignee: 'platform', comment: 'acknowledged' }));
  });

  it('posts workspace member invite/update payload and includes scoped headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ member: { member_id: 'member-user-a' } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.upsertWorkspaceMember(
      'workspace-a',
      {
        member_id: 'member-user-a',
        user_id: 'user-a',
        email: 'user-a@example.com',
        role: 'admin',
        status: 'active'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace-a/members');
    expect(options.method).toBe('POST');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace-a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('follows next_cursor when listing workspace members', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          items: [
            {
              tenant_id: 'tenant-a',
              workspace_id: 'workspace-a',
              member_id: 'member-a',
              user_id: 'user-a',
              role: 'owner',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            }
          ],
          next_cursor: 'cursor-2'
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          items: [
            {
              tenant_id: 'tenant-a',
              workspace_id: 'workspace-a',
              member_id: 'member-b',
              user_id: 'user-b',
              role: 'viewer',
              status: 'invited',
              joined_at: '2026-01-02T00:00:00Z',
              updated_at: '2026-01-02T00:00:00Z'
            }
          ]
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    const response = await apiClient.listWorkspaceMembers(
      'workspace-a',
      { limit: 1 },
      { tenantID: 'tenant-a', workspaceID: 'workspace-a' }
    );

    expect(response.items).toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstURL] = fetchMock.mock.calls[0] as [string];
    const [secondURL] = fetchMock.mock.calls[1] as [string];
    expect(firstURL).toContain('/v1/workspaces/workspace-a/members?limit=1');
    expect(secondURL).toContain('/v1/workspaces/workspace-a/members?limit=1&cursor=cursor-2');
  });

  it('lists workspace projects with archive filters and scoped headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listProjects(
      'workspace/a',
      {
        limit: 25,
        sort_by: 'updated_at',
        sort_order: 'desc',
        include_archived: true
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects?limit=25&sort_by=updated_at&sort_order=desc&include_archived=true'
    );
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('posts workspace project payload and encodes the target workspace id', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ project: { project_id: 'project-1' } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.upsertProject(
      'workspace/a',
      {
        project_id: 'project-1',
        name: 'Project 1',
        slug: 'project-1',
        description: 'Production boundary'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace%2Fa/projects');
    expect(options.method).toBe('POST');
    expect(options.body).toBe(
      JSON.stringify({
        project_id: 'project-1',
        name: 'Project 1',
        slug: 'project-1',
        description: 'Production boundary'
      })
    );
  });

  it('lists and upserts project scan policies with scoped headers', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ items: [] })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ policy: { policy_id: 'default' } })
      });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listProjectScanPolicies(
      'workspace/a',
      'project 1',
      { trigger_mode: 'scheduled', enabled: true, limit: 10, sort_by: 'updated_at', sort_order: 'desc' },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );
    await apiClient.upsertProjectScanPolicy(
      'workspace/a',
      'project 1',
      {
        policy_id: 'default',
        name: 'Default policy',
        trigger_mode: 'scheduled',
        cron: '0 * * * *',
        max_concurrent_scans: 2,
        history_limit: 300,
        max_findings: 120
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [listURL, listOptions] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(listURL).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/scan-policies?trigger_mode=scheduled&enabled=true&limit=10&sort_by=updated_at&sort_order=desc'
    );
    const listHeaders = new Headers(listOptions.headers);
    expect(listHeaders.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(listHeaders.get('x-identrail-workspace-id')).toBe('workspace/a');

    const [upsertURL, upsertOptions] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(upsertURL).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/scan-policies');
    expect(upsertOptions.method).toBe('POST');
    expect(upsertOptions.body).toBe(
      JSON.stringify({
        policy_id: 'default',
        name: 'Default policy',
        trigger_mode: 'scheduled',
        cron: '0 * * * *',
        max_concurrent_scans: 2,
        history_limit: 300,
        max_findings: 120
      })
    );
  });

  it('supports 204 no-content workspace member removal responses', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 204,
      json: async () => ({})
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      apiClient.deleteWorkspaceMember('workspace-a', 'member-a', {
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a'
      })
    ).resolves.toBeUndefined();

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace-a/members/member-a');
    expect(options.method).toBe('DELETE');
  });

  it('supports project scan policy deletion responses', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 204,
      json: async () => ({})
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      apiClient.deleteProjectScanPolicy('workspace-a', 'project-1', 'default', {
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a'
      })
    ).resolves.toBeUndefined();

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace-a/projects/project-1/scan-policies/default');
    expect(options.method).toBe('DELETE');
  });

  it('posts project source connector payloads with scoped headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ connection: { provider: 'aws', connected: true } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.upsertAWSProjectConnection(
      'workspace/a',
      'project 1',
      {
        role_arn: 'arn:aws:iam::123456789012:role/IdentrailReadOnly',
        external_id: 'external-prod',
        region: 'us-east-1'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/connection');
    expect(options.method).toBe('POST');
    expect(options.body).toBe(
      JSON.stringify({
        role_arn: 'arn:aws:iam::123456789012:role/IdentrailReadOnly',
        external_id: 'external-prod',
        region: 'us-east-1'
      })
    );
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });
});
