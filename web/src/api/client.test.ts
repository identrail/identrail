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

  it('starts scans through the authenticated scan endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ scan: { id: 'scan-1' } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.startScan({ tenantID: 'tenant-a', workspaceID: 'workspace-a' });
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/scans');
    expect(options.method).toBe('POST');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace-a');
  });

  it('starts scans with optional project and connector scope', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ scan: { id: 'scan-1' } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.startScan(
      { project_id: 'project-a', connector_id: 'aws-project-a' },
      { tenantID: 'tenant-a', workspaceID: 'workspace-a' }
    );
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(options.method).toBe('POST');
    expect(options.body).toBe(JSON.stringify({ project_id: 'project-a', connector_id: 'aws-project-a' }));
  });

  it('keeps auth headers when an empty scan payload is passed with auth', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ scan: { id: 'scan-1' } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.startScan({}, { tenantID: 'tenant-a', workspaceID: 'workspace-a' });
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(options.method).toBe('POST');
    expect(options.body).toBeUndefined();
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace-a');
  });

  it('persists onboarding state through server endpoints', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ state: { current_step: 'workspace' } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.startOnboarding();
    await apiClient.getOnboardingState();
    await apiClient.updateOnboardingState({ current_step: 'org', org_name: 'Acme Security' });
    await apiClient.completeOnboarding();

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect((fetchMock.mock.calls[0] as [string, RequestInit])[0]).toContain('/v1/onboarding/start');
    expect((fetchMock.mock.calls[1] as [string, RequestInit])[0]).toContain('/v1/onboarding/state');
    const [, updateOptions] = fetchMock.mock.calls[2] as [string, RequestInit];
    expect(updateOptions.method).toBe('POST');
    expect(updateOptions.body).toBe(JSON.stringify({ current_step: 'org', org_name: 'Acme Security' }));
    expect((fetchMock.mock.calls[3] as [string, RequestInit])[0]).toContain('/v1/onboarding/complete');
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

  it('queues repository scans with the scoped auth headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        repo_scan: {
          id: 'repo-scan-1',
          repository: 'identrail/identrail',
          status: 'queued',
          started_at: '2026-05-17T10:00:00Z',
          commits_scanned: 0,
          files_scanned: 0,
          finding_count: 0,
          truncated: false
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.runRepoScan(
      { repository: 'identrail/identrail', history_limit: 50, max_findings: 100 },
      { tenantID: 'tenant-a', workspaceID: 'workspace-a' }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/repo-scans');
    expect(options.method).toBe('POST');
    expect(options.body).toBe(
      JSON.stringify({ repository: 'identrail/identrail', history_limit: 50, max_findings: 100 })
    );
    const headers = options.headers as Headers;
    expect(headers.get('X-Identrail-Tenant-ID')).toBe('tenant-a');
    expect(headers.get('X-Identrail-Workspace-ID')).toBe('workspace-a');
  });

  it('preserves API error code and detail for repository scan diagnostics', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({
        error: 'failed to enqueue repo scan',
        error_code: 'repo_scan_migration_missing',
        error_detail: 'Repository scan persistence failed; the hosted database may be missing migrations.'
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiClient.runRepoScan({ repository: 'identrail/identrail' })).rejects.toMatchObject({
      name: 'ApiError',
      message: 'failed to enqueue repo scan',
      status: 500,
      code: 'repo_scan_migration_missing',
      detail: 'Repository scan persistence failed; the hosted database may be missing migrations.'
    });
  });

  it('cancels repository scans with the scoped auth headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        repo_scan: {
          id: 'repo-scan-1',
          repository: 'identrail/identrail',
          status: 'failed',
          started_at: '2026-05-17T10:00:00Z',
          finished_at: '2026-05-17T10:01:00Z',
          commits_scanned: 0,
          files_scanned: 0,
          finding_count: 0,
          truncated: false,
          error_message: 'repository scan canceled by user'
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.cancelRepoScan('repo/scan with space', { tenantID: 'tenant-a', workspaceID: 'workspace-a' });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/repo-scans/repo%2Fscan%20with%20space/cancel');
    expect(options.method).toBe('POST');
    const headers = options.headers as Headers;
    expect(headers.get('X-Identrail-Tenant-ID')).toBe('tenant-a');
    expect(headers.get('X-Identrail-Workspace-ID')).toBe('workspace-a');
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
        type: 'secret_exposure',
        source: 'github_secret_scanning',
        min_confidence: 0.8
      },
      { apiKey: 'reader' }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/repo-findings?sort_by=created_at&sort_order=desc&repo_scan_id=repo-scan-1&severity=high&type=secret_exposure&source=github_secret_scanning&min_confidence=0.8'
    );
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

  it('gets and verifies AWS project baseline gate with scoped headers', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ baseline: { status: 'not_run', checks: [] } })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ baseline: { status: 'ready', checks: [] } })
      });
    vi.stubGlobal('fetch', fetchMock);

    const auth = {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    };

    await apiClient.getAWSProjectBaseline('workspace/a', 'project 1', 'aws-prod', auth);
    await apiClient.verifyAWSProjectBaseline('workspace/a', 'project 1', { connector_id: 'aws-prod' }, auth);

    const [getURL, getOptions] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(getURL).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/baseline?connector_id=aws-prod');
    expect(getOptions.method ?? 'GET').toBe('GET');

    const [postURL, postOptions] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(postURL).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/baseline');
    expect(postOptions.method).toBe('POST');
    expect(postOptions.body).toBe(JSON.stringify({ connector_id: 'aws-prod' }));
    const headers = new Headers(postOptions.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS project dependency index with scoped headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ index: { status: 'ready', issue_count: 85, checks: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectDependencyIndex('workspace/a', 'project 1', 'aws-prod', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/dependency-index?connector_id=aws-prod');
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS project validation harness with scoped headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ harness: { status: 'ready', scenario_count: 6, scenarios: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectValidationHarness('workspace/a', 'project 1', 'aws-prod', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/validation-harness?connector_id=aws-prod');
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS project collector contract with scoped headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ contract: { status: 'ready', required_field_count: 17, fixture_cases: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectCollectorContract('workspace/a', 'project 1', 'aws-prod', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/collector-contract?connector_id=aws-prod');
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS EC2 instance profile inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 2, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectEC2InstanceProfiles('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/ec2-instance-profiles?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS ECS task role inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 2, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectECSTaskRoles('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/ecs-task-roles?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS Lambda execution role inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 2, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectLambdaExecutionRoles('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/lambda-execution-roles?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS CodeBuild service role inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 2, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectCodeBuildServiceRoles('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/codebuild-service-roles?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS event-driven role inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 3, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectEventDrivenRoles('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/event-driven-roles?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS managed compute role inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 9, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectManagedComputeRoles('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/managed-compute-roles?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS SageMaker workload role inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 8, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectSageMakerWorkloadRoles('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/sagemaker-workload-roles?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS IAM PassRole relationship inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 5, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectIAMPassRoleRelationships('workspace/a', 'project 1', 'aws-prod', 'degraded', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/iam-passrole-relationships?connector_id=aws-prod&fixture_state=degraded'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS S3 bucket reachability inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', bucket_count: 4, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectS3BucketReachability('workspace/a', 'project 1', 'aws-prod', 'degraded', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/s3-bucket-reachability?connector_id=aws-prod&fixture_state=degraded'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS KMS decrypt reachability inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', key_count: 5, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectKMSDecryptReachability('workspace/a', 'project 1', 'aws-prod', 'degraded', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/kms-decrypt-reachability?connector_id=aws-prod&fixture_state=degraded'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS credential references inventory with scoped headers, fixture state, and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', reference_count: 5, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectCredentialReferences(
      'workspace/a',
      'project 1',
      'aws-prod',
      'partial_failure',
      { resourceType: 'lambda_function', identity: 'summarizer', provider: 'openai' },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/credential-references?connector_id=aws-prod&fixture_state=partial_failure&resource_type=lambda_function&identity=summarizer&provider=openai'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS coverage plan with scoped headers, fixture state, and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ plan: { status: 'ready', summary: { total_targets: 6 }, targets: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectCoveragePlan(
      'workspace/a',
      'project 1',
      'aws-prod',
      'partial_failure',
      { account: '111111111111', region: 'us-east-1', service: 'iam', state: 'failed' },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/coverage-plan?connector_id=aws-prod&fixture_state=partial_failure&account=111111111111&region=us-east-1&service=iam&state=failed'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS Organizations topology with scoped headers, fixture state, and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ topology: { status: 'ready', summary: { account_count: 4 }, accounts: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectOrganizationsTopology(
      'workspace/a',
      'project 1',
      'aws-prod',
      'partial_failure',
      { account: '111111111111', ou: '/Production', state: 'failed', status: 'active' },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/organizations-topology?connector_id=aws-prod&fixture_state=partial_failure&account=111111111111&ou=%2FProduction&state=failed&status=active'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS StackSet onboarding with scoped headers, fixture state, and deployment mode', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        onboarding: {
          status: 'ready',
          summary: { total_instances: 6, active_instances: 2 },
          instances: [],
          validation: { status: 'ready' }
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectStackSetOnboarding(
      'workspace/a',
      'project 1',
      'aws-prod',
      'partial_failure',
      { deploymentMode: 'self_managed' },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/stackset-onboarding?connector_id=aws-prod&fixture_state=partial_failure&deployment_mode=self_managed'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS Bedrock Agents inventory with scoped headers, fixture state, and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        inventory: {
          status: 'ready',
          agent_count: 2,
          filtered_agent_count: 2,
          records: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectBedrockAgents(
      'workspace/a',
      'project 1',
      'aws-prod',
      'partial_failure',
      { agentID: 'PAYMENTSAGENT1', identity: 'payments', provider: 'amazon-bedrock' },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/bedrock-agents?connector_id=aws-prod&fixture_state=partial_failure&agent_id=PAYMENTSAGENT1&identity=payments&provider=amazon-bedrock'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS runtime events with scoped headers, fixture state, and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        runtime: {
          status: 'ready',
          event_count: 2,
          filtered_event_count: 2,
          records: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectRuntimeEvents(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'partial_failure',
        eventType: 'agent-tool',
        identity: 'payments',
        agentID: 'PAYMENTSAGENT1',
        resource: 'arn:aws:s3:::payments-prod',
        evidence: 'cloudtrail',
        owner: 'security',
        status: 'observed'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/runtime-events?connector_id=aws-prod&fixture_state=partial_failure&event_type=agent-tool&identity=payments&agent_id=PAYMENTSAGENT1&resource=arn%3Aaws%3As3%3A%3A%3Apayments-prod&evidence=cloudtrail&owner=security&status=observed'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS least privilege recommendations with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        recommendations: {
          status: 'ready',
          summary: {
            total_recommendations: 1,
            filtered_recommendations: 1
          },
          recommendations: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectLeastPrivilege(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'lambda-invoice-agent',
        resource: 'prod/ai/openai-key',
        service: 'secretsmanager',
        severity: 'high',
        status: 'review',
        decision: 'remove'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/least-privilege?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=lambda-invoice-agent&resource=prod%2Fai%2Fopenai-key&service=secretsmanager&severity=high&status=review&decision=remove'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS unused dormant access findings with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        findings: {
          status: 'ready',
          summary: {
            total_findings: 1,
            filtered_findings: 1
          },
          findings: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectUnusedDormantAccess(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'lambda-invoice-agent',
        resource: 'prod/ai/openai-key',
        service: 'secretsmanager',
        severity: 'high',
        status: 'cleanup_candidate',
        dormancyState: 'never_used'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/unused-dormant-access?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=lambda-invoice-agent&resource=prod%2Fai%2Fopenai-key&service=secretsmanager&severity=high&status=cleanup_candidate&dormancy_state=never_used'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS identity sprawl findings with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        findings: {
          status: 'ready',
          summary: { total_findings: 0, filtered_findings: 0 },
          findings: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectIdentitySprawl(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'payments-lambda-execution',
        owner: 'platform',
        cluster: 'duplicate_role_signature',
        findingType: 'stale_identity',
        severity: 'medium',
        status: 'review'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/identity-sprawl?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=payments-lambda-execution&owner=platform&cluster=duplicate_role_signature&finding_type=stale_identity&severity=medium&status=review'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS privilege escalation findings with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        findings: {
          status: 'ready',
          summary: { total_findings: 0, filtered_findings: 0 },
          findings: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectPrivilegeEscalation(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'security-admin',
        target: '*',
        escalationType: 'passrole_unscoped_trust_path',
        severity: 'critical',
        status: 'action_required'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/privilege-escalation?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=security-admin&target=*&escalation_type=passrole_unscoped_trust_path&severity=critical&status=action_required'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS cross-account trust findings with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        findings: {
          status: 'ready',
          summary: { total_findings: 0, filtered_findings: 0 },
          findings: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectCrossAccountTrust(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        service: 'kms',
        principal: 'partner-ingest',
        resource: 'partner-feed',
        findingType: 'cross_account_resource_access',
        severity: 'high',
        status: 'review',
        ou: 'Security'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/cross-account-trust?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&service=kms&principal=partner-ingest&resource=partner-feed&finding_type=cross_account_resource_access&severity=high&status=review&ou=Security'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS secret-permission equivalence findings with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        findings: {
          status: 'ready',
          summary: { total_findings: 0, filtered_findings: 0 },
          findings: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectSecretPermissionEquivalence(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'case-triage-runtime',
        secret: 'openai/api-key',
        provider: 'openai',
        equivalenceType: 'agent_provider_key_equivalence',
        evidence: 'runtime-backed',
        search: 'role',
        severity: 'high',
        status: 'review'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/secret-permission-equivalence?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=case-triage-runtime&secret=openai%2Fapi-key&provider=openai&equivalence_type=agent_provider_key_equivalence&evidence=runtime-backed&search=role&severity=high&status=review'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS AI agent risk findings with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        findings: {
          status: 'ready',
          summary: { total_findings: 0, filtered_findings: 0 },
          findings: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectAIAgentRisk(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        agentID: 'support-assistant',
        riskType: 'external_credential_exposure',
        evidence: 'runtime-backed',
        search: 'anthropic',
        severity: 'high',
        status: 'review'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/ai-agent-risk?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&agent_id=support-assistant&risk_type=external_credential_exposure&severity=high&status=review&evidence=runtime-backed&search=anthropic'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS remediation cases with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        cases: {
          status: 'ready',
          summary: { total_cases: 0, filtered_cases: 0 },
          cases: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectRemediationCases(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'case-triage',
        sourceType: 'ai_agent_risk',
        lifecycle: 'in_review',
        severity: 'high',
        status: 'action_required',
        approvalState: 'pending_owner',
        ownerAssigned: 'false',
        search: 'rotation'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/remediation-cases?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=case-triage&source_type=ai_agent_risk&lifecycle=in_review&severity=high&status=action_required&approval_state=pending_owner&owner_assigned=false&search=rotation'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS IAM policy least-privilege diffs with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        diffs: {
          status: 'ready',
          summary: { total_diffs: 0, filtered_diffs: 0 },
          diffs: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectIAMPolicyDiffs(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'data-loader',
        service: 's3',
        decision: 'remove',
        severity: 'high',
        status: 'action_required',
        breakageLevel: 'low',
        readyForApply: 'true',
        search: 's3:DeleteObject'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/iam-policy-diffs?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=data-loader&service=s3&decision=remove&severity=high&status=action_required&breakage_level=low&ready_for_apply=true&search=s3%3ADeleteObject'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS trust policy hardening plans with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        plans: {
          status: 'ready',
          summary: { total_plans: 0, filtered_plans: 0 },
          plans: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectTrustPolicyHardeningPlans(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        service: 'iam',
        resource: 'payments-cross-account',
        principal: 'billing-runner',
        hardeningDirection: 'add_org_or_source_condition',
        breakageLevel: 'low',
        severity: 'high',
        status: 'action_required',
        readyForApply: 'true',
        search: 'sts:ExternalId'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/trust-policy-hardening?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&service=iam&resource=payments-cross-account&principal=billing-runner&hardening_direction=add_org_or_source_condition&breakage_level=low&severity=high&status=action_required&ready_for_apply=true&search=sts%3AExternalId'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS permission boundary and SCP plans with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        plans: {
          status: 'ready',
          summary: { total_plans: 0, filtered_plans: 0 },
          plans: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectPermissionBoundarySCPPlans(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        service: 's3',
        kind: 'permission_boundary',
        targetScope: 'identity',
        severity: 'high',
        status: 'action_required',
        breakageLevel: 'low',
        readyForApply: 'true',
        search: 's3:DeleteObject'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/permission-boundary-scp?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&service=s3&kind=permission_boundary&target_scope=identity&severity=high&status=action_required&breakage_level=low&ready_for_apply=true&search=s3%3ADeleteObject'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS secret/key rotation plans with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        plans: {
          status: 'ready',
          summary: { total_plans: 0, filtered_plans: 0 },
          plans: []
        }
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectSecretKeyRotationPlans(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        rotationType: 'provider_key',
        provider: 'openai',
        owner: 'appsec',
        severity: 'high',
        status: 'action_required',
        readyForApply: 'true',
        search: 'rotation_re_evaluate'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/secret-key-rotation?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&rotation_type=provider_key&provider=openai&owner=appsec&severity=high&status=action_required&ready_for_apply=true&search=rotation_re_evaluate'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS access key quarantine plans with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ plans: { status: 'ready', plans: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectAccessKeyQuarantinePlans(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'orders-ci',
        quarantineState: 'quarantine_candidate',
        owner: 'orders-platform',
        severity: 'high',
        status: 'ready_for_quarantine',
        readyForApply: 'true',
        search: 'quarantine_re_evaluate'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/access-key-quarantine?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=orders-ci&quarantine_state=quarantine_candidate&owner=orders-platform&severity=high&status=ready_for_quarantine&ready_for_apply=true&search=quarantine_re_evaluate'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS IaC remediation PR plans with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ plans: { status: 'ready', plans: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectIaCRemediationPlans(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        identity: 'orders-ci',
        iacTarget: 'terraform',
        changeKind: 'iam_policy_diff',
        severity: 'high',
        status: 'ready_for_apply',
        readyForApply: 'true',
        search: 'terraform validate'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/iac-remediation-plans?connector_id=aws-prod&fixture_state=success&account_id=123456789012&region=us-east-1&identity=orders-ci&iac_target=terraform&change_kind=iam_policy_diff&severity=high&status=ready_for_apply&ready_for_apply=true&search=terraform+validate'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS remediation approval queue with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ queue: { status: 'ready', entries: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectRemediationApprovalQueue(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        caseID: 'aws-remediation-case:orders-ci',
        state: 'requested',
        riskTier: 'high',
        scopeType: 'identity',
        requestor: 'orders-platform',
        approverRole: 'security-reviewer',
        severity: 'high',
        readyForExecution: 'false',
        killSwitchEngaged: 'false',
        search: 'remediation_kill_switch'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/remediation-approval-queue?');
    expect(url).toContain('connector_id=aws-prod');
    expect(url).toContain('risk_tier=high');
    expect(url).toContain('approver_role=security-reviewer');
    expect(url).toContain('kill_switch_engaged=false');
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS remediation dry-run with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ dry_run: { status: 'ready', entries: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectRemediationDryRun(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        approvalID: 'aws-remediation-approval:orders-ci',
        caseID: 'aws-remediation-case:orders-ci',
        sourceType: 'least_privilege',
        outcome: 'would_succeed',
        riskTier: 'medium',
        severity: 'medium',
        search: 'PutRolePolicy'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/remediation-dry-run?');
    expect(url).toContain('source_type=least_privilege');
    expect(url).toContain('outcome=would_succeed');
    expect(url).toContain('risk_tier=medium');
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS low-risk live remediation with scoped headers and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ low_risk_live_remediation: { status: 'ready', entries: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectLowRiskLiveRemediation(
      'workspace/a',
      'project 1',
      {
        connectorID: 'aws-prod',
        fixtureState: 'success',
        accountID: '123456789012',
        region: 'us-east-1',
        dryRunID: 'aws-remediation-dry-run:orders-ci',
        caseID: 'aws-remediation-case:orders-ci',
        action: 'iam:UpdateAccessKey',
        actionCategory: 'approved_disable',
        state: 'projected',
        severity: 'low',
        search: 'allowlist'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/workspace%2Fa/projects/project%201/aws/low-risk-live-remediation?');
    expect(url).toContain('action_category=approved_disable');
    expect(url).toContain('state=projected');
    expect(url).toContain('action=iam%3AUpdateAccessKey');
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS Secrets Manager metadata inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', secret_count: 3, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectSecretsManagerMetadata('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/secrets-manager-metadata?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS SSM parameter metadata inventory with scoped headers, fixture state, and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', parameter_count: 3, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectSSMParameterMetadata(
      'workspace/a',
      'project 1',
      'aws-prod',
      'partial_failure',
      { parameterType: 'secure_string', identity: 'payments-deployer' },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/ssm-parameter-metadata?connector_id=aws-prod&fixture_state=partial_failure&parameter_type=secure_string&identity=payments-deployer'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS ECR repository metadata inventory with scoped headers, fixture state, and filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', repository_count: 3, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectECRRepositoryMetadata(
      'workspace/a',
      'project 1',
      'aws-prod',
      'partial_failure',
      { repositoryName: 'payments/api', identity: 'payments-service' },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace/a',
        bearerToken: 'token-a'
      }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/ecr-repository-metadata?connector_id=aws-prod&fixture_state=partial_failure&repository_name=payments%2Fapi&identity=payments-service'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });

  it('gets AWS EKS workload identity inventory with scoped headers and fixture state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ inventory: { status: 'ready', record_count: 2, records: [] } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getAWSProjectEKSWorkloadIdentities('workspace/a', 'project 1', 'aws-prod', 'partial_failure', {
      tenantID: 'tenant-a',
      workspaceID: 'workspace/a',
      bearerToken: 'token-a'
    });

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/v1/workspaces/workspace%2Fa/projects/project%201/aws/eks-workload-identities?connector_id=aws-prod&fixture_state=partial_failure'
    );
    expect(options.method ?? 'GET').toBe('GET');
    const headers = new Headers(options.headers);
    expect(headers.get('x-identrail-tenant-id')).toBe('tenant-a');
    expect(headers.get('x-identrail-workspace-id')).toBe('workspace/a');
    expect(headers.get('authorization')).toBe('Bearer token-a');
  });
});
