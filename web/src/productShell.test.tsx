import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  AWSConnectionStatus,
  CurrentUserContext,
  Finding,
  GitHubConnectionStatus,
  RepoScanRecord
} from './api/client';
import type { BackendFeatureState } from './hooks/useBackendFeatures';

const loggedInWithoutWorkspace: CurrentUserContext = {
  user: {
    id: 'user-1',
    primary_email: 'owner@example.com',
    display_name: 'Owner User',
    status: 'active',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  }
};

async function renderProductIndexRedirect(featureEnabled: boolean, backendOnboarding: BackendFeatureState) {
  vi.resetModules();
  vi.doMock('./hooks/useMe', () => ({
    useMe: () => ({
      me: loggedInWithoutWorkspace,
      loading: false,
      error: '',
      unauthenticated: false,
      refresh: vi.fn()
    })
  }));
  vi.doMock('./pages/onboarding/onboardingUtils', () => ({
    FEATURE_ONBOARDING_WIZARD: featureEnabled,
    FEATURE_ONBOARDING_CONNECTOR_AWS: false,
    FEATURE_ONBOARDING_CONNECTOR_GITHUB: false,
    FEATURE_ONBOARDING_CONNECTOR_K8S: false
  }));
  vi.doMock('./hooks/useBackendFeatures', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./hooks/useBackendFeatures')>();
    return {
      ...actual,
      useBackendFeatures: () => ({
        features: {
          onboardingWizard: backendOnboarding,
          connectors: { github: undefined, aws: undefined, kubernetes: undefined },
          configReachable: true
        },
        loading: false
      })
    };
  });

  const { ProductAppIndexRedirect } = await import('./productShell');

  render(
    <MemoryRouter initialEntries={['/app']}>
      <Routes>
        <Route path="/app" element={<ProductAppIndexRedirect />} />
        <Route path="/onboarding/org" element={<h1>Start onboarding</h1>} />
      </Routes>
    </MemoryRouter>
  );
}

const disconnectedAWS: AWSConnectionStatus = {
  provider: 'aws',
  connected: false,
  status: 'pending',
  health_status: 'unknown',
  external_id_configured: false,
  permission_checks: [],
  diagnostics: [],
  capabilities: { requested: ['discovery'], validated: ['discovery'], effective: ['discovery'], unavailable: [] }
};

const connectedGitHub: GitHubConnectionStatus = {
  provider: 'github_app',
  connected: true,
  connector_id: 'github-app',
  display_name: 'Identrail',
  status: 'active',
  health_status: 'healthy',
  account_login: 'identrail',
  installation_id: 12345,
  webhook_secret_rotation_required: false,
  selected_repositories: ['identrail/identrail'],
  updated_at: '2026-05-17T10:00:00Z'
};

const queuedRepoScan: RepoScanRecord = {
  id: 'repo-scan-queued',
  repository: 'identrail/identrail',
  status: 'queued',
  started_at: '2026-05-17T11:00:00Z',
  commits_scanned: 0,
  files_scanned: 0,
  finding_count: 0,
  truncated: false
};

const canceledRepoScan: RepoScanRecord = {
  ...queuedRepoScan,
  status: 'failed',
  finished_at: '2026-05-17T11:01:00Z',
  error_message: 'repository scan canceled by user'
};

const connectedGitHubPAT: GitHubConnectionStatus = {
  ...connectedGitHub,
  provider: 'github_pat',
  connector_id: 'github-enterprise',
  display_name: 'GitHub Enterprise'
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

async function renderProjectDetail(
  githubBackend: BackendFeatureState,
  githubConnection = connectedGitHub,
  options: {
    repoScanError?: { message: string; status: number; code?: string; detail?: string };
    repoScans?: RepoScanRecord[];
    listRepoScans?: () => Promise<{ items: RepoScanRecord[] }>;
    withProjectSwitcher?: boolean;
  } = {}
) {
  vi.resetModules();
  vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
    return {
      ...actual,
      FEATURE_ONBOARDING_CONNECTOR_AWS: false,
      FEATURE_ONBOARDING_CONNECTOR_GITHUB: true,
      FEATURE_ONBOARDING_CONNECTOR_K8S: false
    };
  });
  vi.doMock('./hooks/useBackendFeatures', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./hooks/useBackendFeatures')>();
    return {
      ...actual,
      useBackendFeatures: () => ({
        features: {
          onboardingWizard: undefined,
          connectors: { github: githubBackend, aws: undefined, kubernetes: undefined },
          configReachable: true
        },
        loading: false
      })
    };
  });

  const api = await import('./api/client');
  const getGitHubConnectorStatus = vi
    .spyOn(api.apiClient, 'getGitHubConnectorStatus')
    .mockResolvedValue({ connection: githubConnection });
  vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
  vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockResolvedValue({ items: [] });
  const listRepoScans = vi.spyOn(api.apiClient, 'listRepoScans');
  if (options.listRepoScans) {
    listRepoScans.mockImplementation(() => options.listRepoScans?.() ?? Promise.resolve({ items: [] }));
  } else {
    listRepoScans.mockResolvedValue({ items: options.repoScans ?? [] });
  }
  const runRepoScan = vi.spyOn(api.apiClient, 'runRepoScan');
  if (options.repoScanError) {
    runRepoScan.mockRejectedValue(
      new api.ApiError(options.repoScanError.message, options.repoScanError.status, {
        code: options.repoScanError.code,
        detail: options.repoScanError.detail
      })
    );
  } else {
    runRepoScan.mockResolvedValue({ repo_scan: queuedRepoScan });
  }
  const cancelRepoScan = vi.spyOn(api.apiClient, 'cancelRepoScan').mockResolvedValue({ repo_scan: canceledRepoScan });
  const getGitHubConnectorRepositoryPosture = vi
    .spyOn(api.apiClient, 'getGitHubConnectorRepositoryPosture')
    .mockResolvedValue({
      connector_id: 'github-app',
      provider: 'github_app',
      posture: {
        repository: 'identrail/identrail',
        installation_id: 12345,
        collected_at: '2026-05-17T10:02:00Z',
        checks: [
          {
            id: 'default_branch_protection',
            category: 'branch_protection',
            state: 'secure',
            reason: 'protection_enforced',
            summary: 'Default branch requires pull request reviews.'
          },
          {
            id: 'actions_permissions',
            category: 'actions',
            state: 'insecure',
            reason: 'write_workflow_token',
            summary: 'Actions token can write by default.'
          }
        ],
        rate_limit: { limit: 5000, remaining: 4990 }
      }
    });
  const startGitHubConnector = vi.spyOn(api.apiClient, 'startGitHubConnector').mockImplementation(async (payload) => ({
    connection: {
      provider: 'github_app',
      connected: false,
      connector_id: 'github-app',
      display_name: 'Identrail',
      status: 'pending',
      health_status: 'unknown',
      webhook_secret_rotation_required: false,
      selected_repositories: []
    },
    connector_id: 'github-app',
    state: 'github-state',
    install_url: 'https://github.com/apps/identrail/installations/select_target?state=github-state',
    install_account_type: payload.install_account_type ?? 'any',
    webhook_url: '/auth/webhooks/github',
    expires_at: '2026-05-17T10:10:00Z'
  }));

  const { ProductProjectDetailPage } = await import('./productShell');
  function ProjectDetailHarness() {
    const navigate = useNavigate();
    return (
      <>
        <ProductProjectDetailPage />
        {options.withProjectSwitcher ? (
          <button type="button" onClick={() => navigate('/app/tenant-a/workspace-a/projects/project-2')}>
            Open project 2
          </button>
        ) : null}
      </>
    );
  }

  render(
    <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/projects/project-1']}>
      <Routes>
        <Route path="/app/:tenantID/:workspaceID/projects/:projectID" element={<ProjectDetailHarness />} />
      </Routes>
    </MemoryRouter>
  );

  return {
    getGitHubConnectorStatus,
    getGitHubConnectorRepositoryPosture,
    startGitHubConnector,
    listRepoScans,
    runRepoScan,
    cancelRepoScan
  };
}

describe('ProductAppIndexRedirect', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useMe');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.resetModules();
  });

  it('starts self-serve onboarding when the bundle and API both enable it', async () => {
    await renderProductIndexRedirect(true, true);

    expect(await screen.findByRole('heading', { level: 1, name: 'Start onboarding' })).toBeInTheDocument();
    expect(screen.queryByText(/No workspace is attached yet/i)).not.toBeInTheDocument();
  });

  it('shows a clear unavailable state when the API does not advertise onboarding', async () => {
    await renderProductIndexRedirect(true, undefined);

    expect(
      await screen.findByRole('heading', { level: 1, name: /Self-serve onboarding is not enabled on this API/i })
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Start onboarding' })).not.toBeInTheDocument();
  });

  it('shows a clear unavailable state instead of a 404 when the API lacks onboarding', async () => {
    await renderProductIndexRedirect(true, false);

    expect(
      await screen.findByRole('heading', { level: 1, name: /Self-serve onboarding is not enabled on this API/i })
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Start onboarding' })).not.toBeInTheDocument();
  });

  it('keeps the explicit workspace-required state when the bundle disables onboarding', async () => {
    await renderProductIndexRedirect(false, undefined);

    expect(await screen.findByRole('heading', { level: 1, name: /No workspace is attached yet/i })).toBeInTheDocument();
  });
});

describe('ProductShellLayout', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.resetModules();
  });

  it('limits default source logo stacks to feature-enabled connectors', async () => {
    vi.resetModules();
    vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
      const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
      return {
        ...actual,
        FEATURE_ONBOARDING_CONNECTOR_GITHUB: false,
        FEATURE_ONBOARDING_CONNECTOR_K8S: false
      };
    });

    const { ProductShellLayout, SourceLogoMark } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route
              index
              element={
                <>
                  <p>Child view</p>
                  <SourceLogoMark provider="aws" />
                  <SourceLogoMark provider="github" />
                  <SourceLogoMark provider="kubernetes" />
                </>
              }
            />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getAllByRole('img', { name: 'AWS' }).length).toBeGreaterThan(0);
    expect(screen.queryByRole('img', { name: 'GitHub' })).not.toBeInTheDocument();
    expect(screen.queryByRole('img', { name: 'Kubernetes' })).not.toBeInTheDocument();
  });
});

describe('ProductShellLayout', () => {
  afterEach(() => {
    vi.doUnmock('./hooks/useMe');
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('opens the workspace finder from keyboard shortcuts and routes to a selected section', async () => {
    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route index element={<h2>Overview content</h2>} />
            <Route path="findings" element={<h2>Findings content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByRole('button', { name: /Open workspace finder/i })).toBeInTheDocument();

    fireEvent.keyDown(window, { key: '/' });
    expect(screen.getByRole('dialog', { name: /Go to anything/i })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Search workspace commands/i), { target: { value: 'findings' } });
    fireEvent.keyDown(screen.getByLabelText(/Search workspace commands/i), { key: 'Enter' });

    expect(await screen.findByRole('heading', { level: 2, name: /Findings content/i })).toBeInTheDocument();
  });
});

describe('ProductProjectDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.resetModules();
    vi.unstubAllEnvs();
  });

  it('marks GitHub unavailable without calling its status endpoint when the API disables the connector', async () => {
    const { getGitHubConnectorStatus } = await renderProjectDetail(false);

    expect(await screen.findByRole('heading', { level: 3, name: 'AWS' })).toBeInTheDocument();
    const githubButton = screen.getByRole('button', { name: /GitHub/i });
    expect(githubButton).toBeDisabled();
    expect(githubButton).toHaveTextContent('Unavailable');
    expect(githubButton).toHaveTextContent('Not available on this API server.');
    expect(getGitHubConnectorStatus).not.toHaveBeenCalled();
  });

  it('loads the GitHub connection and selected repositories when the bundle and API both enable it', async () => {
    const { getGitHubConnectorStatus } = await renderProjectDetail(true);

    expect((await screen.findAllByText('identrail/identrail')).length).toBeGreaterThan(0);
    expect(within(screen.getByLabelText('Source types')).getByRole('button', { name: /GitHub/i })).not.toBeDisabled();
    expect(screen.getByText(/Installation 12345/i)).toBeInTheDocument();
    expect(getGitHubConnectorStatus).toHaveBeenCalledWith(
      'workspace-a',
      'project-1',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('opens GitHub installation in a new tab through GitHub account picker', async () => {
    const userAgent = vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0');
    const open = vi.spyOn(window, 'open').mockReturnValue({} as Window);
    const { startGitHubConnector } = await renderProjectDetail(true);

    expect(await screen.findByText('Install Identrail on GitHub')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Install GitHub App/i }));

    await waitFor(() =>
      expect(startGitHubConnector).toHaveBeenCalledWith(
        expect.not.objectContaining({ install_account_type: expect.anything() }),
        expect.any(Object)
      )
    );
    expect(open).toHaveBeenCalledWith(
      'https://github.com/apps/identrail/installations/select_target?state=github-state',
      '_blank',
      'noopener,noreferrer'
    );
    expect(open).not.toHaveBeenCalledWith('', '_blank');
    expect(await screen.findByText(/GitHub opened in a new tab/i)).toBeInTheDocument();

    userAgent.mockRestore();
  });

  it('keeps advanced GitHub and scan policy controls collapsed until requested', async () => {
    await renderProjectDetail(true);

    expect(await screen.findByText('GitHub Enterprise fallback')).toBeInTheDocument();
    expect(screen.getByLabelText(/Personal access token/i)).not.toBeVisible();

    fireEvent.click(screen.getByText('GitHub Enterprise fallback'));
    expect(screen.getByLabelText(/Personal access token/i)).toBeVisible();

    const scanLimits = screen.getByText('Scan limits').closest('details');
    expect(scanLimits).not.toBeNull();
    expect(within(scanLimits as HTMLElement).getByLabelText(/History limit/i)).not.toBeVisible();

    fireEvent.click(within(scanLimits as HTMLElement).getByText('Scan limits'));
    expect(within(scanLimits as HTMLElement).getByLabelText(/History limit/i)).toBeVisible();

    expect(screen.getByText('Scan policy editor')).toBeInTheDocument();
    expect(screen.getByLabelText(/Trigger mode/i)).not.toBeVisible();

    fireEvent.click(screen.getByText('Scan policy editor'));
    expect(screen.getByLabelText(/Trigger mode/i)).toBeVisible();
  });

  it('loads GitHub repository posture for the selected app repository', async () => {
    const { getGitHubConnectorRepositoryPosture } = await renderProjectDetail(true);

    expect(await screen.findByText('Repository posture')).toBeInTheDocument();
    const postureDetails = await screen.findByText(/Review 1 check/i);
    expect(screen.getByText(/Actions token can write by default/i)).not.toBeVisible();
    fireEvent.click(postureDetails);
    expect(screen.getByText(/Actions token can write by default/i)).toBeVisible();
    expect(getGitHubConnectorRepositoryPosture).toHaveBeenCalledWith(
      'github-app',
      'workspace-a',
      'project-1',
      'identrail/identrail',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('queues the first repository scan from the selected GitHub repository', async () => {
    let listCalls = 0;
    const { runRepoScan } = await renderProjectDetail(true, connectedGitHub, {
      listRepoScans: () => {
        listCalls += 1;
        return Promise.resolve({ items: listCalls === 1 ? [] : [queuedRepoScan] });
      }
    });

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());

    fireEvent.click(queueButton);

    await waitFor(() =>
      expect(runRepoScan).toHaveBeenCalledWith(
        { repository: 'identrail/identrail', project_id: 'project-1', connector_id: 'github-app' },
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByText(/Repository scan queued for identrail\/identrail/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /View findings/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/findings'
    );
    expect(screen.getByLabelText(/recent repository scan activity/i)).toHaveTextContent('Queued');
  });

  it('preserves the generic scan payload for GitHub PAT connections', async () => {
    let listCalls = 0;
    const { runRepoScan } = await renderProjectDetail(true, connectedGitHubPAT, {
      listRepoScans: () => {
        listCalls += 1;
        return Promise.resolve({ items: listCalls === 1 ? [] : [queuedRepoScan] });
      }
    });

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());

    fireEvent.click(queueButton);

    await waitFor(() =>
      expect(runRepoScan).toHaveBeenCalledWith(
        { repository: 'identrail/identrail' },
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('cancels an active repository scan before retrying', async () => {
    let listCalls = 0;
    const { cancelRepoScan } = await renderProjectDetail(true, connectedGitHub, {
      listRepoScans: () => {
        listCalls += 1;
        return Promise.resolve({ items: listCalls === 1 ? [queuedRepoScan] : [canceledRepoScan] });
      }
    });

    expect(await screen.findByRole('button', { name: /Scan already active/i })).toBeDisabled();
    const cancelButton = screen.getByRole('button', { name: /Cancel scan/i });
    fireEvent.click(cancelButton);

    await waitFor(() =>
      expect(cancelRepoScan).toHaveBeenCalledWith(
        queuedRepoScan.id,
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByText(/Repository scan canceled for identrail\/identrail/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/recent repository scan activity/i)).toHaveTextContent('repository scan canceled by user');
  });

  it('clears canceling state when the cancel response is stale after refresh', async () => {
    const pendingCancel = deferred<{ repo_scan: RepoScanRecord }>();
    const { cancelRepoScan, listRepoScans } = await renderProjectDetail(true, connectedGitHub, {
      listRepoScans: () => Promise.resolve({ items: [queuedRepoScan] })
    });
    cancelRepoScan.mockReturnValueOnce(pendingCancel.promise);

    const cancelButton = await screen.findByRole('button', { name: /Cancel scan/i });
    fireEvent.click(cancelButton);

    expect(await screen.findByRole('button', { name: /Canceling/i })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: /Refresh status/i }));
    await waitFor(() => expect(listRepoScans).toHaveBeenCalledTimes(2));

    await act(async () => {
      pendingCancel.resolve({ repo_scan: canceledRepoScan });
      await pendingCancel.promise;
    });

    await waitFor(() => expect(screen.queryByRole('button', { name: /Canceling/i })).not.toBeInTheDocument());
    expect(screen.getByRole('button', { name: /Cancel scan/i })).not.toBeDisabled();
  });

  it('allows queueing another selected repository while a different repository is active', async () => {
    const multiRepoConnection: GitHubConnectionStatus = {
      ...connectedGitHub,
      selected_repositories: ['identrail/identrail', 'identrail/docs']
    };
    const { runRepoScan } = await renderProjectDetail(true, multiRepoConnection, {
      repoScans: [queuedRepoScan]
    });

    expect(await screen.findByRole('button', { name: /Scan already active/i })).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/^Repository$/i), { target: { value: 'identrail/docs' } });

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());
    fireEvent.click(queueButton);

    await waitFor(() =>
      expect(runRepoScan).toHaveBeenCalledWith(
        { repository: 'identrail/docs', project_id: 'project-1', connector_id: 'github-app' },
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('keeps stale repo scan refresh responses from overwriting refreshed activity', async () => {
    const staleRefresh = deferred<{ items: RepoScanRecord[] }>();
    const refreshedRepoScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-refreshed',
      status: 'completed',
      files_scanned: 12,
      finding_count: 3,
      finished_at: '2026-05-17T11:03:00Z'
    };
    const staleRepoScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-stale',
      status: 'failed',
      files_scanned: 9,
      finding_count: 7,
      error_message: 'stale response'
    };
    let listRepoScanCalls = 0;
    const { listRepoScans } = await renderProjectDetail(true, connectedGitHub, {
      listRepoScans: () => {
        listRepoScanCalls += 1;
        if (listRepoScanCalls === 1) {
          return Promise.resolve({ items: [] });
        }
        if (listRepoScanCalls === 2) {
          return staleRefresh.promise;
        }
        return Promise.resolve({ items: [refreshedRepoScan] });
      }
    });

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());
    fireEvent.click(queueButton);

    expect(await screen.findByText(/Repository scan queued for identrail\/identrail/i)).toBeInTheDocument();
    await waitFor(() => expect(listRepoScans).toHaveBeenCalledTimes(2));

    fireEvent.click(screen.getByRole('button', { name: /Refresh status/i }));

    const activity = screen.getByLabelText(/recent repository scan activity/i);
    await waitFor(() => expect(activity).toHaveTextContent('3 findings'));

    await act(async () => {
      staleRefresh.resolve({ items: [staleRepoScan] });
      await staleRefresh.promise;
    });

    expect(activity).toHaveTextContent('3 findings');
    expect(activity).not.toHaveTextContent('7 findings');
  });

  it('keeps refresh disabled while the first repository scan is queueing', async () => {
    const pendingSubmit = deferred<{ repo_scan: RepoScanRecord }>();
    const { runRepoScan } = await renderProjectDetail(true);
    runRepoScan.mockReturnValueOnce(pendingSubmit.promise);

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());
    fireEvent.click(queueButton);

    expect(await screen.findByRole('button', { name: /Queueing/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Refresh status/i })).toBeDisabled();

    await act(async () => {
      pendingSubmit.resolve({ repo_scan: queuedRepoScan });
      await pendingSubmit.promise;
    });

    await waitFor(() => expect(screen.getByRole('button', { name: /Queue first scan/i })).not.toBeDisabled());
  });

  it('keeps an old route submit from clearing a newer repo scan submit', async () => {
    const firstSubmit = deferred<{ repo_scan: RepoScanRecord }>();
    const secondSubmit = deferred<{ repo_scan: RepoScanRecord }>();
    const { runRepoScan } = await renderProjectDetail(true, connectedGitHub, { withProjectSwitcher: true });
    runRepoScan.mockReturnValueOnce(firstSubmit.promise).mockReturnValueOnce(secondSubmit.promise);

    const firstQueueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(firstQueueButton).not.toBeDisabled());
    fireEvent.click(firstQueueButton);
    expect(await screen.findByRole('button', { name: /Queueing/i })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: /Open project 2/i }));
    expect(await screen.findByRole('heading', { name: /Connect project sources/i })).toBeInTheDocument();
    const secondQueueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(secondQueueButton).not.toBeDisabled());
    fireEvent.click(secondQueueButton);
    expect(await screen.findByRole('button', { name: /Queueing/i })).toBeDisabled();

    await act(async () => {
      firstSubmit.resolve({ repo_scan: queuedRepoScan });
      await firstSubmit.promise;
    });

    expect(screen.getByRole('button', { name: /Queueing/i })).toBeDisabled();

    await act(async () => {
      secondSubmit.resolve({ repo_scan: queuedRepoScan });
      await secondSubmit.promise;
    });

    await waitFor(() => expect(screen.getByRole('button', { name: /Queue first scan/i })).not.toBeDisabled());
  });

  it('explains selected-repository and allowlist failures when the first repository scan is not permitted', async () => {
    const { runRepoScan } = await renderProjectDetail(true, connectedGitHub, {
      repoScanError: { message: 'repo target not allowed', status: 403 }
    });

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());
    fireEvent.click(queueButton);

    await waitFor(() => expect(runRepoScan).toHaveBeenCalled());
    expect(
      await screen.findByText(/select it during installation and refresh status/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/ask an operator to allow that owner\/repo target/i)).toBeInTheDocument();
  });

  it('surfaces hosted repository scan diagnostics from the API response', async () => {
    const { runRepoScan } = await renderProjectDetail(true, connectedGitHub, {
      repoScanError: {
        message: 'failed to enqueue repo scan',
        status: 500,
        code: 'repo_scan_migration_missing',
        detail: 'Repository scan persistence failed; the hosted database may be missing migrations.'
      }
    });

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());
    fireEvent.click(queueButton);

    await waitFor(() => expect(runRepoScan).toHaveBeenCalled());
    expect(await screen.findByText(/hosted database may be missing migrations/i)).toBeInTheDocument();
  });
});

async function renderFindings(options: { repoScans?: RepoScanRecord[]; repoFindings?: Finding[] } = {}) {
  vi.resetModules();
  vi.doMock('./hooks/useMe', () => ({
    useMe: () => ({
      me: { ...loggedInWithoutWorkspace, role: 'owner' } as CurrentUserContext,
      loading: false,
      error: '',
      unauthenticated: false,
      refresh: vi.fn()
    })
  }));

  const api = await import('./api/client');
  const listRepoScans = vi
    .spyOn(api.apiClient, 'listRepoScans')
    .mockResolvedValue({ items: options.repoScans ?? [] });
  const listRepoFindings = vi
    .spyOn(api.apiClient, 'listRepoFindings')
    .mockImplementation(async (params) => {
      // Apply the server-side filters (severity/type) the component passes so
      // tests that exercise filtering observe a realistic empty result.
      let items = options.repoFindings ?? [];
      if (params?.severity) {
        items = items.filter((finding) => finding.severity === params.severity);
      }
      if (params?.type) {
        items = items.filter((finding) => finding.type === params.type);
      }
      return { items, summary: undefined };
    });
  vi.spyOn(api.apiClient, 'getRepoFindingsTrends').mockResolvedValue({ items: [] });
  vi.spyOn(api.apiClient, 'getRepoRiskGraph').mockRejectedValue(new Error('no graph'));

  const { ProductFindingsPage } = await import('./productShell');
  render(
    <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/findings']}>
      <Routes>
        <Route path="/app/:tenantID/:workspaceID/findings" element={<ProductFindingsPage />} />
      </Routes>
    </MemoryRouter>
  );

  return { listRepoScans, listRepoFindings };
}

describe('ProductFindingsPage states', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useMe');
    vi.resetModules();
  });

  it('shows a first-scan onboarding state when no scans have run', async () => {
    await renderFindings({ repoScans: [] });

    expect(await screen.findByText('Run your first repository scan')).toBeInTheDocument();
    // The zero-filled dashboard chrome must not render in the empty state.
    expect(screen.queryByText('Completed scans')).not.toBeInTheDocument();
  });

  it('surfaces a failure state instead of zeros when every scan failed', async () => {
    const failedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-failed',
      status: 'failed',
      finished_at: '2026-05-17T11:05:00Z',
      error_message: 'Repository not found or access revoked'
    };

    await renderFindings({ repoScans: [failedScan] });

    expect(await screen.findByText('Your last repository scan failed')).toBeInTheDocument();
    expect(screen.getByText(/Repository not found or access revoked/i)).toBeInTheDocument();
    expect(screen.queryByText('Completed scans')).not.toBeInTheDocument();
  });

  it('shows a clean "no exposure" state when a scan succeeded with zero findings', async () => {
    const succeededScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-succeeded',
      status: 'succeeded',
      finished_at: '2026-05-17T11:05:00Z',
      finding_count: 0
    };

    await renderFindings({ repoScans: [succeededScan] });

    expect(await screen.findByText('No exposure found')).toBeInTheDocument();
    // The consolidated KPI strip renders for a succeeded scan.
    expect(screen.getByText('Completed scans')).toBeInTheDocument();
    // With no findings and no active filters, the filter panel and the empty
    // detail pane are gated out (no redundant empty placeholders).
    expect(screen.queryByText('Filters and sorting')).not.toBeInTheDocument();
    expect(screen.queryByText('Select a finding')).not.toBeInTheDocument();
  });

  it('does not show failed state when a canceled scan is the latest', async () => {
    const failedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-failed-legacy',
      status: 'failed',
      finished_at: '2026-05-17T11:00:00Z',
      error_message: 'Repository not found or access revoked'
    };
    const canceledScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-canceled-latest',
      status: 'canceled',
      finished_at: '2026-05-17T11:05:00Z',
      error_message: 'User canceled scan from API'
    };

    await renderFindings({ repoScans: [canceledScan, failedScan] });

    expect(await screen.findByText('No completed scan results')).toBeInTheDocument();
    expect(screen.queryByText('Your last repository scan failed')).not.toBeInTheDocument();
  });

  it('shows "No completed scan results" while an active scan is still running', async () => {
    const failedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-failed-in-flight',
      status: 'failed',
      finished_at: '2026-05-17T11:03:00Z',
      error_message: 'Repository access revoked'
    };
    const queuedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-queued-in-flight',
      status: 'queued',
      finished_at: undefined
    };

    await renderFindings({ repoScans: [queuedScan, failedScan] });

    expect(await screen.findByText('No completed scan results')).toBeInTheDocument();
    expect(screen.queryByText('No exposure found')).not.toBeInTheDocument();
    expect(screen.queryByText('Your last repository scan failed')).not.toBeInTheDocument();
  });

  it('keeps findings visible when failed scans still return historical findings', async () => {
    const failedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-failed-latest',
      status: 'failed',
      started_at: '2026-05-17T12:00:00Z',
      finished_at: '2026-05-17T12:01:00Z',
      error_message: 'Repository not found or access revoked'
    };
    const oldSucceededScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-succeeded-older',
      status: 'succeeded',
      started_at: '2026-05-17T11:00:00Z',
      finished_at: '2026-05-17T11:30:00Z',
      finding_count: 2
    };
    const historicFinding: Finding = {
      id: 'finding-legacy',
      scan_id: 'repo-scan-succeeded-older',
      type: 'secrets',
      severity: 'high',
      title: 'Legacy finding',
      human_summary: 'Legacy risky secret exposure',
      remediation: 'Rotate and clean up repository secret.',
      created_at: '2026-05-17T11:10:00Z'
    };

    await renderFindings({
      repoScans: [failedScan, oldSucceededScan],
      repoFindings: [historicFinding]
    });

    expect(screen.queryByText('Your last repository scan failed')).not.toBeInTheDocument();
    expect(await screen.findByText('Completed scans')).toBeInTheDocument();
    expect(await screen.findByText('Legacy finding')).toBeInTheDocument();
  });

  it('does not report cancellation as a failed scan', async () => {
    const canceledScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-canceled',
      status: 'canceled',
      finished_at: '2026-05-17T11:09:00Z',
      error_message: 'User canceled scan from API'
    };

    await renderFindings({ repoScans: [canceledScan] });

    expect(await screen.findByText('No completed scan results')).toBeInTheDocument();
    expect(screen.queryByText('Your last repository scan failed')).not.toBeInTheDocument();
  });

  it('restores focus to the triggering row when the finding detail dialog closes', async () => {
    const scan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-with-findings',
      status: 'succeeded',
      finished_at: '2026-05-17T11:06:00Z',
      finding_count: 1
    };

    const finding: Finding = {
      id: 'finding-1',
      scan_id: scan.id,
      type: 'aws_access_key',
      severity: 'critical',
      title: 'IAM role with wildcard trust',
      human_summary: 'AssumeRole trust policy allows any principal.',
      remediation: 'Tighten trust policy principals.',
      created_at: '2026-05-17T11:06:00Z'
    };

    await renderFindings({ repoScans: [scan], repoFindings: [finding] });

    const rowButton = (await screen.findAllByRole('listitem')).find((node) =>
      node.textContent?.includes('IAM role with wildcard trust')
    ) as HTMLButtonElement | undefined;
    expect(rowButton).toBeDefined();
    if (!rowButton) return;
    rowButton.focus();
    fireEvent.click(rowButton);

    const closeButton = await screen.findByRole('button', { name: /Close finding detail/i });
    fireEvent.click(closeButton);

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /Close finding detail/i })).not.toBeInTheDocument();
    });
    await waitFor(() => {
      expect(document.activeElement).toBe(rowButton);
    });
  });

  it('keeps visible filters when active filters match no findings', async () => {
    const scan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-with-findings',
      status: 'succeeded',
      finished_at: '2026-05-17T11:06:00Z',
      finding_count: 1
    };

    const finding: Finding = {
      id: 'finding-1',
      scan_id: scan.id,
      type: 'aws_access_key',
      severity: 'critical',
      title: 'IAM role with wildcard trust',
      human_summary: 'AssumeRole trust policy allows any principal.',
      remediation: 'Tighten trust policy principals.',
      created_at: '2026-05-17T11:06:00Z'
    };

    await renderFindings({
      repoScans: [scan],
      repoFindings: [finding]
    });

    expect((await screen.findAllByText('IAM role with wildcard trust')).length).toBeGreaterThan(0);

    expect(await screen.findByText('Filters and sorting')).toBeInTheDocument();

    const severityFilter = screen.getByLabelText('Severity');
    fireEvent.change(severityFilter, { target: { value: 'high' } });

    expect(await screen.findByText('No findings match the current filters.')).toBeInTheDocument();
    expect(screen.getByLabelText('Repository finding filters and sorting')).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: /IAM role with wildcard trust/i })).not.toBeInTheDocument();
  });
});
