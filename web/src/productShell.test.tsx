import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AWSConnectionStatus, CurrentUserContext, GitHubConnectionStatus, RepoScanRecord } from './api/client';
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
          connectors: { github: undefined, aws: undefined, kubernetes: undefined }
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
  diagnostics: []
};

const connectedGitHub: GitHubConnectionStatus = {
  provider: 'github',
  connected: true,
  connector_id: 'github-app',
  display_name: 'GitHub App',
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
    repoScanError?: { message: string; status: number };
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
          connectors: { github: githubBackend, aws: undefined, kubernetes: undefined }
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
    runRepoScan.mockRejectedValue(new api.ApiError(options.repoScanError.message, options.repoScanError.status));
  } else {
    runRepoScan.mockResolvedValue({ repo_scan: queuedRepoScan });
  }

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

  return { getGitHubConnectorStatus, listRepoScans, runRepoScan };
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

  it('falls back to the bundle flag when the API does not advertise onboarding', async () => {
    await renderProductIndexRedirect(true, undefined);

    expect(await screen.findByRole('heading', { level: 1, name: 'Start onboarding' })).toBeInTheDocument();
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
    expect(screen.getByRole('button', { name: /GitHub/i })).not.toBeDisabled();
    expect(screen.getByText('Installation 12345')).toBeInTheDocument();
    expect(getGitHubConnectorStatus).toHaveBeenCalledWith(
      'workspace-a',
      'project-1',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('queues the first repository scan from the selected GitHub repository', async () => {
    const { runRepoScan } = await renderProjectDetail(true, connectedGitHub, { repoScans: [queuedRepoScan] });

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());

    fireEvent.click(queueButton);

    await waitFor(() =>
      expect(runRepoScan).toHaveBeenCalledWith(
        { repository: 'identrail/identrail' },
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
    expect(await screen.findByRole('heading', { name: /Connect sources for project-2/i })).toBeInTheDocument();
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

  it('explains allowlist failures when the first repository scan is not permitted', async () => {
    const { runRepoScan } = await renderProjectDetail(true, connectedGitHub, {
      repoScanError: { message: 'repo target not allowed', status: 403 }
    });

    const queueButton = await screen.findByRole('button', { name: /Queue first scan/i });
    await waitFor(() => expect(queueButton).not.toBeDisabled());
    fireEvent.click(queueButton);

    await waitFor(() => expect(runRepoScan).toHaveBeenCalled());
    expect(
      await screen.findByText(/outside the allowed scan targets/i)
    ).toBeInTheDocument();
  });
});
