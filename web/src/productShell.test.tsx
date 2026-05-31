import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  AuthConfigResponse,
  AWSConnectorStartResponse,
  AWSConnectionStatus,
  CurrentUserContext,
  Finding,
  GitHubConnectionStatus,
  RepoFindingRemediationPreview,
  RepoFindingRemediationPublishResponse,
  RepoScanRecord,
  WhoAmIResponse
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

const loggedInWithWorkspace: CurrentUserContext = {
  user: {
    id: 'user-1',
    primary_email: 'owner@example.com',
    display_name: 'Owner User',
    avatar_url: 'https://avatars.githubusercontent.com/u/1?v=4',
    status: 'active',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  },
  org_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'project-a',
  role: 'admin',
  workspace: {
    tenant_id: 'tenant-a',
    workspace_id: 'workspace-a',
    display_name: 'Workspace A',
    slug: 'workspace-a',
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

const connectedAWS: AWSConnectionStatus = {
  provider: 'aws',
  connected: true,
  connector_id: 'aws-connector-1',
  display_name: 'Production AWS',
  status: 'active',
  health_status: 'healthy',
  role_arn: 'arn:aws:iam::123456789012:role/IdentrailReadOnly',
  external_id_configured: true,
  account_id: '123456789012',
  principal_arn: 'arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail',
  region: 'us-east-1',
  permission_checks: [
    {
      name: 'iam:GetRole',
      passed: true,
      message: 'Role metadata can be inspected.'
    }
  ],
  diagnostics: [
    {
      code: 'cloudtrail_pending',
      message: 'Runtime evidence is not wired for this environment yet.',
      remediation: 'No action required for connector setup.'
    }
  ],
  capabilities: { requested: ['discovery'], validated: ['discovery'], effective: ['discovery'], unavailable: [] },
  updated_at: '2026-05-17T10:00:00Z',
  last_validated_at: '2026-05-17T10:00:00Z'
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

function mockBackendFeatures(connectors: {
  github?: BackendFeatureState;
  aws?: BackendFeatureState;
  kubernetes?: BackendFeatureState;
} = {}) {
  vi.doMock('./hooks/useBackendFeatures', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./hooks/useBackendFeatures')>();
    return {
      ...actual,
      useBackendFeatures: () => ({
        features: {
          onboardingWizard: undefined,
          connectors: {
            github: connectors.github,
            aws: connectors.aws,
            kubernetes: connectors.kubernetes
          },
          configReachable: true
        },
        loading: false
      })
    };
  });
}

function mockConnectorFeatureFlags({
  aws = true,
  github = true,
  kubernetes = true
}: {
  aws?: boolean;
  github?: boolean;
  kubernetes?: boolean;
} = {}) {
  vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
    return {
      ...actual,
      FEATURE_ONBOARDING_CONNECTOR_AWS: aws,
      FEATURE_ONBOARDING_CONNECTOR_GITHUB: github,
      FEATURE_ONBOARDING_CONNECTOR_K8S: kubernetes
    };
  });
}

const settingsAuthConfig: AuthConfigResponse = {
  auth: {
    manual_mode: false,
    workos_login_enabled: true,
    native_saml_enabled: false,
    providers: ['github_oauth', 'google_oauth']
  },
  features: {
    onboarding_wizard: true,
    connectors: { github: true, aws: true, kubernetes: true }
  }
};

function settingsWhoAmI(me: CurrentUserContext): WhoAmIResponse {
  const workspace = me.workspace ?? {
    tenant_id: 'tenant-a',
    workspace_id: 'workspace-a',
    display_name: 'Workspace A',
    slug: 'workspace-a',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  };
  const member = {
    tenant_id: workspace.tenant_id,
    workspace_id: workspace.workspace_id,
    member_id: 'member-a',
    user_id: 'oidc-subject-a',
    email: me.user.primary_email,
    role: me.role ?? 'admin',
    status: 'active' as const,
    joined_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  };
  return {
    principal: { type: 'subject', id: 'oidc-subject-a' },
    roles: [member.role],
    scopes: ['me:read', 'me:write'],
    scope: { tenant_id: workspace.tenant_id, workspace_id: workspace.workspace_id },
    active_workspace: { workspace, member, is_active: true },
    workspaces: [{ workspace, member, is_active: true }]
  };
}

async function renderProductSettingsPage(options: {
  me?: CurrentUserContext;
  updateMe?: CurrentUserContext | Error;
} = {}) {
  vi.resetModules();
  const me = options.me ?? loggedInWithWorkspace;
  const primeMeCache = vi.fn();
  vi.doMock('./hooks/useMe', () => ({
    useMe: () => ({
      me,
      loading: false,
      error: '',
      unauthenticated: false,
      refresh: vi.fn()
    }),
    primeMeCache,
    clearMeCache: vi.fn()
  }));

  const api = await import('./api/client');
  const whoAmI = settingsWhoAmI(me);
  vi.spyOn(api.apiClient, 'getWhoAmI').mockResolvedValue(whoAmI);
  vi.spyOn(api.apiClient, 'listWorkspaceMembers').mockResolvedValue({
    items: whoAmI.active_workspace?.member ? [whoAmI.active_workspace.member] : []
  });
  vi.spyOn(api.apiClient, 'getAuthConfig').mockResolvedValue(settingsAuthConfig);
  vi.spyOn(api.apiClient, 'listCurrentUserSessions').mockResolvedValue({ items: [] });
  const updateMe = vi.spyOn(api.apiClient, 'updateMe');
  if (options.updateMe instanceof Error) {
    updateMe.mockRejectedValue(options.updateMe);
  } else {
    updateMe.mockResolvedValue({ me: options.updateMe ?? me });
  }

  const { ProductSettingsPage } = await import('./productShell');
  render(
    <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/settings']}>
      <Routes>
        <Route path="/app/:tenantID/:workspaceID/settings" element={<ProductSettingsPage />} />
      </Routes>
    </MemoryRouter>
  );

  return { primeMeCache, updateMe };
}

async function renderProjectDetail(
  githubBackend: BackendFeatureState,
  githubConnection = connectedGitHub,
  options: {
    initialEntry?: string;
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
            Open environment 2
          </button>
        ) : null}
      </>
    );
  }

  render(
    <MemoryRouter initialEntries={[options.initialEntry ?? '/app/tenant-a/workspace-a/projects/project-1']}>
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

describe('ProductSettingsPage profile', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useMe');
    vi.resetModules();
  });

  it('updates profile fields optimistically from settings', async () => {
    const updatedMe: CurrentUserContext = {
      ...loggedInWithWorkspace,
      user: {
        ...loggedInWithWorkspace.user,
        display_name: 'Updated Owner',
        avatar_url: 'https://avatars.githubusercontent.com/u/42?v=4',
        updated_at: '2026-05-17T10:00:00Z'
      }
    };
    const { primeMeCache, updateMe } = await renderProductSettingsPage({ updateMe: updatedMe });

    expect(await screen.findByRole('heading', { name: 'Owner User' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: '  Updated Owner  ' } });
    fireEvent.change(screen.getByLabelText('Avatar URL'), {
      target: { value: 'https://avatars.githubusercontent.com/u/42?v=4' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    await waitFor(() =>
      expect(updateMe).toHaveBeenCalledWith({
        display_name: 'Updated Owner',
        avatar_url: 'https://avatars.githubusercontent.com/u/42?v=4'
      })
    );
    expect(primeMeCache).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        user: expect.objectContaining({
          display_name: 'Updated Owner',
          avatar_url: 'https://avatars.githubusercontent.com/u/42?v=4'
        })
      })
    );
    await waitFor(() => expect(primeMeCache).toHaveBeenLastCalledWith(updatedMe));
  });

  it('rolls back the optimistic profile update when saving fails', async () => {
    const { primeMeCache, updateMe } = await renderProductSettingsPage({
      updateMe: new Error('avatar_url host is not allowed')
    });

    expect(await screen.findByRole('heading', { name: 'Owner User' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Blocked Owner' } });
    fireEvent.change(screen.getByLabelText('Avatar URL'), { target: { value: 'https://example.com/avatar.png' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    await waitFor(() => expect(updateMe).toHaveBeenCalled());
    expect(await screen.findByRole('alert')).toHaveTextContent('avatar_url host is not allowed');
    expect(primeMeCache).toHaveBeenLastCalledWith(loggedInWithWorkspace);
  });

  it('validates display name before submitting a profile update', async () => {
    const { primeMeCache, updateMe } = await renderProductSettingsPage();

    expect(await screen.findByRole('heading', { name: 'Owner User' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: '   ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Display name must be 1-80 characters.');
    expect(updateMe).not.toHaveBeenCalled();
    expect(primeMeCache).not.toHaveBeenCalled();
  });
});

describe('ProductShellLayout', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.resetModules();
  });

  it('keeps source logo stacks feature-scoped while domain sections stay discoverable', async () => {
    vi.resetModules();
    vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
      const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
      return {
        ...actual,
        FEATURE_ONBOARDING_CONNECTOR_GITHUB: false,
        FEATURE_ONBOARDING_CONNECTOR_K8S: false
      };
    });
    mockBackendFeatures();

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
    expect(screen.getByRole('button', { name: 'GitHub' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Kubernetes' })).toBeInTheDocument();
  });
});

describe('ProductShellLayout', () => {
  afterEach(() => {
    vi.doUnmock('./hooks/useMe');
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('opens the workspace finder from keyboard shortcuts and routes to a selected section', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route index element={<h2>Overview content</h2>} />
            <Route path="github/findings" element={<h2>GitHub findings content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByRole('button', { name: /Open workspace finder/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'AWS' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'GitHub' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Kubernetes' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Projects' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Findings' })).not.toBeInTheDocument();
    expect(screen.queryByText('Control plane')).not.toBeInTheDocument();

    expect(screen.getByRole('link', { name: 'Overview' })).toHaveClass('active');
    fireEvent.click(screen.getByRole('button', { name: 'AWS' }));
    expect(screen.getByRole('link', { name: 'Overview' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'AWS' })).toHaveClass('is-open');
    fireEvent.keyDown(window, { key: 'Escape' });

    fireEvent.click(screen.getByRole('button', { name: 'GitHub' }));
    const githubFlyout = screen.getByRole('dialog', { name: 'GitHub' });
    expect(within(githubFlyout).queryByText('Section')).not.toBeInTheDocument();
    expect(within(githubFlyout).queryByRole('heading', { name: 'GitHub' })).not.toBeInTheDocument();
    expect(within(githubFlyout).getByRole('link', { name: 'GitHub Control center' })).toBeInTheDocument();
    expect(within(githubFlyout).getByRole('link', { name: 'GitHub Findings' })).toBeInTheDocument();
    expect(within(githubFlyout).getAllByText('AI / Agentic Risk').length).toBeGreaterThan(0);

    fireEvent.keyDown(window, { key: '/' });
    const finder = screen.getByRole('dialog', { name: /Workspace finder/i });
    expect(finder).toBeInTheDocument();
    expect(within(finder).queryByText('Workspace finder')).not.toBeInTheDocument();
    expect(within(finder).queryByText('Go to anything')).not.toBeInTheDocument();

    expect(screen.queryByRole('option', { name: /^Projects\b/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /^Findings\b/i })).not.toBeInTheDocument();
    expect(
      within(within(finder).getByRole('option', { name: /^OverviewDomain/i })).queryByText('O')
    ).not.toBeInTheDocument();
    expect(
      within(within(finder).getByRole('option', { name: /^GitHub findingsRepository/i })).queryByText('F')
    ).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Search workspace commands/i), { target: { value: 'github findings' } });
    fireEvent.keyDown(screen.getByLabelText(/Search workspace commands/i), { key: 'Enter' });

    expect(await screen.findByRole('heading', { level: 2, name: /GitHub findings content/i })).toBeInTheDocument();
  });

  it('keeps GitHub domain navigation open when the connector is unavailable', async () => {
    vi.resetModules();
    vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
      const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
      return {
        ...actual,
        FEATURE_ONBOARDING_CONNECTOR_GITHUB: true,
        FEATURE_ONBOARDING_CONNECTOR_K8S: false
      };
    });
    mockBackendFeatures({ github: false });

    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route index element={<h2>Overview content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    const githubButton = screen.getByRole('button', { name: 'GitHub' });
    expect(githubButton).not.toBeDisabled();
    fireEvent.click(githubButton);
    expect(screen.getByRole('dialog', { name: 'GitHub' })).toBeInTheDocument();

    fireEvent.keyDown(window, { key: '/' });
    expect(screen.getByRole('dialog', { name: /Workspace finder/i })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Search workspace commands/i), { target: { value: 'github' } });
    expect(screen.getAllByRole('option', { name: /^GitHub\b/i }).length).toBeGreaterThan(0);
    expect(screen.queryByRole('option', { name: /Connect GitHub/i })).not.toBeInTheDocument();
  });

  it('lets an open domain flyout own the sidebar highlight over Reports routes', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/reports']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route path="reports" element={<h2>Reports content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: /Reports content/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Reports' })).toHaveClass('active');

    fireEvent.click(screen.getByRole('button', { name: 'AWS' }));

    expect(screen.getByRole('link', { name: 'Reports' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'AWS' })).toHaveClass('is-open');
    expect(screen.getByRole('button', { name: 'AWS' })).toHaveAttribute('aria-expanded', 'true');

    fireEvent.click(screen.getByRole('button', { name: 'GitHub' }));

    expect(screen.getByRole('link', { name: 'Reports' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'AWS' })).not.toHaveClass('is-active');
    expect(screen.getByRole('button', { name: 'GitHub' })).toHaveClass('is-open');
  });

  it('removes Settings active styling while a domain flyout is open', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/settings']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route path="settings" element={<h2>Settings content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: /Settings content/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Settings' })).toHaveClass('active');

    fireEvent.click(screen.getByRole('button', { name: 'Kubernetes' }));

    expect(screen.getByRole('link', { name: 'Settings' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'Kubernetes' })).toHaveClass('is-open');
  });
});

describe('Domain-first app routes', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.resetModules();
  });

  it('publishes the full route manifest required for the new app IA', async () => {
    const { DOMAIN_APP_ROUTE_MANIFEST } = await import('./productDomainRoutes');

    expect(DOMAIN_APP_ROUTE_MANIFEST).toEqual([
      '/app/:tenantID/:workspaceID',
      '/app/:tenantID/:workspaceID/aws',
      '/app/:tenantID/:workspaceID/aws/connect',
      '/app/:tenantID/:workspaceID/aws/accounts',
      '/app/:tenantID/:workspaceID/aws/identities',
      '/app/:tenantID/:workspaceID/aws/agents',
      '/app/:tenantID/:workspaceID/aws/resources',
      '/app/:tenantID/:workspaceID/aws/runtime',
      '/app/:tenantID/:workspaceID/aws/graph',
      '/app/:tenantID/:workspaceID/aws/findings',
      '/app/:tenantID/:workspaceID/aws/remediation',
      '/app/:tenantID/:workspaceID/aws/governance',
      '/app/:tenantID/:workspaceID/github',
      '/app/:tenantID/:workspaceID/github/connect',
      '/app/:tenantID/:workspaceID/github/repositories',
      '/app/:tenantID/:workspaceID/github/actions',
      '/app/:tenantID/:workspaceID/github/findings',
      '/app/:tenantID/:workspaceID/github/remediation',
      '/app/:tenantID/:workspaceID/github/agentic-risk',
      '/app/:tenantID/:workspaceID/github/agentic-risk/configs',
      '/app/:tenantID/:workspaceID/github/agentic-risk/mcp-tools',
      '/app/:tenantID/:workspaceID/github/agentic-risk/prompts',
      '/app/:tenantID/:workspaceID/github/agentic-risk/secrets',
      '/app/:tenantID/:workspaceID/github/agentic-risk/workflow-trust-paths',
      '/app/:tenantID/:workspaceID/github/agentic-risk/findings',
      '/app/:tenantID/:workspaceID/kubernetes',
      '/app/:tenantID/:workspaceID/kubernetes/connect',
      '/app/:tenantID/:workspaceID/kubernetes/clusters',
      '/app/:tenantID/:workspaceID/kubernetes/workloads',
      '/app/:tenantID/:workspaceID/kubernetes/service-accounts',
      '/app/:tenantID/:workspaceID/kubernetes/findings',
      '/app/:tenantID/:workspaceID/kubernetes/remediation',
      '/app/:tenantID/:workspaceID/reports',
      '/app/:tenantID/:workspaceID/settings'
    ]);
    expect(DOMAIN_APP_ROUTE_MANIFEST).not.toContain('/app/:tenantID/:workspaceID/projects');
    expect(DOMAIN_APP_ROUTE_MANIFEST).not.toContain('/app/:tenantID/:workspaceID/findings');
  });

  it('renders premium domain route shells with provider marks and environment scope', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production-platform',
          name: 'Production Platform',
          slug: 'production-platform',
          description: 'Production identity boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging-platform',
          name: 'Staging Platform',
          slug: 'staging-platform',
          description: 'Staging identity boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    const { ProductDomainRoutePage } = await import('./productShell');
    function LocationProbe() {
      const location = useLocation();
      return <p data-testid="location">{`${location.pathname}${location.search}`}</p>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/agentic-risk/mcp-tools?environment=staging-platform']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/github/agentic-risk/mcp-tools"
            element={
              <>
                <LocationProbe />
                <ProductDomainRoutePage domain="github" routeID="agentic-risk-mcp-tools" />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: /MCP tools/i })).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'GitHub' })).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: /GitHub sections/i })).not.toBeInTheDocument();
    expect(await screen.findByRole('option', { name: 'Staging Platform' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('staging-platform');
    expect(screen.getByRole('link', { name: /Connect GitHub/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github/connect?environment=staging-platform'
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), {
      target: { value: 'production-platform' }
    });
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/app/tenant-a/workspace-a/github/agentic-risk/mcp-tools?environment=production-platform'
    );
    expect(screen.getByText('Route contract')).toBeInTheDocument();
  });

  it('keeps a requested environment selected when it is outside the first selector page', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: Array.from({ length: 50 }, (_, index) => ({
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: `recent-environment-${index + 1}`,
        name: `Recent Environment ${index + 1}`,
        slug: `recent-environment-${index + 1}`,
        description: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }))
    });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'older-production',
        name: 'Older Production',
        slug: 'older-production',
        description: 'Long-lived production boundary.',
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-02T00:00:00Z'
      }
    });

    const { ProductDomainRoutePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/repositories?environment=older-production']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/github/repositories"
            element={<ProductDomainRoutePage domain="github" routeID="repositories" />}
          />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('older-production'));
    expect(api.apiClient.getProject).toHaveBeenCalledWith(
      'workspace-a',
      'older-production',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(screen.getByRole('link', { name: /Connect GitHub/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github/connect?environment=older-production'
    );
    expect(screen.getByRole('link', { name: /GitHub findings/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github/findings?environment=older-production'
    );
  });

  it('renders the AWS Control Center with current and future capability labels', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });

    const { ProductAWSControlCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws" element={<ProductAWSControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'AWS Control Center' })).toBeInTheDocument();
    expect((await screen.findAllByText(/Account 123456789012/i)).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Connect AWS/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/connect?environment=production'
    );
    expect(screen.getAllByText('Wired now').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Coming').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Not yet available').length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Resources and secrets/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/resources?environment=production'
    );
  });

  it('ignores stale AWS Control Center status loads after switching environments', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging',
          name: 'Staging',
          slug: 'staging',
          description: 'Staging AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    const productionStatus = deferred<{ connection: AWSConnectionStatus }>();
    const stagingStatus = deferred<{ connection: AWSConnectionStatus }>();
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockImplementation((_workspaceID, projectID) =>
      projectID === 'production' ? productionStatus.promise : stagingStatus.promise
    );

    const { ProductAWSControlCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws" element={<ProductAWSControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('production');
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      stagingStatus.resolve({
        connection: { ...connectedAWS, display_name: 'Staging AWS', account_id: '222222222222', region: 'us-west-2' }
      });
    });
    expect(await screen.findByText('Staging AWS')).toBeInTheDocument();
    expect(screen.getAllByText(/Account 222222222222/i).length).toBeGreaterThan(0);

    await act(async () => {
      productionStatus.resolve({
        connection: { ...connectedAWS, display_name: 'Production AWS', account_id: '111111111111', region: 'us-east-1' }
      });
    });
    expect(screen.getByText('Staging AWS')).toBeInTheDocument();
    expect(screen.queryByText('Production AWS')).not.toBeInTheDocument();
  });

  it('renders AWS account and region inventory with current connector coverage', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });

    const { ProductAWSAccountsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/accounts?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/accounts" element={<ProductAWSAccountsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'AWS accounts and regions' })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'AWS account and region coverage' })).toBeInTheDocument();
    expect(screen.getAllByText(/AWS account 123456789012/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Region us-east-1/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Open Connect AWS/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/connect?environment=production'
    );
  });

  it('renders AWS machine identity inventory with the current IAM role and future workload rows', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });

    const { ProductAWSIdentitiesPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/identities?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/identities" element={<ProductAWSIdentitiesPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'AWS machine identities' })).toBeInTheDocument();
    expect(screen.getByRole('search', { name: /AWS machine identities filters/i })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'AWS machine identity inventory' })).toBeInTheDocument();
    expect(screen.getAllByText('arn:aws:iam::123456789012:role/IdentrailReadOnly').length).toBeGreaterThan(0);
    expect(screen.getByText(/EC2 instance profiles/i)).toBeInTheDocument();
    expect(screen.getByText(/Risk score/i)).toBeInTheDocument();
    expect(screen.getByText(/Unscored until AWS findings land/i)).toBeInTheDocument();
  });

  it('renders AWS agent identity inventory as an honest reserved surface', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });

    const { ProductAWSAgentsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/agents?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/agents" element={<ProductAWSAgentsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'AWS agent identities' })).toBeInTheDocument();
    expect(screen.getAllByText(/Connect AWS to populate current inventory anchors/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Bedrock agents/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AgentCore runtime and gateway identity/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Secret metadata only, no value reads/i)).toBeInTheDocument();
  });

  it('keeps AWS resources inventory metadata-only when no environment exists', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    const getAWSProjectConnection = vi.spyOn(api.apiClient, 'getAWSProjectConnection');

    const { ProductAWSResourcesPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/resources']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/resources" element={<ProductAWSResourcesPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'AWS resources and credentials' })).toBeInTheDocument();
    expect(screen.getByText(/Create an environment before inventory can resolve/i)).toBeInTheDocument();
    expect(screen.getByText(/No secret value reads/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Secrets Manager metadata/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Open environments/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/projects?source=aws'
    );
    expect(getAWSProjectConnection).not.toHaveBeenCalled();
  });

  it('keeps AWS connect on the domain page when no environment exists', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });

    const { ProductAWSConnectPage } = await import('./productShell');
    function LocationProbe() {
      const location = useLocation();
      return <p data-testid="location">{`${location.pathname}${location.search}`}</p>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/connect"
            element={
              <>
                <LocationProbe />
                <ProductAWSConnectPage />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Connect AWS' })).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/app/tenant-a/workspace-a/aws/connect');
    expect(screen.getByRole('heading', { level: 3, name: /Create an environment before connecting AWS/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open environments/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/projects?source=aws'
    );
  });

  it('clears stale AWS connect form values when the selected environment changes', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging',
          name: 'Staging',
          slug: 'staging',
          description: 'Staging AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    const productionStatus = deferred<{ connection: AWSConnectionStatus }>();
    const stagingStatus = deferred<{ connection: AWSConnectionStatus }>();
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockImplementation((_workspaceID, projectID) =>
      projectID === 'production' ? productionStatus.promise : stagingStatus.promise
    );

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('production');
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      stagingStatus.resolve({
        connection: {
          ...disconnectedAWS,
          permission_checks: [],
          diagnostics: []
        }
      });
    });

    expect(await screen.findByRole('heading', { level: 3, name: /AWS read-only connector/i })).toBeInTheDocument();
    expect(screen.getByLabelText('Role ARN')).toHaveValue('');
    expect(screen.getByLabelText('Display name')).toHaveValue('');
    expect(screen.getByLabelText('Region')).toHaveValue('us-east-1');

    await act(async () => {
      productionStatus.resolve({ connection: connectedAWS });
    });
    expect(screen.getByLabelText('Role ARN')).toHaveValue('');
    expect(screen.queryByDisplayValue('Production AWS')).not.toBeInTheDocument();
  });

  it('ignores stale AWS CloudFormation start responses after switching environments', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging',
          name: 'Staging',
          slug: 'staging',
          description: 'Staging AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    const startResponse = deferred<AWSConnectorStartResponse>();
    vi.spyOn(api.apiClient, 'startAWSConnector').mockReturnValue(startResponse.promise);

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    const launchButton = await screen.findByRole('button', { name: /Launch stack/i });
    fireEvent.click(launchButton);
    await waitFor(() =>
      expect(api.apiClient.startAWSConnector).toHaveBeenCalledWith(
        expect.objectContaining({ project_id: 'production' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      startResponse.resolve({
        connection: connectedAWS,
        connector_id: 'aws-connector-1',
        external_id: 'stale-external-id',
        launch_url: 'https://console.aws.amazon.com/cloudformation',
        template_url: 'https://example.com/template.yaml',
        role_name: 'IdentrailReadOnly',
        stack_name: 'identrail-readonly-connector',
        policy_hash: 'sha256:example',
        permission_preview: [
          { service: 'IAM', actions: ['iam:GetRole'], resources: ['*'], reason: 'Inspect role metadata.' }
        ],
        permission_tiers: []
      });
    });

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('staging');
    expect(screen.getByLabelText('External ID')).toHaveValue('');
    expect(screen.queryByText(/AWS CloudFormation launch is ready/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Preview permissions/i })).not.toBeInTheDocument();
  });

  it('ignores stale AWS poll responses after switching environments', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging',
          name: 'Staging',
          slug: 'staging',
          description: 'Staging AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ connection: projectID === 'production' ? connectedAWS : disconnectedAWS })
    );
    const pollResponse = deferred<{ connection: AWSConnectionStatus }>();
    vi.spyOn(api.apiClient, 'pollAWSConnector').mockReturnValue(pollResponse.promise);

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 3, name: /AWS read-only connector/i })).toBeInTheDocument();
    const refreshButton = within(screen.getByLabelText('AWS connector setup')).getByRole('button', {
      name: /Refresh status/i
    });
    fireEvent.click(refreshButton);
    await waitFor(() =>
      expect(api.apiClient.pollAWSConnector).toHaveBeenCalledWith(
        'aws-connector-1',
        'workspace-a',
        'production',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      pollResponse.resolve({
        connection: { ...connectedAWS, display_name: 'Production poll AWS', account_id: '111111111111' }
      });
    });

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('staging');
    expect(screen.queryByText('AWS connector is active.')).not.toBeInTheDocument();
    expect(screen.queryByText('Production poll AWS')).not.toBeInTheDocument();
  });

  it('ignores stale AWS validation responses after switching environments', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging',
          name: 'Staging',
          slug: 'staging',
          description: 'Staging AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ connection: projectID === 'production' ? connectedAWS : disconnectedAWS })
    );
    const validationResponse = deferred<{ connection: AWSConnectionStatus }>();
    vi.spyOn(api.apiClient, 'validateAWSConnector').mockReturnValue(validationResponse.promise);

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    const submitButton = await screen.findByRole('button', { name: /Validate and save AWS/i });
    fireEvent.click(submitButton);
    await waitFor(() =>
      expect(api.apiClient.validateAWSConnector).toHaveBeenCalledWith(
        'aws-connector-1',
        expect.objectContaining({ project_id: 'production' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      validationResponse.resolve({
        connection: { ...connectedAWS, display_name: 'Validated production AWS', account_id: '111111111111' }
      });
    });

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('staging');
    expect(screen.queryByText('AWS connector is active.')).not.toBeInTheDocument();
    expect(screen.queryByText('Validated production AWS')).not.toBeInTheDocument();
  });

  it('loads AWS connect actions for the selected environment even when it is outside the first page', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: Array.from({ length: 50 }, (_, index) => ({
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: `recent-environment-${index + 1}`,
        name: `Recent Environment ${index + 1}`,
        slug: `recent-environment-${index + 1}`,
        description: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }))
    });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'older-production',
        name: 'Older Production',
        slug: 'older-production',
        description: 'Long-lived production boundary.',
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-02T00:00:00Z'
      }
    });
    const getAWSProjectConnection = vi
      .spyOn(api.apiClient, 'getAWSProjectConnection')
      .mockResolvedValue({ connection: connectedAWS });

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=older-production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('older-production');
    expect(await screen.findByRole('heading', { level: 3, name: /AWS read-only connector/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /AWS home/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws?environment=older-production'
    );
    const setupPayload = screen.getByLabelText('Setup payload');
    expect(within(setupPayload).getByText('workspace-a')).toBeInTheDocument();
    expect(within(setupPayload).getByText('older-production')).toBeInTheDocument();
    expect(listProjects).toHaveBeenCalled();
    expect(getAWSProjectConnection).toHaveBeenCalledWith(
      'workspace-a',
      'older-production',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('keeps requested environment selected when getProject check fails for a transient error', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: Array.from({ length: 50 }, (_, index) => ({
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: `recent-environment-${index + 1}`,
        name: `Recent Environment ${index + 1}`,
        slug: `recent-environment-${index + 1}`,
        description: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }))
    });
    vi.spyOn(api.apiClient, 'getProject').mockRejectedValue(new api.ApiError('temporary outage', 503));

    const { ProductDomainRoutePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/repositories?environment=older-production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/repositories" element={<ProductDomainRoutePage domain="github" routeID="repositories" />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('older-production');
    expect(screen.getByRole('link', { name: /Connect GitHub/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github/connect?environment=older-production'
    );
    expect(await screen.findByText(/Unable to verify selected environment older-production/i)).toBeInTheDocument();
  });

  it('does not silently switch AWS connect to a fallback environment when getProject check fails transiently', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'active-production',
          name: 'Active Production',
          slug: 'active-production',
          description: 'Active production boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getProject').mockRejectedValue(new api.ApiError('temporary outage', 503));
    const getAWSProjectConnection = vi
      .spyOn(api.apiClient, 'getAWSProjectConnection')
      .mockResolvedValue({ connection: disconnectedAWS });

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=older-production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Connect AWS' })).toBeInTheDocument();
    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('older-production');
    expect(screen.getByText(/Unable to verify selected environment older-production/i)).toBeInTheDocument();
    expect(screen.getByText('older-production')).toBeInTheDocument();
    expect(listProjects).toHaveBeenCalled();
    expect(getAWSProjectConnection).toHaveBeenCalledWith(
      'workspace-a',
      'older-production',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('falls back to an active environment when the requested environment is archived', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'active-production',
          name: 'Active Production',
          slug: 'active-production',
          description: 'Active production boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'archived-production',
        name: 'Archived Production',
        slug: 'archived-production',
        description: 'Retired boundary.',
        archived_at: '2026-01-03T00:00:00Z',
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2026-01-03T00:00:00Z'
      }
    });

    const { ProductDomainRoutePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/identities?environment=archived-production']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/identities"
            element={<ProductDomainRoutePage domain="aws" routeID="identities" />}
          />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('active-production'));
    expect(screen.getByRole('link', { name: /Connect AWS/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/connect?environment=active-production'
    );
    expect(screen.getByRole('link', { name: /AWS findings/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/findings?environment=active-production'
    );
  });

  it('creates a new unique environment key instead of overwriting an existing environment', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    const firstPageProjects = Array.from({ length: 50 }, (_, index) => ({
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: `recent-environment-${index + 1}`,
      name: `Recent Environment ${index + 1}`,
      slug: `recent-environment-${index + 1}`,
      description: '',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z'
    }));
    const existingProject = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'production-platform',
      name: 'Production Platform',
      slug: 'production-platform',
      description: 'Existing production boundary.',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z'
    };
    vi.spyOn(api.apiClient, 'listProjects').mockImplementation(async (_workspaceID, filters: any) => {
      if (filters?.limit === 50) {
        return { items: firstPageProjects };
      }
      if (filters?.cursor === 'older-page') {
        return { items: [existingProject] };
      }
      return { items: firstPageProjects, next_cursor: 'older-page' };
    });
    vi.spyOn(api.apiClient, 'upsertProject').mockImplementation(async (_workspaceID, payload: any) => ({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: payload.project_id,
        name: payload.name,
        slug: payload.slug,
        description: payload.description ?? '',
        created_at: '2026-01-03T00:00:00Z',
        updated_at: '2026-01-03T00:00:00Z'
      }
    }));

    const { ProductProjectsPage } = await import('./productShell');
    function LocationProbe() {
      const location = useLocation();
      return <p data-testid="location">{`${location.pathname}${location.search}`}</p>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/projects?source=aws']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/projects"
            element={
              <>
                <LocationProbe />
                <ProductProjectsPage />
              </>
            }
          />
          <Route path="/app/:tenantID/:workspaceID/projects/:projectID" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Environments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Environment name/i), { target: { value: 'Production Platform' } });
    fireEvent.click(screen.getByRole('button', { name: /Create environment/i }));

    await waitFor(() =>
      expect(screen.getByTestId('location')).toHaveTextContent(
        '/app/tenant-a/workspace-a/projects/production-platform-2?source=aws'
      )
    );
    expect(api.apiClient.upsertProject).toHaveBeenCalledWith(
      'workspace-a',
      expect.objectContaining({ project_id: 'production-platform-2', slug: 'production-platform-2' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('creates stable hidden keys for non-ASCII environment names', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'upsertProject').mockImplementation(async (_workspaceID, payload: any) => ({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: payload.project_id,
        name: payload.name,
        slug: payload.slug,
        description: payload.description ?? '',
        created_at: '2026-01-03T00:00:00Z',
        updated_at: '2026-01-03T00:00:00Z'
      }
    }));

    const { ProductProjectsPage } = await import('./productShell');
    function LocationProbe() {
      const location = useLocation();
      return <p data-testid="location">{`${location.pathname}${location.search}`}</p>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/projects?source=github']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/projects"
            element={
              <>
                <LocationProbe />
                <ProductProjectsPage />
              </>
            }
          />
          <Route path="/app/:tenantID/:workspaceID/projects/:projectID" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Environments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Environment name/i), { target: { value: '本番環境' } });
    fireEvent.click(screen.getByRole('button', { name: /Create environment/i }));

    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/projects/environment-'));
    const payload = (api.apiClient.upsertProject as any).mock.calls[0][1];
    expect(payload.project_id).toMatch(/^environment-[a-z0-9]+$/);
    expect(payload.project_id).not.toBe('default-environment');
  });

  it('opens nested GitHub AI risk routes from the sidebar domain flyout', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    const { container } = render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/agentic-risk/mcp-tools']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route path="github/agentic-risk/mcp-tools" element={<h2>MCP tools content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: /MCP tools content/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'GitHub' }));

    const githubFlyout = screen.getByRole('dialog', { name: 'GitHub' });
    expect(within(githubFlyout).getAllByText('AI / Agentic Risk').length).toBeGreaterThan(0);
    expect(within(githubFlyout).getByRole('link', { name: 'GitHub AI / Agentic Risk MCP / tools' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(container.querySelector('details.idt-domain-flyout-nested')).toHaveAttribute('open');
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

  it('scopes domain connect pages to the requested provider', async () => {
    await renderProjectDetail(true, connectedGitHub, {
      initialEntry: '/app/tenant-a/workspace-a/projects/project-1?source=github'
    });

    expect(await screen.findByRole('heading', { level: 1, name: 'Connect GitHub' })).toBeInTheDocument();
    expect(screen.queryByLabelText('GitHub source')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Source types')).not.toBeInTheDocument();
    expect(screen.queryByText('This page is scoped to GitHub.')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 3, name: 'GitHub' })).not.toBeInTheDocument();
    expect(screen.getByText('Setup')).toBeInTheDocument();
    expect(screen.queryByText('Recommended setup')).not.toBeInTheDocument();
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

    expect(screen.getByText('Scan policy')).toBeInTheDocument();
    expect(screen.getByLabelText(/Trigger mode/i)).not.toBeVisible();

    fireEvent.click(screen.getByText('Scan policy'));
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
      '/app/tenant-a/workspace-a/github/findings'
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

    fireEvent.click(screen.getByRole('button', { name: /Open environment 2/i }));
    expect(await screen.findByRole('heading', { name: /Connect environment sources/i })).toBeInTheDocument();
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
    <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/findings']}>
      <Routes>
        <Route path="/app/:tenantID/:workspaceID/github/findings" element={<ProductFindingsPage />} />
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

describe('GitHub domain pages (#1382)', () => {
  const productionProject = {
    tenant_id: 'tenant-a',
    workspace_id: 'workspace-a',
    project_id: 'production-platform',
    name: 'Production Platform',
    slug: 'production-platform',
    description: 'Production identity boundary.',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-02T00:00:00Z'
  };

  const succeededRepoScan: RepoScanRecord = {
    id: 'repo-scan-succeeded',
    repository: 'identrail/identrail',
    status: 'succeeded',
    started_at: '2026-05-17T10:50:00Z',
    finished_at: '2026-05-17T10:55:00Z',
    commits_scanned: 12,
    files_scanned: 340,
    finding_count: 3,
    truncated: false,
    scan_mode: 'quick'
  };

  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.resetModules();
  });

  async function renderGitHubPage(
    pageName: 'control-center' | 'connect' | 'repositories' | 'actions' | 'remediation',
    options: {
      githubConnection?: GitHubConnectionStatus | null;
      scans?: RepoScanRecord[];
      repoFindings?: Finding[];
      remediationPreview?: RepoFindingRemediationPreview;
      remediationPublish?: RepoFindingRemediationPublishResponse;
      listRepoScans?: () => Promise<{ items: RepoScanRecord[]; next_cursor?: string }>;
      githubFeatureFlag?: boolean;
      githubBackend?: BackendFeatureState;
      runRepoScanError?: { message: string; status: number };
      cancelRepoScanError?: { message: string; status: number };
      initialEntry?: string;
    } = {}
  ) {
    mockConnectorFeatureFlags({ aws: false, github: options.githubFeatureFlag ?? true, kubernetes: false });
    mockBackendFeatures({ github: options.githubBackend ?? true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValue({ connection: options.githubConnection ?? connectedGitHub });
    const listRepoScans = vi.spyOn(api.apiClient, 'listRepoScans');
    if (options.listRepoScans) {
      listRepoScans.mockImplementation(() => options.listRepoScans?.() ?? Promise.resolve({ items: [] }));
    } else {
      listRepoScans.mockResolvedValue({ items: options.scans ?? [] });
    }
    const listRepoFindings = vi
      .spyOn(api.apiClient, 'listRepoFindings')
      .mockResolvedValue({ items: options.repoFindings ?? [], summary: undefined });
    const previewRepoFindingRemediation = vi
      .spyOn(api.apiClient, 'previewRepoFindingRemediation')
      .mockResolvedValue(
        options.remediationPreview ?? {
          finding: options.repoFindings?.[0] ?? {
            id: 'finding-default',
            scan_id: 'repo-scan-default',
            type: 'secret_exposure',
            severity: 'high',
            title: 'Default remediation finding',
            human_summary: 'Default remediation finding summary.',
            remediation: 'Rotate and remove the exposed secret.',
            created_at: '2026-05-17T11:00:00Z'
          },
          remediation: {
            detector: 'secret_exposure',
            summary: 'Rotate and remove the exposed secret',
            risk_summary: 'The exposed credential can be replayed outside GitHub.',
            steps: ['Rotate the exposed credential', 'Remove the committed value'],
            safety_notes: ['Confirm the replacement secret is available before merging'],
            validation: ['Run the repository scan again'],
            secret_rotation: true,
            publishable: true,
            evidence: { finding_id: 'finding-default', scan_id: 'repo-scan-default' }
          },
          fix_pr_plan: {
            base_branch: 'main',
            branch_name: 'identrail/fix/finding-default',
            commit_message: 'Remove exposed secret',
            pr_title: 'Remove exposed secret',
            pr_body: 'Remediates the exposed repository secret.',
            files: [{ path: '.github/workflows/deploy.yml', content: 'env: {}' }],
            finding_id: 'finding-default',
            finding_type: 'secret_exposure'
          }
        }
      );
    const publishRepoFindingRemediation = vi
      .spyOn(api.apiClient, 'publishRepoFindingRemediation')
      .mockResolvedValue(
        options.remediationPublish ?? {
          finding: options.repoFindings?.[0] ?? {
            id: 'finding-default',
            scan_id: 'repo-scan-default',
            type: 'secret_exposure',
            severity: 'high',
            title: 'Default remediation finding',
            human_summary: 'Default remediation finding summary.',
            remediation: 'Rotate and remove the exposed secret.',
            created_at: '2026-05-17T11:00:00Z'
          },
          remediation: {
            detector: 'secret_exposure',
            summary: 'Rotate and remove the exposed secret',
            risk_summary: 'The exposed credential can be replayed outside GitHub.',
            steps: ['Rotate the exposed credential'],
            safety_notes: ['Confirm the replacement secret is available before merging'],
            validation: ['Run the repository scan again'],
            secret_rotation: true,
            publishable: true,
            evidence: { finding_id: 'finding-default', scan_id: 'repo-scan-default' }
          },
          publish: {
            pr_number: 42,
            pr_url: 'https://github.com/identrail/identrail/pull/42',
            branch_name: 'identrail/fix/finding-default',
            commit_sha: 'abc1234'
          }
        }
      );
    const runRepoScan = vi.spyOn(api.apiClient, 'runRepoScan');
    if (options.runRepoScanError) {
      runRepoScan.mockRejectedValue(new api.ApiError(options.runRepoScanError.message, options.runRepoScanError.status));
    } else {
      runRepoScan.mockResolvedValue({ repo_scan: queuedRepoScan });
    }
    const cancelRepoScan = vi.spyOn(api.apiClient, 'cancelRepoScan');
    if (options.cancelRepoScanError) {
      cancelRepoScan.mockRejectedValue(
        new api.ApiError(options.cancelRepoScanError.message, options.cancelRepoScanError.status)
      );
    } else {
      cancelRepoScan.mockResolvedValue({ repo_scan: canceledRepoScan });
    }
    const startGitHubConnector = vi.spyOn(api.apiClient, 'startGitHubConnector').mockResolvedValue({
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
      install_account_type: 'any',
      webhook_url: '/auth/webhooks/github',
      expires_at: '2026-05-17T10:10:00Z'
    });

    const productShell = await import('./productShell');
    const page =
      pageName === 'control-center' ? <productShell.ProductGitHubControlCenterPage /> :
      pageName === 'connect' ? <productShell.ProductGitHubConnectPage /> :
      pageName === 'repositories' ? <productShell.ProductGitHubRepositoriesPage /> :
      pageName === 'remediation' ? <productShell.ProductGitHubRemediationPage /> :
      <productShell.ProductGitHubActionsPage />;

    const routePath =
      pageName === 'control-center' ? 'github' :
      pageName === 'connect' ? 'github/connect' :
      pageName === 'repositories' ? 'github/repositories' :
      pageName === 'remediation' ? 'github/remediation' :
      'github/actions';

    render(
      <MemoryRouter initialEntries={[options.initialEntry ?? `/app/tenant-a/workspace-a/${routePath}`]}>
        <Routes>
          <Route path={`/app/:tenantID/:workspaceID/${routePath}`} element={page} />
        </Routes>
      </MemoryRouter>
    );

    return {
      getGitHubConnectorStatus,
      listRepoScans,
      listRepoFindings,
      previewRepoFindingRemediation,
      publishRepoFindingRemediation,
      runRepoScan,
      cancelRepoScan,
      startGitHubConnector
    };
  }

  it('Control Center loads the GitHub connection and surfaces premium status', async () => {
    const mocks = await renderGitHubPage('control-center', { scans: [succeededRepoScan] });

    await screen.findByRole('heading', { level: 2, name: 'GitHub Control Center' });
    await waitFor(() => expect(mocks.getGitHubConnectorStatus).toHaveBeenCalledWith(
      'workspace-a',
      'production-platform',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    ));
    await screen.findByText(/Connected as identrail/i);
    await waitFor(() => {
      const openRepos = screen
        .getAllByRole('link', { name: /Open Repositories/i })
        .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/repositories'));
      expect(openRepos).toBeDefined();
    });
    const connectLinks = screen
      .getAllByRole('link', { name: /Connect GitHub/i })
      .filter((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/connect'));
    expect(connectLinks.length).toBeGreaterThan(0);
    const findingsLinks = screen
      .getAllByRole('link', { name: /GitHub findings/i })
      .filter((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/findings'));
    expect(findingsLinks.length).toBeGreaterThan(0);
    expect(screen.getByText(/Last 1 repository scans/i)).toBeInTheDocument();
  });

  it('Control Center prompts to connect when not connected', async () => {
    await renderGitHubPage('control-center', {
      githubConnection: {
        ...connectedGitHub,
        connected: false,
        account_login: undefined,
        installation_id: undefined,
        selected_repositories: []
      },
      scans: []
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub Control Center' });
    await screen.findByText(/GitHub is not connected for this environment yet/i);
    await waitFor(() => {
      const heroConnect = screen
        .getAllByRole('link', { name: /Connect GitHub/i })
        .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/connect'));
      expect(heroConnect).toBeDefined();
    });
  });

  it('Control Center shows the unavailable shell when the GitHub connector is gated off', async () => {
    await renderGitHubPage('control-center', { githubFeatureFlag: false, githubBackend: false });

    await screen.findByRole('heading', { level: 2, name: 'GitHub Control Center' });
    await screen.findByRole('heading', { level: 3, name: /GitHub is not available on this API/i });
  });

  it('Connect page calls startGitHubConnector and opens the install URL', async () => {
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    const mocks = await renderGitHubPage('connect', {
      githubConnection: {
        ...connectedGitHub,
        connected: false,
        account_login: undefined,
        installation_id: undefined,
        selected_repositories: []
      }
    });

    const installButton = (await screen.findAllByRole('button', { name: 'Install GitHub App' }))[0];
    fireEvent.click(installButton);

    await waitFor(() =>
      expect(mocks.startGitHubConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          project_id: 'production-platform',
          install_account_type: 'any',
          redirect_uri: expect.stringMatching(/\/app\/github\/callback$/)
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await waitFor(() =>
      expect(openSpy).toHaveBeenCalledWith(
        'https://github.com/apps/identrail/installations/select_target?state=github-state',
        '_blank',
        'noopener,noreferrer'
      )
    );

    const enterpriseLinks = screen
      .getAllByRole('link', { name: /Manage Enterprise \/ PAT/i })
      .filter((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/projects/production-platform'));
    expect(enterpriseLinks.length).toBeGreaterThan(0);
    expect(enterpriseLinks[0].getAttribute('href')).toContain('source=github');
    openSpy.mockRestore();
  });

  it('Repositories page launches a scan via the existing API', async () => {
    const mocks = await renderGitHubPage('repositories', { scans: [] });

    await screen.findByRole('heading', { level: 2, name: 'GitHub repositories' });
    const queueButton = await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' });
    fireEvent.click(queueButton);

    await waitFor(() =>
      expect(mocks.runRepoScan).toHaveBeenCalledWith(
        expect.objectContaining({
          repository: 'identrail/identrail',
          project_id: 'production-platform',
          connector_id: 'github-app'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await screen.findByText(/Repository scan queued for identrail\/identrail/i);
  });

  it('Repositories page cancels an active scan via the existing API', async () => {
    const mocks = await renderGitHubPage('repositories', { scans: [queuedRepoScan] });

    await screen.findByRole('heading', { level: 2, name: 'GitHub repositories' });
    const cancelButton = await screen.findByRole('button', { name: 'Cancel scan for identrail/identrail' });
    fireEvent.click(cancelButton);

    await waitFor(() =>
      expect(mocks.cancelRepoScan).toHaveBeenCalledWith(
        'repo-scan-queued',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await screen.findByText(/Repository scan canceled for identrail\/identrail/i);
  });

  it('Repositories page shows the empty state when no repositories are selected', async () => {
    await renderGitHubPage('repositories', {
      githubConnection: { ...connectedGitHub, selected_repositories: [] }
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub repositories' });
    await screen.findByRole('heading', { level: 3, name: /Select repositories for Identrail to watch/i });
    await waitFor(() => {
      const selectLink = screen
        .getAllByRole('link')
        .find((link) => link.textContent?.includes('Select repositories'));
      expect(selectLink).toBeDefined();
      expect(selectLink?.getAttribute('href')).toMatch(/^\/app\/tenant-a\/workspace-a\/github\/connect/);
    });
  });

  it('Repositories page surfaces a scan error inline without breaking navigation', async () => {
    await renderGitHubPage('repositories', {
      runRepoScanError: { message: 'rate limited', status: 429 }
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub repositories' });
    const queueButton = await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' });
    fireEvent.click(queueButton);

    await screen.findByRole('heading', { level: 3, name: /Repository scan error/i });
    const homeLink = screen
      .getAllByRole('link', { name: /GitHub home/i })
      .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github'));
    expect(homeLink).toBeDefined();
  });

  it('Actions page renders the premium waiting-for-coverage shell', async () => {
    await renderGitHubPage('actions');

    await screen.findByRole('heading', { level: 2, name: 'GitHub Actions / OIDC' });
    await screen.findByRole('heading', { level: 3, name: /Workflow and OIDC posture is rolling out/i });
    expect(screen.getAllByText(/Workflow inventory/i).length).toBeGreaterThan(0);
    await waitFor(() => {
      const openReposLink = screen
        .getAllByRole('link', { name: /Open Repositories/i })
        .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/repositories'));
      expect(openReposLink).toBeDefined();
    });
    const homeLink = screen
      .getAllByRole('link', { name: /GitHub home/i })
      .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github'));
    expect(homeLink).toBeDefined();
  });

  it('Actions page renders the unavailable shell when the GitHub connector is gated off', async () => {
    await renderGitHubPage('actions', { githubFeatureFlag: false, githubBackend: false });

    await screen.findByRole('heading', { level: 2, name: 'GitHub Actions / OIDC' });
    await screen.findByRole('heading', { level: 3, name: /GitHub is not available on this API/i });
  });

  it('Remediation page shows the never-scanned state', async () => {
    await renderGitHubPage('remediation', { scans: [], repoFindings: [] });

    await screen.findByRole('heading', { level: 2, name: 'GitHub remediation' });
    await screen.findByRole('heading', { level: 3, name: /Run your first repository scan/i });
    const repositoriesLink = screen
      .getAllByRole('link', { name: /Open Repositories/i })
      .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/repositories'));
    expect(repositoriesLink).toBeDefined();
  });

  it('Remediation page surfaces a failed scan state before showing remediation chrome', async () => {
    const failedScan: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-remediation-failed',
      status: 'failed',
      finding_count: 0,
      error_message: 'GitHub App installation access revoked'
    };

    await renderGitHubPage('remediation', { scans: [failedScan], repoFindings: [] });

    await screen.findByRole('heading', { level: 3, name: /Your last repository scan failed/i });
    expect(screen.getByText(/GitHub App installation access revoked/i)).toBeInTheDocument();
    expect(screen.queryByText('Actionable findings')).not.toBeInTheDocument();
  });

  it('Remediation page previews and publishes a fix PR only after approval gates pass', async () => {
    const finding: Finding = {
      id: 'finding-deployment-token',
      scan_id: succeededRepoScan.id,
      type: 'secret_exposure',
      severity: 'critical',
      confidence_score: 0.96,
      title: 'Workflow exposes deployment token',
      human_summary: 'A deployment token is committed into a GitHub Actions workflow.',
      remediation: 'Move the deployment token into GitHub Actions secrets and rotate it.',
      repository: 'identrail/identrail',
      file_path: '.github/workflows/deploy.yml',
      line_number: 18,
      detector: 'github_actions_secret',
      source_url: 'https://github.com/identrail/identrail/blob/main/.github/workflows/deploy.yml#L18',
      lifecycle_status: 'open',
      created_at: '2026-05-17T11:10:00Z'
    };
    const preview: RepoFindingRemediationPreview = {
      finding,
      remediation: {
        detector: 'github_actions_secret',
        summary: 'Rotate leaked deployment token',
        risk_summary: 'The token can be reused by anyone with repository history access.',
        steps: ['Create a GitHub Actions secret for the replacement token', 'Remove the inline token from deploy.yml'],
        safety_notes: ['Confirm the replacement secret exists before merging'],
        validation: ['Run the repository scan again', 'Confirm the workflow still deploys from the secret'],
        secret_rotation: true,
        publishable: true,
        evidence: {
          finding_id: finding.id,
          scan_id: finding.scan_id,
          repository: 'identrail/identrail',
          file_path: finding.file_path,
          line_number: finding.line_number
        }
      },
      fix_pr_plan: {
        base_branch: 'main',
        branch_name: 'identrail/fix/deployment-token',
        commit_message: 'Move deployment token into Actions secrets',
        pr_title: 'Move deployment token into Actions secrets',
        pr_body: 'Remediates the exposed deployment token finding.',
        files: [{ path: '.github/workflows/deploy.yml', content: 'env:\\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}' }],
        finding_id: finding.id,
        finding_type: finding.type
      }
    };
    const publish: RepoFindingRemediationPublishResponse = {
      finding,
      remediation: preview.remediation,
      publish: {
        pr_number: 42,
        pr_url: 'https://github.com/identrail/identrail/pull/42',
        branch_name: 'identrail/fix/deployment-token',
        commit_sha: 'abc1234'
      }
    };
    const mocks = await renderGitHubPage('remediation', {
      scans: [{ ...succeededRepoScan, finding_count: 1 }],
      repoFindings: [finding],
      remediationPreview: preview,
      remediationPublish: publish
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub remediation' });
    expect(await screen.findByText('Actionable findings')).toBeInTheDocument();
    expect(screen.getAllByText('Workflow exposes deployment token').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/.github\/workflows\/deploy.yml:18/i).length).toBeGreaterThan(0);

    const previewButton = await screen.findByRole('button', { name: /Preview fix plan/i });
    fireEvent.click(previewButton);

    await waitFor(() =>
      expect(mocks.previewRepoFindingRemediation).toHaveBeenCalledWith(
        finding.id,
        expect.objectContaining({
          repo_scan_id: succeededRepoScan.id,
          finding_url: finding.source_url
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(screen.getByLabelText('Current source content'), {
      target: { value: 'env:\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}' }
    });
    fireEvent.click(previewButton);
    await waitFor(() =>
      expect(mocks.previewRepoFindingRemediation).toHaveBeenCalledWith(
        finding.id,
        expect.objectContaining({
          repo_scan_id: succeededRepoScan.id,
          finding_url: finding.source_url,
          source_content: 'env:\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
          require_fix_plan: true
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByText('Rotate leaked deployment token')).toBeInTheDocument();
    expect(screen.getByText('Branch identrail/fix/deployment-token')).toBeInTheDocument();

    const publishButton = await screen.findByRole('button', { name: /Publish fix PR/i });
    expect(publishButton).toBeDisabled();
    expect(mocks.publishRepoFindingRemediation).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText('Current source content'), {
      target: { value: 'env:\\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}' }
    });
    fireEvent.change(screen.getByLabelText('GitHub token'), { target: { value: 'ghp_write_token' } });
    fireEvent.click(screen.getByLabelText('Approved for publish'));
    fireEvent.click(screen.getByLabelText('GitHub token is intentionally write-capable'));

    await waitFor(() => expect(publishButton).not.toBeDisabled());
    fireEvent.click(publishButton);

    await waitFor(() =>
      expect(mocks.publishRepoFindingRemediation).toHaveBeenCalledWith(
        finding.id,
        expect.objectContaining({
          repo_scan_id: succeededRepoScan.id,
          source_content: 'env:\\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
          base_branch: 'main',
          finding_url: finding.source_url,
          operator_approved: true,
          write_permissions_configured: true,
          github_token: 'ghp_write_token'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByText(/PR #42 opened/i)).toBeInTheDocument();
  });

  it('Control Center surfaces an error when listing repository scans fails', async () => {
    const api = await import('./api/client');
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockRejectedValue(
      new api.ApiError('rate limited', 429)
    );

    const productShell = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github" element={<productShell.ProductGitHubControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'GitHub Control Center' });
    await screen.findByRole('heading', { level: 3, name: /Unable to load GitHub status/i });
  });

  it('Control Center hides recent scans when no repositories are selected', async () => {
    const unrelatedScan: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-unrelated',
      repository: 'someone-else/other-repo'
    };
    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: [] },
      scans: [unrelatedScan]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub Control Center' });
    expect(screen.queryByText(/Last \d+ repository scans/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/someone-else\/other-repo/i)).not.toBeInTheDocument();
    await screen.findByRole('heading', { level: 3, name: /No repository scans yet/i });
  });

  it('Control Center latest-scan KPI reflects the newest scan even when it failed', async () => {
    const olderSucceeded: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-older-success',
      started_at: '2026-05-16T10:00:00Z',
      finished_at: '2026-05-16T10:05:00Z'
    };
    const newerFailed: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-newer-failed',
      status: 'failed',
      started_at: '2026-05-17T12:00:00Z',
      finished_at: '2026-05-17T12:05:00Z',
      error_message: 'scan exploded',
      finding_count: 0
    };
    await renderGitHubPage('control-center', { scans: [newerFailed, olderSucceeded] });

    await screen.findByRole('heading', { level: 2, name: 'GitHub Control Center' });
    await screen.findAllByText(/scan exploded/i);
    const kpiStrip = screen.getByLabelText('GitHub control center metrics');
    expect(within(kpiStrip).getByText(/scan exploded/i)).toBeInTheDocument();
  });

  it('Connect page renders an Open GitHub fallback link when the install popup is blocked', async () => {
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    await renderGitHubPage('connect', {
      githubConnection: {
        ...connectedGitHub,
        connected: false,
        account_login: undefined,
        installation_id: undefined,
        selected_repositories: []
      }
    });

    const installButton = (await screen.findAllByRole('button', { name: 'Install GitHub App' }))[0];
    fireEvent.click(installButton);

    const fallback = await screen.findByRole('link', { name: 'Open GitHub' });
    expect(fallback.getAttribute('href')).toBe(
      'https://github.com/apps/identrail/installations/select_target?state=github-state'
    );
    expect(openSpy).toHaveBeenCalled();
    openSpy.mockRestore();
  });

  it('Repositories page activity timeline ignores scans for unselected repositories', async () => {
    const unrelatedScan: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-unrelated',
      repository: 'someone-else/other-repo'
    };
    await renderGitHubPage('repositories', { scans: [unrelatedScan] });

    await screen.findByRole('heading', { level: 2, name: 'GitHub repositories' });
    await screen.findByRole('heading', { level: 3, name: /Recent repository scan activity/i });
    expect(screen.getByText(/0 scans loaded/i)).toBeInTheDocument();
    expect(screen.queryByText(/someone-else\/other-repo/i)).not.toBeInTheDocument();
  });

  it('Repositories page fetches additional scan pages until selected-repository activity is available', async () => {
    const unrelatedRepoScans: RepoScanRecord[] = Array.from({ length: 3 }).map((_, index) => ({
      ...succeededRepoScan,
      id: `repo-scan-unrelated-${index}`,
      repository: `team-${index + 1}/unrelated`
    }));
    const selectedRepoScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-selected',
      repository: 'identrail/identrail',
      status: 'completed',
      started_at: '2026-05-18T10:00:00Z',
      finished_at: '2026-05-18T10:03:00Z',
      finding_count: 2,
      files_scanned: 17
    };

    let pageCalls = 0;
    const mocks = await renderGitHubPage('repositories', {
      listRepoScans: () => {
        pageCalls += 1;
        if (pageCalls === 1) {
          return Promise.resolve({
            items: unrelatedRepoScans,
            next_cursor: 'repo-page-2'
          });
        }
        return Promise.resolve({
          items: [selectedRepoScan]
        });
      }
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub repositories' });
    await waitFor(() => expect(mocks.listRepoScans).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByText(/1 scan loaded/i)).toBeInTheDocument());
    expect(screen.getAllByText(/identrail\/identrail/i)).toHaveLength(2);
  });

  it('Repositories page clears stale GitHub connection data when a reloading environment status fails', async () => {
    const api = await import('./api/client');
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });

    const activeProject = productionProject;
    const staleProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [activeProject, staleProject]
    });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation(async (_workspaceID, projectID) => ({
      project:
        projectID === staleProject.project_id
          ? staleProject
          : activeProject
    }));

    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValueOnce({ connection: connectedGitHub })
      .mockRejectedValue(new api.ApiError('status endpoint unavailable', 503));
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [queuedRepoScan] });
    vi.spyOn(api.apiClient, 'runRepoScan').mockResolvedValue({ repo_scan: queuedRepoScan });
    vi.spyOn(api.apiClient, 'cancelRepoScan').mockResolvedValue({ repo_scan: canceledRepoScan });

    const { ProductGitHubRepositoriesPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/repositories?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/repositories" element={<ProductGitHubRepositoriesPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'GitHub repositories' });
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('production-platform'));
    expect(await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' })).toBeInTheDocument();

    await act(async () => {
      fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), {
        target: { value: 'staging-platform' }
      });
    });

    await screen.findByRole('heading', { level: 3, name: /Unable to load repository status/i });
    expect(screen.queryByRole('button', { name: 'Queue scan for identrail/identrail' })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: /Connect GitHub to manage repositories/i })).toBeInTheDocument();

    expect(getGitHubConnectorStatus).toHaveBeenCalledTimes(2);
  });

  it('Repositories page disables Queue scan while environment data is reloading', async () => {
    const mocks = await renderGitHubPage('repositories', { scans: [] });

    expect(await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' })).not.toBeDisabled();

    let resolveQueued: ((value: { repo_scan: RepoScanRecord }) => void) | null = null;
    let resolvePending: ((value: { items: RepoScanRecord[] }) => void) | null = null;
    mocks.runRepoScan.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveQueued = resolve;
        })
    );
    mocks.listRepoScans.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolvePending = resolve;
        })
    );

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Queue scan for identrail/identrail' }));
    });
    await waitFor(() => expect(mocks.runRepoScan).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Queue scan for identrail/identrail' })).toBeDisabled());
    expect(screen.getByRole('button', { name: 'Queue scan for identrail/identrail' })).toHaveTextContent(/Refreshing|Queuing/i);

    await act(async () => {
      resolveQueued?.({ repo_scan: queuedRepoScan });
      await Promise.resolve();
    });
    await act(async () => {
      resolvePending?.({ items: [] });
      await Promise.resolve();
    });
  });
});
