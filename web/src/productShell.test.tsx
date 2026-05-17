import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AWSConnectionStatus, CurrentUserContext, GitHubConnectionStatus } from './api/client';
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

async function renderProjectDetail(githubBackend: BackendFeatureState, githubConnection = connectedGitHub) {
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

  const { ProductProjectDetailPage } = await import('./productShell');

  render(
    <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/projects/project-1']}>
      <Routes>
        <Route path="/app/:tenantID/:workspaceID/projects/:projectID" element={<ProductProjectDetailPage />} />
      </Routes>
    </MemoryRouter>
  );

  return { getGitHubConnectorStatus };
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

    expect(await screen.findByText('identrail/identrail')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /GitHub/i })).not.toBeDisabled();
    expect(screen.getByText('Installation 12345')).toBeInTheDocument();
    expect(getGitHubConnectorStatus).toHaveBeenCalledWith(
      'workspace-a',
      'project-1',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });
});
