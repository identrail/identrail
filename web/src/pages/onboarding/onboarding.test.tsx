import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { OnboardingState, ScanRecord } from '../../api/client';

const baseState: OnboardingState = {
  user_id: '11111111-1111-4111-8111-111111111111',
  current_step: 'org',
  connector_skipped: false,
  scan_skipped: false,
  started_at: '2026-05-14T10:00:00Z',
  updated_at: '2026-05-14T10:00:00Z'
};

function state(overrides: Partial<OnboardingState>): OnboardingState {
  return { ...baseState, ...overrides };
}

function scan(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: 'scan-1',
    provider: 'aws',
    status: 'completed',
    finding_count: 3,
    started_at: '2026-05-14T10:05:00Z',
    ...overrides
  } as ScanRecord;
}

function renderOnboarding(ui: ReactElement, path: string) {
  return render(<MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>);
}

function setFeatureFlagEnv(enabled: boolean) {
  const env = (import.meta as unknown as { env: Record<string, string | undefined> }).env;
  const value = enabled ? 'true' : undefined;
  for (const key of [
    'VITE_FEATURE_ONBOARDING_WIZARD',
    'VITE_FEATURE_CONNECTOR_AWS',
    'VITE_FEATURE_CONNECTOR_GITHUB_V2',
    'VITE_FEATURE_CONNECTOR_K8S'
  ]) {
    if (value) {
      env[key] = value;
      vi.stubEnv(key, value);
    } else {
      delete env[key];
    }
  }
  if (!enabled) {
    vi.unstubAllEnvs();
  }
}

async function loadOnboardingModules() {
  vi.resetModules();
  setFeatureFlagEnv(true);
  vi.doMock('./onboardingUtils', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./onboardingUtils')>();
    return {
      ...actual,
      FEATURE_ONBOARDING_WIZARD: true,
      FEATURE_ONBOARDING_CONNECTOR_AWS: true,
      FEATURE_ONBOARDING_CONNECTOR_GITHUB: true,
      FEATURE_ONBOARDING_CONNECTOR_K8S: true
    };
  });

  const api = await import('../../api/client');
  const [org, workspace, connect, scanPage, invite] = await Promise.all([
    import('./OrgPage'),
    import('./WorkspacePage'),
    import('./ConnectPage'),
    import('./ScanPage'),
    import('./InvitePage')
  ]);

  return {
    apiClient: api.apiClient,
    OrgPage: org.OrgPage,
    WorkspacePage: workspace.WorkspacePage,
    ConnectPage: connect.ConnectPage,
    ScanPage: scanPage.ScanPage,
    InvitePage: invite.InvitePage
  };
}

describe('onboarding pages', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./onboardingUtils');
    setFeatureFlagEnv(false);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./onboardingUtils');
    vi.resetModules();
    setFeatureFlagEnv(false);
  });

  it('creates an organization and routes to workspace setup', async () => {
    const { apiClient, OrgPage } = await loadOnboardingModules();
    const startState = state({ current_step: 'org' });
    vi.spyOn(apiClient, 'startOnboarding').mockResolvedValue({ state: startState, redirect_path: '/onboarding/org' });
    vi.spyOn(apiClient, 'getMe').mockResolvedValue({
      me: {
        user: {
          id: 'user-1',
          primary_email: 'owner@example.com',
          display_name: 'Owner User',
          status: 'active',
          created_at: '2026-05-14T10:00:00Z',
          updated_at: '2026-05-14T10:00:00Z'
        }
      }
    });
    const update = vi.spyOn(apiClient, 'updateOnboardingState').mockResolvedValue({
      state: state({ current_step: 'workspace', org_id: 'owner-user-security' }),
      redirect_path: '/onboarding/workspace'
    });

    renderOnboarding(<OrgPage />, '/onboarding/org');

    const input = await screen.findByLabelText('Organization name');
    fireEvent.change(input, { target: { value: 'Aurelius Security' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create organization' }));

    await waitFor(() => {
      expect(update).toHaveBeenCalledWith({ current_step: 'org', org_name: 'Aurelius Security' });
    });
  });

  it('creates the workspace and default project', async () => {
    const { apiClient, WorkspacePage } = await loadOnboardingModules();
    vi.spyOn(apiClient, 'getOnboardingState').mockResolvedValue({
      state: state({ current_step: 'workspace', org_id: 'tenant-a' }),
      redirect_path: '/onboarding/workspace'
    });
    const update = vi.spyOn(apiClient, 'updateOnboardingState').mockResolvedValue({
      state: state({ current_step: 'connect', org_id: 'tenant-a', workspace_id: 'production', project_id: 'production' }),
      redirect_path: '/onboarding/connect'
    });

    renderOnboarding(<WorkspacePage />, '/onboarding/workspace');

    expect(await screen.findByRole('heading', { name: 'Name the environment you will secure first' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Workspace name'), { target: { value: 'Production' } });
    fireEvent.change(screen.getByLabelText('First project'), { target: { value: 'Identity Control Plane' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create workspace' }));

    await waitFor(() => {
      expect(update).toHaveBeenCalledWith({
        current_step: 'workspace',
        workspace_name: 'Production',
        project_name: 'Identity Control Plane'
      });
    });
  });

  it('records the selected connector source', async () => {
    const { apiClient, ConnectPage } = await loadOnboardingModules();
    vi.spyOn(apiClient, 'getOnboardingState').mockResolvedValue({
      state: state({
        current_step: 'connect',
        org_id: 'tenant-a',
        workspace_id: 'production',
        project_id: 'production'
      }),
      redirect_path: '/onboarding/connect'
    });
    const update = vi.spyOn(apiClient, 'updateOnboardingState').mockResolvedValue({
      state: state({
        current_step: 'scan',
        org_id: 'tenant-a',
        workspace_id: 'production',
        project_id: 'production',
        connector_type: 'github'
      }),
      redirect_path: '/onboarding/scan'
    });

    renderOnboarding(<ConnectPage />, '/onboarding/connect');

    fireEvent.click(await screen.findByRole('button', { name: /GitHubRepositories/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    await waitFor(() => {
      expect(update).toHaveBeenCalledWith({
        current_step: 'connect',
        connector_type: 'github',
        connector_skipped: false
      });
    });
  });

  it('continues after a successful first scan', async () => {
    const { apiClient, ScanPage } = await loadOnboardingModules();
    vi.spyOn(apiClient, 'getOnboardingState').mockResolvedValue({
      state: state({
        current_step: 'scan',
        org_id: 'tenant-a',
        workspace_id: 'production',
        project_id: 'production',
        connector_type: 'aws'
      }),
      redirect_path: '/onboarding/scan'
    });
    vi.spyOn(apiClient, 'listScans').mockResolvedValue({ items: [scan()] });
    const update = vi.spyOn(apiClient, 'updateOnboardingState').mockResolvedValue({
      state: state({
        current_step: 'invite',
        org_id: 'tenant-a',
        workspace_id: 'production',
        project_id: 'production',
        connector_type: 'aws'
      }),
      redirect_path: '/onboarding/invite'
    });

    renderOnboarding(<ScanPage />, '/onboarding/scan');

    expect(await screen.findByText('3 findings')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    await waitFor(() => {
      expect(update).toHaveBeenCalledWith({ current_step: 'scan' });
    });
  });

  it('invites teammates and completes onboarding', async () => {
    const { apiClient, InvitePage } = await loadOnboardingModules();
    vi.spyOn(apiClient, 'getOnboardingState').mockResolvedValue({
      state: state({
        current_step: 'invite',
        org_id: 'tenant-a',
        workspace_id: 'production',
        project_id: 'production'
      }),
      redirect_path: '/onboarding/invite'
    });
    const invite = vi.spyOn(apiClient, 'upsertWorkspaceMember').mockResolvedValue({
      member: {
        tenant_id: 'tenant-a',
        workspace_id: 'production',
        member_id: 'member-analyst-example-com',
        user_id: 'analyst@example.com',
        email: 'analyst@example.com',
        role: 'viewer',
        status: 'invited',
        joined_at: '2026-05-14T10:00:00Z',
        updated_at: '2026-05-14T10:00:00Z'
      }
    });
    const complete = vi.spyOn(apiClient, 'completeOnboarding').mockResolvedValue({
      state: state({
        current_step: 'complete',
        org_id: 'tenant-a',
        workspace_id: 'production',
        project_id: 'production',
        completed_at: '2026-05-14T10:15:00Z'
      }),
      redirect_path: '/app/tenant-a/production'
    });

    renderOnboarding(<InvitePage />, '/onboarding/invite');

    fireEvent.change(await screen.findByLabelText('Email addresses'), { target: { value: 'analyst@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Invite and finish' }));

    await waitFor(() => {
      expect(invite).toHaveBeenCalledWith(
        'production',
        expect.objectContaining({ email: 'analyst@example.com', role: 'viewer', status: 'invited' }),
        { tenantID: 'tenant-a', workspaceID: 'production' }
      );
      expect(complete).toHaveBeenCalled();
    });
  });
});
