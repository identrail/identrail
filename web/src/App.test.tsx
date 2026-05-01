import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { saveProductSession } from './productShell';

const OIDC_PENDING_LOGIN_STORAGE_KEY = 'identrail-oidc-pending-login';

function makeJWT(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  return `${header}.${body}.signature`;
}

describe('App', () => {
  beforeEach(() => {
    window.sessionStorage.removeItem('identrail-product-session');
    window.sessionStorage.removeItem(OIDC_PENDING_LOGIN_STORAGE_KEY);
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('renders homepage hero and conversion CTAs', () => {
    window.history.pushState({}, '', '/');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Identify risky machine trust paths before they become incidents.'
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: 'Start Free Risk Scan' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: 'Book Demo' }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Adoption Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Reachable Risk Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('tab', { name: 'Graph' }).length).toBeGreaterThan(0);
  });

  it('renders pricing page routes and key elements', () => {
    window.history.pushState({}, '', '/pricing');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Pricing aligned to how teams adopt machine identity security/i
      })
    ).toBeInTheDocument();

    expect(screen.getByRole('button', { name: /Annual/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Contact Sales' })).toBeInTheDocument();
  });

  it('renders read-only scan intake flow route', () => {
    window.history.pushState({}, '', '/read-only-scan');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Start a machine identity risk scan with deployment-safe onboarding/i
      })
    ).toBeInTheDocument();

    expect(screen.getByText(/Step 1 of 3/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeInTheDocument();
  });

  it('renders deployment models route', () => {
    window.history.pushState({}, '', '/deployment-models');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Choose your control boundary without changing operating model/i
      })
    ).toBeInTheDocument();
  });

  it('renders integrations route', () => {
    window.history.pushState({}, '', '/integrations');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Identity signal coverage across cloud, cluster, and code workflows/i
      })
    ).toBeInTheDocument();
  });

  it('renders ROI assessment route', () => {
    window.history.pushState({}, '', '/roi-assessment');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Model risk-reduction impact with transparent assumptions/i
      })
    ).toBeInTheDocument();
  });

  it('renders full FAQ route', () => {
    window.history.pushState({}, '', '/faq');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Technical and operational questions teams ask before rollout/i
      })
    ).toBeInTheDocument();
  });

  it('renders responsible disclosure route', () => {
    window.history.pushState({}, '', '/responsible-disclosure');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Report security issues through a coordinated disclosure process/i
      })
    ).toBeInTheDocument();
  });

  it('guards product shell routes and redirects unauthenticated users to app login', () => {
    window.history.pushState({}, '', '/app/default/default');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Sign in to the Identrail app shell/i
      })
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/login');
    expect(window.location.search).toContain('next=%2Fapp%2Fdefault%2Fdefault');
  });

  it('loads authenticated product shell placeholders after login', async () => {
    window.history.pushState({}, '', '/app/login');
    render(<App />);

    fireEvent.change(screen.getByLabelText(/Tenant ID/i), { target: { value: 'tenant-a' } });
    fireEvent.change(screen.getByLabelText(/Workspace ID/i), { target: { value: 'workspace-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Continue to app/i }));

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
  });

  it('renders tenancy-scoped project detail placeholder route inside app shell', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });
    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Project detail/i })).toBeInTheDocument();
    expect(await screen.findByText(/Project project-1 placeholder/i)).toBeInTheDocument();
  });

  it('supports workspace member invite workflow from app shell administration route', async () => {
    saveProductSession({
      tenantID: 'default',
      workspaceID: 'default'
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          principal: { type: 'subject', id: 'owner-user' },
          roles: ['owner'],
          scopes: ['read', 'write', 'admin'],
          scope: { tenant_id: 'default', workspace_id: 'default' },
          active_workspace: {
            workspace: {
              tenant_id: 'default',
              workspace_id: 'default',
              display_name: 'Default',
              slug: 'default',
              created_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            },
            member: {
              tenant_id: 'default',
              workspace_id: 'default',
              member_id: 'member-owner-user',
              user_id: 'owner-user',
              email: 'owner@example.com',
              role: 'owner',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            },
            is_active: true
          },
          workspaces: [
            {
              workspace: {
                tenant_id: 'default',
                workspace_id: 'default',
                display_name: 'Default',
                slug: 'default',
                created_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              },
              member: {
                tenant_id: 'default',
                workspace_id: 'default',
                member_id: 'member-owner-user',
                user_id: 'owner-user',
                email: 'owner@example.com',
                role: 'owner',
                status: 'active',
                joined_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              },
              is_active: true
            }
          ]
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          items: [
            {
              tenant_id: 'default',
              workspace_id: 'default',
              member_id: 'member-owner-user',
              user_id: 'owner-user',
              email: 'owner@example.com',
              role: 'owner',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            }
          ]
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          member: {
            tenant_id: 'default',
            workspace_id: 'default',
            member_id: 'member-analyst-example-com',
            user_id: 'analyst@example.com',
            email: 'analyst@example.com',
            role: 'viewer',
            status: 'invited',
            joined_at: '2026-01-02T00:00:00Z',
            updated_at: '2026-01-02T00:00:00Z'
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          items: [
            {
              tenant_id: 'default',
              workspace_id: 'default',
              member_id: 'member-owner-user',
              user_id: 'owner-user',
              email: 'owner@example.com',
              role: 'owner',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            },
            {
              tenant_id: 'default',
              workspace_id: 'default',
              member_id: 'member-analyst-example-com',
              user_id: 'analyst@example.com',
              email: 'analyst@example.com',
              role: 'viewer',
              status: 'invited',
              joined_at: '2026-01-02T00:00:00Z',
              updated_at: '2026-01-02T00:00:00Z'
            }
          ]
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/default/default/workspaces');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Members and roles/i })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('User ID'), { target: { value: 'analyst@example.com' } });
    fireEvent.change(screen.getByLabelText('Email (optional)'), { target: { value: 'analyst@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /Invite member/i }));

    await screen.findByText(/Member invitation saved/i);
    expect(screen.getAllByText('analyst@example.com').length).toBeGreaterThan(0);

    const inviteCall = fetchMock.mock.calls.find(([url, options]) => {
      return typeof url === 'string' && url.includes('/v1/workspaces/default/members') && options?.method === 'POST';
    });
    expect(inviteCall).toBeDefined();
  });

  it('switches workspace context from workspaces admin route', async () => {
    saveProductSession({
      tenantID: 'default',
      workspaceID: 'default'
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          principal: { type: 'subject', id: 'owner-user' },
          roles: ['owner'],
          scopes: ['read', 'write', 'admin'],
          scope: { tenant_id: 'default', workspace_id: 'default' },
          active_workspace: {
            workspace: {
              tenant_id: 'default',
              workspace_id: 'default',
              display_name: 'Default',
              slug: 'default',
              created_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            },
            member: {
              tenant_id: 'default',
              workspace_id: 'default',
              member_id: 'member-owner-user',
              user_id: 'owner-user',
              email: 'owner@example.com',
              role: 'owner',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            },
            is_active: true
          },
          workspaces: [
            {
              workspace: {
                tenant_id: 'default',
                workspace_id: 'default',
                display_name: 'Default',
                slug: 'default',
                created_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              },
              member: {
                tenant_id: 'default',
                workspace_id: 'default',
                member_id: 'member-owner-user',
                user_id: 'owner-user',
                email: 'owner@example.com',
                role: 'owner',
                status: 'active',
                joined_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              },
              is_active: true
            },
            {
              workspace: {
                tenant_id: 'default',
                workspace_id: 'payments',
                display_name: 'Payments',
                slug: 'payments',
                created_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              },
              member: {
                tenant_id: 'default',
                workspace_id: 'payments',
                member_id: 'member-owner-user',
                user_id: 'owner-user',
                email: 'owner@example.com',
                role: 'owner',
                status: 'active',
                joined_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              },
              is_active: false
            }
          ]
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ items: [] })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          active_workspace: {
            workspace: {
              tenant_id: 'default',
              workspace_id: 'payments',
              display_name: 'Payments',
              slug: 'payments',
              created_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            },
            member: {
              tenant_id: 'default',
              workspace_id: 'payments',
              member_id: 'member-owner-user',
              user_id: 'owner-user',
              email: 'owner@example.com',
              role: 'owner',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            },
            is_active: true
          },
          scope: { tenant_id: 'default', workspace_id: 'payments' },
          scope_headers: {
            'X-Identrail-Tenant-ID': 'default',
            'X-Identrail-Workspace-ID': 'payments'
          }
        })
      })
      .mockResolvedValue({
        ok: true,
        json: async () => ({ items: [] })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/default/default/workspaces');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Members and roles/i })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Workspace'), { target: { value: 'payments' } });
    fireEvent.click(screen.getByRole('button', { name: /Switch workspace/i }));

    await waitFor(() => {
      expect(window.location.pathname).toBe('/app/default/payments/workspaces');
    });
  });

  it('redirects expired oidc sessions to login with re-auth prompt', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a',
      authMode: 'oidc',
      accessToken: 'access-token',
      expiresAt: Date.now() - 60_000
    });
    window.history.pushState({}, '', '/app/tenant-a/workspace-a');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to the Identrail app shell/i })).toBeInTheDocument();
    expect(await screen.findByText(/Your session expired/i)).toBeInTheDocument();
  });

  it('completes oidc callback and restores authenticated workspace shell', async () => {
    vi.stubEnv('VITE_OIDC_ISSUER_URL', 'https://sso.example.com/realms/identrail');
    vi.stubEnv('VITE_OIDC_CLIENT_ID', 'identrail-web');
    window.sessionStorage.setItem(
      OIDC_PENDING_LOGIN_STORAGE_KEY,
      JSON.stringify({
        state: 'state-1',
        codeVerifier: 'verifier-1',
        nextPath: '/app/tenant-oidc/workspace-oidc',
        createdAt: Date.now()
      })
    );

    const idToken = makeJWT({
      sub: 'user-123',
      tenant_id: 'tenant-oidc',
      workspace_id: 'workspace-oidc',
      roles: ['owner'],
      exp: Math.floor(Date.now() / 1000) + 3600
    });
    const accessToken = makeJWT({
      sub: 'user-123',
      tenant_id: 'tenant-oidc',
      workspace_id: 'workspace-oidc',
      exp: Math.floor(Date.now() / 1000) + 3600
    });

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          authorization_endpoint: 'https://sso.example.com/auth',
          token_endpoint: 'https://sso.example.com/token',
          end_session_endpoint: 'https://sso.example.com/logout'
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: accessToken,
          refresh_token: 'refresh-1',
          id_token: idToken,
          expires_in: 3600
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/callback?code=code-1&state=state-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();

    const stored = JSON.parse(window.sessionStorage.getItem('identrail-product-session') ?? '{}');
    expect(stored.authMode).toBe('oidc');
    expect(stored.tenantID).toBe('tenant-oidc');
    expect(stored.workspaceID).toBe('workspace-oidc');
  });

  it('refreshes oidc sessions before expiry in route guard', async () => {
    vi.stubEnv('VITE_OIDC_ISSUER_URL', 'https://sso.example.com/realms/identrail');
    vi.stubEnv('VITE_OIDC_CLIENT_ID', 'identrail-web');

    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a',
      authMode: 'oidc',
      accessToken: makeJWT({
        sub: 'user-1',
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        exp: Math.floor(Date.now() / 1000) + 20
      }),
      refreshToken: 'refresh-token',
      expiresAt: Date.now() + 20_000
    });

    const refreshedAccessToken = makeJWT({
      sub: 'user-1',
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      exp: Math.floor(Date.now() / 1000) + 3600
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          authorization_endpoint: 'https://sso.example.com/auth',
          token_endpoint: 'https://sso.example.com/token'
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: refreshedAccessToken,
          refresh_token: 'refresh-token-2',
          expires_in: 3600
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/tenant-a/workspace-a');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();
    await waitFor(() => {
      const session = JSON.parse(window.sessionStorage.getItem('identrail-product-session') ?? '{}');
      expect(session.tenantID).toBe('tenant-a');
      expect(session.authMode).toBe('oidc');
    });
  });

  it('returns to login after app logout when oidc end-session endpoint is unavailable', async () => {
    vi.stubEnv('VITE_OIDC_ISSUER_URL', 'https://sso.example.com/realms/identrail');
    vi.stubEnv('VITE_OIDC_CLIENT_ID', 'identrail-web');
    vi.stubEnv('VITE_OIDC_POST_LOGOUT_REDIRECT_URI', 'https://app.identrail.com/app/login?signed_out=1');

    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a',
      authMode: 'oidc',
      idToken: makeJWT({
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 3600
      })
    });

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          authorization_endpoint: 'https://sso.example.com/auth',
          token_endpoint: 'https://sso.example.com/token'
        })
      })
    );

    window.history.pushState({}, '', '/app/logout');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to the Identrail app shell/i })).toBeInTheDocument();
    expect(await screen.findByText(/Signed out successfully/i)).toBeInTheDocument();
  });
});
