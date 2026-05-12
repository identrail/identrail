import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { saveProductSession } from './productShell';

const OIDC_PENDING_LOGIN_STORAGE_KEY = 'identrail-oidc-pending-login';

function okJSON(payload: unknown) {
  return {
    ok: true,
    json: async () => payload
  };
}

function errorJSON(status: number, error: string) {
  return {
    ok: false,
    status,
    json: async () => ({ error })
  };
}

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

function setCurrentPath(pathname: string) {
  act(() => {
    window.history.pushState({}, '', pathname);
  });
}

describe('App', () => {
  beforeEach(() => {
    window.sessionStorage.removeItem('identrail-product-session');
    window.sessionStorage.removeItem(OIDC_PENDING_LOGIN_STORAGE_KEY);
    vi.unstubAllEnvs();
    vi.stubEnv('VITE_ALLOW_MANUAL_PRODUCT_SESSION', 'true');
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('renders homepage hero and conversion CTAs', () => {
    setCurrentPath('/');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Every machine identity path/i
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: 'Start Free Risk Scan' }).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Book Demo/i })).toBeInTheDocument();
    expect(screen.getAllByText(/Adoption Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Reachable Risk Paths/i).length).toBeGreaterThan(0);
    expect(
      screen.getByRole('heading', { level: 2, name: /From connector setup to evidence-ready remediation/i })
    ).toBeInTheDocument();
  });

  it('renders pricing page routes and key elements', () => {
    setCurrentPath('/pricing');
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
    setCurrentPath('/read-only-scan');
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
    setCurrentPath('/deployment-models');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Choose your control boundary without changing operating model/i
      })
    ).toBeInTheDocument();
  });

  it('renders integrations route', () => {
    setCurrentPath('/integrations');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Identity signal coverage across cloud, cluster, and code workflows/i
      })
    ).toBeInTheDocument();
  });

  it('renders ROI assessment route', () => {
    setCurrentPath('/roi-assessment');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Model risk-reduction impact with transparent assumptions/i
      })
    ).toBeInTheDocument();
  });

  it('renders full FAQ route', () => {
    setCurrentPath('/faq');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Technical and operational questions teams ask before rollout/i
      })
    ).toBeInTheDocument();
  });

  it('renders responsible disclosure route', () => {
    setCurrentPath('/responsible-disclosure');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Report security issues through a coordinated disclosure process/i
      })
    ).toBeInTheDocument();
  });

  it('guards product shell routes and redirects unauthenticated users to app login', () => {
    setCurrentPath('/app/default/default');
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
    vi.stubEnv('VITE_DEFAULT_PRODUCT_API_KEY', 'writer-key');
    setCurrentPath('/app/login');
    render(<App />);

    fireEvent.change(screen.getByLabelText(/Tenant ID/i), { target: { value: 'tenant-a' } });
    fireEvent.change(screen.getByLabelText(/Workspace ID/i), { target: { value: 'workspace-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Continue to app/i }));

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    expect(JSON.parse(window.sessionStorage.getItem('identrail-product-session') ?? '{}')).toMatchObject({
      apiKey: 'writer-key'
    });
  });

  it('rejects persisted manual workspace sessions in production builds', async () => {
    vi.stubEnv('VITE_ALLOW_MANUAL_PRODUCT_SESSION', 'false');
    window.sessionStorage.setItem(
      'identrail-product-session',
      JSON.stringify({
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a',
        authMode: 'manual'
      })
    );

    window.history.pushState({}, '', '/app/tenant-a/workspace-a');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to the Identrail app shell/i })).toBeInTheDocument();
    expect((await screen.findAllByText(/Manual workspace entry is disabled for this deployment/i)).length).toBeGreaterThan(0);
  });

  it('renders tenancy-scoped project detail placeholder route inside app shell', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });
    setCurrentPath('/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-1/i })).toBeInTheDocument();
    expect(await screen.findByText(/Project source onboarding/i)).toBeInTheDocument();
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

    setCurrentPath('/app/default/default/workspaces');
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

    setCurrentPath('/app/default/default/workspaces');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Members and roles/i })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Workspace'), { target: { value: 'payments' } });
    fireEvent.click(screen.getByRole('button', { name: /Switch workspace/i }));

    await waitFor(() => {
      expect(window.location.pathname).toBe('/app/default/payments/workspaces');
    });
  });

  it('ignores stale workspace member responses after scope changes', async () => {
    saveProductSession({
      tenantID: 'default',
      workspaceID: 'default'
    });

    let resolveInitialMembers: ((value: { ok: boolean; json: () => Promise<{ items: unknown[] }> }) => void) | undefined;
    const initialMembersResponse = new Promise<{ ok: boolean; json: () => Promise<{ items: unknown[] }> }>((resolve) => {
      resolveInitialMembers = resolve;
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
                member_id: 'member-payments-user',
                user_id: 'payments-user',
                email: 'payments@example.com',
                role: 'admin',
                status: 'active',
                joined_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              },
              is_active: false
            }
          ]
        })
      })
      .mockImplementationOnce(() => initialMembersResponse)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          principal: { type: 'subject', id: 'payments-user' },
          roles: ['admin'],
          scopes: ['read', 'write', 'admin'],
          scope: { tenant_id: 'default', workspace_id: 'payments' },
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
              member_id: 'member-payments-user',
              user_id: 'payments-user',
              email: 'payments@example.com',
              role: 'admin',
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
                workspace_id: 'payments',
                display_name: 'Payments',
                slug: 'payments',
                created_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              },
              member: {
                tenant_id: 'default',
                workspace_id: 'payments',
                member_id: 'member-payments-user',
                user_id: 'payments-user',
                email: 'payments@example.com',
                role: 'admin',
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
              workspace_id: 'payments',
              member_id: 'member-payments-user',
              user_id: 'payments-user',
              email: 'payments@example.com',
              role: 'admin',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-01T00:00:00Z'
            }
          ]
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/default/default/workspaces');
    render(<App />);

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    setCurrentPath('/app/default/payments/workspaces');
    act(() => {
      window.dispatchEvent(new PopStateEvent('popstate'));
    });

    expect(await screen.findByRole('heading', { level: 2, name: /Members and roles/i })).toBeInTheDocument();
    expect(await screen.findByText('payments-user')).toBeInTheDocument();

    resolveInitialMembers?.({
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
    });

    await waitFor(() => {
      expect(screen.getByText('payments-user')).toBeInTheDocument();
      expect(screen.queryByText('owner-user')).not.toBeInTheDocument();
    });
  });

  it('shows workspace admin load errors without redirecting to login', async () => {
    saveProductSession({
      tenantID: 'default',
      workspaceID: 'default'
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(errorJSON(403, 'workspace access denied')));

    setCurrentPath('/app/default/default/workspaces');
    render(<App />);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/workspace access denied/i);
    expect(window.location.pathname).toBe('/app/default/default/workspaces');
    expect(window.location.pathname).not.toBe('/app/login');
  });

  it('keeps existing member state when invite action fails', async () => {
    saveProductSession({
      tenantID: 'default',
      workspaceID: 'default'
    });

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        okJSON({
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
      )
      .mockResolvedValueOnce(
        okJSON({
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
      )
      .mockResolvedValueOnce(errorJSON(500, 'invite rejected'));
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/default/default/workspaces');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Members and roles/i })).toBeInTheDocument();
    expect(screen.getByText('owner-user')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('User ID'), { target: { value: 'analyst@example.com' } });
    fireEvent.change(screen.getByLabelText('Email (optional)'), { target: { value: 'analyst@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /Invite member/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/invite rejected/i);
    expect(screen.getByText('owner-user')).toBeInTheDocument();
    expect(screen.queryByText('member-analyst-example-com')).not.toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/default/default/workspaces');
  });

  it('redirects expired oidc sessions to login with re-auth prompt', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a',
      authMode: 'oidc',
      accessToken: 'access-token',
      expiresAt: Date.now() - 60_000
    });
    setCurrentPath('/app/tenant-a/workspace-a');
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

    setCurrentPath('/app/callback?code=code-1&state=state-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();

    const stored = JSON.parse(window.sessionStorage.getItem('identrail-product-session') ?? '{}');
    expect(stored.authMode).toBe('oidc');
    expect(stored.tenantID).toBe('tenant-oidc');
    expect(stored.workspaceID).toBe('workspace-oidc');
  });

  it('redirects to login with state_mismatch reason when oidc callback state is invalid', async () => {
    vi.stubEnv('VITE_OIDC_ISSUER_URL', 'https://sso.example.com/realms/identrail');
    vi.stubEnv('VITE_OIDC_CLIENT_ID', 'identrail-web');
    window.sessionStorage.setItem(
      OIDC_PENDING_LOGIN_STORAGE_KEY,
      JSON.stringify({
        state: 'expected-state',
        codeVerifier: 'verifier-1',
        nextPath: '/app/tenant-oidc/workspace-oidc',
        createdAt: Date.now()
      })
    );

    window.history.pushState({}, '', '/app/callback?code=code-1&state=wrong-state');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to the Identrail app shell/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/login');
    expect(window.location.search).toContain('reason=state_mismatch');
    expect(window.sessionStorage.getItem(OIDC_PENDING_LOGIN_STORAGE_KEY)).toBeNull();
    expect(window.sessionStorage.getItem('identrail-product-session')).toBeNull();
  });

  it('redirects to login with callback_error reason when oidc token exchange fails', async () => {
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
        ok: false,
        status: 400,
        json: async () => ({
          error: 'invalid_grant',
          error_description: 'authorization code expired'
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/callback?code=code-1&state=state-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to the Identrail app shell/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/login');
    expect(window.location.search).toContain('reason=callback_error');
    expect(window.sessionStorage.getItem(OIDC_PENDING_LOGIN_STORAGE_KEY)).toBeNull();
    expect(window.sessionStorage.getItem('identrail-product-session')).toBeNull();
  });

  it('redirects to login with callback_error reason when oidc token response misses access_token', async () => {
    vi.stubEnv('VITE_OIDC_ISSUER_URL', 'https://sso.example.com/realms/identrail');
    vi.stubEnv('VITE_OIDC_CLIENT_ID', 'identrail-web');
    window.sessionStorage.setItem(
      OIDC_PENDING_LOGIN_STORAGE_KEY,
      JSON.stringify({
        state: 'state-2',
        codeVerifier: 'verifier-2',
        nextPath: '/app/tenant-oidc/workspace-oidc',
        createdAt: Date.now()
      })
    );

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
          refresh_token: 'refresh-1',
          expires_in: 3600
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/callback?code=code-2&state=state-2');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to the Identrail app shell/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/login');
    expect(window.location.search).toContain('reason=callback_error');
    expect(window.sessionStorage.getItem(OIDC_PENDING_LOGIN_STORAGE_KEY)).toBeNull();
    expect(window.sessionStorage.getItem('identrail-product-session')).toBeNull();
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

    setCurrentPath('/app/tenant-a/workspace-a');
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

    setCurrentPath('/app/logout');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to the Identrail app shell/i })).toBeInTheDocument();
    expect(await screen.findByText(/Signed out successfully/i)).toBeInTheDocument();
  });
});
