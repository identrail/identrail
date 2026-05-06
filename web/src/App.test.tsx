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

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
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
        name: 'Every machine identity path, clear to you.'
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: 'Start Free Risk Scan' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: 'Book Demo' }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Adoption Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Reachable Risk Paths/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('heading', { level: 2, name: /From connector setup to board-ready risk evidence/i })).toBeInTheDocument();
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

  it('routes overview onboarding into the real project selection flow', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });

    window.history.pushState({}, '', '/app/tenant-a/workspace-a');
    render(<App />);

    const selectProjectLink = await screen.findByRole('link', { name: /Select project/i });
    expect(selectProjectLink).toHaveAttribute('href', '/app/tenant-a/workspace-a/projects');
  });

  it('lists workspace projects and links them to concrete source onboarding routes', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        items: [
          {
            tenant_id: 'tenant-a',
            workspace_id: 'workspace-a',
            project_id: 'project-1',
            name: 'Production platform',
            slug: 'production-platform',
            description: 'Primary production boundary',
            created_at: '2026-05-04T10:00:00Z',
            updated_at: '2026-05-05T10:00:00Z'
          }
        ]
      })
    });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Choose a project before connecting source data/i })).toBeInTheDocument();
    expect(screen.getByText('Production platform')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Manage sources/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/projects/project-1'
    );
  });

  it('renders tenancy-scoped connect-source wizard inside app shell', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'github_app',
            connected: false,
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'kubernetes',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            permission_checks: [],
            diagnostics: []
          }
        })
      });
    vi.stubGlobal('fetch', fetchMock);
    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-1/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Generate install link/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /AWS/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Kubernetes/i })).toBeInTheDocument();
  });

  it('ignores stale project refresh responses after route changes', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });

    const project1GitHub = deferred<Response>();
    const project1AWS = deferred<Response>();
    const project1Kubernetes = deferred<Response>();
    const project2GitHub = deferred<Response>();
    const project2AWS = deferred<Response>();
    const project2Kubernetes = deferred<Response>();

    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => project1GitHub.promise)
      .mockImplementationOnce(() => project1AWS.promise)
      .mockImplementationOnce(() => project1Kubernetes.promise)
      .mockImplementationOnce(() => project2GitHub.promise)
      .mockImplementationOnce(() => project2AWS.promise)
      .mockImplementationOnce(() => project2Kubernetes.promise);
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-2');
    window.dispatchEvent(new PopStateEvent('popstate'));

    project2GitHub.resolve({
      ok: true,
      json: async () => ({
        connection: {
          provider: 'github_app',
          connected: true,
          account_login: 'project-2-org',
          installation_id: 22,
          token_reference: 'github-app-installation:22',
          webhook_secret_reference: 'github-webhook:project-2:22',
          webhook_secret_rotation_required: false,
          selected_repositories: ['identrail/project-2'],
          updated_at: '2026-05-05T10:05:00Z'
        }
      })
    } as Response);
    project2AWS.resolve({
      ok: true,
      json: async () => ({
        connection: {
          provider: 'aws',
          connected: false,
          status: 'pending',
          health_status: 'unknown',
          external_id_configured: false,
          permission_checks: [],
          diagnostics: []
        }
      })
    } as Response);
    project2Kubernetes.resolve({
      ok: true,
      json: async () => ({
        connection: {
          provider: 'kubernetes',
          connected: false,
          status: 'pending',
          health_status: 'unknown',
          permission_checks: [],
          diagnostics: []
        }
      })
    } as Response);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-2/i })).toBeInTheDocument();
    expect(await screen.findByText(/Account project-2-org/i)).toBeInTheDocument();

    project1GitHub.resolve({
      ok: true,
      json: async () => ({
        connection: {
          provider: 'github_app',
          connected: true,
          account_login: 'project-1-org',
          installation_id: 11,
          token_reference: 'github-app-installation:11',
          webhook_secret_reference: 'github-webhook:project-1:11',
          webhook_secret_rotation_required: false,
          selected_repositories: ['identrail/project-1'],
          updated_at: '2026-05-05T09:55:00Z'
        }
      })
    } as Response);
    project1AWS.resolve({
      ok: true,
      json: async () => ({
        connection: {
          provider: 'aws',
          connected: false,
          status: 'pending',
          health_status: 'unknown',
          external_id_configured: false,
          permission_checks: [],
          diagnostics: []
        }
      })
    } as Response);
    project1Kubernetes.resolve({
      ok: true,
      json: async () => ({
        connection: {
          provider: 'kubernetes',
          connected: false,
          status: 'pending',
          health_status: 'unknown',
          permission_checks: [],
          diagnostics: []
        }
      })
    } as Response);

    await waitFor(() => {
      expect(screen.queryByText(/Account project-1-org/i)).not.toBeInTheDocument();
    });
    expect(screen.getByText(/Account project-2-org/i)).toBeInTheDocument();
  });

  it('ignores stale connector submit responses after project navigation', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });

    let staleAWSResponseParsed = false;
    const staleAWSSubmit = deferred<Response>();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'github_app',
            connected: false,
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'kubernetes',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockImplementationOnce(() => staleAWSSubmit.promise)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'github_app',
            connected: false,
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'kubernetes',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            permission_checks: [],
            diagnostics: []
          }
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-1/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /AWS/i }));
    fireEvent.change(screen.getByLabelText('Role ARN'), {
      target: { value: 'arn:aws:iam::123456789012:role/IdentrailReadOnly' }
    });
    fireEvent.click(screen.getByRole('button', { name: /Validate and save AWS/i }));

    await act(async () => {
      window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-2');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-2/i })).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Refresh status/i })).not.toBeDisabled();
    });
    expect(screen.getByRole('button', { name: /Validate and save AWS/i })).not.toBeDisabled();

    await act(async () => {
      staleAWSSubmit.resolve({
        ok: true,
        json: async () => {
          staleAWSResponseParsed = true;
          return {
            connection: {
              provider: 'aws',
              connected: true,
              status: 'active',
              health_status: 'healthy',
              role_arn: 'arn:aws:iam::123456789012:role/IdentrailReadOnly',
              external_id_configured: false,
              permission_checks: [],
              diagnostics: []
            }
          };
        }
      } as Response);
      await staleAWSSubmit.promise;
    });

    await waitFor(() => {
      expect(staleAWSResponseParsed).toBe(true);
    });

    expect(screen.queryByText(/AWS connector is active\./i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Validate and save AWS/i })).not.toBeDisabled();
  });

  it('validates and saves an AWS source from the connect-source wizard', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'github_app',
            connected: false,
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'kubernetes',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'aws',
            connected: true,
            status: 'active',
            health_status: 'healthy',
            role_arn: 'arn:aws:iam::123456789012:role/IdentrailReadOnly',
            external_id_configured: true,
            account_id: '123456789012',
            region: 'us-east-1',
            permission_checks: [{ name: 'sts:AssumeRole', passed: true, message: 'Role assumption succeeded.' }],
            diagnostics: [],
            last_validated_at: '2026-05-05T10:00:00Z'
          }
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-1/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /AWS/i }));
    fireEvent.change(screen.getByLabelText('Role ARN'), {
      target: { value: 'arn:aws:iam::123456789012:role/IdentrailReadOnly' }
    });
    fireEvent.change(screen.getByLabelText('External ID'), { target: { value: 'external-prod' } });
    fireEvent.click(screen.getByRole('button', { name: /Validate and save AWS/i }));

    expect(await screen.findByText(/AWS connector is active/i)).toBeInTheDocument();
    const postCall = fetchMock.mock.calls.find(([url, options]) => {
      return typeof url === 'string' && url.includes('/projects/project-1/aws/connection') && options?.method === 'POST';
    });
    expect(postCall).toBeDefined();
    expect(postCall?.[1]?.body).toContain('external-prod');
  });

  it('starts and completes a GitHub source from the connect-source wizard', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'github_app',
            connected: false,
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'kubernetes',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            state: 'state-123',
            connect_url: 'https://github.com/apps/identrail/installations/new?state=state-123',
            expires_at: '2026-05-05T10:10:00Z'
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'github_app',
            connected: true,
            account_login: 'identrail',
            installation_id: 77,
            token_reference: 'github-app-installation:77',
            webhook_secret_reference: 'github-webhook:project-1:77',
            webhook_secret_rotation_required: false,
            selected_repositories: ['identrail/identrail'],
            updated_at: '2026-05-05T10:05:00Z'
          }
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-1/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Generate install link/i }));
    expect(await screen.findByText(/GitHub installation link generated/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open GitHub/i })).toHaveAttribute('href', expect.stringContaining('state-123'));

    fireEvent.change(screen.getByLabelText('Installation ID'), { target: { value: '77' } });
    fireEvent.change(screen.getByLabelText('Account login'), { target: { value: 'identrail' } });
    fireEvent.change(screen.getByLabelText('Selected repositories'), { target: { value: 'Identrail/Identrail' } });
    fireEvent.click(screen.getByRole('button', { name: /Save GitHub connection/i }));

    expect(await screen.findByText(/GitHub connection saved/i)).toBeInTheDocument();
    const completeCall = fetchMock.mock.calls.find(([url, options]) => {
      return typeof url === 'string' && url.includes('/projects/project-1/github/connect/complete') && options?.method === 'POST';
    });
    expect(completeCall).toBeDefined();
    expect(completeCall?.[1]?.body).toContain('"selected_repositories":["identrail/identrail"]');
  });

  it('runs Kubernetes preflight from the connect-source wizard', async () => {
    saveProductSession({
      tenantID: 'tenant-a',
      workspaceID: 'workspace-a'
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'github_app',
            connected: false,
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'kubernetes',
            connected: false,
            status: 'pending',
            health_status: 'unknown',
            permission_checks: [],
            diagnostics: []
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          connection: {
            provider: 'kubernetes',
            connected: true,
            status: 'active',
            health_status: 'healthy',
            display_name: 'Production cluster',
            context: 'prod',
            cluster: 'prod-cluster',
            server: 'https://kubernetes.example.test',
            permission_checks: [
              {
                verb: 'list',
                resource: 'pods',
                scope: 'cluster',
                allowed: true
              }
            ],
            diagnostics: [],
            last_validated_at: '2026-05-05T10:00:00Z'
          }
        })
      });
    vi.stubGlobal('fetch', fetchMock);

    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-1/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Kubernetes/i }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Production cluster' } });
    fireEvent.change(screen.getByLabelText('kubectl context'), { target: { value: 'prod' } });
    fireEvent.click(screen.getByRole('button', { name: /Run preflight and save/i }));

    expect(await screen.findByText(/Kubernetes connector is active/i)).toBeInTheDocument();
    expect(screen.getByText(/prod-cluster/i)).toBeInTheDocument();
    const postCall = fetchMock.mock.calls.find(([url, options]) => {
      return typeof url === 'string' && url.includes('/projects/project-1/kubernetes/connection') && options?.method === 'POST';
    });
    expect(postCall).toBeDefined();
    expect(postCall?.[1]?.body).toContain('"context":"prod"');
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

  it('shows workspace admin load errors without redirecting to login', async () => {
    saveProductSession({
      tenantID: 'default',
      workspaceID: 'default'
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(errorJSON(403, 'workspace access denied')));

    window.history.pushState({}, '', '/app/default/default/workspaces');
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

    window.history.pushState({}, '', '/app/default/default/workspaces');
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
    window.history.pushState({}, '', '/app/tenant-a/workspace-a');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to the Identrail app shell/i })).toBeInTheDocument();
    expect(await screen.findByText(/Your session expired/i)).toBeInTheDocument();
  });

  it('redirects persisted oidc sessions without tokens back to login after reload', async () => {
    window.sessionStorage.setItem(
      'identrail-product-session',
      JSON.stringify({
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a',
        authMode: 'oidc',
        expiresAt: Date.now() + 60_000
      })
    );

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
