import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';

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

function authConfig(manualMode = false, workOSLoginEnabled = true) {
  return okJSON({
    auth: {
      manual_mode: manualMode,
      workos_login_enabled: workOSLoginEnabled,
      native_saml_enabled: false,
      providers: workOSLoginEnabled ? ['github_oauth', 'google_oauth', 'authkit'] : []
    }
  });
}

function currentMePayload(tenantID = 'default', workspaceID = 'default', role = 'owner') {
  return {
    me: {
      user: {
        id: 'user-1',
        primary_email: 'owner@example.com',
        display_name: 'Owner User',
        status: 'active',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      },
      org_id: tenantID,
      workspace_id: workspaceID,
      role
    }
  };
}

function setCurrentPath(pathname: string) {
  act(() => {
    window.history.pushState({}, '', pathname);
  });
}

describe('App', () => {
  beforeEach(() => {
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
        name: /Start a read-only identity risk scan/i
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

  it('renders Google user data disclosures on the privacy route', () => {
    setCurrentPath('/privacy');
    render(<App />);

    expect(screen.getByRole('heading', { level: 1, name: /Privacy Policy/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /Google user data disclosure/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: /Google sign-in data accessed/i })).toBeInTheDocument();
    expect(screen.getByText(/Identrail does not use Google sign-in to access Gmail/i)).toBeInTheDocument();
    expect(screen.getByText(/Google API Services User Data Policy/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /security@identrail.com/i })).toHaveAttribute(
      'href',
      'mailto:security@identrail.com?subject=Privacy%20Request'
    );
  });

  it('renders standardized terms of use content on the terms route', () => {
    setCurrentPath('/terms');
    render(<App />);

    expect(screen.getByRole('heading', { level: 1, name: /Terms of Use/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /Standard terms/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: /Acceptance and scope/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: /Acceptable use/i })).toBeInTheDocument();
    expect(screen.getByText(/Customer data and integrations/i)).toBeInTheDocument();
    expect(screen.getByText(/Questions about these Terms of Use can be sent to security@identrail.com/i)).toBeInTheDocument();
  });

  it('guards product shell routes and redirects unauthenticated users to sign-in', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(errorJSON(401, 'unauthorized'))
        .mockResolvedValueOnce(authConfig(false, true))
    );
    setCurrentPath('/app/default/default');
    render(<App />);

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: /Log in to Identrail/i
      })
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/signin');
    expect(window.location.search).toContain('return_to=%2Fapp%2Fdefault%2Fdefault');
  });

  it('creates a dev manual cookie session and loads the product overview', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/auth/config')) {
        return authConfig(true, false);
      }
      if (url.endsWith('/auth/manual')) {
        return okJSON({ ok: true, redirect_to: '/app/tenant-a/workspace-a' });
      }
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.includes('/v1/workspaces/workspace-a/projects')) {
        if (url.includes('include_archived=true')) {
          return okJSON({
            items: [
              {
                tenant_id: 'tenant-a',
                workspace_id: 'workspace-a',
                project_id: 'legacy-project',
                name: 'Legacy GitHub',
                slug: 'legacy-github',
                description: 'Archived repository coverage.',
                archived_at: '2026-01-01T00:00:00Z',
                created_at: '2025-12-01T00:00:00Z',
                updated_at: '2026-01-01T00:00:00Z'
              }
            ]
          });
        }
        return okJSON({
          items: [
            {
              tenant_id: 'tenant-a',
              workspace_id: 'workspace-a',
              project_id: 'project-1',
              name: 'Production GitHub',
              slug: 'production-github',
              description: 'Repositories that feed production identity risk.',
              created_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-02T00:00:00Z'
            }
          ]
        });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({
          items: [
            {
              id: 'repo-scan-1',
              repository: 'owner/repo',
              status: 'succeeded',
              started_at: '2026-01-02T00:00:00Z',
              finished_at: '2026-01-02T00:05:00Z',
              commits_scanned: 12,
              files_scanned: 4,
              finding_count: 1,
              truncated: false
            }
          ]
        });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({
          items: [
            {
              scan_id: 'repo-scan-0',
              started_at: '2026-01-01T00:00:00Z',
              total: 10,
              by_severity: { critical: 1, high: 3, medium: 3, low: 2, info: 1 }
            },
            {
              scan_id: 'repo-scan-1',
              started_at: '2026-01-02T00:00:00Z',
              total: 4,
              by_severity: { critical: 0, high: 1, medium: 2, low: 1, info: 0 }
            }
          ]
        });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({
          items: [
            {
              id: 'repo-f1',
              scan_id: 'repo-scan-1',
              type: 'secret_exposure',
              severity: 'high',
              title: 'Potential AWS access key exposed in commit history',
              human_summary: 'A line added in commit history appears to contain an AWS access key identifier.',
              repository: 'owner/repo',
              file_path: 'config/app.env',
              line_number: 7,
              remediation: 'Rotate the key and move the credential to a secret manager.',
              created_at: '2026-01-02T00:00:00Z'
            }
          ]
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/signin');
    render(<App />);

    fireEvent.change(await screen.findByLabelText(/Tenant ID/i), { target: { value: 'tenant-a' } });
    fireEvent.change(screen.getByLabelText(/Workspace ID/i), { target: { value: 'workspace-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Continue in dev mode/i }));

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();
    expect(await screen.findByText(/Open risk/i)).toBeInTheDocument();
    expect(await screen.findByText(/Priority findings/i)).toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    expect(await screen.findByText(/Production GitHub/i)).toBeInTheDocument();
    expect(await screen.findByText(/1 archived/i)).toBeInTheDocument();
    expect(await screen.findByText(/Latest scan total 4/i)).toBeInTheDocument();
    expect(await screen.findByText('-6')).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some(([url]) => {
        return (
          typeof url === 'string' &&
          url.includes('/v1/workspaces/workspace-a/projects') &&
          url.includes('include_archived=false')
        );
      })
    ).toBe(true);
    expect(
      fetchMock.mock.calls.some(([url]) => {
        return (
          typeof url === 'string' &&
          url.includes('/v1/repo-findings') &&
          url.includes('sort_by=severity') &&
          url.includes('sort_order=desc')
        );
      })
    ).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8080/auth/manual',
      expect.objectContaining({ credentials: 'include' })
    );
  });

  it('keeps the overview trend delta neutral until two trend points exist', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.includes('/v1/workspaces/workspace-a/projects')) {
        return okJSON({
          items: [
            {
              tenant_id: 'tenant-a',
              workspace_id: 'workspace-a',
              project_id: 'project-1',
              name: 'Production GitHub',
              slug: 'production-github',
              description: 'Repositories that feed production identity risk.',
              created_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-02T00:00:00Z'
            }
          ]
        });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({
          items: [
            {
              scan_id: 'repo-scan-1',
              started_at: '2026-01-02T00:00:00Z',
              total: 12,
              by_severity: { critical: 1, high: 2, medium: 4, low: 4, info: 1 }
            }
          ]
        });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a');
    render(<App />);

    expect(await screen.findByText(/Trend delta/i)).toBeInTheDocument();
    expect(await screen.findByText('N/A')).toBeInTheDocument();
    expect(await screen.findByText(/Latest scan total 12; awaiting another scan/i)).toBeInTheDocument();
    expect(screen.queryByText('+12')).not.toBeInTheDocument();
  });

  it('hides manual workspace entry when auth config disables manual mode', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(authConfig(false, true)));

    setCurrentPath('/signin?return_to=/app/team/workspace');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Log in to Identrail/i })).toBeInTheDocument();
    expect(screen.queryByLabelText(/Tenant ID/i)).not.toBeInTheDocument();
    const hostedSignIn = screen.getByRole('link', { name: /Continue with Google/i });
    expect(hostedSignIn).toBeInTheDocument();
    expect(hostedSignIn).toHaveAttribute(
      'href',
      `http://localhost:8080/auth/login?return_to=${encodeURIComponent(`${window.location.origin}/app/team/workspace`)}&provider=google_oauth`
    );
  });

  it('does not show loading copy or provider actions while auth config loads', () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(() => new Promise(() => {})));

    setCurrentPath('/signup');
    render(<App />);

    expect(screen.getByRole('heading', { level: 1, name: /Your first trust graph/i })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Continue with Google/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Continue with GitHub/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Continue with SAML SSO/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/Loading authentication/i)).not.toBeInTheDocument();
  });

  it('keeps the auth theme trigger icon-only while exposing named menu choices', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(authConfig(false, true)));

    setCurrentPath('/signup');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Your first trust graph/i })).toBeInTheDocument();
    const themeTrigger = screen.getByRole('button', { name: /Color theme: Dark/i });
    expect(themeTrigger.textContent).toBe('');

    fireEvent.click(themeTrigger);

    expect(screen.getByRole('menuitemradio', { name: /Light/i })).toBeInTheDocument();
    expect(screen.getByRole('menuitemradio', { name: /System/i })).toBeInTheDocument();
    expect(screen.getByRole('menuitemradio', { name: /Dark/i })).toBeInTheDocument();
  });

  it('renders the GitHub provider mark on the light sign-up page', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(authConfig(false, true)));

    setCurrentPath('/signup');
    render(<App />);

    const themeTrigger = screen.getByRole('button', { name: /Color theme: Dark/i });
    fireEvent.click(themeTrigger);
    fireEvent.click(screen.getByRole('menuitemradio', { name: /Light/i }));
    expect(await screen.findByRole('button', { name: /Color theme: Light/i })).toBeInTheDocument();

    const githubProvider = await screen.findByRole('link', { name: /Continue with GitHub/i });
    const githubIcon = githubProvider.querySelector('.idt-auth-provider-icon-github');

    expect(githubIcon).toBeInTheDocument();
    expect(githubIcon).toHaveAttribute('src', '/brand-logos/github.svg');
  });

  it('shows a clear API reachability error when auth config cannot be fetched', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new TypeError('Failed to fetch')));

    setCurrentPath('/signin');
    render(<App />);

    expect(await screen.findByText(/Identrail API is not reachable yet/i)).toBeInTheDocument();
  });

  it('renders tenancy-scoped project detail placeholder route inside app shell', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(okJSON(currentMePayload('tenant-a', 'workspace-a'))));
    setCurrentPath('/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect sources for project-1/i })).toBeInTheDocument();
    expect(await screen.findByText(/Project source onboarding/i)).toBeInTheDocument();
  });

  it('renders repository findings with direct GitHub line links inside the app shell', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({
          items: [
            {
              id: 'repo-scan-1',
              repository: 'owner/repo',
              status: 'succeeded',
              started_at: '2026-01-01T00:00:00Z',
              finished_at: '2026-01-01T00:05:00Z',
              commits_scanned: 12,
              files_scanned: 4,
              finding_count: 1,
              truncated: false
            }
          ]
        });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({
          items: [
            {
              scan_id: 'repo-scan-1',
              started_at: '2026-01-01T00:00:00Z',
              total: 1,
              by_severity: {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                info: 0
              }
            }
          ]
        });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({
          items: [
            {
              id: 'repo-f1',
              scan_id: 'repo-scan-1',
              type: 'secret_exposure',
              severity: 'high',
              title: 'Potential AWS access key exposed in commit history',
              human_summary: 'A line added in commit history appears to contain an AWS access key identifier.',
              repository: 'owner/repo',
              commit: 'abc123',
              file_path: 'config/app.env',
              line_number: 7,
              detector: 'aws_access_key_id',
              line_snippet: 'AWS_ACCESS_KEY_ID=AKIA****',
              line_snippet_redacted: true,
              source_url: 'https://github.com/owner/repo/blob/abc123/config/app.env#L7',
              remediation: 'Rotate the key and move the credential to a secret manager.',
              created_at: '2026-01-01T00:00:00Z'
            }
          ]
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/findings');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Findings/i })).toBeInTheDocument();
    expect(await screen.findByText(/Review repository findings and jump directly to the exact GitHub line/i)).toBeInTheDocument();
    expect(await screen.findByText(/Finding trend/i)).toBeInTheDocument();
    expect(await screen.findByText(/Critical 0 \/ High 1 \/ Medium 0 \/ Low 0 \/ Info 0/i)).toBeInTheDocument();
    expect(await screen.findByText(/Risk/i)).toBeInTheDocument();

    const openInGitHub = await screen.findByRole('link', { name: /Open in GitHub/i });
    expect(openInGitHub).toHaveAttribute('href', 'https://github.com/owner/repo/blob/abc123/config/app.env#L7');
    expect((await screen.findAllByText('config/app.env:7')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('owner/repo')).length).toBeGreaterThan(0);
  });

  it('renders real workspace settings from account, member, and auth config APIs', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a', 'admin'));
      }
      if (url.endsWith('/v1/whoami')) {
        return okJSON({
          principal: { type: 'subject', id: 'user-1' },
          roles: ['admin'],
          scopes: ['tenancy.read', 'tenancy.write'],
          scope: { tenant_id: 'tenant-a', workspace_id: 'workspace-a' },
          active_workspace: {
            workspace: {
              tenant_id: 'tenant-a',
              workspace_id: 'workspace-a',
              display_name: 'Security Workspace',
              slug: 'security-workspace',
              created_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-03T00:00:00Z'
            },
            member: {
              tenant_id: 'tenant-a',
              workspace_id: 'workspace-a',
              member_id: 'member-user-1',
              user_id: 'user-1',
              email: 'owner@example.com',
              role: 'admin',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-03T00:00:00Z'
            },
            is_active: true
          },
          workspaces: []
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/members')) {
        return okJSON({
          items: [
            {
              tenant_id: 'tenant-a',
              workspace_id: 'workspace-a',
              member_id: 'member-user-1',
              user_id: 'user-1',
              email: 'owner@example.com',
              role: 'admin',
              status: 'active',
              joined_at: '2026-01-01T00:00:00Z',
              updated_at: '2026-01-03T00:00:00Z'
            },
            {
              tenant_id: 'tenant-a',
              workspace_id: 'workspace-a',
              member_id: 'member-analyst',
              user_id: 'analyst',
              email: 'analyst@example.com',
              role: 'analyst',
              status: 'invited',
              joined_at: '2026-01-02T00:00:00Z',
              updated_at: '2026-01-02T00:00:00Z'
            }
          ]
        });
      }
      if (url.endsWith('/v1/auth/config')) {
        return authConfig(false, true);
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/settings');
    render(<App />);

    expect(await screen.findByText(/Security Workspace/i)).toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 2, name: /Settings/i })).toBeInTheDocument();
    expect(await screen.findByText(/Hosted WorkOS login/i)).toBeInTheDocument();
    expect(await screen.findByText(/Total members/i)).toBeInTheDocument();
    const accountSecurityLinks = await screen.findAllByRole('link', { name: /Account security/i });
    expect(accountSecurityLinks.some((link) => link.getAttribute('href') === '/app/account/security')).toBe(true);
  });

  it('supports workspace member invite workflow from app shell administration route', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(okJSON(currentMePayload('default', 'default')))
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
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(okJSON(currentMePayload('default', 'default')))
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

  it('synchronizes cookie workspace context before rendering a deep-linked workspace route', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(okJSON(currentMePayload('default', 'default')))
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
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          principal: { type: 'subject', id: 'owner-user' },
          roles: ['owner'],
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
          workspaces: []
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ items: [] })
      });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/default/payments/workspaces');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Members and roles/i })).toBeInTheDocument();
    const activeWorkspaceCallIndex = fetchMock.mock.calls.findIndex(([url, options]) => {
      return typeof url === 'string' && url.includes('/v1/workspaces/active') && options?.method === 'POST';
    });
    const membersCallIndex = fetchMock.mock.calls.findIndex(([url]) => {
      return typeof url === 'string' && url.includes('/v1/workspaces/payments/members');
    });
    expect(activeWorkspaceCallIndex).toBeGreaterThan(0);
    expect(membersCallIndex).toBeGreaterThan(activeWorkspaceCallIndex);
    expect(fetchMock.mock.calls[activeWorkspaceCallIndex]?.[1]).toEqual(
      expect.objectContaining({
        body: JSON.stringify({ workspace_id: 'payments' })
      })
    );
  });

  it('ignores stale workspace member responses after scope changes', async () => {
    let resolveInitialMembers: ((value: { ok: boolean; json: () => Promise<{ items: unknown[] }> }) => void) | undefined;
    const initialMembersResponse = new Promise<{ ok: boolean; json: () => Promise<{ items: unknown[] }> }>((resolve) => {
      resolveInitialMembers = resolve;
    });

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(okJSON(currentMePayload('default', 'default')))
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
      .mockResolvedValueOnce(okJSON(currentMePayload('default', 'payments', 'admin')))
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
      expect(fetchMock).toHaveBeenCalledTimes(3);
    });

    setCurrentPath('/app/default/payments/workspaces');
    act(() => {
      window.dispatchEvent(new PopStateEvent('popstate'));
    });

    expect(await screen.findByRole('heading', { level: 2, name: /Members and roles/i })).toBeInTheDocument();

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
      expect(screen.queryByText('owner-user')).not.toBeInTheDocument();
    });
  });

  it('shows workspace admin load errors without redirecting to login', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce(okJSON(currentMePayload('default', 'default'))).mockResolvedValueOnce(errorJSON(403, 'workspace access denied'))
    );

    setCurrentPath('/app/default/default/workspaces');
    render(<App />);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/workspace access denied/i);
    expect(window.location.pathname).toBe('/app/default/default/workspaces');
    expect(window.location.pathname).not.toBe('/app/login');
  });

  it('keeps existing member state when invite action fails', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(okJSON(currentMePayload('default', 'default')))
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

  it('finishes frontend auth callback by resolving the server session', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(okJSON(currentMePayload('tenant-a', 'workspace-a')))
        .mockResolvedValueOnce(okJSON(currentMePayload('tenant-a', 'workspace-a')))
    );

    setCurrentPath('/auth/callback');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/tenant-a/workspace-a');
  });

  it('redirects failed frontend auth callback checks back to sign-in', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce(errorJSON(401, 'unauthorized')).mockResolvedValueOnce(authConfig(false, true))
    );

    setCurrentPath('/auth/callback');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Log in to Identrail/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/signin');
    expect(window.location.search).toContain('reason=callback_error');
  });

  it('completes a WorkOS MFA enrollment challenge before opening the app', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        okJSON({
          mode: 'enrollment',
          user_email: 'owner@example.com',
          challenge_started: false,
          factors: []
        })
      )
      .mockResolvedValueOnce(
        okJSON({
          mode: 'enrollment',
          user_email: 'owner@example.com',
          challenge_started: true,
          factors: [{ id: 'auth_factor_1', type: 'totp' }],
          totp: {
            factor_id: 'auth_factor_1',
            qr_code: 'data:image/png;base64,qr',
            secret: 'SECRET',
            uri: 'otpauth://totp/Identrail:owner@example.com'
          }
        })
      )
      .mockResolvedValueOnce(okJSON({ ok: true, redirect_to: '/app/tenant-a/workspace-a' }))
      .mockResolvedValueOnce(okJSON(currentMePayload('tenant-a', 'workspace-a')));
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/auth/mfa?return_to=%2Fapp');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Set up two-factor authentication/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Set up authenticator app/i }));

    expect(await screen.findByAltText(/Authenticator QR code/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Authentication code/i), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: /Verify and continue/i }));

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/tenant-a/workspace-a');
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8080/auth/mfa/verify',
      expect.objectContaining({ body: JSON.stringify({ code: '123456' }), credentials: 'include', method: 'POST' })
    );
  });

  it('lists account security sessions and revokes other browsers', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(okJSON(currentMePayload('default', 'default')))
      .mockResolvedValueOnce(okJSON(currentMePayload('default', 'default')))
      .mockResolvedValueOnce(
        okJSON({
          items: [
            {
              id: 'current-session',
              ip: '127.0.0.1',
              user_agent: 'current browser',
              auth_method: 'workos',
              created_at: '2026-01-01T00:00:00Z',
              last_seen_at: '2026-01-01T00:00:00Z',
              idle_expires_at: '2026-01-01T00:15:00Z',
              current: true
            },
            {
              id: 'other-session',
              ip: '127.0.0.2',
              user_agent: 'other browser',
              auth_method: 'workos',
              created_at: '2026-01-01T00:00:00Z',
              last_seen_at: '2026-01-01T00:00:00Z',
              idle_expires_at: '2026-01-01T00:15:00Z',
              current: false
            }
          ]
        })
      )
      .mockResolvedValueOnce(okJSON({ ok: true, revoked: 1 }))
      .mockResolvedValueOnce(
        okJSON({
          items: [
            {
              id: 'current-session',
              ip: '127.0.0.1',
              user_agent: 'current browser',
              auth_method: 'workos',
              created_at: '2026-01-01T00:00:00Z',
              last_seen_at: '2026-01-01T00:00:00Z',
              idle_expires_at: '2026-01-01T00:15:00Z',
              current: true
            }
          ]
        })
      );
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/account/security');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Owner User/i })).toBeInTheDocument();
    expect(await screen.findByText(/other browser/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Revoke others/i }));

    await waitFor(() => {
      expect(screen.queryByText(/other browser/i)).not.toBeInTheDocument();
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8080/v1/me/sessions/revoke-others',
      expect.objectContaining({ method: 'POST', credentials: 'include' })
    );
  });

  it('logs out by revoking the server cookie session', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce(okJSON({ ok: true })).mockResolvedValueOnce(authConfig(false, true))
    );

    setCurrentPath('/app/logout');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Log in to Identrail/i })).toBeInTheDocument();
    expect(await screen.findByText(/Signed out successfully/i)).toBeInTheDocument();
    expect(window.location.pathname).toBe('/signin');
  });

  it('treats an already-missing logout session as signed out', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce(errorJSON(401, 'unauthorized')).mockResolvedValueOnce(authConfig(false, true))
    );

    setCurrentPath('/app/logout');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Log in to Identrail/i })).toBeInTheDocument();
    expect(await screen.findByText(/Signed out successfully/i)).toBeInTheDocument();
    expect(window.location.pathname).toBe('/signin');
  });

  it('does not report logout success when server session revocation fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(errorJSON(500, 'logout failed')));

    setCurrentPath('/app/logout');
    render(<App />);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/Unable to sign out/i);
    expect(alert).toHaveTextContent(/logout failed/i);
    expect(window.location.pathname).toBe('/app/logout');
    expect(screen.queryByText(/Signed out successfully/i)).not.toBeInTheDocument();
  });
});
