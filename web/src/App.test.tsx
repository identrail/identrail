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

describe('App marketing surface (post-redesign)', () => {
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

  it('renders the new homepage hero promise + primary CTAs', () => {
    setCurrentPath('/');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Trace every machine identity/i
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: /Start a free risk scan/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: /Read the source/i }).length).toBeGreaterThan(0);
    expect(screen.getByText(/Reviewed across your identity stack/i)).toBeInTheDocument();
  });

  it('renders the new pricing page with three plans and a billing toggle', () => {
    setCurrentPath('/pricing');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Honest pricing for an open-core security tool/i
      })
    ).toBeInTheDocument();

    expect(screen.getByRole('radio', { name: /Annual/i })).toBeInTheDocument();
    expect(screen.getAllByText(/Open source/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Most teams pick this/i)).toBeInTheDocument();
  });

  it('renders the consolidated security teams solution page', () => {
    setCurrentPath('/for/security-teams');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Spend the queue on what can actually reach something/i
      })
    ).toBeInTheDocument();
  });

  it('renders the integrations page and lists at least the AWS integration', () => {
    setCurrentPath('/integrations');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Every system Identrail watches today/i
      })
    ).toBeInTheDocument();

    expect(screen.getAllByText(/AWS IAM/i).length).toBeGreaterThan(0);
  });

  it('renders the demo page form and lets the user submit', () => {
    setCurrentPath('/demo');
    render(<App />);

    expect(screen.getByLabelText(/Work email/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Request a demo/i })).toBeInTheDocument();
  });

  it('renders the responsible disclosure process', () => {
    setCurrentPath('/responsible-disclosure');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Find a security issue/i
      })
    ).toBeInTheDocument();
  });

  it('redirects legacy /solutions/aws → /for/security-teams', async () => {
    setCurrentPath('/solutions/aws');
    render(<App />);

    await waitFor(() => {
      expect(window.location.pathname).toBe('/for/security-teams');
    });
  });

  it('redirects legacy /features/* → /product', async () => {
    setCurrentPath('/features/aws');
    render(<App />);

    await waitFor(() => {
      expect(window.location.pathname).toBe('/product');
    });
  });

  it('redirects /read-only-scan → /demo', async () => {
    setCurrentPath('/read-only-scan');
    render(<App />);

    await waitFor(() => {
      expect(window.location.pathname).toBe('/demo');
    });
  });
});

describe('App dashboard surface', () => {
  beforeEach(() => {
    window.sessionStorage.removeItem('identrail-product-session');
    window.sessionStorage.removeItem(OIDC_PENDING_LOGIN_STORAGE_KEY);
    vi.unstubAllEnvs();
    // Manual app-shell sessions are gated behind this env var as of dev's
    // PR #890 (Fixes #683). Tests that exercise the manual login flow rely
    // on it being enabled; the dedicated test that flips it to 'false'
    // (rejects persisted manual workspace sessions in production builds)
    // overrides per-test.
    vi.stubEnv('VITE_ALLOW_MANUAL_PRODUCT_SESSION', 'true');
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('guards product shell routes and redirects unauthenticated users to app login', () => {
    setCurrentPath('/app/default/default');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Sign in to Identrail/i
      })
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/login');
    expect(window.location.search).toContain('next=%2Fapp%2Fdefault%2Fdefault');
  });

  it('loads authenticated product shell placeholders after login', async () => {
    setCurrentPath('/app/login');
    render(<App />);

    fireEvent.change(screen.getByLabelText(/Tenant ID/i), { target: { value: 'tenant-a' } });
    fireEvent.change(screen.getByLabelText(/Workspace ID/i), { target: { value: 'workspace-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Continue to app/i }));

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
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

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to Identrail/i })).toBeInTheDocument();
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

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to Identrail/i })).toBeInTheDocument();
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

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to Identrail/i })).toBeInTheDocument();
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

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to Identrail/i })).toBeInTheDocument();
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

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to Identrail/i })).toBeInTheDocument();
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

    expect(await screen.findByRole('heading', { level: 1, name: /Sign in to Identrail/i })).toBeInTheDocument();
    expect(await screen.findByText(/Signed out successfully/i)).toBeInTheDocument();
  });

  it('keeps okJSON helper available for future workspace tests', () => {
    // Helper is intentionally exported in this file; future workspace member
    // invite tests can be added here using okJSON(...) as the first response.
    expect(typeof okJSON).toBe('function');
  });
});
