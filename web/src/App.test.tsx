import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { clearAuthConfigCacheForTests } from './authConfigCache';
import { resetBackendFeaturesCacheForTests } from './hooks/useBackendFeatures';
import { clearMeCacheForTests } from './hooks/useMe';
import { clearProductAuthSessionCacheForTests } from './productShell';

function resetBrowserState() {
  window.history.replaceState({}, '', '/');
  window.localStorage.clear();
  window.sessionStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  document.body.removeAttribute('style');
}

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

function getLinkByPath(path: string) {
  const link = screen.getAllByRole('link').find((item) => item.getAttribute('href') === path);
  if (!link) {
    throw new Error(`Expected link with href "${path}"`);
  }
  return link;
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

function repoRiskGraphPayload() {
  return {
    repository: 'owner/repo',
    nodes: [
      { id: 'repo:owner/repo', kind: 'repository', label: 'owner/repo', repository: 'owner/repo', evidence_state: 'known' },
      { id: 'finding:repo-f1', kind: 'finding', label: 'Potential AWS access key exposed', repository: 'owner/repo', evidence_state: 'known' },
      { id: 'token:aws_access_key', kind: 'token', label: 'AWS access key', repository: 'owner/repo', evidence_state: 'known' },
      { id: 'role:unknown', kind: 'cloud_role', label: 'Unknown cloud role', repository: 'owner/repo', evidence_state: 'unknown' }
    ],
    edges: [
      { id: 'repo-f1-exposes-token', kind: 'finding_exposes_token', from_node_id: 'finding:repo-f1', to_node_id: 'token:aws_access_key', evidence_state: 'known' },
      { id: 'token-reaches-role', kind: 'token_reaches_role', from_node_id: 'token:aws_access_key', to_node_id: 'role:unknown', evidence_state: 'unknown' },
      { id: 'repo-contains-finding', kind: 'repository_contains_finding', from_node_id: 'repo:owner/repo', to_node_id: 'finding:repo-f1', evidence_state: 'known' }
    ],
    scores: [
      {
        finding_id: 'repo-f1',
        finding_node_id: 'finding:repo-f1',
        score: 91,
        severity: 'high',
        confidence: 0.98,
        factors: {
          severity: 80,
          confidence: 98,
          exploitability: 90,
          privilege: 70,
          exposure: 95,
          environment_criticality: 80,
          freshness: 88
        },
        unknowns: ['cloud_role']
      }
    ],
    summary: {
      finding_count: 1,
      node_count: 4,
      edge_count: 3,
      unknown_node_count: 1,
      unknown_edge_count: 1,
      high_risk_findings: 1,
      critical_findings: 0
    }
  };
}

function repoRemediationPreviewPayload() {
  return {
    finding: {
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
      created_at: '2026-01-01T00:00:00Z'
    },
    remediation: {
      detector: 'aws_access_key_id',
      summary: 'Rotate exposed AWS credential',
      risk_summary: 'The credential may still authorize access outside the repository.',
      steps: ['Revoke the leaked access key', 'Move workload auth to short-lived credentials'],
      safety_notes: ['Do not copy secret material into the fix branch.'],
      validation: ['Confirm the key is disabled in IAM', 'Rescan the repository after rotation'],
      secret_rotation: true,
      publishable: false,
      publish_blocked_reason: 'Secret rotation required',
      evidence: {
        finding_id: 'repo-f1',
        scan_id: 'repo-scan-1',
        repository: 'owner/repo'
      }
    }
  };
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

function fillScanIdentityStep({
  email = 'security@company.com',
  fullName = 'Alex Morgan',
  roleTitle = 'Security Engineering Lead',
  company = 'Company Inc',
  companyWebsite = 'company.com'
} = {}) {
  fireEvent.change(screen.getByLabelText(/Work email/i), {
    target: { value: email }
  });
  fireEvent.change(screen.getByLabelText(/Your name/i), {
    target: { value: fullName }
  });
  fireEvent.change(screen.getByLabelText(/Role or title/i), {
    target: { value: roleTitle }
  });
  fireEvent.change(screen.getByLabelText(/Company name/i), {
    target: { value: company }
  });
  fireEvent.change(screen.getByLabelText(/Company website/i), {
    target: { value: companyWebsite }
  });
}

function leadCaptureCalls(fetchMock: ReturnType<typeof vi.fn>) {
  return fetchMock.mock.calls.filter(([url]) => url === '/api/leads');
}

describe('App', () => {
  beforeEach(() => {
    vi.useRealTimers();
    cleanup();
    resetBrowserState();
    clearAuthConfigCacheForTests();
    resetBackendFeaturesCacheForTests();
    clearMeCacheForTests();
    clearProductAuthSessionCacheForTests();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    cleanup();
    resetBrowserState();
    clearAuthConfigCacheForTests();
    resetBackendFeaturesCacheForTests();
    clearMeCacheForTests();
    clearProductAuthSessionCacheForTests();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('renders homepage hero and conversion CTAs', () => {
    setCurrentPath('/');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /See every machine identity path/i
      })
    ).toBeInTheDocument();

    const scanButtons = screen.getAllByRole('button', { name: 'Request Trust Path Review' });
    expect(scanButtons.length).toBeGreaterThan(0);
    fireEvent.click(scanButtons[0]);
    expect(screen.getByRole('dialog', { name: /Verify company identity/i })).toBeInTheDocument();
    expect(screen.queryByText(/Need enterprise procurement/i)).not.toBeInTheDocument();
    expect(screen.getAllByText(/Adoption Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Reachable Risk Paths/i).length).toBeGreaterThan(0);
    expect(
      screen.getByRole('heading', { level: 2, name: /Connect sources, trace risk/i })
    ).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Book Demo/i }).length).toBeGreaterThan(0);
    expect(document.querySelector('#risk-scan-form')).not.toBeInTheDocument();
    expect(document.querySelector('.idt-trust-strip + .idt-home-after-stack')).toBeInTheDocument();
    expect(document.querySelector('.idt-home-after-stack .idt-shell')).not.toBeInTheDocument();
  });


  it('opens the trust graph review flow from enterprise CTAs', () => {
    setCurrentPath('/enterprise');
    render(<App />);

    fireEvent.click(screen.getByRole('button', { name: /Book Demo/i }));

    expect(screen.getByRole('dialog', { name: /Verify company identity/i })).toBeInTheDocument();
  });

  it('keeps legacy demo links on the trust graph review flow without rendering a demo page', async () => {
    setCurrentPath('/demo');
    render(<App />);

    await waitFor(() => expect(window.location.pathname).toBe('/'));
    expect(screen.getByRole('dialog', { name: /Verify company identity/i })).toBeInTheDocument();
  });

  it.each([
    ['l', '/signin'],
    ['S', '/signup']
  ])('routes the %s header keyboard shortcut to %s', async (key, expectedPath) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(authConfig(false, true)));
    setCurrentPath('/');
    render(<App />);

    fireEvent.keyDown(document, { key });

    await waitFor(() => expect(window.location.pathname).toBe(expectedPath));
  });

  it('reuses loaded auth options when switching between log in and sign up', async () => {
    const fetchMock = vi.fn().mockResolvedValue(authConfig(false, true));
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/signin');
    render(<App />);

    expect(await screen.findByRole('link', { name: /Continue with GitHub/i })).toBeInTheDocument();
    const authCallsBeforeNavigation = fetchMock.mock.calls.filter(
      ([url]) => typeof url === 'string' && url.endsWith('/v1/auth/config')
    ).length;

    fireEvent.click(screen.getAllByRole('link', { name: 'Sign Up' })[0]);

    await waitFor(() => expect(window.location.pathname).toBe('/signup'));
    expect(await screen.findByRole('link', { name: /Continue with GitHub/i })).toBeInTheDocument();
    expect(screen.queryByText(/Loading authentication/i)).not.toBeInTheDocument();
    const authCallsAfterNavigation = fetchMock.mock.calls.filter(
      ([url]) => typeof url === 'string' && url.endsWith('/v1/auth/config')
    ).length;
    expect(authCallsAfterNavigation).toBe(authCallsBeforeNavigation);
  });

  it.each([
    ['nested textbox role', <span role="textbox"><span data-testid="editable-shortcut-target">sale note</span></span>],
    ['plaintext contenteditable', <span contentEditable="plaintext-only"><span data-testid="editable-shortcut-target">login note</span></span>]
  ])('keeps header shortcuts inactive inside %s editors', async (_name, editor) => {
    setCurrentPath('/');
    render(
      <>
        <App />
        {editor}
      </>
    );

    fireEvent.keyDown(screen.getByTestId('editable-shortcut-target'), { key: 's' });

    expect(window.location.pathname).toBe('/');
  });


  it('resets scroll when a routed hash target is missing', async () => {
    setCurrentPath('/pricing');
    render(<App />);
    document.documentElement.scrollTop = 640;
    document.body.scrollTop = 640;

    act(() => {
      window.history.pushState({}, '', '/product#missing-anchor');
      window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
    });

    await waitFor(() => expect(document.documentElement.scrollTop).toBe(0));
    expect(document.body.scrollTop).toBe(0);
  });

  it('cancels scheduled hash scrolling when navigation changes first', async () => {
    const requestAnimationFrame = vi.fn(() => 42);
    const cancelAnimationFrame = vi.fn();
    vi.stubGlobal('requestAnimationFrame', requestAnimationFrame);
    vi.stubGlobal('cancelAnimationFrame', cancelAnimationFrame);
    setCurrentPath('/pricing#missing-anchor');
    render(<App />);
    expect(requestAnimationFrame).toHaveBeenCalled();

    act(() => {
      window.history.pushState({}, '', '/product');
      window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
    });

    await waitFor(() => expect(cancelAnimationFrame).toHaveBeenCalledWith(42));
  });

  it('does not apply marketing scroll reset inside app routes', async () => {
    setCurrentPath('/app/login');
    render(<App />);
    document.documentElement.scrollTop = 640;
    document.body.scrollTop = 640;

    act(() => {
      window.history.pushState({}, '', '/app/login?return_to=/app/default/default');
      window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
    });

    await waitFor(() => expect(document.documentElement.scrollTop).toBe(640));
    expect(document.body.scrollTop).toBe(640);
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
    expect(screen.getByText(/Choose deployment model/i)).toBeInTheDocument();
    expect(screen.getByText(/Procurement ready/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Talk to Enterprise/i })).toBeInTheDocument();
  });

  it('renders the full-bleed product page story', () => {
    setCurrentPath('/product');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Machine identity risk, mapped end to end/i
      })
    ).toBeInTheDocument();

    expect(screen.getByRole('heading', { level: 2, name: /Four product surfaces/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /The Trust Graph is the control plane/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /From discovery to fix/i })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Request Trust Path Review/i }).length).toBeGreaterThan(0);
    expect(document.querySelector('main main')).not.toBeInTheDocument();
    expect(document.querySelector('.idt-product-hero-visual')).toHaveAttribute('aria-hidden', 'true');
    expect(document.querySelector('.idt-product-trust-svg')).toBeInTheDocument();
    expect(document.querySelectorAll('.idt-product-path-edge.is-active')).toHaveLength(3);
    expect(document.querySelectorAll('.idt-product-node-badge.is-danger')).toHaveLength(2);
    expect(document.querySelectorAll('.idt-product-node-status.is-risk')).toHaveLength(0);

    const readSvgBox = (group: Element) => {
      const [, x = '0', y = '0'] = group.getAttribute('transform')?.match(/translate\(([-.\d]+) ([-.\d]+)\)/) ?? [];
      const rect = group.querySelector('rect');
      return {
        x: Number(x),
        y: Number(y),
        width: Number(rect?.getAttribute('width') ?? 0),
        height: Number(rect?.getAttribute('height') ?? 0)
      };
    };
    const overlaps = (a: ReturnType<typeof readSvgBox>, b: ReturnType<typeof readSvgBox>) =>
      a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y;
    const labelBoxes = [...document.querySelectorAll('.idt-product-path-tag')].map(readSvgBox);
    const nodeBoxes = [...document.querySelectorAll('.idt-product-path-node')].map(readSvgBox);

    expect(labelBoxes).toHaveLength(3);
    expect(nodeBoxes).toHaveLength(4);
    for (const labelBox of labelBoxes) {
      for (const nodeBox of nodeBoxes) {
        expect(overlaps(labelBox, nodeBox)).toBe(false);
      }
    }
  });

  it('rejects personal email domains before advancing the read-only scan intake', () => {
    setCurrentPath('/');
    const fetchMock = vi.fn(async () => okJSON({ status: 'accepted' }));
    vi.stubGlobal('fetch', fetchMock);
    render(<App />);
    fireEvent.click(screen.getAllByRole('button', { name: 'Request Trust Path Review' })[0]);

    fillScanIdentityStep({
      email: 'person@gmail.com',
      company: 'Personal Co'
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    expect(screen.getByRole('alert')).toHaveTextContent(/company or work email/i);
    expect(screen.getByText(/Step 1 of 4/i)).toBeInTheDocument();
    expect(leadCaptureCalls(fetchMock)).toHaveLength(0);
  });

  it('rejects company domains that do not match the work email domain', () => {
    setCurrentPath('/');
    const fetchMock = vi.fn(async () => okJSON({ status: 'accepted' }));
    vi.stubGlobal('fetch', fetchMock);
    render(<App />);
    fireEvent.click(screen.getAllByRole('button', { name: 'Request Trust Path Review' })[0]);

    fillScanIdentityStep({
      companyWebsite: 'other-company.com'
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    expect(screen.getByRole('alert')).toHaveTextContent(/match the domain/i);
    expect(screen.getByText(/Step 1 of 4/i)).toBeInTheDocument();
    expect(leadCaptureCalls(fetchMock)).toHaveLength(0);
  });

  it('rejects a whitespace-only company name before advancing', () => {
    setCurrentPath('/');
    const fetchMock = vi.fn(async () => okJSON({ status: 'accepted' }));
    vi.stubGlobal('fetch', fetchMock);
    render(<App />);
    fireEvent.click(screen.getAllByRole('button', { name: 'Request Trust Path Review' })[0]);

    fillScanIdentityStep({
      company: '   '
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    expect(screen.getByRole('alert')).toHaveTextContent(/enter your company name/i);
    expect(screen.getByText(/Step 1 of 4/i)).toBeInTheDocument();
    expect(leadCaptureCalls(fetchMock)).toHaveLength(0);
  });

  it('does not submit the read-only scan intake before the final step', async () => {
    setCurrentPath('/');
    const fetchMock = vi.fn(async () => okJSON({ status: 'accepted' }));
    vi.stubGlobal('fetch', fetchMock);
    render(<App />);
    fireEvent.click(screen.getAllByRole('button', { name: 'Request Trust Path Review' })[0]);

    fillScanIdentityStep();
    const form = document.querySelector('form.idt-scan-form');
    expect(form).toBeTruthy();
    fireEvent.submit(form as HTMLFormElement);

    await waitFor(() => expect(screen.getByText(/Step 2 of 4/i)).toBeInTheDocument());
    expect(leadCaptureCalls(fetchMock)).toHaveLength(0);
  });

  it('submits read-only scan challenge details to lead capture', async () => {
    setCurrentPath('/');
    const fetchMock = vi.fn(async () => okJSON({ status: 'accepted' }));
    vi.stubGlobal('fetch', fetchMock);
    render(<App />);
    fireEvent.click(screen.getAllByRole('button', { name: 'Request Trust Path Review' })[0]);

    fillScanIdentityStep({
      companyWebsite: 'https://www.company.com'
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    fireEvent.change(screen.getByLabelText(/Public code host/i), {
      target: { value: 'gitlab.com/platform/security/identity-risk' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Review Request' }));
    expect(screen.getByText(/Step 4 of 4/i)).toBeInTheDocument();
    expect(screen.getByText('security@company.com')).toBeInTheDocument();
    expect(screen.getByText(/Alex Morgan - Security Engineering Lead/i)).toBeInTheDocument();
    expect(screen.getByText('company.com')).toBeInTheDocument();
    expect(screen.getByText('https://gitlab.com/platform/security/identity-risk')).toBeInTheDocument();
    expect(leadCaptureCalls(fetchMock)).toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'Submit Review Request' }));

    await waitFor(() => expect(leadCaptureCalls(fetchMock)).toHaveLength(1));
    const [, init] = leadCaptureCalls(fetchMock)[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toMatchObject({
      email: 'security@company.com',
      full_name: 'Alex Morgan',
      role_title: 'Security Engineering Lead',
      company: 'Company Inc',
      company_domain: 'company.com',
      environment: 'AWS IAM + Kubernetes',
      challenge: 'Trust path visibility',
      identity_provider: 'AWS IAM Identity Center / SSO',
      infrastructure_scope: '1-5 cloud accounts or clusters',
      repository_url: 'https://gitlab.com/platform/security/identity-risk',
      page_path: '/'
    });
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
    expect(screen.getByRole('link', { name: /support@identrail.com/i })).toHaveAttribute(
      'href',
      'mailto:support@identrail.com?subject=Privacy%20Request'
    );
  });

  it('renders standardized terms of use content on the terms route', () => {
    setCurrentPath('/terms');
    render(<App />);

    expect(screen.getByRole('heading', { level: 1, name: /Terms of Use/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /Standard terms/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: /Acceptance and scope/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: /Acceptable use/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: /Customer data and integrations/i })).toBeInTheDocument();
    expect(screen.getByText(/Questions about these Terms of Use can be sent to support@identrail.com/i)).toBeInTheDocument();
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

    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    expect(await screen.findByText(/Open risk/i)).toBeInTheDocument();
    expect(await screen.findByText(/Priority findings/i)).toBeInTheDocument();
    expect(await screen.findByText(/Production GitHub/i)).toBeInTheDocument();
    expect(await screen.findByText(/1 archived/i)).toBeInTheDocument();
    expect(await screen.findByText(/vs\. previous scan \(4 total\)/i)).toBeInTheDocument();
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

  it('keeps the workspace shell mounted when switching app sections', async () => {
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
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a');
    render(<App />);

    await screen.findByRole('region', { name: /Get started/i });
    expect(screen.getByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Production GitHub/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/projects/project-1'
    );
    const meCallsBeforeNavigation = fetchMock.mock.calls.filter(([url]) => typeof url === 'string' && url.endsWith('/v1/me')).length;

    fireEvent.click(screen.getByRole('button', { name: 'AWS' }));
    fireEvent.click(await waitFor(() => getLinkByPath('/app/tenant-a/workspace-a/aws')));

    expect(screen.queryByText(/Validating session/i)).not.toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: /App sections/i })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 2, name: 'AWS Control Center' })).toBeInTheDocument();
    await waitFor(() => {
      const meCallsAfterNavigation = fetchMock.mock.calls.filter(([url]) => typeof url === 'string' && url.endsWith('/v1/me')).length;
      expect(meCallsAfterNavigation).toBeGreaterThan(meCallsBeforeNavigation);
    });
  });

  it('keeps validated session state warm across guarded app routes', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.endsWith('/v1/me/sessions')) {
        return okJSON({
          items: [
            {
              id: 'session-1',
              auth_method: 'manual',
              created_at: '2026-01-01T00:00:00Z',
              idle_expires_at: '2026-01-02T00:00:00Z',
              last_seen_at: '2026-01-01T01:00:00Z',
              user_agent: 'Safari',
              ip: '127.0.0.1',
              current: true
            }
          ]
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a');
    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    });

    act(() => {
      window.history.pushState({}, '', '/app/account/security');
      window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
    });

    expect(screen.queryByText(/Validating session/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Loading account security/i)).not.toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 1, name: /Owner User/i })).toBeInTheDocument();
  });

  it('silently revalidates warm guarded routes and clears a revoked server session', async () => {
    let meCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        meCalls += 1;
        return meCalls === 1 ? okJSON(currentMePayload('tenant-a', 'workspace-a')) : errorJSON(401, 'session revoked');
      }
      if (url.endsWith('/v1/auth/config')) {
        return authConfig(false, true);
      }
      if (url.includes('/v1/workspaces/workspace-a/projects')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a');
    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'AWS' }));
    fireEvent.click(await waitFor(() => getLinkByPath('/app/tenant-a/workspace-a/aws')));

    expect(screen.queryByText(/Validating session/i)).not.toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 1, name: /Log in to Identrail/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/signin');
    expect(window.location.search).toContain('return_to=%2Fapp%2Ftenant-a%2Fworkspace-a%2Faws');
  });

  it('keeps mismatched scoped routes loading until tenant redirects complete', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-b', 'workspace-b'));
      }
      if (url.includes('/v1/workspaces/workspace-b/projects')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects')) {
        throw new Error('stale workspace route rendered before tenant redirect completed');
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a');
    render(<App />);

    await waitFor(() => {
      expect(window.location.pathname).toBe('/app/tenant-b/workspace-b');
    });
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    });
    expect(
      fetchMock.mock.calls.some(([url]) => typeof url === 'string' && url.includes('/v1/workspaces/workspace-a/projects'))
    ).toBe(false);
  });

  it('clears stale scoped auth after a session-only validation', async () => {
    let meCalls = 0;
    let resolveScopedMe: (response: ReturnType<typeof okJSON>) => void = () => {};
    const scopedMeResponse = new Promise<ReturnType<typeof okJSON>>((resolve) => {
      resolveScopedMe = resolve;
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        meCalls += 1;
        if (meCalls === 1) {
          return okJSON(currentMePayload('tenant-a', 'workspace-a'));
        }
        if (meCalls === 2) {
          return okJSON(currentMePayload('', ''));
        }
        return scopedMeResponse;
      }
      if (url.endsWith('/v1/me/sessions')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a');
    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    });

    act(() => {
      window.history.pushState({}, '', '/app/account/security');
      window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
    });

    expect(await screen.findByRole('heading', { level: 1, name: /Owner User/i })).toBeInTheDocument();

    act(() => {
      window.history.pushState({}, '', '/app/tenant-a/workspace-a/aws');
      window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
    });

    expect(await screen.findByText(/Validating session/i)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 2, name: 'AWS Control Center' })).not.toBeInTheDocument();

    await act(async () => {
      resolveScopedMe(okJSON(currentMePayload('tenant-a', 'workspace-a')));
      await scopedMeResponse;
    });

    expect(await screen.findByRole('heading', { level: 2, name: 'AWS Control Center' })).toBeInTheDocument();
  });

  it('revalidates session after same-workspace navigation from an auth error', async () => {
    let meCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        meCalls += 1;
        return meCalls === 1
          ? errorJSON(503, 'temporary session outage')
          : okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.includes('/v1/workspaces/workspace-a/projects')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a');
    render(<App />);

    expect(await screen.findByRole('alert')).toHaveTextContent(/Unable to validate account session/i);

    act(() => {
      window.history.pushState({}, '', '/app/tenant-a/workspace-a/aws');
      window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
    });

    expect(await screen.findByRole('heading', { level: 2, name: 'AWS Control Center' })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(meCalls).toBe(2);
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

    expect(await screen.findByText(/Trend/i)).toBeInTheDocument();
    expect(await screen.findByText('—')).toBeInTheDocument();
    expect(await screen.findByText(/12 findings · awaiting another scan/i)).toBeInTheDocument();
    expect(screen.queryByText('+12')).not.toBeInTheDocument();
  });

  it('does not mark source onboarding complete when onboarding state belongs to another workspace', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/me')) {
        return okJSON(currentMePayload('tenant-b', 'workspace-b'));
      }
      if (url.includes('/v1/onboarding/state')) {
        return okJSON({
          state: {
            user_id: 'user-1',
            current_step: 'invite',
            org_id: 'tenant-a',
            workspace_id: 'workspace-a',
            project_id: 'project-a',
            connector_id: 'github-app',
            connector_type: 'github',
            connector_skipped: false,
            scan_skipped: false,
            started_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-01T00:00:00Z'
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-b/projects')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-b/workspace-b');
    render(<App />);

    const checklistRegion = await screen.findByRole('region', { name: /Get started/i }, { timeout: 10000 });
    const sourceChecklistItem = within(checklistRegion).getByText('Connect a domain source').closest('li');
    expect(sourceChecklistItem).not.toBeNull();
    if (!sourceChecklistItem) {
      throw new Error('missing source checklist item');
    }
    expect(sourceChecklistItem).toHaveAttribute('data-complete', 'false');
    expect(within(sourceChecklistItem).getByRole('link', { name: 'Connect' })).toHaveAttribute(
      'href',
      '/app/tenant-b/workspace-b/aws/connect'
    );
    expect(screen.getByRole('link', { name: 'Connect AWS' })).toHaveAttribute(
      'href',
      '/app/tenant-b/workspace-b/aws/connect'
    );
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

  it('points unknown hosted sign-ins to sign-up without raw callback errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(authConfig(false, true)));

    setCurrentPath('/signin?reason=account_not_found&return_to=/app/team/workspace');
    render(<App />);

    expect(await screen.findByText(/No Identrail account uses that sign-in method yet/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Create an account/i })).toHaveAttribute(
      'href',
      '/signup?return_to=%2Fapp%2Fteam%2Fworkspace'
    );
  });

  it('points removed hosted accounts to sign-up reactivation', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(authConfig(false, true)));

    setCurrentPath('/signin?reason=account_reactivation_required&return_to=/app/team/workspace');
    render(<App />);

    expect(await screen.findByText(/That Identrail account was previously removed/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Reactivate account/i })).toHaveAttribute(
      'href',
      '/signup?return_to=%2Fapp%2Fteam%2Fworkspace'
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

  it('renders tenancy-scoped AWS identity route inside app shell', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(okJSON(currentMePayload('tenant-a', 'workspace-a'))));
    setCurrentPath('/app/tenant-a/workspace-a/aws/identities');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /AWS machine identities/i })).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: /AWS sections/i })).not.toBeInTheDocument();
  });

  it('keeps legacy project callback routes hidden but working', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.endsWith('/v1/auth/config')) {
        return authConfig(false, true);
      }
      if (url.includes('/v1/connectors/github')) {
        return okJSON({
          connection: {
            provider: 'github_app',
            connected: false,
            connector_id: 'github-app',
            display_name: 'Identrail',
            status: 'disconnected',
            health_status: 'unknown',
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/aws/connection')) {
        return okJSON({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'disconnected',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: [],
            capabilities: { requested: [], validated: [], effective: [], unavailable: [] }
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/scan-policies')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Connect environment sources/i })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: /App sections/i })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Projects' })).not.toBeInTheDocument();
  });

  it('gates the GitHub connect domain entry when the connector is not enabled in the bundle', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.endsWith('/v1/auth/config')) {
        return authConfig(false, true);
      }
      if (url.includes('/v1/workspaces/workspace-a/projects?')) {
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
      if (url.includes('/v1/connectors/github')) {
        return okJSON({
          connection: {
            provider: 'github_app',
            connected: false,
            connector_id: 'github-app',
            display_name: 'Identrail',
            status: 'disconnected',
            health_status: 'unknown',
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/aws/connection')) {
        return okJSON({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'disconnected',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: [],
            capabilities: { requested: [], validated: [], effective: [], unavailable: [] }
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/scan-policies')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/github/connect');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Unable to open GitHub setup/i })).toBeInTheDocument();
    expect(screen.getByText(/GitHub connector is not available in this build/i)).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/tenant-a/workspace-a/github/connect');
    expect(screen.queryByRole('link', { name: 'Projects' })).not.toBeInTheDocument();
  });

  it('routes the AWS connect domain entry to the working connector setup', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.endsWith('/v1/auth/config')) {
        return authConfig(false, true);
      }
      if (url.includes('/v1/workspaces/workspace-a/projects?')) {
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
      if (url.includes('/v1/connectors/github')) {
        return okJSON({
          connection: {
            provider: 'github_app',
            connected: false,
            connector_id: 'github-app',
            display_name: 'Identrail',
            status: 'disconnected',
            health_status: 'unknown',
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/aws/connection')) {
        return okJSON({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'disconnected',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: [],
            capabilities: { requested: [], validated: [], effective: [], unavailable: [] }
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection')) {
        return okJSON({
          connection: {
            provider: 'kubernetes',
            connected: false,
            status: 'disconnected',
            health_status: 'unknown',
            diagnostics: [],
            selected_context: ''
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/scan-policies')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/aws/connect');
    render(<App />);

    await waitFor(() => expect(window.location.pathname).toBe('/app/tenant-a/workspace-a/projects/project-1'));
    expect(window.location.search).toBe('?source=aws');
    expect(await screen.findByRole('heading', { level: 1, name: /Connect AWS/i })).toBeInTheDocument();
    expect(screen.queryByLabelText('AWS source')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Source types')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 3, name: 'AWS' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Projects' })).not.toBeInTheDocument();
  });

  it('gates the Kubernetes connect domain entry when the connector is not enabled in the bundle', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.endsWith('/v1/auth/config')) {
        return authConfig(false, true);
      }
      if (url.includes('/v1/workspaces/workspace-a/projects?')) {
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
      if (url.includes('/v1/connectors/github')) {
        return okJSON({
          connection: {
            provider: 'github_app',
            connected: false,
            connector_id: 'github-app',
            display_name: 'Identrail',
            status: 'disconnected',
            health_status: 'unknown',
            webhook_secret_rotation_required: false,
            selected_repositories: []
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/aws/connection')) {
        return okJSON({
          connection: {
            provider: 'aws',
            connected: false,
            status: 'disconnected',
            health_status: 'unknown',
            external_id_configured: false,
            permission_checks: [],
            diagnostics: [],
            capabilities: { requested: [], validated: [], effective: [], unavailable: [] }
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/kubernetes/connection')) {
        return okJSON({
          connection: {
            provider: 'kubernetes',
            connected: false,
            status: 'disconnected',
            health_status: 'unknown',
            diagnostics: [],
            selected_context: ''
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects/project-1/scan-policies')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/kubernetes/connect');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Unable to open Kubernetes setup/i })).toBeInTheDocument();
    expect(screen.getByText(/Kubernetes connector is not available in this build/i)).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/tenant-a/workspace-a/kubernetes/connect');
    expect(screen.queryByRole('link', { name: 'Projects' })).not.toBeInTheDocument();
  });

  it('redirects legacy findings and AI risk deep links to GitHub-owned routes', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({
          summary: {
            total_open: 0,
            fixed_count: 0,
            reopened_count: 0,
            suppressed_count: 0,
            sla_aged_count: 0,
            mttr_ready_resolved_count: 0,
            by_owner: {},
            by_detector: {},
            by_severity: {}
          },
          items: []
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/findings');
    render(<App />);

    await waitFor(() => expect(window.location.pathname).toBe('/app/tenant-a/workspace-a/github/findings'));
    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/v1/repo-findings'))).toBe(true);
    });
    const repoFindingCallsBeforeAIRiskRedirect = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes('/v1/repo-findings')
    ).length;

    cleanup();
    resetBrowserState();
    clearAuthConfigCacheForTests();
    resetBackendFeaturesCacheForTests();
    clearMeCacheForTests();
    clearProductAuthSessionCacheForTests();

    setCurrentPath('/app/tenant-a/workspace-a/ai-risks');
    render(<App />);

    await waitFor(() => expect(window.location.pathname).toBe('/app/tenant-a/workspace-a/github/agentic-risk'));
    await waitFor(() => {
      const repoFindingCalls = fetchMock.mock.calls.filter(([input]) => String(input).includes('/v1/repo-findings')).length;
      expect(repoFindingCalls).toBeGreaterThan(repoFindingCallsBeforeAIRiskRedirect);
    });
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
      if (url.includes('/v1/repo-risk-graph')) {
        return okJSON(repoRiskGraphPayload());
      }
      if (url.includes('/v1/repo-findings/repo-f1/remediation/preview')) {
        return okJSON(repoRemediationPreviewPayload());
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
            },
            {
              id: 'repo-f2',
              scan_id: 'repo-scan-1',
              type: 'repo_exposure',
              severity: undefined,
              title: 'Finding record with a missing severity',
              human_summary: 'Legacy API records can omit optional display fields while scans are still being normalized.',
              repository: 'owner/repo',
              created_at: '2026-01-01T00:01:00Z'
            }
          ]
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/github/findings');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /^GitHub findings$/i })).toBeInTheDocument();
    expect(await screen.findByText(/Review repository findings and jump directly to the exact GitHub line/i)).toBeInTheDocument();
    expect(await screen.findByText(/Risk graph/i)).toBeInTheDocument();
    expect(await screen.findByText(/High-risk findings/i)).toBeInTheDocument();
    expect(await screen.findByText('91')).toBeInTheDocument();
    expect(await screen.findByText(/Finding trend/i)).toBeInTheDocument();
    expect(await screen.findByText(/Critical 0 \/ High 1 \/ Medium 0 \/ Low 0 \/ Info 0/i)).toBeInTheDocument();
    expect(await screen.findByText(/Risk \(high/i)).toBeInTheDocument();
    const missingSeverityFinding = await screen.findByText(/Finding record with a missing severity/i);
    const missingSeverityRow = missingSeverityFinding.closest('button');
    expect(missingSeverityRow).not.toBeNull();
    if (!missingSeverityRow) {
      throw new Error('missing finding row');
    }
    expect(within(missingSeverityRow).getByText('Unknown')).toBeInTheDocument();

    const linkedFinding = await screen.findByText(/Potential AWS access key exposed in commit history/i);
    const linkedFindingRow = linkedFinding.closest('button');
    expect(linkedFindingRow).not.toBeNull();
    if (!linkedFindingRow) {
      throw new Error('linked finding row');
    }
    fireEvent.click(linkedFindingRow);

    const findingDialog = await screen.findByRole('dialog', {
      name: /Potential AWS access key exposed in commit history/i
    });
    const openInGitHub = await screen.findByRole('link', { name: /Open in GitHub/i });
    expect(openInGitHub).toHaveAttribute('href', 'https://github.com/owner/repo/blob/abc123/config/app.env#L7');
    expect(within(findingDialog).getAllByText('config/app.env:7').length).toBeGreaterThan(0);
    expect(within(findingDialog).getAllByText('owner/repo').length).toBeGreaterThan(0);

    fireEvent.click(within(findingDialog).getByRole('button', { name: /Preview remediation plan/i }));
    expect(await screen.findByText(/Rotate exposed AWS credential/i)).toBeInTheDocument();
    expect(await screen.findByText(/Revoke the leaked access key/i)).toBeInTheDocument();
    expect(await screen.findByText(/Secret rotation required/i)).toBeInTheDocument();
  });

  it('renders the GitHub AI / Agentic Risk dashboard inside the app shell', async () => {
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
              started_at: '2026-01-02T00:00:00Z',
              finished_at: '2026-01-02T00:05:00Z',
              commits_scanned: 12,
              files_scanned: 9,
              finding_count: 5,
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
              started_at: '2026-01-02T00:00:00Z',
              total: 5,
              by_severity: { critical: 1, high: 2, medium: 1, low: 1, info: 0 }
            }
          ]
        });
      }
      if (url.includes('/v1/repo-findings')) {
        if (url.includes('cursor=repo-page-2')) {
          return okJSON({
            items: Array.from({ length: 5 }, (_, index) => ({
              id: `repo-ai-${index + 2}`,
              scan_id: 'repo-scan-1',
              type: 'ai_agent_surface',
              severity: 'low',
              detector: 'ai_agent_config_secret_ref',
              title: `Additional AI exposure ${index + 2}`,
              human_summary: 'Additional scoped AI risk for repository counting.',
              repository: `owner/repo-${index + 2}`,
              file_path: '.mcp.json',
              remediation: 'Move sensitive values behind scoped secrets.',
              created_at: `2026-01-02T00:0${index + 5}:00Z`
            }))
          });
        }
        return okJSON({
          summary: {
            total_open: 99,
            fixed_count: 2,
            reopened_count: 1,
            suppressed_count: 0,
            sla_aged_count: 0,
            mttr_ready_resolved_count: 2,
            by_owner: {},
            by_detector: {},
            by_severity: { critical: 1, high: 2, medium: 1, low: 1 }
          },
          items: [
            {
              id: 'repo-ai',
              scan_id: 'repo-scan-1',
              type: 'ai_agent_surface',
              severity: 'high',
              detector: 'ai_agent_config_secret_ref',
              title: 'MCP server exposes sensitive environment references',
              human_summary: 'An MCP configuration exposes sensitive environment variable names.',
              repository: 'owner/repo',
              file_path: '.mcp.json',
              remediation: 'Move sensitive values behind scoped secrets.',
              created_at: '2026-01-02T00:00:00Z'
            },
            {
              id: 'repo-workflow',
              scan_id: 'repo-scan-1',
              type: 'repo_misconfiguration',
              severity: 'critical',
              detector: 'workflow_ai_agent_prompt_injection',
              title: 'AI workflow prompt injection can reach Claude',
              human_summary: 'Untrusted pull request text is sent to an AI workflow step.',
              repository: 'owner/repo',
              file_path: '.github/workflows/review.yml',
              remediation: 'Gate AI workflow input behind trusted events.',
              created_at: '2026-01-02T00:01:00Z'
            },
            {
              id: 'repo-native',
              scan_id: 'repo-scan-1',
              type: 'dependency_vulnerability',
              severity: 'medium',
              detector: 'github_dependabot_alert',
              adapter_source: 'github_dependabot',
              title: 'Dependabot alert requires package update',
              human_summary: 'GitHub reported a vulnerable dependency.',
              repository: 'owner/repo',
              remediation: 'Update the vulnerable package.',
              created_at: '2026-01-02T00:02:00Z'
            },
            {
              id: 'repo-runner',
              scan_id: 'repo-scan-1',
              type: 'repo_misconfiguration',
              severity: 'high',
              detector: 'workflow_self_hosted_runner',
              title: 'Self-hosted runner is reachable from repository workflow',
              human_summary: 'A workflow can execute on a self-hosted runner.',
              repository: 'owner/repo',
              remediation: 'Restrict runner labels and workflow triggers.',
              created_at: '2026-01-02T00:03:00Z'
            },
            {
              id: 'repo-org',
              scan_id: 'repo-scan-1',
              type: 'repo_misconfiguration',
              severity: 'low',
              detector: 'org_secret_scanning_policy',
              title: 'Organization secret scanning policy needs review',
              human_summary: 'Organization policy is not uniformly enforced.',
              repository: 'owner/repo',
              remediation: 'Enable organization-level secret scanning policy.',
              created_at: '2026-01-02T00:04:00Z'
            },
            {
              id: 'repo-out-of-scope',
              scan_id: 'repo-scan-1',
              type: 'license_notice',
              severity: 'low',
              detector: 'license_notice',
              title: 'Out-of-scope repository notice',
              human_summary: 'This finding should not affect AI Risks metrics.',
              repository: 'owner/unrelated',
              file_path: 'NOTICE',
              remediation: 'Review license notice separately.',
              created_at: '2026-01-02T00:10:00Z'
            }
          ],
          next_cursor: 'repo-page-2'
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/github/agentic-risk');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /^AI \/ Agentic Risk$/i })).toBeInTheDocument();
    const summary = await screen.findByLabelText(/^AI \/ Agentic Risk summary$/i);
    const openMetric = within(summary).getByText('Open').closest('article') as HTMLElement;
    const repoMetric = within(summary).getByText('Repos').closest('article') as HTMLElement;
    expect(within(openMetric).getByText('10')).toBeInTheDocument();
    expect(within(repoMetric).getByText('6')).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('cursor=repo-page-2'))).toBe(true);
    expect(screen.queryByText(/Out-of-scope repository notice/i)).not.toBeInTheDocument();
    expect((await screen.findAllByText(/AI\/MCP Exposure/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/AI Workflow Risk/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/GitHub Alerts/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/Runner Risk/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/Org Policy/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/Fix Ready/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/AI workflow prompt injection can reach Claude/i)).length).toBeGreaterThan(0);
    expect(await screen.findByText(/Repository hotspots/i)).toBeInTheDocument();
    expect((await screen.findAllByText(/owner\/repo/i)).length).toBeGreaterThan(0);
    expect(await screen.findByText(/Scan health/i)).toBeInTheDocument();
    expect(await screen.findByText(/Success rate/i)).toBeInTheDocument();
    expect((await screen.findAllByText(/3 high priority/i)).length).toBeGreaterThan(0);
  });

  it('keeps the GitHub AI / Agentic Risk dashboard usable when trend loading fails', async () => {
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
              started_at: '2026-01-02T00:00:00Z',
              finished_at: '2026-01-02T00:05:00Z',
              commits_scanned: 12,
              files_scanned: 9,
              finding_count: 1,
              truncated: false
            }
          ]
        });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return errorJSON(503, 'trend down');
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({
          summary: {
            total_open: 1,
            fixed_count: 0,
            reopened_count: 0,
            suppressed_count: 0,
            sla_aged_count: 0,
            mttr_ready_resolved_count: 0,
            by_owner: {},
            by_detector: {},
            by_severity: { high: 1 }
          },
          items: [
            {
              id: 'repo-ai',
              scan_id: 'repo-scan-1',
              type: 'ai_agent_surface',
              severity: 'high',
              detector: 'ai_agent_config_secret_ref',
              title: 'MCP server exposes sensitive environment references',
              human_summary: 'An MCP configuration exposes sensitive environment variable names.',
              repository: 'owner/repo',
              file_path: '.mcp.json',
              remediation: 'Move sensitive values behind scoped secrets.',
              created_at: '2026-01-02T00:00:00Z'
            }
          ]
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/github/agentic-risk');
    render(<App />);

    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/v1/repo-findings'))).toBe(true));
    expect(await screen.findByRole('heading', { level: 2, name: /^AI \/ Agentic Risk$/i })).toBeInTheDocument();
    expect(await screen.findByText(/MCP server exposes sensitive environment references/i)).toBeInTheDocument();
    expect(await screen.findByText(/Trend unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText(/No AI \/ Agentic Risk yet/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Failed to load AI \/ Agentic Risk/i)).not.toBeInTheDocument();
  });

  it('allows suppressed repository finding assignee edits without a new suppression reason', async () => {
    const suppressionExpiresAt = '2027-01-01T00:00:00Z';
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.includes('/v1/findings/repo-f1/triage')) {
        return okJSON({
          finding: {
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
            triage: { status: 'suppressed', assignee: 'platform', suppression_expires_at: suppressionExpiresAt },
            created_at: '2026-01-01T00:00:00Z'
          }
        });
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
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-risk-graph')) {
        return okJSON(repoRiskGraphPayload());
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
              triage: { status: 'suppressed', assignee: 'secops', suppression_expires_at: suppressionExpiresAt },
              created_at: '2026-01-01T00:00:00Z'
            }
          ]
        });
      }
      throw new Error(`Unexpected URL ${url} ${init?.method ?? 'GET'}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/app/tenant-a/workspace-a/github/findings');
    render(<App />);

    const findingRow = (await screen.findByText(/Potential AWS access key exposed in commit history/i)).closest('button');
    expect(findingRow).not.toBeNull();
    if (!findingRow) {
      throw new Error('finding row');
    }
    fireEvent.click(findingRow);

    const findingDialog = await screen.findByRole('dialog', {
      name: /Potential AWS access key exposed in commit history/i
    });
    const workflowControls = within(findingDialog).getByText(/Workflow controls/i).closest('.idt-repo-finding-triage-form');
    expect(workflowControls).toBeInTheDocument();

    fireEvent.change(within(workflowControls as HTMLElement).getByLabelText(/Assignee/i), { target: { value: 'platform' } });
    fireEvent.click(within(workflowControls as HTMLElement).getByRole('button', { name: /Apply workflow/i }));

    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(([url]) => String(url).includes('/v1/findings/repo-f1/triage'))
      ).toBe(true);
    });

    const triageCall = fetchMock.mock.calls.find(([url]) => String(url).includes('/v1/findings/repo-f1/triage'));
    const payload = JSON.parse(String((triageCall?.[1] as RequestInit | undefined)?.body));
    expect(payload.assignee).toBe('platform');
    expect(payload.comment).toBeUndefined();
    expect(payload.status).toBeUndefined();
    expect(screen.queryByText(/Suppression requires a reason/i)).not.toBeInTheDocument();
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
          scopes: null,
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
    expect(await screen.findByText(/None granted/i)).toBeInTheDocument();
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
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a'));
      }
      if (url.includes('/v1/onboarding/state')) {
        return okJSON({
          state: {
            user_id: 'user-1',
            current_step: 'connect',
            org_id: 'tenant-a',
            workspace_id: 'workspace-a',
            connector_skipped: false,
            scan_skipped: false,
            started_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-01T00:00:00Z'
          }
        });
      }
      if (url.includes('/v1/workspaces/workspace-a/projects')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-scans')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings/trends')) {
        return okJSON({ items: [] });
      }
      if (url.includes('/v1/repo-findings')) {
        return okJSON({ items: [] });
      }
      throw new Error(`Unexpected URL ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/auth/callback');
    render(<App />);

    await waitFor(() => expect(window.location.pathname).toBe('/app/tenant-a/workspace-a'));
    await waitFor(
      () => expect(screen.getByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument(),
      { timeout: 10000 }
    );
    expect(window.location.pathname).toBe('/app/tenant-a/workspace-a');
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/v1/auth/config'))).toBe(false);
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
    fireEvent.click(screen.getByRole('button', { name: /^Continue$/i }));

    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/tenant-a/workspace-a');
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8080/auth/mfa/verify',
      expect.objectContaining({ body: JSON.stringify({ code: '123456' }), credentials: 'include', method: 'POST' })
    );
  });

  it('starts a WorkOS MFA authenticator challenge before asking for the code', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        okJSON({
          mode: 'challenge',
          user_email: 'owner@example.com',
          challenge_started: false,
          factors: [{ id: 'auth_factor_1', type: 'totp' }]
        })
      )
      .mockResolvedValueOnce(okJSON({ challenge_started: true, factor_id: 'auth_factor_1' }))
      .mockResolvedValueOnce(okJSON({ ok: true, redirect_to: '/app/tenant-a/workspace-a' }))
      .mockResolvedValueOnce(okJSON(currentMePayload('tenant-a', 'workspace-a')));
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/auth/mfa?return_to=%2Fapp');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Enter verification code/i })).toBeInTheDocument();
    expect(await screen.findByLabelText(/Authentication code/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Use authenticator app/i })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Authentication code/i), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: /^Continue$/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        'http://localhost:8080/auth/mfa/challenge',
        expect.objectContaining({
          body: JSON.stringify({ factor_id: 'auth_factor_1' }),
          credentials: 'include',
          method: 'POST'
        })
      );
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8080/auth/mfa/verify',
      expect.objectContaining({ body: JSON.stringify({ code: '123456' }), credentials: 'include', method: 'POST' })
    );
    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/app/tenant-a/workspace-a');
  });

  it('defers WorkOS MFA verify until the silent challenge completes when the form is programmatically submitted', async () => {
    // tsc -b (incremental build) can't track that the executor assigns
    // `resolveChallenge` synchronously, so initialize with a no-op default
    // to keep the type callable instead of narrowing to `never`. Use the
    // okJSON return type so the resolved value matches what the fetch mock
    // returns elsewhere in this file.
    type MockedFetchResponse = ReturnType<typeof okJSON>;
    let resolveChallenge: (value: MockedFetchResponse) => void = () => {};
    const challengeResponse = okJSON({ challenge_started: true, factor_id: 'auth_factor_1' });
    const pendingChallenge = new Promise<MockedFetchResponse>((resolve) => {
      resolveChallenge = resolve;
    });

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        okJSON({
          mode: 'challenge',
          user_email: 'owner@example.com',
          challenge_started: false,
          factors: [{ id: 'auth_factor_1', type: 'totp' }]
        })
      )
      .mockReturnValueOnce(pendingChallenge)
      .mockResolvedValueOnce(okJSON({ ok: true, redirect_to: '/app/tenant-a/workspace-a' }))
      .mockResolvedValueOnce(okJSON(currentMePayload('tenant-a', 'workspace-a')));
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/auth/mfa?return_to=%2Fapp');
    render(<App />);

    const input = await screen.findByLabelText(/Authentication code/i);
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        'http://localhost:8080/auth/mfa/challenge',
        expect.objectContaining({ method: 'POST' })
      );
    });

    fireEvent.change(input, { target: { value: '123456' } });
    // Simulate an OTP autofill helper or programmatic submit (Enter / form.requestSubmit)
    // that bypasses the disabled submit button while the challenge is in flight.
    const form = input.closest('form');
    expect(form).not.toBeNull();
    fireEvent.submit(form as HTMLFormElement);

    // Verify must not fire yet — the silent challenge is still pending.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(fetchMock).not.toHaveBeenCalledWith(
      'http://localhost:8080/auth/mfa/verify',
      expect.anything()
    );

    // Resolve the challenge; verify should then proceed and the app should land.
    resolveChallenge(challengeResponse);

    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8080/auth/mfa/verify',
      expect.objectContaining({ body: JSON.stringify({ code: '123456' }), credentials: 'include', method: 'POST' })
    );
    expect(window.location.pathname).toBe('/app/tenant-a/workspace-a');
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

  it('renders the downloadable executive report from the API response', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/v1/me')) {
        return okJSON(currentMePayload('tenant-a', 'workspace-a', 'viewer'));
      }
      if (url.endsWith('/v1/enterprise/reports/executive')) {
        return okJSON({
          organization_id: 'tenant-a',
          generated_at: '2026-05-17T12:00:00Z',
          window_start: '2026-05-10T12:00:00Z',
          window_end: '2026-05-17T12:00:00Z',
          total_open_findings: 7,
          open_by_severity: { critical: 2, high: 3, medium: 1, low: 1 },
          open_by_type: { secret_exposure: 4, repo_misconfiguration: 3 },
          top_finding_types: [
            { type: 'secret_exposure', count: 4 },
            { type: 'repo_misconfiguration', count: 3 }
          ],
          week_over_week: { current_count: 5, previous_count: 2, delta: 3 },
          mean_time_to_resolve: { resolved_count: 2, seconds: 1800 }
        });
      }
      return errorJSON(404, `unexpected ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    setCurrentPath('/reports/executive');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 1, name: /Risk posture summary/i })).toBeInTheDocument();
    expect(screen.getByText('tenant-a')).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument();
    expect(screen.getByText('5 critical or high')).toBeInTheDocument();
    expect(screen.getAllByText('30m').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Secret Exposure').length).toBeGreaterThan(0);
    expect(screen.getByRole('heading', { level: 2, name: /Severity composition/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /Top finding types/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: /Notes for leadership/i })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Review findings/i })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Download report/i })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8080/v1/enterprise/reports/executive',
      expect.objectContaining({
        credentials: 'include',
        headers: expect.any(Headers)
      })
    );
  });
});
