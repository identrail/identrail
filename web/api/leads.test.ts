import { afterEach, describe, expect, it, vi } from 'vitest';
import { resolve4, resolve6, resolveMx } from 'node:dns/promises';
import handler, { __resetLeadRequestBucketsForTests } from './leads';

const dnsMocks = vi.hoisted(() => ({
  resolve4: vi.fn(async () => ['203.0.113.10']),
  resolve6: vi.fn(async () => []),
  resolveMx: vi.fn(async () => [])
}));

vi.mock('node:dns/promises', () => ({
  ...dnsMocks,
  default: dnsMocks
}));

type MockResponse = {
  statusCode: number;
  body: unknown;
  status: (code: number) => { json: (payload: unknown) => void };
};

function createMockResponse(): MockResponse {
  return {
    statusCode: 200,
    body: null,
    status(code: number) {
      this.statusCode = code;
      return {
        json: (payload: unknown) => {
          this.body = payload;
        }
      };
    }
  };
}

const resolve4Mock = vi.mocked(resolve4);
const resolve6Mock = vi.mocked(resolve6);
const resolveMxMock = vi.mocked(resolveMx);

function mockCompanyDomainDNS(hasRecords = true) {
  resolve4Mock.mockReset();
  resolve6Mock.mockReset();
  resolveMxMock.mockReset();

  if (hasRecords) {
    resolve4Mock.mockResolvedValue(['203.0.113.10']);
  } else {
    resolve4Mock.mockRejectedValue(new Error('not found'));
  }
  resolve6Mock.mockRejectedValue(new Error('not found'));
  resolveMxMock.mockRejectedValue(new Error('not found'));
}

const readOnlyScanDetails = {
  full_name: 'Alex Morgan',
  role_title: 'Security Engineering Lead',
  identity_provider: 'AWS IAM Identity Center / SSO',
  infrastructure_scope: '1-5 cloud accounts or clusters'
};

describe('web/api/leads handler', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.RESEND_API_KEY;
    delete process.env.LEAD_NOTIFY_TO;
    delete process.env.LEAD_EMAIL_FROM;
    delete process.env.LEAD_EMAIL_SUBJECT_PREFIX;
    delete process.env.LEAD_EMAIL_TIMEOUT_MS;
    delete process.env.LEAD_REPLY_TO;
    delete process.env.LEAD_CONFIRMATION_ENABLED;
    delete process.env.LEAD_CONFIRMATION_SUBJECT;
    delete process.env.LEAD_WEBHOOK_URL;
    delete process.env.LEAD_WEBHOOK_HMAC_SECRET;
    delete process.env.LEAD_WEBHOOK_TIMEOUT_MS;
    delete process.env.LEAD_CAPTURE_RATE_LIMIT_PER_MIN;
    mockCompanyDomainDNS(true);
    __resetLeadRequestBucketsForTests();
  });

  it('rejects invalid email payloads', async () => {
    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'invalid-email',
          environment: 'AWS IAM'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Please use a company or work email address.' });
  });

  it('rejects common personal email domains before delivery', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'person@gmail.com',
          environment: 'AWS IAM'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Please use a company or work email address.' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects disposable bot email domains before delivery', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'person@mailinator.com',
          environment: 'AWS IAM'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Please use a company or work email address.' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('requires a matching company domain for read-only scan requests', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'other-company.com',
          environment: 'AWS IAM',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Company website must match the domain in your work email.' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('requires requester details for read-only scan requests', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM',
          role_title: readOnlyScanDetails.role_title,
          identity_provider: readOnlyScanDetails.identity_provider,
          infrastructure_scope: readOnlyScanDetails.infrastructure_scope,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Full name is required.' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects read-only scan company domains without public DNS records', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    mockCompanyDomainDNS(false);
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Company website must be a registered domain with public DNS records.' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects invalid public repository URLs for read-only scan requests', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM',
          repository_url: 'https://example.com/company/repo',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({
      error: 'Public repository URL must be a valid GitHub, GitLab, or Bitbucket organization or repository URL.'
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects non-string public repository URL values without throwing', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM',
          repository_url: 123,
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({
      error: 'Public repository URL must be a valid GitHub, GitLab, or Bitbucket organization or repository URL.'
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects non-web public repository URL schemes', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM',
          repository_url: 'ssh://git@github.com/company/repo',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({
      error: 'Public repository URL must be a valid GitHub, GitLab, or Bitbucket organization or repository URL.'
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('treats a stalled DNS resolver as no public records instead of hanging', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    resolve4Mock.mockReset();
    resolve6Mock.mockReset();
    resolveMxMock.mockReset();
    const never = new Promise<string[]>(() => {});
    resolve4Mock.mockReturnValue(never);
    resolve6Mock.mockReturnValue(never);
    resolveMxMock.mockReturnValue(never);
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);
    vi.useFakeTimers();

    const res = createMockResponse();
    const pending = handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );
    await vi.advanceTimersByTimeAsync(2_000);
    await pending;
    vi.useRealTimers();

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Company website must be a registered domain with public DNS records.' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns 503 when no lead delivery channel is configured', async () => {
    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM + Kubernetes',
          deployment_model: 'Hosted SaaS',
          urgency: 'This quarter',
          team_size: '6-20',
          scan_goal: 'AWS IAM + Kubernetes trust-path risk reduction',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(503);
    expect(res.body).toEqual({ error: 'Lead capture is not configured.' });
  });

  it('rejects insecure non-localhost webhook URLs', async () => {
    process.env.LEAD_WEBHOOK_URL = 'http://example.test/webhook';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      res
    );

    expect(res.statusCode).toBe(503);
    expect(res.body).toEqual({ error: 'Lead capture is not configured.' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('allows localhost IPv6 webhook URLs', async () => {
    process.env.LEAD_WEBHOOK_URL = 'http://[::1]:3001/webhook';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('applies per-IP abuse throttling', async () => {
    process.env.LEAD_WEBHOOK_URL = 'https://example.test/webhook';
    process.env.LEAD_CAPTURE_RATE_LIMIT_PER_MIN = '1';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const first = createMockResponse();
    await handler(
      {
        method: 'POST',
        headers: { 'x-forwarded-for': '203.0.113.8' },
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      first
    );
    expect(first.statusCode).toBe(202);

    const second = createMockResponse();
    await handler(
      {
        method: 'POST',
        headers: { 'x-forwarded-for': '203.0.113.8' },
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      second
    );
    expect(second.statusCode).toBe(429);
    expect(second.body).toEqual({ error: 'Too many lead requests. Please try again shortly.' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('evicts stale rate-limit buckets while keeping the current request history', async () => {
    process.env.LEAD_WEBHOOK_URL = 'https://example.test/webhook';
    process.env.LEAD_CAPTURE_RATE_LIMIT_PER_MIN = '2';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-05-05T12:00:00Z'));

    const stale = createMockResponse();
    await handler(
      {
        method: 'POST',
        headers: { 'x-forwarded-for': '198.51.100.20' },
        body: {
          email: 'stale@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      stale
    );
    expect(stale.statusCode).toBe(202);

    vi.setSystemTime(new Date('2026-05-05T12:02:00Z'));

    const current = createMockResponse();
    await handler(
      {
        method: 'POST',
        headers: { 'x-forwarded-for': '203.0.113.8' },
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      current
    );
    expect(current.statusCode).toBe(202);

    const followUp = createMockResponse();
    await handler(
      {
        method: 'POST',
        headers: { 'x-forwarded-for': '203.0.113.8' },
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      followUp
    );
    expect(followUp.statusCode).toBe(202);
    expect(fetchMock).toHaveBeenCalledTimes(3);

    vi.useRealTimers();
  });

  it('silently accepts honeypot website submissions without forwarding', async () => {
    process.env.LEAD_WEBHOOK_URL = 'https://example.test/webhook';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes',
          website: 'bot-filled'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('sends internal and confirmation emails through Resend when configured', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com, security@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM + Kubernetes',
          challenge: 'Trust path visibility',
          deployment_model: 'Hosted SaaS',
          urgency: 'This quarter',
          team_size: '6-20',
          scan_goal: 'AWS IAM + Kubernetes trust-path risk reduction',
          repository_url: 'gitlab.com/platform/security/identity-risk/-/tree/main',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [notificationURL, notificationInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(notificationURL).toBe('https://api.resend.com/emails');
    const notificationHeaders = (notificationInit.headers ?? {}) as Record<string, string>;
    expect(notificationHeaders.Authorization).toBe('Bearer re_test_key');
    expect(notificationHeaders['Idempotency-Key']).toMatch(/lead-notification$/);
    const notificationBody = JSON.parse(String(notificationInit.body));
    expect(notificationBody).toMatchObject({
      from: 'Identrail <scan@identrail.com>',
      to: ['sales@identrail.com', 'security@identrail.com'],
      reply_to: 'security@company.com',
      subject: '[Identrail] New risk scan request from Company Inc (security@company.com)'
    });
    expect(notificationBody.text).toContain('Name: Alex Morgan');
    expect(notificationBody.text).toContain('Role/title: Security Engineering Lead');
    expect(notificationBody.text).toContain('Public repository: https://gitlab.com/platform/security/identity-risk');

    const [, confirmationInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    const confirmationHeaders = (confirmationInit.headers ?? {}) as Record<string, string>;
    expect(confirmationHeaders['Idempotency-Key']).toMatch(/lead-confirmation$/);
    expect(JSON.parse(String(confirmationInit.body))).toMatchObject({
      from: 'Identrail <scan@identrail.com>',
      to: 'security@company.com',
      reply_to: 'sales@identrail.com',
      subject: 'We received your Identrail risk scan request'
    });
  });

  it('requires an explicit sender address for Resend delivery', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      res
    );

    expect(res.statusCode).toBe(503);
    expect(res.body).toEqual({ error: 'Lead capture is not configured.' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('can disable requester confirmation while still notifying the team', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    process.env.LEAD_CONFIRMATION_ENABLED = 'false';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('accepts the lead when requester confirmation fails after notifying the team', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce({ ok: false });
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [notificationURL] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const [confirmationURL] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(notificationURL).toBe('https://api.resend.com/emails');
    expect(confirmationURL).toBe('https://api.resend.com/emails');
  });

  it('returns 502 when Resend email delivery fails', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    const fetchMock = vi.fn(async () => ({ ok: false }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      res
    );

    expect(res.statusCode).toBe(502);
    expect(res.body).toEqual({ error: 'Lead email delivery failed.' });
  });

  it('still forwards to the webhook when Resend email delivery fails', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    process.env.LEAD_WEBHOOK_URL = 'https://example.test/webhook';
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false })
      .mockResolvedValueOnce({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM + Kubernetes',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [emailURL] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(emailURL).toBe('https://api.resend.com/emails');
    const [webhookURL, webhookInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(webhookURL).toBe('https://example.test/webhook');
    expect(JSON.parse(String(webhookInit.body))).toMatchObject({
      email: 'security@company.com',
      source: 'Read-Only Scan Intake'
    });
  });

  it('accepts the lead when Resend succeeds and optional webhook forwarding fails', async () => {
    process.env.RESEND_API_KEY = 're_test_key';
    process.env.LEAD_NOTIFY_TO = 'sales@identrail.com';
    process.env.LEAD_EMAIL_FROM = 'Identrail <scan@identrail.com>';
    process.env.LEAD_CONFIRMATION_ENABLED = 'false';
    process.env.LEAD_WEBHOOK_URL = 'https://example.test/webhook';
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce({ ok: false });
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [emailURL] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const [webhookURL] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(emailURL).toBe('https://api.resend.com/emails');
    expect(webhookURL).toBe('https://example.test/webhook');
  });

  it('signs outbound requests when webhook signing secret is configured', async () => {
    process.env.LEAD_WEBHOOK_URL = 'https://example.test/webhook';
    process.env.LEAD_WEBHOOK_HMAC_SECRET = 'test-signing-secret';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const headers = (init.headers ?? {}) as Record<string, string>;
    expect(headers['X-Identrail-Signature']).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(headers['X-Identrail-Lead-Request-ID']).toBeTruthy();
    expect(init.signal).toBeDefined();
  });

  it('accepts payloads when webhook forwarding succeeds', async () => {
    process.env.LEAD_WEBHOOK_URL = 'https://example.test/webhook';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          company: 'Company Inc',
          company_domain: 'company.com',
          environment: 'AWS IAM + Kubernetes',
          challenge: 'Trust path visibility',
          deployment_model: 'Hosted SaaS',
          urgency: 'This quarter',
          team_size: '6-20',
          scan_goal: 'AWS IAM + Kubernetes trust-path risk reduction',
          ...readOnlyScanDetails,
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toMatchObject({
      email: 'security@company.com',
      full_name: 'Alex Morgan',
      role_title: 'Security Engineering Lead',
      environment: 'AWS IAM + Kubernetes',
      challenge: 'Trust path visibility',
      identity_provider: 'AWS IAM Identity Center / SSO',
      infrastructure_scope: '1-5 cloud accounts or clusters'
    });
  });
});
