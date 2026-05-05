import { afterEach, describe, expect, it, vi } from 'vitest';
import handler, { __resetLeadRequestBucketsForTests } from './leads';

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

describe('web/api/leads handler', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.LEAD_WEBHOOK_URL;
    delete process.env.LEAD_WEBHOOK_HMAC_SECRET;
    delete process.env.LEAD_WEBHOOK_TIMEOUT_MS;
    delete process.env.LEAD_CAPTURE_RATE_LIMIT_PER_MIN;
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
    expect(res.body).toEqual({ error: 'Valid work email is required.' });
  });

  it('returns 503 when lead webhook is not configured', async () => {
    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes',
          deployment_model: 'Hosted SaaS',
          urgency: 'This quarter',
          team_size: '6-20',
          scan_goal: 'AWS IAM + Kubernetes trust-path risk reduction',
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

  it('silently accepts honeypot challenge submissions without forwarding', async () => {
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
          challenge: 'bot-filled'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).not.toHaveBeenCalled();
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
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
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
          environment: 'AWS IAM + Kubernetes',
          deployment_model: 'Hosted SaaS',
          urgency: 'This quarter',
          team_size: '6-20',
          scan_goal: 'AWS IAM + Kubernetes trust-path risk reduction',
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
