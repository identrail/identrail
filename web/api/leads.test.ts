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
