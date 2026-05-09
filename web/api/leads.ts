import { createHmac, randomUUID } from 'node:crypto';

type LeadCapturePayload = {
  email?: string;
  environment?: string;
  company?: string;
  challenge?: string;
  deployment_model?: string;
  scan_goal?: string;
  urgency?: string;
  team_size?: string;
  source?: string;
  page_path?: string;
};

const ALLOWED_DEPLOYMENT_MODELS = new Set(['Hosted SaaS', 'Self-hosted open-core', 'Enterprise private tenancy']);
const ALLOWED_URGENCY = new Set(['This quarter', 'This month', 'Immediate']);
const ALLOWED_TEAM_SIZE = new Set(['1-5', '6-20', '21-50', '50+']);
const DEFAULT_FORWARD_TIMEOUT_MS = 3_000;
const MIN_FORWARD_TIMEOUT_MS = 500;
const MAX_FORWARD_TIMEOUT_MS = 10_000;
const DEFAULT_RATE_LIMIT_PER_MIN = 15;
const MIN_RATE_LIMIT_PER_MIN = 1;
const MAX_RATE_LIMIT_PER_MIN = 120;
const RATE_WINDOW_MS = 60_000;
const MAX_EMAIL_LENGTH = 254;
const MAX_ENVIRONMENT_LENGTH = 180;
const MAX_COMPANY_LENGTH = 120;
const MAX_CHALLENGE_LENGTH = 2_000;
const MAX_SCAN_GOAL_LENGTH = 600;
const MAX_SOURCE_LENGTH = 120;
const MAX_PAGE_PATH_LENGTH = 240;
const MAX_TEAM_SIZE_LENGTH = 16;
const MAX_URGENCY_LENGTH = 32;
const MAX_DEPLOYMENT_MODEL_LENGTH = 64;
const leadRequestBuckets = new Map<string, number[]>();

export function __resetLeadRequestBucketsForTests() {
  leadRequestBuckets.clear();
}

type HandlerRequest = {
  method?: string;
  body?: unknown;
  headers?: Record<string, string | string[] | undefined>;
};

type HandlerResponse = {
  status: (code: number) => { json: (payload: unknown) => void };
};

function trimOptional(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function badRequest(res: HandlerResponse, message: string) {
  res.status(400).json({ error: message });
}

function getEnv(): Record<string, string | undefined> {
  return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {};
}

function parseBoundedInt(value: string | undefined, fallback: number, min: number, max: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  if (parsed < min) {
    return min;
  }
  if (parsed > max) {
    return max;
  }
  return parsed;
}

function readHeader(headers: HandlerRequest['headers'], name: string): string {
  if (!headers) {
    return '';
  }
  const lowerName = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== lowerName || value == null) {
      continue;
    }
    if (Array.isArray(value)) {
      return String(value[0] ?? '').trim();
    }
    return String(value).trim();
  }
  return '';
}

function requestIP(req: HandlerRequest): string {
  const forwarded = readHeader(req.headers, 'x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0].trim() || 'unknown';
  }
  const realIP = readHeader(req.headers, 'x-real-ip');
  return realIP || 'unknown';
}

function checkRateLimit(ip: string, now: number, maxPerMinute: number): boolean {
  const threshold = now - RATE_WINDOW_MS;
  for (const [bucketIP, bucket] of leadRequestBuckets.entries()) {
    const fresh = bucket.filter((ts) => ts >= threshold);
    if (fresh.length == 0) {
      leadRequestBuckets.delete(bucketIP);
      continue;
    }
    if (fresh.length != bucket.length) {
      leadRequestBuckets.set(bucketIP, fresh);
    }
  }
  const entries = leadRequestBuckets.get(ip) ?? [];
  const recent = entries.filter((ts) => ts >= threshold);
  if (recent.length >= maxPerMinute) {
    leadRequestBuckets.set(ip, recent);
    return false;
  }
  recent.push(now);
  leadRequestBuckets.set(ip, recent);
  return true;
}

function parseWebhookURL(rawWebhook: string): URL | null {
  try {
    return new URL(rawWebhook);
  } catch {
    return null;
  }
}

function isLocalHost(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase();
  return normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1' || normalized === '[::1]';
}

function hasValidWebhookURL(webhookURL: URL): boolean {
  if (webhookURL.protocol === 'https:') {
    return true;
  }
  return webhookURL.protocol === 'http:' && isLocalHost(webhookURL.hostname);
}

function assertLength(res: HandlerResponse, value: string, maxLength: number, message: string): boolean {
  if (value.length <= maxLength) {
    return true;
  }
  badRequest(res, message);
  return false;
}

export default async function handler(
  req: HandlerRequest,
  res: HandlerResponse
) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const env = getEnv();
  const rateLimitPerMinute = parseBoundedInt(
    env.LEAD_CAPTURE_RATE_LIMIT_PER_MIN,
    DEFAULT_RATE_LIMIT_PER_MIN,
    MIN_RATE_LIMIT_PER_MIN,
    MAX_RATE_LIMIT_PER_MIN
  );
  if (!checkRateLimit(requestIP(req), Date.now(), rateLimitPerMinute)) {
    res.status(429).json({ error: 'Too many lead requests. Please try again shortly.' });
    return;
  }

  const body: LeadCapturePayload = req.body && typeof req.body === 'object' ? (req.body as LeadCapturePayload) : {};
  const email = trimOptional(body.email) ?? '';
  const environment = trimOptional(body.environment) ?? '';
  const company = trimOptional(body.company);
  const challenge = trimOptional(body.challenge);
  const scanGoal = trimOptional(body.scan_goal);
  const source = trimOptional(body.source) || 'unknown';
  const pagePath = trimOptional(body.page_path) || '/';

  if (!email || !isValidEmail(email)) {
    badRequest(res, 'Valid work email is required.');
    return;
  }

  if (!environment) {
    badRequest(res, 'Environment is required.');
    return;
  }

  if (!assertLength(res, email, MAX_EMAIL_LENGTH, 'Email is too long.')) {
    return;
  }
  if (!assertLength(res, environment, MAX_ENVIRONMENT_LENGTH, 'Environment value is too long.')) {
    return;
  }
  if (company && !assertLength(res, company, MAX_COMPANY_LENGTH, 'Company value is too long.')) {
    return;
  }
  if (challenge && !assertLength(res, challenge, MAX_CHALLENGE_LENGTH, 'Challenge value is too long.')) {
    return;
  }
  if (scanGoal && !assertLength(res, scanGoal, MAX_SCAN_GOAL_LENGTH, 'Scan goal value is too long.')) {
    return;
  }
  if (!assertLength(res, source, MAX_SOURCE_LENGTH, 'Source value is too long.')) {
    return;
  }
  if (!assertLength(res, pagePath, MAX_PAGE_PATH_LENGTH, 'Page path value is too long.')) {
    return;
  }

  if (challenge) {
    res.status(202).json({ status: 'accepted' });
    return;
  }

  const deploymentModel = trimOptional(body.deployment_model);
  const urgency = trimOptional(body.urgency);
  const teamSize = trimOptional(body.team_size);
  const normalizedPagePath = pagePath.startsWith('/') ? pagePath : '/';

  if (deploymentModel && !assertLength(res, deploymentModel, MAX_DEPLOYMENT_MODEL_LENGTH, 'Deployment model is too long.')) {
    return;
  }
  if (urgency && !assertLength(res, urgency, MAX_URGENCY_LENGTH, 'Urgency value is too long.')) {
    return;
  }
  if (teamSize && !assertLength(res, teamSize, MAX_TEAM_SIZE_LENGTH, 'Team size value is too long.')) {
    return;
  }

  const payload = {
    email,
    environment,
    company,
    challenge: undefined,
    deployment_model: deploymentModel && ALLOWED_DEPLOYMENT_MODELS.has(deploymentModel) ? deploymentModel : undefined,
    scan_goal: scanGoal,
    urgency: urgency && ALLOWED_URGENCY.has(urgency) ? urgency : undefined,
    team_size: teamSize && ALLOWED_TEAM_SIZE.has(teamSize) ? teamSize : undefined,
    source,
    page_path: normalizedPagePath,
    captured_at: new Date().toISOString()
  };

  const webhook = env.LEAD_WEBHOOK_URL?.trim();

  if (!webhook) {
    res.status(503).json({ error: 'Lead capture is not configured.' });
    return;
  }
  const webhookURL = parseWebhookURL(webhook);
  if (!webhookURL || !hasValidWebhookURL(webhookURL)) {
    res.status(503).json({ error: 'Lead capture is not configured.' });
    return;
  }

  const payloadJSON = JSON.stringify(payload);
  const requestID = randomUUID();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Identrail-Lead-Request-ID': requestID
  };
  const signingSecret = env.LEAD_WEBHOOK_HMAC_SECRET?.trim();
  if (signingSecret) {
    headers['X-Identrail-Signature'] = `sha256=${createHmac('sha256', signingSecret).update(payloadJSON).digest('hex')}`;
  }

  const timeoutMS = parseBoundedInt(
    env.LEAD_WEBHOOK_TIMEOUT_MS,
    DEFAULT_FORWARD_TIMEOUT_MS,
    MIN_FORWARD_TIMEOUT_MS,
    MAX_FORWARD_TIMEOUT_MS
  );
  const abortController = new AbortController();
  const timeoutHandle = setTimeout(() => abortController.abort(), timeoutMS);

  try {
    const forward = await fetch(webhookURL.toString(), {
      method: 'POST',
      headers,
      body: payloadJSON,
      signal: abortController.signal
    });
    if (!forward.ok) {
      res.status(502).json({ error: 'Lead forwarding failed.' });
      return;
    }
  } catch {
    res.status(502).json({ error: 'Lead forwarding failed.' });
    return;
  } finally {
    clearTimeout(timeoutHandle);
  }

  res.status(202).json({ status: 'accepted' });
}
