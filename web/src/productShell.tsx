import { Component, FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  apiClient,
  type RequestAuthContext,
  type WhoAmIResponse,
  type WorkspaceMemberRecord,
  type WorkspaceMemberRole,
  type WorkspaceMemberStatus
} from './api/client';

type ProductSessionAuthMode = 'manual' | 'oidc';

type ProductSession = {
  tenantID: string;
  workspaceID: string;
  projectID?: string;
  authMode?: ProductSessionAuthMode;
  accessToken?: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt?: number;
  subject?: string;
  roles?: string[];
};

type ScopeRouteParams = {
  tenantID?: string;
  workspaceID?: string;
  projectID?: string;
};

type ScopedShellPageProps = {
  title: string;
  description: string;
  actionLabel?: string;
  actionTo?: string;
};

type SourceProviderID = 'github' | 'aws' | 'kubernetes';

type SourceOnboardingStepID = 'source' | 'setup' | 'validate' | 'complete';

type SourceConnectionStatus = 'ready' | 'needs_retry' | 'connected';

type SourceConnectionRecord = {
  id: string;
  provider: SourceProviderID;
  displayName: string;
  owner: string;
  environment: string;
  status: SourceConnectionStatus;
  validatedAt: string;
  summary: string;
};

type SourceOnboardingDraft = {
  displayName: string;
  owner: string;
  environment: string;
  githubOrg: string;
  githubInstallationID: string;
  awsAccountID: string;
  awsRoleARN: string;
  awsExternalID: string;
  clusterName: string;
  apiServerURL: string;
  namespace: string;
};

type SourceValidationCheck = {
  label: string;
  passed: boolean;
  detail: string;
};

type SourceValidationState = {
  status: 'idle' | 'running' | 'passed' | 'failed';
  message: string;
  checks: SourceValidationCheck[];
};

type OIDCConfig = {
  issuerURL: string;
  clientID: string;
  scope: string;
  redirectURI: string;
  postLogoutRedirectURI: string;
  tenantClaim: string;
  workspaceClaim: string;
  rolesClaim: string;
};

type OIDCDiscoveryDocument = {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  endSessionEndpoint?: string;
};

type OIDCPendingLogin = {
  state: string;
  codeVerifier: string;
  nextPath: string;
  createdAt: number;
};

type OIDCClaims = {
  sub?: string;
  exp?: number;
  [key: string]: unknown;
};

type OIDCCallbackResult = {
  session: ProductSession;
  nextPath: string;
};

const PRODUCT_SESSION_STORAGE_KEY = 'identrail-product-session';
const OIDC_PENDING_LOGIN_STORAGE_KEY = 'identrail-oidc-pending-login';
const SOURCE_ONBOARDING_STORAGE_KEY = 'identrail-source-onboarding-v1';

type ProductSessionTokens = {
  accessToken?: string;
  refreshToken?: string;
  idToken?: string;
};

let inMemoryTokens: ProductSessionTokens = {};
const OIDC_REFRESH_SKEW_MS = 90 * 1000;
const OIDC_MAX_PENDING_LOGIN_AGE_MS = 10 * 60 * 1000;

const SOURCE_ONBOARDING_STEPS: Array<{ id: SourceOnboardingStepID; label: string }> = [
  { id: 'source', label: 'Choose source' },
  { id: 'setup', label: 'Configure' },
  { id: 'validate', label: 'Validate' },
  { id: 'complete', label: 'Connect' }
];

const SOURCE_PROVIDER_OPTIONS: Array<{
  id: SourceProviderID;
  name: string;
  description: string;
  setupLabel: string;
  validationFocus: string;
}> = [
  {
    id: 'github',
    name: 'GitHub',
    description: 'Connect repository and workflow identity signals with read-only installation scope.',
    setupLabel: 'GitHub App installation',
    validationFocus: 'organization access, installation scope, webhook readiness'
  },
  {
    id: 'aws',
    name: 'AWS IAM',
    description: 'Validate a read-only IAM role before the first account inventory scan is queued.',
    setupLabel: 'Cross-account IAM role',
    validationFocus: 'account ID, role ARN, external ID, read-only policy boundary'
  },
  {
    id: 'kubernetes',
    name: 'Kubernetes',
    description: 'Register a cluster endpoint and namespace boundary for RBAC and service account mapping.',
    setupLabel: 'Cluster service account',
    validationFocus: 'API server reachability, namespace scope, RBAC list permissions'
  }
];

const DEFAULT_SOURCE_DRAFT: SourceOnboardingDraft = {
  displayName: '',
  owner: '',
  environment: 'production',
  githubOrg: '',
  githubInstallationID: '',
  awsAccountID: '',
  awsRoleARN: '',
  awsExternalID: '',
  clusterName: '',
  apiServerURL: '',
  namespace: 'default'
};

function normalizeValue(value: string): string {
  return value.trim();
}

function sourceScopeKey(scope: ProductSession): string {
  return [scope.tenantID, scope.workspaceID, scope.projectID ?? 'workspace'].map(encodeURIComponent).join(':');
}

function readSourceOnboardingStore(): Record<string, SourceConnectionRecord[]> {
  if (typeof window === 'undefined') {
    return {};
  }
  const raw = window.localStorage.getItem(SOURCE_ONBOARDING_STORAGE_KEY);
  if (!raw) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, SourceConnectionRecord[]>;
    if (!parsed || typeof parsed !== 'object') {
      return {};
    }
    return parsed;
  } catch {
    return {};
  }
}

function readSourceConnections(scope: ProductSession): SourceConnectionRecord[] {
  return readSourceOnboardingStore()[sourceScopeKey(scope)] ?? [];
}

function saveSourceConnections(scope: ProductSession, connections: SourceConnectionRecord[]) {
  if (typeof window === 'undefined') {
    return;
  }
  const store = readSourceOnboardingStore();
  store[sourceScopeKey(scope)] = connections;
  window.localStorage.setItem(SOURCE_ONBOARDING_STORAGE_KEY, JSON.stringify(store));
}

function isValidGithubOrg(value: string): boolean {
  return /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(value);
}

function isValidAWSAccountID(value: string): boolean {
  return /^\d{12}$/.test(value);
}

function isValidAWSRoleARN(value: string): boolean {
  return /^arn:aws[a-zA-Z-]*:iam::\d{12}:role\/[\w+=,.@/-]{1,128}$/.test(value);
}

function isValidHTTPSURL(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

function createSourceSummary(provider: SourceProviderID, draft: SourceOnboardingDraft): string {
  if (provider === 'github') {
    return `${normalizeValue(draft.githubOrg)} organization`;
  }
  if (provider === 'aws') {
    return `${normalizeValue(draft.awsAccountID)} account`;
  }
  return `${normalizeValue(draft.clusterName)} cluster`;
}

function validateSourceDraft(provider: SourceProviderID, draft: SourceOnboardingDraft): SourceValidationCheck[] {
  const displayName = normalizeValue(draft.displayName);
  const owner = normalizeValue(draft.owner);
  const environment = normalizeValue(draft.environment);
  const checks: SourceValidationCheck[] = [
    {
      label: 'Source name',
      passed: displayName.length >= 3,
      detail: displayName.length >= 3 ? 'Connection name is ready for operators.' : 'Use at least 3 characters.'
    },
    {
      label: 'Owner',
      passed: owner.length >= 3,
      detail: owner.length >= 3 ? 'Owner context is available for triage.' : 'Assign a team or responder.'
    },
    {
      label: 'Environment',
      passed: ['production', 'staging', 'development', 'sandbox'].includes(environment),
      detail: environment ? 'Environment will scope scan priority.' : 'Choose an environment.'
    }
  ];

  if (provider === 'github') {
    const org = normalizeValue(draft.githubOrg);
    const installationID = normalizeValue(draft.githubInstallationID);
    checks.push(
      {
        label: 'Organization',
        passed: isValidGithubOrg(org),
        detail: isValidGithubOrg(org) ? 'Organization slug format is valid.' : 'Enter a valid GitHub organization slug.'
      },
      {
        label: 'Installation',
        passed: /^\d{2,}$/.test(installationID),
        detail: /^\d{2,}$/.test(installationID)
          ? 'Installation ID can be reconciled by the connector service.'
          : 'Enter the numeric GitHub App installation ID.'
      },
      {
        label: 'Permission boundary',
        passed: true,
        detail: 'Requested scope is read-only repository metadata, workflows, and security findings.'
      }
    );
  }

  if (provider === 'aws') {
    const accountID = normalizeValue(draft.awsAccountID);
    const roleARN = normalizeValue(draft.awsRoleARN);
    checks.push(
      {
        label: 'Account ID',
        passed: isValidAWSAccountID(accountID),
        detail: isValidAWSAccountID(accountID) ? 'AWS account ID format is valid.' : 'Enter a 12 digit AWS account ID.'
      },
      {
        label: 'Role ARN',
        passed: isValidAWSRoleARN(roleARN) && roleARN.includes(`::${accountID}:`),
        detail:
          isValidAWSRoleARN(roleARN) && roleARN.includes(`::${accountID}:`)
            ? 'Role ARN matches the selected account.'
            : 'Enter a valid IAM role ARN for this account.'
      },
      {
        label: 'External ID',
        passed: normalizeValue(draft.awsExternalID).length >= 8,
        detail:
          normalizeValue(draft.awsExternalID).length >= 8
            ? 'External ID is present for confused-deputy protection.'
            : 'Use an external ID with at least 8 characters.'
      }
    );
  }

  if (provider === 'kubernetes') {
    const clusterName = normalizeValue(draft.clusterName);
    const namespace = normalizeValue(draft.namespace);
    checks.push(
      {
        label: 'Cluster name',
        passed: clusterName.length >= 3,
        detail: clusterName.length >= 3 ? 'Cluster label is ready for inventory.' : 'Enter a recognizable cluster name.'
      },
      {
        label: 'API server',
        passed: isValidHTTPSURL(normalizeValue(draft.apiServerURL)),
        detail: isValidHTTPSURL(normalizeValue(draft.apiServerURL))
          ? 'API server URL uses HTTPS.'
          : 'Enter an HTTPS Kubernetes API server URL.'
      },
      {
        label: 'Namespace boundary',
        passed: /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(namespace),
        detail: /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(namespace)
          ? 'Namespace scope is valid.'
          : 'Use a valid Kubernetes namespace name.'
      }
    );
  }

  return checks;
}

function normalizeClaimName(value: string, fallback: string): string {
  const normalized = normalizeValue(value);
  return normalized || fallback;
}

function readOIDCConfig(): OIDCConfig | null {
  const issuerURL = normalizeValue(import.meta.env.VITE_OIDC_ISSUER_URL ?? '');
  const clientID = normalizeValue(import.meta.env.VITE_OIDC_CLIENT_ID ?? '');
  if (!issuerURL || !clientID) {
    return null;
  }

  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const redirectURI =
    normalizeValue(import.meta.env.VITE_OIDC_REDIRECT_URI ?? '') ||
    (origin ? `${origin}/app/callback` : '/app/callback');
  const postLogoutRedirectURI =
    normalizeValue(import.meta.env.VITE_OIDC_POST_LOGOUT_REDIRECT_URI ?? '') ||
    (origin ? `${origin}/app/login?signed_out=1` : '/app/login?signed_out=1');

  return {
    issuerURL,
    clientID,
    scope: normalizeValue(import.meta.env.VITE_OIDC_SCOPE ?? '') || 'openid profile email offline_access',
    redirectURI,
    postLogoutRedirectURI,
    tenantClaim: normalizeClaimName(import.meta.env.VITE_OIDC_TENANT_CLAIM ?? '', 'tenant_id'),
    workspaceClaim: normalizeClaimName(import.meta.env.VITE_OIDC_WORKSPACE_CLAIM ?? '', 'workspace_id'),
    rolesClaim: normalizeClaimName(import.meta.env.VITE_OIDC_ROLES_CLAIM ?? '', 'roles')
  };
}

function isOIDCEnabled(): boolean {
  return readOIDCConfig() !== null;
}

async function loadOIDCDiscovery(config: OIDCConfig): Promise<OIDCDiscoveryDocument> {
  const issuer = config.issuerURL.endsWith('/') ? config.issuerURL.slice(0, -1) : config.issuerURL;
  const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
    headers: {
      Accept: 'application/json'
    }
  });
  if (!response.ok) {
    throw new Error(`Failed to load OIDC discovery document (${response.status})`);
  }

  const payload = (await response.json()) as {
    authorization_endpoint?: unknown;
    token_endpoint?: unknown;
    end_session_endpoint?: unknown;
  };

  if (typeof payload.authorization_endpoint !== 'string' || !normalizeValue(payload.authorization_endpoint)) {
    throw new Error('OIDC discovery document missing authorization_endpoint');
  }
  if (typeof payload.token_endpoint !== 'string' || !normalizeValue(payload.token_endpoint)) {
    throw new Error('OIDC discovery document missing token_endpoint');
  }

  return {
    authorizationEndpoint: payload.authorization_endpoint,
    tokenEndpoint: payload.token_endpoint,
    endSessionEndpoint:
      typeof payload.end_session_endpoint === 'string' && normalizeValue(payload.end_session_endpoint)
        ? payload.end_session_endpoint
        : undefined
  };
}

function bytesToBase64URL(bytes: Uint8Array): string {
  let binary = '';
  for (const value of bytes) {
    binary += String.fromCharCode(value);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomString(byteLength: number): string {
  const buffer = new Uint8Array(byteLength);
  crypto.getRandomValues(buffer);
  return bytesToBase64URL(buffer);
}

async function pkceChallenge(codeVerifier: string): Promise<string> {
  if (!crypto?.subtle) {
    throw new Error('Web Crypto API is unavailable for PKCE flow');
  }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  return bytesToBase64URL(new Uint8Array(digest));
}

function readPendingOIDCLogin(): OIDCPendingLogin | null {
  if (typeof window === 'undefined') {
    return null;
  }
  const raw = window.sessionStorage.getItem(OIDC_PENDING_LOGIN_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<OIDCPendingLogin>;
    const state = normalizeValue(parsed.state ?? '');
    const codeVerifier = normalizeValue(parsed.codeVerifier ?? '');
    const nextPath = normalizeValue(parsed.nextPath ?? '');
    const createdAt = Number(parsed.createdAt ?? 0);

    if (!state || !codeVerifier || !nextPath || !Number.isFinite(createdAt) || createdAt <= 0) {
      return null;
    }
    if (Date.now() - createdAt > OIDC_MAX_PENDING_LOGIN_AGE_MS) {
      return null;
    }

    return {
      state,
      codeVerifier,
      nextPath,
      createdAt
    };
  } catch {
    return null;
  }
}

function savePendingOIDCLogin(pending: OIDCPendingLogin) {
  if (typeof window === 'undefined') {
    return;
  }
  window.sessionStorage.setItem(OIDC_PENDING_LOGIN_STORAGE_KEY, JSON.stringify(pending));
}

function clearPendingOIDCLogin() {
  if (typeof window === 'undefined') {
    return;
  }
  window.sessionStorage.removeItem(OIDC_PENDING_LOGIN_STORAGE_KEY);
}

function parseJWTClaims(token: string): OIDCClaims {
  const parts = token.split('.');
  if (parts.length < 2) {
    return {};
  }
  const payload = parts[1];
  if (!payload) {
    return {};
  }

  const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');

  try {
    const decoded = atob(padded);
    return JSON.parse(decoded) as OIDCClaims;
  } catch {
    return {};
  }
}

function claimString(claims: OIDCClaims, key: string): string {
  const value = claims[key];
  if (typeof value !== 'string') {
    return '';
  }
  return normalizeValue(value);
}

function claimStringArray(claims: OIDCClaims, key: string): string[] {
  const value = claims[key];
  if (Array.isArray(value)) {
    const values = value
      .map((entry) => (typeof entry === 'string' ? normalizeValue(entry) : ''))
      .filter((entry) => entry.length > 0);
    return values;
  }
  if (typeof value === 'string') {
    const normalized = normalizeValue(value);
    return normalized ? [normalized] : [];
  }
  return [];
}

function resolveSessionScopeFromClaims(claims: OIDCClaims, config: OIDCConfig): { tenantID: string; workspaceID: string } {
  const tenantID = claimString(claims, config.tenantClaim) || claimString(claims, 'tenant_id') || claimString(claims, 'tenant') || 'default';
  const workspaceID =
    claimString(claims, config.workspaceClaim) ||
    claimString(claims, 'workspace_id') ||
    claimString(claims, 'workspace') ||
    'default';

  return { tenantID, workspaceID };
}

function resolveExpiry(claims: OIDCClaims, expiresInSeconds?: number): number {
  const now = Date.now();
  if (typeof expiresInSeconds === 'number' && Number.isFinite(expiresInSeconds) && expiresInSeconds > 0) {
    return now + expiresInSeconds * 1000;
  }
  const exp = claims.exp;
  if (typeof exp === 'number' && Number.isFinite(exp) && exp > 0) {
    return exp * 1000;
  }
  return now + 5 * 60 * 1000;
}

async function beginOIDCLogin(nextPath: string) {
  const config = readOIDCConfig();
  if (!config) {
    throw new Error('OIDC is not configured for this environment');
  }

  const discovery = await loadOIDCDiscovery(config);
  const state = randomString(24);
  const codeVerifier = randomString(64);
  const challenge = await pkceChallenge(codeVerifier);

  savePendingOIDCLogin({
    state,
    codeVerifier,
    nextPath: nextPath.startsWith('/app/') ? nextPath : '/app',
    createdAt: Date.now()
  });

  const authorizationURL = new URL(discovery.authorizationEndpoint);
  authorizationURL.searchParams.set('client_id', config.clientID);
  authorizationURL.searchParams.set('response_type', 'code');
  authorizationURL.searchParams.set('scope', config.scope);
  authorizationURL.searchParams.set('redirect_uri', config.redirectURI);
  authorizationURL.searchParams.set('state', state);
  authorizationURL.searchParams.set('code_challenge', challenge);
  authorizationURL.searchParams.set('code_challenge_method', 'S256');

  window.location.assign(authorizationURL.toString());
}

async function completeOIDCCallback(search: string): Promise<OIDCCallbackResult> {
  const config = readOIDCConfig();
  if (!config) {
    throw new Error('OIDC is not configured for this environment');
  }

  const params = new URLSearchParams(search);
  const callbackError = normalizeValue(params.get('error') ?? '');
  if (callbackError) {
    const callbackErrorDescription = normalizeValue(params.get('error_description') ?? '');
    throw new Error(callbackErrorDescription ? `${callbackError}: ${callbackErrorDescription}` : callbackError);
  }

  const code = normalizeValue(params.get('code') ?? '');
  const state = normalizeValue(params.get('state') ?? '');
  if (!code || !state) {
    throw new Error('Missing code/state callback parameters');
  }

  const pending = readPendingOIDCLogin();
  clearPendingOIDCLogin();
  if (!pending || pending.state !== state) {
    throw new Error('OIDC callback state mismatch');
  }

  const discovery = await loadOIDCDiscovery(config);
  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('client_id', config.clientID);
  body.set('code', code);
  body.set('redirect_uri', config.redirectURI);
  body.set('code_verifier', pending.codeVerifier);

  const tokenResponse = await fetch(discovery.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body
  });

  const tokenPayload = (await tokenResponse.json()) as {
    access_token?: unknown;
    refresh_token?: unknown;
    id_token?: unknown;
    expires_in?: unknown;
    error?: unknown;
    error_description?: unknown;
  };

  if (!tokenResponse.ok) {
    const tokenError = typeof tokenPayload.error === 'string' ? tokenPayload.error : 'token_exchange_failed';
    const tokenErrorDescription =
      typeof tokenPayload.error_description === 'string' ? tokenPayload.error_description : '';
    throw new Error(tokenErrorDescription ? `${tokenError}: ${tokenErrorDescription}` : tokenError);
  }

  const accessToken = typeof tokenPayload.access_token === 'string' ? tokenPayload.access_token : '';
  if (!accessToken) {
    throw new Error('OIDC token response did not include access_token');
  }

  const idToken = typeof tokenPayload.id_token === 'string' ? tokenPayload.id_token : undefined;
  const refreshToken = typeof tokenPayload.refresh_token === 'string' ? tokenPayload.refresh_token : undefined;

  const idClaims = idToken ? parseJWTClaims(idToken) : {};
  const accessClaims = parseJWTClaims(accessToken);
  const claims = Object.keys(idClaims).length > 0 ? idClaims : accessClaims;

  const { tenantID, workspaceID } = resolveSessionScopeFromClaims(claims, config);
  const subject = claimString(claims, 'sub') || undefined;
  const roles = claimStringArray(claims, config.rolesClaim);
  const expiresIn =
    typeof tokenPayload.expires_in === 'number'
      ? tokenPayload.expires_in
      : Number.parseInt(String(tokenPayload.expires_in ?? ''), 10);

  const session: ProductSession = {
    tenantID,
    workspaceID,
    authMode: 'oidc',
    accessToken,
    refreshToken,
    idToken,
    expiresAt: resolveExpiry(claims, Number.isFinite(expiresIn) ? expiresIn : undefined),
    subject,
    roles: roles.length > 0 ? roles : undefined
  };

  const nextPath = pending.nextPath.startsWith('/app/') ? pending.nextPath : buildTenantWorkspacePath(session.tenantID, session.workspaceID);

  return { session, nextPath };
}

function readProductSession(): ProductSession | null {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    const raw = window.sessionStorage.getItem(PRODUCT_SESSION_STORAGE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as Partial<ProductSession>;
    const tenantID = normalizeValue(parsed.tenantID ?? '');
    const workspaceID = normalizeValue(parsed.workspaceID ?? '');
    if (!tenantID || !workspaceID) {
      return null;
    }

    const authMode: ProductSessionAuthMode = parsed.authMode === 'oidc' ? 'oidc' : 'manual';
    const accessToken = normalizeValue(inMemoryTokens.accessToken ?? '') || undefined;
    const refreshToken = normalizeValue(inMemoryTokens.refreshToken ?? '') || undefined;
    const idToken = normalizeValue(inMemoryTokens.idToken ?? '') || undefined;
    const subject = normalizeValue(parsed.subject ?? '') || undefined;
    const expiresAtRaw = Number(parsed.expiresAt ?? 0);
    const roles = Array.isArray(parsed.roles)
      ? parsed.roles
          .map((role) => normalizeValue(String(role ?? '')))
          .filter((role) => role.length > 0)
      : undefined;

    return {
      tenantID,
      workspaceID,
      projectID: normalizeValue(parsed.projectID ?? '') || undefined,
      authMode,
      accessToken,
      refreshToken,
      idToken,
      subject,
      expiresAt: Number.isFinite(expiresAtRaw) && expiresAtRaw > 0 ? expiresAtRaw : undefined,
      roles: roles && roles.length > 0 ? roles : undefined
    };
  } catch {
    return null;
  }
}

export function saveProductSession(session: ProductSession) {
  if (typeof window === 'undefined') {
    return;
  }
  inMemoryTokens = {
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    idToken: session.idToken
  };
  const { accessToken: _a, refreshToken: _r, idToken: _i, ...persistable } = session;
  window.localStorage.removeItem(PRODUCT_SESSION_STORAGE_KEY);
  window.sessionStorage.setItem(PRODUCT_SESSION_STORAGE_KEY, JSON.stringify(persistable));
}

function clearProductSession() {
  inMemoryTokens = {};
  if (typeof window === 'undefined') {
    return;
  }
  window.sessionStorage.removeItem(PRODUCT_SESSION_STORAGE_KEY);
}

function isOIDCSession(session: ProductSession): boolean {
  return session.authMode === 'oidc';
}

function isSessionExpired(session: ProductSession): boolean {
  if (!isOIDCSession(session)) {
    return false;
  }
  if (!session.expiresAt) {
    return true;
  }
  return Date.now() >= session.expiresAt;
}

function needsSessionRefresh(session: ProductSession): boolean {
  if (!isOIDCSession(session) || !session.expiresAt) {
    return false;
  }
  return session.expiresAt - Date.now() <= OIDC_REFRESH_SKEW_MS;
}

async function refreshOIDCSession(session: ProductSession): Promise<ProductSession | null> {
  if (!isOIDCSession(session) || !session.refreshToken) {
    return null;
  }

  const config = readOIDCConfig();
  if (!config) {
    return null;
  }

  const discovery = await loadOIDCDiscovery(config);
  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  body.set('client_id', config.clientID);
  body.set('refresh_token', session.refreshToken);

  const refreshResponse = await fetch(discovery.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body
  });

  const payload = (await refreshResponse.json()) as {
    access_token?: unknown;
    refresh_token?: unknown;
    id_token?: unknown;
    expires_in?: unknown;
  };

  if (!refreshResponse.ok) {
    return null;
  }

  const accessToken = typeof payload.access_token === 'string' ? payload.access_token : '';
  if (!accessToken) {
    return null;
  }

  const idToken = typeof payload.id_token === 'string' ? payload.id_token : session.idToken;
  const refreshToken =
    typeof payload.refresh_token === 'string' && normalizeValue(payload.refresh_token)
      ? payload.refresh_token
      : session.refreshToken;

  const claims = idToken ? parseJWTClaims(idToken) : parseJWTClaims(accessToken);
  const { tenantID, workspaceID } = resolveSessionScopeFromClaims(claims, config);
  const subject = claimString(claims, 'sub') || session.subject;
  const roles = claimStringArray(claims, config.rolesClaim);
  const expiresIn =
    typeof payload.expires_in === 'number' ? payload.expires_in : Number.parseInt(String(payload.expires_in ?? ''), 10);

  return {
    ...session,
    tenantID,
    workspaceID,
    accessToken,
    refreshToken,
    idToken,
    subject,
    roles: roles.length > 0 ? roles : session.roles,
    expiresAt: resolveExpiry(claims, Number.isFinite(expiresIn) ? expiresIn : undefined)
  };
}

async function ensureActiveSession(session: ProductSession): Promise<ProductSession | null> {
  if (!isOIDCSession(session)) {
    return session;
  }

  if (!isSessionExpired(session) && !needsSessionRefresh(session)) {
    return session;
  }

  return refreshOIDCSession(session);
}

async function resolveOIDCLogoutURL(session: ProductSession): Promise<string | null> {
  if (!isOIDCSession(session)) {
    return null;
  }

  const config = readOIDCConfig();
  if (!config) {
    return null;
  }

  const discovery = await loadOIDCDiscovery(config);
  if (!discovery.endSessionEndpoint) {
    return null;
  }

  const logoutURL = new URL(discovery.endSessionEndpoint);
  logoutURL.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectURI);
  logoutURL.searchParams.set('client_id', config.clientID);
  if (session.idToken) {
    logoutURL.searchParams.set('id_token_hint', session.idToken);
  }

  return logoutURL.toString();
}

function loginReasonMessage(reason: string): string {
  switch (reason) {
    case 'session_expired':
      return 'Your session expired. Sign in again to continue.';
    case 'callback_error':
      return 'OIDC callback failed. Please retry sign-in.';
    case 'state_mismatch':
      return 'Secure login validation failed. Please retry sign-in.';
    default:
      return '';
  }
}

function buildTenantWorkspacePath(tenantID: string, workspaceID: string): string {
  return `/app/${encodeURIComponent(tenantID)}/${encodeURIComponent(workspaceID)}`;
}

function buildScopedPath(scope: ProductSession, suffix = ''): string {
  const base = buildTenantWorkspacePath(scope.tenantID, scope.workspaceID);
  return suffix ? `${base}/${suffix}` : base;
}

const MEMBER_ROLE_OPTIONS: WorkspaceMemberRole[] = ['owner', 'admin', 'analyst', 'viewer'];
const MEMBER_STATUS_OPTIONS: WorkspaceMemberStatus[] = ['invited', 'active', 'suspended', 'removed'];

function buildProductAuthContext(scope: ProductSession): RequestAuthContext {
  const session = readProductSession();
  return {
    tenantID: scope.tenantID,
    workspaceID: scope.workspaceID,
    bearerToken: session?.accessToken
  };
}

function normalizeMemberID(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
  return normalized || 'member';
}

function deriveMemberID(userID: string, email: string): string {
  const userToken = normalizeMemberID(userID);
  const emailToken = normalizeMemberID(email.split('@')[0] ?? '');
  const token = userToken || emailToken;
  return token ? `member-${token}`.slice(0, 72) : `member-${Date.now()}`;
}

function hasWorkspaceAdminAccess(scope: ProductSession, whoAmI: WhoAmIResponse | null): boolean {
  const fromSession = (readProductSession()?.roles ?? []).map((role) => role.toLowerCase());
  if (fromSession.includes('owner') || fromSession.includes('admin')) {
    return true;
  }
  if (fromSession.includes('viewer') || fromSession.includes('analyst')) {
    return false;
  }
  if (!whoAmI) {
    return false;
  }
  const activeRole =
    whoAmI.active_workspace?.member?.role ??
    whoAmI.workspaces.find((item) => item.workspace.workspace_id === scope.workspaceID)?.member?.role;
  if (!activeRole) {
    return false;
  }
  return activeRole === 'owner' || activeRole === 'admin';
}

function useScaffoldDataState(delayMS = 320) {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const timer = window.setTimeout(() => setLoading(false), delayMS);
    return () => window.clearTimeout(timer);
  }, [delayMS]);

  return loading;
}

function ProductErrorBoundary({ children }: { children: ReactNode }) {
  return <ProductErrorBoundaryInner>{children}</ProductErrorBoundaryInner>;
}

type ProductErrorBoundaryState = {
  hasError: boolean;
  message: string;
};

class ProductErrorBoundaryInner extends Component<
  { children: ReactNode },
  ProductErrorBoundaryState
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error: unknown): ProductErrorBoundaryState {
    return {
      hasError: true,
      message: error instanceof Error ? error.message : 'Unexpected app shell failure'
    };
  }

  componentDidCatch() {
    // Intentionally no-op: fallback UI already captures global shell failures.
  }

  render() {
    if (this.state.hasError) {
      return (
        <section className="idt-app-shell-screen" role="alert">
          <article className="idt-app-panel idt-app-panel-error">
            <p className="idt-app-kicker">App shell error</p>
            <h1>We hit a shell boundary error</h1>
            <p>{this.state.message}</p>
            <p>Refresh the page or return to the marketing site while we restore this workspace view.</p>
            <Link className="idt-btn idt-btn-primary" to="/">
              Back to homepage
            </Link>
          </article>
        </section>
      );
    }

    return this.props.children;
  }
}

function AppShellLoading({ message }: { message: string }) {
  return (
    <section className="idt-app-shell-screen" aria-live="polite">
      <article className="idt-app-panel">
        <p className="idt-app-kicker">Loading</p>
        <h1>{message}</h1>
        <p>Preparing route context and tenancy scope.</p>
      </article>
    </section>
  );
}

function AppShellEmptyState({ title, body }: { title: string; body: string }) {
  return (
    <article className="idt-app-empty-state">
      <h2>{title}</h2>
      <p>{body}</p>
    </article>
  );
}

export function RequireProductAuth({ children }: { children: ReactNode }) {
  const location = useLocation();
  const [ready, setReady] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [reason, setReason] = useState('');

  useEffect(() => {
    let mounted = true;

    const run = async () => {
      const existing = readProductSession();
      if (!existing) {
        if (!mounted) {
          return;
        }
        setAuthenticated(false);
        setReady(true);
        return;
      }

      try {
        const activeSession = await ensureActiveSession(existing);
        if (!mounted) {
          return;
        }

        if (!activeSession) {
          clearProductSession();
          setReason('session_expired');
          setAuthenticated(false);
          setReady(true);
          return;
        }

        if (JSON.stringify(activeSession) !== JSON.stringify(existing)) {
          saveProductSession(activeSession);
        }

        setAuthenticated(true);
        setReady(true);
      } catch {
        if (!mounted) {
          return;
        }
        clearProductSession();
        setReason('session_expired');
        setAuthenticated(false);
        setReady(true);
      }
    };

    void run();

    return () => {
      mounted = false;
    };
  }, [location.pathname, location.search]);

  if (!ready) {
    return <AppShellLoading message="Validating session" />;
  }

  if (!authenticated) {
    const next = `${location.pathname}${location.search}`;
    const redirect = `/app/login?next=${encodeURIComponent(next)}${reason ? `&reason=${encodeURIComponent(reason)}` : ''}`;
    return <Navigate to={redirect} replace />;
  }

  return <>{children}</>;
}

export function ProductLoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const query = new URLSearchParams(location.search);
  const nextPath = normalizeValue(query.get('next') ?? '');
  const existing = useMemo(() => readProductSession(), []);
  const oidcEnabled = isOIDCEnabled();

  const [tenantID, setTenantID] = useState(existing?.tenantID ?? 'default');
  const [workspaceID, setWorkspaceID] = useState(existing?.workspaceID ?? 'default');
  const [projectID, setProjectID] = useState(existing?.projectID ?? '');
  const [oidcError, setOIDCError] = useState('');
  const [oidcLoading, setOIDCLoading] = useState(false);

  const reason = normalizeValue(query.get('reason') ?? '');
  const signedOut = normalizeValue(query.get('signed_out') ?? '') === '1';

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const normalizedTenantID = normalizeValue(tenantID);
    const normalizedWorkspaceID = normalizeValue(workspaceID);
    if (!normalizedTenantID || !normalizedWorkspaceID) {
      return;
    }

    const session: ProductSession = {
      tenantID: normalizedTenantID,
      workspaceID: normalizedWorkspaceID,
      projectID: normalizeValue(projectID) || undefined,
      authMode: 'manual'
    };
    saveProductSession(session);

    if (nextPath.startsWith('/app/')) {
      navigate(nextPath, { replace: true });
      return;
    }

    navigate(buildScopedPath(session), { replace: true });
  };

  const handleOIDCSignIn = async () => {
    setOIDCError('');
    setOIDCLoading(true);
    try {
      await beginOIDCLogin(nextPath || '/app');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to start OIDC sign-in';
      setOIDCError(message);
      setOIDCLoading(false);
    }
  };

  return (
    <section className="idt-app-shell-screen">
      <article className="idt-app-panel">
        <p className="idt-app-kicker">Product access</p>
        <h1>Sign in to the Identrail app shell</h1>
        <p>Authenticate and restore tenant/workspace session scope before entering the app route boundary.</p>

        {signedOut ? <p role="status">Signed out successfully.</p> : null}
        {reason ? <p role="status">{loginReasonMessage(reason)}</p> : null}

        {oidcEnabled ? (
          <div className="idt-app-auth-card">
            <button
              className="idt-btn idt-btn-primary"
              type="button"
              onClick={() => {
                void handleOIDCSignIn();
              }}
              disabled={oidcLoading}
            >
              {oidcLoading ? 'Redirecting to Keycloak...' : 'Continue with Keycloak'}
            </button>
            <p>Single sign-on uses authorization code + PKCE with automatic refresh and clean logout.</p>
            {oidcError ? <p role="alert">{oidcError}</p> : null}
          </div>
        ) : null}

        <form className="idt-app-form" onSubmit={handleSubmit}>
          <label>
            Tenant ID
            <input value={tenantID} onChange={(event) => setTenantID(event.target.value)} required />
          </label>
          <label>
            Workspace ID
            <input value={workspaceID} onChange={(event) => setWorkspaceID(event.target.value)} required />
          </label>
          <label>
            Project ID (optional)
            <input value={projectID} onChange={(event) => setProjectID(event.target.value)} />
          </label>
          <button className="idt-btn idt-btn-ghost" type="submit">
            Continue to app
          </button>
        </form>
      </article>
    </section>
  );
}

export function ProductOIDCCallbackPage() {
  const navigate = useNavigate();

  useEffect(() => {
    let mounted = true;

    const run = async () => {
      try {
        const result = await completeOIDCCallback(window.location.search);
        if (!mounted) {
          return;
        }
        saveProductSession(result.session);
        navigate(result.nextPath, { replace: true });
      } catch (error) {
        if (!mounted) {
          return;
        }
        clearProductSession();
        const message = error instanceof Error ? error.message.toLowerCase() : '';
        const reason = message.includes('state') ? 'state_mismatch' : 'callback_error';
        navigate(`/app/login?reason=${encodeURIComponent(reason)}`, { replace: true });
      }
    };

    void run();

    return () => {
      mounted = false;
    };
  }, [navigate]);

  return <AppShellLoading message="Completing sign-in" />;
}

export function ProductLogoutPage() {
  const navigate = useNavigate();

  useEffect(() => {
    let mounted = true;

    const run = async () => {
      const session = readProductSession();
      clearProductSession();

      if (session && isOIDCSession(session)) {
        try {
          const logoutURL = await resolveOIDCLogoutURL(session);
          if (logoutURL) {
            window.location.assign(logoutURL);
            return;
          }
        } catch {
          // Fall through to local login redirect.
        }
      }

      if (mounted) {
        navigate('/app/login?signed_out=1', { replace: true });
      }
    };

    void run();

    return () => {
      mounted = false;
    };
  }, [navigate]);

  return <AppShellLoading message="Signing out" />;
}

export function ProductAppIndexRedirect() {
  const session = readProductSession();
  if (!session) {
    return <Navigate to="/app/login" replace />;
  }
  return <Navigate to={buildScopedPath(session)} replace />;
}

function resolveScopeFromParams(params: ScopeRouteParams): ProductSession | null {
  const tenantID = normalizeValue(params.tenantID ?? '');
  const workspaceID = normalizeValue(params.workspaceID ?? '');
  const projectID = normalizeValue(params.projectID ?? '') || undefined;
  if (!tenantID || !workspaceID) {
    return null;
  }
  return { tenantID, workspaceID, projectID };
}

export function ProductShellLayout() {
  const params = useParams<ScopeRouteParams>();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);

  useEffect(() => {
    if (!scope) {
      return;
    }
    const current = readProductSession();
    if (!current) {
      return;
    }
    saveProductSession({
      ...current,
      tenantID: scope.tenantID,
      workspaceID: scope.workspaceID,
      projectID: scope.projectID ?? current.projectID
    });
  }, [scope]);

  useEffect(() => {
    let refreshInFlight = false;

    const timer = window.setInterval(() => {
      if (refreshInFlight) {
        return;
      }

      const current = readProductSession();
      if (!current || !isOIDCSession(current) || !needsSessionRefresh(current)) {
        return;
      }

      refreshInFlight = true;
      void refreshOIDCSession(current)
        .then((updated) => {
          if (!updated) {
            clearProductSession();
            navigate('/app/login?reason=session_expired', { replace: true });
            return;
          }
          saveProductSession(updated);
        })
        .catch(() => {
          clearProductSession();
          navigate('/app/login?reason=session_expired', { replace: true });
        })
        .finally(() => {
          refreshInFlight = false;
        });
    }, 30 * 1000);

    return () => {
      window.clearInterval(timer);
    };
  }, [navigate]);

  if (!scope) {
    return <AppShellLoading message="Resolving workspace scope" />;
  }

  const basePath = buildScopedPath(scope);

  return (
    <ProductErrorBoundary>
      <div className="idt-app-shell" data-tenant={scope.tenantID} data-workspace={scope.workspaceID}>
        <header className="idt-app-shell-header">
          <div>
            <p className="idt-app-kicker">Authenticated app shell</p>
            <h1>Identrail Workspace</h1>
            <p>
              Tenant <strong>{scope.tenantID}</strong> · Workspace <strong>{scope.workspaceID}</strong>
              {scope.projectID ? (
                <>
                  {' '}
                  · Project <strong>{scope.projectID}</strong>
                </>
              ) : null}
            </p>
          </div>
          <div className="idt-app-shell-actions">
            <button
              type="button"
              className="idt-btn idt-btn-ghost"
              onClick={() => {
                navigate('/app/logout', { replace: true });
              }}
            >
              Sign out
            </button>
            <Link to="/" className="idt-btn idt-btn-dark">
              Marketing site
            </Link>
          </div>
        </header>

        <nav className="idt-app-shell-nav" aria-label="App sections">
          <NavLink to={basePath} end>
            Overview
          </NavLink>
          <NavLink to={`${basePath}/workspaces`}>Workspaces</NavLink>
          <NavLink to={`${basePath}/projects`}>Sources</NavLink>
          <NavLink to={`${basePath}/findings`}>Findings</NavLink>
          <NavLink to={`${basePath}/settings`}>Settings</NavLink>
        </nav>

        <main className="idt-app-shell-main">
          <Outlet />
        </main>
      </div>
    </ProductErrorBoundary>
  );
}

function ScopedShellPage({ title, description, actionLabel, actionTo }: ScopedShellPageProps) {
  const loading = useScaffoldDataState();

  if (loading) {
    return (
      <section className="idt-app-panel" aria-busy="true" aria-live="polite">
        <p className="idt-app-kicker">Loading</p>
        <h2>{title}</h2>
        <p>Fetching scoped data for this workspace route.</p>
      </section>
    );
  }

  return (
    <section className="idt-app-panel">
      <p className="idt-app-kicker">Scaffold</p>
      <h2>{title}</h2>
      <p>{description}</p>
      <AppShellEmptyState
        title="No data yet"
        body="This placeholder is intentionally empty until backend wiring and feature-specific views are connected."
      />
      {actionLabel && actionTo ? (
        <div className="idt-inline-actions">
          <Link className="idt-btn idt-btn-primary" to={actionTo}>
            {actionLabel}
          </Link>
        </div>
      ) : null}
    </section>
  );
}

export function ProductOverviewPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);

  return (
    <ScopedShellPage
      title="Overview"
      description={`Entry view for tenant ${scope?.tenantID ?? 'unknown'} and workspace ${scope?.workspaceID ?? 'unknown'}.`}
      actionLabel="Open findings"
      actionTo={`/app/${encodeURIComponent(scope?.tenantID ?? 'default')}/${encodeURIComponent(scope?.workspaceID ?? 'default')}/findings`}
    />
  );
}

type MemberDraftState = Record<
  string,
  {
    role: WorkspaceMemberRole;
    status: WorkspaceMemberStatus;
  }
>;

export function ProductWorkspacesPage() {
  const params = useParams<ScopeRouteParams>();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const [whoAmI, setWhoAmI] = useState<WhoAmIResponse | null>(null);
  const [members, setMembers] = useState<WorkspaceMemberRecord[]>([]);
  const [memberDrafts, setMemberDrafts] = useState<MemberDraftState>({});

  const [workspaceTarget, setWorkspaceTarget] = useState('');
  const [switching, setSwitching] = useState(false);

  const [memberSearch, setMemberSearch] = useState('');
  const [memberRoleFilter, setMemberRoleFilter] = useState<'all' | WorkspaceMemberRole>('all');
  const [memberStatusFilter, setMemberStatusFilter] = useState<'all' | WorkspaceMemberStatus>('all');

  const [inviting, setInviting] = useState(false);
  const [inviteInput, setInviteInput] = useState({
    userID: '',
    email: '',
    role: 'viewer' as WorkspaceMemberRole,
    status: 'invited' as WorkspaceMemberStatus
  });

  const [savingMemberID, setSavingMemberID] = useState('');
  const [removingMemberID, setRemovingMemberID] = useState('');

  const refreshMembers = async (targetScope: ProductSession) => {
    const auth = buildProductAuthContext(targetScope);
    const response = await apiClient.listWorkspaceMembers(targetScope.workspaceID, {}, auth);
    setMembers(response.items);
    setMemberDrafts(
      response.items.reduce<MemberDraftState>((acc, member) => {
        acc[member.member_id] = { role: member.role, status: member.status };
        return acc;
      }, {})
    );
  };

  useEffect(() => {
    if (!scope) {
      setLoading(false);
      setError('Workspace route context is missing.');
      return;
    }

    let mounted = true;
    const run = async () => {
      setLoading(true);
      setError('');
      setSuccessMessage('');
      try {
        const auth = buildProductAuthContext(scope);
        const snapshot = await apiClient.getWhoAmI(auth);
        if (!mounted) {
          return;
        }
        setWhoAmI(snapshot);
        setWorkspaceTarget(snapshot.scope.workspace_id || scope.workspaceID);
        await refreshMembers(scope);
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        const message = requestError instanceof Error ? requestError.message : 'Failed to load workspace administration data.';
        setError(message);
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };
    void run();
    return () => {
      mounted = false;
    };
  }, [scope?.tenantID, scope?.workspaceID]);

  if (!scope) {
    return <AppShellLoading message="Resolving workspace scope" />;
  }

  const canAdmin = hasWorkspaceAdminAccess(scope, whoAmI);
  const roleCounts = members.reduce<Record<WorkspaceMemberRole, number>>(
    (acc, member) => {
      acc[member.role] += 1;
      return acc;
    },
    { owner: 0, admin: 0, analyst: 0, viewer: 0 }
  );

  const activeCount = members.filter((member) => member.status === 'active').length;
  const invitedCount = members.filter((member) => member.status === 'invited').length;
  const filteredMembers = members.filter((member) => {
    const search = normalizeValue(memberSearch).toLowerCase();
    const matchesSearch =
      search.length === 0 ||
      member.user_id.toLowerCase().includes(search) ||
      (member.email ?? '').toLowerCase().includes(search) ||
      member.member_id.toLowerCase().includes(search);
    const matchesRole = memberRoleFilter === 'all' || member.role === memberRoleFilter;
    const matchesStatus = memberStatusFilter === 'all' || member.status === memberStatusFilter;
    return matchesSearch && matchesRole && matchesStatus;
  });

  const handleSwitchWorkspace = async () => {
    if (!workspaceTarget || workspaceTarget === scope.workspaceID) {
      return;
    }
    setSwitching(true);
    setError('');
    setSuccessMessage('');
    try {
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.resolveActiveWorkspace(workspaceTarget, auth);
      const switchedScope: ProductSession = {
        ...scope,
        tenantID: response.scope.tenant_id,
        workspaceID: response.scope.workspace_id
      };
      const current = readProductSession();
      if (current) {
        saveProductSession({
          ...current,
          tenantID: switchedScope.tenantID,
          workspaceID: switchedScope.workspaceID
        });
      }
      navigate(buildScopedPath(switchedScope, 'workspaces'), { replace: true });
    } catch (switchError) {
      const message = switchError instanceof Error ? switchError.message : 'Failed to switch workspace.';
      setError(message);
    } finally {
      setSwitching(false);
    }
  };

  const handleInviteMember = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canAdmin) {
      return;
    }
    setInviting(true);
    setError('');
    setSuccessMessage('');
    try {
      const userID = normalizeValue(inviteInput.userID);
      const email = normalizeValue(inviteInput.email);
      if (!userID) {
        throw new Error('User ID is required.');
      }
      const auth = buildProductAuthContext(scope);
      await apiClient.upsertWorkspaceMember(
        scope.workspaceID,
        {
          member_id: deriveMemberID(userID, email),
          user_id: userID,
          email: email || undefined,
          role: inviteInput.role,
          status: inviteInput.status
        },
        auth
      );
      await refreshMembers(scope);
      setInviteInput({
        userID: '',
        email: '',
        role: 'viewer',
        status: 'invited'
      });
      setSuccessMessage('Member invitation saved.');
    } catch (inviteError) {
      const message = inviteError instanceof Error ? inviteError.message : 'Failed to invite member.';
      setError(message);
    } finally {
      setInviting(false);
    }
  };

  const handleSaveMember = async (member: WorkspaceMemberRecord) => {
    if (!canAdmin) {
      return;
    }
    const draft = memberDrafts[member.member_id];
    if (!draft) {
      return;
    }
    setSavingMemberID(member.member_id);
    setError('');
    setSuccessMessage('');
    try {
      const auth = buildProductAuthContext(scope);
      await apiClient.upsertWorkspaceMember(
        scope.workspaceID,
        {
          member_id: member.member_id,
          user_id: member.user_id,
          email: member.email,
          role: draft.role,
          status: draft.status
        },
        auth
      );
      await refreshMembers(scope);
      setSuccessMessage(`Updated ${member.user_id}.`);
    } catch (saveError) {
      const message = saveError instanceof Error ? saveError.message : 'Failed to update member.';
      setError(message);
    } finally {
      setSavingMemberID('');
    }
  };

  const handleRemoveMember = async (member: WorkspaceMemberRecord) => {
    if (!canAdmin) {
      return;
    }
    const shouldRemove = window.confirm(`Remove ${member.user_id} from workspace ${scope.workspaceID}?`);
    if (!shouldRemove) {
      return;
    }
    setRemovingMemberID(member.member_id);
    setError('');
    setSuccessMessage('');
    try {
      const auth = buildProductAuthContext(scope);
      await apiClient.deleteWorkspaceMember(scope.workspaceID, member.member_id, auth);
      await refreshMembers(scope);
      setSuccessMessage(`Removed ${member.user_id} from workspace.`);
    } catch (removeError) {
      const message = removeError instanceof Error ? removeError.message : 'Failed to remove member.';
      setError(message);
    } finally {
      setRemovingMemberID('');
    }
  };

  if (loading) {
    return <AppShellLoading message="Loading workspace administration" />;
  }

  const availableWorkspaces = whoAmI?.workspaces ?? [];

  return (
    <section className="idt-app-panel idt-workspace-admin">
      <p className="idt-app-kicker">Workspace administration</p>
      <h2>Members and roles</h2>
      <p>Invite members, update roles instantly, and switch active workspace scope without leaving the app shell.</p>

      {error ? (
        <p role="alert" className="idt-app-alert idt-app-alert-error">
          {error}
        </p>
      ) : null}
      {successMessage ? (
        <p role="status" className="idt-app-alert idt-app-alert-success">
          {successMessage}
        </p>
      ) : null}
      {!canAdmin ? (
        <p className="idt-app-alert">
          You currently have read-only tenancy access. Ask a workspace owner/admin to grant elevated role access.
        </p>
      ) : null}

      <div className="idt-workspace-stats" aria-label="workspace membership summary">
        <article>
          <h3>{members.length}</h3>
          <p>Total members</p>
        </article>
        <article>
          <h3>{activeCount}</h3>
          <p>Active</p>
        </article>
        <article>
          <h3>{invitedCount}</h3>
          <p>Invited</p>
        </article>
        <article>
          <h3>{roleCounts.owner + roleCounts.admin}</h3>
          <p>Privileged roles</p>
        </article>
      </div>

      <div className="idt-workspace-admin-grid">
        <article className="idt-app-empty-state">
          <h3>Switch active workspace</h3>
          <p>Change context to another workspace you can access.</p>
          <div className="idt-workspace-switcher">
            <label htmlFor="workspace-switch-select">Workspace</label>
            <select
              id="workspace-switch-select"
              value={workspaceTarget}
              onChange={(event) => setWorkspaceTarget(event.target.value)}
            >
              {[...availableWorkspaces]
                .sort((a, b) => a.workspace.display_name.localeCompare(b.workspace.display_name))
                .map((item) => (
                  <option key={item.workspace.workspace_id} value={item.workspace.workspace_id}>
                    {item.workspace.display_name} ({item.workspace.workspace_id})
                  </option>
                ))}
            </select>
            <button
              type="button"
              className="idt-btn idt-btn-ghost"
              onClick={() => {
                void handleSwitchWorkspace();
              }}
              disabled={switching || workspaceTarget === scope.workspaceID}
            >
              {switching ? 'Switching...' : 'Switch workspace'}
            </button>
          </div>
        </article>

        <article className="idt-app-empty-state">
          <h3>Invite member</h3>
          <form className="idt-app-form" onSubmit={handleInviteMember}>
            <label>
              User ID
              <input
                value={inviteInput.userID}
                onChange={(event) => setInviteInput((current) => ({ ...current, userID: event.target.value }))}
                placeholder="engineer@example.com"
                disabled={!canAdmin || inviting}
                required
              />
            </label>
            <label>
              Email (optional)
              <input
                type="email"
                value={inviteInput.email}
                onChange={(event) => setInviteInput((current) => ({ ...current, email: event.target.value }))}
                placeholder="engineer@example.com"
                disabled={!canAdmin || inviting}
              />
            </label>
            <div className="idt-workspace-inline-fields">
              <label>
                Role
                <select
                  value={inviteInput.role}
                  onChange={(event) =>
                    setInviteInput((current) => ({ ...current, role: event.target.value as WorkspaceMemberRole }))
                  }
                  disabled={!canAdmin || inviting}
                >
                  {MEMBER_ROLE_OPTIONS.map((role) => (
                    <option key={role} value={role}>
                      {role}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Status
                <select
                  value={inviteInput.status}
                  onChange={(event) =>
                    setInviteInput((current) => ({ ...current, status: event.target.value as WorkspaceMemberStatus }))
                  }
                  disabled={!canAdmin || inviting}
                >
                  {MEMBER_STATUS_OPTIONS.map((status) => (
                    <option key={status} value={status}>
                      {status}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <button className="idt-btn idt-btn-primary" type="submit" disabled={!canAdmin || inviting}>
              {inviting ? 'Saving...' : 'Invite member'}
            </button>
          </form>
        </article>
      </div>

      <div className="idt-workspace-member-toolbar">
        <label>
          Search
          <input
            value={memberSearch}
            onChange={(event) => setMemberSearch(event.target.value)}
            placeholder="user id, email, or member id"
          />
        </label>
        <label>
          Role
          <select
            value={memberRoleFilter}
            onChange={(event) => setMemberRoleFilter(event.target.value as 'all' | WorkspaceMemberRole)}
          >
            <option value="all">all</option>
            {MEMBER_ROLE_OPTIONS.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
        </label>
        <label>
          Status
          <select
            value={memberStatusFilter}
            onChange={(event) => setMemberStatusFilter(event.target.value as 'all' | WorkspaceMemberStatus)}
          >
            <option value="all">all</option>
            {MEMBER_STATUS_OPTIONS.map((status) => (
              <option key={status} value={status}>
                {status}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="idt-workspace-table-wrap">
        <table className="idt-workspace-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Member ID</th>
              <th>Role</th>
              <th>Status</th>
              <th>Last updated</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredMembers.map((member) => {
              const draft = memberDrafts[member.member_id] ?? { role: member.role, status: member.status };
              const dirty = draft.role !== member.role || draft.status !== member.status;
              return (
                <tr key={member.member_id}>
                  <td>
                    <strong>{member.user_id}</strong>
                    {member.email ? <span>{member.email}</span> : null}
                  </td>
                  <td>{member.member_id}</td>
                  <td>
                    <select
                      value={draft.role}
                      onChange={(event) =>
                        setMemberDrafts((current) => ({
                          ...current,
                          [member.member_id]: {
                            role: event.target.value as WorkspaceMemberRole,
                            status: current[member.member_id]?.status ?? member.status
                          }
                        }))
                      }
                      disabled={!canAdmin}
                    >
                      {MEMBER_ROLE_OPTIONS.map((role) => (
                        <option key={role} value={role}>
                          {role}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select
                      value={draft.status}
                      onChange={(event) =>
                        setMemberDrafts((current) => ({
                          ...current,
                          [member.member_id]: {
                            role: current[member.member_id]?.role ?? member.role,
                            status: event.target.value as WorkspaceMemberStatus
                          }
                        }))
                      }
                      disabled={!canAdmin}
                    >
                      {MEMBER_STATUS_OPTIONS.map((status) => (
                        <option key={status} value={status}>
                          {status}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>{new Date(member.updated_at).toLocaleString()}</td>
                  <td>
                    <div className="idt-workspace-actions">
                      <button
                        type="button"
                        className="idt-btn idt-btn-ghost"
                        onClick={() => {
                          void handleSaveMember(member);
                        }}
                        disabled={!canAdmin || !dirty || savingMemberID === member.member_id}
                      >
                        {savingMemberID === member.member_id ? 'Saving...' : 'Save'}
                      </button>
                      <button
                        type="button"
                        className="idt-btn idt-btn-dark"
                        onClick={() => {
                          void handleRemoveMember(member);
                        }}
                        disabled={!canAdmin || removingMemberID === member.member_id}
                      >
                        {removingMemberID === member.member_id ? 'Removing...' : 'Remove'}
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {filteredMembers.length === 0 ? (
        <AppShellEmptyState
          title="No members match this filter"
          body="Try adjusting role/status filters or invite a new workspace member."
        />
      ) : null}
    </section>
  );
}

function ProductSourceOnboardingWizard({ scope }: { scope: ProductSession }) {
  const [provider, setProvider] = useState<SourceProviderID>('github');
  const [step, setStep] = useState<SourceOnboardingStepID>('source');
  const [draft, setDraft] = useState<SourceOnboardingDraft>(DEFAULT_SOURCE_DRAFT);
  const [connections, setConnections] = useState<SourceConnectionRecord[]>(() => readSourceConnections(scope));
  const [validation, setValidation] = useState<SourceValidationState>({
    status: 'idle',
    message: '',
    checks: []
  });
  const validationRunRef = useRef(0);
  const validationTimerRef = useRef<number | null>(null);
  const connectLockedRef = useRef(false);

  useEffect(() => {
    setConnections(readSourceConnections(scope));
  }, [scope.tenantID, scope.workspaceID, scope.projectID]);

  useEffect(() => {
    return () => {
      if (validationTimerRef.current !== null) {
        window.clearTimeout(validationTimerRef.current);
      }
      validationRunRef.current += 1;
    };
  }, []);

  const providerConfig = SOURCE_PROVIDER_OPTIONS.find((option) => option.id === provider) ?? SOURCE_PROVIDER_OPTIONS[0];
  const currentStepIndex = SOURCE_ONBOARDING_STEPS.findIndex((item) => item.id === step);
  const completedSources = connections.filter((connection) => connection.status === 'connected').length;
  const progressClass = `idt-source-progress-${step}`;

  const updateDraft = (key: keyof SourceOnboardingDraft, value: string) => {
    validationRunRef.current += 1;
    connectLockedRef.current = false;
    setDraft((current) => ({ ...current, [key]: value }));
    if (validation.status !== 'idle') {
      setValidation({ status: 'idle', message: '', checks: [] });
    }
  };

  const handleProviderSelect = (nextProvider: SourceProviderID) => {
    const nextConfig = SOURCE_PROVIDER_OPTIONS.find((option) => option.id === nextProvider) ?? SOURCE_PROVIDER_OPTIONS[0];
    validationRunRef.current += 1;
    connectLockedRef.current = false;
    setProvider(nextProvider);
    setStep('setup');
    setValidation({ status: 'idle', message: '', checks: [] });
    setDraft((current) => ({
      ...current,
      displayName: normalizeValue(current.displayName) || `${nextConfig.name} production`
    }));
  };

  const handleValidate = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    validationRunRef.current += 1;
    connectLockedRef.current = false;
    const validationRunID = validationRunRef.current;
    const providerSnapshot = provider;
    const draftSnapshot = { ...draft };
    const providerNameSnapshot = providerConfig.name;
    if (validationTimerRef.current !== null) {
      window.clearTimeout(validationTimerRef.current);
    }
    setStep('validate');
    setValidation({
      status: 'running',
      message: `Running ${providerNameSnapshot} readiness checks...`,
      checks: []
    });

    validationTimerRef.current = window.setTimeout(() => {
      if (validationRunID !== validationRunRef.current) {
        return;
      }
      const checks = validateSourceDraft(providerSnapshot, draftSnapshot);
      const passed = checks.every((check) => check.passed);
      validationTimerRef.current = null;
      setValidation({
        status: passed ? 'passed' : 'failed',
        message: passed
          ? 'All read-only checks passed. This source can be connected.'
          : 'Validation found setup gaps. Fix the failed checks and retry.',
        checks
      });
    }, 250);
  };

  const handleConnect = () => {
    if (step === 'complete' || connectLockedRef.current) {
      return;
    }
    if (validation.status !== 'passed') {
      setValidation((current) => ({
        ...current,
        status: 'failed',
        message: 'Run a successful validation before connecting this source.'
      }));
      return;
    }
    connectLockedRef.current = true;

    const now = new Date().toISOString();
    const connection: SourceConnectionRecord = {
      id: `${provider}-${Date.now()}`,
      provider,
      displayName: normalizeValue(draft.displayName),
      owner: normalizeValue(draft.owner),
      environment: normalizeValue(draft.environment),
      status: 'connected',
      validatedAt: now,
      summary: createSourceSummary(provider, draft)
    };
    const nextConnections = [connection, ...connections];
    setConnections(nextConnections);
    saveSourceConnections(scope, nextConnections);
    setStep('complete');
    setValidation({ status: 'idle', message: '', checks: [] });
  };

  const handleRetry = () => {
    validationRunRef.current += 1;
    connectLockedRef.current = false;
    setStep('setup');
    setValidation({ status: 'idle', message: '', checks: [] });
  };

  const handleStartAnother = () => {
    validationRunRef.current += 1;
    connectLockedRef.current = false;
    setStep('source');
    setDraft(DEFAULT_SOURCE_DRAFT);
    setValidation({ status: 'idle', message: '', checks: [] });
  };

  return (
    <section className="idt-app-panel idt-source-onboarding" aria-labelledby="source-onboarding-title">
      <div className="idt-source-header">
        <div>
          <p className="idt-app-kicker">Source onboarding</p>
          <h2 id="source-onboarding-title">Connect a source</h2>
          <p>
            Guide the first read-only connector setup for GitHub, AWS, or Kubernetes with validation before any scan is
            queued.
          </p>
        </div>
        <div className="idt-source-progress-summary" aria-label="source onboarding summary">
          <strong>{completedSources}</strong>
          <span>connected sources</span>
        </div>
      </div>

      <div className="idt-source-progress" aria-label="source onboarding progress">
        <div className={`idt-source-progress-bar ${progressClass}`}>
          <span />
        </div>
        <ol>
          {SOURCE_ONBOARDING_STEPS.map((item, index) => (
            <li key={item.id} className={index <= currentStepIndex ? 'is-active' : ''} aria-current={item.id === step ? 'step' : undefined}>
              {item.label}
            </li>
          ))}
        </ol>
      </div>

      <div className="idt-source-layout">
        <div className="idt-source-provider-list" role="list" aria-label="available source providers">
          {SOURCE_PROVIDER_OPTIONS.map((option) => (
            <button
              key={option.id}
              type="button"
              className={option.id === provider ? 'is-selected' : ''}
              onClick={() => handleProviderSelect(option.id)}
              aria-pressed={option.id === provider}
            >
              <strong>{option.name}</strong>
              <span>{option.description}</span>
            </button>
          ))}
        </div>

        <form className="idt-source-form" onSubmit={handleValidate}>
          <div className="idt-source-form-heading">
            <div>
              <h3>{providerConfig.setupLabel}</h3>
              <p>{providerConfig.validationFocus}</p>
            </div>
            <span>{providerConfig.name}</span>
          </div>

          <div className="idt-source-field-grid">
            <label>
              Connection name
              <input
                value={draft.displayName}
                onChange={(event) => updateDraft('displayName', event.target.value)}
                placeholder={`${providerConfig.name} production`}
                required
              />
            </label>
            <label>
              Owner
              <input
                value={draft.owner}
                onChange={(event) => updateDraft('owner', event.target.value)}
                placeholder="platform-security"
                required
              />
            </label>
            <label>
              Environment
              <select value={draft.environment} onChange={(event) => updateDraft('environment', event.target.value)}>
                <option value="production">production</option>
                <option value="staging">staging</option>
                <option value="development">development</option>
                <option value="sandbox">sandbox</option>
              </select>
            </label>
          </div>

          {provider === 'github' ? (
            <div className="idt-source-field-grid">
              <label>
                GitHub organization
                <input
                  value={draft.githubOrg}
                  onChange={(event) => updateDraft('githubOrg', event.target.value)}
                  placeholder="identrail"
                  required
                />
              </label>
              <label>
                GitHub App installation ID
                <input
                  inputMode="numeric"
                  value={draft.githubInstallationID}
                  onChange={(event) => updateDraft('githubInstallationID', event.target.value)}
                  placeholder="12345678"
                  required
                />
              </label>
            </div>
          ) : null}

          {provider === 'aws' ? (
            <div className="idt-source-field-grid">
              <label>
                AWS account ID
                <input
                  inputMode="numeric"
                  value={draft.awsAccountID}
                  onChange={(event) => updateDraft('awsAccountID', event.target.value)}
                  placeholder="123456789012"
                  required
                />
              </label>
              <label>
                Read-only role ARN
                <input
                  value={draft.awsRoleARN}
                  onChange={(event) => updateDraft('awsRoleARN', event.target.value)}
                  placeholder="arn:aws:iam::123456789012:role/identrail-readonly"
                  required
                />
              </label>
              <label>
                External ID
                <input
                  value={draft.awsExternalID}
                  onChange={(event) => updateDraft('awsExternalID', event.target.value)}
                  placeholder="workspace-generated-id"
                  required
                />
              </label>
            </div>
          ) : null}

          {provider === 'kubernetes' ? (
            <div className="idt-source-field-grid">
              <label>
                Cluster name
                <input
                  value={draft.clusterName}
                  onChange={(event) => updateDraft('clusterName', event.target.value)}
                  placeholder="prod-us-east-1"
                  required
                />
              </label>
              <label>
                API server URL
                <input
                  type="url"
                  value={draft.apiServerURL}
                  onChange={(event) => updateDraft('apiServerURL', event.target.value)}
                  placeholder="https://cluster.example.com"
                  required
                />
              </label>
              <label>
                Namespace scope
                <input
                  value={draft.namespace}
                  onChange={(event) => updateDraft('namespace', event.target.value)}
                  placeholder="default"
                  required
                />
              </label>
            </div>
          ) : null}

          <div className="idt-source-guardrails" aria-label="onboarding guardrails">
            <span>Read-only scan</span>
            <span>No secret persistence</span>
            <span>Retryable validation</span>
          </div>

          {validation.message ? (
            <p
              role={validation.status === 'failed' ? 'alert' : 'status'}
              className={`idt-app-alert ${validation.status === 'failed' ? 'idt-app-alert-error' : 'idt-app-alert-success'}`}
            >
              {validation.message}
            </p>
          ) : null}

          {validation.checks.length > 0 ? (
            <ul className="idt-source-checks" aria-label="validation checks">
              {validation.checks.map((check) => (
                <li key={check.label} className={check.passed ? 'is-passed' : 'is-failed'}>
                  <strong>{check.label}</strong>
                  <span>{check.detail}</span>
                </li>
              ))}
            </ul>
          ) : null}

          <div className="idt-source-actions">
            <button className="idt-btn idt-btn-primary" type="submit" disabled={validation.status === 'running'}>
              {validation.status === 'running' ? 'Validating...' : 'Validate setup'}
            </button>
            <button
              className="idt-btn idt-btn-dark"
              type="button"
              onClick={handleConnect}
              disabled={validation.status !== 'passed' || step === 'complete'}
            >
              Connect source
            </button>
            {validation.status === 'failed' ? (
              <button className="idt-btn idt-btn-ghost" type="button" onClick={handleRetry}>
                Retry validation
              </button>
            ) : null}
          </div>
        </form>
      </div>

      {step === 'complete' ? (
        <div className="idt-app-alert idt-app-alert-success" role="status">
          {providerConfig.name} connected. The first read-only scan is ready to be scheduled from this workspace.
        </div>
      ) : null}

      <div className="idt-source-connected">
        <div className="idt-source-connected-heading">
          <h3>Connected sources</h3>
          <button className="idt-btn idt-btn-ghost" type="button" onClick={handleStartAnother}>
            Add another source
          </button>
        </div>
        {connections.length === 0 ? (
          <AppShellEmptyState title="No sources connected yet" body="Choose a provider, validate the setup, then connect the first source." />
        ) : (
          <ul className="idt-source-connection-list">
            {connections.map((connection) => {
              const config =
                SOURCE_PROVIDER_OPTIONS.find((option) => option.id === connection.provider) ?? SOURCE_PROVIDER_OPTIONS[0];
              return (
                <li key={connection.id}>
                  <div>
                    <strong>{connection.displayName}</strong>
                    <span>
                      {config.name} - {connection.summary}
                    </span>
                  </div>
                  <div>
                    <span>{connection.owner}</span>
                    <span>{connection.environment}</span>
                    <span>{new Date(connection.validatedAt).toLocaleString()}</span>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}

export function ProductProjectsPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);
  if (!scope) {
    return <AppShellLoading message="Resolving workspace scope" />;
  }
  return (
    <ProductSourceOnboardingWizard scope={scope} />
  );
}

export function ProductProjectDetailPage() {
  const params = useParams<ScopeRouteParams>();
  return (
    <ScopedShellPage
      title="Project detail"
      description={`Project ${params.projectID ?? 'unknown'} placeholder with room for run status, controls, and ownership context.`}
    />
  );
}

export function ProductFindingsPage() {
  return <ScopedShellPage title="Findings" description="Finding triage queue placeholder for scoped findings, filters, and ownership assignment." />;
}

export function ProductSettingsPage() {
  return <ScopedShellPage title="Settings" description="Tenant/workspace app settings, auth provider mapping, and shell preferences will render here." />;
}
