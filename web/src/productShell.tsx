import { Component, FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  apiClient,
  type AWSConnectionStatus,
  type GitHubConnectionStartResponse,
  type GitHubConnectionStatus,
  type KubernetesConnectionStatus,
  type ProjectRecord,
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

type SourceProvider = 'github' | 'aws' | 'kubernetes';

type SourceConnectionMap = {
  github?: GitHubConnectionStatus;
  aws?: AWSConnectionStatus;
  kubernetes?: KubernetesConnectionStatus;
};

type SourceProfile = {
  provider: SourceProvider;
  name: string;
  eyebrow: string;
  summary: string;
  primarySignal: string;
  requiredAccess: string;
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

type ProductSessionTokens = {
  accessToken?: string;
  refreshToken?: string;
  idToken?: string;
};

let inMemoryTokens: ProductSessionTokens = {};
const OIDC_REFRESH_SKEW_MS = 90 * 1000;
const OIDC_MAX_PENDING_LOGIN_AGE_MS = 10 * 60 * 1000;

function normalizeValue(value: string): string {
  return value.trim();
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

function isManualSessionEntryEnabled(): boolean {
  const enabled = normalizeValue(import.meta.env.VITE_ALLOW_MANUAL_PRODUCT_SESSION ?? '').toLowerCase();
  return enabled === 'true';
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

  if (!session.accessToken) {
    return session.refreshToken ? refreshOIDCSession(session) : null;
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
    case 'manual_auth_disabled':
      return 'Manual workspace entry is disabled for this deployment. Sign in with single sign-on to continue.';
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

function buildProjectsPath(scope: ProductSession): string {
  return buildScopedPath(scope, 'projects');
}

function buildProjectPath(scope: ProductSession, projectID: string): string {
  return `${buildProjectsPath(scope)}/${encodeURIComponent(projectID)}`;
}

const MEMBER_ROLE_OPTIONS: WorkspaceMemberRole[] = ['owner', 'admin', 'analyst', 'viewer'];
const MEMBER_STATUS_OPTIONS: WorkspaceMemberStatus[] = ['invited', 'active', 'suspended', 'removed'];
const SOURCE_PROFILES: Record<SourceProvider, SourceProfile> = {
  github: {
    provider: 'github',
    name: 'GitHub',
    eyebrow: 'Code and workflow identity',
    summary: 'Connect a GitHub App installation and select repositories that should feed exposure telemetry.',
    primarySignal: 'Repositories, workflow identity, webhook scan triggers',
    requiredAccess: 'GitHub App installation with selected repository access'
  },
  aws: {
    provider: 'aws',
    name: 'AWS',
    eyebrow: 'Cloud IAM identity',
    summary: 'Validate a read-only IAM role before Identrail records the account connector.',
    primarySignal: 'Roles, trust policies, account identity, IAM read checks',
    requiredAccess: 'Assumable read-only IAM role ARN'
  },
  kubernetes: {
    provider: 'kubernetes',
    name: 'Kubernetes',
    eyebrow: 'Cluster service identity',
    summary: 'Run a non-mutating preflight against the configured cluster context before activation.',
    primarySignal: 'Service accounts, RBAC bindings, pods, cluster metadata',
    requiredAccess: 'Read-only kubectl context available to the API runtime'
  }
};
const SOURCE_ORDER: SourceProvider[] = ['github', 'aws', 'kubernetes'];
const CONNECT_SOURCE_STEPS = ['Choose', 'Configure', 'Validate', 'Active'] as const;
const GITHUB_REPOSITORY_SPLIT_PATTERN = /[\n,]+/;
const AWS_ROLE_ARN_PATTERN = /^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/;

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

function normalizeProjectToken(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

function deriveProjectToken(value: string, fallback = 'project'): string {
  return normalizeProjectToken(value) || fallback;
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

function sourceConnection(connections: SourceConnectionMap, provider: SourceProvider) {
  return provider === 'github'
    ? connections.github
    : provider === 'aws'
      ? connections.aws
      : connections.kubernetes;
}

function connectionHealth(status?: GitHubConnectionStatus | AWSConnectionStatus | KubernetesConnectionStatus): string {
  if (!status) {
    return 'unknown';
  }
  if ('health_status' in status) {
    return status.health_status;
  }
  return status.connected ? 'healthy' : 'unknown';
}

function connectionLifecycle(status?: GitHubConnectionStatus | AWSConnectionStatus | KubernetesConnectionStatus): string {
  if (!status) {
    return 'Not checked';
  }
  if (status.connected) {
    return 'Active';
  }
  if ('status' in status) {
    return status.status.charAt(0).toUpperCase() + status.status.slice(1);
  }
  return 'Not connected';
}

function connectionTone(status?: GitHubConnectionStatus | AWSConnectionStatus | KubernetesConnectionStatus): 'success' | 'warning' | 'error' | 'neutral' {
  if (!status) {
    return 'neutral';
  }
  const health = connectionHealth(status);
  if (status.connected && (health === 'healthy' || health === 'unknown')) {
    return 'success';
  }
  if (health === 'error' || ('status' in status && status.status === 'degraded')) {
    return 'error';
  }
  if (health === 'warning') {
    return 'warning';
  }
  return 'neutral';
}

function formatConnectionTime(value?: string): string {
  if (!value) {
    return 'Never';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function parseGitHubRepositories(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(GITHUB_REPOSITORY_SPLIT_PATTERN)
    .map((entry) => normalizeValue(entry).toLowerCase())
    .filter((entry) => {
      if (!entry || !entry.includes('/') || seen.has(entry)) {
        return false;
      }
      seen.add(entry);
      return true;
    });
}

function newWebhookSecret(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    return `whsec_${randomString(32)}`;
  }
  return `whsec_${Date.now().toString(36)}`;
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

        const manualSessionAllowed = isManualSessionEntryEnabled() || !isOIDCEnabled();
        if (activeSession.authMode === 'manual' && !manualSessionAllowed) {
          clearProductSession();
          setReason('manual_auth_disabled');
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
    const preserveNextPath = reason !== 'manual_auth_disabled';
    const query = new URLSearchParams();
    if (preserveNextPath) {
      query.set('next', `${location.pathname}${location.search}`);
    }
    if (reason) {
      query.set('reason', reason);
    }
    const redirect = query.size > 0 ? `/app/login?${query.toString()}` : '/app/login';
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
  const manualEntryEnabled = isManualSessionEntryEnabled() || !oidcEnabled;

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

        {manualEntryEnabled ? (
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
        ) : (
          <p className="idt-app-alert">
            Manual workspace entry is disabled for this deployment. Use single sign-on to establish tenant and workspace access.
          </p>
        )}
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
          <NavLink to={`${basePath}/projects`}>Projects</NavLink>
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
      description={`Choose a project for tenant ${scope?.tenantID ?? 'unknown'} and workspace ${scope?.workspaceID ?? 'unknown'} before connecting source telemetry.`}
      actionLabel="Select project"
      actionTo={scope ? buildProjectsPath(scope) : undefined}
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

export function ProductProjectsPage() {
  const params = useParams<ScopeRouteParams>();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);

  const [projects, setProjects] = useState<ProjectRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [draftName, setDraftName] = useState('');
  const [draftProjectID, setDraftProjectID] = useState('');
  const [draftSlug, setDraftSlug] = useState('');
  const [draftDescription, setDraftDescription] = useState('');
  const [projectIDEdited, setProjectIDEdited] = useState(false);
  const [slugEdited, setSlugEdited] = useState(false);

  useEffect(() => {
    if (!scope) {
      setProjects([]);
      setLoading(false);
      return;
    }

    let active = true;

    const loadProjects = async () => {
      setLoading(true);
      setError('');
      setProjects([]);
      try {
        const auth = buildProductAuthContext(scope);
        const response = await apiClient.listProjects(
          scope.workspaceID,
          {
            limit: 50,
            sort_by: 'updated_at',
            sort_order: 'desc',
            include_archived: true
          },
          auth
        );
        if (!active) {
          return;
        }
        setProjects(response.items);
      } catch (loadError) {
        if (!active) {
          return;
        }
        setError(loadError instanceof Error ? loadError.message : 'Unable to load workspace projects.');
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    void loadProjects();

    return () => {
      active = false;
    };
  }, [scope?.tenantID, scope?.workspaceID]);

  const activeProjectCount = useMemo(
    () => projects.filter((project) => !normalizeValue(project.archived_at ?? '')).length,
    [projects]
  );
  const archivedProjectCount = projects.length - activeProjectCount;
  const latestProject = projects[0];

  if (!scope) {
    return <AppShellLoading message="Resolving workspace scope" />;
  }

  if (loading) {
    return <AppShellLoading message="Loading projects" />;
  }

  const handleNameChange = (value: string) => {
    setDraftName(value);
    const token = deriveProjectToken(value);
    if (!projectIDEdited) {
      setDraftProjectID(token);
    }
    if (!slugEdited) {
      setDraftSlug(token);
    }
  };

  const handleCreateProject = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const name = normalizeValue(draftName);
    const projectID = normalizeValue(draftProjectID) || deriveProjectToken(name);
    const slug = normalizeValue(draftSlug) || deriveProjectToken(name);
    const description = normalizeValue(draftDescription);

    if (!name) {
      setError('Project name is required.');
      return;
    }
    if (!projectID) {
      setError('Project ID is required.');
      return;
    }
    if (!slug) {
      setError('Project slug is required.');
      return;
    }

    setSaving(true);
    setError('');

    try {
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.upsertProject(
        scope.workspaceID,
        {
          project_id: projectID,
          name,
          slug,
          description: description || undefined
        },
        auth
      );
      setProjects((current) => {
        const remaining = current.filter((project) => project.project_id !== response.project.project_id);
        return [response.project, ...remaining];
      });
      setDraftName('');
      setDraftProjectID('');
      setDraftSlug('');
      setDraftDescription('');
      setProjectIDEdited(false);
      setSlugEdited(false);
      navigate(buildProjectPath(scope, response.project.project_id));
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Unable to save project.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="idt-app-panel idt-projects-page">
      <div className="idt-projects-header">
        <div>
          <p className="idt-app-kicker">Project registry</p>
          <h2>Choose a project before connecting source data</h2>
          <p>Projects set the workspace boundary for GitHub, AWS, and Kubernetes onboarding.</p>
        </div>
        <div className="idt-inline-actions">
          <Link className="idt-btn idt-btn-ghost" to={buildScopedPath(scope)}>
            Back to overview
          </Link>
        </div>
      </div>

      <div className="idt-projects-summary">
        <article>
          <span>{projects.length}</span>
          <p>Total projects</p>
        </article>
        <article>
          <span>{activeProjectCount}</span>
          <p>Active boundaries</p>
        </article>
        <article>
          <span>{latestProject ? formatConnectionTime(latestProject.updated_at) : 'No activity yet'}</span>
          <p>Latest update</p>
        </article>
      </div>

      {error ? <div className="idt-app-alert idt-app-alert-error">{error}</div> : null}

      <div className="idt-projects-grid">
        <article className="idt-projects-list">
          <div className="idt-projects-section-header">
            <div>
              <h3>Workspace projects</h3>
              <p>
                {archivedProjectCount > 0
                  ? `${activeProjectCount} active, ${archivedProjectCount} archived.`
                  : 'Select an existing project to continue source onboarding.'}
              </p>
            </div>
          </div>

          {projects.length === 0 ? (
            <AppShellEmptyState
              title="No projects yet"
              body="Create the first project for this workspace, then continue into source onboarding."
            />
          ) : (
            <div className="idt-project-card-list">
              {projects.map((project) => {
                const archived = Boolean(normalizeValue(project.archived_at ?? ''));
                return (
                  <article key={project.project_id} className="idt-project-card">
                    <div className="idt-project-card-header">
                      <div>
                        <h4>{project.name}</h4>
                        <p>{project.description || 'No description yet. Use this project to scope connector onboarding and scan ownership.'}</p>
                      </div>
                      <span
                        className={`idt-source-status-pill ${archived ? 'is-warning' : 'is-success'}`}
                      >
                        {archived ? 'Archived' : 'Active'}
                      </span>
                    </div>

                    <dl className="idt-project-card-meta">
                      <div>
                        <dt>Project ID</dt>
                        <dd>{project.project_id}</dd>
                      </div>
                      <div>
                        <dt>Slug</dt>
                        <dd>{project.slug}</dd>
                      </div>
                      <div>
                        <dt>Updated</dt>
                        <dd>{formatConnectionTime(project.updated_at)}</dd>
                      </div>
                    </dl>

                    <div className="idt-inline-actions">
                      <Link className="idt-btn idt-btn-primary" to={buildProjectPath(scope, project.project_id)}>
                        Manage sources
                      </Link>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </article>

        <article className="idt-project-composer">
          <div className="idt-projects-section-header">
            <div>
              <h3>Create project</h3>
              <p>Set the canonical project ID and route-safe slug once, then continue into connector setup.</p>
            </div>
          </div>

          <form className="idt-app-form" onSubmit={handleCreateProject}>
            <label>
              Project name
              <input
                value={draftName}
                onChange={(event) => handleNameChange(event.target.value)}
                placeholder="Production platform"
                required
              />
            </label>
            <div className="idt-project-inline-fields">
              <label>
                Project ID
                <input
                  value={draftProjectID}
                  onChange={(event) => {
                    setProjectIDEdited(true);
                    setDraftProjectID(normalizeProjectToken(event.target.value));
                  }}
                  placeholder="production-platform"
                  required
                />
              </label>
              <label>
                Slug
                <input
                  value={draftSlug}
                  onChange={(event) => {
                    setSlugEdited(true);
                    setDraftSlug(normalizeProjectToken(event.target.value));
                  }}
                  placeholder="production-platform"
                  required
                />
              </label>
            </div>
            <label>
              Description
              <textarea
                value={draftDescription}
                onChange={(event) => setDraftDescription(event.target.value)}
                placeholder="Identity boundary for the production control plane and its delivery repositories."
              />
            </label>
            <button className="idt-btn idt-btn-primary" type="submit" disabled={saving}>
              {saving ? 'Creating project...' : 'Create project and continue'}
            </button>
          </form>
        </article>
      </div>
    </section>
  );
}

export function ProductProjectDetailPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);
  const projectID = normalizeValue(params.projectID ?? '');
  const refreshSequenceRef = useRef(0);

  const [connections, setConnections] = useState<SourceConnectionMap>({});
  const [sourceErrors, setSourceErrors] = useState<Partial<Record<SourceProvider, string>>>({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [submitting, setSubmitting] = useState<SourceProvider | ''>('');
  const [selectedSource, setSelectedSource] = useState<SourceProvider>('github');
  const [successMessage, setSuccessMessage] = useState('');
  const [githubStart, setGitHubStart] = useState<GitHubConnectionStartResponse | null>(null);
  const [githubStartForm, setGitHubStartForm] = useState({
    appSlug: 'identrail',
    redirectURI: ''
  });
  const [githubComplete, setGitHubComplete] = useState({
    state: '',
    installationID: '',
    accountLogin: '',
    repositories: '',
    tokenReference: '',
    webhookSecret: '',
    webhookSecretReference: ''
  });
  const [awsForm, setAWSForm] = useState({
    roleARN: '',
    externalID: '',
    region: 'us-east-1',
    displayName: '',
    sessionName: 'identrail-connector-validation'
  });
  const [kubernetesForm, setKubernetesForm] = useState({
    displayName: '',
    context: ''
  });

  const nextRequestSequence = () => {
    const nextSequence = refreshSequenceRef.current + 1;
    refreshSequenceRef.current = nextSequence;
    return nextSequence;
  };

  const isStaleRequestSequence = (sequence: number) => refreshSequenceRef.current !== sequence;

  const refreshConnections = async (quiet = false) => {
    const refreshSequence = nextRequestSequence();

    if (!scope || !projectID) {
      setConnections({});
      setSourceErrors({});
      setLoading(false);
      setRefreshing(false);
      return;
    }

    if (quiet) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setSourceErrors({});
    const auth = buildProductAuthContext(scope);

    const results = await Promise.allSettled([
      apiClient.getGitHubProjectConnection(scope.workspaceID, projectID, auth),
      apiClient.getAWSProjectConnection(scope.workspaceID, projectID, auth),
      apiClient.getKubernetesProjectConnection(scope.workspaceID, projectID, auth)
    ]);

    if (isStaleRequestSequence(refreshSequence)) {
      return;
    }

    const nextConnections: SourceConnectionMap = {};
    const nextErrors: Partial<Record<SourceProvider, string>> = {};
    const providers: SourceProvider[] = ['github', 'aws', 'kubernetes'];

    results.forEach((result, index) => {
      const provider = providers[index];
      if (!provider) {
        return;
      }
      if (result.status === 'fulfilled') {
        if (provider === 'github') {
          nextConnections.github = result.value.connection as GitHubConnectionStatus;
        } else if (provider === 'aws') {
          nextConnections.aws = result.value.connection as AWSConnectionStatus;
        } else {
          nextConnections.kubernetes = result.value.connection as KubernetesConnectionStatus;
        }
        return;
      }
      nextErrors[provider] = result.reason instanceof Error ? result.reason.message : `Unable to load ${SOURCE_PROFILES[provider].name} status.`;
    });

    setConnections(nextConnections);
    setSourceErrors(nextErrors);
    setLoading(false);
    setRefreshing(false);
  };

  useEffect(() => {
    setConnections({});
    setSourceErrors({});
    setSubmitting('');
    setSuccessMessage('');
    setGitHubStart(null);
    void refreshConnections(false);

    return () => {
      refreshSequenceRef.current += 1;
    };
  }, [scope?.tenantID, scope?.workspaceID, projectID]);

  if (!scope || !projectID) {
    return <AppShellLoading message="Resolving project scope" />;
  }

  if (loading) {
    return <AppShellLoading message="Loading source connections" />;
  }

  const selectedStatus = sourceConnection(connections, selectedSource);
  const selectedProfile = SOURCE_PROFILES[selectedSource];
  const connectedCount = SOURCE_ORDER.filter((provider) => sourceConnection(connections, provider)?.connected).length;
  const activeStepIndex = selectedStatus?.connected ? 3 : submitting === selectedSource ? 2 : 1;

  const handleGitHubStart = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting('github');
    setSuccessMessage('');
    setSourceErrors((current) => ({ ...current, github: undefined }));
    const requestSequence = refreshSequenceRef.current;
    try {
      const auth = buildProductAuthContext(scope);
      const redirectURI =
        normalizeValue(githubStartForm.redirectURI) ||
        (typeof window !== 'undefined' ? `${window.location.origin}${buildProjectPath(scope, projectID)}` : undefined);
      const response = await apiClient.startGitHubProjectConnection(
        scope.workspaceID,
        projectID,
        {
          app_slug: normalizeValue(githubStartForm.appSlug) || undefined,
          redirect_uri: redirectURI
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setGitHubStart(response.connection);
      setGitHubComplete((current) => ({
        ...current,
        state: response.connection.state,
        webhookSecret: current.webhookSecret || newWebhookSecret(),
        webhookSecretReference:
          current.webhookSecretReference || `github-webhook:${projectID}:${response.connection.state.slice(0, 8)}`
      }));
      setSuccessMessage('GitHub installation link generated.');
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      const message = error instanceof Error ? error.message : 'Unable to start GitHub connection.';
      setSourceErrors((current) => ({ ...current, github: message }));
    } finally {
      if (!isStaleRequestSequence(requestSequence)) {
        setSubmitting('');
      }
    }
  };

  const handleGitHubComplete = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting('github');
    setSuccessMessage('');
    setSourceErrors((current) => ({ ...current, github: undefined }));
    const requestSequence = refreshSequenceRef.current;
    try {
      const state = normalizeValue(githubComplete.state || githubStart?.state || '');
      const installationID = Number.parseInt(githubComplete.installationID, 10);
      const repositories = parseGitHubRepositories(githubComplete.repositories);
      if (!state) {
        throw new Error('Generate a GitHub install state before saving the connection.');
      }
      if (!Number.isFinite(installationID) || installationID <= 0) {
        throw new Error('Enter a valid GitHub App installation ID.');
      }
      if (repositories.length === 0) {
        throw new Error('Add at least one repository in owner/name format.');
      }

      const tokenReference =
        normalizeValue(githubComplete.tokenReference) || `github-app-installation:${installationID}`;
      const webhookSecret = normalizeValue(githubComplete.webhookSecret) || newWebhookSecret();
      const webhookSecretReference =
        normalizeValue(githubComplete.webhookSecretReference) || `github-webhook:${projectID}:${installationID}`;
      setGitHubComplete((current) => ({
        ...current,
        tokenReference,
        webhookSecret,
        webhookSecretReference
      }));

      const auth = buildProductAuthContext(scope);
      const response = await apiClient.completeGitHubProjectConnection(
        scope.workspaceID,
        projectID,
        {
          state,
          installation_id: installationID,
          account_login: normalizeValue(githubComplete.accountLogin) || undefined,
          token_reference: tokenReference,
          webhook_secret: webhookSecret,
          webhook_secret_reference: webhookSecretReference,
          selected_repositories: repositories
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setConnections((current) => ({ ...current, github: response.connection }));
      setGitHubStart(null);
      setSuccessMessage('GitHub connection saved and ready for repository events.');
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      const message = error instanceof Error ? error.message : 'Unable to complete GitHub connection.';
      setSourceErrors((current) => ({ ...current, github: message }));
    } finally {
      if (!isStaleRequestSequence(requestSequence)) {
        setSubmitting('');
      }
    }
  };

  const handleAWSSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting('aws');
    setSuccessMessage('');
    setSourceErrors((current) => ({ ...current, aws: undefined }));
    const requestSequence = refreshSequenceRef.current;
    try {
      const roleARN = normalizeValue(awsForm.roleARN);
      if (!AWS_ROLE_ARN_PATTERN.test(roleARN)) {
        throw new Error('Enter a valid IAM role ARN, for example arn:aws:iam::123456789012:role/IdentrailReadOnly.');
      }
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.upsertAWSProjectConnection(
        scope.workspaceID,
        projectID,
        {
          role_arn: roleARN,
          external_id: normalizeValue(awsForm.externalID) || undefined,
          region: normalizeValue(awsForm.region) || 'us-east-1',
          display_name: normalizeValue(awsForm.displayName) || undefined,
          session_name: normalizeValue(awsForm.sessionName) || undefined
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setConnections((current) => ({ ...current, aws: response.connection }));
      setSuccessMessage(
        response.connection.connected ? 'AWS connector is active.' : 'AWS connector saved with diagnostics to resolve.'
      );
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      const message = error instanceof Error ? error.message : 'Unable to validate AWS connection.';
      setSourceErrors((current) => ({ ...current, aws: message }));
    } finally {
      if (!isStaleRequestSequence(requestSequence)) {
        setSubmitting('');
      }
    }
  };

  const handleKubernetesSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting('kubernetes');
    setSuccessMessage('');
    setSourceErrors((current) => ({ ...current, kubernetes: undefined }));
    const requestSequence = refreshSequenceRef.current;
    try {
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.upsertKubernetesProjectConnection(
        scope.workspaceID,
        projectID,
        {
          display_name: normalizeValue(kubernetesForm.displayName) || undefined,
          context: normalizeValue(kubernetesForm.context) || undefined
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setConnections((current) => ({ ...current, kubernetes: response.connection }));
      setSuccessMessage(
        response.connection.connected
          ? 'Kubernetes connector is active.'
          : 'Kubernetes preflight completed with diagnostics to resolve.'
      );
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      const message = error instanceof Error ? error.message : 'Unable to validate Kubernetes connection.';
      setSourceErrors((current) => ({ ...current, kubernetes: message }));
    } finally {
      if (!isStaleRequestSequence(requestSequence)) {
        setSubmitting('');
      }
    }
  };

  return (
    <section className="idt-app-panel idt-source-onboarding">
      <div className="idt-source-onboarding-header">
        <div>
          <p className="idt-app-kicker">Project source onboarding</p>
          <h2>Connect sources for {projectID}</h2>
          <p>
            Add GitHub, AWS, or Kubernetes signals for workspace <strong>{scope.workspaceID}</strong> with live
            validation and remediation feedback.
          </p>
        </div>
        <button
          type="button"
          className="idt-btn idt-btn-ghost"
          onClick={() => {
            void refreshConnections(true);
          }}
          disabled={refreshing || submitting !== ''}
        >
          {refreshing ? 'Refreshing...' : 'Refresh status'}
        </button>
      </div>

      <div className="idt-source-summary" aria-label="source connection summary">
        <article>
          <span>{connectedCount}</span>
          <p>Active sources</p>
        </article>
        <article>
          <span>{SOURCE_ORDER.length - connectedCount}</span>
          <p>Remaining</p>
        </article>
        <article>
          <span>{connectionLifecycle(selectedStatus)}</span>
          <p>Selected status</p>
        </article>
      </div>

      {successMessage ? (
        <p role="status" className="idt-app-alert idt-app-alert-success">
          {successMessage}
        </p>
      ) : null}

      <ol className="idt-source-stepper" aria-label="Connect source steps">
        {CONNECT_SOURCE_STEPS.map((step, index) => (
          <li key={step} className={index <= activeStepIndex ? 'is-active' : ''}>
            <span>{index + 1}</span>
            {step}
          </li>
        ))}
      </ol>

      <div className="idt-source-wizard-grid">
        <aside className="idt-source-picker" aria-label="Source types">
          {SOURCE_ORDER.map((provider) => {
            const profile = SOURCE_PROFILES[provider];
            const status = sourceConnection(connections, provider);
            const error = sourceErrors[provider];
            return (
              <button
                key={provider}
                type="button"
                className={`idt-source-card ${selectedSource === provider ? 'is-selected' : ''}`}
                aria-pressed={selectedSource === provider}
                onClick={() => setSelectedSource(provider)}
              >
                <span className="idt-source-card-topline">
                  <span>{profile.eyebrow}</span>
                  <span className={`idt-source-status-pill is-${connectionTone(status)}`}>
                    {error ? 'Needs retry' : connectionLifecycle(status)}
                  </span>
                </span>
                <strong>{profile.name}</strong>
                <small>{profile.primarySignal}</small>
              </button>
            );
          })}
        </aside>

        <div className="idt-source-config">
          <div className="idt-source-config-header">
            <div>
              <p className="idt-app-kicker">{selectedProfile.eyebrow}</p>
              <h3>{selectedProfile.name}</h3>
              <p>{selectedProfile.summary}</p>
            </div>
            <span className={`idt-source-status-pill is-${connectionTone(selectedStatus)}`}>
              {connectionLifecycle(selectedStatus)}
            </span>
          </div>

          <dl className="idt-source-meta">
            <div>
              <dt>Required access</dt>
              <dd>{selectedProfile.requiredAccess}</dd>
            </div>
            <div>
              <dt>Health</dt>
              <dd>{connectionHealth(selectedStatus)}</dd>
            </div>
            <div>
              <dt>Last validation</dt>
              <dd>
                {selectedStatus && 'last_validated_at' in selectedStatus
                  ? formatConnectionTime(selectedStatus.last_validated_at)
                  : formatConnectionTime(selectedStatus?.updated_at)}
              </dd>
            </div>
          </dl>

          {sourceErrors[selectedSource] ? (
            <p role="alert" className="idt-app-alert idt-app-alert-error">
              {sourceErrors[selectedSource]}
            </p>
          ) : null}

          {selectedSource === 'github' ? (
            <div className="idt-source-form-stack">
              <form className="idt-app-form" onSubmit={handleGitHubStart}>
                <div className="idt-source-inline-fields">
                  <label>
                    GitHub App slug
                    <input
                      value={githubStartForm.appSlug}
                      onChange={(event) => setGitHubStartForm((current) => ({ ...current, appSlug: event.target.value }))}
                      placeholder="identrail"
                    />
                  </label>
                  <label>
                    Redirect URI
                    <input
                      value={githubStartForm.redirectURI}
                      onChange={(event) =>
                        setGitHubStartForm((current) => ({ ...current, redirectURI: event.target.value }))
                      }
                      placeholder="Current project page"
                    />
                  </label>
                </div>
                <button className="idt-btn idt-btn-primary" type="submit" disabled={submitting !== ''}>
                  {submitting === 'github' ? 'Preparing...' : 'Generate install link'}
                </button>
              </form>

              {githubStart ? (
                <article className="idt-source-install-card">
                  <div>
                    <h4>GitHub installation ready</h4>
                    <p>State expires {formatConnectionTime(githubStart.expires_at)}.</p>
                  </div>
                  <a className="idt-btn idt-btn-dark" href={githubStart.connect_url} target="_blank" rel="noreferrer">
                    Open GitHub
                  </a>
                </article>
              ) : null}

              <form className="idt-app-form" onSubmit={handleGitHubComplete}>
                <div className="idt-source-inline-fields">
                  <label>
                    Install state
                    <input
                      value={githubComplete.state}
                      onChange={(event) => setGitHubComplete((current) => ({ ...current, state: event.target.value }))}
                      placeholder="Generated install state"
                      required
                    />
                  </label>
                  <label>
                    Installation ID
                    <input
                      inputMode="numeric"
                      value={githubComplete.installationID}
                      onChange={(event) =>
                        setGitHubComplete((current) => ({ ...current, installationID: event.target.value }))
                      }
                      placeholder="12345678"
                      required
                    />
                  </label>
                </div>
                <label>
                  Account login
                  <input
                    value={githubComplete.accountLogin}
                    onChange={(event) =>
                      setGitHubComplete((current) => ({ ...current, accountLogin: event.target.value }))
                    }
                    placeholder="organization or user"
                  />
                </label>
                <label>
                  Selected repositories
                  <textarea
                    value={githubComplete.repositories}
                    onChange={(event) =>
                      setGitHubComplete((current) => ({ ...current, repositories: event.target.value }))
                    }
                    placeholder="owner/repo, owner/security-platform"
                    required
                  />
                </label>
                <details className="idt-source-advanced">
                  <summary>Credential references</summary>
                  <div className="idt-source-inline-fields">
                    <label>
                      Token reference
                      <input
                        value={githubComplete.tokenReference}
                        onChange={(event) =>
                          setGitHubComplete((current) => ({ ...current, tokenReference: event.target.value }))
                        }
                        placeholder="Auto generated from installation ID"
                      />
                    </label>
                    <label>
                      Webhook secret reference
                      <input
                        value={githubComplete.webhookSecretReference}
                        onChange={(event) =>
                          setGitHubComplete((current) => ({ ...current, webhookSecretReference: event.target.value }))
                        }
                        placeholder="Auto generated for this project"
                      />
                    </label>
                  </div>
                  <label>
                    Webhook secret
                    <input
                      type="password"
                      value={githubComplete.webhookSecret}
                      onChange={(event) =>
                        setGitHubComplete((current) => ({ ...current, webhookSecret: event.target.value }))
                      }
                      placeholder="Generated when install link is created"
                    />
                  </label>
                </details>
                <button className="idt-btn idt-btn-primary" type="submit" disabled={submitting !== ''}>
                  {submitting === 'github' ? 'Saving...' : 'Save GitHub connection'}
                </button>
              </form>
            </div>
          ) : null}

          {selectedSource === 'aws' ? (
            <form className="idt-app-form" onSubmit={handleAWSSubmit}>
              <label>
                Role ARN
                <input
                  value={awsForm.roleARN}
                  onChange={(event) => setAWSForm((current) => ({ ...current, roleARN: event.target.value }))}
                  placeholder="arn:aws:iam::123456789012:role/IdentrailReadOnly"
                  required
                />
              </label>
              <div className="idt-source-inline-fields">
                <label>
                  External ID
                  <input
                    value={awsForm.externalID}
                    onChange={(event) => setAWSForm((current) => ({ ...current, externalID: event.target.value }))}
                    placeholder="optional trust-policy guard"
                  />
                </label>
                <label>
                  Region
                  <input
                    value={awsForm.region}
                    onChange={(event) => setAWSForm((current) => ({ ...current, region: event.target.value }))}
                    placeholder="us-east-1"
                  />
                </label>
              </div>
              <div className="idt-source-inline-fields">
                <label>
                  Display name
                  <input
                    value={awsForm.displayName}
                    onChange={(event) => setAWSForm((current) => ({ ...current, displayName: event.target.value }))}
                    placeholder="Production AWS"
                  />
                </label>
                <label>
                  Session name
                  <input
                    value={awsForm.sessionName}
                    onChange={(event) => setAWSForm((current) => ({ ...current, sessionName: event.target.value }))}
                    placeholder="identrail-connector-validation"
                  />
                </label>
              </div>
              <button className="idt-btn idt-btn-primary" type="submit" disabled={submitting !== ''}>
                {submitting === 'aws' ? 'Validating...' : 'Validate and save AWS'}
              </button>
            </form>
          ) : null}

          {selectedSource === 'kubernetes' ? (
            <form className="idt-app-form" onSubmit={handleKubernetesSubmit}>
              <div className="idt-source-inline-fields">
                <label>
                  Display name
                  <input
                    value={kubernetesForm.displayName}
                    onChange={(event) =>
                      setKubernetesForm((current) => ({ ...current, displayName: event.target.value }))
                    }
                    placeholder="Production cluster"
                  />
                </label>
                <label>
                  kubectl context
                  <input
                    value={kubernetesForm.context}
                    onChange={(event) => setKubernetesForm((current) => ({ ...current, context: event.target.value }))}
                    placeholder="API runtime default"
                  />
                </label>
              </div>
              <button className="idt-btn idt-btn-primary" type="submit" disabled={submitting !== ''}>
                {submitting === 'kubernetes' ? 'Running preflight...' : 'Run preflight and save'}
              </button>
            </form>
          ) : null}

          {selectedSource === 'aws' && connections.aws ? (
            <div className="idt-source-diagnostics">
              {connections.aws.account_id ? <p>Account {connections.aws.account_id}</p> : null}
              {connections.aws.principal_arn ? <p>Principal {connections.aws.principal_arn}</p> : null}
              {connections.aws.permission_checks.map((check) => (
                <article key={check.name}>
                  <strong>{check.name}</strong>
                  <span>{check.passed ? 'Passed' : 'Needs attention'}</span>
                  <p>{check.message}</p>
                  {check.remediation ? <small>{check.remediation}</small> : null}
                </article>
              ))}
              {connections.aws.diagnostics.map((diagnostic) => (
                <article key={diagnostic.code}>
                  <strong>{diagnostic.code}</strong>
                  <span>Diagnostic</span>
                  <p>{diagnostic.message}</p>
                  {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
                </article>
              ))}
            </div>
          ) : null}

          {selectedSource === 'kubernetes' && connections.kubernetes ? (
            <div className="idt-source-diagnostics">
              {connections.kubernetes.cluster ? <p>Cluster {connections.kubernetes.cluster}</p> : null}
              {connections.kubernetes.server ? <p>Server {connections.kubernetes.server}</p> : null}
              {connections.kubernetes.permission_checks.map((check) => (
                <article key={`${check.verb}-${check.resource}-${check.scope}`}>
                  <strong>
                    {check.verb} {check.resource}
                  </strong>
                  <span>{check.allowed ? 'Allowed' : 'Blocked'}</span>
                  {check.diagnostic ? <p>{check.diagnostic}</p> : null}
                  {check.remediation ? <small>{check.remediation}</small> : null}
                </article>
              ))}
              {connections.kubernetes.diagnostics.map((diagnostic) => (
                <article key={diagnostic.code}>
                  <strong>{diagnostic.code}</strong>
                  <span>{diagnostic.severity}</span>
                  <p>{diagnostic.message}</p>
                  {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
                </article>
              ))}
            </div>
          ) : null}

          {selectedSource === 'github' && connections.github ? (
            <div className="idt-source-diagnostics">
              {connections.github.account_login ? <p>Account {connections.github.account_login}</p> : null}
              {connections.github.installation_id ? <p>Installation {connections.github.installation_id}</p> : null}
              {connections.github.webhook_secret_rotation_due_at ? (
                <p>Webhook rotation due {formatConnectionTime(connections.github.webhook_secret_rotation_due_at)}</p>
              ) : null}
              {connections.github.selected_repositories.map((repository) => (
                <article key={repository}>
                  <strong>{repository}</strong>
                  <span>Selected</span>
                </article>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

export function ProductFindingsPage() {
  return <ScopedShellPage title="Findings" description="Finding triage queue placeholder for scoped findings, filters, and ownership assignment." />;
}

export function ProductSettingsPage() {
  return <ScopedShellPage title="Settings" description="Tenant/workspace app settings, auth provider mapping, and shell preferences will render here." />;
}
