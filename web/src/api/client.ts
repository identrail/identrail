export type FindingsSummary = {
  total: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
};

export type Finding = {
  id: string;
  scan_id: string;
  type: string;
  severity: string;
  title: string;
  human_summary: string;
  path?: string[];
  repository?: string;
  commit?: string;
  file_path?: string;
  line_number?: number;
  detector?: string;
  line_snippet?: string;
  line_snippet_redacted?: boolean;
  source_url?: string;
  evidence?: Record<string, unknown>;
  remediation: string;
  created_at: string;
  triage?: FindingTriage;
};

export type RepoScanRecord = {
  id: string;
  repository: string;
  status: string;
  started_at: string;
  finished_at?: string;
  commits_scanned: number;
  files_scanned: number;
  finding_count: number;
  truncated: boolean;
  error_message?: string;
};

export type ScanRecord = {
  id: string;
  provider: string;
  status: string;
  started_at: string;
  finished_at?: string;
  asset_count: number;
  finding_count: number;
  error_message?: string;
};

export type TrendPoint = {
  scan_id: string;
  started_at: string;
  total: number;
  by_severity: Record<string, number>;
};

export type ScanDiff = {
  scan_id: string;
  previous_scan_id?: string;
  added_count: number;
  resolved_count: number;
  persisting_count: number;
  added: Finding[];
  resolved: Finding[];
  persisting: Finding[];
};

export type Identity = {
  id: string;
  provider: string;
  type: string;
  name: string;
  arn: string;
  owner_hint: string;
  created_at: string;
  last_used_at?: string;
  tags?: Record<string, string>;
  raw_ref: string;
};

export type Relationship = {
  id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  discovered_at: string;
};

export type ScanEvent = {
  id: string;
  scan_id: string;
  level: string;
  message: string;
  metadata?: Record<string, unknown>;
  created_at: string;
};

export type RequestAuthContext = {
  apiKey?: string;
  tenantID?: string;
  workspaceID?: string;
  bearerToken?: string;
};

export const IDENTRAIL_SCOPE_HEADERS = {
  tenantID: 'X-Identrail-Tenant-ID',
  workspaceID: 'X-Identrail-Workspace-ID'
} as const;

export type IdentrailScopeHeaders = {
  [IDENTRAIL_SCOPE_HEADERS.tenantID]: string;
  [IDENTRAIL_SCOPE_HEADERS.workspaceID]: string;
};

export type WorkspaceMemberRole = 'owner' | 'admin' | 'analyst' | 'viewer';
export type WorkspaceMemberStatus = 'invited' | 'active' | 'suspended' | 'removed';

export type WorkspaceRecord = {
  tenant_id: string;
  workspace_id: string;
  display_name: string;
  slug: string;
  created_at: string;
  updated_at: string;
};

export type WorkspaceMemberRecord = {
  tenant_id: string;
  workspace_id: string;
  member_id: string;
  user_id: string;
  email?: string;
  role: WorkspaceMemberRole;
  status: WorkspaceMemberStatus;
  joined_at: string;
  updated_at: string;
};

export type WorkspaceContextSnapshot = {
  workspace: WorkspaceRecord;
  member?: WorkspaceMemberRecord;
  is_active: boolean;
};

type WorkspaceMemberPage = {
  items: WorkspaceMemberRecord[];
  next_cursor?: string;
};

export type AuthConfigResponse = {
  auth: {
    manual_mode: boolean;
    workos_login_enabled: boolean;
    providers: string[];
  };
};

export type CurrentUser = {
  id: string;
  primary_email: string;
  display_name?: string;
  avatar_url?: string;
  status: 'active' | 'deactivated' | 'deleted' | string;
  created_at: string;
  updated_at: string;
  deleted_at?: string | null;
};

export type OrganizationRecord = {
  tenant_id: string;
  display_name: string;
  slug: string;
  created_at: string;
  updated_at: string;
};

export type CurrentUserContext = {
  user: CurrentUser;
  org_id?: string;
  workspace_id?: string;
  project_id?: string;
  role?: WorkspaceMemberRole;
  organization?: OrganizationRecord;
  workspace?: WorkspaceRecord;
  project?: ProjectRecord;
};

export type SessionListItem = {
  id: string;
  ip?: string;
  user_agent?: string;
  auth_method: 'workos' | 'oidc' | 'manual' | string;
  created_at: string;
  last_seen_at: string;
  idle_expires_at: string;
  current: boolean;
};

export type ManualLoginPayload = {
  tenant_id: string;
  workspace_id: string;
  project_id?: string;
  email?: string;
  display_name?: string;
};

export type ManualLoginResponse = {
  ok: boolean;
  redirect_to: string;
};

export type ProjectRecord = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  name: string;
  slug: string;
  description?: string;
  archived_at?: string | null;
  created_at: string;
  updated_at: string;
};

export type ProjectUpsertRequest = {
  project_id: string;
  name: string;
  slug: string;
  description?: string;
  archived_at?: string | null;
};

export type ScanTriggerMode = 'manual' | 'scheduled' | 'event' | 'hybrid';

export type ScanPolicyRecord = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  policy_id: string;
  name: string;
  enabled: boolean;
  trigger_mode: ScanTriggerMode;
  cron?: string;
  max_concurrent_scans: number;
  history_limit: number;
  max_findings: number;
  created_at: string;
  updated_at: string;
};

export type ScanPolicyUpsertRequest = {
  policy_id: string;
  name: string;
  enabled?: boolean;
  trigger_mode?: ScanTriggerMode;
  cron?: string;
  max_concurrent_scans?: number;
  history_limit?: number;
  max_findings?: number;
};

export type WhoAmIResponse = {
  principal: {
    type: 'subject' | 'api_key' | 'anonymous';
    id: string;
  };
  roles: string[];
  scopes: string[];
  scope: {
    tenant_id: string;
    workspace_id: string;
  };
  active_workspace?: WorkspaceContextSnapshot;
  workspaces: WorkspaceContextSnapshot[];
};

export type FindingLifecycleStatus = 'open' | 'ack' | 'suppressed' | 'resolved';

export type LeadCapturePayload = {
  email: string;
  environment: string;
  company?: string;
  challenge?: string;
  deployment_model?: string;
  scan_goal?: string;
  urgency?: string;
  team_size?: string;
  source: string;
  page_path: string;
};

export type FindingTriage = {
  status: FindingLifecycleStatus;
  assignee?: string;
  suppression_expires_at?: string;
  updated_at?: string;
  updated_by?: string;
};

export type FindingTriageEvent = {
  id: string;
  finding_id: string;
  action: string;
  from_status: FindingLifecycleStatus;
  to_status: FindingLifecycleStatus;
  assignee?: string;
  suppression_expires_at?: string;
  comment?: string;
  actor?: string;
  created_at: string;
};

export type FindingTriageRequest = {
  status?: FindingLifecycleStatus;
  assignee?: string;
  suppression_expires_at?: string;
  comment?: string;
};

export type ConnectorLifecycleStatus = 'pending' | 'active' | 'degraded' | 'disconnected';
export type ConnectorHealthStatus = 'unknown' | 'healthy' | 'warning' | 'error';

export type AWSConnectionPermissionCheck = {
  name: string;
  passed: boolean;
  message: string;
  remediation?: string;
};

export type AWSConnectionDiagnostic = {
  code: string;
  message: string;
  remediation?: string;
};

export type AWSPermissionPreviewItem = {
  service: string;
  actions: string[];
  resources: string[];
  reason: string;
};

export type AWSConnectionStatus = {
  provider: 'aws';
  connected: boolean;
  connector_id?: string;
  display_name?: string;
  status: ConnectorLifecycleStatus;
  health_status: ConnectorHealthStatus;
  role_arn?: string;
  external_id_configured: boolean;
  account_id?: string;
  principal_arn?: string;
  user_id?: string;
  region?: string;
  permission_checks: AWSConnectionPermissionCheck[];
  diagnostics: AWSConnectionDiagnostic[];
  remediation_message?: string;
  launch_url?: string;
  template_url?: string;
  policy_hash?: string;
  created_at?: string;
  updated_at?: string;
  last_validated_at?: string;
};

export type AWSConnectionUpsertRequest = {
  connector_id?: string;
  display_name?: string;
  role_arn: string;
  external_id?: string;
  region?: string;
  session_name?: string;
};

export type AWSConnectorStartRequest = {
  workspace_id?: string;
  project_id?: string;
  connector_id?: string;
  display_name?: string;
  region?: string;
  role_name?: string;
  stack_name?: string;
};

export type AWSConnectorStartResponse = {
  connection: AWSConnectionStatus;
  connector_id: string;
  external_id: string;
  launch_url: string;
  template_url: string;
  role_name: string;
  stack_name: string;
  policy_hash: string;
  permission_preview: AWSPermissionPreviewItem[];
};

export type AWSConnectorValidateRequest = {
  workspace_id?: string;
  project_id?: string;
  role_arn: string;
  external_id?: string;
  region?: string;
  session_name?: string;
};

export type AWSConnectorPolicyResponse = {
  policy_hash: string;
  policy_document: Record<string, unknown>;
  permission_preview: AWSPermissionPreviewItem[];
};

export type KubernetesPermissionCheck = {
  verb: string;
  resource: string;
  scope: string;
  allowed: boolean;
  diagnostic?: string;
  remediation?: string;
};

export type KubernetesPreflightDiagnostic = {
  code: string;
  severity: 'warning' | 'error';
  message: string;
  remediation?: string;
};

export type KubernetesConnectionStatus = {
  provider: 'kubernetes';
  connected: boolean;
  connector_id?: string;
  display_name?: string;
  status: ConnectorLifecycleStatus;
  health_status: ConnectorHealthStatus;
  context?: string;
  cluster?: string;
  server?: string;
  git_version?: string;
  platform?: string;
  permission_checks: KubernetesPermissionCheck[];
  diagnostics: KubernetesPreflightDiagnostic[];
  remediation_message?: string;
  created_at?: string;
  updated_at?: string;
  last_validated_at?: string;
};

export type KubernetesConnectionUpsertRequest = {
  connector_id?: string;
  display_name?: string;
  context?: string;
};

export type GitHubConnectionStartRequest = {
  app_slug?: string;
  redirect_uri?: string;
};

export type GitHubConnectionStartResponse = {
  state: string;
  connect_url: string;
  expires_at: string;
};

export type GitHubConnectorStartRequest = {
  workspace_id?: string;
  project_id?: string;
  connector_id?: string;
  display_name?: string;
  redirect_uri?: string;
};

export type GitHubConnectorStartResponse = {
  connection: GitHubConnectionStatus;
  connector_id: string;
  state: string;
  install_url: string;
  webhook_url?: string;
  expires_at: string;
};

export type GitHubConnectorCompleteRequest = {
  state: string;
  installation_id: number;
  setup_action?: string;
  account_login?: string;
};

export type GitHubConnectorCompleteResponse = {
  connection: GitHubConnectionStatus;
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  redirect_path: string;
};

export type GitHubPATConnectorRequest = {
  workspace_id?: string;
  project_id?: string;
  connector_id?: string;
  display_name?: string;
  base_url?: string;
  token: string;
  selected_repositories?: string[];
};

export type GitHubRepositoryStatus = {
  full_name: string;
  private?: boolean;
};

export type GitHubRepositoryListResponse = {
  connector_id: string;
  provider: string;
  repositories: GitHubRepositoryStatus[];
};

export type GitHubConnectionCompleteRequest = {
  state: string;
  installation_id: number;
  account_login?: string;
  token_reference: string;
  webhook_secret: string;
  webhook_secret_reference: string;
  selected_repositories?: string[];
};

export type GitHubConnectionStatus = {
  provider: string;
  connected: boolean;
  connector_id?: string;
  display_name?: string;
  status?: ConnectorLifecycleStatus;
  health_status?: ConnectorHealthStatus;
  account_login?: string;
  installation_id?: number;
  base_url?: string;
  scopes?: string[];
  token_reference?: string;
  webhook_secret_reference?: string;
  webhook_secret_key_version?: string;
  webhook_secret_algorithm?: string;
  webhook_secret_rotated_at?: string;
  webhook_secret_rotation_due_at?: string;
  webhook_secret_rotation_required: boolean;
  selected_repositories: string[];
  created_at?: string;
  updated_at?: string;
  last_webhook_event_type?: string;
  last_webhook_delivery_id?: string;
  last_webhook_event_at?: string;
};

const viteEnv = ((import.meta as unknown as { env?: Record<string, unknown> }).env ?? {}) as Record<string, unknown>;
const isProd = viteEnv.PROD === true || viteEnv.PROD === 'true';
const configuredURL = typeof viteEnv.VITE_IDENTRAIL_API_URL === 'string' ? trimOrUndefined(viteEnv.VITE_IDENTRAIL_API_URL) : undefined;
const IDENTRAIL_CLOUD_WEB_HOSTNAMES = new Set(['identrail.com', 'www.identrail.com', 'app.identrail.com']);
export const IDENTRAIL_CLOUD_API_URL = 'https://api.identrail.com';

function trimOrUndefined(value?: string): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function currentBrowserHostname(): string | undefined {
  if (typeof window === 'undefined') {
    return undefined;
  }
  return window.location.hostname;
}

export function resolveAPIBaseURL(configuredAPIURL: string | undefined, production: boolean, hostname?: string): string {
  const trimmedConfiguredURL = trimOrUndefined(configuredAPIURL);
  if (trimmedConfiguredURL) {
    return trimmedConfiguredURL;
  }
  const normalizedHostname = hostname?.trim().toLowerCase();
  if (production && normalizedHostname && IDENTRAIL_CLOUD_WEB_HOSTNAMES.has(normalizedHostname)) {
    return IDENTRAIL_CLOUD_API_URL;
  }
  return production ? '' : 'http://localhost:8080';
}

const baseURL = resolveAPIBaseURL(configuredURL, isProd, currentBrowserHostname());

// Never silently fall back to localhost in production builds (for example on Vercel).
// Hosted Identrail domains use the canonical cloud API default; custom
// production hosts still fail loudly unless explicitly configured.
if (isProd && baseURL) {
  const parsed = new URL(baseURL);
  if (parsed.protocol === 'http:' && parsed.hostname !== 'localhost') {
    throw new Error('VITE_IDENTRAIL_API_URL must use HTTPS in production (HTTP only allowed for localhost)');
  }
}

type IdentrailRequestInit = RequestInit & {
  redirectOnUnauthorized?: boolean;
};

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export function buildAPIURL(path: string): string {
  if (isProd && !baseURL) {
    throw new Error(
      'Identrail API URL is not configured. Set VITE_IDENTRAIL_API_URL or use an Identrail Cloud web domain.'
    );
  }
  return `${baseURL}${path}`;
}

function buildRequestHeaders(auth?: RequestAuthContext): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const apiKey = trimOrUndefined(auth?.apiKey);
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }
  const tenantID = trimOrUndefined(auth?.tenantID);
  if (tenantID) {
    headers[IDENTRAIL_SCOPE_HEADERS.tenantID] = tenantID;
  }
  const workspaceID = trimOrUndefined(auth?.workspaceID);
  if (workspaceID) {
    headers[IDENTRAIL_SCOPE_HEADERS.workspaceID] = workspaceID;
  }
  const bearerToken = trimOrUndefined(auth?.bearerToken);
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  }
  return headers;
}

export function mergeRequestHeaders(auth?: RequestAuthContext, initHeaders?: HeadersInit): Headers {
  const headers = new Headers(buildRequestHeaders(auth));
  if (!initHeaders) {
    return headers;
  }
  const normalizedHeaders = new Headers(initHeaders);
  normalizedHeaders.forEach((value, key) => {
    headers.set(key, value);
  });
  return headers;
}

function redirectToSignInForUnauthorized() {
  if (typeof window === 'undefined') {
    return;
  }
  const returnTo = `${window.location.pathname}${window.location.search}`;
  const query = new URLSearchParams();
  if (returnTo && !returnTo.startsWith('/signin') && !returnTo.startsWith('/signup')) {
    query.set('return_to', returnTo);
  }
  const target = query.size > 0 ? `/signin?${query.toString()}` : '/signin';
  window.location.assign(target);
}

async function request<T>(path: string, auth?: RequestAuthContext, init: IdentrailRequestInit = {}): Promise<T> {
  if (isProd && !baseURL) {
    throw new Error(
      'Identrail API URL is not configured. Set VITE_IDENTRAIL_API_URL or use an Identrail Cloud web domain.'
    );
  }
  const { redirectOnUnauthorized = true, ...fetchInit } = init;
  const headers = mergeRequestHeaders(auth, init.headers);
  const res = await fetch(buildAPIURL(path), {
    ...fetchInit,
    credentials: fetchInit.credentials ?? 'include',
    headers
  });
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const payload = (await res.json()) as { error?: string };
      if (payload?.error) {
        message = payload.error;
      }
    } catch {
      // Keep status-based message when server does not return a JSON error body.
    }
    if (res.status === 401 && redirectOnUnauthorized) {
      redirectToSignInForUnauthorized();
    }
    throw new ApiError(message, res.status);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

function buildQuery(params: Record<string, string | number | boolean | undefined>): string {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === '') return;
    query.set(key, String(value));
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : '';
}

export const apiClient = {
  getAuthConfig() {
    return request<AuthConfigResponse>('/v1/auth/config', undefined, { redirectOnUnauthorized: false });
  },
  getMe(options: { redirectOnUnauthorized?: boolean } = {}) {
    return request<{ me: CurrentUserContext }>('/v1/me', undefined, {
      redirectOnUnauthorized: options.redirectOnUnauthorized ?? false
    });
  },
  listCurrentUserSessions() {
    return request<{ items: SessionListItem[] }>('/v1/me/sessions');
  },
  revokeCurrentUserSession(sessionID: string) {
    return request<{ ok: boolean }>(`/v1/me/sessions/${encodeURIComponent(sessionID)}`, undefined, {
      method: 'DELETE'
    });
  },
  revokeOtherCurrentUserSessions() {
    return request<{ ok: boolean; revoked: number }>('/v1/me/sessions/revoke-others', undefined, {
      method: 'POST'
    });
  },
  logout() {
    return request<{ ok: boolean }>('/auth/logout', undefined, {
      method: 'POST',
      redirectOnUnauthorized: false
    });
  },
  manualLogin(payload: ManualLoginPayload) {
    return request<ManualLoginResponse>('/auth/manual', undefined, {
      method: 'POST',
      body: JSON.stringify(payload),
      redirectOnUnauthorized: false
    });
  },
  getWhoAmI(auth?: RequestAuthContext) {
    return request<WhoAmIResponse>('/v1/whoami', auth);
  },
  resolveActiveWorkspace(workspaceID: string, auth?: RequestAuthContext) {
    return request<{
      active_workspace: WorkspaceContextSnapshot;
      scope: { tenant_id: string; workspace_id: string };
      scope_headers: IdentrailScopeHeaders;
    }>('/v1/workspaces/active', auth, {
      method: 'POST',
      body: JSON.stringify({ workspace_id: workspaceID })
    });
  },
  listWorkspaceMembers(
    workspaceID: string,
    filters: {
      role?: WorkspaceMemberRole;
      status?: WorkspaceMemberStatus;
      limit?: number;
    } = {},
    auth?: RequestAuthContext
  ) {
    const encodedWorkspaceID = encodeURIComponent(workspaceID);
    const loadAllPages = async () => {
      const items: WorkspaceMemberRecord[] = [];
      let nextCursor: string | undefined;

      do {
        const page = await request<WorkspaceMemberPage>(
          `/v1/workspaces/${encodedWorkspaceID}/members${buildQuery({
            ...filters,
            cursor: nextCursor
          })}`,
          auth
        );
        items.push(...page.items);
        nextCursor = trimOrUndefined(page.next_cursor);
      } while (nextCursor);

      return { items };
    };

    return loadAllPages();
  },
  listProjects(
    workspaceID: string,
    filters: {
      limit?: number;
      cursor?: string;
      sort_by?: string;
      sort_order?: 'asc' | 'desc';
      include_archived?: boolean;
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: ProjectRecord[]; next_cursor?: string }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects${buildQuery(filters)}`,
      auth
    );
  },
  getProject(workspaceID: string, projectID: string, auth?: RequestAuthContext) {
    return request<{ project: ProjectRecord }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}`,
      auth
    );
  },
  upsertProject(workspaceID: string, payload: ProjectUpsertRequest, auth?: RequestAuthContext) {
    return request<{ project: ProjectRecord }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  listProjectScanPolicies(
    workspaceID: string,
    projectID: string,
    filters: {
      limit?: number;
      cursor?: string;
      sort_by?: string;
      sort_order?: 'asc' | 'desc';
      trigger_mode?: ScanTriggerMode;
      enabled?: boolean;
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: ScanPolicyRecord[]; next_cursor?: string }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/scan-policies${buildQuery(filters)}`,
      auth
    );
  },
  getProjectScanPolicy(workspaceID: string, projectID: string, policyID: string, auth?: RequestAuthContext) {
    return request<{ policy: ScanPolicyRecord }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/scan-policies/${encodeURIComponent(policyID)}`,
      auth
    );
  },
  upsertProjectScanPolicy(
    workspaceID: string,
    projectID: string,
    payload: ScanPolicyUpsertRequest,
    auth?: RequestAuthContext
  ) {
    return request<{ policy: ScanPolicyRecord }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/scan-policies`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  deleteProjectScanPolicy(workspaceID: string, projectID: string, policyID: string, auth?: RequestAuthContext) {
    return request<void>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/scan-policies/${encodeURIComponent(policyID)}`,
      auth,
      {
        method: 'DELETE'
      }
    );
  },
  upsertWorkspaceMember(
    workspaceID: string,
    payload: {
      member_id: string;
      user_id: string;
      email?: string;
      role: WorkspaceMemberRole;
      status: WorkspaceMemberStatus;
    },
    auth?: RequestAuthContext
  ) {
    return request<{ member: WorkspaceMemberRecord }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/members`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  deleteWorkspaceMember(workspaceID: string, memberID: string, auth?: RequestAuthContext) {
    return request<void>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/members/${encodeURIComponent(memberID)}`,
      auth,
      {
        method: 'DELETE'
      }
    );
  },
  getFindingsSummary(auth?: RequestAuthContext) {
    return request<FindingsSummary>('/v1/findings/summary', auth);
  },
  getFindingsTrends(
    filters: { points?: number; severity?: string; type?: string } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: TrendPoint[] }>(`/v1/findings/trends${buildQuery(filters)}`, auth);
  },
  listScans(auth?: RequestAuthContext) {
    return request<{ items: ScanRecord[] }>('/v1/scans?sort_by=started_at&sort_order=desc', auth);
  },
  listRepoScans(
    filters: {
      limit?: number;
      cursor?: string;
      sort_by?: string;
      sort_order?: 'asc' | 'desc';
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: RepoScanRecord[] }>(
      `/v1/repo-scans${buildQuery({ sort_by: 'started_at', sort_order: 'desc', ...filters })}`,
      auth
    );
  },
  listFindings(
    filters: {
      limit?: number;
      scan_id?: string;
      severity?: string;
      type?: string;
      lifecycle_status?: FindingLifecycleStatus;
      assignee?: string;
      sort_by?: string;
      sort_order?: 'asc' | 'desc';
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: Finding[] }>(`/v1/findings${buildQuery(filters)}`, auth);
  },
  listRepoFindings(
    filters: {
      limit?: number;
      cursor?: string;
      repo_scan_id?: string;
      severity?: string;
      type?: string;
      sort_by?: string;
      sort_order?: 'asc' | 'desc';
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: Finding[] }>(
      `/v1/repo-findings${buildQuery({ sort_by: 'created_at', sort_order: 'desc', ...filters })}`,
      auth
    );
  },
  getFinding(findingID: string, scanID?: string, auth?: RequestAuthContext) {
    const suffix = buildQuery({ scan_id: scanID });
    return request<Finding>(`/v1/findings/${encodeURIComponent(findingID)}${suffix}`, auth);
  },
  listFindingHistory(findingID: string, scanID?: string, limit = 20, auth?: RequestAuthContext) {
    return request<{ items: FindingTriageEvent[] }>(
      `/v1/findings/${encodeURIComponent(findingID)}/history${buildQuery({ scan_id: scanID, limit })}`,
      auth
    );
  },
  triageFinding(findingID: string, payload: FindingTriageRequest, scanID?: string, auth?: RequestAuthContext) {
    const suffix = buildQuery({ scan_id: scanID });
    return request<{ finding: Finding }>(`/v1/findings/${encodeURIComponent(findingID)}/triage${suffix}`, auth, {
      method: 'PATCH',
      body: JSON.stringify(payload)
    });
  },
  getScanDiff(scanID: string, limit = 20, auth?: RequestAuthContext, previousScanID?: string) {
    return request<ScanDiff>(
      `/v1/scans/${encodeURIComponent(scanID)}/diff${buildQuery({
        limit,
        previous_scan_id: previousScanID
      })}`,
      auth
    );
  },
  listIdentities(scanID: string, limit = 100, auth?: RequestAuthContext) {
    return request<{ items: Identity[] }>(
      `/v1/identities${buildQuery({ scan_id: scanID, limit, sort_by: 'name', sort_order: 'asc' })}`,
      auth
    );
  },
  listRelationships(scanID: string, limit = 100, auth?: RequestAuthContext) {
    return request<{ items: Relationship[] }>(
      `/v1/relationships${buildQuery({ scan_id: scanID, limit, sort_by: 'discovered_at', sort_order: 'desc' })}`,
      auth
    );
  },
  listScanEvents(scanID: string, level?: string, limit = 50, auth?: RequestAuthContext) {
    return request<{ items: ScanEvent[] }>(
      `/v1/scans/${encodeURIComponent(scanID)}/events${buildQuery({
        level,
        limit,
        sort_by: 'created_at',
        sort_order: 'desc'
      })}`,
      auth
    );
  },
  getAWSProjectConnection(workspaceID: string, projectID: string, auth?: RequestAuthContext) {
    return request<{ connection: AWSConnectionStatus }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/connection`,
      auth
    );
  },
  startAWSConnector(payload: AWSConnectorStartRequest, auth?: RequestAuthContext) {
    return request<AWSConnectorStartResponse>('/v1/connectors/aws', auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  pollAWSConnector(connectorID: string, workspaceID: string, projectID: string, auth?: RequestAuthContext) {
    return request<{ connection: AWSConnectionStatus }>(
      `/v1/connectors/aws/${encodeURIComponent(connectorID)}/poll${buildQuery({ workspace_id: workspaceID, project_id: projectID })}`,
      auth
    );
  },
  validateAWSConnector(connectorID: string, payload: AWSConnectorValidateRequest, auth?: RequestAuthContext) {
    return request<{ connection: AWSConnectionStatus }>(
      `/v1/connectors/aws/${encodeURIComponent(connectorID)}/validate`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  refreshAWSConnectorPolicy(
    connectorID: string,
    payload: { workspace_id?: string; project_id?: string },
    auth?: RequestAuthContext
  ) {
    return request<AWSConnectorPolicyResponse>(`/v1/connectors/aws/${encodeURIComponent(connectorID)}/refresh-policy`, auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  startGitHubConnector(payload: GitHubConnectorStartRequest, auth?: RequestAuthContext) {
    return request<GitHubConnectorStartResponse>('/v1/connectors/github', auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  completeGitHubConnector(payload: GitHubConnectorCompleteRequest, auth?: RequestAuthContext) {
    return request<GitHubConnectorCompleteResponse>('/v1/connectors/github/complete', auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  getGitHubConnectorStatus(workspaceID: string, projectID: string, auth?: RequestAuthContext) {
    return request<{ connection: GitHubConnectionStatus }>(
      `/v1/connectors/github${buildQuery({ workspace_id: workspaceID, project_id: projectID })}`,
      auth
    );
  },
  upsertGitHubPATConnector(payload: GitHubPATConnectorRequest, auth?: RequestAuthContext) {
    return request<{ connection: GitHubConnectionStatus }>('/v1/connectors/github/pat', auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  listGitHubConnectorRepositories(connectorID: string, workspaceID: string, projectID: string, auth?: RequestAuthContext) {
    return request<GitHubRepositoryListResponse>(
      `/v1/connectors/github/${encodeURIComponent(connectorID)}/repos${buildQuery({ workspace_id: workspaceID, project_id: projectID })}`,
      auth
    );
  },
  upsertAWSProjectConnection(
    workspaceID: string,
    projectID: string,
    payload: AWSConnectionUpsertRequest,
    auth?: RequestAuthContext
  ) {
    return request<{ connection: AWSConnectionStatus }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/connection`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  getKubernetesProjectConnection(workspaceID: string, projectID: string, auth?: RequestAuthContext) {
    return request<{ connection: KubernetesConnectionStatus }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/kubernetes/connection`,
      auth
    );
  },
  upsertKubernetesProjectConnection(
    workspaceID: string,
    projectID: string,
    payload: KubernetesConnectionUpsertRequest,
    auth?: RequestAuthContext
  ) {
    return request<{ connection: KubernetesConnectionStatus }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/kubernetes/connection`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  getGitHubProjectConnection(workspaceID: string, projectID: string, auth?: RequestAuthContext) {
    return request<{ connection: GitHubConnectionStatus }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/github/connection`,
      auth
    );
  },
  startGitHubProjectConnection(
    workspaceID: string,
    projectID: string,
    payload: GitHubConnectionStartRequest = {},
    auth?: RequestAuthContext
  ) {
    return request<{ connection: GitHubConnectionStartResponse }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/github/connect/start`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  completeGitHubProjectConnection(
    workspaceID: string,
    projectID: string,
    payload: GitHubConnectionCompleteRequest,
    auth?: RequestAuthContext
  ) {
    return request<{ connection: GitHubConnectionStatus }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/github/connect/complete`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  async submitLeadCapture(payload: LeadCapturePayload) {
    const res = await fetch('/api/leads', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      let message = 'Unable to submit lead request right now.';
      try {
        const data = (await res.json()) as { error?: string };
        if (data?.error) {
          message = data.error;
        }
      } catch {
        // Keep generic message when API body is unavailable.
      }
      throw new Error(message);
    }
    return (await res.json()) as { status: string };
  }
};

export { buildQuery };
