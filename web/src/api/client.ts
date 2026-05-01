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
  evidence?: Record<string, unknown>;
  remediation: string;
  created_at: string;
  triage?: FindingTriage;
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

const viteEnv = ((import.meta as unknown as { env?: Record<string, unknown> }).env ?? {}) as Record<string, unknown>;
const isProd = viteEnv.PROD === true || viteEnv.PROD === 'true';
const configuredURL = typeof viteEnv.VITE_IDENTRAIL_API_URL === 'string' ? viteEnv.VITE_IDENTRAIL_API_URL : undefined;

// Never silently fall back to localhost in production builds (for example on Vercel).
// If the API URL is not configured, requests should fail loudly when invoked.
if (isProd && configuredURL) {
  const parsed = new URL(configuredURL);
  if (parsed.protocol === 'http:' && parsed.hostname !== 'localhost') {
    throw new Error('VITE_IDENTRAIL_API_URL must use HTTPS in production (HTTP only allowed for localhost)');
  }
}

const baseURL = configuredURL ?? (isProd ? '' : 'http://localhost:8080');

function trimOrUndefined(value?: string): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function buildRequestHeaders(auth?: RequestAuthContext): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const apiKey = trimOrUndefined(auth?.apiKey);
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }
  const tenantID = trimOrUndefined(auth?.tenantID);
  if (tenantID) {
    headers['X-Identrail-Tenant-ID'] = tenantID;
  }
  const workspaceID = trimOrUndefined(auth?.workspaceID);
  if (workspaceID) {
    headers['X-Identrail-Workspace-ID'] = workspaceID;
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

async function request<T>(path: string, auth?: RequestAuthContext, init: RequestInit = {}): Promise<T> {
  if (isProd && !configuredURL) {
    throw new Error(
      'Identrail API URL is not configured. Set VITE_IDENTRAIL_API_URL in Vercel project environment variables.'
    );
  }
  const headers = mergeRequestHeaders(auth, init.headers);
  const res = await fetch(`${baseURL}${path}`, { ...init, headers });
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
    throw new Error(message);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

function buildQuery(params: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === '') return;
    query.set(key, String(value));
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : '';
}

export const apiClient = {
  getWhoAmI(auth?: RequestAuthContext) {
    return request<WhoAmIResponse>('/v1/whoami', auth);
  },
  resolveActiveWorkspace(workspaceID: string, auth?: RequestAuthContext) {
    return request<{
      active_workspace: WorkspaceContextSnapshot;
      scope: { tenant_id: string; workspace_id: string };
      scope_headers: { 'X-Identrail-Tenant-ID': string; 'X-Identrail-Workspace-ID': string };
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
    return request<{ items: WorkspaceMemberRecord[] }>(
      `/v1/workspaces/${encodedWorkspaceID}/members${buildQuery(filters)}`,
      auth
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
  listFindings(
    filters: {
      limit?: number;
      scan_id?: string;
      severity?: string;
      type?: string;
      sort_by?: string;
      sort_order?: 'asc' | 'desc';
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: Finding[] }>(`/v1/findings${buildQuery(filters)}`, auth);
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
