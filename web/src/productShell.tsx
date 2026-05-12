import { Component, FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  ApiError,
  apiClient,
  type AWSConnectionStatus,
  type CurrentUserContext,
  type GitHubConnectionStartResponse,
  type GitHubConnectionStatus,
  type KubernetesConnectionStatus,
  type ProjectRecord,
  type RequestAuthContext,
  type ScanPolicyRecord,
  type ScanTriggerMode,
  type WhoAmIResponse,
  type WorkspaceMemberRecord,
  type WorkspaceMemberRole,
  type WorkspaceMemberStatus
} from './api/client';
import { useMe } from './hooks/useMe';

type ProductSession = {
  tenantID: string;
  workspaceID: string;
  projectID?: string;
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

function normalizeValue(value: string): string {
  return value.trim();
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

function buildCurrentUserAppPath(me: CurrentUserContext | null): string {
  if (me?.org_id && me.workspace_id) {
    return buildTenantWorkspacePath(me.org_id, me.workspace_id);
  }
  return '/app';
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
const SCAN_POLICY_TRIGGER_MODES: ScanTriggerMode[] = ['manual', 'scheduled', 'event', 'hybrid'];

function buildProductAuthContext(scope: ProductSession): RequestAuthContext {
  return {
    tenantID: scope.tenantID,
    workspaceID: scope.workspaceID
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
  if (!whoAmI) {
    return false;
  }
  const activeRole =
    whoAmI.active_workspace?.member?.role ??
    whoAmI.workspaces?.find((item) => item.workspace.workspace_id === scope.workspaceID)?.member?.role;
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

function formatScanTriggerModeLabel(mode: ScanTriggerMode): string {
  return mode.charAt(0).toUpperCase() + mode.slice(1);
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
  const navigate = useNavigate();
  const params = useParams<ScopeRouteParams>();
  const routeKey = `${location.pathname}?${location.search}`;
  const [status, setStatus] = useState<'checking' | 'authenticated' | 'unauthenticated' | 'error'>('checking');
  const [validatedRouteKey, setValidatedRouteKey] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;

    const run = async () => {
      setStatus('checking');
      setError('');
      try {
        const current = await apiClient.getMe({ redirectOnUnauthorized: false });
        const routeTenantID = normalizeValue(params.tenantID ?? '');
        const routeWorkspaceID = normalizeValue(params.workspaceID ?? '');
        const currentTenantID = normalizeValue(current.me.org_id ?? '');
        const currentWorkspaceID = normalizeValue(current.me.workspace_id ?? '');
        if (
          routeTenantID &&
          routeWorkspaceID &&
          currentTenantID &&
          currentWorkspaceID &&
          (routeTenantID !== currentTenantID || routeWorkspaceID !== currentWorkspaceID)
        ) {
          if (routeTenantID !== currentTenantID) {
            if (!mounted) {
              return;
            }
            navigate(buildTenantWorkspacePath(currentTenantID, currentWorkspaceID), { replace: true });
            setStatus('authenticated');
            return;
          }
          await apiClient.resolveActiveWorkspace(routeWorkspaceID, {
            tenantID: currentTenantID,
            workspaceID: currentWorkspaceID
          });
        }
        if (!mounted) {
          return;
        }
        setValidatedRouteKey(routeKey);
        setStatus('authenticated');
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        if (requestError instanceof ApiError && requestError.status === 401) {
          setStatus('unauthenticated');
          return;
        }
        const message = requestError instanceof Error ? requestError.message : 'Unable to validate account session.';
        setValidatedRouteKey('');
        setError(message);
        setStatus('error');
      }
    };

    void run();

    return () => {
      mounted = false;
    };
  }, [navigate, params.tenantID, params.workspaceID, routeKey]);

  if (status === 'checking' || (status === 'authenticated' && validatedRouteKey !== routeKey)) {
    return <AppShellLoading message="Validating session" />;
  }

  if (status === 'error') {
    return (
      <section className="idt-app-shell-screen" role="alert">
        <article className="idt-app-panel idt-app-panel-error">
          <p className="idt-app-kicker">Session check failed</p>
          <h1>Unable to validate account session</h1>
          <p>{error}</p>
        </article>
      </section>
    );
  }

  if (status === 'unauthenticated') {
    const query = new URLSearchParams();
    query.set('return_to', `${location.pathname}${location.search}`);
    const redirect = `/signin?${query.toString()}`;
    return <Navigate to={redirect} replace />;
  }

  return <>{children}</>;
}

export function ProductLoginPage() {
  const location = useLocation();
  const query = new URLSearchParams(location.search);
  const nextPath = normalizeValue(query.get('next') ?? query.get('return_to') ?? '');
  const nextQuery = new URLSearchParams();
  if (nextPath) {
    nextQuery.set('return_to', nextPath);
  }
  const reason = normalizeValue(query.get('reason') ?? '');
  if (reason) {
    nextQuery.set('reason', reason);
  }
  if (normalizeValue(query.get('signed_out') ?? '') === '1') {
    nextQuery.set('signed_out', '1');
  }
  return <Navigate to={`/signin${nextQuery.size > 0 ? `?${nextQuery.toString()}` : ''}`} replace />;
}

export function ProductAuthCallbackRedirectPage() {
  return <Navigate to="/auth/callback" replace />;
}

export function ProductLogoutPage() {
  const navigate = useNavigate();
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;

    const run = async () => {
      try {
        await apiClient.logout();
      } catch (logoutError) {
        if (!(logoutError instanceof ApiError && logoutError.status === 401)) {
          if (mounted) {
            const message = logoutError instanceof Error ? logoutError.message : 'Unable to revoke this browser session.';
            setError(message);
          }
          return;
        }
      }

      if (mounted) {
        navigate('/signin?signed_out=1', { replace: true });
      }
    };

    void run();

    return () => {
      mounted = false;
    };
  }, [navigate]);

  if (error) {
    return (
      <section className="idt-app-shell-screen" role="alert">
        <article className="idt-app-panel idt-app-panel-error">
          <p className="idt-app-kicker">Sign out failed</p>
          <h1>Unable to sign out</h1>
          <p>{error}</p>
        </article>
      </section>
    );
  }

  return <AppShellLoading message="Signing out" />;
}

export function ProductAppIndexRedirect() {
  const { me, loading, error, unauthenticated } = useMe();
  if (loading) {
    return <AppShellLoading message="Resolving workspace scope" />;
  }
  if (unauthenticated) {
    return <Navigate to="/signin?return_to=%2Fapp" replace />;
  }
  if (error) {
    return (
      <section className="idt-app-shell-screen" role="alert">
        <article className="idt-app-panel idt-app-panel-error">
          <p className="idt-app-kicker">Session check failed</p>
          <h1>Unable to resolve app workspace</h1>
          <p>{error}</p>
        </article>
      </section>
    );
  }
  if (!me?.org_id || !me.workspace_id) {
    return (
      <section className="idt-app-shell-screen">
        <article className="idt-app-panel">
          <p className="idt-app-kicker">Workspace required</p>
          <h1>No workspace is attached yet</h1>
          <p>Your account is active, but no workspace membership has been assigned.</p>
        </article>
      </section>
    );
  }
  return <Navigate to={buildCurrentUserAppPath(me)} replace />;
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
            <Link to="/app/account/security" className="idt-btn idt-btn-ghost">
              Account security
            </Link>
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
          <NavLink to="/app/account/security">Security</NavLink>
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
  const membersRequestRef = useRef(0);

  const refreshMembers = async (targetScope: ProductSession) => {
    const requestID = ++membersRequestRef.current;
    const auth = buildProductAuthContext(targetScope);
    const response = await apiClient.listWorkspaceMembers(targetScope.workspaceID, {}, auth);
    if (requestID !== membersRequestRef.current) {
      return;
    }
    setMembers(response.items);
    setMemberDrafts(
      response.items.reduce<MemberDraftState>((acc, member) => {
        acc[member.member_id] = { role: member.role, status: member.status };
        return acc;
      }, {})
    );
  };

  useEffect(() => {
    return () => {
      membersRequestRef.current += 1;
    };
  }, [scope?.tenantID, scope?.workspaceID]);

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
        setWorkspaceTarget(snapshot.scope?.workspace_id || scope.workspaceID);
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
  const [scanPolicies, setScanPolicies] = useState<ScanPolicyRecord[]>([]);
  const [scanPolicyError, setScanPolicyError] = useState('');
  const [policySaving, setPolicySaving] = useState(false);
  const [policyDeletingID, setPolicyDeletingID] = useState('');
  const [policyForm, setPolicyForm] = useState({
    policyID: 'default',
    name: 'Default policy',
    enabled: true,
    triggerMode: 'manual' as ScanTriggerMode,
    cron: '',
    maxConcurrentScans: '1',
    historyLimit: '500',
    maxFindings: '200'
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
      apiClient.getKubernetesProjectConnection(scope.workspaceID, projectID, auth),
      apiClient.listProjectScanPolicies(
        scope.workspaceID,
        projectID,
        {
          limit: 50,
          sort_by: 'updated_at',
          sort_order: 'desc'
        },
        auth
      )
    ]);

    if (isStaleRequestSequence(refreshSequence)) {
      return;
    }

    const nextConnections: SourceConnectionMap = {};
    const nextErrors: Partial<Record<SourceProvider, string>> = {};
    const [githubResult, awsResult, kubernetesResult, scanPolicyResult] = results;

    if (githubResult.status === 'fulfilled') {
      nextConnections.github = githubResult.value.connection;
    } else {
      nextErrors.github =
        githubResult.reason instanceof Error ? githubResult.reason.message : `Unable to load ${SOURCE_PROFILES.github.name} status.`;
    }
    if (awsResult.status === 'fulfilled') {
      nextConnections.aws = awsResult.value.connection;
    } else {
      nextErrors.aws =
        awsResult.reason instanceof Error ? awsResult.reason.message : `Unable to load ${SOURCE_PROFILES.aws.name} status.`;
    }
    if (kubernetesResult.status === 'fulfilled') {
      nextConnections.kubernetes = kubernetesResult.value.connection;
    } else {
      nextErrors.kubernetes =
        kubernetesResult.reason instanceof Error
          ? kubernetesResult.reason.message
          : `Unable to load ${SOURCE_PROFILES.kubernetes.name} status.`;
    }

    setConnections(nextConnections);
    setSourceErrors(nextErrors);
    if (scanPolicyResult?.status === 'fulfilled') {
      const items = scanPolicyResult.value.items ?? [];
      setScanPolicies(items);
      setScanPolicyError('');
      setPolicyForm((current) => {
        if (items.length === 0) {
          return {
            policyID: current.policyID || 'default',
            name: current.name || 'Default policy',
            enabled: current.enabled,
            triggerMode: current.triggerMode,
            cron: current.cron,
            maxConcurrentScans: current.maxConcurrentScans,
            historyLimit: current.historyLimit,
            maxFindings: current.maxFindings
          };
        }
        const selected = items.find((item) => item.policy_id === current.policyID) ?? items[0];
        return {
          policyID: selected.policy_id,
          name: selected.name,
          enabled: selected.enabled,
          triggerMode: selected.trigger_mode,
          cron: selected.cron ?? '',
          maxConcurrentScans: String(selected.max_concurrent_scans),
          historyLimit: String(selected.history_limit),
          maxFindings: String(selected.max_findings)
        };
      });
    } else if (scanPolicyResult?.status === 'rejected') {
      setScanPolicyError(
        scanPolicyResult.reason instanceof Error
          ? scanPolicyResult.reason.message
          : 'Unable to load scan policies for this project.'
      );
      setScanPolicies([]);
    }
    setLoading(false);
    setRefreshing(false);
  };

  useEffect(() => {
    setConnections({});
    setSourceErrors({});
    setScanPolicies([]);
    setScanPolicyError('');
    setPolicySaving(false);
    setPolicyDeletingID('');
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

  const parsePositiveInteger = (value: string, field: string): number => {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error(`${field} must be a positive integer.`);
    }
    return parsed;
  };

  const handleScanPolicySubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPolicySaving(true);
    setScanPolicyError('');
    setSuccessMessage('');
    const requestSequence = refreshSequenceRef.current;
    try {
      const policyID = normalizeProjectToken(policyForm.policyID);
      if (!policyID) {
        throw new Error('Policy ID is required.');
      }
      const name = normalizeValue(policyForm.name);
      if (!name) {
        throw new Error('Policy name is required.');
      }
      const triggerMode = policyForm.triggerMode;
      const cron = normalizeValue(policyForm.cron);
      if ((triggerMode === 'scheduled' || triggerMode === 'hybrid') && !cron) {
        throw new Error('Cron is required when trigger mode is scheduled or hybrid.');
      }
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.upsertProjectScanPolicy(
        scope.workspaceID,
        projectID,
        {
          policy_id: policyID,
          name,
          enabled: policyForm.enabled,
          trigger_mode: triggerMode,
          cron: cron || undefined,
          max_concurrent_scans: parsePositiveInteger(policyForm.maxConcurrentScans, 'Max concurrent scans'),
          history_limit: parsePositiveInteger(policyForm.historyLimit, 'History limit'),
          max_findings: parsePositiveInteger(policyForm.maxFindings, 'Max findings')
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      const policy = response.policy;
      setPolicyForm({
        policyID: policy.policy_id,
        name: policy.name,
        enabled: policy.enabled,
        triggerMode: policy.trigger_mode,
        cron: policy.cron ?? '',
        maxConcurrentScans: String(policy.max_concurrent_scans),
        historyLimit: String(policy.history_limit),
        maxFindings: String(policy.max_findings)
      });
	      setSuccessMessage('Scan policy saved.');
	      setPolicySaving(false);
	      void refreshConnections(true);
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setScanPolicyError(error instanceof Error ? error.message : 'Unable to save scan policy.');
    } finally {
      if (!isStaleRequestSequence(requestSequence)) {
        setPolicySaving(false);
      }
    }
  };

  const handleScanPolicyDelete = async (policyID: string) => {
    const normalizedPolicyID = normalizeValue(policyID);
    if (!normalizedPolicyID) {
      return;
    }
    setPolicyDeletingID(normalizedPolicyID);
    setScanPolicyError('');
    setSuccessMessage('');
    const requestSequence = refreshSequenceRef.current;
    try {
      const auth = buildProductAuthContext(scope);
      await apiClient.deleteProjectScanPolicy(scope.workspaceID, projectID, normalizedPolicyID, auth);
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
	      setSuccessMessage(`Scan policy ${normalizedPolicyID} deleted.`);
	      setPolicyDeletingID('');
	      void refreshConnections(true);
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setScanPolicyError(error instanceof Error ? error.message : 'Unable to delete scan policy.');
    } finally {
      if (!isStaleRequestSequence(requestSequence)) {
        setPolicyDeletingID('');
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

      <article className="idt-app-panel">
        <div className="idt-source-onboarding-header">
          <div>
            <p className="idt-app-kicker">Automation policies</p>
            <h3>Scan policy editor</h3>
            <p>Define trigger mode, schedule cadence, and scan limits for this project.</p>
          </div>
        </div>

        {scanPolicyError ? (
          <p role="alert" className="idt-app-alert idt-app-alert-error">
            {scanPolicyError}
          </p>
        ) : null}

        <div className="idt-source-summary" aria-label="scan policy summary">
          <article>
            <span>{scanPolicies.length}</span>
            <p>Policies</p>
          </article>
          <article>
            <span>{scanPolicies.filter((item) => item.enabled).length}</span>
            <p>Enabled</p>
          </article>
          <article>
            <span>{policyForm.triggerMode}</span>
            <p>Editing mode</p>
          </article>
        </div>

        {scanPolicies.length > 0 ? (
          <div className="idt-source-diagnostics">
            {scanPolicies.map((policy) => (
              <article key={policy.policy_id}>
                <strong>{policy.name}</strong>
                <span>{policy.enabled ? 'Enabled' : 'Disabled'}</span>
                <p>
                  {formatScanTriggerModeLabel(policy.trigger_mode)} · concurrency {policy.max_concurrent_scans} · history{' '}
                  {policy.history_limit} · findings {policy.max_findings}
                </p>
                <div className="idt-source-inline-fields">
                  <button
                    type="button"
                    className="idt-btn idt-btn-ghost"
                    onClick={() =>
                      setPolicyForm({
                        policyID: policy.policy_id,
                        name: policy.name,
                        enabled: policy.enabled,
                        triggerMode: policy.trigger_mode,
                        cron: policy.cron ?? '',
                        maxConcurrentScans: String(policy.max_concurrent_scans),
                        historyLimit: String(policy.history_limit),
                        maxFindings: String(policy.max_findings)
                      })
                    }
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="idt-btn idt-btn-ghost"
                    onClick={() => {
                      void handleScanPolicyDelete(policy.policy_id);
                    }}
                    disabled={policyDeletingID === policy.policy_id}
                  >
                    {policyDeletingID === policy.policy_id ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
              </article>
            ))}
          </div>
        ) : null}

        <form className="idt-app-form" onSubmit={handleScanPolicySubmit}>
          <div className="idt-source-inline-fields">
            <label>
              Policy ID
              <input
                value={policyForm.policyID}
                onChange={(event) => setPolicyForm((current) => ({ ...current, policyID: normalizeProjectToken(event.target.value) }))}
                placeholder="default"
                required
              />
            </label>
            <label>
              Policy name
              <input
                value={policyForm.name}
                onChange={(event) => setPolicyForm((current) => ({ ...current, name: event.target.value }))}
                placeholder="Default policy"
                required
              />
            </label>
          </div>
          <div className="idt-source-inline-fields">
            <label>
              Trigger mode
              <select
                value={policyForm.triggerMode}
                onChange={(event) => setPolicyForm((current) => ({ ...current, triggerMode: event.target.value as ScanTriggerMode }))}
              >
                {SCAN_POLICY_TRIGGER_MODES.map((mode) => (
                  <option key={mode} value={mode}>
                    {formatScanTriggerModeLabel(mode)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Enabled
              <select
                value={policyForm.enabled ? 'true' : 'false'}
                onChange={(event) => setPolicyForm((current) => ({ ...current, enabled: event.target.value === 'true' }))}
              >
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
            </label>
          </div>
          {policyForm.triggerMode === 'scheduled' || policyForm.triggerMode === 'hybrid' ? (
            <label>
              Cron schedule
              <input
                value={policyForm.cron}
                onChange={(event) => setPolicyForm((current) => ({ ...current, cron: event.target.value }))}
                placeholder="0 * * * *"
                required
              />
            </label>
          ) : null}
          <div className="idt-source-inline-fields">
            <label>
              Max concurrent scans
              <input
                inputMode="numeric"
                value={policyForm.maxConcurrentScans}
                onChange={(event) => setPolicyForm((current) => ({ ...current, maxConcurrentScans: event.target.value }))}
                placeholder="1"
                required
              />
            </label>
            <label>
              History limit
              <input
                inputMode="numeric"
                value={policyForm.historyLimit}
                onChange={(event) => setPolicyForm((current) => ({ ...current, historyLimit: event.target.value }))}
                placeholder="500"
                required
              />
            </label>
            <label>
              Max findings
              <input
                inputMode="numeric"
                value={policyForm.maxFindings}
                onChange={(event) => setPolicyForm((current) => ({ ...current, maxFindings: event.target.value }))}
                placeholder="200"
                required
              />
            </label>
          </div>
          <button className="idt-btn idt-btn-primary" type="submit" disabled={policySaving}>
            {policySaving ? 'Saving policy...' : 'Save scan policy'}
          </button>
        </form>
      </article>
    </section>
  );
}

export function ProductFindingsPage() {
  return <ScopedShellPage title="Findings" description="Finding triage queue placeholder for scoped findings, filters, and ownership assignment." />;
}

export function ProductSettingsPage() {
  return <ScopedShellPage title="Settings" description="Tenant/workspace app settings, auth provider mapping, and shell preferences will render here." />;
}
