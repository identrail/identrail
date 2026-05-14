import { Component, FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  ApiError,
  apiClient,
  type AWSConnectorStartResponse,
  type AWSConnectionStatus,
  type AWSPermissionPreviewItem,
  type CurrentUserContext,
  type Finding as ApiFinding,
  type FindingLifecycleStatus,
  type GitHubConnectorStartResponse,
  type GitHubConnectionStatus,
  type KubernetesConnectionStatus,
  type ProjectRecord,
  type RepoScanRecord,
  type TrendPoint,
  type RequestAuthContext,
  type ScanPolicyRecord,
  type ScanTriggerMode,
  type WhoAmIResponse,
  type WorkspaceMemberRecord,
  type WorkspaceMemberRole,
  type WorkspaceMemberStatus
} from './api/client';
import { PermissionPreviewModal } from './components/connector/PermissionPreviewModal';
import { useMe } from './hooks/useMe';
import {
  buildRepoFindingSelectionKey,
  findRepoFindingBySelectionKey,
  groupRepoFindingsForDisplay,
  mergeUpdatedRepoFinding
} from './repoFindingDisplay';

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
const CONNECT_SOURCE_STEPS = ['Choose', 'Configure', 'Validate', 'Active'] as const;
const GITHUB_REPOSITORY_SPLIT_PATTERN = /[\n,]+/;
const AWS_ROLE_ARN_PATTERN = /^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/;
const PRODUCT_VITE_ENV = ((import.meta as unknown as { env?: Record<string, unknown> }).env ?? {}) as Record<
  string,
  unknown
>;
const FEATURE_CONNECTOR_GITHUB_V2 =
  PRODUCT_VITE_ENV.VITE_FEATURE_CONNECTOR_GITHUB_V2 === true ||
  PRODUCT_VITE_ENV.VITE_FEATURE_CONNECTOR_GITHUB_V2 === 'true';
const FEATURE_CONNECTOR_AWS =
  PRODUCT_VITE_ENV.VITE_FEATURE_CONNECTOR_AWS === true || PRODUCT_VITE_ENV.VITE_FEATURE_CONNECTOR_AWS === 'true';
const SOURCE_ORDER: SourceProvider[] = FEATURE_CONNECTOR_GITHUB_V2
  ? ['github', 'aws', 'kubernetes']
  : ['aws', 'kubernetes'];
const SCAN_POLICY_TRIGGER_MODES: ScanTriggerMode[] = ['manual', 'scheduled', 'event', 'hybrid'];
const REPO_FINDING_SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
const REPO_FINDING_TYPE_FILTERS = ['all', 'secret_exposure', 'repo_misconfiguration'] as const;
const REPO_FINDING_SORT_FIELDS = ['severity', 'created_at', 'type', 'title'] as const;
const REPO_FINDING_STATUS_FILTERS = ['all', 'open', 'ack', 'suppressed', 'resolved'] as const;

const SORT_LABEL_BY_FIELD: Record<(typeof REPO_FINDING_SORT_FIELDS)[number], string> = {
  severity: 'Risk (high → low)',
  created_at: 'Newest first',
  type: 'Finding type',
  title: 'Finding title'
};

const TREND_POINTS = 10;
function formatConfidenceScore(value: number | undefined): string {
  if (!Number.isFinite(value ?? NaN)) {
    return 'N/A';
  }
  const clamped = Math.max(0, Math.min(100, Math.round((value ?? 0) * 100)));
  return `${clamped}%`;
}

function formatDateLabel(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function toLocalDateTimeInputValue(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }
  const localTimestamp = new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60 * 1000);
  return localTimestamp.toISOString().slice(0, 16);
}

function normalizeFindingStatus(value: string | undefined): FindingLifecycleStatus {
  const normalized = normalizeValue(value ?? '').toLowerCase();
  if (normalized === 'ack' || normalized === 'suppressed' || normalized === 'resolved') {
    return normalized;
  }
  return 'open';
}

function repoFindingStatusClass(status: FindingLifecycleStatus): string {
  return `idt-repo-finding-status is-${status}`;
}

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

function formatTokenLabel(value: string): string {
  const trimmed = normalizeValue(value);
  if (!trimmed) {
    return 'Unknown';
  }
  return trimmed
    .replace(/[-_]+/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function canonicalGitHubRepositoryDisplay(value: string): string {
  const trimmed = normalizeValue(value).replace(/\/+$/g, '');
  if (!trimmed) {
    return '';
  }
  if (/^git@github\.com:/i.test(trimmed)) {
    return trimmed
      .replace(/^git@github\.com:/i, '')
      .replace(/\.git$/i, '');
  }
  if (/^https?:\/\/github\.com\//i.test(trimmed) || /^ssh:\/\/git@github\.com\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      return parsed.pathname.replace(/^\/+/, '').replace(/\/+$/g, '').replace(/\.git$/i, '');
    } catch {
      return trimmed;
    }
  }
  return trimmed.replace(/\.git$/i, '');
}

function repoFindingRepositoryValue(finding: ApiFinding, repoScansByID: Record<string, RepoScanRecord>): string {
  if (normalizeValue(finding.repository ?? '')) {
    return normalizeValue(finding.repository ?? '');
  }
  const evidenceRepository = finding.evidence?.repository;
  if (typeof evidenceRepository === 'string' && normalizeValue(evidenceRepository)) {
    return normalizeValue(evidenceRepository);
  }
  return normalizeValue(repoScansByID[finding.scan_id]?.repository ?? '');
}

function repoFindingLocationLabel(finding: ApiFinding): string {
  if (finding.file_path && finding.line_number) {
    return `${finding.file_path}:${finding.line_number}`;
  }
  if (finding.file_path) {
    return finding.file_path;
  }
  return 'Location unavailable';
}

function repoFindingSeverityClass(severity: string): string {
  const normalized = normalizeValue(severity).toLowerCase() || 'unknown';
  return `idt-repo-finding-severity is-${normalized}`;
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
    return status.health_status ?? (status.connected ? 'healthy' : 'unknown');
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
    const lifecycle = status.status;
    if (lifecycle) {
      return lifecycle.charAt(0).toUpperCase() + lifecycle.slice(1);
    }
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

export function ProductGitHubCallbackPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;
    const query = new URLSearchParams(location.search);
    const state = normalizeValue(query.get('state') ?? '');
    const setupAction = normalizeValue(query.get('setup_action') ?? '');
    const installationID = Number.parseInt(normalizeValue(query.get('installation_id') ?? ''), 10);

    const run = async () => {
      if (!state || !Number.isFinite(installationID) || installationID <= 0) {
        setError('GitHub did not return a valid installation callback.');
        return;
      }
      try {
        const response = await apiClient.completeGitHubConnector({
          state,
          installation_id: installationID,
          setup_action: setupAction || undefined
        });
        if (mounted) {
          navigate(response.redirect_path || '/app', {
            replace: true,
            state: { connector: response.connection.connector_id, connected: response.connection.connected }
          });
        }
      } catch (callbackError) {
        if (mounted) {
          const message = callbackError instanceof Error ? callbackError.message : 'Unable to complete GitHub installation.';
          setError(message);
        }
      }
    };

    void run();

    return () => {
      mounted = false;
    };
  }, [location.search, navigate]);

  if (error) {
    return (
      <section className="idt-app-shell-screen" role="alert">
        <article className="idt-app-panel idt-app-panel-error">
          <p className="idt-app-kicker">GitHub setup failed</p>
          <h1>Unable to complete GitHub</h1>
          <p>{error}</p>
          <Link className="idt-btn idt-btn-primary" to="/app">
            Return to app
          </Link>
        </article>
      </section>
    );
  }

  return <AppShellLoading message="Completing GitHub installation" />;
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
  const [selectedSource, setSelectedSource] = useState<SourceProvider>(SOURCE_ORDER[0] ?? 'aws');
  const [successMessage, setSuccessMessage] = useState('');
  const [githubStart, setGitHubStart] = useState<GitHubConnectorStartResponse | null>(null);
  const [githubAppForm, setGitHubAppForm] = useState({
    displayName: 'GitHub App'
  });
  const [githubPATForm, setGitHubPATForm] = useState({
    displayName: 'GitHub Enterprise',
    baseURL: '',
    token: '',
    repositories: ''
  });
  const [awsForm, setAWSForm] = useState({
    roleARN: '',
    externalID: '',
    region: 'us-east-1',
    displayName: '',
    sessionName: 'identrail-connector-validation',
    roleName: 'IdentrailReadOnly',
    stackName: 'identrail-readonly-connector'
  });
  const [awsCloudFormationStart, setAWSCloudFormationStart] = useState<AWSConnectorStartResponse | null>(null);
  const [awsPermissionPreview, setAWSPermissionPreview] = useState<AWSPermissionPreviewItem[]>([]);
  const [awsPreviewOpen, setAWSPreviewOpen] = useState(false);
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
      FEATURE_CONNECTOR_GITHUB_V2
        ? apiClient.getGitHubConnectorStatus(scope.workspaceID, projectID, auth)
        : Promise.resolve({ connection: undefined as unknown as GitHubConnectionStatus }),
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

    if (githubResult.status === 'fulfilled' && githubResult.value.connection) {
      nextConnections.github = githubResult.value.connection;
    } else {
      if (FEATURE_CONNECTOR_GITHUB_V2) {
        nextErrors.github =
          githubResult.status === 'rejected' && githubResult.reason instanceof Error
            ? githubResult.reason.message
            : `Unable to load ${SOURCE_PROFILES.github.name} status.`;
      }
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
    setAWSCloudFormationStart(null);
    setAWSPermissionPreview([]);
    setAWSPreviewOpen(false);
    setAWSForm((current) => ({ ...current, externalID: '' }));
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
        typeof window !== 'undefined' ? `${window.location.origin}/app/github/callback` : undefined;
      const response = await apiClient.startGitHubConnector(
        {
          workspace_id: scope.workspaceID,
          project_id: projectID,
          display_name: normalizeValue(githubAppForm.displayName) || undefined,
          redirect_uri: redirectURI
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setGitHubStart(response);
      setConnections((current) => ({ ...current, github: response.connection }));
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

  const handleGitHubPATSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting('github');
    setSuccessMessage('');
    setSourceErrors((current) => ({ ...current, github: undefined }));
    const requestSequence = refreshSequenceRef.current;
    try {
      const token = normalizeValue(githubPATForm.token);
      if (!token) {
        throw new Error('Enter a GitHub personal access token for the self-hosted fallback.');
      }
      const repositories = parseGitHubRepositories(githubPATForm.repositories);
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.upsertGitHubPATConnector(
        {
          workspace_id: scope.workspaceID,
          project_id: projectID,
          display_name: normalizeValue(githubPATForm.displayName) || undefined,
          base_url: normalizeValue(githubPATForm.baseURL) || undefined,
          token,
          selected_repositories: repositories
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setConnections((current) => ({ ...current, github: response.connection }));
      setGitHubStart(null);
      setGitHubPATForm((current) => ({ ...current, token: '' }));
      setSuccessMessage('GitHub Enterprise connector validated and saved.');
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      const message = error instanceof Error ? error.message : 'Unable to save GitHub Enterprise connector.';
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
      const payload = {
          role_arn: roleARN,
          external_id: normalizeValue(awsForm.externalID) || undefined,
          region: normalizeValue(awsForm.region) || 'us-east-1',
          display_name: normalizeValue(awsForm.displayName) || undefined,
          session_name: normalizeValue(awsForm.sessionName) || undefined
        };
      const response =
        FEATURE_CONNECTOR_AWS && awsCloudFormationStart?.connector_id
          ? await apiClient.validateAWSConnector(
              awsCloudFormationStart.connector_id,
              {
                workspace_id: scope.workspaceID,
                project_id: projectID,
                role_arn: payload.role_arn,
                external_id: payload.external_id,
                region: payload.region,
                session_name: payload.session_name
              },
              auth
            )
          : await apiClient.upsertAWSProjectConnection(scope.workspaceID, projectID, payload, auth);
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

  const handleAWSCloudFormationStart = async () => {
    if (!scope || !projectID) {
      return;
    }
    setSubmitting('aws');
    setSuccessMessage('');
    setSourceErrors((current) => ({ ...current, aws: undefined }));
    const requestSequence = refreshSequenceRef.current;
    try {
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.startAWSConnector(
        {
          workspace_id: scope.workspaceID,
          project_id: projectID,
          display_name: normalizeValue(awsForm.displayName) || undefined,
          region: normalizeValue(awsForm.region) || 'us-east-1',
          role_name: normalizeValue(awsForm.roleName) || undefined,
          stack_name: normalizeValue(awsForm.stackName) || undefined
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setAWSCloudFormationStart(response);
      setAWSPermissionPreview(response.permission_preview);
      setAWSForm((current) => ({ ...current, externalID: response.external_id }));
      setConnections((current) => ({ ...current, aws: response.connection }));
      setSuccessMessage('AWS stack launch is ready.');
      window.open(response.launch_url, '_blank', 'noopener,noreferrer');
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      const message = error instanceof Error ? error.message : 'Unable to start AWS connector setup.';
      setSourceErrors((current) => ({ ...current, aws: message }));
    } finally {
      if (!isStaleRequestSequence(requestSequence)) {
        setSubmitting('');
      }
    }
  };

  const handleAWSPoll = async () => {
    if (!scope || !projectID || !awsCloudFormationStart?.connector_id) {
      return;
    }
    setSubmitting('aws');
    setSourceErrors((current) => ({ ...current, aws: undefined }));
    const requestSequence = refreshSequenceRef.current;
    try {
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.pollAWSConnector(
        awsCloudFormationStart.connector_id,
        scope.workspaceID,
        projectID,
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setConnections((current) => ({ ...current, aws: response.connection }));
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      const message = error instanceof Error ? error.message : 'Unable to poll AWS connector setup.';
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
                    Display name
                    <input
                      value={githubAppForm.displayName}
                      onChange={(event) =>
                        setGitHubAppForm((current) => ({ ...current, displayName: event.target.value }))
                      }
                      placeholder="GitHub App"
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
                  <a className="idt-btn idt-btn-dark" href={githubStart.install_url} target="_blank" rel="noreferrer">
                    Open GitHub
                  </a>
                </article>
              ) : null}

              <form className="idt-app-form" onSubmit={handleGitHubPATSubmit}>
                <div className="idt-source-inline-fields">
                  <label>
                    Enterprise base URL
                    <input
                      value={githubPATForm.baseURL}
                      onChange={(event) => setGitHubPATForm((current) => ({ ...current, baseURL: event.target.value }))}
                      placeholder="https://github.company.com"
                    />
                  </label>
                  <label>
                    Display name
                    <input
                      value={githubPATForm.displayName}
                      onChange={(event) =>
                        setGitHubPATForm((current) => ({ ...current, displayName: event.target.value }))
                      }
                      placeholder="GitHub Enterprise"
                    />
                  </label>
                </div>
                <label>
                  Personal access token
                  <input
                    type="password"
                    value={githubPATForm.token}
                    onChange={(event) => setGitHubPATForm((current) => ({ ...current, token: event.target.value }))}
                    placeholder="GitHub Enterprise fallback token"
                    required
                  />
                </label>
                <label>
                  Repository allowlist
                  <textarea
                    value={githubPATForm.repositories}
                    onChange={(event) =>
                      setGitHubPATForm((current) => ({ ...current, repositories: event.target.value }))
                    }
                    placeholder="owner/repo, owner/security-platform"
                  />
                </label>
                <button className="idt-btn idt-btn-primary" type="submit" disabled={submitting !== ''}>
                  {submitting === 'github' ? 'Validating...' : 'Save enterprise fallback'}
                </button>
              </form>
            </div>
          ) : null}

          {selectedSource === 'aws' ? (
            <form className="idt-app-form" onSubmit={handleAWSSubmit}>
              {FEATURE_CONNECTOR_AWS ? (
                <article className="idt-source-install-card idt-aws-launch-card">
                  <div>
                    <h4>CloudFormation setup</h4>
                    <p>{awsCloudFormationStart ? 'Stack launch generated.' : 'Generate a least-privilege stack launch.'}</p>
                  </div>
                  <div className="idt-source-actions">
                    <button className="idt-btn idt-btn-dark" type="button" onClick={handleAWSCloudFormationStart} disabled={submitting !== ''}>
                      {submitting === 'aws' ? 'Preparing...' : 'Launch stack'}
                    </button>
                    {awsCloudFormationStart ? (
                      <a className="idt-btn idt-btn-dark" href={awsCloudFormationStart.launch_url} target="_blank" rel="noreferrer">
                        Open stack
                      </a>
                    ) : null}
                    {awsPermissionPreview.length > 0 ? (
                      <button className="idt-btn idt-btn-ghost" type="button" onClick={() => setAWSPreviewOpen(true)}>
                        Preview permissions
                      </button>
                    ) : null}
                    {awsCloudFormationStart ? (
                      <button className="idt-btn idt-btn-ghost" type="button" onClick={handleAWSPoll} disabled={submitting !== ''}>
                        Refresh status
                      </button>
                    ) : null}
                  </div>
                </article>
              ) : null}
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
                {FEATURE_CONNECTOR_AWS ? (
                  <>
                    <label>
                      Role name
                      <input
                        value={awsForm.roleName}
                        onChange={(event) => setAWSForm((current) => ({ ...current, roleName: event.target.value }))}
                        placeholder="IdentrailReadOnly"
                      />
                    </label>
                    <label>
                      Stack name
                      <input
                        value={awsForm.stackName}
                        onChange={(event) => setAWSForm((current) => ({ ...current, stackName: event.target.value }))}
                        placeholder="identrail-readonly-connector"
                      />
                    </label>
                  </>
                ) : null}
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
      <PermissionPreviewModal
        open={awsPreviewOpen}
        title="AWS read-only connector policy"
        items={awsPermissionPreview}
        onClose={() => setAWSPreviewOpen(false)}
      />
    </section>
  );
}

export function ProductFindingsPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);
  const { me } = useMe();

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [signalsLoading, setSignalsLoading] = useState(false);
  const [signalsRefreshing, setSignalsRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [signalError, setSignalError] = useState('');
  const [trendError, setTrendError] = useState('');
  const [repoScans, setRepoScans] = useState<RepoScanRecord[]>([]);
  const [repoFindings, setRepoFindings] = useState<ApiFinding[]>([]);
  const [trendPoints, setTrendPoints] = useState<TrendPoint[]>([]);
  const [repoScanFilter, setRepoScanFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<(typeof REPO_FINDING_SEVERITY_FILTERS)[number]>('all');
  const [typeFilter, setTypeFilter] = useState<(typeof REPO_FINDING_TYPE_FILTERS)[number]>('all');
  const [statusFilter, setStatusFilter] = useState<(typeof REPO_FINDING_STATUS_FILTERS)[number]>('all');
  const [assigneeFilter, setAssigneeFilter] = useState('');
  const [sortBy, setSortBy] = useState<(typeof REPO_FINDING_SORT_FIELDS)[number]>('severity');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [selectedFindingKey, setSelectedFindingKey] = useState('');
  const [workflowStatus, setWorkflowStatus] = useState<FindingLifecycleStatus>('open');
  const [workflowAssignee, setWorkflowAssignee] = useState('');
  const [workflowComment, setWorkflowComment] = useState('');
  const [workflowSuppressionExpiresAt, setWorkflowSuppressionExpiresAt] = useState('');
  const [workflowLoading, setWorkflowLoading] = useState(false);
  const [workflowSuccess, setWorkflowSuccess] = useState('');
  const [workflowError, setWorkflowError] = useState('');

  const requestRef = useRef(0);
  const signalRequestRef = useRef(0);

  const hasTriageAccess = Boolean(me?.role === 'owner' || me?.role === 'admin');

  const trendMaxTotal = useMemo(() => {
    const totals = trendPoints.map((point) => point.total);
    return totals.length ? Math.max(...totals) : 0;
  }, [trendPoints]);

  const repoScansByID = useMemo(
    () =>
      repoScans.reduce<Record<string, RepoScanRecord>>((acc, scan) => {
        acc[scan.id] = scan;
        return acc;
      }, {}),
    [repoScans]
  );

  const filteredFindings = useMemo(() => {
    const normalizedAssigneeFilter = normalizeValue(assigneeFilter).toLowerCase();
    return repoFindings.filter((finding) => {
      const status = normalizeFindingStatus(finding.triage?.status);
      const assignee = normalizeValue(finding.triage?.assignee ?? '').toLowerCase();
      const matchesStatus = statusFilter === 'all' || status === statusFilter;
      const matchesAssignee = !normalizedAssigneeFilter || assignee.includes(normalizedAssigneeFilter);

      return matchesStatus && matchesAssignee;
    });
  }, [repoFindings, statusFilter, assigneeFilter]);

  const findingGroups = useMemo(
    () => groupRepoFindingsForDisplay(filteredFindings, sortBy, sortOrder),
    [filteredFindings, sortBy, sortOrder]
  );

  const selectedFinding = useMemo(
    () => findRepoFindingBySelectionKey(filteredFindings, selectedFindingKey) ?? filteredFindings[0] ?? null,
    [filteredFindings, selectedFindingKey]
  );

  const linkedFindingCount = useMemo(
    () => filteredFindings.filter((finding) => normalizeValue(finding.source_url ?? '')).length,
    [filteredFindings]
  );

  const criticalFindingCount = useMemo(
    () => filteredFindings.filter((finding) => normalizeValue(finding.severity).toLowerCase() === 'critical').length,
    [filteredFindings]
  );

  const activeScanCount = useMemo(
    () => repoScans.filter((scan) => normalizeValue(scan.status).toLowerCase() === 'succeeded').length,
    [repoScans]
  );

  const openFindingCount = useMemo(
    () => filteredFindings.filter((finding) => normalizeFindingStatus(finding.triage?.status) === 'open').length,
    [filteredFindings]
  );

  const averageConfidence = useMemo(() => {
    const findingsWithConfidence = filteredFindings.filter((finding) => Number.isFinite(finding.confidence_score ?? NaN));
    if (findingsWithConfidence.length === 0) {
      return 'N/A';
    }
    const sum = findingsWithConfidence.reduce((acc, finding) => acc + (finding.confidence_score ?? 0), 0);
    return formatConfidenceScore(sum / findingsWithConfidence.length);
  }, [filteredFindings]);

  const loadRepoFindings = async (targetScope: ProductSession, mode: 'initial' | 'refresh') => {
    const requestID = ++requestRef.current;
    if (mode === 'initial') {
      setLoading(true);
    } else {
      setRefreshing(true);
    }
    setError('');
    try {
      const auth = buildProductAuthContext(targetScope);
      const [repoScanResponse, repoFindingResponse] = await Promise.all([
        apiClient.listRepoScans({ limit: 50 }, auth),
        apiClient.listRepoFindings(
          {
            limit: 100,
            repo_scan_id: normalizeValue(repoScanFilter) || undefined,
            severity: severityFilter !== 'all' ? severityFilter : undefined,
            type: typeFilter !== 'all' ? typeFilter : undefined,
            lifecycle_status: statusFilter !== 'all' ? statusFilter : undefined,
            assignee: normalizeValue(assigneeFilter) || undefined,
            sort_by: sortBy,
            sort_order: sortOrder
          },
          auth
        )
      ]);
      if (requestID !== requestRef.current) {
        return;
      }
      setRepoScans(repoScanResponse.items);
      setRepoFindings(repoFindingResponse.items);
    } catch (requestError) {
      if (requestID !== requestRef.current) {
        return;
      }
      const message = requestError instanceof Error ? requestError.message : 'Failed to load repository findings.';
      setError(message);
    } finally {
      if (requestID === requestRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  };

  const loadTrendSignals = async (targetScope: ProductSession, mode: 'initial' | 'refresh') => {
    const requestID = ++signalRequestRef.current;
    if (mode === 'initial') {
      setSignalsLoading(true);
    } else {
      setSignalsRefreshing(true);
    }
    setSignalError('');
    setTrendError('');
    try {
      const auth = buildProductAuthContext(targetScope);
      const trendResponse = await apiClient.getRepoFindingsTrends(
        {
          points: TREND_POINTS,
          severity: severityFilter !== 'all' ? severityFilter : undefined,
          type: typeFilter !== 'all' ? typeFilter : undefined
        },
        auth
      );
      if (requestID !== signalRequestRef.current) {
        return;
      }
      setTrendPoints(trendResponse.items);
    } catch (requestError) {
      if (requestID !== signalRequestRef.current) {
        return;
      }
      const message = requestError instanceof Error ? requestError.message : 'Failed to load finding trend metrics.';
      setTrendError(message);
    } finally {
      if (requestID === signalRequestRef.current) {
        setSignalsLoading(false);
        setSignalsRefreshing(false);
      }
    }
  };

  const handleApplyWorkflow = async () => {
    if (!scope || !selectedFinding || workflowLoading) {
      return;
    }

    const nextStatus = normalizeFindingStatus(workflowStatus);
    const nextAssignee = normalizeValue(workflowAssignee);
    const currentStatus = normalizeFindingStatus(selectedFinding.triage?.status);
    const currentAssignee = normalizeValue(selectedFinding.triage?.assignee ?? '');
    const trackingSuppression = nextStatus === 'suppressed';
    const currentSuppression = normalizeValue(toLocalDateTimeInputValue(selectedFinding.triage?.suppression_expires_at ?? ''));
    const nextSuppression = normalizeValue(workflowSuppressionExpiresAt);
    const hasChanges =
      nextStatus !== currentStatus ||
      nextAssignee !== currentAssignee ||
      normalizeValue(workflowComment).length > 0 ||
      (trackingSuppression && nextSuppression !== currentSuppression);

    if (!hasChanges) {
      setWorkflowError('Make a workflow change before saving.');
      return;
    }

    setWorkflowLoading(true);
    setWorkflowError('');
    setWorkflowSuccess('');
    try {
      const auth = buildProductAuthContext(scope);
      const request: {
        status?: FindingLifecycleStatus;
        assignee?: string;
        suppression_expires_at?: string;
        comment?: string;
      } = {};
      if (trackingSuppression && !nextSuppression) {
        setWorkflowError('Suppression requires an expiry date/time.');
        setWorkflowLoading(false);
        return;
      }
      if (trackingSuppression && nextSuppression) {
        const parsedExpiry = new Date(nextSuppression);
        if (Number.isNaN(parsedExpiry.getTime())) {
          setWorkflowError('Suppression expiry must be a valid date/time.');
          setWorkflowLoading(false);
          return;
        }
        if (parsedExpiry.getTime() <= Date.now()) {
          setWorkflowError('Suppression expiry must be set in the future.');
          setWorkflowLoading(false);
          return;
        }
        request.suppression_expires_at = parsedExpiry.toISOString();
      }
      if (nextStatus !== currentStatus) {
        request.status = nextStatus;
      }
      if (nextAssignee !== currentAssignee) {
        request.assignee = nextAssignee;
      }
      const trimmedComment = normalizeValue(workflowComment);
      if (trimmedComment) {
        request.comment = trimmedComment;
      }
      const response = await apiClient.triageFinding(selectedFinding.id, request, selectedFinding.scan_id, auth);
      setRepoFindings((current) => mergeUpdatedRepoFinding(current, response.finding));
      setWorkflowSuccess('Workflow state updated successfully.');
      setWorkflowComment('');
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : 'Failed to update workflow state.';
      setWorkflowError(message);
    } finally {
      setWorkflowLoading(false);
      setTimeout(() => setWorkflowSuccess(''), 2200);
    }
  };

  useEffect(() => {
    if (!scope) {
      setLoading(false);
      setError('Workspace route context is missing.');
      return;
    }
    void loadRepoFindings(scope, 'initial');
    void loadTrendSignals(scope, 'initial');
    return () => {
      requestRef.current += 1;
      signalRequestRef.current += 1;
    };
  }, [
    scope?.tenantID,
    scope?.workspaceID,
    repoScanFilter,
    severityFilter,
    typeFilter,
    statusFilter,
    assigneeFilter,
    sortBy,
    sortOrder
  ]);

  useEffect(() => {
    if (!selectedFinding) {
      setWorkflowStatus('open');
      setWorkflowAssignee('');
      setWorkflowComment('');
      setWorkflowSuppressionExpiresAt('');
      return;
    }

    setWorkflowStatus(normalizeFindingStatus(selectedFinding.triage?.status));
    setWorkflowAssignee(selectedFinding.triage?.assignee ?? '');
    setWorkflowComment('');
    setWorkflowSuppressionExpiresAt(
      selectedFinding.triage?.suppression_expires_at ? toLocalDateTimeInputValue(selectedFinding.triage.suppression_expires_at) : ''
    );
  }, [
    selectedFinding?.id,
    selectedFinding?.scan_id,
    selectedFinding?.triage?.status,
    selectedFinding?.triage?.assignee,
    selectedFinding?.triage?.suppression_expires_at
  ]);

  useEffect(() => {
    if (filteredFindings.length === 0) {
      if (selectedFindingKey) {
        setSelectedFindingKey('');
      }
      return;
    }
    if (!findRepoFindingBySelectionKey(filteredFindings, selectedFindingKey)) {
      setSelectedFindingKey(buildRepoFindingSelectionKey(filteredFindings[0]));
    }
  }, [filteredFindings, selectedFindingKey]);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error">
        <p className="idt-app-kicker">Findings</p>
        <h2>Repository findings</h2>
        <p>Workspace route context is missing.</p>
      </section>
    );
  }

  if (loading) {
    return <AppShellLoading message="Loading repository findings" />;
  }

  const handleRefresh = () => {
    void loadRepoFindings(scope, 'refresh');
    void loadTrendSignals(scope, 'refresh');
  };

  const totalTrendItems = trendPoints.reduce((acc, point) => acc + point.total, 0);
  const trendRows = trendPoints.map((point, index) => {
    const bySeverity = point.by_severity ?? ({} as Record<string, number>);
    const severityValues = {
      critical: bySeverity.critical ?? 0,
      high: bySeverity.high ?? 0,
      medium: bySeverity.medium ?? 0,
      low: bySeverity.low ?? 0,
      info: bySeverity.info ?? 0
    };
    const percentage = trendMaxTotal > 0 ? Math.round((point.total / trendMaxTotal) * 100) : 0;
    const startedAt = new Date(point.started_at);
    const pointLabel =
      Number.isNaN(startedAt.getTime()) ?
      'Unknown scan'
      : startedAt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    return { ...severityValues, key: `${point.started_at}-${index}`, percentage, label: pointLabel, total: point.total };
  });

  const trendDisplayLoading = signalsLoading;

  return (
    <section className="idt-app-panel">
      <div className="idt-repo-findings-header">
        <div>
          <p className="idt-app-kicker">Repository Exposure</p>
          <h2>Findings</h2>
          <p>Review repository findings and jump directly to the exact GitHub line when link metadata is available.</p>
        </div>
        <div className="idt-inline-actions">
          <button className="idt-btn idt-btn-ghost" type="button" onClick={handleRefresh} disabled={refreshing}>
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
          <button
            className="idt-btn idt-btn-ghost"
            type="button"
            onClick={handleRefresh}
            disabled={signalsRefreshing || signalsLoading}
            style={{ marginLeft: '0.45rem' }}
          >
            {signalsRefreshing ? 'Loading signals...' : 'Reload trend'}
          </button>
          {selectedFinding?.source_url ? (
            <a className="idt-btn idt-btn-primary" href={selectedFinding.source_url} target="_blank" rel="noreferrer">
              Open in GitHub
            </a>
          ) : null}
        </div>
      </div>

      {error ? <div className="idt-app-alert idt-app-alert-error">{error}</div> : null}
      {signalError ? <div className="idt-app-alert idt-app-alert-error">{signalError}</div> : null}
      {trendError ? <div className="idt-app-alert idt-app-alert-error">{trendError}</div> : null}

      <div className="idt-repo-finding-stats" aria-label="Repository finding summary">
        <article className="idt-repo-finding-stat">
          <span>Total repo findings</span>
          <strong>{filteredFindings.length}</strong>
        </article>
        <article className="idt-repo-finding-stat">
          <span>GitHub-linked findings</span>
          <strong>{linkedFindingCount}</strong>
        </article>
        <article className="idt-repo-finding-stat">
          <span>Open findings</span>
          <strong>{openFindingCount}</strong>
        </article>
        <article className="idt-repo-finding-stat">
          <span>Critical findings</span>
          <strong>{criticalFindingCount}</strong>
        </article>
        <article className="idt-repo-finding-stat">
          <span>Avg confidence</span>
          <strong>{averageConfidence}</strong>
        </article>
        <article className="idt-repo-finding-stat">
          <span>Completed repo scans</span>
          <strong>{activeScanCount}</strong>
        </article>
      </div>

      <div className="idt-repo-finding-trend">
        <div className="idt-repo-finding-trend-head">
          <h3>Finding trend</h3>
          {trendDisplayLoading ? <span className="idt-app-alert idt-app-alert-success">Loading trend</span> : null}
          <span className="idt-repo-finding-trend-subtitle">{totalTrendItems > 0 ? `${totalTrendItems} total events in window` : 'No trend items yet'}</span>
        </div>
        <div className="idt-repo-finding-trend-rows">
          {trendRows.length === 0 ? (
            <AppShellEmptyState
              title="Trend unavailable"
              body="Run a scan so finding trend snapshots can appear with severity distribution over time."
            />
          ) : (
            trendRows.map((row) => (
              <article key={row.key} className="idt-repo-finding-trend-row">
                <div className="idt-repo-finding-trend-meta">
                  <span>{row.label}</span>
                  <strong>{row.total}</strong>
                </div>
                <div className="idt-repo-finding-trend-bar-track" role="img" aria-label={`Trend point ${row.label}`}>
                  <div className="idt-repo-finding-trend-bar" style={{ width: `${row.percentage}%` }} />
                </div>
                <p>
                  {`Critical ${row.critical} / High ${row.high} / Medium ${row.medium} / Low ${row.low} / Info ${row.info}`}
                </p>
              </article>
            ))
          )}
        </div>
      </div>

      <div className="idt-repo-finding-filters">
        <label>
          Repository scan
          <select value={repoScanFilter} onChange={(event) => setRepoScanFilter(event.target.value)}>
            <option value="">All repository scans</option>
            {repoScans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {canonicalGitHubRepositoryDisplay(scan.repository)} · {formatTokenLabel(scan.status)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Severity
          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value as (typeof REPO_FINDING_SEVERITY_FILTERS)[number])}
          >
            {REPO_FINDING_SEVERITY_FILTERS.map((value) => (
              <option key={value} value={value}>
                {value === 'all' ? 'All severities' : formatTokenLabel(value)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Type
          <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value as (typeof REPO_FINDING_TYPE_FILTERS)[number])}>
            {REPO_FINDING_TYPE_FILTERS.map((value) => (
              <option key={value} value={value}>
                {value === 'all' ? 'All finding types' : formatTokenLabel(value)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort by
          <select value={sortBy} onChange={(event) => setSortBy(event.target.value as (typeof REPO_FINDING_SORT_FIELDS)[number])}>
            {REPO_FINDING_SORT_FIELDS.map((value) => (
              <option key={value} value={value}>
                {SORT_LABEL_BY_FIELD[value]}
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort order
          <select value={sortOrder} onChange={(event) => setSortOrder(event.target.value as 'asc' | 'desc')}>
            <option value="asc">Ascending</option>
            <option value="desc">Descending</option>
          </select>
        </label>
        <label>
          Lifecycle status
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as (typeof REPO_FINDING_STATUS_FILTERS)[number])}>
            {REPO_FINDING_STATUS_FILTERS.map((value) => (
              <option key={value} value={value}>
                {formatTokenLabel(value)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Assignee
          <input
            type="text"
            placeholder="Filter by assignee"
            value={assigneeFilter}
            onChange={(event) => setAssigneeFilter(event.target.value)}
          />
        </label>
      </div>

      <div className="idt-repo-finding-layout">
        <div className="idt-repo-finding-list">
          <div className="idt-repo-finding-list-header">
            <h3>Repository findings</h3>
            <p>{filteredFindings.length ? `${filteredFindings.length} findings in scope` : 'No findings match the current filters.'}</p>
          </div>
          {findingGroups.length === 0 ? (
            <AppShellEmptyState
              title="No repository findings"
              body="Run a repository exposure scan or loosen the current filters to inspect GitHub-linked findings."
            />
          ) : (
            <div>
              {findingGroups.map((group) => {
                const items = (
                  <div className="idt-repo-finding-items" role="list">
                    {group.findings.map((finding) => {
                      const repositoryValue = repoFindingRepositoryValue(finding, repoScansByID);
                      const repositoryLabel = canonicalGitHubRepositoryDisplay(repositoryValue) || 'Repository unavailable';
                      const selectionKey = buildRepoFindingSelectionKey(finding);
                      const isSelected = selectedFindingKey === selectionKey;
                      const lifecycle = normalizeFindingStatus(finding.triage?.status);
                      return (
                        <button
                          key={selectionKey}
                          type="button"
                          role="listitem"
                          className={`idt-repo-finding-row${isSelected ? ' is-selected' : ''}`}
                          onClick={() => setSelectedFindingKey(selectionKey)}
                        >
                          <div className="idt-repo-finding-row-top">
                            <strong>{finding.title}</strong>
                            <span className={repoFindingSeverityClass(finding.severity)}>{formatTokenLabel(finding.severity)}</span>
                          </div>
                          <p>{finding.human_summary}</p>
                          <div className="idt-repo-finding-row-meta">
                            <span>{repositoryLabel}</span>
                            <span>{repoFindingLocationLabel(finding)}</span>
                            <span>{formatTokenLabel(finding.type)}</span>
                            <span>{`Confidence ${formatConfidenceScore(finding.confidence_score)}`}</span>
                          </div>
                          <div className="idt-repo-finding-row-meta">
                            <span className={repoFindingStatusClass(lifecycle)}>{formatTokenLabel(lifecycle)}</span>
                            <span>{`Assignee ${finding.triage?.assignee || 'Unassigned'}`}</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                );

                if (!group.label) {
                  return <div key={group.key}>{items}</div>;
                }

                return (
                  <section className="idt-repo-finding-group" key={group.key}>
                    <h4>
                      {formatTokenLabel(group.label)} · {group.findings.length}
                    </h4>
                    {items}
                  </section>
                );
              })}
            </div>
          )}
        </div>

        <aside className="idt-repo-finding-detail">
          {selectedFinding ? (
            <>
              <div className="idt-repo-finding-detail-copy">
                <p className="idt-app-kicker">Finding detail</p>
                <h3>{selectedFinding.title}</h3>
                <p>{selectedFinding.human_summary}</p>
              </div>

              <dl className="idt-repo-finding-facts">
                <div>
                  <dt>Repository</dt>
                  <dd>{canonicalGitHubRepositoryDisplay(repoFindingRepositoryValue(selectedFinding, repoScansByID)) || 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Confidence</dt>
                  <dd>{formatConfidenceScore(selectedFinding.confidence_score)}</dd>
                </div>
                <div>
                  <dt>Location</dt>
                  <dd>{repoFindingLocationLabel(selectedFinding)}</dd>
                </div>
                <div>
                  <dt>Commit</dt>
                  <dd>{selectedFinding.commit || 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Lifecycle status</dt>
                  <dd>{formatTokenLabel(normalizeFindingStatus(selectedFinding.triage?.status))}</dd>
                </div>
                <div>
                  <dt>Assignee</dt>
                  <dd>{selectedFinding.triage?.assignee || 'Unassigned'}</dd>
                </div>
                <div>
                  <dt>Detector</dt>
                  <dd>{selectedFinding.detector ? formatTokenLabel(selectedFinding.detector) : 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Last triage update</dt>
                  <dd>{selectedFinding.triage?.updated_at ? formatDateLabel(selectedFinding.triage.updated_at) : 'Never'}</dd>
                </div>
              </dl>

              {selectedFinding.source_url ? (
                <a className="idt-repo-finding-link" href={selectedFinding.source_url} target="_blank" rel="noreferrer">
                  {selectedFinding.source_url}
                </a>
              ) : (
                <div className="idt-app-alert">GitHub line link unavailable for this finding. Rescan the repository to refresh line-link metadata.</div>
              )}

              {selectedFinding.line_snippet ? (
                <div className="idt-repo-finding-code">
                  <span>Evidence line</span>
                  <pre>
                    <code>{selectedFinding.line_snippet}</code>
                  </pre>
                </div>
              ) : null}

              <div className="idt-repo-finding-remediation">
                <h4>Remediation</h4>
                <p>{selectedFinding.remediation}</p>
              </div>

              <div className="idt-repo-finding-triage-form">
                <h4>Workflow controls</h4>
                {workflowError ? <div className="idt-app-alert idt-app-alert-error">{workflowError}</div> : null}
                {workflowSuccess ? <div className="idt-app-alert idt-app-alert-success">{workflowSuccess}</div> : null}
                <label>
                  Status
                  <select
                    value={workflowStatus}
                    onChange={(event) => {
                      const nextStatus = event.target.value as FindingLifecycleStatus;
                      setWorkflowStatus(nextStatus);
                      if (nextStatus !== 'suppressed') {
                        setWorkflowSuppressionExpiresAt('');
                      } else if (!workflowSuppressionExpiresAt && selectedFinding?.triage?.suppression_expires_at) {
                        setWorkflowSuppressionExpiresAt(
                          toLocalDateTimeInputValue(selectedFinding.triage.suppression_expires_at)
                        );
                      }
                    }}
                    disabled={workflowLoading || !hasTriageAccess}
                  >
                    {REPO_FINDING_STATUS_FILTERS.filter((status) => status !== 'all').map((status) => (
                      <option key={status} value={status}>
                        {formatTokenLabel(status)}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Suppression expiry
                  <input
                    type="datetime-local"
                    value={workflowSuppressionExpiresAt}
                    onChange={(event) => setWorkflowSuppressionExpiresAt(event.target.value)}
                    min={toLocalDateTimeInputValue(new Date().toISOString())}
                    disabled={workflowLoading || !hasTriageAccess || workflowStatus !== 'suppressed'}
                    placeholder="YYYY-MM-DDThh:mm"
                  />
                  <span className="idt-app-field-hint">
                    Required when setting status to <strong>suppressed</strong>, ignored otherwise.
                  </span>
                </label>
                <label>
                  Assignee
                  <input
                    type="text"
                    value={workflowAssignee}
                    onChange={(event) => setWorkflowAssignee(event.target.value)}
                    disabled={workflowLoading || !hasTriageAccess}
                    placeholder="analyst handle"
                  />
                </label>
                <label>
                  Comment
                  <textarea
                    rows={3}
                    value={workflowComment}
                    onChange={(event) => setWorkflowComment(event.target.value)}
                    disabled={workflowLoading || !hasTriageAccess}
                    placeholder="Optional workflow comment"
                    maxLength={500}
                  />
                </label>
                <button
                  type="button"
                  className="idt-btn idt-btn-primary"
                  onClick={handleApplyWorkflow}
                  disabled={workflowLoading || !hasTriageAccess}
                >
                  {workflowLoading ? 'Saving...' : 'Apply workflow'}
                </button>
              </div>
            </>
          ) : (
            <AppShellEmptyState
              title="Select a finding"
              body="Choose one repository finding to inspect commit, detector, and GitHub line-link context."
            />
          )}
        </aside>
      </div>
    </section>
  );
}

export function ProductSettingsPage() {
  return <ScopedShellPage title="Settings" description="Tenant/workspace app settings, auth provider mapping, and shell preferences will render here." />;
}
