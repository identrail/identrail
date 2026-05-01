import { Component, FormEvent, ReactNode, useEffect, useMemo, useState } from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate, useParams } from 'react-router-dom';

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

const PRODUCT_SESSION_STORAGE_KEY = 'identrail-product-session';

function normalizeValue(value: string): string {
  return value.trim();
}

function readProductSession(): ProductSession | null {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    const raw = window.localStorage.getItem(PRODUCT_SESSION_STORAGE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as Partial<ProductSession>;
    const tenantID = normalizeValue(parsed.tenantID ?? '');
    const workspaceID = normalizeValue(parsed.workspaceID ?? '');
    if (!tenantID || !workspaceID) {
      return null;
    }
    return {
      tenantID,
      workspaceID,
      projectID: normalizeValue(parsed.projectID ?? '') || undefined
    };
  } catch {
    return null;
  }
}

function saveProductSession(session: ProductSession) {
  if (typeof window === 'undefined') {
    return;
  }
  window.localStorage.setItem(PRODUCT_SESSION_STORAGE_KEY, JSON.stringify(session));
}

function clearProductSession() {
  if (typeof window === 'undefined') {
    return;
  }
  window.localStorage.removeItem(PRODUCT_SESSION_STORAGE_KEY);
}

function buildTenantWorkspacePath(tenantID: string, workspaceID: string): string {
  return `/app/${encodeURIComponent(tenantID)}/${encodeURIComponent(workspaceID)}`;
}

function buildScopedPath(scope: ProductSession, suffix = ''): string {
  const base = buildTenantWorkspacePath(scope.tenantID, scope.workspaceID);
  return suffix ? `${base}/${suffix}` : base;
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
  const session = readProductSession();

  if (!session) {
    const next = `${location.pathname}${location.search}`;
    return <Navigate to={`/app/login?next=${encodeURIComponent(next)}`} replace />;
  }

  return <>{children}</>;
}

export function ProductLoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const query = new URLSearchParams(location.search);
  const nextPath = normalizeValue(query.get('next') ?? '');
  const existing = useMemo(() => readProductSession(), []);

  const [tenantID, setTenantID] = useState(existing?.tenantID ?? 'default');
  const [workspaceID, setWorkspaceID] = useState(existing?.workspaceID ?? 'default');
  const [projectID, setProjectID] = useState(existing?.projectID ?? '');

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
      projectID: normalizeValue(projectID) || undefined
    };
    saveProductSession(session);

    if (nextPath.startsWith('/app/')) {
      navigate(nextPath, { replace: true });
      return;
    }

    navigate(buildScopedPath(session), { replace: true });
  };

  return (
    <section className="idt-app-shell-screen">
      <article className="idt-app-panel">
        <p className="idt-app-kicker">Product access</p>
        <h1>Sign in to the Identrail app shell</h1>
        <p>Set your tenant and workspace scope to enter the authenticated app route boundary.</p>

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
          <button className="idt-btn idt-btn-primary" type="submit">
            Continue to app
          </button>
        </form>
      </article>
    </section>
  );
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
                clearProductSession();
                navigate('/app/login', { replace: true });
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
      description={`Entry view for tenant ${scope?.tenantID ?? 'unknown'} and workspace ${scope?.workspaceID ?? 'unknown'}.`}
      actionLabel="Open findings"
      actionTo={`/app/${encodeURIComponent(scope?.tenantID ?? 'default')}/${encodeURIComponent(scope?.workspaceID ?? 'default')}/findings`}
    />
  );
}

export function ProductWorkspacesPage() {
  return <ScopedShellPage title="Workspaces" description="Workspace lifecycle, membership, and scope boundaries will be managed from this route group." />;
}

export function ProductProjectsPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);
  return (
    <ScopedShellPage
      title="Projects"
      description="Project-level onboarding and scan boundaries live here."
      actionLabel="View placeholder project"
      actionTo={`/app/${encodeURIComponent(scope?.tenantID ?? 'default')}/${encodeURIComponent(scope?.workspaceID ?? 'default')}/projects/${encodeURIComponent(scope?.projectID ?? 'sample-project')}`}
    />
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
