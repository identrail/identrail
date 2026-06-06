import { ChangeEvent, Component, FormEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  CSSProperties,
  KeyboardEvent as ReactKeyboardEvent,
  MutableRefObject,
  PointerEvent as ReactPointerEvent
} from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  BarChart3,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  ExternalLink,
  FolderKanban,
  HelpCircle,
  LayoutDashboard,
  LogOut,
  Pencil,
  Search,
  Settings as SettingsIcon
} from 'lucide-react';
import {
  ApiError,
  apiClient,
  buildAPIURL,
  type AccountDeletionWorkspace,
  type AuthConfigResponse,
  type AWSCapabilityPermissionTier,
  type AWSConnectorStartResponse,
  type AWSConnectionStatus,
  type AWSCodeBuildServiceRoleInventoryResult,
  type AWSCodeBuildServiceRoleRecord,
  type AWSCodePipelineDeploymentRoleInventoryResult,
  type AWSCodePipelineDeploymentRoleRecord,
  type AWSStepFunctionsStateMachineRoleInventoryResult,
  type AWSStepFunctionsStateMachineRoleRecord,
  type AWSEC2InstanceProfileInventoryResult,
  type AWSEC2InstanceProfileRecord,
  type AWSEKSWorkloadIdentityInventoryResult,
  type AWSEKSWorkloadIdentityRecord,
  type AWSECSTaskRoleInventoryResult,
  type AWSECSTaskRoleRecord,
  type AWSLambdaExecutionRoleInventoryResult,
  type AWSLambdaExecutionRoleRecord,
  type AWSPlatformBaselineResult,
  type AWSPlatformDependencyIndexResult,
  type AWSPlatformValidationHarnessResult,
  type AWSServiceCollectorContractResult,
  type AWSPermissionPreviewItem,
  type CurrentUserContext,
  type ExecutiveReport,
  type Finding as ApiFinding,
  type FindingLifecycleStatus,
  type GitHubConnectorStartResponse,
  type GitHubConnectionStatus,
  type GitHubOrganizationPosture,
  type GitHubRepositoryPosture,
  type GitHubRepositoryPostureCheck,
  type KubernetesConnectorStartResponse,
  type KubernetesConnectionStatus,
  type ProjectRecord,
  type RepoFindingRemediationPublishResponse,
  type RepoFindingRemediationPreview,
  type RepoFindingsSummary,
  type RepoFindingLifecycleStatus,
  type RepoRiskGraph,
  type RepoRiskGraphFindingScore,
  type RepoScanRequest,
  type RepoScanRecord,
  type TrendPoint,
  type RequestAuthContext,
  type ScanPolicyRecord,
  type ScanTriggerMode,
  type SessionListItem,
  type WhoAmIResponse,
  type WorkspaceDeleteResponse,
  type WorkspaceMemberRecord,
  type WorkspaceMemberRole,
  type WorkspaceMemberStatus,
  type WorkspaceRecord,
  type WorkspaceSoleOwnerAffectedMember
} from './api/client';
import { SessionsList } from './components/auth/SessionsList';
import { PermissionPreviewModal } from './components/connector/PermissionPreviewModal';
import { ConfirmDestructiveModal, DangerZone, DangerZoneRow } from './components/settings/DangerZone';
import {
  DomainDetailPanel,
  DomainCoverageCard,
  DomainDataTable,
  DomainEmptyState,
  DomainErrorState,
  DomainFilterBar,
  DomainKpiStrip,
  DomainLoadingState,
  DomainLogoMark,
  DomainLogoStack,
  DomainPageShell,
  DomainStatusBadge,
  DomainStatusPanel,
  DomainTimeline,
  type DomainTimelineEntry
} from './components/app/DomainFoundation';
import { getDomainAsset, type DomainAssetKey } from './design/domainAssets';
import { clearMeCache, primeMeCache, useMe } from './hooks/useMe';
import { isFeatureAvailable, type BackendFeatures, useBackendFeatures } from './hooks/useBackendFeatures';
import {
  FEATURE_ONBOARDING_CONNECTOR_AWS as FEATURE_CONNECTOR_AWS,
  FEATURE_ONBOARDING_CONNECTOR_GITHUB as FEATURE_CONNECTOR_GITHUB_V2,
  FEATURE_ONBOARDING_CONNECTOR_K8S as FEATURE_CONNECTOR_K8S,
  FEATURE_ONBOARDING_WIZARD
} from './pages/onboarding/onboardingUtils';
import { OnboardingUnavailableNotice, useOnboardingAvailable } from './components/onboarding/OnboardingAvailability';
import {
  buildRepoFindingSelectionKey,
  findRepoFindingBySelectionKey,
  groupRepoFindingsByRepositoryDateSeverity,
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

type SourceProvider = DomainAssetKey;

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

type RepoFindingRequestFilters = {
  repo_scan_id?: string;
  severity?: string;
  type?: string;
  source?: string;
  assignee?: string;
  min_confidence?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  lifecycle_status?: FindingLifecycleStatus;
};

type SourceAvailability = {
  visible: boolean;
  available: boolean;
  unavailableMessage?: string;
};

type OverviewDomainState = 'connected' | 'degraded' | 'not_connected' | 'no_data' | 'shell';

const OVERVIEW_DOMAIN_STATE_LABELS: Record<OverviewDomainState, string> = {
  connected: 'Connected',
  degraded: 'Needs review',
  not_connected: 'Not connected',
  no_data: 'Pending',
  shell: 'Unavailable'
};

type OverviewSourceConnection = AWSConnectionStatus | KubernetesConnectionStatus;

type OverviewConnectionRollup = {
  checkedCount: number;
  connectedCount: number;
  degradedCount: number;
};

type OverviewConnectionRollups = {
  aws: OverviewConnectionRollup;
  kubernetes: OverviewConnectionRollup;
};

function normalizeValue(value: unknown): string {
  if (typeof value === 'string') {
    return value.trim();
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value).trim();
  }
  return '';
}

function formatScopeDisplay(value: unknown): string {
  const normalized = normalizeValue(value);
  if (normalized.length <= 28) {
    return normalized;
  }
  return `${normalized.slice(0, 14)}...${normalized.slice(-8)}`;
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

function normalizeSourceProvider(value: unknown): SourceProvider | null {
  const normalized = normalizeValue(value);
  if (normalized === 'aws' || normalized === 'github' || normalized === 'kubernetes') {
    return normalized;
  }
  return null;
}

function appendSourceQuery(path: string, provider: SourceProvider | null): string {
  return provider ? `${path}${path.includes('?') ? '&' : '?'}source=${encodeURIComponent(provider)}` : path;
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
    name: getDomainAsset('github').label,
    eyebrow: 'Repositories and workflows',
    summary: 'Install Identrail on selected repositories so scans can read repository, workflow, and review signals.',
    primarySignal: 'Repository, workflow, and pull request signals',
    requiredAccess: 'GitHub App with selected repository access'
  },
  aws: {
    provider: 'aws',
    name: getDomainAsset('aws').label,
    eyebrow: 'Cloud IAM identity',
    summary: 'Connect a read-only IAM role so Identrail can inspect roles, trust policies, and account context.',
    primarySignal: 'IAM roles, trust policies, and account context',
    requiredAccess: 'Read-only IAM role ARN'
  },
  kubernetes: {
    provider: 'kubernetes',
    name: getDomainAsset('kubernetes').label,
    eyebrow: 'Cluster identity',
    summary: 'Enroll a read-only agent or kubeconfig fallback for service account and RBAC signals.',
    primarySignal: 'Service accounts, RBAC bindings, and pods',
    requiredAccess: 'Read-only ClusterRole through the Identrail agent'
  }
};
const GITHUB_REPOSITORY_SPLIT_PATTERN = /[\n,]+/;
const AWS_ROLE_ARN_PATTERN = /^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/;
const SOURCE_ORDER: SourceProvider[] = [
  ...(FEATURE_CONNECTOR_GITHUB_V2 ? (['github'] as SourceProvider[]) : []),
  'aws',
  ...(FEATURE_CONNECTOR_K8S ? (['kubernetes'] as SourceProvider[]) : [])
];
const DOMAIN_NAV_ORDER: SourceProvider[] = ['aws', 'github', 'kubernetes'];
const SHOULD_LOAD_CONNECTOR_BACKEND_FEATURES = FEATURE_CONNECTOR_GITHUB_V2 || FEATURE_CONNECTOR_K8S;
const SOURCE_STACK: SourceProvider[] = [...SOURCE_ORDER];
const SCAN_POLICY_TRIGGER_MODES: ScanTriggerMode[] = ['manual', 'scheduled', 'event', 'hybrid'];
const REPO_FINDING_SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
const REPO_FINDING_TYPE_FILTERS = ['all', 'secret_exposure', 'repo_misconfiguration'] as const;
const REPO_FINDING_SORT_FIELDS = ['severity', 'created_at', 'type', 'title'] as const;
const REPO_FINDING_STATUS_FILTERS = ['all', 'open', 'ack', 'suppressed', 'resolved'] as const;
const ENVIRONMENT_QUERY_PARAM = 'environment';
const OVERVIEW_FINDING_LIMIT = 50;
const OVERVIEW_RISK_DISPLAY_LIMIT = 8;
const OVERVIEW_SCAN_LIMIT = 5;
const OVERVIEW_PROJECT_PAGE_LIMIT = 100;
const ENVIRONMENT_SELECTOR_LIMIT = 50;
const AI_RISKS_REPO_FINDINGS_PAGE_LIMIT = 100;
const EXECUTIVE_REPORT_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

type ProductDomainRouteID =
  | 'overview'
  | 'connect'
  | 'accounts'
  | 'identities'
  | 'agents'
  | 'resources'
  | 'runtime'
  | 'graph'
  | 'findings'
  | 'remediation'
  | 'governance'
  | 'repositories'
  | 'actions'
  | 'agentic-risk'
  | 'agentic-risk-configs'
  | 'agentic-risk-mcp-tools'
  | 'agentic-risk-prompts'
  | 'agentic-risk-secrets'
  | 'agentic-risk-workflow-trust-paths'
  | 'agentic-risk-findings'
  | 'clusters'
  | 'workloads'
  | 'service-accounts';

type ProductDomainRoute = {
  id: ProductDomainRouteID;
  label: string;
  path: string;
  title: string;
  eyebrow: string;
  description: string;
  phase: string;
  status: string;
  metrics: Array<{ label: string; value: string; detail: string; tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info' }>;
  plannedWork: Array<{ capability: string; route: string; readiness: string }>;
  children?: ProductDomainRoute[];
};

type ProductDomainConfig = {
  key: SourceProvider;
  label: string;
  navLabel: string;
  description: string;
  routePrefix: string;
  connectRouteID: ProductDomainRouteID;
  routes: ProductDomainRoute[];
};

function productDomainRoute(
  id: ProductDomainRouteID,
  label: string,
  path: string,
  title: string,
  eyebrow: string,
  description: string,
  options: {
    phase?: string;
    status?: string;
    metrics?: ProductDomainRoute['metrics'];
    plannedWork?: ProductDomainRoute['plannedWork'];
    children?: ProductDomainRoute[];
  } = {}
): ProductDomainRoute {
  return {
    id,
    label,
    path,
    title,
    eyebrow,
    description,
    phase: options.phase ?? 'Route foundation',
    status: options.status ?? 'Route live',
    metrics:
      options.metrics ?? [
        { label: 'Route', value: 'Live', detail: 'Scoped workspace entry point is registered.', tone: 'success' },
        { label: 'Data', value: 'Next', detail: 'Domain APIs will attach in sequenced PRs.' },
        { label: 'UX', value: 'Premium', detail: 'Page shell, launcher, and actions are in place.' }
      ],
    plannedWork:
      options.plannedWork ?? [
        { capability: 'Connection flow', route: 'Domain-owned onboarding and health', readiness: 'planned' },
        { capability: 'Inventory and graph', route: 'Collected identities and resources', readiness: 'planned' },
        { capability: 'Findings and remediation', route: 'Domain-scoped risk workflow', readiness: 'planned' }
      ],
    children: options.children
  };
}

const PRODUCT_DOMAIN_CONFIGS: Record<SourceProvider, ProductDomainConfig> = {
  aws: {
    key: 'aws',
    label: 'AWS',
    navLabel: 'AWS',
    description: 'AWS for this workspace.',
    routePrefix: 'aws',
    connectRouteID: 'connect',
    routes: [
      productDomainRoute('overview', 'Overview', '', 'AWS', '', 'AWS for this workspace.'),
      productDomainRoute('connect', 'Connect AWS', 'connect', 'Connect AWS', '', 'Connect an AWS account so Identrail can scan it.'),
      productDomainRoute('accounts', 'Accounts', 'accounts', 'Accounts', '', "Which AWS account and region you're connected to."),
      productDomainRoute('identities', 'Identities', 'identities', 'Identities', '', 'IAM roles, workload identities, and what they can reach.'),
      productDomainRoute('agents', 'Agents', 'agents', 'Agents', '', 'Bedrock and MCP agents Identrail can see.'),
      productDomainRoute('resources', 'Resources', 'resources', 'Resources', '', 'Secrets, KMS keys, and S3 buckets your AWS roles can reach.'),
      productDomainRoute('runtime', 'Runtime', 'runtime', 'Runtime', '', 'What your AWS roles actually did, from CloudTrail.'),
      productDomainRoute('graph', 'Graph', 'graph', 'Graph', '', 'How AWS roles can reach things, visualised.'),
      productDomainRoute('findings', 'Findings', 'findings', 'Findings', '', 'Risks Identrail found in your AWS setup.'),
      productDomainRoute('remediation', 'Remediation', 'remediation', 'Remediation', '', 'AWS fixes Identrail prepares for you to approve.'),
      productDomainRoute('governance', 'Governance', 'governance', 'Governance', '', "Advice on AWS access. Identrail won't apply changes for you.")
    ]
  },
  github: {
    key: 'github',
    label: 'GitHub',
    navLabel: 'GitHub',
    description: 'Repositories, Actions/OIDC, agentic risk surfaces, findings, and remediation for GitHub.',
    routePrefix: 'github',
    connectRouteID: 'connect',
    routes: [
      productDomainRoute('overview', 'Control center', '', 'GitHub Control Center', 'Repository identity', 'Operate repository, workflow, OIDC, code, and agentic risk coverage from the GitHub section.'),
      productDomainRoute('connect', 'Connect GitHub', 'connect', 'Connect GitHub', 'GitHub App onboarding', 'Prepare the GitHub-owned connection route while existing installation and selected-repository internals stay intact.'),
      productDomainRoute('repositories', 'Repositories', 'repositories', 'GitHub repositories', 'Repository inventory', 'Route repository posture, selected installation scope, exposure signals, and scan health into a domain-owned page.'),
      productDomainRoute('actions', 'Actions / OIDC', 'actions', 'GitHub Actions / OIDC', 'Workflow trust', 'Reserve the workflow identity page for OIDC roles, deploy trust paths, Actions permissions, and runner posture.'),
      productDomainRoute('findings', 'Findings', 'findings', 'GitHub findings', 'Domain-scoped findings', 'Keep repository findings in the GitHub section instead of a global queue.'),
      productDomainRoute('remediation', 'Remediation', 'remediation', 'GitHub remediation', 'Repository fixes', 'Stage remediation PR planning, review workflow, lifecycle state, and verification from the GitHub section.'),
      productDomainRoute(
        'agentic-risk',
        'AI / Agentic Risk',
        'agentic-risk',
        'GitHub AI / Agentic Risk',
        'Agent and tool surfaces',
        'Make GitHub-hosted agent identities, MCP tools, prompts, secrets, and workflow trust paths visible without making AI risk a separate top-level product.',
        {
          children: [
            productDomainRoute('agentic-risk-configs', 'Agent identities', 'agentic-risk/configs', 'Agent identities', 'AI configuration inventory', 'Track repository agent definitions, assistant configuration files, and automation identities.'),
            productDomainRoute('agentic-risk-mcp-tools', 'MCP / tools', 'agentic-risk/mcp-tools', 'MCP tools', 'Tool reachability', 'Map MCP servers, tool grants, command surfaces, and repository-controlled execution paths.'),
            productDomainRoute('agentic-risk-prompts', 'Prompt surfaces', 'agentic-risk/prompts', 'Prompt surfaces', 'Prompt exposure', 'Inventory prompts, instruction files, workflow prompt assembly, and untrusted input paths.'),
            productDomainRoute('agentic-risk-secrets', 'Secrets', 'agentic-risk/secrets', 'Agentic secrets', 'Secret references', 'Track token, environment, and secret references used by AI workflows without exposing secret values.'),
            productDomainRoute('agentic-risk-workflow-trust-paths', 'Workflow trust paths', 'agentic-risk/workflow-trust-paths', 'Workflow trust paths', 'Trust path analysis', 'Prepare the route for pull request, workflow, runner, OIDC, and tool escalation paths.'),
            productDomainRoute('agentic-risk-findings', 'Findings', 'agentic-risk/findings', 'Agentic risk findings', 'AI finding queue', 'Keep AI and agentic findings nested under GitHub where the surfaces originate.')
          ]
        }
      )
    ]
  },
  kubernetes: {
    key: 'kubernetes',
    label: 'Kubernetes',
    navLabel: 'Kubernetes',
    description: 'Kubernetes identity and RBAC coverage.',
    routePrefix: 'kubernetes',
    connectRouteID: 'connect',
    routes: [
      productDomainRoute('overview', 'Control center', '', 'Kubernetes Control Center', 'Cluster identity', 'Cluster identity coverage.'),
      productDomainRoute('connect', 'Connect Kubernetes', 'connect', 'Connect Kubernetes', 'Cluster onboarding', 'Agent enrollment and kubeconfig fallback.'),
      productDomainRoute('clusters', 'Clusters', 'clusters', 'Kubernetes clusters', 'Cluster coverage', 'Cluster version and health.'),
      productDomainRoute('workloads', 'Workloads', 'workloads', 'Kubernetes workloads', 'Runtime workloads', 'Workload identity inventory.'),
      productDomainRoute('service-accounts', 'Service accounts / RBAC', 'service-accounts', 'Service accounts / RBAC', 'Kubernetes machine identity', 'Service accounts, roles, and bindings.'),
      productDomainRoute('findings', 'Findings', 'findings', 'Kubernetes findings', 'Domain-scoped findings', 'Kubernetes-scoped findings.'),
      productDomainRoute('remediation', 'Remediation', 'remediation', 'Kubernetes remediation', 'Manifest and policy fixes', 'RBAC and manifest fixes.')
    ]
  }
};

const SORT_LABEL_BY_FIELD: Record<(typeof REPO_FINDING_SORT_FIELDS)[number], string> = {
  severity: 'Risk (high → low)',
  created_at: 'Newest first',
  type: 'Finding type',
  title: 'Finding title'
};
const MODAL_FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

const TREND_POINTS = 10;
const PRODUCT_AUTH_SESSION_SCOPE_KEY = '__product_session__';
let validatedProductAuthSession = false;
let validatedProductAuthScopeKey = '';
let productAuthSessionVersion = 0;

function hasValidatedProductAuthScope(routeScopeKey: string): boolean {
  if (!validatedProductAuthSession) {
    return false;
  }
  return routeScopeKey === PRODUCT_AUTH_SESSION_SCOPE_KEY || validatedProductAuthScopeKey === routeScopeKey;
}

function setValidatedProductAuthScope(routeScopeKey: string) {
  validatedProductAuthSession = true;
  if (routeScopeKey !== PRODUCT_AUTH_SESSION_SCOPE_KEY) {
    validatedProductAuthScopeKey = routeScopeKey;
  } else {
    validatedProductAuthScopeKey = '';
  }
}

function resetProductAuthSessionCache(options: { unauthenticated?: boolean } = {}) {
  productAuthSessionVersion += 1;
  clearProductScopedDataCaches();
  validatedProductAuthSession = false;
  validatedProductAuthScopeKey = '';
  clearMeCache(options);
}

export function clearProductAuthSessionCacheForTests() {
  productAuthSessionVersion += 1;
  clearProductScopedDataCaches();
  validatedProductAuthSession = false;
  validatedProductAuthScopeKey = '';
}

function productScopedCacheKey(parts: string[]): string {
  return [String(productAuthSessionVersion), ...parts].join('::');
}

function currentProductAuthSessionVersion(): number {
  return productAuthSessionVersion;
}

function isCurrentProductAuthSessionVersion(version: number): boolean {
  return version === productAuthSessionVersion;
}

function isCurrentProductScopedCacheKey(key: string): boolean {
  return key.startsWith(`${productAuthSessionVersion}::`);
}

function clearProductScopedDataCaches() {
  environmentScopeCache.clear();
  environmentScopeRequests.clear();
  gitHubDomainDataCache.clear();
  gitHubDomainDataRequests.clear();
  gitHubDomainDataCacheEpochs.clear();
}

function resolveEnabledSourceProvider(provider: SourceProvider): SourceProvider | null {
  return DOMAIN_NAV_ORDER.includes(provider) ? provider : null;
}

export function SourceLogoMark({
  provider,
  className = '',
  decorative = false
}: {
  provider: SourceProvider;
  className?: string;
  decorative?: boolean;
}) {
  const enabledProvider = resolveEnabledSourceProvider(provider);
  if (!enabledProvider) {
    return null;
  }

  return <DomainLogoMark domain={enabledProvider} className={className} decorative={decorative} />;
}

function SourceLogoStack({
  providers = SOURCE_STACK,
  label = 'Source coverage stack',
  className = ''
}: {
  providers?: SourceProvider[];
  label?: string;
  className?: string;
}) {
  return <DomainLogoStack domains={providers} label={label} className={className} />;
}

function formatSourceNameList(providers: SourceProvider[]): string {
  const names = providers.map((provider) => SOURCE_PROFILES[provider].name);
  if (names.length === 0) {
    return 'source';
  }
  if (names.length === 1) {
    return names[0];
  }
  if (names.length === 2) {
    return `${names[0]} and ${names[1]}`;
  }
  return `${names.slice(0, -1).join(', ')}, and ${names[names.length - 1]}`;
}

async function listOverviewProjects(
  workspaceID: string,
  filters: { include_archived: boolean },
  auth: RequestAuthContext
): Promise<ProjectRecord[]> {
  const items: ProjectRecord[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;

  do {
    const response = await apiClient.listProjects(
      workspaceID,
      {
        limit: OVERVIEW_PROJECT_PAGE_LIMIT,
        cursor,
        sort_by: 'updated_at',
        sort_order: 'desc',
        include_archived: filters.include_archived
      },
      auth
    );
    items.push(...response.items);

    const nextCursor = response.next_cursor?.trim();
    if (!nextCursor) {
      break;
    }
    if (seenCursors.has(nextCursor)) {
      throw new Error('Environment pagination returned a repeated cursor');
    }
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  } while (cursor);

  return items;
}

function emptyOverviewConnectionRollup(): OverviewConnectionRollup {
  return { checkedCount: 0, connectedCount: 0, degradedCount: 0 };
}

function emptyOverviewConnectionRollups(): OverviewConnectionRollups {
  return {
    aws: emptyOverviewConnectionRollup(),
    kubernetes: emptyOverviewConnectionRollup()
  };
}

function summarizeOverviewConnections<T extends OverviewSourceConnection>(
  results: Array<PromiseSettledResult<{ connection: T }>>
): OverviewConnectionRollup {
  const rollup = emptyOverviewConnectionRollup();

  results.forEach((result) => {
    if (result.status !== 'fulfilled') {
      return;
    }
    const connection = result.value.connection;
    if (!connection) {
      return;
    }
    rollup.checkedCount += 1;
    if (!connection.connected) {
      return;
    }
    rollup.connectedCount += 1;
    if (connectionDomainTone(connection) !== 'success') {
      rollup.degradedCount += 1;
    }
  });

  return rollup;
}

async function loadOverviewConnectionRollups(
  scope: ProductSession,
  projects: ProjectRecord[],
  sourceAvailability: Record<SourceProvider, SourceAvailability>,
  auth: RequestAuthContext
): Promise<OverviewConnectionRollups> {
  const projectIDs = projects.map((project) => project.project_id).filter(Boolean);
  if (projectIDs.length === 0) {
    return emptyOverviewConnectionRollups();
  }

  const [awsResults, kubernetesResults] = await Promise.all([
    Promise.allSettled(
      projectIDs.map((projectID) => apiClient.getAWSProjectConnection(scope.workspaceID, projectID, auth))
    ),
    sourceAvailability.kubernetes.available
      ? Promise.allSettled(
          projectIDs.map((projectID) =>
            apiClient.getKubernetesProjectConnection(scope.workspaceID, projectID, auth)
          )
        )
      : Promise.resolve([])
  ]);

  return {
    aws: summarizeOverviewConnections(awsResults),
    kubernetes: summarizeOverviewConnections(kubernetesResults)
  };
}

function overviewStateFromConnectionRollup(
  availability: SourceAvailability,
  rollup: OverviewConnectionRollup
): OverviewDomainState {
  if (!availability.available) {
    return 'shell';
  }
  if (rollup.connectedCount === 0) {
    return 'not_connected';
  }
  return rollup.degradedCount > 0 ? 'degraded' : 'connected';
}

function overviewConnectionMetric(rollup: OverviewConnectionRollup, singular: string): string {
  return rollup.connectedCount > 0 ? formatCountLabel(rollup.connectedCount, singular) : 'Not connected';
}

async function listAIRisksRepoFindings(
  auth: RequestAuthContext,
  filters: RepoFindingRequestFilters = {}
): Promise<ApiFinding[]> {
  const items: ApiFinding[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;

  do {
    const response = await apiClient.listRepoFindings(
      {
        limit: AI_RISKS_REPO_FINDINGS_PAGE_LIMIT,
        ...filters,
        cursor,
        sort_by: filters.sort_by ?? 'severity',
        sort_order: filters.sort_order ?? 'desc'
      },
      auth
    );
    items.push(...(response.items ?? []));

    const nextCursor = response.next_cursor?.trim();
    if (!nextCursor) {
      break;
    }
    if (seenCursors.has(nextCursor)) {
      throw new Error('Repository finding pagination returned a repeated cursor');
    }
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  } while (cursor);

  return items;
}

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

function formatShortDateLabel(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });
}

function formatExecutiveDuration(seconds: number | undefined): string {
  if (!Number.isFinite(seconds ?? NaN)) {
    return 'N/A';
  }
  const totalSeconds = Math.max(0, Math.round(seconds ?? 0));
  if (totalSeconds < 3600) {
    if (totalSeconds === 0) {
      return '0m';
    }
    return `${Math.max(1, Math.round(totalSeconds / 60))}m`;
  }
  if (totalSeconds >= 86400) {
    const days = Math.round(totalSeconds / 86400);
    return `${days}d`;
  }
  const hours = Math.round(totalSeconds / 3600);
  return `${hours}h`;
}

function countHighPriorityExecutiveFindings(report: ExecutiveReport): number {
  return (report.open_by_severity.critical ?? 0) + (report.open_by_severity.high ?? 0);
}

const EXECUTIVE_SEVERITY_PALETTE: Record<(typeof EXECUTIVE_REPORT_SEVERITY_ORDER)[number], string> = {
  critical: '#e26b6b',
  high: '#e0995b',
  medium: '#d8c074',
  low: '#7fb5a6',
  info: '#7fa2d8'
};

function escapeReportHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
}

function buildExecutiveReportHtml(report: ExecutiveReport, highPriorityFindings: number): string {
  const weekDelta = report.week_over_week.delta;
  const topFindingTypes = report.top_finding_types ?? [];
  const severityRows = EXECUTIVE_REPORT_SEVERITY_ORDER.map((severity) => ({
    severity,
    count: report.open_by_severity[severity] ?? 0
  }));
  const totalOpen = report.total_open_findings;
  const sharePct = (count: number) =>
    totalOpen > 0 ? Math.round((count / totalOpen) * 100) : 0;

  const stackSegments = severityRows
    .filter((row) => row.count > 0)
    .map(
      (row) =>
        `<span style="display:inline-block;height:100%;width:${sharePct(row.count)}%;background:${EXECUTIVE_SEVERITY_PALETTE[row.severity]};"></span>`
    )
    .join('');

  const legendRows = severityRows
    .map((row) => {
      const dim = row.count === 0 ? 'opacity:0.5;' : '';
      return `<li style="display:flex;align-items:center;gap:0.65rem;padding:0.35rem 0;font-size:0.92rem;${dim}">
            <span style="display:inline-block;width:0.55rem;height:0.55rem;border-radius:999px;background:${EXECUTIVE_SEVERITY_PALETTE[row.severity]};"></span>
            <span style="flex:1;color:#2a2f37;">${escapeReportHtml(formatTokenLabel(row.severity))}</span>
            <span style="font-variant-numeric:tabular-nums;font-weight:600;color:#10141a;">${row.count}</span>
            <span style="font-variant-numeric:tabular-nums;color:#5e6776;min-width:3rem;text-align:right;">${sharePct(row.count)}%</span>
          </li>`;
    })
    .join('');

  const themeRows =
    topFindingTypes.length === 0
      ? `<p style="color:#5e6776;font-size:0.92rem;">No dominant finding types in this window.</p>`
      : `<ol style="list-style:none;margin:0;padding:0;">
          ${topFindingTypes
            .map(
              (item, index) =>
                `<li style="display:grid;grid-template-columns:1.5rem 1fr auto auto;gap:1rem;align-items:center;padding:0.75rem 0;border-top:1px solid #e6e9ee;font-size:0.95rem;${index === topFindingTypes.length - 1 ? 'border-bottom:1px solid #e6e9ee;' : ''}">
                  <span style="color:#9aa3b2;font-variant-numeric:tabular-nums;font-size:0.82rem;">${String(index + 1).padStart(2, '0')}</span>
                  <span style="color:#10141a;">${escapeReportHtml(formatTokenLabel(item.type))}</span>
                  <span style="color:#5e6776;font-variant-numeric:tabular-nums;font-size:0.85rem;">${sharePct(item.count)}%</span>
                  <span style="color:#10141a;font-variant-numeric:tabular-nums;font-weight:600;min-width:2.5rem;text-align:right;">${item.count}</span>
                </li>`
            )
            .join('')}
        </ol>`;

  const trendNote =
    weekDelta > 0
      ? `Open finding volume grew by <strong>${weekDelta}</strong> compared with the prior 7-day window.`
      : weekDelta < 0
        ? `Open finding volume fell by <strong>${Math.abs(weekDelta)}</strong> compared with the prior 7-day window.`
        : 'Open finding volume held steady against the prior 7-day window.';

  const mttrNote = report.mean_time_to_resolve
    ? `Mean time to resolve is <strong>${escapeReportHtml(formatExecutiveDuration(report.mean_time_to_resolve.seconds))}</strong> across ${report.mean_time_to_resolve.resolved_count} resolved findings with reliable timestamps.`
    : 'Mean time to resolve will be reported once resolved findings accumulate reliable timestamps.';

  const topThemeNote = topFindingTypes[0]
    ? `Largest theme is <strong>${escapeReportHtml(formatTokenLabel(topFindingTypes[0].type))}</strong>, representing ${sharePct(topFindingTypes[0].count)}% of open findings.`
    : '';

  const kpis = [
    {
      label: 'Open findings',
      value: totalOpen.toLocaleString(),
      detail: `${highPriorityFindings} critical or high`
    },
    {
      label: 'Net change · 7 days',
      value: weekDelta > 0 ? `+${weekDelta}` : String(weekDelta),
      detail: `${report.week_over_week.current_count} new · ${report.week_over_week.previous_count} previous`
    },
    {
      label: 'Mean time to resolve',
      value: formatExecutiveDuration(report.mean_time_to_resolve?.seconds),
      detail: report.mean_time_to_resolve
        ? `${report.mean_time_to_resolve.resolved_count} resolved samples`
        : 'Awaiting reliable resolution data'
    },
    {
      label: 'Top risk type',
      value: topFindingTypes[0] ? formatTokenLabel(topFindingTypes[0].type) : '—',
      detail: topFindingTypes[0]
        ? `${topFindingTypes[0].count} of ${totalOpen} open`
        : 'No open findings in scope'
    }
  ];

  const kpiCells = kpis
    .map(
      (kpi, index) => `<td style="padding:1.25rem 1.25rem 1.25rem ${index === 0 ? '0' : '1.25rem'};border-right:${index === kpis.length - 1 ? '0' : '1px solid #e6e9ee'};vertical-align:top;width:25%;">
        <div style="color:#5e6776;font-size:0.72rem;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.5rem;">${escapeReportHtml(kpi.label)}</div>
        <div style="font-family:'Georgia','Times New Roman',serif;font-size:1.85rem;font-weight:600;color:#10141a;line-height:1.05;margin-bottom:0.45rem;">${escapeReportHtml(kpi.value)}</div>
        <div style="color:#5e6776;font-size:0.84rem;">${escapeReportHtml(kpi.detail)}</div>
      </td>`
    )
    .join('');

  const generatedLabel = formatDateLabel(report.generated_at);
  const windowLabel = `${formatShortDateLabel(report.window_start)} – ${formatShortDateLabel(report.window_end)}`;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Identrail · Executive Report · ${escapeReportHtml(report.organization_id)}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      @page { size: A4; margin: 1.6cm; }
      * { box-sizing: border-box; }
      html, body { background: #f7f8fa; }
      body {
        margin: 0;
        font-family: -apple-system, 'Helvetica Neue', Helvetica, Arial, sans-serif;
        color: #10141a;
        line-height: 1.5;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      .sheet {
        max-width: 820px;
        margin: 32px auto;
        padding: 56px 56px 48px;
        background: #ffffff;
        border: 1px solid #e6e9ee;
        border-radius: 4px;
      }
      h1 { font-family: 'Georgia','Times New Roman',serif; font-weight: 600; letter-spacing: 0; margin: 0 0 0.55rem; font-size: 1.95rem; color: #10141a; }
      h2 { font-family: 'Georgia','Times New Roman',serif; font-weight: 600; font-size: 1.05rem; margin: 0 0 0.65rem; color: #10141a; }
      p { margin: 0; }
      .eyebrow { color: #5e6776; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.16em; text-transform: uppercase; margin-bottom: 0.55rem; }
      .meta { color: #5e6776; font-size: 0.84rem; margin-top: 0.4rem; }
      .meta strong { color: #2a2f37; font-weight: 500; }
      .hr { border: 0; border-top: 1px solid #e6e9ee; margin: 2.25rem 0; }
      .lede { color: #5e6776; font-size: 0.9rem; margin-top: -0.25rem; }
      .kpi-row { width: 100%; border-collapse: collapse; border-top: 1px solid #e6e9ee; border-bottom: 1px solid #e6e9ee; margin: 1.5rem 0 2.25rem; }
      .section { margin-bottom: 2rem; }
      .section:last-child { margin-bottom: 0; }
      .stack { width: 100%; height: 0.6rem; border-radius: 999px; background: #eef0f3; overflow: hidden; display: flex; margin: 0.9rem 0 1rem; }
      .legend { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: 0.05rem 1.5rem; }
      .notes { list-style: none; margin: 0; padding: 0; }
      .notes li { padding: 0.45rem 0 0.45rem 1rem; position: relative; color: #2a2f37; font-size: 0.95rem; }
      .notes li::before { content: ''; position: absolute; left: 0; top: 1rem; width: 0.45rem; border-top: 1px solid #5e6776; }
      .notes strong { color: #10141a; font-weight: 600; }
      footer { margin-top: 2.5rem; padding-top: 1.25rem; border-top: 1px solid #e6e9ee; color: #8b94a3; font-size: 0.78rem; }
      @media print {
        html, body { background: #ffffff; }
        .sheet { margin: 0; border: 0; border-radius: 0; padding: 0; max-width: none; }
      }
    </style>
  </head>
  <body>
    <main class="sheet">
      <header>
        <p class="eyebrow">Executive Report</p>
        <h1>Risk posture summary</h1>
        <p class="meta">Organization <strong>${escapeReportHtml(report.organization_id)}</strong> · Window ${escapeReportHtml(windowLabel)} · Generated ${escapeReportHtml(generatedLabel)}</p>
      </header>

      <table class="kpi-row" role="presentation">
        <tbody><tr>${kpiCells}</tr></tbody>
      </table>

      <section class="section">
        <h2>Severity composition</h2>
        <p class="lede">How the ${totalOpen.toLocaleString()} open findings break down today.</p>
        <div class="stack" role="img" aria-label="Open findings by severity">${stackSegments || '<span style="width:100%;background:#eef0f3;"></span>'}</div>
        <ul class="legend">${legendRows}</ul>
      </section>

      <hr class="hr" />

      <section class="section">
        <h2>Top finding types</h2>
        <p class="lede">Themes driving open risk this window.</p>
        ${themeRows}
      </section>

      <hr class="hr" />

      <section class="section">
        <h2>Notes for leadership</h2>
        <ul class="notes">
          <li>${trendNote}</li>
          <li>${mttrNote}</li>
          ${topThemeNote ? `<li>${topThemeNote}</li>` : ''}
        </ul>
      </section>

      <footer>
        <p>Scope: organization ${escapeReportHtml(report.organization_id)}, window ${escapeReportHtml(windowLabel)}.</p>
        <p>Generated by Identrail on ${escapeReportHtml(generatedLabel)}.</p>
      </footer>
    </main>
  </body>
</html>`;
}

function executiveReportFileSlug(report: ExecutiveReport): string {
  const orgSlug = report.organization_id.replace(/[^a-z0-9]+/gi, '-').toLowerCase() || 'org';
  const windowEnd = report.window_end.slice(0, 10).replace(/-/g, '');
  return `identrail-executive-report-${orgSlug}-${windowEnd}.html`;
}

function downloadExecutiveReport(report: ExecutiveReport, highPriorityFindings: number): void {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return;
  }
  const html = buildExecutiveReportHtml(report, highPriorityFindings);
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = executiveReportFileSlug(report);
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
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

function normalizeRepoFindingLifecycleStatus(value: string | undefined): RepoFindingLifecycleStatus {
  const normalized = normalizeValue(value ?? '').toLowerCase();
  if (
    normalized === 'fixed' ||
    normalized === 'reopened' ||
    normalized === 'suppressed' ||
    normalized === 'risk_accepted' ||
    normalized === 'false_positive'
  ) {
    return normalized;
  }
  return 'open';
}

function repoFindingStatusClass(status: FindingLifecycleStatus | RepoFindingLifecycleStatus): string {
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

function tokenWithNumericSuffix(base: string, suffix: number): string {
  const suffixToken = `-${suffix}`;
  return `${base.slice(0, Math.max(1, 64 - suffixToken.length))}${suffixToken}`;
}

function stableEnvironmentTokenHash(value: string): string {
  let hash = 2166136261;
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    hash ^= codePoint;
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash.toString(36);
}

function uniqueEnvironmentToken(name: string, existingProjects: ProjectRecord[]): string {
  const existingIDs = new Set(existingProjects.map((project) => normalizeValue(project.project_id)).filter(Boolean));
  const base = normalizeProjectToken(name) || `environment-${stableEnvironmentTokenHash(name)}`;

  if (base && !existingIDs.has(base)) {
    return base;
  }

  for (let suffix = 2; suffix < 1000; suffix += 1) {
    const candidate = tokenWithNumericSuffix(base, suffix);
    if (!existingIDs.has(candidate)) {
      return candidate;
    }
  }

  return tokenWithNumericSuffix(base, Date.now());
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

function projectEnvironmentLabel(project: ProjectRecord): string {
  const name = normalizeValue(project.name);
  if (name) {
    return name;
  }
  const slug = normalizeValue(project.slug);
  if (slug) {
    return formatTokenLabel(slug);
  }
  return environmentFallbackLabel(project.project_id);
}

function isProjectArchived(project: ProjectRecord): boolean {
  return Boolean(normalizeValue(project.archived_at ?? ''));
}

function isTransientProjectLookupError(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status !== 404;
}

function environmentFallbackLabel(projectID: string | undefined): string {
  const normalized = normalizeValue(projectID ?? '');
  if (!normalized || /^project(?:[-_]\d+)?$/i.test(normalized) || /^legacy[-_]project$/i.test(normalized)) {
    return 'Default environment';
  }
  return formatTokenLabel(normalized);
}

function environmentIDFromSearch(search: string): string {
  return normalizeValue(new URLSearchParams(search).get(ENVIRONMENT_QUERY_PARAM));
}

function environmentSearch(search: string, environmentID: string): string {
  const params = new URLSearchParams(search);
  const normalized = normalizeValue(environmentID);
  if (normalized) {
    params.set(ENVIRONMENT_QUERY_PARAM, normalized);
  } else {
    params.delete(ENVIRONMENT_QUERY_PARAM);
  }
  const next = params.toString();
  return next ? `?${next}` : '';
}

function appendEnvironmentQuery(path: string, environmentID: string | undefined): string {
  const normalized = normalizeValue(environmentID ?? '');
  if (!normalized) {
    return path;
  }
  const [pathname, rawSearch = ''] = path.split('?');
  return `${pathname}${environmentSearch(rawSearch, normalized)}`;
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

function repoFindingScanTimestamp(finding: ApiFinding, repoScansByID: Record<string, RepoScanRecord>): number {
  const scan = repoScansByID[finding.scan_id];
  const timestamp =
    normalizeValue(scan?.finished_at) ||
    normalizeValue(scan?.started_at) ||
    normalizeValue(finding.last_seen_at) ||
    normalizeValue(finding.first_seen_at) ||
    normalizeValue(finding.created_at);
  const parsed = new Date(timestamp);
  return Number.isNaN(parsed.getTime()) ? 0 : parsed.getTime();
}

function repoFindingScanDateLabel(finding: ApiFinding, repoScansByID: Record<string, RepoScanRecord>): string {
  const timestamp = repoFindingScanTimestamp(finding, repoScansByID);
  if (!timestamp) {
    return 'Scan date unavailable';
  }
  return new Date(timestamp).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });
}

function repoFindingSeverityClass(severity: string): string {
  const normalized = normalizeValue(severity).toLowerCase() || 'unknown';
  return `idt-repo-finding-severity is-${normalized}`;
}

function severityRank(severity: string): number {
  const normalized = normalizeValue(severity).toLowerCase();
  if (normalized === 'critical') return 5;
  if (normalized === 'high') return 4;
  if (normalized === 'medium') return 3;
  if (normalized === 'low') return 2;
  if (normalized === 'info') return 1;
  return 0;
}

function isActiveScanStatus(status: string): boolean {
  const normalized = normalizeValue(status).toLowerCase();
  return normalized === 'queued' || normalized === 'running' || normalized === 'in_progress' || normalized === 'pending';
}

function isCompletedScanStatus(status: string): boolean {
  const normalized = normalizeValue(status).toLowerCase();
  return normalized === 'succeeded' || normalized === 'completed' || normalized === 'failed' || normalized === 'canceled';
}

function isFailedScanStatus(status: string): boolean {
  const normalized = normalizeValue(status).toLowerCase();
  return normalized === 'failed';
}

function scanCompletionSortValue(scan: RepoScanRecord): number {
  const finishedAt = new Date(scan.finished_at ?? '');
  if (!Number.isNaN(finishedAt.getTime())) {
    return finishedAt.getTime();
  }

  const startedAt = new Date(scan.started_at ?? '');
  return Number.isNaN(startedAt.getTime()) ? -Infinity : startedAt.getTime();
}

function repoScanStatusTone(status: string): 'success' | 'warning' | 'error' | 'neutral' {
  const normalized = normalizeValue(status).toLowerCase();
  if (normalized === 'succeeded' || normalized === 'completed') {
    return 'success';
  }
  if (normalized === 'failed' || normalized === 'canceled') {
    return 'error';
  }
  if (isActiveScanStatus(normalized)) {
    return 'warning';
  }
  return 'neutral';
}

function githubPostureStateTone(state: GitHubRepositoryPostureCheck['state']): 'success' | 'warning' | 'error' | 'neutral' {
  if (state === 'secure') {
    return 'success';
  }
  if (state === 'insecure') {
    return 'error';
  }
  if (state === 'permission_limited') {
    return 'warning';
  }
  if (state === 'unsupported' || state === 'unknown') {
    return 'warning';
  }
  return 'neutral';
}

function countGitHubPostureChecks(
  posture: GitHubRepositoryPosture | GitHubOrganizationPosture | null,
  state: GitHubRepositoryPostureCheck['state']
): number {
  return posture?.checks.filter((check) => check.state === state).length ?? 0;
}

function formatCountLabel(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

function sortRepoRiskGraphScores(scores: RepoRiskGraphFindingScore[]): RepoRiskGraphFindingScore[] {
  return [...scores].sort((left, right) => {
    if (right.score !== left.score) {
      return right.score - left.score;
    }
    return severityRank(right.severity) - severityRank(left.severity);
  });
}

function uniqueGitHubRepositories(repositories: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  repositories.forEach((repository) => {
    const normalized = canonicalGitHubRepositoryDisplay(repository);
    const key = normalized.toLowerCase();
    if (!normalized || seen.has(key)) {
      return;
    }
    seen.add(key);
    result.push(normalized);
  });
  return result;
}

function countMembersByStatus(members: WorkspaceMemberRecord[], status: WorkspaceMemberStatus): number {
  return members.filter((member) => member.status === status).length;
}

function countMembersByRole(members: WorkspaceMemberRecord[], role: WorkspaceMemberRole): number {
  return members.filter((member) => member.role === role).length;
}

type ProfileDraft = {
  displayName: string;
};

function profileDraftFromMe(me: CurrentUserContext | null | undefined): ProfileDraft {
  return {
    displayName: me?.user.display_name ?? ''
  };
}

function formatProfileDisplayName(me: CurrentUserContext | null | undefined): string {
  const displayName = me?.user.display_name?.trim();
  if (displayName) {
    return displayName;
  }
  return me?.user.primary_email ?? 'Current user';
}

function formatProfileInitials(me: CurrentUserContext | null | undefined): string {
  const source = formatProfileDisplayName(me).split('@')[0] || 'U';
  const parts = source
    .split(/[\s._-]+/)
    .map((part) => part.trim())
    .filter(Boolean);
  const initials = (parts.length > 1 ? parts[0][0] + parts[1][0] : source.slice(0, 2)).toUpperCase();
  return initials || 'U';
}

function formatSettingsAuthProvider(provider: string): string {
  const normalized = provider.toLowerCase();
  if (normalized.includes('github')) {
    return 'GitHub';
  }
  if (normalized.includes('google')) {
    return 'Google';
  }
  if (normalized.includes('saml')) {
    return 'SAML SSO';
  }
  if (normalized.includes('workos') || normalized.includes('authkit')) {
    return 'Hosted login';
  }
  return formatTokenLabel(provider.replace(/_oauth$/i, ''));
}

function formatSettingsAuthProviders(config: AuthConfigResponse | null): string {
  const providers = config?.auth.providers ?? [];
  const labels = Array.from(new Set(providers.map(formatSettingsAuthProvider))).filter((label) => label !== 'Hosted login');
  if (labels.length) {
    return labels.join(', ');
  }
  if (config?.auth.workos_login_enabled) {
    return 'Hosted login';
  }
  if (config?.auth.native_saml_enabled) {
    return 'SAML SSO';
  }
  if (config?.auth.manual_mode) {
    return 'Manual development';
  }
  return 'Session-only';
}

const PROFILE_AVATAR_MAX_BYTES = 5 * 1024 * 1024;
const PROFILE_AVATAR_MAX_BYTES_LABEL = '5 MB';
const PROFILE_AVATAR_ALLOWED_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);

function validateProfileDraft(draft: ProfileDraft): string {
  const displayName = draft.displayName.trim();
  if (!displayName || Array.from(displayName).length > 80) {
    return 'Display name must be 1-80 characters.';
  }
  if (Array.from(displayName).some(isUnsafeProfileNameCharacter)) {
    return 'Display name cannot contain control or bidirectional formatting characters.';
  }
  return '';
}

function validateProfileAvatarFile(file: File): string {
  if (!PROFILE_AVATAR_ALLOWED_TYPES.has(file.type)) {
    return 'Profile photo must be PNG, JPG, WebP, or GIF.';
  }
  if (file.size > PROFILE_AVATAR_MAX_BYTES) {
    return `Profile photo must be smaller than ${PROFILE_AVATAR_MAX_BYTES_LABEL}.`;
  }
  return '';
}

function formatProfileAvatarError(err: unknown): string {
  if (err instanceof ApiError && err.message.toLowerCase().includes('avatar_url')) {
    return `Upload failed. Use a PNG, JPG, WebP, or GIF under ${PROFILE_AVATAR_MAX_BYTES_LABEL}.`;
  }
  return err instanceof Error ? err.message : 'Unable to update profile photo.';
}

function readProfileAvatarFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        resolve(reader.result);
        return;
      }
      reject(new Error('Unable to read profile photo.'));
    };
    reader.onerror = () => reject(new Error('Unable to read profile photo.'));
    reader.readAsDataURL(file);
  });
}

function isUnsafeProfileNameCharacter(char: string): boolean {
  const code = char.codePointAt(0) ?? 0;
  return (
    code < 32 ||
    code === 127 ||
    code === 0x061c ||
    code === 0x200e ||
    code === 0x200f ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
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

function buildSourceAvailability(backendFeatures: BackendFeatures): Record<SourceProvider, SourceAvailability> {
  return {
    github: {
      visible: true,
      available: isFeatureAvailable(FEATURE_CONNECTOR_GITHUB_V2, backendFeatures.connectors.github),
      unavailableMessage: backendFeatures.connectors.github === false ? 'Not available on this API server.' : undefined
    },
    aws: {
      visible: true,
      available: true
    },
    kubernetes: {
      visible: true,
      available: isFeatureAvailable(FEATURE_CONNECTOR_K8S, backendFeatures.connectors.kubernetes),
      unavailableMessage: backendFeatures.connectors.kubernetes === false ? 'Not available on this API server.' : undefined
    }
  };
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

function connectionDomainTone(status?: GitHubConnectionStatus | AWSConnectionStatus | KubernetesConnectionStatus): 'success' | 'warning' | 'danger' | 'neutral' {
  const tone = connectionTone(status);
  return tone === 'error' ? 'danger' : tone;
}

function sourceAvailabilityTone(
  availability: SourceAvailability,
  status?: GitHubConnectionStatus | AWSConnectionStatus | KubernetesConnectionStatus
): 'success' | 'warning' | 'error' | 'neutral' {
  return availability.available ? connectionTone(status) : 'error';
}

function openGitHubInstallURL(installURL: string) {
  if (typeof window === 'undefined' || !installURL) {
    return false;
  }
  if (/jsdom/i.test(window.navigator.userAgent)) {
    return false;
  }
  try {
    return window.open(installURL, '_blank', 'noopener,noreferrer') !== null;
  } catch {
    return false;
  }
}

function formatAPIError(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    const detail = normalizeValue(error.detail);
    if (detail) {
      return detail;
    }
    if (error.message) {
      return error.message;
    }
  }
  return error instanceof Error ? error.message : fallback;
}

function appendAPIDetail(message: string, error: ApiError): string {
  const detail = normalizeValue(error.detail);
  if (!detail) {
    return message;
  }
  return `${message} ${detail}`;
}

function formatRepoScanSubmitError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 400) {
      return appendAPIDetail('Choose a valid owner/repo repository target before queueing a scan.', error);
    }
    if (error.status === 403) {
      return appendAPIDetail(
        'That repository is not currently allowed for this GitHub source. Select it during installation and refresh status, or ask an operator to allow that owner/repo target for PAT-backed scans.',
        error
      );
    }
    if (error.status === 409) {
      return appendAPIDetail(
        'A scan is already queued or running for this repository. Watch recent scan activity below.',
        error
      );
    }
    if (error.status === 429) {
      return appendAPIDetail('The repository scan queue is full. Wait for worker capacity to drain, then retry.', error);
    }
    if (error.status === 503) {
      return appendAPIDetail(
        'Repository scanning is disabled on this API server. Ask an operator to enable repo scanning before queueing the first scan.',
        error
      );
    }
    if (error.detail) {
      return `Unable to queue repository scan. ${error.detail}`;
    }
  }
  return error instanceof Error ? error.message : 'Unable to queue repository scan.';
}

function formatRepoScanCancelError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404) {
      return 'That repository scan no longer exists. Refresh recent activity before retrying.';
    }
    if (error.status === 409) {
      return 'That repository scan already reached a terminal state. Refresh recent activity before retrying.';
    }
  }
  return error instanceof Error ? error.message : 'Unable to cancel repository scan.';
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
      message: error instanceof Error ? error.message : 'Unexpected workspace view failure'
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
            <p className="idt-app-kicker">Workspace view error</p>
            <h1>Workspace view failed to load</h1>
            <p>{this.state.message}</p>
            <p>Refresh the page. If it keeps happening, return to the homepage while we restore this workspace view.</p>
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

function AppRouteLoadingState({ title, body }: { title: string; body: string }) {
  return (
    <section className="idt-app-panel idt-app-route-loading" aria-busy="true" aria-live="polite">
      <p className="idt-app-kicker">Loading</p>
      <h2>{title}</h2>
      <p>{body}</p>
    </section>
  );
}

function AppShellEmptyState({
  title,
  body,
  action
}: {
  title: string;
  body: string;
  action?: { label: string; to: string };
}) {
  return (
    <article className="idt-app-empty-state">
      <h2>{title}</h2>
      <p>{body}</p>
      {action ? (
        <Link className="idt-app-empty-state-action" to={action.to}>
          {action.label}
        </Link>
      ) : null}
    </article>
  );
}

type CommandPaletteItem = {
  id: string;
  label: string;
  description: string;
  keywords: string[];
  shortcut?: string;
  path?: string;
  action?: () => void;
};

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  const tagName = target.tagName.toLowerCase();
  return target.isContentEditable || tagName === 'input' || tagName === 'select' || tagName === 'textarea';
}

function CommandPalette({
  open,
  items,
  onClose,
  onSelect
}: {
  open: boolean;
  items: CommandPaletteItem[];
  onClose: () => void;
  onSelect: (item: CommandPaletteItem) => void;
}) {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!open) {
      setQuery('');
      return;
    }

    const focusTimer = window.setTimeout(() => inputRef.current?.focus(), 0);
    const root = document.documentElement;
    const previousOverflow = root.style.overflow;
    root.style.overflow = 'hidden';
    return () => {
      window.clearTimeout(focusTimer);
      root.style.overflow = previousOverflow;
    };
  }, [open]);

  const filteredItems = useMemo(() => {
    const search = normalizeValue(query).toLowerCase();
    if (!search) {
      return items;
    }
    return items.filter((item) =>
      [item.label, item.description, ...item.keywords].some((value) => value.toLowerCase().includes(search))
    );
  }, [items, query]);

  if (!open) {
    return null;
  }

  const handleInputKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key === 'Enter' && filteredItems[0]) {
      event.preventDefault();
      onSelect(filteredItems[0]);
    }
  };

  return (
    <div
      className="idt-command-palette-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <section
        className="idt-command-palette"
        role="dialog"
        aria-modal="true"
        aria-label="Workspace finder"
        onKeyDown={(event) => {
          if (event.defaultPrevented) {
            return;
          }
          if (event.key === 'Escape') {
            event.preventDefault();
            onClose();
          }
        }}
      >
        <div className="idt-command-palette-search-row">
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={handleInputKeyDown}
            placeholder="Search views, reports, settings, and actions"
            aria-label="Search workspace commands"
          />
          <button type="button" className="idt-command-palette-close" onClick={onClose} aria-label="Close workspace finder">
            ESC
          </button>
        </div>
        <div className="idt-command-palette-results" role="listbox" aria-label="Workspace commands">
          {filteredItems.length > 0 ? (
            filteredItems.map((item) => (
              <button key={item.id} type="button" role="option" onClick={() => onSelect(item)}>
                <span>
                  <strong>{item.label}</strong>
                  <small>{item.description}</small>
                </span>
                {item.shortcut ? <kbd>{item.shortcut}</kbd> : null}
              </button>
            ))
          ) : (
            <p>No matching commands yet.</p>
          )}
        </div>
      </section>
    </div>
  );
}

export function RequireProductAuth({ children }: { children: ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const navigateRef = useRef(navigate);
  const params = useParams<ScopeRouteParams>();
  const routeTenantID = normalizeValue(params.tenantID);
  const routeWorkspaceID = normalizeValue(params.workspaceID);
  const routeHasExplicitScope = Boolean(routeTenantID && routeWorkspaceID);
  const routeScopeKey = routeHasExplicitScope ? `${routeTenantID}::${routeWorkspaceID}` : PRODUCT_AUTH_SESSION_SCOPE_KEY;
  const routeLocationKey = `${location.pathname}${location.search}`;
  const routeAuthWarm = hasValidatedProductAuthScope(routeScopeKey);
  const [status, setStatus] = useState<'checking' | 'authenticated' | 'unauthenticated' | 'error'>(
    routeAuthWarm ? 'authenticated' : 'checking'
  );
  const [validatedScopeKey, setValidatedScopeKey] = useState(routeAuthWarm ? routeScopeKey : '');
  const validatedScopeKeyRef = useRef(routeAuthWarm ? routeScopeKey : '');
  const statusRef = useRef(status);
  const [error, setError] = useState('');

  useEffect(() => {
    navigateRef.current = navigate;
  }, [navigate]);

  useEffect(() => {
    statusRef.current = status;
  }, [status]);

  useEffect(() => {
    let mounted = true;

    const validateSession = async (options: { silent?: boolean } = {}) => {
      const silent = options.silent === true;
      const requestSessionVersion = productAuthSessionVersion;
      const retryIfSessionChanged = () => {
        if (requestSessionVersion === productAuthSessionVersion) {
          return false;
        }
        void validateSession(options);
        return true;
      };
      if (!silent) {
        setStatus('checking');
      }
      setError('');
      try {
        const current = await apiClient.getMe({ redirectOnUnauthorized: false });
        const currentTenantID = normalizeValue(current.me.org_id ?? '');
        const currentWorkspaceID = normalizeValue(current.me.workspace_id ?? '');
        const currentScopeKey =
          currentTenantID && currentWorkspaceID ? `${currentTenantID}::${currentWorkspaceID}` : PRODUCT_AUTH_SESSION_SCOPE_KEY;
        let validatedRouteScopeKey = routeScopeKey;
        if (!mounted || retryIfSessionChanged()) {
          return;
        }
        primeMeCache(current.me);
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
            navigateRef.current(buildTenantWorkspacePath(currentTenantID, currentWorkspaceID), { replace: true });
            setValidatedProductAuthScope(currentScopeKey);
            validatedScopeKeyRef.current = currentScopeKey;
            setValidatedScopeKey(currentScopeKey);
            setStatus('authenticated');
            return;
          }
          await apiClient.resolveActiveWorkspace(routeWorkspaceID, {
            tenantID: currentTenantID,
            workspaceID: currentWorkspaceID
          });
          validatedRouteScopeKey = routeScopeKey;
        } else if (!routeHasExplicitScope) {
          validatedRouteScopeKey = currentScopeKey;
        }
        setValidatedProductAuthScope(validatedRouteScopeKey);
        validatedScopeKeyRef.current = routeScopeKey;
        setValidatedScopeKey(routeScopeKey);
        setStatus('authenticated');
      } catch (requestError) {
        if (!mounted || retryIfSessionChanged()) {
          return;
        }
        if (requestError instanceof ApiError && requestError.status === 401) {
          resetProductAuthSessionCache({ unauthenticated: true });
          setStatus('unauthenticated');
          return;
        }
        if (silent) {
          return;
        }
        const message = requestError instanceof Error ? requestError.message : 'Unable to validate account session.';
        resetProductAuthSessionCache();
        validatedScopeKeyRef.current = '';
        setValidatedScopeKey('');
        setError(message);
        setStatus('error');
      }
    };

    const run = async () => {
      const alreadyValidated = validatedScopeKeyRef.current === routeScopeKey || hasValidatedProductAuthScope(routeScopeKey);
      if (alreadyValidated && statusRef.current === 'authenticated') {
        validatedScopeKeyRef.current = routeScopeKey;
        setValidatedScopeKey(routeScopeKey);
        await validateSession({ silent: true });
        return;
      }
      await validateSession();
    };

    void run();

    return () => {
      mounted = false;
    };
  }, [routeHasExplicitScope, routeTenantID, routeWorkspaceID, routeScopeKey, routeLocationKey]);

  if (status === 'checking' || (status === 'authenticated' && validatedScopeKey !== routeScopeKey)) {
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
        resetProductAuthSessionCache({ unauthenticated: true });
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
  const onboardingAvailable = useOnboardingAvailable();
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
    if (FEATURE_ONBOARDING_WIZARD && onboardingAvailable === undefined) {
      return <AppShellLoading message="Resolving workspace scope" />;
    }
    if (onboardingAvailable) {
      return <Navigate to="/onboarding/org" replace />;
    }
    if (FEATURE_ONBOARDING_WIZARD) {
      // The web bundle ships the wizard but the API does not register the
      // onboarding routes. Show a clear state instead of redirecting into a
      // flow that would fail with a raw 404.
      return <OnboardingUnavailableNotice />;
    }
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

function domainRoutePath(scope: ProductSession, domain: SourceProvider, route: ProductDomainRoute): string {
  const config = PRODUCT_DOMAIN_CONFIGS[domain];
  return buildScopedPath(scope, [config.routePrefix, route.path].filter(Boolean).join('/'));
}

function flattenDomainRoutes(routes: ProductDomainRoute[]): ProductDomainRoute[] {
  return routes.flatMap((route) => [route, ...(route.children ? flattenDomainRoutes(route.children) : [])]);
}

function routeMatchesPath(scope: ProductSession, domain: SourceProvider, route: ProductDomainRoute, pathname: string): boolean {
  return pathname === domainRoutePath(scope, domain, route);
}

function findDomainRoute(domain: SourceProvider, routeID: ProductDomainRouteID): ProductDomainRoute {
  const config = PRODUCT_DOMAIN_CONFIGS[domain];
  return flattenDomainRoutes(config.routes).find((route) => route.id === routeID) ?? config.routes[0];
}

function findActiveDomain(scope: ProductSession, pathname: string): SourceProvider | null {
  return (Object.keys(PRODUCT_DOMAIN_CONFIGS) as SourceProvider[]).find((domain) => {
    const base = buildScopedPath(scope, PRODUCT_DOMAIN_CONFIGS[domain].routePrefix);
    return pathname === base || pathname.startsWith(`${base}/`);
  }) ?? null;
}

function findActiveDomainRouteID(
  scope: ProductSession,
  domain: SourceProvider,
  pathname: string
): ProductDomainRouteID | null {
  const routes = flattenDomainRoutes(PRODUCT_DOMAIN_CONFIGS[domain].routes);
  const active = routes.find((route) => routeMatchesPath(scope, domain, route, pathname));
  return active?.id ?? null;
}

function SidebarDomainIcon({ domain }: { domain: SourceProvider }) {
  const asset = getDomainAsset(domain);
  return (
    <img
      className={`idt-sidebar-domain-logo is-${domain}`}
      src={asset.logoSrc}
      alt=""
      aria-hidden="true"
      loading="lazy"
      decoding="async"
    />
  );
}

function ProductDomainFlyoutRouteLink({
  scope,
  domain,
  route,
  activeRouteID,
  child = false,
  onClose
}: {
  scope: ProductSession;
  domain: SourceProvider;
  route: ProductDomainRoute;
  activeRouteID: ProductDomainRouteID | null;
  child?: boolean;
  onClose: () => void;
}) {
  const active = activeRouteID === route.id;
  const config = PRODUCT_DOMAIN_CONFIGS[domain];
  const routeLabel = route.label.includes(config.navLabel) ? route.label : `${config.navLabel} ${route.label}`;
  const linkLabel = child ? `${config.navLabel} AI / Agentic Risk ${route.label}` : routeLabel;
  return (
    <Link
      className={`idt-domain-flyout-link${active ? ' is-active' : ''}${child ? ' is-child' : ''}`}
      to={domainRoutePath(scope, domain, route)}
      aria-label={linkLabel}
      aria-current={active ? 'page' : undefined}
      onClick={onClose}
    >
      <span className="idt-domain-flyout-link-copy">
        <strong>{route.label}</strong>
      </span>
      <ChevronRight size={14} strokeWidth={1.8} aria-hidden="true" />
    </Link>
  );
}

function ProductDomainFlyout({
  domain,
  scope,
  activeRouteID,
  labelledBy,
  panelRef,
  onClose
}: {
  domain: SourceProvider;
  scope: ProductSession;
  activeRouteID: ProductDomainRouteID | null;
  labelledBy: string;
  panelRef: MutableRefObject<HTMLDivElement | null>;
  onClose: () => void;
}) {
  const config = PRODUCT_DOMAIN_CONFIGS[domain];
  const startRoutes = config.routes.filter((route) => route.id === 'overview' || route.id === 'connect');
  const nestedRoutes = config.routes.filter((route) => route.children?.length);
  const riskRoutes = config.routes.filter((route) => ['findings', 'remediation', 'governance'].includes(route.id));
  const surfaceRoutes = config.routes.filter(
    (route) => !startRoutes.includes(route) && !nestedRoutes.includes(route) && !riskRoutes.includes(route)
  );

  return (
    <div
      id={`idt-${domain}-domain-flyout`}
      ref={panelRef}
      className={`idt-domain-flyout is-${domain}`}
      role="dialog"
      aria-modal="true"
      aria-labelledby={labelledBy}
    >
      <div className="idt-domain-flyout-section">
        <span className="idt-domain-flyout-section-label">Start</span>
        <div className="idt-domain-flyout-list">
          {startRoutes.map((route) => (
            <ProductDomainFlyoutRouteLink
              key={route.id}
              scope={scope}
              domain={domain}
              route={route}
              activeRouteID={activeRouteID}
              onClose={onClose}
            />
          ))}
        </div>
      </div>

      {surfaceRoutes.length ? (
        <div className="idt-domain-flyout-section">
          <span className="idt-domain-flyout-section-label">Inventory</span>
          <div className="idt-domain-flyout-list">
            {surfaceRoutes.map((route) => (
              <ProductDomainFlyoutRouteLink
                key={route.id}
                scope={scope}
                domain={domain}
                route={route}
                activeRouteID={activeRouteID}
                onClose={onClose}
              />
            ))}
          </div>
        </div>
      ) : null}

      {nestedRoutes.map((route) => {
        const childActive = route.children?.some((child) => child.id === activeRouteID) ?? false;
        return (
          <details key={route.id} className="idt-domain-flyout-nested" open={route.id === activeRouteID || childActive}>
            <summary>
              <span>
                <strong>{route.label}</strong>
                <small>Agent surfaces</small>
              </span>
              <ChevronDown size={14} strokeWidth={1.8} aria-hidden="true" />
            </summary>
            <div className="idt-domain-flyout-nested-body">
              <ProductDomainFlyoutRouteLink
                scope={scope}
                domain={domain}
                route={route}
                activeRouteID={activeRouteID}
                onClose={onClose}
              />
              {route.children?.map((child) => (
                <ProductDomainFlyoutRouteLink
                  key={child.id}
                  scope={scope}
                  domain={domain}
                  route={child}
                  activeRouteID={activeRouteID}
                  child
                  onClose={onClose}
                />
              ))}
            </div>
          </details>
        );
      })}

      {riskRoutes.length ? (
        <div className="idt-domain-flyout-section">
          <span className="idt-domain-flyout-section-label">Risk</span>
          <div className="idt-domain-flyout-list">
            {riskRoutes.map((route) => (
              <ProductDomainFlyoutRouteLink
                key={route.id}
                scope={scope}
                domain={domain}
                route={route}
                activeRouteID={activeRouteID}
                onClose={onClose}
              />
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

type EnvironmentScopeState = {
  items: ProjectRecord[];
  selectedID: string;
  loading: boolean;
  error: string;
};

type EnvironmentScopeSnapshot = {
  items: ProjectRecord[];
  rejectedRequestedID: string;
  error: string;
};

const ENVIRONMENT_SCOPE_CACHE_LIMIT = 24;
const environmentScopeCache = new Map<string, EnvironmentScopeSnapshot>();
const environmentScopeRequests = new Map<string, Promise<EnvironmentScopeSnapshot>>();

function environmentScopeCacheKey(scope: ProductSession | null, requestedEnvironmentID: string): string {
  if (!scope) {
    return '';
  }
  return productScopedCacheKey([scope.tenantID, scope.workspaceID, normalizeValue(requestedEnvironmentID)]);
}

function writeEnvironmentScopeCache(key: string, snapshot: EnvironmentScopeSnapshot) {
  if (!key || !isCurrentProductScopedCacheKey(key)) {
    return;
  }
  environmentScopeCache.delete(key);
  environmentScopeCache.set(key, {
    items: snapshot.items,
    rejectedRequestedID: snapshot.rejectedRequestedID,
    error: snapshot.error
  });
  while (environmentScopeCache.size > ENVIRONMENT_SCOPE_CACHE_LIMIT) {
    const oldestKey = environmentScopeCache.keys().next().value;
    if (!oldestKey) {
      break;
    }
    environmentScopeCache.delete(oldestKey);
  }
}

function primeEnvironmentScopeCache(scope: ProductSession, projects: ProjectRecord[]) {
  const key = environmentScopeCacheKey(scope, '');
  writeEnvironmentScopeCache(key, {
    items: projects
      .slice()
      .sort((left, right) => new Date(right.updated_at).getTime() - new Date(left.updated_at).getTime())
      .slice(0, ENVIRONMENT_SELECTOR_LIMIT),
    rejectedRequestedID: '',
    error: ''
  });
}

function loadEnvironmentScopeSnapshot(
  scope: ProductSession,
  requestedEnvironmentID: string,
  auth: RequestAuthContext
): Promise<EnvironmentScopeSnapshot> {
  const cacheKey = environmentScopeCacheKey(scope, requestedEnvironmentID);
  const cached = environmentScopeCache.get(cacheKey);
  if (cached) {
    return Promise.resolve(cached);
  }
  const inFlight = environmentScopeRequests.get(cacheKey);
  if (inFlight) {
    return inFlight;
  }

  const request = (async () => {
    const requestedID = normalizeValue(requestedEnvironmentID);
    const response = await apiClient.listProjects(
      scope.workspaceID,
      {
        limit: ENVIRONMENT_SELECTOR_LIMIT,
        sort_by: 'updated_at',
        sort_order: 'desc',
        include_archived: false
      },
      auth
    );
    let nextItems = response.items ?? [];
    let rejectedID = '';
    let error = '';

    if (requestedID && !nextItems.some((item) => item.project_id === requestedID)) {
      try {
        const requestedResponse = await apiClient.getProject(scope.workspaceID, requestedID, auth);
        if (isProjectArchived(requestedResponse.project)) {
          rejectedID = requestedID;
        } else {
          nextItems = [requestedResponse.project, ...nextItems];
        }
      } catch (requestError) {
        if (isTransientProjectLookupError(requestError)) {
          const requestedErrorMessage = normalizeValue(formatAPIError(requestError, ''));
          const fallbackMessage = `Unable to verify selected environment ${requestedID}.`;
          error = requestedErrorMessage ? `${fallbackMessage} ${requestedErrorMessage}` : fallbackMessage;
        } else {
          rejectedID = requestedID;
        }
      }
    }

    return {
      items: nextItems,
      rejectedRequestedID: rejectedID,
      error
    };
  })();

  environmentScopeRequests.set(cacheKey, request);
  return request
    .then((snapshot) => {
      if (!snapshot.error) {
        writeEnvironmentScopeCache(cacheKey, snapshot);
      }
      return snapshot;
    })
    .finally(() => {
      environmentScopeRequests.delete(cacheKey);
    });
}

function useEnvironmentScope(scope: ProductSession | null, requestedEnvironmentID: string): EnvironmentScopeState {
  const cacheKey = environmentScopeCacheKey(scope, requestedEnvironmentID);
  const cachedSnapshot = cacheKey ? environmentScopeCache.get(cacheKey) : undefined;
  const [items, setItems] = useState<ProjectRecord[]>(() => cachedSnapshot?.items ?? []);
  const [loading, setLoading] = useState(Boolean(scope) && !cachedSnapshot);
  const [error, setError] = useState(() => cachedSnapshot?.error ?? '');
  const [rejectedRequestedID, setRejectedRequestedID] = useState(() => cachedSnapshot?.rejectedRequestedID ?? '');

  useEffect(() => {
    if (!scope) {
      setItems([]);
      setLoading(false);
      setError('');
      setRejectedRequestedID('');
      return undefined;
    }

    let active = true;
    const requestCacheKey = environmentScopeCacheKey(scope, requestedEnvironmentID);
    const requestSnapshot = requestCacheKey ? environmentScopeCache.get(requestCacheKey) : undefined;
    setLoading(!requestSnapshot);
    setError(requestSnapshot?.error ?? '');
    setRejectedRequestedID(requestSnapshot?.rejectedRequestedID ?? '');
    setItems(requestSnapshot?.items ?? []);

    loadEnvironmentScopeSnapshot(scope, requestedEnvironmentID, buildProductAuthContext(scope))
      .then((snapshot) => {
        if (!active || !isCurrentProductScopedCacheKey(requestCacheKey)) {
          return;
        }
        setItems(snapshot.items);
        setRejectedRequestedID(snapshot.rejectedRequestedID);
        setError(snapshot.error);
      })
      .catch((loadError) => {
        if (active && isCurrentProductScopedCacheKey(requestCacheKey)) {
          setItems([]);
          setRejectedRequestedID('');
          setError(loadError instanceof Error ? loadError.message : 'Unable to load environments.');
        }
      })
      .finally(() => {
        if (active && isCurrentProductScopedCacheKey(requestCacheKey)) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [requestedEnvironmentID, scope?.tenantID, scope?.workspaceID]);

  const requestedID = normalizeValue(requestedEnvironmentID);
  const selectedID = requestedID && rejectedRequestedID !== requestedID ? requestedID : items[0]?.project_id || '';

  return { items, selectedID, loading, error };
}

function ProductEnvironmentSelector({
  state,
  onChange
}: {
  state: EnvironmentScopeState;
  onChange: (environmentID: string) => void;
}) {
  const hasEnvironments = state.items.length > 0;
  const selectedID = normalizeValue(state.selectedID);
  const selectedIsLoaded = state.items.some((item) => item.project_id === selectedID);

  return (
    <label className="idt-environment-selector">
      <span>Environment</span>
      <select
        aria-label="Environment"
        value={selectedID}
        disabled={state.loading || (!hasEnvironments && !selectedID)}
        onChange={(event) => onChange(event.target.value)}
      >
        {selectedID && !selectedIsLoaded ? <option value={selectedID}>{environmentFallbackLabel(selectedID)}</option> : null}
        {hasEnvironments ? (
          state.items.map((item) => (
            <option key={item.project_id} value={item.project_id}>
              {projectEnvironmentLabel(item)}
            </option>
          ))
        ) : (
          <option value="">Default environment</option>
        )}
      </select>
      <small>{state.loading ? 'Loading...' : state.error ? state.error : selectedID ? 'Active scope' : 'Default environment'}</small>
    </label>
  );
}

function ProductRouteReadinessList({ route }: { route: ProductDomainRoute }) {
  return (
    <section className="idt-domain-status-panel idt-domain-readiness-list" aria-label={`${route.title} route readiness`}>
      <header>
        <div>
          <p className="idt-app-kicker">Sequenced delivery</p>
          <h3>What lands here next</h3>
        </div>
        <span>Planned</span>
      </header>
      <div className="idt-domain-readiness-items">
        {route.plannedWork.map((row) => (
          <article key={row.capability}>
            <div>
              <strong>{row.capability}</strong>
              <p>{row.route}</p>
            </div>
            <span>{formatTokenLabel(row.readiness)}</span>
          </article>
        ))}
      </div>
    </section>
  );
}

type AWSCapabilityStage = 'wired' | 'coming' | 'not-available';

type AWSControlCard = {
  id: string;
  label: string;
  routeID: ProductDomainRouteID;
  stage: AWSCapabilityStage;
  metric: string;
  detail: string;
};

// AWS_CONTROL_CARDS is the source of truth for what surfaces this app
// actually has today. New surfaces appear here when they ship — that is the
// mechanism for "feature shipping" since the page no longer carries a
// roadmap-in-UI ("Wired now" / "Coming wave"). Pre-ship surfaces stay out
// of the array (or are added with a `featureFlag` gate) so users never see
// a placeholder card for something that doesn't work.
const AWS_CONTROL_CARDS: AWSControlCard[] = [
  {
    id: 'connect',
    label: 'Connection',
    routeID: 'connect',
    stage: 'wired',
    metric: '',
    detail: 'Manage the AWS connection for this environment.'
  },
  {
    id: 'accounts',
    label: 'Accounts',
    routeID: 'accounts',
    stage: 'coming',
    metric: '',
    detail: "Which AWS account and region you're connected to."
  },
  {
    id: 'identities',
    label: 'Identities',
    routeID: 'identities',
    stage: 'coming',
    metric: '',
    detail: 'IAM roles, workload identities, and what they can reach.'
  },
  {
    id: 'agents',
    label: 'Agents',
    routeID: 'agents',
    stage: 'coming',
    metric: '',
    detail: 'Bedrock and MCP agents Identrail can see.'
  },
  {
    id: 'resources',
    label: 'Resources',
    routeID: 'resources',
    stage: 'coming',
    metric: '',
    detail: 'Secrets, KMS keys, and S3 buckets your AWS roles can reach.'
  },
  {
    id: 'runtime',
    label: 'Runtime',
    routeID: 'runtime',
    stage: 'coming',
    metric: '',
    detail: 'What your AWS roles actually did, from CloudTrail.'
  },
  {
    id: 'findings',
    label: 'Findings',
    routeID: 'findings',
    stage: 'not-available',
    metric: '',
    detail: 'Risks Identrail found in your AWS setup.'
  },
  {
    id: 'remediation',
    label: 'Remediation',
    routeID: 'remediation',
    stage: 'not-available',
    metric: '',
    detail: 'AWS fixes Identrail prepares for you to approve.'
  }
];

function awsStageLabel(stage: AWSCapabilityStage): string {
  if (stage === 'wired') {
    return 'Wired now';
  }
  if (stage === 'coming') {
    return 'Coming';
  }
  return 'Not yet available';
}

function awsStageTone(stage: AWSCapabilityStage): 'success' | 'warning' | 'neutral' {
  if (stage === 'wired') {
    return 'success';
  }
  if (stage === 'coming') {
    return 'warning';
  }
  return 'neutral';
}

function awsDomainTone(connection: AWSConnectionStatus | null, loading = false): 'success' | 'warning' | 'danger' | 'neutral' | 'info' {
  if (loading) {
    return 'info';
  }
  const tone = connectionTone(connection ?? undefined);
  if (tone === 'error') {
    return 'danger';
  }
  if (tone === 'success' || tone === 'warning') {
    return tone;
  }
  return 'neutral';
}

function awsStatusVariant(connection: AWSConnectionStatus | null): 'connected' | 'disconnected' | 'degraded' | 'missing-permissions' {
  if (!connection) {
    return 'disconnected';
  }
  const failedChecks = connection.permission_checks.filter((check) => !check.passed).length;
  if (failedChecks > 0) {
    return 'missing-permissions';
  }
  if (connection.health_status === 'warning' || connection.status === 'degraded') {
    return 'degraded';
  }
  return connection.connected ? 'connected' : 'disconnected';
}

function awsPermissionSummary(connection: AWSConnectionStatus | null): string {
  if (!connection || connection.permission_checks.length === 0) {
    return 'Not validated';
  }
  const passed = connection.permission_checks.filter((check) => check.passed).length;
  return `${passed}/${connection.permission_checks.length} passed`;
}

function awsDiagnosticSummary(connection: AWSConnectionStatus | null): string {
  if (!connection || connection.diagnostics.length === 0) {
    return connection?.connected ? 'Clear' : 'No diagnostics';
  }
  return formatCountLabel(connection.diagnostics.length, 'item');
}

function awsBaselineLabel(baseline: AWSPlatformBaselineResult | null): string {
  if (!baseline) {
    return 'Not verified';
  }
  if (baseline.status === 'ready') {
    return 'Ready';
  }
  if (baseline.status === 'degraded') {
    return 'Degraded';
  }
  if (baseline.status === 'blocked') {
    return 'Blocked';
  }
  return 'Not run';
}

function awsBaselineTone(
  baseline: AWSPlatformBaselineResult | null,
  loading = false
): 'success' | 'warning' | 'danger' | 'neutral' | 'info' {
  if (loading) {
    return 'info';
  }
  if (!baseline) {
    return 'neutral';
  }
  if (baseline.status === 'ready') {
    return 'success';
  }
  if (baseline.status === 'degraded' || baseline.status === 'not_run') {
    return 'warning';
  }
  return 'danger';
}

function awsBaselineCheckTone(status: AWSPlatformBaselineResult['checks'][number]['status']): 'success' | 'warning' | 'error' | 'neutral' {
  if (status === 'passed') {
    return 'success';
  }
  if (status === 'failed' || status === 'permission_denied') {
    return 'error';
  }
  if (status === 'degraded') {
    return 'warning';
  }
  return 'neutral';
}

function awsBaselineSummary(baseline: AWSPlatformBaselineResult | null): string {
  if (!baseline) {
    return 'No verification';
  }
  if (baseline.status === 'ready') {
    return `${formatConfidenceScore(baseline.confidence)} confidence`;
  }
  return baseline.failure_reasons[0] ? formatTokenLabel(baseline.failure_reasons[0]) : formatTokenLabel(baseline.status);
}

function awsBaselineAccountRegionLabel(baseline: AWSPlatformBaselineResult | null): string {
  if (!baseline?.account_id && !baseline?.region) {
    return 'Pending';
  }
  return [baseline.account_id ? `Account ${baseline.account_id}` : '', baseline.region ? `Region ${baseline.region}` : '']
    .filter(Boolean)
    .join(' · ');
}

function awsAccountRegionLabel(connection: AWSConnectionStatus | null): string {
  if (!connection?.account_id && !connection?.region) {
    return 'Pending';
  }
  return [connection.account_id ? `Account ${connection.account_id}` : '', connection.region ? `Region ${connection.region}` : '']
    .filter(Boolean)
    .join(' · ');
}

function awsConnectionLabel(connection: AWSConnectionStatus | null): string {
  if (!connection) {
    return 'Not loaded';
  }
  return connection.connected ? 'Connected' : connectionLifecycle(connection);
}

function awsRouteLink(scope: ProductSession, routeID: ProductDomainRouteID, environmentID: string): string {
  return appendEnvironmentQuery(domainRoutePath(scope, 'aws', findDomainRoute('aws', routeID)), environmentID);
}

function AWSConnectionDiagnostics({
  connection,
  emptyLabel = 'No diagnostics reported for this environment.'
}: {
  connection: AWSConnectionStatus | null;
  emptyLabel?: string;
}) {
  if (!connection) {
    return (
      <article>
        <strong>Connection not loaded</strong>
        <span>Waiting</span>
        <p>Select an environment to load AWS status.</p>
      </article>
    );
  }

  const checks = connection.permission_checks;
  const diagnostics = connection.diagnostics;

  if (checks.length === 0 && diagnostics.length === 0) {
    return (
      <article>
        <strong>AWS diagnostics</strong>
        <span>{connection.connected ? 'Clear' : 'Pending'}</span>
        <p>{emptyLabel}</p>
      </article>
    );
  }

  return (
    <>
      {checks.map((check) => (
        <article key={check.name}>
          <strong>{check.name}</strong>
          <span className={`idt-source-status-pill is-${check.passed ? 'success' : 'warning'}`}>
            {check.passed ? 'Passed' : 'Needs attention'}
          </span>
          <p>{check.message}</p>
          {check.remediation ? <small>{check.remediation}</small> : null}
        </article>
      ))}
      {diagnostics.map((diagnostic, index) => (
        <article key={`${diagnostic.code}-${index}`}>
          <strong>{formatTokenLabel(diagnostic.code)}</strong>
          <span className="idt-source-status-pill is-warning">Diagnostic</span>
          <p>{diagnostic.message}</p>
          {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
        </article>
      ))}
    </>
  );
}

function AWSBaselineGateSummary({
  baseline,
  loading = false,
  emptyLabel = 'AWS baseline has not run for this environment.'
}: {
  baseline: AWSPlatformBaselineResult | null;
  loading?: boolean;
  emptyLabel?: string;
}) {
  if (loading) {
    return (
      <article>
        <strong>AWS baseline gate</strong>
        <span className="idt-source-status-pill is-neutral">Loading</span>
        <p>Loading baseline checks.</p>
      </article>
    );
  }
  if (!baseline) {
    return (
      <article>
        <strong>AWS baseline gate</strong>
        <span className="idt-source-status-pill is-neutral">Not run</span>
        <p>{emptyLabel}</p>
      </article>
    );
  }
  if (baseline.checks.length === 0) {
    return (
      <article>
        <strong>AWS baseline gate</strong>
        <span className={`idt-source-status-pill is-${baseline.status === 'ready' ? 'success' : 'warning'}`}>
          {awsBaselineLabel(baseline)}
        </span>
        <p>{awsBaselineSummary(baseline)}</p>
      </article>
    );
  }
  return (
    <>
      {baseline.checks.map((check) => (
        <article key={check.name}>
          <strong>{formatTokenLabel(check.name)}</strong>
          <span className={`idt-source-status-pill is-${awsBaselineCheckTone(check.status)}`}>{formatTokenLabel(check.status)}</span>
          <p>{check.message}</p>
          <small>
            {check.required ? 'Required' : 'Optional'} · confidence {formatConfidenceScore(check.confidence)} ·{' '}
            {formatConnectionTime(check.checked_at)}
          </small>
          {check.failure_reason ? <small>{formatTokenLabel(check.failure_reason)}</small> : null}
          {check.remediation ? <small>{check.remediation}</small> : null}
          {check.evidence_url ? (
            <a href={check.evidence_url} target={check.evidence_url.startsWith('http') ? '_blank' : undefined} rel="noreferrer">
              Evidence
            </a>
          ) : null}
        </article>
      ))}
    </>
  );
}

function awsDependencyIndexLabel(index: AWSPlatformDependencyIndexResult | null): string {
  if (!index) {
    return 'Not loaded';
  }
  if (index.status === 'ready') {
    return 'Ready';
  }
  if (index.status === 'degraded') {
    return 'Degraded';
  }
  return 'Blocked';
}

function awsDependencyIndexTone(
  index: AWSPlatformDependencyIndexResult | null,
  loading = false
): 'success' | 'warning' | 'danger' | 'neutral' | 'info' {
  if (loading) {
    return 'info';
  }
  if (!index) {
    return 'neutral';
  }
  if (index.status === 'ready') {
    return 'success';
  }
  if (index.status === 'degraded') {
    return 'warning';
  }
  return 'danger';
}

function awsDependencyCheckTone(status: AWSPlatformDependencyIndexResult['checks'][number]['status']): 'success' | 'warning' | 'error' | 'neutral' {
  if (status === 'ready') {
    return 'success';
  }
  if (status === 'degraded') {
    return 'warning';
  }
  if (status === 'blocked') {
    return 'error';
  }
  return 'neutral';
}

function awsDependencyIndexSummary(index: AWSPlatformDependencyIndexResult | null): string {
  if (!index) {
    return 'No ledger loaded';
  }
  return `${formatCountLabel(index.ready_issue_count, 'ready issue')} · ${formatCountLabel(index.blocked_issue_count, 'blocked issue')} · ${formatCountLabel(
    index.completed_issue_refs.length,
    'completed issue'
  )}`;
}

function AWSDependencyIndexSummary({
  index,
  loading = false,
  emptyLabel = 'Dependency index has not loaded for this environment.'
}: {
  index: AWSPlatformDependencyIndexResult | null;
  loading?: boolean;
  emptyLabel?: string;
}) {
  if (loading) {
    return (
      <article>
        <strong>AWS dependency index</strong>
        <span className="idt-source-status-pill is-neutral">Loading</span>
        <p>Loading issue sequencing checks.</p>
      </article>
    );
  }
  if (!index) {
    return (
      <article>
        <strong>AWS dependency index</strong>
        <span className="idt-source-status-pill is-neutral">Not loaded</span>
        <p>{emptyLabel}</p>
      </article>
    );
  }
  const readyRefs = index.ready_issue_refs.slice(0, 5);
  return (
    <>
      <article>
        <strong>Next ready issues</strong>
        <span className="idt-source-status-pill is-success">Ready</span>
        <p>{readyRefs.length ? readyRefs.join(', ') : 'No issue is currently ready.'}</p>
        <small>{awsDependencyIndexSummary(index)}</small>
      </article>
      {index.checks.map((check) => (
        <article key={check.name}>
          <strong>{formatTokenLabel(check.name)}</strong>
          <span className={`idt-source-status-pill is-${awsDependencyCheckTone(check.status)}`}>{formatTokenLabel(check.status)}</span>
          <p>{check.message}</p>
          <small>
            {check.required ? 'Required' : 'Optional'} · confidence {formatConfidenceScore(check.confidence)} ·{' '}
            {formatConnectionTime(check.checked_at)}
          </small>
          {check.failure_reason ? <small>{formatTokenLabel(check.failure_reason)}</small> : null}
          {check.remediation ? <small>{check.remediation}</small> : null}
          {check.evidence_url ? (
            <a href={check.evidence_url} target={check.evidence_url.startsWith('http') ? '_blank' : undefined} rel="noreferrer">
              Evidence
            </a>
          ) : null}
        </article>
      ))}
    </>
  );
}

function awsValidationHarnessLabel(harness: AWSPlatformValidationHarnessResult | null): string {
  if (!harness) {
    return 'Not loaded';
  }
  if (harness.status === 'ready') {
    return 'Ready';
  }
  if (harness.status === 'degraded') {
    return 'Degraded';
  }
  return 'Blocked';
}

function awsValidationHarnessTone(
  harness: AWSPlatformValidationHarnessResult | null,
  loading = false
): 'success' | 'warning' | 'danger' | 'neutral' | 'info' {
  if (loading) {
    return 'info';
  }
  if (!harness) {
    return 'neutral';
  }
  if (harness.status === 'ready') {
    return 'success';
  }
  if (harness.status === 'degraded') {
    return 'warning';
  }
  return 'danger';
}

function awsValidationHarnessSummary(harness: AWSPlatformValidationHarnessResult | null): string {
  if (!harness) {
    return 'No app proof loaded';
  }
  return `${formatCountLabel(harness.scenario_count, 'scenario')} · ${formatCountLabel(
    harness.browser_steps.length,
    'browser step'
  )} · ${formatCountLabel(harness.api_steps.length, 'API step')}`;
}

function awsValidationFixtureTone(
  state: AWSPlatformValidationHarnessResult['scenarios'][number]['fixture_state']
): 'success' | 'warning' | 'error' | 'neutral' {
  if (state === 'success') {
    return 'success';
  }
  if (state === 'empty') {
    return 'neutral';
  }
  if (state === 'permission_denied') {
    return 'error';
  }
  return 'warning';
}

function awsValidationHarnessStatusPillTone(status: AWSPlatformValidationHarnessResult['status']): 'success' | 'warning' | 'error' {
  if (status === 'ready') {
    return 'success';
  }
  if (status === 'degraded') {
    return 'warning';
  }
  return 'error';
}

function AWSValidationHarnessSummary({
  harness,
  loading = false,
  emptyLabel = 'Validation harness has not loaded for this environment.'
}: {
  harness: AWSPlatformValidationHarnessResult | null;
  loading?: boolean;
  emptyLabel?: string;
}) {
  if (loading) {
    return (
      <article>
        <strong>AWS validation harness</strong>
        <span className="idt-source-status-pill is-neutral">Loading</span>
        <p>Loading app proof states.</p>
      </article>
    );
  }
  if (!harness) {
    return (
      <article>
        <strong>AWS validation harness</strong>
        <span className="idt-source-status-pill is-neutral">Not loaded</span>
        <p>{emptyLabel}</p>
      </article>
    );
  }
  return (
    <>
      <article>
        <strong>Fixture coverage</strong>
        <span className={`idt-source-status-pill is-${awsValidationHarnessStatusPillTone(harness.status)}`}>
          {formatTokenLabel(harness.status)}
        </span>
        <p>{harness.fixture_states.map(formatTokenLabel).join(', ')}</p>
        <small>{awsValidationHarnessSummary(harness)}</small>
      </article>
      {harness.scenarios.map((scenario) => (
        <article key={scenario.id}>
          <strong>{scenario.label}</strong>
          <span className={`idt-source-status-pill is-${awsValidationFixtureTone(scenario.fixture_state)}`}>
            {formatTokenLabel(scenario.fixture_state)}
          </span>
          <p>{scenario.summary}</p>
          <small>
            {formatTokenLabel(scenario.flow)} · confidence {formatConfidenceScore(scenario.confidence)} ·{' '}
            {formatConnectionTime(scenario.checked_at)}
          </small>
          {scenario.failure_reason ? <small>{formatTokenLabel(scenario.failure_reason)}</small> : null}
          {scenario.remediation ? <small>{scenario.remediation}</small> : null}
          {scenario.evidence_url ? (
            <a href={scenario.evidence_url} target={scenario.evidence_url.startsWith('http') ? '_blank' : undefined} rel="noreferrer">
              Evidence
            </a>
          ) : null}
        </article>
      ))}
    </>
  );
}

function awsServiceCollectorContractLabel(contract: AWSServiceCollectorContractResult | null): string {
  if (!contract) {
    return 'Not loaded';
  }
  if (contract.status === 'ready') {
    return 'Ready';
  }
  if (contract.status === 'degraded') {
    return 'Degraded';
  }
  return 'Blocked';
}

function awsServiceCollectorContractTone(
  contract: AWSServiceCollectorContractResult | null,
  loading = false
): 'success' | 'warning' | 'danger' | 'neutral' | 'info' {
  if (loading) {
    return 'info';
  }
  if (!contract) {
    return 'neutral';
  }
  if (contract.status === 'ready') {
    return 'success';
  }
  if (contract.status === 'degraded') {
    return 'warning';
  }
  return 'danger';
}

function awsServiceCollectorContractSummary(contract: AWSServiceCollectorContractResult | null): string {
  if (!contract) {
    return 'No collector contract loaded';
  }
  return `${formatCountLabel(contract.required_field_count, 'field')} · ${formatCountLabel(
    contract.fixture_case_count,
    'fixture'
  )} · ${formatCountLabel(contract.graph_edge_count, 'edge')}`;
}

function awsServiceCollectorCheckTone(status: AWSServiceCollectorContractResult['checks'][number]['status']): 'success' | 'warning' | 'error' | 'neutral' {
  if (status === 'ready') {
    return 'success';
  }
  if (status === 'degraded') {
    return 'warning';
  }
  if (status === 'blocked') {
    return 'error';
  }
  return 'neutral';
}

function awsServiceCollectorFixtureTone(
  status: AWSServiceCollectorContractResult['fixture_cases'][number]['expected_status']
): 'success' | 'warning' | 'error' | 'neutral' {
  if (status === 'ready') {
    return 'success';
  }
  if (status === 'degraded') {
    return 'warning';
  }
  if (status === 'blocked') {
    return 'error';
  }
  return 'neutral';
}

function AWSServiceCollectorContractSummary({
  contract,
  loading = false,
  emptyLabel = 'Collector contract has not loaded for this environment.'
}: {
  contract: AWSServiceCollectorContractResult | null;
  loading?: boolean;
  emptyLabel?: string;
}) {
  if (loading) {
    return (
      <article>
        <strong>AWS collector contract</strong>
        <span className="idt-source-status-pill is-neutral">Loading</span>
        <p>Loading collector contract checks.</p>
      </article>
    );
  }
  if (!contract) {
    return (
      <article>
        <strong>AWS collector contract</strong>
        <span className="idt-source-status-pill is-neutral">Not loaded</span>
        <p>{emptyLabel}</p>
      </article>
    );
  }
  return (
    <>
      <article>
        <strong>Normalized record</strong>
        <span className={`idt-source-status-pill is-${awsServiceCollectorCheckTone(contract.status)}`}>
          {formatTokenLabel(contract.status)}
        </span>
        <p>{contract.normalized_record_fields.slice(0, 8).map(formatTokenLabel).join(', ')}</p>
        <small>{awsServiceCollectorContractSummary(contract)}</small>
      </article>
      {contract.checks.map((check) => (
        <article key={check.name}>
          <strong>{formatTokenLabel(check.name)}</strong>
          <span className={`idt-source-status-pill is-${awsServiceCollectorCheckTone(check.status)}`}>{formatTokenLabel(check.status)}</span>
          <p>{check.message}</p>
          <small>
            {check.required ? 'Required' : 'Optional'} · confidence {formatConfidenceScore(check.confidence)} ·{' '}
            {formatConnectionTime(check.checked_at)}
          </small>
          {check.failure_reason ? <small>{formatTokenLabel(check.failure_reason)}</small> : null}
          {check.remediation ? <small>{check.remediation}</small> : null}
          {check.evidence_url ? (
            <a href={check.evidence_url} target={check.evidence_url.startsWith('http') ? '_blank' : undefined} rel="noreferrer">
              Evidence
            </a>
          ) : null}
        </article>
      ))}
      {contract.fixture_cases.map((fixture) => (
        <article key={fixture.id}>
          <strong>{fixture.label}</strong>
          <span className={`idt-source-status-pill is-${awsServiceCollectorFixtureTone(fixture.expected_status)}`}>
            {formatTokenLabel(fixture.state)}
          </span>
          <p>{fixture.evidence_boundary}</p>
          <small>{fixture.source_error_code ? formatTokenLabel(fixture.source_error_code) : 'No source error expected'}</small>
        </article>
      ))}
      {contract.graph_edges.map((edge) => (
        <article key={edge.name}>
          <strong>{edge.name}</strong>
          <span className="idt-source-status-pill is-neutral">{formatTokenLabel(edge.relationship_type)}</span>
          <p>{edge.evidence}</p>
          <small>
            {formatTokenLabel(edge.from_endpoint)} to {formatTokenLabel(edge.to_endpoint)}
          </small>
        </article>
      ))}
    </>
  );
}

type AWSInventoryRouteID = Extract<ProductDomainRouteID, 'accounts' | 'identities' | 'agents' | 'resources'>;

type AWSInventoryPageCopy = {
  routeID: AWSInventoryRouteID;
  title: string;
  eyebrow: string;
  description: string;
  statusLabel: string;
  primaryKpi: string;
  currentCapability: string;
  plannedCapability: string;
};

const AWS_INVENTORY_PAGE_COPY: Record<AWSInventoryRouteID, AWSInventoryPageCopy> = {
  accounts: {
    routeID: 'accounts',
    title: 'Accounts',
    eyebrow: '',
    description: "Which AWS account and region you're connected to.",
    statusLabel: '',
    primaryKpi: 'Account scope',
    currentCapability: '',
    plannedCapability: ''
  },
  identities: {
    routeID: 'identities',
    title: 'Identities',
    eyebrow: '',
    description: 'IAM roles, workload identities, and what they can reach.',
    statusLabel: '',
    primaryKpi: 'Identity anchor',
    currentCapability: '',
    plannedCapability: ''
  },
  agents: {
    routeID: 'agents',
    title: 'Agents',
    eyebrow: '',
    description: 'Bedrock and MCP agents Identrail can see.',
    statusLabel: '',
    primaryKpi: 'Agent graph',
    currentCapability: '',
    plannedCapability: ''
  },
  resources: {
    routeID: 'resources',
    title: 'Resources',
    eyebrow: '',
    description: 'Secrets, KMS keys, and S3 buckets your AWS roles can reach.',
    statusLabel: '',
    primaryKpi: 'Resource scope',
    currentCapability: '',
    plannedCapability: ''
  }
};

type AWSInventoryDataState = {
  scope: ProductSession | null;
  environmentScope: EnvironmentScopeState;
  selectedEnvironmentID: string;
  connection: AWSConnectionStatus | null;
  connectionLoading: boolean;
  connectionError: string;
  onChangeEnvironment: (environmentID: string) => void;
  refreshConnection: () => void;
};

type AWSInventoryFilterState = Record<string, string>;

type AWSInventoryFilterConfigOption = {
  label: string;
  value: string;
};

type AWSInventoryFilterConfig = {
  id: string;
  label: string;
  options: AWSInventoryFilterConfigOption[];
};

type AWSInventoryFilterConfigMap = Record<AWSInventoryRouteID, AWSInventoryFilterConfig[]>;

type AWSInventoryFilterable = {
  filters: Record<string, string>;
  searchText: string;
};

type AWSInventoryTableRow = AWSInventoryFilterable & {
  id: string;
  name: string;
  category: string;
  scope: string;
  status: string;
  stage: AWSCapabilityStage;
  detail: string;
};

type AWSInventoryEC2State = {
  inventory: AWSEC2InstanceProfileInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryECSState = {
  inventory: AWSECSTaskRoleInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryLambdaState = {
  inventory: AWSLambdaExecutionRoleInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryCodeBuildState = {
  inventory: AWSCodeBuildServiceRoleInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryCodePipelineState = {
  inventory: AWSCodePipelineDeploymentRoleInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryStepFunctionsState = {
  inventory: AWSStepFunctionsStateMachineRoleInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryEKSState = {
  inventory: AWSEKSWorkloadIdentityInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryCoverageRow = AWSInventoryFilterable & {
  id: string;
  category: string;
  coverage: string;
  source: string;
  status: string;
  detail: string;
};

const AWS_INVENTORY_FILTER_DEFAULTS: Record<AWSInventoryRouteID, AWSInventoryFilterState> = {
  accounts: { account: 'all', region: 'all', coverage: 'all', search: '' },
  identities: { identityType: 'all', service: 'all', risk: 'all', status: 'all', search: '' },
  agents: { surface: 'all', relationship: 'all', status: 'all', search: '' },
  resources: { category: 'all', sensitivity: 'all', readPosture: 'all', search: '' }
};

const AWS_INVENTORY_FILTERS: AWSInventoryFilterConfigMap = {
  accounts: [
    { id: 'account', label: 'Account', options: [{ label: 'All accounts', value: 'all' }, { label: 'Connected account', value: 'connected' }, { label: 'Planned accounts', value: 'planned' }] },
    { id: 'region', label: 'Region', options: [{ label: 'All regions', value: 'all' }, { label: 'Current region', value: 'current' }, { label: 'Uncovered regions', value: 'uncovered' }] },
    {
      id: 'coverage',
      label: 'Coverage',
      options: [
        { label: 'All coverage', value: 'all' },
        { label: 'Covered', value: 'covered' },
        { label: 'Missing', value: 'missing' },
        { label: 'Degraded', value: 'degraded' },
        { label: 'Not yet available', value: 'not-yet-available' }
      ]
    }
  ],
  identities: [
    {
      id: 'identityType',
      label: 'Identity type',
      options: [
        { label: 'All types', value: 'all' },
        { label: 'IAM role', value: 'iam-role' },
        { label: 'Instance profile', value: 'instance-profile' },
        { label: 'ECS task role', value: 'ecs-task-role' },
        { label: 'Lambda role', value: 'lambda-role' },
        { label: 'CodeBuild role', value: 'codebuild-role' },
        { label: 'CodePipeline role', value: 'codepipeline-role' },
        { label: 'Step Functions role', value: 'stepfunctions-role' },
        { label: 'EKS identity', value: 'eks-identity' },
        { label: 'CI/CD role', value: 'cicd-role' }
      ]
    },
    { id: 'service', label: 'Service', options: [{ label: 'All services', value: 'all' }, { label: 'IAM', value: 'iam' }, { label: 'EC2', value: 'ec2' }, { label: 'ECS', value: 'ecs' }, { label: 'Lambda', value: 'lambda' }, { label: 'CodeBuild', value: 'codebuild' }, { label: 'CodePipeline', value: 'codepipeline' }, { label: 'Step Functions', value: 'stepfunctions' }, { label: 'EKS', value: 'eks' }, { label: 'OIDC', value: 'oidc' }] },
    {
      id: 'risk',
      label: 'Risk',
      options: [{ label: 'All risk', value: 'all' }, { label: 'Unscored', value: 'unscored' }, { label: 'High', value: 'high' }, { label: 'Medium', value: 'medium' }, { label: 'Low', value: 'low' }]
    },
    {
      id: 'status',
      label: 'Status',
      options: [
        { label: 'All status', value: 'all' },
        { label: 'Wired now', value: 'wired-now' },
        { label: 'Degraded', value: 'degraded' },
        { label: 'Coming', value: 'coming' },
        { label: 'Not yet available', value: 'not-yet-available' }
      ]
    }
  ],
  agents: [
    {
      id: 'surface',
      label: 'Agent surface',
      options: [
        { label: 'All surfaces', value: 'all' },
        { label: 'Bedrock agents', value: 'bedrock-agents' },
        { label: 'AgentCore runtime', value: 'agentcore-runtime' },
        { label: 'MCP gateway', value: 'mcp-gateway' },
        { label: 'External provider keys', value: 'external-provider-keys' }
      ]
    },
    {
      id: 'relationship',
      label: 'Relationship',
      options: [
        { label: 'All relationships', value: 'all' },
        { label: 'Agent to role', value: 'agent-to-role' },
        { label: 'Agent to tool', value: 'agent-to-tool' },
        { label: 'Agent to secret', value: 'agent-to-secret' }
      ]
    },
    {
      id: 'status',
      label: 'Status',
      options: [{ label: 'All status', value: 'all' }, { label: 'Role anchor', value: 'role-anchor' }, { label: 'Coming', value: 'coming' }, { label: 'Not yet available', value: 'not-yet-available' }]
    }
  ],
  resources: [
    {
      id: 'category',
      label: 'Category',
      options: [
        { label: 'All categories', value: 'all' },
        { label: 'Secrets Manager', value: 'secrets-manager' },
        { label: 'SSM Parameter', value: 'ssm-parameter' },
        { label: 'KMS', value: 'kms' },
        { label: 'S3', value: 's3' },
        { label: 'Control plane', value: 'control-plane' }
      ]
    },
    {
      id: 'sensitivity',
      label: 'Sensitivity',
      options: [
        { label: 'All sensitivity', value: 'all' },
        { label: 'Credential reference', value: 'credential-reference' },
        { label: 'Customer data', value: 'customer-data' },
        { label: 'Secret-bearing', value: 'secret-bearing' },
        { label: 'KMS-admin', value: 'kms-admin' },
        { label: 'Control-plane', value: 'control-plane' }
      ]
    },
    {
      id: 'readPosture',
      label: 'Read posture',
      options: [{ label: 'All postures', value: 'all' }, { label: 'Metadata only', value: 'metadata-only' }, { label: 'No secret values', value: 'no-secret-values' }]
    }
  ]
};

function normalizeFilterValue(value: string): string {
  return value.trim().toLowerCase();
}

function matchesFilterCell(rowValue: string | undefined, selectedValue: string): boolean {
  const normalizedSelectedValue = normalizeFilterValue(selectedValue);
  if (!rowValue) {
    return false;
  }
  const values = rowValue
    .split(',')
    .map((value) => normalizeFilterValue(value))
    .filter((value) => value.length > 0);
  return values.includes(normalizedSelectedValue);
}

function inventorySearchText(parts: Array<string | undefined>): string {
  return parts
    .filter((value): value is string => Boolean(value && value.length > 0))
    .join(' ')
    .toLowerCase();
}

function filterAWSInventoryRows<RowType extends AWSInventoryFilterable>(rows: RowType[], filters: AWSInventoryFilterState): RowType[] {
  const query = normalizeFilterValue(filters.search ?? '');
  return rows.filter((row) => {
    for (const [filterID, selectedValue] of Object.entries(filters)) {
      if (filterID === 'search') {
        continue;
      }
      if (!selectedValue || selectedValue === 'all') {
        continue;
      }
      if (!matchesFilterCell(row.filters[filterID], selectedValue)) {
        return false;
      }
    }
    if (!query) {
      return true;
    }
    return row.searchText.includes(query);
  });
}

function useAWSInventoryData(): AWSInventoryDataState {
  const params = useParams<ScopeRouteParams>();
  const location = useLocation();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);
  const requestedEnvironmentID = useMemo(() => environmentIDFromSearch(location.search), [location.search]);
  const environmentScope = useEnvironmentScope(scope, requestedEnvironmentID);
  const selectedEnvironmentID = environmentScope.selectedID;
  const [connection, setConnection] = useState<AWSConnectionStatus | null>(null);
  const [connectionLoading, setConnectionLoading] = useState(false);
  const [connectionError, setConnectionError] = useState('');
  const connectionRequestRef = useRef(0);
  const selectedEnvironmentIDRef = useRef(selectedEnvironmentID);
  const scopeKey = scope ? `${scope.tenantID}::${scope.workspaceID}` : '';
  const scopeKeyRef = useRef(scopeKey);
  selectedEnvironmentIDRef.current = selectedEnvironmentID;
  scopeKeyRef.current = scopeKey;

  const refreshConnection = useCallback(async () => {
    const requestID = ++connectionRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    const requestScopeKey = scopeKeyRef.current;
    setConnection(null);
    setConnectionError('');
    if (!scope || !requestEnvironmentID) {
      setConnectionLoading(false);
      return;
    }
    const isStale = () =>
      requestID !== connectionRequestRef.current ||
      selectedEnvironmentIDRef.current !== requestEnvironmentID ||
      scopeKeyRef.current !== requestScopeKey;
    setConnectionLoading(true);
    setConnectionError('');
    try {
      const response = await apiClient.getAWSProjectConnection(
        scope.workspaceID,
        requestEnvironmentID,
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setConnection(response.connection);
    } catch (error) {
      if (isStale()) {
        return;
      }
      setConnection(null);
      setConnectionError(formatAPIError(error, 'Unable to load AWS inventory status.'));
    } finally {
      if (!isStale()) {
        setConnectionLoading(false);
      }
    }
  }, [scope?.tenantID, scope?.workspaceID, selectedEnvironmentID]);

  useEffect(() => {
    void refreshConnection();
    return () => {
      connectionRequestRef.current += 1;
    };
  }, [refreshConnection]);

  const onChangeEnvironment = useCallback(
    (environmentID: string) => {
      connectionRequestRef.current += 1;
      setConnection(null);
      setConnectionError('');
      navigate(
        {
          pathname: location.pathname,
          search: environmentSearch(location.search, environmentID)
        },
        { replace: false }
      );
    },
    [location.pathname, location.search, navigate]
  );

  return {
    scope,
    environmentScope,
    selectedEnvironmentID,
    connection,
    connectionLoading,
    connectionError,
    onChangeEnvironment,
    refreshConnection: () => void refreshConnection()
  };
}

function awsCoverageState(connection: AWSConnectionStatus | null): string {
  if (!connection) {
    return 'missing';
  }
  if (!connection.connected) {
    return 'degraded';
  }
  if (connection.health_status === 'warning' || connection.status === 'degraded') {
    return 'degraded';
  }
  if (connection.permission_checks.some((check) => !check.passed)) {
    return 'degraded';
  }
  return 'covered';
}

function awsInventoryPillTone(stage: AWSCapabilityStage): 'success' | 'warning' | 'neutral' {
  return awsStageTone(stage);
}

function AWSInventoryPill({
  stage,
  label
}: {
  stage: AWSCapabilityStage;
  label?: string;
}) {
  return <span className={`idt-aws-inventory-pill is-${awsInventoryPillTone(stage)}`}>{label ?? awsStageLabel(stage)}</span>;
}

function AWSInventoryFilterSet({
  routeID,
  filters,
  onChange
}: {
  routeID: AWSInventoryRouteID;
  filters: AWSInventoryFilterState;
  onChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const searchPlaceholder: Record<AWSInventoryRouteID, string> = {
    accounts: 'Search account or region',
    identities: 'Search identity ARN',
    agents: 'Search agent surface',
    resources: 'Search resource metadata'
  };
  const onFilterChange = (id: string, value: string): void => {
    onChange({
      ...filters,
      [id]: value
    });
  };
  const onSearchChange = (event: ChangeEvent<HTMLInputElement>): void => {
    onChange({
      ...filters,
      search: event.target.value
    });
  };

  return (
    <DomainFilterBar label={`${AWS_INVENTORY_PAGE_COPY[routeID].title} filters`}>
      {AWS_INVENTORY_FILTERS[routeID].map((filter) => (
        <label key={filter.label}>
          {filter.label}
          <select value={filters[filter.id] ?? 'all'} onChange={(event) => onFilterChange(filter.id, event.target.value)}>
            {filter.options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      ))}
      <label>
        Search
        <input
          placeholder={searchPlaceholder[routeID]}
          value={filters.search ?? ''}
          onChange={onSearchChange}
          aria-label={`${AWS_INVENTORY_PAGE_COPY[routeID].title} search`}
        />
      </label>
    </DomainFilterBar>
  );
}

function buildAWSInventoryKpis(routeID: AWSInventoryRouteID, connection: AWSConnectionStatus | null) {
  const permissionTotal = connection?.permission_checks.length ?? 0;
  const permissionPassed = connection?.permission_checks.filter((check) => check.passed).length ?? 0;
  const primaryValue =
    routeID === 'accounts'
      ? connection?.account_id
        ? '1 account'
        : 'Pending'
      : routeID === 'identities'
        ? connection?.role_arn
          ? '1 role'
          : 'Pending'
        : routeID === 'agents'
          ? 'Reserved'
          : 'Metadata only';

  return [
    {
      label: AWS_INVENTORY_PAGE_COPY[routeID].primaryKpi,
      value: primaryValue,
      detail:
        routeID === 'resources'
          ? 'Secret values are not requested or displayed.'
          : connection?.display_name ?? 'Connect AWS to populate current inventory anchors.',
      tone: connection?.connected || routeID === 'resources' ? 'success' : 'warning'
    },
    {
      label: 'Account / region',
      value: connection?.account_id ? 'Scoped' : 'Missing',
      detail: awsAccountRegionLabel(connection),
      tone: connection?.account_id ? 'success' : 'warning'
    },
    {
      label: 'Permission checks',
      value: permissionTotal > 0 ? `${permissionPassed}/${permissionTotal}` : 'Not run',
      detail: permissionTotal > 0 ? 'Connector validation evidence available.' : 'Validation evidence is not available for this environment.',
      tone: permissionTotal > 0 && permissionPassed === permissionTotal ? 'success' : permissionTotal > 0 ? 'warning' : 'neutral'
    },
    {
      label: 'Backend wave',
      value: 'Future-ready',
      detail: AWS_INVENTORY_PAGE_COPY[routeID].plannedCapability,
      tone: 'info'
    }
  ] satisfies ProductDomainRoute['metrics'];
}

function AWSInventoryRouteAside({
  copy,
  connection,
  selectedEnvironmentID
}: {
  copy: AWSInventoryPageCopy;
  connection: AWSConnectionStatus | null;
  selectedEnvironmentID: string;
}) {
  return (
    <DomainDetailPanel title="Inventory contract" eyebrow={copy.eyebrow}>
      <dl className="idt-domain-route-facts">
        <div>
          <dt>Environment</dt>
          <dd>{selectedEnvironmentID ? environmentFallbackLabel(selectedEnvironmentID) : 'Not selected'}</dd>
        </div>
        <div>
          <dt>Current data</dt>
          <dd>{copy.currentCapability}</dd>
        </div>
        <div>
          <dt>Connector</dt>
          <dd>{connection?.connector_id ?? 'Not assigned'}</dd>
        </div>
        <div>
          <dt>Secret posture</dt>
          <dd>No secret values requested</dd>
        </div>
      </dl>
    </DomainDetailPanel>
  );
}

function AWSInventoryPrerequisites({
  scope,
  selectedEnvironmentID,
  connection,
  connectPath
}: {
  scope: ProductSession;
  selectedEnvironmentID: string;
  connection: AWSConnectionStatus | null;
  connectPath: string;
}) {
  if (!selectedEnvironmentID) {
    return (
      <DomainEmptyState
        eyebrow="Environment required"
        title="Create an environment before inventory can resolve"
        body="AWS inventory is scoped through the existing workspace and environment contract. Create or pick an environment, then return to this AWS page."
        nextAction={{ label: 'Open environments', to: appendSourceQuery(buildProjectsPath(scope), 'aws') }}
      />
    );
  }

  if (!connection?.connected) {
    return (
      <DomainEmptyState
        eyebrow="Connector prerequisite"
        title="Connect AWS to populate current inventory anchors"
        body="These pages stay honest until the read-only AWS role is validated. The planned tables remain visible, but current account, region, role, permission, and diagnostic data come from Connect AWS."
        nextAction={{ label: 'Connect AWS', to: connectPath }}
      />
    );
  }

  return null;
}

function AWSAccountsInventoryContent({
  connection,
  connectPath,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  connectPath: string;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const accountCoverage = awsCoverageState(connection);
  const hasHealthyCoverage = accountCoverage === 'covered';
  const currentCoverageFilter = accountCoverage === 'covered' ? 'covered' : accountCoverage === 'degraded' ? 'degraded' : 'missing';
  const rows: AWSInventoryCoverageRow[] = [
    {
      id: 'current-account',
      category: connection?.account_id ? `AWS account ${connection.account_id}` : 'Selected AWS account',
      coverage: accountCoverage,
      source: connection?.display_name ?? 'Connect AWS',
      status: connection?.connected ? 'covered' : 'missing',
      detail: connection?.region ? `Validated in ${connection.region}` : 'Region coverage starts after validation.',
      filters: {
        account: connection?.account_id ? 'connected' : 'planned',
        region: connection?.region ? 'current' : 'uncovered',
        coverage: currentCoverageFilter,
        search: ''
      },
      searchText: inventorySearchText([connection?.account_id, connection?.region, connection?.display_name, 'current account', 'covered', 'missing'])
      },
      {
        id: 'current-region',
        category: connection?.region ? `Region ${connection.region}` : 'Current region',
        coverage: accountCoverage,
        source: 'AWS connector payload',
        status: accountCoverage,
        detail: connection?.last_validated_at ? `Last validation ${formatConnectionTime(connection.last_validated_at)}` : 'No validation time yet.',
        filters: {
          account: connection?.account_id ? 'connected' : 'planned',
          region: connection?.region ? 'current' : 'uncovered',
          coverage: currentCoverageFilter,
          search: ''
        },
        searchText: inventorySearchText([connection?.region, 'region', 'coverage', 'region coverage'])
      },
    {
      id: 'org-planner',
      category: 'Organization account planner',
      coverage: 'not yet available',
      source: 'Future AWS inventory API',
      status: 'not yet available',
      detail: 'Will track account enrollment, incremental cursors, and partial account failure.',
      filters: {
        account: 'planned',
        region: 'uncovered',
        coverage: 'not-yet-available',
        search: ''
      },
      searchText: inventorySearchText([
        'organization',
        'planner',
        'account',
        'not yet available'
      ])
    },
    {
      id: 'region-planner',
      category: 'Multi-region scan planner',
      coverage: 'not yet available',
      source: 'Future AWS inventory API',
      status: 'not yet available',
      detail: 'Will track service-by-region coverage and degraded or unreachable regions.',
      filters: {
        account: 'planned',
        region: 'uncovered',
        coverage: 'not-yet-available',
        search: ''
      },
      searchText: inventorySearchText([
        'multi-region',
        'planner',
        'coverage',
        'not yet available',
        'degraded',
        'region'
      ])
    }
  ];
  const passedChecks = connection?.permission_checks.filter((check) => check.passed).length ?? 0;
  const totalChecks = connection?.permission_checks.length ?? 0;
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSInventoryFilterSet routeID="accounts" filters={filters} onChange={onFiltersChange} />
      <section className="idt-aws-inventory-coverage" aria-label="AWS account and region coverage map">
        <DomainCoverageCard label="Account coverage" scanned={hasHealthyCoverage ? 1 : 0} total={1} detail="Selected environment" />
        <DomainCoverageCard label="Region coverage" scanned={hasHealthyCoverage ? 1 : 0} total={1} detail={hasHealthyCoverage ? connection?.region ?? 'Pending' : 'Pending'} />
        <DomainCoverageCard label="Permission evidence" scanned={passedChecks} total={Math.max(totalChecks, 1)} detail="Read-only validation" />
      </section>
      <DomainDataTable
        label="AWS account and region coverage"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        columns={[
          { key: 'category', header: 'Coverage scope', render: (row) => <strong>{row.category}</strong> },
          { key: 'coverage', header: 'Coverage', render: (row) => <AWSInventoryPill stage={row.coverage === 'covered' ? 'wired' : row.coverage === 'not yet available' ? 'not-available' : 'coming'} label={formatTokenLabel(row.coverage)} /> },
          { key: 'source', header: 'Source', render: (row) => row.source },
          { key: 'detail', header: 'Detail', render: (row) => row.detail }
        ]}
      />
      <DomainStatusPanel
        eyebrow="Connector dependency"
        title="Coverage is scoped by the read-only AWS role"
        status={connection?.connected ? 'Current account visible' : 'Setup required'}
        tone={connection?.connected ? 'success' : 'warning'}
        actions={[{ label: 'Open Connect AWS', to: connectPath, variant: 'secondary' }]}
      >
        <p>
          Account and region coverage uses the current AWS connector when it exists. Organization-wide scale, cursor health,
          and partial-region failure reporting stay labeled as future AWS inventory work.
        </p>
      </DomainStatusPanel>
    </>
  );
}

function AWSMachineIdentitiesContent({
  connection,
  ec2State,
  ecsState,
  lambdaState,
  codeBuildState,
  codePipelineState,
  stepFunctionsState,
  eksState,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  ec2State: AWSInventoryEC2State;
  ecsState: AWSInventoryECSState;
  lambdaState: AWSInventoryLambdaState;
  codeBuildState: AWSInventoryCodeBuildState;
  codePipelineState: AWSInventoryCodePipelineState;
  stepFunctionsState: AWSInventoryStepFunctionsState;
  eksState: AWSInventoryEKSState;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const ec2Inventory = ec2State.inventory;
  const ecsInventory = ecsState.inventory;
  const lambdaInventory = lambdaState.inventory;
  const codeBuildInventory = codeBuildState.inventory;
  const codePipelineInventory = codePipelineState.inventory;
  const stepFunctionsInventory = stepFunctionsState.inventory;
  const eksInventory = eksState.inventory;
  const ec2Rows = buildAWSEC2InstanceProfileRows(ec2Inventory, ec2State.loading, connection);
  const ecsRows = buildAWSECSTaskRoleRows(ecsInventory, ecsState.loading, connection);
  const lambdaRows = buildAWSLambdaExecutionRoleRows(lambdaInventory, lambdaState.loading, connection);
  const codeBuildRows = buildAWSCodeBuildServiceRoleRows(codeBuildInventory, codeBuildState.loading, connection);
  const codePipelineRows = buildAWSCodePipelineDeploymentRoleRows(codePipelineInventory, codePipelineState.loading, connection);
  const stepFunctionsRows = buildAWSStepFunctionsStateMachineRoleRows(stepFunctionsInventory, stepFunctionsState.loading, connection);
  const eksRows = buildAWSEKSWorkloadIdentityRows(eksInventory, eksState.loading, connection);
  const rows: AWSInventoryTableRow[] = [
    ...(connection?.role_arn
      ? [
          {
            id: 'current-role',
            name: connection.role_arn,
            category: 'IAM role',
            scope: awsAccountRegionLabel(connection),
            status: connection.connected ? 'wired now' : 'pending validation',
            stage: connection.connected ? ('wired' as AWSCapabilityStage) : ('coming' as AWSCapabilityStage),
            detail: connection.principal_arn ?? 'Role principal will appear after validation.',
            filters: {
              identityType: 'iam-role',
              service: 'iam',
              risk: 'unscored',
              status: connection.connected ? 'wired-now' : 'coming',
              search: ''
            },
            searchText: inventorySearchText([connection.role_arn, awsAccountRegionLabel(connection), 'iam', 'identity'])
          }
        ]
      : []),
    ...ec2Rows,
    ...ecsRows,
    ...lambdaRows,
    ...codeBuildRows,
    ...codePipelineRows,
    ...stepFunctionsRows,
    ...eksRows,
    {
      id: 'cicd-oidc',
      name: 'CI/CD deploy and OIDC roles',
      category: 'Deployment identity',
      scope: 'GitHub and external CI',
      status: 'coming',
      stage: 'coming',
      detail: 'Deployment trust paths will connect repository evidence to AWS role assumption.',
      filters: { identityType: 'cicd-role', service: 'oidc', risk: 'unscored', status: 'coming', search: '' },
      searchText: inventorySearchText(['ci', 'cd', 'cicd', 'oidc'])
    }
  ];
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSInventoryFilterSet routeID="identities" filters={filters} onChange={onFiltersChange} />
      {ec2State.loading ? <DomainLoadingState label="Loading EC2 instance profiles" /> : null}
      {ecsState.loading ? <DomainLoadingState label="Loading ECS task roles" /> : null}
      {lambdaState.loading ? <DomainLoadingState label="Loading Lambda execution roles" /> : null}
      {codeBuildState.loading ? <DomainLoadingState label="Loading CodeBuild service roles" /> : null}
      {codePipelineState.loading ? <DomainLoadingState label="Loading CodePipeline deployment roles" /> : null}
      {stepFunctionsState.loading ? <DomainLoadingState label="Loading Step Functions state-machine roles" /> : null}
      {eksState.loading ? <DomainLoadingState label="Loading EKS workload identities" /> : null}
      {ec2State.error ? (
        <DomainErrorState
          title="EC2 instance profiles could not load"
          body={ec2State.error}
          retryAction={{ label: 'Retry EC2 inventory', onClick: ec2State.onRetry }}
        />
      ) : null}
      {ecsState.error ? (
        <DomainErrorState
          title="ECS task roles could not load"
          body={ecsState.error}
          retryAction={{ label: 'Retry ECS inventory', onClick: ecsState.onRetry }}
        />
      ) : null}
      {lambdaState.error ? (
        <DomainErrorState
          title="Lambda execution roles could not load"
          body={lambdaState.error}
          retryAction={{ label: 'Retry Lambda inventory', onClick: lambdaState.onRetry }}
        />
      ) : null}
      {codeBuildState.error ? (
        <DomainErrorState
          title="CodeBuild service roles could not load"
          body={codeBuildState.error}
          retryAction={{ label: 'Retry CodeBuild inventory', onClick: codeBuildState.onRetry }}
        />
      ) : null}
      {codePipelineState.error ? (
        <DomainErrorState
          title="CodePipeline deployment roles could not load"
          body={codePipelineState.error}
          retryAction={{ label: 'Retry CodePipeline inventory', onClick: codePipelineState.onRetry }}
        />
      ) : null}
      {stepFunctionsState.error ? (
        <DomainErrorState
          title="Step Functions state-machine roles could not load"
          body={stepFunctionsState.error}
          retryAction={{ label: 'Retry Step Functions inventory', onClick: stepFunctionsState.onRetry }}
        />
      ) : null}
      {eksState.error ? (
        <DomainErrorState
          title="EKS workload identities could not load"
          body={eksState.error}
          retryAction={{ label: 'Retry EKS inventory', onClick: eksState.onRetry }}
        />
      ) : null}
      {ec2Inventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="EC2 collector diagnostics"
          title="Partial EC2 identity evidence"
          status={formatTokenLabel(ec2Inventory.status)}
          tone={ec2Inventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="EC2 instance profile diagnostics">
            {ec2Inventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {ecsInventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="ECS collector diagnostics"
          title="Partial ECS task role evidence"
          status={formatTokenLabel(ecsInventory.status)}
          tone={ecsInventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="ECS task role diagnostics">
            {ecsInventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {lambdaInventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="Lambda collector diagnostics"
          title="Partial Lambda execution-role evidence"
          status={formatTokenLabel(lambdaInventory.status)}
          tone={lambdaInventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="Lambda execution role diagnostics">
            {lambdaInventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {codeBuildInventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="CodeBuild collector diagnostics"
          title="Partial CodeBuild service-role evidence"
          status={formatTokenLabel(codeBuildInventory.status)}
          tone={codeBuildInventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="CodeBuild service role diagnostics">
            {codeBuildInventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {codePipelineInventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="CodePipeline collector diagnostics"
          title="Partial CodePipeline deployment-role evidence"
          status={formatTokenLabel(codePipelineInventory.status)}
          tone={codePipelineInventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="CodePipeline deployment role diagnostics">
            {codePipelineInventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {stepFunctionsInventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="Step Functions collector diagnostics"
          title="Partial Step Functions state-machine role evidence"
          status={formatTokenLabel(stepFunctionsInventory.status)}
          tone={stepFunctionsInventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="Step Functions state-machine role diagnostics">
            {stepFunctionsInventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {eksInventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="EKS collector diagnostics"
          title="Partial EKS workload identity evidence"
          status={formatTokenLabel(eksInventory.status)}
          tone={eksInventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="EKS workload identity diagnostics">
            {eksInventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      <section className="idt-aws-inventory-split">
        <DomainDataTable
          label="AWS machine identity inventory"
          rows={displayedRows}
          getRowKey={(row) => row.id}
          columns={[
            {
              key: 'name',
              header: 'Identity',
              render: (row) => (
                <div className="idt-aws-inventory-table-cell">
                  <strong>{row.name}</strong>
                  <p>{row.detail}</p>
                </div>
              )
            },
            { key: 'category', header: 'Type', render: (row) => row.category },
            { key: 'scope', header: 'Account / region / service', render: (row) => row.scope },
            { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
          ]}
        />
        <DomainDetailPanel title="Selected identity detail" eyebrow="Current data">
          <dl className="idt-domain-route-facts">
            <div>
              <dt>Role ARN</dt>
              <dd>{connection?.role_arn ?? 'Not available yet'}</dd>
            </div>
            <div>
              <dt>Principal</dt>
              <dd>{connection?.principal_arn ?? 'Pending validation'}</dd>
            </div>
            <div>
              <dt>Trust policy</dt>
              <dd>{connection?.external_id_configured ? 'External ID configured' : 'External ID not configured'}</dd>
            </div>
            <div>
              <dt>Risk score</dt>
              <dd>Unscored until AWS findings land</dd>
            </div>
            <div>
              <dt>EC2 workload links</dt>
              <dd>{ec2Inventory ? `${ec2Inventory.workload_count} workloads / ${ec2Inventory.relationship_count} relationships` : ec2State.loading ? 'Loading' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>IMDS posture</dt>
              <dd>{awsEC2IMDSLabel(ec2Inventory)}</dd>
            </div>
            <div>
              <dt>EC2 diagnostics</dt>
              <dd>{ec2Inventory?.diagnostics.length ? `${ec2Inventory.diagnostics.length} active` : ec2Inventory ? 'Clear' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>ECS workload links</dt>
              <dd>{ecsInventory ? `${ecsInventory.workload_count} workloads / ${ecsInventory.relationship_count} relationships` : ecsState.loading ? 'Loading' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>ECS task roles</dt>
              <dd>{ecsInventory ? `${ecsInventory.task_role_count} task / ${ecsInventory.execution_role_count} execution` : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>ECS diagnostics</dt>
              <dd>{ecsInventory?.diagnostics.length ? `${ecsInventory.diagnostics.length} active` : ecsInventory ? 'Clear' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>Lambda workload links</dt>
              <dd>{lambdaInventory ? `${lambdaInventory.function_count} functions / ${lambdaInventory.relationship_count} relationships` : lambdaState.loading ? 'Loading' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>Lambda event sources</dt>
              <dd>{lambdaInventory ? `${lambdaInventory.event_source_count} mapped / ${lambdaInventory.disabled_event_source_count} disabled` : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>Lambda diagnostics</dt>
              <dd>{lambdaInventory?.diagnostics.length ? `${lambdaInventory.diagnostics.length} active` : lambdaInventory ? 'Clear' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>CodeBuild workload links</dt>
              <dd>{codeBuildInventory ? `${codeBuildInventory.project_count} projects / ${codeBuildInventory.relationship_count} relationships` : codeBuildState.loading ? 'Loading' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>CodeBuild credential refs</dt>
              <dd>{codeBuildInventory ? `${codeBuildInventory.secret_ref_count} secret refs / ${codeBuildInventory.vpc_project_count} VPC projects` : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>CodeBuild diagnostics</dt>
              <dd>{codeBuildInventory?.diagnostics.length ? `${codeBuildInventory.diagnostics.length} active` : codeBuildInventory ? 'Clear' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>EKS workload links</dt>
              <dd>{eksInventory ? `${eksInventory.service_account_count} service accounts / ${eksInventory.relationship_count} relationships` : eksState.loading ? 'Loading' : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>EKS identity mix</dt>
              <dd>{eksInventory ? `${eksInventory.irsa_annotation_count} IRSA / ${eksInventory.pod_identity_association_count} Pod Identity / ${eksInventory.node_role_count} node` : 'Not loaded'}</dd>
            </div>
            <div>
              <dt>EKS diagnostics</dt>
              <dd>{eksInventory?.diagnostics.length ? `${eksInventory.diagnostics.length} active` : eksInventory ? 'Clear' : 'Not loaded'}</dd>
            </div>
          </dl>
        </DomainDetailPanel>
      </section>
    </>
  );
}

function buildAWSEC2InstanceProfileRows(
  inventory: AWSEC2InstanceProfileInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsEC2InstanceProfileRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'instance-profiles-blocked',
        name: 'EC2 instance profiles unavailable',
        category: 'Workload identity',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'EC2 instance profile collection is blocked.',
        filters: { identityType: 'instance-profile', service: 'ec2', risk: 'unscored', status: 'not-yet-available', search: '' },
        searchText: inventorySearchText(['ec2', 'instance profile', inventory.account_id, inventory.region, 'blocked'])
      }
    ];
  }
  if (inventory) {
    return [
      {
        id: 'instance-profiles-empty',
        name: 'No EC2 instance profile workloads found',
        category: 'Workload identity',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'wired now',
        stage: 'wired',
        detail: 'The collector completed for this account and region without role-bearing EC2 workloads.',
        filters: { identityType: 'instance-profile', service: 'ec2', risk: 'low', status: 'wired-now', search: '' },
        searchText: inventorySearchText(['ec2', 'instance profile', inventory.account_id, inventory.region, 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'instance-profiles-loading',
        name: 'EC2 instance profiles',
        category: 'Workload identity',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading EC2 instance profile evidence for the selected environment.',
        filters: { identityType: 'instance-profile', service: 'ec2', risk: 'unscored', status: 'coming', search: '' },
        searchText: inventorySearchText(['ec2', 'instance profile', 'loading'])
      }
    ];
  }
  return [
    {
      id: 'instance-profiles',
      name: 'EC2 instance profiles',
      category: 'Workload identity',
      scope: 'Account and region expansion',
      status: 'coming',
      stage: 'coming',
      detail: 'Instance profile inventory maps roles back to EC2 workloads after AWS is connected.',
      filters: { identityType: 'instance-profile', service: 'ec2', risk: 'unscored', status: 'coming', search: '' },
      searchText: inventorySearchText(['ec2', 'instance profile', 'workload identity', 'inventory'])
    }
  ];
}

function awsEC2InstanceProfileRow(record: AWSEC2InstanceProfileRecord): AWSInventoryTableRow {
  const isLaunchTemplate = record.workload_type === 'ec2_launch_template';
  const stage: AWSCapabilityStage = record.status === 'ready' && record.role_arn ? 'wired' : 'coming';
  const status = stage === 'wired' ? 'wired now' : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const workloadLabel = record.instance_name || record.launch_template_name || record.workload_name || record.workload_id;
  const imdsLabel = record.imds_http_tokens ? `IMDS ${formatTokenLabel(record.imds_http_tokens)}` : 'IMDS not applicable';
  return {
    id: `instance-profile-${record.from_node_id}`,
    name: record.instance_profile_name || roleLabel,
    category: isLaunchTemplate ? 'Launch template profile' : 'EC2 instance profile',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: `${workloadLabel} ${isLaunchTemplate ? 'attaches' : 'runs as'} ${roleLabel}; ${imdsLabel}.`,
    filters: {
      identityType: 'instance-profile',
      service: 'ec2',
      risk: record.imds_http_tokens === 'required' || isLaunchTemplate ? 'low' : 'medium',
      status: stage === 'wired' ? 'wired-now' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.instance_profile_name,
      record.role_arn,
      record.role_name,
      record.instance_id,
      record.instance_name,
      record.launch_template_id,
      record.launch_template_name,
      record.workload_id,
      record.account_id,
      record.region,
      record.imds_http_tokens,
      'ec2 instance profile'
    ])
  };
}

function buildAWSECSTaskRoleRows(
  inventory: AWSECSTaskRoleInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsECSTaskRoleRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'ecs-task-roles-blocked',
        name: 'ECS task roles unavailable',
        category: 'ECS task role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'ECS task role collection is blocked.',
        filters: { identityType: 'ecs-task-role', service: 'ecs', risk: 'unscored', status: 'not-yet-available', search: '' },
        searchText: inventorySearchText(['ecs', 'task role', 'execution role', inventory.account_id, inventory.region, 'blocked'])
      }
    ];
  }
  if (inventory) {
    return [
      {
        id: 'ecs-task-roles-empty',
        name: 'No ECS task or execution roles found',
        category: 'ECS task role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'wired now',
        stage: 'wired',
        detail: 'The collector completed for this account and region without ECS workloads that reference task or execution roles.',
        filters: { identityType: 'ecs-task-role', service: 'ecs', risk: 'low', status: 'wired-now', search: '' },
        searchText: inventorySearchText(['ecs', 'task role', 'execution role', inventory.account_id, inventory.region, 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'ecs-task-roles-loading',
        name: 'ECS task and execution roles',
        category: 'ECS task role',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading ECS task role evidence for the selected environment.',
        filters: { identityType: 'ecs-task-role', service: 'ecs', risk: 'unscored', status: 'coming', search: '' },
        searchText: inventorySearchText(['ecs', 'task role', 'execution role', 'loading'])
      }
    ];
  }
  return [
    {
      id: 'ecs-task-roles',
      name: 'ECS task and execution roles',
      category: 'ECS task role',
      scope: 'Account and region expansion',
      status: 'coming',
      stage: 'coming',
      detail: 'Task-role inventory maps ECS services and task definitions back to IAM roles after AWS is connected.',
      filters: { identityType: 'ecs-task-role', service: 'ecs', risk: 'unscored', status: 'coming', search: '' },
      searchText: inventorySearchText(['ecs', 'task role', 'execution role', 'inventory'])
    }
  ];
}

function awsECSTaskRoleRow(record: AWSECSTaskRoleRecord): AWSInventoryTableRow {
  const isExecutionRole = record.role_kind === 'execution_role';
  const stage: AWSCapabilityStage = record.status === 'ready' && record.role_arn ? 'wired' : 'coming';
  const status = stage === 'wired' ? 'wired now' : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const workloadLabel = record.service_name || record.task_definition_family || record.workload_name || record.workload_id;
  const launchLabel = record.launch_type || record.compatibilities?.join(', ') || 'launch not reported';
  const imageLabel = record.container_images?.[0] ? `image ${record.container_images[0]}` : 'image not reported';
  const secretLabel = record.secret_refs?.length ? `${record.secret_refs.length} secret refs, values hidden` : 'no secret refs reported';
  const hasTaskCount = typeof record.running_count === 'number' || typeof record.desired_count === 'number';
  const runningCount = record.running_count ?? 0;
  const desiredCount = record.desired_count ?? runningCount;
  const taskCountLabel = hasTaskCount ? `${runningCount}/${desiredCount} running` : 'task count not reported';
  const rowRoleID = record.to_node_id || record.role_arn || record.role_name || record.role_kind;
  return {
    id: `ecs-task-role-${record.from_node_id}-${rowRoleID}`,
    name: roleLabel,
    category: isExecutionRole ? 'ECS execution role' : 'ECS task role',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: `${workloadLabel} ${isExecutionRole ? 'attaches execution support to' : 'runs as'} ${roleLabel}; ${launchLabel}; ${taskCountLabel}; ${imageLabel}; ${secretLabel}.`,
    filters: {
      identityType: 'ecs-task-role',
      service: 'ecs',
      risk: record.secret_refs?.length ? 'medium' : 'low',
      status: stage === 'wired' ? 'wired-now' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.role_arn,
      record.role_name,
      record.role_kind,
      record.cluster_name,
      record.service_name,
      record.task_definition_family,
      record.task_definition_arn,
      record.launch_type,
      ...(record.compatibilities ?? []),
      ...(record.container_images ?? []),
      ...(record.secret_refs ?? []),
      ...(record.environment_keys ?? []),
      record.account_id,
      record.region,
      'ecs task role execution role'
    ])
  };
}

function buildAWSLambdaExecutionRoleRows(
  inventory: AWSLambdaExecutionRoleInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsLambdaExecutionRoleRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'lambda-execution-roles-blocked',
        name: 'Lambda execution roles unavailable',
        category: 'Lambda execution role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'Lambda execution-role collection is blocked.',
        filters: { identityType: 'lambda-role', service: 'lambda', risk: 'unscored', status: 'not-yet-available', search: '' },
        searchText: inventorySearchText(['lambda', 'execution role', inventory.account_id, inventory.region, 'blocked'])
      }
    ];
  }
  if (inventory) {
    return [
      {
        id: 'lambda-execution-roles-empty',
        name: 'No Lambda execution roles found',
        category: 'Lambda execution role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'wired now',
        stage: 'wired',
        detail: 'The collector completed for this account and region without Lambda functions that reference execution roles.',
        filters: { identityType: 'lambda-role', service: 'lambda', risk: 'low', status: 'wired-now', search: '' },
        searchText: inventorySearchText(['lambda', 'execution role', inventory.account_id, inventory.region, 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'lambda-execution-roles-loading',
        name: 'Lambda execution roles',
        category: 'Lambda execution role',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading Lambda execution-role evidence for the selected environment.',
        filters: { identityType: 'lambda-role', service: 'lambda', risk: 'unscored', status: 'coming', search: '' },
        searchText: inventorySearchText(['lambda', 'execution role', 'loading'])
      }
    ];
  }
  return [
    {
      id: 'lambda-execution-roles',
      name: 'Lambda execution roles',
      category: 'Lambda execution role',
      scope: 'Account and region expansion',
      status: 'coming',
      stage: 'coming',
      detail: 'Execution-role inventory maps Lambda functions back to IAM roles after AWS is connected.',
      filters: { identityType: 'lambda-role', service: 'lambda', risk: 'unscored', status: 'coming', search: '' },
      searchText: inventorySearchText(['lambda', 'execution role', 'inventory'])
    }
  ];
}

function awsLambdaExecutionRoleRow(record: AWSLambdaExecutionRoleRecord): AWSInventoryTableRow {
  const stage: AWSCapabilityStage = record.status === 'ready' && record.role_arn ? 'wired' : 'coming';
  const status = stage === 'wired' ? 'wired now' : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const functionLabel = record.function_name || record.workload_name || record.function_arn || record.workload_id;
  const runtimeLabel = record.runtime ? `${record.runtime}${record.handler ? ` / ${record.handler}` : ''}` : record.package_type || 'runtime not reported';
  const eventSourceCount = (record.event_source_arns?.length ?? 0) + (record.disabled_event_source_arns?.length ?? 0);
  const eventSourceLabel = eventSourceCount
    ? `${eventSourceCount} event source${eventSourceCount === 1 ? '' : 's'}${record.disabled_event_source_arns?.length ? `, ${record.disabled_event_source_arns.length} disabled` : ''}`
    : 'no event sources reported';
  const envLabel = record.environment_keys?.length ? `${record.environment_keys.length} env keys, values hidden` : 'no env keys reported';
  const secretLabel = record.secret_refs?.length ? `${record.secret_refs.length} secret refs, values hidden` : 'no secret refs reported';
  return {
    id: `lambda-execution-role-${record.from_node_id}-${record.to_node_id || record.role_arn || record.function_arn}`,
    name: roleLabel,
    category: 'Lambda execution role',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: `${functionLabel} runs as ${roleLabel}; ${runtimeLabel}; ${eventSourceLabel}; ${envLabel}; ${secretLabel}.`,
    filters: {
      identityType: 'lambda-role',
      service: 'lambda',
      risk: record.secret_refs?.length || record.disabled_event_source_arns?.length ? 'medium' : 'low',
      status: stage === 'wired' ? 'wired-now' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.role_arn,
      record.role_name,
      record.function_arn,
      record.function_name,
      record.runtime,
      record.package_type,
      record.handler,
      record.kms_key_arn,
      ...(record.alias_names ?? []),
      ...(record.version_refs ?? []),
      ...(record.event_source_arns ?? []),
      ...(record.disabled_event_source_arns ?? []),
      ...(record.secret_refs ?? []),
      ...(record.environment_keys ?? []),
      record.account_id,
      record.region,
      'lambda execution role'
    ])
  };
}

function buildAWSCodeBuildServiceRoleRows(
  inventory: AWSCodeBuildServiceRoleInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsCodeBuildServiceRoleRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'codebuild-service-roles-blocked',
        name: 'CodeBuild service roles unavailable',
        category: 'CodeBuild service role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'CodeBuild service-role collection is blocked.',
        filters: { identityType: 'codebuild-role', service: 'codebuild', risk: 'unscored', status: 'not-yet-available', search: '' },
        searchText: inventorySearchText(['codebuild', 'service role', inventory.account_id, inventory.region, 'blocked'])
      }
    ];
  }
  if (inventory) {
    return [
      {
        id: 'codebuild-service-roles-empty',
        name: 'No CodeBuild service roles found',
        category: 'CodeBuild service role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'wired now',
        stage: 'wired',
        detail: 'The collector completed for this account and region without CodeBuild projects that reference service roles.',
        filters: { identityType: 'codebuild-role', service: 'codebuild', risk: 'low', status: 'wired-now', search: '' },
        searchText: inventorySearchText(['codebuild', 'service role', inventory.account_id, inventory.region, 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'codebuild-service-roles-loading',
        name: 'CodeBuild service roles',
        category: 'CodeBuild service role',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading CodeBuild project service-role evidence for the selected environment.',
        filters: { identityType: 'codebuild-role', service: 'codebuild', risk: 'unscored', status: 'coming', search: '' },
        searchText: inventorySearchText(['codebuild', 'service role', 'loading'])
      }
    ];
  }
  return [
    {
      id: 'codebuild-service-roles',
      name: 'CodeBuild service roles',
      category: 'CodeBuild service role',
      scope: 'Account and region expansion',
      status: 'coming',
      stage: 'coming',
      detail: 'Service-role inventory maps CodeBuild projects back to IAM roles after AWS is connected.',
      filters: { identityType: 'codebuild-role', service: 'codebuild', risk: 'unscored', status: 'coming', search: '' },
      searchText: inventorySearchText(['codebuild', 'service role', 'ci', 'cd', 'inventory'])
    }
  ];
}

function awsCodeBuildServiceRoleRow(record: AWSCodeBuildServiceRoleRecord): AWSInventoryTableRow {
  const stage: AWSCapabilityStage = record.status === 'ready' && record.role_arn ? 'wired' : 'coming';
  const status = stage === 'wired' ? (record.privileged_mode || record.project_visibility === 'PUBLIC_READ' ? 'degraded' : 'wired now') : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const projectLabel = record.project_name || record.workload_name || record.project_arn || record.workload_id;
  const sourceLabel = record.source_type ? `${formatTokenLabel(record.source_type)} source` : 'source not reported';
  const environmentLabel = record.environment_type || record.compute_type ? `${record.environment_type || 'environment not reported'} / ${record.compute_type || 'compute not reported'}` : 'environment not reported';
  const artifactLabel = record.artifact_types?.length ? `${record.artifact_types.join(', ')} artifacts` : 'artifacts not reported';
  const secretLabel = record.secret_refs?.length ? `${record.secret_refs.length} secret refs, values hidden` : 'no secret refs reported';
  const vpcLabel = record.vpc_id ? `VPC ${record.vpc_id}` : 'no VPC config reported';
  const risk = record.privileged_mode || record.project_visibility === 'PUBLIC_READ' ? 'high' : record.secret_refs?.length ? 'medium' : 'low';
  return {
    id: `codebuild-service-role-${record.from_node_id}-${record.to_node_id || record.role_arn || record.project_arn}`,
    name: roleLabel,
    category: 'CodeBuild service role',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: `${projectLabel} runs as ${roleLabel}; ${sourceLabel}; ${environmentLabel}; ${artifactLabel}; ${vpcLabel}; ${secretLabel}.`,
    filters: {
      identityType: 'codebuild-role',
      service: 'codebuild',
      risk,
      status: status === 'wired now' ? 'wired-now' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.role_arn,
      record.role_name,
      record.project_arn,
      record.project_name,
      record.source_type,
      record.source_location,
      record.source_auth_type,
      record.source_version,
      record.environment_type,
      record.compute_type,
      record.image,
      record.kms_key_arn,
      record.vpc_id,
      ...(record.source_identifiers ?? []),
      ...(record.artifact_types ?? []),
      ...(record.artifact_locations ?? []),
      ...(record.log_types ?? []),
      ...(record.subnet_ids ?? []),
      ...(record.security_group_ids ?? []),
      ...(record.secret_refs ?? []),
      ...(record.environment_keys ?? []),
      record.account_id,
      record.region,
      'codebuild service role ci cd build project'
    ])
  };
}

function buildAWSCodePipelineDeploymentRoleRows(
  inventory: AWSCodePipelineDeploymentRoleInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsCodePipelineDeploymentRoleRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'codepipeline-deployment-roles-blocked',
        name: 'CodePipeline deployment roles unavailable',
        category: 'CodePipeline deployment role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'CodePipeline deployment-role collection is blocked.',
        filters: { identityType: 'codepipeline-role', service: 'codepipeline', risk: 'unscored', status: 'not-yet-available', search: '' },
        searchText: inventorySearchText(['codepipeline', 'deployment role', inventory.account_id, inventory.region, 'blocked'])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'codepipeline-deployment-roles-empty',
        name: degraded ? 'CodePipeline deployment roles incomplete' : 'No CodePipeline deployment roles found',
        category: 'CodePipeline deployment role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'wired now',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'CodePipeline deployment-role collection completed with degraded evidence and no retained records.') : 'The collector completed for this account and region without CodePipeline pipelines that reference deployment roles.',
        filters: { identityType: 'codepipeline-role', service: 'codepipeline', risk: degraded ? 'medium' : 'low', status: degraded ? 'degraded' : 'wired-now', search: '' },
        searchText: inventorySearchText(['codepipeline', 'deployment role', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'codepipeline-deployment-roles-loading',
        name: 'CodePipeline deployment roles',
        category: 'CodePipeline deployment role',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading CodePipeline pipeline and action role evidence for the selected environment.',
        filters: { identityType: 'codepipeline-role', service: 'codepipeline', risk: 'unscored', status: 'coming', search: '' },
        searchText: inventorySearchText(['codepipeline', 'deployment role', 'loading'])
      }
    ];
  }
  return [
    {
      id: 'codepipeline-deployment-roles',
      name: 'CodePipeline deployment roles',
      category: 'CodePipeline deployment role',
      scope: 'Account and region expansion',
      status: 'coming',
      stage: 'coming',
      detail: 'Deployment-role inventory maps CodePipeline pipelines and action roles back to IAM roles after AWS is connected.',
      filters: { identityType: 'codepipeline-role', service: 'codepipeline', risk: 'unscored', status: 'coming', search: '' },
      searchText: inventorySearchText(['codepipeline', 'deployment role', 'ci', 'cd', 'inventory'])
    }
  ];
}

function awsCodePipelineDeploymentRoleRow(record: AWSCodePipelineDeploymentRoleRecord): AWSInventoryTableRow {
  const degraded = record.status !== 'ready' || record.cross_account_role || record.cross_region_action || record.cross_region_artifact_stores || Boolean(record.disabled_stage_transitions?.length);
  const stage: AWSCapabilityStage = record.status === 'ready' && record.role_arn ? 'wired' : 'coming';
  const status = stage === 'wired' ? (degraded ? 'degraded' : 'wired now') : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const pipelineLabel = record.pipeline_name || record.workload_name || record.pipeline_arn || record.workload_id;
  const actionLabel = record.action_name ? `${record.stage_name || 'stage'} / ${record.action_name}` : 'pipeline service role';
  const providerLabel = record.action_provider ? `${record.action_category || 'action'} via ${record.action_provider}` : 'pipeline service role';
  const artifactLabel = record.artifact_store_regions?.length ? `${record.artifact_store_regions.length} artifact regions` : 'artifact store region not reported';
  const roleAccountLabel = record.role_account_id && record.role_account_id !== record.account_id ? `role account ${record.role_account_id}` : 'same-account role';
  const pathLabel = [
    record.cross_account_role ? 'cross-account role' : '',
    record.cross_region_action ? 'cross-region action' : '',
    record.cross_region_artifact_stores ? 'cross-region artifact store' : '',
    record.disabled_stage_transitions?.length ? 'disabled transition' : ''
  ].filter(Boolean).join(', ') || 'standard deployment path';
  const risk = record.cross_account_role || record.disabled_stage_transitions?.length ? 'high' : record.cross_region_action || record.cross_region_artifact_stores || record.pass_role_adjacent ? 'medium' : 'low';
  return {
    id: `codepipeline-deployment-role-${record.from_node_id}-${record.to_node_id || record.role_arn || record.pipeline_arn}`,
    name: roleLabel,
    category: 'CodePipeline deployment role',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: `${pipelineLabel} ${actionLabel} runs as ${roleLabel}; ${providerLabel}; ${artifactLabel}; ${roleAccountLabel}; ${pathLabel}.`,
    filters: {
      identityType: 'codepipeline-role',
      service: 'codepipeline',
      risk,
      status: status === 'wired now' ? 'wired-now' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.role_arn,
      record.role_name,
      record.role_account_id,
      record.role_kind,
      record.pipeline_arn,
      record.pipeline_name,
      record.pipeline_type,
      record.execution_mode,
      record.stage_name,
      record.action_name,
      record.action_category,
      record.action_owner,
      record.action_provider,
      record.action_region,
      ...(record.input_artifact_names ?? []),
      ...(record.output_artifact_names ?? []),
      ...(record.artifact_store_types ?? []),
      ...(record.artifact_store_locations ?? []),
      ...(record.artifact_store_regions ?? []),
      ...(record.artifact_kms_key_arns ?? []),
      ...(record.configuration_keys ?? []),
      ...(record.provider_identifiers ?? []),
      ...(record.disabled_stage_transitions ?? []),
      record.account_id,
      record.region,
      'codepipeline deployment role ci cd pipeline action'
    ])
  };
}

function buildAWSStepFunctionsStateMachineRoleRows(
  inventory: AWSStepFunctionsStateMachineRoleInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsStepFunctionsStateMachineRoleRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'stepfunctions-state-machine-roles-blocked',
        name: 'Step Functions state-machine roles unavailable',
        category: 'Step Functions state-machine role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'Step Functions state-machine role collection is blocked.',
        filters: { identityType: 'stepfunctions-role', service: 'stepfunctions', risk: 'unscored', status: 'not-yet-available', search: '' },
        searchText: inventorySearchText(['step functions', 'stepfunctions', 'state machine role', inventory.account_id, inventory.region, 'blocked'])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'stepfunctions-state-machine-roles-empty',
        name: degraded ? 'Step Functions state-machine roles incomplete' : 'No Step Functions state-machine roles found',
        category: 'Step Functions state-machine role',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'wired now',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'Step Functions collection completed with degraded evidence and no retained records.') : 'The collector completed for this account and region without Step Functions state machines that reference execution roles.',
        filters: { identityType: 'stepfunctions-role', service: 'stepfunctions', risk: degraded ? 'medium' : 'low', status: degraded ? 'degraded' : 'wired-now', search: '' },
        searchText: inventorySearchText(['step functions', 'stepfunctions', 'state machine role', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'stepfunctions-state-machine-roles-loading',
        name: 'Step Functions state-machine roles',
        category: 'Step Functions state-machine role',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading Step Functions workflow, execution role, service integration, nested workflow, and logging evidence.',
        filters: { identityType: 'stepfunctions-role', service: 'stepfunctions', risk: 'unscored', status: 'coming', search: '' },
        searchText: inventorySearchText(['step functions', 'stepfunctions', 'state machine role', 'loading'])
      }
    ];
  }
  return [
    {
      id: 'stepfunctions-state-machine-roles',
      name: 'Step Functions state-machine roles',
      category: 'Step Functions state-machine role',
      scope: 'Account and region expansion',
      status: 'coming',
      stage: 'coming',
      detail: 'State-machine role inventory maps workflows, nested workflows, service integrations, and logging config back to IAM roles after AWS is connected.',
      filters: { identityType: 'stepfunctions-role', service: 'stepfunctions', risk: 'unscored', status: 'coming', search: '' },
      searchText: inventorySearchText(['step functions', 'stepfunctions', 'state machine role', 'workflow', 'inventory'])
    }
  ];
}

function awsStepFunctionsStateMachineRoleRow(record: AWSStepFunctionsStateMachineRoleRecord): AWSInventoryTableRow {
  const degraded = record.status !== 'ready' || Boolean(record.logging_include_execution_data);
  const stage: AWSCapabilityStage = record.status === 'ready' && record.role_arn ? 'wired' : 'coming';
  const status = stage === 'wired' ? (degraded ? 'degraded' : 'wired now') : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const workflowLabel = record.state_machine_name || record.workload_name || record.state_machine_arn || record.workload_id;
  const integrationLabel = record.service_integration_resources?.length ? `${record.service_integration_resources.join(', ')} integrations` : 'no service integrations reported';
  const nestedLabel = record.nested_state_machine_arns?.length ? `${record.nested_state_machine_arns.length} nested workflows` : 'no nested workflows reported';
  const loggingLabel = record.logging_level ? `logging ${record.logging_level}${record.logging_include_execution_data ? ' with execution data' : ''}` : 'logging not reported';
  const risk = record.logging_include_execution_data ? 'high' : record.nested_state_machine_arns?.length || record.service_integration_resources?.length ? 'medium' : 'low';
  return {
    id: `stepfunctions-state-machine-role-${record.from_node_id}-${record.to_node_id || record.role_arn || record.state_machine_arn}`,
    name: roleLabel,
    category: 'Step Functions state-machine role',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: `${workflowLabel} runs as ${roleLabel}; ${integrationLabel}; ${nestedLabel}; ${loggingLabel}.`,
    filters: {
      identityType: 'stepfunctions-role',
      service: 'stepfunctions',
      risk,
      status: status === 'wired now' ? 'wired-now' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.role_arn,
      record.role_name,
      record.role_account_id,
      record.state_machine_arn,
      record.state_machine_name,
      record.state_machine_type,
      record.state_machine_status,
      record.revision_id,
      record.definition_sha256,
      ...(record.definition_resource_arns ?? []),
      ...(record.task_resource_arns ?? []),
      ...(record.service_integration_resources ?? []),
      ...(record.nested_state_machine_arns ?? []),
      record.logging_level,
      ...(record.log_group_arns ?? []),
      record.encryption_type,
      record.kms_key_arn,
      record.account_id,
      record.region,
      'step functions stepfunctions state machine workflow role'
    ])
  };
}

function buildAWSEKSWorkloadIdentityRows(
  inventory: AWSEKSWorkloadIdentityInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsEKSWorkloadIdentityRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'eks-workload-identities-blocked',
        name: 'EKS workload identities unavailable',
        category: 'EKS workload identity',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'EKS workload identity collection is blocked.',
        filters: { identityType: 'eks-identity', service: 'eks', risk: 'unscored', status: 'not-yet-available', search: '' },
        searchText: inventorySearchText(['eks', 'irsa', 'pod identity', 'node role', inventory.account_id, inventory.region, 'blocked'])
      }
    ];
  }
  if (inventory) {
    return [
      {
        id: 'eks-workload-identities-empty',
        name: 'No EKS workload identities found',
        category: 'EKS workload identity',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'wired now',
        stage: 'wired',
        detail: 'The collector completed for this account and region without Kubernetes-backed IRSA, Pod Identity, node role, or Fargate pod execution role evidence.',
        filters: { identityType: 'eks-identity', service: 'eks', risk: 'low', status: 'wired-now', search: '' },
        searchText: inventorySearchText(['eks', 'irsa', 'pod identity', 'node role', inventory.account_id, inventory.region, 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'eks-workload-identities-loading',
        name: 'EKS workload identities',
        category: 'EKS workload identity',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading Kubernetes-backed IRSA, EKS Pod Identity, node role, and Fargate pod execution-role evidence for the selected environment.',
        filters: { identityType: 'eks-identity', service: 'eks', risk: 'unscored', status: 'coming', search: '' },
        searchText: inventorySearchText(['eks', 'irsa', 'pod identity', 'node role', 'loading'])
      }
    ];
  }
  return [
    {
      id: 'eks-workload-identities',
      name: 'EKS workload identities',
      category: 'EKS workload identity',
      scope: 'Account and region expansion',
      status: 'coming',
      stage: 'coming',
      detail: 'Kubernetes-backed IRSA and Pod Identity inventory maps service accounts and EKS compute back to IAM roles after AWS is connected.',
      filters: { identityType: 'eks-identity', service: 'eks', risk: 'unscored', status: 'coming', search: '' },
      searchText: inventorySearchText(['eks', 'irsa', 'pod identity', 'node role', 'inventory'])
    }
  ];
}

function awsEKSWorkloadIdentityRow(record: AWSEKSWorkloadIdentityRecord): AWSInventoryTableRow {
  const stage: AWSCapabilityStage = record.status === 'ready' && record.role_arn ? 'wired' : 'coming';
  const status = stage === 'wired' ? (record.kubernetes_access_status === 'available' || record.role_kind !== 'irsa' ? 'wired now' : 'degraded') : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const clusterLabel = record.cluster_name || record.cluster_arn || 'cluster not reported';
  const subjectLabel =
    record.kubernetes_subject ||
    (record.namespace && record.service_account ? `${record.namespace}/${record.service_account}` : '') ||
    record.nodegroup_name ||
    record.fargate_profile_name ||
    record.workload_name ||
    record.workload_id;
  const oidcLabel = record.oidc_provider_arn ? 'OIDC provider linked' : 'OIDC provider unresolved';
  const kubernetesLabel =
    record.kubernetes_access_status === 'available'
      ? 'Kubernetes annotations proven'
      : record.role_kind === 'irsa'
        ? 'Kubernetes annotations degraded'
        : 'AWS-side evidence';
  const roleKindLabel = formatTokenLabel(record.role_kind);
  const associationLabel = record.association_id ? `association ${record.association_id}` : record.nodegroup_status || record.fargate_profile_status || record.cluster_status || 'status not reported';
  const risk = record.role_kind === 'irsa' && record.kubernetes_access_status !== 'available' ? 'medium' : record.role_kind === 'node_role' ? 'medium' : 'low';
  const category =
    record.role_kind === 'irsa'
      ? 'EKS IRSA'
      : record.role_kind === 'pod_identity'
        ? 'EKS Pod Identity'
        : record.role_kind === 'node_role'
          ? 'EKS node role'
          : record.role_kind === 'fargate_pod_execution_role'
            ? 'EKS Fargate pod role'
            : 'EKS workload identity';
  return {
    id: `eks-workload-identity-${record.from_node_id}-${record.to_node_id || record.role_arn || record.evidence_ref}`,
    name: roleLabel,
    category,
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage: status === 'wired now' ? 'wired' : 'coming',
    detail: `${subjectLabel} ${record.relationship_type === 'attached_to' ? 'attaches' : 'runs as'} ${roleLabel}; ${clusterLabel}; ${roleKindLabel}; ${oidcLabel}; ${associationLabel}; ${kubernetesLabel}.`,
    filters: {
      identityType: 'eks-identity',
      service: 'eks',
      risk,
      status: status === 'wired now' ? 'wired-now' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.role_arn,
      record.role_name,
      record.role_kind,
      record.cluster_name,
      record.cluster_arn,
      record.namespace,
      record.service_account,
      record.kubernetes_subject,
      record.association_arn,
      record.association_id,
      record.nodegroup_name,
      record.fargate_profile_name,
      record.oidc_provider_arn,
      ...(record.selector_namespaces ?? []),
      ...(record.selector_labels ?? []),
      ...(record.irsa_annotation_keys ?? []),
      record.account_id,
      record.region,
      'eks irsa pod identity workload identity'
    ])
  };
}

function awsAccountRegionInventoryLabel(accountID?: string, region?: string): string {
  const accountLabel = accountID ? `Account ${accountID}` : 'Account pending';
  const regionLabel = region ? `Region ${region}` : 'Region pending';
  return `${accountLabel} / ${regionLabel}`;
}

function awsEC2IMDSLabel(inventory: AWSEC2InstanceProfileInventoryResult | null): string {
  const instanceRecord = inventory?.records.find((record) => record.instance_id);
  if (!instanceRecord) {
    return inventory ? 'No EC2 instance record' : 'Not loaded';
  }
  if (!instanceRecord.imds_http_tokens) {
    return 'Not reported';
  }
  return `${formatTokenLabel(instanceRecord.imds_http_tokens)} tokens, hop limit ${instanceRecord.imds_hop_limit || 'not reported'}`;
}

function AWSAgentIdentitiesContent({
  connection,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const rows: AWSInventoryTableRow[] = [
    {
      id: 'role-anchor',
      name: connection?.role_arn ?? 'AWS role anchor',
      category: 'Agent-to-role anchor',
      scope: awsAccountRegionLabel(connection),
      status: connection?.connected ? 'role anchor' : 'not yet available',
      stage: connection?.connected ? 'wired' : 'not-available',
      detail: 'Future agent inventory can attach Bedrock or external agent execution back to this AWS role context.',
      filters: {
        surface: 'agentcore-runtime',
        relationship: 'agent-to-role',
        status: connection?.connected ? 'role-anchor' : 'not-yet-available',
        search: ''
      },
      searchText: inventorySearchText(['agent to role', 'agent', 'role anchor', 'role relationship'])
    },
    {
      id: 'bedrock-agents',
      name: 'Bedrock agents',
      category: 'AWS-native agent',
      scope: 'Bedrock',
      status: 'coming',
      stage: 'coming',
      detail: 'Agent identity, action groups, tool use, and role relationship slots are reserved here.',
      filters: { surface: 'bedrock-agents', relationship: 'agent-to-tool', status: 'coming', search: '' },
      searchText: inventorySearchText(['bedrock', 'agent surface', 'tools'])
    },
    {
      id: 'agentcore',
      name: 'AgentCore runtime and gateway identity',
      category: 'AgentCore',
      scope: 'Runtime / gateway',
      status: 'coming',
      stage: 'coming',
      detail: 'Will map AgentCore runtime, gateway, identity metadata, MCP gateway, and tool relationships.',
      filters: { surface: 'agentcore-runtime,mcp-gateway', relationship: 'agent-to-tool', status: 'coming', search: '' },
      searchText: inventorySearchText(['agentcore', 'runtime', 'gateway', 'identity'])
    },
    {
      id: 'external-provider-keys',
      name: 'External AI provider key metadata',
      category: 'Safe metadata',
      scope: 'Secrets metadata only',
      status: 'not yet available',
      stage: 'not-available',
      detail: 'OpenAI, Anthropic, and Claude Platform usage mapping will use safe metadata, never secret values.',
      filters: {
        surface: 'external-provider-keys',
        relationship: 'agent-to-secret',
        status: 'not-yet-available',
        search: ''
      },
      searchText: inventorySearchText(['external', 'provider', 'keys', 'agent'])
    }
  ];
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSInventoryFilterSet routeID="agents" filters={filters} onChange={onFiltersChange} />
      <section className="idt-aws-agent-relationship-grid" aria-label="AWS agent relationship slots">
        {[
          ['Agent to role', connection?.role_arn ? 'Role anchor available' : 'Waiting for role validation'],
          ['Agent to tool', 'Tool and MCP gateway coverage reserved'],
          ['Agent to secret', 'Secret metadata only, no value reads'],
          ['Agent to user', 'Human owner mapping reserved for governance waves']
        ].map(([label, detail]) => (
          <article key={label}>
            <strong>{label}</strong>
            <p>{detail}</p>
          </article>
        ))}
      </section>
      <DomainDataTable
        label="AWS agent identity inventory"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        columns={[
          { key: 'name', header: 'Agent surface', render: (row) => <strong>{row.name}</strong> },
          { key: 'category', header: 'Category', render: (row) => row.category },
          { key: 'scope', header: 'Scope', render: (row) => row.scope },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> },
          { key: 'detail', header: 'Relationship slot', render: (row) => row.detail }
        ]}
      />
    </>
  );
}

function AWSResourcesInventoryContent({
  connection,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const rows: AWSInventoryTableRow[] = [
    {
      id: 'secrets-manager',
      name: 'Secrets Manager metadata',
      category: 'Secret-bearing',
      scope: connection?.account_id ? `Account ${connection.account_id}` : 'Account pending',
      status: 'coming',
      stage: 'coming',
      detail: 'Name, tags, rotation, policy, and reference metadata only. Secret values are out of scope.',
      filters: { category: 'secrets-manager', sensitivity: 'secret-bearing', readPosture: 'metadata-only', search: '' },
      searchText: inventorySearchText(['secrets manager', 'secret', 'metadata', 'category'])
    },
    {
      id: 'ssm-parameters',
      name: 'SSM Parameter metadata',
      category: 'Credential reference',
      scope: connection?.region ?? 'Region pending',
      status: 'coming',
      stage: 'coming',
      detail: 'Parameter paths, tags, encryption metadata, and reachability hints without value reads.',
      filters: { category: 'ssm-parameter', sensitivity: 'credential-reference', readPosture: 'metadata-only', search: '' },
      searchText: inventorySearchText(['ssm parameter', 'reference', 'tags', 'encryption'])
    },
    {
      id: 'kms',
      name: 'KMS key reachability',
      category: 'KMS-admin',
      scope: 'Policies and grants',
      status: 'coming',
      stage: 'coming',
      detail: 'Key policy and grant reachability will highlight decrypt/admin blast radius.',
      filters: { category: 'kms', sensitivity: 'kms-admin', readPosture: 'metadata-only', search: '' },
      searchText: inventorySearchText(['kms', 'key', 'reachability', 'policy', 'grants'])
    },
    {
      id: 's3',
      name: 'S3 bucket sensitivity',
      category: 'Customer data',
      scope: 'Bucket metadata',
      status: 'coming',
      stage: 'coming',
      detail: 'Bucket policy, public access, tags, and sensitivity labels land with resource coverage.',
      filters: { category: 's3', sensitivity: 'customer-data', readPosture: 'metadata-only', search: '' },
      searchText: inventorySearchText(['s3', 'bucket', 'customer data', 'sensitivity', 'metadata'])
    },
    {
      id: 'secret-values',
      name: 'Secret values',
      category: 'Protected value',
      scope: 'Never read',
      status: 'not requested',
      stage: 'not-available',
      detail: 'Identrail inventory pages do not request, store, or display secret values.',
      filters: { category: 'control-plane', sensitivity: 'control-plane', readPosture: 'no-secret-values', search: '' },
      searchText: inventorySearchText(['secret values', 'not requested', 'metadata only', 'not read'])
    }
  ];
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSInventoryFilterSet routeID="resources" filters={filters} onChange={onFiltersChange} />
      <section className="idt-aws-resource-coverage-grid" aria-label="AWS resource category coverage">
        <DomainCoverageCard label="Secrets metadata" scanned={0} total={1} detail="Coming wave" />
        <DomainCoverageCard label="KMS reachability" scanned={0} total={1} detail="Coming wave" />
        <DomainCoverageCard label="S3 sensitivity" scanned={0} total={1} detail="Coming wave" />
      </section>
      <DomainStatusPanel eyebrow="Safety posture" title="No secret value reads" status="Metadata only" tone="success">
        <p>
          Resource inventory is designed around reachability and metadata. Secrets Manager, SSM Parameter, and external AI
          provider key mapping must use safe metadata and credential references, not credential values.
        </p>
      </DomainStatusPanel>
      <DomainDataTable
        label="AWS resource and credential reachability"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        columns={[
          { key: 'name', header: 'Resource category', render: (row) => <strong>{row.name}</strong> },
          { key: 'category', header: 'Sensitivity', render: (row) => row.category },
          { key: 'scope', header: 'Scope', render: (row) => row.scope },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> },
          { key: 'detail', header: 'Coverage note', render: (row) => row.detail }
        ]}
      />
    </>
  );
}

function ProductAWSInventoryPage({ routeID }: { routeID: AWSInventoryRouteID }) {
  const data = useAWSInventoryData();
  const { scope, environmentScope, selectedEnvironmentID, connection, connectionLoading, connectionError } = data;
  const copy = AWS_INVENTORY_PAGE_COPY[routeID];
  const [activeFilters, setActiveFilters] = useState<AWSInventoryFilterState>(() => ({
    ...AWS_INVENTORY_FILTER_DEFAULTS[routeID]
  }));
  const [ec2Inventory, setEC2Inventory] = useState<AWSEC2InstanceProfileInventoryResult | null>(null);
  const [ec2InventoryLoading, setEC2InventoryLoading] = useState(false);
  const [ec2InventoryError, setEC2InventoryError] = useState('');
  const ec2InventoryRequestRef = useRef(0);
  const [ecsInventory, setECSInventory] = useState<AWSECSTaskRoleInventoryResult | null>(null);
  const [ecsInventoryLoading, setECSInventoryLoading] = useState(false);
  const [ecsInventoryError, setECSInventoryError] = useState('');
  const ecsInventoryRequestRef = useRef(0);
  const [lambdaInventory, setLambdaInventory] = useState<AWSLambdaExecutionRoleInventoryResult | null>(null);
  const [lambdaInventoryLoading, setLambdaInventoryLoading] = useState(false);
  const [lambdaInventoryError, setLambdaInventoryError] = useState('');
  const lambdaInventoryRequestRef = useRef(0);
  const [codeBuildInventory, setCodeBuildInventory] = useState<AWSCodeBuildServiceRoleInventoryResult | null>(null);
  const [codeBuildInventoryLoading, setCodeBuildInventoryLoading] = useState(false);
  const [codeBuildInventoryError, setCodeBuildInventoryError] = useState('');
  const codeBuildInventoryRequestRef = useRef(0);
  const [codePipelineInventory, setCodePipelineInventory] = useState<AWSCodePipelineDeploymentRoleInventoryResult | null>(null);
  const [codePipelineInventoryLoading, setCodePipelineInventoryLoading] = useState(false);
  const [codePipelineInventoryError, setCodePipelineInventoryError] = useState('');
  const codePipelineInventoryRequestRef = useRef(0);
  const [stepFunctionsInventory, setStepFunctionsInventory] = useState<AWSStepFunctionsStateMachineRoleInventoryResult | null>(null);
  const [stepFunctionsInventoryLoading, setStepFunctionsInventoryLoading] = useState(false);
  const [stepFunctionsInventoryError, setStepFunctionsInventoryError] = useState('');
  const stepFunctionsInventoryRequestRef = useRef(0);
  const [eksInventory, setEKSInventory] = useState<AWSEKSWorkloadIdentityInventoryResult | null>(null);
  const [eksInventoryLoading, setEKSInventoryLoading] = useState(false);
  const [eksInventoryError, setEKSInventoryError] = useState('');
  const eksInventoryRequestRef = useRef(0);

  const onFiltersChange = (nextFilters: AWSInventoryFilterState): void => {
    setActiveFilters(nextFilters);
  };

  useEffect(() => {
    setActiveFilters({ ...AWS_INVENTORY_FILTER_DEFAULTS[routeID] });
  }, [routeID]);

  const loadEC2Inventory = useCallback(async () => {
    const requestID = ++ec2InventoryRequestRef.current;
    setEC2Inventory(null);
    setEC2InventoryError('');
    if (routeID !== 'identities' || !scope || !selectedEnvironmentID || !connection?.connected) {
      setEC2InventoryLoading(false);
      return;
    }
    setEC2InventoryLoading(true);
    try {
      const response = await apiClient.getAWSProjectEC2InstanceProfiles(
        scope.workspaceID,
        selectedEnvironmentID,
        connection.connector_id,
        undefined,
        buildProductAuthContext(scope)
      );
      if (requestID !== ec2InventoryRequestRef.current) {
        return;
      }
      setEC2Inventory(response.inventory);
    } catch (error) {
      if (requestID !== ec2InventoryRequestRef.current) {
        return;
      }
      setEC2InventoryError(formatAPIError(error, 'Unable to load EC2 instance profile inventory.'));
    } finally {
      if (requestID === ec2InventoryRequestRef.current) {
        setEC2InventoryLoading(false);
      }
    }
  }, [routeID, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, connection?.connected, connection?.connector_id]);

  useEffect(() => {
    void loadEC2Inventory();
    return () => {
      ec2InventoryRequestRef.current += 1;
    };
  }, [loadEC2Inventory]);

  const loadECSInventory = useCallback(async () => {
    const requestID = ++ecsInventoryRequestRef.current;
    setECSInventory(null);
    setECSInventoryError('');
    if (routeID !== 'identities' || !scope || !selectedEnvironmentID || !connection?.connected) {
      setECSInventoryLoading(false);
      return;
    }
    setECSInventoryLoading(true);
    try {
      const response = await apiClient.getAWSProjectECSTaskRoles(
        scope.workspaceID,
        selectedEnvironmentID,
        connection.connector_id,
        undefined,
        buildProductAuthContext(scope)
      );
      if (requestID !== ecsInventoryRequestRef.current) {
        return;
      }
      setECSInventory(response.inventory);
    } catch (error) {
      if (requestID !== ecsInventoryRequestRef.current) {
        return;
      }
      setECSInventoryError(formatAPIError(error, 'Unable to load ECS task role inventory.'));
    } finally {
      if (requestID === ecsInventoryRequestRef.current) {
        setECSInventoryLoading(false);
      }
    }
  }, [routeID, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, connection?.connected, connection?.connector_id]);

  useEffect(() => {
    void loadECSInventory();
    return () => {
      ecsInventoryRequestRef.current += 1;
    };
  }, [loadECSInventory]);

  const loadLambdaInventory = useCallback(async () => {
    const requestID = ++lambdaInventoryRequestRef.current;
    setLambdaInventory(null);
    setLambdaInventoryError('');
    if (routeID !== 'identities' || !scope || !selectedEnvironmentID || !connection?.connected) {
      setLambdaInventoryLoading(false);
      return;
    }
    setLambdaInventoryLoading(true);
    try {
      const response = await apiClient.getAWSProjectLambdaExecutionRoles(
        scope.workspaceID,
        selectedEnvironmentID,
        connection.connector_id,
        undefined,
        buildProductAuthContext(scope)
      );
      if (requestID !== lambdaInventoryRequestRef.current) {
        return;
      }
      setLambdaInventory(response.inventory);
    } catch (error) {
      if (requestID !== lambdaInventoryRequestRef.current) {
        return;
      }
      setLambdaInventoryError(formatAPIError(error, 'Unable to load Lambda execution role inventory.'));
    } finally {
      if (requestID === lambdaInventoryRequestRef.current) {
        setLambdaInventoryLoading(false);
      }
    }
  }, [routeID, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, connection?.connected, connection?.connector_id]);

  useEffect(() => {
    void loadLambdaInventory();
    return () => {
      lambdaInventoryRequestRef.current += 1;
    };
  }, [loadLambdaInventory]);

  const loadCodeBuildInventory = useCallback(async () => {
    const requestID = ++codeBuildInventoryRequestRef.current;
    setCodeBuildInventory(null);
    setCodeBuildInventoryError('');
    if (routeID !== 'identities' || !scope || !selectedEnvironmentID || !connection?.connected) {
      setCodeBuildInventoryLoading(false);
      return;
    }
    setCodeBuildInventoryLoading(true);
    try {
      const response = await apiClient.getAWSProjectCodeBuildServiceRoles(
        scope.workspaceID,
        selectedEnvironmentID,
        connection.connector_id,
        undefined,
        buildProductAuthContext(scope)
      );
      if (requestID !== codeBuildInventoryRequestRef.current) {
        return;
      }
      setCodeBuildInventory(response.inventory);
    } catch (error) {
      if (requestID !== codeBuildInventoryRequestRef.current) {
        return;
      }
      setCodeBuildInventoryError(formatAPIError(error, 'Unable to load CodeBuild service role inventory.'));
    } finally {
      if (requestID === codeBuildInventoryRequestRef.current) {
        setCodeBuildInventoryLoading(false);
      }
    }
  }, [routeID, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, connection?.connected, connection?.connector_id]);

  useEffect(() => {
    void loadCodeBuildInventory();
    return () => {
      codeBuildInventoryRequestRef.current += 1;
    };
  }, [loadCodeBuildInventory]);

  const loadCodePipelineInventory = useCallback(async () => {
    const requestID = ++codePipelineInventoryRequestRef.current;
    setCodePipelineInventory(null);
    setCodePipelineInventoryError('');
    if (routeID !== 'identities' || !scope || !selectedEnvironmentID || !connection?.connected) {
      setCodePipelineInventoryLoading(false);
      return;
    }
    setCodePipelineInventoryLoading(true);
    try {
      const response = await apiClient.getAWSProjectCodePipelineDeploymentRoles(
        scope.workspaceID,
        selectedEnvironmentID,
        connection.connector_id,
        undefined,
        buildProductAuthContext(scope)
      );
      if (requestID !== codePipelineInventoryRequestRef.current) {
        return;
      }
      setCodePipelineInventory(response.inventory);
    } catch (error) {
      if (requestID !== codePipelineInventoryRequestRef.current) {
        return;
      }
      setCodePipelineInventoryError(formatAPIError(error, 'Unable to load CodePipeline deployment role inventory.'));
    } finally {
      if (requestID === codePipelineInventoryRequestRef.current) {
        setCodePipelineInventoryLoading(false);
      }
    }
  }, [routeID, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, connection?.connected, connection?.connector_id]);

  useEffect(() => {
    void loadCodePipelineInventory();
    return () => {
      codePipelineInventoryRequestRef.current += 1;
    };
  }, [loadCodePipelineInventory]);

  const loadStepFunctionsInventory = useCallback(async () => {
    const requestID = ++stepFunctionsInventoryRequestRef.current;
    setStepFunctionsInventory(null);
    setStepFunctionsInventoryError('');
    if (routeID !== 'identities' || !scope || !selectedEnvironmentID || !connection?.connected) {
      setStepFunctionsInventoryLoading(false);
      return;
    }
    setStepFunctionsInventoryLoading(true);
    try {
      const response = await apiClient.getAWSProjectStepFunctionsStateMachineRoles(
        scope.workspaceID,
        selectedEnvironmentID,
        connection.connector_id,
        undefined,
        buildProductAuthContext(scope)
      );
      if (requestID !== stepFunctionsInventoryRequestRef.current) {
        return;
      }
      setStepFunctionsInventory(response.inventory);
    } catch (error) {
      if (requestID !== stepFunctionsInventoryRequestRef.current) {
        return;
      }
      setStepFunctionsInventoryError(formatAPIError(error, 'Unable to load Step Functions state-machine role inventory.'));
    } finally {
      if (requestID === stepFunctionsInventoryRequestRef.current) {
        setStepFunctionsInventoryLoading(false);
      }
    }
  }, [routeID, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, connection?.connected, connection?.connector_id]);

  useEffect(() => {
    void loadStepFunctionsInventory();
    return () => {
      stepFunctionsInventoryRequestRef.current += 1;
    };
  }, [loadStepFunctionsInventory]);

  const loadEKSInventory = useCallback(async () => {
    const requestID = ++eksInventoryRequestRef.current;
    setEKSInventory(null);
    setEKSInventoryError('');
    if (routeID !== 'identities' || !scope || !selectedEnvironmentID || !connection?.connected) {
      setEKSInventoryLoading(false);
      return;
    }
    setEKSInventoryLoading(true);
    try {
      const response = await apiClient.getAWSProjectEKSWorkloadIdentities(
        scope.workspaceID,
        selectedEnvironmentID,
        connection.connector_id,
        undefined,
        buildProductAuthContext(scope)
      );
      if (requestID !== eksInventoryRequestRef.current) {
        return;
      }
      setEKSInventory(response.inventory);
    } catch (error) {
      if (requestID !== eksInventoryRequestRef.current) {
        return;
      }
      setEKSInventoryError(formatAPIError(error, 'Unable to load EKS workload identity inventory.'));
    } finally {
      if (requestID === eksInventoryRequestRef.current) {
        setEKSInventoryLoading(false);
      }
    }
  }, [routeID, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, connection?.connected, connection?.connector_id]);

  useEffect(() => {
    void loadEKSInventory();
    return () => {
      eksInventoryRequestRef.current += 1;
    };
  }, [loadEKSInventory]);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">{copy.title}</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading AWS inventory.</p>
      </section>
    );
  }

  const statusTone = awsDomainTone(connection, environmentScope.loading || connectionLoading);
  const connectPath = awsRouteLink(scope, 'connect', selectedEnvironmentID);
  const homePath = appendEnvironmentQuery(buildScopedPath(scope, 'aws'), selectedEnvironmentID);
  const findingsPath = awsRouteLink(scope, 'findings', selectedEnvironmentID);
  // Subtitle: the inventory shell carries no "shell" / "reserved" labels.
  // It just describes what the user can see today — same as overview.
  const inventorySubtitle = (() => {
    if (environmentScope.loading || connectionLoading) {
      return `Loading ${copy.title.toLowerCase()}…`;
    }
    if (connectionError) {
      return "Couldn't load AWS status.";
    }
    if (!connection?.connected) {
      return 'Not connected for this environment.';
    }
    const bits: string[] = [];
    if (connection.account_id) bits.push(connection.account_id);
    if (connection.region) bits.push(connection.region);
    return bits.join(' · ') || copy.description;
  })();

  return (
    <DomainPageShell
      domain="aws"
      eyebrow={null}
      hideLogo
      title={copy.title}
      description={inventorySubtitle}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={data.onChangeEnvironment} />}
      statusTone={connectionError ? 'danger' : statusTone}
      primaryAction={
        connectionError || environmentScope.loading || connectionLoading
          ? undefined
          : connection?.connected
            ? { label: 'AWS findings', to: findingsPath, variant: 'primary' }
            : { label: 'Connect AWS', to: connectPath, variant: 'primary' }
      }
    >
      {connectionError ? (
        <DomainErrorState
          title="Couldn't load AWS status"
          body={connectionError}
          retryAction={{ label: 'Retry', onClick: data.refreshConnection }}
        />
      ) : null}

      {!environmentScope.loading && !connectionLoading && !connectionError ? (
        <AWSInventoryPrerequisites
          scope={scope}
          selectedEnvironmentID={selectedEnvironmentID}
          connection={connection}
          connectPath={connectPath}
        />
      ) : null}

      {routeID === 'accounts' ? (
        <AWSAccountsInventoryContent connection={connection} connectPath={connectPath} filters={activeFilters} onFiltersChange={onFiltersChange} />
      ) : null}
      {routeID === 'identities' ? (
        <AWSMachineIdentitiesContent
          connection={connection}
          ec2State={{
            inventory: ec2Inventory,
            loading: ec2InventoryLoading,
            error: ec2InventoryError,
            onRetry: () => void loadEC2Inventory()
          }}
          ecsState={{
            inventory: ecsInventory,
            loading: ecsInventoryLoading,
            error: ecsInventoryError,
            onRetry: () => void loadECSInventory()
          }}
          lambdaState={{
            inventory: lambdaInventory,
            loading: lambdaInventoryLoading,
            error: lambdaInventoryError,
            onRetry: () => void loadLambdaInventory()
          }}
          codeBuildState={{
            inventory: codeBuildInventory,
            loading: codeBuildInventoryLoading,
            error: codeBuildInventoryError,
            onRetry: () => void loadCodeBuildInventory()
          }}
          codePipelineState={{
            inventory: codePipelineInventory,
            loading: codePipelineInventoryLoading,
            error: codePipelineInventoryError,
            onRetry: () => void loadCodePipelineInventory()
          }}
          stepFunctionsState={{
            inventory: stepFunctionsInventory,
            loading: stepFunctionsInventoryLoading,
            error: stepFunctionsInventoryError,
            onRetry: () => void loadStepFunctionsInventory()
          }}
          eksState={{
            inventory: eksInventory,
            loading: eksInventoryLoading,
            error: eksInventoryError,
            onRetry: () => void loadEKSInventory()
          }}
          filters={activeFilters}
          onFiltersChange={onFiltersChange}
        />
      ) : null}
      {routeID === 'agents' ? (
        <AWSAgentIdentitiesContent connection={connection} filters={activeFilters} onFiltersChange={onFiltersChange} />
      ) : null}
      {routeID === 'resources' ? (
        <AWSResourcesInventoryContent connection={connection} filters={activeFilters} onFiltersChange={onFiltersChange} />
      ) : null}
    </DomainPageShell>
  );
}

export function ProductAWSAccountsPage() {
  return <ProductAWSInventoryPage routeID="accounts" />;
}

export function ProductAWSIdentitiesPage() {
  return <ProductAWSInventoryPage routeID="identities" />;
}

export function ProductAWSAgentsPage() {
  return <ProductAWSInventoryPage routeID="agents" />;
}

export function ProductAWSResourcesPage() {
  return <ProductAWSInventoryPage routeID="resources" />;
}

type AWSRiskOperationRouteID = Extract<
  ProductDomainRouteID,
  'runtime' | 'graph' | 'findings' | 'remediation' | 'governance'
>;

type AWSRiskOperationPageCopy = {
  routeID: AWSRiskOperationRouteID;
  title: string;
  eyebrow: string;
  description: string;
  statusLabel: string;
  currentCapability: string;
  plannedCapability: string;
  nextAction: string;
  unavailableTitle: string;
  unavailableBody: string;
};

const AWS_RISK_OPERATION_PAGE_COPY: Record<AWSRiskOperationRouteID, AWSRiskOperationPageCopy> = {
  runtime: {
    routeID: 'runtime',
    title: 'Runtime',
    eyebrow: '',
    description: 'What your AWS roles actually did, from CloudTrail.',
    statusLabel: '',
    currentCapability: '',
    plannedCapability: '',
    nextAction: '',
    unavailableTitle: 'No runtime events yet',
    unavailableBody: "Runtime activity will appear here once Identrail starts ingesting your AWS logs."
  },
  graph: {
    routeID: 'graph',
    title: 'Graph',
    eyebrow: '',
    description: 'How AWS roles can reach things, visualised.',
    statusLabel: '',
    currentCapability: '',
    plannedCapability: '',
    nextAction: '',
    unavailableTitle: 'No graph yet',
    unavailableBody: 'The graph will populate once Identrail has scanned your AWS roles and resources.'
  },
  findings: {
    routeID: 'findings',
    title: 'Findings',
    eyebrow: '',
    description: 'Risks Identrail found in your AWS setup.',
    statusLabel: '',
    currentCapability: '',
    plannedCapability: '',
    nextAction: '',
    unavailableTitle: 'No findings yet',
    unavailableBody: "Findings will appear here after your first AWS scan."
  },
  remediation: {
    routeID: 'remediation',
    title: 'Remediation',
    eyebrow: '',
    description: 'AWS fixes Identrail prepares for you to approve.',
    statusLabel: '',
    currentCapability: '',
    plannedCapability: '',
    nextAction: '',
    unavailableTitle: 'No fixes prepared',
    unavailableBody: 'Fixes will appear here after a finding has been triaged.'
  },
  governance: {
    routeID: 'governance',
    title: 'Governance',
    eyebrow: '',
    description: "Advice on AWS access. Identrail won't apply changes for you.",
    statusLabel: '',
    currentCapability: '',
    plannedCapability: '',
    nextAction: '',
    unavailableTitle: 'No advice yet',
    unavailableBody: "Identrail will flag risky AWS access requests here once it has graph and runtime evidence."
  }
};

type AWSRiskOperationFilterConfigMap = Record<AWSRiskOperationRouteID, AWSInventoryFilterConfig[]>;

const AWS_RISK_OPERATION_FILTER_DEFAULTS: Record<AWSRiskOperationRouteID, AWSInventoryFilterState> = {
  runtime: { event: 'all', evidence: 'all', owner: 'all', search: '' },
  graph: { node: 'all', edge: 'all', evidence: 'all', search: '' },
  findings: { severity: 'all', account: 'all', region: 'all', evidence: 'all', status: 'all', search: '' },
  remediation: { change: 'all', approval: 'all', stage: 'all', search: '' },
  governance: { decision: 'all', mode: 'all', evidence: 'all', search: '' }
};

const AWS_RISK_OPERATION_FILTERS: AWSRiskOperationFilterConfigMap = {
  runtime: [
    {
      id: 'event',
      label: 'Event type',
      options: [
        { label: 'All events', value: 'all' },
        { label: 'CloudTrail', value: 'cloudtrail' },
        { label: 'STS AssumeRole', value: 'sts-assume-role' },
        { label: 'Secrets Manager', value: 'secrets-manager' },
        { label: 'KMS decrypt', value: 'kms-decrypt' },
        { label: 'Agent tool', value: 'agent-tool' }
      ]
    },
    {
      id: 'evidence',
      label: 'Evidence',
      options: [
        { label: 'All evidence', value: 'all' },
        { label: 'Current connector', value: 'current-connector' },
        { label: 'Coming', value: 'coming' },
        { label: 'Unavailable', value: 'unavailable' }
      ]
    },
    {
      id: 'owner',
      label: 'Owner',
      options: [
        { label: 'All owners', value: 'all' },
        { label: 'Security', value: 'security' },
        { label: 'Platform', value: 'platform' },
        { label: 'Application', value: 'application' }
      ]
    }
  ],
  graph: [
    {
      id: 'node',
      label: 'Node type',
      options: [
        { label: 'All nodes', value: 'all' },
        { label: 'Identity', value: 'identity' },
        { label: 'Agent', value: 'agent' },
        { label: 'Resource', value: 'resource' },
        { label: 'Finding', value: 'finding' },
        { label: 'Owner', value: 'owner' }
      ]
    },
    {
      id: 'edge',
      label: 'Edge',
      options: [
        { label: 'All edges', value: 'all' },
        { label: 'Can assume', value: 'can-assume' },
        { label: 'Can read secret', value: 'can-read-secret' },
        { label: 'Can decrypt', value: 'can-decrypt' },
        { label: 'Owns', value: 'owns' }
      ]
    },
    {
      id: 'evidence',
      label: 'Evidence',
      options: [
        { label: 'All evidence', value: 'all' },
        { label: 'Known', value: 'known' },
        { label: 'Unknown', value: 'unknown' },
        { label: 'Planned', value: 'planned' }
      ]
    }
  ],
  findings: [
    {
      id: 'severity',
      label: 'Severity',
      options: [
        { label: 'All severities', value: 'all' },
        { label: 'Critical', value: 'critical' },
        { label: 'High', value: 'high' },
        { label: 'Medium', value: 'medium' },
        { label: 'Low', value: 'low' },
        { label: 'Info', value: 'info' }
      ]
    },
    {
      id: 'account',
      label: 'Account',
      options: [
        { label: 'All accounts', value: 'all' },
        { label: 'Connected account', value: 'connected' },
        { label: 'Unknown account', value: 'unknown' }
      ]
    },
    {
      id: 'region',
      label: 'Region',
      options: [
        { label: 'All regions', value: 'all' },
        { label: 'Current region', value: 'current' },
        { label: 'Unknown region', value: 'unknown' }
      ]
    },
    {
      id: 'evidence',
      label: 'Evidence',
      options: [
        { label: 'All evidence', value: 'all' },
        { label: 'Runtime backed', value: 'runtime-backed' },
        { label: 'Inventory backed', value: 'inventory-backed' },
        { label: 'Unavailable', value: 'unavailable' }
      ]
    },
    {
      id: 'status',
      label: 'Remediation',
      options: [
        { label: 'All statuses', value: 'all' },
        { label: 'Open', value: 'open' },
        { label: 'Queued', value: 'queued' },
        { label: 'Blocked', value: 'blocked' },
        { label: 'Unavailable', value: 'unavailable' }
      ]
    }
  ],
  remediation: [
    {
      id: 'change',
      label: 'Change type',
      options: [
        { label: 'All changes', value: 'all' },
        { label: 'IAM policy', value: 'iam-policy' },
        { label: 'Trust policy', value: 'trust-policy' },
        { label: 'Permission boundary', value: 'permission-boundary' },
        { label: 'Secret rotation', value: 'secret-rotation' },
        { label: 'IaC PR', value: 'iac-pr' }
      ]
    },
    {
      id: 'approval',
      label: 'Approval',
      options: [
        { label: 'All approvals', value: 'all' },
        { label: 'Owner required', value: 'owner-required' },
        { label: 'Security required', value: 'security-required' },
        { label: 'Dry run required', value: 'dry-run-required' }
      ]
    },
    {
      id: 'stage',
      label: 'Stage',
      options: [
        { label: 'All stages', value: 'all' },
        { label: 'No case', value: 'no-case' },
        { label: 'Draft only', value: 'draft-only' },
        { label: 'Not active', value: 'not-active' }
      ]
    }
  ],
  governance: [
    {
      id: 'decision',
      label: 'Decision',
      options: [
        { label: 'All decisions', value: 'all' },
        { label: 'Warn', value: 'warn' },
        { label: 'Approval', value: 'approval' },
        { label: 'Quarantine', value: 'quarantine' },
        { label: 'Recommend deny', value: 'recommend-deny' }
      ]
    },
    {
      id: 'mode',
      label: 'Mode',
      options: [
        { label: 'All modes', value: 'all' },
        { label: 'Advisory', value: 'advisory' },
        { label: 'Canary', value: 'canary' },
        { label: 'Not enforcing', value: 'not-enforcing' }
      ]
    },
    {
      id: 'evidence',
      label: 'Evidence',
      options: [
        { label: 'All evidence', value: 'all' },
        { label: 'Runtime required', value: 'runtime-required' },
        { label: 'Approval required', value: 'approval-required' },
        { label: 'Audit required', value: 'audit-required' }
      ]
    }
  ]
};

type AWSRiskOperationTableRow = AWSInventoryFilterable & {
  id: string;
  title: string;
  category: string;
  evidence: string;
  owner: string;
  blastRadius: string;
  nextAction: string;
  status: string;
  stage: AWSCapabilityStage;
};

function AWSRiskOperationFilterSet({
  routeID,
  filters,
  onChange
}: {
  routeID: AWSRiskOperationRouteID;
  filters: AWSInventoryFilterState;
  onChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const searchPlaceholder: Record<AWSRiskOperationRouteID, string> = {
    runtime: 'Search events',
    graph: 'Search graph',
    findings: 'Search findings',
    remediation: 'Search changes',
    governance: 'Search decisions'
  };
  const onFilterChange = (id: string, value: string): void => {
    onChange({
      ...filters,
      [id]: value
    });
  };
  const onSearchChange = (event: ChangeEvent<HTMLInputElement>): void => {
    onChange({
      ...filters,
      search: event.target.value
    });
  };

  return (
    <DomainFilterBar label={`${AWS_RISK_OPERATION_PAGE_COPY[routeID].title} filters`}>
      {AWS_RISK_OPERATION_FILTERS[routeID].map((filter) => (
        <label key={filter.label}>
          {filter.label}
          <select value={filters[filter.id] ?? 'all'} onChange={(event) => onFilterChange(filter.id, event.target.value)}>
            {filter.options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      ))}
      <label>
        Search
        <input
          placeholder={searchPlaceholder[routeID]}
          value={filters.search ?? ''}
          onChange={onSearchChange}
          aria-label={`${AWS_RISK_OPERATION_PAGE_COPY[routeID].title} search`}
        />
      </label>
    </DomainFilterBar>
  );
}

function awsConnectionRoleLabel(connection: AWSConnectionStatus | null): string {
  const roleName = connection?.role_arn?.match(/:role\/(.+)$/)?.[1];
  if (roleName) {
    return `Role ${roleName}`;
  }
  if (connection?.role_arn) {
    return 'Validated AWS role';
  }
  return 'AWS role anchor';
}

function AWSRiskOperationScope({
  copy,
  connection,
  selectedEnvironmentID
}: {
  copy: AWSRiskOperationPageCopy;
  connection: AWSConnectionStatus | null;
  selectedEnvironmentID: string;
}) {
  const facts = [
    ['Status', copy.statusLabel],
    ['Scope', connection?.account_id ? awsAccountRegionLabel(connection) : selectedEnvironmentID ? 'Pending connector' : 'No environment'],
    ['Role', connection?.role_arn ? awsConnectionRoleLabel(connection) : 'Not connected'],
    ['Mode', copy.routeID === 'governance' ? 'Advisory' : 'Read-only']
  ];

  return (
    <section className="idt-aws-risk-scope" aria-label={`${copy.title} scope`}>
      <dl>
        {facts.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function AWSRiskOperationPrerequisites({
  scope,
  selectedEnvironmentID,
  connection,
  connectPath
}: {
  scope: ProductSession;
  selectedEnvironmentID: string;
  connection: AWSConnectionStatus | null;
  connectPath: string;
}) {
  if (!selectedEnvironmentID) {
    return (
      <DomainEmptyState
        eyebrow="Environment required"
        title="Create an environment before AWS operations can resolve"
        body="Create an environment, then return to AWS."
        nextAction={{ label: 'Open environments', to: appendSourceQuery(buildProjectsPath(scope), 'aws') }}
      />
    );
  }

  if (!connection?.connected) {
    return (
      <DomainEmptyState
        eyebrow="Connector prerequisite"
        title="Connect AWS to load operational context"
        body="Account, region, role, and diagnostics come from the read-only AWS connector."
        nextAction={{ label: 'Connect AWS', to: connectPath }}
      />
    );
  }

  return null;
}

function AWSRuntimeEvidenceContent({
  connection,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const rows: AWSRiskOperationTableRow[] = [
    ...(connection?.role_arn
      ? [
          {
            id: 'runtime-role-anchor',
            title: awsConnectionRoleLabel(connection),
            category: 'STS AssumeRole',
            evidence: 'Connector',
            owner: 'Security',
            blastRadius: awsAccountRegionLabel(connection),
            nextAction: 'Attach CloudTrail',
            status: 'connector',
            stage: 'wired' as AWSCapabilityStage,
            filters: { event: 'sts-assume-role', evidence: 'current-connector', owner: 'security', search: '' },
            searchText: inventorySearchText([connection.role_arn, connection.principal_arn, 'sts assume role current connector'])
          }
        ]
      : []),
    {
      id: 'cloudtrail-management-events',
      title: 'CloudTrail management events',
      category: 'CloudTrail',
      evidence: 'Planned',
      owner: 'Security',
      blastRadius: connection?.account_id ? `Account ${connection.account_id}` : 'Account pending',
      nextAction: 'Wire ingestion',
      status: 'planned',
      stage: 'coming',
      filters: { event: 'cloudtrail', evidence: 'coming', owner: 'security', search: '' },
      searchText: inventorySearchText(['cloudtrail', 'management events', 'runtime evidence'])
    },
    {
      id: 'secret-read-events',
      title: 'Secrets Manager GetSecretValue',
      category: 'Secrets Manager',
      evidence: 'Planned',
      owner: 'Application',
      blastRadius: 'Secret metadata only',
      nextAction: 'Map metadata',
      status: 'planned',
      stage: 'coming',
      filters: { event: 'secrets-manager', evidence: 'coming', owner: 'application', search: '' },
      searchText: inventorySearchText(['secrets manager', 'getsecretvalue', 'secret reads'])
    },
    {
      id: 'kms-decrypt-events',
      title: 'KMS Decrypt activity',
      category: 'KMS decrypt',
      evidence: 'Planned',
      owner: 'Platform',
      blastRadius: 'Key reachability pending',
      nextAction: 'Join key policy',
      status: 'planned',
      stage: 'coming',
      filters: { event: 'kms-decrypt', evidence: 'coming', owner: 'platform', search: '' },
      searchText: inventorySearchText(['kms', 'decrypt', 'runtime evidence'])
    },
    {
      id: 'agent-tool-events',
      title: 'Agent tool invocation',
      category: 'Agent tool',
      evidence: 'Unavailable',
      owner: 'Security',
      blastRadius: 'Agent graph pending',
      nextAction: 'Map agent identity',
      status: 'unavailable',
      stage: 'not-available',
      filters: { event: 'agent-tool', evidence: 'unavailable', owner: 'security', search: '' },
      searchText: inventorySearchText(['agent', 'tool', 'mcp', 'agentcore'])
    }
  ];
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSRiskOperationFilterSet routeID="runtime" filters={filters} onChange={onFiltersChange} />
      <DomainDataTable
        label="AWS runtime evidence surfaces"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        columns={[
          {
            key: 'event',
            header: 'Event surface',
            render: (row) => <strong>{row.title}</strong>
          },
          { key: 'evidence', header: 'Evidence', render: (row) => row.evidence },
          { key: 'owner', header: 'Owner', render: (row) => row.owner },
          { key: 'blast', header: 'Blast radius', render: (row) => row.blastRadius },
          { key: 'next', header: 'Next action', render: (row) => row.nextAction },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
        ]}
      />
    </>
  );
}

function AWSGraphExplorerContent({
  connection,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const rows: AWSRiskOperationTableRow[] = [
    {
      id: 'identity-anchor',
      title: awsConnectionRoleLabel(connection),
      category: 'Identity',
      evidence: connection?.role_arn ? 'Connector' : 'Unknown',
      owner: 'Security',
      blastRadius: awsAccountRegionLabel(connection),
      nextAction: 'Join policies',
      status: connection?.role_arn ? 'known' : 'unknown',
      stage: connection?.role_arn ? 'wired' : 'coming',
      filters: { node: 'identity', edge: 'can-assume', evidence: connection?.role_arn ? 'known' : 'unknown', search: '' },
      searchText: inventorySearchText([connection?.role_arn, connection?.principal_arn, 'identity', 'role anchor'])
    },
    {
      id: 'secret-node',
      title: 'Secrets Manager metadata node',
      category: 'Resource',
      evidence: 'Planned',
      owner: 'Application',
      blastRadius: 'Secret reachability pending',
      nextAction: 'Collect metadata',
      status: 'planned',
      stage: 'coming',
      filters: { node: 'resource', edge: 'can-read-secret', evidence: 'planned', search: '' },
      searchText: inventorySearchText(['secret', 'resource', 'can read secret', 'metadata'])
    },
    {
      id: 'kms-node',
      title: 'KMS decrypt path',
      category: 'Resource',
      evidence: 'Planned',
      owner: 'Platform',
      blastRadius: 'Key grants pending',
      nextAction: 'Attach key policy',
      status: 'planned',
      stage: 'coming',
      filters: { node: 'resource', edge: 'can-decrypt', evidence: 'planned', search: '' },
      searchText: inventorySearchText(['kms', 'decrypt', 'resource'])
    },
    {
      id: 'finding-node',
      title: 'AWS finding node',
      category: 'Finding',
      evidence: 'Unknown',
      owner: 'Security',
      blastRadius: 'No finding selected',
      nextAction: 'Wire findings',
      status: 'unavailable',
      stage: 'not-available',
      filters: { node: 'finding', edge: 'owns', evidence: 'unknown', search: '' },
      searchText: inventorySearchText(['finding', 'risk path', 'evidence'])
    }
  ];
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSRiskOperationFilterSet routeID="graph" filters={filters} onChange={onFiltersChange} />
      <DomainDataTable
        label="AWS graph nodes and edges"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        columns={[
          {
            key: 'node',
            header: 'Node / edge',
            render: (row) => <strong>{row.title}</strong>
          },
          { key: 'category', header: 'Type', render: (row) => row.category },
          { key: 'evidence', header: 'Evidence', render: (row) => row.evidence },
          { key: 'blast', header: 'Blast radius', render: (row) => row.blastRadius },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
        ]}
      />
    </>
  );
}

function AWSFindingsContent({
  filters,
  onFiltersChange
}: {
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const rows: AWSRiskOperationTableRow[] = [];
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSRiskOperationFilterSet routeID="findings" filters={filters} onChange={onFiltersChange} />
      <DomainDataTable
        label="AWS findings"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        emptyState={
          <DomainEmptyState
            eyebrow="Empty"
            title="No AWS findings"
            body="Finding generation is not connected yet."
          />
        }
        columns={[
          { key: 'title', header: 'Finding', render: (row) => <strong>{row.title}</strong> },
          { key: 'category', header: 'Severity', render: (row) => row.category },
          { key: 'evidence', header: 'Evidence', render: (row) => row.evidence },
          { key: 'blast', header: 'Blast radius', render: (row) => row.blastRadius },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
        ]}
      />
    </>
  );
}

function AWSRemediationContent({
  connection,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const rows: AWSRiskOperationTableRow[] = [
    {
      id: 'iam-policy-diff',
      title: 'IAM policy diff preview',
      category: 'IAM policy',
      evidence: 'Finding required',
      owner: 'Security',
      blastRadius: connection?.account_id ? `Account ${connection.account_id}` : 'Account pending',
      nextAction: 'Generate diff',
      status: 'draft',
      stage: 'coming',
      filters: { change: 'iam-policy', approval: 'owner-required', stage: 'draft-only', search: '' },
      searchText: inventorySearchText(['iam policy', 'diff', 'least privilege', 'draft'])
    },
    {
      id: 'trust-policy-hardening',
      title: 'Trust policy hardening',
      category: 'Trust policy',
      evidence: 'Trust analysis',
      owner: 'Platform',
      blastRadius: 'Role assumption path pending',
      nextAction: 'Compare trust path',
      status: 'draft',
      stage: 'coming',
      filters: { change: 'trust-policy', approval: 'security-required', stage: 'draft-only', search: '' },
      searchText: inventorySearchText(['trust policy', 'hardening', 'external id'])
    },
    {
      id: 'permission-boundary-scp',
      title: 'Permission boundary review',
      category: 'Permission boundary',
      evidence: 'Governance input',
      owner: 'Security',
      blastRadius: 'Organization scope pending',
      nextAction: 'Keep advisory',
      status: 'not active',
      stage: 'not-available',
      filters: { change: 'permission-boundary', approval: 'security-required', stage: 'not-active', search: '' },
      searchText: inventorySearchText(['permission boundary', 'scp', 'governance'])
    },
    {
      id: 'secret-rotation',
      title: 'Secret rotation planner',
      category: 'Secret rotation',
      evidence: 'Secret metadata',
      owner: 'Application',
      blastRadius: 'Secret metadata pending',
      nextAction: 'Plan rotation',
      status: 'not active',
      stage: 'not-available',
      filters: { change: 'secret-rotation', approval: 'owner-required', stage: 'not-active', search: '' },
      searchText: inventorySearchText(['secret rotation', 'planner', 'metadata'])
    },
    {
      id: 'iac-pr-plan',
      title: 'IaC PR plan and verification',
      category: 'IaC PR',
      evidence: 'Repo mapping',
      owner: 'Platform',
      blastRadius: 'Environment and repo pending',
      nextAction: 'Map repository',
      status: 'not active',
      stage: 'not-available',
      filters: { change: 'iac-pr', approval: 'dry-run-required', stage: 'not-active', search: '' },
      searchText: inventorySearchText(['iac', 'pr', 'verification', 'rollback'])
    }
  ];
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSRiskOperationFilterSet routeID="remediation" filters={filters} onChange={onFiltersChange} />
      <DomainDataTable
        label="AWS remediation plan surfaces"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        columns={[
          {
            key: 'change',
            header: 'Change plan',
            render: (row) => <strong>{row.title}</strong>
          },
          { key: 'category', header: 'Type', render: (row) => row.category },
          { key: 'owner', header: 'Owner', render: (row) => row.owner },
          { key: 'next', header: 'Next action', render: (row) => row.nextAction },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
        ]}
      />
    </>
  );
}

function AWSGovernanceContent({
  connection,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const rows: AWSRiskOperationTableRow[] = [
    {
      id: 'warn',
      title: 'Warn on risky activity',
      category: 'Warn',
      evidence: 'Runtime evidence',
      owner: 'Security',
      blastRadius: connection?.account_id ? `Account ${connection.account_id}` : 'Account pending',
      nextAction: 'Define routing',
      status: 'advisory',
      stage: 'coming',
      filters: { decision: 'warn', mode: 'advisory', evidence: 'runtime-required', search: '' },
      searchText: inventorySearchText(['warn', 'runtime', 'advisory'])
    },
    {
      id: 'approval',
      title: 'Require approval',
      category: 'Approval',
      evidence: 'Approval workflow',
      owner: 'Security',
      blastRadius: 'Sensitive action pending',
      nextAction: 'Map owner',
      status: 'not enforcing',
      stage: 'not-available',
      filters: { decision: 'approval', mode: 'not-enforcing', evidence: 'approval-required', search: '' },
      searchText: inventorySearchText(['approval', 'sensitive access', 'not enforcing'])
    },
    {
      id: 'quarantine',
      title: 'Quarantine candidate identity',
      category: 'Quarantine',
      evidence: 'High-confidence finding',
      owner: 'Security',
      blastRadius: 'Identity scope pending',
      nextAction: 'Add safety gates',
      status: 'not enforcing',
      stage: 'not-available',
      filters: { decision: 'quarantine', mode: 'not-enforcing', evidence: 'audit-required', search: '' },
      searchText: inventorySearchText(['quarantine', 'kill switch', 'rollback'])
    },
    {
      id: 'recommend-deny',
      title: 'Recommend deny policy',
      category: 'Recommend deny',
      evidence: 'Runtime + approval',
      owner: 'Platform',
      blastRadius: 'Permission boundary pending',
      nextAction: 'Draft advisory',
      status: 'advisory',
      stage: 'coming',
      filters: { decision: 'recommend-deny', mode: 'advisory', evidence: 'runtime-required,approval-required', search: '' },
      searchText: inventorySearchText(['recommend deny', 'session policy', 'permission boundary', 'agentcore'])
    }
  ];
  const displayedRows = filterAWSInventoryRows(rows, filters);

  return (
    <>
      <AWSRiskOperationFilterSet routeID="governance" filters={filters} onChange={onFiltersChange} />
      <DomainDataTable
        label="AWS governance decision modes"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        columns={[
          {
            key: 'decision',
            header: 'Decision mode',
            render: (row) => <strong>{row.title}</strong>
          },
          { key: 'evidence', header: 'Evidence required', render: (row) => row.evidence },
          { key: 'owner', header: 'Owner', render: (row) => row.owner },
          { key: 'next', header: 'Next action', render: (row) => row.nextAction },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
        ]}
      />
    </>
  );
}

function ProductAWSRiskOperationsPage({ routeID }: { routeID: AWSRiskOperationRouteID }) {
  const data = useAWSInventoryData();
  const { scope, environmentScope, selectedEnvironmentID, connection, connectionLoading, connectionError } = data;
  const copy = AWS_RISK_OPERATION_PAGE_COPY[routeID];
  const [activeFilters, setActiveFilters] = useState<AWSInventoryFilterState>(() => ({
    ...AWS_RISK_OPERATION_FILTER_DEFAULTS[routeID]
  }));

  const onFiltersChange = (nextFilters: AWSInventoryFilterState): void => {
    setActiveFilters(nextFilters);
  };

  useEffect(() => {
    setActiveFilters({ ...AWS_RISK_OPERATION_FILTER_DEFAULTS[routeID] });
  }, [routeID]);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">{copy.title}</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading AWS operations.</p>
      </section>
    );
  }

  const statusTone = awsDomainTone(connection, environmentScope.loading || connectionLoading);
  const connectPath = awsRouteLink(scope, 'connect', selectedEnvironmentID);
  const homePath = appendEnvironmentQuery(buildScopedPath(scope, 'aws'), selectedEnvironmentID);
  const graphPath = awsRouteLink(scope, 'graph', selectedEnvironmentID);
  const findingsPath = awsRouteLink(scope, 'findings', selectedEnvironmentID);
  const remediationPath = awsRouteLink(scope, 'remediation', selectedEnvironmentID);
  const governancePath = awsRouteLink(scope, 'governance', selectedEnvironmentID);
  const status =
    environmentScope.loading || connectionLoading
      ? 'Loading operations'
      : connectionError
        ? 'Needs retry'
        : connection?.connected
          ? copy.statusLabel
          : 'Setup required';
  // Suppress engineering-status copy ("Setup required" / "Not ingesting"
  // / "Advisory only") and the noun-list secondary nav. The header subtitle
  // is the same state-driven single line used across the AWS section.
  const riskSubtitle = (() => {
    if (environmentScope.loading || connectionLoading) {
      return `Loading ${copy.title.toLowerCase()}…`;
    }
    if (connectionError) {
      return "Couldn't load AWS status.";
    }
    if (!connection?.connected) {
      return 'Not connected for this environment.';
    }
    return copy.description;
  })();
  // Silence unused linter warnings for the path helpers that used to feed
  // the prior secondary-nav noun-list; they still exist for downstream
  // pages but are not surfaced as header CTAs anymore.
  void graphPath;
  void remediationPath;
  void governancePath;
  void homePath;

  return (
    <DomainPageShell
      domain="aws"
      eyebrow={null}
      hideLogo
      title={copy.title}
      description={riskSubtitle}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={data.onChangeEnvironment} />}
      statusTone={connectionError ? 'danger' : statusTone}
      primaryAction={
        connectionError || environmentScope.loading || connectionLoading
          ? undefined
          : connection?.connected
            ? undefined
            : { label: 'Connect AWS', to: connectPath, variant: 'primary' }
      }
    >
      <div className="idt-aws-risk-page">
        {connectionError ? (
          <DomainErrorState
            title="Couldn't load AWS status"
            body={connectionError}
            retryAction={{ label: 'Retry', onClick: data.refreshConnection }}
          />
        ) : null}

        {!environmentScope.loading && !connectionLoading && !connectionError ? (
          <AWSRiskOperationPrerequisites
            scope={scope}
            selectedEnvironmentID={selectedEnvironmentID}
            connection={connection}
            connectPath={connectPath}
          />
        ) : null}

        {routeID === 'runtime' ? (
          <AWSRuntimeEvidenceContent connection={connection} filters={activeFilters} onFiltersChange={onFiltersChange} />
        ) : null}
        {routeID === 'graph' ? (
          <AWSGraphExplorerContent
            connection={connection}
            filters={activeFilters}
            onFiltersChange={onFiltersChange}
          />
        ) : null}
        {routeID === 'findings' ? (
          <AWSFindingsContent
            filters={activeFilters}
            onFiltersChange={onFiltersChange}
          />
        ) : null}
        {routeID === 'remediation' ? (
          <AWSRemediationContent connection={connection} filters={activeFilters} onFiltersChange={onFiltersChange} />
        ) : null}
        {routeID === 'governance' ? (
          <AWSGovernanceContent connection={connection} filters={activeFilters} onFiltersChange={onFiltersChange} />
        ) : null}
      </div>
    </DomainPageShell>
  );
}

export function ProductAWSRuntimePage() {
  return <ProductAWSRiskOperationsPage routeID="runtime" />;
}

export function ProductAWSGraphPage() {
  return <ProductAWSRiskOperationsPage routeID="graph" />;
}

export function ProductAWSFindingsPage() {
  return <ProductAWSRiskOperationsPage routeID="findings" />;
}

export function ProductAWSRemediationPage() {
  return <ProductAWSRiskOperationsPage routeID="remediation" />;
}

export function ProductAWSGovernancePage() {
  return <ProductAWSRiskOperationsPage routeID="governance" />;
}

export function ProductAWSControlCenterPage() {
  const params = useParams<ScopeRouteParams>();
  const location = useLocation();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);
  const requestedEnvironmentID = useMemo(() => environmentIDFromSearch(location.search), [location.search]);
  const environmentScope = useEnvironmentScope(scope, requestedEnvironmentID);
  const selectedEnvironmentID = environmentScope.selectedID;
  const [connection, setConnection] = useState<AWSConnectionStatus | null>(null);
  const [connectionLoading, setConnectionLoading] = useState(false);
  const [connectionError, setConnectionError] = useState('');
  const [baseline, setBaseline] = useState<AWSPlatformBaselineResult | null>(null);
  const [baselineLoading, setBaselineLoading] = useState(false);
  const [baselineError, setBaselineError] = useState('');
  const connectionRequestRef = useRef(0);
  const baselineRequestRef = useRef(0);
  const selectedEnvironmentIDRef = useRef(selectedEnvironmentID);
  selectedEnvironmentIDRef.current = selectedEnvironmentID;

  const refreshConnection = useCallback(async () => {
    const requestID = ++connectionRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    if (!scope || !requestEnvironmentID) {
      setConnection(null);
      setConnectionError('');
      setConnectionLoading(false);
      return;
    }
    const isStale = () => requestID !== connectionRequestRef.current || selectedEnvironmentIDRef.current !== requestEnvironmentID;
    setConnectionLoading(true);
    setConnectionError('');
    try {
      const response = await apiClient.getAWSProjectConnection(
        scope.workspaceID,
        requestEnvironmentID,
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setConnection(response.connection);
    } catch (error) {
      if (isStale()) {
        return;
      }
      setConnection(null);
      setConnectionError(formatAPIError(error, 'Unable to load AWS connection status.'));
    } finally {
      if (!isStale()) {
        setConnectionLoading(false);
      }
    }
  }, [scope?.tenantID, scope?.workspaceID, selectedEnvironmentID]);

  const refreshBaseline = useCallback(async () => {
    const requestID = ++baselineRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    if (!scope || !requestEnvironmentID) {
      setBaseline(null);
      setBaselineError('');
      setBaselineLoading(false);
      return;
    }
    const isStale = () => requestID !== baselineRequestRef.current || selectedEnvironmentIDRef.current !== requestEnvironmentID;
    setBaselineLoading(true);
    setBaselineError('');
    try {
      const response = await apiClient.getAWSProjectBaseline(
        scope.workspaceID,
        requestEnvironmentID,
        undefined,
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setBaseline(response.baseline);
    } catch (error) {
      if (isStale()) {
        return;
      }
      setBaseline(null);
      setBaselineError(formatAPIError(error, 'Unable to load AWS baseline gate.'));
    } finally {
      if (!isStale()) {
        setBaselineLoading(false);
      }
    }
  }, [scope?.tenantID, scope?.workspaceID, selectedEnvironmentID]);

  const verifyBaseline = useCallback(async () => {
    const requestID = ++baselineRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    if (!scope || !requestEnvironmentID) {
      return;
    }
    const isStale = () => requestID !== baselineRequestRef.current || selectedEnvironmentIDRef.current !== requestEnvironmentID;
    setBaselineLoading(true);
    setBaselineError('');
    try {
      const response = await apiClient.verifyAWSProjectBaseline(
        scope.workspaceID,
        requestEnvironmentID,
        { connector_id: connection?.connector_id },
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setBaseline(response.baseline);
    } catch (error) {
      if (isStale()) {
        return;
      }
      setBaselineError(formatAPIError(error, 'Unable to verify AWS baseline gate.'));
    } finally {
      if (!isStale()) {
        setBaselineLoading(false);
      }
    }
  }, [scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, connection?.connector_id]);

  useEffect(() => {
    void refreshConnection();
    void refreshBaseline();
    return () => {
      connectionRequestRef.current += 1;
      baselineRequestRef.current += 1;
    };
  }, [refreshConnection, refreshBaseline]);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">AWS</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading AWS.</p>
      </section>
    );
  }

  const handleEnvironmentChange = (environmentID: string) => {
    connectionRequestRef.current += 1;
    baselineRequestRef.current += 1;
    setConnection(null);
    setBaseline(null);
    setConnectionError('');
    setBaselineError('');
    navigate(
      {
        pathname: location.pathname,
        search: environmentSearch(location.search, environmentID)
      },
      { replace: false }
    );
  };

  const connectPath = awsRouteLink(scope, 'connect', selectedEnvironmentID);
  const findingsPath = awsRouteLink(scope, 'findings', selectedEnvironmentID);
  const failedChecks = connection?.permission_checks.filter((check) => !check.passed).length ?? 0;
  const statusTone = awsDomainTone(connection, connectionLoading || environmentScope.loading);
  const connected = Boolean(connection?.connected);
  const awaitingFirstLoad =
    (environmentScope.loading || connectionLoading) && !connection && !connectionError;
  const hasConnectionError = Boolean(connectionError);
  const baselineReady = baseline?.status === 'ready';
  const baselineKnown = Boolean(baseline);

  // Subtitle: one short line. State-aware. No KPI cards.
  const subtitle = (() => {
    if (awaitingFirstLoad) {
      return 'Loading AWS status…';
    }
    if (hasConnectionError) {
      return "Couldn't load AWS status.";
    }
    if (!connected) {
      const bits: string[] = ['Not connected'];
      if (connection && !connection.external_id_configured) {
        bits.push('External ID not set');
      }
      return bits.join(' · ');
    }
    const bits: string[] = [];
    if (connection?.account_id) {
      bits.push(connection.account_id);
    }
    if (connection?.region) {
      bits.push(connection.region);
    }
    if (failedChecks > 0) {
      bits.push(`${failedChecks} permission check${failedChecks === 1 ? '' : 's'} failing`);
    } else if (connection?.permission_checks.length) {
      bits.push('Permissions OK');
    }
    if (baselineReady) {
      bits.push('Baseline ready');
    } else if (baselineKnown) {
      bits.push('Baseline needs attention');
    }
    return bits.join(' · ');
  })();

  // Primary CTA: state-aware. Connect when disconnected, Findings when connected,
  // omitted while the first load is in flight or the status request errored
  // (matches the pattern used on the GitHub overview and Connect pages).
  const primaryAction = awaitingFirstLoad || hasConnectionError
    ? undefined
    : connected
      ? { label: 'Findings', to: findingsPath, variant: 'primary' as const }
      : { label: 'Connect AWS', to: connectPath, variant: 'primary' as const };

  type AWSOverviewBanner = {
    id: string;
    message: ReactNode;
    detail?: string;
    actionLabel: string;
    actionTo?: string;
    actionOnClick?: () => void;
    tone: 'info' | 'warning' | 'danger';
  };

  // Single contextual banner: one recommendation, one button. The actual
  // state surfaces (recent findings, scan history, etc.) live on their own
  // sub-pages — this page just nudges the user toward the next thing.
  const banner: AWSOverviewBanner | null = (() => {
    if (awaitingFirstLoad || hasConnectionError) {
      return null;
    }
    if (!selectedEnvironmentID) {
      return {
        id: 'pick-environment',
        message: 'Pick an environment to load AWS status.',
        actionLabel: 'Open environments',
        actionTo: buildProjectsPath(scope),
        tone: 'info'
      };
    }
    if (!connected) {
      return {
        id: 'connect-aws',
        message: 'Connect AWS to start scanning this environment.',
        actionLabel: 'Connect AWS',
        actionTo: connectPath,
        tone: 'info'
      };
    }
    if (failedChecks > 0) {
      return {
        id: 'fix-permissions',
        message: `${failedChecks} permission check${failedChecks === 1 ? '' : 's'} failing.`,
        actionLabel: 'Open setup',
        actionTo: connectPath,
        tone: 'warning'
      };
    }
    if (!baselineReady) {
      return {
        id: 'run-baseline',
        message: 'Baseline not verified yet for this environment.',
        actionLabel: baselineLoading ? 'Running…' : 'Run baseline',
        actionOnClick: () => void verifyBaseline(),
        tone: 'info'
      };
    }
    return null;
  })();

  const showCards = !awaitingFirstLoad && !hasConnectionError && Boolean(selectedEnvironmentID);

  return (
    <DomainPageShell
      domain="aws"
      eyebrow={null}
      hideLogo
      title="AWS"
      description={subtitle}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={handleEnvironmentChange} />}
      statusTone={statusTone}
      primaryAction={primaryAction}
    >
      {connectionError ? (
        <DomainErrorState
          title="Couldn't load AWS status"
          body={connectionError}
          retryAction={{ label: 'Retry', onClick: () => void refreshConnection() }}
        />
      ) : null}
      {baselineError && !connectionError ? (
        <DomainErrorState
          title="Couldn't load AWS baseline"
          body={baselineError}
          retryAction={{ label: 'Retry', onClick: () => void refreshBaseline() }}
        />
      ) : null}
      {banner ? <AWSOverviewBannerView banner={banner} /> : null}
      {showCards ? (
        <section className="idt-aws-control-grid" aria-label="AWS sections">
          {AWS_CONTROL_CARDS.map((card) => (
            <Link
              key={card.id}
              className={`idt-aws-capability-card is-${card.stage}`}
              to={awsRouteLink(scope, card.routeID, selectedEnvironmentID)}
            >
              <strong>{card.label}</strong>
              <p>{card.detail}</p>
            </Link>
          ))}
        </section>
      ) : null}
    </DomainPageShell>
  );
}

function AWSOverviewBannerView({
  banner
}: {
  banner: {
    id: string;
    message: ReactNode;
    detail?: string;
    actionLabel: string;
    actionTo?: string;
    actionOnClick?: () => void;
    tone: 'info' | 'warning' | 'danger';
  };
}) {
  return (
    <section
      className={`idt-overview-banner is-${banner.tone}`}
      aria-label="AWS action recommendation"
      data-banner-id={banner.id}
    >
      <div>
        <p>{banner.message}</p>
        {banner.detail ? <small>{banner.detail}</small> : null}
      </div>
      {banner.actionTo ? (
        <Link to={banner.actionTo} className="idt-btn idt-btn-primary idt-domain-action">
          <span>{banner.actionLabel}</span>
        </Link>
      ) : (
        <button
          type="button"
          className="idt-btn idt-btn-primary idt-domain-action"
          onClick={banner.actionOnClick}
        >
          <span>{banner.actionLabel}</span>
        </button>
      )}
    </section>
  );
}

export function ProductDomainRoutePage({
  domain,
  routeID = 'overview'
}: {
  domain: SourceProvider;
  routeID?: ProductDomainRouteID;
}) {
  const params = useParams<ScopeRouteParams>();
  const location = useLocation();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);
  const requestedEnvironmentID = useMemo(() => environmentIDFromSearch(location.search), [location.search]);
  const environmentScope = useEnvironmentScope(scope, requestedEnvironmentID);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">Domain route</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading this domain section.</p>
      </section>
    );
  }

  const config = PRODUCT_DOMAIN_CONFIGS[domain];
  const route = findDomainRoute(domain, routeID);
  const selectedEnvironmentID = environmentScope.selectedID;
  const domainBasePath = appendEnvironmentQuery(buildScopedPath(scope, config.routePrefix), selectedEnvironmentID);
  const connectPath = appendEnvironmentQuery(
    domainRoutePath(scope, domain, findDomainRoute(domain, config.connectRouteID)),
    selectedEnvironmentID
  );
  const findingsPath = appendEnvironmentQuery(buildScopedPath(scope, `${config.routePrefix}/findings`), selectedEnvironmentID);
  const sectionPath = domainRoutePath(scope, domain, route);
  const handleEnvironmentChange = (environmentID: string) => {
    navigate(
      {
        pathname: location.pathname,
        search: environmentSearch(location.search, environmentID)
      },
      { replace: false }
    );
  };

  return (
    <DomainPageShell
      domain={domain}
      eyebrow={route.eyebrow}
      title={route.title}
      description={route.description}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={handleEnvironmentChange} />}
      status={route.status}
      statusTone="success"
      primaryAction={
        route.id === config.connectRouteID
          ? { label: `${config.navLabel} home`, to: domainBasePath, variant: 'secondary' }
          : { label: `Connect ${config.navLabel}`, to: connectPath, variant: 'primary' }
      }
      secondaryActions={route.id === 'findings' ? [] : [{ label: `${config.navLabel} findings`, to: findingsPath }]}
      aside={
        <DomainDetailPanel title="Route contract" eyebrow={config.navLabel}>
          <dl className="idt-domain-route-facts">
            <div>
              <dt>Path</dt>
              <dd>{sectionPath}</dd>
            </div>
            <div>
              <dt>Owner</dt>
              <dd>{config.navLabel}</dd>
            </div>
            <div>
              <dt>Phase</dt>
              <dd>{route.phase}</dd>
            </div>
          </dl>
        </DomainDetailPanel>
      }
    >
      <DomainKpiStrip label={`${route.title} readiness`} items={route.metrics} />
      <DomainStatusPanel
        eyebrow="Route foundation"
        title="Domain-owned entry point is ready"
        status="No legacy nav"
        tone="success"
      >
        <p>
          This page establishes the scoped route, provider mark, active subsection navigation, and premium placeholder
          state that later collector, graph, runtime, reasoning, remediation, and governance PRs can fill in order.
        </p>
      </DomainStatusPanel>
      <ProductRouteReadinessList route={route} />
    </DomainPageShell>
  );
}

type ConnectorConnectPageProps = {
  provider: SourceProvider;
  providerLabel: string;
};

function ProductConnectorConnectPage({ provider, providerLabel }: ConnectorConnectPageProps) {
  const params = useParams<ScopeRouteParams>();
  const location = useLocation();
  const scope = resolveScopeFromParams(params);
  const requestedEnvironmentID = useMemo(() => environmentIDFromSearch(location.search), [location.search]);
  const shouldLoadBackendFeatures =
    provider === 'github' ? FEATURE_CONNECTOR_GITHUB_V2 : provider === 'kubernetes' ? FEATURE_CONNECTOR_K8S : false;
  const { features: backendFeatures, loading: backendFeaturesLoading } = useBackendFeatures({
    enabled: shouldLoadBackendFeatures
  });
  const sourceAvailability = useMemo(() => buildSourceAvailability(backendFeatures), [backendFeatures]);
  const providerAvailability = sourceAvailability[provider];
  const [targetPath, setTargetPath] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (backendFeaturesLoading) {
      setTargetPath('');
      setError('');
      return;
    }
    if (!providerAvailability.visible || !providerAvailability.available) {
      setTargetPath('');
      setError(providerAvailability.unavailableMessage ?? `${providerLabel} connector is not available in this build.`);
      return;
    }
    if (!scope) {
      setTargetPath('/app');
      setError('');
      return;
    }

    let active = true;
    setTargetPath('');
    setError('');

    const resolveConnectorSetup = async () => {
      try {
        const requestedProjectID = normalizeValue(requestedEnvironmentID);
        if (requestedProjectID) {
          try {
            const requestedResponse = await apiClient.getProject(
              scope.workspaceID,
              requestedProjectID,
              buildProductAuthContext(scope)
            );
            if (!active) {
              return;
            }
            if (!isProjectArchived(requestedResponse.project)) {
              setTargetPath(appendSourceQuery(buildProjectPath(scope, requestedProjectID), provider));
              return;
            }
          } catch (requestError) {
            if (!active) {
              return;
            }
            if (isTransientProjectLookupError(requestError)) {
              setError(formatAPIError(requestError, `Unable to resolve ${providerLabel} connector setup.`));
              return;
            }
          }
        }
        const response = await apiClient.listProjects(
          scope.workspaceID,
          {
            limit: ENVIRONMENT_SELECTOR_LIMIT,
            sort_by: 'updated_at',
            sort_order: 'desc',
            include_archived: false
          },
          buildProductAuthContext(scope)
        );
        if (!active) {
          return;
        }
        const projectID = normalizeValue(response.items[0]?.project_id ?? '');
        setTargetPath(
          projectID
            ? appendSourceQuery(buildProjectPath(scope, projectID), provider)
            : appendSourceQuery(buildProjectsPath(scope), provider)
        );
      } catch (requestError) {
        if (!active) {
          return;
        }
        setError(formatAPIError(requestError, `Unable to resolve ${providerLabel} connector setup.`));
      }
    };

    void resolveConnectorSetup();

    return () => {
      active = false;
    };
  }, [
    backendFeaturesLoading,
    provider,
    providerAvailability.available,
    providerAvailability.unavailableMessage,
    providerAvailability.visible,
    providerLabel,
    requestedEnvironmentID,
    scope?.tenantID,
    scope?.workspaceID
  ]);

  if (targetPath) {
    return <Navigate to={targetPath} replace />;
  }

  if (error) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">Connect {providerLabel}</p>
        <h2>Unable to open {providerLabel} setup</h2>
        <p>{error}</p>
      </section>
    );
  }

  return (
    <AppRouteLoadingState
      title={`Opening ${providerLabel} setup`}
      body="Routing this domain entry point to the working connector setup for this workspace."
    />
  );
}

export function ProductAWSConnectPage() {
  const params = useParams<ScopeRouteParams>();
  const location = useLocation();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);
  const requestedEnvironmentID = useMemo(() => environmentIDFromSearch(location.search), [location.search]);
  const environmentScope = useEnvironmentScope(scope, requestedEnvironmentID);
  const selectedEnvironmentID = environmentScope.selectedID;
  const [connection, setConnection] = useState<AWSConnectionStatus | null>(null);
  const [loadingConnection, setLoadingConnection] = useState(false);
  const [refreshingConnection, setRefreshingConnection] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [baseline, setBaseline] = useState<AWSPlatformBaselineResult | null>(null);
  const [baselineLoading, setBaselineLoading] = useState(false);
  const [baselineError, setBaselineError] = useState('');
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
  const [awsPermissionTiers, setAWSPermissionTiers] = useState<AWSCapabilityPermissionTier[]>([]);
  const [awsPreviewOpen, setAWSPreviewOpen] = useState(false);
  const connectionRequestRef = useRef(0);
  const baselineRequestRef = useRef(0);
  const awsStartRequestRef = useRef(0);
  const awsPollRequestRef = useRef(0);
  const awsValidationRequestRef = useRef(0);
  const selectedEnvironmentIDRef = useRef(selectedEnvironmentID);
  const scopeKey = scope ? `${scope.tenantID}::${scope.workspaceID}` : '';
  const scopeKeyRef = useRef(scopeKey);
  selectedEnvironmentIDRef.current = selectedEnvironmentID;
  scopeKeyRef.current = scopeKey;

  const refreshConnection = useCallback(
    async (mode: 'initial' | 'manual' = 'initial') => {
      const requestID = ++connectionRequestRef.current;
      const requestEnvironmentID = selectedEnvironmentID;
      const requestScopeKey = scopeKeyRef.current;
      if (!scope || !requestEnvironmentID) {
        setConnection(null);
        setErrorMessage('');
        setLoadingConnection(false);
        setRefreshingConnection(false);
        return;
      }
      const isStale = () =>
        requestID !== connectionRequestRef.current ||
        selectedEnvironmentIDRef.current !== requestEnvironmentID ||
        scopeKeyRef.current !== requestScopeKey;
      if (mode === 'manual') {
        setRefreshingConnection(true);
      } else {
        setLoadingConnection(true);
      }
      setErrorMessage('');
      try {
        const response = await apiClient.getAWSProjectConnection(
          scope.workspaceID,
          requestEnvironmentID,
          buildProductAuthContext(scope)
        );
        if (isStale()) {
          return;
        }
        setConnection(response.connection);
        setAWSForm((current) => ({
          ...current,
          roleARN: response.connection.role_arn ?? '',
          region: response.connection.region ?? 'us-east-1',
          displayName: response.connection.display_name ?? ''
        }));
      } catch (error) {
        if (isStale()) {
          return;
        }
        setConnection(null);
        setErrorMessage(formatAPIError(error, 'Unable to load AWS connection.'));
      } finally {
        if (!isStale()) {
          setLoadingConnection(false);
          setRefreshingConnection(false);
        }
      }
    },
    [scope?.tenantID, scope?.workspaceID, selectedEnvironmentID]
  );

  const refreshBaseline = useCallback(async () => {
    const requestID = ++baselineRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    const requestScopeKey = scopeKeyRef.current;
    if (!scope || !requestEnvironmentID) {
      setBaseline(null);
      setBaselineError('');
      setBaselineLoading(false);
      return;
    }
    const isStale = () =>
      requestID !== baselineRequestRef.current ||
      selectedEnvironmentIDRef.current !== requestEnvironmentID ||
      scopeKeyRef.current !== requestScopeKey;
    setBaselineLoading(true);
    setBaselineError('');
    try {
      const response = await apiClient.getAWSProjectBaseline(
        scope.workspaceID,
        requestEnvironmentID,
        undefined,
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setBaseline(response.baseline);
    } catch (error) {
      if (isStale()) {
        return;
      }
      setBaseline(null);
      setBaselineError(formatAPIError(error, 'Unable to load AWS baseline gate.'));
    } finally {
      if (!isStale()) {
        setBaselineLoading(false);
      }
    }
  }, [scope?.tenantID, scope?.workspaceID, selectedEnvironmentID]);

  const verifyBaseline = useCallback(async () => {
    const requestID = ++baselineRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    const requestScopeKey = scopeKeyRef.current;
    if (!scope || !requestEnvironmentID) {
      return;
    }
    const isStale = () =>
      requestID !== baselineRequestRef.current ||
      selectedEnvironmentIDRef.current !== requestEnvironmentID ||
      scopeKeyRef.current !== requestScopeKey;
    setBaselineLoading(true);
    setBaselineError('');
    try {
      const response = await apiClient.verifyAWSProjectBaseline(
        scope.workspaceID,
        requestEnvironmentID,
        {
          connector_id: awsCloudFormationStart?.connector_id ?? connection?.connector_id
        },
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setBaseline(response.baseline);
    } catch (error) {
      if (isStale()) {
        return;
      }
      setBaselineError(formatAPIError(error, 'Unable to verify AWS baseline gate.'));
    } finally {
      if (!isStale()) {
        setBaselineLoading(false);
      }
    }
  }, [scope?.tenantID, scope?.workspaceID, selectedEnvironmentID, awsCloudFormationStart?.connector_id, connection?.connector_id]);


  useEffect(() => {
    connectionRequestRef.current += 1;
    baselineRequestRef.current += 1;
    awsStartRequestRef.current += 1;
    awsPollRequestRef.current += 1;
    awsValidationRequestRef.current += 1;
    setSuccessMessage('');
    setErrorMessage('');
    setBaseline(null);
    setBaselineError('');
    setSubmitting(false);
    setAWSCloudFormationStart(null);
    setAWSPermissionPreview([]);
    setAWSPermissionTiers([]);
    setAWSPreviewOpen(false);
    setAWSForm((current) => ({
      ...current,
      roleARN: '',
      externalID: '',
      region: 'us-east-1',
      displayName: ''
    }));
    void refreshConnection('initial');
    void refreshBaseline();
    return () => {
      connectionRequestRef.current += 1;
      baselineRequestRef.current += 1;
      awsStartRequestRef.current += 1;
      awsPollRequestRef.current += 1;
      awsValidationRequestRef.current += 1;
    };
  }, [refreshConnection, refreshBaseline]);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">Connect AWS</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading AWS setup.</p>
      </section>
    );
  }

  const handleEnvironmentChange = (environmentID: string) => {
    connectionRequestRef.current += 1;
    baselineRequestRef.current += 1;
    awsStartRequestRef.current += 1;
    awsPollRequestRef.current += 1;
    awsValidationRequestRef.current += 1;
    setConnection(null);
    setBaseline(null);
    setBaselineError('');
    navigate(
      {
        pathname: location.pathname,
        search: environmentSearch(location.search, environmentID)
      },
      { replace: false }
    );
  };

  const controlPath = appendEnvironmentQuery(buildScopedPath(scope, 'aws'), selectedEnvironmentID);
  const findingsPath = awsRouteLink(scope, 'findings', selectedEnvironmentID);
  const statusTone = awsDomainTone(connection, loadingConnection || refreshingConnection || environmentScope.loading);
  const baselineTone = awsBaselineTone(baseline, baselineLoading || environmentScope.loading);
  const canSubmit = !submitting && !loadingConnection && Boolean(selectedEnvironmentID);
  const activeConnectorID = awsCloudFormationStart?.connector_id ?? connection?.connector_id ?? '';

  const handleAWSCloudFormationStart = async () => {
    if (!selectedEnvironmentID) {
      setErrorMessage('Choose an environment before launching the AWS stack.');
      return;
    }
    setSubmitting(true);
    setSuccessMessage('');
    setErrorMessage('');
    const requestID = ++awsStartRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    const requestScopeKey = scopeKeyRef.current;
    const isStale = () =>
      requestID !== awsStartRequestRef.current ||
      selectedEnvironmentIDRef.current !== requestEnvironmentID ||
      scopeKeyRef.current !== requestScopeKey;
    try {
      const response = await apiClient.startAWSConnector(
        {
          workspace_id: scope.workspaceID,
          project_id: requestEnvironmentID,
          display_name: normalizeValue(awsForm.displayName) || undefined,
          region: normalizeValue(awsForm.region) || 'us-east-1',
          role_name: normalizeValue(awsForm.roleName) || undefined,
          stack_name: normalizeValue(awsForm.stackName) || undefined
        },
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setAWSCloudFormationStart(response);
      setAWSPermissionPreview(response.permission_preview);
      setAWSPermissionTiers(response.permission_tiers ?? []);
      setAWSForm((current) => ({ ...current, externalID: response.external_id }));
      setConnection(response.connection);
      setSuccessMessage('AWS CloudFormation launch is ready. Open the stack, then refresh status or validate the role.');
      if (typeof window !== 'undefined' && !/jsdom/i.test(window.navigator.userAgent)) {
        window.open(response.launch_url, '_blank', 'noopener,noreferrer');
      }
    } catch (error) {
      if (isStale()) {
        return;
      }
      setErrorMessage(formatAPIError(error, 'Unable to start AWS connector setup.'));
    } finally {
      if (!isStale()) {
        setSubmitting(false);
      }
    }
  };

  const handleAWSPoll = async () => {
    if (!selectedEnvironmentID || !activeConnectorID) {
      setErrorMessage('Launch the stack or save a connector before polling AWS status.');
      return;
    }
    setSubmitting(true);
    setErrorMessage('');
    const requestID = ++awsPollRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    const requestScopeKey = scopeKeyRef.current;
    const requestConnectorID = activeConnectorID;
    const isStale = () =>
      requestID !== awsPollRequestRef.current ||
      selectedEnvironmentIDRef.current !== requestEnvironmentID ||
      scopeKeyRef.current !== requestScopeKey;
    try {
      const response = await apiClient.pollAWSConnector(
        requestConnectorID,
        scope.workspaceID,
        requestEnvironmentID,
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setConnection(response.connection);
      setSuccessMessage(response.connection.connected ? 'AWS connector is active.' : 'AWS status refreshed.');
      if (response.connection.connected) {
        void verifyBaseline();
      }
    } catch (error) {
      if (isStale()) {
        return;
      }
      setErrorMessage(formatAPIError(error, 'Unable to poll AWS connector setup.'));
    } finally {
      if (!isStale()) {
        setSubmitting(false);
      }
    }
  };

  const handleAWSSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedEnvironmentID) {
      setErrorMessage('Choose an environment before validating AWS.');
      return;
    }
    setSubmitting(true);
    setSuccessMessage('');
    setErrorMessage('');
    const requestID = ++awsValidationRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    const requestScopeKey = scopeKeyRef.current;
    const requestConnectorID = activeConnectorID;
    const isStale = () =>
      requestID !== awsValidationRequestRef.current ||
      selectedEnvironmentIDRef.current !== requestEnvironmentID ||
      scopeKeyRef.current !== requestScopeKey;
    try {
      const roleARN = normalizeValue(awsForm.roleARN);
      if (!AWS_ROLE_ARN_PATTERN.test(roleARN)) {
        throw new Error('Enter a valid IAM role ARN, for example arn:aws:iam::123456789012:role/IdentrailReadOnly.');
      }
      const payload = {
        role_arn: roleARN,
        external_id: normalizeValue(awsForm.externalID) || undefined,
        region: normalizeValue(awsForm.region) || 'us-east-1',
        display_name: normalizeValue(awsForm.displayName) || undefined,
        session_name: normalizeValue(awsForm.sessionName) || undefined
      };
      const auth = buildProductAuthContext(scope);
      const response =
        FEATURE_CONNECTOR_AWS && requestConnectorID
          ? await apiClient.validateAWSConnector(
              requestConnectorID,
              {
                workspace_id: scope.workspaceID,
                project_id: requestEnvironmentID,
                role_arn: payload.role_arn,
                external_id: payload.external_id,
                region: payload.region,
                session_name: payload.session_name
              },
              auth
            )
          : await apiClient.upsertAWSProjectConnection(scope.workspaceID, requestEnvironmentID, payload, auth);
      if (isStale()) {
        return;
      }
      setConnection(response.connection);
      setSuccessMessage(
        response.connection.connected ? 'AWS connector is active.' : 'AWS connector saved with diagnostics to resolve.'
      );
      if (response.connection.connected) {
        void verifyBaseline();
      }
    } catch (error) {
      if (isStale()) {
        return;
      }
      setErrorMessage(formatAPIError(error, 'Unable to validate AWS connection.'));
    } finally {
      if (!isStale()) {
        setSubmitting(false);
      }
    }
  };

  const connectedNow = Boolean(connection?.connected);
  const awaitingFirstConnectLoad = loadingConnection && !connection && !errorMessage;
  const connectSubtitle = (() => {
    if (awaitingFirstConnectLoad || environmentScope.loading) {
      return 'Loading AWS status…';
    }
    if (!selectedEnvironmentID) {
      return 'Pick an environment to connect.';
    }
    if (!connectedNow) {
      return 'Not connected for this environment.';
    }
    const bits: string[] = [];
    if (connection?.account_id) {
      bits.push(connection.account_id);
    }
    if (connection?.region) {
      bits.push(connection.region);
    }
    const failed = connection?.permission_checks.filter((check) => !check.passed).length ?? 0;
    if (failed > 0) {
      bits.push(`${failed} permission check${failed === 1 ? '' : 's'} failing`);
    } else if (connection?.permission_checks.length) {
      bits.push('Permissions OK');
    }
    return bits.join(' · ');
  })();

  return (
    <DomainPageShell
      domain="aws"
      eyebrow={null}
      hideLogo
      title="Connect AWS"
      description={connectSubtitle}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={handleEnvironmentChange} />}
      statusTone={statusTone}
      primaryAction={
        awaitingFirstConnectLoad
          ? undefined
          : { label: 'AWS overview', to: controlPath, variant: 'primary' as const }
      }
    >
      {!selectedEnvironmentID && !environmentScope.loading ? (
        <DomainEmptyState
          title="Pick an environment"
          body="The AWS connection is scoped per environment. Pick or create one before continuing."
          nextAction={{ label: 'Open environments', to: appendSourceQuery(buildProjectsPath(scope), 'aws') }}
        />
      ) : null}

      {successMessage ? (
        <p role="status" className="idt-app-alert idt-app-alert-success">
          {successMessage}
        </p>
      ) : null}
      {errorMessage ? (
        <p role="alert" className="idt-app-alert idt-app-alert-error">
          {errorMessage}
        </p>
      ) : null}
      {baselineError ? (
        <p role="alert" className="idt-app-alert idt-app-alert-error">
          {baselineError}
        </p>
      ) : null}

      {selectedEnvironmentID ? (
        <div className="idt-aws-connect-layout">
          <section className="idt-source-config idt-aws-connect-panel" aria-label="AWS connector setup">
            <div className="idt-source-config-header">
              <div className="idt-source-config-title">
                <SourceLogoMark provider="aws" className="is-hero" />
                <div>
                  <h3>AWS read-only connector</h3>
                  <p>Launch the role stack or paste an existing role ARN.</p>
                </div>
              </div>
              <DomainStatusBadge variant={awsStatusVariant(connection)} detail={connection?.health_status ?? 'unknown'} />
            </div>

            <dl className="idt-source-meta">
              <div>
                <dt>Required access</dt>
                <dd>Read-only IAM role ARN</dd>
              </div>
              <div>
                <dt>Health</dt>
                <dd>{connectionHealth(connection ?? undefined)}</dd>
              </div>
              <div>
                <dt>Last validation</dt>
                <dd>{formatConnectionTime(connection?.last_validated_at ?? connection?.updated_at)}</dd>
              </div>
            </dl>

            <form className="idt-app-form idt-aws-connect-form" onSubmit={handleAWSSubmit}>
              {FEATURE_CONNECTOR_AWS ? (
                <article className="idt-source-install-card idt-aws-launch-card">
                  <div>
                    <h4>Launch read-only stack</h4>
                    <p>
                      {awsCloudFormationStart
                        ? 'Stack launch generated with external ID and permission preview.'
                        : 'Generate the IAM role, trust policy, and read-only permissions for this environment.'}
                    </p>
                  </div>
                  <div className="idt-source-actions">
                    <button
                      className="idt-btn idt-btn-dark"
                      type="button"
                      onClick={handleAWSCloudFormationStart}
                      disabled={!canSubmit}
                    >
                      {submitting ? 'Preparing...' : 'Launch stack'}
                    </button>
                    {awsCloudFormationStart ? (
                      <a className="idt-btn idt-btn-dark" href={awsCloudFormationStart.launch_url} target="_blank" rel="noreferrer">
                        <ExternalLink size={15} strokeWidth={1.8} aria-hidden="true" />
                        <span>Open stack</span>
                      </a>
                    ) : null}
                    {awsPermissionPreview.length > 0 ? (
                      <button className="idt-btn idt-btn-ghost" type="button" onClick={() => setAWSPreviewOpen(true)}>
                        Preview permissions
                      </button>
                    ) : null}
                    {activeConnectorID ? (
                      <button className="idt-btn idt-btn-ghost" type="button" onClick={handleAWSPoll} disabled={submitting}>
                        {submitting ? 'Refreshing...' : 'Refresh status'}
                      </button>
                    ) : null}
                  </div>
                </article>
              ) : (
                <article className="idt-source-install-card idt-aws-launch-card">
                  <div>
                    <h4>CloudFormation launch unavailable</h4>
                    <p>This build still supports direct role ARN validation and save.</p>
                  </div>
                </article>
              )}

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
              <button className="idt-btn idt-btn-primary" type="submit" disabled={!canSubmit}>
                {submitting ? 'Validating...' : 'Validate and save AWS'}
              </button>
            </form>
          </section>

          <div className="idt-aws-connect-side">
            <DomainStatusPanel
              eyebrow="Validation"
              title="Permission health and diagnostics"
              status={awsDiagnosticSummary(connection)}
              tone={statusTone === 'danger' ? 'danger' : statusTone}
              actions={[{ label: 'Refresh status', onClick: () => void refreshConnection('manual'), disabled: refreshingConnection }]}
            >
              <div className="idt-source-diagnostics" aria-label="AWS permission diagnostics">
                <AWSConnectionDiagnostics connection={connection} emptyLabel="Validate the role to populate permission checks." />
              </div>
            </DomainStatusPanel>

            <DomainStatusPanel
              eyebrow="Baseline gate"
              title="Platform readiness"
              status={awsBaselineLabel(baseline)}
              tone={baselineTone}
              actions={[
                { label: 'Run baseline', onClick: () => void verifyBaseline(), disabled: baselineLoading || !selectedEnvironmentID },
                { label: 'Refresh gate', onClick: () => void refreshBaseline(), variant: 'ghost', disabled: baselineLoading || !selectedEnvironmentID }
              ]}
            >
              <dl className="idt-domain-route-facts">
                <div>
                  <dt>Verified</dt>
                  <dd>{formatConnectionTime(baseline?.verified_at)}</dd>
                </div>
                <div>
                  <dt>Confidence</dt>
                  <dd>{baseline ? formatConfidenceScore(baseline.confidence) : 'N/A'}</dd>
                </div>
                <div>
                  <dt>Account / region</dt>
                  <dd>{awsBaselineAccountRegionLabel(baseline)}</dd>
                </div>
              </dl>
              <div className="idt-source-diagnostics" aria-label="AWS baseline diagnostics">
                <AWSBaselineGateSummary baseline={baseline} loading={baselineLoading} />
              </div>
            </DomainStatusPanel>

          </div>
        </div>
      ) : null}

      <PermissionPreviewModal
        open={awsPreviewOpen}
        title="AWS read-only connector policy"
        items={awsPermissionPreview}
        tiers={awsPermissionTiers}
        onClose={() => setAWSPreviewOpen(false)}
      />
    </DomainPageShell>
  );
}

type KubernetesDomainRouteID = Extract<ProductDomainRouteID, 'overview' | 'connect' | 'clusters' | 'workloads' | 'service-accounts' | 'findings' | 'remediation'>;

type KubernetesStage = 'wired' | 'planned' | 'unavailable';

type KubernetesTableRow = {
  id: string;
  name: string;
  kind: string;
  cluster: string;
  namespace: string;
  identity: string;
  evidence: string;
  nextAction: string;
  status: string;
  stage: KubernetesStage;
  filters: Record<string, string>;
  searchText: string;
};

type KubernetesFilterConfig = {
  id: string;
  label: string;
  options: Array<{ label: string; value: string }>;
};

type KubernetesFilterState = Record<string, string>;

const KUBERNETES_FILTER_DEFAULTS: Record<Exclude<KubernetesDomainRouteID, 'overview' | 'connect'>, KubernetesFilterState> = {
  clusters: { cluster: 'all', health: 'all', evidence: 'all', search: '' },
  workloads: { namespace: 'all', kind: 'all', identity: 'all', search: '' },
  'service-accounts': { namespace: 'all', binding: 'all', privilege: 'all', search: '' },
  findings: { cluster: 'all', namespace: 'all', serviceAccount: 'all', severity: 'all', status: 'all', search: '' },
  remediation: { change: 'all', approval: 'all', stage: 'all', search: '' }
};

const KUBERNETES_FILTERS: Record<Exclude<KubernetesDomainRouteID, 'overview' | 'connect'>, KubernetesFilterConfig[]> = {
  clusters: [
    { id: 'cluster', label: 'Cluster', options: [{ label: 'All clusters', value: 'all' }, { label: 'Connected cluster', value: 'connected' }, { label: 'Planned clusters', value: 'planned' }] },
    { id: 'health', label: 'Health', options: [{ label: 'All health', value: 'all' }, { label: 'Healthy', value: 'healthy' }, { label: 'Needs attention', value: 'needs-attention' }, { label: 'Unavailable', value: 'unavailable' }] },
    { id: 'evidence', label: 'Evidence', options: [{ label: 'All evidence', value: 'all' }, { label: 'Connector', value: 'connector' }, { label: 'Planned', value: 'planned' }] }
  ],
  workloads: [
    { id: 'namespace', label: 'Namespace', options: [{ label: 'All namespaces', value: 'all' }, { label: 'Known namespace', value: 'known' }, { label: 'Unknown namespace', value: 'unknown' }] },
    { id: 'kind', label: 'Kind', options: [{ label: 'All kinds', value: 'all' }, { label: 'Deployment', value: 'deployment' }, { label: 'CronJob', value: 'cronjob' }, { label: 'DaemonSet', value: 'daemonset' }] },
    { id: 'identity', label: 'Identity', options: [{ label: 'All identities', value: 'all' }, { label: 'Service account', value: 'service-account' }, { label: 'External identity', value: 'external' }] }
  ],
  'service-accounts': [
    { id: 'namespace', label: 'Namespace', options: [{ label: 'All namespaces', value: 'all' }, { label: 'Known namespace', value: 'known' }, { label: 'Unknown namespace', value: 'unknown' }] },
    { id: 'binding', label: 'Binding', options: [{ label: 'All bindings', value: 'all' }, { label: 'RoleBinding', value: 'rolebinding' }, { label: 'ClusterRoleBinding', value: 'clusterrolebinding' }] },
    { id: 'privilege', label: 'Privilege', options: [{ label: 'All privileges', value: 'all' }, { label: 'Read-only', value: 'read-only' }, { label: 'Elevated', value: 'elevated' }, { label: 'Unknown', value: 'unknown' }] }
  ],
  findings: [
    { id: 'cluster', label: 'Cluster', options: [{ label: 'All clusters', value: 'all' }, { label: 'Connected cluster', value: 'connected' }, { label: 'Unknown cluster', value: 'unknown' }] },
    { id: 'namespace', label: 'Namespace', options: [{ label: 'All namespaces', value: 'all' }, { label: 'Known namespace', value: 'known' }, { label: 'Unknown namespace', value: 'unknown' }] },
    { id: 'serviceAccount', label: 'Service account', options: [{ label: 'All accounts', value: 'all' }, { label: 'Known account', value: 'known' }, { label: 'Unknown account', value: 'unknown' }] },
    { id: 'severity', label: 'Severity', options: [{ label: 'All severities', value: 'all' }, { label: 'Critical', value: 'critical' }, { label: 'High', value: 'high' }, { label: 'Medium', value: 'medium' }, { label: 'Low', value: 'low' }] },
    { id: 'status', label: 'Status', options: [{ label: 'All statuses', value: 'all' }, { label: 'Open', value: 'open' }, { label: 'Queued', value: 'queued' }, { label: 'Unavailable', value: 'unavailable' }] }
  ],
  remediation: [
    { id: 'change', label: 'Change', options: [{ label: 'All changes', value: 'all' }, { label: 'RBAC hardening', value: 'rbac-hardening' }, { label: 'Service account', value: 'service-account' }, { label: 'Manifest patch', value: 'manifest-patch' }] },
    { id: 'approval', label: 'Approval', options: [{ label: 'All approvals', value: 'all' }, { label: 'Platform required', value: 'platform-required' }, { label: 'Security required', value: 'security-required' }] },
    { id: 'stage', label: 'Stage', options: [{ label: 'All stages', value: 'all' }, { label: 'Draft', value: 'draft' }, { label: 'Not active', value: 'not-active' }] }
  ]
};

function kubernetesRouteLink(scope: ProductSession, routeID: ProductDomainRouteID, environmentID: string): string {
  return appendEnvironmentQuery(domainRoutePath(scope, 'kubernetes', findDomainRoute('kubernetes', routeID)), environmentID);
}

function kubernetesStatusVariant(
  connection: KubernetesConnectionStatus | null,
  loading = false
): 'connected' | 'disconnected' | 'needs-attention' | 'degraded' | 'coming-soon' {
  if (loading) {
    return 'coming-soon';
  }
  if (!connection) {
    return 'disconnected';
  }
  if (connection.connected && connection.health_status === 'healthy') {
    return 'connected';
  }
  if (connection.health_status === 'warning' || connection.status === 'degraded') {
    return 'degraded';
  }
  if (connection.health_status === 'error' || connection.diagnostics.some((diagnostic) => diagnostic.severity === 'error')) {
    return 'needs-attention';
  }
  return connection.connected ? 'connected' : 'disconnected';
}

function kubernetesConnectionLabel(connection: KubernetesConnectionStatus | null): string {
  if (!connection) {
    return 'Not connected';
  }
  if (connection.connected) {
    return 'Connected';
  }
  return formatTokenLabel(connection.status || 'disconnected');
}

function kubernetesScopeLabel(connection: KubernetesConnectionStatus | null, selectedEnvironmentID: string): string {
  if (connection?.cluster) {
    return connection.cluster;
  }
  if (connection?.context) {
    return connection.context;
  }
  return selectedEnvironmentID ? environmentFallbackLabel(selectedEnvironmentID) : 'No environment';
}

function kubernetesPermissionSummary(connection: KubernetesConnectionStatus | null): string {
  const checks = connection?.permission_checks ?? [];
  if (!checks.length) {
    return 'No checks';
  }
  const allowed = checks.filter((check) => check.allowed).length;
  return `${allowed}/${checks.length} allowed`;
}

function KubernetesPill({ stage, label }: { stage: KubernetesStage; label: string }) {
  return (
    <span className={`idt-kubernetes-pill is-${stage}`}>
      {label}
    </span>
  );
}

function useKubernetesAvailability() {
  const { features, loading } = useBackendFeatures({ enabled: FEATURE_CONNECTOR_K8S });
  const availability = useMemo(() => buildSourceAvailability(features).kubernetes, [features]);
  return {
    loading,
    available: availability.available,
    visible: availability.visible,
    unavailableMessage: availability.unavailableMessage ?? 'Connector disabled.'
  };
}

function useKubernetesDomainScope() {
  const params = useParams<ScopeRouteParams>();
  const location = useLocation();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);
  const requestedEnvironmentID = useMemo(() => environmentIDFromSearch(location.search), [location.search]);
  const environmentScope = useEnvironmentScope(scope, requestedEnvironmentID);
  const selectedEnvironmentID = environmentScope.selectedID;
  const onChangeEnvironment = (environmentID: string) => {
    navigate(
      {
        pathname: location.pathname,
        search: environmentSearch(location.search, environmentID)
      },
      { replace: false }
    );
  };
  return { scope, location, environmentScope, selectedEnvironmentID, onChangeEnvironment };
}

function useKubernetesConnection(scope: ProductSession | null, selectedEnvironmentID: string, enabled: boolean) {
  const [connection, setConnection] = useState<KubernetesConnectionStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const requestRef = useRef(0);

  const refresh = useCallback(async () => {
    const requestID = ++requestRef.current;
    if (!scope || !selectedEnvironmentID || !enabled) {
      setConnection(null);
      setLoading(false);
      setError('');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await apiClient.getKubernetesProjectConnection(
        scope.workspaceID,
        selectedEnvironmentID,
        buildProductAuthContext(scope)
      );
      if (requestID !== requestRef.current) {
        return;
      }
      setConnection(response.connection);
    } catch (requestError) {
      if (requestID !== requestRef.current) {
        return;
      }
      setConnection(null);
      setError(formatAPIError(requestError, 'Unable to load Kubernetes connection.'));
    } finally {
      if (requestID === requestRef.current) {
        setLoading(false);
      }
    }
  }, [enabled, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID]);

  useEffect(() => {
    void refresh();
    return () => {
      requestRef.current += 1;
    };
  }, [refresh]);

  return { connection, loading, error, refresh };
}

function KubernetesUnavailableState({
  message,
  connectPath
}: {
  message: string;
  connectPath?: string;
}) {
  return (
    <DomainEmptyState
      eyebrow="Connector unavailable"
      title="Kubernetes unavailable"
      body={message}
      nextAction={connectPath ? { label: 'Open Connect Kubernetes', to: connectPath } : undefined}
    />
  );
}

function KubernetesMissingEnvironmentState({ scope }: { scope: ProductSession }) {
  return (
    <DomainEmptyState
      eyebrow="Environment required"
      title="Choose an environment"
      body="Kubernetes is scoped by environment."
      nextAction={{ label: 'Open environments', to: appendSourceQuery(buildProjectsPath(scope), 'kubernetes') }}
    />
  );
}

function KubernetesFilterSet({
  routeID,
  filters,
  onChange
}: {
  routeID: Exclude<KubernetesDomainRouteID, 'overview' | 'connect'>;
  filters: KubernetesFilterState;
  onChange: (filters: KubernetesFilterState) => void;
}) {
  const onFilterChange = (id: string, value: string) => onChange({ ...filters, [id]: value });
  const onSearchChange = (event: ChangeEvent<HTMLInputElement>) => onChange({ ...filters, search: event.target.value });
  return (
    <DomainFilterBar label={`${PRODUCT_DOMAIN_CONFIGS.kubernetes.routes.find((route) => route.id === routeID)?.title ?? 'Kubernetes'} filters`}>
      {KUBERNETES_FILTERS[routeID].map((filter) => (
        <label key={filter.id}>
          {filter.label}
          <select value={filters[filter.id] ?? 'all'} onChange={(event) => onFilterChange(filter.id, event.target.value)}>
            {filter.options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      ))}
      <label>
        Search
        <input
          value={filters.search ?? ''}
          onChange={onSearchChange}
          placeholder={`Search ${routeID.replace('-', ' ')}`}
          aria-label={`Search Kubernetes ${routeID}`}
        />
      </label>
    </DomainFilterBar>
  );
}

function filterKubernetesRows(rows: KubernetesTableRow[], filters: KubernetesFilterState): KubernetesTableRow[] {
  const search = normalizeValue(filters.search ?? '').toLowerCase();
  return rows.filter((row) => {
    const matchesFilters = Object.entries(filters).every(([key, value]) => {
      if (key === 'search' || value === 'all' || !value) {
        return true;
      }
      return row.filters[key]?.split(',').includes(value);
    });
    const matchesSearch = !search || row.searchText.toLowerCase().includes(search);
    return matchesFilters && matchesSearch;
  });
}

function buildKubernetesSubnav(scope: ProductSession, activeRouteID: ProductDomainRouteID, selectedEnvironmentID: string) {
  return PRODUCT_DOMAIN_CONFIGS.kubernetes.routes.map((route) => ({
    id: route.id,
    label: route.label,
    to: appendEnvironmentQuery(domainRoutePath(scope, 'kubernetes', route), selectedEnvironmentID),
    active: route.id === activeRouteID
  }));
}

function KubernetesPageShell({
  routeID,
  children,
  connection,
  loading,
  environmentScope,
  selectedEnvironmentID,
  onChangeEnvironment,
  scope,
  primaryAction,
  secondaryActions = []
}: {
  routeID: KubernetesDomainRouteID;
  children: ReactNode;
  connection: KubernetesConnectionStatus | null;
  loading: boolean;
  environmentScope: EnvironmentScopeState;
  selectedEnvironmentID: string;
  onChangeEnvironment: (environmentID: string) => void;
  scope: ProductSession;
  primaryAction?: { label: string; to?: string; onClick?: () => void; disabled?: boolean; variant?: 'primary' | 'secondary' | 'ghost' };
  secondaryActions?: Array<{ label: string; to: string; variant?: 'primary' | 'secondary' | 'ghost' }>;
}) {
  const route = findDomainRoute('kubernetes', routeID);
  const connectPath = kubernetesRouteLink(scope, 'connect', selectedEnvironmentID);
  const defaultPrimary =
    routeID === 'connect'
      ? { label: 'Kubernetes home', to: kubernetesRouteLink(scope, 'overview', selectedEnvironmentID), variant: 'secondary' as const }
      : { label: 'Connect Kubernetes', to: connectPath, variant: 'primary' as const };
  const statusVariant = kubernetesStatusVariant(connection, loading || environmentScope.loading);

  return (
    <DomainPageShell
      domain="kubernetes"
      eyebrow={route.eyebrow}
      title={route.title}
      description={route.description}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      status={<DomainStatusBadge variant={statusVariant} label={loading ? 'Loading' : kubernetesConnectionLabel(connection)} />}
      statusTone={connectionDomainTone(connection ?? undefined)}
      primaryAction={primaryAction ?? defaultPrimary}
      secondaryActions={secondaryActions}
      subnav={buildKubernetesSubnav(scope, routeID, selectedEnvironmentID)}
      subnavLabel="Kubernetes sections"
    >
      <div className="idt-kubernetes-page">{children}</div>
    </DomainPageShell>
  );
}

function KubernetesLoadingAndErrors({
  loading,
  error,
  refresh
}: {
  loading: boolean;
  error: string;
  refresh: () => void;
}) {
  return (
    <>
      {loading ? <DomainLoadingState label="Loading Kubernetes connection" /> : null}
      {error ? <DomainErrorState title="Unable to load Kubernetes state" body={error} retryAction={{ label: 'Retry', onClick: refresh }} /> : null}
    </>
  );
}

function KubernetesSectionRows({
  scope,
  selectedEnvironmentID,
  connection
}: {
  scope: ProductSession;
  selectedEnvironmentID: string;
  connection: KubernetesConnectionStatus | null;
}) {
  const rows = [
    {
      label: 'Clusters',
      focus: 'Version, health',
      status: connection?.cluster ?? 'Pending',
      to: kubernetesRouteLink(scope, 'clusters', selectedEnvironmentID)
    },
    {
      label: 'Workloads',
      focus: 'Namespace, account',
      status: connection?.connected ? 'Planned' : 'Connect first',
      to: kubernetesRouteLink(scope, 'workloads', selectedEnvironmentID)
    },
    {
      label: 'Service accounts / RBAC',
      focus: 'Roles, bindings',
      status: kubernetesPermissionSummary(connection),
      to: kubernetesRouteLink(scope, 'service-accounts', selectedEnvironmentID)
    },
    {
      label: 'Findings',
      focus: 'Open findings',
      status: 'None',
      to: kubernetesRouteLink(scope, 'findings', selectedEnvironmentID)
    },
    {
      label: 'Remediation',
      focus: 'Fixes, approvals',
      status: 'Draft',
      to: kubernetesRouteLink(scope, 'remediation', selectedEnvironmentID)
    }
  ];
  return (
    <DomainDataTable
      label="Kubernetes section links"
      rows={rows}
      getRowKey={(row) => row.label}
      columns={[
        { key: 'section', header: 'Section', render: (row) => <Link to={row.to}><strong>{row.label}</strong></Link> },
        { key: 'focus', header: 'Focus', render: (row) => row.focus },
        { key: 'status', header: 'Status', render: (row) => row.status }
      ]}
    />
  );
}

export function ProductKubernetesControlCenterPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useKubernetesDomainScope();
  const availability = useKubernetesAvailability();
  const data = useKubernetesConnection(scope, selectedEnvironmentID, availability.available && !availability.loading);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">Kubernetes</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading Kubernetes.</p>
      </section>
    );
  }

  return (
    <KubernetesPageShell
      routeID="overview"
      scope={scope}
      connection={data.connection}
      loading={data.loading || availability.loading}
      environmentScope={environmentScope}
      selectedEnvironmentID={selectedEnvironmentID}
      onChangeEnvironment={onChangeEnvironment}
      primaryAction={{ label: 'Connect Kubernetes', to: kubernetesRouteLink(scope, 'connect', selectedEnvironmentID), variant: 'primary' }}
      secondaryActions={[{ label: 'Kubernetes findings', to: kubernetesRouteLink(scope, 'findings', selectedEnvironmentID) }]}
    >
      <KubernetesLoadingAndErrors loading={data.loading || availability.loading} error={data.error} refresh={data.refresh} />
      {!selectedEnvironmentID && !environmentScope.loading ? <KubernetesMissingEnvironmentState scope={scope} /> : null}
      {!availability.available && !availability.loading ? (
        <KubernetesUnavailableState message={availability.unavailableMessage} connectPath={kubernetesRouteLink(scope, 'connect', selectedEnvironmentID)} />
      ) : null}
      <KubernetesSectionRows scope={scope} selectedEnvironmentID={selectedEnvironmentID} connection={data.connection} />
    </KubernetesPageShell>
  );
}

export function ProductKubernetesConnectPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useKubernetesDomainScope();
  const availability = useKubernetesAvailability();
  const data = useKubernetesConnection(scope, selectedEnvironmentID, availability.available && !availability.loading);
  const [form, setForm] = useState({
    mode: 'agent' as 'agent' | 'kubeconfig',
    displayName: '',
    apiURL: '',
    context: '',
    kubeconfig: ''
  });
  const [enrollment, setEnrollment] = useState<KubernetesConnectorStartResponse | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const submitRequestRef = useRef(0);
  const scopeKey = scope ? `${scope.tenantID}:${scope.workspaceID}` : '';
  const selectedEnvironmentIDRef = useRef(selectedEnvironmentID);
  const scopeKeyRef = useRef(scopeKey);
  selectedEnvironmentIDRef.current = selectedEnvironmentID;
  scopeKeyRef.current = scopeKey;

  useEffect(() => {
    submitRequestRef.current += 1;
    setEnrollment(null);
    setMessage('');
    setError('');
    setSubmitting(false);
  }, [selectedEnvironmentID, scopeKey]);

  useEffect(() => {
    setForm((current) => ({
      ...current,
      mode: data.connection?.connection_mode ?? current.mode,
      displayName: data.connection?.display_name ?? '',
      context: data.connection?.context ?? '',
      apiURL: '',
      kubeconfig: ''
    }));
  }, [
    data.connection?.connector_id,
    data.connection?.connection_mode,
    data.connection?.display_name,
    data.connection?.context,
    selectedEnvironmentID
  ]);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">Connect Kubernetes</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading Kubernetes setup.</p>
      </section>
    );
  }

  const clustersPath = kubernetesRouteLink(scope, 'clusters', selectedEnvironmentID);
  const canSubmit = availability.available && !availability.loading && Boolean(selectedEnvironmentID) && !submitting && !data.loading;

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedEnvironmentID) {
      setError('Choose an environment before connecting Kubernetes.');
      return;
    }
    if (availability.loading) {
      setError('Kubernetes availability is still loading.');
      return;
    }
    if (!availability.available) {
      setError(availability.unavailableMessage);
      return;
    }
    setSubmitting(true);
    setError('');
    setMessage('');
    setEnrollment(null);
    const requestID = ++submitRequestRef.current;
    const requestEnvironmentID = selectedEnvironmentID;
    const requestScopeKey = scopeKey;
    const requestScope = scope;
    const isStale = () =>
      requestID !== submitRequestRef.current ||
      selectedEnvironmentIDRef.current !== requestEnvironmentID ||
      scopeKeyRef.current !== requestScopeKey;
    try {
      if (form.mode === 'kubeconfig') {
        const response = await apiClient.upsertKubernetesKubeconfigConnector(
          {
            workspace_id: requestScope.workspaceID,
            project_id: requestEnvironmentID,
            connector_id: data.connection?.connector_id,
            display_name: normalizeValue(form.displayName) || undefined,
            context: normalizeValue(form.context) || undefined,
            kubeconfig: form.kubeconfig
          },
          buildProductAuthContext(requestScope)
        );
        if (isStale()) {
          return;
        }
        setMessage(response.connection.connected ? 'Kubeconfig active.' : 'Kubeconfig saved.');
      } else {
        const response = await apiClient.startKubernetesConnector(
          {
            workspace_id: requestScope.workspaceID,
            project_id: requestEnvironmentID,
            connector_id: data.connection?.connector_id,
            display_name: normalizeValue(form.displayName) || undefined,
            api_url: normalizeValue(form.apiURL) || undefined
          },
          buildProductAuthContext(requestScope)
        );
        if (isStale()) {
          return;
        }
        setEnrollment(response);
        setMessage('Enrollment token ready.');
      }
      if (!isStale()) {
        await data.refresh();
      }
    } catch (requestError) {
      if (isStale()) {
        return;
      }
      setError(formatAPIError(requestError, 'Unable to validate Kubernetes connection.'));
    } finally {
      if (!isStale()) {
        setSubmitting(false);
      }
    }
  };

  return (
    <KubernetesPageShell
      routeID="connect"
      scope={scope}
      connection={data.connection}
      loading={data.loading || availability.loading}
      environmentScope={environmentScope}
      selectedEnvironmentID={selectedEnvironmentID}
      onChangeEnvironment={onChangeEnvironment}
      secondaryActions={[{ label: 'Clusters', to: clustersPath }]}
    >
      <KubernetesLoadingAndErrors loading={data.loading || availability.loading} error={data.error} refresh={data.refresh} />
      {!selectedEnvironmentID && !environmentScope.loading ? <KubernetesMissingEnvironmentState scope={scope} /> : null}
      {!availability.available && !availability.loading ? <KubernetesUnavailableState message={availability.unavailableMessage} /> : null}
      {message ? <p role="status" className="idt-app-alert idt-app-alert-success">{message}</p> : null}
      {error ? <p role="alert" className="idt-app-alert idt-app-alert-error">{error}</p> : null}
      {selectedEnvironmentID ? (
        <form className="idt-source-config idt-kubernetes-connect-panel" onSubmit={submit} aria-label="Kubernetes connector setup">
          <div className="idt-source-config-header">
            <div className="idt-source-config-title">
              <SourceLogoMark provider="kubernetes" className="is-hero" />
              <div>
                <p className="idt-app-kicker">Read-only enrollment</p>
                <h3>Connector</h3>
              </div>
            </div>
            <button className="idt-btn idt-btn-ghost" type="button" onClick={data.refresh} disabled={data.loading}>
              Refresh
            </button>
          </div>
          <label>
            Mode
            <select value={form.mode} onChange={(event) => setForm((current) => ({ ...current, mode: event.target.value === 'kubeconfig' ? 'kubeconfig' : 'agent' }))}>
              <option value="agent">Agent</option>
              <option value="kubeconfig">Kubeconfig</option>
            </select>
          </label>
          <label>
            Display name
            <input value={form.displayName} onChange={(event) => setForm((current) => ({ ...current, displayName: event.target.value }))} placeholder="Production cluster" />
          </label>
          {form.mode === 'agent' ? (
            <label>
              API URL
              <input value={form.apiURL} onChange={(event) => setForm((current) => ({ ...current, apiURL: event.target.value }))} placeholder="https://api.identrail.com" />
            </label>
          ) : (
            <>
              <label>
                Kubeconfig context
                <input value={form.context} onChange={(event) => setForm((current) => ({ ...current, context: event.target.value }))} placeholder="production-admin" />
              </label>
              <label>
                Kubeconfig
                <textarea value={form.kubeconfig} onChange={(event) => setForm((current) => ({ ...current, kubeconfig: event.target.value }))} placeholder="Paste kubeconfig YAML" required />
              </label>
            </>
          )}
          <button className="idt-btn idt-btn-primary" type="submit" disabled={!canSubmit}>
            {submitting ? 'Preparing...' : form.mode === 'agent' ? 'Generate token' : 'Save kubeconfig'}
          </button>
          {enrollment ? (
            <article className="idt-kubernetes-enrollment">
              <div>
                <strong>Enrollment token</strong>
                <span>Expires {formatConnectionTime(enrollment.enrollment_expires_at)}</span>
                <code>{enrollment.enrollment_token}</code>
              </div>
              <div>
                <strong>Helm command</strong>
                <code>{enrollment.helm_command}</code>
              </div>
            </article>
          ) : null}
        </form>
      ) : null}
    </KubernetesPageShell>
  );
}

function buildKubernetesClusterRows(connection: KubernetesConnectionStatus | null): KubernetesTableRow[] {
  return [
    ...(connection?.cluster || connection?.context
      ? [
          {
            id: 'connected-cluster',
            name: connection.cluster || connection.context || 'Connected cluster',
            kind: connection.git_version || connection.platform || 'Cluster',
            cluster: kubernetesScopeLabel(connection, ''),
            namespace: 'All namespaces',
            identity: connection.connection_mode ? formatTokenLabel(connection.connection_mode) : 'Connector',
            evidence: 'Connector',
            nextAction: connection.connected ? 'Monitor heartbeat' : 'Resolve diagnostics',
            status: connection.connected ? 'connected' : 'needs attention',
            stage: connection.connected ? ('wired' as KubernetesStage) : ('planned' as KubernetesStage),
            filters: { cluster: 'connected', health: connection.connected ? 'healthy' : 'needs-attention', evidence: 'connector' },
            searchText: inventorySearchText([connection.cluster, connection.context, connection.git_version, connection.server])
          }
        ]
      : []),
    {
      id: 'coverage-gaps',
      name: 'Unenrolled clusters',
      kind: 'Coverage',
      cluster: 'Additional clusters',
      namespace: 'All namespaces',
      identity: 'Agent enrollment',
      evidence: 'Planned',
      nextAction: 'Enroll clusters',
      status: 'planned',
      stage: 'planned',
      filters: { cluster: 'planned', health: 'unavailable', evidence: 'planned' },
      searchText: inventorySearchText(['cluster coverage gaps enrollment planned'])
    }
  ];
}

export function ProductKubernetesClustersPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useKubernetesDomainScope();
  const availability = useKubernetesAvailability();
  const data = useKubernetesConnection(scope, selectedEnvironmentID, availability.available && !availability.loading);
  const [filters, setFilters] = useState(KUBERNETES_FILTER_DEFAULTS.clusters);
  const inventoryReady = availability.available && !availability.loading && Boolean(selectedEnvironmentID);
  const rows = inventoryReady ? filterKubernetesRows(buildKubernetesClusterRows(data.connection), filters) : [];

  if (!scope) {
    return <section className="idt-app-panel idt-app-panel-error" role="alert"><p className="idt-app-kicker">Kubernetes clusters</p><h2>Workspace route context is missing</h2></section>;
  }

  return (
    <KubernetesPageShell routeID="clusters" scope={scope} connection={data.connection} loading={data.loading || availability.loading} environmentScope={environmentScope} selectedEnvironmentID={selectedEnvironmentID} onChangeEnvironment={onChangeEnvironment}>
      <KubernetesLoadingAndErrors loading={data.loading || availability.loading} error={data.error} refresh={data.refresh} />
      {!selectedEnvironmentID && !environmentScope.loading ? <KubernetesMissingEnvironmentState scope={scope} /> : null}
      {!availability.available && !availability.loading ? <KubernetesUnavailableState message={availability.unavailableMessage} /> : null}
      {inventoryReady ? (
        <>
          <KubernetesFilterSet routeID="clusters" filters={filters} onChange={setFilters} />
          <DomainDataTable
            label="Cluster coverage"
            rows={rows}
            getRowKey={(row) => row.id}
            columns={[
              { key: 'cluster', header: 'Cluster', render: (row) => <strong>{row.name}</strong> },
              { key: 'version', header: 'Version / platform', render: (row) => row.kind },
              { key: 'mode', header: 'Mode', render: (row) => row.identity },
              { key: 'evidence', header: 'Evidence', render: (row) => row.evidence },
              { key: 'status', header: 'Status', render: (row) => <KubernetesPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
            ]}
          />
        </>
      ) : null}
    </KubernetesPageShell>
  );
}

function buildKubernetesWorkloadRows(connection: KubernetesConnectionStatus | null): KubernetesTableRow[] {
  const cluster = kubernetesScopeLabel(connection, '');
  return [
    {
      id: 'deployment-slot',
      name: 'Deployments',
      kind: 'Deployment',
      cluster,
      namespace: 'Known namespace',
      identity: 'Service account',
      evidence: connection?.connected ? 'Connector' : 'Planned',
      nextAction: 'Collect workloads',
      status: 'planned',
      stage: 'planned',
      filters: { namespace: connection?.context ? 'known' : 'unknown', kind: 'deployment', identity: 'service-account' },
      searchText: inventorySearchText(['deployment workload service account relationship'])
    },
    {
      id: 'cronjob-slot',
      name: 'CronJobs',
      kind: 'CronJob',
      cluster,
      namespace: 'Unknown namespace',
      identity: 'External identity',
      evidence: 'Planned',
      nextAction: 'Map jobs',
      status: 'planned',
      stage: 'planned',
      filters: { namespace: 'unknown', kind: 'cronjob', identity: 'external' },
      searchText: inventorySearchText(['cronjob automation external identity'])
    }
  ];
}

export function ProductKubernetesWorkloadsPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useKubernetesDomainScope();
  const availability = useKubernetesAvailability();
  const data = useKubernetesConnection(scope, selectedEnvironmentID, availability.available && !availability.loading);
  const [filters, setFilters] = useState(KUBERNETES_FILTER_DEFAULTS.workloads);
  const inventoryReady = availability.available && !availability.loading && Boolean(selectedEnvironmentID);
  const rows = inventoryReady ? filterKubernetesRows(buildKubernetesWorkloadRows(data.connection), filters) : [];

  if (!scope) {
    return <section className="idt-app-panel idt-app-panel-error" role="alert"><p className="idt-app-kicker">Kubernetes workloads</p><h2>Workspace route context is missing</h2></section>;
  }

  return (
    <KubernetesPageShell routeID="workloads" scope={scope} connection={data.connection} loading={data.loading || availability.loading} environmentScope={environmentScope} selectedEnvironmentID={selectedEnvironmentID} onChangeEnvironment={onChangeEnvironment}>
      <KubernetesLoadingAndErrors loading={data.loading || availability.loading} error={data.error} refresh={data.refresh} />
      {!selectedEnvironmentID && !environmentScope.loading ? <KubernetesMissingEnvironmentState scope={scope} /> : null}
      {!availability.available && !availability.loading ? <KubernetesUnavailableState message={availability.unavailableMessage} /> : null}
      {inventoryReady ? (
        <>
          <KubernetesFilterSet routeID="workloads" filters={filters} onChange={setFilters} />
          <DomainDataTable
            label="Workload identity"
            rows={rows}
            getRowKey={(row) => row.id}
            columns={[
              { key: 'workload', header: 'Workload', render: (row) => <strong>{row.name}</strong> },
              { key: 'kind', header: 'Kind', render: (row) => row.kind },
              { key: 'namespace', header: 'Namespace', render: (row) => row.namespace },
              { key: 'identity', header: 'Identity', render: (row) => row.identity },
              { key: 'status', header: 'Status', render: (row) => <KubernetesPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
            ]}
          />
        </>
      ) : null}
    </KubernetesPageShell>
  );
}

function buildKubernetesServiceAccountRows(connection: KubernetesConnectionStatus | null): KubernetesTableRow[] {
  return [
    {
      id: 'connector-rbac',
      name: connection?.agent_id ? `Agent ${connection.agent_id}` : 'Connector service account',
      kind: 'ServiceAccount',
      cluster: kubernetesScopeLabel(connection, ''),
      namespace: connection?.context || 'Known namespace',
      identity: 'Read-only role',
      evidence: connection?.permission_checks.length ? 'Permission checks' : 'Planned',
      nextAction: connection?.connected ? 'Review RBAC' : 'Connect Kubernetes',
      status: connection?.connected ? 'read only' : 'planned',
      stage: connection?.connected ? 'wired' : 'planned',
      filters: { namespace: connection?.context ? 'known' : 'unknown', binding: 'clusterrolebinding', privilege: 'read-only' },
      searchText: inventorySearchText(['service account rbac clusterrolebinding readonly identrail connector'])
    },
    {
      id: 'privilege-review',
      name: 'Elevated bindings',
      kind: 'ClusterRoleBinding',
      cluster: kubernetesScopeLabel(connection, ''),
      namespace: 'All namespaces',
      identity: 'Privilege',
      evidence: 'Planned',
      nextAction: 'Collect RBAC',
      status: 'planned',
      stage: 'planned',
      filters: { namespace: 'unknown', binding: 'clusterrolebinding', privilege: 'elevated' },
      searchText: inventorySearchText(['elevated binding review clusterrolebinding privilege'])
    }
  ];
}

export function ProductKubernetesServiceAccountsPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useKubernetesDomainScope();
  const availability = useKubernetesAvailability();
  const data = useKubernetesConnection(scope, selectedEnvironmentID, availability.available && !availability.loading);
  const [filters, setFilters] = useState(KUBERNETES_FILTER_DEFAULTS['service-accounts']);
  const inventoryReady = availability.available && !availability.loading && Boolean(selectedEnvironmentID);
  const rows = inventoryReady ? filterKubernetesRows(buildKubernetesServiceAccountRows(data.connection), filters) : [];

  if (!scope) {
    return <section className="idt-app-panel idt-app-panel-error" role="alert"><p className="idt-app-kicker">Kubernetes service accounts</p><h2>Workspace route context is missing</h2></section>;
  }

  return (
    <KubernetesPageShell routeID="service-accounts" scope={scope} connection={data.connection} loading={data.loading || availability.loading} environmentScope={environmentScope} selectedEnvironmentID={selectedEnvironmentID} onChangeEnvironment={onChangeEnvironment}>
      <KubernetesLoadingAndErrors loading={data.loading || availability.loading} error={data.error} refresh={data.refresh} />
      {!selectedEnvironmentID && !environmentScope.loading ? <KubernetesMissingEnvironmentState scope={scope} /> : null}
      {!availability.available && !availability.loading ? <KubernetesUnavailableState message={availability.unavailableMessage} /> : null}
      {inventoryReady ? (
        <>
          <KubernetesFilterSet routeID="service-accounts" filters={filters} onChange={setFilters} />
          <DomainDataTable
            label="Service accounts and RBAC"
            rows={rows}
            getRowKey={(row) => row.id}
            columns={[
              { key: 'account', header: 'Service account / binding', render: (row) => <strong>{row.name}</strong> },
              { key: 'namespace', header: 'Namespace', render: (row) => row.namespace },
              { key: 'identity', header: 'RBAC', render: (row) => row.identity },
              { key: 'next', header: 'Next action', render: (row) => row.nextAction },
              { key: 'status', header: 'Status', render: (row) => <KubernetesPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
            ]}
          />
        </>
      ) : null}
    </KubernetesPageShell>
  );
}

export function ProductKubernetesFindingsPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useKubernetesDomainScope();
  const availability = useKubernetesAvailability();
  const data = useKubernetesConnection(scope, selectedEnvironmentID, availability.available && !availability.loading);
  const [filters, setFilters] = useState(KUBERNETES_FILTER_DEFAULTS.findings);
  const inventoryReady = availability.available && !availability.loading && Boolean(selectedEnvironmentID);

  if (!scope) {
    return <section className="idt-app-panel idt-app-panel-error" role="alert"><p className="idt-app-kicker">Kubernetes findings</p><h2>Workspace route context is missing</h2></section>;
  }

  return (
    <KubernetesPageShell routeID="findings" scope={scope} connection={data.connection} loading={data.loading || availability.loading} environmentScope={environmentScope} selectedEnvironmentID={selectedEnvironmentID} onChangeEnvironment={onChangeEnvironment}>
      <KubernetesLoadingAndErrors loading={data.loading || availability.loading} error={data.error} refresh={data.refresh} />
      {!selectedEnvironmentID && !environmentScope.loading ? <KubernetesMissingEnvironmentState scope={scope} /> : null}
      {!availability.available && !availability.loading ? <KubernetesUnavailableState message={availability.unavailableMessage} /> : null}
      {inventoryReady ? (
        <>
          <KubernetesFilterSet routeID="findings" filters={filters} onChange={setFilters} />
          <DomainDataTable
            label="Kubernetes findings"
            rows={[] as KubernetesTableRow[]}
            getRowKey={(row) => row.id}
            emptyState={<DomainEmptyState eyebrow="Empty" title="No findings" body="No open items." />}
            columns={[
              { key: 'finding', header: 'Finding', render: (row) => <strong>{row.name}</strong> },
              { key: 'scope', header: 'Cluster / namespace', render: (row) => `${row.cluster} / ${row.namespace}` },
              { key: 'identity', header: 'Identity', render: (row) => row.identity },
              { key: 'status', header: 'Status', render: (row) => <KubernetesPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
            ]}
          />
        </>
      ) : null}
    </KubernetesPageShell>
  );
}

function buildKubernetesRemediationRows(): KubernetesTableRow[] {
  return [
    { id: 'rbac-hardening', name: 'RBAC reduction', kind: 'RBAC', cluster: 'Selected cluster', namespace: 'All namespaces', identity: 'Role / ClusterRole', evidence: 'Finding', nextAction: 'Draft fix', status: 'draft', stage: 'planned', filters: { change: 'rbac-hardening', approval: 'security-required', stage: 'draft' }, searchText: inventorySearchText(['rbac hardening role clusterrole']) },
    { id: 'service-account-change', name: 'Service account update', kind: 'ServiceAccount', cluster: 'Selected cluster', namespace: 'Known namespace', identity: 'Service account', evidence: 'Owner approval', nextAction: 'Assign owner', status: 'draft', stage: 'planned', filters: { change: 'service-account', approval: 'platform-required', stage: 'draft' }, searchText: inventorySearchText(['service account change owner approval']) },
    { id: 'manifest-patch', name: 'Manifest patch', kind: 'IaC', cluster: 'Selected cluster', namespace: 'Known namespace', identity: 'Manifest', evidence: 'Verification', nextAction: 'Map repo', status: 'not active', stage: 'unavailable', filters: { change: 'manifest-patch', approval: 'platform-required', stage: 'not-active' }, searchText: inventorySearchText(['manifest helm iac patch verification']) }
  ];
}

export function ProductKubernetesRemediationPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useKubernetesDomainScope();
  const availability = useKubernetesAvailability();
  const data = useKubernetesConnection(scope, selectedEnvironmentID, availability.available && !availability.loading);
  const [filters, setFilters] = useState(KUBERNETES_FILTER_DEFAULTS.remediation);
  const inventoryReady = availability.available && !availability.loading && Boolean(selectedEnvironmentID);
  const rows = inventoryReady ? filterKubernetesRows(buildKubernetesRemediationRows(), filters) : [];

  if (!scope) {
    return <section className="idt-app-panel idt-app-panel-error" role="alert"><p className="idt-app-kicker">Kubernetes remediation</p><h2>Workspace route context is missing</h2></section>;
  }

  return (
    <KubernetesPageShell routeID="remediation" scope={scope} connection={data.connection} loading={data.loading || availability.loading} environmentScope={environmentScope} selectedEnvironmentID={selectedEnvironmentID} onChangeEnvironment={onChangeEnvironment}>
      <KubernetesLoadingAndErrors loading={data.loading || availability.loading} error={data.error} refresh={data.refresh} />
      {!selectedEnvironmentID && !environmentScope.loading ? <KubernetesMissingEnvironmentState scope={scope} /> : null}
      {!availability.available && !availability.loading ? <KubernetesUnavailableState message={availability.unavailableMessage} /> : null}
      {inventoryReady ? (
        <>
          <KubernetesFilterSet routeID="remediation" filters={filters} onChange={setFilters} />
          <DomainDataTable
            label="Remediation"
            rows={rows}
            getRowKey={(row) => row.id}
            columns={[
              { key: 'plan', header: 'Plan', render: (row) => <strong>{row.name}</strong> },
              { key: 'kind', header: 'Type', render: (row) => row.kind },
              { key: 'evidence', header: 'Evidence', render: (row) => row.evidence },
              { key: 'next', header: 'Next action', render: (row) => row.nextAction },
              { key: 'status', header: 'Status', render: (row) => <KubernetesPill stage={row.stage} label={formatTokenLabel(row.status)} /> }
            ]}
          />
        </>
      ) : null}
    </KubernetesPageShell>
  );
}

// =====================================================
// GitHub domain pages (issue #1382 — GitHub Control Center)
// -----------------------------------------------------
// These four pages move GitHub setup, repository scan operation, and the
// Actions/OIDC posture surface out of the legacy /projects/:projectID source
// tab and into a domain-owned section. The repository scan launch, cancel,
// and connector status APIs are unchanged — these pages call them with the
// existing project_id-scoped contract so backend behavior is preserved.
// =====================================================

const GITHUB_CONTROL_CENTER_RECENT_SCANS_LIMIT = 5;
const GITHUB_CONTROL_CENTER_SCAN_FETCH_LIMIT = 50;
const GITHUB_REPOSITORIES_SCANS_LIMIT = 50;
const GITHUB_REMEDIATION_FINDINGS_LIMIT = 100;
const GITHUB_MAX_SCAN_PAGE_FETCHES = 50;
const GITHUB_DOMAIN_DATA_CACHE_LIMIT = 24;

type GitHubAvailability = {
  loading: boolean;
  available: boolean;
  unavailableMessage?: string;
};

function useGitHubAvailability(): GitHubAvailability {
  const { features, loading } = useBackendFeatures({ enabled: FEATURE_CONNECTOR_GITHUB_V2 });
  const availability = useMemo(() => buildSourceAvailability(features), [features]);
  return {
    loading,
    available: availability.github.available,
    unavailableMessage: availability.github.unavailableMessage
  };
}

type GitHubDomainScopeState = {
  scope: ProductSession | null;
  environmentScope: EnvironmentScopeState;
  selectedEnvironmentID: string;
  onChangeEnvironment: (environmentID: string) => void;
};

function useGitHubDomainScope(): GitHubDomainScopeState {
  const params = useParams<ScopeRouteParams>();
  const location = useLocation();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);
  const requestedEnvironmentID = useMemo(() => environmentIDFromSearch(location.search), [location.search]);
  const environmentScope = useEnvironmentScope(scope, requestedEnvironmentID);
  const onChangeEnvironment = useCallback(
    (environmentID: string) => {
      navigate(
        {
          pathname: location.pathname,
          search: environmentSearch(location.search, environmentID)
        },
        { replace: false }
      );
    },
    [location.pathname, location.search, navigate]
  );
  return {
    scope,
    environmentScope,
    selectedEnvironmentID: environmentScope.selectedID,
    onChangeEnvironment
  };
}

type GitHubSectionLink = {
  id: string;
  label: string;
  description: string;
  to: string;
};

function buildGitHubSectionLinks(scope: ProductSession, environmentID: string | undefined): GitHubSectionLink[] {
  const link = (id: string, suffix: string, label: string, description: string): GitHubSectionLink => ({
    id,
    label,
    description,
    to: appendEnvironmentQuery(buildScopedPath(scope, `github/${suffix}`), environmentID)
  });
  return [
    link('connect', 'connect', 'Connect GitHub', 'App installation and scope.'),
    link('repositories', 'repositories', 'Repositories', 'Scan history and controls.'),
    link('actions', 'actions', 'Actions / OIDC', 'Permissions and OIDC trust paths.'),
    link('findings', 'findings', 'Findings', 'Repository, workflow, and secret findings.'),
    link('remediation', 'remediation', 'Remediation', 'Fix PRs and verification.'),
    link('agentic-risk', 'agentic-risk', 'AI / Agentic Risk', 'Identities, MCP tools, prompts, and trust paths.')
  ];
}

type GitHubDomainDataState = {
  loading: boolean;
  error: string;
  connection: GitHubConnectionStatus | null;
  scans: RepoScanRecord[];
  reload: () => void;
};

type GitHubDomainDataSnapshot = {
  connection: GitHubConnectionStatus | null;
  scans: RepoScanRecord[];
};

type GitHubDomainDataLoadResult = GitHubDomainDataSnapshot & {
  error: string;
};

type GitHubDomainDataCacheWriteOptions = {
  expectedEpoch?: number;
};

type GitHubDomainDataFetchOptions = {
  bypassInFlight?: boolean;
};

const gitHubDomainDataCache = new Map<string, GitHubDomainDataSnapshot>();
const gitHubDomainDataRequests = new Map<string, Promise<GitHubDomainDataLoadResult>>();
const gitHubDomainDataCacheEpochs = new Map<string, number>();

function gitHubDomainDataCacheKey(
  scope: ProductSession | null,
  projectID: string | undefined,
  scanLimit: number
): string {
  const trimmedProject = normalizeValue(projectID);
  if (!scope || !trimmedProject) {
    return '';
  }
  return productScopedCacheKey([scope.tenantID, scope.workspaceID, trimmedProject, String(scanLimit)]);
}

function rememberGitHubDomainDataCacheEpoch(key: string, epoch: number) {
  if (!key) {
    return;
  }
  gitHubDomainDataCacheEpochs.delete(key);
  gitHubDomainDataCacheEpochs.set(key, epoch);
  while (gitHubDomainDataCacheEpochs.size > GITHUB_DOMAIN_DATA_CACHE_LIMIT * 2) {
    const oldestKey = gitHubDomainDataCacheEpochs.keys().next().value;
    if (!oldestKey) {
      break;
    }
    gitHubDomainDataCacheEpochs.delete(oldestKey);
  }
}

function gitHubDomainDataCacheEpoch(key: string): number {
  const epoch = key ? (gitHubDomainDataCacheEpochs.get(key) ?? 0) : 0;
  rememberGitHubDomainDataCacheEpoch(key, epoch);
  return epoch;
}

function bumpGitHubDomainDataCacheEpoch(key: string): number {
  const epoch = key ? (gitHubDomainDataCacheEpochs.get(key) ?? 0) + 1 : 0;
  rememberGitHubDomainDataCacheEpoch(key, epoch);
  return epoch;
}

function writeGitHubDomainDataCache(
  key: string,
  snapshot: GitHubDomainDataSnapshot,
  options: GitHubDomainDataCacheWriteOptions = {}
) {
  if (!key || !isCurrentProductScopedCacheKey(key)) {
    return;
  }
  if (options.expectedEpoch !== undefined && gitHubDomainDataCacheEpochs.get(key) !== options.expectedEpoch) {
    return;
  }
  gitHubDomainDataCache.delete(key);
  gitHubDomainDataCache.set(key, {
    connection: snapshot.connection,
    scans: snapshot.scans
  });
  while (gitHubDomainDataCache.size > GITHUB_DOMAIN_DATA_CACHE_LIMIT) {
    const oldestKey = gitHubDomainDataCache.keys().next().value;
    if (!oldestKey) {
      break;
    }
    gitHubDomainDataCache.delete(oldestKey);
    gitHubDomainDataCacheEpochs.delete(oldestKey);
  }
}

async function listRepoScansForSelectedRepositories(
  selectedRepositories: string[],
  scanLimit: number,
  auth: RequestAuthContext,
  options: { pageLimit?: number; maxPages?: number } = {}
): Promise<RepoScanRecord[]> {
  if (!selectedRepositories.length || scanLimit <= 0) {
    return [];
  }

  const pageLimit = Math.max(scanLimit, options.pageLimit ?? scanLimit);
  const maxPages = Math.max(1, options.maxPages ?? GITHUB_MAX_SCAN_PAGE_FETCHES);
  const allowed = new Set(selectedRepositories.map((repository) => canonicalGitHubRepositoryDisplay(repository).toLowerCase()));
  const matches: RepoScanRecord[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  let pagesFetched = 0;

  do {
    if (pagesFetched >= maxPages) {
      break;
    }
    pagesFetched += 1;

    const response = (await apiClient.listRepoScans(
      {
        limit: pageLimit,
        cursor,
        sort_by: 'started_at',
        sort_order: 'desc'
      },
      auth
    )) as { items: RepoScanRecord[]; next_cursor?: string };

    for (const scan of response.items) {
      if (allowed.has(canonicalGitHubRepositoryDisplay(scan.repository).toLowerCase())) {
        matches.push(scan);
      }
    }

    if (matches.length >= scanLimit) {
      break;
    }

    const nextCursor = response.next_cursor?.trim();
    if (!nextCursor) {
      break;
    }
    if (seenCursors.has(nextCursor)) {
      throw new Error('Repository scan pagination returned a repeated cursor');
    }
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  } while (cursor);

  return matches.slice(0, scanLimit);
}

function gitHubDomainDataRequestKey(cacheKey: string, scanPageLimit: number, maxScanPages: number): string {
  return [cacheKey, scanPageLimit, maxScanPages].join('::');
}

function fetchGitHubDomainDataSnapshot(
  scope: ProductSession,
  projectID: string,
  scanLimit: number,
  scanPageLimit: number,
  maxScanPages: number,
  auth: RequestAuthContext,
  options: GitHubDomainDataFetchOptions = {}
): Promise<GitHubDomainDataLoadResult> {
  const cacheKey = gitHubDomainDataCacheKey(scope, projectID, scanLimit);
  const requestKey = gitHubDomainDataRequestKey(cacheKey, scanPageLimit, maxScanPages);
  if (!options.bypassInFlight) {
    const inFlight = gitHubDomainDataRequests.get(requestKey);
    if (inFlight) {
      return inFlight;
    }
  }

  const request = (async () => {
    const statusResult = await apiClient.getGitHubConnectorStatus(scope.workspaceID, projectID, auth);
    const connection = statusResult.connection ?? null;
    let scans: RepoScanRecord[] = [];
    let error = '';

    try {
      scans = await listRepoScansForSelectedRepositories(connection?.selected_repositories ?? [], scanLimit, auth, {
        pageLimit: scanPageLimit,
        maxPages: maxScanPages
      });
    } catch (scanError) {
      error = formatAPIError(scanError, 'Unable to load recent repository scans.');
    }

    return { connection, scans, error };
  })();

  gitHubDomainDataRequests.set(requestKey, request);
  return request.finally(() => {
    if (gitHubDomainDataRequests.get(requestKey) === request) {
      gitHubDomainDataRequests.delete(requestKey);
    }
  });
}

function primeGitHubControlCenterDataCache(
  scope: ProductSession,
  projects: ProjectRecord[],
  availability: SourceAvailability,
  auth: RequestAuthContext
) {
  if (!availability.available) {
    return;
  }
  const defaultProject = projects.find((project) => !isProjectArchived(project));
  if (!defaultProject) {
    return;
  }
  const cacheKey = gitHubDomainDataCacheKey(
    scope,
    defaultProject.project_id,
    GITHUB_CONTROL_CENTER_RECENT_SCANS_LIMIT
  );
  if (!cacheKey || gitHubDomainDataCache.has(cacheKey)) {
    return;
  }
  const cacheEpoch = gitHubDomainDataCacheEpoch(cacheKey);

  void fetchGitHubDomainDataSnapshot(
    scope,
    defaultProject.project_id,
    GITHUB_CONTROL_CENTER_RECENT_SCANS_LIMIT,
    GITHUB_CONTROL_CENTER_SCAN_FETCH_LIMIT,
    GITHUB_MAX_SCAN_PAGE_FETCHES,
    auth
  )
    .then((snapshot) => {
      if (!snapshot.error) {
        writeGitHubDomainDataCache(cacheKey, { connection: snapshot.connection, scans: snapshot.scans }, {
          expectedEpoch: cacheEpoch
        });
      }
    })
    .catch(() => {
      // This is a background warm-up only. The Control Center performs the
      // authoritative load and surfaces any failure when the user opens it.
    });
}

function useGitHubDomainData(
  scope: ProductSession | null,
  projectID: string | undefined,
  available: boolean,
  scanLimit: number,
  scanPageLimit = scanLimit,
  maxScanPages = GITHUB_MAX_SCAN_PAGE_FETCHES
): GitHubDomainDataState {
  const cacheKey = gitHubDomainDataCacheKey(scope, projectID, scanLimit);
  const cachedSnapshot = cacheKey ? gitHubDomainDataCache.get(cacheKey) : undefined;
  const activeCacheKeyRef = useRef(cacheKey);
  const [connection, setConnection] = useState<GitHubConnectionStatus | null>(() => cachedSnapshot?.connection ?? null);
  const [scans, setScans] = useState<RepoScanRecord[]>(() => cachedSnapshot?.scans ?? []);
  // Start in the loading state when a fetch is going to happen so the very
  // first render does not falsely advertise the user as disconnected before
  // the API has even been called.
  const [loading, setLoading] = useState<boolean>(Boolean(scope) && available && !cachedSnapshot);
  const [error, setError] = useState('');
  const [reloadToken, setReloadToken] = useState(0);

  const reload = useCallback(() => setReloadToken((current) => current + 1), []);

  useEffect(() => {
    if (!scope || !available) {
      activeCacheKeyRef.current = '';
      setConnection(null);
      setScans([]);
      setError('');
      setLoading(false);
      return undefined;
    }
    const trimmedProject = normalizeValue(projectID);
    if (!trimmedProject) {
      // The environment scope has not finished resolving yet. Stay in the
      // loading state so the caller does not interpret connection=null as
      // "confirmed disconnected" while we are still waiting for the
      // project ID to settle.
      activeCacheKeyRef.current = '';
      setLoading(true);
      setConnection(null);
      setScans([]);
      setError('');
      return undefined;
    }
    let active = true;
    const requestCacheKey = gitHubDomainDataCacheKey(scope, trimmedProject, scanLimit);
    const requestSnapshot = requestCacheKey ? gitHubDomainDataCache.get(requestCacheKey) : undefined;
    const isSameRequestTarget = activeCacheKeyRef.current === requestCacheKey;
    activeCacheKeyRef.current = requestCacheKey;
    const bypassInFlight = reloadToken > 0 && isSameRequestTarget;
    const requestCacheEpoch = bypassInFlight
      ? bumpGitHubDomainDataCacheEpoch(requestCacheKey)
      : gitHubDomainDataCacheEpoch(requestCacheKey);
    setLoading(!requestSnapshot);
    setError('');
    if (!isSameRequestTarget) {
      setConnection(requestSnapshot?.connection ?? null);
      setScans(requestSnapshot?.scans ?? []);
    }
    const auth = buildProductAuthContext(scope);

    fetchGitHubDomainDataSnapshot(scope, trimmedProject, scanLimit, scanPageLimit, maxScanPages, auth, {
      bypassInFlight
    })
      .then((snapshot) => {
        if (!active || !isCurrentProductScopedCacheKey(requestCacheKey)) {
          return;
        }
        if (snapshot.error) {
          const fallbackSnapshot = requestCacheKey ? gitHubDomainDataCache.get(requestCacheKey) : undefined;
          if (fallbackSnapshot) {
            setConnection(snapshot.connection);
            setScans(fallbackSnapshot.scans);
            writeGitHubDomainDataCache(requestCacheKey, { connection: snapshot.connection, scans: fallbackSnapshot.scans }, {
              expectedEpoch: requestCacheEpoch
            });
            setError(snapshot.error);
            return;
          }
        }
        if (!snapshot.error) {
          writeGitHubDomainDataCache(requestCacheKey, { connection: snapshot.connection, scans: snapshot.scans }, {
            expectedEpoch: requestCacheEpoch
          });
        }
        setConnection(snapshot.connection);
        setScans(snapshot.scans);
        setError(snapshot.error);
      })
      .catch((error) => {
        if (!active || !isCurrentProductScopedCacheKey(requestCacheKey)) {
          return;
        }
        const fallbackSnapshot = requestCacheKey ? gitHubDomainDataCache.get(requestCacheKey) : undefined;
        if (fallbackSnapshot) {
          setConnection(fallbackSnapshot.connection);
          setScans(fallbackSnapshot.scans);
          setError(formatAPIError(error, 'Unable to load GitHub connection status.'));
          return;
        }
        setError(formatAPIError(error, 'Unable to load GitHub connection status.'));
      })
      .finally(() => {
        if (active && isCurrentProductScopedCacheKey(requestCacheKey)) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [available, maxScanPages, projectID, reloadToken, scanLimit, scanPageLimit, scope?.tenantID, scope?.workspaceID]);

  return { loading, error, connection, scans, reload };
}

function gitHubScansForSelectedRepositories(scans: RepoScanRecord[], selectedRepositories: string[]): RepoScanRecord[] {
  if (!selectedRepositories.length) {
    return [];
  }
  const allowed = new Set(selectedRepositories.map((repo) => canonicalGitHubRepositoryDisplay(repo).toLowerCase()));
  return scans.filter((scan) => allowed.has(canonicalGitHubRepositoryDisplay(scan.repository).toLowerCase()));
}

function gitHubRecentScans(scans: RepoScanRecord[], selectedRepositories: string[], limit: number): RepoScanRecord[] {
  return gitHubScansForSelectedRepositories(scans, selectedRepositories).slice(0, limit);
}

function gitHubRecentScansTimeline(scans: RepoScanRecord[]): DomainTimelineEntry[] {
  return scans.map((scan) => {
    const repo = canonicalGitHubRepositoryDisplay(scan.repository) || scan.repository;
    const tone = repoScanStatusTone(scan.status);
    const statusLabel = formatTokenLabel(scan.status);
    const detail = isCompletedScanStatus(scan.status)
      ? scan.error_message
        ? summarizeScanFailure(scan)
        : summarizeSuccessfulRepoScan(scan)
      : `${scan.scan_mode ?? 'scan'} queued`;
    return {
      id: scan.id,
      timestamp: formatRelativeTime(scan.finished_at || scan.started_at),
      title: (
        <>
          <strong>{repo}</strong> · {statusLabel}
        </>
      ),
      detail,
      tone: tone === 'warning' ? 'warning' : tone === 'error' ? 'danger' : tone === 'success' ? 'success' : 'neutral'
    };
  });
}

function gitHubConnectionTone(status: GitHubConnectionStatus | null, loading: boolean): 'success' | 'warning' | 'danger' | 'neutral' {
  if (loading) {
    return 'neutral';
  }
  if (!status || !status.connected) {
    return 'neutral';
  }
  const tone = connectionTone(status);
  if (tone === 'error') {
    return 'danger';
  }
  return tone;
}

function gitHubConnectionSummary(status: GitHubConnectionStatus | null): string {
  if (!status || !status.connected) {
    return 'GitHub is not connected for this environment yet.';
  }
  const account = normalizeValue(status.account_login);
  const installation = status.installation_id ? `installation ${status.installation_id}` : '';
  const parts = [account ? `Connected as ${account}` : 'Connected'];
  if (installation) {
    parts.push(installation);
  }
  parts.push(`health ${formatTokenLabel(connectionHealth(status))}`);
  return `${parts.join(' · ')}.`;
}

function gitHubOverviewSubtitle(
  status: GitHubConnectionStatus | null,
  recentScans: RepoScanRecord[]
): ReactNode {
  if (!status || !status.connected) {
    return 'Not connected for this environment.';
  }
  const parts: string[] = [];
  if (status.installation_id) {
    parts.push(`Installation ${status.installation_id}`);
  } else if (status.account_login) {
    parts.push(`@${status.account_login}`);
  }
  parts.push(formatTokenLabel(connectionHealth(status)));
  const lastCompleted = recentScans.find((scan) => isCompletedScanStatus(scan.status));
  if (lastCompleted) {
    parts.push(`Last scan ${formatRelativeTime(lastCompleted.finished_at || lastCompleted.started_at)}`);
  }
  return parts.join(' · ');
}

function gitHubConnectionStatusVariantFor(status: GitHubConnectionStatus | null, loading: boolean) {
  if (loading) {
    return 'coming-soon' as const;
  }
  if (!status || !status.connected) {
    return 'disconnected' as const;
  }
  const tone = connectionTone(status);
  if (tone === 'error') {
    return 'missing-permissions' as const;
  }
  if (tone === 'warning') {
    return 'needs-attention' as const;
  }
  return 'connected' as const;
}

function GitHubSectionLinksGrid({ links }: { links: GitHubSectionLink[] }) {
  return (
    <section className="idt-domain-status-panel idt-github-section-links" aria-label="GitHub sections">
      <header>
        <div>
          <h3>Sections</h3>
        </div>
      </header>
      <div className="idt-domain-readiness-items">
        {links.map((link) => (
          <Link key={link.id} to={link.to} className="idt-github-section-link" aria-label={link.label}>
            <div>
              <strong>{link.label}</strong>
              <p>{link.description}</p>
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}

type GitHubControlCenterBanner = {
  id: string;
  message: ReactNode;
  detail?: string;
  actionLabel: string;
  actionTo: string;
  tone: 'info' | 'warning' | 'danger';
};

function selectGitHubControlCenterBanner({
  connected,
  selectedRepositories,
  recentScans,
  connectPath,
  repositoriesPath,
  findingsPath
}: {
  connected: boolean;
  selectedRepositories: string[];
  recentScans: RepoScanRecord[];
  connectPath: string;
  repositoriesPath: string;
  findingsPath: string;
}): GitHubControlCenterBanner | null {
  if (!connected) {
    return {
      id: 'connect',
      message: 'Install the GitHub App to enable repository scanning.',
      actionLabel: 'Connect GitHub',
      actionTo: connectPath,
      tone: 'info'
    };
  }
  if (selectedRepositories.length === 0) {
    return {
      id: 'select-repositories',
      message: 'Pick repositories for Identrail to watch.',
      actionLabel: 'Select repositories',
      actionTo: connectPath,
      tone: 'info'
    };
  }
  const latestPerRepo = latestCompletedScanPerRepository(recentScans);
  const activeScanRepos = new Set(
    recentScans.filter((scan) => isActiveScanStatus(scan.status)).map((scan) => repoLookupKey(scan.repository))
  );
  const failedLatest = latestPerRepo.find(
    (scan) => !activeScanRepos.has(repoLookupKey(scan.repository)) && isFailedScanStatus(scan.status)
  );
  if (failedLatest) {
    const repo = canonicalGitHubRepositoryDisplay(failedLatest.repository) || failedLatest.repository;
    return {
      id: 'review-failed-scan',
      message: (
        <>
          <strong>{repo}</strong> failed its last scan.
        </>
      ),
      detail: summarizeScanFailure(failedLatest),
      actionLabel: 'Review',
      actionTo: repositoriesPath,
      tone: 'danger'
    };
  }
  // recentScans is capped at GITHUB_CONTROL_CENTER_RECENT_SCANS_LIMIT, so a
  // total summed from it would underreport when more selected repos have
  // open findings than fit in the recent window. The findings page is the
  // source of truth for the precise number — the banner just signals that
  // there is work to do.
  const hasOpenFindings = latestPerRepo.some((scan) => scan.finding_count > 0);
  if (hasOpenFindings) {
    return {
      id: 'triage-findings',
      message: 'Repository findings need triage.',
      actionLabel: 'Review',
      actionTo: findingsPath,
      tone: 'warning'
    };
  }
  const activeScan = recentScans.find((scan) => isActiveScanStatus(scan.status));
  if (activeScan) {
    const repo = canonicalGitHubRepositoryDisplay(activeScan.repository) || activeScan.repository;
    return {
      id: 'scan-in-progress',
      message: (
        <>
          Scan in progress · <strong>{repo}</strong>
        </>
      ),
      actionLabel: 'Repositories',
      actionTo: repositoriesPath,
      tone: 'info'
    };
  }
  if (latestPerRepo.length === 0) {
    return {
      id: 'run-first-scan',
      message: 'Queue the first repository scan.',
      actionLabel: 'Repositories',
      actionTo: repositoriesPath,
      tone: 'info'
    };
  }
  return null;
}

// Build the latest authoritative scan per repository. Canceled scans are
// skipped because cancellation does not refresh the finding count or the
// failure state — letting a canceled scan supersede a prior successful or
// failed scan would hide real triage work or a real failure recommendation.
function latestCompletedScanPerRepository(scans: RepoScanRecord[]): RepoScanRecord[] {
  const byRepo = new Map<string, RepoScanRecord>();
  for (const scan of scans) {
    if (!isCompletedScanStatus(scan.status) || isCanceledScanStatus(scan.status)) {
      continue;
    }
    const repo = repoLookupKey(scan.repository);
    const existing = byRepo.get(repo);
    if (!existing || scanFinishedAt(scan) > scanFinishedAt(existing)) {
      byRepo.set(repo, scan);
    }
  }
  return [...byRepo.values()];
}

// Single source of truth for the repository key used by the GitHub overview
// banner selector. Building the key in two places (e.g. once when seeding a
// Set and again when querying it) is the bug class this helper exists to
// prevent — when canonicalGitHubRepositoryDisplay can't canonicalize a
// value, the bare-string fallback must match on both sides.
function repoLookupKey(repository: string): string {
  return canonicalGitHubRepositoryDisplay(repository).toLowerCase() || repository.toLowerCase();
}

function isCanceledScanStatus(status: string): boolean {
  return normalizeValue(status).toLowerCase() === 'canceled';
}

function scanFinishedAt(scan: RepoScanRecord): number {
  const stamp = scan.finished_at || scan.started_at;
  if (!stamp) {
    return 0;
  }
  const ms = Date.parse(stamp);
  return Number.isNaN(ms) ? 0 : ms;
}

function GitHubControlCenterBannerView({ banner }: { banner: GitHubControlCenterBanner }) {
  return (
    <section
      className={`idt-overview-banner is-${banner.tone}`}
      aria-label="GitHub action recommendation"
      data-banner-id={banner.id}
    >
      <div>
        <p>{banner.message}</p>
        {banner.detail ? <small>{banner.detail}</small> : null}
      </div>
      <Link to={banner.actionTo} className="idt-btn idt-btn-primary idt-domain-action">
        <span>{banner.actionLabel}</span>
      </Link>
    </section>
  );
}

function legacyProjectSetupPath(scope: ProductSession, projectID: string | undefined): string {
  const trimmed = normalizeValue(projectID);
  if (!trimmed) {
    return appendSourceQuery(buildProjectsPath(scope), 'github');
  }
  return appendSourceQuery(buildProjectPath(scope, trimmed), 'github');
}

function GitHubUnavailableShell({
  title,
  scope,
  environmentScope,
  selectedEnvironmentID,
  onEnvironmentChange,
  unavailableMessage
}: {
  title: string;
  scope: ProductSession;
  environmentScope: EnvironmentScopeState;
  selectedEnvironmentID: string;
  onEnvironmentChange: (id: string) => void;
  unavailableMessage?: string;
}) {
  const basePath = appendEnvironmentQuery(buildScopedPath(scope, 'github'), selectedEnvironmentID);
  return (
    <DomainPageShell
      domain="github"
      eyebrow="GitHub"
      title={title}
      description="The GitHub connector is not enabled on this Identrail build."
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={onEnvironmentChange} />}
      status={<DomainStatusBadge variant="coming-soon" label="Unavailable" />}
      statusTone="neutral"
      primaryAction={{ label: 'GitHub home', to: basePath, variant: 'secondary' }}
    >
      <DomainErrorState
        title="GitHub is not available on this API"
        body={unavailableMessage ?? 'Ask your operator to enable the GitHub connector to unlock this page.'}
      />
      <OnboardingUnavailableNotice />
    </DomainPageShell>
  );
}

function GitHubMissingEnvironmentShell({
  title,
  scope,
  environmentScope,
  selectedEnvironmentID,
  onEnvironmentChange
}: {
  title: string;
  scope: ProductSession;
  environmentScope: EnvironmentScopeState;
  selectedEnvironmentID: string;
  onEnvironmentChange: (id: string) => void;
}) {
  const projectsPath = appendSourceQuery(buildProjectsPath(scope), 'github');
  const basePath = appendEnvironmentQuery(buildScopedPath(scope, 'github'), selectedEnvironmentID);
  return (
    <DomainPageShell
      domain="github"
      eyebrow="GitHub"
      title={title}
      description="Pick an environment to scope GitHub to a project boundary."
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={onEnvironmentChange} />}
      status={<DomainStatusBadge variant="coming-soon" label="Pick environment" />}
      statusTone="neutral"
      primaryAction={{ label: 'Create environment', to: projectsPath, variant: 'primary' }}
      secondaryActions={[{ label: 'GitHub home', to: basePath }]}
    >
      <DomainEmptyState
        eyebrow="Environment required"
        title="Choose an environment for GitHub"
        body="GitHub installations are scoped per project. Create or pick an environment to load connection status, repository coverage, and scan activity."
      />
    </DomainPageShell>
  );
}

export function ProductGitHubControlCenterPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useGitHubDomainScope();
  const availability = useGitHubAvailability();
  const data = useGitHubDomainData(
    scope,
    selectedEnvironmentID,
    availability.available,
    GITHUB_CONTROL_CENTER_RECENT_SCANS_LIMIT,
    GITHUB_CONTROL_CENTER_SCAN_FETCH_LIMIT
  );

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">GitHub</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading the GitHub control center.</p>
      </section>
    );
  }

  if (availability.loading) {
    return (
      <DomainPageShell
        domain="github"
        eyebrow="GitHub"
        title="GitHub Control Center"
        description="Loading GitHub availability for this build."
        scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      >
        <DomainLoadingState label="Loading GitHub availability" />
      </DomainPageShell>
    );
  }

  if (!availability.available) {
    return (
      <GitHubUnavailableShell
        title="GitHub Control Center"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
        unavailableMessage={availability.unavailableMessage}
      />
    );
  }

  if (!selectedEnvironmentID) {
    return (
      <GitHubMissingEnvironmentShell
        title="GitHub Control Center"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
      />
    );
  }

  const links = buildGitHubSectionLinks(scope, selectedEnvironmentID);
  const connectPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/connect'), selectedEnvironmentID);
  const repositoriesPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/repositories'), selectedEnvironmentID);
  const findingsPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/findings'), selectedEnvironmentID);
  const selectedRepositories = uniqueGitHubRepositories(data.connection?.selected_repositories ?? []);
  const recentScans = gitHubRecentScans(data.scans, selectedRepositories, GITHUB_CONTROL_CENTER_RECENT_SCANS_LIMIT);
  const connected = Boolean(data.connection?.connected);
  // Suppress every connection-dependent surface (subtitle copy, banner,
  // primary CTA, empty state) while the very first connection fetch is
  // still in flight. Without this guard the page renders "Not connected"
  // + "Install the GitHub App" + a Connect CTA during the API round-trip,
  // then flips to the connected state once the response lands — a
  // misleading flash that, on slower networks, can last several seconds.
  const awaitingFirstLoad = data.loading && data.connection === null && !data.error;
  const hasError = Boolean(data.error);
  // When the scan list errors out, we cannot truthfully recommend a next
  // action or claim "no repository scans yet" — the fetch failed, the
  // page does not know whether scans exist. The error panel becomes the
  // single source of truth and the speculative banner / empty state are
  // suppressed. The header subtitle and primary CTA can still reflect
  // the connection result because that fetch did succeed.
  const suppressDerivedSurfaces = awaitingFirstLoad || hasError;
  const banner = suppressDerivedSurfaces
    ? null
    : selectGitHubControlCenterBanner({
        connected,
        selectedRepositories,
        recentScans,
        connectPath,
        repositoriesPath,
        findingsPath
      });
  const primaryAction = awaitingFirstLoad
    ? undefined
    : connected
      ? { label: 'Repositories', to: repositoriesPath, variant: 'primary' as const }
      : { label: 'Connect GitHub', to: connectPath, variant: 'primary' as const };
  const subtitle = awaitingFirstLoad
    ? undefined
    : gitHubOverviewSubtitle(data.connection, recentScans);

  return (
    <DomainPageShell
      domain="github"
      eyebrow={null}
      hideLogo
      title="GitHub"
      description={subtitle}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      statusTone={gitHubConnectionTone(data.connection, data.loading)}
      primaryAction={primaryAction}
    >
      {data.error ? <DomainErrorState title="Unable to load GitHub status" body={data.error} retryAction={{ label: 'Retry', onClick: data.reload }} /> : null}
      {banner ? <GitHubControlCenterBannerView banner={banner} /> : null}
      {recentScans.length > 0 ? (
        <section className="idt-domain-status-panel" aria-label="Recent repository scans">
          <header>
            <div>
              <h3>Recent scans</h3>
            </div>
            <Link to={repositoriesPath}>Manage scans</Link>
          </header>
          <DomainTimeline label="Recent repository scans" entries={gitHubRecentScansTimeline(recentScans)} />
        </section>
      ) : !suppressDerivedSurfaces && connected ? (
        <DomainEmptyState
          title="No repository scans yet"
          body="Queue a scan to populate the activity timeline."
          nextAction={{ label: 'Repositories', to: repositoriesPath }}
        />
      ) : null}
      <GitHubSectionLinksGrid links={links} />
    </DomainPageShell>
  );
}

export function ProductGitHubConnectPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useGitHubDomainScope();
  const availability = useGitHubAvailability();
  const data = useGitHubDomainData(scope, selectedEnvironmentID, availability.available, 0);
  const [installError, setInstallError] = useState('');
  const [installing, setInstalling] = useState(false);
  const [pendingInstallURL, setPendingInstallURL] = useState('');

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">Connect GitHub</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading the GitHub connector setup.</p>
      </section>
    );
  }

  if (availability.loading) {
    return (
      <DomainPageShell
        domain="github"
        eyebrow="GitHub"
        title="Connect GitHub"
        description="Loading GitHub availability for this build."
        scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      >
        <DomainLoadingState label="Loading GitHub availability" />
      </DomainPageShell>
    );
  }

  if (!availability.available) {
    return (
      <GitHubUnavailableShell
        title="Connect GitHub"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
        unavailableMessage={availability.unavailableMessage}
      />
    );
  }

  if (!selectedEnvironmentID) {
    return (
      <GitHubMissingEnvironmentShell
        title="Connect GitHub"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
      />
    );
  }

  const basePath = appendEnvironmentQuery(buildScopedPath(scope, 'github'), selectedEnvironmentID);
  const legacyPath = legacyProjectSetupPath(scope, selectedEnvironmentID);
  const repositoriesPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/repositories'), selectedEnvironmentID);

  const handleInstall = async () => {
    setInstallError('');
    setPendingInstallURL('');
    setInstalling(true);
    try {
      const redirectURI =
        typeof window !== 'undefined' ? `${window.location.origin}/app/github/callback` : undefined;
      const response = await apiClient.startGitHubConnector(
        {
          project_id: selectedEnvironmentID,
          install_account_type: 'any',
          redirect_uri: redirectURI
        },
        buildProductAuthContext(scope)
      );
      const installURL = response.install_url ?? '';
      if (installURL) {
        let opened: Window | null = null;
        if (typeof window !== 'undefined') {
          opened = window.open(installURL, '_blank', 'noopener,noreferrer');
        }
        if (!opened) {
          setPendingInstallURL(installURL);
        }
      }
      data.reload();
    } catch (error) {
      setInstallError(formatAPIError(error, 'Unable to start GitHub App installation.'));
    } finally {
      setInstalling(false);
    }
  };

  const connected = Boolean(data.connection?.connected);
  const selectedRepositoryCount = uniqueGitHubRepositories(data.connection?.selected_repositories ?? []).length;
  // Suppress the install/manage body during the first connection fetch and
  // during a load failure. The page header still shows the loading subtitle
  // or the error panel respectively, so the body would only add a
  // speculative state surface (e.g. an Install button while we already have
  // a real installation, or a Manage card built from stale data).
  const awaitingFirstLoad = data.loading && data.connection === null && !data.error;
  const hasError = Boolean(data.error);
  const showBody = !awaitingFirstLoad && !hasError;
  const subtitle = (() => {
    if (awaitingFirstLoad) {
      return 'Loading GitHub status…';
    }
    // When the connection-status request fails we do not actually know
    // whether the user is connected, so the subtitle must not assert
    // "Not connected" — that would contradict the error panel below and
    // tempt a user into a redundant reinstall flow when the real state
    // is "unknown".
    if (hasError) {
      return 'Unable to load GitHub status.';
    }
    if (!connected) {
      return 'Not connected for this environment.';
    }
    const parts: string[] = [];
    if (data.connection?.installation_id) {
      parts.push(`Installation ${data.connection.installation_id}`);
    } else if (data.connection?.account_login) {
      parts.push(`@${data.connection.account_login}`);
    }
    if (data.connection) {
      parts.push(formatTokenLabel(connectionHealth(data.connection)));
    }
    parts.push(
      `${selectedRepositoryCount} ${selectedRepositoryCount === 1 ? 'repository' : 'repositories'}`
    );
    return parts.join(' · ');
  })();
  // The primary CTA is omitted both during the initial load and during a
  // load failure: in the error case the connection state is unknown, so
  // any "Install" / "Open Repositories" call-to-action is speculative —
  // the user should retry via the error panel rather than start a flow
  // that might collide with a real existing installation.
  const primaryAction = awaitingFirstLoad || hasError
    ? undefined
    : connected
      ? { label: 'Open Repositories', to: repositoriesPath, variant: 'primary' as const }
      : {
          label: installing ? 'Opening install...' : 'Install GitHub App',
          onClick: handleInstall,
          disabled: installing,
          variant: 'primary' as const
        };

  return (
    <DomainPageShell
      domain="github"
      eyebrow={null}
      hideLogo
      title="Connect GitHub"
      description={subtitle}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      statusTone={gitHubConnectionTone(data.connection, data.loading)}
      primaryAction={primaryAction}
    >
      {installError ? <DomainErrorState title="Unable to start install" body={installError} retryAction={{ label: 'Try again', onClick: handleInstall }} /> : null}
      {pendingInstallURL ? (
        <DomainStatusPanel
          eyebrow="Install GitHub App"
          title="Browser blocked the install popup"
          tone="warning"
        >
          <p>Open the GitHub App install page directly to finish connecting Identrail.</p>
          <a
            className="idt-btn idt-btn-primary"
            href={pendingInstallURL}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Open GitHub"
          >
            Open GitHub
          </a>
        </DomainStatusPanel>
      ) : null}
      {data.error ? <DomainErrorState title="Unable to load connection status" body={data.error} retryAction={{ label: 'Retry', onClick: data.reload }} /> : null}
      {showBody && connected ? (
        <section className="idt-domain-status-panel idt-github-connect-installation" aria-label="GitHub installation">
          <header>
            <div>
              <h3>Installation</h3>
            </div>
          </header>
          <dl className="idt-domain-route-facts">
            {data.connection?.account_login ? (
              <div>
                <dt>Account</dt>
                <dd>{data.connection.account_login}</dd>
              </div>
            ) : null}
            <div>
              <dt>Installation</dt>
              <dd>{data.connection?.installation_id ?? '—'}</dd>
            </div>
            <div>
              <dt>Selected repositories</dt>
              <dd>{selectedRepositoryCount}</dd>
            </div>
          </dl>
          <footer className="idt-github-connect-actions">
            <button
              type="button"
              className="idt-btn idt-btn-dark"
              onClick={handleInstall}
              disabled={installing}
              aria-label="Install GitHub App"
            >
              {installing ? 'Opening install...' : 'Reinstall on GitHub'}
            </button>
            <Link to={legacyPath} className="idt-btn idt-btn-ghost">
              Manage Enterprise / PAT
            </Link>
            <Link to={basePath} className="idt-btn idt-btn-ghost">
              GitHub home
            </Link>
          </footer>
        </section>
      ) : null}
      {showBody && !connected ? (
        <section className="idt-domain-status-panel idt-github-connect-install" aria-label="Install GitHub App">
          <header>
            <div>
              <h3>Install the Identrail GitHub App</h3>
            </div>
          </header>
          <p>Grants scoped repository and Actions access for the selected environment.</p>
          <footer className="idt-github-connect-actions">
            <button
              type="button"
              className="idt-btn idt-btn-primary"
              onClick={handleInstall}
              disabled={installing}
              aria-label="Install GitHub App"
            >
              {installing ? 'Opening install...' : 'Install GitHub App'}
            </button>
            <Link to={legacyPath} className="idt-btn idt-btn-dark">
              Manage Enterprise / PAT
            </Link>
          </footer>
        </section>
      ) : null}
    </DomainPageShell>
  );
}

type GitHubRepositoryRow = {
  repository: string;
  scans: RepoScanRecord[];
  latest?: RepoScanRecord;
  activeScan?: RepoScanRecord;
};

function buildGitHubRepositoryRows(selectedRepositories: string[], scans: RepoScanRecord[]): GitHubRepositoryRow[] {
  return selectedRepositories.map((repository) => {
    const lower = repository.toLowerCase();
    const matching = scans.filter((scan) => canonicalGitHubRepositoryDisplay(scan.repository).toLowerCase() === lower);
    const latest = [...matching].sort((left, right) => scanCompletionSortValue(right) - scanCompletionSortValue(left))[0];
    const activeScan = matching.find((scan) => isActiveScanStatus(scan.status));
    return { repository, scans: matching, latest, activeScan };
  });
}

export function ProductGitHubRepositoriesPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useGitHubDomainScope();
  const availability = useGitHubAvailability();
  const data = useGitHubDomainData(scope, selectedEnvironmentID, availability.available, GITHUB_REPOSITORIES_SCANS_LIMIT);
  const [scanError, setScanError] = useState('');
  const [scanInfo, setScanInfo] = useState('');
  const [submittingRepository, setSubmittingRepository] = useState('');
  const [cancelingScanID, setCancelingScanID] = useState('');

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">GitHub repositories</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading the GitHub repositories page.</p>
      </section>
    );
  }

  if (availability.loading) {
    return (
      <DomainPageShell
        domain="github"
        eyebrow="GitHub"
        title="GitHub repositories"
        description="Loading GitHub availability for this build."
        scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      >
        <DomainLoadingState label="Loading GitHub availability" />
      </DomainPageShell>
    );
  }

  if (!availability.available) {
    return (
      <GitHubUnavailableShell
        title="GitHub repositories"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
        unavailableMessage={availability.unavailableMessage}
      />
    );
  }

  if (!selectedEnvironmentID) {
    return (
      <GitHubMissingEnvironmentShell
        title="GitHub repositories"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
      />
    );
  }

  const connectPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/connect'), selectedEnvironmentID);
  const findingsPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/findings'), selectedEnvironmentID);
  const selectedRepositories = uniqueGitHubRepositories(data.connection?.selected_repositories ?? []);
  const rows = buildGitHubRepositoryRows(selectedRepositories, data.scans);
  const selectedRepositoryScans = gitHubScansForSelectedRepositories(data.scans, selectedRepositories);

  const connected = Boolean(data.connection?.connected);
  const statusVariant = gitHubConnectionStatusVariantFor(data.connection, data.loading);
  const hasRepositories = selectedRepositories.length > 0;

  const launchScan = async (repository: string) => {
    if (!data.connection?.connected) {
      setScanError('Connect GitHub before queueing a repository scan.');
      return;
    }
    setScanError('');
    setScanInfo('');
    setSubmittingRepository(repository);
    try {
      const request: RepoScanRequest = { repository };
      if (data.connection.provider === 'github_app') {
        request.project_id = selectedEnvironmentID;
        if (data.connection.connector_id) {
          request.connector_id = data.connection.connector_id;
        }
      }
      await apiClient.runRepoScan(request, buildProductAuthContext(scope));
      setScanInfo(`Repository scan queued for ${repository}.`);
      data.reload();
    } catch (error) {
      setScanError(formatRepoScanSubmitError(error));
    } finally {
      setSubmittingRepository((current) => (current === repository ? '' : current));
    }
  };

  const cancelScan = async (scan: RepoScanRecord) => {
    if (!isActiveScanStatus(scan.status)) {
      setScanError('Only queued or running repository scans can be canceled.');
      return;
    }
    setScanError('');
    setScanInfo('');
    setCancelingScanID(scan.id);
    try {
      await apiClient.cancelRepoScan(scan.id, buildProductAuthContext(scope));
      setScanInfo(`Repository scan canceled for ${canonicalGitHubRepositoryDisplay(scan.repository) || scan.repository}.`);
      data.reload();
    } catch (error) {
      setScanError(formatRepoScanCancelError(error));
    } finally {
      setCancelingScanID((current) => (current === scan.id ? '' : current));
    }
  };

  // Suppress every connection-dependent surface (subtitle, repo list,
  // recent activity) while the first connection fetch is in flight or
  // has failed. The header subtitle and any error panel below speak for
  // the page in those states — the body is silenced so we do not
  // contradict the error panel by, e.g., rendering "Connect GitHub to
  // manage repositories" when the connection request itself failed.
  const awaitingFirstLoad = data.loading && data.connection === null && !data.error;
  const hasError = Boolean(data.error);
  const showBody = !awaitingFirstLoad && !hasError;
  const recentScanCount = selectedRepositoryScans.length;
  const failedRecentScanCount = selectedRepositoryScans.filter((scan) => isFailedScanStatus(scan.status)).length;
  const subtitle = (() => {
    if (awaitingFirstLoad) {
      return 'Loading repositories…';
    }
    if (hasError) {
      return 'Unable to load repositories.';
    }
    if (!connected) {
      return 'Not connected for this environment.';
    }
    const parts: string[] = [];
    parts.push(
      `${selectedRepositories.length} ${selectedRepositories.length === 1 ? 'repository' : 'repositories'}`
    );
    if (recentScanCount > 0) {
      parts.push(`${recentScanCount} recent ${recentScanCount === 1 ? 'scan' : 'scans'}`);
    }
    if (failedRecentScanCount > 0) {
      parts.push(`${failedRecentScanCount} failed`);
    }
    return parts.join(' · ');
  })();
  const primaryAction = awaitingFirstLoad || hasError
    ? undefined
    : connected
      ? { label: 'GitHub findings', to: findingsPath, variant: 'primary' as const }
      : { label: 'Connect GitHub', to: connectPath, variant: 'primary' as const };

  return (
    <DomainPageShell
      domain="github"
      eyebrow={null}
      hideLogo
      title="Repositories"
      description={subtitle}
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      statusTone={gitHubConnectionTone(data.connection, data.loading)}
      primaryAction={primaryAction}
    >
      {data.error ? <DomainErrorState title="Unable to load repository status" body={data.error} retryAction={{ label: 'Retry', onClick: data.reload }} /> : null}
      {scanError ? <DomainErrorState title="Repository scan error" body={scanError} /> : null}
      {scanInfo ? (
        <DomainStatusPanel eyebrow="Scan activity" title="Update" tone="info">
          <p>{scanInfo}</p>
        </DomainStatusPanel>
      ) : null}
      {showBody && !connected ? (
        <DomainEmptyState
          title="Connect GitHub to manage repositories"
          body="Install the GitHub App or paste an Enterprise PAT to populate the repository inventory."
          nextAction={{ label: 'Connect GitHub', to: connectPath }}
        />
      ) : null}
      {showBody && connected && !hasRepositories ? (
        <DomainEmptyState
          title="Select repositories for Identrail to watch"
          body="Pick repositories on the connection page so Identrail can queue scans and detect risk."
          nextAction={{ label: 'Select repositories', to: connectPath }}
        />
      ) : null}
      {showBody && connected && hasRepositories ? (
        <section className="idt-domain-status-panel idt-github-repository-panel" aria-label="Selected repositories">
          <header>
            <div>
              <h3>Repositories</h3>
            </div>
          </header>
          <div className="idt-github-repository-table" role="list" aria-label="Repository scan controls">
            {rows.map((row) => {
              const submitting = submittingRepository === row.repository;
              const canCancel = Boolean(row.activeScan);
              const cancelingThis = canCancel && cancelingScanID === row.activeScan?.id;
              const statusText = row.latest
                ? isFailedScanStatus(row.latest.status)
                  ? `${formatRelativeTime(row.latest.finished_at || row.latest.started_at)} · failed · ${summarizeScanFailure(row.latest)}`
                  : isCompletedScanStatus(row.latest.status)
                    ? `${formatRelativeTime(row.latest.finished_at || row.latest.started_at)} · ${row.latest.finding_count} ${row.latest.finding_count === 1 ? 'finding' : 'findings'}`
                    : `${row.latest.scan_mode ?? 'scan'} in flight`
                : 'Not scanned';
              return (
                <article key={row.repository} role="listitem" className="idt-github-repository-row">
                  <div className="idt-github-repository-row-main">
                    <strong>{row.repository}</strong>
                    <span className="idt-github-repository-row-status">{statusText}</span>
                  </div>
                  <div className="idt-github-repository-row-actions">
                    {canCancel && row.activeScan ? (
                      <button
                        type="button"
                        className="idt-btn idt-btn-ghost"
                        onClick={() => cancelScan(row.activeScan as RepoScanRecord)}
                        disabled={cancelingThis || data.loading}
                        aria-label={`Cancel scan for ${row.repository}`}
                      >
                        {cancelingThis ? 'Canceling...' : 'Cancel scan'}
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="idt-btn idt-btn-primary"
                      onClick={() => launchScan(row.repository)}
                      disabled={submitting || Boolean(row.activeScan) || data.loading}
                      aria-label={`Queue scan for ${row.repository}`}
                    >
                      {data.loading && !submitting
                        ? 'Refreshing...'
                        : submitting
                          ? 'Queuing...'
                          : row.activeScan
                            ? 'Scan in progress'
                            : 'Queue scan'}
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      ) : null}
      {showBody && connected && hasRepositories ? (
        <section className="idt-domain-status-panel" aria-label="Recent repository scan activity">
          <header>
            <div>
              <h3>Recent activity</h3>
            </div>
          </header>
          {selectedRepositoryScans.length === 0 ? (
            <DomainEmptyState
              title="No repository scans recorded yet"
              body="Queue a scan for a selected repository to seed activity here."
            />
          ) : (
            <DomainTimeline label="Recent repository scan activity" entries={gitHubRecentScansTimeline(selectedRepositoryScans.slice(0, GITHUB_CONTROL_CENTER_RECENT_SCANS_LIMIT * 2))} />
          )}
        </section>
      ) : null}
    </DomainPageShell>
  );
}

export function ProductGitHubActionsPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useGitHubDomainScope();
  const availability = useGitHubAvailability();

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">GitHub Actions / OIDC</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading GitHub Actions / OIDC.</p>
      </section>
    );
  }

  if (availability.loading) {
    return (
      <DomainPageShell
        domain="github"
        eyebrow="Workflow trust"
        title="GitHub Actions / OIDC"
        description="Loading GitHub availability for this build."
        scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      >
        <DomainLoadingState label="Loading GitHub availability" />
      </DomainPageShell>
    );
  }

  if (!availability.available) {
    return (
      <GitHubUnavailableShell
        title="GitHub Actions / OIDC"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
        unavailableMessage={availability.unavailableMessage}
      />
    );
  }

  const basePath = appendEnvironmentQuery(buildScopedPath(scope, 'github'), selectedEnvironmentID);
  const connectPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/connect'), selectedEnvironmentID);
  const repositoriesPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/repositories'), selectedEnvironmentID);
  const findingsPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/findings'), selectedEnvironmentID);

  const surfaces = [
    {
      id: 'workflows',
      title: 'Workflow inventory',
      body: 'Track which repositories run GitHub Actions, what triggers them, and which workflows ship secrets to runners.'
    },
    {
      id: 'permissions',
      title: 'Actions permissions',
      body: 'Surface repositories that allow write workflow tokens, broad GITHUB_TOKEN scopes, or unrestricted action sources.'
    },
    {
      id: 'oidc',
      title: 'OIDC trust paths',
      body: 'Map AWS, GCP, and Azure roles that trust GitHub Actions OIDC claims, including branch and environment scoping.'
    },
    {
      id: 'runners',
      title: 'Runner posture',
      body: 'Inventory self-hosted runners, label scoping, and ephemerality posture so risky reuse is easy to spot.'
    }
  ];

  return (
    <DomainPageShell
      domain="github"
      eyebrow="Workflow trust"
      title="GitHub Actions / OIDC"
      description="Workflow permissions, OIDC trust paths, Actions runners, and automation identity posture for GitHub."
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      status={<DomainStatusBadge variant="coming-soon" label="Coverage incoming" />}
      statusTone="neutral"
      primaryAction={{ label: 'Connect GitHub', to: connectPath, variant: 'primary' }}
      secondaryActions={[
        { label: 'Open Repositories', to: repositoriesPath },
        { label: 'GitHub findings', to: findingsPath },
        { label: 'GitHub home', to: basePath }
      ]}
      aside={
        <DomainDetailPanel title="Why this page exists" eyebrow="Domain charter">
          <p>
            GitHub Actions own the most powerful CI identities in many environments. Identrail will track workflow tokens,
            OIDC trust, and runner posture here so security teams can reason about them as first-class machine identities.
          </p>
        </DomainDetailPanel>
      }
    >
      <DomainStatusPanel
        eyebrow="Coverage status"
        title="Workflow and OIDC posture is rolling out"
        status={<DomainStatusBadge variant="coming-soon" label="Premium preview" />}
        tone="info"
      >
        <p>
          The Identrail GitHub collector already ingests workflow and OIDC signal. The triage UI surfaces — workflow
          inventory, permission posture, OIDC trust analysis, and runner inventory — land here as they ship so this page
          stays the single home for Actions and automation identity in GitHub.
        </p>
      </DomainStatusPanel>
      <section className="idt-domain-status-panel" aria-label="Surfaces planned here">
        <header>
          <div>
            <p className="idt-app-kicker">Surfaces in this page</p>
            <h3>What lands on Actions / OIDC</h3>
          </div>
          <span>4 surfaces</span>
        </header>
        <div className="idt-domain-readiness-items">
          {surfaces.map((surface) => (
            <article key={surface.id}>
              <div>
                <strong>{surface.title}</strong>
                <p>{surface.body}</p>
              </div>
              <span>Planned</span>
            </article>
          ))}
        </div>
      </section>
    </DomainPageShell>
  );
}

function isGitHubRemediationCandidate(finding: ApiFinding): boolean {
  const lifecycle = normalizeRepoFindingLifecycleStatus(finding.lifecycle_status);
  return lifecycle === 'open' || lifecycle === 'reopened';
}

function gitHubRemediationReadiness(
  finding: ApiFinding,
  preview: RepoFindingRemediationPreview | null
): { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' } {
  if (preview) {
    if (preview.remediation.publishable) {
      return { label: 'Publish-ready', tone: 'success' };
    }
    return { label: 'Manual remediation', tone: 'warning' };
  }

  const lifecycle = normalizeRepoFindingLifecycleStatus(finding.lifecycle_status);
  if (lifecycle === 'fixed') {
    return { label: 'Fixed', tone: 'success' };
  }
  if (lifecycle === 'suppressed' || lifecycle === 'risk_accepted' || lifecycle === 'false_positive') {
    return { label: 'Triage-held', tone: 'neutral' };
  }
  if (!normalizeValue(finding.source_url ?? '')) {
    return { label: 'Needs GitHub link', tone: 'warning' };
  }
  if (!normalizeValue(finding.file_path ?? '') && !normalizeValue(finding.evidence?.file_path ?? '')) {
    return { label: 'Needs file evidence', tone: 'warning' };
  }
  return { label: 'Preview ready', tone: 'neutral' };
}

function sortGitHubRemediationQueue(findings: ApiFinding[]): ApiFinding[] {
  return [...findings].sort((left, right) => {
    const leftCandidate = isGitHubRemediationCandidate(left) ? 1 : 0;
    const rightCandidate = isGitHubRemediationCandidate(right) ? 1 : 0;
    if (rightCandidate !== leftCandidate) {
      return rightCandidate - leftCandidate;
    }
    const severityDelta = severityRank(right.severity) - severityRank(left.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return new Date(right.created_at).getTime() - new Date(left.created_at).getTime();
  });
}

export function ProductGitHubRemediationPage() {
  const { scope, environmentScope, selectedEnvironmentID, onChangeEnvironment } = useGitHubDomainScope();
  const availability = useGitHubAvailability();
  const data = useGitHubDomainData(
    scope,
    selectedEnvironmentID,
    availability.available,
    0
  );
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [repoScans, setRepoScans] = useState<RepoScanRecord[]>([]);
  const [repoFindings, setRepoFindings] = useState<ApiFinding[]>([]);
  const [repoFindingSummary, setRepoFindingSummary] = useState<RepoFindingsSummary | null>(null);
  const [selectedFindingKey, setSelectedFindingKey] = useState('');
  const [remediationPreview, setRemediationPreview] = useState<RepoFindingRemediationPreview | null>(null);
  const [remediationPreviewFindingKey, setRemediationPreviewFindingKey] = useState('');
  const [remediationPreviewLoading, setRemediationPreviewLoading] = useState(false);
  const [remediationPreviewError, setRemediationPreviewError] = useState('');
  const [remediationPublishSourceContent, setRemediationPublishSourceContent] = useState('');
  const [remediationPublishBaseBranch, setRemediationPublishBaseBranch] = useState('main');
  const [remediationPublishToken, setRemediationPublishToken] = useState('');
  const [remediationPublishApproved, setRemediationPublishApproved] = useState(false);
  const [remediationPublishWritePermsConfirmed, setRemediationPublishWritePermsConfirmed] = useState(false);
  const [remediationPublishLoading, setRemediationPublishLoading] = useState(false);
  const [remediationPublishError, setRemediationPublishError] = useState('');
  const [remediationPublishResult, setRemediationPublishResult] =
    useState<RepoFindingRemediationPublishResponse | null>(null);

  const requestRef = useRef(0);
  const remediationPreviewRequestRef = useRef(0);
  const remediationPublishRequestRef = useRef(0);

  const repoScansByID = useMemo(
    () =>
      repoScans.reduce<Record<string, RepoScanRecord>>((acc, scan) => {
        acc[scan.id] = scan;
        return acc;
      }, {}),
    [repoScans]
  );

  const remediationQueue = useMemo(() => sortGitHubRemediationQueue(repoFindings), [repoFindings]);
  const actionableFindings = useMemo(
    () => remediationQueue.filter((finding) => isGitHubRemediationCandidate(finding)),
    [remediationQueue]
  );
  const selectedFinding = useMemo(
    () => findRepoFindingBySelectionKey(remediationQueue, selectedFindingKey),
    [remediationQueue, selectedFindingKey]
  );
  const selectedFindingPreviewKey = selectedFinding ? buildRepoFindingSelectionKey(selectedFinding) : '';
  const activeRemediationPreview =
    remediationPreview && remediationPreviewFindingKey === selectedFindingPreviewKey ? remediationPreview : null;
  const repositoryCount = useMemo(() => {
    const repositories = repoFindings
      .map((finding) => canonicalGitHubRepositoryDisplay(repoFindingRepositoryValue(finding, repoScansByID)))
      .filter(Boolean);
    return uniqueGitHubRepositories(repositories).length;
  }, [repoFindings, repoScansByID]);
  const highPriorityCount = actionableFindings.filter((finding) => {
    const severity = normalizeValue(finding.severity).toLowerCase();
    return severity === 'critical' || severity === 'high';
  }).length;
  const publishablePreviewCount = activeRemediationPreview?.remediation.publishable ? 1 : 0;
  const queueSelectionKeys = remediationQueue.map((finding) => buildRepoFindingSelectionKey(finding)).join('|');

  const resetRemediationPublishState = () => {
    setRemediationPublishSourceContent('');
    setRemediationPublishBaseBranch('main');
    setRemediationPublishToken('');
    setRemediationPublishApproved(false);
    setRemediationPublishWritePermsConfirmed(false);
    setRemediationPublishLoading(false);
    setRemediationPublishError('');
    setRemediationPublishResult(null);
  };

  const selectRemediationFinding = (finding: ApiFinding | null) => {
    remediationPreviewRequestRef.current += 1;
    remediationPublishRequestRef.current += 1;
    setSelectedFindingKey(finding ? buildRepoFindingSelectionKey(finding) : '');
  };

  const loadRemediationData = async (targetScope: ProductSession, mode: 'initial' | 'refresh') => {
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
            limit: GITHUB_REMEDIATION_FINDINGS_LIMIT,
            sort_by: 'severity',
            sort_order: 'desc'
          },
          auth
        )
      ]);
      if (requestID !== requestRef.current) {
        return;
      }
      setRepoScans(repoScanResponse.items);
      setRepoFindings(repoFindingResponse.items);
      setRepoFindingSummary(repoFindingResponse.summary ?? null);
    } catch (requestError) {
      if (requestID !== requestRef.current) {
        return;
      }
      setError(formatAPIError(requestError, 'Failed to load GitHub remediation queue.'));
      setRepoScans([]);
      setRepoFindings([]);
      setRepoFindingSummary(null);
    } finally {
      if (requestID === requestRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  };

  const handleRefresh = () => {
    if (!scope) {
      return;
    }
    data.reload();
    void loadRemediationData(scope, 'refresh');
  };

  const handleLoadRemediationPreview = async () => {
    if (!scope || !selectedFinding || remediationPreviewLoading) {
      return;
    }

    const selectionKey = buildRepoFindingSelectionKey(selectedFinding);
    const requestID = ++remediationPreviewRequestRef.current;
    setRemediationPreviewLoading(true);
    setRemediationPreviewError('');
    setRemediationPreview(null);
    setRemediationPreviewFindingKey(selectionKey);
    setRemediationPublishResult(null);
    setRemediationPublishError('');
    try {
      const sourceContent = remediationPublishSourceContent.trim();
      const previewRequest = {
        repo_scan_id: selectedFinding.scan_id,
        finding_url: selectedFinding.source_url || undefined,
        ...(sourceContent
          ? {
              source_content: sourceContent,
              require_fix_plan: true
            }
          : {})
      };
      const preview = await apiClient.previewRepoFindingRemediation(
        selectedFinding.id,
        previewRequest,
        buildProductAuthContext(scope)
      );
      if (requestID !== remediationPreviewRequestRef.current) {
        return;
      }
      setRemediationPreview(preview);
      setRemediationPreviewFindingKey(selectionKey);
      setRemediationPublishBaseBranch(preview.fix_pr_plan?.base_branch || 'main');
    } catch (requestError) {
      if (requestID !== remediationPreviewRequestRef.current) {
        return;
      }
      setRemediationPreview(null);
      setRemediationPreviewError(
        requestError instanceof Error ? requestError.message : 'Failed to load remediation preview.'
      );
    } finally {
      if (requestID === remediationPreviewRequestRef.current) {
        setRemediationPreviewLoading(false);
      }
    }
  };

  const handlePublishRemediation = async () => {
    if (!scope || !selectedFinding || !activeRemediationPreview || remediationPublishLoading) {
      return;
    }

    const sourceContent = remediationPublishSourceContent;
    const token = remediationPublishToken.trim();
    if (!sourceContent.trim()) {
      setRemediationPublishError('Current source content is required.');
      return;
    }
    if (!remediationPublishApproved) {
      setRemediationPublishError('Operator approval is required.');
      return;
    }
    if (!remediationPublishWritePermsConfirmed) {
      setRemediationPublishError('Confirm the GitHub token is intentionally write-capable.');
      return;
    }
    if (!token) {
      setRemediationPublishError('A write-capable GitHub token is required.');
      return;
    }

    const requestID = ++remediationPublishRequestRef.current;
    setRemediationPublishLoading(true);
    setRemediationPublishError('');
    setRemediationPublishResult(null);
    try {
      const response = await apiClient.publishRepoFindingRemediation(
        selectedFinding.id,
        {
          repo_scan_id: selectedFinding.scan_id,
          source_content: sourceContent,
          base_branch: remediationPublishBaseBranch.trim() || undefined,
          finding_url: selectedFinding.source_url || undefined,
          operator_approved: remediationPublishApproved,
          write_permissions_configured: remediationPublishWritePermsConfirmed,
          github_token: token
        },
        buildProductAuthContext(scope)
      );
      if (requestID !== remediationPublishRequestRef.current) {
        return;
      }
      setRemediationPublishResult(response);
      setRemediationPublishToken('');
      setRemediationPublishApproved(false);
      setRemediationPublishWritePermsConfirmed(false);
    } catch (requestError) {
      if (requestID !== remediationPublishRequestRef.current) {
        return;
      }
      setRemediationPublishError(
        requestError instanceof Error ? requestError.message : 'Failed to publish remediation PR.'
      );
    } finally {
      if (requestID === remediationPublishRequestRef.current) {
        setRemediationPublishLoading(false);
      }
    }
  };

  useEffect(() => {
    if (!scope || !availability.available || !selectedEnvironmentID) {
      setLoading(false);
      setRepoScans([]);
      setRepoFindings([]);
      setError('');
      return undefined;
    }
    void loadRemediationData(scope, 'initial');
    return () => {
      requestRef.current += 1;
    };
  }, [availability.available, scope?.tenantID, scope?.workspaceID, selectedEnvironmentID]);

  useEffect(() => {
    if (remediationQueue.length === 0) {
      if (selectedFindingKey) {
        selectRemediationFinding(null);
      }
      return;
    }

    if (!selectedFinding || !remediationQueue.some((finding) => buildRepoFindingSelectionKey(finding) === selectedFindingKey)) {
      selectRemediationFinding(remediationQueue[0]);
    }
  }, [queueSelectionKeys, remediationQueue, selectedFinding, selectedFindingKey]);

  useEffect(() => {
    setRemediationPreview(null);
    setRemediationPreviewFindingKey('');
    setRemediationPreviewLoading(false);
    setRemediationPreviewError('');
    resetRemediationPublishState();
  }, [selectedFinding?.id, selectedFinding?.scan_id]);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <p className="idt-app-kicker">GitHub remediation</p>
        <h2>Workspace route context is missing</h2>
        <p>Choose a tenant and workspace before loading GitHub remediation.</p>
      </section>
    );
  }

  if (availability.loading) {
    return (
      <DomainPageShell
        domain="github"
        eyebrow="Remediation"
        title="GitHub remediation"
        description="Loading GitHub availability for this build."
        scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      >
        <DomainLoadingState label="Loading GitHub availability" />
      </DomainPageShell>
    );
  }

  if (!availability.available) {
    return (
      <GitHubUnavailableShell
        title="GitHub remediation"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
        unavailableMessage={availability.unavailableMessage}
      />
    );
  }

  if (!selectedEnvironmentID) {
    return (
      <GitHubMissingEnvironmentShell
        title="GitHub remediation"
        scope={scope}
        environmentScope={environmentScope}
        selectedEnvironmentID={selectedEnvironmentID}
        onEnvironmentChange={onChangeEnvironment}
      />
    );
  }

  const basePath = appendEnvironmentQuery(buildScopedPath(scope, 'github'), selectedEnvironmentID);
  const repositoriesPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/repositories'), selectedEnvironmentID);
  const findingsPath = appendEnvironmentQuery(buildScopedPath(scope, 'github/findings'), selectedEnvironmentID);
  const scansByRecency = [...repoScans].sort((left, right) => scanCompletionSortValue(right) - scanCompletionSortValue(left));
  const latestScan = scansByRecency[0] ?? null;
  const failedScans = scansByRecency.filter((scan) => isFailedScanStatus(scan.status));
  const latestFailedScan = failedScans[0] ?? null;
  const succeededScanCount = repoScans.filter((scan) => repoScanStatusTone(scan.status) === 'success').length;
  const hasQueuedOrRunningScan = repoScans.some((scan) => isActiveScanStatus(scan.status));
  const neverScanned = repoScans.length === 0;
  const latestScanFailed = latestScan ? isFailedScanStatus(latestScan.status) : false;
  const summaryFindingTotal = repoFindingSummary
    ? repoFindingSummary.total_open +
      repoFindingSummary.fixed_count +
      repoFindingSummary.reopened_count +
      repoFindingSummary.suppressed_count
    : 0;
  const hasRepoFindings =
    summaryFindingTotal > 0 || repoFindings.length > 0 || repoScans.some((scan) => (scan.finding_count ?? 0) > 0);
  const allScansFailed = !neverScanned && !hasQueuedOrRunningScan && !hasRepoFindings && succeededScanCount === 0 && latestScanFailed;
  const showInitialLoading = loading && repoScans.length === 0 && repoFindings.length === 0;
  const statusVariant = gitHubConnectionStatusVariantFor(data.connection, data.loading);
  const selectedRepository = selectedFinding
    ? canonicalGitHubRepositoryDisplay(repoFindingRepositoryValue(selectedFinding, repoScansByID)) || 'Repository unavailable'
    : '';
  const selectedReadiness = selectedFinding
    ? gitHubRemediationReadiness(selectedFinding, activeRemediationPreview)
    : { label: 'No finding selected', tone: 'neutral' as const };

  return (
    <DomainPageShell
      domain="github"
      eyebrow="Remediation"
      title="GitHub remediation"
      description="Stage repository fix plans, separate preview from publish, and keep every approval tied to the finding evidence."
      scope={<ProductEnvironmentSelector state={environmentScope} onChange={onChangeEnvironment} />}
      status={
        <DomainStatusBadge
          variant={statusVariant}
          detail={data.connection?.account_login ? `@${data.connection.account_login}` : undefined}
        />
      }
      statusTone={gitHubConnectionTone(data.connection, data.loading)}
      primaryAction={{ label: 'GitHub findings', to: findingsPath, variant: 'primary' }}
      secondaryActions={[{ label: 'Repositories', to: repositoriesPath }, { label: 'GitHub home', to: basePath }]}
      aside={
        <DomainDetailPanel title="Approval boundary" eyebrow="Fix PRs">
          <ul className="idt-domain-charter-list">
            <li>Preview plans are read-only and safe to generate.</li>
            <li>Publishing requires explicit operator approval.</li>
            <li>Write-capable GitHub tokens are confirmed per publish.</li>
            <li>Every case stays tied to finding, scan, file, line, detector, severity, and confidence.</li>
          </ul>
        </DomainDetailPanel>
      }
    >
      {data.error ? <DomainErrorState title="Unable to load GitHub status" body={data.error} retryAction={{ label: 'Retry', onClick: data.reload }} /> : null}
      {error ? <DomainErrorState title="Unable to load remediation queue" body={error} retryAction={{ label: 'Retry', onClick: handleRefresh }} /> : null}

      {showInitialLoading ? (
        <DomainLoadingState label="Loading GitHub remediation queue" />
      ) : neverScanned ? (
        <DomainEmptyState
          eyebrow="No scans"
          title="Run your first repository scan"
          body="Repository findings must exist before Identrail can prepare remediation plans."
          nextAction={{ label: 'Open Repositories', to: repositoriesPath }}
        />
      ) : allScansFailed ? (
        <DomainErrorState
          title="Your last repository scan failed"
          body={latestFailedScan ? summarizeScanFailure(latestFailedScan) : 'The scan did not complete.'}
          retryAction={{ label: 'Review and re-run scan', to: repositoriesPath }}
        />
      ) : !hasRepoFindings ? (
        <DomainEmptyState
          eyebrow="No findings"
          title="No GitHub remediation work"
          body="The latest repository scan completed without findings that need remediation."
          nextAction={{ label: 'Open GitHub findings', to: findingsPath }}
        />
      ) : (
        <>
          {latestScanFailed ? (
            <DomainErrorState
              title="Latest scan needs attention"
              body={latestFailedScan ? summarizeScanFailure(latestFailedScan) : 'The latest scan did not complete.'}
              retryAction={{ label: 'Review scans', to: repositoriesPath }}
            />
          ) : null}

          <DomainKpiStrip
            label="GitHub remediation metrics"
            items={[
              {
                label: 'Actionable findings',
                value: actionableFindings.length,
                detail: `${formatCountLabel(repoFindings.length, 'finding')} loaded`,
                tone: actionableFindings.length > 0 ? 'warning' : 'neutral'
              },
              {
                label: 'High priority',
                value: highPriorityCount,
                detail: 'Critical and high severity',
                tone: highPriorityCount > 0 ? 'danger' : 'neutral'
              },
              {
                label: 'Repositories',
                value: repositoryCount,
                detail: 'With remediation evidence',
                tone: repositoryCount > 0 ? 'success' : 'neutral'
              },
              {
                label: 'Publish-ready',
                value: publishablePreviewCount,
                detail: activeRemediationPreview ? 'Current preview' : 'Preview a finding first',
                tone: publishablePreviewCount > 0 ? 'success' : 'neutral'
              }
            ]}
          />

          <div className="idt-github-remediation-workspace">
            <section className="idt-domain-status-panel idt-github-remediation-queue" aria-label="GitHub remediation queue">
              <header>
                <div>
                  <p className="idt-app-kicker">Remediation queue</p>
                  <h3>{formatCountLabel(remediationQueue.length, 'finding')} in scope</h3>
                </div>
                <button
                  type="button"
                  className="idt-btn idt-btn-ghost"
                  onClick={handleRefresh}
                  disabled={refreshing || data.loading}
                >
                  {refreshing || data.loading ? 'Refreshing...' : 'Refresh'}
                </button>
              </header>
              <div className="idt-github-remediation-list" role="list">
                {remediationQueue.map((finding) => {
                  const selectionKey = buildRepoFindingSelectionKey(finding);
                  const repository = canonicalGitHubRepositoryDisplay(repoFindingRepositoryValue(finding, repoScansByID)) || 'Repository unavailable';
                  const readiness = gitHubRemediationReadiness(
                    finding,
                    selectionKey === selectedFindingPreviewKey ? activeRemediationPreview : null
                  );
                  return (
                    <button
                      key={selectionKey}
                      type="button"
                      role="listitem"
                      className={`idt-repo-finding-row idt-github-remediation-row${selectedFindingKey === selectionKey ? ' is-selected' : ''}`}
                      onClick={() => selectRemediationFinding(finding)}
                    >
                      <SourceLogoMark provider="github" className="is-row" />
                      <div className="idt-repo-finding-row-copy">
                        <div className="idt-repo-finding-row-top">
                          <strong>{finding.title}</strong>
                          <span className={repoFindingSeverityClass(finding.severity)}>
                            {formatTokenLabel(finding.severity)}
                          </span>
                        </div>
                        <p>{finding.remediation || finding.human_summary}</p>
                        <div className="idt-repo-finding-row-meta">
                          <span>{repository}</span>
                          <span>{repoFindingLocationLabel(finding)}</span>
                          <span>{finding.detector ? formatTokenLabel(finding.detector) : formatTokenLabel(finding.type)}</span>
                          <span>{`Confidence ${formatConfidenceScore(finding.confidence_score)}`}</span>
                        </div>
                        <div className="idt-repo-finding-row-meta">
                          <span className={repoFindingStatusClass(normalizeRepoFindingLifecycleStatus(finding.lifecycle_status))}>
                            {formatTokenLabel(normalizeRepoFindingLifecycleStatus(finding.lifecycle_status))}
                          </span>
                          <span className={`idt-github-remediation-readiness is-${readiness.tone}`}>{readiness.label}</span>
                          <span>{repoFindingScanDateLabel(finding, repoScansByID)}</span>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </section>

            <section className="idt-domain-status-panel idt-github-remediation-plan" aria-label="GitHub remediation plan">
              <header>
                <div>
                  <p className="idt-app-kicker">Plan and publish</p>
                  <h3>{selectedFinding ? selectedFinding.title : 'No finding selected'}</h3>
                </div>
                <span className={`idt-github-remediation-readiness is-${selectedReadiness.tone}`}>
                  {selectedReadiness.label}
                </span>
              </header>

              {!selectedFinding ? (
                <DomainEmptyState
                  eyebrow="Empty queue"
                  title="No remediation candidates loaded"
                  body="New remediation candidates appear after GitHub scans produce repository findings."
                  nextAction={{ label: 'Open GitHub findings', to: findingsPath }}
                />
              ) : (
                <>
                  <div className="idt-github-remediation-finding-header">
                    <div>
                      <SourceLogoMark provider="github" className="is-row" />
                      <div>
                        <strong>{selectedRepository}</strong>
                        <p>{selectedFinding.human_summary}</p>
                      </div>
                    </div>
                    <button
                      className="idt-btn idt-btn-primary"
                      type="button"
                      onClick={() => void handleLoadRemediationPreview()}
                      disabled={remediationPreviewLoading}
                    >
                      {remediationPreviewLoading ? 'Loading preview...' : 'Preview fix plan'}
                    </button>
                  </div>

                  <dl className="idt-repo-finding-facts">
                    <div>
                      <dt>Finding</dt>
                      <dd>{selectedFinding.id}</dd>
                    </div>
                    <div>
                      <dt>Scan</dt>
                      <dd>{selectedFinding.scan_id}</dd>
                    </div>
                    <div>
                      <dt>Repository</dt>
                      <dd>{selectedRepository}</dd>
                    </div>
                    <div>
                      <dt>Location</dt>
                      <dd>{repoFindingLocationLabel(selectedFinding)}</dd>
                    </div>
                    <div>
                      <dt>Detector</dt>
                      <dd>{selectedFinding.detector ? formatTokenLabel(selectedFinding.detector) : formatTokenLabel(selectedFinding.type)}</dd>
                    </div>
                    <div>
                      <dt>Severity</dt>
                      <dd>{formatTokenLabel(selectedFinding.severity)}</dd>
                    </div>
                    <div>
                      <dt>Confidence</dt>
                      <dd>{formatConfidenceScore(selectedFinding.confidence_score)}</dd>
                    </div>
                    <div>
                      <dt>Lifecycle</dt>
                      <dd>{formatTokenLabel(normalizeRepoFindingLifecycleStatus(selectedFinding.lifecycle_status))}</dd>
                    </div>
                  </dl>

                  {selectedFinding.source_url ? (
                    <a className="idt-repo-finding-link" href={selectedFinding.source_url} target="_blank" rel="noreferrer">
                      <ExternalLink size={14} strokeWidth={2} aria-hidden="true" />
                      Open linked GitHub line
                    </a>
                  ) : (
                    <div className="idt-app-alert">GitHub line link unavailable for this finding.</div>
                  )}

                  {remediationPreviewError ? (
                    <div className="idt-app-alert idt-app-alert-error">{remediationPreviewError}</div>
                  ) : null}

                  {activeRemediationPreview ? (
                    <div className="idt-repo-remediation-preview">
                      <h5>{activeRemediationPreview.remediation.summary}</h5>
                      <p>{activeRemediationPreview.remediation.risk_summary}</p>
                      <div className="idt-repo-remediation-preview-grid">
                        <div>
                          <strong>Steps</strong>
                          <ul>
                            {(activeRemediationPreview.remediation.steps ?? []).map((step) => (
                              <li key={step}>{step}</li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <strong>Validation</strong>
                          <ul>
                            {(activeRemediationPreview.remediation.validation ?? []).map((item) => (
                              <li key={item}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                      {(activeRemediationPreview.remediation.safety_notes ?? []).length > 0 ? (
                        <div>
                          <strong>Safety notes</strong>
                          <ul>
                            {(activeRemediationPreview.remediation.safety_notes ?? []).map((note) => (
                              <li key={note}>{note}</li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {activeRemediationPreview.fix_pr_plan ? (
                        <div className="idt-github-remediation-plan-files">
                          <strong>{activeRemediationPreview.fix_pr_plan.pr_title}</strong>
                          <span>{`Branch ${activeRemediationPreview.fix_pr_plan.branch_name}`}</span>
                          <ul>
                            {activeRemediationPreview.fix_pr_plan.files.map((file) => (
                              <li key={file.path}>{file.path}</li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      <p>
                        {activeRemediationPreview.remediation.publishable
                          ? 'A fix PR can be published after approval and write-permission confirmation.'
                          : activeRemediationPreview.remediation.publish_blocked_reason || 'Manual remediation is required.'}
                      </p>
                      {activeRemediationPreview.remediation.publishable ? (
                        <div className="idt-repo-remediation-publish">
                          {remediationPublishError ? (
                            <div className="idt-app-alert idt-app-alert-error">{remediationPublishError}</div>
                          ) : null}
                          {remediationPublishResult ? (
                            <div className="idt-app-alert idt-app-alert-success">
                              PR #{remediationPublishResult.publish.pr_number} opened on{' '}
                              {remediationPublishResult.publish.branch_name}.{' '}
                              <a href={remediationPublishResult.publish.pr_url} target="_blank" rel="noreferrer">
                                View PR
                              </a>
                            </div>
                          ) : null}
                          <div className="idt-github-remediation-publish-grid">
                            <label>
                              Base branch
                              <input
                                type="text"
                                value={remediationPublishBaseBranch}
                                onChange={(event) => setRemediationPublishBaseBranch(event.target.value)}
                                placeholder="main"
                              />
                            </label>
                            <label>
                              GitHub token
                              <input
                                type="password"
                                value={remediationPublishToken}
                                onChange={(event) => setRemediationPublishToken(event.target.value)}
                                autoComplete="off"
                              />
                            </label>
                          </div>
                          <label>
                            Current source content
                            <textarea
                              value={remediationPublishSourceContent}
                              onChange={(event) => setRemediationPublishSourceContent(event.target.value)}
                              rows={7}
                              spellCheck={false}
                            />
                          </label>
                          <label className="idt-repo-remediation-approval">
                            <input
                              type="checkbox"
                              checked={remediationPublishApproved}
                              onChange={(event) => setRemediationPublishApproved(event.target.checked)}
                            />
                            <span>Approved for publish</span>
                          </label>
                          <label className="idt-repo-remediation-approval">
                            <input
                              type="checkbox"
                              checked={remediationPublishWritePermsConfirmed}
                              onChange={(event) => setRemediationPublishWritePermsConfirmed(event.target.checked)}
                            />
                            <span>GitHub token is intentionally write-capable</span>
                          </label>
                          <button
                            className="idt-btn idt-btn-primary"
                            type="button"
                            onClick={() => void handlePublishRemediation()}
                            disabled={
                              remediationPublishLoading ||
                              !remediationPublishApproved ||
                              !remediationPublishWritePermsConfirmed
                            }
                          >
                            {remediationPublishLoading ? 'Publishing...' : 'Publish fix PR'}
                          </button>
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </>
              )}
            </section>
          </div>
        </>
      )}
    </DomainPageShell>
  );
}

export function ProductReportsPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);
  const reportPath = scope ? buildScopedPath(scope, 'reports') : '/app';

  return (
    <section className="idt-app-panel idt-reports-page">
      <header className="idt-settings-header">
        <div>
          <p className="idt-app-kicker">Reports</p>
          <h2>Reports</h2>
          <p>
            Executive posture, trend narratives, and domain outcome reporting now live inside the scoped app instead of
            being treated as a detached workspace artifact.
          </p>
        </div>
        <div className="idt-inline-actions">
          <Link className="idt-btn idt-btn-primary" to="/reports/executive">
            Open executive report
          </Link>
        </div>
      </header>
      <div className="idt-domain-kpi-strip" aria-label="Report route readiness">
        <article className="idt-domain-kpi is-success">
          <span>Route</span>
          <strong>Live</strong>
          <p>{reportPath}</p>
        </article>
        <article className="idt-domain-kpi">
          <span>Scope</span>
          <strong>Domain</strong>
          <p>AWS, GitHub, Kubernetes, and executive reporting can land here in later PRs.</p>
        </article>
        <article className="idt-domain-kpi">
          <span>Output</span>
          <strong>Board</strong>
          <p>Designed for executive posture and remediation outcome summaries.</p>
        </article>
      </div>
      <DomainStatusPanel eyebrow="Reporting foundation" title="Outcome views are staged" status="Staged" tone="success">
        <p>
          This route keeps the IA complete while the deeper executive outcome, domain coverage, and remediation reporting
          experiences arrive in their planned sequence.
        </p>
      </DomainStatusPanel>
    </section>
  );
}

const SIDEBAR_COLLAPSED_STORAGE_KEY = 'idt:sidebar:collapsed';
const SIDEBAR_WIDTH_STORAGE_KEY = 'idt:sidebar:width';
const SIDEBAR_DEFAULT_WIDTH = 248; // matches the prior 15.5rem
const SIDEBAR_MIN_EXPANDED_WIDTH = 196;
const SIDEBAR_MAX_WIDTH = 360;
const SIDEBAR_COLLAPSE_THRESHOLD = 140; // dragging below this snaps to collapsed
const SIDEBAR_COLLAPSED_WIDTH = 60;
const SCROLL_NAVIGATOR_MIN_THUMB_HEIGHT = 88;
const SCROLL_NAVIGATOR_MAX_THUMB_HEIGHT = 168;

type ScrollNavigatorMetrics = {
  visible: boolean;
  thumbHeight: number;
  thumbTop: number;
};

function readSidebarCollapsed(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }
  try {
    return window.localStorage.getItem(SIDEBAR_COLLAPSED_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function readSidebarWidth(): number {
  if (typeof window === 'undefined') {
    return SIDEBAR_DEFAULT_WIDTH;
  }
  try {
    const raw = window.localStorage.getItem(SIDEBAR_WIDTH_STORAGE_KEY);
    if (!raw) {
      return SIDEBAR_DEFAULT_WIDTH;
    }
    const parsed = Number.parseInt(raw, 10);
    if (Number.isNaN(parsed)) {
      return SIDEBAR_DEFAULT_WIDTH;
    }
    return Math.min(SIDEBAR_MAX_WIDTH, Math.max(SIDEBAR_MIN_EXPANDED_WIDTH, parsed));
  } catch {
    return SIDEBAR_DEFAULT_WIDTH;
  }
}

function isMacPlatform(): boolean {
  if (typeof navigator === 'undefined') {
    return false;
  }
  return /Mac|iPhone|iPad|iPod/i.test(navigator.platform || '');
}

export function ProductShellLayout() {
  const params = useParams<ScopeRouteParams>();
  const location = useLocation();
  const navigate = useNavigate();
  const scope = resolveScopeFromParams(params);
  const { features: backendFeatures } = useBackendFeatures({ enabled: SHOULD_LOAD_CONNECTOR_BACKEND_FEATURES });
  const sourceAvailability = useMemo(() => buildSourceAvailability(backendFeatures), [backendFeatures]);
  const visibleDomainOrder = useMemo(
    () => DOMAIN_NAV_ORDER.filter((domain) => sourceAvailability[domain].visible),
    [sourceAvailability]
  );
  const [commandOpen, setCommandOpen] = useState(false);
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const [workspaceMenuOpen, setWorkspaceMenuOpen] = useState(false);
  const [openDomainFlyout, setOpenDomainFlyout] = useState<SourceProvider | null>(null);
  const [lastOpenedDomainFlyout, setLastOpenedDomainFlyout] = useState<SourceProvider | null>(null);
  const [sidebarCollapsedPref, setSidebarCollapsedPref] = useState<boolean>(() => readSidebarCollapsed());
  const [sidebarWidth, setSidebarWidth] = useState<number>(() => readSidebarWidth());
  const [isDraggingSidebar, setIsDraggingSidebar] = useState(false);
  const [isSidebarEdgeFocused, setIsSidebarEdgeFocused] = useState(false);
  const [scrollNavigator, setScrollNavigator] = useState<ScrollNavigatorMetrics>({
    visible: false,
    thumbHeight: 0,
    thumbTop: 0
  });
  const [isNarrowViewport, setIsNarrowViewport] = useState<boolean>(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return false;
    }
    return window.matchMedia('(max-width: 960px)').matches;
  });
  // The collapsed state is forced off on narrow viewports because the rail
  // becomes a horizontal top bar there — there is no useful "collapsed" mode
  // for a horizontal nav, and persisting a collapsed preference into mobile
  // would otherwise leave users without a way to expand it.
  const sidebarCollapsed = sidebarCollapsedPref && !isNarrowViewport;
  const renderedSidebarWidth = isNarrowViewport
    ? undefined
    : sidebarCollapsed
      ? SIDEBAR_COLLAPSED_WIDTH
      : sidebarWidth;
  const accountMenuRef = useRef<HTMLDivElement | null>(null);
  const workspaceMenuRef = useRef<HTMLDivElement | null>(null);
  const domainFlyoutRef = useRef<HTMLDivElement | null>(null);
  const domainTriggerRefs = useRef<Record<SourceProvider, HTMLButtonElement | null>>({
    aws: null,
    github: null,
    kubernetes: null
  });
  const sidebarRef = useRef<HTMLElement | null>(null);
  const sidebarResizeMovedRef = useRef(false);
  const basePath = scope ? buildScopedPath(scope) : '/app';
  const activeDomain = scope ? findActiveDomain(scope, location.pathname) : null;
  const activeDomainRouteID =
    scope && openDomainFlyout ? findActiveDomainRouteID(scope, openDomainFlyout, location.pathname) : null;
  const commandItems = useMemo<CommandPaletteItem[]>(() => {
    if (!scope) {
      return [];
    }
    const items: CommandPaletteItem[] = [
      {
        id: 'overview',
        label: 'Overview',
        description: 'Cross-domain posture and next actions',
        keywords: ['home', 'dashboard', 'workspace', 'domains'],
        path: basePath
      }
    ];

    if (sourceAvailability.aws.visible) {
      items.push({
        id: 'aws',
        label: 'AWS',
        description: 'AWS machine identity control center',
        keywords: ['aws', 'cloud', 'iam', 'identity'],
        path: `${basePath}/aws`
      });
      items.push({
        id: 'aws-findings',
        label: 'AWS findings',
        description: 'Domain-scoped AWS risk queue',
        keywords: ['aws', 'findings', 'risk', 'iam'],
        path: `${basePath}/aws/findings`
      });
      if (sourceAvailability.aws.available) {
        items.push({
          id: 'aws-connect',
          label: 'Connect AWS',
          description: 'Start AWS account and identity onboarding',
          keywords: ['aws', 'connect', 'account', 'role'],
          path: `${basePath}/aws/connect`
        });
      }
    }

    if (sourceAvailability.github.visible) {
      items.push({
        id: 'github',
        label: 'GitHub',
        description: 'Repositories, Actions/OIDC, and agentic risk',
        keywords: ['github', 'repositories', 'actions', 'oidc'],
        path: `${basePath}/github`
      });
      items.push({
        id: 'github-findings',
        label: 'GitHub findings',
        description: 'Repository risk inside the GitHub section',
        keywords: ['github', 'findings', 'repository', 'triage'],
        path: `${basePath}/github/findings`
      });
      items.push({
        id: 'github-agentic-risk',
        label: 'GitHub AI / Agentic Risk',
        description: 'Agent identities, MCP tools, prompts, secrets, and workflow trust paths',
        keywords: ['github', 'agentic', 'ai', 'mcp', 'tools', 'prompts', 'secrets', 'workflow'],
        path: `${basePath}/github/agentic-risk`
      });
      if (sourceAvailability.github.available) {
        items.push({
          id: 'github-connect',
          label: 'Connect GitHub',
          description: 'Start GitHub App onboarding',
          keywords: ['github', 'connect', 'app', 'install'],
          path: `${basePath}/github/connect`
        });
      }
    }

    if (sourceAvailability.kubernetes.visible) {
      items.push({
        id: 'kubernetes',
        label: 'Kubernetes',
        description: 'Clusters, workloads, service accounts, and RBAC',
        keywords: ['kubernetes', 'k8s', 'clusters', 'rbac'],
        path: `${basePath}/kubernetes`
      });
      items.push({
        id: 'kubernetes-findings',
        label: 'Kubernetes findings',
        description: 'Cluster and service-account risk queue',
        keywords: ['kubernetes', 'k8s', 'findings', 'rbac'],
        path: `${basePath}/kubernetes/findings`
      });
      if (sourceAvailability.kubernetes.available) {
        items.push({
          id: 'kubernetes-connect',
          label: 'Connect Kubernetes',
          description: 'Start cluster onboarding',
          keywords: ['kubernetes', 'k8s', 'connect', 'cluster'],
          path: `${basePath}/kubernetes/connect`
        });
      }
    }

    items.push(
      {
        id: 'reports',
        label: 'Reports',
        description: 'Executive posture and domain outcome views',
        keywords: ['report', 'board', 'risk', 'executive'],
        path: `${basePath}/reports`
      },
      {
        id: 'settings',
        label: 'Settings',
        description: 'Workspace identity, members, sessions, and lifecycle',
        keywords: ['identity', 'access', 'authentication', 'members', 'sessions'],
        path: `${basePath}/settings`
      },
      {
        id: 'marketing-site',
        label: 'Marketing site',
        description: 'Return to the public Identrail site',
        keywords: ['public', 'website', 'home'],
        path: '/'
      },
      {
        id: 'sign-out',
        label: 'Sign out',
        description: 'End this workspace session',
        keywords: ['logout', 'session'],
        action: () => navigate('/app/logout', { replace: true })
      }
    );
    return items;
  }, [basePath, navigate, scope, sourceAvailability]);

  useEffect(() => {
    setOpenDomainFlyout(null);
    setLastOpenedDomainFlyout(null);
  }, [location.pathname]);

  useEffect(() => {
    if (!openDomainFlyout) {
      return;
    }
    setAccountMenuOpen(false);
    setWorkspaceMenuOpen(false);
    const focusFrame = window.requestAnimationFrame(() => {
      const firstAction = domainFlyoutRef.current?.querySelector<HTMLElement>(
        '[data-domain-flyout-primary="true"], a[href], button:not([disabled]), summary'
      );
      firstAction?.focus();
    });
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        const trigger = domainTriggerRefs.current[openDomainFlyout];
        setOpenDomainFlyout(null);
        window.requestAnimationFrame(() => trigger?.focus());
        return;
      }
      if (event.key === 'Tab' && domainFlyoutRef.current) {
        const focusable = Array.from(
          domainFlyoutRef.current.querySelectorAll<HTMLElement>(
            'a[href], button:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'
          )
        ).filter((element) => element.offsetParent !== null || element.tagName === 'SUMMARY');
        if (!focusable.length) {
          return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
          return;
        }
        if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      window.removeEventListener('keydown', handleKey);
    };
  }, [openDomainFlyout]);

  useEffect(() => {
    if (commandOpen) {
      setOpenDomainFlyout(null);
    }
  }, [commandOpen]);

  useEffect(() => {
    if (!openDomainFlyout || typeof document === 'undefined') {
      return undefined;
    }

    const root = document.documentElement;
    const body = document.body;
    const previousRootOverflow = root.style.overflow;
    const previousBodyOverflow = body.style.overflow;
    root.style.overflow = 'hidden';
    body.style.overflow = 'hidden';
    return () => {
      root.style.overflow = previousRootOverflow;
      body.style.overflow = previousBodyOverflow;
    };
  }, [openDomainFlyout]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || isEditableTarget(event.target)) {
        return;
      }

      const key = event.key.toLowerCase();
      if ((event.metaKey || event.ctrlKey) && key === 'k') {
        event.preventDefault();
        setCommandOpen(true);
        return;
      }
      if ((event.metaKey || event.ctrlKey) && key === 'b') {
        event.preventDefault();
        setSidebarCollapsedPref((current) => !current);
        return;
      }
      if (!event.metaKey && !event.ctrlKey && !event.altKey && (key === '/' || key === 'f')) {
        event.preventDefault();
        setCommandOpen(true);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    try {
      window.localStorage.setItem(SIDEBAR_COLLAPSED_STORAGE_KEY, sidebarCollapsedPref ? '1' : '0');
    } catch {
      // Storage failure should not break the layout.
    }
  }, [sidebarCollapsedPref]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    try {
      window.localStorage.setItem(SIDEBAR_WIDTH_STORAGE_KEY, String(sidebarWidth));
    } catch {
      // Storage failure should not break the layout.
    }
  }, [sidebarWidth]);

  const toggleSidebarCollapsed = useCallback(() => {
    if (isNarrowViewport) {
      return;
    }
    setSidebarCollapsedPref((current) => !current);
  }, [isNarrowViewport]);

  const handleSidebarResizeStart = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (isNarrowViewport) {
      return;
    }
    if (event.button !== 0) {
      return;
    }
    event.preventDefault();
    const handleEl = event.currentTarget;
    const pointerId = event.pointerId;
    const startClientX = event.clientX;
    sidebarResizeMovedRef.current = false;
    // Capture the pointer so every subsequent move / up / cancel for this
    // gesture is delivered to the handle even if the user releases outside the
    // viewport, the OS steals focus, or the browser fires `pointercancel`.
    // Without this, releasing off-window left `isDraggingSidebar` stuck true
    // and the body `cursor: col-resize` / `user-select: none` overrides
    // applied to the entire page.
    try {
      handleEl.setPointerCapture(pointerId);
    } catch {
      // Some test environments (jsdom) don't implement setPointerCapture.
      // Falling through is safe — the cleanup is still wired up below.
    }
    setIsDraggingSidebar(true);
    const sidebarEl = sidebarRef.current;
    const startLeft = sidebarEl ? sidebarEl.getBoundingClientRect().left : 0;
    const handlePointerMove = (moveEvent: PointerEvent) => {
      if (moveEvent.pointerId !== pointerId) {
        return;
      }
      if (Math.abs(moveEvent.clientX - startClientX) > 4) {
        sidebarResizeMovedRef.current = true;
      }
      const proposed = moveEvent.clientX - startLeft;
      if (proposed < SIDEBAR_COLLAPSE_THRESHOLD) {
        setSidebarCollapsedPref(true);
        return;
      }
      const clamped = Math.min(SIDEBAR_MAX_WIDTH, Math.max(SIDEBAR_MIN_EXPANDED_WIDTH, proposed));
      setSidebarCollapsedPref(false);
      setSidebarWidth(clamped);
    };
    const cleanup = (cleanupEvent?: PointerEvent) => {
      if (cleanupEvent && cleanupEvent.pointerId !== pointerId) {
        return;
      }
      const shouldToggle = cleanupEvent?.type === 'pointerup' && !sidebarResizeMovedRef.current;
      setIsDraggingSidebar(false);
      handleEl.removeEventListener('pointermove', handlePointerMove);
      handleEl.removeEventListener('pointerup', cleanup);
      handleEl.removeEventListener('pointercancel', cleanup);
      handleEl.removeEventListener('lostpointercapture', cleanup);
      if (shouldToggle) {
        toggleSidebarCollapsed();
      }
    };
    handleEl.addEventListener('pointermove', handlePointerMove);
    handleEl.addEventListener('pointerup', cleanup);
    handleEl.addEventListener('pointercancel', cleanup);
    // `lostpointercapture` fires whenever capture ends for any reason —
    // including the OS canceling the gesture or the element being unmounted
    // by React. It is the most reliable final cleanup signal.
    handleEl.addEventListener('lostpointercapture', cleanup);
  };

  const handleSidebarResizeKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key !== 'Enter' && event.key !== ' ') {
      return;
    }
    event.preventDefault();
    toggleSidebarCollapsed();
  };

  // Safety net: any time we leave the dragging state, ensure the body style
  // overrides we applied are released. Also handles the unmount-mid-drag
  // case (effect cleanup runs once on unmount) without leaving the document
  // stuck in `cursor: col-resize` / `user-select: none`.
  useEffect(() => {
    if (typeof document === 'undefined') {
      return;
    }
    if (isDraggingSidebar) {
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
      return () => {
        document.body.style.removeProperty('cursor');
        document.body.style.removeProperty('user-select');
      };
    }
    document.body.style.removeProperty('cursor');
    document.body.style.removeProperty('user-select');
    return undefined;
  }, [isDraggingSidebar]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    let frameID: number | undefined;
    const requestFrame =
      window.requestAnimationFrame ?? ((callback: FrameRequestCallback) => window.setTimeout(callback, 16));
    const cancelFrame = window.cancelAnimationFrame ?? window.clearTimeout;
    const updateMetrics = () => {
      frameID = undefined;
      const scrollingElement = document.scrollingElement ?? document.documentElement;
      const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
      const scrollHeight = Math.max(
        scrollingElement.scrollHeight,
        document.documentElement.scrollHeight,
        document.body.scrollHeight
      );
      const scrollRange = scrollHeight - viewportHeight;

      if (scrollRange <= 24 || viewportHeight <= 0) {
        setScrollNavigator((current) =>
          current.visible ? { visible: false, thumbHeight: 0, thumbTop: 0 } : current
        );
        return;
      }

      const trackTop = Math.min(112, Math.max(80, viewportHeight * 0.13));
      const trackBottom = Math.min(56, Math.max(36, viewportHeight * 0.05));
      const trackHeight = Math.max(120, viewportHeight - trackTop - trackBottom);
      const thumbHeight = Math.round(
        Math.min(
          SCROLL_NAVIGATOR_MAX_THUMB_HEIGHT,
          Math.max(SCROLL_NAVIGATOR_MIN_THUMB_HEIGHT, trackHeight * 0.22)
        )
      );
      const scrollProgress = Math.min(1, Math.max(0, scrollingElement.scrollTop / scrollRange));
      const thumbTop = Math.round(trackTop + (trackHeight - thumbHeight) * scrollProgress);

      setScrollNavigator((current) => {
        if (
          current.visible &&
          current.thumbHeight === thumbHeight &&
          Math.abs(current.thumbTop - thumbTop) <= 1
        ) {
          return current;
        }
        return { visible: true, thumbHeight, thumbTop };
      });
    };
    const scheduleUpdate = () => {
      if (frameID !== undefined) {
        cancelFrame(frameID);
      }
      frameID = requestFrame(updateMetrics);
    };

    updateMetrics();
    window.addEventListener('scroll', scheduleUpdate, { passive: true });
    window.addEventListener('resize', scheduleUpdate);

    const observer =
      typeof ResizeObserver === 'undefined'
        ? null
        : new ResizeObserver(() => {
            scheduleUpdate();
          });
    observer?.observe(document.documentElement);
    observer?.observe(document.body);

    return () => {
      if (frameID !== undefined) {
        cancelFrame(frameID);
      }
      window.removeEventListener('scroll', scheduleUpdate);
      window.removeEventListener('resize', scheduleUpdate);
      observer?.disconnect();
    };
  }, [location.pathname]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const mql = window.matchMedia('(max-width: 960px)');
    const update = () => setIsNarrowViewport(mql.matches);
    update();
    if (typeof mql.addEventListener === 'function') {
      mql.addEventListener('change', update);
      return () => mql.removeEventListener('change', update);
    }
    // Safari < 14 fallback.
    mql.addListener(update);
    return () => mql.removeListener(update);
  }, []);

  useEffect(() => {
    if (!accountMenuOpen) {
      return;
    }
    const handleClick = (event: MouseEvent) => {
      if (!accountMenuRef.current || accountMenuRef.current.contains(event.target as Node)) {
        return;
      }
      setAccountMenuOpen(false);
    };
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setAccountMenuOpen(false);
      }
    };
    window.addEventListener('mousedown', handleClick);
    window.addEventListener('keydown', handleKey);
    return () => {
      window.removeEventListener('mousedown', handleClick);
      window.removeEventListener('keydown', handleKey);
    };
  }, [accountMenuOpen]);

  useEffect(() => {
    if (!workspaceMenuOpen) {
      return;
    }
    const handleClick = (event: MouseEvent) => {
      if (!workspaceMenuRef.current || workspaceMenuRef.current.contains(event.target as Node)) {
        return;
      }
      setWorkspaceMenuOpen(false);
    };
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setWorkspaceMenuOpen(false);
      }
    };
    window.addEventListener('mousedown', handleClick);
    window.addEventListener('keydown', handleKey);
    return () => {
      window.removeEventListener('mousedown', handleClick);
      window.removeEventListener('keydown', handleKey);
    };
  }, [workspaceMenuOpen]);

  if (!scope) {
    return <AppShellLoading message="Resolving workspace scope" />;
  }

  const rawWorkspaceLabel = formatScopeDisplay(scope.workspaceID);
  const looksLikeSlug = /^[a-z0-9][a-z0-9._-]*$/i.test(rawWorkspaceLabel);
  const workspaceDisplayName = looksLikeSlug
    ? rawWorkspaceLabel.replace(/[-_]+/g, ' ').replace(/\b\w/g, (ch) => ch.toUpperCase())
    : rawWorkspaceLabel || 'Workspace';
  const userDisplayName = 'Account';
  const userEmail = '';
  const userInitial = (workspaceDisplayName.charAt(0) || 'A').toUpperCase();
  const collapseShortcut = isMacPlatform() ? '⌘B' : 'Ctrl+B';
  const runCommand = (item: CommandPaletteItem) => {
    setCommandOpen(false);
    setOpenDomainFlyout(null);
    setLastOpenedDomainFlyout(null);
    if (item.path) {
      navigate(item.path);
      return;
    }
    item.action?.();
  };
  const closeDomainFlyout = () => setOpenDomainFlyout(null);
  const resetDomainFlyoutHighlight = () => {
    setOpenDomainFlyout(null);
    setLastOpenedDomainFlyout(null);
  };
  const toggleDomainFlyout = (domain: SourceProvider) => {
    setAccountMenuOpen(false);
    setWorkspaceMenuOpen(false);
    setCommandOpen(false);
    setLastOpenedDomainFlyout(domain);
    setOpenDomainFlyout((current) => (current === domain ? null : domain));
  };
  const rememberedDomainHighlight =
    lastOpenedDomainFlyout && visibleDomainOrder.includes(lastOpenedDomainFlyout) ? lastOpenedDomainFlyout : null;
  const domainFlyoutOwnsRouteHighlight = Boolean(openDomainFlyout || (!activeDomain && rememberedDomainHighlight));

  return (
    <ProductErrorBoundary>
      <div
        className={`idt-app-shell idt-app-console-layout${sidebarCollapsed ? ' is-sidebar-collapsed' : ''}${isDraggingSidebar ? ' is-sidebar-dragging' : ''}${openDomainFlyout ? ' is-domain-flyout-open' : ''}`}
        data-tenant={scope.tenantID}
        data-workspace={scope.workspaceID}
        style={
          renderedSidebarWidth !== undefined
            ? ({ ['--idt-sidebar-width' as string]: `${renderedSidebarWidth}px` } as CSSProperties)
            : undefined
        }
      >
        <aside
          ref={sidebarRef}
          className="idt-app-sidebar"
          aria-label="Workspace navigation"
          data-collapsed={sidebarCollapsed ? 'true' : 'false'}
        >
          <div
            className={`idt-app-sidebar-resize-handle${isDraggingSidebar ? ' is-dragging' : ''}${isSidebarEdgeFocused ? ' is-focused' : ''}${openDomainFlyout ? ' is-domain-flyout-blocked' : ''}`}
            role="separator"
            tabIndex={openDomainFlyout ? -1 : 0}
            aria-orientation="vertical"
            aria-label={`${sidebarCollapsed ? 'Expand' : 'Collapse'} sidebar. Drag to resize.`}
            data-sidebar-action={sidebarCollapsed ? 'Click to expand' : 'Click to collapse'}
            data-sidebar-shortcut={collapseShortcut}
            onPointerDown={handleSidebarResizeStart}
            onKeyDown={handleSidebarResizeKeyDown}
            onFocus={() => setIsSidebarEdgeFocused(true)}
            onBlur={() => setIsSidebarEdgeFocused(false)}
          />
          <div className="idt-app-sidebar-workspace" ref={workspaceMenuRef}>
            <button
              type="button"
              className="idt-app-sidebar-workspace-trigger"
              aria-haspopup="menu"
              aria-expanded={workspaceMenuOpen}
              aria-label={`Workspace: ${workspaceDisplayName}. Open switcher.`}
              onClick={() => {
                setOpenDomainFlyout(null);
                setWorkspaceMenuOpen((value) => !value);
              }}
              title={sidebarCollapsed ? workspaceDisplayName : undefined}
            >
              <span className="idt-app-sidebar-mark" aria-hidden="true">
                <img src="/identrail-logo.png" alt="" aria-hidden="true" />
              </span>
              <span className="idt-app-sidebar-workspace-copy">
                <strong>{workspaceDisplayName}</strong>
              </span>
              <span className="idt-app-sidebar-workspace-caret" aria-hidden="true">
                <ChevronDown size={12} strokeWidth={2} />
              </span>
            </button>
            {workspaceMenuOpen ? (
              <div className="idt-app-sidebar-workspace-menu" role="menu">
                <div className="idt-app-sidebar-workspace-meta">
                  <span className="idt-app-sidebar-workspace-meta-eyebrow">Current workspace</span>
                  <strong>{workspaceDisplayName}</strong>
                </div>
                <Link
                  role="menuitem"
                  to={`${basePath}/workspaces`}
                  onClick={() => {
                    setWorkspaceMenuOpen(false);
                    resetDomainFlyoutHighlight();
                  }}
                >
                  Switch workspace
                </Link>
                <Link
                  role="menuitem"
                  to={`${basePath}/settings`}
                  onClick={() => {
                    setWorkspaceMenuOpen(false);
                    resetDomainFlyoutHighlight();
                  }}
                >
                  Settings
                </Link>
                <Link
                  role="menuitem"
                  to="/onboarding/org"
                  onClick={() => {
                    setWorkspaceMenuOpen(false);
                    resetDomainFlyoutHighlight();
                  }}
                >
                  Create a workspace
                </Link>
              </div>
            ) : null}
          </div>

          <button
            type="button"
            className="idt-app-quick-find"
            onClick={() => setCommandOpen(true)}
            aria-label="Open workspace finder"
            title={sidebarCollapsed ? 'Find (⌘K)' : undefined}
          >
            <span className="idt-app-quick-find-icon" aria-hidden="true">
              <Search size={14} strokeWidth={2} />
            </span>
            <span className="idt-app-quick-find-label">Find</span>
            <kbd className="idt-app-quick-find-key">⌘K</kbd>
          </button>

          {openDomainFlyout ? (
            <button
              type="button"
              className="idt-domain-flyout-sidebar-backdrop"
              aria-hidden="true"
              tabIndex={-1}
              onClick={closeDomainFlyout}
            />
          ) : null}

          <nav className="idt-app-shell-nav" aria-label="App sections">
            <NavLink
              to={basePath}
              end
              aria-label="Overview"
              title={sidebarCollapsed ? 'Overview' : undefined}
              className={({ isActive }) => (isActive && !domainFlyoutOwnsRouteHighlight ? 'active' : undefined)}
              onClick={resetDomainFlyoutHighlight}
            >
              <span className="idt-app-nav-icon" aria-hidden="true">
                <LayoutDashboard size={16} strokeWidth={1.75} />
              </span>
              <span className="idt-app-nav-label">Overview</span>
            </NavLink>
            {visibleDomainOrder.map((domain) => {
              const config = PRODUCT_DOMAIN_CONFIGS[domain];
              const availability = sourceAvailability[domain];
              const isOpen = openDomainFlyout === domain;
              const isActive =
                (activeDomain === domain && (!openDomainFlyout || isOpen)) ||
                (!openDomainFlyout && !activeDomain && rememberedDomainHighlight === domain);
              const triggerID = `idt-${domain}-domain-trigger`;
              return (
                <div key={domain} className={`idt-app-domain-nav-item${isOpen ? ' is-open' : ''}`}>
                  <button
                    id={triggerID}
                    ref={(node) => {
                      domainTriggerRefs.current[domain] = node;
                    }}
                    type="button"
                    className={`idt-app-nav-domain-trigger${isActive ? ' is-active' : ''}${isOpen ? ' is-open' : ''}`}
                    data-connector-available={availability.available ? 'true' : 'false'}
                    aria-haspopup="dialog"
                    aria-expanded={isOpen}
                    aria-controls={isOpen ? `idt-${domain}-domain-flyout` : undefined}
                    aria-label={config.navLabel}
                    title={
                      sidebarCollapsed
                        ? config.navLabel
                        : !availability.available
                          ? availability.unavailableMessage ?? 'Unavailable'
                          : undefined
                    }
                    onClick={() => toggleDomainFlyout(domain)}
                  >
                    <span className="idt-app-nav-icon" aria-hidden="true">
                      <SidebarDomainIcon domain={domain} />
                    </span>
                    <span className="idt-app-nav-label">{config.navLabel}</span>
                    <ChevronDown className="idt-app-nav-disclosure" size={13} strokeWidth={1.8} aria-hidden="true" />
                  </button>
                  {isOpen ? (
                    <ProductDomainFlyout
                      domain={domain}
                      scope={scope}
                      activeRouteID={activeDomainRouteID}
                      labelledBy={triggerID}
                      panelRef={domainFlyoutRef}
                      onClose={closeDomainFlyout}
                    />
                  ) : null}
                </div>
              );
            })}
            <NavLink
              to={`${basePath}/reports`}
              aria-label="Reports"
              title={sidebarCollapsed ? 'Reports' : undefined}
              className={({ isActive }) => (isActive && !domainFlyoutOwnsRouteHighlight ? 'active' : undefined)}
              onClick={resetDomainFlyoutHighlight}
            >
              <span className="idt-app-nav-icon" aria-hidden="true">
                <BarChart3 size={16} strokeWidth={1.75} />
              </span>
              <span className="idt-app-nav-label">Reports</span>
            </NavLink>
            <NavLink
              to={`${basePath}/settings`}
              aria-label="Settings"
              title={sidebarCollapsed ? 'Settings' : undefined}
              className={({ isActive }) => (isActive && !domainFlyoutOwnsRouteHighlight ? 'active' : undefined)}
              onClick={resetDomainFlyoutHighlight}
            >
              <span className="idt-app-nav-icon" aria-hidden="true">
                <SettingsIcon size={16} strokeWidth={1.75} />
              </span>
              <span className="idt-app-nav-label">Settings</span>
            </NavLink>
          </nav>

          <div className="idt-app-sidebar-footer">
            <div className="idt-app-sidebar-account" ref={accountMenuRef}>
              <button
                type="button"
                className="idt-app-sidebar-account-trigger"
                aria-haspopup="menu"
                aria-expanded={accountMenuOpen}
                aria-label={`Account menu for ${userDisplayName}`}
                onClick={() => {
                  setOpenDomainFlyout(null);
                  setAccountMenuOpen((current) => !current);
                }}
                title={sidebarCollapsed ? userDisplayName : undefined}
              >
                <span className="idt-app-sidebar-account-avatar" aria-hidden="true">
                  {userInitial}
                </span>
                <span className="idt-app-sidebar-account-name">
                  <strong>{userDisplayName}</strong>
                  {userEmail && userEmail !== userDisplayName ? <span>{userEmail}</span> : null}
                </span>
                <span className="idt-app-sidebar-account-caret" aria-hidden="true">
                  <ChevronUp size={12} strokeWidth={2} />
                </span>
              </button>
              {accountMenuOpen ? (
                <div className="idt-app-sidebar-account-menu" role="menu">
                  <div className="idt-app-sidebar-account-meta">
                    <strong>{userDisplayName}</strong>
                    {userEmail ? <span>{userEmail}</span> : null}
                  </div>
                  <a
                    role="menuitem"
                    href="https://github.com/identrail/identrail/issues"
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={() => setAccountMenuOpen(false)}
                  >
                    <HelpCircle size={14} strokeWidth={1.75} aria-hidden="true" />
                    Help &amp; feedback
                  </a>
                  <Link role="menuitem" to="/" onClick={() => setAccountMenuOpen(false)}>
                    <ExternalLink size={14} strokeWidth={1.75} aria-hidden="true" />
                    Marketing site
                  </Link>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setAccountMenuOpen(false);
                      navigate('/app/logout', { replace: true });
                    }}
                  >
                    <LogOut size={14} strokeWidth={1.75} aria-hidden="true" />
                    Sign out
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        </aside>

        {openDomainFlyout ? (
          <button
            type="button"
            className="idt-domain-flyout-backdrop"
            aria-label="Close domain section menu"
            onClick={closeDomainFlyout}
          />
        ) : null}

        <div className="idt-app-console">
          <main className="idt-app-shell-main">
            <Outlet />
          </main>
        </div>
        {scrollNavigator.visible ? (
          <div
            className="idt-app-scroll-navigator"
            aria-hidden="true"
            style={
              {
                '--idt-scroll-navigator-thumb-height': `${scrollNavigator.thumbHeight}px`,
                '--idt-scroll-navigator-thumb-top': `${scrollNavigator.thumbTop}px`
              } as CSSProperties
            }
          >
            <span className="idt-app-scroll-navigator-thumb" />
          </div>
        ) : null}
      </div>
      <CommandPalette
        open={commandOpen}
        items={commandItems}
        onClose={() => setCommandOpen(false)}
        onSelect={runCommand}
      />
    </ProductErrorBoundary>
  );
}

function formatRelativeTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  const diffMs = Date.now() - parsed.getTime();
  const diffMinutes = Math.round(diffMs / 60000);
  if (diffMinutes < 1) return 'just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.round(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return parsed.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function summarizeScanFailure(scan: RepoScanRecord): string {
  const message = (scan.error_message || '').trim();
  if (!message) {
    return 'Failed without a reported reason';
  }
  const lowered = message.toLowerCase();
  if (lowered.includes('rate limit') || lowered.includes('secondary rate')) {
    return 'Hit GitHub rate limit';
  }
  if (lowered.includes('timeout') || lowered.includes('timed out')) {
    return 'Scan timed out';
  }
  if (lowered.includes('unauthor') || lowered.includes('401') || lowered.includes('token') || lowered.includes('credential')) {
    return 'Authentication failed — reconnect the source';
  }
  if (lowered.includes('not found') || lowered.includes('404')) {
    return 'Repository not found or access revoked';
  }
  if (lowered.includes('forbid') || lowered.includes('403')) {
    return 'Access forbidden — check permissions';
  }
  if (message.length <= 96) {
    return message;
  }
  return `${message.slice(0, 93)}...`;
}

type ScanGroup = {
  reason: string;
  status: string;
  count: number;
  latest: RepoScanRecord;
  repos: string[];
};

function summarizeSuccessfulRepoScan(scan: RepoScanRecord): string {
  const parts = [formatCountLabel(scan.finding_count ?? 0, 'finding')];
  if (Number.isFinite(scan.files_scanned)) {
    parts.push(formatCountLabel(scan.files_scanned, 'file'));
  }
  return parts.join(' · ');
}

function groupRecentScans(scans: RepoScanRecord[]): ScanGroup[] {
  const groups: ScanGroup[] = [];
  scans.forEach((scan) => {
    const status = normalizeValue(scan.status).toLowerCase();
    const isFailure = status === 'failed' || status === 'canceled';
    const reason = isFailure
      ? summarizeScanFailure(scan)
      : status === 'succeeded' || status === 'completed'
        ? summarizeSuccessfulRepoScan(scan)
        : 'In progress';
    const repo = canonicalGitHubRepositoryDisplay(scan.repository) || scan.repository;
    const last = groups[groups.length - 1];
    // Only collapse consecutive failures with the same reason. Successful and
    // running scans are independent events even when their human-readable
    // summary happens to match, so we render each as its own row to preserve
    // accurate activity history.
    if (isFailure && last && last.status === status && last.reason === reason) {
      last.count += 1;
      if (!last.repos.includes(repo)) {
        last.repos.push(repo);
      }
      return;
    }
    groups.push({ reason, status, count: 1, latest: scan, repos: [repo] });
  });
  return groups;
}

const INVITE_SKIPPED_STORAGE_KEY = 'idt:overview:invite-skipped';
// Previous key that shipped briefly between the first two PR revisions. Kept so
// any user who already clicked Invite (and persisted the old flag) does not see
// the checklist regress.
const INVITE_LEGACY_STORAGE_KEY = 'idt:overview:invite-dismissed';

function inviteScopeKey(tenantID: string | undefined, workspaceID: string | undefined): string | null {
  if (!tenantID || !workspaceID) {
    return null;
  }
  return `${tenantID}:${workspaceID}`;
}

function readInviteSkipped(tenantID: string | undefined, workspaceID: string | undefined): boolean {
  if (typeof window === 'undefined') {
    return false;
  }
  const scope = inviteScopeKey(tenantID, workspaceID);
  if (!scope) {
    return false;
  }
  try {
    if (window.localStorage.getItem(`${INVITE_SKIPPED_STORAGE_KEY}:${scope}`) === '1') {
      return true;
    }
    // The earlier `idt:overview:invite-dismissed` key was also tenant-scoped in
    // the previous revision, so honoring it here is safe — it never crossed
    // tenants. The workspace-only legacy keys are intentionally NOT consulted
    // so a Skip in tenant A no longer leaks into tenant B that happens to
    // reuse the same workspace slug in the same browser profile.
    return window.localStorage.getItem(`${INVITE_LEGACY_STORAGE_KEY}:${scope}`) === '1';
  } catch {
    return false;
  }
}

function persistInviteSkipped(tenantID: string | undefined, workspaceID: string | undefined): void {
  if (typeof window === 'undefined') {
    return;
  }
  const scope = inviteScopeKey(tenantID, workspaceID);
  if (!scope) {
    return;
  }
  try {
    window.localStorage.setItem(`${INVITE_SKIPPED_STORAGE_KEY}:${scope}`, '1');
    // Drop the matching tenant-scoped legacy key on the same scope, but do NOT
    // touch the unscoped workspace-only keys that may belong to other tenants.
    window.localStorage.removeItem(`${INVITE_LEGACY_STORAGE_KEY}:${scope}`);
  } catch {
    // Storage failures are non-fatal.
  }
}

export function ProductOverviewPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);
  const { features: backendFeatures } = useBackendFeatures({ enabled: SHOULD_LOAD_CONNECTOR_BACKEND_FEATURES });
  const sourceAvailability = useMemo(() => buildSourceAvailability(backendFeatures), [backendFeatures]);
  const [showTour, setShowTour] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeProjects, setActiveProjects] = useState<ProjectRecord[]>([]);
  const [repoScans, setRepoScans] = useState<RepoScanRecord[]>([]);
  const [repoFindings, setRepoFindings] = useState<ApiFinding[]>([]);
  const [sourceConnectionRollups, setSourceConnectionRollups] = useState<OverviewConnectionRollups>(
    emptyOverviewConnectionRollups()
  );
  const [, setInviteSkipTick] = useState(0);
  const [connectorConfiguredFromOnboarding, setConnectorConfiguredFromOnboarding] = useState(false);
  const [onboardingConnectorProvider, setOnboardingConnectorProvider] = useState<SourceProvider | null>(null);

  useEffect(() => {
    const tenantID = scope?.tenantID;
    const workspaceID = scope?.workspaceID;
    if (!FEATURE_ONBOARDING_WIZARD || !tenantID || !workspaceID) {
      setShowTour(false);
      setConnectorConfiguredFromOnboarding(false);
      setOnboardingConnectorProvider(null);
      return;
    }
    let mounted = true;
    // Reset immediately when scope changes so stale onboarding data cannot
    // bleed connector-complete state into another workspace.
    setConnectorConfiguredFromOnboarding(false);
    setOnboardingConnectorProvider(null);
    const run = async () => {
      try {
        const response = await apiClient.getOnboardingState({ tenantID, workspaceID });
        if (!mounted) {
          return;
        }
        const state = response.state;
        const onboardingMatchesScope =
          normalizeValue(state.org_id ?? '') === tenantID &&
          normalizeValue(state.workspace_id ?? '') === workspaceID;
        setShowTour(
          onboardingMatchesScope && state.current_step === 'complete' && !state.dashboard_tour_dismissed_at
        );
        // Source-checklist signal: the user finished the connect step if either
        // a connector_id was persisted or onboarding progressed past 'connect'
        // without an explicit skip. This avoids the false negative where a
        // connector exists but no scan has run yet (which would otherwise leave
        // the checklist forever stuck at "Connect a source").
        const stepsPastConnect: ReadonlyArray<typeof state.current_step> = ['scan', 'invite', 'complete'];
        const reachedConnect =
          onboardingMatchesScope &&
          (Boolean(state.connector_id) ||
            (!state.connector_skipped && stepsPastConnect.includes(state.current_step)));
        setConnectorConfiguredFromOnboarding(reachedConnect);
        setOnboardingConnectorProvider(reachedConnect ? normalizeSourceProvider(state.connector_type) : null);
      } catch {
        if (mounted) {
          setShowTour(false);
          setConnectorConfiguredFromOnboarding(false);
          setOnboardingConnectorProvider(null);
        }
      }
    };
    void run();
    return () => {
      mounted = false;
    };
  }, [scope?.tenantID, scope?.workspaceID]);

  useEffect(() => {
    if (!scope) {
      setError('Choose a workspace before loading the overview.');
      setLoading(false);
      setSourceConnectionRollups(emptyOverviewConnectionRollups());
      return;
    }

    let mounted = true;
    const loadOverview = async () => {
      const requestSessionVersion = currentProductAuthSessionVersion();
      setLoading(true);
      setError('');
      try {
        const auth = buildProductAuthContext(scope);
        const activeProjectItems = await listOverviewProjects(scope.workspaceID, { include_archived: false }, auth);
        if (!mounted || !isCurrentProductAuthSessionVersion(requestSessionVersion)) {
          return;
        }
        primeEnvironmentScopeCache(scope, activeProjectItems);
        primeGitHubControlCenterDataCache(scope, activeProjectItems, sourceAvailability.github, auth);
        const [scanResponse, findingResponse, connectionRollups] = await Promise.all([
          apiClient.listRepoScans({ limit: OVERVIEW_SCAN_LIMIT }, auth),
          apiClient.listRepoFindings(
            {
              limit: OVERVIEW_FINDING_LIMIT,
              lifecycle_status: 'open',
              sort_by: 'severity',
              sort_order: 'desc'
            },
            auth
          ),
          loadOverviewConnectionRollups(scope, activeProjectItems, sourceAvailability, auth)
        ]);
        if (!mounted || !isCurrentProductAuthSessionVersion(requestSessionVersion)) {
          return;
        }
        setActiveProjects(
          activeProjectItems
            .slice()
            .sort((left, right) => new Date(right.updated_at).getTime() - new Date(left.updated_at).getTime())
        );
        setRepoScans(scanResponse.items);
        setRepoFindings(
          findingResponse.items
            .slice()
            .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))
        );
        setSourceConnectionRollups(connectionRollups);
      } catch (err) {
        if (!mounted || !isCurrentProductAuthSessionVersion(requestSessionVersion)) {
          return;
        }
        setError(formatAPIError(err, 'Unable to load workspace overview'));
        setSourceConnectionRollups(emptyOverviewConnectionRollups());
      } finally {
        if (mounted && isCurrentProductAuthSessionVersion(requestSessionVersion)) {
          setLoading(false);
        }
      }
    };

    void loadOverview();

    return () => {
      mounted = false;
    };
  }, [
    scope?.tenantID,
    scope?.workspaceID,
    scope?.projectID,
    sourceAvailability.aws.available,
    sourceAvailability.github.available,
    sourceAvailability.kubernetes.available
  ]);

  const dismissTour = async () => {
    setShowTour(false);
    try {
      await apiClient.updateOnboardingState({ dashboard_tour_dismissed: true });
    } catch {
      // The dashboard should remain usable even if tour dismissal cannot persist.
    }
  };

  const openFindings = repoFindings.filter((finding) => normalizeFindingStatus(finding.triage?.status) === 'open');
  const highPriorityFindings = openFindings.filter((finding) => {
    const severity = normalizeValue(finding.severity).toLowerCase();
    return severity === 'critical' || severity === 'high';
  });
  const agenticRiskFindings = openFindings.filter(isAgenticRiskFinding);
  const succeededScanCount = repoScans.filter((scan) => {
    const normalized = normalizeValue(scan.status).toLowerCase();
    return normalized === 'succeeded' || normalized === 'completed';
  }).length;
  const failedScanCount = repoScans.filter((scan) => {
    const normalized = normalizeValue(scan.status).toLowerCase();
    return normalized === 'failed' || normalized === 'canceled';
  }).length;
  const awsPath = scope ? buildScopedPath(scope, 'aws') : '/app';
  const awsConnectPath = scope ? buildScopedPath(scope, 'aws/connect') : '/app';
  const awsGovernancePath = scope ? buildScopedPath(scope, 'aws/governance') : '/app';
  const githubPath = scope ? buildScopedPath(scope, 'github') : '/app';
  const findingsPath = scope ? buildScopedPath(scope, 'github/findings') : '/app';
  const githubRemediationPath = scope ? buildScopedPath(scope, 'github/remediation') : '/app';
  const githubAgenticRiskPath = scope ? buildScopedPath(scope, 'github/agentic-risk') : '/app';
  const kubernetesPath = scope ? buildScopedPath(scope, 'kubernetes') : '/app';
  const kubernetesConnectPath = scope ? buildScopedPath(scope, 'kubernetes/connect') : '/app';
  const workspacesPath = scope ? buildScopedPath(scope, 'workspaces') : '/app';
  const connectSourcesProvider = DOMAIN_NAV_ORDER.find((provider) => sourceAvailability[provider].available) ?? 'aws';
  const connectSourcesPath = scope ? buildScopedPath(scope, `${connectSourcesProvider}/connect`) : '/app';
  const connectSourcesLabel = `Connect ${PRODUCT_DOMAIN_CONFIGS[connectSourcesProvider].navLabel}`;
  const hasAnySuccessfulScan = succeededScanCount > 0;
  const awsRollup = sourceConnectionRollups.aws;
  const kubernetesRollup = sourceConnectionRollups.kubernetes;
  // A source counts as connected when either (a) onboarding records a connector
  // configuration on the workspace, (b) any scan has run (you can't scan
  // without a connector), or (c) AWS/Kubernetes report an active environment
  // connector. This keeps non-GitHub customers out of duplicate setup prompts.
  const hasConnectedSource =
    connectorConfiguredFromOnboarding ||
    repoScans.length > 0 ||
    awsRollup.connectedCount > 0 ||
    kubernetesRollup.connectedCount > 0;
  const hasGitHubFindingEvidence = repoFindings.length > 0;
  const hasGitHubEvidence = repoScans.length > 0 || hasGitHubFindingEvidence;
  const hasGitHubConnectorEvidence = hasGitHubEvidence || onboardingConnectorProvider === 'github';
  const highPriorityCount = highPriorityFindings.length;
  const activeEnvironmentCount = activeProjects.length;
  const githubState: OverviewDomainState = !sourceAvailability.github.available && !hasGitHubConnectorEvidence
    ? 'shell'
    : failedScanCount > 0 && succeededScanCount === 0
      ? 'degraded'
      : succeededScanCount > 0 || hasGitHubFindingEvidence
        ? 'connected'
        : hasGitHubConnectorEvidence
        ? 'no_data'
        : 'not_connected';
  const awsState = overviewStateFromConnectionRollup(sourceAvailability.aws, awsRollup);
  const kubernetesState = overviewStateFromConnectionRollup(sourceAvailability.kubernetes, kubernetesRollup);
  const agenticRiskState: OverviewDomainState = !sourceAvailability.github.available && !hasGitHubConnectorEvidence
    ? 'shell'
    : agenticRiskFindings.length > 0
      ? 'degraded'
      : hasGitHubConnectorEvidence
        ? 'no_data'
        : 'not_connected';
  const domainPosture: Array<{
    id: string;
    label: string;
    provider: SourceProvider;
    state: OverviewDomainState;
    metric: string;
    to: string;
  }> = [
    {
      id: 'aws',
      label: 'AWS',
      provider: 'aws',
      state: awsState,
      metric: awsState === 'shell' ? 'Connector off' : overviewConnectionMetric(awsRollup, 'account'),
      to: awsState === 'not_connected' ? awsConnectPath : awsPath
    },
    {
      id: 'github',
      label: 'GitHub',
      provider: 'github',
      state: githubState,
      metric:
        githubState === 'shell'
          ? 'Connector off'
          : repoScans.length > 0
          ? formatCountLabel(repoScans.length, 'scan')
          : hasGitHubFindingEvidence
            ? formatCountLabel(repoFindings.length, 'finding')
            : 'No scans',
      to: highPriorityCount > 0 ? findingsPath : githubPath
    },
    {
      id: 'kubernetes',
      label: 'Kubernetes',
      provider: 'kubernetes',
      state: kubernetesState,
      metric: kubernetesState === 'shell' ? 'Connector off' : overviewConnectionMetric(kubernetesRollup, 'cluster'),
      to: kubernetesState === 'not_connected' ? kubernetesConnectPath : kubernetesPath
    },
    {
      id: 'agentic-risk',
      label: 'AI / Agentic Risk',
      provider: 'github',
      state: agenticRiskState,
      metric:
        agenticRiskState === 'shell'
          ? 'Connector off'
          : agenticRiskFindings.length > 0
            ? formatCountLabel(agenticRiskFindings.length, 'signal')
            : 'No signals',
      to: agenticRiskState === 'not_connected' ? githubPath : githubAgenticRiskPath
    }
  ];
  const activeDomainCount = domainPosture.filter((item) =>
    item.state === 'connected' || item.state === 'degraded' || item.state === 'no_data'
  ).length;
  const hasDomainDegradation = domainPosture.some((item) => item.state === 'degraded');
  const postureLabel = highPriorityCount > 0 || failedScanCount > 0 || hasDomainDegradation ? 'Action needed' : 'Stable';
  const coverageLabel = `${activeDomainCount}/${domainPosture.length}`;
  const evidenceLabel = repoScans.length > 0 ? formatCountLabel(repoScans.length, 'scan') : 'No scans';
  const nextActions: Array<{ id: string; label: string; to: string; tone?: 'danger' | 'warning' | 'neutral' }> = [];
  if (highPriorityCount > 0) {
    nextActions.push({
      id: 'priority',
      label: 'Review priority findings',
      to: findingsPath,
      tone: 'danger'
    });
  }
  if (!hasConnectedSource) {
    nextActions.push({
      id: 'connect',
      label: connectSourcesLabel,
      to: connectSourcesPath,
      tone: 'warning'
    });
  }
  if (failedScanCount > 0) {
    nextActions.push({
      id: 'scan',
      label: 'Review scan health',
      to: findingsPath,
      tone: 'warning'
    });
  }
  if (agenticRiskFindings.length > 0) {
    nextActions.push({
      id: 'agentic',
      label: 'Open agentic risk',
      to: githubAgenticRiskPath,
      tone: 'danger'
    });
  }
  nextActions.push(
    {
      id: 'remediation',
      label: 'Open remediation',
      to: githubRemediationPath,
      tone: highPriorityCount > 0 ? 'warning' : 'neutral'
    },
    {
      id: 'governance',
      label: 'Check governance',
      to: awsGovernancePath,
      tone: 'neutral'
    }
  );
  const visibleActions = nextActions.slice(0, 3);
  const onboardingChecklist: Array<{
    id: string;
    label: string;
    complete: boolean;
    actionLabel?: string;
    to?: string;
    skippable?: boolean;
  }> = [
    {
      id: 'domain',
      label: 'Choose your first domain',
      complete: activeEnvironmentCount > 0,
      actionLabel: activeEnvironmentCount > 0 ? undefined : 'Open',
      to: awsPath
    },
    {
      id: 'source',
      label: 'Connect a domain source',
      complete: hasConnectedSource,
      actionLabel: hasConnectedSource ? undefined : 'Connect',
      to: connectSourcesPath
    },
    {
      id: 'scan',
      label: 'Run your first scan',
      complete: hasAnySuccessfulScan,
      actionLabel: hasAnySuccessfulScan ? undefined : 'Run scan',
      to: connectSourcesPath
    },
    {
      id: 'invite',
      label: 'Invite a teammate',
      complete: readInviteSkipped(scope?.tenantID, scope?.workspaceID),
      actionLabel: readInviteSkipped(scope?.tenantID, scope?.workspaceID) ? undefined : 'Invite',
      to: workspacesPath,
      skippable: !readInviteSkipped(scope?.tenantID, scope?.workspaceID)
    }
  ];
  const shouldShowOnboarding = onboardingChecklist.some((item) => item.id !== 'invite' && !item.complete);

  if (loading) {
    return (
      <section className="idt-app-panel idt-overview-page" aria-busy="true" aria-live="polite">
        <header className="idt-overview-header">
          <h2>Overview</h2>
          <p>Loading command center.</p>
        </header>
      </section>
    );
  }

  if (error) {
    return (
      <section className="idt-app-panel idt-app-panel-error idt-overview-page" role="alert">
        <header className="idt-overview-header">
          <h2>Overview</h2>
          <p>{error}</p>
        </header>
      </section>
    );
  }

  const scanGroups = groupRecentScans(repoScans);

  return (
    <>
      <section className="idt-app-panel idt-overview-page">
        <header className="idt-overview-header">
          <h2>Overview</h2>
        </header>

        {shouldShowOnboarding ? (
          <section className="idt-overview-checklist" aria-label="Get started">
            <header>
              <h3>Get started</h3>
              <p>{onboardingChecklist.filter((item) => item.complete).length} of {onboardingChecklist.length} complete</p>
            </header>
            <ol>
              {onboardingChecklist.map((item) => (
                <li key={item.id} data-complete={item.complete ? 'true' : 'false'}>
                  <span className="idt-overview-checklist-mark" aria-hidden="true">
                    {item.complete ? (
                      <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="m3.5 8.5 3 3 6-7" />
                      </svg>
                    ) : null}
                  </span>
                  <div className="idt-overview-checklist-body">
                    <strong>{item.label}</strong>
                  </div>
                  <div className="idt-overview-checklist-actions">
                    {item.skippable && !item.complete ? (
                      <button
                        type="button"
                        className="idt-overview-checklist-skip"
                        onClick={() => {
                          persistInviteSkipped(scope?.tenantID, scope?.workspaceID);
                          setInviteSkipTick((value) => value + 1);
                        }}
                        aria-label={`Skip: ${item.label}`}
                      >
                        Skip
                      </button>
                    ) : null}
                    {item.actionLabel && item.to ? (
                      <Link className="idt-overview-checklist-action" to={item.to}>
                        {item.actionLabel}
                      </Link>
                    ) : null}
                  </div>
                </li>
              ))}
            </ol>
          </section>
        ) : null}

        <div className="idt-overview-metrics" aria-label="Command center summary">
          <article className={`idt-overview-metric-card${postureLabel === 'Action needed' ? ' is-attention' : ''}`}>
            <span className="idt-overview-metric-label">Posture</span>
            <strong>{postureLabel}</strong>
          </article>
          <article className="idt-overview-metric-card">
            <span className="idt-overview-metric-label">High priority</span>
            <strong>{highPriorityCount}</strong>
          </article>
          <article className="idt-overview-metric-card">
            <span className="idt-overview-metric-label">Coverage</span>
            <strong>{coverageLabel}</strong>
          </article>
          <article className="idt-overview-metric-card">
            <span className="idt-overview-metric-label">Evidence</span>
            <strong>{evidenceLabel}</strong>
          </article>
        </div>

        <section className="idt-overview-domain-strip" aria-label="Domain posture">
          {domainPosture.map((item) => (
            <Link key={item.id} to={item.to} className={`idt-overview-domain-card is-${item.state}`}>
              <div className="idt-overview-domain-card-top">
                <SourceLogoMark provider={item.provider} className="is-row" decorative />
                <span className={`idt-overview-state-pill is-${item.state}`}>{OVERVIEW_DOMAIN_STATE_LABELS[item.state]}</span>
              </div>
              <strong>{item.label}</strong>
              <span>{item.metric}</span>
            </Link>
          ))}
        </section>

        <div className="idt-overview-grid">
          <section className="idt-overview-card">
            <div className="idt-overview-card-header">
              <h3>Highest priority</h3>
              <Link className="idt-premium-text-link" to={findingsPath}>View GitHub findings</Link>
            </div>
            {highPriorityFindings.length > 0 ? (
              <div className="idt-overview-list">
                {highPriorityFindings.slice(0, OVERVIEW_RISK_DISPLAY_LIMIT).map((finding) => {
                  const repository = canonicalGitHubRepositoryDisplay(finding.repository ?? '');
                  return (
                    <article key={`${finding.scan_id}:${finding.id}`} className="idt-overview-risk-row">
                      <SourceLogoMark provider="github" className="is-row" />
                      <div className="idt-overview-row-copy">
                        <div>
                          <strong>{finding.title}</strong>
                          <p>
                            {repository || 'Repository unavailable'} · {repoFindingLocationLabel(finding)}
                          </p>
                        </div>
                        <span className={repoFindingSeverityClass(finding.severity)}>{formatTokenLabel(finding.severity)}</span>
                      </div>
                    </article>
                  );
                })}
              </div>
            ) : (
              <AppShellEmptyState
                title="No priority findings"
                body="Critical and high findings appear here."
                action={hasAnySuccessfulScan ? undefined : { label: 'Run a scan', to: connectSourcesPath }}
              />
            )}
          </section>

          <section className="idt-overview-card">
            <div className="idt-overview-card-header">
              <h3>Next actions</h3>
              <Link className="idt-premium-text-link" to={githubRemediationPath}>Open remediation</Link>
            </div>
            <div className="idt-overview-action-list">
              {visibleActions.map((item) => (
                <Link key={item.id} to={item.to} className={`idt-overview-action-row is-${item.tone ?? 'neutral'}`}>
                  <span>
                    <strong>{item.label}</strong>
                  </span>
                  <ChevronRight size={16} aria-hidden="true" />
                </Link>
              ))}
            </div>
          </section>
        </div>

        <div className="idt-overview-grid idt-overview-grid-single">
          <section className="idt-overview-card">
            <div className="idt-overview-card-header">
              <h3>Recent activity</h3>
              <Link className="idt-premium-text-link" to={findingsPath}>View GitHub findings</Link>
            </div>
            {scanGroups.length > 0 ? (
              <div className="idt-overview-list idt-overview-activity-list">
                {scanGroups.map((group) => {
                  const isFailure = group.status === 'failed' || group.status === 'canceled';
                  const isActive = isActiveScanStatus(group.status);
                  const repoLabel =
                    group.repos.length === 1
                      ? group.repos[0]
                      : `${group.repos[0]} +${group.repos.length - 1} more`;
                  return (
                    <article
                      key={`${group.status}-${group.reason}-${group.latest.id}`}
                      className={`idt-overview-scan-row${isFailure ? ' is-failure' : isActive ? ' is-active' : ' is-success'}`}
                    >
                      <SourceLogoMark provider="github" className="is-row" />
                      <div className="idt-overview-row-copy">
                        <div>
                          <strong>{repoLabel}</strong>
                          <p>{group.reason} · {formatRelativeTime(group.latest.started_at)}</p>
                        </div>
                        <span className={`idt-overview-scan-badge is-${isFailure ? 'error' : isActive ? 'warning' : 'success'}`}>
                          {isFailure ? 'Failed' : isActive ? 'Running' : 'Succeeded'}
                        </span>
                      </div>
                    </article>
                  );
                })}
              </div>
            ) : (
              <AppShellEmptyState
                title="No activity"
                body="Scans and connector events appear here."
                action={{ label: 'Connect a source', to: connectSourcesPath }}
              />
            )}
          </section>
        </div>
      </section>
      {showTour ? (
        <aside className="idt-onboarding-tour" aria-label="Onboarding tour">
          <div>
            <p className="idt-app-kicker">Next best actions</p>
            <h2>Turn setup into operating rhythm</h2>
          </div>
          <ol>
            <li>Review connector health</li>
            <li>Open the latest scan</li>
            <li>Triage the first finding</li>
            <li>Invite a teammate</li>
          </ol>
          <button type="button" className="idt-btn idt-btn-primary" onClick={dismissTour}>
            Got it
          </button>
        </aside>
      ) : null}
    </>
  );
}

export function ProductExecutiveReportPage() {
  const { me, loading: sessionLoading, error: sessionError, unauthenticated } = useMe();
  const [report, setReport] = useState<ExecutiveReport | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [reportError, setReportError] = useState('');

  useEffect(() => {
    if (!me?.org_id || !me.workspace_id) {
      return;
    }

    let mounted = true;
    const loadReport = async () => {
      setLoadingReport(true);
      setReportError('');
      try {
        const response = await apiClient.getExecutiveReport({
          tenantID: me.org_id,
          workspaceID: me.workspace_id
        });
        if (mounted) {
          setReport(response);
        }
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        if (requestError instanceof ApiError && requestError.status === 403) {
          setReportError('You do not have access to the executive report for this organization.');
          return;
        }
        const message = requestError instanceof Error ? requestError.message : 'Unable to load executive report.';
        setReportError(message);
      } finally {
        if (mounted) {
          setLoadingReport(false);
        }
      }
    };

    void loadReport();

    return () => {
      mounted = false;
    };
  }, [me?.org_id, me?.workspace_id]);

  if (sessionLoading || loadingReport) {
    return <AppShellLoading message="Loading executive report" />;
  }

  if (unauthenticated) {
    return <Navigate to="/signin?return_to=%2Freports%2Fexecutive" replace />;
  }

  if (sessionError || reportError) {
    return (
      <section className="idt-app-shell-screen idt-executive-report-shell" role="alert">
        <article className="idt-app-panel idt-app-panel-error">
          <p className="idt-app-kicker">Executive report</p>
          <h1>Unable to load executive report</h1>
          <p>{sessionError || reportError}</p>
          <Link className="idt-btn idt-btn-ghost" to="/app">
            Return to app
          </Link>
        </article>
      </section>
    );
  }

  if (!me?.org_id || !me.workspace_id) {
    return (
      <section className="idt-app-shell-screen idt-executive-report-shell">
        <article className="idt-app-panel">
          <p className="idt-app-kicker">Executive report</p>
          <h1>Organization context required</h1>
          <p>Your account needs an active organization and workspace before the executive report can be rendered.</p>
        </article>
      </section>
    );
  }

  if (!report) {
    return <AppShellLoading message="Preparing executive report" />;
  }

  const highPriorityFindings = countHighPriorityExecutiveFindings(report);
  const weekDelta = report.week_over_week.delta;
  const topFindingTypes = report.top_finding_types ?? [];
  const severityRows = EXECUTIVE_REPORT_SEVERITY_ORDER.map((severity) => ({
    severity,
    count: report.open_by_severity[severity] ?? 0
  }));
  const appPath = buildCurrentUserAppPath(me);

  const totalOpen = report.total_open_findings;
  const sharePct = (count: number) => (totalOpen > 0 ? Math.round((count / totalOpen) * 100) : 0);
  const visibleSeverity = severityRows.filter((row) => row.count > 0);
  const windowLabel = `${formatShortDateLabel(report.window_start)} – ${formatShortDateLabel(report.window_end)}`;

  return (
    <section className="idt-app-shell-screen idt-executive-report-shell">
      <article className="idt-exec-report">
        <header className="idt-exec-report__header">
          <div className="idt-exec-report__title">
            <p className="idt-exec-report__eyebrow">Executive report</p>
            <h1>Risk posture summary</h1>
            <p className="idt-exec-report__meta">
              <span>
                Organization <strong>{report.organization_id}</strong>
              </span>
              <span aria-hidden="true">·</span>
              <span>{windowLabel}</span>
              <span aria-hidden="true">·</span>
              <span>Generated {formatDateLabel(report.generated_at)}</span>
            </p>
          </div>
          <div className="idt-exec-report__actions">
            <Link className="idt-btn idt-btn-ghost" to={appPath}>
              Back to workspace
            </Link>
            <button
              className="idt-btn idt-btn-primary idt-exec-report__download"
              type="button"
              onClick={() => downloadExecutiveReport(report, highPriorityFindings)}
            >
              <svg
                aria-hidden="true"
                focusable="false"
                width="14"
                height="14"
                viewBox="0 0 16 16"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M8 2v8.5" />
                <path d="M4.5 7L8 10.5 11.5 7" />
                <path d="M2.5 13.5h11" />
              </svg>
              Download report
            </button>
          </div>
        </header>

        <dl className="idt-exec-kpis" aria-label="Executive report summary">
          <div className="idt-exec-kpi">
            <dt>Open findings</dt>
            <dd>{totalOpen.toLocaleString()}</dd>
            <p>{highPriorityFindings} critical or high</p>
          </div>
          <div className="idt-exec-kpi">
            <dt>Net change · 7 days</dt>
            <dd>{weekDelta > 0 ? `+${weekDelta}` : weekDelta}</dd>
            <p>
              {report.week_over_week.current_count} new · {report.week_over_week.previous_count} previous
            </p>
          </div>
          <div className="idt-exec-kpi">
            <dt>Mean time to resolve</dt>
            <dd>{formatExecutiveDuration(report.mean_time_to_resolve?.seconds)}</dd>
            <p>
              {report.mean_time_to_resolve
                ? `${report.mean_time_to_resolve.resolved_count} resolved samples`
                : 'Awaiting reliable resolution data'}
            </p>
          </div>
          <div className="idt-exec-kpi">
            <dt>Top risk type</dt>
            <dd>{topFindingTypes[0] ? formatTokenLabel(topFindingTypes[0].type) : '—'}</dd>
            <p>
              {topFindingTypes[0]
                ? `${topFindingTypes[0].count} of ${totalOpen} open`
                : 'No open findings in scope'}
            </p>
          </div>
        </dl>

        {totalOpen === 0 ? (
          <AppShellEmptyState
            title="No open findings in this report window"
            body="The current organization report has no open findings to prioritize."
          />
        ) : (
          <>
            <section className="idt-exec-section">
              <h2>Severity composition</h2>
              <p className="idt-exec-section__lede">
                How the {totalOpen.toLocaleString()} open findings break down today.
              </p>
              <div
                className="idt-exec-stack"
                role="img"
                aria-label={`Open findings by severity: ${severityRows
                  .filter((row) => row.count > 0)
                  .map((row) => `${formatTokenLabel(row.severity)} ${row.count}`)
                  .join(', ')}`}
              >
                {visibleSeverity.map((row) => (
                  <span
                    key={row.severity}
                    className={`idt-exec-stack__seg is-${row.severity}`}
                    style={{ width: `${sharePct(row.count)}%` }}
                  />
                ))}
              </div>
              <ul className="idt-exec-legend">
                {severityRows.map((row) => (
                  <li key={row.severity} className={row.count === 0 ? 'is-empty' : undefined}>
                    <span className={`idt-exec-dot is-${row.severity}`} aria-hidden="true" />
                    <span className="idt-exec-legend__label">{formatTokenLabel(row.severity)}</span>
                    <span className="idt-exec-legend__count">{row.count}</span>
                    <span className="idt-exec-legend__share">{sharePct(row.count)}%</span>
                  </li>
                ))}
              </ul>
            </section>

            <section className="idt-exec-section">
              <h2>Top finding types</h2>
              <p className="idt-exec-section__lede">Themes driving open risk this window.</p>
              {topFindingTypes.length > 0 ? (
                <ol className="idt-exec-rank">
                  {topFindingTypes.map((item, index) => (
                    <li key={item.type}>
                      <span className="idt-exec-rank__index">{String(index + 1).padStart(2, '0')}</span>
                      <span className="idt-exec-rank__label">{formatTokenLabel(item.type)}</span>
                      <span className="idt-exec-rank__share">{sharePct(item.count)}%</span>
                      <span className="idt-exec-rank__count">{item.count}</span>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="idt-exec-section__empty">
                  Finding type breakdown will appear once findings are present.
                </p>
              )}
            </section>

            <section className="idt-exec-section">
              <h2>Notes for leadership</h2>
              <ul className="idt-exec-notes">
                <li>
                  {weekDelta > 0
                    ? `Open finding volume grew by ${weekDelta} compared with the prior 7-day window.`
                    : weekDelta < 0
                      ? `Open finding volume fell by ${Math.abs(weekDelta)} compared with the prior 7-day window.`
                      : 'Open finding volume held steady against the prior 7-day window.'}
                </li>
                <li>
                  {report.mean_time_to_resolve
                    ? `Mean time to resolve is ${formatExecutiveDuration(report.mean_time_to_resolve.seconds)} across ${report.mean_time_to_resolve.resolved_count} resolved findings with reliable timestamps.`
                    : 'Mean time to resolve will be reported once resolved findings accumulate reliable timestamps.'}
                </li>
                {topFindingTypes[0] ? (
                  <li>
                    Largest theme is <strong>{formatTokenLabel(topFindingTypes[0].type)}</strong>, representing{' '}
                    {sharePct(topFindingTypes[0].count)}% of open findings.
                  </li>
                ) : null}
              </ul>
            </section>
          </>
        )}

        <footer className="idt-exec-report__footer">
          <p>
            Scope: organization {report.organization_id}, window {windowLabel}.
          </p>
          <p>Generated by Identrail on {formatDateLabel(report.generated_at)}.</p>
        </footer>
      </article>
    </section>
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
    return (
      <AppRouteLoadingState
        title="Preparing workspace access"
        body="Refreshing member access details for this workspace."
      />
    );
  }

  const availableWorkspaces = whoAmI?.workspaces ?? [];

  return (
    <section className="idt-app-panel idt-workspace-admin">
      <header className="idt-workspace-admin-header">
        <div>
          <h2>Members</h2>
          <p>Invite teammates, set roles, and keep workspace access current.</p>
        </div>
      </header>

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
          <p>Admins</p>
        </article>
      </div>

      <div className="idt-workspace-admin-grid">
        <article className="idt-workspace-card">
          <header className="idt-workspace-card-header">
            <div>
              <h3>Workspace</h3>
              <p>Change the workspace context for this session.</p>
            </div>
          </header>
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

        <article className="idt-workspace-card">
          <header className="idt-workspace-card-header">
            <div>
              <h3>Invite member</h3>
              <p>Set the initial role and status before access is granted.</p>
            </div>
          </header>
          <form className="idt-app-form idt-workspace-invite-form" onSubmit={handleInviteMember}>
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
              {inviting ? 'Saving...' : 'Send invite'}
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
                    <details className="idt-workspace-member-details">
                      <summary>Member details</summary>
                      <dl>
                        <div>
                          <dt>Member ID</dt>
                          <dd>{member.member_id}</dd>
                        </div>
                      </dl>
                    </details>
                  </td>
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
  const location = useLocation();
  const scope = resolveScopeFromParams(params);
  const requestedSource = useMemo(
    () => normalizeSourceProvider(new URLSearchParams(location.search).get('source')),
    [location.search]
  );

  const [projects, setProjects] = useState<ProjectRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [draftName, setDraftName] = useState('');
  const [draftDescription, setDraftDescription] = useState('');

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
        setError(loadError instanceof Error ? loadError.message : 'Unable to load workspace environments.');
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
    return (
      <AppRouteLoadingState
        title="Preparing environments"
        body="Keeping workspace scope ready while environment boundaries refresh."
      />
    );
  }

  const handleCreateProject = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const name = normalizeValue(draftName);
    const description = normalizeValue(draftDescription);

    if (!name) {
      setError('Environment name is required.');
      return;
    }

    setSaving(true);
    setError('');

    try {
      const auth = buildProductAuthContext(scope);
      const knownProjects = await listOverviewProjects(scope.workspaceID, { include_archived: true }, auth);
      const projectID = uniqueEnvironmentToken(name, knownProjects);
      const slug = projectID;
      if (!projectID) {
        setError('Enter a readable environment name.');
        return;
      }
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
      setDraftDescription('');
      navigate(appendSourceQuery(buildProjectPath(scope, response.project.project_id), requestedSource));
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Unable to save environment.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="idt-app-panel idt-projects-page">
      <div className="idt-projects-header">
        <div>
          <p className="idt-app-kicker">Workspace scope</p>
          <h2>Environments</h2>
          <p>Choose the operating boundary for repository, workflow, cloud, and cluster identity signals.</p>
        </div>
        <div className="idt-inline-actions">
          <Link className="idt-btn idt-btn-ghost" to={buildScopedPath(scope)}>
            Back to overview
          </Link>
        </div>
      </div>

      <div className="idt-projects-summary">
        <article className="is-light-surface">
          <div className="idt-overview-metric-top">
            <span>{projects.length}</span>
          </div>
          <p>Total environments</p>
        </article>
        <article>
          <div className="idt-overview-metric-top">
            <span>{activeProjectCount}</span>
          </div>
          <p>Active environments</p>
        </article>
        <article>
          <div className="idt-overview-metric-top">
            <span>{latestProject ? formatConnectionTime(latestProject.updated_at) : 'No activity yet'}</span>
          </div>
          <p>Last updated</p>
        </article>
      </div>

      {error ? <div className="idt-app-alert idt-app-alert-error">{error}</div> : null}

      <div className="idt-projects-grid">
        <article className="idt-projects-list">
          <div className="idt-projects-section-header">
            <div>
              <h3>Environment list</h3>
              <p>
                {archivedProjectCount > 0
                  ? `${activeProjectCount} active, ${archivedProjectCount} archived.`
                  : 'Open an environment to manage source connections and scans.'}
              </p>
            </div>
          </div>

          {projects.length === 0 ? (
            <AppShellEmptyState
              title="No environments yet"
              body="Create the first workspace boundary for this source."
            />
          ) : (
            <div className="idt-project-card-list">
              {projects.map((project) => {
                const archived = Boolean(normalizeValue(project.archived_at ?? ''));
                return (
                  <article key={project.project_id} className="idt-project-card">
                    <div className="idt-project-card-header">
                      <div>
                        <div className="idt-project-card-title">
                          <h4>{project.name}</h4>
                        </div>
                        <p>{project.description || 'Scope source connections, scans, and findings for this environment.'}</p>
                      </div>
                      <span
                        className={`idt-source-status-pill ${archived ? 'is-warning' : 'is-success'}`}
                      >
                        {archived ? 'Archived' : 'Active'}
                      </span>
                    </div>

                    <details className="idt-project-card-details">
                      <summary>Environment details</summary>
                      <dl className="idt-project-card-meta">
                        <div>
                          <dt>Internal key</dt>
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
                    </details>

                    <div className="idt-inline-actions">
                      <Link
                        className="idt-btn idt-btn-primary"
                        to={appendSourceQuery(buildProjectPath(scope, project.project_id), requestedSource)}
                      >
                        Open environment
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
              <h3>New environment</h3>
              <p>Name the boundary once. Identrail keeps the internal key behind the scenes.</p>
            </div>
          </div>

          <form className="idt-app-form" onSubmit={handleCreateProject}>
            <label>
              Environment name
              <input
                value={draftName}
                onChange={(event) => setDraftName(event.target.value)}
                placeholder="Production platform"
                required
              />
            </label>
            <label>
              Description
              <textarea
                value={draftDescription}
                onChange={(event) => setDraftDescription(event.target.value)}
                placeholder="Identity boundary for the production control plane and its delivery repositories."
              />
            </label>
            <button className="idt-btn idt-btn-primary" type="submit" disabled={saving}>
              {saving ? 'Creating environment...' : 'Create environment'}
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
  const location = useLocation();
  const { features: backendFeatures, loading: backendFeaturesLoading } = useBackendFeatures({
    enabled: SHOULD_LOAD_CONNECTOR_BACKEND_FEATURES
  });
  const refreshSequenceRef = useRef(0);
  const repoScanSubmitSequenceRef = useRef(0);
  const githubPostureRequestRef = useRef(0);
  const sourceAvailability = useMemo(() => buildSourceAvailability(backendFeatures), [backendFeatures]);
  const selectedSourceFromConnect = useMemo(() => {
    return normalizeSourceProvider(new URLSearchParams(location.search).get('source'));
  }, [location.search]);
  const sourceScope = useMemo(() => {
    if (!selectedSourceFromConnect || !sourceAvailability[selectedSourceFromConnect]?.visible) {
      return null;
    }
    return selectedSourceFromConnect;
  }, [selectedSourceFromConnect, sourceAvailability]);
  const sourceOrder = useMemo(
    () => (sourceScope ? [sourceScope] : SOURCE_ORDER.filter((provider) => sourceAvailability[provider].visible)),
    [sourceAvailability, sourceScope]
  );
  const actionableSourceOrder = useMemo(
    () => sourceOrder.filter((provider) => sourceAvailability[provider].available),
    [sourceAvailability, sourceOrder]
  );

  const [connections, setConnections] = useState<SourceConnectionMap>({});
  const [sourceErrors, setSourceErrors] = useState<Partial<Record<SourceProvider, string>>>({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [submitting, setSubmitting] = useState<SourceProvider | ''>('');
  const [selectedSource, setSelectedSource] = useState<SourceProvider>(
    selectedSourceFromConnect ?? SOURCE_ORDER[0] ?? 'aws'
  );
  const [successMessage, setSuccessMessage] = useState('');
  const [githubStart, setGitHubStart] = useState<GitHubConnectorStartResponse | null>(null);
  const [githubAppForm, setGitHubAppForm] = useState({
    displayName: 'Identrail'
  });
  const [githubPATForm, setGitHubPATForm] = useState({
    displayName: 'GitHub Enterprise',
    baseURL: '',
    token: '',
    repositories: ''
  });
  const [repoScanForm, setRepoScanForm] = useState({
    repository: '',
    historyLimit: '',
    maxFindings: ''
  });
  const [recentRepoScans, setRecentRepoScans] = useState<RepoScanRecord[]>([]);
  const [repoScanSubmitting, setRepoScanSubmitting] = useState(false);
  const [repoScanCancelingID, setRepoScanCancelingID] = useState('');
  const [repoScanError, setRepoScanError] = useState('');
  const [githubPosture, setGitHubPosture] = useState<GitHubRepositoryPosture | null>(null);
  const [githubOrganizationPosture, setGitHubOrganizationPosture] = useState<GitHubOrganizationPosture | null>(null);
  const [githubPostureLoading, setGitHubPostureLoading] = useState(false);
  const [githubPostureError, setGitHubPostureError] = useState('');
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
  const [awsPermissionTiers, setAWSPermissionTiers] = useState<AWSCapabilityPermissionTier[]>([]);
  const [awsPreviewOpen, setAWSPreviewOpen] = useState(false);
  const [kubernetesForm, setKubernetesForm] = useState({
    displayName: '',
    context: '',
    mode: 'agent' as 'agent' | 'kubeconfig',
    apiURL: '',
    kubeconfig: ''
  });
  const [kubernetesEnrollment, setKubernetesEnrollment] = useState<KubernetesConnectorStartResponse | null>(null);
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
  const githubSelectedRepositories = useMemo(
    () => uniqueGitHubRepositories(connections.github?.selected_repositories ?? []),
    [connections.github?.selected_repositories]
  );
  const githubSelectedRepositoriesKey = githubSelectedRepositories.join('\n');
  const githubSelectedRepositoryKeys = useMemo(
    () => new Set(githubSelectedRepositories.map((repository) => repository.toLowerCase())),
    [githubSelectedRepositories]
  );
  const githubRecentRepoScans = useMemo(() => {
    if (githubSelectedRepositoryKeys.size === 0) {
      return recentRepoScans;
    }
    return recentRepoScans.filter((scan) =>
      githubSelectedRepositoryKeys.has(canonicalGitHubRepositoryDisplay(scan.repository).toLowerCase())
    );
  }, [githubSelectedRepositoryKeys, recentRepoScans]);
  const repoScanRepository = normalizeValue(repoScanForm.repository);
  const effectiveRepoScanRepository = repoScanRepository || githubSelectedRepositories[0] || '';
  const effectiveRepoScanRepositoryKey = canonicalGitHubRepositoryDisplay(effectiveRepoScanRepository).toLowerCase();
  const githubPostureSecureCount = countGitHubPostureChecks(githubPosture, 'secure');
  const githubPostureAttentionCount = countGitHubPostureChecks(githubPosture, 'insecure');
  const githubPostureLimitedCount = countGitHubPostureChecks(githubPosture, 'permission_limited');
  const githubPostureUnavailableCount = countGitHubPostureChecks(githubPosture, 'unavailable');
  const githubPostureUnsupportedCount = countGitHubPostureChecks(githubPosture, 'unsupported');
  const githubPostureUnknownCount = countGitHubPostureChecks(githubPosture, 'unknown');
  const githubOrganizationPostureSecureCount = countGitHubPostureChecks(githubOrganizationPosture, 'secure');
  const githubOrganizationPostureAttentionCount = countGitHubPostureChecks(githubOrganizationPosture, 'insecure');
  const githubOrganizationPostureLimitedCount = countGitHubPostureChecks(githubOrganizationPosture, 'permission_limited');
  const githubOrganizationPostureUnavailableCount = countGitHubPostureChecks(githubOrganizationPosture, 'unavailable');
  const githubOrganizationPostureUnsupportedCount = countGitHubPostureChecks(githubOrganizationPosture, 'unsupported');
  const githubOrganizationPostureUnknownCount = countGitHubPostureChecks(githubOrganizationPosture, 'unknown');
  const githubPostureAttentionChecks = useMemo(
    () => githubPosture?.checks.filter((check) => check.state !== 'secure') ?? [],
    [githubPosture]
  );
  const githubPostureDetailChecks =
    githubPostureAttentionChecks.length > 0 ? githubPostureAttentionChecks : (githubPosture?.checks ?? []);
  const githubPostureNeedsAttentionCount =
    githubPostureAttentionCount +
    githubPostureLimitedCount +
    githubPostureUnavailableCount +
    githubPostureUnsupportedCount +
    githubPostureUnknownCount;
  const githubOrganizationPostureAttentionChecks = useMemo(
    () => githubOrganizationPosture?.checks.filter((check) => check.state !== 'secure') ?? [],
    [githubOrganizationPosture]
  );
  const githubOrganizationPostureDetailChecks =
    githubOrganizationPostureAttentionChecks.length > 0
      ? githubOrganizationPostureAttentionChecks
      : (githubOrganizationPosture?.checks ?? []);
  const githubHasActiveRepoScan = githubRecentRepoScans.some((scan) => isActiveScanStatus(scan.status));
  const githubHasActiveSelectedRepoScan =
    effectiveRepoScanRepositoryKey !== '' &&
    githubRecentRepoScans.some(
      (scan) =>
        isActiveScanStatus(scan.status) &&
        canonicalGitHubRepositoryDisplay(scan.repository).toLowerCase() === effectiveRepoScanRepositoryKey
    );
  const repoScanFindingsPath = scope ? buildScopedPath(scope, 'github/findings') : '/app';

  const nextRequestSequence = () => {
    const nextSequence = refreshSequenceRef.current + 1;
    refreshSequenceRef.current = nextSequence;
    return nextSequence;
  };

  const isStaleRequestSequence = (sequence: number) => refreshSequenceRef.current !== sequence;

  const nextRepoScanSubmitSequence = () => {
    const nextSequence = repoScanSubmitSequenceRef.current + 1;
    repoScanSubmitSequenceRef.current = nextSequence;
    return nextSequence;
  };

  const isLatestRepoScanSubmitSequence = (sequence: number) => repoScanSubmitSequenceRef.current === sequence;

  const refreshConnections = async (quiet = false) => {
    const refreshSequence = nextRequestSequence();

    if (backendFeaturesLoading) {
      setLoading(true);
      setRefreshing(false);
      return;
    }

    if (!scope || !projectID) {
      setConnections({});
      setSourceErrors({});
      setRecentRepoScans([]);
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
      sourceAvailability.github.available
        ? apiClient.getGitHubConnectorStatus(scope.workspaceID, projectID, auth)
        : Promise.resolve({ connection: undefined as unknown as GitHubConnectionStatus }),
      apiClient.getAWSProjectConnection(scope.workspaceID, projectID, auth),
      sourceAvailability.kubernetes.available
        ? apiClient.getKubernetesConnectorStatus(scope.workspaceID, projectID, auth)
        : Promise.resolve({ connection: undefined as unknown as KubernetesConnectionStatus }),
      apiClient.listProjectScanPolicies(
        scope.workspaceID,
        projectID,
        {
          limit: 50,
          sort_by: 'updated_at',
          sort_order: 'desc'
        },
        auth
      ),
      apiClient.listRepoScans({ limit: 8 }, auth)
    ]);

    if (isStaleRequestSequence(refreshSequence)) {
      return;
    }

    const nextConnections: SourceConnectionMap = {};
    const nextErrors: Partial<Record<SourceProvider, string>> = {};
    const [githubResult, awsResult, kubernetesResult, scanPolicyResult, repoScanResult] = results;

    if (githubResult.status === 'fulfilled' && githubResult.value.connection) {
      nextConnections.github = githubResult.value.connection;
    } else {
      if (sourceAvailability.github.available) {
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
    if (kubernetesResult.status === 'fulfilled' && kubernetesResult.value.connection) {
      nextConnections.kubernetes = kubernetesResult.value.connection;
    } else {
      if (sourceAvailability.kubernetes.available) {
        nextErrors.kubernetes =
          kubernetesResult.status === 'rejected' && kubernetesResult.reason instanceof Error
            ? kubernetesResult.reason.message
            : `Unable to load ${SOURCE_PROFILES.kubernetes.name} status.`;
      }
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
          : 'Unable to load scan policies for this source.'
      );
      setScanPolicies([]);
    }
    if (repoScanResult?.status === 'fulfilled') {
      setRecentRepoScans(repoScanResult.value.items ?? []);
    }
    setLoading(false);
    setRefreshing(false);
  };

  const refreshRecentRepoScans = async (targetScope: ProductSession, mode: 'silent' | 'interactive' = 'silent') => {
    const requestSequence = refreshSequenceRef.current;
    try {
      const auth = buildProductAuthContext(targetScope);
      const response = await apiClient.listRepoScans({ limit: 8 }, auth);
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setRecentRepoScans(response.items ?? []);
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      if (mode === 'interactive') {
        setRepoScanError(formatAPIError(error, 'Unable to refresh recent repository scans.'));
      }
    }
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
    setRepoScanForm({ repository: '', historyLimit: '', maxFindings: '' });
    setRecentRepoScans([]);
    repoScanSubmitSequenceRef.current += 1;
    githubPostureRequestRef.current += 1;
    setRepoScanSubmitting(false);
    setRepoScanCancelingID('');
    setRepoScanError('');
    setGitHubPosture(null);
    setGitHubPostureLoading(false);
    setGitHubPostureError('');
    setAWSCloudFormationStart(null);
    setAWSPermissionPreview([]);
    setAWSPermissionTiers([]);
    setAWSPreviewOpen(false);
    setAWSForm((current) => ({ ...current, externalID: '' }));
    if (backendFeaturesLoading) {
      setLoading(true);
      return undefined;
    }
    void refreshConnections(false);

    return () => {
      refreshSequenceRef.current += 1;
    };
  }, [
    scope?.tenantID,
    scope?.workspaceID,
    projectID,
    backendFeaturesLoading,
    sourceAvailability.github.available,
    sourceAvailability.kubernetes.available
  ]);

  useEffect(() => {
    if (backendFeaturesLoading || sourceScope || sourceAvailability[selectedSource]?.available) {
      return;
    }
    setSelectedSource(actionableSourceOrder[0] ?? 'aws');
  }, [actionableSourceOrder, backendFeaturesLoading, selectedSource, sourceAvailability, sourceScope]);

  useEffect(() => {
    if (!selectedSourceFromConnect || backendFeaturesLoading) {
      return;
    }

    if (sourceAvailability[selectedSourceFromConnect]?.visible) {
      setSelectedSource(selectedSourceFromConnect);
    }
  }, [backendFeaturesLoading, selectedSourceFromConnect, sourceAvailability]);

  useEffect(() => {
    if (!connections.github?.connected) {
      return;
    }
    setRepoScanForm((current) => {
      const currentRepository = canonicalGitHubRepositoryDisplay(current.repository);
      if (
        currentRepository &&
        (githubSelectedRepositories.length === 0 ||
          githubSelectedRepositories.some((repository) => repository.toLowerCase() === currentRepository.toLowerCase()))
      ) {
        return current;
      }
      return { ...current, repository: githubSelectedRepositories[0] ?? current.repository };
    });
  }, [connections.github?.connected, githubSelectedRepositories, githubSelectedRepositoriesKey]);

  useEffect(() => {
    const connection = connections.github;
    const repository = canonicalGitHubRepositoryDisplay(effectiveRepoScanRepository);
    const requestID = githubPostureRequestRef.current + 1;
    githubPostureRequestRef.current = requestID;

    if (
      !scope ||
      !projectID ||
      selectedSource !== 'github' ||
      !connection?.connected ||
      connection.provider !== 'github_app' ||
      !connection.connector_id ||
      !repository
    ) {
      setGitHubPosture(null);
      setGitHubPostureLoading(false);
      setGitHubPostureError('');
      setGitHubOrganizationPosture(null);
      return undefined;
    }

    setGitHubPostureLoading(true);
    setGitHubPostureError('');
    setGitHubPosture(null);
    setGitHubOrganizationPosture(null);
    void apiClient
      .getGitHubConnectorRepositoryPosture(
        connection.connector_id,
        scope.workspaceID,
        projectID,
        repository,
        buildProductAuthContext(scope)
      )
      .then((response) => {
        if (githubPostureRequestRef.current !== requestID) {
          return;
        }
        setGitHubPosture(response.posture);
        setGitHubOrganizationPosture(response.organization_posture ?? null);
      })
      .catch((error) => {
        if (githubPostureRequestRef.current !== requestID) {
          return;
        }
        setGitHubPosture(null);
        setGitHubOrganizationPosture(null);
        setGitHubPostureError(error instanceof Error ? error.message : 'Unable to load GitHub repository posture.');
      })
      .finally(() => {
        if (githubPostureRequestRef.current === requestID) {
          setGitHubPostureLoading(false);
        }
      });

    return () => {
      if (githubPostureRequestRef.current === requestID) {
        githubPostureRequestRef.current += 1;
      }
    };
  }, [
    connections.github?.connected,
    connections.github?.connector_id,
    connections.github?.provider,
    effectiveRepoScanRepository,
    projectID,
    scope?.tenantID,
    scope?.workspaceID,
    selectedSource
  ]);

  useEffect(() => {
    if (!scope || !githubHasActiveRepoScan) {
      return undefined;
    }
    const activeScope = scope;
    const intervalID = window.setInterval(() => {
      void refreshRecentRepoScans(activeScope);
    }, 8000);
    return () => window.clearInterval(intervalID);
  }, [githubHasActiveRepoScan, scope?.tenantID, scope?.workspaceID]);

  if (!scope || !projectID) {
    return <AppShellLoading message="Resolving environment scope" />;
  }

  if (loading) {
    return (
      <AppRouteLoadingState
        title="Preparing source connections"
        body="Keeping the environment visible while connector status refreshes."
      />
    );
  }

  const selectedStatus = sourceConnection(connections, selectedSource);
  const selectedProfile = SOURCE_PROFILES[selectedSource];
  const selectedAvailability = sourceAvailability[selectedSource] ?? { visible: true, available: true };
  const selectedUnavailable = !selectedAvailability.available;
  const sourceScopeProfile = sourceScope ? SOURCE_PROFILES[sourceScope] : null;
  const sourcePageTitle = sourceScopeProfile ? `Connect ${sourceScopeProfile.name}` : 'Connect environment sources';
  const sourcePageBody =
    sourceScopeProfile?.summary ?? 'Install source connections to collect repository, workflow, and cloud identity signals.';

  const handleGitHubStart = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!sourceAvailability.github.available) {
      setSourceErrors((current) => ({
        ...current,
        github: sourceAvailability.github.unavailableMessage ?? 'GitHub connector is not available.'
      }));
      return;
    }
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
      const opened = openGitHubInstallURL(response.install_url);
      setSuccessMessage(
        opened
          ? 'GitHub opened in a new tab. Finish the installation there to complete setup.'
          : 'GitHub installation is ready. Continue with the GitHub button below.'
      );
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
    if (!sourceAvailability.github.available) {
      setSourceErrors((current) => ({
        ...current,
        github: sourceAvailability.github.unavailableMessage ?? 'GitHub connector is not available.'
      }));
      return;
    }
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
      setAWSPermissionTiers(response.permission_tiers ?? []);
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
    if (!sourceAvailability.kubernetes.available) {
      setSourceErrors((current) => ({
        ...current,
        kubernetes: sourceAvailability.kubernetes.unavailableMessage ?? 'Connector disabled.'
      }));
      return;
    }
    setSubmitting('kubernetes');
    setSuccessMessage('');
    setSourceErrors((current) => ({ ...current, kubernetes: undefined }));
    const requestSequence = refreshSequenceRef.current;
    try {
      const auth = buildProductAuthContext(scope);
      if (kubernetesForm.mode === 'kubeconfig') {
        const response = await apiClient.upsertKubernetesKubeconfigConnector(
          {
            workspace_id: scope.workspaceID,
            project_id: projectID,
            display_name: normalizeValue(kubernetesForm.displayName) || undefined,
            context: normalizeValue(kubernetesForm.context) || undefined,
            kubeconfig: kubernetesForm.kubeconfig
          },
          auth
        );
        if (isStaleRequestSequence(requestSequence)) {
          return;
        }
        setConnections((current) => ({ ...current, kubernetes: response.connection }));
        setKubernetesEnrollment(null);
        setSuccessMessage('Kubeconfig saved.');
        return;
      }
      const response = await apiClient.startKubernetesConnector(
        {
          workspace_id: scope.workspaceID,
          project_id: projectID,
          display_name: normalizeValue(kubernetesForm.displayName) || undefined,
          api_url: normalizeValue(kubernetesForm.apiURL) || undefined
        },
        auth
      );
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setConnections((current) => ({ ...current, kubernetes: response.connection }));
      setKubernetesEnrollment(response);
      setSuccessMessage('Enrollment token ready.');
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

  const parseOptionalPositiveInteger = (value: string, field: string): number | undefined => {
    const normalized = normalizeValue(value);
    return normalized ? parsePositiveInteger(normalized, field) : undefined;
  };

  const handleRepoScanSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!scope) {
      setRepoScanError('Workspace route context is missing.');
      return;
    }
    if (!connections.github?.connected) {
      setRepoScanError('Connect GitHub before queueing a repository scan.');
      return;
    }
    const repository = canonicalGitHubRepositoryDisplay(effectiveRepoScanRepository);
    if (!repository) {
      setRepoScanError('Choose a selected GitHub repository before queueing a scan.');
      return;
    }
    setRepoScanSubmitting(true);
    setRepoScanError('');
    setSuccessMessage('');
    const requestSequence = refreshSequenceRef.current;
    const submitSequence = nextRepoScanSubmitSequence();
    try {
      const githubConnection = connections.github;
      const request: RepoScanRequest = { repository };
      if (githubConnection?.provider === 'github_app') {
        request.project_id = projectID;
        if (githubConnection.connector_id) {
          request.connector_id = githubConnection.connector_id;
        }
      }
      const historyLimit = parseOptionalPositiveInteger(repoScanForm.historyLimit, 'History limit');
      const maxFindings = parseOptionalPositiveInteger(repoScanForm.maxFindings, 'Max findings');
      if (historyLimit) {
        request.history_limit = historyLimit;
      }
      if (maxFindings) {
        request.max_findings = maxFindings;
      }
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.runRepoScan(request, auth);
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setRecentRepoScans((current) =>
        [response.repo_scan, ...current.filter((scan) => scan.id !== response.repo_scan.id)].slice(0, 8)
      );
      setSuccessMessage(`Repository scan queued for ${canonicalGitHubRepositoryDisplay(response.repo_scan.repository)}.`);
      void refreshRecentRepoScans(scope);
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setRepoScanError(formatRepoScanSubmitError(error));
    } finally {
      if (isLatestRepoScanSubmitSequence(submitSequence)) {
        setRepoScanSubmitting(false);
      }
    }
  };

  const handleRepoScanCancel = async (scan: RepoScanRecord) => {
    if (!scope) {
      setRepoScanError('Workspace route context is missing.');
      return;
    }
    if (!isActiveScanStatus(scan.status)) {
      setRepoScanError('Only queued or running repository scans can be canceled.');
      return;
    }
    setRepoScanCancelingID(scan.id);
    setRepoScanError('');
    setSuccessMessage('');
    const requestSequence = refreshSequenceRef.current;
    try {
      const auth = buildProductAuthContext(scope);
      const response = await apiClient.cancelRepoScan(scan.id, auth);
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setRecentRepoScans((current) => current.map((item) => (item.id === response.repo_scan.id ? response.repo_scan : item)));
      setSuccessMessage(`Repository scan canceled for ${canonicalGitHubRepositoryDisplay(response.repo_scan.repository)}.`);
      void refreshRecentRepoScans(scope, 'interactive');
    } catch (error) {
      if (isStaleRequestSequence(requestSequence)) {
        return;
      }
      setRepoScanError(formatRepoScanCancelError(error));
    } finally {
      setRepoScanCancelingID((current) => (current === scan.id ? '' : current));
    }
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
    <section className={`idt-app-panel idt-source-onboarding${sourceScope ? ' is-source-scoped' : ''}`}>
      <div className="idt-source-onboarding-header">
        {sourceScopeProfile ? (
          <div className="idt-source-onboarding-title-row">
            <SourceLogoMark provider={selectedSource} className="is-hero" />
            <div>
              <h1>{sourcePageTitle}</h1>
              <p>{sourcePageBody}</p>
            </div>
          </div>
        ) : (
          <div>
            <p className="idt-app-kicker">Environment sources</p>
            <h2>{sourcePageTitle}</h2>
            <p>
              {sourcePageBody} Environment <strong>{environmentFallbackLabel(projectID)}</strong>.
            </p>
          </div>
        )}
        <div className="idt-source-onboarding-actions">
          {sourceScopeProfile ? (
            <span className={`idt-source-status-pill is-${sourceAvailabilityTone(selectedAvailability, selectedStatus)}`}>
              {selectedUnavailable ? 'Unavailable' : connectionLifecycle(selectedStatus)}
            </span>
          ) : null}
          <button
            type="button"
            className="idt-btn idt-btn-ghost"
            onClick={() => {
              void refreshConnections(true);
            }}
            disabled={backendFeaturesLoading || refreshing || submitting !== '' || repoScanSubmitting}
          >
            {refreshing ? 'Refreshing...' : 'Refresh status'}
          </button>
        </div>
      </div>

      {successMessage ? (
        <p role="status" className="idt-app-alert idt-app-alert-success">
          {successMessage}
        </p>
      ) : null}

      <div className="idt-source-wizard-grid">
        {sourceScopeProfile ? null : (
          <aside className="idt-source-picker" aria-label="Source types">
            {sourceOrder.map((provider) => {
              const profile = SOURCE_PROFILES[provider];
              const status = sourceConnection(connections, provider);
              const error = sourceErrors[provider];
              const availability = sourceAvailability[provider];
              return (
                <button
                  key={provider}
                  type="button"
                  className={`idt-source-card is-provider-${provider} ${selectedSource === provider ? 'is-selected' : ''} ${
                    availability.available ? '' : 'is-unavailable'
                  }`}
                  aria-pressed={selectedSource === provider}
                  aria-disabled={!availability.available}
                  onClick={() => setSelectedSource(provider)}
                  disabled={!availability.available}
                >
                  <span className="idt-source-card-topline">
                    <span className="idt-source-card-identity">
                      <SourceLogoMark provider={provider} />
                      <span>{profile.eyebrow}</span>
                    </span>
                    <span className={`idt-source-status-pill is-${sourceAvailabilityTone(availability, status)}`}>
                      {!availability.available ? 'Unavailable' : error ? 'Needs retry' : connectionLifecycle(status)}
                    </span>
                  </span>
                  <strong>{profile.name}</strong>
                  <small>{availability.unavailableMessage ?? profile.primarySignal}</small>
                </button>
              );
            })}
          </aside>
        )}

        <div className="idt-source-config">
          {sourceScopeProfile ? null : (
            <div className="idt-source-config-header">
              <div className="idt-source-config-title">
                <SourceLogoMark provider={selectedSource} className="is-hero" />
                <div>
                  <p className="idt-app-kicker">{selectedProfile.eyebrow}</p>
                  <h3>{selectedProfile.name}</h3>
                  <p>{selectedProfile.summary}</p>
                </div>
              </div>
              <span className={`idt-source-status-pill is-${sourceAvailabilityTone(selectedAvailability, selectedStatus)}`}>
                {selectedUnavailable ? 'Unavailable' : connectionLifecycle(selectedStatus)}
              </span>
            </div>
          )}

          <dl className="idt-source-meta">
            <div>
              <dt>Required access</dt>
              <dd>{selectedProfile.requiredAccess}</dd>
            </div>
            <div>
              <dt>Health</dt>
              <dd>{selectedUnavailable ? 'unavailable' : connectionHealth(selectedStatus)}</dd>
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

          {selectedUnavailable ? (
            <p role="status" className="idt-app-alert">
              {selectedAvailability.unavailableMessage ?? `${selectedProfile.name} connector is not available.`}
            </p>
          ) : sourceErrors[selectedSource] ? (
            <p role="alert" className="idt-app-alert idt-app-alert-error">
              {sourceErrors[selectedSource]}
            </p>
          ) : null}

          {selectedSource === 'github' && !selectedUnavailable ? (
            <div className="idt-source-form-stack">
              <article className="idt-source-install-card idt-source-primary-action">
                <div className="idt-source-primary-copy">
                  <p className="idt-app-kicker">Setup</p>
                  <h4>Install Identrail on GitHub</h4>
                  <p>Choose the account and repositories to scan.</p>
                </div>
                <form className="idt-app-form" onSubmit={handleGitHubStart}>
                  <label>
                    Installation name
                    <input
                      value={githubAppForm.displayName}
                      onChange={(event) =>
                        setGitHubAppForm((current) => ({ ...current, displayName: event.target.value }))
                      }
                      placeholder="Identrail"
                    />
                  </label>
                  <button className="idt-btn idt-btn-primary" type="submit" disabled={submitting !== ''}>
                    {submitting === 'github' ? 'Preparing GitHub...' : 'Install GitHub App'}
                  </button>
                </form>
              </article>

              {githubStart ? (
                <article className="idt-source-install-card">
                  <div>
                    <h4>GitHub did not open?</h4>
                    <p>
                      Open the account picker manually. This link expires {formatConnectionTime(githubStart.expires_at)}.
                    </p>
                  </div>
                  <a className="idt-btn idt-btn-dark" href={githubStart.install_url} target="_blank" rel="noreferrer">
                    Open GitHub
                  </a>
                </article>
              ) : null}

              <details className="idt-source-advanced idt-source-enterprise-fallback">
                <summary>
                  <span>
                    <strong>GitHub Enterprise fallback</strong>
                    <small>Use only for self-hosted GitHub Server or restricted app-install environments.</small>
                  </span>
                </summary>
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
              </details>

              {connections.github?.connected ? (
                <form className="idt-app-form idt-repo-scan-launch" onSubmit={handleRepoScanSubmit}>
                  <article className="idt-source-install-card idt-repo-scan-launch-card">
                    <div>
                      <h4>Run scan</h4>
                      <p>Scan a selected repository and route results to GitHub findings.</p>
                    </div>
                    <Link className="idt-btn idt-btn-ghost" to={repoScanFindingsPath}>
                      View findings
                    </Link>
                  </article>

                  {repoScanError ? (
                    <article role="alert" className="idt-source-recovery-card">
                      <strong>Scan could not start</strong>
                      <p>{repoScanError}</p>
                      <button className="idt-btn idt-btn-ghost" type="button" onClick={() => setRepoScanError('')}>
                        Dismiss
                      </button>
                    </article>
                  ) : null}

                  <div className="idt-source-inline-fields">
                    {githubSelectedRepositories.length > 0 ? (
                      <label>
                        Repository
                        <select
                          value={effectiveRepoScanRepository}
                          onChange={(event) => {
                            setRepoScanForm((current) => ({ ...current, repository: event.target.value }));
                            setRepoScanError('');
                          }}
                        >
                          {githubSelectedRepositories.map((repository) => (
                            <option key={repository} value={repository}>
                              {repository}
                            </option>
                          ))}
                        </select>
                      </label>
                    ) : (
                      <label>
                        Repository
                        <input
                          value={repoScanForm.repository}
                          onChange={(event) => {
                            setRepoScanForm((current) => ({ ...current, repository: event.target.value }));
                            setRepoScanError('');
                          }}
                          placeholder="owner/repo"
                          required
                        />
                      </label>
                    )}
                  </div>

                  <details className="idt-source-advanced idt-scan-limits-details">
                    <summary>
                      <span>
                        <strong>Scan limits</strong>
                        <small>Optional</small>
                      </span>
                    </summary>
                    <div className="idt-source-inline-fields">
                      <label>
                        History limit
                        <input
                          inputMode="numeric"
                          value={repoScanForm.historyLimit}
                          onChange={(event) => setRepoScanForm((current) => ({ ...current, historyLimit: event.target.value }))}
                          placeholder="default"
                        />
                      </label>
                      <label>
                        Max findings
                        <input
                          inputMode="numeric"
                          value={repoScanForm.maxFindings}
                          onChange={(event) => setRepoScanForm((current) => ({ ...current, maxFindings: event.target.value }))}
                          placeholder="default"
                        />
                      </label>
                    </div>
                  </details>

                  <button
                    className="idt-btn idt-btn-primary"
                    type="submit"
                    disabled={
                      repoScanSubmitting || submitting !== '' || !effectiveRepoScanRepository || githubHasActiveSelectedRepoScan
                    }
                  >
                    {repoScanSubmitting ? 'Queueing...' : githubHasActiveSelectedRepoScan ? 'Scan already active' : 'Queue first scan'}
                  </button>

                  <div className="idt-source-diagnostics idt-repo-scan-activity" aria-label="recent repository scan activity">
                    <p>Scan activity</p>
                    {githubRecentRepoScans.length > 0 ? (
                      githubRecentRepoScans.map((scan) => (
                        <article key={scan.id}>
                          <strong>{canonicalGitHubRepositoryDisplay(scan.repository) || scan.repository}</strong>
                          <span className={`idt-source-status-pill is-${repoScanStatusTone(scan.status)}`}>
                            {formatTokenLabel(scan.status)}
                          </span>
                          <p>
                            {scan.finding_count} findings · {scan.files_scanned} files · {formatDateLabel(scan.started_at)}
                          </p>
                          {scan.error_message ? <small>{scan.error_message}</small> : null}
                          {isActiveScanStatus(scan.status) ? (
                            <button
                              className="idt-btn idt-btn-ghost idt-repo-scan-cancel"
                              type="button"
                              disabled={repoScanCancelingID === scan.id || submitting !== ''}
                              onClick={() => void handleRepoScanCancel(scan)}
                            >
                              {repoScanCancelingID === scan.id ? 'Canceling...' : 'Cancel scan'}
                            </button>
                          ) : null}
                        </article>
                      ))
                    ) : (
                      <article>
                        <strong>No scans yet</strong>
                        <p>Run the first scan to populate history.</p>
                      </article>
                    )}
                    {githubHasActiveRepoScan ? <p>Refreshing while a scan is queued or running.</p> : null}
                  </div>
                </form>
              ) : null}
            </div>
          ) : null}

          {selectedSource === 'aws' && !selectedUnavailable ? (
            <form className="idt-app-form" onSubmit={handleAWSSubmit}>
              {FEATURE_CONNECTOR_AWS ? (
                <article className="idt-source-install-card idt-aws-launch-card">
                  <div>
                    <h4>Launch read-only stack</h4>
                    <p>{awsCloudFormationStart ? 'Stack launch generated.' : 'Generate the read-only role and trust policy.'}</p>
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

          {selectedSource === 'kubernetes' && !selectedUnavailable ? (
            <form className="idt-app-form" onSubmit={handleKubernetesSubmit}>
              <div className="idt-source-inline-fields">
                <label>
                  Mode
                  <select
                    value={kubernetesForm.mode}
                    onChange={(event) =>
                      setKubernetesForm((current) => ({
                        ...current,
                        mode: event.target.value === 'kubeconfig' ? 'kubeconfig' : 'agent'
                      }))
                    }
                  >
                    <option value="agent">Agent</option>
                    <option value="kubeconfig">Kubeconfig</option>
                  </select>
                </label>
              </div>
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
                {kubernetesForm.mode === 'agent' ? (
                  <label>
                    API URL
                    <input
                      value={kubernetesForm.apiURL}
                      onChange={(event) =>
                        setKubernetesForm((current) => ({ ...current, apiURL: event.target.value }))
                      }
                      placeholder="https://api.identrail.com"
                    />
                  </label>
                ) : (
                  <label>
                    Kubeconfig context
                    <input
                      value={kubernetesForm.context}
                      onChange={(event) =>
                        setKubernetesForm((current) => ({ ...current, context: event.target.value }))
                      }
                      placeholder="current-context"
                    />
                  </label>
                )}
              </div>
              {kubernetesForm.mode === 'kubeconfig' ? (
                <label>
                  kubeconfig
                  <textarea
                    value={kubernetesForm.kubeconfig}
                    onChange={(event) =>
                      setKubernetesForm((current) => ({ ...current, kubeconfig: event.target.value }))
                    }
                    placeholder="Paste kubeconfig YAML"
                    rows={8}
                  />
                </label>
              ) : null}
              <button className="idt-btn idt-btn-primary" type="submit" disabled={submitting !== ''}>
                {submitting === 'kubernetes'
                  ? 'Preparing...'
                  : kubernetesForm.mode === 'agent'
                    ? 'Generate token'
                    : 'Save kubeconfig'}
              </button>
              {kubernetesEnrollment ? (
                <div className="idt-source-diagnostics">
                  <article>
                    <strong>Install command</strong>
                    <span>Expires {formatConnectionTime(kubernetesEnrollment.enrollment_expires_at)}</span>
                    <p>
                      <code>{kubernetesEnrollment.helm_command}</code>
                    </p>
                  </article>
                </div>
              ) : null}
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
              {connections.kubernetes.connection_mode ? <p>Mode {connections.kubernetes.connection_mode}</p> : null}
              {connections.kubernetes.agent_id ? <p>Agent {connections.kubernetes.agent_id}</p> : null}
              {connections.kubernetes.last_heartbeat_at ? (
                <p>Last heartbeat {formatConnectionTime(connections.kubernetes.last_heartbeat_at)}</p>
              ) : null}
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
              <details className="idt-source-advanced idt-source-compact-details idt-source-connection-details">
                <summary>
                  <span>
                    <strong>GitHub installation</strong>
                    <small>
                      {githubSelectedRepositories.length > 0
                        ? formatCountLabel(githubSelectedRepositories.length, 'repository', 'repositories')
                        : 'Connected'}
                    </small>
                  </span>
                </summary>
                <div className="idt-source-connection-body">
                  <p>
                    {connections.github.account_login ? `Installed on ${connections.github.account_login}` : 'Installation active'}
                    {connections.github.installation_id ? ` · Installation ${connections.github.installation_id}` : ''}
                  </p>
                  {githubSelectedRepositories.length > 0 ? (
                    <div className="idt-source-chip-list">
                      {githubSelectedRepositories.map((repository) => (
                        <span key={repository}>{repository}</span>
                      ))}
                    </div>
                  ) : null}
                </div>
              </details>
              {connections.github.webhook_secret_rotation_due_at ? (
                <p>Webhook rotation due {formatConnectionTime(connections.github.webhook_secret_rotation_due_at)}</p>
              ) : null}
              {githubPostureLoading ? (
                <article>
                  <strong>{effectiveRepoScanRepository || 'Selected repository'}</strong>
                  <span>Loading posture</span>
                  <p>Collecting GitHub repository posture signals.</p>
                </article>
              ) : null}
              {githubPostureError ? (
                <p role="alert" className="idt-app-alert idt-app-alert-error">
                  {githubPostureError}
                </p>
              ) : null}
              {githubPosture ? (
                <>
                  <article className="idt-github-posture-card">
                    <div className="idt-github-posture-card-head">
                      <div>
                        <strong>Repository posture</strong>
                        <p>Collected {formatConnectionTime(githubPosture.collected_at)}</p>
                      </div>
                      <span className={`idt-source-status-pill is-${githubPostureNeedsAttentionCount > 0 ? 'warning' : 'success'}`}>
                        {githubPostureNeedsAttentionCount > 0
                          ? formatCountLabel(githubPostureNeedsAttentionCount, 'check', 'checks')
                          : 'Secure'}
                      </span>
                    </div>
                    <dl className="idt-github-posture-stats" aria-label="GitHub posture summary">
                      <div>
                        <dt>Secure</dt>
                        <dd>{githubPostureSecureCount}</dd>
                      </div>
                      <div>
                        <dt>Attention</dt>
                        <dd>{githubPostureAttentionCount}</dd>
                      </div>
                      <div>
                        <dt>Limited</dt>
                        <dd>{githubPostureLimitedCount}</dd>
                      </div>
                      <div>
                        <dt>Unavailable</dt>
                        <dd>{githubPostureUnavailableCount}</dd>
                      </div>
                    </dl>
                  </article>
                  <details className="idt-source-advanced idt-github-posture-details">
                    <summary>
                      <span>
                        <strong>
                          {githubPostureNeedsAttentionCount > 0
                            ? `Review ${formatCountLabel(githubPostureNeedsAttentionCount, 'check', 'checks')}`
                            : 'Review checks'}
                        </strong>
                        <small>
                          {githubPostureNeedsAttentionCount > 0 ? 'Branch, Actions, security' : 'Collected GitHub signals'}
                        </small>
                      </span>
                    </summary>
                    {githubPosture.rate_limit?.remaining !== undefined ? (
                      <p className="idt-github-posture-rate-limit">
                        GitHub API remaining {githubPosture.rate_limit.remaining}
                        {githubPosture.rate_limit.limit ? ` of ${githubPosture.rate_limit.limit}` : ''}
                      </p>
                    ) : null}
                    <div className="idt-github-posture-checks">
                      {githubPostureDetailChecks.slice(0, 6).map((check) => (
                        <article key={check.id}>
                          <strong>{formatTokenLabel(check.category || check.id)}</strong>
                          <span className={`idt-source-status-pill is-${githubPostureStateTone(check.state)}`}>
                            {formatTokenLabel(check.state)}
                          </span>
                          <p>{check.summary}</p>
                          {check.reason ? <small>{formatTokenLabel(check.reason)}</small> : null}
                        </article>
                      ))}
                      {githubPostureDetailChecks.length > 6 ? (
                        <p>{formatCountLabel(githubPostureDetailChecks.length - 6, 'additional check', 'additional checks')} hidden.</p>
                      ) : null}
                      {githubOrganizationPosture ? (
                        <>
                          <article>
                            <strong>Organization posture</strong>
                            <span>{formatConnectionTime(githubOrganizationPosture.collected_at)}</span>
                            <p>
                              {githubOrganizationPostureSecureCount} secure · {githubOrganizationPostureAttentionCount}{' '}
                              attention · {githubOrganizationPostureLimitedCount} permission limited ·{' '}
                              {githubOrganizationPostureUnavailableCount} unavailable
                            </p>
                            <small>
                              {githubOrganizationPostureUnsupportedCount} unsupported ·{' '}
                              {githubOrganizationPostureUnknownCount} unknown
                            </small>
                          </article>
                          {githubOrganizationPostureDetailChecks.slice(0, 5).map((check) => (
                            <article key={`org-${check.id}`}>
                              <strong>{formatTokenLabel(check.category || check.id)}</strong>
                              <span className={`idt-source-status-pill is-${githubPostureStateTone(check.state)}`}>
                                {formatTokenLabel(check.state)}
                              </span>
                              <p>{check.summary}</p>
                              {check.reason ? <small>{formatTokenLabel(check.reason)}</small> : null}
                            </article>
                          ))}
                          {githubOrganizationPostureDetailChecks.length > 5 ? (
                            <p>
                              {formatCountLabel(
                                githubOrganizationPostureDetailChecks.length - 5,
                                'additional organization check',
                                'additional organization checks'
                              )}{' '}
                              hidden.
                            </p>
                          ) : null}
                        </>
                      ) : null}
                    </div>
                  </details>
                </>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>

      <article className="idt-app-panel idt-source-policy-panel">
        <details>
          <summary className="idt-source-policy-summary">
            <div>
              <p className="idt-app-kicker">Automation policies</p>
              <h3>Scan policy</h3>
              <p>Define trigger mode, cadence, and limits for this source.</p>
            </div>
            <span className="idt-source-status-pill is-warning">Advanced</span>
          </summary>
          <div className="idt-source-policy-body">

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
          <p className="idt-form-note">
            Manual keeps GitHub events from starting scans. Event and hybrid modes allow selected-repository webhooks to queue scans.
          </p>
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
          </div>
        </details>
      </article>
      <PermissionPreviewModal
        open={awsPreviewOpen}
        title="AWS read-only connector policy"
        items={awsPermissionPreview}
        tiers={awsPermissionTiers}
        onClose={() => setAWSPreviewOpen(false)}
      />
    </section>
  );
}

type GitHubIntelligenceCategory = {
  id: string;
  label: string;
  summary: string;
  empty: string;
  match: (finding: ApiFinding) => boolean;
};

function repoFindingSearchText(finding: ApiFinding): string {
  const evidence = (() => {
    try {
      return finding.evidence ? JSON.stringify(finding.evidence) : '';
    } catch {
      return '';
    }
  })();
  return [
    finding.type,
    finding.detector,
    finding.adapter_source,
    finding.title,
    finding.human_summary,
    finding.file_path,
    finding.line_snippet,
    finding.remediation,
    evidence
  ]
    .map((value) => normalizeValue(value).toLowerCase())
    .filter(Boolean)
    .join(' ');
}

function repoFindingMatchesAny(finding: ApiFinding, tokens: string[]): boolean {
  const haystack = repoFindingSearchText(finding);
  return tokens.some((token) => haystack.includes(token));
}

const AGENTIC_RISK_SCOPE_TOKENS: string[] = [
  'ai_agent_surface',
  'ai_agent_config',
  'ai agent config',
  'assistant configuration',
  '.mcp.json',
  '.cursor',
  '.continue',
  '.codex',
  '.claude',
  'copilot-instructions',
  'agent config',
  'agent instruction',
  'mcp',
  'model context protocol',
  'tool capability',
  'dangerous tool',
  'external capability',
  'command surface',
  'stdio',
  'shell tool',
  'server inventory',
  'prompt',
  'instruction',
  'prompt injection',
  'workflow prompt',
  'untrusted input',
  'pull request text',
  'issue body',
  'ai step',
  'secret',
  'token',
  'credential',
  'api key',
  'env var',
  'environment variable',
  'github_secret_scanning',
  'secret scanning',
  'agentic secret',
  'github actions',
  'workflow_ai_agent_prompt_injection',
  'pull_request_target',
  'oidc',
  'id-token',
  'permissions',
  'runner',
  'self-hosted',
  'bot',
  'trust path'
];

function isAgenticRiskFinding(finding: ApiFinding): boolean {
  return repoFindingMatchesAny(finding, AGENTIC_RISK_SCOPE_TOKENS);
}

const GITHUB_INTELLIGENCE_CATEGORIES: GitHubIntelligenceCategory[] = [
  {
    id: 'ai-agent-mcp',
    label: 'AI/MCP Exposure',
    summary: 'Agent configs, MCP servers, and risky tool access.',
    empty: 'No AI/MCP exposure.',
    match: (finding) =>
      repoFindingMatchesAny(finding, [
        'ai_agent_surface',
        'ai_agent_config',
        'ai agent config',
        'mcp',
        '.mcp.json',
        '.cursor',
        '.continue',
        '.codex',
        '.claude',
        'copilot-instructions',
        'agent config',
        'dangerous tool'
      ])
  },
  {
    id: 'ai-workflow',
    label: 'AI Workflow Risk',
    summary: 'Untrusted PR or issue text reaching AI steps.',
    empty: 'No AI workflow risk.',
    match: (finding) =>
      repoFindingMatchesAny(finding, [
        'workflow_ai_agent_prompt_injection',
        'prompt injection',
        'workflow prompt',
        'pull_request_target',
        'anthropic',
        'claude',
        'openai',
        'codex',
        'gemini',
        'aider',
        'cursor'
      ])
  },
  {
    id: 'native-alerts',
    label: 'GitHub Alerts',
    summary: 'Secret scanning and Dependabot alerts.',
    empty: 'No GitHub alerts.',
    match: (finding) =>
      repoFindingMatchesAny(finding, [
        'github_secret_scanning',
        'secret scanning alert',
        'github_dependabot',
        'dependabot',
        'vulnerability alert'
      ])
  },
  {
    id: 'runner-posture',
    label: 'Runner Risk',
    summary: 'Self-hosted runner reachability and labels.',
    empty: 'No runner risk.',
    match: (finding) =>
      repoFindingMatchesAny(finding, [
        'workflow_self_hosted_runner',
        'self_hosted_runner',
        'self-hosted runner',
        'runs-on self-hosted',
        'runner label',
        'runner group'
      ])
  },
  {
    id: 'org-posture',
    label: 'Org Policy',
    summary: 'Rulesets, branch protection, and scanning policy.',
    empty: 'No org policy risk.',
    match: (finding) =>
      repoFindingMatchesAny(finding, [
        'organization posture',
        'org_secret_scanning_policy',
        'secret scanning policy',
        'dependabot policy',
        'ruleset',
        'branch protection',
        'repository rules'
      ])
  },
  {
    id: 'remediation-ready',
    label: 'Fix Ready',
    summary: 'Open findings with file or line context.',
    empty: 'No fix-ready risks.',
    match: (finding) => {
      const lifecycle = normalizeRepoFindingLifecycleStatus(finding.lifecycle_status);
      if (lifecycle !== 'open' && lifecycle !== 'reopened') {
        return false;
      }
      return Boolean(normalizeValue(finding.source_url ?? '') || normalizeValue(finding.file_path ?? ''));
    }
  }
];

const GITHUB_INTELLIGENCE_SCOPE_CATEGORIES = GITHUB_INTELLIGENCE_CATEGORIES.filter(
  (category) => category.id !== 'remediation-ready'
);

function githubIntelligenceCategoryForFinding(finding: ApiFinding): GitHubIntelligenceCategory {
  return GITHUB_INTELLIGENCE_CATEGORIES.find((category) => category.match(finding)) ?? GITHUB_INTELLIGENCE_CATEGORIES[5];
}

function isOpenRepoFinding(finding: ApiFinding): boolean {
  const lifecycle = normalizeRepoFindingLifecycleStatus(finding.lifecycle_status);
  const triage = normalizeFindingStatus(finding.triage?.status);
  return (lifecycle === 'open' || lifecycle === 'reopened') && triage !== 'resolved' && triage !== 'suppressed';
}

function sortGitHubIntelligenceFindings(findings: ApiFinding[]): ApiFinding[] {
  return [...findings].sort((left, right) => {
    const severityDelta = severityRank(right.severity) - severityRank(left.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }
    const confidenceDelta = (right.confidence_score ?? 0) - (left.confidence_score ?? 0);
    if (confidenceDelta !== 0) {
      return confidenceDelta;
    }
    return new Date(right.created_at).getTime() - new Date(left.created_at).getTime();
  });
}

export function ProductAIRisksPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [trendError, setTrendError] = useState('');
  const [repoScans, setRepoScans] = useState<RepoScanRecord[]>([]);
  const [repoFindings, setRepoFindings] = useState<ApiFinding[]>([]);
  const [trendPoints, setTrendPoints] = useState<TrendPoint[]>([]);
  const requestRef = useRef(0);

  const repoScansByID = useMemo(
    () =>
      repoScans.reduce<Record<string, RepoScanRecord>>((acc, scan) => {
        acc[scan.id] = scan;
        return acc;
      }, {}),
    [repoScans]
  );

  const findingsInScope = useMemo(
    () =>
      repoFindings.filter((finding) =>
        GITHUB_INTELLIGENCE_SCOPE_CATEGORIES.some((category) => category.match(finding))
      ),
    [repoFindings]
  );

  const openFindings = useMemo(() => findingsInScope.filter(isOpenRepoFinding), [findingsInScope]);
  const sortedOpenFindings = useMemo(() => sortGitHubIntelligenceFindings(openFindings), [openFindings]);
  const priorityFindings = sortedOpenFindings.slice(0, 6);

  const categoryCards = useMemo(
    () =>
      GITHUB_INTELLIGENCE_CATEGORIES.map((category) => {
        const findings = findingsInScope.filter((finding) => category.match(finding));
        const open = findings.filter(isOpenRepoFinding);
        const criticalHigh = open.filter((finding) => {
          const severity = normalizeValue(finding.severity).toLowerCase();
          return severity === 'critical' || severity === 'high';
        }).length;
        return {
          ...category,
          total: findings.length,
          open: open.length,
          criticalHigh
        };
      }),
    [findingsInScope]
  );

  const allRepositoryRows = useMemo(() => {
    const byRepository = new Map<string, { repository: string; open: number; criticalHigh: number; total: number }>();
    for (const finding of findingsInScope) {
      const repository = canonicalGitHubRepositoryDisplay(repoFindingRepositoryValue(finding, repoScansByID)) || 'Repository unavailable';
      const current = byRepository.get(repository) ?? { repository, open: 0, criticalHigh: 0, total: 0 };
      current.total += 1;
      if (isOpenRepoFinding(finding)) {
        current.open += 1;
        const severity = normalizeValue(finding.severity).toLowerCase();
        if (severity === 'critical' || severity === 'high') {
          current.criticalHigh += 1;
        }
      }
      byRepository.set(repository, current);
    }
    return [...byRepository.values()]
      .sort((left, right) => right.criticalHigh - left.criticalHigh || right.open - left.open || right.total - left.total);
  }, [findingsInScope, repoScansByID]);

  const repositoryRows = useMemo(() => allRepositoryRows.slice(0, 5), [allRepositoryRows]);

  const trendRows = useMemo(() => {
    const maxTotal = Math.max(...trendPoints.map((point) => point.total), 0);
    return trendPoints.slice(-6).map((point, index) => {
      const startedAt = new Date(point.started_at);
      const priority = (point.by_severity?.critical ?? 0) + (point.by_severity?.high ?? 0);
      return {
        key: `${point.started_at}-${index}`,
        label: Number.isNaN(startedAt.getTime())
          ? 'Unknown'
          : startedAt.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }),
        total: point.total,
        percentage: maxTotal > 0 ? Math.round((point.total / maxTotal) * 100) : 0,
        priority
      };
    });
  }, [trendPoints]);

  const loadDashboard = async (targetScope: ProductSession, mode: 'initial' | 'refresh') => {
    const requestID = ++requestRef.current;
    if (mode === 'initial') {
      setLoading(true);
    } else {
      setRefreshing(true);
    }
    setError('');
    setTrendError('');
    try {
      const auth = buildProductAuthContext(targetScope);
      const [scanResult, findingResult, trendResult] = await Promise.allSettled([
        apiClient.listRepoScans({ limit: 50 }, auth),
        listAIRisksRepoFindings(auth),
        apiClient.getRepoFindingsTrends({ points: TREND_POINTS }, auth)
      ]);
      if (requestID !== requestRef.current) {
        return;
      }
      if (scanResult.status === 'rejected') {
        throw scanResult.reason;
      }
      if (findingResult.status === 'rejected') {
        throw findingResult.reason;
      }
      setRepoScans(scanResult.value.items ?? []);
      setRepoFindings(findingResult.value);
      if (trendResult.status === 'fulfilled') {
        setTrendPoints(trendResult.value.items ?? []);
      } else {
        setTrendPoints([]);
        setTrendError(formatAPIError(trendResult.reason, 'Finding trend is unavailable.'));
      }
    } catch (requestError) {
      if (requestID !== requestRef.current) {
        return;
      }
      setError(formatAPIError(requestError, 'Failed to load AI / Agentic Risk.'));
      setRepoScans([]);
      setRepoFindings([]);
      setTrendPoints([]);
      setTrendError('');
    } finally {
      if (requestID === requestRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  };

  useEffect(() => {
    if (!scope) {
      setLoading(false);
      setError('Workspace route context is missing.');
      return;
    }
    void loadDashboard(scope, 'initial');
    return () => {
      requestRef.current += 1;
    };
  }, [scope?.tenantID, scope?.workspaceID]);

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error">
        <p className="idt-app-kicker">GitHub</p>
        <h2>AI / Agentic Risk unavailable</h2>
        <p>Workspace route context is missing.</p>
      </section>
    );
  }

  if (loading) {
    return (
      <AppRouteLoadingState
        title="Preparing AI / Agentic Risk"
        body="Loading repository scans, GitHub alerts, and AI workflow signals."
      />
    );
  }

  const findingsPath = buildScopedPath(scope, 'github/findings');
  const connectPath = buildScopedPath(scope, 'github/connect');
  const scansByRecency = [...repoScans].sort(
    (left, right) => new Date(right.started_at).getTime() - new Date(left.started_at).getTime()
  );
  const scansByCompletion = [...repoScans].sort(
    (left, right) => scanCompletionSortValue(right) - scanCompletionSortValue(left)
  );
  const latestScan = scansByRecency[0] ?? null;
  const latestScanTone = latestScan ? repoScanStatusTone(latestScan.status) : 'neutral';
  const activeScanCount = repoScans.filter((scan) => isActiveScanStatus(scan.status)).length;
  const failedScanCount = repoScans.filter((scan) => isFailedScanStatus(scan.status)).length;
  const completedScanCount = scansByRecency.filter((scan) => isCompletedScanStatus(scan.status)).length;
  const successfulScanCount = scansByRecency.filter((scan) => repoScanStatusTone(scan.status) === 'success').length;
  const latestCompletedScan = scansByCompletion.find((scan) => isCompletedScanStatus(scan.status)) ?? null;
  const latestSuccessfulScan = scansByCompletion.find((scan) => repoScanStatusTone(scan.status) === 'success') ?? null;
  const scanSuccessRate = completedScanCount > 0 ? Math.round((successfulScanCount / completedScanCount) * 100) : null;
  const totalFilesScanned = scansByRecency.reduce((acc, scan) => acc + (scan.files_scanned ?? 0), 0);
  const totalScanFindings = scansByRecency.reduce((acc, scan) => acc + (scan.finding_count ?? 0), 0);
  const openFindingCount = openFindings.length;
  const highPriorityCount = openFindings.filter((finding) => {
    const severity = normalizeValue(finding.severity).toLowerCase();
    return severity === 'critical' || severity === 'high';
  }).length;
  const repositoriesWithSignals = allRepositoryRows.length;
  const fixedFindingCount = findingsInScope.filter((finding) => normalizeRepoFindingLifecycleStatus(finding.lifecycle_status) === 'fixed').length;
  const reopenedFindingCount = findingsInScope.filter((finding) => normalizeRepoFindingLifecycleStatus(finding.lifecycle_status) === 'reopened').length;
  const latestScanLabel = latestScan
    ? `${canonicalGitHubRepositoryDisplay(latestScan.repository) || latestScan.repository} · ${formatTokenLabel(latestScan.status)}`
    : 'No repository scans yet';
  const scanHealthTone = latestScanTone === 'error'
    ? 'error'
    : activeScanCount > 0
      ? 'warning'
      : latestScanTone === 'success'
        ? 'success'
        : 'neutral';
  const scanHealthStatusLabel =
    scanHealthTone === 'error'
      ? 'Action needed'
      : scanHealthTone === 'warning'
        ? 'Running'
        : scanHealthTone === 'success'
          ? 'Healthy'
          : 'No completed scan';
  const scanHealthSummary =
    scanHealthTone === 'error'
      ? latestScan?.error_message || 'Latest scan needs operator attention.'
      : scanHealthTone === 'warning'
        ? 'A repository scan is currently queued or running.'
        : latestSuccessfulScan
          ? `Latest successful scan finished ${formatRelativeTime(latestSuccessfulScan.finished_at || latestSuccessfulScan.started_at)}.`
          : 'Waiting for a completed repository scan.';

  return (
    <section className="idt-app-panel idt-github-intelligence-page">
      <div className="idt-repo-findings-header idt-github-intelligence-header">
        <div>
          <p className="idt-app-kicker">GitHub</p>
          <h2>AI / Agentic Risk</h2>
          <p>AI, MCP, workflow, runner, GitHub alert, and fix-ready signals.</p>
          <div className="idt-overview-source-strip">
            <SourceLogoMark provider="github" className="is-ai-risk-source" />
            <span>{latestScanLabel}</span>
          </div>
        </div>
        <div className="idt-inline-actions">
          <button
            className="idt-btn idt-btn-ghost"
            type="button"
            onClick={() => void loadDashboard(scope, 'refresh')}
            disabled={refreshing}
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
          <Link className="idt-btn idt-btn-primary" to={findingsPath}>
            Open findings
          </Link>
        </div>
      </div>

      {error ? <div className="idt-app-alert idt-app-alert-error">{error}</div> : null}

      <div className="idt-repo-finding-stats idt-github-intelligence-stats" aria-label="AI / Agentic Risk summary">
        <article className="idt-repo-finding-stat">
          <span>Open</span>
          <strong>{openFindingCount}</strong>
          <small className="idt-repo-finding-stat-note">{formatCountLabel(findingsInScope.length, 'signal')}</small>
        </article>
        <article className="idt-repo-finding-stat">
          <span>High</span>
          <strong>{highPriorityCount}</strong>
          <small className="idt-repo-finding-stat-note">critical or high</small>
        </article>
        <article className="idt-repo-finding-stat">
          <span>Repos</span>
          <strong>{repositoriesWithSignals}</strong>
          <small className="idt-repo-finding-stat-note">
            {formatCountLabel(activeScanCount, 'active scan')} · {formatCountLabel(failedScanCount, 'failed scan')}
          </small>
        </article>
        <article className="idt-repo-finding-stat">
          <span>Fixed</span>
          <strong>{fixedFindingCount}</strong>
          <small className="idt-repo-finding-stat-note">
            {formatCountLabel(reopenedFindingCount, 'reopened', 'reopened')}
          </small>
        </article>
      </div>

      {!error && repoScans.length === 0 && findingsInScope.length === 0 ? (
        <AppShellEmptyState
          title="No AI / Agentic Risk yet"
          body="Connect GitHub and run a repository scan to populate AI, MCP, workflow, runner, alert, and fix-ready signals."
          action={{ label: 'Connect GitHub', to: connectPath }}
        />
      ) : null}

      <div className="idt-github-intelligence-grid">
        {categoryCards.map((category) => (
          <article className="idt-github-intelligence-card" key={category.id}>
            <div className="idt-github-intelligence-card-head">
              <div>
                <span>{category.label}</span>
                <strong>{category.open}</strong>
              </div>
              <small>{category.criticalHigh > 0 ? formatCountLabel(category.criticalHigh, 'high', 'high') : 'No high'}</small>
            </div>
            <p>{category.summary}</p>
            <Link
              className="idt-github-intelligence-card-link"
              to={findingsPath}
              aria-label={category.total > 0 ? `Review ${category.label} findings` : category.empty}
            >
              {category.total > 0 ? 'Review' : 'Clear'}
            </Link>
          </article>
        ))}
      </div>

      <div className="idt-github-intelligence-main">
        <section className="idt-github-intelligence-panel">
          <div className="idt-github-intelligence-panel-head">
            <h3>Priority queue</h3>
            <Link to={findingsPath}>Review all</Link>
          </div>
          {priorityFindings.length === 0 ? (
            <AppShellEmptyState
              title="No priority risks"
              body="Open AI, MCP, workflow, runner, alert, or fix-ready findings will appear here."
            />
          ) : (
            <div className="idt-github-intelligence-list" role="list">
              {priorityFindings.map((finding) => {
                const repository = canonicalGitHubRepositoryDisplay(repoFindingRepositoryValue(finding, repoScansByID)) || 'Repository unavailable';
                const category = githubIntelligenceCategoryForFinding(finding);
                return (
                  <Link className="idt-github-intelligence-row" to={findingsPath} key={`${finding.scan_id}-${finding.id}`} role="listitem">
                    <div className="idt-repo-finding-row-top">
                      <strong>{finding.title}</strong>
                      <span className={repoFindingSeverityClass(finding.severity)}>{formatTokenLabel(finding.severity)}</span>
                    </div>
                    <p>{finding.human_summary}</p>
                    <div className="idt-repo-finding-row-meta">
                      <span>{category.label}</span>
                      <span>{repository}</span>
                      <span>{repoFindingLocationLabel(finding)}</span>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </section>

        <aside className="idt-github-intelligence-panel idt-github-intelligence-hotspot-panel">
          <div className="idt-github-intelligence-panel-head">
            <h3>Repository hotspots</h3>
            <span>{repositoryRows.length ? formatCountLabel(repositoryRows.length, 'repo') : 'No hotspots'}</span>
          </div>
          {repositoryRows.length === 0 ? (
            <AppShellEmptyState
              title="No repository hotspots"
              body="Hotspots appear once findings can be attributed to repositories."
            />
          ) : (
            <div className="idt-github-intelligence-hotspots">
              {repositoryRows.map((row) => {
                const priorityShare = Math.round((row.criticalHigh / Math.max(row.total, 1)) * 100);
                return (
                  <Link className="idt-github-intelligence-hotspot-row" to={findingsPath} key={row.repository}>
                    <div className="idt-github-intelligence-hotspot-row-top">
                      <div className="idt-github-intelligence-hotspot-identity">
                        <SourceLogoMark provider="github" className="is-hotspot" />
                        <div>
                          <strong>{row.repository}</strong>
                          <span>{formatCountLabel(row.open, 'open finding')}</span>
                        </div>
                      </div>
                      <span className="idt-github-intelligence-hotspot-score">{row.criticalHigh}</span>
                    </div>
                    <div className="idt-github-intelligence-hotspot-meta">
                      <span>{formatCountLabel(row.total, 'total signal')}</span>
                      <span>{formatCountLabel(row.criticalHigh, 'high-priority signal')}</span>
                    </div>
                    <div className="idt-github-intelligence-hotspot-meter" aria-hidden="true">
                      <span style={{ width: `${priorityShare}%` }} />
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </aside>
      </div>

      <div className="idt-github-intelligence-main">
        <section className="idt-github-intelligence-panel idt-repo-scan-health-panel" aria-label="Repository scan health">
          <div className="idt-repo-scan-health-head">
            <div>
              <h3>Scan health</h3>
              <p>{scanHealthSummary}</p>
            </div>
            <div className="idt-repo-scan-health-actions">
              <span className={`idt-repo-scan-health-status is-${scanHealthTone}`}>
                {scanHealthStatusLabel}
              </span>
              <Link to={connectPath}>Manage scans</Link>
            </div>
          </div>
          {latestScan ? (
            <>
              <div className="idt-repo-scan-health-grid">
                <div>
                  <span>Success rate</span>
                  <strong>{scanSuccessRate === null ? 'N/A' : `${scanSuccessRate}%`}</strong>
                  <small>{formatCountLabel(completedScanCount, 'completed scan')}</small>
                </div>
                <div>
                  <span>Last completed</span>
                  <strong>{latestCompletedScan ? formatRelativeTime(latestCompletedScan.finished_at || latestCompletedScan.started_at) : 'N/A'}</strong>
                  <small>{latestCompletedScan ? formatTokenLabel(latestCompletedScan.status) : 'No finished scan'}</small>
                </div>
                <div>
                  <span>Files covered</span>
                  <strong>{totalFilesScanned.toLocaleString()}</strong>
                  <small>{formatCountLabel(scansByRecency.length, 'recent scan')}</small>
                </div>
                <div>
                  <span>Findings surfaced</span>
                  <strong>{totalScanFindings.toLocaleString()}</strong>
                  <small>{formatCountLabel(highPriorityCount, 'high priority', 'high priority')}</small>
                </div>
              </div>
              <div className="idt-repo-scan-health-timeline" aria-label="Recent repository scan events">
                {scansByRecency.slice(0, 4).map((scan) => {
                  const tone = repoScanStatusTone(scan.status);
                  const repositoryLabel = canonicalGitHubRepositoryDisplay(scan.repository) || scan.repository || 'Repository unavailable';
                  const scanTime = scan.finished_at || scan.started_at;
                  return (
                    <article key={scan.id} className={`idt-repo-scan-health-event is-${tone}`}>
                      <span className="idt-repo-scan-health-dot" aria-hidden="true" />
                      <div>
                        <strong>{repositoryLabel}</strong>
                        <span>
                          {formatTokenLabel(scan.status)} · {formatCountLabel(scan.finding_count, 'finding')} · {formatCountLabel(scan.files_scanned, 'file')}
                        </span>
                      </div>
                      <time dateTime={scanTime}>{formatRelativeTime(scanTime)}</time>
                    </article>
                  );
                })}
              </div>
            </>
          ) : (
            <AppShellEmptyState
              title="No scans yet"
              body="AI / Agentic Risk needs at least one repository scan."
            />
          )}
        </section>

        <section className="idt-github-intelligence-panel">
          <div className="idt-github-intelligence-panel-head">
            <h3>Finding trend</h3>
            <span>{trendRows.length ? formatCountLabel(trendRows.length, 'point') : 'No trend'}</span>
          </div>
          {trendError ? (
            <AppShellEmptyState
              title="Trend unavailable"
              body={trendError}
            />
          ) : trendRows.length === 0 ? (
            <AppShellEmptyState
              title="No trend yet"
              body="Trend points will appear after repository finding snapshots are available."
            />
          ) : (
            <div className="idt-github-intelligence-trend">
              {trendRows.map((row) => (
                <article key={row.key}>
                  <div>
                    <span>{row.label}</span>
                    <strong>{row.total}</strong>
                  </div>
                  <div className="idt-repo-finding-trend-bar-track" role="img" aria-label={`AI / Agentic Risk trend ${row.label}`}>
                    <div className="idt-repo-finding-trend-bar" style={{ width: `${row.percentage}%` }} />
                  </div>
                  <small>{formatCountLabel(row.priority, 'high priority', 'high priority')}</small>
                </article>
              ))}
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

export function ProductFindingsPage({ agenticOnly = false }: { agenticOnly?: boolean } = {}) {
  const location = useLocation();
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
  const [repoFindingSummary, setRepoFindingSummary] = useState<RepoFindingsSummary | null>(null);
  const [trendPoints, setTrendPoints] = useState<TrendPoint[]>([]);
  const [repoRiskGraph, setRepoRiskGraph] = useState<RepoRiskGraph | null>(null);
  const [riskGraphError, setRiskGraphError] = useState('');
  const [repoScanFilter, setRepoScanFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<(typeof REPO_FINDING_SEVERITY_FILTERS)[number]>('all');
  const [typeFilter, setTypeFilter] = useState<(typeof REPO_FINDING_TYPE_FILTERS)[number]>('all');
  const [statusFilter, setStatusFilter] = useState<(typeof REPO_FINDING_STATUS_FILTERS)[number]>('all');
  const [assigneeFilter, setAssigneeFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [minConfidenceFilter, setMinConfidenceFilter] = useState('');
  const [sortBy, setSortBy] = useState<(typeof REPO_FINDING_SORT_FIELDS)[number]>('severity');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [filtersExpanded, setFiltersExpanded] = useState(true);
  const [hierarchyOpenState, setHierarchyOpenState] = useState<{
    repositories: Set<string>;
    scans: Set<string>;
    severities: Set<string>;
    initialized: boolean;
  }>({
    repositories: new Set(),
    scans: new Set(),
    severities: new Set(),
    initialized: false
  });
  const [selectedFindingKey, setSelectedFindingKey] = useState('');
  const [findingDetailOpen, setFindingDetailOpen] = useState(false);
  const [workflowStatus, setWorkflowStatus] = useState<FindingLifecycleStatus>('open');
  const [workflowAssignee, setWorkflowAssignee] = useState('');
  const [workflowComment, setWorkflowComment] = useState('');
  const [workflowSuppressionExpiresAt, setWorkflowSuppressionExpiresAt] = useState('');
  const [workflowLoading, setWorkflowLoading] = useState(false);
  const [workflowSuccess, setWorkflowSuccess] = useState('');
  const [workflowError, setWorkflowError] = useState('');
  const [remediationPreview, setRemediationPreview] = useState<RepoFindingRemediationPreview | null>(null);
  const [remediationPreviewFindingKey, setRemediationPreviewFindingKey] = useState('');
  const [remediationPreviewLoading, setRemediationPreviewLoading] = useState(false);
  const [remediationPreviewError, setRemediationPreviewError] = useState('');
  const [remediationPublishSourceContent, setRemediationPublishSourceContent] = useState('');
  const [remediationPublishBaseBranch, setRemediationPublishBaseBranch] = useState('main');
  const [remediationPublishToken, setRemediationPublishToken] = useState('');
  const [remediationPublishApproved, setRemediationPublishApproved] = useState(false);
  const [remediationPublishWritePermsConfirmed, setRemediationPublishWritePermsConfirmed] = useState(false);
  const [remediationPublishLoading, setRemediationPublishLoading] = useState(false);
  const [remediationPublishError, setRemediationPublishError] = useState('');
  const [remediationPublishResult, setRemediationPublishResult] =
    useState<RepoFindingRemediationPublishResponse | null>(null);

  const requestRef = useRef(0);
  const signalRequestRef = useRef(0);
  const remediationPreviewRequestRef = useRef(0);
  const remediationPublishRequestRef = useRef(0);
  const findingDetailCloseRef = useRef<HTMLButtonElement | null>(null);
  const findingDetailModalRef = useRef<HTMLElement | null>(null);
  const findingDetailOpenerRef = useRef<HTMLElement | null>(null);

  const hasTriageAccess = Boolean(me?.role === 'owner' || me?.role === 'admin');

  const updateHierarchyOpenState = (
    level: 'repositories' | 'scans' | 'severities',
    key: string,
    open: boolean
  ) => {
    setHierarchyOpenState((current) => {
      if (current[level].has(key) === open) {
        return current;
      }
      const nextKeys = new Set(current[level]);
      if (open) {
        nextKeys.add(key);
      } else {
        nextKeys.delete(key);
      }
      return { ...current, [level]: nextKeys, initialized: true };
    });
  };

  const handleFindingDetailModalKeyDown = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeFindingDetail();
      return;
    }

    if (event.key !== 'Tab') {
      return;
    }

    const modal = findingDetailModalRef.current;
    if (!modal) {
      return;
    }

    const focusableElements = Array.from(modal.querySelectorAll<HTMLElement>(MODAL_FOCUSABLE_SELECTOR)).filter(
      (element) => element.getAttribute('aria-hidden') !== 'true'
    );
    if (focusableElements.length === 0) {
      event.preventDefault();
      modal.focus();
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    const activeElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusIsOutsideModal = !activeElement || !modal.contains(activeElement);

    if (event.shiftKey) {
      if (focusIsOutsideModal || activeElement === firstElement) {
        event.preventDefault();
        lastElement.focus();
      }
      return;
    }

    if (focusIsOutsideModal || activeElement === lastElement) {
      event.preventDefault();
      firstElement.focus();
    }
  };

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

  const scopedRepoFindings = useMemo(
    () => (agenticOnly ? repoFindings.filter(isAgenticRiskFinding) : repoFindings),
    [agenticOnly, repoFindings]
  );

  const filteredFindings = useMemo(() => {
    const normalizedAssigneeFilter = normalizeValue(assigneeFilter).toLowerCase();
    return scopedRepoFindings.filter((finding) => {
      const status = normalizeFindingStatus(finding.triage?.status);
      const assignee = normalizeValue(finding.triage?.assignee ?? '').toLowerCase();
      const matchesStatus = statusFilter === 'all' || status === statusFilter;
      const matchesAssignee = !normalizedAssigneeFilter || assignee.includes(normalizedAssigneeFilter);

      return matchesStatus && matchesAssignee;
    });
  }, [scopedRepoFindings, statusFilter, assigneeFilter]);

  const findingHierarchy = useMemo(
    () =>
      groupRepoFindingsByRepositoryDateSeverity(filteredFindings, {
        repositoryForFinding: (finding) =>
          canonicalGitHubRepositoryDisplay(repoFindingRepositoryValue(finding, repoScansByID)) ||
          'Repository unavailable',
        scanDateForFinding: (finding) => repoFindingScanDateLabel(finding, repoScansByID),
        scanSortValueForFinding: (finding) => repoFindingScanTimestamp(finding, repoScansByID),
        sortBy,
        sortOrder
      }),
    [filteredFindings, repoScansByID, sortBy, sortOrder]
  );

  useEffect(() => {
    if (findingHierarchy.length === 0) {
      return;
    }
    setHierarchyOpenState((current) => {
      if (current.initialized) {
        return current;
      }
      const firstRepository = findingHierarchy[0];
      const firstScan = firstRepository.scanGroups[0];
      const firstSeverity = firstScan?.severityGroups[0];
      return {
        repositories: new Set(firstRepository ? [firstRepository.key] : []),
        scans: new Set(firstScan ? [firstScan.key] : []),
        severities: new Set(firstSeverity ? [firstSeverity.key] : []),
        initialized: true
      };
    });
  }, [findingHierarchy]);

  const selectedFinding = useMemo(
    () => findRepoFindingBySelectionKey(filteredFindings, selectedFindingKey),
    [filteredFindings, selectedFindingKey]
  );

  const topRiskGraphScores = useMemo(
    () => {
      if (filteredFindings.length === 0) {
        return [];
      }
      const visibleFindingIDs = new Set(filteredFindings.map((finding) => finding.id));
      return sortRepoRiskGraphScores(repoRiskGraph?.scores ?? [])
        .filter((score) => visibleFindingIDs.has(score.finding_id))
        .slice(0, 3);
    },
    [filteredFindings, repoRiskGraph]
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
    () =>
      repoFindingSummary?.total_open ??
      filteredFindings.filter((finding) => {
        const lifecycle = normalizeRepoFindingLifecycleStatus(finding.lifecycle_status);
        return lifecycle === 'open' || lifecycle === 'reopened';
      }).length,
    [filteredFindings, repoFindingSummary?.total_open]
  );

  const slaAgedFindingCount = repoFindingSummary?.sla_aged_count ?? 0;
  const mttrSeconds = repoFindingSummary?.mean_time_to_resolve_seconds;
  const mttrLabel = typeof mttrSeconds === 'number' && Number.isFinite(mttrSeconds) ? formatExecutiveDuration(mttrSeconds) : 'N/A';

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
      const sourceFilterValue = normalizeValue(sourceFilter).toLowerCase();
      const normalizedMinConfidence = Number.parseFloat(normalizeValue(minConfidenceFilter));
      const repoFindingRequest = {
        repo_scan_id: normalizeValue(repoScanFilter) || undefined,
        severity: severityFilter !== 'all' ? severityFilter : undefined,
        type: typeFilter !== 'all' ? typeFilter : undefined,
        source: sourceFilterValue || undefined,
        assignee: normalizeValue(assigneeFilter) || undefined,
        min_confidence: Number.isFinite(normalizedMinConfidence) ? normalizedMinConfidence : undefined,
        sort_by: sortBy,
        sort_order: sortOrder
      };

      const [repoScanResponse, repoFindingResponse] = await Promise.all([
        apiClient.listRepoScans({ limit: 50 }, auth),
        agenticOnly
          ? listAIRisksRepoFindings(auth, repoFindingRequest)
          : apiClient.listRepoFindings(
              {
                ...repoFindingRequest,
                limit: 100,
                lifecycle_status: statusFilter !== 'all' ? statusFilter : undefined
              },
              auth
            )
      ]);
      if (requestID !== requestRef.current) {
        return;
      }
      setRepoScans(repoScanResponse.items);
      if (agenticOnly) {
        if (!Array.isArray(repoFindingResponse)) {
          return;
        }
        setRepoFindings(repoFindingResponse);
        setRepoFindingSummary(null);
      } else {
        if (Array.isArray(repoFindingResponse)) {
          return;
        }
        setRepoFindings(repoFindingResponse.items);
        setRepoFindingSummary(repoFindingResponse.summary ?? null);
      }
    } catch (requestError) {
      if (requestID !== requestRef.current) {
        return;
      }
      setError(formatAPIError(requestError, 'Failed to load repository findings.'));
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
    setRiskGraphError('');
    try {
      const auth = buildProductAuthContext(targetScope);
      const severity = severityFilter !== 'all' ? severityFilter : undefined;
      const type = typeFilter !== 'all' ? typeFilter : undefined;
      const repoScanID = normalizeValue(repoScanFilter) || undefined;
      const [trendResult, riskGraphResult] = await Promise.allSettled([
        apiClient.getRepoFindingsTrends(
          {
            points: TREND_POINTS,
            severity,
            type
          },
          auth
        ),
        apiClient.getRepoRiskGraph(
          {
            repo_scan_id: repoScanID,
            severity,
            type
          },
          auth
        )
      ]);
      if (requestID !== signalRequestRef.current) {
        return;
      }
      if (trendResult.status === 'fulfilled') {
        setTrendPoints(trendResult.value.items);
      } else {
        setTrendPoints([]);
        setTrendError(
          trendResult.reason instanceof Error ? trendResult.reason.message : 'Failed to load finding trend metrics.'
        );
      }
      if (riskGraphResult.status === 'fulfilled') {
        setRepoRiskGraph(riskGraphResult.value);
      } else {
        setRepoRiskGraph(null);
        setRiskGraphError(
          riskGraphResult.reason instanceof Error
            ? riskGraphResult.reason.message
            : 'Failed to load repository risk graph.'
        );
      }
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
    const enteringSuppression = currentStatus !== 'suppressed' && trackingSuppression;
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
      const trimmedComment = normalizeValue(workflowComment);
      if (enteringSuppression && !trimmedComment) {
        setWorkflowError('Suppression requires a reason.');
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

  const handleLoadRemediationPreview = async () => {
    if (!scope || !selectedFinding || remediationPreviewLoading) {
      return;
    }

    const selectionKey = buildRepoFindingSelectionKey(selectedFinding);
    const requestID = ++remediationPreviewRequestRef.current;
    setRemediationPreviewLoading(true);
    setRemediationPreviewError('');
    setRemediationPreview(null);
    setRemediationPreviewFindingKey(selectionKey);
    try {
      const sourceContent = remediationPublishSourceContent.trim();
      const previewRequest = {
        repo_scan_id: selectedFinding.scan_id,
        ...(sourceContent
          ? {
              source_content: sourceContent,
              require_fix_plan: true
            }
          : {})
      };
      const preview = await apiClient.previewRepoFindingRemediation(
        selectedFinding.id,
        previewRequest,
        buildProductAuthContext(scope)
      );
      if (requestID !== remediationPreviewRequestRef.current) {
        return;
      }
      setRemediationPreview(preview);
      setRemediationPublishBaseBranch(preview.fix_pr_plan?.base_branch || remediationPublishBaseBranch || 'main');
    } catch (requestError) {
      if (requestID !== remediationPreviewRequestRef.current) {
        return;
      }
      setRemediationPreview(null);
      setRemediationPreviewError(
        requestError instanceof Error ? requestError.message : 'Failed to load remediation preview.'
      );
    } finally {
      if (requestID === remediationPreviewRequestRef.current) {
        setRemediationPreviewLoading(false);
      }
    }
  };

  const resetRemediationPublishState = () => {
    setRemediationPublishSourceContent('');
    setRemediationPublishBaseBranch('main');
    setRemediationPublishToken('');
    setRemediationPublishApproved(false);
    setRemediationPublishWritePermsConfirmed(false);
    setRemediationPublishLoading(false);
    setRemediationPublishError('');
    setRemediationPublishResult(null);
  };

  // Changing (or clearing) the selected finding must invalidate any in-flight
  // remediation preview/publish requests synchronously, on the transition
  // itself, so a slow response cannot land on a newly selected finding. Bumping
  // the guards here closes the race window that exists if invalidation is left
  // to a post-render effect.
  const selectRepoFinding = (key: string, openDetail = true, opener: HTMLElement | null = null) => {
    remediationPreviewRequestRef.current += 1;
    remediationPublishRequestRef.current += 1;
    const willOpenDialog = Boolean(key) && openDetail;
    if (willOpenDialog) {
      findingDetailOpenerRef.current =
        opener ??
        (typeof document !== 'undefined' && document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null);
    }
    setSelectedFindingKey(key);
    setFindingDetailOpen(willOpenDialog);
  };

  const handlePublishRemediation = async () => {
    if (!scope || !selectedFinding || !activeRemediationPreview || remediationPublishLoading) {
      return;
    }

    const sourceContent = remediationPublishSourceContent;
    const token = remediationPublishToken.trim();
    if (!sourceContent.trim()) {
      setRemediationPublishError('Current source content is required.');
      return;
    }
    if (!remediationPublishApproved) {
      setRemediationPublishError('Operator approval is required.');
      return;
    }
    if (!remediationPublishWritePermsConfirmed) {
      setRemediationPublishError('Confirm the GitHub token is intentionally write-capable.');
      return;
    }
    if (!token) {
      setRemediationPublishError('A write-capable GitHub token is required.');
      return;
    }

    // The selection-change effect bumps remediationPublishRequestRef, so a
    // finding/scope switch (or a newer publish) invalidates this request.
    const requestID = ++remediationPublishRequestRef.current;
    const isStale = () => requestID !== remediationPublishRequestRef.current;
    setRemediationPublishLoading(true);
    setRemediationPublishError('');
    setRemediationPublishResult(null);
    try {
      const response = await apiClient.publishRepoFindingRemediation(
        selectedFinding.id,
        {
          repo_scan_id: selectedFinding.scan_id,
          source_content: sourceContent,
          base_branch: remediationPublishBaseBranch.trim() || undefined,
          finding_url: selectedFinding.source_url || undefined,
          operator_approved: remediationPublishApproved,
          write_permissions_configured: remediationPublishWritePermsConfirmed,
          github_token: token
        },
        buildProductAuthContext(scope)
      );
      if (isStale()) {
        return;
      }
      setRemediationPublishResult(response);
      setRemediationPublishToken('');
      setRemediationPublishApproved(false);
      setRemediationPublishWritePermsConfirmed(false);
    } catch (requestError) {
      if (isStale()) {
        return;
      }
      setRemediationPublishError(
        requestError instanceof Error ? requestError.message : 'Failed to publish remediation PR.'
      );
    } finally {
      if (requestID === remediationPublishRequestRef.current) {
        setRemediationPublishLoading(false);
      }
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
    sourceFilter,
    minConfidenceFilter,
    sortBy,
    sortOrder
  ]);

  useEffect(() => {
    if (!selectedFinding) {
      setWorkflowStatus('open');
      setWorkflowAssignee('');
      setWorkflowComment('');
      setWorkflowSuppressionExpiresAt('');
      remediationPreviewRequestRef.current += 1;
      remediationPublishRequestRef.current += 1;
      setRemediationPreview(null);
      setRemediationPreviewFindingKey('');
      setRemediationPreviewLoading(false);
      setRemediationPreviewError('');
      resetRemediationPublishState();
      return;
    }

    setWorkflowStatus(normalizeFindingStatus(selectedFinding.triage?.status));
    setWorkflowAssignee(selectedFinding.triage?.assignee ?? '');
    setWorkflowComment('');
    setWorkflowSuppressionExpiresAt(
      selectedFinding.triage?.suppression_expires_at ? toLocalDateTimeInputValue(selectedFinding.triage.suppression_expires_at) : ''
    );
    remediationPreviewRequestRef.current += 1;
    remediationPublishRequestRef.current += 1;
    setRemediationPreview(null);
    setRemediationPreviewFindingKey('');
    setRemediationPreviewLoading(false);
    setRemediationPreviewError('');
    resetRemediationPublishState();
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
        selectRepoFinding('', false);
      }
      return;
    }
    if (selectedFindingKey && !findRepoFindingBySelectionKey(filteredFindings, selectedFindingKey)) {
      selectRepoFinding('', false);
    }
  }, [filteredFindings, selectedFindingKey]);

  useEffect(() => {
    if (!findingDetailOpen || typeof document === 'undefined') {
      return undefined;
    }
    const root = document.documentElement;
    const previousOverflow = root.style.overflow;
    root.style.overflow = 'hidden';
    return () => {
      root.style.overflow = previousOverflow;
    };
  }, [findingDetailOpen]);

  useEffect(() => {
    if (!findingDetailOpen || typeof window === 'undefined') {
      return undefined;
    }
    const frame = window.requestAnimationFrame(() => {
      findingDetailCloseRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [findingDetailOpen, selectedFindingKey]);

  const closeFindingDetail = () => {
    setFindingDetailOpen(false);
    if (typeof document === 'undefined') {
      return;
    }
    const opener = findingDetailOpenerRef.current;
    findingDetailOpenerRef.current = null;
    if (opener && document.contains(opener) && typeof opener.focus === 'function') {
      opener.focus();
    }
  };

  if (!scope) {
    return (
      <section className="idt-app-panel idt-app-panel-error">
        <p className="idt-app-kicker">GitHub findings</p>
        <h2>GitHub findings</h2>
        <p>Workspace route context is missing.</p>
      </section>
    );
  }

  if (loading) {
    return (
      <AppRouteLoadingState
        title="Preparing GitHub findings"
        body="Refreshing finding and trend data for this workspace."
      />
    );
  }

  const handleRefresh = () => {
    void loadRepoFindings(scope, 'refresh');
    void loadTrendSignals(scope, 'refresh');
  };

  const connectPath = buildScopedPath(scope, 'github/connect');
  const remediationPath = appendEnvironmentQuery(
    buildScopedPath(scope, 'github/remediation'),
    environmentIDFromSearch(location.search)
  );
  const scansByRecency = [...repoScans].sort(
    (left, right) => new Date(right.started_at).getTime() - new Date(left.started_at).getTime()
  );
  const succeededScanCount = repoScans.filter((scan) => repoScanStatusTone(scan.status) === 'success').length;
  const failedScans = scansByRecency.filter((scan) => isFailedScanStatus(scan.status));
  const latestScan = scansByRecency[0] ?? null;
  const latestFailedScan = failedScans[0] ?? null;
  const hasQueuedOrRunningScan = scansByRecency.some((scan) => isActiveScanStatus(scan.status));
  const latestScanSucceeded = latestScan ? repoScanStatusTone(latestScan.status) === 'success' : false;
  const latestScanFailed = latestScan ? isFailedScanStatus(latestScan.status) : false;
  const neverScanned = repoScans.length === 0;
  // "Has findings" must be independent of both active finding filters and the
  // recent-scan window (listRepoScans is capped). Combine the server-side
  // lifecycle summary (uncapped, the authoritative signal) with the loaded list
  // and per-scan finding counts so the all-failed empty state never triggers
  // while findings exist anywhere in history.
  const summaryFindingTotal = repoFindingSummary
    ? repoFindingSummary.total_open +
      repoFindingSummary.fixed_count +
      repoFindingSummary.reopened_count +
      repoFindingSummary.suppressed_count
    : 0;
  const hasRepoFindings =
    summaryFindingTotal > 0 ||
    repoFindings.length > 0 ||
    repoScans.some((scan) => (scan.finding_count ?? 0) > 0);
  const allScansFailed = !neverScanned && !hasQueuedOrRunningScan && !hasRepoFindings && succeededScanCount === 0 && latestScanFailed;
  const filtersActive =
    normalizeValue(repoScanFilter) !== '' ||
    severityFilter !== 'all' ||
    typeFilter !== 'all' ||
    statusFilter !== 'all' ||
    normalizeValue(assigneeFilter) !== '' ||
    normalizeValue(sourceFilter) !== '' ||
    normalizeValue(minConfidenceFilter) !== '';

  const formatScanDate = (scan: RepoScanRecord | null): string => {
    if (!scan) {
      return '';
    }
    const when = new Date(scan.finished_at || scan.started_at);
    return Number.isNaN(when.getTime()) ? '' : when.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  };

  const describeScanFailure = (scan: RepoScanRecord | null): string => {
    if (!scan) {
      return 'The scan did not complete.';
    }
    const parts = [summarizeScanFailure(scan)];
    const repository = canonicalGitHubRepositoryDisplay(scan.repository);
    if (repository) {
      parts.push(repository);
    }
    const when = formatScanDate(scan);
    if (when) {
      parts.push(when);
    }
    return parts.join(' · ');
  };

  // Distinct empty/failed states: never showing the populated dashboard chrome
  // (KPI grid, risk graph, trend, filters) filled with zeros when no scan has
  // produced findings. A failed-only state surfaces the failure instead of
  // silently rendering zeros.
  if (neverScanned || allScansFailed) {
    return (
      <section className="idt-app-panel idt-repo-findings-page">
        <div className="idt-repo-findings-header">
          <div>
            <h2>GitHub findings</h2>
          </div>
          <div className="idt-inline-actions">
            <Link className="idt-btn idt-btn-primary" to={remediationPath}>
              Open remediation
            </Link>
            <button
              className="idt-btn idt-btn-ghost"
              type="button"
              onClick={handleRefresh}
              disabled={refreshing || signalsRefreshing}
            >
              {refreshing || signalsRefreshing ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>

        {error ? <div className="idt-app-alert idt-app-alert-error">{error}</div> : null}

        {neverScanned ? (
          <AppShellEmptyState
            title="Run your first repository scan"
            body="Scan a connected repository to surface risky trust paths, exposed secrets, and authorization gaps — then jump straight to the exact GitHub line."
            action={{ label: 'Connect GitHub', to: connectPath }}
          />
        ) : (
          <article className="idt-app-empty-state idt-repo-scan-failure-state">
            <h2>Your last repository scan failed</h2>
            <p>{describeScanFailure(latestFailedScan)}</p>
            <div className="idt-inline-actions">
              <Link className="idt-app-empty-state-action" to={connectPath}>
                Review &amp; re-run scan
              </Link>
              <button
                className="idt-btn idt-btn-ghost"
                type="button"
                onClick={handleRefresh}
                disabled={refreshing || signalsRefreshing}
              >
                {refreshing || signalsRefreshing ? 'Refreshing...' : 'Refresh'}
              </button>
            </div>
          </article>
        )}
      </section>
    );
  }

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
  const riskGraphSummary = repoRiskGraph?.summary;
  const riskGraphUnknownEvidenceCount =
    (riskGraphSummary?.unknown_node_count ?? 0) + (riskGraphSummary?.unknown_edge_count ?? 0);
  const selectedFindingPreviewKey = selectedFinding ? buildRepoFindingSelectionKey(selectedFinding) : '';
  const activeRemediationPreview =
    remediationPreview && remediationPreviewFindingKey === selectedFindingPreviewKey ? remediationPreview : null;

  return (
    <section className="idt-app-panel idt-repo-findings-page">
      <div className="idt-repo-findings-header">
        <div>
          <h2>GitHub findings</h2>
        </div>
        <div className="idt-inline-actions">
          <Link className="idt-btn idt-btn-primary" to={remediationPath}>
            Open remediation
          </Link>
          <button
            className="idt-btn idt-btn-ghost"
            type="button"
            onClick={handleRefresh}
            disabled={refreshing || signalsRefreshing}
          >
            {refreshing || signalsRefreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {error ? <div className="idt-app-alert idt-app-alert-error">{error}</div> : null}
      {signalError ? <div className="idt-app-alert idt-app-alert-error">{signalError}</div> : null}
      {trendError ? <div className="idt-app-alert idt-app-alert-error">{trendError}</div> : null}
      {riskGraphError ? <div className="idt-app-alert idt-app-alert-error">{riskGraphError}</div> : null}

      {latestScanFailed ? (
        <div className="idt-app-alert idt-app-alert-error idt-repo-scan-health">
          <span>Last scan failed: {describeScanFailure(latestFailedScan)}</span>
          <Link to={connectPath}>Review &amp; re-run</Link>
        </div>
      ) : null}

      <div className="idt-repo-finding-stats" aria-label="Repository finding summary">
        <article className="idt-repo-finding-stat">
          <span>Open findings</span>
          <strong>{openFindingCount}</strong>
        </article>
        <article className="idt-repo-finding-stat">
          <span>Critical findings</span>
          <strong>{criticalFindingCount}</strong>
          {slaAgedFindingCount > 0 ? <small className="idt-repo-finding-stat-note">SLA-aged {slaAgedFindingCount}</small> : null}
        </article>
        <article className="idt-repo-finding-stat">
          <span>Mean time to fix</span>
          <strong>{mttrLabel}</strong>
        </article>
        <article className="idt-repo-finding-stat">
          <span>Completed scans</span>
          <strong>{activeScanCount}</strong>
        </article>
      </div>

      {filteredFindings.length > 0 || filtersActive ? (
        <details
          className="idt-repo-filter-panel"
          aria-label="Repository finding filters and sorting"
          open={filtersExpanded}
          onToggle={(event) => setFiltersExpanded(event.currentTarget.open)}
        >
          <summary className="idt-repo-filter-panel-header">
            <span>Filters and sorting</span>
          </summary>
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
            <label>
              Source
              <input
                type="text"
                placeholder="Source name"
                value={sourceFilter}
                onChange={(event) => setSourceFilter(event.target.value)}
              />
            </label>
            <label>
              Min confidence
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                placeholder="e.g. 0.7"
                value={minConfidenceFilter}
                onChange={(event) => setMinConfidenceFilter(event.target.value)}
              />
            </label>
          </div>
        </details>
      ) : null}

      <div className="idt-repo-finding-layout">
        <div className="idt-repo-finding-list">
          <div className="idt-repo-finding-list-header">
            <h3>Repository findings</h3>
          </div>
          {findingHierarchy.length === 0 ? (
            filtersActive ? (
              <AppShellEmptyState
                title="No findings match these filters"
                body="Loosen the current filters to inspect GitHub-linked findings from your scans."
              />
            ) : latestScanSucceeded ? (
              <AppShellEmptyState
                title="No exposure found"
                body="Your latest repository scan completed and surfaced no findings. New findings will appear here after the next scan."
              />
            ) : (
              <AppShellEmptyState
                title="No completed scan results"
                body="No completed scan has surfaced findings yet. New findings will appear here after the next successful scan."
              />
            )
          ) : (
            <div className="idt-repo-finding-hierarchy">
              {findingHierarchy.map((repositoryGroup, repositoryIndex) => {
                const criticalCount = repositoryGroup.findings.filter(
                  (finding) => normalizeValue(finding.severity).toLowerCase() === 'critical'
                ).length;
                const highCount = repositoryGroup.findings.filter(
                  (finding) => normalizeValue(finding.severity).toLowerCase() === 'high'
                ).length;
                const latestScanLabel =
                  [...repositoryGroup.scanGroups].sort((left, right) => right.sortValue - left.sortValue)[0]?.label ??
                  'Scan date unavailable';

                return (
                  <details
                    className="idt-repo-finding-bucket idt-repo-finding-repository"
                    key={repositoryGroup.key}
                    open={hierarchyOpenState.repositories.has(repositoryGroup.key)}
                    onToggle={(event) =>
                      updateHierarchyOpenState('repositories', repositoryGroup.key, event.currentTarget.open)
                    }
                  >
                    <summary className="idt-repo-repository-summary">
                      <span className="idt-repo-summary-main">
                        <span className="idt-repo-summary-icon" aria-hidden="true">
                          <FolderKanban size={18} strokeWidth={2} />
                        </span>
                        <span>
                          <strong>{repositoryGroup.label}</strong>
                        </span>
                      </span>
                      <span className="idt-repo-summary-metrics" aria-label="Repository finding summary">
                        <span>
                          <strong>{repositoryGroup.findings.length}</strong>
                          <small>Findings</small>
                        </span>
                        <span>
                          <strong>{criticalCount + highCount}</strong>
                          <small>High risk</small>
                        </span>
                        <span>
                          <strong>{latestScanLabel}</strong>
                          <small>Latest scan</small>
                        </span>
                      </span>
                    </summary>
                    <div className="idt-repo-finding-bucket-body idt-repo-scan-timeline">
                      {repositoryGroup.scanGroups.map((scanGroup, scanIndex) => (
                        <details
                          className="idt-repo-finding-bucket idt-repo-finding-scan"
                          key={scanGroup.key}
                          open={hierarchyOpenState.scans.has(scanGroup.key)}
                          onToggle={(event) =>
                            updateHierarchyOpenState('scans', scanGroup.key, event.currentTarget.open)
                          }
                        >
                          <summary className="idt-repo-scan-summary">
                            <span className="idt-repo-scan-node" aria-hidden="true" />
                            <span className="idt-repo-scan-copy">
                              <strong>{scanGroup.label}</strong>
                            </span>
                            <span className="idt-repo-scan-meta">
                              <span>{scanGroup.findings.length} findings</span>
                            </span>
                          </summary>
                          <div className="idt-repo-finding-bucket-body idt-repo-severity-lanes">
                            {scanGroup.severityGroups.map((severityGroup, severityIndex) => (
                              <details
                                className={`idt-repo-finding-bucket idt-repo-finding-severity-group is-${severityGroup.label}`}
                                key={severityGroup.key}
                                open={hierarchyOpenState.severities.has(severityGroup.key)}
                                onToggle={(event) =>
                                  updateHierarchyOpenState('severities', severityGroup.key, event.currentTarget.open)
                                }
                              >
                                <summary className="idt-repo-severity-summary">
                                  <span className="idt-repo-severity-copy">
                                    <span className={repoFindingSeverityClass(severityGroup.label)}>
                                      {formatTokenLabel(severityGroup.label)}
                                    </span>
                                  </span>
                                  <span className="idt-repo-severity-count">
                                    <strong>{severityGroup.findings.length}</strong>
                                    <small>findings</small>
                                  </span>
                                </summary>
                                <div className="idt-repo-finding-items" role="list">
                                  {severityGroup.findings.map((finding) => {
                                    const repositoryValue = repoFindingRepositoryValue(finding, repoScansByID);
                                    const repositoryLabel =
                                      canonicalGitHubRepositoryDisplay(repositoryValue) || 'Repository unavailable';
                                    const selectionKey = buildRepoFindingSelectionKey(finding);
                                    const isSelected = selectedFindingKey === selectionKey;
                                    const lifecycle = normalizeRepoFindingLifecycleStatus(finding.lifecycle_status);
                                    return (
                                      <button
                                        key={selectionKey}
                                        type="button"
                                        role="listitem"
                                        aria-haspopup="dialog"
                                        className={`idt-repo-finding-row${isSelected ? ' is-selected' : ''}`}
                                        onClick={(event) => selectRepoFinding(selectionKey, true, event.currentTarget)}
                                      >
                                        <SourceLogoMark provider="github" className="is-row" />
                                        <div className="idt-repo-finding-row-copy">
                                          <div className="idt-repo-finding-row-top">
                                            <strong>{finding.title}</strong>
                                            <span className={repoFindingSeverityClass(finding.severity)}>
                                              {formatTokenLabel(finding.severity)}
                                            </span>
                                          </div>
                                          <div className="idt-repo-finding-row-meta">
                                            <span>{repositoryLabel}</span>
                                            <span>{repoFindingLocationLabel(finding)}</span>
                                            <span>{formatTokenLabel(finding.type)}</span>
                                            <span className={repoFindingStatusClass(lifecycle)}>{formatTokenLabel(lifecycle)}</span>
                                            <span>{finding.owner || finding.triage?.assignee || 'Unassigned'}</span>
                                          </div>
                                        </div>
                                      </button>
                                    );
                                  })}
                                </div>
                              </details>
                            ))}
                          </div>
                        </details>
                      ))}
                    </div>
                  </details>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {findingDetailOpen && selectedFinding ? (
        <div
          className="idt-modal-backdrop idt-repo-finding-modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              closeFindingDetail();
            }
          }}
        >
          <section
            aria-modal="true"
            aria-labelledby="repo-finding-detail-title"
            className="idt-repo-finding-detail-modal"
            ref={findingDetailModalRef}
            role="dialog"
            tabIndex={-1}
            onKeyDown={handleFindingDetailModalKeyDown}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <header className="idt-repo-finding-detail-modal-header">
              <div className="idt-source-config-title">
                <SourceLogoMark provider="github" className="is-hero" />
                <div>
                  <p className="idt-app-kicker">Finding detail</p>
                  <h3 id="repo-finding-detail-title">{selectedFinding.title}</h3>
                  <p>{selectedFinding.human_summary}</p>
                </div>
              </div>
              <button
                ref={findingDetailCloseRef}
                className="idt-esc-close idt-repo-finding-modal-close"
                type="button"
                aria-label="Close finding detail"
                autoFocus
                onClick={() => closeFindingDetail()}
              >
                ESC
              </button>
            </header>

            <div className="idt-repo-finding-detail-modal-body">
              <div className="idt-repo-finding-detail-pills" aria-label="Finding status summary">
                <span className={repoFindingSeverityClass(selectedFinding.severity)}>
                  {formatTokenLabel(selectedFinding.severity)}
                </span>
                <span className={repoFindingStatusClass(normalizeRepoFindingLifecycleStatus(selectedFinding.lifecycle_status))}>
                  {formatTokenLabel(normalizeRepoFindingLifecycleStatus(selectedFinding.lifecycle_status))}
                </span>
                <span>{`Confidence ${formatConfidenceScore(selectedFinding.confidence_score)}`}</span>
              </div>

              <dl className="idt-repo-finding-facts">
                <div>
                  <dt>Repository</dt>
                  <dd>{canonicalGitHubRepositoryDisplay(repoFindingRepositoryValue(selectedFinding, repoScansByID)) || 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Scan date</dt>
                  <dd>{repoFindingScanDateLabel(selectedFinding, repoScansByID)}</dd>
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
                  <dt>Owner</dt>
                  <dd>{selectedFinding.owner || selectedFinding.triage?.assignee || 'Unassigned'}</dd>
                </div>
                <div>
                  <dt>Triage status</dt>
                  <dd>{formatTokenLabel(normalizeFindingStatus(selectedFinding.triage?.status))}</dd>
                </div>
                <div>
                  <dt>First seen</dt>
                  <dd>{selectedFinding.first_seen_at ? formatDateLabel(selectedFinding.first_seen_at) : formatDateLabel(selectedFinding.created_at)}</dd>
                </div>
                <div>
                  <dt>Last seen</dt>
                  <dd>{selectedFinding.last_seen_at ? formatDateLabel(selectedFinding.last_seen_at) : formatDateLabel(selectedFinding.created_at)}</dd>
                </div>
                <div>
                  <dt>Fixed at</dt>
                  <dd>{selectedFinding.fixed_at ? formatDateLabel(selectedFinding.fixed_at) : 'Not fixed yet'}</dd>
                </div>
                <div>
                  <dt>Detector</dt>
                  <dd>{selectedFinding.detector ? formatTokenLabel(selectedFinding.detector) : 'Unavailable'}</dd>
                </div>
                <div>
                  <dt>Last triage update</dt>
                  <dd>{selectedFinding.triage?.updated_at ? formatDateLabel(selectedFinding.triage.updated_at) : 'Never'}</dd>
                </div>
                <div>
                  <dt>Source</dt>
                  <dd>{selectedFinding.adapter_source || 'native'}</dd>
                </div>
              </dl>

              <section className="idt-repo-finding-detail-section">
                <div className="idt-repo-finding-section-head">
                  <div>
                    <h4>Evidence</h4>
                    <p>{repoFindingLocationLabel(selectedFinding)}</p>
                  </div>
                  {selectedFinding.source_url ? (
                    <a className="idt-btn idt-btn-primary" href={selectedFinding.source_url} target="_blank" rel="noreferrer">
                      <ExternalLink size={14} strokeWidth={2} aria-hidden="true" />
                      Open in GitHub
                    </a>
                  ) : null}
                </div>
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
              </section>

              <section className="idt-repo-finding-detail-section idt-repo-finding-remediation">
                <h4>Remediation</h4>
                <p>{selectedFinding.remediation}</p>
                <button
                  className="idt-btn idt-btn-ghost"
                  type="button"
                  onClick={() => void handleLoadRemediationPreview()}
                  disabled={remediationPreviewLoading}
                >
                  {remediationPreviewLoading ? 'Loading remediation...' : 'Preview remediation plan'}
                </button>
                {remediationPreviewError ? (
                  <div className="idt-app-alert idt-app-alert-error">{remediationPreviewError}</div>
                ) : null}
                {activeRemediationPreview ? (
                  <div className="idt-repo-remediation-preview">
                    <h5>{activeRemediationPreview.remediation.summary}</h5>
                    <p>{activeRemediationPreview.remediation.risk_summary}</p>
                    <div className="idt-repo-remediation-preview-grid">
                      <div>
                        <strong>Steps</strong>
                        <ul>
                          {(activeRemediationPreview.remediation.steps ?? []).map((step) => (
                            <li key={step}>{step}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <strong>Validation</strong>
                        <ul>
                          {(activeRemediationPreview.remediation.validation ?? []).map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                    {(activeRemediationPreview.remediation.safety_notes ?? []).length > 0 ? (
                      <div>
                        <strong>Safety notes</strong>
                        <ul>
                          {(activeRemediationPreview.remediation.safety_notes ?? []).map((note) => (
                            <li key={note}>{note}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                    <p>
                      {activeRemediationPreview.remediation.publishable
                        ? 'A deterministic fix branch can be prepared for this finding.'
                        : activeRemediationPreview.remediation.publish_blocked_reason || 'Manual remediation is required.'}
                    </p>
                    {activeRemediationPreview.remediation.publishable ? (
                      <div className="idt-repo-remediation-publish">
                        {remediationPublishError ? (
                          <div className="idt-app-alert idt-app-alert-error">{remediationPublishError}</div>
                        ) : null}
                        {remediationPublishResult ? (
                          <div className="idt-app-alert idt-app-alert-success">
                            PR #{remediationPublishResult.publish.pr_number} opened on{' '}
                            {remediationPublishResult.publish.branch_name}.{' '}
                            <a href={remediationPublishResult.publish.pr_url} target="_blank" rel="noreferrer">
                              View PR
                            </a>
                          </div>
                        ) : null}
                        <label>
                          Base branch
                          <input
                            type="text"
                            value={remediationPublishBaseBranch}
                            onChange={(event) => setRemediationPublishBaseBranch(event.target.value)}
                            placeholder="main"
                          />
                        </label>
                        <label>
                          Current source content
                          <textarea
                            value={remediationPublishSourceContent}
                            onChange={(event) => setRemediationPublishSourceContent(event.target.value)}
                            rows={6}
                            spellCheck={false}
                          />
                        </label>
                        <label>
                          GitHub token
                          <input
                            type="password"
                            value={remediationPublishToken}
                            onChange={(event) => setRemediationPublishToken(event.target.value)}
                            autoComplete="off"
                          />
                        </label>
                        <label className="idt-repo-remediation-approval">
                          <input
                            type="checkbox"
                            checked={remediationPublishApproved}
                            onChange={(event) => setRemediationPublishApproved(event.target.checked)}
                          />
                          <span>Approved for publish</span>
                        </label>
                        <label className="idt-repo-remediation-approval">
                          <input
                            type="checkbox"
                            checked={remediationPublishWritePermsConfirmed}
                            onChange={(event) =>
                              setRemediationPublishWritePermsConfirmed(event.target.checked)
                            }
                          />
                          <span>GitHub token is intentionally write-capable</span>
                        </label>
                        <button
                          className="idt-btn"
                          type="button"
                          onClick={() => void handlePublishRemediation()}
                          disabled={
                            remediationPublishLoading ||
                            !remediationPublishApproved ||
                            !remediationPublishWritePermsConfirmed
                          }
                        >
                          {remediationPublishLoading ? 'Publishing...' : 'Publish fix PR'}
                        </button>
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </section>

              <section className="idt-repo-finding-detail-section idt-repo-finding-triage-form">
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
              </section>
            </div>
          </section>
        </div>
      ) : null}

      <details className="idt-repo-finding-trend idt-repo-analysis-panel" aria-label="Repository risk graph summary">
        <summary className="idt-repo-finding-trend-head">
          <h3>Risk graph</h3>
          {trendDisplayLoading ? <span className="idt-app-alert idt-app-alert-success">Loading graph</span> : null}
          <span className="idt-repo-finding-trend-subtitle">
            {repoRiskGraph
              ? `${repoRiskGraph.nodes.length} nodes · ${repoRiskGraph.edges.length} paths · ${canonicalGitHubRepositoryDisplay(repoRiskGraph.repository) || repoRiskGraph.repository || 'repository scope'}`
              : 'No graph loaded yet'}
          </span>
        </summary>
        {riskGraphSummary ? (
          <div className="idt-repo-finding-trend-rows">
            <article className="idt-repo-finding-trend-row">
              <div className="idt-repo-finding-trend-meta">
                <span>High-risk findings</span>
                <strong>{riskGraphSummary.high_risk_findings}</strong>
              </div>
              <p>
                {riskGraphSummary.critical_findings} critical · {riskGraphUnknownEvidenceCount} unknown evidence gaps
              </p>
            </article>
            {topRiskGraphScores.length > 0 ? (
              topRiskGraphScores.map((score) => (
                <article key={score.finding_id} className="idt-repo-finding-trend-row">
                  <div className="idt-repo-finding-trend-meta">
                    <span>{score.finding_id}</span>
                    <strong>{Math.round(score.score)}</strong>
                  </div>
                  <p>
                    {formatTokenLabel(score.severity)} · confidence {formatConfidenceScore(score.confidence)}
                    {(score.unknowns ?? []).length > 0
                      ? ` · unknown ${(score.unknowns ?? []).map(formatTokenLabel).join(', ')}`
                      : ''}
                  </p>
                </article>
              ))
            ) : (
              <article className="idt-repo-finding-trend-row">
                <div className="idt-repo-finding-trend-meta">
                  <span>No scored findings</span>
                  <strong>{riskGraphSummary.finding_count}</strong>
                </div>
                <p>Risk scores will appear after graph evidence is available for repository findings.</p>
              </article>
            )}
          </div>
        ) : (
          <AppShellEmptyState
            title="Risk graph unavailable"
            body="Run a repository exposure scan so machine-identity paths and finding risk scores can appear here."
          />
        )}
      </details>

      <details className="idt-repo-finding-trend idt-repo-analysis-panel">
        <summary className="idt-repo-finding-trend-head">
          <h3>Finding trend</h3>
          {trendDisplayLoading ? <span className="idt-app-alert idt-app-alert-success">Loading trend</span> : null}
          <span className="idt-repo-finding-trend-subtitle">{totalTrendItems > 0 ? `${totalTrendItems} total events in window` : 'No trend items yet'}</span>
        </summary>
        <div className="idt-repo-finding-trend-rows">
          {totalTrendItems === 0 ? (
            <AppShellEmptyState
              title="No trend yet"
              body="Trend snapshots with severity distribution will appear here once a scan produces findings."
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
      </details>
    </section>
  );
}

// requestDataExport drives the "Download my data" lifecycle (#1421): enqueue
// the export job, then poll until the bundle reaches a terminal state.
type ExportSetters = {
  signal: AbortSignal;
  setExportPending: (value: boolean) => void;
  setExportError: (value: string) => void;
  setExportStatus: (
    value:
      | { kind: 'idle' }
      | { kind: 'preparing'; message: string }
      | { kind: 'ready'; downloadURL: string; expiresAt?: string }
  ) => void;
};

function resolveDataExportDownloadURL(downloadURL: string): string {
  if (/^https?:\/\//i.test(downloadURL)) {
    return downloadURL;
  }
  return buildAPIURL(downloadURL);
}

function exportAbortError(): Error {
  const err = new Error('Data export polling was canceled.');
  err.name = 'AbortError';
  return err;
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === 'AbortError';
}

function formatDataExportError(err: unknown): string {
  if (
    err instanceof ApiError &&
    ((err.status === 404 && err.payload === undefined) ||
      (err.status === 503 && /data export is not configured/i.test(err.message)))
  ) {
    return 'Data export is not available on this deployment yet.';
  }
  return err instanceof Error ? err.message : 'Unable to start the export.';
}

function waitForExportPoll(signal: AbortSignal, delayMs: number): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(exportAbortError());
  }
  return new Promise((resolve, reject) => {
    let timeout: ReturnType<typeof window.setTimeout>;
    const abort = () => {
      window.clearTimeout(timeout);
      reject(exportAbortError());
    };
    timeout = window.setTimeout(() => {
      signal.removeEventListener('abort', abort);
      resolve();
    }, delayMs);
    signal.addEventListener('abort', abort, { once: true });
  });
}

async function requestDataExport({ signal, setExportPending, setExportError, setExportStatus }: ExportSetters) {
  if (signal.aborted) {
    return;
  }
  setExportPending(true);
  setExportError('');
  setExportStatus({ kind: 'preparing', message: 'Preparing your data export…' });
  try {
    const job = await apiClient.enqueueDataExport({ signal });
    let current = job;
    // Keep polling until backend reaches a terminal state so jobs that are simply
    // slower than expected stay reachable and can still be downloaded when ready.
    const longPollingThreshold = 30;
    let attempt = 0;
    while (
      current.status !== 'ready' &&
      current.status !== 'failed' &&
      current.status !== 'expired'
    ) {
      if (attempt > 0) {
        await waitForExportPoll(signal, 1000);
      }
      attempt += 1;
      current = await apiClient.getDataExport(current.id, { signal });
      if (attempt === longPollingThreshold + 1) {
        setExportStatus({ kind: 'preparing', message: 'The export is taking longer than expected; continuing to check until complete.' });
      }
    }
    if (signal.aborted) {
      return;
    }
    if (current.status === 'ready' && current.download_url) {
      const downloadURL = resolveDataExportDownloadURL(current.download_url);
      setExportStatus({
        kind: 'ready',
        downloadURL,
        expiresAt: current.download_expires_at
      });
      // Auto-trigger the browser download so the user does not have to
      // hunt for the link on the page.
      const link = document.createElement('a');
      link.href = downloadURL;
      link.rel = 'noopener noreferrer';
      document.body.appendChild(link);
      link.click();
      link.remove();
    } else if (current.status === 'failed') {
      setExportStatus({ kind: 'idle' });
      setExportError(current.error_message || 'The export failed. Please try again.');
    } else if (current.status === 'expired') {
      setExportStatus({ kind: 'idle' });
      setExportError('Your download link has expired. Please request a new export.');
    } else {
      setExportStatus({ kind: 'idle' });
      setExportError('Your export is taking longer than expected. Please try again in a few minutes.');
    }
  } catch (err) {
    if (signal.aborted || isAbortError(err)) {
      return;
    }
    setExportStatus({ kind: 'idle' });
    setExportError(formatDataExportError(err));
  } finally {
    if (!signal.aborted) {
      setExportPending(false);
    }
  }
}

function accountDeletionWorkspacesFromError(error: ApiError): AccountDeletionWorkspace[] {
  const payload = error.payload as { workspaces?: unknown } | undefined;
  if (!Array.isArray(payload?.workspaces)) {
    return [];
  }
  return payload.workspaces.filter((workspace): workspace is AccountDeletionWorkspace => {
    if (!workspace || typeof workspace !== 'object') {
      return false;
    }
    const record = workspace as Partial<AccountDeletionWorkspace>;
    return (
      typeof record.tenant_id === 'string' &&
      record.tenant_id.trim() !== '' &&
      typeof record.workspace_id === 'string' &&
      record.workspace_id.trim() !== ''
    );
  });
}

function accountDeletionWorkspaceLabel(workspace: AccountDeletionWorkspace): string {
  const displayName = workspace.display_name?.trim();
  const slug = workspace.slug?.trim();
  return displayName || slug || workspace.workspace_id;
}

function accountDeletionSignInPath(hardDeleteAfter?: string): string {
  const query = new URLSearchParams({ reason: 'account_pending_deletion' });
  if (hardDeleteAfter?.trim()) {
    query.set('hard_delete_after', hardDeleteAfter);
  }
  return `/signin?${query.toString()}`;
}

// Extracts the affected-member array from a sole-owner 409 payload so the
// destructive modal can render an inline block listing who would be stranded
// and a deep link to the workspace member-management screen.
function workspaceSoleOwnerMembersFromError(error: ApiError): WorkspaceSoleOwnerAffectedMember[] {
  const payload = error.payload as { affected_members?: unknown } | undefined;
  if (!Array.isArray(payload?.affected_members)) {
    return [];
  }
  return payload.affected_members.filter(
    (member): member is WorkspaceSoleOwnerAffectedMember => {
      if (!member || typeof member !== 'object') {
        return false;
      }
      const record = member as Partial<WorkspaceSoleOwnerAffectedMember>;
      return (
        typeof record.member_id === 'string' &&
        record.member_id.trim() !== '' &&
        typeof record.user_id === 'string' &&
        typeof record.role === 'string'
      );
    }
  );
}

function workspaceSoleOwnerMemberLabel(member: WorkspaceSoleOwnerAffectedMember): string {
  const email = member.email?.trim();
  if (email) {
    return `${email} (${member.role})`;
  }
  return `${member.user_id || member.member_id} (${member.role})`;
}

export function ProductSettingsPage() {
  const params = useParams<ScopeRouteParams>();
  const scope = resolveScopeFromParams(params);
  const { me } = useMe();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [whoAmI, setWhoAmI] = useState<WhoAmIResponse | null>(null);
  const [members, setMembers] = useState<WorkspaceMemberRecord[]>([]);
  const [authConfig, setAuthConfig] = useState<AuthConfigResponse | null>(null);
  const [sessions, setSessions] = useState<SessionListItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(true);
  const [sessionsError, setSessionsError] = useState('');
  const [busySessionID, setBusySessionID] = useState('');
  const [revokingOthers, setRevokingOthers] = useState(false);
  const [suspendModalOpen, setSuspendModalOpen] = useState(false);
  const [suspendPending, setSuspendPending] = useState(false);
  const [suspendError, setSuspendError] = useState('');
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [deletePending, setDeletePending] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [deleteSoleOwnerWorkspaces, setDeleteSoleOwnerWorkspaces] = useState<AccountDeletionWorkspace[]>([]);
  const [workspaceLifecycle, setWorkspaceLifecycle] = useState<WorkspaceRecord | null>(null);
  const [workspaceSuspendModalOpen, setWorkspaceSuspendModalOpen] = useState(false);
  const [workspaceSuspendPending, setWorkspaceSuspendPending] = useState(false);
  const [workspaceSuspendError, setWorkspaceSuspendError] = useState('');
  const [workspaceSuspendStranded, setWorkspaceSuspendStranded] = useState<
    WorkspaceSoleOwnerAffectedMember[]
  >([]);
  // Sticky 409 flag (cubic PR #1456 P2): a malformed or empty `affected_members`
  // payload would otherwise leave `workspaceSuspendStranded` empty and silently
  // hide the blocker. Track the sole-owner 409 explicitly so the inline block
  // still renders with fallback copy + the Manage-members deep link.
  const [workspaceSuspendSoleOwner, setWorkspaceSuspendSoleOwner] = useState(false);
  const [workspaceReactivateModalOpen, setWorkspaceReactivateModalOpen] = useState(false);
  const [workspaceReactivatePending, setWorkspaceReactivatePending] = useState(false);
  const [workspaceReactivateError, setWorkspaceReactivateError] = useState('');
  const [workspaceDeleteModalOpen, setWorkspaceDeleteModalOpen] = useState(false);
  const [workspaceDeletePending, setWorkspaceDeletePending] = useState(false);
  const [workspaceDeleteError, setWorkspaceDeleteError] = useState('');
  const [workspaceDeleteStranded, setWorkspaceDeleteStranded] = useState<
    WorkspaceSoleOwnerAffectedMember[]
  >([]);
  // Mirrors `workspaceSuspendSoleOwner` for the Delete flow (cubic PR #1456 P2).
  const [workspaceDeleteSoleOwner, setWorkspaceDeleteSoleOwner] = useState(false);
  const [workspaceRestoreModalOpen, setWorkspaceRestoreModalOpen] = useState(false);
  const [workspaceRestorePending, setWorkspaceRestorePending] = useState(false);
  const [workspaceRestoreError, setWorkspaceRestoreError] = useState('');
  const [exportPending, setExportPending] = useState(false);
  const [exportError, setExportError] = useState('');
  const [exportStatus, setExportStatus] = useState<
    | { kind: 'idle' }
    | { kind: 'preparing'; message: string }
    | { kind: 'ready'; downloadURL: string; expiresAt?: string }
  >({ kind: 'idle' });
  const exportAbortRef = useRef<AbortController | null>(null);
  const avatarControlRef = useRef<HTMLDivElement | null>(null);
  const avatarFileInputRef = useRef<HTMLInputElement | null>(null);
  const [profileEditing, setProfileEditing] = useState(false);
  const [avatarMenuOpen, setAvatarMenuOpen] = useState(false);
  const [profileDraft, setProfileDraft] = useState<ProfileDraft>(() => profileDraftFromMe(me));
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileError, setProfileError] = useState('');
  const settingsMountedRef = useRef(true);

  useEffect(() => {
    settingsMountedRef.current = true;
    return () => {
      settingsMountedRef.current = false;
    };
  }, []);

  const loadSessions = async () => {
    setSessionsLoading(true);
    setSessionsError('');
    try {
      const response = await apiClient.listCurrentUserSessions();
      if (!settingsMountedRef.current) {
        return;
      }
      setSessions(response.items);
    } catch (sessionError) {
      if (!settingsMountedRef.current) {
        return;
      }
      const message = sessionError instanceof Error ? sessionError.message : 'Unable to load active sessions.';
      setSessionsError(message);
    } finally {
      if (settingsMountedRef.current) {
        setSessionsLoading(false);
      }
    }
  };

  const startDataExport = useCallback(() => {
    exportAbortRef.current?.abort();
    const controller = new AbortController();
    exportAbortRef.current = controller;
    void requestDataExport({
      signal: controller.signal,
      setExportPending,
      setExportError,
      setExportStatus
    }).finally(() => {
      if (exportAbortRef.current === controller) {
        exportAbortRef.current = null;
      }
    });
  }, []);

  useEffect(() => {
    return () => {
      exportAbortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!scope) {
      setError('Choose a workspace before loading settings.');
      setLoading(false);
      return;
    }

    let mounted = true;
    const loadSettings = async () => {
      setLoading(true);
      setError('');
      try {
        const auth = buildProductAuthContext(scope);
        const [whoAmIResponse, memberResponse, authConfigResponse] = await Promise.all([
          apiClient.getWhoAmI(auth),
          apiClient.listWorkspaceMembers(scope.workspaceID, { limit: 100 }, auth),
          apiClient.getAuthConfig()
        ]);
        if (!mounted) {
          return;
        }
        setWhoAmI(whoAmIResponse);
        setMembers(memberResponse.items);
        setAuthConfig(authConfigResponse);
        // Seed the workspace lifecycle banner + row state from whoAmI so the
        // Danger Zone reflects the current status before any mutation lands.
        const snapshotWorkspace =
          whoAmIResponse.active_workspace?.workspace ??
          whoAmIResponse.workspaces?.find(
            (item) => item.workspace.workspace_id === scope.workspaceID
          )?.workspace ??
          null;
        setWorkspaceLifecycle(snapshotWorkspace);
      } catch (err) {
        if (!mounted) {
          return;
        }
        setError(err instanceof Error ? err.message : 'Unable to load workspace settings');
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    void loadSettings();
    void loadSessions();

    return () => {
      mounted = false;
    };
  }, [scope?.tenantID, scope?.workspaceID, scope?.projectID]);

  useEffect(() => {
    if (!profileEditing && !profileSaving) {
      setProfileDraft(profileDraftFromMe(me));
      setProfileError('');
    }
  }, [me?.user.display_name, profileEditing, profileSaving]);

  useEffect(() => {
    if (!avatarMenuOpen) {
      return;
    }
    const handlePointerDown = (event: MouseEvent) => {
      const target = event.target;
      if (target instanceof Node && avatarControlRef.current?.contains(target)) {
        return;
      }
      setAvatarMenuOpen(false);
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setAvatarMenuOpen(false);
      }
    };
    document.addEventListener('pointerdown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [avatarMenuOpen]);

  const activeWorkspace = whoAmI?.active_workspace?.workspace ?? me?.workspace;
  const activeMember =
    whoAmI?.active_workspace?.member ??
    whoAmI?.workspaces?.find((item) => item.workspace.workspace_id === scope?.workspaceID)?.member;
  const activeRole = activeMember?.role ?? me?.role ?? 'viewer';
  const workspaceDisplayName = activeWorkspace?.display_name ?? scope?.workspaceID ?? 'Workspace';
  // Prefer the mutated lifecycle copy (refreshed after suspend/delete/etc.)
  // and fall back to whatever whoAmI seeded. Defaults to 'active' so a
  // legacy backend that omits the field still renders the same rows it
  // would have rendered before #1420 shipped.
  const workspaceLifecycleStatus =
    workspaceLifecycle?.status ?? activeWorkspace?.status ?? 'active';
  const workspaceSlugValue = (workspaceLifecycle?.slug ?? activeWorkspace?.slug ?? '').trim();
  const isWorkspaceOwner = activeRole === 'owner';
  const authProviders = authConfig?.auth.providers ?? [];
  const scopes = Array.isArray(whoAmI?.scopes) ? whoAmI.scopes : [];
  const workspacesPath = scope ? buildScopedPath(scope, 'workspaces') : '/app';
  const primaryEmail = me?.user.primary_email?.trim() ?? '';
  const profileDisplayName = formatProfileDisplayName(me);
  const profileAvatarURL = me?.user.avatar_url?.trim() ?? '';
  const profileInitials = formatProfileInitials(me);
  const activeMembers = countMembersByStatus(members, 'active');
  const invitedMembers = countMembersByStatus(members, 'invited');
  const adminMembers = countMembersByRole(members, 'owner') + countMembersByRole(members, 'admin');
  const signInMethods = formatSettingsAuthProviders(authConfig);
  const hostedLoginStatus = authConfig?.auth.workos_login_enabled ? 'Enabled' : 'Disabled';
  const samlStatus = authConfig?.auth.native_saml_enabled ? 'Configured' : 'Not configured';
  const mfaStatus = authConfig?.auth.workos_login_enabled ? 'Hosted login' : 'Not configured';
  const developerScopeLabel = scopes.length ? scopes.map(formatTokenLabel).join(', ') : 'No custom restrictions';
  const developerProviderLabel = authProviders.length ? authProviders.join(', ') : 'None advertised';

  const handleProfileEdit = () => {
    if (profileEditing) {
      setProfileError('');
      setAvatarMenuOpen(false);
      return;
    }
    setProfileDraft(profileDraftFromMe(me));
    setProfileError('');
    setProfileEditing(true);
    setAvatarMenuOpen(false);
  };

  const handleProfileCancel = () => {
    if (profileSaving) return;
    setProfileDraft(profileDraftFromMe(me));
    setProfileError('');
    setProfileEditing(false);
    setAvatarMenuOpen(false);
  };

  const handleAvatarDelete = async () => {
    if (!me || profileSaving || !profileAvatarURL) {
      return;
    }
    const previousMe = me;
    const previousDraft = profileDraft;
    const wasProfileEditing = profileEditing;
    const optimisticMe: CurrentUserContext = {
      ...previousMe,
      user: {
        ...previousMe.user,
        avatar_url: '',
        updated_at: new Date().toISOString()
      }
    };
    setAvatarMenuOpen(false);
    setProfileSaving(true);
    setProfileError('');
    primeMeCache(optimisticMe);
    try {
      const response = await apiClient.updateMe({ avatar_url: '' });
      primeMeCache(response.me);
      if (wasProfileEditing) {
        setProfileDraft(previousDraft);
      } else {
        setProfileDraft(profileDraftFromMe(response.me));
        setProfileEditing(false);
      }
    } catch (err) {
      primeMeCache(previousMe);
      setProfileDraft(wasProfileEditing ? previousDraft : profileDraftFromMe(previousMe));
      setProfileError(formatProfileAvatarError(err));
    } finally {
      setProfileSaving(false);
    }
  };

  const handleAvatarUploadClick = () => {
    if (!me || profileSaving) {
      return;
    }
    setAvatarMenuOpen(false);
    setProfileError('');
    avatarFileInputRef.current?.click();
  };

  const handleAvatarFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = '';
    if (!file || !me || profileSaving) {
      return;
    }
    const validationError = validateProfileAvatarFile(file);
    if (validationError) {
      setProfileError(validationError);
      return;
    }
    const previousMe = me;
    const previousDraft = profileDraft;
    const wasProfileEditing = profileEditing;
    let nextAvatarURL = '';
    try {
      nextAvatarURL = await readProfileAvatarFile(file);
    } catch (err) {
      setProfileError(err instanceof Error ? err.message : 'Unable to read profile photo.');
      return;
    }
    const optimisticMe: CurrentUserContext = {
      ...previousMe,
      user: {
        ...previousMe.user,
        avatar_url: nextAvatarURL,
        updated_at: new Date().toISOString()
      }
    };
    setProfileSaving(true);
    setProfileError('');
    primeMeCache(optimisticMe);
    try {
      const response = await apiClient.updateMe({ avatar_url: nextAvatarURL });
      primeMeCache(response.me);
      if (wasProfileEditing) {
        setProfileDraft(previousDraft);
      } else {
        setProfileDraft(profileDraftFromMe(response.me));
      }
    } catch (err) {
      primeMeCache(previousMe);
      setProfileDraft(wasProfileEditing ? previousDraft : profileDraftFromMe(previousMe));
      setProfileError(formatProfileAvatarError(err));
    } finally {
      setProfileSaving(false);
    }
  };

  const handleProfileSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!me) {
      setProfileError('Current user is unavailable.');
      return;
    }
    const previousMe = me;
    const previousDisplayName = previousMe.user.display_name?.trim() ?? '';
    const nextDisplayName = profileDraft.displayName.trim();
    const displayNameChanged = nextDisplayName !== previousDisplayName;
    const validationError = validateProfileDraft(profileDraft);
    if (validationError) {
      setProfileError(validationError);
      return;
    }
    if (!displayNameChanged) {
      setProfileError('');
      setProfileEditing(false);
      return;
    }
    const optimisticMe: CurrentUserContext = {
      ...previousMe,
      user: {
        ...previousMe.user,
        display_name: nextDisplayName,
        updated_at: new Date().toISOString()
      }
    };
    setProfileSaving(true);
    setProfileError('');
    primeMeCache(optimisticMe);
    try {
      const payload = {
        display_name: nextDisplayName
      };
      const response = await apiClient.updateMe(payload);
      primeMeCache(response.me);
      setProfileDraft(profileDraftFromMe(response.me));
      setProfileEditing(false);
    } catch (err) {
      primeMeCache(previousMe);
      setProfileDraft(profileDraftFromMe(previousMe));
      setProfileError(err instanceof Error ? err.message : 'Unable to update profile.');
    } finally {
      setProfileSaving(false);
    }
  };

  const handleRevokeSession = async (sessionID: string, isCurrent: boolean) => {
    setBusySessionID(sessionID);
    setSessionsError('');
    try {
      await apiClient.revokeCurrentUserSession(sessionID);
      if (isCurrent) {
        resetProductAuthSessionCache({ unauthenticated: true });
        navigate('/signin?signed_out=1', { replace: true });
        return;
      }
      await loadSessions();
    } catch (sessionError) {
      const message = sessionError instanceof Error ? sessionError.message : 'Unable to revoke session.';
      setSessionsError(message);
    } finally {
      setBusySessionID('');
    }
  };

  const handleRevokeOtherSessions = async () => {
    setRevokingOthers(true);
    setSessionsError('');
    try {
      await apiClient.revokeOtherCurrentUserSessions();
      await loadSessions();
    } catch (sessionError) {
      const message = sessionError instanceof Error ? sessionError.message : 'Unable to revoke other sessions.';
      setSessionsError(message);
    } finally {
      setRevokingOthers(false);
    }
  };

  const handleOpenDeleteModal = () => {
    setDeleteError('');
    setDeleteSoleOwnerWorkspaces([]);
    setDeleteModalOpen(true);
  };

  const handleCancelDeleteModal = () => {
    if (deletePending) return;
    setDeleteModalOpen(false);
    setDeleteError('');
    setDeleteSoleOwnerWorkspaces([]);
  };

  const handleDeleteAccount = async () => {
    if (deletePending) return;
    setDeletePending(true);
    setDeleteError('');
    setDeleteSoleOwnerWorkspaces([]);
    try {
      const response = await apiClient.deleteMe();
      resetProductAuthSessionCache({ unauthenticated: true });
      clearMeCache({ unauthenticated: true });
      navigate(accountDeletionSignInPath(response.hard_delete_after), { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.status === 409 && err.code === 'sole_owner') {
        setDeleteSoleOwnerWorkspaces(accountDeletionWorkspacesFromError(err));
        setDeleteError('');
      } else {
        setDeleteError(err instanceof Error ? err.message : 'Unable to delete your account. Please retry.');
      }
    } finally {
      setDeletePending(false);
    }
  };

  // ---------------------------------------------------------------
  // Workspace lifecycle handlers (PR 3 of #1420).
  //
  // Every destructive transition first opens a ConfirmDestructiveModal so the
  // owner has to consciously confirm (type-to-confirm for Suspend/Delete,
  // checkbox for the restorative Reactivate/Restore). The button on the row
  // itself never fires the API — that always happens from inside the modal —
  // so an accidental click on the row only opens the dialog.
  //
  // Sole-owner 409 from the backend is rendered inline in the open modal
  // (not a toast, not a navigation) so the owner can see who would be
  // stranded, promote another owner, and retry without losing their place.
  // The non-destructive `ApiError` branches fall through to errorMessage on
  // the same modal.
  const handleOpenWorkspaceSuspendModal = () => {
    setWorkspaceSuspendError('');
    setWorkspaceSuspendStranded([]);
    setWorkspaceSuspendSoleOwner(false);
    setWorkspaceSuspendModalOpen(true);
  };
  const handleCancelWorkspaceSuspendModal = () => {
    if (workspaceSuspendPending) return;
    setWorkspaceSuspendModalOpen(false);
    setWorkspaceSuspendError('');
    setWorkspaceSuspendStranded([]);
    setWorkspaceSuspendSoleOwner(false);
  };
  const handleSuspendWorkspace = async () => {
    if (workspaceSuspendPending || !scope) return;
    setWorkspaceSuspendPending(true);
    setWorkspaceSuspendError('');
    setWorkspaceSuspendStranded([]);
    setWorkspaceSuspendSoleOwner(false);
    try {
      const response = await apiClient.suspendWorkspace(
        scope.workspaceID,
        buildProductAuthContext(scope)
      );
      setWorkspaceLifecycle(response.workspace);
      setWorkspaceSuspendModalOpen(false);
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.status === 409 &&
        err.code === 'sole_owner_requires_transfer'
      ) {
        // Latch the 409 flag even when affected_members fails to parse
        // (cubic PR #1456 P2) so the inline blocker still renders with a
        // fallback message — otherwise the modal would close the pending
        // state with no visible error and the actor would be left guessing.
        setWorkspaceSuspendSoleOwner(true);
        setWorkspaceSuspendStranded(workspaceSoleOwnerMembersFromError(err));
      } else {
        setWorkspaceSuspendError(
          err instanceof Error ? err.message : 'Unable to suspend the workspace. Please retry.'
        );
      }
    } finally {
      setWorkspaceSuspendPending(false);
    }
  };

  const handleOpenWorkspaceReactivateModal = () => {
    setWorkspaceReactivateError('');
    setWorkspaceReactivateModalOpen(true);
  };
  const handleCancelWorkspaceReactivateModal = () => {
    if (workspaceReactivatePending) return;
    setWorkspaceReactivateModalOpen(false);
    setWorkspaceReactivateError('');
  };
  const handleReactivateWorkspace = async () => {
    if (workspaceReactivatePending || !scope) return;
    setWorkspaceReactivatePending(true);
    setWorkspaceReactivateError('');
    try {
      const response = await apiClient.reactivateWorkspace(
        scope.workspaceID,
        buildProductAuthContext(scope)
      );
      setWorkspaceLifecycle(response.workspace);
      setWorkspaceReactivateModalOpen(false);
    } catch (err) {
      setWorkspaceReactivateError(
        err instanceof Error ? err.message : 'Unable to reactivate the workspace. Please retry.'
      );
    } finally {
      setWorkspaceReactivatePending(false);
    }
  };

  const handleOpenWorkspaceDeleteModal = () => {
    setWorkspaceDeleteError('');
    setWorkspaceDeleteStranded([]);
    setWorkspaceDeleteSoleOwner(false);
    setWorkspaceDeleteModalOpen(true);
  };
  const handleCancelWorkspaceDeleteModal = () => {
    if (workspaceDeletePending) return;
    setWorkspaceDeleteModalOpen(false);
    setWorkspaceDeleteError('');
    setWorkspaceDeleteStranded([]);
    setWorkspaceDeleteSoleOwner(false);
  };
  const handleDeleteWorkspace = async () => {
    if (workspaceDeletePending || !scope) return;
    setWorkspaceDeletePending(true);
    setWorkspaceDeleteError('');
    setWorkspaceDeleteStranded([]);
    setWorkspaceDeleteSoleOwner(false);
    try {
      const response: WorkspaceDeleteResponse = await apiClient.deleteWorkspace(
        scope.workspaceID,
        buildProductAuthContext(scope)
      );
      setWorkspaceLifecycle(response.workspace);
      setWorkspaceDeleteModalOpen(false);
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.status === 409 &&
        err.code === 'sole_owner_requires_transfer'
      ) {
        // See suspend handler — keep the blocker visible even with an empty
        // or malformed affected_members payload (cubic PR #1456 P2).
        setWorkspaceDeleteSoleOwner(true);
        setWorkspaceDeleteStranded(workspaceSoleOwnerMembersFromError(err));
      } else {
        setWorkspaceDeleteError(
          err instanceof Error ? err.message : 'Unable to delete the workspace. Please retry.'
        );
      }
    } finally {
      setWorkspaceDeletePending(false);
    }
  };

  const handleOpenWorkspaceRestoreModal = () => {
    setWorkspaceRestoreError('');
    setWorkspaceRestoreModalOpen(true);
  };
  const handleCancelWorkspaceRestoreModal = () => {
    if (workspaceRestorePending) return;
    setWorkspaceRestoreModalOpen(false);
    setWorkspaceRestoreError('');
  };
  const handleRestoreWorkspace = async () => {
    if (workspaceRestorePending || !scope) return;
    setWorkspaceRestorePending(true);
    setWorkspaceRestoreError('');
    try {
      const response = await apiClient.cancelWorkspaceDeletion(
        scope.workspaceID,
        buildProductAuthContext(scope)
      );
      setWorkspaceLifecycle(response.workspace);
      setWorkspaceRestoreModalOpen(false);
    } catch (err) {
      setWorkspaceRestoreError(
        err instanceof Error ? err.message : 'Unable to restore the workspace. Please retry.'
      );
    } finally {
      setWorkspaceRestorePending(false);
    }
  };

  if (loading) {
    return (
      <section className="idt-app-panel" aria-busy="true" aria-live="polite">
        <h2>Settings</h2>
      </section>
    );
  }

  if (error) {
    return (
      <section className="idt-app-panel idt-app-panel-error" role="alert">
        <h2>Settings</h2>
        <p>{error}</p>
      </section>
    );
  }

  return (
    <section className="idt-app-panel idt-settings-page">
      <header className="idt-settings-header">
        <div>
          <h2>Settings</h2>
        </div>
      </header>

      <section className="idt-settings-card idt-profile-card" aria-labelledby="idt-profile-heading">
        <div className="idt-settings-card-header">
          <div>
            <h3 id="idt-profile-heading">Profile</h3>
          </div>
          {profileEditing ? (
            <div className="idt-profile-actions">
              <button
                type="submit"
                form="idt-profile-form"
                className="idt-btn idt-btn-primary"
                disabled={profileSaving}
              >
                {profileSaving ? 'Saving...' : 'Save profile'}
              </button>
              <button
                type="button"
                className="idt-btn idt-btn-ghost"
                onClick={handleProfileCancel}
                disabled={profileSaving}
              >
                Cancel
              </button>
            </div>
          ) : null}
        </div>

        <div className="idt-profile-body">
          <div
            className="idt-profile-avatar-control"
            data-menu-open={avatarMenuOpen ? 'true' : 'false'}
            ref={avatarControlRef}
          >
            <input
              ref={avatarFileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp,image/gif"
              hidden
              onChange={(event) => {
                void handleAvatarFileChange(event);
              }}
            />
            <button
              type="button"
              className="idt-profile-avatar"
              aria-expanded={avatarMenuOpen}
              aria-haspopup="menu"
              aria-label={profileAvatarURL ? 'Update or delete profile photo' : 'Upload profile photo'}
              onClick={() => setAvatarMenuOpen((open) => !open)}
              disabled={!me}
            >
              {profileAvatarURL ? <img src={profileAvatarURL} alt="" /> : <span>{profileInitials}</span>}
              <span className="idt-profile-avatar-edit" aria-hidden="true">
                <Pencil size={14} />
              </span>
            </button>
            {avatarMenuOpen ? (
              <div className="idt-profile-avatar-menu" role="menu">
                <button type="button" role="menuitem" onClick={handleAvatarUploadClick} disabled={profileSaving}>
                  {profileAvatarURL ? 'Update photo' : 'Upload photo'}
                </button>
                {profileAvatarURL ? (
                  <button type="button" role="menuitem" onClick={() => void handleAvatarDelete()} disabled={profileSaving}>
                    Delete photo
                  </button>
                ) : null}
              </div>
            ) : null}
          </div>

          {profileEditing ? (
            <form id="idt-profile-form" className="idt-app-form idt-profile-form" onSubmit={handleProfileSubmit}>
              <div className="idt-profile-editing-note" role="status">
                Editing profile
              </div>
              <label>
                Display name
                <input
                  type="text"
                  value={profileDraft.displayName}
                  onChange={(event) => setProfileDraft((draft) => ({ ...draft, displayName: event.target.value }))}
                  maxLength={80}
                  disabled={profileSaving}
                  required
                />
              </label>
              <label>
                Email
                <input
                  type="email"
                  value={primaryEmail || 'Unavailable'}
                  disabled
                  readOnly
                />
              </label>
              {profileError ? (
                <p className="idt-app-alert idt-app-alert-error" role="alert">
                  {profileError}
                </p>
              ) : null}
            </form>
          ) : (
            <dl className="idt-settings-facts idt-profile-facts">
              <div>
                <dt>Name</dt>
                <dd>{profileDisplayName}</dd>
              </div>
              <div>
                <dt>Email</dt>
                <dd>{me?.user.primary_email ?? 'Unavailable'}</dd>
              </div>
            </dl>
          )}
        </div>

        {!profileEditing && profileError ? (
          <p className="idt-app-alert idt-app-alert-error" role="alert">
            {profileError}
          </p>
        ) : null}

        <div className="idt-settings-action-stack">
          {!profileEditing ? (
            <button
              aria-label="Edit profile"
              className="idt-settings-action-row"
              onClick={handleProfileEdit}
              type="button"
              disabled={!me}
            >
              <span>
                <strong>Edit profile</strong>
              </span>
              <ChevronRight size={16} aria-hidden="true" />
            </button>
          ) : null}
          <div className="idt-settings-action-item" data-testid="idt-export-account-row">
            <button
              aria-label="Download my data"
              className="idt-settings-action-row"
              data-testid="idt-export-account-button"
              disabled={exportPending}
              onClick={startDataExport}
              type="button"
            >
              <span>
                <strong>Download my data</strong>
              </span>
              <ChevronRight size={16} aria-hidden="true" />
            </button>
            {exportStatus.kind === 'ready' ? (
              <p className="idt-settings-inline-status idt-danger-zone-success" data-testid="idt-export-ready">
                Your data export is ready.{' '}
                <a href={exportStatus.downloadURL} rel="noopener noreferrer">
                  Download the ZIP
                </a>
                {exportStatus.expiresAt ? ` - link expires ${new Date(exportStatus.expiresAt).toLocaleString()}` : ''}.
              </p>
            ) : exportStatus.kind === 'preparing' ? (
              <p className="idt-settings-inline-status idt-danger-zone-status" data-testid="idt-export-preparing">
                {exportStatus.message}
              </p>
            ) : null}
            {exportError ? (
              <p className="idt-settings-inline-status idt-danger-zone-error" role="alert">
                {exportError}
              </p>
            ) : null}
          </div>
        </div>
      </section>

      <div className="idt-settings-grid">
        <section className="idt-settings-card idt-settings-security-card">
          <div className="idt-settings-card-header">
            <div>
              <h3>Security</h3>
            </div>
          </div>
          <dl className="idt-settings-facts">
            <div>
              <dt>Sign-in methods</dt>
              <dd>{signInMethods}</dd>
            </div>
            <div>
              <dt>2FA</dt>
              <dd>{mfaStatus}</dd>
            </div>
            <div>
              <dt>SAML SSO</dt>
              <dd>{samlStatus}</dd>
            </div>
          </dl>
          <details className="idt-settings-inline-disclosure idt-settings-sessions-card">
            <summary className="idt-settings-action-row idt-settings-action-summary">
              <span>
                <strong>Manage sessions</strong>
              </span>
              <ChevronDown className="idt-settings-row-chevron" size={16} aria-hidden="true" />
            </summary>
            <div className="idt-settings-disclosure-body">
              {sessionsLoading ? <p className="idt-app-alert">Loading active sessions...</p> : null}
              {sessionsError ? (
                <p className="idt-app-alert idt-app-alert-error" role="alert">
                  {sessionsError}
                </p>
              ) : null}
              {!sessionsLoading ? (
                <SessionsList
                  busySessionID={busySessionID}
                  revokingOthers={revokingOthers}
                  sessions={sessions}
                  onRevoke={handleRevokeSession}
                  onRevokeOthers={handleRevokeOtherSessions}
                />
              ) : null}
            </div>
          </details>
        </section>

        <section className="idt-settings-card idt-settings-workspace-card">
          <div className="idt-settings-card-header">
            <div>
              <h3>Workspace</h3>
            </div>
          </div>
          <dl className="idt-settings-facts">
            <div>
              <dt>Name</dt>
              <dd>{workspaceDisplayName}</dd>
            </div>
            <div>
              <dt>Your access</dt>
              <dd>{formatTokenLabel(activeRole)}</dd>
            </div>
            <div>
              <dt>Admins</dt>
              <dd>{adminMembers}</dd>
            </div>
          </dl>
          <div className="idt-settings-counts">
            <article>
              <strong>{members.length}</strong>
              <span>Total members</span>
            </article>
            <article>
              <strong>{activeMembers}</strong>
              <span>Active</span>
            </article>
            <article>
              <strong>{invitedMembers}</strong>
              <span>Invited</span>
            </article>
          </div>
          <Link className="idt-settings-action-row" to={workspacesPath}>
            <span>
              <strong>Manage members</strong>
            </span>
            <ChevronRight size={16} aria-hidden="true" />
          </Link>
        </section>
      </div>

      <details className="idt-settings-card idt-settings-disclosure">
        <summary className="idt-settings-disclosure-summary">
          <div>
            <h3>Developer details</h3>
          </div>
          <span aria-hidden="true" className="idt-settings-disclosure-chevron">
            <ChevronDown size={14} />
          </span>
        </summary>
        <div className="idt-settings-disclosure-body">
          <dl className="idt-settings-facts">
            <div>
              <dt>Tenant ID</dt>
              <dd>{scope?.tenantID ?? 'Unavailable'}</dd>
            </div>
            <div>
              <dt>Workspace ID</dt>
              <dd>{scope?.workspaceID ?? 'Unavailable'}</dd>
            </div>
            <div>
              <dt>Principal ID</dt>
              <dd>{whoAmI ? `${formatTokenLabel(whoAmI.principal.type)} - ${whoAmI.principal.id}` : 'Unavailable'}</dd>
            </div>
            <div>
              <dt>Custom scopes</dt>
              <dd>{developerScopeLabel}</dd>
            </div>
            <div>
              <dt>Hosted login</dt>
              <dd>{hostedLoginStatus}</dd>
            </div>
            <div>
              <dt>Auth providers</dt>
              <dd>{developerProviderLabel}</dd>
            </div>
          </dl>
        </div>
      </details>

      <DangerZone>
        <DangerZoneRow
          actionLabel="Suspend account"
          onAction={() => {
            setSuspendError('');
            setSuspendModalOpen(true);
          }}
          pending={suspendPending}
          testId="idt-suspend-account-row"
          title="Suspend account"
        />
        <DangerZoneRow
          actionLabel="Delete account"
          disabled={!primaryEmail}
          onAction={handleOpenDeleteModal}
          pending={deletePending}
          testId="idt-delete-account-row"
          title="Delete account"
        />
        {/* Owner-only workspace rows (PR 3 of #1420). Appended into the same */}
        {/* DangerZone card on purpose: a second card with an identical title */}
        {/* would feel like the page lost the plot, and the row titles already */}
        {/* state the scope (Suspend workspace vs Suspend account). Non-owners */}
        {/* render exactly the two account rows above, no layout change. */}
        {isWorkspaceOwner && workspaceLifecycleStatus === 'active' ? (
          <DangerZoneRow
            actionLabel="Suspend workspace"
            onAction={handleOpenWorkspaceSuspendModal}
            pending={workspaceSuspendPending}
            testId="idt-suspend-workspace-row"
            title="Suspend workspace"
          />
        ) : null}
        {isWorkspaceOwner && workspaceLifecycleStatus === 'suspended' ? (
          <DangerZoneRow
            actionLabel="Reactivate workspace"
            onAction={handleOpenWorkspaceReactivateModal}
            pending={workspaceReactivatePending}
            testId="idt-reactivate-workspace-row"
            title="Reactivate workspace"
          />
        ) : null}
        {isWorkspaceOwner && workspaceLifecycleStatus !== 'deleted' ? (
          <DangerZoneRow
            actionLabel="Delete workspace"
            disabled={!workspaceSlugValue}
            onAction={handleOpenWorkspaceDeleteModal}
            pending={workspaceDeletePending}
            testId="idt-delete-workspace-row"
            title="Delete workspace"
          />
        ) : null}
        {isWorkspaceOwner && workspaceLifecycleStatus === 'deleted' ? (
          <DangerZoneRow
            actionLabel="Restore workspace"
            onAction={handleOpenWorkspaceRestoreModal}
            pending={workspaceRestorePending}
            testId="idt-restore-workspace-row"
            title="Restore workspace"
          />
        ) : null}
      </DangerZone>

      <ConfirmDestructiveModal
        body={
          <>
            <p>You will be signed out on all devices.</p>
            <p>Your workspace, projects, memberships, and connector data will remain intact.</p>
          </>
        }
        confirmation={{
          kind: 'type-to-confirm',
          expectedValue: 'SUSPEND',
          inputLabel: (
            <>
              Type <em className="idt-danger-confirm-value">SUSPEND</em> to continue
            </>
          )
        }}
        continueLabel="Suspend account"
        errorMessage={suspendError || undefined}
        onCancel={() => {
          if (suspendPending) return;
          setSuspendModalOpen(false);
        }}
        onConfirm={async () => {
          if (suspendPending) return;
          setSuspendPending(true);
          setSuspendError('');
          try {
            await apiClient.deactivateCurrentUser();
            // Reset both auth caches the way the logout handler does so that
            // back-navigating to a previously-validated /app/... route does
            // not transiently render the protected shell against stale state
            // before the silent /v1/me check returns 401.
            resetProductAuthSessionCache({ unauthenticated: true });
            clearMeCache({ unauthenticated: true });
            navigate('/signin?reason=account_deactivated', { replace: true });
          } catch (err) {
            setSuspendError(
              err instanceof Error ? err.message : 'Unable to suspend your account. Please retry.'
            );
            setSuspendPending(false);
            return;
          }
          setSuspendPending(false);
          setSuspendModalOpen(false);
        }}
        open={suspendModalOpen}
        pending={suspendPending}
        title="Suspend account"
      />
      <ConfirmDestructiveModal
        body={
          <>
            <p>This starts a 30-day recovery window and blocks normal sign-in.</p>
            <p>
              After the window, the account is permanently deleted. Need an archive?{' '}
              <button
                className="idt-inline-button-link"
                disabled={exportPending}
                onClick={startDataExport}
                type="button"
              >
                {exportPending ? 'Preparing export' : 'Download my data'}
              </button>{' '}
              before deleting.
            </p>
            {deleteSoleOwnerWorkspaces.length > 0 ? (
              <div
                className="idt-danger-modal-blocker"
                data-testid="idt-delete-sole-owner-workspaces"
                role="alert"
              >
                <p>
                  Transfer ownership for these workspaces before deleting this account.
                </p>
                <ul>
                  {deleteSoleOwnerWorkspaces.map((workspace) => (
                    <li key={`${workspace.tenant_id}:${workspace.workspace_id}`}>
                      {accountDeletionWorkspaceLabel(workspace)}
                    </li>
                  ))}
                </ul>
                <Link to={workspacesPath}>Manage members</Link>
              </div>
            ) : null}
          </>
        }
        confirmation={{
          kind: 'type-to-confirm',
          expectedValue: primaryEmail,
          inputLabel: 'Confirm primary email',
          helpText: primaryEmail ? (
            <>
              Enter <em className="idt-danger-confirm-value">{primaryEmail}</em> exactly.
            </>
          ) : undefined
        }}
        continueLabel="Delete account"
        errorMessage={deleteError || undefined}
        onCancel={handleCancelDeleteModal}
        onConfirm={handleDeleteAccount}
        open={deleteModalOpen}
        pending={deletePending}
        title="Delete account"
      />

      {/* --- Workspace lifecycle confirmation modals (PR 3 of #1420). --- */}
      {/* Body copy mirrors the account-side patterns above: two short      */}
      {/* sentences, monospaced token chip for type-to-confirm, ESC + cancel*/}
      {/* affordances. Sole-owner 409 renders inline so the owner can fix   */}
      {/* the stranding and retry without losing the modal context.        */}
      <ConfirmDestructiveModal
        body={
          <>
            <p>Connectors, scans, and webhooks will pause.</p>
            <p>Member access and stored data remain intact.</p>
            {workspaceSuspendSoleOwner ? (
              <div
                className="idt-danger-modal-blocker"
                data-testid="idt-suspend-workspace-sole-owner-block"
                role="alert"
              >
                {workspaceSuspendStranded.length > 0 ? (
                  <>
                    <p>
                      Promote another owner before suspending so these members are not
                      stranded.
                    </p>
                    <ul>
                      {workspaceSuspendStranded.map((member) => (
                        <li key={member.member_id}>
                          {workspaceSoleOwnerMemberLabel(member)}
                        </li>
                      ))}
                    </ul>
                  </>
                ) : (
                  // Backend confirmed sole-owner stranding but the affected-member
                  // list didn't parse — still surface the blocker so the actor
                  // knows what to do (cubic PR #1456 P2).
                  <p>
                    This workspace has only one owner. Promote another owner before
                    suspending so other members are not stranded.
                  </p>
                )}
                <Link to={workspacesPath}>Manage members</Link>
              </div>
            ) : null}
          </>
        }
        confirmation={{
          kind: 'type-to-confirm',
          expectedValue: 'SUSPEND',
          inputLabel: (
            <>
              Type <em className="idt-danger-confirm-value">SUSPEND</em> to continue
            </>
          )
        }}
        continueLabel="Suspend workspace"
        errorMessage={workspaceSuspendError || undefined}
        onCancel={handleCancelWorkspaceSuspendModal}
        onConfirm={handleSuspendWorkspace}
        open={workspaceSuspendModalOpen}
        pending={workspaceSuspendPending}
        title="Suspend workspace"
      />

      <ConfirmDestructiveModal
        body={
          <>
            <p>Connectors, scans, and webhooks will resume.</p>
          </>
        }
        confirmation={{
          kind: 'checkbox',
          label: 'Resume connectors, scans, and webhooks for this workspace.'
        }}
        continueLabel="Reactivate workspace"
        errorMessage={workspaceReactivateError || undefined}
        onCancel={handleCancelWorkspaceReactivateModal}
        onConfirm={handleReactivateWorkspace}
        open={workspaceReactivateModalOpen}
        pending={workspaceReactivatePending}
        title="Reactivate workspace"
      />

      <ConfirmDestructiveModal
        body={
          <>
            <p>This starts a 30-day recovery window and disables the workspace.</p>
            <p>After the window, the workspace and all its data are permanently purged.</p>
            {workspaceDeleteSoleOwner ? (
              <div
                className="idt-danger-modal-blocker"
                data-testid="idt-delete-workspace-sole-owner-block"
                role="alert"
              >
                {workspaceDeleteStranded.length > 0 ? (
                  <>
                    <p>
                      Promote another owner before deleting so these members are not
                      stranded.
                    </p>
                    <ul>
                      {workspaceDeleteStranded.map((member) => (
                        <li key={member.member_id}>
                          {workspaceSoleOwnerMemberLabel(member)}
                        </li>
                      ))}
                    </ul>
                  </>
                ) : (
                  <p>
                    This workspace has only one owner. Promote another owner before
                    deleting so other members are not stranded.
                  </p>
                )}
                <Link to={workspacesPath}>Manage members</Link>
              </div>
            ) : null}
          </>
        }
        confirmation={{
          kind: 'type-to-confirm',
          expectedValue: workspaceSlugValue,
          inputLabel: 'Confirm workspace slug',
          helpText: workspaceSlugValue ? (
            <>
              Enter <em className="idt-danger-confirm-value">{workspaceSlugValue}</em>{' '}
              exactly.
            </>
          ) : (
            'Workspace slug is unavailable; reload the page before retrying.'
          )
        }}
        continueLabel="Delete workspace"
        errorMessage={workspaceDeleteError || undefined}
        onCancel={handleCancelWorkspaceDeleteModal}
        onConfirm={handleDeleteWorkspace}
        open={workspaceDeleteModalOpen}
        pending={workspaceDeletePending}
        title="Delete workspace"
      />

      <ConfirmDestructiveModal
        body={
          <>
            <p>Restores the workspace and cancels the scheduled deletion.</p>
          </>
        }
        confirmation={{
          kind: 'checkbox',
          label: 'Cancel the scheduled deletion and restore this workspace.'
        }}
        continueLabel="Restore workspace"
        errorMessage={workspaceRestoreError || undefined}
        onCancel={handleCancelWorkspaceRestoreModal}
        onConfirm={handleRestoreWorkspace}
        open={workspaceRestoreModalOpen}
        pending={workspaceRestorePending}
        title="Restore workspace"
      />
    </section>
  );
}
