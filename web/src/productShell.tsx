import { ChangeEvent, Component, FormEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  CSSProperties,
  KeyboardEvent as ReactKeyboardEvent,
  MutableRefObject,
  PointerEvent as ReactPointerEvent
} from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate, useParams } from 'react-router';
import {
  BarChart3,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  ExternalLink,
  FolderKanban,
  HelpCircle,
  LayoutDashboard,
  LogOut,
  Monitor,
  Moon,
  MoreHorizontal,
  Palette,
  Pencil,
  Search,
  Settings as SettingsIcon,
  Sun,
  Trash2
} from 'lucide-react';
import { workspaceMemberID } from './utils/workspaceMemberID';
import {
  ApiError,
  apiClient,
  buildAPIURL,
  type AccountDeletionWorkspace,
  type AuthConfigResponse,
  type AWSCapabilityPermissionTier,
  type AWSConnectorStartResponse,
  type AWSConnectorScopeType,
  type AWSConnectorDeploymentMethod,
  type AWSConnectorOnboardingStatus,
  type AWSConnectorNextAction,
  type AWSConnectionDiagnostic,
  type AWSConnectionStatus,
  type AWSCodeBuildServiceRoleInventoryResult,
  type AWSCodeBuildServiceRoleRecord,
  type AWSCodePipelineDeploymentRoleInventoryResult,
  type AWSCodePipelineDeploymentRoleRecord,
  type AWSEventDrivenRoleInventoryResult,
  type AWSEventDrivenRoleRecord,
  type AWSManagedComputeRoleInventoryResult,
  type AWSManagedComputeRoleRecord,
  type AWSAIAgentIdentityQuery,
  type AWSAIAgentIdentityInventoryResult,
  type AWSMachineIdentityDetailResult,
  type AWSAgentIdentityDetailResult,
  type AWSRemediationCenterResult,
  type AWSRemediationCenterCase,
  type AWSRemediationCenterQuery,
  type AWSBedrockAgentsInventoryResult,
  type AWSBedrockAgentRecord,
  type AWSAIAgentIdentityRecord,
  type AWSRuntimeEventRecord,
  type AWSRuntimeEventResult,
  type AWSSecretsKMSRuntimeAccessRecord,
  type AWSSecretsKMSRuntimeAccessResult,
  type AWSS3RuntimeAccessRecord,
  type AWSS3RuntimeAccessResult,
  type AWSAgentRuntimeAccessRecord,
  type AWSAgentRuntimeAccessResult,
  type AWSAIAgentRiskFinding,
  type AWSAIAgentRiskResult,
  type AWSRemediationCase,
  type AWSRemediationCaseResult,
  type AWSIAMPolicyDiff,
  type AWSIAMPolicyDiffResult,
  type AWSTrustPolicyHardeningPlan,
  type AWSTrustPolicyHardeningResult,
  type AWSPermissionBoundarySCPPlan,
  type AWSPermissionBoundarySCPResult,
  type AWSSecretKeyRotationPlan,
  type AWSSecretKeyRotationResult,
  type AWSAccessKeyQuarantinePlan,
  type AWSAccessKeyQuarantineResult,
  type AWSIaCRemediationPlan,
  type AWSIaCRemediationResult,
  type AWSRemediationApprovalEntry,
  type AWSRemediationApprovalResult,
  type AWSRemediationDryRunEntry,
  type AWSRemediationDryRunResult,
  type AWSLowRiskRemediationEntry,
  type AWSLowRiskRemediationResult,
  type AWSPermissionBoundaryExecutorEntry,
  type AWSPermissionBoundaryExecutorResult,
  type AWSScpGuardrailExecutorEntry,
  type AWSScpGuardrailExecutorResult,
  type AWSPostRemediationVerificationEntry,
  type AWSPostRemediationVerificationResult,
  type AWSAdvisoryAuthorizationDecision,
  type AWSAdvisoryAuthorizationResult,
  type AWSLimitedEnforcementEntry,
  type AWSLimitedEnforcementResult,
  type AWSLimitedEnforcementPilotDecision,
  type AWSLimitedEnforcementPilotResult,
  type AWSGovernanceAuditReportRecord,
  type AWSGovernanceAuditReportingQuery,
  type AWSGovernanceAuditReportingResult,
  type AWSExecutiveOutcomeMetric,
  type AWSExecutiveOutcomeViewQuery,
  type AWSExecutiveOutcomeViewResult,
  type AWSPlatformObservabilityMetric,
  type AWSPlatformObservabilityQuery,
  type AWSPlatformObservabilityResult,
  type AWSPlatformObservabilityTrace,
  type AWSGADemoHardeningQuery,
  type AWSGADemoHardeningResult,
  type AWSGADemoHardeningStage,
  type AWSGADemoHardeningReadinessCheck,
  type AWSSessionPolicyRecommendationEntry,
  type AWSSessionPolicyRecommendationResult,
  type AWSAgentCoreGatewayPolicyAdvisoryEntry,
  type AWSAgentCoreGatewayPolicyAdvisoryResult,
  type AWSTrustPolicyHardeningExecutorEntry,
  type AWSTrustPolicyHardeningExecutorResult,
  type AWSGraphExplorerNode,
  type AWSGraphExplorerResult,
  type AWSGraphExplorerEdge,
  type AWSGraphExplorerPath,
  type AWSGraphExplorerEvidence,
  type AWSBlastRadiusFinding,
  type AWSBlastRadiusResult,
  type AWSLeastPrivilegeRecommendation,
  type AWSLeastPrivilegeResult,
  type AWSUnusedDormantAccessFinding,
  type AWSUnusedDormantAccessResult,
  type AWSIdentitySprawlFinding,
  type AWSIdentitySprawlResult,
  type AWSPrivilegeEscalationFinding,
  type AWSPrivilegeEscalationResult,
  type AWSCrossAccountTrustFinding,
  type AWSCrossAccountTrustResult,
  type AWSSecretPermissionEquivalenceFinding,
  type AWSSecretPermissionEquivalenceQuery,
  type AWSSecretPermissionEquivalenceResult,
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
  type AWSPartialFailureReport,
  type AWSECRRepositoryMetadataInventoryResult,
  type AWSECRRepositoryMetadataRecord,
  type AWSDynamoDBRDSReachabilityInventoryResult,
  type AWSDynamoDBRDSReachabilityRecord,
  type AWSCredentialReferencesInventoryResult,
  type AWSCredentialReferenceRecord,
  type AWSAccountRegionCoverageRecord,
  type AWSAccountRegionCoverageResult,
  type AWSCoveragePlanResult,
  type AWSCoveragePlanTarget,
  type AWSFanOutExecutionResult,
  type AWSOrganizationsTopologyAccount,
  type AWSOrganizationsTopologyResult,
  type AWSStackSetOnboardingResult,
  type AWSStackSetOnboardingDiagnostic,
  type AWSStackSetOnboardingInstance,
  type AWSStackSetOnboardingPrerequisite,
  type AWSStackSetOnboardingSummary,
  type AWSStackSetOnboardingCoverageExpectation,
  type AWSStackSetOnboardingRecoveryAction,
  type AWSOrganizationRolloutResult,
  type AWSOrganizationRolloutTargetView,
  type AWSOrganizationRolloutStartRequest,
  type AWSSecretsManagerMetadataInventoryResult,
  type AWSSecretsManagerMetadataRecord,
  type AWSSQSSNSReachabilityInventoryResult,
  type AWSSQSSNSReachabilityRecord,
  type AWSSSMParameterMetadataInventoryResult,
  type AWSSSMParameterMetadataRecord,
  type AWSPermissionPreviewItem,
  type CurrentUserContext,
  type ExecutiveReport,
  type ExecutiveReportDomain,
  type Finding as ApiFinding,
  type FindingTriageEvent,
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
  type RepoFindingDeleteTarget,
  type RepoFindingsBulkDeleteResponse,
  type RepoFindingsSummary,
  type RepoFindingLifecycleStatus,
  type RepoRiskGraph,
  type RepoRiskGraphEdge,
  type RepoRiskGraphEdgeKind,
  type RepoRiskGraphFindingScore,
  type RepoRiskGraphNode,
  type RepoRiskGraphNodeKind,
  type RepoScanRequest,
  type RepoScanRecord,
  type ScanEvent,
  type ScanRecord,
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
  DomainDetailDrawer,
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
  type DomainDataTableColumn,
  type DomainAction,
  type DomainTimelineEntry
} from './components/app/DomainFoundation';
import { getDomainAsset, type DomainAssetKey } from './design/domainAssets';
import { clearMeCache, primeMeCache, useMe } from './hooks/useMe';
import { isFeatureAvailable, type BackendFeatures, useBackendFeatures } from './hooks/useBackendFeatures';
import {
  APPEARANCE_FONT_LABELS,
  APPEARANCE_PRESETS,
  applyAppearancePreferences,
  findAppearancePreset,
  normalizeAppearancePreferences,
  readAppearancePreferences,
  resolveAppearanceThemeMode,
  saveAppearancePreferences,
  type AppearanceFontID,
  type AppearancePreferences,
  type AppearancePresetID,
  type AppearanceReduceMotion,
  type AppearanceThemeMode
} from './appearance';
import {
  FEATURE_ONBOARDING_CONNECTOR_GITHUB as FEATURE_CONNECTOR_GITHUB_V2,
  FEATURE_ONBOARDING_CONNECTOR_K8S as FEATURE_CONNECTOR_K8S,
  FEATURE_ONBOARDING_WIZARD
} from './pages/onboarding/onboardingUtils';
import { OnboardingUnavailableNotice, useOnboardingAvailable } from './components/onboarding/OnboardingAvailability';
import {
  buildRepoFindingSelectionKey,
  findRepoFindingBySelectionKey,
  groupRepoFindingsByRepositoryDateSeverity
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
  no_data: 'No scan yet',
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

type OverviewGitHubConnectionRollup = OverviewConnectionRollup & {
  connectorCount: number;
  configuredConnectorCount: number;
  pendingCount: number;
  statusChecksIncomplete: boolean;
  connectorProjectID?: string;
  connectedProjectID?: string;
  defaultConnection?: GitHubConnectionStatus;
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
const AWS_REGION_PATTERN = /^[a-z]{2}(-gov)?-[a-z]+-[0-9]$/;

type AWSSetupMode = 'cloudformation' | 'organization' | 'selected_ous' | 'selected_accounts' | 'manual';
type AWSPartition = 'aws' | 'aws-us-gov' | 'aws-cn';

const AWS_OU_ID_PATTERN = /^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$/;
const AWS_ORG_ROOT_ID_PATTERN = /^r-[a-z0-9]{4,32}$/;
const AWS_ACCOUNT_ID_PATTERN = /^[0-9]{12}$/;

function splitScopeTokens(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((token) => token.trim())
    .filter(Boolean);
}

function uniqueTokens(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    if (!seen.has(value)) {
      seen.add(value);
      out.push(value);
    }
  }
  return out;
}

function awsSetupModeFromResponse(scopeType: AWSConnectorScopeType): AWSSetupMode {
  switch (scopeType) {
    case 'organization':
      return 'organization';
    case 'selected_ous':
      return 'selected_ous';
    case 'selected_accounts':
      return 'selected_accounts';
    case 'manual_role':
      return 'manual';
    case 'single_account':
    default:
      return 'cloudformation';
  }
}

function awsScopeTypeFromMode(mode: AWSSetupMode): AWSConnectorScopeType {
  switch (mode) {
    case 'organization':
      return 'organization';
    case 'selected_ous':
      return 'selected_ous';
    case 'selected_accounts':
      return 'selected_accounts';
    case 'manual':
      return 'manual_role';
    case 'cloudformation':
    default:
      return 'single_account';
  }
}

type AWSStackSetContractSnapshot = {
  scopeType: AWSConnectorScopeType;
  deploymentMethod: AWSConnectorDeploymentMethod;
  targetRegions: string[];
  targetOUIDs: string[];
  targetAccountIDs: string[];
  excludedAccountIDs: string[];
  autoOnboardNewAccounts: boolean;
  stackSetName: string;
};

function buildStackSetContractSnapshot(
  mode: AWSSetupMode,
  values: {
    organizationRootID: string;
    targetRegions: string[];
    targetOUIDs: string[];
    targetAccountIDs: string[];
    excludedAccountIDs: string[];
    autoOnboardNewAccounts: boolean;
    stackSetName: string;
  }
): AWSStackSetContractSnapshot {
  const targetOUIDs = (() => {
    if (mode === 'selected_ous') {
      return values.targetOUIDs;
    }
    if (mode === 'organization' || mode === 'selected_accounts') {
      return values.organizationRootID ? [values.organizationRootID] : [];
    }
    return [];
  })();
  const targetAccountIDs = mode === 'selected_accounts' ? values.targetAccountIDs : [];
  const excludedAccountIDs = mode !== 'selected_accounts' ? values.excludedAccountIDs : [];
  const autoOnboard = mode === 'organization' || mode === 'selected_ous' ? values.autoOnboardNewAccounts : false;
  return {
    scopeType: awsScopeTypeFromMode(mode),
    // The wizard only issues service-managed StackSet starts today.
    deploymentMethod: 'stackset_service_managed',
    targetRegions: [...values.targetRegions],
    targetOUIDs: [...targetOUIDs],
    targetAccountIDs: [...targetAccountIDs],
    excludedAccountIDs: [...excludedAccountIDs],
    autoOnboardNewAccounts: autoOnboard,
    stackSetName: values.stackSetName
  };
}

function normalizeContractForScope(
  scopeType: AWSConnectorScopeType,
  deploymentMethod: AWSConnectorDeploymentMethod,
  raw: {
    targetRegions?: string[];
    targetOUIDs?: string[];
    targetAccountIDs?: string[];
    excludedAccountIDs?: string[];
    autoOnboardNewAccounts?: boolean;
    stackSetName?: string;
  }
): AWSStackSetContractSnapshot {
  const mode = awsSetupModeFromResponse(scopeType);
  const rootIDs = (raw.targetOUIDs ?? []).filter((id) => AWS_ORG_ROOT_ID_PATTERN.test(id));
  const ouIDs = (raw.targetOUIDs ?? []).filter((id) => AWS_OU_ID_PATTERN.test(id));
  const targetOUIDs = (() => {
    if (mode === 'selected_ous') {
      return ouIDs;
    }
    if (mode === 'organization' || mode === 'selected_accounts') {
      return rootIDs.length > 0 ? [rootIDs[0]] : [];
    }
    return [];
  })();
  const targetAccountIDs = mode === 'selected_accounts' ? [...(raw.targetAccountIDs ?? [])] : [];
  const excludedAccountIDs = mode !== 'selected_accounts' ? [...(raw.excludedAccountIDs ?? [])] : [];
  const autoOnboard =
    mode === 'organization' || mode === 'selected_ous' ? Boolean(raw.autoOnboardNewAccounts) : false;
  return {
    scopeType,
    deploymentMethod,
    targetRegions: [...(raw.targetRegions ?? [])],
    targetOUIDs,
    targetAccountIDs,
    excludedAccountIDs,
    autoOnboardNewAccounts: autoOnboard,
    stackSetName: raw.stackSetName ?? ''
  };
}

function contractFromStartResponse(start: AWSConnectorStartResponse): AWSStackSetContractSnapshot {
  return normalizeContractForScope(start.scope_type, start.deployment_method, {
    targetRegions: start.target_regions,
    targetOUIDs: start.target_ou_ids,
    targetAccountIDs: start.target_account_ids,
    excludedAccountIDs: start.excluded_account_ids,
    autoOnboardNewAccounts: start.auto_onboard_new_accounts,
    stackSetName: start.stack_set_name
  });
}

function contractFromConnection(connection: AWSConnectionStatus): AWSStackSetContractSnapshot {
  return normalizeContractForScope(
    connection.scope_type ?? 'single_account',
    connection.deployment_method ?? 'cloudformation',
    {
      targetRegions: connection.target_regions,
      targetOUIDs: connection.target_ou_ids,
      targetAccountIDs: connection.target_account_ids,
      excludedAccountIDs: connection.excluded_account_ids,
      autoOnboardNewAccounts: connection.auto_onboard_new_accounts,
      stackSetName: connection.stack_set_name
    }
  );
}

function stackSetContractsMatch(a: AWSStackSetContractSnapshot, b: AWSStackSetContractSnapshot): boolean {
  if (a.scopeType !== b.scopeType) {
    return false;
  }
  if (a.deploymentMethod !== b.deploymentMethod) {
    // resumeAWSStackSetConnectorStart compares deployment_method exactly, so
    // a self-managed persisted connector is not resumable from a
    // service-managed wizard start (or vice versa).
    return false;
  }
  if (a.autoOnboardNewAccounts !== b.autoOnboardNewAccounts) {
    return false;
  }
  if (a.stackSetName && b.stackSetName && a.stackSetName !== b.stackSetName) {
    return false;
  }
  const positionalListsEqual = (left: string[], right: string[]) => {
    if (left.length !== right.length) {
      return false;
    }
    return left.every((value, index) => value === right[index]);
  };
  const unorderedListsEqual = (left: string[], right: string[]) => {
    if (left.length !== right.length) {
      return false;
    }
    const l = [...left].sort();
    const r = [...right].sort();
    return l.every((value, index) => value === r[index]);
  };
  return (
    // target_regions is order-sensitive: the first entry is the StackSet home
    // region, matching the backend's derivation.
    positionalListsEqual(a.targetRegions, b.targetRegions) &&
    // Backend normalizeAWSOUIDs/normalizeAWSAccountIDs sort these lists before
    // awsConnectorSetupContractsMatch, so ordering doesn't count as drift.
    unorderedListsEqual(a.targetOUIDs, b.targetOUIDs) &&
    unorderedListsEqual(a.targetAccountIDs, b.targetAccountIDs) &&
    unorderedListsEqual(a.excludedAccountIDs, b.excludedAccountIDs)
  );
}

const AWS_SCOPE_OPTION_LABELS: Record<AWSSetupMode, { title: string; kicker: string; blurb: string }> = {
  cloudformation: {
    kicker: 'Single account',
    title: 'This account',
    blurb: 'Guided CloudFormation setup'
  },
  organization: {
    kicker: 'AWS Organization',
    title: 'All accounts',
    blurb: 'Best for teams'
  },
  selected_ous: {
    kicker: 'Selected scope',
    title: 'Accounts or OUs',
    blurb: 'Choose a subset'
  },
  selected_accounts: {
    kicker: 'Selected scope',
    title: 'Accounts or OUs',
    blurb: 'Choose a subset'
  },
  manual: {
    kicker: 'Bring your own role',
    title: 'Existing IAM role',
    blurb: 'Use an existing read-only role'
  }
};

type AWSChoiceOption = {
  value: string;
  kicker: string;
  title: string;
  blurb: string;
};

function AWSChoiceGroup({
  ariaLabel,
  className,
  options,
  selectedValue,
  onChange
}: {
  ariaLabel: string;
  className: string;
  options: AWSChoiceOption[];
  selectedValue: string | null;
  onChange: (value: string) => void;
}) {
  const groupRef = useRef<HTMLDivElement | null>(null);

  const focusOption = (value: string) => {
    groupRef.current
      ?.querySelector<HTMLButtonElement>(`[data-aws-choice-value="${value}"]`)
      ?.focus();
  };

  const handleKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>, value: string) => {
    const currentIndex = options.findIndex((option) => option.value === value);
    if (currentIndex < 0) {
      return;
    }

    let nextIndex = currentIndex;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      nextIndex = (currentIndex + 1) % options.length;
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      nextIndex = (currentIndex - 1 + options.length) % options.length;
    } else if (event.key === 'Home') {
      nextIndex = 0;
    } else if (event.key === 'End') {
      nextIndex = options.length - 1;
    } else {
      return;
    }

    event.preventDefault();
    const nextValue = options[nextIndex].value;
    onChange(nextValue);
    focusOption(nextValue);
  };

  return (
    <div ref={groupRef} className={className} role="radiogroup" aria-label={ariaLabel}>
      {options.map((option, index) => {
        const isSelected = selectedValue === option.value;
        const isTabStop = isSelected || (selectedValue === null && index === 0);
        return (
          <div className="idt-aws-scope-option-shell" key={option.value}>
            <button
              className={`idt-aws-scope-option ${isSelected ? 'is-selected' : ''}`}
              type="button"
              role="radio"
              aria-checked={isSelected}
              tabIndex={isTabStop ? 0 : -1}
              data-aws-choice-value={option.value}
              onClick={() => onChange(option.value)}
              onKeyDown={(event) => handleKeyDown(event, option.value)}
            >
              <span>{option.kicker}</span>
              <strong>{option.title}</strong>
              <small>{option.blurb}</small>
            </button>
          </div>
        );
      })}
    </div>
  );
}

function awsRoleNameFromARN(roleARN: string): string {
  const match = normalizeValue(roleARN).match(/^arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role\/(.+)$/);
  return match ? match[1] : '';
}

function awsPartitionForManualTrustPolicy(roleARN: string, region: string): AWSPartition {
  const arnPartition = normalizeValue(roleARN).match(/^arn:(aws|aws-us-gov|aws-cn):iam::/)?.[1] as AWSPartition | undefined;
  if (arnPartition) {
    return arnPartition;
  }
  const normalizedRegion = normalizeValue(region).toLowerCase();
  if (normalizedRegion.startsWith('us-gov-')) {
    return 'aws-us-gov';
  }
  if (normalizedRegion.startsWith('cn-')) {
    return 'aws-cn';
  }
  return 'aws';
}

function buildAWSManualTrustPolicy(identrailAccountID: string, externalID: string, partition: AWSPartition = 'aws'): string {
  const accountID = normalizeValue(identrailAccountID);
  const trustGuard = normalizeValue(externalID);
  if (!accountID || !trustGuard) {
    return '';
  }
  return JSON.stringify(
    {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: `arn:${partition}:iam::${accountID}:root`
          },
          Action: 'sts:AssumeRole',
          Condition: {
            StringEquals: {
              'sts:ExternalId': trustGuard
            }
          }
        }
      ]
    },
    null,
    2
  );
}
const SOURCE_ORDER: SourceProvider[] = [
  ...(FEATURE_CONNECTOR_GITHUB_V2 ? (['github'] as SourceProvider[]) : []),
  'aws',
  ...(FEATURE_CONNECTOR_K8S ? (['kubernetes'] as SourceProvider[]) : [])
];
const DOMAIN_NAV_ORDER: SourceProvider[] = ['aws', 'github', 'kubernetes'];
const SHOULD_LOAD_CONNECTOR_BACKEND_FEATURES = FEATURE_CONNECTOR_GITHUB_V2 || FEATURE_CONNECTOR_K8S;
const SOURCE_STACK: SourceProvider[] = [...SOURCE_ORDER];
const SCAN_POLICY_TRIGGER_MODES: ScanTriggerMode[] = ['manual', 'scheduled', 'event', 'hybrid'];
const createDefaultGitHubPATForm = () => ({ displayName: '', baseURL: '', token: '', repositories: '' });
const createDefaultScanPolicyForm = () => ({
  policyID: 'default',
  name: 'Default policy',
  enabled: true,
  triggerMode: 'manual' as ScanTriggerMode,
  cron: '',
  maxConcurrentScans: '1',
  historyLimit: '500',
  maxFindings: '200'
});
const REPO_FINDING_SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
const REPO_FINDING_TYPE_FILTERS = ['all', 'secret_exposure', 'repo_misconfiguration'] as const;
const REPO_FINDING_SORT_FIELDS = ['severity', 'created_at', 'type', 'title'] as const;
const REPO_FINDING_STATUS_FILTERS = ['all', 'open', 'ack', 'suppressed', 'resolved'] as const;
type RepoFindingFilterSnapshot = {
  repoScanFilter: string;
  severityFilter: (typeof REPO_FINDING_SEVERITY_FILTERS)[number];
  typeFilter: (typeof REPO_FINDING_TYPE_FILTERS)[number];
  statusFilter: (typeof REPO_FINDING_STATUS_FILTERS)[number];
  assigneeFilter: string;
  sourceFilter: string;
  minConfidenceFilter: string;
  sortBy: (typeof REPO_FINDING_SORT_FIELDS)[number];
  sortOrder: 'asc' | 'desc';
};
const ENVIRONMENT_QUERY_PARAM = 'environment';
const OVERVIEW_FINDING_LIMIT = 50;
const OVERVIEW_RISK_DISPLAY_LIMIT = 8;
const OVERVIEW_SCAN_LIMIT = 5;
const OVERVIEW_SCAN_FETCH_LIMIT = 50;
const OVERVIEW_PROJECT_PAGE_LIMIT = 100;
const ENVIRONMENT_SELECTOR_LIMIT = 50;
const AI_RISKS_REPO_FINDINGS_PAGE_LIMIT = 100;
const EXECUTIVE_REPORT_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

type ProductDomainRouteID =
  | 'overview'
  | 'connect'
  | 'accounts'
  | 'coverage'
  | 'identities'
  | 'agents'
  | 'resources'
  | 'runtime'
  | 'observability'
  | 'ga-demo'
  | 'graph'
  | 'findings'
  | 'remediation'
  | 'outcomes'
  | 'governance'
  | 'repositories'
  | 'repositories-detail'
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

// Exported for tests that assert nav-configuration invariants (e.g. the
// #1712 drilldown detail route intentionally not appearing in the flyout).
export const PRODUCT_DOMAIN_CONFIGS: Record<SourceProvider, ProductDomainConfig> = {
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
      productDomainRoute('coverage', 'Coverage', 'coverage', 'Coverage', '', 'Account, region, service, and collector coverage states.'),
      productDomainRoute('identities', 'Identities', 'identities', 'Identities', '', 'IAM roles, workload identities, and what they can reach.'),
      productDomainRoute('agents', 'Agents', 'agents', 'Agents', '', 'Bedrock and MCP agents Identrail can see.'),
      productDomainRoute('resources', 'Resources', 'resources', 'Resources', '', 'Secrets, KMS keys, and S3 buckets your AWS roles can reach.'),
      productDomainRoute('runtime', 'Runtime', 'runtime', 'Runtime', '', 'What your AWS roles actually did, from runtime evidence.'),
      productDomainRoute('observability', 'Observability', 'observability', 'Observability', '', 'Platform health, metrics, traces, and alerts for AWS collection and governance.'),
      productDomainRoute('ga-demo', 'GA Demo', 'ga-demo', 'GA Demo', '', 'End-to-end AWS operator walkthrough, permission docs, and GA readiness checks.'),
      productDomainRoute('graph', 'Graph', 'graph', 'Graph', '', 'How AWS roles can reach things, visualised.'),
      productDomainRoute('findings', 'Findings', 'findings', 'Findings', '', 'Prioritized AWS risks for the connected scope.'),
      productDomainRoute('remediation', 'Remediation', 'remediation', 'Remediation', '', 'AWS fixes Identrail prepares for you to approve.'),
      productDomainRoute('outcomes', 'Outcomes', 'outcomes', 'Outcomes', '', 'Executive outcome view for coverage, risk reduction, verified fixes, enforcement, and remaining exposure.'),
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
      // 'repositories-detail' is intentionally NOT registered in the domain
      // config: ProductDomainFlyout classifies every entry here as inventory
      // navigation and renders it with just its `domainRoutePath`, but the
      // drilldown requires a ?repository= query param to render anything
      // other than the "Repository not selected" error. Reach it by clicking
      // a specific repository row on the Repositories page instead.
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
  severity: 'Risk (high â†’ low)',
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

function invalidateGitHubDomainDataCacheForScope(scope: ProductSession | null) {
  if (!scope) {
    return;
  }
  const cachePrefix = `${productScopedCacheKey([scope.tenantID, scope.workspaceID])}::`;
  const cacheKeys = [...gitHubDomainDataCache.keys()].filter((key) => key.startsWith(cachePrefix));
  const requestKeys = [...gitHubDomainDataRequests.keys()].filter((key) => key.startsWith(cachePrefix));
  const epochKeys = [...gitHubDomainDataCacheEpochs.keys()].filter((key) => key.startsWith(cachePrefix));
  for (const key of cacheKeys) {
    gitHubDomainDataCache.delete(key);
  }
  for (const key of requestKeys) {
    gitHubDomainDataRequests.delete(key);
  }
  for (const key of epochKeys) {
    bumpGitHubDomainDataCacheEpoch(key);
  }
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

type OverviewScanLoadResult = {
  items: RepoScanRecord[];
  hasSuccessfulScan: boolean;
  failedScanCount: number;
  historyComplete: boolean;
};

function isOverviewFailedScanStatus(status: unknown): boolean {
  const normalized = normalizeValue(status).toLowerCase();
  return normalized === 'failed' || normalized === 'canceled';
}

async function listOverviewScans(auth: RequestAuthContext): Promise<OverviewScanLoadResult> {
  const response = await apiClient.listRepoScans(
    {
      limit: OVERVIEW_SCAN_FETCH_LIMIT,
      sort_by: 'started_at',
      sort_order: 'desc'
    },
    auth
  );
  const hasServerSummary = typeof response.has_successful_scan === 'boolean';
  const hasSuccessfulScan = hasServerSummary
    ? response.has_successful_scan === true
    : response.items.some((scan) => repoScanStatusTone(scan.status) === 'success');
  const failedScanCount = response.items.filter((scan) => isOverviewFailedScanStatus(scan.status)).length;

  return {
    items: response.items.slice(0, OVERVIEW_SCAN_LIMIT),
    hasSuccessfulScan,
    failedScanCount,
    // Older API deployments may not include the summary. In that case, a
    // cursor means the visible page cannot establish the full history.
    historyComplete: hasServerSummary || !response.next_cursor?.trim()
  };
}

function emptyOverviewGitHubConnectionRollup(): OverviewGitHubConnectionRollup {
  return {
    ...emptyOverviewConnectionRollup(),
    connectorCount: 0,
    configuredConnectorCount: 0,
    pendingCount: 0,
    statusChecksIncomplete: false
  };
}

function githubConnectionHasEvidence(connection: GitHubConnectionStatus): boolean {
  return Boolean(normalizeValue(connection.connector_id)) ||
    connection.status === 'active' ||
    connection.status === 'degraded' ||
    connection.status === 'disconnected' ||
    connection.health_status === 'warning' ||
    connection.health_status === 'error';
}

function githubConnectionNeedsReview(connection: GitHubConnectionStatus): boolean {
  return connection.status === 'degraded' ||
    connection.status === 'disconnected' ||
    connection.health_status === 'warning' ||
    connection.health_status === 'error';
}

function githubConnectionIsPending(connection: GitHubConnectionStatus): boolean {
  return !connection.connected && connection.status === 'pending';
}

function summarizeOverviewGitHubConnections(
  projects: ProjectRecord[],
  results: Array<PromiseSettledResult<{ connection: GitHubConnectionStatus }>>
): OverviewGitHubConnectionRollup {
  const rollup = emptyOverviewGitHubConnectionRollup();
  const defaultProjectID = projects.find((project) => !isProjectArchived(project))?.project_id;

  results.forEach((result, index) => {
    if (result.status !== 'fulfilled' || !result.value.connection) {
      return;
    }
    const connection = result.value.connection;
    rollup.checkedCount += 1;
    if (projects[index]?.project_id === defaultProjectID) {
      rollup.defaultConnection = connection;
    }
    if (!githubConnectionHasEvidence(connection)) {
      return;
    }
    const projectID = projects[index]?.project_id;
    rollup.connectorCount += 1;
    if (projectID && !rollup.connectorProjectID) {
      rollup.connectorProjectID = projectID;
    }
    if (githubConnectionIsPending(connection)) {
      rollup.pendingCount += 1;
    } else {
      rollup.configuredConnectorCount += 1;
    }
    if (connection.connected) {
      rollup.connectedCount += 1;
      if (projectID && !rollup.connectedProjectID) {
        rollup.connectedProjectID = projectID;
      }
    }
    if (githubConnectionNeedsReview(connection)) {
      rollup.degradedCount += 1;
    }
  });
  rollup.statusChecksIncomplete = rollup.checkedCount < projects.length;

  return rollup;
}

async function loadOverviewGitHubConnectionRollup(
  scope: ProductSession,
  projects: ProjectRecord[],
  availability: SourceAvailability,
  auth: RequestAuthContext
): Promise<OverviewGitHubConnectionRollup> {
  const rollup = emptyOverviewGitHubConnectionRollup();
  if (!availability.available) {
    return rollup;
  }
  const activeProjects = projects.filter((project) => !isProjectArchived(project) && project.project_id);
  if (activeProjects.length === 0) {
    return rollup;
  }
  const results = await Promise.allSettled(
    activeProjects.map((project) => apiClient.getGitHubConnectorStatus(scope.workspaceID, project.project_id, auth))
  );
  return summarizeOverviewGitHubConnections(activeProjects, results);
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
      label: 'Net change Â· 7 days',
      value: weekDelta > 0 ? `+${weekDelta}` : String(weekDelta),
      detail: `${report.week_over_week.current_count} new Â· ${report.week_over_week.previous_count} previous`
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
      value: topFindingTypes[0] ? formatTokenLabel(topFindingTypes[0].type) : 'â€”',
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
  const windowLabel = `${formatShortDateLabel(report.window_start)} â€“ ${formatShortDateLabel(report.window_end)}`;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Identrail Â· Executive Report Â· ${escapeReportHtml(report.organization_id)}</title>
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
        <p class="meta">Organization <strong>${escapeReportHtml(report.organization_id)}</strong> Â· Window ${escapeReportHtml(windowLabel)} Â· Generated ${escapeReportHtml(generatedLabel)}</p>
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

function decrementSummaryBucket(values: Record<string, number>, rawKey: string | undefined): Record<string, number> {
  const key = normalizeValue(rawKey ?? '');
  if (!key || !Object.prototype.hasOwnProperty.call(values, key)) {
    return values;
  }
  return {
    ...values,
    [key]: Math.max(0, (values[key] ?? 0) - 1)
  };
}

function repoFindingCountsTowardSLAAged(finding: ApiFinding, now = Date.now()): boolean {
  const lifecycle = normalizeRepoFindingLifecycleStatus(finding.lifecycle_status);
  if (lifecycle !== 'open' && lifecycle !== 'reopened') {
    return false;
  }
  const severity = normalizeValue(finding.severity).toLowerCase();
  if (severity !== 'high' && severity !== 'critical') {
    return false;
  }
  const firstSeen = new Date(finding.first_seen_at || finding.created_at).getTime();
  if (!Number.isFinite(firstSeen)) {
    return false;
  }
  return now - firstSeen >= 14 * 24 * 60 * 60 * 1000;
}

export function decrementRepoFindingsSummaryForDeletedFinding(
  summary: RepoFindingsSummary | null,
  finding: ApiFinding
): RepoFindingsSummary | null {
  if (!summary) {
    return summary;
  }
  const lifecycle = normalizeRepoFindingLifecycleStatus(finding.lifecycle_status);
  const nextSummary: RepoFindingsSummary = {
    ...summary,
    by_owner: decrementSummaryBucket(summary.by_owner, finding.owner || 'unassigned'),
    by_detector: decrementSummaryBucket(summary.by_detector, finding.detector || 'unknown'),
    by_severity: decrementSummaryBucket(summary.by_severity, finding.severity || 'unknown')
  };
  if (lifecycle === 'fixed') {
    nextSummary.fixed_count = Math.max(0, summary.fixed_count - 1);
  } else if (lifecycle === 'reopened') {
    nextSummary.reopened_count = Math.max(0, summary.reopened_count - 1);
    nextSummary.total_open = Math.max(0, summary.total_open - 1);
  } else if (lifecycle === 'suppressed' || lifecycle === 'risk_accepted' || lifecycle === 'false_positive') {
    nextSummary.suppressed_count = Math.max(0, summary.suppressed_count - 1);
  } else {
    nextSummary.total_open = Math.max(0, summary.total_open - 1);
  }
  if (repoFindingCountsTowardSLAAged(finding)) {
    nextSummary.sla_aged_count = Math.max(0, summary.sla_aged_count - 1);
  }
  return nextSummary;
}

export function decrementRepoFindingsSummaryForDeletedFindings(
  summary: RepoFindingsSummary | null,
  findings: ApiFinding[]
): RepoFindingsSummary | null {
  return findings.reduce<RepoFindingsSummary | null>(
    (current, finding) => decrementRepoFindingsSummaryForDeletedFinding(current, finding),
    summary
  );
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

function productSessionKey(scope: ProductSession | null | undefined): string {
  if (!scope) {
    return '';
  }
  return `${scope.tenantID}:${scope.workspaceID}:${scope.projectID ?? ''}`;
}

function normalizeProjectToken(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

function parsePositiveInteger(value: string, label: string): number {
  const normalized = normalizeValue(value);
  const parsed = Number.parseInt(normalized, 10);
  if (!Number.isFinite(parsed) || parsed <= 0 || String(parsed) !== normalized) {
    throw new Error(`${label} must be a positive whole number.`);
  }
  return parsed;
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

function environmentSearch(search: string, environmentID: string, options: { omit?: string[] } = {}): string {
  const params = new URLSearchParams(search);
  const normalized = normalizeValue(environmentID);
  if (normalized) {
    params.set(ENVIRONMENT_QUERY_PARAM, normalized);
  } else {
    params.delete(ENVIRONMENT_QUERY_PARAM);
  }
  for (const key of options.omit ?? []) {
    params.delete(key);
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

function repoScanSourceHealth(scan: RepoScanRecord): string {
  return normalizeValue(scan.source_health || 'complete').toLowerCase();
}

function repoScanHasDegradedSourceHealth(scan: RepoScanRecord): boolean {
  const health = repoScanSourceHealth(scan);
  return health !== '' && health !== 'complete';
}

function repoScanTone(scan: RepoScanRecord): 'success' | 'warning' | 'error' | 'neutral' {
  const tone = repoScanStatusTone(scan.status);
  if (tone === 'success' && repoScanHasDegradedSourceHealth(scan)) {
    return 'warning';
  }
  return tone;
}

function summarizeRepoScanSourceHealth(scan: RepoScanRecord): string {
  switch (repoScanSourceHealth(scan)) {
    case 'partial':
      return 'Partial source collection';
    case 'permission_limited':
      return 'Permission-limited source collection';
    case 'rate_limited':
      return 'Rate-limited source collection';
    case 'unavailable':
      return 'Unavailable source collection';
    case 'unknown':
      return 'Source details unavailable';
    default:
      return '';
  }
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

function repoFindingDeleteTargetFromFinding(finding: ApiFinding): RepoFindingDeleteTarget {
  return {
    finding_id: finding.id,
    repo_scan_id: finding.scan_id
  };
}

export const REPO_FINDING_BULK_DELETE_BATCH_SIZE = 5000;

export function chunkRepoFindingDeleteTargets(
  targets: RepoFindingDeleteTarget[],
  batchSize = REPO_FINDING_BULK_DELETE_BATCH_SIZE
): RepoFindingDeleteTarget[][] {
  const normalizedBatchSize = Math.max(1, Math.floor(batchSize));
  const batches: RepoFindingDeleteTarget[][] = [];
  for (let index = 0; index < targets.length; index += normalizedBatchSize) {
    batches.push(targets.slice(index, index + normalizedBatchSize));
  }
  return batches;
}

function mergeRepoFindingsBulkDeleteResponses(
  responses: RepoFindingsBulkDeleteResponse[]
): RepoFindingsBulkDeleteResponse {
  return responses.reduce<RepoFindingsBulkDeleteResponse>(
    (acc, response) => ({
      deleted: [...acc.deleted, ...response.deleted],
      failed: [...(acc.failed ?? []), ...(response.failed ?? [])]
    }),
    { deleted: [], failed: [] }
  );
}

type RepoFindingBulkDeleteBatchResult = {
  response: RepoFindingsBulkDeleteResponse;
  errorMessage?: string;
};

function repoFindingDeleteBatchErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Failed to delete finding.';
}

export async function deleteRepoFindingTargetsInBatches(
  targets: RepoFindingDeleteTarget[],
  deleteTargets: (batch: RepoFindingDeleteTarget[]) => Promise<RepoFindingsBulkDeleteResponse>,
  batchSize = REPO_FINDING_BULK_DELETE_BATCH_SIZE
): Promise<RepoFindingBulkDeleteBatchResult> {
  const responses: RepoFindingsBulkDeleteResponse[] = [];
  for (const batch of chunkRepoFindingDeleteTargets(targets, batchSize)) {
    try {
      responses.push(await deleteTargets(batch));
    } catch (requestError) {
      const response = mergeRepoFindingsBulkDeleteResponses(responses);
      if (response.deleted.length === 0 && (response.failed ?? []).length === 0) {
        throw requestError;
      }
      return { response, errorMessage: repoFindingDeleteBatchErrorMessage(requestError) };
    }
  }
  return { response: mergeRepoFindingsBulkDeleteResponses(responses) };
}

function isUnsupportedDeleteEndpointError(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 404 || error.status === 405);
}

const UNSUPPORTED_REPO_FINDING_BULK_DELETE_MESSAGE =
  'Clear all requires the bulk delete API. Delete findings individually or update the API.';

async function deleteRepoFindingTargetsWithBulkEndpoint(
  targets: RepoFindingDeleteTarget[],
  auth: RequestAuthContext
): Promise<RepoFindingBulkDeleteBatchResult> {
  try {
    return await deleteRepoFindingTargetsInBatches(targets, (batch) => apiClient.deleteRepoFindings(batch, auth));
  } catch (error) {
    if (!isUnsupportedDeleteEndpointError(error)) {
      throw error;
    }
  }

  return {
    response: {
      deleted: [],
      failed: targets.map((target) => ({
        ...target,
        error: UNSUPPORTED_REPO_FINDING_BULK_DELETE_MESSAGE
      }))
    },
    errorMessage: UNSUPPORTED_REPO_FINDING_BULK_DELETE_MESSAGE
  };
}

function repoFindingDeleteTargetKey(target: RepoFindingDeleteTarget): string {
  return `${target.repo_scan_id}::${target.finding_id}`;
}

function repoFindingDeleteTargetKeyFromFinding(finding: ApiFinding): string {
  return repoFindingDeleteTargetKey(repoFindingDeleteTargetFromFinding(finding));
}

const DISMISSED_REPO_FAILED_SCAN_STORAGE_KEY = 'idt:repo-failed-scan-dismissals:v1';

function failedRepoScanDismissalKey(scope: ProductSession, scanID: string): string {
  return `${scope.tenantID}:${scope.workspaceID}:${scanID}`;
}

function readDismissedRepoFailedScanKeys(): Set<string> {
  if (typeof window === 'undefined') {
    return new Set();
  }
  try {
    const raw = window.localStorage.getItem(DISMISSED_REPO_FAILED_SCAN_STORAGE_KEY);
    if (!raw) {
      return new Set();
    }
    const parsed = JSON.parse(raw);
    return new Set(Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : []);
  } catch {
    return new Set();
  }
}

function writeDismissedRepoFailedScanKeys(keys: Set<string>) {
  if (typeof window === 'undefined') {
    return;
  }
  try {
    window.localStorage.setItem(DISMISSED_REPO_FAILED_SCAN_STORAGE_KEY, JSON.stringify([...keys]));
  } catch {
    // Local storage is an enhancement here; the in-memory dismissal still applies.
  }
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

function hasRepoFindingDeleteAccess(me: CurrentUserContext | null | undefined): boolean {
  return me?.role === 'owner' || me?.role === 'admin';
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

function formatAWSFindingsError(
  error: unknown,
  fallback: string,
  source: 'live' | 'scan' = 'scan'
): string {
  const apiLike = error instanceof Error || (typeof error === 'object' && error !== null)
    ? (error as { status?: number; detail?: string; message?: string })
    : null;
  const detail = normalizeValue(apiLike?.detail);
  if (detail && !['forbidden', 'unauthorized'].includes(detail.toLowerCase())) {
    return detail;
  }
  if (apiLike?.status === 401) {
    return 'Your Identrail session has expired. Sign in again, then retry loading AWS findings.';
  }
  if (apiLike?.status === 403) {
    return 'Identrail denied the findings request for this workspace. Your AWS connection is separate from this access check. Refresh and retry; if it continues, verify the selected workspace or contact your Identrail administrator.';
  }
  if (apiLike?.status === 404) {
    return source === 'live'
      ? 'Identrail could not load live AWS secret-to-permission evidence. Verify the AWS connection and retry.'
      : 'This AWS scan is no longer available. Run AWS discovery again to create a fresh findings result.';
  }
  const message = normalizeValue(formatAPIError(error, ''));
  if (message) {
    return message;
  }
  return fallback;
}

function formatAWSConnectorSetupError(error: unknown): string {
  const apiLike = error instanceof Error || (typeof error === 'object' && error !== null)
    ? (error as { status?: number; detail?: string; message?: string })
    : null;
  if (apiLike) {
    const detail = normalizeValue(apiLike.detail);
    if (detail) {
      return detail;
    }
    if (apiLike.status === 503) {
      return 'AWS CloudFormation setup is not configured for this deployment. Set the connector template URL and Identrail AWS account ID, then redeploy.';
    }
    const message = normalizeValue(apiLike.message);
    if (message && !/^request failed\b/i.test(message)) {
      return message;
    }
    if (apiLike.status === 404) {
      return 'AWS account connection is not enabled for this deployment. Enable the AWS connector backend and redeploy before connecting AWS accounts.';
    }
  }
  return formatAPIError(error, 'Unable to start AWS connector setup.');
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

function AppShellLoading({
  message,
  kicker = 'Loading',
  body = 'Preparing workspace context.'
}: {
  message: string;
  kicker?: string;
  body?: string;
}) {
  return (
    <section className="idt-app-shell-screen" aria-live="polite">
      <article className="idt-app-panel idt-app-loading-panel">
        <p className="idt-app-kicker">{kicker}</p>
        <h1>{message}</h1>
        <p>{body}</p>
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
    return <AppShellLoading message="Preparing workspace" body="Opening your app with the saved account and appearance settings." />;
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
    const code = normalizeValue(query.get('code') ?? '');
    const setupAction = normalizeValue(query.get('setup_action') ?? '');
    const installationID = Number.parseInt(normalizeValue(query.get('installation_id') ?? ''), 10);

    const run = async () => {
      if (!state || !Number.isFinite(installationID) || installationID <= 0) {
        setError(
          'GitHub did not finish the installation â€” the installation details were missing from its response. This usually means setup was cancelled before completing. Start the GitHub connection again to retry.'
        );
        return;
      }
      if (!code) {
        setError(
          'GitHub did not return an authorization code, so we could not verify the installation. Start the GitHub connection again to retry. If this keeps happening, contact support.'
        );
        return;
      }
      try {
        const response = await apiClient.completeGitHubConnector({
          state,
          installation_id: installationID,
          code,
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
          const message =
            callbackError instanceof Error && callbackError.message.trim()
              ? callbackError.message
              : 'We could not complete the GitHub installation. Start the GitHub connection again to retry, and contact support if it persists.';
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
          <h1>Couldn't finish connecting GitHub</h1>
          <p>{error}</p>
          <Link className="idt-btn idt-btn-primary" to="/app">
            Return to app
          </Link>
        </article>
      </section>
    );
  }

  return (
    <AppShellLoading
      kicker="GitHub"
      message="Finishing GitHub connection"
      body="Returning you to Identrail with your saved appearance settings."
    />
  );
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
// actually has today. New surfaces appear here when they ship â€” that is the
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
    stage: 'wired',
    metric: '',
    detail: 'Connected accounts, regions, and coverage anchors.'
  },
  {
    id: 'coverage',
    label: 'Coverage',
    routeID: 'coverage',
    stage: 'wired',
    metric: '',
    detail: 'Track account, region, service, and collector coverage states.'
  },
  {
    id: 'identities',
    label: 'Identities',
    routeID: 'identities',
    stage: 'wired',
    metric: '',
    detail: 'IAM roles and workload identities with reachability evidence.'
  },
  {
    id: 'agents',
    label: 'Agents',
    routeID: 'agents',
    stage: 'wired',
    metric: '',
    detail: 'Bedrock, AgentCore, custom, and MCP-backed agent identities.'
  },
  {
    id: 'resources',
    label: 'Resources',
    routeID: 'resources',
    stage: 'wired',
    metric: '',
    detail: 'Secrets, KMS keys, S3, queues, databases, parameters, ECR, and credential references.'
  },
  {
    id: 'runtime',
    label: 'Runtime',
    routeID: 'runtime',
    stage: 'wired',
    metric: '',
    detail: 'CloudTrail, runtime, tool-call, and policy-use evidence.'
  },
  {
    id: 'findings',
    label: 'Findings',
    routeID: 'findings',
    stage: 'wired',
    metric: '',
    detail: 'AWS risks produced from graph, runtime, and inventory evidence.'
  },
  {
    id: 'remediation',
    label: 'Remediation',
    routeID: 'remediation',
    stage: 'wired',
    metric: '',
    detail: 'Reviewable AWS fixes, dry-runs, approvals, and verification.'
  }
];

function awsStageLabel(stage: AWSCapabilityStage): string {
  if (stage === 'wired') {
    return 'Ready';
  }
  if (stage === 'coming') {
    return 'Needs evidence';
  }
  return 'Unavailable';
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

function awsDiagnosticLabel(code: string): string | null {
  switch (code.trim().toLowerCase()) {
    case 'assume_role_failed':
      return 'Assume role failed';
    case 'external_id_mismatch':
      return 'Trust policy mismatch';
    case 'role_arn_malformed':
      return 'Invalid role ARN';
    case 'missing_read_only_permission_tier':
      return 'Missing permissions';
    default:
      return null;
  }
}

function awsStatusLabel(connection: AWSConnectionStatus | null): string {
  if (!connection) {
    return 'Disconnected';
  }
  const diagnosticLabel = connection.diagnostics.map((diagnostic) => awsDiagnosticLabel(diagnostic.code)).find(Boolean);
  if (diagnosticLabel) {
    return diagnosticLabel;
  }
  const failedChecks = connection.permission_checks.filter((check) => !check.passed);
  if (failedChecks.some((check) => /assume\s*role/i.test(check.name))) {
    return 'Assume role failed';
  }
  if (failedChecks.length > 0) {
    return 'Missing permissions';
  }
  if (connection.health_status === 'error') {
    return 'Needs attention';
  }
  if (connection.health_status === 'warning' || connection.status === 'degraded') {
    return 'Degraded';
  }
  return connection.connected ? 'Connected' : 'Disconnected';
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
  const diagnosticLabel = connection.diagnostics.map((diagnostic) => awsDiagnosticLabel(diagnostic.code)).find(Boolean);
  if (diagnosticLabel && connection.diagnostics.length === 1) {
    return diagnosticLabel;
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
    .join(' Â· ');
}

function awsAccountRegionLabel(connection: AWSConnectionStatus | null): string {
  if (!connection?.account_id && !connection?.region) {
    return 'Pending';
  }
  return [connection.account_id ? `Account ${connection.account_id}` : '', connection.region ? `Region ${connection.region}` : '']
    .filter(Boolean)
    .join(' Â· ');
}

function awsConnectionLabel(connection: AWSConnectionStatus | null): string {
  if (!connection) {
    return 'Not loaded';
  }
  return connection.connected ? 'Connected' : connectionLifecycle(connection);
}

function awsExcludedAccountCount(connection: AWSConnectionStatus): number {
  return connection.target_summary?.excluded_account_count ?? connection.excluded_account_ids.length;
}

function awsExcludedAccountLabel(count: number): string {
  return `${count} excluded account${count === 1 ? '' : 's'}`;
}

function awsConnectedScopeLabel(connection: AWSConnectionStatus): string {
  const excludedCount = awsExcludedAccountCount(connection);
  switch (connection.scope_type) {
    case 'organization':
      if (!connection.target_summary?.all_accounts) {
        return 'Organization';
      }
      return excludedCount > 0
        ? `Organization, all accounts except ${awsExcludedAccountLabel(excludedCount)}`
        : 'Organization, all accounts';
    case 'selected_ous':
      return 'Selected organizational units';
    case 'selected_accounts':
      return 'Selected accounts';
    case 'manual_role':
      return 'Existing IAM role';
    case 'single_account':
    default:
      return 'Single account';
  }
}

function awsConnectedAccountCoverageLabel(connection: AWSConnectionStatus): string {
  const excludedCount = awsExcludedAccountCount(connection);
  if (connection.target_summary?.all_accounts) {
    const coverage = connection.target_summary.account_count_known
      ? `${connection.target_summary.account_count} account${connection.target_summary.account_count === 1 ? '' : 's'}`
      : 'All organization accounts';
    return excludedCount > 0 ? `${coverage} except ${awsExcludedAccountLabel(excludedCount)}` : coverage;
  }
  if (connection.target_summary?.account_count_known) {
    const coverage = `${connection.target_summary.account_count} account${connection.target_summary.account_count === 1 ? '' : 's'}`;
    return excludedCount > 0 ? `${coverage} after ${awsExcludedAccountLabel(excludedCount)}` : coverage;
  }
  if (connection.target_summary) {
    return 'Pending';
  }
  if (connection.target_account_ids.length > 0) {
    return `${connection.target_account_ids.length} account${connection.target_account_ids.length === 1 ? '' : 's'}`;
  }
  return connection.account_id ? `Account ${connection.account_id}` : 'Pending';
}

function awsConnectedRegionCoverageLabel(connection: AWSConnectionStatus): string {
  const count = connection.target_summary?.region_count ?? connection.target_regions.length;
  if (count > 0) {
    return `${count} region${count === 1 ? '' : 's'}`;
  }
  return connection.region ? connection.region : 'Pending';
}

function awsConnectedTradeoffs(connection: AWSConnectionStatus): string[] {
  switch (connection.scope_type) {
    case 'organization':
      return connection.auto_onboard_new_accounts
        ? ['New organization accounts are included automatically.', 'Excluded accounts stay out of collection until removed from the exclusion list.']
        : ['Organization coverage is fixed to the current targets.', 'New accounts need an explicit onboarding update before Identrail collects them.'];
    case 'selected_ous':
      return [
        connection.excluded_account_ids.length > 0
          ? 'Accounts in the selected OUs are collected, except excluded accounts.'
          : 'Only accounts in the selected OUs are collected.',
        connection.auto_onboard_new_accounts
          ? 'New accounts under those OUs are included automatically.'
          : 'New accounts under those OUs need an explicit onboarding update.'
      ];
    case 'selected_accounts':
      return ['Only the selected account IDs are collected.', 'OU movement does not change coverage until the selected account list changes.'];
    case 'manual_role':
      return ['IAM trust and permissions are managed outside Identrail.', 'Update the role manually before rerunning validation.'];
    case 'single_account':
    default:
      return ['Collection is limited to one account and home region.', 'Use Manage connection to expand coverage through an organization or selected scope.'];
  }
}

function awsRouteLink(
  scope: ProductSession,
  routeID: ProductDomainRouteID,
  environmentID: string,
  options: { scanID?: string } = {}
): string {
  const path = appendEnvironmentQuery(domainRoutePath(scope, 'aws', findDomainRoute('aws', routeID)), environmentID);
  if (!options.scanID) {
    return path;
  }
  const separator = path.includes('?') ? '&' : '?';
  return `${path}${separator}scan_id=${encodeURIComponent(options.scanID)}`;
}

function awsDiscoveryPath(
  scope: ProductSession,
  environmentID: string,
  options: { start?: boolean; scanID?: string } = {}
): string {
  const params = new URLSearchParams();
  if (normalizeValue(environmentID)) {
    params.set(ENVIRONMENT_QUERY_PARAM, normalizeValue(environmentID));
  }
  if (options.start) {
    params.set('start', '1');
  }
  if (options.scanID) {
    params.set('scan_id', options.scanID);
  }
  const query = params.toString();
  return `${buildScopedPath(scope, 'aws/discovery')}${query ? `?${query}` : ''}`;
}

function awsRemediationCenterPath(scope: ProductSession, environmentID: string): string {
  return appendEnvironmentQuery(buildScopedPath(scope, 'aws/remediation/center'), environmentID);
}

function awsMachineIdentityDetailLink(
  scope: ProductSession,
  environmentID: string,
  identity: string,
  tab = 'graph'
): string {
  const params = new URLSearchParams();
  const normalizedEnvironmentID = normalizeValue(environmentID);
  const normalizedIdentity = normalizeValue(identity);
  const normalizedTab = normalizeValue(tab);
  if (normalizedEnvironmentID) {
    params.set(ENVIRONMENT_QUERY_PARAM, normalizedEnvironmentID);
  }
  if (normalizedIdentity) {
    params.set('identity', normalizedIdentity);
  }
  if (normalizedTab) {
    params.set('tab', normalizedTab);
  }
  const search = params.toString();
  return `${buildScopedPath(scope, 'aws/identities/detail')}${search ? `?${search}` : ''}`;
}

function awsAgentIdentityDetailLink(
  scope: ProductSession,
  environmentID: string,
  agent: string,
  tab = 'overview'
): string {
  const params = new URLSearchParams();
  const normalizedEnvironmentID = normalizeValue(environmentID);
  const normalizedAgent = normalizeValue(agent);
  const normalizedTab = normalizeValue(tab);
  if (normalizedEnvironmentID) {
    params.set(ENVIRONMENT_QUERY_PARAM, normalizedEnvironmentID);
  }
  if (normalizedAgent) {
    params.set('agent', normalizedAgent);
  }
  if (normalizedTab) {
    params.set('tab', normalizedTab);
  }
  const search = params.toString();
  return `${buildScopedPath(scope, 'aws/agents/detail')}${search ? `?${search}` : ''}`;
}

// githubRepositoryDetailLink returns the drilldown URL for one repository. It
// mirrors the AWS identity/agent detail-link convention: environment carried on
// the environment query param, subject (here: repository slug) as its own param
// so tests and browser deep-links can address a specific repository review.
function githubRepositoryDetailLink(
  scope: ProductSession,
  environmentID: string,
  repository: string
): string {
  const params = new URLSearchParams();
  const normalizedEnvironmentID = normalizeValue(environmentID);
  const normalizedRepository = canonicalGitHubRepositoryDisplay(repository);
  if (normalizedEnvironmentID) {
    params.set(ENVIRONMENT_QUERY_PARAM, normalizedEnvironmentID);
  }
  if (normalizedRepository) {
    params.set('repository', normalizedRepository);
  }
  const search = params.toString();
  return `${buildScopedPath(scope, 'github/repositories/detail')}${search ? `?${search}` : ''}`;
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

  const diagnostics = connection.diagnostics;
  const checks = connection.permission_checks.filter((check) => {
    if (check.passed) {
      return true;
    }
    const normalizedName = check.name.toLowerCase().replace(/[^a-z0-9]/g, '');
    return !diagnostics.some((diagnostic) => {
      if (diagnostic.code === 'assume_role_failed') {
        return normalizedName.includes('assumerole');
      }
      if (diagnostic.code === 'missing_read_only_permission_tier') {
        return !normalizedName.includes('assumerole');
      }
      return diagnostic.evidence_ref === `aws-permission-check:${check.name}`;
    });
  });
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

type AWSGuidedRepairItem = {
  id: string;
  code: string;
  severity: string;
  scope: string;
  message: string;
  operatorAction: string;
  evidenceRef: string;
  tradeoff: string;
  retryable: boolean;
  actions: AWSConnectorNextAction[];
};

function awsRepairSeverityRank(severity: string): number {
  switch (severity) {
    case 'critical':
    case 'blocking':
    case 'error':
      return 0;
    case 'warning':
      return 1;
    default:
      return 2;
  }
}

function awsRepairTone(items: AWSGuidedRepairItem[], connected: boolean): 'success' | 'warning' | 'danger' | 'neutral' {
  if (items.some((item) => awsRepairSeverityRank(item.severity) === 0)) {
    return 'danger';
  }
  if (items.length > 0) {
    return 'warning';
  }
  return connected ? 'success' : 'neutral';
}

function awsRepairStatus(items: AWSGuidedRepairItem[], connected: boolean): string {
  if (items.length === 0) {
    return connected ? 'Healthy' : 'Pending';
  }
  const blockers = items.filter((item) => awsRepairSeverityRank(item.severity) === 0).length;
  if (blockers > 0) {
    return `${blockers} blocker${blockers === 1 ? '' : 's'}`;
  }
  return `${items.length} warning${items.length === 1 ? '' : 's'}`;
}

function awsGuidedRepairItems(connection: AWSConnectionStatus | null, stackSetOnboarding: AWSStackSetOnboardingResult | null): AWSGuidedRepairItem[] {
  const items: AWSGuidedRepairItem[] = [];
  for (const diagnostic of connection?.diagnostics ?? []) {
    items.push(awsRepairItemFromConnectionDiagnostic(diagnostic, connection));
  }
  if ((connection?.diagnostics ?? []).length === 0) {
    for (const check of connection?.permission_checks ?? []) {
      if (check.passed) {
        continue;
      }
      const code = /assumerole/i.test(check.name) ? 'assume_role_failed' : 'missing_read_only_permission_tier';
      items.push({
        id: `check-${check.name}`,
        code,
        severity: 'blocking',
        scope: awsAccountRegionLabel(connection),
        message: check.message,
        operatorAction: check.remediation || (code === 'assume_role_failed' ? 'Update the trust policy, then revalidate the role.' : 'Refresh the expected policy, update the role, then revalidate.'),
        evidenceRef: `aws-permission-check:${check.name}`,
        tradeoff: code === 'missing_read_only_permission_tier' ? 'Identrail will not claim coverage for services it cannot read.' : '',
        retryable: true,
        actions: code === 'assume_role_failed' ? ['copy_trust_policy', 'validate_role', 'refresh_status'] : ['refresh_policy', 'validate_role', 'refresh_status']
      });
    }
  }
  for (const prereq of stackSetOnboarding?.validation.prerequisites ?? connection?.prerequisites ?? []) {
    if (prereq.satisfied) {
      continue;
    }
    const code = prereq.id === 'stackset.trusted_access_enabled'
      ? 'stackset_trusted_access_missing'
      : prereq.id === 'stackset.delegated_admin_registered'
        ? 'delegated_admin_recommended'
        : 'selected_target_missing_stackset_instance';
    items.push({
      id: `prereq-${prereq.id}`,
      code,
      severity: prereq.severity,
      scope: prereq.id,
      message: prereq.reason,
      operatorAction: prereq.remediation || 'Resolve this prerequisite, then refresh status.',
      evidenceRef: `aws-stackset-prerequisite:${prereq.id}`,
      tradeoff: code === 'delegated_admin_recommended' ? 'Delegated administration narrows the management-account blast radius.' : '',
      retryable: true,
      actions: code === 'stackset_trusted_access_missing'
        ? ['open_docs', 'refresh_status']
        : code === 'delegated_admin_recommended'
          ? ['open_docs', 'refresh_status']
          : ['open_stackset', 'refresh_status']
    });
  }
  for (const diagnostic of stackSetOnboarding?.diagnostics ?? []) {
    items.push(awsRepairItemFromStackSetDiagnostic(diagnostic));
  }
  return dedupeAWSGuidedRepairItems(items)
    .sort((left, right) => awsRepairSeverityRank(left.severity) - awsRepairSeverityRank(right.severity))
    .slice(0, 6);
}

function awsRepairItemFromConnectionDiagnostic(diagnostic: AWSConnectionDiagnostic, connection: AWSConnectionStatus | null): AWSGuidedRepairItem {
  return {
    id: `diagnostic-${diagnostic.code}-${diagnostic.affected_scope ?? diagnostic.evidence_ref ?? diagnostic.message}`,
    code: diagnostic.code,
    severity: diagnostic.severity ?? (connection?.connected ? 'warning' : 'blocking'),
    scope: diagnostic.affected_scope ?? awsAccountRegionLabel(connection),
    message: diagnostic.message,
    operatorAction: diagnostic.operator_action ?? diagnostic.remediation ?? 'Resolve this diagnostic, then revalidate the role.',
    evidenceRef: diagnostic.evidence_ref ?? `aws-connector:${diagnostic.code}`,
    tradeoff: diagnostic.tradeoff ?? '',
    retryable: diagnostic.retryable ?? true,
    actions: diagnostic.actions ?? ['validate_role', 'refresh_status']
  };
}

function awsRepairItemFromStackSetDiagnostic(diagnostic: AWSStackSetOnboardingDiagnostic): AWSGuidedRepairItem {
  return {
    id: `stackset-${diagnostic.code}-${diagnostic.affected_scope ?? diagnostic.scope ?? diagnostic.evidence_ref ?? diagnostic.message}`,
    code: diagnostic.code,
    severity: diagnostic.severity ?? 'warning',
    scope: diagnostic.affected_scope ?? diagnostic.scope ?? diagnostic.source,
    message: diagnostic.message,
    operatorAction: diagnostic.operator_action ?? diagnostic.remediation ?? 'Resolve this StackSet diagnostic, then refresh status.',
    evidenceRef: diagnostic.evidence_ref ?? `aws-stackset:${diagnostic.code}`,
    tradeoff: diagnostic.tradeoff ?? '',
    retryable: diagnostic.retryable,
    actions: diagnostic.actions ?? ['open_stackset', 'refresh_status']
  };
}

function dedupeAWSGuidedRepairItems(items: AWSGuidedRepairItem[]): AWSGuidedRepairItem[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.code}\0${item.scope}\0${item.evidenceRef}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function awsRepairActionLabel(action: AWSConnectorNextAction): string {
  switch (action) {
    case 'launch_stack':
      return 'Open AWS stack';
    case 'open_stackset':
      return 'Open StackSet';
    case 'enable_trusted_access':
      return 'Trusted access guide';
    case 'register_delegated_admin':
      return 'Delegated admin guide';
    case 'select_targets':
      return 'Review targets';
    case 'validate_role':
      return 'Revalidate role';
    case 'refresh_status':
      return 'Refresh status';
    case 'repair_permissions':
      return 'Repair permissions';
    case 'refresh_policy':
      return 'Refresh policy';
    case 'copy_trust_policy':
      return 'Copy trust policy';
    case 'open_docs':
      return 'Open runbook';
    case 'start_intelligence':
      return 'Start discovery';
    default:
      return formatTokenLabel(action);
  }
}

function awsOnboardingStatusLabel(status: AWSConnectorOnboardingStatus): string {
  switch (status) {
    case 'waiting_for_aws':
      return 'Waiting for approval';
    case 'registering':
      return 'Creating role';
    case 'validating':
      return 'Verifying access';
    case 'connected':
      return 'Connected';
    case 'needs_fix':
    case 'failed':
      return 'Needs attention';
    case 'expired':
      return 'Expired';
    default:
      return 'Ready';
  }
}

function awsGuidedRepairPriorityLabel(item: AWSGuidedRepairItem, index: number): string {
  if (index !== 0) {
    return formatTokenLabel(item.severity);
  }
  return awsRepairSeverityRank(item.severity) === 0 ? 'Primary blocker' : `Primary ${formatTokenLabel(item.severity).toLowerCase()}`;
}

function AWSGuidedRepairList({
  items,
  actionsForItem
}: {
  items: AWSGuidedRepairItem[];
  actionsForItem: (item: AWSGuidedRepairItem) => DomainAction[];
}) {
  if (items.length === 0) {
    return (
      <article className="idt-aws-repair-card is-clear">
        <strong>All checks passing</strong>
        <p>Connector diagnostics are clear for this environment.</p>
      </article>
    );
  }
  return (
    <div className="idt-aws-repair-list" aria-label="AWS guided repair actions">
      {items.map((item, index) => (
        <article key={item.id} className={`idt-aws-repair-card is-${awsRepairSeverityRank(item.severity) === 0 ? 'blocking' : 'warning'}`}>
          <header>
            <span>{awsGuidedRepairPriorityLabel(item, index)}</span>
            <strong>{formatTokenLabel(item.code)}</strong>
          </header>
          <p>{item.message}</p>
          <p><strong>Next:</strong> {item.operatorAction}</p>
          {item.tradeoff ? <small>{item.tradeoff}</small> : null}
          <dl>
            <div>
              <dt>Scope</dt>
              <dd>{item.scope || 'Current connector'}</dd>
            </div>
            <div>
              <dt>Evidence</dt>
              <dd>{item.evidenceRef}</dd>
            </div>
          </dl>
          <div className="idt-source-actions">
            {actionsForItem(item).map((action, actionIndex) =>
              action.href ? (
                <a
                  key={`${item.id}-${action.label}-${actionIndex}`}
                  className={`idt-btn ${action.variant === 'primary' ? 'idt-btn-primary' : action.variant === 'secondary' ? 'idt-btn-dark' : 'idt-btn-ghost'}`}
                  href={action.href}
                  target={action.target}
                  rel={action.rel ?? (action.target === '_blank' ? 'noreferrer' : undefined)}
                >
                  {action.icon}
                  <span>{action.label}</span>
                </a>
              ) : (
                <button
                  key={`${item.id}-${action.label}-${actionIndex}`}
                  className={`idt-btn ${action.variant === 'primary' ? 'idt-btn-primary' : action.variant === 'secondary' ? 'idt-btn-dark' : 'idt-btn-ghost'}`}
                  type="button"
                  onClick={action.onClick}
                  disabled={action.disabled}
                >
                  {action.icon}
                  <span>{action.label}</span>
                </button>
              )
            )}
          </div>
        </article>
      ))}
    </div>
  );
}

function AWSConnectedSuccessPanel({
  scope,
  environmentID,
  connection,
  baseline,
  refreshing,
  baselineLoading,
  onRefresh,
  onRunBaseline,
  onManageConnection,
  onDisconnect,
  onDisable,
  lifecycleBusy
}: {
  scope: ProductSession;
  environmentID: string;
  connection: AWSConnectionStatus;
  baseline: AWSPlatformBaselineResult | null;
  refreshing: boolean;
  baselineLoading: boolean;
  onRefresh: () => void;
  onRunBaseline: () => void;
  onManageConnection: () => void;
  onDisconnect: () => void;
  onDisable: () => void;
  lifecycleBusy: boolean;
}) {
  const discoveryPath = awsDiscoveryPath(scope, environmentID, { start: true });
  const identitiesPath = awsRouteLink(scope, 'identities', environmentID);
  const coveragePath = awsRouteLink(scope, 'coverage', environmentID);
  const findingsPath = awsRouteLink(scope, 'findings', environmentID);
  const tradeoffs = awsConnectedTradeoffs(connection);
  const connectorConnected = connection.connected;
  const permissionFailures = connection.permission_checks.filter((check) => !check.passed).length;
  const showFindingsAction =
    connection.health_status === 'warning' ||
    connection.health_status === 'error' ||
    connection.status === 'degraded' ||
    permissionFailures > 0;

  return (
    <section className="idt-source-config idt-aws-connected-success" aria-label="AWS connected summary">
      <div className="idt-source-config-header">
        <div className="idt-source-config-title">
          <SourceLogoMark provider="aws" className="is-hero" />
          <div>
            <p className="idt-app-kicker">{connectorConnected ? 'Connected' : 'Needs attention'}</p>
            <h3>{connection.display_name || (connectorConnected ? 'AWS connector is active' : 'AWS connector needs attention')}</h3>
            <p>
              {connection.setup_summary ||
                (connectorConnected
                  ? 'AWS is connected and ready for identity intelligence.'
                  : 'Lifecycle controls remain available while AWS access is repaired.')}
            </p>
          </div>
        </div>
        <DomainStatusBadge
          variant={awsStatusVariant(connection)}
          label={awsStatusLabel(connection)}
          detail={connection.health_status}
        />
      </div>

      <dl className="idt-aws-connected-facts">
        <div>
          <dt>Scope</dt>
          <dd>{awsConnectedScopeLabel(connection)}</dd>
        </div>
        <div>
          <dt>Accounts</dt>
          <dd>{awsConnectedAccountCoverageLabel(connection)}</dd>
        </div>
        <div>
          <dt>Regions</dt>
          <dd>{awsConnectedRegionCoverageLabel(connection)}</dd>
        </div>
        <div>
          <dt>Health</dt>
          <dd>{formatTokenLabel(connection.health_status)}</dd>
        </div>
        <div>
          <dt>Last validation</dt>
      <dd>{formatConnectionTime(connection.last_validated_at)}</dd>
        </div>
        <div>
          <dt>Permissions</dt>
          <dd>
            {connection.permission_checks.length > 0
              ? `${connection.permission_checks.length - permissionFailures}/${connection.permission_checks.length} passed`
              : 'Not validated'}
          </dd>
        </div>
        <div>
          <dt>Readiness</dt>
          <dd>{awsBaselineLabel(baseline)}</dd>
        </div>
      </dl>

      <div className="idt-aws-connected-actions">
        {connectorConnected ? (
          <>
            <Link className="idt-btn idt-btn-primary" to={discoveryPath}>
              Start AWS intelligence
            </Link>
            <Link className="idt-btn idt-btn-dark" to={identitiesPath}>
              Review machine identities
            </Link>
            <Link className="idt-btn idt-btn-secondary" to={coveragePath}>
              View coverage gaps
            </Link>
            {showFindingsAction ? (
              <Link className="idt-btn idt-btn-ghost" to={findingsPath}>
                Review findings
              </Link>
            ) : null}
          </>
        ) : null}
        <button className="idt-btn idt-btn-ghost" type="button" onClick={onRefresh} disabled={refreshing}>
          {refreshing ? 'Refreshing...' : 'Refresh status'}
        </button>
        {connectorConnected ? (
          <button className="idt-btn idt-btn-ghost" type="button" onClick={onRunBaseline} disabled={baselineLoading}>
            {baselineLoading ? 'Running...' : 'Run baseline'}
          </button>
        ) : null}
        <button className="idt-btn idt-btn-ghost" type="button" onClick={onManageConnection}>
          Manage connection
        </button>
        <button className="idt-btn idt-btn-ghost" type="button" onClick={onDisable} disabled={lifecycleBusy}>
          {lifecycleBusy ? 'Updating...' : 'Pause connector'}
        </button>
        <button className="idt-btn idt-btn-ghost" type="button" onClick={onDisconnect} disabled={lifecycleBusy}>
          Disconnect
        </button>
      </div>

      <ul className="idt-aws-connected-tradeoffs" aria-label="AWS setup tradeoffs">
        {tradeoffs.map((tradeoff) => (
          <li key={tradeoff}>{tradeoff}</li>
        ))}
      </ul>
    </section>
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
            {check.required ? 'Required' : 'Optional'} Â· confidence {formatConfidenceScore(check.confidence)} Â·{' '}
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
  return `${formatCountLabel(index.ready_issue_count, 'ready issue')} Â· ${formatCountLabel(index.blocked_issue_count, 'blocked issue')} Â· ${formatCountLabel(
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
            {check.required ? 'Required' : 'Optional'} Â· confidence {formatConfidenceScore(check.confidence)} Â·{' '}
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
  return `${formatCountLabel(harness.scenario_count, 'scenario')} Â· ${formatCountLabel(
    harness.browser_steps.length,
    'browser step'
  )} Â· ${formatCountLabel(harness.api_steps.length, 'API step')}`;
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
            {formatTokenLabel(scenario.flow)} Â· confidence {formatConfidenceScore(scenario.confidence)} Â·{' '}
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
  return `${formatCountLabel(contract.required_field_count, 'field')} Â· ${formatCountLabel(
    contract.fixture_case_count,
    'fixture'
  )} Â· ${formatCountLabel(contract.graph_edge_count, 'edge')}`;
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
            {check.required ? 'Required' : 'Optional'} Â· confidence {formatConfidenceScore(check.confidence)} Â·{' '}
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

type AWSInventoryRouteID = Extract<ProductDomainRouteID, 'accounts' | 'coverage' | 'identities' | 'agents' | 'resources'>;
type AWSCoverageInventoryRouteID = Extract<AWSInventoryRouteID, 'accounts' | 'coverage'>;

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
  coverage: {
    routeID: 'coverage',
    title: 'Coverage',
    eyebrow: '',
    description: 'Account, region, service, and collector coverage for this AWS environment.',
    statusLabel: '',
    primaryKpi: 'Target coverage',
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
  detailIdentity?: string;
  detailAgent?: string;
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

type AWSInventoryEventDrivenState = {
  inventory: AWSEventDrivenRoleInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryManagedComputeState = {
  inventory: AWSManagedComputeRoleInventoryResult | null;
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

type AWSInventoryAIAgentState = {
  inventory: AWSAIAgentIdentityInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryBedrockAgentsState = {
  inventory: AWSBedrockAgentsInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventorySecretsManagerState = {
  inventory: AWSSecretsManagerMetadataInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventorySSMParameterState = {
  inventory: AWSSSMParameterMetadataInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryECRRepositoryState = {
  inventory: AWSECRRepositoryMetadataInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventorySQSSNSState = {
  inventory: AWSSQSSNSReachabilityInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryDynamoDBRDSState = {
  inventory: AWSDynamoDBRDSReachabilityInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryCredentialReferencesState = {
  inventory: AWSCredentialReferencesInventoryResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryCoveragePlanState = {
  plan: AWSCoveragePlanResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryAccountRegionCoverageState = {
  coverage: AWSAccountRegionCoverageResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryFanOutExecutionState = {
  execution: AWSFanOutExecutionResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryOrganizationsTopologyState = {
  topology: AWSOrganizationsTopologyResult | null;
  loading: boolean;
  error: string;
  onRetry: () => void;
};

type AWSInventoryStackSetOnboardingState = {
  onboarding: AWSStackSetOnboardingResult | null;
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
  coverage: { account: 'all', region: 'all', coverage: 'all', search: '' },
  identities: { identityType: 'all', service: 'all', risk: 'all', status: 'all', search: '' },
  agents: { surface: 'all', relationship: 'all', provider: 'all', runtime: 'all', risk: 'all', confidence: 'all', status: 'all', search: '' },
  resources: { category: 'all', sensitivity: 'all', readPosture: 'all', search: '' }
};

const AWS_INVENTORY_FILTERS: AWSInventoryFilterConfigMap = {
  accounts: [
    { id: 'account', label: 'Account', options: [{ label: 'All accounts', value: 'all' }, { label: 'Connected account', value: 'connected' }, { label: 'Additional accounts', value: 'planned' }] },
    { id: 'region', label: 'Region', options: [{ label: 'All regions', value: 'all' }, { label: 'Current region', value: 'current' }, { label: 'Uncovered regions', value: 'uncovered' }] },
    {
      id: 'coverage',
      label: 'Coverage',
      options: [
        { label: 'All coverage', value: 'all' },
        { label: 'Covered', value: 'covered' },
        { label: 'Queued', value: 'planned' },
        { label: 'Missing', value: 'missing' },
        { label: 'Blocked', value: 'blocked' },
        { label: 'Unsupported', value: 'unsupported' },
        { label: 'Disabled', value: 'disabled' },
        { label: 'Degraded', value: 'degraded' },
        { label: 'Failed', value: 'failed' },
        { label: 'Permission denied', value: 'permission_denied' },
        { label: 'Unavailable', value: 'not-yet-available' }
      ]
    }
  ],
  coverage: [
    { id: 'account', label: 'Account', options: [{ label: 'All accounts', value: 'all' }, { label: 'Connected account', value: 'connected' }, { label: 'Additional accounts', value: 'planned' }] },
    { id: 'region', label: 'Region', options: [{ label: 'All regions', value: 'all' }, { label: 'Current region', value: 'current' }, { label: 'Uncovered regions', value: 'uncovered' }] },
    {
      id: 'coverage',
      label: 'Coverage',
      options: [
        { label: 'All coverage', value: 'all' },
        { label: 'Covered', value: 'covered' },
        { label: 'Queued', value: 'planned' },
        { label: 'Missing', value: 'missing' },
        { label: 'Blocked', value: 'blocked' },
        { label: 'Unsupported', value: 'unsupported' },
        { label: 'Disabled', value: 'disabled' },
        { label: 'Degraded', value: 'degraded' },
        { label: 'Failed', value: 'failed' },
        { label: 'Permission denied', value: 'permission_denied' },
        { label: 'Unavailable', value: 'not-yet-available' }
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
        { label: 'Event-driven role', value: 'event-driven-role' },
        { label: 'Managed compute role', value: 'managed-compute-role' },
        { label: 'EKS identity', value: 'eks-identity' },
        { label: 'CI/CD role', value: 'cicd-role' }
      ]
    },
    { id: 'service', label: 'Service', options: [{ label: 'All services', value: 'all' }, { label: 'IAM', value: 'iam' }, { label: 'EC2', value: 'ec2' }, { label: 'ECS', value: 'ecs' }, { label: 'Lambda', value: 'lambda' }, { label: 'CodeBuild', value: 'codebuild' }, { label: 'CodePipeline', value: 'codepipeline' }, { label: 'Step Functions', value: 'stepfunctions' }, { label: 'EventBridge', value: 'eventbridge' }, { label: 'Scheduler', value: 'scheduler' }, { label: 'Pipes', value: 'pipes' }, { label: 'App Runner', value: 'apprunner' }, { label: 'Batch', value: 'batch' }, { label: 'Glue', value: 'glue' }, { label: 'EMR', value: 'emr' }, { label: 'EKS', value: 'eks' }, { label: 'OIDC', value: 'oidc' }] },
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
        { label: 'Ready', value: 'wired-now' },
        { label: 'Degraded', value: 'degraded' },
        { label: 'Disabled', value: 'disabled' },
        { label: 'Needs evidence', value: 'coming' },
        { label: 'Unavailable', value: 'not-yet-available' }
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
        { label: 'AgentCore capabilities', value: 'agentcore-capabilities' },
        { label: 'Custom agents', value: 'custom-agents' },
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
        { label: 'Agent to secret', value: 'agent-to-secret' },
        { label: 'Agent to storage', value: 'agent-to-storage' }
      ]
    },
    {
      id: 'provider',
      label: 'Provider',
      options: [
        { label: 'All providers', value: 'all' },
        { label: 'Amazon Bedrock', value: 'amazon-bedrock' },
        { label: 'AgentCore', value: 'amazon-bedrock-agentcore' },
        { label: 'External provider', value: 'external_provider' },
        { label: 'OpenAI', value: 'openai' },
        { label: 'Anthropic', value: 'anthropic' },
        { label: 'Custom', value: 'custom' }
      ]
    },
    {
      id: 'runtime',
      label: 'Runtime',
      options: [
        { label: 'All runtimes', value: 'all' },
        { label: 'Bedrock', value: 'bedrock' },
        { label: 'AgentCore', value: 'agentcore' },
        { label: 'ECS', value: 'ecs' },
        { label: 'Lambda', value: 'lambda' },
        { label: 'EKS', value: 'eks' },
        { label: 'EC2', value: 'ec2' },
        { label: 'SageMaker', value: 'sagemaker' },
        { label: 'Step Functions', value: 'stepfunctions' },
        { label: 'CodeBuild', value: 'codebuild' }
      ]
    },
    {
      id: 'risk',
      label: 'Risk',
      options: [
        { label: 'All risk', value: 'all' },
        { label: 'High', value: 'high' },
        { label: 'Medium', value: 'medium' },
        { label: 'Low', value: 'low' },
        { label: 'Unscored', value: 'unscored' }
      ]
    },
    {
      id: 'confidence',
      label: 'Confidence',
      options: [
        { label: 'All confidence', value: 'all' },
        { label: '0.90+', value: '0.9' },
        { label: '0.75+', value: '0.75' },
        { label: '0.50+', value: '0.5' }
      ]
    },
    {
      id: 'status',
      label: 'Status',
      options: [{ label: 'All status', value: 'all' }, { label: 'Role anchor', value: 'role-anchor' }, { label: 'Candidate', value: 'candidate' }, { label: 'Degraded', value: 'degraded' }, { label: 'Needs evidence', value: 'coming' }, { label: 'Unavailable', value: 'not-yet-available' }]
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
        { label: 'Credential reference', value: 'credential-reference' },
        { label: 'ECR repository', value: 'ecr-repository' },
        { label: 'KMS', value: 'kms' },
        { label: 'S3', value: 's3' },
        { label: 'Control plane', value: 'control-plane' },
        { label: 'SQS/SNS', value: 'sqs-sns' },
        { label: 'SQS queue', value: 'sqs-queue' },
        { label: 'SNS topic', value: 'sns-topic' },
        { label: 'DynamoDB/RDS', value: 'dynamodb-rds' },
        { label: 'DynamoDB table', value: 'dynamodb_table' },
        { label: 'DynamoDB stream', value: 'dynamodb_stream' },
        { label: 'RDS instance', value: 'rds_instance' },
        { label: 'RDS cluster', value: 'rds_cluster' },
        { label: 'RDS proxy', value: 'rds_proxy' }
      ]
    },
    {
      id: 'sensitivity',
      label: 'Sensitivity',
      options: [
        { label: 'All sensitivity', value: 'all' },
        { label: 'Credential reference', value: 'credential-reference' },
        { label: 'Container image', value: 'container-image' },
        { label: 'Runtime image', value: 'runtime-image' },
        { label: 'Customer data', value: 'customer-data' },
        { label: 'Secret-bearing', value: 'secret-bearing' },
        { label: 'KMS-admin', value: 'kms-admin' },
        { label: 'Control-plane', value: 'control-plane' },
        { label: 'Messaging resource', value: 'messaging-resource' },
        { label: 'Messaging exposure', value: 'messaging-exposure' },
        { label: 'Database resource', value: 'database-resource' },
        { label: 'Database exposure', value: 'database-exposure' }
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

function awsAIAgentIdentityQueryFromFilters(
  filters: AWSInventoryFilterState,
  connection: AWSConnectionStatus
): AWSAIAgentIdentityQuery {
  const query: AWSAIAgentIdentityQuery = {
    connectorID: connection.connector_id,
    accountID: connection.account_id,
    region: connection.region
  };
  if (filters.provider && filters.provider !== 'all') {
    query.provider = filters.provider;
  }
  if (filters.runtime && filters.runtime !== 'all') {
    query.runtime = filters.runtime;
  }
  if (filters.status && filters.status !== 'all') {
    query.status = filters.status;
  }
  if (filters.risk && filters.risk !== 'all') {
    query.risk = filters.risk;
  }
  if (filters.confidence && filters.confidence !== 'all') {
    query.minConfidence = filters.confidence;
  }
  return query;
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
          search: environmentSearch(
            location.search,
            environmentID,
            location.pathname.endsWith('/aws/findings') ? { omit: ['scan_id', 'finding_id'] } : undefined
          )
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

function isAWSStackSetConnector(connection: AWSConnectionStatus | null): boolean {
  return Boolean(
    connection &&
      (connection.scope_type === 'organization' ||
        connection.scope_type === 'selected_ous' ||
        connection.scope_type === 'selected_accounts' ||
        connection.deployment_method === 'stackset_service_managed' ||
        connection.deployment_method === 'stackset_self_managed')
  );
}

function awsInventoryPillTone(stage: AWSCapabilityStage): 'success' | 'warning' | 'neutral' {
  return awsStageTone(stage);
}

function awsDisplayStatusLabel(label: string): string {
  const normalizedLabel = normalizeValue(label).toLowerCase();
  switch (normalizedLabel) {
    case 'wired now':
    case 'wired-now':
      return 'Ready';
    case 'coming':
      return 'Needs evidence';
    case 'not yet available':
    case 'not-yet-available':
      return 'Unavailable';
    case 'planned':
      return 'Queued';
    default:
      return label;
  }
}

function AWSInventoryPill({
  stage,
  label
}: {
  stage: AWSCapabilityStage;
  label?: string;
}) {
  return <span className={`idt-aws-inventory-pill is-${awsInventoryPillTone(stage)}`}>{label ? awsDisplayStatusLabel(label) : awsStageLabel(stage)}</span>;
}

function awsCoveragePlanFilterValue(state: string): string {
  switch (state) {
    case 'covered':
      return 'covered';
    case 'failed':
    case 'partial':
    case 'permission_denied':
    case 'in_progress':
      return 'degraded';
    case 'blocked':
    case 'planned':
    case 'pending':
      return 'missing';
    case 'unsupported':
      return 'unsupported';
    case 'disabled':
      return 'disabled';
    default:
      return 'not-yet-available';
  }
}

function awsCoveragePlanStage(state: string): AWSCapabilityStage {
  return state === 'covered'
    ? 'wired'
    : state === 'disabled' || state === 'unsupported' || state === 'suspended'
      ? 'not-available'
      : 'coming';
}

function hasAWSCoverageObservedAt(value?: string): boolean {
  const timestamp = value?.trim();
  return Boolean(timestamp && !timestamp.startsWith('0001-01-01T00:00:00'));
}

function awsCoveragePlanTargetDetail(target: AWSCoveragePlanTarget): string {
  const details = [`Priority ${formatTokenLabel(target.priority)}`];
  if (target.failure_reason) {
    details.push(target.failure_reason);
  }
  if (target.reason) {
    details.push(target.reason);
  }
  if (target.prerequisites.length > 0) {
    details.push(target.prerequisites[0]);
  }
  if (target.cursor) {
    details.push(`Cursor ${target.cursor}`);
  }
  if (target.collector) {
    details.push(`Collector ${formatTokenLabel(target.collector)}`);
  }
  if (hasAWSCoverageObservedAt(target.observed_at)) {
    details.push(`Observed ${formatConnectionTime(target.observed_at)}`);
  }
  if (details.length === 1) {
    details.push(target.next_action);
  }
  if (target.attempts) {
    details.push(`${target.attempts} ${target.attempts === 1 ? 'attempt' : 'attempts'}`);
  }
  return details.join(' Â· ');
}

function awsAccountRegionCoverageDetail(record: AWSAccountRegionCoverageRecord): string {
  const details: string[] = [];
  if (record.failure_reason) {
    details.push(record.failure_reason);
  }
  if (record.checkpoint || record.cursor) {
    details.push(`Checkpoint ${record.checkpoint ?? record.cursor}`);
  }
  if (record.attempts) {
    details.push(`${record.attempts} ${record.attempts === 1 ? 'attempt' : 'attempts'}`);
  }
  if (record.evidence_ref) {
    details.push(record.evidence_ref);
  }
  if (hasAWSCoverageObservedAt(record.observed_at)) {
    details.push(`Observed ${formatConnectionTime(record.observed_at)}`);
  }
  if (details.length === 0) {
    details.push(record.next_action);
  } else {
    details.push(record.next_action);
  }
  return details.join(' Â· ');
}

function awsAccountRegionCoverageFilterValue(status: string): string {
  switch (status) {
    case 'covered':
      return 'covered';
    case 'disabled':
    case 'suspended':
      return 'disabled';
    case 'missing':
    case 'unreachable':
      return 'missing';
    case 'degraded':
    case 'permission_denied':
    case 'stale':
      return 'degraded';
    default:
      return awsCoveragePlanFilterValue(status);
  }
}

function buildAWSAccountRegionCoverageRows(
  coverage: AWSAccountRegionCoverageResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryCoverageRow[] {
  if (coverage?.records.length) {
    return coverage.records.map((record) => {
      const filterValue = awsAccountRegionCoverageFilterValue(record.coverage_status);
      const accountFilter = connection?.account_id && record.account_id === connection.account_id ? 'connected,planned' : 'planned';
      const regionFilter =
        connection?.region && record.region.toLowerCase() === connection.region.toLowerCase() ? 'current' : 'uncovered';
      return {
        id: record.key,
        category: `${record.account_name || record.account_id} / ${record.region} / ${formatTokenLabel(record.service)}`,
        coverage: record.coverage_status,
        source: record.collector ? formatTokenLabel(record.collector) : record.evidence_ref,
        status: record.state,
        detail: awsAccountRegionCoverageDetail(record),
        filters: {
          account: accountFilter,
          region: regionFilter,
          coverage: `${filterValue},${record.coverage_status},${record.state}`,
          search: ''
        },
        searchText: inventorySearchText([
          record.account_id,
          record.account_name,
          record.region,
          record.service,
          record.service_name,
          record.collector,
          record.state,
          record.coverage_status,
          record.failure_reason,
          record.next_action,
          record.evidence_ref
        ])
      };
    });
  }
  if (loading) {
    return [
      {
        id: 'account-region-coverage-loading',
        category: 'Coverage API',
        coverage: 'planned',
        source: 'AWS account-region coverage API',
        status: 'loading',
        detail: 'Loading public coverage records.',
        filters: { account: 'planned', region: 'uncovered', coverage: 'planned', search: '' },
        searchText: inventorySearchText(['coverage api loading'])
      }
    ];
  }
  return [];
}

function buildAWSCoveragePlanRows(
  plan: AWSCoveragePlanResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryCoverageRow[] {
  if (plan?.targets.length) {
    return plan.targets.map((target) => {
      const coverage = awsCoveragePlanFilterValue(target.state);
      const accountFilter = connection?.account_id && target.account_id === connection.account_id ? 'connected,planned' : 'planned';
      const regionFilter =
        connection?.region && target.region.toLowerCase() === connection.region.toLowerCase() ? 'current' : 'uncovered';
      return {
        id: target.key,
        category: `${target.account_name || target.account_id} / ${target.region} / ${formatTokenLabel(target.service)}`,
        coverage: target.state,
        source: target.evidence_ref,
        status: target.state,
        detail: awsCoveragePlanTargetDetail(target),
        filters: {
          account: accountFilter,
          region: regionFilter,
          coverage: `${coverage},${target.state}`,
          search: ''
        },
        searchText: inventorySearchText([
          target.account_id,
          target.account_name,
          target.region,
          target.service,
          target.service_name,
          target.collector,
          target.state,
          target.priority,
          target.failure_reason,
          target.next_action,
          target.evidence_ref,
          ...target.prerequisites
        ])
      };
    });
  }
  if (loading) {
    return [
      {
        id: 'coverage-plan-loading',
        category: 'Coverage plan',
        coverage: 'planned',
        source: 'AWS coverage planner',
        status: 'loading',
        detail: 'Loading account, region, and service targets.',
        filters: { account: 'planned', region: 'uncovered', coverage: 'planned', search: '' },
        searchText: inventorySearchText(['coverage plan loading'])
      }
    ];
  }
  const accountCoverage = awsCoverageState(connection);
  const currentCoverageFilter = accountCoverage === 'covered' ? 'covered' : accountCoverage === 'degraded' ? 'degraded' : 'missing';
  return [
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
    }
  ];
}

function awsOrganizationsTopologyFilterValue(account: AWSOrganizationsTopologyAccount): string {
  if (
    account.status === 'suspended' ||
    account.status === 'closed' ||
    account.status === 'pending_activation' ||
    account.status === 'pending_closure' ||
    account.state === 'disabled' ||
    account.state === 'unsupported'
  ) {
    return 'missing';
  }
  return awsCoveragePlanFilterValue(account.state);
}

function awsOrganizationsTopologyDetail(account: AWSOrganizationsTopologyAccount): string {
  const details: string[] = [];
  if (account.management) {
    details.push('Management account');
  }
  if (account.delegated_admin_services.length > 0) {
    details.push(`Delegated admin for ${account.delegated_admin_services.map(formatTokenLabel).join(', ')}`);
  }
  if (account.failure_reason) {
    details.push(account.failure_reason);
  } else if (account.eligibility_failure_reason) {
    details.push(account.eligibility_failure_reason);
  } else if (account.cursor) {
    details.push(`Cursor ${account.cursor}`);
  } else {
    details.push(account.next_action);
  }
  if (account.attempts) {
    details.push(`${account.attempts} ${account.attempts === 1 ? 'attempt' : 'attempts'}`);
  }
  return details.join(' Â· ');
}

function buildAWSOrganizationsTopologyRows(
  topology: AWSOrganizationsTopologyResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryCoverageRow[] {
  if (topology?.accounts?.length) {
    return topology.accounts.map((account) => {
      const coverage = awsOrganizationsTopologyFilterValue(account);
      const coverageTokens = [coverage, account.state];
      if (account.status !== 'active') {
        coverageTokens.push(account.status);
      }
      const accountFilter = connection?.account_id && account.account_id === connection.account_id ? 'connected,planned' : 'planned';
      return {
        id: `org-${account.account_id}`,
        category: `${account.account_name || account.account_id} / ${account.ou_path || account.parent_id || 'Root'}`,
        coverage: account.state,
        source: account.evidence_ref,
        status: account.status,
        detail: awsOrganizationsTopologyDetail(account),
        filters: {
          account: accountFilter,
          region: 'current,uncovered',
          coverage: [...new Set(coverageTokens)].join(','),
          search: ''
        },
        searchText: inventorySearchText([
          account.account_id,
          account.account_name,
          account.status,
          account.parent_id,
          account.ou_path,
          account.state,
          account.failure_reason,
          account.eligibility_failure_reason,
          account.next_action,
          account.evidence_ref,
          ...account.delegated_admin_services
        ])
      };
    });
  }
  if (loading) {
    return [
      {
        id: 'organizations-topology-loading',
        category: 'AWS Organizations topology',
        coverage: 'planned',
        source: 'AWS Organizations discovery',
        status: 'loading',
        detail: 'Loading accounts, OUs, parent relationships, and delegated-admin metadata.',
        filters: { account: 'planned', region: 'current,uncovered', coverage: 'planned', search: '' },
        searchText: inventorySearchText(['organizations topology loading'])
      }
    ];
  }
  return [];
}

function buildAWSStackSetOnboardingRows(
  onboarding: AWSStackSetOnboardingResult | null,
  loading: boolean
): AWSInventoryCoverageRow[] {
  if (onboarding?.instances.length) {
    return onboarding.instances.map((instance) => awsStackSetOnboardingInstanceRow(instance, onboarding.account_id ?? '', onboarding.region ?? ''));
  }
  if (onboarding) {
    const validation = onboarding.validation;
    const blocked = validation.status === 'blocked' || validation.status === 'permission_denied';
    return [
      {
        id: 'stackset-onboarding-empty',
        category: 'StackSet onboarding',
        coverage: blocked ? 'missing' : 'planned',
        source: onboarding.stack_set_name,
        status: validation.status,
        detail: blocked
          ? validation.failure_reasons[0] ?? 'Resolve blocking prerequisites before launching the StackSet.'
          : 'Configure target accounts/OUs and regions to populate the StackSet onboarding plan.',
        filters: {
          account: 'planned',
          region: 'uncovered',
          coverage: blocked ? 'missing' : 'planned',
          search: ''
        },
        searchText: inventorySearchText(['stackset onboarding empty', validation.status])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'stackset-onboarding-loading',
        category: 'AWS Organization StackSet onboarding',
        coverage: 'planned',
        source: 'StackSet onboarding planner',
        status: 'loading',
        detail: 'Loading StackSet target accounts, regions, prerequisites, and launch URL.',
        filters: { account: 'planned', region: 'current,uncovered', coverage: 'planned', search: '' },
        searchText: inventorySearchText(['stackset onboarding loading'])
      }
    ];
  }
  return [];
}

function awsStackSetOnboardingInstanceRow(
  instance: AWSStackSetOnboardingInstance,
  connectionAccountID: string,
  connectionRegion: string
): AWSInventoryCoverageRow {
  const coverage = instance.state === 'active'
    ? 'covered'
    : instance.state === 'failed' || instance.state === 'permission_denied' || instance.state === 'suspended' || instance.state === 'blocked' || instance.state === 'unsupported'
      ? 'missing'
      : 'planned';
  const coverageTokens = [coverage, instance.state];
  return {
    id: `stackset-instance-${instance.key}`,
    category: `${instance.account_name || instance.account_id} / ${instance.region_name || instance.region}`,
    coverage,
    source: instance.evidence_ref,
    status: instance.state,
    detail: `${instance.next_action}${instance.failure_reason ? ` (${instance.failure_reason})` : ''}`,
    filters: {
      account: instance.account_id && instance.account_id === connectionAccountID ? 'connected,planned' : 'planned',
      region: instance.region && instance.region === connectionRegion ? 'current' : 'uncovered',
      coverage: [...new Set(coverageTokens)].join(','),
      search: ''
    },
    searchText: inventorySearchText([
      instance.account_id,
      instance.account_name,
      instance.ou_path,
      instance.region,
      instance.region_name,
      instance.state,
      instance.next_action,
      instance.failure_reason,
      instance.evidence_ref
    ])
  };
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
    coverage: 'Search coverage scope',
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
      : routeID === 'coverage'
        ? connection?.connected
          ? 'Tracking'
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
  routeID,
  scope,
  selectedEnvironmentID,
  connection,
  connectPath
}: {
  routeID: AWSInventoryRouteID;
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

  if (!connection?.connected || !connection.connector_id) {
    const isAccountsRoute = routeID === 'accounts';
    return (
      <DomainEmptyState
        eyebrow={isAccountsRoute ? 'Next step' : 'Connector prerequisite'}
        title={isAccountsRoute ? 'Connect AWS to see account inventory' : 'Connect AWS to load live inventory'}
        body={
          isAccountsRoute
            ? 'Connect a read-only AWS role to load accounts, regions, permissions, and diagnostic evidence.'
            : 'Inventory pages show the workspace shape now. Connect the read-only role to load account, region, role, permission, and diagnostic evidence.'
        }
        nextAction={{ label: 'Connect AWS', to: connectPath }}
      />
    );
  }

  return null;
}

function AWSAccountsInventoryContent({
  routeID,
  connection,
  connectPath,
  coveragePlanState,
  accountRegionCoverageState,
  fanOutExecutionState,
  organizationsTopologyState,
  stackSetOnboardingState,
  filters,
  onFiltersChange
}: {
  routeID: AWSCoverageInventoryRouteID;
  connection: AWSConnectionStatus | null;
  connectPath: string;
  coveragePlanState: AWSInventoryCoveragePlanState;
  accountRegionCoverageState: AWSInventoryAccountRegionCoverageState;
  fanOutExecutionState: AWSInventoryFanOutExecutionState;
  organizationsTopologyState: AWSInventoryOrganizationsTopologyState;
  stackSetOnboardingState: AWSInventoryStackSetOnboardingState;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  if (!connection?.connected || !connection.connector_id) {
    return null;
  }

  const accountCoverage = awsCoverageState(connection);
  const hasHealthyCoverage = accountCoverage === 'covered';
  const plan = coveragePlanState.plan;
  const coverageAPI = accountRegionCoverageState.coverage;
  const execution = fanOutExecutionState.execution;
  const topology = organizationsTopologyState.topology;
  const rows = buildAWSCoveragePlanRows(plan, coveragePlanState.loading, connection);
  const coverageAPIRows = buildAWSAccountRegionCoverageRows(coverageAPI, accountRegionCoverageState.loading, connection);
  const topologyRows = buildAWSOrganizationsTopologyRows(topology, organizationsTopologyState.loading, connection);
  const stackSetOnboarding = stackSetOnboardingState.onboarding;
  const stackSetRows = buildAWSStackSetOnboardingRows(stackSetOnboarding, stackSetOnboardingState.loading);
  const passedChecks = connection?.permission_checks.filter((check) => check.passed).length ?? 0;
  const totalChecks = connection?.permission_checks.length ?? 0;
  const coveredAccounts = plan
    ? new Set(plan.targets.filter((target) => target.state === 'covered').map((target) => target.account_id)).size
    : hasHealthyCoverage
      ? 1
      : 0;
  const coveredRegions = plan
    ? new Set(plan.targets.filter((target) => target.state === 'covered').map((target) => target.region)).size
    : hasHealthyCoverage
      ? 1
      : 0;
  const displayedRows = filterAWSInventoryRows(rows, filters);
  const displayedCoverageAPIRows = filterAWSInventoryRows(coverageAPIRows, filters);
  const displayedTopologyRows = filterAWSInventoryRows(topologyRows, filters);
  const partialFailureReports = dedupeAWSPartialFailureReports([
    ...(execution?.partial_failure_reports ?? []),
    ...(plan?.partial_failure_reports ?? [])
  ]);

  return (
    <>
      <AWSInventoryFilterSet routeID={routeID} filters={filters} onChange={onFiltersChange} />
      {coveragePlanState.loading ? <DomainLoadingState label="Loading account and region coverage plan" /> : null}
      {accountRegionCoverageState.loading ? <DomainLoadingState label="Loading account and region coverage API" /> : null}
      {fanOutExecutionState.loading ? <DomainLoadingState label="Loading fan-out execution state" /> : null}
      {organizationsTopologyState.loading ? <DomainLoadingState label="Loading AWS Organizations topology" /> : null}
      {coveragePlanState.error ? (
        <DomainErrorState
          title="Coverage plan could not load"
          body={coveragePlanState.error}
          retryAction={{ label: 'Retry coverage plan', onClick: coveragePlanState.onRetry }}
        />
      ) : null}
      {accountRegionCoverageState.error ? (
        <DomainErrorState
          title="Coverage API could not load"
          body={accountRegionCoverageState.error}
          retryAction={{ label: 'Retry coverage API', onClick: accountRegionCoverageState.onRetry }}
        />
      ) : null}
      {fanOutExecutionState.error ? (
        <DomainErrorState
          title="Fan-out execution could not load"
          body={fanOutExecutionState.error}
          retryAction={{ label: 'Retry fan-out execution', onClick: fanOutExecutionState.onRetry }}
        />
      ) : null}
      {organizationsTopologyState.error ? (
        <DomainErrorState
          title="Organizations topology could not load"
          body={organizationsTopologyState.error}
          retryAction={{ label: 'Retry Organizations topology', onClick: organizationsTopologyState.onRetry }}
        />
      ) : null}
      <section className="idt-aws-inventory-coverage" aria-label="AWS account and region coverage map">
        <DomainCoverageCard label="Account coverage" scanned={coveredAccounts} total={plan?.summary.account_count ?? 1} detail="Configured accounts" />
        <DomainCoverageCard label="Region coverage" scanned={coveredRegions} total={plan?.summary.region_count ?? 1} detail={plan ? `${plan.summary.coverage_percent}% target coverage` : hasHealthyCoverage ? connection?.region ?? 'Pending' : 'Pending'} />
        <DomainCoverageCard
          label="Organizations accounts"
          scanned={topology?.summary.scan_eligible_accounts ?? coveredAccounts}
          total={topology?.summary.account_count ?? plan?.summary.account_count ?? 1}
          detail={topology ? `${topology.fixture_state === 'live' ? 'Live AWS Â· ' : ''}${topology.summary.organizational_unit_count} OUs` : 'Topology pending'}
        />
        <DomainCoverageCard label="Permission evidence" scanned={passedChecks} total={Math.max(totalChecks, 1)} detail="Read-only validation" />
      </section>
      {coverageAPI ? (
        <DomainStatusPanel
          eyebrow="Coverage API"
          title="Public account and region coverage records"
          status={formatTokenLabel(coverageAPI.status)}
          tone={coverageAPI.status === 'blocked' ? 'danger' : coverageAPI.status === 'degraded' ? 'warning' : 'success'}
        >
          <section className="idt-aws-inventory-coverage" aria-label="AWS account and region coverage API summary">
            <DomainCoverageCard
              label="Covered records"
              scanned={coverageAPI.summary.covered_records}
              total={Math.max(coverageAPI.summary.total_records, 1)}
              detail={`${coverageAPI.summary.account_count} accounts`}
            />
            <DomainCoverageCard
              label="Missing records"
              scanned={coverageAPI.summary.missing_records}
              total={Math.max(coverageAPI.summary.total_records, 1)}
              detail={`${coverageAPI.summary.retryable_records} retryable`}
            />
            <DomainCoverageCard
              label="Degraded records"
              scanned={coverageAPI.summary.degraded_records + coverageAPI.summary.permission_denied_records}
              total={Math.max(coverageAPI.summary.total_records, 1)}
              detail={`${coverageAPI.summary.unreachable_records} unreachable`}
            />
            <DomainCoverageCard
              label="Stale records"
              scanned={coverageAPI.summary.stale_records}
              total={Math.max(coverageAPI.summary.total_records, 1)}
              detail={`${coverageAPI.summary.disabled_records + coverageAPI.summary.suspended_records} disabled or suspended`}
            />
          </section>
          <DomainDataTable
            label="AWS account-region coverage API records"
            rows={displayedCoverageAPIRows}
            getRowKey={(row) => row.id}
            columns={[
              { key: 'category', header: 'Coverage scope', render: (row) => <strong>{row.category}</strong> },
              { key: 'coverage', header: 'Status', render: (row) => <AWSInventoryPill stage={awsCoveragePlanStage(row.coverage)} label={formatTokenLabel(row.coverage)} /> },
              { key: 'source', header: 'Collector', render: (row) => row.source },
              { key: 'detail', header: 'Evidence / action', render: (row) => row.detail }
            ]}
          />
        </DomainStatusPanel>
      ) : null}
      {execution ? (
        <DomainStatusPanel
          eyebrow="Fan-out worker"
          title="Account and region execution is target-scoped"
          status={formatTokenLabel(execution.status)}
          tone={execution.status === 'blocked' ? 'danger' : execution.status === 'degraded' ? 'warning' : 'success'}
        >
          <section className="idt-aws-inventory-coverage" aria-label="AWS fan-out execution status">
            <DomainCoverageCard
              label="Worker slots"
              scanned={execution.summary.in_progress_targets}
              total={Math.max(execution.summary.concurrency_limit, 1)}
              detail={`${execution.summary.queued_targets} queued`}
            />
            <DomainCoverageCard
              label="Completed targets"
              scanned={execution.summary.covered_targets}
              total={Math.max(execution.summary.executable_targets, 1)}
              detail={`${execution.summary.skipped_targets} skipped`}
            />
            <DomainCoverageCard
              label="Retryable targets"
              scanned={execution.summary.retryable_targets}
              total={Math.max(execution.summary.executable_targets, 1)}
              detail={`${execution.summary.throttled_targets} throttled`}
            />
            <DomainCoverageCard
              label="Denied targets"
              scanned={execution.summary.permission_denied_targets}
              total={Math.max(execution.summary.executable_targets, 1)}
              detail={`${execution.summary.failed_targets + execution.summary.partial_targets} degraded`}
            />
          </section>
          {execution.diagnostics.length ? (
            <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="AWS fan-out execution diagnostics">
              {execution.diagnostics.map((diagnostic) => (
                <article key={`${diagnostic.code}-${diagnostic.scope ?? diagnostic.source}`}>
                  <strong>{formatTokenLabel(diagnostic.code)}</strong>
                  <p>{diagnostic.message}</p>
                  {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
                </article>
              ))}
            </div>
          ) : null}
          {execution.remediation_hints.length ? (
            <ul className="idt-domain-charter-list">
              {execution.remediation_hints.map((hint) => (
                <li key={hint}>{hint}</li>
              ))}
            </ul>
          ) : null}
        </DomainStatusPanel>
      ) : null}
      {plan?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="Coverage diagnostics"
          title="Planner found explicit recovery work"
          status={formatTokenLabel(plan.status)}
          tone={plan.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="AWS coverage plan diagnostics">
            {plan.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.scope ?? diagnostic.source}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {partialFailureReports.length ? (
        <DomainStatusPanel
          eyebrow="Partial failure reporting"
          title="Degraded targets stay scoped and recoverable"
          status={`${partialFailureReports.length} target${partialFailureReports.length === 1 ? '' : 's'}`}
          tone="warning"
        >
          <AWSPartialFailureReportList reports={partialFailureReports} label="AWS partial failure reports" />
        </DomainStatusPanel>
      ) : null}
      {topology?.diagnostics?.length ? (
        <DomainStatusPanel
          eyebrow="Organizations diagnostics"
          title="Topology discovery has explicit recovery work"
          status={formatTokenLabel(topology.status)}
          tone={topology.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="AWS Organizations topology diagnostics">
            {topology.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.scope ?? diagnostic.source}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      <DomainDataTable
        label="AWS Organizations topology"
        rows={displayedTopologyRows}
        getRowKey={(row) => row.id}
        emptyState={
          <DomainEmptyState
            title="No organization records match this view"
            body="Clear filters or adjust the AWS scope to see organization accounts and OUs."
          />
        }
        columns={[
          { key: 'category', header: 'Account / OU', render: (row) => <strong>{row.category}</strong> },
          { key: 'coverage', header: 'Discovery', render: (row) => <AWSInventoryPill stage={awsCoveragePlanStage(row.coverage)} label={formatTokenLabel(row.coverage)} /> },
          { key: 'status', header: 'Account status', render: (row) => formatTokenLabel(row.status) },
          { key: 'detail', header: 'Detail', render: (row) => row.detail }
        ]}
      />
      {stackSetOnboardingState.loading ? <DomainLoadingState label="Loading StackSet onboarding plan" /> : null}
      {stackSetOnboardingState.error ? (
        <DomainErrorState
          title="StackSet onboarding could not load"
          body={stackSetOnboardingState.error}
          retryAction={{ label: 'Retry StackSet onboarding', onClick: stackSetOnboardingState.onRetry }}
        />
      ) : null}
      {stackSetOnboarding ? (
        <DomainStatusPanel
          eyebrow="StackSet onboarding"
          title="AWS Organization StackSet read-only deployment"
          status={formatTokenLabel(stackSetOnboarding.validation.status)}
              tone={
                stackSetOnboarding.status === 'blocked' || stackSetOnboarding.status === 'permission_denied' || stackSetOnboarding.status === 'partial_failure'
                  ? 'danger'
                  : stackSetOnboarding.status === 'degraded'
                    ? 'warning'
                    : 'success'
              }
          actions={
            stackSetOnboarding.launch_url
              ? [{ label: 'Open StackSet launch URL', to: stackSetOnboarding.launch_url, variant: 'primary' }]
              : undefined
          }
        >
          <section className="idt-aws-inventory-coverage" aria-label="StackSet onboarding plan summary">
            <DomainCoverageCard
              label="Target accounts"
              scanned={stackSetOnboarding.summary.target_accounts_known === false ? 0 : stackSetOnboarding.summary.target_accounts}
              total={Math.max(stackSetOnboarding.summary.target_accounts_known === false ? 1 : stackSetOnboarding.summary.target_accounts, 1)}
              detail={stackSetOnboarding.summary.target_accounts_known === false ? 'Pending AWS resolution' : `${stackSetOnboarding.summary.target_regions} regions`}
            />
            <DomainCoverageCard
              label="Active instances"
              scanned={stackSetOnboarding.summary.active_instances}
              total={Math.max(stackSetOnboarding.summary.total_instances_known === false ? 1 : stackSetOnboarding.summary.total_instances, 1)}
              detail={stackSetOnboarding.summary.deployed_percent_known === false ? 'Pending AWS resolution' : `${stackSetOnboarding.summary.deployed_percent}% deployed`}
            />
            <DomainCoverageCard
              label="Failed or blocked"
              scanned={stackSetOnboarding.summary.failed_instances + stackSetOnboarding.summary.blocked_instances}
              total={Math.max(stackSetOnboarding.summary.total_instances_known === false ? 1 : stackSetOnboarding.summary.total_instances, 1)}
              detail={stackSetOnboarding.summary.total_instances_known === false ? 'Pending AWS resolution' : `${stackSetOnboarding.summary.permission_denied_instances} permission denied`}
            />
            <DomainCoverageCard
              label="Expected coverage"
              scanned={stackSetOnboarding.coverage_expectation.expected_coverage_targets_known === false ? 0 : stackSetOnboarding.coverage_expectation.expected_coverage_targets}
              total={Math.max(stackSetOnboarding.coverage_expectation.expected_coverage_targets_known === false ? 1 : stackSetOnboarding.coverage_expectation.expected_coverage_targets, 1)}
              detail={stackSetOnboarding.coverage_expectation.coverage_percent_known === false ? 'Pending AWS resolution' : `${stackSetOnboarding.coverage_expectation.coverage_percent}% projected`}
            />
          </section>
          {stackSetOnboarding.validation.prerequisites.length ? (
            <ul className="idt-domain-charter-list" aria-label="StackSet onboarding prerequisites">
              {stackSetOnboarding.validation.prerequisites.map((prereq) => (
                <li key={prereq.id}>
                  <strong>{prereq.satisfied ? 'âœ“' : prereq.severity === 'blocking' ? 'âœ—' : '!'} {prereq.title}</strong>
                  {' â€” '}
                  {prereq.reason}
                  {prereq.remediation ? <small> {prereq.remediation}</small> : null}
                </li>
              ))}
            </ul>
          ) : null}
          {stackSetOnboarding.recovery_actions.length ? (
            <ul className="idt-domain-charter-list" aria-label="StackSet onboarding recovery actions">
              {stackSetOnboarding.recovery_actions.map((action) => (
                <li key={action.id}>
                  <strong>{action.title}</strong>
                  {' â€” '}
                  {action.description}
                </li>
              ))}
            </ul>
          ) : null}
          {stackSetOnboarding.diagnostics.length ? (
            <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="StackSet onboarding diagnostics">
              {stackSetOnboarding.diagnostics.map((diagnostic) => (
                <article key={`${diagnostic.code}-${diagnostic.scope ?? diagnostic.source}`}>
                  <strong>{formatTokenLabel(diagnostic.code)}</strong>
                  <p>{diagnostic.message}</p>
                  {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
                </article>
              ))}
            </div>
          ) : null}
        </DomainStatusPanel>
      ) : null}
      {isAWSStackSetConnector(connection) ? (
        <DomainDataTable
          label="StackSet onboarding instances"
          rows={filterAWSInventoryRows(stackSetRows, filters)}
          getRowKey={(row) => row.id}
          emptyState={
            <DomainEmptyState
              title="No onboarding instances match this view"
              body="Clear filters or adjust the AWS scope to see StackSet onboarding progress."
            />
          }
          columns={[
            { key: 'category', header: 'Account / region', render: (row) => <strong>{row.category}</strong> },
            { key: 'coverage', header: 'Stage', render: (row) => <AWSInventoryPill stage={awsCoveragePlanStage(row.coverage)} label={formatTokenLabel(row.coverage)} /> },
            { key: 'status', header: 'Instance state', render: (row) => formatTokenLabel(row.status) },
            { key: 'detail', header: 'Next action', render: (row) => row.detail }
          ]}
        />
      ) : null}
      <DomainDataTable
        label="AWS account and region coverage"
        rows={displayedRows}
        getRowKey={(row) => row.id}
        columns={[
          { key: 'category', header: 'Coverage scope', render: (row) => <strong>{row.category}</strong> },
          { key: 'coverage', header: 'Coverage', render: (row) => <AWSInventoryPill stage={awsCoveragePlanStage(row.coverage)} label={formatTokenLabel(row.coverage)} /> },
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
          Account and region coverage uses the current AWS connector when it exists. The plan stays metadata-only,
          keeps cursor and failure state explicit, and never treats denied or partial targets as successful coverage.
        </p>
        {plan?.remediation_hints.length ? (
          <ul className="idt-domain-charter-list">
            {plan.remediation_hints.map((hint) => (
              <li key={hint}>{hint}</li>
            ))}
          </ul>
        ) : null}
        {topology?.remediation_hints?.length ? (
          <ul className="idt-domain-charter-list">
            {topology.remediation_hints.map((hint) => (
              <li key={hint}>{hint}</li>
            ))}
          </ul>
        ) : null}
      </DomainStatusPanel>
    </>
  );
}

function dedupeAWSPartialFailureReports(reports: AWSPartialFailureReport[]) {
  const seen = new Set<string>();
  const deduped: AWSPartialFailureReport[] = [];
  for (const report of reports) {
    const key = report.key || `${report.account_id}|${report.region}|${report.service}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(report);
  }
  return deduped;
}

function AWSPartialFailureReportList({ reports, label }: { reports: AWSPartialFailureReport[]; label: string }) {
  return (
    <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label={label}>
      {reports.map((report) => (
        <article key={`${report.key}-${report.worker_state ?? report.state}-${report.reason_code}`}>
          <strong>
            {formatTokenLabel(report.service)} Â· {formatTokenLabel(report.reason_code)}
          </strong>
          <p>
            {report.account_id} / {report.region}
            {report.collector ? ` / ${formatTokenLabel(report.collector)}` : ''}
          </p>
          <small>
            {formatTokenLabel(report.worker_state ?? report.state)} Â· {report.retryable ? 'Retryable' : 'Not retryable'}
            {report.attempts ? ` Â· ${report.attempts} attempts` : ''}
            {report.cursor ? ` Â· ${report.cursor}` : ''}
          </small>
          {report.failure_reason ? <p>{report.failure_reason}</p> : null}
          <small>{report.next_action}</small>
        </article>
      ))}
    </div>
  );
}

function AWSMachineIdentitiesContent({
  scope,
  selectedEnvironmentID,
  connection,
  ec2State,
  ecsState,
  lambdaState,
  codeBuildState,
  codePipelineState,
  stepFunctionsState,
  eventDrivenState,
  managedComputeState,
  eksState,
  filters,
  onFiltersChange
}: {
  scope: ProductSession;
  selectedEnvironmentID: string;
  connection: AWSConnectionStatus | null;
  ec2State: AWSInventoryEC2State;
  ecsState: AWSInventoryECSState;
  lambdaState: AWSInventoryLambdaState;
  codeBuildState: AWSInventoryCodeBuildState;
  codePipelineState: AWSInventoryCodePipelineState;
  stepFunctionsState: AWSInventoryStepFunctionsState;
  eventDrivenState: AWSInventoryEventDrivenState;
  managedComputeState: AWSInventoryManagedComputeState;
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
  const eventDrivenInventory = eventDrivenState.inventory;
  const managedComputeInventory = managedComputeState.inventory;
  const eksInventory = eksState.inventory;
  const ec2Rows = buildAWSEC2InstanceProfileRows(ec2Inventory, ec2State.loading, connection);
  const ecsRows = buildAWSECSTaskRoleRows(ecsInventory, ecsState.loading, connection);
  const lambdaRows = buildAWSLambdaExecutionRoleRows(lambdaInventory, lambdaState.loading, connection);
  const codeBuildRows = buildAWSCodeBuildServiceRoleRows(codeBuildInventory, codeBuildState.loading, connection);
  const codePipelineRows = buildAWSCodePipelineDeploymentRoleRows(codePipelineInventory, codePipelineState.loading, connection);
  const stepFunctionsRows = buildAWSStepFunctionsStateMachineRoleRows(stepFunctionsInventory, stepFunctionsState.loading, connection);
  const eventDrivenRows = buildAWSEventDrivenRoleRows(eventDrivenInventory, eventDrivenState.loading, connection);
  const managedComputeRows = buildAWSManagedComputeRoleRows(managedComputeInventory, managedComputeState.loading, connection);
  const eksRows = buildAWSEKSWorkloadIdentityRows(eksInventory, eksState.loading, connection);
  const rows: AWSInventoryTableRow[] = [
    ...(connection?.role_arn
      ? [
          {
            id: 'current-role',
            name: connection.role_arn,
            detailIdentity: connection.role_arn,
            category: 'IAM role',
            scope: awsAccountRegionLabel(connection),
            status: connection.connected ? 'wired now' : 'pending validation',
            stage: connection.connected ? ('wired' as AWSCapabilityStage) : ('coming' as AWSCapabilityStage),
            detail: connection.principal_arn ?? 'Role principal appears after validation.',
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
    ...eventDrivenRows,
    ...managedComputeRows,
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
      {eventDrivenState.loading ? <DomainLoadingState label="Loading EventBridge, Scheduler, and Pipes roles" /> : null}
      {managedComputeState.loading ? <DomainLoadingState label="Loading managed compute roles" /> : null}
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
      {eventDrivenState.error ? (
        <DomainErrorState
          title="Event-driven roles could not load"
          body={eventDrivenState.error}
          retryAction={{ label: 'Retry event-driven inventory', onClick: eventDrivenState.onRetry }}
        />
      ) : null}
      {managedComputeState.error ? (
        <DomainErrorState
          title="Managed compute roles could not load"
          body={managedComputeState.error}
          retryAction={{ label: 'Retry managed compute inventory', onClick: managedComputeState.onRetry }}
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
      {eventDrivenInventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="EventBridge collector diagnostics"
          title="Partial event-driven role evidence"
          status={formatTokenLabel(eventDrivenInventory.status)}
          tone={eventDrivenInventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="EventBridge Scheduler and Pipes role diagnostics">
            {eventDrivenInventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {managedComputeInventory?.diagnostics.length ? (
        <DomainStatusPanel
          eyebrow="Managed compute collector diagnostics"
          title="Partial managed compute role evidence"
          status={formatTokenLabel(managedComputeInventory.status)}
          tone={managedComputeInventory.status === 'blocked' ? 'danger' : 'warning'}
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="Managed compute role diagnostics">
            {managedComputeInventory.diagnostics.map((diagnostic) => (
              <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                <strong>{formatTokenLabel(diagnostic.code)}</strong>
                <p>{diagnostic.message}</p>
                {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
              </article>
            ))}
          </div>
        </DomainStatusPanel>
      ) : null}
      {managedComputeInventory?.coverage_gaps.length ? (
        <DomainStatusPanel
          eyebrow="Managed compute coverage gaps"
          title="Unsupported managed compute services"
          status={`${managedComputeInventory.coverage_gaps.length} gaps`}
          tone="warning"
        >
          <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="Managed compute coverage gaps">
            {managedComputeInventory.coverage_gaps.map((gap) => (
              <article key={`${gap.service}-${gap.status}`}>
                <strong>{formatTokenLabel(gap.service)}</strong>
                <p>{gap.reason}</p>
                {gap.remediation ? <small>{gap.remediation}</small> : null}
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
                  <strong>
                    {row.detailAgent ? (
                      <Link to={awsAgentIdentityDetailLink(scope, selectedEnvironmentID, row.detailAgent)}>{row.name}</Link>
                    ) : row.detailIdentity ? (
                      <Link to={awsMachineIdentityDetailLink(scope, selectedEnvironmentID, row.detailIdentity)}>{row.name}</Link>
                    ) : (
                      row.name
                    )}
                  </strong>
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
    detailIdentity: record.role_arn,
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
    detailIdentity: record.role_arn,
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
    detailIdentity: record.role_arn,
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
    detailIdentity: record.role_arn,
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
    detailIdentity: record.role_arn,
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
    detailIdentity: record.role_arn,
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

function buildAWSEventDrivenRoleRows(
  inventory: AWSEventDrivenRoleInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsEventDrivenRoleRow(record));
  }
  if (inventory?.status === 'blocked') {
    return eventDrivenFallbackRows(inventory, 'not-yet-available', 'not-available', 'not yet available', inventory.failure_reasons[0] ?? 'Event-driven role collection is blocked.');
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    const filterStatus = degraded ? 'degraded' : 'wired-now';
    return eventDrivenFallbackRows(
      inventory,
      filterStatus,
      'wired',
      degraded ? 'degraded' : 'wired now',
      degraded
        ? (inventory.failure_reasons[0] ?? 'Event-driven collection completed with degraded evidence and no retained records.')
        : 'The collector completed for this account and region without matching invocation roles.'
    );
  }
  if (loading) {
    return eventDrivenFallbackRows(null, 'coming', 'coming', 'coming', 'Loading rule target roles, schedule target roles, pipe execution roles, targets, DLQs, and payload-safe metadata.', connection);
  }
  return eventDrivenFallbackRows(null, 'coming', 'coming', 'coming', 'Event-driven role inventory maps rules, schedules, pipes, targets, and DLQs back to IAM roles after AWS is connected.');
}

function eventDrivenFallbackRows(
  inventory: AWSEventDrivenRoleInventoryResult | null,
  filterStatus: string,
  stage: AWSCapabilityStage,
  status: string,
  detail: string,
  connection?: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  const scope = inventory ? awsAccountRegionInventoryLabel(inventory.account_id, inventory.region) : connection ? awsAccountRegionLabel(connection) : 'Account and region expansion';
  const risk = filterStatus === 'degraded' ? 'medium' : filterStatus === 'wired-now' ? 'low' : 'unscored';
  return [
    { service: 'eventbridge', name: 'EventBridge rule roles', category: 'EventBridge rule role' },
    { service: 'scheduler', name: 'EventBridge Scheduler roles', category: 'Scheduler schedule role' },
    { service: 'pipes', name: 'EventBridge Pipes roles', category: 'Pipes execution role' }
  ].map((item) => ({
    id: `event-driven-roles-${item.service}-${filterStatus}`,
    name: item.name,
    category: item.category,
    scope,
    status,
    stage,
    detail,
    filters: { identityType: 'event-driven-role', service: item.service, risk, status: filterStatus, search: '' },
    searchText: inventorySearchText([item.service, item.name, item.category, inventory?.account_id, inventory?.region, filterStatus])
  }));
}

function awsEventDrivenRoleRow(record: AWSEventDrivenRoleRecord): AWSInventoryTableRow {
  const service = record.service || 'eventbridge';
  const disabled = Boolean(record.disabled) || record.status === 'disabled';
  const degraded = record.status === 'degraded' || Boolean(record.execution_data_logging);
  const stage: AWSCapabilityStage = record.role_arn ? 'wired' : 'coming';
  const status = disabled ? 'disabled' : stage === 'wired' ? (degraded ? 'degraded' : 'wired now') : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const workloadLabel = record.workload_name || record.workload_arn || record.workload_id;
  const targetRef = record.target_arn || record.pipe_target_arn || 'target not reported';
  const dlqLabel = record.dead_letter_arns?.length ? `${record.dead_letter_arns.length} DLQs` : 'no DLQ reported';
  const metadataLabel = record.event_pattern_sha256 || record.input_transformer_sha256 ? 'hashed matching metadata retained' : 'no pattern hash reported';
  const risk = record.execution_data_logging ? 'high' : disabled ? 'low' : record.dead_letter_arns?.length ? 'medium' : 'low';
  return {
    id: `event-driven-role-${record.from_node_id}-${record.to_node_id || record.role_arn || record.workload_arn}`,
    name: roleLabel,
    detailIdentity: record.role_arn,
    category: formatTokenLabel(record.workload_type || 'event_driven_role'),
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: `${workloadLabel} runs as ${roleLabel}; target ${targetRef}; ${dlqLabel}; ${metadataLabel}.`,
    filters: {
      identityType: 'event-driven-role',
      service,
      risk,
      status: status === 'wired now' ? 'wired-now' : disabled ? 'disabled' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.role_arn,
      record.role_name,
      record.role_kind,
      record.role_account_id,
      record.workload_arn,
      record.workload_name,
      record.workload_type,
      record.event_bus_name,
      record.event_bus_arn,
      record.schedule_group_name,
      record.schedule_expression,
      record.schedule_timezone,
      record.pipe_source_arn,
      record.pipe_target_arn,
      record.pipe_enrichment_arn,
      record.target_arn,
      record.target_id,
      record.target_service,
      ...(record.dead_letter_arns ?? []),
      record.event_pattern_sha256,
      record.input_transformer_sha256,
      ...(record.log_destination_arns ?? []),
      record.kms_key_arn,
      record.state_reason,
      record.account_id,
      record.region,
      'eventbridge scheduler pipes event driven rule schedule pipe role'
    ])
  };
}

function buildAWSManagedComputeRoleRows(
  inventory: AWSManagedComputeRoleInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsManagedComputeRoleRow(record));
  }
  if (inventory?.status === 'blocked') {
    return managedComputeFallbackRows(inventory, 'not-yet-available', 'not-available', 'not yet available', inventory.failure_reasons[0] ?? 'Managed compute role collection is blocked.');
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    const filterStatus = degraded ? 'degraded' : 'wired-now';
    return managedComputeFallbackRows(
      inventory,
      filterStatus,
      'wired',
      degraded ? 'degraded' : 'wired now',
      degraded
        ? (inventory.failure_reasons[0] ?? 'Managed compute collection completed with degraded evidence and no retained records.')
        : 'The collector completed for this account and region without matching managed compute roles.'
    );
  }
  if (loading) {
    return managedComputeFallbackRows(null, 'coming', 'coming', 'coming', 'Loading App Runner, Batch, Glue, and EMR service role evidence.', connection);
  }
  return managedComputeFallbackRows(null, 'coming', 'coming', 'coming', 'Managed compute inventory maps App Runner, Batch, Glue, and EMR workloads back to IAM roles after AWS is connected.');
}

function managedComputeFallbackRows(
  inventory: AWSManagedComputeRoleInventoryResult | null,
  filterStatus: string,
  stage: AWSCapabilityStage,
  status: string,
  detail: string,
  connection?: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  const scope = inventory ? awsAccountRegionInventoryLabel(inventory.account_id, inventory.region) : connection ? awsAccountRegionLabel(connection) : 'Account and region expansion';
  const risk = filterStatus === 'degraded' ? 'medium' : filterStatus === 'wired-now' ? 'low' : 'unscored';
  return [
    { service: 'apprunner', name: 'App Runner service roles', category: 'App Runner service role' },
    { service: 'batch', name: 'AWS Batch roles', category: 'Batch workload role' },
    { service: 'glue', name: 'AWS Glue roles', category: 'Glue workload role' },
    { service: 'emr', name: 'Amazon EMR roles', category: 'EMR cluster role' }
  ].map((item) => ({
    id: `managed-compute-roles-${item.service}-${filterStatus}`,
    name: item.name,
    category: item.category,
    scope,
    status,
    stage,
    detail,
    filters: { identityType: 'managed-compute-role', service: item.service, risk, status: filterStatus, search: '' },
    searchText: inventorySearchText([item.service, item.name, item.category, inventory?.account_id, inventory?.region, filterStatus])
  }));
}

function awsManagedComputeRoleRow(record: AWSManagedComputeRoleRecord): AWSInventoryTableRow {
  const service = record.service || 'managed-compute';
  const disabled = Boolean(record.disabled) || record.status === 'disabled';
  const degraded = record.status === 'degraded' || record.coverage_status === 'unsupported';
  const stage: AWSCapabilityStage = record.role_arn ? 'wired' : 'coming';
  const status = disabled ? 'disabled' : stage === 'wired' ? (degraded ? 'degraded' : 'wired now') : 'degraded';
  const roleLabel = record.role_name || record.role_arn || 'role unresolved';
  const workloadLabel = record.workload_name || record.workload_arn || record.workload_id;
  const statusLabel = record.resource_status ? `status ${record.resource_status}` : 'status not reported';
  const engineLabel = record.compute_engine ? `engine ${record.compute_engine}` : formatTokenLabel(record.workload_type || 'managed_compute_workload');
  const revisionLabel = record.revision ? `revision ${record.revision}` : '';
  const risk = record.coverage_status === 'unsupported' ? 'medium' : disabled ? 'low' : record.role_kind?.includes('execution') ? 'medium' : 'low';
  return {
    id: `managed-compute-role-${record.from_node_id}-${record.to_node_id || record.role_arn || record.workload_arn}`,
    name: roleLabel,
    detailIdentity: record.role_arn,
    category: formatTokenLabel(record.role_kind || record.workload_type || 'managed_compute_role'),
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: `${workloadLabel} uses ${roleLabel}; ${statusLabel}; ${engineLabel}${revisionLabel ? `; ${revisionLabel}` : ''}.`,
    filters: {
      identityType: 'managed-compute-role',
      service,
      risk,
      status: status === 'wired now' ? 'wired-now' : disabled ? 'disabled' : 'degraded',
      search: ''
    },
    searchText: inventorySearchText([
      record.role_arn,
      record.role_name,
      record.role_kind,
      record.role_account_id,
      record.workload_arn,
      record.workload_name,
      record.workload_type,
      record.resource_arn,
      record.resource_type,
      record.resource_status,
      record.compute_engine,
      record.queue_arn,
      record.cluster_arn,
      record.job_definition_arn,
      record.unsupported_service,
      record.coverage_status,
      record.coverage_reason,
      record.account_id,
      record.region,
      'apprunner batch glue emr managed compute service role job execution'
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
    detailIdentity: record.role_arn,
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
  scope,
  selectedEnvironmentID,
  connection,
  aiAgentState,
  bedrockAgentsState,
  filters,
  onFiltersChange
}: {
  scope: ProductSession;
  selectedEnvironmentID: string;
  connection: AWSConnectionStatus | null;
  aiAgentState: AWSInventoryAIAgentState;
  bedrockAgentsState: AWSInventoryBedrockAgentsState;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const inventory = aiAgentState.inventory;
  const bedrock = bedrockAgentsState.inventory;
  const rows = buildAWSAIAgentIdentityRows(inventory, aiAgentState.loading, connection);
  const bedrockRows = buildAWSBedrockAgentsRows(bedrock, bedrockAgentsState.loading, connection);
  const displayedRows = filterAWSInventoryRows(rows, filters);
  const displayedBedrockRows = filterAWSInventoryRows(bedrockRows, filters);

  return (
    <>
      <AWSInventoryFilterSet routeID="agents" filters={filters} onChange={onFiltersChange} />
      {aiAgentState.loading ? <DomainLoadingState label="Loading AWS AI agent identities" /> : null}
      {aiAgentState.error ? (
        <DomainErrorState
          title="AI agent identities could not load"
          body={aiAgentState.error}
          retryAction={{ label: 'Retry AI agents', onClick: aiAgentState.onRetry }}
        />
      ) : null}
      {inventory ? (
        <DomainStatusPanel
          eyebrow="Normalized agent model"
          title="AI agent identities are metadata-only"
          status={formatTokenLabel(inventory.status)}
          tone={inventory.status === 'blocked' ? 'danger' : inventory.status === 'degraded' ? 'warning' : 'success'}
        >
          <section className="idt-aws-inventory-coverage" aria-label="AWS AI agent identity summary">
            <DomainCoverageCard
              label="Agent records"
              scanned={inventory.record_count}
              total={Math.max(inventory.total_record_count || inventory.record_count, 1)}
              detail={`${inventory.runtime_role_count} runtime roles${inventory.total_record_count > inventory.record_count ? `; ${inventory.record_count}/${inventory.total_record_count} filtered` : ''}`}
            />
            <DomainCoverageCard
              label="Native agents"
              scanned={inventory.bedrock_agent_count + inventory.agentcore_runtime_count}
              total={Math.max(inventory.record_count, 1)}
              detail={`${inventory.gateway_count} gateways`}
            />
            <DomainCoverageCard
              label="Custom agents"
              scanned={inventory.custom_agent_count}
              total={Math.max(inventory.record_count, 1)}
              detail={`${inventory.external_agent_count} external-provider agents`}
            />
            <DomainCoverageCard
              label="Tools"
              scanned={inventory.tool_count}
              total={Math.max(inventory.tool_count, 1)}
              detail={`${inventory.capability_count} capabilities`}
            />
            <DomainCoverageCard
              label="AgentCore capabilities"
              scanned={inventory.capability_agent_count}
              total={Math.max(inventory.record_count, 1)}
              detail={`${inventory.memory_store_count} memory Â· ${inventory.browser_count} browser Â· ${inventory.code_interpreter_count} code`}
            />
            <DomainCoverageCard
              label="External provider keys"
              scanned={inventory.external_provider_key_count}
              total={Math.max(inventory.credential_reference_count, 1)}
              detail={`${inventory.ai_provider_key_count} AI keys, values hidden`}
            />
          </section>
          {inventory.diagnostics.length ? (
            <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="AWS AI agent identity diagnostics">
              {inventory.diagnostics.map((diagnostic) => (
                <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                  <strong>{formatTokenLabel(diagnostic.code)}</strong>
                  <p>{diagnostic.message}</p>
                  {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
                </article>
              ))}
            </div>
          ) : null}
          {inventory.coverage_gaps.length ? (
            <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="AWS AI agent identity sensitive boundaries">
              {inventory.coverage_gaps.map((gap) => (
                <article key={`${gap.capability}-${gap.status}`}>
                  <strong>{formatTokenLabel(gap.capability)}</strong>
                  <p>{gap.reason}</p>
                  {gap.remediation ? <small>{gap.remediation}</small> : null}
                </article>
              ))}
            </div>
          ) : null}
        </DomainStatusPanel>
      ) : null}
      <section className="idt-aws-agent-relationship-grid" aria-label="AWS agent relationship slots">
        {[
          ['Agent to role', inventory ? `${inventory.runtime_role_count} runtime role anchors` : connection?.role_arn ? 'Role anchor available' : 'Waiting for role validation'],
          ['Agent to tool', inventory ? `${inventory.tool_count} tool names` : 'Tool and gateway metadata pending'],
          ['Agent to secret', inventory ? `${inventory.external_provider_key_count} external provider keys, ${inventory.credential_reference_count} credential references; values hidden` : 'Secret metadata only, no value reads'],
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
          {
            key: 'name',
            header: 'Agent surface',
            render: (row) => (
              <strong>
                {row.detailAgent ? (
                  <Link to={awsAgentIdentityDetailLink(scope, selectedEnvironmentID, row.detailAgent)}>{row.name}</Link>
                ) : (
                  row.name
                )}
              </strong>
            )
          },
          { key: 'category', header: 'Category', render: (row) => row.category },
          { key: 'scope', header: 'Scope', render: (row) => row.scope },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> },
          { key: 'detail', header: 'Relationship slot', render: (row) => row.detail }
        ]}
      />
      {bedrockAgentsState.loading ? <DomainLoadingState label="Loading AWS Bedrock Agents" /> : null}
      {bedrockAgentsState.error ? (
        <DomainErrorState
          title="Bedrock Agents could not load"
          body={bedrockAgentsState.error}
          retryAction={{ label: 'Retry Bedrock Agents', onClick: bedrockAgentsState.onRetry }}
        />
      ) : null}
      {bedrock ? (
        <DomainStatusPanel
          eyebrow="Bedrock Agents collector"
          title="Bedrock agent identities are metadata-only"
          status={formatTokenLabel(bedrock.status)}
          tone={bedrock.status === 'blocked' ? 'danger' : bedrock.status === 'degraded' ? 'warning' : 'success'}
        >
          <section className="idt-aws-inventory-coverage" aria-label="AWS Bedrock Agents summary">
            <DomainCoverageCard
              label="Bedrock agents"
              scanned={bedrock.agent_count}
              total={Math.max(bedrock.agent_count, 1)}
              detail={`${bedrock.runtime_role_count} runtime roles`}
            />
            <DomainCoverageCard
              label="Action group tools"
              scanned={bedrock.tool_count}
              total={Math.max(bedrock.tool_count, 1)}
              detail={`${bedrock.knowledge_base_count} knowledge bases`}
            />
            <DomainCoverageCard
              label="Guardrails"
              scanned={bedrock.guardrail_count}
              total={Math.max(bedrock.agent_count, 1)}
              detail={`${bedrock.model_count} foundation models`}
            />
            <DomainCoverageCard
              label="Credential refs"
              scanned={bedrock.credential_reference_count}
              total={Math.max(bedrock.credential_reference_count, 1)}
              detail="Values hidden"
            />
          </section>
          {bedrock.diagnostics.length ? (
            <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="AWS Bedrock Agents diagnostics">
              {bedrock.diagnostics.map((diagnostic) => (
                <article key={`${diagnostic.code}-${diagnostic.source_id ?? diagnostic.collector}`}>
                  <strong>{formatTokenLabel(diagnostic.code)}</strong>
                  <p>{diagnostic.message}</p>
                  {diagnostic.remediation ? <small>{diagnostic.remediation}</small> : null}
                </article>
              ))}
            </div>
          ) : null}
          {bedrock.coverage_gaps.length ? (
            <div className="idt-source-diagnostics idt-aws-control-diagnostics" aria-label="AWS Bedrock Agents sensitive boundaries">
              {bedrock.coverage_gaps.map((gap) => (
                <article key={`${gap.capability}-${gap.status}`}>
                  <strong>{formatTokenLabel(gap.capability)}</strong>
                  <p>{gap.reason}</p>
                  {gap.remediation ? <small>{gap.remediation}</small> : null}
                </article>
              ))}
            </div>
          ) : null}
          {bedrock.remediation_hints.length ? (
            <ul className="idt-domain-charter-list" aria-label="AWS Bedrock Agents remediation hints">
              {bedrock.remediation_hints.map((hint) => (
                <li key={hint}>{hint}</li>
              ))}
            </ul>
          ) : null}
        </DomainStatusPanel>
      ) : null}
      <DomainDataTable
        label="AWS Bedrock Agents inventory"
        rows={displayedBedrockRows}
        getRowKey={(row) => row.id}
        columns={[
          { key: 'name', header: 'Bedrock agent', render: (row) => <strong>{row.name}</strong> },
          { key: 'category', header: 'Category', render: (row) => row.category },
          { key: 'scope', header: 'Scope', render: (row) => row.scope },
          { key: 'status', header: 'Status', render: (row) => <AWSInventoryPill stage={row.stage} label={formatTokenLabel(row.status)} /> },
          { key: 'detail', header: 'Next action', render: (row) => row.detail }
        ]}
      />
    </>
  );
}

function buildAWSBedrockAgentsRows(
  inventory: AWSBedrockAgentsInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsBedrockAgentRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'bedrock-agents-blocked',
        name: 'Bedrock Agents unavailable',
        category: 'Bedrock agent',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'Bedrock Agents collection is blocked by permissions.',
        filters: {
          surface: 'bedrock-agents',
          relationship: 'agent-to-role,agent-to-tool,agent-to-secret',
          provider: 'amazon-bedrock',
          runtime: 'bedrock',
          risk: 'high',
          confidence: 'all',
          status: 'not-yet-available',
          search: ''
        },
        searchText: inventorySearchText(['bedrock agents blocked', inventory.account_id, inventory.region])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'bedrock-agents-empty',
        name: degraded ? 'Bedrock Agents incomplete' : 'No Bedrock Agents found',
        category: 'Bedrock agent',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'role anchor',
        stage: 'wired',
        detail: degraded
          ? (inventory.failure_reasons[0] ?? 'Bedrock Agents collection completed with degraded evidence.')
          : 'No Bedrock agents were observed in this account/region.',
        filters: {
          surface: 'bedrock-agents',
          relationship: 'agent-to-role',
          provider: 'amazon-bedrock',
          runtime: 'bedrock',
          risk: degraded ? 'high' : 'low',
          confidence: 'all',
          status: degraded ? 'degraded' : 'role-anchor',
          search: ''
        },
        searchText: inventorySearchText(['bedrock agents', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'bedrock-agents-loading',
        name: 'Bedrock Agents',
        category: 'Bedrock agent',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading Bedrock agents, action groups, knowledge bases, and guardrails.',
        filters: { surface: 'bedrock-agents', relationship: 'agent-to-role', provider: 'amazon-bedrock', runtime: 'bedrock', risk: 'unscored', confidence: 'all', status: 'coming', search: '' },
        searchText: inventorySearchText(['bedrock agents loading'])
      }
    ];
  }
  return [];
}

function awsBedrockAgentRow(record: AWSBedrockAgentRecord): AWSInventoryTableRow {
  const degraded = record.coverage_status === 'degraded' || record.status === 'degraded';
  const status = degraded ? 'degraded' : 'role anchor';
  const stage = degraded ? 'coming' : 'wired';
  const detail = record.next_action;
  // Derive the relationship filter from the record's actual edges so selecting
  // "Agent to secret" never matches a record that has no credential references,
  // and "Agent to tool" never matches a record without action groups.
  const relationshipTokens: string[] = [];
  if (record.runtime_role_arn) {
    relationshipTokens.push('agent-to-role');
  }
  if (record.tool_names.length > 0) {
    relationshipTokens.push('agent-to-tool');
  }
  if (record.credential_reference_refs.length > 0) {
    relationshipTokens.push('agent-to-secret');
  }
  if (record.memory_store_refs.length > 0) {
    relationshipTokens.push('agent-to-knowledge-base');
  }
  return {
    id: `bedrock-agent-${record.agent_id}`,
    name: record.agent_name || record.agent_id,
    category: record.guardrail_id ? 'Bedrock agent (guardrailed)' : 'Bedrock agent',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail,
    filters: {
      surface: 'bedrock-agents',
      relationship: relationshipTokens.join(','),
      provider: record.provider ?? 'amazon-bedrock',
      runtime: record.service || 'bedrock',
      risk: awsBedrockAgentRiskFilter(record),
      confidence: awsAIAgentConfidenceFilter(record.confidence),
      status: degraded ? 'degraded' : 'role-anchor',
      search: ''
    },
    searchText: inventorySearchText([
      record.agent_id,
      record.agent_name,
      record.agent_arn,
      record.runtime_role_arn,
      record.runtime_role_name,
      record.model_id,
      record.provider,
      record.guardrail_id,
      ...record.tool_names,
      ...record.capability_names,
      record.account_id,
      record.region,
      degraded ? 'degraded' : 'ready'
    ])
  };
}

function awsBedrockAgentRiskFilter(record: AWSBedrockAgentRecord): string {
  if (record.status === 'degraded' || record.coverage_status === 'degraded' || record.coverage_reason) {
    return 'high';
  }
  if (record.confidence === 0) {
    return 'unscored';
  }
  if (record.confidence < 0.75) {
    return 'medium';
  }
  return 'low';
}

function buildAWSAIAgentIdentityRows(
  inventory: AWSAIAgentIdentityInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsAIAgentIdentityRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'ai-agent-identities-blocked',
        name: 'AI agent identities unavailable',
        category: 'AI agent identity',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'AI agent identity collection is blocked.',
        filters: { surface: 'bedrock-agents,agentcore-runtime,mcp-gateway,external-provider-keys', relationship: 'agent-to-role,agent-to-tool,agent-to-secret', status: 'not-yet-available', search: '' },
        searchText: inventorySearchText(['ai agent identity blocked', inventory.account_id, inventory.region])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'ai-agent-identities-empty',
        name: degraded ? 'AI agent identities incomplete' : 'No AI agent identities found',
        category: 'AI agent identity',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'role anchor',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'AI agent identity collection completed with degraded evidence and no retained records.') : 'The collector completed without Bedrock, AgentCore, custom, external-provider-backed, or gateway agent records.',
        filters: { surface: 'bedrock-agents,agentcore-runtime,mcp-gateway,external-provider-keys', relationship: 'agent-to-role', status: degraded ? 'degraded' : 'role-anchor', search: '' },
        searchText: inventorySearchText(['ai agent identity', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'ai-agent-identities-loading',
        name: 'AI agent identities',
        category: 'AI agent identity',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading Bedrock, AgentCore, custom, external-provider-backed, and gateway metadata.',
        filters: { surface: 'bedrock-agents,agentcore-runtime,mcp-gateway,external-provider-keys', relationship: 'agent-to-role,agent-to-tool,agent-to-secret', status: 'coming', search: '' },
        searchText: inventorySearchText(['ai agent identity loading'])
      }
    ];
  }
  return [
    {
      id: 'role-anchor',
      name: connection?.role_arn ?? 'AWS role anchor',
      category: 'Agent-to-role anchor',
      scope: awsAccountRegionLabel(connection),
      status: connection?.connected ? 'role anchor' : 'not yet available',
      stage: connection?.connected ? 'wired' : 'not-available',
      detail: 'AI agent inventory can attach Bedrock, AgentCore, custom, and external agent execution back to this AWS role context.',
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
      detail: 'Agent identity, action groups, tool use, and runtime role relationships are normalized when AWS is connected.',
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
      detail: 'AgentCore runtime, gateway, identity metadata, MCP gateway, and tool relationships are normalized when AWS is connected.',
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
      detail: 'External provider usage mapping uses safe credential-reference metadata, never secret values.',
      filters: {
        surface: 'external-provider-keys',
        relationship: 'agent-to-secret',
        status: 'not-yet-available',
        search: ''
      },
      searchText: inventorySearchText(['external', 'provider', 'keys', 'agent'])
    },
    {
      id: 'ai-agent-identities',
      name: 'AI agent identities',
      category: 'AI agent identity',
      scope: 'Account and region expansion',
      status: 'coming',
      stage: 'coming',
      detail: 'Bedrock, AgentCore, custom, external-provider-backed, and gateway metadata maps agents to runtime roles, tools, and credential references.',
      filters: { surface: 'bedrock-agents,agentcore-runtime,mcp-gateway,external-provider-keys', relationship: 'agent-to-role,agent-to-tool,agent-to-secret', status: 'coming', search: '' },
      searchText: inventorySearchText(['bedrock agentcore custom external provider gateway ai agent'])
    }
  ];
}

function awsAIAgentIdentityRow(record: AWSAIAgentIdentityRecord): AWSInventoryTableRow {
  const candidate = record.status === 'candidate' || record.coverage_status === 'candidate';
  const stage: AWSCapabilityStage = record.status === 'ready' && record.runtime_role_arn ? 'wired' : record.status === 'blocked' ? 'not-available' : 'coming';
  const degraded = !candidate && (record.status !== 'ready' || record.coverage_status === 'degraded' || Boolean(record.coverage_reason));
  const status = candidate ? 'candidate' : stage === 'not-available' ? 'not yet available' : degraded ? 'degraded' : 'role anchor';
  const roleLabel = record.runtime_role_name || record.runtime_role_arn || 'runtime role unresolved';
  const runtimeLabel = record.runtime_version || 'runtime version not reported';
  const toolLabel = record.tool_names?.length ? `${record.tool_names.length} tools` : 'no tools reported';
  const capabilityLabel = record.capability_names?.length ? `${record.capability_names.join(', ')} capabilities` : 'capabilities not reported';
  const credentialLabel = record.credential_reference_refs?.length ? `${record.credential_reference_refs.length} credential refs, values hidden` : 'no credential refs reported';
  const authLabel = record.auth_mode ? `${formatTokenLabel(record.auth_mode)} auth` : 'auth mode not reported';
  const actionLabel = record.allowed_actions?.length ? `${record.allowed_actions.length} allowed actions` : 'allowed actions not reported';
  const endpointLabel = record.execution_endpoint_names?.length ? `${record.execution_endpoint_names.length} execution endpoints` : 'no execution endpoints reported';
  const protocolLabel = record.server_protocol || 'protocol not reported';
  const networkLabel = record.network_mode || 'network mode not reported';
  const providerKeyLabel = record.provider_key_references?.length
    ? `${record.provider_key_references.map((ref) => formatTokenLabel(ref.provider)).join(', ')} provider keys, values hidden`
    : credentialLabel;
  const surface = awsAIAgentSurfaceFilter(record);
  const providerFilter = awsAIAgentProviderFilter(record);
  const runtimeFilter = awsAIAgentRuntimeFilter(record);
  const riskFilter = awsAIAgentRiskFilter(record);
  const confidenceFilter = awsAIAgentConfidenceFilter(record.confidence);
  const relationships = new Set<string>(['agent-to-role']);
  if (record.tool_names?.length || record.gateway_arn) {
    relationships.add('agent-to-tool');
  }
  if (record.credential_reference_refs?.length) {
    relationships.add('agent-to-secret');
  }
  if (record.execution_endpoint_arns?.length) {
    relationships.add('agent-to-endpoint');
  }
  if (record.storage_reference_refs?.length || record.memory_store_refs?.length || record.encryption_key_arn) {
    relationships.add('agent-to-storage');
  }
  // AgentCore Memory / Browser / Code Interpreter capability surface detail.
  const capabilityDetail =
    record.capability_kind === 'memory'
      ? `memory store; ${record.encryption_key_arn ? 'customer-encrypted; ' : ''}${(record.storage_reference_refs?.length || record.memory_store_refs?.length || 0)} storage refs`
      : record.capability_kind === 'browser'
        ? `browser tool; ${record.network_mode || 'network mode not reported'}; ${(record.storage_reference_refs?.length || 0)} recording refs`
        : record.capability_kind === 'code_interpreter'
          ? `code interpreter; ${record.network_mode || 'network mode not reported'}`
          : '';
  const category = record.capability_kind
    ? `AgentCore ${formatTokenLabel(record.capability_kind)}`
    : formatTokenLabel(record.agent_type);
  return {
    id: `ai-agent-identity-${record.agent_node_id || record.agent_id}`,
    name: record.agent_name || record.agent_id,
    detailAgent: record.agent_node_id || record.agent_id,
    category,
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage,
    detail: record.capability_kind
      ? `${capabilityDetail}; runs as ${roleLabel}; ${capabilityLabel}. Contents never collected.`
      : `${record.provider || 'provider not reported'} ${record.model_id || 'model not reported'}; runs as ${roleLabel}; ${runtimeLabel}; ${toolLabel}; ${authLabel}; ${actionLabel}; ${endpointLabel}; ${networkLabel}; ${protocolLabel}; ${capabilityLabel}; ${providerKeyLabel}.`,
    filters: {
      surface,
      relationship: Array.from(relationships).join(','),
      provider: providerFilter,
      runtime: runtimeFilter,
      risk: riskFilter,
      confidence: confidenceFilter,
      status: status === 'role anchor' ? 'role-anchor' : status === 'not yet available' ? 'not-yet-available' : status === 'candidate' ? 'candidate' : status === 'degraded' ? 'degraded' : 'coming',
      search: ''
    },
    searchText: inventorySearchText([
      record.agent_id,
      record.agent_arn,
      record.agent_name,
      record.agent_type,
      record.provider,
      record.model_id,
      record.runtime_role_arn,
      record.runtime_role_name,
      record.runtime_version,
      record.gateway_id,
      record.gateway_arn,
      record.external_provider,
      record.auth_mode,
      ...(record.tool_names ?? []),
      ...(record.tool_target_refs ?? []),
      ...(record.allowed_actions ?? []),
      ...(record.execution_endpoint_names ?? []),
      ...(record.execution_endpoint_arns ?? []),
      ...(record.observability_links ?? []),
      ...(record.capability_names ?? []),
      ...(record.credential_reference_refs ?? []),
      ...(record.provider_key_references?.flatMap((ref) => [ref.provider, ref.sensitivity, ref.reference_kind, ref.reference]) ?? []),
      ...(record.storage_reference_refs ?? []),
      ...(record.memory_store_refs ?? []),
      record.capability_kind,
      record.encryption_key_arn,
      record.network_mode,
      record.server_protocol,
      record.account_id,
      record.region,
      providerFilter,
      runtimeFilter,
      riskFilter,
      confidenceFilter,
      'ai agent identity metadata only values hidden'
    ])
  };
}

function awsAIAgentProviderFilter(record: AWSAIAgentIdentityRecord): string {
  const providers = [
    record.provider,
    record.external_provider,
    ...(record.provider_key_references?.map((ref) => ref.provider) ?? []),
    ...awsAIAgentModelProviderFilterTokens(record.model_id)
  ]
    .filter((value): value is string => Boolean(value))
    .map((value) => awsAIAgentProviderFilterToken(value));
  return providers.length ? Array.from(new Set(providers)).join(',') : 'custom';
}

function awsAIAgentModelProviderFilterTokens(modelID?: string): string[] {
  const normalizedModel = normalizeFilterValue(modelID ?? '');
  const tokens: string[] = [];
  if (normalizedModel.includes('anthropic') || normalizedModel.includes('claude')) {
    tokens.push('anthropic');
  }
  if (normalizedModel.includes('openai') || normalizedModel.includes('gpt')) {
    tokens.push('openai');
  }
  if (normalizedModel.includes('bedrock')) {
    tokens.push('bedrock');
  }
  return tokens;
}

function awsAIAgentProviderFilterToken(value: string): string {
  return normalizeFilterValue(value) === 'external_ai_provider' ? 'external_provider' : value;
}

function awsAIAgentRuntimeFilter(record: AWSAIAgentIdentityRecord): string {
  const values = [record.service, record.agent_type, record.runtime_version, record.network_mode, record.server_protocol]
    .filter((value): value is string => Boolean(value))
    .map((value) => normalizeFilterValue(value));
  return values.length ? Array.from(new Set(values)).join(',') : 'unknown';
}

function awsAIAgentRiskFilter(record: AWSAIAgentIdentityRecord): string {
  if (record.status === 'degraded' || record.coverage_status === 'degraded' || record.coverage_reason) {
    return 'high';
  }
  if (record.confidence === 0) {
    return 'unscored';
  }
  if (record.status === 'candidate' || record.coverage_status === 'candidate' || record.confidence < 0.75) {
    return 'medium';
  }
  return 'low';
}

function awsAIAgentConfidenceFilter(confidence: number): string {
  const tokens = ['all'];
  if (confidence >= 0.5) {
    tokens.push('0.5');
  }
  if (confidence >= 0.75) {
    tokens.push('0.75');
  }
  if (confidence >= 0.9) {
    tokens.push('0.9');
  }
  return tokens.join(',');
}

function awsAIAgentSurfaceFilter(record: AWSAIAgentIdentityRecord): string {
  switch (record.agent_type) {
    case 'bedrock_agent':
      return 'bedrock-agents';
    case 'agentcore_runtime':
      return 'agentcore-runtime';
    case 'agent_gateway':
      return 'mcp-gateway';
    case 'agentcore_capability':
      return 'agentcore-capabilities';
    case 'external_provider_agent':
      return 'external-provider-keys';
    case 'custom_agent':
      return record.credential_reference_refs?.length ? 'custom-agents,external-provider-keys' : 'custom-agents';
    default:
      return 'bedrock-agents,agentcore-runtime,agentcore-capabilities,custom-agents,mcp-gateway,external-provider-keys';
  }
}

function AWSResourcesInventoryContent({
  connection,
  secretsManagerState,
  ssmParameterState,
  ecrRepositoryState,
  sqsSNSState,
  dynamoDBRDSState,
  credentialReferencesState,
  filters,
  onFiltersChange
}: {
  connection: AWSConnectionStatus | null;
  secretsManagerState: AWSInventorySecretsManagerState;
  ssmParameterState: AWSInventorySSMParameterState;
  ecrRepositoryState: AWSInventoryECRRepositoryState;
  sqsSNSState: AWSInventorySQSSNSState;
  dynamoDBRDSState: AWSInventoryDynamoDBRDSState;
  credentialReferencesState: AWSInventoryCredentialReferencesState;
  filters: AWSInventoryFilterState;
  onFiltersChange: (nextFilters: AWSInventoryFilterState) => void;
}) {
  const secretsInventory = secretsManagerState.inventory;
  const secretsRows = buildAWSSecretsManagerMetadataRows(secretsInventory, secretsManagerState.loading, connection);
  const ssmInventory = ssmParameterState.inventory;
  const ssmRows = buildAWSSSMParameterMetadataRows(ssmInventory, ssmParameterState.loading, connection);
  const ecrInventory = ecrRepositoryState.inventory;
  const ecrRows = buildAWSECRRepositoryMetadataRows(ecrInventory, ecrRepositoryState.loading, connection);
  const sqsSNSInventory = sqsSNSState.inventory;
  const sqsSNSRows = buildAWSSQSSNSReachabilityRows(sqsSNSInventory, sqsSNSState.loading, connection);
  const dynamoDBRDSInventory = dynamoDBRDSState.inventory;
  const dynamoDBRDSRows = buildAWSDynamoDBRDSReachabilityRows(dynamoDBRDSInventory, dynamoDBRDSState.loading, connection);
  const credentialReferencesInventory = credentialReferencesState.inventory;
  const credentialReferencesRows = buildAWSCredentialReferenceRows(credentialReferencesInventory, credentialReferencesState.loading, connection);
  const rows: AWSInventoryTableRow[] = [
    ...secretsRows,
    ...ssmRows,
    ...credentialReferencesRows,
    ...ecrRows,
    ...sqsSNSRows,
    ...dynamoDBRDSRows,
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
        <DomainCoverageCard
          label="Secrets metadata"
          scanned={secretsInventory && secretsInventory.status !== 'blocked' ? 1 : 0}
          total={1}
          detail={secretsManagerState.loading ? 'Loading' : secretsInventory ? formatTokenLabel(secretsInventory.status) : 'Pending'}
        />
        <DomainCoverageCard
          label="SSM parameters"
          scanned={ssmInventory && ssmInventory.status !== 'blocked' ? 1 : 0}
          total={1}
          detail={ssmParameterState.loading ? 'Loading' : ssmInventory ? formatTokenLabel(ssmInventory.status) : 'Pending'}
        />
        <DomainCoverageCard
          label="ECR repositories"
          scanned={ecrInventory && ecrInventory.status !== 'blocked' ? 1 : 0}
          total={1}
          detail={ecrRepositoryState.loading ? 'Loading' : ecrInventory ? formatTokenLabel(ecrInventory.status) : 'Pending'}
        />
        <DomainCoverageCard
          label="SQS/SNS reachability"
          scanned={sqsSNSInventory && sqsSNSInventory.status !== 'blocked' ? 1 : 0}
          total={1}
          detail={sqsSNSState.loading ? 'Loading' : sqsSNSInventory ? formatTokenLabel(sqsSNSInventory.status) : 'Pending'}
        />
        <DomainCoverageCard
          label="DynamoDB/RDS reachability"
          scanned={dynamoDBRDSInventory && dynamoDBRDSInventory.status !== 'blocked' ? 1 : 0}
          total={1}
          detail={dynamoDBRDSState.loading ? 'Loading' : dynamoDBRDSInventory ? formatTokenLabel(dynamoDBRDSInventory.status) : 'Pending'}
        />
        <DomainCoverageCard
          label="Credential references"
          scanned={credentialReferencesInventory && credentialReferencesInventory.status !== 'blocked' ? 1 : 0}
          total={1}
          detail={credentialReferencesState.loading ? 'Loading' : credentialReferencesInventory ? formatTokenLabel(credentialReferencesInventory.status) : 'Pending'}
        />
        <DomainCoverageCard label="KMS reachability" scanned={0} total={1} detail="Needs evidence" />
        <DomainCoverageCard label="S3 sensitivity" scanned={0} total={1} detail="Needs evidence" />
      </section>
      {secretsManagerState.loading ? <DomainLoadingState label="Loading Secrets Manager metadata" /> : null}
      {secretsManagerState.error ? (
        <DomainErrorState
          title="Secrets Manager metadata could not load"
          body={secretsManagerState.error}
          retryAction={{ label: 'Retry Secrets Manager metadata', onClick: secretsManagerState.onRetry }}
        />
      ) : null}
      {ssmParameterState.loading ? <DomainLoadingState label="Loading SSM Parameter metadata" /> : null}
      {ssmParameterState.error ? (
        <DomainErrorState
          title="SSM Parameter metadata could not load"
          body={ssmParameterState.error}
          retryAction={{ label: 'Retry SSM Parameter metadata', onClick: ssmParameterState.onRetry }}
        />
      ) : null}
      {ecrRepositoryState.loading ? <DomainLoadingState label="Loading ECR repository metadata" /> : null}
      {ecrRepositoryState.error ? (
        <DomainErrorState
          title="ECR repository metadata could not load"
          body={ecrRepositoryState.error}
          retryAction={{ label: 'Retry ECR repository metadata', onClick: ecrRepositoryState.onRetry }}
        />
      ) : null}
      {sqsSNSState.loading ? <DomainLoadingState label="Loading SQS and SNS reachability" /> : null}
      {sqsSNSState.error ? (
        <DomainErrorState
          title="SQS/SNS reachability could not load"
          body={sqsSNSState.error}
          retryAction={{ label: 'Retry SQS/SNS reachability', onClick: sqsSNSState.onRetry }}
        />
      ) : null}
      {dynamoDBRDSState.loading ? <DomainLoadingState label="Loading DynamoDB and RDS reachability" /> : null}
      {dynamoDBRDSState.error ? (
        <DomainErrorState
          title="DynamoDB/RDS reachability could not load"
          body={dynamoDBRDSState.error}
          retryAction={{ label: 'Retry DynamoDB/RDS reachability', onClick: dynamoDBRDSState.onRetry }}
        />
      ) : null}
      {credentialReferencesState.loading ? <DomainLoadingState label="Loading credential and secret references" /> : null}
      {credentialReferencesState.error ? (
        <DomainErrorState
          title="Credential references could not load"
          body={credentialReferencesState.error}
          retryAction={{ label: 'Retry credential references', onClick: credentialReferencesState.onRetry }}
        />
      ) : null}
      <DomainStatusPanel eyebrow="Safety posture" title="No secret value reads" status="Metadata only" tone="success">
        <p>
          Resource inventory is designed around reachability and metadata. Secrets Manager, SSM Parameter, ECR image
          repository, SQS queues, SNS topics, DynamoDB tables, and RDS resources must use safe metadata and credential
          references, not credential values, message bodies, notification payloads, database rows, query text, snapshots,
          or image payloads.
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

function buildAWSSecretsManagerMetadataRows(
  inventory: AWSSecretsManagerMetadataInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsSecretsManagerMetadataRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'secrets-manager-blocked',
        name: 'Secrets Manager metadata unavailable',
        category: 'Secret-bearing',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'Secrets Manager metadata collection is blocked.',
        filters: { category: 'secrets-manager', sensitivity: 'secret-bearing', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['secrets manager', 'blocked', inventory.account_id, inventory.region])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'secrets-manager-empty',
        name: degraded ? 'Secrets Manager metadata incomplete' : 'No Secrets Manager secrets found',
        category: 'Secret-bearing',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'wired now',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'Secrets Manager metadata collection completed with degraded evidence and no retained records.') : 'The collector completed without Secrets Manager records in this account and region.',
        filters: { category: 'secrets-manager', sensitivity: 'secret-bearing', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['secrets manager', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'secrets-manager-loading',
        name: 'Secrets Manager metadata',
        category: 'Secret-bearing',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading secret metadata, rotation state, resource-policy grants, KMS references, and workload references.',
        filters: { category: 'secrets-manager', sensitivity: 'secret-bearing', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['secrets manager', 'metadata', 'loading'])
      }
    ];
  }
  return [
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
    }
  ];
}

function awsSecretsManagerMetadataRow(record: AWSSecretsManagerMetadataRecord): AWSInventoryTableRow {
  const degraded = record.status !== 'ready' || record.exposure_classification === 'public' || record.exposure_classification === 'cross_account' || !record.rotation_enabled;
  const status = degraded ? 'degraded' : 'wired now';
  const referenceLabel = record.referenced_by?.length ? `${record.referenced_by.length} workload references` : 'no resolved workload references';
  const policyLabel = record.has_resource_policy ? `${record.resource_policy_statement_count} policy statements` : 'no resource policy';
  const rotationLabel = record.rotation_enabled ? `rotation enabled${record.rotation_interval_days ? ` every ${record.rotation_interval_days} days` : ''}` : 'rotation not enabled';
  const kmsLabel = record.kms_key_arn || record.kms_key_id ? 'KMS referenced' : 'default encryption metadata';
  const sensitivityLabel = record.sensitive ? (record.sensitivity_classification === 'runtime_secret_reference' ? 'runtime-secret-reference' : 'secret-bearing') : 'non-secret';
  const sourceLabel = record.sensitivity_classification_source === 'operator_override' ? `override: ${record.sensitivity_classification}` : `classified by ${record.sensitivity_classification_source}`;
  return {
    id: `secrets-manager-${record.secret_arn}`,
    name: record.secret_name || record.secret_arn,
    category: 'Secret-bearing',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage: 'wired',
    detail: `${rotationLabel}; ${policyLabel}; ${referenceLabel}; ${kmsLabel}. Values hidden.`,
    filters: {
      category: 'secrets-manager',
      sensitivity: 'secret-bearing',
      readPosture: 'metadata-only',
      search: ''
    },
    searchText: inventorySearchText([
      record.secret_arn,
      record.secret_name,
      record.account_id,
      record.region,
      record.secret_status,
      record.sensitivity_classification,
      record.sensitivity_classification_source,
      record.sensitivity_classification_override ?? '',
      record.exposure_classification,
      ...(record.exposure_reasons ?? []),
      ...(record.referenced_by ?? []).map((ref) => `${ref.source_service ?? ''} ${ref.workload_name ?? ''} ${ref.reference}`),
      ...(record.unresolved_references ?? []).map((ref) => `${ref.source_service ?? ''} ${ref.workload_name ?? ''} ${ref.reference}`),
      `sensitivity ${sensitivityLabel}; ${sourceLabel}`,
      'secrets manager metadata rotation policy kms references values hidden'
    ])
  };
}

function buildAWSSSMParameterMetadataRows(
  inventory: AWSSSMParameterMetadataInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsSSMParameterMetadataRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'ssm-parameters-blocked',
        name: 'SSM Parameter metadata unavailable',
        category: 'Credential reference',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'SSM parameter metadata collection is blocked.',
        filters: { category: 'ssm-parameter', sensitivity: 'credential-reference', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['ssm parameter', 'blocked', inventory.account_id, inventory.region])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'ssm-parameters-empty',
        name: degraded ? 'SSM Parameter metadata incomplete' : 'No SSM parameters found',
        category: 'Credential reference',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'wired now',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'SSM parameter metadata collection completed with degraded evidence and no retained records.') : 'The collector completed without SSM parameters in this account and region.',
        filters: { category: 'ssm-parameter', sensitivity: 'credential-reference', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['ssm parameter', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'ssm-parameters-loading',
        name: 'SSM Parameter metadata',
        category: 'Credential reference',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading parameter type, tier, path, KMS references, policies, and workload references.',
        filters: { category: 'ssm-parameter', sensitivity: 'credential-reference', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['ssm parameter', 'metadata', 'loading'])
      }
    ];
  }
  return [
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
    }
  ];
}

function awsSSMParameterMetadataRow(record: AWSSSMParameterMetadataRecord): AWSInventoryTableRow {
  const plainTextReferenced = (record.referenced_by?.length ?? 0) > 0 && record.parameter_type !== 'secure_string';
  const degraded = record.status !== 'ready' || plainTextReferenced;
  const status = degraded ? 'degraded' : 'wired now';
  const typeLabel = record.parameter_type === 'secure_string' ? `SecureString (${record.sensitivity_classification === 'secure_string_customer_kms' ? 'customer KMS' : 'AWS-managed KMS'})` : record.parameter_type;
  const referenceLabel = record.referenced_by?.length ? `${record.referenced_by.length} workload references` : 'no resolved workload references';
  const expirationPolicy = (record.parameter_policies ?? []).find((policy) => (policy.policy_type ?? '').toLowerCase() === 'expiration');
  const lifecycleLabel = expirationPolicy ? `expires ${expirationPolicy.expires_at ?? 'per policy'}` : 'no expiration policy';
  const modifiedLabel = record.last_modified_by ? `last modified by ${record.last_modified_by.split('/').pop() ?? record.last_modified_by}` : 'modifier unknown';
  return {
    id: `ssm-parameter-${record.parameter_arn}`,
    name: record.parameter_name || record.parameter_arn,
    category: record.sensitive ? 'Secret-bearing' : 'Credential reference',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage: 'wired',
    detail: `${typeLabel}, ${record.tier} tier; ${referenceLabel}; ${lifecycleLabel}; ${modifiedLabel}. Values hidden.`,
    filters: {
      category: 'ssm-parameter',
      sensitivity: record.sensitive ? 'secret-bearing' : 'credential-reference',
      readPosture: 'metadata-only',
      search: ''
    },
    searchText: inventorySearchText([
      record.parameter_arn,
      record.parameter_name,
      record.parameter_path ?? '',
      record.account_id,
      record.region,
      record.parameter_type,
      record.tier,
      record.sensitivity_classification,
      record.exposure_classification,
      record.last_modified_by ?? '',
      ...(record.exposure_reasons ?? []),
      ...(record.referenced_by ?? []).map((ref) => `${ref.source_service ?? ''} ${ref.workload_name ?? ''} ${ref.reference}`),
      ...(record.unresolved_references ?? []).map((ref) => `${ref.source_service ?? ''} ${ref.workload_name ?? ''} ${ref.reference}`),
      'ssm parameter metadata type tier path kms references values hidden'
    ])
  };
}

function buildAWSECRRepositoryMetadataRows(
  inventory: AWSECRRepositoryMetadataInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsECRRepositoryMetadataRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'ecr-repositories-blocked',
        name: 'ECR repository metadata unavailable',
        category: 'Container image',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'ECR repository metadata collection is blocked.',
        filters: { category: 'ecr-repository', sensitivity: 'container-image', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['ecr repository', 'blocked', inventory.account_id, inventory.region])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'ecr-repositories-empty',
        name: degraded ? 'ECR repository metadata incomplete' : 'No ECR repositories found',
        category: 'Container image',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'wired now',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'ECR repository metadata collection completed with degraded evidence and no retained records.') : 'The collector completed without ECR repositories in this account and region.',
        filters: { category: 'ecr-repository', sensitivity: 'container-image', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['ecr repository', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'ecr-repositories-loading',
        name: 'ECR repository metadata',
        category: 'Container image',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading repository metadata, tags, scan settings, lifecycle policies, and workload image references.',
        filters: { category: 'ecr-repository', sensitivity: 'container-image', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['ecr repository', 'metadata', 'loading'])
      }
    ];
  }
  return [
    {
      id: 'ecr-repositories',
      name: 'ECR repository metadata',
      category: 'Container image',
      scope: connection?.region ?? 'Region pending',
      status: 'coming',
      stage: 'coming',
      detail: 'Repository, tag, scan, encryption, policy, lifecycle, and workload image-reference metadata only.',
      filters: { category: 'ecr-repository', sensitivity: 'container-image', readPosture: 'metadata-only', search: '' },
      searchText: inventorySearchText(['ecr repository', 'container image', 'metadata', 'scan'])
    }
  ];
}

function awsECRRepositoryMetadataRow(record: AWSECRRepositoryMetadataRecord): AWSInventoryTableRow {
  const unscanned = !record.scan_on_push && !record.enhanced_scanning_enabled;
  const mutable = record.image_tag_mutability !== 'immutable';
  const degraded = record.status !== 'ready' || unscanned || mutable;
  const status = degraded ? 'degraded' : 'wired now';
  const referenceLabel = record.referenced_by?.length ? `${record.referenced_by.length} workload image references` : 'no resolved workload references';
  const scanLabel = record.enhanced_scanning_enabled ? 'enhanced scanning enabled' : record.scan_on_push ? 'scan on push enabled' : 'scan metadata disabled';
  const policyLabel = record.has_repository_policy ? `${record.repository_policy_statement_count} policy statements` : 'no repository policy';
  const lifecycleLabel = record.has_lifecycle_policy ? `${record.lifecycle_rule_count} lifecycle rules` : 'no lifecycle policy';
  return {
    id: `ecr-repository-${record.repository_arn}`,
    name: record.repository_name || record.repository_uri,
    category: 'Container image',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage: 'wired',
    detail: `${record.image_tag_mutability} tags; ${scanLabel}; ${policyLabel}; ${lifecycleLabel}; ${referenceLabel}. Image payloads hidden.`,
    filters: {
      category: 'ecr-repository',
      sensitivity: record.referenced_by?.length ? 'runtime-image' : 'container-image',
      readPosture: 'metadata-only',
      search: ''
    },
    searchText: inventorySearchText([
      record.repository_arn,
      record.repository_name,
      record.repository_uri,
      record.account_id,
      record.region,
      record.image_tag_mutability,
      record.encryption_type ?? '',
      record.kms_key_id ?? '',
      record.sensitivity_classification,
      record.exposure_classification,
      ...(record.exposure_reasons ?? []),
      ...(record.referenced_by ?? []).map((ref) => `${ref.source_service ?? ''} ${ref.workload_name ?? ''} ${ref.image_uri}`),
      ...(record.unresolved_references ?? []).map((ref) => `${ref.source_service ?? ''} ${ref.workload_name ?? ''} ${ref.image_uri}`),
      'ecr repository metadata container image scan lifecycle policy payloads hidden'
    ])
  };
}

function buildAWSSQSSNSReachabilityRows(
  inventory: AWSSQSSNSReachabilityInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsSQSSNSReachabilityRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'sqs-sns-blocked',
        name: 'SQS/SNS reachability unavailable',
        category: 'Messaging resource',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'SQS/SNS reachability collection is blocked.',
        filters: { category: 'sqs-sns', sensitivity: 'messaging-resource', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['sqs sns messaging blocked', inventory.account_id, inventory.region])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'sqs-sns-empty',
        name: degraded ? 'SQS/SNS reachability incomplete' : 'No SQS queues or SNS topics found',
        category: 'Messaging resource',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'wired now',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'SQS/SNS collection completed with degraded evidence and no retained records.') : 'The collector completed without SQS queues or SNS topics in this account and region.',
        filters: { category: 'sqs-sns', sensitivity: 'messaging-resource', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['sqs sns messaging', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'sqs-sns-loading',
        name: 'SQS/SNS reachability',
        category: 'Messaging resource',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading queue and topic policies, encryption, DLQs, subscriptions, and endpoint-safe metadata.',
        filters: { category: 'sqs-sns', sensitivity: 'messaging-resource', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['sqs sns messaging loading'])
      }
    ];
  }
  return [
    {
      id: 'sqs-sns',
      name: 'SQS/SNS reachability',
      category: 'Messaging resource',
      scope: connection?.region ?? 'Region pending',
      status: 'coming',
      stage: 'coming',
      detail: 'Queue/topic policies, encryption, DLQs, and subscriptions without message or notification payload reads.',
      filters: { category: 'sqs-sns', sensitivity: 'messaging-resource', readPosture: 'metadata-only', search: '' },
      searchText: inventorySearchText(['sqs', 'sns', 'queue', 'topic', 'reachability'])
    }
  ];
}

function buildAWSCredentialReferenceRows(
  inventory: AWSCredentialReferencesInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsCredentialReferenceRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'credential-references-blocked',
        name: 'Credential references unavailable',
        category: 'Credential reference',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'Credential reference mapping is blocked by workload inventory permissions.',
        filters: { category: 'credential-reference', sensitivity: 'credential-reference', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['credential reference blocked', inventory.account_id, inventory.region])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'credential-references-empty',
        name: degraded ? 'Credential references incomplete' : 'No credential or secret references found',
        category: 'Credential reference',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'wired now',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'Reference mapping completed with degraded evidence and no retained records.') : 'No workload referenced a secret, parameter, or provider key in this account and region.',
        filters: { category: 'credential-reference', sensitivity: 'credential-reference', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['credential reference', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'credential-references-loading',
        name: 'Credential and secret references',
        category: 'Credential reference',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading provider, kind, sensitivity, and resolved status for workload credential references.',
        filters: { category: 'credential-reference', sensitivity: 'credential-reference', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['credential reference loading'])
      }
    ];
  }
  return [
    {
      id: 'credential-references',
      name: 'Credential and secret references',
      category: 'Credential reference',
      scope: connection?.region ?? 'Region pending',
      status: 'coming',
      stage: 'coming',
      detail: 'Provider-classified credential references (AI, source control, database, webhook, AWS secret stores) across workloads. Names and ARNs only, never values.',
      filters: { category: 'credential-reference', sensitivity: 'credential-reference', readPosture: 'metadata-only', search: '' },
      searchText: inventorySearchText(['credential', 'secret', 'reference', 'provider key', 'openai', 'github'])
    }
  ];
}

function awsCredentialReferenceRow(record: AWSCredentialReferenceRecord): AWSInventoryTableRow {
  const external = record.provider !== 'aws_secrets_manager' && record.provider !== 'aws_ssm' && record.provider !== 'generic';
  const degraded = record.status !== 'ready' || (record.unresolved && external);
  const status = degraded ? 'degraded' : 'wired now';
  const resolutionLabel = record.resolved ? 'resolved to collected secret' : 'unresolved reference';
  const providerLabel = formatTokenLabel(record.provider);
  return {
    id: `credential-reference-${record.workload_id}-${record.reference}`,
    name: record.reference_name || record.reference,
    category: record.sensitivity === 'ai_provider_api_key' || external ? 'Provider key' : 'Credential reference',
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage: 'wired',
    detail: `${providerLabel} ${formatTokenLabel(record.reference_kind)} on ${record.workload_name || record.workload_id}; ${formatTokenLabel(record.sensitivity)}; ${resolutionLabel}. Values hidden.`,
    filters: {
      category: 'credential-reference',
      sensitivity: external ? 'credential-reference' : 'secret-bearing',
      readPosture: 'metadata-only',
      search: ''
    },
    searchText: inventorySearchText([
      record.reference,
      record.reference_name ?? '',
      record.provider,
      record.sensitivity,
      record.reference_kind,
      record.workload_id,
      record.workload_name,
      record.resource_type,
      record.source_service,
      record.account_id,
      record.region,
      record.resolved ? 'resolved' : 'unresolved',
      'credential secret reference provider key values hidden'
    ])
  };
}

function buildAWSDynamoDBRDSReachabilityRows(
  inventory: AWSDynamoDBRDSReachabilityInventoryResult | null,
  loading: boolean,
  connection: AWSConnectionStatus | null
): AWSInventoryTableRow[] {
  if (inventory?.records.length) {
    return inventory.records.map((record) => awsDynamoDBRDSReachabilityRow(record));
  }
  if (inventory?.status === 'blocked') {
    return [
      {
        id: 'dynamodb-rds-blocked',
        name: 'DynamoDB/RDS reachability unavailable',
        category: 'Database resource',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: 'not yet available',
        stage: 'not-available',
        detail: inventory.failure_reasons[0] ?? 'DynamoDB/RDS reachability collection is blocked.',
        filters: { category: 'dynamodb-rds', sensitivity: 'database-resource', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['dynamodb rds database blocked', inventory.account_id, inventory.region])
      }
    ];
  }
  if (inventory) {
    const degraded = inventory.status === 'degraded' || inventory.diagnostics.length > 0 || inventory.failure_reasons.length > 0;
    return [
      {
        id: 'dynamodb-rds-empty',
        name: degraded ? 'DynamoDB/RDS reachability incomplete' : 'No DynamoDB or RDS resources found',
        category: 'Database resource',
        scope: awsAccountRegionInventoryLabel(inventory.account_id, inventory.region),
        status: degraded ? 'degraded' : 'wired now',
        stage: 'wired',
        detail: degraded ? (inventory.failure_reasons[0] ?? 'DynamoDB/RDS collection completed with degraded evidence and no retained records.') : 'The collector completed without DynamoDB or RDS resources in this account and region.',
        filters: { category: 'dynamodb-rds', sensitivity: 'database-resource', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['dynamodb rds database', inventory.account_id, inventory.region, degraded ? 'degraded empty' : 'empty'])
      }
    ];
  }
  if (loading) {
    return [
      {
        id: 'dynamodb-rds-loading',
        name: 'DynamoDB/RDS reachability',
        category: 'Database resource',
        scope: awsAccountRegionLabel(connection),
        status: 'coming',
        stage: 'coming',
        detail: 'Loading table, stream, cluster, instance, proxy, encryption, IAM-auth, and policy metadata.',
        filters: { category: 'dynamodb-rds', sensitivity: 'database-resource', readPosture: 'metadata-only', search: '' },
        searchText: inventorySearchText(['dynamodb rds database loading'])
      }
    ];
  }
  return [
    {
      id: 'dynamodb-rds',
      name: 'DynamoDB/RDS reachability',
      category: 'Database resource',
      scope: connection?.region ?? 'Region pending',
      status: 'coming',
      stage: 'coming',
      detail: 'DynamoDB table/stream and RDS cluster/instance/proxy metadata without rows, queries, snapshots, or database contents.',
      filters: { category: 'dynamodb-rds', sensitivity: 'database-resource', readPosture: 'metadata-only', search: '' },
      searchText: inventorySearchText(['dynamodb', 'rds', 'database', 'reachability'])
    }
  ];
}

function awsDynamoDBRDSReachabilityRow(record: AWSDynamoDBRDSReachabilityRecord): AWSInventoryTableRow {
  const publicOrCross = record.exposure_classification === 'public' || record.exposure_classification === 'cross_account';
  const status = record.status !== 'ready' || publicOrCross ? 'degraded' : 'wired now';
  const policyLabel = record.has_resource_policy ? `${record.resource_policy_statement_count} policy statements` : 'no resource policy';
  const grantLabel = record.identity_grants?.length ? `${record.identity_grants.length} policy grants` : 'no policy grants';
  const roleLabel = record.associated_role_arns?.length ? `${record.associated_role_arns.length} associated roles` : 'no associated roles';
  const encryptionLabel = record.kms_key_id || record.storage_encrypted ? 'encryption configured' : 'encryption metadata default';
  const authLabel = record.iam_database_authentication_enabled ? 'IAM auth enabled' : record.publicly_accessible ? 'public endpoint flag' : 'private metadata';
  return {
    id: `dynamodb-rds-${record.resource_arn}`,
    name: record.resource_name || record.resource_arn,
    category: formatTokenLabel(record.resource_type),
    scope: awsAccountRegionInventoryLabel(record.account_id, record.region),
    status,
    stage: 'wired',
    detail: `${formatTokenLabel(record.exposure_classification)}; ${policyLabel}; ${grantLabel}; ${roleLabel}; ${encryptionLabel}; ${authLabel}. Contents hidden.`,
    filters: {
      category: `dynamodb-rds,${record.resource_type}`,
      sensitivity: publicOrCross ? 'database-exposure' : 'database-resource',
      readPosture: 'metadata-only',
      search: ''
    },
    searchText: inventorySearchText([
      record.resource_arn,
      record.resource_name,
      record.resource_type,
      record.service,
      record.account_id,
      record.region,
      record.engine,
      record.engine_version,
      record.exposure_classification,
      ...(record.exposure_reasons ?? []),
      ...(record.associated_role_arns ?? []),
      ...(record.identity_grants ?? []).map((grant) => `${grant.principal_arn ?? ''} ${(grant.actions ?? []).join(' ')} ${(grant.capabilities ?? []).join(' ')}`),
      'dynamodb rds database reachability rows queries snapshots hidden'
    ])
  };
}

function awsSQSSNSReachabilityRow(record: AWSSQSSNSReachabilityRecord): AWSInventoryTableRow {
  const publicOrCross = record.exposure_classification === 'public' || record.exposure_classification === 'cross_account';
  const degraded = record.status !== 'ready' || publicOrCross;
  const status = degraded ? 'degraded' : 'wired now';
  const policyLabel = record.has_resource_policy ? `${record.resource_policy_statement_count} policy statements` : 'no resource policy';
  const grantLabel = record.identity_grants?.length ? `${record.identity_grants.length} policy grants` : 'no policy grants';
  const dlqLabel = record.dlq_arns?.length ? `${record.dlq_arns.length} DLQs` : 'no DLQ reported';
  const encryptionLabel = record.kms_key_id ? 'customer KMS configured' : record.sqs_managed_sse ? 'SQS-managed encryption' : 'encryption metadata default';
  const subscriptionLabel = record.resource_type === 'sns_topic' ? `${record.subscription_count ?? record.subscriptions?.length ?? 0} subscriptions` : record.visibility_timeout_seconds ? `${record.visibility_timeout_seconds}s visibility timeout` : 'queue timing metadata';
  const risk = record.exposure_classification === 'public' ? 'high' : record.exposure_classification === 'cross_account' ? 'medium' : 'low';
  return {
    id: `sqs-sns-${record.resource_arn}`,
    name: record.resource_name || record.resource_arn×]t×O[Ê×¬¢h­µçBv³‡5÷&—f–ÆVvVE÷G'VRrÀ¢wFW'&f÷&Õ÷V&Æ–5÷35ö6Âp¥Ò“° ¦gVæ7F–öâ—5&VÖVF–F–öå7W÷'FVDf–æF–ær†f–æF–æs¢”f–æF–ær“¢&ööÆVâ°¢–b†f–æF–ærçG—RÓÓÒw6V7&WEöW‡÷7W&Rr’&WGW&âG'VS°¢6öç7BFWFV7F÷"Ò†f–æF–æræFWFV7F÷"óòrr’çFôÆ÷vW$66R‚“°¢–b‚FWFV7F÷"’&WGW&âfÇ6S°¢–b…$Uõô”åDTÄÄ”tTä4Uõ$TÔTD”D”ôåôU„5EôDUDT5Dõ%2æ†2†FWFV7F÷"’’&WGW&âG'VS°¢&WGW&â$Uõô”åDTÄÄ”tTä4Uõ$TÔTD”D”ôåôDUDT5Dõ%õ$Td•„U2ç6öÖR‚‡&Vf—‚’ÓâFWFV7F÷"ç7F'G5v—F‚‡&Vf—‚’“°§Ð ¦gVæ7F–öâ—5V&Æ—6†&ÆU&VÖVF–F–öäf–æF–ær†f–æF–æs¢”f–æF–ær“¢&ööÆVâ°¢6öç7BFWFV7F÷"Ò†f–æF–æræFWFV7F÷"óòrr’çFôÆ÷vW$66R‚“°¢–b‚FWFV7F÷"’&WGW&âfÇ6S°¢&WGW&â$Uõô”åDTÄÄ”tTä4UõT$Ä•4„$ÄUôDUDT5Dõ%2æ†2†FWFV7F÷"“°§Ð ¦gVæ7F–öâ—47F—fU&Wô–çFVÆÆ–vVæ6Tf–æF–ær†f–æF–æs¢”f–æF–ær“¢&ööÆVâ°¢6öç7B7FGW2Òf–æF–æræÆ–fV7–6ÆU÷7FGW3°¢òòf–æF–æw2F†BæWfW"&V6V—fVBÆ–fV7–6ÆR7FGW2FVfVÇBFò&7F—fR"–à¢òòF—7Æ’FW&×3¢G&÷–ærF†VÒv÷VÆB6–ÆVçFÇ’†–FRÆVv—F–ÖFR÷Vâf–æF–æw0¢òòv†÷6RFFW"†2æ÷B–WB7F'FVBVÖ—GF–ærÆ–fV7–6ÆRÖWFFFà¢–b‚7FGW2’&WGW&âG'VS°¢&WGW&â…$Uõô”åDTÄÄ”tTä4Uô5D•dUôÄ”dT5”4ÄUõ5DEU4U22&VFöæÇ’7G&–æuµÒ’æ–æ6ÇVFW2‡7FGW2“°§Ð ¢òò6†÷rÖç’æöFW2&Æ7B×&F—W26†–â6†÷w2âv—D‡V"f–æF–ærw&‡26à¢òò&V6‚ã†÷2†f–æF–ær(i"v÷&¶fÆ÷r(i"¦ö"(i"6V7&WB(i"Fö¶Vâ(i"ö–F5÷7V&¦V7@¢òò(i"6Æ÷VE÷&öÆR(i"Vçf—&öæÖVçB(i"(
b’Â'WB7BB†÷2F†R6†–â7F÷2†VÇ–æp¢òòâ÷W&F÷"66âF†RæVÂ(	BF†W’w&R&WGFW"öfb÷Væ–ærF†R&—6²Öw&€¢òòFWF–Âf–Wrf÷"F†Bf–æF–ærà¦6öç7B$Uõô”åDTÄÄ”tTä4UõD…ôÔ…ô„õ2ÒC° ¢òòæöFR¶–æG2F†R÷W&F÷"vçG2Fò6VRöâ&Æ7B×&F—W26†–ââ&W÷6—F÷'’ð¢òòFVfVÇEö'&æ6‚æB&f–æF–ær"—G6VÆbFBæò–æf÷&ÖF–öâFòF†RF€¢òò7VÖÖ'’‡F†R÷W&F÷"Ç&VG’¶æ÷w2F†W’w&Rf–Wv–ærf–æF–ær–âF†—0¢òò&W÷6—F÷'’’Â6òF†W’w&R6¶—VBv†VâF†RvÆ¶W"–6·2F†RæW‡B†÷à¦6öç7B$Uõô”åDTÄÄ”tTä4UõD…õTä”ädõ$ÔD•dUô´”äE2ÒæWr6WCÅ&Wõ&—6´w&„æöFT¶–æCâ…°¢w&W÷6—F÷'’rÀ¢vFVfVÇEö'&æ6‚rÀ¢vf–æF–ærp¥Ò“° §G—R&Wô–çFVÆÆ–vVæ6UF„†÷Ò°¢æöFUö–C¢7G&–æs°¢¶–æC¢&Wõ&—6´w&„æöFT¶–æC°¢Æ&VÃ¢7G&–æs°¢VFvUö¶–æC¢&Wõ&—6´w&„VFvT¶–æBÂçVÆÃ°¢Wf–FVæ6U÷7FFS¢v¶æ÷vârÂwVæ¶æ÷vâs°§Ó° ¢òòFW&—fRF†R&Æ7B×&F—W26†–âg&öÒF†R&—6²w&‚'’vÆ¶–ær÷WFvö–æp¢òòVFvW2g&öÒF†Rf–æF–ærw2æöFRVçF–ÂV—F†W"†’F†RvÆ¶W"&V6†W0¢òò$Uõô”åDTÄÄ”tTä4UõD…ôÔ…ô„õ2–æf÷&ÖF—fR†÷2÷"†"’F†R7W'&VçBæöFP¢òò†2æò÷WFvö–ærVFvRFòâVçf—6—FVB–æf÷&ÖF—fRæöFRâF†R&WGW&æV@¢òò6†–âW†6ÇVFW2F†Rf–æF–æræöFR—G6VÆb(	BF†Bw2Ç&VG’Æ&VÆVB–âF†P¢òò&÷r†VFW"(	B6òF†RæVÂ6†÷w2F†R&V6†&ÆR7W&f6Rà¢òð¢òò&VfW'2&¶æ÷vâ"VFvW2÷fW"'Væ¶æ÷vâ"öæW26ò6öæ7&WFP¢òòf–æF–ær(i"v÷&¶fÆ÷r(i"6Æ÷VE÷&öÆR6†–âv–ç2÷fW"&V6†&–Æ—G•÷Væ¶æ÷và¢òò&ö¦V7F–öâÂÖF6†–ær†÷rF†R&—6²w&‚fÆw27V7VÆF—fRVFvW2à¦gVæ7F–öâFW&—fU&Wô–çFVÆÆ–vVæ6T&Æ7E&F—W5F‚€¢w&ƒ¢&Wõ&—6´w&‚À¢7F'DæöFT”C¢7G&–æp¢“¢&Wô–çFVÆÆ–vVæ6UF„†÷µÒ°¢–b‚7F'DæöFT”B’&WGW&âµÓ°¢6öç7BæöFW4'””BÒæWrÖÇ7G&–ærÂ&Wõ&—6´w&„æöFSâ‚“°¢w&‚ææöFW2æf÷$V6‚‚†æöFR’ÓâæöFW4'””Bç6WB†æöFRæ–BÂæöFR’“°¢6öç7BVFvW4'”g&öÒÒæWrÖÇ7G&–ærÂ&Wõ&—6´w&„VFvUµÓâ‚“°¢w&‚æVFvW2æf÷$V6‚‚†VFvR’Óâ°¢6öç7BÆ—7BÒVFvW4'”g&öÒævWB†VFvRæg&öÕöæöFUö–B“°¢–b†Æ—7B’°¢Æ—7BçW6‚†VFvR“°¢ÒVÇ6R°¢VFvW4'”g&öÒç6WB†VFvRæg&öÕöæöFUö–BÂ¶VFvUÒ“°¢Ð¢Ò“°¢6öç7Bf—6—FVBÒæWr6WCÇ7G&–æsâ…·7F'DæöFT”EÒ“°¢6öç7B6†–ã¢&Wô–çFVÆÆ–vVæ6UF„†÷µÒÒµÓ°¢ÆWB7W'&VçD”BÒ7F'DæöFT”C°¢v†–ÆR†6†–âæÆVæwF‚Â$Uõô”åDTÄÄ”tTä4UõD…ôÔ…ô„õ2’°¢6öç7B÷WFvö–ærÒVFvW4'”g&öÒævWB†7W'&VçD”B’óòµÓ°¢òò&æ²6æF–FFW26ò&¶æ÷vâ"÷WFvö–ærVFvRFòâ–æf÷&ÖF—fRæöFP¢òòv–ç2÷fW"&÷F‚Væ¶æ÷vâVFvW2æBVFvW2ÆVF–ær&6²Fò&÷&–æp¢òòæöFR‡&W÷6—F÷'’òFVfVÇEö'&æ6‚òæ÷F†W"f–æF–ær’à¢6öç7B6æF–FFW2Ò÷WFvö–æp¢æÖ‚†VFvR’Óâ‡²VFvRÂF&vWC¢æöFW4'””BævWB†VFvRçFõöæöFUö–B’óòçVÆÂÒ’¢æf–ÇFW"‚‡²VFvRÂF&vWBÒ’ÓâF&vWBÓÒçVÆÂbbf—6—FVBæ†2†VFvRçFõöæöFUö–B’“°¢–b†6æF–FFW2æÆVæwF‚ÓÓÒ’'&V³°¢6æF–FFW2ç6÷'B‚†ÆVgBÂ&–v‡B’Óâ°¢6öç7BÆVgD¶æ÷vâÒÆVgBæVFvRæWf–FVæ6U÷7FFRÓÓÒv¶æ÷vârò¢°¢6öç7B&–v‡D¶æ÷vâÒ&–v‡BæVFvRæWf–FVæ6U÷7FFRÓÓÒv¶æ÷vârò¢°¢–b†ÆVgD¶æ÷vâÓÒ&–v‡D¶æ÷vâ’&WGW&âÆVgD¶æ÷vâÒ&–v‡D¶æ÷vã°¢6öç7BÆVgD&÷&–ærÒ$Uõô”åDTÄÄ”tTä4UõD…õTä”ädõ$ÔD•dUô´”äE2æ†2€¢†ÆVgBçF&vWB2&Wõ&—6´w&„æöFR’æ¶–æ@¢¢ò¢¢°¢6öç7B&–v‡D&÷&–ærÒ$Uõô”åDTÄÄ”tTä4UõD…õTä”ädõ$ÔD•dUô´”äE2æ†2€¢‡&–v‡BçF&vWB2&Wõ&—6´w&„æöFR’æ¶–æ@¢¢ò¢¢°¢&WGW&âÆVgD&÷&–ærÒ&–v‡D&÷&–æs°¢Ò“°¢6öç7BæW‡BÒ6æF–FFW5³Ó°¢6öç7BæW‡EF&vWBÒæW‡BçF&vWB2&Wõ&—6´w&„æöFS°¢f—6—FVBæFB†æW‡BæVFvRçFõöæöFUö–B“°¢òòVæ–æf÷&ÖF—fRæW‡B†÷27F–ÆÂ6öç7VÖR6Æ÷Bf÷"7–6ÆRÖfö–Fæ6RÀ¢òò'WBFöâwBvWBW6†VBFòF†Rf—6–&ÆR6†–â(	BF†R÷W&F÷"FöW2æ÷@¢òò&VæVf—Bg&öÒ6VV–ær.(i"&W÷6—F÷'’"–âF†R7VÖÖ'’à¢–b‚$Uõô”åDTÄÄ”tTä4UõD…õTä”ädõ$ÔD•dUô´”äE2æ†2†æW‡EF&vWBæ¶–æB’’°¢6†–âçW6‚‡°¢æöFUö–C¢æW‡EF&vWBæ–BÀ¢¶–æC¢æW‡EF&vWBæ¶–æBÀ¢Æ&VÃ¢æW‡EF&vWBæÆ&VÂÇÂf÷&ÖEFö¶VäÆ&VÂ†æW‡EF&vWBæ¶–æB’À¢VFvUö¶–æC¢æW‡BæVFvRæ¶–æBÀ¢Wf–FVæ6U÷7FFS¢æW‡BæVFvRæWf–FVæ6U÷7FFP¢Ò“°¢Ð¢7W'&VçD”BÒæW‡BæVFvRçFõöæöFUö–C°¢Ð¢&WGW&â6†–ã°§Ð ¢òòÖW&vRw&‚ç66÷&W2–çFòf–æF–æw2'’f–æF–æuö–B6òF†RVWVR6â6÷'B'¢òòw&‚Öv&R&Æ7B×&F—W266÷&R&F†W"F†â§W7B6WfW&—G’âf–æF–æw2F†@¢òò†fRæòÖF6†–ær66÷&R†RærââöÆFW"f–æF–ærv—F†÷WBg&W6‚&—6²w&‚¢òòfÆÂ&6²Fò6WfW&—G’&æ²6òF†W’7F–ÆÂV"–â7F&ÆR÷&FW"à¦gVæ7F–öâ'V–ÆE&Wô–çFVÆÆ–vVæ6UVWVR€¢f–æF–æw3¢”f–æF–æuµÒÀ¢w&ƒ¢&Wõ&—6´w&‚ÂçVÆÀ¢“¢'&“Ç²f–æF–æs¢”f–æF–æs²66÷&S¢&Wõ&—6´w&„f–æF–æu66÷&RÂçVÆÃ²6FVv÷'“¢&Wô–çFVÆÆ–vVæ6Tf–æF–æt6FVv÷'’Óâ°¢6öç7B66÷&W4'”f–æF–æt”BÒæWrÖÇ7G&–ærÂ&Wõ&—6´w&„f–æF–æu66÷&Sâ‚“°¢w&ƒòç66÷&W3òæf÷$V6‚‚‡66÷&R’Óâ°¢–b‡66÷&Ræf–æF–æuö–B’°¢66÷&W4'”f–æF–æt”Bç6WB‡66÷&Ræf–æF–æuö–BÂ66÷&R“°¢Ð¢Ò“°¢6öç7BVç&–6†VBÒf–æF–æw2æf–ÇFW"†—47F—fU&Wô–çFVÆÆ–vVæ6Tf–æF–ær’æÖ‚†f–æF–ær’Óâ‡°¢f–æF–ærÀ¢66÷&S¢66÷&W4'”f–æF–æt”BævWB†f–æF–æræ–B’óòçVÆÂÀ¢6FVv÷'“¢6Æ76–g•&Wô–çFVÆÆ–vVæ6Tf–æF–ær†f–æF–ær¢Ò’“°¢&WGW&âVç&–6†VBç6÷'B‚†ÆVgBÂ&–v‡B’Óâ°¢6öç7BÆVgE66÷&RÒÆVgBç66÷&Sòç66÷&RóòÓ°¢6öç7B&–v‡E66÷&RÒ&–v‡Bç66÷&Sòç66÷&RóòÓ°¢–b†ÆVgE66÷&RÓÒ&–v‡E66÷&R’°¢&WGW&â&–v‡E66÷&RÒÆVgE66÷&S°¢Ð¢&WGW&â6WfW&—G•&æ²‡&–v‡Bæf–æF–ærç6WfW&—G’óòrr’Ò6WfW&—G•&æ²†ÆVgBæf–æF–ærç6WfW&—G’óòrr“°¢Ò“°§Ð ¦gVæ7F–öâ&Wô–çFVÆÆ–vVæ6U66ä6ö×ÆWFVæW72‡66ã¢&Wõ66å&V6÷&BÂçVÆÂ“¢°¢Æ&VÃ¢7G&–æs°¢FöæS¢w7V66W72rÂwv&æ–ærrÂvæWWG&ÂrÂvFævW"s°§Ò°¢–b‚66â’°¢&WGW&â²Æ&VÃ¢tæò66ârÂFöæS¢væWWG&ÂrÓ°¢Ð¢6öç7B7FGW2Ò66âç6÷W&6Uö†VÇF‚óò‡66âç7FGW2ÓÓÒw7V66VVFVBròv6ö×ÆWFRr¢wVæ¶æ÷vâr“°¢7v—F6‚‡7FGW2’°¢66Rv6ö×ÆWFRs ¢&WGW&â²Æ&VÃ¢t6ö×ÆWFR66ârÂFöæS¢w7V66W72rÓ°¢66Rw'F–Âs ¢&WGW&â²Æ&VÃ¢u'F–Â66ârÂFöæS¢wv&æ–ærrÓ°¢66RwW&Ö—76–öåöÆ–Ö—FVBs ¢&WGW&â²Æ&VÃ¢uW&Ö—76–öâÆ–Ö—FVBrÂFöæS¢wv&æ–ærrÓ°¢66Rw&FUöÆ–Ö—FVBs ¢&WGW&â²Æ&VÃ¢u&FRÆ–Ö—FVBrÂFöæS¢wv&æ–ærrÓ°¢66RwVæf–Æ&ÆRs ¢&WGW&â²Æ&VÃ¢u6÷W&6RVæf–Æ&ÆRrÂFöæS¢wv&æ–ærrÓ°¢FVfVÇC ¢&WGW&â²Æ&VÃ¢u66â7FFRVæ¶æ÷vârÂFöæS¢væWWG&ÂrÓ°¢Ð§Ð ¢òòv—D‡V"&W÷6—F÷'’6ÇVw2&R66RÖ–ç6Vç6—F—fS¢F†Rf–æF–æw27F÷&R6ö×&W0¢òòF†VÒv—F‚ÄõtU"‚âââ’Â6òFVWÆ–æ²F†Bw&—FW2$–FVçG&–Âõ&Wò"×W7BÖF6€¢òò66â&V6÷&Bw&—GFVâ2&–FVçG&–Â÷&Wò"âæ÷&ÖÆ—¦R&÷F‚6–FW2&Vf÷&P¢òò6ö×&–ær6ò66RÖÖ—6ÖF6†VBFVWÆ–æ²FöW2æ÷BfÇ6VÇ’&W÷'@¢òò$æò66â–WB"v†–ÆRf–æF–æw2æB÷7GW&R÷VÆFR6÷'&V7FÇ’à¦gVæ7F–öâ&Wô–çFVÆÆ–vVæ6U6ÇVt¶W’‡fÇVS¢7G&–ær“¢7G&–ær°¢&WGW&â6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡fÇVR’çFôÆ÷vW$66R‚“°§Ð §G—R&Wô–çFVÆÆ–vVæ6U66äÆöö·WÒ°¢66ã¢&Wõ66å&V6÷&BÂçVÆÃ°¢òòG'VRv†VâF†R6V&6‚†—B—G2vR6V–Æ–ærv—F‚Ö÷&Rv÷&·76R66ç27F–ÆÀ¢òòf–Æ&ÆRâçVÆÆ66âv—F‚G'Væ6FVC¢G'VVÖVç2'F†R&W÷6—F÷'’Ö¢òò†fRâöÆFW"66âvRF–Bæ÷B&V6‚"(	BF†RG&–ÆÆF÷vâ×W7B6’6ò–ç7FV@¢òòöb&VæFW&–ær$æò66â–WB"Âv†–6‚v÷VÆBFVÆÂF†R÷W&F÷"F†R&W÷6—F÷'¢òò†2æWfW"&VVâ66ææVBâF†R#×vR6¢S×W"×vRÆ–Ö—BÖVç2F†P¢òò&W÷6—F÷'’w2æWvW7B66â6â&R6†F÷vVB'’ÃæWvW"v÷&·76R66ç2à¢G'Væ6FVC¢&ööÆVã°§Ó° ¦7–æ2gVæ7F–öâf–æE&Wô–çFVÆÆ–vVæ6TÆFW7E66â€¢&W÷6—F÷'“¢7G&–ærÀ¢WFƒ¢&WVW7DWF„6öçFW‡BÂVæFVf–æVBÀ¢—47W'&VçC¢‚’Óâ&ööÆVà¢“¢&öÖ—6SÅ&Wô–çFVÆÆ–vVæ6U66äÆöö·Wâ°¢6öç7BF&vWBÒ&Wô–çFVÆÆ–vVæ6U6ÇVt¶W’‡&W÷6—F÷'’“°¢ÆWB7W'6÷#¢7G&–ærÂVæFVf–æVC°¢f÷"†ÆWBvRÒ²vRÂ$Uõô”åDTÄÄ”tTä4Uõ44åôÔ…õtU3²vR³Ò’°¢–b‚—47W'&VçB‚’’&WGW&â²66ã¢çVÆÂÂG'Væ6FVC¢fÇ6RÓ°¢6öç7B&W7öç6RÒv—B”6Æ–VçBæÆ—7E&Wõ66ç2€¢²Æ–Ö—C¢$Uõô”åDTÄÄ”tTä4Uõ44åõtUôÄ”Ô•BÂ7W'6÷"ÒÀ¢WF€¢“°¢6öç7BÖF6‚Ò&W7öç6Ræ—FV×2æf–æB€¢†—FVÒ’Óâ&Wô–çFVÆÆ–vVæ6U6ÇVt¶W’†—FVÒç&W÷6—F÷'’’ÓÓÒF&vW@¢“°¢–b†ÖF6‚’&WGW&â²66ã¢ÖF6‚ÂG'Væ6FVC¢fÇ6RÓ°¢–b‚&W7öç6RææW‡Eö7W'6÷"’&WGW&â²66ã¢çVÆÂÂG'Væ6FVC¢fÇ6RÓ°¢7W'6÷"Ò&W7öç6RææW‡Eö7W'6÷#°¢Ð¢&WGW&â²66ã¢çVÆÂÂG'Væ6FVC¢G'VRÓ°§Ð §G—R&Wô–çFVÆÆ–vVæ6Tf–æF–æw5&W7VÇBÒ°¢—FV×3¢”f–æF–æuµÓ°¢7VÖÖ'“¢&Wôf–æF–æw57VÖÖ'’ÂçVÆÃ°¢G'Væ6FVC¢&ööÆVã°§Ó° ¦7–æ2gVæ7F–öâfWF6…&Wô–çFVÆÆ–vVæ6Tf–æF–æw2€¢&W÷6—F÷'“¢7G&–ærÀ¢WFƒ¢&WVW7DWF„6öçFW‡BÂVæFVf–æVBÀ¢—47W'&VçC¢‚’Óâ&ööÆVà¢“¢&öÖ—6SÅ&Wô–çFVÆÆ–vVæ6Tf–æF–æw5&W7VÇCâ°¢6öç7B—FV×3¢”f–æF–æuµÒÒµÓ°¢ÆWB7VÖÖ'“¢&Wôf–æF–æw57VÖÖ'’ÂçVÆÂÒçVÆÃ°¢ÆWB7W'6÷#¢7G&–ærÂVæFVf–æVC°¢ÆWB7F—fT6÷VçBÒ°¢f÷"†ÆWBvRÒ²vRÂ$Uõô”åDTÄÄ”tTä4Uôd”äD”äu5ôÔ…õtU3²vR³Ò’°¢–b‚—47W'&VçB‚’’&WGW&â²—FV×2Â7VÖÖ'’ÂG'Væ6FVC¢fÇ6RÓ°¢6öç7B&W7öç6RÒv—B”6Æ–VçBæÆ—7E&Wôf–æF–æw2€¢²&W÷6—F÷'’ÂÆ–Ö—C¢$Uõô”åDTÄÄ”tTä4Uôd”äD”äu5ôÄ”Ô•BÂ7W'6÷"ÒÀ¢WF€¢“°¢—FV×2çW6‚‚ââç&W7öç6Ræ—FV×2“°¢7F—fT6÷VçB³Ò&W7öç6Ræ—FV×2ç&VGV6R€¢†6÷VçBÂf–æF–ær’Óâ6÷VçB²†—47F—fU&Wô–çFVÆÆ–vVæ6Tf–æF–ær†f–æF–ær’ò¢’À¢ ¢“°¢–b‡vRÓÓÒbb&W7öç6Rç7VÖÖ'’’°¢7VÖÖ'’Ò&W7öç6Rç7VÖÖ'“°¢Ð¢–b‚&W7öç6RææW‡Eö7W'6÷"’°¢&WGW&â²—FV×2Â7VÖÖ'’ÂG'Væ6FVC¢fÇ6RÓ°¢Ð¢òò7F÷öæ6RvR†fRVæ÷Vv‚5D•dRf–æF–æw2Fòf–ÆÂF†RVWVS¢&Wð¢òòFöÖ–æFVB'’6Æ÷6VBf–æF–æw2v÷VÆB÷F†W'v—6Rv7FR—G2vR'VFvWBæ@¢òò&W÷'B$æòf–æF–æw2"v†–ÆR7F—fR&—6·2v–æFVBgW'F†W"&6²æWfW ¢òò&V6‚F†RVWVRâ†—GF–ærF†—2F&vWBv†–ÆRÖ÷&RvW2&VÖ–â7F–ÆÀ¢òò6÷VçG22G'Væ6F–öâ6òF†R÷W&F÷"6VW2F†Rv&æ–ær&ææW"&F†W ¢òòF†â77VÖ–ærF†RF÷öbF†RVWVR—2F†R†–v†W7B×66÷&–ærf–æF–ærà¢–b†7F—fT6÷VçBãÒ$Uõô”åDTÄÄ”tTä4Uôd”äD”äu5ô5D•dUõD$tUB’°¢&WGW&â²—FV×2Â7VÖÖ'’ÂG'Væ6FVC¢G'VRÓ°¢Ð¢7W'6÷"Ò&W7öç6RææW‡Eö7W'6÷#°¢Ð¢&WGW&â²—FV×2Â7VÖÖ'’ÂG'Væ6FVC¢G'VRÓ°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7Dv—D‡V%&W÷6—F÷'”FWF–ÅvR‚’°¢6öç7B²66÷RÂVçf—&öæÖVçE66÷RÂ6VÆV7FVDVçf—&öæÖVçD”BÂöä6†ævTVçf—&öæÖVçBÒÒW6Tv—D‡V$FöÖ–å66÷R‚“°¢6öç7Bf–Æ&–Æ—G’ÒW6Tv—D‡V$f–Æ&–Æ—G’‚“°¢òò66äÆ–Ö—CÓ6¶—2W6Tv—D‡V$FöÖ–äFFw2&V6VçB×66â&VÆöC¢F†RG&–ÆÆF÷và¢òò&VG266ç2F‡&÷Vv‚f–æE&Wô–çFVÆÆ–vVæ6TÆFW7E66â†—G2÷vâv–æF÷"¢òò&F†W"F†âFöÖ–äFFç66ç2â76–ærR†W&Rv÷VÆBv–æFP¢òòÆ—7E&Wõ66ç4f÷%6VÆV7FVE&W÷6—F÷&–W2v—F‚R×&V6÷&BvW2f÷"WFð¢òòt•D…T%ôÔ…õ44åõtUôdUD4„U26WVVçF–Â&WVW7G2&Vf÷&RF†RG&–ÆÆF÷và¢òòVffV7B6âWfVâ7F'BÂ6–æ6RF†RVffV7Bv—G2f÷"FöÖ–äFFæÆöF–ærFð¢òò6ÆV"âF†RG&–ÆÆF÷vâöæÇ’æVVG26öææV7F–öâ7FGW2g&öÒW6Tv—D‡V$FöÖ–äFFà¢6öç7BFöÖ–äFFÒW6Tv—D‡V$FöÖ–äFF‡66÷RÂ6VÆV7FVDVçf—&öæÖVçD”BÂf–Æ&–Æ—G’æf–Æ&ÆRÂ“°¢6öç7BÆö6F–öâÒW6TÆö6F–öâ‚“° ¢6öç7B6V&6…&×2ÒW6TÖVÖò‚‚’ÓâæWrU$Å6V&6…&×2†Æö6F–öâç6V&6‚’Â¶Æö6F–öâç6V&6…Ò“°¢6öç7B&WVW7FVE&W÷6—F÷'’ÒW6TÖVÖò€¢‚’Óâ6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡6V&6…&×2ævWB‚w&W÷6—F÷'’r’óòrr’À¢·6V&6…&×5Ð¢“° ¢6öç7B·66âÂ6WE66åÒÒW6U7FFSÅ&Wõ66å&V6÷&BÂçVÆÃâ†çVÆÂ“°¢6öç7B·66äÆöö·WG'Væ6FVBÂ6WE66äÆöö·WG'Væ6FVEÒÒW6U7FFR†fÇ6R“°¢6öç7B¶f–æF–æw2Â6WDf–æF–æw5ÒÒW6U7FFSÄ”f–æF–æuµÓâ…µÒ“°¢6öç7B¶f–æF–æw57VÖÖ'’Â6WDf–æF–æw57VÖÖ'•ÒÒW6U7FFSÅ&Wôf–æF–æw57VÖÖ'’ÂçVÆÃâ†çVÆÂ“°¢6öç7B¶f–æF–æw5G'Væ6FVBÂ6WDf–æF–æw5G'Væ6FVEÒÒW6U7FFR†fÇ6R“°¢6öç7B·&—6´w&‚Â6WE&—6´w&…ÒÒW6U7FFSÅ&Wõ&—6´w&‚ÂçVÆÃâ†çVÆÂ“°¢6öç7B·÷7GW&RÂ6WE÷7GW&UÒÒW6U7FFSÄv—D‡V%&W÷6—F÷'•÷7GW&RÂçVÆÃâ†çVÆÂ“°¢6öç7B¶÷&væ—¦F–öå÷7GW&RÂ6WD÷&væ—¦F–öå÷7GW&UÒÒW6U7FFSÄv—D‡V$÷&væ—¦F–öå÷7GW&RÂçVÆÃâ†çVÆÂ“°¢6öç7B·66äÆöF–ærÂ6WE66äÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶f–æF–æw4ÆöF–ærÂ6WDf–æF–æw4ÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·÷7GW&TÆöF–ærÂ6WE÷7GW&TÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·&—6´w&„ÆöF–ærÂ6WE&—6´w&„ÆöF–æuÒÒW6U7FFR†fÇ6R“°¢òò6†&VBW'&÷"&ææW"öæÇ’7W&f6W2VffV7BÖÆWfVÂf–ÇW&W2F†RæVÇ0¢òò6ææ÷BW‡&W72öâF†V—"÷vâ†RærââF÷FVB6öææV7F–öâ×7FGW2W'&÷"’à¢òòW"ÖÆæRW'&÷'27W&f6R–âF†V—"÷vâæVÇ26ò66âf–ÇW&RFöW2æ÷@¢òò†–FR7V66W76gVÂf–æF–æw2VWVRæBf–6RfW'6à¢6öç7B¶W'&÷"Â6WDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·66äW'&÷"Â6WE66äW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B¶f–æF–æw4W'&÷"Â6WDf–æF–æw4W'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·÷7GW&TW'&÷"Â6WE÷7GW&TW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&—6´w&„W'&÷"Â6WE&—6´w&„W'&÷%ÒÒW6U7FFR‚rr“°¢6öç7BÆöF–ærÒ66äÆöF–ærÇÂf–æF–æw4ÆöF–æs°¢6öç7B·&Wf–Wtf–æF–æt”BÂ6WE&Wf–Wtf–æF–æt”EÒÒW6U7FFR‚rr“°¢6öç7B·&Wf–WrÂ6WE&Wf–WuÒÒW6U7FFSÅ&Wôf–æF–æu&VÖVF–F–öå&Wf–WrÂçVÆÃâ†çVÆÂ“°¢6öç7B·&Wf–WtÆöF–ærÂ6WE&Wf–WtÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·&Wf–WtW'&÷"Â6WE&Wf–WtW'&÷%ÒÒW6U7FFR‚rr“° ¢6öç7B&WVW7E&VbÒW6U&Vbƒ“°¢6öç7B&Wf–Wu&WVW7E&VbÒW6U&Vbƒ“° ¢6öç7B&W6WE&W÷6—F÷'•7FFRÒW6T6ÆÆ&6²‚‚’Óâ°¢6WE66â†çVÆÂ“°¢6WE66äÆöö·WG'Væ6FVB†fÇ6R“°¢6WE66äW'&÷"‚rr“°¢6WE66äÆöF–ær†fÇ6R“°¢6WDf–æF–æw2…µÒ“°¢6WDf–æF–æw57VÖÖ'’†çVÆÂ“°¢6WDf–æF–æw5G'Væ6FVB†fÇ6R“°¢6WDf–æF–æw4W'&÷"‚rr“°¢6WDf–æF–æw4ÆöF–ær†fÇ6R“°¢6WE&—6´w&‚†çVÆÂ“°¢6WE&—6´w&„W'&÷"‚rr“°¢6WE&—6´w&„ÆöF–ær†fÇ6R“°¢6WE÷7GW&R†çVÆÂ“°¢6WD÷&væ—¦F–öå÷7GW&R†çVÆÂ“°¢6WE÷7GW&TW'&÷"‚rr“°¢6WE÷7GW&TÆöF–ær†fÇ6R“°¢òòç’VæF–ær&VÖVF–F–öâ&Wf–Wr&VÆöæw2FòF†R&Wf–÷W266÷RÂ6òG&÷ ¢òò—G2F—7Æ’7FFRæB–çfÆ–FFR—G2&WVW7BFö¶Vâ6òÆFR6ö×ÆWF–öà¢òò6ææ÷B÷fW'w&—FRF†RæWr66÷Rw27FFRà¢&Wf–Wu&WVW7E&Vbæ7W'&VçB³Ò°¢6WE&Wf–Wtf–æF–æt”B‚rr“°¢6WE&Wf–Wr†çVÆÂ“°¢6WE&Wf–WtÆöF–ær†fÇ6R“°¢6WE&Wf–WtW'&÷"‚rr“°¢ÒÂµÒ“° ¢W6TVffV7B‚‚’Óâ°¢òòf–Æ&–Æ—G’æÆöF–ær†2FòvFRF†RfWF6‚†W&RWfVâF†÷Vv‚F†R¥5€¢òò6†÷w2F†RÆöF–ær6†VÆÂFöó¢F†R¥5‚'Vç2gFW"F†—2†öö²Â6òv—F†÷W@¢òòF†RwV&BF†RG&–ÆÆF÷vâ×7V6–f–2Æ—7E&Wôf–æF–æw2övWE&Wõ&—6´w&€¢òò6ÆÇ2v÷VÆBf—&R&Vf÷&RF†R÷W&F÷"WfW"6VW2F†RÆöF–ær6†VÆÂà¢òòFöÖ–äFFæÆöF–ærvFW2F†R6ÖRfWF6†W3¢v—F†÷WB—BÂ66âöf–æF–æw2ð¢òòw&‚f—&RöâF†R–æ—F–Â&VæFW"v—F‚6öææV7F–öãÖçVÆÂÂF†VâF†RVffV7@¢òò6ÆVçW–çfÆ–FFW2F†VÒæB&Vf—&W2F†VÒöæ6R6öææV7F–öâ6WGFÆW2à¢òò––ærF÷V&ÆRF†Rv–æF–öâ6÷7B—2W7V6–ÆÇ’v7FVgVÂöâ&W÷2v—F€¢òòFVW66â†—7F÷&–W2â÷7GW&RÇ&VG’v—G2f÷"6öææV7F–öâ&V6W6R—@¢òòæVVG2F†R6öææV7F÷%ö–BæB&÷f–FW"Â6òvF–ærF†R÷F†W'2†W&R§W7@¢òòÆ–vç2F†RF‡&VRÆæW2FòF†R6ÖR&6öææV7F–öâ&VG’"G&–vvW"à¢–b€¢f–Æ&–Æ—G’æÆöF–ærÇÀ¢66÷RÇÀ¢f–Æ&–Æ—G’æf–Æ&ÆRÇÀ¢6VÆV7FVDVçf—&öæÖVçD”BÇÀ¢&WVW7FVE&W÷6—F÷'’ÇÀ¢FöÖ–äFFæÆöF–æp¢’°¢&WVW7E&Vbæ7W'&VçB³Ò°¢&W6WE&W÷6—F÷'•7FFR‚“°¢òò¶VW&÷F‚ÆæW2Ö&¶VBÆöF–ærv†–ÆRF†R6öææV7F–öâ—27F–ÆÀ¢òò&W6öÇf–ær6òF†R÷WFW"FöÖ–äÆöF–æu7FFR&VæFW'2–ç7FVBö`¢òòV×G’×7FFRæVÇ2F†Bv÷VÆBfÆ6‚$æò66â–WB"ò$æòf–æF–æw2 ¢òò–âF†R–çFW&ÖVF–FRg&ÖRà¢6WE66äÆöF–ær†FöÖ–äFFæÆöF–ær“°¢6WDf–æF–æw4ÆöF–ær†FöÖ–äFFæÆöF–ær“°¢6WDW'&÷"‚rr“°¢&WGW&âVæFVf–æVC°¢Ð¢6öç7B&WVW7D”BÒ²·&WVW7E&Vbæ7W'&VçC°¢òò&W6WB&W÷6—F÷'’Ö&÷VæB7FFR&Vf÷&RF†RfWF6‚'Vç2âv—F†÷WBF†—2¢òòf–Æ–ær&WVW7Bv÷VÆBÆVfRF†R&Wf–÷W2&W÷6—F÷'’w266âÂf–æF–æw2À¢òòw&‚ÂæB÷7GW&R&VæFW&VBVæFW"F†RæWr&W÷6—F÷'’†VF–æröæ6P¢òòÆöF–ærfÆ—VB&6²FòfÇ6Rà¢&W6WE&W÷6—F÷'•7FFR‚“°¢6WE66äÆöF–ær‡G'VR“°¢6WDf–æF–æw4ÆöF–ær‡G'VR“°¢6WDW'&÷"‚rr“° ¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢6öç7B6öææV7F–öâÒFöÖ–äFFæ6öææV7F–öã°¢6öç7B6öææV7F÷$”BÒ6öææV7F–öãòæ6öææV7F÷%ö–Bóòrs°¢òòv—Bf÷"F†R6öææV7F–öâ7FGW2fWF6‚Fò6WGFÆR&Vf÷&RFV6–F–ærv†WF†W ¢òò÷7GW&R—27W÷'FVBâ&VF–ær&÷f–FW&v†–ÆRFöÖ–äFFæÆöF–æv—0¢òòG'VRv÷VÆBG&VBâ–âÖfÆ–v‡Bv—F‡V%ö&W7öç6R2–b—BvW&Rà¢òòVç7W÷'FVB&÷f–FW"æBV–WFÇ’6¶—÷7GW&S²&V¦V7FVB6öææV7F–öà¢òòfWF6‚v÷VÆBÆVfRF†RG&–ÆÆF÷vâ6Æ–Ö–ær$6öææV7Bv—D‡V""v†–ÆRF†P¢òò&VÂW'&÷"v2†–FFVââ7W&f6RF†RfWF6†VBW'&÷"W‡Æ–6—FÇ’æBvFP¢òò÷7GW&Röâ&÷F‚ÆöF–æræB6öææV7FVB7FFRà¢–b†FöÖ–äFFæW'&÷"’°¢òò&W6W'fRF†RW†—7F–ærW'&÷"–bF†RG&–ÆÆF÷vâw2÷vâfWF6‚Ç&VG¢òòf–ÆVC²÷F†W'v—6RF÷BF†R6öææV7F–öâ×7FGW2W'&÷"6òF†R÷W&F÷ ¢òò6VW2F†R&VÂ6W6R–ç7FVBöbF†R$6öææV7Bv—D‡V""V×G’7FFRà¢6WDW'&÷"‚†7W'&VçB’Óâ7W'&VçBÇÂFöÖ–äFFæW'&÷"“°¢Ð¢6öç7B÷7GW&U7W÷'FVBÒ&ööÆVâ€¢FöÖ–äFFæÆöF–ærb`¢6öææV7F÷$”Bb`¢6öææV7F–öãòæ6öææV7FVBb`¢6öææV7F–öâç&÷f–FW"ÓÓÒvv—F‡V%öp¢“°¢6öç7B—47W'&VçBÒ‚’Óâ&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçC° ¢òò¶æ÷vâÆ–Ö—FF–öã¢Æ—7E&Wõ66ç2ÂÆ—7E&Wôf–æF–æw2ÂæBvWE&Wõ&—6´w&€¢òòÆÂ66÷R'’v÷&·76Rf–F†RWF‚6öçFW‡B'WBFòæ÷B66WB¢òò&ö¦V7BöVçf—&öæÖVçBf–ÇFW"Â6ò&W÷6—F÷'’66ææVBF‡&÷Vv‚Gvð¢òòVçf—&öæÖVçG2–âF†R6ÖRv÷&·76R6âÖ—‚F†R÷F†W"Vçf—&öæÖVçBw0¢òò&V6÷&G2–çFòF†—2G&–ÆÆF÷vâWfVâF†÷Vv‚F†RVçf—&öæÖVçB6VÆV7F÷ ¢òò7VvvW7G2÷F†W'v—6RâF†—2—2æ÷BG&–ÆÆF÷vâ×7V6–f–2(	BWfW'’W†—7F–æp¢òòv—D‡V"ÖFöÖ–âvRF†BW6W2F†W6RVæGö–çG2–æ†W&—G2F†R6ÖP¢òò&V†f–÷"(	BæBf—†–ær—B&WV—&W2&6¶VæBf–ÇFW'2‡6VRföÆÆ÷r×W ¢òòF6²’â÷7GW&R—2Ç&VG’Vçf—&öæÖVçB×66÷VB&V6W6R—BW6W2F†P¢òò6öææV7F÷"VæGö–çBF†B6'&–W2F†R&ö¦V7Eö–Bà¢òò66âÆöö·WæBf–æF–æw2v–æF–öâV6‚'VâöâF†V—"÷vâ&öÖ—6P¢òòÆæR6òG&ç6–VçBf–ÇW&RöâöæRVæGö–çB6ææ÷BF—66&B¢òò7V66W76gVÂ&W7öç6Rg&öÒF†R÷F†W"â†öÆF–ærf–æF–æw2&V†–æB¢òò&V¦V7FVB÷c÷&Wò×66ç26ÆÂv÷VÆB&VæFW"$æòf–æF–æw2"Æöæw6–FP¢òò6†&VBW'&÷"&ææW"WfVâF†÷Vv‚F†Rf–æF–æw2&WVW7B6ö×ÆWFV@¢òò7V66W76gVÆÇ’(	BæBf–6RfW'6à¢f–æE&Wô–çFVÆÆ–vVæ6TÆFW7E66â‡&WVW7FVE&W÷6—F÷'’ÂWF‚Â—47W'&VçB¢çF†Vâ‚‡66å&W7VÇB’Óâ°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WE66â‡66å&W7VÇBç66â“°¢6WE66äÆöö·WG'Væ6FVB‡66å&W7VÇBçG'Væ6FVB“°¢Ò¢æ6F6‚‚‡66äfWF6„W'&÷#¢Væ¶æ÷vâ’Óâ°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WE66äW'&÷"†f÷&ÖD”W'&÷"‡66äfWF6„W'&÷"ÂuVæ&ÆRFòÆöBÆFW7B66âf÷"F†—2&W÷6—F÷'’âr’“°¢Ò¢æf–æÆÇ’‚‚’Óâ°¢–b‡&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçB’°¢6WE66äÆöF–ær†fÇ6R“°¢Ð¢Ò“° ¢fWF6…&Wô–çFVÆÆ–vVæ6Tf–æF–æw2‡&WVW7FVE&W÷6—F÷'’ÂWF‚Â—47W'&VçB¢çF†Vâ‚†f–æF–æw5&W7VÇB’Óâ°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WDf–æF–æw2†f–æF–æw5&W7VÇBæ—FV×2“°¢6WDf–æF–æw57VÖÖ'’†f–æF–æw5&W7VÇBç7VÖÖ'’“°¢6WDf–æF–æw5G'Væ6FVB†f–æF–æw5&W7VÇBçG'Væ6FVB“°¢Ò¢æ6F6‚‚†f–æF–æw4fWF6„W'&÷#¢Væ¶æ÷vâ’Óâ°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WDf–æF–æw4W'&÷"†f÷&ÖD”W'&÷"†f–æF–æw4fWF6„W'&÷"ÂuVæ&ÆRFòÆöBf–æF–æw2f÷"F†—2&W÷6—F÷'’âr’“°¢Ò¢æf–æÆÇ’‚‚’Óâ°¢–b‡&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçB’°¢6WDf–æF–æw4ÆöF–ær†fÇ6R“°¢Ð¢Ò“° ¢òò&—6²w&‚'Vç2öâ—G2÷vâÆæRFöòâ—Bw2÷F–öæÂVç&–6†ÖVçB‡F†P¢òòVWVRÇ&VG’fÆÇ2&6²Fò6WfW&—G’÷&FW&–ærv†Vâ&—6´w&‚—0¢òòçVÆÂ’æB—G2VæGö–çB6â&R6Æ÷r÷"Væf–Æ&ÆR–æFWVæFVçBö`¢òò66ç2æBf–æF–æw2à¢6WE&—6´w&„ÆöF–ær‡G'VR“°¢”6Æ–Vç@¢ævWE&Wõ&—6´w&‚‡²&W÷6—F÷'“¢&WVW7FVE&W÷6—F÷'’ÒÂWF‚¢çF†Vâ‚†w&‚’Óâ°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WE&—6´w&‚†w&‚“°¢Ò¢æ6F6‚‚†w&„fWF6„W'&÷#¢Væ¶æ÷vâ’Óâ°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WE&—6´w&„W'&÷"†f÷&ÖD”W'&÷"†w&„fWF6„W'&÷"ÂuVæ&ÆRFòÆöB&W÷6—F÷'’&—6²w&‚âr’“°¢Ò¢æf–æÆÇ’‚‚’Óâ°¢–b‡&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçB’°¢6WE&—6´w&„ÆöF–ær†fÇ6R“°¢Ð¢Ò“° ¢òò÷7GW&R'Vç2öâ—G2÷vâÆæRÂ6W&FRg&öÒF†RÖ–â&öÖ—6RæÆÂâF†P¢òòv—D‡V"÷7GW&RVæGö–çBW&f÷&×2Æ—fR&W÷6—F÷'’æB÷&væ—¦F–öà¢òò6öÆÆV7F–öâv–ç7BF†Rv—D‡V"’Â6ò—G2ÆFVæ7’—2&÷VæFVB'’v—D‡V ¢òò&F†W"F†â'’–FVçG&–Ââ†öÆF–ærF†RVçF—&RG&–ÆÆF÷vâ&V†–æB—Bv÷VÆ@¢òòv—F††öÆBÇ&VG’Ö6ö×ÆWFVB66âÂf–æF–æw2ÂæB&—6²Öw&‚&W7VÇG0¢òòv†–ÆR&FRÖÆ–Ö—FVB÷"6Æ÷r÷7GW&R6ÆÂf–æ—6†VBâF†R÷7GW&RæVÀ¢òò†2—G2÷vâÆöF–æræBW'&÷"7FFR6ò÷W&F÷'27F–ÆÂ6VR&öw&W70¢òòf÷"—Bv—F†÷WBvF–ærF†R&W7BöbF†RvRà¢–b‡÷7GW&U7W÷'FVB’°¢6WE÷7GW&TÆöF–ær‡G'VR“°¢”6Æ–Vç@¢ævWDv—D‡V$6öææV7F÷%&W÷6—F÷'•÷7GW&R†6öææV7F÷$”BÂ66÷Rçv÷&·76T”BÂ6VÆV7FVDVçf—&öæÖVçD”BÂ&WVW7FVE&W÷6—F÷'’ÂWF‚¢çF†Vâ‚‡&W7öç6R’Óâ°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WE÷7GW&R‡&W7öç6Rç÷7GW&R“°¢òò÷&væ—¦F–öâ÷7GW&R7W&f6W2–æ†W&—FVB6öçG&öÂv2„7F–öç0¢òòöÆ–7’Â6V7W&—G’6öæf–wW&F–öâÂ'VææW"öÆ–7’’F†Bv÷VÆ@¢òò÷F†W'v—6R&R–çf—6–&ÆRöâF†RG&–ÆÆF÷vâWfVâF†÷Vv‚F†W’v÷fW&à¢òòF†R&W÷6—F÷'’â7F÷&R—B6W&FVÇ’g&öÒ&W÷6—F÷'’÷7GW&R6ð¢òò&÷F‚6WG2&VæFW"v—F‚F†V—"÷vâ66÷RÆ&VÂà¢6WD÷&væ—¦F–öå÷7GW&R‡&W7öç6Ræ÷&væ—¦F–öå÷÷7GW&RóòçVÆÂ“°¢Ò¢æ6F6‚‚‡÷7GW&TfWF6„W'&÷#¢Væ¶æ÷vâ’Óâ°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WE÷7GW&TW'&÷"†f÷&ÖD”W'&÷"‡÷7GW&TfWF6„W'&÷"ÂuVæ&ÆRFòÆöB&W÷6—F÷'’÷7GW&Râr’“°¢Ò¢æf–æÆÇ’‚‚’Óâ°¢–b‡&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçB’°¢6WE÷7GW&TÆöF–ær†fÇ6R“°¢Ð¢Ò“°¢Ð ¢&WGW&â‚’Óâ°¢–b‡&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçB’°¢&WVW7E&Vbæ7W'&VçB³Ò°¢Ð¢Ó°¢ÒÂ°¢66÷SòçFVæçD”BÀ¢66÷Sòçv÷&·76T”BÀ¢f–Æ&–Æ—G’æf–Æ&ÆRÀ¢f–Æ&–Æ—G’æÆöF–ærÀ¢6VÆV7FVDVçf—&öæÖVçD”BÀ¢&WVW7FVE&W÷6—F÷'’À¢FöÖ–äFFæ6öææV7F–öãòæ6öææV7FVBÀ¢FöÖ–äFFæ6öææV7F–öãòæ6öææV7F÷%ö–BÀ¢FöÖ–äFFæ6öææV7F–öãòç&÷f–FW"À¢FöÖ–äFFæÆöF–ærÀ¢FöÖ–äFFæW'&÷"À¢&W6WE&W÷6—F÷'•7FFP¢Ò“° ¢6öç7BVWVRÒW6TÖVÖò‚‚’Óâ'V–ÆE&Wô–çFVÆÆ–vVæ6UVWVR†f–æF–æw2Â&—6´w&‚’Â¶f–æF–æw2Â&—6´w&…Ò“°¢òòF÷&Æ7B×&F—W2F‡2×W7B&VfÆV7BöæÇ’5D•dRf–æF–æw2âF†R&—6²w&€¢òò'V–ÆG266÷&W2F—&V7FÇ’g&öÒÆ—7E&Wôf–æF–æw2v—F†÷WBÇ––ærÆ–fV7–6ÆP¢òòf–ÇFW&–ærÂ6òf—†VBò7W&W76VBò&—6²Ö66WFVBòfÇ6R×÷6—F—fP¢òòf–æF–ær6â7F–ÆÂ6''’†–v‚66÷&RæBF—7Æ6Râ÷VâöæRg&öÒF†P¢òòF÷ÓRâ–çFW'6V7BF†R6÷'FVB66÷&W2v—F‚F†RVWVRw27F—fRf–æF–ær”G0¢òò&Vf÷&R6Æ–6–ær6òF†RÆ—7BöæÇ’6†÷w2&—6·2F†R÷W&F÷"7F–ÆÂæVVG2Fð¢òò7Böââ6÷'Bf—'7B6òF†R’w2–ç6W'F–öâ÷&FW"6âæWfW"FWFW&Ö–æP¢òòf–æÂ&æ²à¢6öç7BF÷F‡2ÒW6TÖVÖò‚‚’Óâ°¢6öç7B7F—fTf–æF–æt”G2ÒæWr6WB‡VWVRæÖ‚‡²f–æF–ærÒ’Óâf–æF–æræ–B’“°¢6öç7Bf–æF–æuF—FÆT'””BÒæWrÖ‡VWVRæÖ‚‡²f–æF–ærÒ’Óâ¶f–æF–æræ–BÂf–æF–ærçF—FÆRÇÂf–æF–æræFWFV7F÷"ÇÂf–æF–ærçG—UÒ’“°¢&WGW&â6÷'E&Wõ&—6´w&…66÷&W2‡&—6´w&ƒòç66÷&W2óòµÒ¢æf–ÇFW"‚‡66÷&R’Óâ7F—fTf–æF–æt”G2æ†2‡66÷&Ræf–æF–æuö–B’¢ç6Æ–6RƒÂ$Uõô”åDTÄÄ”tTä4UõDõõD…5ôÄ”Ô•B¢òòVç&–6‚V6‚66÷&Rv—F‚F†R7GVÂæöFR6†–â—B&V6†W2F‡&÷Vv‚F†P¢òòw&‚w2÷WFvö–ærVFvW26òF†RæVÂ6†÷w2F†Rv÷&¶fÆ÷rö–FVçF—G’ð¢òò'VææW"öVçf—&öæÖVçBö6öçG&öÂ&VÆF–öç6†—2F†B6öç7F—GWFR&Æ7@¢òò&F—W2Âæ÷B§W7BF†Rf–æF–ær66÷&RâfÆÇ2&6²FòâV×G’6†–à¢òòv†VâF†Rw&‚†2æòæöFW2öVFvW2†öÆFW"7VÖÖ&–W2v—F†÷W@¢òò&V6†&–Æ—G’FF’(	BF†R&÷r7F–ÆÂ&VæFW'2v—F‚F†Rf–æF–ær†VFW ¢òòæB66÷&R–âF†B66Rà¢æÖ‚‡66÷&R’Óâ‡°¢66÷&RÀ¢F—FÆS¢f–æF–æuF—FÆT'””BævWB‡66÷&Ræf–æF–æuö–B’óò66÷&Ræf–æF–æuö–BÀ¢6†–ã¢&—6´w&€¢òFW&—fU&Wô–çFVÆÆ–vVæ6T&Æ7E&F—W5F‚‡&—6´w&‚Â66÷&Ræf–æF–æuöæöFUö–B¢¢µÐ¢Ò’“°¢ÒÂ·VWVRÂ&—6´w&…Ò“°¢òò&W6VçB&W÷6—F÷'’æB÷&væ—¦F–öâ÷7GW&RFövWF†W"ÂFvvVB'’66÷R6ð¢òò÷W&F÷'26âFVÆÂ–æ†W&—FVB÷&röÆ–7’v2g&öÒ&W÷6—F÷'’öæW2â6V7W&P¢òòæBVç7W÷'FVB6†V6·2&R†–FFVâB&÷F‚66÷W2à¢6öç7B–ç6V7W&U÷7GW&T6†V6·2ÒW6TÖVÖò€¢‚’Óâ°¢âââ‡÷7GW&Sòæ6†V6·2óòµÒ¢æf–ÇFW"‚†6†V6²’Óâ6†V6²ç7FFRÓÒw6V7W&Rrbb6†V6²ç7FFRÓÒwVç7W÷'FVBr¢æÖ‚†6†V6²’Óâ‡²66÷S¢w&W÷6—F÷'’r26öç7BÂ6†V6²Ò’’À¢âââ†÷&væ—¦F–öå÷7GW&Sòæ6†V6·2óòµÒ¢æf–ÇFW"‚†6†V6²’Óâ6†V6²ç7FFRÓÒw6V7W&Rrbb6†V6²ç7FFRÓÒwVç7W÷'FVBr¢æÖ‚†6†V6²’Óâ‡²66÷S¢v÷&væ—¦F–öâr26öç7BÂ6†V6²Ò’¢ÒÀ¢·÷7GW&RÂ÷&væ—¦F–öå÷7GW&UÐ¢“°¢6öç7B6ö×ÆWFVæW72Ò&Wô–çFVÆÆ–vVæ6U66ä6ö×ÆWFVæW72‡66â“°¢òòFW&—fRf—‚×&VG’6÷VçBg&öÒF†RFWFW&Ö–æ—7F–2×F6‚7V'6WBöb7W÷'FV@¢òòFWFV7F÷'2(	BF†RöæW2v†÷6R&6¶VæB&VÖVF–F–öâ&WGW&ç2V&Æ—6†&ÆS§G'VRà¢òò&VF–ærf–æF–æræWf–FVæ6RçV&Æ—6†&ÆRv÷VÆB&W÷'B¦W&òöâf—'7B&VæFW ¢òòæBw&÷röæÇ’v†VâF†R÷W&F÷"ÖçVÆÇ’&Wf–WvVBV6‚f–æF–ærÂæ@¢òò6÷VçF–ærF†RgVÆÂ7W÷'FVB6WBv÷VÆB÷fW"ÖGfW'F—6R6–æ6R6V7&W@¢òòW‡÷7W&W2æBwV–Fæ6RÖöæÇ’v÷&¶fÆ÷rö•övVçBFWFV7F÷'2&WGW&à¢òòV&Æ—6†&ÆS¦fÇ6RWfVâF†÷Vv‚&Wf–Wr—2f–Æ&ÆRà¢6öç7BV&Æ—6†&ÆT6÷VçBÒVWVRæf–ÇFW"‚‡²f–æF–ærÒ’Óâ—5V&Æ—6†&ÆU&VÖVF–F–öäf–æF–ær†f–æF–ær’’æÆVæwFƒ°¢6öç7B&Wf–Wu&VG”6÷VçBÒVWVRæf–ÇFW"‚‡²f–æF–ærÒ’Óâ—5&VÖVF–F–öå7W÷'FVDf–æF–ær†f–æF–ær’’æÆVæwFƒ° ¢6öç7B6Æ÷6U&Wf–WrÒW6T6ÆÆ&6²‚‚’Óâ°¢òò'V×–ærF†R&WVW7BFö¶Vâ†W&RÖGFW'2WfVâv†Vâæò&WVW7B—2–âfÆ–v‡@¢òò(	B–bF†R÷W&F÷"F—6Ö—76VBF†RæVÂv†–ÆR&Wf–Wrv27F–ÆÂÆöF–ærÀ¢òòF†RÆFR&W7öç6Rv÷VÆB72F†R&Wf–÷W2Fö¶VâwV&BÂw&—FR–çFð¢òò&Wf–WvÂæB6†ævRV&Æ—6†&ÆT6÷VçFf÷"f–æF–ærF†R÷W&F÷ ¢òòW‡Æ–6—FÇ’6Æ÷6VBâ6ÆV&–ærWfW'’&Wf–Wr×&VÆFVB7FFR†–æ6ÇVF–æp¢òò&Wf–WtÆöF–ærÂv†–6‚F†RV&Æ–W"6Æ÷6R†æFÆW"ÆVgB–âF†RÆöF–æp¢òò÷6—F–öâ’¶VW2F†RT’æBF†RFö¶Vâ–â7–æ2à¢&Wf–Wu&WVW7E&Vbæ7W'&VçB³Ò°¢6WE&Wf–Wtf–æF–æt”B‚rr“°¢6WE&Wf–Wr†çVÆÂ“°¢6WE&Wf–WtW'&÷"‚rr“°¢6WE&Wf–WtÆöF–ær†fÇ6R“°¢ÒÂµÒ“° ¢6öç7B÷Vå&Wf–WrÒW6T6ÆÆ&6²€¢7–æ2†f–æF–æs¢”f–æF–ær’Óâ°¢–b‚66÷R’&WGW&ã°¢òòWfW'’÷Vå&Wf–Wr–çfö6F–öâ6Æ–×2æWrFö¶Vã¢&W÷6—F÷'’÷ ¢òòVçf—&öæÖVçB6†ævR'V×2&Wf–Wu&WVW7E&Vb–â&W6WE&W÷6—F÷'•7FFRÀ¢òòæB6V6öæB6Æ–6²&Vf÷&RF†Rf—'7B&WVW7B&W6öÇfW2'V×2—Bv–à¢òò†W&RâÆFR6ö×ÆWF–öç2v†÷6RFö¶VâæòÆöævW"ÖF6†W2æWfW"F÷V6€¢òò&Wf–Wr7FFRÂ6òF†W’6ææ÷B&VæFW"F†R&Wf–÷W266÷Rw2÷"¢òò7WW'6VFVBf–æF–ærw2&VÖVF–F–öâVæFW"F†R7W'&VçB†VF–ærà¢6öç7B&Wf–Wt”BÒ²·&Wf–Wu&WVW7E&Vbæ7W'&VçC°¢6WE&Wf–Wtf–æF–æt”B†f–æF–æræ–B“°¢6WE&Wf–Wr†çVÆÂ“°¢6WE&Wf–WtW'&÷"‚rr“°¢6WE&Wf–WtÆöF–ær‡G'VR“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢òòF†R&VÖVF–F–öâ&Wf–WrVæGö–çBÆöö·2F†Rf–æF–ærW'’&÷F‚–@¢òòäB66â–Bâ&WF–æVBöÆFW"f–æF–ærv†÷6RæWvW"66â—2æ÷rF†P¢òò&W÷6—F÷'’w2ÆFW7B7F–ÆÂÆ—fW2öâ—G2÷vâ66âÂ6ò76–ærF†P¢òòG&–ÆÆF÷vâw266âæ–Fv÷VÆBCBâ&VfW"F†Rf–æF–ærw2÷vâ66â–@¢òòæBöæÇ’fÆÂ&6²FòF†RÆFW7B66âv†VâF†Rf–æF–ærFöW2æ÷@¢òò6''’öæR†RærâFFW'2F†B†fRæ÷B–WB7F'FVBVÖ—GF–ær—B’à¢6öç7B&Wf–Wu66ä”BÒf–æF–ærç66åö–BÇÂ66ãòæ–BÇÂrs°¢6öç7B&W7öç6RÒv—B”6Æ–VçBç&Wf–Wu&Wôf–æF–æu&VÖVF–F–öâ€¢f–æF–æræ–BÀ¢²&Wõ÷66åö–C¢&Wf–Wu66ä”BÒÀ¢WF€¢“°¢–b‡&Wf–Wt”BÓÒ&Wf–Wu&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WE&Wf–Wr‡&W7öç6R“°¢Ò6F6‚‡&Wf–WtfWF6„W'&÷#¢Væ¶æ÷vâ’°¢–b‡&Wf–Wt”BÓÒ&Wf–Wu&WVW7E&Vbæ7W'&VçB’&WGW&ã°¢6WE&Wf–WtW'&÷"†f÷&ÖD”W'&÷"‡&Wf–WtfWF6„W'&÷"ÂuVæ&ÆRFò&Wf–Wr&VÖVF–F–öâf÷"F†—2f–æF–ærâr’“°¢Òf–æÆÇ’°¢–b‡&Wf–Wt”BÓÓÒ&Wf–Wu&WVW7E&Vbæ7W'&VçB’°¢6WE&Wf–WtÆöF–ær†fÇ6R“°¢Ð¢Ð¢ÒÀ¢·66÷RÂ66ãòæ–EÐ¢“° ¢–b‚66÷R’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷""&öÆSÒ&ÆW'B#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äv—D‡V"&W÷6—F÷'’–çFVÆÆ–vVæ6SÂ÷à¢Æƒ#åv÷&·76R&÷WFR6öçFW‡B—2Ö—76–æsÂöƒ#à¢Çä6†ö÷6RFVæçBæBv÷&·76R&Vf÷&R÷Væ–ær&W÷6—F÷'’G&–ÆÆF÷vâãÂ÷à¢Â÷6V7F–öãà¢“°¢Ð ¢òòfVGW&RF—66÷fW'’Âv—D‡V"f–Æ&–Æ—G’ÂæBVçf—&öæÖVçB6VÆV7F–öâ×W7B&P¢òò&W6öÇfVB&Vf÷&RF†RG&–ÆÆF÷vâ&VæFW'2—G2æ÷&ÖÂ6†VÆÂâv—F†÷WBF†W6P¢òòwV&G2ÆöF–ær÷"Væf–Æ&ÆR'V–ÆBv÷VÆBfÆÂF‡&÷Vv‚FòF†R6ÖP¢òòæVÇ2æB6†÷r$æò66â–WB"ò$æòf–æF–æw2"ò$6öææV7Bv—D‡V""WfVà¢òòF†÷Vv‚F†R&6¶VæBæWfW"vfRF†RG&–ÆÆF÷vâ6†æ6RFòfWF6‚ç—F†–ærà¢òòÖF6†W2F†RGFW&âF†R&W÷6—F÷&–W2–çfVçF÷'’vRW6W2à¢–b†f–Æ&–Æ—G’æÆöF–ær’°¢&WGW&â€¢ÄFöÖ–åvU6†VÆÀ¢FöÖ–ãÒ&v—F‡V" ¢W–V'&÷sÒ%&W÷6—F÷'’–çFVÆÆ–vVæ6R ¢F—FÆSÒ$v—D‡V"&W÷6—F÷'’–çFVÆÆ–vVæ6R ¢FW67&—F–öãÒ$ÆöF–ærv—D‡V"f–Æ&–Æ—G’f÷"F†—2'V–ÆBâ ¢66÷S×³Å&öGV7DVçf—&öæÖVçE6VÆV7F÷"7FFS×¶Vçf—&öæÖVçE66÷WÒöä6†ævS×¶öä6†ævTVçf—&öæÖVçGÒóçÐ¢à¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ærv—D‡V"f–Æ&–Æ—G’"óà¢ÂôFöÖ–åvU6†VÆÃà¢“°¢Ð ¢–b‚f–Æ&–Æ—G’æf–Æ&ÆR’°¢&WGW&â€¢Äv—D‡V%Væf–Æ&ÆU6†VÆÀ¢F—FÆSÒ$v—D‡V"&W÷6—F÷'’–çFVÆÆ–vVæ6R ¢66÷S×·66÷WÐ¢Vçf—&öæÖVçE66÷S×¶Vçf—&öæÖVçE66÷WÐ¢6VÆV7FVDVçf—&öæÖVçD”C×·6VÆV7FVDVçf—&öæÖVçD”GÐ¢öäVçf—&öæÖVçD6†ævS×¶öä6†ævTVçf—&öæÖVçGÐ¢Væf–Æ&ÆTÖW76vS×¶f–Æ&–Æ—G’çVæf–Æ&ÆTÖW76vWÐ¢óà¢“°¢Ð ¢–b‚6VÆV7FVDVçf—&öæÖVçD”B’°¢&WGW&â€¢Äv—D‡V$Ö—76–ætVçf—&öæÖVçE6†VÆÀ¢F—FÆSÒ$v—D‡V"&W÷6—F÷'’–çFVÆÆ–vVæ6R ¢66÷S×·66÷WÐ¢Vçf—&öæÖVçE66÷S×¶Vçf—&öæÖVçE66÷WÐ¢6VÆV7FVDVçf—&öæÖVçD”C×·6VÆV7FVDVçf—&öæÖVçD”GÐ¢öäVçf—&öæÖVçD6†ævS×¶öä6†ævTVçf—&öæÖVçGÐ¢óà¢“°¢Ð ¢òòwV&G2&÷fRÇ&VG’&WGW&æVBv†Vâ6VÆV7FVDVçf—&öæÖVçD”B—2V×G’f–¢òòv—D‡V$Ö—76–ætVçf—&öæÖVçE6†VÆÂÂ6òF†—2Çv—2VæG2&VÂVçf—&öæÖVçBà¢6öç7B&W÷6—F÷&–W5F‚ÒG¶'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"÷&W÷6—F÷&–W2r—ÓòG´Tåd•$ôäÔTåEõTU%•õ$×ÓÒG¶Væ6öFUU$”6ö×öæVçB‡6VÆV7FVDVçf—&öæÖVçD”B—Ö° ¢–b‚&WVW7FVE&W÷6—F÷'’’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷""&öÆSÒ&ÆW'B#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äv—D‡V"&W÷6—F÷'’–çFVÆÆ–vVæ6SÂ÷à¢Æƒ#å&W÷6—F÷'’æ÷B6VÆV7FVCÂöƒ#à¢ÇäFBÆ6öFSã÷&W÷6—F÷'“Ö÷væW"öæÖSÂö6öFSâVW'’&ÖWFW"÷"÷Vâ&W÷6—F÷'’g&öÒF†R–çfVçF÷'’ãÂ÷à¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖÖV×G’×7FFRÖ7F–öâ"Fó×·&W÷6—F÷&–W5F‡Óà¢&6²Fò&W÷6—F÷&–W0¢ÂôÆ–æ³à¢Â÷6V7F–öãà¢“°¢Ð ¢6öç7B7FGW5FöæRÒÆöF–æròvæWWG&Âr¢W'&÷"ÇÂ66äW'&÷"ÇÂf–æF–æw4W'&÷"òvFævW"r¢6ö×ÆWFVæW72çFöæS° ¢&WGW&â€¢ÄFöÖ–åvU6†VÆÀ¢FöÖ–ãÒ&v—F‡V" ¢W–V'&÷sÒ%&W÷6—F÷'’–çFVÆÆ–vVæ6R ¢†–FTÆövð¢F—FÆS×·&WVW7FVE&W÷6—F÷'—Ð¢FW67&—F–öãÒ%Væ–f–VB66â7FFRÂ÷7GW&Rv2Âf–æF–æw2VWVRÂ&Æ7B×&F—W2F‡2ÂæB&VÖVF–F–öâ7F–öç2f÷"öæR&W÷6—F÷'’â ¢66÷S×°¢Å&öGV7DVçf—&öæÖVçE6VÆV7F÷ ¢7FFS×¶Vçf—&öæÖVçE66÷WÐ¢öä6†ævS×¶öä6†ævTVçf—&öæÖVçGÐ¢óà¢Ð¢7FGW5FöæS×·7FGW5FöæWÐ¢&–Ö'”7F–öã×·²Æ&VÃ¢t&6²Fò&W÷6—F÷&–W2rÂFó¢&W÷6—F÷&–W5F‚Âf&–çC¢w6V6öæF'’r×Ð¢à¢¶W'&÷"ò€¢ÄFöÖ–äW'&÷%7FFP¢F—FÆSÒ$6÷VÆFâwBÆöB&W÷6—F÷'’–çFVÆÆ–vVæ6R ¢&öG“×¶W'&÷'Ð¢óà¢’¢çVÆÇÐ ¢¶ÆöF–ærbb66âbbf–æF–æw2æÆVæwF‚bb66äW'&÷"bbf–æF–æw4W'&÷"ò€¢òò6†÷rF†R÷WFW"ÆöF–ær6†VÆÂöæÇ’öâ6öÆB66†Rv†VâæV—F†W ¢òòÆæR†26öÖÖ—GFVBç—F†–ær–WBâ26ööâ2V—F†W"ÆæR6WGFÆW0¢òò‡7V66W72÷"W'&÷"’vR&VæFW"F†R–æF—f–GVÂæVÇ26ò¢òò7V66W76gVÂÆæR—2æ÷B†VÆB&V†–æBF†R÷F†W"w2–âÖfÆ–v‡B&WVW7Bà¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ær&W÷6—F÷'’–çFVÆÆ–vVæ6R"óà¢’¢€¢Ãà¢Ç6V7F–öà¢6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×66â ¢&–ÖÆ&VÃÒ$ÆFW7B66â ¢à¢Æ†VFW"6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂÖ†VB#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äÆFW7B66ãÂ÷à¢Æƒ3à¢·66äÆöF–æp¢òtÆöF–ærÆFW7B66î(
bp¢¢66äW'&÷ ¢òtÆFW7B66âVæf–Æ&ÆRp¢¢66à¢òf÷&ÖEFö¶VäÆ&VÂ‡66âç7FGW2¢¢66äÆöö·WG'Væ6FV@¢òu66â†—7F÷'’G'Væ6FVBp¢¢tæò66â–WBwÐ¢Âöƒ3à¢²66äÆöF–ærbb66äW'&÷"bb66âbb66äÆöö·WG'Væ6FVBò€¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'B×v&æ–ær#à¢&W÷6—F÷'’66â6V&6‚†—B—G26fWG’6V–Æ–ær&Vf÷&Rf–æF–ærÖF6‚âF†R&W÷6—F÷'’Ö’†fRâöÆFW"66â&V†–æBÖ÷&R&V6VçBv÷&·76R66ç3²÷VâF†R66ç2vRæBf–ÇFW"'’&W÷6—F÷'’Fò6öæf—&Òà¢Â÷à¢’¢çVÆÇÐ¢Âö†VFW#à¢·66äÆöF–ærò€¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ærÆFW7B66â"óà¢’¢66äW'&÷"ò€¢òò66âÆæRf–ÆVB–æFWVæFVçFÇ’âf–æF–æw2æB÷7GW&R7F–ÆÀ¢òò&VæFW"&VÆ÷rv—F‚F†V—"÷vâ7FFRÂ6òF†—2æVÂöæÇ¢òò&W÷'G2—G2÷vâW'&÷"à¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·66äW'&÷'ÓÂ÷à¢’¢€¢Ãà¢ÄFöÖ–å7FGW4&FvP¢f&–çC×°¢6ö×ÆWFVæW72çFöæRÓÓÒw7V66W72p¢òv6öææV7FVBp¢¢6ö×ÆWFVæW72çFöæRÓÓÒwv&æ–ærp¢òvFVw&FVBp¢¢6ö×ÆWFVæW72çFöæRÓÓÒvFævW"p¢òvÖ—76–ær×W&Ö—76–öç2p¢¢vF—66öææV7FVBp¢Ð¢Æ&VÃ×¶6ö×ÆWFVæW72æÆ&VÇÐ¢FWF–Ã×·66ãòæf–æ—6†VEöBòf÷&ÖDFFTÆ&VÂ‡66âæf–æ—6†VEöB’¢66ãòç7F'FVEöBòf÷&ÖDFFTÆ&VÂ‡66âç7F'FVEöB’¢VæFVf–æVGÐ¢óà¢·66âò€¢ÆFÂ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×7FG2#à¢ÆF—cãÆGCäf–æF–æw3ÂöGCãÆFCç·66âæf–æF–æuö6÷VçGÓÂöFCãÂöF—cà¢ÆF—cãÆGCäf–ÆW266ææVCÂöGCãÆFCç·66âæf–ÆW5÷66ææVGÓÂöFCãÂöF—cà¢ÆF—cãÆGCä6öÖÖ—G266ææVCÂöGCãÆFCç·66âæ6öÖÖ—G5÷66ææVGÓÂöFCãÂöF—cà¢·66âç66åöÖöFRòÆF—cãÆGCå66âÖöFSÂöGCãÆFCç¶f÷&ÖEFö¶VäÆ&VÂ‡66âç66åöÖöFR—ÓÂöFCãÂöF—câ¢çVÆÇÐ¢ÂöFÃà¢’¢çVÆÇÐ¢·66ãòç6÷W&6Uö†VÇF…öFWF–Ç2bb66âç6÷W&6Uö†VÇF…öFWF–Ç2æÆVæwF‚âò€¢ÇVÂ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×6÷W&6RÖ†VÇF‚"&–ÖÆ&VÃÒ%6÷W&6R†VÇF‚FWF–Ç2#à¢·66âç6÷W&6Uö†VÇF…öFWF–Ç2æÖ‚‡6÷W&6R’Óâ€¢ÆÆ’¶W“×·6÷W&6Rç6÷W&6WÓà¢Ç7G&öæsç¶f÷&ÖEFö¶VäÆ&VÂ‡6÷W&6Rç6÷W&6R—ÓÂ÷7G&öæsà¢Ç7â6Æ74æÖS×¶–GB×6÷W&6R×7FGW2×–ÆÂ—2ÒG·6÷W&6Rç7FGW2ÓÓÒv6ö×ÆWFRròw7V66W72r¢6÷W&6Rç7FGW2ÓÓÒw'F–ÂrÇÂ6÷W&6Rç7FGW2ÓÓÒwW&Ö—76–öåöÆ–Ö—FVBrÇÂ6÷W&6Rç7FGW2ÓÓÒw&FUöÆ–Ö—FVBròwv&æ–ærr¢væWWG&ÂwÖÓà¢¶f÷&ÖEFö¶VäÆ&VÂ‡6÷W&6Rç7FGW2—Ð¢Â÷7ãà¢·6÷W&6RæÖW76vRòÇ7ãç·6÷W&6RæÖW76vWÓÂ÷7ãâ¢çVÆÇÐ¢ÂöÆ“à¢’—Ð¢Â÷VÃà¢’¢çVÆÇÐ¢Âóà¢—Ð¢Â÷6V7F–öãà ¢Ç6V7F–öà¢6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×÷7GW&R ¢&–ÖÆ&VÃÒ%÷7GW&Rv2 ¢à¢Æ†VFW"6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂÖ†VB#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äv—D‡V"6öçG&öÂ×ÆæR÷7GW&SÂ÷à¢Æƒ3å÷7GW&Rv3Âöƒ3à¢Âö†VFW#à¢·÷7GW&TW'&÷"ò€¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·÷7GW&TW'&÷'ÓÂ÷à¢’¢÷7GW&TÆöF–ærò€¢òòF†R÷7GW&RVæGö–çBW&f÷&×2Æ—fRv—D‡V"6öÆÆV7F–öâ6ò—B6à¢òò&R6Æ÷vW"F†âF†R&W7BöbF†RG&–ÆÆF÷vã²&VæFW"—G2÷và¢òòÆöF–ær–æF–6F÷"6ò÷W&F÷'26VR&öw&W72†W&Rv—F†÷W@¢òòvF–ær66âöf–æF–æw2öw&‚&VæFW&–ærà¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ær&W÷6—F÷'’÷7GW&R"óà¢’¢÷7GW&RÇÂ÷&væ—¦F–öå÷7GW&Rò€¢–ç6V7W&U÷7GW&T6†V6·2æÆVæwF‚ÓÓÒò€¢ÄFöÖ–äV×G•7FFP¢F—FÆSÒ$æò÷7GW&Rv2 ¢&öG“Ò$WfW'’6öÆÆV7FVB&W÷6—F÷'’æB÷&væ—¦F–öâ÷7GW&R6†V6²&W÷'G26V7W&R÷"Vç7W÷'FVB7FFRâ ¢óà¢’¢€¢ÇVÂ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖÆ—7B#à¢¶–ç6V7W&U÷7GW&T6†V6·2æÖ‚‡²66÷S¢÷7GW&U66÷RÂ6†V6²Ò’Óâ€¢ÆÆ’¶W“×¶G·÷7GW&U66÷WÓ¢G¶6†V6²æ–GÖÒ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×&÷r–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×&÷rÖG&–ÆÆF÷vâ#à¢Ç7â6Æ74æÖS×¶–GB×6÷W&6R×7FGW2×–ÆÂ—2ÒG¶6†V6²ç7FFRÓÓÒv–ç6V7W&Rròwv&æ–ærr¢væWWG&ÂwÖÓà¢¶f÷&ÖEFö¶VäÆ&VÂ†6†V6²ç7FFR—Ð¢Â÷7ãà¢ÆF—cà¢Ç7G&öæsà¢·÷7GW&U66÷RÓÓÒv÷&væ—¦F–öâròt÷&væ—¦F–öâ(
"r¢rwÐ¢¶f÷&ÖEFö¶VäÆ&VÂ†6†V6²æ6FVv÷'’—Ó¢¶f÷&ÖEFö¶VäÆ&VÂ†6†V6²æ–B—Ð¢Â÷7G&öæsà¢Çç¶6†V6²ç7VÖÖ'—ÓÂ÷à¢¶6†V6²ç&V6öâò€¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#à¢&V6öã¢¶f÷&ÖEFö¶VäÆ&VÂ†6†V6²ç&V6öâ—Ð¢Â÷à¢’¢çVÆÇÐ¢ÂöF—cà¢ÂöÆ“à¢’—Ð¢Â÷VÃà¢¢’¢€¢ÄFöÖ–äV×G•7FFP¢F—FÆSÒ$æò÷7GW&R6öÆÆV7FVB ¢&öG“×¶FöÖ–äFFæ6öææV7F–öãòæ6öææV7FVBòu÷7GW&R—2æ÷Bf–Æ&ÆRf÷"F†—2&W÷6—F÷'’–WBâr¢t6öææV7Bv—D‡V"Fò6öÆÆV7B&W÷6—F÷'’÷7GW&RâwÐ¢óà¢—Ð¢Â÷6V7F–öãà ¢Ç6V7F–öà¢6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×VWVR ¢&–ÖÆ&VÃÒ%&–÷&—F—¦VBf–æF–æw2VWVR ¢à¢Æ†VFW"6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂÖ†VB#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#å&–÷&—F—¦VBVWVSÂ÷à¢Æƒ3äf–æF–æw2÷&FW&VB'’&Æ7B&F—W3Âöƒ3à¢²f–æF–æw4ÆöF–ærbbf–æF–æw4W'&÷"bbVWVRæÆVæwF‚âò€¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#à¢·VWVRæÆVæwF‡Òf–æF–æw·VWVRæÆVæwF‚ÓÓÒòrr¢w2wÐ¢¶f–æF–æw57VÖÖ'“òçF÷FÅö÷VâÒçVÆÂò(
"G¶f–æF–æw57VÖÖ'’çF÷FÅö÷VçÒ÷Væ¢rwÐ¢·V&Æ—6†&ÆT6÷VçBâò(
"G·V&Æ—6†&ÆT6÷VçGÒf—‚×&VG–¢rwÐ¢·&Wf–Wu&VG”6÷VçBâV&Æ—6†&ÆT6÷VçBò(
"G·&Wf–Wu&VG”6÷VçBÒV&Æ—6†&ÆT6÷VçGÒ&Wf–WrÖöæÇ–¢rwÐ¢Â÷à¢’¢çVÆÇÐ¢²f–æF–æw4ÆöF–ærbbf–æF–æw4W'&÷"bbf–æF–æw5G'Væ6FVBò€¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'B×v&æ–ær#à¢f–æF–æw2v–æF–öâ†—B—G26fWG’6V–Æ–ær&Vf÷&RÆÂvW2&WGW&æVBâ&Vf–æRf–ÇFW'2–âF†Rv—D‡V"f–æF–æw2vRFò&Wf–WrF†R&W7Bà¢Â÷à¢’¢çVÆÇÐ¢Âö†VFW#à¢¶f–æF–æw4ÆöF–ærò€¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ærf–æF–æw2"óà¢’¢f–æF–æw4W'&÷"ò€¢òòf–æF–æw2ÆæRf–ÆVB–æFWVæFVçFÇ’â66â7G&—Â÷7GW&RÂæ@¢òòw&‚7F–ÆÂ&VæFW"v—F‚F†V—"÷vâ7FFRà¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç¶f–æF–æw4W'&÷'ÓÂ÷à¢’¢VWVRæÆVæwF‚ÓÓÒò€¢ÄFöÖ–äV×G•7FFP¢F—FÆSÒ$æòf–æF–æw2f÷"F†—2&W÷6—F÷'’ ¢&öG“Ò$æV—F†W"÷7GW&RÂ’ôÔ5Âv÷&¶fÆ÷rÂæ÷"6V7&WBFWFV7F÷'2&W÷'FVBâ÷Vâf–æF–ærf÷"F†—2&W÷6—F÷'’â ¢óà¢’¢€¢ÇVÂ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖÆ—7B#à¢·VWVRæÖ‚‡²f–æF–ærÂ66÷&RÂ6FVv÷'’Ò’Óâ€¢ÆÆ’¶W“×¶f–æF–æræ–GÒ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×&÷r–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×&÷rÖG&–ÆÆF÷vâ"FFÖ6FVv÷'“×¶6FVv÷'—Óà¢Ç7â6Æ74æÖS×¶–GB×6÷W&6R×7FGW2×–ÆÂ—2ÒG¶f–æF–ærç6WfW&—G’ÓÓÒv7&—F–6ÂrÇÂf–æF–ærç6WfW&—G’ÓÓÒv†–v‚ròwv&æ–ærr¢væWWG&ÂwÖÓà¢¶f÷&ÖEFö¶VäÆ&VÂ†f–æF–ærç6WfW&—G’óòwVæ¶æ÷vâr—Ð¢Â÷7ãà¢ÆF—cà¢Ç7G&öæsç¶f–æF–ærçF—FÆRÇÂf–æF–æræFWFV7F÷"ÇÂf–æF–ærçG—WÓÂ÷7G&öæsà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#à¢µ$Uõô”åDTÄÄ”tTä4Uô4DTtõ%•ôÄ$TÅ5¶6FVv÷'•×Ð¢·66÷&Rò(
"66÷&RG·66÷&Rç66÷&WÖ¢rwÐ¢·66÷&SòçVæ¶æ÷vç3òæÆVæwF‚ò(
"Væ¶æ÷vã¢G·66÷&RçVæ¶æ÷vç2æ¦ö–â‚rÂr—Ö¢rwÐ¢Â÷à¢¶f–æF–æræ‡VÖå÷7VÖÖ'’òÇç¶f–æF–æræ‡VÖå÷7VÖÖ'—ÓÂ÷â¢çVÆÇÐ¢ÂöF—cà¢¶—5&VÖVF–F–öå7W÷'FVDf–æF–ær†f–æF–ær’ò€¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ×6V6öæF'’Ö'WGFöâ ¢öä6Æ–6³×²‚’Óâ÷Vå&Wf–Wr†f–æF–ær—Ð¢F—6&ÆVC×·&Wf–WtÆöF–ærbb&Wf–Wtf–æF–æt”BÓÓÒf–æF–æræ–GÐ¢à¢·&Wf–WtÆöF–ærbb&Wf–Wtf–æF–æt”BÓÓÒf–æF–æræ–BòtÆöF–æ~(
br¢u&Wf–Wr&VÖVF–F–öâwÐ¢Âö'WGFöãà¢’¢€¢òòf–æF–æw2v†÷6RFWFV7F÷"—2æ÷B–âF†R7VvvW7E&WôW‡÷7W&U&VÖVF–F–öà¢òò7W÷'FVB6WB†æ÷F&Ç’v—D‡V"÷7GW&Rf–æF–æw2’v÷VÆBC#"öâ&Wf–Wrà¢òò6†÷r÷W&F÷"Ö7F–öæ&ÆRwV–Fæ6R–ç7FVBöbâ7F–öâ'WGFöâF†@¢òòv÷VÆBf–Âà¢Ç7â6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#å&Wf–Wr–âv—D‡V#Â÷7ãà¢—Ð¢ÂöÆ“à¢’—Ð¢Â÷VÃà¢—Ð¢Â÷6V7F–öãà ¢·F÷F‡2æÆVæwF‚âÇÂ&—6´w&„ÆöF–ærÇÂ&—6´w&„W'&÷"ò€¢Ç6V7F–öà¢6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×F‡2 ¢&–ÖÆ&VÃÒ%F÷&Æ7B×&F—W2F‡2 ¢à¢Æ†VFW"6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂÖ†VB#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#å&—6²w&ƒÂ÷à¢Æƒ3åF÷&Æ7B×&F—W2F‡3Âöƒ3à¢Âö†VFW#à¢·&—6´w&„ÆöF–ærò€¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ær&W÷6—F÷'’&—6²w&‚"óà¢’¢&—6´w&„W'&÷"ò€¢òò&—6²w&‚—2÷F–öæÂVç&–6†ÖVçC¢F†RVWVR&÷fR7F–ÆÀ¢òò&VæFW'26÷'FVB'’6WfW&—G’v†VâF†Rw&‚—2Væf–Æ&ÆRà¢òò7W&f6RF†Rw&‚W'&÷"–æÆ–æR6ò÷W&F÷'2¶æ÷rF†RF÷ ¢òòF‡2æVÂ—2FVw&FVBÂæ÷B6–ÆVçFÇ’†–F–ærFFà¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'B×v&æ–ær#à¢·&—6´w&„W'&÷'Ð¢Â÷à¢’¢€¢ÆöÂ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖÆ—7B#à¢·F÷F‡2æÖ‚‡²66÷&RÂF—FÆRÂ6†–âÒ’Óâ€¢ÆÆ’¶W“×·66÷&Ræf–æF–æuöæöFUö–BÇÂ66÷&Ræf–æF–æuö–GÒ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×&÷r–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×&÷rÖG&–ÆÆF÷vâ#à¢Ç7â6Æ74æÖSÒ&–GB×6÷W&6R×7FGW2×–ÆÂ—2×v&æ–ær#ç66÷&R·66÷&Rç66÷&WÓÂ÷7ãà¢ÆF—cà¢Ç7G&öæsç·F—FÆWÓÂ÷7G&öæsà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#à¢6WfW&—G’·66÷&Rç6WfW&—G—Ò(
"6öæf–FVæ6R²‡66÷&Ræ6öæf–FVæ6R¢’çFôf—†VBƒ—ÒP¢·66÷&Ræf7F÷'2ç÷7GW&Uö×Æ–f–W"ò(
"÷7GW&R×Æ–f–W"G·66÷&Ræf7F÷'2ç÷7GW&Uö×Æ–f–W'Ö¢rwÐ¢Â÷à¢¶6†–âæÆVæwF‚âò€¢òò&VæFW"F†RæöFR6†–âF†Rf–æF–ær&V6†W2F‡&÷Vv€¢òòF†Rw&‚â%Væ¶æ÷vâ"VFvW2&Rf—7VÆÇ’Ö&¶V@¢òò†F6†VB'&÷r’6òF†R÷W&F÷"6âFVÆÂ6öæ7&WFP¢òò&V6†&–Æ—G’F‚g&öÒ7V7VÆF—fRöæRà¢Ç6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ&Æ7B×&F—W2"&–ÖÆ&VÃ×¶&Æ7B&F—W3¢G¶6†–âæÖ‚††÷’Óâ†÷æÆ&VÂ’æ¦ö–â‚rÓâr—ÖÓà¢¶6†–âæÖ‚††÷Â–æFW‚’Óâ€¢Ç7â¶W“×¶†÷ææöFUö–GÒ6Æ74æÖS×¶–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ&Æ7B×&F—W2Ö†÷—2ÒG¶†÷æWf–FVæ6U÷7FFWÖÓà¢Ç7â&–Ö†–FFVãÒ'G'VR#ç¶–æFW‚ÓÓÒò~(i"r¢†÷æWf–FVæ6U÷7FFRÓÓÒwVæ¶æ÷vâròr(z"r¢r(i"wÓÂ÷7ãà¢Ç7â6Æ74æÖS×¶–GB×6÷W&6R×7FGW2×–ÆÂ—2ÖæWWG&ÆÓç¶f÷&ÖEFö¶VäÆ&VÂ††÷æ¶–æB—ÓÂ÷7ãà¢Ç7ãâ¶†÷æÆ&VÇÓÂ÷7ãà¢Â÷7ãà¢’—Ð¢Â÷à¢’¢€¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#à¢æò&V6†&–Æ—G’w&‚6öÆÆV7FVBf÷"F†—2f–æF–ærà¢Â÷à¢—Ð¢ÂöF—cà¢ÂöÆ“à¢’—Ð¢ÂööÃà¢—Ð¢Â÷6V7F–öãà¢’¢çVÆÇÐ ¢·&Wf–Wtf–æF–æt”Bò€¢Ç6V7F–öà¢6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×&Wf–Wr ¢&–ÖÆ&VÃÒ%&VÖVF–F–öâ&Wf–Wr ¢&öÆSÒ'&Vv–öâ ¢à¢Æ†VFW"6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂÖ†VB#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#å&VÖVF–F–öâ&Wf–WsÂ÷à¢Æƒ3äf–æF–ær·&Wf–Wtf–æF–æt”GÓÂöƒ3à¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ×FW'F–'’Ö'WGFöâ ¢öä6Æ–6³×¶6Æ÷6U&Wf–WwÐ¢à¢6Æ÷6P¢Âö'WGFöãà¢Âö†VFW#à¢·&Wf–WtÆöF–æròÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ær&VÖVF–F–öâ&Wf–Wr"óâ¢çVÆÇÐ¢·&Wf–WtW'&÷"ò€¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·&Wf–WtW'&÷'ÓÂ÷à¢’¢çVÆÇÐ¢·&Wf–Wrò€¢ÆF—cà¢ÇãÇ7G&öæsç·&Wf–Wrç&VÖVF–F–öâç7VÖÖ'—ÓÂ÷7G&öæsãÂ÷à¢·&Wf–Wrç&VÖVF–F–öâç&—6µ÷7VÖÖ'’òÇç·&Wf–Wrç&VÖVF–F–öâç&—6µ÷7VÖÖ'—ÓÂ÷â¢çVÆÇÐ¢·&Wf–Wrç&VÖVF–F–öâçV&Æ—6…ö&Æö6¶VE÷&V6öâò€¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#à¢V&Æ—6‚&Æö6¶VC¢·&Wf–Wrç&VÖVF–F–öâçV&Æ—6…ö&Æö6¶VE÷&V6öçÐ¢Â÷à¢’¢çVÆÇÐ¢·&Wf–Wrç&VÖVF–F–öâç7FW2æÆVæwF‚âò€¢ÆöÃà¢·&Wf–Wrç&VÖVF–F–öâç7FW2æÖ‚‡7FWÂ–æFW‚’Óâ€¢ÆÆ’¶W“×¶–æFW‡Óç·7FWÓÂöÆ“à¢’—Ð¢ÂööÃà¢’¢çVÆÇÐ¢ÂöF—cà¢’¢çVÆÇÐ¢Â÷6V7F–öãà¢’¢çVÆÇÐ¢Âóà¢—Ð¢ÂôFöÖ–åvU6†VÆÃà¢“°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7Dv—D‡V$7F–öç5vR‚’°¢6öç7B²66÷RÂVçf—&öæÖVçE66÷RÂ6VÆV7FVDVçf—&öæÖVçD”BÂöä6†ævTVçf—&öæÖVçBÒÒW6Tv—D‡V$FöÖ–å66÷R‚“°¢6öç7Bf–Æ&–Æ—G’ÒW6Tv—D‡V$f–Æ&–Æ—G’‚“° ¢–b‚66÷R’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷""&öÆSÒ&ÆW'B#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äv—D‡V"7F–öç2òô”D3Â÷à¢Æƒ#åv÷&·76R&÷WFR6öçFW‡B—2Ö—76–æsÂöƒ#à¢Çä6†ö÷6RFVæçBæBv÷&·76R&Vf÷&RÆöF–ærv—D‡V"7F–öç2òô”D2ãÂ÷à¢Â÷6V7F–öãà¢“°¢Ð ¢–b†f–Æ&–Æ—G’æÆöF–ær’°¢&WGW&â€¢ÄFöÖ–åvU6†VÆÀ¢FöÖ–ãÒ&v—F‡V" ¢W–V'&÷sÒ%v÷&¶fÆ÷rG'W7B ¢F—FÆSÒ$v—D‡V"7F–öç2òô”D2 ¢FW67&—F–öãÒ$ÆöF–ærv—D‡V"f–Æ&–Æ—G’f÷"F†—2'V–ÆBâ ¢66÷S×³Å&öGV7DVçf—&öæÖVçE6VÆV7F÷"7FFS×¶Vçf—&öæÖVçE66÷WÒöä6†ævS×¶öä6†ævTVçf—&öæÖVçGÒóçÐ¢à¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ærv—D‡V"f–Æ&–Æ—G’"óà¢ÂôFöÖ–åvU6†VÆÃà¢“°¢Ð ¢–b‚f–Æ&–Æ—G’æf–Æ&ÆR’°¢&WGW&â€¢Äv—D‡V%Væf–Æ&ÆU6†VÆÀ¢F—FÆSÒ$v—D‡V"7F–öç2òô”D2 ¢66÷S×·66÷WÐ¢Vçf—&öæÖVçE66÷S×¶Vçf—&öæÖVçE66÷WÐ¢6VÆV7FVDVçf—&öæÖVçD”C×·6VÆV7FVDVçf—&öæÖVçD”GÐ¢öäVçf—&öæÖVçD6†ævS×¶öä6†ævTVçf—&öæÖVçGÐ¢Væf–Æ&ÆTÖW76vS×¶f–Æ&–Æ—G’çVæf–Æ&ÆTÖW76vWÐ¢óà¢“°¢Ð ¢6öç7B&6UF‚ÒVæDVçf—&öæÖVçEVW'’†'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"r’Â6VÆV7FVDVçf—&öæÖVçD”B“°¢6öç7B6öææV7EF‚ÒVæDVçf—&öæÖVçEVW'’†'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"ö6öææV7Br’Â6VÆV7FVDVçf—&öæÖVçD”B“°¢6öç7B&W÷6—F÷&–W5F‚ÒVæDVçf—&öæÖVçEVW'’†'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"÷&W÷6—F÷&–W2r’Â6VÆV7FVDVçf—&öæÖVçD”B“°¢6öç7Bf–æF–æw5F‚ÒVæDVçf—&öæÖVçEVW'’†'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"öf–æF–æw2r’Â6VÆV7FVDVçf—&öæÖVçD”B“° ¢6öç7B7W&f6W2Ò°¢°¢–C¢wv÷&¶fÆ÷w2rÀ¢F—FÆS¢uv÷&¶fÆ÷r–çfVçF÷'’rÀ¢&öG“¢uG&6²v†–6‚&W÷6—F÷&–W2'Vâv—D‡V"7F–öç2Âv†BG&–vvW'2F†VÒÂæBv†–6‚v÷&¶fÆ÷w26†—6V7&WG2Fò'VææW'2âp¢ÒÀ¢°¢–C¢wW&Ö—76–öç2rÀ¢F—FÆS¢t7F–öç2W&Ö—76–öç2rÀ¢&öG“¢u7W&f6R&W÷6—F÷&–W2F†BÆÆ÷rw&—FRv÷&¶fÆ÷rFö¶Vç2Â'&öBt•D…T%õDô´Tâ66÷W2Â÷"Vç&W7G&–7FVB7F–öâ6÷W&6W2âp¢ÒÀ¢°¢–C¢vö–F2rÀ¢F—FÆS¢tô”D2G'W7BF‡2rÀ¢&öG“¢tÖu2Ât5ÂæB§W&R&öÆW2F†BG'W7Bv—D‡V"7F–öç2ô”D26Æ–×2Â–æ6ÇVF–ær'&æ6‚æBVçf—&öæÖVçB66÷–ærâp¢ÒÀ¢°¢–C¢w'VææW'2rÀ¢F—FÆS¢u'VææW"÷7GW&RrÀ¢&öG“¢t–çfVçF÷'’6VÆbÖ†÷7FVB'VææW'2ÂÆ&VÂ66÷–ærÂæBW†VÖW&Æ—G’÷7GW&R6ò&—6·’&WW6R—2V7’Fò7÷Bâp¢Ð¢Ó° ¢&WGW&â€¢ÄFöÖ–åvU6†VÆÀ¢FöÖ–ãÒ&v—F‡V" ¢W–V'&÷sÒ%v÷&¶fÆ÷rG'W7B ¢F—FÆSÒ$v—D‡V"7F–öç2òô”D2 ¢FW67&—F–öãÒ%v÷&¶fÆ÷rW&Ö—76–öç2Âô”D2G'W7BF‡2Â7F–öç2'VææW'2ÂæBWFöÖF–öâ–FVçF—G’÷7GW&Rf÷"v—D‡V"â ¢66÷S×³Å&öGV7DVçf—&öæÖVçE6VÆV7F÷"7FFS×¶Vçf—&öæÖVçE66÷WÒöä6†ævS×¶öä6†ævTVçf—&öæÖVçGÒóçÐ¢7FGW3×³ÄFöÖ–å7FGW4&FvRf&–çCÒ&6öÖ–ær×6ööâ"Æ&VÃÒ$6÷fW&vR–æ6öÖ–ær"óçÐ¢7FGW5FöæSÒ&æWWG&Â ¢&–Ö'”7F–öã×·²Æ&VÃ¢t6öææV7Bv—D‡V"rÂFó¢6öææV7EF‚Âf&–çC¢w&–Ö'’r×Ð¢6V6öæF'”7F–öç3×µ°¢²Æ&VÃ¢t÷Vâ&W÷6—F÷&–W2rÂFó¢&W÷6—F÷&–W5F‚ÒÀ¢²Æ&VÃ¢tv—D‡V"f–æF–æw2rÂFó¢f–æF–æw5F‚ÒÀ¢²Æ&VÃ¢tv—D‡V"†öÖRrÂFó¢&6UF‚Ð¢×Ð¢6–FS×°¢ÄFöÖ–äFWF–ÅæVÂF—FÆSÒ%v‡’F†—2vRW†—7G2"W–V'&÷sÒ$FöÖ–â6†'FW"#à¢Çà¢v—D‡V"7F–öç2÷vâF†RÖ÷7B÷vW&gVÂ4’–FVçF—F–W2–âÖç’Vçf—&öæÖVçG2â–FVçG&–Âv–ÆÂG&6²v÷&¶fÆ÷rFö¶Vç2À¢ô”D2G'W7BÂæB'VææW"÷7GW&R†W&R6ò6V7W&—G’FV×26â&V6öâ&÷WBF†VÒ2f—'7BÖ6Æ72Ö6†–æR–FVçF—F–W2à¢Â÷à¢ÂôFöÖ–äFWF–ÅæVÃà¢Ð¢à¢ÄFöÖ–å7FGW5æVÀ¢W–V'&÷sÒ$6÷fW&vR7FGW2 ¢F—FÆSÒ%v÷&¶fÆ÷ræBô”D2÷7GW&R—2&öÆÆ–ær÷WB ¢7FGW3×³ÄFöÖ–å7FGW4&FvRf&–çCÒ&6öÖ–ær×6ööâ"Æ&VÃÒ%&VÖ—VÒ&Wf–Wr"óçÐ¢FöæSÒ&–æfò ¢à¢Çà¢F†R–FVçG&–Âv—D‡V"6öÆÆV7F÷"Ç&VG’–ævW7G2v÷&¶fÆ÷ræBô”D26–væÂâF†RG&–vRT’7W&f6W2(	Bv÷&¶fÆ÷p¢–çfVçF÷'’ÂW&Ö—76–öâ÷7GW&RÂô”D2G'W7BæÇ—6—2ÂæB'VææW"–çfVçF÷'’(	BÆæB†W&R2F†W’6†—6òF†—2vP¢7F—2F†R6–ævÆR†öÖRf÷"7F–öç2æBWFöÖF–öâ–FVçF—G’–âv—D‡V"à¢Â÷à¢ÂôFöÖ–å7FGW5æVÃà¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖFöÖ–â×7FGW2×æVÂ"&–ÖÆ&VÃÒ%7W&f6W2ÆææVB†W&R#à¢Æ†VFW#à¢ÆF—cà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#å7W&f6W2–âF†—2vSÂ÷à¢Æƒ3åv†BÆæG2öâ7F–öç2òô”D3Âöƒ3à¢ÂöF—cà¢Ç7ããB7W&f6W3Â÷7ãà¢Âö†VFW#à¢ÆF—b6Æ74æÖSÒ&–GBÖFöÖ–â×&VF–æW72Ö—FV×2#à¢·7W&f6W2æÖ‚‡7W&f6R’Óâ€¢Æ'F–6ÆR¶W“×·7W&f6Ræ–GÓà¢ÆF—cà¢Ç7G&öæsç·7W&f6RçF—FÆWÓÂ÷7G&öæsà¢Çç·7W&f6Ræ&öG—ÓÂ÷à¢ÂöF—cà¢Ç7ãåÆææVCÂ÷7ãà¢Âö'F–6ÆSà¢’—Ð¢ÂöF—cà¢Â÷6V7F–öãà¢ÂôFöÖ–åvU6†VÆÃà¢“°§Ð ¦gVæ7F–öâ—4v—D‡V%&VÖVF–F–öä6æF–FFR†f–æF–æs¢”f–æF–ær“¢&ööÆVâ°¢6öç7BÆ–fV7–6ÆRÒæ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2“°¢&WGW&âÆ–fV7–6ÆRÓÓÒv÷VârÇÂÆ–fV7–6ÆRÓÓÒw&V÷VæVBs°§Ð ¦gVæ7F–öâv—D‡V%&VÖVF–F–öå&VF–æW72€¢f–æF–æs¢”f–æF–ærÀ¢&Wf–Ws¢&Wôf–æF–æu&VÖVF–F–öå&Wf–WrÂçVÆÀ¢“¢²Æ&VÃ¢7G&–æs²FöæS¢w7V66W72rÂwv&æ–ærrÂvFævW"rÂvæWWG&ÂrÒ°¢–b‡&Wf–Wr’°¢–b‡&Wf–Wrç&VÖVF–F–öâçV&Æ—6†&ÆR’°¢&WGW&â²Æ&VÃ¢uV&Æ—6‚×&VG’rÂFöæS¢w7V66W72rÓ°¢Ð¢&WGW&â²Æ&VÃ¢tÖçVÂ&VÖVF–F–öârÂFöæS¢wv&æ–ærrÓ°¢Ð ¢6öç7BÆ–fV7–6ÆRÒæ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2“°¢–b†Æ–fV7–6ÆRÓÓÒvf—†VBr’°¢&WGW&â²Æ&VÃ¢tf—†VBrÂFöæS¢w7V66W72rÓ°¢Ð¢–b†Æ–fV7–6ÆRÓÓÒw7W&W76VBrÇÂÆ–fV7–6ÆRÓÓÒw&—6µö66WFVBrÇÂÆ–fV7–6ÆRÓÓÒvfÇ6U÷÷6—F—fRr’°¢&WGW&â²Æ&VÃ¢uG&–vRÖ†VÆBrÂFöæS¢væWWG&ÂrÓ°¢Ð¢–b‚æ÷&ÖÆ—¦UfÇVR†f–æF–ærç6÷W&6U÷W&Âóòrr’’°¢&WGW&â²Æ&VÃ¢tæVVG2v—D‡V"Æ–æ²rÂFöæS¢wv&æ–ærrÓ°¢Ð¢–b‚æ÷&ÖÆ—¦UfÇVR†f–æF–æræf–ÆU÷F‚óòrr’bbæ÷&ÖÆ—¦UfÇVR†f–æF–æræWf–FVæ6Sòæf–ÆU÷F‚óòrr’’°¢&WGW&â²Æ&VÃ¢tæVVG2f–ÆRWf–FVæ6RrÂFöæS¢wv&æ–ærrÓ°¢Ð¢&WGW&â²Æ&VÃ¢u&Wf–Wr&VG’rÂFöæS¢væWWG&ÂrÓ°§Ð ¦gVæ7F–öâ6÷'Dv—D‡V%&VÖVF–F–öåVWVR†f–æF–æw3¢”f–æF–æuµÒ“¢”f–æF–æuµÒ°¢&WGW&â²ââæf–æF–æw5Òç6÷'B‚†ÆVgBÂ&–v‡B’Óâ°¢6öç7BÆVgD6æF–FFRÒ—4v—D‡V%&VÖVF–F–öä6æF–FFR†ÆVgB’ò¢°¢6öç7B&–v‡D6æF–FFRÒ—4v—D‡V%&VÖVF–F–öä6æF–FFR‡&–v‡B’ò¢°¢–b‡&–v‡D6æF–FFRÓÒÆVgD6æF–FFR’°¢&WGW&â&–v‡D6æF–FFRÒÆVgD6æF–FFS°¢Ð¢6öç7B6WfW&—G”FVÇFÒ6WfW&—G•&æ²‡&–v‡Bç6WfW&—G’’Ò6WfW&—G•&æ²†ÆVgBç6WfW&—G’“°¢–b‡6WfW&—G”FVÇFÓÒ’°¢&WGW&â6WfW&—G”FVÇF°¢Ð¢&WGW&âæWrFFR‡&–v‡Bæ7&VFVEöB’ævWEF–ÖR‚’ÒæWrFFR†ÆVgBæ7&VFVEöB’ævWEF–ÖR‚“°¢Ò“°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7Dv—D‡V%&VÖVF–F–öåvR‚’°¢6öç7B²66÷RÂVçf—&öæÖVçE66÷RÂ6VÆV7FVDVçf—&öæÖVçD”BÂöä6†ævTVçf—&öæÖVçBÒÒW6Tv—D‡V$FöÖ–å66÷R‚“°¢6öç7Bf–Æ&–Æ—G’ÒW6Tv—D‡V$f–Æ&–Æ—G’‚“°¢6öç7BFFÒW6Tv—D‡V$FöÖ–äFF€¢66÷RÀ¢6VÆV7FVDVçf—&öæÖVçD”BÀ¢f–Æ&–Æ—G’æf–Æ&ÆRÀ¢ ¢“°¢6öç7B¶ÆöF–ærÂ6WDÆöF–æuÒÒW6U7FFR‡G'VR“°¢6öç7B·&Vg&W6†–ærÂ6WE&Vg&W6†–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶W'&÷"Â6WDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&Wõ66ç2Â6WE&Wõ66ç5ÒÒW6U7FFSÅ&Wõ66å&V6÷&EµÓâ…µÒ“°¢6öç7B·&Wôf–æF–æw2Â6WE&Wôf–æF–æw5ÒÒW6U7FFSÄ”f–æF–æuµÓâ…µÒ“°¢6öç7B·&Wôf–æF–æu7VÖÖ'’Â6WE&Wôf–æF–æu7VÖÖ'•ÒÒW6U7FFSÅ&Wôf–æF–æw57VÖÖ'’ÂçVÆÃâ†çVÆÂ“°¢6öç7B·6VÆV7FVDf–æF–æt¶W’Â6WE6VÆV7FVDf–æF–æt¶W•ÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öå&Wf–WrÂ6WE&VÖVF–F–öå&Wf–WuÒÒW6U7FFSÅ&Wôf–æF–æu&VÖVF–F–öå&Wf–WrÂçVÆÃâ†çVÆÂ“°¢6öç7B·&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’Â6WE&VÖVF–F–öå&Wf–Wtf–æF–æt¶W•ÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öå&Wf–WtÆöF–ærÂ6WE&VÖVF–F–öå&Wf–WtÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·&VÖVF–F–öå&Wf–WtW'&÷"Â6WE&VÖVF–F–öå&Wf–WtW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçBÂ6WE&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçEÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öåV&Æ—6„&6T'&æ6‚Â6WE&VÖVF–F–öåV&Æ—6„&6T'&æ6…ÒÒW6U7FFR‚vÖ–âr“°¢6öç7B·&VÖVF–F–öåV&Æ—6…Fö¶VâÂ6WE&VÖVF–F–öåV&Æ—6…Fö¶VåÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öåV&Æ—6„&÷fVBÂ6WE&VÖVF–F–öåV&Æ—6„&÷fVEÒÒW6U7FFR†fÇ6R“°¢6öç7B·&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVBÂ6WE&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVEÒÒW6U7FFR†fÇ6R“°¢6öç7B·&VÖVF–F–öåV&Æ—6„ÆöF–ærÂ6WE&VÖVF–F–öåV&Æ—6„ÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·&VÖVF–F–öåV&Æ—6„W'&÷"Â6WE&VÖVF–F–öåV&Æ—6„W'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öåV&Æ—6…&W7VÇBÂ6WE&VÖVF–F–öåV&Æ—6…&W7VÇEÒÐ¢W6U7FFSÅ&Wôf–æF–æu&VÖVF–F–öåV&Æ—6…&W7öç6RÂçVÆÃâ†çVÆÂ“° ¢6öç7B&WVW7E&VbÒW6U&Vbƒ“°¢6öç7B&VÖVF–F–öå&Wf–Wu&WVW7E&VbÒW6U&Vbƒ“°¢6öç7B&VÖVF–F–öåV&Æ—6…&WVW7E&VbÒW6U&Vbƒ“° ¢6öç7B&Wõ66ç4'””BÒW6TÖVÖò€¢‚’Óà¢&Wõ66ç2ç&VGV6SÅ&V6÷&CÇ7G&–ærÂ&Wõ66å&V6÷&Cãâ‚†62Â66â’Óâ°¢65·66âæ–EÒÒ66ã°¢&WGW&â63°¢ÒÂ·Ò’À¢·&Wõ66ç5Ð¢“° ¢6öç7B&VÖVF–F–öåVWVRÒW6TÖVÖò‚‚’Óâ6÷'Dv—D‡V%&VÖVF–F–öåVWVR‡&Wôf–æF–æw2’Â·&Wôf–æF–æw5Ò“°¢6öç7B7F–öæ&ÆTf–æF–æw2ÒW6TÖVÖò€¢‚’Óâ&VÖVF–F–öåVWVRæf–ÇFW"‚†f–æF–ær’Óâ—4v—D‡V%&VÖVF–F–öä6æF–FFR†f–æF–ær’’À¢·&VÖVF–F–öåVWVUÐ¢“°¢6öç7B6VÆV7FVDf–æF–ærÒW6TÖVÖò€¢‚’Óâf–æE&Wôf–æF–æt'•6VÆV7F–öä¶W’‡&VÖVF–F–öåVWVRÂ6VÆV7FVDf–æF–æt¶W’’À¢·&VÖVF–F–öåVWVRÂ6VÆV7FVDf–æF–æt¶W•Ð¢“°¢6öç7B6VÆV7FVDf–æF–æu&Wf–Wt¶W’Ò6VÆV7FVDf–æF–ærò'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’‡6VÆV7FVDf–æF–ær’¢rs°¢6öç7B7F—fU&VÖVF–F–öå&Wf–WrÐ¢&VÖVF–F–öå&Wf–Wrbb&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’ÓÓÒ6VÆV7FVDf–æF–æu&Wf–Wt¶W’ò&VÖVF–F–öå&Wf–Wr¢çVÆÃ°¢6öç7B&W÷6—F÷'”6÷VçBÒW6TÖVÖò‚‚’Óâ°¢6öç7B&W÷6—F÷&–W2Ò&Wôf–æF–æw0¢æÖ‚†f–æF–ær’Óâ6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡&Wôf–æF–æu&W÷6—F÷'•fÇVR†f–æF–ærÂ&Wõ66ç4'””B’’¢æf–ÇFW"„&ööÆVâ“°¢&WGW&âVæ—VTv—D‡V%&W÷6—F÷&–W2‡&W÷6—F÷&–W2’æÆVæwFƒ°¢ÒÂ·&Wôf–æF–æw2Â&Wõ66ç4'””EÒ“°¢6öç7B†–v…&–÷&—G”6÷VçBÒ7F–öæ&ÆTf–æF–æw2æf–ÇFW"‚†f–æF–ær’Óâ°¢6öç7B6WfW&—G’Òæ÷&ÖÆ—¦UfÇVR†f–æF–ærç6WfW&—G’’çFôÆ÷vW$66R‚“°¢&WGW&â6WfW&—G’ÓÓÒv7&—F–6ÂrÇÂ6WfW&—G’ÓÓÒv†–v‚s°¢Ò’æÆVæwFƒ°¢6öç7BV&Æ—6†&ÆU&Wf–Wt6÷VçBÒ7F—fU&VÖVF–F–öå&Wf–Wsòç&VÖVF–F–öâçV&Æ—6†&ÆRò¢°¢6öç7BVWVU6VÆV7F–öä¶W—2Ò&VÖVF–F–öåVWVRæÖ‚†f–æF–ær’Óâ'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’†f–æF–ær’’æ¦ö–â‚wÂr“° ¢6öç7B&W6WE&VÖVF–F–öåV&Æ—6…7FFRÒ‚’Óâ°¢6WE&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçB‚rr“°¢6WE&VÖVF–F–öåV&Æ—6„&6T'&æ6‚‚vÖ–âr“°¢6WE&VÖVF–F–öåV&Æ—6…Fö¶Vâ‚rr“°¢6WE&VÖVF–F–öåV&Æ—6„&÷fVB†fÇ6R“°¢6WE&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVB†fÇ6R“°¢6WE&VÖVF–F–öåV&Æ—6„ÆöF–ær†fÇ6R“°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚rr“°¢6WE&VÖVF–F–öåV&Æ—6…&W7VÇB†çVÆÂ“°¢Ó° ¢6öç7B6VÆV7E&VÖVF–F–öäf–æF–ærÒ†f–æF–æs¢”f–æF–ærÂçVÆÂ’Óâ°¢&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB³Ò°¢&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçB³Ò°¢6WE6VÆV7FVDf–æF–æt¶W’†f–æF–ærò'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’†f–æF–ær’¢rr“°¢Ó° ¢6öç7BÆöE&VÖVF–F–öäFFÒ7–æ2‡F&vWE66÷S¢&öGV7E6W76–öâÂÖöFS¢v–æ—F–ÂrÂw&Vg&W6‚r’Óâ°¢6öç7B&WVW7D”BÒ²·&WVW7E&Vbæ7W'&VçC°¢–b†ÖöFRÓÓÒv–æ—F–Âr’°¢6WDÆöF–ær‡G'VR“°¢ÒVÇ6R°¢6WE&Vg&W6†–ær‡G'VR“°¢Ð¢6WDW'&÷"‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡F&vWE66÷R“°¢6öç7B·&Wõ66å&W7öç6RÂ&Wôf–æF–æu&W7öç6UÒÒv—B&öÖ—6RæÆÂ…°¢”6Æ–VçBæÆ—7E&Wõ66ç2‡²Æ–Ö—C¢SÒÂWF‚’À¢”6Æ–VçBæÆ—7E&Wôf–æF–æw2€¢°¢Æ–Ö—C¢t•D…T%õ$TÔTD”D”ôåôd”äD”äu5ôÄ”Ô•BÀ¢6÷'Eö'“¢w6WfW&—G’rÀ¢6÷'Eö÷&FW#¢vFW62p¢ÒÀ¢WF€¢¢Ò“°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE&Wõ66ç2‡&Wõ66å&W7öç6Ræ—FV×2“°¢6WE&Wôf–æF–æw2‡&Wôf–æF–æu&W7öç6Ræ—FV×2“°¢6WE&Wôf–æF–æu7VÖÖ'’‡&Wôf–æF–æu&W7öç6Rç7VÖÖ'’óòçVÆÂ“°¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WDW'&÷"†f÷&ÖD”W'&÷"‡&WVW7DW'&÷"Âtf–ÆVBFòÆöBv—D‡V"&VÖVF–F–öâVWVRâr’“°¢6WE&Wõ66ç2…µÒ“°¢6WE&Wôf–æF–æw2…µÒ“°¢6WE&Wôf–æF–æu7VÖÖ'’†çVÆÂ“°¢Òf–æÆÇ’°¢–b‡&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçB’°¢6WDÆöF–ær†fÇ6R“°¢6WE&Vg&W6†–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢6öç7B†æFÆU&Vg&W6‚Ò‚’Óâ°¢–b‚66÷R’°¢&WGW&ã°¢Ð¢FFç&VÆöB‚“°¢fö–BÆöE&VÖVF–F–öäFF‡66÷RÂw&Vg&W6‚r“°¢Ó° ¢6öç7B†æFÆTÆöE&VÖVF–F–öå&Wf–WrÒ7–æ2‚’Óâ°¢–b‚66÷RÇÂ6VÆV7FVDf–æF–ærÇÂ&VÖVF–F–öå&Wf–WtÆöF–ær’°¢&WGW&ã°¢Ð ¢6öç7B6VÆV7F–öä¶W’Ò'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’‡6VÆV7FVDf–æF–ær“°¢6öç7B&WVW7D”BÒ²·&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçC°¢6WE&VÖVF–F–öå&Wf–WtÆöF–ær‡G'VR“°¢6WE&VÖVF–F–öå&Wf–WtW'&÷"‚rr“°¢6WE&VÖVF–F–öå&Wf–Wr†çVÆÂ“°¢6WE&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’‡6VÆV7F–öä¶W’“°¢6WE&VÖVF–F–öåV&Æ—6…&W7VÇB†çVÆÂ“°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚rr“°¢G'’°¢6öç7B6÷W&6T6öçFVçBÒ&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçBçG&–Ò‚“°¢6öç7B&Wf–Wu&WVW7BÒ°¢&Wõ÷66åö–C¢6VÆV7FVDf–æF–ærç66åö–BÀ¢f–æF–æu÷W&Ã¢6VÆV7FVDf–æF–ærç6÷W&6U÷W&ÂÇÂVæFVf–æVBÀ¢âââ‡6÷W&6T6öçFVç@¢ò°¢6÷W&6Uö6öçFVçC¢6÷W&6T6öçFVçBÀ¢&WV—&Uöf—…÷Æã¢G'VP¢Ð¢¢·Ò¢Ó°¢6öç7B&Wf–WrÒv—B”6Æ–VçBç&Wf–Wu&Wôf–æF–æu&VÖVF–F–öâ€¢6VÆV7FVDf–æF–æræ–BÀ¢&Wf–Wu&WVW7BÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢–b‡&WVW7D”BÓÒ&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE&VÖVF–F–öå&Wf–Wr‡&Wf–Wr“°¢6WE&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’‡6VÆV7F–öä¶W’“°¢6WE&VÖVF–F–öåV&Æ—6„&6T'&æ6‚‡&Wf–Wræf—…÷%÷Æãòæ&6Uö'&æ6‚ÇÂvÖ–âr“°¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‡&WVW7D”BÓÒ&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE&VÖVF–F–öå&Wf–Wr†çVÆÂ“°¢6WE&VÖVF–F–öå&Wf–WtW'&÷"€¢&WVW7DW'&÷"–ç7Fæ6VöbW'&÷"ò&WVW7DW'&÷"æÖW76vR¢tf–ÆVBFòÆöB&VÖVF–F–öâ&Wf–Wrâp¢“°¢Òf–æÆÇ’°¢–b‡&WVW7D”BÓÓÒ&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB’°¢6WE&VÖVF–F–öå&Wf–WtÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢6öç7B†æFÆUV&Æ—6…&VÖVF–F–öâÒ7–æ2‚’Óâ°¢–b‚66÷RÇÂ6VÆV7FVDf–æF–ærÇÂ7F—fU&VÖVF–F–öå&Wf–WrÇÂ&VÖVF–F–öåV&Æ—6„ÆöF–ær’°¢&WGW&ã°¢Ð ¢6öç7B6÷W&6T6öçFVçBÒ&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçC°¢6öç7BFö¶VâÒ&VÖVF–F–öåV&Æ—6…Fö¶VâçG&–Ò‚“°¢–b‚6÷W&6T6öçFVçBçG&–Ò‚’’°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚t7W'&VçB6÷W&6R6öçFVçB—2&WV—&VBâr“°¢&WGW&ã°¢Ð¢–b‚&VÖVF–F–öåV&Æ—6„&÷fVB’°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚t÷W&F÷"&÷fÂ—2&WV—&VBâr“°¢&WGW&ã°¢Ð¢–b‚&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVB’°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚t6öæf—&ÒF†Rv—D‡V"Fö¶Vâ—2–çFVçF–öæÆÇ’w&—FRÖ6&ÆRâr“°¢&WGW&ã°¢Ð¢–b‚Fö¶Vâ’°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚tw&—FRÖ6&ÆRv—D‡V"Fö¶Vâ—2&WV—&VBâr“°¢&WGW&ã°¢Ð ¢6öç7B&WVW7D”BÒ²·&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçC°¢6WE&VÖVF–F–öåV&Æ—6„ÆöF–ær‡G'VR“°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚rr“°¢6WE&VÖVF–F–öåV&Æ—6…&W7VÇB†çVÆÂ“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBçV&Æ—6…&Wôf–æF–æu&VÖVF–F–öâ€¢6VÆV7FVDf–æF–æræ–BÀ¢°¢&Wõ÷66åö–C¢6VÆV7FVDf–æF–ærç66åö–BÀ¢6÷W&6Uö6öçFVçC¢6÷W&6T6öçFVçBÀ¢&6Uö'&æ6ƒ¢&VÖVF–F–öåV&Æ—6„&6T'&æ6‚çG&–Ò‚’ÇÂVæFVf–æVBÀ¢f–æF–æu÷W&Ã¢6VÆV7FVDf–æF–ærç6÷W&6U÷W&ÂÇÂVæFVf–æVBÀ¢÷W&F÷%ö&÷fVC¢&VÖVF–F–öåV&Æ—6„&÷fVBÀ¢w&—FU÷W&Ö—76–öç5ö6öæf–wW&VC¢&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVBÀ¢v—F‡V%÷Fö¶Vã¢Fö¶Và¢ÒÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢–b‡&WVW7D”BÓÒ&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE&VÖVF–F–öåV&Æ—6…&W7VÇB‡&W7öç6R“°¢6WE&VÖVF–F–öåV&Æ—6…Fö¶Vâ‚rr“°¢6WE&VÖVF–F–öåV&Æ—6„&÷fVB†fÇ6R“°¢6WE&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVB†fÇ6R“°¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‡&WVW7D”BÓÒ&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"€¢&WVW7DW'&÷"–ç7Fæ6VöbW'&÷"ò&WVW7DW'&÷"æÖW76vR¢tf–ÆVBFòV&Æ—6‚&VÖVF–F–öâ"âp¢“°¢Òf–æÆÇ’°¢–b‡&WVW7D”BÓÓÒ&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçB’°¢6WE&VÖVF–F–öåV&Æ—6„ÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢W6TVffV7B‚‚’Óâ°¢–b‚66÷RÇÂf–Æ&–Æ—G’æf–Æ&ÆRÇÂ6VÆV7FVDVçf—&öæÖVçD”B’°¢6WDÆöF–ær†fÇ6R“°¢6WE&Wõ66ç2…µÒ“°¢6WE&Wôf–æF–æw2…µÒ“°¢6WDW'&÷"‚rr“°¢&WGW&âVæFVf–æVC°¢Ð¢fö–BÆöE&VÖVF–F–öäFF‡66÷RÂv–æ—F–Âr“°¢&WGW&â‚’Óâ°¢&WVW7E&Vbæ7W'&VçB³Ò°¢Ó°¢ÒÂ¶f–Æ&–Æ—G’æf–Æ&ÆRÂ66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”BÂ6VÆV7FVDVçf—&öæÖVçD”EÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‡&VÖVF–F–öåVWVRæÆVæwF‚ÓÓÒ’°¢–b‡6VÆV7FVDf–æF–æt¶W’’°¢6VÆV7E&VÖVF–F–öäf–æF–ær†çVÆÂ“°¢Ð¢&WGW&ã°¢Ð ¢–b‚6VÆV7FVDf–æF–ærÇÂ&VÖVF–F–öåVWVRç6öÖR‚†f–æF–ær’Óâ'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’†f–æF–ær’ÓÓÒ6VÆV7FVDf–æF–æt¶W’’’°¢6VÆV7E&VÖVF–F–öäf–æF–ær‡&VÖVF–F–öåVWVU³Ò“°¢Ð¢ÒÂ·VWVU6VÆV7F–öä¶W—2Â&VÖVF–F–öåVWVRÂ6VÆV7FVDf–æF–ærÂ6VÆV7FVDf–æF–æt¶W•Ò“° ¢W6TVffV7B‚‚’Óâ°¢6WE&VÖVF–F–öå&Wf–Wr†çVÆÂ“°¢6WE&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’‚rr“°¢6WE&VÖVF–F–öå&Wf–WtÆöF–ær†fÇ6R“°¢6WE&VÖVF–F–öå&Wf–WtW'&÷"‚rr“°¢&W6WE&VÖVF–F–öåV&Æ—6…7FFR‚“°¢ÒÂ·6VÆV7FVDf–æF–æsòæ–BÂ6VÆV7FVDf–æF–æsòç66åö–EÒ“° ¢–b‚66÷R’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷""&öÆSÒ&ÆW'B#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äv—D‡V"&VÖVF–F–öãÂ÷à¢Æƒ#åv÷&·76R&÷WFR6öçFW‡B—2Ö—76–æsÂöƒ#à¢Çä6†ö÷6RFVæçBæBv÷&·76R&Vf÷&RÆöF–ærv—D‡V"&VÖVF–F–öâãÂ÷à¢Â÷6V7F–öãà¢“°¢Ð ¢–b†f–Æ&–Æ—G’æÆöF–ær’°¢&WGW&â€¢ÄFöÖ–åvU6†VÆÀ¢FöÖ–ãÒ&v—F‡V" ¢W–V'&÷sÒ%&VÖVF–F–öâ ¢F—FÆSÒ$v—D‡V"&VÖVF–F–öâ ¢FW67&—F–öãÒ$ÆöF–ærv—D‡V"f–Æ&–Æ—G’f÷"F†—2'V–ÆBâ ¢66÷S×³Å&öGV7DVçf—&öæÖVçE6VÆV7F÷"7FFS×¶Vçf—&öæÖVçE66÷WÒöä6†ævS×¶öä6†ævTVçf—&öæÖVçGÒóçÐ¢à¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ærv—D‡V"f–Æ&–Æ—G’"óà¢ÂôFöÖ–åvU6†VÆÃà¢“°¢Ð ¢–b‚f–Æ&–Æ—G’æf–Æ&ÆR’°¢&WGW&â€¢Äv—D‡V%Væf–Æ&ÆU6†VÆÀ¢F—FÆSÒ$v—D‡V"&VÖVF–F–öâ ¢66÷S×·66÷WÐ¢Vçf—&öæÖVçE66÷S×¶Vçf—&öæÖVçE66÷WÐ¢6VÆV7FVDVçf—&öæÖVçD”C×·6VÆV7FVDVçf—&öæÖVçD”GÐ¢öäVçf—&öæÖVçD6†ævS×¶öä6†ævTVçf—&öæÖVçGÐ¢Væf–Æ&ÆTÖW76vS×¶f–Æ&–Æ—G’çVæf–Æ&ÆTÖW76vWÐ¢óà¢“°¢Ð ¢–b‚6VÆV7FVDVçf—&öæÖVçD”B’°¢&WGW&â€¢Äv—D‡V$Ö—76–ætVçf—&öæÖVçE6†VÆÀ¢F—FÆSÒ$v—D‡V"&VÖVF–F–öâ ¢66÷S×·66÷WÐ¢Vçf—&öæÖVçE66÷S×¶Vçf—&öæÖVçE66÷WÐ¢6VÆV7FVDVçf—&öæÖVçD”C×·6VÆV7FVDVçf—&öæÖVçD”GÐ¢öäVçf—&öæÖVçD6†ævS×¶öä6†ævTVçf—&öæÖVçGÐ¢óà¢“°¢Ð ¢6öç7B&6UF‚ÒVæDVçf—&öæÖVçEVW'’†'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"r’Â6VÆV7FVDVçf—&öæÖVçD”B“°¢6öç7B&W÷6—F÷&–W5F‚ÒVæDVçf—&öæÖVçEVW'’†'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"÷&W÷6—F÷&–W2r’Â6VÆV7FVDVçf—&öæÖVçD”B“°¢6öç7Bf–æF–æw5F‚ÒVæDVçf—&öæÖVçEVW'’†'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"öf–æF–æw2r’Â6VÆV7FVDVçf—&öæÖVçD”B“°¢6öç7B66ç4'•&V6Væ7’Ò²ââç&Wõ66ç5Òç6÷'B‚†ÆVgBÂ&–v‡B’Óâ66ä6ö×ÆWF–öå6÷'EfÇVR‡&–v‡B’Ò66ä6ö×ÆWF–öå6÷'EfÇVR†ÆVgB’“°¢6öç7BÆFW7E66âÒ66ç4'•&V6Væ7•³ÒóòçVÆÃ°¢6öç7Bf–ÆVE66ç2Ò66ç4'•&V6Væ7’æf–ÇFW"‚‡66â’Óâ—4f–ÆVE66å7FGW2‡66âç7FGW2’“°¢6öç7BÆFW7Df–ÆVE66âÒf–ÆVE66ç5³ÒóòçVÆÃ°¢6öç7B7V66VVFVE66ä6÷VçBÒ&Wõ66ç2æf–ÇFW"‚‡66â’Óâ&Wõ66å7FGW5FöæR‡66âç7FGW2’ÓÓÒw7V66W72r’æÆVæwFƒ°¢6öç7B†5VWVVD÷%'Vææ–æu66âÒ&Wõ66ç2ç6öÖR‚‡66â’Óâ—47F—fU66å7FGW2‡66âç7FGW2’“°¢6öç7BæWfW%66ææVBÒ&Wõ66ç2æÆVæwF‚ÓÓÒ°¢6öç7BÆFW7E66äf–ÆVBÒÆFW7E66âò—4f–ÆVE66å7FGW2†ÆFW7E66âç7FGW2’¢fÇ6S°¢6öç7B7VÖÖ'”f–æF–æuF÷FÂÒ&Wôf–æF–æu7VÖÖ'¢ò&Wôf–æF–æu7VÖÖ'’çF÷FÅö÷Vâ°¢&Wôf–æF–æu7VÖÖ'’æf—†VEö6÷VçB°¢&Wôf–æF–æu7VÖÖ'’ç&V÷VæVEö6÷VçB°¢&Wôf–æF–æu7VÖÖ'’ç7W&W76VEö6÷Vç@¢¢°¢6öç7B†5&Wôf–æF–æw2Ð¢7VÖÖ'”f–æF–æuF÷FÂâÇÂ&Wôf–æF–æw2æÆVæwF‚âÇÂ&Wõ66ç2ç6öÖR‚‡66â’Óâ‡66âæf–æF–æuö6÷VçBóò’â“°¢6öç7BÆÅ66ç4f–ÆVBÒæWfW%66ææVBbb†5VWVVD÷%'Vææ–æu66âbb†5&Wôf–æF–æw2bb7V66VVFVE66ä6÷VçBÓÓÒbbÆFW7E66äf–ÆVC°¢6öç7B6†÷t–æ—F–ÄÆöF–ærÒÆöF–ærbb&Wõ66ç2æÆVæwF‚ÓÓÒbb&Wôf–æF–æw2æÆVæwF‚ÓÓÒ°¢6öç7B7FGW5f&–çBÒv—D‡V$6öææV7F–öå7FGW5f&–çDf÷"†FFæ6öææV7F–öâÂFFæÆöF–ær“°¢6öç7B6VÆV7FVE&W÷6—F÷'’Ò6VÆV7FVDf–æF–æp¢ò6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡&Wôf–æF–æu&W÷6—F÷'•fÇVR‡6VÆV7FVDf–æF–ærÂ&Wõ66ç4'””B’’ÇÂu&W÷6—F÷'’Væf–Æ&ÆRp¢¢rs°¢6öç7B6VÆV7FVE&VF–æW72Ò6VÆV7FVDf–æF–æp¢òv—D‡V%&VÖVF–F–öå&VF–æW72‡6VÆV7FVDf–æF–ærÂ7F—fU&VÖVF–F–öå&Wf–Wr¢¢²Æ&VÃ¢tæòf–æF–ær6VÆV7FVBrÂFöæS¢væWWG&Âr26öç7BÓ° ¢&WGW&â€¢ÄFöÖ–åvU6†VÆÀ¢FöÖ–ãÒ&v—F‡V" ¢W–V'&÷sÒ%&VÖVF–F–öâ ¢F—FÆSÒ$v—D‡V"&VÖVF–F–öâ ¢FW67&—F–öãÒ%7FvR&W÷6—F÷'’f—‚Æç2Â6W&FR&Wf–Wrg&öÒV&Æ—6‚ÂæB¶VWWfW'’&÷fÂF–VBFòF†Rf–æF–ærWf–FVæ6Râ ¢66÷S×³Å&öGV7DVçf—&öæÖVçE6VÆV7F÷"7FFS×¶Vçf—&öæÖVçE66÷WÒöä6†ævS×¶öä6†ævTVçf—&öæÖVçGÒóçÐ¢7FGW3×°¢ÄFöÖ–å7FGW4&FvP¢f&–çC×·7FGW5f&–çGÐ¢FWF–Ã×¶FFæ6öææV7F–öãòæ66÷VçEöÆöv–âòG¶FFæ6öææV7F–öâæ66÷VçEöÆöv–çÖ¢VæFVf–æVGÐ¢óà¢Ð¢7FGW5FöæS×¶v—D‡V$6öææV7F–öåFöæR†FFæ6öææV7F–öâÂFFæÆöF–ær—Ð¢&–Ö'”7F–öã×·²Æ&VÃ¢tv—D‡V"f–æF–æw2rÂFó¢f–æF–æw5F‚Âf&–çC¢w&–Ö'’r×Ð¢6V6öæF'”7F–öç3×µ·²Æ&VÃ¢u&W÷6—F÷&–W2rÂFó¢&W÷6—F÷&–W5F‚ÒÂ²Æ&VÃ¢tv—D‡V"†öÖRrÂFó¢&6UF‚Õ×Ð¢6–FS×°¢ÄFöÖ–äFWF–ÅæVÂF—FÆSÒ$&÷fÂ&÷VæF'’"W–V'&÷sÒ$f—‚'2#à¢ÇVÂ6Æ74æÖSÒ&–GBÖFöÖ–âÖ6†'FW"ÖÆ—7B#à¢ÆÆ“å&Wf–WrÆç2&R&VBÖöæÇ’æB6fRFòvVæW&FRãÂöÆ“à¢ÆÆ“åV&Æ—6†–ær&WV—&W2W‡Æ–6—B÷W&F÷"&÷fÂãÂöÆ“à¢ÆÆ“åw&—FRÖ6&ÆRv—D‡V"Fö¶Vç2&R6öæf—&ÖVBW"V&Æ—6‚ãÂöÆ“à¢ÆÆ“äWfW'’66R7F—2F–VBFòf–æF–ærÂ66âÂf–ÆRÂÆ–æRÂFWFV7F÷"Â6WfW&—G’ÂæB6öæf–FVæ6RãÂöÆ“à¢Â÷VÃà¢ÂôFöÖ–äFWF–ÅæVÃà¢Ð¢à¢¶FFæW'&÷"òÄFöÖ–äW'&÷%7FFRF—FÆSÒ%Væ&ÆRFòÆöBv—D‡V"7FGW2"&öG“×¶FFæW'&÷'Ò&WG'”7F–öã×·²Æ&VÃ¢u&WG'’rÂöä6Æ–6³¢FFç&VÆöB×Òóâ¢çVÆÇÐ¢¶W'&÷"òÄFöÖ–äW'&÷%7FFRF—FÆSÒ%Væ&ÆRFòÆöB&VÖVF–F–öâVWVR"&öG“×¶W'&÷'Ò&WG'”7F–öã×·²Æ&VÃ¢u&WG'’rÂöä6Æ–6³¢†æFÆU&Vg&W6‚×Òóâ¢çVÆÇÐ ¢·6†÷t–æ—F–ÄÆöF–ærò€¢ÄFöÖ–äÆöF–æu7FFRÆ&VÃÒ$ÆöF–ærv—D‡V"&VÖVF–F–öâVWVR"óà¢’¢æWfW%66ææVBò€¢ÄFöÖ–äV×G•7FFP¢W–V'&÷sÒ$æò66ç2 ¢F—FÆSÒ%'Vâ–÷W"f—'7B&W÷6—F÷'’66â ¢&öG“Ò%&W÷6—F÷'’f–æF–æw2×W7BW†—7B&Vf÷&R–FVçG&–Â6â&W&R&VÖVF–F–öâÆç2â ¢æW‡D7F–öã×·²Æ&VÃ¢t÷Vâ&W÷6—F÷&–W2rÂFó¢&W÷6—F÷&–W5F‚×Ð¢óà¢’¢ÆÅ66ç4f–ÆVBò€¢ÄFöÖ–äW'&÷%7FFP¢F—FÆSÒ%–÷W"Æ7B&W÷6—F÷'’66âf–ÆVB ¢&öG“×¶ÆFW7Df–ÆVE66âò7VÖÖ&—¦U66äf–ÇW&R†ÆFW7Df–ÆVE66â’¢uF†R66âF–Bæ÷B6ö×ÆWFRâwÐ¢&WG'”7F–öã×·²Æ&VÃ¢u&Wf–WræB&R×'Vâ66ârÂFó¢&W÷6—F÷&–W5F‚×Ð¢óà¢’¢†5&Wôf–æF–æw2ò€¢ÄFöÖ–äV×G•7FFP¢W–V'&÷sÒ$æòf–æF–æw2 ¢F—FÆSÒ$æòv—D‡V"&VÖVF–F–öâv÷&² ¢&öG“Ò%F†RÆFW7B&W÷6—F÷'’66â6ö×ÆWFVBv—F†÷WBf–æF–æw2F†BæVVB&VÖVF–F–öââ ¢æW‡D7F–öã×·²Æ&VÃ¢t÷Vâv—D‡V"f–æF–æw2rÂFó¢f–æF–æw5F‚×Ð¢óà¢’¢€¢Ãà¢¶ÆFW7E66äf–ÆVBò€¢ÄFöÖ–äW'&÷%7FFP¢F—FÆSÒ$ÆFW7B66âæVVG2GFVçF–öâ ¢&öG“×¶ÆFW7Df–ÆVE66âò7VÖÖ&—¦U66äf–ÇW&R†ÆFW7Df–ÆVE66â’¢uF†RÆFW7B66âF–Bæ÷B6ö×ÆWFRâwÐ¢&WG'”7F–öã×·²Æ&VÃ¢u&Wf–Wr66ç2rÂFó¢&W÷6—F÷&–W5F‚×Ð¢óà¢’¢çVÆÇÐ ¢ÄFöÖ–ä·•7G&— ¢Æ&VÃÒ$v—D‡V"&VÖVF–F–öâÖWG&–72 ¢—FV×3×µ°¢°¢Æ&VÃ¢t7F–öæ&ÆRf–æF–æw2rÀ¢fÇVS¢7F–öæ&ÆTf–æF–æw2æÆVæwF‚À¢FWF–Ã¢G¶f÷&ÖD6÷VçDÆ&VÂ‡&Wôf–æF–æw2æÆVæwF‚Âvf–æF–ærr—ÒÆöFVFÀ¢FöæS¢7F–öæ&ÆTf–æF–æw2æÆVæwF‚âòwv&æ–ærr¢væWWG&Âp¢ÒÀ¢°¢Æ&VÃ¢t†–v‚&–÷&—G’rÀ¢fÇVS¢†–v…&–÷&—G”6÷VçBÀ¢FWF–Ã¢t7&—F–6ÂæB†–v‚6WfW&—G’rÀ¢FöæS¢†–v…&–÷&—G”6÷VçBâòvFævW"r¢væWWG&Âp¢ÒÀ¢°¢Æ&VÃ¢u&W÷6—F÷&–W2rÀ¢fÇVS¢&W÷6—F÷'”6÷VçBÀ¢FWF–Ã¢uv—F‚&VÖVF–F–öâWf–FVæ6RrÀ¢FöæS¢&W÷6—F÷'”6÷VçBâòw7V66W72r¢væWWG&Âp¢ÒÀ¢°¢Æ&VÃ¢uV&Æ—6‚×&VG’rÀ¢fÇVS¢V&Æ—6†&ÆU&Wf–Wt6÷VçBÀ¢FWF–Ã¢7F—fU&VÖVF–F–öå&Wf–Wròt7W'&VçB&Wf–Wrr¢u&Wf–Wrf–æF–ærf—'7BrÀ¢FöæS¢V&Æ—6†&ÆU&Wf–Wt6÷VçBâòw7V66W72r¢væWWG&Âp¢Ð¢×Ð¢óà ¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"×&VÖVF–F–öâ×v÷&·76R#à¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖFöÖ–â×7FGW2×æVÂ–GBÖv—F‡V"×&VÖVF–F–öâ×VWVR"&–ÖÆ&VÃÒ$v—D‡V"&VÖVF–F–öâVWVR#à¢Æ†VFW#à¢ÆF—cà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#å&VÖVF–F–öâVWVSÂ÷à¢Æƒ3ç¶f÷&ÖD6÷VçDÆ&VÂ‡&VÖVF–F–öåVWVRæÆVæwF‚Âvf–æF–ærr—Ò–â66÷SÂöƒ3à¢ÂöF—cà¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢öä6Æ–6³×¶†æFÆU&Vg&W6‡Ð¢F—6&ÆVC×·&Vg&W6†–ærÇÂFFæÆöF–æwÐ¢à¢·&Vg&W6†–ærÇÂFFæÆöF–æròu&Vg&W6†–ærâââr¢u&Vg&W6‚wÐ¢Âö'WGFöãà¢Âö†VFW#à¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"×&VÖVF–F–öâÖÆ—7B"&öÆSÒ&Æ—7B#à¢·&VÖVF–F–öåVWVRæÖ‚†f–æF–ær’Óâ°¢6öç7B6VÆV7F–öä¶W’Ò'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’†f–æF–ær“°¢6öç7B&W÷6—F÷'’Ò6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡&Wôf–æF–æu&W÷6—F÷'•fÇVR†f–æF–ærÂ&Wõ66ç4'””B’’ÇÂu&W÷6—F÷'’Væf–Æ&ÆRs°¢6öç7B&VF–æW72Òv—D‡V%&VÖVF–F–öå&VF–æW72€¢f–æF–ærÀ¢6VÆV7F–öä¶W’ÓÓÒ6VÆV7FVDf–æF–æu&Wf–Wt¶W’ò7F—fU&VÖVF–F–öå&Wf–Wr¢çVÆÀ¢“°¢&WGW&â€¢Æ'WGFöà¢¶W“×·6VÆV7F–öä¶W—Ð¢G—SÒ&'WGFöâ ¢&öÆSÒ&Æ—7F—FVÒ ¢6Æ74æÖS×¶–GB×&WòÖf–æF–ær×&÷r–GBÖv—F‡V"×&VÖVF–F–öâ×&÷rG·6VÆV7FVDf–æF–æt¶W’ÓÓÒ6VÆV7F–öä¶W’òr—2×6VÆV7FVBr¢rwÖÐ¢öä6Æ–6³×²‚’Óâ6VÆV7E&VÖVF–F–öäf–æF–ær†f–æF–ær—Ð¢à¢Å6÷W&6TÆövôÖ&²&÷f–FW#Ò&v—F‡V""6Æ74æÖSÒ&—2×&÷r"óà¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷rÖ6÷’#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷r×F÷#à¢Ç7G&öæsç¶f–æF–ærçF—FÆWÓÂ÷7G&öæsà¢Ç7â6Æ74æÖS×·&Wôf–æF–æu6WfW&—G”6Æ72†f–æF–ærç6WfW&—G’—Óà¢¶f÷&ÖEFö¶VäÆ&VÂ†f–æF–ærç6WfW&—G’—Ð¢Â÷7ãà¢ÂöF—cà¢Çç¶f–æF–ærç&VÖVF–F–öâÇÂf–æF–æræ‡VÖå÷7VÖÖ'—ÓÂ÷à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷rÖÖWF#à¢Ç7ãç·&W÷6—F÷'—ÓÂ÷7ãà¢Ç7ãç·&Wôf–æF–ætÆö6F–öäÆ&VÂ†f–æF–ær—ÓÂ÷7ãà¢Ç7ãç¶f–æF–æræFWFV7F÷"òf÷&ÖEFö¶VäÆ&VÂ†f–æF–æræFWFV7F÷"’¢f÷&ÖEFö¶VäÆ&VÂ†f–æF–ærçG—R—ÓÂ÷7ãà¢Ç7ãç¶6öæf–FVæ6RG¶f÷&ÖD6öæf–FVæ6U66÷&R†f–æF–æræ6öæf–FVæ6U÷66÷&R—ÖÓÂ÷7ãà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷rÖÖWF#à¢Ç7â6Æ74æÖS×·&Wôf–æF–æu7FGW46Æ72†æ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2’—Óà¢¶f÷&ÖEFö¶VäÆ&VÂ†æ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2’—Ð¢Â÷7ãà¢Ç7â6Æ74æÖS×¶–GBÖv—F‡V"×&VÖVF–F–öâ×&VF–æW72—2ÒG·&VF–æW72çFöæWÖÓç·&VF–æW72æÆ&VÇÓÂ÷7ãà¢Ç7ãç·&Wôf–æF–æu66äFFTÆ&VÂ†f–æF–ærÂ&Wõ66ç4'””B—ÓÂ÷7ãà¢ÂöF—cà¢ÂöF—cà¢Âö'WGFöãà¢“°¢Ò—Ð¢ÂöF—cà¢Â÷6V7F–öãà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖFöÖ–â×7FGW2×æVÂ–GBÖv—F‡V"×&VÖVF–F–öâ×Æâ"&–ÖÆ&VÃÒ$v—D‡V"&VÖVF–F–öâÆâ#à¢Æ†VFW#à¢ÆF—cà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#åÆâæBV&Æ—6ƒÂ÷à¢Æƒ3ç·6VÆV7FVDf–æF–ærò6VÆV7FVDf–æF–ærçF—FÆR¢tæòf–æF–ær6VÆV7FVBwÓÂöƒ3à¢ÂöF—cà¢Ç7â6Æ74æÖS×¶–GBÖv—F‡V"×&VÖVF–F–öâ×&VF–æW72—2ÒG·6VÆV7FVE&VF–æW72çFöæWÖÓà¢·6VÆV7FVE&VF–æW72æÆ&VÇÐ¢Â÷7ãà¢Âö†VFW#à ¢²6VÆV7FVDf–æF–ærò€¢ÄFöÖ–äV×G•7FFP¢W–V'&÷sÒ$V×G’VWVR ¢F—FÆSÒ$æò&VÖVF–F–öâ6æF–FFW2ÆöFVB ¢&öG“Ò$æWr&VÖVF–F–öâ6æF–FFW2V"gFW"v—D‡V"66ç2&öGV6R&W÷6—F÷'’f–æF–æw2â ¢æW‡D7F–öã×·²Æ&VÃ¢t÷Vâv—D‡V"f–æF–æw2rÂFó¢f–æF–æw5F‚×Ð¢óà¢’¢€¢Ãà¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"×&VÖVF–F–öâÖf–æF–ærÖ†VFW"#à¢ÆF—cà¢Å6÷W&6TÆövôÖ&²&÷f–FW#Ò&v—F‡V""6Æ74æÖSÒ&—2×&÷r"óà¢ÆF—cà¢Ç7G&öæsç·6VÆV7FVE&W÷6—F÷'—ÓÂ÷7G&öæsà¢Çç·6VÆV7FVDf–æF–æræ‡VÖå÷7VÖÖ'—ÓÂ÷à¢ÂöF—cà¢ÂöF—cà¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’ ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâfö–B†æFÆTÆöE&VÖVF–F–öå&Wf–Wr‚—Ð¢F—6&ÆVC×·&VÖVF–F–öå&Wf–WtÆöF–æwÐ¢à¢·&VÖVF–F–öå&Wf–WtÆöF–æròtÆöF–ær&Wf–Wrâââr¢u&Wf–Wrf—‚ÆâwÐ¢Âö'WGFöãà¢ÂöF—cà ¢ÆFÂ6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖf7G2#à¢ÆF—cà¢ÆGCäf–æF–æsÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræ–GÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå66ãÂöGCà¢ÆFCç·6VÆV7FVDf–æF–ærç66åö–GÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå&W÷6—F÷'“ÂöGCà¢ÆFCç·6VÆV7FVE&W÷6—F÷'—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäÆö6F–öãÂöGCà¢ÆFCç·&Wôf–æF–ætÆö6F–öäÆ&VÂ‡6VÆV7FVDf–æF–ær—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäFWFV7F÷#ÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræFWFV7F÷"òf÷&ÖEFö¶VäÆ&VÂ‡6VÆV7FVDf–æF–æræFWFV7F÷"’¢f÷&ÖEFö¶VäÆ&VÂ‡6VÆV7FVDf–æF–ærçG—R—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå6WfW&—G“ÂöGCà¢ÆFCç¶f÷&ÖEFö¶VäÆ&VÂ‡6VÆV7FVDf–æF–ærç6WfW&—G’—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCä6öæf–FVæ6SÂöGCà¢ÆFCç¶f÷&ÖD6öæf–FVæ6U66÷&R‡6VÆV7FVDf–æF–æræ6öæf–FVæ6U÷66÷&R—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäÆ–fV7–6ÆSÂöGCà¢ÆFCç¶f÷&ÖEFö¶VäÆ&VÂ†æ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2‡6VÆV7FVDf–æF–æræÆ–fV7–6ÆU÷7FGW2’—ÓÂöFCà¢ÂöF—cà¢ÂöFÃà ¢·6VÆV7FVDf–æF–ærç6÷W&6U÷W&Âò€¢Æ6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖÆ–æ²"‡&Vc×·6VÆV7FVDf–æF–ærç6÷W&6U÷W&ÇÒF&vWCÒ%ö&Ææ²"&VÃÒ&æ÷&VfW'&W"#à¢ÄW‡FW&æÄÆ–æ²6—¦S×³GÒ7G&ö¶Uv–GFƒ×³'Ò&–Ö†–FFVãÒ'G'VR"óà¢÷VâÆ–æ¶VBv—D‡V"Æ–æP¢Âöà¢’¢€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B#äv—D‡V"Æ–æRÆ–æ²Væf–Æ&ÆRf÷"F†—2f–æF–ærãÂöF—cà¢—Ð ¢·&VÖVF–F–öå&Wf–WtW'&÷"ò€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·&VÖVF–F–öå&Wf–WtW'&÷'ÓÂöF—cà¢’¢çVÆÇÐ ¢¶7F—fU&VÖVF–F–öå&Wf–Wrò€¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâ×&Wf–Wr#à¢ÆƒSç¶7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç7VÖÖ'—ÓÂöƒSà¢Çç¶7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç&—6µ÷7VÖÖ'—ÓÂ÷à¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâ×&Wf–WrÖw&–B#à¢ÆF—cà¢Ç7G&öæså7FW3Â÷7G&öæsà¢ÇVÃà¢²†7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç7FW2óòµÒ’æÖ‚‡7FW’Óâ€¢ÆÆ’¶W“×·7FWÓç·7FWÓÂöÆ“à¢’—Ð¢Â÷VÃà¢ÂöF—cà¢ÆF—cà¢Ç7G&öæsåfÆ–FF–öãÂ÷7G&öæsà¢ÇVÃà¢²†7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâçfÆ–FF–öâóòµÒ’æÖ‚†—FVÒ’Óâ€¢ÆÆ’¶W“×¶—FV×Óç¶—FV×ÓÂöÆ“à¢’—Ð¢Â÷VÃà¢ÂöF—cà¢ÂöF—cà¢²†7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç6fWG•öæ÷FW2óòµÒ’æÆVæwF‚âò€¢ÆF—cà¢Ç7G&öæså6fWG’æ÷FW3Â÷7G&öæsà¢ÇVÃà¢²†7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç6fWG•öæ÷FW2óòµÒ’æÖ‚†æ÷FR’Óâ€¢ÆÆ’¶W“×¶æ÷FWÓç¶æ÷FWÓÂöÆ“à¢’—Ð¢Â÷VÃà¢ÂöF—cà¢’¢çVÆÇÐ¢¶7F—fU&VÖVF–F–öå&Wf–Wræf—…÷%÷Æâò€¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"×&VÖVF–F–öâ×ÆâÖf–ÆW2#à¢Ç7G&öæsç¶7F—fU&VÖVF–F–öå&Wf–Wræf—…÷%÷Æâç%÷F—FÆWÓÂ÷7G&öæsà¢Ç7ãç¶'&æ6‚G¶7F—fU&VÖVF–F–öå&Wf–Wræf—…÷%÷Æâæ'&æ6…öæÖWÖÓÂ÷7ãà¢ÇVÃà¢¶7F—fU&VÖVF–F–öå&Wf–Wræf—…÷%÷Æâæf–ÆW2æÖ‚†f–ÆR’Óâ€¢ÆÆ’¶W“×¶f–ÆRçF‡Óç¶f–ÆRçF‡ÓÂöÆ“à¢’—Ð¢Â÷VÃà¢ÂöF—cà¢’¢çVÆÇÐ¢Çà¢¶7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâçV&Æ—6†&ÆP¢òtf—‚"6â&RV&Æ—6†VBgFW"&÷fÂæBw&—FR×W&Ö—76–öâ6öæf—&ÖF–öââp¢¢7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâçV&Æ—6…ö&Æö6¶VE÷&V6öâÇÂtÖçVÂ&VÖVF–F–öâ—2&WV—&VBâwÐ¢Â÷à¢¶7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâçV&Æ—6†&ÆRò€¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâ×V&Æ—6‚#à¢·&VÖVF–F–öåV&Æ—6„W'&÷"ò€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·&VÖVF–F–öåV&Æ—6„W'&÷'ÓÂöF—cà¢’¢çVÆÇÐ¢·&VÖVF–F–öåV&Æ—6…&W7VÇBò€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'B×7V66W72#à¢"7·&VÖVF–F–öåV&Æ—6…&W7VÇBçV&Æ—6‚ç%öçVÖ&W'Ò÷VæVBöç²rwÐ¢·&VÖVF–F–öåV&Æ—6…&W7VÇBçV&Æ—6‚æ'&æ6…öæÖWÒç²rwÐ¢Æ‡&Vc×·&VÖVF–F–öåV&Æ—6…&W7VÇBçV&Æ—6‚ç%÷W&ÇÒF&vWCÒ%ö&Ææ²"&VÃÒ&æ÷&VfW'&W"#à¢f–Wr ¢Âöà¢ÂöF—cà¢’¢çVÆÇÐ¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"×&VÖVF–F–öâ×V&Æ—6‚Öw&–B#à¢ÆÆ&VÃà¢&6R'&æ6€¢Æ–çW@¢G—SÒ'FW‡B ¢fÇVS×·&VÖVF–F–öåV&Æ—6„&6T'&æ6‡Ð¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6„&6T'&æ6‚†WfVçBçF&vWBçfÇVR—Ð¢Æ6V†öÆFW#Ò&Ö–â ¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢v—D‡V"Fö¶Và¢Æ–çW@¢G—SÒ'77v÷&B ¢fÇVS×·&VÖVF–F–öåV&Æ—6…Fö¶VçÐ¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6…Fö¶Vâ†WfVçBçF&vWBçfÇVR—Ð¢WFô6ö×ÆWFSÒ&öfb ¢óà¢ÂöÆ&VÃà¢ÂöF—cà¢ÆÆ&VÃà¢7W'&VçB6÷W&6R6öçFVç@¢ÇFW‡F&V¢fÇVS×·&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçGÐ¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçB†WfVçBçF&vWBçfÇVR—Ð¢&÷w3×³wÐ¢7VÆÄ6†V6³×¶fÇ6WÐ¢óà¢ÂöÆ&VÃà¢ÆÆ&VÂ6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâÖ&÷fÂ#à¢Æ–çW@¢G—SÒ&6†V6¶&÷‚ ¢6†V6¶VC×·&VÖVF–F–öåV&Æ—6„&÷fVGÐ¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6„&÷fVB†WfVçBçF&vWBæ6†V6¶VB—Ð¢óà¢Ç7ãä&÷fVBf÷"V&Æ—6ƒÂ÷7ãà¢ÂöÆ&VÃà¢ÆÆ&VÂ6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâÖ&÷fÂ#à¢Æ–çW@¢G—SÒ&6†V6¶&÷‚ ¢6†V6¶VC×·&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVGÐ¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVB†WfVçBçF&vWBæ6†V6¶VB—Ð¢óà¢Ç7ãäv—D‡V"Fö¶Vâ—2–çFVçF–öæÆÇ’w&—FRÖ6&ÆSÂ÷7ãà¢ÂöÆ&VÃà¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’ ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâfö–B†æFÆUV&Æ—6…&VÖVF–F–öâ‚—Ð¢F—6&ÆVC×°¢&VÖVF–F–öåV&Æ—6„ÆöF–ærÇÀ¢&VÖVF–F–öåV&Æ—6„&÷fVBÇÀ¢&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖV@¢Ð¢à¢·&VÖVF–F–öåV&Æ—6„ÆöF–æròuV&Æ—6†–ærâââr¢uV&Æ—6‚f—‚"wÐ¢Âö'WGFöãà¢ÂöF—cà¢’¢çVÆÇÐ¢ÂöF—cà¢’¢çVÆÇÐ¢Âóà¢—Ð¢Â÷6V7F–öãà¢ÂöF—cà¢Âóà¢—Ð¢ÂôFöÖ–åvU6†VÆÃà¢“°§Ð  ¦6öç7B4”DT$%ô4ôÄÄ4TEõ5Dõ$tUô´U’Òv–GC§6–FV&#¦6öÆÆ6VBs°¦6öç7B4”DT$%õt”ED…õ5Dõ$tUô´U’Òv–GC§6–FV&#§v–GF‚s°¦6öç7B4”DT$%ôDTdTÅEõt”ED‚Ò#Cƒ²òòÖF6†W2F†R&–÷"RãW&VÐ¦6öç7B4”DT$%ôÔ”åôU…äDTEõt”ED‚Ò“c°¦6öç7B4”DT$%ôÔ…õt”ED‚Ò3c°¦6öç7B4”DT$%ô4ôÄÄ4UõD…$U4„ôÄBÒC²òòG&vv–ær&VÆ÷rF†—26æ2Fò6öÆÆ6V@¦6öç7B4”DT$%ô4ôÄÄ4TEõt”ED‚Òc°¦6öç7B45$ôÄÅôäd”tDõ%ôÔ”åõD…TÔ%ô„T”t…BÒcƒ°¦6öç7B45$ôÄÅôäd”tDõ%ôÔ…õD…TÔ%ô„T”t…BÒ3#° §G—R67&öÆÄæf–vF÷$ÖWG&–72Ò°¢f—6–&ÆS¢&ööÆVã°¢F‡VÖ$†V–v‡C¢çVÖ&W#°¢F‡VÖ%F÷¢çVÖ&W#°§Ó° ¦gVæ7F–öâ&VE6–FV&$6öÆÆ6VB‚“¢&ööÆVâ°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBr’°¢&WGW&âfÇ6S°¢Ð¢G'’°¢&WGW&âv–æF÷ræÆö6Å7F÷&vRævWD—FVÒ…4”DT$%ô4ôÄÄ4TEõ5Dõ$tUô´U’’ÓÓÒss°¢Ò6F6‚°¢&WGW&âfÇ6S°¢Ð§Ð ¦gVæ7F–öâ&VE6–FV&%v–GF‚‚“¢çVÖ&W"°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBr’°¢&WGW&â4”DT$%ôDTdTÅEõt”EDƒ°¢Ð¢G'’°¢6öç7B&rÒv–æF÷ræÆö6Å7F÷&vRævWD—FVÒ…4”DT$%õt”ED…õ5Dõ$tUô´U’“°¢–b‚&r’°¢&WGW&â4”DT$%ôDTdTÅEõt”EDƒ°¢Ð¢6öç7B'6VBÒçVÖ&W"ç'6T–çB‡&rÂ“°¢–b„çVÖ&W"æ—4æâ‡'6VB’’°¢&WGW&â4”DT$%ôDTdTÅEõt”EDƒ°¢Ð¢&WGW&âÖF‚æÖ–â…4”DT$%ôÔ…õt”ED‚ÂÖF‚æÖ‚…4”DT$%ôÔ”åôU…äDTEõt”ED‚Â'6VB’“°¢Ò6F6‚°¢&WGW&â4”DT$%ôDTdTÅEõt”EDƒ°¢Ð§Ð ¦gVæ7F–öâ—4Ö5ÆFf÷&Ò‚“¢&ööÆVâ°¢–b‡G—Vöbæf–vF÷"ÓÓÒwVæFVf–æVBr’°¢&WGW&âfÇ6S°¢Ð¢&WGW&âôÖ7Æ•†öæWÆ•GÆ•öBö’çFW7B†æf–vF÷"çÆFf÷&ÒÇÂrr“°§Ð ¦gVæ7F–öâf÷&ÖEÆFf÷&Õ6†÷'F7WB†¶W“¢7G&–ær“¢7G&–ær°¢6öç7Bæ÷&ÖÆ—¦VD¶W’Ò¶W’çG&–Ò‚’çFõWW$66R‚“°¢&WGW&â—4Ö5ÆFf÷&Ò‚’ò(É‚G¶æ÷&ÖÆ—¦VD¶W—Ö¢7G&Â²G¶æ÷&ÖÆ—¦VD¶W—Ö°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7E6†VÆÄÆ–÷WB‚’°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7BÆö6F–öâÒW6TÆö6F–öâ‚“°¢6öç7Bæf–vFRÒW6Tæf–vFR‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“°¢6öç7B²fVGW&W3¢&6¶VæDfVGW&W2ÒÒW6T&6¶VæDfVGW&W2‡²Væ&ÆVC¢4„õTÄEôÄôEô4ôääT5Dõ%ô$4´TäEôdTEU$U2Ò“°¢6öç7B6÷W&6Tf–Æ&–Æ—G’ÒW6TÖVÖò‚‚’Óâ'V–ÆE6÷W&6Tf–Æ&–Æ—G’†&6¶VæDfVGW&W2’Â¶&6¶VæDfVGW&W5Ò“°¢6öç7Bf—6–&ÆTFöÖ–ä÷&FW"ÒW6TÖVÖò€¢‚’ÓâDôÔ”åôäeôõ$DU"æf–ÇFW"‚†FöÖ–â’Óâ6÷W&6Tf–Æ&–Æ—G•¶FöÖ–åÒçf—6–&ÆR’À¢·6÷W&6Tf–Æ&–Æ—G•Ð¢“°¢6öç7B¶6öÖÖæD÷VâÂ6WD6öÖÖæD÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B¶66÷VçDÖVçT÷VâÂ6WD66÷VçDÖVçT÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76TÖVçT÷VâÂ6WEv÷&·76TÖVçT÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B¶÷VäFöÖ–äfÇ–÷WBÂ6WD÷VäFöÖ–äfÇ–÷WEÒÒW6U7FFSÅ6÷W&6U&÷f–FW"ÂçVÆÃâ†çVÆÂ“°¢6öç7B¶Æ7D÷VæVDFöÖ–äfÇ–÷WBÂ6WDÆ7D÷VæVDFöÖ–äfÇ–÷WEÒÒW6U7FFSÅ6÷W&6U&÷f–FW"ÂçVÆÃâ†çVÆÂ“°¢6öç7B·6–FV&$6öÆÆ6VE&VbÂ6WE6–FV&$6öÆÆ6VE&VeÒÒW6U7FFSÆ&ööÆVãâ‚‚’Óâ&VE6–FV&$6öÆÆ6VB‚’“°¢6öç7B·6–FV&%v–GF‚Â6WE6–FV&%v–GF…ÒÒW6U7FFSÆçVÖ&W#â‚‚’Óâ&VE6–FV&%v–GF‚‚’“°¢6öç7B¶—4G&vv–æu6–FV&"Â6WD—4G&vv–æu6–FV&%ÒÒW6U7FFR†fÇ6R“°¢6öç7B¶—56–FV&$VFvTfö7W6VBÂ6WD—56–FV&$VFvTfö7W6VEÒÒW6U7FFR†fÇ6R“°¢6öç7B67&öÆÄæf–vF÷%&VbÒW6U&VcÄ…DÔÄF—dVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7B67&öÆÄæf–vF÷%F‡VÖ%&VbÒW6U&VcÄ…DÔÅ7äVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7B¶—4æ'&÷uf–Ww÷'BÂ6WD—4æ'&÷uf–Ww÷'EÒÒW6U7FFSÆ&ööÆVãâ‚‚’Óâ°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBrÇÂG—Vöbv–æF÷ræÖF6„ÖVF–ÓÒvgVæ7F–öâr’°¢&WGW&âfÇ6S°¢Ð¢&WGW&âv–æF÷ræÖF6„ÖVF–‚r†Ö‚×v–GFƒ¢“c‚’r’æÖF6†W3°¢Ò“°¢òòF†R6öÆÆ6VB7FFR—2f÷&6VBöfböâæ'&÷rf–Ww÷'G2&V6W6RF†R&–À¢òò&V6öÖW2†÷&—¦öçFÂF÷&"F†W&R(	BF†W&R—2æòW6VgVÂ&6öÆÆ6VB"ÖöFP¢òòf÷"†÷&—¦öçFÂæbÂæBW'6—7F–ær6öÆÆ6VB&VfW&Væ6R–çFòÖö&–ÆP¢òòv÷VÆB÷F†W'v—6RÆVfRW6W'2v—F†÷WBv’FòW‡æB—Bà¢6öç7B6–FV&$6öÆÆ6VBÒ6–FV&$6öÆÆ6VE&Vbbb—4æ'&÷uf–Ww÷'C°¢6öç7B&VæFW&VE6–FV&%v–GF‚Ò—4æ'&÷uf–Ww÷'@¢òVæFVf–æV@¢¢6–FV&$6öÆÆ6V@¢ò4”DT$%ô4ôÄÄ4TEõt”ED€¢¢6–FV&%v–GFƒ°¢6öç7B66÷VçDÖVçU&VbÒW6U&VcÄ…DÔÄF—dVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7Bv÷&·76TÖVçU&VbÒW6U&VcÄ…DÔÄF—dVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7BFöÖ–äfÇ–÷WE&VbÒW6U&VcÄ…DÔÄF—dVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7BFöÖ–åG&–vvW%&Vg2ÒW6U&VcÅ&V6÷&CÅ6÷W&6U&÷f–FW"Â…DÔÄ'WGFöäVÆVÖVçBÂçVÆÃãâ‡°¢w3¢çVÆÂÀ¢v—F‡V#¢çVÆÂÀ¢·V&W&æWFW3¢çVÆÀ¢Ò“°¢6öç7B6–FV&%&VbÒW6U&VcÄ…DÔÄVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7B6–FV&%&W6—¦TÖ÷fVE&VbÒW6U&Vb†fÇ6R“°¢6öç7B&6UF‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷R’¢rös°¢6öç7B7F—fTFöÖ–âÒ66÷Ròf–æD7F—fTFöÖ–â‡66÷RÂÆö6F–öâçF†æÖR’¢çVÆÃ°¢6öç7B7F—fTFöÖ–å&÷WFT”BÐ¢66÷Rbb÷VäFöÖ–äfÇ–÷WBòf–æD7F—fTFöÖ–å&÷WFT”B‡66÷RÂ÷VäFöÖ–äfÇ–÷WBÂÆö6F–öâçF†æÖR’¢çVÆÃ°¢6öç7B6öÖÖæD—FV×2ÒW6TÖVÖóÄ6öÖÖæEÆWGFT—FVÕµÓâ‚‚’Óâ°¢–b‚66÷R’°¢&WGW&âµÓ°¢Ð¢6öç7B7W'&VçDVçf—&öæÖVçD”BÒVçf—&öæÖVçD”Dg&öÕ6V&6‚†Æö6F–öâç6V&6‚“°¢6öç7BFöÖ–ä6öÖÖæEF‚Ò‡Fƒ¢7G&–ær’ÓâVæDVçf—&öæÖVçEVW'’‡F‚Â7W'&VçDVçf—&öæÖVçD”B“°¢6öç7B—FV×3¢6öÖÖæEÆWGFT—FVÕµÒÒ°¢°¢–C¢v÷fW'f–WrrÀ¢Æ&VÃ¢t÷fW'f–WrrÀ¢FW67&—F–öã¢t7&÷72ÖFöÖ–â÷7GW&RæBæW‡B7F–öç2rÀ¢¶W—v÷&G3¢²v†öÖRrÂvF6†&ö&BrÂwv÷&·76RrÂvFöÖ–ç2uÒÀ¢Fƒ¢&6UF€¢Ð¢Ó° ¢–b‡6÷W&6Tf–Æ&–Æ—G’æw2çf—6–&ÆR’°¢—FV×2çW6‚‡°¢–C¢vw2rÀ¢Æ&VÃ¢tu2rÀ¢FW67&—F–öã¢tu2Ö6†–æR–FVçF—G’6öçG&öÂ6VçFW"rÀ¢¶W—v÷&G3¢²vw2rÂv6Æ÷VBrÂv–ÒrÂv–FVçF—G’uÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöw6¢Ò“°¢—FV×2çW6‚‡°¢–C¢vw2Ö6÷fW&vRrÀ¢Æ&VÃ¢tu26÷fW&vRrÀ¢FW67&—F–öã¢t66÷VçBÂ&Vv–öâÂ6W'f–6RÂæB6öÆÆV7F÷"6÷fW&vRF6†&ö&BrÀ¢¶W—v÷&G3¢²vw2rÂv6÷fW&vRrÂv66÷VçBrÂw&Vv–öârÂv6öÆÆV7F÷"uÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöw2ö6÷fW&vV¢Ò“°¢—FV×2çW6‚‡°¢–C¢vw2Ö–FVçF—F–W2rÀ¢Æ&VÃ¢tu2–FVçF—F–W2rÀ¢FW67&—F–öã¢tÖ6†–æR–FVçF—F–W2F—66÷fW&VBg&öÒF†R6öææV7FVBu266÷RrÀ¢¶W—v÷&G3¢²vw2rÂv–FVçF—F–W2rÂv–ÒrÂw&öÆW2rÂvÖ6†–æRuÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöw2ö–FVçF—F–W6¢Ò“°¢—FV×2çW6‚‡°¢–C¢vw2Öf–æF–æw2rÀ¢Æ&VÃ¢tu2f–æF–æw2rÀ¢FW67&—F–öã¢tFöÖ–â×66÷VBu2&—6²VWVRrÀ¢¶W—v÷&G3¢²vw2rÂvf–æF–æw2rÂw&—6²rÂv–ÒuÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöw2öf–æF–æw6¢Ò“°¢–b‡6÷W&6Tf–Æ&–Æ—G’æw2æf–Æ&ÆR’°¢—FV×2çW6‚‡°¢–C¢vw2Ö6öææV7BrÀ¢Æ&VÃ¢t6öææV7Bu2rÀ¢FW67&—F–öã¢u&Wf–Wru26öææV7F–öâ7FGW2÷"ÖævRöæ&ö&F–ærrÀ¢¶W—v÷&G3¢²vw2rÂv6öææV7BrÂv66÷VçBrÂw&öÆRrÂw7FGW2rÂvöæ&ö&F–æruÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöw2ö6öææV7F¢Ò“°¢Ð¢Ð ¢–b‡6÷W&6Tf–Æ&–Æ—G’æv—F‡V"çf—6–&ÆR’°¢—FV×2çW6‚‡°¢–C¢vv—F‡V"rÀ¢Æ&VÃ¢tv—D‡V"rÀ¢FW67&—F–öã¢u&W÷6—F÷&–W2Â7F–öç2ôô”D2ÂæBvVçF–2&—6²rÀ¢¶W—v÷&G3¢²vv—F‡V"rÂw&W÷6—F÷&–W2rÂv7F–öç2rÂvö–F2uÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöv—F‡V&¢Ò“°¢—FV×2çW6‚‡°¢–C¢vv—F‡V"Öf–æF–æw2rÀ¢Æ&VÃ¢tv—D‡V"f–æF–æw2rÀ¢FW67&—F–öã¢u&W÷6—F÷'’&—6²–ç6–FRF†Rv—D‡V"6V7F–öârÀ¢¶W—v÷&G3¢²vv—F‡V"rÂvf–æF–æw2rÂw&W÷6—F÷'’rÂwG&–vRuÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöv—F‡V"öf–æF–æw6¢Ò“°¢—FV×2çW6‚‡°¢–C¢vv—F‡V"ÖvVçF–2×&—6²rÀ¢Æ&VÃ¢tv—D‡V"’òvVçF–2&—6²rÀ¢FW67&—F–öã¢tvVçB–FVçF—F–W2ÂÔ5FööÇ2Â&ö×G2Â6V7&WG2ÂæBv÷&¶fÆ÷rG'W7BF‡2rÀ¢¶W—v÷&G3¢²vv—F‡V"rÂvvVçF–2rÂv’rÂvÖ7rÂwFööÇ2rÂw&ö×G2rÂw6V7&WG2rÂwv÷&¶fÆ÷ruÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöv—F‡V"övVçF–2×&—6¶¢Ò“°¢–b‡6÷W&6Tf–Æ&–Æ—G’æv—F‡V"æf–Æ&ÆR’°¢—FV×2çW6‚‡°¢–C¢vv—F‡V"Ö6öææV7BrÀ¢Æ&VÃ¢t6öææV7Bv—D‡V"rÀ¢FW67&—F–öã¢u7F'Bv—D‡V"öæ&ö&F–ærrÀ¢¶W—v÷&G3¢²vv—F‡V"rÂv6öææV7BrÂvrÂv–ç7FÆÂuÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òöv—F‡V"ö6öææV7F¢Ò“°¢Ð¢Ð ¢–b‡6÷W&6Tf–Æ&–Æ—G’æ·V&W&æWFW2çf—6–&ÆR’°¢—FV×2çW6‚‡°¢–C¢v·V&W&æWFW2rÀ¢Æ&VÃ¢t·V&W&æWFW2rÀ¢FW67&—F–öã¢t6ÇW7FW'2Âv÷&¶ÆöG2Â6W'f–6R66÷VçG2ÂæB$$2rÀ¢¶W—v÷&G3¢²v·V&W&æWFW2rÂv³‡2rÂv6ÇW7FW'2rÂw&&2uÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òö·V&W&æWFW6¢Ò“°¢—FV×2çW6‚‡°¢–C¢v·V&W&æWFW2Öf–æF–æw2rÀ¢Æ&VÃ¢t·V&W&æWFW2f–æF–æw2rÀ¢FW67&—F–öã¢t6ÇW7FW"æB6W'f–6RÖ66÷VçB&—6²VWVRrÀ¢¶W—v÷&G3¢²v·V&W&æWFW2rÂv³‡2rÂvf–æF–æw2rÂw&&2uÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òö·V&W&æWFW2öf–æF–æw6¢Ò“°¢–b‡6÷W&6Tf–Æ&–Æ—G’æ·V&W&æWFW2æf–Æ&ÆR’°¢—FV×2çW6‚‡°¢–C¢v·V&W&æWFW2Ö6öææV7BrÀ¢Æ&VÃ¢t6öææV7B·V&W&æWFW2rÀ¢FW67&—F–öã¢u7F'B6ÇW7FW"öæ&ö&F–ærrÀ¢¶W—v÷&G3¢²v·V&W&æWFW2rÂv³‡2rÂv6öææV7BrÂv6ÇW7FW"uÒÀ¢Fƒ¢FöÖ–ä6öÖÖæEF‚†G¶&6UF‡Òö·V&W&æWFW2ö6öææV7F¢Ò“°¢Ð¢Ð ¢—FV×2çW6‚€¢°¢–C¢w&W÷'G2rÀ¢Æ&VÃ¢u&W÷'G2rÀ¢FW67&—F–öã¢tW†V7WF—fR÷7GW&RæBFöÖ–â÷WF6öÖRf–Ww2rÀ¢¶W—v÷&G3¢²w&W÷'BrÂv&ö&BrÂw&—6²rÂvW†V7WF—fRuÒÀ¢Fƒ¢G¶&6UF‡Ò÷&W÷'G6 ¢ÒÀ¢°¢–C¢w6WGF–æw2rÀ¢Æ&VÃ¢u6WGF–æw2rÀ¢FW67&—F–öã¢uv÷&·76R–FVçF—G’ÂÖVÖ&W'2Â6W76–öç2ÂæBÆ–fV7–6ÆRrÀ¢¶W—v÷&G3¢²v–FVçF—G’rÂv66W72rÂvWF†VçF–6F–öârÂvÖVÖ&W'2rÂw6W76–öç2uÒÀ¢Fƒ¢G¶&6UF‡Ò÷6WGF–æw6 ¢ÒÀ¢°¢–C¢vÖ&¶WF–ær×6—FRrÀ¢Æ&VÃ¢tÖ&¶WF–ær6—FRrÀ¢FW67&—F–öã¢u&WGW&âFòF†RV&Æ–2–FVçG&–Â6—FRrÀ¢¶W—v÷&G3¢²wV&Æ–2rÂwvV'6—FRrÂv†öÖRuÒÀ¢Fƒ¢ròp¢ÒÀ¢°¢–C¢w6–vâÖ÷WBrÀ¢Æ&VÃ¢u6–vâ÷WBrÀ¢FW67&—F–öã¢tVæBF†—2v÷&·76R6W76–öârÀ¢¶W—v÷&G3¢²vÆöv÷WBrÂw6W76–öâuÒÀ¢7F–öã¢‚’Óâæf–vFR‚rööÆöv÷WBrÂ²&WÆ6S¢G'VRÒ¢Ð¢“°¢&WGW&â—FV×3°¢ÒÂ¶&6UF‚ÂÆö6F–öâç6V&6‚Âæf–vFRÂ66÷RÂ6÷W&6Tf–Æ&–Æ—G•Ò“° ¢W6TVffV7B‚‚’Óâ°¢6WD÷VäFöÖ–äfÇ–÷WB†çVÆÂ“°¢6WDÆ7D÷VæVDFöÖ–äfÇ–÷WB†çVÆÂ“°¢ÒÂ¶Æö6F–öâçF†æÖUÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚÷VäFöÖ–äfÇ–÷WB’°¢&WGW&ã°¢Ð¢6WD66÷VçDÖVçT÷Vâ†fÇ6R“°¢6WEv÷&·76TÖVçT÷Vâ†fÇ6R“°¢6öç7Bfö7W4g&ÖRÒv–æF÷rç&WVW7Dæ–ÖF–öäg&ÖR‚‚’Óâ°¢6öç7Bf—'7D7F–öâÒFöÖ–äfÇ–÷WE&Vbæ7W'&VçCòçVW'•6VÆV7F÷#Ä…DÔÄVÆVÖVçCâ€¢u¶FFÖFöÖ–âÖfÇ–÷WB×&–Ö'“Ò'G'VR%ÒÂ¶‡&VeÒÂ'WGFöã¦æ÷B…¶F—6&ÆVEÒ’Â7VÖÖ'’p¢“°¢f—'7D7F–öãòæfö7W2‚“°¢Ò“°¢6öç7B†æFÆT¶W’Ò†WfVçC¢¶W–&ö&DWfVçB’Óâ°¢–b†WfVçBæ¶W’ÓÓÒtW66Rr’°¢WfVçBç&WfVçDFVfVÇB‚“°¢6öç7BG&–vvW"ÒFöÖ–åG&–vvW%&Vg2æ7W'&VçE¶÷VäFöÖ–äfÇ–÷WEÓ°¢6WD÷VäFöÖ–äfÇ–÷WB†çVÆÂ“°¢v–æF÷rç&WVW7Dæ–ÖF–öäg&ÖR‚‚’ÓâG&–vvW#òæfö7W2‚’“°¢&WGW&ã°¢Ð¢–b†WfVçBæ¶W’ÓÓÒuF"rbbFöÖ–äfÇ–÷WE&Vbæ7W'&VçB’°¢6öç7Bfö7W6&ÆRÒ'&’æg&öÒ€¢FöÖ–äfÇ–÷WE&Vbæ7W'&VçBçVW'•6VÆV7F÷$ÆÃÄ…DÔÄVÆVÖVçCâ€¢v¶‡&VeÒÂ'WGFöã¦æ÷B…¶F—6&ÆVEÒ’Â7VÖÖ'’Â·F&–æFW…Ó¦æ÷B…·F&–æFWƒÒ"Ó%Ò’p¢¢’æf–ÇFW"‚†VÆVÖVçB’ÓâVÆVÖVçBæöfg6WE&VçBÓÒçVÆÂÇÂVÆVÖVçBçFtæÖRÓÓÒu5TÔÔ%’r“°¢–b‚fö7W6&ÆRæÆVæwF‚’°¢&WGW&ã°¢Ð¢6öç7Bf—'7BÒfö7W6&ÆU³Ó°¢6öç7BÆ7BÒfö7W6&ÆU¶fö7W6&ÆRæÆVæwF‚ÒÓ°¢–b†WfVçBç6†–gD¶W’bbFö7VÖVçBæ7F—fTVÆVÖVçBÓÓÒf—'7B’°¢WfVçBç&WfVçDFVfVÇB‚“°¢Æ7Bæfö7W2‚“°¢&WGW&ã°¢Ð¢–b‚WfVçBç6†–gD¶W’bbFö7VÖVçBæ7F—fTVÆVÖVçBÓÓÒÆ7B’°¢WfVçBç&WfVçDFVfVÇB‚“°¢f—'7Bæfö7W2‚“°¢Ð¢Ð¢Ó°¢v–æF÷ræFDWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W’“°¢&WGW&â‚’Óâ°¢v–æF÷ræ6æ6VÄæ–ÖF–öäg&ÖR†fö7W4g&ÖR“°¢v–æF÷rç&VÖ÷fTWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W’“°¢Ó°¢ÒÂ¶÷VäFöÖ–äfÇ–÷WEÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b†6öÖÖæD÷Vâ’°¢6WD÷VäFöÖ–äfÇ–÷WB†çVÆÂ“°¢Ð¢ÒÂ¶6öÖÖæD÷VåÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚÷VäFöÖ–äfÇ–÷WBÇÂG—VöbFö7VÖVçBÓÓÒwVæFVf–æVBr’°¢&WGW&âVæFVf–æVC°¢Ð ¢6öç7B&ö÷BÒFö7VÖVçBæFö7VÖVçDVÆVÖVçC°¢6öç7B&öG’ÒFö7VÖVçBæ&öG“°¢6öç7B&Wf–÷W5&ö÷D÷fW&fÆ÷rÒ&ö÷Bç7G–ÆRæ÷fW&fÆ÷s°¢6öç7B&Wf–÷W4&öG”÷fW&fÆ÷rÒ&öG’ç7G–ÆRæ÷fW&fÆ÷s°¢&ö÷Bç7G–ÆRæ÷fW&fÆ÷rÒv†–FFVâs°¢&öG’ç7G–ÆRæ÷fW&fÆ÷rÒv†–FFVâs°¢&WGW&â‚’Óâ°¢&ö÷Bç7G–ÆRæ÷fW&fÆ÷rÒ&Wf–÷W5&ö÷D÷fW&fÆ÷s°¢&öG’ç7G–ÆRæ÷fW&fÆ÷rÒ&Wf–÷W4&öG”÷fW&fÆ÷s°¢Ó°¢ÒÂ¶÷VäFöÖ–äfÇ–÷WEÒ“° ¢W6TVffV7B‚‚’Óâ°¢6öç7B†æFÆT¶W”F÷vâÒ†WfVçC¢¶W–&ö&DWfVçB’Óâ°¢–b†WfVçBæFVfVÇE&WfVçFVBÇÂ—4VF—F&ÆUF&vWB†WfVçBçF&vWB’’°¢&WGW&ã°¢Ð ¢6öç7B¶W’ÒWfVçBæ¶W’çFôÆ÷vW$66R‚“°¢–b‚†WfVçBæÖWF¶W’ÇÂWfVçBæ7G&Ä¶W’’bb¶W’ÓÓÒv²r’°¢WfVçBç&WfVçDFVfVÇB‚“°¢6WD6öÖÖæD÷Vâ‡G'VR“°¢&WGW&ã°¢Ð¢–b‚†WfVçBæÖWF¶W’ÇÂWfVçBæ7G&Ä¶W’’bb¶W’ÓÓÒv"r’°¢WfVçBç&WfVçDFVfVÇB‚“°¢6WE6–FV&$6öÆÆ6VE&Vb‚†7W'&VçB’Óâ7W'&VçB“°¢&WGW&ã°¢Ð¢–b‚WfVçBæÖWF¶W’bbWfVçBæ7G&Ä¶W’bbWfVçBæÇD¶W’bb†¶W’ÓÓÒròrÇÂ¶W’ÓÓÒvbr’’°¢WfVçBç&WfVçDFVfVÇB‚“°¢6WD6öÖÖæD÷Vâ‡G'VR“°¢Ð¢Ó° ¢v–æF÷ræFDWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W”F÷vâ“°¢&WGW&â‚’Óâv–æF÷rç&VÖ÷fTWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W”F÷vâ“°¢ÒÂµÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBr’°¢&WGW&ã°¢Ð¢G'’°¢v–æF÷ræÆö6Å7F÷&vRç6WD—FVÒ…4”DT$%ô4ôÄÄ4TEõ5Dõ$tUô´U’Â6–FV&$6öÆÆ6VE&Vbòsr¢sr“°¢Ò6F6‚°¢òò7F÷&vRf–ÇW&R6†÷VÆBæ÷B'&V²F†RÆ–÷WBà¢Ð¢ÒÂ·6–FV&$6öÆÆ6VE&VeÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBr’°¢&WGW&ã°¢Ð¢G'’°¢v–æF÷ræÆö6Å7F÷&vRç6WD—FVÒ…4”DT$%õt”ED…õ5Dõ$tUô´U’Â7G&–ær‡6–FV&%v–GF‚’“°¢Ò6F6‚°¢òò7F÷&vRf–ÇW&R6†÷VÆBæ÷B'&V²F†RÆ–÷WBà¢Ð¢ÒÂ·6–FV&%v–GF…Ò“° ¢6öç7BFövvÆU6–FV&$6öÆÆ6VBÒW6T6ÆÆ&6²‚‚’Óâ°¢–b†—4æ'&÷uf–Ww÷'B’°¢&WGW&ã°¢Ð¢6WE6–FV&$6öÆÆ6VE&Vb‚†7W'&VçB’Óâ7W'&VçB“°¢ÒÂ¶—4æ'&÷uf–Ww÷'EÒ“° ¢6öç7B†æFÆU6–FV&%&W6—¦U7F'BÒ†WfVçC¢&V7Eö–çFW$WfVçCÄ…DÔÄF—dVÆVÖVçCâ’Óâ°¢–b†—4æ'&÷uf–Ww÷'B’°¢&WGW&ã°¢Ð¢–b†WfVçBæ'WGFöâÓÒ’°¢&WGW&ã°¢Ð¢WfVçBç&WfVçDFVfVÇB‚“°¢6öç7B†æFÆTVÂÒWfVçBæ7W'&VçEF&vWC°¢6öç7Bö–çFW$–BÒWfVçBçö–çFW$–C°¢6öç7B7F'D6Æ–VçE‚ÒWfVçBæ6Æ–VçEƒ°¢6–FV&%&W6—¦TÖ÷fVE&Vbæ7W'&VçBÒfÇ6S°¢òò6GW&RF†Rö–çFW"6òWfW'’7V'6WVVçBÖ÷fRòWò6æ6VÂf÷"F†—0¢òòvW7GW&R—2FVÆ—fW&VBFòF†R†æFÆRWfVâ–bF†RW6W"&VÆV6W2÷WG6–FRF†P¢òòf–Ww÷'BÂF†Rõ27FVÇ2fö7W2Â÷"F†R'&÷w6W"f—&W2ö–çFW&6æ6VÆà¢òòv—F†÷WBF†—2Â&VÆV6–æröfb×v–æF÷rÆVgB—4G&vv–æu6–FV&&7GV6²G'VP¢òòæBF†R&öG’7W'6÷#¢6öÂ×&W6—¦VòW6W"×6VÆV7C¢æöæV÷fW'&–FW0¢òòÆ–VBFòF†RVçF—&RvRà¢G'’°¢†æFÆTVÂç6WEö–çFW$6GW&R‡ö–çFW$–B“°¢Ò6F6‚°¢òò6öÖRFW7BVçf—&öæÖVçG2†§6FöÒ’FöâwB–×ÆVÖVçB6WEö–çFW$6GW&Rà¢òòfÆÆ–ærF‡&÷Vv‚—26fR(	BF†R6ÆVçW—27F–ÆÂv—&VBW&VÆ÷rà¢Ð¢6WD—4G&vv–æu6–FV&"‡G'VR“°¢6öç7B6–FV&$VÂÒ6–FV&%&Vbæ7W'&VçC°¢6öç7B7F'DÆVgBÒ6–FV&$VÂò6–FV&$VÂævWD&÷VæF–æt6Æ–VçE&V7B‚’æÆVgB¢°¢6öç7B†æFÆUö–çFW$Ö÷fRÒ†Ö÷fTWfVçC¢ö–çFW$WfVçB’Óâ°¢–b†Ö÷fTWfVçBçö–çFW$–BÓÒö–çFW$–B’°¢&WGW&ã°¢Ð¢–b„ÖF‚æ'2†Ö÷fTWfVçBæ6Æ–VçE‚Ò7F'D6Æ–VçE‚’âB’°¢6–FV&%&W6—¦TÖ÷fVE&Vbæ7W'&VçBÒG'VS°¢Ð¢6öç7B&÷÷6VBÒÖ÷fTWfVçBæ6Æ–VçE‚Ò7F'DÆVgC°¢–b‡&÷÷6VBÂ4”DT$%ô4ôÄÄ4UõD…$U4„ôÄB’°¢6WE6–FV&$6öÆÆ6VE&Vb‡G'VR“°¢&WGW&ã°¢Ð¢6öç7B6Æ×VBÒÖF‚æÖ–â…4”DT$%ôÔ…õt”ED‚ÂÖF‚æÖ‚…4”DT$%ôÔ”åôU…äDTEõt”ED‚Â&÷÷6VB’“°¢6WE6–FV&$6öÆÆ6VE&Vb†fÇ6R“°¢6WE6–FV&%v–GF‚†6Æ×VB“°¢Ó°¢6öç7B6ÆVçWÒ†6ÆVçWWfVçCó¢ö–çFW$WfVçB’Óâ°¢–b†6ÆVçWWfVçBbb6ÆVçWWfVçBçö–çFW$–BÓÒö–çFW$–B’°¢&WGW&ã°¢Ð¢6öç7B6†÷VÆEFövvÆRÒ6ÆVçWWfVçCòçG—RÓÓÒwö–çFW'Wrbb6–FV&%&W6—¦TÖ÷fVE&Vbæ7W'&VçC°¢6WD—4G&vv–æu6–FV&"†fÇ6R“°¢†æFÆTVÂç&VÖ÷fTWfVçDÆ—7FVæW"‚wö–çFW&Ö÷fRrÂ†æFÆUö–çFW$Ö÷fR“°¢†æFÆTVÂç&VÖ÷fTWfVçDÆ—7FVæW"‚wö–çFW'WrÂ6ÆVçW“°¢†æFÆTVÂç&VÖ÷fTWfVçDÆ—7FVæW"‚wö–çFW&6æ6VÂrÂ6ÆVçW“°¢†æFÆTVÂç&VÖ÷fTWfVçDÆ—7FVæW"‚vÆ÷7Gö–çFW&6GW&RrÂ6ÆVçW“°¢–b‡6†÷VÆEFövvÆR’°¢FövvÆU6–FV&$6öÆÆ6VB‚“°¢Ð¢Ó°¢†æFÆTVÂæFDWfVçDÆ—7FVæW"‚wö–çFW&Ö÷fRrÂ†æFÆUö–çFW$Ö÷fR“°¢†æFÆTVÂæFDWfVçDÆ—7FVæW"‚wö–çFW'WrÂ6ÆVçW“°¢†æFÆTVÂæFDWfVçDÆ—7FVæW"‚wö–çFW&6æ6VÂrÂ6ÆVçW“°¢òòÆ÷7Gö–çFW&6GW&Vf—&W2v†VæWfW"6GW&RVæG2f÷"ç’&V6öâ(	@¢òò–æ6ÇVF–ærF†Rõ26æ6VÆ–ærF†RvW7GW&R÷"F†RVÆVÖVçB&V–ærVæÖ÷VçFV@¢òò'’&V7Bâ—B—2F†RÖ÷7B&VÆ–&ÆRf–æÂ6ÆVçW6–væÂà¢†æFÆTVÂæFDWfVçDÆ—7FVæW"‚vÆ÷7Gö–çFW&6GW&RrÂ6ÆVçW“°¢Ó° ¢6öç7B†æFÆU6–FV&%&W6—¦T¶W”F÷vâÒ†WfVçC¢&V7D¶W–&ö&DWfVçCÄ…DÔÄF—dVÆVÖVçCâ’Óâ°¢–b†WfVçBæ¶W’ÓÒtVçFW"rbbWfVçBæ¶W’ÓÒrr’°¢&WGW&ã°¢Ð¢WfVçBç&WfVçDFVfVÇB‚“°¢FövvÆU6–FV&$6öÆÆ6VB‚“°¢Ó° ¢òò6fWG’æWC¢ç’F–ÖRvRÆVfRF†RG&vv–ær7FFRÂVç7W&RF†R&öG’7G–ÆP¢òò÷fW'&–FW2vRÆ–VB&R&VÆV6VBâÇ6ò†æFÆW2F†RVæÖ÷VçBÖÖ–BÖG&p¢òò66R†VffV7B6ÆVçW'Vç2öæ6RöâVæÖ÷VçB’v—F†÷WBÆVf–ærF†RFö7VÖVç@¢òò7GV6²–â7W'6÷#¢6öÂ×&W6—¦VòW6W"×6VÆV7C¢æöæVà¢W6TVffV7B‚‚’Óâ°¢–b‡G—VöbFö7VÖVçBÓÓÒwVæFVf–æVBr’°¢&WGW&ã°¢Ð¢–b†—4G&vv–æu6–FV&"’°¢Fö7VÖVçBæ&öG’ç7G–ÆRæ7W'6÷"Òv6öÂ×&W6—¦Rs°¢Fö7VÖVçBæ&öG’ç7G–ÆRçW6W%6VÆV7BÒvæöæRs°¢&WGW&â‚’Óâ°¢Fö7VÖVçBæ&öG’ç7G–ÆRç&VÖ÷fU&÷W'G’‚v7W'6÷"r“°¢Fö7VÖVçBæ&öG’ç7G–ÆRç&VÖ÷fU&÷W'G’‚wW6W"×6VÆV7Br“°¢Ó°¢Ð¢Fö7VÖVçBæ&öG’ç7G–ÆRç&VÖ÷fU&÷W'G’‚v7W'6÷"r“°¢Fö7VÖVçBæ&öG’ç7G–ÆRç&VÖ÷fU&÷W'G’‚wW6W"×6VÆV7Br“°¢&WGW&âVæFVf–æVC°¢ÒÂ¶—4G&vv–æu6–FV&%Ò“° ¢W6TVffV7B‚‚’Óâ°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBrÇÂG—VöbFö7VÖVçBÓÓÒwVæFVf–æVBr’°¢&WGW&ã°¢Ð ¢ÆWBg&ÖT”C¢çVÖ&W"ÂVæFVf–æVC°¢6öç7B&WVW7Dg&ÖRÐ¢v–æF÷rç&WVW7Dæ–ÖF–öäg&ÖRóò‚†6ÆÆ&6³¢g&ÖU&WVW7D6ÆÆ&6²’Óâv–æF÷rç6WEF–ÖV÷WB†6ÆÆ&6²Âb’“°¢6öç7B6æ6VÄg&ÖRÒv–æF÷ræ6æ6VÄæ–ÖF–öäg&ÖRóòv–æF÷ræ6ÆV%F–ÖV÷WC°¢6öç7BWFFTÖWG&–72Ò‚’Óâ°¢g&ÖT”BÒVæFVf–æVC°¢6öç7Bæf–vF÷$VÂÒ67&öÆÄæf–vF÷%&Vbæ7W'&VçC°¢6öç7BF‡VÖ$VÂÒ67&öÆÄæf–vF÷%F‡VÖ%&Vbæ7W'&VçC°¢–b‚æf–vF÷$VÂÇÂF‡VÖ$VÂ’°¢&WGW&ã°¢Ð¢6öç7B67&öÆÆ–ætVÆVÖVçBÒFö7VÖVçBç67&öÆÆ–ætVÆVÖVçBóòFö7VÖVçBæFö7VÖVçDVÆVÖVçC°¢6öç7Bf–Ww÷'D†V–v‡BÒv–æF÷ræ–ææW$†V–v‡BÇÂFö7VÖVçBæFö7VÖVçDVÆVÖVçBæ6Æ–VçD†V–v‡C°¢6öç7B67&öÆÄ†V–v‡BÒÖF‚æÖ‚€¢67&öÆÆ–ætVÆVÖVçBç67&öÆÄ†V–v‡BÀ¢Fö7VÖVçBæFö7VÖVçDVÆVÖVçBç67&öÆÄ†V–v‡BÀ¢Fö7VÖVçBæ&öG’ç67&öÆÄ†V–v‡@¢“°¢6öç7B67&öÆÅ&ævRÒ67&öÆÄ†V–v‡BÒf–Ww÷'D†V–v‡C° ¢–b‡67&öÆÅ&ævRÃÒ#BÇÂf–Ww÷'D†V–v‡BÃÒ’°¢æf–vF÷$VÂç7G–ÆRæ÷6—G’Òss°¢æf–vF÷$VÂç7G–ÆRçf—6–&–Æ—G’Òv†–FFVâs°¢&WGW&ã°¢Ð ¢6öç7BG&6µF÷ÒÖF‚æÖ–âƒs"ÂÖF‚æÖ‚ƒ#‚Âf–Ww÷'D†V–v‡B¢ãSR’“°¢6öç7BG&6´&÷GFöÒÒÖF‚æÖ–âƒcBÂÖF‚æÖ‚ƒ#‚Âf–Ww÷'D†V–v‡B¢ãCR’“°¢6öç7BG&6´†V–v‡BÒÖF‚æÖ‚ƒ#Âf–Ww÷'D†V–v‡BÒG&6µF÷ÒG&6´&÷GFöÒ“°¢6öç7BF‡VÖ$†V–v‡BÒÖF‚æÖ–â€¢45$ôÄÅôäd”tDõ%ôÔ…õD…TÔ%ô„T”t…BÀ¢ÖF‚æÖ‚…45$ôÄÅôäd”tDõ%ôÔ”åõD…TÔ%ô„T”t…BÂG&6´†V–v‡B¢ãb¢“°¢6öç7B67&öÆÅ&öw&W72ÒÖF‚æÖ–âƒÂÖF‚æÖ‚ƒÂ67&öÆÆ–ætVÆVÖVçBç67&öÆÅF÷ò67&öÆÅ&ævR’“°¢6öç7BF‡VÖ%F÷ÒG&6µF÷²‡G&6´†V–v‡BÒF‡VÖ$†V–v‡B’¢67&öÆÅ&öw&W73° ¢F‡VÖ$VÂç7G–ÆRæ†V–v‡BÒG·F‡VÖ$†V–v‡G×†°¢F‡VÖ$VÂç7G–ÆRçG&ç6f÷&ÒÒG&ç6ÆFS6BƒÂG·F‡VÖ%F÷×‚Â–°¢æf–vF÷$VÂç7G–ÆRæ÷6—G’Òss°¢æf–vF÷$VÂç7G–ÆRçf—6–&–Æ—G’Òwf—6–&ÆRs°¢Ó°¢6öç7B66†VGVÆUWFFRÒ‚’Óâ°¢–b†g&ÖT”BÓÒVæFVf–æVB’°¢&WGW&ã°¢Ð¢g&ÖT”BÒ&WVW7Dg&ÖR‡WFFTÖWG&–72“°¢Ó° ¢WFFTÖWG&–72‚“°¢v–æF÷ræFDWfVçDÆ—7FVæW"‚w67&öÆÂrÂ66†VGVÆUWFFRÂ²76—fS¢G'VRÒ“°¢v–æF÷ræFDWfVçDÆ—7FVæW"‚w&W6—¦RrÂ66†VGVÆUWFFR“° ¢6öç7Bö'6W'fW"Ð¢G—Vöb&W6—¦Tö'6W'fW"ÓÓÒwVæFVf–æVBp¢òçVÆÀ¢¢æWr&W6—¦Tö'6W'fW"‚‚’Óâ°¢66†VGVÆUWFFR‚“°¢Ò“°¢ö'6W'fW#òæö'6W'fR†Fö7VÖVçBæFö7VÖVçDVÆVÖVçB“°¢ö'6W'fW#òæö'6W'fR†Fö7VÖVçBæ&öG’“° ¢&WGW&â‚’Óâ°¢–b†g&ÖT”BÓÒVæFVf–æVB’°¢6æ6VÄg&ÖR†g&ÖT”B“°¢Ð¢v–æF÷rç&VÖ÷fTWfVçDÆ—7FVæW"‚w67&öÆÂrÂ66†VGVÆUWFFR“°¢v–æF÷rç&VÖ÷fTWfVçDÆ—7FVæW"‚w&W6—¦RrÂ66†VGVÆUWFFR“°¢ö'6W'fW#òæF—66öææV7B‚“°¢Ó°¢ÒÂ¶Æö6F–öâçF†æÖUÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBrÇÂG—Vöbv–æF÷ræÖF6„ÖVF–ÓÒvgVæ7F–öâr’°¢&WGW&ã°¢Ð¢6öç7B×ÂÒv–æF÷ræÖF6„ÖVF–‚r†Ö‚×v–GFƒ¢“c‚’r“°¢6öç7BWFFRÒ‚’Óâ6WD—4æ'&÷uf–Ww÷'B†×ÂæÖF6†W2“°¢WFFR‚“°¢–b‡G—Vöb×ÂæFDWfVçDÆ—7FVæW"ÓÓÒvgVæ7F–öâr’°¢×ÂæFDWfVçDÆ—7FVæW"‚v6†ævRrÂWFFR“°¢&WGW&â‚’Óâ×Âç&VÖ÷fTWfVçDÆ—7FVæW"‚v6†ævRrÂWFFR“°¢Ð¢òò6f&’ÂBfÆÆ&6²à¢×ÂæFDÆ—7FVæW"‡WFFR“°¢&WGW&â‚’Óâ×Âç&VÖ÷fTÆ—7FVæW"‡WFFR“°¢ÒÂµÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚66÷VçDÖVçT÷Vâ’°¢&WGW&ã°¢Ð¢6öç7B†æFÆT6Æ–6²Ò†WfVçC¢Ö÷W6TWfVçB’Óâ°¢–b‚66÷VçDÖVçU&Vbæ7W'&VçBÇÂ66÷VçDÖVçU&Vbæ7W'&VçBæ6öçF–ç2†WfVçBçF&vWB2æöFR’’°¢&WGW&ã°¢Ð¢6WD66÷VçDÖVçT÷Vâ†fÇ6R“°¢Ó°¢6öç7B†æFÆT¶W’Ò†WfVçC¢¶W–&ö&DWfVçB’Óâ°¢–b†WfVçBæ¶W’ÓÓÒtW66Rr’°¢6WD66÷VçDÖVçT÷Vâ†fÇ6R“°¢Ð¢Ó°¢v–æF÷ræFDWfVçDÆ—7FVæW"‚vÖ÷W6VF÷vârÂ†æFÆT6Æ–6²“°¢v–æF÷ræFDWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W’“°¢&WGW&â‚’Óâ°¢v–æF÷rç&VÖ÷fTWfVçDÆ—7FVæW"‚vÖ÷W6VF÷vârÂ†æFÆT6Æ–6²“°¢v–æF÷rç&VÖ÷fTWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W’“°¢Ó°¢ÒÂ¶66÷VçDÖVçT÷VåÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚v÷&·76TÖVçT÷Vâ’°¢&WGW&ã°¢Ð¢6öç7B†æFÆT6Æ–6²Ò†WfVçC¢Ö÷W6TWfVçB’Óâ°¢–b‚v÷&·76TÖVçU&Vbæ7W'&VçBÇÂv÷&·76TÖVçU&Vbæ7W'&VçBæ6öçF–ç2†WfVçBçF&vWB2æöFR’’°¢&WGW&ã°¢Ð¢6WEv÷&·76TÖVçT÷Vâ†fÇ6R“°¢Ó°¢6öç7B†æFÆT¶W’Ò†WfVçC¢¶W–&ö&DWfVçB’Óâ°¢–b†WfVçBæ¶W’ÓÓÒtW66Rr’°¢6WEv÷&·76TÖVçT÷Vâ†fÇ6R“°¢Ð¢Ó°¢v–æF÷ræFDWfVçDÆ—7FVæW"‚vÖ÷W6VF÷vârÂ†æFÆT6Æ–6²“°¢v–æF÷ræFDWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W’“°¢&WGW&â‚’Óâ°¢v–æF÷rç&VÖ÷fTWfVçDÆ—7FVæW"‚vÖ÷W6VF÷vârÂ†æFÆT6Æ–6²“°¢v–æF÷rç&VÖ÷fTWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W’“°¢Ó°¢ÒÂ·v÷&·76TÖVçT÷VåÒ“° ¢–b‚66÷R’°¢&WGW&âÄ6†VÆÄÆöF–ærÖW76vSÒ%&W6öÇf–ærv÷&·76R66÷R"óã°¢Ð ¢6öç7B&uv÷&·76TÆ&VÂÒf÷&ÖE66÷TF—7Æ’‡66÷Rçv÷&·76T”B“°¢6öç7BÆöö·4Æ–¶U6ÇVrÒõå¶×£Ó•Õ¶×£Ó’åòÕÒ¢Bö’çFW7B‡&uv÷&·76TÆ&VÂ“°¢6öç7Bv÷&·76TF—7Æ”æÖRÒÆöö·4Æ–¶U6ÇVp¢ò&uv÷&·76TÆ&VÂç&WÆ6R‚õ²ÕõÒ²örÂrr’ç&WÆ6R‚õÆ%ÇrörÂ†6‚’Óâ6‚çFõWW$66R‚’¢¢&uv÷&·76TÆ&VÂÇÂuv÷&·76Rs°¢6öç7BW6W$F—7Æ”æÖRÒt66÷VçBs°¢6öç7BW6W$VÖ–ÂÒrs°¢6öç7BW6W$–æ—F–ÂÒ‡v÷&·76TF—7Æ”æÖRæ6†$Bƒ’ÇÂtr’çFõWW$66R‚“°¢6öç7B6öÆÆ6U6†÷'F7WBÒf÷&ÖEÆFf÷&Õ6†÷'F7WB‚t"r“°¢6öç7Bf–æFW%6†÷'F7WBÒf÷&ÖEÆFf÷&Õ6†÷'F7WB‚t²r“°¢6öç7B'Vä6öÖÖæBÒ†—FVÓ¢6öÖÖæEÆWGFT—FVÒ’Óâ°¢6WD6öÖÖæD÷Vâ†fÇ6R“°¢6WD÷VäFöÖ–äfÇ–÷WB†çVÆÂ“°¢6WDÆ7D÷VæVDFöÖ–äfÇ–÷WB†çVÆÂ“°¢–b†—FVÒçF‚’°¢æf–vFR†—FVÒçF‚“°¢&WGW&ã°¢Ð¢—FVÒæ7F–öãòâ‚“°¢Ó°¢6öç7B6Æ÷6TFöÖ–äfÇ–÷WBÒ‚’Óâ6WD÷VäFöÖ–äfÇ–÷WB†çVÆÂ“°¢6öç7B&W6WDFöÖ–äfÇ–÷WD†–v†Æ–v‡BÒ‚’Óâ°¢6WD÷VäFöÖ–äfÇ–÷WB†çVÆÂ“°¢6WDÆ7D÷VæVDFöÖ–äfÇ–÷WB†çVÆÂ“°¢Ó°¢6öç7BFövvÆTFöÖ–äfÇ–÷WBÒ†FöÖ–ã¢6÷W&6U&÷f–FW"’Óâ°¢6WD66÷VçDÖVçT÷Vâ†fÇ6R“°¢6WEv÷&·76TÖVçT÷Vâ†fÇ6R“°¢6WD6öÖÖæD÷Vâ†fÇ6R“°¢6WDÆ7D÷VæVDFöÖ–äfÇ–÷WB†FöÖ–â“°¢6WD÷VäFöÖ–äfÇ–÷WB‚†7W'&VçB’Óâ†7W'&VçBÓÓÒFöÖ–âòçVÆÂ¢FöÖ–â’“°¢Ó°¢6öç7B&VÖVÖ&W&VDFöÖ–ä†–v†Æ–v‡BÐ¢Æ7D÷VæVDFöÖ–äfÇ–÷WBbbf—6–&ÆTFöÖ–ä÷&FW"æ–æ6ÇVFW2†Æ7D÷VæVDFöÖ–äfÇ–÷WB’òÆ7D÷VæVDFöÖ–äfÇ–÷WB¢çVÆÃ°¢6öç7BFöÖ–äfÇ–÷WD÷vç5&÷WFT†–v†Æ–v‡BÒ&ööÆVâ†÷VäFöÖ–äfÇ–÷WBÇÂ‚7F—fTFöÖ–âbb&VÖVÖ&W&VDFöÖ–ä†–v†Æ–v‡B’“° ¢&WGW&â€¢Å&öGV7DW'&÷$&÷VæF'“à¢ÆF—`¢6Æ74æÖS×¶–GBÖ×6†VÆÂ–GBÖÖ6öç6öÆRÖÆ–÷WBG·6–FV&$6öÆÆ6VBòr—2×6–FV&"Ö6öÆÆ6VBr¢rwÒG¶—4G&vv–æu6–FV&"òr—2×6–FV&"ÖG&vv–ærr¢rwÒG¶÷VäFöÖ–äfÇ–÷WBòr—2ÖFöÖ–âÖfÇ–÷WBÖ÷Vâr¢rwÖÐ¢FF×FVæçC×·66÷RçFVæçD”GÐ¢FF×v÷&·76S×·66÷Rçv÷&·76T”GÐ¢7G–ÆS×°¢&VæFW&VE6–FV&%v–GF‚ÓÒVæFVf–æV@¢ò‡²²rÒÖ–GB×6–FV&"×v–GF‚r27G&–æuÓ¢G·&VæFW&VE6–FV&%v–GF‡×†Ò2555&÷W'F–W2¢¢VæFVf–æV@¢Ð¢à¢Æ6–FP¢&Vc×·6–FV&%&VgÐ¢6Æ74æÖSÒ&–GBÖ×6–FV&" ¢&–ÖÆ&VÃÒ%v÷&·76Ræf–vF–öâ ¢FFÖ6öÆÆ6VC×·6–FV&$6öÆÆ6VBòwG'VRr¢vfÇ6RwÐ¢à¢ÆF—`¢6Æ74æÖS×¶–GBÖ×6–FV&"×&W6—¦RÖ†æFÆRG¶—4G&vv–æu6–FV&"òr—2ÖG&vv–ærr¢rwÒG¶—56–FV&$VFvTfö7W6VBòr—2Öfö7W6VBr¢rwÒG¶÷VäFöÖ–äfÇ–÷WBòr—2ÖFöÖ–âÖfÇ–÷WBÖ&Æö6¶VBr¢rwÖÐ¢&öÆSÒ'6W&F÷" ¢F$–æFWƒ×¶÷VäFöÖ–äfÇ–÷WBòÓ¢Ð¢&–Ö÷&–VçFF–öãÒ'fW'F–6Â ¢&–ÖÆ&VÃ×¶G·6–FV&$6öÆÆ6VBòtW‡æBr¢t6öÆÆ6RwÒ6–FV&"âG&rFò&W6—¦RæÐ¢öåö–çFW$F÷vã×¶†æFÆU6–FV&%&W6—¦U7F'GÐ¢öä¶W”F÷vã×¶†æFÆU6–FV&%&W6—¦T¶W”F÷vçÐ¢öäfö7W3×²‚’Óâ6WD—56–FV&$VFvTfö7W6VB‡G'VR—Ð¢öä&ÇW#×²‚’Óâ6WD—56–FV&$VFvTfö7W6VB†fÇ6R—Ð¢à¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"×&W6—¦R×FööÇF—"&–Ö†–FFVãÒ'G'VR#à¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"×&W6—¦R×FööÇF—×&÷r#à¢Ç7ãç·6–FV&$6öÆÆ6VBòt6Æ–6²FòW‡æBr¢t6Æ–6²Fò6öÆÆ6RwÓÂ÷7ãà¢Æ¶&Cç¶6öÆÆ6U6†÷'F7WGÓÂö¶&Cà¢Â÷7ãà¢Ç7ãäG&rFò&W6—¦SÂ÷7ãà¢Â÷7ãà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖ×6–FV&"×v÷&·76R"&Vc×·v÷&·76TÖVçU&VgÓà¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ×6–FV&"×v÷&·76R×G&–vvW" ¢&–Ö†7÷WÒ&ÖVçR ¢&–ÖW‡æFVC×·v÷&·76TÖVçT÷VçÐ¢&–ÖÆ&VÃ×¶v÷&·76S¢G·v÷&·76TF—7Æ”æÖWÒâ÷Vâ7v—F6†W"æÐ¢öä6Æ–6³×²‚’Óâ°¢6WD÷VäFöÖ–äfÇ–÷WB†çVÆÂ“°¢6WEv÷&·76TÖVçT÷Vâ‚‡fÇVR’ÓâfÇVR“°¢×Ð¢F—FÆS×·6–FV&$6öÆÆ6VBòv÷&·76TF—7Æ”æÖR¢VæFVf–æVGÐ¢à¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"ÖÖ&²"&–Ö†–FFVãÒ'G'VR#à¢Æ–Ör7&3Ò"ö–FVçG&–ÂÖÆövòçær"ÇCÒ""&–Ö†–FFVãÒ'G'VR"óà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"×v÷&·76RÖ6÷’#à¢Ç7G&öæsç·v÷&·76TF—7Æ”æÖWÓÂ÷7G&öæsà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"×v÷&·76RÖ6&WB"&–Ö†–FFVãÒ'G'VR#à¢Ä6†Wg&öäF÷vâ6—¦S×³'Ò7G&ö¶Uv–GFƒ×³'Òóà¢Â÷7ãà¢Âö'WGFöãà¢·v÷&·76TÖVçT÷Vâò€¢ÆF—b6Æ74æÖSÒ&–GBÖ×6–FV&"×v÷&·76RÖÖVçR"&öÆSÒ&ÖVçR#à¢ÆF—b6Æ74æÖSÒ&–GBÖ×6–FV&"×v÷&·76RÖÖWF#à¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"×v÷&·76RÖÖWFÖW–V'&÷r#ä7W'&VçBv÷&·76SÂ÷7ãà¢Ç7G&öæsç·v÷&·76TF—7Æ”æÖWÓÂ÷7G&öæsà¢ÂöF—cà¢ÄÆ–æ°¢&öÆSÒ&ÖVçV—FVÒ ¢Fó×¶G¶&6UF‡Ò÷v÷&·76W6Ð¢öä6Æ–6³×²‚’Óâ°¢6WEv÷&·76TÖVçT÷Vâ†fÇ6R“°¢&W6WDFöÖ–äfÇ–÷WD†–v†Æ–v‡B‚“°¢×Ð¢à¢7v—F6‚v÷&·76P¢ÂôÆ–æ³à¢ÄÆ–æ°¢&öÆSÒ&ÖVçV—FVÒ ¢Fó×¶G¶&6UF‡Ò÷6WGF–æw6Ð¢öä6Æ–6³×²‚’Óâ°¢6WEv÷&·76TÖVçT÷Vâ†fÇ6R“°¢&W6WDFöÖ–äfÇ–÷WD†–v†Æ–v‡B‚“°¢×Ð¢à¢6WGF–æw0¢ÂôÆ–æ³à¢ÄÆ–æ°¢&öÆSÒ&ÖVçV—FVÒ ¢FóÒ"ööæ&ö&F–ærö÷&r ¢öä6Æ–6³×²‚’Óâ°¢6WEv÷&·76TÖVçT÷Vâ†fÇ6R“°¢&W6WDFöÖ–äfÇ–÷WD†–v†Æ–v‡B‚“°¢×Ð¢à¢7&VFRv÷&·76P¢ÂôÆ–æ³à¢ÂöF—cà¢’¢çVÆÇÐ¢ÂöF—cà ¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ×V–6²Öf–æB ¢öä6Æ–6³×²‚’Óâ6WD6öÖÖæD÷Vâ‡G'VR—Ð¢&–ÖÆ&VÃÒ$÷Vâv÷&·76Rf–æFW" ¢F—FÆS×·6–FV&$6öÆÆ6VBòf–æB‚G¶f–æFW%6†÷'F7WGÒ–¢VæFVf–æVGÐ¢à¢Ç7â6Æ74æÖSÒ&–GBÖ×V–6²Öf–æBÖ–6öâ"&–Ö†–FFVãÒ'G'VR#à¢Å6V&6‚6—¦S×³GÒ7G&ö¶Uv–GFƒ×³'Òóà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖ×V–6²Öf–æBÖÆ&VÂ#äf–æCÂ÷7ãà¢Æ¶&B6Æ74æÖSÒ&–GBÖ×V–6²Öf–æBÖ¶W’#ç¶f–æFW%6†÷'F7WGÓÂö¶&Cà¢Âö'WGFöãà ¢¶÷VäFöÖ–äfÇ–÷WBò€¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖFöÖ–âÖfÇ–÷WB×6–FV&"Ö&6¶G&÷ ¢&–Ö†–FFVãÒ'G'VR ¢F$–æFWƒ×²ÓÐ¢öä6Æ–6³×¶6Æ÷6TFöÖ–äfÇ–÷WGÐ¢óà¢’¢çVÆÇÐ ¢Ææb6Æ74æÖSÒ&–GBÖ×6†VÆÂÖæb"&–ÖÆ&VÃÒ$6V7F–öç2#à¢ÄædÆ–æ°¢Fó×¶&6UF‡Ð¢Væ@¢&–ÖÆ&VÃÒ$÷fW'f–Wr ¢F—FÆS×·6–FV&$6öÆÆ6VBòt÷fW'f–Wrr¢VæFVf–æVGÐ¢6Æ74æÖS×²‡²—47F—fRÒ’Óâ†—47F—fRbbFöÖ–äfÇ–÷WD÷vç5&÷WFT†–v†Æ–v‡Bòv7F—fRr¢VæFVf–æVB—Ð¢öä6Æ–6³×·&W6WDFöÖ–äfÇ–÷WD†–v†Æ–v‡GÐ¢à¢Ç7â6Æ74æÖSÒ&–GBÖÖæbÖ–6öâ"&–Ö†–FFVãÒ'G'VR#à¢ÄÆ–÷WDF6†&ö&B6—¦S×³gÒ7G&ö¶Uv–GFƒ×³ãsWÒóà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖÖæbÖÆ&VÂ#ä÷fW'f–WsÂ÷7ãà¢ÂôædÆ–æ³à¢·f—6–&ÆTFöÖ–ä÷&FW"æÖ‚†FöÖ–â’Óâ°¢6öç7B6öæf–rÒ$ôET5EôDôÔ”åô4ôäd”u5¶FöÖ–åÓ°¢6öç7Bf–Æ&–Æ—G’Ò6÷W&6Tf–Æ&–Æ—G•¶FöÖ–åÓ°¢6öç7B—4÷VâÒ÷VäFöÖ–äfÇ–÷WBÓÓÒFöÖ–ã°¢6öç7B—47F—fRÐ¢†7F—fTFöÖ–âÓÓÒFöÖ–âbb‚÷VäFöÖ–äfÇ–÷WBÇÂ—4÷Vâ’’ÇÀ¢‚÷VäFöÖ–äfÇ–÷WBbb7F—fTFöÖ–âbb&VÖVÖ&W&VDFöÖ–ä†–v†Æ–v‡BÓÓÒFöÖ–â“°¢6öç7BG&–vvW$”BÒ–GBÒG¶FöÖ–çÒÖFöÖ–â×G&–vvW&°¢&WGW&â€¢ÆF—b¶W“×¶FöÖ–çÒ6Æ74æÖS×¶–GBÖÖFöÖ–âÖæbÖ—FVÒG¶—4÷Vâòr—2Ö÷Vâr¢rwÖÓà¢Æ'WGFöà¢–C×·G&–vvW$”GÐ¢&Vc×²†æöFR’Óâ°¢FöÖ–åG&–vvW%&Vg2æ7W'&VçE¶FöÖ–åÒÒæöFS°¢×Ð¢G—SÒ&'WGFöâ ¢6Æ74æÖS×¶–GBÖÖæbÖFöÖ–â×G&–vvW"G¶—47F—fRòr—2Ö7F—fRr¢rwÒG¶—4÷Vâòr—2Ö÷Vâr¢rwÖÐ¢FFÖ6öææV7F÷"Öf–Æ&ÆS×¶f–Æ&–Æ—G’æf–Æ&ÆRòwG'VRr¢vfÇ6RwÐ¢&–Ö†7÷WÒ&F–Æör ¢&–ÖW‡æFVC×¶—4÷VçÐ¢&–Ö6öçG&öÇ3×¶—4÷Vâò–GBÒG¶FöÖ–çÒÖFöÖ–âÖfÇ–÷WF¢VæFVf–æVGÐ¢&–ÖÆ&VÃ×¶6öæf–ræædÆ&VÇÐ¢F—FÆS×°¢6–FV&$6öÆÆ6V@¢ò6öæf–ræædÆ&VÀ¢¢f–Æ&–Æ—G’æf–Æ&ÆP¢òf–Æ&–Æ—G’çVæf–Æ&ÆTÖW76vRóòuVæf–Æ&ÆRp¢¢VæFVf–æV@¢Ð¢öä6Æ–6³×²‚’ÓâFövvÆTFöÖ–äfÇ–÷WB†FöÖ–â—Ð¢à¢Ç7â6Æ74æÖSÒ&–GBÖÖæbÖ–6öâ"&–Ö†–FFVãÒ'G'VR#à¢Å6–FV&$FöÖ–ä–6öâFöÖ–ã×¶FöÖ–çÒóà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖÖæbÖÆ&VÂ#ç¶6öæf–ræædÆ&VÇÓÂ÷7ãà¢Ä6†Wg&öäF÷vâ6Æ74æÖSÒ&–GBÖÖæbÖF—66Æ÷7W&R"6—¦S×³7Ò7G&ö¶Uv–GFƒ×³ã‡Ò&–Ö†–FFVãÒ'G'VR"óà¢Âö'WGFöãà¢¶—4÷Vâò€¢Å&öGV7DFöÖ–äfÇ–÷W@¢FöÖ–ã×¶FöÖ–çÐ¢66÷S×·66÷WÐ¢7F—fU&÷WFT”C×¶7F—fTFöÖ–å&÷WFT”GÐ¢Æ&VÆÆVD'“×·G&–vvW$”GÐ¢æVÅ&Vc×¶FöÖ–äfÇ–÷WE&VgÐ¢öä6Æ÷6S×¶6Æ÷6TFöÖ–äfÇ–÷WGÐ¢óà¢’¢çVÆÇÐ¢ÂöF—cà¢“°¢Ò—Ð¢ÄædÆ–æ°¢Fó×¶G¶&6UF‡Ò÷&W÷'G6Ð¢&–ÖÆ&VÃÒ%&W÷'G2 ¢F—FÆS×·6–FV&$6öÆÆ6VBòu&W÷'G2r¢VæFVf–æVGÐ¢6Æ74æÖS×²‡²—47F—fRÒ’Óâ†—47F—fRbbFöÖ–äfÇ–÷WD÷vç5&÷WFT†–v†Æ–v‡Bòv7F—fRr¢VæFVf–æVB—Ð¢öä6Æ–6³×·&W6WDFöÖ–äfÇ–÷WD†–v†Æ–v‡GÐ¢à¢Ç7â6Æ74æÖSÒ&–GBÖÖæbÖ–6öâ"&–Ö†–FFVãÒ'G'VR#à¢Ä&$6†'C26—¦S×³gÒ7G&ö¶Uv–GFƒ×³ãsWÒóà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖÖæbÖÆ&VÂ#å&W÷'G3Â÷7ãà¢ÂôædÆ–æ³à¢ÄædÆ–æ°¢Fó×¶G¶&6UF‡Ò÷6WGF–æw6Ð¢&–ÖÆ&VÃÒ%6WGF–æw2 ¢F—FÆS×·6–FV&$6öÆÆ6VBòu6WGF–æw2r¢VæFVf–æVGÐ¢6Æ74æÖS×²‡²—47F—fRÒ’Óâ†—47F—fRbbFöÖ–äfÇ–÷WD÷vç5&÷WFT†–v†Æ–v‡Bòv7F—fRr¢VæFVf–æVB—Ð¢öä6Æ–6³×·&W6WDFöÖ–äfÇ–÷WD†–v†Æ–v‡GÐ¢à¢Ç7â6Æ74æÖSÒ&–GBÖÖæbÖ–6öâ"&–Ö†–FFVãÒ'G'VR#à¢Å6WGF–æw4–6öâ6—¦S×³gÒ7G&ö¶Uv–GFƒ×³ãsWÒóà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖÖæbÖÆ&VÂ#å6WGF–æw3Â÷7ãà¢ÂôædÆ–æ³à¢Âöæcà ¢ÆF—b6Æ74æÖSÒ&–GBÖ×6–FV&"Öfö÷FW"#à¢ÆF—b6Æ74æÖSÒ&–GBÖ×6–FV&"Ö66÷VçB"&Vc×¶66÷VçDÖVçU&VgÓà¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ×6–FV&"Ö66÷VçB×G&–vvW" ¢&–Ö†7÷WÒ&ÖVçR ¢&–ÖW‡æFVC×¶66÷VçDÖVçT÷VçÐ¢&–ÖÆ&VÃ×¶66÷VçBÖVçRf÷"G·W6W$F—7Æ”æÖWÖÐ¢öä6Æ–6³×²‚’Óâ°¢6WD÷VäFöÖ–äfÇ–÷WB†çVÆÂ“°¢6WD66÷VçDÖVçT÷Vâ‚†7W'&VçB’Óâ7W'&VçB“°¢×Ð¢F—FÆS×·6–FV&$6öÆÆ6VBòW6W$F—7Æ”æÖR¢VæFVf–æVGÐ¢à¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"Ö66÷VçBÖfF""&–Ö†–FFVãÒ'G'VR#à¢·W6W$–æ—F–ÇÐ¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"Ö66÷VçBÖæÖR#à¢Ç7G&öæsç·W6W$F—7Æ”æÖWÓÂ÷7G&öæsà¢·W6W$VÖ–ÂbbW6W$VÖ–ÂÓÒW6W$F—7Æ”æÖRòÇ7ãç·W6W$VÖ–ÇÓÂ÷7ãâ¢çVÆÇÐ¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖ×6–FV&"Ö66÷VçBÖ6&WB"&–Ö†–FFVãÒ'G'VR#à¢Ä6†Wg&öåW6—¦S×³'Ò7G&ö¶Uv–GFƒ×³'Òóà¢Â÷7ãà¢Âö'WGFöãà¢¶66÷VçDÖVçT÷Vâò€¢ÆF—b6Æ74æÖSÒ&–GBÖ×6–FV&"Ö66÷VçBÖÖVçR"&öÆSÒ&ÖVçR#à¢ÆF—b6Æ74æÖSÒ&–GBÖ×6–FV&"Ö66÷VçBÖÖWF#à¢Ç7G&öæsç·W6W$F—7Æ”æÖWÓÂ÷7G&öæsà¢·W6W$VÖ–ÂòÇ7ãç·W6W$VÖ–ÇÓÂ÷7ãâ¢çVÆÇÐ¢ÂöF—cà¢Æ¢&öÆSÒ&ÖVçV—FVÒ ¢‡&VcÒ&‡GG3¢òöv—F‡V"æ6öÒö–FVçG&–Âö–FVçG&–Âö—77VW2 ¢F&vWCÒ%ö&Ææ² ¢&VÃÒ&æö÷VæW"æ÷&VfW'&W" ¢öä6Æ–6³×²‚’Óâ6WD66÷VçDÖVçT÷Vâ†fÇ6R—Ð¢à¢Ä†VÇ6—&6ÆR6—¦S×³GÒ7G&ö¶Uv–GFƒ×³ãsWÒ&–Ö†–FFVãÒ'G'VR"óà¢†VÇf×²fVVF&6°¢Âöà¢ÄÆ–æ²&öÆSÒ&ÖVçV—FVÒ"FóÒ"ò"öä6Æ–6³×²‚’Óâ6WD66÷VçDÖVçT÷Vâ†fÇ6R—Óà¢ÄW‡FW&æÄÆ–æ²6—¦S×³GÒ7G&ö¶Uv–GFƒ×³ãsWÒ&–Ö†–FFVãÒ'G'VR"óà¢Ö&¶WF–ær6—FP¢ÂôÆ–æ³à¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢&öÆSÒ&ÖVçV—FVÒ ¢öä6Æ–6³×²‚’Óâ°¢6WD66÷VçDÖVçT÷Vâ†fÇ6R“°¢æf–vFR‚rööÆöv÷WBrÂ²&WÆ6S¢G'VRÒ“°¢×Ð¢à¢ÄÆöt÷WB6—¦S×³GÒ7G&ö¶Uv–GFƒ×³ãsWÒ&–Ö†–FFVãÒ'G'VR"óà¢6–vâ÷W@¢Âö'WGFöãà¢ÂöF—cà¢’¢çVÆÇÐ¢ÂöF—cà¢ÂöF—cà¢Âö6–FSà ¢¶÷VäFöÖ–äfÇ–÷WBò€¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖFöÖ–âÖfÇ–÷WBÖ&6¶G&÷ ¢&–ÖÆ&VÃÒ$6Æ÷6RFöÖ–â6V7F–öâÖVçR ¢öä6Æ–6³×¶6Æ÷6TFöÖ–äfÇ–÷WGÐ¢óà¢’¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GBÖÖ6öç6öÆR#à¢ÆÖ–â6Æ74æÖSÒ&–GBÖ×6†VÆÂÖÖ–â#à¢Ä÷WFÆWBóà¢ÂöÖ–ãà¢ÂöF—cà¢ÆF—`¢&Vc×·67&öÆÄæf–vF÷%&VgÐ¢6Æ74æÖSÒ&–GBÖ×67&öÆÂÖæf–vF÷" ¢&–Ö†–FFVãÒ'G'VR ¢à¢Ç7â&Vc×·67&öÆÄæf–vF÷%F‡VÖ%&VgÒ6Æ74æÖSÒ&–GBÖ×67&öÆÂÖæf–vF÷"×F‡VÖ""óà¢ÂöF—cà¢ÂöF—cà¢Ä6öÖÖæEÆWGFP¢÷Vã×¶6öÖÖæD÷VçÐ¢—FV×3×¶6öÖÖæD—FV×7Ð¢öä6Æ÷6S×²‚’Óâ6WD6öÖÖæD÷Vâ†fÇ6R—Ð¢öå6VÆV7C×·'Vä6öÖÖæGÐ¢óà¢Âõ&öGV7DW'&÷$&÷VæF'“à¢“°§Ð ¦gVæ7F–öâf÷&ÖE&VÆF—fUF–ÖR‡fÇVS¢7G&–ær“¢7G&–ær°¢6öç7B'6VBÒæWrFFR‡fÇVR“°¢–b„çVÖ&W"æ—4æâ‡'6VBævWEF–ÖR‚’’’°¢&WGW&âfÇVS°¢Ð¢6öç7BF–fd×2ÒFFRææ÷r‚’Ò'6VBævWEF–ÖR‚“°¢6öç7BF–fdÖ–çWFW2ÒÖF‚ç&÷VæB†F–fd×2òc“°¢–b†F–fdÖ–çWFW2Â’&WGW&âv§W7Bæ÷rs°¢–b†F–fdÖ–çWFW2Âc’&WGW&âG¶F–fdÖ–çWFW7ÖÒvö°¢6öç7BF–fd†÷W'2ÒÖF‚ç&÷VæB†F–fdÖ–çWFW2òc“°¢–b†F–fd†÷W'2Â#B’&WGW&âG¶F–fd†÷W'7Ö‚vö°¢6öç7BF–fdF—2ÒÖF‚ç&÷VæB†F–fd†÷W'2ò#B“°¢–b†F–fdF—2Âr’&WGW&âG¶F–fdF—7ÖBvö°¢&WGW&â'6VBçFôÆö6ÆTFFU7G&–ær‡VæFVf–æVBÂ²ÖöçFƒ¢w6†÷'BrÂF“¢vçVÖW&–2rÒ“°§Ð ¦gVæ7F–öâ7VÖÖ&—¦U66äf–ÇW&R‡66ã¢&Wõ66å&V6÷&B“¢7G&–ær°¢6öç7BÖW76vRÒ‡66âæW'&÷%öÖW76vRÇÂrr’çG&–Ò‚“°¢–b‚ÖW76vR’°¢&WGW&âtf–ÆVBv—F†÷WB&W÷'FVB&V6öâs°¢Ð¢6öç7BÆ÷vW&VBÒÖW76vRçFôÆ÷vW$66R‚“°¢–b†Æ÷vW&VBæ–æ6ÇVFW2‚w&FRÆ–Ö—Br’ÇÂÆ÷vW&VBæ–æ6ÇVFW2‚w6V6öæF'’&FRr’’°¢&WGW&ât†—Bv—D‡V"&FRÆ–Ö—Bs°¢Ð¢–b†Æ÷vW&VBæ–æ6ÇVFW2‚wF–ÖV÷WBr’ÇÂÆ÷vW&VBæ–æ6ÇVFW2‚wF–ÖVB÷WBr’’°¢&WGW&âu66âF–ÖVB÷WBs°¢Ð¢–b†Æ÷vW&VBæ–æ6ÇVFW2‚wVæWF†÷"r’ÇÂÆ÷vW&VBæ–æ6ÇVFW2‚sCr’ÇÂÆ÷vW&VBæ–æ6ÇVFW2‚wFö¶Vâr’ÇÂÆ÷vW&VBæ–æ6ÇVFW2‚v7&VFVçF–Âr’’°¢&WGW&âtWF†VçF–6F–öâf–ÆVB(	B&V6öææV7BF†R6÷W&6Rs°¢Ð¢–b†Æ÷vW&VBæ–æ6ÇVFW2‚væ÷Bf÷VæBr’ÇÂÆ÷vW&VBæ–æ6ÇVFW2‚sCBr’’°¢&WGW&âu&W÷6—F÷'’æ÷Bf÷VæB÷"66W72&Wfö¶VBs°¢Ð¢–b†Æ÷vW&VBæ–æ6ÇVFW2‚vf÷&&–Br’ÇÂÆ÷vW&VBæ–æ6ÇVFW2‚sC2r’’°¢&WGW&ât66W72f÷&&–FFVâ(	B6†V6²W&Ö—76–öç2s°¢Ð¢–b†ÖW76vRæÆVæwF‚ÃÒ“b’°¢&WGW&âÖW76vS°¢Ð¢&WGW&âG¶ÖW76vRç6Æ–6RƒÂ“2—Òââæ°§Ð §G—R66äw&÷WÒ°¢&V6öã¢7G&–æs°¢7FGW3¢7G&–æs°¢6÷VçC¢çVÖ&W#°¢ÆFW7C¢&Wõ66å&V6÷&C°¢&W÷3¢7G&–æuµÓ°§Ó° ¦gVæ7F–öâ7VÖÖ&—¦U7V66W76gVÅ&Wõ66â‡66ã¢&Wõ66å&V6÷&B“¢7G&–ær°¢6öç7B'G2Ò¶f÷&ÖD6÷VçDÆ&VÂ‡66âæf–æF–æuö6÷VçBóòÂvf–æF–ærr•Ó°¢–b„çVÖ&W"æ—4f–æ—FR‡66âæf–ÆW5÷66ææVB’’°¢'G2çW6‚†f÷&ÖD6÷VçDÆ&VÂ‡66âæf–ÆW5÷66ææVBÂvf–ÆRr’“°¢Ð¢6öç7B6÷W&6T†VÇF‚Ò7VÖÖ&—¦U&Wõ66å6÷W&6T†VÇF‚‡66â“°¢–b‡6÷W&6T†VÇF‚’°¢'G2çVç6†–gB‡6÷W&6T†VÇF‚“°¢Ð¢&WGW&â'G2æ¦ö–â‚r+rr“°§Ð ¦gVæ7F–öâw&÷W&V6VçE66ç2‡66ç3¢&Wõ66å&V6÷&EµÒ“¢66äw&÷WµÒ°¢6öç7Bw&÷W3¢66äw&÷WµÒÒµÓ°¢66ç2æf÷$V6‚‚‡66â’Óâ°¢6öç7B7FGW2Òæ÷&ÖÆ—¦UfÇVR‡66âç7FGW2’çFôÆ÷vW$66R‚“°¢6öç7B—4f–ÇW&RÒ7FGW2ÓÓÒvf–ÆVBrÇÂ7FGW2ÓÓÒv6æ6VÆVBs°¢6öç7B&V6öâÒ—4f–ÇW&P¢ò7VÖÖ&—¦U66äf–ÇW&R‡66â¢¢7FGW2ÓÓÒw7V66VVFVBrÇÂ7FGW2ÓÓÒv6ö×ÆWFVBp¢ò7VÖÖ&—¦U7V66W76gVÅ&Wõ66â‡66â¢¢t–â&öw&W72s°¢6öç7B&WòÒ6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡66âç&W÷6—F÷'’’ÇÂ66âç&W÷6—F÷'“°¢6öç7BÆ7BÒw&÷W5¶w&÷W2æÆVæwF‚ÒÓ°¢òòöæÇ’6öÆÆ6R6öç6V7WF—fRf–ÇW&W2v—F‚F†R6ÖR&V6öââ7V66W76gVÂæ@¢òò'Vææ–ær66ç2&R–æFWVæFVçBWfVçG2WfVâv†VâF†V—"‡VÖâ×&VF&ÆP¢òò7VÖÖ'’†Vç2FòÖF6‚Â6òvR&VæFW"V6‚2—G2÷vâ&÷rFò&W6W'fP¢òò67W&FR7F—f—G’†—7F÷'’à¢–b†—4f–ÇW&RbbÆ7BbbÆ7Bç7FGW2ÓÓÒ7FGW2bbÆ7Bç&V6öâÓÓÒ&V6öâ’°¢Æ7Bæ6÷VçB³Ò°¢–b‚Æ7Bç&W÷2æ–æ6ÇVFW2‡&Wò’’°¢Æ7Bç&W÷2çW6‚‡&Wò“°¢Ð¢&WGW&ã°¢Ð¢w&÷W2çW6‚‡²&V6öâÂ7FGW2Â6÷VçC¢ÂÆFW7C¢66âÂ&W÷3¢·&WõÒÒ“°¢Ò“°¢&WGW&âw&÷W3°§Ð ¦6öç7B”åd•DUõ4´•TEõ5Dõ$tUô´U’Òv–GC¦÷fW'f–Ws¦–çf—FR×6¶—VBs°¢òò&Wf–÷W2¶W’F†B6†—VB'&–VfÇ’&WGvVVâF†Rf—'7BGvò"&Wf—6–öç2â¶WB6ð¢òòç’W6W"v†òÇ&VG’6Æ–6¶VB–çf—FR†æBW'6—7FVBF†RöÆBfÆr’FöW2æ÷B6VP¢òòF†R6†V6¶Æ—7B&Vw&W72à¦6öç7B”åd•DUôÄTt5•õ5Dõ$tUô´U’Òv–GC¦÷fW'f–Ws¦–çf—FRÖF—6Ö—76VBs° ¦gVæ7F–öâ–çf—FU66÷T¶W’‡FVæçD”C¢7G&–ærÂVæFVf–æVBÂv÷&·76T”C¢7G&–ærÂVæFVf–æVB“¢7G&–ærÂçVÆÂ°¢–b‚FVæçD”BÇÂv÷&·76T”B’°¢&WGW&âçVÆÃ°¢Ð¢&WGW&âG·FVæçD”GÓ¢G·v÷&·76T”GÖ°§Ð ¦gVæ7F–öâ&VD–çf—FU6¶—VB‡FVæçD”C¢7G&–ærÂVæFVf–æVBÂv÷&·76T”C¢7G&–ærÂVæFVf–æVB“¢&ööÆVâ°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBr’°¢&WGW&âfÇ6S°¢Ð¢6öç7B66÷RÒ–çf—FU66÷T¶W’‡FVæçD”BÂv÷&·76T”B“°¢–b‚66÷R’°¢&WGW&âfÇ6S°¢Ð¢G'’°¢–b‡v–æF÷ræÆö6Å7F÷&vRævWD—FVÒ†G´”åd•DUõ4´•TEõ5Dõ$tUô´U—Ó¢G·66÷WÖ’ÓÓÒsr’°¢&WGW&âG'VS°¢Ð¢òòF†RV&Æ–W"–GC¦÷fW'f–Ws¦–çf—FRÖF—6Ö—76VF¶W’v2Ç6òFVæçB×66÷VB–à¢òòF†R&Wf–÷W2&Wf—6–öâÂ6ò†öæ÷&–ær—B†W&R—26fR(	B—BæWfW"7&÷76V@¢òòFVæçG2âF†Rv÷&·76RÖöæÇ’ÆVv7’¶W—2&R–çFVçF–öæÆÇ’äõB6öç7VÇFV@¢òò6ò6¶—–âFVæçBæòÆöævW"ÆV·2–çFòFVæçB"F†B†Vç2Fð¢òò&WW6RF†R6ÖRv÷&·76R6ÇVr–âF†R6ÖR'&÷w6W"&öf–ÆRà¢&WGW&âv–æF÷ræÆö6Å7F÷&vRævWD—FVÒ†G´”åd•DUôÄTt5•õ5Dõ$tUô´U—Ó¢G·66÷WÖ’ÓÓÒss°¢Ò6F6‚°¢&WGW&âfÇ6S°¢Ð§Ð ¦gVæ7F–öâW'6—7D–çf—FU6¶—VB‡FVæçD”C¢7G&–ærÂVæFVf–æVBÂv÷&·76T”C¢7G&–ærÂVæFVf–æVB“¢fö–B°¢–b‡G—Vöbv–æF÷rÓÓÒwVæFVf–æVBr’°¢&WGW&ã°¢Ð¢6öç7B66÷RÒ–çf—FU66÷T¶W’‡FVæçD”BÂv÷&·76T”B“°¢–b‚66÷R’°¢&WGW&ã°¢Ð¢G'’°¢v–æF÷ræÆö6Å7F÷&vRç6WD—FVÒ†G´”åd•DUõ4´•TEõ5Dõ$tUô´U—Ó¢G·66÷WÖÂsr“°¢òòG&÷F†RÖF6†–ærFVæçB×66÷VBÆVv7’¶W’öâF†R6ÖR66÷RÂ'WBFòäõ@¢òòF÷V6‚F†RVç66÷VBv÷&·76RÖöæÇ’¶W—2F†BÖ’&VÆöærFò÷F†W"FVæçG2à¢v–æF÷ræÆö6Å7F÷&vRç&VÖ÷fT—FVÒ†G´”åd•DUôÄTt5•õ5Dõ$tUô´U—Ó¢G·66÷WÖ“°¢Ò6F6‚°¢òò7F÷&vRf–ÇW&W2&RæöâÖfFÂà¢Ð§Ð ¦W‡÷'BgVæ7F–öâ&öGV7D÷fW'f–WuvR‚’°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“°¢6öç7B²fVGW&W3¢&6¶VæDfVGW&W2ÒÒW6T&6¶VæDfVGW&W2‡²Væ&ÆVC¢4„õTÄEôÄôEô4ôääT5Dõ%ô$4´TäEôdTEU$U2Ò“°¢6öç7B6÷W&6Tf–Æ&–Æ—G’ÒW6TÖVÖò‚‚’Óâ'V–ÆE6÷W&6Tf–Æ&–Æ—G’†&6¶VæDfVGW&W2’Â¶&6¶VæDfVGW&W5Ò“°¢6öç7B·6†÷uF÷W"Â6WE6†÷uF÷W%ÒÒW6U7FFR†fÇ6R“°¢6öç7B¶ÆöF–ærÂ6WDÆöF–æuÒÒW6U7FFR‡G'VR“°¢6öç7B¶W'&÷"Â6WDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B¶7F—fU&ö¦V7G2Â6WD7F—fU&ö¦V7G5ÒÒW6U7FFSÅ&ö¦V7E&V6÷&EµÓâ…µÒ“°¢6öç7B·&Wõ66ç2Â6WE&Wõ66ç5ÒÒW6U7FFSÅ&Wõ66å&V6÷&EµÓâ…µÒ“°¢6öç7B¶f–ÆVE66ä6÷VçBÂ6WDf–ÆVE66ä6÷VçEÒÒW6U7FFRƒ“°¢6öç7B·&Wôf–æF–æw2Â6WE&Wôf–æF–æw5ÒÒW6U7FFSÄ”f–æF–æuµÓâ…µÒ“°¢6öç7B·6÷W&6T6öææV7F–öå&öÆÇW2Â6WE6÷W&6T6öææV7F–öå&öÆÇW5ÒÒW6U7FFSÄ÷fW'f–Wt6öææV7F–öå&öÆÇW3â€¢V×G”÷fW'f–Wt6öææV7F–öå&öÆÇW2‚¢“°¢6öç7B¶†4†—7F÷&–6Å7V66W76gVÅ66âÂ6WD†4†—7F÷&–6Å7V66W76gVÅ66åÒÒW6U7FFR†fÇ6R“°¢6öç7B·66ä†—7F÷'”6ö×ÆWFRÂ6WE66ä†—7F÷'”6ö×ÆWFUÒÒW6U7FFR‡G'VR“°¢6öç7B¶f–æF–æw4†—7F÷'”6ö×ÆWFRÂ6WDf–æF–æw4†—7F÷'”6ö×ÆWFUÒÒW6U7FFR‡G'VR“°¢6öç7B¶v—F‡V$6öææV7F–öå&öÆÇWÂ6WDv—F‡V$6öææV7F–öå&öÆÇWÒÒW6U7FFSÄ÷fW'f–Wtv—D‡V$6öææV7F–öå&öÆÇWâ€¢V×G”÷fW'f–Wtv—D‡V$6öææV7F–öå&öÆÇW‚¢“°¢6öç7B²Â6WD–çf—FU6¶—F–6µÒÒW6U7FFRƒ“°¢6öç7B¶6öææV7F÷$6öæf–wW&VDg&öÔöæ&ö&F–ærÂ6WD6öææV7F÷$6öæf–wW&VDg&öÔöæ&ö&F–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶öæ&ö&F–æt6öææV7F÷%&÷f–FW"Â6WDöæ&ö&F–æt6öææV7F÷%&÷f–FW%ÒÒW6U7FFSÅ6÷W&6U&÷f–FW"ÂçVÆÃâ†çVÆÂ“° ¢W6TVffV7B‚‚’Óâ°¢6öç7BFVæçD”BÒ66÷SòçFVæçD”C°¢6öç7Bv÷&·76T”BÒ66÷Sòçv÷&·76T”C°¢–b‚dTEU$Uôôä$ô$D”äuõt•¤$BÇÂFVæçD”BÇÂv÷&·76T”B’°¢6WE6†÷uF÷W"†fÇ6R“°¢6WD6öææV7F÷$6öæf–wW&VDg&öÔöæ&ö&F–ær†fÇ6R“°¢6WDöæ&ö&F–æt6öææV7F÷%&÷f–FW"†çVÆÂ“°¢&WGW&ã°¢Ð¢ÆWBÖ÷VçFVBÒG'VS°¢òò&W6WB–ÖÖVF–FVÇ’v†Vâ66÷R6†ævW26ò7FÆRöæ&ö&F–ærFF6ææ÷@¢òò&ÆVVB6öææV7F÷"Ö6ö×ÆWFR7FFR–çFòæ÷F†W"v÷&·76Rà¢6WD6öææV7F÷$6öæf–wW&VDg&öÔöæ&ö&F–ær†fÇ6R“°¢6WDöæ&ö&F–æt6öææV7F÷%&÷f–FW"†çVÆÂ“°¢6öç7B'VâÒ7–æ2‚’Óâ°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBævWDöæ&ö&F–æu7FFR‡²FVæçD”BÂv÷&·76T”BÒ“°¢–b‚Ö÷VçFVB’°¢&WGW&ã°¢Ð¢6öç7B7FFRÒ&W7öç6Rç7FFS°¢6öç7Böæ&ö&F–ætÖF6†W566÷RÐ¢æ÷&ÖÆ—¦UfÇVR‡7FFRæ÷&uö–Bóòrr’ÓÓÒFVæçD”Bb`¢æ÷&ÖÆ—¦UfÇVR‡7FFRçv÷&·76Uö–Bóòrr’ÓÓÒv÷&·76T”C°¢6WE6†÷uF÷W"€¢öæ&ö&F–ætÖF6†W566÷Rbb7FFRæ7W'&VçE÷7FWÓÓÒv6ö×ÆWFRrbb7FFRæF6†&ö&E÷F÷W%öF—6Ö—76VEö@¢“°¢òò6÷W&6RÖ6†V6¶Æ—7B6–væÃ¢F†RW6W"f–æ—6†VBF†R6öææV7B7FW–bV—F†W ¢òò6öææV7F÷%ö–Bv2W'6—7FVB÷"öæ&ö&F–ær&öw&W76VB7Bv6öææV7Bp¢òòv—F†÷WBâW‡Æ–6—B6¶—âF†—2fö–G2F†RfÇ6RæVvF—fRv†W&R¢òò6öææV7F÷"W†—7G2'WBæò66â†2'Vâ–WB‡v†–6‚v÷VÆB÷F†W'v—6RÆVfP¢òòF†R6†V6¶Æ—7Bf÷&WfW"7GV6²B$6öææV7B6÷W&6R"’à¢6öç7B7FW57D6öææV7C¢&VFöæÇ”'&“ÇG—Vöb7FFRæ7W'&VçE÷7FWâÒ²w66ârÂv–çf—FRrÂv6ö×ÆWFRuÓ°¢6öç7B&V6†VD6öææV7BÐ¢öæ&ö&F–ætÖF6†W566÷Rb`¢„&ööÆVâ‡7FFRæ6öææV7F÷%ö–B’ÇÀ¢‚7FFRæ6öææV7F÷%÷6¶—VBbb7FW57D6öææV7Bæ–æ6ÇVFW2‡7FFRæ7W'&VçE÷7FW’’“°¢6WD6öææV7F÷$6öæf–wW&VDg&öÔöæ&ö&F–ær‡&V6†VD6öææV7B“°¢6WDöæ&ö&F–æt6öææV7F÷%&÷f–FW"‡&V6†VD6öææV7Bòæ÷&ÖÆ—¦U6÷W&6U&÷f–FW"‡7FFRæ6öææV7F÷%÷G—R’¢çVÆÂ“°¢Ò6F6‚°¢–b†Ö÷VçFVB’°¢6WE6†÷uF÷W"†fÇ6R“°¢6WD6öææV7F÷$6öæf–wW&VDg&öÔöæ&ö&F–ær†fÇ6R“°¢6WDöæ&ö&F–æt6öææV7F÷%&÷f–FW"†çVÆÂ“°¢Ð¢Ð¢Ó°¢fö–B'Vâ‚“°¢&WGW&â‚’Óâ°¢Ö÷VçFVBÒfÇ6S°¢Ó°¢ÒÂ·66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”EÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚66÷R’°¢6WDW'&÷"‚t6†ö÷6Rv÷&·76R&Vf÷&RÆöF–ærF†R÷fW'f–Wrâr“°¢6WDÆöF–ær†fÇ6R“°¢6WE6÷W&6T6öææV7F–öå&öÆÇW2†V×G”÷fW'f–Wt6öææV7F–öå&öÆÇW2‚’“°¢6WD†4†—7F÷&–6Å7V66W76gVÅ66â†fÇ6R“°¢6WDf–ÆVE66ä6÷VçBƒ“°¢6WE66ä†—7F÷'”6ö×ÆWFR‡G'VR“°¢6WDf–æF–æw4†—7F÷'”6ö×ÆWFR‡G'VR“°¢6WDv—F‡V$6öææV7F–öå&öÆÇW†V×G”÷fW'f–Wtv—D‡V$6öææV7F–öå&öÆÇW‚’“°¢&WGW&ã°¢Ð ¢ÆWBÖ÷VçFVBÒG'VS°¢6öç7BÆöD÷fW'f–WrÒ7–æ2‚’Óâ°¢6öç7B&WVW7E6W76–öåfW'6–öâÒ7W'&VçE&öGV7DWF…6W76–öåfW'6–öâ‚“°¢6WDÆöF–ær‡G'VR“°¢6WDW'&÷"‚rr“°¢6WD†4†—7F÷&–6Å7V66W76gVÅ66â†fÇ6R“°¢6WDf–ÆVE66ä6÷VçBƒ“°¢6WE66ä†—7F÷'”6ö×ÆWFR‡G'VR“°¢6WDf–æF–æw4†—7F÷'”6ö×ÆWFR‡G'VR“°¢6WDv—F‡V$6öææV7F–öå&öÆÇW†V×G”÷fW'f–Wtv—D‡V$6öææV7F–öå&öÆÇW‚’“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢6öç7B7F—fU&ö¦V7D—FV×2Òv—BÆ—7D÷fW'f–Wu&ö¦V7G2‡66÷Rçv÷&·76T”BÂ²–æ6ÇVFUö&6†—fVC¢fÇ6RÒÂWF‚“°¢–b‚Ö÷VçFVBÇÂ—47W'&VçE&öGV7DWF…6W76–öåfW'6–öâ‡&WVW7E6W76–öåfW'6–öâ’’°¢&WGW&ã°¢Ð¢&–ÖTVçf—&öæÖVçE66÷T66†R‡66÷RÂ7F—fU&ö¦V7D—FV×2“°¢6öç7B·66å&W7öç6RÂf–æF–æu&W7öç6RÂ6öææV7F–öå&öÆÇW2Âv—F‡V$6öææV7F–öå&öÆÇWÒÒv—B&öÖ—6RæÆÂ…°¢Æ—7D÷fW'f–Wu66ç2†WF‚’À¢”6Æ–VçBæÆ—7E&Wôf–æF–æw2€¢°¢Æ–Ö—C¢õdU%d”Uuôd”äD”äuôÄ”Ô•BÀ¢Æ–fV7–6ÆU÷7FGW3¢v÷VârÀ¢6÷'Eö'“¢w6WfW&—G’rÀ¢6÷'Eö÷&FW#¢vFW62p¢ÒÀ¢WF€¢’À¢ÆöD÷fW'f–Wt6öææV7F–öå&öÆÇW2‡66÷RÂ7F—fU&ö¦V7D—FV×2Â6÷W&6Tf–Æ&–Æ—G’ÂWF‚’À¢ÆöD÷fW'f–Wtv—D‡V$6öææV7F–öå&öÆÇW‡66÷RÂ7F—fU&ö¦V7D—FV×2Â6÷W&6Tf–Æ&–Æ—G’æv—F‡V"ÂWF‚¢Ò“°¢–b‚Ö÷VçFVBÇÂ—47W'&VçE&öGV7DWF…6W76–öåfW'6–öâ‡&WVW7E6W76–öåfW'6–öâ’’°¢&WGW&ã°¢Ð¢6WD7F—fU&ö¦V7G2€¢7F—fU&ö¦V7D—FV×0¢ç6Æ–6R‚¢ç6÷'B‚†ÆVgBÂ&–v‡B’ÓâæWrFFR‡&–v‡BçWFFVEöB’ævWEF–ÖR‚’ÒæWrFFR†ÆVgBçWFFVEöB’ævWEF–ÖR‚’¢“°¢6WE&Wõ66ç2‡66å&W7öç6Ræ—FV×2“°¢6WD†4†—7F÷&–6Å7V66W76gVÅ66â‡66å&W7öç6Ræ†57V66W76gVÅ66â“°¢6WDf–ÆVE66ä6÷VçB‡66å&W7öç6Ræf–ÆVE66ä6÷VçB“°¢6WE66ä†—7F÷'”6ö×ÆWFR‡66å&W7öç6Ræ†—7F÷'”6ö×ÆWFR“°¢6WE&Wôf–æF–æw2€¢f–æF–æu&W7öç6Ræ—FV×0¢ç6Æ–6R‚¢ç6÷'B‚†ÆVgBÂ&–v‡B’Óâ6WfW&—G•&æ²‡&–v‡Bç6WfW&—G’’Ò6WfW&—G•&æ²†ÆVgBç6WfW&—G’’¢“°¢6WDf–æF–æw4†—7F÷'”6ö×ÆWFR‚f–æF–æu&W7öç6RææW‡Eö7W'6÷#òçG&–Ò‚’“°¢6WDv—F‡V$6öææV7F–öå&öÆÇW†v—F‡V$6öææV7F–öå&öÆÇW“°¢6WE6÷W&6T6öææV7F–öå&öÆÇW2†6öææV7F–öå&öÆÇW2“°¢&–ÖTv—D‡V$6öçG&öÄ6VçFW$FF66†R€¢66÷RÀ¢7F—fU&ö¦V7D—FV×2À¢6÷W&6Tf–Æ&–Æ—G’æv—F‡V"À¢WF‚À¢v—F‡V$6öææV7F–öå&öÆÇWæFVfVÇD6öææV7F–öà¢“°¢Ò6F6‚†W'"’°¢–b‚Ö÷VçFVBÇÂ—47W'&VçE&öGV7DWF…6W76–öåfW'6–öâ‡&WVW7E6W76–öåfW'6–öâ’’°¢&WGW&ã°¢Ð¢6WDW'&÷"†f÷&ÖD”W'&÷"†W'"ÂuVæ&ÆRFòÆöBv÷&·76R÷fW'f–Wrr’“°¢6WE6÷W&6T6öææV7F–öå&öÆÇW2†V×G”÷fW'f–Wt6öææV7F–öå&öÆÇW2‚’“°¢6WD†4†—7F÷&–6Å7V66W76gVÅ66â†fÇ6R“°¢6WDf–ÆVE66ä6÷VçBƒ“°¢6WE66ä†—7F÷'”6ö×ÆWFR‡G'VR“°¢6WDf–æF–æw4†—7F÷'”6ö×ÆWFR‡G'VR“°¢6WDv—F‡V$6öææV7F–öå&öÆÇW†V×G”÷fW'f–Wtv—D‡V$6öææV7F–öå&öÆÇW‚’“°¢Òf–æÆÇ’°¢–b†Ö÷VçFVBbb—47W'&VçE&öGV7DWF…6W76–öåfW'6–öâ‡&WVW7E6W76–öåfW'6–öâ’’°¢6WDÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢fö–BÆöD÷fW'f–Wr‚“° ¢&WGW&â‚’Óâ°¢Ö÷VçFVBÒfÇ6S°¢Ó°¢ÒÂ°¢66÷SòçFVæçD”BÀ¢66÷Sòçv÷&·76T”BÀ¢66÷Sòç&ö¦V7D”BÀ¢6÷W&6Tf–Æ&–Æ—G’æw2æf–Æ&ÆRÀ¢6÷W&6Tf–Æ&–Æ—G’æv—F‡V"æf–Æ&ÆRÀ¢6÷W&6Tf–Æ&–Æ—G’æ·V&W&æWFW2æf–Æ&ÆP¢Ò“° ¢6öç7BF—6Ö—75F÷W"Ò7–æ2‚’Óâ°¢6WE6†÷uF÷W"†fÇ6R“°¢G'’°¢v—B”6Æ–VçBçWFFTöæ&ö&F–æu7FFR‡²F6†&ö&E÷F÷W%öF—6Ö—76VC¢G'VRÒ“°¢Ò6F6‚°¢òòF†RF6†&ö&B6†÷VÆB&VÖ–âW6&ÆRWfVâ–bF÷W"F—6Ö—76Â6ææ÷BW'6—7Bà¢Ð¢Ó° ¢6öç7B÷Väf–æF–æw2Ò&Wôf–æF–æw2æf–ÇFW"‚†f–æF–ær’Óâæ÷&ÖÆ—¦Tf–æF–æu7FGW2†f–æF–ærçG&–vSòç7FGW2’ÓÓÒv÷Vâr“°¢6öç7B†–v…&–÷&—G”f–æF–æw2Ò÷Väf–æF–æw2æf–ÇFW"‚†f–æF–ær’Óâ°¢6öç7B6WfW&—G’Òæ÷&ÖÆ—¦UfÇVR†f–æF–ærç6WfW&—G’’çFôÆ÷vW$66R‚“°¢&WGW&â6WfW&—G’ÓÓÒv7&—F–6ÂrÇÂ6WfW&—G’ÓÓÒv†–v‚s°¢Ò“°¢6öç7BvVçF–5&—6´f–æF–æw2Ò÷Väf–æF–æw2æf–ÇFW"†—4vVçF–5&—6´f–æF–ær“°¢6öç7B7V66VVFVE66ä6÷VçBÒ&Wõ66ç2æf–ÇFW"‚‡66â’Óâ°¢6öç7Bæ÷&ÖÆ—¦VBÒæ÷&ÖÆ—¦UfÇVR‡66âç7FGW2’çFôÆ÷vW$66R‚“°¢&WGW&âæ÷&ÖÆ—¦VBÓÓÒw7V66VVFVBrÇÂæ÷&ÖÆ—¦VBÓÓÒv6ö×ÆWFVBs°¢Ò’æÆVæwFƒ°¢6öç7Bw5F‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂvw2r’¢rös°¢6öç7Bw46öææV7EF‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂvw2ö6öææV7Br’¢rös°¢6öç7Bw4v÷fW&ææ6UF‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂvw2öv÷fW&ææ6Rr’¢rös°¢6öç7Bv—F‡V%F‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"r’¢rös°¢6öç7Bv—F‡V$7F–öå&ö¦V7D”BÐ¢v—F‡V$6öææV7F–öå&öÆÇWæ6öææV7FVE&ö¦V7D”Bóòv—F‡V$6öææV7F–öå&öÆÇWæ6öææV7F÷%&ö¦V7D”C°¢6öç7Bv—F‡V$7F–öåF‚ÒVæDVçf—&öæÖVçEVW'’†v—F‡V%F‚Âv—F‡V$7F–öå&ö¦V7D”B“°¢6öç7Bf–æF–æw5F‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"öf–æF–æw2r’¢rös°¢6öç7Bv—F‡V%&VÖVF–F–öåF‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"÷&VÖVF–F–öâr’¢rös°¢6öç7Bv—F‡V$vVçF–5&—6µF‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"övVçF–2×&—6²r’¢rös°¢6öç7B·V&W&æWFW5F‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂv·V&W&æWFW2r’¢rös°¢6öç7B·V&W&æWFW46öææV7EF‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂv·V&W&æWFW2ö6öææV7Br’¢rös°¢6öç7Bv÷&·76W5F‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂwv÷&·76W2r’¢rös°¢6öç7B6öææV7E6÷W&6W5&÷f–FW"ÒDôÔ”åôäeôõ$DU"æf–æB‚‡&÷f–FW"’Óâ6÷W&6Tf–Æ&–Æ—G•·&÷f–FW%Òæf–Æ&ÆR’óòvw2s°¢6öç7B6öææV7E6÷W&6W5F‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂG¶6öææV7E6÷W&6W5&÷f–FW'Òö6öææV7F’¢rös°¢6öç7B†4ç•7V66W76gVÅ66âÒ7V66VVFVE66ä6÷VçBâÇÂ†4†—7F÷&–6Å7V66W76gVÅ66ã°¢6öç7Bw5&öÆÇWÒ6÷W&6T6öææV7F–öå&öÆÇW2æw3°¢6öç7B·V&W&æWFW5&öÆÇWÒ6÷W&6T6öææV7F–öå&öÆÇW2æ·V&W&æWFW3°¢òò6÷W&6R6÷VçG226öæf–wW&VBv†VâV—F†W"†’öæ&ö&F–ær&V6÷&G2¢òò6öææV7F÷"6öæf–wW&F–öâöâF†Rv÷&·76RÂ†"’ç’66â†2'Vâ‡–÷R6âw@¢òò66âv—F†÷WB6öææV7F÷"’Â†2’v—D‡V"&W÷'G2âW†—7F–æræöâ×VæF–æp¢òò6öææV7F÷"Â÷"†B’u2ô·V&W&æWFW2&W÷'Bâ7F—fRVçf—&öæÖVçB6öææV7F÷"à¢òòVæF–ærv—D‡V"ôWF‚×W7B&VÖ–â–æ6ö×ÆWFR6ò—B6ææ÷B–çf—FR66à¢òò&Vf÷&R–ç7FÆÆF–öâf–æ—6†W2à¢6öç7B†46öææV7FVE6÷W&6RÐ¢6öææV7F÷$6öæf–wW&VDg&öÔöæ&ö&F–ærÇÀ¢v—F‡V$6öææV7F–öå&öÆÇWæ6öæf–wW&VD6öææV7F÷$6÷VçBâÇÀ¢&Wõ66ç2æÆVæwF‚âÇÀ¢w5&öÆÇWæ6öææV7FVD6÷VçBâÇÀ¢·V&W&æWFW5&öÆÇWæ6öææV7FVD6÷VçBâ°¢6öç7B†4v—D‡V$f–æF–ætWf–FVæ6RÒ&Wôf–æF–æw2æÆVæwF‚â°¢6öç7B†4Ö÷&Tv—D‡V$f–æF–æw2Òf–æF–æw4†—7F÷'”6ö×ÆWFS°¢6öç7B†4v—D‡V$Wf–FVæ6RÒ&Wõ66ç2æÆVæwF‚âÇÂ†4v—D‡V$f–æF–ætWf–FVæ6S°¢6öç7B†4v—D‡V$6ö×ÆWFVDWf–FVæ6RÒ†4ç•7V66W76gVÅ66âÇÂ†4v—D‡V$f–æF–ætWf–FVæ6S°¢6öç7B†4v—D‡V$6öææV7F÷$Wf–FVæ6RÐ¢†4v—D‡V$Wf–FVæ6RÇÀ¢öæ&ö&F–æt6öææV7F÷%&÷f–FW"ÓÓÒvv—F‡V"rÇÀ¢v—F‡V$6öææV7F–öå&öÆÇWæ6öææV7F÷$6÷VçBâÇÀ¢v—F‡V$6öææV7F–öå&öÆÇWç7FGW46†V6·4–æ6ö×ÆWFS°¢6öç7B†4v—D‡V$6öææV7F÷$æVVG5&Wf–WrÒv—F‡V$6öææV7F–öå&öÆÇWæFVw&FVD6÷VçBâ°¢6öç7B†4v—D‡V$6öææV7F÷%VæF–ærÒv—F‡V$6öææV7F–öå&öÆÇWçVæF–æt6÷VçBâ°¢6öç7B†4v—D‡V$6öææV7F–öå7FGW4–æ6ö×ÆWFRÒv—F‡V$6öææV7F–öå&öÆÇWç7FGW46†V6·4–æ6ö×ÆWFS°¢6öç7B†4v—D‡V$6öææV7F÷$GFVçF–öâÐ¢†4v—D‡V$6öææV7F÷$æVVG5&Wf–WrÇÂ†4v—D‡V$6öææV7F÷%VæF–ærÇÂ†4v—D‡V$6öææV7F–öå7FGW4–æ6ö×ÆWFS°¢6öç7B†47F—fTv—D‡V%66âÒ&Wõ66ç2ç6öÖR‚‡66â’Óâ—47F—fU66å7FGW2‡66âç7FGW2’“°¢6öç7B†4v—D‡V%66åv—F†÷WD6ö×ÆWFVDWf–FVæ6RÒ&Wõ66ç2æÆVæwF‚âbb†4v—D‡V$6ö×ÆWFVDWf–FVæ6S°¢6öç7B†5Væ¶æ÷väv—D‡V%66ä†—7F÷'’Ò†4v—D‡V%66åv—F†÷WD6ö×ÆWFVDWf–FVæ6Rbb66ä†—7F÷'”6ö×ÆWFS°¢6öç7Bv—F‡V$vVçF–4v—F–æu7FGW2Ò†47F—fTv—D‡V%66à¢òu66â–â&öw&W72p¢¢†5Væ¶æ÷väv—D‡V%66ä†—7F÷'¢òu66â†—7F÷'’–æ6ö×ÆWFRp¢¢†4v—D‡V%66åv—F†÷WD6ö×ÆWFVDWf–FVæ6P¢òu66â–æ6ö×ÆWFRp¢¢tæò66â–WBs°¢6öç7Bv—F‡V$vVçF–4v—F–ætÖWG&–2Ò†5Væ¶æ÷väv—D‡V%66ä†—7F÷'¢òu&Wf–Wr66â†—7F÷'’p¢¢†4v—D‡V%66åv—F†÷WD6ö×ÆWFVDWf–FVæ6P¢òtv—F–ær66â6ö×ÆWF–öâp¢¢tv—F–ærf—'7B66âs°¢6öç7B66ä7F–öåF‚Ò†4v—D‡V$6öææV7F÷$Wf–FVæ6Ròv—F‡V$7F–öåF‚¢6öææV7E6÷W&6W5Fƒ°¢6öç7B†–v…&–÷&—G”6÷VçBÒ†–v…&–÷&—G”f–æF–æw2æÆVæwFƒ°¢6öç7B7F—fTVçf—&öæÖVçD6÷VçBÒ7F—fU&ö¦V7G2æÆVæwFƒ°¢6öç7Bv—F‡V%7FFS¢÷fW'f–WtFöÖ–å7FFRÒ6÷W&6Tf–Æ&–Æ—G’æv—F‡V"æf–Æ&ÆRbb†4v—D‡V$6öææV7F÷$Wf–FVæ6P¢òw6†VÆÂp¢¢†4v—D‡V$6öææV7F÷$GFVçF–öâÇÂ†f–ÆVE66ä6÷VçBâbb7V66VVFVE66ä6÷VçBÓÓÒ¢òvFVw&FVBp¢¢†4ç•7V66W76gVÅ66âÇÂ†4v—D‡V$f–æF–ætWf–FVæ6P¢òv6öææV7FVBp¢¢†4v—D‡V$6öææV7F÷$Wf–FVæ6P¢òvæõöFFp¢¢væ÷Eö6öææV7FVBs°¢6öç7Bw57FFRÒ÷fW'f–Wu7FFTg&öÔ6öææV7F–öå&öÆÇW‡6÷W&6Tf–Æ&–Æ—G’æw2Âw5&öÆÇW“°¢6öç7B·V&W&æWFW57FFRÒ÷fW'f–Wu7FFTg&öÔ6öææV7F–öå&öÆÇW‡6÷W&6Tf–Æ&–Æ—G’æ·V&W&æWFW2Â·V&W&æWFW5&öÆÇW“°¢6öç7BvVçF–5&—6µ7FFS¢÷fW'f–WtFöÖ–å7FFRÒ6÷W&6Tf–Æ&–Æ—G’æv—F‡V"æf–Æ&ÆRbb†4v—D‡V$6öææV7F÷$Wf–FVæ6P¢òw6†VÆÂp¢¢†4v—D‡V$6öææV7F÷$GFVçF–öâÇÂvVçF–5&—6´f–æF–æw2æÆVæwF‚â ¢òvFVw&FVBp¢¢†4v—D‡V$6öææV7F÷$Wf–FVæ6P¢òvæõöFFp¢¢væ÷Eö6öææV7FVBs°¢6öç7BFöÖ–å÷7GW&S¢'&“Ç°¢–C¢7G&–æs°¢Æ&VÃ¢7G&–æs°¢&÷f–FW#¢6÷W&6U&÷f–FW#°¢7FFS¢÷fW'f–WtFöÖ–å7FFS°¢7FGW4Æ&VÃ¢7G&–æs°¢ÖWG&–3¢7G&–æs°¢Fó¢7G&–æs°¢ÓâÒ°¢°¢–C¢vw2rÀ¢Æ&VÃ¢tu2rÀ¢&÷f–FW#¢vw2rÀ¢7FFS¢w57FFRÀ¢7FGW4Æ&VÃ¢õdU%d”UuôDôÔ”åõ5DDUôÄ$TÅ5¶w57FFUÒÀ¢ÖWG&–3¢w57FFRÓÓÒw6†VÆÂròt6öææV7F÷"öfbr¢÷fW'f–Wt6öææV7F–öäÖWG&–2†w5&öÆÇWÂv66÷VçBr’À¢Fó¢w57FFRÓÓÒvæ÷Eö6öææV7FVBròw46öææV7EF‚¢w5F€¢ÒÀ¢°¢–C¢vv—F‡V"rÀ¢Æ&VÃ¢tv—D‡V"rÀ¢&÷f–FW#¢vv—F‡V"rÀ¢7FFS¢v—F‡V%7FFRÀ¢7FGW4Æ&VÃ¢õdU%d”UuôDôÔ”åõ5DDUôÄ$TÅ5¶v—F‡V%7FFUÒÀ¢ÖWG&–3 ¢v—F‡V%7FFRÓÓÒw6†VÆÂp¢òt6öææV7F÷"öfbp¢¢†4v—D‡V$6öææV7F÷%VæF–æp¢òtf–æ—6‚6öææV7F–öâp¢¢†4v—D‡V$6öææV7F÷$æVVG5&Wf–Wp¢òu&Wf–Wr6öææV7F÷"p¢¢†4v—D‡V$6öææV7F–öå7FGW4–æ6ö×ÆWFP¢òu&Wf–Wr6öææV7F÷"7FGW2p¢¢&Wõ66ç2æÆVæwF‚â ¢òf÷&ÖD6÷VçDÆ&VÂ‡&Wõ66ç2æÆVæwF‚Âw66âr¢¢†4v—D‡V$f–æF–ætWf–FVæ6P¢òf÷&ÖD6÷VçDÆ&VÂ‡&Wôf–æF–æw2æÆVæwF‚Âvf–æF–ærr¢¢†4v—D‡V$6öææV7F÷$Wf–FVæ6P¢òtv—F–ærf—'7B66âp¢¢t6öææV7Bv—D‡V"rÀ¢Fó¢†–v…&–÷&—G”6÷VçBâòf–æF–æw5F‚¢v—F‡V%F€¢ÒÀ¢°¢–C¢v·V&W&æWFW2rÀ¢Æ&VÃ¢t·V&W&æWFW2rÀ¢&÷f–FW#¢v·V&W&æWFW2rÀ¢7FFS¢·V&W&æWFW57FFRÀ¢7FGW4Æ&VÃ¢õdU%d”UuôDôÔ”åõ5DDUôÄ$TÅ5¶·V&W&æWFW57FFUÒÀ¢ÖWG&–3¢·V&W&æWFW57FFRÓÓÒw6†VÆÂròt6öææV7F÷"öfbr¢÷fW'f–Wt6öææV7F–öäÖWG&–2†·V&W&æWFW5&öÆÇWÂv6ÇW7FW"r’À¢Fó¢·V&W&æWFW57FFRÓÓÒvæ÷Eö6öææV7FVBrò·V&W&æWFW46öææV7EF‚¢·V&W&æWFW5F€¢ÒÀ¢°¢–C¢vvVçF–2×&—6²rÀ¢Æ&VÃ¢t’òvVçF–2&—6²rÀ¢&÷f–FW#¢vv—F‡V"rÀ¢7FFS¢vVçF–5&—6µ7FFRÀ¢7FGW4Æ&VÃ ¢vVçF–5&—6µ7FFRÓÓÒvæõöFFrbb†4v—D‡V$6ö×ÆWFVDWf–FVæ6P¢ò†4Ö÷&Tv—D‡V$f–æF–æw2òtÖ÷&Rf–æF–æw2r¢tæòf–æF–æw2p¢¢vVçF–5&—6µ7FFRÓÓÒvæõöFFrbb†4v—D‡V$6öææV7F÷$Wf–FVæ6P¢òv—F‡V$vVçF–4v—F–æu7FGW0¢¢õdU%d”UuôDôÔ”åõ5DDUôÄ$TÅ5¶vVçF–5&—6µ7FFUÒÀ¢ÖWG&–3 ¢vVçF–5&—6µ7FFRÓÓÒw6†VÆÂp¢òt6öææV7F÷"öfbp¢¢†4v—D‡V$6öææV7F÷%VæF–æp¢òtf–æ—6‚6öææV7F–öâp¢¢†4v—D‡V$6öææV7F÷$æVVG5&Wf–Wp¢òu&Wf–Wr6öææV7F÷"p¢¢†4v—D‡V$6öææV7F–öå7FGW4–æ6ö×ÆWFP¢òu&Wf–Wr6öææV7F÷"7FGW2p¢¢vVçF–5&—6´f–æF–æw2æÆVæwF‚â ¢òf÷&ÖD6÷VçDÆ&VÂ†vVçF–5&—6´f–æF–æw2æÆVæwF‚Âw6–væÂr¢¢†4v—D‡V$6ö×ÆWFVDWf–FVæ6Rbb†4Ö÷&Tv—D‡V$f–æF–æw0¢òtÖ÷&Rf–æF–æw2Fò&Wf–Wrp¢¢†4v—D‡V$6ö×ÆWFVDWf–FVæ6P¢òtæò6–væÇ2FWFV7FVBp¢¢†4v—D‡V$6öææV7F÷$Wf–FVæ6P¢òv—F‡V$vVçF–4v—F–ætÖWG&–0¢¢t6öææV7B6÷W&6Rf—'7BrÀ¢Fó¢vVçF–5&—6µ7FFRÓÓÒvæ÷Eö6öææV7FVBròv—F‡V%F‚¢v—F‡V$vVçF–5&—6µF€¢Ð¢Ó°¢6öç7B7F—fTFöÖ–ä6÷VçBÒFöÖ–å÷7GW&Ræf–ÇFW"‚†—FVÒ’Óà¢—FVÒç7FFRÓÓÒv6öææV7FVBrÇÂ—FVÒç7FFRÓÓÒvFVw&FVBrÇÂ—FVÒç7FFRÓÓÒvæõöFFp¢’æÆVæwFƒ°¢6öç7B†4FöÖ–äFVw&FF–öâÒFöÖ–å÷7GW&Rç6öÖR‚†—FVÒ’Óâ—FVÒç7FFRÓÓÒvFVw&FVBr“°¢6öç7B†4FöÖ–å6WGWvÒFöÖ–å÷7GW&Rç6öÖR‚†—FVÒ’Óâ—FVÒç7FFRÓÓÒvæ÷Eö6öææV7FVBrÇÂ—FVÒç7FFRÓÓÒw6†VÆÂr“°¢6öç7B÷7GW&UFöæS¢vFævW"rÂwv&æ–ærrÂvæWWG&ÂrÒ†–v…&–÷&—G”6÷VçBâ ¢òvFævW"p¢¢f–ÆVE66ä6÷VçBâÇÂ†4FöÖ–äFVw&FF–öâÇÂ†4FöÖ–å6WGWv ¢òwv&æ–ærp¢¢væWWG&Âs°¢6öç7B÷7GW&TÆ&VÂÒ†–v…&–÷&—G”6÷VçBâ ¢òt†–v‚×&–÷&—G’&—6²p¢¢f–ÆVE66ä6÷VçBâ ¢òu66âæVVG2&Wf–Wrp¢¢†4FöÖ–äFVw&FF–öà¢òt6÷fW&vRæVVG2&Wf–Wrp¢¢†4FöÖ–å6WGWv ¢òt6÷fW&vR–æ6ö×ÆWFRp¢¢u7F&ÆRs°¢6öç7B7F—fTFöÖ–ç4Æ&VÂÒG¶7F—fTFöÖ–ä6÷VçGÒöbG¶FöÖ–å÷7GW&RæÆVæwF‡Ö°¢6öç7BWf–FVæ6TÆ&VÂÒ&Wõ66ç2æÆVæwF‚âòf÷&ÖD6÷VçDÆ&VÂ‡&Wõ66ç2æÆVæwF‚Âw66âr’¢tæò66ç2s°¢6öç7Bf—'7E6÷W&6TvÒFöÖ–å÷7GW&Ræf–æB‚†—FVÒ’Óâ—FVÒç7FFRÓÓÒvæ÷Eö6öææV7FVBrÇÂ—FVÒç7FFRÓÓÒw6†VÆÂr“°¢6öç7BæW‡D7F–öç3¢'&“Ç°¢–C¢7G&–æs°¢Æ&VÃ¢7G&–æs°¢FW67&—F–öã¢7G&–æs°¢Fó¢7G&–æs°¢FöæSó¢vFævW"rÂwv&æ–ærrÂvæWWG&Âs°¢ÓâÒµÓ°¢–b††–v…&–÷&—G”6÷VçBâ’°¢æW‡D7F–öç2çW6‚‡°¢–C¢w&–÷&—G’rÀ¢Æ&VÃ¢&Wf–WrG¶f÷&ÖD6÷VçDÆ&VÂ††–v…&–÷&—G”6÷VçBÂv†–v‚×&–÷&—G’f–æF–ærr—ÖÀ¢FW67&—F–öã¢t7&—F–6ÂæB†–v‚f–æF–æw2æVVBG&–vRârÀ¢Fó¢f–æF–æw5F‚À¢FöæS¢vFævW"p¢Ò“°¢Ð¢–b†f–ÆVE66ä6÷VçBâ’°¢æW‡D7F–öç2çW6‚‡°¢–C¢w66ârÀ¢Æ&VÃ¢&Wf–WrG¶f÷&ÖD6÷VçDÆ&VÂ†f–ÆVE66ä6÷VçBÂvf–ÆVB66âr—ÖÀ¢FW67&—F–öã¢t6†V6²F†R&W÷'FVBW'&÷"ÂF†Vâ'VâF†R66âv–âârÀ¢Fó¢v—F‡V$7F–öåF‚À¢FöæS¢wv&æ–ærp¢Ò“°¢Ð¢–b††4v—D‡V$6öææV7F÷$GFVçF–öâ’°¢æW‡D7F–öç2çW6‚‡°¢–C¢vv—F‡V"Ö6öææV7F–öârÀ¢Æ&VÃ¢†4v—D‡V$6öææV7F÷%VæF–æròtf–æ—6‚v—D‡V"6öææV7F–öâr¢u&Wf–Wrv—D‡V"6öææV7F–öârÀ¢FW67&—F–öã¢†4v—D‡V$6öææV7F÷%VæF–æp¢òuF†Rv—D‡V"–ç7FÆÆF–öâ—27F–ÆÂVæF–æs²f–æ—6‚6öææV7F–ær—B&Vf÷&R66ææ–ærâp¢¢†4v—D‡V$6öææV7F–öå7FGW4–æ6ö×ÆWFP¢òtv—D‡V"6öææV7F÷"7FGW26÷VÆBæ÷B&R6öæf—&ÖVBf÷"WfW'’7F—fR&ö¦V7Bâp¢¢uF†Rv—D‡V"6öææV7F÷"—2&W6VçB'WBæVVG2GFVçF–öâ&Vf÷&R66ææ–ærârÀ¢Fó¢v—F‡V$7F–öåF‚À¢FöæS¢wv&æ–ærp¢Ò“°¢Ð¢–b†f—'7E6÷W&6Tv’°¢6öç7B6÷W&6TvÆ&VÂÒf—'7E6÷W&6Tvç7FFRÓÓÒvæ÷Eö6öææV7FVBp¢ò6öææV7BG¶f—'7E6÷W&6TvæÆ&VÇÖ ¢¢&Wf–WrG¶f—'7E6÷W&6TvæÆ&VÇÒf–Æ&–Æ—G–°¢æW‡D7F–öç2çW6‚‡°¢–C¢v6öææV7BrÀ¢Æ&VÃ¢6÷W&6TvÆ&VÂÀ¢FW67&—F–öã¢f—'7E6÷W&6Tvç7FFRÓÓÒvæ÷Eö6öææV7FVBp¢òG¶f—'7E6÷W&6TvæÆ&VÇÒ—2æ÷B6öææV7FVBFòF†—2v÷&·76Ræ ¢¢G¶f—'7E6÷W&6TvæÆ&VÇÒ—2Væf–Æ&ÆR–âF†—2v÷&·76RæÀ¢Fó¢f—'7E6÷W&6TvçFòÀ¢FöæS¢wv&æ–ærp¢Ò“°¢Ð¢–b†vVçF–5&—6´f–æF–æw2æÆVæwF‚â’°¢æW‡D7F–öç2çW6‚‡°¢–C¢vvVçF–2rÀ¢Æ&VÃ¢t÷VâvVçF–2&—6²rÀ¢FW67&—F–öã¢G¶f÷&ÖD6÷VçDÆ&VÂ†vVçF–5&—6´f–æF–æw2æÆVæwF‚Âv÷Vâ6–væÂr—ÒæVVB&Wf–WræÀ¢Fó¢v—F‡V$vVçF–5&—6µF‚À¢FöæS¢vFævW"p¢Ò“°¢Ð¢–b†æW‡D7F–öç2æÆVæwF‚Â2’°¢æW‡D7F–öç2çW6‚‡°¢–C¢†4ç•7V66W76gVÅ66âÇÂ†5Væ¶æ÷väv—D‡V%66ä†—7F÷'’òw66ç2r¢w66â×7F'BrÀ¢Æ&VÃ¢†4ç•7V66W76gVÅ66à¢òu&Wf–Wr66â&W7VÇG2p¢¢†5Væ¶æ÷väv—D‡V%66ä†—7F÷'¢òu&Wf–Wr66â†—7F÷'’p¢¢u'Vâ66ârÀ¢FW67&—F–öã¢†4ç•7V66W76gVÅ66à¢òt6†V6²&V6VçBWf–FVæ6RæB&W÷6—F÷'’6÷fW&vRâp¢¢†5Væ¶æ÷väv—D‡V%66ä†—7F÷'¢òt6öæf—&Òv†WF†W"V&Æ–W"66ç26ö×ÆWFVB7V66W76gVÆÇ’âp¢¢t6ö×ÆWFR66âFò&öGV6R7W'&VçBWf–FVæ6RârÀ¢Fó¢†4ç•7V66W76gVÅ66âÇÂ†5Væ¶æ÷väv—D‡V%66ä†—7F÷'’òv—F‡V%F‚¢66ä7F–öåF‚À¢FöæS¢væWWG&Âp¢Ò“°¢Ð¢–b†æW‡D7F–öç2æÆVæwF‚Â2’°¢æW‡D7F–öç2çW6‚‡°¢–C¢vv÷fW&ææ6RrÀ¢Æ&VÃ¢u&Wf–Wrv÷fW&ææ6RrÀ¢FW67&—F–öã¢t6†V6²6öææV7F÷"æBöÆ–7’6÷fW&vRârÀ¢Fó¢w4v÷fW&ææ6UF‚À¢FöæS¢væWWG&Âp¢Ò“°¢Ð¢6öç7Bf—6–&ÆT7F–öç2ÒæW‡D7F–öç2ç6Æ–6RƒÂ2“°¢6öç7Böæ&ö&F–æt6†V6¶Æ—7C¢'&“Ç°¢–C¢7G&–æs°¢Æ&VÃ¢7G&–æs°¢6ö×ÆWFS¢&ööÆVã°¢7F–öäÆ&VÃó¢7G&–æs°¢Fóó¢7G&–æs°¢6¶—&ÆSó¢&ööÆVã°¢ÓâÒ°¢°¢–C¢vFöÖ–ârÀ¢Æ&VÃ¢t6†ö÷6R–÷W"f—'7BFöÖ–ârÀ¢6ö×ÆWFS¢7F—fTVçf—&öæÖVçD6÷VçBâÀ¢7F–öäÆ&VÃ¢7F—fTVçf—&öæÖVçD6÷VçBâòVæFVf–æVB¢t÷VârÀ¢Fó¢w5F€¢ÒÀ¢°¢–C¢w6÷W&6RrÀ¢Æ&VÃ¢t6öææV7BFöÖ–â6÷W&6RrÀ¢6ö×ÆWFS¢†46öææV7FVE6÷W&6RÀ¢7F–öäÆ&VÃ¢†46öææV7FVE6÷W&6RòVæFVf–æVB¢t6öææV7BrÀ¢Fó¢6öææV7E6÷W&6W5F€¢ÒÀ¢°¢–C¢w66ârÀ¢Æ&VÃ¢u'Vâ–÷W"f—'7B66ârÀ¢6ö×ÆWFS¢†4ç•7V66W76gVÅ66âÀ¢7F–öäÆ&VÃ¢†4ç•7V66W76gVÅ66âòVæFVf–æVB¢u'Vâ66ârÀ¢Fó¢66ä7F–öåF€¢ÒÀ¢°¢–C¢v–çf—FRrÀ¢Æ&VÃ¢t–çf—FRFVÖÖFRrÀ¢6ö×ÆWFS¢&VD–çf—FU6¶—VB‡66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”B’À¢7F–öäÆ&VÃ¢&VD–çf—FU6¶—VB‡66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”B’òVæFVf–æVB¢t–çf—FRrÀ¢Fó¢v÷&·76W5F‚À¢6¶—&ÆS¢&VD–çf—FU6¶—VB‡66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”B¢Ð¢Ó°¢6öç7B6†÷VÆE6†÷töæ&ö&F–ærÒöæ&ö&F–æt6†V6¶Æ—7Bç6öÖR‚†—FVÒ’Óâ—FVÒæ–BÓÒv–çf—FRrbb—FVÒæ6ö×ÆWFR“° ¢–b†ÆöF–ær’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ÷fW'f–Wr×vR"&–Ö'W7“Ò'G'VR"&–ÖÆ—fSÒ'öÆ—FR#à¢Æ†VFW"6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ†VFW"#à¢Æƒ#ä÷fW'f–WsÂöƒ#à¢ÇäÆöF–ær6öÖÖæB6VçFW"ãÂ÷à¢Âö†VFW#à¢Â÷6V7F–öãà¢“°¢Ð ¢–b†W'&÷"’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷"–GBÖ÷fW'f–Wr×vR"&öÆSÒ&ÆW'B#à¢Æ†VFW"6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ†VFW"#à¢Æƒ#ä÷fW'f–WsÂöƒ#à¢Çç¶W'&÷'ÓÂ÷à¢Âö†VFW#à¢Â÷6V7F–öãà¢“°¢Ð ¢6öç7B66äw&÷W2Òw&÷W&V6VçE66ç2‡&Wõ66ç2“° ¢&WGW&â€¢Ãà¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ÷fW'f–Wr×vR#à¢Æ†VFW"6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ†VFW"#à¢Æƒ#ä÷fW'f–WsÂöƒ#à¢Âö†VFW#à ¢·6†÷VÆE6†÷töæ&ö&F–ærò€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6†V6¶Æ—7B"&–ÖÆ&VÃÒ$vWB7F'FVB#à¢Æ†VFW#à¢Æƒ3ävWB7F'FVCÂöƒ3à¢Çç¶öæ&ö&F–æt6†V6¶Æ—7Bæf–ÇFW"‚†—FVÒ’Óâ—FVÒæ6ö×ÆWFR’æÆVæwF‡Òöb¶öæ&ö&F–æt6†V6¶Æ—7BæÆVæwF‡Ò6ö×ÆWFSÂ÷à¢Âö†VFW#à¢ÆöÃà¢¶öæ&ö&F–æt6†V6¶Æ—7BæÖ‚†—FVÒ’Óâ€¢ÆÆ’¶W“×¶—FVÒæ–GÒFFÖ6ö×ÆWFS×¶—FVÒæ6ö×ÆWFRòwG'VRr¢vfÇ6RwÓà¢Ç7â6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6†V6¶Æ—7BÖÖ&²"&–Ö†–FFVãÒ'G'VR#à¢¶—FVÒæ6ö×ÆWFRò€¢Ç7frf–Wt&÷ƒÒ#bb"v–GFƒÒ#""†V–v‡CÒ#""f–ÆÃÒ&æöæR"7G&ö¶SÒ&7W'&VçD6öÆ÷""7G&ö¶Uv–GFƒÒ#""7G&ö¶TÆ–æV6Ò'&÷VæB"7G&ö¶TÆ–æV¦ö–ãÒ'&÷VæB#à¢ÇF‚CÒ&Ó2ãR‚ãR22bÓr"óà¢Â÷7fsà¢’¢çVÆÇÐ¢Â÷7ãà¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6†V6¶Æ—7BÖ&öG’#à¢Ç7G&öæsç¶—FVÒæÆ&VÇÓÂ÷7G&öæsà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6†V6¶Æ—7BÖ7F–öç2#à¢¶—FVÒç6¶—&ÆRbb—FVÒæ6ö×ÆWFRò€¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6†V6¶Æ—7B×6¶— ¢öä6Æ–6³×²‚’Óâ°¢W'6—7D–çf—FU6¶—VB‡66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”B“°¢6WD–çf—FU6¶—F–6²‚‡fÇVR’ÓâfÇVR²“°¢×Ð¢&–ÖÆ&VÃ×¶6¶—¢G¶—FVÒæÆ&VÇÖÐ¢à¢6¶— ¢Âö'WGFöãà¢’¢çVÆÇÐ¢¶—FVÒæ7F–öäÆ&VÂbb—FVÒçFòò€¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6†V6¶Æ—7BÖ7F–öâ"Fó×¶—FVÒçF÷Óà¢¶—FVÒæ7F–öäÆ&VÇÐ¢ÂôÆ–æ³à¢’¢çVÆÇÐ¢ÂöF—cà¢ÂöÆ“à¢’—Ð¢ÂööÃà¢Â÷6V7F–öãà¢’¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–72"&–ÖÆ&VÃÒ$6öÖÖæB6VçFW"7VÖÖ'’#à¢Æ'F–6ÆR6Æ74æÖS×¶–GBÖ÷fW'f–WrÖÖWG&–2Ö6&BG·÷7GW&UFöæRÓÓÒvFævW"ròr—2ÖGFVçF–öâr¢÷7GW&UFöæRÓÓÒwv&æ–ærròr—2×v&æ–ærr¢rwÖÓà¢Ç7â6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2ÖÆ&VÂ#å÷7GW&SÂ÷7ãà¢Ç7G&öæsç·÷7GW&TÆ&VÇÓÂ÷7G&öæsà¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2Ö6&B#à¢Ç7â6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2ÖÆ&VÂ#ä†–v‚&–÷&—G“Â÷7ãà¢Ç7G&öæsç¶†–v…&–÷&—G”6÷VçGÓÂ÷7G&öæsà¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2Ö6&B#à¢Ç7â6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2ÖÆ&VÂ#ä7F—fRFöÖ–ç3Â÷7ãà¢Ç7G&öæsç¶7F—fTFöÖ–ç4Æ&VÇÓÂ÷7G&öæsà¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2Ö6&B#à¢Ç7â6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2ÖÆ&VÂ#å66âWf–FVæ6SÂ÷7ãà¢Ç7G&öæsç¶Wf–FVæ6TÆ&VÇÓÂ÷7G&öæsà¢Âö'F–6ÆSà¢ÂöF—cà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖFöÖ–â×7G&—"&–ÖÆ&VÃÒ$FöÖ–â÷7GW&R#à¢¶FöÖ–å÷7GW&RæÖ‚†—FVÒ’Óâ€¢ÄÆ–æ²¶W“×¶—FVÒæ–GÒFó×¶—FVÒçF÷Ò6Æ74æÖS×¶–GBÖ÷fW'f–WrÖFöÖ–âÖ6&B—2ÒG¶—FVÒç7FFWÖÓà¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖFöÖ–âÖ6&B×F÷#à¢Å6÷W&6TÆövôÖ&²&÷f–FW#×¶—FVÒç&÷f–FW'Ò6Æ74æÖSÒ&—2×&÷r"FV6÷&F—fRóà¢Ç7â6Æ74æÖS×¶–GBÖ÷fW'f–Wr×7FFR×–ÆÂ—2ÒG¶—FVÒç7FFWÖÓç¶—FVÒç7FGW4Æ&VÇÓÂ÷7ãà¢ÂöF—cà¢Ç7G&öæsç¶—FVÒæÆ&VÇÓÂ÷7G&öæsà¢Ç7ãç¶—FVÒæÖWG&–7ÓÂ÷7ãà¢ÂôÆ–æ³à¢’—Ð¢Â÷6V7F–öãà ¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖw&–B#à¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6&B#à¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6&BÖ†VFW"#à¢Æƒ3ä†–v†W7B&–÷&—G“Âöƒ3à¢ÄÆ–æ²6Æ74æÖSÒ&–GB×&VÖ—VÒ×FW‡BÖÆ–æ²"Fó×¶f–æF–æw5F‡Óåf–Wrv—D‡V"f–æF–æw3ÂôÆ–æ³à¢ÂöF—cà¢¶†–v…&–÷&—G”f–æF–æw2æÆVæwF‚âò€¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÆ—7B#à¢¶†–v…&–÷&—G”f–æF–æw2ç6Æ–6RƒÂõdU%d”Uuõ$•4µôD•5Ä•ôÄ”Ô•B’æÖ‚†f–æF–ær’Óâ°¢6öç7B&W÷6—F÷'’Ò6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’†f–æF–ærç&W÷6—F÷'’óòrr“°¢&WGW&â€¢Æ'F–6ÆR¶W“×¶G¶f–æF–ærç66åö–GÓ¢G¶f–æF–æræ–GÖÒ6Æ74æÖSÒ&–GBÖ÷fW'f–Wr×&—6²×&÷r#à¢Å6÷W&6TÆövôÖ&²&÷f–FW#Ò&v—F‡V""6Æ74æÖSÒ&—2×&÷r"óà¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–Wr×&÷rÖ6÷’#à¢ÆF—cà¢Ç7G&öæsç¶f–æF–ærçF—FÆWÓÂ÷7G&öæsà¢Çà¢·&W÷6—F÷'’ÇÂu&W÷6—F÷'’Væf–Æ&ÆRwÒ+r·&Wôf–æF–ætÆö6F–öäÆ&VÂ†f–æF–ær—Ð¢Â÷à¢ÂöF—cà¢Ç7â6Æ74æÖS×·&Wôf–æF–æu6WfW&—G”6Æ72†f–æF–ærç6WfW&—G’—Óç¶f÷&ÖEFö¶VäÆ&VÂ†f–æF–ærç6WfW&—G’—ÓÂ÷7ãà¢ÂöF—cà¢Âö'F–6ÆSà¢“°¢Ò—Ð¢ÂöF—cà¢’¢€¢Ä6†VÆÄV×G•7FFP¢F—FÆS×¶†4ç•7V66W76gVÅ66à¢òtæò†–v‚×&–÷&—G’f–æF–æw2p¢¢†5Væ¶æ÷väv—D‡V%66ä†—7F÷'¢òu66â†—7F÷'’–æ6ö×ÆWFRp¢¢tæò6ö×ÆWFVB66âwÐ¢&öG“×¶†4ç•7V66W76gVÅ66à¢òt6ö×ÆWFVB66ç2†fRæò÷Vâ7&—F–6Â÷"†–v‚f–æF–æw2âp¢¢†5Væ¶æ÷väv—D‡V%66ä†—7F÷'¢òu&V6VçB66ç2Fòæ÷B6†÷rv†WF†W"V&Æ–W"Wf–FVæ6R6ö×ÆWFVB7V66W76gVÆÇ’âp¢¢t6ö×ÆWFR66âFò6†V6²f÷"7&—F–6ÂæB†–v‚f–æF–æw2âwÐ¢7F–öã×¶†4ç•7V66W76gVÅ66à¢òVæFVf–æV@¢¢†5Væ¶æ÷väv—D‡V%66ä†—7F÷'¢ò²Æ&VÃ¢u&Wf–Wr66â†—7F÷'’rÂFó¢v—F‡V%F‚Ð¢¢²Æ&VÃ¢u'Vâ66ârÂFó¢66ä7F–öåF‚×Ð¢óà¢—Ð¢Â÷6V7F–öãà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6&B"&–ÖÆ&VÃÒ%&V6öÖÖVæFVBæW‡B7F–öç2#à¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6&BÖ†VFW"#à¢Æƒ3äæW‡B7F–öç3Âöƒ3à¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ7F–öâÖÆ—7B#à¢·f—6–&ÆT7F–öç2æÖ‚†—FVÒ’Óâ€¢ÄÆ–æ²¶W“×¶—FVÒæ–GÒFó×¶—FVÒçF÷Ò6Æ74æÖS×¶–GBÖ÷fW'f–WrÖ7F–öâ×&÷r—2ÒG¶—FVÒçFöæRóòvæWWG&ÂwÖÓà¢Ç7ãà¢Ç7G&öæsç¶—FVÒæÆ&VÇÓÂ÷7G&öæsà¢Ç6ÖÆÃç¶—FVÒæFW67&—F–öçÓÂ÷6ÖÆÃà¢Â÷7ãà¢Ä6†Wg&öå&–v‡B6—¦S×³gÒ&–Ö†–FFVãÒ'G'VR"óà¢ÂôÆ–æ³à¢’—Ð¢ÂöF—cà¢Â÷6V7F–öãà¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖw&–B–GBÖ÷fW'f–WrÖw&–B×6–ævÆR#à¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6&B#à¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖ6&BÖ†VFW"#à¢Æƒ3å&V6VçB7F—f—G“Âöƒ3à¢ÄÆ–æ²6Æ74æÖSÒ&–GB×&VÖ—VÒ×FW‡BÖÆ–æ²"Fó×¶f–æF–æw5F‡Óåf–Wrv—D‡V"f–æF–æw3ÂôÆ–æ³à¢ÂöF—cà¢·66äw&÷W2æÆVæwF‚âò€¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÆ—7B–GBÖ÷fW'f–WrÖ7F—f—G’ÖÆ—7B#à¢·66äw&÷W2æÖ‚†w&÷W’Óâ°¢6öç7B—4f–ÇW&RÒw&÷Wç7FGW2ÓÓÒvf–ÆVBrÇÂw&÷Wç7FGW2ÓÓÒv6æ6VÆVBs°¢6öç7B—47F—fRÒ—47F—fU66å7FGW2†w&÷Wç7FGW2“°¢6öç7B&WôÆ&VÂÐ¢w&÷Wç&W÷2æÆVæwF‚ÓÓÒ¢òw&÷Wç&W÷5³Ð¢¢G¶w&÷Wç&W÷5³×Ò²G¶w&÷Wç&W÷2æÆVæwF‚ÒÒÖ÷&V°¢&WGW&â€¢Æ'F–6ÆP¢¶W“×¶G¶w&÷Wç7FGW7ÒÒG¶w&÷Wç&V6öçÒÒG¶w&÷WæÆFW7Bæ–GÖÐ¢6Æ74æÖS×¶–GBÖ÷fW'f–Wr×66â×&÷rG¶—4f–ÇW&Ròr—2Öf–ÇW&Rr¢—47F—fRòr—2Ö7F—fRr¢r—2×7V66W72wÖÐ¢à¢Å6÷W&6TÆövôÖ&²&÷f–FW#Ò&v—F‡V""6Æ74æÖSÒ&—2×&÷r"óà¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–Wr×&÷rÖ6÷’#à¢ÆF—cà¢Ç7G&öæsç·&WôÆ&VÇÓÂ÷7G&öæsà¢Çç¶w&÷Wç&V6öçÒ+r¶f÷&ÖE&VÆF—fUF–ÖR†w&÷WæÆFW7Bç7F'FVEöB—ÓÂ÷à¢ÂöF—cà¢Ç7â6Æ74æÖS×¶–GBÖ÷fW'f–Wr×66âÖ&FvR—2ÒG¶—4f–ÇW&RòvW'&÷"r¢—47F—fRòwv&æ–ærr¢w7V66W72wÖÓà¢¶—4f–ÇW&Ròtf–ÆVBr¢—47F—fRòu'Vææ–ærr¢u7V66VVFVBwÐ¢Â÷7ãà¢ÂöF—cà¢Âö'F–6ÆSà¢“°¢Ò—Ð¢ÂöF—cà¢’¢€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æò7F—f—G’ ¢&öG“Ò%66ç2æB6öææV7F÷"WfVçG2V"†W&Râ ¢7F–öã×·²Æ&VÃ¢t6öææV7B6÷W&6RrÂFó¢6öææV7E6÷W&6W5F‚×Ð¢óà¢—Ð¢Â÷6V7F–öãà¢ÂöF—cà¢Â÷6V7F–öãà¢·6†÷uF÷W"ò€¢Æ6–FR6Æ74æÖSÒ&–GBÖöæ&ö&F–ær×F÷W""&–ÖÆ&VÃÒ$öæ&ö&F–ærF÷W"#à¢ÆF—cà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äæW‡B&W7B7F–öç3Â÷à¢Æƒ#åGW&â6WGW–çFò÷W&F–ær&‡—F†ÓÂöƒ#à¢ÂöF—cà¢ÆöÃà¢ÆÆ“å&Wf–Wr6öææV7F÷"†VÇFƒÂöÆ“à¢ÆÆ“ä÷VâF†RÆFW7B66ãÂöÆ“à¢ÆÆ“åG&–vRF†Rf—'7Bf–æF–æsÂöÆ“à¢ÆÆ“ä–çf—FRFVÖÖFSÂöÆ“à¢ÂööÃà¢Æ'WGFöâG—SÒ&'WGFöâ"6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’"öä6Æ–6³×¶F—6Ö—75F÷W'Óà¢v÷B—@¢Âö'WGFöãà¢Âö6–FSà¢’¢çVÆÇÐ¢Âóà¢“°§Ð ¢òòFöÖ–ç2F†RW†V7WF—fR&W÷'B6â&R66÷VBFòâV×G’7G&–ærÖVç2$ÆÂ"à¢òò¶WBÆ–væVBv—F‚W†V7WF—fU&W÷'DFöÖ–â–âF†R’6Æ–VçB²F†R6W'fW"w0¢òò'6TW†V7WF—fU&W÷'DFöÖ–âÆÆ÷vÆ—7C²Væ¶æ÷vâfÇVW2&R&V¦V7FVB6W'fW"×6–FRà¦6öç7BU„T5UD•dUõ$Uõ%EôDôÔ”åôõD”ôå3¢'&“Ç²fÇVS¢W†V7WF—fU&W÷'DFöÖ–ã²Æ&VÃ¢7G&–ærÓâÒ°¢²fÇVS¢rrÂÆ&VÃ¢tÆÂrÒÀ¢²fÇVS¢vw2rÂÆ&VÃ¢tu2rÒÀ¢²fÇVS¢vv—F‡V"rÂÆ&VÃ¢tv—D‡V"rÒÀ¢²fÇVS¢v·V&W&æWFW2rÂÆ&VÃ¢t·V&W&æWFW2rÐ¥Ó° ¢òò'6TW†V7WF—fU&W÷'DFöÖ–å&Ò6W&FW2&æòFöÖ–â–âU$Â"†VffV7F—fRÒrrÀ¢òò–çfÆ–E&rÒçVÆÂ’g&öÒ%U$Â†2FöÖ–âfÇVRF†B—2æ÷BÆÆ÷vÆ—7FVB ¢òò†VffV7F—fRÒrrÂ–çfÆ–E&rÒF†R&r7G&–ær’âv—F†÷WBF†—2F—7F–æ7F–öâF†P¢òòvRv÷VÆB6–ÆVçFÇ’v–FVâ7FÆR÷"G—òvBfÇVRÆ–¶RöFöÖ–ãÖw72Fò$ÆÂ"À¢òòv†–6‚FVfVG2F†R6W'fW"×6–FRG—ò&÷FV7F–öâFFVB–âF†—2"à¦gVæ7F–öâ'6TW†V7WF—fU&W÷'DFöÖ–å&Ò‡&s¢7G&–ærÂçVÆÂÂVæFVf–æVB“¢°¢VffV7F—fS¢W†V7WF—fU&W÷'DFöÖ–ã°¢–çfÆ–E&s¢7G&–ærÂçVÆÃ°§Ò°¢–b‡&rÓÓÒçVÆÂÇÂ&rÓÓÒVæFVf–æVB’°¢&WGW&â²VffV7F—fS¢rrÂ–çfÆ–E&s¢çVÆÂÓ°¢Ð¢6öç7BG&–ÖÖVBÒ&rçG&–Ò‚“°¢–b‡G&–ÖÖVBÓÓÒrr’°¢òòöFöÖ–ãÒv—F‚âV×G’fÇVR&V†fW22&æòf–ÇFW""à¢&WGW&â²VffV7F—fS¢rrÂ–çfÆ–E&s¢çVÆÂÓ°¢Ð¢6öç7BÆ÷vW"ÒG&–ÖÖVBçFôÆ÷vW$66R‚“°¢–b†Æ÷vW"ÓÓÒvw2rÇÂÆ÷vW"ÓÓÒvv—F‡V"rÇÂÆ÷vW"ÓÓÒv·V&W&æWFW2r’°¢&WGW&â²VffV7F—fS¢Æ÷vW"Â–çfÆ–E&s¢çVÆÂÓ°¢Ð¢&WGW&â²VffV7F—fS¢rrÂ–çfÆ–E&s¢G&–ÖÖVBÓ°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7DW†V7WF—fU&W÷'EvR‚’°¢6öç7B²ÖRÂÆöF–æs¢6W76–öäÆöF–ærÂW'&÷#¢6W76–öäW'&÷"ÂVæWF†VçF–6FVBÒÒW6TÖR‚“°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“°¢6öç7B·&W÷'BÂ6WE&W÷'EÒÒW6U7FFSÄW†V7WF—fU&W÷'BÂçVÆÃâ†çVÆÂ“°¢6öç7B¶ÆöF–æu&W÷'BÂ6WDÆöF–æu&W÷'EÒÒW6U7FFR†fÇ6R“°¢6öç7B·&W÷'DW'&÷"Â6WE&W÷'DW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7BÆö6F–öâÒW6TÆö6F–öâ‚“°¢6öç7Bæf–vFRÒW6Tæf–vFR‚“°¢6öç7BFVæçD”BÒ66÷SòçFVæçD”BóòÖSòæ÷&uö–C°¢6öç7Bv÷&·76T”BÒ66÷Sòçv÷&·76T”BóòÖSòçv÷&·76Uö–C°¢òòG&—fRF†R7F—fRFöÖ–âöfbF†RU$Â6òFVWÆ–æ·2ò&Vg&W6†W2&W6W'fR—Bà¢òò'6TW†V7WF—fU&W÷'DFöÖ–å&ÒFVÆÇ2W2v†WF†W"F†RU$Â—2&B6òvR6à¢òò7W&f6RF†B2âW'&÷"&F†W"F†â6–ÆVçFÇ’v–FVâFòÆÂà¢6öç7B²VffV7F—fS¢6VÆV7FVDFöÖ–âÂ–çfÆ–E&s¢–çfÆ–DFöÖ–å&rÒÒ'6TW†V7WF—fU&W÷'DFöÖ–å&Ò€¢æWrU$Å6V&6…&×2†Æö6F–öâç6V&6‚’ævWB‚vFöÖ–âr¢“° ¢W6TVffV7B‚‚’Óâ°¢–b‚FVæçD”BÇÂv÷&·76T”B’°¢&WGW&ã°¢Ð¢òò6¶—F†RfWF6‚VçF—&VÇ’v†VâF†RU$Â6'&–W2âVç&V6övæ—¦VBFöÖ–à¢òòfÇVS²F†RW'&÷"æVÂ&VÆ÷rÇ&VG’W‡Æ–ç2F†R&V6÷fW'’F‚à¢òð¢òò6ÆV"ÆöF–æu&W÷'BäB&W÷'DW'&÷"&V6W6R–bF†RU$ÂG&ç6—F–öç2g&öÐ¢òòfÆ–BFò–çfÆ–Bv†–ÆR&–÷"&WVW7B—27F–ÆÂ–âfÆ–v‡BÂF†@¢òò&WVW7Bw2f–æÆÇ–—2vFVB'’F†R6ÆVæVB×WÖ÷VçFVF6Æ÷7W&Ræ@¢òòv–ÆÂæWfW"6ÆV"F†RÆöF–ærfÆrâv—F†÷WBF†—26ÆV"ÂF†R&VæFW"F€¢òòv÷VÆB7F’öâF†RÆöF–ær7–ææW"–ç7FVBöb6†÷v–ærF†R&V6÷fW'’æVÂà¢–b†–çfÆ–DFöÖ–å&rÓÒçVÆÂ’°¢6WE&W÷'B†çVÆÂ“°¢6WDÆöF–æu&W÷'B†fÇ6R“°¢6WE&W÷'DW'&÷"‚rr“°¢&WGW&ã°¢Ð ¢ÆWBÖ÷VçFVBÒG'VS°¢6öç7BÆöE&W÷'BÒ7–æ2‚’Óâ°¢6WDÆöF–æu&W÷'B‡G'VR“°¢6WE&W÷'DW'&÷"‚rr“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBævWDW†V7WF—fU&W÷'B€¢²FöÖ–ã¢6VÆV7FVDFöÖ–âÒÀ¢²FVæçD”BÂv÷&·76T”BÐ¢“°¢–b†Ö÷VçFVB’°¢6WE&W÷'B‡&W7öç6R“°¢Ð¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‚Ö÷VçFVB’°¢&WGW&ã°¢Ð¢–b‡&WVW7DW'&÷"–ç7Fæ6Vöb”W'&÷"bb&WVW7DW'&÷"ç7FGW2ÓÓÒC2’°¢6WE&W÷'DW'&÷"‚u–÷RFòæ÷B†fR66W72FòF†RW†V7WF—fR&W÷'Bf÷"F†—2÷&væ—¦F–öââr“°¢&WGW&ã°¢Ð¢6öç7BÖW76vRÒ&WVW7DW'&÷"–ç7Fæ6VöbW'&÷"ò&WVW7DW'&÷"æÖW76vR¢uVæ&ÆRFòÆöBW†V7WF—fR&W÷'Bâs°¢6WE&W÷'DW'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢–b†Ö÷VçFVB’°¢6WDÆöF–æu&W÷'B†fÇ6R“°¢Ð¢Ð¢Ó° ¢fö–BÆöE&W÷'B‚“° ¢&WGW&â‚’Óâ°¢Ö÷VçFVBÒfÇ6S°¢Ó°¢ÒÂ·FVæçD”BÂv÷&·76T”BÂ6VÆV7FVDFöÖ–âÂ–çfÆ–DFöÖ–å&uÒ“° ¢6öç7B†æFÆTFöÖ–ä6†ævRÒ†æW‡C¢W†V7WF—fU&W÷'DFöÖ–â’Óâ°¢–b†æW‡BÓÓÒ6VÆV7FVDFöÖ–âbb–çfÆ–DFöÖ–å&rÓÓÒçVÆÂ’°¢&WGW&ã°¢Ð¢6öç7B&×2ÒæWrU$Å6V&6…&×2†Æö6F–öâç6V&6‚“°¢–b†æW‡BÓÓÒrr’°¢&×2æFVÆWFR‚vFöÖ–âr“°¢ÒVÇ6R°¢&×2ç6WB‚vFöÖ–ârÂæW‡B“°¢Ð¢6öç7B6V&6‚Ò&×2çFõ7G&–ær‚“°¢æf–vFR‡²F†æÖS¢Æö6F–öâçF†æÖRÂ6V&6ƒ¢6V&6‚òòG·6V&6‡Ö¢rrÒÂ²&WÆ6S¢G'VRÒ“°¢Ó° ¢òòF†R6VvÖVçFVB7v—F6‚—2&VæFW&VB&÷F‚öâF†R&W÷'B—G6VÆbæB–ç6–FRF†P¢òò–çfÆ–BÖFöÖ–âW'&÷"æVÂÂ6òF†RW6W"6â&V6÷fW"g&öÒ&BU$Âà¢6öç7B&VæFW$FöÖ–å7v—F6‚Ò‚’Óâ€¢ÆF—b6Æ74æÖSÒ&–GBÖW†V2×&W÷'EõöFöÖ–â"&öÆSÒ'F&Æ—7B"&–ÖÆ&VÃÒ%&W÷'BFöÖ–â#à¢´U„T5UD•dUõ$Uõ%EôDôÔ”åôõD”ôå2æÖ‚†÷F–öâ’Óâ°¢6öç7B7F—fRÒ÷F–öâçfÇVRÓÓÒ6VÆV7FVDFöÖ–âbb–çfÆ–DFöÖ–å&rÓÓÒçVÆÃ°¢&WGW&â€¢Æ'WGFöà¢¶W“×¶÷F–öâçfÇVRÇÂvÆÂwÐ¢G—SÒ&'WGFöâ ¢&öÆSÒ'F" ¢&–×6VÆV7FVC×¶7F—fWÐ¢6Æ74æÖS×¶–GBÖW†V2×&W÷'EõöFöÖ–â×F"G¶7F—fRòr—2Ö7F—fRr¢rwÖÐ¢öä6Æ–6³×²‚’Óâ†æFÆTFöÖ–ä6†ævR†÷F–öâçfÇVR—Ð¢F—6&ÆVC×¶ÆöF–æu&W÷'Bbb7F—fWÐ¢à¢¶÷F–öâæÆ&VÇÐ¢Âö'WGFöãà¢“°¢Ò—Ð¢ÂöF—cà¢“° ¢òò÷&FW"ÖGFW'3¢VæWF†VçF–6FVB×W7Bv–â‡vR6ææ÷B&VæFW"ç—F†–ærv—F†÷W@¢òò6W76–öâ’ÂF†Vâ–çfÆ–DFöÖ–å&rÂF†VâÆöF–ærâWGF–ær–çfÆ–DFöÖ–å&p¢òò&÷fRÆöF–æu&W÷'BwV&çFVW2&BU$Â6†÷w2F†R&V6÷fW'’æVÂWfVâ–`¢òò&–÷"–âÖfÆ–v‡B&WVW7BÆVgBÆöF–æu&W÷'B7GV6²†—G2f–æÆÇ–v0¢òòvFVB'’F†R6ÆVæVB×WÖ÷VçFVF6Æ÷7W&RæBæWfW"6ÆV&VB’à¢–b‡VæWF†VçF–6FVB’°¢&WGW&âÄæf–vFRFóÒ"÷6–væ–ã÷&WGW&å÷FóÒS$g&W÷'G2S$fW†V7WF—fR"&WÆ6Róã°¢Ð ¢–b†–çfÆ–DFöÖ–å&rÓÒçVÆÂ’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×6†VÆÂ×67&VVâ–GBÖW†V7WF—fR×&W÷'B×6†VÆÂ"&öÆSÒ&ÆW'B#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷"#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äW†V7WF—fR&W÷'CÂ÷à¢ÆƒåVæ¶æ÷vâ&W÷'BFöÖ–ãÂöƒà¢Çà¢Æ6öFSç¶–çfÆ–DFöÖ–å&wÓÂö6öFSâ—2æ÷B&V6övæ—¦VB&W÷'BFöÖ–ââ6†ö÷6Ru2Âv—D‡V"Â·V&W&æWFW2Â÷"ÆÂFð¢6öçF–çVRà¢Â÷à¢·&VæFW$FöÖ–å7v—F6‚‚—Ð¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B"FóÒ"ö#à¢&WGW&âFò ¢ÂôÆ–æ³à¢Âö'F–6ÆSà¢Â÷6V7F–öãà¢“°¢Ð ¢–b‡6W76–öäÆöF–ærÇÂÆöF–æu&W÷'B’°¢&WGW&âÄ6†VÆÄÆöF–ærÖW76vSÒ$ÆöF–ærW†V7WF—fR&W÷'B"óã°¢Ð ¢–b‡6W76–öäW'&÷"ÇÂ&W÷'DW'&÷"’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×6†VÆÂ×67&VVâ–GBÖW†V7WF—fR×&W÷'B×6†VÆÂ"&öÆSÒ&ÆW'B#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷"#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äW†V7WF—fR&W÷'CÂ÷à¢ÆƒåVæ&ÆRFòÆöBW†V7WF—fR&W÷'CÂöƒà¢Çç·6W76–öäW'&÷"ÇÂ&W÷'DW'&÷'ÓÂ÷à¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B"FóÒ"ö#à¢&WGW&âFò ¢ÂôÆ–æ³à¢Âö'F–6ÆSà¢Â÷6V7F–öãà¢“°¢Ð ¢–b‚ÖSòæ÷&uö–BÇÂÖRçv÷&·76Uö–B’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×6†VÆÂ×67&VVâ–GBÖW†V7WF—fR×&W÷'B×6†VÆÂ#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖ×æVÂ#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äW†V7WF—fR&W÷'CÂ÷à¢Æƒä÷&væ—¦F–öâ6öçFW‡B&WV—&VCÂöƒà¢Çå–÷W"66÷VçBæVVG2â7F—fR÷&væ—¦F–öâæBv÷&·76R&Vf÷&RF†RW†V7WF—fR&W÷'B6â&R&VæFW&VBãÂ÷à¢Âö'F–6ÆSà¢Â÷6V7F–öãà¢“°¢Ð ¢–b‚&W÷'B’°¢&WGW&âÄ6†VÆÄÆöF–ærÖW76vSÒ%&W&–ærW†V7WF—fR&W÷'B"óã°¢Ð ¢6öç7B†–v…&–÷&—G”f–æF–æw2Ò6÷VçD†–v…&–÷&—G”W†V7WF—fTf–æF–æw2‡&W÷'B“°¢6öç7BvVV´FVÇFÒ&W÷'BçvVVµö÷fW%÷vVV²æFVÇF°¢6öç7BF÷f–æF–æuG—W2Ò&W÷'BçF÷öf–æF–æu÷G—W2óòµÓ°¢6öç7B6WfW&—G•&÷w2ÒU„T5UD•dUõ$Uõ%Eõ4UdU$•E•ôõ$DU"æÖ‚‡6WfW&—G’’Óâ‡°¢6WfW&—G’À¢6÷VçC¢&W÷'Bæ÷Våö'•÷6WfW&—G•·6WfW&—G•Òóò ¢Ò’“°¢òò$&6²Fòv÷&·76R"×W7B&WGW&âFòF†Rv÷&·76Rv†÷6R&W÷'B—26†÷vâà¢òòf÷"66÷VB&÷WFR‚öó§FVæçD”Bó§v÷&·76T”B÷&W÷'G2’F†B—2F†R&÷WFP¢òò66÷RÂv†–6‚6âF–ffW"g&öÒF†RW6W"w27W'&VçBöFVfVÇBv÷&·76S²öæÇ¢òòfÆÂ&6²FòF†R7W'&VçB×W6W"F‚f÷"F†RVç66÷VBÆVv7’&÷WFRà¢6öç7BF‚Ð¢FVæçD”Bbbv÷&·76T”Bò'V–ÆEFVæçEv÷&·76UF‚‡FVæçD”BÂv÷&·76T”B’¢'V–ÆD7W'&VçEW6W$F‚†ÖR“° ¢6öç7BF÷FÄ÷VâÒ&W÷'BçF÷FÅö÷Våöf–æF–æw3°¢6öç7B6†&U7BÒ†6÷VçC¢çVÖ&W"’Óâ‡F÷FÄ÷VââòÖF‚ç&÷VæB‚†6÷VçBòF÷FÄ÷Vâ’¢’¢“°¢6öç7Bf—6–&ÆU6WfW&—G’Ò6WfW&—G•&÷w2æf–ÇFW"‚‡&÷r’Óâ&÷ræ6÷VçBâ“°¢6öç7Bv–æF÷tÆ&VÂÒG¶f÷&ÖE6†÷'DFFTÆ&VÂ‡&W÷'Bçv–æF÷u÷7F'B—Ò(	2G¶f÷&ÖE6†÷'DFFTÆ&VÂ‡&W÷'Bçv–æF÷uöVæB—Ö° ¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×6†VÆÂ×67&VVâ–GBÖW†V7WF—fR×&W÷'B×6†VÆÂ#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖW†V2×&W÷'B#à¢Æ†VFW"6Æ74æÖSÒ&–GBÖW†V2×&W÷'Eõö†VFW"#à¢ÆF—b6Æ74æÖSÒ&–GBÖW†V2×&W÷'Eõ÷F—FÆR#à¢Ç6Æ74æÖSÒ&–GBÖW†V2×&W÷'EõöW–V'&÷r#äW†V7WF—fR&W÷'CÂ÷à¢Æƒå&—6²÷7GW&R7VÖÖ'“Âöƒà¢Ç6Æ74æÖSÒ&–GBÖW†V2×&W÷'EõöÖWF#à¢Ç7ãà¢÷&væ—¦F–öâÇ7G&öæsç·&W÷'Bæ÷&væ—¦F–öåö–GÓÂ÷7G&öæsà¢Â÷7ãà¢Ç7â&–Ö†–FFVãÒ'G'VR#ì+sÂ÷7ãà¢Ç7ãç·v–æF÷tÆ&VÇÓÂ÷7ãà¢Ç7â&–Ö†–FFVãÒ'G'VR#ì+sÂ÷7ãà¢Ç7ãävVæW&FVB¶f÷&ÖDFFTÆ&VÂ‡&W÷'BævVæW&FVEöB—ÓÂ÷7ãà¢Â÷à¢ÂöF—cà¢·&VæFW$FöÖ–å7v—F6‚‚—Ð¢ÆF—b6Æ74æÖSÒ&–GBÖW†V2×&W÷'Eõö7F–öç2#à¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B"Fó×¶F‡Óà¢&6²Fòv÷&·76P¢ÂôÆ–æ³à¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’–GBÖW†V2×&W÷'EõöF÷væÆöB ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’ÓâF÷væÆöDW†V7WF—fU&W÷'B‡&W÷'BÂ†–v…&–÷&—G”f–æF–æw2—Ð¢à¢Ç7fp¢&–Ö†–FFVãÒ'G'VR ¢fö7W6&ÆSÒ&fÇ6R ¢v–GFƒÒ#B ¢†V–v‡CÒ#B ¢f–Wt&÷ƒÒ#bb ¢f–ÆÃÒ&æöæR ¢7G&ö¶SÒ&7W'&VçD6öÆ÷" ¢7G&ö¶Uv–GFƒÒ#ãb ¢7G&ö¶TÆ–æV6Ò'&÷VæB ¢7G&ö¶TÆ–æV¦ö–ãÒ'&÷VæB ¢à¢ÇF‚CÒ$Ó‚'c‚ãR"óà¢ÇF‚CÒ$ÓBãRtÃ‚ãRãRr"óà¢ÇF‚CÒ$Ó"ãR2ãVƒ"óà¢Â÷7fsà¢F÷væÆöB&W÷'@¢Âö'WGFöãà¢ÂöF—cà¢Âö†VFW#à ¢ÆFÂ6Æ74æÖSÒ&–GBÖW†V2Ö·—2"&–ÖÆ&VÃÒ$W†V7WF—fR&W÷'B7VÖÖ'’#à¢ÆF—b6Æ74æÖSÒ&–GBÖW†V2Ö·’#à¢ÆGCä÷Vâf–æF–æw3ÂöGCà¢ÆFCç·F÷FÄ÷VâçFôÆö6ÆU7G&–ær‚—ÓÂöFCà¢Çç¶†–v…&–÷&—G”f–æF–æw7Ò7&—F–6Â÷"†–vƒÂ÷à¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖW†V2Ö·’#à¢ÆGCäæWB6†ævR+rrF—3ÂöGCà¢ÆFCç·vVV´FVÇFâò²G·vVV´FVÇFÖ¢vVV´FVÇFÓÂöFCà¢Çà¢·&W÷'BçvVVµö÷fW%÷vVV²æ7W'&VçEö6÷VçGÒæWr+r·&W÷'BçvVVµö÷fW%÷vVV²ç&Wf–÷W5ö6÷VçGÒ&Wf–÷W0¢Â÷à¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖW†V2Ö·’#à¢ÆGCäÖVâF–ÖRFò&W6öÇfSÂöGCà¢ÆFCç¶f÷&ÖDW†V7WF—fTGW&F–öâ‡&W÷'BæÖVå÷F–ÖU÷Fõ÷&W6öÇfSòç6V6öæG2—ÓÂöFCà¢Çà¢·&W÷'BæÖVå÷F–ÖU÷Fõ÷&W6öÇfP¢òG·&W÷'BæÖVå÷F–ÖU÷Fõ÷&W6öÇfRç&W6öÇfVEö6÷VçGÒ&W6öÇfVB6×ÆW6 ¢¢tv—F–ær&VÆ–&ÆR&W6öÇWF–öâFFwÐ¢Â÷à¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖW†V2Ö·’#à¢ÆGCåF÷&—6²G—SÂöGCà¢ÆFCç·F÷f–æF–æuG—W5³Òòf÷&ÖEFö¶VäÆ&VÂ‡F÷f–æF–æuG—W5³ÒçG—R’¢~(	BwÓÂöFCà¢Çà¢·F÷f–æF–æuG—W5³Ð¢òG·F÷f–æF–æuG—W5³Òæ6÷VçGÒöbG·F÷FÄ÷VçÒ÷Væ ¢¢tæò÷Vâf–æF–æw2–â66÷RwÐ¢Â÷à¢ÂöF—cà¢ÂöFÃà ¢·F÷FÄ÷VâÓÓÒò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æò÷Vâf–æF–æw2–âF†—2&W÷'Bv–æF÷r ¢&öG“Ò%F†R7W'&VçB÷&væ—¦F–öâ&W÷'B†2æò÷Vâf–æF–æw2Fò&–÷&—F—¦Râ ¢óà¢’¢€¢Ãà¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖW†V2×6V7F–öâ#à¢Æƒ#å6WfW&—G’6ö×÷6—F–öãÂöƒ#à¢Ç6Æ74æÖSÒ&–GBÖW†V2×6V7F–öåõöÆVFR#à¢†÷rF†R·F÷FÄ÷VâçFôÆö6ÆU7G&–ær‚—Ò÷Vâf–æF–æw2'&V²F÷vâFöF’à¢Â÷à¢ÆF—`¢6Æ74æÖSÒ&–GBÖW†V2×7F6² ¢&öÆSÒ&–Ör ¢&–ÖÆ&VÃ×¶÷Vâf–æF–æw2'’6WfW&—G“¢G·6WfW&—G•&÷w0¢æf–ÇFW"‚‡&÷r’Óâ&÷ræ6÷VçBâ¢æÖ‚‡&÷r’ÓâG¶f÷&ÖEFö¶VäÆ&VÂ‡&÷rç6WfW&—G’—ÒG·&÷ræ6÷VçGÖ¢æ¦ö–â‚rÂr—ÖÐ¢à¢·f—6–&ÆU6WfW&—G’æÖ‚‡&÷r’Óâ€¢Ç7à¢¶W“×·&÷rç6WfW&—G—Ð¢6Æ74æÖS×¶–GBÖW†V2×7F6µõ÷6Vr—2ÒG·&÷rç6WfW&—G—ÖÐ¢7G–ÆS×·²v–GFƒ¢G·6†&U7B‡&÷ræ6÷VçB—ÒV×Ð¢óà¢’—Ð¢ÂöF—cà¢ÇVÂ6Æ74æÖSÒ&–GBÖW†V2ÖÆVvVæB#à¢·6WfW&—G•&÷w2æÖ‚‡&÷r’Óâ€¢ÆÆ’¶W“×·&÷rç6WfW&—G—Ò6Æ74æÖS×·&÷ræ6÷VçBÓÓÒòv—2ÖV×G’r¢VæFVf–æVGÓà¢Ç7â6Æ74æÖS×¶–GBÖW†V2ÖF÷B—2ÒG·&÷rç6WfW&—G—ÖÒ&–Ö†–FFVãÒ'G'VR"óà¢Ç7â6Æ74æÖSÒ&–GBÖW†V2ÖÆVvVæEõöÆ&VÂ#ç¶f÷&ÖEFö¶VäÆ&VÂ‡&÷rç6WfW&—G’—ÓÂ÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖW†V2ÖÆVvVæEõö6÷VçB#ç·&÷ræ6÷VçGÓÂ÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖW†V2ÖÆVvVæEõ÷6†&R#ç·6†&U7B‡&÷ræ6÷VçB—ÒSÂ÷7ãà¢ÂöÆ“à¢’—Ð¢Â÷VÃà¢Â÷6V7F–öãà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖW†V2×6V7F–öâ#à¢Æƒ#åF÷f–æF–ærG—W3Âöƒ#à¢Ç6Æ74æÖSÒ&–GBÖW†V2×6V7F–öåõöÆVFR#åF†VÖW2G&—f–ær÷Vâ&—6²F†—2v–æF÷rãÂ÷à¢·F÷f–æF–æuG—W2æÆVæwF‚âò€¢ÆöÂ6Æ74æÖSÒ&–GBÖW†V2×&æ²#à¢·F÷f–æF–æuG—W2æÖ‚†—FVÒÂ–æFW‚’Óâ€¢ÆÆ’¶W“×¶—FVÒçG—WÓà¢Ç7â6Æ74æÖSÒ&–GBÖW†V2×&æµõö–æFW‚#çµ7G&–ær†–æFW‚²’çE7F'Bƒ"Âsr—ÓÂ÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖW†V2×&æµõöÆ&VÂ#ç¶f÷&ÖEFö¶VäÆ&VÂ†—FVÒçG—R—ÓÂ÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖW†V2×&æµõ÷6†&R#ç·6†&U7B†—FVÒæ6÷VçB—ÒSÂ÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖW†V2×&æµõö6÷VçB#ç¶—FVÒæ6÷VçGÓÂ÷7ãà¢ÂöÆ“à¢’—Ð¢ÂööÃà¢’¢€¢Ç6Æ74æÖSÒ&–GBÖW†V2×6V7F–öåõöV×G’#à¢f–æF–ærG—R'&V¶F÷vâv–ÆÂV"öæ6Rf–æF–æw2&R&W6VçBà¢Â÷à¢—Ð¢Â÷6V7F–öãà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖW†V2×6V7F–öâ#à¢Æƒ#äæ÷FW2f÷"ÆVFW'6†—Âöƒ#à¢ÇVÂ6Æ74æÖSÒ&–GBÖW†V2Öæ÷FW2#à¢ÆÆ“à¢·vVV´FVÇFâ ¢ò÷Vâf–æF–ærföÇVÖRw&Wr'’G·vVV´FVÇFÒ6ö×&VBv—F‚F†R&–÷"rÖF’v–æF÷ræ ¢¢vVV´FVÇFÂ ¢ò÷Vâf–æF–ærföÇVÖRfVÆÂ'’G´ÖF‚æ'2‡vVV´FVÇF—Ò6ö×&VBv—F‚F†R&–÷"rÖF’v–æF÷ræ ¢¢t÷Vâf–æF–ærföÇVÖR†VÆB7FVG’v–ç7BF†R&–÷"rÖF’v–æF÷râwÐ¢ÂöÆ“à¢ÆÆ“à¢·&W÷'BæÖVå÷F–ÖU÷Fõ÷&W6öÇfP¢òÖVâF–ÖRFò&W6öÇfR—2G¶f÷&ÖDW†V7WF—fTGW&F–öâ‡&W÷'BæÖVå÷F–ÖU÷Fõ÷&W6öÇfRç6V6öæG2—Ò7&÷72G·&W÷'BæÖVå÷F–ÖU÷Fõ÷&W6öÇfRç&W6öÇfVEö6÷VçGÒ&W6öÇfVBf–æF–æw2v—F‚&VÆ–&ÆRF–ÖW7F×2æ ¢¢tÖVâF–ÖRFò&W6öÇfRv–ÆÂ&R&W÷'FVBöæ6R&W6öÇfVBf–æF–æw267V×VÆFR&VÆ–&ÆRF–ÖW7F×2âwÐ¢ÂöÆ“à¢·F÷f–æF–æuG—W5³Òò€¢ÆÆ“à¢Æ&vW7BF†VÖR—2Ç7G&öæsç¶f÷&ÖEFö¶VäÆ&VÂ‡F÷f–æF–æuG—W5³ÒçG—R—ÓÂ÷7G&öæsâÂ&W&W6VçF–æw²rwÐ¢·6†&U7B‡F÷f–æF–æuG—W5³Òæ6÷VçB—ÒRöb÷Vâf–æF–æw2à¢ÂöÆ“à¢’¢çVÆÇÐ¢Â÷VÃà¢Â÷6V7F–öãà¢Âóà¢—Ð ¢Æfö÷FW"6Æ74æÖSÒ&–GBÖW†V2×&W÷'Eõöfö÷FW"#à¢Çà¢66÷S¢÷&væ—¦F–öâ·&W÷'Bæ÷&væ—¦F–öåö–GÒÂv–æF÷r·v–æF÷tÆ&VÇÒà¢Â÷à¢ÇävVæW&FVB'’–FVçG&–Âöâ¶f÷&ÖDFFTÆ&VÂ‡&W÷'BævVæW&FVEöB—ÒãÂ÷à¢Âöfö÷FW#à¢Âö'F–6ÆSà¢Â÷6V7F–öãà¢“°§Ð §G—RÖVÖ&W$G&gE7FFRÒ&V6÷&CÀ¢7G&–ærÀ¢°¢&öÆS¢v÷&·76TÖVÖ&W%&öÆS°¢7FGW3¢v÷&·76TÖVÖ&W%7FGW3°¢Ð£ã° ¦W‡÷'BgVæ7F–öâ&öGV7Ev÷&·76W5vR‚’°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7Bæf–vFRÒW6Tæf–vFR‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“° ¢6öç7B¶ÆöF–ærÂ6WDÆöF–æuÒÒW6U7FFR‡G'VR“°¢6öç7B¶W'&÷"Â6WDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·7V66W74ÖW76vRÂ6WE7V66W74ÖW76vUÒÒW6U7FFR‚rr“° ¢6öç7B·v†ôÔ’Â6WEv†ôÔ•ÒÒW6U7FFSÅv†ôÔ•&W7öç6RÂçVÆÃâ†çVÆÂ“°¢6öç7B¶ÖVÖ&W'2Â6WDÖVÖ&W'5ÒÒW6U7FFSÅv÷&·76TÖVÖ&W%&V6÷&EµÓâ…µÒ“°¢6öç7B¶ÖVÖ&W$G&gG2Â6WDÖVÖ&W$G&gG5ÒÒW6U7FFSÄÖVÖ&W$G&gE7FFSâ‡·Ò“° ¢6öç7B·v÷&·76UF&vWBÂ6WEv÷&·76UF&vWEÒÒW6U7FFR‚rr“°¢6öç7B·7v—F6†–ærÂ6WE7v—F6†–æuÒÒW6U7FFR†fÇ6R“° ¢6öç7B¶ÖVÖ&W%6V&6‚Â6WDÖVÖ&W%6V&6…ÒÒW6U7FFR‚rr“°¢6öç7B¶ÖVÖ&W%&öÆTf–ÇFW"Â6WDÖVÖ&W%&öÆTf–ÇFW%ÒÒW6U7FFSÂvÆÂrÂv÷&·76TÖVÖ&W%&öÆSâ‚vÆÂr“°¢6öç7B¶ÖVÖ&W%7FGW4f–ÇFW"Â6WDÖVÖ&W%7FGW4f–ÇFW%ÒÒW6U7FFSÂvÆÂrÂv÷&·76TÖVÖ&W%7FGW3â‚vÆÂr“° ¢6öç7B¶–çf—F–ærÂ6WD–çf—F–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶–çf—FT–çWBÂ6WD–çf—FT–çWEÒÒW6U7FFR‡°¢W6W$”C¢rrÀ¢VÖ–Ã¢rrÀ¢&öÆS¢wf–WvW"r2v÷&·76TÖVÖ&W%&öÆRÀ¢7FGW3¢v–çf—FVBr2v÷&·76TÖVÖ&W%7FGW0¢Ò“° ¢6öç7B·6f–ætÖVÖ&W$”BÂ6WE6f–ætÖVÖ&W$”EÒÒW6U7FFR‚rr“°¢6öç7B·&VÖ÷f–ætÖVÖ&W$”BÂ6WE&VÖ÷f–ætÖVÖ&W$”EÒÒW6U7FFR‚rr“°¢6öç7BÖVÖ&W'5&WVW7E&VbÒW6U&Vbƒ“° ¢6öç7B&Vg&W6„ÖVÖ&W'2Ò7–æ2‡F&vWE66÷S¢&öGV7E6W76–öâ’Óâ°¢6öç7B&WVW7D”BÒ²¶ÖVÖ&W'5&WVW7E&Vbæ7W'&VçC°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡F&vWE66÷R“°¢6öç7B&W7öç6RÒv—B”6Æ–VçBæÆ—7Ev÷&·76TÖVÖ&W'2‡F&vWE66÷Rçv÷&·76T”BÂ·ÒÂWF‚“°¢–b‡&WVW7D”BÓÒÖVÖ&W'5&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WDÖVÖ&W'2‡&W7öç6Ræ—FV×2“°¢6WDÖVÖ&W$G&gG2€¢&W7öç6Ræ—FV×2ç&VGV6SÄÖVÖ&W$G&gE7FFSâ‚†62ÂÖVÖ&W"’Óâ°¢65¶ÖVÖ&W"æÖVÖ&W%ö–EÒÒ²&öÆS¢ÖVÖ&W"ç&öÆRÂ7FGW3¢ÖVÖ&W"ç7FGW2Ó°¢&WGW&â63°¢ÒÂ·Ò¢“°¢Ó° ¢W6TVffV7B‚‚’Óâ°¢&WGW&â‚’Óâ°¢ÖVÖ&W'5&WVW7E&Vbæ7W'&VçB³Ò°¢Ó°¢ÒÂ·66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”EÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚66÷R’°¢6WDÆöF–ær†fÇ6R“°¢6WDW'&÷"‚uv÷&·76R&÷WFR6öçFW‡B—2Ö—76–ærâr“°¢&WGW&ã°¢Ð ¢ÆWBÖ÷VçFVBÒG'VS°¢6öç7B'VâÒ7–æ2‚’Óâ°¢6WDÆöF–ær‡G'VR“°¢6WDW'&÷"‚rr“°¢6WE7V66W74ÖW76vR‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢6öç7B6æ6†÷BÒv—B”6Æ–VçBævWEv†ôÔ’†WF‚“°¢–b‚Ö÷VçFVB’°¢&WGW&ã°¢Ð¢6WEv†ôÔ’‡6æ6†÷B“°¢6WEv÷&·76UF&vWB‡6æ6†÷Bç66÷Sòçv÷&·76Uö–BÇÂ66÷Rçv÷&·76T”B“°¢v—B&Vg&W6„ÖVÖ&W'2‡66÷R“°¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‚Ö÷VçFVB’°¢&WGW&ã°¢Ð¢6öç7BÖW76vRÒ&WVW7DW'&÷"–ç7Fæ6VöbW'&÷"ò&WVW7DW'&÷"æÖW76vR¢tf–ÆVBFòÆöBv÷&·76RFÖ–æ—7G&F–öâFFâs°¢6WDW'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢–b†Ö÷VçFVB’°¢6WDÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó°¢fö–B'Vâ‚“°¢&WGW&â‚’Óâ°¢Ö÷VçFVBÒfÇ6S°¢Ó°¢ÒÂ·66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”EÒ“° ¢–b‚66÷R’°¢&WGW&âÄ6†VÆÄÆöF–ærÖW76vSÒ%&W6öÇf–ærv÷&·76R66÷R"óã°¢Ð ¢6öç7B6äFÖ–âÒ†5v÷&·76TFÖ–ä66W72‡66÷RÂv†ôÔ’“°¢6öç7B&öÆT6÷VçG2ÒÖVÖ&W'2ç&VGV6SÅ&V6÷&CÅv÷&·76TÖVÖ&W%&öÆRÂçVÖ&W#ãâ€¢†62ÂÖVÖ&W"’Óâ°¢65¶ÖVÖ&W"ç&öÆUÒ³Ò°¢&WGW&â63°¢ÒÀ¢²÷væW#¢ÂFÖ–ã¢ÂæÇ—7C¢Âf–WvW#¢Ð¢“° ¢6öç7B7F—fT6÷VçBÒÖVÖ&W'2æf–ÇFW"‚†ÖVÖ&W"’ÓâÖVÖ&W"ç7FGW2ÓÓÒv7F—fRr’æÆVæwFƒ°¢6öç7B–çf—FVD6÷VçBÒÖVÖ&W'2æf–ÇFW"‚†ÖVÖ&W"’ÓâÖVÖ&W"ç7FGW2ÓÓÒv–çf—FVBr’æÆVæwFƒ°¢6öç7Bf–ÇFW&VDÖVÖ&W'2ÒÖVÖ&W'2æf–ÇFW"‚†ÖVÖ&W"’Óâ°¢6öç7B6V&6‚Òæ÷&ÖÆ—¦UfÇVR†ÖVÖ&W%6V&6‚’çFôÆ÷vW$66R‚“°¢6öç7BÖF6†W56V&6‚Ð¢6V&6‚æÆVæwF‚ÓÓÒÇÀ¢ÖVÖ&W"çW6W%ö–BçFôÆ÷vW$66R‚’æ–æ6ÇVFW2‡6V&6‚’ÇÀ¢†ÖVÖ&W"æVÖ–Âóòrr’çFôÆ÷vW$66R‚’æ–æ6ÇVFW2‡6V&6‚’ÇÀ¢ÖVÖ&W"æÖVÖ&W%ö–BçFôÆ÷vW$66R‚’æ–æ6ÇVFW2‡6V&6‚“°¢6öç7BÖF6†W5&öÆRÒÖVÖ&W%&öÆTf–ÇFW"ÓÓÒvÆÂrÇÂÖVÖ&W"ç&öÆRÓÓÒÖVÖ&W%&öÆTf–ÇFW#°¢6öç7BÖF6†W57FGW2ÒÖVÖ&W%7FGW4f–ÇFW"ÓÓÒvÆÂrÇÂÖVÖ&W"ç7FGW2ÓÓÒÖVÖ&W%7FGW4f–ÇFW#°¢&WGW&âÖF6†W56V&6‚bbÖF6†W5&öÆRbbÖF6†W57FGW3°¢Ò“° ¢6öç7B†æFÆU7v—F6…v÷&·76RÒ7–æ2‚’Óâ°¢–b‚v÷&·76UF&vWBÇÂv÷&·76UF&vWBÓÓÒ66÷Rçv÷&·76T”B’°¢&WGW&ã°¢Ð¢6WE7v—F6†–ær‡G'VR“°¢6WDW'&÷"‚rr“°¢6WE7V66W74ÖW76vR‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢6öç7B&W7öç6RÒv—B”6Æ–VçBç&W6öÇfT7F—fUv÷&·76R‡v÷&·76UF&vWBÂWF‚“°¢6öç7B7v—F6†VE66÷S¢&öGV7E6W76–öâÒ°¢ââç66÷RÀ¢FVæçD”C¢&W7öç6Rç66÷RçFVæçEö–BÀ¢v÷&·76T”C¢&W7öç6Rç66÷Rçv÷&·76Uö–@¢Ó°¢æf–vFR†'V–ÆE66÷VEF‚‡7v—F6†VE66÷RÂwv÷&·76W2r’Â²&WÆ6S¢G'VRÒ“°¢Ò6F6‚‡7v—F6„W'&÷"’°¢6öç7BÖW76vRÒ7v—F6„W'&÷"–ç7Fæ6VöbW'&÷"ò7v—F6„W'&÷"æÖW76vR¢tf–ÆVBFò7v—F6‚v÷&·76Râs°¢6WDW'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢6WE7v—F6†–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆT–çf—FTÖVÖ&W"Ò7–æ2†WfVçC¢f÷&ÔWfVçCÄ…DÔÄf÷&ÔVÆVÖVçCâ’Óâ°¢WfVçBç&WfVçDFVfVÇB‚“°¢–b‚6äFÖ–â’°¢&WGW&ã°¢Ð¢6WD–çf—F–ær‡G'VR“°¢6WDW'&÷"‚rr“°¢6WE7V66W74ÖW76vR‚rr“°¢G'’°¢6öç7BW6W$”BÒæ÷&ÖÆ—¦UfÇVR†–çf—FT–çWBçW6W$”B“°¢6öç7BVÖ–ÂÒæ÷&ÖÆ—¦UfÇVR†–çf—FT–çWBæVÖ–Â“°¢–b‚W6W$”B’°¢F‡&÷ræWrW'&÷"‚uW6W"”B—2&WV—&VBâr“°¢Ð¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢6öç7BÖVÖ&W$”BÒv—Bv÷&·76TÖVÖ&W$”B†VÖ–ÂÇÂW6W$”B“°¢v—B”6Æ–VçBçW6W'Ev÷&·76TÖVÖ&W"€¢66÷Rçv÷&·76T”BÀ¢°¢ÖVÖ&W%ö–C¢ÖVÖ&W$”BÀ¢W6W%ö–C¢W6W$”BÀ¢VÖ–Ã¢VÖ–ÂÇÂVæFVf–æVBÀ¢&öÆS¢–çf—FT–çWBç&öÆRÀ¢7FGW3¢–çf—FT–çWBç7FGW0¢ÒÀ¢WF€¢“°¢v—B&Vg&W6„ÖVÖ&W'2‡66÷R“°¢6WD–çf—FT–çWB‡°¢W6W$”C¢rrÀ¢VÖ–Ã¢rrÀ¢&öÆS¢wf–WvW"rÀ¢7FGW3¢v–çf—FVBp¢Ò“°¢6WE7V66W74ÖW76vR‚tÖVÖ&W"–çf—FF–öâ6fVBâr“°¢Ò6F6‚†–çf—FTW'&÷"’°¢6öç7BÖW76vRÒ–çf—FTW'&÷"–ç7Fæ6VöbW'&÷"ò–çf—FTW'&÷"æÖW76vR¢tf–ÆVBFò–çf—FRÖVÖ&W"âs°¢6WDW'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢6WD–çf—F–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆU6fTÖVÖ&W"Ò7–æ2†ÖVÖ&W#¢v÷&·76TÖVÖ&W%&V6÷&B’Óâ°¢–b‚6äFÖ–â’°¢&WGW&ã°¢Ð¢6öç7BG&gBÒÖVÖ&W$G&gG5¶ÖVÖ&W"æÖVÖ&W%ö–EÓ°¢–b‚G&gB’°¢&WGW&ã°¢Ð¢6WE6f–ætÖVÖ&W$”B†ÖVÖ&W"æÖVÖ&W%ö–B“°¢6WDW'&÷"‚rr“°¢6WE7V66W74ÖW76vR‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢v—B”6Æ–VçBçW6W'Ev÷&·76TÖVÖ&W"€¢66÷Rçv÷&·76T”BÀ¢°¢ÖVÖ&W%ö–C¢ÖVÖ&W"æÖVÖ&W%ö–BÀ¢W6W%ö–C¢ÖVÖ&W"çW6W%ö–BÀ¢VÖ–Ã¢ÖVÖ&W"æVÖ–ÂÀ¢&öÆS¢G&gBç&öÆRÀ¢7FGW3¢G&gBç7FGW0¢ÒÀ¢WF€¢“°¢v—B&Vg&W6„ÖVÖ&W'2‡66÷R“°¢6WE7V66W74ÖW76vR†WFFVBG¶ÖVÖ&W"çW6W%ö–GÒæ“°¢Ò6F6‚‡6fTW'&÷"’°¢6öç7BÖW76vRÒ6fTW'&÷"–ç7Fæ6VöbW'&÷"ò6fTW'&÷"æÖW76vR¢tf–ÆVBFòWFFRÖVÖ&W"âs°¢6WDW'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢6WE6f–ætÖVÖ&W$”B‚rr“°¢Ð¢Ó° ¢6öç7B†æFÆU&VÖ÷fTÖVÖ&W"Ò7–æ2†ÖVÖ&W#¢v÷&·76TÖVÖ&W%&V6÷&B’Óâ°¢–b‚6äFÖ–â’°¢&WGW&ã°¢Ð¢6öç7B6†÷VÆE&VÖ÷fRÒv–æF÷ræ6öæf—&Ò†&VÖ÷fRG¶ÖVÖ&W"çW6W%ö–GÒg&öÒv÷&·76RG·66÷Rçv÷&·76T”GÓö“°¢–b‚6†÷VÆE&VÖ÷fR’°¢&WGW&ã°¢Ð¢6WE&VÖ÷f–ætÖVÖ&W$”B†ÖVÖ&W"æÖVÖ&W%ö–B“°¢6WDW'&÷"‚rr“°¢6WE7V66W74ÖW76vR‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢v—B”6Æ–VçBæFVÆWFUv÷&·76TÖVÖ&W"‡66÷Rçv÷&·76T”BÂÖVÖ&W"æÖVÖ&W%ö–BÂWF‚“°¢v—B&Vg&W6„ÖVÖ&W'2‡66÷R“°¢6WE7V66W74ÖW76vR†&VÖ÷fVBG¶ÖVÖ&W"çW6W%ö–GÒg&öÒv÷&·76Ræ“°¢Ò6F6‚‡&VÖ÷fTW'&÷"’°¢6öç7BÖW76vRÒ&VÖ÷fTW'&÷"–ç7Fæ6VöbW'&÷"ò&VÖ÷fTW'&÷"æÖW76vR¢tf–ÆVBFò&VÖ÷fRÖVÖ&W"âs°¢6WDW'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢6WE&VÖ÷f–ætÖVÖ&W$”B‚rr“°¢Ð¢Ó° ¢–b†ÆöF–ær’°¢&WGW&â€¢Ä&÷WFTÆöF–æu7FFP¢F—FÆSÒ%&W&–ærv÷&·76R66W72 ¢&öG“Ò%&Vg&W6†–ærÖVÖ&W"66W72FWF–Ç2f÷"F†—2v÷&·76Râ ¢óà¢“°¢Ð ¢6öç7Bf–Æ&ÆUv÷&·76W2Òv†ôÔ“òçv÷&·76W2óòµÓ° ¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GB×v÷&·76RÖFÖ–â#à¢Æ†VFW"6Æ74æÖSÒ&–GB×v÷&·76RÖFÖ–âÖ†VFW"#à¢ÆF—cà¢Æƒ#äÖVÖ&W'3Âöƒ#à¢Çä–çf—FRFVÖÖFW2Â6WB&öÆW2ÂæB¶VWv÷&·76R66W727W'&VçBãÂ÷à¢ÂöF—cà¢Âö†VFW#à ¢¶W'&÷"ò€¢Ç&öÆSÒ&ÆW'B"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#à¢¶W'&÷'Ð¢Â÷à¢’¢çVÆÇÐ¢·7V66W74ÖW76vRò€¢Ç&öÆSÒ'7FGW2"6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'B×7V66W72#à¢·7V66W74ÖW76vWÐ¢Â÷à¢’¢çVÆÇÐ¢²6äFÖ–âò€¢Ç6Æ74æÖSÒ&–GBÖÖÆW'B#à¢–÷R7W'&VçFÇ’†fR&VBÖöæÇ’FVææ7’66W72â6²v÷&·76R÷væW"öFÖ–âFòw&çBVÆWfFVB&öÆR66W72à¢Â÷à¢’¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GB×v÷&·76R×7FG2"&–ÖÆ&VÃÒ'v÷&·76RÖVÖ&W'6†—7VÖÖ'’#à¢Æ'F–6ÆSà¢Æƒ3ç¶ÖVÖ&W'2æÆVæwF‡ÓÂöƒ3à¢ÇåF÷FÂÖVÖ&W'3Â÷à¢Âö'F–6ÆSà¢Æ'F–6ÆSà¢Æƒ3ç¶7F—fT6÷VçGÓÂöƒ3à¢Çä7F—fSÂ÷à¢Âö'F–6ÆSà¢Æ'F–6ÆSà¢Æƒ3ç¶–çf—FVD6÷VçGÓÂöƒ3à¢Çä–çf—FVCÂ÷à¢Âö'F–6ÆSà¢Æ'F–6ÆSà¢Æƒ3ç·&öÆT6÷VçG2æ÷væW"²&öÆT6÷VçG2æFÖ–çÓÂöƒ3à¢ÇäFÖ–ç3Â÷à¢Âö'F–6ÆSà¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GB×v÷&·76RÖFÖ–âÖw&–B#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×v÷&·76RÖ6&B#à¢Æ†VFW"6Æ74æÖSÒ&–GB×v÷&·76RÖ6&BÖ†VFW"#à¢ÆF—cà¢Æƒ3åv÷&·76SÂöƒ3à¢Çä6†ævRF†Rv÷&·76R6öçFW‡Bf÷"F†—26W76–öâãÂ÷à¢ÂöF—cà¢Âö†VFW#à¢ÆF—b6Æ74æÖSÒ&–GB×v÷&·76R×7v—F6†W"#à¢ÆÆ&VÂ‡FÖÄf÷#Ò'v÷&·76R×7v—F6‚×6VÆV7B#åv÷&·76SÂöÆ&VÃà¢Ç6VÆV7@¢–CÒ'v÷&·76R×7v—F6‚×6VÆV7B ¢fÇVS×·v÷&·76UF&vWGÐ¢öä6†ævS×²†WfVçB’Óâ6WEv÷&·76UF&vWB†WfVçBçF&vWBçfÇVR—Ð¢à¢µ²ââæf–Æ&ÆUv÷&·76W5Ð¢ç6÷'B‚†Â"’Óâçv÷&·76RæF—7Æ•öæÖRæÆö6ÆT6ö×&R†"çv÷&·76RæF—7Æ•öæÖR’¢æÖ‚†—FVÒ’Óâ€¢Æ÷F–öâ¶W“×¶—FVÒçv÷&·76Rçv÷&·76Uö–GÒfÇVS×¶—FVÒçv÷&·76Rçv÷&·76Uö–GÓà¢¶—FVÒçv÷&·76RæF—7Æ•öæÖWÒ‡¶—FVÒçv÷&·76Rçv÷&·76Uö–GÒ¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢öä6Æ–6³×²‚’Óâ°¢fö–B†æFÆU7v—F6…v÷&·76R‚“°¢×Ð¢F—6&ÆVC×·7v—F6†–ærÇÂv÷&·76UF&vWBÓÓÒ66÷Rçv÷&·76T”GÐ¢à¢·7v—F6†–æròu7v—F6†–ærâââr¢u7v—F6‚v÷&·76RwÐ¢Âö'WGFöãà¢ÂöF—cà¢Âö'F–6ÆSà ¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×v÷&·76RÖ6&B#à¢Æ†VFW"6Æ74æÖSÒ&–GB×v÷&·76RÖ6&BÖ†VFW"#à¢ÆF—cà¢Æƒ3ä–çf—FRÖVÖ&W#Âöƒ3à¢Çå6WBF†R–æ—F–Â&öÆRæB7FGW2&Vf÷&R66W72—2w&çFVBãÂ÷à¢ÂöF—cà¢Âö†VFW#à¢Æf÷&Ò6Æ74æÖSÒ&–GBÖÖf÷&Ò–GB×v÷&·76RÖ–çf—FRÖf÷&Ò"öå7V&Ö—C×¶†æFÆT–çf—FTÖVÖ&W'Óà¢ÆÆ&VÃà¢W6W"”@¢Æ–çW@¢fÇVS×¶–çf—FT–çWBçW6W$”GÐ¢öä6†ævS×²†WfVçB’Óâ6WD–çf—FT–çWB‚†7W'&VçB’Óâ‡²ââæ7W'&VçBÂW6W$”C¢WfVçBçF&vWBçfÇVRÒ’—Ð¢Æ6V†öÆFW#Ò&Væv–æVW$W†×ÆRæ6öÒ ¢F—6&ÆVC×²6äFÖ–âÇÂ–çf—F–æwÐ¢&WV—&V@¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢VÖ–Â†÷F–öæÂ¢Æ–çW@¢G—SÒ&VÖ–Â ¢fÇVS×¶–çf—FT–çWBæVÖ–ÇÐ¢öä6†ævS×²†WfVçB’Óâ6WD–çf—FT–çWB‚†7W'&VçB’Óâ‡²ââæ7W'&VçBÂVÖ–Ã¢WfVçBçF&vWBçfÇVRÒ’—Ð¢Æ6V†öÆFW#Ò&Væv–æVW$W†×ÆRæ6öÒ ¢F—6&ÆVC×²6äFÖ–âÇÂ–çf—F–æwÐ¢óà¢ÂöÆ&VÃà¢ÆF—b6Æ74æÖSÒ&–GB×v÷&·76RÖ–æÆ–æRÖf–VÆG2#à¢ÆÆ&VÃà¢&öÆP¢Ç6VÆV7@¢fÇVS×¶–çf—FT–çWBç&öÆWÐ¢öä6†ævS×²†WfVçB’Óà¢6WD–çf—FT–çWB‚†7W'&VçB’Óâ‡²ââæ7W'&VçBÂ&öÆS¢WfVçBçF&vWBçfÇVR2v÷&·76TÖVÖ&W%&öÆRÒ’¢Ð¢F—6&ÆVC×²6äFÖ–âÇÂ–çf—F–æwÐ¢à¢´ÔTÔ$U%õ$ôÄUôõD”ôå2æÖ‚‡&öÆR’Óâ€¢Æ÷F–öâ¶W“×·&öÆWÒfÇVS×·&öÆWÓà¢·&öÆWÐ¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢7FGW0¢Ç6VÆV7@¢fÇVS×¶–çf—FT–çWBç7FGW7Ð¢öä6†ævS×²†WfVçB’Óà¢6WD–çf—FT–çWB‚†7W'&VçB’Óâ‡²ââæ7W'&VçBÂ7FGW3¢WfVçBçF&vWBçfÇVR2v÷&·76TÖVÖ&W%7FGW2Ò’¢Ð¢F—6&ÆVC×²6äFÖ–âÇÂ–çf—F–æwÐ¢à¢´ÔTÔ$U%õ5DEU5ôõD”ôå2æÖ‚‡7FGW2’Óâ€¢Æ÷F–öâ¶W“×·7FGW7ÒfÇVS×·7FGW7Óà¢·7FGW7Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÂöF—cà¢Æ'WGFöâ6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’"G—SÒ'7V&Ö—B"F—6&ÆVC×²6äFÖ–âÇÂ–çf—F–æwÓà¢¶–çf—F–æròu6f–ærâââr¢u6VæB–çf—FRwÐ¢Âö'WGFöãà¢Âöf÷&Óà¢Âö'F–6ÆSà¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GB×v÷&·76RÖÖVÖ&W"×FööÆ&"#à¢ÆÆ&VÃà¢6V&6€¢Æ–çW@¢fÇVS×¶ÖVÖ&W%6V&6‡Ð¢öä6†ævS×²†WfVçB’Óâ6WDÖVÖ&W%6V&6‚†WfVçBçF&vWBçfÇVR—Ð¢Æ6V†öÆFW#Ò'W6W"–BÂVÖ–ÂÂ÷"ÖVÖ&W"–B ¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢&öÆP¢Ç6VÆV7@¢fÇVS×¶ÖVÖ&W%&öÆTf–ÇFW'Ð¢öä6†ævS×²†WfVçB’Óâ6WDÖVÖ&W%&öÆTf–ÇFW"†WfVçBçF&vWBçfÇVR2vÆÂrÂv÷&·76TÖVÖ&W%&öÆR—Ð¢à¢Æ÷F–öâfÇVSÒ&ÆÂ#æÆÃÂö÷F–öãà¢´ÔTÔ$U%õ$ôÄUôõD”ôå2æÖ‚‡&öÆR’Óâ€¢Æ÷F–öâ¶W“×·&öÆWÒfÇVS×·&öÆWÓà¢·&öÆWÐ¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢7FGW0¢Ç6VÆV7@¢fÇVS×¶ÖVÖ&W%7FGW4f–ÇFW'Ð¢öä6†ævS×²†WfVçB’Óâ6WDÖVÖ&W%7FGW4f–ÇFW"†WfVçBçF&vWBçfÇVR2vÆÂrÂv÷&·76TÖVÖ&W%7FGW2—Ð¢à¢Æ÷F–öâfÇVSÒ&ÆÂ#æÆÃÂö÷F–öãà¢´ÔTÔ$U%õ5DEU5ôõD”ôå2æÖ‚‡7FGW2’Óâ€¢Æ÷F–öâ¶W“×·7FGW7ÒfÇVS×·7FGW7Óà¢·7FGW7Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GB×v÷&·76R×F&ÆR×w&#à¢ÇF&ÆR6Æ74æÖSÒ&–GB×v÷&·76R×F&ÆR#à¢ÇF†VCà¢ÇG#à¢ÇFƒåW6W#Â÷Fƒà¢ÇFƒå&öÆSÂ÷Fƒà¢ÇFƒå7FGW3Â÷Fƒà¢ÇFƒäÆ7BWFFVCÂ÷Fƒà¢ÇFƒä7F–öç3Â÷Fƒà¢Â÷G#à¢Â÷F†VCà¢ÇF&öG“à¢¶f–ÇFW&VDÖVÖ&W'2æÖ‚†ÖVÖ&W"’Óâ°¢6öç7BG&gBÒÖVÖ&W$G&gG5¶ÖVÖ&W"æÖVÖ&W%ö–EÒóò²&öÆS¢ÖVÖ&W"ç&öÆRÂ7FGW3¢ÖVÖ&W"ç7FGW2Ó°¢6öç7BF—'G’ÒG&gBç&öÆRÓÒÖVÖ&W"ç&öÆRÇÂG&gBç7FGW2ÓÒÖVÖ&W"ç7FGW3°¢&WGW&â€¢ÇG"¶W“×¶ÖVÖ&W"æÖVÖ&W%ö–GÓà¢ÇFCà¢Ç7G&öæsç¶ÖVÖ&W"çW6W%ö–GÓÂ÷7G&öæsà¢¶ÖVÖ&W"æVÖ–ÂòÇ7ãç¶ÖVÖ&W"æVÖ–ÇÓÂ÷7ãâ¢çVÆÇÐ¢ÆFWF–Ç26Æ74æÖSÒ&–GB×v÷&·76RÖÖVÖ&W"ÖFWF–Ç2#à¢Ç7VÖÖ'“äÖVÖ&W"FWF–Ç3Â÷7VÖÖ'“à¢ÆFÃà¢ÆF—cà¢ÆGCäÖVÖ&W"”CÂöGCà¢ÆFCç¶ÖVÖ&W"æÖVÖ&W%ö–GÓÂöFCà¢ÂöF—cà¢ÂöFÃà¢ÂöFWF–Ç3à¢Â÷FCà¢ÇFCà¢Ç6VÆV7@¢fÇVS×¶G&gBç&öÆWÐ¢öä6†ævS×²†WfVçB’Óà¢6WDÖVÖ&W$G&gG2‚†7W'&VçB’Óâ‡°¢ââæ7W'&VçBÀ¢¶ÖVÖ&W"æÖVÖ&W%ö–EÓ¢°¢&öÆS¢WfVçBçF&vWBçfÇVR2v÷&·76TÖVÖ&W%&öÆRÀ¢7FGW3¢7W'&VçE¶ÖVÖ&W"æÖVÖ&W%ö–EÓòç7FGW2óòÖVÖ&W"ç7FGW0¢Ð¢Ò’¢Ð¢F—6&ÆVC×²6äFÖ–çÐ¢à¢´ÔTÔ$U%õ$ôÄUôõD”ôå2æÖ‚‡&öÆR’Óâ€¢Æ÷F–öâ¶W“×·&öÆWÒfÇVS×·&öÆWÓà¢·&öÆWÐ¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢Â÷FCà¢ÇFCà¢Ç6VÆV7@¢fÇVS×¶G&gBç7FGW7Ð¢öä6†ævS×²†WfVçB’Óà¢6WDÖVÖ&W$G&gG2‚†7W'&VçB’Óâ‡°¢ââæ7W'&VçBÀ¢¶ÖVÖ&W"æÖVÖ&W%ö–EÓ¢°¢&öÆS¢7W'&VçE¶ÖVÖ&W"æÖVÖ&W%ö–EÓòç&öÆRóòÖVÖ&W"ç&öÆRÀ¢7FGW3¢WfVçBçF&vWBçfÇVR2v÷&·76TÖVÖ&W%7FGW0¢Ð¢Ò’¢Ð¢F—6&ÆVC×²6äFÖ–çÐ¢à¢´ÔTÔ$U%õ5DEU5ôõD”ôå2æÖ‚‡7FGW2’Óâ€¢Æ÷F–öâ¶W“×·7FGW7ÒfÇVS×·7FGW7Óà¢·7FGW7Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢Â÷FCà¢ÇFCç¶æWrFFR†ÖVÖ&W"çWFFVEöB’çFôÆö6ÆU7G&–ær‚—ÓÂ÷FCà¢ÇFCà¢ÆF—b6Æ74æÖSÒ&–GB×v÷&·76RÖ7F–öç2#à¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢öä6Æ–6³×²‚’Óâ°¢fö–B†æFÆU6fTÖVÖ&W"†ÖVÖ&W"“°¢×Ð¢F—6&ÆVC×²6äFÖ–âÇÂF—'G’ÇÂ6f–ætÖVÖ&W$”BÓÓÒÖVÖ&W"æÖVÖ&W%ö–GÐ¢à¢·6f–ætÖVÖ&W$”BÓÓÒÖVÖ&W"æÖVÖ&W%ö–Bòu6f–ærâââr¢u6fRwÐ¢Âö'WGFöãà¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖF&² ¢öä6Æ–6³×²‚’Óâ°¢fö–B†æFÆU&VÖ÷fTÖVÖ&W"†ÖVÖ&W"“°¢×Ð¢F—6&ÆVC×²6äFÖ–âÇÂ&VÖ÷f–ætÖVÖ&W$”BÓÓÒÖVÖ&W"æÖVÖ&W%ö–GÐ¢à¢·&VÖ÷f–ætÖVÖ&W$”BÓÓÒÖVÖ&W"æÖVÖ&W%ö–Bòu&VÖ÷f–ærâââr¢u&VÖ÷fRwÐ¢Âö'WGFöãà¢ÂöF—cà¢Â÷FCà¢Â÷G#à¢“°¢Ò—Ð¢Â÷F&öG“à¢Â÷F&ÆSà¢ÂöF—cà ¢¶f–ÇFW&VDÖVÖ&W'2æÆVæwF‚ÓÓÒò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æòÖVÖ&W'2ÖF6‚F†—2f–ÇFW" ¢&öG“Ò%G'’F§W7F–ær&öÆR÷7FGW2f–ÇFW'2÷"–çf—FRæWrv÷&·76RÖVÖ&W"â ¢óà¢’¢çVÆÇÐ¢Â÷6V7F–öãà¢“°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7E&ö¦V7G5vR‚’°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7Bæf–vFRÒW6Tæf–vFR‚“°¢6öç7BÆö6F–öâÒW6TÆö6F–öâ‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“°¢6öç7B&WVW7FVE6÷W&6RÒW6TÖVÖò€¢‚’Óâæ÷&ÖÆ—¦U6÷W&6U&÷f–FW"†æWrU$Å6V&6…&×2†Æö6F–öâç6V&6‚’ævWB‚w6÷W&6Rr’’À¢¶Æö6F–öâç6V&6…Ð¢“° ¢6öç7B·&ö¦V7G2Â6WE&ö¦V7G5ÒÒW6U7FFSÅ&ö¦V7E&V6÷&EµÓâ…µÒ“°¢6öç7B¶ÆöF–ærÂ6WDÆöF–æuÒÒW6U7FFR‡G'VR“°¢6öç7B·6f–ærÂ6WE6f–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶W'&÷"Â6WDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B¶G&gDæÖRÂ6WDG&gDæÖUÒÒW6U7FFR‚rr“°¢6öç7B¶G&gDFW67&—F–öâÂ6WDG&gDFW67&—F–öåÒÒW6U7FFR‚rr“°¢6öç7B¶FVÆWFUF&vWBÂ6WDFVÆWFUF&vWEÒÒW6U7FFSÅ&ö¦V7E&V6÷&BÂçVÆÃâ†çVÆÂ“°¢6öç7B¶FVÆWFUVæF–ærÂ6WDFVÆWFUVæF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶FVÆWFTW'&÷"Â6WDFVÆWFTW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B66÷T¶W’Ò66÷RòG·66÷RçFVæçD”GÓ¢G·66÷Rçv÷&·76T”GÖ¢rs°¢6öç7BFVÆWFU66÷T¶W•&VbÒW6U&Vb‡66÷T¶W’“°¢6öç7BFVÆWFU&WVW7EfW'6–öå&VbÒW6U&Vbƒ“° ¢W6TVffV7B‚‚’Óâ°¢FVÆWFU66÷T¶W•&Vbæ7W'&VçBÒ66÷T¶W“°¢FVÆWFU&WVW7EfW'6–öå&Vbæ7W'&VçB³Ò°¢6WDFVÆWFUF&vWB†çVÆÂ“°¢6WDFVÆWFTW'&÷"‚rr“°¢6WDFVÆWFUVæF–ær†fÇ6R“°¢ÒÂ·66÷T¶W•Ò“° ¢W6TVffV7B‚‚’Óâ°¢–b‚66÷R’°¢6WE&ö¦V7G2…µÒ“°¢6WDÆöF–ær†fÇ6R“°¢&WGW&ã°¢Ð ¢ÆWB7F—fRÒG'VS° ¢6öç7BÆöE&ö¦V7G2Ò7–æ2‚’Óâ°¢6WDÆöF–ær‡G'VR“°¢6WDW'&÷"‚rr“°¢6WE&ö¦V7G2…µÒ“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢6öç7B&W7öç6RÒv—B”6Æ–VçBæÆ—7E&ö¦V7G2€¢66÷Rçv÷&·76T”BÀ¢°¢Æ–Ö—C¢SÀ¢6÷'Eö'“¢wWFFVEöBrÀ¢6÷'Eö÷&FW#¢vFW62rÀ¢–æ6ÇVFUö&6†—fVC¢G'VP¢ÒÀ¢WF€¢“°¢–b‚7F—fR’°¢&WGW&ã°¢Ð¢6WE&ö¦V7G2‡&W7öç6Ræ—FV×2“°¢Ò6F6‚†ÆöDW'&÷"’°¢–b‚7F—fR’°¢&WGW&ã°¢Ð¢6WDW'&÷"†ÆöDW'&÷"–ç7Fæ6VöbW'&÷"òÆöDW'&÷"æÖW76vR¢uVæ&ÆRFòÆöBv÷&·76RVçf—&öæÖVçG2âr“°¢Òf–æÆÇ’°¢–b†7F—fR’°¢6WDÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢fö–BÆöE&ö¦V7G2‚“° ¢&WGW&â‚’Óâ°¢7F—fRÒfÇ6S°¢Ó°¢ÒÂ·66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”EÒ“° ¢6öç7B7F—fU&ö¦V7D6÷VçBÒW6TÖVÖò€¢‚’Óâ&ö¦V7G2æf–ÇFW"‚‡&ö¦V7B’Óâæ÷&ÖÆ—¦UfÇVR‡&ö¦V7Bæ&6†—fVEöBóòrr’’æÆVæwF‚À¢·&ö¦V7G5Ð¢“°¢6öç7B&6†—fVE&ö¦V7D6÷VçBÒ&ö¦V7G2æÆVæwF‚Ò7F—fU&ö¦V7D6÷VçC°¢6öç7BÆFW7E&ö¦V7BÒ&ö¦V7G5³Ó°¢–b‚66÷R’°¢&WGW&âÄ6†VÆÄÆöF–ærÖW76vSÒ%&W6öÇf–ærv÷&·76R66÷R"óã°¢Ð ¢–b†ÆöF–ær’°¢&WGW&â€¢Ä&÷WFTÆöF–æu7FFP¢F—FÆSÒ%&W&–ærVçf—&öæÖVçG2 ¢&öG“Ò$¶VW–ærv÷&·76R66÷R&VG’v†–ÆRVçf—&öæÖVçB&÷VæF&–W2&Vg&W6‚â ¢óà¢“°¢Ð ¢6öç7B†æFÆT7&VFU&ö¦V7BÒ7–æ2†WfVçC¢f÷&ÔWfVçCÄ…DÔÄf÷&ÔVÆVÖVçCâ’Óâ°¢WfVçBç&WfVçDFVfVÇB‚“° ¢6öç7BæÖRÒæ÷&ÖÆ—¦UfÇVR†G&gDæÖR“°¢6öç7BFW67&—F–öâÒæ÷&ÖÆ—¦UfÇVR†G&gDFW67&—F–öâ“° ¢–b‚æÖR’°¢6WDW'&÷"‚tVçf—&öæÖVçBæÖR—2&WV—&VBâr“°¢&WGW&ã°¢Ð ¢6WE6f–ær‡G'VR“°¢6WDW'&÷"‚rr“° ¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢6öç7B¶æ÷vå&ö¦V7G2Òv—BÆ—7D÷fW'f–Wu&ö¦V7G2‡66÷Rçv÷&·76T”BÂ²–æ6ÇVFUö&6†—fVC¢G'VRÒÂWF‚“°¢6öç7B&ö¦V7D”BÒVæ—VTVçf—&öæÖVçEFö¶Vâ†æÖRÂ¶æ÷vå&ö¦V7G2“°¢6öç7B6ÇVrÒ&ö¦V7D”C°¢–b‚&ö¦V7D”B’°¢6WDW'&÷"‚tVçFW"&VF&ÆRVçf—&öæÖVçBæÖRâr“°¢&WGW&ã°¢Ð¢6öç7B&W7öç6RÒv—B”6Æ–VçBçW6W'E&ö¦V7B€¢66÷Rçv÷&·76T”BÀ¢°¢&ö¦V7Eö–C¢&ö¦V7D”BÀ¢æÖRÀ¢6ÇVrÀ¢FW67&—F–öã¢FW67&—F–öâÇÂVæFVf–æV@¢ÒÀ¢WF€¢“°¢6WE&ö¦V7G2‚†7W'&VçB’Óâ°¢6öç7B&VÖ–æ–ærÒ7W'&VçBæf–ÇFW"‚‡&ö¦V7B’Óâ&ö¦V7Bç&ö¦V7Eö–BÓÒ&W7öç6Rç&ö¦V7Bç&ö¦V7Eö–B“°¢&WGW&â·&W7öç6Rç&ö¦V7BÂââç&VÖ–æ–æuÓ°¢Ò“°¢6WDG&gDæÖR‚rr“°¢6WDG&gDFW67&—F–öâ‚rr“°¢æf–vFR†VæE6÷W&6UVW'’†'V–ÆE&ö¦V7EF‚‡66÷RÂ&W7öç6Rç&ö¦V7Bç&ö¦V7Eö–B’Â&WVW7FVE6÷W&6R’“°¢Ò6F6‚‡6fTW'&÷"’°¢6WDW'&÷"‡6fTW'&÷"–ç7Fæ6VöbW'&÷"ò6fTW'&÷"æÖW76vR¢uVæ&ÆRFò6fRVçf—&öæÖVçBâr“°¢Òf–æÆÇ’°¢6WE6f–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆT÷VäFVÆWFU&ö¦V7BÒ‡&ö¦V7C¢&ö¦V7E&V6÷&B’Óâ°¢6WDFVÆWFTW'&÷"‚rr“°¢6WDFVÆWFUF&vWB‡&ö¦V7B“°¢Ó° ¢6öç7B†æFÆT6æ6VÄFVÆWFU&ö¦V7BÒ‚’Óâ°¢–b†FVÆWFUVæF–ær’°¢&WGW&ã°¢Ð¢6WDFVÆWFUF&vWB†çVÆÂ“°¢6WDFVÆWFTW'&÷"‚rr“°¢Ó° ¢6öç7B†æFÆTFVÆWFU&ö¦V7BÒ7–æ2‚’Óâ°¢–b‚66÷RÇÂFVÆWFUF&vWBÇÂFVÆWFUVæF–ær’°¢&WGW&ã°¢Ð¢–b†FVÆWFUF&vWBçFVæçEö–BÓÒ66÷RçFVæçD”BÇÂFVÆWFUF&vWBçv÷&·76Uö–BÓÒ66÷Rçv÷&·76T”B’°¢6WDFVÆWFUF&vWB†çVÆÂ“°¢6WDFVÆWFTW'&÷"‚rr“°¢&WGW&ã°¢Ð¢6öç7BF&vWBÒFVÆWFUF&vWC°¢6öç7B–æ—F–F–æu66÷T¶W’Ò66÷T¶W“°¢6öç7B&WVW7EfW'6–öâÒFVÆWFU&WVW7EfW'6–öå&Vbæ7W'&VçB²°¢FVÆWFU&WVW7EfW'6–öå&Vbæ7W'&VçBÒ&WVW7EfW'6–öã°¢6WDFVÆWFUVæF–ær‡G'VR“°¢6WDFVÆWFTW'&÷"‚rr“°¢G'’°¢v—B”6Æ–VçBæFVÆWFU&ö¦V7B€¢66÷Rçv÷&·76T”BÀ¢F&vWBç&ö¦V7Eö–BÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢–b†FVÆWFU66÷T¶W•&Vbæ7W'&VçBÓÒ–æ—F–F–æu66÷T¶W’ÇÂFVÆWFU&WVW7EfW'6–öå&Vbæ7W'&VçBÓÒ&WVW7EfW'6–öâ’°¢&WGW&ã°¢Ð¢6WE&ö¦V7G2‚†7W'&VçB’Óâ7W'&VçBæf–ÇFW"‚‡&ö¦V7B’Óâ&ö¦V7Bç&ö¦V7Eö–BÓÒF&vWBç&ö¦V7Eö–B’“°¢6WDFVÆWFUF&vWB†çVÆÂ“°¢Ò6F6‚†FVÆWFU&ö¦V7DW'&÷"’°¢–b†FVÆWFU66÷T¶W•&Vbæ7W'&VçBÓÒ–æ—F–F–æu66÷T¶W’ÇÂFVÆWFU&WVW7EfW'6–öå&Vbæ7W'&VçBÓÒ&WVW7EfW'6–öâ’°¢&WGW&ã°¢Ð¢6WDFVÆWFTW'&÷"€¢FVÆWFU&ö¦V7DW'&÷"–ç7Fæ6VöbW'&÷"òFVÆWFU&ö¦V7DW'&÷"æÖW76vR¢uVæ&ÆRFòFVÆWFRF†—2Vçf—&öæÖVçBâÆV6R&WG'’âp¢“°¢Òf–æÆÇ’°¢–b†FVÆWFU66÷T¶W•&Vbæ7W'&VçBÓÓÒ–æ—F–F–æu66÷T¶W’bbFVÆWFU&WVW7EfW'6–öå&Vbæ7W'&VçBÓÓÒ&WVW7EfW'6–öâ’°¢6WDFVÆWFUVæF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GB×&ö¦V7G2×vR#à¢ÆF—b6Æ74æÖSÒ&–GB×&ö¦V7G2Ö†VFW"#à¢ÆF—cà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#åv÷&·76R66÷SÂ÷à¢Æƒ#äVçf—&öæÖVçG3Âöƒ#à¢Çä6†ö÷6RF†R÷W&F–ær&÷VæF'’f÷"&W÷6—F÷'’Âv÷&¶fÆ÷rÂ6Æ÷VBÂæB6ÇW7FW"–FVçF—G’6–væÇ2ãÂ÷à¢Ç6Æ74æÖSÒ&–GB×&ö¦V7G2Ö†VFW"Öæ÷FR#à¢FVÆWFRâVçf—&öæÖVçBFò&VÖ÷fR—G26öææV7F÷'2Â66ç2Âf–æF–æw2ÂæB6WGW7FFRv†–ÆR¶VW–ærF†—2v÷&·76R–çF7Bà¢Â÷à¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖ–æÆ–æRÖ7F–öç2#à¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B"Fó×¶'V–ÆE66÷VEF‚‡66÷R—Óà¢&6²Fò÷fW'f–Wp¢ÂôÆ–æ³à¢ÂöF—cà¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GB×&ö¦V7G2×7VÖÖ'’#à¢Æ'F–6ÆR6Æ74æÖSÒ&—2ÖÆ–v‡B×7W&f6R#à¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2×F÷#à¢Ç7ãç·&ö¦V7G2æÆVæwF‡ÓÂ÷7ãà¢ÂöF—cà¢ÇåF÷FÂVçf—&öæÖVçG3Â÷à¢Âö'F–6ÆSà¢Æ'F–6ÆSà¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2×F÷#à¢Ç7ãç¶7F—fU&ö¦V7D6÷VçGÓÂ÷7ãà¢ÂöF—cà¢Çä7F—fRVçf—&öæÖVçG3Â÷à¢Âö'F–6ÆSà¢Æ'F–6ÆSà¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–WrÖÖWG&–2×F÷#à¢Ç7ãç¶ÆFW7E&ö¦V7Bòf÷&ÖD6öææV7F–öåF–ÖR†ÆFW7E&ö¦V7BçWFFVEöB’¢tæò7F—f—G’–WBwÓÂ÷7ãà¢ÂöF—cà¢ÇäÆ7BWFFVCÂ÷à¢Âö'F–6ÆSà¢ÂöF—cà ¢¶W'&÷"òÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç¶W'&÷'ÓÂöF—câ¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GB×&ö¦V7G2Öw&–B#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&ö¦V7G2ÖÆ—7B#à¢ÆF—b6Æ74æÖSÒ&–GB×&ö¦V7G2×6V7F–öâÖ†VFW"#à¢ÆF—cà¢Æƒ3äVçf—&öæÖVçBÆ—7CÂöƒ3à¢Çà¢¶&6†—fVE&ö¦V7D6÷VçBâ ¢òG¶7F—fU&ö¦V7D6÷VçGÒ7F—fRÂG¶&6†—fVE&ö¦V7D6÷VçGÒ&6†—fVBæ ¢¢t÷VââVçf—&öæÖVçBFòÖævR6÷W&6R6öææV7F–öç2æB66ç2âwÐ¢Â÷à¢ÂöF—cà¢ÂöF—cà ¢·&ö¦V7G2æÆVæwF‚ÓÓÒò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æòVçf—&öæÖVçG2–WB ¢&öG“Ò$7&VFRF†Rf—'7Bv÷&·76R&÷VæF'’f÷"F†—26÷W&6Râ ¢óà¢’¢€¢ÆF—b6Æ74æÖSÒ&–GB×&ö¦V7BÖ6&BÖÆ—7B#à¢·&ö¦V7G2æÖ‚‡&ö¦V7B’Óâ°¢6öç7B&6†—fVBÒ&ööÆVâ†æ÷&ÖÆ—¦UfÇVR‡&ö¦V7Bæ&6†—fVEöBóòrr’“°¢&WGW&â€¢Æ'F–6ÆR¶W“×·&ö¦V7Bç&ö¦V7Eö–GÒ6Æ74æÖSÒ&–GB×&ö¦V7BÖ6&B#à¢ÆF—b6Æ74æÖSÒ&–GB×&ö¦V7BÖ6&BÖ†VFW"#à¢ÆF—cà¢ÆF—b6Æ74æÖSÒ&–GB×&ö¦V7BÖ6&B×F—FÆR#à¢ÆƒCç·&ö¦V7BææÖWÓÂöƒCà¢ÂöF—cà¢Çç·&ö¦V7BæFW67&—F–öâÇÂu66÷R6÷W&6R6öææV7F–öç2Â66ç2ÂæBf–æF–æw2f÷"F†—2Vçf—&öæÖVçBâwÓÂ÷à¢ÂöF—cà¢Ç7à¢6Æ74æÖS×¶–GB×6÷W&6R×7FGW2×–ÆÂG¶&6†—fVBòv—2×v&æ–ærr¢v—2×7V66W72wÖÐ¢à¢¶&6†—fVBòt&6†—fVBr¢t7F—fRwÐ¢Â÷7ãà¢ÂöF—cà ¢ÆFWF–Ç26Æ74æÖSÒ&–GB×&ö¦V7BÖ6&BÖFWF–Ç2#à¢Ç7VÖÖ'“äVçf—&öæÖVçBFWF–Ç3Â÷7VÖÖ'“à¢ÆFÂ6Æ74æÖSÒ&–GB×&ö¦V7BÖ6&BÖÖWF#à¢ÆF—cà¢ÆGCä–çFW&æÂ¶W“ÂöGCà¢ÆFCç·&ö¦V7Bç&ö¦V7Eö–GÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå6ÇVsÂöGCà¢ÆFCç·&ö¦V7Bç6ÇVwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCåWFFVCÂöGCà¢ÆFCç¶f÷&ÖD6öææV7F–öåF–ÖR‡&ö¦V7BçWFFVEöB—ÓÂöFCà¢ÂöF—cà¢ÂöFÃà¢ÂöFWF–Ç3à ¢ÆF—b6Æ74æÖSÒ&–GBÖ–æÆ–æRÖ7F–öç2#à¢ÄÆ–æ°¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’ ¢Fó×¶VæE6÷W&6UVW'’†'V–ÆE&ö¦V7EF‚‡66÷RÂ&ö¦V7Bç&ö¦V7Eö–B’Â&WVW7FVE6÷W&6R—Ð¢à¢÷VâVçf—&öæÖVç@¢ÂôÆ–æ³à¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖFævW" ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâ†æFÆT÷VäFVÆWFU&ö¦V7B‡&ö¦V7B—Ð¢F—6&ÆVC×¶FVÆWFUVæF–æwÐ¢à¢FVÆWFRVçf—&öæÖVç@¢Âö'WGFöãà¢ÂöF—cà¢Âö'F–6ÆSà¢“°¢Ò—Ð¢ÂöF—cà¢—Ð¢Âö'F–6ÆSà ¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&ö¦V7BÖ6ö×÷6W"#à¢ÆF—b6Æ74æÖSÒ&–GB×&ö¦V7G2×6V7F–öâÖ†VFW"#à¢ÆF—cà¢Æƒ3äæWrVçf—&öæÖVçCÂöƒ3à¢ÇäæÖRF†R&÷VæF'’öæ6Râ–FVçG&–Â¶VW2F†R–çFW&æÂ¶W’&V†–æBF†R66VæW2ãÂ÷à¢ÂöF—cà¢ÂöF—cà ¢Æf÷&Ò6Æ74æÖSÒ&–GBÖÖf÷&Ò"öå7V&Ö—C×¶†æFÆT7&VFU&ö¦V7GÓà¢ÆÆ&VÃà¢Vçf—&öæÖVçBæÖP¢Æ–çW@¢fÇVS×¶G&gDæÖWÐ¢öä6†ævS×²†WfVçB’Óâ6WDG&gDæÖR†WfVçBçF&vWBçfÇVR—Ð¢Æ6V†öÆFW#Ò%&öGV7F–öâÆFf÷&Ò ¢&WV—&V@¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢FW67&—F–öà¢ÇFW‡F&V¢fÇVS×¶G&gDFW67&—F–öçÐ¢öä6†ævS×²†WfVçB’Óâ6WDG&gDFW67&—F–öâ†WfVçBçF&vWBçfÇVR—Ð¢Æ6V†öÆFW#Ò$–FVçF—G’&÷VæF'’f÷"F†R&öGV7F–öâ6öçG&öÂÆæRæB—G2FVÆ—fW'’&W÷6—F÷&–W2â ¢óà¢ÂöÆ&VÃà¢Æ'WGFöâ6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’"G—SÒ'7V&Ö—B"F—6&ÆVC×·6f–æwÓà¢·6f–æròt7&VF–ærVçf—&öæÖVçBâââr¢t7&VFRVçf—&öæÖVçBwÐ¢Âö'WGFöãà¢Âöf÷&Óà¢Âö'F–6ÆSà¢ÂöF—cà ¢Ä6öæf—&ÔFW7G'V7F—fTÖöFÀ¢&öG“×°¢Ãà¢Çà¢F†—2W&ÖæVçFÇ’&VÖ÷fW2F†RVçf—&öæÖVçBÂ—G26öææV7F÷'2Â66ç2Âf–æF–æw2Â&6VÆ–æW2ÂæB6WGW7FFRà¢Â÷à¢Çà¢—BFöW2æ÷B&VÖ÷fR”Ò&öÆW2Â6Æ÷VDf÷&ÖF–öâ7F6·2Â÷"÷F†W"&W6÷W&6W2–â–÷W"u266÷VçBâ&VÖ÷fRF†÷6R6W&FVÇ’–âu2–b–÷R&R7F'F–ær÷fW"F†W&RFöòà¢Â÷à¢Âóà¢Ð¢6öæf—&ÖF–öã×·°¢¶–æC¢wG—R×FòÖ6öæf—&ÒrÀ¢W‡V7FVEfÇVS¢FVÆWFUF&vWCòç&ö¦V7Eö–BóòrrÀ¢–çWDÆ&VÃ¢t6öæf—&ÒVçf—&öæÖVçB¶W’rÀ¢†VÇFW‡C¢FVÆWFUF&vWBò€¢Ãà¢VçFW"ÆVÒ6Æ74æÖSÒ&–GBÖFævW"Ö6öæf—&Ò×fÇVR#ç¶FVÆWFUF&vWBç&ö¦V7Eö–GÓÂöVÓâW†7FÇ’à¢Âóà¢’¢VæFVf–æV@¢×Ð¢6öçF–çVTÆ&VÃÒ$FVÆWFRVçf—&öæÖVçB ¢W'&÷$ÖW76vS×¶FVÆWFTW'&÷"ÇÂVæFVf–æVGÐ¢öä6æ6VÃ×¶†æFÆT6æ6VÄFVÆWFU&ö¦V7GÐ¢öä6öæf—&Ó×¶†æFÆTFVÆWFU&ö¦V7GÐ¢÷Vã×¶FVÆWFUF&vWBÓÒçVÆÇÐ¢VæF–æs×¶FVÆWFUVæF–æwÐ¢F—FÆS×¶FVÆWFUF&vWBòFVÆWFRG¶FVÆWFUF&vWBææÖWÖ¢tFVÆWFRVçf—&öæÖVçBwÐ¢óà¢Â÷6V7F–öãà¢“°§Ð  §G—Rv—D‡V$–çFVÆÆ–vVæ6T6FVv÷'’Ò°¢–C¢7G&–æs°¢Æ&VÃ¢7G&–æs°¢7VÖÖ'“¢7G&–æs°¢V×G“¢7G&–æs°¢ÖF6ƒ¢†f–æF–æs¢”f–æF–ær’Óâ&ööÆVã°§Ó° ¦gVæ7F–öâ&Wôf–æF–æu6V&6…FW‡B†f–æF–æs¢”f–æF–ær“¢7G&–ær°¢6öç7BWf–FVæ6RÒ‚‚’Óâ°¢G'’°¢&WGW&âf–æF–æræWf–FVæ6Rò¥4ôâç7G&–æv–g’†f–æF–æræWf–FVæ6R’¢rs°¢Ò6F6‚°¢&WGW&ârs°¢Ð¢Ò’‚“°¢&WGW&â°¢f–æF–ærçG—RÀ¢f–æF–æræFWFV7F÷"À¢f–æF–æræFFW%÷6÷W&6RÀ¢f–æF–ærçF—FÆRÀ¢f–æF–æræ‡VÖå÷7VÖÖ'’À¢f–æF–æræf–ÆU÷F‚À¢f–æF–æræÆ–æU÷6æ—WBÀ¢f–æF–ærç&VÖVF–F–öâÀ¢Wf–FVæ6P¢Ð¢æÖ‚‡fÇVR’Óâæ÷&ÖÆ—¦UfÇVR‡fÇVR’çFôÆ÷vW$66R‚’¢æf–ÇFW"„&ööÆVâ¢æ¦ö–â‚rr“°§Ð ¦gVæ7F–öâ&Wôf–æF–æu6æ—WDÆöö·4Æ–¶TF–fb†Æ–æW3¢7G&–æuµÒ“¢&ööÆVâ°¢6öç7BÖVæ–ævgVÄÆ–æW2ÒÆ–æW2æf–ÇFW"‚†Æ–æR’ÓâÆ–æRçG&–Ò‚’æÆVæwF‚â“°¢6öç7B—4F–fdÖWFFFÆ–æRÒ†Æ–æS¢7G&–ær’Óà¢Æ–æRç7F'G5v—F‚‚tr’ÇÀ¢Æ–æRç7F'G5v—F‚‚vF–fbÒÖv—Br’ÇÀ¢Æ–æRç7F'G5v—F‚‚v–æFW‚r’ÇÀ¢Æ–æRç7F'G5v—F‚‚vöÆBÖöFRr’ÇÀ¢Æ–æRç7F'G5v—F‚‚væWrÖöFRr’ÇÀ¢Æ–æRç7F'G5v—F‚‚vFVÆWFVBf–ÆRÖöFRr’ÇÀ¢Æ–æRç7F'G5v—F‚‚væWrf–ÆRÖöFRr’ÇÀ¢Æ–æRç7F'G5v—F‚‚w6–Ö–Æ&—G’–æFW‚r’ÇÀ¢Æ–æRç7F'G5v—F‚‚vF—76–Ö–Æ&—G’–æFW‚r’ÇÀ¢Æ–æRç7F'G5v—F‚‚w&VæÖRg&öÒr’ÇÀ¢Æ–æRç7F'G5v—F‚‚w&VæÖRFòr’ÇÀ¢Æ–æRç7F'G5v—F‚‚v6÷’g&öÒr’ÇÀ¢Æ–æRç7F'G5v—F‚‚v6÷’Fòr’ÇÀ¢Æ–æRç7F'G5v—F‚‚rÒÒÒr’ÇÀ¢Æ–æRç7F'G5v—F‚‚r²²²r’ÇÀ¢Æ–æRç7F'G5v—F‚‚uÅÂr“°¢6öç7B†4F–fd†VFW"ÒÖVæ–ævgVÄÆ–æW2ç6öÖR€¢†Æ–æR’ÓâÆ–æRç7F'G5v—F‚‚tr’ÇÂÆ–æRç7F'G5v—F‚‚vF–fbÒÖv—Br’ÇÂÆ–æRç7F'G5v—F‚‚rÒÒÒr’ÇÂÆ–æRç7F'G5v—F‚‚r²²²r¢“°¢6öç7BF–fd&öG”Æ–æW2ÒÖVæ–ævgVÄÆ–æW2æf–ÇFW"€¢†Æ–æR’Óâ—4F–fdÖWFFFÆ–æR†Æ–æR¢“°¢&WGW&â€¢†4F–fd†VFW"b`¢F–fd&öG”Æ–æW2ç6öÖR‚†Æ–æR’ÓâÆ–æRç7F'G5v—F‚‚r²r’ÇÂÆ–æRç7F'G5v—F‚‚rÒr’’b`¢ÖVæ–ævgVÄÆ–æW2æWfW'’€¢†Æ–æR’Óà¢Æ–æRç7F'G5v—F‚‚r²r’ÇÀ¢Æ–æRç7F'G5v—F‚‚rÒr’ÇÀ¢Æ–æRç7F'G5v—F‚‚rr’ÇÀ¢—4F–fdÖWFFFÆ–æR†Æ–æR¢¢“°§Ð ¦gVæ7F–öâ&Wôf–æF–æu6æ—WDF–fdÖ&¶W"†Æ–æS¢7G&–ærÂ—4F–fe6æ—WC¢&ööÆVâ“¢r²rÂrÒrÂçVÆÂ°¢–b‚—4F–fe6æ—WBÇÂÆ–æRç7F'G5v—F‚‚r²²²r’ÇÂÆ–æRç7F'G5v—F‚‚rÒÒÒr’’°¢&WGW&âçVÆÃ°¢Ð¢–b†Æ–æRç7F'G5v—F‚‚r²r’’°¢&WGW&âr²s°¢Ð¢–b†Æ–æRç7F'G5v—F‚‚rÒr’’°¢&WGW&ârÒs°¢Ð¢&WGW&âçVÆÃ°§Ð ¦gVæ7F–öâ&Wôf–æF–æu6æ—WDÆ–æT6Æ72†F–fdÖ&¶W#¢r²rÂrÒrÂçVÆÂ“¢7G&–ær°¢–b†F–fdÖ&¶W"ÓÓÒr²r’°¢&WGW&âv–GB×&WòÖf–æF–ærÖ6öFRÖÆ–æR—2ÖFBs°¢Ð¢–b†F–fdÖ&¶W"ÓÓÒrÒr’°¢&WGW&âv–GB×&WòÖf–æF–ærÖ6öFRÖÆ–æR—2×&VÖ÷fRs°¢Ð¢&WGW&âv–GB×&WòÖf–æF–ærÖ6öFRÖÆ–æRs°§Ð ¦gVæ7F–öâ&VæFW%&Wôf–æF–ætÆ–æU6æ—WB‡6æ—WC¢7G&–ær’°¢6öç7BÆ–æW2Ò6æ—WBç7Æ—B‚uÆâr“°¢6öç7B—4F–fe6æ—WBÒ&Wôf–æF–æu6æ—WDÆöö·4Æ–¶TF–fb†Æ–æW2“°¢&WGW&âÆ–æW2æÖ‚†Æ–æRÂ–æFW‚’Óâ°¢6öç7BF–fdÖ&¶W"Ò&Wôf–æF–æu6æ—WDF–fdÖ&¶W"†Æ–æRÂ—4F–fe6æ—WB“°¢&WGW&â€¢Ç7â6Æ74æÖS×·&Wôf–æF–æu6æ—WDÆ–æT6Æ72†F–fdÖ&¶W"—Ò¶W“×¶G¶–æFW‡ÒÒG¶Æ–æWÖÓà¢¶F–fdÖ&¶W"òÇ7â6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ6öFRÖÖ&¶W"#ç¶F–fdÖ&¶W'ÓÂ÷7ãâ¢çVÆÇÐ¢¶F–fdÖ&¶W"òÆ–æRç6Æ–6Rƒ’ÇÂrr¢Æ–æRÇÂrwÐ¢Â÷7ãà¢“°¢Ò“°§Ð ¦gVæ7F–öâ&Wôf–æF–ætÖF6†W4ç’†f–æF–æs¢”f–æF–ærÂFö¶Vç3¢7G&–æuµÒ“¢&ööÆVâ°¢6öç7B†—7F6²Ò&Wôf–æF–æu6V&6…FW‡B†f–æF–ær“°¢&WGW&âFö¶Vç2ç6öÖR‚‡Fö¶Vâ’Óâ†—7F6²æ–æ6ÇVFW2‡Fö¶Vâ’“°§Ð ¦6öç7BtTåD”5õ$•4µõ44õUõDô´Tå3¢7G&–æuµÒÒ°¢v•övVçE÷7W&f6RrÀ¢v•övVçEö6öæf–rrÀ¢v’vVçB6öæf–rrÀ¢v76—7FçB6öæf–wW&F–öârÀ¢ræÖ7æ§6öârÀ¢ræ7W'6÷"rÀ¢ræ6öçF–çVRrÀ¢ræ6öFW‚rÀ¢ræ6ÆVFRrÀ¢v6÷–Æ÷BÖ–ç7G'V7F–öç2rÀ¢vvVçB6öæf–rrÀ¢vvVçB–ç7G'V7F–öârÀ¢vÖ7rÀ¢vÖöFVÂ6öçFW‡B&÷Fö6öÂrÀ¢wFööÂ6&–Æ—G’rÀ¢vFævW&÷W2FööÂrÀ¢vW‡FW&æÂ6&–Æ—G’rÀ¢v6öÖÖæB7W&f6RrÀ¢w7FF–òrÀ¢w6†VÆÂFööÂrÀ¢w6W'fW"–çfVçF÷'’rÀ¢w&ö×BrÀ¢v–ç7G'V7F–öârÀ¢w&ö×B–æ¦V7F–öârÀ¢wv÷&¶fÆ÷r&ö×BrÀ¢wVçG'W7FVB–çWBrÀ¢wVÆÂ&WVW7BFW‡BrÀ¢v—77VR&öG’rÀ¢v’7FWrÀ¢w6V7&WBrÀ¢wFö¶VârÀ¢v7&VFVçF–ÂrÀ¢v’¶W’rÀ¢vVçbf"rÀ¢vVçf—&öæÖVçBf&–&ÆRrÀ¢vv—F‡V%÷6V7&WE÷66ææ–ærrÀ¢w6V7&WB66ææ–ærrÀ¢vvVçF–26V7&WBrÀ¢vv—F‡V"7F–öç2rÀ¢wv÷&¶fÆ÷uö•övVçE÷&ö×Eö–æ¦V7F–öârÀ¢wVÆÅ÷&WVW7E÷F&vWBrÀ¢vö–F2rÀ¢v–B×Fö¶VârÀ¢wW&Ö—76–öç2rÀ¢w'VææW"rÀ¢w6VÆbÖ†÷7FVBrÀ¢v&÷BrÀ¢wG'W7BF‚p¥Ó° ¦gVæ7F–öâ—4vVçF–5&—6´f–æF–ær†f–æF–æs¢”f–æF–ær“¢&ööÆVâ°¢&WGW&â&Wôf–æF–ætÖF6†W4ç’†f–æF–ærÂtTåD”5õ$•4µõ44õUõDô´Tå2“°§Ð ¦6öç7Bt•D…T%ô”åDTÄÄ”tTä4Uô4DTtõ$”U3¢v—D‡V$–çFVÆÆ–vVæ6T6FVv÷'•µÒÒ°¢°¢–C¢v’ÖvVçBÖÖ7rÀ¢Æ&VÃ¢t’ôÔ5W‡÷7W&RrÀ¢7VÖÖ'“¢tvVçB6öæf–w2ÂÔ56W'fW'2ÂæB&—6·’FööÂ66W72ârÀ¢V×G“¢tæò’ôÔ5W‡÷7W&RârÀ¢ÖF6ƒ¢†f–æF–ær’Óà¢&Wôf–æF–ætÖF6†W4ç’†f–æF–ærÂ°¢v•övVçE÷7W&f6RrÀ¢v•övVçEö6öæf–rrÀ¢v’vVçB6öæf–rrÀ¢vÖ7rÀ¢ræÖ7æ§6öârÀ¢ræ7W'6÷"rÀ¢ræ6öçF–çVRrÀ¢ræ6öFW‚rÀ¢ræ6ÆVFRrÀ¢v6÷–Æ÷BÖ–ç7G'V7F–öç2rÀ¢vvVçB6öæf–rrÀ¢vFævW&÷W2FööÂp¢Ò¢ÒÀ¢°¢–C¢v’×v÷&¶fÆ÷rrÀ¢Æ&VÃ¢t’v÷&¶fÆ÷r&—6²rÀ¢7VÖÖ'“¢uVçG'W7FVB"÷"—77VRFW‡B&V6†–ær’7FW2ârÀ¢V×G“¢tæò’v÷&¶fÆ÷r&—6²ârÀ¢ÖF6ƒ¢†f–æF–ær’Óà¢&Wôf–æF–ætÖF6†W4ç’†f–æF–ærÂ°¢wv÷&¶fÆ÷uö•övVçE÷&ö×Eö–æ¦V7F–öârÀ¢w&ö×B–æ¦V7F–öârÀ¢wv÷&¶fÆ÷r&ö×BrÀ¢wVÆÅ÷&WVW7E÷F&vWBrÀ¢vçF‡&÷–2rÀ¢v6ÆVFRrÀ¢v÷Væ’rÀ¢v6öFW‚rÀ¢vvVÖ–æ’rÀ¢v–FW"rÀ¢v7W'6÷"p¢Ò¢ÒÀ¢°¢–C¢væF—fRÖÆW'G2rÀ¢Æ&VÃ¢tv—D‡V"ÆW'G2rÀ¢7VÖÖ'“¢u6V7&WB66ææ–æræBFWVæF&÷BÆW'G2ârÀ¢V×G“¢tæòv—D‡V"ÆW'G2ârÀ¢ÖF6ƒ¢†f–æF–ær’Óà¢&Wôf–æF–ætÖF6†W4ç’†f–æF–ærÂ°¢vv—F‡V%÷6V7&WE÷66ææ–ærrÀ¢w6V7&WB66ææ–ærÆW'BrÀ¢vv—F‡V%öFWVæF&÷BrÀ¢vFWVæF&÷BrÀ¢wgVÆæW&&–Æ—G’ÆW'Bp¢Ò¢ÒÀ¢°¢–C¢w'VææW"×÷7GW&RrÀ¢Æ&VÃ¢u'VææW"&—6²rÀ¢7VÖÖ'“¢u6VÆbÖ†÷7FVB'VææW"&V6†&–Æ—G’æBÆ&VÇ2ârÀ¢V×G“¢tæò'VææW"&—6²ârÀ¢ÖF6ƒ¢†f–æF–ær’Óà¢&Wôf–æF–ætÖF6†W4ç’†f–æF–ærÂ°¢wv÷&¶fÆ÷u÷6VÆeö†÷7FVE÷'VææW"rÀ¢w6VÆeö†÷7FVE÷'VææW"rÀ¢w6VÆbÖ†÷7FVB'VææW"rÀ¢w'Vç2Ööâ6VÆbÖ†÷7FVBrÀ¢w'VææW"Æ&VÂrÀ¢w'VææW"w&÷Wp¢Ò¢ÒÀ¢°¢–C¢v÷&r×÷7GW&RrÀ¢Æ&VÃ¢t÷&röÆ–7’rÀ¢7VÖÖ'“¢u'VÆW6WG2Â'&æ6‚&÷FV7F–öâÂæB66ææ–æröÆ–7’ârÀ¢V×G“¢tæò÷&röÆ–7’&—6²ârÀ¢ÖF6ƒ¢†f–æF–ær’Óà¢&Wôf–æF–ætÖF6†W4ç’†f–æF–ærÂ°¢v÷&væ—¦F–öâ÷7GW&RrÀ¢v÷&u÷6V7&WE÷66ææ–æu÷öÆ–7’rÀ¢w6V7&WB66ææ–æröÆ–7’rÀ¢vFWVæF&÷BöÆ–7’rÀ¢w'VÆW6WBrÀ¢v'&æ6‚&÷FV7F–öârÀ¢w&W÷6—F÷'’'VÆW2p¢Ò¢ÒÀ¢°¢–C¢w&VÖVF–F–öâ×&VG’rÀ¢Æ&VÃ¢tf—‚&VG’rÀ¢7VÖÖ'“¢t÷Vâf–æF–æw2v—F‚f–ÆR÷"Æ–æR6öçFW‡BârÀ¢V×G“¢tæòf—‚×&VG’&—6·2ârÀ¢ÖF6ƒ¢†f–æF–ær’Óâ°¢6öç7BÆ–fV7–6ÆRÒæ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2“°¢–b†Æ–fV7–6ÆRÓÒv÷VârbbÆ–fV7–6ÆRÓÒw&V÷VæVBr’°¢&WGW&âfÇ6S°¢Ð¢&WGW&â&ööÆVâ†æ÷&ÖÆ—¦UfÇVR†f–æF–ærç6÷W&6U÷W&Âóòrr’ÇÂæ÷&ÖÆ—¦UfÇVR†f–æF–æræf–ÆU÷F‚óòrr’“°¢Ð¢Ð¥Ó° ¦6öç7Bt•D…T%ô”åDTÄÄ”tTä4Uõ44õUô4DTtõ$”U2Òt•D…T%ô”åDTÄÄ”tTä4Uô4DTtõ$”U2æf–ÇFW"€¢†6FVv÷'’’Óâ6FVv÷'’æ–BÓÒw&VÖVF–F–öâ×&VG’p¢“° ¦gVæ7F–öâv—F‡V$–çFVÆÆ–vVæ6T6FVv÷'”f÷$f–æF–ær†f–æF–æs¢”f–æF–ær“¢v—D‡V$–çFVÆÆ–vVæ6T6FVv÷'’°¢&WGW&ât•D…T%ô”åDTÄÄ”tTä4Uô4DTtõ$”U2æf–æB‚†6FVv÷'’’Óâ6FVv÷'’æÖF6‚†f–æF–ær’’óòt•D…T%ô”åDTÄÄ”tTä4Uô4DTtõ$”U5³UÓ°§Ð ¦gVæ7F–öâ—4÷Vå&Wôf–æF–ær†f–æF–æs¢”f–æF–ær“¢&ööÆVâ°¢6öç7BÆ–fV7–6ÆRÒæ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2“°¢6öç7BG&–vRÒæ÷&ÖÆ—¦Tf–æF–æu7FGW2†f–æF–ærçG&–vSòç7FGW2“°¢&WGW&â†Æ–fV7–6ÆRÓÓÒv÷VârÇÂÆ–fV7–6ÆRÓÓÒw&V÷VæVBr’bbG&–vRÓÒw&W6öÇfVBrbbG&–vRÓÒw7W&W76VBs°§Ð ¦gVæ7F–öâ6÷'Dv—D‡V$–çFVÆÆ–vVæ6Tf–æF–æw2†f–æF–æw3¢”f–æF–æuµÒ“¢”f–æF–æuµÒ°¢&WGW&â²ââæf–æF–æw5Òç6÷'B‚†ÆVgBÂ&–v‡B’Óâ°¢6öç7B6WfW&—G”FVÇFÒ6WfW&—G•&æ²‡&–v‡Bç6WfW&—G’’Ò6WfW&—G•&æ²†ÆVgBç6WfW&—G’“°¢–b‡6WfW&—G”FVÇFÓÒ’°¢&WGW&â6WfW&—G”FVÇF°¢Ð¢6öç7B6öæf–FVæ6TFVÇFÒ‡&–v‡Bæ6öæf–FVæ6U÷66÷&Róò’Ò†ÆVgBæ6öæf–FVæ6U÷66÷&Róò“°¢–b†6öæf–FVæ6TFVÇFÓÒ’°¢&WGW&â6öæf–FVæ6TFVÇF°¢Ð¢&WGW&âæWrFFR‡&–v‡Bæ7&VFVEöB’ævWEF–ÖR‚’ÒæWrFFR†ÆVgBæ7&VFVEöB’ævWEF–ÖR‚“°¢Ò“°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7D•&—6·5vR‚’°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“°¢6öç7B¶ÆöF–ærÂ6WDÆöF–æuÒÒW6U7FFR‡G'VR“°¢6öç7B·&Vg&W6†–ærÂ6WE&Vg&W6†–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶W'&÷"Â6WDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·G&VæDW'&÷"Â6WEG&VæDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&Wõ66ç2Â6WE&Wõ66ç5ÒÒW6U7FFSÅ&Wõ66å&V6÷&EµÓâ…µÒ“°¢6öç7B·&Wôf–æF–æw2Â6WE&Wôf–æF–æw5ÒÒW6U7FFSÄ”f–æF–æuµÓâ…µÒ“°¢6öç7B·G&VæEö–çG2Â6WEG&VæEö–çG5ÒÒW6U7FFSÅG&VæEö–çEµÓâ…µÒ“°¢6öç7B&WVW7E&VbÒW6U&Vbƒ“° ¢6öç7B&Wõ66ç4'””BÒW6TÖVÖò€¢‚’Óà¢&Wõ66ç2ç&VGV6SÅ&V6÷&CÇ7G&–ærÂ&Wõ66å&V6÷&Cãâ‚†62Â66â’Óâ°¢65·66âæ–EÒÒ66ã°¢&WGW&â63°¢ÒÂ·Ò’À¢·&Wõ66ç5Ð¢“° ¢6öç7Bf–æF–æw4–å66÷RÒW6TÖVÖò€¢‚’Óà¢&Wôf–æF–æw2æf–ÇFW"‚†f–æF–ær’Óà¢t•D…T%ô”åDTÄÄ”tTä4Uõ44õUô4DTtõ$”U2ç6öÖR‚†6FVv÷'’’Óâ6FVv÷'’æÖF6‚†f–æF–ær’¢’À¢·&Wôf–æF–æw5Ð¢“° ¢6öç7B÷Väf–æF–æw2ÒW6TÖVÖò‚‚’Óâf–æF–æw4–å66÷Ræf–ÇFW"†—4÷Vå&Wôf–æF–ær’Â¶f–æF–æw4–å66÷UÒ“°¢6öç7B6÷'FVD÷Väf–æF–æw2ÒW6TÖVÖò‚‚’Óâ6÷'Dv—D‡V$–çFVÆÆ–vVæ6Tf–æF–æw2†÷Väf–æF–æw2’Â¶÷Väf–æF–æw5Ò“°¢6öç7B&–÷&—G”f–æF–æw2Ò6÷'FVD÷Väf–æF–æw2ç6Æ–6RƒÂb“° ¢6öç7B6FVv÷'”6&G2ÒW6TÖVÖò€¢‚’Óà¢t•D…T%ô”åDTÄÄ”tTä4Uô4DTtõ$”U2æÖ‚†6FVv÷'’’Óâ°¢6öç7Bf–æF–æw2Òf–æF–æw4–å66÷Ræf–ÇFW"‚†f–æF–ær’Óâ6FVv÷'’æÖF6‚†f–æF–ær’“°¢6öç7B÷VâÒf–æF–æw2æf–ÇFW"†—4÷Vå&Wôf–æF–ær“°¢6öç7B7&—F–6Ä†–v‚Ò÷Vâæf–ÇFW"‚†f–æF–ær’Óâ°¢6öç7B6WfW&—G’Òæ÷&ÖÆ—¦UfÇVR†f–æF–ærç6WfW&—G’’çFôÆ÷vW$66R‚“°¢&WGW&â6WfW&—G’ÓÓÒv7&—F–6ÂrÇÂ6WfW&—G’ÓÓÒv†–v‚s°¢Ò’æÆVæwFƒ°¢&WGW&â°¢ââæ6FVv÷'’À¢F÷FÃ¢f–æF–æw2æÆVæwF‚À¢÷Vã¢÷VâæÆVæwF‚À¢7&—F–6Ä†–v€¢Ó°¢Ò’À¢¶f–æF–æw4–å66÷UÐ¢“° ¢6öç7BÆÅ&W÷6—F÷'•&÷w2ÒW6TÖVÖò‚‚’Óâ°¢6öç7B'•&W÷6—F÷'’ÒæWrÖÇ7G&–ærÂ²&W÷6—F÷'“¢7G&–æs²÷Vã¢çVÖ&W#²7&—F–6Ä†–vƒ¢çVÖ&W#²F÷FÃ¢çVÖ&W"Óâ‚“°¢f÷"†6öç7Bf–æF–æröbf–æF–æw4–å66÷R’°¢6öç7B&W÷6—F÷'’Ò6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡&Wôf–æF–æu&W÷6—F÷'•fÇVR†f–æF–ærÂ&Wõ66ç4'””B’’ÇÂu&W÷6—F÷'’Væf–Æ&ÆRs°¢6öç7B7W'&VçBÒ'•&W÷6—F÷'’ævWB‡&W÷6—F÷'’’óò²&W÷6—F÷'’Â÷Vã¢Â7&—F–6Ä†–vƒ¢ÂF÷FÃ¢Ó°¢7W'&VçBçF÷FÂ³Ò°¢–b†—4÷Vå&Wôf–æF–ær†f–æF–ær’’°¢7W'&VçBæ÷Vâ³Ò°¢6öç7B6WfW&—G’Òæ÷&ÖÆ—¦UfÇVR†f–æF–ærç6WfW&—G’’çFôÆ÷vW$66R‚“°¢–b‡6WfW&—G’ÓÓÒv7&—F–6ÂrÇÂ6WfW&—G’ÓÓÒv†–v‚r’°¢7W'&VçBæ7&—F–6Ä†–v‚³Ò°¢Ð¢Ð¢'•&W÷6—F÷'’ç6WB‡&W÷6—F÷'’Â7W'&VçB“°¢Ð¢&WGW&â²ââæ'•&W÷6—F÷'’çfÇVW2‚•Ð¢ç6÷'B‚†ÆVgBÂ&–v‡B’Óâ&–v‡Bæ7&—F–6Ä†–v‚ÒÆVgBæ7&—F–6Ä†–v‚ÇÂ&–v‡Bæ÷VâÒÆVgBæ÷VâÇÂ&–v‡BçF÷FÂÒÆVgBçF÷FÂ“°¢ÒÂ¶f–æF–æw4–å66÷RÂ&Wõ66ç4'””EÒ“° ¢6öç7B&W÷6—F÷'•&÷w2ÒW6TÖVÖò‚‚’ÓâÆÅ&W÷6—F÷'•&÷w2ç6Æ–6RƒÂR’Â¶ÆÅ&W÷6—F÷'•&÷w5Ò“° ¢6öç7BG&VæE&÷w2ÒW6TÖVÖò‚‚’Óâ°¢6öç7BÖ…F÷FÂÒÖF‚æÖ‚‚ââçG&VæEö–çG2æÖ‚‡ö–çB’Óâö–çBçF÷FÂ’Â“°¢&WGW&âG&VæEö–çG2ç6Æ–6R‚Ób’æÖ‚‡ö–çBÂ–æFW‚’Óâ°¢6öç7B7F'FVDBÒæWrFFR‡ö–çBç7F'FVEöB“°¢6öç7B&–÷&—G’Ò‡ö–çBæ'•÷6WfW&—G“òæ7&—F–6Âóò’²‡ö–çBæ'•÷6WfW&—G“òæ†–v‚óò“°¢&WGW&â°¢¶W“¢G·ö–çBç7F'FVEöGÒÒG¶–æFW‡ÖÀ¢Æ&VÃ¢çVÖ&W"æ—4æâ‡7F'FVDBævWEF–ÖR‚’¢òuVæ¶æ÷vâp¢¢7F'FVDBçFôÆö6ÆU7G&–ær‡VæFVf–æVBÂ²ÖöçFƒ¢w6†÷'BrÂF“¢vçVÖW&–2rÂ†÷W#¢vçVÖW&–2rÂÖ–çWFS¢s"ÖF–v—BrÒ’À¢F÷FÃ¢ö–çBçF÷FÂÀ¢W&6VçFvS¢Ö…F÷FÂâòÖF‚ç&÷VæB‚‡ö–çBçF÷FÂòÖ…F÷FÂ’¢’¢À¢&–÷&—G¢Ó°¢Ò“°¢ÒÂ·G&VæEö–çG5Ò“° ¢6öç7BÆöDF6†&ö&BÒ7–æ2‡F&vWE66÷S¢&öGV7E6W76–öâÂÖöFS¢v–æ—F–ÂrÂw&Vg&W6‚r’Óâ°¢6öç7B&WVW7D”BÒ²·&WVW7E&Vbæ7W'&VçC°¢–b†ÖöFRÓÓÒv–æ—F–Âr’°¢6WDÆöF–ær‡G'VR“°¢ÒVÇ6R°¢6WE&Vg&W6†–ær‡G'VR“°¢Ð¢6WDW'&÷"‚rr“°¢6WEG&VæDW'&÷"‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡F&vWE66÷R“°¢6öç7B·66å&W7VÇBÂf–æF–æu&W7VÇBÂG&VæE&W7VÇEÒÒv—B&öÖ—6RæÆÅ6WGFÆVB…°¢”6Æ–VçBæÆ—7E&Wõ66ç2‡²Æ–Ö—C¢SÒÂWF‚’À¢Æ—7D•&—6·5&Wôf–æF–æw2†WF‚’À¢”6Æ–VçBævWE&Wôf–æF–æw5G&VæG2‡²ö–çG3¢E$TäEõô”åE2ÒÂWF‚¢Ò“°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢–b‡66å&W7VÇBç7FGW2ÓÓÒw&V¦V7FVBr’°¢F‡&÷r66å&W7VÇBç&V6öã°¢Ð¢–b†f–æF–æu&W7VÇBç7FGW2ÓÓÒw&V¦V7FVBr’°¢F‡&÷rf–æF–æu&W7VÇBç&V6öã°¢Ð¢6WE&Wõ66ç2‡66å&W7VÇBçfÇVRæ—FV×2óòµÒ“°¢6WE&Wôf–æF–æw2†f–æF–æu&W7VÇBçfÇVR“°¢–b‡G&VæE&W7VÇBç7FGW2ÓÓÒvgVÆf–ÆÆVBr’°¢6WEG&VæEö–çG2‡G&VæE&W7VÇBçfÇVRæ—FV×2óòµÒ“°¢ÒVÇ6R°¢6WEG&VæEö–çG2…µÒ“°¢6WEG&VæDW'&÷"†f÷&ÖD”W'&÷"‡G&VæE&W7VÇBç&V6öâÂtf–æF–ærG&VæB—2Væf–Æ&ÆRâr’“°¢Ð¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WDW'&÷"†f÷&ÖD”W'&÷"‡&WVW7DW'&÷"Âtf–ÆVBFòÆöB’òvVçF–2&—6²âr’“°¢6WE&Wõ66ç2…µÒ“°¢6WE&Wôf–æF–æw2…µÒ“°¢6WEG&VæEö–çG2…µÒ“°¢6WEG&VæDW'&÷"‚rr“°¢Òf–æÆÇ’°¢–b‡&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçB’°¢6WDÆöF–ær†fÇ6R“°¢6WE&Vg&W6†–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢W6TVffV7B‚‚’Óâ°¢–b‚66÷R’°¢6WDÆöF–ær†fÇ6R“°¢6WDW'&÷"‚uv÷&·76R&÷WFR6öçFW‡B—2Ö—76–ærâr“°¢&WGW&ã°¢Ð¢fö–BÆöDF6†&ö&B‡66÷RÂv–æ—F–Âr“°¢&WGW&â‚’Óâ°¢&WVW7E&Vbæ7W'&VçB³Ò°¢Ó°¢ÒÂ·66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”EÒ“° ¢–b‚66÷R’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷"#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äv—D‡V#Â÷à¢Æƒ#ä’òvVçF–2&—6²Væf–Æ&ÆSÂöƒ#à¢Çåv÷&·76R&÷WFR6öçFW‡B—2Ö—76–ærãÂ÷à¢Â÷6V7F–öãà¢“°¢Ð ¢–b†ÆöF–ær’°¢&WGW&â€¢Ä&÷WFTÆöF–æu7FFP¢F—FÆSÒ%&W&–ær’òvVçF–2&—6² ¢&öG“Ò$ÆöF–ær&W÷6—F÷'’66ç2Âv—D‡V"ÆW'G2ÂæB’v÷&¶fÆ÷r6–væÇ2â ¢óà¢“°¢Ð ¢6öç7Bf–æF–æw5F‚Ò'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"öf–æF–æw2r“°¢6öç7B6öææV7EF‚Ò'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"ö6öææV7Br“°¢6öç7B66ç4'•&V6Væ7’Ò²ââç&Wõ66ç5Òç6÷'B€¢†ÆVgBÂ&–v‡B’ÓâæWrFFR‡&–v‡Bç7F'FVEöB’ævWEF–ÖR‚’ÒæWrFFR†ÆVgBç7F'FVEöB’ævWEF–ÖR‚¢“°¢6öç7B66ç4'”6ö×ÆWF–öâÒ²ââç&Wõ66ç5Òç6÷'B€¢†ÆVgBÂ&–v‡B’Óâ66ä6ö×ÆWF–öå6÷'EfÇVR‡&–v‡B’Ò66ä6ö×ÆWF–öå6÷'EfÇVR†ÆVgB¢“°¢6öç7BÆFW7E66âÒ66ç4'•&V6Væ7•³ÒóòçVÆÃ°¢6öç7BÆFW7E66åFöæRÒÆFW7E66âò&Wõ66å7FGW5FöæR†ÆFW7E66âç7FGW2’¢væWWG&Âs°¢6öç7B7F—fU66ä6÷VçBÒ&Wõ66ç2æf–ÇFW"‚‡66â’Óâ—47F—fU66å7FGW2‡66âç7FGW2’’æÆVæwFƒ°¢6öç7Bf–ÆVE66ä6÷VçBÒ&Wõ66ç2æf–ÇFW"‚‡66â’Óâ—4f–ÆVE66å7FGW2‡66âç7FGW2’’æÆVæwFƒ°¢6öç7B6ö×ÆWFVE66ä6÷VçBÒ66ç4'•&V6Væ7’æf–ÇFW"‚‡66â’Óâ—46ö×ÆWFVE66å7FGW2‡66âç7FGW2’’æÆVæwFƒ°¢6öç7B7V66W76gVÅ66ä6÷VçBÒ66ç4'•&V6Væ7’æf–ÇFW"‚‡66â’Óâ&Wõ66å7FGW5FöæR‡66âç7FGW2’ÓÓÒw7V66W72r’æÆVæwFƒ°¢6öç7BÆFW7D6ö×ÆWFVE66âÒ66ç4'”6ö×ÆWF–öâæf–æB‚‡66â’Óâ—46ö×ÆWFVE66å7FGW2‡66âç7FGW2’’óòçVÆÃ°¢6öç7BÆFW7E7V66W76gVÅ66âÒ66ç4'”6ö×ÆWF–öâæf–æB‚‡66â’Óâ&Wõ66å7FGW5FöæR‡66âç7FGW2’ÓÓÒw7V66W72r’óòçVÆÃ°¢6öç7B66å7V66W75&FRÒ6ö×ÆWFVE66ä6÷VçBâòÖF‚ç&÷VæB‚‡7V66W76gVÅ66ä6÷VçBò6ö×ÆWFVE66ä6÷VçB’¢’¢çVÆÃ°¢6öç7BF÷FÄf–ÆW566ææVBÒ66ç4'•&V6Væ7’ç&VGV6R‚†62Â66â’Óâ62²‡66âæf–ÆW5÷66ææVBóò’Â“°¢6öç7BF÷FÅ66äf–æF–æw2Ò66ç4'•&V6Væ7’ç&VGV6R‚†62Â66â’Óâ62²‡66âæf–æF–æuö6÷VçBóò’Â“°¢6öç7B÷Väf–æF–æt6÷VçBÒ÷Väf–æF–æw2æÆVæwFƒ°¢6öç7B†–v…&–÷&—G”6÷VçBÒ÷Väf–æF–æw2æf–ÇFW"‚†f–æF–ær’Óâ°¢6öç7B6WfW&—G’Òæ÷&ÖÆ—¦UfÇVR†f–æF–ærç6WfW&—G’’çFôÆ÷vW$66R‚“°¢&WGW&â6WfW&—G’ÓÓÒv7&—F–6ÂrÇÂ6WfW&—G’ÓÓÒv†–v‚s°¢Ò’æÆVæwFƒ°¢6öç7B&W÷6—F÷&–W5v—F…6–væÇ2ÒÆÅ&W÷6—F÷'•&÷w2æÆVæwFƒ°¢6öç7Bf—†VDf–æF–æt6÷VçBÒf–æF–æw4–å66÷Ræf–ÇFW"‚†f–æF–ær’Óâæ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2’ÓÓÒvf—†VBr’æÆVæwFƒ°¢6öç7B&V÷VæVDf–æF–æt6÷VçBÒf–æF–æw4–å66÷Ræf–ÇFW"‚†f–æF–ær’Óâæ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2’ÓÓÒw&V÷VæVBr’æÆVæwFƒ°¢6öç7BÆFW7E66äÆ&VÂÒÆFW7E66à¢òG¶6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’†ÆFW7E66âç&W÷6—F÷'’’ÇÂÆFW7E66âç&W÷6—F÷'—Ò+rG¶f÷&ÖEFö¶VäÆ&VÂ†ÆFW7E66âç7FGW2—Ö ¢¢tæò&W÷6—F÷'’66ç2–WBs°¢6öç7B66ä†VÇF…FöæRÒÆFW7E66åFöæRÓÓÒvW'&÷"p¢òvW'&÷"p¢¢7F—fU66ä6÷VçBâ ¢òwv&æ–ærp¢¢ÆFW7E66åFöæRÓÓÒw7V66W72p¢òw7V66W72p¢¢væWWG&Âs°¢6öç7B66ä†VÇF…7FGW4Æ&VÂÐ¢66ä†VÇF…FöæRÓÓÒvW'&÷"p¢òt7F–öâæVVFVBp¢¢66ä†VÇF…FöæRÓÓÒwv&æ–ærp¢òu'Vææ–ærp¢¢66ä†VÇF…FöæRÓÓÒw7V66W72p¢òt†VÇF‡’p¢¢tæò6ö×ÆWFVB66âs°¢6öç7B66ä†VÇF…7VÖÖ'’Ð¢66ä†VÇF…FöæRÓÓÒvW'&÷"p¢òÆFW7E66ãòæW'&÷%öÖW76vRÇÂtÆFW7B66âæVVG2÷W&F÷"GFVçF–öââp¢¢66ä†VÇF…FöæRÓÓÒwv&æ–ærp¢òt&W÷6—F÷'’66â—27W'&VçFÇ’VWVVB÷"'Vææ–ærâp¢¢ÆFW7E7V66W76gVÅ66à¢òÆFW7B7V66W76gVÂ66âf–æ—6†VBG¶f÷&ÖE&VÆF—fUF–ÖR†ÆFW7E7V66W76gVÅ66âæf–æ—6†VEöBÇÂÆFW7E7V66W76gVÅ66âç7F'FVEöB—Òæ ¢¢uv—F–ærf÷"6ö×ÆWFVB&W÷6—F÷'’66ââs° ¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×vR#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–æw2Ö†VFW"–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†VFW"#à¢ÆF—cà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äv—D‡V#Â÷à¢Æƒ#ä’òvVçF–2&—6³Âöƒ#à¢Çä’ÂÔ5Âv÷&¶fÆ÷rÂ'VææW"Âv—D‡V"ÆW'BÂæBf—‚×&VG’6–væÇ2ãÂ÷à¢ÆF—b6Æ74æÖSÒ&–GBÖ÷fW'f–Wr×6÷W&6R×7G&—#à¢Å6÷W&6TÆövôÖ&²&÷f–FW#Ò&v—F‡V""6Æ74æÖSÒ&—2Ö’×&—6²×6÷W&6R"óà¢Ç7ãç¶ÆFW7E66äÆ&VÇÓÂ÷7ãà¢ÂöF—cà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖ–æÆ–æRÖ7F–öç2#à¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâfö–BÆöDF6†&ö&B‡66÷RÂw&Vg&W6‚r—Ð¢F—6&ÆVC×·&Vg&W6†–æwÐ¢à¢·&Vg&W6†–æròu&Vg&W6†–ærâââr¢u&Vg&W6‚wÐ¢Âö'WGFöãà¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’"Fó×¶f–æF–æw5F‡Óà¢÷Vâf–æF–æw0¢ÂôÆ–æ³à¢ÂöF—cà¢ÂöF—cà ¢¶W'&÷"òÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç¶W'&÷'ÓÂöF—câ¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FG2–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×7FG2"&–ÖÆ&VÃÒ$’òvVçF–2&—6²7VÖÖ'’#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FB#à¢Ç7ãä÷VãÂ÷7ãà¢Ç7G&öæsç¶÷Väf–æF–æt6÷VçGÓÂ÷7G&öæsà¢Ç6ÖÆÂ6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FBÖæ÷FR#ç¶f÷&ÖD6÷VçDÆ&VÂ†f–æF–æw4–å66÷RæÆVæwF‚Âw6–væÂr—ÓÂ÷6ÖÆÃà¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FB#à¢Ç7ãä†–vƒÂ÷7ãà¢Ç7G&öæsç¶†–v…&–÷&—G”6÷VçGÓÂ÷7G&öæsà¢Ç6ÖÆÂ6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FBÖæ÷FR#æ7&—F–6Â÷"†–vƒÂ÷6ÖÆÃà¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FB#à¢Ç7ãå&W÷3Â÷7ãà¢Ç7G&öæsç·&W÷6—F÷&–W5v—F…6–væÇ7ÓÂ÷7G&öæsà¢Ç6ÖÆÂ6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FBÖæ÷FR#à¢¶f÷&ÖD6÷VçDÆ&VÂ†7F—fU66ä6÷VçBÂv7F—fR66âr—Ò+r¶f÷&ÖD6÷VçDÆ&VÂ†f–ÆVE66ä6÷VçBÂvf–ÆVB66âr—Ð¢Â÷6ÖÆÃà¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FB#à¢Ç7ãäf—†VCÂ÷7ãà¢Ç7G&öæsç¶f—†VDf–æF–æt6÷VçGÓÂ÷7G&öæsà¢Ç6ÖÆÂ6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FBÖæ÷FR#à¢¶f÷&ÖD6÷VçDÆ&VÂ‡&V÷VæVDf–æF–æt6÷VçBÂw&V÷VæVBrÂw&V÷VæVBr—Ð¢Â÷6ÖÆÃà¢Âö'F–6ÆSà¢ÂöF—cà ¢²W'&÷"bb&Wõ66ç2æÆVæwF‚ÓÓÒbbf–æF–æw4–å66÷RæÆVæwF‚ÓÓÒò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æò’òvVçF–2&—6²–WB ¢&öG“Ò$6öææV7Bv—D‡V"æB'Vâ&W÷6—F÷'’66âFò÷VÆFR’ÂÔ5Âv÷&¶fÆ÷rÂ'VææW"ÂÆW'BÂæBf—‚×&VG’6–væÇ2â ¢7F–öã×·²Æ&VÃ¢t6öææV7Bv—D‡V"rÂFó¢6öææV7EF‚×Ð¢óà¢’¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖw&–B#à¢¶6FVv÷'”6&G2æÖ‚†6FVv÷'’’Óâ€¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ6&B"¶W“×¶6FVv÷'’æ–GÓà¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ6&BÖ†VB#à¢ÆF—cà¢Ç7ãç¶6FVv÷'’æÆ&VÇÓÂ÷7ãà¢Ç7G&öæsç¶6FVv÷'’æ÷VçÓÂ÷7G&öæsà¢ÂöF—cà¢Ç6ÖÆÃç¶6FVv÷'’æ7&—F–6Ä†–v‚âòf÷&ÖD6÷VçDÆ&VÂ†6FVv÷'’æ7&—F–6Ä†–v‚Âv†–v‚rÂv†–v‚r’¢tæò†–v‚wÓÂ÷6ÖÆÃà¢ÂöF—cà¢Çç¶6FVv÷'’ç7VÖÖ'—ÓÂ÷à¢ÄÆ–æ°¢6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ6&BÖÆ–æ² ¢Fó×¶f–æF–æw5F‡Ð¢&–ÖÆ&VÃ×¶6FVv÷'’çF÷FÂâò&Wf–WrG¶6FVv÷'’æÆ&VÇÒf–æF–æw6¢6FVv÷'’æV×G—Ð¢à¢¶6FVv÷'’çF÷FÂâòu&Wf–Wrr¢t6ÆV"wÐ¢ÂôÆ–æ³à¢Âö'F–6ÆSà¢’—Ð¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖÖ–â#à¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ#à¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂÖ†VB#à¢Æƒ3å&–÷&—G’VWVSÂöƒ3à¢ÄÆ–æ²Fó×¶f–æF–æw5F‡Óå&Wf–WrÆÃÂôÆ–æ³à¢ÂöF—cà¢·&–÷&—G”f–æF–æw2æÆVæwF‚ÓÓÒò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æò&–÷&—G’&—6·2 ¢&öG“Ò$÷Vâ’ÂÔ5Âv÷&¶fÆ÷rÂ'VææW"ÂÆW'BÂ÷"f—‚×&VG’f–æF–æw2v–ÆÂV"†W&Râ ¢óà¢’¢€¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖÆ—7B"&öÆSÒ&Æ—7B#à¢·&–÷&—G”f–æF–æw2æÖ‚†f–æF–ær’Óâ°¢6öç7B&W÷6—F÷'’Ò6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡&Wôf–æF–æu&W÷6—F÷'•fÇVR†f–æF–ærÂ&Wõ66ç4'””B’’ÇÂu&W÷6—F÷'’Væf–Æ&ÆRs°¢6öç7B6FVv÷'’Òv—F‡V$–çFVÆÆ–vVæ6T6FVv÷'”f÷$f–æF–ær†f–æF–ær“°¢&WGW&â€¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×&÷r"Fó×¶f–æF–æw5F‡Ò¶W“×¶G¶f–æF–ærç66åö–GÒÒG¶f–æF–æræ–GÖÒ&öÆSÒ&Æ—7F—FVÒ#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷r×F÷#à¢Ç7G&öæsç¶f–æF–ærçF—FÆWÓÂ÷7G&öæsà¢Ç7â6Æ74æÖS×·&Wôf–æF–æu6WfW&—G”6Æ72†f–æF–ærç6WfW&—G’—Óç¶f÷&ÖEFö¶VäÆ&VÂ†f–æF–ærç6WfW&—G’—ÓÂ÷7ãà¢ÂöF—cà¢Çç¶f–æF–æræ‡VÖå÷7VÖÖ'—ÓÂ÷à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷rÖÖWF#à¢Ç7ãç¶6FVv÷'’æÆ&VÇÓÂ÷7ãà¢Ç7ãç·&W÷6—F÷'—ÓÂ÷7ãà¢Ç7ãç·&Wôf–æF–ætÆö6F–öäÆ&VÂ†f–æF–ær—ÓÂ÷7ãà¢ÂöF—cà¢ÂôÆ–æ³à¢“°¢Ò—Ð¢ÂöF—cà¢—Ð¢Â÷6V7F–öãà ¢Æ6–FR6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†÷G7÷B×æVÂ#à¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂÖ†VB#à¢Æƒ3å&W÷6—F÷'’†÷G7÷G3Âöƒ3à¢Ç7ãç·&W÷6—F÷'•&÷w2æÆVæwF‚òf÷&ÖD6÷VçDÆ&VÂ‡&W÷6—F÷'•&÷w2æÆVæwF‚Âw&Wòr’¢tæò†÷G7÷G2wÓÂ÷7ãà¢ÂöF—cà¢·&W÷6—F÷'•&÷w2æÆVæwF‚ÓÓÒò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æò&W÷6—F÷'’†÷G7÷G2 ¢&öG“Ò$†÷G7÷G2V"öæ6Rf–æF–æw26â&RGG&–'WFVBFò&W÷6—F÷&–W2â ¢óà¢’¢€¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†÷G7÷G2#à¢·&W÷6—F÷'•&÷w2æÖ‚‡&÷r’Óâ°¢6öç7B&–÷&—G•6†&RÒÖF‚ç&÷VæB‚‡&÷ræ7&—F–6Ä†–v‚òÖF‚æÖ‚‡&÷rçF÷FÂÂ’’¢“°¢&WGW&â€¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†÷G7÷B×&÷r"Fó×¶f–æF–æw5F‡Ò¶W“×·&÷rç&W÷6—F÷'—Óà¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†÷G7÷B×&÷r×F÷#à¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†÷G7÷BÖ–FVçF—G’#à¢Å6÷W&6TÆövôÖ&²&÷f–FW#Ò&v—F‡V""6Æ74æÖSÒ&—2Ö†÷G7÷B"óà¢ÆF—cà¢Ç7G&öæsç·&÷rç&W÷6—F÷'—ÓÂ÷7G&öæsà¢Ç7ãç¶f÷&ÖD6÷VçDÆ&VÂ‡&÷ræ÷VâÂv÷Vâf–æF–ærr—ÓÂ÷7ãà¢ÂöF—cà¢ÂöF—cà¢Ç7â6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†÷G7÷B×66÷&R#ç·&÷ræ7&—F–6Ä†–v‡ÓÂ÷7ãà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†÷G7÷BÖÖWF#à¢Ç7ãç¶f÷&ÖD6÷VçDÆ&VÂ‡&÷rçF÷FÂÂwF÷FÂ6–væÂr—ÓÂ÷7ãà¢Ç7ãç¶f÷&ÖD6÷VçDÆ&VÂ‡&÷ræ7&—F–6Ä†–v‚Âv†–v‚×&–÷&—G’6–væÂr—ÓÂ÷7ãà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖ†÷G7÷BÖÖWFW""&–Ö†–FFVãÒ'G'VR#à¢Ç7â7G–ÆS×·²v–GFƒ¢G·&–÷&—G•6†&WÒV×Òóà¢ÂöF—cà¢ÂôÆ–æ³à¢“°¢Ò—Ð¢ÂöF—cà¢—Ð¢Âö6–FSà¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6RÖÖ–â#à¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ–GB×&Wò×66âÖ†VÇF‚×æVÂ"&–ÖÆ&VÃÒ%&W÷6—F÷'’66â†VÇF‚#à¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×66âÖ†VÇF‚Ö†VB#à¢ÆF—cà¢Æƒ3å66â†VÇFƒÂöƒ3à¢Çç·66ä†VÇF…7VÖÖ'—ÓÂ÷à¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×66âÖ†VÇF‚Ö7F–öç2#à¢Ç7â6Æ74æÖS×¶–GB×&Wò×66âÖ†VÇF‚×7FGW2—2ÒG·66ä†VÇF…FöæWÖÓà¢·66ä†VÇF…7FGW4Æ&VÇÐ¢Â÷7ãà¢ÄÆ–æ²Fó×¶6öææV7EF‡ÓäÖævR66ç3ÂôÆ–æ³à¢ÂöF—cà¢ÂöF—cà¢¶ÆFW7E66âò€¢Ãà¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×66âÖ†VÇF‚Öw&–B#à¢ÆF—cà¢Ç7ãå7V66W72&FSÂ÷7ãà¢Ç7G&öæsç·66å7V66W75&FRÓÓÒçVÆÂòtâôr¢G·66å7V66W75&FWÒVÓÂ÷7G&öæsà¢Ç6ÖÆÃç¶f÷&ÖD6÷VçDÆ&VÂ†6ö×ÆWFVE66ä6÷VçBÂv6ö×ÆWFVB66âr—ÓÂ÷6ÖÆÃà¢ÂöF—cà¢ÆF—cà¢Ç7ãäÆ7B6ö×ÆWFVCÂ÷7ãà¢Ç7G&öæsç¶ÆFW7D6ö×ÆWFVE66âòf÷&ÖE&VÆF—fUF–ÖR†ÆFW7D6ö×ÆWFVE66âæf–æ—6†VEöBÇÂÆFW7D6ö×ÆWFVE66âç7F'FVEöB’¢tâôwÓÂ÷7G&öæsà¢Ç6ÖÆÃç¶ÆFW7D6ö×ÆWFVE66âòf÷&ÖEFö¶VäÆ&VÂ†ÆFW7D6ö×ÆWFVE66âç7FGW2’¢tæòf–æ—6†VB66âwÓÂ÷6ÖÆÃà¢ÂöF—cà¢ÆF—cà¢Ç7ãäf–ÆW26÷fW&VCÂ÷7ãà¢Ç7G&öæsç·F÷FÄf–ÆW566ææVBçFôÆö6ÆU7G&–ær‚—ÓÂ÷7G&öæsà¢Ç6ÖÆÃç¶f÷&ÖD6÷VçDÆ&VÂ‡66ç4'•&V6Væ7’æÆVæwF‚Âw&V6VçB66âr—ÓÂ÷6ÖÆÃà¢ÂöF—cà¢ÆF—cà¢Ç7ãäf–æF–æw27W&f6VCÂ÷7ãà¢Ç7G&öæsç·F÷FÅ66äf–æF–æw2çFôÆö6ÆU7G&–ær‚—ÓÂ÷7G&öæsà¢Ç6ÖÆÃç¶f÷&ÖD6÷VçDÆ&VÂ††–v…&–÷&—G”6÷VçBÂv†–v‚&–÷&—G’rÂv†–v‚&–÷&—G’r—ÓÂ÷6ÖÆÃà¢ÂöF—cà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×66âÖ†VÇF‚×F–ÖVÆ–æR"&–ÖÆ&VÃÒ%&V6VçB&W÷6—F÷'’66âWfVçG2#à¢·66ç4'•&V6Væ7’ç6Æ–6RƒÂB’æÖ‚‡66â’Óâ°¢6öç7BFöæRÒ&Wõ66å7FGW5FöæR‡66âç7FGW2“°¢6öç7B&W÷6—F÷'”Æ&VÂÒ6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡66âç&W÷6—F÷'’’ÇÂ66âç&W÷6—F÷'’ÇÂu&W÷6—F÷'’Væf–Æ&ÆRs°¢6öç7B66åF–ÖRÒ66âæf–æ—6†VEöBÇÂ66âç7F'FVEöC°¢&WGW&â€¢Æ'F–6ÆR¶W“×·66âæ–GÒ6Æ74æÖS×¶–GB×&Wò×66âÖ†VÇF‚ÖWfVçB—2ÒG·FöæWÖÓà¢Ç7â6Æ74æÖSÒ&–GB×&Wò×66âÖ†VÇF‚ÖF÷B"&–Ö†–FFVãÒ'G'VR"óà¢ÆF—cà¢Ç7G&öæsç·&W÷6—F÷'”Æ&VÇÓÂ÷7G&öæsà¢Ç7ãà¢¶f÷&ÖEFö¶VäÆ&VÂ‡66âç7FGW2—Ò+r¶f÷&ÖD6÷VçDÆ&VÂ‡66âæf–æF–æuö6÷VçBÂvf–æF–ærr—Ò+r¶f÷&ÖD6÷VçDÆ&VÂ‡66âæf–ÆW5÷66ææVBÂvf–ÆRr—Ð¢Â÷7ãà¢ÂöF—cà¢ÇF–ÖRFFUF–ÖS×·66åF–ÖWÓç¶f÷&ÖE&VÆF—fUF–ÖR‡66åF–ÖR—ÓÂ÷F–ÖSà¢Âö'F–6ÆSà¢“°¢Ò—Ð¢ÂöF—cà¢Âóà¢’¢€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æò66ç2–WB ¢&öG“Ò$’òvVçF–2&—6²æVVG2BÆV7BöæR&W÷6—F÷'’66ââ ¢óà¢—Ð¢Â÷6V7F–öãà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂ#à¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×æVÂÖ†VB#à¢Æƒ3äf–æF–ærG&VæCÂöƒ3à¢Ç7ãç·G&VæE&÷w2æÆVæwF‚òf÷&ÖD6÷VçDÆ&VÂ‡G&VæE&÷w2æÆVæwF‚Âwö–çBr’¢tæòG&VæBwÓÂ÷7ãà¢ÂöF—cà¢·G&VæDW'&÷"ò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ%G&VæBVæf–Æ&ÆR ¢&öG“×·G&VæDW'&÷'Ð¢óà¢’¢G&VæE&÷w2æÆVæwF‚ÓÓÒò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æòG&VæB–WB ¢&öG“Ò%G&VæBö–çG2v–ÆÂV"gFW"&W÷6—F÷'’f–æF–ær6æ6†÷G2&Rf–Æ&ÆRâ ¢óà¢’¢€¢ÆF—b6Æ74æÖSÒ&–GBÖv—F‡V"Ö–çFVÆÆ–vVæ6R×G&VæB#à¢·G&VæE&÷w2æÖ‚‡&÷r’Óâ€¢Æ'F–6ÆR¶W“×·&÷ræ¶W—Óà¢ÆF—cà¢Ç7ãç·&÷ræÆ&VÇÓÂ÷7ãà¢Ç7G&öæsç·&÷rçF÷FÇÓÂ÷7G&öæsà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖ&"×G&6²"&öÆSÒ&–Ör"&–ÖÆ&VÃ×¶’òvVçF–2&—6²G&VæBG·&÷ræÆ&VÇÖÓà¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖ&""7G–ÆS×·²v–GFƒ¢G·&÷rçW&6VçFvWÒV×Òóà¢ÂöF—cà¢Ç6ÖÆÃç¶f÷&ÖD6÷VçDÆ&VÂ‡&÷rç&–÷&—G’Âv†–v‚&–÷&—G’rÂv†–v‚&–÷&—G’r—ÓÂ÷6ÖÆÃà¢Âö'F–6ÆSà¢’—Ð¢ÂöF—cà¢—Ð¢Â÷6V7F–öãà¢ÂöF—cà¢Â÷6V7F–öãà¢“°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7Df–æF–æw5vR‡²vVçF–4öæÇ’ÒfÇ6RÓ¢²vVçF–4öæÇ“ó¢&ööÆVâÒÒ·Ò’°¢6öç7BÆö6F–öâÒW6TÆö6F–öâ‚“°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“°¢6öç7B66÷T¶W’Ò&öGV7E6W76–öä¶W’‡66÷R“°¢6öç7B²ÖRÒÒW6TÖR‚“° ¢6öç7B¶ÆöF–ærÂ6WDÆöF–æuÒÒW6U7FFR‡G'VR“°¢6öç7B·&Vg&W6†–ærÂ6WE&Vg&W6†–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·6–væÇ4ÆöF–ærÂ6WE6–væÇ4ÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·6–væÇ5&Vg&W6†–ærÂ6WE6–væÇ5&Vg&W6†–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶W'&÷"Â6WDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·6–væÄW'&÷"Â6WE6–væÄW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·G&VæDW'&÷"Â6WEG&VæDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&Wõ66ç2Â6WE&Wõ66ç5ÒÒW6U7FFSÅ&Wõ66å&V6÷&EµÓâ…µÒ“°¢6öç7B·&Wôf–æF–æw2Â6WE&Wôf–æF–æw5ÒÒW6U7FFSÄ”f–æF–æuµÓâ…µÒ“°¢6öç7B·&Wôf–æF–æu7VÖÖ'’Â6WE&Wôf–æF–æu7VÖÖ'•ÒÒW6U7FFSÅ&Wôf–æF–æw57VÖÖ'’ÂçVÆÃâ†çVÆÂ“°¢6öç7B·G&VæEö–çG2Â6WEG&VæEö–çG5ÒÒW6U7FFSÅG&VæEö–çEµÓâ…µÒ“°¢6öç7B·&Wõ&—6´w&‚Â6WE&Wõ&—6´w&…ÒÒW6U7FFSÅ&Wõ&—6´w&‚ÂçVÆÃâ†çVÆÂ“°¢6öç7B·&—6´w&„W'&÷"Â6WE&—6´w&„W'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&Wõ66äf–ÇFW"Â6WE&Wõ66äf–ÇFW%ÒÒW6U7FFR‚rr“°¢6öç7B·6WfW&—G”f–ÇFW"Â6WE6WfW&—G”f–ÇFW%ÒÒW6U7FFSÂ‡G—Vöb$Uõôd”äD”äuõ4UdU$•E•ôd”ÅDU%2•¶çVÖ&W%Óâ‚vÆÂr“°¢6öç7B·G—Tf–ÇFW"Â6WEG—Tf–ÇFW%ÒÒW6U7FFSÂ‡G—Vöb$Uõôd”äD”äuõE•Uôd”ÅDU%2•¶çVÖ&W%Óâ‚vÆÂr“°¢6öç7B·7FGW4f–ÇFW"Â6WE7FGW4f–ÇFW%ÒÒW6U7FFSÂ‡G—Vöb$Uõôd”äD”äuõ5DEU5ôd”ÅDU%2•¶çVÖ&W%Óâ‚vÆÂr“°¢6öç7B¶76–væVTf–ÇFW"Â6WD76–væVTf–ÇFW%ÒÒW6U7FFR‚rr“°¢6öç7B·6÷W&6Tf–ÇFW"Â6WE6÷W&6Tf–ÇFW%ÒÒW6U7FFR‚rr“°¢6öç7B¶Ö–ä6öæf–FVæ6Tf–ÇFW"Â6WDÖ–ä6öæf–FVæ6Tf–ÇFW%ÒÒW6U7FFR‚rr“°¢6öç7B·6÷'D'’Â6WE6÷'D'•ÒÒW6U7FFSÂ‡G—Vöb$Uõôd”äD”äuõ4õ%Eôd”TÄE2•¶çVÖ&W%Óâ‚w6WfW&—G’r“°¢6öç7B·6÷'D÷&FW"Â6WE6÷'D÷&FW%ÒÒW6U7FFSÂv62rÂvFW62sâ‚vFW62r“°¢6öç7B&Wôf–æF–ætf–ÇFW%6æ6†÷C¢&Wôf–æF–ætf–ÇFW%6æ6†÷BÒ°¢&Wõ66äf–ÇFW"À¢6WfW&—G”f–ÇFW"À¢G—Tf–ÇFW"À¢7FGW4f–ÇFW"À¢76–væVTf–ÇFW"À¢6÷W&6Tf–ÇFW"À¢Ö–ä6öæf–FVæ6Tf–ÇFW"À¢6÷'D'’À¢6÷'D÷&FW ¢Ó°¢6öç7B¶f–ÇFW'4W‡æFVBÂ6WDf–ÇFW'4W‡æFVEÒÒW6U7FFR‡G'VR“°¢6öç7B¶F—6Ö—76VDf–ÆVE66ä¶W—2Â6WDF—6Ö—76VDf–ÆVE66ä¶W—5ÒÒW6U7FFSÅ6WCÇ7G&–æsãâ‚‚’Óà¢&VDF—6Ö—76VE&Wôf–ÆVE66ä¶W—2‚¢“°¢6öç7B·&VÖ÷f–ætf–ÆVE66ä”BÂ6WE&VÖ÷f–ætf–ÆVE66ä”EÒÒW6U7FFR‚rr“°¢6öç7B¶†–W&&6‡”÷Vå7FFRÂ6WD†–W&&6‡”÷Vå7FFUÒÒW6U7FFSÇ°¢&W÷6—F÷&–W3¢6WCÇ7G&–æsã°¢66ç3¢6WCÇ7G&–æsã°¢6WfW&—F–W3¢6WCÇ7G&–æsã°¢–æ—F–Æ—¦VC¢&ööÆVã°¢Óâ‡°¢&W÷6—F÷&–W3¢æWr6WB‚’À¢66ç3¢æWr6WB‚’À¢6WfW&—F–W3¢æWr6WB‚’À¢–æ—F–Æ—¦VC¢fÇ6P¢Ò“°¢6öç7B·6VÆV7FVDf–æF–æt¶W’Â6WE6VÆV7FVDf–æF–æt¶W•ÒÒW6U7FFR‚rr“°¢6öç7B¶f–æF–ætFWF–Ä÷VâÂ6WDf–æF–ætFWF–Ä÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B¶f–æF–ætÖVçT¶W’Â6WDf–æF–ætÖVçT¶W•ÒÒW6U7FFR‚rr“°¢6öç7B¶f–æF–ætÖVçUÆ6VÖVçBÂ6WDf–æF–ætÖVçUÆ6VÖVçEÒÒW6U7FFSÂvF÷vârÂwWsâ‚vF÷vâr“°¢6öç7B¶FVÆWFT6æF–FFRÂ6WDFVÆWFT6æF–FFUÒÒW6U7FFSÄ”f–æF–ærÂçVÆÃâ†çVÆÂ“°¢6öç7B¶'VÆ´FVÆWFT6æF–FFW2Â6WD'VÆ´FVÆWFT6æF–FFW5ÒÒW6U7FFSÄ”f–æF–æuµÓâ…µÒ“°¢6öç7B¶FVÆWFTÆöF–ærÂ6WDFVÆWFTÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶FVÆWFTW'&÷"Â6WDFVÆWFTW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öå&Wf–WrÂ6WE&VÖVF–F–öå&Wf–WuÒÒW6U7FFSÅ&Wôf–æF–æu&VÖVF–F–öå&Wf–WrÂçVÆÃâ†çVÆÂ“°¢6öç7B·&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’Â6WE&VÖVF–F–öå&Wf–Wtf–æF–æt¶W•ÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öå&Wf–WtÆöF–ærÂ6WE&VÖVF–F–öå&Wf–WtÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·&VÖVF–F–öå&Wf–WtW'&÷"Â6WE&VÖVF–F–öå&Wf–WtW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçBÂ6WE&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçEÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öåV&Æ—6„&6T'&æ6‚Â6WE&VÖVF–F–öåV&Æ—6„&6T'&æ6…ÒÒW6U7FFR‚vÖ–âr“°¢6öç7B·&VÖVF–F–öåV&Æ—6…Fö¶VâÂ6WE&VÖVF–F–öåV&Æ—6…Fö¶VåÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öåV&Æ—6„&÷fVBÂ6WE&VÖVF–F–öåV&Æ—6„&÷fVEÒÒW6U7FFR†fÇ6R“°¢6öç7B·&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVBÂ6WE&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVEÒÒW6U7FFR†fÇ6R“°¢6öç7B·&VÖVF–F–öåV&Æ—6„ÆöF–ærÂ6WE&VÖVF–F–öåV&Æ—6„ÆöF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·&VÖVF–F–öåV&Æ—6„W'&÷"Â6WE&VÖVF–F–öåV&Æ—6„W'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·&VÖVF–F–öåV&Æ—6…&W7VÇBÂ6WE&VÖVF–F–öåV&Æ—6…&W7VÇEÒÐ¢W6U7FFSÅ&Wôf–æF–æu&VÖVF–F–öåV&Æ—6…&W7öç6RÂçVÆÃâ†çVÆÂ“° ¢6öç7B&WVW7E&VbÒW6U&Vbƒ“°¢6öç7B6–væÅ&WVW7E&VbÒW6U&Vbƒ“°¢6öç7Bf–æDFVÆWFU&WVW7E&VbÒW6U&Vbƒ“°¢6öç7Bf–ÆVE66å&VÖ÷fU&WVW7E&VbÒW6U&Vbƒ“°¢6öç7B7W'&VçE66÷T¶W•&VbÒW6U&Vb‡66÷T¶W’“°¢6öç7B&Wôf–æF–ætf–ÇFW%&VbÒW6U&VcÅ&Wôf–æF–ætf–ÇFW%6æ6†÷Câ‡&Wôf–æF–ætf–ÇFW%6æ6†÷B“°¢6öç7B&VÖVF–F–öå&Wf–Wu&WVW7E&VbÒW6U&Vbƒ“°¢6öç7B&VÖVF–F–öåV&Æ—6…&WVW7E&VbÒW6U&Vbƒ“°¢6öç7Bf–æF–ætFWF–Ä6Æ÷6U&VbÒW6U&VcÄ…DÔÄ'WGFöäVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7Bf–æF–ætFWF–ÄÖöFÅ&VbÒW6U&VcÄ…DÔÄVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7Bf–æF–ætFWF–Ä÷VæW%&VbÒW6U&VcÄ…DÔÄVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7Bf–æF–ætFVÆWFT6Æ÷6U&VbÒW6U&VcÄ…DÔÄ'WGFöäVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7Bf–æF–ætFVÆWFTÖöFÅ&VbÒW6U&VcÄ…DÔÄVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7Bf–æF–ætFVÆWFT÷VæW%&VbÒW6U&VcÄ…DÔÄVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢7W'&VçE66÷T¶W•&Vbæ7W'&VçBÒ66÷T¶W“°¢&Wôf–æF–ætf–ÇFW%&Vbæ7W'&VçBÒ&Wôf–æF–ætf–ÇFW%6æ6†÷C° ¢6öç7BWFFT†–W&&6‡”÷Vå7FFRÒ€¢ÆWfVÃ¢w&W÷6—F÷&–W2rÂw66ç2rÂw6WfW&—F–W2rÀ¢¶W“¢7G&–ærÀ¢÷Vã¢&ööÆVà¢’Óâ°¢6WD†–W&&6‡”÷Vå7FFR‚†7W'&VçB’Óâ°¢–b†7W'&VçE¶ÆWfVÅÒæ†2†¶W’’ÓÓÒ÷Vâ’°¢&WGW&â7W'&VçC°¢Ð¢6öç7BæW‡D¶W—2ÒæWr6WB†7W'&VçE¶ÆWfVÅÒ“°¢–b†÷Vâ’°¢æW‡D¶W—2æFB†¶W’“°¢ÒVÇ6R°¢æW‡D¶W—2æFVÆWFR†¶W’“°¢Ð¢&WGW&â²ââæ7W'&VçBÂ¶ÆWfVÅÓ¢æW‡D¶W—2Â–æ—F–Æ—¦VC¢G'VRÓ°¢Ò“°¢Ó° ¢6öç7B†æFÆTf–æF–ætFWF–ÄÖöFÄ¶W”F÷vâÒ†WfVçC¢&V7D¶W–&ö&DWfVçCÄ…DÔÄVÆVÖVçCâ’Óâ°¢–b†WfVçBæ¶W’ÓÓÒtW66Rr’°¢WfVçBç&WfVçDFVfVÇB‚“°¢6Æ÷6Tf–æF–ætFWF–Â‚“°¢&WGW&ã°¢Ð ¢–b†WfVçBæ¶W’ÓÒuF"r’°¢&WGW&ã°¢Ð ¢6öç7BÖöFÂÒf–æF–ætFWF–ÄÖöFÅ&Vbæ7W'&VçC°¢–b‚ÖöFÂ’°¢&WGW&ã°¢Ð ¢6öç7Bfö7W6&ÆTVÆVÖVçG2Ò'&’æg&öÒ†ÖöFÂçVW'•6VÆV7F÷$ÆÃÄ…DÔÄVÆVÖVçCâ„ÔôDÅôdô5U4$ÄUõ4TÄT5Dõ"’’æf–ÇFW"€¢†VÆVÖVçB’ÓâVÆVÖVçBævWDGG&–'WFR‚v&–Ö†–FFVâr’ÓÒwG'VRp¢“°¢–b†fö7W6&ÆTVÆVÖVçG2æÆVæwF‚ÓÓÒ’°¢WfVçBç&WfVçDFVfVÇB‚“°¢ÖöFÂæfö7W2‚“°¢&WGW&ã°¢Ð ¢6öç7Bf—'7DVÆVÖVçBÒfö7W6&ÆTVÆVÖVçG5³Ó°¢6öç7BÆ7DVÆVÖVçBÒfö7W6&ÆTVÆVÖVçG5¶fö7W6&ÆTVÆVÖVçG2æÆVæwF‚ÒÓ°¢6öç7B7F—fTVÆVÖVçBÒFö7VÖVçBæ7F—fTVÆVÖVçB–ç7Fæ6Vöb…DÔÄVÆVÖVçBòFö7VÖVçBæ7F—fTVÆVÖVçB¢çVÆÃ°¢6öç7Bfö7W4—4÷WG6–FTÖöFÂÒ7F—fTVÆVÖVçBÇÂÖöFÂæ6öçF–ç2†7F—fTVÆVÖVçB“° ¢–b†WfVçBç6†–gD¶W’’°¢–b†fö7W4—4÷WG6–FTÖöFÂÇÂ7F—fTVÆVÖVçBÓÓÒf—'7DVÆVÖVçB’°¢WfVçBç&WfVçDFVfVÇB‚“°¢Æ7DVÆVÖVçBæfö7W2‚“°¢Ð¢&WGW&ã°¢Ð ¢–b†fö7W4—4÷WG6–FTÖöFÂÇÂ7F—fTVÆVÖVçBÓÓÒÆ7DVÆVÖVçB’°¢WfVçBç&WfVçDFVfVÇB‚“°¢f—'7DVÆVÖVçBæfö7W2‚“°¢Ð¢Ó° ¢6öç7B6Æ÷6Tf–æF–ætFVÆWFTF–ÆörÒ†÷F–öç3¢²ÆÆ÷tGW&–ætÆöF–æsó¢&ööÆVâÒÒ·Ò’Óâ°¢–b†FVÆWFTÆöF–ærbb÷F–öç2æÆÆ÷tGW&–ætÆöF–ær’°¢&WGW&ã°¢Ð¢6WDFVÆWFT6æF–FFR†çVÆÂ“°¢6WD'VÆ´FVÆWFT6æF–FFW2…µÒ“°¢6WDFVÆWFTW'&÷"‚rr“°¢6öç7B÷VæW"Òf–æF–ætFVÆWFT÷VæW%&Vbæ7W'&VçC°¢f–æF–ætFVÆWFT÷VæW%&Vbæ7W'&VçBÒçVÆÃ°¢–b†÷VæW"bbFö7VÖVçBæ6öçF–ç2†÷VæW"’bbG—Vöb÷VæW"æfö7W2ÓÓÒvgVæ7F–öâr’°¢÷VæW"æfö7W2‚“°¢Ð¢Ó° ¢6öç7B†æFÆTf–æF–ætFVÆWFTÖöFÄ¶W”F÷vâÒ†WfVçC¢&V7D¶W–&ö&DWfVçCÄ…DÔÄVÆVÖVçCâ’Óâ°¢–b†WfVçBæ¶W’ÓÓÒtW66Rr’°¢WfVçBç&WfVçDFVfVÇB‚“°¢–b‚FVÆWFTÆöF–ær’°¢6Æ÷6Tf–æF–ætFVÆWFTF–Æör‚“°¢Ð¢&WGW&ã°¢Ð ¢–b†WfVçBæ¶W’ÓÒuF"r’°¢&WGW&ã°¢Ð ¢6öç7BÖöFÂÒf–æF–ætFVÆWFTÖöFÅ&Vbæ7W'&VçC°¢–b‚ÖöFÂ’°¢&WGW&ã°¢Ð ¢6öç7Bfö7W6&ÆTVÆVÖVçG2Ò'&’æg&öÒ†ÖöFÂçVW'•6VÆV7F÷$ÆÃÄ…DÔÄVÆVÖVçCâ„ÔôDÅôdô5U4$ÄUõ4TÄT5Dõ"’’æf–ÇFW"€¢†VÆVÖVçB’ÓâVÆVÖVçBævWDGG&–'WFR‚v&–Ö†–FFVâr’ÓÒwG'VRp¢“°¢–b†fö7W6&ÆTVÆVÖVçG2æÆVæwF‚ÓÓÒ’°¢WfVçBç&WfVçDFVfVÇB‚“°¢ÖöFÂæfö7W2‚“°¢&WGW&ã°¢Ð ¢6öç7Bf—'7DVÆVÖVçBÒfö7W6&ÆTVÆVÖVçG5³Ó°¢6öç7BÆ7DVÆVÖVçBÒfö7W6&ÆTVÆVÖVçG5¶fö7W6&ÆTVÆVÖVçG2æÆVæwF‚ÒÓ°¢6öç7B7F—fTVÆVÖVçBÒFö7VÖVçBæ7F—fTVÆVÖVçB–ç7Fæ6Vöb…DÔÄVÆVÖVçBòFö7VÖVçBæ7F—fTVÆVÖVçB¢çVÆÃ°¢6öç7Bfö7W4—4÷WG6–FTÖöFÂÒ7F—fTVÆVÖVçBÇÂÖöFÂæ6öçF–ç2†7F—fTVÆVÖVçB“° ¢–b†WfVçBç6†–gD¶W’’°¢–b†fö7W4—4÷WG6–FTÖöFÂÇÂ7F—fTVÆVÖVçBÓÓÒf—'7DVÆVÖVçB’°¢WfVçBç&WfVçDFVfVÇB‚“°¢Æ7DVÆVÖVçBæfö7W2‚“°¢Ð¢&WGW&ã°¢Ð ¢–b†fö7W4—4÷WG6–FTÖöFÂÇÂ7F—fTVÆVÖVçBÓÓÒÆ7DVÆVÖVçB’°¢WfVçBç&WfVçDFVfVÇB‚“°¢f—'7DVÆVÖVçBæfö7W2‚“°¢Ð¢Ó° ¢6öç7B†æFÆTf–æF–ætÖVçT¶W”F÷vâÒ†WfVçC¢&V7D¶W–&ö&DWfVçCÄ…DÔÄVÆVÖVçCâ’Óâ°¢WfVçBç7F÷&÷vF–öâ‚“°¢–b†WfVçBæ¶W’ÓÓÒtW66Rr’°¢WfVçBç&WfVçDFVfVÇB‚“°¢6WDf–æF–ætÖVçT¶W’‚rr“°¢Ð¢Ó° ¢6öç7BG&VæDÖ…F÷FÂÒW6TÖVÖò‚‚’Óâ°¢6öç7BF÷FÇ2ÒG&VæEö–çG2æÖ‚‡ö–çB’Óâö–çBçF÷FÂ“°¢&WGW&âF÷FÇ2æÆVæwF‚òÖF‚æÖ‚‚ââçF÷FÇ2’¢°¢ÒÂ·G&VæEö–çG5Ò“° ¢6öç7B&Wõ66ç4'””BÒW6TÖVÖò€¢‚’Óà¢&Wõ66ç2ç&VGV6SÅ&V6÷&CÇ7G&–ærÂ&Wõ66å&V6÷&Cãâ‚†62Â66â’Óâ°¢65·66âæ–EÒÒ66ã°¢&WGW&â63°¢ÒÂ·Ò’À¢·&Wõ66ç5Ð¢“° ¢6öç7B66÷VE&Wôf–æF–æw2ÒW6TÖVÖò€¢‚’Óâ†vVçF–4öæÇ’ò&Wôf–æF–æw2æf–ÇFW"†—4vVçF–5&—6´f–æF–ær’¢&Wôf–æF–æw2’À¢¶vVçF–4öæÇ’Â&Wôf–æF–æw5Ð¢“° ¢6öç7Bf–ÇFW&VDf–æF–æw2ÒW6TÖVÖò‚‚’Óâ°¢6öç7Bæ÷&ÖÆ—¦VD76–væVTf–ÇFW"Òæ÷&ÖÆ—¦UfÇVR†76–væVTf–ÇFW"’çFôÆ÷vW$66R‚“°¢&WGW&â66÷VE&Wôf–æF–æw2æf–ÇFW"‚†f–æF–ær’Óâ°¢6öç7B7FGW2Òæ÷&ÖÆ—¦Tf–æF–æu7FGW2†f–æF–ærçG&–vSòç7FGW2“°¢6öç7B76–væVRÒæ÷&ÖÆ—¦UfÇVR†f–æF–ærçG&–vSòæ76–væVRóòrr’çFôÆ÷vW$66R‚“°¢6öç7BÖF6†W57FGW2Ò7FGW4f–ÇFW"ÓÓÒvÆÂrÇÂ7FGW2ÓÓÒ7FGW4f–ÇFW#°¢6öç7BÖF6†W476–væVRÒæ÷&ÖÆ—¦VD76–væVTf–ÇFW"ÇÂ76–væVRæ–æ6ÇVFW2†æ÷&ÖÆ—¦VD76–væVTf–ÇFW"“° ¢&WGW&âÖF6†W57FGW2bbÖF6†W476–væVS°¢Ò“°¢ÒÂ·66÷VE&Wôf–æF–æw2Â7FGW4f–ÇFW"Â76–væVTf–ÇFW%Ò“° ¢6öç7B&—6´w&„f–ÇFW'5Vç7W÷'FVBÐ¢7FGW4f–ÇFW"ÓÒvÆÂrÇÀ¢æ÷&ÖÆ—¦UfÇVR†76–væVTf–ÇFW"’ÓÒrrÇÀ¢æ÷&ÖÆ—¦UfÇVR‡6÷W&6Tf–ÇFW"’ÓÒrs° ¢6öç7Bf–æF–æt†–W&&6‡’ÒW6TÖVÖò€¢‚’Óà¢w&÷W&Wôf–æF–æw4'•&W÷6—F÷'”FFU6WfW&—G’†f–ÇFW&VDf–æF–æw2Â°¢&W÷6—F÷'”f÷$f–æF–æs¢†f–æF–ær’Óà¢6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡&Wôf–æF–æu&W÷6—F÷'•fÇVR†f–æF–ærÂ&Wõ66ç4'””B’’ÇÀ¢u&W÷6—F÷'’Væf–Æ&ÆRrÀ¢66äFFTf÷$f–æF–æs¢†f–æF–ær’Óâ&Wôf–æF–æu66äFFTÆ&VÂ†f–æF–ærÂ&Wõ66ç4'””B’À¢66å6÷'EfÇVTf÷$f–æF–æs¢†f–æF–ær’Óâ&Wôf–æF–æu66åF–ÖW7F×†f–æF–ærÂ&Wõ66ç4'””B’À¢6÷'D'’À¢6÷'D÷&FW ¢Ò’À¢¶f–ÇFW&VDf–æF–æw2Â&Wõ66ç4'””BÂ6÷'D'’Â6÷'D÷&FW%Ð¢“° ¢W6TVffV7B‚‚’Óâ°¢–b†f–æF–æt†–W&&6‡’æÆVæwF‚ÓÓÒ’°¢&WGW&ã°¢Ð¢6WD†–W&&6‡”÷Vå7FFR‚†7W'&VçB’Óâ°¢–b†7W'&VçBæ–æ—F–Æ—¦VB’°¢&WGW&â7W'&VçC°¢Ð¢6öç7Bf—'7E&W÷6—F÷'’Òf–æF–æt†–W&&6‡•³Ó°¢6öç7Bf—'7E66âÒf—'7E&W÷6—F÷'’ç66äw&÷W5³Ó°¢6öç7Bf—'7E6WfW&—G’Òf—'7E66ãòç6WfW&—G”w&÷W5³Ó°¢&WGW&â°¢&W÷6—F÷&–W3¢æWr6WB†f—'7E&W÷6—F÷'’ò¶f—'7E&W÷6—F÷'’æ¶W•Ò¢µÒ’À¢66ç3¢æWr6WB†f—'7E66âò¶f—'7E66âæ¶W•Ò¢µÒ’À¢6WfW&—F–W3¢æWr6WB†f—'7E6WfW&—G’ò¶f—'7E6WfW&—G’æ¶W•Ò¢µÒ’À¢–æ—F–Æ—¦VC¢G'VP¢Ó°¢Ò“°¢ÒÂ¶f–æF–æt†–W&&6‡•Ò“° ¢6öç7B6VÆV7FVDf–æF–ærÒW6TÖVÖò€¢‚’Óâf–æE&Wôf–æF–æt'•6VÆV7F–öä¶W’†f–ÇFW&VDf–æF–æw2Â6VÆV7FVDf–æF–æt¶W’’À¢¶f–ÇFW&VDf–æF–æw2Â6VÆV7FVDf–æF–æt¶W•Ð¢“° ¢6öç7BF÷&—6´w&…66÷&W2ÒW6TÖVÖò€¢‚’Óâ°¢–b†f–ÇFW&VDf–æF–æw2æÆVæwF‚ÓÓÒÇÂ&—6´w&„f–ÇFW'5Vç7W÷'FVB’°¢&WGW&âµÓ°¢Ð¢6öç7Bf—6–&ÆTf–æF–æt”G2ÒæWr6WB†f–ÇFW&VDf–æF–æw2æÖ‚†f–æF–ær’Óâf–æF–æræ–B’“°¢&WGW&â6÷'E&Wõ&—6´w&…66÷&W2‡&Wõ&—6´w&ƒòç66÷&W2óòµÒ¢æf–ÇFW"‚‡66÷&R’Óâf—6–&ÆTf–æF–æt”G2æ†2‡66÷&Ræf–æF–æuö–B’¢ç6Æ–6RƒÂ2“°¢ÒÀ¢¶f–ÇFW&VDf–æF–æw2Â&Wõ&—6´w&‚Â&—6´w&„f–ÇFW'5Vç7W÷'FVEÐ¢“° ¢6öç7B7&—F–6Äf–æF–æt6÷VçBÒW6TÖVÖò€¢‚’Óâf–ÇFW&VDf–æF–æw2æf–ÇFW"‚†f–æF–ær’Óâæ÷&ÖÆ—¦UfÇVR†f–æF–ærç6WfW&—G’’çFôÆ÷vW$66R‚’ÓÓÒv7&—F–6Âr’æÆVæwF‚À¢¶f–ÇFW&VDf–æF–æw5Ð¢“° ¢6öç7B7F—fU66ä6÷VçBÒW6TÖVÖò€¢‚’Óâ&Wõ66ç2æf–ÇFW"‚‡66â’Óâæ÷&ÖÆ—¦UfÇVR‡66âç7FGW2’çFôÆ÷vW$66R‚’ÓÓÒw7V66VVFVBr’æÆVæwF‚À¢·&Wõ66ç5Ð¢“° ¢6öç7B÷Väf–æF–æt6÷VçBÒW6TÖVÖò€¢‚’Óà¢&Wôf–æF–æu7VÖÖ'“òçF÷FÅö÷Vâóð¢f–ÇFW&VDf–æF–æw2æf–ÇFW"‚†f–æF–ær’Óâ°¢6öç7BÆ–fV7–6ÆRÒæ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2“°¢&WGW&âÆ–fV7–6ÆRÓÓÒv÷VârÇÂÆ–fV7–6ÆRÓÓÒw&V÷VæVBs°¢Ò’æÆVæwF‚À¢¶f–ÇFW&VDf–æF–æw2Â&Wôf–æF–æu7VÖÖ'“òçF÷FÅö÷VåÐ¢“° ¢6öç7B6ÆvVDf–æF–æt6÷VçBÒ&Wôf–æF–æu7VÖÖ'“òç6ÆövVEö6÷VçBóò°¢6öç7B×GG%6V6öæG2Ò&Wôf–æF–æu7VÖÖ'“òæÖVå÷F–ÖU÷Fõ÷&W6öÇfU÷6V6öæG3°¢6öç7B×GG$Æ&VÂÒG—Vöb×GG%6V6öæG2ÓÓÒvçVÖ&W"rbbçVÖ&W"æ—4f–æ—FR†×GG%6V6öæG2’òf÷&ÖDW†V7WF—fTGW&F–öâ†×GG%6V6öæG2’¢tâôs°¢6öç7B6äFVÆWFU&Wôf–æF–æw2Ò†5&Wôf–æF–ætFVÆWFT66W72†ÖR“°¢6öç7B6å&VÖ÷fTf–ÆVE&Wõ66ç2Ò6äFVÆWFU&Wôf–æF–æw3°¢6öç7B7F—fTFVÆWFT6æF–FFW2Ò'VÆ´FVÆWFT6æF–FFW2æÆVæwF‚â ¢ò'VÆ´FVÆWFT6æF–FFW0¢¢FVÆWFT6æF–FFP¢ò¶FVÆWFT6æF–FFUÐ¢¢µÓ°¢6öç7B'VÆ´FVÆWFT7F—fRÒ'VÆ´FVÆWFT6æF–FFW2æÆVæwF‚â°¢6öç7BFVÆWFT7F–öç4F—6&ÆVBÒFVÆWFTÆöF–ærÇÂ&Vg&W6†–ærÇÂ6–væÇ5&Vg&W6†–æs° ¢6öç7BÆöE&Wôf–æF–æw2Ò7–æ2€¢F&vWE66÷S¢&öGV7E6W76–öâÀ¢ÖöFS¢v–æ—F–ÂrÂw&Vg&W6‚rÀ¢÷fW'&–FW3ó¢'F–ÃÅ&Wôf–æF–ætf–ÇFW%6æ6†÷Cà¢’Óâ°¢6öç7B&WVW7D”BÒ²·&WVW7E&Vbæ7W'&VçC°¢–b†ÖöFRÓÓÒv–æ—F–Âr’°¢6WDÆöF–ær‡G'VR“°¢ÒVÇ6R°¢6WE&Vg&W6†–ær‡G'VR“°¢Ð¢6WDW'&÷"‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡F&vWE66÷R“°¢6öç7Bf–ÇFW'2Ò²ââç&Wôf–æF–ætf–ÇFW%&Vbæ7W'&VçBÂââæ÷fW'&–FW2Ó°¢6öç7B6÷W&6Tf–ÇFW%fÇVRÒæ÷&ÖÆ—¦UfÇVR†f–ÇFW'2ç6÷W&6Tf–ÇFW"’çFôÆ÷vW$66R‚“°¢6öç7Bæ÷&ÖÆ—¦VDÖ–ä6öæf–FVæ6RÒçVÖ&W"ç'6TfÆöB†æ÷&ÖÆ—¦UfÇVR†f–ÇFW'2æÖ–ä6öæf–FVæ6Tf–ÇFW"’“°¢6öç7B&Wôf–æF–æu&WVW7BÒ°¢&Wõ÷66åö–C¢æ÷&ÖÆ—¦UfÇVR†f–ÇFW'2ç&Wõ66äf–ÇFW"’ÇÂVæFVf–æVBÀ¢6WfW&—G“¢f–ÇFW'2ç6WfW&—G”f–ÇFW"ÓÒvÆÂròf–ÇFW'2ç6WfW&—G”f–ÇFW"¢VæFVf–æVBÀ¢G—S¢f–ÇFW'2çG—Tf–ÇFW"ÓÒvÆÂròf–ÇFW'2çG—Tf–ÇFW"¢VæFVf–æVBÀ¢6÷W&6S¢6÷W&6Tf–ÇFW%fÇVRÇÂVæFVf–æVBÀ¢76–væVS¢æ÷&ÖÆ—¦UfÇVR†f–ÇFW'2æ76–væVTf–ÇFW"’ÇÂVæFVf–æVBÀ¢Ö–åö6öæf–FVæ6S¢çVÖ&W"æ—4f–æ—FR†æ÷&ÖÆ—¦VDÖ–ä6öæf–FVæ6R’òæ÷&ÖÆ—¦VDÖ–ä6öæf–FVæ6R¢VæFVf–æVBÀ¢6÷'Eö'“¢f–ÇFW'2ç6÷'D'’À¢6÷'Eö÷&FW#¢f–ÇFW'2ç6÷'D÷&FW ¢Ó° ¢6öç7B·&Wõ66å&W7öç6RÂ&Wôf–æF–æu&W7öç6UÒÒv—B&öÖ—6RæÆÂ…°¢”6Æ–VçBæÆ—7E&Wõ66ç2‡²Æ–Ö—C¢SÒÂWF‚’À¢vVçF–4öæÇ¢òÆ—7D•&—6·5&Wôf–æF–æw2†WF‚Â&Wôf–æF–æu&WVW7B¢¢”6Æ–VçBæÆ—7E&Wôf–æF–æw2€¢°¢ââç&Wôf–æF–æu&WVW7BÀ¢Æ–Ö—C¢À¢Æ–fV7–6ÆU÷7FGW3¢f–ÇFW'2ç7FGW4f–ÇFW"ÓÒvÆÂròf–ÇFW'2ç7FGW4f–ÇFW"¢VæFVf–æV@¢ÒÀ¢WF€¢¢Ò“°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE&Wõ66ç2‡&Wõ66å&W7öç6Ræ—FV×2“°¢–b†vVçF–4öæÇ’’°¢–b‚'&’æ—4'&’‡&Wôf–æF–æu&W7öç6R’’°¢&WGW&ã°¢Ð¢6WE&Wôf–æF–æw2‡&Wôf–æF–æu&W7öç6R“°¢6WE&Wôf–æF–æu7VÖÖ'’†çVÆÂ“°¢ÒVÇ6R°¢–b„'&’æ—4'&’‡&Wôf–æF–æu&W7öç6R’’°¢&WGW&ã°¢Ð¢6WE&Wôf–æF–æw2‡&Wôf–æF–æu&W7öç6Ræ—FV×2“°¢6WE&Wôf–æF–æu7VÖÖ'’‡&Wôf–æF–æu&W7öç6Rç7VÖÖ'’óòçVÆÂ“°¢Ð¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‡&WVW7D”BÓÒ&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WDW'&÷"†f÷&ÖD”W'&÷"‡&WVW7DW'&÷"Âtf–ÆVBFòÆöB&W÷6—F÷'’f–æF–æw2âr’“°¢Òf–æÆÇ’°¢–b‡&WVW7D”BÓÓÒ&WVW7E&Vbæ7W'&VçB’°¢6WDÆöF–ær†fÇ6R“°¢6WE&Vg&W6†–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢6öç7BÆöEG&VæE6–væÇ2Ò7–æ2€¢F&vWE66÷S¢&öGV7E6W76–öâÀ¢ÖöFS¢v–æ—F–ÂrÂw&Vg&W6‚rÀ¢÷fW'&–FW3ó¢'F–ÃÅ&Wôf–æF–ætf–ÇFW%6æ6†÷Cà¢’Óâ°¢6öç7B&WVW7D”BÒ²·6–væÅ&WVW7E&Vbæ7W'&VçC°¢–b†ÖöFRÓÓÒv–æ—F–Âr’°¢6WE6–væÇ4ÆöF–ær‡G'VR“°¢ÒVÇ6R°¢6WE6–væÇ5&Vg&W6†–ær‡G'VR“°¢Ð¢6WE6–væÄW'&÷"‚rr“°¢6WEG&VæDW'&÷"‚rr“°¢6WE&—6´w&„W'&÷"‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡F&vWE66÷R“°¢6öç7Bf–ÇFW'2Ò²ââç&Wôf–æF–ætf–ÇFW%&Vbæ7W'&VçBÂââæ÷fW'&–FW2Ó°¢6öç7B6WfW&—G’Òf–ÇFW'2ç6WfW&—G”f–ÇFW"ÓÒvÆÂròf–ÇFW'2ç6WfW&—G”f–ÇFW"¢VæFVf–æVC°¢6öç7BG—RÒf–ÇFW'2çG—Tf–ÇFW"ÓÒvÆÂròf–ÇFW'2çG—Tf–ÇFW"¢VæFVf–æVC°¢6öç7B&Wõ66ä”BÒæ÷&ÖÆ—¦UfÇVR†f–ÇFW'2ç&Wõ66äf–ÇFW"’ÇÂVæFVf–æVC°¢6öç7Bæ÷&ÖÆ—¦VDÖ–ä6öæf–FVæ6RÒçVÖ&W"ç'6TfÆöB†æ÷&ÖÆ—¦UfÇVR†f–ÇFW'2æÖ–ä6öæf–FVæ6Tf–ÇFW"’“°¢6öç7BÖ–ä6öæf–FVæ6RÒçVÖ&W"æ—4f–æ—FR†æ÷&ÖÆ—¦VDÖ–ä6öæf–FVæ6R’òæ÷&ÖÆ—¦VDÖ–ä6öæf–FVæ6R¢VæFVf–æVC°¢6öç7B·G&VæE&W7VÇBÂ&—6´w&…&W7VÇEÒÒv—B&öÖ—6RæÆÅ6WGFÆVB…°¢”6Æ–VçBævWE&Wôf–æF–æw5G&VæG2€¢°¢ö–çG3¢E$TäEõô”åE2À¢6WfW&—G’À¢G—RÀ¢Ö–åö6öæf–FVæ6S¢Ö–ä6öæf–FVæ6P¢ÒÀ¢WF€¢’À¢”6Æ–VçBævWE&Wõ&—6´w&‚€¢°¢&Wõ÷66åö–C¢&Wõ66ä”BÀ¢6WfW&—G’À¢G—RÀ¢Ö–åö6öæf–FVæ6S¢Ö–ä6öæf–FVæ6P¢ÒÀ¢WF€¢¢Ò“°¢–b‡&WVW7D”BÓÒ6–væÅ&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢–b‡G&VæE&W7VÇBç7FGW2ÓÓÒvgVÆf–ÆÆVBr’°¢6WEG&VæEö–çG2‡G&VæE&W7VÇBçfÇVRæ—FV×2“°¢ÒVÇ6R°¢6WEG&VæEö–çG2…µÒ“°¢6WEG&VæDW'&÷"€¢G&VæE&W7VÇBç&V6öâ–ç7Fæ6VöbW'&÷"òG&VæE&W7VÇBç&V6öâæÖW76vR¢tf–ÆVBFòÆöBf–æF–ærG&VæBÖWG&–72âp¢“°¢Ð¢–b‡&—6´w&…&W7VÇBç7FGW2ÓÓÒvgVÆf–ÆÆVBr’°¢6WE&Wõ&—6´w&‚‡&—6´w&…&W7VÇBçfÇVR“°¢ÒVÇ6R°¢6WE&Wõ&—6´w&‚†çVÆÂ“°¢6WE&—6´w&„W'&÷"€¢&—6´w&…&W7VÇBç&V6öâ–ç7Fæ6VöbW'&÷ ¢ò&—6´w&…&W7VÇBç&V6öâæÖW76vP¢¢tf–ÆVBFòÆöB&W÷6—F÷'’&—6²w&‚âp¢“°¢Ð¢Òf–æÆÇ’°¢–b‡&WVW7D”BÓÓÒ6–væÅ&WVW7E&Vbæ7W'&VçB’°¢6WE6–væÇ4ÆöF–ær†fÇ6R“°¢6WE6–væÇ5&Vg&W6†–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢6öç7B–çfÆ–FFTf–æF–ætFVÆWFU7FFRÒ‚’Óâ°¢f–æDFVÆWFU&WVW7E&Vbæ7W'&VçB³Ò°¢6WDf–æF–ætÖVçT¶W’‚rr“°¢6WDFVÆWFT6æF–FFR†çVÆÂ“°¢6WD'VÆ´FVÆWFT6æF–FFW2…µÒ“°¢6WDFVÆWFTÆöF–ær†fÇ6R“°¢6WDFVÆWFTW'&÷"‚rr“°¢Ó° ¢6öç7B&WVW7DFVÆWFTf–æF–ærÒ†f–æF–æs¢”f–æF–ærÂ÷VæW#¢…DÔÄVÆVÖVçBÂçVÆÂÒçVÆÂ’Óâ°¢–b†FVÆWFT7F–öç4F—6&ÆVB’°¢6WDf–æF–ætÖVçT¶W’‚rr“°¢&WGW&ã°¢Ð¢6WDf–æF–ætÖVçT¶W’‚rr“°¢6WDFVÆWFT6æF–FFR†f–æF–ær“°¢6WD'VÆ´FVÆWFT6æF–FFW2…µÒ“°¢6WDFVÆWFTW'&÷"‚rr“°¢f–æF–ætFVÆWFT÷VæW%&Vbæ7W'&VçBÐ¢÷VæW"óð¢‡G—VöbFö7VÖVçBÓÒwVæFVf–æVBrbbFö7VÖVçBæ7F—fTVÆVÖVçB–ç7Fæ6Vöb…DÔÄVÆVÖVç@¢òFö7VÖVçBæ7F—fTVÆVÖVç@¢¢çVÆÂ“°¢Ó° ¢6öç7B&WVW7DFVÆWFTÆÅf—6–&ÆTf–æF–æw2Ò†÷VæW#¢…DÔÄVÆVÖVçBÂçVÆÂÒçVÆÂ’Óâ°¢–b†FVÆWFT7F–öç4F—6&ÆVBÇÂf–ÇFW&VDf–æF–æw2æÆVæwF‚ÓÓÒ’°¢&WGW&ã°¢Ð¢6WDf–æF–ætÖVçT¶W’‚rr“°¢6WDFVÆWFT6æF–FFR†çVÆÂ“°¢6WD'VÆ´FVÆWFT6æF–FFW2†f–ÇFW&VDf–æF–æw2“°¢6WDFVÆWFTW'&÷"‚rr“°¢f–æF–ætFVÆWFT÷VæW%&Vbæ7W'&VçBÐ¢÷VæW"óð¢‡G—VöbFö7VÖVçBÓÒwVæFVf–æVBrbbFö7VÖVçBæ7F—fTVÆVÖVçB–ç7Fæ6Vöb…DÔÄVÆVÖVç@¢òFö7VÖVçBæ7F—fTVÆVÖVç@¢¢çVÆÂ“°¢Ó° ¢6öç7BÇ”FVÆWFVE&Wôf–æF–æw2Ò†FVÆWFVDf–æF–æw3¢”f–æF–æuµÒ’Óâ°¢–b†FVÆWFVDf–æF–æw2æÆVæwF‚ÓÓÒ’°¢&WGW&ã°¢Ð¢6öç7BFVÆWFVD¶W—2ÒæWr6WB†FVÆWFVDf–æF–æw2æÖ†'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’’“°¢6öç7BFVÆWFT6÷VçG4'•66âÒFVÆWFVDf–æF–æw2ç&VGV6SÄÖÇ7G&–ærÂçVÖ&W#ãâ‚†62Âf–æF–ær’Óâ°¢62ç6WB†f–æF–ærç66åö–BÂ†62ævWB†f–æF–ærç66åö–B’óò’²“°¢&WGW&â63°¢ÒÂæWrÖ‚’“°¢6WE&Wôf–æF–æw2‚†7W'&VçB’Óâ7W'&VçBæf–ÇFW"‚†f–æF–ær’ÓâFVÆWFVD¶W—2æ†2†'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’†f–æF–ær’’’“°¢6WE&Wõ66ç2‚†7W'&VçB’Óà¢7W'&VçBæÖ‚‡66â’Óâ°¢6öç7BFVÆWFVD6÷VçBÒFVÆWFT6÷VçG4'•66âævWB‡66âæ–B’óò°¢–b†FVÆWFVD6÷VçBÓÓÒ’°¢&WGW&â66ã°¢Ð¢&WGW&â²ââç66âÂf–æF–æuö6÷VçC¢ÖF‚æÖ‚ƒÂ‡66âæf–æF–æuö6÷VçBóò’ÒFVÆWFVD6÷VçB’Ó°¢Ò¢“°¢6WE&Wôf–æF–æu7VÖÖ'’‚†7W'&VçB’ÓâFV7&VÖVçE&Wôf–æF–æw57VÖÖ'”f÷$FVÆWFVDf–æF–æw2†7W'&VçBÂFVÆWFVDf–æF–æw2’“°¢–b‡6VÆV7FVDf–æF–æt¶W’bbFVÆWFVD¶W—2æ†2‡6VÆV7FVDf–æF–æt¶W’’’°¢6WE6VÆV7FVDf–æF–æt¶W’‚rr“°¢6WDf–æF–ætFWF–Ä÷Vâ†fÇ6R“°¢f–æF–ætFWF–Ä÷VæW%&Vbæ7W'&VçBÒçVÆÃ°¢Ð¢Ó° ¢6öç7BÇ”f–ÆVE&Wôf–æF–ætFVÆWFW2Ò€¢f–ÆVD6æF–FFW3¢”f–æF–æuµÒÀ¢FVÆWFVD6÷VçC¢çVÖ&W"À¢fÆÆ&6²Òtf–ÆVBFòFVÆWFRf–æF–ærârÀ¢¶VW'VÆ´6öçFW‡BÒfÇ6P¢’Óâ°¢6WD'VÆ´FVÆWFT6æF–FFW2†¶VW'VÆ´6öçFW‡Bòf–ÆVD6æF–FFW2¢f–ÆVD6æF–FFW2æÆVæwF‚âòf–ÆVD6æF–FFW2¢µÒ“°¢6WDFVÆWFT6æF–FFR†¶VW'VÆ´6öçFW‡BòçVÆÂ¢f–ÆVD6æF–FFW2æÆVæwF‚ÓÓÒòf–ÆVD6æF–FFW5³Ò¢çVÆÂ“°¢6WDFVÆWFTW'&÷"€¢FVÆWFVD6÷VçBâ ¢òG¶FVÆWFVD6÷VçGÒFVÆWFVBâG¶f–ÆVD6æF–FFW2æÆVæwF‡Ò&VÖ–æ–æræ ¢¢fÆÆ&6°¢“°¢Ó° ¢6öç7B†æFÆT6öæf—&ÔFVÆWFTf–æF–ærÒ7–æ2‚’Óâ°¢–b‚66÷RÇÂ7F—fTFVÆWFT6æF–FFW2æÆVæwF‚ÓÓÒÇÂFVÆWFT7F–öç4F—6&ÆVB’°¢&WGW&ã°¢Ð¢6öç7B6æF–FFW2Ò7F—fTFVÆWFT6æF–FFW3°¢6öç7B&WVW7D”BÒ²¶f–æDFVÆWFU&WVW7E&Vbæ7W'&VçC°¢6WDFVÆWFTÆöF–ær‡G'VR“°¢6WDFVÆWFTW'&÷"‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢ÆWBFVÆWFVDf–æF–æw3¢”f–æF–æuµÒÒµÓ°¢ÆWBf–ÆVD6æF–FFW3¢”f–æF–æuµÒÒµÓ°¢ÆWBf–ÇW&TÖW76vRÒtf–ÆVBFòFVÆWFRf–æF–ærâs°¢–b†'VÆ´FVÆWFT7F—fR’°¢6öç7B²&W7öç6RÂW'&÷$ÖW76vRÒÒv—BFVÆWFU&Wôf–æF–æuF&vWG5v—F„'VÆ´VæGö–çB€¢6æF–FFW2æÖ‡&Wôf–æF–ætFVÆWFUF&vWDg&öÔf–æF–ær’À¢WF€¢“°¢6öç7BFVÆWFVD¶W—2ÒæWr6WB‡&W7öç6RæFVÆWFVBæÖ‡&Wôf–æF–ætFVÆWFUF&vWD¶W’’“°¢6öç7Bf–ÆVD¶W—2ÒæWr6WB‚‡&W7öç6Ræf–ÆVBóòµÒ’æÖ‡&Wôf–æF–ætFVÆWFUF&vWD¶W’’“°¢FVÆWFVDf–æF–æw2Ò6æF–FFW2æf–ÇFW"‚†6æF–FFR’Óà¢FVÆWFVD¶W—2æ†2‡&Wôf–æF–ætFVÆWFUF&vWD¶W”g&öÔf–æF–ær†6æF–FFR’¢“°¢f–ÆVD6æF–FFW2Ò6æF–FFW2æf–ÇFW"‚†6æF–FFR’Óâ°¢6öç7B¶W’Ò&Wôf–æF–ætFVÆWFUF&vWD¶W”g&öÔf–æF–ær†6æF–FFR“°¢&WGW&âf–ÆVD¶W—2æ†2†¶W’’ÇÂFVÆWFVD¶W—2æ†2†¶W’“°¢Ò“°¢f–ÇW&TÖW76vRÒ&W7öç6Ræf–ÆVCòå³ÓòæW'&÷"ÇÂW'&÷$ÖW76vRÇÂf–ÇW&TÖW76vS°¢ÒVÇ6R°¢6öç7B6æF–FFRÒ6æF–FFW5³Ó°¢–b†6æF–FFR’°¢v—B”6Æ–VçBæFVÆWFU&Wôf–æF–ær†6æF–FFRæ–BÂ6æF–FFRç66åö–BÂWF‚“°¢FVÆWFVDf–æF–æw2Ò¶6æF–FFUÓ°¢Ð¢Ð¢–b†f–æDFVÆWFU&WVW7E&Vbæ7W'&VçBÓÒ&WVW7D”B’°¢&WGW&ã°¢Ð¢–b†FVÆWFVDf–æF–æw2æÆVæwF‚â’°¢–çfÆ–FFTv—D‡V$FöÖ–äFF66†Tf÷%66÷R‡66÷R“°¢Ç”FVÆWFVE&Wôf–æF–æw2†FVÆWFVDf–æF–æw2“°¢Ð¢–b†f–ÆVD6æF–FFW2æÆVæwF‚â’°¢Ç”f–ÆVE&Wôf–æF–ætFVÆWFW2†f–ÆVD6æF–FFW2ÂFVÆWFVDf–æF–æw2æÆVæwF‚Âf–ÇW&TÖW76vRÂ'VÆ´FVÆWFT7F—fR“°¢–b†FVÆWFVDf–æF–æw2æÆVæwF‚â’°¢v—BÆöE&Wôf–æF–æw2‡66÷RÂw&Vg&W6‚r“°¢v—BÆöEG&VæE6–væÇ2‡66÷RÂw&Vg&W6‚r“°¢Ð¢&WGW&ã°¢Ð¢v—BÆöE&Wôf–æF–æw2‡66÷RÂw&Vg&W6‚r“°¢v—BÆöEG&VæE6–væÇ2‡66÷RÂw&Vg&W6‚r“°¢6Æ÷6Tf–æF–ætFVÆWFTF–Æör‡²ÆÆ÷tGW&–ætÆöF–æs¢G'VRÒ“°¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b†f–æDFVÆWFU&WVW7E&Vbæ7W'&VçBÓÒ&WVW7D”B’°¢&WGW&ã°¢Ð¢6WDFVÆWFTW'&÷"‡&WVW7DW'&÷"–ç7Fæ6VöbW'&÷"ò&WVW7DW'&÷"æÖW76vR¢tf–ÆVBFòFVÆWFRf–æF–ærâr“°¢Òf–æÆÇ’°¢–b†f–æDFVÆWFU&WVW7E&Vbæ7W'&VçBÓÓÒ&WVW7D”B’°¢6WDFVÆWFTÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢6öç7B&VÆöE&Wôf–æF–æw2Ò7–æ2‡F&vWE66÷S¢&öGV7E6W76–öâÂÖöFS¢v–æ—F–ÂrÂw&Vg&W6‚r’Óâ°¢–çfÆ–FFTf–æF–ætFVÆWFU7FFR‚“°¢v—BÆöE&Wôf–æF–æw2‡F&vWE66÷RÂÖöFR“°¢Ó° ¢6öç7B†æFÆTÆöE&VÖVF–F–öå&Wf–WrÒ7–æ2‚’Óâ°¢–b‚66÷RÇÂ6VÆV7FVDf–æF–ærÇÂ&VÖVF–F–öå&Wf–WtÆöF–ær’°¢&WGW&ã°¢Ð ¢6öç7B6VÆV7F–öä¶W’Ò'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’‡6VÆV7FVDf–æF–ær“°¢6öç7B&WVW7D”BÒ²·&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçC°¢6WE&VÖVF–F–öå&Wf–WtÆöF–ær‡G'VR“°¢6WE&VÖVF–F–öå&Wf–WtW'&÷"‚rr“°¢6WE&VÖVF–F–öå&Wf–Wr†çVÆÂ“°¢6WE&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’‡6VÆV7F–öä¶W’“°¢G'’°¢6öç7B6÷W&6T6öçFVçBÒ&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçBçG&–Ò‚“°¢6öç7B&Wf–Wu&WVW7BÒ°¢&Wõ÷66åö–C¢6VÆV7FVDf–æF–ærç66åö–BÀ¢âââ‡6÷W&6T6öçFVç@¢ò°¢6÷W&6Uö6öçFVçC¢6÷W&6T6öçFVçBÀ¢&WV—&Uöf—…÷Æã¢G'VP¢Ð¢¢·Ò¢Ó°¢6öç7B&Wf–WrÒv—B”6Æ–VçBç&Wf–Wu&Wôf–æF–æu&VÖVF–F–öâ€¢6VÆV7FVDf–æF–æræ–BÀ¢&Wf–Wu&WVW7BÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢–b‡&WVW7D”BÓÒ&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE&VÖVF–F–öå&Wf–Wr‡&Wf–Wr“°¢6WE&VÖVF–F–öåV&Æ—6„&6T'&æ6‚‡&Wf–Wræf—…÷%÷Æãòæ&6Uö'&æ6‚ÇÂ&VÖVF–F–öåV&Æ—6„&6T'&æ6‚ÇÂvÖ–âr“°¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‡&WVW7D”BÓÒ&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE&VÖVF–F–öå&Wf–Wr†çVÆÂ“°¢6WE&VÖVF–F–öå&Wf–WtW'&÷"€¢&WVW7DW'&÷"–ç7Fæ6VöbW'&÷"ò&WVW7DW'&÷"æÖW76vR¢tf–ÆVBFòÆöB&VÖVF–F–öâ&Wf–Wrâp¢“°¢Òf–æÆÇ’°¢–b‡&WVW7D”BÓÓÒ&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB’°¢6WE&VÖVF–F–öå&Wf–WtÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢6öç7B&W6WE&VÖVF–F–öåV&Æ—6…7FFRÒ‚’Óâ°¢6WE&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçB‚rr“°¢6WE&VÖVF–F–öåV&Æ—6„&6T'&æ6‚‚vÖ–âr“°¢6WE&VÖVF–F–öåV&Æ—6…Fö¶Vâ‚rr“°¢6WE&VÖVF–F–öåV&Æ—6„&÷fVB†fÇ6R“°¢6WE&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVB†fÇ6R“°¢6WE&VÖVF–F–öåV&Æ—6„ÆöF–ær†fÇ6R“°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚rr“°¢6WE&VÖVF–F–öåV&Æ—6…&W7VÇB†çVÆÂ“°¢Ó° ¢òò6†æv–ær†÷"6ÆV&–ær’F†R6VÆV7FVBf–æF–ær×W7B–çfÆ–FFRç’–âÖfÆ–v‡@¢òò&VÖVF–F–öâ&Wf–Wr÷V&Æ—6‚&WVW7G27–æ6‡&öæ÷W6Ç’ÂöâF†RG&ç6—F–öà¢òò—G6VÆbÂ6ò6Æ÷r&W7öç6R6ææ÷BÆæBöâæWvÇ’6VÆV7FVBf–æF–ærâ'V×–æp¢òòF†RwV&G2†W&R6Æ÷6W2F†R&6Rv–æF÷rF†BW†—7G2–b–çfÆ–FF–öâ—2ÆVg@¢òòFò÷7B×&VæFW"VffV7Bà¢6öç7B6VÆV7E&Wôf–æF–ærÒ†¶W“¢7G&–ærÂ÷VäFWF–ÂÒG'VRÂ÷VæW#¢…DÔÄVÆVÖVçBÂçVÆÂÒçVÆÂ’Óâ°¢&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB³Ò°¢&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçB³Ò°¢6WDf–æF–ætÖVçT¶W’‚rr“°¢6öç7Bv–ÆÄ÷VäF–ÆörÒ&ööÆVâ†¶W’’bb÷VäFWF–Ã°¢–b‡v–ÆÄ÷VäF–Æör’°¢f–æF–ætFWF–Ä÷VæW%&Vbæ7W'&VçBÐ¢÷VæW"óð¢‡G—VöbFö7VÖVçBÓÒwVæFVf–æVBrbbFö7VÖVçBæ7F—fTVÆVÖVçB–ç7Fæ6Vöb…DÔÄVÆVÖVç@¢òFö7VÖVçBæ7F—fTVÆVÖVç@¢¢çVÆÂ“°¢Ð¢6WE6VÆV7FVDf–æF–æt¶W’†¶W’“°¢6WDf–æF–ætFWF–Ä÷Vâ‡v–ÆÄ÷VäF–Æör“°¢Ó° ¢6öç7B†æFÆUV&Æ—6…&VÖVF–F–öâÒ7–æ2‚’Óâ°¢–b‚66÷RÇÂ6VÆV7FVDf–æF–ærÇÂ7F—fU&VÖVF–F–öå&Wf–WrÇÂ&VÖVF–F–öåV&Æ—6„ÆöF–ær’°¢&WGW&ã°¢Ð ¢6öç7B6÷W&6T6öçFVçBÒ&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçC°¢6öç7BFö¶VâÒ&VÖVF–F–öåV&Æ—6…Fö¶VâçG&–Ò‚“°¢–b‚6÷W&6T6öçFVçBçG&–Ò‚’’°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚t7W'&VçB6÷W&6R6öçFVçB—2&WV—&VBâr“°¢&WGW&ã°¢Ð¢–b‚&VÖVF–F–öåV&Æ—6„&÷fVB’°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚t÷W&F÷"&÷fÂ—2&WV—&VBâr“°¢&WGW&ã°¢Ð¢–b‚&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVB’°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚t6öæf—&ÒF†Rv—D‡V"Fö¶Vâ—2–çFVçF–öæÆÇ’w&—FRÖ6&ÆRâr“°¢&WGW&ã°¢Ð¢–b‚Fö¶Vâ’°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚tw&—FRÖ6&ÆRv—D‡V"Fö¶Vâ—2&WV—&VBâr“°¢&WGW&ã°¢Ð ¢òòF†R6VÆV7F–öâÖ6†ævRVffV7B'V×2&VÖVF–F–öåV&Æ—6…&WVW7E&VbÂ6ò¢òòf–æF–ær÷66÷R7v—F6‚†÷"æWvW"V&Æ—6‚’–çfÆ–FFW2F†—2&WVW7Bà¢6öç7B&WVW7D”BÒ²·&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçC°¢6öç7B—57FÆRÒ‚’Óâ&WVW7D”BÓÒ&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçC°¢6WE&VÖVF–F–öåV&Æ—6„ÆöF–ær‡G'VR“°¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"‚rr“°¢6WE&VÖVF–F–öåV&Æ—6…&W7VÇB†çVÆÂ“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBçV&Æ—6…&Wôf–æF–æu&VÖVF–F–öâ€¢6VÆV7FVDf–æF–æræ–BÀ¢°¢&Wõ÷66åö–C¢6VÆV7FVDf–æF–ærç66åö–BÀ¢6÷W&6Uö6öçFVçC¢6÷W&6T6öçFVçBÀ¢&6Uö'&æ6ƒ¢&VÖVF–F–öåV&Æ—6„&6T'&æ6‚çG&–Ò‚’ÇÂVæFVf–æVBÀ¢f–æF–æu÷W&Ã¢6VÆV7FVDf–æF–ærç6÷W&6U÷W&ÂÇÂVæFVf–æVBÀ¢÷W&F÷%ö&÷fVC¢&VÖVF–F–öåV&Æ—6„&÷fVBÀ¢w&—FU÷W&Ö—76–öç5ö6öæf–wW&VC¢&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVBÀ¢v—F‡V%÷Fö¶Vã¢Fö¶Và¢ÒÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢–b†—57FÆR‚’’°¢&WGW&ã°¢Ð¢6WE&VÖVF–F–öåV&Æ—6…&W7VÇB‡&W7öç6R“°¢6WE&VÖVF–F–öåV&Æ—6…Fö¶Vâ‚rr“°¢6WE&VÖVF–F–öåV&Æ—6„&÷fVB†fÇ6R“°¢6WE&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVB†fÇ6R“°¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b†—57FÆR‚’’°¢&WGW&ã°¢Ð¢6WE&VÖVF–F–öåV&Æ—6„W'&÷"€¢&WVW7DW'&÷"–ç7Fæ6VöbW'&÷"ò&WVW7DW'&÷"æÖW76vR¢tf–ÆVBFòV&Æ—6‚&VÖVF–F–öâ"âp¢“°¢Òf–æÆÇ’°¢–b‡&WVW7D”BÓÓÒ&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçB’°¢6WE&VÖVF–F–öåV&Æ—6„ÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢W6TVffV7B‚‚’Óâ°¢f–ÆVE66å&VÖ÷fU&WVW7E&Vbæ7W'&VçB³Ò°¢6WE&VÖ÷f–ætf–ÆVE66ä”B‚rr“°¢ÒÂ·66÷T¶W•Ò“° ¢W6TVffV7B‚‚’Óâ°¢–b‚66÷R’°¢6WDÆöF–ær†fÇ6R“°¢6WDW'&÷"‚uv÷&·76R&÷WFR6öçFW‡B—2Ö—76–ærâr“°¢&WGW&ã°¢Ð¢fö–B&VÆöE&Wôf–æF–æw2‡66÷RÂv–æ—F–Âr“°¢fö–BÆöEG&VæE6–væÇ2‡66÷RÂv–æ—F–Âr“°¢&WGW&â‚’Óâ°¢&WVW7E&Vbæ7W'&VçB³Ò°¢6–væÅ&WVW7E&Vbæ7W'&VçB³Ò°¢Ó°¢ÒÂ°¢66÷SòçFVæçD”BÀ¢66÷Sòçv÷&·76T”BÀ¢&Wõ66äf–ÇFW"À¢6WfW&—G”f–ÇFW"À¢G—Tf–ÇFW"À¢7FGW4f–ÇFW"À¢76–væVTf–ÇFW"À¢6÷W&6Tf–ÇFW"À¢Ö–ä6öæf–FVæ6Tf–ÇFW"À¢6÷'D'’À¢6÷'D÷&FW ¢Ò“° ¢W6TVffV7B‚‚’Óâ°¢–b‚6VÆV7FVDf–æF–ær’°¢&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB³Ò°¢&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçB³Ò°¢6WE&VÖVF–F–öå&Wf–Wr†çVÆÂ“°¢6WE&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’‚rr“°¢6WE&VÖVF–F–öå&Wf–WtÆöF–ær†fÇ6R“°¢6WE&VÖVF–F–öå&Wf–WtW'&÷"‚rr“°¢&W6WE&VÖVF–F–öåV&Æ—6…7FFR‚“°¢&WGW&ã°¢Ð ¢&VÖVF–F–öå&Wf–Wu&WVW7E&Vbæ7W'&VçB³Ò°¢&VÖVF–F–öåV&Æ—6…&WVW7E&Vbæ7W'&VçB³Ò°¢6WE&VÖVF–F–öå&Wf–Wr†çVÆÂ“°¢6WE&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’‚rr“°¢6WE&VÖVF–F–öå&Wf–WtÆöF–ær†fÇ6R“°¢6WE&VÖVF–F–öå&Wf–WtW'&÷"‚rr“°¢&W6WE&VÖVF–F–öåV&Æ—6…7FFR‚“°¢ÒÂ°¢6VÆV7FVDf–æF–æsòæ–BÀ¢6VÆV7FVDf–æF–æsòç66åö–@¢Ò“° ¢W6TVffV7B‚‚’Óâ°¢–b†f–ÇFW&VDf–æF–æw2æÆVæwF‚ÓÓÒ’°¢–b‡6VÆV7FVDf–æF–æt¶W’’°¢6VÆV7E&Wôf–æF–ær‚rrÂfÇ6R“°¢Ð¢&WGW&ã°¢Ð¢–b‡6VÆV7FVDf–æF–æt¶W’bbf–æE&Wôf–æF–æt'•6VÆV7F–öä¶W’†f–ÇFW&VDf–æF–æw2Â6VÆV7FVDf–æF–æt¶W’’’°¢6VÆV7E&Wôf–æF–ær‚rrÂfÇ6R“°¢Ð¢ÒÂ¶f–ÇFW&VDf–æF–æw2Â6VÆV7FVDf–æF–æt¶W•Ò“° ¢W6TVffV7B‚‚’Óâ°¢–b‚f–æF–ætFWF–Ä÷VâÇÂG—VöbFö7VÖVçBÓÓÒwVæFVf–æVBr’°¢&WGW&âVæFVf–æVC°¢Ð¢6öç7B&ö÷BÒFö7VÖVçBæFö7VÖVçDVÆVÖVçC°¢6öç7B&Wf–÷W4÷fW&fÆ÷rÒ&ö÷Bç7G–ÆRæ÷fW&fÆ÷s°¢&ö÷Bç7G–ÆRæ÷fW&fÆ÷rÒv†–FFVâs°¢&WGW&â‚’Óâ°¢&ö÷Bç7G–ÆRæ÷fW&fÆ÷rÒ&Wf–÷W4÷fW&fÆ÷s°¢Ó°¢ÒÂ¶f–æF–ætFWF–Ä÷VåÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚f–æF–ætFWF–Ä÷VâÇÂG—Vöbv–æF÷rÓÓÒwVæFVf–æVBr’°¢&WGW&âVæFVf–æVC°¢Ð¢6öç7Bg&ÖRÒv–æF÷rç&WVW7Dæ–ÖF–öäg&ÖR‚‚’Óâ°¢f–æF–ætFWF–Ä6Æ÷6U&Vbæ7W'&VçCòæfö7W2‚“°¢Ò“°¢&WGW&â‚’Óâv–æF÷ræ6æ6VÄæ–ÖF–öäg&ÖR†g&ÖR“°¢ÒÂ¶f–æF–ætFWF–Ä÷VâÂ6VÆV7FVDf–æF–æt¶W•Ò“° ¢W6TVffV7B‚‚’Óâ°¢–b†7F—fTFVÆWFT6æF–FFW2æÆVæwF‚ÓÓÒÇÂG—VöbFö7VÖVçBÓÓÒwVæFVf–æVBr’°¢&WGW&âVæFVf–æVC°¢Ð¢6öç7B&ö÷BÒFö7VÖVçBæFö7VÖVçDVÆVÖVçC°¢6öç7B&öG’ÒFö7VÖVçBæ&öG“°¢6öç7B&Wf–÷W5&ö÷D÷fW&fÆ÷rÒ&ö÷Bç7G–ÆRæ÷fW&fÆ÷s°¢6öç7B&Wf–÷W4&öG”÷fW&fÆ÷rÒ&öG’ç7G–ÆRæ÷fW&fÆ÷s°¢&ö÷Bç7G–ÆRæ÷fW&fÆ÷rÒv†–FFVâs°¢&öG’ç7G–ÆRæ÷fW&fÆ÷rÒv†–FFVâs°¢&WGW&â‚’Óâ°¢&ö÷Bç7G–ÆRæ÷fW&fÆ÷rÒ&Wf–÷W5&ö÷D÷fW&fÆ÷s°¢&öG’ç7G–ÆRæ÷fW&fÆ÷rÒ&Wf–÷W4&öG”÷fW&fÆ÷s°¢Ó°¢ÒÂ¶7F—fTFVÆWFT6æF–FFW2æÆVæwF…Ò“° ¢W6TVffV7B‚‚’Óâ°¢–b†7F—fTFVÆWFT6æF–FFW2æÆVæwF‚ÓÓÒÇÂG—Vöbv–æF÷rÓÓÒwVæFVf–æVBr’°¢&WGW&âVæFVf–æVC°¢Ð¢6öç7Bg&ÖRÒv–æF÷rç&WVW7Dæ–ÖF–öäg&ÖR‚‚’Óâ°¢f–æF–ætFVÆWFT6Æ÷6U&Vbæ7W'&VçCòæfö7W2‚“°¢Ò“°¢&WGW&â‚’Óâv–æF÷ræ6æ6VÄæ–ÖF–öäg&ÖR†g&ÖR“°¢ÒÂ¶7F—fTFVÆWFT6æF–FFW2æÆVæwF…Ò“° ¢6öç7B6Æ÷6Tf–æF–ætFWF–ÂÒ‚’Óâ°¢6WDf–æF–ætFWF–Ä÷Vâ†fÇ6R“°¢–b‡G—VöbFö7VÖVçBÓÓÒwVæFVf–æVBr’°¢&WGW&ã°¢Ð¢6öç7B÷VæW"Òf–æF–ætFWF–Ä÷VæW%&Vbæ7W'&VçC°¢f–æF–ætFWF–Ä÷VæW%&Vbæ7W'&VçBÒçVÆÃ°¢–b†÷VæW"bbFö7VÖVçBæ6öçF–ç2†÷VæW"’bbG—Vöb÷VæW"æfö7W2ÓÓÒvgVæ7F–öâr’°¢÷VæW"æfö7W2‚“°¢Ð¢Ó° ¢–b‚66÷R’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷"#à¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äv—D‡V"f–æF–æw3Â÷à¢Æƒ#äv—D‡V"f–æF–æw3Âöƒ#à¢Çåv÷&·76R&÷WFR6öçFW‡B—2Ö—76–ærãÂ÷à¢Â÷6V7F–öãà¢“°¢Ð ¢–b†ÆöF–ær’°¢&WGW&â€¢Ä&÷WFTÆöF–æu7FFP¢F—FÆSÒ%&W&–ærv—D‡V"f–æF–æw2 ¢&öG“Ò%&Vg&W6†–ærf–æF–æræBG&VæBFFf÷"F†—2v÷&·76Râ ¢óà¢“°¢Ð ¢6öç7B†æFÆU&Vg&W6‚Ò‚’Óâ°¢fö–B&VÆöE&Wôf–æF–æw2‡66÷RÂw&Vg&W6‚r“°¢fö–BÆöEG&VæE6–væÇ2‡66÷RÂw&Vg&W6‚r“°¢Ó° ¢6öç7B†–FTf–ÆVE&Wõ66âÒ‡66ã¢&Wõ66å&V6÷&BÂçVÆÂ’Óâ°¢–b‚66â’°¢&WGW&ã°¢Ð¢6WDF—6Ö—76VDf–ÆVE66ä¶W—2‚†7W'&VçB’Óâ°¢6öç7BæW‡BÒæWr6WB†7W'&VçB“°¢æW‡BæFB†f–ÆVE&Wõ66äF—6Ö—76Ä¶W’‡66÷RÂ66âæ–B’“°¢w&—FTF—6Ö—76VE&Wôf–ÆVE66ä¶W—2†æW‡B“°¢&WGW&âæW‡C°¢Ò“°¢Ó° ¢6öç7B&VÖ÷fTf–ÆVE&Wõ66âÒ7–æ2‡66ã¢&Wõ66å&V6÷&BÂçVÆÂ’Óâ°¢–b‚66÷RÇÂ66âÇÂ&VÖ÷f–ætf–ÆVE66ä”B’°¢&WGW&ã°¢Ð¢6öç7BF&vWE66÷RÒ66÷S°¢6öç7BF&vWE66÷T¶W’Ò&öGV7E6W76–öä¶W’‡F&vWE66÷R“°¢6öç7B&WVW7D”BÒ²¶f–ÆVE66å&VÖ÷fU&WVW7E&Vbæ7W'&VçC°¢6öç7B—47F—fU&WVW7BÒ‚’Óà¢f–ÆVE66å&VÖ÷fU&WVW7E&Vbæ7W'&VçBÓÓÒ&WVW7D”Bbb7W'&VçE66÷T¶W•&Vbæ7W'&VçBÓÓÒF&vWE66÷T¶W“°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡F&vWE66÷R“°¢6WE&VÖ÷f–ætf–ÆVE66ä”B‡66âæ–B“°¢6WDW'&÷"‚rr“°¢G'’°¢v—B”6Æ–VçBæFVÆWFU&Wõ66â‡66âæ–BÂWF‚“°¢–b‚—47F—fU&WVW7B‚’’°¢&WGW&ã°¢Ð¢6WE&Wõ66ç2‚†7W'&VçB’Óâ7W'&VçBæf–ÇFW"‚†—FVÒ’Óâ—FVÒæ–BÓÒ66âæ–B’“°¢6WDF—6Ö—76VDf–ÆVE66ä¶W—2‚†7W'&VçB’Óâ°¢6öç7BæW‡BÒæWr6WB†7W'&VçB“°¢æW‡BæFB†f–ÆVE&Wõ66äF—6Ö—76Ä¶W’‡F&vWE66÷RÂ66âæ–B’“°¢w&—FTF—6Ö—76VE&Wôf–ÆVE66ä¶W—2†æW‡B“°¢&WGW&âæW‡C°¢Ò“°¢6öç7B&Vg&W6„÷fW'&–FW3¢&Wôf–æF–ætf–ÇFW%6æ6†÷BÒ²ââç&Wôf–æF–ætf–ÇFW%&Vbæ7W'&VçBÓ°¢–b†æ÷&ÖÆ—¦UfÇVR‡&Vg&W6„÷fW'&–FW2ç&Wõ66äf–ÇFW"’ÓÓÒ66âæ–B’°¢&Vg&W6„÷fW'&–FW2ç&Wõ66äf–ÇFW"Òrs°¢&Wôf–æF–ætf–ÇFW%&Vbæ7W'&VçBÒ²ââç&Wôf–æF–ætf–ÇFW%&Vbæ7W'&VçBÂ&Wõ66äf–ÇFW#¢rrÓ°¢6WE&Wõ66äf–ÇFW"‚rr“°¢Ð¢v—BÆöE&Wôf–æF–æw2‡F&vWE66÷RÂw&Vg&W6‚rÂ&Vg&W6„÷fW'&–FW2“°¢–b‚—47F—fU&WVW7B‚’’°¢&WGW&ã°¢Ð¢v—BÆöEG&VæE6–væÇ2‡F&vWE66÷RÂw&Vg&W6‚rÂ&Wôf–æF–ætf–ÇFW%&Vbæ7W'&VçB“°¢Ò6F6‚‡&WVW7DW'&÷"’°¢–b‚—47F—fU&WVW7B‚’’°¢&WGW&ã°¢Ð¢–b†—5Vç7W÷'FVDFVÆWFTVæGö–çDW'&÷"‡&WVW7DW'&÷"’’°¢†–FTf–ÆVE&Wõ66â‡66â“°¢&WGW&ã°¢Ð¢6WDW'&÷"†f÷&ÖD”W'&÷"‡&WVW7DW'&÷"Âtf–ÆVBFò&VÖ÷fRf–ÆVB66ââr’“°¢Òf–æÆÇ’°¢–b†—47F—fU&WVW7B‚’’°¢6WE&VÖ÷f–ætf–ÆVE66ä”B‚rr“°¢Ð¢Ð¢Ó° ¢6öç7B6öææV7EF‚Ò'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"ö6öææV7Br“°¢6öç7B&VÖVF–F–öåF‚ÒVæDVçf—&öæÖVçEVW'’€¢'V–ÆE66÷VEF‚‡66÷RÂvv—F‡V"÷&VÖVF–F–öâr’À¢Vçf—&öæÖVçD”Dg&öÕ6V&6‚†Æö6F–öâç6V&6‚¢“°¢6öç7B66ç4'•&V6Væ7’Ò²ââç&Wõ66ç5Òç6÷'B€¢†ÆVgBÂ&–v‡B’ÓâæWrFFR‡&–v‡Bç7F'FVEöB’ævWEF–ÖR‚’ÒæWrFFR†ÆVgBç7F'FVEöB’ævWEF–ÖR‚¢“°¢6öç7B7V66VVFVE66ä6÷VçBÒ&Wõ66ç2æf–ÇFW"‚‡66â’Óâ&Wõ66å7FGW5FöæR‡66âç7FGW2’ÓÓÒw7V66W72r’æÆVæwFƒ°¢6öç7Bf–ÆVE66ç2Ò66ç4'•&V6Væ7’æf–ÇFW"‚‡66â’Óâ—4f–ÆVE66å7FGW2‡66âç7FGW2’“°¢6öç7Bf—6–&ÆTf–ÆVE66ç2Òf–ÆVE66ç2æf–ÇFW"€¢‡66â’ÓâF—6Ö—76VDf–ÆVE66ä¶W—2æ†2†f–ÆVE&Wõ66äF—6Ö—76Ä¶W’‡66÷RÂ66âæ–B’¢“°¢6öç7BÆFW7E66âÒ66ç4'•&V6Væ7•³ÒóòçVÆÃ°¢6öç7BÆFW7Df–ÆVE66âÒf—6–&ÆTf–ÆVE66ç5³ÒóòçVÆÃ°¢6öç7B†5VWVVD÷%'Vææ–æu66âÒ66ç4'•&V6Væ7’ç6öÖR‚‡66â’Óâ—47F—fU66å7FGW2‡66âç7FGW2’“°¢6öç7BÆFW7E66å7V66VVFVBÒÆFW7E66âò&Wõ66å7FGW5FöæR†ÆFW7E66âç7FGW2’ÓÓÒw7V66W72r¢fÇ6S°¢6öç7BÆFW7E66äf–ÆVBÒÆFW7E66à¢ò—4f–ÆVE66å7FGW2†ÆFW7E66âç7FGW2’b`¢F—6Ö—76VDf–ÆVE66ä¶W—2æ†2†f–ÆVE&Wõ66äF—6Ö—76Ä¶W’‡66÷RÂÆFW7E66âæ–B’¢¢fÇ6S°¢6öç7BæWfW%66ææVBÒ&Wõ66ç2æÆVæwF‚ÓÓÒ°¢òò$†2f–æF–æw2"×W7B&R–æFWVæFVçBöb&÷F‚7F—fRf–æF–ærf–ÇFW'2æBF†P¢òò&V6VçB×66âv–æF÷r†Æ—7E&Wõ66ç2—26VB’â6öÖ&–æRF†R6W'fW"×6–FP¢òòÆ–fV7–6ÆR7VÖÖ'’‡Væ6VBÂF†RWF†÷&—FF—fR6–væÂ’v—F‚F†RÆöFVBÆ—7@¢òòæBW"×66âf–æF–ær6÷VçG26òF†RÆÂÖf–ÆVBV×G’7FFRæWfW"G&–vvW'0¢òòv†–ÆRf–æF–æw2W†—7Bç—v†W&R–â†—7F÷'’à¢6öç7B7VÖÖ'”f–æF–æuF÷FÂÒ&Wôf–æF–æu7VÖÖ'¢ò&Wôf–æF–æu7VÖÖ'’çF÷FÅö÷Vâ°¢&Wôf–æF–æu7VÖÖ'’æf—†VEö6÷VçB°¢&Wôf–æF–æu7VÖÖ'’ç&V÷VæVEö6÷VçB°¢&Wôf–æF–æu7VÖÖ'’ç7W&W76VEö6÷Vç@¢¢°¢6öç7B†5&Wôf–æF–æw2Ð¢7VÖÖ'”f–æF–æuF÷FÂâÇÀ¢&Wôf–æF–æw2æÆVæwF‚âÇÀ¢&Wõ66ç2ç6öÖR‚‡66â’Óâ‡66âæf–æF–æuö6÷VçBóò’â“°¢6öç7BÆÅ66ç4f–ÆVBÒæWfW%66ææVBbb†5VWVVD÷%'Vææ–æu66âbb†5&Wôf–æF–æw2bb7V66VVFVE66ä6÷VçBÓÓÒbbÆFW7E66äf–ÆVC°¢6öç7Bf–ÇFW'47F—fRÐ¢æ÷&ÖÆ—¦UfÇVR‡&Wõ66äf–ÇFW"’ÓÒrrÇÀ¢6WfW&—G”f–ÇFW"ÓÒvÆÂrÇÀ¢G—Tf–ÇFW"ÓÒvÆÂrÇÀ¢7FGW4f–ÇFW"ÓÒvÆÂrÇÀ¢æ÷&ÖÆ—¦UfÇVR†76–væVTf–ÇFW"’ÓÒrrÇÀ¢æ÷&ÖÆ—¦UfÇVR‡6÷W&6Tf–ÇFW"’ÓÒrrÇÀ¢æ÷&ÖÆ—¦UfÇVR†Ö–ä6öæf–FVæ6Tf–ÇFW"’ÓÒrs° ¢6öç7Bf÷&ÖE66äFFRÒ‡66ã¢&Wõ66å&V6÷&BÂçVÆÂ“¢7G&–ærÓâ°¢–b‚66â’°¢&WGW&ârs°¢Ð¢6öç7Bv†VâÒæWrFFR‡66âæf–æ—6†VEöBÇÂ66âç7F'FVEöB“°¢&WGW&âçVÖ&W"æ—4æâ‡v†VâævWEF–ÖR‚’’òrr¢v†VâçFôÆö6ÆTFFU7G&–ær‡VæFVf–æVBÂ²ÖöçFƒ¢w6†÷'BrÂF“¢vçVÖW&–2rÒ“°¢Ó° ¢6öç7BFW67&–&U66äf–ÇW&RÒ‡66ã¢&Wõ66å&V6÷&BÂçVÆÂ“¢7G&–ærÓâ°¢–b‚66â’°¢&WGW&âuF†R66âF–Bæ÷B6ö×ÆWFRâs°¢Ð¢6öç7B'G2Ò·7VÖÖ&—¦U66äf–ÇW&R‡66â•Ó°¢6öç7B&W÷6—F÷'’Ò6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡66âç&W÷6—F÷'’“°¢–b‡&W÷6—F÷'’’°¢'G2çW6‚‡&W÷6—F÷'’“°¢Ð¢6öç7Bv†VâÒf÷&ÖE66äFFR‡66â“°¢–b‡v†Vâ’°¢'G2çW6‚‡v†Vâ“°¢Ð¢&WGW&â'G2æ¦ö–â‚r+rr“°¢Ó° ¢òòF—7F–æ7BV×G’öf–ÆVB7FFW3¢æWfW"6†÷v–ærF†R÷VÆFVBF6†&ö&B6‡&öÖP¢òò„µ’w&–BÂ&—6²w&‚ÂG&VæBÂf–ÇFW'2’f–ÆÆVBv—F‚¦W&÷2v†Vâæò66â†0¢òò&öGV6VBf–æF–æw2âf–ÆVBÖöæÇ’7FFR7W&f6W2F†Rf–ÇW&R–ç7FVBö`¢òò6–ÆVçFÇ’&VæFW&–ær¦W&÷2à¢–b†æWfW%66ææVBÇÂÆÅ66ç4f–ÆVB’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GB×&WòÖf–æF–æw2×vR#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–æw2Ö†VFW"#à¢ÆF—cà¢Æƒ#äv—D‡V"f–æF–æw3Âöƒ#à¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖ–æÆ–æRÖ7F–öç2#à¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’"Fó×·&VÖVF–F–öåF‡Óà¢÷Vâ&VÖVF–F–öà¢ÂôÆ–æ³à¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×¶†æFÆU&Vg&W6‡Ð¢F—6&ÆVC×·&Vg&W6†–ærÇÂ6–væÇ5&Vg&W6†–æwÐ¢à¢·&Vg&W6†–ærÇÂ6–væÇ5&Vg&W6†–æròu&Vg&W6†–ærâââr¢u&Vg&W6‚wÐ¢Âö'WGFöãà¢ÂöF—cà¢ÂöF—cà ¢¶W'&÷"òÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç¶W'&÷'ÓÂöF—câ¢çVÆÇÐ ¢¶æWfW%66ææVBò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ%'Vâ–÷W"f—'7B&W÷6—F÷'’66â ¢&öG“Ò%66â6öææV7FVB&W÷6—F÷'’Fò7W&f6R&—6·’G'W7BF‡2ÂW‡÷6VB6V7&WG2ÂæBWF†÷&—¦F–öâv2(	BF†Vâ§V×7G&–v‡BFòF†RW†7Bv—D‡V"Æ–æRâ ¢7F–öã×·²Æ&VÃ¢t6öææV7Bv—D‡V"rÂFó¢6öææV7EF‚×Ð¢óà¢’¢€¢Æ'F–6ÆR6Æ74æÖSÒ&–GBÖÖV×G’×7FFR–GB×&Wò×66âÖf–ÇW&R×7FFR#à¢Æƒ#å–÷W"Æ7B&W÷6—F÷'’66âf–ÆVCÂöƒ#à¢Çç¶FW67&–&U66äf–ÇW&R†ÆFW7Df–ÆVE66â—ÓÂ÷à¢ÆF—b6Æ74æÖSÒ&–GBÖ–æÆ–æRÖ7F–öç2#à¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖÖV×G’×7FFRÖ7F–öâ"Fó×¶6öææV7EF‡Óà¢&Wf–Wrf×²&R×'Vâ66à¢ÂôÆ–æ³à¢¶6å&VÖ÷fTf–ÆVE&Wõ66ç2ò€¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâfö–B&VÖ÷fTf–ÆVE&Wõ66â†ÆFW7Df–ÆVE66â—Ð¢F—6&ÆVC×´&ööÆVâ‡&VÖ÷f–ætf–ÆVE66ä”B—Ð¢à¢·&VÖ÷f–ætf–ÆVE66ä”BÓÓÒÆFW7Df–ÆVE66ãòæ–Bòu&VÖ÷f–ærâââr¢u&VÖ÷fRwÐ¢Âö'WGFöãà¢’¢€¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâ†–FTf–ÆVE&Wõ66â†ÆFW7Df–ÆVE66â—Ð¢à¢F—6Ö—70¢Âö'WGFöãà¢—Ð¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×¶†æFÆU&Vg&W6‡Ð¢F—6&ÆVC×·&Vg&W6†–ærÇÂ6–væÇ5&Vg&W6†–æwÐ¢à¢·&Vg&W6†–ærÇÂ6–væÇ5&Vg&W6†–æròu&Vg&W6†–ærâââr¢u&Vg&W6‚wÐ¢Âö'WGFöãà¢ÂöF—cà¢Âö'F–6ÆSà¢—Ð¢Â÷6V7F–öãà¢“°¢Ð ¢6öç7BF÷FÅG&VæD—FV×2ÒG&VæEö–çG2ç&VGV6R‚†62Âö–çB’Óâ62²ö–çBçF÷FÂÂ“°¢6öç7BG&VæE&÷w2ÒG&VæEö–çG2æÖ‚‡ö–çBÂ–æFW‚’Óâ°¢6öç7B'•6WfW&—G’Òö–çBæ'•÷6WfW&—G’óò‡·Ò2&V6÷&CÇ7G&–ærÂçVÖ&W#â“°¢6öç7B6WfW&—G•fÇVW2Ò°¢7&—F–6Ã¢'•6WfW&—G’æ7&—F–6ÂóòÀ¢†–vƒ¢'•6WfW&—G’æ†–v‚óòÀ¢ÖVF—VÓ¢'•6WfW&—G’æÖVF—VÒóòÀ¢Æ÷s¢'•6WfW&—G’æÆ÷róòÀ¢–æfó¢'•6WfW&—G’æ–æfòóò ¢Ó°¢6öç7BW&6VçFvRÒG&VæDÖ…F÷FÂâòÖF‚ç&÷VæB‚‡ö–çBçF÷FÂòG&VæDÖ…F÷FÂ’¢’¢°¢6öç7B7F'FVDBÒæWrFFR‡ö–çBç7F'FVEöB“°¢6öç7Bö–çDÆ&VÂÐ¢çVÖ&W"æ—4æâ‡7F'FVDBævWEF–ÖR‚’’ð¢uVæ¶æ÷vâ66âp¢¢7F'FVDBçFôÆö6ÆTFFU7G&–ær‡VæFVf–æVBÂ²ÖöçFƒ¢w6†÷'BrÂF“¢vçVÖW&–2rÒ“°¢&WGW&â²ââç6WfW&—G•fÇVW2Â¶W“¢G·ö–çBç7F'FVEöGÒÒG¶–æFW‡ÖÂW&6VçFvRÂÆ&VÃ¢ö–çDÆ&VÂÂF÷FÃ¢ö–çBçF÷FÂÓ°¢Ò“° ¢6öç7BG&VæDF—7Æ”ÆöF–ærÒ6–væÇ4ÆöF–æs°¢6öç7Bf—6–&ÆU&Wõ&—6´w&‚Òf–ÇFW&VDf–æF–æw2æÆVæwF‚âbb&—6´w&„f–ÇFW'5Vç7W÷'FVBò&Wõ&—6´w&‚¢çVÆÃ°¢6öç7B&—6´w&…7VÖÖ'’Òf—6–&ÆU&Wõ&—6´w&ƒòç7VÖÖ'“°¢6öç7B&—6´w&„†–FFVä'”f–ÇFW'2Òf–ÇFW&VDf–æF–æw2æÆVæwF‚âbb&—6´w&„f–ÇFW'5Vç7W÷'FVC°¢6öç7B&—6´w&…Væf–Æ&ÆT&öG’Ò&—6´w&„†–FFVä'”f–ÇFW'0¢òt6ÆV"6÷W&6RÂ76–væVRÂ÷"Æ–fV7–6ÆRf–ÇFW'2Fòf–WrF†Rw&‚âp¢¢u'Vâ&W÷6—F÷'’W‡÷7W&R66â6òÖ6†–æRÖ–FVçF—G’F‡2æBf–æF–ær&—6²66÷&W26âV"†W&Râs°¢6öç7B&—6´w&…Væ¶æ÷väWf–FVæ6T6÷VçBÐ¢‡&—6´w&…7VÖÖ'“òçVæ¶æ÷våöæöFUö6÷VçBóò’²‡&—6´w&…7VÖÖ'“òçVæ¶æ÷våöVFvUö6÷VçBóò“°¢6öç7B6VÆV7FVDf–æF–æu&Wf–Wt¶W’Ò6VÆV7FVDf–æF–ærò'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’‡6VÆV7FVDf–æF–ær’¢rs°¢6öç7B7F—fU&VÖVF–F–öå&Wf–WrÐ¢&VÖVF–F–öå&Wf–Wrbb&VÖVF–F–öå&Wf–Wtf–æF–æt¶W’ÓÓÒ6VÆV7FVDf–æF–æu&Wf–Wt¶W’ò&VÖVF–F–öå&Wf–Wr¢çVÆÃ° ¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GB×&WòÖf–æF–æw2×vR#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–æw2Ö†VFW"#à¢ÆF—cà¢Æƒ#äv—D‡V"f–æF–æw3Âöƒ#à¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GBÖ–æÆ–æRÖ7F–öç2#à¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×¶†æFÆU&Vg&W6‡Ð¢F—6&ÆVC×·&Vg&W6†–ærÇÂ6–væÇ5&Vg&W6†–æwÐ¢à¢·&Vg&W6†–ærÇÂ6–væÇ5&Vg&W6†–æròu&Vg&W6†–ærâââr¢u&Vg&W6‚wÐ¢Âö'WGFöãà¢¶6äFVÆWFU&Wôf–æF–æw2bbf–ÇFW&VDf–æF–æw2æÆVæwF‚âò€¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖFævW"–GB×&WòÖ6ÆV"ÖÆÂÖ'Fâ ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²†WfVçB’Óâ&WVW7DFVÆWFTÆÅf—6–&ÆTf–æF–æw2†WfVçBæ7W'&VçEF&vWB—Ð¢F—6&ÆVC×¶FVÆWFT7F–öç4F—6&ÆVGÐ¢à¢ÅG&6ƒ"6—¦S×³WÒ7G&ö¶Uv–GFƒ×³'Ò&–Ö†–FFVãÒ'G'VR"óà¢6ÆV"ÆÀ¢Âö'WGFöãà¢’¢çVÆÇÐ¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’"Fó×·&VÖVF–F–öåF‡Óà¢÷Vâ&VÖVF–F–öà¢ÂôÆ–æ³à¢ÂöF—cà¢ÂöF—cà ¢¶W'&÷"òÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç¶W'&÷'ÓÂöF—câ¢çVÆÇÐ¢·6–væÄW'&÷"òÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·6–væÄW'&÷'ÓÂöF—câ¢çVÆÇÐ¢·G&VæDW'&÷"òÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·G&VæDW'&÷'ÓÂöF—câ¢çVÆÇÐ¢·&—6´w&„W'&÷"òÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·&—6´w&„W'&÷'ÓÂöF—câ¢çVÆÇÐ ¢¶ÆFW7E66äf–ÆVBò€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"–GB×&Wò×66âÖ†VÇF‚#à¢Ç7ãäÆ7B66âf–ÆVC¢¶FW67&–&U66äf–ÇW&R†ÆFW7Df–ÆVE66â—ÓÂ÷7ãà¢Ç7â6Æ74æÖSÒ&–GB×&Wò×66âÖ†VÇF‚Ö7F–öç2Ö–æÆ–æR#à¢¶6å&VÖ÷fTf–ÆVE&Wõ66ç2ò€¢Æ'WGFöà¢6Æ74æÖSÒ&–GB×&Wò×66âÖ†VÇF‚×&VÖ÷fR ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâfö–B&VÖ÷fTf–ÆVE&Wõ66â†ÆFW7Df–ÆVE66â—Ð¢F—6&ÆVC×´&ööÆVâ‡&VÖ÷f–ætf–ÆVE66ä”B—Ð¢à¢·&VÖ÷f–ætf–ÆVE66ä”BÓÓÒÆFW7Df–ÆVE66ãòæ–Bòu&VÖ÷f–ærâââr¢u&VÖ÷fRwÐ¢Âö'WGFöãà¢’¢€¢Æ'WGFöà¢6Æ74æÖSÒ&–GB×&Wò×66âÖ†VÇF‚×&VÖ÷fR ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâ†–FTf–ÆVE&Wõ66â†ÆFW7Df–ÆVE66â—Ð¢à¢F—6Ö—70¢Âö'WGFöãà¢—Ð¢ÄÆ–æ²Fó×¶6öææV7EF‡Óå&Wf–Wrf×²&R×'VãÂôÆ–æ³à¢Â÷7ãà¢ÂöF—cà¢’¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FG2"&–ÖÆ&VÃÒ%&W÷6—F÷'’f–æF–ær7VÖÖ'’#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FB#à¢Ç7ãä÷Vâf–æF–æw3Â÷7ãà¢Ç7G&öæsç¶÷Väf–æF–æt6÷VçGÓÂ÷7G&öæsà¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FB#à¢Ç7ãä7&—F–6Âf–æF–æw3Â÷7ãà¢Ç7G&öæsç¶7&—F–6Äf–æF–æt6÷VçGÓÂ÷7G&öæsà¢·6ÆvVDf–æF–æt6÷VçBâòÇ6ÖÆÂ6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FBÖæ÷FR#å4ÄÖvVB·6ÆvVDf–æF–æt6÷VçGÓÂ÷6ÖÆÃâ¢çVÆÇÐ¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FB#à¢Ç7ãäÖVâF–ÖRFòf—ƒÂ÷7ãà¢Ç7G&öæsç¶×GG$Æ&VÇÓÂ÷7G&öæsà¢Âö'F–6ÆSà¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×7FB#à¢Ç7ãä6ö×ÆWFVB66ç3Â÷7ãà¢Ç7G&öæsç¶7F—fU66ä6÷VçGÓÂ÷7G&öæsà¢Âö'F–6ÆSà¢ÂöF—cà ¢¶f–ÇFW&VDf–æF–æw2æÆVæwF‚âÇÂf–ÇFW'47F—fRò€¢ÆFWF–Ç0¢6Æ74æÖSÒ&–GB×&WòÖf–ÇFW"×æVÂ ¢&–ÖÆ&VÃÒ%&W÷6—F÷'’f–æF–ærf–ÇFW'2æB6÷'F–ær ¢÷Vã×¶f–ÇFW'4W‡æFVGÐ¢öåFövvÆS×²†WfVçB’Óâ6WDf–ÇFW'4W‡æFVB†WfVçBæ7W'&VçEF&vWBæ÷Vâ—Ð¢à¢Ç7VÖÖ'’6Æ74æÖSÒ&–GB×&WòÖf–ÇFW"×æVÂÖ†VFW"#à¢Ç7ãäf–ÇFW'2æB6÷'F–æsÂ÷7ãà¢Â÷7VÖÖ'“à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖf–ÇFW'2#à¢ÆÆ&VÃà¢&W÷6—F÷'’66à¢Ç6VÆV7BfÇVS×·&Wõ66äf–ÇFW'Òöä6†ævS×²†WfVçB’Óâ6WE&Wõ66äf–ÇFW"†WfVçBçF&vWBçfÇVR—Óà¢Æ÷F–öâfÇVSÒ"#äÆÂ&W÷6—F÷'’66ç3Âö÷F–öãà¢·&Wõ66ç2æÖ‚‡66â’Óâ€¢Æ÷F–öâ¶W“×·66âæ–GÒfÇVS×·66âæ–GÓà¢¶6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡66âç&W÷6—F÷'’—Ò+r¶f÷&ÖEFö¶VäÆ&VÂ‡66âç7FGW2—Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢6WfW&—G¢Ç6VÆV7@¢fÇVS×·6WfW&—G”f–ÇFW'Ð¢öä6†ævS×²†WfVçB’Óâ6WE6WfW&—G”f–ÇFW"†WfVçBçF&vWBçfÇVR2‡G—Vöb$Uõôd”äD”äuõ4UdU$•E•ôd”ÅDU%2•¶çVÖ&W%Ò—Ð¢à¢µ$Uõôd”äD”äuõ4UdU$•E•ôd”ÅDU%2æÖ‚‡fÇVR’Óâ€¢Æ÷F–öâ¶W“×·fÇVWÒfÇVS×·fÇVWÓà¢·fÇVRÓÓÒvÆÂròtÆÂ6WfW&—F–W2r¢f÷&ÖEFö¶VäÆ&VÂ‡fÇVR—Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢G—P¢Ç6VÆV7BfÇVS×·G—Tf–ÇFW'Òöä6†ævS×²†WfVçB’Óâ6WEG—Tf–ÇFW"†WfVçBçF&vWBçfÇVR2‡G—Vöb$Uõôd”äD”äuõE•Uôd”ÅDU%2•¶çVÖ&W%Ò—Óà¢µ$Uõôd”äD”äuõE•Uôd”ÅDU%2æÖ‚‡fÇVR’Óâ€¢Æ÷F–öâ¶W“×·fÇVWÒfÇVS×·fÇVWÓà¢·fÇVRÓÓÒvÆÂròtÆÂf–æF–ærG—W2r¢f÷&ÖEFö¶VäÆ&VÂ‡fÇVR—Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢6÷'B'¢Ç6VÆV7BfÇVS×·6÷'D'—Òöä6†ævS×²†WfVçB’Óâ6WE6÷'D'’†WfVçBçF&vWBçfÇVR2‡G—Vöb$Uõôd”äD”äuõ4õ%Eôd”TÄE2•¶çVÖ&W%Ò—Óà¢µ$Uõôd”äD”äuõ4õ%Eôd”TÄE2æÖ‚‡fÇVR’Óâ€¢Æ÷F–öâ¶W“×·fÇVWÒfÇVS×·fÇVWÓà¢µ4õ%EôÄ$TÅô%•ôd”TÄE·fÇVU×Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢6÷'B÷&FW ¢Ç6VÆV7BfÇVS×·6÷'D÷&FW'Òöä6†ævS×²†WfVçB’Óâ6WE6÷'D÷&FW"†WfVçBçF&vWBçfÇVR2v62rÂvFW62r—Óà¢Æ÷F–öâfÇVSÒ&62#ä66VæF–æsÂö÷F–öãà¢Æ÷F–öâfÇVSÒ&FW62#äFW66VæF–æsÂö÷F–öãà¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢Æ–fV7–6ÆR7FGW0¢Ç6VÆV7BfÇVS×·7FGW4f–ÇFW'Òöä6†ævS×²†WfVçB’Óâ6WE7FGW4f–ÇFW"†WfVçBçF&vWBçfÇVR2‡G—Vöb$Uõôd”äD”äuõ5DEU5ôd”ÅDU%2•¶çVÖ&W%Ò—Óà¢µ$Uõôd”äD”äuõ5DEU5ôd”ÅDU%2æÖ‚‡fÇVR’Óâ€¢Æ÷F–öâ¶W“×·fÇVWÒfÇVS×·fÇVWÓà¢¶f÷&ÖEFö¶VäÆ&VÂ‡fÇVR—Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢76–væVP¢Æ–çW@¢G—SÒ'FW‡B ¢Æ6V†öÆFW#Ò$f–ÇFW"'’76–væVR ¢fÇVS×¶76–væVTf–ÇFW'Ð¢öä6†ævS×²†WfVçB’Óâ6WD76–væVTf–ÇFW"†WfVçBçF&vWBçfÇVR—Ð¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢6÷W&6P¢Æ–çW@¢G—SÒ'FW‡B ¢Æ6V†öÆFW#Ò%6÷W&6RæÖR ¢fÇVS×·6÷W&6Tf–ÇFW'Ð¢öä6†ævS×²†WfVçB’Óâ6WE6÷W&6Tf–ÇFW"†WfVçBçF&vWBçfÇVR—Ð¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢Ö–â6öæf–FVæ6P¢Æ–çW@¢G—SÒ&çVÖ&W" ¢7FWÒ#ã ¢Ö–ãÒ# ¢ÖƒÒ# ¢Æ6V†öÆFW#Ò&Rærâãr ¢fÇVS×¶Ö–ä6öæf–FVæ6Tf–ÇFW'Ð¢öä6†ævS×²†WfVçB’Óâ6WDÖ–ä6öæf–FVæ6Tf–ÇFW"†WfVçBçF&vWBçfÇVR—Ð¢óà¢ÂöÆ&VÃà¢ÂöF—cà¢ÂöFWF–Ç3à¢’¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖÆ–÷WB#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖÆ—7B#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖÆ—7BÖ†VFW"#à¢Æƒ3å&W÷6—F÷'’f–æF–æw3Âöƒ3à¢ÂöF—cà¢¶f–æF–æt†–W&&6‡’æÆVæwF‚ÓÓÒò€¢f–ÇFW'47F—fRò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æòf–æF–æw2ÖF6‚F†W6Rf–ÇFW'2 ¢&öG“Ò$Æö÷6VâF†R7W'&VçBf–ÇFW'2Fò–ç7V7Bv—D‡V"ÖÆ–æ¶VBf–æF–æw2g&öÒ–÷W"66ç2â ¢óà¢’¢ÆFW7E66å7V66VVFVBò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æòW‡÷7W&Rf÷VæB ¢&öG“Ò%–÷W"ÆFW7B&W÷6—F÷'’66â6ö×ÆWFVBæB7W&f6VBæòf–æF–æw2âæWrf–æF–æw2v–ÆÂV"†W&RgFW"F†RæW‡B66ââ ¢óà¢’¢€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æò6ö×ÆWFVB66â&W7VÇG2 ¢&öG“Ò$æò6ö×ÆWFVB66â†27W&f6VBf–æF–æw2–WBâæWrf–æF–æw2v–ÆÂV"†W&RgFW"F†RæW‡B7V66W76gVÂ66ââ ¢óà¢¢’¢€¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ†–W&&6‡’#à¢¶f–æF–æt†–W&&6‡’æÖ‚‡&W÷6—F÷'”w&÷WÂ&W÷6—F÷'”–æFW‚’Óâ°¢6öç7B7&—F–6Ä6÷VçBÒ&W÷6—F÷'”w&÷Wæf–æF–æw2æf–ÇFW"€¢†f–æF–ær’Óâæ÷&ÖÆ—¦UfÇVR†f–æF–ærç6WfW&—G’’çFôÆ÷vW$66R‚’ÓÓÒv7&—F–6Âp¢’æÆVæwFƒ°¢6öç7B†–v„6÷VçBÒ&W÷6—F÷'”w&÷Wæf–æF–æw2æf–ÇFW"€¢†f–æF–ær’Óâæ÷&ÖÆ—¦UfÇVR†f–æF–ærç6WfW&—G’’çFôÆ÷vW$66R‚’ÓÓÒv†–v‚p¢’æÆVæwFƒ°¢6öç7BÆFW7E66äÆ&VÂÐ¢²ââç&W÷6—F÷'”w&÷Wç66äw&÷W5Òç6÷'B‚†ÆVgBÂ&–v‡B’Óâ&–v‡Bç6÷'EfÇVRÒÆVgBç6÷'EfÇVR•³ÓòæÆ&VÂóð¢u66âFFRVæf–Æ&ÆRs° ¢&WGW&â€¢ÆFWF–Ç0¢6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ'V6¶WB–GB×&WòÖf–æF–ær×&W÷6—F÷'’ ¢¶W“×·&W÷6—F÷'”w&÷Wæ¶W—Ð¢÷Vã×¶†–W&&6‡”÷Vå7FFRç&W÷6—F÷&–W2æ†2‡&W÷6—F÷'”w&÷Wæ¶W’—Ð¢öåFövvÆS×²†WfVçB’Óà¢WFFT†–W&&6‡”÷Vå7FFR‚w&W÷6—F÷&–W2rÂ&W÷6—F÷'”w&÷Wæ¶W’ÂWfVçBæ7W'&VçEF&vWBæ÷Vâ¢Ð¢à¢Ç7VÖÖ'’6Æ74æÖSÒ&–GB×&Wò×&W÷6—F÷'’×7VÖÖ'’#à¢Ç7â6Æ74æÖSÒ&–GB×&Wò×7VÖÖ'’ÖÖ–â#à¢Ç7â6Æ74æÖSÒ&–GB×&Wò×7VÖÖ'’Ö–6öâ"&–Ö†–FFVãÒ'G'VR#à¢ÄföÆFW$¶æ&â6—¦S×³‡Ò7G&ö¶Uv–GFƒ×³'Òóà¢Â÷7ãà¢Ç7ãà¢Ç7G&öæsç·&W÷6—F÷'”w&÷WæÆ&VÇÓÂ÷7G&öæsà¢Â÷7ãà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GB×&Wò×7VÖÖ'’ÖÖWG&–72"&–ÖÆ&VÃÒ%&W÷6—F÷'’f–æF–ær7VÖÖ'’#à¢Ç7ãà¢Ç7G&öæsç·&W÷6—F÷'”w&÷Wæf–æF–æw2æÆVæwF‡ÓÂ÷7G&öæsà¢Ç6ÖÆÃäf–æF–æw3Â÷6ÖÆÃà¢Â÷7ãà¢Ç7ãà¢Ç7G&öæsç¶7&—F–6Ä6÷VçB²†–v„6÷VçGÓÂ÷7G&öæsà¢Ç6ÖÆÃä†–v‚&—6³Â÷6ÖÆÃà¢Â÷7ãà¢Ç7ãà¢Ç7G&öæsç¶ÆFW7E66äÆ&VÇÓÂ÷7G&öæsà¢Ç6ÖÆÃäÆFW7B66ãÂ÷6ÖÆÃà¢Â÷7ãà¢Â÷7ãà¢Â÷7VÖÖ'“à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ'V6¶WBÖ&öG’–GB×&Wò×66â×F–ÖVÆ–æR#à¢·&W÷6—F÷'”w&÷Wç66äw&÷W2æÖ‚‡66äw&÷WÂ66ä–æFW‚’Óâ€¢ÆFWF–Ç0¢6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ'V6¶WB–GB×&WòÖf–æF–ær×66â ¢¶W“×·66äw&÷Wæ¶W—Ð¢÷Vã×¶†–W&&6‡”÷Vå7FFRç66ç2æ†2‡66äw&÷Wæ¶W’—Ð¢öåFövvÆS×²†WfVçB’Óà¢WFFT†–W&&6‡”÷Vå7FFR‚w66ç2rÂ66äw&÷Wæ¶W’ÂWfVçBæ7W'&VçEF&vWBæ÷Vâ¢Ð¢à¢Ç7VÖÖ'’6Æ74æÖSÒ&–GB×&Wò×66â×7VÖÖ'’#à¢Ç7â6Æ74æÖSÒ&–GB×&Wò×66âÖæöFR"&–Ö†–FFVãÒ'G'VR"óà¢Ç7â6Æ74æÖSÒ&–GB×&Wò×66âÖ6÷’#à¢Ç7G&öæsç·66äw&÷WæÆ&VÇÓÂ÷7G&öæsà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GB×&Wò×66âÖÖWF#à¢Ç7ãç·66äw&÷Wæf–æF–æw2æÆVæwF‡Òf–æF–æw3Â÷7ãà¢Â÷7ãà¢Â÷7VÖÖ'“à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ'V6¶WBÖ&öG’–GB×&Wò×6WfW&—G’ÖÆæW2#à¢·66äw&÷Wç6WfW&—G”w&÷W2æÖ‚‡6WfW&—G”w&÷WÂ6WfW&—G”–æFW‚’Óâ€¢ÆFWF–Ç0¢6Æ74æÖS×¶–GB×&WòÖf–æF–ærÖ'V6¶WB–GB×&WòÖf–æF–ær×6WfW&—G’Öw&÷W—2ÒG·6WfW&—G”w&÷WæÆ&VÇÖÐ¢¶W“×·6WfW&—G”w&÷Wæ¶W—Ð¢÷Vã×¶†–W&&6‡”÷Vå7FFRç6WfW&—F–W2æ†2‡6WfW&—G”w&÷Wæ¶W’—Ð¢öåFövvÆS×²†WfVçB’Óà¢WFFT†–W&&6‡”÷Vå7FFR‚w6WfW&—F–W2rÂ6WfW&—G”w&÷Wæ¶W’ÂWfVçBæ7W'&VçEF&vWBæ÷Vâ¢Ð¢à¢Ç7VÖÖ'’6Æ74æÖSÒ&–GB×&Wò×6WfW&—G’×7VÖÖ'’#à¢Ç7â6Æ74æÖSÒ&–GB×&Wò×6WfW&—G’Ö6÷’#à¢Ç7â6Æ74æÖS×·&Wôf–æF–æu6WfW&—G”6Æ72‡6WfW&—G”w&÷WæÆ&VÂ—Óà¢¶f÷&ÖEFö¶VäÆ&VÂ‡6WfW&—G”w&÷WæÆ&VÂ—Ð¢Â÷7ãà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GB×&Wò×6WfW&—G’Ö6÷VçB#à¢Ç7G&öæsç·6WfW&—G”w&÷Wæf–æF–æw2æÆVæwF‡ÓÂ÷7G&öæsà¢Ç6ÖÆÃæf–æF–æw3Â÷6ÖÆÃà¢Â÷7ãà¢Â÷7VÖÖ'“à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ—FV×2"&öÆSÒ&Æ—7B#à¢·6WfW&—G”w&÷Wæf–æF–æw2æÖ‚†f–æF–ær’Óâ°¢6öç7B&W÷6—F÷'•fÇVRÒ&Wôf–æF–æu&W÷6—F÷'•fÇVR†f–æF–ærÂ&Wõ66ç4'””B“°¢6öç7B&W÷6—F÷'”Æ&VÂÐ¢6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡&W÷6—F÷'•fÇVR’ÇÂu&W÷6—F÷'’Væf–Æ&ÆRs°¢6öç7B6VÆV7F–öä¶W’Ò'V–ÆE&Wôf–æF–æu6VÆV7F–öä¶W’†f–æF–ær“°¢6öç7B—56VÆV7FVBÒ6VÆV7FVDf–æF–æt¶W’ÓÓÒ6VÆV7F–öä¶W“°¢6öç7BÆ–fV7–6ÆRÒæ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2†f–æF–æræÆ–fV7–6ÆU÷7FGW2“°¢&WGW&â€¢ÆF—`¢¶W“×·6VÆV7F–öä¶W—Ð¢&öÆSÒ&Æ—7F—FVÒ ¢F$–æFWƒ×³Ð¢&–Ö†7÷WÒ&F–Æör ¢6Æ74æÖS×¶–GB×&WòÖf–æF–ær×&÷r–GB×&WòÖf–æF–ærÖ7F–öâ×&÷rG¶—56VÆV7FVBòr—2×6VÆV7FVBr¢rwÒG¶f–æF–ætÖVçT¶W’ÓÓÒ6VÆV7F–öä¶W’òr—2ÖÖVçRÖ÷Vâr¢rwÖÐ¢öä6Æ–6³×²†WfVçB’Óâ6VÆV7E&Wôf–æF–ær‡6VÆV7F–öä¶W’ÂG'VRÂWfVçBæ7W'&VçEF&vWB—Ð¢öä¶W”F÷vã×²†WfVçB’Óâ°¢–b†WfVçBçF&vWBÓÒWfVçBæ7W'&VçEF&vWB’°¢&WGW&ã°¢Ð¢–b†WfVçBæ¶W’ÓÓÒtVçFW"rÇÂWfVçBæ¶W’ÓÓÒrr’°¢WfVçBç&WfVçDFVfVÇB‚“°¢6VÆV7E&Wôf–æF–ær‡6VÆV7F–öä¶W’ÂG'VRÂWfVçBæ7W'&VçEF&vWB“°¢Ð¢×Ð¢à¢Å6÷W&6TÆövôÖ&²&÷f–FW#Ò&v—F‡V""6Æ74æÖSÒ&—2×&÷r"óà¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷rÖ6÷’#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷r×F÷#à¢Ç7G&öæsç¶f–æF–ærçF—FÆWÓÂ÷7G&öæsà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷rÖÖWF#à¢Ç7ãç·&W÷6—F÷'”Æ&VÇÓÂ÷7ãà¢Ç7ãç·&Wôf–æF–ætÆö6F–öäÆ&VÂ†f–æF–ær—ÓÂ÷7ãà¢Ç7ãç¶f÷&ÖEFö¶VäÆ&VÂ†f–æF–ærçG—R—ÓÂ÷7ãà¢Ç7â6Æ74æÖS×·&Wôf–æF–æu7FGW46Æ72†Æ–fV7–6ÆR—Óç¶f÷&ÖEFö¶VäÆ&VÂ†Æ–fV7–6ÆR—ÓÂ÷7ãà¢Ç7ãç¶f–æF–æræ÷væW"ÇÂf–æF–ærçG&–vSòæ76–væVRÇÂuVæ76–væVBwÓÂ÷7ãà¢ÂöF—cà¢ÂöF—cà¢Ç7â6Æ74æÖS×·&Wôf–æF–æu6WfW&—G”6Æ72†f–æF–ærç6WfW&—G’—Óà¢¶f÷&ÖEFö¶VäÆ&VÂ†f–æF–ærç6WfW&—G’—Ð¢Â÷7ãà¢¶6äFVÆWFU&Wôf–æF–æw2ò€¢ÆF—`¢6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×&÷rÖ7F–öç2 ¢öä6Æ–6³×²†WfVçB’ÓâWfVçBç7F÷&÷vF–öâ‚—Ð¢öä¶W”F÷vã×¶†æFÆTf–æF–ætÖVçT¶W”F÷vçÐ¢à¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖÖVçR×G&–vvW" ¢&–ÖÆ&VÃ×¶÷Vâ7F–öç2f÷"G¶f–æF–ærçF—FÆWÖÐ¢&–Ö†7÷WÒ&ÖVçR ¢&–ÖW‡æFVC×¶f–æF–ætÖVçT¶W’ÓÓÒ6VÆV7F–öä¶W—Ð¢F—6&ÆVC×¶FVÆWFT7F–öç4F—6&ÆVGÐ¢öä6Æ–6³×²†WfVçB’Óâ°¢6öç7BæW‡D÷VâÒf–æF–ætÖVçT¶W’ÓÒ6VÆV7F–öä¶W“°¢–b†æW‡D÷VâbbG—Vöbv–æF÷rÓÒwVæFVf–æVBr’°¢6öç7B&V7BÒWfVçBæ7W'&VçEF&vWBævWD&÷VæF–æt6Æ–VçE&V7B‚“°¢6öç7B76T&VÆ÷rÒv–æF÷ræ–ææW$†V–v‡BÒ&V7Bæ&÷GFöÓ°¢6öç7B76T&÷fRÒ&V7BçF÷°¢6WDf–æF–ætÖVçUÆ6VÖVçB‡76T&VÆ÷rÂ#bb76T&÷fRâ76T&VÆ÷ròwWr¢vF÷vâr“°¢Ð¢6WDf–æF–ætÖVçT¶W’‚†7W'&VçB’Óâ†7W'&VçBÓÓÒ6VÆV7F–öä¶W’òrr¢6VÆV7F–öä¶W’’“°¢6WDFVÆWFTW'&÷"‚rr“°¢×Ð¢öä¶W”F÷vã×¶†æFÆTf–æF–ætÖVçT¶W”F÷vçÐ¢à¢ÄÖ÷&T†÷&—¦öçFÂ6—¦S×³gÒ7G&ö¶Uv–GFƒ×³'Ò&–Ö†–FFVãÒ'G'VR"óà¢Âö'WGFöãà¢¶f–æF–ætÖVçT¶W’ÓÓÒ6VÆV7F–öä¶W’bbFVÆWFT7F–öç4F—6&ÆVBò€¢ÆF—`¢6Æ74æÖS×¶–GB×&WòÖf–æF–ærÖÖVçRG¶f–æF–ætÖVçUÆ6VÖVçBÓÓÒwWròr—2×Wr¢rwÖÐ¢&öÆSÒ&ÖVçR ¢à¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢&öÆSÒ&ÖVçV—FVÒ ¢6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖÖVçRÖ—FVÒ—2ÖFævW" ¢öä6Æ–6³×²†WfVçB’Óâ°¢6öç7B&÷t6öçF–æW"ÒWfVçBæ7W'&VçEF&vWBæ6Æ÷6W7B‚ræ–GB×&WòÖf–æF–ær×&÷rr“°¢6öç7BÖVçUG&–vvW"Ò&÷t6öçF–æW#òçVW'•6VÆV7F÷#Ä…DÔÄ'WGFöäVÆVÖVçCâ€¢ræ–GB×&WòÖf–æF–ærÖÖVçR×G&–vvW"p¢“°¢&WVW7DFVÆWFTf–æF–ær†f–æF–ærÂÖVçUG&–vvW"“°¢×Ð¢à¢ÅG&6ƒ"6—¦S×³WÒ7G&ö¶Uv–GFƒ×³'Ò&–Ö†–FFVãÒ'G'VR"óà¢FVÆWFP¢Âö'WGFöãà¢ÂöF—cà¢’¢çVÆÇÐ¢ÂöF—cà¢’¢çVÆÇÐ¢ÂöF—cà¢“°¢Ò—Ð¢ÂöF—cà¢ÂöFWF–Ç3à¢’—Ð¢ÂöF—cà¢ÂöFWF–Ç3à¢’—Ð¢ÂöF—cà¢ÂöFWF–Ç3à¢“°¢Ò—Ð¢ÂöF—cà¢—Ð¢ÂöF—cà¢ÂöF—cà ¢¶f–æF–ætFWF–Ä÷Vâbb6VÆV7FVDf–æF–ærò€¢ÆF—`¢6Æ74æÖSÒ&–GBÖÖöFÂÖ&6¶G&÷–GB×&WòÖf–æF–ærÖÖöFÂÖ&6¶G&÷ ¢&öÆSÒ'&W6VçFF–öâ ¢öäÖ÷W6TF÷vã×²†WfVçB’Óâ°¢–b†WfVçBçF&vWBÓÓÒWfVçBæ7W'&VçEF&vWB’°¢6Æ÷6Tf–æF–ætFWF–Â‚“°¢Ð¢×Ð¢à¢Ç6V7F–öà¢&–ÖÖöFÃÒ'G'VR ¢&–ÖÆ&VÆÆVF'“Ò'&WòÖf–æF–ærÖFWF–Â×F—FÆR ¢6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖFWF–ÂÖÖöFÂ ¢&Vc×¶f–æF–ætFWF–ÄÖöFÅ&VgÐ¢&öÆSÒ&F–Æör ¢F$–æFWƒ×²ÓÐ¢öä¶W”F÷vã×¶†æFÆTf–æF–ætFWF–ÄÖöFÄ¶W”F÷vçÐ¢öäÖ÷W6TF÷vã×²†WfVçB’ÓâWfVçBç7F÷&÷vF–öâ‚—Ð¢à¢Æ†VFW"6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖFWF–ÂÖÖöFÂÖ†VFW"#à¢ÆF—b6Æ74æÖSÒ&–GB×6÷W&6RÖ6öæf–r×F—FÆR#à¢Å6÷W&6TÆövôÖ&²&÷f–FW#Ò&v—F‡V""6Æ74æÖSÒ&—2Ö†W&ò"óà¢ÆF—cà¢Ç6Æ74æÖSÒ&–GBÖÖ¶–6¶W"#äf–æF–ærFWF–ÃÂ÷à¢Æƒ2–CÒ'&WòÖf–æF–ærÖFWF–Â×F—FÆR#ç·6VÆV7FVDf–æF–ærçF—FÆWÓÂöƒ3à¢Çç·6VÆV7FVDf–æF–æræ‡VÖå÷7VÖÖ'—ÓÂ÷à¢ÂöF—cà¢ÂöF—cà¢Æ'WGFöà¢&Vc×¶f–æF–ætFWF–Ä6Æ÷6U&VgÐ¢6Æ74æÖSÒ&–GBÖW62Ö6Æ÷6R–GB×&WòÖf–æF–ærÖÖöFÂÖ6Æ÷6R ¢G—SÒ&'WGFöâ ¢&–ÖÆ&VÃÒ$6Æ÷6Rf–æF–ærFWF–Â ¢WFôfö7W0¢öä6Æ–6³×²‚’Óâ6Æ÷6Tf–æF–ætFWF–Â‚—Ð¢à¢U40¢Âö'WGFöãà¢Âö†VFW#à ¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖFWF–ÂÖÖöFÂÖ&öG’#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖFWF–Â×–ÆÇ2"&–ÖÆ&VÃÒ$f–æF–ær7FGW27VÖÖ'’#à¢Ç7â6Æ74æÖS×·&Wôf–æF–æu6WfW&—G”6Æ72‡6VÆV7FVDf–æF–ærç6WfW&—G’—Óà¢¶f÷&ÖEFö¶VäÆ&VÂ‡6VÆV7FVDf–æF–ærç6WfW&—G’—Ð¢Â÷7ãà¢Ç7â6Æ74æÖS×·&Wôf–æF–æu7FGW46Æ72†æ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2‡6VÆV7FVDf–æF–æræÆ–fV7–6ÆU÷7FGW2’—Óà¢¶f÷&ÖEFö¶VäÆ&VÂ†æ÷&ÖÆ—¦U&Wôf–æF–ætÆ–fV7–6ÆU7FGW2‡6VÆV7FVDf–æF–æræÆ–fV7–6ÆU÷7FGW2’—Ð¢Â÷7ãà¢Ç7ãç¶6öæf–FVæ6RG¶f÷&ÖD6öæf–FVæ6U66÷&R‡6VÆV7FVDf–æF–æræ6öæf–FVæ6U÷66÷&R—ÖÓÂ÷7ãà¢ÂöF—cà ¢ÆFÂ6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖf7G2#à¢ÆF—cà¢ÆGCå&W÷6—F÷'“ÂöGCà¢ÆFCç¶6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡&Wôf–æF–æu&W÷6—F÷'•fÇVR‡6VÆV7FVDf–æF–ærÂ&Wõ66ç4'””B’’ÇÂuVæf–Æ&ÆRwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå66âFFSÂöGCà¢ÆFCç·&Wôf–æF–æu66äFFTÆ&VÂ‡6VÆV7FVDf–æF–ærÂ&Wõ66ç4'””B—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäÆö6F–öãÂöGCà¢ÆFCç·&Wôf–æF–ætÆö6F–öäÆ&VÂ‡6VÆV7FVDf–æF–ær—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCä6öÖÖ—CÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræ6öÖÖ—BÇÂuVæf–Æ&ÆRwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCä÷væW#ÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræ÷væW"ÇÂ6VÆV7FVDf–æF–ærçG&–vSòæ76–væVRÇÂuVæ76–væVBwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCåG&–vR7FGW3ÂöGCà¢ÆFCç¶f÷&ÖEFö¶VäÆ&VÂ†æ÷&ÖÆ—¦Tf–æF–æu7FGW2‡6VÆV7FVDf–æF–ærçG&–vSòç7FGW2’—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäf—'7B6VVãÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræf—'7E÷6VVåöBòf÷&ÖDFFTÆ&VÂ‡6VÆV7FVDf–æF–æræf—'7E÷6VVåöB’¢f÷&ÖDFFTÆ&VÂ‡6VÆV7FVDf–æF–æræ7&VFVEöB—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäÆ7B6VVãÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræÆ7E÷6VVåöBòf÷&ÖDFFTÆ&VÂ‡6VÆV7FVDf–æF–æræÆ7E÷6VVåöB’¢f÷&ÖDFFTÆ&VÂ‡6VÆV7FVDf–æF–æræ7&VFVEöB—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäf—†VBCÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræf—†VEöBòf÷&ÖDFFTÆ&VÂ‡6VÆV7FVDf–æF–æræf—†VEöB’¢tæ÷Bf—†VB–WBwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäFWFV7F÷#ÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræFWFV7F÷"òf÷&ÖEFö¶VäÆ&VÂ‡6VÆV7FVDf–æF–æræFWFV7F÷"’¢uVæf–Æ&ÆRwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäÆ7BG&–vRWFFSÂöGCà¢ÆFCç·6VÆV7FVDf–æF–ærçG&–vSòçWFFVEöBòf÷&ÖDFFTÆ&VÂ‡6VÆV7FVDf–æF–ærçG&–vRçWFFVEöB’¢tæWfW"wÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå6÷W&6SÂöGCà¢ÆFCç·6VÆV7FVDf–æF–æræFFW%÷6÷W&6RÇÂvæF—fRwÓÂöFCà¢ÂöF—cà¢ÂöFÃà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖFWF–Â×6V7F–öâ#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×6V7F–öâÖ†VB#à¢ÆF—cà¢ÆƒCäWf–FVæ6SÂöƒCà¢Çç·&Wôf–æF–ætÆö6F–öäÆ&VÂ‡6VÆV7FVDf–æF–ær—ÓÂ÷à¢ÂöF—cà¢·6VÆV7FVDf–æF–ærç6÷W&6U÷W&Âò€¢Æ6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’"‡&Vc×·6VÆV7FVDf–æF–ærç6÷W&6U÷W&ÇÒF&vWCÒ%ö&Ææ²"&VÃÒ&æ÷&VfW'&W"#à¢ÄW‡FW&æÄÆ–æ²6—¦S×³GÒ7G&ö¶Uv–GFƒ×³'Ò&–Ö†–FFVãÒ'G'VR"óà¢÷Vâ–âv—D‡V ¢Âöà¢’¢çVÆÇÐ¢ÂöF—cà¢·6VÆV7FVDf–æF–ærç6÷W&6U÷W&Âò€¢Æ6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖÆ–æ²"‡&Vc×·6VÆV7FVDf–æF–ærç6÷W&6U÷W&ÇÒF&vWCÒ%ö&Ææ²"&VÃÒ&æ÷&VfW'&W"#à¢·6VÆV7FVDf–æF–ærç6÷W&6U÷W&ÇÐ¢Âöà¢’¢€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B#äv—D‡V"Æ–æRÆ–æ²Væf–Æ&ÆRf÷"F†—2f–æF–ærâ&W66âF†R&W÷6—F÷'’Fò&Vg&W6‚Æ–æRÖÆ–æ²ÖWFFFãÂöF—cà¢—Ð¢·6VÆV7FVDf–æF–æræÆ–æU÷6æ—WBò€¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ6öFR#à¢Ç7â6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖ6öFRÖÆ&VÂ#äWf–FVæ6RÆ–æSÂ÷7ãà¢Ç&Sà¢Æ6öFSç·&VæFW%&Wôf–æF–ætÆ–æU6æ—WB‡6VÆV7FVDf–æF–æræÆ–æU÷6æ—WB—ÓÂö6öFSà¢Â÷&Sà¢ÂöF—cà¢’¢çVÆÇÐ¢Â÷6V7F–öãà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GB×&WòÖf–æF–ærÖFWF–Â×6V7F–öâ–GB×&WòÖf–æF–ær×&VÖVF–F–öâ#à¢ÆƒCå&VÖVF–F–öãÂöƒCà¢Çç·6VÆV7FVDf–æF–ærç&VÖVF–F–öçÓÂ÷à¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâfö–B†æFÆTÆöE&VÖVF–F–öå&Wf–Wr‚—Ð¢F—6&ÆVC×·&VÖVF–F–öå&Wf–WtÆöF–æwÐ¢à¢·&VÖVF–F–öå&Wf–WtÆöF–æròtÆöF–ær&VÖVF–F–öââââr¢u&Wf–Wr&VÖVF–F–öâÆâwÐ¢Âö'WGFöãà¢·&VÖVF–F–öå&Wf–WtW'&÷"ò€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·&VÖVF–F–öå&Wf–WtW'&÷'ÓÂöF—cà¢’¢çVÆÇÐ¢¶7F—fU&VÖVF–F–öå&Wf–Wrò€¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâ×&Wf–Wr#à¢ÆƒSç¶7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç7VÖÖ'—ÓÂöƒSà¢Çç¶7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç&—6µ÷7VÖÖ'—ÓÂ÷à¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâ×&Wf–WrÖw&–B#à¢ÆF—cà¢Ç7G&öæså7FW3Â÷7G&öæsà¢ÇVÃà¢²†7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç7FW2óòµÒ’æÖ‚‡7FW’Óâ€¢ÆÆ’¶W“×·7FWÓç·7FWÓÂöÆ“à¢’—Ð¢Â÷VÃà¢ÂöF—cà¢ÆF—cà¢Ç7G&öæsåfÆ–FF–öãÂ÷7G&öæsà¢ÇVÃà¢²†7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâçfÆ–FF–öâóòµÒ’æÖ‚†—FVÒ’Óâ€¢ÆÆ’¶W“×¶—FV×Óç¶—FV×ÓÂöÆ“à¢’—Ð¢Â÷VÃà¢ÂöF—cà¢ÂöF—cà¢²†7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç6fWG•öæ÷FW2óòµÒ’æÆVæwF‚âò€¢ÆF—cà¢Ç7G&öæså6fWG’æ÷FW3Â÷7G&öæsà¢ÇVÃà¢²†7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâç6fWG•öæ÷FW2óòµÒ’æÖ‚†æ÷FR’Óâ€¢ÆÆ’¶W“×¶æ÷FWÓç¶æ÷FWÓÂöÆ“à¢’—Ð¢Â÷VÃà¢ÂöF—cà¢’¢çVÆÇÐ¢Çà¢¶7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâçV&Æ—6†&ÆP¢òtFWFW&Ö–æ—7F–2f—‚'&æ6‚6â&R&W&VBf÷"F†—2f–æF–ærâp¢¢7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâçV&Æ—6…ö&Æö6¶VE÷&V6öâÇÂtÖçVÂ&VÖVF–F–öâ—2&WV—&VBâwÐ¢Â÷à¢¶7F—fU&VÖVF–F–öå&Wf–Wrç&VÖVF–F–öâçV&Æ—6†&ÆRò€¢ÆF—b6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâ×V&Æ—6‚#à¢·&VÖVF–F–öåV&Æ—6„W'&÷"ò€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷"#ç·&VÖVF–F–öåV&Æ—6„W'&÷'ÓÂöF—cà¢’¢çVÆÇÐ¢·&VÖVF–F–öåV&Æ—6…&W7VÇBò€¢ÆF—b6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'B×7V66W72#à¢"7·&VÖVF–F–öåV&Æ—6…&W7VÇBçV&Æ—6‚ç%öçVÖ&W'Ò÷VæVBöç²rwÐ¢·&VÖVF–F–öåV&Æ—6…&W7VÇBçV&Æ—6‚æ'&æ6…öæÖWÒç²rwÐ¢Æ‡&Vc×·&VÖVF–F–öåV&Æ—6…&W7VÇBçV&Æ—6‚ç%÷W&ÇÒF&vWCÒ%ö&Ææ²"&VÃÒ&æ÷&VfW'&W"#à¢f–Wr ¢Âöà¢ÂöF—cà¢’¢çVÆÇÐ¢ÆÆ&VÃà¢&6R'&æ6€¢Æ–çW@¢G—SÒ'FW‡B ¢fÇVS×·&VÖVF–F–öåV&Æ—6„&6T'&æ6‡Ð¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6„&6T'&æ6‚†WfVçBçF&vWBçfÇVR—Ð¢Æ6V†öÆFW#Ò&Ö–â ¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢7W'&VçB6÷W&6R6öçFVç@¢ÇFW‡F&V¢fÇVS×·&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçGÐ¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6…6÷W&6T6öçFVçB†WfVçBçF&vWBçfÇVR—Ð¢&÷w3×³gÐ¢7VÆÄ6†V6³×¶fÇ6WÐ¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢v—D‡V"Fö¶Và¢Æ–çW@¢G—SÒ'77v÷&B ¢fÇVS×·&VÖVF–F–öåV&Æ—6…Fö¶VçÐ¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6…Fö¶Vâ†WfVçBçF&vWBçfÇVR—Ð¢WFô6ö×ÆWFSÒ&öfb ¢óà¢ÂöÆ&VÃà¢ÆÆ&VÂ6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâÖ&÷fÂ#à¢Æ–çW@¢G—SÒ&6†V6¶&÷‚ ¢6†V6¶VC×·&VÖVF–F–öåV&Æ—6„&÷fVGÐ¢öä6†ævS×²†WfVçB’Óâ6WE&VÖVF–F–öåV&Æ—6„&÷fVB†WfVçBçF&vWBæ6†V6¶VB—Ð¢óà¢Ç7ãä&÷fVBf÷"V&Æ—6ƒÂ÷7ãà¢ÂöÆ&VÃà¢ÆÆ&VÂ6Æ74æÖSÒ&–GB×&Wò×&VÖVF–F–öâÖ&÷fÂ#à¢Æ–çW@¢G—SÒ&6†V6¶&÷‚ ¢6†V6¶VC×·&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVGÐ¢öä6†ævS×²†WfVçB’Óà¢6WE&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖVB†WfVçBçF&vWBæ6†V6¶VB¢Ð¢óà¢Ç7ãäv—D‡V"Fö¶Vâ—2–çFVçF–öæÆÇ’w&—FRÖ6&ÆSÂ÷7ãà¢ÂöÆ&VÃà¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ'Fâ ¢G—SÒ&'WGFöâ ¢öä6Æ–6³×²‚’Óâfö–B†æFÆUV&Æ—6…&VÖVF–F–öâ‚—Ð¢F—6&ÆVC×°¢&VÖVF–F–öåV&Æ—6„ÆöF–ærÇÀ¢&VÖVF–F–öåV&Æ—6„&÷fVBÇÀ¢&VÖVF–F–öåV&Æ—6…w&—FUW&×46öæf—&ÖV@¢Ð¢à¢·&VÖVF–F–öåV&Æ—6„ÆöF–æròuV&Æ—6†–ærâââr¢uV&Æ—6‚f—‚"wÐ¢Âö'WGFöãà¢ÂöF—cà¢’¢çVÆÇÐ¢ÂöF—cà¢’¢çVÆÇÐ¢Â÷6V7F–öãà ¢ÂöF—cà¢Â÷6V7F–öãà¢ÂöF—cà¢’¢çVÆÇÐ ¢¶7F—fTFVÆWFT6æF–FFW2æÆVæwF‚âò€¢ÆF—`¢6Æ74æÖSÒ&–GBÖÖöFÂÖ&6¶G&÷–GB×&WòÖf–æF–ærÖFVÆWFRÖ&6¶G&÷ ¢&öÆSÒ'&W6VçFF–öâ ¢öäÖ÷W6TF÷vã×²†WfVçB’Óâ°¢–b†WfVçBçF&vWBÓÓÒWfVçBæ7W'&VçEF&vWBbbFVÆWFTÆöF–ær’°¢6Æ÷6Tf–æF–ætFVÆWFTF–Æör‚“°¢Ð¢×Ð¢à¢Ç6V7F–öà¢&–ÖÖöFÃÒ'G'VR ¢&–ÖÆ&VÆÆVF'“Ò'&WòÖf–æF–ærÖFVÆWFR×F—FÆR ¢6Æ74æÖSÒ&–GBÖFævW"ÖÖöFÂ–GB×&WòÖf–æF–ærÖFVÆWFRÖÖöFÂ ¢&Vc×¶f–æF–ætFVÆWFTÖöFÅ&VgÐ¢&öÆSÒ&F–Æör ¢F$–æFWƒ×²ÓÐ¢öä¶W”F÷vã×¶†æFÆTf–æF–ætFVÆWFTÖöFÄ¶W”F÷vçÐ¢öäÖ÷W6TF÷vã×²†WfVçB’ÓâWfVçBç7F÷&÷vF–öâ‚—Ð¢à¢Æ†VFW#à¢ÆF—cà¢Æƒ2–CÒ'&WòÖf–æF–ærÖFVÆWFR×F—FÆR#ç¶'VÆ´FVÆWFT7F—fRòt6ÆV"f–æF–æw3òr¢tFVÆWFRf–æF–æsòwÓÂöƒ3à¢ÂöF—cà¢Âö†VFW#à¢ÆF—b6Æ74æÖSÒ&–GBÖFævW"ÖÖöFÂÖ&öG’#à¢¶'VÆ´FVÆWFT7F—fRò€¢ÇäFVÆWFR¶f÷&ÖD6÷VçDÆ&VÂ†7F—fTFVÆWFT6æF–FFW2æÆVæwF‚Âwf—6–&ÆRf–æF–ærr—ÒãÂ÷à¢’¢€¢Çà¢&VÖ÷fRÇ7G&öæsç¶7F—fTFVÆWFT6æF–FFW5³ÓòçF—FÆWÓÂ÷7G&öæsâà¢Â÷à¢—Ð¢Ç6Æ74æÖSÒ&–GBÖFævW"ÖÖöFÂÖ†VÇ#à¢gWGW&R66ç26â&VF—66÷fW"F†R6ÖR&—6²à¢Â÷à¢¶FVÆWFTW'&÷"òÆF—b6Æ74æÖSÒ&–GBÖFævW"ÖÖöFÂÖW'&÷"#ç¶FVÆWFTW'&÷'ÓÂöF—câ¢çVÆÇÐ¢ÆF—b6Æ74æÖSÒ&–GBÖFævW"ÖÖöFÂÖ7F–öç2#à¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢&Vc×¶f–æF–ætFVÆWFT6Æ÷6U&VgÐ¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢öä6Æ–6³×²‚’Óâ6Æ÷6Tf–æF–ætFVÆWFTF–Æör‚—Ð¢F—6&ÆVC×¶FVÆWFTÆöF–æwÐ¢à¢6æ6VÀ¢Âö'WGFöãà¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖFævW" ¢öä6Æ–6³×²‚’Óâfö–B†æFÆT6öæf—&ÔFVÆWFTf–æF–ær‚—Ð¢F—6&ÆVC×¶FVÆWFTÆöF–æwÐ¢à¢¶FVÆWFTÆöF–æròtFVÆWF–ærâââr¢'VÆ´FVÆWFT7F—fRòtFVÆWFRÆÂr¢tFVÆWFRwÐ¢Âö'WGFöãà¢ÂöF—cà¢ÂöF—cà¢Â÷6V7F–öãà¢ÂöF—cà¢’¢çVÆÇÐ ¢ÆFWF–Ç26Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB–GB×&WòÖæÇ—6—2×æVÂ"&–ÖÆ&VÃÒ%&W÷6—F÷'’&—6²w&‚7VÖÖ'’#à¢Ç7VÖÖ'’6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖ†VB#à¢Æƒ3å&—6²w&ƒÂöƒ3à¢·G&VæDF—7Æ”ÆöF–æròÇ7â6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'B×7V66W72#äÆöF–ærw&ƒÂ÷7ãâ¢çVÆÇÐ¢Ç7â6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB×7V'F—FÆR#à¢·f—6–&ÆU&Wõ&—6´w&€¢òG·f—6–&ÆU&Wõ&—6´w&‚ææöFW2æÆVæwF‡ÒæöFW2+rG·f—6–&ÆU&Wõ&—6´w&‚æVFvW2æÆVæwF‡ÒF‡2+rG¶6æöæ–6Äv—D‡V%&W÷6—F÷'”F—7Æ’‡f—6–&ÆU&Wõ&—6´w&‚ç&W÷6—F÷'’’ÇÂf—6–&ÆU&Wõ&—6´w&‚ç&W÷6—F÷'’ÇÂw&W÷6—F÷'’66÷RwÖ ¢¢&—6´w&„†–FFVä'”f–ÇFW'0¢òt†–FFVâf÷"7W'&VçBf–ÇFW'2p¢¢tæòw&‚ÆöFVB–WBwÐ¢Â÷7ãà¢Â÷7VÖÖ'“à¢·&—6´w&…7VÖÖ'’ò€¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB×&÷w2#à¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB×&÷r#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖÖWF#à¢Ç7ãä†–v‚×&—6²f–æF–æw3Â÷7ãà¢Ç7G&öæsç·&—6´w&…7VÖÖ'’æ†–v…÷&—6µöf–æF–æw7ÓÂ÷7G&öæsà¢ÂöF—cà¢Çà¢·&—6´w&…7VÖÖ'’æ7&—F–6Åöf–æF–æw7Ò7&—F–6Â+r·&—6´w&…Væ¶æ÷väWf–FVæ6T6÷VçGÒVæ¶æ÷vâWf–FVæ6Rv0¢Â÷à¢Âö'F–6ÆSà¢·F÷&—6´w&…66÷&W2æÆVæwF‚âò€¢F÷&—6´w&…66÷&W2æÖ‚‡66÷&R’Óâ€¢Æ'F–6ÆR¶W“×·66÷&Ræf–æF–æuö–GÒ6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB×&÷r#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖÖWF#à¢Ç7ãç·66÷&Ræf–æF–æuö–GÓÂ÷7ãà¢Ç7G&öæsç´ÖF‚ç&÷VæB‡66÷&Rç66÷&R—ÓÂ÷7G&öæsà¢ÂöF—cà¢Çà¢¶f÷&ÖEFö¶VäÆ&VÂ‡66÷&Rç6WfW&—G’—Ò+r6öæf–FVæ6R¶f÷&ÖD6öæf–FVæ6U66÷&R‡66÷&Ræ6öæf–FVæ6R—Ð¢²‡66÷&RçVæ¶æ÷vç2óòµÒ’æÆVæwF‚â ¢ò+rVæ¶æ÷vâG²‡66÷&RçVæ¶æ÷vç2óòµÒ’æÖ†f÷&ÖEFö¶VäÆ&VÂ’æ¦ö–â‚rÂr—Ö ¢¢rwÐ¢Â÷à¢Âö'F–6ÆSà¢’¢’¢€¢Æ'F–6ÆR6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB×&÷r#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖÖWF#à¢Ç7ãäæò66÷&VBf–æF–æw3Â÷7ãà¢Ç7G&öæsç·&—6´w&…7VÖÖ'’æf–æF–æuö6÷VçGÓÂ÷7G&öæsà¢ÂöF—cà¢Çå&—6²66÷&W2v–ÆÂV"gFW"w&‚Wf–FVæ6R—2f–Æ&ÆRf÷"&W÷6—F÷'’f–æF–æw2ãÂ÷à¢Âö'F–6ÆSà¢—Ð¢ÂöF—cà¢’¢€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ%&—6²w&‚Væf–Æ&ÆR ¢&öG“×·&—6´w&…Væf–Æ&ÆT&öG—Ð¢óà¢—Ð¢ÂöFWF–Ç3à ¢ÆFWF–Ç26Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB–GB×&WòÖæÇ—6—2×æVÂ#à¢Ç7VÖÖ'’6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖ†VB#à¢Æƒ3äf–æF–ærG&VæCÂöƒ3à¢·G&VæDF—7Æ”ÆöF–æròÇ7â6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'B×7V66W72#äÆöF–ærG&VæCÂ÷7ãâ¢çVÆÇÐ¢Ç7â6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB×7V'F—FÆR#ç·F÷FÅG&VæD—FV×2âòG·F÷FÅG&VæD—FV×7ÒF÷FÂWfVçG2–âv–æF÷v¢tæòG&VæB—FV×2–WBwÓÂ÷7ãà¢Â÷7VÖÖ'“à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB×&÷w2#à¢·F÷FÅG&VæD—FV×2ÓÓÒò€¢Ä6†VÆÄV×G•7FFP¢F—FÆSÒ$æòG&VæB–WB ¢&öG“Ò%G&VæB6æ6†÷G2v—F‚6WfW&—G’F—7G&–'WF–öâv–ÆÂV"†W&Röæ6R66â&öGV6W2f–æF–æw2â ¢óà¢’¢€¢G&VæE&÷w2æÖ‚‡&÷r’Óâ€¢Æ'F–6ÆR¶W“×·&÷ræ¶W—Ò6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæB×&÷r#à¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖÖWF#à¢Ç7ãç·&÷ræÆ&VÇÓÂ÷7ãà¢Ç7G&öæsç·&÷rçF÷FÇÓÂ÷7G&öæsà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖ&"×G&6²"&öÆSÒ&–Ör"&–ÖÆ&VÃ×¶G&VæBö–çBG·&÷ræÆ&VÇÖÓà¢ÆF—b6Æ74æÖSÒ&–GB×&WòÖf–æF–ær×G&VæBÖ&""7G–ÆS×·²v–GFƒ¢G·&÷rçW&6VçFvWÒV×Òóà¢ÂöF—cà¢Çà¢¶7&—F–6ÂG·&÷ræ7&—F–6ÇÒò†–v‚G·&÷ræ†–v‡ÒòÖVF—VÒG·&÷ræÖVF—V×ÒòÆ÷rG·&÷ræÆ÷wÒò–æfòG·&÷ræ–æf÷ÖÐ¢Â÷à¢Âö'F–6ÆSà¢’¢—Ð¢ÂöF—cà¢ÂöFWF–Ç3à¢Â÷6V7F–öãà¢“°§Ð ¢òò&WVW7DFFW‡÷'BG&—fW2F†R$F÷væÆöB×’FF"Æ–fV7–6ÆR‚3C#“¢VçVWVP¢òòF†RW‡÷'B¦ö"ÂF†VâöÆÂVçF–ÂF†R'VæFÆR&V6†W2FW&Ö–æÂ7FFRà§G—RW‡÷'E6WGFW'2Ò°¢6–væÃ¢&÷'E6–væÃ°¢6WDW‡÷'EVæF–æs¢‡fÇVS¢&ööÆVâ’Óâfö–C°¢6WDW‡÷'DW'&÷#¢‡fÇVS¢7G&–ær’Óâfö–C°¢6WDW‡÷'E7FGW3¢€¢fÇVS ¢Â²¶–æC¢v–FÆRrÐ¢Â²¶–æC¢w&W&–ærs²ÖW76vS¢7G&–ærÐ¢Â²¶–æC¢w&VG’s²F÷væÆöEU$Ã¢7G&–æs²W‡—&W4Có¢7G&–ærÐ¢’Óâfö–C°§Ó° ¦gVæ7F–öâ&W6öÇfTFFW‡÷'DF÷væÆöEU$Â†F÷væÆöEU$Ã¢7G&–ær“¢7G&–ær°¢–b‚õæ‡GG3ó¥ÂõÂòö’çFW7B†F÷væÆöEU$Â’’°¢&WGW&âF÷væÆöEU$Ã°¢Ð¢&WGW&â'V–ÆD•U$Â†F÷væÆöEU$Â“°§Ð ¦gVæ7F–öâW‡÷'D&÷'DW'&÷"‚“¢W'&÷"°¢6öç7BW'"ÒæWrW'&÷"‚tFFW‡÷'BöÆÆ–ærv26æ6VÆVBâr“°¢W'"ææÖRÒt&÷'DW'&÷"s°¢&WGW&âW'#°§Ð ¦gVæ7F–öâ—4&÷'DW'&÷"†W'#¢Væ¶æ÷vâ“¢&ööÆVâ°¢&WGW&âW'"–ç7Fæ6VöbW'&÷"bbW'"ææÖRÓÓÒt&÷'DW'&÷"s°§Ð ¦gVæ7F–öâf÷&ÖDFFW‡÷'DW'&÷"†W'#¢Væ¶æ÷vâ“¢7G&–ær°¢–b€¢W'"–ç7Fæ6Vöb”W'&÷"b`¢‚†W'"ç7FGW2ÓÓÒCBbbW'"ç–ÆöBÓÓÒVæFVf–æVB’ÇÀ¢†W'"ç7FGW2ÓÓÒS2bböFFW‡÷'B—2æ÷B6öæf–wW&VBö’çFW7B†W'"æÖW76vR’’¢’°¢&WGW&âtFFW‡÷'B—2æ÷Bf–Æ&ÆRöâF†—2FWÆ÷–ÖVçB–WBâs°¢Ð¢&WGW&âW'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFò7F'BF†RW‡÷'Bâs°§Ð ¦gVæ7F–öâv—Df÷$W‡÷'EöÆÂ‡6–væÃ¢&÷'E6–væÂÂFVÆ”×3¢çVÖ&W"“¢&öÖ—6SÇfö–Câ°¢–b‡6–væÂæ&÷'FVB’°¢&WGW&â&öÖ—6Rç&V¦V7B†W‡÷'D&÷'DW'&÷"‚’“°¢Ð¢&WGW&âæWr&öÖ—6R‚‡&W6öÇfRÂ&V¦V7B’Óâ°¢ÆWBF–ÖV÷WBÒ°¢6öç7B&÷'BÒ‚’Óâ°¢v–æF÷ræ6ÆV%F–ÖV÷WB‡F–ÖV÷WB“°¢&V¦V7B†W‡÷'D&÷'DW'&÷"‚’“°¢Ó°¢F–ÖV÷WBÒv–æF÷rç6WEF–ÖV÷WB‚‚’Óâ°¢6–væÂç&VÖ÷fTWfVçDÆ—7FVæW"‚v&÷'BrÂ&÷'B“°¢&W6öÇfR‚“°¢ÒÂFVÆ”×2“°¢6–væÂæFDWfVçDÆ—7FVæW"‚v&÷'BrÂ&÷'BÂ²öæ6S¢G'VRÒ“°¢Ò“°§Ð ¦7–æ2gVæ7F–öâ&WVW7DFFW‡÷'B‡²6–væÂÂ6WDW‡÷'EVæF–ærÂ6WDW‡÷'DW'&÷"Â6WDW‡÷'E7FGW2Ó¢W‡÷'E6WGFW'2’°¢–b‡6–væÂæ&÷'FVB’°¢&WGW&ã°¢Ð¢6WDW‡÷'EVæF–ær‡G'VR“°¢6WDW‡÷'DW'&÷"‚rr“°¢6WDW‡÷'E7FGW2‡²¶–æC¢w&W&–ærrÂÖW76vS¢u&W&–ær–÷W"FFW‡÷'N(
brÒ“°¢G'’°¢6öç7B¦ö"Òv—B”6Æ–VçBæVçVWVTFFW‡÷'B‡²6–væÂÒ“°¢ÆWB7W'&VçBÒ¦ö#°¢òò¶VWöÆÆ–ærVçF–Â&6¶VæB&V6†W2FW&Ö–æÂ7FFR6ò¦ö'2F†B&R6–×Ç¢òò6Æ÷vW"F†âW‡V7FVB7F’&V6†&ÆRæB6â7F–ÆÂ&RF÷væÆöFVBv†Vâ&VG’à¢6öç7BÆöæuöÆÆ–æuF‡&W6†öÆBÒ3°¢ÆWBGFV×BÒ°¢v†–ÆR€¢7W'&VçBç7FGW2ÓÒw&VG’rb`¢7W'&VçBç7FGW2ÓÒvf–ÆVBrb`¢7W'&VçBç7FGW2ÓÒvW‡—&VBp¢’°¢–b†GFV×Bâ’°¢v—Bv—Df÷$W‡÷'EöÆÂ‡6–væÂÂ“°¢Ð¢GFV×B³Ò°¢7W'&VçBÒv—B”6Æ–VçBævWDFFW‡÷'B†7W'&VçBæ–BÂ²6–væÂÒ“°¢–b†GFV×BÓÓÒÆöæuöÆÆ–æuF‡&W6†öÆB²’°¢6WDW‡÷'E7FGW2‡²¶–æC¢w&W&–ærrÂÖW76vS¢uF†RW‡÷'B—2F¶–ærÆöævW"F†âW‡V7FVC²6öçF–çV–ærFò6†V6²VçF–Â6ö×ÆWFRârÒ“°¢Ð¢Ð¢–b‡6–væÂæ&÷'FVB’°¢&WGW&ã°¢Ð¢–b†7W'&VçBç7FGW2ÓÓÒw&VG’rbb7W'&VçBæF÷væÆöE÷W&Â’°¢6öç7BF÷væÆöEU$ÂÒ&W6öÇfTFFW‡÷'DF÷væÆöEU$Â†7W'&VçBæF÷væÆöE÷W&Â“°¢6WDW‡÷'E7FGW2‡°¢¶–æC¢w&VG’rÀ¢F÷væÆöEU$ÂÀ¢W‡—&W4C¢7W'&VçBæF÷væÆöEöW‡—&W5ö@¢Ò“°¢òòWFò×G&–vvW"F†R'&÷w6W"F÷væÆöB6òF†RW6W"FöW2æ÷B†fRFð¢òò‡VçBf÷"F†RÆ–æ²öâF†RvRà¢6öç7BÆ–æ²ÒFö7VÖVçBæ7&VFTVÆVÖVçB‚vr“°¢Æ–æ²æ‡&VbÒF÷væÆöEU$Ã°¢Æ–æ²ç&VÂÒvæö÷VæW"æ÷&VfW'&W"s°¢Fö7VÖVçBæ&öG’æVæD6†–ÆB†Æ–æ²“°¢Æ–æ²æ6Æ–6²‚“°¢Æ–æ²ç&VÖ÷fR‚“°¢ÒVÇ6R–b†7W'&VçBç7FGW2ÓÓÒvf–ÆVBr’°¢6WDW‡÷'E7FGW2‡²¶–æC¢v–FÆRrÒ“°¢6WDW‡÷'DW'&÷"†7W'&VçBæW'&÷%öÖW76vRÇÂuF†RW‡÷'Bf–ÆVBâÆV6RG'’v–ââr“°¢ÒVÇ6R–b†7W'&VçBç7FGW2ÓÓÒvW‡—&VBr’°¢6WDW‡÷'E7FGW2‡²¶–æC¢v–FÆRrÒ“°¢6WDW‡÷'DW'&÷"‚u–÷W"F÷væÆöBÆ–æ²†2W‡—&VBâÆV6R&WVW7BæWrW‡÷'Bâr“°¢ÒVÇ6R°¢6WDW‡÷'E7FGW2‡²¶–æC¢v–FÆRrÒ“°¢6WDW‡÷'DW'&÷"‚u–÷W"W‡÷'B—2F¶–ærÆöævW"F†âW‡V7FVBâÆV6RG'’v–â–âfWrÖ–çWFW2âr“°¢Ð¢Ò6F6‚†W'"’°¢–b‡6–væÂæ&÷'FVBÇÂ—4&÷'DW'&÷"†W'"’’°¢&WGW&ã°¢Ð¢6WDW‡÷'E7FGW2‡²¶–æC¢v–FÆRrÒ“°¢6WDW‡÷'DW'&÷"†f÷&ÖDFFW‡÷'DW'&÷"†W'"’“°¢Òf–æÆÇ’°¢–b‚6–væÂæ&÷'FVB’°¢6WDW‡÷'EVæF–ær†fÇ6R“°¢Ð¢Ð§Ð ¦gVæ7F–öâ66÷VçDFVÆWF–öåv÷&·76W4g&öÔW'&÷"†W'&÷#¢”W'&÷"“¢66÷VçDFVÆWF–öåv÷&·76UµÒ°¢6öç7B–ÆöBÒW'&÷"ç–ÆöB2²v÷&·76W3ó¢Væ¶æ÷vâÒÂVæFVf–æVC°¢–b‚'&’æ—4'&’‡–ÆöCòçv÷&·76W2’’°¢&WGW&âµÓ°¢Ð¢&WGW&â–ÆöBçv÷&·76W2æf–ÇFW"‚‡v÷&·76R“¢v÷&·76R—266÷VçDFVÆWF–öåv÷&·76RÓâ°¢–b‚v÷&·76RÇÂG—Vöbv÷&·76RÓÒvö&¦V7Br’°¢&WGW&âfÇ6S°¢Ð¢6öç7B&V6÷&BÒv÷&·76R2'F–ÃÄ66÷VçDFVÆWF–öåv÷&·76Sã°¢&WGW&â€¢G—Vöb&V6÷&BçFVæçEö–BÓÓÒw7G&–ærrb`¢&V6÷&BçFVæçEö–BçG&–Ò‚’ÓÒrrb`¢G—Vöb&V6÷&Bçv÷&·76Uö–BÓÓÒw7G&–ærrb`¢&V6÷&Bçv÷&·76Uö–BçG&–Ò‚’ÓÒrp¢“°¢Ò“°§Ð ¦gVæ7F–öâ66÷VçDFVÆWF–öåv÷&·76TÆ&VÂ‡v÷&·76S¢66÷VçDFVÆWF–öåv÷&·76R“¢7G&–ær°¢6öç7BF—7Æ”æÖRÒv÷&·76RæF—7Æ•öæÖSòçG&–Ò‚“°¢6öç7B6ÇVrÒv÷&·76Rç6ÇVsòçG&–Ò‚“°¢&WGW&âF—7Æ”æÖRÇÂ6ÇVrÇÂv÷&·76Rçv÷&·76Uö–C°§Ð ¦gVæ7F–öâ66÷VçDFVÆWF–öå6–vä–åF‚††&DFVÆWFTgFW#ó¢7G&–ær“¢7G&–ær°¢6öç7BVW'’ÒæWrU$Å6V&6…&×2‡²&V6öã¢v66÷VçE÷VæF–æuöFVÆWF–öârÒ“°¢–b††&DFVÆWFTgFW#òçG&–Ò‚’’°¢VW'’ç6WB‚v†&EöFVÆWFUögFW"rÂ†&DFVÆWFTgFW"“°¢Ð¢&WGW&â÷6–væ–ãòG·VW'’çFõ7G&–ær‚—Ö°§Ð ¢òòW‡G&7G2F†RffV7FVBÖÖVÖ&W"'&’g&öÒ6öÆRÖ÷væW"C’–ÆöB6òF†P¢òòFW7G'V7F—fRÖöFÂ6â&VæFW"â–æÆ–æR&Æö6²Æ—7F–ærv†òv÷VÆB&R7G&æFV@¢òòæBFVWÆ–æ²FòF†Rv÷&·76RÖVÖ&W"ÖÖævVÖVçB67&VVâà¦gVæ7F–öâv÷&·76U6öÆT÷væW$ÖVÖ&W'4g&öÔW'&÷"†W'&÷#¢”W'&÷"“¢v÷&·76U6öÆT÷væW$ffV7FVDÖVÖ&W%µÒ°¢6öç7B–ÆöBÒW'&÷"ç–ÆöB2²ffV7FVEöÖVÖ&W'3ó¢Væ¶æ÷vâÒÂVæFVf–æVC°¢–b‚'&’æ—4'&’‡–ÆöCòæffV7FVEöÖVÖ&W'2’’°¢&WGW&âµÓ°¢Ð¢&WGW&â–ÆöBæffV7FVEöÖVÖ&W'2æf–ÇFW"€¢†ÖVÖ&W"“¢ÖVÖ&W"—2v÷&·76U6öÆT÷væW$ffV7FVDÖVÖ&W"Óâ°¢–b‚ÖVÖ&W"ÇÂG—VöbÖVÖ&W"ÓÒvö&¦V7Br’°¢&WGW&âfÇ6S°¢Ð¢6öç7B&V6÷&BÒÖVÖ&W"2'F–ÃÅv÷&·76U6öÆT÷væW$ffV7FVDÖVÖ&W#ã°¢&WGW&â€¢G—Vöb&V6÷&BæÖVÖ&W%ö–BÓÓÒw7G&–ærrb`¢&V6÷&BæÖVÖ&W%ö–BçG&–Ò‚’ÓÒrrb`¢G—Vöb&V6÷&BçW6W%ö–BÓÓÒw7G&–ærrb`¢G—Vöb&V6÷&Bç&öÆRÓÓÒw7G&–ærp¢“°¢Ð¢“°§Ð ¦gVæ7F–öâv÷&·76U6öÆT÷væW$ÖVÖ&W$Æ&VÂ†ÖVÖ&W#¢v÷&·76U6öÆT÷væW$ffV7FVDÖVÖ&W"“¢7G&–ær°¢6öç7BVÖ–ÂÒÖVÖ&W"æVÖ–ÃòçG&–Ò‚“°¢–b†VÖ–Â’°¢&WGW&âG¶VÖ–ÇÒ‚G¶ÖVÖ&W"ç&öÆWÒ–°¢Ð¢&WGW&âG¶ÖVÖ&W"çW6W%ö–BÇÂÖVÖ&W"æÖVÖ&W%ö–GÒ‚G¶ÖVÖ&W"ç&öÆWÒ–°§Ð ¦6öç7BT$ä4UõD„TÔUôõD”ôå3¢'&“Ç°¢–C¢V&æ6UF†VÖTÖöFS°¢Æ&VÃ¢7G&–æs°¢–6öã¢&V7DæöFS°§ÓâÒ°¢²–C¢vÆ–v‡BrÂÆ&VÃ¢tÆ–v‡BrÂ–6öã¢Å7Vâ6—¦S×³WÒ&–Ö†–FFVãÒ'G'VR"óâÒÀ¢²–C¢vF&²rÂÆ&VÃ¢tF&²rÂ–6öã¢ÄÖööâ6—¦S×³WÒ&–Ö†–FFVãÒ'G'VR"óâÒÀ¢²–C¢w7—7FVÒrÂÆ&VÃ¢u7—7FVÒrÂ–6öã¢ÄÖöæ—F÷"6—¦S×³WÒ&–Ö†–FFVãÒ'G'VR"óâÐ¥Ó° ¦6öç7BT$ä4UôÔõD”ôåôõD”ôå3¢'&“Ç²–C¢V&æ6U&VGV6TÖ÷F–öã²Æ&VÃ¢7G&–ærÓâÒ°¢²–C¢w7—7FVÒrÂÆ&VÃ¢u7—7FVÒrÒÀ¢²–C¢vöârÂÆ&VÃ¢töârÒÀ¢²–C¢vöfbrÂÆ&VÃ¢töfbrÐ¥Ó° ¦6öç7BT$ä4UõT•ôdôåEôõD”ôå3¢V&æ6TföçD”EµÒÒ°¢v–çFW"rÀ¢vvV—7BrÀ¢w7—7FVÒrÀ¢w76RÖw&÷FW6²rÀ¢v&&Æ÷rÖ6öæFVç6VBrÀ¢vÖç&÷Rp¥Ó° ¦gVæ7F–öâV&æ6U&W6WD÷F–öç2†ÖöFS¢vÆ–v‡BrÂvF&²r’°¢&WGW&âT$ä4Uõ$U4UE2æf–ÇFW"‚‡&W6WB’Óà¢ÖöFRÓÓÒvÆ–v‡Brò&W6WBæÖöFRÓÓÒvÆ–v‡Br¢&W6WBæÖöFRÓÓÒvF&²rÇÂ&W6WBæÖöFRÓÓÒv&÷F‚p¢“°§Ð §G—RV&æ6U6VvÖVçFVD6öçG&öÅ&÷3ÅBW‡FVæG27G&–æsâÒ°¢Æ&VÃ¢7G&–æs°¢fÇVS¢C°¢÷F–öç3¢'&“Ç²–C¢C²Æ&VÃ¢7G&–æs²–6öãó¢&V7DæöFRÓã°¢öä6†ævS¢†æW‡EfÇVS¢B’Óâfö–C°§Ó° ¦gVæ7F–öâV&æ6U6VvÖVçFVD6öçG&öÃÅBW‡FVæG27G&–æsâ‡°¢Æ&VÂÀ¢fÇVRÀ¢÷F–öç2À¢öä6†ævP§Ó¢V&æ6U6VvÖVçFVD6öçG&öÅ&÷3ÅCâ’°¢&WGW&â€¢ÆF—b6Æ74æÖSÒ&–GBÖV&æ6R×6VvÖVçFVB"&öÆSÒ&w&÷W"&–ÖÆ&VÃ×¶Æ&VÇÓà¢¶÷F–öç2æÖ‚†÷F–öâ’Óâ€¢Æ'WGFöà¢¶W“×¶÷F–öâæ–GÐ¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖV&æ6R×6VvÖVçB ¢&–×&W76VC×·fÇVRÓÓÒ÷F–öâæ–GÐ¢öä6Æ–6³×²‚’Óâöä6†ævR†÷F–öâæ–B—Ð¢à¢¶÷F–öâæ–6öçÐ¢Ç7ãç¶÷F–öâæÆ&VÇÓÂ÷7ãà¢Âö'WGFöãà¢’—Ð¢ÂöF—cà¢“°§Ð §G—RV&æ6U7v—F6…&÷2Ò°¢6†V6¶VC¢&ööÆVã°¢Æ&VÃ¢7G&–æs°¢öä6†ævS¢†6†V6¶VC¢&ööÆVâ’Óâfö–C°§Ó° ¦gVæ7F–öâV&æ6U7v—F6‚‡²6†V6¶VBÂÆ&VÂÂöä6†ævRÓ¢V&æ6U7v—F6…&÷2’°¢&WGW&â€¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖV&æ6R×7v—F6‚ ¢&öÆSÒ'7v—F6‚ ¢&–Ö6†V6¶VC×¶6†V6¶VGÐ¢&–ÖÆ&VÃ×¶Æ&VÇÐ¢öä6Æ–6³×²‚’Óâöä6†ævR‚6†V6¶VB—Ð¢à¢Ç7â6Æ74æÖSÒ&–GBÖV&æ6R×7v—F6‚×F‡VÖ""&–Ö†–FFVãÒ'G'VR"óà¢Ç7â6Æ74æÖSÒ&–GBÖV&æ6R×7v—F6‚ÖÆ&VÂ"&–Ö†–FFVãÒ'G'VR#à¢¶6†V6¶VBòtöâr¢töfbwÐ¢Â÷7ãà¢Âö'WGFöãà¢“°§Ð §G—RV&æ6TçVÖ&W$–çWE&÷2Ò°¢Æ&VÃ¢7G&–æs°¢Öƒ¢çVÖ&W#°¢Ö–ã¢çVÖ&W#°¢öä6öÖÖ—C¢‡fÇVS¢çVÖ&W"’Óâfö–C°¢fÇVS¢çVÖ&W#°§Ó° ¦gVæ7F–öâV&æ6TçVÖ&W$–çWB‡°¢Æ&VÂÀ¢Ö‚À¢Ö–âÀ¢öä6öÖÖ—BÀ¢fÇVP§Ó¢V&æ6TçVÖ&W$–çWE&÷2’°¢6öç7B–çWE&VbÒW6U&VcÄ…DÔÄ–çWDVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7B¶G&gBÂ6WDG&gEÒÒW6U7FFR‚‚’Óâ7G&–ær‡fÇVR’“° ¢W6TVffV7B‚‚’Óâ°¢–b†Fö7VÖVçBæ7F—fTVÆVÖVçBÓÒ–çWE&Vbæ7W'&VçB’°¢6WDG&gB…7G&–ær‡fÇVR’“°¢Ð¢ÒÂ·fÇVUÒ“° ¢6öç7B6öÖÖ—DG&gBÒ‚’Óâ°¢6öç7B'6VBÒçVÖ&W"†G&gB“°¢–b‚çVÖ&W"æ—4f–æ—FR‡'6VB’’°¢6WDG&gB…7G&–ær‡fÇVR’“°¢&WGW&ã°¢Ð¢öä6öÖÖ—B‡'6VB“°¢Ó° ¢&WGW&â€¢Æ–çW@¢&Vc×¶–çWE&VgÐ¢&–ÖÆ&VÃ×¶Æ&VÇÐ¢G—SÒ&çVÖ&W" ¢Ö–ã×¶Ö–çÐ¢Öƒ×¶Ö‡Ð¢fÇVS×¶G&gGÐ¢öä6†ævS×²†WfVçB’Óâ6WDG&gB†WfVçBçF&vWBçfÇVR—Ð¢öä&ÇW#×¶6öÖÖ—DG&gGÐ¢öä¶W”F÷vã×²†WfVçB’Óâ°¢–b†WfVçBæ¶W’ÓÓÒtVçFW"r’°¢6öÖÖ—DG&gB‚“°¢WfVçBæ7W'&VçEF&vWBæ&ÇW"‚“°¢Ð¢–b†WfVçBæ¶W’ÓÓÒtW66Rr’°¢6WDG&gB…7G&–ær‡fÇVR’“°¢WfVçBæ7W'&VçEF&vWBæ&ÇW"‚“°¢Ð¢×Ð¢óà¢“°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7DV&æ6U6WGF–æw5vR‚’°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“°¢6öç7B6WGF–æw5F‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂw6WGF–æw2r’¢rös°¢6öç7B·&VfW&Væ6W2Â6WE&VfW&Væ6W5ÒÒW6U7FFSÄV&æ6U&VfW&Væ6W3â‚‚’Óà¢&VDV&æ6U&VfW&Væ6W2‚¢“°¢6öç7B&W6öÇfVEF†VÖRÒ&W6öÇfTV&æ6UF†VÖTÖöFR‡&VfW&Væ6W2çF†VÖTÖöFR“°¢6öç7B7F—fU&W6WBÒf–æDV&æ6U&W6WB€¢&W6öÇfVEF†VÖRÓÓÒvÆ–v‡Brò&VfW&Væ6W2æÆ–v‡E&W6WB¢&VfW&Væ6W2æF&µ&W6W@¢“°¢6öç7BVffV7F—fT6öÆ÷'2Ò&VfW&Væ6W2æ7W7FöÔ6öÆ÷'0¢ò°¢66VçC¢&VfW&Væ6W2æ66VçBÀ¢&6¶w&÷VæC¢&VfW&Væ6W2æ&6¶w&÷VæBÀ¢f÷&Vw&÷VæC¢&VfW&Væ6W2æf÷&Vw&÷Væ@¢Ð¢¢°¢66VçC¢7F—fU&W6WBæ66VçBÀ¢&6¶w&÷VæC¢7F—fU&W6WBæ&6¶w&÷VæBÀ¢f÷&Vw&÷VæC¢7F—fU&W6WBæf÷&Vw&÷Væ@¢Ó° ¢W6TVffV7B‚‚’Óâ°¢Ç”V&æ6U&VfW&Væ6W2‡&VfW&Væ6W2“°¢ÒÂ·&VfW&Væ6W5Ò“° ¢6öç7B6öÖÖ—E&VfW&Væ6W2ÒW6T6ÆÆ&6²‚‡F6ƒ¢'F–ÃÄV&æ6U&VfW&Væ6W3â’Óâ°¢6WE&VfW&Væ6W2‚†7W'&VçB’Óâ°¢6öç7BæW‡BÒæ÷&ÖÆ—¦TV&æ6U&VfW&Væ6W2‡²ââæ7W'&VçBÂââçF6‚Ò“°¢6öç7B6fVBÒ6fTV&æ6U&VfW&Væ6W2†æW‡B“°¢Ç”V&æ6U&VfW&Væ6W2‡6fVB“°¢&WGW&â6fVC°¢Ò“°¢ÒÂµÒ“° ¢6öç7BWFFU&W6WBÒ†¶W“¢vÆ–v‡E&W6WBrÂvF&µ&W6WBrÂ&W6WD”C¢V&æ6U&W6WD”B’Óâ°¢6öç7B&W6WBÒf–æDV&æ6U&W6WB‡&W6WD”B“°¢6öç7B7F—fU&W6WD¶W’Ò&W6öÇfVEF†VÖRÓÓÒvÆ–v‡BròvÆ–v‡E&W6WBr¢vF&µ&W6WBs°¢–b†¶W’ÓÒ7F—fU&W6WD¶W’’°¢6öÖÖ—E&VfW&Væ6W2‡²¶¶W•Ó¢&W6WBæ–BÒ“°¢&WGW&ã°¢Ð¢6öÖÖ—E&VfW&Væ6W2‡°¢¶¶W•Ó¢&W6WBæ–BÀ¢66VçC¢&W6WBæ66VçBÀ¢&6¶w&÷VæC¢&W6WBæ&6¶w&÷VæBÀ¢f÷&Vw&÷VæC¢&W6WBæf÷&Vw&÷VæBÀ¢7W7FöÔ6öÆ÷'3¢fÇ6P¢Ò“°¢Ó° ¢6öç7BWFFT†W…&VfW&Væ6RÒ€¢¶W“¢v66VçBrÂv&6¶w&÷VæBrÂvf÷&Vw&÷VæBrÀ¢fÇVS¢7G&–æp¢’Óâ°¢6öÖÖ—E&VfW&Væ6W2‡°¢66VçC¢¶W’ÓÓÒv66VçBròfÇVR¢VffV7F—fT6öÆ÷'2æ66VçBÀ¢&6¶w&÷VæC¢¶W’ÓÓÒv&6¶w&÷VæBròfÇVR¢VffV7F—fT6öÆ÷'2æ&6¶w&÷VæBÀ¢f÷&Vw&÷VæC¢¶W’ÓÓÒvf÷&Vw&÷VæBròfÇVR¢VffV7F—fT6öÆ÷'2æf÷&Vw&÷VæBÀ¢7W7FöÔ6öÆ÷'3¢G'VP¢Ò“°¢Ó° ¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GB×6WGF–æw2×vR–GBÖV&æ6R×vR#à¢Ç6V7F–öâ6Æ74æÖSÒ&–GB×6WGF–æw2Ö6&B–GBÖV&æ6RÖ6&B"&–ÖÆ&VÆÆVF'“Ò&–GBÖV&æ6R×F†VÖRÖ†VF–ær#à¢ÆF—b6Æ74æÖSÒ&–GBÖV&æ6RÖ6&BÖ†VFW"#à¢ÄÆ–æ²6Æ74æÖSÒ&–GBÖV&æ6RÖ&6²"Fó×·6WGF–æw5F‡Ò&–ÖÆ&VÃÒ$&6²Fò6WGF–æw2#à¢Ä6†Wg&öäÆVgB6—¦S×³#Ò&–Ö†–FFVãÒ'G'VR"óà¢ÂôÆ–æ³à¢ÆF—b6Æ74æÖSÒ&–GBÖV&æ6RÖ6&B×F—FÆR#à¢Æƒ2–CÒ&–GBÖV&æ6R×F†VÖRÖ†VF–ær#åF†VÖSÂöƒ3à¢Çä6†ö÷6RF†VÖR÷"föÆÆ÷r–÷W"7—7FVÓÂ÷à¢ÂöF—cà¢ÄV&æ6U6VvÖVçFVD6öçG&öÀ¢Æ&VÃÒ%F†VÖR ¢fÇVS×·&VfW&Væ6W2çF†VÖTÖöFWÐ¢÷F–öç3×´T$ä4UõD„TÔUôõD”ôå7Ð¢öä6†ævS×²‡F†VÖTÖöFR’Óâ6öÖÖ—E&VfW&Væ6W2‡²F†VÖTÖöFRÒ—Ð¢óà¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GBÖV&æ6RÖ6öçG&öÂÖÆ—7B#à¢ÆÆ&VÂ6Æ74æÖSÒ&–GBÖV&æ6RÖ6öçG&öÂ×&÷r#à¢Ç7ãà¢Ç7G&öæsäÆ–v‡BF†VÖSÂ÷7G&öæsà¢Ç6ÖÆÃç·&W6öÇfVEF†VÖRÓÓÒvÆ–v‡Bròt7F—fRæ÷rr¢uW6VBv†VâÆ–v‡B—26VÆV7FVBwÓÂ÷6ÖÆÃà¢Â÷7ãà¢Ç6VÆV7@¢&–ÖÆ&VÃÒ$Æ–v‡BF†VÖR ¢fÇVS×·&VfW&Væ6W2æÆ–v‡E&W6WGÐ¢öä6†ævS×²†WfVçB’ÓâWFFU&W6WB‚vÆ–v‡E&W6WBrÂWfVçBçF&vWBçfÇVR2V&æ6U&W6WD”B—Ð¢à¢¶V&æ6U&W6WD÷F–öç2‚vÆ–v‡Br’æÖ‚‡&W6WB’Óâ€¢Æ÷F–öâ¶W“×·&W6WBæ–GÒfÇVS×·&W6WBæ–GÓà¢·&W6WBæÆ&VÇÐ¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà ¢ÆÆ&VÂ6Æ74æÖSÒ&–GBÖV&æ6RÖ6öçG&öÂ×&÷r#à¢Ç7ãà¢Ç7G&öæsäF&²F†VÖSÂ÷7G&öæsà¢Ç6ÖÆÃç·&W6öÇfVEF†VÖRÓÓÒvF&²ròt7F—fRæ÷rr¢uW6VBv†VâF&²—26VÆV7FVBwÓÂ÷6ÖÆÃà¢Â÷7ãà¢Ç6VÆV7@¢&–ÖÆ&VÃÒ$F&²F†VÖR ¢fÇVS×·&VfW&Væ6W2æF&µ&W6WGÐ¢öä6†ævS×²†WfVçB’ÓâWFFU&W6WB‚vF&µ&W6WBrÂWfVçBçF&vWBçfÇVR2V&æ6U&W6WD”B—Ð¢à¢¶V&æ6U&W6WD÷F–öç2‚vF&²r’æÖ‚‡&W6WB’Óâ€¢Æ÷F–öâ¶W“×·&W6WBæ–GÒfÇVS×·&W6WBæ–GÓà¢·&W6WBæÆ&VÇÐ¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà ¢µ°¢²v66VçBrÂt66VçBrÂVffV7F—fT6öÆ÷'2æ66VçEÒÀ¢²v&6¶w&÷VæBrÂt&6¶w&÷VæBrÂVffV7F—fT6öÆ÷'2æ&6¶w&÷VæEÒÀ¢²vf÷&Vw&÷VæBrÂtf÷&Vw&÷VæBrÂVffV7F—fT6öÆ÷'2æf÷&Vw&÷VæEÐ¢ÒæÖ‚…¶¶W’ÂÆ&VÂÂfÇVUÒ’Óâ€¢ÆÆ&VÂ¶W“×¶¶W—Ò6Æ74æÖSÒ&–GBÖV&æ6RÖ6öçG&öÂ×&÷r#à¢Ç7ãà¢Ç7G&öæsç¶Æ&VÇÓÂ÷7G&öæsà¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖV&æ6RÖ6öÆ÷"Ö–çWB#à¢Æ–çW@¢&–ÖÆ&VÃ×¶G¶Æ&VÇÒ6öÆ÷&Ð¢G—SÒ&6öÆ÷" ¢fÇVS×·fÇVWÐ¢öä6†ævS×²†WfVçB’Óà¢WFFT†W…&VfW&Væ6R†¶W’2v66VçBrÂv&6¶w&÷VæBrÂvf÷&Vw&÷VæBrÂWfVçBçF&vWBçfÇVR¢Ð¢óà¢Æ6öFSç·fÇVWÓÂö6öFSà¢Â÷7ãà¢ÂöÆ&VÃà¢’—Ð ¢ÆÆ&VÂ6Æ74æÖSÒ&–GBÖV&æ6RÖ6öçG&öÂ×&÷r#à¢Ç7ãà¢Ç7G&öæsåT’föçCÂ÷7G&öæsà¢Â÷7ãà¢Ç6VÆV7@¢&–ÖÆ&VÃÒ%T’föçB ¢fÇVS×·&VfW&Væ6W2çV”föçGÐ¢öä6†ævS×²†WfVçB’Óâ6öÖÖ—E&VfW&Væ6W2‡²V”föçC¢WfVçBçF&vWBçfÇVR2V&æ6TföçD”BÒ—Ð¢à¢´T$ä4UõT•ôdôåEôõD”ôå2æÖ‚†föçD”B’Óâ€¢Æ÷F–öâ¶W“×¶föçD”GÒfÇVS×¶föçD”GÓà¢´T$ä4UôdôåEôÄ$TÅ5¶föçD”E×Ð¢Âö÷F–öãà¢’—Ð¢Â÷6VÆV7Cà¢ÂöÆ&VÃà ¢ÆF—b6Æ74æÖSÒ&–GBÖV&æ6RÖ&V†f–÷"×&÷r#à¢ÆF—cà¢Æƒ3å&VGV6RÖ÷F–öãÂöƒ3à¢Çå&VGV6Ræ–ÖF–öç2÷"ÖF6‚–÷W"7—7FVÓÂ÷à¢ÂöF—cà¢ÄV&æ6U6VvÖVçFVD6öçG&öÀ¢Æ&VÃÒ%&VGV6RÖ÷F–öâ ¢fÇVS×·&VfW&Væ6W2ç&VGV6TÖ÷F–öçÐ¢÷F–öç3×´T$ä4UôÔõD”ôåôõD”ôå7Ð¢öä6†ævS×²‡&VGV6TÖ÷F–öâ’Óâ6öÖÖ—E&VfW&Væ6W2‡²&VGV6TÖ÷F–öâÒ—Ð¢óà¢ÂöF—cà ¢ÆÆ&VÂ6Æ74æÖSÒ&–GBÖV&æ6RÖ&V†f–÷"×&÷r#à¢Ç7ãà¢Æƒ3åT’föçB6—¦SÂöƒ3à¢ÇäF§W7BF†R&6R6—¦RW6VBf÷"F†R–FVçG&–ÂT“Â÷à¢Â÷7ãà¢Ç7â6Æ74æÖSÒ&–GBÖV&æ6RÖçVÖ&W"#à¢ÄV&æ6TçVÖ&W$–çW@¢Æ&VÃÒ%T’föçB6—¦R ¢Ö–ã×³GÐ¢Öƒ×³#'Ð¢fÇVS×·&VfW&Væ6W2çV”föçE6—¦WÐ¢öä6öÖÖ—C×²‡V”föçE6—¦R’Óâ6öÖÖ—E&VfW&Væ6W2‡²V”föçE6—¦RÒ—Ð¢óà¢Ç7ãçƒÂ÷7ãà¢Â÷7ãà¢ÂöÆ&VÃà ¢ÆF—b6Æ74æÖSÒ&–GBÖV&æ6RÖ&V†f–÷"×&÷r#à¢ÆF—cà¢Æƒ3äföçB6Öö÷F†–æsÂöƒ3à¢ÇåW6RæF—fRföçB6Öö÷F†–ærv†W&R7W÷'FVCÂ÷à¢ÂöF—cà¢ÄV&æ6U7v—F6€¢6†V6¶VC×·&VfW&Væ6W2æföçE6Öö÷F†–æwÐ¢Æ&VÃÒ$föçB6Öö÷F†–ær ¢öä6†ævS×²†föçE6Öö÷F†–ær’Óâ6öÖÖ—E&VfW&Væ6W2‡²föçE6Öö÷F†–ærÒ—Ð¢óà¢ÂöF—cà¢ÂöF—cà¢Â÷6V7F–öãà¢Â÷6V7F–öãà¢“°§Ð ¦W‡÷'BgVæ7F–öâ&öGV7E6WGF–æw5vR‚’°¢6öç7B&×2ÒW6U&×3Å66÷U&÷WFU&×3â‚“°¢6öç7B66÷RÒ&W6öÇfU66÷Tg&öÕ&×2‡&×2“°¢6öç7B²ÖRÒÒW6TÖR‚“°¢6öç7Bæf–vFRÒW6Tæf–vFR‚“° ¢6öç7B¶ÆöF–ærÂ6WDÆöF–æuÒÒW6U7FFR‡G'VR“°¢6öç7B¶W'&÷"Â6WDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·v†ôÔ’Â6WEv†ôÔ•ÒÒW6U7FFSÅv†ôÔ•&W7öç6RÂçVÆÃâ†çVÆÂ“°¢6öç7B¶ÖVÖ&W'2Â6WDÖVÖ&W'5ÒÒW6U7FFSÅv÷&·76TÖVÖ&W%&V6÷&EµÓâ…µÒ“°¢6öç7B¶WF„6öæf–rÂ6WDWF„6öæf–uÒÒW6U7FFSÄWF„6öæf–u&W7öç6RÂçVÆÃâ†çVÆÂ“°¢6öç7B·6W76–öç2Â6WE6W76–öç5ÒÒW6U7FFSÅ6W76–öäÆ—7D—FVÕµÓâ…µÒ“°¢6öç7B·6W76–öç4ÆöF–ærÂ6WE6W76–öç4ÆöF–æuÒÒW6U7FFR‡G'VR“°¢6öç7B·6W76–öç4W'&÷"Â6WE6W76–öç4W'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B¶'W7•6W76–öä”BÂ6WD'W7•6W76–öä”EÒÒW6U7FFR‚rr“°¢6öç7B·&Wfö¶–æt÷F†W'2Â6WE&Wfö¶–æt÷F†W'5ÒÒW6U7FFR†fÇ6R“°¢6öç7B·7W7VæDÖöFÄ÷VâÂ6WE7W7VæDÖöFÄ÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B·7W7VæEVæF–ærÂ6WE7W7VæEVæF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·7W7VæDW'&÷"Â6WE7W7VæDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B¶FVÆWFTÖöFÄ÷VâÂ6WDFVÆWFTÖöFÄ÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B¶FVÆWFUVæF–ærÂ6WDFVÆWFUVæF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶FVÆWFTW'&÷"Â6WDFVÆWFTW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B¶FVÆWFU6öÆT÷væW%v÷&·76W2Â6WDFVÆWFU6öÆT÷væW%v÷&·76W5ÒÒW6U7FFSÄ66÷VçDFVÆWF–öåv÷&·76UµÓâ…µÒ“°¢6öç7B·v÷&·76TÆ–fV7–6ÆRÂ6WEv÷&·76TÆ–fV7–6ÆUÒÒW6U7FFSÅv÷&·76U&V6÷&BÂçVÆÃâ†çVÆÂ“°¢6öç7B·v÷&·76U7W7VæDÖöFÄ÷VâÂ6WEv÷&·76U7W7VæDÖöFÄ÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76U7W7VæEVæF–ærÂ6WEv÷&·76U7W7VæEVæF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76U7W7VæDW'&÷"Â6WEv÷&·76U7W7VæDW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·v÷&·76U7W7VæE7G&æFVBÂ6WEv÷&·76U7W7VæE7G&æFVEÒÒW6U7FFSÀ¢v÷&·76U6öÆT÷væW$ffV7FVDÖVÖ&W%µÐ¢â…µÒ“°¢òò7F–6·’C’fÆr†7V&–2"3CSb"“¢ÖÆf÷&ÖVB÷"V×G’ffV7FVEöÖVÖ&W'6 ¢òò–ÆöBv÷VÆB÷F†W'v—6RÆVfRv÷&·76U7W7VæE7G&æFVFV×G’æB6–ÆVçFÇ¢òò†–FRF†R&Æö6¶W"âG&6²F†R6öÆRÖ÷væW"C’W‡Æ–6—FÇ’6òF†R–æÆ–æR&Æö6°¢òò7F–ÆÂ&VæFW'2v—F‚fÆÆ&6²6÷’²F†RÖævRÖÖVÖ&W'2FVWÆ–æ²à¢6öç7B·v÷&·76U7W7VæE6öÆT÷væW"Â6WEv÷&·76U7W7VæE6öÆT÷væW%ÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76U&V7F—fFTÖöFÄ÷VâÂ6WEv÷&·76U&V7F—fFTÖöFÄ÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76U&V7F—fFUVæF–ærÂ6WEv÷&·76U&V7F—fFUVæF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76U&V7F—fFTW'&÷"Â6WEv÷&·76U&V7F—fFTW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·v÷&·76TFVÆWFTÖöFÄ÷VâÂ6WEv÷&·76TFVÆWFTÖöFÄ÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76TFVÆWFUVæF–ærÂ6WEv÷&·76TFVÆWFUVæF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76TFVÆWFTW'&÷"Â6WEv÷&·76TFVÆWFTW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B·v÷&·76TFVÆWFU7G&æFVBÂ6WEv÷&·76TFVÆWFU7G&æFVEÒÒW6U7FFSÀ¢v÷&·76U6öÆT÷væW$ffV7FVDÖVÖ&W%µÐ¢â…µÒ“°¢òòÖ—'&÷'2v÷&·76U7W7VæE6öÆT÷væW&f÷"F†RFVÆWFRfÆ÷r†7V&–2"3CSb"’à¢6öç7B·v÷&·76TFVÆWFU6öÆT÷væW"Â6WEv÷&·76TFVÆWFU6öÆT÷væW%ÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76U&W7F÷&TÖöFÄ÷VâÂ6WEv÷&·76U&W7F÷&TÖöFÄ÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76U&W7F÷&UVæF–ærÂ6WEv÷&·76U&W7F÷&UVæF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·v÷&·76U&W7F÷&TW'&÷"Â6WEv÷&·76U&W7F÷&TW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B¶W‡÷'EVæF–ærÂ6WDW‡÷'EVæF–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶W‡÷'DW'&÷"Â6WDW‡÷'DW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B¶W‡÷'E7FGW2Â6WDW‡÷'E7FGW5ÒÒW6U7FFSÀ¢Â²¶–æC¢v–FÆRrÐ¢Â²¶–æC¢w&W&–ærs²ÖW76vS¢7G&–ærÐ¢Â²¶–æC¢w&VG’s²F÷væÆöEU$Ã¢7G&–æs²W‡—&W4Có¢7G&–ærÐ¢â‡²¶–æC¢v–FÆRrÒ“°¢6öç7BW‡÷'D&÷'E&VbÒW6U&VcÄ&÷'D6öçG&öÆÆW"ÂçVÆÃâ†çVÆÂ“°¢6öç7BfF$6öçG&öÅ&VbÒW6U&VcÄ…DÔÄF—dVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7BfF$f–ÆT–çWE&VbÒW6U&VcÄ…DÔÄ–çWDVÆVÖVçBÂçVÆÃâ†çVÆÂ“°¢6öç7B·&öf–ÆTVF—F–ærÂ6WE&öf–ÆTVF—F–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B¶fF$ÖVçT÷VâÂ6WDfF$ÖVçT÷VåÒÒW6U7FFR†fÇ6R“°¢6öç7B·&öf–ÆTG&gBÂ6WE&öf–ÆTG&gEÒÒW6U7FFSÅ&öf–ÆTG&gCâ‚‚’Óâ&öf–ÆTG&gDg&öÔÖR†ÖR’“°¢6öç7B·&öf–ÆU6f–ærÂ6WE&öf–ÆU6f–æuÒÒW6U7FFR†fÇ6R“°¢6öç7B·&öf–ÆTW'&÷"Â6WE&öf–ÆTW'&÷%ÒÒW6U7FFR‚rr“°¢6öç7B6WGF–æw4Ö÷VçFVE&VbÒW6U&Vb‡G'VR“° ¢W6TVffV7B‚‚’Óâ°¢6WGF–æw4Ö÷VçFVE&Vbæ7W'&VçBÒG'VS°¢&WGW&â‚’Óâ°¢6WGF–æw4Ö÷VçFVE&Vbæ7W'&VçBÒfÇ6S°¢Ó°¢ÒÂµÒ“° ¢6öç7BÆöE6W76–öç2Ò7–æ2‚’Óâ°¢6WE6W76–öç4ÆöF–ær‡G'VR“°¢6WE6W76–öç4W'&÷"‚rr“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBæÆ—7D7W'&VçEW6W%6W76–öç2‚“°¢–b‚6WGF–æw4Ö÷VçFVE&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6WE6W76–öç2‡&W7öç6Ræ—FV×2“°¢Ò6F6‚‡6W76–öäW'&÷"’°¢–b‚6WGF–æw4Ö÷VçFVE&Vbæ7W'&VçB’°¢&WGW&ã°¢Ð¢6öç7BÖW76vRÒ6W76–öäW'&÷"–ç7Fæ6VöbW'&÷"ò6W76–öäW'&÷"æÖW76vR¢uVæ&ÆRFòÆöB7F—fR6W76–öç2âs°¢6WE6W76–öç4W'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢–b‡6WGF–æw4Ö÷VçFVE&Vbæ7W'&VçB’°¢6WE6W76–öç4ÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢6öç7B7F'DFFW‡÷'BÒW6T6ÆÆ&6²‚‚’Óâ°¢W‡÷'D&÷'E&Vbæ7W'&VçCòæ&÷'B‚“°¢6öç7B6öçG&öÆÆW"ÒæWr&÷'D6öçG&öÆÆW"‚“°¢W‡÷'D&÷'E&Vbæ7W'&VçBÒ6öçG&öÆÆW#°¢fö–B&WVW7DFFW‡÷'B‡°¢6–væÃ¢6öçG&öÆÆW"ç6–væÂÀ¢6WDW‡÷'EVæF–ærÀ¢6WDW‡÷'DW'&÷"À¢6WDW‡÷'E7FGW0¢Ò’æf–æÆÇ’‚‚’Óâ°¢–b†W‡÷'D&÷'E&Vbæ7W'&VçBÓÓÒ6öçG&öÆÆW"’°¢W‡÷'D&÷'E&Vbæ7W'&VçBÒçVÆÃ°¢Ð¢Ò“°¢ÒÂµÒ“° ¢W6TVffV7B‚‚’Óâ°¢&WGW&â‚’Óâ°¢W‡÷'D&÷'E&Vbæ7W'&VçCòæ&÷'B‚“°¢Ó°¢ÒÂµÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚66÷R’°¢6WDW'&÷"‚t6†ö÷6Rv÷&·76R&Vf÷&RÆöF–ær6WGF–æw2âr“°¢6WDÆöF–ær†fÇ6R“°¢&WGW&ã°¢Ð ¢ÆWBÖ÷VçFVBÒG'VS°¢6öç7BÆöE6WGF–æw2Ò7–æ2‚’Óâ°¢6WDÆöF–ær‡G'VR“°¢6WDW'&÷"‚rr“°¢G'’°¢6öç7BWF‚Ò'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R“°¢6öç7B·v†ôÔ•&W7öç6RÂÖVÖ&W%&W7öç6RÂWF„6öæf–u&W7öç6UÒÒv—B&öÖ—6RæÆÂ…°¢”6Æ–VçBævWEv†ôÔ’†WF‚’À¢”6Æ–VçBæÆ—7Ev÷&·76TÖVÖ&W'2‡66÷Rçv÷&·76T”BÂ²Æ–Ö—C¢ÒÂWF‚’À¢”6Æ–VçBævWDWF„6öæf–r‚¢Ò“°¢–b‚Ö÷VçFVB’°¢&WGW&ã°¢Ð¢6WEv†ôÔ’‡v†ôÔ•&W7öç6R“°¢6WDÖVÖ&W'2†ÖVÖ&W%&W7öç6Ræ—FV×2“°¢6WDWF„6öæf–r†WF„6öæf–u&W7öç6R“°¢òò6VVBF†Rv÷&·76RÆ–fV7–6ÆR&ææW"²&÷r7FFRg&öÒv†ôÔ’6òF†P¢òòFævW"¦öæR&VfÆV7G2F†R7W'&VçB7FGW2&Vf÷&Rç’×WFF–öâÆæG2à¢6öç7B6æ6†÷Ev÷&·76RÐ¢v†ôÔ•&W7öç6Ræ7F—fU÷v÷&·76Sòçv÷&·76Róð¢v†ôÔ•&W7öç6Rçv÷&·76W3òæf–æB€¢†—FVÒ’Óâ—FVÒçv÷&·76Rçv÷&·76Uö–BÓÓÒ66÷Rçv÷&·76T”@¢“òçv÷&·76Róð¢çVÆÃ°¢6WEv÷&·76TÆ–fV7–6ÆR‡6æ6†÷Ev÷&·76R“°¢Ò6F6‚†W'"’°¢–b‚Ö÷VçFVB’°¢&WGW&ã°¢Ð¢6WDW'&÷"†W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFòÆöBv÷&·76R6WGF–æw2r“°¢Òf–æÆÇ’°¢–b†Ö÷VçFVB’°¢6WDÆöF–ær†fÇ6R“°¢Ð¢Ð¢Ó° ¢fö–BÆöE6WGF–æw2‚“°¢fö–BÆöE6W76–öç2‚“° ¢&WGW&â‚’Óâ°¢Ö÷VçFVBÒfÇ6S°¢Ó°¢ÒÂ·66÷SòçFVæçD”BÂ66÷Sòçv÷&·76T”BÂ66÷Sòç&ö¦V7D”EÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚&öf–ÆTVF—F–ærbb&öf–ÆU6f–ær’°¢6WE&öf–ÆTG&gB‡&öf–ÆTG&gDg&öÔÖR†ÖR’“°¢6WE&öf–ÆTW'&÷"‚rr“°¢Ð¢ÒÂ¶ÖSòçW6W"æF—7Æ•öæÖRÂ&öf–ÆTVF—F–ærÂ&öf–ÆU6f–æuÒ“° ¢W6TVffV7B‚‚’Óâ°¢–b‚fF$ÖVçT÷Vâ’°¢&WGW&ã°¢Ð¢6öç7B†æFÆUö–çFW$F÷vâÒ†WfVçC¢Ö÷W6TWfVçB’Óâ°¢6öç7BF&vWBÒWfVçBçF&vWC°¢–b‡F&vWB–ç7Fæ6VöbæöFRbbfF$6öçG&öÅ&Vbæ7W'&VçCòæ6öçF–ç2‡F&vWB’’°¢&WGW&ã°¢Ð¢6WDfF$ÖVçT÷Vâ†fÇ6R“°¢Ó°¢6öç7B†æFÆT¶W”F÷vâÒ†WfVçC¢¶W–&ö&DWfVçB’Óâ°¢–b†WfVçBæ¶W’ÓÓÒtW66Rr’°¢6WDfF$ÖVçT÷Vâ†fÇ6R“°¢Ð¢Ó°¢Fö7VÖVçBæFDWfVçDÆ—7FVæW"‚wö–çFW&F÷vârÂ†æFÆUö–çFW$F÷vâ“°¢Fö7VÖVçBæFDWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W”F÷vâ“°¢&WGW&â‚’Óâ°¢Fö7VÖVçBç&VÖ÷fTWfVçDÆ—7FVæW"‚wö–çFW&F÷vârÂ†æFÆUö–çFW$F÷vâ“°¢Fö7VÖVçBç&VÖ÷fTWfVçDÆ—7FVæW"‚v¶W–F÷vârÂ†æFÆT¶W”F÷vâ“°¢Ó°¢ÒÂ¶fF$ÖVçT÷VåÒ“° ¢6öç7B7F—fUv÷&·76RÒv†ôÔ“òæ7F—fU÷v÷&·76Sòçv÷&·76RóòÖSòçv÷&·76S°¢6öç7B7F—fTÖVÖ&W"Ð¢v†ôÔ“òæ7F—fU÷v÷&·76SòæÖVÖ&W"óð¢v†ôÔ“òçv÷&·76W3òæf–æB‚†—FVÒ’Óâ—FVÒçv÷&·76Rçv÷&·76Uö–BÓÓÒ66÷Sòçv÷&·76T”B“òæÖVÖ&W#°¢6öç7B7F—fU&öÆRÒ7F—fTÖVÖ&W#òç&öÆRóòÖSòç&öÆRóòwf–WvW"s°¢6öç7Bv÷&·76TF—7Æ”æÖRÒ7F—fUv÷&·76SòæF—7Æ•öæÖRóò66÷Sòçv÷&·76T”Bóòuv÷&·76Rs°¢òò&VfW"F†R×WFFVBÆ–fV7–6ÆR6÷’‡&Vg&W6†VBgFW"7W7VæBöFVÆWFRöWF2â¢òòæBfÆÂ&6²Fòv†FWfW"v†ôÔ’6VVFVBâFVfVÇG2Fòv7F—fRr6ò¢òòÆVv7’&6¶VæBF†BöÖ—G2F†Rf–VÆB7F–ÆÂ&VæFW'2F†R6ÖR&÷w2—@¢òòv÷VÆB†fR&VæFW&VB&Vf÷&R3C#6†—VBà¢6öç7Bv÷&·76TÆ–fV7–6ÆU7FGW2Ð¢v÷&·76TÆ–fV7–6ÆSòç7FGW2óò7F—fUv÷&·76Sòç7FGW2óòv7F—fRs°¢6öç7Bv÷&·76U6ÇVufÇVRÒ‡v÷&·76TÆ–fV7–6ÆSòç6ÇVróò7F—fUv÷&·76Sòç6ÇVróòrr’çG&–Ò‚“°¢6öç7B—5v÷&·76T÷væW"Ò7F—fU&öÆRÓÓÒv÷væW"s°¢6öç7BWF…&÷f–FW'2ÒWF„6öæf–sòæWF‚ç&÷f–FW'2óòµÓ°¢6öç7B66÷W2Ò'&’æ—4'&’‡v†ôÔ“òç66÷W2’òv†ôÔ’ç66÷W2¢µÓ°¢6öç7Bv÷&·76W5F‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂwv÷&·76W2r’¢rös°¢6öç7B&–Ö'”VÖ–ÂÒÖSòçW6W"ç&–Ö'•öVÖ–ÃòçG&–Ò‚’óòrs°¢6öç7B&öf–ÆTF—7Æ”æÖRÒf÷&ÖE&öf–ÆTF—7Æ”æÖR†ÖR“°¢6öç7B&öf–ÆTfF%U$ÂÒÖSòçW6W"æfF%÷W&ÃòçG&–Ò‚’óòrs°¢6öç7B&öf–ÆT–æ—F–Ç2Òf÷&ÖE&öf–ÆT–æ—F–Ç2†ÖR“°¢6öç7B7F—fTÖVÖ&W'2Ò6÷VçDÖVÖ&W'4'•7FGW2†ÖVÖ&W'2Âv7F—fRr“°¢6öç7B–çf—FVDÖVÖ&W'2Ò6÷VçDÖVÖ&W'4'•7FGW2†ÖVÖ&W'2Âv–çf—FVBr“°¢6öç7BFÖ–äÖVÖ&W'2Ò6÷VçDÖVÖ&W'4'•&öÆR†ÖVÖ&W'2Âv÷væW"r’²6÷VçDÖVÖ&W'4'•&öÆR†ÖVÖ&W'2ÂvFÖ–âr“°¢6öç7B6–vä–äÖWF†öG2Òf÷&ÖE6WGF–æw4WF…&÷f–FW'2†WF„6öæf–r“°¢6öç7B†÷7FVDÆöv–å7FGW2ÒWF„6öæf–sòæWF‚çv÷&¶÷5öÆöv–åöVæ&ÆVBòtVæ&ÆVBr¢tF—6&ÆVBs°¢6öç7B6ÖÅ7FGW2ÒWF„6öæf–sòæWF‚ææF—fU÷6ÖÅöVæ&ÆVBòt6öæf–wW&VBr¢tæ÷B6öæf–wW&VBs°¢6öç7BÖf7FGW2ÒWF„6öæf–sòæWF‚çv÷&¶÷5öÆöv–åöVæ&ÆVBòt†÷7FVBÆöv–âr¢tæ÷B6öæf–wW&VBs°¢6öç7BFWfVÆ÷W%66÷TÆ&VÂÒ66÷W2æÆVæwF‚ò66÷W2æÖ†f÷&ÖEFö¶VäÆ&VÂ’æ¦ö–â‚rÂr’¢tæò7W7FöÒ&W7G&–7F–öç2s°¢6öç7BFWfVÆ÷W%&÷f–FW$Æ&VÂÒWF…&÷f–FW'2æÆVæwF‚òWF…&÷f–FW'2æ¦ö–â‚rÂr’¢tæöæRGfW'F—6VBs°¢6öç7BV&æ6UF‚Ò66÷Rò'V–ÆE66÷VEF‚‡66÷RÂw6WGF–æw2öV&æ6Rr’¢rös° ¢6öç7B†æFÆU&öf–ÆTVF—BÒ‚’Óâ°¢–b‡&öf–ÆTVF—F–ær’°¢6WE&öf–ÆTW'&÷"‚rr“°¢6WDfF$ÖVçT÷Vâ†fÇ6R“°¢&WGW&ã°¢Ð¢6WE&öf–ÆTG&gB‡&öf–ÆTG&gDg&öÔÖR†ÖR’“°¢6WE&öf–ÆTW'&÷"‚rr“°¢6WE&öf–ÆTVF—F–ær‡G'VR“°¢6WDfF$ÖVçT÷Vâ†fÇ6R“°¢Ó° ¢6öç7B†æFÆU&öf–ÆT6æ6VÂÒ‚’Óâ°¢–b‡&öf–ÆU6f–ær’&WGW&ã°¢6WE&öf–ÆTG&gB‡&öf–ÆTG&gDg&öÔÖR†ÖR’“°¢6WE&öf–ÆTW'&÷"‚rr“°¢6WE&öf–ÆTVF—F–ær†fÇ6R“°¢6WDfF$ÖVçT÷Vâ†fÇ6R“°¢Ó° ¢6öç7B†æFÆTfF$FVÆWFRÒ7–æ2‚’Óâ°¢–b‚ÖRÇÂ&öf–ÆU6f–ærÇÂ&öf–ÆTfF%U$Â’°¢&WGW&ã°¢Ð¢6öç7B&Wf–÷W4ÖRÒÖS°¢6öç7B&Wf–÷W4G&gBÒ&öf–ÆTG&gC°¢6öç7Bv5&öf–ÆTVF—F–ærÒ&öf–ÆTVF—F–æs°¢6öç7B÷F–Ö—7F–4ÖS¢7W'&VçEW6W$6öçFW‡BÒ°¢ââç&Wf–÷W4ÖRÀ¢W6W#¢°¢ââç&Wf–÷W4ÖRçW6W"À¢fF%÷W&Ã¢rrÀ¢WFFVEöC¢æWrFFR‚’çFô•4õ7G&–ær‚¢Ð¢Ó°¢6WDfF$ÖVçT÷Vâ†fÇ6R“°¢6WE&öf–ÆU6f–ær‡G'VR“°¢6WE&öf–ÆTW'&÷"‚rr“°¢&–ÖTÖT66†R†÷F–Ö—7F–4ÖR“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBçWFFTÖR‡²fF%÷W&Ã¢rrÒ“°¢&–ÖTÖT66†R‡&W7öç6RæÖR“°¢–b‡v5&öf–ÆTVF—F–ær’°¢6WE&öf–ÆTG&gB‡&Wf–÷W4G&gB“°¢ÒVÇ6R°¢6WE&öf–ÆTG&gB‡&öf–ÆTG&gDg&öÔÖR‡&W7öç6RæÖR’“°¢6WE&öf–ÆTVF—F–ær†fÇ6R“°¢Ð¢Ò6F6‚†W'"’°¢&–ÖTÖT66†R‡&Wf–÷W4ÖR“°¢6WE&öf–ÆTG&gB‡v5&öf–ÆTVF—F–ærò&Wf–÷W4G&gB¢&öf–ÆTG&gDg&öÔÖR‡&Wf–÷W4ÖR’“°¢6WE&öf–ÆTW'&÷"†f÷&ÖE&öf–ÆTfF$W'&÷"†W'"’“°¢Òf–æÆÇ’°¢6WE&öf–ÆU6f–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆTfF%WÆöD6Æ–6²Ò‚’Óâ°¢–b‚ÖRÇÂ&öf–ÆU6f–ær’°¢&WGW&ã°¢Ð¢6WDfF$ÖVçT÷Vâ†fÇ6R“°¢6WE&öf–ÆTW'&÷"‚rr“°¢fF$f–ÆT–çWE&Vbæ7W'&VçCòæ6Æ–6²‚“°¢Ó° ¢6öç7B†æFÆTfF$f–ÆT6†ævRÒ7–æ2†WfVçC¢6†ævTWfVçCÄ…DÔÄ–çWDVÆVÖVçCâ’Óâ°¢6öç7Bf–ÆRÒWfVçBæ7W'&VçEF&vWBæf–ÆW3òå³Ó°¢WfVçBæ7W'&VçEF&vWBçfÇVRÒrs°¢–b‚f–ÆRÇÂÖRÇÂ&öf–ÆU6f–ær’°¢&WGW&ã°¢Ð¢6öç7BfÆ–FF–öäW'&÷"ÒfÆ–FFU&öf–ÆTfF$f–ÆR†f–ÆR“°¢–b‡fÆ–FF–öäW'&÷"’°¢6WE&öf–ÆTW'&÷"‡fÆ–FF–öäW'&÷"“°¢&WGW&ã°¢Ð¢6öç7B&Wf–÷W4ÖRÒÖS°¢6öç7B&Wf–÷W4G&gBÒ&öf–ÆTG&gC°¢6öç7Bv5&öf–ÆTVF—F–ærÒ&öf–ÆTVF—F–æs°¢ÆWBæW‡DfF%U$ÂÒrs°¢G'’°¢æW‡DfF%U$ÂÒv—B&VE&öf–ÆTfF$f–ÆR†f–ÆR“°¢Ò6F6‚†W'"’°¢6WE&öf–ÆTW'&÷"†W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFò&VB&öf–ÆR†÷Fòâr“°¢&WGW&ã°¢Ð¢6öç7B÷F–Ö—7F–4ÖS¢7W'&VçEW6W$6öçFW‡BÒ°¢ââç&Wf–÷W4ÖRÀ¢W6W#¢°¢ââç&Wf–÷W4ÖRçW6W"À¢fF%÷W&Ã¢æW‡DfF%U$ÂÀ¢WFFVEöC¢æWrFFR‚’çFô•4õ7G&–ær‚¢Ð¢Ó°¢6WE&öf–ÆU6f–ær‡G'VR“°¢6WE&öf–ÆTW'&÷"‚rr“°¢&–ÖTÖT66†R†÷F–Ö—7F–4ÖR“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBçWFFTÖR‡²fF%÷W&Ã¢æW‡DfF%U$ÂÒ“°¢&–ÖTÖT66†R‡&W7öç6RæÖR“°¢–b‡v5&öf–ÆTVF—F–ær’°¢6WE&öf–ÆTG&gB‡&Wf–÷W4G&gB“°¢ÒVÇ6R°¢6WE&öf–ÆTG&gB‡&öf–ÆTG&gDg&öÔÖR‡&W7öç6RæÖR’“°¢Ð¢Ò6F6‚†W'"’°¢&–ÖTÖT66†R‡&Wf–÷W4ÖR“°¢6WE&öf–ÆTG&gB‡v5&öf–ÆTVF—F–ærò&Wf–÷W4G&gB¢&öf–ÆTG&gDg&öÔÖR‡&Wf–÷W4ÖR’“°¢6WE&öf–ÆTW'&÷"†f÷&ÖE&öf–ÆTfF$W'&÷"†W'"’“°¢Òf–æÆÇ’°¢6WE&öf–ÆU6f–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆU&öf–ÆU7V&Ö—BÒ7–æ2†WfVçC¢f÷&ÔWfVçB’Óâ°¢WfVçBç&WfVçDFVfVÇB‚“°¢–b‚ÖR’°¢6WE&öf–ÆTW'&÷"‚t7W'&VçBW6W"—2Væf–Æ&ÆRâr“°¢&WGW&ã°¢Ð¢6öç7B&Wf–÷W4ÖRÒÖS°¢6öç7B&Wf–÷W4F—7Æ”æÖRÒ&Wf–÷W4ÖRçW6W"æF—7Æ•öæÖSòçG&–Ò‚’óòrs°¢6öç7BæW‡DF—7Æ”æÖRÒ&öf–ÆTG&gBæF—7Æ”æÖRçG&–Ò‚“°¢6öç7BF—7Æ”æÖT6†ævVBÒæW‡DF—7Æ”æÖRÓÒ&Wf–÷W4F—7Æ”æÖS°¢6öç7BfÆ–FF–öäW'&÷"ÒfÆ–FFU&öf–ÆTG&gB‡&öf–ÆTG&gB“°¢–b‡fÆ–FF–öäW'&÷"’°¢6WE&öf–ÆTW'&÷"‡fÆ–FF–öäW'&÷"“°¢&WGW&ã°¢Ð¢–b‚F—7Æ”æÖT6†ævVB’°¢6WE&öf–ÆTW'&÷"‚rr“°¢6WE&öf–ÆTVF—F–ær†fÇ6R“°¢&WGW&ã°¢Ð¢6öç7B÷F–Ö—7F–4ÖS¢7W'&VçEW6W$6öçFW‡BÒ°¢ââç&Wf–÷W4ÖRÀ¢W6W#¢°¢ââç&Wf–÷W4ÖRçW6W"À¢F—7Æ•öæÖS¢æW‡DF—7Æ”æÖRÀ¢WFFVEöC¢æWrFFR‚’çFô•4õ7G&–ær‚¢Ð¢Ó°¢6WE&öf–ÆU6f–ær‡G'VR“°¢6WE&öf–ÆTW'&÷"‚rr“°¢&–ÖTÖT66†R†÷F–Ö—7F–4ÖR“°¢G'’°¢6öç7B–ÆöBÒ°¢F—7Æ•öæÖS¢æW‡DF—7Æ”æÖP¢Ó°¢6öç7B&W7öç6RÒv—B”6Æ–VçBçWFFTÖR‡–ÆöB“°¢&–ÖTÖT66†R‡&W7öç6RæÖR“°¢6WE&öf–ÆTG&gB‡&öf–ÆTG&gDg&öÔÖR‡&W7öç6RæÖR’“°¢6WE&öf–ÆTVF—F–ær†fÇ6R“°¢Ò6F6‚†W'"’°¢&–ÖTÖT66†R‡&Wf–÷W4ÖR“°¢6WE&öf–ÆTG&gB‡&öf–ÆTG&gDg&öÔÖR‡&Wf–÷W4ÖR’“°¢6WE&öf–ÆTW'&÷"†W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFòWFFR&öf–ÆRâr“°¢Òf–æÆÇ’°¢6WE&öf–ÆU6f–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆU&Wfö¶U6W76–öâÒ7–æ2‡6W76–öä”C¢7G&–ærÂ—47W'&VçC¢&ööÆVâ’Óâ°¢6WD'W7•6W76–öä”B‡6W76–öä”B“°¢6WE6W76–öç4W'&÷"‚rr“°¢G'’°¢v—B”6Æ–VçBç&Wfö¶T7W'&VçEW6W%6W76–öâ‡6W76–öä”B“°¢–b†—47W'&VçB’°¢&W6WE&öGV7DWF…6W76–öä66†R‡²VæWF†VçF–6FVC¢G'VRÒ“°¢æf–vFR‚r÷6–væ–ã÷6–væVEö÷WCÓrÂ²&WÆ6S¢G'VRÒ“°¢&WGW&ã°¢Ð¢v—BÆöE6W76–öç2‚“°¢Ò6F6‚‡6W76–öäW'&÷"’°¢6öç7BÖW76vRÒ6W76–öäW'&÷"–ç7Fæ6VöbW'&÷"ò6W76–öäW'&÷"æÖW76vR¢uVæ&ÆRFò&Wfö¶R6W76–öââs°¢6WE6W76–öç4W'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢6WD'W7•6W76–öä”B‚rr“°¢Ð¢Ó° ¢6öç7B†æFÆU&Wfö¶T÷F†W%6W76–öç2Ò7–æ2‚’Óâ°¢6WE&Wfö¶–æt÷F†W'2‡G'VR“°¢6WE6W76–öç4W'&÷"‚rr“°¢G'’°¢v—B”6Æ–VçBç&Wfö¶T÷F†W$7W'&VçEW6W%6W76–öç2‚“°¢v—BÆöE6W76–öç2‚“°¢Ò6F6‚‡6W76–öäW'&÷"’°¢6öç7BÖW76vRÒ6W76–öäW'&÷"–ç7Fæ6VöbW'&÷"ò6W76–öäW'&÷"æÖW76vR¢uVæ&ÆRFò&Wfö¶R÷F†W"6W76–öç2âs°¢6WE6W76–öç4W'&÷"†ÖW76vR“°¢Òf–æÆÇ’°¢6WE&Wfö¶–æt÷F†W'2†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆT÷VäFVÆWFTÖöFÂÒ‚’Óâ°¢6WDFVÆWFTW'&÷"‚rr“°¢6WDFVÆWFU6öÆT÷væW%v÷&·76W2…µÒ“°¢6WDFVÆWFTÖöFÄ÷Vâ‡G'VR“°¢Ó° ¢6öç7B†æFÆT6æ6VÄFVÆWFTÖöFÂÒ‚’Óâ°¢–b†FVÆWFUVæF–ær’&WGW&ã°¢6WDFVÆWFTÖöFÄ÷Vâ†fÇ6R“°¢6WDFVÆWFTW'&÷"‚rr“°¢6WDFVÆWFU6öÆT÷væW%v÷&·76W2…µÒ“°¢Ó° ¢6öç7B†æFÆTFVÆWFT66÷VçBÒ7–æ2‚’Óâ°¢–b†FVÆWFUVæF–ær’&WGW&ã°¢6WDFVÆWFUVæF–ær‡G'VR“°¢6WDFVÆWFTW'&÷"‚rr“°¢6WDFVÆWFU6öÆT÷væW%v÷&·76W2…µÒ“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBæFVÆWFTÖR‚“°¢&W6WE&öGV7DWF…6W76–öä66†R‡²VæWF†VçF–6FVC¢G'VRÒ“°¢6ÆV$ÖT66†R‡²VæWF†VçF–6FVC¢G'VRÒ“°¢æf–vFR†66÷VçDFVÆWF–öå6–vä–åF‚‡&W7öç6Ræ†&EöFVÆWFUögFW"’Â²&WÆ6S¢G'VRÒ“°¢Ò6F6‚†W'"’°¢–b†W'"–ç7Fæ6Vöb”W'&÷"bbW'"ç7FGW2ÓÓÒC’bbW'"æ6öFRÓÓÒw6öÆUö÷væW"r’°¢6WDFVÆWFU6öÆT÷væW%v÷&·76W2†66÷VçDFVÆWF–öåv÷&·76W4g&öÔW'&÷"†W'"’“°¢6WDFVÆWFTW'&÷"‚rr“°¢ÒVÇ6R°¢6WDFVÆWFTW'&÷"†W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFòFVÆWFR–÷W"66÷VçBâÆV6R&WG'’âr“°¢Ð¢Òf–æÆÇ’°¢6WDFVÆWFUVæF–ær†fÇ6R“°¢Ð¢Ó° ¢òòÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÒÐ¢òòv÷&·76RÆ–fV7–6ÆR†æFÆW'2…"2öb3C#’à¢òð¢òòWfW'’FW7G'V7F—fRG&ç6—F–öâf—'7B÷Vç26öæf—&ÔFW7G'V7F—fTÖöFÂ6òF†P¢òò÷væW"†2Fò6öç66–÷W6Ç’6öæf—&Ò‡G—R×FòÖ6öæf—&Òf÷"7W7VæBôFVÆWFRÀ¢òò6†V6¶&÷‚f÷"F†R&W7F÷&F—fR&V7F—fFRõ&W7F÷&R’âF†R'WGFöâöâF†R&÷p¢òò—G6VÆbæWfW"f—&W2F†R’(	BF†BÇv—2†Vç2g&öÒ–ç6–FRF†RÖöFÂ(	@¢òò6òâ66–FVçFÂ6Æ–6²öâF†R&÷röæÇ’÷Vç2F†RF–Æörà¢òð¢òò6öÆRÖ÷væW"C’g&öÒF†R&6¶VæB—2&VæFW&VB–æÆ–æR–âF†R÷VâÖöFÀ¢òò†æ÷BFö7BÂæ÷Bæf–vF–öâ’6òF†R÷væW"6â6VRv†òv÷VÆB&P¢òò7G&æFVBÂ&öÖ÷FRæ÷F†W"÷væW"ÂæB&WG'’v—F†÷WBÆ÷6–ærF†V—"Æ6Rà¢òòF†RæöâÖFW7G'V7F—fR”W'&÷&'&æ6†W2fÆÂF‡&÷Vv‚FòW'&÷$ÖW76vRöà¢òòF†R6ÖRÖöFÂà¢6öç7B†æFÆT÷Våv÷&·76U7W7VæDÖöFÂÒ‚’Óâ°¢6WEv÷&·76U7W7VæDW'&÷"‚rr“°¢6WEv÷&·76U7W7VæE7G&æFVB…µÒ“°¢6WEv÷&·76U7W7VæE6öÆT÷væW"†fÇ6R“°¢6WEv÷&·76U7W7VæDÖöFÄ÷Vâ‡G'VR“°¢Ó°¢6öç7B†æFÆT6æ6VÅv÷&·76U7W7VæDÖöFÂÒ‚’Óâ°¢–b‡v÷&·76U7W7VæEVæF–ær’&WGW&ã°¢6WEv÷&·76U7W7VæDÖöFÄ÷Vâ†fÇ6R“°¢6WEv÷&·76U7W7VæDW'&÷"‚rr“°¢6WEv÷&·76U7W7VæE7G&æFVB…µÒ“°¢6WEv÷&·76U7W7VæE6öÆT÷væW"†fÇ6R“°¢Ó°¢6öç7B†æFÆU7W7VæEv÷&·76RÒ7–æ2‚’Óâ°¢–b‡v÷&·76U7W7VæEVæF–ærÇÂ66÷R’&WGW&ã°¢6WEv÷&·76U7W7VæEVæF–ær‡G'VR“°¢6WEv÷&·76U7W7VæDW'&÷"‚rr“°¢6WEv÷&·76U7W7VæE7G&æFVB…µÒ“°¢6WEv÷&·76U7W7VæE6öÆT÷væW"†fÇ6R“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBç7W7VæEv÷&·76R€¢66÷Rçv÷&·76T”BÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢6WEv÷&·76TÆ–fV7–6ÆR‡&W7öç6Rçv÷&·76R“°¢6WEv÷&·76U7W7VæDÖöFÄ÷Vâ†fÇ6R“°¢Ò6F6‚†W'"’°¢–b€¢W'"–ç7Fæ6Vöb”W'&÷"b`¢W'"ç7FGW2ÓÓÒC’b`¢W'"æ6öFRÓÓÒw6öÆUö÷væW%÷&WV—&W5÷G&ç6fW"p¢’°¢òòÆF6‚F†RC’fÆrWfVâv†VâffV7FVEöÖVÖ&W'2f–Ç2Fò'6P¢òò†7V&–2"3CSb"’6òF†R–æÆ–æR&Æö6¶W"7F–ÆÂ&VæFW'2v—F‚¢òòfÆÆ&6²ÖW76vR(	B÷F†W'v—6RF†RÖöFÂv÷VÆB6Æ÷6RF†RVæF–æp¢òò7FFRv—F‚æòf—6–&ÆRW'&÷"æBF†R7F÷"v÷VÆB&RÆVgBwVW76–ærà¢6WEv÷&·76U7W7VæE6öÆT÷væW"‡G'VR“°¢6WEv÷&·76U7W7VæE7G&æFVB‡v÷&·76U6öÆT÷væW$ÖVÖ&W'4g&öÔW'&÷"†W'"’“°¢ÒVÇ6R°¢6WEv÷&·76U7W7VæDW'&÷"€¢W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFò7W7VæBF†Rv÷&·76RâÆV6R&WG'’âp¢“°¢Ð¢Òf–æÆÇ’°¢6WEv÷&·76U7W7VæEVæF–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆT÷Våv÷&·76U&V7F—fFTÖöFÂÒ‚’Óâ°¢6WEv÷&·76U&V7F—fFTW'&÷"‚rr“°¢6WEv÷&·76U&V7F—fFTÖöFÄ÷Vâ‡G'VR“°¢Ó°¢6öç7B†æFÆT6æ6VÅv÷&·76U&V7F—fFTÖöFÂÒ‚’Óâ°¢–b‡v÷&·76U&V7F—fFUVæF–ær’&WGW&ã°¢6WEv÷&·76U&V7F—fFTÖöFÄ÷Vâ†fÇ6R“°¢6WEv÷&·76U&V7F—fFTW'&÷"‚rr“°¢Ó°¢6öç7B†æFÆU&V7F—fFUv÷&·76RÒ7–æ2‚’Óâ°¢–b‡v÷&·76U&V7F—fFUVæF–ærÇÂ66÷R’&WGW&ã°¢6WEv÷&·76U&V7F—fFUVæF–ær‡G'VR“°¢6WEv÷&·76U&V7F—fFTW'&÷"‚rr“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBç&V7F—fFUv÷&·76R€¢66÷Rçv÷&·76T”BÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢6WEv÷&·76TÆ–fV7–6ÆR‡&W7öç6Rçv÷&·76R“°¢6WEv÷&·76U&V7F—fFTÖöFÄ÷Vâ†fÇ6R“°¢Ò6F6‚†W'"’°¢6WEv÷&·76U&V7F—fFTW'&÷"€¢W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFò&V7F—fFRF†Rv÷&·76RâÆV6R&WG'’âp¢“°¢Òf–æÆÇ’°¢6WEv÷&·76U&V7F—fFUVæF–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆT÷Våv÷&·76TFVÆWFTÖöFÂÒ‚’Óâ°¢6WEv÷&·76TFVÆWFTW'&÷"‚rr“°¢6WEv÷&·76TFVÆWFU7G&æFVB…µÒ“°¢6WEv÷&·76TFVÆWFU6öÆT÷væW"†fÇ6R“°¢6WEv÷&·76TFVÆWFTÖöFÄ÷Vâ‡G'VR“°¢Ó°¢6öç7B†æFÆT6æ6VÅv÷&·76TFVÆWFTÖöFÂÒ‚’Óâ°¢–b‡v÷&·76TFVÆWFUVæF–ær’&WGW&ã°¢6WEv÷&·76TFVÆWFTÖöFÄ÷Vâ†fÇ6R“°¢6WEv÷&·76TFVÆWFTW'&÷"‚rr“°¢6WEv÷&·76TFVÆWFU7G&æFVB…µÒ“°¢6WEv÷&·76TFVÆWFU6öÆT÷væW"†fÇ6R“°¢Ó°¢6öç7B†æFÆTFVÆWFUv÷&·76RÒ7–æ2‚’Óâ°¢–b‡v÷&·76TFVÆWFUVæF–ærÇÂ66÷R’&WGW&ã°¢6WEv÷&·76TFVÆWFUVæF–ær‡G'VR“°¢6WEv÷&·76TFVÆWFTW'&÷"‚rr“°¢6WEv÷&·76TFVÆWFU7G&æFVB…µÒ“°¢6WEv÷&·76TFVÆWFU6öÆT÷væW"†fÇ6R“°¢G'’°¢6öç7B&W7öç6S¢v÷&·76TFVÆWFU&W7öç6RÒv—B”6Æ–VçBæFVÆWFUv÷&·76R€¢66÷Rçv÷&·76T”BÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢6WEv÷&·76TÆ–fV7–6ÆR‡&W7öç6Rçv÷&·76R“°¢6WEv÷&·76TFVÆWFTÖöFÄ÷Vâ†fÇ6R“°¢Ò6F6‚†W'"’°¢–b€¢W'"–ç7Fæ6Vöb”W'&÷"b`¢W'"ç7FGW2ÓÓÒC’b`¢W'"æ6öFRÓÓÒw6öÆUö÷væW%÷&WV—&W5÷G&ç6fW"p¢’°¢òò6VR7W7VæB†æFÆW"(	B¶VWF†R&Æö6¶W"f—6–&ÆRWfVâv—F‚âV×G¢òò÷"ÖÆf÷&ÖVBffV7FVEöÖVÖ&W'2–ÆöB†7V&–2"3CSb"’à¢6WEv÷&·76TFVÆWFU6öÆT÷væW"‡G'VR“°¢6WEv÷&·76TFVÆWFU7G&æFVB‡v÷&·76U6öÆT÷væW$ÖVÖ&W'4g&öÔW'&÷"†W'"’“°¢ÒVÇ6R°¢6WEv÷&·76TFVÆWFTW'&÷"€¢W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFòFVÆWFRF†Rv÷&·76RâÆV6R&WG'’âp¢“°¢Ð¢Òf–æÆÇ’°¢6WEv÷&·76TFVÆWFUVæF–ær†fÇ6R“°¢Ð¢Ó° ¢6öç7B†æFÆT÷Våv÷&·76U&W7F÷&TÖöFÂÒ‚’Óâ°¢6WEv÷&·76U&W7F÷&TW'&÷"‚rr“°¢6WEv÷&·76U&W7F÷&TÖöFÄ÷Vâ‡G'VR“°¢Ó°¢6öç7B†æFÆT6æ6VÅv÷&·76U&W7F÷&TÖöFÂÒ‚’Óâ°¢–b‡v÷&·76U&W7F÷&UVæF–ær’&WGW&ã°¢6WEv÷&·76U&W7F÷&TÖöFÄ÷Vâ†fÇ6R“°¢6WEv÷&·76U&W7F÷&TW'&÷"‚rr“°¢Ó°¢6öç7B†æFÆU&W7F÷&Uv÷&·76RÒ7–æ2‚’Óâ°¢–b‡v÷&·76U&W7F÷&UVæF–ærÇÂ66÷R’&WGW&ã°¢6WEv÷&·76U&W7F÷&UVæF–ær‡G'VR“°¢6WEv÷&·76U&W7F÷&TW'&÷"‚rr“°¢G'’°¢6öç7B&W7öç6RÒv—B”6Æ–VçBæ6æ6VÅv÷&·76TFVÆWF–öâ€¢66÷Rçv÷&·76T”BÀ¢'V–ÆE&öGV7DWF„6öçFW‡B‡66÷R¢“°¢6WEv÷&·76TÆ–fV7–6ÆR‡&W7öç6Rçv÷&·76R“°¢6WEv÷&·76U&W7F÷&TÖöFÄ÷Vâ†fÇ6R“°¢Ò6F6‚†W'"’°¢6WEv÷&·76U&W7F÷&TW'&÷"€¢W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFò&W7F÷&RF†Rv÷&·76RâÆV6R&WG'’âp¢“°¢Òf–æÆÇ’°¢6WEv÷&·76U&W7F÷&UVæF–ær†fÇ6R“°¢Ð¢Ó° ¢–b†ÆöF–ær’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ"&–Ö'W7“Ò'G'VR"&–ÖÆ—fSÒ'öÆ—FR#à¢Æƒ#å6WGF–æw3Âöƒ#à¢Â÷6V7F–öãà¢“°¢Ð ¢–b†W'&÷"’°¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GBÖ×æVÂÖW'&÷""&öÆSÒ&ÆW'B#à¢Æƒ#å6WGF–æw3Âöƒ#à¢Çç¶W'&÷'ÓÂ÷à¢Â÷6V7F–öãà¢“°¢Ð ¢&WGW&â€¢Ç6V7F–öâ6Æ74æÖSÒ&–GBÖ×æVÂ–GB×6WGF–æw2×vR#à¢Æ†VFW"6Æ74æÖSÒ&–GB×6WGF–æw2Ö†VFW"#à¢ÆF—cà¢Æƒ#å6WGF–æw3Âöƒ#à¢ÂöF—cà¢Âö†VFW#à ¢Ç6V7F–öâ6Æ74æÖSÒ&–GB×6WGF–æw2Ö6&B–GB×6WGF–æw2ÖV&æ6RÖVçG'’"&–ÖÆ&VÆÆVF'“Ò&–GB×6WGF–æw2ÖV&æ6RÖ†VF–ær#à¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö6&BÖ†VFW"#à¢ÆF—cà¢Æƒ2–CÒ&–GB×6WGF–æw2ÖV&æ6RÖ†VF–ær#äV&æ6SÂöƒ3à¢ÂöF—cà¢ÅÆWGFR6—¦S×³‡Ò&–Ö†–FFVãÒ'G'VR"óà¢ÂöF—cà¢ÇåF†VÖRÂföçG2Â6öçG&7BÂæBÖ÷F–öâ&VfW&Væ6W2ãÂ÷à¢ÄÆ–æ²6Æ74æÖSÒ&–GB×6WGF–æw2Ö7F–öâ×&÷r"Fó×¶V&æ6UF‡Óà¢Ç7ãà¢Ç7G&öæsä÷VâV&æ6R6WGF–æw3Â÷7G&öæsà¢Â÷7ãà¢Ä6†Wg&öå&–v‡B6—¦S×³gÒ&–Ö†–FFVãÒ'G'VR"óà¢ÂôÆ–æ³à¢Â÷6V7F–öãà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GB×6WGF–æw2Ö6&B–GB×&öf–ÆRÖ6&B"&–ÖÆ&VÆÆVF'“Ò&–GB×&öf–ÆRÖ†VF–ær#à¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö6&BÖ†VFW"#à¢ÆF—cà¢Æƒ2–CÒ&–GB×&öf–ÆRÖ†VF–ær#å&öf–ÆSÂöƒ3à¢ÂöF—cà¢·&öf–ÆTVF—F–ærò€¢ÆF—b6Æ74æÖSÒ&–GB×&öf–ÆRÖ7F–öç2#à¢Æ'WGFöà¢G—SÒ'7V&Ö—B ¢f÷&ÓÒ&–GB×&öf–ÆRÖf÷&Ò ¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'Fâ×&–Ö'’ ¢F—6&ÆVC×·&öf–ÆU6f–æwÐ¢à¢·&öf–ÆU6f–æròu6f–ærâââr¢u6fR&öf–ÆRwÐ¢Âö'WGFöãà¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GBÖ'Fâ–GBÖ'FâÖv†÷7B ¢öä6Æ–6³×¶†æFÆU&öf–ÆT6æ6VÇÐ¢F—6&ÆVC×·&öf–ÆU6f–æwÐ¢à¢6æ6VÀ¢Âö'WGFöãà¢ÂöF—cà¢’¢çVÆÇÐ¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GB×&öf–ÆRÖ&öG’#à¢ÆF—`¢6Æ74æÖSÒ&–GB×&öf–ÆRÖfF"Ö6öçG&öÂ ¢FFÖÖVçRÖ÷Vã×¶fF$ÖVçT÷VâòwG'VRr¢vfÇ6RwÐ¢&Vc×¶fF$6öçG&öÅ&VgÐ¢à¢Æ–çW@¢&Vc×¶fF$f–ÆT–çWE&VgÐ¢G—SÒ&f–ÆR ¢66WCÒ&–ÖvR÷ærÆ–ÖvRö§VrÆ–ÖvR÷vV'Æ–ÖvRöv–b ¢†–FFVà¢öä6†ævS×²†WfVçB’Óâ°¢fö–B†æFÆTfF$f–ÆT6†ævR†WfVçB“°¢×Ð¢óà¢Æ'WGFöà¢G—SÒ&'WGFöâ ¢6Æ74æÖSÒ&–GB×&öf–ÆRÖfF" ¢&–ÖW‡æFVC×¶fF$ÖVçT÷VçÐ¢&–Ö†7÷WÒ&ÖVçR ¢&–ÖÆ&VÃ×·&öf–ÆTfF%U$ÂòuWFFR÷"FVÆWFR&öf–ÆR†÷Fòr¢uWÆöB&öf–ÆR†÷FòwÐ¢öä6Æ–6³×²‚’Óâ6WDfF$ÖVçT÷Vâ‚†÷Vâ’Óâ÷Vâ—Ð¢F—6&ÆVC×²ÖWÐ¢à¢·&öf–ÆTfF%U$ÂòÆ–Ör7&3×·&öf–ÆTfF%U$ÇÒÇCÒ""óâ¢Ç7ãç·&öf–ÆT–æ—F–Ç7ÓÂ÷7ãçÐ¢Ç7â6Æ74æÖSÒ&–GB×&öf–ÆRÖfF"ÖVF—B"&–Ö†–FFVãÒ'G'VR#à¢ÅVæ6–Â6—¦S×³GÒóà¢Â÷7ãà¢Âö'WGFöãà¢¶fF$ÖVçT÷Vâò€¢ÆF—b6Æ74æÖSÒ&–GB×&öf–ÆRÖfF"ÖÖVçR"&öÆSÒ&ÖVçR#à¢Æ'WGFöâG—SÒ&'WGFöâ"&öÆSÒ&ÖVçV—FVÒ"öä6Æ–6³×¶†æFÆTfF%WÆöD6Æ–6·ÒF—6&ÆVC×·&öf–ÆU6f–æwÓà¢·&öf–ÆTfF%U$ÂòuWFFR†÷Fòr¢uWÆöB†÷FòwÐ¢Âö'WGFöãà¢·&öf–ÆTfF%U$Âò€¢Æ'WGFöâG—SÒ&'WGFöâ"&öÆSÒ&ÖVçV—FVÒ"öä6Æ–6³×²‚’Óâfö–B†æFÆTfF$FVÆWFR‚—ÒF—6&ÆVC×·&öf–ÆU6f–æwÓà¢FVÆWFR†÷Fð¢Âö'WGFöãà¢’¢çVÆÇÐ¢ÂöF—cà¢’¢çVÆÇÐ¢ÂöF—cà ¢·&öf–ÆTVF—F–ærò€¢Æf÷&Ò–CÒ&–GB×&öf–ÆRÖf÷&Ò"6Æ74æÖSÒ&–GBÖÖf÷&Ò–GB×&öf–ÆRÖf÷&Ò"öå7V&Ö—C×¶†æFÆU&öf–ÆU7V&Ö—GÓà¢ÆF—b6Æ74æÖSÒ&–GB×&öf–ÆRÖVF—F–ærÖæ÷FR"&öÆSÒ'7FGW2#à¢VF—F–ær&öf–ÆP¢ÂöF—cà¢ÆÆ&VÃà¢F—7Æ’æÖP¢Æ–çW@¢G—SÒ'FW‡B ¢fÇVS×·&öf–ÆTG&gBæF—7Æ”æÖWÐ¢öä6†ævS×²†WfVçB’Óâ6WE&öf–ÆTG&gB‚†G&gB’Óâ‡²ââæG&gBÂF—7Æ”æÖS¢WfVçBçF&vWBçfÇVRÒ’—Ð¢Ö„ÆVæwFƒ×³ƒÐ¢F—6&ÆVC×·&öf–ÆU6f–æwÐ¢&WV—&V@¢óà¢ÂöÆ&VÃà¢ÆÆ&VÃà¢VÖ–À¢Æ–çW@¢G—SÒ&VÖ–Â ¢fÇVS×·&–Ö'”VÖ–ÂÇÂuVæf–Æ&ÆRwÐ¢F—6&ÆV@¢&VDöæÇ¢óà¢ÂöÆ&VÃà¢·&öf–ÆTW'&÷"ò€¢Ç6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷""&öÆSÒ&ÆW'B#à¢·&öf–ÆTW'&÷'Ð¢Â÷à¢’¢çVÆÇÐ¢Âöf÷&Óà¢’¢€¢ÆFÂ6Æ74æÖSÒ&–GB×6WGF–æw2Öf7G2–GB×&öf–ÆRÖf7G2#à¢ÆF—cà¢ÆGCäæÖSÂöGCà¢ÆFCç·&öf–ÆTF—7Æ”æÖWÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäVÖ–ÃÂöGCà¢ÆFCç¶ÖSòçW6W"ç&–Ö'•öVÖ–ÂóòuVæf–Æ&ÆRwÓÂöFCà¢ÂöF—cà¢ÂöFÃà¢—Ð¢ÂöF—cà ¢²&öf–ÆTVF—F–ærbb&öf–ÆTW'&÷"ò€¢Ç6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷""&öÆSÒ&ÆW'B#à¢·&öf–ÆTW'&÷'Ð¢Â÷à¢’¢çVÆÇÐ ¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö7F–öâ×7F6²#à¢²&öf–ÆTVF—F–ærò€¢Æ'WGFöà¢&–ÖÆ&VÃÒ$VF—B&öf–ÆR ¢6Æ74æÖSÒ&–GB×6WGF–æw2Ö7F–öâ×&÷r ¢öä6Æ–6³×¶†æFÆU&öf–ÆTVF—GÐ¢G—SÒ&'WGFöâ ¢F—6&ÆVC×²ÖWÐ¢à¢Ç7ãà¢Ç7G&öæsäVF—B&öf–ÆSÂ÷7G&öæsà¢Â÷7ãà¢Ä6†Wg&öå&–v‡B6—¦S×³gÒ&–Ö†–FFVãÒ'G'VR"óà¢Âö'WGFöãà¢’¢çVÆÇÐ¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö7F–öâÖ—FVÒ"FF×FW7F–CÒ&–GBÖW‡÷'BÖ66÷VçB×&÷r#à¢Æ'WGFöà¢&–ÖÆ&VÃÒ$F÷væÆöB×’FF ¢6Æ74æÖSÒ&–GB×6WGF–æw2Ö7F–öâ×&÷r ¢FF×FW7F–CÒ&–GBÖW‡÷'BÖ66÷VçBÖ'WGFöâ ¢F—6&ÆVC×¶W‡÷'EVæF–æwÐ¢öä6Æ–6³×·7F'DFFW‡÷'GÐ¢G—SÒ&'WGFöâ ¢à¢Ç7ãà¢Ç7G&öæsäF÷væÆöB×’FFÂ÷7G&öæsà¢Â÷7ãà¢Ä6†Wg&öå&–v‡B6—¦S×³gÒ&–Ö†–FFVãÒ'G'VR"óà¢Âö'WGFöãà¢¶W‡÷'E7FGW2æ¶–æBÓÓÒw&VG’rò€¢Ç6Æ74æÖSÒ&–GB×6WGF–æw2Ö–æÆ–æR×7FGW2–GBÖFævW"×¦öæR×7V66W72"FF×FW7F–CÒ&–GBÖW‡÷'B×&VG’#à¢–÷W"FFW‡÷'B—2&VG’ç²rwÐ¢Æ‡&Vc×¶W‡÷'E7FGW2æF÷væÆöEU$ÇÒ&VÃÒ&æö÷VæW"æ÷&VfW'&W"#à¢F÷væÆöBF†R¤• ¢Âöà¢¶W‡÷'E7FGW2æW‡—&W4BòÒÆ–æ²W‡—&W2G¶æWrFFR†W‡÷'E7FGW2æW‡—&W4B’çFôÆö6ÆU7G&–ær‚—Ö¢rwÒà¢Â÷à¢’¢W‡÷'E7FGW2æ¶–æBÓÓÒw&W&–ærrò€¢Ç6Æ74æÖSÒ&–GB×6WGF–æw2Ö–æÆ–æR×7FGW2–GBÖFævW"×¦öæR×7FGW2"FF×FW7F–CÒ&–GBÖW‡÷'B×&W&–ær#à¢¶W‡÷'E7FGW2æÖW76vWÐ¢Â÷à¢’¢çVÆÇÐ¢¶W‡÷'DW'&÷"ò€¢Ç6Æ74æÖSÒ&–GB×6WGF–æw2Ö–æÆ–æR×7FGW2–GBÖFævW"×¦öæRÖW'&÷""&öÆSÒ&ÆW'B#à¢¶W‡÷'DW'&÷'Ð¢Â÷à¢’¢çVÆÇÐ¢ÂöF—cà¢ÂöF—cà¢Â÷6V7F–öãà ¢Ç6V7F–öâ6Æ74æÖSÒ&–GB×6WGF–æw2Ö6&B–GB×6WGF–æw2Ö66W72Ö6&B"&–ÖÆ&VÆÆVF'“Ò&–GB×6WGF–æw2Ö66W72Ö†VF–ær#à¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö6&BÖ†VFW"#à¢ÆF—cà¢Æƒ2–CÒ&–GB×6WGF–æw2Ö66W72Ö†VF–ær#å6V7W&—G’æBv÷&·76SÂöƒ3à¢ÂöF—cà¢ÂöF—cà¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö66W72Öw&–B#à¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö66W72×6V7F–öâ#à¢ÆƒCå6V7W&—G“ÂöƒCà¢ÆFÂ6Æ74æÖSÒ&–GB×6WGF–æw2Öf7G2–GB×6WGF–æw2×6V7W&—G’Öf7G2#à¢ÆF—cà¢ÆGCå6–vâÖ–âÖWF†öG3ÂöGCà¢ÆFCç·6–vä–äÖWF†öG7ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCã$dÂöGCà¢ÆFCç¶Öf7FGW7ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå4ÔÂ54óÂöGCà¢ÆFCç·6ÖÅ7FGW7ÓÂöFCà¢ÂöF—cà¢ÂöFÃà¢ÆFWF–Ç26Æ74æÖSÒ&–GB×6WGF–æw2Ö–æÆ–æRÖF—66Æ÷7W&R–GB×6WGF–æw2×6W76–öç2Ö6&B#à¢Ç7VÖÖ'’6Æ74æÖSÒ&–GB×6WGF–æw2Ö7F–öâ×&÷r–GB×6WGF–æw2Ö7F–öâ×7VÖÖ'’#à¢Ç7ãà¢Ç7G&öæsäÖævR6W76–öç3Â÷7G&öæsà¢Â÷7ãà¢Ä6†Wg&öäF÷vâ6Æ74æÖSÒ&–GB×6WGF–æw2×&÷rÖ6†Wg&öâ"6—¦S×³gÒ&–Ö†–FFVãÒ'G'VR"óà¢Â÷7VÖÖ'“à¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2ÖF—66Æ÷7W&RÖ&öG’#à¢·6W76–öç4ÆöF–æròÇ6Æ74æÖSÒ&–GBÖÖÆW'B#äÆöF–ær7F—fR6W76–öç2ââãÂ÷â¢çVÆÇÐ¢·6W76–öç4W'&÷"ò€¢Ç6Æ74æÖSÒ&–GBÖÖÆW'B–GBÖÖÆW'BÖW'&÷""&öÆSÒ&ÆW'B#à¢·6W76–öç4W'&÷'Ð¢Â÷à¢’¢çVÆÇÐ¢²6W76–öç4ÆöF–ærò€¢Å6W76–öç4Æ—7@¢'W7•6W76–öä”C×¶'W7•6W76–öä”GÐ¢&Wfö¶–æt÷F†W'3×·&Wfö¶–æt÷F†W'7Ð¢6W76–öç3×·6W76–öç7Ð¢öå&Wfö¶S×¶†æFÆU&Wfö¶U6W76–öçÐ¢öå&Wfö¶T÷F†W'3×¶†æFÆU&Wfö¶T÷F†W%6W76–öç7Ð¢óà¢’¢çVÆÇÐ¢ÂöF—cà¢ÂöFWF–Ç3à¢ÂöF—cà ¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö66W72×6V7F–öâ#à¢ÆƒCåv÷&·76SÂöƒCà¢ÆFÂ6Æ74æÖSÒ&–GB×6WGF–æw2Öf7G2–GB×6WGF–æw2×v÷&·76RÖf7G2#à¢ÆF—cà¢ÆGCäæÖSÂöGCà¢ÆFCç·v÷&·76TF—7Æ”æÖWÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå–÷W"66W73ÂöGCà¢ÆFCç¶f÷&ÖEFö¶VäÆ&VÂ†7F—fU&öÆR—ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäFÖ–ç3ÂöGCà¢ÆFCç¶FÖ–äÖVÖ&W'7ÓÂöFCà¢ÂöF—cà¢ÂöFÃà¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2Ö6÷VçG2#à¢Æ'F–6ÆSà¢Ç7G&öæsç¶ÖVÖ&W'2æÆVæwF‡ÓÂ÷7G&öæsà¢Ç7ãåF÷FÂÖVÖ&W'3Â÷7ãà¢Âö'F–6ÆSà¢Æ'F–6ÆSà¢Ç7G&öæsç¶7F—fTÖVÖ&W'7ÓÂ÷7G&öæsà¢Ç7ãä7F—fSÂ÷7ãà¢Âö'F–6ÆSà¢Æ'F–6ÆSà¢Ç7G&öæsç¶–çf—FVDÖVÖ&W'7ÓÂ÷7G&öæsà¢Ç7ãä–çf—FVCÂ÷7ãà¢Âö'F–6ÆSà¢ÂöF—cà¢ÄÆ–æ²6Æ74æÖSÒ&–GB×6WGF–æw2Ö7F–öâ×&÷r"Fó×·v÷&·76W5F‡Óà¢Ç7ãà¢Ç7G&öæsäÖævRÖVÖ&W'3Â÷7G&öæsà¢Â÷7ãà¢Ä6†Wg&öå&–v‡B6—¦S×³gÒ&–Ö†–FFVãÒ'G'VR"óà¢ÂôÆ–æ³à¢ÂöF—cà¢ÂöF—cà¢Â÷6V7F–öãà ¢ÆFWF–Ç26Æ74æÖSÒ&–GB×6WGF–æw2Ö6&B–GB×6WGF–æw2ÖF—66Æ÷7W&R#à¢Ç7VÖÖ'’6Æ74æÖSÒ&–GB×6WGF–æw2ÖF—66Æ÷7W&R×7VÖÖ'’#à¢ÆF—cà¢Æƒ3äFWfVÆ÷W"FWF–Ç3Âöƒ3à¢ÂöF—cà¢Ç7â&–Ö†–FFVãÒ'G'VR"6Æ74æÖSÒ&–GB×6WGF–æw2ÖF—66Æ÷7W&RÖ6†Wg&öâ#à¢Ä6†Wg&öäF÷vâ6—¦S×³GÒóà¢Â÷7ãà¢Â÷7VÖÖ'“à¢ÆF—b6Æ74æÖSÒ&–GB×6WGF–æw2ÖF—66Æ÷7W&RÖ&öG’#à¢ÆFÂ6Æ74æÖSÒ&–GB×6WGF–æw2Öf7G2#à¢ÆF—cà¢ÆGCåFVæçB”CÂöGCà¢ÆFCç·66÷SòçFVæçD”BóòuVæf–Æ&ÆRwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCåv÷&·76R”CÂöGCà¢ÆFCç·66÷Sòçv÷&·76T”BóòuVæf–Æ&ÆRwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCå&–æ6—Â”CÂöGCà¢ÆFCç·v†ôÔ’òG¶f÷&ÖEFö¶VäÆ&VÂ‡v†ôÔ’ç&–æ6—ÂçG—R—ÒÒG·v†ôÔ’ç&–æ6—Âæ–GÖ¢uVæf–Æ&ÆRwÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCä7W7FöÒ66÷W3ÂöGCà¢ÆFCç¶FWfVÆ÷W%66÷TÆ&VÇÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCä†÷7FVBÆöv–ãÂöGCà¢ÆFCç¶†÷7FVDÆöv–å7FGW7ÓÂöFCà¢ÂöF—cà¢ÆF—cà¢ÆGCäWF‚&÷f–FW'3ÂöGCà¢ÆFCç¶FWfVÆ÷W%&÷f–FW$Æ&VÇÓÂöFCà¢ÂöF—cà¢ÂöFÃà¢ÂöF—cà¢ÂöFWF–Ç3à ¢ÄFævW%¦öæSà¢ÄFævW%¦öæU&÷p¢7F–öäÆ&VÃÒ%7W7VæB66÷VçB ¢öä7F–öã×²‚’Óâ°¢6WE7W7VæDW'&÷"‚rr“°¢6WE7W7VæDÖöFÄ÷Vâ‡G'VR“°¢×Ð¢VæF–æs×·7W7VæEVæF–æwÐ¢FW7D–CÒ&–GB×7W7VæBÖ66÷VçB×&÷r ¢F—FÆSÒ%7W7VæB66÷VçB ¢óà¢ÄFævW%¦öæU&÷p¢7F–öäÆ&VÃÒ$FVÆWFR66÷VçB ¢F—6&ÆVC×²&–Ö'”VÖ–ÇÐ¢öä7F–öã×¶†æFÆT÷VäFVÆWFTÖöFÇÐ¢VæF–æs×¶FVÆWFUVæF–æwÐ¢FW7D–CÒ&–GBÖFVÆWFRÖ66÷VçB×&÷r ¢F—FÆSÒ$FVÆWFR66÷VçB ¢óà¢²ò¢÷væW"ÖöæÇ’v÷&·76R&÷w2…"2öb3C#’âVæFVB–çFòF†R6ÖR¢÷Ð¢²ò¢FævW%¦öæR6&BöâW'÷6S¢6V6öæB6&Bv—F‚â–FVçF–6ÂF—FÆR¢÷Ð¢²ò¢v÷VÆBfVVÂÆ–¶RF†RvRÆ÷7BF†RÆ÷BÂæBF†R&÷rF—FÆW2Ç&VG’¢÷Ð¢²ò¢7FFRF†R66÷R…7W7VæBv÷&·76Rg27W7VæB66÷VçB’âæöâÖ÷væW'2¢÷Ð¢²ò¢&VæFW"W†7FÇ’F†RGvò66÷VçB&÷w2&÷fRÂæòÆ–÷WB6†ævRâ¢÷Ð¢¶—5v÷&·76T÷væW"bbv÷&·76TÆ–fV7–6ÆU7FGW2ÓÓÒv7F—fRrò€¢ÄFævW%¦öæU&÷p¢7F–öäÆ&VÃÒ%7W7VæBv÷&·76R ¢öä7F–öã×¶†æFÆT÷Våv÷&·76U7W7VæDÖöFÇÐ¢VæF–æs×·v÷&·76U7W7VæEVæF–æwÐ¢FW7D–CÒ&–GB×7W7VæB×v÷&·76R×&÷r ¢F—FÆSÒ%7W7VæBv÷&·76R ¢óà¢’¢çVÆÇÐ¢¶—5v÷&·76T÷væW"bbv÷&·76TÆ–fV7–6ÆU7FGW2ÓÓÒw7W7VæFVBrò€¢ÄFævW%¦öæU&÷p¢7F–öäÆ&VÃÒ%&V7F—fFRv÷&·76R ¢öä7F–öã×¶†æFÆT÷Våv÷&·76U&V7F—fFTÖöFÇÐ¢VæF–æs×·v÷&·76U&V7F—fFUVæF–æwÐ¢FW7D–CÒ&–GB×&V7F—fFR×v÷&·76R×&÷r ¢F—FÆSÒ%&V7F—fFRv÷&·76R ¢óà¢’¢çVÆÇÐ¢¶—5v÷&·76T÷væW"bbv÷&·76TÆ–fV7–6ÆU7FGW2ÓÒvFVÆWFVBrò€¢ÄFævW%¦öæU&÷p¢7F–öäÆ&VÃÒ$FVÆWFRv÷&·76R ¢F—6&ÆVC×²v÷&·76U6ÇVufÇVWÐ¢öä7F–öã×¶†æFÆT÷Våv÷&·76TFVÆWFTÖöFÇÐ¢VæF–æs×·v÷&·76TFVÆWFUVæF–æwÐ¢FW7D–CÒ&–GBÖFVÆWFR×v÷&·76R×&÷r ¢F—FÆSÒ$FVÆWFRv÷&·76R ¢óà¢’¢çVÆÇÐ¢¶—5v÷&·76T÷væW"bbv÷&·76TÆ–fV7–6ÆU7FGW2ÓÓÒvFVÆWFVBrò€¢ÄFævW%¦öæU&÷p¢7F–öäÆ&VÃÒ%&W7F÷&Rv÷&·76R ¢öä7F–öã×¶†æFÆT÷Våv÷&·76U&W7F÷&TÖöFÇÐ¢VæF–æs×·v÷&·76U&W7F÷&UVæF–æwÐ¢FW7D–CÒ&–GB×&W7F÷&R×v÷&·76R×&÷r ¢F—FÆSÒ%&W7F÷&Rv÷&·76R ¢óà¢’¢çVÆÇÐ¢ÂôFævW%¦öæSà ¢Ä6öæf—&ÔFW7G'V7F—fTÖöFÀ¢&öG“×°¢Ãà¢Çå–÷Rv–ÆÂ&R6–væVB÷WBöâÆÂFWf–6W2ãÂ÷à¢Çå–÷W"v÷&·76RÂ&ö¦V7G2ÂÖVÖ&W'6†—2ÂæB6öææV7F÷"FFv–ÆÂ&VÖ–â–çF7BãÂ÷à¢Âóà¢Ð¢6öæf—&ÖF–öã×·°¢¶–æC¢wG—R×FòÖ6öæf—&ÒrÀ¢W‡V7FVEfÇVS¢u5U5TäBrÀ¢–çWDÆ&VÃ¢€¢Ãà¢G—RÆVÒ6Æ74æÖSÒ&–GBÖFævW"Ö6öæf—&Ò×fÇVR#å5U5TäCÂöVÓâFò6öçF–çVP¢Âóà¢¢×Ð¢6öçF–çVTÆ&VÃÒ%7W7VæB66÷VçB ¢W'&÷$ÖW76vS×·7W7VæDW'&÷"ÇÂVæFVf–æVGÐ¢öä6æ6VÃ×²‚’Óâ°¢–b‡7W7VæEVæF–ær’&WGW&ã°¢6WE7W7VæDÖöFÄ÷Vâ†fÇ6R“°¢×Ð¢öä6öæf—&Ó×¶7–æ2‚’Óâ°¢–b‡7W7VæEVæF–ær’&WGW&ã°¢6WE7W7VæEVæF–ær‡G'VR“°¢6WE7W7VæDW'&÷"‚rr“°¢G'’°¢v—B”6Æ–VçBæFV7F—fFT7W'&VçEW6W"‚“°¢òò&W6WB&÷F‚WF‚66†W2F†Rv’F†RÆöv÷WB†æFÆW"FöW26òF†@¢òò&6²Öæf–vF–ærFò&Wf–÷W6Ç’×fÆ–FFVBöòâââ&÷WFRFöW0¢òòæ÷BG&ç6–VçFÇ’&VæFW"F†R&÷FV7FVB6†VÆÂv–ç7B7FÆR7FFP¢òò&Vf÷&RF†R6–ÆVçB÷cöÖR6†V6²&WGW&ç2Cà¢&W6WE&öGV7DWF…6W76–öä66†R‡²VæWF†VçF–6FVC¢G'VRÒ“°¢6ÆV$ÖT66†R‡²VæWF†VçF–6FVC¢G'VRÒ“°¢æf–vFR‚r÷6–væ–ã÷&V6öãÖ66÷VçEöFV7F—fFVBrÂ²&WÆ6S¢G'VRÒ“°¢Ò6F6‚†W'"’°¢6WE7W7VæDW'&÷"€¢W'"–ç7Fæ6VöbW'&÷"òW'"æÖW76vR¢uVæ&ÆRFò7W7VæB–÷W"66÷VçBâÆV6R&WG'’âp¢“°¢6WE7W7VæEVæF–ær†fÇ6R“°¢&WGW&ã°¢Ð¢6WE7W7VæEVæF–ær†fÇ6R“°¢6WE7W7VæDÖöFÄ÷Vâ†fÇ6R“°¢×Ð¢÷Vã×·7W7VæDÖöFÄ÷VçÐ¢VæF–æs×·7W7VæEVæF–æwÐ¢F—FÆSÒ%7W7VæB66÷VçB ¢óà¢Ä6öæf—&ÔFW7G'V7F—fTÖöFÀ¢&öG“×°¢Ãà¢ÇåF†—27F'G23ÖF’&V6÷fW'’v–æF÷ræB&Æö6·2æ÷&ÖÂ6–vâÖ–âãÂ÷à¢Çà¢gFW"F†Rv–æF÷rÂF†R66÷VçB—2W&ÖæVçFÇ’FVÆWFVBâæVVBâ&6†—fS÷²rwÐ¢Æ'WGFöà¢6Æ74æÖSÒ&–GBÖ–æÆ–æRÖ'WGFöâÖÆ–æ² ¢F—6&ÆVC×¶W‡÷'EVæF–æwÐ¢öä6Æ–6³×·7F'DFFW‡÷'GÐ¢G—SÒ&'WGFöâ ¢à¢¶W‡÷'EVæF–æròu&W&–ærW‡÷'Br¢tF÷væÆöB×’FFwÐ¢Âö'WGFöãç²rwÐ¢&Vf÷&RFVÆWF–ærà¢Â÷à¢¶FVÆWFU6öÆT÷væW%v÷&·76W2æÆVæwF‚âò€¢ÆF—`¢6Æ74æÖSÒ&–GBÖFævW"ÖÖöFÂÖ&Æö6¶W" ¢FF×FW7F–CÒ&–GBÖFVÆWFR×6öÆRÖ÷væW"×v÷&·76W2 ¢&öÆSÒ&ÆW'B ¢à¢Çà¢G&ç6fW"÷væW'6†—f÷"F†W6Rv÷&·76W2&Vf÷&RFVÆWF–ærF†—266÷VçBà¢Â÷à¢ÇVÃà¢¶FVÆWFU6öÆT÷væW%v÷&·76W2æÖ‚‡v÷&·76R’Óâ€¢ÆÆ’¶W“×¶G·v÷&·76RçFVæçEö–GÓ¢G·v÷&·76Rçv÷&·76Uö–GÖÓà¢¶66÷VçDFVÆWF–öåv÷&·76TÆ&VÂ‡v÷&·76R—Ð¢ÂöÆ“à¢’—Ð¢Â÷VÃà¢ÄÆ–æ²Fó×·v÷&·76W5F‡ÓäÖævRÖVÖ&W'3ÂôÆ–æ³à¢ÂöF—cà¢’¢çVÆÇÐ¢Âóà¢Ð¢6öæf—&ÖF–öã×·°¢¶–æC¢wG—R×FòÖ6öæf—&ÒrÀ¢W‡V7FVEfÇVS¢&–Ö'”VÖ–ÂÀ¢–çWDÆ&VÃ¢t6öæf—&Ò&–Ö'’VÖ–ÂrÀ¢†VÇFW‡C¢&–Ö'”VÖ–Âò€¢Ãà¢VçFW"ÆVÒ6Æ74æÖSÒ&–GBÖFævW"Ö6öæf—&Ò×fÇVR#ç·&–Ö'”VÖ–ÇÓÂöVÓâW†7FÇ’à¢Âóà¢’¢VæFVf–æV@¢×Ð¢6öçF–çVTÆ&VÃÒ$FVÆWFR66÷VçB ¢W'&÷$ÖW76vS×¶FVÆWFTW'&÷"ÇÂVæFVf–æVGÐ¢öä6æ6VÃ×¶†æFÆT6æ6VÄFVÆWFTÖöFÇÐ¢öä6öæf—&Ó×¶†æFÆTFVÆWFT66÷VçGÐ¢÷Vã×¶FVÆWFTÖöFÄ÷VçÐ¢VæF–æs×¶FVÆWFUVæF–æwÐ¢F—FÆSÒ$FVÆWFR66÷VçB ¢óà ¢²ò¢ÒÒÒv÷&·76RÆ–fV7–6ÆR6öæf—&ÖF–öâÖöFÇ2…"2öb3C#’âÒÒÒ¢÷Ð¢²ò¢&öG’6÷’Ö—'&÷'2F†R66÷VçB×6–FRGFW&ç2&÷fS¢Gvò6†÷'B¢÷Ð¢²ò¢6VçFVæ6W2ÂÖöæ÷76VBFö¶Vâ6†—f÷"G—R×FòÖ6öæf—&ÒÂU42²6æ6VÂ¢÷Ð¢²ò¢ff÷&Fæ6W2â6öÆRÖ÷væW"C’&VæFW'2–æÆ–æR6òF†R÷væW"6âf—‚¢÷Ð¢²ò¢F†R7G&æF–æræB&WG'’v—F†÷WBÆ÷6–ærF†RÖöFÂ6öçFW‡Bâ¢÷Ð¢Ä6öæf—&ÔFW7G'V7F—fTÖöFÀ¢&öG“×°¢Ãà¢Çä6öææV7F÷'2Â66ç2ÂæBvV&†öö·2v–ÆÂW6RãÂ÷à¢ÇäÖVÖ&W"66W72æB7F÷&VBFF&VÖ–â–çF7BãÂ÷à¢·v÷&·76U7W7VæE6öÆT÷væW"ò€¢ÆF—`¢6Æ74æÖSÒ&–GBÖFævW"ÖÖöFÂÖ&Æö6¶W" ¢FF×FW7F–CÒ&–GB×7W7VæB×v÷&·76R×6öÆRÖ÷væW"Ö&Æö6² ¢&öÆSÒ&ÆW'B ¢à¢·v÷&·76U7W7VæE7G&æFVBæÆVæwF‚âò€¢Ãà¢Çà¢&öÖ÷FRæ÷F†W"÷væW"&Vf÷&R7W7VæF–ær6òF†W6RÖVÖ&W'2&Ræ÷@¢7G&æFVBà¢Â÷à¢ÇVÃà¢·v÷&·76U7W7VæE7G&æFVBæÖ‚†ÖVÖ&W"’Óâ€¢ÆÆ’¶W“×¶ÖVÖ&W"æÖVÖ&W%ö–GÓà¢·v÷&·76U6öÆT÷væW$ÖVÖ&W$Æ&VÂ†ÖVÖ&W"—Ð¢ÂöÆ“à¢’—Ð¢Â÷VÃà¢Âóà¢’¢€¢òò&6¶VæB6öæf—&ÖVB6öÆRÖ÷væW"7G&æF–ær'WBF†RffV7FVBÖÖVÖ&W ¢òòÆ—7BF–FâwB'6R(	B7F–ÆÂ7W&f6RF†R&Æö6¶W"6òF†R7F÷ ¢òò¶æ÷w2v†BFòFò†7V&–2"3CSb"’à¢Çà¢F†—2v÷&·76R†2öæÇ’öæR÷væW"â&öÖ÷FRæ÷F†W"÷væW"&Vf÷&P¢7W7VæF–ær6ò÷F†W"ÖVÖ&W'2&Ræ÷B7G&æFVBà¢Â÷à¢—Ð¢ÄÆ–æ²Fó×·v÷&·76W5F‡ÓäÖævRÖVÖ&W'3ÂôÆ–æ³à¢ÂöF—cà¢’¢çVÆÇÐ¢Âóà¢Ð¢6öæf—&ÖF–öã×·°¢¶–æC¢wG—R×FòÖ6öæf—&ÒrÀ¢W‡V7FVEfÇVS¢u5U5TäBrÀ¢–çWDÆ&VÃ¢€¢Ãà¢G—RÆVÒ6Æ74æÖSÒ&–GBÖFævW"Ö6öæf—&Ò×fÇVR#å5U5TäCÂöVÓâFò6öçF–çVP¢Âóà¢¢×Ð¢6öçF–çVTÆ&VÃÒ%7W7VæBv÷&·76R ¢W'&÷$ÖW76vS×·v÷&·76U7W7VæDW'&÷"ÇÂVæFVf–æVGÐ¢öä6æ6VÃ×¶†æFÆT6æ6VÅv÷&·76U7W7VæDÖöFÇÐ¢öä6öæf—&Ó×¶†æFÆU7W7VæEv÷&·76WÐ¢÷Vã×·v÷&·76U7W7VæDÖöFÄ÷VçÐ¢VæF–æs×·v÷&·76U7W7VæEVæF–æwÐ¢F—FÆSÒ%7W7VæBv÷&·76R ¢óà ¢Ä6öæf—&ÔFW7G'V7F—fTÖöFÀ¢&öG“×°¢Ãà¢Çä6öææV7F÷'2Â66ç2ÂæBvV&†öö·2v–ÆÂ&W7VÖRãÂ÷à¢Âóà¢Ð¢6öæf—&ÖF–öã×·°¢¶–æC¢v6†V6¶&÷‚rÀ¢Æ&VÃ¢u&W7VÖR6öææV7F÷'2Â66ç2ÂæBvV&†öö·2f÷"F†—2v÷&·76Râp¢×Ð¢6öçF–çVTÆ&VÃÒ%&V7F—fFRv÷&·76R ¢W'&÷$ÖW76vS×·v÷&·76U&V7F—fFTW'&÷"ÇÂVæFVf–æVGÐ¢öä6æ6VÃ×¶†æFÆT6æ6VÅv÷&·76U&V7F—fFTÖöFÇÐ¢öä6öæf—&Ó×¶†æFÆU&V7F—fFUv÷&·76WÐ¢÷Vã×·v÷&·76U&V7F—fFTÖöFÄ÷VçÐ¢VæF–æs×·v÷&·76U&V7F—fFUVæF–æwÐ¢F—FÆSÒ%&V7F—fFRv÷&·76R ¢óà ¢Ä6öæf—&ÔFW7G'V7F—fTÖöFÀ¢&öG“×°¢Ãà¢ÇåF†—27F'G23ÖF’&V6÷fW'’v–æF÷ræBF—6&ÆW2F†Rv÷&·76RãÂ÷à¢ÇägFW"F†Rv–æF÷rÂF†Rv÷&·76RæBÆÂ—G2FF&RW&ÖæVçFÇ’W&vVBãÂ÷à¢·v÷&·76TFVÆWFU6öÆT÷væW"ò€¢ÆF—`¢6Æ74æÖSÒ&–GBÖFævW"ÖÖöFÂÖ&Æö6¶W" ¢FF×FW7F–CÒ&–GBÖFVÆWFR×v÷&·76R×6öÆRÖ÷væW"Ö&Æö6² ¢&öÆSÒ&ÆW'B ¢à¢·v÷&·76TFVÆWFU7G&æFVBæÆVæwF‚âò€¢Ãà¢Çà¢&öÖ÷FRæ÷F†W"÷væW"&Vf÷&RFVÆWF–ær6òF†W6RÖVÖ&W'2&Ræ÷@¢7G&æFVBà¢Â÷à¢ÇVÃà¢·v÷&·76TFVÆWFU7G&æFVBæÖ‚†ÖVÖ&W"’Óâ€¢ÆÆ’¶W“×¶ÖVÖ&W"æÖVÖ&W%ö–GÓà¢·v÷&·76U6öÆT÷væW$ÖVÖ&W$Æ&VÂ†ÖVÖ&W"—Ð¢ÂöÆ“à¢’—Ð¢Â÷VÃà¢Âóà¢’¢€¢Çà¢F†—2v÷&·76R†2öæÇ’öæR÷væW"â&öÖ÷FRæ÷F†W"÷væW"&Vf÷&P¢FVÆWF–ær6ò÷F†W"ÖVÖ&W'2&Ræ÷B7G&æFVBà¢Â÷à¢—Ð¢ÄÆ–æ²Fó×·v÷&·76W5F‡ÓäÖævRÖVÖ&W'3ÂôÆ–æ³à¢ÂöF—cà¢’¢çVÆÇÐ¢Âóà¢Ð¢6öæf—&ÖF–öã×·°¢¶–æC¢wG—R×FòÖ6öæf—&ÒrÀ¢W‡V7FVEfÇVS¢v÷&·76U6ÇVufÇVRÀ¢–çWDÆ&VÃ¢t6öæf—&Òv÷&·76R6ÇVrrÀ¢†VÇFW‡C¢v÷&·76U6ÇVufÇVRò€¢Ãà¢VçFW"ÆVÒ6Æ74æÖSÒ&–GBÖFævW"Ö6öæf—&Ò×fÇVR#ç·v÷&·76U6ÇVufÇVWÓÂöVÓç²rwÐ¢W†7FÇ’à¢Âóà¢’¢€¢uv÷&·76R6ÇVr—2Væf–Æ&ÆS²&VÆöBF†RvR&Vf÷&R&WG'––ærâp¢¢×Ð¢6öçF–çVTÆ&VÃÒ$FVÆWFRv÷&·76R ¢W'&÷$ÖW76vS×·v÷&·76TFVÆWFTW'&÷"ÇÂVæFVf–æVGÐ¢öä6æ6VÃ×¶†æFÆT6æ6VÅv÷&·76TFVÆWFTÖöFÇÐ¢öä6öæf—&Ó×¶†æFÆTFVÆWFUv÷&·76WÐ¢÷Vã×·v÷&·76TFVÆWFTÖöFÄ÷VçÐ¢VæF–æs×·v÷&·76TFVÆWFUVæF–æwÐ¢F—FÆSÒ$FVÆWFRv÷&·76R ¢óà ¢Ä6öæf—&ÔFW7G'V7F—fTÖöFÀ¢&öG“×°¢Ãà¢Çå&W7F÷&W2F†Rv÷&·76RæB6æ6VÇ2F†R66†VGVÆVBFVÆWF–öâãÂ÷à¢Âóà¢Ð¢6öæf—&ÖF–öã×·°¢¶–æC¢v6†V6¶&÷‚rÀ¢Æ&VÃ¢t6æ6VÂF†R66†VGVÆVBFVÆWF–öâæB&W7F÷&RF†—2v÷&·76Râp¢×Ð¢6öçF–çVTÆ&VÃÒ%&W7F÷&Rv÷&·76R ¢W'&÷$ÖW76vS×·v÷&·76U&W7F÷&TW'&÷"ÇÂVæFVf–æVGÐ¢öä6æ6VÃ×¶†æFÆT6æ6VÅv÷&·76U&W7F÷&TÖöFÇÐ¢öä6öæf—&Ó×¶†æFÆU&W7F÷&Uv÷&·76WÐ¢÷Vã×·v÷&·76U&W7F÷&TÖöFÄ÷VçÐ¢VæF–æs×·v÷&·76U&W7F÷&UVæF–æwÐ¢F—FÆSÒ%&W7F÷&Rv÷&·76R ¢óà¢Â÷6V7F–öãà¢“°§Ð