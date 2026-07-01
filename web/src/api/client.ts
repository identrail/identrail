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
  confidence_score?: number;
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
  lifecycle_key?: string;
  lifecycle_status?: RepoFindingLifecycleStatus;
  owner?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  fixed_at?: string;
  reopened_at?: string;
  dismissed_at?: string;
  suppression_expires_at?: string;
  rule_version?: string;
  detector_version?: string;
  adapter_source?: string;
  confidence_state?: string;
  verification_status?: string;
  scan_mode?: string;
  evidence_version?: string;
  evidence?: Record<string, unknown>;
  remediation: string;
  created_at: string;
  triage?: FindingTriage;
};

export type RepoFindingLifecycleStatus =
  | 'open'
  | 'fixed'
  | 'reopened'
  | 'suppressed'
  | 'risk_accepted'
  | 'false_positive';

export type RepoFindingsSummary = {
  total_open: number;
  fixed_count: number;
  reopened_count: number;
  suppressed_count: number;
  sla_aged_count: number;
  mttr_ready_resolved_count: number;
  mean_time_to_resolve_seconds?: number;
  oldest_open_first_seen_at?: string;
  by_owner: Record<string, number>;
  by_detector: Record<string, number>;
  by_severity: Record<string, number>;
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
  scan_mode?: 'quick' | 'delta' | 'deep';
  base_revision?: string;
  head_revision?: string;
  cursor_before?: string;
  cursor_after?: string;
  changed_paths?: string[];
  error_message?: string;
};

export type RepoScanRequest = {
  repository: string;
  project_id?: string;
  connector_id?: string;
  scan_mode?: 'quick' | 'delta' | 'deep';
  base_revision?: string;
  head_revision?: string;
  changed_paths?: string[];
  history_limit?: number;
  max_findings?: number;
};

export type RepoExposurePatchTemplate = {
  strategy:
    | 'line_literal'
    | 'line_regex'
    | 'workflow_permissions_read_default'
    | 'workflow_pull_request_trigger';
  description: string;
  match?: string;
  match_pattern?: string;
  replacement: string;
  requires_source_content: boolean;
  placeholder: boolean;
};

export type RepoExposureRemediationScope = {
  finding_id: string;
  scan_id?: string;
  repository?: string;
  commit?: string;
  file_path?: string;
  line_number?: number;
  line_snippet?: string;
};

export type RepoExposureRemediation = {
  detector: string;
  summary: string;
  risk_summary: string;
  steps: string[];
  safety_notes: string[];
  validation: string[];
  patch?: RepoExposurePatchTemplate;
  secret_rotation: boolean;
  publishable: boolean;
  publish_blocked_reason?: string;
  evidence: RepoExposureRemediationScope;
};

export type FixPRPlanFile = {
  path: string;
  content: string;
};

export type FixPRPlan = {
  base_branch: string;
  branch_name: string;
  commit_message: string;
  pr_title: string;
  pr_body: string;
  files: FixPRPlanFile[];
  finding_id: string;
  finding_type: string;
};

export type RepoFindingRemediationPreviewRequest = {
  repo_scan_id?: string;
  source_content?: string;
  base_branch?: string;
  branch_prefix?: string;
  finding_url?: string;
  require_fix_plan?: boolean;
};

export type RepoFindingRemediationPreview = {
  finding: Finding;
  remediation: RepoExposureRemediation;
  fix_pr_plan?: FixPRPlan;
};

export type RepoFindingRemediationPublishRequest = {
  repo_scan_id?: string;
  source_content: string;
  base_branch?: string;
  branch_prefix?: string;
  finding_url?: string;
  operator_approved: boolean;
  write_permissions_configured: boolean;
  github_token: string;
};

export type RepoRemediationPublishResult = {
  pr_number: number;
  pr_url: string;
  branch_name: string;
  commit_sha: string;
};

export type RepoFindingRemediationPublishResponse = {
  finding: Finding;
  remediation: RepoExposureRemediation;
  publish: RepoRemediationPublishResult;
};

export type RepoRiskGraphNode = {
  id: string;
  kind: string;
  label: string;
  repository?: string;
  evidence_state: 'known' | 'unknown';
  evidence?: Record<string, unknown>;
};

export type RepoRiskGraphEdge = {
  id: string;
  kind: string;
  from_node_id: string;
  to_node_id: string;
  evidence_state: 'known' | 'unknown';
  evidence?: Record<string, unknown>;
};

export type RepoRiskGraphScoreFactors = {
  severity: number;
  confidence: number;
  exploitability: number;
  privilege: number;
  exposure: number;
  environment_criticality: number;
  freshness: number;
};

export type RepoRiskGraphFindingScore = {
  finding_id: string;
  finding_node_id: string;
  score: number;
  severity: string;
  confidence: number;
  factors: RepoRiskGraphScoreFactors;
  unknowns: string[];
};

export type RepoRiskGraphSummary = {
  finding_count: number;
  node_count: number;
  edge_count: number;
  unknown_node_count: number;
  unknown_edge_count: number;
  high_risk_findings: number;
  critical_findings: number;
};

export type RepoRiskGraph = {
  repository: string;
  nodes: RepoRiskGraphNode[];
  edges: RepoRiskGraphEdge[];
  scores: RepoRiskGraphFindingScore[];
  summary: RepoRiskGraphSummary;
};

export type ScanRecord = {
  id: string;
  project_id?: string;
  connector_id?: string;
  provider: string;
  status: string;
  started_at: string;
  finished_at?: string;
  asset_count: number;
  finding_count: number;
  error_message?: string;
};

export type ScanRequest = {
  project_id?: string;
  connector_id?: string;
};

export type TrendPoint = {
  scan_id: string;
  started_at: string;
  total: number;
  by_severity: Record<string, number>;
};

// Domain filter accepted by /v1/enterprise/reports/executive. Empty string
// means "all domains" (the default). Unknown values are rejected server-side.
export type ExecutiveReportDomain = '' | 'aws' | 'github' | 'kubernetes';

export type ExecutiveReport = {
  organization_id: string;
  generated_at: string;
  window_start: string;
  window_end: string;
  total_open_findings: number;
  open_by_severity: Record<string, number>;
  open_by_type: Record<string, number>;
  top_finding_types?: Array<{ type: string; count: number }> | null;
  week_over_week: {
    current_count: number;
    previous_count: number;
    delta: number;
  };
  mean_time_to_resolve?: {
    resolved_count: number;
    seconds: number;
  } | null;
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

export type WorkspaceLifecycleStatus = 'active' | 'suspended' | 'deleted';

export type WorkspaceRecord = {
  tenant_id: string;
  workspace_id: string;
  display_name: string;
  slug: string;
  created_at: string;
  updated_at: string;
  status?: WorkspaceLifecycleStatus;
  suspended_at?: string | null;
  deleted_at?: string | null;
};

// Each lifecycle endpoint deterministically transitions the workspace to a
// single terminal state, so the top-level `status` is narrowed to that
// literal (cubic PR #1456 P3). The broader `WorkspaceLifecycleStatus` still
// lives on `workspace.status` via `WorkspaceRecord` because that field
// reflects whatever the backend serialized for the workspace as a whole.
export type WorkspaceSuspendResponse = {
  workspace: WorkspaceRecord;
  status: 'suspended';
  suspended_at?: string | null;
};

export type WorkspaceReactivateResponse = {
  workspace: WorkspaceRecord;
  status: 'active';
};

export type WorkspaceDeleteResponse = {
  workspace: WorkspaceRecord;
  status: 'deleted';
  deleted_at?: string | null;
  hard_delete_after?: string;
  grace_period_hours?: number;
};

export type WorkspaceCancelDeletionResponse = {
  workspace: WorkspaceRecord;
  status: 'active';
};

export type WorkspaceSoleOwnerAffectedMember = {
  member_id: string;
  user_id: string;
  email?: string;
  role: string;
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
    native_saml_enabled: boolean;
    providers: string[];
  };
  // Advertised by the API so the web bundle does not show a backend-gated
  // self-serve flow the API cannot serve. Optional for resilience against an
  // older API that predates this contract.
  features?: {
    onboarding_wizard: boolean;
    connectors: {
      github: boolean;
      aws: boolean;
      kubernetes: boolean;
    };
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

export type CurrentUserProfileUpdate = {
  display_name?: string;
  avatar_url?: string;
};

export type AccountDeletionWorkspace = {
  tenant_id: string;
  workspace_id: string;
  display_name?: string;
  slug?: string;
};

export type DeleteCurrentUserResponse = {
  status: 'deleted';
  deleted_at?: string | null;
  hard_delete_after?: string;
  grace_period_hours?: number;
};

export type CancelCurrentUserDeletionResponse = {
  status: 'active';
};

export type OnboardingStep = 'org' | 'workspace' | 'connect' | 'scan' | 'invite' | 'complete';

export type OnboardingState = {
  user_id: string;
  current_step: OnboardingStep;
  org_id?: string;
  workspace_id?: string;
  project_id?: string;
  connector_id?: string;
  connector_type?: 'aws' | 'github' | 'kubernetes';
  connector_skipped: boolean;
  scan_skipped: boolean;
  dashboard_tour_dismissed_at?: string;
  completed_at?: string;
  started_at: string;
  updated_at: string;
};

export type OnboardingStateUpdateRequest = {
  current_step?: Exclude<OnboardingStep, 'complete'>;
  org_name?: string;
  org_slug?: string;
  workspace_name?: string;
  workspace_slug?: string;
  project_name?: string;
  project_id?: string;
  connector_id?: string;
  connector_type?: 'aws' | 'github' | 'kubernetes';
  connector_skipped?: boolean;
  scan_skipped?: boolean;
  dashboard_tour_dismissed?: boolean;
};

export type OnboardingStateResponse = {
  state: OnboardingState;
  redirect_path?: string;
};

export type DataExportJobStatus = 'queued' | 'running' | 'ready' | 'failed' | 'expired';

export type DataExportJob = {
  id: string;
  status: DataExportJobStatus;
  requested_at: string;
  started_at?: string;
  completed_at?: string;
  download_url?: string;
  download_expires_at?: string;
  bundle_size_bytes?: number;
  bundle_sha256?: string;
  error_message?: string;
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

export type WorkOSMFAFactor = {
  id: string;
  type: string;
};

export type WorkOSMFATOTP = {
  factor_id: string;
  qr_code: string;
  secret: string;
  uri: string;
};

export type WorkOSMFAPendingResponse = {
  mode: 'enrollment' | 'challenge' | string;
  user_email?: string;
  challenge_started: boolean;
  factors: WorkOSMFAFactor[];
  totp?: WorkOSMFATOTP;
  expires_at?: string;
};

export type WorkOSMFAChallengeResponse = {
  challenge_started: boolean;
  factor_id: string;
  expires_at?: string;
};

export type WorkOSMFAVerifyResponse = {
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
  scopes: string[] | null;
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
  full_name?: string;
  role_title?: string;
  environment: string;
  company?: string;
  company_domain?: string;
  challenge?: string;
  preferred_day?: string;
  preferred_time?: string;
  identity_provider?: string;
  infrastructure_scope?: string;
  repository_url?: string;
  website?: string;
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
  resolved_at?: string;
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

export type ConnectorCapability =
  | 'discovery'
  | 'runtime_evidence'
  | 'remediation_plan'
  | 'approved_remediation'
  | 'authorization_advisory'
  | 'authorization_enforcement';

export type ConnectorCapabilityTier = 'read_only' | 'write';

export type AWSCapabilityPermissionTier = {
  capability: ConnectorCapability;
  tier: ConnectorCapabilityTier;
  available: boolean;
  summary: string;
  permissions: AWSPermissionPreviewItem[];
};

export type AWSConnectorCapabilityUnavailable = {
  capability: ConnectorCapability;
  tier: ConnectorCapabilityTier;
  reason: string;
};

export type AWSConnectorCapabilities = {
  requested: ConnectorCapability[];
  validated: ConnectorCapability[];
  effective: ConnectorCapability[];
  unavailable: AWSConnectorCapabilityUnavailable[];
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
  capabilities: AWSConnectorCapabilities;
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
  capabilities?: ConnectorCapability[];
};

export type AWSPlatformBaselineStatus = 'not_run' | 'ready' | 'degraded' | 'blocked';
export type AWSPlatformBaselineCheckStatus = 'passed' | 'failed' | 'degraded' | 'permission_denied' | 'unknown' | 'skipped';

export type AWSPlatformBaselineCheck = {
  name: string;
  category: string;
  required: boolean;
  status: AWSPlatformBaselineCheckStatus;
  message: string;
  failure_reason?: string;
  remediation?: string;
  evidence_url?: string;
  confidence: number;
  evidence?: Record<string, unknown>;
  checked_at: string;
};

export type AWSPlatformBaselineResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  git_sha: string;
  source_mode: string;
  fixture_only: boolean;
  connector_profile_version: string;
  graph_contract_version: string;
  account_id?: string;
  region?: string;
  status: AWSPlatformBaselineStatus;
  confidence: number;
  required_checks_passed: boolean;
  failure_reasons: string[];
  evidence_links: string[];
  checks: AWSPlatformBaselineCheck[];
  verified_at: string;
  created_at: string;
  updated_at: string;
};

export type AWSPlatformBaselineRequest = {
  connector_id?: string;
  git_sha?: string;
};

export type AWSPlatformDependencyStatus = 'ready' | 'degraded' | 'blocked';
export type AWSPlatformIssueDependencyStatus = 'completed' | 'ready' | 'blocked';

export type AWSPlatformDependencyCheck = {
  name: string;
  category: string;
  required: boolean;
  status: AWSPlatformDependencyStatus;
  message: string;
  failure_reason?: string;
  remediation?: string;
  evidence_url?: string;
  confidence: number;
  evidence?: Record<string, unknown>;
  checked_at: string;
};

export type AWSPlatformDependencyIssue = {
  issue_number: number;
  issue_ref: string;
  title: string;
  wave: number;
  wave_name: string;
  sequence: number;
  blocker_refs: string[];
  downstream_refs: string[];
  dependency_status: AWSPlatformIssueDependencyStatus;
  ready_for_pr: boolean;
  failure_reasons: string[];
  remediation: string;
  next_action: string;
  evidence_url: string;
};

export type AWSPlatformDependencyIndexResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSPlatformDependencyStatus;
  confidence: number;
  issue_count: number;
  wave_count: number;
  ready_issue_count: number;
  blocked_issue_count: number;
  completed_issue_refs: string[];
  ready_issue_refs: string[];
  blocked_issue_refs: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  checks: AWSPlatformDependencyCheck[];
  issues: AWSPlatformDependencyIssue[];
  generated_at: string;
  updated_at: string;
};

export type AWSPlatformValidationStatus = 'ready' | 'degraded' | 'blocked';
export type AWSPlatformValidationFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied'
  | 'unsupported_service';

export type AWSPlatformValidationStep = {
  id: string;
  kind: 'browser' | 'api' | string;
  flow: string;
  label: string;
  target: string;
  method?: string;
  expected_state: string;
  required: boolean;
  evidence_url: string;
};

export type AWSPlatformValidationScenario = {
  id: string;
  flow: string;
  fixture_state: AWSPlatformValidationFixtureState;
  status: AWSPlatformValidationStatus;
  label: string;
  summary: string;
  operator_message: string;
  failure_reason?: string;
  remediation?: string;
  next_action: string;
  evidence_url: string;
  account_id?: string;
  region?: string;
  required: boolean;
  confidence: number;
  evidence?: Record<string, unknown>;
  browser_step_ids: string[];
  api_step_ids: string[];
  checked_at: string;
};

export type AWSPlatformValidationHarnessResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSPlatformValidationStatus;
  confidence: number;
  scenario_count: number;
  required_scenario_count: number;
  fixture_states: AWSPlatformValidationFixtureState[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  browser_steps: AWSPlatformValidationStep[];
  api_steps: AWSPlatformValidationStep[];
  scenarios: AWSPlatformValidationScenario[];
  generated_at: string;
  updated_at: string;
};

export type AWSServiceCollectorContractStatus = 'ready' | 'degraded' | 'blocked';
export type AWSServiceCollectorFixtureState =
  | 'success'
  | 'empty'
  | 'pagination'
  | 'throttling'
  | 'partial_failure'
  | 'unsupported_region'
  | 'permission_denied'
  | 'degraded';

export type AWSServiceCollectorContractCheck = {
  name: string;
  category: string;
  required: boolean;
  status: AWSServiceCollectorContractStatus;
  message: string;
  failure_reason?: string;
  remediation?: string;
  evidence_url?: string;
  confidence: number;
  evidence?: Record<string, unknown>;
  checked_at: string;
};

export type AWSServiceCollectorGraphEdge = {
  name: string;
  relationship_type: string;
  from_endpoint: string;
  to_endpoint: string;
  evidence: string;
  required: boolean;
};

export type AWSServiceCollectorFixtureCase = {
  id: string;
  state: AWSServiceCollectorFixtureState;
  label: string;
  expected_status: AWSServiceCollectorContractStatus;
  source_error_code?: string;
  retryable: boolean;
  required: boolean;
  evidence_boundary: string;
};

export type AWSServiceCollectorContractResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSServiceCollectorContractStatus;
  confidence: number;
  required_field_count: number;
  graph_edge_count: number;
  fixture_case_count: number;
  required_fixture_case_count: number;
  normalized_record_fields: string[];
  required_permissions: string[];
  read_only_boundaries: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  checks: AWSServiceCollectorContractCheck[];
  graph_edges: AWSServiceCollectorGraphEdge[];
  fixture_cases: AWSServiceCollectorFixtureCase[];
  generated_at: string;
  updated_at: string;
};

export type AWSEC2InstanceProfileInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSEC2InstanceProfileFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSEC2InstanceProfileRecord = {
  account_id: string;
  region: string;
  service: string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_arn?: string;
  role_name?: string;
  instance_id?: string;
  instance_arn?: string;
  instance_name?: string;
  instance_state?: string;
  instance_profile_arn?: string;
  instance_profile_id?: string;
  instance_profile_name?: string;
  launch_template_id?: string;
  launch_template_name?: string;
  launch_template_version?: string;
  imds_endpoint?: string;
  imds_http_tokens?: string;
  imds_hop_limit?: number;
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSEC2InstanceProfileRelationship = {
  type: 'runs_as' | 'attached_to' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSEC2InstanceProfileDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSEC2InstanceProfileInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSEC2InstanceProfileInventoryStatus;
  fixture_state: AWSEC2InstanceProfileFixtureState;
  confidence: number;
  record_count: number;
  workload_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  records: AWSEC2InstanceProfileRecord[];
  relationships: AWSEC2InstanceProfileRelationship[];
  diagnostics: AWSEC2InstanceProfileDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSECSTaskRoleInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSECSTaskRoleFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSECSTaskRoleRecord = {
  account_id: string;
  region: string;
  service: string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_kind: 'task_role' | 'execution_role' | string;
  role_arn?: string;
  role_name?: string;
  cluster_arn?: string;
  cluster_name?: string;
  service_arn?: string;
  service_name?: string;
  service_status?: string;
  task_definition_arn?: string;
  task_definition_family?: string;
  task_definition_revision?: string;
  task_definition_status?: string;
  task_role_arn?: string;
  execution_role_arn?: string;
  launch_type?: string;
  scheduling_strategy?: string;
  desired_count?: number;
  running_count?: number;
  pending_count?: number;
  compatibilities?: string[];
  container_images?: string[];
  secret_refs?: string[];
  environment_keys?: string[];
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | 'attached_to' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSECSTaskRoleRelationship = {
  type: 'runs_as' | 'attached_to' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSECSTaskRoleDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSECSTaskRoleInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSECSTaskRoleInventoryStatus;
  fixture_state: AWSECSTaskRoleFixtureState;
  confidence: number;
  record_count: number;
  task_role_count: number;
  execution_role_count: number;
  workload_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  records: AWSECSTaskRoleRecord[];
  relationships: AWSECSTaskRoleRelationship[];
  diagnostics: AWSECSTaskRoleDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSLambdaExecutionRoleInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSLambdaExecutionRoleFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSLambdaExecutionRoleRecord = {
  account_id: string;
  region: string;
  service: string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_arn?: string;
  role_name?: string;
  function_arn?: string;
  function_name?: string;
  function_version?: string;
  function_state?: string;
  last_update_status?: string;
  runtime?: string;
  package_type?: string;
  handler?: string;
  kms_key_arn?: string;
  memory_size?: number;
  timeout?: number;
  vpc_id?: string;
  subnet_ids?: string[];
  security_group_ids?: string[];
  architectures?: string[];
  layer_arns?: string[];
  alias_names?: string[];
  version_refs?: string[];
  event_source_arns?: string[];
  event_source_mapping_uuids?: string[];
  disabled_event_source_arns?: string[];
  disabled_event_source_reasons?: string[];
  environment_keys?: string[];
  secret_refs?: string[];
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSLambdaExecutionRoleRelationship = {
  type: 'runs_as' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSLambdaExecutionRoleDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSLambdaExecutionRoleInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSLambdaExecutionRoleInventoryStatus;
  fixture_state: AWSLambdaExecutionRoleFixtureState;
  confidence: number;
  record_count: number;
  function_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  event_source_count: number;
  disabled_event_source_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  records: AWSLambdaExecutionRoleRecord[];
  relationships: AWSLambdaExecutionRoleRelationship[];
  diagnostics: AWSLambdaExecutionRoleDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSCodeBuildServiceRoleInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSCodeBuildServiceRoleFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSCodeBuildServiceRoleRecord = {
  account_id: string;
  region: string;
  service: string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_arn?: string;
  role_name?: string;
  project_arn?: string;
  project_name?: string;
  project_description?: string;
  project_visibility?: string;
  source_type?: string;
  source_location?: string;
  source_auth_type?: string;
  source_version?: string;
  source_identifiers?: string[];
  artifact_types?: string[];
  artifact_locations?: string[];
  environment_type?: string;
  compute_type?: string;
  image?: string;
  image_pull_credentials_type?: string;
  privileged_mode?: boolean;
  kms_key_arn?: string;
  cache_type?: string;
  cache_location?: string;
  log_types?: string[];
  vpc_id?: string;
  subnet_ids?: string[];
  security_group_ids?: string[];
  environment_keys?: string[];
  secret_refs?: string[];
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSCodeBuildServiceRoleRelationship = {
  type: 'runs_as' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSCodeBuildServiceRoleDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSCodeBuildServiceRoleInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSCodeBuildServiceRoleInventoryStatus;
  fixture_state: AWSCodeBuildServiceRoleFixtureState;
  confidence: number;
  record_count: number;
  project_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  secret_ref_count: number;
  vpc_project_count: number;
  public_project_count: number;
  privileged_project_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  records: AWSCodeBuildServiceRoleRecord[];
  relationships: AWSCodeBuildServiceRoleRelationship[];
  diagnostics: AWSCodeBuildServiceRoleDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSCodePipelineDeploymentRoleInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSCodePipelineDeploymentRoleFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSCodePipelineDeploymentRoleRecord = {
  account_id: string;
  region: string;
  service: string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_arn?: string;
  role_name?: string;
  role_account_id?: string;
  role_kind?: string;
  pipeline_arn?: string;
  pipeline_name?: string;
  pipeline_version?: number;
  pipeline_type?: string;
  execution_mode?: string;
  stage_name?: string;
  action_name?: string;
  action_category?: string;
  action_owner?: string;
  action_provider?: string;
  action_version?: string;
  action_region?: string;
  run_order?: number;
  namespace?: string;
  input_artifact_names?: string[];
  output_artifact_names?: string[];
  artifact_store_types?: string[];
  artifact_store_locations?: string[];
  artifact_store_regions?: string[];
  artifact_kms_key_arns?: string[];
  configuration_keys?: string[];
  provider_identifiers?: string[];
  disabled_stage_transitions?: string[];
  cross_region_artifact_stores?: boolean;
  cross_region_action?: boolean;
  cross_account_role?: boolean;
  pass_role_adjacent?: boolean;
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSCodePipelineDeploymentRoleRelationship = {
  type: 'runs_as' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSCodePipelineDeploymentRoleDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSCodePipelineDeploymentRoleInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSCodePipelineDeploymentRoleInventoryStatus;
  fixture_state: AWSCodePipelineDeploymentRoleFixtureState;
  confidence: number;
  record_count: number;
  pipeline_count: number;
  action_role_count: number;
  cross_account_role_count: number;
  cross_region_action_count: number;
  disabled_stage_transition_count: number;
  pass_role_adjacent_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  records: AWSCodePipelineDeploymentRoleRecord[];
  relationships: AWSCodePipelineDeploymentRoleRelationship[];
  diagnostics: AWSCodePipelineDeploymentRoleDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSStepFunctionsStateMachineRoleInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSStepFunctionsStateMachineRoleFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSStepFunctionsStateMachineRoleRecord = {
  account_id: string;
  region: string;
  service: string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_arn?: string;
  role_name?: string;
  role_account_id?: string;
  state_machine_arn?: string;
  state_machine_name?: string;
  state_machine_type?: string;
  state_machine_status?: string;
  revision_id?: string;
  definition_sha256?: string;
  definition_resource_arns?: string[];
  task_resource_arns?: string[];
  service_integration_resources?: string[];
  nested_state_machine_arns?: string[];
  logging_level?: string;
  logging_include_execution_data?: boolean;
  log_group_arns?: string[];
  tracing_enabled?: boolean;
  encryption_type?: string;
  kms_key_arn?: string;
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSStepFunctionsStateMachineRoleRelationship = {
  type: 'runs_as' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSStepFunctionsStateMachineRoleDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSStepFunctionsStateMachineRoleInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSStepFunctionsStateMachineRoleInventoryStatus;
  fixture_state: AWSStepFunctionsStateMachineRoleFixtureState;
  confidence: number;
  record_count: number;
  state_machine_count: number;
  nested_workflow_count: number;
  task_resource_count: number;
  service_integration_count: number;
  log_group_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  records: AWSStepFunctionsStateMachineRoleRecord[];
  relationships: AWSStepFunctionsStateMachineRoleRelationship[];
  diagnostics: AWSStepFunctionsStateMachineRoleDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSEventDrivenRoleInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSEventDrivenRoleFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSEventDrivenRoleRecord = {
  account_id: string;
  region: string;
  service: 'eventbridge' | 'scheduler' | 'pipes' | string;
  workload_id: string;
  workload_type: 'eventbridge_rule' | 'scheduler_schedule' | 'eventbridge_pipe' | string;
  workload_name: string;
  role_arn?: string;
  role_name?: string;
  role_kind?: string;
  role_account_id?: string;
  workload_arn?: string;
  event_bus_name?: string;
  event_bus_arn?: string;
  schedule_group_name?: string;
  schedule_expression?: string;
  schedule_timezone?: string;
  pipe_source_arn?: string;
  pipe_target_arn?: string;
  pipe_enrichment_arn?: string;
  target_arn?: string;
  target_id?: string;
  target_service?: string;
  dead_letter_arns?: string[];
  retry_maximum_age_seconds?: number;
  retry_maximum_attempts?: number;
  event_pattern_sha256?: string;
  input_transformer_sha256?: string;
  input_path_configured?: boolean;
  target_input_configured?: boolean;
  execution_data_logging?: boolean;
  log_destination_arns?: string[];
  kms_key_arn?: string;
  active: boolean;
  disabled: boolean;
  state_reason?: string;
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSEventDrivenRoleRelationship = {
  type: 'runs_as' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSEventDrivenRoleDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSEventDrivenRoleInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSEventDrivenRoleInventoryStatus;
  fixture_state: AWSEventDrivenRoleFixtureState;
  confidence: number;
  record_count: number;
  rule_count: number;
  schedule_count: number;
  pipe_count: number;
  target_count: number;
  dead_letter_count: number;
  disabled_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  records: AWSEventDrivenRoleRecord[];
  relationships: AWSEventDrivenRoleRelationship[];
  diagnostics: AWSEventDrivenRoleDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSManagedComputeRoleInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSManagedComputeRoleFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSManagedComputeCoverageGap = {
  service: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSManagedComputeRoleRecord = {
  account_id: string;
  region: string;
  service: 'apprunner' | 'batch' | 'glue' | 'emr' | string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_arn?: string;
  role_name?: string;
  role_kind?: string;
  role_account_id?: string;
  workload_arn?: string;
  resource_arn?: string;
  resource_type?: string;
  resource_status?: string;
  compute_engine?: string;
  queue_arn?: string;
  cluster_arn?: string;
  job_definition_arn?: string;
  revision?: number;
  unsupported_service?: string;
  coverage_status: string;
  coverage_reason?: string;
  active: boolean;
  disabled: boolean;
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSManagedComputeRoleRelationship = {
  type: 'runs_as' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSManagedComputeRoleDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSManagedComputeRoleInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSManagedComputeRoleInventoryStatus;
  fixture_state: AWSManagedComputeRoleFixtureState;
  confidence: number;
  record_count: number;
  service_count: number;
  app_runner_count: number;
  batch_count: number;
  glue_count: number;
  emr_count: number;
  unsupported_service_count: number;
  disabled_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSManagedComputeCoverageGap[];
  records: AWSManagedComputeRoleRecord[];
  relationships: AWSManagedComputeRoleRelationship[];
  diagnostics: AWSManagedComputeRoleDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSSageMakerWorkloadRoleInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSSageMakerWorkloadRoleFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSSageMakerCoverageGap = {
  workload_type: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSSageMakerWorkloadRoleRecord = {
  account_id: string;
  region: string;
  service: 'sagemaker' | string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_arn?: string;
  role_name?: string;
  role_kind?: string;
  role_account_id?: string;
  workload_arn?: string;
  resource_arn?: string;
  resource_type?: string;
  resource_status?: string;
  domain_id?: string;
  domain_arn?: string;
  user_profile?: string;
  space_name?: string;
  pipeline_arn?: string;
  model_arn?: string;
  endpoint_config?: string;
  network_mode?: string;
  image_uris?: string[];
  s3_references?: string[];
  kms_key_arns?: string[];
  coverage_status: string;
  coverage_reason?: string;
  active: boolean;
  disabled: boolean;
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | 'attached_to' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSSageMakerWorkloadRoleRelationship = {
  type: 'runs_as' | 'attached_to' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSSageMakerWorkloadRoleDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSSageMakerWorkloadRoleInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSSageMakerWorkloadRoleInventoryStatus;
  fixture_state: AWSSageMakerWorkloadRoleFixtureState;
  confidence: number;
  record_count: number;
  workload_type_count: number;
  notebook_count: number;
  training_job_count: number;
  processing_job_count: number;
  transform_job_count: number;
  model_count: number;
  endpoint_count: number;
  pipeline_count: number;
  domain_count: number;
  s3_reference_count: number;
  ecr_image_count: number;
  kms_key_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSSageMakerCoverageGap[];
  records: AWSSageMakerWorkloadRoleRecord[];
  relationships: AWSSageMakerWorkloadRoleRelationship[];
  diagnostics: AWSSageMakerWorkloadRoleDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSAIAgentIdentityInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSAIAgentIdentityFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSAIAgentCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSAIAgentIdentityRecord = {
  account_id: string;
  region: string;
  service: string;
  agent_id: string;
  agent_arn?: string;
  agent_name: string;
  agent_type: 'bedrock_agent' | 'agentcore_runtime' | 'custom_agent' | 'external_provider_agent' | 'agent_gateway' | string;
  runtime_version?: string;
  provider?: string;
  model_id?: string;
  runtime_role_arn?: string;
  runtime_role_name?: string;
  runtime_role_account_id?: string;
  workload_identity_arn?: string;
  gateway_id?: string;
  gateway_arn?: string;
  external_provider?: string;
  tool_names?: string[];
  tool_target_refs?: string[];
  allowed_actions?: string[];
  auth_mode?: string;
  memory_enabled: boolean;
  memory_store_refs?: string[];
  browser_enabled: boolean;
  code_interpreter_enabled: boolean;
  capability_kind?: 'memory' | 'browser' | 'code_interpreter';
  storage_reference_refs?: string[];
  encryption_key_arn?: string;
  capability_names?: string[];
  credential_reference_refs?: string[];
  resource_reference_refs?: string[];
  execution_endpoint_arns?: string[];
  execution_endpoint_names?: string[];
  execution_endpoint_statuses?: string[];
  observability_links?: string[];
  network_mode?: string;
  server_protocol?: string;
  sensitive_boundary: string;
  coverage_status: string;
  coverage_reason?: string;
  source: string;
  evidence_ref: string;
  agent_node_id: string;
  runtime_role_node_id?: string;
  gateway_node_id?: string;
  relationship_types: string[];
  provider_key_references?: AWSAIAgentProviderKeyReference[];
  confidence: number;
  collected_at: string;
  status: string;
  tags?: Record<string, string>;
};

export type AWSAIAgentProviderKeyReference = {
  reference: string;
  reference_name?: string;
  reference_kind: string;
  provider: string;
  sensitivity: string;
  resolved: boolean;
  target_node_id?: string;
  evidence_ref: string;
  confidence: number;
};

export type AWSAIAgentIdentityRelationship = {
  type: 'runs_as' | 'calls_tool' | 'uses_secret' | 'invokes' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSAIAgentIdentityDiagnostic = {
  collector: string;
  source_id?: string;
  code: 'ai_agent_credential_reference_unresolved' | 'ai_agent_gateway_list_failed' | 'ai_agent_gateway_describe_failed' | 'ai_agent_gateway_malformed' | 'ai_agent_gateway_target_describe_failed' | 'ai_agent_gateway_target_list_failed' | 'ai_agent_identity_page_failed' | 'agentcore_runtime_describe_failed' | 'agentcore_runtime_endpoint_list_failed' | 'agentcore_runtime_malformed' | 'permission_denied' | string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSAIAgentIdentityInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSAIAgentIdentityInventoryStatus;
  fixture_state: AWSAIAgentIdentityFixtureState;
  confidence: number;
  applied_filters: Record<string, string>;
  record_count: number;
  total_record_count: number;
  filtered_record_count: number;
  bedrock_agent_count: number;
  agentcore_runtime_count: number;
  custom_agent_count: number;
  external_agent_count: number;
  gateway_count: number;
  capability_agent_count: number;
  memory_store_count: number;
  browser_count: number;
  code_interpreter_count: number;
  runtime_role_count: number;
  provider_count: number;
  model_count: number;
  tool_count: number;
  capability_count: number;
  credential_reference_count: number;
  external_provider_key_count: number;
  ai_provider_key_count: number;
  provider_key_breakdown: Record<string, number>;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSAIAgentCoverageGap[];
  records: AWSAIAgentIdentityRecord[];
  relationships: AWSAIAgentIdentityRelationship[];
  diagnostics: AWSAIAgentIdentityDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSAIAgentIdentityQuery = {
  connectorID?: string;
  fixtureState?: AWSAIAgentIdentityFixtureState;
  accountID?: string;
  region?: string;
  agentID?: string;
  provider?: string;
  runtime?: string;
  tool?: string;
  status?: string;
  risk?: string;
  minConfidence?: string;
};

export type AWSRuntimeEventStatus = 'ready' | 'degraded' | 'blocked';
// AWSRuntimeEventFixtureStateRequest is the query-side enum: every
// value here is one the backend accepts as `?fixture_state=...`. It
// intentionally excludes `capability_unavailable` because that state
// is only produced by the API when a healthy connector lacks the
// `runtime_evidence` capability; sending it as a request would be
// rejected with HTTP 400.
export type AWSRuntimeEventFixtureStateRequest =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

// AWSRuntimeEventFixtureState is the response-side enum and is a
// superset of the request enum. `capability_unavailable` is returned
// when the connector is otherwise healthy but its effective
// capability set does not include `runtime_evidence`, so live
// CloudTrail LookupEvents ingestion was intentionally not attempted;
// the response carries fixture-shaped records with a degraded status
// so the UI surfaces the boundary.
export type AWSRuntimeEventFixtureState =
  | AWSRuntimeEventFixtureStateRequest
  | 'capability_unavailable';

export type AWSRuntimeEventSession = {
  session_id: string;
  session_node_id?: string;
  principal_arn: string;
  principal_type: string;
  assumed_role_arn?: string;
  session_issuer_arn?: string;
  source_identity?: string;
  role_session_name?: string;
  session_tag_keys?: string[];
  transitive_tag_keys?: string[];
  original_actor_arn?: string;
  original_actor_node_id?: string;
  chained_from_principal_arn?: string;
  chained_from_node_id?: string;
  lineage_status?: 'resolved' | 'source_identity_missing' | 'ambiguous' | string;
  lineage_reason?: string;
  source_ip_address?: string;
  user_agent?: string;
  // started_at / expires_at are omitted from the JSON response when
  // CloudTrail did not supply a real value (e.g. IAM/root/service
  // events that carry no session, or assumed-role events where STS
  // rotated the credential and did not expose an expiration). The API
  // never emits the bogus year-0001 literal.
  started_at?: string;
  expires_at?: string;
};

export type AWSRuntimeEventRecord = {
  event_id: string;
  account_id: string;
  region: string;
  event_type: 'sts-session' | 'api-call' | 'secret-read' | 'kms-decrypt' | 'agent-tool' | string;
  event_source: string;
  event_name: string;
  action: string;
  actor_principal_arn: string;
  actor_principal_type: string;
  actor_identity_node_id: string;
  session: AWSRuntimeEventSession;
  target_resource_arn?: string;
  target_resource_type?: string;
  target_resource_name?: string;
  resource_node_id?: string;
  agent_id?: string;
  agent_node_id?: string;
  tool_name?: string;
  tool_target_ref?: string;
  signal_category?: string;
  signal_scope?: string;
  analyzer_arn?: string;
  signal_stale_at?: string;
  owner: string;
  evidence_category: string;
  evidence_ref: string;
  confidence: number;
  observed_at: string;
  collected_at: string;
  status: string;
  next_action: string;
  redaction_boundary: string;
};

export type AWSRuntimeEventRelationship = {
  type: 'observed_runtime_action' | 'agent_invoked_runtime_action' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSRuntimeEventDiagnostic = {
  collector: string;
  source_id?: string;
  code: 'runtime_event_delivery_delayed' | 'agent_runtime_event_source_failed' | 'permission_denied' | string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSRuntimeEventCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSRuntimeEventSummary = {
  total_events: number;
  filtered_events: number;
  event_type_counts: Record<string, number>;
  status_counts: Record<string, number>;
  owner_counts: Record<string, number>;
  account_count: number;
  region_count: number;
  identity_count: number;
  resource_count: number;
  agent_event_count: number;
  secret_read_count: number;
  kms_decrypt_count: number;
  api_call_count: number;
  sts_session_count: number;
  iam_last_used_signal_count?: number;
  access_analyzer_finding_count?: number;
  dormant_access_count?: number;
  lineage_resolved_count?: number;
  missing_source_identity_count?: number;
  ambiguous_lineage_count?: number;
  relationship_count: number;
  permission_denied_events: number;
};

export type AWSRuntimeEventResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSRuntimeEventStatus;
  fixture_state: AWSRuntimeEventFixtureState;
  confidence: number;
  applied_filters: Record<string, string>;
  summary: AWSRuntimeEventSummary;
  records: AWSRuntimeEventRecord[];
  relationships: AWSRuntimeEventRelationship[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSRuntimeEventCoverageGap[];
  diagnostics: AWSRuntimeEventDiagnostic[];
  generated_at: string;
  updated_at: string;
};

// AWSRuntimeEventDeliverySource selects which CloudTrail delivery
// channel the API drives for a request. `lookup_events` (the default)
// keeps the existing LookupEvents-API path; `s3` reads from the
// trail's S3 log destination; `eventbridge` consumes the EventBridge
// target SQS queue; `all` fans out across every wired channel and
// dedupes by EventID.
export type AWSRuntimeEventDeliverySource =
  | 'lookup_events'
  | 's3'
  | 'eventbridge'
  | 'all';

export type AWSRuntimeEventQuery = {
  connectorID?: string;
  deliverySource?: AWSRuntimeEventDeliverySource;
  fixtureState?: AWSRuntimeEventFixtureStateRequest;
  accountID?: string;
  region?: string;
  eventType?: string;
  identity?: string;
  agentID?: string;
  resource?: string;
  evidence?: string;
  owner?: string;
  status?: string;
};

// AWSSecretsKMSRuntimeAccess* types describe the Secrets Manager read /
// KMS decrypt runtime access correlation: observed runtime events joined
// with the static reachability edges Identrail discovered, classified per
// (identity, resource) pair with a correlation confidence and explicit
// missing-event caveats.
export type AWSSecretsKMSRuntimeAccessStatus = 'ready' | 'degraded' | 'blocked';
export type AWSSecretsKMSRuntimeAccessFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSSecretsKMSRuntimeAccessCorrelationStatus =
  | 'confirmed'
  | 'observed_without_grant'
  | 'granted_unused';
export type AWSSecretsKMSRuntimeAccessResourceKind = 'secret' | 'kms_key';

export type AWSSecretsKMSRuntimeAccessRecord = {
  correlation_id: string;
  account_id: string;
  region: string;
  identity_node_id: string;
  principal_arn?: string;
  resource_kind: AWSSecretsKMSRuntimeAccessResourceKind | string;
  resource_arn: string;
  resource_name?: string;
  resource_node_id: string;
  status: AWSSecretsKMSRuntimeAccessCorrelationStatus | string;
  confidence: number;
  observed_count: number;
  observed_event_ids?: string[];
  actions?: string[];
  session_ids?: string[];
  agent_id?: string;
  agent_node_id?: string;
  first_observed_at?: string;
  last_observed_at?: string;
  static_sources?: string[];
  static_effect?: string;
  conditional?: boolean;
  cross_account?: boolean;
  caveats?: string[];
  evidence_ref: string;
  evidence_refs?: string[];
  next_action: string;
  redaction_boundary: string;
};

export type AWSSecretsKMSRuntimeAccessRelationship = {
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSSecretsKMSRuntimeAccessDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSSecretsKMSRuntimeAccessCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSSecretsKMSRuntimeAccessSummary = {
  total_correlations: number;
  filtered_correlations: number;
  status_counts: Record<string, number>;
  confirmed_count: number;
  observed_without_grant_count: number;
  granted_unused_count: number;
  secret_correlation_count: number;
  kms_key_correlation_count: number;
  identity_count: number;
  resource_count: number;
  observed_access_count: number;
  static_grant_count: number;
  relationship_count: number;
};

export type AWSSecretsKMSRuntimeAccessResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSSecretsKMSRuntimeAccessStatus;
  fixture_state: AWSSecretsKMSRuntimeAccessFixtureState;
  confidence: number;
  applied_filters: Record<string, string>;
  summary: AWSSecretsKMSRuntimeAccessSummary;
  records: AWSSecretsKMSRuntimeAccessRecord[];
  relationships: AWSSecretsKMSRuntimeAccessRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSSecretsKMSRuntimeAccessCoverageGap[];
  diagnostics: AWSSecretsKMSRuntimeAccessDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSSecretsKMSRuntimeAccessQuery = {
  connectorID?: string;
  fixtureState?: AWSSecretsKMSRuntimeAccessFixtureState;
  deliverySource?: AWSRuntimeEventDeliverySource;
  accountID?: string;
  region?: string;
  identity?: string;
  agentID?: string;
  resource?: string;
  resourceKind?: string;
  status?: string;
};

// AWSS3RuntimeAccess* types describe the S3 read/write/list runtime data
// access correlation: observed S3 runtime events joined with the static
// reachability edges Identrail discovered and the bucket's exposure /
// sensitivity classification, classified per (identity, bucket) pair.
// Object keys and contents are never present — only bucket ARNs and
// bounded, sanitized safe prefixes.
export type AWSS3RuntimeAccessStatus = 'ready' | 'degraded' | 'blocked';
export type AWSS3RuntimeAccessFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSS3RuntimeAccessCorrelationStatus =
  | 'confirmed'
  | 'observed_without_grant'
  | 'granted_unused';
export type AWSS3RuntimeAccessMode = 'read' | 'write' | 'list';

export type AWSS3RuntimeAccessRecord = {
  correlation_id: string;
  account_id: string;
  region: string;
  identity_node_id: string;
  principal_arn?: string;
  bucket_arn: string;
  bucket_name?: string;
  resource_node_id: string;
  status: AWSS3RuntimeAccessCorrelationStatus | string;
  confidence: number;
  observed_count: number;
  observed_event_ids?: string[];
  observed_modes?: string[];
  granted_modes?: string[];
  safe_prefixes?: string[];
  actions?: string[];
  session_ids?: string[];
  agent_id?: string;
  agent_node_id?: string;
  first_observed_at?: string;
  last_observed_at?: string;
  static_sources?: string[];
  static_effect?: string;
  exposure?: string;
  sensitivity?: string;
  conditional?: boolean;
  cross_account?: boolean;
  caveats?: string[];
  evidence_ref: string;
  evidence_refs?: string[];
  next_action: string;
  redaction_boundary: string;
};

export type AWSS3RuntimeAccessRelationship = {
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSS3RuntimeAccessDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSS3RuntimeAccessCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSS3RuntimeAccessSummary = {
  total_correlations: number;
  filtered_correlations: number;
  status_counts: Record<string, number>;
  confirmed_count: number;
  observed_without_grant_count: number;
  granted_unused_count: number;
  read_count: number;
  write_count: number;
  list_count: number;
  sensitive_exposed_count: number;
  mode_exceeds_grant_count: number;
  identity_count: number;
  bucket_count: number;
  observed_access_count: number;
  static_grant_count: number;
  relationship_count: number;
};

export type AWSS3RuntimeAccessResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSS3RuntimeAccessStatus;
  fixture_state?: AWSS3RuntimeAccessFixtureState;
  confidence: number;
  applied_filters: Record<string, string>;
  summary: AWSS3RuntimeAccessSummary;
  records: AWSS3RuntimeAccessRecord[];
  relationships: AWSS3RuntimeAccessRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSS3RuntimeAccessCoverageGap[];
  diagnostics: AWSS3RuntimeAccessDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSS3RuntimeAccessQuery = {
  connectorID?: string;
  fixtureState?: AWSS3RuntimeAccessFixtureState;
  deliverySource?: AWSRuntimeEventDeliverySource;
  accountID?: string;
  region?: string;
  identity?: string;
  agentID?: string;
  resource?: string;
  accessMode?: string;
  sensitivity?: string;
  exposure?: string;
  status?: string;
};

// AWSAgentRuntimeAccess* types describe the agent runtime / tool-call
// correlation: observed agent tool-call events joined with the static
// AI-agent inventory (declared agents, backing roles, declared tools),
// classified per (agent, tool) pair. Prompts, completions, and tool
// payloads are never present.
export type AWSAgentRuntimeAccessStatus = 'ready' | 'degraded' | 'blocked';
export type AWSAgentRuntimeAccessFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSAgentRuntimeAccessCorrelationStatus =
  | 'confirmed'
  | 'observed_without_declaration'
  | 'declared_unused';

export type AWSAgentRuntimeAccessRecord = {
  correlation_id: string;
  account_id: string;
  region: string;
  agent_node_id: string;
  agent_id?: string;
  agent_name?: string;
  agent_type?: string;
  runtime_version?: string;
  tool_name?: string;
  tool_target_ref?: string;
  status: AWSAgentRuntimeAccessCorrelationStatus | string;
  confidence: number;
  observed_count: number;
  observed_event_ids?: string[];
  backing_role_arns?: string[];
  backing_role_node_ids?: string[];
  declared_backing_role?: string;
  declared_backing_role_node_id?: string;
  target_resource_arns?: string[];
  target_resource_node_ids?: string[];
  outcomes?: string[];
  session_ids?: string[];
  first_observed_at?: string;
  last_observed_at?: string;
  declared_in_inventory: boolean;
  caveats?: string[];
  evidence_ref: string;
  evidence_refs?: string[];
  next_action: string;
  redaction_boundary: string;
};

export type AWSAgentRuntimeAccessRelationship = {
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSAgentRuntimeAccessDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSAgentRuntimeAccessCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSAgentRuntimeAccessSummary = {
  total_correlations: number;
  filtered_correlations: number;
  status_counts: Record<string, number>;
  confirmed_count: number;
  observed_without_declaration_count: number;
  declared_unused_count: number;
  shadow_agent_count: number;
  undeclared_tool_count: number;
  backing_role_mismatch_count: number;
  failed_tool_call_count: number;
  agent_count: number;
  tool_count: number;
  observed_tool_call_count: number;
  declared_tool_count: number;
  relationship_count: number;
};

export type AWSAgentRuntimeAccessResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSAgentRuntimeAccessStatus;
  fixture_state?: AWSAgentRuntimeAccessFixtureState;
  confidence: number;
  applied_filters: Record<string, string>;
  summary: AWSAgentRuntimeAccessSummary;
  records: AWSAgentRuntimeAccessRecord[];
  relationships: AWSAgentRuntimeAccessRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSAgentRuntimeAccessCoverageGap[];
  diagnostics: AWSAgentRuntimeAccessDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSAgentRuntimeAccessQuery = {
  connectorID?: string;
  fixtureState?: AWSAgentRuntimeAccessFixtureState;
  deliverySource?: AWSRuntimeEventDeliverySource;
  accountID?: string;
  region?: string;
  identity?: string;
  agentID?: string;
  tool?: string;
  resource?: string;
  outcome?: string;
  status?: string;
};

export type AWSAIAgentRiskStatus = 'ready' | 'degraded' | 'blocked';
export type AWSAIAgentRiskFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSAIAgentRiskSeverity = 'critical' | 'high' | 'medium' | 'low' | string;
export type AWSAIAgentRiskFindingStatus = 'action_required' | 'review' | 'monitor' | string;

export type AWSAIAgentRiskRelationship = {
  finding_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSAIAgentRiskFinding = {
  finding_id: string;
  calculation_version: string;
  risk_type: string;
  severity: AWSAIAgentRiskSeverity;
  status: AWSAIAgentRiskFindingStatus;
  score: number;
  confidence: number;
  account_id: string;
  region: string;
  agent_node_id: string;
  agent_id?: string;
  agent_name?: string;
  agent_type?: string;
  runtime_role_arn?: string;
  runtime_role_node_id?: string;
  provider?: string;
  tool_names?: string[];
  capability_names?: string[];
  sensitive_resources?: string[];
  source_signals: string[];
  rationale: string;
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  evidence: AWSLeastPrivilegeEvidence[];
  next_action: string;
  remediation_case: AWSLeastPrivilegeRemediationCasePreview;
  created_at: string;
  updated_at: string;
};

export type AWSAIAgentRiskSummary = {
  total_findings: number;
  filtered_findings: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  risk_type_counts: Record<string, number>;
  external_credential_count: number;
  broad_tool_access_count: number;
  sensitive_reachability_count: number;
  ownerless_agent_count: number;
  runtime_observed_count: number;
  backing_role_scope_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
  remediation_preview_count: number;
};

export type AWSAIAgentRiskResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSAIAgentRiskStatus;
  fixture_state?: AWSAIAgentRiskFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSAIAgentRiskSummary;
  findings: AWSAIAgentRiskFinding[];
  relationships: AWSAIAgentRiskRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSAIAgentRiskQuery = {
  connectorID?: string;
  fixtureState?: AWSAIAgentRiskFixtureState;
  accountID?: string;
  region?: string;
  agentID?: string;
  riskType?: string;
  severity?: string;
  status?: string;
  evidence?: string;
  search?: string;
};

export type AWSRemediationCaseStatus = 'ready' | 'degraded' | 'blocked';
export type AWSRemediationCaseFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSRemediationCaseSeverity = 'critical' | 'high' | 'medium' | 'low' | string;
export type AWSRemediationCaseLifecycle =
  | 'proposed'
  | 'in_review'
  | 'approved'
  | 'executed'
  | 'verified'
  | 'closed'
  | 'rolled_back'
  | string;
export type AWSRemediationCaseSourceType =
  | 'ai_agent_risk'
  | 'least_privilege'
  | 'secret_permission_equivalence'
  | 'blast_radius'
  | string;
export type AWSRemediationCaseApprovalState =
  | 'not_required'
  | 'pending_owner'
  | 'pending_owner_review'
  | 'pending_approver'
  | 'approved'
  | 'rejected'
  | string;

export type AWSRemediationDiffIntent = {
  kind: string;
  before_ref?: string;
  after_ref?: string;
  diff_summary: string;
  no_op: boolean;
  read_only_projection: boolean;
};

export type AWSRemediationTradeoff = {
  dimension: string;
  direction: 'improves' | 'worsens' | 'neutral' | string;
  description: string;
  severity: string;
};

export type AWSRemediationRollbackPlan = {
  strategy: string;
  steps: string[];
  evidence_ref?: string;
};

export type AWSRemediationVerificationPlan = {
  strategy: string;
  steps: string[];
  success_signals?: string[];
  failure_signals?: string[];
  evidence_ref?: string;
};

export type AWSRemediationAuditEntry = {
  event_id: string;
  actor: string;
  event_type: string;
  occurred_at: string;
  evidence_ref?: string;
  notes?: string;
};

export type AWSRemediationRelationship = {
  case_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSRemediationCase = {
  case_id: string;
  calculation_version: string;
  source_type: AWSRemediationCaseSourceType;
  source_finding_id: string;
  lifecycle: AWSRemediationCaseLifecycle;
  severity: AWSRemediationCaseSeverity;
  status: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  target_account_ids?: string[];
  region: string;
  identity_node_id?: string;
  identity_arn?: string;
  identity_name?: string;
  identity_type?: string;
  provider?: string;
  resource_node_ids?: string[];
  owner?: string;
  owner_assigned: boolean;
  approval_required: boolean;
  approval_state: AWSRemediationCaseApprovalState;
  diff_intent: AWSRemediationDiffIntent;
  tradeoffs: AWSRemediationTradeoff[];
  rollback_plan: AWSRemediationRollbackPlan;
  verification_plan: AWSRemediationVerificationPlan;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_actions: string[];
  audit_trail: AWSRemediationAuditEntry[];
  created_at: string;
  updated_at: string;
};

export type AWSRemediationCaseSummary = {
  total_cases: number;
  filtered_cases: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  lifecycle_counts: Record<string, number>;
  source_type_counts: Record<string, number>;
  approval_state_counts: Record<string, number>;
  owner_assigned_count: number;
  ownerless_count: number;
  approval_required_count: number;
  read_only_projection_count: number;
  rollback_plan_count: number;
  verification_plan_count: number;
  relationship_count: number;
  audit_entry_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSRemediationCaseResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSRemediationCaseStatus;
  fixture_state?: AWSRemediationCaseFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSRemediationCaseSummary;
  cases: AWSRemediationCase[];
  relationships: AWSRemediationRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSRemediationCaseQuery = {
  connectorID?: string;
  fixtureState?: AWSRemediationCaseFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  sourceType?: string;
  lifecycle?: string;
  severity?: string;
  status?: string;
  approvalState?: string;
  ownerAssigned?: string;
  search?: string;
};

export type AWSIAMPolicyDiffStatus = 'ready' | 'degraded' | 'blocked';
export type AWSIAMPolicyDiffFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSIAMPolicyDiffSeverity = 'critical' | 'high' | 'medium' | 'low' | string;
export type AWSIAMPolicyDiffDecision = 'keep' | 'remove' | 'review' | string;
export type AWSIAMPolicyDiffBreakageLevel = 'low' | 'medium' | 'high' | 'unknown' | string;

export type AWSIAMPolicyStatementDiff = {
  statement_sid: string;
  effect: string;
  change_kind: 'scope_removed' | 'statement_removed' | 'manual_review' | string;
  removed_actions?: string[];
  kept_actions?: string[];
  resource_before?: string[];
  resource_after?: string[];
  condition_before?: string[];
  condition_after?: string[];
  rationale: string;
};

export type AWSIAMPolicyDiffBreakageProjection = {
  level: AWSIAMPolicyDiffBreakageLevel;
  rationale: string;
  signals?: string[];
};

export type AWSIAMPolicyDiffRollbackPlan = {
  strategy: string;
  steps: string[];
  evidence_ref?: string;
};

export type AWSIAMPolicyDiffVerificationPlan = {
  strategy: string;
  steps: string[];
  success_signals?: string[];
  failure_signals?: string[];
  evidence_ref?: string;
};

export type AWSIAMPolicyDiffRelationship = {
  diff_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSIAMPolicyDiff = {
  diff_id: string;
  calculation_version: string;
  source_recommendation_id: string;
  decision: AWSIAMPolicyDiffDecision;
  severity: AWSIAMPolicyDiffSeverity;
  status: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  service?: string;
  identity_node_id: string;
  identity_arn?: string;
  identity_name?: string;
  resource_node_id?: string;
  resource_arn?: string;
  statement_changes: AWSIAMPolicyStatementDiff[];
  removed_actions?: string[];
  kept_actions?: string[];
  observed_actions?: string[];
  granted_actions?: string[];
  resource_scope_before?: string[];
  resource_scope_after?: string[];
  breakage_projection: AWSIAMPolicyDiffBreakageProjection;
  rollback_plan: AWSIAMPolicyDiffRollbackPlan;
  verification_plan: AWSIAMPolicyDiffVerificationPlan;
  ready_for_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  created_at: string;
  updated_at: string;
};

export type AWSIAMPolicyDiffSummary = {
  total_diffs: number;
  filtered_diffs: number;
  decision_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  breakage_level_counts: Record<string, number>;
  service_counts: Record<string, number>;
  removed_action_count: number;
  kept_action_count: number;
  statement_change_count: number;
  ready_for_apply_count: number;
  manual_review_count: number;
  no_op_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSIAMPolicyDiffResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSIAMPolicyDiffStatus;
  fixture_state?: AWSIAMPolicyDiffFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSIAMPolicyDiffSummary;
  diffs: AWSIAMPolicyDiff[];
  relationships: AWSIAMPolicyDiffRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSIAMPolicyDiffQuery = {
  connectorID?: string;
  fixtureState?: AWSIAMPolicyDiffFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  service?: string;
  decision?: string;
  severity?: string;
  status?: string;
  breakageLevel?: string;
  readyForApply?: string;
  search?: string;
};

export type AWSTrustPolicyHardeningStatus = 'ready' | 'degraded' | 'blocked';
export type AWSTrustPolicyHardeningFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSTrustPolicyHardeningSeverity = 'critical' | 'high' | 'medium' | 'low' | string;
export type AWSTrustPolicyHardeningDirection =
  | 'remove_public_principal'
  | 'add_org_or_source_condition'
  | 'scope_to_known_external_principal'
  | 'tighten_existing_condition'
  | string;
export type AWSTrustPolicyHardeningBreakageLevel = 'low' | 'medium' | 'high' | 'unknown' | string;

export type AWSTrustPolicyPrincipalChange = {
  before_principals?: string[];
  after_principals?: string[];
  public_principal_removed: boolean;
  rationale: string;
};

export type AWSTrustPolicyConditionRecommendation = {
  operator: string;
  key: string;
  value: string;
  rationale: string;
  evidence_ref?: string;
};

export type AWSTrustPolicyStatementSnippet = {
  statement_sid: string;
  effect: string;
  change_kind: string;
  before_ref?: string;
  after_ref?: string;
  condition_before?: string[];
  condition_after?: string[];
  rationale: string;
};

export type AWSTrustPolicyAffectedCaller = {
  principal_arn: string;
  principal_account_id?: string;
  ou_path?: string;
  trusted_within_organization: boolean;
  runtime_observed: boolean;
  analyzer_backed: boolean;
  evidence_ref?: string;
};

export type AWSTrustPolicyHardeningBreakageProjection = {
  level: AWSTrustPolicyHardeningBreakageLevel;
  rationale: string;
  signals?: string[];
};

export type AWSTrustPolicyHardeningRollbackPlan = {
  strategy: string;
  steps: string[];
  evidence_ref?: string;
};

export type AWSTrustPolicyHardeningVerificationPlan = {
  strategy: string;
  steps: string[];
  success_signals?: string[];
  failure_signals?: string[];
  evidence_ref?: string;
};

export type AWSTrustPolicyHardeningRelationship = {
  plan_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSTrustPolicyHardeningPlan = {
  plan_id: string;
  calculation_version: string;
  source_finding_id: string;
  finding_type: string;
  hardening_direction: AWSTrustPolicyHardeningDirection;
  severity: AWSTrustPolicyHardeningSeverity;
  status: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  service?: string;
  resource_type?: string;
  resource_node_id?: string;
  resource_arn?: string;
  resource_label?: string;
  public_principal: boolean;
  trusted_within_organization: boolean;
  runtime_observed: boolean;
  analyzer_backed: boolean;
  principal_change: AWSTrustPolicyPrincipalChange;
  condition_recommendations: AWSTrustPolicyConditionRecommendation[];
  statement_snippets: AWSTrustPolicyStatementSnippet[];
  affected_callers: AWSTrustPolicyAffectedCaller[];
  breakage_projection: AWSTrustPolicyHardeningBreakageProjection;
  rollback_plan: AWSTrustPolicyHardeningRollbackPlan;
  verification_plan: AWSTrustPolicyHardeningVerificationPlan;
  ready_for_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  created_at: string;
  updated_at: string;
};

export type AWSTrustPolicyHardeningSummary = {
  total_plans: number;
  filtered_plans: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  finding_type_counts: Record<string, number>;
  hardening_direction_counts: Record<string, number>;
  breakage_level_counts: Record<string, number>;
  public_principal_count: number;
  cross_account_count: number;
  conditioned_count: number;
  runtime_observed_count: number;
  analyzer_backed_count: number;
  ready_for_apply_count: number;
  manual_review_count: number;
  affected_caller_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSTrustPolicyHardeningResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSTrustPolicyHardeningStatus;
  fixture_state?: AWSTrustPolicyHardeningFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSTrustPolicyHardeningSummary;
  plans: AWSTrustPolicyHardeningPlan[];
  relationships: AWSTrustPolicyHardeningRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSTrustPolicyHardeningQuery = {
  connectorID?: string;
  fixtureState?: AWSTrustPolicyHardeningFixtureState;
  accountID?: string;
  region?: string;
  service?: string;
  resource?: string;
  principal?: string;
  hardeningDirection?: string;
  breakageLevel?: string;
  severity?: string;
  status?: string;
  readyForApply?: string;
  search?: string;
};

export type AWSPermissionBoundarySCPStatus = 'ready' | 'degraded' | 'blocked';
export type AWSPermissionBoundarySCPFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSPermissionBoundarySCPSeverity = 'critical' | 'high' | 'medium' | 'low' | string;
export type AWSPermissionBoundarySCPKind = 'permission_boundary' | 'scp' | string;
export type AWSPermissionBoundarySCPTargetScope = 'identity' | 'account' | 'ou' | 'org_root' | string;
export type AWSPermissionBoundarySCPBreakageLevel = 'low' | 'medium' | 'high' | 'unknown' | string;

export type AWSPermissionBoundarySCPStatementSnippet = {
  statement_sid: string;
  effect: string;
  change_kind: string;
  before_ref?: string;
  after_ref?: string;
  denied_actions?: string[];
  allowed_actions?: string[];
  resource_scope?: string[];
  condition_keys?: string[];
  rationale: string;
};

export type AWSPermissionBoundarySCPBreakageProjection = {
  level: AWSPermissionBoundarySCPBreakageLevel;
  rationale: string;
  affected_identities: number;
  affected_accounts: number;
  affected_ous: number;
  signals?: string[];
};

export type AWSPermissionBoundarySCPRollbackPlan = {
  strategy: string;
  steps: string[];
  evidence_ref?: string;
};

export type AWSPermissionBoundarySCPVerificationPlan = {
  strategy: string;
  steps: string[];
  success_signals?: string[];
  failure_signals?: string[];
  evidence_ref?: string;
};

export type AWSPermissionBoundarySCPRelationship = {
  plan_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSPermissionBoundarySCPPlan = {
  plan_id: string;
  calculation_version: string;
  kind: AWSPermissionBoundarySCPKind;
  target_scope: AWSPermissionBoundarySCPTargetScope;
  severity: AWSPermissionBoundarySCPSeverity;
  status: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id?: string;
  region?: string;
  service?: string;
  target_account_ids?: string[];
  target_ou_paths?: string[];
  target_identity_node_ids?: string[];
  prevented_behavior: string;
  source_finding_ids: string[];
  statement_snippets: AWSPermissionBoundarySCPStatementSnippet[];
  breakage_projection: AWSPermissionBoundarySCPBreakageProjection;
  rollback_plan: AWSPermissionBoundarySCPRollbackPlan;
  verification_plan: AWSPermissionBoundarySCPVerificationPlan;
  ready_for_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  created_at: string;
  updated_at: string;
};

export type AWSPermissionBoundarySCPSummary = {
  total_plans: number;
  filtered_plans: number;
  kind_counts: Record<string, number>;
  target_scope_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  breakage_level_counts: Record<string, number>;
  boundary_plan_count: number;
  scp_plan_count: number;
  ready_for_apply_count: number;
  affected_identity_count: number;
  affected_account_count: number;
  affected_ou_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSPermissionBoundarySCPResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSPermissionBoundarySCPStatus;
  fixture_state?: AWSPermissionBoundarySCPFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSPermissionBoundarySCPSummary;
  plans: AWSPermissionBoundarySCPPlan[];
  relationships: AWSPermissionBoundarySCPRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSPermissionBoundarySCPQuery = {
  connectorID?: string;
  fixtureState?: AWSPermissionBoundarySCPFixtureState;
  accountID?: string;
  region?: string;
  service?: string;
  kind?: string;
  targetScope?: string;
  severity?: string;
  status?: string;
  breakageLevel?: string;
  readyForApply?: string;
  search?: string;
};

export type AWSPermissionBoundaryExecutorStatus = 'ready' | 'degraded' | 'blocked';
export type AWSPermissionBoundaryExecutorFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSPermissionBoundaryExecutorState = 'projected' | 'precondition_failed' | 'blocked' | string;

export type AWSPermissionBoundaryExecutorPrecondition = {
  name: string;
  status: string;
  rationale: string;
};

export type AWSPermissionBoundaryExecutorSimulation = {
  simulation_ref: string;
  outcome: string;
  before_ref: string;
  after_ref: string;
  denied_action_count: number;
  target_identity_count: number;
  signals?: string[];
};

export type AWSPermissionBoundaryExecutorVerification = {
  source: string;
  signal: string;
  status: string;
  description: string;
};

export type AWSPermissionBoundaryExecutorRelationship = {
  execution_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSPermissionBoundaryExecutorEntry = {
  execution_id: string;
  calculation_version: string;
  dry_run_id: string;
  approval_id: string;
  case_id: string;
  plan_id: string;
  source_artifact_id: string;
  state: AWSPermissionBoundaryExecutorState;
  severity: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  operation: string;
  idempotency_key: string;
  target_identity_node_ids?: string[];
  target_account_ids?: string[];
  target_ou_paths?: string[];
  prevented_behavior: string;
  statement_snippets: AWSPermissionBoundarySCPStatementSnippet[];
  breakage_projection: AWSPermissionBoundarySCPBreakageProjection;
  intended_api_call: AWSRemediationDryRunIntendedAPICall;
  preconditions: AWSPermissionBoundaryExecutorPrecondition[];
  boundary_simulation: AWSPermissionBoundaryExecutorSimulation;
  verifications: AWSPermissionBoundaryExecutorVerification[];
  rollback_plan: AWSPermissionBoundarySCPRollbackPlan;
  verification_plan: AWSPermissionBoundarySCPVerificationPlan;
  audit_trail: AWSRemediationAuditEntry[];
  kill_switch_engaged: boolean;
  ready_for_live_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  projected_at: string;
  created_at: string;
  updated_at: string;
};

export type AWSPermissionBoundaryExecutorSummary = {
  total_entries: number;
  filtered_entries: number;
  state_counts: Record<string, number>;
  operation_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  ready_for_live_apply_count: number;
  kill_switch_engaged_count: number;
  failed_precondition_count: number;
  target_identity_count: number;
  verification_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSPermissionBoundaryExecutorResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSPermissionBoundaryExecutorStatus;
  fixture_state?: AWSPermissionBoundaryExecutorFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSPermissionBoundaryExecutorSummary;
  entries: AWSPermissionBoundaryExecutorEntry[];
  relationships: AWSPermissionBoundaryExecutorRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSPermissionBoundaryExecutorQuery = {
  connectorID?: string;
  fixtureState?: AWSPermissionBoundaryExecutorFixtureState;
  accountID?: string;
  region?: string;
  dryRunID?: string;
  caseID?: string;
  planID?: string;
  operation?: string;
  state?: string;
  severity?: string;
  search?: string;
};

export type AWSScpGuardrailExecutorStatus = 'ready' | 'degraded' | 'blocked';
export type AWSScpGuardrailExecutorFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSScpGuardrailExecutorState = 'projected' | 'precondition_failed' | 'blocked' | string;

export type AWSScpGuardrailExecutorPrecondition = AWSPermissionBoundaryExecutorPrecondition;
export type AWSScpGuardrailExecutorVerification = AWSPermissionBoundaryExecutorVerification;
export type AWSScpGuardrailExecutorRelationship = AWSPermissionBoundaryExecutorRelationship;

export type AWSScpGuardrailExecutorSimulation = {
  simulation_ref: string;
  outcome: string;
  before_ref: string;
  after_ref: string;
  denied_action_count: number;
  target_account_count: number;
  target_ou_count: number;
  signals?: string[];
};

export type AWSScpGuardrailExecutorEntry = {
  execution_id: string;
  calculation_version: string;
  dry_run_id: string;
  approval_id: string;
  case_id: string;
  plan_id: string;
  source_artifact_id: string;
  state: AWSScpGuardrailExecutorState;
  severity: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  operation: string;
  idempotency_key: string;
  target_account_ids?: string[];
  target_ou_paths?: string[];
  prevented_behavior: string;
  statement_snippets: AWSPermissionBoundarySCPStatementSnippet[];
  breakage_projection: AWSPermissionBoundarySCPBreakageProjection;
  intended_api_call: AWSRemediationDryRunIntendedAPICall;
  preconditions: AWSScpGuardrailExecutorPrecondition[];
  boundary_simulation: AWSScpGuardrailExecutorSimulation;
  verifications: AWSScpGuardrailExecutorVerification[];
  rollback_plan: AWSPermissionBoundarySCPRollbackPlan;
  verification_plan: AWSPermissionBoundarySCPVerificationPlan;
  audit_trail: AWSRemediationAuditEntry[];
  kill_switch_engaged: boolean;
  ready_for_live_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  projected_at: string;
  created_at: string;
  updated_at: string;
};

export type AWSScpGuardrailExecutorSummary = {
  total_entries: number;
  filtered_entries: number;
  state_counts: Record<string, number>;
  operation_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  ready_for_live_apply_count: number;
  kill_switch_engaged_count: number;
  failed_precondition_count: number;
  target_account_count: number;
  target_ou_count: number;
  verification_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSScpGuardrailExecutorResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSScpGuardrailExecutorStatus;
  fixture_state?: AWSScpGuardrailExecutorFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSScpGuardrailExecutorSummary;
  entries: AWSScpGuardrailExecutorEntry[];
  relationships: AWSScpGuardrailExecutorRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSScpGuardrailExecutorQuery = {
  connectorID?: string;
  fixtureState?: AWSScpGuardrailExecutorFixtureState;
  accountID?: string;
  region?: string;
  dryRunID?: string;
  caseID?: string;
  planID?: string;
  operation?: string;
  targetScope?: string;
  state?: string;
  severity?: string;
  search?: string;
};

export type AWSSecretKeyRotationStatus = 'ready' | 'degraded' | 'blocked';
export type AWSSecretKeyRotationFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSSecretKeyRotationType = 'provider_key' | 'secrets_manager_secret' | 'kms_related' | string;

export type AWSSecretKeyRotationOwnerHandoff = {
  owner: string;
  assigned: boolean;
  approval_state: string;
  required_actors?: string[];
  instructions?: string[];
};

export type AWSSecretKeyRotationTargetRef = {
  ref_type: string;
  node_id?: string;
  arn?: string;
  label: string;
  provider?: string;
  metadata_ref?: string;
};

export type AWSSecretKeyRotationWorkload = {
  workload_id?: string;
  workload_name?: string;
  workload_type?: string;
  resource_arn?: string;
  owner?: string;
  refresh_order: number;
};

export type AWSSecretKeyRotationStep = {
  order: number;
  phase: string;
  action: string;
  actor?: string;
  evidence_ref?: string;
  blocks_on?: string[];
};

export type AWSSecretKeyRotationReadinessGate = {
  name: string;
  status: string;
  rationale: string;
};

export type AWSSecretKeyRotationPlan = {
  plan_id: string;
  calculation_version: string;
  rotation_type: AWSSecretKeyRotationType;
  severity: string;
  status: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  provider?: string;
  owner_handoff: AWSSecretKeyRotationOwnerHandoff;
  source_finding_ids: string[];
  target_secrets?: AWSSecretKeyRotationTargetRef[];
  target_keys?: AWSSecretKeyRotationTargetRef[];
  dependent_workloads?: AWSSecretKeyRotationWorkload[];
  rotation_order: AWSSecretKeyRotationStep[];
  diff_intent: AWSRemediationDiffIntent;
  tradeoffs: AWSRemediationTradeoff[];
  rollback_plan: AWSRemediationRollbackPlan;
  verification_plan: AWSRemediationVerificationPlan;
  readiness_gates: AWSSecretKeyRotationReadinessGate[];
  ready_for_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  created_at: string;
  updated_at: string;
};

export type AWSSecretKeyRotationRelationship = {
  plan_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSSecretKeyRotationSummary = {
  total_plans: number;
  filtered_plans: number;
  rotation_type_counts: Record<string, number>;
  provider_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  owner_assigned_count: number;
  ownerless_count: number;
  ready_for_apply_count: number;
  target_secret_count: number;
  target_key_count: number;
  dependent_workload_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSSecretKeyRotationResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSSecretKeyRotationStatus;
  fixture_state?: AWSSecretKeyRotationFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSSecretKeyRotationSummary;
  plans: AWSSecretKeyRotationPlan[];
  relationships: AWSSecretKeyRotationRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSSecretKeyRotationQuery = {
  connectorID?: string;
  fixtureState?: AWSSecretKeyRotationFixtureState;
  accountID?: string;
  region?: string;
  rotationType?: string;
  provider?: string;
  owner?: string;
  severity?: string;
  status?: string;
  readyForApply?: string;
  search?: string;
};

export type AWSAccessKeyQuarantineStatus = 'ready' | 'degraded' | 'blocked';
export type AWSAccessKeyQuarantineFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSAccessKeyQuarantineState = 'disable_candidate' | 'quarantine_candidate' | 'grace_period_required' | 'needs_review' | string;

export type AWSAccessKeyQuarantineOwnerNotice = {
  owner: string;
  assigned: boolean;
  notification: string;
  grace_period: string;
  required_actors?: string[];
  instructions?: string[];
};

export type AWSAccessKeyQuarantineTarget = {
  ref_type: string;
  access_key_id?: string;
  node_id?: string;
  principal?: string;
  label: string;
  metadata_ref?: string;
};

export type AWSAccessKeyQuarantineStep = {
  order: number;
  phase: string;
  action: string;
  actor?: string;
  evidence_ref?: string;
  blocks_on?: string[];
};

export type AWSAccessKeyQuarantineGate = {
  name: string;
  status: string;
  rationale: string;
};

export type AWSAccessKeyQuarantinePlan = {
  plan_id: string;
  calculation_version: string;
  quarantine_state: AWSAccessKeyQuarantineState;
  severity: string;
  status: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  owner_notice: AWSAccessKeyQuarantineOwnerNotice;
  source_finding_ids: string[];
  target_access_keys: AWSAccessKeyQuarantineTarget[];
  affected_principals?: AWSAccessKeyQuarantineTarget[];
  last_used_at?: string;
  dormant_days: number;
  grace_period_days: number;
  quarantine_order: AWSAccessKeyQuarantineStep[];
  diff_intent: AWSRemediationDiffIntent;
  tradeoffs: AWSRemediationTradeoff[];
  rollback_plan: AWSRemediationRollbackPlan;
  verification_plan: AWSRemediationVerificationPlan;
  readiness_gates: AWSAccessKeyQuarantineGate[];
  ready_for_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  created_at: string;
  updated_at: string;
};

export type AWSAccessKeyQuarantineRelationship = {
  plan_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSAccessKeyQuarantineSummary = {
  total_plans: number;
  filtered_plans: number;
  quarantine_state_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  owner_assigned_count: number;
  ownerless_count: number;
  ready_for_apply_count: number;
  access_key_count: number;
  affected_principal_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSAccessKeyQuarantineResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSAccessKeyQuarantineStatus;
  fixture_state?: AWSAccessKeyQuarantineFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSAccessKeyQuarantineSummary;
  plans: AWSAccessKeyQuarantinePlan[];
  relationships: AWSAccessKeyQuarantineRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSAccessKeyQuarantineQuery = {
  connectorID?: string;
  fixtureState?: AWSAccessKeyQuarantineFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  quarantineState?: string;
  owner?: string;
  severity?: string;
  status?: string;
  readyForApply?: string;
  search?: string;
};

export type AWSIaCRemediationStatus = 'ready' | 'degraded' | 'blocked';
export type AWSIaCRemediationFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSIaCRemediationTarget = 'terraform' | 'cloudformation' | 'cdk' | 'policy_as_code' | string;
export type AWSIaCRemediationChangeKind = 'iam_policy_diff' | 'trust_policy_hardening' | string;

export type AWSIaCFileChange = {
  path: string;
  change_intent: string;
  resource_type?: string;
  before_ref?: string;
  after_ref?: string;
  rationale: string;
};

export type AWSIaCValidationHint = {
  tool: string;
  command: string;
  description: string;
};

export type AWSIaCCloudVerificationCheck = {
  source: string;
  signal: string;
  description: string;
};

export type AWSIaCPRNotes = {
  title: string;
  summary: string;
  labels?: string[];
  evidence_refs?: string[];
  reviewers?: string[];
};

export type AWSIaCReadinessGate = {
  name: string;
  status: string;
  rationale: string;
};

export type AWSIaCRemediationRelationship = {
  plan_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSIaCRemediationPlan = {
  plan_id: string;
  calculation_version: string;
  change_kind: AWSIaCRemediationChangeKind;
  iac_target: AWSIaCRemediationTarget;
  source_artifact_id: string;
  source_case_id?: string;
  severity: string;
  status: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  service?: string;
  identity_node_id?: string;
  identity_arn?: string;
  identity_name?: string;
  resource_node_id?: string;
  resource_arn?: string;
  file_changes: AWSIaCFileChange[];
  validation_hints: AWSIaCValidationHint[];
  cloud_verification: AWSIaCCloudVerificationCheck[];
  pr_notes: AWSIaCPRNotes;
  diff_intent: AWSRemediationDiffIntent;
  tradeoffs: AWSRemediationTradeoff[];
  rollback_plan: AWSRemediationRollbackPlan;
  verification_plan: AWSRemediationVerificationPlan;
  readiness_gates: AWSIaCReadinessGate[];
  ready_for_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  created_at: string;
  updated_at: string;
};

export type AWSIaCRemediationSummary = {
  total_plans: number;
  filtered_plans: number;
  change_kind_counts: Record<string, number>;
  iac_target_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  ready_for_apply_count: number;
  manual_review_count: number;
  file_change_count: number;
  validation_hint_count: number;
  verification_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSIaCRemediationResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSIaCRemediationStatus;
  fixture_state?: AWSIaCRemediationFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSIaCRemediationSummary;
  plans: AWSIaCRemediationPlan[];
  relationships: AWSIaCRemediationRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSIaCRemediationQuery = {
  connectorID?: string;
  fixtureState?: AWSIaCRemediationFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  iacTarget?: string;
  changeKind?: string;
  severity?: string;
  status?: string;
  readyForApply?: string;
  search?: string;
};
export type AWSRemediationApprovalStatus = 'ready' | 'degraded' | 'blocked';
export type AWSRemediationApprovalFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSRemediationApprovalState = 'requested' | 'under_review' | 'approved' | 'denied' | 'expired' | 'blocked' | string;
export type AWSRemediationApprovalRiskTier = 'critical' | 'high' | 'medium' | 'low' | string;
export type AWSRemediationApprovalScopeType = 'identity' | 'resource' | 'account' | 'ou' | 'org_root' | string;

export type AWSRemediationApprovalActor = {
  role: string;
  label: string;
  required: boolean;
  acknowledged: boolean;
};

export type AWSRemediationApprovalScope = {
  scope_type: AWSRemediationApprovalScopeType;
  account_ids?: string[];
  regions?: string[];
  connector_ids?: string[];
  identity_node_ids?: string[];
  resource_node_ids?: string[];
};

export type AWSRemediationApprovalRBACGate = {
  name: string;
  status: string;
  required_role: string;
  rationale: string;
};

export type AWSRemediationApprovalFeatureFlag = {
  name: string;
  enabled: boolean;
  scope: string;
  rationale: string;
};

export type AWSRemediationApprovalRelationship = {
  approval_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSRemediationApprovalEntry = {
  approval_id: string;
  calculation_version: string;
  case_id: string;
  source_artifact_id: string;
  source_type: string;
  state: AWSRemediationApprovalState;
  risk_tier: AWSRemediationApprovalRiskTier;
  severity: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  requestor: AWSRemediationApprovalActor;
  required_approvers: AWSRemediationApprovalActor[];
  scope: AWSRemediationApprovalScope;
  rbac_gates: AWSRemediationApprovalRBACGate[];
  feature_flags: AWSRemediationApprovalFeatureFlag[];
  idempotency_key: string;
  dry_run_ref?: string;
  diff_intent: AWSRemediationDiffIntent;
  tradeoffs: AWSRemediationTradeoff[];
  rollback_plan: AWSRemediationRollbackPlan;
  verification_plan: AWSRemediationVerificationPlan;
  audit_trail: AWSRemediationAuditEntry[];
  ready_for_execution: boolean;
  kill_switch_engaged: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  requested_at: string;
  expires_at: string;
  created_at: string;
  updated_at: string;
};

export type AWSRemediationApprovalSummary = {
  total_entries: number;
  filtered_entries: number;
  state_counts: Record<string, number>;
  risk_tier_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  scope_type_counts: Record<string, number>;
  required_approver_count: number;
  ready_for_execution_count: number;
  kill_switch_engaged_count: number;
  rbac_gate_blocked_count: number;
  audit_entry_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSRemediationApprovalResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSRemediationApprovalStatus;
  fixture_state?: AWSRemediationApprovalFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSRemediationApprovalSummary;
  entries: AWSRemediationApprovalEntry[];
  relationships: AWSRemediationApprovalRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSRemediationApprovalQuery = {
  connectorID?: string;
  fixtureState?: AWSRemediationApprovalFixtureState;
  accountID?: string;
  region?: string;
  caseID?: string;
  state?: string;
  riskTier?: string;
  scopeType?: string;
  requestor?: string;
  approverRole?: string;
  severity?: string;
  readyForExecution?: string;
  killSwitchEngaged?: string;
  search?: string;
};

export type AWSRemediationDryRunStatus = 'ready' | 'degraded' | 'blocked';
export type AWSRemediationDryRunFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSRemediationDryRunOutcome = 'would_succeed' | 'would_fail' | 'requires_review' | 'blocked' | 'kill_switch_engaged' | string;

export type AWSRemediationDryRunIntendedAPICall = {
  service: string;
  operation: string;
  target_resource?: string;
  parameter_refs?: string[];
  idempotent: boolean;
  requires_approval: boolean;
};

export type AWSRemediationDryRunAffectedResource = {
  node_id: string;
  resource_arn?: string;
  resource_type?: string;
  change_kind: string;
  before_ref?: string;
  after_ref?: string;
};

export type AWSRemediationDryRunPrerequisite = {
  name: string;
  status: string;
  rationale: string;
};

export type AWSRemediationDryRunVerificationCheck = {
  source: string;
  signal: string;
  description: string;
};

export type AWSRemediationDryRunRelationship = {
  dry_run_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSRemediationDryRunEntry = {
  dry_run_id: string;
  calculation_version: string;
  approval_id: string;
  case_id: string;
  source_artifact_id: string;
  source_type: string;
  outcome: AWSRemediationDryRunOutcome;
  risk_tier: string;
  severity: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  account_ids?: string[];
  region: string;
  idempotency_key: string;
  dry_run_ref: string;
  diff_intent: AWSRemediationDiffIntent;
  intended_api_calls: AWSRemediationDryRunIntendedAPICall[];
  affected_resources: AWSRemediationDryRunAffectedResource[];
  satisfied_prerequisites: AWSRemediationDryRunPrerequisite[];
  failed_prerequisites: AWSRemediationDryRunPrerequisite[];
  verification_checks: AWSRemediationDryRunVerificationCheck[];
  rollback_plan: AWSRemediationRollbackPlan;
  verification_plan: AWSRemediationVerificationPlan;
  tradeoffs: AWSRemediationTradeoff[];
  audit_trail: AWSRemediationAuditEntry[];
  kill_switch_engaged: boolean;
  ready_for_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  simulated_at: string;
  created_at: string;
  updated_at: string;
};

export type AWSRemediationDryRunSummary = {
  total_entries: number;
  filtered_entries: number;
  outcome_counts: Record<string, number>;
  source_type_counts: Record<string, number>;
  risk_tier_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  api_call_count: number;
  affected_resource_count: number;
  failed_prerequisite_count: number;
  verification_check_count: number;
  ready_for_apply_count: number;
  kill_switch_engaged_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSRemediationDryRunResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSRemediationDryRunStatus;
  fixture_state?: AWSRemediationDryRunFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSRemediationDryRunSummary;
  entries: AWSRemediationDryRunEntry[];
  relationships: AWSRemediationDryRunRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSRemediationDryRunQuery = {
  connectorID?: string;
  fixtureState?: AWSRemediationDryRunFixtureState;
  accountID?: string;
  region?: string;
  approvalID?: string;
  caseID?: string;
  sourceType?: string;
  outcome?: string;
  riskTier?: string;
  severity?: string;
  search?: string;
};

export type AWSLowRiskRemediationStatus = 'ready' | 'degraded' | 'blocked';
export type AWSLowRiskRemediationFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSLowRiskRemediationState = 'projected' | 'skipped' | 'blocked' | string;
export type AWSLowRiskRemediationActionCategory = 'tagging' | 'stale_metadata_cleanup' | 'approved_disable' | 'approved_detach' | string;

export type AWSLowRiskRemediationAllowlistRule = {
  name: string;
  category: AWSLowRiskRemediationActionCategory;
  action: string;
  match_sources?: string[];
  max_blast_radius?: string;
  rationale: string;
};

export type AWSLowRiskRemediationPreflight = {
  name: string;
  status: string;
  rationale: string;
};

export type AWSLowRiskRemediationMutationRecord = {
  service: string;
  operation: string;
  target_resource: string;
  change_kind: string;
  before_ref?: string;
  after_ref?: string;
  parameter_refs?: string[];
};

export type AWSLowRiskRemediationVerificationRecord = {
  source: string;
  signal: string;
  status: string;
  description: string;
};

export type AWSLowRiskRemediationRelationship = {
  execution_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSLowRiskRemediationEntry = {
  execution_id: string;
  calculation_version: string;
  dry_run_id: string;
  approval_id: string;
  case_id: string;
  source_artifact_id: string;
  source_type: string;
  state: AWSLowRiskRemediationState;
  severity: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  idempotency_key: string;
  allowlist_rule: AWSLowRiskRemediationAllowlistRule;
  mutation: AWSLowRiskRemediationMutationRecord;
  preflights: AWSLowRiskRemediationPreflight[];
  verifications: AWSLowRiskRemediationVerificationRecord[];
  rollback_plan: AWSRemediationRollbackPlan;
  verification_plan: AWSRemediationVerificationPlan;
  tradeoffs: AWSRemediationTradeoff[];
  audit_trail: AWSRemediationAuditEntry[];
  kill_switch_engaged: boolean;
  ready_for_live_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  projected_at: string;
  created_at: string;
  updated_at: string;
};

export type AWSLowRiskRemediationSummary = {
  total_entries: number;
  filtered_entries: number;
  state_counts: Record<string, number>;
  action_counts: Record<string, number>;
  category_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  ready_for_live_apply_count: number;
  kill_switch_engaged_count: number;
  failed_preflight_count: number;
  mutation_count: number;
  verification_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSLowRiskRemediationResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSLowRiskRemediationStatus;
  fixture_state?: AWSLowRiskRemediationFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  allowlist: AWSLowRiskRemediationAllowlistRule[];
  summary: AWSLowRiskRemediationSummary;
  entries: AWSLowRiskRemediationEntry[];
  relationships: AWSLowRiskRemediationRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSLowRiskRemediationQuery = {
  connectorID?: string;
  fixtureState?: AWSLowRiskRemediationFixtureState;
  accountID?: string;
  region?: string;
  dryRunID?: string;
  caseID?: string;
  action?: string;
  actionCategory?: string;
  state?: string;
  severity?: string;
  search?: string;
};

export type AWSTrustPolicyHardeningExecutorStatus = 'ready' | 'degraded' | 'blocked';
export type AWSTrustPolicyHardeningExecutorFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSTrustPolicyHardeningExecutorState = 'projected' | 'precondition_failed' | 'blocked' | string;

export type AWSTrustPolicyHardeningExecutorPrecondition = {
  name: string;
  status: string;
  rationale: string;
};

export type AWSTrustPolicyHardeningExecutorPolicySimulation = {
  simulation_ref: string;
  outcome: string;
  before_ref: string;
  after_ref: string;
  allowed_count: number;
  denied_count: number;
  signals?: string[];
};

export type AWSTrustPolicyHardeningExecutorVerification = {
  source: string;
  signal: string;
  status: string;
  description: string;
};

export type AWSTrustPolicyHardeningExecutorRelationship = {
  execution_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref?: string;
};

export type AWSTrustPolicyHardeningExecutorEntry = {
  execution_id: string;
  calculation_version: string;
  dry_run_id: string;
  approval_id: string;
  case_id: string;
  plan_id: string;
  source_artifact_id: string;
  state: AWSTrustPolicyHardeningExecutorState;
  hardening_direction: string;
  severity: string;
  score: number;
  confidence: number;
  title: string;
  summary: string;
  account_id: string;
  region: string;
  idempotency_key: string;
  resource_node_id: string;
  resource_arn?: string;
  resource_label?: string;
  public_principal: boolean;
  principal_change: AWSTrustPolicyPrincipalChange;
  condition_recommendations: AWSTrustPolicyConditionRecommendation[];
  statement_snippets: AWSTrustPolicyStatementSnippet[];
  affected_callers: AWSTrustPolicyAffectedCaller[];
  breakage_projection: AWSTrustPolicyHardeningBreakageProjection;
  intended_api_call: AWSRemediationDryRunIntendedAPICall;
  preconditions: AWSTrustPolicyHardeningExecutorPrecondition[];
  policy_simulation: AWSTrustPolicyHardeningExecutorPolicySimulation;
  verifications: AWSTrustPolicyHardeningExecutorVerification[];
  rollback_plan: AWSTrustPolicyHardeningRollbackPlan;
  verification_plan: AWSTrustPolicyHardeningVerificationPlan;
  audit_trail: AWSRemediationAuditEntry[];
  kill_switch_engaged: boolean;
  ready_for_live_apply: boolean;
  read_only_projection: boolean;
  source_signals: string[];
  evidence: AWSLeastPrivilegeEvidence[];
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  next_action: string;
  projected_at: string;
  created_at: string;
  updated_at: string;
};

export type AWSTrustPolicyHardeningExecutorSummary = {
  total_entries: number;
  filtered_entries: number;
  state_counts: Record<string, number>;
  hardening_direction_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  ready_for_live_apply_count: number;
  kill_switch_engaged_count: number;
  public_principal_count: number;
  failed_precondition_count: number;
  verification_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
};

export type AWSTrustPolicyHardeningExecutorResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSTrustPolicyHardeningExecutorStatus;
  fixture_state?: AWSTrustPolicyHardeningExecutorFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSTrustPolicyHardeningExecutorSummary;
  entries: AWSTrustPolicyHardeningExecutorEntry[];
  relationships: AWSTrustPolicyHardeningExecutorRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSTrustPolicyHardeningExecutorQuery = {
  connectorID?: string;
  fixtureState?: AWSTrustPolicyHardeningExecutorFixtureState;
  accountID?: string;
  region?: string;
  dryRunID?: string;
  caseID?: string;
  planID?: string;
  hardeningDirection?: string;
  state?: string;
  severity?: string;
  search?: string;
};

export type AWSBlastRadiusStatus = 'ready' | 'degraded' | 'blocked';
export type AWSBlastRadiusFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSBlastRadiusSeverity = 'critical' | 'high' | 'medium' | 'low' | string;
export type AWSBlastRadiusFindingStatus = 'action_required' | 'review' | 'monitor' | string;

export type AWSBlastRadiusEvidence = {
  source: string;
  evidence_ref: string;
  label: string;
  confidence: number;
  observed_at?: string;
  relationship?: string;
};

export type AWSBlastRadiusPathStep = {
  node_id: string;
  node_type: string;
  label: string;
  account_id?: string;
  region?: string;
};

export type AWSBlastRadiusRelationship = {
  finding_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSBlastRadiusRemediationCasePreview = {
  case_id: string;
  title: string;
  recommended_action: string;
  approval_required: boolean;
  blocking_evidence?: string[];
  impacted_node_count: number;
  estimated_risk_drop: number;
  read_only_projection: boolean;
};

export type AWSBlastRadiusFinding = {
  finding_id: string;
  calculation_version: string;
  risk_type: string;
  severity: AWSBlastRadiusSeverity;
  status: AWSBlastRadiusFindingStatus;
  score: number;
  confidence: number;
  account_id: string;
  region: string;
  identity_node_id: string;
  principal_arn?: string;
  display_name: string;
  rationale: string;
  impacted_nodes: string[];
  impacted_path: AWSBlastRadiusPathStep[];
  sensitive_nodes?: string[];
  cross_account_edges?: string[];
  runtime_actions?: string[];
  agent_tool_paths?: string[];
  evidence: AWSBlastRadiusEvidence[];
  next_action: string;
  remediation_case: AWSBlastRadiusRemediationCasePreview;
  created_at: string;
  updated_at: string;
};

export type AWSBlastRadiusSummary = {
  total_findings: number;
  filtered_findings: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  risk_type_counts: Record<string, number>;
  critical_count: number;
  high_count: number;
  sensitive_node_count: number;
  cross_account_edge_count: number;
  runtime_action_count: number;
  agent_tool_path_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
  remediation_preview_count: number;
};

export type AWSBlastRadiusDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSBlastRadiusCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSBlastRadiusResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSBlastRadiusStatus;
  fixture_state?: AWSBlastRadiusFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSBlastRadiusSummary;
  findings: AWSBlastRadiusFinding[];
  relationships: AWSBlastRadiusRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSBlastRadiusCoverageGap[];
  diagnostics: AWSBlastRadiusDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSBlastRadiusQuery = {
  connectorID?: string;
  fixtureState?: AWSBlastRadiusFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  resource?: string;
  severity?: string;
  status?: string;
  riskType?: string;
};

export type AWSLeastPrivilegeStatus = 'ready' | 'degraded' | 'blocked';
export type AWSLeastPrivilegeFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';
export type AWSLeastPrivilegeDecision = 'keep' | 'remove' | 'review' | string;
export type AWSLeastPrivilegeSeverity = 'critical' | 'high' | 'medium' | 'low' | string;
export type AWSLeastPrivilegeFindingStatus = 'action_required' | 'review' | 'monitor' | string;
export type AWSLeastPrivilegeBreakagePrediction = 'low' | 'medium' | 'high' | 'unknown' | string;

export type AWSLeastPrivilegeEvidence = {
  source: string;
  evidence_ref: string;
  label: string;
  confidence: number;
  observed_at?: string;
  relationship?: string;
};

export type AWSLeastPrivilegePathStep = {
  node_id: string;
  node_type: string;
  label: string;
  account_id?: string;
  region?: string;
};

export type AWSLeastPrivilegeRelationship = {
  recommendation_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSLeastPrivilegeRemediationCasePreview = {
  case_id: string;
  title: string;
  recommended_action: string;
  approval_required: boolean;
  blocking_evidence?: string[];
  impacted_node_count: number;
  estimated_risk_drop: number;
  breakage_prediction: AWSLeastPrivilegeBreakagePrediction;
  read_only_projection: boolean;
};

export type AWSLeastPrivilegeRecommendation = {
  recommendation_id: string;
  calculation_version: string;
  recommendation_type: string;
  decision: AWSLeastPrivilegeDecision;
  severity: AWSLeastPrivilegeSeverity;
  status: AWSLeastPrivilegeFindingStatus;
  score: number;
  confidence: number;
  account_id: string;
  region: string;
  service: string;
  identity_node_id: string;
  principal_arn?: string;
  resource_node_id?: string;
  resource_arn?: string;
  display_name: string;
  rationale: string;
  breakage_prediction: AWSLeastPrivilegeBreakagePrediction;
  breakage_rationale: string;
  keep_actions?: string[];
  remove_actions?: string[];
  observed_actions?: string[];
  granted_actions?: string[];
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  evidence: AWSLeastPrivilegeEvidence[];
  next_action: string;
  remediation_case: AWSLeastPrivilegeRemediationCasePreview;
  created_at: string;
  updated_at: string;
};

export type AWSLeastPrivilegeSummary = {
  total_recommendations: number;
  filtered_recommendations: number;
  decision_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  service_counts: Record<string, number>;
  remove_count: number;
  keep_count: number;
  review_count: number;
  low_breakage_count: number;
  unknown_breakage_count: number;
  runtime_evidence_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
  remediation_preview_count: number;
  permission_denied_evidence_count: number;
};

export type AWSLeastPrivilegeDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSLeastPrivilegeCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSLeastPrivilegeResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSLeastPrivilegeStatus;
  fixture_state?: AWSLeastPrivilegeFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSLeastPrivilegeSummary;
  recommendations: AWSLeastPrivilegeRecommendation[];
  relationships: AWSLeastPrivilegeRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSLeastPrivilegeQuery = {
  connectorID?: string;
  fixtureState?: AWSLeastPrivilegeFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  resource?: string;
  service?: string;
  severity?: string;
  status?: string;
  decision?: string;
};

export type AWSUnusedDormantAccessStatus = 'ready' | 'degraded' | 'blocked';
export type AWSUnusedDormantAccessFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSUnusedDormantAccessDormancyState = 'never_used' | 'stale' | 'no_runtime_evidence' | 'unknown' | string;
export type AWSUnusedDormantAccessFindingStatus = 'cleanup_candidate' | 'review' | string;

export type AWSUnusedDormantAccessRelationship = {
  finding_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSUnusedDormantAccessFinding = {
  finding_id: string;
  calculation_version: string;
  finding_type: string;
  dormancy_state: AWSUnusedDormantAccessDormancyState;
  severity: AWSLeastPrivilegeSeverity;
  status: AWSUnusedDormantAccessFindingStatus;
  score: number;
  confidence: number;
  account_id: string;
  region: string;
  service: string;
  identity_node_id: string;
  principal_arn?: string;
  resource_node_id?: string;
  resource_arn?: string;
  display_name: string;
  owner_context: string;
  policy_scope: string;
  rationale: string;
  last_used_at?: string;
  dormant_days: number;
  scan_window_days: number;
  candidate_actions?: string[];
  observed_actions?: string[];
  granted_actions?: string[];
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  evidence: AWSLeastPrivilegeEvidence[];
  next_action: string;
  remediation_case: AWSLeastPrivilegeRemediationCasePreview;
  created_at: string;
  updated_at: string;
};

export type AWSUnusedDormantAccessSummary = {
  total_findings: number;
  filtered_findings: number;
  dormancy_state_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  service_counts: Record<string, number>;
  cleanup_candidate_count: number;
  review_required_count: number;
  no_runtime_evidence_count: number;
  unknown_evidence_count: number;
  stale_access_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
  remediation_preview_count: number;
  permission_denied_evidence_count: number;
};

export type AWSUnusedDormantAccessResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSUnusedDormantAccessStatus;
  fixture_state?: AWSUnusedDormantAccessFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSUnusedDormantAccessSummary;
  findings: AWSUnusedDormantAccessFinding[];
  relationships: AWSUnusedDormantAccessRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSUnusedDormantAccessQuery = {
  connectorID?: string;
  fixtureState?: AWSUnusedDormantAccessFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  resource?: string;
  service?: string;
  severity?: string;
  status?: string;
  dormancyState?: string;
};

// AWSIdentitySprawl* types describe Wave 6.04 sprawl findings: stale,
// ownerless, duplicate, and shared IAM roles clustered by attachment
// surface and runtime usage.
export type AWSIdentitySprawlStatus = 'ready' | 'degraded' | 'blocked';
export type AWSIdentitySprawlFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSIdentitySprawlFindingType =
  | 'stale_identity'
  | 'ownerless_identity'
  | 'duplicate_identity'
  | 'shared_role'
  | string;
export type AWSIdentitySprawlFindingStatus = 'review' | 'cleanup_candidate' | string;

export type AWSIdentitySprawlRelationship = {
  finding_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSIdentitySprawlCluster = {
  cluster_id: string;
  cluster_kind: string;
  identity_node_ids: string[];
  workload_types?: string[];
  signature_hint?: string;
};

export type AWSIdentitySprawlFinding = {
  finding_id: string;
  calculation_version: string;
  finding_type: AWSIdentitySprawlFindingType;
  severity: string;
  status: AWSIdentitySprawlFindingStatus;
  score: number;
  confidence: number;
  account_id: string;
  region: string;
  identity_node_id: string;
  principal_arn?: string;
  role_name?: string;
  display_name: string;
  owner_label?: string;
  owner_source: string;
  workload_types?: string[];
  workload_node_ids?: string[];
  cluster_id?: string;
  cluster_kind?: string;
  rationale: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  evidence: AWSLeastPrivilegeEvidence[];
  next_action: string;
  remediation_case: AWSLeastPrivilegeRemediationCasePreview;
  created_at: string;
  updated_at: string;
};

export type AWSIdentitySprawlSummary = {
  total_findings: number;
  filtered_findings: number;
  finding_type_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  owner_source_counts: Record<string, number>;
  stale_identity_count: number;
  ownerless_identity_count: number;
  duplicate_cluster_count: number;
  shared_role_count: number;
  unique_identity_count: number;
  unique_workload_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
  remediation_preview_count: number;
};

export type AWSIdentitySprawlResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSIdentitySprawlStatus;
  fixture_state?: AWSIdentitySprawlFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSIdentitySprawlSummary;
  findings: AWSIdentitySprawlFinding[];
  clusters: AWSIdentitySprawlCluster[];
  relationships: AWSIdentitySprawlRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSIdentitySprawlQuery = {
  connectorID?: string;
  fixtureState?: AWSIdentitySprawlFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  owner?: string;
  cluster?: string;
  findingType?: AWSIdentitySprawlFindingType;
  severity?: string;
  status?: string;
};

// AWSPrivilegeEscalation* types describe Wave 6.05 escalation paths composed
// from PassRole, policy attachment, trust, admin-equivalence, KMS/secrets, and
// cross-account graph evidence.
export type AWSPrivilegeEscalationStatus = 'ready' | 'degraded' | 'blocked';
export type AWSPrivilegeEscalationFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSPrivilegeEscalationType =
  | 'passrole_service_escalation'
  | 'passrole_wildcard_escalation'
  | 'passrole_unscoped_trust_path'
  | 'policy_attachment_escalation'
  | 'kms_admin_equivalence'
  | 'secrets_admin_equivalence'
  | 'cross_account_escalation_path'
  | string;
export type AWSPrivilegeEscalationFindingStatus = 'review' | 'action_required' | string;

export type AWSPrivilegeEscalationRelationship = {
  finding_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSPrivilegeEscalationFinding = {
  finding_id: string;
  calculation_version: string;
  escalation_type: AWSPrivilegeEscalationType;
  severity: string;
  status: AWSPrivilegeEscalationFindingStatus;
  score: number;
  confidence: number;
  account_id: string;
  region: string;
  identity_node_id: string;
  principal_arn?: string;
  target_node_id?: string;
  target_label: string;
  display_name: string;
  rationale: string;
  exploitability: string;
  runtime_context: string;
  policy_sources?: string[];
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  evidence: AWSLeastPrivilegeEvidence[];
  next_action: string;
  remediation_case: AWSLeastPrivilegeRemediationCasePreview;
  created_at: string;
  updated_at: string;
};

export type AWSPrivilegeEscalationSummary = {
  total_findings: number;
  filtered_findings: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  escalation_type_counts: Record<string, number>;
  critical_count: number;
  high_count: number;
  cross_account_path_count: number;
  passrole_path_count: number;
  admin_equivalent_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
  remediation_preview_count: number;
};

export type AWSPrivilegeEscalationResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSPrivilegeEscalationStatus;
  fixture_state?: AWSPrivilegeEscalationFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSPrivilegeEscalationSummary;
  findings: AWSPrivilegeEscalationFinding[];
  relationships: AWSPrivilegeEscalationRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSPrivilegeEscalationQuery = {
  connectorID?: string;
  fixtureState?: AWSPrivilegeEscalationFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  target?: string;
  escalationType?: AWSPrivilegeEscalationType;
  severity?: string;
  status?: string;
};

// AWSCrossAccountTrust* types describe Wave 6.06 external access decisions
// composed from Organizations, resource-policy, runtime, Access Analyzer, and
// graph evidence.
export type AWSCrossAccountTrustStatus = 'ready' | 'degraded' | 'blocked';
export type AWSCrossAccountTrustFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSCrossAccountTrustFindingType =
  | 'cross_account_resource_access'
  | 'public_resource_trust'
  | 'runtime_cross_account_assumption'
  | 'access_analyzer_external_access'
  | 'cross_account_graph_path'
  | string;

export type AWSCrossAccountTrustRelationship = {
  finding_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSCrossAccountTrustFinding = {
  finding_id: string;
  calculation_version: string;
  finding_type: AWSCrossAccountTrustFindingType;
  severity: string;
  status: string;
  score: number;
  confidence: number;
  account_id: string;
  region: string;
  service: string;
  resource_type: string;
  resource_arn?: string;
  resource_node_id?: string;
  resource_label: string;
  external_principal_arn?: string;
  external_principal_account?: string;
  external_principal_ou_path?: string;
  trusted_within_organization: boolean;
  public_principal: boolean;
  has_condition: boolean;
  condition_keys?: string[];
  policy_sources?: string[];
  runtime_observed: boolean;
  analyzer_backed: boolean;
  rationale: string;
  hardening_direction: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  evidence: AWSLeastPrivilegeEvidence[];
  next_action: string;
  remediation_case: AWSLeastPrivilegeRemediationCasePreview;
  created_at: string;
  updated_at: string;
};

export type AWSCrossAccountTrustSummary = {
  total_findings: number;
  filtered_findings: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  finding_type_counts: Record<string, number>;
  service_counts: Record<string, number>;
  critical_count: number;
  high_count: number;
  public_principal_count: number;
  cross_account_grant_count: number;
  runtime_observed_count: number;
  analyzer_backed_count: number;
  unconditional_grant_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
  remediation_preview_count: number;
};

export type AWSCrossAccountTrustResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSCrossAccountTrustStatus;
  fixture_state?: AWSCrossAccountTrustFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSCrossAccountTrustSummary;
  findings: AWSCrossAccountTrustFinding[];
  relationships: AWSCrossAccountTrustRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSCrossAccountTrustQuery = {
  connectorID?: string;
  fixtureState?: AWSCrossAccountTrustFixtureState;
  accountID?: string;
  region?: string;
  service?: string;
  principal?: string;
  resource?: string;
  findingType?: AWSCrossAccountTrustFindingType;
  severity?: string;
  status?: string;
  ou?: string;
};

// AWSSecretPermissionEquivalence* types describe Wave 6.07 decisions where a
// readable secret/provider key is treated as a permission-bearing capability.
export type AWSSecretPermissionEquivalenceStatus = 'ready' | 'degraded' | 'blocked';
export type AWSSecretPermissionEquivalenceFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSSecretPermissionEquivalenceType =
  | 'workload_provider_key_equivalence'
  | 'secret_read_policy_equivalence'
  | 'kms_decrypt_secret_equivalence'
  | 'kms_live_grant_secret_equivalence'
  | 'runtime_secret_access_equivalence'
  | 'agent_provider_key_equivalence'
  | 'blast_radius_secret_equivalence'
  | 'admin_equivalent_secret_permission'
  | string;

export type AWSSecretPermissionEquivalenceRelationship = {
  finding_id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSSecretPermissionEquivalenceFinding = {
  finding_id: string;
  calculation_version: string;
  equivalence_type: AWSSecretPermissionEquivalenceType;
  severity: string;
  status: string;
  score: number;
  confidence: number;
  account_id: string;
  region: string;
  identity_node_id: string;
  principal_arn?: string;
  workload_id?: string;
  workload_name?: string;
  agent_id?: string;
  agent_name?: string;
  secret_node_id: string;
  secret_arn?: string;
  secret_label: string;
  provider: string;
  provider_key_reference?: string;
  unresolved_reference?: boolean;
  equivalent_permissions: string[];
  implied_actions?: string[];
  source_signals: string[];
  rationale: string;
  evidence_boundary: string;
  impacted_nodes: string[];
  impacted_path: AWSLeastPrivilegePathStep[];
  evidence: AWSLeastPrivilegeEvidence[];
  next_action: string;
  remediation_case: AWSLeastPrivilegeRemediationCasePreview;
  created_at: string;
  updated_at: string;
};

export type AWSSecretPermissionEquivalenceSummary = {
  total_findings: number;
  filtered_findings: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  equivalence_type_counts: Record<string, number>;
  provider_counts: Record<string, number>;
  external_provider_key_count: number;
  aws_managed_secret_count: number;
  runtime_observed_count: number;
  kms_backed_count: number;
  unresolved_reference_count: number;
  relationship_count: number;
  highest_score: number;
  average_confidence_pct: number;
  remediation_preview_count: number;
};

export type AWSSecretPermissionEquivalenceResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSSecretPermissionEquivalenceStatus;
  fixture_state?: AWSSecretPermissionEquivalenceFixtureState;
  confidence: number;
  calculation_version: string;
  applied_filters: Record<string, string>;
  summary: AWSSecretPermissionEquivalenceSummary;
  findings: AWSSecretPermissionEquivalenceFinding[];
  relationships: AWSSecretPermissionEquivalenceRelationship[];
  caveats: string[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSLeastPrivilegeCoverageGap[];
  diagnostics: AWSLeastPrivilegeDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSSecretPermissionEquivalenceQuery = {
  connectorID?: string;
  fixtureState?: AWSSecretPermissionEquivalenceFixtureState;
  accountID?: string;
  region?: string;
  identity?: string;
  secret?: string;
  provider?: string;
  equivalenceType?: AWSSecretPermissionEquivalenceType;
  evidence?: string;
  search?: string;
  severity?: string;
  status?: string;
};

export type AWSBedrockAgentsInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSBedrockAgentsFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSBedrockAgentsProvider = 'amazon-bedrock';

export type AWSBedrockAgentCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSBedrockAgentRecord = {
  account_id: string;
  region: string;
  service: string;
  agent_id: string;
  agent_arn?: string;
  agent_name: string;
  agent_type: string;
  provider?: string;
  model_id?: string;
  runtime_role_arn?: string;
  runtime_role_name?: string;
  runtime_role_account_id?: string;
  tool_names: string[];
  tool_count: number;
  memory_enabled: boolean;
  memory_store_refs: string[];
  capability_names: string[];
  credential_reference_refs: string[];
  guardrail_id?: string;
  sensitive_boundary: string;
  coverage_status: string;
  coverage_reason?: string;
  source: string;
  evidence_ref: string;
  agent_node_id: string;
  runtime_role_node_id?: string;
  relationship_types: string[];
  confidence: number;
  next_action: string;
  collected_at: string;
  status: string;
  tags?: Record<string, string>;
};

export type AWSBedrockAgentRelation = {
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSBedrockAgentDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSBedrockAgentsInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSBedrockAgentsInventoryStatus;
  fixture_state: AWSBedrockAgentsFixtureState;
  confidence: number;
  agent_count: number;
  filtered_agent_count: number;
  guardrail_count: number;
  knowledge_base_count: number;
  tool_count: number;
  credential_reference_count: number;
  runtime_role_count: number;
  model_count: number;
  provider_breakdown: Record<string, number>;
  status_breakdown: Record<string, number>;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSBedrockAgentCoverageGap[];
  records: AWSBedrockAgentRecord[];
  relationships: AWSBedrockAgentRelation[];
  diagnostics: AWSBedrockAgentDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSIAMPassRoleRelationshipInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSIAMPassRoleRelationshipFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSIAMPassRoleCoverageGap = {
  capability: string;
  status: 'unsupported';
  reason: string;
  remediation?: string;
};

export type AWSIAMPassRoleRelationshipRecord = {
  account_id: string;
  region?: string;
  service: 'iam-passrole';
  workload_id: string;
  workload_type: 'iam_passrole_relationship' | string;
  workload_name: string;
  source_role_arn: string;
  source_role_name?: string;
  source_role_path?: string;
  target_resource: string;
  target_wildcard_kind: 'specific' | 'path_wildcard' | 'account_wildcard' | 'all' | 'malformed';
  policy_name?: string;
  statement_sid?: string;
  action_expression: 'iam:PassRole' | 'iam:*' | '*' | string;
  effect: 'Allow' | 'Deny';
  passed_to_service?: string;
  condition_operator?: string;
  not_action?: boolean;
  not_resource?: boolean;
  other_condition_keys?: string[];
  unresolved_target: boolean;
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'can_pass_role' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSIAMPassRoleRelationshipEdge = {
  type: 'can_pass_role' | string;
  from_node_id: string;
  to_node_id?: string;
  evidence_ref: string;
  effect: 'Allow' | 'Deny';
  passed_to_service?: string;
};

export type AWSIAMPassRoleRelationshipDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSIAMPassRoleRelationshipInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSIAMPassRoleRelationshipInventoryStatus;
  fixture_state: AWSIAMPassRoleRelationshipFixtureState;
  confidence: number;
  record_count: number;
  source_role_count: number;
  target_role_count: number;
  wildcard_target_count: number;
  deny_statement_count: number;
  service_scoped_count: number;
  unscoped_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSIAMPassRoleCoverageGap[];
  records: AWSIAMPassRoleRelationshipRecord[];
  relationships: AWSIAMPassRoleRelationshipEdge[];
  diagnostics: AWSIAMPassRoleRelationshipDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSS3BucketReachabilityInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSS3BucketReachabilityFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSS3CoverageGap = {
  capability: string;
  status: 'unsupported';
  reason: string;
  remediation?: string;
};

export type AWSS3PublicAccessBlock = {
  block_public_acls: boolean;
  ignore_public_acls: boolean;
  block_public_policy: boolean;
  restrict_public_buckets: boolean;
};

export type AWSS3AccessPointReference = {
  name: string;
  arn?: string;
  network_origin?: string;
  vpc_id?: string;
};

export type AWSS3IdentityGrant = {
  principal_arn?: string;
  principal_type?: string;
  effect: 'Allow' | 'Deny';
  actions?: string[];
  not_action?: boolean;
  condition_keys?: string[];
  is_public?: boolean;
  is_cross_account?: boolean;
  has_condition?: boolean;
  statement_sid?: string;
  wildcard_principal?: boolean;
};

export type AWSS3BucketReachabilityRecord = {
  account_id: string;
  region: string;
  service: 's3';
  bucket_arn: string;
  bucket_name: string;
  bucket_region?: string;
  created_at?: string;
  has_bucket_policy: boolean;
  bucket_policy_statement_count: number;
  public_access_block?: AWSS3PublicAccessBlock;
  ownership_controls?: string;
  block_public_acls: boolean;
  block_public_policy: boolean;
  ignore_public_acls: boolean;
  restrict_public_buckets: boolean;
  default_encryption_algorithm?: string;
  default_encryption_kms_key_arn?: string;
  bucket_key_enabled: boolean;
  access_points?: AWSS3AccessPointReference[];
  identity_grants?: AWSS3IdentityGrant[];
  exposure_classification:
    | 'public'
    | 'cross_account'
    | 'restricted'
    | 'private_with_grants'
    | 'private'
    | 'unknown';
  exposure_reasons?: string[];
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  relationship_type: 'can_access';
  confidence: number;
  collected_at: string;
  status: 'ready' | 'degraded';
};

export type AWSS3BucketReachabilityEdge = {
  type: 'can_access';
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  effect: 'Allow';
  principal_type: string;
  has_condition?: boolean;
};

export type AWSS3BucketReachabilityDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSS3BucketReachabilityInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSS3BucketReachabilityInventoryStatus;
  fixture_state: AWSS3BucketReachabilityFixtureState;
  confidence: number;
  bucket_count: number;
  public_bucket_count: number;
  cross_account_bucket_count: number;
  restricted_bucket_count: number;
  buckets_with_policy_count: number;
  buckets_without_pab_count: number;
  buckets_with_kms_count: number;
  access_point_count: number;
  identity_grant_count: number;
  public_grant_count: number;
  cross_account_grant_count: number;
  deny_grant_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSS3CoverageGap[];
  records: AWSS3BucketReachabilityRecord[];
  relationships: AWSS3BucketReachabilityEdge[];
  diagnostics: AWSS3BucketReachabilityDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSKMSDecryptReachabilityInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSKMSDecryptReachabilityFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSKMSCoverageGap = {
  capability: string;
  status: 'unsupported';
  reason: string;
  remediation?: string;
};

export type AWSKMSIdentityGrant = {
  principal_arn?: string;
  principal_type?: string;
  effect: 'Allow' | 'Deny';
  actions?: string[];
  not_action?: boolean;
  capabilities?: string[];
  condition_keys?: string[];
  is_public?: boolean;
  is_cross_account?: boolean;
  has_condition?: boolean;
  statement_sid?: string;
  wildcard_principal?: boolean;
};

export type AWSKMSGrant = {
  grant_id?: string;
  name?: string;
  grantee_principal?: string;
  grantee_principal_type?: string;
  retiring_principal?: string;
  issuing_account?: string;
  operations?: string[];
  capabilities?: string[];
  encryption_context_keys?: string[];
  encryption_context_subset_keys?: string[];
  has_constraints?: boolean;
  is_cross_account?: boolean;
  created_at?: string;
};

export type AWSKMSDecryptReachabilityRecord = {
  account_id: string;
  region: string;
  service: 'kms';
  key_arn: string;
  key_id: string;
  key_manager?: 'CUSTOMER' | 'AWS' | '';
  key_state?: string;
  key_usage?: string;
  key_spec?: string;
  origin?: string;
  description?: string;
  enabled: boolean;
  created_at?: string;
  deletion_date?: string;
  multi_region?: boolean;
  multi_region_primary?: boolean;
  primary_key_arn?: string;
  replica_key_arns?: string[];
  rotation_enabled: boolean;
  rotation_supported: boolean;
  aliases?: string[];
  has_key_policy: boolean;
  key_policy_statement_count: number;
  iam_delegation_enabled: boolean;
  identity_grants?: AWSKMSIdentityGrant[];
  grants?: AWSKMSGrant[];
  exposure_classification:
    | 'public'
    | 'cross_account'
    | 'restricted'
    | 'managed_by_iam'
    | 'managed_by_aws'
    | 'private_with_grants'
    | 'private'
    | 'unknown';
  exposure_reasons?: string[];
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  relationship_type: 'can_decrypt';
  confidence: number;
  collected_at: string;
  status: 'ready' | 'degraded';
};

export type AWSKMSDecryptReachabilityEdge = {
  type: 'can_decrypt';
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  effect: 'Allow';
  source: 'key_policy' | 'kms_grant';
  principal_type: string;
  capabilities?: string[];
  has_condition?: boolean;
};

export type AWSKMSDecryptReachabilityDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSKMSDecryptReachabilityInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSKMSDecryptReachabilityInventoryStatus;
  fixture_state: AWSKMSDecryptReachabilityFixtureState;
  confidence: number;
  key_count: number;
  customer_managed_key_count: number;
  aws_managed_key_count: number;
  public_key_count: number;
  cross_account_key_count: number;
  restricted_key_count: number;
  keys_with_rotation_count: number;
  keys_missing_rotation_count: number;
  keys_pending_deletion_count: number;
  multi_region_key_count: number;
  identity_grant_count: number;
  public_grant_count: number;
  cross_account_grant_count: number;
  deny_grant_count: number;
  live_grant_count: number;
  cross_account_live_grant_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSKMSCoverageGap[];
  records: AWSKMSDecryptReachabilityRecord[];
  relationships: AWSKMSDecryptReachabilityEdge[];
  diagnostics: AWSKMSDecryptReachabilityDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSSQSSNSReachabilityInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSSQSSNSReachabilityFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSSQSSNSCoverageGap = {
  capability: string;
  status: 'unsupported';
  reason: string;
  remediation?: string;
};

export type AWSSQSSNSIdentityGrant = {
  principal_arn?: string;
  principal_type?: string;
  effect: 'Allow' | 'Deny';
  actions?: string[];
  not_action?: boolean;
  capabilities?: string[];
  condition_keys?: string[];
  is_public?: boolean;
  is_cross_account?: boolean;
  has_condition?: boolean;
  statement_sid?: string;
  wildcard_principal?: boolean;
};

export type AWSSNSTopicSubscription = {
  subscription_arn?: string;
  protocol?: string;
  owner_account_id?: string;
  endpoint_resource_arn?: string;
  endpoint_present?: boolean;
  endpoint_redacted?: boolean;
  pending_confirmation?: boolean;
  raw_message_delivery?: boolean;
  filter_policy_present?: boolean;
  dlq_arn?: string;
};

export type AWSSQSSNSReachabilityRecord = {
  account_id: string;
  region: string;
  service: 'sqs' | 'sns';
  resource_arn: string;
  resource_name: string;
  resource_type: 'sqs_queue' | 'sns_topic';
  resource_url?: string;
  queue_url?: string;
  topic_arn?: string;
  owner_account_id?: string;
  created_at?: string;
  last_modified_at?: string;
  fifo: boolean;
  content_based_deduplication: boolean;
  sqs_managed_sse: boolean;
  kms_key_id?: string;
  visibility_timeout_seconds?: number;
  message_retention_seconds?: number;
  dlq_arns?: string[];
  subscription_count?: number;
  subscriptions?: AWSSNSTopicSubscription[];
  has_resource_policy: boolean;
  resource_policy_statement_count: number;
  resource_policy_source?: string;
  identity_grants?: AWSSQSSNSIdentityGrant[];
  exposure_classification:
    | 'public'
    | 'cross_account'
    | 'restricted'
    | 'private_with_grants'
    | 'private'
    | 'unknown';
  exposure_reasons?: string[];
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  relationship_type: 'can_access';
  confidence: number;
  collected_at: string;
  status: 'ready' | 'degraded';
};

export type AWSSQSSNSReachabilityRelationship = {
  type: 'can_access';
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  effect: 'Allow';
  principal_type: string;
  capabilities?: string[];
  has_condition?: boolean;
};

export type AWSSQSSNSReachabilityDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSSQSSNSReachabilityInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSSQSSNSReachabilityInventoryStatus;
  fixture_state: AWSSQSSNSReachabilityFixtureState;
  confidence: number;
  resource_count: number;
  queue_count: number;
  topic_count: number;
  public_resource_count: number;
  cross_account_resource_count: number;
  restricted_resource_count: number;
  encrypted_resource_count: number;
  dlq_resource_count: number;
  subscription_count: number;
  identity_grant_count: number;
  public_grant_count: number;
  cross_account_grant_count: number;
  deny_grant_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSSQSSNSCoverageGap[];
  records: AWSSQSSNSReachabilityRecord[];
  relationships: AWSSQSSNSReachabilityRelationship[];
  diagnostics: AWSSQSSNSReachabilityDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSDynamoDBRDSReachabilityInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSDynamoDBRDSReachabilityFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSDynamoDBRDSCoverageGap = {
  capability: string;
  status: 'unsupported' | 'partial';
  reason: string;
  remediation?: string;
};

export type AWSDynamoDBRDSIdentityGrant = {
  principal_arn?: string;
  principal_type?: string;
  effect: 'Allow' | 'Deny';
  actions?: string[];
  not_action?: boolean;
  capabilities?: string[];
  condition_keys?: string[];
  is_public?: boolean;
  is_cross_account?: boolean;
  has_condition?: boolean;
  statement_sid?: string;
  wildcard_principal?: boolean;
};

export type AWSDynamoDBRDSReachabilityRecord = {
  account_id: string;
  region: string;
  service: 'dynamodb' | 'rds';
  resource_arn: string;
  resource_name: string;
  resource_type: 'dynamodb_table' | 'dynamodb_stream' | 'rds_instance' | 'rds_cluster' | 'rds_proxy';
  resource_id?: string;
  engine?: string;
  engine_version?: string;
  resource_status?: string;
  endpoint?: string;
  kms_key_id?: string;
  storage_encrypted: boolean;
  iam_database_authentication_enabled: boolean;
  publicly_accessible: boolean;
  deletion_protection_enabled: boolean;
  performance_insights_enabled: boolean;
  stream_enabled: boolean;
  stream_arn?: string;
  billing_mode?: string;
  associated_role_arns?: string[];
  identity_grants?: AWSDynamoDBRDSIdentityGrant[];
  has_resource_policy: boolean;
  resource_policy_statement_count: number;
  resource_policy_source?: string;
  exposure_classification: 'public' | 'cross_account' | 'private_with_grants' | 'private' | 'unknown';
  exposure_reasons?: string[];
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  relationship_type: 'can_access';
  confidence: number;
  collected_at: string;
  status: 'ready' | 'degraded';
};

export type AWSDynamoDBRDSReachabilityRelationship = {
  type: 'can_access';
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  effect: 'Allow';
  principal_type: string;
  capabilities?: string[];
  has_condition?: boolean;
};

export type AWSDynamoDBRDSReachabilityDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSCredentialReferencesInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSCredentialReferencesFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSCredentialProvider =
  | 'openai'
  | 'anthropic'
  | 'bedrock'
  | 'github'
  | 'slack'
  | 'database'
  | 'webhook'
  | 'aws_secrets_manager'
  | 'aws_ssm'
  | 'generic';

export type AWSCredentialReferenceCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSCredentialReferenceRecord = {
  account_id: string;
  region: string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  resource_id?: string;
  resource_type: string;
  source_service: string;
  reference: string;
  reference_name?: string;
  reference_kind: 'secrets_manager' | 'ssm_parameter' | 'repository_credentials' | 'environment_variable';
  provider: AWSCredentialProvider;
  provider_confidence: number;
  sensitivity:
    | 'ai_provider_api_key'
    | 'source_control_token'
    | 'messaging_token'
    | 'database_credential'
    | 'webhook_url'
    | 'aws_managed_secret'
    | 'generic_secret';
  resolved: boolean;
  unresolved: boolean;
  target_node_id?: string;
  source: string;
  evidence_ref: string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSCredentialReferenceEdge = {
  type: 'uses_secret';
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  source: string;
  resolved: boolean;
  confidence: number;
};

export type AWSCredentialReferenceDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSCredentialReferencesInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSCredentialReferencesInventoryStatus;
  fixture_state: AWSCredentialReferencesFixtureState;
  confidence: number;
  reference_count: number;
  resolved_reference_count: number;
  unresolved_reference_count: number;
  external_provider_key_count: number;
  ai_provider_key_count: number;
  database_credential_count: number;
  distinct_workload_count: number;
  distinct_provider_count: number;
  relationship_count: number;
  provider_breakdown: Record<string, number>;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSCredentialReferenceCoverageGap[];
  records: AWSCredentialReferenceRecord[];
  relationships: AWSCredentialReferenceEdge[];
  diagnostics: AWSCredentialReferenceDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSCoveragePlanStatus = 'ready' | 'degraded' | 'blocked';
export type AWSCoveragePlanFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSCoveragePriority = 'critical' | 'high' | 'normal' | 'low';
export type AWSCoverageState =
  | 'planned'
  | 'pending'
  | 'in_progress'
  | 'covered'
  | 'partial'
  | 'failed'
  | 'permission_denied'
  | 'unsupported'
  | 'blocked'
  | 'disabled';

export type AWSCoveragePlanTarget = {
  key: string;
  account_id: string;
  account_name?: string;
  region: string;
  region_name?: string;
  service: string;
  service_name?: string;
  collector?: string;
  global: boolean;
  enabled: boolean;
  priority: AWSCoveragePriority;
  priority_rank: number;
  reason?: string;
  prerequisites: string[];
  state: AWSCoverageState;
  cursor?: string;
  failure_reason?: string;
  attempts?: number;
  resumable: boolean;
  next_action: string;
  evidence_ref: string;
  observed_at?: string;
};

export type AWSCoveragePlanSummary = {
  total_targets: number;
  enabled_targets: number;
  disabled_targets: number;
  account_count: number;
  region_count: number;
  service_count: number;
  outstanding_targets: number;
  covered_targets: number;
  blocked_targets: number;
  failed_targets: number;
  permission_denied_targets: number;
  resumable_targets: number;
  coverage_percent: number;
  state_counts: Record<string, number>;
  priority_counts: Record<string, number>;
  prerequisites: string[];
};

export type AWSCoveragePlanDiagnostic = {
  source: string;
  scope?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSPartialFailureReport = {
  key: string;
  account_id: string;
  region: string;
  service: string;
  collector?: string;
  state: AWSCoverageState;
  worker_state?: AWSCoverageState;
  reason_code: string;
  failure_reason?: string;
  retryable: boolean;
  attempts?: number;
  cursor?: string;
  evidence_ref: string;
  next_action: string;
  observed_at?: string;
};

export type AWSCoveragePlanCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSCoveragePlanResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSCoveragePlanStatus;
  fixture_state?: AWSCoveragePlanFixtureState;
  confidence: number;
  filtered_targets: number;
  summary: AWSCoveragePlanSummary;
  targets: AWSCoveragePlanTarget[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  partial_failure_reports: AWSPartialFailureReport[];
  coverage_gaps: AWSCoveragePlanCoverageGap[];
  diagnostics: AWSCoveragePlanDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSAccountRegionCoverageStatus = 'covered' | 'missing' | 'degraded' | 'unreachable' | 'suspended' | 'disabled' | 'stale' | 'permission_denied';

export type AWSAccountRegionCoverageRecord = {
  key: string;
  account_id: string;
  account_name?: string;
  region: string;
  region_name?: string;
  service: string;
  service_name?: string;
  collector?: string;
  global: boolean;
  enabled: boolean;
  state: AWSCoverageState;
  coverage_status: AWSAccountRegionCoverageStatus;
  cursor?: string;
  checkpoint?: string;
  attempts?: number;
  failure_reason?: string;
  retryable: boolean;
  stale: boolean;
  evidence_ref: string;
  next_action: string;
  observed_at?: string;
  updated_at: string;
};

export type AWSAccountRegionCoverageSummary = {
  total_records: number;
  filtered_records: number;
  account_count: number;
  region_count: number;
  service_count: number;
  covered_records: number;
  missing_records: number;
  degraded_records: number;
  unreachable_records: number;
  suspended_records: number;
  disabled_records: number;
  stale_records: number;
  permission_denied_records: number;
  retryable_records: number;
  status_counts: Record<string, number>;
  state_counts: Record<string, number>;
  collector_counts: Record<string, number>;
};

export type AWSAccountRegionCoverageResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSCoveragePlanStatus;
  fixture_state?: AWSCoveragePlanFixtureState;
  confidence: number;
  summary: AWSAccountRegionCoverageSummary;
  records: AWSAccountRegionCoverageRecord[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSCoveragePlanCoverageGap[];
  diagnostics: AWSCoveragePlanDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSFanOutExecutionTarget = {
  key: string;
  account_id: string;
  region: string;
  service: string;
  collector?: string;
  priority: AWSCoveragePriority;
  state: AWSCoverageState;
  worker_state: AWSCoverageState;
  enabled: boolean;
  attempts: number;
  max_attempts: number;
  concurrency_slot?: number;
  checkpoint?: string;
  retryable: boolean;
  throttled: boolean;
  retry_after?: string;
  failure_reason?: string;
  evidence_ref: string;
  next_action: string;
  observed_at?: string;
};

export type AWSFanOutExecutionSummary = {
  total_targets: number;
  executable_targets: number;
  skipped_targets: number;
  queued_targets: number;
  in_progress_targets: number;
  covered_targets: number;
  partial_targets: number;
  failed_targets: number;
  permission_denied_targets: number;
  throttled_targets: number;
  retryable_targets: number;
  concurrency_limit: number;
  max_attempts: number;
};

export type AWSFanOutExecutionResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSCoveragePlanStatus;
  fixture_state?: AWSCoveragePlanFixtureState;
  confidence: number;
  filtered_targets: number;
  summary: AWSFanOutExecutionSummary;
  targets: AWSFanOutExecutionTarget[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  partial_failure_reports: AWSPartialFailureReport[];
  coverage_gaps: AWSCoveragePlanCoverageGap[];
  diagnostics: AWSCoveragePlanDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSOrganizationsTopologyStatus = AWSCoveragePlanStatus;
export type AWSOrganizationsTopologyFixtureState = AWSCoveragePlanFixtureState;
export type AWSOrganizationsAccountStatus = 'active' | 'suspended' | 'closed' | 'pending_activation' | 'pending_closure';

export type AWSOrganizationsTopologyAccount = {
  account_id: string;
  account_name?: string;
  status: AWSOrganizationsAccountStatus;
  parent_id?: string;
  ou_path?: string;
  partition: string;
  management: boolean;
  delegated_admin_services: string[];
  connector_scoped: boolean;
  scan_eligible: boolean;
  state: AWSCoverageState;
  cursor?: string;
  failure_reason?: string;
  attempts?: number;
  resumable: boolean;
  next_action: string;
  evidence_ref: string;
  observed_at?: string;
  eligibility_failure_reason?: string;
};

export type AWSOrganizationsTopologyOU = {
  id: string;
  name?: string;
  parent_id?: string;
  path: string;
  enabled: boolean;
  reason?: string;
};

export type AWSOrganizationsTopologyRelationship = {
  parent_id: string;
  child_id: string;
  child_type: 'organizational_unit' | 'account';
  relationship: string;
};

export type AWSOrganizationsTopologySummary = {
  account_count: number;
  organizational_unit_count: number;
  management_account_count: number;
  delegated_admin_account_count: number;
  suspended_account_count: number;
  connector_scoped_accounts: number;
  scan_eligible_accounts: number;
  blocked_accounts: number;
  permission_denied_accounts: number;
  failed_accounts: number;
  resumable_accounts: number;
  state_counts: Record<string, number>;
  status_counts: Record<string, number>;
};

export type AWSOrganizationsTopologyDiagnostic = AWSCoveragePlanDiagnostic;

export type AWSOrganizationsTopologyCoverageGap = AWSCoveragePlanCoverageGap;

export type AWSOrganizationsTopologyResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  organization_id?: string;
  management_account_id?: string;
  partition: string;
  version: string;
  status: AWSOrganizationsTopologyStatus;
  fixture_state: AWSOrganizationsTopologyFixtureState;
  confidence: number;
  filtered_accounts: number;
  summary: AWSOrganizationsTopologySummary;
  organizational_units: AWSOrganizationsTopologyOU[];
  accounts: AWSOrganizationsTopologyAccount[];
  relationships: AWSOrganizationsTopologyRelationship[];
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSOrganizationsTopologyCoverageGap[];
  diagnostics: AWSOrganizationsTopologyDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSStackSetOnboardingStatus = 'ready' | 'degraded' | 'blocked' | 'permission_denied' | 'partial_failure';
export type AWSStackSetOnboardingFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSStackSetDeploymentMode = 'service_managed' | 'self_managed';
export type AWSStackSetOnboardingValidationStatus = 'ready' | 'degraded' | 'blocked' | 'permission_denied';
export type AWSStackSetOnboardingState =
  | 'pending'
  | 'validating'
  | 'blocked'
  | 'deploying'
  | 'active'
  | 'degraded'
  | 'failed'
  | 'permission_denied'
  | 'unsupported'
  | 'suspended'
  | 'canceled';
export type AWSStackSetOnboardingPrerequisiteSeverity = 'blocking' | 'advisory';

export type AWSStackSetOnboardingPrerequisite = {
  id: string;
  title: string;
  severity: AWSStackSetOnboardingPrerequisiteSeverity;
  satisfied: boolean;
  reason: string;
  remediation?: string;
};

export type AWSStackSetOnboardingPermissionPreviewItem = {
  service: string;
  actions: string[];
  resources: string[];
  reason: string;
};

export type AWSStackSetOnboardingPermissionPreview = {
  capability: string;
  tier: string;
  available: boolean;
  summary: string;
  permissions: AWSStackSetOnboardingPermissionPreviewItem[];
};

export type AWSStackSetOnboardingValidation = {
  status: AWSStackSetOnboardingValidationStatus;
  confidence: number;
  blocking_count: number;
  advisory_count: number;
  prerequisites: AWSStackSetOnboardingPrerequisite[];
  failure_reasons: string[];
  remediation_hints: string[];
};

export type AWSStackSetOnboardingTargetAccount = {
  account_id: string;
  name?: string;
  ou_path?: string;
  management?: boolean;
  suspended?: boolean;
};

export type AWSStackSetOnboardingTargetRegion = {
  region: string;
  name?: string;
  opt_in?: boolean;
};

export type AWSStackSetOnboardingOU = {
  id: string;
  name?: string;
  parent_id?: string;
  path?: string;
  enabled: boolean;
  reason?: string;
};

export type AWSStackSetOnboardingTargets = {
  organization_id?: string;
  organizational_units: AWSStackSetOnboardingOU[];
  accounts: AWSStackSetOnboardingTargetAccount[];
  regions: AWSStackSetOnboardingTargetRegion[];
};

export type AWSStackSetOnboardingInstance = {
  key: string;
  account_id: string;
  account_name?: string;
  ou_path?: string;
  region: string;
  region_name?: string;
  state: AWSStackSetOnboardingState;
  stack_id?: string;
  operation_id?: string;
  failure_reason?: string;
  attempts?: number;
  resumable: boolean;
  suspended?: boolean;
  opt_in_region?: boolean;
  next_action: string;
  coverage_targets: number;
  evidence_ref: string;
  observed_at?: string;
};

export type AWSStackSetOnboardingCoverageExpectation = {
  expected_accounts: number;
  expected_regions: number;
  expected_instances: number;
  expected_coverage_targets: number;
  coverage_percent: number;
  global_service_notes: string;
};

export type AWSStackSetOnboardingRecoveryAction = {
  id: string;
  title: string;
  description: string;
  targets: string[];
};

export type AWSStackSetOnboardingSummary = {
  target_accounts: number;
  target_regions: number;
  total_instances: number;
  pending_instances: number;
  active_instances: number;
  blocked_instances: number;
  failed_instances: number;
  degraded_instances: number;
  suspended_instances: number;
  permission_denied_instances: number;
  unsupported_instances: number;
  resumable_instances: number;
  deployed_percent: number;
  state_counts: Record<string, number>;
};

export type AWSStackSetOnboardingDiagnostic = {
  source: string;
  scope?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSStackSetOnboardingCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSStackSetOnboardingResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  organization_id?: string;
  management_account_id?: string;
  stack_set_name: string;
  template_url?: string;
  template_checksum?: string;
  launch_url?: string;
  deployment_mode: AWSStackSetDeploymentMode;
  partition: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSStackSetOnboardingStatus;
  fixture_state: AWSStackSetOnboardingFixtureState;
  confidence: number;
  validation: AWSStackSetOnboardingValidation;
  permission_preview: AWSStackSetOnboardingPermissionPreview[];
  targets: AWSStackSetOnboardingTargets;
  instances: AWSStackSetOnboardingInstance[];
  coverage_expectation: AWSStackSetOnboardingCoverageExpectation;
  recovery_actions: AWSStackSetOnboardingRecoveryAction[];
  summary: AWSStackSetOnboardingSummary;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSStackSetOnboardingCoverageGap[];
  diagnostics: AWSStackSetOnboardingDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSDynamoDBRDSReachabilityInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSDynamoDBRDSReachabilityInventoryStatus;
  fixture_state: AWSDynamoDBRDSReachabilityFixtureState;
  confidence: number;
  resource_count: number;
  dynamodb_table_count: number;
  dynamodb_stream_count: number;
  rds_instance_count: number;
  rds_cluster_count: number;
  rds_proxy_count: number;
  public_resource_count: number;
  cross_account_resource_count: number;
  encrypted_resource_count: number;
  iam_auth_resource_count: number;
  identity_grant_count: number;
  associated_role_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSDynamoDBRDSCoverageGap[];
  records: AWSDynamoDBRDSReachabilityRecord[];
  relationships: AWSDynamoDBRDSReachabilityRelationship[];
  diagnostics: AWSDynamoDBRDSReachabilityDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSSecretsManagerMetadataInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSSecretsManagerMetadataFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSSecretsManagerCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSSecretsManagerIdentityGrant = {
  principal_arn?: string;
  principal_type?: string;
  effect: string;
  actions?: string[];
  condition_keys?: string[];
  is_public?: boolean;
  is_cross_account?: boolean;
  has_condition?: boolean;
  statement_sid?: string;
  wildcard_principal?: boolean;
};

export type AWSSecretsManagerVersionStage = {
  version_id?: string;
  stages?: string[];
  created_at?: string;
  last_accessed_at?: string;
  kms_key_ids?: string[];
};

export type AWSSecretsManagerReplicaRegion = {
  region?: string;
  kms_key_id?: string;
  status?: string;
  status_message?: string;
  last_accessed_at?: string;
};

export type AWSSecretsManagerWorkloadReference = {
  source_service?: string;
  workload_id?: string;
  workload_type?: string;
  workload_name?: string;
  resource_arn?: string;
  resource_id?: string;
  reference: string;
  reference_kind: string;
  confidence: number;
};

export type AWSSecretsManagerMetadataRecord = {
  account_id: string;
  region: string;
  service: 'secretsmanager';
  secret_arn: string;
  secret_name: string;
  description_present: boolean;
  sensitive: boolean;
  sensitivity_classification: string;
  sensitivity_classification_source: string;
  sensitivity_classification_override?: string;
  kms_key_id?: string;
  kms_key_arn?: string;
  owning_service?: string;
  primary_region?: string;
  secret_status: string;
  rotation_enabled: boolean;
  rotation_lambda_arn?: string;
  rotation_interval_days?: number;
  created_at?: string;
  last_changed_at?: string;
  last_accessed_at?: string;
  last_rotated_at?: string;
  deleted_at?: string;
  has_resource_policy: boolean;
  resource_policy_statement_count: number;
  identity_grants?: AWSSecretsManagerIdentityGrant[];
  version_stages?: AWSSecretsManagerVersionStage[];
  replica_regions?: AWSSecretsManagerReplicaRegion[];
  tags?: Record<string, string>;
  exposure_classification: string;
  exposure_reasons?: string[];
  referenced_by?: AWSSecretsManagerWorkloadReference[];
  unresolved_references?: AWSSecretsManagerWorkloadReference[];
  source: string;
  evidence_ref: string;
  from_node_id: string;
  relationship_type: string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSSecretsManagerReferenceEdge = {
  type: 'uses_secret';
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  source: string;
  confidence: number;
};

export type AWSSecretsManagerMetadataDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSSecretsManagerMetadataInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSSecretsManagerMetadataInventoryStatus;
  fixture_state: AWSSecretsManagerMetadataFixtureState;
  confidence: number;
  secret_count: number;
  referenced_secret_count: number;
  unreferenced_secret_count: number;
  rotation_enabled_count: number;
  missing_rotation_count: number;
  resource_policy_count: number;
  public_secret_count: number;
  cross_account_secret_count: number;
  kms_referenced_count: number;
  relationship_count: number;
  unresolved_reference_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSSecretsManagerCoverageGap[];
  records: AWSSecretsManagerMetadataRecord[];
  relationships: AWSSecretsManagerReferenceEdge[];
  diagnostics: AWSSecretsManagerMetadataDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSSSMParameterMetadataInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSSSMParameterMetadataFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';
export type AWSSSMParameterTypeFilter = 'string' | 'string_list' | 'secure_string';

export type AWSSSMParameterCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSSSMParameterPolicy = {
  policy_type?: string;
  policy_status?: string;
  expires_at?: string;
};

export type AWSSSMParameterWorkloadReference = {
  source_service?: string;
  workload_id?: string;
  workload_type?: string;
  workload_name?: string;
  resource_arn?: string;
  resource_id?: string;
  reference: string;
  reference_kind: string;
  confidence: number;
};

export type AWSSSMParameterMetadataRecord = {
  account_id: string;
  region: string;
  service: 'ssm';
  parameter_arn: string;
  parameter_name: string;
  parameter_path?: string;
  path_depth?: number;
  parameter_type: string;
  tier: string;
  data_type?: string;
  version?: number;
  description_present: boolean;
  allowed_pattern_present: boolean;
  kms_key_id?: string;
  kms_key_arn?: string;
  last_modified_at?: string;
  last_modified_by?: string;
  parameter_policies?: AWSSSMParameterPolicy[];
  tags?: Record<string, string>;
  sensitive: boolean;
  sensitivity_classification: string;
  exposure_classification: string;
  exposure_reasons?: string[];
  referenced_by?: AWSSSMParameterWorkloadReference[];
  unresolved_references?: AWSSSMParameterWorkloadReference[];
  source: string;
  evidence_ref: string;
  from_node_id: string;
  relationship_type: string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSSSMParameterReferenceEdge = {
  type: 'uses_secret';
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  source: string;
  confidence: number;
};

export type AWSSSMParameterMetadataDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSSSMParameterMetadataInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSSSMParameterMetadataInventoryStatus;
  fixture_state: AWSSSMParameterMetadataFixtureState;
  confidence: number;
  parameter_count: number;
  secure_string_count: number;
  customer_kms_count: number;
  referenced_parameter_count: number;
  unreferenced_parameter_count: number;
  plain_text_referenced_count: number;
  expiring_parameter_count: number;
  advanced_tier_count: number;
  relationship_count: number;
  unresolved_reference_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSSSMParameterCoverageGap[];
  records: AWSSSMParameterMetadataRecord[];
  relationships: AWSSSMParameterReferenceEdge[];
  diagnostics: AWSSSMParameterMetadataDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSECRRepositoryMetadataInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSECRRepositoryMetadataFixtureState =
  | 'success'
  | 'empty'
  | 'degraded'
  | 'partial_failure'
  | 'permission_denied';

export type AWSECRRepositoryCoverageGap = {
  capability: string;
  status: string;
  reason: string;
  remediation?: string;
};

export type AWSECRImageWorkloadReference = {
  source_service?: string;
  workload_id?: string;
  workload_type?: string;
  workload_name?: string;
  resource_arn?: string;
  resource_id?: string;
  image_uri: string;
  reference_kind: string;
  confidence: number;
};

export type AWSECRRepositoryMetadataRecord = {
  account_id: string;
  region: string;
  service: 'ecr';
  repository_arn: string;
  repository_name: string;
  registry_id?: string;
  repository_uri: string;
  image_tag_mutability: string;
  encryption_type?: string;
  kms_key_id?: string;
  scan_on_push: boolean;
  enhanced_scanning_known: boolean;
  enhanced_scanning_enabled: boolean;
  has_repository_policy: boolean;
  repository_policy_statement_count: number;
  has_lifecycle_policy: boolean;
  lifecycle_rule_count: number;
  image_count: number;
  tagged_image_count: number;
  untagged_image_count: number;
  last_pushed_at?: string;
  created_at?: string;
  tags?: Record<string, string>;
  sensitivity_classification: string;
  exposure_classification: string;
  exposure_reasons?: string[];
  referenced_by?: AWSECRImageWorkloadReference[];
  unresolved_references?: AWSECRImageWorkloadReference[];
  source: string;
  evidence_ref: string;
  from_node_id: string;
  relationship_type: string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSECRRepositoryReferenceEdge = {
  type: 'uses_image';
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  source: string;
  confidence: number;
};

export type AWSECRRepositoryMetadataDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSECRRepositoryMetadataInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSECRRepositoryMetadataInventoryStatus;
  fixture_state: AWSECRRepositoryMetadataFixtureState;
  confidence: number;
  repository_count: number;
  referenced_repository_count: number;
  unreferenced_repository_count: number;
  mutable_repository_count: number;
  unscanned_repository_count: number;
  repository_policy_count: number;
  lifecycle_policy_count: number;
  relationship_count: number;
  unresolved_reference_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  coverage_gaps: AWSECRRepositoryCoverageGap[];
  records: AWSECRRepositoryMetadataRecord[];
  relationships: AWSECRRepositoryReferenceEdge[];
  diagnostics: AWSECRRepositoryMetadataDiagnostic[];
  generated_at: string;
  updated_at: string;
};

export type AWSEKSWorkloadIdentityInventoryStatus = 'ready' | 'degraded' | 'blocked';
export type AWSEKSWorkloadIdentityFixtureState = 'success' | 'empty' | 'degraded' | 'partial_failure' | 'permission_denied';

export type AWSEKSWorkloadIdentityRecord = {
  account_id: string;
  region: string;
  service: string;
  workload_id: string;
  workload_type: string;
  workload_name: string;
  role_kind: 'irsa' | 'pod_identity' | 'node_role' | 'fargate_pod_execution_role' | string;
  role_arn?: string;
  role_name?: string;
  cluster_arn?: string;
  cluster_name?: string;
  cluster_status?: string;
  kubernetes_version?: string;
  oidc_issuer?: string;
  oidc_provider_arn?: string;
  namespace?: string;
  service_account?: string;
  kubernetes_subject?: string;
  association_arn?: string;
  association_id?: string;
  association_owner_arn?: string;
  external_id?: string;
  disable_session_tags?: boolean;
  target_role_arn?: string;
  nodegroup_arn?: string;
  nodegroup_name?: string;
  nodegroup_status?: string;
  node_role_arn?: string;
  fargate_profile_arn?: string;
  fargate_profile_name?: string;
  fargate_profile_status?: string;
  pod_execution_role_arn?: string;
  selector_namespaces?: string[];
  selector_labels?: string[];
  subnet_ids?: string[];
  kubernetes_access_status?: string;
  irsa_annotation_keys?: string[];
  tags?: Record<string, string>;
  source: string;
  evidence_ref: string;
  from_node_id: string;
  to_node_id?: string;
  relationship_type: 'runs_as' | 'attached_to' | string;
  confidence: number;
  collected_at: string;
  status: string;
};

export type AWSEKSWorkloadIdentityRelationship = {
  type: 'runs_as' | 'attached_to' | string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
};

export type AWSEKSWorkloadIdentityDiagnostic = {
  collector: string;
  source_id?: string;
  code: string;
  message: string;
  remediation?: string;
  retryable: boolean;
};

export type AWSEKSWorkloadIdentityInventoryResult = {
  tenant_id: string;
  workspace_id: string;
  project_id: string;
  connector_id?: string;
  account_id?: string;
  region?: string;
  parent_issue_number: number;
  parent_issue_ref: string;
  current_issue_number: number;
  current_issue_ref: string;
  version: string;
  status: AWSEKSWorkloadIdentityInventoryStatus;
  fixture_state: AWSEKSWorkloadIdentityFixtureState;
  confidence: number;
  record_count: number;
  cluster_count: number;
  oidc_provider_count: number;
  service_account_count: number;
  pod_identity_association_count: number;
  irsa_annotation_count: number;
  node_role_count: number;
  fargate_profile_count: number;
  identity_count: number;
  resource_count: number;
  relationship_count: number;
  failure_reasons: string[];
  remediation_hints: string[];
  evidence_links: string[];
  records: AWSEKSWorkloadIdentityRecord[];
  relationships: AWSEKSWorkloadIdentityRelationship[];
  diagnostics: AWSEKSWorkloadIdentityDiagnostic[];
  generated_at: string;
  updated_at: string;
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
  permission_tiers: AWSCapabilityPermissionTier[];
};

export type AWSConnectorValidateRequest = {
  workspace_id?: string;
  project_id?: string;
  role_arn: string;
  external_id?: string;
  region?: string;
  session_name?: string;
  capabilities?: ConnectorCapability[];
};

export type AWSConnectorPolicyResponse = {
  policy_hash: string;
  policy_document: Record<string, unknown>;
  permission_preview: AWSPermissionPreviewItem[];
  permission_tiers: AWSCapabilityPermissionTier[];
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
  connection_mode?: 'agent' | 'kubeconfig';
  agent_id?: string;
  permission_checks: KubernetesPermissionCheck[];
  diagnostics: KubernetesPreflightDiagnostic[];
  remediation_message?: string;
  created_at?: string;
  updated_at?: string;
  last_validated_at?: string;
  last_heartbeat_at?: string;
  enrollment_expires_at?: string;
};

export type KubernetesConnectionUpsertRequest = {
  connector_id?: string;
  display_name?: string;
  context?: string;
};

export type KubernetesConnectorStartRequest = {
  workspace_id?: string;
  project_id?: string;
  connector_id?: string;
  display_name?: string;
  api_url?: string;
};

export type KubernetesConnectorStartResponse = {
  connection: KubernetesConnectionStatus;
  enrollment_token: string;
  enrollment_expires_at: string;
  helm_command: string;
};

export type KubernetesConnectorKubeconfigRequest = {
  workspace_id?: string;
  project_id?: string;
  connector_id?: string;
  display_name?: string;
  kubeconfig: string;
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
  install_account_type?: 'any' | 'personal' | 'organization';
};

export type GitHubConnectorStartResponse = {
  connection: GitHubConnectionStatus;
  connector_id: string;
  state: string;
  install_url: string;
  install_account_type: 'any' | 'personal' | 'organization';
  webhook_url?: string;
  expires_at: string;
};

export type GitHubConnectorCompleteRequest = {
  state: string;
  installation_id: number;
  code: string;
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

export type GitHubRepositoryPostureState =
  | 'secure'
  | 'insecure'
  | 'unavailable'
  | 'permission_limited'
  | 'unsupported'
  | 'unknown';

export type GitHubRepositoryPostureCheck = {
  id: string;
  category: string;
  state: GitHubRepositoryPostureState;
  reason?: string;
  summary: string;
  evidence?: Record<string, unknown>;
};

export type GitHubRateLimitState = {
  limit?: number;
  remaining?: number;
  reset_at?: string;
};

export type GitHubRepositoryPosture = {
  repository: string;
  installation_id?: number;
  collected_at: string;
  checks: GitHubRepositoryPostureCheck[];
  rate_limit?: GitHubRateLimitState;
};

export type GitHubOrganizationPosture = {
  organization: string;
  installation_id?: number;
  collected_at: string;
  checks: GitHubRepositoryPostureCheck[];
  rate_limit?: GitHubRateLimitState;
};

export type GitHubRepositoryPostureResponse = {
  connector_id: string;
  provider: string;
  posture: GitHubRepositoryPosture;
  organization_posture?: GitHubOrganizationPosture;
};

export type GitHubConnectionCompleteRequest = {
  state: string;
  installation_id: number;
  code: string;
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

function isRequestAuthContext(value?: ScanRequest | RequestAuthContext): value is RequestAuthContext {
  return Boolean(
    value &&
      ('apiKey' in value || 'tenantID' in value || 'workspaceID' in value || 'bearerToken' in value)
  );
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
  code?: string;
  detail?: string;
  payload?: unknown;

  constructor(message: string, status: number, options: { code?: string; detail?: string; payload?: unknown } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = options.code;
    this.detail = options.detail;
    this.payload = options.payload;
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
    let code: string | undefined;
    let detail: string | undefined;
    let payload: unknown;
    try {
      payload = await res.json();
      const errorPayload = payload as {
        error?: string;
        error_code?: string;
        error_detail?: string;
        code?: string;
      };
      if (errorPayload?.error) {
        message = errorPayload.error;
      }
      code = errorPayload?.error_code ?? errorPayload?.code;
      detail = errorPayload?.error_detail;
    } catch {
      // Keep status-based message when server does not return a JSON error body.
    }
    if (res.status === 401 && redirectOnUnauthorized) {
      redirectToSignInForUnauthorized();
    }
    throw new ApiError(message, res.status, { code, detail, payload });
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
  updateMe(payload: CurrentUserProfileUpdate) {
    return request<{ me: CurrentUserContext }>('/v1/me', undefined, {
      method: 'PATCH',
      body: JSON.stringify(payload)
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
  deactivateCurrentUser() {
    return request<{ status: 'deactivated' }>('/v1/me/deactivate', undefined, {
      method: 'POST'
    });
  },
  reactivateCurrentUser() {
    return request<{ status: 'active' }>('/v1/me/reactivate', undefined, {
      method: 'POST'
    });
  },
  deleteMe() {
    return request<DeleteCurrentUserResponse>('/v1/me', undefined, {
      method: 'DELETE'
    });
  },
  cancelCurrentUserDeletion() {
    return request<CancelCurrentUserDeletionResponse>('/v1/me/cancel-deletion', undefined, {
      method: 'POST',
      redirectOnUnauthorized: false
    });
  },
  enqueueDataExport(init: RequestInit = {}) {
    return request<DataExportJob>('/v1/me/export', undefined, {
      ...init,
      method: 'POST'
    });
  },
  getDataExport(jobID: string, init: RequestInit = {}) {
    return request<DataExportJob>(`/v1/me/export/${encodeURIComponent(jobID)}`, undefined, init);
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
  getWorkOSMFAPending() {
    return request<WorkOSMFAPendingResponse>('/auth/mfa/pending', undefined, {
      redirectOnUnauthorized: false
    });
  },
  enrollWorkOSMFA() {
    return request<WorkOSMFAPendingResponse>('/auth/mfa/enroll', undefined, {
      method: 'POST',
      redirectOnUnauthorized: false
    });
  },
  challengeWorkOSMFA(factorID: string) {
    return request<WorkOSMFAChallengeResponse>('/auth/mfa/challenge', undefined, {
      method: 'POST',
      body: JSON.stringify({ factor_id: factorID }),
      redirectOnUnauthorized: false
    });
  },
  verifyWorkOSMFA(code: string) {
    return request<WorkOSMFAVerifyResponse>('/auth/mfa/verify', undefined, {
      method: 'POST',
      body: JSON.stringify({ code }),
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
  suspendWorkspace(workspaceID: string, auth?: RequestAuthContext) {
    return request<WorkspaceSuspendResponse>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/suspend`,
      auth,
      { method: 'POST' }
    );
  },
  reactivateWorkspace(workspaceID: string, auth?: RequestAuthContext) {
    return request<WorkspaceReactivateResponse>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/reactivate`,
      auth,
      { method: 'POST' }
    );
  },
  deleteWorkspace(workspaceID: string, auth?: RequestAuthContext) {
    return request<WorkspaceDeleteResponse>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}`,
      auth,
      { method: 'DELETE' }
    );
  },
  cancelWorkspaceDeletion(workspaceID: string, auth?: RequestAuthContext) {
    return request<WorkspaceCancelDeletionResponse>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/cancel-deletion`,
      auth,
      { method: 'POST' }
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
  getRepoFindingsTrends(
    filters: { points?: number; severity?: string; type?: string } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: TrendPoint[] }>(`/v1/repo-findings/trends${buildQuery(filters)}`, auth);
  },
  getExecutiveReport(options?: { domain?: ExecutiveReportDomain }, auth?: RequestAuthContext) {
    const domain = options?.domain ?? '';
    const suffix = domain ? `?domain=${encodeURIComponent(domain)}` : '';
    return request<ExecutiveReport>(`/v1/enterprise/reports/executive${suffix}`, auth);
  },
  listScans(auth?: RequestAuthContext) {
    return request<{ items: ScanRecord[] }>('/v1/scans?sort_by=started_at&sort_order=desc', auth);
  },
  startScan(payloadOrAuth?: ScanRequest | RequestAuthContext, maybeAuth?: RequestAuthContext) {
    // A second argument means the first is unambiguously the scan payload. With a single
    // argument, treat it as auth only when it carries auth fields, so an empty or
    // conditionally-built payload (e.g. startScan({}, auth)) does not swallow the auth context.
    const firstIsPayload = maybeAuth !== undefined || !isRequestAuthContext(payloadOrAuth);
    const payload = firstIsPayload ? (payloadOrAuth as ScanRequest | undefined) : undefined;
    const auth = firstIsPayload ? maybeAuth : (payloadOrAuth as RequestAuthContext | undefined);
    return request<{ scan: ScanRecord }>('/v1/scans', auth, {
      method: 'POST',
      body: payload && (payload.project_id || payload.connector_id) ? JSON.stringify(payload) : undefined
    });
  },
  startOnboarding(auth?: RequestAuthContext) {
    return request<OnboardingStateResponse>('/v1/onboarding/start', auth, {
      method: 'POST'
    });
  },
  getOnboardingState(auth?: RequestAuthContext) {
    return request<OnboardingStateResponse>('/v1/onboarding/state', auth);
  },
  updateOnboardingState(payload: OnboardingStateUpdateRequest, auth?: RequestAuthContext) {
    return request<OnboardingStateResponse>('/v1/onboarding/state', auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  completeOnboarding(auth?: RequestAuthContext) {
    return request<OnboardingStateResponse>('/v1/onboarding/complete', auth, {
      method: 'POST'
    });
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
  runRepoScan(payload: RepoScanRequest, auth?: RequestAuthContext) {
    return request<{ repo_scan: RepoScanRecord }>('/v1/repo-scans', auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  cancelRepoScan(repoScanID: string, auth?: RequestAuthContext) {
    return request<{ repo_scan: RepoScanRecord }>(`/v1/repo-scans/${encodeURIComponent(repoScanID)}/cancel`, auth, {
      method: 'POST'
    });
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
      repository?: string;
      severity?: string;
      type?: string;
      source?: string;
      repo_lifecycle_status?: RepoFindingLifecycleStatus;
      detector?: string;
      owner?: string;
      confidence?: number;
      min_confidence?: number;
      age_days?: number;
      min_age_days?: number;
      lifecycle_status?: FindingLifecycleStatus;
      assignee?: string;
      sort_by?: string;
      sort_order?: 'asc' | 'desc';
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: Finding[]; summary?: RepoFindingsSummary; next_cursor?: string }>(
      `/v1/repo-findings${buildQuery({ sort_by: 'created_at', sort_order: 'desc', ...filters })}`,
      auth
    );
  },
  getRepoRiskGraph(
    filters: {
      repo_scan_id?: string;
      repository?: string;
      default_branch?: string;
      severity?: string;
      type?: string;
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<RepoRiskGraph>(`/v1/repo-risk-graph${buildQuery(filters)}`, auth);
  },
  previewRepoFindingRemediation(
    findingID: string,
    payload: RepoFindingRemediationPreviewRequest = {},
    auth?: RequestAuthContext
  ) {
    const query = buildQuery({ repo_scan_id: payload.repo_scan_id });
    return request<RepoFindingRemediationPreview>(
      `/v1/repo-findings/${encodeURIComponent(findingID)}/remediation/preview${query}`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
    );
  },
  publishRepoFindingRemediation(
    findingID: string,
    payload: RepoFindingRemediationPublishRequest,
    auth?: RequestAuthContext
  ) {
    const query = buildQuery({ repo_scan_id: payload.repo_scan_id });
    return request<RepoFindingRemediationPublishResponse>(
      `/v1/repo-findings/${encodeURIComponent(findingID)}/remediation/publish${query}`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
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
  getAWSProjectBaseline(workspaceID: string, projectID: string, connectorID?: string, auth?: RequestAuthContext) {
    return request<{ baseline: AWSPlatformBaselineResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/baseline${buildQuery({
        connector_id: connectorID
      })}`,
      auth
    );
  },
  getAWSProjectDependencyIndex(workspaceID: string, projectID: string, connectorID?: string, auth?: RequestAuthContext) {
    return request<{ index: AWSPlatformDependencyIndexResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/dependency-index${buildQuery({
        connector_id: connectorID
      })}`,
      auth
    );
  },
  getAWSProjectValidationHarness(workspaceID: string, projectID: string, connectorID?: string, auth?: RequestAuthContext) {
    return request<{ harness: AWSPlatformValidationHarnessResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/validation-harness${buildQuery({
        connector_id: connectorID
      })}`,
      auth
    );
  },
  getAWSProjectCollectorContract(workspaceID: string, projectID: string, connectorID?: string, auth?: RequestAuthContext) {
    return request<{ contract: AWSServiceCollectorContractResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/collector-contract${buildQuery({
        connector_id: connectorID
      })}`,
      auth
    );
  },
  getAWSProjectEC2InstanceProfiles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSEC2InstanceProfileFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSEC2InstanceProfileInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/ec2-instance-profiles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectECSTaskRoles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSECSTaskRoleFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSECSTaskRoleInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/ecs-task-roles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectLambdaExecutionRoles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSLambdaExecutionRoleFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSLambdaExecutionRoleInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/lambda-execution-roles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectCodeBuildServiceRoles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSCodeBuildServiceRoleFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSCodeBuildServiceRoleInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/codebuild-service-roles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectCodePipelineDeploymentRoles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSCodePipelineDeploymentRoleFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSCodePipelineDeploymentRoleInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/codepipeline-deployment-roles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectStepFunctionsStateMachineRoles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSStepFunctionsStateMachineRoleFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSStepFunctionsStateMachineRoleInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/stepfunctions-state-machine-roles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectEventDrivenRoles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSEventDrivenRoleFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSEventDrivenRoleInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/event-driven-roles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectManagedComputeRoles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSManagedComputeRoleFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSManagedComputeRoleInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/managed-compute-roles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectSageMakerWorkloadRoles(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSSageMakerWorkloadRoleFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSSageMakerWorkloadRoleInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/sagemaker-workload-roles${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectAIAgentIdentities(
    workspaceID: string,
    projectID: string,
    query?: AWSAIAgentIdentityQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSAIAgentIdentityInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/ai-agent-identities${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        agent_id: query?.agentID,
        provider: query?.provider,
        runtime: query?.runtime,
        tool: query?.tool,
        status: query?.status,
        risk: query?.risk,
        min_confidence: query?.minConfidence
      })}`,
      auth
    );
  },
  getAWSProjectBedrockAgents(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSBedrockAgentsFixtureState,
    filters?: { agentID?: string; identity?: string; provider?: AWSBedrockAgentsProvider },
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSBedrockAgentsInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/bedrock-agents${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        agent_id: filters?.agentID,
        identity: filters?.identity,
        provider: filters?.provider
      })}`,
      auth
    );
  },
  getAWSProjectRuntimeEvents(
    workspaceID: string,
    projectID: string,
    query?: AWSRuntimeEventQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ runtime: AWSRuntimeEventResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/runtime-events${buildQuery({
        connector_id: query?.connectorID,
        delivery_source: query?.deliverySource,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        event_type: query?.eventType,
        identity: query?.identity,
        agent_id: query?.agentID,
        resource: query?.resource,
        evidence: query?.evidence,
        owner: query?.owner,
        status: query?.status
      })}`,
      auth
    );
  },
  getAWSProjectSecretsKMSRuntimeAccess(
    workspaceID: string,
    projectID: string,
    query?: AWSSecretsKMSRuntimeAccessQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ correlation: AWSSecretsKMSRuntimeAccessResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/secrets-kms-runtime-access${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        delivery_source: query?.deliverySource,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        agent_id: query?.agentID,
        resource: query?.resource,
        resource_kind: query?.resourceKind,
        status: query?.status
      })}`,
      auth
    );
  },
  getAWSProjectS3RuntimeAccess(
    workspaceID: string,
    projectID: string,
    query?: AWSS3RuntimeAccessQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ correlation: AWSS3RuntimeAccessResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/s3-runtime-access${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        delivery_source: query?.deliverySource,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        agent_id: query?.agentID,
        resource: query?.resource,
        access_mode: query?.accessMode,
        sensitivity: query?.sensitivity,
        exposure: query?.exposure,
        status: query?.status
      })}`,
      auth
    );
  },
  getAWSProjectAgentRuntimeAccess(
    workspaceID: string,
    projectID: string,
    query?: AWSAgentRuntimeAccessQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ correlation: AWSAgentRuntimeAccessResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/agent-runtime-access${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        delivery_source: query?.deliverySource,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        agent_id: query?.agentID,
        tool: query?.tool,
        resource: query?.resource,
        outcome: query?.outcome,
        status: query?.status
      })}`,
      auth
    );
  },
  getAWSProjectAIAgentRisk(
    workspaceID: string,
    projectID: string,
    query?: AWSAIAgentRiskQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ findings: AWSAIAgentRiskResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/ai-agent-risk${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        agent_id: query?.agentID,
        risk_type: query?.riskType,
        severity: query?.severity,
        status: query?.status,
        evidence: query?.evidence,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectRemediationCases(
    workspaceID: string,
    projectID: string,
    query?: AWSRemediationCaseQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ cases: AWSRemediationCaseResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/remediation-cases${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        source_type: query?.sourceType,
        lifecycle: query?.lifecycle,
        severity: query?.severity,
        status: query?.status,
        approval_state: query?.approvalState,
        owner_assigned: query?.ownerAssigned,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectIAMPolicyDiffs(
    workspaceID: string,
    projectID: string,
    query?: AWSIAMPolicyDiffQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ diffs: AWSIAMPolicyDiffResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/iam-policy-diffs${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        service: query?.service,
        decision: query?.decision,
        severity: query?.severity,
        status: query?.status,
        breakage_level: query?.breakageLevel,
        ready_for_apply: query?.readyForApply,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectTrustPolicyHardeningPlans(
    workspaceID: string,
    projectID: string,
    query?: AWSTrustPolicyHardeningQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ plans: AWSTrustPolicyHardeningResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/trust-policy-hardening${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        service: query?.service,
        resource: query?.resource,
        principal: query?.principal,
        hardening_direction: query?.hardeningDirection,
        breakage_level: query?.breakageLevel,
        severity: query?.severity,
        status: query?.status,
        ready_for_apply: query?.readyForApply,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectPermissionBoundarySCPPlans(
    workspaceID: string,
    projectID: string,
    query?: AWSPermissionBoundarySCPQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ plans: AWSPermissionBoundarySCPResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/permission-boundary-scp${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        service: query?.service,
        kind: query?.kind,
        target_scope: query?.targetScope,
        severity: query?.severity,
        status: query?.status,
        breakage_level: query?.breakageLevel,
        ready_for_apply: query?.readyForApply,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectPermissionBoundaryExecutor(
    workspaceID: string,
    projectID: string,
    query?: AWSPermissionBoundaryExecutorQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ permission_boundary_executor: AWSPermissionBoundaryExecutorResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/permission-boundary-executor${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        dry_run_id: query?.dryRunID,
        case_id: query?.caseID,
        plan_id: query?.planID,
        operation: query?.operation,
        state: query?.state,
        severity: query?.severity,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectScpGuardrailExecutor(
    workspaceID: string,
    projectID: string,
    query?: AWSScpGuardrailExecutorQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ scp_guardrail_executor: AWSScpGuardrailExecutorResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/scp-guardrail-executor${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        dry_run_id: query?.dryRunID,
        case_id: query?.caseID,
        plan_id: query?.planID,
        operation: query?.operation,
        target_scope: query?.targetScope,
        state: query?.state,
        severity: query?.severity,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectSecretKeyRotationPlans(
    workspaceID: string,
    projectID: string,
    query?: AWSSecretKeyRotationQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ plans: AWSSecretKeyRotationResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/secret-key-rotation${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        rotation_type: query?.rotationType,
        provider: query?.provider,
        owner: query?.owner,
        severity: query?.severity,
        status: query?.status,
        ready_for_apply: query?.readyForApply,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectAccessKeyQuarantinePlans(
    workspaceID: string,
    projectID: string,
    query?: AWSAccessKeyQuarantineQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ plans: AWSAccessKeyQuarantineResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/access-key-quarantine${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        quarantine_state: query?.quarantineState,
        owner: query?.owner,
        severity: query?.severity,
        status: query?.status,
        ready_for_apply: query?.readyForApply,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectIaCRemediationPlans(
    workspaceID: string,
    projectID: string,
    query?: AWSIaCRemediationQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ plans: AWSIaCRemediationResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/iac-remediation-plans${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        iac_target: query?.iacTarget,
        change_kind: query?.changeKind,
        severity: query?.severity,
        status: query?.status,
        ready_for_apply: query?.readyForApply,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectRemediationApprovalQueue(
    workspaceID: string,
    projectID: string,
    query?: AWSRemediationApprovalQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ queue: AWSRemediationApprovalResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/remediation-approval-queue${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        case_id: query?.caseID,
        state: query?.state,
        risk_tier: query?.riskTier,
        scope_type: query?.scopeType,
        requestor: query?.requestor,
        approver_role: query?.approverRole,
        severity: query?.severity,
        ready_for_execution: query?.readyForExecution,
        kill_switch_engaged: query?.killSwitchEngaged,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectRemediationDryRun(
    workspaceID: string,
    projectID: string,
    query?: AWSRemediationDryRunQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ dry_run: AWSRemediationDryRunResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/remediation-dry-run${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        approval_id: query?.approvalID,
        case_id: query?.caseID,
        source_type: query?.sourceType,
        outcome: query?.outcome,
        risk_tier: query?.riskTier,
        severity: query?.severity,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectLowRiskLiveRemediation(
    workspaceID: string,
    projectID: string,
    query?: AWSLowRiskRemediationQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ low_risk_live_remediation: AWSLowRiskRemediationResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/low-risk-live-remediation${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        dry_run_id: query?.dryRunID,
        case_id: query?.caseID,
        action: query?.action,
        action_category: query?.actionCategory,
        state: query?.state,
        severity: query?.severity,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectTrustPolicyHardeningExecutor(
    workspaceID: string,
    projectID: string,
    query?: AWSTrustPolicyHardeningExecutorQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ trust_policy_hardening_executor: AWSTrustPolicyHardeningExecutorResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/trust-policy-hardening-executor${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        dry_run_id: query?.dryRunID,
        case_id: query?.caseID,
        plan_id: query?.planID,
        hardening_direction: query?.hardeningDirection,
        state: query?.state,
        severity: query?.severity,
        search: query?.search
      })}`,
      auth
    );
  },
  getAWSProjectBlastRadius(
    workspaceID: string,
    projectID: string,
    query?: AWSBlastRadiusQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ intelligence: AWSBlastRadiusResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/blast-radius${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        resource: query?.resource,
        severity: query?.severity,
        status: query?.status,
        risk_type: query?.riskType
      })}`,
      auth
    );
  },
  getAWSProjectLeastPrivilege(
    workspaceID: string,
    projectID: string,
    query?: AWSLeastPrivilegeQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ recommendations: AWSLeastPrivilegeResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/least-privilege${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        resource: query?.resource,
        service: query?.service,
        severity: query?.severity,
        status: query?.status,
        decision: query?.decision
      })}`,
      auth
    );
  },
  getAWSProjectUnusedDormantAccess(
    workspaceID: string,
    projectID: string,
    query?: AWSUnusedDormantAccessQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ findings: AWSUnusedDormantAccessResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/unused-dormant-access${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        resource: query?.resource,
        service: query?.service,
        severity: query?.severity,
        status: query?.status,
        dormancy_state: query?.dormancyState
      })}`,
      auth
    );
  },
  getAWSProjectIdentitySprawl(
    workspaceID: string,
    projectID: string,
    query?: AWSIdentitySprawlQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ findings: AWSIdentitySprawlResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/identity-sprawl${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        owner: query?.owner,
        cluster: query?.cluster,
        finding_type: query?.findingType,
        severity: query?.severity,
        status: query?.status
      })}`,
      auth
    );
  },
  getAWSProjectPrivilegeEscalation(
    workspaceID: string,
    projectID: string,
    query?: AWSPrivilegeEscalationQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ findings: AWSPrivilegeEscalationResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/privilege-escalation${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        target: query?.target,
        escalation_type: query?.escalationType,
        severity: query?.severity,
        status: query?.status
      })}`,
      auth
    );
  },
  getAWSProjectCrossAccountTrust(
    workspaceID: string,
    projectID: string,
    query?: AWSCrossAccountTrustQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ findings: AWSCrossAccountTrustResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/cross-account-trust${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        service: query?.service,
        principal: query?.principal,
        resource: query?.resource,
        finding_type: query?.findingType,
        severity: query?.severity,
        status: query?.status,
        ou: query?.ou
      })}`,
      auth
    );
  },
  getAWSProjectSecretPermissionEquivalence(
    workspaceID: string,
    projectID: string,
    query?: AWSSecretPermissionEquivalenceQuery,
    auth?: RequestAuthContext
  ) {
    return request<{ findings: AWSSecretPermissionEquivalenceResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/secret-permission-equivalence${buildQuery({
        connector_id: query?.connectorID,
        fixture_state: query?.fixtureState,
        account_id: query?.accountID,
        region: query?.region,
        identity: query?.identity,
        secret: query?.secret,
        provider: query?.provider,
        equivalence_type: query?.equivalenceType,
        evidence: query?.evidence,
        search: query?.search,
        severity: query?.severity,
        status: query?.status
      })}`,
      auth
    );
  },
  getAWSProjectIAMPassRoleRelationships(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSIAMPassRoleRelationshipFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSIAMPassRoleRelationshipInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/iam-passrole-relationships${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectS3BucketReachability(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSS3BucketReachabilityFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSS3BucketReachabilityInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/s3-bucket-reachability${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectKMSDecryptReachability(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSKMSDecryptReachabilityFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSKMSDecryptReachabilityInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/kms-decrypt-reachability${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectSQSSNSReachability(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSSQSSNSReachabilityFixtureState,
    auth?: RequestAuthContext,
    resourceType?: 'sqs_queue' | 'sns_topic',
    identity?: string
  ) {
    return request<{ inventory: AWSSQSSNSReachabilityInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/sqs-sns-reachability${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        resource_type: resourceType,
        identity
      })}`,
      auth
    );
  },
  getAWSProjectDynamoDBRDSReachability(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSDynamoDBRDSReachabilityFixtureState,
    auth?: RequestAuthContext,
    resourceType?: AWSDynamoDBRDSReachabilityRecord['resource_type'] | AWSDynamoDBRDSReachabilityRecord['service'],
    identity?: string
  ) {
    return request<{ inventory: AWSDynamoDBRDSReachabilityInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/dynamodb-rds-reachability${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        resource_type: resourceType,
        identity
      })}`,
      auth
    );
  },
  getAWSProjectCredentialReferences(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSCredentialReferencesFixtureState,
    filters?: { resourceType?: string; identity?: string; provider?: AWSCredentialProvider },
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSCredentialReferencesInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/credential-references${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        resource_type: filters?.resourceType,
        identity: filters?.identity,
        provider: filters?.provider
      })}`,
      auth
    );
  },
  getAWSProjectCoveragePlan(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSCoveragePlanFixtureState,
    filters?: { account?: string; region?: string; service?: string; state?: AWSCoverageState },
    auth?: RequestAuthContext
  ) {
    return request<{ plan: AWSCoveragePlanResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/coverage-plan${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        account: filters?.account,
        region: filters?.region,
        service: filters?.service,
        state: filters?.state
      })}`,
      auth
    );
  },
  getAWSProjectAccountRegionCoverage(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSCoveragePlanFixtureState,
    filters?: { account?: string; region?: string; service?: string; collector?: string; state?: AWSCoverageState; status?: AWSAccountRegionCoverageStatus },
    auth?: RequestAuthContext
  ) {
    return request<{ coverage: AWSAccountRegionCoverageResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/account-region-coverage${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        account: filters?.account,
        region: filters?.region,
        service: filters?.service,
        collector: filters?.collector,
        state: filters?.state,
        status: filters?.status
      })}`,
      auth
    );
  },
  getAWSProjectFanOutExecution(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSCoveragePlanFixtureState,
    filters?: { account?: string; region?: string; service?: string; state?: AWSCoverageState; maxConcurrency?: number },
    auth?: RequestAuthContext
  ) {
    return request<{ execution: AWSFanOutExecutionResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/fanout-execution${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        account: filters?.account,
        region: filters?.region,
        service: filters?.service,
        state: filters?.state,
        max_concurrency: filters?.maxConcurrency
      })}`,
      auth
    );
  },
  getAWSProjectOrganizationsTopology(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSOrganizationsTopologyFixtureState,
    filters?: { account?: string; ou?: string; state?: AWSCoverageState; status?: AWSOrganizationsAccountStatus },
    auth?: RequestAuthContext
  ) {
    return request<{ topology: AWSOrganizationsTopologyResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/organizations-topology${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        account: filters?.account,
        ou: filters?.ou,
        state: filters?.state,
        status: filters?.status
      })}`,
      auth
    );
  },
  getAWSProjectStackSetOnboarding(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSStackSetOnboardingFixtureState,
    options?: { deploymentMode?: AWSStackSetDeploymentMode },
    auth?: RequestAuthContext
  ) {
    return request<{ onboarding: AWSStackSetOnboardingResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/stackset-onboarding${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        deployment_mode: options?.deploymentMode
      })}`,
      auth
    );
  },
  getAWSProjectSecretsManagerMetadata(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSSecretsManagerMetadataFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSSecretsManagerMetadataInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/secrets-manager-metadata${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  getAWSProjectSSMParameterMetadata(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSSSMParameterMetadataFixtureState,
    filters?: { parameterType?: AWSSSMParameterTypeFilter; identity?: string },
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSSSMParameterMetadataInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/ssm-parameter-metadata${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        parameter_type: filters?.parameterType,
        identity: filters?.identity
      })}`,
      auth
    );
  },
  getAWSProjectECRRepositoryMetadata(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSECRRepositoryMetadataFixtureState,
    filters?: { repositoryName?: string; identity?: string },
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSECRRepositoryMetadataInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/ecr-repository-metadata${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState,
        repository_name: filters?.repositoryName,
        identity: filters?.identity
      })}`,
      auth
    );
  },
  getAWSProjectEKSWorkloadIdentities(
    workspaceID: string,
    projectID: string,
    connectorID?: string,
    fixtureState?: AWSEKSWorkloadIdentityFixtureState,
    auth?: RequestAuthContext
  ) {
    return request<{ inventory: AWSEKSWorkloadIdentityInventoryResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/eks-workload-identities${buildQuery({
        connector_id: connectorID,
        fixture_state: fixtureState
      })}`,
      auth
    );
  },
  verifyAWSProjectBaseline(workspaceID: string, projectID: string, payload: AWSPlatformBaselineRequest = {}, auth?: RequestAuthContext) {
    return request<{ baseline: AWSPlatformBaselineResult }>(
      `/v1/workspaces/${encodeURIComponent(workspaceID)}/projects/${encodeURIComponent(projectID)}/aws/baseline`,
      auth,
      {
        method: 'POST',
        body: JSON.stringify(payload)
      }
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
  getGitHubConnectorRepositoryPosture(
    connectorID: string,
    workspaceID: string,
    projectID: string,
    repository: string,
    auth?: RequestAuthContext
  ) {
    return request<GitHubRepositoryPostureResponse>(
      `/v1/connectors/github/${encodeURIComponent(connectorID)}/posture${buildQuery({
        workspace_id: workspaceID,
        project_id: projectID,
        repository
      })}`,
      auth
    );
  },
  startKubernetesConnector(payload: KubernetesConnectorStartRequest, auth?: RequestAuthContext) {
    return request<KubernetesConnectorStartResponse>('/v1/connectors/k8s', auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },
  getKubernetesConnectorStatus(workspaceID: string, projectID: string, auth?: RequestAuthContext) {
    return request<{ connection: KubernetesConnectionStatus }>(
      `/v1/connectors/k8s${buildQuery({ workspace_id: workspaceID, project_id: projectID })}`,
      auth
    );
  },
  upsertKubernetesKubeconfigConnector(payload: KubernetesConnectorKubeconfigRequest, auth?: RequestAuthContext) {
    return request<{ connection: KubernetesConnectionStatus }>('/v1/connectors/k8s/kubeconfig', auth, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
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
