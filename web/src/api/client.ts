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
  getExecutiveReport(auth?: RequestAuthContext) {
    return request<ExecutiveReport>('/v1/enterprise/reports/executive', auth);
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
