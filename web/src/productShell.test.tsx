import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  AuthConfigResponse,
  AWSAccountRegionCoverageResult,
  AWSConnectorStartResponse,
  AWSCodeBuildServiceRoleInventoryResult,
  AWSConnectionStatus,
  AWSAIAgentIdentityInventoryResult,
  AWSBedrockAgentsInventoryResult,
  AWSCoveragePlanResult,
  AWSEC2InstanceProfileInventoryResult,
  AWSEKSWorkloadIdentityInventoryResult,
  AWSECSTaskRoleInventoryResult,
  AWSFanOutExecutionResult,
  AWSLambdaExecutionRoleInventoryResult,
  AWSLeastPrivilegeResult,
  AWSAgentIdentityDetailResult,
  AWSMachineIdentityDetailResult,
  AWSOrganizationsTopologyResult,
  AWSPlatformBaselineResult,
  AWSPlatformDependencyIndexResult,
  AWSPlatformValidationHarnessResult,
  AWSRemediationCenterResult,
  AWSRuntimeEventResult,
  AWSServiceCollectorContractResult,
  AWSStackSetOnboardingResult,
  AWSUnusedDormantAccessResult,
  CurrentUserContext,
  Finding,
  FindingTriageEvent,
  GitHubConnectionStatus,
  GitHubOrganizationPosture,
  GitHubRepositoryPosture,
  KubernetesConnectorStartResponse,
  KubernetesConnectionStatus,
  RepoFindingsSummary,
  RepoFindingRemediationPreview,
  RepoFindingRemediationPublishResponse,
  RepoRiskGraph,
  TrendPoint,
  RepoScanRecord,
  ScanPolicyRecord,
  WhoAmIResponse
} from './api/client';
import type { BackendFeatureState } from './hooks/useBackendFeatures';
// Vite's `?raw` import returns the file contents as a string at bundle
// time, so the AWS copy-redundancy guard below can scan productShell.tsx
// without needing node's `require` or fs typings.
import productShellSource from './productShell.tsx?raw';

const stylesSource = readFileSync(join(process.cwd(), 'src/styles.css'), 'utf8');

const loggedInWithoutWorkspace: CurrentUserContext = {
  user: {
    id: 'user-1',
    primary_email: 'owner@example.com',
    display_name: 'Owner User',
    status: 'active',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  }
};

const loggedInWithWorkspace: CurrentUserContext = {
  user: {
    id: 'user-1',
    primary_email: 'owner@example.com',
    display_name: 'Owner User',
    avatar_url: 'https://avatars.githubusercontent.com/u/1?v=4',
    status: 'active',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  },
  org_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'project-a',
  role: 'admin',
  workspace: {
    tenant_id: 'tenant-a',
    workspace_id: 'workspace-a',
    display_name: 'Workspace A',
    slug: 'workspace-a',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  }
};

async function renderProductIndexRedirect(featureEnabled: boolean, backendOnboarding: BackendFeatureState) {
  vi.resetModules();
  vi.doMock('./hooks/useMe', () => ({
    useMe: () => ({
      me: loggedInWithoutWorkspace,
      loading: false,
      error: '',
      unauthenticated: false,
      refresh: vi.fn()
    })
  }));
  vi.doMock('./pages/onboarding/onboardingUtils', () => ({
    FEATURE_ONBOARDING_WIZARD: featureEnabled,
    FEATURE_ONBOARDING_CONNECTOR_AWS: false,
    FEATURE_ONBOARDING_CONNECTOR_GITHUB: false,
    FEATURE_ONBOARDING_CONNECTOR_K8S: false
  }));
  vi.doMock('./hooks/useBackendFeatures', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./hooks/useBackendFeatures')>();
    return {
      ...actual,
      useBackendFeatures: () => ({
        features: {
          onboardingWizard: backendOnboarding,
          connectors: { github: undefined, aws: undefined, kubernetes: undefined },
          configReachable: true
        },
        loading: false
      })
    };
  });

  const { ProductAppIndexRedirect } = await import('./productShell');

  render(
    <MemoryRouter initialEntries={['/app']}>
      <Routes>
        <Route path="/app" element={<ProductAppIndexRedirect />} />
        <Route path="/onboarding/org" element={<h1>Start onboarding</h1>} />
      </Routes>
    </MemoryRouter>
  );
}

const disconnectedAWS: AWSConnectionStatus = {
  provider: 'aws',
  connected: false,
  status: 'pending',
  health_status: 'unknown',
  external_id_configured: false,
  scope_type: 'single_account',
  deployment_method: 'cloudformation',
  onboarding_status: 'draft',
  target_regions: ['us-east-1'],
  target_account_ids: [],
  target_ou_ids: [],
  excluded_account_ids: [],
  auto_onboard_new_accounts: false,
  setup_summary: 'Single AWS account read-only setup through CloudFormation.',
  next_actions: ['launch_stack', 'validate_role', 'refresh_status'],
  permission_checks: [],
  diagnostics: [],
  capabilities: { requested: ['discovery'], validated: ['discovery'], effective: ['discovery'], unavailable: [] }
};

const connectedAWS: AWSConnectionStatus = {
  provider: 'aws',
  connected: true,
  connector_id: 'aws-connector-1',
  display_name: 'Production AWS',
  status: 'active',
  health_status: 'healthy',
  role_arn: 'arn:aws:iam::123456789012:role/IdentrailReadOnly',
  external_id_configured: true,
  account_id: '123456789012',
  principal_arn: 'arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail',
  region: 'us-east-1',
  scope_type: 'single_account',
  deployment_method: 'cloudformation',
  onboarding_status: 'connected',
  target_regions: ['us-east-1'],
  target_account_ids: ['123456789012'],
  target_ou_ids: [],
  excluded_account_ids: [],
  auto_onboard_new_accounts: false,
  setup_summary: 'AWS connector is connected and ready for discovery.',
  next_actions: ['start_intelligence', 'refresh_status'],
  permission_checks: [
    {
      name: 'iam:GetRole',
      passed: true,
      message: 'Role metadata can be inspected.'
    }
  ],
  diagnostics: [
    {
      code: 'cloudtrail_pending',
      message: 'Runtime evidence is not wired for this environment yet.',
      remediation: 'No action required for connector setup.'
    }
  ],
  capabilities: { requested: ['discovery'], validated: ['discovery'], effective: ['discovery'], unavailable: [] },
  updated_at: '2026-05-17T10:00:00Z',
  last_validated_at: '2026-05-17T10:00:00Z'
};

const readyAWSCoveragePlan: AWSCoveragePlanResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1503,
  parent_issue_ref: '#1503',
  current_issue_number: 1553,
  current_issue_ref: '#1553',
  version: 'aws-coverage-plan-v1',
  status: 'degraded',
  fixture_state: 'partial_failure',
  confidence: 0.96,
  filtered_targets: 2,
  summary: {
    total_targets: 2,
    enabled_targets: 2,
    disabled_targets: 0,
    account_count: 1,
    region_count: 2,
    service_count: 2,
    outstanding_targets: 1,
    covered_targets: 1,
    blocked_targets: 0,
    failed_targets: 1,
    permission_denied_targets: 0,
    resumable_targets: 1,
    coverage_percent: 50,
    state_counts: { covered: 1, partial: 1 },
    priority_counts: { critical: 1, high: 1 },
    prerequisites: []
  },
  targets: [
    {
      key: '123456789012/us-east-1/iam',
      account_id: '123456789012',
      account_name: 'Production',
      region: 'us-east-1',
      region_name: 'US East (N. Virginia)',
      service: 'iam',
      service_name: 'IAM',
      collector: 'iam_roles',
      global: true,
      enabled: true,
      priority: 'critical',
      priority_rank: 1,
      reason: 'Global IAM anchor',
      prerequisites: [],
      state: 'covered',
      resumable: false,
      next_action: 'No action required.',
      evidence_ref: 'aws-coverage-plan:iam',
      observed_at: '2026-06-12T12:00:00Z'
    },
    {
      key: '123456789012/us-west-2/lambda',
      account_id: '123456789012',
      account_name: 'Production',
      region: 'us-west-2',
      region_name: 'US West (Oregon)',
      service: 'lambda',
      service_name: 'Lambda',
      collector: 'lambda_execution_roles',
      global: false,
      enabled: true,
      priority: 'high',
      priority_rank: 2,
      reason: 'Regional execution-role collector',
      prerequisites: ['Deploy the read-only StackSet instance to us-west-2.'],
      state: 'partial',
      cursor: 'lambda-page-2',
      failure_reason: 'Lambda collector stopped at page 2.',
      attempts: 2,
      resumable: true,
      next_action: 'Resume Lambda collector from saved cursor.',
      evidence_ref: 'aws-coverage-plan:lambda',
      observed_at: '2026-06-12T12:05:00Z'
    }
  ],
  failure_reasons: ['Lambda collector stopped at page 2.'],
  remediation_hints: ['Resume Lambda collector from saved cursor.'],
  evidence_links: ['/docs/aws-account-region-coverage-planner'],
  partial_failure_reports: [
    {
      key: '123456789012/us-west-2/lambda',
      account_id: '123456789012',
      region: 'us-west-2',
      service: 'lambda',
      collector: 'lambda_execution_roles',
      state: 'partial',
      worker_state: 'failed',
      reason_code: 'collector_partial_failure',
      failure_reason: 'Lambda collector stopped at page 2.',
      retryable: true,
      attempts: 2,
      cursor: 'lambda-page-2',
      evidence_ref: 'aws-coverage-partial:lambda',
      next_action: 'Resume Lambda collector from saved cursor.',
      observed_at: '2026-06-12T12:05:00Z'
    }
  ],
  coverage_gaps: [
    {
      capability: 'regional_lambda',
      status: 'partial',
      reason: 'US West 2 Lambda coverage is partial.',
      remediation: 'Resume Lambda collector from the stored checkpoint.'
    }
  ],
  diagnostics: [
    {
      source: 'coverage_planner',
      scope: '123456789012/us-west-2/lambda',
      code: 'collector_partial_failure',
      message: 'Lambda coverage is partial.',
      remediation: 'Resume Lambda collector from checkpoint.',
      retryable: true
    }
  ],
  generated_at: '2026-06-12T12:10:00Z',
  updated_at: '2026-06-12T12:10:00Z'
};

const readyAWSAccountRegionCoverage: AWSAccountRegionCoverageResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1503,
  parent_issue_ref: '#1503',
  current_issue_number: 1553,
  current_issue_ref: '#1553',
  version: 'aws-account-region-coverage-v1',
  status: 'degraded',
  fixture_state: 'partial_failure',
  confidence: 0.96,
  summary: {
    total_records: 2,
    filtered_records: 2,
    account_count: 1,
    region_count: 2,
    service_count: 2,
    covered_records: 1,
    missing_records: 0,
    degraded_records: 1,
    unreachable_records: 0,
    suspended_records: 0,
    disabled_records: 0,
    stale_records: 0,
    permission_denied_records: 0,
    retryable_records: 1,
    status_counts: { covered: 1, degraded: 1 },
    state_counts: { covered: 1, partial: 1 },
    collector_counts: { iam_roles: 1, lambda_execution_roles: 1 }
  },
  records: [
    {
      key: '123456789012/us-east-1/iam',
      account_id: '123456789012',
      account_name: 'Production',
      region: 'us-east-1',
      region_name: 'US East (N. Virginia)',
      service: 'iam',
      service_name: 'IAM',
      collector: 'iam_roles',
      global: true,
      enabled: true,
      state: 'covered',
      coverage_status: 'covered',
      retryable: false,
      stale: false,
      evidence_ref: 'aws-account-region-coverage:iam',
      next_action: 'No action required.',
      observed_at: '2026-06-12T12:00:00Z',
      updated_at: '2026-06-12T12:00:00Z'
    },
    {
      key: '123456789012/us-west-2/lambda',
      account_id: '123456789012',
      account_name: 'Production',
      region: 'us-west-2',
      region_name: 'US West (Oregon)',
      service: 'lambda',
      service_name: 'Lambda',
      collector: 'lambda_execution_roles',
      global: false,
      enabled: true,
      state: 'partial',
      coverage_status: 'degraded',
      cursor: 'lambda-page-2',
      checkpoint: 'lambda-page-2',
      attempts: 2,
      failure_reason: 'Lambda collector stopped at page 2.',
      retryable: true,
      stale: false,
      evidence_ref: 'aws-account-region-coverage:lambda',
      next_action: 'Resume Lambda collector from saved cursor.',
      observed_at: '2026-06-12T12:05:00Z',
      updated_at: '2026-06-12T12:05:00Z'
    }
  ],
  failure_reasons: ['Lambda collector stopped at page 2.'],
  remediation_hints: ['Resume Lambda collector from saved cursor.'],
  evidence_links: ['/docs/aws-account-region-coverage-planner'],
  coverage_gaps: readyAWSCoveragePlan.coverage_gaps,
  diagnostics: readyAWSCoveragePlan.diagnostics,
  generated_at: '2026-06-12T12:10:00Z',
  updated_at: '2026-06-12T12:10:00Z'
};

const readyAWSFanOutExecution: AWSFanOutExecutionResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1503,
  parent_issue_ref: '#1503',
  current_issue_number: 1553,
  current_issue_ref: '#1553',
  version: 'aws-fanout-execution-v1',
  status: 'degraded',
  fixture_state: 'partial_failure',
  confidence: 0.94,
  filtered_targets: 2,
  summary: {
    total_targets: 2,
    executable_targets: 2,
    skipped_targets: 0,
    queued_targets: 1,
    in_progress_targets: 1,
    covered_targets: 1,
    partial_targets: 1,
    failed_targets: 0,
    permission_denied_targets: 0,
    throttled_targets: 0,
    retryable_targets: 1,
    concurrency_limit: 4,
    max_attempts: 3
  },
  targets: [],
  failure_reasons: ['Lambda collector stopped at page 2.'],
  remediation_hints: ['Queue or resume retryable targets from their checkpoints.'],
  evidence_links: ['/docs/aws-account-region-coverage-planner'],
  partial_failure_reports: readyAWSCoveragePlan.partial_failure_reports,
  coverage_gaps: readyAWSCoveragePlan.coverage_gaps,
  diagnostics: [],
  generated_at: '2026-06-12T12:10:00Z',
  updated_at: '2026-06-12T12:10:00Z'
};

const readyAWSOrganizationsTopology: AWSOrganizationsTopologyResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1503,
  parent_issue_ref: '#1503',
  current_issue_number: 1553,
  current_issue_ref: '#1553',
  organization_id: 'o-identrail',
  management_account_id: '123456789012',
  partition: 'aws',
  version: 'aws-organizations-topology-v1',
  status: 'ready',
  fixture_state: 'live',
  confidence: 0.95,
  filtered_accounts: 1,
  summary: {
    account_count: 1,
    organizational_unit_count: 1,
    management_account_count: 1,
    delegated_admin_account_count: 0,
    suspended_account_count: 0,
    connector_scoped_accounts: 1,
    scan_eligible_accounts: 1,
    blocked_accounts: 0,
    permission_denied_accounts: 0,
    failed_accounts: 0,
    resumable_accounts: 0,
    state_counts: { covered: 1 },
    status_counts: { active: 1 }
  },
  organizational_units: [{ id: 'r-identrail', name: 'Root', path: '/', enabled: true }],
  accounts: [
    {
      account_id: '123456789012',
      account_name: 'Production',
      status: 'active',
      parent_id: 'r-identrail',
      ou_path: '/',
      partition: 'aws',
      management: true,
      delegated_admin_services: [],
      connector_scoped: true,
      scan_eligible: true,
      state: 'covered',
      resumable: false,
      next_action: 'Use this account for downstream coverage.',
      evidence_ref: 'aws-organizations:aws-connector-1:123456789012'
    }
  ],
  relationships: [
    {
      parent_id: 'r-identrail',
      child_id: '123456789012',
      child_type: 'account',
      relationship: 'contains'
    }
  ],
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-account-region-coverage-planner'],
  coverage_gaps: [],
  diagnostics: [],
  generated_at: '2026-06-12T12:10:00Z',
  updated_at: '2026-06-12T12:10:00Z'
};

const readyAWSStackSetOnboarding: AWSStackSetOnboardingResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  organization_id: 'o-identrail',
  management_account_id: '123456789012',
  stack_set_name: 'IdentrailReadOnlyCoverage',
  deployment_mode: 'service_managed',
  partition: 'aws',
  parent_issue_number: 1503,
  parent_issue_ref: '#1503',
  current_issue_number: 1553,
  current_issue_ref: '#1553',
  version: 'aws-stackset-onboarding-v1',
  status: 'degraded',
  fixture_state: 'partial_failure',
  confidence: 0.92,
  validation: {
    status: 'degraded',
    confidence: 0.92,
    blocking_count: 0,
    advisory_count: 1,
    prerequisites: [
      {
        id: 'us-west-2-instance',
        title: 'Deploy us-west-2 read-only role',
        severity: 'advisory',
        satisfied: false,
        reason: 'The regional StackSet instance has not reported active yet.',
        remediation: 'Deploy the read-only StackSet instance to us-west-2.'
      }
    ],
    failure_reasons: ['The regional StackSet instance has not reported active yet.'],
    remediation_hints: ['Deploy the read-only StackSet instance to us-west-2.']
  },
  permission_preview: [],
  targets: {
    organization_id: 'o-identrail',
    organizational_units: [{ id: 'r-identrail', name: 'Root', path: '/', enabled: true }],
    accounts: [{ account_id: '123456789012', name: 'Production', ou_path: '/', management: true }],
    regions: [
      { region: 'us-east-1', name: 'US East (N. Virginia)' },
      { region: 'us-west-2', name: 'US West (Oregon)', opt_in: false }
    ]
  },
  instances: [
    {
      key: '123456789012/us-west-2',
      account_id: '123456789012',
      account_name: 'Production',
      ou_path: '/',
      region: 'us-west-2',
      region_name: 'US West (Oregon)',
      state: 'degraded',
      failure_reason: 'The regional StackSet instance has not reported active yet.',
      attempts: 1,
      resumable: true,
      next_action: 'Redeploy or refresh the StackSet instance.',
      coverage_targets: 1,
      evidence_ref: 'aws-stackset-onboarding:us-west-2',
      observed_at: '2026-06-12T12:05:00Z'
    }
  ],
  coverage_expectation: {
    expected_accounts: 1,
    expected_regions: 2,
    expected_instances: 2,
    expected_coverage_targets: 2,
    coverage_percent: 50,
    global_service_notes: 'IAM remains anchored in the home region.'
  },
  recovery_actions: [
    {
      id: 'redeploy-us-west-2',
      title: 'Redeploy regional StackSet instance',
      description: 'Refresh the us-west-2 read-only role so collectors can continue.',
      targets: ['123456789012/us-west-2']
    }
  ],
  summary: {
    target_accounts: 1,
    target_regions: 2,
    total_instances: 2,
    pending_instances: 0,
    active_instances: 1,
    blocked_instances: 0,
    failed_instances: 0,
    degraded_instances: 1,
    suspended_instances: 0,
    permission_denied_instances: 0,
    unsupported_instances: 0,
    resumable_instances: 1,
    deployed_percent: 50,
    state_counts: { active: 1, degraded: 1 }
  },
  failure_reasons: ['The regional StackSet instance has not reported active yet.'],
  remediation_hints: ['Deploy the read-only StackSet instance to us-west-2.'],
  evidence_links: ['/docs/aws-account-region-coverage-planner'],
  coverage_gaps: [{ capability: 'regional_stackset', status: 'degraded', reason: 'us-west-2 needs a read-only role.' }],
  diagnostics: [],
  generated_at: '2026-06-12T12:10:00Z',
  updated_at: '2026-06-12T12:10:00Z'
};

function mockAWSCoverageDashboardAPIs(api: typeof import('./api/client')) {
  const getCoveragePlan = vi.spyOn(api.apiClient, 'getAWSProjectCoveragePlan').mockResolvedValue({ plan: readyAWSCoveragePlan });
  const getAccountRegionCoverage = vi
    .spyOn(api.apiClient, 'getAWSProjectAccountRegionCoverage')
    .mockResolvedValue({ coverage: readyAWSAccountRegionCoverage });
  const getFanOutExecution = vi
    .spyOn(api.apiClient, 'getAWSProjectFanOutExecution')
    .mockResolvedValue({ execution: readyAWSFanOutExecution });
  const getOrganizationsTopology = vi
    .spyOn(api.apiClient, 'getAWSProjectOrganizationsTopology')
    .mockResolvedValue({ topology: readyAWSOrganizationsTopology });
  const getStackSetOnboarding = vi
    .spyOn(api.apiClient, 'getAWSProjectStackSetOnboarding')
    .mockResolvedValue({ onboarding: readyAWSStackSetOnboarding });

  return {
    getCoveragePlan,
    getAccountRegionCoverage,
    getFanOutExecution,
    getOrganizationsTopology,
    getStackSetOnboarding
  };
}

const readyAWSRuntimeEvents: AWSRuntimeEventResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1517,
  current_issue_ref: '#1517',
  version: 'aws-runtime-events-contract-v3',
  status: 'ready',
  fixture_state: 'success',
  confidence: 0.92,
  applied_filters: {},
  summary: {
    total_events: 6,
    filtered_events: 6,
    event_type_counts: { 'sts-session': 1, 'api-call': 1, 'secret-read': 1, 'kms-decrypt': 1, 'agent-tool': 1, 'access-analyzer': 1 },
    status_counts: { observed: 5, stale: 1 },
    owner_counts: { security: 6 },
    account_count: 1,
    region_count: 1,
    identity_count: 3,
    resource_count: 5,
    agent_event_count: 1,
    secret_read_count: 1,
    kms_decrypt_count: 1,
    api_call_count: 1,
    sts_session_count: 1,
    iam_last_used_signal_count: 0,
    access_analyzer_finding_count: 1,
    dormant_access_count: 0,
    lineage_resolved_count: 4,
    missing_source_identity_count: 0,
    ambiguous_lineage_count: 0,
    relationship_count: 5,
    permission_denied_events: 0
  },
  records: [
    {
      event_id: 'evt-assume-role',
      account_id: '123456789012',
      region: 'us-east-1',
      event_type: 'sts-session',
      event_source: 'sts.amazonaws.com',
      event_name: 'AssumeRole',
      action: 'sts:AssumeRole',
      actor_principal_arn: 'arn:aws:iam::123456789012:user/billing-operator',
      actor_principal_type: 'iam_user',
      actor_identity_node_id: 'aws:identity:user/billing-operator',
      session: {
        session_id: 'sess-invoice-agent',
        session_node_id: 'aws:runtime-session:sess-invoice-agent',
        principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
        principal_type: 'assumed_role',
        assumed_role_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
        session_issuer_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
        source_identity: 'billing-operator@example.com',
        role_session_name: 'invoice-agent-run',
        session_tag_keys: ['tenant', 'job'],
        transitive_tag_keys: ['tenant'],
        original_actor_arn: 'arn:aws:iam::123456789012:user/billing-operator',
        original_actor_node_id: 'aws:identity:user/billing-operator',
        lineage_status: 'resolved',
        lineage_reason: 'SourceIdentity and role session name matched the CloudTrail STS event.',
        source_ip_address: '203.0.113.10',
        user_agent: 'aws-sdk-js/3',
        started_at: '2026-06-14T17:00:00Z',
        expires_at: '2026-06-14T18:00:00Z'
      },
      target_resource_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
      target_resource_type: 'AWS::IAM::Role',
      target_resource_name: 'lambda-invoice-agent',
      resource_node_id: 'aws:identity:lambda-invoice-agent',
      owner: 'security',
      evidence_category: 'cloudtrail',
      evidence_ref: 'runtime-evidence://123456789012/us-east-1/evt-assume-role',
      confidence: 0.93,
      observed_at: '2026-06-14T17:01:00Z',
      collected_at: '2026-06-14T17:03:00Z',
      status: 'observed',
      next_action: 'Use the resolved STS lineage to correlate downstream actions.',
      redaction_boundary: 'metadata_only_no_payloads_no_secret_values'
    },
    {
      event_id: 'evt-s3-access',
      account_id: '123456789012',
      region: 'us-east-1',
      event_type: 'api-call',
      event_source: 's3.amazonaws.com',
      event_name: 'GetObject',
      action: 's3:GetObject',
      actor_principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
      actor_principal_type: 'assumed_role',
      actor_identity_node_id: 'aws:identity:lambda-invoice-agent',
      session: {
        session_id: 'sess-invoice-agent',
        session_node_id: 'aws:runtime-session:sess-invoice-agent',
        principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
        principal_type: 'assumed_role',
        source_identity: 'billing-operator@example.com',
        role_session_name: 'invoice-agent-run',
        original_actor_arn: 'arn:aws:iam::123456789012:user/billing-operator',
        original_actor_node_id: 'aws:identity:user/billing-operator',
        lineage_status: 'resolved',
        lineage_reason: 'Downstream data event reused the resolved STS session.',
        started_at: '2026-06-14T17:00:00Z',
        expires_at: '2026-06-14T18:00:00Z'
      },
      target_resource_arn: 'arn:aws:s3:::billing-artifacts-123456789012/reports/redacted',
      target_resource_type: 's3_object_metadata',
      target_resource_name: 'redacted',
      resource_node_id: 'aws:runtime-resource:s3_object_metadata:redacted',
      owner: 'security',
      evidence_category: 'cloudtrail',
      evidence_ref: 'runtime-evidence://123456789012/us-east-1/evt-s3-access',
      confidence: 0.9,
      observed_at: '2026-06-14T17:15:00Z',
      collected_at: '2026-06-14T17:17:00Z',
      status: 'observed',
      next_action: 'Correlate runtime evidence with identity and resource graph context.',
      redaction_boundary: 'metadata_only_no_payloads_no_secret_values'
    },
    {
      event_id: 'evt-secret-read',
      account_id: '123456789012',
      region: 'us-east-1',
      event_type: 'secret-read',
      event_source: 'secretsmanager.amazonaws.com',
      event_name: 'GetSecretValue',
      action: 'secretsmanager:GetSecretValue',
      actor_principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
      actor_principal_type: 'assumed_role',
      actor_identity_node_id: 'aws:identity:lambda-invoice-agent',
      session: {
        session_id: 'sess-invoice-agent',
        session_node_id: 'aws:runtime-session:sess-invoice-agent',
        principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
        principal_type: 'assumed_role',
        source_identity: 'billing-operator@example.com',
        role_session_name: 'invoice-agent-run',
        original_actor_arn: 'arn:aws:iam::123456789012:user/billing-operator',
        original_actor_node_id: 'aws:identity:user/billing-operator',
        lineage_status: 'resolved',
        lineage_reason: 'Secret read reused the resolved STS session.',
        started_at: '2026-06-14T17:00:00Z',
        expires_at: '2026-06-14T18:00:00Z'
      },
      target_resource_arn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/ai/openai-key',
      target_resource_type: 'AWS::SecretsManager::Secret',
      target_resource_name: 'prod/ai/openai-key',
      resource_node_id: 'aws:runtime-resource:aws--secretsmanager--secret:openai-key',
      owner: 'security',
      evidence_category: 'cloudtrail',
      evidence_ref: 'runtime-evidence://123456789012/us-east-1/evt-secret-read',
      confidence: 0.91,
      observed_at: '2026-06-14T17:16:00Z',
      collected_at: '2026-06-14T17:18:00Z',
      status: 'observed',
      next_action: 'Join the secret read with static secret reachability and rotation evidence.',
      redaction_boundary: 'metadata_only_no_payloads_no_secret_values'
    },
    {
      event_id: 'evt-kms-decrypt',
      account_id: '123456789012',
      region: 'us-east-1',
      event_type: 'kms-decrypt',
      event_source: 'kms.amazonaws.com',
      event_name: 'Decrypt',
      action: 'kms:Decrypt',
      actor_principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
      actor_principal_type: 'assumed_role',
      actor_identity_node_id: 'aws:identity:lambda-invoice-agent',
      session: {
        session_id: 'sess-invoice-agent',
        session_node_id: 'aws:runtime-session:sess-invoice-agent',
        principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
        principal_type: 'assumed_role',
        source_identity: 'billing-operator@example.com',
        role_session_name: 'invoice-agent-run',
        original_actor_arn: 'arn:aws:iam::123456789012:user/billing-operator',
        original_actor_node_id: 'aws:identity:user/billing-operator',
        lineage_status: 'resolved',
        lineage_reason: 'KMS decrypt reused the resolved STS session.',
        started_at: '2026-06-14T17:00:00Z',
        expires_at: '2026-06-14T18:00:00Z'
      },
      target_resource_arn: 'arn:aws:kms:us-east-1:123456789012:key/openai-provider',
      target_resource_type: 'AWS::KMS::Key',
      target_resource_name: 'openai-provider',
      resource_node_id: 'aws:runtime-resource:kms-key:openai-provider',
      owner: 'security',
      evidence_category: 'cloudtrail',
      evidence_ref: 'runtime-evidence://123456789012/us-east-1/evt-kms-decrypt',
      confidence: 0.91,
      observed_at: '2026-06-14T17:16:30Z',
      collected_at: '2026-06-14T17:18:00Z',
      status: 'observed',
      next_action: 'Join the decrypt event with static KMS reachability.',
      redaction_boundary: 'metadata_only_no_payloads_no_secret_values_no_decrypted_plaintext'
    },
    {
      event_id: 'evt-agent-tool',
      account_id: '123456789012',
      region: 'us-east-1',
      event_type: 'agent-tool',
      event_source: 'bedrock-agentcore.amazonaws.com',
      event_name: 'InvokeTool',
      action: 'bedrock-agentcore:InvokeTool',
      actor_principal_arn: 'arn:aws:iam::123456789012:role/agentcore-case-triage-runtime',
      actor_principal_type: 'assumed_role',
      actor_identity_node_id: 'aws:identity:agentcore-case-triage-runtime',
      session: {
        session_id: 'sess-agentcore-runtime',
        principal_arn: 'arn:aws:iam::123456789012:role/agentcore-case-triage-runtime',
        principal_type: 'assumed_role',
        started_at: '2026-06-14T17:18:00Z'
      },
      target_resource_arn: 'arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/runtime-case-triage/blue',
      target_resource_type: 'agent_tool_target',
      target_resource_name: 'blue',
      resource_node_id: 'aws:runtime-resource:agent_tool_target:blue',
      agent_id: 'runtime-case-triage',
      agent_node_id: 'aws:agent:runtime-case-triage',
      tool_name: 'case-router',
      tool_target_ref: 'case-router-policy-checker',
      owner: 'security',
      evidence_category: 'agent-runtime',
      evidence_ref: 'runtime-evidence://123456789012/us-east-1/evt-agent-tool',
      confidence: 0.9,
      observed_at: '2026-06-14T17:19:00Z',
      collected_at: '2026-06-14T17:21:00Z',
      status: 'observed',
      next_action: 'Review the agent identity and tool target relationship.',
      redaction_boundary: 'metadata_only_no_payloads_no_secret_values'
    },
    {
      event_id: 'evt-access-analyzer-open-secret',
      account_id: '123456789012',
      region: 'us-east-1',
      event_type: 'access-analyzer',
      event_source: 'access-analyzer.amazonaws.com',
      event_name: 'Finding',
      action: 'secretsmanager:GetSecretValue',
      actor_principal_arn: 'access-analyzer:external-principal',
      actor_principal_type: 'aws_principal',
      actor_identity_node_id: 'aws:identity:access-analyzer:external-principal',
      session: {
        session_id: '',
        principal_arn: 'access-analyzer:external-principal',
        principal_type: 'aws_principal'
      },
      target_resource_arn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/ai/openai-key',
      target_resource_type: 'AWS::SecretsManager::Secret',
      target_resource_name: 'prod/ai/openai-key',
      resource_node_id: 'aws:runtime-resource:aws--secretsmanager--secret:openai-key',
      signal_category: 'access-analyzer',
      signal_scope: 'account',
      analyzer_arn: 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/identrail-fixture',
      signal_stale_at: '2026-06-14T17:58:00Z',
      owner: 'security',
      evidence_category: 'access-analyzer',
      evidence_ref: 'runtime-evidence://123456789012/us-east-1/evt-access-analyzer-open-secret',
      confidence: 0.9,
      observed_at: '2026-06-14T17:49:00Z',
      collected_at: '2026-06-14T17:58:00Z',
      status: 'stale',
      next_action: 'Review Access Analyzer scope and finding status before trusting or remediating access.',
      redaction_boundary: 'metadata_only_no_payloads_no_secret_values'
    }
  ],
  relationships: [],
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-runtime-events', 'javascript:alert(1)', 'https://docs.identrail.com/aws-runtime-events'],
  coverage_gaps: [],
  diagnostics: [],
  generated_at: '2026-06-14T17:30:00Z',
  updated_at: '2026-06-14T17:30:00Z'
};

const readyAWSLeastPrivilege: AWSLeastPrivilegeResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1522,
  current_issue_ref: '#1522',
  version: 'aws-least-privilege-recommendation-engine-v1',
  status: 'ready',
  fixture_state: 'success',
  confidence: 0.9,
  calculation_version: 'aws-least-privilege-recommendation-engine-v1',
  applied_filters: {},
  summary: {
    total_recommendations: 1,
    filtered_recommendations: 1,
    decision_counts: { remove: 1 },
    severity_counts: { high: 1 },
    status_counts: { review: 1 },
    service_counts: { secretsmanager: 1 },
    remove_count: 1,
    keep_count: 0,
    review_count: 0,
    low_breakage_count: 1,
    unknown_breakage_count: 0,
    runtime_evidence_count: 1,
    relationship_count: 1,
    highest_score: 82,
    average_confidence_pct: 90,
    remediation_preview_count: 1,
    permission_denied_evidence_count: 0
  },
  recommendations: [
    {
      recommendation_id: 'aws-least-privilege:secret-unused',
      calculation_version: 'aws-least-privilege-recommendation-engine-v1',
      recommendation_type: 'remove-unused-secret-kms-grant',
      decision: 'remove',
      severity: 'high',
      status: 'review',
      score: 82,
      confidence: 0.9,
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'secretsmanager',
      identity_node_id: 'aws:identity:lambda-invoice-agent',
      principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
      resource_node_id: 'aws:resource:secret:openai-key',
      resource_arn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/ai/openai-key',
      display_name: 'lambda-invoice-agent',
      rationale: 'Static secret grant has no matching runtime evidence in the scoped window.',
      breakage_prediction: 'low',
      breakage_rationale: 'No matching runtime use was observed in the scoped evidence window.',
      remove_actions: ['secretsmanager:GetSecretValue'],
      granted_actions: ['secretsmanager:GetSecretValue'],
      impacted_nodes: ['aws:identity:lambda-invoice-agent', 'aws:resource:secret:openai-key'],
      impacted_path: [
        {
          node_id: 'aws:identity:lambda-invoice-agent',
          node_type: 'identity',
          label: 'lambda-invoice-agent',
          account_id: '123456789012',
          region: 'us-east-1'
        },
        {
          node_id: 'aws:resource:secret:openai-key',
          node_type: 'secret',
          label: 'prod/ai/openai-key',
          account_id: '123456789012',
          region: 'us-east-1'
        }
      ],
      evidence: [
        {
          source: 'secrets_kms_runtime_access',
          evidence_ref: 'secrets-kms-runtime-access://secret-unused',
          label: 'Secrets Manager / KMS runtime access',
          confidence: 0.9,
          observed_at: '2026-06-14T17:30:00Z',
          relationship: 'granted_unused'
        }
      ],
      next_action:
        'Open a read-only least-privilege case for secret/KMS, require owner approval, and verify low breakage prediction before policy diff generation.',
      remediation_case: {
        case_id: 'aws-least-privilege-preview:secret-unused',
        title: 'remove unused secret grant',
        recommended_action: 'Create a read-only case to remove unused grants after owner approval.',
        approval_required: true,
        blocking_evidence: ['secrets-kms-runtime-access://secret-unused'],
        impacted_node_count: 1,
        estimated_risk_drop: 40,
        breakage_prediction: 'low',
        read_only_projection: true
      },
      created_at: '2026-06-14T17:30:00Z',
      updated_at: '2026-06-14T17:30:00Z'
    }
  ],
  relationships: [
    {
      recommendation_id: 'aws-least-privilege:secret-unused',
      type: 'least_privilege_scope',
      from_node_id: 'aws:identity:lambda-invoice-agent',
      to_node_id: 'aws:resource:secret:openai-key',
      evidence_ref: 'secrets-kms-runtime-access://secret-unused'
    }
  ],
  caveats: [],
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-least-privilege-engine'],
  coverage_gaps: [],
  diagnostics: [],
  generated_at: '2026-06-14T17:30:00Z',
  updated_at: '2026-06-14T17:30:00Z'
};

const readyAWSUnusedDormantAccess: AWSUnusedDormantAccessResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1523,
  current_issue_ref: '#1523',
  version: 'aws-unused-dormant-access-engine-v1',
  status: 'ready',
  fixture_state: 'success',
  confidence: 0.9,
  calculation_version: 'aws-unused-dormant-access-engine-v1',
  applied_filters: {},
  summary: {
    total_findings: 1,
    filtered_findings: 1,
    dormancy_state_counts: { never_used: 1 },
    severity_counts: { high: 1 },
    status_counts: { cleanup_candidate: 1 },
    service_counts: { secretsmanager: 1 },
    cleanup_candidate_count: 1,
    review_required_count: 0,
    no_runtime_evidence_count: 0,
    unknown_evidence_count: 0,
    stale_access_count: 0,
    relationship_count: 1,
    highest_score: 82,
    average_confidence_pct: 90,
    remediation_preview_count: 1,
    permission_denied_evidence_count: 0
  },
  findings: [
    {
      finding_id: 'aws-unused-dormant-access:secret-unused',
      calculation_version: 'aws-unused-dormant-access-engine-v1',
      finding_type: 'cleanup_candidate',
      dormancy_state: 'never_used',
      severity: 'high',
      status: 'cleanup_candidate',
      score: 82,
      confidence: 0.9,
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'secretsmanager',
      identity_node_id: 'aws:identity:lambda-invoice-agent',
      principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
      resource_node_id: 'aws:resource:secret:openai-key',
      resource_arn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/ai/openai-key',
      display_name: 'lambda-invoice-agent',
      owner_context: 'resource-owner-review',
      policy_scope: 'secretsmanager:GetSecretValue',
      rationale: 'lambda-invoice-agent has granted secretsmanager access with no matching runtime evidence.',
      dormant_days: 90,
      scan_window_days: 90,
      candidate_actions: ['secretsmanager:GetSecretValue'],
      granted_actions: ['secretsmanager:GetSecretValue'],
      impacted_nodes: ['aws:identity:lambda-invoice-agent', 'aws:resource:secret:openai-key'],
      impacted_path: readyAWSLeastPrivilege.recommendations[0].impacted_path,
      evidence: readyAWSLeastPrivilege.recommendations[0].evidence,
      next_action: 'Create a read-only cleanup case, confirm owner approval, and verify policy scope before generating an IAM diff.',
      remediation_case: {
        case_id: 'aws-unused-dormant-preview:secret-unused',
        title: 'never used dormant-access remove',
        recommended_action: 'Create a read-only case to remove unused grants after owner approval.',
        approval_required: true,
        blocking_evidence: ['secrets-kms-runtime-access://secret-unused'],
        impacted_node_count: 1,
        estimated_risk_drop: 40,
        breakage_prediction: 'low',
        read_only_projection: true
      },
      created_at: '2026-06-14T17:30:00Z',
      updated_at: '2026-06-14T17:30:00Z'
    }
  ],
  relationships: [
    {
      finding_id: 'aws-unused-dormant-access:secret-unused',
      type: 'unused_dormant_access_scope',
      from_node_id: 'aws:identity:lambda-invoice-agent',
      to_node_id: 'aws:resource:secret:openai-key',
      evidence_ref: 'secrets-kms-runtime-access://secret-unused'
    }
  ],
  caveats: [],
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-unused-dormant-access-engine'],
  coverage_gaps: [],
  diagnostics: [],
  generated_at: '2026-06-14T17:30:00Z',
  updated_at: '2026-06-14T17:30:00Z'
};

const readyAWSEC2InstanceProfileInventory: AWSEC2InstanceProfileInventoryResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1477,
  current_issue_ref: '#1477',
  version: 'aws-ec2-instance-profile-inventory-v1',
  status: 'ready',
  fixture_state: 'success',
  confidence: 0.97,
  record_count: 2,
  workload_count: 2,
  identity_count: 2,
  resource_count: 3,
  relationship_count: 2,
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-ec2-instance-profiles'],
  records: [
    {
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'ec2',
      workload_id: 'i-0477ec2profile',
      workload_type: 'ec2_instance',
      workload_name: 'payments-api',
      role_arn: 'arn:aws:iam::123456789012:role/payments-ec2-instance-profile',
      role_name: 'payments-ec2-instance-profile',
      instance_id: 'i-0477ec2profile',
      instance_arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0477ec2profile',
      instance_name: 'payments-api',
      instance_state: 'running',
      instance_profile_arn: 'arn:aws:iam::123456789012:instance-profile/payments-ec2-profile',
      instance_profile_id: 'AIPAJ477EXAMPLE',
      instance_profile_name: 'payments-ec2-profile',
      imds_endpoint: 'enabled',
      imds_http_tokens: 'required',
      imds_hop_limit: 2,
      tags: { owner: 'platform', service: 'payments' },
      source: 'describeinstances',
      evidence_ref: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0477ec2profile',
      from_node_id: 'aws:workload:ec2:123456789012:us-east-1:instance/i-0477ec2profile',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-ec2-instance-profile',
      confidence: 0.96,
      collected_at: '2026-05-17T10:00:00Z',
      status: 'ready'
    },
    {
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'ec2',
      workload_id: 'lt-0477template:3',
      workload_type: 'ec2_launch_template',
      workload_name: 'web-launch-template',
      role_arn: 'arn:aws:iam::123456789012:role/web-launch-template-role',
      role_name: 'web-launch-template-role',
      instance_profile_arn: 'arn:aws:iam::123456789012:instance-profile/web-launch-template-profile',
      instance_profile_name: 'web-launch-template-profile',
      launch_template_id: 'lt-0477template',
      launch_template_name: 'web-launch-template',
      launch_template_version: '3',
      source: 'describelaunchtemplateversions',
      evidence_ref: 'lt-0477template',
      from_node_id: 'aws:workload:ec2:123456789012:us-east-1:launch-template/lt-0477template:3',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/web-launch-template-role',
      confidence: 0.9,
      collected_at: '2026-05-17T10:00:00Z',
      status: 'ready'
    }
  ],
  relationships: [
    {
      type: 'runs_as',
      from_node_id: 'aws:workload:ec2:123456789012:us-east-1:instance/i-0477ec2profile',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-ec2-instance-profile',
      evidence_ref: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0477ec2profile'
    },
    {
      type: 'attached_to',
      from_node_id: 'aws:workload:ec2:123456789012:us-east-1:launch-template/lt-0477template:3',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/web-launch-template-role',
      evidence_ref: 'lt-0477template'
    }
  ],
  diagnostics: [],
  generated_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

const readyAWSECSTaskRoleInventory: AWSECSTaskRoleInventoryResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1478,
  current_issue_ref: '#1478',
  version: 'aws-ecs-task-role-inventory-v1',
  status: 'ready',
  fixture_state: 'success',
  confidence: 0.97,
  record_count: 2,
  task_role_count: 1,
  execution_role_count: 1,
  workload_count: 2,
  identity_count: 2,
  resource_count: 2,
  relationship_count: 2,
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-ecs-task-roles'],
  records: [
    {
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'ecs',
      workload_id: 'arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api',
      workload_type: 'ecs_service',
      workload_name: 'payments-api',
      role_kind: 'task_role',
      role_arn: 'arn:aws:iam::123456789012:role/payments-ecs-task',
      role_name: 'payments-ecs-task',
      cluster_arn: 'arn:aws:ecs:us-east-1:123456789012:cluster/prod-cluster',
      cluster_name: 'prod-cluster',
      service_arn: 'arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api',
      service_name: 'payments-api',
      service_status: 'ACTIVE',
      task_definition_arn: 'arn:aws:ecs:us-east-1:123456789012:task-definition/payments-api:42',
      task_definition_family: 'payments-api',
      task_definition_revision: '42',
      task_definition_status: 'ACTIVE',
      task_role_arn: 'arn:aws:iam::123456789012:role/payments-ecs-task',
      execution_role_arn: 'arn:aws:iam::123456789012:role/payments-ecs-execution',
      launch_type: 'FARGATE',
      scheduling_strategy: 'REPLICA',
      desired_count: 3,
      running_count: 0,
      pending_count: 0,
      compatibilities: ['FARGATE'],
      container_images: ['123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api:2026-06-04'],
      secret_refs: ['DATABASE_PASSWORD=arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db'],
      environment_keys: ['APP_ENV', 'LOG_LEVEL'],
      tags: { owner: 'platform', service: 'payments' },
      source: 'describeservices',
      evidence_ref: 'arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api',
      from_node_id: 'aws:workload:ecs:123456789012:us-east-1:ecs_service/arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-ecs-task',
      relationship_type: 'runs_as',
      confidence: 0.96,
      collected_at: '2026-05-17T10:00:00Z',
      status: 'ready'
    },
    {
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'ecs',
      workload_id: 'arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api',
      workload_type: 'ecs_service',
      workload_name: 'payments-api',
      role_kind: 'execution_role',
      role_arn: 'arn:aws:iam::123456789012:role/payments-ecs-execution',
      role_name: 'payments-ecs-execution',
      cluster_name: 'prod-cluster',
      service_name: 'payments-api',
      service_status: 'ACTIVE',
      task_definition_arn: 'arn:aws:ecs:us-east-1:123456789012:task-definition/payments-api:42',
      task_definition_family: 'payments-api',
      task_definition_revision: '42',
      task_definition_status: 'ACTIVE',
      task_role_arn: 'arn:aws:iam::123456789012:role/payments-ecs-task',
      execution_role_arn: 'arn:aws:iam::123456789012:role/payments-ecs-execution',
      launch_type: 'FARGATE',
      scheduling_strategy: 'REPLICA',
      desired_count: 3,
      running_count: 0,
      pending_count: 0,
      compatibilities: ['FARGATE'],
      container_images: ['123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api:2026-06-04'],
      secret_refs: ['DATABASE_PASSWORD=arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db'],
      environment_keys: ['APP_ENV', 'LOG_LEVEL'],
      source: 'describeservices',
      evidence_ref: 'arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api',
      from_node_id: 'aws:workload:ecs:123456789012:us-east-1:ecs_service/arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-ecs-execution',
      relationship_type: 'attached_to',
      confidence: 0.9,
      collected_at: '2026-05-17T10:00:00Z',
      status: 'ready'
    }
  ],
  relationships: [
    {
      type: 'runs_as',
      from_node_id: 'aws:workload:ecs:123456789012:us-east-1:ecs_service/payments-api/task_role',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-ecs-task',
      evidence_ref: 'arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api'
    },
    {
      type: 'attached_to',
      from_node_id: 'aws:workload:ecs:123456789012:us-east-1:ecs_service/payments-api/execution_role',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-ecs-execution',
      evidence_ref: 'arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/payments-api'
    }
  ],
  diagnostics: [],
  generated_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

const readyAWSLambdaExecutionRoleInventory: AWSLambdaExecutionRoleInventoryResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1479,
  current_issue_ref: '#1479',
  version: 'aws-lambda-execution-role-inventory-v1',
  status: 'ready',
  fixture_state: 'success',
  confidence: 0.97,
  record_count: 1,
  function_count: 1,
  identity_count: 1,
  resource_count: 1,
  relationship_count: 1,
  event_source_count: 1,
  disabled_event_source_count: 0,
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-lambda-execution-roles'],
  records: [
    {
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'lambda',
      workload_id: 'arn:aws:lambda:us-east-1:123456789012:function:payments-worker',
      workload_type: 'lambda_function',
      workload_name: 'payments-worker',
      role_arn: 'arn:aws:iam::123456789012:role/payments-lambda-execution',
      role_name: 'payments-lambda-execution',
      function_arn: 'arn:aws:lambda:us-east-1:123456789012:function:payments-worker',
      function_name: 'payments-worker',
      function_version: '$LATEST',
      function_state: 'Active',
      last_update_status: 'Successful',
      runtime: 'nodejs20.x',
      package_type: 'Zip',
      handler: 'index.handler',
      kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/lambda-env',
      memory_size: 512,
      timeout: 30,
      vpc_id: 'vpc-prod',
      subnet_ids: ['subnet-a', 'subnet-b'],
      security_group_ids: ['sg-lambda-payments'],
      architectures: ['x86_64'],
      alias_names: ['prod=3'],
      version_refs: ['$LATEST', '3'],
      event_source_arns: ['arn:aws:sqs:us-east-1:123456789012:payments'],
      event_source_mapping_uuids: ['mapping-payments-sqs'],
      environment_keys: ['APP_ENV', 'LOG_LEVEL', 'DATABASE_PASSWORD'],
      secret_refs: ['BASIC_AUTH=arn:aws:secretsmanager:us-east-1:123456789012:secret:lambda/kafka'],
      tags: { owner: 'platform', service: 'payments' },
      source: 'listfunctions',
      evidence_ref: 'arn:aws:lambda:us-east-1:123456789012:function:payments-worker',
      from_node_id: 'aws:workload:lambda:123456789012:us-east-1:function/payments-worker',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-lambda-execution',
      relationship_type: 'runs_as',
      confidence: 0.96,
      collected_at: '2026-05-17T10:00:00Z',
      status: 'ready'
    }
  ],
  relationships: [
    {
      type: 'runs_as',
      from_node_id: 'aws:workload:lambda:123456789012:us-east-1:function/payments-worker',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-lambda-execution',
      evidence_ref: 'arn:aws:lambda:us-east-1:123456789012:function:payments-worker'
    }
  ],
  diagnostics: [],
  generated_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

const readyAWSCodeBuildServiceRoleInventory: AWSCodeBuildServiceRoleInventoryResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1481,
  current_issue_ref: '#1481',
  version: 'aws-codebuild-service-role-inventory-v1',
  status: 'ready',
  fixture_state: 'success',
  confidence: 0.96,
  record_count: 1,
  project_count: 1,
  identity_count: 1,
  resource_count: 1,
  relationship_count: 1,
  secret_ref_count: 1,
  vpc_project_count: 1,
  public_project_count: 0,
  privileged_project_count: 0,
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-codebuild-service-roles'],
  records: [
    {
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'codebuild',
      workload_id: 'arn:aws:codebuild:us-east-1:123456789012:project/payments-build',
      workload_type: 'codebuild_project',
      workload_name: 'payments-build',
      role_arn: 'arn:aws:iam::123456789012:role/payments-codebuild-service',
      role_name: 'payments-codebuild-service',
      project_arn: 'arn:aws:codebuild:us-east-1:123456789012:project/payments-build',
      project_name: 'payments-build',
      project_visibility: 'PRIVATE',
      source_type: 'GITHUB',
      source_location: 'https://github.com/identrail/payments',
      source_auth_type: 'CODECONNECTIONS',
      source_version: 'main',
      source_identifiers: ['payments/main'],
      artifact_types: ['S3'],
      artifact_locations: ['identrail-build-artifacts/payments'],
      environment_type: 'LINUX_CONTAINER',
      compute_type: 'BUILD_GENERAL1_MEDIUM',
      image: 'aws/codebuild/standard:7.0',
      image_pull_credentials_type: 'CODEBUILD',
      privileged_mode: false,
      kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/codebuild-artifacts',
      cache_type: 'S3',
      cache_location: 'identrail-codebuild-cache/payments',
      log_types: ['cloudwatch'],
      vpc_id: 'vpc-prod',
      subnet_ids: ['subnet-a', 'subnet-b'],
      security_group_ids: ['sg-codebuild-payments'],
      environment_keys: ['APP_ENV', 'NPM_TOKEN'],
      secret_refs: ['NPM_TOKEN=arn:aws:secretsmanager:us-east-1:123456789012:secret:codebuild/npm'],
      tags: { owner: 'platform', service: 'payments' },
      source: 'batchgetprojects',
      evidence_ref: 'arn:aws:codebuild:us-east-1:123456789012:project/payments-build',
      from_node_id: 'aws:workload:codebuild:123456789012:us-east-1:project/payments-build',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-codebuild-service',
      relationship_type: 'runs_as',
      confidence: 0.96,
      collected_at: '2026-05-17T10:00:00Z',
      status: 'ready'
    }
  ],
  relationships: [
    {
      type: 'runs_as',
      from_node_id: 'aws:workload:codebuild:123456789012:us-east-1:project/payments-build',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-codebuild-service',
      evidence_ref: 'arn:aws:codebuild:us-east-1:123456789012:project/payments-build'
    }
  ],
  diagnostics: [],
  generated_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

const readyAWSEKSWorkloadIdentityInventory: AWSEKSWorkloadIdentityInventoryResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1480,
  current_issue_ref: '#1480',
  version: 'aws-eks-workload-identity-inventory-v1',
  status: 'ready',
  fixture_state: 'success',
  confidence: 0.97,
  record_count: 2,
  cluster_count: 1,
  oidc_provider_count: 1,
  service_account_count: 2,
  pod_identity_association_count: 1,
  irsa_annotation_count: 1,
  node_role_count: 0,
  fargate_profile_count: 0,
  identity_count: 2,
  resource_count: 3,
  relationship_count: 2,
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-eks-workload-identities'],
  records: [
    {
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'eks',
      workload_id: 'prod-cluster/payments/payments-api',
      workload_type: 'eks_service_account',
      workload_name: 'payments/payments-api',
      role_kind: 'irsa',
      role_arn: 'arn:aws:iam::123456789012:role/payments-irsa',
      role_name: 'payments-irsa',
      cluster_arn: 'arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster',
      cluster_name: 'prod-cluster',
      cluster_status: 'ACTIVE',
      kubernetes_version: '1.30',
      oidc_provider_arn: 'arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE',
      namespace: 'payments',
      service_account: 'payments-api',
      kubernetes_subject: 'payments/payments-api',
      kubernetes_access_status: 'available',
      irsa_annotation_keys: ['eks.amazonaws.com/role-arn'],
      source: 'kubernetes_serviceaccount_annotation',
      evidence_ref: 'payments/payments-api',
      from_node_id: 'aws:workload:eks:123456789012:us-east-1:irsa/prod-cluster/payments/payments-api',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-irsa',
      relationship_type: 'runs_as',
      confidence: 0.95,
      collected_at: '2026-05-17T10:00:00Z',
      status: 'ready'
    },
    {
      account_id: '123456789012',
      region: 'us-east-1',
      service: 'eks',
      workload_id: 'arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123',
      workload_type: 'eks_service_account',
      workload_name: 'jobs/batch-worker',
      role_kind: 'pod_identity',
      role_arn: 'arn:aws:iam::123456789012:role/batch-pod-identity',
      role_name: 'batch-pod-identity',
      cluster_arn: 'arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster',
      cluster_name: 'prod-cluster',
      oidc_provider_arn: 'arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE',
      namespace: 'jobs',
      service_account: 'batch-worker',
      kubernetes_subject: 'jobs/batch-worker',
      association_arn: 'arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123',
      association_id: 'a-123',
      kubernetes_access_status: 'aws_metadata_only',
      source: 'listpodidentityassociations',
      evidence_ref: 'arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123',
      from_node_id: 'aws:workload:eks:123456789012:us-east-1:pod-identity/jobs/batch-worker',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/batch-pod-identity',
      relationship_type: 'runs_as',
      confidence: 0.97,
      collected_at: '2026-05-17T10:00:00Z',
      status: 'ready'
    }
  ],
  relationships: [
    {
      type: 'runs_as',
      from_node_id: 'aws:workload:eks:123456789012:us-east-1:irsa/prod-cluster/payments/payments-api',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-irsa',
      evidence_ref: 'payments/payments-api'
    },
    {
      type: 'runs_as',
      from_node_id: 'aws:workload:eks:123456789012:us-east-1:pod-identity/jobs/batch-worker',
      to_node_id: 'aws:identity:arn:aws:iam::123456789012:role/batch-pod-identity',
      evidence_ref: 'arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123'
    }
  ],
  diagnostics: [],
  generated_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

const readyAWSBaseline: AWSPlatformBaselineResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  git_sha: '6dd631b1',
  source_mode: 'sdk',
  fixture_only: false,
  connector_profile_version: 'aws-readonly-iam-v1',
  graph_contract_version: 'relationship-contract-v1',
  account_id: '123456789012',
  region: 'us-east-1',
  status: 'ready',
  confidence: 0.95,
  required_checks_passed: true,
  failure_reasons: [],
  evidence_links: ['/app/tenant-a/workspace-a/aws?environment=production'],
  checks: [
    {
      name: 'aws_connector_health',
      category: 'connector',
      required: true,
      status: 'passed',
      message: 'AWS connector is active and healthy.',
      confidence: 0.96,
      checked_at: '2026-05-17T10:00:00Z'
    }
  ],
  verified_at: '2026-05-17T10:00:00Z',
  created_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

const readyAWSDependencyIndex: AWSPlatformDependencyIndexResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1474,
  current_issue_ref: '#1474',
  version: 'aws-platform-dependency-index-v1',
  status: 'ready',
  confidence: 0.97,
  issue_count: 85,
  wave_count: 11,
  ready_issue_count: 17,
  blocked_issue_count: 61,
  completed_issue_refs: ['#1473', '#1474', '#1475', '#1476', '#1477', '#1478', '#1479'],
  ready_issue_refs: [
    '#1480',
    '#1481',
    '#1482',
    '#1483',
    '#1484',
    '#1485',
    '#1486',
    '#1487',
    '#1488',
    '#1489',
    '#1490',
    '#1491',
    '#1492',
    '#1493',
    '#1494',
    '#1495',
    '#1496'
  ],
  blocked_issue_refs: ['#1497'],
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: [
    'https://github.com/identrail/identrail/issues/1472',
    'https://github.com/identrail/identrail/issues/1474',
    '/docs/aws-platform-dependency-index'
  ],
  checks: [
    {
      name: 'current_issue_readiness',
      category: 'readiness',
      required: true,
      status: 'ready',
      message: '#1474 is unblocked because all blockers are closed in the ledger.',
      confidence: 0.96,
      checked_at: '2026-05-17T10:00:00Z'
    }
  ],
  issues: [
    {
      issue_number: 1474,
      issue_ref: '#1474',
      title: 'AWS platform issue dependency index',
      wave: 0,
      wave_name: 'Clean baseline and epic setup',
      sequence: 2,
      blocker_refs: ['#1473'],
      downstream_refs: [],
      dependency_status: 'completed',
      ready_for_pr: false,
      failure_reasons: [],
      remediation: 'No PR needed; this dependency is already closed.',
      next_action: 'Use as evidence for downstream blockers.',
      evidence_url: 'https://github.com/identrail/identrail/issues/1474'
    }
  ],
  generated_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

function mockAWSDependencyIndex(
  api: typeof import('./api/client'),
  index: AWSPlatformDependencyIndexResult = readyAWSDependencyIndex
) {
  vi.spyOn(api.apiClient, 'getAWSProjectDependencyIndex').mockResolvedValue({
    index
  });
}

const readyAWSValidationHarness: AWSPlatformValidationHarnessResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1475,
  current_issue_ref: '#1475',
  version: 'aws-platform-validation-harness-v1',
  status: 'ready',
  confidence: 0.98,
  scenario_count: 6,
  required_scenario_count: 6,
  fixture_states: ['success', 'empty', 'degraded', 'partial_failure', 'permission_denied', 'unsupported_service'],
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: [
    'https://github.com/identrail/identrail/issues/1472',
    'https://github.com/identrail/identrail/issues/1475',
    '/docs/aws-platform-validation-harness'
  ],
  browser_steps: [
    {
      id: 'browser_connector_setup',
      kind: 'browser',
      flow: 'connector_setup',
      label: 'Open Connect AWS setup',
      target: '/app/tenant-a/workspace-a/aws/connect?environment=production',
      expected_state: 'success',
      required: true,
      evidence_url: '/app/tenant-a/workspace-a/aws/connect?environment=production'
    },
    {
      id: 'browser_control_center_states',
      kind: 'browser',
      flow: 'diagnostics',
      label: 'Validate AWS Control Center state panels',
      target: '/app/tenant-a/workspace-a/aws?environment=production',
      expected_state: 'success, empty, degraded, partial_failure, permission_denied, unsupported_service',
      required: true,
      evidence_url: '/app/tenant-a/workspace-a/aws?environment=production'
    }
  ],
  api_steps: [
    {
      id: 'api_validation_harness',
      kind: 'api',
      flow: 'validation_harness',
      label: 'Fetch deterministic AWS validation harness',
      target: '/v1/workspaces/workspace-a/projects/production/aws/validation-harness',
      method: 'GET',
      expected_state: 'all fixture states returned with scoped evidence',
      required: true,
      evidence_url: '/docs/aws-platform-validation-harness'
    }
  ],
  scenarios: [
    {
      id: 'connector_setup_success',
      flow: 'connector_setup',
      fixture_state: 'success',
      status: 'ready',
      label: 'Connector setup success',
      summary: 'The app can show a connected AWS role with account, region, permission checks, diagnostics, and evidence links.',
      operator_message: 'Use this fixture when a PR changes AWS setup.',
      next_action: 'Capture the Connect AWS and Control Center panels in PR validation notes.',
      evidence_url: '/app/tenant-a/workspace-a/aws/connect?environment=production',
      account_id: '123456789012',
      region: 'us-east-1',
      required: true,
      confidence: 0.98,
      browser_step_ids: ['browser_connector_setup'],
      api_step_ids: ['api_validation_harness'],
      checked_at: '2026-05-17T10:00:00Z'
    },
    {
      id: 'runtime_evidence_partial_failure',
      flow: 'runtime_evidence',
      fixture_state: 'partial_failure',
      status: 'ready',
      label: 'Runtime evidence partial failure',
      summary: 'The app can show runtime evidence where one service succeeds while another reports an explicit partial failure.',
      operator_message: 'Use this fixture when runtime ingestion changes.',
      failure_reason: 'one AWS service partition did not return runtime evidence',
      remediation: 'Keep successful runtime evidence separate from the failed partition and list the retry target.',
      next_action: 'Summarize successful and failed partitions separately in PR notes.',
      evidence_url: '/app/tenant-a/workspace-a/aws?environment=production',
      account_id: '123456789012',
      region: 'us-east-1',
      required: true,
      confidence: 0.95,
      browser_step_ids: ['browser_control_center_states'],
      api_step_ids: ['api_validation_harness'],
      checked_at: '2026-05-17T10:00:00Z'
    },
    {
      id: 'remediation_permission_denied',
      flow: 'remediation',
      fixture_state: 'permission_denied',
      status: 'ready',
      label: 'Remediation permission denied',
      summary: 'The app can show an approved remediation path that is blocked by read-only scope or missing approval without hiding the reason.',
      operator_message: 'Use this fixture when approval or executor UX changes.',
      failure_reason: 'live AWS mutation is not permitted by this harness',
      remediation: 'Require explicit approval and executor scope before any live AWS mutation.',
      next_action: 'Show the denied action, approval requirement, and rollback guidance.',
      evidence_url: '/app/tenant-a/workspace-a/aws?environment=production',
      account_id: '123456789012',
      region: 'us-east-1',
      required: true,
      confidence: 0.97,
      browser_step_ids: ['browser_control_center_states'],
      api_step_ids: ['api_validation_harness'],
      checked_at: '2026-05-17T10:00:00Z'
    }
  ],
  generated_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

function mockAWSValidationHarness(
  api: typeof import('./api/client'),
  harness: AWSPlatformValidationHarnessResult = readyAWSValidationHarness
) {
  vi.spyOn(api.apiClient, 'getAWSProjectValidationHarness').mockResolvedValue({
    harness
  });
}

const readyAWSServiceCollectorContract: AWSServiceCollectorContractResult = {
  tenant_id: 'tenant-a',
  workspace_id: 'workspace-a',
  project_id: 'production',
  connector_id: 'aws-connector-1',
  account_id: '123456789012',
  region: 'us-east-1',
  parent_issue_number: 1472,
  parent_issue_ref: '#1472',
  current_issue_number: 1476,
  current_issue_ref: '#1476',
  version: 'aws-service-collector-contract-v1',
  status: 'ready',
  confidence: 0.97,
  required_field_count: 17,
  graph_edge_count: 7,
  fixture_case_count: 8,
  required_fixture_case_count: 8,
  normalized_record_fields: [
    'tenant_id',
    'workspace_id',
    'project_id',
    'connector_id',
    'account_id',
    'region',
    'service',
    'workload_id',
    'workload_type',
    'workload_name',
    'role_arn',
    'source',
    'evidence_ref',
    'confidence',
    'scan_id',
    'collector_name',
    'collected_at'
  ],
  required_permissions: [
    'sts:GetCallerIdentity',
    'iam:ListRoles',
    'iam:GetRole',
    'lambda:ListFunctions',
    'lambda:ListAliases',
    'lambda:ListVersionsByFunction',
    'lambda:ListEventSourceMappings',
    'lambda:ListTags'
  ],
  read_only_boundaries: ['collect metadata and policy documents only'],
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: [
    'https://github.com/identrail/identrail/issues/1472',
    'https://github.com/identrail/identrail/issues/1476',
    '/docs/aws-service-collector-contract'
  ],
  checks: [
    {
      name: 'normalized_record_schema',
      category: 'record',
      required: true,
      status: 'ready',
      message: 'Normalized AWS service collector record fields are deterministic.',
      confidence: 0.98,
      checked_at: '2026-05-17T10:00:00Z'
    }
  ],
  graph_edges: [
    {
      name: 'runs-on',
      relationship_type: 'runs_as',
      from_endpoint: 'workload',
      to_endpoint: 'identity',
      evidence: 'runtime or workload configuration proving the identity used at execution time',
      required: true
    },
    {
      name: 'observed-runtime-action',
      relationship_type: 'observed_action',
      from_endpoint: 'identity_workload_agent_or_runtime_session',
      to_endpoint: 'observed_action_target',
      evidence: 'audit log, trace span, runtime event, or provider activity record',
      required: true
    }
  ],
  fixture_cases: [
    {
      id: 'pagination_multiple_pages',
      state: 'pagination',
      label: 'Multi-page pagination',
      expected_status: 'ready',
      retryable: false,
      required: true,
      evidence_boundary: 'cursor/page counts only; no raw customer payloads'
    },
    {
      id: 'permission_denied',
      state: 'permission_denied',
      label: 'Read-only permission denied',
      expected_status: 'blocked',
      source_error_code: 'permission_denied',
      retryable: false,
      required: true,
      evidence_boundary: 'denied action name and remediation hint, never credentials'
    }
  ],
  generated_at: '2026-05-17T10:00:00Z',
  updated_at: '2026-05-17T10:00:00Z'
};

function mockAWSServiceCollectorContract(
  api: typeof import('./api/client'),
  contract: AWSServiceCollectorContractResult = readyAWSServiceCollectorContract
) {
  vi.spyOn(api.apiClient, 'getAWSProjectCollectorContract').mockResolvedValue({
    contract
  });
}

function mockAWSBaseline(api: typeof import('./api/client'), baseline: AWSPlatformBaselineResult = readyAWSBaseline) {
  vi.spyOn(api.apiClient, 'getAWSProjectBaseline').mockResolvedValue({
    baseline
  });
  vi.spyOn(api.apiClient, 'verifyAWSProjectBaseline').mockResolvedValue({
    baseline
  });
  mockAWSDependencyIndex(api);
  mockAWSValidationHarness(api);
  mockAWSServiceCollectorContract(api);
}

async function openAWSConnectionManagement(): Promise<HTMLElement> {
  const summary = await screen.findByRole('region', { name: 'AWS connected summary' });
  fireEvent.click(within(summary).getByRole('button', { name: /Manage connection/i }));
  return screen.findByRole('region', { name: 'AWS account setup' });
}

const disconnectedKubernetes: KubernetesConnectionStatus = {
  provider: 'kubernetes',
  connected: false,
  status: 'disconnected',
  health_status: 'unknown',
  permission_checks: [],
  diagnostics: []
};

const connectedKubernetes: KubernetesConnectionStatus = {
  provider: 'kubernetes',
  connected: true,
  connector_id: 'k8s-connector-1',
  display_name: 'Production Kubernetes',
  status: 'active',
  health_status: 'healthy',
  context: 'production',
  cluster: 'production-cluster',
  server: 'https://k8s.example.com',
  git_version: 'v1.31.2',
  platform: 'eks',
  connection_mode: 'agent',
  agent_id: 'agent-production',
  permission_checks: [
    { verb: 'get', resource: 'pods', scope: 'cluster', allowed: true },
    { verb: 'list', resource: 'serviceaccounts', scope: 'cluster', allowed: true }
  ],
  diagnostics: [],
  updated_at: '2026-05-17T10:00:00Z',
  last_validated_at: '2026-05-17T10:00:00Z',
  last_heartbeat_at: '2026-05-17T10:00:00Z'
};

const connectedGitHub: GitHubConnectionStatus = {
  provider: 'github_app',
  connected: true,
  connector_id: 'github-app',
  display_name: 'Identrail',
  status: 'active',
  health_status: 'healthy',
  account_login: 'identrail',
  installation_id: 12345,
  webhook_secret_rotation_required: false,
  selected_repositories: ['identrail/identrail'],
  updated_at: '2026-05-17T10:00:00Z'
};

const disconnectedGitHub: GitHubConnectionStatus = {
  ...connectedGitHub,
  connected: false,
  connector_id: undefined,
  status: 'pending',
  health_status: 'unknown'
};

const queuedRepoScan: RepoScanRecord = {
  id: 'repo-scan-queued',
  repository: 'identrail/identrail',
  status: 'queued',
  started_at: '2026-05-17T11:00:00Z',
  commits_scanned: 0,
  files_scanned: 0,
  finding_count: 0,
  truncated: false
};

const canceledRepoScan: RepoScanRecord = {
  ...queuedRepoScan,
  status: 'failed',
  finished_at: '2026-05-17T11:01:00Z',
  error_message: 'repository scan canceled by user'
};

const connectedGitHubPAT: GitHubConnectionStatus = {
  ...connectedGitHub,
  provider: 'github_pat',
  connector_id: 'github-enterprise',
  display_name: 'GitHub Enterprise'
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

function mockBackendFeatures(connectors: {
  github?: BackendFeatureState;
  aws?: BackendFeatureState;
  kubernetes?: BackendFeatureState;
} = {}, options: { loading?: boolean } = {}) {
  vi.doMock('./hooks/useBackendFeatures', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./hooks/useBackendFeatures')>();
    return {
      ...actual,
      useBackendFeatures: () => ({
        features: {
          onboardingWizard: undefined,
          connectors: {
            github: connectors.github,
            aws: connectors.aws,
            kubernetes: connectors.kubernetes
          },
          configReachable: true
        },
        loading: options.loading ?? false
      })
    };
  });
}

function mockConnectorFeatureFlags({
  aws = true,
  github = true,
  kubernetes = true
}: {
  aws?: boolean;
  github?: boolean;
  kubernetes?: boolean;
} = {}) {
  vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
    return {
      ...actual,
      FEATURE_ONBOARDING_CONNECTOR_AWS: aws,
      FEATURE_ONBOARDING_CONNECTOR_GITHUB: github,
      FEATURE_ONBOARDING_CONNECTOR_K8S: kubernetes
    };
  });
}

const settingsAuthConfig: AuthConfigResponse = {
  auth: {
    manual_mode: false,
    workos_login_enabled: true,
    native_saml_enabled: false,
    providers: ['github_oauth', 'google_oauth']
  },
  features: {
    onboarding_wizard: true,
    connectors: { github: true, aws: true, kubernetes: true }
  }
};

function settingsWhoAmI(me: CurrentUserContext): WhoAmIResponse {
  const workspace = me.workspace ?? {
    tenant_id: 'tenant-a',
    workspace_id: 'workspace-a',
    display_name: 'Workspace A',
    slug: 'workspace-a',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  };
  const member = {
    tenant_id: workspace.tenant_id,
    workspace_id: workspace.workspace_id,
    member_id: 'member-a',
    user_id: 'oidc-subject-a',
    email: me.user.primary_email,
    role: me.role ?? 'admin',
    status: 'active' as const,
    joined_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  };
  return {
    principal: { type: 'subject', id: 'oidc-subject-a' },
    roles: [member.role],
    scopes: ['me:read', 'me:write'],
    scope: { tenant_id: workspace.tenant_id, workspace_id: workspace.workspace_id },
    active_workspace: { workspace, member, is_active: true },
    workspaces: [{ workspace, member, is_active: true }]
  };
}

async function renderProductSettingsPage(options: {
  me?: CurrentUserContext;
  authConfig?: AuthConfigResponse;
  updateMe?: CurrentUserContext | Error;
  updateMeApiError?: { message: string; status: number };
  workspaceStatus?: 'active' | 'suspended' | 'deleted';
  workspaceSlug?: string;
} = {}) {
  vi.resetModules();
  const me = options.me ?? loggedInWithWorkspace;
  const primeMeCache = vi.fn();
  vi.doMock('./hooks/useMe', () => ({
    useMe: () => ({
      me,
      loading: false,
      error: '',
      unauthenticated: false,
      refresh: vi.fn()
    }),
    primeMeCache,
    clearMeCache: vi.fn()
  }));

  const api = await import('./api/client');
  const whoAmI = settingsWhoAmI(me);
  // Workspace lifecycle status drives which Danger Zone rows render for owners
  // (PR 3 of #1420). The fixture seeds the active_workspace snapshot so the
  // component sees the same shape it would after PR 1 shipped the new fields.
  if (whoAmI.active_workspace) {
    whoAmI.active_workspace.workspace = {
      ...whoAmI.active_workspace.workspace,
      status: options.workspaceStatus ?? 'active',
      slug: options.workspaceSlug ?? whoAmI.active_workspace.workspace.slug
    };
  }
  vi.spyOn(api.apiClient, 'getWhoAmI').mockResolvedValue(whoAmI);
  vi.spyOn(api.apiClient, 'listWorkspaceMembers').mockResolvedValue({
    items: whoAmI.active_workspace?.member ? [whoAmI.active_workspace.member] : []
  });
  vi.spyOn(api.apiClient, 'getAuthConfig').mockResolvedValue(options.authConfig ?? settingsAuthConfig);
  vi.spyOn(api.apiClient, 'listCurrentUserSessions').mockResolvedValue({ items: [] });
  const updateMe = vi.spyOn(api.apiClient, 'updateMe');
  if (options.updateMeApiError) {
    updateMe.mockRejectedValue(new api.ApiError(options.updateMeApiError.message, options.updateMeApiError.status));
  } else if (options.updateMe instanceof Error) {
    updateMe.mockRejectedValue(options.updateMe);
  } else {
    updateMe.mockResolvedValue({ me: options.updateMe ?? me });
  }
  const suspendWorkspace = vi.spyOn(api.apiClient, 'suspendWorkspace');
  const reactivateWorkspace = vi.spyOn(api.apiClient, 'reactivateWorkspace');
  const deleteWorkspace = vi.spyOn(api.apiClient, 'deleteWorkspace');
  const cancelWorkspaceDeletion = vi.spyOn(api.apiClient, 'cancelWorkspaceDeletion');

  const { ProductSettingsPage } = await import('./productShell');
  render(
    <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/settings']}>
      <Routes>
        <Route path="/app/:tenantID/:workspaceID/settings" element={<ProductSettingsPage />} />
        <Route
          path="/app/:tenantID/:workspaceID/workspaces"
          element={<h2>Workspace members</h2>}
        />
      </Routes>
    </MemoryRouter>
  );

  return {
    primeMeCache,
    updateMe,
    api,
    suspendWorkspace,
    reactivateWorkspace,
    deleteWorkspace,
    cancelWorkspaceDeletion
  };
}

async function renderProductAppearanceSettingsPage() {
  vi.resetModules();
  const { ProductAppearanceSettingsPage } = await import('./productShell');
  render(
    <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/settings/appearance']}>
      <Routes>
        <Route
          path="/app/:tenantID/:workspaceID/settings/appearance"
          element={<ProductAppearanceSettingsPage />}
        />
        <Route path="/app/:tenantID/:workspaceID/settings" element={<h2>Settings</h2>} />
      </Routes>
    </MemoryRouter>
  );
}


describe('ProductAppIndexRedirect', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useMe');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.resetModules();
  });

  it('starts self-serve onboarding when the bundle and API both enable it', async () => {
    await renderProductIndexRedirect(true, true);

    expect(await screen.findByRole('heading', { level: 1, name: 'Start onboarding' })).toBeInTheDocument();
    expect(screen.queryByText(/No workspace is attached yet/i)).not.toBeInTheDocument();
  });

  it('shows a clear unavailable state when the API does not advertise onboarding', async () => {
    await renderProductIndexRedirect(true, undefined);

    expect(
      await screen.findByRole('heading', { level: 1, name: /Self-serve onboarding is not enabled on this API/i })
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Start onboarding' })).not.toBeInTheDocument();
  });

  it('shows a clear unavailable state instead of a 404 when the API lacks onboarding', async () => {
    await renderProductIndexRedirect(true, false);

    expect(
      await screen.findByRole('heading', { level: 1, name: /Self-serve onboarding is not enabled on this API/i })
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Start onboarding' })).not.toBeInTheDocument();
  });

  it('keeps the explicit workspace-required state when the bundle disables onboarding', async () => {
    await renderProductIndexRedirect(false, undefined);

    expect(await screen.findByRole('heading', { level: 1, name: /No workspace is attached yet/i })).toBeInTheDocument();
  });
});

describe('ProductSettingsPage profile', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useMe');
    vi.resetModules();
  });

  it('links to the dedicated appearance settings page', async () => {
    await renderProductSettingsPage();

    expect(await screen.findByRole('heading', { name: 'Appearance' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open appearance settings/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/settings/appearance'
    );
  });

  it('updates profile fields optimistically from settings', async () => {
    const updatedMe: CurrentUserContext = {
      ...loggedInWithWorkspace,
      user: {
        ...loggedInWithWorkspace.user,
        display_name: 'Updated Owner',
        updated_at: '2026-05-17T10:00:00Z'
      }
    };
    const { primeMeCache, updateMe } = await renderProductSettingsPage({ updateMe: updatedMe });

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: '  Updated Owner  ' } });
    expect(screen.queryByLabelText('Photo URL')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    await waitFor(() => expect(updateMe).toHaveBeenCalledWith({ display_name: 'Updated Owner' }));
    expect(primeMeCache).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        user: expect.objectContaining({
          display_name: 'Updated Owner'
        })
      })
    );
    await waitFor(() => expect(primeMeCache).toHaveBeenLastCalledWith(updatedMe));
  });

  it('keeps readonly profile details lean before editing', async () => {
    await renderProductSettingsPage();

    const profileHeading = await screen.findByRole('heading', { name: 'Profile' });
    const profileCard = profileHeading.closest('section');
    expect(profileCard).not.toBeNull();
    expect(within(profileCard!).getByText('Name')).toBeInTheDocument();
    expect(within(profileCard!).getByText('Email')).toBeInTheDocument();
    expect(within(profileCard!).queryByText(/Account status/i)).not.toBeInTheDocument();
  });

  it('marks the profile form as an editing state', async () => {
    await renderProductSettingsPage();

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));

    expect(screen.getByRole('status')).toHaveTextContent('Editing profile');
    expect(screen.getByRole('button', { name: 'Save profile' })).toBeInTheDocument();
  });

  it('uploads profile photos from the avatar menu without exposing a URL field', async () => {
    const updatedMe: CurrentUserContext = {
      ...loggedInWithWorkspace,
      user: {
        ...loggedInWithWorkspace.user,
        avatar_url: 'data:image/png;base64,YXZhdGFy',
        updated_at: '2026-05-17T10:00:00Z'
      }
    };
    const { updateMe } = await renderProductSettingsPage({ updateMe: updatedMe });

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Photo URL')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Update or delete profile photo/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Update photo' }));

    const avatarInput = document.querySelector<HTMLInputElement>('input[type="file"]');
    expect(avatarInput).toBeTruthy();
    fireEvent.change(avatarInput!, {
      target: { files: [new File(['avatar'], 'avatar.png', { type: 'image/png' })] }
    });

    await waitFor(() =>
      expect(updateMe).toHaveBeenCalledWith({
        avatar_url: expect.stringMatching(/^data:image\/png;base64,/)
      })
    );
  });

  it('uses helpful profile photo upload errors instead of raw backend field names', async () => {
    const { updateMe } = await renderProductSettingsPage({
      updateMeApiError: { message: 'avatar_url must be a valid https URL', status: 400 }
    });

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Update or delete profile photo/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Update photo' }));
    const avatarInput = document.querySelector<HTMLInputElement>('input[type="file"]');
    expect(avatarInput).toBeTruthy();
    fireEvent.change(avatarInput!, {
      target: { files: [new File(['avatar'], 'avatar.png', { type: 'image/png' })] }
    });

    await waitFor(() => expect(updateMe).toHaveBeenCalled());
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Upload failed. Use a PNG, JPG, WebP, or GIF under 5 MB.'
    );
    expect(screen.queryByText(/avatar_url/i)).not.toBeInTheDocument();
  });

  it('allows profile photos up to 5 MB and rejects larger files before uploading', async () => {
    const { updateMe } = await renderProductSettingsPage();

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Update or delete profile photo/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Update photo' }));
    const avatarInput = document.querySelector<HTMLInputElement>('input[type="file"]');
    expect(avatarInput).toBeTruthy();

    fireEvent.change(avatarInput!, {
      target: { files: [new File([new Uint8Array(5 * 1024 * 1024 + 1)], 'huge.png', { type: 'image/png' })] }
    });

    expect(await screen.findByRole('alert')).toHaveTextContent('Profile photo must be smaller than 5 MB.');
    expect(updateMe).not.toHaveBeenCalled();
  });

  it('keeps unsaved profile edits when deleting the profile photo', async () => {
    const updatedMe: CurrentUserContext = {
      ...loggedInWithWorkspace,
      user: {
        ...loggedInWithWorkspace.user,
        avatar_url: '',
        updated_at: '2026-05-17T10:00:00Z'
      }
    };
    const { updateMe } = await renderProductSettingsPage({ updateMe: updatedMe });

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Unsaved Owner' } });

    fireEvent.click(screen.getByRole('button', { name: /Update or delete profile photo/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete photo' }));

    await waitFor(() => expect(updateMe).toHaveBeenCalledWith({ avatar_url: '' }));
    expect(screen.getByLabelText('Display name')).toHaveValue('Unsaved Owner');
    expect(screen.queryByLabelText('Photo URL')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save profile' })).toBeInTheDocument();
  });

  it('keeps unsaved profile edits when updating the profile photo', async () => {
    const updatedMe: CurrentUserContext = {
      ...loggedInWithWorkspace,
      user: {
        ...loggedInWithWorkspace.user,
        avatar_url: 'data:image/png;base64,YXZhdGFy',
        updated_at: '2026-05-17T10:00:00Z'
      }
    };
    const { updateMe } = await renderProductSettingsPage({ updateMe: updatedMe });

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Draft Owner' } });

    fireEvent.click(screen.getByRole('button', { name: /Update or delete profile photo/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Update photo' }));
    const avatarInput = document.querySelector<HTMLInputElement>('input[type="file"]');
    expect(avatarInput).toBeTruthy();
    fireEvent.change(avatarInput!, {
      target: { files: [new File(['avatar'], 'avatar.png', { type: 'image/png' })] }
    });

    await waitFor(() => expect(updateMe).toHaveBeenCalledWith({ avatar_url: expect.any(String) }));
    expect(screen.getByLabelText('Display name')).toHaveValue('Draft Owner');
    expect(screen.queryByLabelText('Photo URL')).not.toBeInTheDocument();
  });

  it('rolls back the optimistic profile update when saving fails', async () => {
    const { primeMeCache, updateMe } = await renderProductSettingsPage({
      updateMe: new Error('profile update failed')
    });

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Blocked Owner' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    await waitFor(() => expect(updateMe).toHaveBeenCalled());
    expect(await screen.findByRole('alert')).toHaveTextContent('profile update failed');
    expect(primeMeCache).toHaveBeenLastCalledWith(loggedInWithWorkspace);
  });

  it('validates display name before submitting a profile update', async () => {
    const { primeMeCache, updateMe } = await renderProductSettingsPage();

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit profile' }));
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: '   ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Display name must be 1-80 characters.');
    expect(updateMe).not.toHaveBeenCalled();
    expect(primeMeCache).not.toHaveBeenCalled();
  });

  it('labels empty manual auth config without advertising hosted login', async () => {
    await renderProductSettingsPage({
      authConfig: {
        ...settingsAuthConfig,
        auth: {
          manual_mode: true,
          workos_login_enabled: false,
          native_saml_enabled: false,
          providers: []
        }
      }
    });

    expect(await screen.findByText('Manual development')).toBeInTheDocument();
    expect(screen.queryByText('GitHub, Google')).not.toBeInTheDocument();
  });

  it('closes the avatar menu with Escape and outside clicks', async () => {
    await renderProductSettingsPage();

    fireEvent.click(await screen.findByRole('button', { name: /Update or delete profile photo/i }));
    expect(screen.getByRole('menuitem', { name: /Update photo/i })).toBeInTheDocument();

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('menuitem', { name: /Update photo/i })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Update or delete profile photo/i }));
    expect(screen.getByRole('menuitem', { name: /Update photo/i })).toBeInTheDocument();

    fireEvent.pointerDown(document.body);
    expect(screen.queryByRole('menuitem', { name: /Update photo/i })).not.toBeInTheDocument();
  });
});

describe('ProductAppearanceSettingsPage', () => {
  afterEach(() => {
    window.localStorage.removeItem('identrail-appearance');
    window.localStorage.removeItem('identrail-theme');
    delete document.documentElement.dataset.appearanceReady;
    delete document.documentElement.dataset.appearancePreset;
    delete document.documentElement.dataset.theme;
    document.documentElement.removeAttribute('style');
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('loads without workspace API calls and applies theme preferences immediately', async () => {
    const api = await import('./api/client');
    const getWhoAmI = vi.spyOn(api.apiClient, 'getWhoAmI');

    await renderProductAppearanceSettingsPage();

    expect(await screen.findByRole('heading', { name: 'Theme' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to settings' })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/settings'
    );
    expect(getWhoAmI).not.toHaveBeenCalled();
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(document.documentElement.dataset.appearancePreset).toBe('vercel');
    expect(document.documentElement.style.getPropertyValue('--appearance-bg')).toBe('#000000');
    expect(document.documentElement.style.getPropertyValue('--appearance-fg')).toBe('#ededed');
    expect(document.documentElement.style.getPropertyValue('--appearance-ui-font')).toContain('Inter');
    expect(document.documentElement.style.getPropertyValue('--appearance-contrast')).toBe('52');
    expect(screen.queryByRole('heading', { name: 'App icon' })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Theme preview')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('App preview')).not.toBeInTheDocument();
    expect(screen.queryByRole('switch', { name: 'Translucent sidebar' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Light' }));
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(JSON.parse(window.localStorage.getItem('identrail-appearance') ?? '{}')).toMatchObject({
      themeMode: 'light'
    });
  });

  it('persists appearance controls through the allowlisted appearance model', async () => {
    await renderProductAppearanceSettingsPage();

    fireEvent.change(screen.getByLabelText('Light theme'), { target: { value: 'xcode' } });
    fireEvent.change(screen.getByLabelText('Accent color'), { target: { value: '#123456' } });
    fireEvent.click(screen.getByRole('switch', { name: 'Font smoothing' }));

    const stored = JSON.parse(window.localStorage.getItem('identrail-appearance') ?? '{}');
    expect(stored).toMatchObject({
      lightPreset: 'xcode',
      accent: '#123456',
      customColors: true,
      fontSmoothing: false
    });
    expect(document.documentElement.style.getPropertyValue('--appearance-accent')).toBe('#123456');
    expect(document.documentElement.dataset.fontSmoothing).toBe('false');
    expect(document.documentElement.dataset.appearanceAppIcon).toBeUndefined();
  });

  it('keeps dark palettes out of the light appearance preset choices', async () => {
    await renderProductAppearanceSettingsPage();

    const lightTheme = screen.getByLabelText('Light theme');
    const darkTheme = screen.getByLabelText('Dark theme');

    expect(within(lightTheme).queryByRole('option', { name: 'Vercel' })).not.toBeInTheDocument();
    expect(within(lightTheme).queryByRole('option', { name: 'GitHub' })).not.toBeInTheDocument();
    expect(within(lightTheme).getByRole('option', { name: 'Stripe' })).toBeInTheDocument();
    expect(within(lightTheme).getByRole('option', { name: 'Slack' })).toBeInTheDocument();
    expect(within(lightTheme).getByRole('option', { name: 'Shopify' })).toBeInTheDocument();
    expect(within(lightTheme).getByRole('option', { name: 'Xcode' })).toBeInTheDocument();
    expect(within(darkTheme).getByRole('option', { name: 'Vercel' })).toBeInTheDocument();
    expect(within(darkTheme).getByRole('option', { name: 'GitHub' })).toBeInTheDocument();
    expect(within(darkTheme).getByRole('option', { name: 'Stripe' })).toBeInTheDocument();
    expect(within(darkTheme).getByRole('option', { name: 'Slack' })).toBeInTheDocument();
    expect(within(darkTheme).getByRole('option', { name: 'Shopify' })).toBeInTheDocument();
    expect(within(darkTheme).getByRole('option', { name: 'Supabase' })).toBeInTheDocument();
    expect(within(darkTheme).getByRole('option', { name: 'Neon' })).toBeInTheDocument();
  });

  it('sanitizes stored appearance values before they reach CSS variables', async () => {
    const { normalizeAppearancePreferences } = await import('./appearance');

    const normalized = normalizeAppearancePreferences({
      themeMode: 'dark',
      lightPreset: 'vercel',
      darkPreset: 'notion',
      accent: 'url(javascript:alert(1))',
      background: 'expression(alert(1))',
      foreground: '#abcdef',
      customColors: 'yes',
      uiFont: 'url(https://evil.example/font.woff2)',
      codeFont: '<script>alert(1)</script>',
      translucentSidebar: true,
      contrast: 999,
      reduceMotion: 'drop-table',
      appIcon: '../../private'
    });

    expect(normalized).toMatchObject({
      lightPreset: 'notion',
      darkPreset: 'vercel',
      accent: '#ffffff',
      background: '#000000',
      foreground: '#abcdef',
      customColors: false,
      uiFont: 'inter',
      codeFont: 'mono-system',
      translucentSidebar: false,
      contrast: 100,
      reduceMotion: 'system'
    });
  });

  it('uses preset colors for legacy light-theme users without custom colors', async () => {
    const { applyStoredAppearancePreferences } = await import('./appearance');
    window.localStorage.setItem('identrail-theme', 'light');

    applyStoredAppearancePreferences();

    expect(document.documentElement.dataset.theme).toBe('light');
    expect(document.documentElement.dataset.appearancePreset).toBe('notion');
    expect(document.documentElement.style.getPropertyValue('--appearance-bg')).toBe('#ffffff');
    expect(document.documentElement.style.getPropertyValue('--appearance-fg')).toBe('#37352f');
  });

  it('does not seed custom colors from an inactive preset', async () => {
    await renderProductAppearanceSettingsPage();

    fireEvent.click(screen.getByRole('button', { name: 'Dark' }));
    fireEvent.change(screen.getByLabelText('Light theme'), { target: { value: 'xcode' } });
    fireEvent.change(screen.getByLabelText('Accent color'), { target: { value: '#123456' } });

    const stored = JSON.parse(window.localStorage.getItem('identrail-appearance') ?? '{}');
    expect(stored).toMatchObject({
      themeMode: 'dark',
      lightPreset: 'xcode',
      accent: '#123456',
      background: '#000000',
      foreground: '#ededed',
      customColors: true
    });
    expect(document.documentElement.style.getPropertyValue('--appearance-bg')).toBe('#000000');
    expect(document.documentElement.style.getPropertyValue('--appearance-fg')).toBe('#ededed');
  });

  it('seeds the visible preset colors before enabling custom colors', async () => {
    await renderProductAppearanceSettingsPage();

    fireEvent.click(screen.getByRole('button', { name: 'Light' }));
    fireEvent.change(screen.getByLabelText('Accent color'), { target: { value: '#123456' } });

    const stored = JSON.parse(window.localStorage.getItem('identrail-appearance') ?? '{}');
    expect(stored).toMatchObject({
      themeMode: 'light',
      lightPreset: 'notion',
      accent: '#123456',
      background: '#ffffff',
      foreground: '#37352f',
      customColors: true
    });
    expect(document.documentElement.style.getPropertyValue('--appearance-accent')).toBe('#123456');
    expect(document.documentElement.style.getPropertyValue('--appearance-bg')).toBe('#ffffff');
    expect(document.documentElement.style.getPropertyValue('--appearance-fg')).toBe('#37352f');
  });

  it('exposes contrast as real color-mix inputs for shell styles', async () => {
    const { applyAppearancePreferences, normalizeAppearancePreferences } = await import('./appearance');

    applyAppearancePreferences(
      normalizeAppearancePreferences({
        themeMode: 'dark',
        contrast: 100
      })
    );

    expect(document.documentElement.style.getPropertyValue('--appearance-panel-mix')).toBe('88%');
    expect(document.documentElement.style.getPropertyValue('--appearance-border-mix')).toBe('100%');
    expect(document.documentElement.style.getPropertyValue('--appearance-muted-mix')).toBe('90%');
  });

  it('applies code typography preferences as root style variables', async () => {
    const { applyAppearancePreferences, normalizeAppearancePreferences } = await import('./appearance');

    applyAppearancePreferences(
      normalizeAppearancePreferences({
        codeFont: 'ibm-plex-mono',
        codeFontSize: 18
      })
    );

    expect(document.documentElement.style.getPropertyValue('--appearance-code-font')).toContain('IBM Plex Mono');
    expect(document.documentElement.style.getPropertyValue('--appearance-code-font-size')).toBe('18px');
  });

  it('defers font-size clamping until number inputs commit', async () => {
    await renderProductAppearanceSettingsPage();

    const uiFontSize = screen.getByLabelText('UI font size') as HTMLInputElement;
    fireEvent.focus(uiFontSize);
    fireEvent.change(uiFontSize, { target: { value: '1' } });

    expect(uiFontSize.value).toBe('1');
    expect(window.localStorage.getItem('identrail-appearance')).toBeNull();

    fireEvent.change(uiFontSize, { target: { value: '18' } });
    expect(uiFontSize.value).toBe('18');

    fireEvent.blur(uiFontSize);
    expect(JSON.parse(window.localStorage.getItem('identrail-appearance') ?? '{}')).toMatchObject({
      uiFontSize: 18
    });

    // Below the minimum clamps to the floor on commit.
    fireEvent.focus(uiFontSize);
    fireEvent.change(uiFontSize, { target: { value: '1' } });
    fireEvent.blur(uiFontSize);
    await waitFor(() => expect(uiFontSize.value).toBe('14'));
    expect(JSON.parse(window.localStorage.getItem('identrail-appearance') ?? '{}')).toMatchObject({
      uiFontSize: 14
    });
  });

});

describe('ProductShellLayout', () => {
  afterEach(() => {
    window.localStorage.removeItem('idt:sidebar:collapsed');
    vi.restoreAllMocks();
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.resetModules();
  });

  it('keeps official source logos visible while domain sections stay discoverable', async () => {
    vi.resetModules();
    vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
      const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
      return {
        ...actual,
        FEATURE_ONBOARDING_CONNECTOR_GITHUB: false,
        FEATURE_ONBOARDING_CONNECTOR_K8S: false
      };
    });
    mockBackendFeatures();

    const { ProductShellLayout, SourceLogoMark } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route
              index
              element={
                <>
                  <p>Child view</p>
                  <SourceLogoMark provider="aws" />
                  <SourceLogoMark provider="github" />
                  <SourceLogoMark provider="kubernetes" />
                </>
              }
            />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getAllByRole('img', { name: 'AWS' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('img', { name: 'GitHub' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('img', { name: 'Kubernetes' }).length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: 'GitHub' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Kubernetes' })).toBeInTheDocument();
  });
});

describe('ProductShellLayout', () => {
  afterEach(() => {
    window.localStorage.removeItem('idt:sidebar:collapsed');
    vi.doUnmock('./hooks/useMe');
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('opens the workspace finder from keyboard shortcuts and routes to a selected section', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route index element={<h2>Overview content</h2>} />
            <Route path="github/findings" element={<h2>GitHub findings content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByRole('button', { name: /Open workspace finder/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'AWS' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'GitHub' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Kubernetes' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Projects' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Findings' })).not.toBeInTheDocument();
    expect(screen.queryByText('Control plane')).not.toBeInTheDocument();

    expect(screen.getByRole('link', { name: 'Overview' })).toHaveClass('active');
    fireEvent.click(screen.getByRole('button', { name: 'AWS' }));
    expect(screen.getByRole('link', { name: 'Overview' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'AWS' })).toHaveClass('is-open');
    fireEvent.keyDown(window, { key: 'Escape' });

    fireEvent.click(screen.getByRole('button', { name: 'GitHub' }));
    const githubFlyout = screen.getByRole('dialog', { name: 'GitHub' });
    expect(within(githubFlyout).queryByText('Section')).not.toBeInTheDocument();
    expect(within(githubFlyout).queryByRole('heading', { name: 'GitHub' })).not.toBeInTheDocument();
    expect(within(githubFlyout).getByRole('link', { name: 'GitHub Control center' })).toBeInTheDocument();
    expect(within(githubFlyout).getByRole('link', { name: 'GitHub Findings' })).toBeInTheDocument();
    expect(within(githubFlyout).getAllByText('AI / Agentic Risk').length).toBeGreaterThan(0);

    fireEvent.keyDown(window, { key: '/' });
    const finder = screen.getByRole('dialog', { name: /Workspace finder/i });
    expect(finder).toBeInTheDocument();
    expect(within(finder).queryByText('Workspace finder')).not.toBeInTheDocument();
    expect(within(finder).queryByText('Go to anything')).not.toBeInTheDocument();

    expect(screen.queryByRole('option', { name: /^Projects\b/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /^Findings\b/i })).not.toBeInTheDocument();
    expect(
      within(within(finder).getByRole('option', { name: /^OverviewCross-domain/i })).queryByText('O')
    ).not.toBeInTheDocument();
    expect(
      within(within(finder).getByRole('option', { name: /^GitHub findingsRepository/i })).queryByText('F')
    ).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Search workspace commands/i), { target: { value: 'github findings' } });
    fireEvent.keyDown(screen.getByLabelText(/Search workspace commands/i), { key: 'Enter' });

    expect(await screen.findByRole('heading', { level: 2, name: /GitHub findings content/i })).toBeInTheDocument();
  });

  it('keeps collapsed sidebar styles from centering domain flyout links', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    window.localStorage.setItem('idt:sidebar:collapsed', '1');
    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route index element={<h2>Overview content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    fireEvent.click(screen.getByRole('button', { name: 'AWS' }));
    const awsFlyout = screen.getByRole('dialog', { name: 'AWS' });
    expect(within(awsFlyout).getByRole('link', { name: 'AWS Overview' })).toHaveClass('idt-domain-flyout-link');
    expect(stylesSource).toContain('.idt-domain-flyout-link {\n  display: grid;\n  grid-template-columns: minmax(0, 1fr) 1.25rem;');
    expect(stylesSource).toContain('.idt-app-console-layout.is-sidebar-collapsed .idt-app-shell-nav > a');
    expect(stylesSource).not.toContain('.idt-app-console-layout.is-sidebar-collapsed .idt-app-shell-nav a,');
    expect(stylesSource).not.toMatch(/idt-app-shell-nav\s+a/);
  });

  it('preserves the selected environment when routing to AWS coverage from workspace finder', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    function LocationHeading() {
      const location = useLocation();
      return <h2>{`${location.pathname}${location.search}`}</h2>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/identities?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route path="aws/identities" element={<h2>AWS identities content</h2>} />
            <Route path="aws/coverage" element={<LocationHeading />} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'AWS identities content' })).toBeInTheDocument();

    fireEvent.keyDown(window, { key: '/' });
    const finder = screen.getByRole('dialog', { name: /Workspace finder/i });
    fireEvent.change(within(finder).getByLabelText(/Search workspace commands/i), { target: { value: 'aws coverage' } });
    fireEvent.keyDown(within(finder).getByLabelText(/Search workspace commands/i), { key: 'Enter' });

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: '/app/tenant-a/workspace-a/aws/coverage?environment=production'
      })
    ).toBeInTheDocument();
  });

  it('uses Windows shortcut labels when rendering the app shell outside macOS', async () => {
    vi.spyOn(window.navigator, 'platform', 'get').mockReturnValue('Win32');
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route index element={<h2>Overview content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText('Ctrl+K')).toBeInTheDocument();
    expect(screen.getByText('Ctrl+B')).toBeInTheDocument();
    expect(screen.getByText('Click to collapse')).toBeInTheDocument();
    expect(screen.getByText('Drag to resize')).toBeInTheDocument();
  });

  it('uses macOS shortcut labels when rendering the app shell on Apple platforms', async () => {
    vi.spyOn(window.navigator, 'platform', 'get').mockReturnValue('MacIntel');
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route index element={<h2>Overview content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText('âŒ˜K')).toBeInTheDocument();
    expect(screen.getByText('âŒ˜B')).toBeInTheDocument();
    expect(screen.getByText('Click to collapse')).toBeInTheDocument();
    expect(screen.getByText('Drag to resize')).toBeInTheDocument();
  });

  it('keeps GitHub domain navigation open when the connector is unavailable', async () => {
    vi.resetModules();
    vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
      const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
      return {
        ...actual,
        FEATURE_ONBOARDING_CONNECTOR_GITHUB: true,
        FEATURE_ONBOARDING_CONNECTOR_K8S: false
      };
    });
    mockBackendFeatures({ github: false });

    const { ProductShellLayout } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route index element={<h2>Overview content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    const githubButton = screen.getByRole('button', { name: 'GitHub' });
    expect(githubButton).not.toBeDisabled();
    fireEvent.click(githubButton);
    expect(screen.getByRole('dialog', { name: 'GitHub' })).toBeInTheDocument();

    fireEvent.keyDown(window, { key: '/' });
    expect(screen.getByRole('dialog', { name: /Workspace finder/i })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Search workspace commands/i), { target: { value: 'github' } });
    expect(screen.getAllByRole('option', { name: /^GitHub\b/i }).length).toBeGreaterThan(0);
    expect(screen.queryByRole('option', { name: /Connect GitHub/i })).not.toBeInTheDocument();
  });

  it('lets a recently opened domain flyout own the sidebar highlight over Reports routes', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    const { container } = render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/reports']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route path="reports" element={<h2>Reports content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: /Reports content/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Reports' })).toHaveClass('active');
    const resizeHandle = screen.getByRole('separator', { name: /sidebar/i });
    expect(resizeHandle).toHaveAttribute('tabindex', '0');

    fireEvent.click(screen.getByRole('button', { name: 'AWS' }));

    expect(screen.getByRole('link', { name: 'Reports' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'AWS' })).toHaveClass('is-open');
    expect(screen.getByRole('button', { name: 'AWS' })).toHaveAttribute('aria-expanded', 'true');
    const sidebarBackdrop = container.querySelector('.idt-domain-flyout-sidebar-backdrop');
    expect(sidebarBackdrop).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'AWS' }).closest('.idt-app-domain-nav-item')).toHaveClass('is-open');
    expect(resizeHandle).toHaveClass('is-domain-flyout-blocked');
    expect(resizeHandle).toHaveAttribute('tabindex', '-1');

    fireEvent.click(sidebarBackdrop as Element);

    expect(screen.queryByRole('dialog', { name: 'AWS' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Reports' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'AWS' })).toHaveClass('is-active');
    expect(resizeHandle).not.toHaveClass('is-domain-flyout-blocked');
    expect(resizeHandle).toHaveAttribute('tabindex', '0');

    fireEvent.click(screen.getByRole('link', { name: 'Reports' }));

    expect(screen.getByRole('link', { name: 'Reports' })).toHaveClass('active');
    expect(screen.getByRole('button', { name: 'AWS' })).not.toHaveClass('is-active');

    fireEvent.click(screen.getByRole('button', { name: 'GitHub' }));

    expect(screen.getByRole('link', { name: 'Reports' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'AWS' })).not.toHaveClass('is-active');
    expect(screen.getByRole('button', { name: 'GitHub' })).toHaveClass('is-open');
  });

  it('removes Settings active styling while a domain flyout is open', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    const { container } = render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/settings']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route path="settings" element={<h2>Settings content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: /Settings content/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Settings' })).toHaveClass('active');

    fireEvent.click(screen.getByRole('button', { name: 'Kubernetes' }));

    expect(screen.getByRole('link', { name: 'Settings' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'Kubernetes' })).toHaveClass('is-open');

    const sidebarBackdrop = container.querySelector('.idt-domain-flyout-sidebar-backdrop');
    fireEvent.click(sidebarBackdrop as Element);

    expect(screen.queryByRole('dialog', { name: 'Kubernetes' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Settings' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'Kubernetes' })).toHaveClass('is-active');
    expect(screen.getByRole('button', { name: 'Kubernetes' })).not.toHaveClass('is-open');
  });
});

describe('ProductOverviewPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.resetModules();
  });

  it('derives AWS and Kubernetes domain cards from environment connector status', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'aws-env',
          name: 'AWS Production',
          slug: 'aws-production',
          description: '',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'k8s-env',
          name: 'Kubernetes Production',
          slug: 'kubernetes-production',
          description: '',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });
    const getAWSProjectConnection = vi
      .spyOn(api.apiClient, 'getAWSProjectConnection')
      .mockImplementation(async (_workspaceID, projectID) => ({
        connection: projectID === 'aws-env' ? connectedAWS : disconnectedAWS
      }));
    const getKubernetesProjectConnection = vi
      .spyOn(api.apiClient, 'getKubernetesProjectConnection')
      .mockImplementation(async (_workspaceID, projectID) => ({
        connection: projectID === 'k8s-env' ? connectedKubernetes : disconnectedKubernetes
      }));

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const domainPosture = await screen.findByRole('region', { name: 'Domain posture' });
    const awsCard = within(domainPosture).getByRole('link', { name: /AWS/i });
    const kubernetesCard = within(domainPosture).getByRole('link', { name: /Kubernetes/i });

    expect(within(awsCard).getByText('Connected')).toBeInTheDocument();
    expect(within(awsCard).getByText('1 account')).toBeInTheDocument();
    expect(awsCard).toHaveAttribute('href', '/app/tenant-a/workspace-a/aws');
    expect(within(kubernetesCard).getByText('Connected')).toBeInTheDocument();
    expect(within(kubernetesCard).getByText('1 cluster')).toBeInTheDocument();
    expect(kubernetesCard).toHaveAttribute('href', '/app/tenant-a/workspace-a/kubernetes');
    expect(screen.queryByRole('link', { name: 'Connect AWS' })).not.toBeInTheDocument();
    expect(getAWSProjectConnection).toHaveBeenCalledWith(
      'workspace-a',
      'aws-env',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getKubernetesProjectConnection).toHaveBeenCalledWith(
      'workspace-a',
      'k8s-env',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('keeps GitHub pending when onboarding has connected it before the first scan', async () => {
    vi.resetModules();
    vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
      const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
      return {
        ...actual,
        FEATURE_ONBOARDING_WIZARD: true,
        FEATURE_ONBOARDING_CONNECTOR_AWS: true,
        FEATURE_ONBOARDING_CONNECTOR_GITHUB: true,
        FEATURE_ONBOARDING_CONNECTOR_K8S: true
      };
    });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'getOnboardingState').mockResolvedValue({
      state: {
        user_id: 'user-1',
        org_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'project-a',
        connector_id: 'github-app',
        connector_type: 'github',
        current_step: 'scan',
        connector_skipped: false,
        scan_skipped: false,
        started_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }
    });
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const domainPosture = await screen.findByRole('region', { name: 'Domain posture' });
    const githubCard = within(domainPosture).getByRole('link', { name: /GitHub/i });
    const agenticRiskCard = within(domainPosture).getByRole('link', { name: /AI \/ Agentic Risk/i });

    await waitFor(() => expect(within(githubCard).getByText('No scan yet')).toBeInTheDocument());
    expect(within(githubCard).getByText('Awaiting first scan')).toBeInTheDocument();
    expect(within(agenticRiskCard).getByText('Awaiting first scan')).toBeInTheDocument();
    expect(githubCard).toHaveAttribute('href', '/app/tenant-a/workspace-a/github');
    expect(screen.queryByRole('link', { name: 'Connect GitHub' })).not.toBeInTheDocument();
  });

  it('routes a connected GitHub workspace to GitHub controls before its first scan', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [{
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'production-platform',
        name: 'Production Platform',
        slug: 'production-platform',
        description: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }]
    });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [], has_successful_scan: false });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: disconnectedKubernetes });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const nextActions = await screen.findByRole('region', { name: 'Recommended next actions' });
    const runScanAction = within(nextActions).getByRole('link', { name: /Run a scan/i });
    expect(runScanAction).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github?environment=production-platform'
    );
  });

  it('checks every active project when determining GitHub connector evidence', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'default-project',
          name: 'Default project',
          slug: 'default-project',
          description: '',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'github-project',
          name: 'GitHub project',
          slug: 'github-project',
          description: '',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockImplementation(async (_workspaceID, projectID) => ({
        connection: projectID === 'github-project'
          ? connectedGitHub
          : disconnectedGitHub
      }));
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [], has_successful_scan: false });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: disconnectedKubernetes });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const nextActions = await screen.findByRole('region', { name: 'Recommended next actions' });
    expect(within(nextActions).getByRole('link', { name: /Run a scan/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github?environment=github-project'
    );
    expect(getGitHubConnectorStatus).toHaveBeenCalledWith(
      'workspace-a',
      'default-project',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getGitHubConnectorStatus).toHaveBeenCalledWith(
      'workspace-a',
      'github-project',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('shows an existing degraded GitHub connector as needing review', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [{
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'degraded-project',
        name: 'Degraded project',
        slug: 'degraded-project',
        description: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }]
    });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({
      connection: {
        ...connectedGitHub,
        connected: false,
        status: 'active',
        health_status: 'warning'
      }
    });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [], has_successful_scan: false });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: disconnectedKubernetes });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const domainPosture = await screen.findByRole('region', { name: 'Domain posture' });
    const githubCard = within(domainPosture).getByRole('link', { name: /GitHub/i });
    expect(within(githubCard).getByText('Needs review')).toBeInTheDocument();
    expect(within(githubCard).getByText('Review connector')).toBeInTheDocument();
    expect(within(githubCard).queryByText('Not connected')).not.toBeInTheDocument();

    expect(await screen.findByText('Coverage needs review')).toBeInTheDocument();
    const nextActions = screen.getByRole('region', { name: 'Recommended next actions' });
    expect(within(nextActions).getByRole('link', { name: /Review GitHub connection/ })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github?environment=degraded-project'
    );
    expect(within(nextActions).getByText('The GitHub connector is present but needs attention before scanning.')).toBeInTheDocument();
  });

  it('keeps a pending GitHub installation incomplete', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [{
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'pending-project',
        name: 'Pending project',
        slug: 'pending-project',
        description: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }]
    });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({
      connection: {
        ...connectedGitHub,
        connected: false,
        status: 'pending',
        health_status: 'unknown'
      }
    });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [], has_successful_scan: false });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: disconnectedKubernetes });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const domainPosture = await screen.findByRole('region', { name: 'Domain posture' });
    const githubCard = within(domainPosture).getByRole('link', { name: /GitHub/i });
    expect(within(githubCard).getByText('Needs review')).toBeInTheDocument();
    expect(within(githubCard).getByText('Finish connection')).toBeInTheDocument();
    expect(within(githubCard).queryByText('Not connected')).not.toBeInTheDocument();

    const nextActions = screen.getByRole('region', { name: 'Recommended next actions' });
    expect(within(nextActions).getByRole('link', { name: /Finish GitHub connection/ })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github?environment=pending-project'
    );
    expect(within(nextActions).getByText('The GitHub installation is still pending; finish connecting it before scanning.')).toBeInTheDocument();
  });

  it('keeps the GitHub overview uncertain when a project status check fails', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'default-project',
          name: 'Default project',
          slug: 'default-project',
          description: '',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'other-project',
          name: 'Other project',
          slug: 'other-project',
          description: '',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockImplementation(async (_workspaceID, projectID) => {
      if (projectID === 'default-project') {
        throw new Error('temporary connector status failure');
      }
      return {
        connection: disconnectedGitHub
      };
    });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [], has_successful_scan: false });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: disconnectedKubernetes });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const domainPosture = await screen.findByRole('region', { name: 'Domain posture' });
    const githubCard = within(domainPosture).getByRole('link', { name: /GitHub/i });
    expect(within(githubCard).getByText('Needs review')).toBeInTheDocument();
    expect(within(githubCard).getByText('Review connector status')).toBeInTheDocument();
    expect(within(githubCard).queryByText('Not connected')).not.toBeInTheDocument();

    const nextActions = screen.getByRole('region', { name: 'Recommended next actions' });
    expect(within(nextActions).getByRole('link', { name: /Review GitHub connection/ })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github'
    );
    expect(within(nextActions).getByText('GitHub connector status could not be confirmed for every active project.')).toBeInTheDocument();
  });

  it('does not use AWS onboarding as GitHub domain evidence', async () => {
    vi.resetModules();
    vi.doMock('./pages/onboarding/onboardingUtils', async (importOriginal) => {
      const actual = await importOriginal<typeof import('./pages/onboarding/onboardingUtils')>();
      return {
        ...actual,
        FEATURE_ONBOARDING_WIZARD: true,
        FEATURE_ONBOARDING_CONNECTOR_AWS: true,
        FEATURE_ONBOARDING_CONNECTOR_GITHUB: true,
        FEATURE_ONBOARDING_CONNECTOR_K8S: true
      };
    });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'getOnboardingState').mockResolvedValue({
      state: {
        user_id: 'user-1',
        org_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'project-a',
        connector_id: 'aws-connector',
        connector_type: 'aws',
        current_step: 'scan',
        connector_skipped: false,
        scan_skipped: false,
        started_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }
    });
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const domainPosture = await screen.findByRole('region', { name: 'Domain posture' });
    const githubCard = within(domainPosture).getByRole('link', { name: /GitHub/i });
    const agenticRiskCard = within(domainPosture).getByRole('link', { name: /AI \/ Agentic Risk/i });

    await waitFor(() => expect(within(githubCard).getByText('Not connected')).toBeInTheDocument());
    expect(within(githubCard).getByText('Connect GitHub')).toBeInTheDocument();
    expect(within(agenticRiskCard).getByText('Not connected')).toBeInTheDocument();
    expect(within(agenticRiskCard).getByText('Connect a source first')).toBeInTheDocument();
    expect(screen.getByText('0 of 4')).toBeInTheDocument();
  });

  it('explains scan and connector gaps in the posture and next actions', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [{
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'project-a',
        name: 'Production',
        slug: 'production',
        description: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: disconnectedKubernetes });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({
      items: [{
        ...queuedRepoScan,
        id: 'repo-scan-failed-overview',
        status: 'failed',
        started_at: '2026-05-17T11:00:00Z',
        finished_at: '2026-05-17T11:01:00Z',
        error_message: 'Scan timed out'
      }]
    });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: disconnectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Scan needs review')).toBeInTheDocument();
    expect(screen.queryByText('Action needed')).not.toBeInTheDocument();
    expect(screen.getByText('Active domains', { selector: '.idt-overview-metric-label' })).toBeInTheDocument();
    expect(screen.getByText('2 of 4')).toBeInTheDocument();

    const nextActions = screen.getByRole('region', { name: 'Recommended next actions' });
    const actionLinks = within(nextActions).getAllByRole('link');
    const agenticRiskCard = within(screen.getByRole('region', { name: 'Domain posture' }))
      .getByRole('link', { name: /AI \/ Agentic Risk/i });
    expect(actionLinks[0]).toHaveTextContent('Review 1 failed scan');
    expect(actionLinks[0]).toHaveTextContent('Check the reported error, then run the scan again.');
    expect(actionLinks[1]).toHaveTextContent('Connect AWS');
    expect(actionLinks[1]).toHaveTextContent('AWS is not connected to this workspace.');
    expect(actionLinks[2]).toHaveTextContent('Run a scan');
    expect(actionLinks[2]).toHaveTextContent('Complete a scan to produce current evidence.');
    expect(actionLinks[2]).toHaveAttribute('href', '/app/tenant-a/workspace-a/github');
    expect(within(agenticRiskCard).getByText('Scan incomplete')).toBeInTheDocument();
    expect(within(agenticRiskCard).getByText('Awaiting scan completion')).toBeInTheDocument();
    expect(within(agenticRiskCard).queryByText('No findings')).not.toBeInTheDocument();
    expect(within(agenticRiskCard).queryByText('No signals detected')).not.toBeInTheDocument();
    expect(await screen.findByText('No completed scan')).toBeInTheDocument();
  });

  it('preserves completed evidence when it falls beyond the recent scan page', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    const recentFailedScans = Array.from({ length: 5 }, (_, index) => ({
      ...queuedRepoScan,
      id: `repo-scan-failed-${index}`,
      status: 'failed',
      started_at: `2026-05-${17 - index}T11:00:00Z`,
      finished_at: `2026-05-${17 - index}T11:01:00Z`,
      error_message: 'Scan timed out'
    }));
    const listRepoScans = vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({
      items: recentFailedScans,
      next_cursor: 'older-scans',
      has_successful_scan: true
    });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('No high-priority findings')).toBeInTheDocument();
    expect(screen.queryByText('No completed scan')).not.toBeInTheDocument();
    const domainPosture = screen.getByRole('region', { name: 'Domain posture' });
    const agenticRiskCard = within(domainPosture).getByRole('link', { name: /AI \/ Agentic Risk/i });
    expect(within(agenticRiskCard).getByText('No findings')).toBeInTheDocument();
    expect(within(agenticRiskCard).getByText('No signals detected')).toBeInTheDocument();
    await waitFor(() => expect(listRepoScans).toHaveBeenCalledTimes(1));
  });

  it('counts failures across the fetched scan page while limiting recent activity', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    const failedScans = Array.from({ length: 6 }, (_, index) => ({
      ...queuedRepoScan,
      id: `repo-scan-failed-${index}`,
      repository: `owner/repo-${index}`,
      status: 'failed',
      started_at: `2026-05-${17 - index}T11:00:00Z`,
      finished_at: `2026-05-${17 - index}T11:01:00Z`,
      error_message: 'Scan timed out'
    }));
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({
      items: failedScans,
      has_successful_scan: false
    });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [] });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const nextActions = await screen.findByRole('region', { name: 'Recommended next actions' });
    expect(within(nextActions).getByRole('link', { name: /Review 6 failed scans/ })).toBeInTheDocument();
    expect(screen.getByText('owner/repo-0 +4 more')).toBeInTheDocument();
  });

  it('withholds no-signals messaging when open findings are truncated', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });

    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({
      items: [{
        ...queuedRepoScan,
        id: 'repo-scan-complete-overview',
        status: 'succeeded',
        finding_count: 51
      }],
      has_successful_scan: true
    });
    const nonAgenticFinding: Finding = {
      id: 'finding-overview-non-agentic',
      scan_id: 'repo-scan-complete-overview',
      type: 'repo_misconfiguration',
      severity: 'medium',
      title: 'Default branch protection is missing',
      human_summary: 'The default branch does not require pull request reviews.',
      repository: 'owner/repo',
      detector: 'github_default_branch_unprotected',
      evidence: { adapter_source: 'github_posture' },
      remediation: 'Enable branch protection with required reviews.',
      created_at: '2026-05-17T11:00:00Z'
    };
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({
      items: [nonAgenticFinding],
      next_cursor: 'more-findings'
    });

    const { ProductOverviewPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    const domainPosture = await screen.findByRole('region', { name: 'Domain posture' });
    const agenticRiskCard = within(domainPosture).getByRole('link', { name: /AI \/ Agentic Risk/i });
    expect(within(agenticRiskCard).getByText('More findings')).toBeInTheDocument();
    expect(within(agenticRiskCard).getByText('More findings to review')).toBeInTheDocument();
    expect(within(agenticRiskCard).queryByText('No signals detected')).not.toBeInTheDocument();
  });
});

describe('Domain-first app routes', () => {
	beforeEach(async () => {
		const { clearMeCacheForTests } = await import('./hooks/useMe');
		clearMeCacheForTests();
	});

	afterEach(() => {
    window.localStorage.removeItem('idt:sidebar:collapsed');
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.resetModules();
  });

  it('publishes the full route manifest required for the new app IA', async () => {
    const { DOMAIN_APP_ROUTE_MANIFEST } = await import('./productDomainRoutes');

    expect(DOMAIN_APP_ROUTE_MANIFEST).toEqual([
      '/app/:tenantID/:workspaceID',
      '/app/:tenantID/:workspaceID/aws',
      '/app/:tenantID/:workspaceID/aws/discovery',
      '/app/:tenantID/:workspaceID/aws/connect',
      '/app/:tenantID/:workspaceID/aws/accounts',
      '/app/:tenantID/:workspaceID/aws/coverage',
      '/app/:tenantID/:workspaceID/aws/identities',
      '/app/:tenantID/:workspaceID/aws/identities/detail',
      '/app/:tenantID/:workspaceID/aws/agents',
      '/app/:tenantID/:workspaceID/aws/agents/detail',
      '/app/:tenantID/:workspaceID/aws/resources',
      '/app/:tenantID/:workspaceID/aws/runtime',
      '/app/:tenantID/:workspaceID/aws/observability',
      '/app/:tenantID/:workspaceID/aws/ga-demo',
      '/app/:tenantID/:workspaceID/aws/graph',
      '/app/:tenantID/:workspaceID/aws/findings',
      '/app/:tenantID/:workspaceID/aws/remediation',
      '/app/:tenantID/:workspaceID/aws/remediation/center',
      '/app/:tenantID/:workspaceID/aws/outcomes',
      '/app/:tenantID/:workspaceID/aws/governance',
      '/app/:tenantID/:workspaceID/github',
      '/app/:tenantID/:workspaceID/github/connect',
      '/app/:tenantID/:workspaceID/github/repositories',
      '/app/:tenantID/:workspaceID/github/repositories/detail',
      '/app/:tenantID/:workspaceID/github/actions',
      '/app/:tenantID/:workspaceID/github/findings',
      '/app/:tenantID/:workspaceID/github/remediation',
      '/app/:tenantID/:workspaceID/github/agentic-risk',
      '/app/:tenantID/:workspaceID/github/agentic-risk/configs',
      '/app/:tenantID/:workspaceID/github/agentic-risk/mcp-tools',
      '/app/:tenantID/:workspaceID/github/agentic-risk/prompts',
      '/app/:tenantID/:workspaceID/github/agentic-risk/secrets',
      '/app/:tenantID/:workspaceID/github/agentic-risk/workflow-trust-paths',
      '/app/:tenantID/:workspaceID/github/agentic-risk/findings',
      '/app/:tenantID/:workspaceID/kubernetes',
      '/app/:tenantID/:workspaceID/kubernetes/connect',
      '/app/:tenantID/:workspaceID/kubernetes/clusters',
      '/app/:tenantID/:workspaceID/kubernetes/workloads',
      '/app/:tenantID/:workspaceID/kubernetes/service-accounts',
      '/app/:tenantID/:workspaceID/kubernetes/findings',
      '/app/:tenantID/:workspaceID/kubernetes/remediation',
      '/app/:tenantID/:workspaceID/reports',
      '/app/:tenantID/:workspaceID/settings',
      '/app/:tenantID/:workspaceID/settings/appearance'
    ]);
    expect(DOMAIN_APP_ROUTE_MANIFEST).not.toContain('/app/:tenantID/:workspaceID/projects');
    expect(DOMAIN_APP_ROUTE_MANIFEST).not.toContain('/app/:tenantID/:workspaceID/findings');
  });

  it('links the AWS remediation page to the remediation center', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });

    const { ProductAWSRemediationPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/remediation?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/remediation" element={<ProductAWSRemediationPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Remediation' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS remediation plan surfaces' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open center' })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/remediation/center?environment=production'
    );
  });

  it('renders premium domain route shells with provider marks and environment scope', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production-platform',
          name: 'Production Platform',
          slug: 'production-platform',
          description: 'Production identity boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging-platform',
          name: 'Staging Platform',
          slug: 'staging-platform',
          description: 'Staging identity boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    const { ProductDomainRoutePage } = await import('./productShell');
    function LocationProbe() {
      const location = useLocation();
      return <p data-testid="location">{`${location.pathname}${location.search}`}</p>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/agentic-risk/mcp-tools?environment=staging-platform']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/github/agentic-risk/mcp-tools"
            element={
              <>
                <LocationProbe />
                <ProductDomainRoutePage domain="github" routeID="agentic-risk-mcp-tools" />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: /MCP tools/i })).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'GitHub' })).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: /GitHub sections/i })).not.toBeInTheDocument();
    expect(await screen.findByRole('option', { name: 'Staging Platform' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('staging-platform');
    expect(screen.getByRole('link', { name: /Connect GitHub/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github/connect?environment=staging-platform'
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), {
      target: { value: 'production-platform' }
    });
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/app/tenant-a/workspace-a/github/agentic-risk/mcp-tools?environment=production-platform'
    );
    expect(screen.getByText('Route contract')).toBeInTheDocument();
  });

  it('keeps a requested environment selected when it is outside the first selector page', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: Array.from({ length: 50 }, (_, index) => ({
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: `recent-environment-${index + 1}`,
        name: `Recent Environment ${index + 1}`,
        slug: `recent-environment-${index + 1}`,
        description: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }))
    });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'older-production',
        name: 'Older Production',
        slug: 'older-production',
        description: 'Long-lived production boundary.',
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-02T00:00:00Z'
      }
    });

    const { ProductDomainRoutePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/repositories?environment=older-production']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/github/repositories"
            element={<ProductDomainRoutePage domain="github" routeID="repositories" />}
          />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('older-production'));
    expect(api.apiClient.getProject).toHaveBeenCalledWith(
      'workspace-a',
      'older-production',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(screen.getByRole('link', { name: /Connect GitHub/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github/connect?environment=older-production'
    );
    expect(screen.getByRole('link', { name: /GitHub findings/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github/findings?environment=older-production'
    );
  });

  it('renders the AWS overview with a compact header and a navigation grid', async () => {
    const api = await import('./api/client');
    mockAWSBaseline(api);
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    vi.spyOn(api.apiClient, 'getAWSProjectCoveragePlan').mockResolvedValue({
      plan: {
        status: 'ready',
        summary: { account_count: 1, region_count: 1, coverage_percent: 100 },
        targets: [],
        diagnostics: [],
        remediation_hints: []
      } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectOrganizationsTopology').mockResolvedValue({
      topology: {
        status: 'ready',
        summary: { account_count: 1, organizational_unit_count: 1, scan_eligible_accounts: 1 },
        accounts: [
          {
            account_id: '123456789012',
            account_name: 'Production',
            status: 'active',
            parent_id: 'r-identrail',
            ou_path: '/',
            partition: 'aws',
            management: true,
            delegated_admin_services: [],
            connector_scoped: true,
            scan_eligible: true,
            state: 'covered',
            resumable: false,
            next_action: 'Use this account for downstream coverage.',
            evidence_ref: 'aws-organizations:aws-connector-1:123456789012'
          }
        ],
        diagnostics: [],
        remediation_hints: []
      } as any
    });

    const { ProductAWSControlCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws" element={<ProductAWSControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    // Title is just "AWS" â€” no eyebrow, no marketing tagline.
    expect(await screen.findByRole('heading', { level: 2, name: 'AWS' })).toBeInTheDocument();
    // The account / region facts move into the header subtitle.
    expect(await screen.findByText(/123456789012/)).toBeInTheDocument();
    // The capability nav grid is still the way users reach the sub-pages.
    expect(screen.getByRole('link', { name: /Resources/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/resources?environment=production'
    );
    expect(screen.getByRole('link', { name: /^Identities/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/identities?environment=production'
    );
    // The engineering-dashboard panels (validation harness, collector
    // contract, dependency index, Wired-now / Coming wave labels) are
    // gone from the customer UI.
    expect(screen.queryByText('AWS live app validation harness')).not.toBeInTheDocument();
    expect(screen.queryByText('AWS service collector contract')).not.toBeInTheDocument();
    expect(screen.queryByText('AWS platform dependency index')).not.toBeInTheDocument();
    expect(screen.queryByText('Wired now')).not.toBeInTheDocument();
    expect(screen.queryByText('Coming wave')).not.toBeInTheDocument();
  });

  // The validation-harness and collector-contract status panels were
  // removed from the customer AWS Control Center along with the rest of
  // the engineering dashboard. Their tone helpers (awsValidationHarnessStatusPillTone,
  // awsServiceCollectorContractStatusPillTone) still exist for engineering
  // tooling but no longer render in the product UI, so the corresponding
  // "blocked is not styled as success" UI assertions no longer apply.

  it('ignores stale AWS Control Center status loads after switching environments', async () => {
    const api = await import('./api/client');
    mockAWSBaseline(api);
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging',
          name: 'Staging',
          slug: 'staging',
          description: 'Staging AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    const productionStatus = deferred<{ connection: AWSConnectionStatus }>();
    const stagingStatus = deferred<{ connection: AWSConnectionStatus }>();
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockImplementation((_workspaceID, projectID) =>
      projectID === 'production' ? productionStatus.promise : stagingStatus.promise
    );

    const { ProductAWSControlCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws" element={<ProductAWSControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('production');
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      stagingStatus.resolve({
        connection: { ...connectedAWS, display_name: 'Staging AWS', account_id: '222222222222', region: 'us-west-2' }
      });
    });
    expect(await screen.findByText(/222222222222/)).toBeInTheDocument();
    expect(await screen.findByText(/us-west-2/)).toBeInTheDocument();

    await act(async () => {
      productionStatus.resolve({
        connection: { ...connectedAWS, display_name: 'Production AWS', account_id: '111111111111', region: 'us-east-1' }
      });
    });
    // The staging connection is the active selection; the late-arriving
    // production response must not overwrite the displayed account id.
    expect(screen.getByText(/222222222222/)).toBeInTheDocument();
    expect(screen.queryByText(/111111111111/)).not.toBeInTheDocument();
  });

  it('renders AWS account and region inventory with current connector coverage', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    mockAWSCoverageDashboardAPIs(api);

    const { ProductAWSAccountsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/accounts?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/accounts" element={<ProductAWSAccountsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Accounts' })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'AWS Organizations topology' })).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole('article', { name: 'Organizations accounts coverage' })).toHaveTextContent('Live AWS Â· 1 OUs')
    );
    expect(screen.getByRole('table', { name: 'AWS account and region coverage' })).toBeInTheDocument();
    expect(screen.getByText('123456789012 Â· us-east-1')).toBeInTheDocument();
    expect(
      await within(screen.getByRole('table', { name: 'AWS Organizations topology' })).findByText(
        'Management account Â· Use this account for downstream coverage.'
      )
    ).toBeInTheDocument();
    expect(
      await within(screen.getByRole('table', { name: 'AWS account and region coverage' })).findByText(
        /Production \/ us-east-1 \/ IAM/i
      )
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open Connect AWS/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/connect?environment=production'
    );
  });

  it('keeps the disconnected AWS accounts state focused on setup', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    const coverageDashboardAPIs = mockAWSCoverageDashboardAPIs(api);

    const { ProductAWSAccountsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/accounts?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/accounts" element={<ProductAWSAccountsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: 'Connect AWS to see account inventory' })).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'Connect AWS' })).toHaveLength(1);
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.queryByText(/0 of 1 scanned/i)).not.toBeInTheDocument();
    expect(screen.queryByText('Degraded')).not.toBeInTheDocument();
    expect(coverageDashboardAPIs.getCoveragePlan).not.toHaveBeenCalled();
    expect(coverageDashboardAPIs.getAccountRegionCoverage).not.toHaveBeenCalled();
    expect(coverageDashboardAPIs.getFanOutExecution).not.toHaveBeenCalled();
    expect(coverageDashboardAPIs.getOrganizationsTopology).not.toHaveBeenCalled();
    expect(coverageDashboardAPIs.getStackSetOnboarding).not.toHaveBeenCalled();
  });

  it('keeps AWS account inventory usable when Organizations arrays are null', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const { getOrganizationsTopology } = mockAWSCoverageDashboardAPIs(api);
    getOrganizationsTopology.mockResolvedValue({
      topology: {
        ...readyAWSOrganizationsTopology,
        status: 'blocked',
        accounts: null,
        organizational_units: null,
        relationships: null,
        diagnostics: null,
        remediation_hints: null
      } as any
    });

    const { ProductAWSAccountsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/accounts?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/accounts" element={<ProductAWSAccountsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Accounts' })).toBeInTheDocument();
    expect(screen.queryByText('Workspace view failed to load')).not.toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'AWS Organizations topology' })).toBeInTheDocument();
  });

  it('renders AWS coverage dashboard with scoped coverage, topology, fan-out, and onboarding data', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({
      connection: {
        ...connectedAWS,
        scope_type: 'organization',
        deployment_method: 'stackset_service_managed'
      }
    });
    const {
      getCoveragePlan,
      getAccountRegionCoverage,
      getFanOutExecution,
      getOrganizationsTopology,
      getStackSetOnboarding
    } = mockAWSCoverageDashboardAPIs(api);

    const { ProductAWSCoveragePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/coverage?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/coverage" element={<ProductAWSCoveragePage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Coverage' })).toBeInTheDocument();
    expect(await screen.findByText('Public account and region coverage records')).toBeInTheDocument();
    expect(screen.getByRole('search', { name: /Coverage filters/i })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'AWS account-region coverage API records' })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'AWS account and region coverage' })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'AWS Organizations topology' })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'StackSet onboarding instances' })).toBeInTheDocument();
    expect(screen.getByText('Partial failure reporting')).toBeInTheDocument();
    expect(screen.getByText('Queue or resume retryable targets from their checkpoints.')).toBeInTheDocument();
    expect(screen.getAllByText(/Lambda collector stopped at page 2/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Open Connect AWS/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/connect?environment=production'
    );
    expect(getCoveragePlan).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getAccountRegionCoverage).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getFanOutExecution).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      { maxConcurrency: 4 },
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getOrganizationsTopology).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getStackSetOnboarding).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('does not fetch StackSet onboarding for a single-account connector on the AWS Coverage page', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    // connectedAWS is a plain single_account / cloudformation connector.
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const { getStackSetOnboarding } = mockAWSCoverageDashboardAPIs(api);

    const { ProductAWSCoveragePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/coverage?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/coverage" element={<ProductAWSCoveragePage />} />
        </Routes>
      </MemoryRouter>
    );

    // Wait for the page to render (coverage records still load).
    await screen.findByRole('heading', { level: 2, name: 'Coverage' });

    // Backend's GetAWSStackSetOnboarding defaults to a synthetic service-
    // managed success fixture with fabricated OUs and accounts. It must not
    // be called for a plain single_account connector, otherwise the fixture
    // would render as fake organization StackSet progress under the
    // "AWS Organization StackSet read-only deployment" panel.
    expect(getStackSetOnboarding).not.toHaveBeenCalled();
    expect(
      screen.queryByRole('heading', { name: /AWS Organization StackSet read-only deployment/i })
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'StackSet onboarding instances' })).not.toBeInTheDocument();
  });

  it('renders AWS machine identity inventory with current IAM, EC2, ECS, Lambda, CodeBuild, and EKS role rows', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const getEC2InstanceProfiles = vi
      .spyOn(api.apiClient, 'getAWSProjectEC2InstanceProfiles')
      .mockResolvedValue({ inventory: readyAWSEC2InstanceProfileInventory });
    const getECSTaskRoles = vi
      .spyOn(api.apiClient, 'getAWSProjectECSTaskRoles')
      .mockResolvedValue({ inventory: readyAWSECSTaskRoleInventory });
    const getLambdaExecutionRoles = vi
      .spyOn(api.apiClient, 'getAWSProjectLambdaExecutionRoles')
      .mockResolvedValue({ inventory: readyAWSLambdaExecutionRoleInventory });
    const getCodeBuildServiceRoles = vi
      .spyOn(api.apiClient, 'getAWSProjectCodeBuildServiceRoles')
      .mockResolvedValue({ inventory: readyAWSCodeBuildServiceRoleInventory });
    const getEKSWorkloadIdentities = vi
      .spyOn(api.apiClient, 'getAWSProjectEKSWorkloadIdentities')
      .mockResolvedValue({ inventory: readyAWSEKSWorkloadIdentityInventory });

    const { ProductAWSIdentitiesPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/identities?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/identities" element={<ProductAWSIdentitiesPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Identities' })).toBeInTheDocument();
    expect(screen.getByRole('search', { name: /Identities filters/i })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'AWS machine identity inventory' })).toBeInTheDocument();
    expect(screen.getAllByText('arn:aws:iam::123456789012:role/IdentrailReadOnly').length).toBeGreaterThan(0);
    expect(await screen.findByText('payments-ec2-profile')).toBeInTheDocument();
    expect(screen.getByText('web-launch-template-profile')).toBeInTheDocument();
    expect(await screen.findByText('payments-ecs-task')).toBeInTheDocument();
    expect(screen.getByText('payments-ecs-execution')).toBeInTheDocument();
    expect(await screen.findByText('payments-lambda-execution')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'payments-lambda-execution' })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/identities/detail?environment=production&identity=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fpayments-lambda-execution&tab=graph'
    );
    expect(await screen.findByText('payments-codebuild-service')).toBeInTheDocument();
    expect(await screen.findByText('payments-irsa')).toBeInTheDocument();
    expect(screen.getByText('batch-pod-identity')).toBeInTheDocument();
    expect(screen.getByText(/payments-api runs as payments-ec2-instance-profile; IMDS Required/i)).toBeInTheDocument();
    expect(screen.getByText(/payments-api runs as payments-ecs-task; FARGATE; 0\/3 running/i)).toBeInTheDocument();
    expect(screen.getByText(/payments-api attaches execution support to payments-ecs-execution; FARGATE; 0\/3 running/i)).toBeInTheDocument();
    expect(screen.getByText(/payments-worker runs as payments-lambda-execution; nodejs20\.x \/ index\.handler; 1 event source; 3 env keys, values hidden; 1 secret refs, values hidden/i)).toBeInTheDocument();
    expect(screen.getByText(/payments-build runs as payments-codebuild-service; Github source; LINUX_CONTAINER \/ BUILD_GENERAL1_MEDIUM; S3 artifacts; VPC vpc-prod; 1 secret refs, values hidden/i)).toBeInTheDocument();
    expect(screen.getByText(/payments\/payments-api runs as payments-irsa; prod-cluster; Irsa; OIDC provider linked; ACTIVE; Kubernetes annotations proven/i)).toBeInTheDocument();
    expect(screen.getByText(/jobs\/batch-worker runs as batch-pod-identity; prod-cluster; Pod Identity; OIDC provider linked; association a-123; AWS-side evidence/i)).toBeInTheDocument();
    expect(screen.getAllByText(/2 workloads \/ 2 relationships/i).length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/1 functions \/ 1 relationships/i)).toBeInTheDocument();
    expect(screen.getByText(/1 mapped \/ 0 disabled/i)).toBeInTheDocument();
    expect(screen.getByText(/1 projects \/ 1 relationships/i)).toBeInTheDocument();
    expect(screen.getByText(/1 secret refs \/ 1 VPC projects/i)).toBeInTheDocument();
    expect(screen.getByText(/1 task \/ 1 execution/i)).toBeInTheDocument();
    expect(screen.getByText(/2 service accounts \/ 2 relationships/i)).toBeInTheDocument();
    expect(screen.getByText(/1 IRSA \/ 1 Pod Identity \/ 0 node/i)).toBeInTheDocument();
    expect(screen.queryByText(/Lambda execution-role ownership arrives in a later AWS service collector wave/i)).not.toBeInTheDocument();
    expect(getEC2InstanceProfiles).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getECSTaskRoles).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getLambdaExecutionRoles).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getCodeBuildServiceRoles).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getEKSWorkloadIdentities).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(screen.getByText(/Risk score/i)).toBeInTheDocument();
    expect(screen.getByText(/Unscored until AWS findings land/i)).toBeInTheDocument();
  });

  it('renders AWS machine identity detail scoped to the selected identity and tab', async () => {
    const api = await import('./api/client');
    const identity = 'arn:aws:iam::123456789012:role/lambda-invoice-agent';
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const s3RuntimeRecord = readyAWSRuntimeEvents.records.find((record) => record.event_id === 'evt-s3-access') ?? readyAWSRuntimeEvents.records[0];
    const machineIdentityRuntimeEvents: AWSRuntimeEventResult = {
      ...readyAWSRuntimeEvents,
      summary: {
        ...readyAWSRuntimeEvents.summary,
        total_events: 1,
        filtered_events: 1,
        event_type_counts: { 'api-call': 1 },
        status_counts: { observed: 1 },
        owner_counts: { security: 1 },
        identity_count: 1,
        resource_count: 1,
        agent_event_count: 0,
        secret_read_count: 0,
        kms_decrypt_count: 0,
        api_call_count: 1,
        sts_session_count: 0,
        access_analyzer_finding_count: 0,
        lineage_resolved_count: 1,
        relationship_count: 1
      },
      records: [s3RuntimeRecord]
    };
    const machineIdentityDetail = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'production',
      connector_id: 'aws-connector-1',
      account_id: '123456789012',
      region: 'us-east-1',
      parent_issue_number: 1472,
      parent_issue_ref: '#1472',
      current_issue_number: 1549,
      current_issue_ref: '#1549',
      version: 'aws-machine-identity-detail-page-v1',
      status: 'ready',
      fixture_state: 'success',
      confidence: 0.91,
      policy_version: 'aws-machine-identity-detail-policy-v1',
      applied_filters: { identity },
      identity: {
        identity,
        identity_node_id: 'aws:identity:lambda-invoice-agent',
        principal_arn: identity,
        role_name: 'lambda-invoice-agent',
        display_name: 'lambda-invoice-agent',
        account_id: '123456789012',
        region: 'us-east-1',
        status: 'ready',
        confidence: 0.91,
        evidence_boundary: 'metadata_only_no_secret_values_no_policy_bodies_no_payloads'
      },
      summary: {
        workload_binding_count: 1,
        runtime_event_count: 1,
        permission_recommendation_count: 1,
        secret_finding_count: 0,
        finding_count: 0,
        remediation_case_count: 0,
        governance_decision_count: 0,
        resource_reached_count: 1,
        relationship_count: 1,
        evidence_link_count: 1,
        diagnostic_count: 0,
        coverage_gap_count: 0
      },
      tabs: [
        { id: 'graph', label: 'Graph', status: 'ready', count: 1 },
        { id: 'runtime', label: 'Runtime', status: 'ready', count: 1 },
        { id: 'permissions', label: 'Permissions', status: 'ready', count: 1 },
        { id: 'secrets', label: 'Secrets', status: 'empty', count: 0 },
        { id: 'fixes', label: 'Fixes', status: 'empty', count: 0 },
        { id: 'governance', label: 'Governance', status: 'empty', count: 0 }
      ],
      workload_bindings: [],
      permission_summaries: [],
      resources_reached: [],
      findings: [],
      governance_decisions: [],
      relationships: [],
      runtime: machineIdentityRuntimeEvents,
      permissions: readyAWSLeastPrivilege,
      secrets: { findings: [] },
      blast_radius: { findings: [] },
      identity_sprawl: { findings: [] },
      remediation_cases: { cases: [] },
      governance: { records: [] },
      failure_reasons: [],
      remediation_hints: [],
      evidence_links: ['/docs/aws-machine-identity-detail'],
      coverage_gaps: [],
      diagnostics: [],
      generated_at: '2026-06-14T17:30:00Z',
      updated_at: '2026-06-14T17:30:00Z'
    } as unknown as AWSMachineIdentityDetailResult;
    const getMachineIdentityDetail = vi
      .spyOn(api.apiClient, 'getAWSProjectMachineIdentityDetail')
      .mockResolvedValue({ detail: machineIdentityDetail });

    const { ProductAWSMachineIdentityDetailPage } = await import('./productShell');

    render(
      <MemoryRouter
        initialEntries={[
          `/app/tenant-a/workspace-a/aws/identities/detail?environment=production&identity=${encodeURIComponent(identity)}&tab=runtime`
        ]}
      >
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/identities/detail"
            element={<ProductAWSMachineIdentityDetailPage />}
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'lambda-invoice-agent' })).toBeInTheDocument();
    expect(screen.getByText('metadata_only_no_secret_values_no_policy_bodies_no_payloads')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Runtime\s+1/i })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('table', { name: 'Machine identity runtime events' })).toBeInTheDocument();
    expect(screen.getByText('s3:GetObject')).toBeInTheDocument();
    expect(getMachineIdentityDetail).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      {
        connectorID: 'aws-connector-1',
        identity,
        tab: 'runtime'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a'
      }
    );
  });

  it('renders the AWS remediation center scoped to the selected tab', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const remediationCenter = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'production',
      connector_id: 'aws-connector-1',
      account_id: '123456789012',
      region: 'us-east-1',
      parent_issue_number: 1472,
      parent_issue_ref: '#1472',
      current_issue_number: 1552,
      current_issue_ref: '#1552',
      version: 'aws-remediation-center-v1',
      status: 'ready',
      fixture_state: 'success',
      confidence: 0.9,
      policy_version: 'aws-remediation-center-policy-v1',
      applied_filters: {},
      summary: {
        total_cases: 1,
        filtered_cases: 1,
        stage_counts: { dry_run: 1 },
        severity_counts: { high: 1 },
        status_counts: { proposed: 1 },
        action_type_counts: { iam_policy_diff: 1 },
        identity_type_counts: { iam_role: 1 },
        approval_pending_count: 1,
        dry_run_count: 1,
        live_action_count: 0,
        verification_count: 0,
        rollback_count: 0,
        ready_for_apply_count: 0,
        kill_switch_engaged_count: 0,
        blocked_safety_gate_count: 0,
        audit_entry_count: 0,
        highest_score: 80,
        average_confidence_pct: 90
      },
      tabs: [
        { id: 'overview', label: 'Overview', status: 'ready', count: 1 },
        { id: 'cases', label: 'Cases', status: 'ready', count: 1 },
        { id: 'approvals', label: 'Approvals', status: 'ready', count: 1 },
        { id: 'dry_runs', label: 'Dry-runs', status: 'ready', count: 1 },
        { id: 'live_actions', label: 'Live actions', status: 'ready', count: 0 },
        { id: 'verification', label: 'Verification', status: 'ready', count: 0 },
        { id: 'audit', label: 'Audit', status: 'ready', count: 0 }
      ],
      cases: [
        {
          case_id: 'aws-remediation-case:least-privilege-orders',
          title: 'Reduce orders-deployer policy',
          summary: 'Remove unused IAM actions from orders-deployer.',
          source_type: 'least_privilege',
          action_type: 'iam_policy_diff',
          lifecycle: 'proposed',
          stage: 'dry_run',
          severity: 'high',
          score: 80,
          confidence: 0.9,
          account_id: '123456789012',
          region: 'us-east-1',
          identity_node_id: 'aws:identity:orders-deployer',
          identity_type: 'iam_role',
          owner: 'iam-platform',
          owner_assigned: true,
          approval_required: true,
          approval_state: 'pending_approver',
          approval_id: 'aws-remediation-approval:orders',
          dry_run_id: 'aws-remediation-dry-run:orders',
          dry_run_outcome: 'would_succeed',
          ready_for_apply: false,
          kill_switch_engaged: false,
          tradeoffs: [],
          safety_gates: [
            { source: 'dry_run_prerequisite', name: 'approval_state_approved', status: 'blocked', rationale: 'Approval required.' }
          ],
          next_action: 'Advance the approval workflow before scheduling a live action.',
          evidence_boundary: 'metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped',
          audit_entry_count: 0
        }
      ],
      remediation_cases: { cases: [{}] },
      approval_queue: { entries: [] },
      dry_runs: { entries: [] },
      live_actions: { entries: [] },
      verification: { entries: [] },
      failure_reasons: [],
      remediation_hints: [],
      evidence_links: ['/docs/aws-remediation-center'],
      coverage_gaps: [],
      diagnostics: [],
      generated_at: '2026-07-04T10:00:00Z',
      updated_at: '2026-07-04T10:00:00Z'
    } as unknown as AWSRemediationCenterResult;
    const getRemediationCenter = vi
      .spyOn(api.apiClient, 'getAWSProjectRemediationCenter')
      .mockResolvedValue({ remediation_center: remediationCenter });

    const { ProductAWSRemediationCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/remediation/center?environment=production']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/remediation/center"
            element={<ProductAWSRemediationCenterPage />}
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Reduce orders-deployer policy')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: 'Remediation Center' })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Remediation center safety review' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Overview\s+1/i })).toHaveAttribute('aria-selected', 'true');
    expect(getRemediationCenter).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      {
        connectorID: 'aws-connector-1',
        tab: 'overview'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a'
      }
    );
  });

  it('loads the AWS remediation center without a connector identifier', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    const remediationCenter = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'production',
      status: 'permission_denied',
      fixture_state: 'permission_denied',
      confidence: 0,
      policy_version: 'aws-remediation-center-policy-v1',
      parent_issue_number: 1472,
      parent_issue_ref: '#1472',
      current_issue_number: 1552,
      current_issue_ref: '#1552',
      version: 'aws-remediation-center-v1',
      applied_filters: {},
      summary: {
        total_cases: 0,
        filtered_cases: 0,
        stage_counts: {},
        severity_counts: {},
        status_counts: {},
        action_type_counts: {},
        identity_type_counts: {},
        approval_pending_count: 0,
        dry_run_count: 0,
        live_action_count: 0,
        verification_count: 0,
        rollback_count: 0,
        ready_for_apply_count: 0,
        kill_switch_engaged_count: 0,
        blocked_safety_gate_count: 0,
        audit_entry_count: 0,
        highest_score: 0,
        average_confidence_pct: 0
      },
      tabs: [
        { id: 'overview', label: 'Overview', status: 'permission_denied', count: 0 },
        { id: 'cases', label: 'Cases', status: 'permission_denied', count: 0 },
        { id: 'approvals', label: 'Approvals', status: 'permission_denied', count: 0 },
        { id: 'dry_runs', label: 'Dry-runs', status: 'permission_denied', count: 0 },
        { id: 'live_actions', label: 'Live actions', status: 'permission_denied', count: 0 },
        { id: 'verification', label: 'Verification', status: 'permission_denied', count: 0 },
        { id: 'audit', label: 'Audit', status: 'permission_denied', count: 0 }
      ],
      cases: [],
      remediation_cases: { cases: [] },
      approval_queue: { entries: [] },
      dry_runs: { entries: [] },
      live_actions: { entries: [] },
      verification: { entries: [] },
      audit_trail: [],
      failure_reasons: ['Connect an AWS connector before viewing remediation lifecycle evidence.'],
      remediation_hints: ['Finish AWS connector setup or choose another environment.'],
      evidence_links: [],
      coverage_gaps: [],
      diagnostics: [],
      generated_at: '2026-07-04T10:00:00Z',
      updated_at: '2026-07-04T10:00:00Z'
    } as unknown as AWSRemediationCenterResult;
    const getRemediationCenter = vi
      .spyOn(api.apiClient, 'getAWSProjectRemediationCenter')
      .mockResolvedValue({ remediation_center: remediationCenter });

    const { ProductAWSRemediationCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/remediation/center?environment=production']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/remediation/center"
            element={<ProductAWSRemediationCenterPage />}
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Connect an AWS connector before viewing remediation lifecycle evidence.')).toBeInTheDocument();
    expect(screen.getByText('Finish AWS connector setup or choose another environment.')).toBeInTheDocument();
    expect(screen.queryByText('AWS connector is unavailable')).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Overview\s+0/i })).toHaveAttribute('aria-selected', 'true');
    expect(getRemediationCenter).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      {
        tab: 'overview'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a'
      }
    );
  });

  it('renders the consolidated remediation center audit trail across lifecycle stages', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const remediationCenter = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'production',
      connector_id: 'aws-connector-1',
      status: 'ready',
      fixture_state: 'success',
      confidence: 0.9,
      policy_version: 'aws-remediation-center-policy-v1',
      current_issue_ref: '#1552',
      applied_filters: {},
      summary: {
        filtered_cases: 1,
        approval_pending_count: 0,
        dry_run_count: 0,
        live_action_count: 0,
        verification_count: 0,
        rollback_count: 0,
        ready_for_apply_count: 0,
        kill_switch_engaged_count: 0,
        blocked_safety_gate_count: 0,
        audit_entry_count: 2,
        stage_counts: {},
        severity_counts: {},
        status_counts: {},
        action_type_counts: {},
        identity_type_counts: {},
        total_cases: 1,
        highest_score: 80,
        average_confidence_pct: 90
      },
      tabs: [
        { id: 'overview', label: 'Overview', status: 'ready', count: 1 },
        { id: 'cases', label: 'Cases', status: 'ready', count: 1 },
        { id: 'approvals', label: 'Approvals', status: 'ready', count: 0 },
        { id: 'dry_runs', label: 'Dry-runs', status: 'ready', count: 0 },
        { id: 'live_actions', label: 'Live actions', status: 'ready', count: 0 },
        { id: 'verification', label: 'Verification', status: 'ready', count: 0 },
        { id: 'audit', label: 'Audit', status: 'ready', count: 2 }
      ],
      cases: [],
      remediation_cases: { cases: [{}] },
      approval_queue: { entries: [] },
      dry_runs: { entries: [] },
      live_actions: { entries: [] },
      verification: { entries: [] },
      audit_trail: [
        {
          case_id: 'aws-remediation-case:orders',
          stage: 'approval',
          event_id: 'evt-approval-1',
          event_type: 'approval_requested',
          actor: 'iam-platform',
          occurred_at: '2026-07-04T09:00:00Z',
          notes: 'Approval requested.'
        },
        {
          case_id: 'aws-remediation-case:orders',
          stage: 'verification',
          event_id: 'evt-verify-1',
          event_type: 'verification_completed',
          actor: 'identrail',
          occurred_at: '2026-07-04T10:00:00Z',
          notes: 'Verification completed.'
        }
      ],
      failure_reasons: [],
      remediation_hints: [],
      evidence_links: [],
      coverage_gaps: [],
      diagnostics: [],
      generated_at: '2026-07-04T10:00:00Z',
      updated_at: '2026-07-04T10:00:00Z'
    } as unknown as AWSRemediationCenterResult;
    vi.spyOn(api.apiClient, 'getAWSProjectRemediationCenter').mockResolvedValue({ remediation_center: remediationCenter });

    const { ProductAWSRemediationCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/remediation/center?environment=production&tab=audit']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/remediation/center"
            element={<ProductAWSRemediationCenterPage />}
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('table', { name: 'Remediation center audit trail' })).toBeInTheDocument();
    // The audit tab consolidates every lifecycle stage, not just verification.
    expect(screen.getByText('Approval requested.')).toBeInTheDocument();
    expect(screen.getByText('Verification completed.')).toBeInTheDocument();
  });

  it('forwards remediation center filters to the API and preserves them across tabs', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const remediationCenter = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'production',
      connector_id: 'aws-connector-1',
      account_id: '123456789012',
      region: 'us-east-1',
      current_issue_number: 1552,
      current_issue_ref: '#1552',
      version: 'aws-remediation-center-v1',
      status: 'ready',
      fixture_state: 'success',
      confidence: 0.9,
      policy_version: 'aws-remediation-center-policy-v1',
      applied_filters: { severity: 'high', account_id: '123456789012' },
      summary: {
        total_cases: 1,
        filtered_cases: 1,
        stage_counts: {},
        severity_counts: {},
        status_counts: {},
        action_type_counts: {},
        identity_type_counts: {},
        approval_pending_count: 0,
        dry_run_count: 1,
        live_action_count: 0,
        verification_count: 0,
        rollback_count: 0,
        ready_for_apply_count: 0,
        kill_switch_engaged_count: 0,
        blocked_safety_gate_count: 0,
        audit_entry_count: 0,
        highest_score: 80,
        average_confidence_pct: 90
      },
      tabs: [
        { id: 'overview', label: 'Overview', status: 'ready', count: 1 },
        { id: 'cases', label: 'Cases', status: 'ready', count: 1 },
        { id: 'approvals', label: 'Approvals', status: 'ready', count: 0 },
        { id: 'dry_runs', label: 'Dry-runs', status: 'ready', count: 1 },
        { id: 'live_actions', label: 'Live actions', status: 'ready', count: 0 },
        { id: 'verification', label: 'Verification', status: 'ready', count: 0 },
        { id: 'audit', label: 'Audit', status: 'ready', count: 0 }
      ],
      cases: [
        {
          case_id: 'aws-remediation-case:least-privilege-orders',
          title: 'Reduce orders-deployer policy',
          summary: 'Remove unused IAM actions from orders-deployer.',
          source_type: 'least_privilege',
          action_type: 'iam_policy_diff',
          lifecycle: 'proposed',
          stage: 'dry_run',
          severity: 'high',
          score: 80,
          confidence: 0.9,
          account_id: '123456789012',
          region: 'us-east-1',
          identity_type: 'iam_role',
          owner_assigned: true,
          approval_required: true,
          ready_for_apply: false,
          kill_switch_engaged: false,
          tradeoffs: [],
          safety_gates: [],
          next_action: 'Advance the approval workflow before scheduling a live action.',
          evidence_boundary: 'metadata_only',
          audit_entry_count: 0
        }
      ],
      remediation_cases: { cases: [{}] },
      approval_queue: { entries: [] },
      dry_runs: { entries: [] },
      live_actions: { entries: [] },
      verification: { entries: [] },
      failure_reasons: [],
      remediation_hints: [],
      evidence_links: [],
      coverage_gaps: [],
      diagnostics: [],
      generated_at: '2026-07-04T10:00:00Z',
      updated_at: '2026-07-04T10:00:00Z'
    } as unknown as AWSRemediationCenterResult;
    const getRemediationCenter = vi
      .spyOn(api.apiClient, 'getAWSProjectRemediationCenter')
      .mockResolvedValue({ remediation_center: remediationCenter });

    const { ProductAWSRemediationCenterPage } = await import('./productShell');

    render(
      <MemoryRouter
        initialEntries={[
          '/app/tenant-a/workspace-a/aws/remediation/center?environment=production&tab=cases&severity=high&account_id=123456789012'
        ]}
      >
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/remediation/center"
            element={<ProductAWSRemediationCenterPage />}
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Reduce orders-deployer policy')).toBeInTheDocument();
    expect(getRemediationCenter).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      {
        connectorID: 'aws-connector-1',
        tab: 'cases',
        severity: 'high',
        accountID: '123456789012'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a'
      }
    );
    // Tab links preserve the active filter params so deep links survive navigation.
    const dryRunsTab = screen.getByRole('tab', { name: /Dry-runs\s+1/i });
    const href = dryRunsTab.getAttribute('href') ?? '';
    expect(href).toContain('severity=high');
    expect(href).toContain('account_id=123456789012');
    expect(href).toContain('tab=dry_runs');
  });

  it('renders AWS agent identity detail scoped to the selected agent and tab', async () => {
    const api = await import('./api/client');
    const agent = 'AGENTSUPPORT1';
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const agentIdentityDetail = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'production',
      connector_id: 'aws-connector-1',
      account_id: '123456789012',
      region: 'us-east-1',
      parent_issue_number: 1472,
      parent_issue_ref: '#1472',
      current_issue_number: 1550,
      current_issue_ref: '#1550',
      version: 'aws-agent-identity-detail-page-v1',
      status: 'success',
      fixture_state: 'success',
      confidence: 0.88,
      policy_version: 'aws-agent-identity-detail-policy-v1',
      applied_filters: { agent },
      agent: {
        agent,
        agent_id: agent,
        agent_node_id: 'aws:agent:bedrock:AGENTSUPPORT1',
        agent_name: 'support-assistant',
        agent_type: 'bedrock_agent',
        display_name: 'support-assistant',
        provider: 'bedrock',
        model_id: 'anthropic.claude-3-sonnet',
        service: 'bedrock',
        runtime_version: '2026-07',
        runtime_role_arn: 'arn:aws:iam::123456789012:role/bedrock-support-agent',
        runtime_role_name: 'bedrock-support-agent',
        account_id: '123456789012',
        region: 'us-east-1',
        status: 'active',
        resolved: true,
        candidate: false,
        low_confidence: false,
        confidence: 0.88,
        evidence_boundary: 'metadata_only_no_secret_values_no_prompt_text_no_tool_payloads_no_workload_data_tenant_workspace_project_connector_account_region_scoped'
      },
      summary: {
        tool_count: 1,
        declared_tool_count: 1,
        observed_tool_count: 1,
        undeclared_tool_count: 0,
        capability_count: 1,
        secret_reference_count: 1,
        runtime_call_count: 1,
        finding_count: 1,
        recommendation_count: 1,
        remediation_case_count: 0,
        governance_decision_count: 0,
        relationship_count: 0,
        evidence_link_count: 1,
        diagnostic_count: 0,
        coverage_gap_count: 0
      },
      tabs: [
        { id: 'overview', label: 'Overview', status: 'success', count: 2 },
        { id: 'tools', label: 'Tools', status: 'success', count: 1 },
        { id: 'runtime', label: 'Runtime', status: 'success', count: 1 },
        { id: 'secrets', label: 'Secrets', status: 'success', count: 1 },
        { id: 'findings', label: 'Findings', status: 'success', count: 1 },
        { id: 'recommendations', label: 'Recommendations', status: 'success', count: 1 },
        { id: 'remediation', label: 'Remediation', status: 'empty', count: 0 },
        { id: 'governance', label: 'Governance', status: 'empty', count: 0 }
      ],
      tools: [
        {
          tool_name: 'invoke-knowledge-base',
          tool_target_ref: 'bedrock://knowledge-base/support',
          declared: true,
          observed: true,
          status: 'confirmed',
          observed_count: 3,
          evidence_ref: 'evidence://agent/tools/support'
        }
      ],
      capabilities: [
        { capability: 'memory', enabled: true, reference_refs: ['memory://support-session'], encryption_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/support' },
        { capability: 'browser', enabled: false },
        { capability: 'code_interpreter', enabled: false }
      ],
      secret_references: [
        {
          reference: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:support/provider-key',
          reference_name: 'support-provider-key',
          reference_kind: 'secretsmanager_secret',
          provider: 'anthropic',
          sensitivity: 'external_provider_key',
          resolved: true,
          confidence: 0.9
        }
      ],
      runtime_calls: [
        {
          correlation_id: 'agent-runtime-call-1',
          tool_name: 'invoke-knowledge-base',
          tool_target_ref: 'bedrock://knowledge-base/support',
          status: 'confirmed',
          observed_count: 3,
          outcomes: ['allowed'],
          target_arns: ['arn:aws:bedrock:us-east-1:123456789012:knowledge-base/support'],
          evidence_ref: 'evidence://agent/runtime/support',
          next_action: 'Review knowledge-base access.',
          last_observed: '2026-07-03T19:00:00Z'
        }
      ],
      findings: [
        {
          finding_id: 'aws-ai-agent-risk:support-provider-key',
          risk_type: 'external_credential_exposure',
          severity: 'high',
          status: 'review',
          score: 86,
          rationale: 'Agent references an external provider key.',
          next_action: 'Rotate provider key and scope runtime role.'
        }
      ],
      recommendations: [
        {
          recommendation_id: 'aws-least-privilege:agent-runtime-role',
          decision: 'review',
          severity: 'medium',
          status: 'review',
          service: 'bedrock',
          display_name: 'Scope support agent runtime role',
          rationale: 'Runtime role has broader Bedrock access than observed calls need.',
          next_action: 'Approve a scoped policy update.',
          score: 73,
          confidence: 0.86
        }
      ],
      governance_decisions: [],
      relationships: [],
      runtime_access: { records: [] },
      risk: { findings: [] },
      permissions: readyAWSLeastPrivilege,
      remediation_cases: { cases: [] },
      governance: { records: [] },
      failure_reasons: [],
      remediation_hints: [],
      evidence_links: ['/docs/aws-agent-identity-detail'],
      coverage_gaps: [],
      diagnostics: [],
      generated_at: '2026-07-03T19:05:00Z',
      updated_at: '2026-07-03T19:05:00Z'
    } as unknown as AWSAgentIdentityDetailResult;
    const getAgentIdentityDetail = vi
      .spyOn(api.apiClient, 'getAWSProjectAgentIdentityDetail')
      .mockResolvedValue({ detail: agentIdentityDetail });

    const { ProductAWSAgentIdentityDetailPage } = await import('./productShell');

    render(
      <MemoryRouter
        initialEntries={[
          `/app/tenant-a/workspace-a/aws/agents/detail?environment=production&agent=${encodeURIComponent(agent)}&tab=runtime`
        ]}
      >
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/agents/detail"
            element={<ProductAWSAgentIdentityDetailPage />}
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'support-assistant' })).toBeInTheDocument();
    expect(screen.getByText('metadata_only_no_secret_values_no_prompt_text_no_tool_payloads_no_workload_data_tenant_workspace_project_connector_account_region_scoped')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Runtime\s+1/i })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('table', { name: 'Agent identity runtime calls' })).toBeInTheDocument();
    expect(screen.getByText('invoke-knowledge-base')).toBeInTheDocument();
    expect(getAgentIdentityDetail).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      {
        connectorID: 'aws-connector-1',
        agent,
        tab: 'runtime'
      },
      {
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a'
      }
    );
  });

  it('renders AWS agent identity inventory as an honest reserved surface', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });

    const { ProductAWSAgentsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/agents?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/agents" element={<ProductAWSAgentsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Agents' })).toBeInTheDocument();
    expect(screen.getAllByText(/Connect AWS to load live inventory/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Bedrock agents/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AgentCore runtime and gateway identity/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Secret metadata only, no value reads/i)).toBeInTheDocument();
  });

  it('links AWS agent identity rows with the unique agent node id', async () => {
    const api = await import('./api/client');
    const agentNodeID = 'aws:agent:123456789012:us-east-1:agentcore_runtime/shared-agent/2026-07';
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    vi.spyOn(api.apiClient, 'getAWSProjectAIAgentIdentities').mockResolvedValue({
      inventory: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'production',
        connector_id: 'aws-connector-1',
        account_id: '123456789012',
        region: 'us-east-1',
        parent_issue_number: 1472,
        parent_issue_ref: '#1472',
        current_issue_number: 1512,
        current_issue_ref: '#1512',
        version: 'aws-ai-agent-identities-v1',
        status: 'ready',
        fixture_state: 'success',
        confidence: 0.92,
        applied_filters: {},
        record_count: 1,
        total_record_count: 1,
        filtered_record_count: 1,
        bedrock_agent_count: 0,
        agentcore_runtime_count: 1,
        custom_agent_count: 0,
        external_agent_count: 0,
        gateway_count: 0,
        capability_agent_count: 0,
        memory_store_count: 0,
        browser_count: 0,
        code_interpreter_count: 0,
        runtime_role_count: 1,
        provider_count: 1,
        model_count: 1,
        tool_count: 1,
        capability_count: 1,
        credential_reference_count: 0,
        external_provider_key_count: 0,
        ai_provider_key_count: 0,
        provider_key_breakdown: {},
        relationship_count: 1,
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: ['/docs/aws-ai-agent-identities'],
        coverage_gaps: [],
        diagnostics: [],
        relationships: [],
        records: [
          {
            account_id: '123456789012',
            region: 'us-east-1',
            service: 'agentcore',
            agent_id: 'shared-agent',
            agent_name: 'Shared Agent Runtime',
            agent_type: 'agentcore_runtime',
            runtime_version: '2026-07',
            provider: 'amazon-bedrock-agentcore',
            model_id: 'amazon.nova-pro',
            runtime_role_arn: 'arn:aws:iam::123456789012:role/shared-agent-runtime',
            runtime_role_name: 'shared-agent-runtime',
            tool_names: ['case-router'],
            allowed_actions: ['invoke_tool'],
            memory_enabled: false,
            browser_enabled: false,
            code_interpreter_enabled: false,
            capability_names: ['tool_use'],
            sensitive_boundary: 'metadata_only',
            coverage_status: 'covered',
            source: 'ai_agent_metadata',
            evidence_ref: 'evidence://agent/shared-agent',
            agent_node_id: agentNodeID,
            runtime_role_node_id: 'aws:identity:arn:aws:iam::123456789012:role/shared-agent-runtime',
            relationship_types: ['runs_as'],
            confidence: 0.92,
            collected_at: '2026-07-03T19:00:00Z',
            status: 'ready'
          }
        ],
        generated_at: '2026-07-03T19:00:00Z',
        updated_at: '2026-07-03T19:00:00Z'
      } satisfies AWSAIAgentIdentityInventoryResult
    });
    vi.spyOn(api.apiClient, 'getAWSProjectBedrockAgents').mockResolvedValue({
      inventory: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'production',
        connector_id: 'aws-connector-1',
        account_id: '123456789012',
        region: 'us-east-1',
        parent_issue_number: 1472,
        parent_issue_ref: '#1472',
        current_issue_number: 1512,
        current_issue_ref: '#1512',
        version: 'aws-bedrock-agents-v1',
        status: 'ready',
        fixture_state: 'success',
        confidence: 0.9,
        agent_count: 0,
        filtered_agent_count: 0,
        guardrail_count: 0,
        knowledge_base_count: 0,
        tool_count: 0,
        credential_reference_count: 0,
        runtime_role_count: 0,
        model_count: 0,
        provider_breakdown: {},
        status_breakdown: {},
        relationship_count: 0,
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: ['/docs/aws-bedrock-agents'],
        coverage_gaps: [],
        records: [],
        relationships: [],
        diagnostics: [],
        generated_at: '2026-07-03T19:00:00Z',
        updated_at: '2026-07-03T19:00:00Z'
      } satisfies AWSBedrockAgentsInventoryResult
    });

    const { ProductAWSAgentsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/agents?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/agents" element={<ProductAWSAgentsPage />} />
        </Routes>
      </MemoryRouter>
    );

    const link = await screen.findByRole('link', { name: 'Shared Agent Runtime' });
    expect(link).toHaveAttribute(
      'href',
      `/app/tenant-a/workspace-a/aws/agents/detail?environment=production&agent=${encodeURIComponent(agentNodeID)}&tab=overview`
    );
  });

  it('translates AWS runtime filter aliases before querying runtime events', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const getRuntimeEvents = vi
      .spyOn(api.apiClient, 'getAWSProjectRuntimeEvents')
      .mockResolvedValue({ runtime: readyAWSRuntimeEvents });
    vi.spyOn(api.apiClient, 'getAWSProjectSecretsKMSRuntimeAccess').mockResolvedValue({
      correlation: {
        status: 'ready',
        fixture_state: 'success',
        confidence: 0.91,
        applied_filters: {},
        summary: {
          total_correlations: 2,
          filtered_correlations: 2,
          status_counts: { confirmed: 2 },
          confirmed_count: 2,
          observed_without_grant_count: 0,
          granted_unused_count: 0,
          secret_correlation_count: 1,
          kms_key_correlation_count: 1,
          identity_count: 1,
          resource_count: 2,
          observed_access_count: 2,
          static_grant_count: 2,
          relationship_count: 2
        },
        records: [
          {
            correlation_id: 'secret-openai-key',
            account_id: '123456789012',
            region: 'us-east-1',
            identity_node_id: 'aws:identity:lambda-invoice-agent',
            principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
            resource_kind: 'secret',
            resource_arn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/ai/openai-key',
            resource_name: 'prod/ai/openai-key',
            resource_node_id: 'aws:runtime-resource:aws--secretsmanager--secret:openai-key',
            status: 'confirmed',
            confidence: 0.91,
            observed_count: 1,
            observed_event_ids: ['evt-secret-read'],
            actions: ['secretsmanager:GetSecretValue'],
            session_ids: ['sess-invoice-agent'],
            first_observed_at: '2026-06-14T17:16:00Z',
            last_observed_at: '2026-06-14T17:16:00Z',
            static_sources: ['identity_policy'],
            evidence_ref: 'secrets-kms-runtime-access://secret-openai-key',
            evidence_refs: ['runtime-evidence://123456789012/us-east-1/evt-secret-read'],
            next_action: 'Review secret read scope before approving rotation.',
            redaction_boundary: 'metadata_only_no_secret_values_no_decrypted_plaintext'
          },
          {
            correlation_id: 'kms-openai-provider',
            account_id: '123456789012',
            region: 'us-east-1',
            identity_node_id: 'aws:identity:lambda-invoice-agent',
            principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
            resource_kind: 'kms_key',
            resource_arn: 'arn:aws:kms:us-east-1:123456789012:key/openai-provider',
            resource_name: 'openai-provider',
            resource_node_id: 'aws:runtime-resource:kms-key:openai-provider',
            status: 'confirmed',
            confidence: 0.91,
            observed_count: 1,
            observed_event_ids: ['evt-kms-decrypt'],
            actions: ['kms:Decrypt'],
            session_ids: ['sess-invoice-agent'],
            first_observed_at: '2026-06-14T17:16:30Z',
            last_observed_at: '2026-06-14T17:16:30Z',
            static_sources: ['identity_policy'],
            evidence_ref: 'secrets-kms-runtime-access://kms-openai-provider',
            evidence_refs: ['runtime-evidence://123456789012/us-east-1/evt-kms-decrypt'],
            next_action: 'Review decrypt scope before approving key policy changes.',
            redaction_boundary: 'metadata_only_no_secret_values_no_decrypted_plaintext'
          }
        ],
        relationships: [],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectS3RuntimeAccess').mockResolvedValue({
      correlation: {
        status: 'ready',
        fixture_state: 'success',
        confidence: 0.9,
        applied_filters: {},
        summary: {
          total_correlations: 1,
          filtered_correlations: 1,
          status_counts: { confirmed: 1 },
          confirmed_count: 1,
          observed_without_grant_count: 0,
          granted_unused_count: 0,
          read_count: 1,
          write_count: 0,
          list_count: 0,
          sensitive_exposed_count: 0,
          mode_exceeds_grant_count: 0,
          identity_count: 1,
          bucket_count: 1,
          observed_access_count: 1,
          static_grant_count: 1,
          relationship_count: 1
        },
        records: [
          {
            correlation_id: 's3-billing-artifacts',
            account_id: '123456789012',
            region: 'us-east-1',
            identity_node_id: 'aws:identity:lambda-invoice-agent',
            principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
            bucket_arn: 'arn:aws:s3:::billing-artifacts-123456789012',
            bucket_name: 'billing-artifacts-123456789012',
            resource_node_id: 'aws:runtime-resource:s3-bucket:billing-artifacts',
            status: 'confirmed',
            confidence: 0.9,
            observed_count: 1,
            observed_event_ids: ['evt-s3-access'],
            observed_modes: ['read'],
            granted_modes: ['read'],
            safe_prefixes: ['reports/redacted'],
            actions: ['s3:GetObject'],
            session_ids: ['sess-invoice-agent'],
            first_observed_at: '2026-06-14T17:15:00Z',
            last_observed_at: '2026-06-14T17:15:00Z',
            static_sources: ['identity_policy'],
            sensitivity: 'business_metadata',
            evidence_ref: 's3-runtime-access://billing-artifacts',
            evidence_refs: ['runtime-evidence://123456789012/us-east-1/evt-s3-access'],
            next_action: 'Keep object-key details redacted and verify prefix-level scope.',
            redaction_boundary: 'metadata_only_no_object_keys_no_object_payloads'
          }
        ],
        relationships: [],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectAgentRuntimeAccess').mockResolvedValue({
      correlation: {
        status: 'ready',
        fixture_state: 'success',
        confidence: 0.9,
        applied_filters: {},
        summary: {
          total_correlations: 1,
          filtered_correlations: 1,
          status_counts: { confirmed: 1 },
          confirmed_count: 1,
          observed_without_declaration_count: 0,
          declared_unused_count: 0,
          shadow_agent_count: 0,
          undeclared_tool_count: 0,
          backing_role_mismatch_count: 0,
          failed_tool_call_count: 0,
          agent_count: 1,
          tool_count: 1,
          observed_tool_call_count: 1,
          declared_tool_count: 1,
          relationship_count: 1
        },
        records: [
          {
            correlation_id: 'agent-runtime-case-router',
            account_id: '123456789012',
            region: 'us-east-1',
            agent_node_id: 'aws:agent:runtime-case-triage',
            agent_id: 'runtime-case-triage',
            agent_name: 'runtime-case-triage',
            agent_type: 'agentcore_runtime',
            tool_name: 'case-router',
            tool_target_ref: 'case-router-policy-checker',
            status: 'confirmed',
            confidence: 0.9,
            observed_count: 1,
            observed_event_ids: ['evt-agent-tool'],
            backing_role_arns: ['arn:aws:iam::123456789012:role/agentcore-case-triage-runtime'],
            target_resource_arns: [
              'arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/runtime-case-triage/blue'
            ],
            outcomes: ['allowed'],
            session_ids: ['sess-agentcore-runtime'],
            first_observed_at: '2026-06-14T17:19:00Z',
            last_observed_at: '2026-06-14T17:19:00Z',
            declared_in_inventory: true,
            evidence_ref: 'agent-runtime-access://case-router',
            evidence_refs: ['runtime-evidence://123456789012/us-east-1/evt-agent-tool'],
            next_action: 'Review declared tool target and backing role scope.',
            redaction_boundary: 'metadata_only_no_prompts_no_completions_no_tool_payloads'
          }
        ],
        relationships: [],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    const getAIAgentRisk = vi.spyOn(api.apiClient, 'getAWSProjectAIAgentRisk').mockResolvedValue({
      findings: {
        status: 'ready',
        findings: [
          {
            finding_id: 'aws-ai-agent-risk:support-provider-key',
            calculation_version: 'aws-ai-agent-risk-engine-v1',
            risk_type: 'external_credential_exposure',
            severity: 'high',
            status: 'review',
            score: 86,
            confidence: 0.9,
            account_id: '123456789012',
            region: 'us-east-1',
            agent_node_id: 'aws:agent:external-support-agent',
            agent_id: 'external-support-agent',
            agent_name: 'support-assistant',
            agent_type: 'external_provider_agent',
            runtime_role_arn: 'arn:aws:iam::123456789012:role/ecs-support-agent-task',
            runtime_role_node_id: 'aws:identity:arn:aws:iam::123456789012:role/ecs-support-agent-task',
            provider: 'anthropic',
            tool_names: ['support-search'],
            capability_names: ['tool_use'],
            sensitive_resources: ['aws:resource:credential-reference:support-anthropic-key'],
            source_signals: ['ai_agent_identities', 'secret_permission_equivalence'],
            rationale: 'Agent references Anthropic provider credential metadata without exposing the key value.',
            evidence_boundary: 'metadata_only_no_secret_values_no_prompts_no_completions_no_tool_payloads',
            impacted_nodes: [
              'aws:agent:external-support-agent',
              'aws:identity:arn:aws:iam::123456789012:role/ecs-support-agent-task',
              'aws:resource:credential-reference:support-anthropic-key'
            ],
            impacted_path: [
              { node_id: 'aws:agent:external-support-agent', node_type: 'ai_agent', label: 'support-assistant' },
              { node_id: 'aws:identity:arn:aws:iam::123456789012:role/ecs-support-agent-task', node_type: 'runtime_role', label: 'ecs-support-agent-task' },
              { node_id: 'aws:resource:credential-reference:support-anthropic-key', node_type: 'provider_key_reference', label: 'ANTHROPIC_API_KEY' }
            ],
            evidence: [
              {
                source: 'ai_agent_identities',
                evidence_ref: 'evidence://agent/support-assistant/anthropic',
                label: 'Agent provider-key metadata',
                confidence: 0.9,
                observed_at: '2026-06-23T09:00:00Z',
                relationship: 'references_external_provider_key'
              }
            ],
            next_action: 'Rotate or scope the external provider credential and restrict every AWS identity that can read its reference.',
            remediation_case: {
              case_id: 'aws-ai-agent-risk-preview:support-provider-key',
              title: 'External credential exposure AI agent risk review',
              recommended_action: 'Rotate or scope the external provider credential.',
              approval_required: true,
              blocking_evidence: ['evidence://agent/support-assistant/anthropic'],
              impacted_node_count: 3,
              estimated_risk_drop: 40,
              breakage_prediction: 'unknown',
              read_only_projection: true
            },
            created_at: '2026-06-23T09:00:00Z',
            updated_at: '2026-06-23T09:00:00Z'
          }
        ],
        summary: {
          total_findings: 1,
          filtered_findings: 1,
          external_credential_count: 1,
          broad_tool_access_count: 0,
          sensitive_reachability_count: 0,
          ownerless_agent_count: 0,
          runtime_observed_count: 0,
          backing_role_scope_count: 0,
          relationship_count: 1,
          highest_score: 86,
          average_confidence_pct: 90,
          remediation_preview_count: 1,
          severity_counts: { high: 1 },
          status_counts: { review: 1 },
          risk_type_counts: { external_credential_exposure: 1 }
        },
        relationships: [],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectRemediationCases').mockResolvedValue({
      cases: {
        status: 'ready',
        cases: [
          {
            case_id: 'aws-remediation-case:rotation-test',
            calculation_version: 'aws-remediation-case-model-v1',
            source_type: 'ai_agent_risk',
            source_finding_id: 'aws-ai-agent-risk:support-provider-key',
            lifecycle: 'approved',
            severity: 'high',
            status: 'action_required',
            score: 86,
            confidence: 0.9,
            title: 'Rotate external credential for support-assistant',
            summary: 'Rotate the Anthropic provider key used by support-assistant.',
            account_id: '123456789012',
            region: 'us-east-1',
            identity_node_id: 'aws:agent:external-support-agent',
            identity_arn: 'arn:aws:iam::123456789012:role/ecs-support-agent-task',
            identity_name: 'support-assistant',
            identity_type: 'ai_agent',
            provider: 'anthropic',
            resource_node_ids: ['aws:resource:credential-reference:support-anthropic-key'],
            owner: 'ai-platform',
            owner_assigned: true,
            approval_required: true,
            approval_state: 'pending_approver',
            diff_intent: {
              kind: 'secret_rotation',
              before_ref: 'evidence://agent/support-assistant/anthropic',
              after_ref: 'secret://aws:resource:credential-reference:support-anthropic-key/scoped-projection',
              diff_summary: 'Rotate the agent provider key reference and scope downstream secret reads.',
              no_op: false,
              read_only_projection: true
            },
            tradeoffs: [
              {
                dimension: 'downstream_blast_radius',
                direction: 'improves',
                description: 'Rotating the external key revokes any leaked equivalents.',
                severity: 'high'
              }
            ],
            rollback_plan: {
              strategy: 're_create_secret_reference',
              steps: ['Reissue the prior credential if the workload regressed.'],
              evidence_ref: 'evidence://agent/support-assistant/anthropic'
            },
            verification_plan: {
              strategy: 'secret_access_re_evaluate',
              steps: ['Re-run secret-permission equivalence.'],
              success_signals: ['secret-permission-equivalence:no-equivalence'],
              failure_signals: ['secret-permission-equivalence:still-equivalent'],
              evidence_ref: 'evidence://agent/support-assistant/anthropic'
            },
            source_signals: ['ai_agent_identities'],
            evidence: [
              {
                source: 'ai_agent_identities',
                evidence_ref: 'evidence://agent/support-assistant/anthropic',
                label: 'Agent provider-key metadata',
                confidence: 0.9,
                observed_at: '2026-06-23T09:00:00Z',
                relationship: 'references_external_provider_key'
              }
            ],
            evidence_boundary: 'metadata_only_no_secret_values_no_prompts_no_completions_no_tool_payloads_no_rendered_policy_bodies',
            impacted_nodes: ['aws:agent:external-support-agent', 'aws:resource:credential-reference:support-anthropic-key'],
            impacted_path: [],
            next_actions: ['Rotate the external provider credential and refresh dependent identities.'],
            audit_trail: [
              {
                event_id: 'aws-remediation-case:rotation-test/proposed',
                actor: 'system',
                event_type: 'proposed',
                occurred_at: '2026-06-23T09:00:00Z',
                evidence_ref: 'evidence://agent/support-assistant/anthropic',
                notes: 'Deterministic case proposed from ai_agent_risk evidence at lifecycle=approved.'
              }
            ],
            created_at: '2026-06-23T09:00:00Z',
            updated_at: '2026-06-23T09:00:00Z'
          }
        ],
        summary: {
          total_cases: 1,
          filtered_cases: 1,
          severity_counts: { high: 1 },
          status_counts: { action_required: 1 },
          lifecycle_counts: { approved: 1 },
          source_type_counts: { ai_agent_risk: 1 },
          approval_state_counts: { pending_approver: 1 },
          owner_assigned_count: 1,
          ownerless_count: 0,
          approval_required_count: 1,
          read_only_projection_count: 1,
          rollback_plan_count: 1,
          verification_plan_count: 1,
          relationship_count: 0,
          audit_entry_count: 1,
          highest_score: 86,
          average_confidence_pct: 90
        },
        relationships: [],
        caveats: ['Remediation cases are read-only projections; the engine never applies an AWS change.'],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectIAMPolicyDiffs').mockResolvedValue({
      diffs: {
        status: 'ready',
        diffs: [
          {
            diff_id: 'aws-iam-policy-diff:data-loader-remove',
            calculation_version: 'aws-iam-policy-least-privilege-diff-v1',
            source_recommendation_id: 'least-priv:data-loader-remove',
            decision: 'remove',
            severity: 'medium',
            status: 'action_required',
            score: 74,
            confidence: 0.86,
            title: 'Scope data-loader: remove 2 action(s)',
            summary: 'Remove unused s3 actions from data-loader role.',
            account_id: '123456789012',
            region: 'us-east-1',
            service: 's3',
            identity_node_id: 'aws:identity:arn:aws:iam::123456789012:role/data-loader',
            identity_arn: 'arn:aws:iam::123456789012:role/data-loader',
            identity_name: 'data-loader',
            resource_node_id: 'aws:resource:s3-bucket/data-loader',
            resource_arn: 'arn:aws:s3:::data-loader',
            statement_changes: [
              {
                statement_sid: 'least-privilege-projection',
                effect: 'Allow',
                change_kind: 'scope_removed',
                removed_actions: ['s3:DeleteObject', 's3:DeleteBucket'],
                kept_actions: ['s3:GetObject'],
                resource_before: ['arn:aws:s3:::data-loader'],
                resource_after: ['arn:aws:s3:::data-loader'],
                rationale: 'Remove 2 unused action(s) and keep 1 observed action(s) on data-loader.'
              }
            ],
            removed_actions: ['s3:DeleteObject', 's3:DeleteBucket'],
            kept_actions: ['s3:GetObject'],
            observed_actions: ['s3:GetObject'],
            granted_actions: ['s3:DeleteObject', 's3:DeleteBucket', 's3:GetObject'],
            resource_scope_before: ['arn:aws:s3:::data-loader'],
            resource_scope_after: ['arn:aws:s3:::data-loader'],
            breakage_projection: {
              level: 'low',
              rationale: 'Removed actions have no observed callers.',
              signals: ['observed_actions:1', 'removed_actions:2', 'kept_actions:1']
            },
            rollback_plan: {
              strategy: 're_attach_policy',
              steps: ['Re-attach the captured before_ref policy statement.', 'Re-run least-privilege.'],
              evidence_ref: 'evidence://least/data-loader'
            },
            verification_plan: {
              strategy: 'policy_simulate',
              steps: ['Run IAM policy simulator.', 'Re-run least-privilege.'],
              success_signals: ['policy_simulate:no-regression', 'least_privilege:decision-keep'],
              failure_signals: ['policy_simulate:denied-observed-action'],
              evidence_ref: 'evidence://least/data-loader'
            },
            ready_for_apply: true,
            read_only_projection: true,
            source_signals: ['least_privilege'],
            evidence: [
              {
                source: 'least_privilege',
                evidence_ref: 'evidence://least/data-loader',
                label: 'Least-privilege scope recommendation',
                confidence: 0.86,
                observed_at: '2026-06-24T09:00:00Z',
                relationship: 'remove'
              }
            ],
            evidence_boundary: 'metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads',
            impacted_nodes: [
              'aws:identity:arn:aws:iam::123456789012:role/data-loader',
              'aws:resource:s3-bucket/data-loader'
            ],
            impacted_path: [],
            next_action: 'Approve the diff, then apply via the IAM remediation executor.',
            created_at: '2026-06-24T09:00:00Z',
            updated_at: '2026-06-24T09:00:00Z'
          }
        ],
        summary: {
          total_diffs: 1,
          filtered_diffs: 1,
          decision_counts: { remove: 1 },
          severity_counts: { medium: 1 },
          status_counts: { action_required: 1 },
          breakage_level_counts: { low: 1 },
          service_counts: { s3: 1 },
          removed_action_count: 2,
          kept_action_count: 1,
          statement_change_count: 1,
          ready_for_apply_count: 1,
          manual_review_count: 0,
          no_op_count: 0,
          relationship_count: 1,
          highest_score: 74,
          average_confidence_pct: 86
        },
        relationships: [
          {
            diff_id: 'aws-iam-policy-diff:data-loader-remove',
            type: 'iam_policy_diff_path',
            from_node_id: 'aws:identity:arn:aws:iam::123456789012:role/data-loader',
            to_node_id: 'aws:resource:s3-bucket/data-loader',
            evidence_ref: 'evidence://least/data-loader'
          }
        ],
        caveats: ['IAM policy diffs are read-only projections; the engine never applies an AWS change.'],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectTrustPolicyHardeningPlans').mockResolvedValue({
      plans: {
        status: 'ready',
        plans: [
          {
            plan_id: 'aws-trust-policy-hardening:payments-cross-account',
            calculation_version: 'aws-trust-policy-hardening-planner-v1',
            source_finding_id: 'aws-cross-account-trust:payments-cross-account',
            finding_type: 'runtime_cross_account_assumption',
            hardening_direction: 'add_org_or_source_condition',
            severity: 'high',
            status: 'action_required',
            score: 84,
            confidence: 0.88,
            title: 'Add org/source condition to payments-cross-account trust',
            summary: 'Runtime AssumeRole observed without sts:ExternalId.',
            account_id: '123456789012',
            region: 'us-east-1',
            service: 'iam',
            resource_type: 'iam_role',
            resource_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-cross-account',
            resource_arn: 'arn:aws:iam::123456789012:role/payments-cross-account',
            resource_label: 'payments-cross-account',
            public_principal: false,
            trusted_within_organization: false,
            runtime_observed: true,
            analyzer_backed: true,
            principal_change: {
              before_principals: ['arn:aws:iam::555555555555:role/billing-runner'],
              after_principals: ['arn:aws:iam::555555555555:role/billing-runner'],
              public_principal_removed: false,
              rationale: 'Keep the explicit external principal and harden via conditions.'
            },
            condition_recommendations: [
              {
                operator: 'StringEquals',
                key: 'sts:ExternalId',
                value: '<owner-approved-external-id>',
                rationale: 'Require shared external id for cross-account assumption.',
                evidence_ref: 'evidence://trust/payments-cross-account'
              },
              {
                operator: 'StringEquals',
                key: 'aws:SourceIdentity',
                value: '<workload-identity>',
                rationale: 'Preserve workload attribution in audit logs.'
              }
            ],
            statement_snippets: [
              {
                statement_sid: 'trust-policy-hardening-projection',
                effect: 'Allow',
                change_kind: 'condition_added',
                before_ref: 'evidence://trust/payments-cross-account',
                after_ref: 'trust-policy://payments/scoped-projection',
                condition_before: [],
                condition_after: ['sts:ExternalId', 'aws:SourceIdentity'],
                rationale: 'Keep the explicit principal and add the recommended condition boundary.'
              }
            ],
            affected_callers: [
              {
                principal_arn: 'arn:aws:iam::555555555555:role/billing-runner',
                principal_account_id: '555555555555',
                trusted_within_organization: false,
                runtime_observed: true,
                analyzer_backed: true,
                evidence_ref: 'evidence://trust/payments-cross-account'
              }
            ],
            breakage_projection: {
              level: 'low',
              rationale: 'Runtime correlation and Access Analyzer both confirm the caller set.',
              signals: ['runtime_observed:true', 'analyzer_backed:true', 'affected_callers:1']
            },
            rollback_plan: {
              strategy: 'restore_trust_policy',
              steps: ['Restore the previous trust statement from the captured before_ref.'],
              evidence_ref: 'evidence://trust/payments-cross-account'
            },
            verification_plan: {
              strategy: 'trust_policy_re_evaluate',
              steps: ['Re-run cross-account-trust.'],
              success_signals: ['cross_account_trust:finding-resolved'],
              failure_signals: ['cross_account_trust:finding-unchanged'],
              evidence_ref: 'evidence://trust/payments-cross-account'
            },
            ready_for_apply: true,
            read_only_projection: true,
            source_signals: ['cross_account_trust'],
            evidence: [
              {
                source: 'cross_account_trust',
                evidence_ref: 'evidence://trust/payments-cross-account',
                label: 'Cross-account trust evidence',
                confidence: 0.88,
                observed_at: '2026-06-24T10:00:00Z',
                relationship: 'cross_account_assumption'
              }
            ],
            evidence_boundary: 'metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads',
            impacted_nodes: ['aws:identity:arn:aws:iam::123456789012:role/payments-cross-account'],
            impacted_path: [],
            next_action: 'Confirm caller, then apply the condition boundary via the trust-policy executor.',
            created_at: '2026-06-24T10:00:00Z',
            updated_at: '2026-06-24T10:00:00Z'
          }
        ],
        summary: {
          total_plans: 1,
          filtered_plans: 1,
          severity_counts: { high: 1 },
          status_counts: { action_required: 1 },
          finding_type_counts: { runtime_cross_account_assumption: 1 },
          hardening_direction_counts: { add_org_or_source_condition: 1 },
          breakage_level_counts: { low: 1 },
          public_principal_count: 0,
          cross_account_count: 1,
          conditioned_count: 1,
          runtime_observed_count: 1,
          analyzer_backed_count: 1,
          ready_for_apply_count: 1,
          manual_review_count: 0,
          affected_caller_count: 1,
          relationship_count: 1,
          highest_score: 84,
          average_confidence_pct: 88
        },
        relationships: [
          {
            plan_id: 'aws-trust-policy-hardening:payments-cross-account',
            type: 'trust_policy_hardening_affected_caller',
            from_node_id: 'aws:identity:arn:aws:iam::123456789012:role/payments-cross-account',
            to_node_id: 'arn:aws:iam::555555555555:role/billing-runner',
            evidence_ref: 'evidence://trust/payments-cross-account'
          }
        ],
        caveats: ['Trust policy hardening plans are read-only projections; the engine never applies an AWS change.'],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectPermissionBoundarySCPPlans').mockResolvedValue({
      plans: {
        status: 'ready',
        plans: [
          {
            plan_id: 'aws-permission-boundary-scp:s3-delete-object',
            calculation_version: 'aws-permission-boundary-scp-planner-v1',
            kind: 'permission_boundary',
            target_scope: 'identity',
            severity: 'high',
            status: 'action_required',
            score: 74,
            confidence: 0.86,
            title: 'Permission boundary: deny s3:DeleteObject across 3 identities',
            summary: '3 least-privilege recommendations agree that s3:DeleteObject is unused.',
            service: 's3',
            target_account_ids: ['111111111111', '222222222222'],
            target_ou_paths: ['/root/security'],
            target_identity_node_ids: [
              'aws:identity:arn:aws:iam::111111111111:role/loader-a',
              'aws:identity:arn:aws:iam::222222222222:role/loader-b',
              'aws:identity:arn:aws:iam::111111111111:role/loader-c'
            ],
            prevented_behavior: 'Re-grant or future use of s3:DeleteObject by any boundary-bound identity.',
            source_finding_ids: ['least-priv:a', 'least-priv:b', 'least-priv:c'],
            statement_snippets: [
              {
                statement_sid: 'permission-boundary-projection',
                effect: 'Deny',
                change_kind: 'deny_repeated_action',
                before_ref: 'evidence://least/loader',
                after_ref: 'permission-boundary://repeated-action/s3%3Adeleteobject',
                denied_actions: ['s3:DeleteObject'],
                allowed_actions: [],
                resource_scope: ['*'],
                rationale: '3 identities across 2 account(s) all have least-privilege removal for s3:DeleteObject.'
              }
            ],
            breakage_projection: {
              level: 'low',
              rationale: 'All affected identities already have a least-privilege remove decision.',
              affected_identities: 3,
              affected_accounts: 2,
              affected_ous: 1,
              signals: ['affected_identities:3', 'affected_accounts:2', 'affected_ous:1']
            },
            rollback_plan: {
              strategy: 'detach_permission_boundary',
              steps: ['Detach the projected permission boundary from each captured identity.'],
              evidence_ref: 'evidence://least/loader'
            },
            verification_plan: {
              strategy: 'policy_simulate',
              steps: ['Use IAM policy simulator to confirm the boundary denies the action.'],
              success_signals: ['policy_simulate:no-regression', 'least_privilege:decision-keep'],
              failure_signals: ['policy_simulate:denied-observed-action'],
              evidence_ref: 'evidence://least/loader'
            },
            ready_for_apply: true,
            read_only_projection: true,
            source_signals: ['least_privilege'],
            evidence: [
              {
                source: 'least_privilege',
                evidence_ref: 'evidence://least/loader',
                label: 'Repeated least-privilege evidence',
                confidence: 0.86,
                observed_at: '2026-06-24T14:00:00Z',
                relationship: 'remove'
              }
            ],
            evidence_boundary: 'metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads',
            impacted_nodes: [
              'aws:identity:arn:aws:iam::111111111111:role/loader-a',
              'aws:identity:arn:aws:iam::222222222222:role/loader-b',
              'aws:identity:arn:aws:iam::111111111111:role/loader-c'
            ],
            impacted_path: [],
            next_action: 'Confirm the affected identities, then publish the boundary via the IAM remediation executor.',
            created_at: '2026-06-24T14:00:00Z',
            updated_at: '2026-06-24T14:00:00Z'
          }
        ],
        summary: {
          total_plans: 1,
          filtered_plans: 1,
          kind_counts: { permission_boundary: 1 },
          target_scope_counts: { identity: 1 },
          severity_counts: { high: 1 },
          status_counts: { action_required: 1 },
          breakage_level_counts: { low: 1 },
          boundary_plan_count: 1,
          scp_plan_count: 0,
          ready_for_apply_count: 1,
          affected_identity_count: 3,
          affected_account_count: 2,
          affected_ou_count: 1,
          relationship_count: 3,
          highest_score: 74,
          average_confidence_pct: 86
        },
        relationships: [],
        caveats: ['Permission boundary and SCP plans are read-only projections; the engine never applies an AWS change.'],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
      const getPermissionBoundaryExecutor = vi.spyOn(api.apiClient, 'getAWSProjectPermissionBoundaryExecutor').mockResolvedValue({
        permission_boundary_executor: {
        status: 'ready',
        entries: [
          {
            execution_id: 'aws-permission-boundary-executor:s3-delete-object',
            calculation_version: 'aws-permission-boundary-executor-v1',
            dry_run_id: 'aws-remediation-dry-run:s3-delete-object',
            approval_id: 'aws-remediation-approval:s3-delete-object',
            case_id: 'aws-remediation-case:s3-delete-object',
            plan_id: 'aws-permission-boundary-scp:s3-delete-object',
            source_artifact_id: 'aws-permission-boundary-scp:s3-delete-object',
            state: 'projected',
            severity: 'high',
            score: 74,
            confidence: 0.86,
            title: 'Permission boundary execution: deny s3:DeleteObject',
            summary: 'Approved permission boundary execution record for the repeated S3 delete action.',
            account_id: '123456789012',
            region: 'us-east-1',
            operation: 'PutRolePermissionsBoundary',
            idempotency_key: 'idempotency://s3-delete-object',
            target_identity_node_ids: [
              'aws:identity:arn:aws:iam::111111111111:role/loader-a',
              'aws:identity:arn:aws:iam::222222222222:role/loader-b',
              'aws:identity:arn:aws:iam::111111111111:role/loader-c'
            ],
            target_account_ids: ['111111111111', '222222222222'],
            target_ou_paths: ['/root/security'],
            prevented_behavior: 'Re-grant or future use of s3:DeleteObject by any boundary-bound identity.',
            statement_snippets: [
              {
                statement_sid: 'permission-boundary-projection',
                effect: 'Deny',
                change_kind: 'deny_repeated_action',
                before_ref: 'evidence://least/loader',
                after_ref: 'permission-boundary://repeated-action/s3%3Adeleteobject',
                denied_actions: ['s3:DeleteObject'],
                allowed_actions: [],
                resource_scope: ['*'],
                rationale: '3 identities across 2 account(s) all have least-privilege removal for s3:DeleteObject.'
              }
            ],
            breakage_projection: {
              level: 'low',
              rationale: 'All affected identities already have a least-privilege remove decision.',
              affected_identities: 3,
              affected_accounts: 2,
              affected_ous: 1,
              signals: ['affected_identities:3', 'affected_accounts:2', 'affected_ous:1']
            },
            intended_api_call: {
              service: 'iam',
              operation: 'PutRolePermissionsBoundary',
              target_resource: 'aws:identity:arn:aws:iam::111111111111:role/loader-a',
              parameter_refs: ['idempotency://s3-delete-object', 'boundary_ref://aws-remediation-case:s3-delete-object/after'],
              idempotent: true,
              requires_approval: true
            },
            preconditions: [
              { name: 'dry_run_would_succeed', status: 'passed', rationale: 'Dry-run passed.' },
              { name: 'breakage_level_low', status: 'passed', rationale: 'Breakage projection is low.' }
            ],
            boundary_simulation: {
              simulation_ref: 'iam:policy_simulate://aws-permission-boundary-scp:s3-delete-object/permission-boundary',
              outcome: 'would_limit_actions',
              before_ref: 'evidence://least/loader',
              after_ref: 'permission-boundary://aws-permission-boundary-scp:s3-delete-object/intended-boundary',
              denied_action_count: 1,
              target_identity_count: 3,
              signals: ['permission_boundary', 'affected_identities:3']
            },
            verifications: [
              {
                source: 'iam:policy_simulate',
                signal: 'boundary_denies_projected_actions',
                status: 'pending',
                description: 'Re-run IAM policy simulation for each captured identity.'
              }
            ],
            rollback_plan: {
              strategy: 'detach_permission_boundary',
              steps: ['Detach the projected permission boundary from each captured identity.'],
              evidence_ref: 'evidence://least/loader'
            },
            verification_plan: {
              strategy: 'policy_simulate',
              steps: ['Use IAM policy simulator to confirm the boundary denies the action.'],
              success_signals: ['policy_simulate:no-regression'],
              failure_signals: ['policy_simulate:denied-observed-action'],
              evidence_ref: 'evidence://least/loader'
            },
            audit_trail: [],
            kill_switch_engaged: false,
            ready_for_live_apply: true,
            read_only_projection: true,
            source_signals: ['aws_permission_boundary_scp', 'remediation_dry_run'],
            evidence: [],
            evidence_boundary: 'metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads',
            impacted_nodes: ['aws:identity:arn:aws:iam::111111111111:role/loader-a'],
            impacted_path: [],
            next_action: 'Permission boundary operation=PutRolePermissionsBoundary is ready for the wave-8 apply runtime once its feature flag opens.',
            projected_at: '2026-06-30T10:00:00Z',
            created_at: '2026-06-30T10:00:00Z',
            updated_at: '2026-06-30T10:00:00Z'
          }
        ],
        summary: {
          total_entries: 1,
          filtered_entries: 1,
          state_counts: { projected: 1 },
          operation_counts: { PutRolePermissionsBoundary: 1 },
          severity_counts: { high: 1 },
          ready_for_live_apply_count: 1,
          kill_switch_engaged_count: 0,
          failed_precondition_count: 0,
          target_identity_count: 3,
          verification_count: 1,
          relationship_count: 3,
          highest_score: 74,
          average_confidence_pct: 86
        },
        relationships: [],
        caveats: ['Permission boundary executor entries are read-only projections.'],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
          diagnostics: []
        } as any
      });
      const getScpGuardrailExecutor = vi.spyOn(api.apiClient, 'getAWSProjectScpGuardrailExecutor').mockResolvedValue({
        scp_guardrail_executor: {
          status: 'ready',
          entries: [
            {
              execution_id: 'aws-scp-guardrail-executor:external-trust',
              calculation_version: 'aws-scp-guardrail-executor-v1',
              dry_run_id: 'aws-remediation-dry-run:external-trust',
              approval_id: 'aws-remediation-approval:external-trust',
              case_id: 'aws-remediation-case:external-trust',
              plan_id: 'aws-permission-boundary-scp:external-trust',
              source_artifact_id: 'aws-permission-boundary-scp:external-trust',
              state: 'projected',
              severity: 'high',
              score: 81,
              confidence: 0.91,
              title: 'SCP guardrail execution: external trust guardrail',
              summary: 'Approved SCP guardrail execution record for the external trust plan.',
              account_id: '111111111111',
              region: 'us-east-1',
              operation: 'AttachPolicy',
              idempotency_key: 'idempotency://external-trust',
              target_account_ids: [],
              target_ou_paths: ['/engineering'],
              prevented_behavior: 'Re-create the unconditioned external trust pattern.',
              statement_snippets: [
                {
                  statement_sid: 'scp-projection',
                  effect: 'Deny',
                  change_kind: 'deny_external_trust',
                  before_ref: 'evidence://trust/external',
                  after_ref: 'scp://external/scoped-projection',
                  denied_actions: ['iam:UpdateAssumeRolePolicy'],
                  allowed_actions: [],
                  resource_scope: ['arn:aws:iam::111111111111:role/orders'],
                  rationale: 'Block re-introduction of the flagged external trust pattern.'
                }
              ],
              breakage_projection: {
                level: 'low',
                rationale: 'Runtime and analyzer evidence both confirm the caller set.',
                affected_identities: 0,
                affected_accounts: 2,
                affected_ous: 1,
                signals: ['affected_accounts:2', 'affected_ous:1']
              },
              intended_api_call: {
                service: 'organizations',
                operation: 'AttachPolicy',
                target_resource: '/engineering',
                parameter_refs: ['idempotency://external-trust', 'scp_ref://aws-remediation-case:external-trust/after'],
                idempotent: true,
                requires_approval: true
              },
              preconditions: [
                { name: 'dry_run_would_succeed', status: 'passed', rationale: 'Dry-run passed.' },
                { name: 'target_scope_captured', status: 'passed', rationale: 'Target scope captured.' }
              ],
              boundary_simulation: {
                simulation_ref: 'organizations:scp_simulate://aws-permission-boundary-scp:external-trust/scp-guardrail',
                outcome: 'would_attach_guardrail',
                before_ref: 'evidence://trust/external',
                after_ref: 'scp://external/scoped-projection',
                denied_action_count: 1,
                target_account_count: 0,
                target_ou_count: 1,
                signals: ['scp_guardrail', 'affected_accounts:2']
              },
              verifications: [
                {
                  source: 'organizations',
                  signal: 'effective_policy_matches',
                  status: 'pending',
                  description: 'Confirm the effective SCP includes the intended guardrail statement metadata ref.'
                }
              ],
              rollback_plan: {
                strategy: 'detach_scp',
                steps: ['Detach the projected SCP from the captured OU.'],
                evidence_ref: 'evidence://trust/external'
              },
              verification_plan: {
                strategy: 'scp_simulate',
                steps: ['Confirm the SCP denies the prevented behavior.'],
                success_signals: ['cross_account_trust:finding-resolved'],
                failure_signals: ['cross_account_trust:finding-unchanged'],
                evidence_ref: 'evidence://trust/external'
              },
              audit_trail: [],
              kill_switch_engaged: false,
              ready_for_live_apply: true,
              read_only_projection: true,
              source_signals: ['aws_permission_boundary_scp', 'scp'],
              evidence: [],
              evidence_boundary: 'metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads',
              impacted_nodes: ['111111111111', '/engineering'],
              impacted_path: [],
              next_action: 'SCP guardrail operation=AttachPolicy is ready for the wave-8 apply runtime once its feature flag opens.',
              projected_at: '2026-07-01T10:00:00Z',
              created_at: '2026-07-01T10:00:00Z',
              updated_at: '2026-07-01T10:00:00Z'
            }
          ],
          summary: {
            total_entries: 1,
            filtered_entries: 1,
            state_counts: { projected: 1 },
            operation_counts: { AttachPolicy: 1 },
            severity_counts: { high: 1 },
            ready_for_live_apply_count: 1,
            kill_switch_engaged_count: 0,
            failed_precondition_count: 0,
            target_account_count: 0,
            target_ou_count: 1,
            verification_count: 1,
            relationship_count: 3,
            highest_score: 81,
            average_confidence_pct: 91
          },
          relationships: [],
          caveats: ['SCP guardrail executor entries are read-only projections.'],
          failure_reasons: [],
          remediation_hints: [],
          evidence_links: [],
          coverage_gaps: [],
          diagnostics: []
        } as any
      });
      const getPostRemediationVerification = vi.spyOn(api.apiClient, 'getAWSProjectPostRemediationVerification').mockResolvedValue({
        post_remediation_verification: {
          status: 'ready',
          entries: [],
          relationships: [],
          applied_filters: {},
          summary: {
            total_entries: 0,
            filtered_entries: 0,
            state_counts: {},
            source_type_counts: {},
            severity_counts: {},
            verified_count: 0,
            pending_count: 0,
            failed_count: 0,
            rollback_planned_count: 0,
            blocked_count: 0,
            kill_switch_engaged_count: 0,
            failed_precondition_count: 0,
            check_count: 0,
            relationship_count: 0,
            highest_score: 0,
            average_confidence_pct: 0
          },
          caveats: ['Post-remediation verification entries are read-only projections.'],
          failure_reasons: [],
          remediation_hints: [],
          evidence_links: [],
          coverage_gaps: [],
          diagnostics: []
        } as any
      });
      const getAdvisoryAuthorization = vi.spyOn(api.apiClient, 'getAWSProjectAdvisoryAuthorization').mockResolvedValue({
        advisory_authorization: {
          status: 'ready',
          mode: 'advisory',
          policy_version: 'aws-advisory-authorization-policy-v1',
          decisions: [],
          relationships: [],
          applied_filters: {},
          summary: {
            total_decisions: 0,
            filtered_decisions: 0,
            outcome_counts: {},
            severity_counts: {},
            source_type_counts: {},
            allow_count: 0,
            warn_count: 0,
            require_approval_count: 0,
            recommend_deny_count: 0,
            quarantine_count: 0,
            kill_switch_engaged_count: 0,
            relationship_count: 0,
            highest_score: 0,
            average_confidence_pct: 0
          },
          caveats: ['Advisory authorization decisions are read-only recommendations.'],
          failure_reasons: [],
          remediation_hints: [],
          evidence_links: [],
          coverage_gaps: [],
          diagnostics: []
        } as any
      });
      const getSessionPolicyRecommendations = vi.spyOn(api.apiClient, 'getAWSProjectSessionPolicyRecommendations').mockResolvedValue({
        session_policy_recommendations: {
          status: 'ready',
          mode: 'advisory',
          policy_version: 'aws-session-policy-recommendation-policy-v1',
          recommendations: [],
          relationships: [],
          applied_filters: {},
          summary: {
            total_recommendations: 0,
            filtered_recommendations: 0,
            decision_counts: {},
            severity_counts: {},
            allow_action_count: 0,
            deny_action_count: 0,
            observed_action_count: 0,
            validation_signal_count: 0,
            relationship_count: 0,
            highest_score: 0,
            average_confidence_pct: 0
          },
          caveats: ['Session-policy recommendations are advisory-only.'],
          failure_reasons: [],
          remediation_hints: [],
          evidence_links: [],
          coverage_gaps: [],
          diagnostics: []
        } as any
      });
      const getAgentCoreGatewayPolicyAdvisory = vi.spyOn(api.apiClient, 'getAWSProjectAgentCoreGatewayPolicyAdvisory').mockResolvedValue({
        agentcore_gateway_policy_advisory: {
          status: 'ready',
          mode: 'advisory',
          policy_version: 'aws-agentcore-gateway-policy-advisory-policy-v1',
          pilot_state: 'candidate',
          enforcement_state: 'advisory_only',
          advisories: [],
          relationships: [],
          applied_filters: {},
          summary: {
            total_advisories: 0,
            filtered_advisories: 0,
            outcome_counts: {},
            severity_counts: {},
            risk_type_counts: {},
            allow_tools_count: 0,
            warn_count: 0,
            require_approval_count: 0,
            restrict_tools_count: 0,
            block_tools_count: 0,
            restricted_tool_count: 0,
            sensitive_resource_count: 0,
            relationship_count: 0,
            highest_score: 0,
            average_confidence_pct: 0
          },
          caveats: ['AgentCore gateway policy advisories are read-only recommendations.'],
          failure_reasons: [],
          remediation_hints: [],
          evidence_links: [],
          coverage_gaps: [],
          diagnostics: []
        } as any
      });
      const getSecretKeyRotation = vi.spyOn(api.apiClient, 'getAWSProjectSecretKeyRotationPlans').mockResolvedValue({
      plans: {
        status: 'ready',
        plans: [
          {
            plan_id: 'aws-secret-key-rotation:openai-api-key',
            calculation_version: 'aws-credential-rotation-planner-v1',
            rotation_type: 'provider_key',
            severity: 'high',
            status: 'action_required',
            score: 88,
            confidence: 0.9,
            title: 'Provider key rotation: openai/api-key',
            summary: 'Rotate the OpenAI provider key and refresh dependent workloads.',
            account_id: '123456789012',
            region: 'us-east-1',
            provider: 'openai',
            owner_handoff: {
              owner: 'ai-platform',
              assigned: true,
              approval_state: 'pending_approver',
              required_actors: ['application-owner', 'security-reviewer'],
              instructions: ['Confirm dependent workload refresh.']
            },
            source_finding_ids: ['aws-secret-permission-equivalence:openai-agent'],
            target_secrets: [
              {
                ref_type: 'secret',
                node_id: 'aws:resource:secrets-manager-secret:openai/api-key',
                arn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:openai/api-key',
                label: 'openai/api-key',
                provider: 'openai',
                metadata_ref: 'evidence://agent/case-triage/openai'
              }
            ],
            target_keys: [],
            dependent_workloads: [
              {
                workload_id: 'aws:agent:case-triage',
                workload_name: 'case-triage',
                workload_type: 'ai_agent',
                owner: 'ai-platform',
                refresh_order: 1
              }
            ],
            rotation_order: [
              { order: 1, phase: 'prepare', action: 'Confirm owner and fallback.', actor: 'ai-platform' },
              { order: 2, phase: 'dry_run', action: 'Dry-run workload refresh.', actor: 'ai-platform' },
              { order: 3, phase: 'apply', action: 'Rotate the provider key outside Identrail.', actor: 'ai-platform' },
              { order: 4, phase: 'refresh', action: 'Refresh dependent workload.', actor: 'ai-platform' },
              { order: 5, phase: 'verify', action: 'Re-run metadata checks.', actor: 'security' }
            ],
            diff_intent: {
              kind: 'secret_rotation',
              before_ref: 'evidence://agent/case-triage/openai',
              after_ref: 'rotation://openai-api-key/new-version-reference',
              diff_summary: 'Rotate without reading or storing the value.',
              no_op: false,
              read_only_projection: true
            },
            tradeoffs: [
              {
                dimension: 'credential_exposure',
                direction: 'improves',
                description: 'Rotation invalidates the previous provider key.',
                severity: 'high'
              }
            ],
            rollback_plan: {
              strategy: 'restore_previous_secret_version',
              steps: ['Restore the previous secret reference if workload refresh regresses.'],
              evidence_ref: 'evidence://agent/case-triage/openai'
            },
            verification_plan: {
              strategy: 'rotation_re_evaluate',
              steps: ['Re-run secret-permission equivalence.'],
              success_signals: ['secret_permission_equivalence:no-equivalent-stale-access'],
              failure_signals: ['secret_permission_equivalence:stale-reference-observed'],
              evidence_ref: 'evidence://agent/case-triage/openai'
            },
            readiness_gates: [
              { name: 'no_secret_values', status: 'passed', rationale: 'Metadata refs only.' },
              { name: 'owner_handoff', status: 'passed', rationale: 'Owner assigned.' }
            ],
            ready_for_apply: true,
            read_only_projection: true,
            source_signals: ['secret_permission_equivalence'],
            evidence: [
              {
                source: 'secret_permission_equivalence',
                evidence_ref: 'evidence://agent/case-triage/openai',
                label: 'Agent provider-key metadata',
                confidence: 0.9,
                observed_at: '2026-06-24T15:00:00Z',
                relationship: 'agent_uses_permission_bearing_secret'
              }
            ],
            evidence_boundary: 'metadata_only_no_secret_values_no_payloads',
            impacted_nodes: ['aws:agent:case-triage', 'aws:resource:secrets-manager-secret:openai/api-key'],
            impacted_path: [],
            next_action: 'Assign owner handoff, execute rotation, then link verification evidence.',
            created_at: '2026-06-24T15:00:00Z',
            updated_at: '2026-06-24T15:00:00Z'
          }
        ],
        summary: {
          total_plans: 1,
          filtered_plans: 1,
          rotation_type_counts: { provider_key: 1 },
          provider_counts: { openai: 1 },
          severity_counts: { high: 1 },
          status_counts: { action_required: 1 },
          owner_assigned_count: 1,
          ownerless_count: 0,
          ready_for_apply_count: 1,
          target_secret_count: 1,
          target_key_count: 0,
          dependent_workload_count: 1,
          relationship_count: 2,
          highest_score: 88,
          average_confidence_pct: 90
        },
        relationships: [],
        caveats: ['Plans never read, expose, log, rotate, or persist secret values.'],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    const accessKeyID = 'AKIA' + 'ORDERS123456';
    const getAccessKeyQuarantine = vi.spyOn(api.apiClient, 'getAWSProjectAccessKeyQuarantinePlans').mockResolvedValue({
      plans: {
        status: 'ready',
        plans: [
          {
            plan_id: 'aws-access-key-quarantine:orders-ci',
            calculation_version: 'aws-access-key-quarantine-planner-v1',
            quarantine_state: 'quarantine_candidate',
            severity: 'high',
            status: 'ready_for_quarantine',
            score: 82,
            confidence: 0.86,
            title: `Access key quarantine: ${accessKeyID}`,
            summary: 'Plan a stale access key quarantine workflow.',
            account_id: '123456789012',
            region: 'us-east-1',
            owner_notice: {
              owner: 'orders-platform',
              assigned: true,
              notification: 'owner_notification_required',
              grace_period: 'P7D',
              required_actors: ['identity-owner', 'security-reviewer'],
              instructions: ['Notify owner before quarantine.']
            },
            source_finding_ids: ['aws-unused-dormant-access:orders-key'],
            target_access_keys: [
              {
                ref_type: 'iam_access_key',
                access_key_id: accessKeyID,
                node_id: `aws:iam-access-key:${accessKeyID}`,
                principal: 'arn:aws:iam::123456789012:user/orders-ci',
                label: accessKeyID,
                metadata_ref: `runtime-evidence://access-key/${accessKeyID}`
              }
            ],
            affected_principals: [
              {
                ref_type: 'iam_principal',
                node_id: 'aws:identity:user/orders-ci',
                principal: 'arn:aws:iam::123456789012:user/orders-ci',
                label: 'orders-ci',
                metadata_ref: `runtime-evidence://access-key/${accessKeyID}`
              }
            ],
            last_used_at: '2026-03-17T09:35:00Z',
            dormant_days: 100,
            grace_period_days: 7,
            quarantine_order: [
              { order: 1, phase: 'notify', action: 'Notify owner.', actor: 'orders-platform' },
              { order: 2, phase: 'grace_period', action: 'Monitor runtime use.', actor: 'security-reviewer' },
              { order: 3, phase: 'dry_run', action: 'Confirm workload replacement.', actor: 'platform-operator' },
              { order: 4, phase: 'apply', action: 'Disable outside Identrail.', actor: 'platform-operator' },
              { order: 5, phase: 'verify', action: 'Verify no key use.', actor: 'security-reviewer' }
            ],
            diff_intent: {
              kind: 'access_key_quarantine',
              before_ref: `runtime-evidence://access-key/${accessKeyID}`,
              after_ref: 'quarantine://orders-key/disable-after-grace',
              diff_summary: 'Plan DisableAccessKey after owner notice and grace-period verification.',
              no_op: false,
              read_only_projection: true
            },
            tradeoffs: [
              {
                dimension: 'credential_exposure',
                direction: 'improves',
                description: 'Disabling key removes long-lived credential path.',
                severity: 'high'
              }
            ],
            rollback_plan: {
              strategy: 'reactivate_access_key_or_swap_credential',
              steps: ['Re-enable only with emergency owner approval.'],
              evidence_ref: `runtime-evidence://access-key/${accessKeyID}`
            },
            verification_plan: {
              strategy: 'quarantine_re_evaluate',
              steps: ['Check CloudTrail and IAM last-used evidence.'],
              success_signals: ['cloudtrail:no-access-key-use'],
              failure_signals: ['cloudtrail:access-key-use-observed'],
              evidence_ref: `runtime-evidence://access-key/${accessKeyID}`
            },
            readiness_gates: [
              { name: 'read_only_projection', status: 'passed', rationale: 'Metadata refs only.' },
              { name: 'owner_notice', status: 'passed', rationale: 'Owner assigned.' },
              { name: 'runtime_evidence', status: 'passed', rationale: 'Last-used evidence exists.' }
            ],
            ready_for_apply: true,
            read_only_projection: true,
            source_signals: ['unused_dormant_access', 'iam_last_used'],
            evidence: [
              {
                source: 'iam_last_used',
                evidence_ref: `runtime-evidence://access-key/${accessKeyID}`,
                label: accessKeyID,
                confidence: 0.86,
                observed_at: '2026-03-17T09:35:00Z',
                relationship: 'stale_access_key'
              }
            ],
            evidence_boundary: 'metadata_only_no_secret_values_no_payloads',
            impacted_nodes: [`aws:iam-access-key:${accessKeyID}`, 'aws:identity:user/orders-ci'],
            impacted_path: [],
            next_action: 'Notify the owner and wait through the grace window.',
            created_at: '2026-06-25T09:35:00Z',
            updated_at: '2026-06-25T09:35:00Z'
          }
        ],
        summary: {
          total_plans: 1,
          filtered_plans: 1,
          quarantine_state_counts: { quarantine_candidate: 1 },
          severity_counts: { high: 1 },
          status_counts: { ready_for_quarantine: 1 },
          owner_assigned_count: 1,
          ownerless_count: 0,
          ready_for_apply_count: 1,
          access_key_count: 1,
          affected_principal_count: 1,
          relationship_count: 2,
          highest_score: 82,
          average_confidence_pct: 86
        },
        relationships: [],
        caveats: ['Plans never disable IAM access keys directly.'],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectBlastRadius').mockResolvedValue({
      intelligence: {
        status: 'degraded',
        findings: [],
        summary: { critical_count: 0, high_count: 0, relationship_count: 0, remediation_preview_count: 0 },
        caveats: [],
        failure_reasons: [],
        remediation_hints: []
      } as any
    });
    const getLeastPrivilege = vi
      .spyOn(api.apiClient, 'getAWSProjectLeastPrivilege')
      .mockResolvedValue({ recommendations: readyAWSLeastPrivilege });
    const getUnusedDormantAccess = vi
      .spyOn(api.apiClient, 'getAWSProjectUnusedDormantAccess')
      .mockResolvedValue({ findings: readyAWSUnusedDormantAccess });
    vi.spyOn(api.apiClient, 'getAWSProjectIdentitySprawl').mockResolvedValue({
      findings: {
        status: 'degraded',
        findings: [],
        summary: {
          total_findings: 0,
          stale_identity_count: 0,
          ownerless_identity_count: 0,
          duplicate_identity_count: 0,
          duplicate_cluster_count: 0,
          shared_role_count: 0,
          unique_identity_count: 0,
          unique_workload_count: 0,
          relationship_count: 0,
          highest_score: 0,
          average_confidence_pct: 0,
          remediation_preview_count: 0
        },
        clusters: [],
        relationships: [],
        caveats: [],
        failure_reasons: ['live identity-bearing inventory is unavailable'],
        remediation_hints: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    const getPrivilegeEscalation = vi.spyOn(api.apiClient, 'getAWSProjectPrivilegeEscalation').mockResolvedValue({
      findings: {
        status: 'ready',
        findings: [
          {
            finding_id: 'aws-privilege-escalation:security-admin',
            calculation_version: 'aws-privilege-escalation-engine-v1',
            escalation_type: 'passrole_unscoped_trust_path',
            severity: 'critical',
            status: 'action_required',
            score: 92,
            confidence: 0.92,
            account_id: '123456789012',
            region: 'us-east-1',
            identity_node_id: 'aws:identity:security-admin',
            principal_arn: 'arn:aws:iam::123456789012:role/security-admin',
            target_node_id: '*',
            target_label: '*',
            display_name: 'security-admin',
            rationale: 'Role can pass any role without iam:PassedToService scoping.',
            exploitability: 'high',
            runtime_context: 'static PassRole grant',
            policy_sources: ['PassAny'],
            impacted_nodes: ['aws:identity:security-admin', '*'],
            impacted_path: [
              { node_id: 'aws:identity:security-admin', node_type: 'identity', label: 'security-admin' },
              { node_id: '*', node_type: 'iam_role', label: '*' }
            ],
            evidence: [
              {
                source: 'iam_passrole_relationship',
                evidence_ref: 'evidence://passrole/security-admin',
                label: 'IAM PassRole relationship',
                confidence: 0.92,
                observed_at: '2026-06-21T12:00:00Z',
                relationship: 'can_pass_role'
              }
            ],
            next_action: 'Constrain iam:PassRole to specific approved role ARNs and iam:PassedToService conditions.',
            remediation_case: {
              case_id: 'aws-privilege-escalation-preview:security-admin',
              title: 'PassRole review',
              recommended_action: 'Constrain iam:PassRole.',
              approval_required: true,
              blocking_evidence: ['evidence://passrole/security-admin'],
              impacted_node_count: 2,
              estimated_risk_drop: 40,
              breakage_prediction: 'unknown',
              read_only_projection: true
            },
            created_at: '2026-06-21T12:00:00Z',
            updated_at: '2026-06-21T12:00:00Z'
          }
        ],
        summary: {
          total_findings: 1,
          filtered_findings: 1,
          critical_count: 1,
          high_count: 0,
          passrole_path_count: 1,
          admin_equivalent_count: 0,
          cross_account_path_count: 0,
          relationship_count: 1,
          highest_score: 92,
          average_confidence_pct: 92,
          remediation_preview_count: 1,
          severity_counts: { critical: 1 },
          status_counts: { action_required: 1 },
          escalation_type_counts: { passrole_unscoped_trust_path: 1 }
        },
        relationships: [],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    const getCrossAccountTrust = vi.spyOn(api.apiClient, 'getAWSProjectCrossAccountTrust').mockResolvedValue({
      findings: {
        status: 'ready',
        findings: [
          {
            finding_id: 'aws-cross-account-trust:partner-feed',
            calculation_version: 'aws-cross-account-trust-engine-v1',
            finding_type: 'cross_account_resource_access',
            severity: 'high',
            status: 'review',
            score: 86,
            confidence: 0.9,
            account_id: '123456789012',
            region: 'us-east-1',
            service: 'kms',
            resource_type: 'kms_key',
            resource_arn: 'arn:aws:kms:us-east-1:123456789012:key/partner-feed',
            resource_node_id: 'aws:resource:kms-key/partner-feed',
            resource_label: 'partner-feed',
            external_principal_arn: 'arn:aws:iam::999999999999:role/partner-ingest',
            external_principal_account: '999999999999',
            trusted_within_organization: false,
            public_principal: false,
            has_condition: false,
            policy_sources: ['kms:Decrypt'],
            runtime_observed: false,
            analyzer_backed: false,
            rationale: 'KMS key trusts a partner role without condition scoping.',
            hardening_direction: 'Add external ID or source conditions.',
            impacted_nodes: ['aws:identity:arn:aws:iam::999999999999:role/partner-ingest', 'aws:resource:kms-key/partner-feed'],
            impacted_path: [
              { node_id: 'aws:identity:arn:aws:iam::999999999999:role/partner-ingest', node_type: 'external_principal', label: 'partner-ingest' },
              { node_id: 'aws:resource:kms-key/partner-feed', node_type: 'kms_key', label: 'partner-feed' }
            ],
            evidence: [
              {
                source: 'kms_decrypt_reachability',
                evidence_ref: 'evidence://kms/partner-feed',
                label: 'External resource trust',
                confidence: 0.9,
                observed_at: '2026-06-21T13:00:00Z',
                relationship: 'cross_account_resource_access'
              }
            ],
            next_action: 'Confirm the external principal owner before hardening.',
            remediation_case: {
              case_id: 'aws-cross-account-trust-preview:partner-feed',
              title: 'Cross-account trust hardening',
              recommended_action: 'Create an owner-approved trust hardening preview.',
              approval_required: true,
              blocking_evidence: ['evidence://kms/partner-feed'],
              impacted_node_count: 2,
              estimated_risk_drop: 35,
              breakage_prediction: 'unknown',
              read_only_projection: true
            },
            created_at: '2026-06-21T13:00:00Z',
            updated_at: '2026-06-21T13:00:00Z'
          }
        ],
        summary: {
          total_findings: 1,
          filtered_findings: 1,
          critical_count: 0,
          high_count: 1,
          public_principal_count: 0,
          cross_account_grant_count: 1,
          runtime_observed_count: 0,
          analyzer_backed_count: 0,
          unconditional_grant_count: 1,
          relationship_count: 1,
          highest_score: 86,
          average_confidence_pct: 90,
          remediation_preview_count: 1,
          severity_counts: { high: 1 },
          status_counts: { review: 1 },
          finding_type_counts: { cross_account_resource_access: 1 },
          service_counts: { kms: 1 }
        },
        relationships: [],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    const getSecretPermissionEquivalence = vi.spyOn(api.apiClient, 'getAWSProjectSecretPermissionEquivalence').mockResolvedValue({
      findings: {
        status: 'ready',
        findings: [
          {
            finding_id: 'aws-secret-permission-equivalence:openai-agent',
            calculation_version: 'aws-secret-permission-equivalence-engine-v1',
            equivalence_type: 'agent_provider_key_equivalence',
            severity: 'high',
            status: 'review',
            score: 82,
            confidence: 0.9,
            account_id: '123456789012',
            region: 'us-east-1',
            identity_node_id: 'aws:identity:arn:aws:iam::123456789012:role/case-triage-runtime',
            principal_arn: 'arn:aws:iam::123456789012:role/case-triage-runtime',
            agent_id: 'case-triage',
            agent_name: 'case-triage',
            secret_node_id: 'aws:resource:secrets-manager-secret:openai/api-key',
            secret_arn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:openai/api-key',
            secret_label: 'openai/api-key',
            provider: 'openai',
            provider_key_reference: 'OPENAI_API_KEY',
            equivalent_permissions: ['openai:api_request', 'openai:model_inference'],
            source_signals: ['ai_agent_identities'],
            rationale: 'Agent has OpenAI provider-key metadata without exposing the key value.',
            evidence_boundary: 'metadata_only_no_secret_values_no_payloads',
            impacted_nodes: [
              'aws:identity:arn:aws:iam::123456789012:role/case-triage-runtime',
              'aws:resource:secrets-manager-secret:openai/api-key'
            ],
            impacted_path: [
              { node_id: 'aws:identity:arn:aws:iam::123456789012:role/case-triage-runtime', node_type: 'identity', label: 'case-triage-runtime' },
              { node_id: 'aws:agent:case-triage', node_type: 'ai_agent', label: 'case-triage' },
              { node_id: 'aws:resource:secrets-manager-secret:openai/api-key', node_type: 'permission_bearing_secret', label: 'openai/api-key' }
            ],
            evidence: [
              {
                source: 'ai_agent_identities',
                evidence_ref: 'evidence://agent/case-triage/openai',
                label: 'Agent provider-key metadata',
                confidence: 0.9,
                observed_at: '2026-06-21T13:30:00Z',
                relationship: 'agent_uses_permission_bearing_secret'
              }
            ],
            next_action: 'Rotate or scope the provider credential and restrict every identity that can read it.',
            remediation_case: {
              case_id: 'aws-secret-permission-equivalence-preview:openai-agent',
              title: 'Provider key review',
              recommended_action: 'Restrict secret readers.',
              approval_required: true,
              blocking_evidence: ['evidence://agent/case-triage/openai'],
              impacted_node_count: 2,
              estimated_risk_drop: 40,
              breakage_prediction: 'unknown',
              read_only_projection: true
            },
            created_at: '2026-06-21T13:30:00Z',
            updated_at: '2026-06-21T13:30:00Z'
          }
        ],
        summary: {
          total_findings: 1,
          filtered_findings: 1,
          external_provider_key_count: 1,
          aws_managed_secret_count: 0,
          runtime_observed_count: 0,
          kms_backed_count: 0,
          unresolved_reference_count: 0,
          relationship_count: 1,
          highest_score: 82,
          average_confidence_pct: 90,
          remediation_preview_count: 1,
          severity_counts: { high: 1 },
          status_counts: { review: 1 },
          equivalence_type_counts: { agent_provider_key_equivalence: 1 },
          provider_counts: { openai: 1 }
        },
        relationships: [],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });

    const { ProductAWSRuntimePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/runtime?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/runtime" element={<ProductAWSRuntimePage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Runtime' })).toBeInTheDocument();
    expect(await screen.findByText(/CloudTrail: GetObject/i)).toBeInTheDocument();
    expect(await screen.findByText(/Access Analyzer: Finding/i)).toBeInTheDocument();
    const runtimeTimeline = await screen.findByRole('region', { name: 'AWS runtime correlation timeline' });
    expect(within(runtimeTimeline).getByRole('heading', { level: 3, name: 'Runtime timeline' })).toBeInTheDocument();
    expect(within(runtimeTimeline).getByText(/STS AssumeRole.*AssumeRole/i)).toBeInTheDocument();
    expect(within(runtimeTimeline).getAllByText(/SourceIdentity billing-operator@example.com/i).length).toBeGreaterThan(0);
    expect(within(runtimeTimeline).getByText(/runtime-evidence:\/\/123456789012\/us-east-1\/evt-assume-role/i)).toBeInTheDocument();
    expect(within(runtimeTimeline).getByRole('link', { name: '/docs/aws-runtime-events' })).toHaveAttribute(
      'href',
      '/docs/aws-runtime-events'
    );
    expect(within(runtimeTimeline).getByRole('link', { name: 'https://docs.identrail.com/aws-runtime-events' })).toHaveAttribute(
      'href',
      'https://docs.identrail.com/aws-runtime-events'
    );
    expect(within(runtimeTimeline).queryByRole('link', { name: /javascript:alert/i })).not.toBeInTheDocument();
    expect(await within(runtimeTimeline).findByText(/Secret Â· prod\/ai\/openai-key/i)).toBeInTheDocument();
    expect(within(runtimeTimeline).getByText(/S3 Â· billing-artifacts-123456789012/i)).toBeInTheDocument();
    expect(within(runtimeTimeline).getByText(/Agent Â· runtime-case-triage Â· case-router/i)).toBeInTheDocument();
    expect(await within(runtimeTimeline).findByText(/Case Â· Rotate external credential for support-assistant/i)).toBeInTheDocument();
    expect(within(runtimeTimeline).getByText(/Before evidence:\/\/agent\/support-assistant\/anthropic/i)).toBeInTheDocument();
    expect(within(runtimeTimeline).getByText(/After secret:\/\/aws:resource:credential-reference:support-anthropic-key\/scoped-projection/i)).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS AI agent risk findings' })).toBeInTheDocument();
    expect(screen.getAllByText(/External credential exposure/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS remediation cases' })).toBeInTheDocument();
    expect(screen.getAllByText(/Rotate external credential for support-assistant/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Secret rotation/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS IAM policy diffs' })).toBeInTheDocument();
    expect(screen.getByText(/Scope data-loader: remove 2 action\(s\)/i)).toBeInTheDocument();
    expect(screen.getAllByText(/ready Â· Low breakage/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS trust policy hardening plans' })).toBeInTheDocument();
    expect(screen.getByText(/Add org\/source condition to payments-cross-account trust/i)).toBeInTheDocument();
    expect(screen.getAllByText(/sts:ExternalId/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS permission boundary and SCP plans' })).toBeInTheDocument();
    expect(screen.getByText(/Permission boundary: deny s3:DeleteObject across 3 identities/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Permission boundary/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS permission boundary executor entries' })).toBeInTheDocument();
    expect(screen.getByText(/Permission boundary execution: deny s3:DeleteObject/i)).toBeInTheDocument();
    expect(screen.getAllByText(/PutRolePermissionsBoundary/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS SCP guardrail executor entries' })).toBeInTheDocument();
    expect(screen.getByText(/SCP guardrail execution: external trust guardrail/i)).toBeInTheDocument();
    expect(screen.getAllByText(/AttachPolicy/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS secret/key rotation plans' })).toBeInTheDocument();
    expect(screen.getByText(/Provider key rotation: openai\/api-key/i)).toBeInTheDocument();
    expect(screen.getAllByText(/ai-platform Â· Pending approver/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS access key quarantine plans' })).toBeInTheDocument();
    expect(screen.getByText(new RegExp(`Access key quarantine: ${accessKeyID}`, 'i'))).toBeInTheDocument();
    expect(screen.getAllByText(/orders-platform Â· Owner notification required/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS least privilege recommendations' })).toBeInTheDocument();
    expect(screen.getByText(/Remove secretsmanager:GetSecretValue/i)).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS unused and dormant access findings' })).toBeInTheDocument();
    expect(screen.getAllByText(/Cleanup candidate/i).length).toBeGreaterThan(0);
    expect(await screen.findByText(/Identity sprawl could not be calculated/i)).toBeInTheDocument();
    expect(screen.getByText(/live identity-bearing inventory is unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText(/No identity sprawl detected/i)).not.toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS privilege escalation findings' })).toBeInTheDocument();
    expect(screen.getByText(/Passrole unscoped trust path/i)).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS cross-account trust findings' })).toBeInTheDocument();
    expect(screen.getByText(/Cross account resource access/i)).toBeInTheDocument();
    const secretPermissionTable = await screen.findByRole('table', { name: 'AWS secret-to-permission equivalence findings' });
    expect(secretPermissionTable).toBeInTheDocument();
    expect(within(secretPermissionTable).getByRole('link', { name: /Agent provider key equivalence/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/agents/detail?environment=production&agent=case-triage&tab=secrets'
    );
    expect(getLeastPrivilege).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getAIAgentRisk).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getPrivilegeEscalation).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getCrossAccountTrust).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getSecretPermissionEquivalence).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getSecretKeyRotation).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getAccessKeyQuarantine).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getPermissionBoundaryExecutor).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getScpGuardrailExecutor).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getPostRemediationVerification).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getAdvisoryAuthorization).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getSessionPolicyRecommendations).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getAgentCoreGatewayPolicyAdvisory).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(getUnusedDormantAccess).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Event type' }), {
      target: { value: 'cloudtrail' }
    });

    await waitFor(() =>
      expect(getRuntimeEvents).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', eventType: 'api-call' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(screen.getByText(/CloudTrail: GetObject/i)).toBeInTheDocument();
    expect(screen.queryByText(/Agent tool: InvokeTool/i)).not.toBeInTheDocument();

    fireEvent.change(screen.getByRole('combobox', { name: 'Evidence' }), {
      target: { value: 'cloudtrail' }
    });

    await waitFor(() =>
      expect(getRuntimeEvents).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', eventType: 'api-call', evidence: 'cloudtrail' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Event type' }), {
      target: { value: 'all' }
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'Evidence' }), {
      target: { value: 'all' }
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'Status' }), {
      target: { value: 'stale' }
    });

    await waitFor(() =>
      expect(getRuntimeEvents).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', status: 'stale' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(screen.getByText(/Access Analyzer: Finding/i)).toBeInTheDocument();
    expect(screen.queryByText(/CloudTrail: GetObject/i)).not.toBeInTheDocument();
    const staleRuntimeTimeline = screen.getByRole('region', { name: 'AWS runtime correlation timeline' });
    expect(within(staleRuntimeTimeline).getByText(/Access Analyzer.*Finding/i)).toBeInTheDocument();
    expect(within(staleRuntimeTimeline).queryByText(/Secret Â· prod\/ai\/openai-key/i)).not.toBeInTheDocument();
    expect(within(staleRuntimeTimeline).queryByText(/S3 Â· billing-artifacts-123456789012/i)).not.toBeInTheDocument();
    expect(within(staleRuntimeTimeline).queryByText(/Agent Â· runtime-case-triage Â· case-router/i)).not.toBeInTheDocument();
    expect(within(staleRuntimeTimeline).queryByText(/Case Â· Rotate external credential for support-assistant/i)).not.toBeInTheDocument();
  });

  it('shows AWS limited enforcement framework on the governance route', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const getGovernanceAuditReporting = vi.spyOn(api.apiClient, 'getAWSProjectGovernanceAuditReporting').mockResolvedValue({
      governance_audit_reporting: {
        status: 'ready',
        policy_version: 'aws-governance-audit-reporting-policy-v1',
        records: [
          {
            report_id: 'aws-governance-audit:orders',
            calculation_version: 'aws-governance-audit-reporting-v1',
            policy_version: 'aws-limited-enforcement-pilot-policy-v1',
            category: 'enforcement_outcome',
            source_type: 'advisory_authorization',
            source_id: 'aws-limited-enforcement-pilot:orders',
            decision_type: 'limited_enforcement_pilot',
            outcome: 'allow',
            state: 'pilot_canary_ready',
            mode: 'pilot',
            actor: 'identrail-limited-enforcement-pilot',
            account_id: '123456789012',
            region: 'us-east-1',
            identity_node_id: 'aws:identity:orders-deployer',
            action: 'iam:PutRolePolicy',
            confidence: 0.95,
            score: 80,
            title: 'Governance audit: orders deployer',
            summary: 'Export-safe enforcement outcome report row.',
            input_hash: 'audit-hash-a',
            evidence_summary: null,
            evidence_links: ['/docs/aws-limited-enforcement-pilot'],
            evidence_boundary: 'metadata_only_exportable_refs_no_secret_values_no_rendered_policy_bodies_no_customer_payloads',
            audit_trail: null,
            read_only_projection: true,
            exception: false,
            next_action: 'Export the audit row.',
            occurred_at: '2026-07-03T10:00:00Z',
            updated_at: '2026-07-03T10:00:00Z'
          },
          {
            report_id: 'aws-governance-audit:approval',
            calculation_version: 'aws-governance-audit-reporting-v1',
            policy_version: 'aws-governance-audit-reporting-policy-v1',
            category: 'approval',
            source_type: 'aws_permission_boundary_scp',
            source_id: 'aws-remediation-approval:boundary',
            decision_type: 'remediation_approval',
            outcome: 'under_review',
            state: 'under_review',
            approver: 'security_admin',
            account_id: '123456789012',
            region: 'us-east-1',
            confidence: 0.88,
            score: 74,
            title: 'Governance audit approval: boundary review',
            summary: 'Export-safe approval workflow report row.',
            input_hash: 'audit-hash-b',
            evidence_summary: [],
            evidence_links: [],
            evidence_boundary: 'metadata_only_exportable_refs_no_secret_values_no_rendered_policy_bodies_no_customer_payloads',
            audit_trail: [],
            read_only_projection: true,
            exception: false,
            next_action: 'Review the approval.',
            occurred_at: '2026-07-03T10:05:00Z',
            updated_at: '2026-07-03T10:05:00Z'
          },
          {
            report_id: 'aws-governance-audit:verification',
            calculation_version: 'aws-governance-audit-reporting-v1',
            policy_version: 'aws-governance-audit-reporting-policy-v1',
            category: 'remediation',
            source_type: 'post_remediation_verification',
            source_id: 'aws-post-remediation-verification:boundary',
            decision_type: 'post_remediation_verification',
            outcome: 'verified',
            state: 'verified',
            actor: 'identrail-post-remediation-verification',
            account_id: '123456789012',
            region: 'us-east-1',
            confidence: 0.82,
            score: 70,
            title: 'Governance audit remediation: boundary verified',
            summary: 'Export-safe remediation verification report row.',
            input_hash: 'audit-hash-c',
            evidence_summary: [],
            evidence_links: [],
            evidence_boundary: 'metadata_only_exportable_refs_no_secret_values_no_rendered_policy_bodies_no_customer_payloads',
            audit_trail: [],
            read_only_projection: true,
            exception: false,
            next_action: 'Export the verification.',
            occurred_at: '2026-07-03T10:10:00Z',
            updated_at: '2026-07-03T10:10:00Z'
          }
        ],
        applied_filters: {},
        summary: {
          total_records: 3,
          filtered_records: 3,
          category_counts: { enforcement_outcome: 1, approval: 1, remediation: 1 },
          decision_type_counts: { limited_enforcement_pilot: 1, remediation_approval: 1, post_remediation_verification: 1 },
          state_counts: { pilot_canary_ready: 1, under_review: 1, verified: 1 },
          source_type_counts: { advisory_authorization: 1, aws_permission_boundary_scp: 1, post_remediation_verification: 1 },
          account_counts: { '123456789012': 3 },
          decision_count: 0,
          approval_count: 1,
          remediation_count: 1,
          enforcement_outcome_count: 1,
          exception_count: 0,
          exportable_evidence_count: 1,
          audit_entry_count: 0,
          highest_score: 80,
          average_confidence_pct: 95
        },
        caveats: null,
        failure_reasons: null,
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    const getLimitedEnforcement = vi.spyOn(api.apiClient, 'getAWSProjectLimitedEnforcement').mockResolvedValue({
      limited_enforcement: {
        status: 'ready',
        policy_version: 'aws-limited-enforcement-policy-v1',
        safety_config: {
          feature_flag_enabled: true,
          kill_switch_engaged: false,
          canary_percent: 25,
          cohort: 'pilot-a',
          rollback_required: true,
          audit_required: true
        },
        entries: [
          {
            enforcement_id: 'aws-limited-enforcement:orders',
            calculation_version: 'aws-limited-enforcement-v1',
            policy_version: 'aws-limited-enforcement-policy-v1',
            source_type: 'advisory_authorization',
            source_id: 'aws-advisory-authorization:orders',
            mode: 'limited_enforce',
            enforcement_state: 'canary_ready',
            outcome: 'allow',
            confidence: 0.9,
            severity: 'high',
            score: 80,
            title: 'Limited enforcement framework: orders deployer',
            summary: 'Canary-ready limited enforcement framework projection.',
            account_id: '123456789012',
            region: 'us-east-1',
            principal_node_id: 'aws:identity:orders-deployer',
            action: 'iam:PutRolePolicy',
            target_scope: ['aws:identity:orders-deployer'],
            safety_config: {
              feature_flag_enabled: true,
              kill_switch_engaged: false,
              canary_percent: 25,
              cohort: 'pilot-a',
              rollback_required: true,
              audit_required: true
            },
            gates: [
              { name: 'feature_flag_enabled', status: 'passed', rationale: 'Feature flag is enabled.' },
              { name: 'canary_configured', status: 'passed', rationale: 'Pilot cohort is scoped.' }
            ],
            rollback: {
              strategy: 'disable_limited_enforcement_and_revert_to_advisory',
              steps: ['Disable feature flag.'],
              state: 'available',
              rationale: 'Rollback remains available.'
            },
            evidence: [],
            evidence_links: ['/docs/aws-limited-enforcement'],
            evidence_boundary: 'metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads',
            input_hash: 'hash-a',
            audit_trail: [],
            read_only_projection: true,
            ready_for_canary: true,
            ready_for_enforcement: false,
            next_action: 'Monitor the canary.',
            projected_at: '2026-07-03T10:00:00Z',
            updated_at: '2026-07-03T10:00:00Z'
          }
        ],
        relationships: [],
        applied_filters: {},
        summary: {
          total_entries: 1,
          filtered_entries: 1,
          mode_counts: { limited_enforce: 1 },
          enforcement_state_counts: { canary_ready: 1 },
          outcome_counts: { allow: 1 },
          source_type_counts: { advisory_authorization: 1 },
          warn_only_count: 0,
          advisory_count: 0,
          approval_required_count: 0,
          limited_enforce_count: 1,
          canary_ready_count: 1,
          ready_for_enforcement_count: 0,
          kill_switch_engaged_count: 0,
          failed_gate_count: 0,
          relationship_count: 0,
          highest_score: 80,
          average_confidence_pct: 90
        },
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });
    const getLimitedEnforcementPilot = vi.spyOn(api.apiClient, 'getAWSProjectLimitedEnforcementPilot').mockResolvedValue({
      limited_enforcement_pilot: {
        status: 'ready',
        mode: 'pilot',
        policy_version: 'aws-limited-enforcement-pilot-policy-v1',
        operator_override: 'resume',
        safety_config: {
          feature_flag_enabled: true,
          kill_switch_engaged: false,
          canary_percent: 10,
          cohort: 'pilot-a',
          rollback_required: true,
          audit_required: true
        },
        rollback_thresholds: {
          max_denial_regression_pct: 1,
          observation_window: '24h',
          auto_rollback_on_kill_switch: true,
          operator_override_halts_pilot: true
        },
        decisions: [
          {
            pilot_id: 'aws-limited-enforcement-pilot:orders',
            calculation_version: 'aws-limited-enforcement-pilot-v1',
            policy_version: 'aws-limited-enforcement-pilot-policy-v1',
            mode: 'pilot',
            pilot_state: 'pilot_canary_ready',
            eligible: true,
            enforcement_id: 'aws-limited-enforcement:orders',
            source_type: 'advisory_authorization',
            source_id: 'aws-advisory-authorization:orders',
            outcome: 'allow',
            confidence: 0.95,
            severity: 'high',
            score: 80,
            title: 'Enforcement pilot: orders deployer',
            summary: 'Pilot canary-ready decision.',
            rationale: 'Every eligibility rule passed.',
            account_id: '123456789012',
            region: 'us-east-1',
            principal_node_id: 'aws:identity:orders-deployer',
            action: 'iam:PutRolePolicy',
            cohort: 'pilot-a',
            operator_override: 'resume',
            eligibility_rules: [
              { name: 'limited_enforce_mode', status: 'passed', rationale: 'Limited-enforce mode.' },
              { name: 'high_confidence', status: 'passed', rationale: 'Confidence above the pilot floor.' }
            ],
            rollback_thresholds: {
              max_denial_regression_pct: 1,
              observation_window: '24h',
              auto_rollback_on_kill_switch: true,
              operator_override_halts_pilot: true
            },
            metrics: {
              eligibility_rules_passed: 2,
              eligibility_rules_total: 2,
              framework_gates_passed: 2,
              framework_gates_total: 2,
              confidence_pct: 95,
              canary_percent: 10
            },
            evidence_links: ['/docs/aws-limited-enforcement-pilot'],
            evidence_boundary: 'metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads',
            input_hash: 'pilot-hash-a',
            audit_trail: [],
            read_only_projection: true,
            next_action: 'Watch denial-regression metrics.',
            projected_at: '2026-07-03T10:00:00Z',
            updated_at: '2026-07-03T10:00:00Z'
          }
        ],
        relationships: [],
        applied_filters: {},
        summary: {
          total_decisions: 1,
          filtered_decisions: 1,
          pilot_state_counts: { pilot_canary_ready: 1 },
          outcome_counts: { allow: 1 },
          source_type_counts: { advisory_authorization: 1 },
          severity_counts: { high: 1 },
          eligible_count: 1,
          ineligible_count: 0,
          canary_ready_count: 1,
          enforce_ready_count: 0,
          override_hold_count: 0,
          kill_switch_engaged_count: 0,
          failed_rule_count: 0,
          relationship_count: 0,
          highest_score: 80,
          average_confidence_pct: 95
        },
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: []
      } as any
    });

    const { ProductAWSGovernancePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/governance?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/governance" element={<ProductAWSGovernancePage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Governance' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS governance audit reporting records' })).toBeInTheDocument();
    expect(screen.getByText(/Governance audit: orders deployer/i)).toBeInTheDocument();
    expect(screen.getByText(/Governance audit approval: boundary review/i)).toBeInTheDocument();
    expect(screen.getByText(/Governance audit remediation: boundary verified/i)).toBeInTheDocument();
    const approvalRow = screen.getByText(/Governance audit approval: boundary review/i).closest('tr');
    expect(approvalRow).not.toBeNull();
    expect(within(approvalRow as HTMLTableRowElement).getByText('88%')).toHaveClass('is-success');
    const remediationRow = screen.getByText(/Governance audit remediation: boundary verified/i).closest('tr');
    expect(remediationRow).not.toBeNull();
    expect(within(remediationRow as HTMLTableRowElement).getByText('82%')).toHaveClass('is-success');
    expect(getGovernanceAuditReporting).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Decision' }), {
      target: { value: 'approval' }
    });
    await waitFor(() =>
      expect(getGovernanceAuditReporting).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', category: 'approval' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByRole('table', { name: 'AWS limited enforcement framework entries' })).toBeInTheDocument();
    expect(screen.getByText(/Limited enforcement framework: orders deployer/i)).toBeInTheDocument();
    expect(screen.getByText(/pilot-a/i)).toBeInTheDocument();
    expect(getLimitedEnforcement).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(await screen.findByRole('table', { name: 'AWS limited enforcement pilot decisions' })).toBeInTheDocument();
    expect(screen.getByText(/Enforcement pilot: orders deployer/i)).toBeInTheDocument();
    expect(getLimitedEnforcementPilot).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('loads governance audit reporting for disconnected connectors with diagnostics', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({
      connection: {
        ...disconnectedAWS,
        connector_id: 'aws-denied',
        display_name: 'Denied AWS',
        account_id: '123456789012',
        region: 'us-east-1',
        diagnostics: [
          {
            code: 'permission_denied',
            message: 'Organizations read access denied.'
          }
        ]
      }
    });
    const getGovernanceAuditReporting = vi.spyOn(api.apiClient, 'getAWSProjectGovernanceAuditReporting').mockResolvedValue({
      governance_audit_reporting: {
        status: 'blocked',
        policy_version: 'aws-governance-audit-reporting-policy-v1',
        records: [],
        applied_filters: {},
        summary: {
          total_records: 0,
          filtered_records: 0,
          category_counts: {},
          decision_type_counts: {},
          state_counts: {},
          source_type_counts: {},
          account_counts: {},
          decision_count: 0,
          approval_count: 0,
          remediation_count: 0,
          enforcement_outcome_count: 0,
          exception_count: 0,
          exportable_evidence_count: 0,
          audit_entry_count: 0,
          highest_score: 0,
          average_confidence_pct: 0
        },
        caveats: [],
        failure_reasons: ['Organizations read access denied.'],
        remediation_hints: [],
        evidence_links: [],
        coverage_gaps: [],
        diagnostics: [
          {
            collector: 'organizations',
            source_id: 'aws-denied',
            code: 'permission_denied',
            message: 'Organizations read access denied.',
            retryable: true
          }
        ]
      } as any
    });

    const { ProductAWSGovernancePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/governance?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/governance" element={<ProductAWSGovernancePage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Governance' })).toBeInTheDocument();
    await waitFor(() =>
      expect(getGovernanceAuditReporting).toHaveBeenCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-denied' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByText(/Permission required/i)).toBeInTheDocument();
    expect(screen.getByText(/Organizations read access denied/i)).toBeInTheDocument();
  });

  it('shows AWS platform observability and forwards health filters', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const getPlatformObservability = vi.spyOn(api.apiClient, 'getAWSProjectPlatformObservability').mockResolvedValue({
      platform_observability: {
        status: 'degraded',
        confidence: 0.82,
        current_issue_ref: '#1556',
        version: 'aws-platform-observability-v1',
        applied_filters: {},
        summary: {
          total_metrics: 2,
          filtered_metrics: 2,
          total_traces: 1,
          filtered_traces: 1,
          ready_signals: 1,
          degraded_signals: 1,
          blocked_signals: 0,
          alert_count: 1,
          critical_alert_count: 0,
          scan_throughput_per_hour: 12,
          queue_lag_p95_ms: 120000,
          runtime_lag_p95_ms: 60000,
          collector_failure_count: 0,
          throttled_target_count: 0,
          remediation_pending_count: 3,
          verification_failed_count: 1,
          governance_exception_count: 0,
          account_counts: { '123456789012': 2 },
          region_counts: { 'us-east-1': 2 },
          service_counts: { iam: 1, all: 1 },
          component_counts: { collector: 1, verification: 1 },
          status_counts: { ready: 1, degraded: 1 }
        },
        metrics: [
          {
            metric_id: 'scan-throughput',
            component: 'collector',
            signal: 'scan_throughput',
            title: 'Scan throughput',
            summary: 'Targets completed by fan-out.',
            value: 12,
            unit: 'targets_per_hour',
            status: 'ready',
            severity: 'low',
            confidence: 0.94,
            account_id: '123456789012',
            region: 'us-east-1',
            service: 'iam',
            trace_id: 'metric:collector:scan-throughput',
            evidence_links: ['/docs/aws-platform-observability'],
            evidence_ref: 'aws-platform-observability://scan-throughput',
            evidence_boundary: 'metadata_only_platform_observability_no_secret_values_no_customer_payloads',
            next_action: 'Confirm expected targets are advancing.',
            observed_at: '2026-07-09T12:00:00Z',
            updated_at: '2026-07-09T12:00:00Z'
          },
          {
            metric_id: 'verification-outcomes',
            component: 'verification',
            signal: 'verification_outcomes',
            title: 'Verification outcomes',
            summary: 'Failed verification outcomes.',
            value: 1,
            unit: 'outcomes',
            status: 'degraded',
            severity: 'high',
            confidence: 0.78,
            account_id: '123456789012',
            region: 'us-east-1',
            service: 'all',
            trace_id: 'metric:verification:verification-outcomes',
            evidence_links: ['/docs/aws-post-remediation-verification'],
            evidence_ref: 'aws-platform-observability://verification-outcomes',
            evidence_boundary: 'metadata_only_platform_observability_no_secret_values_no_customer_payloads',
            next_action: 'Review failed checks before reporting closure.',
            observed_at: '2026-07-09T12:00:00Z',
            updated_at: '2026-07-09T12:00:00Z'
          }
        ],
        traces: [
          {
            trace_id: 'trace:verification:case-1',
            span_name: 'aws.remediation.verify',
            component: 'verification',
            account_id: '123456789012',
            region: 'us-east-1',
            service: 'aws_scp_guardrail_executor',
            status: 'degraded',
            duration_ms: 2000,
            queue_lag_ms: 0,
            runtime_lag_ms: 0,
            retry_count: 1,
            throttled: false,
            evidence_links: ['/docs/aws-post-remediation-verification'],
            evidence_ref: 'verification://case-1',
            evidence_boundary: 'metadata_only_platform_observability_no_secret_values_no_customer_payloads',
            next_action: 'Review failed checks.',
            started_at: '2026-07-09T11:59:00Z',
            ended_at: '2026-07-09T12:00:00Z'
          }
        ],
        alerts: [
          {
            alert_id: 'alert:verification',
            severity: 'high',
            component: 'verification',
            status: 'degraded',
            title: 'Verification outcomes',
            summary: 'Failed verification outcomes.',
            evidence_ref: 'aws-platform-observability://verification-outcomes',
            evidence_boundary: 'metadata_only_platform_observability_no_secret_values_no_customer_payloads',
            next_action: 'Review failed checks before reporting closure.',
            triggered_at: '2026-07-09T12:00:00Z'
          }
        ],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: ['/docs/aws-platform-observability'],
        coverage_gaps: [],
        diagnostics: [],
        generated_at: '2026-07-09T12:00:00Z',
        updated_at: '2026-07-09T12:00:00Z'
      } as any
    });

    const { ProductAWSPlatformObservabilityPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/observability?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/observability" element={<ProductAWSPlatformObservabilityPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Observability' })).toBeInTheDocument();
    expect(await screen.findByRole('region', { name: 'AWS platform observability summary' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS platform observability metrics' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS platform observability traces' })).toBeInTheDocument();
    expect(screen.getAllByText(/Scan throughput/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Verification outcomes/i).length).toBeGreaterThan(0);
    expect(getPlatformObservability).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Component' }), {
      target: { value: 'verification' }
    });
    await waitFor(() =>
      expect(getPlatformObservability).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', component: 'verification' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('shows AWS GA demo hardening and forwards stage filters', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const getGADemoHardening = vi.spyOn(api.apiClient, 'getAWSProjectGADemoHardening').mockResolvedValue({
      ga_demo_hardening: {
        status: 'degraded',
        confidence: 0.86,
        current_issue_ref: '#1557',
        version: 'aws-ga-demo-hardening-v1',
        applied_filters: {},
        summary: {
          total_stages: 2,
          filtered_stages: 2,
          ready_stages: 1,
          degraded_stages: 1,
          blocked_stages: 0,
          readiness_checks: 2,
          passed_checks: 1,
          required_checks: 2,
          failed_checks: 0,
          permission_warnings: 1,
          status_counts: { ready: 1, degraded: 1 },
          stage_counts: { onboarding: 1, governance: 1 }
        },
        stages: [
          {
            stage_id: 'onboarding',
            order: 1,
            title: 'Onboarding and validation',
            summary: 'AWS connector setup and validation fixtures.',
            status: 'ready',
            confidence: 0.94,
            account_id: '123456789012',
            region: 'us-east-1',
            primary_route: '/app/aws/connect',
            evidence_ref: 'aws-ga-demo://onboarding',
            evidence_links: ['/docs/aws-ga-demo-hardening'],
            evidence_boundary: 'metadata_only_ga_demo_no_secret_values_no_customer_payloads',
            next_action: 'Open connector diagnostics.',
            updated_at: '2026-07-10T09:00:00Z'
          },
          {
            stage_id: 'governance',
            order: 9,
            title: 'Governance reporting',
            summary: 'Export-safe governance metadata.',
            status: 'degraded',
            confidence: 0.78,
            account_id: '123456789012',
            region: 'us-east-1',
            primary_route: '/app/aws/governance',
            evidence_ref: 'aws-ga-demo://governance-reporting',
            evidence_links: ['/docs/aws-governance-audit-reporting'],
            evidence_boundary: 'metadata_only_ga_demo_no_secret_values_no_customer_payloads',
            next_action: 'Resolve governance exceptions.',
            failure_reason: 'Governance exception requires review.',
            updated_at: '2026-07-10T09:00:00Z'
          }
        ],
        readiness_checks: [
          {
            check_id: 'validation-fixtures',
            title: 'App and API fixtures',
            status: 'ready',
            owner: 'platform',
            summary: 'Fixture states are documented.',
            evidence: ['/docs/aws-platform-validation-harness'],
            next_action: 'Run the validation harness.',
            required: true
          },
          {
            check_id: 'permission-docs',
            title: 'Permission documentation',
            status: 'degraded',
            owner: 'security',
            summary: 'Permission docs need review.',
            evidence: ['/docs/aws-ga-demo-hardening'],
            next_action: 'Attach permission docs to handoff.',
            required: true,
            permissions: ['sts:GetCallerIdentity']
          }
        ],
        permissions: ['sts:GetCallerIdentity'],
        safety_notes: ['Read-only.'],
        limitations: ['Coverage is bounded by source contracts.'],
        troubleshooting: ['Review connector diagnostics.'],
        caveats: [],
        failure_reasons: ['Governance exception requires review.'],
        remediation_hints: ['Resolve governance exceptions before handoff.'],
        evidence_links: ['/docs/aws-ga-demo-hardening'],
        generated_at: '2026-07-10T09:00:00Z',
        updated_at: '2026-07-10T09:00:00Z'
      } as any
    });

    const { ProductAWSGADemoPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/ga-demo?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/ga-demo" element={<ProductAWSGADemoPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'GA Demo' })).toBeInTheDocument();
    expect(await screen.findByRole('region', { name: 'AWS GA demo readiness summary' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS GA demo stages' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS GA readiness checks' })).toBeInTheDocument();
    expect(screen.getAllByText(/Governance reporting/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Permission documentation/i).length).toBeGreaterThan(0);
    expect(getGADemoHardening).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Stage' }), {
      target: { value: 'governance' }
    });
    await waitFor(() =>
      expect(getGADemoHardening).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', stage: 'governance' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('shows AWS executive outcome view and forwards outcome filters', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const getExecutiveOutcomes = vi.spyOn(api.apiClient, 'getAWSProjectExecutiveOutcomes').mockResolvedValue({
      executive_outcomes: {
        status: 'ready',
        confidence: 0.9,
        current_issue_ref: '#1555',
        version: 'aws-executive-outcome-view-v1',
        applied_filters: {},
        summary: {
          total_metrics: 3,
          filtered_metrics: 3,
          risk_reduction_score: 72,
          scan_coverage_pct: 83,
          verified_remediation_count: 2,
          enforcement_ready_count: 1,
          remaining_exposure_count: 4,
          degraded_coverage_count: 1,
          governance_record_count: 3,
          exception_count: 0,
          account_counts: { '123456789012': 3 },
          ou_counts: {},
          identity_type_counts: { machine_identity: 2, coverage_target: 1 },
          severity_counts: { high: 2, low: 1 },
          outcome_type_counts: { risk_reduction: 1, coverage: 1, exposure: 1 },
          trend_counts: { improving: 2, needs_attention: 1 },
          highest_score: 92,
          average_confidence_pct: 90
        },
        metrics: [
          {
            metric_id: 'risk-reduction',
            category: 'risk_reduction',
            outcome_type: 'risk_reduction',
            title: 'Risk reduction',
            summary: 'Projected reduction from remediation and verification.',
            value: 72,
            unit: 'score',
            trend: 'improving',
            trend_delta: 12,
            score: 72,
            confidence: 0.91,
            account_id: '123456789012',
            region: 'us-east-1',
            identity_type: 'machine_identity',
            severity: 'high',
            evidence_links: ['/docs/aws-executive-outcome-view'],
            evidence_ref: 'aws-executive-outcome://risk-reduction',
            evidence_boundary: 'metadata_only_outcome_metrics_no_secret_values_no_customer_payloads',
            next_action: 'Approve low-breakage remediation plans.',
            updated_at: '2026-07-09T12:00:00Z'
          },
          {
            metric_id: 'scan-coverage',
            category: 'scan_coverage',
            outcome_type: 'coverage',
            title: 'Scan coverage',
            summary: 'Account and region coverage.',
            value: 83,
            unit: 'percent',
            trend: 'improving',
            trend_delta: 5,
            score: 83,
            confidence: 0.9,
            account_id: '123456789012',
            region: 'us-east-1',
            identity_type: 'coverage_target',
            severity: 'low',
            evidence_links: ['/docs/aws-account-region-coverage-planner'],
            evidence_ref: 'aws-executive-outcome://scan-coverage',
            evidence_boundary: 'metadata_only_outcome_metrics_no_secret_values_no_customer_payloads',
            next_action: 'Close degraded coverage.',
            updated_at: '2026-07-09T12:00:00Z'
          },
          {
            metric_id: 'remaining-exposure',
            category: 'remaining_exposure',
            outcome_type: 'exposure',
            title: 'Remaining exposure',
            summary: 'Open high-severity exposure.',
            value: 4,
            unit: 'open',
            trend: 'needs_attention',
            trend_delta: -4,
            score: 92,
            confidence: 0.88,
            account_id: '123456789012',
            region: 'us-east-1',
            identity_type: 'machine_identity',
            severity: 'high',
            evidence_links: ['/docs/aws-blast-radius-engine'],
            evidence_ref: 'aws-executive-outcome://remaining-exposure',
            evidence_boundary: 'metadata_only_outcome_metrics_no_secret_values_no_customer_payloads',
            next_action: 'Prioritize critical and high exposure.',
            updated_at: '2026-07-09T12:00:00Z'
          }
        ],
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        evidence_links: ['/docs/aws-executive-outcome-view'],
        coverage_gaps: [],
        diagnostics: [],
        generated_at: '2026-07-09T12:00:00Z',
        updated_at: '2026-07-09T12:00:00Z'
      } as any
    });

    const { ProductAWSOutcomesPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/outcomes?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/outcomes" element={<ProductAWSOutcomesPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Outcomes' })).toBeInTheDocument();
    const scope = await screen.findByRole('region', { name: 'Outcomes scope' });
    expect(within(scope).getByText('Read-only')).toBeInTheDocument();
    expect(within(scope).queryByText('Advisory')).not.toBeInTheDocument();
    expect(await screen.findByRole('region', { name: 'AWS executive outcome summary' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'AWS executive outcome metrics' })).toBeInTheDocument();
    expect(screen.getAllByText(/Risk reduction/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Remaining exposure/i).length).toBeGreaterThan(0);
    expect(getExecutiveOutcomes).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      expect.objectContaining({ connectorID: 'aws-connector-1' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Outcome' }), {
      target: { value: 'exposure' }
    });
    await waitFor(() =>
      expect(getExecutiveOutcomes).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', outcomeType: 'exposure' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('passes AWS findings filters to secret-permission equivalence queries', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const equivalenceFinding = {
      finding_id: 'aws-secret-permission-equivalence:findings-route',
      equivalence_type: 'agent_provider_key_equivalence',
      severity: 'high',
      status: 'review',
      score: 82,
      confidence: 0.9,
      account_id: '123456789012',
      region: 'us-east-1',
      identity_node_id: 'aws:identity:case-triage',
      agent_id: 'case-triage-id',
      agent_name: 'Case Triage',
      secret_node_id: 'aws:resource:secret:openai-api-key',
      secret_label: 'openai/api-key',
      provider: 'openai',
      equivalent_permissions: ['openai:api_request'],
      source_signals: ['ai_agent_identities'],
      rationale: 'Agent provider-key metadata is readable.',
      evidence_boundary: 'metadata_only_no_secret_values_no_payloads',
      impacted_nodes: ['aws:identity:case-triage', 'aws:resource:secret:openai-api-key'],
      impacted_path: [],
      evidence: [],
      next_action: 'Review the provider credential scope.'
    } as any;
    const actionableEquivalenceFinding = {
      ...equivalenceFinding,
      finding_id: 'aws-secret-permission-equivalence:findings-route-actionable',
      status: 'action_required'
    };
    const sameIdentityDifferentSecretFinding = {
      ...equivalenceFinding,
      finding_id: 'aws-secret-permission-equivalence:findings-route-second-secret',
      secret_node_id: 'aws:resource:secret:github-api-key',
      secret_label: 'github/api-key',
      provider: 'github'
    };
    const sameNameDifferentIdentityFinding = {
      ...equivalenceFinding,
      finding_id: 'aws-secret-permission-equivalence:findings-route-different-identity',
      region: 'eu-west-1',
      identity_node_id: 'aws:identity:case-triage-eu',
      agent_id: 'case-triage-id-eu',
      secret_node_id: 'aws:resource:secret:anthropic-api-key',
      secret_label: 'anthropic/api-key'
    };
    const getSecretPermissionEquivalence = vi.spyOn(api.apiClient, 'getAWSProjectSecretPermissionEquivalence').mockResolvedValue({
      findings: {
        status: 'ready',
        findings: [
          equivalenceFinding,
          actionableEquivalenceFinding,
          sameIdentityDifferentSecretFinding,
          sameNameDifferentIdentityFinding
        ],
        summary: {
          external_provider_key_count: 0,
          aws_managed_secret_count: 0,
          runtime_observed_count: 0,
          kms_backed_count: 0
        },
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        coverage_gaps: [
          {
            capability: 'secret_value_collection',
            status: 'unsupported',
            reason: 'Secret values are intentionally excluded.'
          }
        ],
        diagnostics: []
      } as any
    });

    const { ProductAWSFindingsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/findings?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/findings" element={<ProductAWSFindingsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Findings' })).toBeInTheDocument();
    const findingsTable = await screen.findByRole('table', { name: 'AWS findings' });
    expect(within(findingsTable).getAllByText(/Completeness: Complete/i)).toHaveLength(2);
    expect(within(findingsTable).getByRole('link', { name: /openai\/api-key/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/agents/detail?environment=production&agent=case-triage-id&tab=secrets'
    );
    const liveFindingRow = within(findingsTable).getByRole('link', { name: /openai\/api-key/i }).closest('tr');
    expect(liveFindingRow).not.toBeNull();
    expect(liveFindingRow).toHaveTextContent('openai/api-key');
    expect(liveFindingRow).toHaveTextContent('Secret Â· Case Triage');
    expect(liveFindingRow).toHaveTextContent('Secret');
    expect(liveFindingRow).toHaveTextContent('Account 123456789012 Â· Region us-east-1');
    expect(liveFindingRow).toHaveTextContent('2 affected resources');
    expect(liveFindingRow).toHaveTextContent('3 related risks');
    expect(within(findingsTable).getByText('Account 123456789012 Â· Region eu-west-1')).toBeInTheDocument();
    expect(
      within(screen.getByRole('region', { name: 'Finding priority summary' })).getByText(
        '4 findings Â· 1 critical/high open Â· 3 affected resources'
      )
    ).toBeInTheDocument();
    const liveDetailsButton = within(liveFindingRow as HTMLElement).getByRole('button', { name: 'View details' });
    liveDetailsButton.focus();
    expect(liveDetailsButton).toHaveFocus();
    fireEvent.click(liveDetailsButton);
    const liveFindingDrawer = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(within(liveFindingDrawer).getByText('Case Triage', { exact: true })).toBeInTheDocument();
    fireEvent.click(within(liveFindingDrawer).getByRole('button', { name: 'Close detail drawer' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Finding details' })).not.toBeInTheDocument());
    expect(within(findingsTable).getAllByText('High')).toHaveLength(2);
    expect(within(findingsTable).getByText('Open')).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'AWS secret-to-permission equivalence findings' })).not.toBeInTheDocument();
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    const degradedEquivalenceResult = {
      status: 'degraded',
      findings: [{ ...equivalenceFinding, region: '' }],
      summary: {
        external_provider_key_count: 0,
        aws_managed_secret_count: 0,
        runtime_observed_count: 0,
        kms_backed_count: 0
      },
      caveats: [],
      failure_reasons: [],
      remediation_hints: [],
      coverage_gaps: [
        {
          capability: 'secrets_manager_runtime',
          status: 'partial',
          reason: 'Runtime delivery evidence is unavailable.'
        }
      ],
      diagnostics: []
    } as any;
    getSecretPermissionEquivalence.mockResolvedValue({ findings: degradedEquivalenceResult });

    fireEvent.change(screen.getByRole('textbox', { name: 'Findings search' }), { target: { value: 'openai' } });
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', search: 'openai' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await waitFor(() =>
      expect(within(screen.getByRole('table', { name: 'AWS findings' })).getByText(/Completeness: Partial/i)).toBeInTheDocument()
    );
    const degradedSummary = screen.getByRole('region', { name: 'Finding priority summary' });
    expect(within(degradedSummary).getByText('Completeness').closest('div')).toHaveTextContent('Partial');
    expect(within(degradedSummary).getByText('Source health').closest('div')).toHaveTextContent('1 unavailable or degraded');
    expect(within(degradedSummary).getByText('Account 123456789012 Â· Region unavailable')).toBeInTheDocument();
    expect(within(degradedSummary).getByText('Secrets Manager Runtime Â· Partial')).toBeInTheDocument();

    getSecretPermissionEquivalence.mockResolvedValue({
      findings: { ...degradedEquivalenceResult, findings: [equivalenceFinding] }
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Findings search' }), { target: { value: '' } });
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', search: undefined }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Account' }), { target: { value: 'unknown' } });
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(getSecretPermissionEquivalence.mock.lastCall?.[2]?.accountID).toBeUndefined();

    fireEvent.change(screen.getByRole('combobox', { name: 'Region' }), { target: { value: 'unknown' } });
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(getSecretPermissionEquivalence.mock.lastCall?.[2]?.region).toBeUndefined();

    fireEvent.change(screen.getByRole('combobox', { name: 'Region' }), { target: { value: 'other' } });
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(getSecretPermissionEquivalence.mock.lastCall?.[2]?.region).toBeUndefined();

    fireEvent.change(screen.getByRole('combobox', { name: 'Severity' }), { target: { value: 'high' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Account' }), { target: { value: 'connected' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Region' }), { target: { value: 'current' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Remediation' }), { target: { value: 'open' } });

    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({
          connectorID: 'aws-connector-1',
          accountID: '123456789012',
          region: 'us-east-1',
          severity: 'high',
          status: 'action_required'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Remediation' }), { target: { value: 'blocked' } });
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', status: 'blocked' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Evidence' }), { target: { value: 'unavailable' } });
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', evidence: 'unavailable' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Remediation' }), { target: { value: 'all' } });
    await waitFor(() =>
      expect(screen.getByRole('link', { name: /Agent provider key equivalence/i })).toBeInTheDocument()
    );

    equivalenceFinding.evidence = [
      {
        source: 'secrets_kms_runtime_access',
        evidence_ref: 'runtime-evidence://secret-read',
        label: 'Runtime secret read',
        confidence: 0.9,
        relationship: 'read'
      },
      {
        source: 'kms_key_policy',
        evidence_ref: 'inventory-evidence://kms-policy',
        label: 'KMS key policy',
        confidence: 0.8,
        relationship: 'decrypt'
      }
    ];
    fireEvent.change(screen.getByRole('combobox', { name: 'Evidence' }), { target: { value: 'inventory-backed' } });
    await waitFor(() =>
      expect(screen.getByRole('link', { name: /Agent provider key equivalence/i })).toBeInTheDocument()
    );
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', evidence: 'inventory-backed' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(screen.getByRole('textbox', { name: 'Findings search' }), { target: { value: 'openai:api_request' } });
    await waitFor(() =>
      expect(screen.getByRole('link', { name: /Agent provider key equivalence/i })).toBeInTheDocument()
    );
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1', search: 'openai:api_request' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('shows incomplete live AWS evidence instead of an empty findings result', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    vi.spyOn(api.apiClient, 'getAWSProjectSecretPermissionEquivalence').mockResolvedValue({
      findings: {
        status: 'degraded',
        findings: [],
        failure_reasons: ['live secret-permission inventory is unavailable'],
        summary: {},
        caveats: [],
        remediation_hints: [],
        coverage_gaps: [],
        diagnostics: [
          {
            collector: 'secret_permission_inventory',
            source_id: 'production/live',
            code: 'live_inventory_unavailable',
            message: 'Live inventory is unavailable.',
            retryable: true
          }
        ]
      } as any
    });

    const { ProductAWSFindingsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/findings?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/findings" element={<ProductAWSFindingsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Live AWS findings are not available yet')).toBeInTheDocument();
    expect(screen.getByText('live secret-permission inventory is unavailable')).toBeInTheDocument();
    expect(screen.queryByText('No AWS findings')).not.toBeInTheDocument();
    const prioritySummary = screen.getByRole('region', { name: 'Finding priority summary' });
    expect(within(prioritySummary).getByText('0 findings Â· 0 critical/high open Â· 0 affected resources')).toBeInTheDocument();
    expect(within(prioritySummary).getByText('Completeness').closest('div')).toHaveTextContent('Partial');
    expect(within(prioritySummary).getByText('Source health').closest('div')).toHaveTextContent('1 unavailable or degraded');
    expect(
      within(prioritySummary).getByText(/Secret Permission Inventory Â· production\/live Â· Live Inventory Unavailable Â· retryable/)
    ).toBeInTheDocument();
    expect(within(prioritySummary).getByRole('link', { name: 'View coverage details' })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/coverage?environment=production'
    );
  });

  it('deep-links persisted AWS findings and records guarded workflow changes', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'getMe').mockResolvedValue({ me: loggedInWithWorkspace });
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [{
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'production',
        name: 'Production',
        slug: 'production',
        description: 'Production AWS boundary.',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    vi.spyOn(api.apiClient, 'getScan').mockResolvedValue({
      scan: {
        id: 'scan-aws-workflow',
        project_id: 'production',
        connector_id: 'aws-connector-1',
        provider: 'aws',
        status: 'succeeded',
        started_at: '2026-08-20T20:00:00Z',
        finished_at: '2026-08-20T20:03:00Z',
        asset_count: 1,
        finding_count: 1
      }
    });
    let persistedFinding: Finding = {
      id: 'finding-aws-workflow',
      scan_id: 'scan-aws-workflow',
      type: 'aws_iam_overprivileged_role',
      severity: 'high',
      title: 'Workflow IAM role',
      human_summary: 'The role grants permissions beyond the observed workload needs.',
      path: ['arn:aws:iam::123456789012:role/workflow-role', 'iam:GetRole -> iam:ListRoles'],
      adapter_source: 'iam-policy collector',
      confidence_score: 0.91,
      actionability: 'action_required',
      evidence_completeness: 'complete',
      provenance: 'aws_iam_inventory',
      evidence: { account_id: '123456789012', region: 'us-east-1' },
      remediation: 'Reduce the role policy and verify the effective permissions.',
      created_at: '2026-08-20T20:03:00Z',
      lifecycle_status: 'open',
      triage: { status: 'open' }
    };
    vi.spyOn(api.apiClient, 'listFindings').mockImplementation(async () => ({ items: [persistedFinding] }));
    vi.spyOn(api.apiClient, 'listScanEvents').mockResolvedValue({ items: [] });
    const history: FindingTriageEvent[] = [];
    const listFindingHistory = vi.spyOn(api.apiClient, 'listFindingHistory').mockImplementation(async () => ({ items: [...history] }));
    const triageFinding = vi.spyOn(api.apiClient, 'triageFinding').mockImplementation(async (_findingID, payload) => {
      persistedFinding = {
        ...persistedFinding,
        triage: {
          status: payload.status ?? persistedFinding.triage?.status ?? 'open',
          assignee: payload.assignee ?? persistedFinding.triage?.assignee,
          suppression_expires_at: payload.suppression_expires_at,
          resolved_at: payload.status === 'resolved' ? '2026-08-24T13:00:00Z' : undefined,
          updated_at: '2026-08-24T13:00:00Z',
          updated_by: 'subject:security-operator'
        }
      };
      history.unshift({
        id: `event-${history.length + 1}`,
        finding_id: persistedFinding.id,
        action: payload.assignee !== undefined ? 'assigned' : payload.status ?? 'commented',
        from_status: 'open',
        to_status: payload.status ?? persistedFinding.triage?.status ?? 'open',
        assignee: payload.assignee,
        suppression_expires_at: payload.suppression_expires_at,
        comment: payload.comment,
        actor: 'subject:security-operator',
        created_at: '2026-08-24T13:00:00Z'
      });
      return { finding: persistedFinding };
    });

    const { ProductAWSFindingsPage } = await import('./productShell');
    function LocationProbe() {
      const currentLocation = useLocation();
      return <output data-testid="aws-finding-location">{currentLocation.search}</output>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/findings?environment=production&scan_id=scan-aws-workflow&finding_id=finding-aws-workflow']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/findings" element={<><ProductAWSFindingsPage /><LocationProbe /></>} />
        </Routes>
      </MemoryRouter>
    );

    const drawer = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(within(drawer).getByText('What happened')).toBeInTheDocument();
    expect(within(drawer).getByText('Blast radius & relationship path')).toBeInTheDocument();
    expect(within(drawer).getByText('Coverage limitations')).toBeInTheDocument();
    expect(within(drawer).getByText('Finding history')).toBeInTheDocument();
    expect(within(drawer).getByLabelText('Remediation handoff text')).toHaveDisplayValue(/Finding ID: finding-aws-workflow/);
    expect(screen.getByTestId('aws-finding-location')).toHaveTextContent('scan_id=scan-aws-workflow');
    expect(screen.getByTestId('aws-finding-location')).toHaveTextContent('finding_id=finding-aws-workflow');

    fireEvent.change(within(drawer).getByLabelText('Finding owner'), { target: { value: 'Platform Security' } });
    fireEvent.click(within(drawer).getByRole('button', { name: 'Save owner' }));
    await waitFor(() => expect(triageFinding).toHaveBeenLastCalledWith(
      'finding-aws-workflow',
      { assignee: 'Platform Security' },
      'scan-aws-workflow',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    ));

    fireEvent.click(within(drawer).getByRole('button', { name: 'Acknowledge' }));
    await waitFor(() => expect(triageFinding).toHaveBeenLastCalledWith(
      'finding-aws-workflow',
      { status: 'ack' },
      'scan-aws-workflow',
      expect.anything()
    ));

    fireEvent.change(within(drawer).getByLabelText('Suppression reason'), { target: { value: 'Approved exception while policy is reviewed.' } });
    fireEvent.click(within(drawer).getByRole('button', { name: 'Suppress finding' }));
    await waitFor(() => expect(triageFinding).toHaveBeenLastCalledWith(
      'finding-aws-workflow',
      { status: 'suppressed', comment: 'Approved exception while policy is reviewed.' },
      'scan-aws-workflow',
      expect.anything()
    ));

    const triageCallCountBeforeEmptyResolution = triageFinding.mock.calls.length;
    fireEvent.click(within(drawer).getByRole('button', { name: 'Mark resolved' }));
    expect(triageFinding.mock.calls).toHaveLength(triageCallCountBeforeEmptyResolution);
    expect(within(drawer).getByRole('alert')).toHaveTextContent('Record the verification basis before resolving this finding.');

    fireEvent.change(within(drawer).getByLabelText('Resolution verification basis'), { target: { value: 'A follow-up scan confirms only the required actions remain.' } });
    fireEvent.click(within(drawer).getByRole('button', { name: 'Mark resolved' }));
    await waitFor(() => expect(triageFinding).toHaveBeenLastCalledWith(
      'finding-aws-workflow',
      { status: 'resolved', comment: 'A follow-up scan confirms only the required actions remain.' },
      'scan-aws-workflow',
      expect.anything()
    ));
    await waitFor(() => expect(listFindingHistory.mock.calls.length).toBeGreaterThanOrEqual(5));
    expect(within(drawer).getByText('Finding resolved with a recorded verification basis.')).toBeInTheDocument();

    fireEvent.change(screen.getByRole('combobox', { name: 'Severity' }), { target: { value: 'critical' } });
    expect(await screen.findByText('No findings match these filters')).toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Finding details' })).toBeInTheDocument();

    fireEvent.click(within(drawer).getByRole('button', { name: 'Close detail drawer' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Finding details' })).not.toBeInTheDocument());
    expect(screen.getByTestId('aws-finding-location')).toHaveTextContent('scan_id=scan-aws-workflow');
    expect(screen.getByTestId('aws-finding-location')).not.toHaveTextContent('finding_id=');
  });

  it('handles a missing AWS finding deep link without dropping scan scope', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [{
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'production',
        name: 'Production',
        slug: 'production',
        description: 'Production AWS boundary.',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    vi.spyOn(api.apiClient, 'getScan').mockResolvedValue({
      scan: {
        id: 'scan-aws-empty',
        project_id: 'production',
        connector_id: 'aws-connector-1',
        provider: 'aws',
        status: 'succeeded',
        started_at: '2026-08-20T20:00:00Z',
        finished_at: '2026-08-20T20:03:00Z',
        asset_count: 1,
        finding_count: 0
      }
    });
    vi.spyOn(api.apiClient, 'listFindings').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listScanEvents').mockResolvedValue({ items: [] });

    const { ProductAWSFindingsPage } = await import('./productShell');
    function LocationProbe() {
      const currentLocation = useLocation();
      return <output data-testid="missing-aws-finding-location">{currentLocation.search}</output>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/findings?environment=production&scan_id=scan-aws-empty&finding_id=missing-finding']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/findings" element={<><ProductAWSFindingsPage /><LocationProbe /></>} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Finding reference unavailable')).toBeInTheDocument();
    expect(screen.getByText(/missing from the selected scan or live scope/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear finding reference' }));
    await waitFor(() => expect(screen.getByTestId('missing-aws-finding-location')).not.toHaveTextContent('finding_id='));
    expect(screen.getByTestId('missing-aws-finding-location')).toHaveTextContent('scan_id=scan-aws-empty');
  });

  it('shows findings persisted by the completed AWS discovery scan', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production AWS boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    const getScan = vi.spyOn(api.apiClient, 'getScan').mockResolvedValue({
      scan: {
        id: 'scan-aws-complete',
        project_id: 'production',
        connector_id: 'aws-connector-1',
        provider: 'AWS',
        status: 'succeeded',
        started_at: '2026-08-20T20:00:00Z',
        finished_at: '2026-08-20T20:03:00Z',
        asset_count: 12,
        finding_count: 5
      }
    });
    const listFindings = vi.spyOn(api.apiClient, 'listFindings').mockImplementation(async (filters = {}) =>
      filters.cursor
        ? {
            items: [
              {
                id: 'finding-aws-2',
                scan_id: 'scan-aws-complete',
                type: 'aws_s3_public_bucket',
                severity: 'medium',
                title: 'Public S3 bucket',
                human_summary: 'The bucket is reachable through a public policy.',
                path: ['production-assets'],
                owner: 'AWS scanner',
                evidence: { source: 's3-policy' },
                remediation: 'Restrict the bucket policy to approved principals.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'fixed'
              },
              {
                id: 'finding-aws-lambda-colon-resource',
                scan_id: 'scan-aws-complete',
                type: 'aws_lambda_function',
                severity: 'low',
                title: 'Lambda resource label',
                human_summary: 'A Lambda finding with a colon-form ARN resource.',
                path: ['arn:aws:lambda:us-east-1:123456789012:function:shared-function-colon'],
                owner: 'AWS scanner',
                evidence: { source: 'lambda-policy' },
                remediation: 'Review the function policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-lambda-qualified-resource',
                scan_id: 'scan-aws-complete',
                type: 'aws_lambda_function',
                severity: 'low',
                title: 'Qualified Lambda resource label',
                human_summary: 'A Lambda finding with a qualified ARN resource.',
                path: ['arn:aws:lambda:us-east-1:123456789012:function:payments:42'],
                owner: 'AWS scanner',
                evidence: { source: 'lambda-policy' },
                remediation: 'Review the function policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-secret-colon-resource',
                scan_id: 'scan-aws-complete',
                type: 'aws_secretsmanager_secret',
                severity: 'low',
                title: 'Secret resource label',
                human_summary: 'A Secrets Manager finding with a colon-form ARN resource.',
                path: ['arn:aws:secretsmanager:us-east-1:123456789012:secret:database-password-abc123'],
                owner: 'AWS scanner',
                evidence: { source: 'secret-policy' },
                remediation: 'Review the secret policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-secret-prod-path',
                scan_id: 'scan-aws-complete',
                type: 'aws_secretsmanager_secret',
                severity: 'low',
                title: 'Production database secret',
                human_summary: 'A path-qualified production secret.',
                path: ['arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db'],
                owner: 'AWS scanner',
                evidence: { source: 'secret-policy' },
                remediation: 'Review the production secret policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-secret-staging-path',
                scan_id: 'scan-aws-complete',
                type: 'aws_secretsmanager_secret',
                severity: 'low',
                title: 'Staging database secret',
                human_summary: 'A path-qualified staging secret.',
                path: ['arn:aws:secretsmanager:us-east-1:123456789012:secret:staging/db'],
                owner: 'AWS scanner',
                evidence: { source: 'secret-policy' },
                remediation: 'Review the staging secret policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-iam-path-role',
                scan_id: 'scan-aws-complete',
                type: 'aws_iam_partition_role',
                severity: 'low',
                title: 'IAM path role',
                human_summary: 'An IAM role with a service path.',
                path: ['arn:aws:iam::123456789012:role/service-role/payments'],
                owner: 'AWS scanner',
                evidence: { source: 'iam-policy' },
                remediation: 'Review the role policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-gov',
                scan_id: 'scan-aws-complete',
                type: 'aws_iam_partition_role',
                severity: 'low',
                title: 'Gov IAM role',
                human_summary: 'A role in the AWS GovCloud partition.',
                path: ['arn:aws-us-gov:iam::123456789012:role/gov-role'],
                owner: 'AWS scanner',
                evidence: { source: 'iam-policy' },
                remediation: 'Review the role policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-cn',
                scan_id: 'scan-aws-complete',
                type: 'aws_iam_partition_role',
                severity: 'low',
                title: 'China IAM role',
                human_summary: 'A role in the AWS China partition.',
                path: ['arn:aws-cn:iam::123456789012:role/cn-role'],
                owner: 'AWS scanner',
                evidence: { source: 'iam-policy' },
                remediation: 'Review the role policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-iso',
                scan_id: 'scan-aws-complete',
                type: 'aws_iam_partition_role',
                severity: 'low',
                title: 'ISO IAM role',
                human_summary: 'A role in the AWS ISO partition.',
                path: ['arn:aws-iso:iam::123456789012:role/iso-role'],
                owner: 'AWS scanner',
                evidence: { source: 'iam-policy' },
                remediation: 'Review the role policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-iso-b',
                scan_id: 'scan-aws-complete',
                type: 'aws_iam_partition_role',
                severity: 'low',
                title: 'ISO-B IAM role',
                human_summary: 'A role in the AWS ISO-B partition.',
                path: ['arn:aws-iso-b:iam::123456789012:role/iso-b-role'],
                owner: 'AWS scanner',
                evidence: { source: 'iam-policy' },
                remediation: 'Review the role policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-lifecycle-suppressed',
                scan_id: 'scan-aws-complete',
                type: 'aws_iam_lifecycle_role',
                severity: 'medium',
                title: 'Suppressed lifecycle role',
                human_summary: 'The role has a suppressed finding.',
                path: ['arn:aws:iam::123456789012:role/lifecycle-role'],
                owner: 'AWS scanner',
                evidence: { source: 'iam-policy' },
                remediation: 'Review the suppression decision.',
                created_at: '2026-08-20T20:03:00Z',
                triage: { status: 'suppressed' }
              },
              {
                id: 'finding-aws-lifecycle-resolved',
                scan_id: 'scan-aws-complete',
                type: 'aws_iam_lifecycle_role',
                severity: 'low',
                title: 'Resolved lifecycle role',
                human_summary: 'The role has a resolved finding.',
                path: ['arn:aws:iam::123456789012:role/lifecycle-role'],
                owner: 'AWS scanner',
                evidence: { source: 'iam-policy' },
                remediation: 'No remediation is pending.',
                created_at: '2026-08-20T20:03:00Z',
                triage: { status: 'resolved' }
              },
              {
                id: 'finding-aws-east-function',
                scan_id: 'scan-aws-complete',
                type: 'aws_lambda_function',
                severity: 'low',
                title: 'East Lambda function',
                human_summary: 'A regional Lambda finding.',
                path: ['arn:aws:lambda:us-east-1:123456789012:function/shared-function'],
                owner: 'AWS scanner',
                evidence: { source: 'lambda-policy' },
                remediation: 'Review the function policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-west-function',
                scan_id: 'scan-aws-complete',
                type: 'aws_lambda_function',
                severity: 'low',
                title: 'West Lambda function',
                human_summary: 'A regional Lambda finding.',
                path: ['arn:aws:lambda:eu-west-1:123456789012:function/shared-function'],
                owner: 'AWS scanner',
                evidence: { source: 'lambda-policy' },
                remediation: 'Review the function policy.',
                created_at: '2026-08-20T20:03:00Z',
                lifecycle_status: 'open'
              },
              {
                id: 'finding-aws-3',
                scan_id: 'scan-aws-complete',
                type: 'aws_iam_acknowledged_role',
                severity: 'low',
                title: 'Acknowledged IAM role',
                human_summary: 'The finding has been acknowledged for review.',
                path: ['review-role'],
                owner: 'AWS scanner',
                evidence: { source: 'iam-policy' },
                remediation: 'Review the acknowledged finding.',
                created_Û~½ãVòµë(š+myÝ±¥•¹Ð°€ÍÑ…ÉÑ]M½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½ÉœµÉ½±”œ°(€€€€€€€Í½Á•}ÑåÁ”è€½É…¹¥é…Ñ¥½¸œ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€ÍÑ…­Í•Ñ}Í•ÉÙ¥•}µ…¹…•œ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€±…Õ¹¡}É•…‘äœ°(€€€€€€€É½±•}…É¸è€…É¸é…ÝÌé¥…´èèÄÈÌÐÔØÜàäÀÄÈéÉ½±”½ÕÍÑ½µ•ÉI•…‘=¹±å%‘•¹ÑÉ…¥°œ°(€€€€€€€ÍÑ…­}Í•Ñ}¹…µ”è€ÕÍÑ½µ•É9…µ•‘MÑ…­M•Ðœ(€€€€€ô°(€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½ÉœµÉ½±”œ°(€€€€€•áÑ•É¹…±}¥è€É½±”µ¡å‘É…Ñ”µ•áÑ•É¹…°œ°(€€€€€±…Õ¹¡}ÕÉ°è€¡ÑÑÁÌè¼½½¹Í½±”¹…ÝÌ¹…µ…é½¸¹½´½±½Õ‘™½Éµ…Ñ¥½¸½¡½µ”Œ½ÍÑ…­Í•ÑÌœ°(€€€€€Ñ•µÁ±…Ñ•}ÕÉ°è€¡ÑÑÁÌè¼½•á…µÁ±”¹½´½Ñ•µÁ±…Ñ”¹å…µ°œ°(€€€€€É½±•}¹…µ”è€ÕÍÑ½µ•ÉI•…‘=¹±å%‘•¹ÑÉ…¥°œ°(€€€€€ÍÑ…­}¹…µ”è€¥‘•¹ÑÉ…¥°µÉ•…‘½¹±äµ½¹¹•Ñ½Èœ°(€€€€€ÍÑ…­}Í•Ñ}¹…µ”è€ÕÍÑ½µ•É9…µ•‘MÑ…­M•Ðœ°(€€€€€Á½±¥å}¡…Í è€Í¡„ÈÔØé•á…µÁ±”œ°(€€€€€Ñ•µÁ±…Ñ•}¡•­ÍÕ´è€Í¡„ÈÔØé•á…µÁ±”œ°(€€€€€Í½Á•}ÑåÁ”è€½É…¹¥é…Ñ¥½¸œ°(€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€ÍÑ…­Í•Ñ}Í•ÉÙ¥•}µ…¹…•œ°(€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€±…Õ¹¡}É•…‘äœ°(€€€€€Ñ…É•Ñ}É•¥½¹ÌèlÕÌµ•…ÍÐ´Ät°(€€€€€Ñ…É•Ñ}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€Ñ…É•Ñ}½Õ}¥‘ÌèlÈµ…‰t°(€€€€€•á±Õ‘•‘}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€…ÕÑ½}½¹‰½…É‘}¹•Ý}…½Õ¹ÑÌèÑÉÕ”°(€€€€€Í•ÑÕÁ}ÍÕµµ…Éäè€=É…¹¥é…Ñ¥½¸Í•ÑÕÀ¸œ°(€€€€€¹•áÑ}…Ñ¥½¹Ìèl½Á•¹}ÍÑ…­Í•Ðœ°€É•™É•Í¡}ÍÑ…ÑÕÌt°(€€€€€ÍÑ…­Í•Ñ}½¹‰½…É‘¥¹œèÉ•…‘å]MMÑ…­M•Ñ=¹‰½…É‘¥¹œ°(€€€€€Á•Éµ¥ÍÍ¥½¹}ÁÉ•Ù¥•Üèmt°(€€€€€Á•Éµ¥ÍÍ¥½¹}Ñ¥•ÉÌèmt(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥Ð½Á•¹]M½¹¹•Ñ¥½¹5…¹…•µ•¹Ð ¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€½MÑ…­M•Ð½¹‰½…É‘¥¹œÁÉ½É•ÍÌ½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½1…Õ¹ MÑ…­M•ÐÍ•ÑÕÀ½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÑ…ÉÑ]M½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€€¼¼Q¡”É½±”¹…µ”…¹MÑ…­M•Ð¹…µ”…É”¡å‘É…Ñ•¥¸Ñ¡”™½É´™½È‘¥ÍÁ±…ä°(€€€€¼¼‰ÕÐÑ¡”É•ÍÕµ”Á…å±½…½µ¥ÑÌÑ¡•´Í¼Ñ¡”‰…­•¹­••ÁÌÑ¡”ÍÑ½É•(€€€€¼¼Ù…±Õ•ÌÉ…Ñ¡•ÈÑ¡…¸½Ù•ÉÝÉ¥Ñ¥¹œÑ¡•´Ý¥Ñ Ñ¡”Ý¥é…É‘•™…Õ±ÑÌ¸(€€€•áÁ•Ð¡ÍÑ…ÉÑ]M½¹¹•Ñ½È¹µ½¬¹…±±ÍlÁtü¹lÁt¤¹Ñ½5…Ñ¡=‰©•Ð¡ì(€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½ÉœµÉ½±”œ°(€€€€€É½±•}¹…µ”èÕ¹‘•™¥¹•°(€€€€€ÍÑ…­}Í•Ñ}¹…µ”èÕ¹‘•™¥¹•(€€€ô¤ì(€ô¤ì((€¥Ð ÁÉ•Í•ÉÙ•ÌÑ¡”±…ÍÐ½½MÑ…­M•Ð½¹‰½…É‘¥¹œÝ¡•¸„É•™É•Í ™…¥±Ìœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½ÉœµÉ•™É•Í µ•ÉÈœ°(€€€€€€€Í½Á•}ÑåÁ”è€½É…¹¥é…Ñ¥½¸œ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€ÍÑ…­Í•Ñ}Í•ÉÙ¥•}µ…¹…•œ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€½¹¹•Ñ•œ°(€€€€€€€Ñ…É•Ñ}É•¥½¹ÌèlÕÌµ•…ÍÐ´Ät°(€€€€€€€Ñ…É•Ñ}½Õ}¥‘ÌèlÈµ…‰t(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€Á½±±]M½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½ÉœµÉ•™É•Í µ•ÉÈœ°(€€€€€€€Í½Á•}ÑåÁ”è€½É…¹¥é…Ñ¥½¸œ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€ÍÑ…­Í•Ñ}Í•ÉÙ¥•}µ…¹…•œ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€½¹¹•Ñ•œ°(€€€€€€€Ñ…É•Ñ}É•¥½¹ÌèlÕÌµ•…ÍÐ´Ät°(€€€€€€€Ñ…É•Ñ}½Õ}¥‘ÌèlÈµ…‰t(€€€€€ô(€€€ô¤ì(€€€½¹ÍÐÁ•ÉÍ¥ÍÑ•è]MMÑ…­M•Ñ=¹‰½…É‘¥¹I•ÍÕ±Ð€ôì(€€€€€€¸¸¹É•…‘å]MMÑ…­M•Ñ=¹‰½…É‘¥¹œ°(€€€€€É•½Ù•Éå}…Ñ¥½¹Ìèl(€€€€€€€ì(€€€€€€€€€¥è€ÁÉ•Í•ÉÙ”µÉ•½Ù•Éäœ°(€€€€€€€€€Ñ¥Ñ±”è€AÉ•Í•ÉÙ•É•½Ù•Éä…Ñ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€M¡½Õ±É•µ…¥¸Ù¥Í¥‰±”…™Ñ•È„ÑÉ…¹Í¥•¹ÐÉ•™É•Í ™…¥±ÕÉ”¸œ°(€€€€€€€€€Ñ…É•ÑÌèmt(€€€€€€€ô(€€€€€t(€€€ôì(€€€±•Ð½¹‰½…É‘¥¹…±±½Õ¹Ð€ô€Àì(€€€½¹ÍÐ•ÑMÑ…­M•Ñ=¹‰½…É‘¥¹œ€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•ÑMÑ…­M•Ñ=¹‰½…É‘¥¹œœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôøì(€€€€€€€½¹‰½…É‘¥¹…±±½Õ¹Ð€¬ô€Äì(€€€€€€€¥˜€¡½¹‰½…É‘¥¹…±±½Õ¹Ð€ôôô€Ä¤ì(€€€€€€€€€É•ÑÕÉ¸AÉ½µ¥Í”¹É•Í½±Ù”¡ì½¹‰½…É‘¥¹œèÁ•ÉÍ¥ÍÑ•ô¤ì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸AÉ½µ¥Í”¹É•©•Ð¡¹•ÜÉÉ½È Ñ•µÁ½É…Éä¹•ÑÝ½É¬•ÉÉ½Èœ¤¤ì(€€€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥Ð½Á•¹]M½¹¹•Ñ¥½¹5…¹…•µ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½AÉ•Í•ÉÙ•É•½Ù•Éä…Ñ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€½¹ÍÐÁÉ¥½É…±±Ì€ô•ÑMÑ…­M•Ñ=¹‰½…É‘¥¹œ¹µ½¬¹…±±Ì¹±•¹Ñ ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½I•™É•Í MÑ…­M•ÐÍÑ…ÑÕÌ½¤ô¤¤ì((€€€€¼¼Q¡”É•™É•Í •ÉÉ½ÈÍÕÉ™…•Ì°‰ÕÐÑ¡”ÁÉ•Ù¥½ÕÌ½¹‰½…É‘¥¹œ¥ÌÉ•Ñ…¥¹•Í¼(€€€€¼¼Ñ¡”Á…¹•°­••ÁÌÉ•¹‘•É¥¹œÝ¥Ñ „É•ÑÉä…Ñ¥½¸¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½Ñ•µÁ½É…Éä¹•ÑÝ½É¬•ÉÉ½È½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½AÉ•Í•ÉÙ•É•½Ù•Éä…Ñ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½I•ÑÉäMÑ…­M•ÐÍÑ…ÑÕÌ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤(€€€€¤ì(€€€•áÁ•Ð¡•ÑMÑ…­M•Ñ=¹‰½…É‘¥¹œ¹µ½¬¹…±±Ì¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸¡ÁÉ¥½É…±±Ì¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÉ•ÕÍ”…¸•á¥ÍÑ¥¹œMÑ…­M•Ð½¹¹•Ñ½ÈÝ¡•¸Ñ¡”½Á•É…Ñ½ÈÍÝ¥Ñ¡•ÌÑ¼„‘¥™™•É•¹ÐÍ½Á”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½Éœµ•á¥ÍÑ¥¹œœ°(€€€€€€€Í½Á•}ÑåÁ”è€½É…¹¥é…Ñ¥½¸œ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€ÍÑ…­Í•Ñ}Í•ÉÙ¥•}µ…¹…•œ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€½¹¹•Ñ•œ°(€€€€€€€Ñ…É•Ñ}É•¥½¹ÌèlÕÌµ•…ÍÐ´Ät°(€€€€€€€Ñ…É•Ñ}½Õ}¥‘ÌèlÈµ…‰t(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•ÑMÑ…­M•Ñ=¹‰½…É‘¥¹œœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹‰½…É‘¥¹œèÉ•…‘å]MMÑ…­M•Ñ=¹‰½…É‘¥¹œ(€€€ô¤ì(€€€½¹ÍÐÍÑ…ÉÑ]M½¹¹•Ñ½È€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ]M½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½Ôµ¹•Üœ°(€€€€€€€Í½Á•}ÑåÁ”è€Í•±•Ñ•‘}½ÕÌœ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€ÍÑ…­Í•Ñ}Í•ÉÙ¥•}µ…¹…•œ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€±…Õ¹¡}É•…‘äœ(€€€€€ô°(€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½Ôµ¹•Üœ°(€€€€€•áÑ•É¹…±}¥è€Í•±•Ñ•µ½Ôµ•áÑ•É¹…°œ°(€€€€€±…Õ¹¡}ÕÉ°è€¡ÑÑÁÌè¼½½¹Í½±”¹…ÝÌ¹…µ…é½¸¹½´½±½Õ‘™½Éµ…Ñ¥½¸½¡½µ”Œ½ÍÑ…­Í•ÑÌœ°(€€€€€Ñ•µÁ±…Ñ•}ÕÉ°è€¡ÑÑÁÌè¼½•á…µÁ±”¹½´½Ñ•µÁ±…Ñ”¹å…µ°œ°(€€€€€É½±•}¹…µ”è€%‘•¹ÑÉ…¥±I•…‘=¹±äœ°(€€€€€ÍÑ…­}¹…µ”è€¥‘•¹ÑÉ…¥°µÉ•…‘½¹±äµ½¹¹•Ñ½Èœ°(€€€€€ÍÑ…­}Í•Ñ}¹…µ”è€%‘•¹ÑÉ…¥±I•…‘=¹±å½Ù•É…”œ°(€€€€€Á½±¥å}¡…Í è€Í¡„ÈÔØé•á…µÁ±”œ°(€€€€€Ñ•µÁ±…Ñ•}¡•­ÍÕ´è€Í¡„ÈÔØé•á…µÁ±”œ°(€€€€€Í½Á•}ÑåÁ”è€Í•±•Ñ•‘}½ÕÌœ°(€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€ÍÑ…­Í•Ñ}Í•ÉÙ¥•}µ…¹…•œ°(€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€±…Õ¹¡}É•…‘äœ°(€€€€€Ñ…É•Ñ}É•¥½¹ÌèlÕÌµ•…ÍÐ´Ät°(€€€€€Ñ…É•Ñ}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€Ñ…É•Ñ}½Õ}¥‘Ìèl½Ô´ÄÈÌÐµ…‰ÔØÜàt°(€€€€€•á±Õ‘•‘}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€…ÕÑ½}½¹‰½…É‘}¹•Ý}…½Õ¹ÑÌèÑÉÕ”°(€€€€€Í•ÑÕÁ}ÍÕµµ…Éäè€M•±•Ñ•=UÌÍ•ÑÕÀ¸œ°(€€€€€¹•áÑ}…Ñ¥½¹Ìèl½Á•¹}ÍÑ…­Í•Ðœ°€É•™É•Í¡}ÍÑ…ÑÕÌt°(€€€€€ÍÑ…­Í•Ñ}½¹‰½…É‘¥¹œèÉ•…‘å]MMÑ…­M•Ñ=¹‰½…É‘¥¹œ°(€€€€€Á•Éµ¥ÍÍ¥½¹}ÁÉ•Ù¥•Üèmt°(€€€€€Á•Éµ¥ÍÍ¥½¹}Ñ¥•ÉÌèmt(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼]…¥Ð™½ÈÑ¡”•á¥ÍÑ¥¹œ½É…¹¥é…Ñ¥½¸½¹¹•Ñ½ÈÑ¼¡å‘É…Ñ”¸(€€€…Ý…¥Ð½Á•¹]M½¹¹•Ñ¥½¹5…¹…•µ•¹Ð ¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€½MÑ…­M•Ð½¹‰½…É‘¥¹œÁÉ½É•ÍÌ½¤ô¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” É…‘¥¼œ°ì¹…µ”è€½M•±•Ñ•Í½Á”½¤ô¤¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ ½Q…É•Ð=T%Ì½¤¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€½Ô´ÄÈÌÐµ…‰ÔØÜàœô(€€€ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½1…Õ¹ MÑ…­M•ÐÍ•ÑÕÀ½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÑ…ÉÑ]M½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€½¹ÍÐÍÑ…ÉÑA…å±½…€ôÍÑ…ÉÑ]M½¹¹•Ñ½È¹µ½¬¹…±±ÍlÁtü¹lÁt…Ìì½¹¹•Ñ½É}¥üèÍÑÉ¥¹œìÍ½Á•}ÑåÁ”üèÍÑÉ¥¹œôì(€€€•áÁ•Ð¡ÍÑ…ÉÑA…å±½…ü¹Í½Á•}ÑåÁ”¤¹Ñ½	” Í•±•Ñ•‘}½ÕÌœ¤ì(€€€•áÁ•Ð¡ÍÑ…ÉÑA…å±½…ü¹½¹¹•Ñ½É}¥¤¹Ñ½	•U¹‘•™¥¹• ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌ]L½Á•É…Ñ¥½¹…°Á…¹•±ÌÝ¡•¸½¹¹•Ñ½È¡•…±Ñ ¥ÌÝ…É¹¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹‘¥Í½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€¡•…±Ñ¡}ÍÑ…ÑÕÌè€Ý…É¹¥¹œœ°(€€€€€€€‘¥…¹½ÍÑ¥Ìèmì½‘”è€Á•Éµ¥ÍÍ¥½¹}Ý…É¹¥¹œœ°µ•ÍÍ…”è€A•Éµ¥ÍÍ¥½¸¡•­Ì¹••…ÑÑ•¹Ñ¥½¸¸œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½A•Éµ¥ÍÍ¥½¸¡•…±Ñ ½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½A±…Ñ™½É´É•…‘¥¹•ÍÌ½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌ½¹¹•Ñ•]LÍÑ…ÑÕÌ…ÌÑ¡”‘•™…Õ±ÐÍÕ•ÍÌÍÑ…Ñ”‰•™½É”Í•ÑÕÀµ…¹…•µ•¹Ðœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€Ñ…É•Ñ}ÍÕµµ…Éäèì(€€€€€€€€€…½Õ¹Ñ}½Õ¹Ðè€Ä°(€€€€€€€€€…½Õ¹Ñ}½Õ¹Ñ}­¹½Ý¸èÑÉÕ”°(€€€€€€€€€½Õ}½Õ¹Ðè€À°(€€€€€€€€€É•¥½¹}½Õ¹Ðè€Ä°(€€€€€€€€€•á±Õ‘•‘}…½Õ¹Ñ}½Õ¹Ðè€À°(€€€€€€€€€•áÁ•Ñ•‘}ÍÑ…­}¥¹ÍÑ…¹•Ìè€Ä°(€€€€€€€€€•áÁ•Ñ•‘}ÍÑ…­}¥¹ÍÑ…¹•Í}­¹½Ý¸èÑÉÕ”°(€€€€€€€€€…±±}…½Õ¹ÑÌè™…±Í”(€€€€€€€ô(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÍÕµµ…Éä€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€]L½¹¹•Ñ•ÍÕµµ…Éäœô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½AÉ½‘ÕÑ¥½¸]L½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åQ•áÐ M¥¹±”…½Õ¹Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åQ•áÐ œÄ…½Õ¹Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åQ•áÐ œÄÉ•¥½¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½MÑ…ÉÐ]L¥¹Ñ•±±¥•¹”½¤ô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½‘¥Í½Ù•Éäý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸™ÍÑ…ÉÐôÄœ(€€€€¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½I•Ù¥•Üµ…¡¥¹”¥‘•¹Ñ¥Ñ¥•Ì½¤ô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½¥‘•¹Ñ¥Ñ¥•Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸œ(€€€€¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” É•¥½¸œ°ì¹…µ”è€]L…½Õ¹ÐÍ•ÑÕÀœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½5…¹…”½¹¹•Ñ¥½¸½¤ô¤¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€]L…½Õ¹ÐÍ•ÑÕÀœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð É•ÑÉ¥•Ì…¸]L‘¥Í½Ù•Éä•¹ÅÕ•Õ”…™Ñ•È„ÑÉ…¹Í¥•¹ÐÍÑ…ÉÐ™…¥±ÕÉ”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍ…¸€ôì(€€€€€¥è€Í…¸µÉ•ÑÉäœ°(€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€ÁÉ½Ù¥‘•Èè€…ÝÌœ°(€€€€€ÍÑ…ÑÕÌè€ÅÕ•Õ•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´Àà´ÈÁPÈÀèÀÀèÀÁhœ°(€€€€€…ÍÍ•Ñ}½Õ¹Ðè€À°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€ôì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤ì(€€€½¹ÍÐÍÑ…ÉÑM…¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑM…¸œ¤(€€€€€€¹µ½­I•©•Ñ•‘Y…±Õ•=¹”¡¹•ÜÉÉ½È Ñ•µÁ½É…ÉäÍÑ…ÉÐ™…¥±ÕÉ”œ¤¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÍ…¸ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑM…¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÍ…¸èì€¸¸¹Í…¸°ÍÑ…ÑÕÌè€ÉÕ¹¹¥¹œœôô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑM…¹Ù•¹ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M¥Í½Ù•ÉåA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½‘¥Í½Ù•Éäý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸™ÍÑ…ÉÐôÄuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½‘¥Í½Ù•Éäˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M¥Í½Ù•ÉåA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½½Õ±‘¸ÐÍÑ…ÉÐ]L‘¥Í½Ù•Éä½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½QÉä……¥¸½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÑ…ÉÑM…¸¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€ô¤ì((€¥Ð …±±½ÝÌ„™…¥±•]L‘¥Í½Ù•ÉäÑ¼ÍÑ…ÉÐ„É•Á±…•µ•¹ÐÍ…¸œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐ™…¥±•‘M…¸€ôì(€€€€€¥è€Í…¸µ™…¥±•œ°(€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€ÁÉ½Ù¥‘•Èè€…ÝÌœ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´Àà´ÈÁPÈÀèÀÀèÀÁhœ°(€€€€€…ÍÍ•Ñ}½Õ¹Ðè€À°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€]LÝ½É­•È™…¥±•¸œ(€€€ôì(€€€½¹ÍÐÉ•Á±…•µ•¹ÑM…¸€ôì€¸¸¹™…¥±•‘M…¸°¥è€Í…¸µÉ•Á±…•µ•¹Ðœ°ÍÑ…ÑÕÌè€ÅÕ•Õ•œ°•ÉÉ½É}µ•ÍÍ…”èÕ¹‘•™¥¹•ôì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤ì(€€€½¹ÍÐÍÑ…ÉÑM…¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑM…¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÍ…¸èÉ•Á±…•µ•¹ÑM…¸ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑM…¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÍ…¸è™…¥±•‘M…¸ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑM…¹Ù•¹ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M¥Í½Ù•ÉåA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½‘¥Í½Ù•Éäý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸™Í…¹}¥õÍ…¸µ™…¥±•uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½‘¥Í½Ù•Éäˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M¥Í½Ù•ÉåA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½¥Í½Ù•Éä™…¥±•½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½MÑ…ÉÐ„¹•Ü‘¥Í½Ù•Éä½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÑ…ÉÑM…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€ìÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœô°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÍÑ…ÉÐ]L‘¥Í½Ù•ÉäÝ¥Ñ Ñ¡”ÁÉ•Ù¥½ÕÌ•¹Ù¥É½¹µ•¹Ð½¹¹•Ñ½Èœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹½¹¹•Ñ¥½¸€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è]M½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€€€¹…µ”è€MÑ…¥¹œœ°(€€€€€€€€€Í±Õœè€ÍÑ…¥¹œœ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€MÑ…¥¹œ]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€ÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œœ€üÍÑ…¥¹½¹¹•Ñ¥½¸¹ÁÉ½µ¥Í”€èAÉ½µ¥Í”¹É•Í½±Ù”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤(€€€€¤ì(€€€½¹ÍÐÍÑ…ÉÑM…¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑM…¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€Í…¸èì(€€€€€€€¥è€Í…¸µÍÑ…¥¹œœ°(€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€½¹¹•Ñ½É}¥è€ÍÑ…¥¹œµ½¹¹•Ñ½Èœ°(€€€€€€€ÁÉ½Ù¥‘•Èè€…ÝÌœ°(€€€€€€€ÍÑ…ÑÕÌè€ÅÕ•Õ•œ°(€€€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´Àà´ÈÁPÈÀèÀÀèÀÁhœ°(€€€€€€€…ÍÍ•Ñ}½Õ¹Ðè€À°(€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M¥Í½Ù•ÉåA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½‘¥Í½Ù•Éäý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½‘¥Í½Ù•Éäˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M¥Í½Ù•ÉåA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐ•¹Ù¥É½¹µ•¹ÑM•±•Ñ½È€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡•¹Ù¥É½¹µ•¹ÑM•±•Ñ½È°ìÑ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œœôô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€ÍÑ…¥¹œœ°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤¤ì(€€€•áÁ•Ð¡ÍÑ…ÉÑM…¸¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÍÑ…¥¹½¹¹•Ñ¥½¸¹É•Í½±Ù”¡ì½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘]L°½¹¹•Ñ½É}¥è€ÍÑ…¥¹œµ½¹¹•Ñ½Èœôô¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÑ…ÉÑM…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€ìÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°½¹¹•Ñ½É}¥è€ÍÑ…¥¹œµ½¹¹•Ñ½Èœô°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤¤ì(€ô¤ì((€¥Ð ¥¹½É•Ì„±…Ñ”]L‘¥Í½Ù•ÉäÍÑ…ÉÐÉ•ÍÁ½¹Í”™É½´Ñ¡”ÁÉ•Ù¥½ÕÌ•¹Ù¥É½¹µ•¹Ðœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…ÉÑAÉ½‘ÕÑ¥½¸€ô‘•™•ÉÉ•ñìÍ…¸èì¥èÍÑÉ¥¹œìÁÉ½©•Ñ}¥èÍÑÉ¥¹œì½¹¹•Ñ½É}¥èÍÑÉ¥¹œìÁÉ½Ù¥‘•ÈèÍÑÉ¥¹œìÍÑ…ÑÕÌèÍÑÉ¥¹œìÍÑ…ÉÑ•‘}…ÐèÍÑÉ¥¹œì…ÍÍ•Ñ}½Õ¹Ðè¹Õµ‰•Èì™¥¹‘¥¹}½Õ¹Ðè¹Õµ‰•Èôôø ¤ì(€€€½¹ÍÐÍÑ…ÉÑMÑ…¥¹œ€ô‘•™•ÉÉ•ñìÍ…¸èì¥èÍÑÉ¥¹œìÁÉ½©•Ñ}¥èÍÑÉ¥¹œì½¹¹•Ñ½É}¥èÍÑÉ¥¹œìÁÉ½Ù¥‘•ÈèÍÑÉ¥¹œìÍÑ…ÑÕÌèÍÑÉ¥¹œìÍÑ…ÉÑ•‘}…ÐèÍÑÉ¥¹œì…ÍÍ•Ñ}½Õ¹Ðè¹Õµ‰•Èì™¥¹‘¥¹}½Õ¹Ðè¹Õµ‰•Èôôø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€€€¹…µ”è€MÑ…¥¹œœ°(€€€€€€€€€Í±Õœè€ÍÑ…¥¹œœ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€MÑ…¥¹œ]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôøAÉ½µ¥Í”¹É•Í½±Ù”¡ì(€€€€€½¹¹•Ñ¥½¸èÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œœ€üì€¸¸¹½¹¹•Ñ•‘]L°½¹¹•Ñ½É}¥è€ÍÑ…¥¹œµ½¹¹•Ñ½Èœô€è½¹¹•Ñ•‘]L(€€€ô¤¤ì(€€€½¹ÍÐÍÑ…ÉÑM…¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑM…¸œ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¹=¹”  ¤€ôøÍÑ…ÉÑAÉ½‘ÕÑ¥½¸¹ÁÉ½µ¥Í”¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¹=¹”  ¤€ôøÍÑ…ÉÑMÑ…¥¹œ¹ÁÉ½µ¥Í”¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑM…¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€Í…¸èì(€€€€€€€¥è€Í…¸µÍÑ…¥¹œœ°(€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€½¹¹•Ñ½É}¥è€ÍÑ…¥¹œµ½¹¹•Ñ½Èœ°(€€€€€€€ÁÉ½Ù¥‘•Èè€…ÝÌœ°(€€€€€€€ÍÑ…ÑÕÌè€ÉÕ¹¹¥¹œœ°(€€€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´Àà´ÈÁPÈÀèÀÀèÀÁhœ°(€€€€€€€…ÍÍ•Ñ}½Õ¹Ðè€À°(€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑM…¹Ù•¹ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M¥Í½Ù•ÉåA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€™Õ¹Ñ¥½¸1½…Ñ¥½¹AÉ½‰” ¤ì(€€€€€½¹ÍÐÕÉÉ•¹Ñ1½…Ñ¥½¸€ôÕÍ•1½…Ñ¥½¸ ¤ì(€€€€€É•ÑÕÉ¸€ñ½ÕÑÁÕÐ‘…Ñ„µÑ•ÍÑ¥ô‰…ÝÌµ‘¥Í½Ù•Éäµ±½…Ñ¥½¸ˆùíÕÉÉ•¹Ñ1½…Ñ¥½¸¹Í•…É¡ôð½½ÕÑÁÕÐøì(€€€ô((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½‘¥Í½Ù•Éäý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸™ÍÑ…ÉÐôÄuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½‘¥Í½Ù•Éäˆ•±•µ•¹ÐõìðøñAÉ½‘ÕÑ]M¥Í½Ù•ÉåA…”€¼øñ1½…Ñ¥½¹AÉ½‰”€¼øð¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÑ…ÉÑM…¸¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ìÑ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œœôô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÑ…ÉÑM…¸¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÍÑ…ÉÑAÉ½‘ÕÑ¥½¸¹É•Í½±Ù”¡ì(€€€€€€€Í…¸èì(€€€€€€€€€¥è€Í…¸µÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€€€ÁÉ½Ù¥‘•Èè€…ÝÌœ°(€€€€€€€€€ÍÑ…ÑÕÌè€ÅÕ•Õ•œ°(€€€€€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´Àà´ÈÁPÈÀèÀÀèÀÁhœ°(€€€€€€€€€…ÍÍ•Ñ}½Õ¹Ðè€À°(€€€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€€€€€ô(€€€€€ô¤ì(€€€ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% …ÝÌµ‘¥Í½Ù•Éäµ±½…Ñ¥½¸œ¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð •¹Ù¥É½¹µ•¹ÐõÍÑ…¥¹œ™ÍÑ…ÉÐôÄœ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÍÑ…ÉÑMÑ…¥¹œ¹É•Í½±Ù”¡ì(€€€€€€€Í…¸èì(€€€€€€€€€¥è€Í…¸µÍÑ…¥¹œœ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€€€½¹¹•Ñ½É}¥è€ÍÑ…¥¹œµ½¹¹•Ñ½Èœ°(€€€€€€€€€ÁÉ½Ù¥‘•Èè€…ÝÌœ°(€€€€€€€€€ÍÑ…ÑÕÌè€ÅÕ•Õ•œ°(€€€€€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´Àà´ÈÁPÈÀèÀÀèÀÁhœ°(€€€€€€€€€…ÍÍ•Ñ}½Õ¹Ðè€À°(€€€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€€€€€ô(€€€€€ô¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% …ÝÌµ‘¥Í½Ù•Éäµ±½…Ñ¥½¸œ¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð •¹Ù¥É½¹µ•¹ÐõÍÑ…¥¹œ™Í…¹}¥õÍ…¸µÍÑ…¥¹œœ¤¤ì(€ô¤ì((€¥Ð ­••ÁÌ•‘¥Ñ•]LÉ½±”‘É…™ÑÌÝ¡•¸Á½±±¥¹œÍÑ…ÑÕÌÉ•ÑÕÉ¹Ì½±‘•È½¹¹•Ñ¥½¸‘…Ñ„œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€Á½±±]M½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€É½±•}…É¸è€…É¸é…ÝÌé¥…´èèÄÈÌÐÔØÜàäÀÄÈéÉ½±”½=±‘•É½¹¹•Ñ½ÉI½±”œ(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€]L½¹¹•Ñ•ÍÕµµ…Éäœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½5…¹…”½¹¹•Ñ¥½¸½¤ô¤¤ì(€€€½¹ÍÐÉ½±•%¹ÁÕÐ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ I½±”I8œ¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡É½±•%¹ÁÕÐ°ìÑ…É•ÐèìÙ…±Õ”è€…É¸é…ÝÌé¥…´èèÄÈÌÐÔØÜàäÀÄÈéÉ½±”½½ÉÉ•Ñ•‘½¹¹•Ñ½ÉI½±”œôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ]L…½Õ¹ÐÍ•ÑÕÀœ¤¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½I•™É•Í ½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹Á½±±]M½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±• ¤¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” É•¥½¸œ°ì¹…µ”è€]L½¹¹•Ñ•ÍÕµµ…Éäœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ I½±”I8œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ­••ÁÌ±•…äÉ½±”µ½¹±ä]L½¹¹•Ñ¥½¹Ì½ÕÐ½˜½¹¹•Ñ½ÈÙ…±¥‘…Ñ¥½¸œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥èÕ¹‘•™¥¹•°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€µ…¹Õ…°œ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€½¹¹•Ñ•œ°(€€€€€€€Í•ÑÕÁ}ÍÕµµ…Éäè€á¥ÍÑ¥¹œ%4É½±”½¹¹•Ñ¥½¸¸œ(€€€€€ô(€€€ô¤ì(€€€½¹ÍÐÙ…±¥‘…Ñ•]M½¹¹•Ñ½È€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€Ù…±¥‘…Ñ•]M½¹¹•Ñ½Èœ¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€]L½¹¹•Ñ•ÍÕµµ…Éäœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½5…¹…”½¹¹•Ñ¥½¸½¤ô¤¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½¡½½Í”Ý¡…ÐÑ¼½Ù•È½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ I½±”I8œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yY…±¥‘…Ñ”É½±”½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½MÑ…ÉÐ±½Õ‘½Éµ…Ñ¥½¸Í•ÑÕÀÑ¼µ½Ù”¥Ð½¹Ñ¼Ñ¡”½¹¹•Ñ½È™±½Ü½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ù…±¥‘…Ñ•]M½¹¹•Ñ½È¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌÑ¡”-Õ‰•É¹•Ñ•Ì½¹ÑÉ½°•¹Ñ•ÈÝ¥Ñ ½¹¹•Ñ•±ÕÍÑ•È½Ù•É…”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹ÑÉ½±•¹Ñ•ÉA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ìˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€-Õ‰•É¹•Ñ•Ì½¹ÑÉ½°•¹Ñ•Èœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ¥µœœ°ì¹…µ”è€-Õ‰•É¹•Ñ•Ìœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ±±	åQ•áÐ ÁÉ½‘ÕÑ¥½¸µ±ÕÍÑ•Èœ¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ œÈ¼È…±±½Ý•œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€½¹ÍÐÍ•Ñ¥½¹Q…‰±”€ôÍÉ••¸¹•Ñ	åI½±” Ñ…‰±”œ°ì¹…µ”è€-Õ‰•É¹•Ñ•ÌÍ•Ñ¥½¸±¥¹­Ìœô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Í•Ñ¥½¹Q…‰±”¤¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€±ÕÍÑ•ÉÌœô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½±ÕÍÑ•ÉÌý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸œ(€€€€¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Í•Ñ¥½¹Q…‰±”¤¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€M•ÉÙ¥”…½Õ¹ÑÌ€¼I	œô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½Í•ÉÙ¥”µ…½Õ¹ÑÌý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸œ(€€€€¤ì(€ô¤ì((€¥Ð Ý…¥ÑÌ™½È-Õ‰•É¹•Ñ•Ì™•…ÑÕÉ”µ•Ñ…‘…Ñ„‰•™½É”±½…‘¥¹œ½¹¹•Ñ¥½¸ÍÑ…Ñ”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÕ¹‘•™¥¹•ô°ì±½…‘¥¹œèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑÌ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€½¹ÍÐ•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹ÑÉ½±•¹Ñ•ÉA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ìˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€-Õ‰•É¹•Ñ•Ì½¹ÑÉ½°•¹Ñ•Èœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±• ¤¤ì(€€€•áÁ•Ð¡•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð ¡¥‘•Ì-Õ‰•É¹•Ñ•ÌÝ½É­±½…¥¹Ù•¹Ñ½ÉäÝ¡•¸Ñ¡”½¹¹•Ñ½È¥ÌÕ¹…Ù…¥±…‰±”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€½¹ÍÐ•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í]½É­±½…‘ÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½Ý½É­±½…‘Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½Ý½É­±½…‘Ìˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í]½É­±½…‘ÍA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ -Õ‰•É¹•Ñ•ÌÕ¹…Ù…¥±…‰±”œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” Ñ…‰±”œ°ì¹…µ”è€]½É­±½…¥‘•¹Ñ¥Ñäœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ •Á±½åµ•¹ÑÌœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð ¡¥‘•Ì-Õ‰•É¹•Ñ•ÌÝ½É­±½…¥¹Ù•¹Ñ½ÉäÝ¡•¸¹¼•¹Ù¥É½¹µ•¹Ð¥ÌÍ•±•Ñ•œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€½¹ÍÐ•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í]½É­±½…‘ÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½Ý½É­±½…‘Ìuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½Ý½É­±½…‘Ìˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í]½É­±½…‘ÍA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¡½½Í”…¸•¹Ù¥É½¹µ•¹Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” Ñ…‰±”œ°ì¹…µ”è€]½É­±½…¥‘•¹Ñ¥Ñäœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ •Á±½åµ•¹ÑÌœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð ­••ÁÌ-Õ‰•É¹•Ñ•Ì½¹¹•Ð½¸Ñ¡”‘½µ…¥¸Á…”Ý¡•¸¹¼•¹Ù¥É½¹µ•¹Ð•á¥ÍÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€½¹ÍÐ•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€½¹¹•Ð-Õ‰•É¹•Ñ•Ìœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½¡½½Í”…¸•¹Ù¥É½¹µ•¹Ð½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½=Á•¸•¹Ù¥É½¹µ•¹ÑÌ½¤ô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½ÁÉ½©•ÑÌýÍ½ÕÉ”õ­Õ‰•É¹•Ñ•Ìœ(€€€€¤ì(€€€•áÁ•Ð¡•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð ‘¥Í…‰±•Ì-Õ‰•É¹•Ñ•Ì½¹¹•Ñ½ÈÍÕ‰µ¥ÐÝ¡¥±”™•…ÑÕÉ”µ•Ñ…‘…Ñ„±½…‘Ìœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÕ¹‘•™¥¹•ô°ì±½…‘¥¹œèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€½¹ÍÐ•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤ì(€€€½¹ÍÐÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½È€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½Èœ¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÍÕ‰µ¥Ñ	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•¹•É…Ñ”Ñ½­•¸½¤ô¤ì(€€€•áÁ•Ð¡ÍÕ‰µ¥Ñ	ÕÑÑ½¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÕ‰µ¥Ñ	ÕÑÑ½¸¤ì(€€€•áÁ•Ð¡•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€•áÁ•Ð¡ÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½È¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð ÍÑ…ÉÑÌ-Õ‰•É¹•Ñ•Ì…•¹Ð•¹É½±±µ•¹ÐÝ¥Ñ Ý½É­ÍÁ…”…¹•¹Ù¥É½¹µ•¹ÐÍ½Á”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€½¹ÍÐ•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì½¹¹•Ñ¥½¸è‘¥Í½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ì°(€€€€€•¹É½±±µ•¹Ñ}Ñ½­•¸è€•¹É½±°µÑ½­•¸´ÄÈÌœ°(€€€€€•¹É½±±µ•¹Ñ}•áÁ¥É•Í}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€¡•±µ}½µµ…¹è€¡•±´ÕÁÉ…‘”€´µ¥¹ÍÑ…±°¥‘•¹ÑÉ…¥°µ…•¹Ð¥‘•¹ÑÉ…¥°½…•¹Ð€´µÍ•ÐÑ½­•¸õ•¹É½±°µÑ½­•¸´ÄÈÌœ(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÍÕ‰µ¥Ñ	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•¹•É…Ñ”Ñ½­•¸½¤ô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥ÍÁ±…ä¹…µ”œ¤°ìÑ…É•ÐèìÙ…±Õ”è€AÉ½‘ÕÑ¥½¸,áÌœôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ A$UI0œ¤°ìÑ…É•ÐèìÙ…±Õ”è€¡ÑÑÁÌè¼½¬áÌ¹•á…µÁ±”¹½´œôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÕ‰µ¥Ñ	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹ÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘¥ÍÁ±…å}¹…µ”è€AÉ½‘ÕÑ¥½¸,áÌœ°(€€€€€€€€€…Á¥}ÕÉ°è€¡ÑÑÁÌè¼½¬áÌ¹•á…µÁ±”¹½´œ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å¥ÍÁ±…åY…±Õ” AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ìœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ •¹É½±°µÑ½­•¸´ÄÈÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½¡•±´ÕÁÉ…‘”€´µ¥¹ÍÑ…±°¥‘•¹ÑÉ…¥°µ…•¹Ð½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ¥¹½É•ÌÍÑ…±”-Õ‰•É¹•Ñ•Ì•¹É½±±µ•¹ÐÉ•ÍÁ½¹Í•Ì…™Ñ•ÈÍÝ¥Ñ¡¥¹œ•¹Ù¥É½¹µ•¹ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€€€¹…µ”è€MÑ…¥¹œœ°(€€€€€€€€€Í±Õœè€ÍÑ…¥¹œœ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€MÑ…¥¹œ-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€½¹ÍÐ•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è‘¥Í½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì(€€€½¹ÍÐ•¹É½±±µ•¹Ð€ô‘•™•ÉÉ•ñ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½ÉMÑ…ÉÑI•ÍÁ½¹Í”ø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½Èœ¤¹µ½­I•ÑÕÉ¹Y…±Õ”¡•¹É½±±µ•¹Ð¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€™Õ¹Ñ¥½¸-Õ‰•É¹•Ñ•Í½¹¹•Ñ!…É¹•ÍÌ ¤ì(€€€€€½¹ÍÐ±½…Ñ¥½¸€ôÕÍ•1½…Ñ¥½¸ ¤ì(€€€€€½¹ÍÐ¹…Ù¥…Ñ”€ôÕÍ•9…Ù¥…Ñ” ¤ì(€€€€€É•ÑÕÉ¸€ (€€€€€€€€ðø(€€€€€€€€€€ñÀ‘…Ñ„µÑ•ÍÑ¥ô‰±½…Ñ¥½¸ˆùí€‘í±½…Ñ¥½¸¹Á…Ñ¡¹…µ•ô‘í±½…Ñ¥½¸¹Í•…É¡õôð½Àø(€€€€€€€€€€ñ‰ÕÑÑ½¸(€€€€€€€€€€€ÑåÁ”ô‰‰ÕÑÑ½¸ˆ(€€€€€€€€€€€½¹±¥¬õì ¤€ôø¹…Ù¥…Ñ” œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÍÑ…¥¹œœ¥ô(€€€€€€€€€€ø(€€€€€€€€€€€=Á•¸ÍÑ…¥¹œ(€€€€€€€€€€ð½‰ÕÑÑ½¸ø(€€€€€€€€€€ñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”€¼ø(€€€€€€€€ð¼ø(€€€€€€¤ì(€€€ô((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðˆ•±•µ•¹Ðõìñ-Õ‰•É¹•Ñ•Í½¹¹•Ñ!…É¹•ÍÌ€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÍÕ‰µ¥Ñ	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•¹•É…Ñ”Ñ½­•¸½¤ô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥ÍÁ±…ä¹…µ”œ¤°ìÑ…É•ÐèìÙ…±Õ”è€AÉ½‘ÕÑ¥½¸,áÌœôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÕ‰µ¥Ñ	ÕÑÑ½¸¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹ÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÝ½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€=Á•¸ÍÑ…¥¹œœô¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ±½…Ñ¥½¸œ¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð •¹Ù¥É½¹µ•¹ÐõÍÑ…¥¹œœ¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€•¹É½±±µ•¹Ð¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ì°(€€€€€€€•¹É½±±µ•¹Ñ}Ñ½­•¸è€ÍÑ…±”µ•¹É½±°µÑ½­•¸œ°(€€€€€€€•¹É½±±µ•¹Ñ}•áÁ¥É•Í}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€€€¡•±µ}½µµ…¹è€¡•±´ÕÁÉ…‘”€´µ¥¹ÍÑ…±°¥‘•¹ÑÉ…¥°µ…•¹Ð¥‘•¹ÑÉ…¥°½…•¹Ð€´µÍ•ÐÑ½­•¸õÍÑ…±”µ•¹É½±°µÑ½­•¸œ(€€€€€ô¤ì(€€€€€…Ý…¥Ð•¹É½±±µ•¹Ð¹ÁÉ½µ¥Í”ì(€€€ô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ÍÑ…±”µ•¹É½±°µÑ½­•¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½¹É½±±µ•¹ÐÑ½­•¸É•…‘ä½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð (€€€€€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸¹µ½¬¹…±±Ì¹™¥±Ñ•È ¡l°ÁÉ½©•Ñ%t¤€ôøÁÉ½©•Ñ%€ôôô€ÁÉ½‘ÕÑ¥½¸œ¤(€€€€¤¹Ñ½!…Ù•1•¹Ñ  Ä¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÁÉ•™¥±°-Õ‰•É¹•Ñ•Ì…•¹ÐA$UI0™É½´Ñ¡”±ÕÍÑ•ÈÍ•ÉÙ•Èœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å¥ÍÁ±…åY…±Õ” AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ìœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ A$UI0œ¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åA±…•¡½±‘•ÉQ•áÐ ¡ÑÑÁÌè¼½…Á¤¹¥‘•¹ÑÉ…¥°¹½´œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å¥ÍÁ±…åY…±Õ” ¡ÑÑÁÌè¼½¬áÌ¹•á…µÁ±”¹½´œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åA±…•¡½±‘•ÉQ•áÐ ¡ÑÑÁÌè¼½­Õ‰•É¹•Ñ•Ì¹‘•™…Õ±Ð¹ÍÙŒœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ÁÉ•Í•ÉÙ•Ì•á¥ÍÑ¥¹œ-Õ‰•É¹•Ñ•Ì­Õ‰•½¹™¥œµ½‘”Ý¡•¸±½…‘¥¹œÑ¡”½¹¹•Ñ¥½¸œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€½¹ÍÐ­Õ‰•½¹™¥½¹¹•Ñ¥½¸è-Õ‰•É¹•Ñ•Í½¹¹•Ñ¥½¹MÑ…ÑÕÌ€ôì(€€€€€€¸¸¹½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ì°(€€€€€½¹¹•Ñ½É}¥è€¬áÌµ­Õ‰•½¹™¥œœ°(€€€€€‘¥ÍÁ±…å}¹…µ”è€AÉ½‘ÕÑ¥½¸™…±±‰…¬œ°(€€€€€½¹Ñ•áÐè€ÁÉ½‘ÕÑ¥½¸µ…‘µ¥¸œ°(€€€€€½¹¹•Ñ¥½¹}µ½‘”è€­Õ‰•½¹™¥œœ(€€€ôì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è­Õ‰•½¹™¥½¹¹•Ñ¥½¸ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑ-Õ‰•É¹•Ñ•Í-Õ‰•½¹™¥½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è­Õ‰•½¹™¥½¹¹•Ñ¥½¸ô¤ì(€€€½¹ÍÐÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½È€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½Èœ¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½M…Ù”­Õ‰•½¹™¥œ½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ 5½‘”œ¤¤¹Ñ½!…Ù•Y…±Õ” ­Õ‰•½¹™¥œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥ÍÁ±…ä¹…µ”œ¤¤¹Ñ½!…Ù•Y…±Õ” AÉ½‘ÕÑ¥½¸™…±±‰…¬œ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ -Õ‰•½¹™¥œ½¹Ñ•áÐœ¤¤¹Ñ½!…Ù•Y…±Õ” ÁÉ½‘ÕÑ¥½¸µ…‘µ¥¸œ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ A$UI0œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ -Õ‰•½¹™¥œœ¤°ìÑ…É•ÐèìÙ…±Õ”è€…Á¥Y•ÉÍ¥½¸èØÅq¹±ÕÍÑ•ÉÌèmtœôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½M…Ù”­Õ‰•½¹™¥œ½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹ÕÁÍ•ÉÑ-Õ‰•É¹•Ñ•Í-Õ‰•½¹™¥½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€½¹¹•Ñ½É}¥è€¬áÌµ­Õ‰•½¹™¥œœ°(€€€€€€€€€‘¥ÍÁ±…å}¹…µ”è€AÉ½‘ÕÑ¥½¸™…±±‰…¬œ°(€€€€€€€€€½¹Ñ•áÐè€ÁÉ½‘ÕÑ¥½¸µ…‘µ¥¸œ°(€€€€€€€€€­Õ‰•½¹™¥œè€…Á¥Y•ÉÍ¥½¸èØÅq¹±ÕÍÑ•ÉÌèmtœ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€•áÁ•Ð¡ÍÑ…ÉÑ-Õ‰•É¹•Ñ•Í½¹¹•Ñ½È¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð Í…Ù•Ì-Õ‰•É¹•Ñ•Ì­Õ‰•½¹™¥œ™…±±‰…¬Ý¥Ñ Ý½É­ÍÁ…”…¹•¹Ù¥É½¹µ•¹ÐÍ½Á”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸-Õ‰•É¹•Ñ•Ì‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì€¸¸¹‘¥Í½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ì°½¹¹•Ñ½É}¥è€¬áÌµ•á¥ÍÑ¥¹œœ°½¹Ñ•áÐè€½±µ½¹Ñ•áÐœô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑ-Õ‰•É¹•Ñ•Í-Õ‰•½¹™¥½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½­Õ‰•É¹•Ñ•Ì½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ-Õ‰•É¹•Ñ•Í½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•¹•É…Ñ”Ñ½­•¸½¤ô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ 5½‘”œ¤°ìÑ…É•ÐèìÙ…±Õ”è€­Õ‰•½¹™¥œœôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥ÍÁ±…ä¹…µ”œ¤°ìÑ…É•ÐèìÙ…±Õ”è€AÉ½‘ÕÑ¥½¸™…±±‰…¬œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ -Õ‰•½¹™¥œ½¹Ñ•áÐœ¤°ìÑ…É•ÐèìÙ…±Õ”è€ÁÉ½‘ÕÑ¥½¸µ…‘µ¥¸œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ -Õ‰•½¹™¥œœ¤°ìÑ…É•ÐèìÙ…±Õ”è€…Á¥Y•ÉÍ¥½¸èØÅq¹±ÕÍÑ•ÉÌèmtœôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½M…Ù”­Õ‰•½¹™¥œ½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹ÕÁÍ•ÉÑ-Õ‰•É¹•Ñ•Í-Õ‰•½¹™¥½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€½¹¹•Ñ½É}¥è€¬áÌµ•á¥ÍÑ¥¹œœ°(€€€€€€€€€‘¥ÍÁ±…å}¹…µ”è€AÉ½‘ÕÑ¥½¸™…±±‰…¬œ°(€€€€€€€€€½¹Ñ•áÐè€ÁÉ½‘ÕÑ¥½¸µ…‘µ¥¸œ°(€€€€€€€€€­Õ‰•½¹™¥œè€…Á¥Y•ÉÍ¥½¸èØÅq¹±ÕÍÑ•ÉÌèmtœ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ -Õ‰•½¹™¥œ…Ñ¥Ù”¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ±•…ÉÌÍÑ…±”]L½¹¹•Ð™½É´Ù…±Õ•ÌÝ¡•¸Ñ¡”Í•±•Ñ••¹Ù¥É½¹µ•¹Ð¡…¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€€€¹…µ”è€MÑ…¥¹œœ°(€€€€€€€€€Í±Õœè€ÍÑ…¥¹œœ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€MÑ…¥¹œ]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€½¹ÍÐÁÉ½‘ÕÑ¥½¹MÑ…ÑÕÌ€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è]M½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì(€€€½¹ÍÐÍÑ…¥¹MÑ…ÑÕÌ€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è]M½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€ÁÉ½©•Ñ%€ôôô€ÁÉ½‘ÕÑ¥½¸œ€üÁÉ½‘ÕÑ¥½¹MÑ…ÑÕÌ¹ÁÉ½µ¥Í”€èÍÑ…¥¹MÑ…ÑÕÌ¹ÁÉ½µ¥Í”(€€€€¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ÁÉ½‘ÕÑ¥½¸œ¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ìÑ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œœôô¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÍÑ…¥¹MÑ…ÑÕÌ¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€€€¸¸¹‘¥Í½¹¹•Ñ•‘]L°(€€€€€€€€€Á•Éµ¥ÍÍ¥½¹}¡•­Ìèmt°(€€€€€€€€€‘¥…¹½ÍÑ¥Ìèmt(€€€€€€€ô(€€€€€ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½¡½½Í”Ý¡…ÐÑ¼½Ù•È½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ I½±”I8œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ I½±”I8œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥ÍÁ±…ä¹…µ”œ¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ !½µ”É•¥½¸œ¤¤¹Ñ½!…Ù•Y…±Õ” ÕÌµ•…ÍÐ´Äœ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÁÉ½‘ÕÑ¥½¹MÑ…ÑÕÌ¹É•Í½±Ù”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤ì(€€€ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ I½±”I8œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å¥ÍÁ±…åY…±Õ” AÉ½‘ÕÑ¥½¸]Lœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ¥¹½É•ÌÍÑ…±”]L±½Õ‘½Éµ…Ñ¥½¸ÍÑ…ÉÐÉ•ÍÁ½¹Í•Ì…™Ñ•ÈÍÝ¥Ñ¡¥¹œ•¹Ù¥É½¹µ•¹ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€€€¹…µ”è€MÑ…¥¹œœ°(€€€€€€€€€Í±Õœè€ÍÑ…¥¹œœ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€MÑ…¥¹œ]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è‘¥Í½¹¹•Ñ•‘]Lô¤ì(€€€½¹ÍÐÍÑ…ÉÑI•ÍÁ½¹Í”€ô‘•™•ÉÉ•ñ]M½¹¹•Ñ½ÉMÑ…ÉÑI•ÍÁ½¹Í”ø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ]M½¹¹•Ñ½Èœ¤¹µ½­I•ÑÕÉ¹Y…±Õ”¡ÍÑ…ÉÑI•ÍÁ½¹Í”¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐ±…Õ¹¡	ÕÑÑ½¸€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½½¹¹•Ð]L½¤ô¤¥lÁtì(€€€™¥É•Ù•¹Ð¹±¥¬¡±…Õ¹¡	ÕÑÑ½¸¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹ÍÑ…ÉÑ]M½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ìÑ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œœôô¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÍÑ…ÉÑI•ÍÁ½¹Í”¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€•áÑ•É¹…±}¥è€ÍÑ…±”µ•áÑ•É¹…°µ¥œ°(€€€€€€€±…Õ¹¡}ÕÉ°è€¡ÑÑÁÌè¼½½¹Í½±”¹…ÝÌ¹…µ…é½¸¹½´½±½Õ‘™½Éµ…Ñ¥½¸œ°(€€€€€€€Ñ•µÁ±…Ñ•}ÕÉ°è€¡ÑÑÁÌè¼½•á…µÁ±”¹½´½Ñ•µÁ±…Ñ”¹å…µ°œ°(€€€€€€€É½±•}¹…µ”è€%‘•¹ÑÉ…¥±I•…‘=¹±äœ°(€€€€€€€ÍÑ…­}¹…µ”è€¥‘•¹ÑÉ…¥°µÉ•…‘½¹±äµ½¹¹•Ñ½Èœ°(€€€€€€€Á½±¥å}¡…Í è€Í¡„ÈÔØé•á…µÁ±”œ°(€€€€€€€Í½Á•}ÑåÁ”è€Í¥¹±•}…½Õ¹Ðœ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€±½Õ‘™½Éµ…Ñ¥½¸œ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€±…Õ¹¡}É•…‘äœ°(€€€€€€€Ñ…É•Ñ}É•¥½¹ÌèlÕÌµ•…ÍÐ´Ät°(€€€€€€€Ñ…É•Ñ}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€€€Ñ…É•Ñ}½Õ}¥‘Ìèmt°(€€€€€€€•á±Õ‘•‘}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€€€…ÕÑ½}½¹‰½…É‘}¹•Ý}…½Õ¹ÑÌè™…±Í”°(€€€€€€€Í•ÑÕÁ}ÍÕµµ…Éäè€M¥¹±”]L…½Õ¹ÐÉ•…µ½¹±äÍ•ÑÕÀÑ¡É½Õ ±½Õ‘½Éµ…Ñ¥½¸¸œ°(€€€€€€€¹•áÑ}…Ñ¥½¹Ìèl±…Õ¹¡}ÍÑ…¬œ°€Ù…±¥‘…Ñ•}É½±”œ°€É•™É•Í¡}ÍÑ…ÑÕÌt°(€€€€€€€Á•Éµ¥ÍÍ¥½¹}ÁÉ•Ù¥•Üèl(€€€€€€€€€ìÍ•ÉÙ¥”è€%4œ°…Ñ¥½¹Ìèl¥…´é•ÑI½±”t°É•Í½ÕÉ•Ìèlœ¨t°É•…Í½¸è€%¹ÍÁ•ÐÉ½±”µ•Ñ…‘…Ñ„¸œô(€€€€€€€t°(€€€€€€€Á•Éµ¥ÍÍ¥½¹}Ñ¥•ÉÌèmt(€€€€€ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ÍÑ…¥¹œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ áÑ•É¹…°%œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ±¥¹¬œ°ì¹…µ”è€½=Á•¸]L½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½]L±½Õ‘½Éµ…Ñ¥½¸±…Õ¹ ¥ÌÉ•…‘ä½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÉ•Ù¥•ÜÁ•Éµ¥ÍÍ¥½¹Ì½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ¥¹½É•ÌÍÑ…±”]LÁ½±°É•ÍÁ½¹Í•Ì…™Ñ•ÈÍÝ¥Ñ¡¥¹œ•¹Ù¥É½¹µ•¹ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€€€¹…µ”è€MÑ…¥¹œœ°(€€€€€€€€€Í±Õœè€ÍÑ…¥¹œœ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€MÑ…¥¹œ]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ì½¹¹•Ñ¥½¸èÁÉ½©•Ñ%€ôôô€ÁÉ½‘ÕÑ¥½¸œ€ü½¹¹•Ñ•‘]L€è‘¥Í½¹¹•Ñ•‘]Lô¤(€€€€¤ì(€€€½¹ÍÐÁ½±±I•ÍÁ½¹Í”€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è]M½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€Á½±±]M½¹¹•Ñ½Èœ¤¹µ½­I•ÑÕÉ¹Y…±Õ”¡Á½±±I•ÍÁ½¹Í”¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥Ð½Á•¹]M½¹¹•Ñ¥½¹5…¹…•µ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½¡½½Í”Ý¡…ÐÑ¼½Ù•È½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€½¹ÍÐÉ•™É•Í¡	ÕÑÑ½¸€ôÝ¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ]L…½Õ¹ÐÍ•ÑÕÀœ¤¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì(€€€€€¹…µ”è€½I•™É•Í ½¤(€€€ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡É•™É•Í¡	ÕÑÑ½¸¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹Á½±±]M½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ìÑ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œœôô¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€Á½±±I•ÍÁ½¹Í”¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘]L°‘¥ÍÁ±…å}¹…µ”è€AÉ½‘ÕÑ¥½¸Á½±°]Lœ°…½Õ¹Ñ}¥è€œÄÄÄÄÄÄÄÄÄÄÄÄœô(€€€€€ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ÍÑ…¥¹œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ]L½¹¹•Ñ½È¥Ì…Ñ¥Ù”¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ AÉ½‘ÕÑ¥½¸Á½±°]Lœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð …ÕÑ½µ…Ñ¥…±±äÁ½±±Ì±½Õ‘½Éµ…Ñ¥½¸Í•ÑÕÀÕ¹Ñ¥°]L¥Ì½¹¹•Ñ•œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹‘¥Í½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€Ý…¥Ñ¥¹}™½É}…ÝÌœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€Á½±±]M½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€É½±•}…É¸è€…É¸é…ÝÌé¥…´èèÄÈÌÐÔØÜàäÀÄÈéÉ½±”½%‘•¹ÑÉ…¥±I•…‘=¹±äœ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€½¹¹•Ñ•œ(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÉ½±•%¹ÁÕÐ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ I½±”I8œ¤ì(€€€•áÁ•Ð¡É½±•%¹ÁÕÐ¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yY…±¥‘…Ñ”É½±”½¤ô¤¤¹Ñ½	•¥Í…‰±• ¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹Á½±±]M½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤°(€€€€€ìÑ¥µ•½ÕÐè€ÐÀÀÀô(€€€€¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€]L½¹¹•Ñ•ÍÕµµ…Éäœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å¥ÍÁ±…åY…±Õ” …É¸é…ÝÌé¥…´èèÄÈÌÐÔØÜàäÀÄÈéÉ½±”½%‘•¹ÑÉ…¥±I•…‘=¹±äœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yY…±¥‘…Ñ”É½±”½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ¡å‘É…Ñ•ÌÑÉÕÍÐµÁ½±¥äÉ•Á…¥Èµ…Ñ•É¥…°Ý¡•¸…ÕÑ½µ…Ñ¥ŒÁ½±±¥¹œÉ•…¡•Ì¹••‘Ìµ™¥àœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹‘¥Í½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€±½Õ‘™½Éµ…Ñ¥½¸œ°(€€€€€€€Í½Á•}ÑåÁ”è€Í¥¹±•}…½Õ¹Ðœ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€Ý…¥Ñ¥¹}™½É}…ÝÌœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€Á½±±]M½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹‘¥Í½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€±½Õ‘™½Éµ…Ñ¥½¸œ°(€€€€€€€Í½Á•}ÑåÁ”è€Í¥¹±•}…½Õ¹Ðœ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€¹••‘Í}™¥àœ°(€€€€€€€ÍÑ…ÑÕÌè€‘•É…‘•œ°(€€€€€€€¡•…±Ñ¡}ÍÑ…ÑÕÌè€•ÉÉ½Èœ(€€€€€ô(€€€ô¤ì(€€€½¹ÍÐ¡å‘É…Ñ•I•Á…¥È€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ]M½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹‘¥Í½¹¹•Ñ•‘]L°(€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€±½Õ‘™½Éµ…Ñ¥½¸œ°(€€€€€€€Í½Á•}ÑåÁ”è€Í¥¹±•}…½Õ¹Ðœ°(€€€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€¹••‘Í}™¥àœ°(€€€€€€€ÍÑ…ÑÕÌè€‘•É…‘•œ°(€€€€€€€¡•…±Ñ¡}ÍÑ…ÑÕÌè€•ÉÉ½Èœ(€€€€€ô°(€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€•áÑ•É¹…±}¥è€É•Á…¥Èµ•áÑ•É¹…°µ¥œ°(€€€€€±…Õ¹¡}ÕÉ°è€œœ°(€€€€€Ñ•µÁ±…Ñ•}ÕÉ°è€¡ÑÑÁÌè¼½•á…µÁ±”¹½´½Ñ•µÁ±…Ñ”¹å…µ°œ°(€€€€€É½±•}¹…µ”è€%‘•¹ÑÉ…¥±I•…‘=¹±äœ°(€€€€€ÍÑ…­}¹…µ”è€¥‘•¹ÑÉ…¥°µÉ•…‘½¹±äµ½¹¹•Ñ½Èœ°(€€€€€Á½±¥å}¡…Í è€Í¡„ÈÔØé•á…µÁ±”œ°(€€€€€Í½Á•}ÑåÁ”è€Í¥¹±•}…½Õ¹Ðœ°(€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€±½Õ‘™½Éµ…Ñ¥½¸œ°(€€€€€½¹‰½…É‘¥¹}ÍÑ…ÑÕÌè€¹••‘Í}™¥àœ°(€€€€€Ñ…É•Ñ}É•¥½¹ÌèlÕÌµ•…ÍÐ´Ät°(€€€€€Ñ…É•Ñ}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€Ñ…É•Ñ}½Õ}¥‘Ìèmt°(€€€€€•á±Õ‘•‘}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€…ÕÑ½}½¹‰½…É‘}¹•Ý}…½Õ¹ÑÌè™…±Í”°(€€€€€Í•ÑÕÁ}ÍÕµµ…Éäè€Q¡”½¹¹•Ñ¥½¸¹••‘Ì…ÑÑ•¹Ñ¥½¸¸œ°(€€€€€¹•áÑ}…Ñ¥½¹ÌèlÉ•Á…¥É}Á•Éµ¥ÍÍ¥½¹Ìœ°€Ù…±¥‘…Ñ•}É½±”œ°€É•™É•Í¡}ÍÑ…ÑÕÌt°(€€€€€Á•Éµ¥ÍÍ¥½¹}ÁÉ•Ù¥•Üèmt°(€€€€€Á•Éµ¥ÍÍ¥½¹}Ñ¥•ÉÌèmt(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹Á½±±]M½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±• ¤°ìÑ¥µ•½ÕÐè€ÐÀÀÀô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡¡å‘É…Ñ•I•Á…¥È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€½¹¹•Ñ½É}¥è€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€€€É•Á…¥É}½¹±äèÑÉÕ”°(€€€€€€€€€Í½Á•}ÑåÁ”è€Í¥¹±•}…½Õ¹Ðœ°(€€€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€±½Õ‘™½Éµ…Ñ¥½¸œ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€ô¤ì((€¥Ð ¥¹½É•ÌÍÑ…±”]LÙ…±¥‘…Ñ¥½¸É•ÍÁ½¹Í•Ì…™Ñ•ÈÍÝ¥Ñ¡¥¹œ•¹Ù¥É½¹µ•¹ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œœ°(€€€€€€€€€¹…µ”è€MÑ…¥¹œœ°(€€€€€€€€€Í±Õœè€ÍÑ…¥¹œœ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€MÑ…¥¹œ]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ì½¹¹•Ñ¥½¸èÁÉ½©•Ñ%€ôôô€ÁÉ½‘ÕÑ¥½¸œ€ü½¹¹•Ñ•‘]L€è‘¥Í½¹¹•Ñ•‘]Lô¤(€€€€¤ì(€€€½¹ÍÐÙ…±¥‘…Ñ¥½¹I•ÍÁ½¹Í”€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è]M½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€Ù…±¥‘…Ñ•]M½¹¹•Ñ½Èœ¤¹µ½­I•ÑÕÉ¹Y…±Õ”¡Ù…±¥‘…Ñ¥½¹I•ÍÁ½¹Í”¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€]L½¹¹•Ñ•ÍÕµµ…Éäœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½5…¹…”½¹¹•Ñ¥½¸½¤ô¤¤ì(€½¹ÍÐÍÕ‰µ¥Ñ	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yY…±¥‘…Ñ”É½±”½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÕ‰µ¥Ñ	ÕÑÑ½¸¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹Ù…±¥‘…Ñ•]M½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€…ÝÌµ½¹¹•Ñ½È´Äœ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ìÑ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œœôô¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€Ù…±¥‘…Ñ¥½¹I•ÍÁ½¹Í”¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘]L°‘¥ÍÁ±…å}¹…µ”è€Y…±¥‘…Ñ•ÁÉ½‘ÕÑ¥½¸]Lœ°…½Õ¹Ñ}¥è€œÄÄÄÄÄÄÄÄÄÄÄÄœô(€€€€€ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ÍÑ…¥¹œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ]L½¹¹•Ñ½È¥Ì…Ñ¥Ù”¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ Y…±¥‘…Ñ•ÁÉ½‘ÕÑ¥½¸]Lœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ±½…‘Ì]L½¹¹•Ð…Ñ¥½¹Ì™½ÈÑ¡”Í•±•Ñ••¹Ù¥É½¹µ•¹Ð•Ù•¸Ý¡•¸¥Ð¥Ì½ÕÑÍ¥‘”Ñ¡”™¥ÉÍÐÁ…”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑÌ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèÉÉ…ä¹™É½´¡ì±•¹Ñ è€ÔÀô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥èÉ••¹Ðµ•¹Ù¥É½¹µ•¹Ð´‘í¥¹‘•à€¬€Åõ€°(€€€€€€€¹…µ”èI••¹Ð¹Ù¥É½¹µ•¹Ð€‘í¥¹‘•à€¬€Åõ€°(€€€€€€€Í±ÕœèÉ••¹Ðµ•¹Ù¥É½¹µ•¹Ð´‘í¥¹‘•à€¬€Åõ€°(€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô¤¤(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥è€½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€¹…µ”è€=±‘•ÈAÉ½‘ÕÑ¥½¸œ°(€€€€€€€Í±Õœè€½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€1½¹œµ±¥Ù•ÁÉ½‘ÕÑ¥½¸‰½Õ¹‘…Éä¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈÔ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈÔ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€½¹ÍÐ•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹Ðõ½±‘•ÈµÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€]L½¹¹•Ñ•ÍÕµµ…Éäœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”½¹¹•Ñ•µÍÑ…Ñ”ÁÉ¥µ…ÉäQ¥ÌÑ¡”]L½Ù•ÉÙ¥•Ü±¥¹¬¸(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½]L½Ù•ÉÙ¥•Ü½¤ô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌý•¹Ù¥É½¹µ•¹Ðõ½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ(€€€€¤ì(€€€€¼¼Q¡”Á…”µÕÍÐÍÑ¥±°¡…Ù”™•Ñ¡•Ñ¡”]L½¹¹•Ñ¥½¸™½ÈÑ¡”(€€€€¼¼É•ÅÕ•ÍÑ••¹Ù¥É½¹µ•¹Ð€¡Ñ¡”•¹¥¹••É¥¹œM•ÑÕÀÁ…å±½…€¼Ù…±¥‘…Ñ¥½¸(€€€€¼¼¡…É¹•ÍÌ€¼½±±•Ñ½È½¹ÑÉ…ÐÁ…¹•±Ì¡…Ù”‰••¸É•µ½Ù•™É½´Ñ¡”(€€€€¼¼ÕÍÑ½µ•ÈU$‰ÕÐÑ¡”½¹¹•Ñ¥½¸™•Ñ ¥ÌÕ¹¡…¹•¤¸(€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€•áÁ•Ð¡•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤ì(€ô¤ì((€¥Ð ÅÕ…±¥™¥•Ì½É…¹¥é…Ñ¥½¸…±°µ…½Õ¹ÐÍÕµµ…É¥•ÌÝ¡•¸…½Õ¹ÑÌ…É”•á±Õ‘•œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸]L‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘]L°(€€€€€€€Í½Á•}ÑåÁ”è€½É…¹¥é…Ñ¥½¸œ°(€€€€€€€‘•Á±½åµ•¹Ñ}µ•Ñ¡½è€ÍÑ…­Í•Ñ}Í•ÉÙ¥•}µ…¹…•œ°(€€€€€€€Ñ…É•Ñ}…½Õ¹Ñ}¥‘Ìèmt°(€€€€€€€Ñ…É•Ñ}½Õ}¥‘ÌèlÈµ…‰t°(€€€€€€€•á±Õ‘•‘}…½Õ¹Ñ}¥‘ÌèlœÄÄÄÄÄÄÄÄÄÄÄÄœ°€œÈÈÈÈÈÈÈÈÈÈÈÈt°(€€€€€€€…ÕÑ½}½¹‰½…É‘}¹•Ý}…½Õ¹ÑÌèÑÉÕ”°(€€€€€€€Ñ…É•Ñ}ÍÕµµ…Éäèì(€€€€€€€€€…½Õ¹Ñ}½Õ¹Ðè€À°(€€€€€€€€€…½Õ¹Ñ}½Õ¹Ñ}­¹½Ý¸è™…±Í”°(€€€€€€€€€½Õ}½Õ¹Ðè€À°(€€€€€€€€€É•¥½¹}½Õ¹Ðè€Ä°(€€€€€€€€€•á±Õ‘•‘}…½Õ¹Ñ}½Õ¹Ðè€È°(€€€€€€€€€•áÁ•Ñ•‘}ÍÑ…­}¥¹ÍÑ…¹•Ìè€À°(€€€€€€€€€•áÁ•Ñ•‘}ÍÑ…­}¥¹ÍÑ…¹•Í}­¹½Ý¸è™…±Í”°(€€€€€€€€€…±±}…½Õ¹ÑÌèÑÉÕ”(€€€€€€€ô(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÍÕµµ…Éä€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€]L½¹¹•Ñ•ÍÕµµ…Éäœô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åQ•áÐ =É…¹¥é…Ñ¥½¸°…±°…½Õ¹ÑÌ•á•ÁÐ€È•á±Õ‘•…½Õ¹ÑÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åQ•áÐ ±°½É…¹¥é…Ñ¥½¸…½Õ¹ÑÌ•á•ÁÐ€È•á±Õ‘•…½Õ¹ÑÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ­••ÁÌÉ•ÅÕ•ÍÑ••¹Ù¥É½¹µ•¹ÐÍ•±•Ñ•Ý¡•¸•ÑAÉ½©•Ð¡•¬™…¥±Ì™½È„ÑÉ…¹Í¥•¹Ð•ÉÉ½Èœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèÉÉ…ä¹™É½´¡ì±•¹Ñ è€ÔÀô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥èÉ••¹Ðµ•¹Ù¥É½¹µ•¹Ð´‘í¥¹‘•à€¬€Åõ€°(€€€€€€€¹…µ”èI••¹Ð¹Ù¥É½¹µ•¹Ð€‘í¥¹‘•à€¬€Åõ€°(€€€€€€€Í±ÕœèÉ••¹Ðµ•¹Ù¥É½¹µ•¹Ð´‘í¥¹‘•à€¬€Åõ€°(€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô¤¤(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•©•Ñ•‘Y…±Õ”¡¹•Ü…Á¤¹Á¥ÉÉ½È Ñ•µÁ½É…Éä½ÕÑ…”œ°€ÔÀÌ¤¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ½µ…¥¹I½ÕÑ•A…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìý•¹Ù¥É½¹µ•¹Ðõ½±‘•ÈµÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ½µ…¥¹I½ÕÑ•A…”‘½µ…¥¸ô‰¥Ñ¡ÕˆˆÉ½ÕÑ•%ô‰É•Á½Í¥Ñ½É¥•Ìˆ€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½½¹¹•Ð¥Ñ!Õˆ½¤ô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹Ðõ½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ(€€€€¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½U¹…‰±”Ñ¼Ù•É¥™äÍ•±•Ñ••¹Ù¥É½¹µ•¹Ð½±‘•ÈµÁÉ½‘ÕÑ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð É•ÑÉ¥•ÌÉ•ÅÕ•ÍÑ••¹Ù¥É½¹µ•¹ÐÙ•É¥™¥…Ñ¥½¸…™Ñ•ÈÑÉ…¹Í¥•¹Ð•ÑAÉ½©•Ð™…¥±ÕÉ•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÉ••¹ÑAÉ½©•ÑÌ€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€ÔÀô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€ÁÉ½©•Ñ}¥èÉ••¹Ðµ•¹Ù¥É½¹µ•¹Ð´‘í¥¹‘•à€¬€Åõ€°(€€€€€¹…µ”èI••¹Ð¹Ù¥É½¹µ•¹Ð€‘í¥¹‘•à€¬€Åõ€°(€€€€€Í±ÕœèÉ••¹Ðµ•¹Ù¥É½¹µ•¹Ð´‘í¥¹‘•à€¬€Åõ€°(€€€€€‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€ô¤¤ì(€€€½¹ÍÐ½±‘•ÉAÉ½‘ÕÑ¥½¸€ôì(€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€ÁÉ½©•Ñ}¥è€½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ°(€€€€€¹…µ”è€=±‘•ÈAÉ½‘ÕÑ¥½¸œ°(€€€€€Í±Õœè€½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ°(€€€€€‘•ÍÉ¥ÁÑ¥½¸è€1½¹œµ±¥Ù•ÁÉ½‘ÕÑ¥½¸‰½Õ¹‘…Éä¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈÔ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈÔ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€ôì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑÌ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèÉ••¹ÑAÉ½©•ÑÌô¤ì(€€€½¹ÍÐ•ÑAÉ½©•Ð€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤(€€€€€€¹µ½­I•©•Ñ•‘Y…±Õ•=¹”¡¹•Ü…Á¤¹Á¥ÉÉ½È Ñ•µÁ½É…Éä½ÕÑ…”œ°€ÔÀÌ¤¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ìÁÉ½©•Ðè½±‘•ÉAÉ½‘ÕÑ¥½¸ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ½µ…¥¹I½ÕÑ•A…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐÉ•¹‘•ÉI•Á½Í¥Ñ½É¥•ÍA…”€ô€ ¤€ôø(€€€€€É•¹‘•È (€€€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìý•¹Ù¥É½¹µ•¹Ðõ½±‘•ÈµÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìˆ(€€€€€€€€€€€€€•±•µ•¹ÐõìñAÉ½‘ÕÑ½µ…¥¹I½ÕÑ•A…”‘½µ…¥¸ô‰¥Ñ¡ÕˆˆÉ½ÕÑ•%ô‰É•Á½Í¥Ñ½É¥•Ìˆ€¼ùô(€€€€€€€€€€€€¼ø(€€€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€€€¤ì((€€€½¹ÍÐ™¥ÉÍÑI•¹‘•È€ôÉ•¹‘•ÉI•Á½Í¥Ñ½É¥•ÍA…” ¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½U¹…‰±”Ñ¼Ù•É¥™äÍ•±•Ñ••¹Ù¥É½¹µ•¹Ð½±‘•ÈµÁÉ½‘ÕÑ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡•ÑAÉ½©•Ð¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€™¥ÉÍÑI•¹‘•È¹Õ¹µ½Õ¹Ð ¤ì((€€€É•¹‘•ÉI•Á½Í¥Ñ½É¥•ÍA…” ¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡•ÑAÉ½©•Ð¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½U¹…‰±”Ñ¼Ù•É¥™äÍ•±•Ñ••¹Ù¥É½¹µ•¹Ð½±‘•ÈµÁÉ½‘ÕÑ¥½¸½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤(€€€€¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÍ¥±•¹Ñ±äÍÝ¥Ñ ]L½¹¹•ÐÑ¼„™…±±‰…¬•¹Ù¥É½¹µ•¹ÐÝ¡•¸•ÑAÉ½©•Ð¡•¬™…¥±ÌÑÉ…¹Í¥•¹Ñ±äœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­]M	…Í•±¥¹”¡…Á¤¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑÌ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€…Ñ¥Ù”µÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€Ñ¥Ù”AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€…Ñ¥Ù”µÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€Ñ¥Ù”ÁÉ½‘ÕÑ¥½¸‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•©•Ñ•‘Y…±Õ”¡¹•Ü…Á¤¹Á¥ÉÉ½È Ñ•µÁ½É…Éä½ÕÑ…”œ°€ÔÀÌ¤¤ì(€€€½¹ÍÐ•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è‘¥Í½¹¹•Ñ•‘]Lô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ]M½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹Ðõ½±‘•ÈµÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ]M½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€½¹¹•Ð]Lœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½U¹…‰±”Ñ¼Ù•É¥™äÍ•±•Ñ••¹Ù¥É½¹µ•¹Ð½±‘•ÈµÁÉ½‘ÕÑ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€•áÁ•Ð¡•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€½±‘•ÈµÁÉ½‘ÕÑ¥½¸œ°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤ì(€ô¤ì((€¥Ð ™…±±Ì‰…¬Ñ¼…¸…Ñ¥Ù”•¹Ù¥É½¹µ•¹ÐÝ¡•¸Ñ¡”É•ÅÕ•ÍÑ••¹Ù¥É½¹µ•¹Ð¥Ì…É¡¥Ù•œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèl(€€€€€€€ì(€€€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€…Ñ¥Ù”µÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€¹…µ”è€Ñ¥Ù”AÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€Í±Õœè€…Ñ¥Ù”µÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€Ñ¥Ù”ÁÉ½‘ÕÑ¥½¸‰½Õ¹‘…Éä¸œ°(€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€€€ô(€€€€€t(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥è€…É¡¥Ù•µÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€¹…µ”è€É¡¥Ù•AÉ½‘ÕÑ¥½¸œ°(€€€€€€€Í±Õœè€…É¡¥Ù•µÁÉ½‘ÕÑ¥½¸œ°(€€€€€€€‘•ÍÉ¥ÁÑ¥½¸è€I•Ñ¥É•‰½Õ¹‘…Éä¸œ°(€€€€€€€…É¡¥Ù•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈÔ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ½µ…¥¹I½ÕÑ•A…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½¥‘•¹Ñ¥Ñ¥•Ìý•¹Ù¥É½¹µ•¹Ðõ…É¡¥Ù•µÁÉ½‘ÕÑ¥½¸uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½…ÝÌ½¥‘•¹Ñ¥Ñ¥•Ìˆ(€€€€€€€€€€€•±•µ•¹ÐõìñAÉ½‘ÕÑ½µ…¥¹I½ÕÑ•A…”‘½µ…¥¸ô‰…ÝÌˆÉ½ÕÑ•%ô‰¥‘•¹Ñ¥Ñ¥•Ìˆ€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” …Ñ¥Ù”µÁÉ½‘ÕÑ¥½¸œ¤¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½½¹¹•Ð]L½¤ô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½½¹¹•Ðý•¹Ù¥É½¹µ•¹Ðõ…Ñ¥Ù”µÁÉ½‘ÕÑ¥½¸œ(€€€€¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½]L™¥¹‘¥¹Ì½¤ô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½…ÝÌ½™¥¹‘¥¹Ìý•¹Ù¥É½¹µ•¹Ðõ…Ñ¥Ù”µÁÉ½‘ÕÑ¥½¸œ(€€€€¤ì(€ô¤ì((€¥Ð É•…Ñ•Ì„¹•ÜÕ¹¥ÅÕ”•¹Ù¥É½¹µ•¹Ð­•ä¥¹ÍÑ•…½˜½Ù•ÉÝÉ¥Ñ¥¹œ…¸•á¥ÍÑ¥¹œ•¹Ù¥É½¹µ•¹Ðœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐ™¥ÉÍÑA…•AÉ½©•ÑÌ€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€ÔÀô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€ÁÉ½©•Ñ}¥èÉ••¹Ðµ•¹Ù¥É½¹µ•¹Ð´‘í¥¹‘•à€¬€Åõ€°(€€€€€¹…µ”èI••¹Ð¹Ù¥É½¹µ•¹Ð€‘í¥¹‘•à€¬€Åõ€°(€€€€€Í±ÕœèÉ••¹Ðµ•¹Ù¥É½¹µ•¹Ð´‘í¥¹‘•à€¬€Åõ€°(€€€€€‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€ô¤¤ì(€€€½¹ÍÐ•á¥ÍÑ¥¹AÉ½©•Ð€ôì(€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°(€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€‘•ÍÉ¥ÁÑ¥½¸è€á¥ÍÑ¥¹œÁÉ½‘ÕÑ¥½¸‰½Õ¹‘…Éä¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€ôì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡}Ý½É­ÍÁ…•%°™¥±Ñ•ÉÌè…¹ä¤€ôøì(€€€€€¥˜€¡™¥±Ñ•ÉÌü¹±¥µ¥Ð€ôôô€ÔÀ¤ì(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌè™¥ÉÍÑA…•AÉ½©•ÑÌôì(€€€€€ô(€€€€€¥˜€¡™¥±Ñ•ÉÌü¹ÕÉÍ½È€ôôô€½±‘•ÈµÁ…”œ¤ì(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm•á¥ÍÑ¥¹AÉ½©•Ñtôì(€€€€€ô(€€€€€É•ÑÕÉ¸ì¥Ñ•µÌè™¥ÉÍÑA…•AÉ½©•ÑÌ°¹•áÑ}ÕÉÍ½Èè€½±‘•ÈµÁ…”œôì(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡}Ý½É­ÍÁ…•%°Á…å±½…è…¹ä¤€ôø€¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥èÁ…å±½…¹ÁÉ½©•Ñ}¥°(€€€€€€€¹…µ”èÁ…å±½…¹¹…µ”°(€€€€€€€Í±ÕœèÁ…å±½…¹Í±Õœ°(€€€€€€€‘•ÍÉ¥ÁÑ¥½¸èÁ…å±½…¹‘•ÍÉ¥ÁÑ¥½¸€üü€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤¤ì((€€€½¹ÍÐìAÉ½‘ÕÑAÉ½©•ÑÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€™Õ¹Ñ¥½¸1½…Ñ¥½¹AÉ½‰” ¤ì(€€€€€½¹ÍÐ±½…Ñ¥½¸€ôÕÍ•1½…Ñ¥½¸ ¤ì(€€€€€É•ÑÕÉ¸€ñÀ‘…Ñ„µÑ•ÍÑ¥ô‰±½…Ñ¥½¸ˆùí€‘í±½…Ñ¥½¸¹Á…Ñ¡¹…µ•ô‘í±½…Ñ¥½¸¹Í•…É¡õôð½Àøì(€€€ô((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½ÁÉ½©•ÑÌýÍ½ÕÉ”õ…ÝÌuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½ÁÉ½©•ÑÌˆ(€€€€€€€€€€€•±•µ•¹Ðõì(€€€€€€€€€€€€€€ðø(€€€€€€€€€€€€€€€€ñ1½…Ñ¥½¹AÉ½‰”€¼ø(€€€€€€€€€€€€€€€€ñAÉ½‘ÕÑAÉ½©•ÑÍA…”€¼ø(€€€€€€€€€€€€€€ð¼ø(€€€€€€€€€€€ô(€€€€€€€€€€¼ø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½ÁÉ½©•ÑÌ¼éÁÉ½©•Ñ%ˆ•±•µ•¹Ðõìñ1½…Ñ¥½¹AÉ½‰”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¹Ù¥É½¹µ•¹ÑÌœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½¹Ù¥É½¹µ•¹Ð¹…µ”½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½É•…Ñ”•¹Ù¥É½¹µ•¹Ð½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ±½…Ñ¥½¸œ¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð (€€€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½ÁÉ½©•ÑÌ½ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´´ÈýÍ½ÕÉ”õ…ÝÌœ(€€€€€€¤(€€€€¤ì(€€€•áÁ•Ð¡…Á¤¹…Á¥±¥•¹Ð¹ÕÁÍ•ÉÑAÉ½©•Ð¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´´Èœ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´´Èœô¤°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤ì(€ô¤ì((€¥Ð É•…Ñ•ÌÍÑ…‰±”¡¥‘‘•¸­•åÌ™½È¹½¸µM%$•¹Ù¥É½¹µ•¹Ð¹…µ•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡}Ý½É­ÍÁ…•%°Á…å±½…è…¹ä¤€ôø€¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥èÁ…å±½…¹ÁÉ½©•Ñ}¥°(€€€€€€€¹…µ”èÁ…å±½…¹¹…µ”°(€€€€€€€Í±ÕœèÁ…å±½…¹Í±Õœ°(€€€€€€€‘•ÍÉ¥ÁÑ¥½¸èÁ…å±½…¹‘•ÍÉ¥ÁÑ¥½¸€üü€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤¤ì((€€€½¹ÍÐìAÉ½‘ÕÑAÉ½©•ÑÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€™Õ¹Ñ¥½¸1½…Ñ¥½¹AÉ½‰” ¤ì(€€€€€½¹ÍÐ±½…Ñ¥½¸€ôÕÍ•1½…Ñ¥½¸ ¤ì(€€€€€É•ÑÕÉ¸€ñÀ‘…Ñ„µÑ•ÍÑ¥ô‰±½…Ñ¥½¸ˆùí€‘í±½…Ñ¥½¸¹Á…Ñ¡¹…µ•ô‘í±½…Ñ¥½¸¹Í•…É¡õôð½Àøì(€€€ô((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½ÁÉ½©•ÑÌýÍ½ÕÉ”õ¥Ñ¡Õˆuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½ÁÉ½©•ÑÌˆ(€€€€€€€€€€€•±•µ•¹Ðõì(€€€€€€€€€€€€€€ðø(€€€€€€€€€€€€€€€€ñ1½…Ñ¥½¹AÉ½‰”€¼ø(€€€€€€€€€€€€€€€€ñAÉ½‘ÕÑAÉ½©•ÑÍA…”€¼ø(€€€€€€€€€€€€€€ð¼ø(€€€€€€€€€€€ô(€€€€€€€€€€¼ø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½ÁÉ½©•ÑÌ¼éÁÉ½©•Ñ%ˆ•±•µ•¹Ðõìñ1½…Ñ¥½¹AÉ½‰”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¹Ù¥É½¹µ•¹ÑÌœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½¹Ù¥É½¹µ•¹Ð¹…µ”½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€Ÿšr³žV«žJÃ–Šœôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½É•…Ñ”•¹Ù¥É½¹µ•¹Ð½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ±½…Ñ¥½¸œ¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð œ½ÁÉ½©•ÑÌ½•¹Ù¥É½¹µ•¹Ð´œ¤¤ì(€€€½¹ÍÐÁ…å±½…€ô€¡…Á¤¹…Á¥±¥•¹Ð¹ÕÁÍ•ÉÑAÉ½©•Ð…Ì…¹ä¤¹µ½¬¹…±±ÍlÁulÅtì(€€€•áÁ•Ð¡Á…å±½…¹ÁÉ½©•Ñ}¥¤¹Ñ½5…Ñ  ½y•¹Ù¥É½¹µ•¹Ðµm„µèÀ´åt¬¼¤ì(€€€•áÁ•Ð¡Á…å±½…¹ÁÉ½©•Ñ}¥¤¹¹½Ð¹Ñ½	” ‘•™…Õ±Ðµ•¹Ù¥É½¹µ•¹Ðœ¤ì(€ô¤ì((€¥Ð É•ÅÕ¥É•ÌÑ¡”•¹Ù¥É½¹µ•¹Ð­•ä‰•™½É”‘•±•Ñ¥¹œ…¸•¹Ù¥É½¹µ•¹Ðœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÁÉ½©•Ð€ôì(€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°(€€€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸‰½Õ¹‘…Éä¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€ôì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½©•Ñtô¤ì(€€€½¹ÍÐ‘•±•Ñ•AÉ½©•Ð€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€‘•±•Ñ•AÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡Õ¹‘•™¥¹•¤ì((€€€½¹ÍÐìAÉ½‘ÕÑAÉ½©•ÑÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½ÁÉ½©•ÑÌuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½ÁÉ½©•ÑÌˆ•±•µ•¹ÐõìñAÉ½‘ÕÑAÉ½©•ÑÍA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¹Ù¥É½¹µ•¹ÑÌœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€•±•Ñ”•¹Ù¥É½¹µ•¹Ðœô¤¤ì((€€€½¹ÍÐµ½‘…°€ôÍÉ••¸¹•Ñ	åI½±” ‘¥…±½œœ°ì¹…µ”è€•±•Ñ”AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œô¤ì(€€€½¹ÍÐ½¹Ñ¥¹Õ•	ÕÑÑ½¸€ôÝ¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ½¹Ñ¥¹Õ”œ¤ì(€€€•áÁ•Ð¡½¹Ñ¥¹Õ•	ÕÑÑ½¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µÑåÁ•œ¤°ìÑ…É•ÐèìÙ…±Õ”èÁÉ½©•Ð¹ÁÉ½©•Ñ}¥ôô¤ì(€€€•áÁ•Ð¡½¹Ñ¥¹Õ•	ÕÑÑ½¸¤¹Ñ½	•¹…‰±• ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡½¹Ñ¥¹Õ•	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡‘•±•Ñ•AÉ½©•Ð¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½Ð…ÁÁ±ä„Á•¹‘¥¹œ‘•±•Ñ”Ñ¼Ñ¡”¹•áÐÝ½É­ÍÁ…”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÝ½É­ÍÁ…•AÉ½©•Ð€ôì(€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€ÁÉ½©•Ñ}¥è€Í¡…É•µ•¹Ù¥É½¹µ•¹Ðœ°(€€€€€¹…µ”è€]½É­ÍÁ…”¹Ù¥É½¹µ•¹Ðœ°(€€€€€Í±Õœè€Í¡…É•µ•¹Ù¥É½¹µ•¹Ðœ°(€€€€€‘•ÍÉ¥ÁÑ¥½¸è€]½É­ÍÁ…”‰½Õ¹‘…Éä¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€ôì(€€€½¹ÍÐÝ½É­ÍÁ…•	AÉ½©•Ð€ôì(€€€€€€¸¸¹Ý½É­ÍÁ…•AÉ½©•Ð°(€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µˆœ°(€€€€€¹…µ”è€]½É­ÍÁ…”¹Ù¥É½¹µ•¹Ðœ°(€€€€€‘•ÍÉ¥ÁÑ¥½¸è€]½É­ÍÁ…”‰½Õ¹‘…Éä¸œ(€€€ôì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡Ý½É­ÍÁ…•%¤€ôø€¡ì(€€€€€¥Ñ•µÌèmÝ½É­ÍÁ…•%€ôôô€Ý½É­ÍÁ…”µ„œ€üÝ½É­ÍÁ…•AÉ½©•Ð€èÝ½É­ÍÁ…•	AÉ½©•Ñt(€€€ô¤¤ì(€€€±•ÐÉ•Í½±Ù••±•Ñ”„è€ ¤€ôøÙ½¥ì(€€€½¹ÍÐ‘•±•Ñ•AÉ½©•Ð€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€‘•±•Ñ•AÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ (€€€€€€ ¤€ôø¹•ÜAÉ½µ¥Í”ñÙ½¥ø ¡É•Í½±Ù”¤€ôøì(€€€€€€€É•Í½±Ù••±•Ñ”€ôÉ•Í½±Ù”ì(€€€€€ô¤(€€€€¤ì((€€€½¹ÍÐìAÉ½‘ÕÑAÉ½©•ÑÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€™Õ¹Ñ¥½¸]½É­ÍÁ…•MÝ¥Ñ¡•È ¤ì(€€€€€½¹ÍÐ¹…Ù¥…Ñ”€ôÕÍ•9…Ù¥…Ñ” ¤ì(€€€€€É•ÑÕÉ¸€ (€€€€€€€€ñ‰ÕÑÑ½¸ÑåÁ”ô‰‰ÕÑÑ½¸ˆ½¹±¥¬õì ¤€ôø¹…Ù¥…Ñ” œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µˆ½ÁÉ½©•ÑÌœ¥ôø(€€€€€€€€€MÝ¥Ñ Ý½É­ÍÁ…”(€€€€€€€€ð½‰ÕÑÑ½¸ø(€€€€€€¤ì(€€€ô((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½ÁÉ½©•ÑÌuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½ÁÉ½©•ÑÌˆ(€€€€€€€€€€€•±•µ•¹Ðõì(€€€€€€€€€€€€€€ðø(€€€€€€€€€€€€€€€€ñ]½É­ÍÁ…•MÝ¥Ñ¡•È€¼ø(€€€€€€€€€€€€€€€€ñAÉ½‘ÕÑAÉ½©•ÑÍA…”€¼ø(€€€€€€€€€€€€€€ð¼ø(€€€€€€€€€€€ô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ]½É­ÍÁ…”¹Ù¥É½¹µ•¹Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€•±•Ñ”•¹Ù¥É½¹µ•¹Ðœô¤¤ì(€€€½¹ÍÐµ½‘…°€ôÍÉ••¸¹•Ñ	åI½±” ‘¥…±½œœ°ì¹…µ”è€•±•Ñ”]½É­ÍÁ…”¹Ù¥É½¹µ•¹Ðœô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µÑåÁ•œ¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”èÝ½É­ÍÁ…•AÉ½©•Ð¹ÁÉ½©•Ñ}¥ô(€€€ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ½¹Ñ¥¹Õ”œ¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡‘•±•Ñ•AÉ½©•Ð¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€Í¡…É•µ•¹Ù¥É½¹µ•¹Ðœ°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€MÝ¥Ñ Ý½É­ÍÁ…”œô¤¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ]½É­ÍÁ…”¹Ù¥É½¹µ•¹Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‘¥…±½œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€É•Í½±Ù••±•Ñ” ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€…Ý…¥ÐAÉ½µ¥Í”¹É•Í½±Ù” ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡‘•±•Ñ•AÉ½©•Ð¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ]½É­ÍÁ…”¹Ù¥É½¹µ•¹Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½Á•¹Ì¹•ÍÑ•¥Ñ!Õˆ$É¥Í¬É½ÕÑ•Ì™É½´Ñ¡”Í¥‘•‰…È‘½µ…¥¸™±å½ÕÐœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐìAÉ½‘ÕÑM¡•±±1…å½ÕÐô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì((€€€½¹ÍÐì½¹Ñ…¥¹•Èô€ôÉ•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½…•¹Ñ¥ŒµÉ¥Í¬½µÀµÑ½½±Ìuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%ˆ•±•µ•¹ÐõìñAÉ½‘ÕÑM¡•±±1…å½ÕÐ€¼ùôø(€€€€€€€€€€€€ñI½ÕÑ”Á…Ñ ô‰¥Ñ¡Õˆ½…•¹Ñ¥ŒµÉ¥Í¬½µÀµÑ½½±Ìˆ•±•µ•¹Ðõìñ Èù5@Ñ½½±Ì½¹Ñ•¹Ðð½ Èùô€¼ø(€€€€€€€€€€ð½I½ÕÑ”ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€½5@Ñ½½±Ì½¹Ñ•¹Ð½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€¥Ñ!Õˆœô¤¤ì((€€€½¹ÍÐ¥Ñ¡Õ‰±å½ÕÐ€ôÍÉ••¸¹•Ñ	åI½±” ‘¥…±½œœ°ì¹…µ”è€¥Ñ!Õˆœô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡¥Ñ¡Õ‰±å½ÕÐ¤¹•Ñ±±	åQ•áÐ $€¼•¹Ñ¥ŒI¥Í¬œ¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡¥Ñ¡Õ‰±å½ÕÐ¤¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€¥Ñ!Õˆ$€¼•¹Ñ¥ŒI¥Í¬5@€¼Ñ½½±Ìœô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€…É¥„µÕÉÉ•¹Ðœ°(€€€€€€Á…”œ(€€€€¤ì(€€€•áÁ•Ð¡½¹Ñ…¥¹•È¹ÅÕ•ÉåM•±•Ñ½È ‘•Ñ…¥±Ì¹¥‘Ðµ‘½µ…¥¸µ™±å½ÕÐµ¹•ÍÑ•œ¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” ½Á•¸œ¤ì(€ô¤ì)ô¤ì(((€…Íå¹Œ™Õ¹Ñ¥½¸É•¹‘•É¥¹‘¥¹Ì (€€€½ÁÑ¥½¹Ìèì(€€€€€É•Á½M…¹ÌüèI•Á½M…¹I•½É‘mtì(€€€€€É•Á½¥¹‘¥¹Ìüè¥¹‘¥¹mtì(€€€€€É•Á½¥¹‘¥¹MÕµµ…ÉäüèI•Á½¥¹‘¥¹ÍMÕµµ…Éäì(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìüè€ (€€€€€€€Á…É…µÌèÕ¹­¹½Ý¸°(€€€€€€€…±°è¹Õµ‰•È(€€€€€€¤€ôøì¥Ñ•µÌè¥¹‘¥¹mtìÍÕµµ…ÉäüèI•Á½¥¹‘¥¹ÍMÕµµ…ÉäôðAÉ½µ¥Í”ñì¥Ñ•µÌè¥¹‘¥¹mtìÍÕµµ…ÉäüèI•Á½¥¹‘¥¹ÍMÕµµ…Éäôøì(€€€€€•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ìüè€¡Á…É…µÌèÕ¹­¹½Ý¸¤€ôøì¥Ñ•µÌèQÉ•¹‘A½¥¹Ñmtôì(€€€€€•ÑI•Á½I¥Í­É…Á üè€¡Á…É…µÌèÕ¹­¹½Ý¸¤€ôøI•Á½I¥Í­É…Á ì(€€€€€É½±”üèÕÉÉ•¹ÑUÍ•É½¹Ñ•áÑlÉ½±”tì(€€€ô€ôíô(€€¤ì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€Ù¤¹‘½5½¬ œ¸½¡½½­Ì½ÕÍ•5”œ°€ ¤€ôø€¡ì(€€€€€ÕÍ•5”è€ ¤€ôø€¡ì(€€€€€€€µ”èì€¸¸¹±½•‘%¹]¥Ñ¡½ÕÑ]½É­ÍÁ…”°É½±”è½ÁÑ¥½¹Ì¹É½±”€üü€½Ý¹•Èœô…ÌÕÉÉ•¹ÑUÍ•É½¹Ñ•áÐ°(€€€€€€€±½…‘¥¹œè™…±Í”°(€€€€€€€•ÉÉ½Èè€œœ°(€€€€€€€Õ¹…ÕÑ¡•¹Ñ¥…Ñ•è™…±Í”°(€€€€€€€É•™É•Í èÙ¤¹™¸ ¤(€€€€€ô¤(€€€ô¤¤ì((€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌè½ÁÑ¥½¹Ì¹É•Á½M…¹Ì€üümtô¤ì(€€€±•Ð±¥ÍÑI•Á½¥¹‘¥¹Í…±°€ô€Àì(€€€½¹ÍÐ±¥ÍÑI•Á½¥¹‘¥¹Ì€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡Á…É…µÌ¤€ôøì(€€€€€€€±¥ÍÑI•Á½¥¹‘¥¹Í…±°€¬ô€Äì(€€€€€€€¥˜€¡½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½¥¹‘¥¹Ì¤ì(€€€€€€€€€É•ÑÕÉ¸½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½¥¹‘¥¹Ì¡Á…É…µÌ°±¥ÍÑI•Á½¥¹‘¥¹Í…±°¤ì(€€€€€€€ô(€€€€€€€€¼¼ÁÁ±äÑ¡”Í•ÉÙ•ÈµÍ¥‘”™¥±Ñ•ÉÌ€¡Í•Ù•É¥Ñä½ÑåÁ”¤Ñ¡”½µÁ½¹•¹ÐÁ…ÍÍ•ÌÍ¼(€€€€€€€€¼¼Ñ•ÍÑÌÑ¡…Ð•á•É¥Í”™¥±Ñ•É¥¹œ½‰Í•ÉÙ”„É•…±¥ÍÑ¥Œ•µÁÑäÉ•ÍÕ±Ð¸(€€€€€€€±•Ð¥Ñ•µÌ€ô½ÁÑ¥½¹Ì¹É•Á½¥¹‘¥¹Ì€üümtì(€€€€€€€¥˜€¡Á…É…µÌü¹Í•Ù•É¥Ñä¤ì(€€€€€€€€€¥Ñ•µÌ€ô¥Ñ•µÌ¹™¥±Ñ•È ¡™¥¹‘¥¹œ¤€ôø™¥¹‘¥¹œ¹Í•Ù•É¥Ñä€ôôôÁ…É…µÌ¹Í•Ù•É¥Ñä¤ì(€€€€€€€ô(€€€€€€€¥˜€¡Á…É…µÌü¹ÑåÁ”¤ì(€€€€€€€€€¥Ñ•µÌ€ô¥Ñ•µÌ¹™¥±Ñ•È ¡™¥¹‘¥¹œ¤€ôø™¥¹‘¥¹œ¹ÑåÁ”€ôôôÁ…É…µÌ¹ÑåÁ”¤ì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌ°ÍÕµµ…Éäè½ÁÑ¥½¹Ì¹É•Á½¥¹‘¥¹MÕµµ…Éäôì(€€€€€ô¤ì(€€€½¹ÍÐÑÉ¥…•¥¹‘¥¹œ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÑÉ¥…•¥¹‘¥¹œœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡™¥¹‘¥¹%°Á…å±½…°Í…¹%¤€ôøì(€€€€€½¹ÍÐ•á¥ÍÑ¥¹œ€ô½ÁÑ¥½¹Ì¹É•Á½¥¹‘¥¹Ìü¹™¥¹ ¡™¥¹‘¥¹œ¤€ôø™¥¹‘¥¹œ¹¥€ôôô™¥¹‘¥¹%¤€üü½ÁÑ¥½¹Ì¹É•Á½¥¹‘¥¹Ìü¹lÁtì(€€€€€É•ÑÕÉ¸ì(€€€€€€€™¥¹‘¥¹œèì(€€€€€€€€€€¸¸¸¡•á¥ÍÑ¥¹œ€üüì(€€€€€€€€€€€¥è™¥¹‘¥¹%°(€€€€€€€€€€€Í…¹}¥èÍ…¹%€üü€É•Á¼µÍ…¸µ‘•™…Õ±Ðœ°(€€€€€€€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€€€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€€€€€€€Ñ¥Ñ±”è€•™…Õ±Ð™¥¹‘¥¹œœ°(€€€€€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€•™…Õ±Ð™¥¹‘¥¹œÍÕµµ…Éä¸œ°(€€€€€€€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”…¹É•µ½Ù”Ñ¡”•áÁ½Í•Í•É•Ð¸œ°(€€€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ(€€€€€€€€€ô¤°(€€€€€€€€€ÑÉ¥…”èì(€€€€€€€€€€€ÍÑ…ÑÕÌèÁ…å±½…¹ÍÑ…ÑÕÌ€üü•á¥ÍÑ¥¹œü¹ÑÉ¥…”ü¹ÍÑ…ÑÕÌ€üü€½Á•¸œ°(€€€€€€€€€€€…ÍÍ¥¹•”èÁ…å±½…¹…ÍÍ¥¹•”€üü•á¥ÍÑ¥¹œü¹ÑÉ¥…”ü¹…ÍÍ¥¹•”°(€€€€€€€€€€€ÍÕÁÁÉ•ÍÍ¥½¹}•áÁ¥É•Í}…ÐèÁ…å±½…¹ÍÕÁÁÉ•ÍÍ¥½¹}•áÁ¥É•Í}…Ð€üü•á¥ÍÑ¥¹œü¹ÑÉ¥…”ü¹ÍÕÁÁÉ•ÍÍ¥½¹}•áÁ¥É•Í}…Ð°(€€€€€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÄÈèÀÁhœ°(€€€€€€€€€€€ÕÁ‘…Ñ•‘}‰äè€Ñ•ÍÐµ½Á•É…Ñ½Èœ(€€€€€€€€€ô(€€€€€€€ô(€€€€€ôì(€€€ô¤ì(€€€½¹ÍÐ‘•±•Ñ•I•Á½¥¹‘¥¹œ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€‘•±•Ñ•I•Á½¥¹‘¥¹œœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡Õ¹‘•™¥¹•¤ì(€€€½¹ÍÐ‘•±•Ñ•I•Á½M…¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€‘•±•Ñ•I•Á½M…¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡Õ¹‘•™¥¹•¤ì(€€€½¹ÍÐ‘•±•Ñ•I•Á½¥¹‘¥¹Ì€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€‘•±•Ñ•I•Á½¥¹‘¥¹Ìœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡¥Ñ•µÌ¤€ôø€¡ì‘•±•Ñ•è¥Ñ•µÌô¤¤ì(€€€½¹ÍÐ•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ìœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡Á…É…µÌ¤€ôøì(€€€€€€€¥˜€¡½ÁÑ¥½¹Ì¹•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì¤ì(€€€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌè½ÁÑ¥½¹Ì¹•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì¡Á…É…µÌ¤¹¥Ñ•µÌôì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmtôì(€€€€€ô¤ì(€€€½¹ÍÐ•ÑI•Á½I¥Í­É…Á €ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡Á…É…µÌ¤€ôøì(€€€€€¥˜€¡½ÁÑ¥½¹Ì¹•ÑI•Á½I¥Í­É…Á ¤ì(€€€€€€€É•ÑÕÉ¸½ÁÑ¥½¹Ì¹•ÑI•Á½I¥Í­É…Á ¡Á…É…µÌ¤ì(€€€€€ô(€€€€€É•ÑÕÉ¸ì(€€€€€€€É•Á½Í¥Ñ½Éäè€É•Á¼µ„œ°(€€€€€€€¹½‘•Ìèmt°(€€€€€€€•‘•Ìèmt°(€€€€€€€Í½É•Ìèmt°(€€€€€€€ÍÕµµ…Éäèì(€€€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°(€€€€€€€€€¹½‘•}½Õ¹Ðè€À°(€€€€€€€€€•‘•}½Õ¹Ðè€À°(€€€€€€€€€Õ¹­¹½Ý¹}¹½‘•}½Õ¹Ðè€À°(€€€€€€€€€Õ¹­¹½Ý¹}•‘•}½Õ¹Ðè€À°(€€€€€€€€€¡¥¡}É¥Í­}™¥¹‘¥¹Ìè€À°(€€€€€€€€€É¥Ñ¥…±}™¥¹‘¥¹Ìè€À(€€€€€€€ô(€€€€€ôì(€€€ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥¹‘¥¹ÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½™¥¹‘¥¹Ìuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½™¥¹‘¥¹Ìˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥¹‘¥¹ÍA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€É•ÑÕÉ¸ì(€€€€€±¥ÍÑI•Á½M…¹Ì°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ì°(€€€€€ÑÉ¥…•¥¹‘¥¹œ°(€€€€€‘•±•Ñ•I•Á½¥¹‘¥¹œ°(€€€€€‘•±•Ñ•I•Á½M…¸°(€€€€€‘•±•Ñ•I•Á½¥¹‘¥¹Ì°(€€€€€•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì°(€€€€€•ÑI•Á½I¥Í­É…Á (€€€ôì(€ô()‘•ÍÉ¥‰” AÉ½‘ÕÑ¥¹‘¥¹ÍA…”ÍÑ…Ñ•Ìœ°€ ¤€ôøì(€…™Ñ•É…   ¤€ôøì(€€€Ý¥¹‘½Ü¹±½…±MÑ½É…”¹±•…È ¤ì(€€€Ù¤¹É•ÍÑ½É•±±5½­Ì ¤ì(€€€Ù¤¹‘½U¹µ½¬ œ¸½¡½½­Ì½ÕÍ•5”œ¤ì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌ„™¥ÉÍÐµÍ…¸½¹‰½…É‘¥¹œÍÑ…Ñ”Ý¡•¸¹¼Í…¹Ì¡…Ù”ÉÕ¸œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹Ìèmtô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ IÕ¸å½ÕÈ™¥ÉÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”é•É¼µ™¥±±•‘…Í¡‰½…É¡É½µ”µÕÍÐ¹½ÐÉ•¹‘•È¥¸Ñ¡”•µÁÑäÍÑ…Ñ”¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½µÁ±•Ñ•Í…¹Ìœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ÍÕÉ™…•Ì„™…¥±ÕÉ”ÍÑ…Ñ”¥¹ÍÑ•…½˜é•É½ÌÝ¡•¸•Ù•ÉäÍ…¸™…¥±•œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÔèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹Ìèm™…¥±•‘M…¹tô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ e½ÕÈ±…ÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸™…¥±•œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½µÁ±•Ñ•Í…¹Ìœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌ„±•…¸€‰¹¼•áÁ½ÍÕÉ”ˆÍÑ…Ñ”Ý¡•¸„Í…¸ÍÕ••‘•Ý¥Ñ é•É¼™¥¹‘¥¹Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍÕ••‘•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÍÕ••‘•œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÔèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹ÌèmÍÕ••‘•‘M…¹tô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 9¼•áÁ½ÍÕÉ”™½Õ¹œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”½¹Í½±¥‘…Ñ•-A$ÍÑÉ¥ÀÉ•¹‘•ÉÌ™½È„ÍÕ••‘•Í…¸¸(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½µÁ±•Ñ•Í…¹Ìœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼]¥Ñ ¹¼™¥¹‘¥¹Ì…¹¹¼…Ñ¥Ù”™¥±Ñ•ÉÌ°Ñ¡”™¥±Ñ•ÈÁ…¹•°…¹Ñ¡”•µÁÑä(€€€€¼¼‘•Ñ…¥°Á…¹”…É”…Ñ•½ÕÐ€¡¹¼É•‘Õ¹‘…¹Ð•µÁÑäÁ±…•¡½±‘•ÉÌ¤¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ¥±Ñ•ÉÌ…¹Í½ÉÑ¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ M•±•Ð„™¥¹‘¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÍ¡½Ü™…¥±•ÍÑ…Ñ”Ý¡•¸„…¹•±•Í…¸¥ÌÑ¡”±…Ñ•ÍÐœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µ±•…äœ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐ…¹•±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ…¹•±•µ±…Ñ•ÍÐœ°(€€€€€ÍÑ…ÑÕÌè€…¹•±•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÔèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€UÍ•È…¹•±•Í…¸™É½´A$œ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹Ìèm…¹•±•‘M…¸°™…¥±•‘M…¹tô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 9¼½µÁ±•Ñ•Í…¸É•ÍÕ±ÑÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ e½ÕÈ±…ÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸™…¥±•œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌ€‰9¼½µÁ±•Ñ•Í…¸É•ÍÕ±ÑÌˆÝ¡¥±”…¸…Ñ¥Ù”Í…¸¥ÌÍÑ¥±°ÉÕ¹¹¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µ¥¸µ™±¥¡Ðœ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÌèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐÅÕ•Õ•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÅÕ•Õ•µ¥¸µ™±¥¡Ðœ°(€€€€€ÍÑ…ÑÕÌè€ÅÕ•Õ•œ°(€€€€€™¥¹¥Í¡•‘}…ÐèÕ¹‘•™¥¹•(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹ÌèmÅÕ•Õ•‘M…¸°™…¥±•‘M…¹tô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 9¼½µÁ±•Ñ•Í…¸É•ÍÕ±ÑÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ 9¼•áÁ½ÍÕÉ”™½Õ¹œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ e½ÕÈ±…ÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸™…¥±•œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ­••ÁÌ™¥¹‘¥¹ÌÙ¥Í¥‰±”Ý¡•¸™…¥±•Í…¹ÌÍÑ¥±°É•ÑÕÉ¸¡¥ÍÑ½É¥…°™¥¹‘¥¹Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µ±…Ñ•ÍÐœ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÄèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐ½±‘MÕ••‘•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÍÕ••‘•µ½±‘•Èœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÌÀèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È(€€€ôì(€€€½¹ÍÐ¡¥ÍÑ½É¥¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ±•…äœ°(€€€€€Í…¹}¥è€É•Á¼µÍ…¸µÍÕ••‘•µ½±‘•Èœ°(€€€€€ÑåÁ”è€Í•É•ÑÌœ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€1•…ä™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€1•…äÉ¥Í­äÍ•É•Ð•áÁ½ÍÕÉ”œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”…¹±•…¸ÕÀÉ•Á½Í¥Ñ½ÉäÍ•É•Ð¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÄÀèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹Ìèm™…¥±•‘M…¸°½±‘MÕ••‘•‘M…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm¡¥ÍÑ½É¥¥¹‘¥¹t(€€€ô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ e½ÕÈ±…ÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸™…¥±•œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½µÁ±•Ñ•Í…¹Ìœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 1•…ä™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ±•ÑÌ½Á•É…Ñ½ÉÌÉ•µ½Ù”„™…¥±•Í…¸‰…¹¹•ÈÝ¥Ñ¡½ÕÐ¡¥‘¥¹œ™¥¹‘¥¹Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µ‘¥Íµ¥ÍÍ¥‰±”œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÄèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐ½±‘MÕ••‘•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ‘¥Íµ¥ÍÍ¥‰±”µÍÕ••‘•œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÌÀèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ‘¥Íµ¥ÍÍ¥‰±”œ°(€€€€€Í…¹}¥è½±‘MÕ••‘•‘M…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€!¥ÍÑ½É¥…°Ý½É­™±½Ü™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ôì((€€€½¹ÍÐì‘•±•Ñ•I•Á½M…¸ô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹Ìèm™…¥±•‘M…¸°½±‘MÕ••‘•‘M…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•µ½Ù”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™…¥±•‘M…¸¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ !¥ÍÑ½É¥…°Ý½É­™±½Ü™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ±•…ÉÌ„Í•±•Ñ•™…¥±•Í…¸™¥±Ñ•È‰•™½É”É•™É•Í¡¥¹œ…™Ñ•ÈÉ•µ½Ù…°œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µÍ•±•Ñ•µ™¥±Ñ•Èœ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÄèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐ½±‘MÕ••‘•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÍ•±•Ñ•µ™¥±Ñ•ÈµÍÕ••‘•œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÌÀèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÍ•±•Ñ•µ™¥±Ñ•Èœ°(€€€€€Í…¹}¥è½±‘MÕ••‘•‘M…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€!¥ÍÑ½É¥…°Í•±•Ñ•µ™¥±Ñ•È™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ôì((€€€½¹ÍÐì‘•±•Ñ•I•Á½M…¸°±¥ÍÑI•Á½¥¹‘¥¹Ì°•ÑI•Á½I¥Í­É…Á ô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹Ìèm™…¥±•‘M…¸°½±‘MÕ••‘•‘M…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€½¹ÍÐÉ•Á½Í¥Ñ½ÉåM…¹¥±Ñ•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸½¤¤…Ì!Q51M•±•Ñ±•µ•¹Ðì(€€€™¥É•Ù•¹Ð¹¡…¹”¡É•Á½Í¥Ñ½ÉåM…¹¥±Ñ•È°ìÑ…É•ÐèìÙ…±Õ”è™…¥±•‘M…¸¹¥ôô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð (€€€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½¬¹…±±Ì¹Í½µ” (€€€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÉ•Á½}Í…¹}¥üèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹É•Á½}Í…¹}¥€ôôô™…¥±•‘M…¸¹¥(€€€€€€€€¤(€€€€€€¤¹Ñ½	”¡ÑÉÕ”¤ì(€€€ô¤ì((€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½­±•…È ¤ì(€€€•ÑI•Á½I¥Í­É…Á ¹µ½­±•…È ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•µ½Ù”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™…¥±•‘M…¸¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€€€•áÁ•Ð ¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸½¤¤…Ì!Q51M•±•Ñ±•µ•¹Ð¤¹Ù…±Õ”¤¹Ñ½	” œœ¤ì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€•áÁ•Ð (€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½¬¹…±±Ì¹Í½µ” (€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÉ•Á½}Í…¹}¥üèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹É•Á½}Í…¹}¥€ôôô™…¥±•‘M…¸¹¥(€€€€€€¤(€€€€¤¹Ñ½	”¡™…±Í”¤ì(€€€•áÁ•Ð (€€€€€•ÑI•Á½I¥Í­É…Á ¹µ½¬¹…±±Ì¹Í½µ” (€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÉ•Á½}Í…¹}¥üèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹É•Á½}Í…¹}¥€ôôô™…¥±•‘M…¸¹¥(€€€€€€¤(€€€€¤¹Ñ½	”¡™…±Í”¤ì(€ô¤ì((€¥Ð ±•…ÉÌ„™…¥±•Í…¸™¥±Ñ•ÈÍ•±•Ñ•Ý¡¥±”É•µ½Ù…°¥Ì¥¸™±¥¡Ðœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µ±¥Ù”µ™¥±Ñ•Èœ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÄèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐ½±‘MÕ••‘•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±¥Ù”µ™¥±Ñ•ÈµÍÕ••‘•œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÌÀèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ±¥Ù”µ™¥±Ñ•Èœ°(€€€€€Í…¹}¥è½±‘MÕ••‘•‘M…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€!¥ÍÑ½É¥…°±¥Ù”µ™¥±Ñ•È™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ôì(€€€½¹ÍÐ‘•±•Ñ•½µÁ±•Ñ¥½¸€ô‘•™•ÉÉ•ñÙ½¥ø ¤ì((€€€½¹ÍÐì‘•±•Ñ•I•Á½M…¸°±¥ÍÑI•Á½¥¹‘¥¹Ì°•ÑI•Á½I¥Í­É…Á ô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹Ìèm™…¥±•‘M…¸°½±‘MÕ••‘•‘M…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t(€€€ô¤ì(€€€‘•±•Ñ•I•Á½M…¸¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø‘•±•Ñ•½µÁ±•Ñ¥½¸¹ÁÉ½µ¥Í”¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•µ½Ù”½¤ô¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™…¥±•‘M…¸¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€ô¤ì((€€€½¹ÍÐÉ•Á½Í¥Ñ½ÉåM…¹¥±Ñ•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸½¤¤…Ì!Q51M•±•Ñ±•µ•¹Ðì(€€€™¥É•Ù•¹Ð¹¡…¹”¡É•Á½Í¥Ñ½ÉåM…¹¥±Ñ•È°ìÑ…É•ÐèìÙ…±Õ”è™…¥±•‘M…¸¹¥ôô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð (€€€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½¬¹…±±Ì¹Í½µ” (€€€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÉ•Á½}Í…¹}¥üèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹É•Á½}Í…¹}¥€ôôô™…¥±•‘M…¸¹¥(€€€€€€€€¤(€€€€€€¤¹Ñ½	”¡ÑÉÕ”¤ì(€€€ô¤ì((€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½­±•…È ¤ì(€€€•ÑI•Á½I¥Í­É…Á ¹µ½­±•…È ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€‘•±•Ñ•½µÁ±•Ñ¥½¸¹É•Í½±Ù” ¤ì(€€€€€…Ý…¥Ð‘•±•Ñ•½µÁ±•Ñ¥½¸¹ÁÉ½µ¥Í”ì(€€€ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð ¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸½¤¤…Ì!Q51M•±•Ñ±•µ•¹Ð¤¹Ù…±Õ”¤¹Ñ½	” œœ¤ì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€•áÁ•Ð (€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½¬¹…±±Ì¹Í½µ” (€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÉ•Á½}Í…¹}¥üèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹É•Á½}Í…¹}¥€ôôô™…¥±•‘M…¸¹¥(€€€€€€¤(€€€€¤¹Ñ½	”¡™…±Í”¤ì(€€€•áÁ•Ð (€€€€€•ÑI•Á½I¥Í­É…Á ¹µ½¬¹…±±Ì¹Í½µ” (€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÉ•Á½}Í…¹}¥üèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹É•Á½}Í…¹}¥€ôôô™…¥±•‘M…¸¹¥(€€€€€€¤(€€€€¤¹Ñ½	”¡™…±Í”¤ì(€ô¤ì((€¥Ð ÕÍ•Ì±¥Ù”™¥¹‘¥¹œ™¥±Ñ•ÉÌÝ¡•¸™…¥±•Í…¸É•µ½Ù…°É•™É•Í¡•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µ±¥Ù”µ™¥¹‘¥¹œµ™¥±Ñ•ÉÌœ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÄèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐ½±‘MÕ••‘•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±¥Ù”µ™¥¹‘¥¹œµ™¥±Ñ•ÈµÍÕ••‘•œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÌÀèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ±¥Ù”µ™¥¹‘¥¹œµ™¥±Ñ•Èœ°(€€€€€Í…¹}¥è½±‘MÕ••‘•‘M…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€!¥ÍÑ½É¥…°±¥Ù”™¥¹‘¥¹œµ™¥±Ñ•È™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ôì(€€€½¹ÍÐ‘•±•Ñ•½µÁ±•Ñ¥½¸€ô‘•™•ÉÉ•ñÙ½¥ø ¤ì((€€€½¹ÍÐì‘•±•Ñ•I•Á½M…¸°±¥ÍÑI•Á½¥¹‘¥¹Ì°•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì°•ÑI•Á½I¥Í­É…Á ô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹Ìèm™…¥±•‘M…¸°½±‘MÕ••‘•‘M…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t(€€€ô¤ì(€€€‘•±•Ñ•I•Á½M…¸¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø‘•±•Ñ•½µÁ±•Ñ¥½¸¹ÁÉ½µ¥Í”¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•µ½Ù”½¤ô¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™…¥±•‘M…¸¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€ô¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½M•Ù•É¥Ñä½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€É¥Ñ¥…°œôô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð (€€€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½¬¹…±±Ì¹Í½µ” (€€€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÍ•Ù•É¥ÑäüèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹Í•Ù•É¥Ñä€ôôô€É¥Ñ¥…°œ(€€€€€€€€¤(€€€€€€¤¹Ñ½	”¡ÑÉÕ”¤ì(€€€ô¤ì((€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½­±•…È ¤ì(€€€•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì¹µ½­±•…È ¤ì(€€€•ÑI•Á½I¥Í­É…Á ¹µ½­±•…È ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€‘•±•Ñ•½µÁ±•Ñ¥½¸¹É•Í½±Ù” ¤ì(€€€€€…Ý…¥Ð‘•±•Ñ•½µÁ±•Ñ¥½¸¹ÁÉ½µ¥Í”ì(€€€ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€€•áÁ•Ð¡±¥ÍÑI•Á½¥¹‘¥¹Ì¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€€€•áÁ•Ð¡•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€€€•áÁ•Ð¡•ÑI•Á½I¥Í­É…Á ¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€ô¤ì(€€€•áÁ•Ð (€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½¬¹…±±Ì¹•Ù•Éä (€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÍ•Ù•É¥ÑäüèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹Í•Ù•É¥Ñä€ôôô€É¥Ñ¥…°œ(€€€€€€¤(€€€€¤¹Ñ½	”¡ÑÉÕ”¤ì(€€€•áÁ•Ð (€€€€€•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì¹µ½¬¹…±±Ì¹•Ù•Éä (€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÍ•Ù•É¥ÑäüèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹Í•Ù•É¥Ñä€ôôô€É¥Ñ¥…°œ(€€€€€€¤(€€€€¤¹Ñ½	”¡ÑÉÕ”¤ì(€€€•áÁ•Ð (€€€€€•ÑI•Á½I¥Í­É…Á ¹µ½¬¹…±±Ì¹•Ù•Éä (€€€€€€€€¡mÁ…É…µÍt¤€ôø€¡Á…É…µÌ…ÌìÍ•Ù•É¥ÑäüèÍÑÉ¥¹œôðÕ¹‘•™¥¹•¤ü¹Í•Ù•É¥Ñä€ôôô€É¥Ñ¥…°œ(€€€€€€¤(€€€€¤¹Ñ½	”¡ÑÉÕ”¤ì(€ô¤ì((€¥Ð ±•ÑÌÙ¥•Ý•ÉÌ‘¥Íµ¥ÍÌ„™…¥±•Í…¸‰…¹¹•ÈÝ¥Ñ¡½ÕÐ‘•±•Ñ¥¹œÑ¡”Í…¸œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µÙ¥•Ý•Èµ‘¥Íµ¥ÍÍ¥‰±”œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÄèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐ½±‘MÕ••‘•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÙ¥•Ý•Èµ‘¥Íµ¥ÍÍ¥‰±”µÍÕ••‘•œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÌÀèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÙ¥•Ý•Èµ‘¥Íµ¥ÍÍ¥‰±”œ°(€€€€€Í…¹}¥è½±‘MÕ••‘•‘M…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€!¥ÍÑ½É¥…°Ù¥•Ý•ÈÝ½É­™±½Ü™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ôì((€€€½¹ÍÐì‘•±•Ñ•I•Á½M…¸ô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹Ìèm™…¥±•‘M…¸°½±‘MÕ••‘•‘M…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t°(€€€€€É½±”è€Ù¥•Ý•Èœ(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y¥Íµ¥ÍÌ½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½M…¸¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ !¥ÍÑ½É¥…°Ù¥•Ý•ÈÝ½É­™±½Ü™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ±•ÑÌ½Á•É…Ñ½ÉÌÉ•µ½Ù”„™…¥±•µ½¹±äÍ…¸ÍÑ…Ñ”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µ½¹±äµ‘¥Íµ¥ÍÍ¥‰±”œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÔèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì((€€€½¹ÍÐì‘•±•Ñ•I•Á½M…¸ô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹Ìèm™…¥±•‘M…¹tô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ e½ÕÈ±…ÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸™…¥±•œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•µ½Ù”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™…¥±•‘M…¸¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ e½ÕÈ±…ÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸™…¥±•œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 9¼½µÁ±•Ñ•Í…¸É•ÍÕ±ÑÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ™…±±Ì‰…¬Ñ¼¡¥‘¥¹œ™…¥±•Í…¸‰…¹¹•ÉÌÝ¡•¸Í…¸É•µ½Ù…°¥Ì¹½Ð‘•Á±½å•å•Ðœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ™…¥±•µÉ•µ½Ù”µÕ¹ÍÕÁÁ½ÉÑ•œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÄèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€I•Á½Í¥Ñ½Éä¹½Ð™½Õ¹½È…•ÍÌÉ•Ù½­•œ(€€€ôì(€€€½¹ÍÐ½±‘MÕ••‘•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÉ•µ½Ù”µÕ¹ÍÕÁÁ½ÉÑ•µÍÕ••‘•œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÌÀèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÉ•µ½Ù”µÕ¹ÍÕÁÁ½ÉÑ•œ°(€€€€€Í…¹}¥è½±‘MÕ••‘•‘M…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€!¥ÍÑ½É¥…°Õ¹ÍÕÁÁ½ÉÑ•É•µ½Ù”™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ôì((€€€½¹ÍÐì‘•±•Ñ•I•Á½M…¸ô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹Ìèm™…¥±•‘M…¸°½±‘MÕ••‘•‘M…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t(€€€ô¤ì(€€€½¹ÍÐìÁ¥ÉÉ½Èô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€‘•±•Ñ•I•Á½M…¸¹µ½­I•©•Ñ•‘Y…±Õ•=¹”¡¹•ÜÁ¥ÉÉ½È I•ÅÕ•ÍÐ™…¥±•€ ÐÀÐ¤œ°€ÐÀÐ¤¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•µ½Ù”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…ÍÐÍ…¸™…¥±•è½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ !¥ÍÑ½É¥…°Õ¹ÍÕÁÁ½ÉÑ•É•µ½Ù”™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÉ•Á½ÉÐ…¹•±±…Ñ¥½¸…Ì„™…¥±•Í…¸œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ…¹•±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ…¹•±•œ°(€€€€€ÍÑ…ÑÕÌè€…¹•±•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀäèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€UÍ•È…¹•±•Í…¸™É½´A$œ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹Ìèm…¹•±•‘M…¹tô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 9¼½µÁ±•Ñ•Í…¸É•ÍÕ±ÑÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ e½ÕÈ±…ÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸™…¥±•œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð É•ÍÑ½É•Ì™½ÕÌÑ¼Ñ¡”ÑÉ¥•É¥¹œÉ½ÜÝ¡•¸Ñ¡”™¥¹‘¥¹œ‘•Ñ…¥°‘¥…±½œ±½Í•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µ™¥¹‘¥¹Ìœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œ´Äœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€…ÝÍ}…•ÍÍ}­•äœ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€%4É½±”Ý¥Ñ Ý¥±‘…ÉÑÉÕÍÐœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€ÍÍÕµ•I½±”ÑÉÕÍÐÁ½±¥ä…±±½ÝÌ…¹äÁÉ¥¹¥Á…°¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€Q¥¡Ñ•¸ÑÉÕÍÐÁ½±¥äÁÉ¥¹¥Á…±Ì¸œ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸½Á½±¥ä¹Ñ˜0Üœ°(€€€€€±¥¹•}Í¹¥ÁÁ•Ðè€ €´Ä€¬Äq¸¬…±±½Ü€ôÑÉÕ•q¸´…±±½Ü€ô™…±Í”œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹ÌèmÍ…¹t°É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹tô¤ì((€€€½¹ÍÐÉ½Ý	ÕÑÑ½¸€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì %4É½±”Ý¥Ñ Ý¥±‘…ÉÑÉÕÍÐœ¤(€€€€¤…Ì!Q51	ÕÑÑ½¹±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ý	ÕÑÑ½¸¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ý	ÕÑÑ½¸¤É•ÑÕÉ¸ì(€€€É½Ý	ÕÑÑ½¸¹™½ÕÌ ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡É½Ý	ÕÑÑ½¸¤ì((€€€½¹ÍÐ…‘‘•‘1¥¹”€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¡|°•±•µ•¹Ð¤€ôø(€€€€€	½½±•…¸¡•±•µ•¹Ðü¹±…ÍÍ1¥ÍÐ¹½¹Ñ…¥¹Ì ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ¤€˜˜•±•µ•¹Ð¹Ñ•áÑ½¹Ñ•¹Ð€ôôô€œ¬…±±½Ü€ôÑÉÕ”œ¤(€€€€¤ì(€€€½¹ÍÐÉ•µ½Ù•‘1¥¹”€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¡|°•±•µ•¹Ð¤€ôø(€€€€€	½½±•…¸¡•±•µ•¹Ðü¹±…ÍÍ1¥ÍÐ¹½¹Ñ…¥¹Ì ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ¤€˜˜•±•µ•¹Ð¹Ñ•áÑ½¹Ñ•¹Ð€ôôô€œ´…±±½Ü€ô™…±Í”œ¤(€€€€¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ Ù¥‘•¹”±¥¹”œ¤¤¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±…‰•°œ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ  €´Ä€¬Ä œ¤¤¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ¤ì(€€€•áÁ•Ð¡…‘‘•‘1¥¹”¤¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ°€¥Ìµ…‘œ¤ì(€€€•áÁ•Ð¡É•µ½Ù•‘1¥¹”¤¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ°€¥ÌµÉ•µ½Ù”œ¤ì(€€€•áÁ•Ð¡…‘‘•‘1¥¹”¤¹¹½Ð¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±…‰•°œ¤ì(€€€•áÁ•Ð¡É•µ½Ù•‘1¥¹”¤¹¹½Ð¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±…‰•°œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡…‘‘•‘1¥¹”¤¹•Ñ	åQ•áÐ œ¬œ¤¤¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µµ…É­•Èœ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•µ½Ù•‘1¥¹”¤¹•Ñ	åQ•áÐ œ´œ¤¤¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µµ…É­•Èœ¤ì((€€€½¹ÍÐ±½Í•	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½±½Í”™¥¹‘¥¹œ‘•Ñ…¥°½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡±½Í•	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½±½Í”™¥¹‘¥¹œ‘•Ñ…¥°½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘½Õµ•¹Ð¹…Ñ¥Ù•±•µ•¹Ð¤¹Ñ½	”¡É½Ý	ÕÑÑ½¸¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ‘•±•Ñ•ÌÉ•Á½Í¥Ñ½Éä™¥¹‘¥¹Ì™É½´Ñ¡”É½Ü½Ù•É™±½Üµ•¹Ôœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µ…Ñ¥½¹…‰±”µ™¥¹‘¥¹œœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ…Ñ¥½¸´Äœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸Ý½É­™±½Ü¡¥ÍÑ½Éäœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸¼¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½‘•Á±½ä¹åµ°0ÄÈœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹œô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôøì(€€€€€€€¥˜€¡…±°€ôôô€Ä¤ì(€€€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm™¥¹‘¥¹tôì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmtôì(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÉ½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸Ý½É­™±½Ü¡¥ÍÑ½Éäœ¤(€€€€¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ü¤É•ÑÕÉ¸ì((€€€½¹ÍÐ…Ñ¥½¹	ÕÑÑ½¸€ôÝ¥Ñ¡¥¸¡É½Ü¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½ÈA½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡…Ñ¥½¹	ÕÑÑ½¸¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åQ•áÐ ½I•µ½Ù”½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ¡•…‘¥¹œœ°ì¹…µ”è€¥¹‘¥¹œ…Ñ¥½¹Ìœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€½¹ÍÐ½¹™¥Éµ…¹•±	ÕÑÑ½¸€ôÝ¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½…¹•°½¤ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘½Õµ•¹Ð¹…Ñ¥Ù•±•µ•¹Ð¤¹Ñ½	”¡½¹™¥Éµ…¹•±	ÕÑÑ½¸¤ì(€€€ô¤ì((€€€™¥É•Ù•¹Ð¹­•å½Ý¸¡‘½Õµ•¹Ð¹…Ñ¥Ù•±•µ•¹Ð„°ì­•äè€Í…Á”œô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘½Õµ•¹Ð¹…Ñ¥Ù•±•µ•¹Ð¤¹Ñ½	”¡…Ñ¥½¹	ÕÑÑ½¸¤ì(€€€ô¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½ÈA½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•½¤ô¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€½¹ÍÐÉ•½Á•¹½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤ì(€€€•áÁ•Ð¡É•½Á•¹½¹™¥Éµ¥…±½œ¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡É•½Á•¹½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹œ¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™¥¹‘¥¹œ¹¥°(€€€€€€€Í…¸¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸Ý½É­™±½Ü¡¥ÍÑ½Éäœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð É•™É•Í¡•ÌÑÉ•¹…¹É¥Í¬É…Á¡Ì…™Ñ•È‘•±•Ñ¥¹œ„™¥¹‘¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µ…Ñ¥½¹…‰±”µ™¥¹‘¥¹œµÉ•™É•Í œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÉ•™É•Í ´Äœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸ÍÑ…±”ÑÉ•¹‘…Ñ„œ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„ÍÑ…±”Ý½É­™±½Ü™¥±”¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”ÍÑ…±”•Ù¥‘•¹”¸œ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸¼¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½ÍÑ…±”¹åµ°0ÄÈœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹œ°•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì°•ÑI•Á½I¥Í­É…Á ô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t°(€€€€€•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ìè€ ¤€ôø€¡ì(€€€€€€€¥Ñ•µÌèl(€€€€€€€€€ì(€€€€€€€€€€€Í…¹}¥è€É•Á¼µÍ…¸µÝ¥Ñ µ…Ñ¥½¹…‰±”µ™¥¹‘¥¹œµÉ•™É•Í œ°(€€€€€€€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€€€€€€€Ñ½Ñ…°è€Ä°(€€€€€€€€€€€‰å}Í•Ù•É¥Ñäèì(€€€€€€€€€€€€€É¥Ñ¥…°è€À°(€€€€€€€€€€€€€¡¥ è€Ä°(€€€€€€€€€€€€€µ•‘¥Õ´è€À°(€€€€€€€€€€€€€±½Üè€À(€€€€€€€€€€€ô(€€€€€€€€€ô(€€€€€€€t(€€€€€ô¤°(€€€€€•ÑI•Á½I¥Í­É…Á è€ ¤€ôø€¡ì(€€€€€€€É•Á½Í¥Ñ½Éäè€É•Á¼µ„œ°(€€€€€€€¹½‘•Ìèmt°(€€€€€€€•‘•Ìèmt°(€€€€€€€Í½É•Ìèmt°(€€€€€€€ÍÕµµ…Éäèì(€€€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä°(€€€€€€€€€¹½‘•}½Õ¹Ðè€À°(€€€€€€€€€•‘•}½Õ¹Ðè€À°(€€€€€€€€€Õ¹­¹½Ý¹}¹½‘•}½Õ¹Ðè€À°(€€€€€€€€€Õ¹­¹½Ý¹}•‘•}½Õ¹Ðè€À°(€€€€€€€€€¡¥¡}É¥Í­}™¥¹‘¥¹Ìè€À°(€€€€€€€€€É¥Ñ¥…±}™¥¹‘¥¹Ìè€À(€€€€€€€ô(€€€€€ô¤(€€€ô¤ì((€€€½¹ÍÐÉ½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸ÍÑ…±”ÑÉ•¹‘…Ñ„œ¤(€€€€¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ü¤É•ÑÕÉ¸ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€€€•áÁ•Ð¡•ÑI•Á½I¥Í­É…Á ¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€ô¤ì(€€€½¹ÍÐ¥¹¥Ñ¥…±QÉ•¹‘…±±Ì€ô•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì¹µ½¬¹…±±Ì¹±•¹Ñ ì(€€€½¹ÍÐ¥¹¥Ñ¥…±I¥Í­…±±Ì€ô•ÑI•Á½I¥Í­É…Á ¹µ½¬¹…±±Ì¹±•¹Ñ ì(€€€•áÁ•Ð¡¥¹¥Ñ¥…±QÉ•¹‘…±±Ì¤¹Ñ½	•É•…Ñ•ÉQ¡…¹=ÉÅÕ…° Ä¤ì(€€€•áÁ•Ð¡¥¹¥Ñ¥…±I¥Í­…±±Ì¤¹Ñ½	•É•…Ñ•ÉQ¡…¹=ÉÅÕ…° Ä¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡É½Ü¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½ÈA½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•½¤ô¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹œ¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™¥¹‘¥¹œ¹¥°(€€€€€€€Í…¸¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡•ÑI•Á½¥¹‘¥¹ÍQÉ•¹‘Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì¡¥¹¥Ñ¥…±QÉ•¹‘…±±Ì€¬€Ä¤ì(€€€€€•áÁ•Ð¡•ÑI•Á½I¥Í­É…Á ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì¡¥¹¥Ñ¥…±I¥Í­…±±Ì€¬€Ä¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ¡¥‘•ÌÑ¡”É¥Í¬É…Á Ý¡•¸Õ¹ÍÕÁÁ½ÉÑ•™¥¹‘¥¹œ™¥±Ñ•ÉÌ…É”…Ñ¥Ù”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÉ¥Í¬µÉ…Á µÍ½ÕÉ”µ™¥±Ñ•Èœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÉ¥Í¬µÉ…Á µÍ½ÕÉ”µ™¥±Ñ•Èœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€M½ÕÉ”µ™¥±Ñ•É•Ý½É­™±½ÜÁ•Éµ¥ÍÍ¥½¸œ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€…‘…ÁÑ•É}Í½ÕÉ”è€¥Ñ¡Õ‰}½‘•}Í…¹¹¥¹œœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t°(€€€€€•ÑI•Á½I¥Í­É…Á è€ ¤€ôø€¡ì(€€€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€€€¹½‘•Ìèl(€€€€€€€€€ì(€€€€€€€€€€€¥è€¹½‘”´Äœ°(€€€€€€€€€€€­¥¹è€™¥¹‘¥¹œœ°(€€€€€€€€€€€±…‰•°è€¥¹‘¥¹œœ°(€€€€€€€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€€€€€€€•Ù¥‘•¹•}ÍÑ…Ñ”è€­¹½Ý¸œ(€€€€€€€€€ô(€€€€€€€t°(€€€€€€€•‘•Ìèmt°(€€€€€€€Í½É•Ìèl(€€€€€€€€€ì(€€€€€€€€€€€™¥¹‘¥¹}¥è™¥¹‘¥¹œ¹¥°(€€€€€€€€€€€™¥¹‘¥¹}¹½‘•}¥è€¹½‘”´Äœ°(€€€€€€€€€€€Í½É”è€äÈ°(€€€€€€€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€€€€€€€½¹™¥‘•¹”è€À¸äÈ°(€€€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€€€Í•Ù•É¥Ñäè€àÀ°(€€€€€€€€€€€€€½¹™¥‘•¹”è€äÈ°(€€€€€€€€€€€€€•áÁ±½¥Ñ…‰¥±¥Ñäè€àÀ°(€€€€€€€€€€€€€ÁÉ¥Ù¥±•”è€ÜÀ°(€€€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÜÀ°(€€€€€€€€€€€€€•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€ØÀ°(€€€€€€€€€€€€€™É•Í¡¹•ÍÌè€äÀ°(€€€€€€€€€€€€€Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€À(€€€€€€€€€€€ô°(€€€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€€€ô(€€€€€€€t°(€€€€€€€ÍÕµµ…Éäèì(€€€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä°(€€€€€€€€€¹½‘•}½Õ¹Ðè€Ä°(€€€€€€€€€•‘•}½Õ¹Ðè€À°(€€€€€€€€€Õ¹­¹½Ý¹}¹½‘•}½Õ¹Ðè€À°(€€€€€€€€€Õ¹­¹½Ý¹}•‘•}½Õ¹Ðè€À°(€€€€€€€€€¡¥¡}É¥Í­}™¥¹‘¥¹Ìè€Ä°(€€€€€€€€€É¥Ñ¥…±}™¥¹‘¥¹Ìè€À(€€€€€€€ô(€€€€€ô¤(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ œÄ¹½‘•Ìƒ
Ü€ÀÁ…Ñ¡Ìƒ
Ü¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	åA±…•¡½±‘•ÉQ•áÐ M½ÕÉ”¹…µ”œ¤°ìÑ…É•ÐèìÙ…±Õ”è€¥Ñ¡Õ‰}½‘•}Í…¹¹¥¹œœôô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ !¥‘‘•¸™½ÈÕÉÉ•¹Ð™¥±Ñ•ÉÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ±•…ÈÍ½ÕÉ”°…ÍÍ¥¹•”°½È±¥™•å±”™¥±Ñ•ÉÌÑ¼Ù¥•ÜÑ¡”É…Á ¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ !¥ µÉ¥Í¬™¥¹‘¥¹Ìœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ¥¹½É•ÌÍÑ…±”™¥¹‘¥¹œ‘•±•Ñ”½µÁ±•Ñ¥½¹Ì…™Ñ•ÈÉ•™É•Í¡¥¹œÑ¡”™¥¹‘¥¹Ì±¥ÍÐœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µ…Ñ¥½¹…‰±”µ™¥¹‘¥¹œœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ…Ñ¥½¸´Èœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸É•±•…Í”…ÉÑ¥™…ÑÌœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸É•±•…Í”µ•Ñ…‘…Ñ„¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”•áÁ½Í•Ù…±Õ”¸œ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸¼¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½É•±•…Í”¹åµ°0ÈÈœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì(€€€½¹ÍÐ‘•±•Ñ•½µÁ±•Ñ¥½¸€ô‘•™•ÉÉ•ñÙ½¥ø ¤ì((€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹œô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹ÌèmÍ…¹t°É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹tô¤ì(€€€‘•±•Ñ•I•Á½¥¹‘¥¹œ¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø‘•±•Ñ•½µÁ±•Ñ¥½¸¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐÉ½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸É•±•…Í”…ÉÑ¥™…ÑÌœ¤(€€€€¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ü¤É•ÑÕÉ¸ì((€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡É½Ü¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½ÈA½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸É•±•…Í”…ÉÑ¥™…ÑÌ½¤ô¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åQ•áÐ ½I•µ½Ù”½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•™É•Í ½¤ô¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹œ¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™¥¹‘¥¹œ¹¥°(€€€€€€€Í…¸¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€ô¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€‘•±•Ñ•½µÁ±•Ñ¥½¸¹É•Í½±Ù” ¤ì(€€€ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸É•±•…Í”…ÉÑ¥™…ÑÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð É•½¹¥±•Ì…±°µÍ…¸‘•‘ÕÁ•É½ÝÌ…™Ñ•È‘•±•Ñ¥¹œ„™¥¹‘¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µ…Ñ¥½¹…‰±”µ™¥¹‘¥¹œœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È(€€€ôì((€€€½¹ÍÐ‘•±•Ñ•‘¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ…Ñ¥½¸´Äœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸Ý½É­™±½Ü¡¥ÍÑ½Éäœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸¼¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½‘•Á±½ä¹åµ°0ÄÈœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€½¹ÍÐÁÉ½µ½Ñ•‘¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ…Ñ¥½¸µÁÉ½µ½Ñ•œ°(€€€€€Í…¹}¥è€É•Á¼µÍ…¸µ½±‘•Èµ•Ù¥‘•¹”œ°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€AÉ½µ½Ñ•Ñ½­•¸•áÁ½ÍÕÉ”™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸…¸½±‘•ÈÍ…¸±¥™•å±”É•ÍÕ±Ð¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸¼¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½‘•Á±½ä¹åµ°0ÄÌœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÀÀèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôøì(€€€€€€€¥˜€¡…±°€ôôô€Ä¤ì(€€€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm‘•±•Ñ•‘¥¹‘¥¹tôì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmÁÉ½µ½Ñ•‘¥¹‘¥¹tôì(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÉ½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸Ý½É­™±½Ü¡¥ÍÑ½Éäœ¤(€€€€¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ü¤É•ÑÕÉ¸ì((€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡É½Ü¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½ÈA½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•½¤ô¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ A½Ñ•¹Ñ¥…°Ñ½­•¸•áÁ½Í•¥¸Ý½É­™±½Ü¡¥ÍÑ½Éäœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ AÉ½µ½Ñ•Ñ½­•¸•áÁ½ÍÕÉ”™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ÁÉ•Í•ÉÙ•ÌÍ•ÉÙ•È™¥¹‘¥¹œÍÕµµ…ÉäÑ½Ñ…±Ì…™Ñ•È‘•±•Ñ¥¹œ„Á…¥¹…Ñ•É½Üœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µµ…¹äµ™¥¹‘¥¹Ìœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€ÈÌÀ(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÙ¥Í¥‰±”µÁ…”´Äœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€‘•Ñ•Ñ½Èè€¥Ñ¡Õ‰}Í•É•Ñ}Í…¹¹¥¹œœ°(€€€€€Ñ¥Ñ±”è€Y¥Í¥‰±”Á…¥¹…Ñ•Ñ½­•¸™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€½Ý¹•Èè€Á±…Ñ™½É´œ°(€€€€€™¥ÉÍÑ}Í••¹}…Ðè€œÈÀÈØ´ÀÔ´ÀÅPÄÄèÀØèÀÁhœ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÀÅPÄÄèÀØèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôøì(€€€€€€€¥˜€¡…±°€ôôô€Ä¤ì(€€€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm™¥¹‘¥¹t°ÍÕµµ…Éäèì(€€€€€€€€€€€Ñ½Ñ…±}½Á•¸è€ÈÌÀ°(€€€€€€€€€€€™¥á•‘}½Õ¹Ðè€Ð°(€€€€€€€€€€€É•½Á•¹•‘}½Õ¹Ðè€Ì°(€€€€€€€€€€€ÍÕÁÁÉ•ÍÍ•‘}½Õ¹Ðè€È°(€€€€€€€€€€€Í±…}…•‘}½Õ¹Ðè€à°(€€€€€€€€€€€µÑÑÉ}É•…‘å}É•Í½±Ù•‘}½Õ¹Ðè€Ð°(€€€€€€€€€€€µ•…¹}Ñ¥µ•}Ñ½}É•Í½±Ù•}Í•½¹‘Ìè€ØÀ€¨€ØÀ€¨€ÈÐ°(€€€€€€€€€€€½±‘•ÍÑ}½Á•¹}™¥ÉÍÑ}Í••¹}…Ðè€œÈÀÈØ´ÀÔ´ÀÅPÄÄèÀØèÀÁhœ°(€€€€€€€€€€€‰å}½Ý¹•ÈèìÁ±…Ñ™½É´è€ÄÈô°(€€€€€€€€€€€‰å}‘•Ñ•Ñ½Èèì¥Ñ¡Õ‰}Í•É•Ñ}Í…¹¹¥¹œè€ÄÜô°(€€€€€€€€€€€‰å}Í•Ù•É¥ÑäèìÉ¥Ñ¥…°è€ÄÄô(€€€€€€€€€õôì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmt°ÍÕµµ…Éäèì(€€€€€€€€€Ñ½Ñ…±}½Á•¸è€ÈÈä°(€€€€€€€€€™¥á•‘}½Õ¹Ðè€Ì°(€€€€€€€€€É•½Á•¹•‘}½Õ¹Ðè€Ì°(€€€€€€€€€ÍÕÁÁÉ•ÍÍ•‘}½Õ¹Ðè€È°(€€€€€€€€€Í±…}…•‘}½Õ¹Ðè€à°(€€€€€€€€€µÑÑÉ}É•…‘å}É•Í½±Ù•‘}½Õ¹Ðè€Ð°(€€€€€€€€€µ•…¹}Ñ¥µ•}Ñ½}É•Í½±Ù•}Í•½¹‘Ìè€ØÀ€¨€ØÀ€¨€ÈÐ°(€€€€€€€€€½±‘•ÍÑ}½Á•¹}™¥ÉÍÑ}Í••¹}…Ðè€œÈÀÈØ´ÀÔ´ÀÅPÄÄèÀØèÀÁhœ°(€€€€€€€€€‰å}½Ý¹•ÈèìÁ±…Ñ™½É´è€ÄÄô°(€€€€€€€€€‰å}‘•Ñ•Ñ½Èèì¥Ñ¡Õ‰}Í•É•Ñ}Í…¹¹¥¹œè€ÄØô°(€€€€€€€€€‰å}Í•Ù•É¥ÑäèìÉ¥Ñ¥…°è€ÄÀô(€€€€€€€õôì(€€€€€ô°(€€€€€É•Á½¥¹‘¥¹MÕµµ…Éäèì(€€€€€€€Ñ½Ñ…±}½Á•¸è€ÈÌÀ°(€€€€€€€™¥á•‘}½Õ¹Ðè€Ð°(€€€€€€€É•½Á•¹•‘}½Õ¹Ðè€Ì°(€€€€€€€ÍÕÁÁÉ•ÍÍ•‘}½Õ¹Ðè€È°(€€€€€€€Í±…}…•‘}½Õ¹Ðè€à°(€€€€€€€µÑÑÉ}É•…‘å}É•Í½±Ù•‘}½Õ¹Ðè€Ð°(€€€€€€€µ•…¹}Ñ¥µ•}Ñ½}É•Í½±Ù•}Í•½¹‘Ìè€ØÀ€¨€ØÀ€¨€ÈÐ°(€€€€€€€½±‘•ÍÑ}½Á•¹}™¥ÉÍÑ}Í••¹}…Ðè€œÈÀÈØ´ÀÔ´ÀÅPÄÄèÀØèÀÁhœ°(€€€€€€€‰å}½Ý¹•ÈèìÁ±…Ñ™½É´è€ÄÈô°(€€€€€€€‰å}‘•Ñ•Ñ½Èèì¥Ñ¡Õ‰}Í•É•Ñ}Í…¹¹¥¹œè€ÄÜô°(€€€€€€€‰å}Í•Ù•É¥ÑäèìÉ¥Ñ¥…°è€ÄÄô(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÍÕµµ…Éä€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	å1…‰•±Q•áÐ I•Á½Í¥Ñ½Éä™¥¹‘¥¹œÍÕµµ…Éäœ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹±…ÍÍ1¥ÍÐ¹½¹Ñ…¥¹Ì ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµÍÑ…ÑÌœ¤(€€€€¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡ÍÕµµ…Éä¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …ÍÕµµ…Éä¤É•ÑÕÉ¸ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åQ•áÐ œÈÌÀœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€½¹ÍÐÉ½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì Y¥Í¥‰±”Á…¥¹…Ñ•Ñ½­•¸™¥¹‘¥¹œœ¤(€€€€¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ü¤É•ÑÕÉ¸ì((€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡É½Ü¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½ÈY¥Í¥‰±”Á…¥¹…Ñ•Ñ½­•¸™¥¹‘¥¹œ½¤ô¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ Y¥Í¥‰±”Á…¥¹…Ñ•Ñ½­•¸™¥¹‘¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åQ•áÐ œÈÈäœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ±•…ÉÌ…±°Ù¥Í¥‰±”É•Á½Í¥Ñ½Éä™¥¹‘¥¹Ì…¹ÕÁ‘…Ñ•Ì±½…‘•½Õ¹ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±•…Èµ…±°µ™¥¹‘¥¹Ìœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹Ìè¥¹‘¥¹mt€ôl(€€€€€ì(€€€€€€€¥è€™¥¹‘¥¹œµ±•…Èµ…±°´Äœ°(€€€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€€€Ñ¥Ñ±”è€¥ÉÍÐ±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ°(€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€€€ô°(€€€€€ì(€€€€€€€¥è€™¥¹‘¥¹œµ±•…Èµ…±°´Èœ°(€€€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€€€Ñ¥Ñ±”è€M•½¹±•…É…‰±”Ý½É­™±½Ü™¥¹‘¥¹œœ°(€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€€€ô(€€€tì((€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹œ°‘•±•Ñ•I•Á½¥¹‘¥¹Ìô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôø€¡ì¥Ñ•µÌè…±°€ôôô€Ä€ü™¥¹‘¥¹Ì€èmtô¤(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¥ÉÍÐ±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ M•½¹±•…É…‰±”Ý½É­™±½Ü™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y±•…È…±°½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½±•…È™¥¹‘¥¹Ì½¤ô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åQ•áÐ ¼ÈÙ¥Í¥‰±”™¥¹‘¥¹Ì½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”…±°½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€l(€€€€€€€€€ì™¥¹‘¥¹}¥è™¥¹‘¥¹ÍlÁt¹¥°É•Á½}Í…¹}¥èÍ…¸¹¥ô°(€€€€€€€€€ì™¥¹‘¥¹}¥è™¥¹‘¥¹ÍlÅt¹¥°É•Á½}Í…¹}¥èÍ…¸¹¥ô(€€€€€€€t°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤ì(€€€ô¤ì(€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹œ¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ¥ÉÍÐ±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ M•½¹±•…É…‰±”Ý½É­™±½Ü™¥¹‘¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 9¼•áÁ½ÍÕÉ”™½Õ¹œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÉ•Á½ÉÐ±•…È…±°ÍÕ•ÍÌÝ¡•¸Ñ¡”‰Õ±¬•¹‘Á½¥¹Ð¥Ì¹½Ð‘•Á±½å•å•Ðœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±•…Èµ…±°µ‰Õ±¬µµ¥ÍÍ¥¹œœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹Ìè¥¹‘¥¹mt€ôl(€€€€€ì(€€€€€€€¥è€™¥¹‘¥¹œµ±•…Èµ™…±±‰…¬µ™¥ÉÍÐœ°(€€€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€€€Ñ¥Ñ±”è€…±±‰…¬±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ°(€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€€€ô°(€€€€€ì(€€€€€€€¥è€™¥¹‘¥¹œµ±•…Èµ™…±±‰…¬µÍ•½¹œ°(€€€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€€€Ñ¥Ñ±”è€…±±‰…¬±•…É…‰±”Ý½É­™±½Ü™¥¹‘¥¹œœ°(€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€€€ô(€€€tì((€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹œ°‘•±•Ñ•I•Á½¥¹‘¥¹Ìô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôø€¡ì¥Ñ•µÌè…±°€ôôô€Ä€ü™¥¹‘¥¹Ì€èm™¥¹‘¥¹ÍlÅutô¤(€€€ô¤ì(€€€½¹ÍÐìÁ¥ÉÉ½Èô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€‘•±•Ñ•I•Á½¥¹‘¥¹Ì¹µ½­I•©•Ñ•‘Y…±Õ•=¹”¡¹•ÜÁ¥ÉÉ½È I•ÅÕ•ÍÐ™…¥±•€ ÐÀÐ¤œ°€ÐÀÐ¤¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ …±±‰…¬±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ …±±‰…¬±•…É…‰±”Ý½É­™±½Ü™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y±•…È…±°½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½±•…È™¥¹‘¥¹Ì½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”…±°½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹œ¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½±•…È…±°É•ÅÕ¥É•ÌÑ¡”‰Õ±¬‘•±•Ñ”A$½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ …±±‰…¬±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ …±±‰…¬±•…É…‰±”Ý½É­™±½Ü™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ 9¼•áÁ½ÍÕÉ”™½Õ¹œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åQ•áÐ ¼ÈÙ¥Í¥‰±”™¥¹‘¥¹Ì½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð É•±½…‘ÌÉ•Á½Í¥Ñ½Éä™¥¹‘¥¹Ì…™Ñ•È±•…É¥¹œ„Á…•±¥ÍÐœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±•…Èµ…±°µÁ…•œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È(€€€ôì(€€€½¹ÍÐ™¥ÉÍÑA…•¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ±•…ÈµÁ…•µ™¥ÉÍÐœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€¥ÉÍÐÁ…”±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì(€€€½¹ÍÐ¹•áÑA…•¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ±•…ÈµÁ…•µ¹•áÐœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è€9•áÐÁ…”Ý½É­™±½Ü™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ôì((€€€½¹ÍÐì±¥ÍÑI•Á½¥¹‘¥¹Ìô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôø€¡ì¥Ñ•µÌè…±°€ôôô€Ä€üm™¥ÉÍÑA…•¥¹‘¥¹t€èm¹•áÑA…•¥¹‘¥¹tô¤(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¥ÉÍÐÁ…”±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y±•…È…±°½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½±•…È™¥¹‘¥¹Ì½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”…±°½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡±¥ÍÑI•Á½¥¹‘¥¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤ì(€€€ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ¥ÉÍÐÁ…”±•…É…‰±”Ñ½­•¸™¥¹‘¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 9•áÐÁ…”Ý½É­™±½Ü™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ¡Õ¹­Ì±•…È…±°Ñ…É•ÑÌ…ÐÑ¡”É•Á½Í¥Ñ½Éä™¥¹‘¥¹œ‰Õ±¬±¥µ¥Ðœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐì¡Õ¹­I•Á½¥¹‘¥¹•±•Ñ•Q…É•ÑÌ°IA=}%9%9}	U1-}1Q}	Q!}M%iô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐÑ…É•ÑÌ€ôÉÉ…ä¹™É½´¡ì±•¹Ñ èIA=}%9%9}	U1-}1Q}	Q!}M%i€¬€Äô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€™¥¹‘¥¹}¥è™¥¹‘¥¹œµ‰Õ±¬µ±¥µ¥Ð´‘í¥¹‘•áõ€°(€€€€€É•Á½}Í…¹}¥è€É•Á¼µÍ…¸µ‰Õ±¬µ±¥µ¥Ðœ(€€€ô¤¤ì((€€€½¹ÍÐ‰…Ñ¡•Ì€ô¡Õ¹­I•Á½¥¹‘¥¹•±•Ñ•Q…É•ÑÌ¡Ñ…É•ÑÌ¤ì((€€€•áÁ•Ð¡‰…Ñ¡•Ì¤¹Ñ½!…Ù•1•¹Ñ  È¤ì(€€€•áÁ•Ð¡‰…Ñ¡•ÍlÁt¤¹Ñ½!…Ù•1•¹Ñ ¡IA=}%9%9}	U1-}1Q}	Q!}M%i¤ì(€€€•áÁ•Ð¡‰…Ñ¡•ÍlÅt¤¹Ñ½ÅÕ…°¡mì™¥¹‘¥¹}¥è€™¥¹‘¥¹œµ‰Õ±¬µ±¥µ¥Ð´ÔÀÀÀœ°É•Á½}Í…¹}¥è€É•Á¼µÍ…¸µ‰Õ±¬µ±¥µ¥Ðœõt¤ì(€ô¤ì((€¥Ð ÁÉ•Í•ÉÙ•Ì½µÁ±•Ñ•±•…È…±°‰…Ñ¡•ÌÝ¡•¸„±…Ñ•È‰…Ñ É•ÅÕ•ÍÐ™…¥±Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹Q…É•ÑÍ%¹	…Ñ¡•Ìô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐÑ…É•ÑÌ€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€Ìô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€™¥¹‘¥¹}¥è™¥¹‘¥¹œµ‰Õ±¬µÁ…ÉÑ¥…°´‘í¥¹‘•áõ€°(€€€€€É•Á½}Í…¹}¥è€É•Á¼µÍ…¸µ‰Õ±¬µÁ…ÉÑ¥…°œ(€€€ô¤¤ì(€€€½¹ÍÐ‘•±•Ñ•Q…É•ÑÌ€ôÙ¤(€€€€€€¹™¸ ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì‘•±•Ñ•èÑ…É•ÑÌ¹Í±¥” À°€È¤ô¤(€€€€€€¹µ½­I•©•Ñ•‘Y…±Õ•=¹”¡¹•ÜÉÉ½È É…Ñ”±¥µ¥Ð•á••‘•œ¤¤ì((€€€½¹ÍÐÉ•ÍÕ±Ð€ô…Ý…¥Ð‘•±•Ñ•I•Á½¥¹‘¥¹Q…É•ÑÍ%¹	…Ñ¡•Ì¡Ñ…É•ÑÌ°‘•±•Ñ•Q…É•ÑÌ°€È¤ì((€€€•áÁ•Ð¡‘•±•Ñ•Q…É•ÑÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤ì(€€€•áÁ•Ð¡É•ÍÕ±Ð¹É•ÍÁ½¹Í”¹‘•±•Ñ•¤¹Ñ½ÅÕ…°¡Ñ…É•ÑÌ¹Í±¥” À°€È¤¤ì(€€€•áÁ•Ð¡É•ÍÕ±Ð¹É•ÍÁ½¹Í”¹™…¥±•¤¹Ñ½ÅÕ…°¡mt¤ì(€€€•áÁ•Ð¡É•ÍÕ±Ð¹•ÉÉ½É5•ÍÍ…”¤¹Ñ½	” É…Ñ”±¥µ¥Ð•á••‘•œ¤ì(€ô¤ì((€¥Ð Í•¹‘Ì±…É”±•…È…±°É•ÅÕ•ÍÑÌ‰•±½ÜÑ¡”Í•ÉÙ•È±¥µ¥Ð…Ì½¹”É•Á½Í¥Ñ½Éä™¥¹‘¥¹œ‰Õ±¬½Á•É…Ñ¥½¸œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±•…Èµ…±°µ±…É”œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€ÄÀÄ(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹Ìè¥¹‘¥¹mt€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€ÄÀÄô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€¥è™¥¹‘¥¹œµ±•…Èµ…±°µ±…É”´‘í¥¹‘•áõ€°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è1…É”±•…È…±°™¥¹‘¥¹œ€‘í¥¹‘•áõ€°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ô¤¤ì((€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹Ìô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôø€¡ì¥Ñ•µÌè…±°€ôôô€Ä€ü™¥¹‘¥¹Ì€èm™¥¹‘¥¹ÍlÄÀÁutô¤(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 1…É”±•…È…±°™¥¹‘¥¹œ€Àœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y±•…È…±°½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½±•…È™¥¹‘¥¹Ì½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”…±°½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€€€ô¤ì(€€€½¹ÍÐÑ…É•ÑÌ€ô‘•±•Ñ•I•Á½¥¹‘¥¹Ì¹µ½¬¹…±±ÍlÁtü¹lÁt€üümtì(€€€•áÁ•Ð¡Ñ…É•ÑÌ¤¹Ñ½!…Ù•1•¹Ñ  ÄÀÄ¤ì(€€€•áÁ•Ð¡Ñ…É•ÑÍlÁt¤¹Ñ½ÅÕ…°¡ì™¥¹‘¥¹}¥è™¥¹‘¥¹ÍlÁt¹¥°É•Á½}Í…¹}¥èÍ…¸¹¥ô¤ì(€€€•áÁ•Ð¡Ñ…É•ÑÍlÄÀÁt¤¹Ñ½ÅÕ…°¡ì™¥¹‘¥¹}¥è™¥¹‘¥¹ÍlÄÀÁt¹¥°É•Á½}Í…¹}¥èÍ…¸¹¥ô¤ì(€ô¤ì((€¥Ð ÁÉ•Í•ÉÙ•Ì½µÁ±•Ñ•±•…È…±°‘•±•Ñ•ÌÝ¡•¸Ñ¡”‰Õ±¬É•ÍÁ½¹Í”¥ÌÁ…ÉÑ¥…°œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±•…Èµ…±°µ‰…Ñ µ™…¥±ÕÉ”œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ì(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹Ìè¥¹‘¥¹mt€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€Ìô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€¥è™¥¹‘¥¹œµ±•…Èµ…±°µ‰…Ñ µ™…¥±ÕÉ”´‘í¥¹‘•áõ€°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€Ñ¥Ñ±”è	…Ñ ™…¥±ÕÉ”™¥¹‘¥¹œ€‘í¥¹‘•áõ€°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€ô¤¤ì((€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹Ìô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôø€¡ì¥Ñ•µÌè…±°€ôôô€Ä€ü™¥¹‘¥¹Ì€èm™¥¹‘¥¹ÍlÉutô¤(€€€ô¤ì(€€€‘•±•Ñ•I•Á½¥¹‘¥¹Ì¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì(€€€€€‘•±•Ñ•è™¥¹‘¥¹Ì¹Í±¥” À°€È¤¹µ…À ¡™¥¹‘¥¹œ¤€ôø€¡ì(€€€€€€€™¥¹‘¥¹}¥è™¥¹‘¥¹œ¹¥°(€€€€€€€É•Á½}Í…¹}¥è™¥¹‘¥¹œ¹Í…¹}¥(€€€€€ô¤¤°(€€€€€™…¥±•èmì™¥¹‘¥¹}¥è™¥¹‘¥¹ÍlÉt¹¥°É•Á½}Í…¹}¥è™¥¹‘¥¹ÍlÉt¹Í…¹}¥°•ÉÉ½Èè€É•Á¼™¥¹‘¥¹œ¹½Ð™½Õ¹œõt(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 	…Ñ ™…¥±ÕÉ”™¥¹‘¥¹œ€Àœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 	…Ñ ™…¥±ÕÉ”™¥¹‘¥¹œ€Èœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y±•…È…±°½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½±•…È™¥¹‘¥¹Ì½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”…±°½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ œÈ‘•±•Ñ•¸€ÄÉ•µ…¥¹¥¹œ¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ 	…Ñ ™…¥±ÕÉ”™¥¹‘¥¹œ€Àœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ 	…Ñ ™…¥±ÕÉ”™¥¹‘¥¹œ€Èœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åQ•áÐ ¼ÄÙ¥Í¥‰±”™¥¹‘¥¹œ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ­••ÁÌ½¹±ä™…¥±•É•Á½Í¥Ñ½Éä™¥¹‘¥¹Ì¥¸Ñ¡”±•…È…±°‘¥…±½œœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±•…Èµ…±°µÁ…ÉÑ¥…°œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹Ìè¥¹‘¥¹mt€ôl(€€€€€ì(€€€€€€€¥è€™¥¹‘¥¹œµ±•…ÈµÁ…ÉÑ¥…°µ‘•±•Ñ•œ°(€€€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€€€Ñ¥Ñ±”è€•±•Ñ•‰Õ±¬Ñ½­•¸™¥¹‘¥¹œœ°(€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€€€ô°(€€€€€ì(€€€€€€€¥è€™¥¹‘¥¹œµ±•…ÈµÁ…ÉÑ¥…°µÉ•µ…¥¹¥¹œœ°(€€€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€€€Ñ¥Ñ±”è€I•µ…¥¹¥¹œ‰Õ±¬Ý½É­™±½Ü™¥¹‘¥¹œœ°(€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÉ…¹ÑÌ‰É½…É•Á½Í¥Ñ½ÉäÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÜèÀÁhœ(€€€€€ô(€€€tì((€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹Ìô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€É•Á½M…¹ÌèmÍ…¹t°(€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôø€¡ì¥Ñ•µÌè…±°€ôôô€Ä€ü™¥¹‘¥¹Ì€èm™¥¹‘¥¹ÍlÅutô¤(€ô¤ì(€€€‘•±•Ñ•I•Á½¥¹‘¥¹Ì¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì(€€€€€‘•±•Ñ•èmì™¥¹‘¥¹}¥è™¥¹‘¥¹ÍlÁt¹¥°É•Á½}Í…¹}¥èÍ…¸¹¥õt°(€€€€€™…¥±•èmì™¥¹‘¥¹}¥è™¥¹‘¥¹ÍlÅt¹¥°É•Á½}Í…¹}¥èÍ…¸¹¥°•ÉÉ½Èè€É•Á¼™¥¹‘¥¹œ¹½Ð™½Õ¹œõt(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ •±•Ñ•‰Õ±¬Ñ½­•¸™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ I•µ…¥¹¥¹œ‰Õ±¬Ý½É­™±½Ü™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½±•…È…±°½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½±•…È™¥¹‘¥¹Ì½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”…±°½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ •±•Ñ•‰Õ±¬Ñ½­•¸™¥¹‘¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ I•µ…¥¹¥¹œ‰Õ±¬Ý½É­™±½Ü™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ œÄ‘•±•Ñ•¸€ÄÉ•µ…¥¹¥¹œ¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åQ•áÐ ¼ÄÙ¥Í¥‰±”™¥¹‘¥¹œ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ‘¥Í…‰±•Ì±•…È…±°Ý¡¥±”É•Á½Í¥Ñ½Éä™¥¹‘¥¹Ì…É”É•™É•Í¡¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±•…Èµ…±°µÉ•™É•Í¡¥¹œœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ±•…Èµ…±°µÉ•™É•Í¡¥¹œœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€I•™É•Í µÁÉ½Ñ•Ñ•Ñ½­•¸™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì(€€€½¹ÍÐÉ•™É•Í¡¥¹‘¥¹Ì€ô‘•™•ÉÉ•ñì¥Ñ•µÌè¥¹‘¥¹mtôø ¤ì((€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹œô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôø€¡…±°€ôôô€Ä€üì¥Ñ•µÌèm™¥¹‘¥¹tô€èÉ•™É•Í¡¥¹‘¥¹Ì¹ÁÉ½µ¥Í”¤(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ I•™É•Í µÁÉ½Ñ•Ñ•Ñ½­•¸™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•™É•Í ½¤ô¤¤ì(€€€½¹ÍÐ±•…É±±	ÕÑÑ½¸€ôÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½±•…È…±°½¤ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡±•…É±±	ÕÑÑ½¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€ô¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡±•…É±±	ÕÑÑ½¸¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‘¥…±½œœ°ì¹…µ”è€½±•…È™¥¹‘¥¹Ì½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹œ¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€É•™É•Í¡¥¹‘¥¹Ì¹É•Í½±Ù”¡ì¥Ñ•µÌèmtô¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ I•™É•Í µÁÉ½Ñ•Ñ•Ñ½­•¸™¥¹‘¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ±½Í•Ì½Á•¸™¥¹‘¥¹œ‘•±•Ñ”µ•¹ÕÌÝ¡¥±”É•Á½Í¥Ñ½Éä™¥¹‘¥¹Ì…É”É•™É•Í¡¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÉ½Üµµ•¹ÔµÉ•™É•Í¡¥¹œœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÉ½Üµµ•¹ÔµÉ•™É•Í¡¥¹œœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€I•™É•Í µÁÉ½Ñ•Ñ•É½Üµ•¹Ô™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì(€€€½¹ÍÐÉ•™É•Í¡¥¹‘¥¹Ì€ô‘•™•ÉÉ•ñì¥Ñ•µÌè¥¹‘¥¹mtôø ¤ì((€€€½¹ÍÐì‘•±•Ñ•I•Á½¥¹‘¥¹œô€ô…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôø€¡…±°€ôôô€Ä€üì¥Ñ•µÌèm™¥¹‘¥¹tô€èÉ•™É•Í¡¥¹‘¥¹Ì¹ÁÉ½µ¥Í”¤(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ I•™É•Í µÁÉ½Ñ•Ñ•É½Üµ•¹Ô™¥¹‘¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€½¹ÍÐÉ½Ü€ôÍÉ••¸(€€€€€€¹•Ñ±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤(€€€€€€¹™¥¹ ¡¹½‘”¤€ôø¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì I•™É•Í µÁÉ½Ñ•Ñ•É½Üµ•¹Ô™¥¹‘¥¹œœ¤¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ü¤É•ÑÕÉ¸ì((€€€½¹ÍÐ…Ñ¥½¹	ÕÑÑ½¸€ôÝ¥Ñ¡¥¸¡É½Ü¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½ÈI•™É•Í µÁÉ½Ñ•Ñ•É½Üµ•¹Ô™¥¹‘¥¹œ½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡…Ñ¥½¹	ÕÑÑ½¸¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½yI•™É•Í ½¤ô¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡…Ñ¥½¹	ÕÑÑ½¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡…Ñ¥½¹	ÕÑÑ½¸¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡‘•±•Ñ•I•Á½¥¹‘¥¹œ¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€É•™É•Í¡¥¹‘¥¹Ì¹É•Í½±Ù”¡ì¥Ñ•µÌèmtô¤ì(€€€ô¤ì(€ô¤ì((€¥Ð É•½µÁÕÑ•Ìµ•…¸Ñ¥µ”Ñ¼™¥à…™Ñ•È‘•±•Ñ¥¹œ™¥á•™¥¹‘¥¹Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µ™¥á•µ™¥¹‘¥¹œœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥á•‘¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ™¥á•´Äœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€™¥á•œ°(€€€€€Ñ¥Ñ±”è€¥á•Ñ½­•¸•áÁ½ÍÕÉ”™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Q¡¥Ì™¥¹‘¥¹œÝ…ÌÉ•Í½±Ù•±…ÍÐÝ••¬¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€9¼…Ñ¥½¸É•ÅÕ¥É•¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÀÀèÀÁhœ(€€€ôì((€€€½¹ÍÐ¥¹¥Ñ¥…±MÕµµ…ÉäèI•Á½¥¹‘¥¹ÍMÕµµ…Éä€ôì(€€€€€Ñ½Ñ…±}½Á•¸è€À°(€€€€€™¥á•‘}½Õ¹Ðè€Ä°(€€€€€É•½Á•¹•‘}½Õ¹Ðè€À°(€€€€€ÍÕÁÁÉ•ÍÍ•‘}½Õ¹Ðè€À°(€€€€€Í±…}…•‘}½Õ¹Ðè€À°(€€€€€µÑÑÉ}É•…‘å}É•Í½±Ù•‘}½Õ¹Ðè€Ä°(€€€€€µ•…¹}Ñ¥µ•}Ñ½}É•Í½±Ù•}Í•½¹‘Ìè€ÌØÀÀ°(€€€€€‰å}½Ý¹•Èèíô°(€€€€€‰å}‘•Ñ•Ñ½Èèì¥Ñ¡Õ‰}Í•É•Ñ}Í…¹¹¥¹œè€Äô°(€€€€€‰å}Í•Ù•É¥ÑäèìÉ¥Ñ¥…°è€Äô°(€€€€€½±‘•ÍÑ}½Á•¹}™¥ÉÍÑ}Í••¹}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÀÀèÀÁhœ(€€€ôì((€€€½¹ÍÐÉ•™É•Í¡•‘MÕµµ…ÉäèI•Á½¥¹‘¥¹ÍMÕµµ…Éä€ôì(€€€€€Ñ½Ñ…±}½Á•¸è€À°(€€€€€™¥á•‘}½Õ¹Ðè€À°(€€€€€É•½Á•¹•‘}½Õ¹Ðè€À°(€€€€€ÍÕÁÁÉ•ÍÍ•‘}½Õ¹Ðè€À°(€€€€€Í±…}…•‘}½Õ¹Ðè€À°(€€€€€µÑÑÉ}É•…‘å}É•Í½±Ù•‘}½Õ¹Ðè€À°(€€€€€µ•…¹}Ñ¥µ•}Ñ½}É•Í½±Ù•}Í•½¹‘Ìè€ÄàÀÀ°(€€€€€‰å}½Ý¹•Èèíô°(€€€€€‰å}‘•Ñ•Ñ½Èèíô°(€€€€€‰å}Í•Ù•É¥Ñäèíô°(€€€€€½±‘•ÍÑ}½Á•¹}™¥ÉÍÑ}Í••¹}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÀÀèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ìè€¡}Á…É…µÌ°…±°¤€ôøì(€€€€€€€¥˜€¡…±°€ôôô€Ä¤ì(€€€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm™¥á•‘¥¹‘¥¹t°ÍÕµµ…Éäè¥¹¥Ñ¥…±MÕµµ…Éäôì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmt°ÍÕµµ…ÉäèÉ•™É•Í¡•‘MÕµµ…Éäôì(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÍÕµµ…Éä€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	å1…‰•±Q•áÐ I•Á½Í¥Ñ½Éä™¥¹‘¥¹œÍÕµµ…Éäœ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹±…ÍÍ1¥ÍÐ¹½¹Ñ…¥¹Ì ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµÍÑ…ÑÌœ¤(€€€€¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡ÍÕµµ…Éä¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …ÍÕµµ…Éä¤É•ÑÕÉ¸ì(€€€½¹ÍÐµÑÑÉ…É€ôÝ¥Ñ¡¥¸¡ÍÕµµ…Éä¤¹•Ñ	åQ•áÐ 5•…¸Ñ¥µ”Ñ¼™¥àœ¤¹±½Í•ÍÐ …ÉÑ¥±”œ¤ì(€€€•áÁ•Ð¡µÑÑÉ…É¤¹Ñ½	•QÉÕÑ¡ä ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡µÑÑÉ…É„¤¹•Ñ	åQ•áÐ œÅ œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€½¹ÍÐÉ½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì ¥á•Ñ½­•¸•áÁ½ÍÕÉ”™¥¹‘¥¹œœ¤(€€€€¤…Ì!Q51±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ü¤É•ÑÕÉ¸ì((€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡É½Ü¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½È¥á•Ñ½­•¸•áÁ½ÍÕÉ”™¥¹‘¥¹œ½¤ô¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì(€€€½¹ÍÐ½¹™¥Éµ¥…±½œ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‘¥…±½œœ°ì¹…µ”è€½•±•Ñ”™¥¹‘¥¹œ½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹™¥Éµ¥…±½œ¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ¥á•Ñ½­•¸•áÁ½ÍÕÉ”™¥¹‘¥¹œœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡µÑÑÉ…É„¤¹•Ñ	åQ•áÐ œÌÁ´œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ‘•É•µ•¹ÑÌÕ¹­¹½Ý¸‘•Ñ•Ñ½È½Í•Ù•É¥Ñä‰Õ­•ÑÌÝ¡•¸‘•±•Ñ¥¹œ™¥¹‘¥¹ÌÝ¥Ñ¡½ÕÐÑ¡½Í”Ù…±Õ•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐì‘•É•µ•¹ÑI•Á½¥¹‘¥¹ÍMÕµµ…Éå½É•±•Ñ•‘¥¹‘¥¹œô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐÍÕµµ…ÉäèI•Á½¥¹‘¥¹ÍMÕµµ…Éä€ôì(€€€€€Ñ½Ñ…±}½Á•¸è€Ä°(€€€€€™¥á•‘}½Õ¹Ðè€À°(€€€€€É•½Á•¹•‘}½Õ¹Ðè€À°(€€€€€ÍÕÁÁÉ•ÍÍ•‘}½Õ¹Ðè€À°(€€€€€Í±…}…•‘}½Õ¹Ðè€À°(€€€€€µÑÑÉ}É•…‘å}É•Í½±Ù•‘}½Õ¹Ðè€À°(€€€€€‰å}½Ý¹•ÈèìÁ±…Ñ™½É´è€Äô°(€€€€€‰å}‘•Ñ•Ñ½ÈèìÕ¹­¹½Ý¸è€Äô°(€€€€€‰å}Í•Ù•É¥ÑäèìÕ¹­¹½Ý¸è€Äô°(€€€€€½±‘•ÍÑ}½Á•¹}™¥ÉÍÑ}Í••¹}…Ðè€œÈÀÈØ´ÀÔ´ÀÅPÄÄèÀÀèÀÁhœ(€€€ôì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÕ¹­¹½Ý¸µÍÕµµ…Éäœ°(€€€€€Í…¹}¥è€É•Á¼µÍ…¸µÍÕµµ…ÉäµÕ¹­¹½Ý¸œ°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€œœ°(€€€€€½Ý¹•Èè€Á±…Ñ™½É´œ°(€€€€€Ñ¥Ñ±”è€¥¹‘¥¹œÝ¥Ñ Õ¹­¹½Ý¸µ•Ñ…‘…Ñ„œ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€™¥¹‘¥¹œÝ¥Ñ Õ¹Í•Ð‘•Ñ•Ñ½È…¹Í•Ù•É¥Ñä¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€QÉ•…Ð…Ì„¹½¸µ…Ñ¥½¹…‰±”Á±…•¡½±‘•È¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÀÅPÄÄèÀÀèÀÁhœ(€€€ôì((€€€½¹ÍÐ¹•áÑMÕµµ…Éä€ô‘•É•µ•¹ÑI•Á½¥¹‘¥¹ÍMÕµµ…Éå½É•±•Ñ•‘¥¹‘¥¹œ¡ÍÕµµ…Éä°™¥¹‘¥¹œ¤ì(€€€•áÁ•Ð¡¹•áÑMÕµµ…Éä¤¹Ñ½	•QÉÕÑ¡ä ¤ì(€€€•áÁ•Ð¡¹•áÑMÕµµ…Éä¤¹Ñ½5…Ñ¡=‰©•Ð¡ì(€€€€€‰å}‘•Ñ•Ñ½ÈèìÕ¹­¹½Ý¸è€Àô°(€€€€€‰å}Í•Ù•É¥ÑäèìÕ¹­¹½Ý¸è€Àô°(€€€€€Ñ½Ñ…±}½Á•¸è€À°(€€€€€‰å}½Ý¹•ÈèìÁ±…Ñ™½É´è€Àô(€€€ô¤ì(€ô¤ì((€¥Ð ¥¹Ù…±¥‘…Ñ•Ì¥Ñ!Õˆ‘½µ…¥¸…¡”•Á½¡ÌÝ¥Ñ¡½ÕÐÉ•Ù¥Í¥Ñ¥¹œÉ•¥¹Í•ÉÑ•­•åÌœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€ÁÉ½‘ÕÑM¡•±°¹±•…ÉAÉ½‘ÕÑÕÑ¡M•ÍÍ¥½¹…¡•½ÉQ•ÍÑÌ ¤ì(€€€½¹ÍÐµ…Ñ¡¥¹-•ä€ôÁÉ½‘ÕÑM¡•±°¹ÁÉ¥µ•¥Ñ!Õ‰½µ…¥¹…Ñ……¡•Á½¡½ÉQ•ÍÑÌ (€€€€€ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô°(€€€€€€ÁÉ½©•Ðµ„œ°(€€€€€€ÔÀ°(€€€€€€È(€€€€¤ì(€€€½¹ÍÐÍ•½¹‘5…Ñ¡¥¹-•ä€ôÁÉ½‘ÕÑM¡•±°¹ÁÉ¥µ•¥Ñ!Õ‰½µ…¥¹…Ñ……¡•Á½¡½ÉQ•ÍÑÌ (€€€€€ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô°(€€€€€€ÁÉ½©•Ðµˆœ°(€€€€€€ÔÀ°(€€€€€€Ð(€€€€¤ì(€€€½¹ÍÐÕ¹É•±…Ñ•‘-•ä€ôÁÉ½‘ÕÑM¡•±°¹ÁÉ¥µ•¥Ñ!Õ‰½µ…¥¹…Ñ……¡•Á½¡½ÉQ•ÍÑÌ (€€€€€ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµˆœ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µˆœô°(€€€€€€ÁÉ½©•Ðµ„œ°(€€€€€€ÔÀ°(€€€€€€Ü(€€€€¤ì((€€€ÁÉ½‘ÕÑM¡•±°¹¥¹Ù…±¥‘…Ñ•¥Ñ!Õ‰½µ…¥¹…Ñ……¡•½ÉM½Á•½ÉQ•ÍÑÌ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤ì((€€€•áÁ•Ð¡ÁÉ½‘ÕÑM¡•±°¹É•…‘¥Ñ!Õ‰½µ…¥¹…Ñ……¡•Á½¡½ÉQ•ÍÑÌ¡µ…Ñ¡¥¹-•ä¤¤¹Ñ½	” Ì¤ì(€€€•áÁ•Ð¡ÁÉ½‘ÕÑM¡•±°¹É•…‘¥Ñ!Õ‰½µ…¥¹…Ñ……¡•Á½¡½ÉQ•ÍÑÌ¡Í•½¹‘5…Ñ¡¥¹-•ä¤¤¹Ñ½	” Ô¤ì(€€€•áÁ•Ð¡ÁÉ½‘ÕÑM¡•±°¹É•…‘¥Ñ!Õ‰½µ…¥¹…Ñ……¡•Á½¡½ÉQ•ÍÑÌ¡Õ¹É•±…Ñ•‘-•ä¤¤¹Ñ½	” Ü¤ì(€ô¤ì((€¥Ð ¡¥‘•ÌÑ¡”É•Á½Í¥Ñ½Éä™¥¹‘¥¹œ‘•±•Ñ”µ•¹Ô™É½´É•…µ½¹±äÕÍ•ÉÌœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÉ•…µ½¹±äµ™¥¹‘¥¹œœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµÉ•…µ½¹±äµ…Ñ¥½¸œ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€Y¥•Ý•ÈµÙ¥Í¥‰±”Ñ½­•¸™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹ÌèmÍ…¹t°É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t°É½±”è€Ù¥•Ý•Èœô¤ì((€€€½¹ÍÐÉ½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì Y¥•Ý•ÈµÙ¥Í¥‰±”Ñ½­•¸™¥¹‘¥¹œœ¤(€€€€¤ì(€€€•áÁ•Ð¡É½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½ÈY¥•Ý•ÈµÙ¥Í¥‰±”Ñ½­•¸™¥¹‘¥¹œ½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ­••ÁÌ­•å‰½…É¥¹Ñ•É…Ñ¥½¸½¸Ñ¡”É½Ü½Ù•É™±½Üµ•¹Ô½ÕÐ½˜Ñ¡”‘•Ñ…¥°‘¥…±½œœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ­•å‰½…Éµ…Ñ¥½¸œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ­•å‰½…Éµ…Ñ¥½¸œ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€-•å‰½…Éµ•¹Ô™¥¹‘¥¹œœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ñ½­•¸µ±¥­”Ù…±Õ”…ÁÁ•…ÉÌ¥¸„½µµ¥ÑÑ•Ý½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”Ñ¡”É•‘•¹Ñ¥…°…¹É•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹ÌèmÍ…¹t°É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹tô¤ì((€€€½¹ÍÐÑÉ¥•È€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½=Á•¸…Ñ¥½¹Ì™½È-•å‰½…Éµ•¹Ô™¥¹‘¥¹œ½¤ô¤ì(€€€ÑÉ¥•È¹™½ÕÌ ¤ì(€€€™¥É•Ù•¹Ð¹­•å½Ý¸¡ÑÉ¥•È°ì­•äè€¹Ñ•Èœô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‘¥…±½œœ°ì¹…µ”è€½-•å‰½…Éµ•¹Ô™¥¹‘¥¹œ½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÑÉ¥•È¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹­•å½Ý¸¡ÑÉ¥•È°ì­•äè€Í…Á”œô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” µ•¹Õ¥Ñ•´œ°ì¹…µ”è€½•±•Ñ”½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‘¥…±½œœ°ì¹…µ”è€½-•å‰½…Éµ•¹Ô™¥¹‘¥¹œ½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½Ðµ…É¬½É‘¥¹…ÉäÍ½ÕÉ”±¥¹•ÌÑ¡…ÐÍÑ…ÉÐÝ¥Ñ Á±ÕÌ½È‘…Í ÁÉ•™¥á•Ì…Ì‘¥™™Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µå…µ°µÍ½ÕÉ”œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµå…µ°µ±¥ÍÐœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€µ•‘¥Õ´œ°(€€€€€Ñ¥Ñ±”è€]½É­™±½ÜÉ…¹ÑÌ‰É½…Á•Éµ¥ÍÍ¥½¹Ìœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÁ•Éµ¥ÍÍ¥½¸•¹ÑÉä¹••‘ÌÉ•Ù¥•Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸½Ý½É­™±½Ü¹åµ°0ÄÈœ°(€€€€€±¥¹•}Í¹¥ÁÁ•Ðè€œ­•¹…‰±•‘q¸´¹…µ”èÁÉ½œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹ÌèmÍ…¹t°É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹tô¤ì((€€€½¹ÍÐÉ½Ý	ÕÑÑ½¸€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì ]½É­™±½ÜÉ…¹ÑÌ‰É½…Á•Éµ¥ÍÍ¥½¹Ìœ¤(€€€€¤…Ì!Q51	ÕÑÑ½¹±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É½Ý	ÕÑÑ½¸¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É½Ý	ÕÑÑ½¸¤É•ÑÕÉ¸ì(€€€™¥É•Ù•¹Ð¹±¥¬¡É½Ý	ÕÑÑ½¸¤ì((€€€½¹ÍÐÁ±ÕÍM½ÕÉ•1¥¹”€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¡|°•±•µ•¹Ð¤€ôø(€€€€€	½½±•…¸¡•±•µ•¹Ðü¹±…ÍÍ1¥ÍÐ¹½¹Ñ…¥¹Ì ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ¤€˜˜•±•µ•¹Ð¹Ñ•áÑ½¹Ñ•¹Ð€ôôô€œ­•¹…‰±•œ¤(€€€€¤ì(€€€½¹ÍÐå…µ±M½ÕÉ•1¥¹”€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¡|°•±•µ•¹Ð¤€ôø(€€€€€	½½±•…¸¡•±•µ•¹Ðü¹±…ÍÍ1¥ÍÐ¹½¹Ñ…¥¹Ì ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ¤€˜˜•±•µ•¹Ð¹Ñ•áÑ½¹Ñ•¹Ð€ôôô€œ´¹…µ”èÁÉ½œ¤(€€€€¤ì(€€€•áÁ•Ð¡Á±ÕÍM½ÕÉ•1¥¹”¤¹¹½Ð¹Ñ½!…Ù•±…ÍÌ ¥Ìµ…‘œ¤ì(€€€•áÁ•Ð¡å…µ±M½ÕÉ•1¥¹”¤¹¹½Ð¹Ñ½!…Ù•±…ÍÌ ¥ÌµÉ•µ½Ù”œ¤ì(€€€•áÁ•Ð¡Á±ÕÍM½ÕÉ•1¥¹”¹ÅÕ•ÉåM•±•Ñ½È œ¹¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µµ…É­•Èœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð¡å…µ±M½ÕÉ•1¥¹”¹ÅÕ•ÉåM•±•Ñ½È œ¹¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µµ…É­•Èœ¤¤¹Ñ½	•9Õ±° ¤ì(€ô¤ì((€¥Ð µ…É­Ì½¹”µÍ¥‘•É•Á½Í¥Ñ½Éä‘¥™˜¡Õ¹­Ì…Ì¡…¹•±¥¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µ½¹”µÍ¥‘•µ‘¥™˜œ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È(€€€ôì((€€€½¹ÍÐ…‘‘¥Ñ¥½¹¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ…‘µ½¹±äµ‘¥™˜œ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€Ý½É­™±½Ý}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€Í•Ù•É¥Ñäè€µ•‘¥Õ´œ°(€€€€€Ñ¥Ñ±”è€]½É­™±½Ü…‘‘Ì‰É½…Á•Éµ¥ÍÍ¥½¹Ìœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÁ•Éµ¥ÍÍ¥½¸•¹ÑÉäÝ…Ì…‘‘•¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€1¥µ¥ÐÝ½É­™±½ÜÁ•Éµ¥ÍÍ¥½¹Ì¸œ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸½Ý½É­™±½Ü¹åµ°0ÄÈœ°(€€€€€±¥¹•}Í¹¥ÁÁ•Ðèl(€€€€€€€€‘¥™˜€´µ¥Ð„½Ý½É­™±½Ü¹åµ°ˆ½Ý½É­™±½Ü¹åµ°œ°(€€€€€€€€¹•Ü™¥±”µ½‘”€ÄÀÀØÐÐœ°(€€€€€€€€¥¹‘•à€ÀÀÀÀÀÀÀ¸¸ÄÄÄÄÄÄÄœ°(€€€€€€€€œ´´´€½‘•Ø½¹Õ±°œ°(€€€€€€€€œ¬¬¬ˆ½Ý½É­™±½Ü¹åµ°œ°(€€€€€€€€ €´À°À€¬Ä œ°(€€€€€€€€œ¬¬­½Õ¹Ðœ(€€€€€t¹©½¥¸ q¸œ¤°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì(€€€½¹ÍÐÉ•µ½Ù…±¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹…‘‘¥Ñ¥½¹¥¹‘¥¹œ°(€€€€€¥è€™¥¹‘¥¹œµÉ•µ½Ù”µ½¹±äµ‘¥™˜œ°(€€€€€Ñ¥Ñ±”è€]½É­™±½ÜÉ•µ½Ù•ÌÕ…É‘É…¥°œ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½ÜÕ…É‘É…¥°Ý…ÌÉ•µ½Ù•¸œ°(€€€€€±¥¹•}Í¹¥ÁÁ•Ðè€ €´Ä€¬À°Àq¸´´µ½Õ¹Ðœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ìÉ•Á½M…¹ÌèmÍ…¹t°É•Á½¥¹‘¥¹Ìèm…‘‘¥Ñ¥½¹¥¹‘¥¹œ°É•µ½Ù…±¥¹‘¥¹tô¤ì((€€€½¹ÍÐ…‘‘I½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì ]½É­™±½Ü…‘‘Ì‰É½…Á•Éµ¥ÍÍ¥½¹Ìœ¤(€€€€¤…Ì!Q51	ÕÑÑ½¹±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡…‘‘I½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ ……‘‘I½Ü¤É•ÑÕÉ¸ì(€€€™¥É•Ù•¹Ð¹±¥¬¡…‘‘I½Ü¤ì((€€€½¹ÍÐ…‘‘•‘1¥¹”€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¡|°•±•µ•¹Ð¤€ôø(€€€€€	½½±•…¸¡•±•µ•¹Ðü¹±…ÍÍ1¥ÍÐ¹½¹Ñ…¥¹Ì ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ¤€˜˜•±•µ•¹Ð¹Ñ•áÑ½¹Ñ•¹Ð€ôôô€œ¬¬­½Õ¹Ðœ¤(€€€€¤ì(€€€•áÁ•Ð¡…‘‘•‘1¥¹”¤¹Ñ½!…Ù•±…ÍÌ ¥Ìµ…‘œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡…‘‘•‘1¥¹”¤¹•Ñ	åQ•áÐ œ¬œ¤¤¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µµ…É­•Èœ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½±½Í”™¥¹‘¥¹œ‘•Ñ…¥°½¤ô¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½±½Í”™¥¹‘¥¹œ‘•Ñ…¥°½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì((€€€½¹ÍÐÉ•µ½Ù•I½Ü€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ±¥ÍÑ¥Ñ•´œ¤¤¹™¥¹ ¡¹½‘”¤€ôø(€€€€€¹½‘”¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì ]½É­™±½ÜÉ•µ½Ù•ÌÕ…É‘É…¥°œ¤(€€€€¤…Ì!Q51	ÕÑÑ½¹±•µ•¹ÐðÕ¹‘•™¥¹•ì(€€€•áÁ•Ð¡É•µ½Ù•I½Ü¤¹Ñ½	••™¥¹• ¤ì(€€€¥˜€ …É•µ½Ù•I½Ü¤É•ÑÕÉ¸ì(€€€™¥É•Ù•¹Ð¹±¥¬¡É•µ½Ù•I½Ü¤ì((€€€½¹ÍÐÉ•µ½Ù•‘1¥¹”€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¡|°•±•µ•¹Ð¤€ôø(€€€€€	½½±•…¸¡•±•µ•¹Ðü¹±…ÍÍ1¥ÍÐ¹½¹Ñ…¥¹Ì ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µ±¥¹”œ¤€˜˜•±•µ•¹Ð¹Ñ•áÑ½¹Ñ•¹Ð€ôôô€œ´´µ½Õ¹Ðœ¤(€€€€¤ì(€€€•áÁ•Ð¡É•µ½Ù•‘1¥¹”¤¹Ñ½!…Ù•±…ÍÌ ¥ÌµÉ•µ½Ù”œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•µ½Ù•‘1¥¹”¤¹•Ñ	åQ•áÐ œ´œ¤¤¹Ñ½!…Ù•±…ÍÌ ¥‘ÐµÉ•Á¼µ™¥¹‘¥¹œµ½‘”µµ…É­•Èœ¤ì(€ô¤ì((€¥Ð ­••ÁÌÙ¥Í¥‰±”™¥±Ñ•ÉÌÝ¡•¸…Ñ¥Ù”™¥±Ñ•ÉÌµ…Ñ ¹¼™¥¹‘¥¹Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÝ¥Ñ µ™¥¹‘¥¹Ìœ°(€€€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä(€€€ôì((€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œ´Äœ°(€€€€€Í…¹}¥èÍ…¸¹¥°(€€€€€ÑåÁ”è€…ÝÍ}…•ÍÍ}­•äœ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€Ñ¥Ñ±”è€%4É½±”Ý¥Ñ Ý¥±‘…ÉÑÉÕÍÐœ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€ÍÍÕµ•I½±”ÑÉÕÍÐÁ½±¥ä…±±½ÝÌ…¹äÁÉ¥¹¥Á…°¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€Q¥¡Ñ•¸ÑÉÕÍÐÁ½±¥äÁÉ¥¹¥Á…±Ì¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀØèÀÁhœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥¹‘¥¹Ì¡ì(€€€€€É•Á½M…¹ÌèmÍ…¹t°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t(€€€ô¤ì((€€€•áÁ•Ð ¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åQ•áÐ %4É½±”Ý¥Ñ Ý¥±‘…ÉÑÉÕÍÐœ¤¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¥±Ñ•ÉÌ…¹Í½ÉÑ¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€½¹ÍÐÍ•Ù•É¥Ñå¥±Ñ•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ M•Ù•É¥Ñäœ¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Í•Ù•É¥Ñå¥±Ñ•È°ìÑ…É•ÐèìÙ…±Õ”è€¡¥ œôô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì¹…µ”è€9¼™¥¹‘¥¹Ìµ…Ñ Ñ¡•Í”™¥±Ñ•ÉÌœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ I•Á½Í¥Ñ½Éä™¥¹‘¥¹œ™¥±Ñ•ÉÌ…¹Í½ÉÑ¥¹œœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‘¥…±½œœ°ì¹…µ”è€½%4É½±”Ý¥Ñ Ý¥±‘…ÉÑÉÕÍÐ½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì)ô¤ì()‘•ÍÉ¥‰” ¥Ñ!Õˆ‘½µ…¥¸Á…•Ì€ ŒÄÌàÈ¤œ°€ ¤€ôøì(€½¹ÍÐÁÉ½‘ÕÑ¥½¹AÉ½©•Ð€ôì(€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°(€€€Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€‘•ÍÉ¥ÁÑ¥½¸è€AÉ½‘ÕÑ¥½¸¥‘•¹Ñ¥Ñä‰½Õ¹‘…Éä¸œ°(€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€ôì((€½¹ÍÐÍÕ••‘•‘I•Á½M…¸èI•Á½M…¹I•½É€ôì(€€€¥è€É•Á¼µÍ…¸µÍÕ••‘•œ°(€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔÀèÀÁhœ°(€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔÔèÀÁhœ°(€€€½µµ¥ÑÍ}Í…¹¹•è€ÄÈ°(€€€™¥±•Í}Í…¹¹•è€ÌÐÀ°(€€€™¥¹‘¥¹}½Õ¹Ðè€Ì°(€€€ÑÉÕ¹…Ñ•è™…±Í”°(€€€Í…¹}µ½‘”è€ÅÕ¥¬œ(€ôì((€½¹ÍÐ‘•™…Õ±ÑM…¹A½±¥äèM…¹A½±¥åI•½É€ôì(€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€Á½±¥å}¥è€‘•™…Õ±Ðœ°(€€€¹…µ”è€•™…Õ±ÐÁ½±¥äœ°(€€€•¹…‰±•èÑÉÕ”°(€€€ÑÉ¥•É}µ½‘”è€•Ù•¹Ðœ°(€€€µ…á}½¹ÕÉÉ•¹Ñ}Í…¹Ìè€Ä°(€€€¡¥ÍÑ½Éå}±¥µ¥Ðè€ÔÀÀ°(€€€µ…á}™¥¹‘¥¹Ìè€ÈÀÀ°(€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€ôì((€½¹ÍÐ‘•™…Õ±ÑI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”è¥Ñ!Õ‰I•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”€ôì(€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€¥¹ÍÑ…±±…Ñ¥½¹}¥è€ÄÈÌÐÔ°(€€€½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔÔèÀÁhœ°(€€€É…Ñ•}±¥µ¥Ðèì±¥µ¥Ðè€ÔÀÀÀ°É•µ…¥¹¥¹œè€ÐääÀô°(€€€¡•­Ìèl(€€€€€ì(€€€€€€€¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°(€€€€€€€…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°(€€€€€€€ÍÑ…Ñ”è€¥¹Í•ÕÉ”œ°(€€€€€€€É•…Í½¸è€µ¥ÍÍ¥¹}É•ÅÕ¥É•‘}É•Ù¥•ÝÌœ°(€€€€€€€ÍÕµµ…Éäè€•™…Õ±Ð‰É…¹ ¥Ìµ¥ÍÍ¥¹œÉ•ÅÕ¥É•ÁÕ±°É•ÅÕ•ÍÐÉ•Ù¥•ÝÌ¸œ(€€€€€ô°(€€€€€ì(€€€€€€€¥è€Í•É•ÐµÍ…¹¹¥¹œœ°(€€€€€€€…Ñ•½Éäè€Í•ÕÉ¥Ñäœ°(€€€€€€€ÍÑ…Ñ”è€Í•ÕÉ”œ°(€€€€€€€ÍÕµµ…Éäè€M•É•ÐÍ…¹¹¥¹œ¥Ì•¹…‰±•¸œ(€€€€€ô(€€€t(€ôì((€½¹ÍÐ‘•™…Õ±Ñ=É…¹¥é…Ñ¥½¹A½ÍÑÕÉ”è¥Ñ!Õ‰=É…¹¥é…Ñ¥½¹A½ÍÑÕÉ”€ôì(€€€½É…¹¥é…Ñ¥½¸è€¥‘•¹ÑÉ…¥°œ°(€€€¥¹ÍÑ…±±…Ñ¥½¹}¥è€ÄÈÌÐÔ°(€€€½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€¡•­Ìèl(€€€€€ì(€€€€€€€¥è€½ÉœµÑÝ¼µ™…Ñ½Èœ°(€€€€€€€…Ñ•½Éäè€½É…¹¥é…Ñ¥½¸Í•ÕÉ¥Ñäœ°(€€€€€€€ÍÑ…Ñ”è€Í•ÕÉ”œ°(€€€€€€€ÍÕµµ…Éäè€=É…¹¥é…Ñ¥½¸ÑÝ¼µ™…Ñ½È…ÕÑ¡•¹Ñ¥…Ñ¥½¸¥Ì•¹™½É•¸œ(€€€€€ô(€€€t(€ôì((€…™Ñ•É…   ¤€ôøì(€€€Ù¤¹É•ÍÑ½É•±±5½­Ì ¤ì(€€€Ù¤¹‘½U¹µ½¬ œ¸½¡½½­Ì½ÕÍ•	…­•¹‘•…ÑÕÉ•Ìœ¤ì(€€€Ù¤¹‘½U¹µ½¬ œ¸½Á…•Ì½½¹‰½…É‘¥¹œ½½¹‰½…É‘¥¹UÑ¥±Ìœ¤ì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€ô¤ì((€…Íå¹Œ™Õ¹Ñ¥½¸É•¹‘•É¥Ñ!Õ‰A…” (€€€Á…•9…µ”è€½¹ÑÉ½°µ•¹Ñ•Èœð€½¹¹•Ðœð€É•Á½Í¥Ñ½É¥•Ìœð€…Ñ¥½¹Ìœð€É•µ•‘¥…Ñ¥½¸œ°(€€€½ÁÑ¥½¹Ìèì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸üè¥Ñ!Õ‰½¹¹•Ñ¥½¹MÑ…ÑÕÌð¹Õ±°ì(€€€€€Í…¹ÌüèI•Á½M…¹I•½É‘mtì(€€€€€Í…¹A½±¥¥•ÌüèM…¹A½±¥åI•½É‘mtì(€€€€€É•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”üè¥Ñ!Õ‰I•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”ì(€€€€€½É…¹¥é…Ñ¥½¹A½ÍÑÕÉ”üè¥Ñ!Õ‰=É…¹¥é…Ñ¥½¹A½ÍÑÕÉ”ì(€€€€€É•Á½¥¹‘¥¹Ìüè¥¹‘¥¹mtì(€€€€€É•µ•‘¥…Ñ¥½¹AÉ•Ù¥•ÜüèI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¹AÉ•Ù¥•Üì(€€€€€É•µ•‘¥…Ñ¥½¹AÕ‰±¥Í üèI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¹AÕ‰±¥Í¡I•ÍÁ½¹Í”ì(€€€€€±¥ÍÑI•Á½M…¹Ìüè€ ¤€ôøAÉ½µ¥Í”ñì¥Ñ•µÌèI•Á½M…¹I•½É‘mtì¹•áÑ}ÕÉÍ½ÈüèÍÑÉ¥¹œôøì(€€€€€¥Ñ¡Õ‰•…ÑÕÉ•±…œüè‰½½±•…¸ì(€€€€€¥Ñ¡Õ‰	…­•¹üè	…­•¹‘•…ÑÕÉ•MÑ…Ñ”ì(€€€€€ÉÕ¹I•Á½M…¹ÉÉ½Èüèìµ•ÍÍ…”èÍÑÉ¥¹œìÍÑ…ÑÕÌè¹Õµ‰•Èôì(€€€€€…¹•±I•Á½M…¹ÉÉ½Èüèìµ•ÍÍ…”èÍÑÉ¥¹œìÍÑ…ÑÕÌè¹Õµ‰•Èôì(€€€€€¥¹¥Ñ¥…±¹ÑÉäüèÍÑÉ¥¹œì(€€€€€ÁÉ½©•ÑÌüèÉÉ…äñÑåÁ•½˜ÁÉ½‘ÕÑ¥½¹AÉ½©•Ðøì(€€€ô€ôíô(€€¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡Õˆè½ÁÑ¥½¹Ì¹¥Ñ¡Õ‰•…ÑÕÉ•±…œ€üüÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡Õˆè½ÁÑ¥½¹Ì¹¥Ñ¡Õ‰	…­•¹€üüÑÉÕ”ô¤ì((€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÁÉ½©•ÑÌ€ô½ÁÑ¥½¹Ì¹ÁÉ½©•ÑÌ€üümÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèÁÉ½©•ÑÌô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•ÑÌ¹™¥¹ ¡ÁÉ½©•Ð¤€ôøÁÉ½©•Ð¹ÁÉ½©•Ñ}¥€ôôôÁÉ½©•Ñ%¤€üüÁÉ½©•ÑÍlÁt€üüÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€½¹ÍÐ•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½ÁÑ¥½¹Ì¹¥Ñ¡Õ‰½¹¹•Ñ¥½¸€üü½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤ì(€€€¥˜€¡½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½M…¹Ì¤ì(€€€€€±¥ÍÑI•Á½M…¹Ì¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½M…¹Ìü¸ ¤€üüAÉ½µ¥Í”¹É•Í½±Ù”¡ì¥Ñ•µÌèmtô¤¤ì(€€€ô•±Í”ì(€€€€€±¥ÍÑI•Á½M…¹Ì¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌè½ÁÑ¥½¹Ì¹Í…¹Ì€üümtô¤ì(€€€ô(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌè½ÁÑ¥½¹Ì¹Í…¹A½±¥¥•Ì€üümtô¤ì(€€€½¹ÍÐÕÁÍ•ÉÑAÉ½©•ÑM…¹A½±¥ä€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑAÉ½©•ÑM…¹A½±¥äœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÁ½±¥äè½ÁÑ¥½¹Ì¹Í…¹A½±¥¥•Ìü¹lÁt€üü‘•™…Õ±ÑM…¹A½±¥äô¤ì(€€€½¹ÍÐ‘•±•Ñ•AÉ½©•ÑM…¹A½±¥ä€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€‘•±•Ñ•AÉ½©•ÑM…¹A½±¥äœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡Õ¹‘•™¥¹•¤ì(€€€½¹ÍÐ•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€€€ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€€€Á½ÍÑÕÉ”è½ÁÑ¥½¹Ì¹É•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”€üü‘•™…Õ±ÑI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”°(€€€€€€€½É…¹¥é…Ñ¥½¹}Á½ÍÑÕÉ”è½ÁÑ¥½¹Ì¹½É…¹¥é…Ñ¥½¹A½ÍÑÕÉ”€üü‘•™…Õ±Ñ=É…¹¥é…Ñ¥½¹A½ÍÑÕÉ”(€€€€€ô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½¥¹‘¥¹Ì€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌè½ÁÑ¥½¹Ì¹É•Á½¥¹‘¥¹Ì€üümt°ÍÕµµ…ÉäèÕ¹‘•™¥¹•ô¤ì(€€€½¹ÍÐÁÉ•Ù¥•ÝI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÁÉ•Ù¥•ÝI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸œ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ” (€€€€€€€½ÁÑ¥½¹Ì¹É•µ•‘¥…Ñ¥½¹AÉ•Ù¥•Ü€üüì(€€€€€€€€€™¥¹‘¥¹œè½ÁÑ¥½¹Ì¹É•Á½¥¹‘¥¹Ìü¹lÁt€üüì(€€€€€€€€€€€¥è€™¥¹‘¥¹œµ‘•™…Õ±Ðœ°(€€€€€€€€€€€Í…¹}¥è€É•Á¼µÍ…¸µ‘•™…Õ±Ðœ°(€€€€€€€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€€€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€€€€€€€Ñ¥Ñ±”è€•™…Õ±ÐÉ•µ•‘¥…Ñ¥½¸™¥¹‘¥¹œœ°(€€€€€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€•™…Õ±ÐÉ•µ•‘¥…Ñ¥½¸™¥¹‘¥¹œÍÕµµ…Éä¸œ°(€€€€€€€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”…¹É•µ½Ù”Ñ¡”•áÁ½Í•Í•É•Ð¸œ°(€€€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ(€€€€€€€€€ô°(€€€€€€€€€É•µ•‘¥…Ñ¥½¸èì(€€€€€€€€€€€‘•Ñ•Ñ½Èè€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€€€€€€€ÍÕµµ…Éäè€I½Ñ…Ñ”…¹É•µ½Ù”Ñ¡”•áÁ½Í•Í•É•Ðœ°(€€€€€€€€€€€É¥Í­}ÍÕµµ…Éäè€Q¡”•áÁ½Í•É•‘•¹Ñ¥…°…¸‰”É•Á±…å•½ÕÑÍ¥‘”¥Ñ!Õˆ¸œ°(€€€€€€€€€€€ÍÑ•ÁÌèlI½Ñ…Ñ”Ñ¡”•áÁ½Í•É•‘•¹Ñ¥…°œ°€I•µ½Ù”Ñ¡”½µµ¥ÑÑ•Ù…±Õ”t°(€€€€€€€€€€€Í…™•Ñå}¹½Ñ•Ìèl½¹™¥É´Ñ¡”É•Á±…•µ•¹ÐÍ•É•Ð¥Ì…Ù…¥±…‰±”‰•™½É”µ•É¥¹œt°(€€€€€€€€€€€Ù…±¥‘…Ñ¥½¸èlIÕ¸Ñ¡”É•Á½Í¥Ñ½ÉäÍ…¸……¥¸t°(€€€€€€€€€€€Í•É•Ñ}É½Ñ…Ñ¥½¸èÑÉÕ”°(€€€€€€€€€€€ÁÕ‰±¥Í¡…‰±”èÑÉÕ”°(€€€€€€€€€€€•Ù¥‘•¹”èì™¥¹‘¥¹}¥è€™¥¹‘¥¹œµ‘•™…Õ±Ðœ°Í…¹}¥è€É•Á¼µÍ…¸µ‘•™…Õ±Ðœô(€€€€€€€€€ô°(€€€€€€€€€™¥á}ÁÉ}Á±…¸èì(€€€€€€€€€€€‰…Í•}‰É…¹ è€µ…¥¸œ°(€€€€€€€€€€€‰É…¹¡}¹…µ”è€¥‘•¹ÑÉ…¥°½™¥à½™¥¹‘¥¹œµ‘•™…Õ±Ðœ°(€€€€€€€€€€€½µµ¥Ñ}µ•ÍÍ…”è€I•µ½Ù”•áÁ½Í•Í•É•Ðœ°(€€€€€€€€€€€ÁÉ}Ñ¥Ñ±”è€I•µ½Ù”•áÁ½Í•Í•É•Ðœ°(€€€€€€€€€€€ÁÉ}‰½‘äè€I•µ•‘¥…Ñ•ÌÑ¡”•áÁ½Í•É•Á½Í¥Ñ½ÉäÍ•É•Ð¸œ°(€€€€€€€€€€€™¥±•ÌèmìÁ…Ñ è€œ¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½‘•Á±½ä¹åµ°œ°½¹Ñ•¹Ðè€•¹Øèíôœõt°(€€€€€€€€€€€™¥¹‘¥¹}¥è€™¥¹‘¥¹œµ‘•™…Õ±Ðœ°(€€€€€€€€€€€™¥¹‘¥¹}ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ(€€€€€€€€€ô(€€€€€€€ô(€€€€€€¤ì(€€€½¹ÍÐÁÕ‰±¥Í¡I•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÁÕ‰±¥Í¡I•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸œ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ” (€€€€€€€½ÁÑ¥½¹Ì¹É•µ•‘¥…Ñ¥½¹AÕ‰±¥Í €üüì(€€€€€€€€€™¥¹‘¥¹œè½ÁÑ¥½¹Ì¹É•Á½¥¹‘¥¹Ìü¹lÁt€üüì(€€€€€€€€€€€¥è€™¥¹‘¥¹œµ‘•™…Õ±Ðœ°(€€€€€€€€€€€Í…¹}¥è€É•Á¼µÍ…¸µ‘•™…Õ±Ðœ°(€€€€€€€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€€€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€€€€€€€Ñ¥Ñ±”è€•™…Õ±ÐÉ•µ•‘¥…Ñ¥½¸™¥¹‘¥¹œœ°(€€€€€€€€€€€¡Õµ…¹}ÍÕµµ…Éäè€•™…Õ±ÐÉ•µ•‘¥…Ñ¥½¸™¥¹‘¥¹œÍÕµµ…Éä¸œ°(€€€€€€€€€€€É•µ•‘¥…Ñ¥½¸è€I½Ñ…Ñ”…¹É•µ½Ù”Ñ¡”•áÁ½Í•Í•É•Ð¸œ°(€€€€€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ(€€€€€€€€€ô°(€€€€€€€€€É•µ•‘¥…Ñ¥½¸èì(€€€€€€€€€€€‘•Ñ•Ñ½Èè€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€€€€€€€ÍÕµµ…Éäè€I½Ñ…Ñ”…¹É•µ½Ù”Ñ¡”•áÁ½Í•Í•É•Ðœ°(€€€€€€€€€€€É¥Í­}ÍÕµµ…Éäè€Q¡”•áÁ½Í•É•‘•¹Ñ¥…°…¸‰”É•Á±…å•½ÕÑÍ¥‘”¥Ñ!Õˆ¸œ°(€€€€€€€€€€€ÍÑ•ÁÌèlI½Ñ…Ñ”Ñ¡”•áÁ½Í•É•‘•¹Ñ¥…°t°(€€€€€€€€€€€Í…™•Ñå}¹½Ñ•Ìèl½¹™¥É´Ñ¡”É•Á±…•µ•¹ÐÍ•É•Ð¥Ì…Ù…¥±…‰±”‰•™½É”µ•É¥¹œt°(€€€€€€€€€€€Ù…±¥‘…Ñ¥½¸èlIÕ¸Ñ¡”É•Á½Í¥Ñ½ÉäÍ…¸……¥¸t°(€€€€€€€€€€€Í•É•Ñ}É½Ñ…Ñ¥½¸èÑÉÕ”°(€€€€€€€€€€€ÁÕ‰±¥Í¡…‰±”èÑÉÕ”°(€€€€€€€€€€€•Ù¥‘•¹”èì™¥¹‘¥¹}¥è€™¥¹‘¥¹œµ‘•™…Õ±Ðœ°Í…¹}¥è€É•Á¼µÍ…¸µ‘•™…Õ±Ðœô(€€€€€€€€€ô°(€€€€€€€€€ÁÕ‰±¥Í èì(€€€€€€€€€€€ÁÉ}¹Õµ‰•Èè€ÐÈ°(€€€€€€€€€€€ÁÉ}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½ÁÕ±°¼ÐÈœ°(€€€€€€€€€€€‰É…¹¡}¹…µ”è€¥‘•¹ÑÉ…¥°½™¥à½™¥¹‘¥¹œµ‘•™…Õ±Ðœ°(€€€€€€€€€€€½µµ¥Ñ}Í¡„è€…‰ŒÄÈÌÐœ(€€€€€€€€€ô(€€€€€€€ô(€€€€€€¤ì(€€€½¹ÍÐÉÕ¹I•Á½M…¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÉÕ¹I•Á½M…¸œ¤ì(€€€¥˜€¡½ÁÑ¥½¹Ì¹ÉÕ¹I•Á½M…¹ÉÉ½È¤ì(€€€€€ÉÕ¹I•Á½M…¸¹µ½­I•©•Ñ•‘Y…±Õ”¡¹•Ü…Á¤¹Á¥ÉÉ½È¡½ÁÑ¥½¹Ì¹ÉÕ¹I•Á½M…¹ÉÉ½È¹µ•ÍÍ…”°½ÁÑ¥½¹Ì¹ÉÕ¹I•Á½M…¹ÉÉ½È¹ÍÑ…ÑÕÌ¤¤ì(€€€ô•±Í”ì(€€€€€ÉÕ¹I•Á½M…¸¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÉ•Á½}Í…¸èÅÕ•Õ•‘I•Á½M…¸ô¤ì(€€€ô(€€€½¹ÍÐ…¹•±I•Á½M…¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€…¹•±I•Á½M…¸œ¤ì(€€€¥˜€¡½ÁÑ¥½¹Ì¹…¹•±I•Á½M…¹ÉÉ½È¤ì(€€€€€…¹•±I•Á½M…¸¹µ½­I•©•Ñ•‘Y…±Õ” (€€€€€€€¹•Ü…Á¤¹Á¥ÉÉ½È¡½ÁÑ¥½¹Ì¹…¹•±I•Á½M…¹ÉÉ½È¹µ•ÍÍ…”°½ÁÑ¥½¹Ì¹…¹•±I•Á½M…¹ÉÉ½È¹ÍÑ…ÑÕÌ¤(€€€€€€¤ì(€€€ô•±Í”ì(€€€€€…¹•±I•Á½M…¸¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÉ•Á½}Í…¸è…¹•±•‘I•Á½M…¸ô¤ì(€€€ô(€€€½¹ÍÐÍÑ…ÉÑ¥Ñ!Õ‰½¹¹•Ñ½È€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ¥Ñ!Õ‰½¹¹•Ñ½Èœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€€€½¹¹•Ñ•è™…±Í”°(€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€€€‘¥ÍÁ±…å}¹…µ”è€%‘•¹ÑÉ…¥°œ°(€€€€€€€ÍÑ…ÑÕÌè€Á•¹‘¥¹œœ°(€€€€€€€¡•…±Ñ¡}ÍÑ…ÑÕÌè€Õ¹­¹½Ý¸œ°(€€€€€€€Ý•‰¡½½­}Í•É•Ñ}É½Ñ…Ñ¥½¹}É•ÅÕ¥É•è™…±Í”°(€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmt(€€€€€ô°(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€ÍÑ…Ñ”è€¥Ñ¡ÕˆµÍÑ…Ñ”œ°(€€€€€¥¹ÍÑ…±±}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½…ÁÁÌ½¥‘•¹ÑÉ…¥°½¥¹ÍÑ…±±…Ñ¥½¹Ì½Í•±•Ñ}Ñ…É•ÐýÍÑ…Ñ”õ¥Ñ¡ÕˆµÍÑ…Ñ”œ°(€€€€€¥¹ÍÑ…±±}…½Õ¹Ñ}ÑåÁ”è€…¹äœ°(€€€€€Ý•‰¡½½­}ÕÉ°è€œ½…ÕÑ ½Ý•‰¡½½­Ì½¥Ñ¡Õˆœ°(€€€€€•áÁ¥É•Í}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÄÀèÀÁhœ(€€€ô¤ì(€€€½¹ÍÐÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½È€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½Èœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õ‰APô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐÁ…”€ô(€€€€€Á…•9…µ”€ôôô€½¹ÑÉ½°µ•¹Ñ•Èœ€ü€ñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”€¼ø€è(€€€€€Á…•9…µ”€ôôô€½¹¹•Ðœ€ü€ñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ø€è(€€€€€Á…•9…µ”€ôôô€É•Á½Í¥Ñ½É¥•Ìœ€ü€ñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½É¥•ÍA…”€¼ø€è(€€€€€Á…•9…µ”€ôôô€É•µ•‘¥…Ñ¥½¸œ€ü€ñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•µ•‘¥…Ñ¥½¹A…”€¼ø€è(€€€€€€ñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰Ñ¥½¹ÍA…”€¼øì((€€€½¹ÍÐÉ½ÕÑ•A…Ñ €ô(€€€€€Á…•9…µ”€ôôô€½¹ÑÉ½°µ•¹Ñ•Èœ€ü€¥Ñ¡Õˆœ€è(€€€€€Á…•9…µ”€ôôô€½¹¹•Ðœ€ü€¥Ñ¡Õˆ½½¹¹•Ðœ€è(€€€€€Á…•9…µ”€ôôô€É•Á½Í¥Ñ½É¥•Ìœ€ü€¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìœ€è(€€€€€Á…•9…µ”€ôôô€É•µ•‘¥…Ñ¥½¸œ€ü€¥Ñ¡Õˆ½É•µ•‘¥…Ñ¥½¸œ€è(€€€€€€¥Ñ¡Õˆ½…Ñ¥½¹Ìœì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím½ÁÑ¥½¹Ì¹¥¹¥Ñ¥…±¹ÑÉä€üü€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„¼‘íÉ½ÕÑ•A…Ñ¡õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ õí€½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%¼‘íÉ½ÕÑ•A…Ñ¡õô•±•µ•¹ÐõíÁ…•ô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€É•ÑÕÉ¸ì(€€€€€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ°(€€€€€±¥ÍÑI•Á½M…¹Ì°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹Ì°(€€€€€ÁÉ•Ù¥•ÝI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸°(€€€€€ÁÕ‰±¥Í¡I•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸°(€€€€€ÉÕ¹I•Á½M…¸°(€€€€€…¹•±I•Á½M…¸°(€€€€€ÍÑ…ÉÑ¥Ñ!Õ‰½¹¹•Ñ½È°(€€€€€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì°(€€€€€ÕÁÍ•ÉÑAÉ½©•ÑM…¹A½±¥ä°(€€€€€‘•±•Ñ•AÉ½©•ÑM…¹A½±¥ä°(€€€€€ÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½È°(€€€€€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”(€€€ôì(€ô((€¥Ð ¥Ñ!Õˆ…±±‰…¬Í¡½ÝÌ„Á½±¥Í¡•¡…¹‘½™˜…¹É•‘¥É•ÑÌÑ¼Ñ¡”±•…¸½¹¹•Ñ¥½¸Á…”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐ½µÁ±•Ñ¥½¸€ô‘•™•ÉÉ•ñÝ…¥Ñ•ñI•ÑÕÉ¹QåÁ”ñÑåÁ•½˜…Á¤¹…Á¥±¥•¹Ð¹½µÁ±•Ñ•¥Ñ!Õ‰½¹¹•Ñ½Èøøø ¤ì(€€€½¹ÍÐ½µÁ±•Ñ•¥Ñ!Õ‰½¹¹•Ñ½È€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€½µÁ±•Ñ•¥Ñ!Õ‰½¹¹•Ñ½Èœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø½µÁ±•Ñ¥½¸¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€™Õ¹Ñ¥½¸1½…Ñ¥½¹…ÁÑÕÉ” ¤ì(€€€€€½¹ÍÐ±½…Ñ¥½¸€ôÕÍ•1½…Ñ¥½¸ ¤ì(€€€€€É•ÑÕÉ¸€ñÀ‘…Ñ„µÑ•ÍÑ¥ô‰±½…Ñ¥½¸ˆùí±½…Ñ¥½¸¹Á…Ñ¡¹…µ”€¬±½…Ñ¥½¸¹Í•…É¡ôð½Àøì(€€€ô((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½¥Ñ¡Õˆ½…±±‰…¬ýÍÑ…Ñ”õ¥Ñ¡ÕˆµÍÑ…Ñ”™¥¹ÍÑ…±±…Ñ¥½¹}¥ôÄÈÌÐÔ™½‘”õ½…ÕÑ µ½‘”™Í•ÑÕÁ}…Ñ¥½¸õ¥¹ÍÑ…±°uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ½¥Ñ¡Õˆ½…±±‰…¬ˆ•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰…±±‰…­A…”€¼ùô€¼ø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ¨ˆ•±•µ•¹Ðõìñ1½…Ñ¥½¹…ÁÑÕÉ”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½¥¹¥Í¡¥¹œ¥Ñ!Õˆ½¹¹•Ñ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½Í…Ù•…ÁÁ•…É…¹”Í•ÑÑ¥¹Ì½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½Y…±¥‘…Ñ¥¹œÍ•ÍÍ¥½¸½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡½µÁ±•Ñ•¥Ñ!Õ‰½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ ¡ì(€€€€€€€ÍÑ…Ñ”è€¥Ñ¡ÕˆµÍÑ…Ñ”œ°(€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥è€ÄÈÌÐÔ°(€€€€€€€½‘”è€½…ÕÑ µ½‘”œ°(€€€€€€€Í•ÑÕÁ}…Ñ¥½¸è€¥¹ÍÑ…±°œ(€€€€€ô¤(€€€€¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€½µÁ±•Ñ¥½¸¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€É•‘¥É•Ñ}Á…Ñ è€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ(€€€€€ô¤ì(€€€€€…Ý…¥Ð½µÁ±•Ñ¥½¸¹ÁÉ½µ¥Í”ì(€€€ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ±½…Ñ¥½¸œ¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð (€€€€€€€€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ(€€€€€€¤(€€€€¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•È±½…‘ÌÑ¡”¥Ñ!Õˆ½¹¹•Ñ¥½¸…¹ÍÕÉ™…•Ì½¹¹•Ñ¥½¸ÍÑ…ÑÕÌœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ìÍ…¹ÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€½¹ÍÐÉ•Á½Ì€ôÍÉ••¸(€€€€€€€€¹•Ñ±±	åI½±” ±¥¹¬œ°ì¹…µ”è€½yI•Á½Í¥Ñ½É¥•Ì¼ô¤(€€€€€€€€¹™¥¹ ¡±¥¹¬¤€ôø±¥¹¬¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤ü¹ÍÑ…ÉÑÍ]¥Ñ  œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìœ¤¤ì(€€€€€•áÁ•Ð¡É•Á½Ì¤¹Ñ½	••™¥¹• ¤ì(€€€ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€I••¹ÐÍ…¹Ìœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì±¥µ¥Ðè€ÔÀ°Í½ÉÑ}‰äè€ÍÑ…ÉÑ•‘}…Ðœ°Í½ÉÑ}½É‘•Èè€‘•ÍŒœô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•È‘¥ÍÑ¥¹Õ¥Í¡•ÌÁ…ÉÑ¥…°É•Á½Í¥Ñ½ÉäÍ½ÕÉ”½±±•Ñ¥½¸œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÁ…ÉÑ¥…±M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÁ…ÉÑ¥…°œ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°(€€€€€Í½ÕÉ•}¡•…±Ñ è€Á…ÉÑ¥…°œ°(€€€€€Í½ÕÉ•}¡•…±Ñ¡}‘•Ñ…¥±Ìèl(€€€€€€€ì(€€€€€€€€€Í½ÕÉ”è€¥Ñ¡Õ‰}Í•É•Ñ}Í…¹¹¥¹œœ°(€€€€€€€€€ÍÑ…ÑÕÌè€Á•Éµ¥ÍÍ¥½¹}±¥µ¥Ñ•œ°(€€€€€€€€€½‘”è€…±•ÉÑ}±¥ÍÑ}•ÉÉ½Èœ°(€€€€€€€€€µ•ÍÍ…”è€É•Í½ÕÉ”¹½Ð…•ÍÍ¥‰±”‰ä¥¹Ñ•É…Ñ¥½¸œ(€€€€€€€ô(€€€€€t(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ìÍ…¹ÌèmÁ…ÉÑ¥…±M…¹tô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½A…ÉÑ¥…°Í½ÕÉ”½±±•Ñ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ¼À™¥¹‘¥¹Ì½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•È±•…ÉÌ…¡•‘…Í¡‰½…É‘…Ñ„Ý¡•¸Ñ¡”…ÕÑ Í•ÍÍ¥½¸É•Í•ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™¥ÉÍÑI•¹‘•È€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ìÍ…¹ÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡™¥ÉÍÑI•¹‘•È¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€±•…¹ÕÀ ¤ì(€€€Ù¤¹É•ÍÑ½É•±±5½­Ì ¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€ÁÉ½‘ÕÑM¡•±°¹±•…ÉAÉ½‘ÕÑÕÑ¡M•ÍÍ¥½¹…¡•½ÉQ•ÍÑÌ ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÁÉ½©•ÐèÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤ì(€€€½¹ÍÐ¹•áÑM•ÍÍ¥½¹MÑ…ÑÕÌ€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è¥Ñ!Õ‰½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•ÑÕÉ¹Y…±Õ”¡¹•áÑM•ÍÍ¥½¹MÑ…ÑÕÌ¹ÁÉ½µ¥Í”¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆˆ•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1½…‘¥¹œ¥Ñ!ÕˆÍÑ…ÑÕÌ½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€¹•áÑM•ÍÍ¥½¹MÑ…ÑÕÌ¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥è€ØÜàäÀ°(€€€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmt(€€€€€€€ô(€€€€€ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ØÜàäÀ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•È™•Ñ¡•Ì…‘‘¥Ñ¥½¹…°Í…¸Á…•ÌÕ¹Ñ¥°Í•±•Ñ•µÉ•Á½Í¥Ñ½Éä…Ñ¥Ù¥Ñä¥Ì…Ù…¥±…‰±”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÕ¹É•±…Ñ•‘I•Á½M…¹ÌèI•Á½M…¹I•½É‘mt€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€Ìô¤¹µ…À ¡|°¥¹‘•à¤€ôø€¡ì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥èÉ•Á¼µÍ…¸µ½¹ÑÉ½°µ•¹Ñ•ÈµÕ¹É•±…Ñ•´‘í¥¹‘•áõ€°(€€€€€É•Á½Í¥Ñ½ÉäèÑ•…´´‘í¥¹‘•à€¬€Åô½Õ¹É•±…Ñ•‘€(€€€ô¤¤ì(€€€½¹ÍÐÍ•±•Ñ•‘I•Á½M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ½¹ÑÉ½°µ•¹Ñ•ÈµÍ•±•Ñ•œ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄáPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄáPÄÀèÀÔèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È°(€€€€€™¥±•Í}Í…¹¹•è€ÄÜ(€€€ôì((€€€±•ÐÁ…•…±±Ì€ô€Àì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€±¥ÍÑI•Á½M…¹Ìè€ ¤€ôøì(€€€€€€€Á…•…±±Ì€¬ô€Äì(€€€€€€€¥˜€¡Á…•…±±Ì€ôôô€Ä¤ì(€€€€€€€€€É•ÑÕÉ¸AÉ½µ¥Í”¹É•Í½±Ù”¡ì(€€€€€€€€€€€¥Ñ•µÌèÕ¹É•±…Ñ•‘I•Á½M…¹Ì°(€€€€€€€€€€€¹•áÑ}ÕÉÍ½Èè€É•Á¼µÁ…”´Èœ(€€€€€€€€€ô¤ì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸AÉ½µ¥Í”¹É•Í½±Ù”¡ì(€€€€€€€€€¥Ñ•µÌèmÍ•±•Ñ•‘I•Á½M…¹t(€€€€€€€ô¤ì(€€€€€ô(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€•áÁ•Ð¡µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹9Ñ¡…±±•‘]¥Ñ  (€€€€€€È°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÕÉÍ½Èè€É•Á¼µÁ…”´Èœ°±¥µ¥Ðè€ÔÀô¤°(€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€I••¹ÐÍ…¹Ìœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½¥‘•¹ÑÉ…¥±p½¥‘•¹ÑÉ…¥°½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÁÉ½µÁÑÌÑ¼½¹¹•ÐÝ¡•¸¹½Ð½¹¹•Ñ•œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€½¹¹•Ñ•è™…±Í”°(€€€€€€€…½Õ¹Ñ}±½¥¸èÕ¹‘•™¥¹•°(€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥èÕ¹‘•™¥¹•°(€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmt(€€€€€ô°(€€€€€Í…¹Ìèmt(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½9½Ð½¹¹•Ñ•™½ÈÑ¡¥Ì•¹Ù¥É½¹µ•¹Ñp¸½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€½¹ÍÐ¡•É½½¹¹•Ð€ôÍÉ••¸(€€€€€€€€¹•Ñ±±	åI½±” ±¥¹¬œ°ì¹…µ”è€½½¹¹•Ð¥Ñ!Õˆ½¤ô¤(€€€€€€€€¹™¥¹ ¡±¥¹¬¤€ôø±¥¹¬¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤ü¹ÍÑ…ÉÑÍ]¥Ñ  œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðœ¤¤ì(€€€€€•áÁ•Ð¡¡•É½½¹¹•Ð¤¹Ñ½	••™¥¹• ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•È‘½•Ì¹½Ð™±…Í „‘¥Í½¹¹•Ñ•ÍÑ…Ñ”Ý¡¥±”Ñ¡”½¹¹•Ñ¥½¸¥ÌÍÑ¥±°±½…‘¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÁÉ½©•ÐèÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤ì(€€€±•ÐÉ•Í½±Ù•MÑ…ÑÕÌè€ ¡Ù…±Õ”èì½¹¹•Ñ¥½¸è¥Ñ!Õ‰½¹¹•Ñ¥½¹MÑ…ÑÕÌô¤€ôøÙ½¥¤ðÕ¹‘•™¥¹•ì(€€€½¹ÍÐÁ•¹‘¥¹MÑ…ÑÕÌ€ô¹•ÜAÉ½µ¥Í”ñì½¹¹•Ñ¥½¸è¥Ñ!Õ‰½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¡É•Í½±Ù”¤€ôøì(€€€€€É•Í½±Ù•MÑ…ÑÕÌ€ôÉ•Í½±Ù”ì(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•ÑÕÉ¹Y…±Õ”¡Á•¹‘¥¹MÑ…ÑÕÌ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆˆ•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€€¼¼]¡¥±”±½…‘¥¹œ°Ñ¡”Á…”µÕÍÐ¹½Ð±…¥´Ñ¡”ÕÍ•È¥Ì‘¥Í½¹¹•Ñ•¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½9½Ð½¹¹•Ñ•™½ÈÑ¡¥Ì•¹Ù¥É½¹µ•¹Ñp¸½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”ÁÉ¥µ…ÉäQ¥¸Ñ¡”¡•…‘•È¥Ì½µ¥ÑÑ•‘ÕÉ¥¹œÑ¡”¥¹¥Ñ¥…°±½…ƒŠP(€€€€¼¼Ñ¡”M•Ñ¥½¹ÌÉ¥ÍÑ¥±°É•¹‘•ÉÌ¥ÑÌ½Ý¸€‰½¹¹•Ð¥Ñ!Õˆˆ¹…Ù¥…Ñ¥½¸(€€€€¼¼…É°Ý¡¥ ¥Ì™¥¹”¸(€€€•áÁ•Ð¡‘½Õµ•¹Ð¹ÅÕ•ÉåM•±•Ñ½È œ¹¥‘Ðµ‘½µ…¥¸µ¡•…‘•Èµ…Ñ¥½¹Ìœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1½…‘¥¹œ¥Ñ!ÕˆÍÑ…ÑÕÌ½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€€¼¼I•Í½±Ù”…Ì‘¥Í½¹¹•Ñ•ìÑ¡”Á…”Í¡½Õ±¹½ÜÍ¡½ÜÑ¡”É•…°‘¥Í½¹¹•Ñ•U$¸(€€€É•Í½±Ù•MÑ…ÑÕÌü¸¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€½¹¹•Ñ•è™…±Í”°(€€€€€€€…½Õ¹Ñ}±½¥¸èÕ¹‘•™¥¹•°(€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥èÕ¹‘•™¥¹•°(€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmt(€€€€€ô(€€€ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½9½Ð½¹¹•Ñ•™½ÈÑ¡¥Ì•¹Ù¥É½¹µ•¹Ñp¸½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€½¹ÍÐ‰…¹¹•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤ì(€€€€€•áÁ•Ð¡‰…¹¹•È¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” ‘…Ñ„µ‰…¹¹•Èµ¥œ°€½¹¹•Ðœ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÍ¡½ÝÌÑ¡”Õ¹…Ù…¥±…‰±”Í¡•±°Ý¡•¸Ñ¡”¥Ñ!Õˆ½¹¹•Ñ½È¥Ì…Ñ•½™˜œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì¥Ñ¡Õ‰•…ÑÕÉ•±…œè™…±Í”°¥Ñ¡Õ‰	…­•¹è™…±Í”ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆ½¹ÑÉ½°•¹Ñ•Èœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½¥Ñ!Õˆ¥Ì¹½Ð…Ù…¥±…‰±”½¸Ñ¡¥ÌA$½¤ô¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”…±±ÌÍÑ…ÉÑ¥Ñ!Õ‰½¹¹•Ñ½È…¹½Á•¹ÌÑ¡”¥¹ÍÑ…±°UI0œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ½Á•¹MÁä€ôÙ¤¹ÍÁå=¸¡Ý¥¹‘½Ü°€½Á•¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø¹Õ±°¤ì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹¹•Ðœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€½¹¹•Ñ•è™…±Í”°(€€€€€€€…½Õ¹Ñ}±½¥¸èÕ¹‘•™¥¹•°(€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥èÕ¹‘•™¥¹•°(€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐ¥¹ÍÑ…±±	ÕÑÑ½¸€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€%¹ÍÑ…±°¥Ñ!ÕˆÁÀœô¤¥lÁtì(€€€™¥É•Ù•¹Ð¹±¥¬¡¥¹ÍÑ…±±	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÍÑ…ÉÑ¥Ñ!Õ‰½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€€¥¹ÍÑ…±±}…½Õ¹Ñ}ÑåÁ”è€…¹äœ°(€€€€€€€€€É•‘¥É•Ñ}ÕÉ¤è•áÁ•Ð¹ÍÑÉ¥¹5…Ñ¡¥¹œ ½p½…ÁÁp½¥Ñ¡Õ‰p½…±±‰…¬¼¤(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡½Á•¹MÁä¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½…ÁÁÌ½¥‘•¹ÑÉ…¥°½¥¹ÍÑ…±±…Ñ¥½¹Ì½Í•±•Ñ}Ñ…É•ÐýÍÑ…Ñ”õ¥Ñ¡ÕˆµÍÑ…Ñ”œ°(€€€€€€€€}‰±…¹¬œ°(€€€€€€€€¹½½Á•¹•È±¹½É•™•ÉÉ•Èœ(€€€€€€¤(€€€€¤ì((€€€€¼¼¹Ñ•ÉÁÉ¥Í”½APµ…¹…•µ•¹Ð¹½Ü±¥Ù•Ì¥¹±¥¹”½¸Ñ¡”½¹¹•ÐÁ…”€¡Ñ¡”(€€€€¼¼±•…äÁ•ÈµÁÉ½©•ÐÁ…”Ý…ÌÉ•Ñ¥É•¤ìÑ¡”½¹ÑÉ½°½Á•¹ÌÑ¡”™…±±‰…¬™½É´¸(€€€½¹ÍÐ•¹Ñ•ÉÁÉ¥Í•	ÕÑÑ½¹Ì€ôÍÉ••¸¹•Ñ±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½5…¹…”¹Ñ•ÉÁÉ¥Í”p¼AP½¤ô¤ì(€€€•áÁ•Ð¡•¹Ñ•ÉÁÉ¥Í•	ÕÑÑ½¹Ì¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½M…Ù”•¹Ñ•ÉÁÉ¥Í”™…±±‰…¬½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€½Á•¹MÁä¹µ½­I•ÍÑ½É” ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”¥¹½É•ÌÍÑ…±”¥Ñ!ÕˆÁÀ¥¹ÍÑ…±°ÍÑ…ÉÑÌ…™Ñ•È•¹Ù¥É½¹µ•¹Ð¡…¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐ½Á•¹MÁä€ôÙ¤¹ÍÁå=¸¡Ý¥¹‘½Ü°€½Á•¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø¹Õ±°¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐ¥¹ÍÑ…±±MÑ…ÉÐ€ô‘•™•ÉÉ•ñì(€€€€€½¹¹•Ñ¥½¸è¥Ñ!Õ‰½¹¹•Ñ¥½¹MÑ…ÑÕÌì(€€€€€½¹¹•Ñ½É}¥èÍÑÉ¥¹œì(€€€€€ÍÑ…Ñ”èÍÑÉ¥¹œì(€€€€€¥¹ÍÑ…±±}ÕÉ°èÍÑÉ¥¹œì(€€€€€¥¹ÍÑ…±±}…½Õ¹Ñ}ÑåÁ”è€…¹äœì(€€€€€Ý•‰¡½½­}ÕÉ°èÍÑÉ¥¹œì(€€€€€•áÁ¥É•Í}…ÐèÍÑÉ¥¹œì(€€€ôø ¤ì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€½¹¹•Ñ•è™…±Í”°(€€€€€€€…½Õ¹Ñ}±½¥¸èÕ¹‘•™¥¹•°(€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥èÕ¹‘•™¥¹•°(€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmt(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€½¹ÍÐÍÑ…ÉÑ¥Ñ!Õ‰½¹¹•Ñ½È€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÍÑ…ÉÑ¥Ñ!Õ‰½¹¹•Ñ½Èœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø¥¹ÍÑ…±±MÑ…ÉÐ¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€™¥É•Ù•¹Ð¹±¥¬ ¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€%¹ÍÑ…±°¥Ñ!ÕˆÁÀœô¤¥lÁt¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÍÑ…ÉÑ¥Ñ!Õ‰½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ÍÑ…¥¹œµÁ±…Ñ™½É´œ¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€¥¹ÍÑ…±±MÑ…ÉÐ¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€€€ÍÑ…Ñ”è€ÁÉ½‘ÕÑ¥½¸µÍÑ…Ñ”œ°(€€€€€€€¥¹ÍÑ…±±}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½…ÁÁÌ½¥‘•¹ÑÉ…¥°½¥¹ÍÑ…±±…Ñ¥½¹Ì½Í•±•Ñ}Ñ…É•ÐýÍÑ…Ñ”õÁÉ½‘ÕÑ¥½¸µÍÑ…Ñ”œ°(€€€€€€€¥¹ÍÑ…±±}…½Õ¹Ñ}ÑåÁ”è€…¹äœ°(€€€€€€€Ý•‰¡½½­}ÕÉ°è€œ½…ÕÑ ½Ý•‰¡½½­Ì½¥Ñ¡Õˆœ°(€€€€€€€•áÁ¥É•Í}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÄÀèÀÁhœ(€€€€€ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡½Á•¹MÁä¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ±¥¹¬œ°ì¹…µ”è€=Á•¸¥Ñ!Õˆœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½ÁÉ½‘ÕÑ¥½¸µÍÑ…Ñ”½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€½Á•¹MÁä¹µ½­I•ÍÑ½É” ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”É•Í•ÑÌ¹Ñ•ÉÁÉ¥Í”AP‘É…™ÑÌÝ¡•¸•¹Ù¥É½¹µ•¹ÑÌ¡…¹”‰•™½É”ÍÕ‰µ¥Ðœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€½¹ÍÐÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½È€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½Èœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õ‰APô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€™¥É•Ù•¹Ð¹±¥¬ ¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½5…¹…”¹Ñ•ÉÁÉ¥Í”p¼AP½¤ô¤¥lÁt¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ ½¹Ñ•ÉÁÉ¥Í”‰…Í”UI0½¤¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹ÁÉ½‘ÕÑ¥½¸¹•á…µÁ±”œô(€€€ô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½¥ÍÁ±…ä¹…µ”½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€AÉ½‘ÕÑ¥½¸!Lœôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½A•ÉÍ½¹…°…•ÍÌÑ½­•¸½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€ÁÉ½‘ÕÑ¥½¸µÑ½­•¸œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½I•Á½Í¥Ñ½Éä…±±½Ý±¥ÍÐ½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€ÁÉ½½É•Á¼œôô¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½A•ÉÍ½¹…°…•ÍÌÑ½­•¸½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½¹Ñ•ÉÁÉ¥Í”‰…Í”UI0½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½¥ÍÁ±…ä¹…µ”½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½I•Á½Í¥Ñ½Éä…±±½Ý±¥ÍÐ½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½M…Ù”•¹Ñ•ÉÁÉ¥Í”™…±±‰…¬½¤ô¤¤ì((€€€•áÁ•Ð¡ÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½È¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”¥¹½É•ÌÍÑ…±”¹Ñ•ÉÁÉ¥Í”APÍ…Ù•Ì…™Ñ•È•¹Ù¥É½¹µ•¹Ð¡…¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐÁ…ÑM…Ù”€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è¥Ñ!Õ‰½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€½¹ÍÐÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½È€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½Èœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôøÁ…ÑM…Ù”¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€™¥É•Ù•¹Ð¹±¥¬ ¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½5…¹…”¹Ñ•ÉÁÉ¥Í”p¼AP½¤ô¤¥lÁt¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ ½¹Ñ•ÉÁÉ¥Í”‰…Í”UI0½¤¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹ÁÉ½‘ÕÑ¥½¸¹•á…µÁ±”œô(€€€ô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½¥ÍÁ±…ä¹…µ”½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€AÉ½‘ÕÑ¥½¸!Lœôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½A•ÉÍ½¹…°…•ÍÌÑ½­•¸½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€ÁÉ½‘ÕÑ¥½¸µÑ½­•¸œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½I•Á½Í¥Ñ½Éä…±±½Ý±¥ÍÐ½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€ÁÉ½½É•Á¼œôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½M…Ù”•¹Ñ•ÉÁÉ¥Í”™…±±‰…¬½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÕÁÍ•ÉÑ¥Ñ!Õ‰AQ½¹¹•Ñ½È¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€€‰…Í•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹ÁÉ½‘ÕÑ¥½¸¹•á…µÁ±”œ°(€€€€€€€€€Ñ½­•¸è€ÁÉ½‘ÕÑ¥½¸µÑ½­•¸œ°(€€€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•ÌèlÁÉ½½É•Á¼t(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½A•ÉÍ½¹…°…•ÍÌÑ½­•¸½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€Á…ÑM…Ù”¹É•Í½±Ù”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õ‰APô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½¥Ñ!Õˆ¹Ñ•ÉÁÉ¥Í”½¹¹•Ñ½ÈÙ…±¥‘…Ñ•…¹Í…Ù•½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½A•ÉÍ½¹…°…•ÍÌÑ½­•¸½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”±…Õ¹¡•Ì„Í…¸Ù¥„Ñ¡”•á¥ÍÑ¥¹œA$œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹Ìèmtô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐÅÕ•Õ•	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÅÕ•Õ•	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÉÕ¹I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸ÅÕ•Õ•™½È¥‘•¹ÑÉ…¥±p½¥‘•¹ÑÉ…¥°½¤¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”ÉÕ¹Ì½¹”µ½™˜Í…¹ÌÝ¥Ñ •áÁ±¥¥Ð±¥µ¥ÑÌÝ¡•¸¹¼É•Á½Í¥Ñ½É¥•Ì…É”Í•±•Ñ•œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õ‰AP°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmtô°(€€€€€Í…¹Ìèmt(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐ½¹•=™™A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€=¹”µ½™˜É•Á½Í¥Ñ½ÉäÍ…¸œô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€…µ”½ÁÉ¥Ù…Ñ”µÉ•Á¼œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½M…¸µ½‘”½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€ÅÕ¥¬œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½!¥ÍÑ½Éä±¥µ¥Ð½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€œÜÔœôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½5…à™¥¹‘¥¹Ì½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€œÈÔœôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½IÕ¸Í…¸½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÉÕ¹I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½Í¥Ñ½Éäè€…µ”½ÁÉ¥Ù…Ñ”µÉ•Á¼œ°(€€€€€€€€€Í…¹}µ½‘”è€ÅÕ¥¬œ°(€€€€€€€€€¡¥ÍÑ½Éå}±¥µ¥Ðè€ÜÔ°(€€€€€€€€€µ…á}™¥¹‘¥¹Ìè€ÈÔ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€•áÁ•Ð¡µ½­Ì¹ÉÕ¹I•Á½M…¸¹µ½¬¹…±±ÍlÁulÁt¤¹¹½Ð¹Ñ½!…Ù•AÉ½Á•ÉÑä ÁÉ½©•Ñ}¥œ¤ì(€€€•áÁ•Ð¡µ½­Ì¹ÉÕ¹I•Á½M…¸¹µ½¬¹…±±ÍlÁulÁt¤¹¹½Ð¹Ñ½!…Ù•AÉ½Á•ÉÑä ½¹¹•Ñ½É}¥œ¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸ÅÕ•Õ•™½È…µ•p½ÁÉ¥Ù…Ñ”µÉ•Á¼½¤¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”Í½Á•Ì½¹”µ½™˜Í…¹ÌÑ¼Ñ¡”¥Ñ!ÕˆÁÀ½¹¹•Ñ½ÈÝ¡•¸…Ù…¥±…‰±”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹Ìèmtô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐ½¹•=™™A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€=¹”µ½™˜É•Á½Í¥Ñ½ÉäÍ…¸œô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½!¥ÍÑ½Éä±¥µ¥Ð½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€œÄÈÔœôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½5…à™¥¹‘¥¹Ì½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€œÔÀœôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½IÕ¸Í…¸½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÉÕ¹I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€€€€€Í…¹}µ½‘”è€‘••Àœ°(€€€€€€€€€¡¥ÍÑ½Éå}±¥µ¥Ðè€ÄÈÔ°(€€€€€€€€€µ…á}™¥¹‘¥¹Ìè€ÔÀ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸ÅÕ•Õ•™½È¥‘•¹ÑÉ…¥±p½¥‘•¹ÑÉ…¥°½¤¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”É•Í•ÑÌ½¹”µ½™˜Í…¸‘É…™ÑÌÝ¡•¸•¹Ù¥É½¹µ•¹ÑÌ¡…¹”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€ÁÉ½©•ÑÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñt°(€€€€€Í…¹Ìèmt°(€€€€€¥¹¥Ñ¥…±¹ÑÉäè€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐ½¹•=™™A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€=¹”µ½™˜É•Á½Í¥Ñ½ÉäÍ…¸œô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€…µ”½ÁÉ½‘ÕÑ¥½¸µÉ•Á¼œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½M…¸µ½‘”½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€ÅÕ¥¬œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½!¥ÍÑ½Éä±¥µ¥Ð½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€œÜÔœôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½5…à™¥¹‘¥¹Ì½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€œÈÔœôô¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì((€€€½¹ÍÐÉ•Í•ÑA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€=¹”µ½™˜É•Á½Í¥Ñ½ÉäÍ…¸œô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½M…¸µ½‘”½¤¤¤¹Ñ½!…Ù•Y…±Õ” ‘••Àœ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½!¥ÍÑ½Éä±¥µ¥Ð½¤¤¤¹Ñ½!…Ù•Y…±Õ” œÔÀÀœ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½5…à™¥¹‘¥¹Ì½¤¤¤¹Ñ½!…Ù•Y…±Õ” œÈÀÀœ¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”¥¹½É•ÌÍÑ…±”½¹”µ½™˜Í…¸½µÁ±•Ñ¥½¹Ì…™Ñ•È•¹Ù¥É½¹µ•¹Ð¡…¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€ÁÉ½©•ÑÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñt°(€€€€€Í…¹Ìèmt°(€€€€€¥¹¥Ñ¥…±¹ÑÉäè€œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ(€€€ô¤ì(€€€½¹ÍÐ½¹•=™™M…¸€ô‘•™•ÉÉ•ñìÉ•Á½}Í…¸èI•Á½M…¹I•½Éôø ¤ì(€€€µ½­Ì¹ÉÕ¹I•Á½M…¸¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø½¹•=™™M…¸¹ÁÉ½µ¥Í”¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐ½¹•=™™A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€=¹”µ½™˜É•Á½Í¥Ñ½ÉäÍ…¸œô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€…µ”½ÁÉ½‘ÕÑ¥½¸µÉ•Á¼œôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½IÕ¸Í…¸½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÉÕ¹I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½Í¥Ñ½Éäè€…µ”½ÁÉ½‘ÕÑ¥½¸µÉ•Á¼œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì(€€€½¹ÍÐÉ•Í•ÑA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€=¹”µ½™˜É•Á½Í¥Ñ½ÉäÍ…¸œô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€½¹•=™™M…¸¹É•Í½±Ù”¡ìÉ•Á½}Í…¸èÅÕ•Õ•‘I•Á½M…¸ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸ÅÕ•Õ•™½È…µ•p½ÁÉ½‘ÕÑ¥½¸µÉ•Á¼½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”É•Í•ÑÌ½¹”µ½™˜Í…¸ÍÑ…Ñ”Ý¡•¸Ñ¡”Ý½É­ÍÁ…”Í½Á”¡…¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÁÉ½©•ÐèÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”è‘•™…Õ±ÑI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”°(€€€€€½É…¹¥é…Ñ¥½¹}Á½ÍÑÕÉ”è‘•™…Õ±Ñ=É…¹¥é…Ñ¥½¹A½ÍÑÕÉ”(€€€ô¤ì(€€€½¹ÍÐ½¹•=™™M…¸€ô‘•™•ÉÉ•ñìÉ•Á½}Í…¸èI•Á½M…¹I•½Éôø ¤ì(€€€½¹ÍÐÉÕ¹I•Á½M…¸€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÉÕ¹I•Á½M…¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø½¹•=™™M…¸¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½É¥•ÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€™Õ¹Ñ¥½¸]½É­ÍÁ…•MÝ¥Ñ¡!…É¹•ÍÌ ¤ì(€€€€€½¹ÍÐ¹…Ù¥…Ñ”€ôÕÍ•9…Ù¥…Ñ” ¤ì(€€€€€É•ÑÕÉ¸€ (€€€€€€€€ðø(€€€€€€€€€€ñ‰ÕÑÑ½¸(€€€€€€€€€€€ÑåÁ”ô‰‰ÕÑÑ½¸ˆ(€€€€€€€€€€€½¹±¥¬õì ¤€ôø¹…Ù¥…Ñ” œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µˆ½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ¥ô(€€€€€€€€€€ø(€€€€€€€€€€€MÝ¥Ñ Ý½É­ÍÁ…”(€€€€€€€€€€ð½‰ÕÑÑ½¸ø(€€€€€€€€€€ñAÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½É¥•ÍA…”€¼ø(€€€€€€€€ð¼ø(€€€€€€¤ì(€€€ô((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìˆ•±•µ•¹Ðõìñ]½É­ÍÁ…•MÝ¥Ñ¡!…É¹•ÍÌ€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐ½¹•=™™A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€=¹”µ½™˜É•Á½Í¥Ñ½ÉäÍ…¸œô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€…µ”½Ý½É­ÍÁ…”µ„µÉ•Á¼œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½!¥ÍÑ½Éä±¥µ¥Ð½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€œÜÔœôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡½¹•=™™A…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½IÕ¸Í…¸½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÉÕ¹I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½Í¥Ñ½Éäè€…µ”½Ý½É­ÍÁ…”µ„µÉ•Á¼œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€MÝ¥Ñ Ý½É­ÍÁ…”œô¤¤ì(€€€½¹ÍÐÉ•Í•ÑA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€=¹”µ½™˜É•Á½Í¥Ñ½ÉäÍ…¸œô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½!¥ÍÑ½Éä±¥µ¥Ð½¤¤¤¹Ñ½!…Ù•Y…±Õ” œÔÀÀœ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€½¹•=™™M…¸¹É•Í½±Ù”¡ìÉ•Á½}Í…¸èÅÕ•Õ•‘I•Á½M…¸ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸ÅÕ•Õ•™½È…µ•p½Ý½É­ÍÁ…”µ„µÉ•Á¼½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡É•Í•ÑA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½yI•Á½Í¥Ñ½Éä½¤¤¤¹Ñ½!…Ù•Y…±Õ” œœ¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”­••ÁÌÉ•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”¡•­ÌÉ•…¡…‰±”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹ÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐÁ½ÍÑÕÉ•A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€I•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”œô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åQ•áÐ 9¼É•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”½±±•Ñ•å•Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡µ½­Ì¹•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì((€€€½¹ÍÐÉ•Ù¥•Ý	ÕÑÑ½¸€ôÝ¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½I•Ù¥•ÜÁ½ÍÑÕÉ”½¤ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡É•Ù¥•Ý	ÕÑÑ½¸¤¹¹½Ð¹Ñ½	•¥Í…‰±• ¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡É•Ù¥•Ý	ÕÑÑ½¸¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÝ¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹™¥¹‘	åQ•áÐ •™…Õ±Ð‰É…¹ ¥Ìµ¥ÍÍ¥¹œÉ•ÅÕ¥É•ÁÕ±°É•ÅÕ•ÍÐÉ•Ù¥•ÝÌ¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!ÕˆÁ½ÍÑÕÉ”ÍÕµµ…Éäœ¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð M•ÕÉ”Äœ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åQ•áÐ =É…¹¥é…Ñ¥½¸Á½ÍÑÕÉ”œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åQ•áÐ I•Ù¥•Ü€Ä¡•¬œ¤¹±½Í•ÍÐ ‘•Ñ…¥±Ìœ¤¤¹¹½Ð¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” ½Á•¸œ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”­••ÁÌÁ½ÍÑÕÉ”É•Ù¥•Ü½ÁÐµ¥¸…™Ñ•ÈÍÝ¥Ñ¡¥¹œÉ•Á½Í¥Ñ½É¥•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèl¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°€¥‘•¹ÑÉ…¥°½‘½Ìt(€€€€€ô°(€€€€€Í…¹ÌèmÍÕ••‘•‘I•Á½M…¹t(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐÁ½ÍÑÕÉ•A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€I•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”œô¤ì(€€€½¹ÍÐÉ•Á½Í¥Ñ½ÉåM•±•Ð€ôÝ¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	å1…‰•±Q•áÐ I•Á½Í¥Ñ½Éäœ¤ì(€€€½¹ÍÐÉ•Ù¥•Ý	ÕÑÑ½¸€ôÝ¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½I•Ù¥•ÜÁ½ÍÑÕÉ”½¤ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡É•Ù¥•Ý	ÕÑÑ½¸¤¹¹½Ð¹Ñ½	•¥Í…‰±• ¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡É•Ù¥•Ý	ÕÑÑ½¸¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÝ¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹™¥¹‘	åQ•áÐ •™…Õ±Ð‰É…¹ ¥Ìµ¥ÍÍ¥¹œÉ•ÅÕ¥É•ÁÕ±°É•ÅÕ•ÍÐÉ•Ù¥•ÝÌ¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡É•Á½Í¥Ñ½ÉåM•±•Ð°ìÑ…É•ÐèìÙ…±Õ”è€¥‘•¹ÑÉ…¥°½‘½Ìœôô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡É•Á½Í¥Ñ½ÉåM•±•Ð¤¹Ñ½!…Ù•Y…±Õ” ¥‘•¹ÑÉ…¥°½‘½Ìœ¤¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åQ•áÐ 9¼É•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”½±±•Ñ•å•Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡µ½­Ì¹•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡É•Á½Í¥Ñ½ÉåM•±•Ð°ìÑ…É•ÐèìÙ…±Õ”è€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œôô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡É•Á½Í¥Ñ½ÉåM•±•Ð¤¹Ñ½!…Ù•Y…±Õ” ¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ¤¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åQ•áÐ 9¼É•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”½±±•Ñ•å•Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡µ½­Ì¹•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”‘¥Í…‰±•ÌÉ•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”É•Ù¥•Ü™½ÈAP½¹¹•Ñ¥½¹Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õ‰AP°(€€€€€Í…¹ÌèmÍÕ••‘•‘I•Á½M…¹t(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐÁ½ÍÑÕÉ•A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€I•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”œô¤ì(€€€½¹ÍÐÉ•Ù¥•Ý	ÕÑÑ½¸€ôÝ¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½¥Ñ!ÕˆÁÀÉ•ÅÕ¥É•½¤ô¤ì((€€€•áÁ•Ð¡É•Ù¥•Ý	ÕÑÑ½¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€•áÁ•Ð (€€€€€Ý¥Ñ¡¥¸¡Á½ÍÑÕÉ•A…¹•°¤¹•Ñ	åQ•áÐ I•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”¡•­Ì…É”…Ù…¥±…‰±”…™Ñ•È½¹¹•Ñ¥¹œÑ¡¥Ì•¹Ù¥É½¹µ•¹ÐÝ¥Ñ Ñ¡”¥Ñ!ÕˆÁÀ¸œ¤(€€€€¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡É•Ù¥•Ý	ÕÑÑ½¸¤ì(€€€•áÁ•Ð¡µ½­Ì¹•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”‰åÁ…ÍÍ•Ì¥¸µ™±¥¡ÐÉ•™É•Í¡•Ì…™Ñ•ÈÅÕ•Õ•¥¹œ„Í…¸œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ¥¹¥Ñ¥…±5½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹Ìèmtô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡¥¹¥Ñ¥…±5½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€±•…¹ÕÀ ¤ì(€€€Ù¤¹É•ÍÑ½É•±±5½­Ì ¤ì((€€€½¹ÍÐÁ•¹‘¥¹I•™É•Í €ô‘•™•ÉÉ•ñì¥Ñ•µÌèI•Á½M…¹I•½É‘mtì¹•áÑ}ÕÉÍ½ÈüèÍÑÉ¥¹œôø ¤ì(€€€½¹ÍÐÅÕ•Õ•‘™Ñ•É5ÕÑ…Ñ¥½¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ…™Ñ•ÈµµÕÑ…Ñ¥½¸œ(€€€ôì(€€€±•Ð±¥ÍÑ…±±Ì€ô€Àì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€±¥ÍÑI•Á½M…¹Ìè€ ¤€ôøì(€€€€€€€±¥ÍÑ…±±Ì€¬ô€Äì(€€€€€€€¥˜€¡±¥ÍÑ…±±Ì€ôôô€Ä¤ì(€€€€€€€€€É•ÑÕÉ¸Á•¹‘¥¹I•™É•Í ¹ÁÉ½µ¥Í”ì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸AÉ½µ¥Í”¹É•Í½±Ù”¡ì¥Ñ•µÌèmÅÕ•Õ•‘™Ñ•É5ÕÑ…Ñ¥½¹tô¤ì(€€€€€ô(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€½¹ÍÐÅÕ•Õ•	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÅÕ•Õ•	ÕÑÑ½¸¤¹¹½Ð¹Ñ½	•¥Í…‰±• ¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÅÕ•Õ•	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÉÕ¹I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€€€€€ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸ÅÕ•Õ•™½È¥‘•¹ÑÉ…¥±p½¥‘•¹ÑÉ…¥°½¤¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½Í…¸¥¸™±¥¡Ð½¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€Á•¹‘¥¹I•™É•Í ¹É•Í½±Ù”¡ì¥Ñ•µÌèmtô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ M•±•Ñ•É•Á½Í¥Ñ½É¥•Ìœ¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð Í…¸¥¸™±¥¡Ðœ¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”…¹•±Ì…¸…Ñ¥Ù”Í…¸Ù¥„Ñ¡”•á¥ÍÑ¥¹œA$œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹ÌèmÅÕ•Õ•‘I•Á½M…¹tô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐ…¹•±	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€…¹•°Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡…¹•±	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹…¹•±I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€É•Á¼µÍ…¸µÅÕ•Õ•œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸…¹•±•™½È¥‘•¹ÑÉ…¥±p½¥‘•¹ÑÉ…¥°½¤¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”Á½±±ÌÝ¡¥±”É•Á½Í¥Ñ½ÉäÍ…¹Ì…É”…Ñ¥Ù”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÍ•Ñ%¹Ñ•ÉÙ…±MÁä€ôÙ¤¹ÍÁå=¸¡Ý¥¹‘½Ü°€Í•Ñ%¹Ñ•ÉÙ…°œ¤ì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹ÌèmÅÕ•Õ•‘I•Á½M…¹tô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½Í…¸¥¸™±¥¡Ð½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡Í•Ñ%¹Ñ•ÉÙ…±MÁä¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ ¡•áÁ•Ð¹…¹ä¡Õ¹Ñ¥½¸¤°€àÀÀÀ¤(€€€€¤ì(€€€½¹ÍÐÁ½±±…±±‰…¬€ôÍ•Ñ%¹Ñ•ÉÙ…±MÁä¹µ½¬¹…±±Ì¹™¥¹ ¡…±°¤€ôø…±±lÅt€ôôô€àÀÀÀ¤ü¹lÁtì(€€€•áÁ•Ð¡Á½±±…±±‰…¬¤¹Ñ½ÅÕ…°¡•áÁ•Ð¹…¹ä¡Õ¹Ñ¥½¸¤¤ì((€€€…Ð  ¤€ôøì(€€€€€€¡Á½±±…±±‰…¬…Ì€ ¤€ôøÙ½¥¤ ¤ì(€€€ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”Í¡½ÝÌÑ¡”•µÁÑäÍÑ…Ñ”Ý¡•¸¹¼É•Á½Í¥Ñ½É¥•Ì…É”Í•±•Ñ•œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmtô(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½M•±•ÐÉ•Á½Í¥Ñ½É¥•Ì™½È%‘•¹ÑÉ…¥°Ñ¼Ý…Ñ ½¤ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€½¹ÍÐÍ•±•Ñ1¥¹¬€ôÍÉ••¸(€€€€€€€€¹•Ñ±±	åI½±” ±¥¹¬œ¤(€€€€€€€€¹™¥¹ ¡±¥¹¬¤€ôø±¥¹¬¹Ñ•áÑ½¹Ñ•¹Ðü¹¥¹±Õ‘•Ì M•±•ÐÉ•Á½Í¥Ñ½É¥•Ìœ¤¤ì(€€€€€•áÁ•Ð¡Í•±•Ñ1¥¹¬¤¹Ñ½	••™¥¹• ¤ì(€€€€€•áÁ•Ð¡Í•±•Ñ1¥¹¬ü¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤¤¹Ñ½5…Ñ  ½yp½…ÁÁp½Ñ•¹…¹Ðµ…p½Ý½É­ÍÁ…”µ…p½¥Ñ¡Õ‰p½½¹¹•Ð¼¤ì(€€€ô¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”ÍÕÉ™…•Ì„Í…¸•ÉÉ½È¥¹±¥¹”Ý¥Ñ¡½ÕÐ‰É•…­¥¹œ¹…Ù¥…Ñ¥½¸œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€ÉÕ¹I•Á½M…¹ÉÉ½Èèìµ•ÍÍ…”è€É…Ñ”±¥µ¥Ñ•œ°ÍÑ…ÑÕÌè€ÐÈäô(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€½¹ÍÐÅÕ•Õ•	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÅÕ•Õ•	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½I•Á½Í¥Ñ½ÉäÍ…¸•ÉÉ½È½¤ô¤ì(€€€€¼¼9…Ù¥…Ñ¥½¸µÕÍÐÍÑ¥±°Ý½É¬…™Ñ•È„Í…¸•ÉÉ½ÈƒŠPÑ¡”ÁÉ¥µ…ÉäQ¥¸(€€€€¼¼Ñ¡”Á…”¡•…‘•È€¡¥Ñ!Õˆ™¥¹‘¥¹Ì±¥¹¬¤ÍÑ…åÌÉ•…¡…‰±”¸(€€€½¹ÍÐ™¥¹‘¥¹Í1¥¹¬€ôÍÉ••¸(€€€€€€¹•Ñ±±	åI½±” ±¥¹¬œ°ì¹…µ”è€½¥Ñ!Õˆ™¥¹‘¥¹Ì½¤ô¤(€€€€€€¹™¥¹ ¡±¥¹¬¤€ôø±¥¹¬¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤ü¹ÍÑ…ÉÑÍ]¥Ñ  œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½™¥¹‘¥¹Ìœ¤¤ì(€€€•áÁ•Ð¡™¥¹‘¥¹Í1¥¹¬¤¹Ñ½	••™¥¹• ¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”É•¹‘•ÉÌ„½µÁ…ÐÍÕ‰Ñ¥Ñ±”…¹‘É½ÁÌÑ¡”M…¸½Á•É…Ñ¥½¹ÌÉ•™•É•¹”œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹ÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€€¼¼MÕ‰Ñ¥Ñ±”É•™±•ÑÌÑ¡”±¥Ù”É•Á¼½Õ¹Ð…¹Í…¸Ñ½Ñ…±ÌƒŠPÉ•Á±…•Ì(€€€€¼¼Ñ¡”±½¹œ€‰1…Õ¹ °µ½¹¥Ñ½È°…¹…¹•°É•Á½Í¥Ñ½ÉäÍ…¹Ì¸¸¸ˆÑ…±¥¹”¸(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ¼ÄÉ•Á½Í¥Ñ½Éäƒ
Ü€ÄÉ••¹ÐÍ…¸½¤¤ì(€€€€¼¼Q¡”€‰M•±•Ñ•É•Á½Í¥Ñ½É¥•Ì€¼€ÄÉ•Á½Í¥Ñ½Éä¥¸Í½Á”ˆÍÕˆµ¡•…‘•È¥Ì(€€€€¼¼‘É½ÁÁ•ƒŠPÑ¡”Í•Ñ¥½¸¡•…‘¥¹œ¥Ì©ÕÍÐ€‰I•Á½Í¥Ñ½É¥•Ìˆ¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ¼ÄÉ•Á½Í¥Ñ½Éä¥¸Í½Á”½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”€‰I•™•É•¹”€¼M…¸½Á•É…Ñ¥½¹Ìˆ…Í¥‘”€¡Ý¥Ñ Ñ¡É•”µ•Ñ„µ‘½Ì(€€€€¼¼‰Õ±±•ÑÌ¤¥ÌÉ•µ½Ù••¹Ñ¥É•±ä¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€M…¸½Á•É…Ñ¥½¹Ìœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½M…¹ÌÕÍ”Ñ¡”•á¥ÍÑ¥¹œÉ•Á½Í¥Ñ½ÉäÍ…¸A%Íp¸½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½…¹•°¥Ì½¹±ä…Ù…¥±…‰±”Ý¡¥±”„Í…¸¥ÌÅÕ•Õ•½ÈÉÕ¹¹¥¹p¸½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”Ñ¥Ù¥ÑäÍ•Ñ¥½¸¡•…‘•È¥ÌÑ¡”Ñ¥¡Ñ•È€‰I••¹Ð…Ñ¥Ù¥Ñäˆ(€€€€¼¼¥¹ÍÑ•…½˜€‰Ñ¥Ù¥Ñä€¼I••¹ÐÉ•Á½Í¥Ñ½ÉäÍ…¸…Ñ¥Ù¥Ñäˆ¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½I••¹ÐÉ•Á½Í¥Ñ½ÉäÍ…¸…Ñ¥Ù¥Ñä½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€I••¹Ð…Ñ¥Ù¥Ñäœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð Ñ¥½¹ÌÁ…”É•¹‘•ÉÌÑ¡”ÁÉ•µ¥Õ´Ý…¥Ñ¥¹œµ™½Èµ½Ù•É…”Í¡•±°œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” …Ñ¥½¹Ìœ¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!ÕˆÑ¥½¹Ì€¼=%œô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½]½É­™±½Ü…¹=%Á½ÍÑÕÉ”¥ÌÉ½±±¥¹œ½ÕÐ½¤ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ±±	åQ•áÐ ½]½É­™±½Ü¥¹Ù•¹Ñ½Éä½¤¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€½¹ÍÐ½Á•¹I•Á½Í1¥¹¬€ôÍÉ••¸(€€€€€€€€¹•Ñ±±	åI½±” ±¥¹¬œ°ì¹…µ”è€½=Á•¸I•Á½Í¥Ñ½É¥•Ì½¤ô¤(€€€€€€€€¹™¥¹ ¡±¥¹¬¤€ôø±¥¹¬¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤ü¹ÍÑ…ÉÑÍ]¥Ñ  œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìœ¤¤ì(€€€€€•áÁ•Ð¡½Á•¹I•Á½Í1¥¹¬¤¹Ñ½	••™¥¹• ¤ì(€€€ô¤ì(€€€½¹ÍÐ¡½µ•1¥¹¬€ôÍÉ••¸(€€€€€€¹•Ñ±±	åI½±” ±¥¹¬œ°ì¹…µ”è€½¥Ñ!Õˆ¡½µ”½¤ô¤(€€€€€€¹™¥¹ ¡±¥¹¬¤€ôø±¥¹¬¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤ü¹ÍÑ…ÉÑÍ]¥Ñ  œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆœ¤¤ì(€€€•áÁ•Ð¡¡½µ•1¥¹¬¤¹Ñ½	••™¥¹• ¤ì(€ô¤ì((€¥Ð Ñ¥½¹ÌÁ…”É•¹‘•ÉÌÑ¡”Õ¹…Ù…¥±…‰±”Í¡•±°Ý¡•¸Ñ¡”¥Ñ!Õˆ½¹¹•Ñ½È¥Ì…Ñ•½™˜œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” …Ñ¥½¹Ìœ°ì¥Ñ¡Õ‰•…ÑÕÉ•±…œè™…±Í”°¥Ñ¡Õ‰	…­•¹è™…±Í”ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!ÕˆÑ¥½¹Ì€¼=%œô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½¥Ñ!Õˆ¥Ì¹½Ð…Ù…¥±…‰±”½¸Ñ¡¥ÌA$½¤ô¤ì(€ô¤ì((€¥Ð I•µ•‘¥…Ñ¥½¸Á…”Í¡½ÝÌÑ¡”¹•Ù•ÈµÍ…¹¹•ÍÑ…Ñ”œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•µ•‘¥…Ñ¥½¸œ°ìÍ…¹Ìèmt°É•Á½¥¹‘¥¹Ìèmtô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!ÕˆÉ•µ•‘¥…Ñ¥½¸œô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½IÕ¸å½ÕÈ™¥ÉÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸½¤ô¤ì(€€€½¹ÍÐÉ•Á½Í¥Ñ½É¥•Í1¥¹¬€ôÍÉ••¸(€€€€€€¹•Ñ±±	åI½±” ±¥¹¬œ°ì¹…µ”è€½=Á•¸I•Á½Í¥Ñ½É¥•Ì½¤ô¤(€€€€€€¹™¥¹ ¡±¥¹¬¤€ôø±¥¹¬¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤ü¹ÍÑ…ÉÑÍ]¥Ñ  œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìœ¤¤ì(€€€•áÁ•Ð¡É•Á½Í¥Ñ½É¥•Í1¥¹¬¤¹Ñ½	••™¥¹• ¤ì(€ô¤ì((€¥Ð I•µ•‘¥…Ñ¥½¸Á…”ÍÕÉ™…•Ì„™…¥±•Í…¸ÍÑ…Ñ”‰•™½É”Í¡½Ý¥¹œÉ•µ•‘¥…Ñ¥½¸¡É½µ”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÉ•µ•‘¥…Ñ¥½¸µ™…¥±•œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€¥Ñ!ÕˆÁÀ¥¹ÍÑ…±±…Ñ¥½¸…•ÍÌÉ•Ù½­•œ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•µ•‘¥…Ñ¥½¸œ°ìÍ…¹Ìèm™…¥±•‘M…¹t°É•Á½¥¹‘¥¹Ìèmtô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½e½ÕÈ±…ÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸™…¥±•½¤ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½¥Ñ!ÕˆÁÀ¥¹ÍÑ…±±…Ñ¥½¸…•ÍÌÉ•Ù½­•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ Ñ¥½¹…‰±”™¥¹‘¥¹Ìœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð I•µ•‘¥…Ñ¥½¸Á…”ÁÉ•Ù¥•ÝÌ…¹ÁÕ‰±¥Í¡•Ì„™¥àAH½¹±ä…™Ñ•È…ÁÁÉ½Ù…°…Ñ•ÌÁ…ÍÌœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€¥è€™¥¹‘¥¹œµ‘•Á±½åµ•¹ÐµÑ½­•¸œ°(€€€€€Í…¹}¥èÍÕ••‘•‘I•Á½M…¸¹¥°(€€€€€ÑåÁ”è€Í•É•Ñ}•áÁ½ÍÕÉ”œ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€½¹™¥‘•¹•}Í½É”è€À¸äØ°(€€€€€Ñ¥Ñ±”è€]½É­™±½Ü•áÁ½Í•Ì‘•Á±½åµ•¹ÐÑ½­•¸œ°(€€€€€¡Õµ…¹}ÍÕµµ…Éäè€‘•Á±½åµ•¹ÐÑ½­•¸¥Ì½µµ¥ÑÑ•¥¹Ñ¼„¥Ñ!ÕˆÑ¥½¹ÌÝ½É­™±½Ü¸œ°(€€€€€É•µ•‘¥…Ñ¥½¸è€5½Ù”Ñ¡”‘•Á±½åµ•¹ÐÑ½­•¸¥¹Ñ¼¥Ñ!ÕˆÑ¥½¹ÌÍ•É•ÑÌ…¹É½Ñ…Ñ”¥Ð¸œ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€™¥±•}Á…Ñ è€œ¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½‘•Á±½ä¹åµ°œ°(€€€€€±¥¹•}¹Õµ‰•Èè€Äà°(€€€€€‘•Ñ•Ñ½Èè€¥Ñ¡Õ‰}…Ñ¥½¹Í}Í•É•Ðœ°(€€€€€Í½ÕÉ•}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½‰±½ˆ½µ…¥¸¼¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½‘•Á±½ä¹åµ°0Äàœ°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€½Á•¸œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÄÀèÀÁhœ(€€€ôì(€€€½¹ÍÐÁÉ•Ù¥•ÜèI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¹AÉ•Ù¥•Ü€ôì(€€€€€™¥¹‘¥¹œ°(€€€€€É•µ•‘¥…Ñ¥½¸èì(€€€€€€€‘•Ñ•Ñ½Èè€¥Ñ¡Õ‰}…Ñ¥½¹Í}Í•É•Ðœ°(€€€€€€€ÍÕµµ…Éäè€I½Ñ…Ñ”±•…­•‘•Á±½åµ•¹ÐÑ½­•¸œ°(€€€€€€€É¥Í­}ÍÕµµ…Éäè€Q¡”Ñ½­•¸…¸‰”É•ÕÍ•‰ä…¹å½¹”Ý¥Ñ É•Á½Í¥Ñ½Éä¡¥ÍÑ½Éä…•ÍÌ¸œ°(€€€€€€€ÍÑ•ÁÌèlÉ•…Ñ”„¥Ñ!ÕˆÑ¥½¹ÌÍ•É•Ð™½ÈÑ¡”É•Á±…•µ•¹ÐÑ½­•¸œ°€I•µ½Ù”Ñ¡”¥¹±¥¹”Ñ½­•¸™É½´‘•Á±½ä¹åµ°t°(€€€€€€€Í…™•Ñå}¹½Ñ•Ìèl½¹™¥É´Ñ¡”É•Á±…•µ•¹ÐÍ•É•Ð•á¥ÍÑÌ‰•™½É”µ•É¥¹œt°(€€€€€€€Ù…±¥‘…Ñ¥½¸èlIÕ¸Ñ¡”É•Á½Í¥Ñ½ÉäÍ…¸……¥¸œ°€½¹™¥É´Ñ¡”Ý½É­™±½ÜÍÑ¥±°‘•Á±½åÌ™É½´Ñ¡”Í•É•Ðt°(€€€€€€€Í•É•Ñ}É½Ñ…Ñ¥½¸èÑÉÕ”°(€€€€€€€ÁÕ‰±¥Í¡…‰±”èÑÉÕ”°(€€€€€€€•Ù¥‘•¹”èì(€€€€€€€€€™¥¹‘¥¹}¥è™¥¹‘¥¹œ¹¥°(€€€€€€€€€Í…¹}¥è™¥¹‘¥¹œ¹Í…¹}¥°(€€€€€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€€€€€™¥±•}Á…Ñ è™¥¹‘¥¹œ¹™¥±•}Á…Ñ °(€€€€€€€€€±¥¹•}¹Õµ‰•Èè™¥¹‘¥¹œ¹±¥¹•}¹Õµ‰•È(€€€€€€€ô(€€€€€ô°(€€€€€™¥á}ÁÉ}Á±…¸èì(€€€€€€€‰…Í•}‰É…¹ è€µ…¥¸œ°(€€€€€€€‰É…¹¡}¹…µ”è€¥‘•¹ÑÉ…¥°½™¥à½‘•Á±½åµ•¹ÐµÑ½­•¸œ°(€€€€€€€½µµ¥Ñ}µ•ÍÍ…”è€5½Ù”‘•Á±½åµ•¹ÐÑ½­•¸¥¹Ñ¼Ñ¥½¹ÌÍ•É•ÑÌœ°(€€€€€€€ÁÉ}Ñ¥Ñ±”è€5½Ù”‘•Á±½åµ•¹ÐÑ½­•¸¥¹Ñ¼Ñ¥½¹ÌÍ•É•ÑÌœ°(€€€€€€€ÁÉ}‰½‘äè€I•µ•‘¥…Ñ•ÌÑ¡”•áÁ½Í•‘•Á±½åµ•¹ÐÑ½­•¸™¥¹‘¥¹œ¸œ°(€€€€€€€™¥±•ÌèmìÁ…Ñ è€œ¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½‘•Á±½ä¹åµ°œ°½¹Ñ•¹Ðè€•¹Øéqq¸€A1=e}Q=-8è€‘íìÍ•É•ÑÌ¹A1=e}Q=-8õôœõt°(€€€€€€€™¥¹‘¥¹}¥è™¥¹‘¥¹œ¹¥°(€€€€€€€™¥¹‘¥¹}ÑåÁ”è™¥¹‘¥¹œ¹ÑåÁ”(€€€€€ô(€€€ôì(€€€½¹ÍÐÁÕ‰±¥Í èI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¹AÕ‰±¥Í¡I•ÍÁ½¹Í”€ôì(€€€€€™¥¹‘¥¹œ°(€€€€€É•µ•‘¥…Ñ¥½¸èÁÉ•Ù¥•Ü¹É•µ•‘¥…Ñ¥½¸°(€€€€€ÁÕ‰±¥Í èì(€€€€€€€ÁÉ}¹Õµ‰•Èè€ÐÈ°(€€€€€€€ÁÉ}ÕÉ°è€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°½ÁÕ±°¼ÐÈœ°(€€€€€€€‰É…¹¡}¹…µ”è€¥‘•¹ÑÉ…¥°½™¥à½‘•Á±½åµ•¹ÐµÑ½­•¸œ°(€€€€€€€½µµ¥Ñ}Í¡„è€…‰ŒÄÈÌÐœ(€€€€€ô(€€€ôì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•µ•‘¥…Ñ¥½¸œ°ì(€€€€€Í…¹Ìèmì€¸¸¹ÍÕ••‘•‘I•Á½M…¸°™¥¹‘¥¹}½Õ¹Ðè€Äõt°(€€€€€É•Á½¥¹‘¥¹Ìèm™¥¹‘¥¹t°(€€€€€É•µ•‘¥…Ñ¥½¹AÉ•Ù¥•ÜèÁÉ•Ù¥•Ü°(€€€€€É•µ•‘¥…Ñ¥½¹AÕ‰±¥Í èÁÕ‰±¥Í (€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!ÕˆÉ•µ•‘¥…Ñ¥½¸œô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ Ñ¥½¹…‰±”™¥¹‘¥¹Ìœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ±±	åQ•áÐ ]½É­™±½Ü•áÁ½Í•Ì‘•Á±½åµ•¹ÐÑ½­•¸œ¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ±±	åQ•áÐ ¼¹¥Ñ¡Õ‰p½Ý½É­™±½ÝÍp½‘•Á±½ä¹åµ°èÄà½¤¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì((€€€½¹ÍÐÁÉ•Ù¥•Ý	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÉ•Ù¥•Ü™¥àÁ±…¸½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÁÉ•Ù¥•Ý	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÁÉ•Ù¥•ÝI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™¥¹‘¥¹œ¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½}Í…¹}¥èÍÕ••‘•‘I•Á½M…¸¹¥°(€€€€€€€€€™¥¹‘¥¹}ÕÉ°è™¥¹‘¥¹œ¹Í½ÕÉ•}ÕÉ°(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ÕÉÉ•¹ÐÍ½ÕÉ”½¹Ñ•¹Ðœ¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€•¹Øéq¸€A1=e}Q=-8è€‘íìÍ•É•ÑÌ¹A1=e}Q=-8õôœô(€€€ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÁÉ•Ù¥•Ý	ÕÑÑ½¸¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÁÉ•Ù¥•ÝI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™¥¹‘¥¹œ¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½}Í…¹}¥èÍÕ••‘•‘I•Á½M…¸¹¥°(€€€€€€€€€™¥¹‘¥¹}ÕÉ°è™¥¹‘¥¹œ¹Í½ÕÉ•}ÕÉ°°(€€€€€€€€€Í½ÕÉ•}½¹Ñ•¹Ðè€•¹Øéq¸€A1=e}Q=-8è€‘íìÍ•É•ÑÌ¹A1=e}Q=-8õôœ°(€€€€€€€€€É•ÅÕ¥É•}™¥á}Á±…¸èÑÉÕ”(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ I½Ñ…Ñ”±•…­•‘•Á±½åµ•¹ÐÑ½­•¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ 	É…¹ ¥‘•¹ÑÉ…¥°½™¥à½‘•Á±½åµ•¹ÐµÑ½­•¸œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€½¹ÍÐÁÕ‰±¥Í¡	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÕ‰±¥Í ™¥àAH½¤ô¤ì(€€€•áÁ•Ð¡ÁÕ‰±¥Í¡	ÕÑÑ½¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€•áÁ•Ð¡µ½­Ì¹ÁÕ‰±¥Í¡I•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ÕÉÉ•¹ÐÍ½ÕÉ”½¹Ñ•¹Ðœ¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€•¹Øéqq¸€A1=e}Q=-8è€‘íìÍ•É•ÑÌ¹A1=e}Q=-8õôœô(€€€ô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!ÕˆÑ½­•¸œ¤°ìÑ…É•ÐèìÙ…±Õ”è€¡Á}ÝÉ¥Ñ•}Ñ½­•¸œôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ÁÁÉ½Ù•™½ÈÁÕ‰±¥Í œ¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!ÕˆÑ½­•¸¥Ì¥¹Ñ•¹Ñ¥½¹…±±äÝÉ¥Ñ”µ…Á…‰±”œ¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÁÕ‰±¥Í¡	ÕÑÑ½¸¤¹¹½Ð¹Ñ½	•¥Í…‰±• ¤¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÁÕ‰±¥Í¡	ÕÑÑ½¸¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÁÕ‰±¥Í¡I•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€™¥¹‘¥¹œ¹¥°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€É•Á½}Í…¹}¥èÍÕ••‘•‘I•Á½M…¸¹¥°(€€€€€€€€€Í½ÕÉ•}½¹Ñ•¹Ðè€•¹Øéqq¸€A1=e}Q=-8è€‘íìÍ•É•ÑÌ¹A1=e}Q=-8õôœ°(€€€€€€€€€‰…Í•}‰É…¹ è€µ…¥¸œ°(€€€€€€€€€™¥¹‘¥¹}ÕÉ°è™¥¹‘¥¹œ¹Í½ÕÉ•}ÕÉ°°(€€€€€€€€€½Á•É…Ñ½É}…ÁÁÉ½Ù•èÑÉÕ”°(€€€€€€€€€ÝÉ¥Ñ•}Á•Éµ¥ÍÍ¥½¹Í}½¹™¥ÕÉ•èÑÉÕ”°(€€€€€€€€€¥Ñ¡Õ‰}Ñ½­•¸è€¡Á}ÝÉ¥Ñ•}Ñ½­•¸œ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½AH€ŒÐÈ½Á•¹•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÍÕÉ™…•Ì…¸•ÉÉ½ÈÝ¡•¸±¥ÍÑ¥¹œÉ•Á½Í¥Ñ½ÉäÍ…¹Ì™…¥±Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÁÉ½©•ÐèÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•©•Ñ•‘Y…±Õ” (€€€€€¹•Ü…Á¤¹Á¥ÉÉ½È É…Ñ”±¥µ¥Ñ•œ°€ÐÈä¤(€€€€¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆˆ•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½U¹…‰±”Ñ¼±½…¥Ñ!ÕˆÍÑ…ÑÕÌ½¤ô¤ì(€€€€¼¼Q¡”•ÉÉ½ÈÁ…¹•°¥ÌÑ¡”Í¥¹±”Í½ÕÉ”½˜ÑÉÕÑ ƒŠPÑ¡”Á…”µÕÍÐ¹½Ð(€€€€¼¼…±Í¼ÍÁ•Õ±…Ñ”„€‰ÉÕ¸å½ÕÈ™¥ÉÍÐÍ…¸ˆÉ•½µµ•¹‘…Ñ¥½¸½È±…¥´(€€€€¼¼€‰¹¼É•Á½Í¥Ñ½ÉäÍ…¹Ìå•Ðˆ½™˜„™…¥±•™•Ñ ¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½9¼É•Á½Í¥Ñ½ÉäÍ…¹Ìå•Ð½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÉ•ÕÍ•ÌÑ¡”±…ÍÐ±½…‘•‘…Í¡‰½…ÉÝ¡¥±”É•™É•Í¡¥¹œÑ¡”Í…µ”•¹Ù¥É½¹µ•¹Ðœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÁÉ½©•ÐèÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤ì(€€€½¹ÍÐ•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì¥Ñ•µÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐÉ•¹‘•É½¹ÑÉ½±•¹Ñ•È€ô€ ¤€ôø(€€€€€É•¹‘•È (€€€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆˆ•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€€€¤ì((€€€½¹ÍÐ™¥ÉÍÑI•¹‘•È€ôÉ•¹‘•É½¹ÑÉ½±•¹Ñ•È ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€I••¹ÐÍ…¹Ìœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€™¥ÉÍÑI•¹‘•È¹Õ¹µ½Õ¹Ð ¤ì((€€€½¹ÍÐÁ•¹‘¥¹MÑ…ÑÕÌ€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è¥Ñ!Õ‰½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì(€€€½¹ÍÐÁ•¹‘¥¹M…¹Ì€ô‘•™•ÉÉ•ñì¥Ñ•µÌèI•Á½M…¹I•½É‘mtôø ¤ì(€€€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¹µ½­I•ÑÕÉ¹Y…±Õ•=¹”¡Á•¹‘¥¹MÑ…ÑÕÌ¹ÁÉ½µ¥Í”¤ì(€€€±¥ÍÑI•Á½M…¹Ì¹µ½­I•ÑÕÉ¹Y…±Õ•=¹”¡Á•¹‘¥¹M…¹Ì¹ÁÉ½µ¥Í”¤ì((€€€É•¹‘•É½¹ÑÉ½±•¹Ñ•È ¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€I••¹ÐÍ…¹Ìœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1½…‘¥¹œ¥Ñ!ÕˆÍÑ…ÑÕÌ½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€Á•¹‘¥¹MÑ…ÑÕÌ¹É•Í½±Ù”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€€€Á•¹‘¥¹M…¹Ì¹É•Í½±Ù”¡ì¥Ñ•µÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•È­••ÁÌ…¡•Í…¹ÌÙ¥Í¥‰±”Ý¡¥±”ÍÕÉ™…¥¹œÍ…µ”µ•¹Ù¥É½¹µ•¹ÐÉ•™É•Í ™…¥±ÕÉ•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÁÉ½©•ÐèÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤ì(€€€½¹ÍÐ•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì¥Ñ•µÌèmÍÕ••‘•‘I•Á½M…¹tô¤(€€€€€€¹µ½­I•©•Ñ•‘Y…±Õ•=¹”¡¹•Ü…Á¤¹Á¥ÉÉ½È É…Ñ”±¥µ¥Ñ•œ°€ÐÈä¤¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐÉ•¹‘•É½¹ÑÉ½±•¹Ñ•È€ô€ ¤€ôø(€€€€€É•¹‘•È (€€€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆˆ•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€€€¤ì((€€€½¹ÍÐ™¥ÉÍÑI•¹‘•È€ôÉ•¹‘•É½¹ÑÉ½±•¹Ñ•È ¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€I••¹ÐÍ…¹Ìœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€™¥ÉÍÑI•¹‘•È¹Õ¹µ½Õ¹Ð ¤ì((€€€É•¹‘•É½¹ÑÉ½±•¹Ñ•È ¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€I••¹ÐÍ…¹Ìœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½U¹…‰±”Ñ¼±½…¥Ñ!ÕˆÍÑ…ÑÕÌ½¤ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½É…Ñ”±¥µ¥Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÉ•ÕÍ•Ì½Ù•ÉÙ¥•Ü…¡•ÌÝ¥Ñ¡½ÕÐÍ¡½Ý¥¹œ„±½…‘¥¹œÍÑ…ÑÕÌœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ=¹‰½…É‘¥¹MÑ…Ñ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÍÑ…Ñ”èì(€€€€€€€ÕÍ•É}¥è€ÕÍ•È´Äœ°(€€€€€€€½É}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥èÁÉ½‘ÕÑ¥½¹AÉ½©•Ð¹ÁÉ½©•Ñ}¥°(€€€€€€€ÕÉÉ•¹Ñ}ÍÑ•Àè€½µÁ±•Ñ”œ°(€€€€€€€½¹¹•Ñ½É}Í­¥ÁÁ•è™…±Í”°(€€€€€€€Í…¹}Í­¥ÁÁ•è™…±Í”°(€€€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑÌ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€½¹ÍÐ•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmt°ÍÕµµ…ÉäèÕ¹‘•™¥¹•ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ=Ù•ÉÙ¥•ÝA…”°AÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐ½Ù•ÉÙ¥•ÝI•¹‘•È€ôÉ•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%ˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ=Ù•ÉÙ¥•ÝA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€½µ…¥¸Á½ÍÑÕÉ”œô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€½Ù•ÉÙ¥•ÝI•¹‘•È¹Õ¹µ½Õ¹Ð ¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1½…‘¥¹œ¥Ñ!ÕˆÍÑ…ÑÕÌ½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€ô¤ì((€¥Ð =Ù•ÉÙ¥•ÜÝ…ÉµÌ¥Ñ!Õˆ…¡•ÌÝ¡•¸‰…­•¹…Ù…¥±…‰¥±¥ÑäÉ•Í½±Ù•Ì…™Ñ•Èµ½Õ¹Ðœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€±•Ð¥Ñ¡Õ‰	…­•¹è	…­•¹‘•…ÑÕÉ•MÑ…Ñ”€ô™…±Í”ì(€€€Ù¤¹‘½5½¬ œ¸½¡½½­Ì½ÕÍ•	…­•¹‘•…ÑÕÉ•Ìœ°…Íå¹Œ€¡¥µÁ½ÉÑ=É¥¥¹…°¤€ôøì(€€€€€½¹ÍÐ…ÑÕ…°€ô…Ý…¥Ð¥µÁ½ÉÑ=É¥¥¹…°ñÑåÁ•½˜¥µÁ½ÉÐ œ¸½¡½½­Ì½ÕÍ•	…­•¹‘•…ÑÕÉ•Ìœ¤ø ¤ì(€€€€€É•ÑÕÉ¸ì(€€€€€€€€¸¸¹…ÑÕ…°°(€€€€€€€ÕÍ•	…­•¹‘•…ÑÕÉ•Ìè€ ¤€ôø€¡ì(€€€€€€€€€™•…ÑÕÉ•Ìèì(€€€€€€€€€€€½¹‰½…É‘¥¹]¥é…ÉèÕ¹‘•™¥¹•°(€€€€€€€€€€€½¹¹•Ñ½ÉÌèì¥Ñ¡Õˆè¥Ñ¡Õ‰	…­•¹°…ÝÌèÕ¹‘•™¥¹•°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô°(€€€€€€€€€€€½¹™¥I•…¡…‰±”èÑÉÕ”(€€€€€€€€€ô°(€€€€€€€€€±½…‘¥¹œè™…±Í”(€€€€€€€ô¤(€€€€€ôì(€€€ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ=¹‰½…É‘¥¹MÑ…Ñ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÍÑ…Ñ”èì(€€€€€€€ÕÍ•É}¥è€ÕÍ•È´Äœ°(€€€€€€€½É}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥èÁÉ½‘ÕÑ¥½¹AÉ½©•Ð¹ÁÉ½©•Ñ}¥°(€€€€€€€ÕÉÉ•¹Ñ}ÍÑ•Àè€½µÁ±•Ñ”œ°(€€€€€€€½¹¹•Ñ½É}Í­¥ÁÁ•è™…±Í”°(€€€€€€€Í…¹}Í­¥ÁÁ•è™…±Í”°(€€€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑÌ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€½¹ÍÐ•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmt°ÍÕµµ…ÉäèÕ¹‘•™¥¹•ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ=Ù•ÉÙ¥•ÝA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐÉ•¹‘•É=Ù•ÉÙ¥•ÝI½ÕÑ”€ô€ ¤€ôø€ (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%ˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ=Ù•ÉÙ¥•ÝA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì(€€€½¹ÍÐ½Ù•ÉÙ¥•ÝI•¹‘•È€ôÉ•¹‘•È¡É•¹‘•É=Ù•ÉÙ¥•ÝI½ÕÑ” ¤¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€½µ…¥¸Á½ÍÑÕÉ”œô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€•áÁ•Ð¡•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì((€€€¥Ñ¡Õ‰	…­•¹€ôÑÉÕ”ì(€€€½Ù•ÉÙ¥•ÝI•¹‘•È¹É•É•¹‘•È¡É•¹‘•É=Ù•ÉÙ¥•ÝI½ÕÑ” ¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€•áÁ•Ð¡±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð =Ù•ÉÙ¥•ÜÍ­¥ÁÌ‘…Í¡‰½…É…¡”Ý…ÉµÕÁÌ…™Ñ•ÈÑ¡”…ÕÑ Í•ÍÍ¥½¸É•Í•ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌèÑÉÕ”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•ÌèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ=¹‰½…É‘¥¹MÑ…Ñ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÍÑ…Ñ”èì(€€€€€€€ÕÍ•É}¥è€ÕÍ•È´Äœ°(€€€€€€€½É}¥è€Ñ•¹…¹Ðµ„œ°(€€€€€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€€€€€ÁÉ½©•Ñ}¥èÁÉ½‘ÕÑ¥½¹AÉ½©•Ð¹ÁÉ½©•Ñ}¥°(€€€€€€€ÕÉÉ•¹Ñ}ÍÑ•Àè€½µÁ±•Ñ”œ°(€€€€€€€½¹¹•Ñ½É}Í­¥ÁÁ•è™…±Í”°(€€€€€€€Í…¹}Í­¥ÁÁ•è™…±Í”°(€€€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°(€€€€€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€½¹ÍÐÁ•¹‘¥¹AÉ½©•ÑÌ€ô‘•™•ÉÉ•ñì¥Ñ•µÌèÑåÁ•½˜ÁÉ½‘ÕÑ¥½¹AÉ½©•Ñmtôø ¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑÌ€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•ÑÕÉ¹Y…±Õ”¡Á•¹‘¥¹AÉ½©•ÑÌ¹ÁÉ½µ¥Í”¤ì(€€€½¹ÍÐ•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÍÕ••‘•‘I•Á½M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmt°ÍÕµµ…ÉäèÕ¹‘•™¥¹•ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ]MAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘]Lô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ-Õ‰•É¹•Ñ•ÍAÉ½©•Ñ½¹¹•Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘-Õ‰•É¹•Ñ•Ìô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ=Ù•ÉÙ¥•ÝA…”°AÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”°±•…ÉAÉ½‘ÕÑÕÑ¡M•ÍÍ¥½¹…¡•½ÉQ•ÍÑÌô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐ½Ù•ÉÙ¥•ÝI•¹‘•È€ôÉ•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%ˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ=Ù•ÉÙ¥•ÝA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡±¥ÍÑAÉ½©•ÑÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€½Ù•ÉÙ¥•ÝI•¹‘•È¹Õ¹µ½Õ¹Ð ¤ì(€€€±•…ÉAÉ½‘ÕÑÕÑ¡M•ÍÍ¥½¹…¡•½ÉQ•ÍÑÌ ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€Á•¹‘¥¹AÉ½©•ÑÌ¹É•Í½±Ù”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€€€…Ý…¥ÐÁ•¹‘¥¹AÉ½©•ÑÌ¹ÁÉ½µ¥Í”ì(€€€€€…Ý…¥ÐAÉ½µ¥Í”¹É•Í½±Ù” ¤ì(€€€ô¤ì((€€€•áÁ•Ð¡•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€•áÁ•Ð¡±¥ÍÑI•Á½M…¹Ì¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€±•…¹ÕÀ ¤ì(€€€Ù¤¹É•ÍÑ½É•±±5½­Ì ¤ì((€€€½¹ÍÐ¹•áÑM•ÍÍ¥½¹MÑ…ÑÕÌ€ô‘•™•ÉÉ•ñì½¹¹•Ñ¥½¸è¥Ñ!Õ‰½¹¹•Ñ¥½¹MÑ…ÑÕÌôø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•ÑÕÉ¹Y…±Õ”¡¹•áÑM•ÍÍ¥½¹MÑ…ÑÕÌ¹ÁÉ½µ¥Í”¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì((€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹ÑÉ½±•¹Ñ•ÉA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1½…‘¥¹œ¥Ñ!ÕˆÍÑ…ÑÕÌ½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€¹•áÑM•ÍÍ¥½¹MÑ…ÑÕÌ¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥è€ØÜàäÀ°(€€€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmt(€€€€€€€ô(€€€€€ô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ØÜàäÀ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•È¡¥‘•ÌÉ••¹ÐÍ…¹ÌÝ¡•¸¹¼É•Á½Í¥Ñ½É¥•Ì…É”Í•±•Ñ•œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÕ¹É•±…Ñ•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÕ¹É•±…Ñ•œ°(€€€€€É•Á½Í¥Ñ½Éäè€Í½µ•½¹”µ•±Í”½½Ñ¡•ÈµÉ•Á¼œ(€€€ôì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmtô°(€€€€€Í…¹ÌèmÕ¹É•±…Ñ•‘M…¹t(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…ÍÐq¬É•Á½Í¥Ñ½ÉäÍ…¹Ì½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½Í½µ•½¹”µ•±Í•p½½Ñ¡•ÈµÉ•Á¼½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½A¥¬É•Á½Í¥Ñ½É¥•Ì™½È%‘•¹ÑÉ…¥°Ñ¼Ý…Ñ¡p¸½¤¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÍÕÉ™…•ÌÑ¡”µ½ÍÐÉ••¹Ð™…¥±•Í…¸¥¸Ñ¡”‰…¹¹•Èœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ½±‘•ÉMÕ••‘•èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ½±‘•ÈµÍÕ•ÍÌœ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½É••¹Ðµ™…¥°œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÙPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÙPÄÀèÀÔèÀÁhœ(€€€ôì(€€€½¹ÍÐ¹•Ý•É…¥±•èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ¹•Ý•Èµ™…¥±•œ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½É••¹Ðµ™…¥°œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÈèÀÔèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€Í…¸•áÁ±½‘•œ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€ôì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèl¥‘•¹ÑÉ…¥°½É••¹Ðµ™…¥°tô°(€€€€€Í…¹Ìèm¹•Ý•É…¥±•°½±‘•ÉMÕ••‘•‘t(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€€€‘…Ñ„µ‰…¹¹•Èµ¥œ°(€€€€€€€€É•Ù¥•Üµ™…¥±•µÍ…¸œ(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐ‰…¹¹•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åQ•áÐ ½™…¥±•¥ÑÌ±…ÍÐÍ…¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åQ•áÐ ½Í…¸•áÁ±½‘•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•È¥¹½É•Ì„ÍÑ…±”™…¥±ÕÉ”½¹”„¹•Ý•ÈÍÕ•ÍÍ™Õ°Í…¸•á¥ÍÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ½±‘•É…¥±•èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ½±‘•Èµ™…¥°œ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½É•½Ù•É•œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÕPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÕPÄÀèÀÔèÀÁhœ°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€Í…¸•áÁ±½‘•œ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€ôì(€€€½¹ÍÐ¹•Ý•ÉMÕ••‘•èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ¹•Ý•ÈµÍÕ•ÍÌœ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½É•½Ù•É•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÀÔèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€ôì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèl¥‘•¹ÑÉ…¥°½É•½Ù•É•tô°(€€€€€Í…¹Ìèm¹•Ý•ÉMÕ••‘•°½±‘•É…¥±•‘t(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÍÕÉ™…•Ì„ÑÉ¥…”‰…¹¹•ÈÝ¡•¸±…Ñ•ÍÐÍ…¹Ì¡…Ù”½Á•¸™¥¹‘¥¹Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÉ•Á½]¥Ñ¡¥¹‘¥¹ÌèI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ±…Ñ•ÍÐµ¡…Ìµ™¥¹‘¥¹Ìœ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½É•Á¼µ„œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÈÁPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÈÁPÄÀèÀÔèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèl¥‘•¹ÑÉ…¥°½É•Á¼µ„tô°(€€€€€Í…¹ÌèmÉ•Á½]¥Ñ¡¥¹‘¥¹Ít(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€€€‘…Ñ„µ‰…¹¹•Èµ¥œ°(€€€€€€€€ÑÉ¥…”µ™¥¹‘¥¹Ìœ(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐ‰…¹¹•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åQ•áÐ ½I•Á½Í¥Ñ½Éä™¥¹‘¥¹Ì¹••ÑÉ¥…•p¸¼¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½I•Ù¥•Ü½¤ô¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€¡É•˜œ°(€€€€€•áÁ•Ð¹ÍÑÉ¥¹5…Ñ¡¥¹œ ½p½¥Ñ¡Õ‰p½™¥¹‘¥¹Ì¼¤(€€€€¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÑÉ¥…”‰…¹¹•È¥¹½É•Ì™¥¹‘¥¹Ì™É½´½±‘•ÈÍ…¹Ì½¹”Ñ¡”±…Ñ•ÍÐÍ…¸¥Ì±•…¸œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÉ•Á¼€ô€¥‘•¹ÑÉ…¥°½É•Á¼µ±•…É•œì(€€€½¹ÍÐ½±‘•É!…‘¥¹‘¥¹ÌèI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€½±‘•Èµ¡…µ™¥¹‘¥¹Ìœ°(€€€€€É•Á½Í¥Ñ½ÉäèÉ•Á¼°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄåPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄåPÄÀèÀÔèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ì(€€€ôì(€€€½¹ÍÐ±…Ñ•ÍÑ±•…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€±…Ñ•ÍÐµ±•…¸œ°(€€€€€É•Á½Í¥Ñ½ÉäèÉ•Á¼°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÈÁPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÈÁPÄÀèÀÔèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•ÌèmÉ•Á½tô°(€€€€€Í…¹Ìèm±…Ñ•ÍÑ±•…¸°½±‘•É!…‘¥¹‘¥¹Ít(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€ô¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÑÉ¥…”‰…¹¹•ÈÍÕÉÙ¥Ù•Ì„±…Ñ•È…¹•±•Í…¸½Ù•È„ÍÕ•ÍÍ™Õ°Í…¸Ý¥Ñ ™¥¹‘¥¹Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÉ•Á¼€ô€¥‘•¹ÑÉ…¥°½É•Á¼µ…¹•±•µ…™Ñ•Èµ™¥¹‘¥¹Ìœì(€€€½¹ÍÐÍÕ••‘•‘]¥Ñ¡¥¹‘¥¹ÌèI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€ÍÕ••‘•µÝ¥Ñ µ™¥¹‘¥¹Ìœ°(€€€€€É•Á½Í¥Ñ½ÉäèÉ•Á¼°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄåPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄåPÄÀèÀÔèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ì(€€€ôì(€€€½¹ÍÐ…¹•±•‘™Ñ•ÈèI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€…¹•±•µ…™Ñ•Èœ°(€€€€€É•Á½Í¥Ñ½ÉäèÉ•Á¼°(€€€€€ÍÑ…ÑÕÌè€…¹•±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÈÁPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÈÁPÄÀèÀÀèÌÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€É•Á½Í¥Ñ½ÉäÍ…¸…¹•±•‰äÕÍ•Èœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•ÌèmÉ•Á½tô°(€€€€€Í…¹Ìèm…¹•±•‘™Ñ•È°ÍÕ••‘•‘]¥Ñ¡¥¹‘¥¹Ít(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€€€‘…Ñ„µ‰…¹¹•Èµ¥œ°(€€€€€€€€ÑÉ¥…”µ™¥¹‘¥¹Ìœ(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐ‰…¹¹•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åQ•áÐ ½I•Á½Í¥Ñ½Éä™¥¹‘¥¹Ì¹••ÑÉ¥…•p¸¼¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÍ¡½ÝÌ„Í…¸µ¥¸µÁÉ½É•ÍÌ‰…¹¹•È¥¹ÍÑ•…½˜ÁÉ½µÁÑ¥¹œÑ¼ÅÕ•Õ”…¹½Ñ¡•Èœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÅÕ•Õ•‘¥ÉÍÑM…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€ÅÕ•Õ•µ™¥ÉÍÐœ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥¸µÁÉ½É•ÍÌœ°(€€€€€ÍÑ…ÑÕÌè€ÉÕ¹¹¥¹œœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèl¥‘•¹ÑÉ…¥°½¥¸µÁÉ½É•ÍÌtô°(€€€€€Í…¹ÌèmÅÕ•Õ•‘¥ÉÍÑM…¹t(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€€€‘…Ñ„µ‰…¹¹•Èµ¥œ°(€€€€€€€€Í…¸µ¥¸µÁÉ½É•ÍÌœ(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐ‰…¹¹•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åQ•áÐ ½M…¸¥¸ÁÉ½É•ÍÌ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åQ•áÐ ¥‘•¹ÑÉ…¥°½¥¸µÁÉ½É•ÍÌœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹ÅÕ•Éå	åQ•áÐ ½EÕ•Õ”Ñ¡”™¥ÉÍÐÉ•Á½Í¥Ñ½ÉäÍ…¸½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹ÑÉ½°•¹Ñ•ÈÍ¡½ÝÌ…¸…Ñ¥Ù”Í…¸‰…¹¹•ÈÝ¡•¸„™…¥±•Í…¸¥Ì‰•¥¹œÉ•ÑÉ¥•œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ™…¥±•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€™…¥±•µÉ•ÑÉäœ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½É•ÑÉå¥¹œµÉ•Á¼œ°(€€€€€ÍÑ…ÑÕÌè€™…¥±•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÙPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÙPÄÀèÀÔèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°(€€€€€•ÉÉ½É}µ•ÍÍ…”è€Í…¸•áÁ±½‘•œ(€€€ôì(€€€½¹ÍÐÉ•ÑÉåM…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•ÑÉäµ¥¸µÁÉ½É•ÍÌœ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½É•ÑÉå¥¹œµÉ•Á¼œ°(€€€€€ÍÑ…ÑÕÌè€ÉÕ¹¹¥¹œœ(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹ÑÉ½°µ•¹Ñ•Èœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèl¥‘•¹ÑÉ…¥°½É•ÑÉå¥¹œµÉ•Á¼tô°(€€€€€Í…¹ÌèmÉ•ÑÉåM…¸°™…¥±•‘M…¹t(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤¤¹Ñ½!…Ù•ÑÑÉ¥‰ÕÑ” (€€€€€€€€‘…Ñ„µ‰…¹¹•Èµ¥œ°(€€€€€€€€Í…¸µ¥¸µÁÉ½É•ÍÌœ(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐ‰…¹¹•È€ôÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ¥Ñ!Õˆ…Ñ¥½¸É•½µµ•¹‘…Ñ¥½¸œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹ÅÕ•Éå	åQ•áÐ ½™…¥±•¥ÑÌ±…ÍÐÍ…¸½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åQ•áÐ ½M…¸¥¸ÁÉ½É•ÍÌ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡‰…¹¹•È¤¹•Ñ	åQ•áÐ ¥‘•¹ÑÉ…¥°½É•ÑÉå¥¹œµÉ•Á¼œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”É•¹‘•ÉÌ…¸=Á•¸¥Ñ!Õˆ™…±±‰…¬±¥¹¬Ý¡•¸Ñ¡”¥¹ÍÑ…±°Á½ÁÕÀ¥Ì‰±½­•œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ½Á•¹MÁä€ôÙ¤¹ÍÁå=¸¡Ý¥¹‘½Ü°€½Á•¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø¹Õ±°¤ì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹¹•Ðœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€½¹¹•Ñ•è™…±Í”°(€€€€€€€…½Õ¹Ñ}±½¥¸èÕ¹‘•™¥¹•°(€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥èÕ¹‘•™¥¹•°(€€€€€€€Í•±•Ñ•‘}É•Á½Í¥Ñ½É¥•Ìèmt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐ¥¹ÍÑ…±±	ÕÑÑ½¸€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€%¹ÍÑ…±°¥Ñ!ÕˆÁÀœô¤¥lÁtì(€€€™¥É•Ù•¹Ð¹±¥¬¡¥¹ÍÑ…±±	ÕÑÑ½¸¤ì((€€€½¹ÍÐ™…±±‰…¬€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ±¥¹¬œ°ì¹…µ”è€=Á•¸¥Ñ!Õˆœô¤ì(€€€•áÁ•Ð¡™…±±‰…¬¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤¤¹Ñ½	” (€€€€€€¡ÑÑÁÌè¼½¥Ñ¡Õˆ¹½´½…ÁÁÌ½¥‘•¹ÑÉ…¥°½¥¹ÍÑ…±±…Ñ¥½¹Ì½Í•±•Ñ}Ñ…É•ÐýÍÑ…Ñ”õ¥Ñ¡ÕˆµÍÑ…Ñ”œ(€€€€¤ì(€€€•áÁ•Ð¡½Á•¹MÁä¤¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€½Á•¹MÁä¹µ½­I•ÍÑ½É” ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”Í¡½ÝÌÑ¡”µ…¹…”Ù¥•ÜÝ¥Ñ ¥¹ÍÑ…±±…Ñ¥½¸™…ÑÌÝ¡•¸…±É•…‘ä½¹¹•Ñ•œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹¹•Ðœ°ì¥Ñ¡Õ‰½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€½¹¹•Ð¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½%¹ÍÑ…±±…Ñ¥½¸€ÄÈÌÐÔ½¤¤ì(€€€½¹ÍÐ¥¹ÍÑ…±±…Ñ¥½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€¥Ñ!Õˆ¥¹ÍÑ…±±…Ñ¥½¸œô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡¥¹ÍÑ…±±…Ñ¥½¸¤¹•Ñ	åQ•áÐ ½Õ¹Ðœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡¥¹ÍÑ…±±…Ñ¥½¸¤¹•Ñ	åQ•áÐ ¥‘•¹ÑÉ…¥°œ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡¥¹ÍÑ…±±…Ñ¥½¸¤¹•Ñ	åQ•áÐ M•±•Ñ•É•Á½Í¥Ñ½É¥•Ìœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”É•¥¹ÍÑ…±°…™™½É‘…¹”…¹Ñ¡”¹Ñ•ÉÁÉ¥Í”½APµ…¹…•µ•¹Ð½¹ÑÉ½°…É”(€€€€¼¼‰½Ñ É•…¡…‰±”™É½´Ñ¡”µ…¹…”Ù¥•Ü¸(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡¥¹ÍÑ…±±…Ñ¥½¸¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€%¹ÍÑ…±°¥Ñ!ÕˆÁÀœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡¥¹ÍÑ…±±…Ñ¥½¸¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½5…¹…”¹Ñ•ÉÁÉ¥Í”p¼AP½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”Á…”µÕÍÐ¹½Ð…±Í¼É•¹‘•ÈÑ¡”‘¥Í½¹¹•Ñ•€‰%¹ÍÑ…±°Ñ¡”%‘•¹ÑÉ…¥°(€€€€¼¼¥Ñ!ÕˆÁÀˆ¥¹ÍÑ…±°…É½¸Ñ½À½˜Ñ¡”µ…¹…”Ù¥•Ü¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” É•¥½¸œ°ì¹…µ”è€%¹ÍÑ…±°¥Ñ!ÕˆÁÀœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”­••ÁÌÍ…¸Á½±¥äµ…¹…•µ•¹ÐÉ•…¡…‰±”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” ½¹¹•Ðœ°ì(€€€€€¥Ñ¡Õ‰½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€Í…¹A½±¥¥•Ìèm‘•™…Õ±ÑM…¹A½±¥åt(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€½¹¹•Ð¥Ñ!Õˆœô¤ì(€€€½¹ÍÐÁ½±¥åA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€M…¸Á½±¥äµ…¹…•µ•¹Ðœô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€M…¸Á½±¥äœô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	åQ•áÐ •™…Õ±ÐÁ½±¥äœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì±¥µ¥Ðè€ÔÀ°Í½ÉÑ}‰äè€ÕÁ‘…Ñ•‘}…Ðœ°Í½ÉÑ}½É‘•Èè€‘•ÍŒœô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½QÉ¥•Èµ½‘”½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€¡å‰É¥œôô¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½É½¸Í¡•‘Õ±”½¤¤°ìÑ…É•ÐèìÙ…±Õ”è€œÀ€¨€¨€¨€¨œôô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½M…Ù”Í…¸Á½±¥ä½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹ÕÁÍ•ÉÑAÉ½©•ÑM…¹A½±¥ä¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ì(€€€€€€€€€Á½±¥å}¥è€‘•™…Õ±Ðœ°(€€€€€€€€€ÑÉ¥•É}µ½‘”è€¡å‰É¥œ°(€€€€€€€€€É½¸è€œÀ€¨€¨€¨€¨œ(€€€€€€€ô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y•±•Ñ”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡µ½­Ì¹‘•±•Ñ•AÉ½©•ÑM…¹A½±¥ä¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€‘•™…Õ±Ðœ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”¥¹½É•ÌÍÑ…±”Í…¸Á½±¥äÉ•ÍÁ½¹Í•Ì…™Ñ•È•¹Ù¥É½¹µ•¹Ð¡…¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐÁÉ½‘ÕÑ¥½¹A½±¥å1½…€ô‘•™•ÉÉ•ñì¥Ñ•µÌèM…¹A½±¥åI•½É‘mtôø ¤ì(€€€½¹ÍÐÍÑ…¥¹A½±¥å1½…€ô‘•™•ÉÉ•ñì¥Ñ•µÌèM…¹A½±¥åI•½É‘mtôø ¤ì(€€€½¹ÍÐÁÉ½‘ÕÑ¥½¹A½±¥äèM…¹A½±¥åI•½É€ôì(€€€€€€¸¸¹‘•™…Õ±ÑM…¹A½±¥ä°(€€€€€Á½±¥å}¥è€ÁÉ½‘ÕÑ¥½¸µ½¹±äœ°(€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸ÍÑ…±”Á½±¥äœ(€€€ôì(€€€½¹ÍÐÍÑ…¥¹A½±¥äèM…¹A½±¥åI•½É€ôì(€€€€€€¸¸¹‘•™…Õ±ÑM…¹A½±¥ä°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€Á½±¥å}¥è€ÍÑ…¥¹œµ½¹±äœ°(€€€€€¹…µ”è€MÑ…¥¹œÁ½±¥äœ(€€€ôì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ (€€€€€€¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€€€ÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹A½±¥å1½…¹ÁÉ½µ¥Í”€èÁÉ½‘ÕÑ¥½¹A½±¥å1½…¹ÁÉ½µ¥Í”(€€€€¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹…¹åÑ¡¥¹œ ¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹…¹åÑ¡¥¹œ ¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÍÑ…¥¹A½±¥å1½…¹É•Í½±Ù”¡ì¥Ñ•µÌèmÍÑ…¥¹A½±¥åtô¤ì(€€€ô¤ì(€€€½¹ÍÐÁ½±¥åA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€M…¸Á½±¥äµ…¹…•µ•¹Ðœô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÝ¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹™¥¹‘	åQ•áÐ MÑ…¥¹œÁ½±¥äœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÁÉ½‘ÕÑ¥½¹A½±¥å1½…¹É•Í½±Ù”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹A½±¥åtô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	åQ•áÐ MÑ…¥¹œÁ½±¥äœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹ÅÕ•Éå	åQ•áÐ AÉ½‘ÕÑ¥½¸ÍÑ…±”Á½±¥äœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”É•Í•ÑÌÍ…¸Á½±¥ä‘É…™ÑÌ™½È•µÁÑä•¹Ù¥É½¹µ•¹ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐÁÉ½‘ÕÑ¥½¹A½±¥äèM…¹A½±¥åI•½É€ôì(€€€€€€¸¸¹‘•™…Õ±ÑM…¹A½±¥ä°(€€€€€Á½±¥å}¥è€ÁÉ½‘ÕÑ¥½¸µ•Ù•¹ÐµÁ½±¥äœ°(€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ°(€€€€€ÑÉ¥•É}µ½‘”è€•Ù•¹Ðœ(€€€ôì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ì¥Ñ•µÌèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€ümt€èmÁÉ½‘ÕÑ¥½¹A½±¥åtô¤(€€€€¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å¥ÍÁ±…åY…±Õ” AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	åI½±” É•¥½¸œ°ì¹…µ”è€M…¸Á½±¥äµ…¹…•µ•¹Ðœô¤¤¹•Ñ	å1…‰•±Q•áÐ ½A½±¥ä¹…µ”½¤¤¤(€€€€€€€€¹Ñ½!…Ù•Y…±Õ” •™…Õ±ÐÁ½±¥äœ¤(€€€€¤ì(€€€½¹ÍÐÕÉÉ•¹ÑA½±¥åA…¹•°€ôÍÉ••¸¹•Ñ	åI½±” É•¥½¸œ°ì¹…µ”è€M…¸Á½±¥äµ…¹…•µ•¹Ðœô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å¥ÍÁ±…åY…±Õ” AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÕÉÉ•¹ÑA½±¥åA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½QÉ¥•Èµ½‘”½¤¤¤¹Ñ½!…Ù•Y…±Õ” µ…¹Õ…°œ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”É•Í•ÑÌÍ…¸Á½±¥ä‘É…™ÑÌÝ¡•¸•¹Ù¥É½¹µ•¹ÐÁ½±¥ä±½…‘¥¹œ™…¥±Ìœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐÁÉ½‘ÕÑ¥½¹A½±¥äèM…¹A½±¥åI•½É€ôì(€€€€€€¸¸¹‘•™…Õ±ÑM…¹A½±¥ä°(€€€€€Á½±¥å}¥è€ÁÉ½‘ÕÑ¥½¸µ•Ù•¹ÐµÁ½±¥äœ°(€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ°(€€€€€ÑÉ¥•É}µ½‘”è€•Ù•¹Ðœ(€€€ôì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€ÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€€€€€€üAÉ½µ¥Í”¹É•©•Ð¡¹•Ü…Á¤¹Á¥ÉÉ½È Í…¸Á½±¥äÕ¹…Ù…¥±…‰±”œ°€ÔÀÌ¤¤(€€€€€€€€èAÉ½µ¥Í”¹É•Í½±Ù”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹A½±¥åtô¤(€€€€¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å¥ÍÁ±…åY…±Õ” AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” …±•ÉÐœ¤ì(€€€½¹ÍÐÕÉÉ•¹ÑA½±¥åA…¹•°€ôÍÉ••¸¹•Ñ	åI½±” É•¥½¸œ°ì¹…µ”è€M…¸Á½±¥äµ…¹…•µ•¹Ðœô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å¥ÍÁ±…åY…±Õ” AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÕÉÉ•¹ÑA½±¥åA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½A½±¥ä¹…µ”½¤¤¤¹Ñ½!…Ù•Y…±Õ” •™…Õ±ÐÁ½±¥äœ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÕÉÉ•¹ÑA½±¥åA…¹•°¤¹•Ñ	å1…‰•±Q•áÐ ½QÉ¥•Èµ½‘”½¤¤¤¹Ñ½!…Ù•Y…±Õ” µ…¹Õ…°œ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”¥¹½É•ÌÍÑ…±”Í…¸Á½±¥äÍ…Ù•Ì…™Ñ•È•¹Ù¥É½¹µ•¹Ð¡…¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐÁÉ½‘ÕÑ¥½¹A½±¥äèM…¹A½±¥åI•½É€ôì(€€€€€€¸¸¹‘•™…Õ±ÑM…¹A½±¥ä°(€€€€€Á½±¥å}¥è€ÁÉ½‘ÕÑ¥½¸µ•Ù•¹ÐµÁ½±¥äœ°(€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ°(€€€€€ÑÉ¥•É}µ½‘”è€•Ù•¹Ðœ(€€€ôì(€€€½¹ÍÐÍÑ…¥¹A½±¥å1½…€ô‘•™•ÉÉ•ñì¥Ñ•µÌèM…¹A½±¥åI•½É‘mtôø ¤ì(€€€½¹ÍÐÍ…Ù•A½±¥ä€ô‘•™•ÉÉ•ñìÁ½±¥äèM…¹A½±¥åI•½Éôø ¤ì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ (€€€€€€¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€€€ÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹A½±¥å1½…¹ÁÉ½µ¥Í”€èAÉ½µ¥Í”¹É•Í½±Ù”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹A½±¥åtô¤(€€€€¤ì(€€€½¹ÍÐÕÁÍ•ÉÑAÉ½©•ÑM…¹A½±¥ä€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÕÁÍ•ÉÑAÉ½©•ÑM…¹A½±¥äœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôøÍ…Ù•A½±¥ä¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÁ½±¥åA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€M…¸Á½±¥äµ…¹…•µ•¹Ðœô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÝ¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹™¥¹‘	å¥ÍÁ±…åY…±Õ” AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½M…Ù”Í…¸Á½±¥ä½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÕÁÍ•ÉÑAÉ½©•ÑM…¹A½±¥ä¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÁ½±¥å}¥è€ÁÉ½‘ÕÑ¥½¸µ•Ù•¹ÐµÁ½±¥äœô¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹…¹åÑ¡¥¹œ ¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÍÑ…¥¹A½±¥å1½…¹É•Í½±Ù”¡ì¥Ñ•µÌèmtô¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½A½±¥ä¹…µ”½¤¤¤¹Ñ½!…Ù•Y…±Õ” •™…Õ±ÐÁ½±¥äœ¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€Í…Ù•A½±¥ä¹É•Í½±Ù”¡ìÁ½±¥äèì€¸¸¹ÁÉ½‘ÕÑ¥½¹A½±¥ä°¹…µ”è€M…Ù•ÁÉ½‘ÕÑ¥½¸Á½±¥äœôô¤ì(€€€ô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ M…¸Á½±¥äÍ…Ù•¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å¥ÍÁ±…åY…±Õ” M…Ù•ÁÉ½‘ÕÑ¥½¸Á½±¥äœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì¹µ½¬¹…±±Ì¹™¥±Ñ•È ¡…±°¤€ôø…±±lÅt€ôôô€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ¤¤¹Ñ½!…Ù•1•¹Ñ  Ä¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”¥¹½É•ÌÍÑ…±”Í…¸Á½±¥ä‘•±•Ñ•Ì…™Ñ•È•¹Ù¥É½¹µ•¹Ð¡…¹•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐÁÉ½‘ÕÑ¥½¹A½±¥äèM…¹A½±¥åI•½É€ôì(€€€€€€¸¸¹‘•™…Õ±ÑM…¹A½±¥ä°(€€€€€Á½±¥å}¥è€ÁÉ½‘ÕÑ¥½¸µ•Ù•¹ÐµÁ½±¥äœ°(€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ°(€€€€€ÑÉ¥•É}µ½‘”è€•Ù•¹Ðœ(€€€ôì(€€€½¹ÍÐÍÑ…¥¹A½±¥å1½…€ô‘•™•ÉÉ•ñì¥Ñ•µÌèM…¹A½±¥åI•½É‘mtôø ¤ì(€€€½¹ÍÐ‘•±•Ñ•A½±¥ä€ô‘•™•ÉÉ•ñÙ½¥ø ¤ì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€½¹ÍÐ±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ (€€€€€€¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€€€ÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹A½±¥å1½…¹ÁÉ½µ¥Í”€èAÉ½µ¥Í”¹É•Í½±Ù”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹A½±¥åtô¤(€€€€¤ì(€€€½¹ÍÐ‘•±•Ñ•AÉ½©•ÑM…¹A½±¥ä€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€‘•±•Ñ•AÉ½©•ÑM…¹A½±¥äœ¤(€€€€€€¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôø‘•±•Ñ•A½±¥ä¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÁ½±¥åA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” É•¥½¸œ°ì¹…µ”è€M…¸Á½±¥äµ…¹…•µ•¹Ðœô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÝ¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹™¥¹‘	åQ•áÐ AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡Á½±¥åA…¹•°¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y•±•Ñ”½¤ô¤¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡‘•±•Ñ•AÉ½©•ÑM…¹A½±¥ä¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€€ÁÉ½‘ÕÑ¥½¸µ•Ù•¹ÐµÁ½±¥äœ°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  (€€€€€€€€Ý½É­ÍÁ…”µ„œ°(€€€€€€€€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€€€•áÁ•Ð¹…¹åÑ¡¥¹œ ¤°(€€€€€€€•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÑ•¹…¹Ñ%è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•%è€Ý½É­ÍÁ…”µ„œô¤(€€€€€€¤(€€€€¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÍÑ…¥¹A½±¥å1½…¹É•Í½±Ù”¡ì¥Ñ•µÌèmtô¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ ½A½±¥ä¹…µ”½¤¤¤¹Ñ½!…Ù•Y…±Õ” •™…Õ±ÐÁ½±¥äœ¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€‘•±•Ñ•A½±¥ä¹É•Í½±Ù” ¤ì(€€€ô¤ì((€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ M…¸Á½±¥äÁÉ½‘ÕÑ¥½¸µ•Ù•¹ÐµÁ½±¥ä‘•±•Ñ•¸œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ì¹µ½¬¹…±±Ì¹™¥±Ñ•È ¡…±°¤€ôø…±±lÅt€ôôô€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ¤¤¹Ñ½!…Ù•1•¹Ñ  Ä¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”±•…ÉÌ½±Í…¸Á½±¥äÉ½ÝÌÝ¡¥±”±½…‘¥¹œ„¹•Ü•¹Ù¥É½¹µ•¹Ðœ°…Íå¹Œ€ ¤€ôøì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€½¹ÍÐÍÑ…¥¹AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€½¹ÍÐÁÉ½‘ÕÑ¥½¹A½±¥äèM…¹A½±¥åI•½É€ôì(€€€€€€¸¸¹‘•™…Õ±ÑM…¹A½±¥ä°(€€€€€Á½±¥å}¥è€ÁÉ½‘ÕÑ¥½¸µ•Ù•¹ÐµÁ½±¥äœ°(€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ°(€€€€€ÑÉ¥•É}µ½‘”è€•Ù•¹Ðœ(€€€ôì(€€€½¹ÍÐÍÑ…¥¹A½±¥å1½…€ô‘•™•ÉÉ•ñì¥Ñ•µÌèM…¹A½±¥åI•½É‘mtôø ¤ì((€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°ÍÑ…¥¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€AÉ½µ¥Í”¹É•Í½±Ù”¡ìÁÉ½©•ÐèÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹AÉ½©•Ð€èÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑM…¹A½±¥¥•Ìœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ ¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø(€€€€€ÁÉ½©•Ñ%€ôôô€ÍÑ…¥¹œµÁ±…Ñ™½É´œ€üÍÑ…¥¹A½±¥å1½…¹ÁÉ½µ¥Í”€èAÉ½µ¥Í”¹É•Í½±Ù”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹A½±¥åtô¤(€€€€¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€™¥É•Ù•¹Ð¹¡…¹”¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€ô¤ì((€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ AÉ½‘ÕÑ¥½¸•Ù•¹ÐÁ½±¥äœ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½y•±•Ñ”½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½¹¹•ÐÁ…”¡¥‘•ÌÑ¡”¥¹ÍÑ…±°½µ…¹…”‰½‘äÝ¡•¸Ñ¡”½¹¹•Ñ¥½¸ÍÑ…ÑÕÌÉ•ÅÕ•ÍÐ™…¥±Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁÉ½‘ÕÑ¥½¹AÉ½©•Ñtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÁÉ½©•ÐèÁÉ½‘ÕÑ¥½¹AÉ½©•Ðô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•©•Ñ•‘Y…±Õ” (€€€€€¹•Ü…Á¤¹Á¥ÉÉ½È É…Ñ”±¥µ¥Ñ•œ°€ÐÈä¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½½¹¹•Ðuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½½¹¹•Ðˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰½¹¹•ÑA…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€½¹¹•Ð¥Ñ!Õˆœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½U¹…‰±”Ñ¼±½…½¹¹•Ñ¥½¸ÍÑ…ÑÕÌ½¤ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” É•¥½¸œ°ì¹…µ”è€%¹ÍÑ…±°¥Ñ!ÕˆÁÀœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” É•¥½¸œ°ì¹…µ”è€¥Ñ!Õˆ¥¹ÍÑ…±±…Ñ¥½¸œô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼]¡•¸Ñ¡”ÍÑ…ÑÕÌÉ•ÅÕ•ÍÐ™…¥±ÌÑ¡”½¹¹•Ñ¥½¸ÍÑ…Ñ”¥ÌÕ¹­¹½Ý¸°Í¼(€€€€¼¼Ñ¡”¡•…‘•ÈµÕÍÐ¹½Ð±…¥´€‰9½Ð½¹¹•Ñ•ˆ…¹µÕÍÐ¹½ÐÍÕÉ™…”„(€€€€¼¼ÍÁ•Õ±…Ñ¥Ù”¥¹ÍÑ…±°½½Á•¸QƒŠPÑ¡”•ÉÉ½ÈÁ…¹•°¥ÌÑ¡”Í¥¹±”(€€€€¼¼Í½ÕÉ”½˜ÑÉÕÑ ¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½9½Ð½¹¹•Ñ•™½ÈÑ¡¥Ì•¹Ù¥É½¹µ•¹Ñp¸½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½U¹…‰±”Ñ¼±½…¥Ñ!ÕˆÍÑ…ÑÕÍp¸½¤¤ì(€€€•áÁ•Ð¡‘½Õµ•¹Ð¹ÅÕ•ÉåM•±•Ñ½È œ¹¥‘Ðµ‘½µ…¥¸µ¡•…‘•Èµ…Ñ¥½¹Ìœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð (€€€€€ÍÉ••¸¹ÅÕ•Éå±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½%¹ÍÑ…±°¥Ñ!ÕˆÁÀ½¤ô¤(€€€€¤¹Ñ½!…Ù•1•¹Ñ  À¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”…Ñ¥Ù¥ÑäÑ¥µ•±¥¹”¥¹½É•ÌÍ…¹Ì™½ÈÕ¹Í•±•Ñ•É•Á½Í¥Ñ½É¥•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÕ¹É•±…Ñ•‘M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÕ¹É•±…Ñ•œ°(€€€€€É•Á½Í¥Ñ½Éäè€Í½µ•½¹”µ•±Í”½½Ñ¡•ÈµÉ•Á¼œ(€€€ôì(€€€…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹ÌèmÕ¹É•±…Ñ•‘M…¹tô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€I••¹Ð…Ñ¥Ù¥Ñäœô¤ì(€€€½¹ÍÐ…Ñ¥Ù¥Ñä€ôÍÉ••¸¹•Ñ	åI½±” É•¥½¸œ°ì¹…µ”è€I••¹ÐÉ•Á½Í¥Ñ½ÉäÍ…¸…Ñ¥Ù¥Ñäœô¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡…Ñ¥Ù¥Ñä¤¹•Ñ	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½9¼É•Á½Í¥Ñ½ÉäÍ…¹ÌÉ•½É‘•å•Ð½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½Í½µ•½¹”µ•±Í•p½½Ñ¡•ÈµÉ•Á¼½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”™•Ñ¡•Ì…‘‘¥Ñ¥½¹…°Í…¸Á…•ÌÕ¹Ñ¥°Í•±•Ñ•µÉ•Á½Í¥Ñ½Éä…Ñ¥Ù¥Ñä¥Ì…Ù…¥±…‰±”œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐÕ¹É•±…Ñ•‘I•Á½M…¹ÌèI•Á½M…¹I•½É‘mt€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€Ìô¤¹µ…À ¡|°¥¹‘•à¤€ôø€¡ì(€€€€€€¸¸¹ÍÕ••‘•‘I•Á½M…¸°(€€€€€¥èÉ•Á¼µÍ…¸µÕ¹É•±…Ñ•´‘í¥¹‘•áõ€°(€€€€€É•Á½Í¥Ñ½ÉäèÑ•…´´‘í¥¹‘•à€¬€Åô½Õ¹É•±…Ñ•‘€(€€€ô¤¤ì(€€€½¹ÍÐÍ•±•Ñ•‘I•Á½M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹ÅÕ•Õ•‘I•Á½M…¸°(€€€€€¥è€É•Á¼µÍ…¸µÍ•±•Ñ•œ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°(€€€€€ÍÑ…ÑÕÌè€½µÁ±•Ñ•œ°(€€€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄáPÄÀèÀÀèÀÁhœ°(€€€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄáPÄÀèÀÌèÀÁhœ°(€€€€€™¥¹‘¥¹}½Õ¹Ðè€È°(€€€€€™¥±•Í}Í…¹¹•è€ÄÜ(€€€ôì((€€€±•ÐÁ…•…±±Ì€ô€Àì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ì(€€€€€±¥ÍÑI•Á½M…¹Ìè€ ¤€ôøì(€€€€€€€Á…•…±±Ì€¬ô€Äì(€€€€€€€¥˜€¡Á…•…±±Ì€ôôô€Ä¤ì(€€€€€€€€€É•ÑÕÉ¸AÉ½µ¥Í”¹É•Í½±Ù”¡ì(€€€€€€€€€€€¥Ñ•µÌèÕ¹É•±…Ñ•‘I•Á½M…¹Ì°(€€€€€€€€€€€¹•áÑ}ÕÉÍ½Èè€É•Á¼µÁ…”´Èœ(€€€€€€€€€ô¤ì(€€€€€€€ô(€€€€€€€É•ÑÕÉ¸AÉ½µ¥Í”¹É•Í½±Ù”¡ì(€€€€€€€€€¥Ñ•µÌèmÍ•±•Ñ•‘I•Á½M…¹t(€€€€€€€ô¤ì(€€€€€ô(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôøì(€€€€€½¹ÍÐ…Ñ¥Ù¥Ñä€ôÍÉ••¸¹•Ñ	åI½±” É•¥½¸œ°ì¹…µ”è€I••¹ÐÉ•Á½Í¥Ñ½ÉäÍ…¸…Ñ¥Ù¥Ñäœô¤ì(€€€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡…Ñ¥Ù¥Ñä¤¹•Ñ±±	åQ•áÐ ½¥‘•¹ÑÉ…¥±p½¥‘•¹ÑÉ…¥°½¤¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì(€€€ô¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ±±	åQ•áÐ ½¥‘•¹ÑÉ…¥±p½¥‘•¹ÑÉ…¥°½¤¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ Ä¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”±•…ÉÌÍÑ…±”¥Ñ!Õˆ½¹¹•Ñ¥½¸‘…Ñ„Ý¡•¸„É•±½…‘¥¹œ•¹Ù¥É½¹µ•¹ÐÍÑ…ÑÕÌ™…¥±Ìœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì((€€€½¹ÍÐ…Ñ¥Ù•AÉ½©•Ð€ôÁÉ½‘ÕÑ¥½¹AÉ½©•Ðì(€€€½¹ÍÐÍÑ…±•AÉ½©•Ð€ôì(€€€€€€¸¸¹ÁÉ½‘ÕÑ¥½¹AÉ½©•Ð°(€€€€€ÁÉ½©•Ñ}¥è€ÍÑ…¥¹œµÁ±…Ñ™½É´œ°(€€€€€¹…µ”è€MÑ…¥¹œA±…Ñ™½É´œ°(€€€€€Í±Õœè€ÍÑ…¥¹œµÁ±…Ñ™½É´œ(€€€ôì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèm…Ñ¥Ù•AÉ½©•Ð°ÍÑ…±•AÉ½©•Ñt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡}Ý½É­ÍÁ…•%°ÁÉ½©•Ñ%¤€ôø€¡ì(€€€€€ÁÉ½©•Ðè(€€€€€€€ÁÉ½©•Ñ%€ôôôÍÑ…±•AÉ½©•Ð¹ÁÉ½©•Ñ}¥(€€€€€€€€€€üÍÑ…±•AÉ½©•Ð(€€€€€€€€€€è…Ñ¥Ù•AÉ½©•Ð(€€€ô¤¤ì((€€€½¹ÍÐ•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ€ôÙ¤(€€€€€€¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤(€€€€€€¹µ½­I•Í½±Ù•‘Y…±Õ•=¹”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤(€€€€€€¹µ½­I•©•Ñ•‘Y…±Õ”¡¹•Ü…Á¤¹Á¥ÉÉ½È ÍÑ…ÑÕÌ•¹‘Á½¥¹ÐÕ¹…Ù…¥±…‰±”œ°€ÔÀÌ¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÅÕ•Õ•‘I•Á½M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÉÕ¹I•Á½M…¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÉ•Á½}Í…¸èÅÕ•Õ•‘I•Á½M…¸ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€…¹•±I•Á½M…¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ìÉ•Á½}Í…¸è…¹•±•‘I•Á½M…¸ô¤ì((€€€½¹ÍÐìAÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½É¥•ÍA…”ô€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõílœ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´uôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ìˆ•±•µ•¹ÐõìñAÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½É¥•ÍA…”€¼ùô€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è€I•Á½Í¥Ñ½É¥•Ìœô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤¤¹Ñ½!…Ù•Y…±Õ” ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ¤¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹¡…¹”¡ÍÉ••¸¹•Ñ	åI½±” ½µ‰½‰½àœ°ì¹…µ”è€¹Ù¥É½¹µ•¹Ðœô¤°ì(€€€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÍÑ…¥¹œµÁ±…Ñ™½É´œô(€€€€€ô¤ì(€€€ô¤ì((€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½U¹…‰±”Ñ¼±½…É•Á½Í¥Ñ½ÉäÍÑ…ÑÕÌ½¤ô¤ì(€€€€¼¼™Ñ•ÈÑ¡”É•±½…‘¥¹œÍÑ…ÑÕÌÉ•ÅÕ•ÍÐ™…¥±ÌÑ¡”ÍÑ…±”EÕ•Õ”Í…¸(€€€€¼¼…™™½É‘…¹”¥Ì‘É½ÁÁ•…¹Ñ¡”‰½‘ä¥ÌÍÕÁÁÉ•ÍÍ•Í¼Ñ¡”•ÉÉ½È(€€€€¼¼Á…¹•°ÍÑ…åÌÑ¡”Í¥¹±”Í½ÕÉ”½˜ÑÉÕÑ ƒŠPÑ¡”Á…”µÕÍÐ¹½Ð…±Í¼(€€€€¼¼É•¹‘•È„ÍÁ•Õ±…Ñ¥Ù”€‰½¹¹•Ð¥Ñ!ÕˆÑ¼µ…¹…”É•Á½Í¥Ñ½É¥•Ìˆ(€€€€¼¼•µÁÑäÍÑ…Ñ”½™˜…¸•ÉÉ½É•ÍÑ…ÑÕÌ¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½½¹¹•Ð¥Ñ!ÕˆÑ¼µ…¹…”É•Á½Í¥Ñ½É¥•Ì½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” É•¥½¸œ°ì¹…µ”è€M•±•Ñ•É•Á½Í¥Ñ½É¥•Ìœô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½U¹…‰±”Ñ¼±½…É•Á½Í¥Ñ½É¥•Íp¸½¤¤ì((€€€•áÁ•Ð¡•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì È¤ì(€ô¤ì((€¥Ð I•Á½Í¥Ñ½É¥•ÌÁ…”‘¥Í…‰±•ÌEÕ•Õ”Í…¸Ý¡¥±”•¹Ù¥É½¹µ•¹Ð‘…Ñ„¥ÌÉ•±½…‘¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐµ½­Ì€ô…Ý…¥ÐÉ•¹‘•É¥Ñ!Õ‰A…” É•Á½Í¥Ñ½É¥•Ìœ°ìÍ…¹Ìèmtô¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤¤¹¹½Ð¹Ñ½	•¥Í…‰±• ¤ì((€€€±•ÐÉ•Í½±Ù•EÕ•Õ•è€ ¡Ù…±Õ”èìÉ•Á½}Í…¸èI•Á½M…¹I•½Éô¤€ôøÙ½¥¤ð¹Õ±°€ô¹Õ±°ì(€€€±•ÐÉ•Í½±Ù•A•¹‘¥¹œè€ ¡Ù…±Õ”èì¥Ñ•µÌèI•Á½M…¹I•½É‘mtô¤€ôøÙ½¥¤ð¹Õ±°€ô¹Õ±°ì(€€€µ½­Ì¹ÉÕ¹I•Á½M…¸¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ (€€€€€€ ¤€ôø(€€€€€€€¹•ÜAÉ½µ¥Í” ¡É•Í½±Ù”¤€ôøì(€€€€€€€€€É•Í½±Ù•EÕ•Õ•€ôÉ•Í½±Ù”ì(€€€€€€€ô¤(€€€€¤ì(€€€µ½­Ì¹±¥ÍÑI•Á½M…¹Ì¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸ (€€€€€€ ¤€ôø(€€€€€€€¹•ÜAÉ½µ¥Í” ¡É•Í½±Ù”¤€ôøì(€€€€€€€€€É•Í½±Ù•A•¹‘¥¹œ€ôÉ•Í½±Ù”ì(€€€€€€€ô¤(€€€€¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡µ½­Ì¹ÉÕ¹I•Á½M…¸¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤¤¹Ñ½	•¥Í…‰±• ¤¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€EÕ•Õ”Í…¸™½È¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œô¤¤¹Ñ½!…Ù•Q•áÑ½¹Ñ•¹Ð ½I•™É•Í¡¥¹ñEÕ•Õ¥¹œ½¤¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€É•Í½±Ù•EÕ•Õ•ü¸¡ìÉ•Á½}Í…¸èÅÕ•Õ•‘I•Á½M…¸ô¤ì(€€€€€…Ý…¥ÐAÉ½µ¥Í”¹É•Í½±Ù” ¤ì(€€€ô¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€É•Í½±Ù•A•¹‘¥¹œü¸¡ì¥Ñ•µÌèmtô¤ì(€€€€€…Ý…¥ÐAÉ½µ¥Í”¹É•Í½±Ù” ¤ì(€€€ô¤ì(€ô¤ì)ô¤ì((¼¼]½É­ÍÁ…”…¹•Èi½¹”ƒŠPAH€Ì½˜€ŒÄÐÈÀ¸(¼¼(¼¼Q¡•Í”½Ù•ÈÑ¡”½Ý¹•Èµ½¹±äÝ½É­ÍÁ…”±¥™•å±”½¹ÑÉ½±Ì…ÁÁ•¹‘•Ñ¼Ñ¡”(¼¼•á¥ÍÑ¥¹œM•ÑÑ¥¹Ì…¹•Èi½¹”…ÉèÝ¡¥ É½ÝÌÍ¡½ÜÁ•ÈÉ½±”€¬±¥™•å±”(¼¼ÍÑ…Ñ”°Ñ¡”ÑåÁ”µÑ¼µ½¹™¥É´…Ñ”½¸MÕÍÁ•¹½•±•Ñ”°Ñ¡”¡•­‰½à½¹™¥É´(¼¼½¸Ñ¡”É•ÍÑ½É…Ñ¥Ù”I•…Ñ¥Ù…Ñ”½I•ÍÑ½É”°…¹Ñ¡”¥¹±¥¹”Í½±”µ½Ý¹•È‰±½¬(¼¼€¡Ý¥Ñ ‘••À±¥¹¬Ñ¼Ñ¡”µ•µ‰•Èµµ…¹…•µ•¹ÐÍÉ••¸¤Ý¡•¸Ñ¡”‰…­•¹(¼¼É•ÑÕÉ¹Ì€ÐÀäÍ½±•}½Ý¹•É}É•ÅÕ¥É•Í}ÑÉ…¹Í™•É€¸)‘•ÍÉ¥‰” ]½É­ÍÁ…”…¹•Èi½¹”€ ŒÄÐÈÀ¤œ°€ ¤€ôøì(€½¹ÍÐ½Ý¹•É]½É­ÍÁ…•¥áÑÕÉ”€ôì(€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°(€€€Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°(€€€‘¥ÍÁ±…å}¹…µ”è€]½É­ÍÁ…”œ°(€€€Í±Õœè€Ý½É­ÍÁ…”µ„œ°(€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÙPÄÀèÀÀèÀÁhœ°(€€€ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÙPÄÀèÀÀèÀÁhœ(€ôì(€½¹ÍÐ½Ý¹•É5”èÕÉÉ•¹ÑUÍ•É½¹Ñ•áÐ€ôì(€€€€¸¸¹±½•‘%¹]¥Ñ¡]½É­ÍÁ…”°(€€€É½±”è€½Ý¹•Èœ°(€€€Ý½É­ÍÁ…”è½Ý¹•É]½É­ÍÁ…•¥áÑÕÉ”(€ôì((€¥Ð ¡¥‘•ÌÑ¡”Ý½É­ÍÁ…”É½ÝÌ•¹Ñ¥É•±ä™½È¹½¸µ½Ý¹•Èµ•µ‰•ÉÌœ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…” ¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µ…½Õ¹ÐµÉ½Üœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘Ðµ‘•±•Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘ÐµÉ•…Ñ¥Ù…Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘ÐµÉ•ÍÑ½É”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌMÕÍÁ•¹€¬•±•Ñ”Ý½É­ÍÁ…”É½ÝÌ™½È½Ý¹•ÉÌ½¸…¸…Ñ¥Ù”Ý½É­ÍÁ…”œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ìµ”è½Ý¹•É5”ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘•±•Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•QÉÕÑ¡ä ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘ÐµÉ•…Ñ¥Ù…Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘ÐµÉ•ÍÑ½É”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€ô¤ì((€¥Ð ÍÝ…ÁÌMÕÍÁ•¹ƒŠHI•…Ñ¥Ù…Ñ”Ý¡•¸Ñ¡”Ý½É­ÍÁ…”¥Ì…±É•…‘äÍÕÍÁ•¹‘•œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ìµ”è½Ý¹•É5”°Ý½É­ÍÁ…•MÑ…ÑÕÌè€ÍÕÍÁ•¹‘•œô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÉ•…Ñ¥Ù…Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘•±•Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•QÉÕÑ¡ä ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€ô¤ì((€¥Ð ½±±…ÁÍ•ÌÑ¼„Í¥¹±”I•ÍÑ½É”É½ÜÝ¡•¸Ñ¡”Ý½É­ÍÁ…”¥ÌÍ½™Ðµ‘•±•Ñ•œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ìµ”è½Ý¹•É5”°Ý½É­ÍÁ…•MÑ…ÑÕÌè€‘•±•Ñ•œô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÉ•ÍÑ½É”µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘ÐµÉ•…Ñ¥Ù…Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•ÍÑ% ¥‘Ðµ‘•±•Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹Ñ½	•9Õ±° ¤ì(€ô¤ì((€¥Ð ÍÕÍÁ•¹‘ÌÑ¡”Ý½É­ÍÁ…”…™Ñ•ÈÑåÁ¥¹œMUMA9¥¸Ñ¡”µ½‘…°œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐìÍÕÍÁ•¹‘]½É­ÍÁ…”ô€ô…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ìµ”è½Ý¹•É5”ô¤ì(€€€ÍÕÍÁ•¹‘]½É­ÍÁ…”¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€Ý½É­ÍÁ…”èì€¸¸¹½Ý¹•É]½É­ÍÁ…•¥áÑÕÉ”°ÍÑ…ÑÕÌè€ÍÕÍÁ•¹‘•œô°(€€€€€ÍÑ…ÑÕÌè€ÍÕÍÁ•¹‘•œ(€€€ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬ (€€€€€€€Ý¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ¤(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐµ½‘…°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°œ¤ì(€€€½¹ÍÐ½¹Ñ¥¹Õ•	Ñ¸€ôÝ¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ½¹Ñ¥¹Õ”œ¤ì(€€€€¼¼…Ñ”ÍÑ…åÌ…Éµ•Õ¹Ñ¥°Ñ¡”ÕÍ•ÈÑåÁ•ÌÑ¡”•á…ÐÑ½­•¸¸(€€€•áÁ•Ð¡½¹Ñ¥¹Õ•	Ñ¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µÑåÁ•œ¤°ì(€€€€€€€Ñ…É•ÐèìÙ…±Õ”è€MUMA9œô(€€€€€ô¤ì(€€€ô¤ì(€€€•áÁ•Ð¡½¹Ñ¥¹Õ•	Ñ¸¤¹¹½Ð¹Ñ½	•¥Í…‰±• ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡½¹Ñ¥¹Õ•	Ñ¸¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÍÕÍÁ•¹‘]½É­ÍÁ…”¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  Ý½É­ÍÁ…”µ„œ°•áÁ•Ð¹…¹åÑ¡¥¹œ ¤¤(€€€€¤ì(€€€€¼¼I½ÜÍÝ…ÁÌÑ¼I•…Ñ¥Ù…Ñ”½¹”Ñ¡”É•ÍÁ½¹Í”±…¹‘Ì¸(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÉ•…Ñ¥Ù…Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€ô¤ì((€¥Ð ÍÑ¥±°É•¹‘•ÉÌ„™…±±‰…¬Í½±”µ½Ý¹•È‰±½­•ÈÝ¡•¸…™™•Ñ•‘}µ•µ‰•ÉÌ¥Ì•µÁÑäœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼I•É•ÍÍ¥½¸™½ÈÕ‰¥ŒAH€ŒÄÐÔØ@ÈèÁÉ•Ù¥½ÕÍ±ä„€ÐÀäÝ¥Ñ „µ¥ÍÍ¥¹œ½È(€€€€¼¼µ…±™½Éµ•…™™•Ñ•‘}µ•µ‰•ÉÌ…ÉÉ…äÝ½Õ±Í•ÐÑ¡”ÍÑÉ…¹‘•±¥ÍÐÑ¼mt(€€€€¼¼…¹Ñ¡”‰±½­•È€¡Ý¡¥ ­•å•½™˜±•¹Ñ €ø€À¤Ý½Õ±¹½ÐÉ•¹‘•È…Ð…±°°(€€€€¼¼±•…Ù¥¹œÑ¡”…Ñ½ÈÝ¥Ñ „±½Í•Á•¹‘¥¹œÍÑ…Ñ”…¹¹¼™••‘‰…¬¸(€€€½¹ÍÐìÍÕÍÁ•¹‘]½É­ÍÁ…”°…Á¤ô€ô…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ìµ”è½Ý¹•É5”ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€€€ÍÕÍÁ•¹‘]½É­ÍÁ…”¹µ½­I•©•Ñ•‘Y…±Õ” (€€€€€¹•Ü…Á¤¹Á¥ÉÉ½È Í½±”½Ý¹•ÈÉ•ÅÕ¥É•ÌÑÉ…¹Í™•Èœ°€ÐÀä°ì(€€€€€€€½‘”è€Í½±•}½Ý¹•É}É•ÅÕ¥É•Í}ÑÉ…¹Í™•Èœ°(€€€€€€€Á…å±½…èì½‘”è€Í½±•}½Ý¹•É}É•ÅÕ¥É•Í}ÑÉ…¹Í™•Èœô(€€€€€ô¤(€€€€¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬ (€€€€€€€Ý¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ¤(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐµ½‘…°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°œ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µÑåÁ•œ¤°ì(€€€€€€€Ñ…É•ÐèìÙ…±Õ”è€MUMA9œô(€€€€€ô¤ì(€€€ô¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ½¹Ñ¥¹Õ”œ¤¤ì(€€€ô¤ì(€€€½¹ÍÐ‰±½¬€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÍ½±”µ½Ý¹•Èµ‰±½¬œ¤ì(€€€€¼¼…±±‰…¬½ÁäµÕÍÐÍÕÉ™…”•Ù•¸Ý¥Ñ ¹¼…™™•Ñ•µµ•µ‰•È±¥ÍÐ¸(€€€•áÁ•Ð¡‰±½¬¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½5…Ñ  ½½¹±ä½¹”½Ý¹•È½¤¤ì(€€€•áÁ•Ð (€€€€€Ý¥Ñ¡¥¸¡‰±½¬¤¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½µ…¹…”µ•µ‰•ÉÌ½¤ô¤¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤(€€€€¤¹Ñ½	” œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½Ý½É­ÍÁ…•Ìœ¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌÑ¡”Í½±”µ½Ý¹•È¥¹±¥¹”‰±½¬Ý¥Ñ „±¥¹¬Ñ¼µ…¹…”µ•µ‰•ÉÌœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐìÍÕÍÁ•¹‘]½É­ÍÁ…”°…Á¤ô€ô…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ìµ”è½Ý¹•É5”ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€€€ÍÕÍÁ•¹‘]½É­ÍÁ…”¹µ½­I•©•Ñ•‘Y…±Õ” (€€€€€¹•Ü…Á¤¹Á¥ÉÉ½È (€€€€€€€€Ý½É­ÍÁ…”¡…Ì…‘‘¥Ñ¥½¹…°…Ñ¥Ù”µ•µ‰•ÉÌ‰ÕÐ½¹±ä½¹”½Ý¹•ÈìÑÉ…¹Í™•È½Ý¹•ÉÍ¡¥À‰•™½É”ÍÕÍÁ•¹‘¥¹œ½È‘•±•Ñ¥¹œœ°(€€€€€€€€ÐÀä°(€€€€€€€ì(€€€€€€€€€½‘”è€Í½±•}½Ý¹•É}É•ÅÕ¥É•Í}ÑÉ…¹Í™•Èœ°(€€€€€€€€€Á…å±½…èì(€€€€€€€€€€€½‘”è€Í½±•}½Ý¹•É}É•ÅÕ¥É•Í}ÑÉ…¹Í™•Èœ°(€€€€€€€€€€€…™™•Ñ•‘}µ•µ‰•ÉÌèl(€€€€€€€€€€€€€ì(€€€€€€€€€€€€€€€µ•µ‰•É}¥è€µ•µ‰•Èµˆœ°(€€€€€€€€€€€€€€€ÕÍ•É}¥è€ÕÍ•Èµˆœ°(€€€€€€€€€€€€€€€•µ…¥°è€ÕÍ•Èµ‰•á…µÁ±”¹½´œ°(€€€€€€€€€€€€€€€É½±”è€…‘µ¥¸œ(€€€€€€€€€€€€€ô(€€€€€€€€€€€t(€€€€€€€€€ô(€€€€€€€ô(€€€€€€¤(€€€€¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬ (€€€€€€€Ý¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ¤(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐµ½‘…°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°œ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µÑåÁ•œ¤°ì(€€€€€€€Ñ…É•ÐèìÙ…±Õ”è€MUMA9œô(€€€€€ô¤ì(€€€ô¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ½¹Ñ¥¹Õ”œ¤¤ì(€€€ô¤ì(€€€½¹ÍÐ‰±½¬€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÍ½±”µ½Ý¹•Èµ‰±½¬œ¤ì(€€€•áÁ•Ð¡‰±½¬¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ÕÍ•Èµ‰•á…µÁ±”¹½´œ¤ì(€€€½¹ÍÐµ…¹…•1¥¹¬€ôÝ¥Ñ¡¥¸¡‰±½¬¤¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½µ…¹…”µ•µ‰•ÉÌ½¤ô¤ì(€€€•áÁ•Ð¡µ…¹…•1¥¹¬¹•ÑÑÑÉ¥‰ÕÑ” ¡É•˜œ¤¤¹Ñ½	” œ½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½Ý½É­ÍÁ…•Ìœ¤ì(€ô¤ì((€¥Ð ­••ÁÌ•±•Ñ”Ý½É­ÍÁ…”…Ñ•Õ¹Ñ¥°Ñ¡”Í±Õœ¥ÌÑåÁ••á…Ñ±äœ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐì‘•±•Ñ•]½É­ÍÁ…”ô€ô…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ìµ”è½Ý¹•É5”ô¤ì(€€€‘•±•Ñ•]½É­ÍÁ…”¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€Ý½É­ÍÁ…”èì€¸¸¹½Ý¹•É]½É­ÍÁ…•¥áÑÕÉ”°ÍÑ…ÑÕÌè€‘•±•Ñ•œ°‘•±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÈÁPÄÀèÀÀèÀÁhœô°(€€€€€ÍÑ…ÑÕÌè€‘•±•Ñ•œ°(€€€€€¡…É‘}‘•±•Ñ•}…™Ñ•Èè€œÈÀÈØ´ÀØ´ÄåPÄÀèÀÀèÀÁhœ°(€€€€€É…•}Á•É¥½‘}¡½ÕÉÌè€ÜÈÀ(€€€ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘Ðµ‘•±•Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬ (€€€€€€€Ý¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘•±•Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ¤(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐµ½‘…°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°œ¤ì(€€€½¹ÍÐ½¹Ñ¥¹Õ•	Ñ¸€ôÝ¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ½¹Ñ¥¹Õ”œ¤ì(€€€•áÁ•Ð¡½¹Ñ¥¹Õ•	Ñ¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µÑåÁ•œ¤°ì(€€€€€€€Ñ…É•ÐèìÙ…±Õ”è€ÝÉ½¹œµÍ±Õœœô(€€€€€ô¤ì(€€€ô¤ì(€€€•áÁ•Ð¡½¹Ñ¥¹Õ•	Ñ¸¤¹Ñ½	•¥Í…‰±• ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹¡…¹”¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µÑåÁ•œ¤°ì(€€€€€€€Ñ…É•ÐèìÙ…±Õ”è€Ý½É­ÍÁ…”µ„œô(€€€€€ô¤ì(€€€ô¤ì(€€€•áÁ•Ð¡½¹Ñ¥¹Õ•	Ñ¸¤¹¹½Ð¹Ñ½	•¥Í…‰±• ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡½¹Ñ¥¹Õ•	Ñ¸¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡‘•±•Ñ•]½É­ÍÁ…”¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  Ý½É­ÍÁ…”µ„œ°•áÁ•Ð¹…¹åÑ¡¥¹œ ¤¤(€€€€¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÉ•ÍÑ½É”µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€ô¤ì((€¥Ð É•…Ñ¥Ù…Ñ•Ì„ÍÕÍÁ•¹‘•Ý½É­ÍÁ…”Ñ¡É½Õ Ñ¡”¡•­‰½àµ½‘…°œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐìÉ•…Ñ¥Ù…Ñ•]½É­ÍÁ…”ô€ô…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ì(€€€€€µ”è½Ý¹•É5”°(€€€€€Ý½É­ÍÁ…•MÑ…ÑÕÌè€ÍÕÍÁ•¹‘•œ(€€€ô¤ì(€€€É•…Ñ¥Ù…Ñ•]½É­ÍÁ…”¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€Ý½É­ÍÁ…”èì€¸¸¹½Ý¹•É]½É­ÍÁ…•¥áÑÕÉ”°ÍÑ…ÑÕÌè€…Ñ¥Ù”œô°(€€€€€ÍÑ…ÑÕÌè€…Ñ¥Ù”œ(€€€ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÉ•…Ñ¥Ù…Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬ (€€€€€€€Ý¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ¥‘ÐµÉ•…Ñ¥Ù…Ñ”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ¤(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐµ½‘…°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°œ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ¡•­‰½àœ¤¤ì(€€€ô¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ½¹Ñ¥¹Õ”œ¤¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡É•…Ñ¥Ù…Ñ•]½É­ÍÁ…”¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  Ý½É­ÍÁ…”µ„œ°•áÁ•Ð¹…¹åÑ¡¥¹œ ¤¤(€€€€¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€ô¤ì((€¥Ð É•ÍÑ½É•Ì„Í½™Ðµ‘•±•Ñ•Ý½É­ÍÁ…”Ñ¡É½Õ Ñ¡”¡•­‰½àµ½‘…°œ°…Íå¹Œ€ ¤€ôøì(€€€½¹ÍÐì…¹•±]½É­ÍÁ…••±•Ñ¥½¸ô€ô…Ý…¥ÐÉ•¹‘•ÉAÉ½‘ÕÑM•ÑÑ¥¹ÍA…”¡ì(€€€€€µ”è½Ý¹•É5”°(€€€€€Ý½É­ÍÁ…•MÑ…ÑÕÌè€‘•±•Ñ•œ(€€€ô¤ì(€€€…¹•±]½É­ÍÁ…••±•Ñ¥½¸¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€Ý½É­ÍÁ…”èì€¸¸¹½Ý¹•É]½É­ÍÁ…•¥áÑÕÉ”°ÍÑ…ÑÕÌè€…Ñ¥Ù”œô°(€€€€€ÍÑ…ÑÕÌè€…Ñ¥Ù”œ(€€€ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÉ•ÍÑ½É”µÝ½É­ÍÁ…”µÉ½Üœ¤ì((€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬ (€€€€€€€Ý¥Ñ¡¥¸¡ÍÉ••¸¹•Ñ	åQ•ÍÑ% ¥‘ÐµÉ•ÍÑ½É”µÝ½É­ÍÁ…”µÉ½Üœ¤¤¹•Ñ	åI½±” ‰ÕÑÑ½¸œ¤(€€€€€€¤ì(€€€ô¤ì(€€€½¹ÍÐµ½‘…°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°œ¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ¡•­‰½àœ¤¤ì(€€€ô¤ì(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€™¥É•Ù•¹Ð¹±¥¬¡Ý¥Ñ¡¥¸¡µ½‘…°¤¹•Ñ	åQ•ÍÑ% ¥‘Ðµ‘…¹•Èµµ½‘…°µ½¹Ñ¥¹Õ”œ¤¤ì(€€€ô¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡…¹•±]½É­ÍÁ…••±•Ñ¥½¸¤¹Ñ½!…Ù•	••¹…±±•‘]¥Ñ  Ý½É­ÍÁ…”µ„œ°•áÁ•Ð¹…¹åÑ¡¥¹œ ¤¤(€€€€¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•ÍÑ% ¥‘ÐµÍÕÍÁ•¹µÝ½É­ÍÁ…”µÉ½Üœ¤ì(€ô¤ì)ô¤ì((¼¼€´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´(¼¼]LÍ•Ñ¥½¸½ÁäµÉ•‘Õ¹‘…¹äÉ•É•ÍÍ¥½¸(¼¼€´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´(¼¼(¼¼AH€ŒÄÔàÈÍÑÉ¥ÁÁ•Ñ¡”]LÍ•Ñ¥½¸½˜•¹¥¹••É¥¹œµÙ¥‰”½ÁäèÑ¡”µ…É­•Ñ¥¹œ(¼¼Ñ…±¥¹”½¸Ñ¡”½Ù•ÉÙ¥•Ü°Ñ¡”•¥¡Ðµ…É-A$ÍÑÉ¥À°•Ù•ÉäÁ•ÈµÁ…”(¼¼ÕÉÉ•¹ÐÙÌÁ±…¹¹•€¼]¥É•¹½Ü€¼A±…¹¹•½Ù•É…•€‰±½¬°Ñ¡”(¼¼%¹Ù•¹Ñ½Éä½¹ÑÉ…Ñ€…¹]MI¥Í­=Á•É…Ñ¥½¹M½Á•€…Í¥‘•Ì°Ñ¡”Ñ¡É•”(¼¼%ÍÍÕ”Í•ÅÕ•¹¥¹œ€¼ÁÀÙ…±¥‘…Ñ¥½¸€¼½±±•Ñ½È½¹ÑÉ…Ñ€¥ÍÍÕ”µÑÉ…­•È(¼¼Á…¹•±Ì°…¹Ñ¡”½µ¥¹œÝ…Ù”€¼½µ¥¹œ±…Ñ•È€¼I•Í•ÉÙ•ÍÕÉ™…”€¼(¼¼%¹Ù•¹Ñ½ÉäÍ¡•±±€ÍÑ…ÑÕÌ±…‰•±Ì¸(¼¼(¼¼Q¡¥ÌÑ•ÍÐÉ•…‘ÌÁÉ½‘ÕÑM¡•±°¹ÑÍà…ÌÍ½ÕÉ”Í¼Ñ¡…Ð„™ÕÑÕÉ”AH…¹¹½Ð(¼¼ÅÕ¥•Ñ±äÉ”µ¥¹ÑÉ½‘Õ”…¹ä½˜Ñ¡½Í”ÍÑÉ¥¹Ì¸Q¡”¡•¬¥Ì„ÍÕ‰ÍÑÉ¥¹œ(¼¼µ…Ñ ƒŠP¥˜…¹ä‰…¹¹•Á¡É…Í”É•…ÁÁ•…ÉÌ…¹åÝ¡•É”¥¸Ñ¡”™¥±”°Ñ¡¥ÌÑ•ÍÐ(¼¼™…¥±ÌÝ¥Ñ „±•…ÈÁ½¥¹Ñ•ÈÑ¼Ý¡¥ ½¹”¸Q¡”±¥ÍÐ¥Ì¥¹Ñ•¹Ñ¥½¹…±±ä(¼¼Í½Á•Ñ¼€©½Áä¨ì¹•Ü½‘”Á…Ñ¡ÌÑ¡…Ð¡…ÁÁ•¸Ñ¼µ•¹Ñ¥½¸€‰Ý…Ù”ˆ½È(¼¼€‰Í¡•±°ˆ¥¸„™Õ¹Ñ¥½¸½ÈÑåÁ”¹…µ”…É”™¥¹”¸()‘•ÍÉ¥‰” ]L½ÁäÉ•‘Õ¹‘…¹äÕ…É€ ŒÄÔàÈ¤œ°€ ¤€ôøì((€€¼¼MÑÉ¥¹ÌÑ¡…ÐµÕÍÐ¹•Ù•È…ÁÁ•…È…ÌÕÍÑ½µ•ÈµÙ¥Í¥‰±”½Áä¥¸Ñ¡”]L(€€¼¼Í•Ñ¥½¸¸¹åÑ¡¥¹œÝÉ…ÁÁ•¥¸)M`±¥Ñ•É…°ÅÕ½Ñ•Ì¥Ì™…¥È…µ”™½ÈÑ¡”(€€¼¼¡•¬ìÑåÁ”¹…µ•Ì…¹¡•±Á•Èµ™Õ¹Ñ¥½¸¥‘•¹Ñ¥™¥•ÉÌ‘¼¹½Ðµ…Ñ (€€¼¼‰•…ÕÍ”Ñ¡•äÕÍ”…µ•±…Í”½ÈA…Í…±…Í”¸(€€¼¼Q¡”±¥ÍÐ¥ÌÍ½Á•Ñ¼Á¡É…Í•ÌÑ¡…Ð…É”Õ¹…µ‰¥Õ½ÕÍ±ä(€€¼¼•¹¥¹••É¥¹œµÉ½…‘µ…Àµ¥¸µU$ìÁ¡É…Í•ÌÑ¡…Ð‘½Õ‰±”…Ì±•¥Ñ¥µ…Ñ”(€€¼¼™¥±Ñ•Èµ½ÁÑ¥½¸±…‰•±Ì€¡”¹œ¸€½µ¥¹œÝ…Ù”œ¥Ì…±Í¼…¸¥¹Ù•¹Ñ½Éä(€€¼¼™¥±Ñ•ÈÙ…±Õ”¤°¥¹Ñ•É¹…°¡•±Á•ÈÉ•ÑÕÉ¸Ù…±Õ•Ì°½È½¹Ñ•¹Ðµ…É½Áä(€€¼¼…É”¥¹Ñ•¹Ñ¥½¹…±±ä9=P½¸Ñ¡¥Ì±¥ÍÐƒŠPÑ¡”Á•Èµ½¹ÍÑ…¹Ð…ÍÍ•ÉÑ¥½¹Ì(€€¼¼‰•±½Ü½Ù•ÈÑ¡”Á…”µÍ¡•±°½¹ÍÑ…¹ÑÌÝ¡•É”Ñ¡½Í”Á¡É…Í•ÌÝ•É”Ñ¡”(€€¼¼…ÑÕ…°É•‘Õ¹‘…¹ä¸(€½¹ÍÐ‰…¹¹•‘]M½ÁåMÑÉ¥¹ÌèI•…‘½¹±åÉÉ…äñÍÑÉ¥¹œø€ôl(€€€€¼¼!•…‘•È€¼½Ù•ÉÙ¥•Ü¡É½µ”É•µ½Ù•‰ä€ŒÄÔàÈ(€€€€]L5!%9%9Q%Qdœ°(€€€€]L½¹ÑÉ½°•¹Ñ•Èœ°(€€€€™É½´½¹”‘½µ…¥¸µ½Ý¹•ÍÕÉ™…”œ°(€€€€=Á•É…Ñ”]L½¹¹•Ñ¥½¸¡•…±Ñ œ°(€€€€¼¼%ÍÍÕ”µÑÉ…­•ÈÁ…¹•±ÌÉ•µ½Ù•™É½´ÕÍÑ½µ•ÈU$‰ä€ŒÄÔàÈ(€€€€]LÁ±…Ñ™½É´‘•Á•¹‘•¹ä¥¹‘•àœ°(€€€€]L±¥Ù”…ÁÀÙ…±¥‘…Ñ¥½¸¡…É¹•ÍÌœ°(€€€€]LÍ•ÉÙ¥”½±±•Ñ½È½¹ÑÉ…Ðœ°(€€€€¼¼A…”µÍ¡•±°Í¡•±±Ì€¼Í½Á•Ì€¼…Í¥‘•ÌÉ•µ½Ù•‰ä€ŒÄÔàÈ(€€€€½Ù•É…”Í¡•±°œ°(€€€€%¹Ù•¹Ñ½ÉäÍ¡•±°œ°(€€€€I•…¡…‰¥±¥ÑäÍ¡•±°œ°(€€€€I•Í•ÉÙ•ÍÕÉ™…”œ°(€€€€]L…Á…‰¥±¥Ñä•áÁ…¹Í¥½¸œ°(€€€€]L…Á…‰¥±¥Ñäµ…Àœ°(€€€€M•ÑÕÀÁ…å±½…œ°(€€€€M½Á•½¹ÑÉ…Ðœ°(€€€€]½É­ÍÁ…”½¹ÑÉ…Ðœ°(€€€€I•…µ½¹±ä…½Õ¹Ð½¹‰½…É‘¥¹œœ(€€€€¼¼9½Ñ”èÍ¡½ÉÐ•¹¥¹••É¥¹œµÙ¥‰”Á¡É…Í•Ì±¥­”€‰9½Ð¥¹•ÍÑ¥¹œˆ€¼€‰‘Ù¥Í½Éä(€€€€¼¼½¹±äˆ€¼€‰½µ¥¹œÝ…Ù”ˆ€¼€‰]¥É•¹½Üˆ€¼€‰9½Ðå•Ð…Ù…¥±…‰±”ˆ…É”(€€€€¼¼¥¹Ñ•¹Ñ¥½¹…±±ä¹½ÐÍÕ‰ÍÑÉ¥¹œµ‰…¹¹•‰•…ÕÍ”Ñ¡•ä‘½Õ‰±”…Ì±•¥Ñ¥µ…Ñ”(€€€€¼¼¥¹Ù•¹Ñ½Éä™¥±Ñ•È±…‰•±Ì½È…ÁÁ•…È¥¸±•…¹ÕÀ½µµ•¹ÑÌ¸Q¡•¥È(€€€€¼¼É•¥¹ÑÉ½‘ÕÑ¥½¸¥¹Ñ¼Ñ¡”]M}%9Y9Q=Ie}A}=Ad…¹(€€€€¼¼]M}I%M-}=AIQ%=9}A}=AdÍ¡•±±Ì¥Ì…Õ¡Ð‰äÑ¡”Á•Èµ½¹ÍÑ…¹Ð(€€€€¼¼…ÍÍ•ÉÑ¥½¹Ì‰•±½Ü¸(€tì((€¥Ð¹•… ¡‰…¹¹•‘]M½ÁåMÑÉ¥¹Ì¤ (€€€€ÁÉ½‘ÕÑM¡•±°¹ÑÍàµÕÍÐ¹½ÐÉ•¥¹ÑÉ½‘Õ”Ñ¡”]L½ÁäÉ•‘Õ¹‘…¹ä€•Àœ°(€€€€¡Á¡É…Í”¤€ôøì(€€€€€€¼¼]”µ…Ñ …¸½Á•¹¥¹œÍ¥¹±”½È‘½Õ‰±”ÅÕ½Ñ”°½ÁÑ¥½¹…°¥¹Ñ•ÉÙ•¹¥¹œ(€€€€€€¼¼Ý¡¥Ñ•ÍÁ…”°…¹Ñ¡”Á¡É…Í”°Í¼Ý”½¹±ä…Ñ Ñ¡”ÍÑÉ¥¹Ì…Ì(€€€€€€¼¼±¥Ñ•É…°½ÁäƒŠP¹½Ð…ÌÁ…ÉÑÌ½˜Ù…É¥…‰±”¹…µ•Ì¸(€€€€€½¹ÍÐ±¥Ñ•É…±½ÉµÌ€ôm€œ‘íÁ¡É…Í•õ€°€ˆ‘íÁ¡É…Í•õ€°q€‘íÁ¡É…Í•õtì(€€€€€½¹ÍÐµ…Ñ¡•€ô±¥Ñ•É…±½ÉµÌ¹™¥¹ ¡¹••‘±”¤€ôøÁÉ½‘ÕÑM¡•±±M½ÕÉ”¹¥¹±Õ‘•Ì¡¹••‘±”¤¤ì(€€€€€¥˜€¡µ…Ñ¡•¤ì(€€€€€€€Ñ¡É½Ü¹•ÜÉÉ½È (€€€€€€€€€]L½ÁäÉ•‘Õ¹‘…¹äÉ•¥¹ÑÉ½‘Õ•è€‘í)M=8¹ÍÑÉ¥¹¥™ä¡Á¡É…Í”¥ôÝ…Ì™½Õ¹…Ì„ÍÑÉ¥¹œ±¥Ñ•É…°¥¸ÁÉ½‘ÕÑM¡•±°¹ÑÍà¸€€¬(€€€€€€€€€€€AH€ŒÄÔàÈÉ•µ½Ù•Ñ¡¥ÌÍÑÉ¥¹œ™…µ¥±ä‰•…ÕÍ”¥ÐÁÕÍ¡••¹¥¹••É¥¹œµÉ½…‘µ…À±…¹Õ…”½¹Ñ¼Ñ¡”ÕÍÑ½µ•ÈU$¸€€¬(€€€€€€€€€€€UÍ”Á±…¥¸µ¹±¥Í Á…”½Áä…¹„É•…°•µÁÑäÍÑ…Ñ”¥¹ÍÑ•…¹€(€€€€€€€€¤ì(€€€€€ô(€€€€€•áÁ•Ð¡µ…Ñ¡•¤¹Ñ½	•U¹‘•™¥¹• ¤ì(€€€ô(€€¤ì((€¥Ð ]L¥¹Ù•¹Ñ½Éä½Áä•¹ÑÉ¥•Ì­••ÀÑ¡”±•…äÉ½…‘µ…Àµ¥¸µU$™¥•±‘Ì‰±…¹¬œ°€ ¤€ôøì(€€€€¼¼Q¡”]M%¹Ù•¹Ñ½ÉåA…•½Áä•¹ÑÉ¥•ÌÝ•É”Ñ¡”Í½ÕÉ”½˜•Ù•Éä(€€€€¼¼]¥É•¹½Ü€¼A±…¹¹•½Ù•É…”€¼MÑ…ÑÕÍ±…‰•±€É•Á•…Ð…É½ÍÌÑ¡”(€€€€¼¼]L¥¹Ù•¹Ñ½ÉäÍÕˆµÁ…•Ì¸Q¡”™¥•±‘Ì(€€€€¼¼ÍÑ¥±°•á¥ÍÐ½¸Ñ¡”ÑåÁ”Í¼Ñ¡”ÍÕÉÉ½Õ¹‘¥¹œÍ¡•±°½¹Ñ¥¹Õ•ÌÑ¼(€€€€¼¼½µÁ¥±”°‰ÕÐÑ¡•¥È€©Ù…±Õ•Ì¨µÕÍÐÍÑ…ä•µÁÑäÍ¼Ñ¡”‘•±•Ñ•Á…¹•°(€€€€¼¼…¹¹½Ð…¥‘•¹Ñ…±±äÉ•…ÁÁ•…È¥˜„™ÕÑÕÉ”AHÉ”µÉ•¹‘•ÉÌÑ¡•´¸(€€€½¹ÍÐ¥¹Ù•¹Ñ½Éå½Áå	±½¬€ôÁÉ½‘ÕÑM¡•±±M½ÕÉ”¹µ…Ñ  (€€€€€€½½¹ÍÐ]M}%9Y9Q=Ie}A}=AemqÍqMt¨ýyôì½´(€€€€¤ì(€€€•áÁ•Ð¡¥¹Ù•¹Ñ½Éå½Áå	±½¬¤¹¹½Ð¹Ñ½	•9Õ±° ¤ì(€€€½¹ÍÐ‰±½¬€ô¥¹Ù•¹Ñ½Éå½Áå	±½¬…lÁtì(€€€€¼¼Ù•Éä…ÍÍ¥¹µ•¹ÐÑ¼Ñ¡”™½ÕÈ™¥•±‘ÌµÕÍÐ‰”Ñ¡”•µÁÑäÍÑÉ¥¹œ¸(€€€™½È€¡½¹ÍÐ™¥•±½˜l•å•‰É½Üœ°€ÍÑ…ÑÕÍ1…‰•°œ°€ÕÉÉ•¹Ñ…Á…‰¥±¥Ñäœ°€Á±…¹¹•‘…Á…‰¥±¥Ñät¤ì(€€€€€½¹ÍÐµ…Ñ¡•Ì€ôl¸¸¹‰±½¬¹µ…Ñ¡±°¡¹•ÜI•áÀ¡€‘í™¥•±‘ôéqqÌ¨œ¡mxt¨¤€°€œœ¤¥tì(€€€€€•áÁ•Ð¡µ…Ñ¡•Ì¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì(€€€€€™½È€¡½¹ÍÐµ…Ñ ½˜µ…Ñ¡•Ì¤ì(€€€€€€€•áÁ•Ð¡µ…Ñ¡lÅt¤¹Ñ½	” œœ¤ì(€€€€€ô(€€€ô(€ô¤ì((€¥Ð ]LÉ¥Í¬µ½Á•É…Ñ¥½¸½Áä•¹ÑÉ¥•Ì­••ÀÑ¡”±•…äÉ½…‘µ…Àµ¥¸µU$™¥•±‘Ì‰±…¹¬œ°€ ¤€ôøì(€€€½¹ÍÐÉ¥Í­½Áå	±½¬€ôÁÉ½‘ÕÑM¡•±±M½ÕÉ”¹µ…Ñ  (€€€€€€½½¹ÍÐ]M}I%M-}=AIQ%=9}A}=AemqÍqMt¨ýyôì½´(€€€€¤ì(€€€•áÁ•Ð¡É¥Í­½Áå	±½¬¤¹¹½Ð¹Ñ½	•9Õ±° ¤ì(€€€½¹ÍÐ‰±½¬€ôÉ¥Í­½Áå	±½¬…lÁtì(€€€™½È€¡½¹ÍÐ™¥•±½˜l•å•‰É½Üœ°€ÍÑ…ÑÕÍ1…‰•°œ°€ÕÉÉ•¹Ñ…Á…‰¥±¥Ñäœ°€Á±…¹¹•‘…Á…‰¥±¥Ñäœ°€¹•áÑÑ¥½¸t¤ì(€€€€€½¹ÍÐµ…Ñ¡•Ì€ôl¸¸¹‰±½¬¹µ…Ñ¡±°¡¹•ÜI•áÀ¡€‘í™¥•±‘ôéqqÌ¨œ¡mxt¨¤€°€œœ¤¥tì(€€€€€•áÁ•Ð¡µ…Ñ¡•Ì¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤ì(€€€€€™½È€¡½¹ÍÐµ…Ñ ½˜µ…Ñ¡•Ì¤ì(€€€€€€€•áÁ•Ð¡µ…Ñ¡lÅt¤¹Ñ½	” œœ¤ì(€€€€€ô(€€€ô(€ô¤ì)ô¤ì((¼¼I•Á½Í¥Ñ½Éä¥¹Ñ•±±¥•¹”‘É¥±±‘½Ý¸€ ŒÄÜÄÈ¤ƒŠPÕ¹¥™¥•Í…¸ÍÑ…Ñ”°Á½ÍÑÕÉ”(¼¼…ÁÌ°ÁÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”°Ñ½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡Ì°…¹É•µ•‘¥…Ñ¥½¸(¼¼…Ñ¥½¹Ì™½È½¹”É•Á½Í¥Ñ½Éä°…‘‘É•ÍÍ•‰ä„€ýÉ•Á½Í¥Ñ½ÉäôÅÕ•ÉäÁ…É…´¸)‘•ÍÉ¥‰” AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€ ŒÄÜÄÈ¤œ°€ ¤€ôøì(€½¹ÍÐÑ…É•ÑI•Á½Í¥Ñ½Éä€ô€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œì((€½¹ÍÐ½µÁ±•Ñ•‘M…¸èI•Á½M…¹I•½É€ôì(€€€¥è€É•Á¼µÍ…¸µ‘•Ñ…¥°µ½µÁ±•Ñ”œ°(€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€ÍÑ…ÑÕÌè€ÍÕ••‘•œ°(€€€ÍÑ…ÉÑ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔÀèÀÁhœ°(€€€™¥¹¥Í¡•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔÔèÀÁhœ°(€€€½µµ¥ÑÍ}Í…¹¹•è€ÄÈ°(€€€™¥±•Í}Í…¹¹•è€ÌÐÀ°(€€€™¥¹‘¥¹}½Õ¹Ðè€Ì°(€€€ÑÉÕ¹…Ñ•è™…±Í”°(€€€Í…¹}µ½‘”è€ÅÕ¥¬œ°(€€€Í½ÕÉ•}¡•…±Ñ è€½µÁ±•Ñ”œ°(€€€Í½ÕÉ•}¡•…±Ñ¡}‘•Ñ…¥±Ìèl(€€€€€ìÍ½ÕÉ”è€¥Ñ¡Õ‰}Á½ÍÑÕÉ”œ°ÍÑ…ÑÕÌè€½µÁ±•Ñ”œô°(€€€€€ìÍ½ÕÉ”è€É•Á½}¥Ñ}¡¥ÍÑ½Éäœ°ÍÑ…ÑÕÌè€½µÁ±•Ñ”œô(€€€t(€ôì((€½¹ÍÐÁ…ÉÑ¥…±M…¸èI•Á½M…¹I•½É€ôì(€€€€¸¸¹½µÁ±•Ñ•‘M…¸°(€€€¥è€É•Á¼µÍ…¸µ‘•Ñ…¥°µÁ…ÉÑ¥…°œ°(€€€Í½ÕÉ•}¡•…±Ñ è€Á…ÉÑ¥…°œ°(€€€Í½ÕÉ•}¡•…±Ñ¡}‘•Ñ…¥±Ìèl(€€€€€ìÍ½ÕÉ”è€¥Ñ¡Õ‰}Á½ÍÑÕÉ”œ°ÍÑ…ÑÕÌè€½µÁ±•Ñ”œô°(€€€€€ìÍ½ÕÉ”è€É•Á½}¥Ñ}¡¥ÍÑ½Éäœ°ÍÑ…ÑÕÌè€Á…ÉÑ¥…°œ°µ•ÍÍ…”è€¥Ð¡¥ÍÑ½ÉäÑÉÕ¹…Ñ•…Ð€ÔÀÀ½µµ¥ÑÌ¸œô(€€€t(€ôì((€½¹ÍÐÁ½ÍÑÕÉ•¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€¥è€™¥¹‘¥¹œµÁ½ÍÑÕÉ”µ‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°(€€€Í…¹}¥è€É•Á¼µÍ…¸µ‘•Ñ…¥°µ½µÁ±•Ñ”œ°(€€€ÑåÁ”è€É•Á½}µ¥Í½¹™¥ÕÉ…Ñ¥½¸œ°(€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€Ñ¥Ñ±”è€•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•œ°(€€€¡Õµ…¹}ÍÕµµ…Éäè€I•Á½Í¥Ñ½Éä‘•™…Õ±Ð‰É…¹ ‘½•Ì¹½ÐÉ•ÅÕ¥É”ÁÕ±°É•ÅÕ•ÍÐÉ•Ù¥•ÝÌ¸œ°(€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€‘•Ñ•Ñ½Èè€¥Ñ¡Õ‰}‘•™…Õ±Ñ}‰É…¹¡}Õ¹ÁÉ½Ñ•Ñ•œ°(€€€•Ù¥‘•¹”èì(€€€€€…‘…ÁÑ•É}Í½ÕÉ”è€¥Ñ¡Õ‰}Á½ÍÑÕÉ”œ°(€€€€€¥Ñ¡Õ‰}Á½ÍÑÕÉ•}¡•­}¥è€‘•™…Õ±Ñ}‰É…¹¡}ÁÉ½Ñ•Ñ¥½¸œ°(€€€€€¥Ñ¡Õ‰}Á½ÍÑÕÉ•}Í½Á”è€É•Á½Í¥Ñ½Éäœ(€€€ô°(€€€É•µ•‘¥…Ñ¥½¸è€¹…‰±”‰É…¹ ÁÉ½Ñ•Ñ¥½¸Ý¥Ñ É•ÅÕ¥É•É•Ù¥•ÝÌ¸œ°(€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÀèÀÁhœ(€ôì((€½¹ÍÐÝ½É­™±½Ý¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€¥è€™¥¹‘¥¹œµÝ½É­™±½Üµ½¥‘Œœ°(€€€Í…¹}¥è€É•Á¼µÍ…¸µ‘•Ñ…¥°µ½µÁ±•Ñ”œ°(€€€ÑåÁ”è€É•Á½}µ¥Í½¹™¥ÕÉ…Ñ¥½¸œ°(€€€Í•Ù•É¥Ñäè€µ•‘¥Õ´œ°(€€€Ñ¥Ñ±”è€]½É­™±½Ü=%ÑÉÕÍÐ¥Ì‰É½…œ°(€€€¡Õµ…¹}ÍÕµµ…Éäè€Ý½É­™±½Ü…¸µ¥¹Ð=%Ñ½­•¹Ì……¥¹ÍÐ„‰É½…]LÉ½±”ÑÉÕÍÐ½¹‘¥Ñ¥½¸¸œ°(€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€‘•Ñ•Ñ½Èè€Ý½É­™±½Ý}½¥‘}‰É½…‘}ÑÉÕÍÐœ°(€€€•Ù¥‘•¹”èì™¥±•}Á…Ñ è€œ¹¥Ñ¡Õˆ½Ý½É­™±½ÝÌ½‘•Á±½ä¹åµ°œô°(€€€É•µ•‘¥…Ñ¥½¸è€I•ÍÑÉ¥Ð=%ÑÉÕÍÐÑ¼„ÍÁ•¥™¥ŒÉ•˜½©½ˆ¸œ°(€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÄèÀÔèÀÁhœ(€ôì((€½¹ÍÐ•µÁÑåI¥Í­É…Á èI•Á½I¥Í­É…Á €ôì(€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€¹½‘•Ìèmt°(€€€•‘•Ìèmt°(€€€Í½É•Ìèmt°(€€€ÍÕµµ…Éäèì(€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°(€€€€€¹½‘•}½Õ¹Ðè€À°(€€€€€•‘•}½Õ¹Ðè€À°(€€€€€Õ¹­¹½Ý¹}¹½‘•}½Õ¹Ðè€À°(€€€€€Õ¹­¹½Ý¹}•‘•}½Õ¹Ðè€À°(€€€€€¡¥¡}É¥Í­}™¥¹‘¥¹Ìè€À°(€€€€€É¥Ñ¥…±}™¥¹‘¥¹Ìè€À(€€€ô(€ôì((€½¹ÍÐÉ¥Í­É…Á¡]¥Ñ¡M½É•ÌèI•Á½I¥Í­É…Á €ôì(€€€€¸¸¹•µÁÑåI¥Í­É…Á °(€€€Í½É•Ìèl(€€€€€ì(€€€€€€€™¥¹‘¥¹}¥èÁ½ÍÑÕÉ•¥¹‘¥¹œ¹¥°(€€€€€€€™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µÁ½ÍÑÕÉ”œ°(€€€€€€€Í½É”è€àà°(€€€€€€€Í•Ù•É¥Ñäè€¡¥ œ°(€€€€€€€½¹™¥‘•¹”è€À¸ä°(€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€Í•Ù•É¥Ñäè€àÀ°(€€€€€€€€€½¹™¥‘•¹”è€äÀ°(€€€€€€€€€•áÁ±½¥Ñ…‰¥±¥Ñäè€ØÀ°(€€€€€€€€€ÁÉ¥Ù¥±•”è€ÐÀ°(€€€€€€€€€•áÁ½ÍÕÉ”è€ÔÔ°(€€€€€€€€€•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€ÌÀ°(€€€€€€€€€™É•Í¡¹•ÍÌè€ÄÀÀ°(€€€€€€€€€Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€ÜÀ(€€€€€€€ô°(€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€ô°(€€€€€ì(€€€€€€€™¥¹‘¥¹}¥èÝ½É­™±½Ý¥¹‘¥¹œ¹¥°(€€€€€€€™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µÝ½É­™±½Üœ°(€€€€€€€Í½É”è€ØÈ°(€€€€€€€Í•Ù•É¥Ñäè€µ•‘¥Õ´œ°(€€€€€€€½¹™¥‘•¹”è€À¸Ü°(€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€Í•Ù•É¥Ñäè€ÔÔ°(€€€€€€€€€½¹™¥‘•¹”è€ÜÀ°(€€€€€€€€€•áÁ±½¥Ñ…‰¥±¥Ñäè€ÔÀ°(€€€€€€€€€ÁÉ¥Ù¥±•”è€ÌÀ°(€€€€€€€€€•áÁ½ÍÕÉ”è€ÐÀ°(€€€€€€€€€•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€À°(€€€€€€€€€™É•Í¡¹•ÍÌè€ÄÀÀ°(€€€€€€€€€Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€À(€€€€€€€ô°(€€€€€€€Õ¹­¹½Ý¹Ìèl¥‘•¹Ñ¥Ñå}Ñ…É•Ðt(€€€€€ô(€€€t(€ôì((€…Íå¹Œ™Õ¹Ñ¥½¸É•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡½ÁÑ¥½¹Ìèì(€€€¥¹¥Ñ¥…±I•Á½Í¥Ñ½ÉäüèÍÑÉ¥¹œì(€€€Í…¹ÌüèI•Á½M…¹I•½É‘mtì(€€€™¥¹‘¥¹Ìüè¥¹‘¥¹mtì(€€€É¥Í­É…Á üèI•Á½I¥Í­É…Á ì(€€€Á½ÍÑÕÉ”üè¥Ñ!Õ‰I•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”ì(€€€Á½ÍÑÕÉ•ÉÉ½Èüèìµ•ÍÍ…”èÍÑÉ¥¹œìÍÑ…ÑÕÌè¹Õµ‰•Èôì(€€€±¥ÍÑI•Á½¥¹‘¥¹ÍÉÉ½Èüèìµ•ÍÍ…”èÍÑÉ¥¹œìÍÑ…ÑÕÌè¹Õµ‰•Èôì(€€€±¥ÍÑI•Á½M…¹ÍÉÉ½Èüèìµ•ÍÍ…”èÍÑÉ¥¹œìÍÑ…ÑÕÌè¹Õµ‰•Èôì(€ô€ôíô¤ì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì((€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐÍ…¹ÍMÁä€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤ì(€€€¥˜€¡½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½M…¹ÍÉÉ½È¤ì(€€€€€Í…¹ÍMÁä¹µ½­I•©•Ñ•‘Y…±Õ”¡¹•Ü…Á¤¹Á¥ÉÉ½È¡½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½M…¹ÍÉÉ½È¹µ•ÍÍ…”°½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½M…¹ÍÉÉ½È¹ÍÑ…ÑÕÌ¤¤ì(€€€ô•±Í”ì(€€€€€Í…¹ÍMÁä¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌè½ÁÑ¥½¹Ì¹Í…¹Ì€üüm½µÁ±•Ñ•‘M…¹tô¤ì(€€€ô((€€€½¹ÍÐ™¥¹‘¥¹ÍMÁä€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤ì(€€€¥˜€¡½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½¥¹‘¥¹ÍÉÉ½È¤ì(€€€€€™¥¹‘¥¹ÍMÁä¹µ½­I•©•Ñ•‘Y…±Õ”¡¹•Ü…Á¤¹Á¥ÉÉ½È¡½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½¥¹‘¥¹ÍÉÉ½È¹µ•ÍÍ…”°½ÁÑ¥½¹Ì¹±¥ÍÑI•Á½¥¹‘¥¹ÍÉÉ½È¹ÍÑ…ÑÕÌ¤¤ì(€€€ô•±Í”ì(€€€€€™¥¹‘¥¹ÍMÁä¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌè½ÁÑ¥½¹Ì¹™¥¹‘¥¹Ì€üümÁ½ÍÑÕÉ•¥¹‘¥¹œ°Ý½É­™±½Ý¥¹‘¥¹tô¤ì(€€€ô(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡½ÁÑ¥½¹Ì¹É¥Í­É…Á €üüÉ¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì((€€€½¹ÍÐÁ½ÍÑÕÉ•MÁä€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤ì(€€€¥˜€¡½ÁÑ¥½¹Ì¹Á½ÍÑÕÉ•ÉÉ½È¤ì(€€€€€Á½ÍÑÕÉ•MÁä¹µ½­I•©•Ñ•‘Y…±Õ”¡¹•Ü…Á¤¹Á¥ÉÉ½È¡½ÁÑ¥½¹Ì¹Á½ÍÑÕÉ•ÉÉ½È¹µ•ÍÍ…”°½ÁÑ¥½¹Ì¹Á½ÍÑÕÉ•ÉÉ½È¹ÍÑ…ÑÕÌ¤¤ì(€€€ô•±Í”ì(€€€€€Á½ÍÑÕÉ•MÁä¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€€€ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€€€Á½ÍÑÕÉ”è½ÁÑ¥½¹Ì¹Á½ÍÑÕÉ”€üüì(€€€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€€€€€€€¥¹ÍÑ…±±…Ñ¥½¹}¥è€ÄÈÌÐÔ°(€€€€€€€€€½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€€€¡•­Ìèl(€€€€€€€€€€€ì(€€€€€€€€€€€€€¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€¥¹Í•ÕÉ”œ°(€€€€€€€€€€€€€ÍÕµµ…Éäè€•™…Õ±Ð‰É…¹ ¥Ìµ¥ÍÍ¥¹œÉ•ÅÕ¥É•ÁÕ±°É•ÅÕ•ÍÐÉ•Ù¥•ÝÌ¸œ(€€€€€€€€€€€ô°(€€€€€€€€€€€ì(€€€€€€€€€€€€€¥è€Í•É•ÐµÍ…¹¹¥¹œœ°…Ñ•½Éäè€Í•ÕÉ¥Ñäœ°ÍÑ…Ñ”è€Í•ÕÉ”œ°(€€€€€€€€€€€€€ÍÕµµ…Éäè€M•É•ÐÍ…¹¹¥¹œ¥Ì•¹…‰±•¸œ(€€€€€€€€€€€ô(€€€€€€€€€t(€€€€€€€ô(€€€€€ô¤ì(€€€ô(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÁÉ•Ù¥•ÝI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€™¥¹‘¥¹œèÁ½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€É•µ•‘¥…Ñ¥½¸èì(€€€€€€€‘•Ñ•Ñ½Èè€¥Ñ¡Õ‰}‘•™…Õ±Ñ}‰É…¹¡}Õ¹ÁÉ½Ñ•Ñ•œ°(€€€€€€€ÍÕµµ…Éäè€I•ÅÕ¥É”ÁÕ±°µÉ•ÅÕ•ÍÐÉ•Ù¥•ÝÌ½¸Ñ¡”‘•™…Õ±Ð‰É…¹ œ°(€€€€€€€É¥Í­}ÍÕµµ…Éäè€U¹É•ÍÑÉ¥Ñ•µ•É•Ì‰åÁ…ÍÌ•Ù¥‘•¹”É•Ù¥•Ü¸œ°(€€€€€€€ÍÑ•ÁÌèl¹…‰±”‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°€I•ÅÕ¥É”Í¥¹•½µµ¥ÑÌt°(€€€€€€€Í…™•Ñå}¹½Ñ•Ìèmt°Ù…±¥‘…Ñ¥½¸èmt°(€€€€€€€Í•É•Ñ}É½Ñ…Ñ¥½¸è™…±Í”°ÁÕ‰±¥Í¡…‰±”èÑÉÕ”°(€€€€€€€•Ù¥‘•¹”èì™¥¹‘¥¹}¥èÁ½ÍÑÕÉ•¥¹‘¥¹œ¹¥ô(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÉ•Á½Í¥Ñ½Éä€ô½ÁÑ¥½¹Ì¹¥¹¥Ñ¥…±I•Á½Í¥Ñ½Éä€üüÑ…É•ÑI•Á½Í¥Ñ½Éäì(€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐ¥¹¥Ñ¥…±¹ÑÉä€ôÉ•Á½Í¥Ñ½Éä(€€€€€€ü€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡É•Á½Í¥Ñ½Éä¥õ€(€€€€€€è€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½Éµ€ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím¥¹¥Ñ¥…±¹ÑÉåuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€É•ÑÕÉ¸ì™¥¹‘¥¹ÍMÁäôì(€ô((€‰•™½É•…   ¤€ôøì(€€€€¼¼AÉ¥½È‘•ÍÉ¥‰”‰±½­Ì¥¸Ñ¡¥Ì™¥±”±•…Ù”µ½‘Õ±”µÍ½Á•µ½­Ì(€€€€¼¼€¡µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì€¼µ½­	…­•¹‘•…ÑÕÉ•ÌÕÍ”Ù¤¹‘½5½¬¤Ñ¡…Ð…¸(€€€€¼¼±¥¹•ÈÁ…ÍÐÑ¡•¥È…™Ñ•É… ¸I•Í•Ð‰½Ñ Ñ¡”µ½¬É•¥ÍÑÉä…¹Ñ¡”µ½‘Õ±”(€€€€¼¼…¡”Í¼•Ù•Éä‘É¥±±‘½Ý¸Ñ•ÍÐÍÑ…ÉÑÌ™É½´„±•…¸¥µÁ½ÉÐÉ…Á ¸(€€€Ù¤¹É•ÍÑ½É•±±5½­Ì ¤ì(€€€Ù¤¹‘½U¹µ½¬ œ¸½¡½½­Ì½ÕÍ•	…­•¹‘•…ÑÕÉ•Ìœ¤ì(€€€Ù¤¹‘½U¹µ½¬ œ¸½Á…•Ì½½¹‰½…É‘¥¹œ½½¹‰½…É‘¥¹UÑ¥±Ìœ¤ì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€ô¤ì((€…™Ñ•É…   ¤€ôøì(€€€Ù¤¹É•ÍÑ½É•±±5½­Ì ¤ì(€€€Ù¤¹‘½U¹µ½¬ œ¸½¡½½­Ì½ÕÍ•	…­•¹‘•…ÑÕÉ•Ìœ¤ì(€€€Ù¤¹‘½U¹µ½¬ œ¸½Á…•Ì½½¹‰½…É‘¥¹œ½½¹‰½…É‘¥¹UÑ¥±Ìœ¤ì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌÕ¹¥™¥•Í…¸ÍÑ…Ñ”°Á½ÍÑÕÉ”…ÁÌ°…¹ÁÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”™½È„É•Á½Í¥Ñ½Éäœ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥° ¤ì((€€€€¼¼!•…‘•È¹…µ•ÌÑ¡”É•Á½Í¥Ñ½Éä¸(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”èÑ…É•ÑI•Á½Í¥Ñ½Éäô¤ì((€€€€¼¼M…¸ÍÑÉ¥ÀÍ¡½ÝÌÑ¡”½µÁ±•Ñ”Á¥±°¸(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½½µÁ±•Ñ”Í…¸½¤¤ì((€€€€¼¼A½ÍÑÕÉ”…ÀÍ•Ñ¥½¸ÍÕÉ™…•ÌÑ¡”¥¹Í•ÕÉ”¡•¬…¹¡¥‘•ÌÑ¡”Í•ÕÉ”½¹”¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½µ¥ÍÍ¥¹œÉ•ÅÕ¥É•ÁÕ±°É•ÅÕ•ÍÐÉ•Ù¥•ÝÌ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½M•É•ÐÍ…¹¹¥¹œ¥Ì•¹…‰±•½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€€¼¼EÕ•Õ”Í¡½ÝÌ‰½Ñ ™¥¹‘¥¹Ì°Á½ÍÑÕÉ”Í½É”€àà½µ•Ì‰•™½É”Ý½É­™±½ÜÍ½É”€ØÈ¸(€€€½¹ÍÐÅÕ•Õ•1¥ÍÐ€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤¹ÅÕ•ÉåM•±•Ñ½È Õ°œ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¤¹¹½Ð¹Ñ½	•9Õ±° ¤ì(€€€½¹ÍÐÉ½ÝÌ€ô€¡ÅÕ•Õ•1¥ÍÐ…Ì!Q51±•µ•¹Ð¤¹ÅÕ•ÉåM•±•Ñ½É±° ±¤œ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ •™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•œ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ Í½É”€ààœ¤ì(€€€•áÁ•Ð¡É½ÝÍlÅt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ]½É­™±½Ü=%ÑÉÕÍÐ¥Ì‰É½…œ¤ì(€€€•áÁ•Ð¡É½ÝÍlÅt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ Í½É”€ØÈœ¤ì(€ô¤ì((€¥Ð ÍÕÉ™…•Ì„Á…ÉÑ¥…°µÍ…¸Á¥±°…¹Á•ÈµÍ½ÕÉ”¡•…±Ñ ‘•Ñ…¥±ÌÝ¡•¸Ñ¡”Í…¸¥ÌÁ…ÉÑ¥…°œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ìÍ…¹ÌèmÁ…ÉÑ¥…±M…¹tô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”èÑ…É•ÑI•Á½Í¥Ñ½Éäô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½A…ÉÑ¥…°Í…¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½¥Ð¡¥ÍÑ½ÉäÑÉÕ¹…Ñ•…Ð€ÔÀÀ½µµ¥ÑÌ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌÑ¡”¹¼µ™¥¹‘¥¹Ì•µÁÑäÍÑ…Ñ”Ý¡•¸Ñ¡”ÅÕ•Õ”¥Ì•µÁÑäœ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì™¥¹‘¥¹Ìèmt°É¥Í­É…Á è•µÁÑåI¥Í­É…Á ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½9¼™¥¹‘¥¹Ì™½ÈÑ¡¥ÌÉ•Á½Í¥Ñ½Éä½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ÍÕÉ™…•Ì„ÑÉÕ¹…Ñ•Í…¸µ¡¥ÍÑ½ÉäÝ…É¹¥¹œ¥¹ÍÑ•…½˜€‰9¼Í…¸å•ÐˆÝ¡•¸Ñ¡”Í•…É ¡¥Ð¥ÑÌ…Àœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼1¥ÍÑI•Á½M…¹Ì¥ÌÝ½É­ÍÁ…”µÝ¥‘”°Í¼„É•Á½Í¥Ñ½ÉäÝ¡½Í”¹•Ý•ÍÐÍ…¸Í¥ÑÌ(€€€€¼¼‰•¡¥¹µ½É”Ñ¡…¸IA=}%9Q11%9}M9}5a}AL€¨M9}A}1%5%P(€€€€¼¼¹•Ý•ÈÝ½É­ÍÁ…”Í…¹Ì¥Ì¹•Ù•ÈÉ•…¡•¸M¥µÕ±…Ñ”Ñ¡…Ð‰äÉ•ÑÕÉ¹¥¹œ(€€€€¼¼Á…•ÌÑ¡…Ð¹•Ù•Èµ…Ñ Ñ¡”Ñ…É•ÐÉ•Á½Í¥Ñ½Éä…¹…±Ý…åÌÉ•ÑÕÉ¸„(€€€€¼¼¹•áÑ}ÕÉÍ½ÈÍ¼Ñ¡”™•Ñ¡•È•á¡…ÕÍÑÌ¥ÑÌ€ÈÀµÁ…”•¥±¥¹œ¸(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐ½Ñ¡•ÉI•Á½M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹½µÁ±•Ñ•‘M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ½Ñ¡•Èœ°(€€€€€É•Á½Í¥Ñ½Éäè€Í½µ•½¹”µ•±Í”½½Ñ¡•ÈµÉ•Á¼œ(€€€ôì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèm½Ñ¡•ÉI•Á½M…¹t°(€€€€€¹•áÑ}ÕÉÍ½Èè€¹•Ù•Èµ•á¡…ÕÍÑ•œ(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmtô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡•µÁÑåI¥Í­É…Á ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼!•…‘•ÈÉ•…‘Ì€‰M…¸¡¥ÍÑ½ÉäÑÉÕ¹…Ñ•ˆ°¹½Ð€‰9¼Í…¸å•Ðˆ¸Q¡”‰…¹¹•È(€€€€¼¼ÍÑ••ÉÌÑ¡”½Á•É…Ñ½ÈÑ¼™¥±Ñ•È‰äÉ•Á½Í¥Ñ½Éä¥¹ÍÑ•…½˜…ÍÍÕµ¥¹œÑ¡”(€€€€¼¼É•Á½Í¥Ñ½Éä¡…Ì¹•Ù•È‰••¸Í…¹¹•¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½M…¸¡¥ÍÑ½ÉäÑÉÕ¹…Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½9¼Í…¸å•Ð½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½I•Á½Í¥Ñ½ÉäÍ…¸Í•…É ¡¥Ð¥ÑÌÍ…™•Ñä•¥±¥¹œ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½Õ¹ÑÌÁÕ‰±¥Í¡…‰±”µÁ…Ñ ‘•Ñ•Ñ½ÉÌ…Ì™¥àµÉ•…‘ä…¹Õ¥‘…¹”µ½¹±ä…ÌÁÉ•Ù¥•Üµ½¹±äœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼Ý½É­™±½Ý}ÝÉ¥Ñ•}…±±}Á•Éµ¥ÍÍ¥½¹ÌƒŠH‘•Ñ•Éµ¥¹¥ÍÑ¥ŒÁ…Ñ €¡AÕ‰±¥Í¡…‰±”éÑÉÕ”¤¸(€€€€¼¼Ý½É­™±½Ý}½¥‘}‰É½…‘}ÑÉÕÍÐƒŠHÕ¥‘…¹”µ½¹±ä€¡AÕ‰±¥Í¡…‰±”é™…±Í”¤¸(€€€€¼¼	½Ñ …É”ÍÕÁÁ½ÉÑ•€¡AÉ•Ù¥•Ü‰ÕÑÑ½¸¤°‰ÕÐ½¹±äÑ¡”™¥ÉÍÐ¥Ì™¥àµÉ•…‘ä¸(€€€½¹ÍÐ™¥áI•…‘å¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Ý½É­™±½Ý¥¹‘¥¹œ°(€€€€€¥è€™¥¹‘¥¹œµÝ½É­™±½ÜµÝÉ¥Ñ”µ…±°œ°(€€€€€Ñ¥Ñ±”è€]½É­™±½Ü¡…ÌÝÉ¥Ñ”µ…±°Á•Éµ¥ÍÍ¥½¹Ìœ°(€€€€€‘•Ñ•Ñ½Èè€Ý½É­™±½Ý}ÝÉ¥Ñ•}…±±}Á•Éµ¥ÍÍ¥½¹Ìœ(€€€ôì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì™¥¹‘¥¹Ìèm™¥áI•…‘å¥¹‘¥¹œ°Ý½É­™±½Ý¥¹‘¥¹tô¤ì(€€€½¹ÍÐÅÕ•Õ•1¥ÍÐ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ œÄ™¥àµÉ•…‘äœ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ œÄÁÉ•Ù¥•Üµ½¹±äœ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½Ð½™™•È„AÉ•Ù¥•Ü‰ÕÑÑ½¸™½ÈÕ¹É•½¹¥é•Ñ•ÉÉ…™½Éµ|‘•Ñ•Ñ½ÉÌœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼É½¹Ñ•¹ÁÉ•™¥àÍ•ÐÕÍ•Ñ¼¥¹±Õ‘”Ñ•ÉÉ…™½Éµ|½‘½­•É|½¬áÍ|°‰ÕÐÑ¡”(€€€€¼¼‰…­•¹ÍÝ¥Ñ ½¹±ä…•ÁÑÌ„™¥á•±¥ÍÐ½˜•á…Ð‘•Ñ•Ñ½ÉÌ™½ÈÑ¡•Í”(€€€€¼¼™…µ¥±¥•Ì¸¸Õ¹É•½¹¥é•Ñ•ÉÉ…™½Éµ|‘•Ñ•Ñ½ÈÝ½Õ±€ÐÈÈ½¸ÁÉ•Ù¥•Ü¸(€€€½¹ÍÐÕ¹ÍÕÁÁ½ÉÑ•‘Q•ÉÉ…™½Éµ¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Ý½É­™±½Ý¥¹‘¥¹œ°(€€€€€¥è€™¥¹‘¥¹œµÑ•ÉÉ…™½É´µÕ¹É•½¹¥é•œ°(€€€€€Ñ¥Ñ±”è€U¹É•½¹¥é•Ñ•ÉÉ…™½É´µ¥Í½¹™¥ÕÉ…Ñ¥½¸œ°(€€€€€‘•Ñ•Ñ½Èè€Ñ•ÉÉ…™½Éµ}Í½µ•}¹•Ý}‘•Ñ•Ñ½É}‰…­•¹‘}‘½•Í}¹½Ñ}¡…¹‘±”œ(€€€ôì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì™¥¹‘¥¹ÌèmÕ¹ÍÕÁÁ½ÉÑ•‘Q•ÉÉ…™½Éµ¥¹‘¥¹tô¤ì(€€€½¹ÍÐÅÕ•Õ•1¥ÍÐ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤ì(€€€€¼¼I½ÜÉ•¹‘•É•™½ÈÑÉ¥…”¸(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ U¹É•½¹¥é•Ñ•ÉÉ…™½É´µ¥Í½¹™¥ÕÉ…Ñ¥½¸œ¤ì(€€€€¼¼9¼AÉ•Ù¥•Ü‰ÕÑÑ½¸¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÉ•Ù¥•ÜÉ•µ•‘¥…Ñ¥½¸½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÅÕ•Õ•1¥ÍÐ¤¹•Ñ	åQ•áÐ ½I•Ù¥•Ü¥¸¥Ñ!Õˆ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌ…¸•ÉÉ½È‰…¹¹•ÈÝ¡•¸Ñ¡”É•Á½Í¥Ñ½ÉäÅÕ•ÉäÁ…É…µ•Ñ•È¥Ìµ¥ÍÍ¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì¥¹¥Ñ¥…±I•Á½Í¥Ñ½Éäè€œœô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½I•Á½Í¥Ñ½Éä¹½ÐÍ•±•Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åI½±” ±¥¹¬œ°ì¹…µ”è€½	…¬Ñ¼É•Á½Í¥Ñ½É¥•Ì½¤ô¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌ…¸¥¹±¥¹”™¥¹‘¥¹Ì•ÉÉ½È‰ÕÐ­••ÁÌÑ¡”Í…¸ÍÑÉ¥À…¹Á½ÍÑÕÉ”ÕÍ…‰±”œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼¥¹‘¥¹Ì±…¹”ÉÕ¹Ì¥¹‘•Á•¹‘•¹Ñ±ä¹½Ü°Í¼„™¥¹‘¥¹Ì™…¥±ÕÉ”ÍÕÉ™…•Ì(€€€€¼¼¥¹±¥¹”¥¸Ñ¡”ÅÕ•Õ”Á…¹•°Ý¡¥±”Ñ¡”Í…¸ÍÑÉ¥À…¹Á½ÍÑÕÉ”Á…¹•±Ì(€€€€¼¼ÍÑ¥±°É•¹‘•ÈÑ¡•¥È½Ý¸ÍÕ•ÍÍ™Õ°ÍÑ…Ñ”¸(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì±¥ÍÑI•Á½¥¹‘¥¹ÍÉÉ½Èèìµ•ÍÍ…”è€‰½½´œ°ÍÑ…ÑÕÌè€ÔÀÀôô¤ì(€€€€¼¼M…¸ÍÑÉ¥À½µµ¥ÑÌ¥ÑÌ½Ý¸ÍÕ•ÍÌ•Ù•¸Ñ¡½Õ ™¥¹‘¥¹ÌÉ•©•Ñ•¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½½µÁ±•Ñ”Í…¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼¥¹‘¥¹ÌÅÕ•Õ”Á…¹•°ÍÕÉ™…•Ì¥ÑÌ½Ý¸•ÉÉ½È¸(€€€½¹ÍÐÅÕ•Õ•A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÅÕ•Õ•A…¹•°¤¹•Ñ	åQ•áÐ ½‰½½´½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼9¼Í¡…É•€‰½Õ±‘¸Ð±½…É•Á½Í¥Ñ½Éä¥¹Ñ•±±¥•¹”ˆ‰…¹¹•ÈƒŠPÑ¡…Ð(€€€€¼¼‰…¹¹•ÈÝ…Ìµ¥Í±•…‘¥¹œ‰•…ÕÍ”¥Ð¡¥Ñ¡”ÍÕ•ÍÍ™Õ°Í…¸Á…¹•°¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½½Õ±‘¸Ð±½…É•Á½Í¥Ñ½Éä¥¹Ñ•±±¥•¹”½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½µµ¥ÑÌÍÕ•ÍÍ™Õ°™¥¹‘¥¹ÌÝ¡•¸Ñ¡”Í…¸±½½­ÕÀÉ•©•ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼M…¸…¹™¥¹‘¥¹Ì±…¹•Ì…É”¥¹‘•Á•¹‘•¹Ð°Í¼„ÑÉ…¹Í¥•¹Ð(€€€€¼¼€½ØÄ½É•Á¼µÍ…¹Ì™…¥±ÕÉ”µÕÍÐ¹½Ð‘¥Í…É„ÍÕ•ÍÍ™Õ±±ä™•Ñ¡•(€€€€¼¼™¥¹‘¥¹ÌÅÕ•Õ”¸AÉ•Ù¥½ÕÍ±äAÉ½µ¥Í”¹…±°É•©•Ñ•Ñ½•Ñ¡•È°Í¼Ñ¡”(€€€€¼¼Á…”µ¥Í±•…‘¥¹±äÍ¡½Ý•‰½Ñ €‰9¼Í…¸å•Ðˆ…¹€‰9¼™¥¹‘¥¹Ìˆ(€€€€¼¼Õ¹‘•È„Í¡…É••ÉÉ½È‰…¹¹•È•Ù•¸Ý¡•¸™¥¹‘¥¹ÌÝ…Ì™¥¹”¸(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì±¥ÍÑI•Á½M…¹ÍÉÉ½Èèìµ•ÍÍ…”è€Í…¹Ì‘½Ý¸œ°ÍÑ…ÑÕÌè€ÔÀÈôô¤ì(€€€€¼¼¥¹‘¥¹ÌÅÕ•Õ”É•¹‘•É•™É½´¥ÑÌ½Ý¸ÍÕ•ÍÍ™Õ°É•ÍÁ½¹Í”¸(€€€½¹ÍÐÅÕ•Õ•A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÅÕ•Õ•A…¹•°¤¹•Ñ	åQ•áÐ ½•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÅÕ•Õ•A…¹•°¤¹•Ñ	åQ•áÐ ½]½É­™±½Ü=%ÑÉÕÍÐ¥Ì‰É½…½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼M…¸ÍÑÉ¥ÀÍÕÉ™…•Ì¥ÑÌ½Ý¸¥¹±¥¹”•ÉÉ½È°¹½ÐÑ¡”Í¡…É•‰…¹¹•È¸(€€€½¹ÍÐÍ…¹A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ 1…Ñ•ÍÐÍ…¸œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Í…¹A…¹•°¤¹•Ñ	åQ•áÐ ½Í…¹Ì‘½Ý¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½½Õ±‘¸Ð±½…É•Á½Í¥Ñ½Éä¥¹Ñ•±±¥•¹”½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼9½ÐÑ¡”µ¥Í±•…‘¥¹œ€‰9¼Í…¸å•Ðˆ™…±±‰…¬•¥Ñ¡•ÈƒŠPÑ¡…ÐÝ½Õ±ÍÕ•ÍÐ(€€€€¼¼Ñ¡”É•Á½Í¥Ñ½Éä¡…Ì¹•Ù•È‰••¸Í…¹¹•É…Ñ¡•ÈÑ¡…¸„ÑÉ…¹Í¥•¹Ð•ÉÉ½È¸(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Í…¹A…¹•°¤¹ÅÕ•Éå	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€Ì°¹…µ”è€½9¼Í…¸å•Ð½¤ô¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð Í¡½ÝÌ…¸¥¹±¥¹”Á½ÍÑÕÉ”•ÉÉ½È‰ÕÐ­••ÁÌÑ¡”É•ÍÐ½˜Ñ¡”‘É¥±±‘½Ý¸ÕÍ…‰±”œ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ìÁ½ÍÑÕÉ•ÉÉ½Èèìµ•ÍÍ…”è€Á½ÍÑÕÉ”É…Ñ”±¥µ¥Ñ•œ°ÍÑ…ÑÕÌè€ÐÈäôô¤ì(€€€€¼¼¥¹‘¥¹ÌÅÕ•Õ”ÍÑ¥±°É•¹‘•É•¸(€€€€¼¼¥¹‘¥¹œÑ¥Ñ±”…ÁÁ•…ÉÌ¥¸‰½Ñ Ñ¡”ÅÕ•Õ”Á…¹•°…¹Ñ¡”Á…Ñ¡ÌÁ…¹•°¹½Ü(€€€€¼¼Ñ¡…ÐÁ…Ñ¡ÌÉ•¹‘•ÈÑ¡”…ÑÕ…°™¥¹‘¥¹œ¡…¥¸°Í¼Í½Á”Ñ¼Ñ¡”ÅÕ•Õ”¸(€€€…Ý…¥ÐÝ¥Ñ¡¥¸¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤¹™¥¹‘	åQ•áÐ ½•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•½¤¤ì(€€€€¼¼A½ÍÑÕÉ”Á…¹•°Í¡½ÝÌ…¸¥¹±¥¹”…±•ÉÐÝ¥Ñ¡½ÕÐ‰É•…­¥¹œÑ¡”Á…”¸]…¥Ð™½ÈÑ¡”(€€€€¼¼…Íå¹ŒÍÑ…Ñ”ÕÁ‘…Ñ”É…Ñ¡•ÈÑ¡…¸É•…‘¥¹œÍå¹¡É½¹½ÕÍ±äèÑ¡”Á½ÍÑÕÉ”É•ÅÕ•ÍÐ(€€€€¼¼É•©•ÑÌ½¸„Í•Á…É…Ñ”ÁÉ½µ¥Í”™É½´Ñ¡”Í…¹Ì½™¥¹‘¥¹Ì½É…Á ™•Ñ °…¹¥ÑÌ(€€€€¼¼…Ñ ¡…¹‘±•ÈÉÕ¹Ì…™Ñ•ÈÑ¡”ÅÕ•Õ”Ì¥¹¥Ñ¥…°É•¹‘•È¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½Á½ÍÑÕÉ”É…Ñ”±¥µ¥Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½Á•¹Ì„É•µ•‘¥…Ñ¥½¸ÁÉ•Ù¥•ÜÝ¡•¸Ñ¡”½Á•É…Ñ½È±¥­ÌAÉ•Ù¥•ÜÉ•µ•‘¥…Ñ¥½¸½¸„™¥àµÉ•…‘ä™¥¹‘¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥° ¤ì(€€€½¹ÍÐÁÉ•Ù¥•Ý	ÕÑÑ½¹Ì€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÉ•Ù¥•ÜÉ•µ•‘¥…Ñ¥½¸½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÁÉ•Ù¥•Ý	ÕÑÑ½¹ÍlÁt¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½I•ÅÕ¥É”ÁÕ±°µÉ•ÅÕ•ÍÐÉ•Ù¥•ÝÌ½¸Ñ¡”‘•™…Õ±Ð‰É…¹ ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½¹…‰±”‰É…¹ ÁÉ½Ñ•Ñ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ½µµ¥ÑÌÍ…¸…¹™¥¹‘¥¹Ì•Ù•¸Ý¡•¸Ñ¡”É¥Í¬É…Á É•ÅÕ•ÍÐÉ•©•ÑÌœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼I¥Í¬É…Á ÉÕ¹Ì½¸¥ÑÌ½Ý¸±…¹”°Í¼„É…Á ™…¥±ÕÉ”µÕÍÐ¹½Ð‰±½¬Ñ¡”(€€€€¼¼Í…¸…¹™¥¹‘¥¹ÌÁ…¹•±ÌèÑ¡”ÅÕ•Õ”…±É•…‘ä™…±±Ì‰…¬Ñ¼Í•Ù•É¥Ñä(€€€€¼¼½É‘•É¥¹œÝ¡•¸É¥Í­É…Á ¥Ì¹Õ±°¸]¥Ñ¡½ÕÐÑ¡”ÍÁ±¥Ð°AÉ½µ¥Í”¹…±°Ý½Õ±(€€€€¼¼É•©•Ð½¸Ñ¡”É…Á •ÉÉ½È…¹Ñ¡”½Á•É…Ñ½ÈÝ½Õ±Í•”Ñ¡”Í¡…É••ÉÉ½È(€€€€¼¼‰…¹¹•È½Ù•È€‰9¼Í…¸å•Ðˆ€¼€‰9¼™¥¹‘¥¹Ìˆ•Ù•¸Ñ¡½Õ Ñ¡”…ÑÕ…°Í…¸(€€€€¼¼…¹™¥¹‘¥¹ÌÉ•ÅÕ•ÍÑÌ½µÁ±•Ñ•ÍÕ•ÍÍ™Õ±±ä¸(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹œ°Ý½É­™±½Ý¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•©•Ñ•‘Y…±Õ” (€€€€€¹•Ü…Á¤¹Á¥ÉÉ½È É¥Í¬É…Á Õ¹…Ù…¥±…‰±”œ°€ÔÀÌ¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼M…¸ÍÑÉ¥À…¹™¥¹‘¥¹ÌÅÕ•Õ”½µµ¥Ð‘•ÍÁ¥Ñ”Ñ¡”É…Á ™…¥±ÕÉ”¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½½µÁ±•Ñ”Í…¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€½¹ÍÐÅÕ•Õ•1¥ÍÐ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÅÕ•Õ•1¥ÍÐ¤¹•Ñ	åQ•áÐ ½•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÅÕ•Õ•1¥ÍÐ¤¹•Ñ	åQ•áÐ ½]½É­™±½Ü=%ÑÉÕÍÐ¥Ì‰É½…½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€€¼¼É…Á •ÉÉ½ÈÍÕÉ™…•Ì¥¹±¥¹”¥¸¥ÑÌ½Ý¸Á…¹•°ìÍ¡…É••ÉÉ½È‰…¹¹•ÈÍÑ…åÌ±•…È¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½É¥Í¬É…Á Õ¹…Ù…¥±…‰±”½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½½Õ±‘¸Ð±½…É•Á½Í¥Ñ½Éä¥¹Ñ•±±¥•¹”½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÁÉ•±½…Ý½É­ÍÁ…”µÝ¥‘”É••¹ÐÍ…¹ÌÑ¡É½Õ ÕÍ•¥Ñ!Õ‰½µ…¥¹…Ñ„œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼Q¡”‘É¥±±‘½Ý¸É•…‘ÌÍ…¹ÌÑ¡É½Õ ¥ÑÌ½Ý¸Á…¥¹…Ñ•(€€€€¼¼™¥¹‘I•Á½%¹Ñ•±±¥•¹•1…Ñ•ÍÑM…¸°¹½Ð‘½µ…¥¹…Ñ„¹Í…¹Ì¸A…ÍÍ¥¹œ„¹½¸µé•É¼(€€€€¼¼Í…¹1¥µ¥ÐÑ¼ÕÍ•¥Ñ!Õ‰½µ…¥¹…Ñ„Ý½Õ±Á…¥¹…Ñ”(€€€€¼¼±¥ÍÑI•Á½M…¹Í½ÉM•±•Ñ•‘I•Á½Í¥Ñ½É¥•ÌÝ¥Ñ ¹…ÉÉ½ÜÁ…•Ì‰•™½É”Ñ¡”(€€€€¼¼‘É¥±±‘½Ý¸•™™•Ð…¸•Ù•¸ÍÑ…ÉÐ°Í¥¹”Ñ¡”•™™•ÐÝ…¥ÑÌ™½È(€€€€¼¼‘½µ…¥¹…Ñ„¹±½…‘¥¹œÑ¼±•…È¸ÍÍ•ÉÐÑ¡”ÁÉ•±½…¹•Ù•ÈÉÕ¹Ì¸(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼]…¥Ð™½ÈÑ¡”‘É¥±±‘½Ý¸Ñ¼™¥¹¥Í ¥ÑÌ½Ý¸Í…¸±½½­ÕÀÍ¼Ý”­¹½ÜÑ¡”(€€€€¼¼•™™•Ð¡…ÌÉÕ¸¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½½µÁ±•Ñ”Í…¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€€¼¼Ù•Éä±¥ÍÑI•Á½M…¹Ì…±°µÕÍÐ‰”Ñ¡”‘É¥±±‘½Ý¸Ì½Ý¸Á…¥¹…Ñ½È€¡Ý¡¥ (€€€€¼¼ÕÍ•ÌIA=}%9Q11%9}M9}A}1%5%PôÔÀ¤°¹½ÐÑ¡”ÁÉ•±½…Ì¹…ÉÉ½Ü(€€€€¼¼€ÔµÉ•½ÉÁ…”¸%˜ÕÍ•¥Ñ!Õ‰½µ…¥¹…Ñ„¡…‰••¸¥Ù•¸„¹½¸µé•É¼(€€€€¼¼Í…¹1¥µ¥Ð°¥ÐÝ½Õ±…±°±¥ÍÑI•Á½M…¹ÌÝ¥Ñ ±¥µ¥ÐôÔ¸(€€€™½È€¡½¹ÍÐ…±°½˜±¥ÍÑI•Á½M…¹Ì¹µ½¬¹…±±Ì¤ì(€€€€€½¹ÍÐ™¥±Ñ•ÉÌ€ô…±±lÁtì(€€€€€•áÁ•Ð¡™¥±Ñ•ÉÌü¹±¥µ¥Ð¤¹¹½Ð¹Ñ½	” Ô¤ì(€€€ô(€ô¤ì((€¥Ð Á…¥¹…Ñ•Ì±¥ÍÑI•Á½M…¹ÌÕ¹Ñ¥°Ñ¡”Ñ…É•ÐÉ•Á½Í¥Ñ½Éä¥Ì™½Õ¹É…Ñ¡•ÈÑ¡…¸É•…‘¥¹œ½¹±äÑ¡”™¥ÉÍÐÁ…”œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì((€€€€¼¼¥ÉÍÐÁ…”¡½±‘Ì„Í…¸™½È…¹½Ñ¡•ÈÉ•Á½Í¥Ñ½ÉäìÑ¡”Ñ…É•ÐÉ•Á¼ÌÍ…¸(€€€€¼¼±¥Ù•Ì½¸Ñ¡”Í•½¹Á…”°­•å•‰äÑ¡”ÕÉÍ½È¸%˜Á…¥¹…Ñ¥½¸¥Ì¹½Ð(€€€€¼¼™½±±½Ý•Ñ¡”‘É¥±±‘½Ý¸™…±Í•±äÉ•Á½ÉÑÌ€‰9¼Í…¸å•Ðˆ¸(€€€½¹ÍÐ½Ñ¡•ÉI•Á½M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹½µÁ±•Ñ•‘M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ¹•Ý•Èµ½Ñ¡•Èœ°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½½Ñ¡•ÈµÉ•Á¼œ(€€€ôì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤ì(€€€±¥ÍÑI•Á½M…¹Ì¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡™¥±Ñ•ÉÌ¤€ôøì(€€€€€¥˜€ …™¥±Ñ•ÉÌü¹ÕÉÍ½È¤ì(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm½Ñ¡•ÉI•Á½M…¹t°¹•áÑ}ÕÉÍ½Èè€ÕÉÍ½ÈµÁ…”´Èœôì(€€€€€ô(€€€€€¥˜€¡™¥±Ñ•ÉÌ¹ÕÉÍ½È€ôôô€ÕÉÍ½ÈµÁ…”´Èœ¤ì(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tôì(€€€€€ô(€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmtôì(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½½µÁ±•Ñ”Í…¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”½¹¹•Ñ¥½¸µ±½…‘¥¹œÉ•¹‘•ÈÑÉ¥•ÉÌ…¸¥¹¥Ñ¥…°¹¼µ½¹¹•Ñ½È•™™•ÐÉÕ¸(€€€€¼¼Í¼±¥ÍÑI•Á½M…¹Ì¥Ì…±±•µ½É”Ñ¡…¸ÑÝ¥”ìÑ¡”µ•…¹¥¹™Õ°…ÍÍ•ÉÑ¥½¸¥Ì(€€€€¼¼Ñ¡…ÐÁ…¥¹…Ñ¥½¸™½±±½Ý•Ñ¡”ÕÉÍ½ÈÑ¼É•… Ñ¡”Ñ…É•ÐÉ•Á½Í¥Ñ½Éä¸(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡±¥ÍÑI•Á½M…¹Ì¹µ½¬¹…±±Ì¹Í½µ” ¡m™¥±Ñ•ÉÍt¤€ôø™¥±Ñ•ÉÌü¹ÕÉÍ½È€ôôô€ÕÉÍ½ÈµÁ…”´Èœ¤¤¹Ñ½	”¡ÑÉÕ”¤(€€€€¤ì(€ô¤ì((€¥Ð Á…¥¹…Ñ•Ì±¥ÍÑI•Á½¥¹‘¥¹ÌÍ¼…¸½±‘•È¡¥¡•ÈµÍ½É¥¹œ™¥¹‘¥¹œ¥Ì¹½Ð‘É½ÁÁ•™É½´Ñ¡”ÅÕ•Õ”œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼=±‘•È™¥¹‘¥¹œ¥Ì½¸Á…”€È‰ÕÐ¡…ÌÑ¡”¡¥¡•ÍÐÉ…Á Í½É”¸EÕ•Õ”µÕÍÐ(€€€€¼¼¥¹±Õ‘”¥Ð…¹É…¹¬¥Ð™¥ÉÍÐ¸(€€€½¹ÍÐ½±‘•ÉÉ¥Ñ¥…±¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥è€™¥¹‘¥¹œµÉ¥Ñ¥…°µ½±‘•Èœ°(€€€€€Ñ¥Ñ±”è€É¥Ñ¥…°¡¥ÍÑ½É¥…°™¥¹‘¥¹œœ°(€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÁPÀäèÀÀèÀÁhœ(€€€ôì(€€€½¹ÍÐÉ¥Ñ¥…±M½É•‘É…Á èI•Á½I¥Í­É…Á €ôì(€€€€€€¸¸¹É¥Í­É…Á¡]¥Ñ¡M½É•Ì°(€€€€€Í½É•Ìèl(€€€€€€€ì(€€€€€€€€€™¥¹‘¥¹}¥è½±‘•ÉÉ¥Ñ¥…±¥¹‘¥¹œ¹¥°(€€€€€€€€€™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µÉ¥Ñ¥…°œ°(€€€€€€€€€Í½É”è€ää°(€€€€€€€€€Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°(€€€€€€€€€½¹™¥‘•¹”è€À¸ää°(€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€Í•Ù•É¥Ñäè€ÄÀÀ°½¹™¥‘•¹”è€ää°•áÁ±½¥Ñ…‰¥±¥Ñäè€äÀ°ÁÉ¥Ù¥±•”è€àÀ°(€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÜÀ°•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€ØÀ°™É•Í¡¹•ÍÌè€ÈÀ°Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€àÀ(€€€€€€€€€ô°(€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€ô(€€€€€t(€€€ôì((€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½¥¹‘¥¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤ì(€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡™¥±Ñ•ÉÌ¤€ôøì(€€€€€¥˜€ …™¥±Ñ•ÉÌü¹ÕÉÍ½È¤ì(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹t°¹•áÑ}ÕÉÍ½Èè€™¥¹‘¥¹ÌµÕÉÍ½È´Èœôì(€€€€€ô(€€€€€¥˜€¡™¥±Ñ•ÉÌ¹ÕÉÍ½È€ôôô€™¥¹‘¥¹ÌµÕÉÍ½È´Èœ¤ì(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm½±‘•ÉÉ¥Ñ¥…±¥¹‘¥¹tôì(€€€€€ô(€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmtôì(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Ñ¥…±M½É•‘É…Á ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼Q¡”½±‘•ÈÉ¥Ñ¥…°™¥¹‘¥¹œµÕÍÐ…ÁÁ•…È…ÐÑ¡”Ñ½À½˜Ñ¡”ÅÕ•Õ”¸(€€€½¹ÍÐÅÕ•Õ•1¥ÍÐ€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤¹ÅÕ•ÉåM•±•Ñ½È Õ°œ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¤¹¹½Ð¹Ñ½	•9Õ±° ¤ì(€€€½¹ÍÐÉ½ÝÌ€ô€¡ÅÕ•Õ•1¥ÍÐ…Ì!Q51±•µ•¹Ð¤¹ÅÕ•ÉåM•±•Ñ½É±° ±¤œ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ É¥Ñ¥…°¡¥ÍÑ½É¥…°™¥¹‘¥¹œœ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ Í½É”€ääœ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½¬¹…±±Ì¹Í½µ” ¡m™¥±Ñ•ÉÍt¤€ôø™¥±Ñ•ÉÌü¹ÕÉÍ½È€ôôô€™¥¹‘¥¹ÌµÕÉÍ½È´Èœ¤¤¹Ñ½	”¡ÑÉÕ”¤(€€€€¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½Ð™•Ñ É•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”½¸„AP½¹¹•Ñ¥½¸Ý¡•É”Ñ¡”•¹‘Á½¥¹Ð¥ÌÕ¹ÍÕÁÁ½ÉÑ•œ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€€¼¼AP½¹¹•Ñ¥½¸è½¹¹•Ñ•Ý¥Ñ „½¹¹•Ñ½É}¥°‰ÕÐÁÉ½Ù¥‘•È¥Ì¥Ñ¡Õ‰}Á…Ð(€€€€¼¼Í¼Ñ¡”Á½ÍÑÕÉ”•¹‘Á½¥¹ÐÝ½Õ±É•ÑÕÉ¸…¸Õ¹ÍÕÁÁ½ÉÑ••ÉÉ½È¥˜Ý”¡¥Ð¥Ð¸(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ¥½¸èì(€€€€€€€€¸¸¹½¹¹•Ñ•‘¥Ñ!Õˆ°(€€€€€€€ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}Á…Ðœ°(€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ•¹Ñ•ÉÁÉ¥Í”œ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€½¹ÍÐÁ½ÍÑÕÉ•MÁä€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼¥¹‘¥¹œÑ¥Ñ±”…ÁÁ•…ÉÌ¥¸‰½Ñ Ñ¡”ÅÕ•Õ”Á…¹•°…¹Ñ¡”Á…Ñ¡ÌÁ…¹•°¹½Ü(€€€€¼¼Ñ¡…ÐÁ…Ñ¡ÌÉ•¹‘•ÈÑ¡”…ÑÕ…°™¥¹‘¥¹œ¡…¥¸°Í¼Í½Á”Ñ¼Ñ¡”ÅÕ•Õ”¸(€€€…Ý…¥ÐÝ¥Ñ¡¥¸¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤¹™¥¹‘	åQ•áÐ ½•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•½¤¤ì(€€€€¼¼A½ÍÑÕÉ”Á…¹•°Í¡½ÝÌÑ¡”•µÁÑäÍÑ…Ñ”°¹½Ð…¸•ÉÉ½È‰…¹¹•È¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½9¼Á½ÍÑÕÉ”½±±•Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼Q¡”Á½ÍÑÕÉ”•¹‘Á½¥¹ÐÝ…Ì¹•Ù•È…±±•™½È„AP½¹¹•Ñ¥½¸¸(€€€•áÁ•Ð¡Á½ÍÑÕÉ•MÁä¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì((€¥Ð Í½ÉÑÌÉ¥Í¬É…Á Í½É•Ì‰•™½É”Ñ…­¥¹œÑ¡”Ñ½À‰±…ÍÐµÉ…‘¥ÕÌÍ±¥”œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼A$É•ÑÕÉ¹ÌÍ½É•Ì¥¸¥¹Í•ÉÑ¥½¸½É‘•ÈÝ¥Ñ Ñ¡”¡¥¡•ÍÐµÍ½É¥¹œÁ…Ñ (€€€€¼¼‰ÕÉ¥•¥¸Ñ¡”µ¥‘‘±”¸Q¡”€‰Q½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡ÌˆÍ•Ñ¥½¸µÕÍÐÍÑ¥±°(€€€€¼¼É…¹¬¥Ð™¥ÉÍÐƒŠPÑ¡”‘É¥±±‘½Ý¸Í½ÉÑÌ‰•™½É”Í±¥¥¹œÉ…Ñ¡•ÈÑ¡…¸É•±å¥¹œ(€€€€¼¼½¸A$µ½É‘•È•ÅÕ…±¥¹œÍ½É”µ½É‘•È¸(€€€½¹ÍÐÕ¹Í½ÉÑ•‘M½É•ÍÉ…Á èI•Á½I¥Í­É…Á €ôì(€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€€€¹½‘•Ìèmt°•‘•Ìèmt°(€€€€€ÍÕµµ…Éäèì(€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°¹½‘•}½Õ¹Ðè€À°•‘•}½Õ¹Ðè€À°Õ¹­¹½Ý¹}¹½‘•}½Õ¹Ðè€À°(€€€€€€€Õ¹­¹½Ý¹}•‘•}½Õ¹Ðè€À°¡¥¡}É¥Í­}™¥¹‘¥¹Ìè€À°É¥Ñ¥…±}™¥¹‘¥¹Ìè€À(€€€€€ô°(€€€€€Í½É•Ìèl(€€€€€€€ì(€€€€€€€€€™¥¹‘¥¹}¥è€±½Ý•ÈµÍ½É”œ°™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µ„œ°(€€€€€€€€€Í½É”è€ÐÀ°Í•Ù•É¥Ñäè€±½Üœ°½¹™¥‘•¹”è€À¸Ø°(€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€Í•Ù•É¥Ñäè€ÐÀ°½¹™¥‘•¹”è€ØÀ°•áÁ±½¥Ñ…‰¥±¥Ñäè€ÌÀ°ÁÉ¥Ù¥±•”è€ÈÀ°(€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÄÔ°•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€À°™É•Í¡¹•ÍÌè€ÄÀÀ°Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€À(€€€€€€€€€ô°(€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€™¥¹‘¥¹}¥è€¡¥¡•ÍÐµÍ½É”œ°™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µˆœ°(€€€€€€€€€Í½É”è€äÔ°Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°½¹™¥‘•¹”è€À¸äÔ°(€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€Í•Ù•É¥Ñäè€ÄÀÀ°½¹™¥‘•¹”è€äÔ°•áÁ±½¥Ñ…‰¥±¥Ñäè€äÀ°ÁÉ¥Ù¥±•”è€àÀ°(€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÜÀ°•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€ØÀ°™É•Í¡¹•ÍÌè€ÄÀÀ°Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€àÀ(€€€€€€€€€ô°(€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€™¥¹‘¥¹}¥è€µ¥‘‘±”µÍ½É”œ°™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µŒœ°(€€€€€€€€€Í½É”è€ØÔ°Í•Ù•É¥Ñäè€µ•‘¥Õ´œ°½¹™¥‘•¹”è€À¸ÜÔ°(€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€Í•Ù•É¥Ñäè€ÔÔ°½¹™¥‘•¹”è€ÜÔ°•áÁ±½¥Ñ…‰¥±¥Ñäè€ÔÀ°ÁÉ¥Ù¥±•”è€ÐÀ°(€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÌÀ°•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€ÄÀ°™É•Í¡¹•ÍÌè€ÄÀÀ°Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€À(€€€€€€€€€ô°(€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€ô(€€€€€t(€€€ôì(€€€€¼¼AÉ½Ù¥‘”½Á•¸™¥¹‘¥¹ÌÝ¡½Í”%Ìµ…Ñ •… Í½É”Í¼Ñ¡”…Ñ¥Ù”µ™¥¹‘¥¹Ì(€€€€¼¼™¥±Ñ•ÈÑ¡…ÐÑ¡”Ñ½ÀµÁ…Ñ¡Ì±¥ÍÐ…ÁÁ±¥•Ì‘½•Ì¹½ÐÉ•µ½Ù”Ñ¡•´¸Q¥Ñ±•Ì(€€€€¼¼…É”Í•Ð™É½´Ñ¡”Í½É”¹…µ”Í¼Ñ¡”½É‘•É¥¹œ…ÍÍ•ÉÑ¥½¹Ì…¸±½½¬…Ð(€€€€¼¼Ñ¡”É½Ü¡•…‘•È€¡Ý¡¥ ÕÍ•ÌÑ¡”™¥¹‘¥¹œÑ¥Ñ±”°¹½Ð¥¤¸(€€€½¹ÍÐ…Ñ¥Ù•¥¹‘¥¹Ìè¥¹‘¥¹mt€ôl±½Ý•ÈµÍ½É”œ°€¡¥¡•ÍÐµÍ½É”œ°€µ¥‘‘±”µÍ½É”t¹µ…À ¡¥¤€ôø€¡ì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥°(€€€€€Ñ¥Ñ±”è¥¹‘¥¹œÉ…¹­•€‘í¥‘õ€°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€½Á•¸œ(€€€ô¤¤ì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì™¥¹‘¥¹Ìè…Ñ¥Ù•¥¹‘¥¹Ì°É¥Í­É…Á èÕ¹Í½ÉÑ•‘M½É•ÍÉ…Á ô¤ì(€€€½¹ÍÐÁ…Ñ¡Í1¥ÍÐ€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ Q½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡Ìœ¤¤¹ÅÕ•ÉåM•±•Ñ½È ½°œ¤ì(€€€•áÁ•Ð¡Á…Ñ¡Í1¥ÍÐ¤¹¹½Ð¹Ñ½	•9Õ±° ¤ì(€€€½¹ÍÐÉ½ÝÌ€ô€¡Á…Ñ¡Í1¥ÍÐ…Ì!Q51±•µ•¹Ð¤¹ÅÕ•ÉåM•±•Ñ½É±° ±¤œ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ¥¹‘¥¹œÉ…¹­•¡¥¡•ÍÐµÍ½É”œ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ Í½É”€äÔœ¤ì(€€€•áÁ•Ð¡É½ÝÍlÅt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ¥¹‘¥¹œÉ…¹­•µ¥‘‘±”µÍ½É”œ¤ì(€€€•áÁ•Ð¡É½ÝÍlÉt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ¥¹‘¥¹œÉ…¹­•±½Ý•ÈµÍ½É”œ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÉ•¹‘•ÈÑ¡”ÁÉ•Ù¥½ÕÌÉ•Á½Í¥Ñ½ÉåpÌ‘…Ñ„Ý¡•¸„É•±½…É•©•ÑÌ½¸•ÉÉ½Èœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼MÑ…ÉÐ½¸É•Á¼Ý¥Ñ ‘…Ñ„°Ñ¡•¸É•ÉÕ¸Ñ¡”É•¹‘•ÈÁ½¥¹Ñ¥¹œ…ÐÉ•Á¼Ý¡•É”(€€€€¼¼±¥ÍÑI•Á½¥¹‘¥¹ÌÉ•©•ÑÌ¸Q¡”¡•…‘•ÈµÕÍÐÍÝ…ÀÑ¼É•Á¼…¹Ñ¡”(€€€€¼¼™¥¹‘¥¹ÌÁ…¹•°µÕÍÐÍ¡½Ü¥ÑÌ½Ý¸¥¹±¥¹”•ÉÉ½ÈƒŠPÑ¡”ÅÕ•Õ”…¹Í…¸(€€€€¼¼Á…¹•±ÌµÕÍÐ¹½Ð…ÉÉäÉ•Á¼Ì±•™Ñ½Ù•È‘…Ñ„¸(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥° ¤ì(€€€€¼¼½¹™¥É´É•Á¼É•¹‘•É•™Õ±±ä¸(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”èÑ…É•ÑI•Á½Í¥Ñ½Éäô¤ì(€€€€¼¼¥¹‘¥¹œÑ¥Ñ±”…ÁÁ•…ÉÌ¥¸‰½Ñ Ñ¡”ÅÕ•Õ”Á…¹•°…¹Ñ¡”Á…Ñ¡ÌÁ…¹•°¹½Ü(€€€€¼¼Ñ¡…ÐÁ…Ñ¡ÌÉ•¹‘•ÈÑ¡”…ÑÕ…°™¥¹‘¥¹œ¡…¥¸°Í¼Í½Á”Ñ¼Ñ¡”ÅÕ•Õ”¸(€€€…Ý…¥ÐÝ¥Ñ¡¥¸¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤¹™¥¹‘	åQ•áÐ ½•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•½¤¤ì(€€€±•…¹ÕÀ ¤ì(€€€Ù¤¹É•ÍÑ½É•±±5½­Ì ¤ì(€€€Ù¤¹É•Í•Ñ5½‘Õ±•Ì ¤ì((€€€½¹ÍÐ½Ñ¡•ÉI•Á½Í¥Ñ½Éä€ô€¥‘•¹ÑÉ…¥°½½Ñ¡•ÈµÉ•Á¼œì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì(€€€€€¥¹¥Ñ¥…±I•Á½Í¥Ñ½Éäè½Ñ¡•ÉI•Á½Í¥Ñ½Éä°(€€€€€±¥ÍÑI•Á½¥¹‘¥¹ÍÉÉ½Èèìµ•ÍÍ…”è€ÑÉ…¹Í¥•¹Ð½ÕÑ…”œ°ÍÑ…ÑÕÌè€ÔÀÀô(€€€ô¤ì(€€€…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ¡•…‘¥¹œœ°ì±•Ù•°è€È°¹…µ”è½Ñ¡•ÉI•Á½Í¥Ñ½Éäô¤ì(€€€€¼¼¥¹‘¥¹ÌÁ…¹•°ÍÕÉ™…•Ì¥ÑÌ½Ý¸•ÉÉ½È¥¹±¥¹”¸(€€€½¹ÍÐÅÕ•Õ•A…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÅÕ•Õ•A…¹•°¤¹•Ñ	åQ•áÐ ½ÑÉ…¹Í¥•¹Ð½ÕÑ…”½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼MÑ…±”ÅÕ•Õ”É½ÝÌ™É½´É•Á¼µÕÍÐ¹½Ð‰”ÁÉ•Í•¹Ð¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½]½É­™±½Ü=%ÑÉÕÍÐ¥Ì‰É½…½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð µ…Ñ¡•ÌÍ…¸É•½É‘Ì…Í”µ¥¹Í•¹Í¥Ñ¥Ù•±äÍ¼µ¥á•µ…Í”‘••À±¥¹­Ì‘¼¹½ÐÉ•Á½ÉÐ9¼Í…¸å•Ðœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼••À±¥¹¬ÕÍ•Ì€‰%‘•¹ÑÉ…¥°½%‘•¹ÑÉ…¥°ˆìÍÑ½É•Í…¸ÕÍ•Ì€‰¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°ˆ¸(€€€½¹ÍÐµ¥á•‘…Í•I•Á½Í¥Ñ½Éä€ô€%‘•¹ÑÉ…¥°½%‘•¹ÑÉ…¥°œì(€€€½¹ÍÐ±½Ý•É…Í•M…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹½µÁ±•Ñ•‘M…¸°(€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ(€€€ôì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm±½Ý•É…Í•M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½Éäè€¥‘•¹ÑÉ…¥°½¥‘•¹ÑÉ…¥°œ°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡µ¥á•‘…Í•I•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼Q¡”…Í”µµ¥Íµ…Ñ¡•‘••À±¥¹¬µÕÍÐÉ•Í½±Ù”Ñ¼Ñ¡”ÍÑ½É•±½Ý•É…Í”Í…¸¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½½µÁ±•Ñ”Í…¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½9¼Í…¸å•Ð½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ¥¹Ù…±¥‘…Ñ•Ì„Á•¹‘¥¹œÉ•µ•‘¥…Ñ¥½¸ÁÉ•Ù¥•ÜÝ¡•¸Ñ¡”½Á•É…Ñ½È±½Í•ÌÑ¡”Á…¹•°œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼M•ÐÕÀ„ÁÉ•Ù¥•Ü•¹‘Á½¥¹ÐÝ¡½Í”ÁÉ½µ¥Í”É•Í½±Ù•Ì½¹±äÝ¡•¸Ý”É•±•…Í”¥Ð°(€€€€¼¼Í¼Ñ¡”±¥¬½¸±½Í”¡…ÁÁ•¹ÌÝ¡¥±”Ñ¡”É•ÅÕ•ÍÐ¥ÌÍÑ¥±°¥¸™±¥¡Ð¸%˜(€€€€¼¼Ñ¡”±½Í”¡…¹‘±•È‘½•Ì¹½Ð¥¹Ù…±¥‘…Ñ”Ñ¡”É•ÅÕ•ÍÐÑ½­•¸°Ñ¡”±…Ñ”(€€€€¼¼É•ÍÁ½¹Í”Ý½Õ±ÝÉ¥Ñ”¥¹Ñ¼ÁÉ•Ù¥•ÜÍÑ…Ñ”¸(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€€¼¼UÍ”„ÍÕÁÁ½ÉÑ•€¡Ý½É­™±½Ý|¨¤‘•Ñ•Ñ½ÈÍ¼Ñ¡”AÉ•Ù¥•Ü‰ÕÑÑ½¸É•¹‘•ÉÌ¸(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÝ½É­™±½Ý¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ•Ù¥•Ý•™•ÉÉ•€ô‘•™•ÉÉ•ñI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¹AÉ•Ù¥•Üø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÁÉ•Ù¥•ÝI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôøÁÉ•Ù¥•Ý•™•ÉÉ•¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼=Á•¸Ñ¡”ÁÉ•Ù¥•ÜƒŠPÉ•ÅÕ•ÍÐ¥Ì¹½ÜÁ•¹‘¥¹œ¸(€€€½¹ÍÐÁÉ•Ù¥•Ý	ÕÑÑ½¹Ì€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÉ•Ù¥•ÜÉ•µ•‘¥…Ñ¥½¸½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÁÉ•Ù¥•Ý	ÕÑÑ½¹ÍlÁt¤ì(€€€€¼¼1½…‘¥¹œ¥¹‘¥…Ñ½È½¹™¥ÉµÌÑ¡”É•ÅÕ•ÍÐ¥Ì¥¸™±¥¡Ð¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½1½…‘¥¹œÉ•µ•‘¥…Ñ¥½¸ÁÉ•Ù¥•Ü½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼±½Í”Ñ¡”Á…¹•°‰•™½É”Ñ¡”É•ÅÕ•ÍÐÉ•Í½±Ù•Ì¸(€€€™¥É•Ù•¹Ð¹±¥¬¡ÍÉ••¸¹•Ñ	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½±½Í”½¤ô¤¤ì((€€€€¼¼9½ÜÉ•±•…Í”Ñ¡”±…Ñ”É•ÍÁ½¹Í”¸(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€ÁÉ•Ù¥•Ý•™•ÉÉ•¹É•Í½±Ù”¡ì(€€€€€€€™¥¹‘¥¹œèÁ½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€€€É•µ•‘¥…Ñ¥½¸èì(€€€€€€€€€‘•Ñ•Ñ½Èè€¥Ñ¡Õ‰}‘•™…Õ±Ñ}‰É…¹¡}Õ¹ÁÉ½Ñ•Ñ•œ°(€€€€€€€€€ÍÕµµ…Éäè€1…Ñ”É•µ•‘¥…Ñ¥½¸Í¡½Õ±¹½Ð½µµ¥Ðœ°(€€€€€€€€€É¥Í­}ÍÕµµ…Éäè€œœ°(€€€€€€€€€ÍÑ•ÁÌèl1…Ñ”ÍÑ•ÀÑ¡…ÐÍ¡½Õ±¹•Ù•ÈÉ•¹‘•Èt°(€€€€€€€€€Í…™•Ñå}¹½Ñ•Ìèmt°Ù…±¥‘…Ñ¥½¸èmt°(€€€€€€€€€Í•É•Ñ}É½Ñ…Ñ¥½¸è™…±Í”°ÁÕ‰±¥Í¡…‰±”èÑÉÕ”°(€€€€€€€€€•Ù¥‘•¹”èì™¥¹‘¥¹}¥èÁ½ÍÑÕÉ•¥¹‘¥¹œ¹¥ô(€€€€€€€ô(€€€€€ô¤ì(€€€€€…Ý…¥ÐÁÉ•Ù¥•Ý•™•ÉÉ•¹ÁÉ½µ¥Í”ì(€€€ô¤ì((€€€€¼¼Q¡”‘¥Íµ¥ÍÍ•ÁÉ•Ù¥•ÜµÕÍÐ¹½ÐÉ•ÍÕÉÉ•Ðè¹¼ÍÕµµ…Éä°¹¼ÍÑ•ÁÌ¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…Ñ”É•µ•‘¥…Ñ¥½¸Í¡½Õ±¹½Ð½µµ¥Ð½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1…Ñ”ÍÑ•ÀÑ¡…ÐÍ¡½Õ±¹•Ù•ÈÉ•¹‘•È½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1½…‘¥¹œÉ•µ•‘¥…Ñ¥½¸ÁÉ•Ù¥•Ü½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½ÐÉ•ÍÑ…ÉÐÍ…¸°™¥¹‘¥¹Ì°…¹É…Á ™•Ñ¡•ÌÝ¡•¸½¹¹•Ñ¥½¸ÍÑ…ÑÕÌÍ•ÑÑ±•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼Q¡”½É”™•Ñ¡•ÌµÕÍÐÝ…¥Ð™½È½¹¹•Ñ¥½¸ÍÑ…ÑÕÌ‰•™½É”™¥É¥¹œ¸]¥Ñ¡½ÕÐ(€€€€¼¼Ñ¡”…Ñ”°Ñ¡”•™™•ÐÝ½Õ±ÉÕ¸½¹”Ý¥Ñ ½¹¹•Ñ¥½¸õ¹Õ±°°ÍÑ…ÉÐÑ¡”(€€€€¼¼Ñ¡É•”™•Ñ¡•Ì°•Ð¥¹Ù…±¥‘…Ñ•Ý¡•¸‘½µ…¥¹…Ñ„¹±½…‘¥¹œ™±¥ÁÌÑ¼™…±Í”°(€€€€¼¼…¹ÍÑ…ÉÐÑ¡•´……¥¸ƒŠP‘½Õ‰±¥¹œÑ¡”Á…¥¹…Ñ¥½¸½ÍÐ½¸‘••ÀÉ•Á½Ì¸(€€€€¼¼ÍÍ•ÉÐ•… ½˜Ñ¡”Ñ¡É•”‘É¥±±‘½Ý¸µ½Ý¹••¹‘Á½¥¹ÑÌ¥Ì…±±•…Ðµ½ÍÐ(€€€€¼¼½¹”™½È„¥Ù•¸É•Á½Í¥Ñ½Éä½¹”Ñ¡”‘É¥±±‘½Ý¸¡…ÌÍ•ÑÑ±•¸(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½M…¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½¥¹‘¥¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€½¹ÍÐ•ÑI•Á½I¥Í­É…Á €ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼]…¥ÐÕ¹Ñ¥°Ñ¡”‘É¥±±‘½Ý¸¡…Ì™¥¹¥Í¡•Í•ÑÑ±¥¹œ€¡Ñ¡”ÅÕ•Õ”É•¹‘•É•¤¸(€€€€¼¼¥¹‘¥¹œÑ¥Ñ±”…ÁÁ•…ÉÌ¥¸‰½Ñ Ñ¡”ÅÕ•Õ”Á…¹•°…¹Ñ¡”Á…Ñ¡ÌÁ…¹•°¹½Ü(€€€€¼¼Ñ¡…ÐÁ…Ñ¡ÌÉ•¹‘•ÈÑ¡”…ÑÕ…°™¥¹‘¥¹œ¡…¥¸°Í¼Í½Á”Ñ¼Ñ¡”ÅÕ•Õ”¸(€€€…Ý…¥ÐÝ¥Ñ¡¥¸¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤¹™¥¹‘	åQ•áÐ ½•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•½¤¤ì((€€€€¼¼=¹±ä½¹”…±°Á•ÈÉ•Á½Í¥Ñ½ÉäƒŠP±¥ÍÑI•Á½M…¹Ì½¥¹‘¥¹Ì½•ÑI•Á½I¥Í­É…Á (€€€€¼¼•… ™¥É•™½ÈÑ¡”Ñ…É•Ð½¹”°¹½ÐÑÝ¥”¸ÕÍ•¥Ñ!Õ‰½µ…¥¹…Ñ„Ì½Ý¸(€€€€¼¼Í…¸™•Ñ ¥ÌÝ½É­ÍÁ…”µÝ¥‘”€¡¹¼ÕÉÍ½È…ÉÕµ•¹Ð¤°Í¼™¥±Ñ•ÈÑ¼Ñ¡”(€€€€¼¼‘É¥±±‘½Ý¸ÌÁ…¥¹…Ñ•…±°‰äµ…Ñ¡¥¹œÑ¡”ÁÉ•Í•¹”½˜ÕÉÍ½È=H„(€€€€¼¼É•ÅÕ•ÍÐÑ¡…ÐÉ•ÑÕÉ¹•Ñ¡”Ñ…É•ÐÉ•Á½Í¥Ñ½ÉäÉ•½É¸(€€€½¹ÍÐÍ…¹…±±Í½ÉI•Á½Í¥Ñ½Éä€ô±¥ÍÑI•Á½M…¹Ì¹µ½¬¹…±±Ì¹™¥±Ñ•È (€€€€€€¡m™¥±Ñ•ÉÍt¤€ôø™¥±Ñ•ÉÌü¹±¥µ¥Ð€ôôô€ÔÀ€¼¼IA=}%9Q11%9}M9}A}1%5%P(€€€€¤¹±•¹Ñ ì(€€€•áÁ•Ð¡Í…¹…±±Í½ÉI•Á½Í¥Ñ½Éä¤¹Ñ½	” Ä¤ì(€€€•áÁ•Ð¡±¥ÍÑI•Á½¥¹‘¥¹Ì¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€€€•áÁ•Ð¡•ÑI•Á½I¥Í­É…Á ¤¹Ñ½!…Ù•	••¹…±±•‘Q¥µ•Ì Ä¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌ½É…¹¥é…Ñ¥½¸Á½ÍÑÕÉ”…ÁÌ…±½¹Í¥‘”É•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”½¸Ñ¡”‘É¥±±‘½Ý¸œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”É•ÑÕÉ¹Ì‰½Ñ É•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”…¹(€€€€¼¼½É…¹¥é…Ñ¥½¹}Á½ÍÑÕÉ”¸Q¡”‘É¥±±‘½Ý¸µÕÍÐÉ•¹‘•È¥¹¡•É¥Ñ•½Éœ½¹ÑÉ½°(€€€€¼¼…ÁÌÑ½¼ƒŠP¡¥‘¥¹œÑ¡•´Ý½Õ±±•…Ù”¥¹¡•É¥Ñ•Ñ¥½¹ÌÁ½±¥ä€¼Í•ÕÉ¥Ñä(€€€€¼¼½¹™¥ÕÉ…Ñ¥½¸€¼ÉÕ¹¹•ÈÁ½ÍÑÕÉ”¥¹Ù¥Í¥‰±”Ñ¼Ñ¡”½Á•É…Ñ½È¸(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€€€€€½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì(€€€€€€€€€¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€¥¹Í•ÕÉ”œ°(€€€€€€€€€ÍÕµµ…Éäè€I•Á½Í¥Ñ½Éä‘•™…Õ±Ð‰É…¹ ¥Ìµ¥ÍÍ¥¹œÉ•ÅÕ¥É•É•Ù¥•ÝÌ¸œ(€€€€€€€õt(€€€€€ô°(€€€€€½É…¹¥é…Ñ¥½¹}Á½ÍÑÕÉ”èì(€€€€€€€½É…¹¥é…Ñ¥½¸è€¥‘•¹ÑÉ…¥°œ°(€€€€€€€½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì(€€€€€€€€€¥è€…Ñ¥½¹ÌµÁ½±¥äœ°…Ñ•½Éäè€…Ñ¥½¹Ìœ°ÍÑ…Ñ”è€¥¹Í•ÕÉ”œ°(€€€€€€€€€ÍÕµµ…Éäè€=É…¹¥é…Ñ¥½¸Ñ¥½¹ÌÁ½±¥ä…±±½ÝÌÝÉ¥Ñ”µ…±°Ý½É­™±½ÜÑ½­•¹Ì¸œ(€€€€€€€õt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼	½Ñ É•Á½Í¥Ñ½Éä…¹½É…¹¥é…Ñ¥½¸Á½ÍÑÕÉ”…ÁÌÉ•¹‘•È°…¹Ñ¡”½ÉœÉ½Ü(€€€€¼¼…ÉÉ¥•ÌÑ¡”Í½Á”ÁÉ•™¥àÍ¼Ñ¡”½Á•É…Ñ½È…¸Ñ•±°Ñ¡•´…Á…ÉÐ¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½I•Á½Í¥Ñ½Éä‘•™…Õ±Ð‰É…¹ ¥Ìµ¥ÍÍ¥¹œÉ•ÅÕ¥É•É•Ù¥•ÝÌ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½=É…¹¥é…Ñ¥½¸Ñ¥½¹ÌÁ½±¥ä…±±½ÝÌÝÉ¥Ñ”µ…±°Ý½É­™±½ÜÑ½­•¹Ì½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½=É…¹¥é…Ñ¥½¸ƒŠˆ€½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ¡¥‘•ÌÑ¡”AÉ•Ù¥•ÜÉ•µ•‘¥…Ñ¥½¸‰ÕÑÑ½¸™½È‘•Ñ•Ñ½ÉÌÑ¡”‰…­•¹…¹¹½ÐÉ•µ•‘¥…Ñ”œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼5¥á•ÅÕ•Õ”èÝ½É­™±½Ý|™¥¹‘¥¹œ¥ÌÍÕÁÁ½ÉÑ•°¥Ñ¡Õ‰|Á½ÍÑÕÉ”™¥¹‘¥¹œ¥Ì(€€€€¼¼¹½Ð¸Q¡”ÅÕ•Õ”µÕÍÐÍÑ¥±°É•¹‘•È‰½Ñ €¡Á½ÍÑÕÉ”™¥¹‘¥¹Ì…É”Ý½ÉÑ (€€€€¼¼ÑÉ¥…¥¹œ•Ù•¸¥˜Ý”…¹¹½Ð…ÕÑ¼µÉ•µ•‘¥…Ñ”Ñ¡•´¤°‰ÕÐ½¹±äÑ¡”Ý½É­™±½Ü(€€€€¼¼½¹”…ÉÉ¥•Ì„AÉ•Ù¥•Ü‰ÕÑÑ½¸¸(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì™¥¹‘¥¹ÌèmÁ½ÍÑÕÉ•¥¹‘¥¹œ°Ý½É­™±½Ý¥¹‘¥¹tô¤ì((€€€½¹ÍÐÅÕ•Õ•1¥ÍÐ€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤ì(€€€€¼¼	½Ñ ™¥¹‘¥¹ÌÉ•¹‘•È¸(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ •™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•œ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ]½É­™±½Ü=%ÑÉÕÍÐ¥Ì‰É½…œ¤ì(€€€€¼¼	ÕÐ½¹±ä½¹”AÉ•Ù¥•Ü‰ÕÑÑ½¸ƒŠPÑ¡”Á½ÍÑÕÉ”™¥¹‘¥¹œÍ¡½ÝÌÑ¡”™…±±‰…¬¸(€€€½¹ÍÐÁÉ•Ù¥•Ý	ÕÑÑ½¹Ì€ôÍÉ••¸¹•Ñ±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÉ•Ù¥•ÜÉ•µ•‘¥…Ñ¥½¸½¤ô¤ì(€€€•áÁ•Ð¡ÁÉ•Ù¥•Ý	ÕÑÑ½¹Ì¹±•¹Ñ ¤¹Ñ½	” Ä¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡ÅÕ•Õ•1¥ÍÐ¤¹•Ñ	åQ•áÐ ½I•Ù¥•Ü¥¸¥Ñ!Õˆ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€€¼¼!•…‘•ÈÍÁ±¥ÑÌÑ¡”ÅÕ•Õ”‰äÉ•µ•‘¥…Ñ¥½¸…Ñ•½ÉäèÝ½É­™±½Ý}½¥‘}‰É½…‘}ÑÉÕÍÐ(€€€€¼¼¥ÌÍÕÁÁ½ÉÑ•€¡AÉ•Ù¥•Ü‰ÕÑÑ½¸¤‰ÕÐ‰…­•¹É•ÑÕÉ¹ÌÁÕ‰±¥Í¡…‰±”é™…±Í”(€€€€¼¼€¡Õ¥‘…¹”µ½¹±ä¤°Í¼¥Ð½Õ¹ÑÌ…ÌÁÉ•Ù¥•Üµ½¹±äÉ…Ñ¡•ÈÑ¡…¸™¥àµÉ•…‘ä¸Q¡¥Ì(€€€€¼¼µ…Ñ¡•ÌÑ¡”…•ÁÑ•µ‘•Ñ•Ñ½ÈÍ•µ…¹Ñ¥Ì¥¸(€€€€¼¼¥¹Ñ•É¹…°½™¥¹‘¥¹Ì½ÍÑ…¹‘…É‘Ì½É•Á½}É•µ•‘¥…Ñ¥½¸¹¼¸(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¹Ñ•áÑ½¹Ñ•¹Ð¤¹¹½Ð¹Ñ½½¹Ñ…¥¸ ™¥àµÉ•…‘äœ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ œÄÁÉ•Ù¥•Üµ½¹±äœ¤ì(€ô¤ì((€¥Ð É•Á½ÉÑÌÑÉÕ¹…Ñ¥½¸Ý¡•¸¥ÐÍÑ½ÁÁ•‰•…ÕÍ”Ñ¡”…Ñ¥Ù”µ™¥¹‘¥¹ÌÑ…É•Ð™¥±±•Ý¡¥±”Á…•ÌÉ•µ…¥¹•œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼	…­•¹­••ÁÌÉ•ÑÕÉ¹¥¹œ¹•áÑ}ÕÉÍ½È¸Q¡”™•Ñ¡•ÈµÕÍÐÍÑ½À½¹”Ñ¡”(€€€€¼¼…Ñ¥Ù”Ñ…É•Ð™¥±±Ì€ ÔÀÀ¤9É•Á½ÉÐÑÉÕ¹…Ñ•éÑÉÕ”Í¼Ñ¡”½Á•É…Ñ½È(€€€€¼¼Í••ÌÑ¡”Í…™•Ñäµ•¥±¥¹œÝ…É¹¥¹œ‰…¹¹•ÈÉ…Ñ¡•ÈÑ¡…¸…ÍÍÕµ¥¹œÑ¡”Ñ½À(€€€€¼¼½˜Ñ¡”ÅÕ•Õ”¥ÌÑ¡”¡¥¡•ÍÐµÍ½É¥¹œ™¥¹‘¥¹œ¸(€€€½¹ÍÐ…Ñ¥Ù•A…”è¥¹‘¥¹mt€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€ÄÀÀô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥è™¥¹‘¥¹œµ…Ñ¥Ù”´‘í¥¹‘•áõ€°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€½Á•¸œ(€€€ô¤¤ì((€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€€¼¼Ù•ÉäÁ…”É•ÑÕÉ¹Ì€ÄÀÀ…Ñ¥Ù”™¥¹‘¥¹Ì€¬„¹•áÑ}ÕÉÍ½È°Í¼Á…¥¹…Ñ¥½¸(€€€€¼¼É•…¡•ÌÑ¡”€ÔÀÀµ…Ñ¥Ù”Ñ…É•Ð½¸Á…”€ÔÝ¥Ñ µ½É”Á…•ÌÍÑ¥±°…Ù…¥±…‰±”¸(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€ ¤€ôø€¡ì(€€€€€¥Ñ•µÌè…Ñ¥Ù•A…”°(€€€€€¹•áÑ}ÕÉÍ½Èè€…±Ý…åÌµ…¹½Ñ¡•ÈµÁ…”œ(€€€ô¤¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼QÉÕ¹…Ñ¥½¸‰…¹¹•ÈÍÕÉ™…•Ì¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½¥¹‘¥¹ÌÁ…¥¹…Ñ¥½¸¡¥Ð¥ÑÌÍ…™•Ñä•¥±¥¹œ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ÁÉ½Á……Ñ•Ì„½¹¹•Ñ¥½¸µÍÑ…ÑÕÌ•ÉÉ½È¥¹ÍÑ•…½˜Í¡½Ý¥¹œ€‰½¹¹•Ð¥Ñ!ÕˆˆÝ¡•¸Ñ¡”ÍÑ…ÑÕÌ™•Ñ ™…¥±Ìœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼½¹¹•Ñ¥½¸™•Ñ É•©•ÑÌ¸]¥Ñ¡½ÕÐÑ¡¥Ì™¥à°Á½ÍÑÕÉ•MÕÁÁ½ÉÑ•Ý½Õ±©ÕÍÐ(€€€€¼¼•Ù…±Õ…Ñ”Ñ¼™…±Í”…¹Ñ¡”‘É¥±±‘½Ý¸Ý½Õ±É•¹‘•È…Ì¥˜Ñ¡”½Á•É…Ñ½È(€€€€¼¼¹••‘•Ñ¼½¹¹•Ð¥Ñ!Õˆ°¡¥‘¥¹œÑ¡”É•…°•ÉÉ½È¸(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•©•Ñ•‘Y…±Õ” (€€€€€¹•Ü…Á¤¹Á¥ÉÉ½È ¥Ñ¡ÕˆÍÑ…ÑÕÌÕ¹…Ù…¥±…‰±”œ°€ÔÀÌ¤(€€€€¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼Q¡”½¹¹•Ñ¥½¸µÍÑ…ÑÕÌ•ÉÉ½ÈÍÕÉ™…•ÌÙ¥„Ñ¡”Í¡…É••ÉÉ½È‰…¹¹•È¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½¥Ñ¡ÕˆÍÑ…ÑÕÌÕ¹…Ù…¥±…‰±”½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌÍ…¸°™¥¹‘¥¹Ì°…¹‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡Ì‰•™½É”Í±½ÜÁ½ÍÑÕÉ”É•Í½±Ù•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼A½ÍÑÕÉ”¥Ì„±¥Ù”¥Ñ!Õˆ…±°…¹…¸‰”Í±½Ý•ÈÑ¡…¸Ñ¡”É•ÍÐ½˜Ñ¡”(€€€€¼¼‘É¥±±‘½Ý¸¸Q¡”Í…¸½™¥¹‘¥¹Ì½É…Á µÕÍÐÉ•¹‘•È…ÌÍ½½¸…ÌÑ¡•¥È½Ý¸(€€€€¼¼ÁÉ½µ¥Í•ÌÍ•ÑÑ±”ìÑ¡”Á½ÍÑÕÉ”Á…¹•°•ÑÌ¥ÑÌ½Ý¸±½…‘¥¹œ¥¹‘¥…Ñ½È(€€€€¼¼…¹‘½•Ì¹½Ð…Ñ”…¹åÑ¡¥¹œ•±Í”¸(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€½¹ÍÐÁ½ÍÑÕÉ••™•ÉÉ•€ô‘•™•ÉÉ•ñì(€€€€€½¹¹•Ñ½É}¥èÍÑÉ¥¹œì(€€€€€ÁÉ½Ù¥‘•ÈèÍÑÉ¥¹œì(€€€€€Á½ÍÑÕÉ”è¥Ñ!Õ‰I•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”ì(€€€ôø ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸  ¤€ôøÁ½ÍÑÕÉ••™•ÉÉ•¹ÁÉ½µ¥Í”¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼¥¹‘¥¹Ì°Í…¸°…¹‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡ÌÉ•¹‘•È‰•™½É”Á½ÍÑÕÉ”Í•ÑÑ±•Ì¸(€€€€¼¼M½Á”Ñ¼Ñ¡”ÅÕ•Õ”Á…¹•°‰•…ÕÍ”Ñ¡”™¥¹‘¥¹œÑ¥Ñ±”…±Í¼…ÁÁ•…ÉÌ¥¸(€€€€¼¼Ñ¡”Á…Ñ¡ÌÁ…¹•°Ì¹½‘”¡…¥¸¸(€€€…Ý…¥ÐÝ¥Ñ¡¥¸¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤(€€€€€€¹™¥¹‘	åQ•áÐ ½•™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•½¤¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½½µÁ±•Ñ”Í…¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	å1…‰•±Q•áÐ Q½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡Ìœ¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€€¼¼A½ÍÑÕÉ”Á…¹•°Í¡½ÝÌ¥ÑÌ½Ý¸±½…‘¥¹œ¥¹‘¥…Ñ½È°¹½ÐÑ¡”‘É¥±±‘½Ý¹pÌÉ½ÕÑ”±½…‘•È¸(€€€€¼¼]…¥Ð™½È½¹¹•Ñ¥½¸ÍÑ…ÑÕÌÑ¼Í•ÑÑ±”Í¼Ñ¡”Í•½¹µÁ…ÍÌ•™™•Ð™¥É•ÌÁ½ÍÑÕÉ”¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½1½…‘¥¹œÉ•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì((€€€€¼¼9½Ü±•ÐÁ½ÍÑÕÉ”Í•ÑÑ±”…¹¡•¬¥ÐÉ•¹‘•ÉÌ¸(€€€…Ý…¥Ð…Ð¡…Íå¹Œ€ ¤€ôøì(€€€€€Á½ÍÑÕÉ••™•ÉÉ•¹É•Í½±Ù”¡ì(€€€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°(€€€€€€€ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€€€Á½ÍÑÕÉ”èì(€€€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€€€€€€€½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€€€¡•­Ìèmì(€€€€€€€€€€€¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€¥¹Í•ÕÉ”œ°(€€€€€€€€€€€É•…Í½¸è€Ý•…­}ÁÉ½Ñ•Ñ¥½¸œ°ÍÕµµ…Éäè€•™…Õ±Ð‰É…¹ ¥Ìµ¥ÍÍ¥¹œÉ•ÅÕ¥É•É•Ù¥•ÝÌ¸œ(€€€€€€€€€õt(€€€€€€€ô(€€€€€ô¤ì(€€€€€…Ý…¥ÐÁ½ÍÑÕÉ••™•ÉÉ•¹ÁÉ½µ¥Í”ì(€€€ô¤ì(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½•™…Õ±Ð‰É…¹ ¥Ìµ¥ÍÍ¥¹œÉ•ÅÕ¥É•É•Ù¥•ÝÌ½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½1½…‘¥¹œÉ•Á½Í¥Ñ½ÉäÁ½ÍÑÕÉ”½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ­••ÁÌÁ…¥¹…Ñ¥¹œÁ…ÍÐ±½Í•µ™¥¹‘¥¹œÁ…•ÌÍ¼½±‘•È…Ñ¥Ù”É¥Í­ÌÉ•… Ñ¡”ÅÕ•Õ”œ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼A…”€Ä¥Ì€ÄÀÀ±½Í•€¡™¥á•¤™¥¹‘¥¹Ì¸A…”€È¡½±‘Ì½¹”…Ñ¥Ù”É•½Á•¹•(€€€€¼¼™¥¹‘¥¹œ¸AÉ•Ù¥½ÕÍ±äÑ¡”‘É¥±±‘½Ý¸ÍÑ½ÁÁ•…ÐÁ…”€Ä‰•…ÕÍ”¥Ð½Õ¹Ñ•(€€€€¼¼Ñ½Ñ…°¥Ñ•µÌÑ½Ý…ÉÑ¡”…Àì¹½Ü¥Ð½Õ¹ÑÌ½¹±äQ%Y¥Ñ•µÌÍ¼¥ÐµÕÍÐ(€€€€¼¼™•Ñ Á…”€È…¹ÍÕÉ™…”Ñ¡”…Ñ¥Ù”½¹”¸(€€€½¹ÍÐ±½Í•‘A…•=¹”è¥¹‘¥¹mt€ôÉÉ…ä¹™É½´¡ì±•¹Ñ è€ÄÀÀô°€¡|°¥¹‘•à¤€ôø€¡ì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥è™¥¹‘¥¹œµ±½Í•´‘í¥¹‘•áõ€°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€™¥á•œ(€€€ô¤¤ì(€€€½¹ÍÐ…Ñ¥Ù•=±‘•Èè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥è€½±‘•Èµ…Ñ¥Ù”µ™¥¹‘¥¹œœ°(€€€€€Ñ¥Ñ±”è€=±‘•È…Ñ¥Ù”™¥¹‘¥¹œ¡¥‘¥¹œ‰•¡¥¹±½Í•Á…”œ°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€É•½Á•¹•œ(€€€ôì((€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½¥¹‘¥¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤ì(€€€±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½­%µÁ±•µ•¹Ñ…Ñ¥½¸¡…Íå¹Œ€¡™¥±Ñ•ÉÌ¤€ôøì(€€€€€¥˜€ …™¥±Ñ•ÉÌü¹ÕÉÍ½È¤ì(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌè±½Í•‘A…•=¹”°¹•áÑ}ÕÉÍ½Èè€±½Í•µ¡•…ÙäµÁ…”´Èœôì(€€€€€ô(€€€€€¥˜€¡™¥±Ñ•ÉÌ¹ÕÉÍ½È€ôôô€±½Í•µ¡•…ÙäµÁ…”´Èœ¤ì(€€€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèm…Ñ¥Ù•=±‘•Étôì(€€€€€ô(€€€€€É•ÑÕÉ¸ì¥Ñ•µÌèmtôì(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼Q¡”½±‘•È…Ñ¥Ù”™¥¹‘¥¹œµÕÍÐ…ÁÁ•…È¥¸Ñ¡”ÅÕ•Õ”ƒŠPÑ¡”‘É¥±±‘½Ý¸(€€€€¼¼Á…¥¹…Ñ•Á…ÍÐÑ¡”±½Í•µ¡•…ÙäÁ…”É…Ñ¡•ÈÑ¡…¸ÍÑ½ÁÁ¥¹œ…ÐÁ…”€Ä¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½=±‘•È…Ñ¥Ù”™¥¹‘¥¹œ¡¥‘¥¹œ‰•¡¥¹±½Í•Á…”½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡±¥ÍÑI•Á½¥¹‘¥¹Ì¹µ½¬¹…±±Ì¹Í½µ” ¡m™¥±Ñ•ÉÍt¤€ôø™¥±Ñ•ÉÌü¹ÕÉÍ½È€ôôô€±½Í•µ¡•…ÙäµÁ…”´Èœ¤¤¹Ñ½	”¡ÑÉÕ”¤(€€€€¤ì(€€€€¼¼9¼™¥á•™¥¹‘¥¹œÉ•¹‘•É•¥¸Ñ¡”ÅÕ•Õ”¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	åQ•áÐ ½™¥¹‘¥¹œµ±½Í•´À½¤¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌÑ¡”…ÑÕ…°‰±…ÍÐµÉ…‘¥ÕÌ¹½‘”¡…¥¸™É½´É¥Í­É…Á ¹¹½‘•Ì…¹É¥Í­É…Á ¹•‘•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼A…¹•°ÁÉ½µ¥Í•Ì€‰Q½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡ÌˆƒŠP¥ÐµÕÍÐÍ¡½ÜÑ¡”É•…¡…‰±”(€€€€¼¼Ý½É­™±½Ü½¥‘•¹Ñ¥Ñä½ÉÕ¹¹•È½•¹Ù¥É½¹µ•¹Ð½½¹ÑÉ½°¡…¥¸Ñ¡”™¥¹‘¥¹œ(€€€€¼¼Ñ½Õ¡•Ì°¹½Ð©ÕÍÐÑ¡”™¥¹‘¥¹œ¥…¹Í½É”¸]…±­•ÈÍÑ…ÉÑÌ…ÐÑ¡”(€€€€¼¼™¥¹‘¥¹œÌ™¥¹‘¥¹}¹½‘•}¥°™½±±½ÝÌ½ÕÑ½¥¹œ•‘•Ì°…¹ÁÉ•™•ÉÌ­¹½Ý¸(€€€€¼¼•‘•Ì½Ù•ÈÉ•…¡…‰¥±¥Ñå}Õ¹­¹½Ý¸¸(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥è€¡…¥¸µ™¥¹‘¥¹œœ°(€€€€€Ñ¥Ñ±”è€]½É­™±½ÜÉ•…¡•ÌÁÉ½‘ÕÑ¥½¸±½ÕÉ½±”œ°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€½Á•¸œ(€€€ôì(€€€½¹ÍÐ¡…¥¹É…Á èI•Á½I¥Í­É…Á €ôì(€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€€€¹½‘•Ìèl(€€€€€€€ì¥è€¹½‘”µ™¥¹‘¥¹œœ°­¥¹è€™¥¹‘¥¹œœ°±…‰•°è€¡…¥¸µ™¥¹‘¥¹œœ°•Ù¥‘•¹•}ÍÑ…Ñ”è€­¹½Ý¸œô°(€€€€€€€ì¥è€¹½‘”µÝ½É­™±½Üœ°­¥¹è€Ý½É­™±½Üœ°±…‰•°è€‘•Á±½ä¹åµ°œ°•Ù¥‘•¹•}ÍÑ…Ñ”è€­¹½Ý¸œô°(€€€€€€€ì¥è€¹½‘”µÍ•É•Ðœ°­¥¹è€Í•É•Ðœ°±…‰•°è€]M}A1=e}-dœ°•Ù¥‘•¹•}ÍÑ…Ñ”è€­¹½Ý¸œô°(€€€€€€€ì¥è€¹½‘”µ±½ÕµÉ½±”œ°­¥¹è€±½Õ‘}É½±”œ°±…‰•°è€ÁÉ½µ‘•Á±½äµÉ½±”œ°•Ù¥‘•¹•}ÍÑ…Ñ”è€­¹½Ý¸œô°(€€€€€€€ì¥è€¹½‘”µÍÁ•Õ±…Ñ¥Ù”œ°­¥¹è€•¹Ù¥É½¹µ•¹Ðœ°±…‰•°è€ÍÁ•Õ±…Ñ¥Ù”µ•¹Øœ°•Ù¥‘•¹•}ÍÑ…Ñ”è€Õ¹­¹½Ý¸œô(€€€€€t°(€€€€€•‘•Ìèl(€€€€€€€ì(€€€€€€€€€¥è€”Äœ°­¥¹è€™¥¹‘¥¹}…™™•ÑÍ}Ý½É­™±½Üœ°(€€€€€€€€€™É½µ}¹½‘•}¥è€¹½‘”µ™¥¹‘¥¹œœ°Ñ½}¹½‘•}¥è€¹½‘”µÝ½É­™±½Üœ°(€€€€€€€€€•Ù¥‘•¹•}ÍÑ…Ñ”è€­¹½Ý¸œ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€¥è€”Èœ°­¥¹è€©½‰}ÕÍ•Í}Í•É•Ðœ°(€€€€€€€€€™É½µ}¹½‘•}¥è€¹½‘”µÝ½É­™±½Üœ°Ñ½}¹½‘•}¥è€¹½‘”µÍ•É•Ðœ°(€€€€€€€€€•Ù¥‘•¹•}ÍÑ…Ñ”è€­¹½Ý¸œ(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€¥è€”Ìœ°­¥¹è€½¥‘}ÍÕ‰©•Ñ}…¹}…ÍÍÕµ•}É½±”œ°(€€€€€€€€€™É½µ}¹½‘•}¥è€¹½‘”µÍ•É•Ðœ°Ñ½}¹½‘•}¥è€¹½‘”µ±½ÕµÉ½±”œ°(€€€€€€€€€•Ù¥‘•¹•}ÍÑ…Ñ”è€­¹½Ý¸œ(€€€€€€€ô°(€€€€€€€€¼¼É•…¡…‰¥±¥Ñå}Õ¹­¹½Ý¸•‘”•á¥ÍÑÌ™É½´Ñ¡”Ý½É­™±½Ü°‰ÕÐÑ¡”(€€€€€€€€¼¼­¹½Ý¸µ•‘”Ý…±¬…‰½Ù”Í¡½Õ±É•… ±½Õ‘}É½±”™¥ÉÍÐìÑ¡”(€€€€€€€€¼¼ÍÁ•Õ±…Ñ¥Ù”¹½‘”µÕÍÐ¹½Ð‰”ÁÉ•™•ÉÉ•½Ù•ÈÑ¡”½¹É•Ñ”¡…¥¸¸(€€€€€€€ì(€€€€€€€€€¥è€”ÐµÕ¹­¹½Ý¸œ°­¥¹è€É•…¡…‰¥±¥Ñå}Õ¹­¹½Ý¸œ°(€€€€€€€€€™É½µ}¹½‘•}¥è€¹½‘”µÝ½É­™±½Üœ°Ñ½}¹½‘•}¥è€¹½‘”µÍÁ•Õ±…Ñ¥Ù”œ°(€€€€€€€€€•Ù¥‘•¹•}ÍÑ…Ñ”è€Õ¹­¹½Ý¸œ(€€€€€€€ô(€€€€€t°(€€€€€Í½É•Ìèl(€€€€€€€ì(€€€€€€€€€™¥¹‘¥¹}¥è™¥¹‘¥¹œ¹¥°™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µ™¥¹‘¥¹œœ°(€€€€€€€€€Í½É”è€àà°Í•Ù•É¥Ñäè€¡¥ œ°½¹™¥‘•¹”è€À¸ä°(€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€Í•Ù•É¥Ñäè€àÀ°½¹™¥‘•¹”è€äÀ°•áÁ±½¥Ñ…‰¥±¥Ñäè€ØÀ°ÁÉ¥Ù¥±•”è€ÐÀ°(€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÔÔ°•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€ÌÀ°™É•Í¡¹•ÍÌè€ÄÀÀ°(€€€€€€€€€€€Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€ÜÀ(€€€€€€€€€ô°(€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€ô(€€€€€t°(€€€€€ÍÕµµ…Éäèì(€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä°¹½‘•}½Õ¹Ðè€Ô°•‘•}½Õ¹Ðè€Ð°Õ¹­¹½Ý¹}¹½‘•}½Õ¹Ðè€Ä°(€€€€€€€Õ¹­¹½Ý¹}•‘•}½Õ¹Ðè€Ä°¡¥¡}É¥Í­}™¥¹‘¥¹Ìè€Ä°É¥Ñ¥…±}™¥¹‘¥¹Ìè€À(€€€€€ô(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì™¥¹‘¥¹Ìèm™¥¹‘¥¹t°É¥Í­É…Á è¡…¥¹É…Á ô¤ì((€€€½¹ÍÐÁ…Ñ¡ÍA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ Q½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡Ìœ¤ì(€€€½¹ÍÐÁ…Ñ¡Í1¥ÍÐ€ôÁ…Ñ¡ÍA…¹•°¹ÅÕ•ÉåM•±•Ñ½È ½°œ¤ì(€€€•áÁ•Ð¡Á…Ñ¡Í1¥ÍÐ¤¹¹½Ð¹Ñ½	•9Õ±° ¤ì(€€€½¹ÍÐÉ½ÝÌ€ô€¡Á…Ñ¡Í1¥ÍÐ…Ì!Q51±•µ•¹Ð¤¹ÅÕ•ÉåM•±•Ñ½É±° ±¤œ¤ì(€€€•áÁ•Ð¡É½ÝÌ¹±•¹Ñ ¤¹Ñ½	” Ä¤ì((€€€€¼¼Q¡”½¹É•Ñ”Ý½É­™±½ÜƒŠHÍ•É•ÐƒŠH±½Õ‘}É½±”¡…¥¸É•¹‘•ÉÌ¥¸Ñ¡”É½Ü¸(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ‘•Á±½ä¹åµ°œ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ]M}A1=e}-dœ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ÁÉ½µ‘•Á±½äµÉ½±”œ¤ì(€€€€¼¼9½‘”­¥¹‘Ì…É”±…‰•±•Í¼Ñ¡”½Á•É…Ñ½È…¸Ñ•±°Ý½É­™±½Ü™É½´É½±”¸(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ]½É­™±½Üœ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ ±½ÕI½±”œ¤ì(€ô¤ì((€¥Ð ™…±±Ì‰…¬Ñ¼„€‰¹¼É•…¡…‰¥±¥Ñäˆ¡¥¹ÐÝ¡•¸Ñ¡”É…Á ¡…Ì¹¼¹½‘•Ì½È•‘•Ìœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼M½µ”É¥Í¬µÉ…Á É•ÍÁ½¹Í•Ì…ÉÉä½¹±äÍ½É•Ì€¡½±‘•ÈÍÕµµ…É¥•Ì½È(€€€€¼¼Á…ÉÑ¥…°½±±•Ñ¥½¸¤¸Q¡”Á…Ñ¡ÌÁ…¹•°µÕÍÐÍÑ¥±°É•¹‘•ÈÝ¥Ñ Ñ¡”(€€€€¼¼™¥¹‘¥¹œÑ¥Ñ±”½Í½É”°‰ÕÐÍ…ä•áÁ±¥¥Ñ±ä¹¼É•…¡…‰¥±¥Ñä¡…¥¸(€€€€¼¼¥Ì…Ù…¥±…‰±”ƒŠP¹•Ù•È±…¥´„¡…¥¸Ñ¡…Ð¥Í¸Ð¥¸Ñ¡”‘…Ñ„¸(€€€½¹ÍÐ™¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥è€¹¼µ¡…¥¸µ™¥¹‘¥¹œœ°(€€€€€Ñ¥Ñ±”è€¥¹‘¥¹œÝ¥Ñ ¹¼É•…¡…‰¥±¥Ñä‘…Ñ„œ°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€½Á•¸œ(€€€ôì(€€€½¹ÍÐÍ½É•Í=¹±åÉ…Á èI•Á½I¥Í­É…Á €ôì(€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€€€¹½‘•Ìèmt°•‘•Ìèmt°(€€€€€Í½É•Ìèl(€€€€€€€ì(€€€€€€€€€™¥¹‘¥¹}¥è™¥¹‘¥¹œ¹¥°™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µàœ°(€€€€€€€€€Í½É”è€ÜÈ°Í•Ù•É¥Ñäè€¡¥ œ°½¹™¥‘•¹”è€À¸à°(€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€Í•Ù•É¥Ñäè€ÜÀ°½¹™¥‘•¹”è€àÀ°•áÁ±½¥Ñ…‰¥±¥Ñäè€ÔÀ°ÁÉ¥Ù¥±•”è€ÌÀ°(€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÐÀ°•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€ÄÀ°™É•Í¡¹•ÍÌè€ÄÀÀ°Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€À(€€€€€€€€€ô°(€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€ô(€€€€€t°(€€€€€ÍÕµµ…Éäèì(€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€Ä°¹½‘•}½Õ¹Ðè€À°•‘•}½Õ¹Ðè€À°Õ¹­¹½Ý¹}¹½‘•}½Õ¹Ðè€À°(€€€€€€€Õ¹­¹½Ý¹}•‘•}½Õ¹Ðè€À°¡¥¡}É¥Í­}™¥¹‘¥¹Ìè€Ä°É¥Ñ¥…±}™¥¹‘¥¹Ìè€À(€€€€€ô(€€€ôì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì™¥¹‘¥¹Ìèm™¥¹‘¥¹t°É¥Í­É…Á èÍ½É•Í=¹±åÉ…Á ô¤ì(€€€½¹ÍÐÁ…Ñ¡ÍA…¹•°€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ Q½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡Ìœ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á…Ñ¡ÍA…¹•°¤¹•Ñ	åQ•áÐ ½¥¹‘¥¹œÝ¥Ñ ¹¼É•…¡…‰¥±¥Ñä‘…Ñ„½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡Ý¥Ñ¡¥¸¡Á…Ñ¡ÍA…¹•°¤¹•Ñ	åQ•áÐ ½9¼É•…¡…‰¥±¥ÑäÉ…Á ½±±•Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ™¥±Ñ•ÉÌÑ½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡ÌÍ¼„±½Í•™¥¹‘¥¹œ…¹¹½Ð‘¥ÍÁ±…”…Ñ¥Ù”É¥Í­Ìœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼¡¥ µÍ½É¥¹œÁ…Ñ ‰•±½¹ÌÑ¼„™¥á•™¥¹‘¥¹œƒŠP¥ÐµÕÍÐ¹½Ð…ÁÁ•…È¥¸(€€€€¼¼Ñ¡”Ñ½Àµ8±¥ÍÐ•Ù•¸Ñ¡½Õ ¥ÑÌÉ…ÜÍ½É”¥ÌÑ¡”¡¥¡•ÍÐ°‰•…ÕÍ”Ñ¡”(€€€€¼¼™¥¹‘¥¹œ¥ÑÍ•±˜¥Ì¹¼±½¹•È…Ñ¥Ù”¸(€€€½¹ÍÐ…Ñ¥Ù•=Á•¸è¥¹‘¥¹œ€ôì€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°¥è€…Ñ¥Ù”µ½Á•¸œ°Ñ¥Ñ±”è€Ñ¥Ù”½Á•¸™¥¹‘¥¹œœ°±¥™•å±•}ÍÑ…ÑÕÌè€½Á•¸œôì(€€€½¹ÍÐ±½Í•‘¥á•è¥¹‘¥¹œ€ôì€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°¥è€±½Í•µ™¥á•œ°Ñ¥Ñ±”è€±½Í•™¥á•™¥¹‘¥¹œœ°±¥™•å±•}ÍÑ…ÑÕÌè€™¥á•œôì(€€€½¹ÍÐÉ…Á¡]¥Ñ¡±½Í•‘Q½ÁM½É”èI•Á½I¥Í­É…Á €ôì(€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€€€¹½‘•Ìèmt°•‘•Ìèmt°(€€€€€ÍÕµµ…Éäèì(€€€€€€€™¥¹‘¥¹}½Õ¹Ðè€À°¹½‘•}½Õ¹Ðè€À°•‘•}½Õ¹Ðè€À°Õ¹­¹½Ý¹}¹½‘•}½Õ¹Ðè€À°(€€€€€€€Õ¹­¹½Ý¹}•‘•}½Õ¹Ðè€À°¡¥¡}É¥Í­}™¥¹‘¥¹Ìè€À°É¥Ñ¥…±}™¥¹‘¥¹Ìè€À(€€€€€ô°(€€€€€Í½É•Ìèl(€€€€€€€ì(€€€€€€€€€™¥¹‘¥¹}¥è±½Í•‘¥á•¹¥°™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µ±½Í•œ°(€€€€€€€€€Í½É”è€ää°Í•Ù•É¥Ñäè€É¥Ñ¥…°œ°½¹™¥‘•¹”è€À¸ää°(€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€Í•Ù•É¥Ñäè€ÄÀÀ°½¹™¥‘•¹”è€ää°•áÁ±½¥Ñ…‰¥±¥Ñäè€äÀ°ÁÉ¥Ù¥±•”è€àÀ°(€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÜÀ°•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€ØÀ°™É•Í¡¹•ÍÌè€ÄÀÀ°Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€àÀ(€€€€€€€€€ô°(€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€ô°(€€€€€€€ì(€€€€€€€€€™¥¹‘¥¹}¥è…Ñ¥Ù•=Á•¸¹¥°™¥¹‘¥¹}¹½‘•}¥è€¹½‘”µ½Á•¸œ°(€€€€€€€€€Í½É”è€ÔÔ°Í•Ù•É¥Ñäè€µ•‘¥Õ´œ°½¹™¥‘•¹”è€À¸Ü°(€€€€€€€€€™…Ñ½ÉÌèì(€€€€€€€€€€€Í•Ù•É¥Ñäè€ÔÔ°½¹™¥‘•¹”è€ÜÀ°•áÁ±½¥Ñ…‰¥±¥Ñäè€ÐÀ°ÁÉ¥Ù¥±•”è€ÌÀ°(€€€€€€€€€€€•áÁ½ÍÕÉ”è€ÈÀ°•¹Ù¥É½¹µ•¹Ñ}É¥Ñ¥…±¥Ñäè€À°™É•Í¡¹•ÍÌè€ÄÀÀ°Á½ÍÑÕÉ•}…µÁ±¥™¥•Èè€À(€€€€€€€€€ô°(€€€€€€€€€Õ¹­¹½Ý¹Ìèmt(€€€€€€€ô(€€€€€t(€€€ôì((€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì(€€€€€™¥¹‘¥¹Ìèm…Ñ¥Ù•=Á•¸°±½Í•‘¥á•‘t°(€€€€€É¥Í­É…Á èÉ…Á¡]¥Ñ¡±½Í•‘Q½ÁM½É”(€€€ô¤ì((€€€½¹ÍÐÁ…Ñ¡Í1¥ÍÐ€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ Q½À‰±…ÍÐµÉ…‘¥ÕÌÁ…Ñ¡Ìœ¤¤¹ÅÕ•ÉåM•±•Ñ½È ½°œ¤ì(€€€•áÁ•Ð¡Á…Ñ¡Í1¥ÍÐ¤¹¹½Ð¹Ñ½	•9Õ±° ¤ì(€€€½¹ÍÐÉ½ÝÌ€ô€¡Á…Ñ¡Í1¥ÍÐ…Ì!Q51±•µ•¹Ð¤¹ÅÕ•ÉåM•±•Ñ½É±° ±¤œ¤ì(€€€€¼¼=¹±äÑ¡”…Ñ¥Ù”™¥¹‘¥¹œ…ÁÁ•…ÉÌƒŠPÑ¡”±½Í•µ‰ÕÐµ¡¥¡•ÍÐµÍ½É¥¹œ½¹”¥Ì™¥±Ñ•É•¸(€€€•áÁ•Ð¡É½ÝÌ¹±•¹Ñ ¤¹Ñ½	” Ä¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ Ñ¥Ù”½Á•¸™¥¹‘¥¹œœ¤ì(€€€•áÁ•Ð¡É½ÝÍlÁt¹Ñ•áÑ½¹Ñ•¹Ð¤¹¹½Ð¹Ñ½½¹Ñ…¥¸ ±½Í•™¥á•™¥¹‘¥¹œœ¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌÑ¡”A$µÁÉ½Ù¥‘•Á½ÍÑÕÉ”¡•¬É•…Í½¸½¸Á•Éµ¥ÍÍ¥½¸µ±¥µ¥Ñ•…¹Õ¹…Ù…¥±…‰±”¡•­Ìœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼Á•Éµ¥ÍÍ¥½¹}±¥µ¥Ñ•Á½ÍÑÕÉ”¡•¬…ÉÉ¥•Ì„É•…Í½¸ÍÑÉ¥¹œÑ¡…Ð(€€€€¼¼‘¥…¹½Í•ÌÑ¡”½±±•Ñ¥½¸…ÀìÑ¡”‘É¥±±‘½Ý¸µÕÍÐÉ•¹‘•È¥ÐÍ¼(€€€€¼¼½Á•É…Ñ½ÉÌ…¸…Ð½¸¥Ð°µ…Ñ¡¥¹œÑ¡”É•Á½Í¥Ñ½É¥•Ì¥¹Ù•¹Ñ½ÉäÙ¥•Ü¸(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°(€€€€€€€½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèl(€€€€€€€€€ì(€€€€€€€€€€€¥è€½ÉœµÉÕ¹¹•ÈµÉ½ÕÁÌœ°(€€€€€€€€€€€…Ñ•½Éäè€ÉÕ¹¹•ÉÌœ°(€€€€€€€€€€€ÍÑ…Ñ”è€Á•Éµ¥ÍÍ¥½¹}±¥µ¥Ñ•œ°(€€€€€€€€€€€É•…Í½¸è€µ¥ÍÍ¥¹}½É…¹¥é…Ñ¥½¹}Á•Éµ¥ÍÍ¥½¸œ°(€€€€€€€€€€€ÍÕµµ…Éäè€M•±˜µ¡½ÍÑ•ÉÕ¹¹•ÈÁ½ÍÑÕÉ”½Õ±¹½Ð‰”½±±•Ñ•¸œ(€€€€€€€€€ô(€€€€€€€t(€€€€€ô(€€€ô¤ì((€€€€¼¼	½Ñ Ñ¡”ÍÕµµ…Éä…¹Ñ¡”É•…Í½¸µÕÍÐ…ÁÁ•…È…±½¹Í¥‘”Ñ¡”¡•¬¸(€€€•áÁ•Ð¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	åQ•áÐ ½M•±˜µ¡½ÍÑ•ÉÕ¹¹•ÈÁ½ÍÑÕÉ”½Õ±¹½Ð‰”½±±•Ñ•½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ	åQ•áÐ ½5¥ÍÍ¥¹œ=É…¹¥é…Ñ¥½¸A•Éµ¥ÍÍ¥½¸½¤¤¤¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€ô¤ì((€¥Ð ‘½•Ì¹½Ð•áÁ½Í”Ñ¡”‘É¥±±‘½Ý¸‘•Ñ…¥°É½ÕÑ”¥¸Ñ¡”¥Ñ!Õˆ‘½µ…¥¸™±å½ÕÐœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼AÉ½‘ÕÑ½µ…¥¹±å½ÕÐÉ•¹‘•ÉÌ•Ù•Éä•¹ÑÉä¥¸AI=UQ}=5%9}=9%L¹¥Ñ¡Õˆ¹É½ÕÑ•Ì(€€€€¼¼…Ì„Á±…¥¸±¥¹¬°Í¼É•¥ÍÑ•É¥¹œÑ¡”Á…É…µ•Ñ•É¥é•‘•Ñ…¥°É½ÕÑ”Ý½Õ±(€€€€¼¼½Á•¸¥ÐÝ¥Ñ ¹¼€ýÉ•Á½Í¥Ñ½ÉäôÁ…É…´…¹¥µµ•‘¥…Ñ•±äÍ¡½Ü€‰I•Á½Í¥Ñ½Éä¹½Ð(€€€€¼¼Í•±•Ñ•¸ˆQ¡”‘É¥±±‘½Ý¸µÕÍÐÑ¡•É•™½É”ÍÑ…ä½ÕÐ½˜AI=UQ}=5%9}=9%L¸(€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€½¹ÍÐ½¹™¥œ€ôÁÉ½‘ÕÑM¡•±°¹AI=UQ}=5%9}=9%L¹¥Ñ¡Õˆì(€€€½¹ÍÐÉ½ÕÑ•%Ì€ô½¹™¥œ¹É½ÕÑ•Ì¹µ…À ¡É½ÕÑ”¤€ôøÉ½ÕÑ”¹¥¤ì(€€€•áÁ•Ð¡É½ÕÑ•%Ì¤¹¹½Ð¹Ñ½½¹Ñ…¥¸ É•Á½Í¥Ñ½É¥•Ìµ‘•Ñ…¥°œ¤ì(€€€€¼¼Q¡”I•Á½Í¥Ñ½É¥•Ì•¹ÑÉä¥ÌÍÑ¥±°Ñ¡•É”Í¼½Á•É…Ñ½ÉÌÉ•… Ñ¡”‘É¥±±‘½Ý¸(€€€€¼¼Ù¥„„É½Ü±¥¬½¸Ñ¡”¥¹Ù•¹Ñ½ÉäÁ…”¥¹ÍÑ•…¸(€€€•áÁ•Ð¡É½ÕÑ•%Ì¤¹Ñ½½¹Ñ…¥¸ É•Á½Í¥Ñ½É¥•Ìœ¤ì(€ô¤ì((€¥Ð •á±Õ‘•Ì™¥á•°ÍÕÁÁÉ•ÍÍ•°É¥Í¬µ…•ÁÑ•°…¹™…±Í”µÁ½Í¥Ñ¥Ù”™¥¹‘¥¹Ì™É½´Ñ¡”ÅÕ•Õ”…¹AÉ•Ù¥•Ü½Õ¹Ðœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼5¥à…Ñ¥Ù”…¹±½Í•™¥¹‘¥¹ÌƒŠPÑ¡”ÅÕ•Õ”µÕÍÐÍ¡½Ü½¹±ä½Á•¸½É•½Á•¹•¸(€€€½¹ÍÐ±½Í•‘¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥è€™¥¹‘¥¹œµ±½Í•µ™¥á•œ°(€€€€€Ñ¥Ñ±”è€±É•…‘ä™¥á•™¥¹‘¥¹œµÕÍÐ¹½ÐÉ…¹¬œ°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€™¥á•œ(€€€ôì(€€€½¹ÍÐÍÕÁÁÉ•ÍÍ•‘¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°(€€€€€¥è€™¥¹‘¥¹œµÍÕÁÁÉ•ÍÍ•œ°(€€€€€Ñ¥Ñ±”è€MÕÁÁÉ•ÍÍ•™¥¹‘¥¹œµÕÍÐ¹½ÐÉ…¹¬œ°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€ÍÕÁÁÉ•ÍÍ•œ(€€€ôì(€€€½¹ÍÐÉ•½Á•¹•‘¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Ý½É­™±½Ý¥¹‘¥¹œ°(€€€€€¥è€™¥¹‘¥¹œµÉ•½Á•¹•œ°(€€€€€Ñ¥Ñ±”è€I•½Á•¹•™¥¹‘¥¹œµÕÍÐ…ÁÁ•…Èœ°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€É•½Á•¹•œ(€€€ôì(€€€½¹ÍÐ…Ñ¥Ù•=Á•¸è¥¹‘¥¹œ€ôì€¸¸¹Á½ÍÑÕÉ•¥¹‘¥¹œ°±¥™•å±•}ÍÑ…ÑÕÌè€½Á•¸œôì(€€€…Ý…¥ÐÉ•¹‘•ÉI•Á½Í¥Ñ½Éå•Ñ…¥°¡ì(€€€€€™¥¹‘¥¹Ìèm…Ñ¥Ù•=Á•¸°±½Í•‘¥¹‘¥¹œ°É•½Á•¹•‘¥¹‘¥¹œ°ÍÕÁÁÉ•ÍÍ•‘¥¹‘¥¹t(€€€ô¤ì((€€€½¹ÍÐÅÕ•Õ•1¥ÍÐ€ô€¡…Ý…¥ÐÍÉ••¸¹™¥¹‘	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤¹ÅÕ•ÉåM•±•Ñ½È Õ°œ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ¤¹¹½Ð¹Ñ½	•9Õ±° ¤ì(€€€½¹ÍÐÉ½ÝÌ€ô€¡ÅÕ•Õ•1¥ÍÐ…Ì!Q51±•µ•¹Ð¤¹ÅÕ•ÉåM•±•Ñ½É±° ±¤œ¤ì(€€€€¼¼€È™¥¹‘¥¹ÌÍÕÉÙ¥Ù•€¡½Á•¸€¬É•½Á•¹•¤°€È±½Í•‘É½ÁÁ•¸(€€€•áÁ•Ð¡É½ÝÌ¹±•¹Ñ ¤¹Ñ½	” È¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ„¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ •™…Õ±Ð‰É…¹ ÁÉ½Ñ•Ñ¥½¸¥ÌÕ¹ÁÉ½Ñ•Ñ•œ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ„¹Ñ•áÑ½¹Ñ•¹Ð¤¹Ñ½½¹Ñ…¥¸ I•½Á•¹•™¥¹‘¥¹œµÕÍÐ…ÁÁ•…Èœ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ„¹Ñ•áÑ½¹Ñ•¹Ð¤¹¹½Ð¹Ñ½½¹Ñ…¥¸ ±É•…‘ä™¥á•™¥¹‘¥¹œµÕÍÐ¹½ÐÉ…¹¬œ¤ì(€€€•áÁ•Ð¡ÅÕ•Õ•1¥ÍÐ„¹Ñ•áÑ½¹Ñ•¹Ð¤¹¹½Ð¹Ñ½½¹Ñ…¥¸ MÕÁÁÉ•ÍÍ•™¥¹‘¥¹œµÕÍÐ¹½ÐÉ…¹¬œ¤ì(€€€€¼¼AÉ•Ù¥•Ü‰ÕÑÑ½¸½¹±ä…ÁÁ•…ÉÌ½¸™¥¹‘¥¹ÌÑ¡”‰…­•¹…¸…ÑÕ…±±ä(€€€€¼¼É•µ•‘¥…Ñ”èÑ¡”É•½Á•¹•™¥¹‘¥¹œÕÍ•Ì„Ý½É­™±½Ý}€‘•Ñ•Ñ½È€¡ÍÕÁÁ½ÉÑ•¤°(€€€€¼¼Ñ¡”…Ñ¥Ù”½Á•¸ÕÍ•Ì„¥Ñ¡Õ‰}€Á½ÍÑÕÉ”‘•Ñ•Ñ½È€¡¹½ÐÍÕÁÁ½ÉÑ•¤¸M¼(€€€€¼¼Ñ¡”‰ÕÑÑ½¸½Õ¹ÐÍ¡½Õ±‰”€Ä°µ…Ñ¡¥¹œÑ¡”™¥àµÉ•…‘äÍÕ‰Í•ÐƒŠP¹½ÐÑ¡”(€€€€¼¼™Õ±°…Ñ¥Ù”½Õ¹Ð½˜€È¸(€€€½¹ÍÐÁÉ•Ù¥•Ý	ÕÑÑ½¹Ì€ôÍÉ••¸¹•Ñ±±	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÉ•Ù¥•ÜÉ•µ•‘¥…Ñ¥½¸½¤ô¤ì(€€€•áÁ•Ð¡ÁÉ•Ù¥•Ý	ÕÑÑ½¹Ì¹±•¹Ñ ¤¹Ñ½	” Ä¤ì(€ô¤ì((€¥Ð Í•¹‘ÌÑ¡”™¥¹‘¥¹pÌ½Ý¸Í…¹}¥Ý¡•¸ÁÉ•Ù¥•Ý¥¹œÉ•µ•‘¥…Ñ¥½¸™½È„É•Ñ…¥¹•½±‘•È™¥¹‘¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€€¼¼Q¡”‘É¥±±‘½Ý¹pÌ±…Ñ•ÍÐÍ…¸¥Ì„¹•Ý•ÈÁ…ÉÑ¥…°Í…¸ìÑ¡”™¥¹‘¥¹œÝ…Ì(€€€€¼¼É•Ñ…¥¹•™É½´…¸½±‘•ÈÍ…¸¸AÉ•Ù¥•ÜµÕÍÐ…±°Ý¥Ñ Ñ¡”™¥¹‘¥¹pÌ(€€€€¼¼Í…¹}¥€¡½±‘•È¤°¹½ÐÑ¡”‘É¥±±‘½Ý¹pÌ±…Ñ•ÍÐÍ…¸¹¥¸(€€€½¹ÍÐ½±‘•ÉM…¹%€ô€É•Á¼µÍ…¸µ½±‘•Èµ‘•Ñ…¥°œì(€€€€¼¼UÍ”Ý½É­™±½Ý¥¹‘¥¹œ…ÌÑ¡”‰…Í”Í¼Ñ¡”‘•Ñ•Ñ½È€¡Ý½É­™±½Ý}½¥‘}‰É½…‘}ÑÉÕÍÑ€¤(€€€€¼¼¥Ì¥¸Ñ¡”MÕ•ÍÑI•Á½áÁ½ÍÕÉ•I•µ•‘¥…Ñ¥½¸ÍÕÁÁ½ÉÑ•Í•ÐìÁ½ÍÑÕÉ”µ‘•Ñ•Ñ½È(€€€€¼¼™¥¹‘¥¹Ì‘¼¹½ÐÉ•¹‘•È„AÉ•Ù¥•Ü‰ÕÑÑ½¸‰ä‘•Í¥¸¸(€€€½¹ÍÐÉ•Ñ…¥¹•‘¥¹‘¥¹œè¥¹‘¥¹œ€ôì(€€€€€€¸¸¹Ý½É­™±½Ý¥¹‘¥¹œ°(€€€€€¥è€™¥¹‘¥¹œµÉ•Ñ…¥¹•µ™É½´µ½±‘•ÈµÍ…¸œ°(€€€€€Í…¹}¥è½±‘•ÉM…¹%°(€€€€€±¥™•å±•}ÍÑ…ÑÕÌè€½Á•¸œ(€€€ôì(€€€½¹ÍÐ¹•Ý•ÉM…¸èI•Á½M…¹I•½É€ôì(€€€€€€¸¸¹½µÁ±•Ñ•‘M…¸°(€€€€€¥è€É•Á¼µÍ…¸µ¹•Ý•ÍÐµ‘•Ñ…¥°œ(€€€ôì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉMÑ…ÑÕÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì½¹¹•Ñ¥½¸è½¹¹•Ñ•‘¥Ñ!Õˆô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm¹•Ý•ÉM…¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÉ•Ñ…¥¹•‘¥¹‘¥¹tô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•Ñ¥Ñ!Õ‰½¹¹•Ñ½ÉI•Á½Í¥Ñ½ÉåA½ÍÑÕÉ”œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€½¹¹•Ñ½É}¥è€¥Ñ¡Õˆµ…ÁÀœ°ÁÉ½Ù¥‘•Èè€¥Ñ¡Õ‰}…ÁÀœ°(€€€€€Á½ÍÑÕÉ”èì(€€€€€€€É•Á½Í¥Ñ½ÉäèÑ…É•ÑI•Á½Í¥Ñ½Éä°½±±•Ñ•‘}…Ðè€œÈÀÈØ´ÀÔ´ÄÝPÄÀèÔØèÀÁhœ°(€€€€€€€¡•­Ìèmì¥è€‰É…¹ µÁÉ½Ñ•Ñ¥½¸œ°…Ñ•½Éäè€‰É…¹ ÁÉ½Ñ•Ñ¥½¸œ°ÍÑ…Ñ”è€Í•ÕÉ”œ°ÍÕµµ…Éäè€Í•ÕÉ”œõt(€€€€€ô(€€€ô¤ì(€€€½¹ÍÐÁÉ•Ù¥•ÝMÁä€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€ÁÉ•Ù¥•ÝI•Á½¥¹‘¥¹I•µ•‘¥…Ñ¥½¸œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€™¥¹‘¥¹œèÉ•Ñ…¥¹•‘¥¹‘¥¹œ°(€€€€€É•µ•‘¥…Ñ¥½¸èì(€€€€€€€‘•Ñ•Ñ½Èè€àœ°ÍÕµµ…Éäè€½¬œ°É¥Í­}ÍÕµµ…Éäè€œœ°ÍÑ•ÁÌèmt°Í…™•Ñå}¹½Ñ•Ìèmt°Ù…±¥‘…Ñ¥½¸èmt°(€€€€€€€Í•É•Ñ}É½Ñ…Ñ¥½¸è™…±Í”°ÁÕ‰±¥Í¡…‰±”èÑÉÕ”°•Ù¥‘•¹”èì™¥¹‘¥¹}¥èÉ•Ñ…¥¹•‘¥¹‘¥¹œ¹¥ô(€€€€€ô(€€€ô¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€½¹ÍÐÁÉ•Ù¥•Ý	ÕÑÑ½¸€ô…Ý…¥ÐÍÉ••¸¹™¥¹‘	åI½±” ‰ÕÑÑ½¸œ°ì¹…µ”è€½AÉ•Ù¥•ÜÉ•µ•‘¥…Ñ¥½¸½¤ô¤ì(€€€™¥É•Ù•¹Ð¹±¥¬¡ÁÉ•Ù¥•Ý	ÕÑÑ½¸¤ì(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø•áÁ•Ð¡ÁÉ•Ù¥•ÝMÁä¤¹Ñ½!…Ù•	••¹…±±• ¤¤ì(€€€€¼¼AÉ•Ù¥•Ü•¹‘Á½¥¹ÐÉ••¥Ù•Ñ¡”™¥¹‘¥¹pÌ½Ý¸Í…¸¥°¹½ÐÑ¡”±…Ñ•ÍÐÍ…¸¸(€€€•áÁ•Ð¡ÁÉ•Ù¥•ÝMÁä¹µ½¬¹…±±ÍlÁtü¹lÁt¤¹Ñ½	”¡É•Ñ…¥¹•‘¥¹‘¥¹œ¹¥¤ì(€€€•áÁ•Ð¡ÁÉ•Ù¥•ÝMÁä¹µ½¬¹…±±ÍlÁtü¹lÅt¤¹Ñ½ÅÕ…°¡•áÁ•Ð¹½‰©•Ñ½¹Ñ…¥¹¥¹œ¡ìÉ•Á½}Í…¹}¥è½±‘•ÉM…¹%ô¤¤ì(€ô¤ì((€¥Ð É•¹‘•ÉÌÑ¡”±½…‘¥¹œÍ¡•±°Ý¡•¸¥Ñ!Õˆ…Ù…¥±…‰¥±¥Ñä¥ÌÍÑ¥±°É•Í½±Ù¥¹œœ°…Íå¹Œ€ ¤€ôøì(€€€µ½­½¹¹•Ñ½É•…ÑÕÉ•±…Ì¡ì…ÝÌè™…±Í”°¥Ñ¡ÕˆèÑÉÕ”°­Õ‰•É¹•Ñ•Ìè™…±Í”ô¤ì(€€€€¼¼±½…‘¥¹œèÑÉÕ”ƒŠP…Ù…¥±…‰¥±¥Ñä¥ÌÍÑ¥±°É•Í½±Ù¥¹œ¸(€€€µ½­	…­•¹‘•…ÑÕÉ•Ì¡ì¥Ñ¡ÕˆèÑÉÕ”ô°ì±½…‘¥¹œèÑÉÕ”ô¤ì(€€€½¹ÍÐ…Á¤€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½…Á¤½±¥•¹Ðœ¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑAÉ½©•ÑÌœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€¥Ñ•µÌèmì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€õt(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑAÉ½©•Ðœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì(€€€€€ÁÉ½©•Ðèì(€€€€€€€Ñ•¹…¹Ñ}¥è€Ñ•¹…¹Ðµ„œ°Ý½É­ÍÁ…•}¥è€Ý½É­ÍÁ…”µ„œ°ÁÉ½©•Ñ}¥è€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°(€€€€€€€¹…µ”è€AÉ½‘ÕÑ¥½¸A±…Ñ™½É´œ°Í±Õœè€ÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´œ°‘•ÍÉ¥ÁÑ¥½¸è€œœ°(€€€€€€€É•…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÅPÀÀèÀÀèÀÁhœ°ÕÁ‘…Ñ•‘}…Ðè€œÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhœ(€€€€€ô(€€€ô¤ì(€€€Ù¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½M…¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèm½µÁ±•Ñ•‘M…¹tô¤ì(€€€½¹ÍÐ±¥ÍÑI•Á½¥¹‘¥¹Ì€ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€±¥ÍÑI•Á½¥¹‘¥¹Ìœ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡ì¥Ñ•µÌèmÁ½ÍÑÕÉ•¥¹‘¥¹tô¤ì(€€€½¹ÍÐ•ÑI•Á½I¥Í­É…Á €ôÙ¤¹ÍÁå=¸¡…Á¤¹…Á¥±¥•¹Ð°€•ÑI•Á½I¥Í­É…Á œ¤¹µ½­I•Í½±Ù•‘Y…±Õ”¡É¥Í­É…Á¡]¥Ñ¡M½É•Ì¤ì((€€€½¹ÍÐÁÉ½‘ÕÑM¡•±°€ô…Ý…¥Ð¥µÁ½ÉÐ œ¸½ÁÉ½‘ÕÑM¡•±°œ¤ì(€€€É•¹‘•È (€€€€€€ñ5•µ½ÉåI½ÕÑ•È¥¹¥Ñ¥…±¹ÑÉ¥•Ìõím€½…ÁÀ½Ñ•¹…¹Ðµ„½Ý½É­ÍÁ…”µ„½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ý•¹Ù¥É½¹µ•¹ÐõÁÉ½‘ÕÑ¥½¸µÁ±…Ñ™½É´™É•Á½Í¥Ñ½Éäô‘í•¹½‘•UI%½µÁ½¹•¹Ð¡Ñ…É•ÑI•Á½Í¥Ñ½Éä¥õuôø(€€€€€€€€ñI½ÕÑ•Ìø(€€€€€€€€€€ñI½ÕÑ”(€€€€€€€€€€€Á…Ñ ôˆ½…ÁÀ¼éÑ•¹…¹Ñ%¼éÝ½É­ÍÁ…•%½¥Ñ¡Õˆ½É•Á½Í¥Ñ½É¥•Ì½‘•Ñ…¥°ˆ(€€€€€€€€€€€•±•µ•¹ÐõìñÁÉ½‘ÕÑM¡•±°¹AÉ½‘ÕÑ¥Ñ!Õ‰I•Á½Í¥Ñ½Éå•Ñ…¥±A…”€¼ùô(€€€€€€€€€€¼ø(€€€€€€€€ð½I½ÕÑ•Ìø(€€€€€€ð½5•µ½ÉåI½ÕÑ•Èø(€€€€¤ì((€€€€¼¼Q¡”±½…‘¥¹œÍ¡•±°É•¹‘•ÉÌ¥¹ÍÑ•…½˜Ñ¡”¹½Éµ…°‘É¥±±‘½Ý¸Í¡•±°¸(€€€€¼¼	½Ñ Ñ¡”½µ…¥¹A…•M¡•±°‘•ÍÉ¥ÁÑ¥½¸…¹Ñ¡”½µ…¥¹1½…‘¥¹MÑ…Ñ”±…‰•°(€€€€¼¼…ÉÉäÑ¡”Á¡É…Í”°Í¼…±±½ÜµÕ±Ñ¥Á±”µ…Ñ¡•Ì¸(€€€…Ý…¥ÐÝ…¥Ñ½È  ¤€ôø(€€€€€•áÁ•Ð¡ÍÉ••¸¹•Ñ±±	åQ•áÐ ½1½…‘¥¹œ¥Ñ!Õˆ…Ù…¥±…‰¥±¥Ñä½¤¤¹±•¹Ñ ¤¹Ñ½	•É•…Ñ•ÉQ¡…¸ À¤(€€€€¤ì(€€€€¼¼Q¡”ÁÉ¥½É¥Ñ¥é•ÅÕ•Õ”…¹Ñ¡”‘É¥±±‘½Ý¸µÍÁ•¥™¥Œ™•Ñ¡•ÌµÕÍÐ¹•Ù•ÈÉÕ¸(€€€€¼¼Ý¡¥±”…Ù…¥±…‰¥±¥Ñä¥ÌÍÑ¥±°É•Í½±Ù¥¹œ¸±¥ÍÑI•Á½M…¹Ì¥Ì½ÉÑ¡½½¹…±±ä(€€€€¼¼•á•É¥Í•‰äÑ¡”Í¡…É•ÕÍ•¥Ñ!Õ‰½µ…¥¹…Ñ„¡½½¬°Í¼½¹±ä…ÍÍ•ÉÐ½¸Ñ¡”(€€€€¼¼‘É¥±±‘½Ý¸µÍÁ•¥™¥Œ™¥¹‘¥¹Ì½É…Á ™•Ñ¡•Ì¡•É”¸(€€€•áÁ•Ð¡ÍÉ••¸¹ÅÕ•Éå	å1…‰•±Q•áÐ AÉ¥½É¥Ñ¥é•™¥¹‘¥¹ÌÅÕ•Õ”œ¤¤¹¹½Ð¹Ñ½	•%¹Q¡•½Õµ•¹Ð ¤ì(€€€•áÁ•Ð¡±¥ÍÑI•Á½¥¹‘¥¹Ì¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€€€•áÁ•Ð¡•ÑI•Á½I¥Í­É…Á ¤¹¹½Ð¹Ñ½!…Ù•	••¹…±±• ¤ì(€ô¤ì)ô¤ì(