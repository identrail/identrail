import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  AuthConfigResponse,
  AWSConnectorStartResponse,
  AWSCodeBuildServiceRoleInventoryResult,
  AWSConnectionStatus,
  AWSEC2InstanceProfileInventoryResult,
  AWSEKSWorkloadIdentityInventoryResult,
  AWSECSTaskRoleInventoryResult,
  AWSLambdaExecutionRoleInventoryResult,
  AWSLeastPrivilegeResult,
  AWSPlatformBaselineResult,
  AWSPlatformDependencyIndexResult,
  AWSPlatformValidationHarnessResult,
  AWSRuntimeEventResult,
  AWSServiceCollectorContractResult,
  AWSUnusedDormantAccessResult,
  CurrentUserContext,
  Finding,
  GitHubConnectionStatus,
  GitHubOrganizationPosture,
  GitHubRepositoryPosture,
  KubernetesConnectorStartResponse,
  KubernetesConnectionStatus,
  RepoFindingRemediationPreview,
  RepoFindingRemediationPublishResponse,
  RepoScanRecord,
  ScanPolicyRecord,
  WhoAmIResponse
} from './api/client';
import type { BackendFeatureState } from './hooks/useBackendFeatures';
// Vite's `?raw` import returns the file contents as a string at bundle
// time, so the AWS copy-redundancy guard below can scan productShell.tsx
// without needing node's `require` or fs typings.
import productShellSource from './productShell.tsx?raw';

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
    total_events: 3,
    filtered_events: 3,
    event_type_counts: { 'api-call': 1, 'agent-tool': 1, 'access-analyzer': 1 },
    status_counts: { observed: 3 },
    owner_counts: { security: 3 },
    account_count: 1,
    region_count: 1,
    identity_count: 1,
    resource_count: 3,
    agent_event_count: 1,
    secret_read_count: 0,
    kms_decrypt_count: 0,
    api_call_count: 1,
    sts_session_count: 0,
    iam_last_used_signal_count: 0,
    access_analyzer_finding_count: 1,
    dormant_access_count: 0,
    relationship_count: 2,
    permission_denied_events: 0
  },
  records: [
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
        principal_arn: 'arn:aws:iam::123456789012:role/lambda-invoice-agent',
        principal_type: 'assumed_role',
        started_at: '2026-06-14T17:00:00Z'
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
      status: 'observed',
      next_action: 'Review Access Analyzer scope and finding status before trusting or remediating access.',
      redaction_boundary: 'metadata_only_no_payloads_no_secret_values'
    }
  ],
  relationships: [],
  failure_reasons: [],
  remediation_hints: [],
  evidence_links: ['/docs/aws-runtime-events'],
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

    expect(screen.getByText('⌘K')).toBeInTheDocument();
    expect(screen.getByText('⌘B')).toBeInTheDocument();
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

    await waitFor(() => expect(within(githubCard).getByText('Pending')).toBeInTheDocument());
    expect(within(githubCard).getByText('No scans')).toBeInTheDocument();
    expect(githubCard).toHaveAttribute('href', '/app/tenant-a/workspace-a/github');
    expect(screen.queryByRole('link', { name: 'Connect GitHub' })).not.toBeInTheDocument();
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
    expect(within(githubCard).getByText('No scans')).toBeInTheDocument();
    expect(within(agenticRiskCard).getByText('Not connected')).toBeInTheDocument();
    expect(within(agenticRiskCard).getByText('No signals')).toBeInTheDocument();
    expect(screen.getByText('0/4')).toBeInTheDocument();
  });
});

describe('Domain-first app routes', () => {
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
      '/app/:tenantID/:workspaceID/aws/connect',
      '/app/:tenantID/:workspaceID/aws/accounts',
      '/app/:tenantID/:workspaceID/aws/identities',
      '/app/:tenantID/:workspaceID/aws/agents',
      '/app/:tenantID/:workspaceID/aws/resources',
      '/app/:tenantID/:workspaceID/aws/runtime',
      '/app/:tenantID/:workspaceID/aws/graph',
      '/app/:tenantID/:workspaceID/aws/findings',
      '/app/:tenantID/:workspaceID/aws/remediation',
      '/app/:tenantID/:workspaceID/aws/governance',
      '/app/:tenantID/:workspaceID/github',
      '/app/:tenantID/:workspaceID/github/connect',
      '/app/:tenantID/:workspaceID/github/repositories',
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

    // Title is just "AWS" — no eyebrow, no marketing tagline.
    expect(await screen.findByRole('heading', { level: 2, name: 'AWS' })).toBeInTheDocument();
    // The account / region facts move into the header subtitle.
    expect(await screen.findByText(/123456789012/)).toBeInTheDocument();
    // The capability nav grid is still the way users reach the sub-pages.
    expect(screen.getByRole('link', { name: /Resources/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/resources?environment=production'
    );
    expect(screen.getByRole('link', { name: /Identities/i })).toHaveAttribute(
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
    expect(screen.getByRole('table', { name: 'AWS account and region coverage' })).toBeInTheDocument();
    expect(screen.getAllByText(/AWS account 123456789012/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Region us-east-1/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Open Connect AWS/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/connect?environment=production'
    );
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
    expect(screen.getAllByText(/Connect AWS to populate current inventory anchors/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Bedrock agents/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AgentCore runtime and gateway identity/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Secret metadata only, no value reads/i)).toBeInTheDocument();
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
      correlation: { status: 'degraded', records: [], summary: {}, caveats: [], failure_reasons: [], remediation_hints: [] } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectS3RuntimeAccess').mockResolvedValue({
      correlation: { status: 'degraded', records: [], summary: {}, caveats: [], failure_reasons: [], remediation_hints: [] } as any
    });
    vi.spyOn(api.apiClient, 'getAWSProjectAgentRuntimeAccess').mockResolvedValue({
      correlation: { status: 'degraded', records: [], summary: {}, caveats: [], failure_reasons: [], remediation_hints: [] } as any
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
    expect(await screen.findByRole('table', { name: 'AWS AI agent risk findings' })).toBeInTheDocument();
    expect(screen.getAllByText(/External credential exposure/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS remediation cases' })).toBeInTheDocument();
    expect(screen.getByText(/Rotate external credential for support-assistant/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Secret rotation/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS IAM policy diffs' })).toBeInTheDocument();
    expect(screen.getByText(/Scope data-loader: remove 2 action\(s\)/i)).toBeInTheDocument();
    expect(screen.getAllByText(/ready · Low breakage/i).length).toBeGreaterThan(0);
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
    expect(screen.getAllByText(/ai-platform · Pending approver/i).length).toBeGreaterThan(0);
    expect(await screen.findByRole('table', { name: 'AWS access key quarantine plans' })).toBeInTheDocument();
    expect(screen.getByText(new RegExp(`Access key quarantine: ${accessKeyID}`, 'i'))).toBeInTheDocument();
    expect(screen.getAllByText(/orders-platform · Owner notification required/i).length).toBeGreaterThan(0);
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
    expect(await screen.findByRole('table', { name: 'AWS secret-to-permission equivalence findings' })).toBeInTheDocument();
    expect(screen.getByText(/Agent provider key equivalence/i)).toBeInTheDocument();
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
    const getSecretPermissionEquivalence = vi.spyOn(api.apiClient, 'getAWSProjectSecretPermissionEquivalence').mockResolvedValue({
      findings: {
        status: 'ready',
        findings: [],
        summary: {
          external_provider_key_count: 0,
          aws_managed_secret_count: 0,
          runtime_observed_count: 0,
          kms_backed_count: 0
        },
        caveats: [],
        failure_reasons: [],
        remediation_hints: [],
        coverage_gaps: [],
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
    await waitFor(() =>
      expect(getSecretPermissionEquivalence).toHaveBeenLastCalledWith(
        'workspace-a',
        'production',
        expect.objectContaining({ connectorID: 'aws-connector-1' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

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
  });

  it('keeps AWS resources inventory metadata-only when no environment exists', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    const getAWSProjectConnection = vi.spyOn(api.apiClient, 'getAWSProjectConnection');

    const { ProductAWSResourcesPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/resources']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/resources" element={<ProductAWSResourcesPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Resources' })).toBeInTheDocument();
    expect(screen.getByText(/Create an environment before inventory can resolve/i)).toBeInTheDocument();
    expect(screen.getByText(/No secret value reads/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Secrets Manager metadata/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Open environments/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/projects?source=aws'
    );
    expect(getAWSProjectConnection).not.toHaveBeenCalled();
  });

  it('renders SQS and SNS reachability in AWS resources inventory', async () => {
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
    vi.spyOn(api.apiClient, 'getAWSProjectSecretsManagerMetadata').mockResolvedValue({
      inventory: { status: 'ready', records: [], diagnostics: [], failure_reasons: [], account_id: '123456789012', region: 'us-east-1' }
    } as any);
    vi.spyOn(api.apiClient, 'getAWSProjectSSMParameterMetadata').mockResolvedValue({
      inventory: { status: 'ready', records: [], diagnostics: [], failure_reasons: [], account_id: '123456789012', region: 'us-east-1' }
    } as any);
    vi.spyOn(api.apiClient, 'getAWSProjectECRRepositoryMetadata').mockResolvedValue({
      inventory: { status: 'ready', records: [], diagnostics: [], failure_reasons: [], account_id: '123456789012', region: 'us-east-1' }
    } as any);
    const getSQSSNSReachability = vi.spyOn(api.apiClient, 'getAWSProjectSQSSNSReachability').mockResolvedValue({
      inventory: {
        status: 'ready',
        records: [
          {
            account_id: '123456789012',
            region: 'us-east-1',
            service: 'sns',
            resource_arn: 'arn:aws:sns:us-east-1:123456789012:billing-events',
            resource_name: 'billing-events',
            resource_type: 'sns_topic',
            fifo: false,
            content_based_deduplication: false,
            sqs_managed_sse: false,
            subscription_count: 1,
            subscriptions: [{ protocol: 'sqs', endpoint_resource_arn: 'arn:aws:sqs:us-east-1:123456789012:payments-worker', endpoint_present: true }],
            has_resource_policy: true,
            resource_policy_statement_count: 1,
            identity_grants: [{ principal_arn: '*', effect: 'Allow', capabilities: ['publish'], is_public: true, wildcard_principal: true }],
            exposure_classification: 'public',
            source: 'sqs_sns_metadata',
            evidence_ref: 'arn:aws:sns:us-east-1:123456789012:billing-events',
            from_node_id: 'aws:resource:sns-topic:arn:aws:sns:us-east-1:123456789012:billing-events',
            relationship_type: 'can_access',
            confidence: 0.94,
            collected_at: '2026-06-11T10:00:00Z',
            status: 'ready'
          },
          {
            account_id: '123456789012',
            region: 'us-east-1',
            service: 'sqs',
            resource_arn: 'arn:aws:sqs:us-east-1:123456789012:partner-ingest',
            resource_name: 'partner-ingest',
            resource_type: 'sqs_queue',
            queue_url: 'https://sqs.us-east-1.amazonaws.com/123456789012/partner-ingest',
            fifo: false,
            content_based_deduplication: false,
            sqs_managed_sse: true,
            dlq_arns: ['arn:aws:sqs:us-east-1:123456789012:partner-ingest-dlq'],
            has_resource_policy: true,
            resource_policy_statement_count: 1,
            identity_grants: [{ principal_arn: 'arn:aws:iam::999999999999:role/partner-publisher', effect: 'Allow', capabilities: ['publish'], is_cross_account: true }],
            exposure_classification: 'cross_account',
            source: 'sqs_sns_metadata',
            evidence_ref: 'arn:aws:sqs:us-east-1:123456789012:partner-ingest',
            from_node_id: 'aws:resource:sqs-queue:arn:aws:sqs:us-east-1:123456789012:partner-ingest',
            relationship_type: 'can_access',
            confidence: 0.91,
            collected_at: '2026-06-11T10:00:00Z',
            status: 'ready'
          }
        ],
        diagnostics: [],
        failure_reasons: [],
        account_id: '123456789012',
        region: 'us-east-1'
      }
    } as any);

    const { ProductAWSResourcesPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/resources?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/resources" element={<ProductAWSResourcesPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('billing-events')).toBeInTheDocument();
    expect(screen.getByText('partner-ingest')).toBeInTheDocument();
    expect(screen.getAllByText(/Payloads hidden/i).length).toBeGreaterThan(0);
    expect(getSQSSNSReachability).toHaveBeenCalledWith(
      'workspace-a',
      'production',
      'aws-connector-1',
      undefined,
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('keeps AWS connect on the domain page when no environment exists', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    mockAWSBaseline(api);
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });

    const { ProductAWSConnectPage } = await import('./productShell');
    function LocationProbe() {
      const location = useLocation();
      return <p data-testid="location">{`${location.pathname}${location.search}`}</p>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/connect"
            element={
              <>
                <LocationProbe />
                <ProductAWSConnectPage />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Connect AWS' })).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/app/tenant-a/workspace-a/aws/connect');
    expect(screen.getByRole('heading', { level: 3, name: /Pick an environment/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open environments/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/projects?source=aws'
    );
  });

  it('renders the Kubernetes Control Center with connected cluster coverage', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: connectedKubernetes });

    const { ProductKubernetesControlCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes" element={<ProductKubernetesControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Kubernetes Control Center' })).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Kubernetes' })).toBeInTheDocument();
    expect(screen.getAllByText('production-cluster').length).toBeGreaterThan(0);
    expect(screen.getByText('2/2 allowed')).toBeInTheDocument();
    const sectionTable = screen.getByRole('table', { name: 'Kubernetes section links' });
    expect(within(sectionTable).getByRole('link', { name: 'Clusters' })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/kubernetes/clusters?environment=production'
    );
    expect(within(sectionTable).getByRole('link', { name: 'Service accounts / RBAC' })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/kubernetes/service-accounts?environment=production'
    );
  });

  it('waits for Kubernetes feature metadata before loading connection state', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: undefined }, { loading: true });
    const api = await import('./api/client');
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    const getKubernetesProjectConnection = vi
      .spyOn(api.apiClient, 'getKubernetesProjectConnection')
      .mockResolvedValue({ connection: connectedKubernetes });

    const { ProductKubernetesControlCenterPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes" element={<ProductKubernetesControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Kubernetes Control Center' })).toBeInTheDocument();
    await waitFor(() => expect(listProjects).toHaveBeenCalled());
    expect(getKubernetesProjectConnection).not.toHaveBeenCalled();
  });

  it('hides Kubernetes workload inventory when the connector is unavailable', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: false });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    const getKubernetesProjectConnection = vi.spyOn(api.apiClient, 'getKubernetesProjectConnection');

    const { ProductKubernetesWorkloadsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/workloads?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/workloads" element={<ProductKubernetesWorkloadsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Kubernetes unavailable')).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'Workload identity' })).not.toBeInTheDocument();
    expect(screen.queryByText('Deployments')).not.toBeInTheDocument();
    expect(getKubernetesProjectConnection).not.toHaveBeenCalled();
  });

  it('hides Kubernetes workload inventory when no environment is selected', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    const getKubernetesProjectConnection = vi.spyOn(api.apiClient, 'getKubernetesProjectConnection');

    const { ProductKubernetesWorkloadsPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/workloads']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/workloads" element={<ProductKubernetesWorkloadsPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Choose an environment')).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'Workload identity' })).not.toBeInTheDocument();
    expect(screen.queryByText('Deployments')).not.toBeInTheDocument();
    expect(getKubernetesProjectConnection).not.toHaveBeenCalled();
  });

  it('keeps Kubernetes connect on the domain page when no environment exists', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    const getKubernetesProjectConnection = vi.spyOn(api.apiClient, 'getKubernetesProjectConnection');

    const { ProductKubernetesConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/connect']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/connect" element={<ProductKubernetesConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Connect Kubernetes' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: /Choose an environment/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open environments/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/projects?source=kubernetes'
    );
    expect(getKubernetesProjectConnection).not.toHaveBeenCalled();
  });

  it('disables Kubernetes connector submit while feature metadata loads', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: undefined }, { loading: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    const getKubernetesProjectConnection = vi.spyOn(api.apiClient, 'getKubernetesProjectConnection');
    const startKubernetesConnector = vi.spyOn(api.apiClient, 'startKubernetesConnector');

    const { ProductKubernetesConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/connect" element={<ProductKubernetesConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    const submitButton = await screen.findByRole('button', { name: /Generate token/i });
    expect(submitButton).toBeDisabled();
    fireEvent.click(submitButton);
    expect(getKubernetesProjectConnection).not.toHaveBeenCalled();
    expect(startKubernetesConnector).not.toHaveBeenCalled();
  });

  it('starts Kubernetes agent enrollment with workspace and environment scope', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    const getKubernetesProjectConnection = vi
      .spyOn(api.apiClient, 'getKubernetesProjectConnection')
      .mockResolvedValueOnce({ connection: disconnectedKubernetes })
      .mockResolvedValueOnce({ connection: connectedKubernetes });
    vi.spyOn(api.apiClient, 'startKubernetesConnector').mockResolvedValue({
      connection: connectedKubernetes,
      enrollment_token: 'enroll-token-123',
      enrollment_expires_at: '2026-05-17T11:00:00Z',
      helm_command: 'helm upgrade --install identrail-agent identrail/agent --set token=enroll-token-123'
    });

    const { ProductKubernetesConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/connect" element={<ProductKubernetesConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    const submitButton = await screen.findByRole('button', { name: /Generate token/i });
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Production K8s' } });
    fireEvent.change(screen.getByLabelText('API URL'), { target: { value: 'https://k8s.example.com' } });
    fireEvent.click(submitButton);

    await waitFor(() =>
      expect(api.apiClient.startKubernetesConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          workspace_id: 'workspace-a',
          project_id: 'production',
          display_name: 'Production K8s',
          api_url: 'https://k8s.example.com'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await waitFor(() => expect(getKubernetesProjectConnection).toHaveBeenCalledTimes(2));
    expect(await screen.findByDisplayValue('Production Kubernetes')).toBeInTheDocument();
    expect(screen.getByText('enroll-token-123')).toBeInTheDocument();
    expect(screen.getByText(/helm upgrade --install identrail-agent/i)).toBeInTheDocument();
  });

  it('ignores stale Kubernetes enrollment responses after switching environments', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        },
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'staging',
          name: 'Staging',
          slug: 'staging',
          description: 'Staging Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z'
        }
      ]
    });
    const getKubernetesProjectConnection = vi
      .spyOn(api.apiClient, 'getKubernetesProjectConnection')
      .mockResolvedValue({ connection: disconnectedKubernetes });
    const enrollment = deferred<KubernetesConnectorStartResponse>();
    vi.spyOn(api.apiClient, 'startKubernetesConnector').mockReturnValue(enrollment.promise);

    const { ProductKubernetesConnectPage } = await import('./productShell');
    function KubernetesConnectHarness() {
      const location = useLocation();
      const navigate = useNavigate();
      return (
        <>
          <p data-testid="location">{`${location.pathname}${location.search}`}</p>
          <button
            type="button"
            onClick={() => navigate('/app/tenant-a/workspace-a/kubernetes/connect?environment=staging')}
          >
            Open staging
          </button>
          <ProductKubernetesConnectPage />
        </>
      );
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/connect" element={<KubernetesConnectHarness />} />
        </Routes>
      </MemoryRouter>
    );

    const submitButton = await screen.findByRole('button', { name: /Generate token/i });
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Production K8s' } });
    fireEvent.click(submitButton);
    await waitFor(() =>
      expect(api.apiClient.startKubernetesConnector).toHaveBeenCalledWith(
        expect.objectContaining({ project_id: 'production' }),
        expect.objectContaining({ workspaceID: 'workspace-a' })
      )
    );

    fireEvent.click(screen.getByRole('button', { name: 'Open staging' }));
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('environment=staging'));

    await act(async () => {
      enrollment.resolve({
        connection: connectedKubernetes,
        enrollment_token: 'stale-enroll-token',
        enrollment_expires_at: '2026-05-17T11:00:00Z',
        helm_command: 'helm upgrade --install identrail-agent identrail/agent --set token=stale-enroll-token'
      });
      await enrollment.promise;
    });

    expect(screen.queryByText('stale-enroll-token')).not.toBeInTheDocument();
    expect(screen.queryByText(/Enrollment token ready/i)).not.toBeInTheDocument();
    expect(
      getKubernetesProjectConnection.mock.calls.filter(([, projectID]) => projectID === 'production')
    ).toHaveLength(1);
  });

  it('does not prefill Kubernetes agent API URL from the cluster server', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: connectedKubernetes });

    const { ProductKubernetesConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/connect" element={<ProductKubernetesConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByDisplayValue('Production Kubernetes')).toBeInTheDocument();
    expect(screen.getByLabelText('API URL')).toHaveValue('');
    expect(screen.getByPlaceholderText('https://api.identrail.com')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('https://k8s.example.com')).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText('https://kubernetes.default.svc')).not.toBeInTheDocument();
  });

  it('preserves existing Kubernetes kubeconfig mode when loading the connection', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    const kubeconfigConnection: KubernetesConnectionStatus = {
      ...connectedKubernetes,
      connector_id: 'k8s-kubeconfig',
      display_name: 'Production fallback',
      context: 'production-admin',
      connection_mode: 'kubeconfig'
    };
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: kubeconfigConnection });
    vi.spyOn(api.apiClient, 'upsertKubernetesKubeconfigConnector').mockResolvedValue({ connection: kubeconfigConnection });
    const startKubernetesConnector = vi.spyOn(api.apiClient, 'startKubernetesConnector');

    const { ProductKubernetesConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/connect" element={<ProductKubernetesConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('button', { name: /Save kubeconfig/i })).toBeInTheDocument();
    expect(screen.getByLabelText('Mode')).toHaveValue('kubeconfig');
    expect(screen.getByLabelText('Display name')).toHaveValue('Production fallback');
    expect(screen.getByLabelText('Kubeconfig context')).toHaveValue('production-admin');
    expect(screen.queryByLabelText('API URL')).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Kubeconfig'), { target: { value: 'apiVersion: v1\nclusters: []' } });
    fireEvent.click(screen.getByRole('button', { name: /Save kubeconfig/i }));

    await waitFor(() =>
      expect(api.apiClient.upsertKubernetesKubeconfigConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          workspace_id: 'workspace-a',
          project_id: 'production',
          connector_id: 'k8s-kubeconfig',
          display_name: 'Production fallback',
          context: 'production-admin',
          kubeconfig: 'apiVersion: v1\nclusters: []'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(startKubernetesConnector).not.toHaveBeenCalled();
  });

  it('saves Kubernetes kubeconfig fallback with workspace and environment scope', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'production',
          name: 'Production',
          slug: 'production',
          description: 'Production Kubernetes boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({
      connection: { ...disconnectedKubernetes, connector_id: 'k8s-existing', context: 'old-context' }
    });
    vi.spyOn(api.apiClient, 'upsertKubernetesKubeconfigConnector').mockResolvedValue({ connection: connectedKubernetes });

    const { ProductKubernetesConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/kubernetes/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/kubernetes/connect" element={<ProductKubernetesConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('button', { name: /Generate token/i });
    fireEvent.change(screen.getByLabelText('Mode'), { target: { value: 'kubeconfig' } });
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Production fallback' } });
    fireEvent.change(screen.getByLabelText('Kubeconfig context'), { target: { value: 'production-admin' } });
    fireEvent.change(screen.getByLabelText('Kubeconfig'), { target: { value: 'apiVersion: v1\nclusters: []' } });
    fireEvent.click(screen.getByRole('button', { name: /Save kubeconfig/i }));

    await waitFor(() =>
      expect(api.apiClient.upsertKubernetesKubeconfigConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          workspace_id: 'workspace-a',
          project_id: 'production',
          connector_id: 'k8s-existing',
          display_name: 'Production fallback',
          context: 'production-admin',
          kubeconfig: 'apiVersion: v1\nclusters: []'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByText('Kubeconfig active.')).toBeInTheDocument();
  });

  it('clears stale AWS connect form values when the selected environment changes', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
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

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('production');
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      stagingStatus.resolve({
        connection: {
          ...disconnectedAWS,
          permission_checks: [],
          diagnostics: []
        }
      });
    });

    expect(await screen.findByRole('heading', { level: 3, name: /AWS read-only connector/i })).toBeInTheDocument();
    expect(screen.getByLabelText('Role ARN')).toHaveValue('');
    expect(screen.getByLabelText('Display name')).toHaveValue('');
    expect(screen.getByLabelText('Region')).toHaveValue('us-east-1');

    await act(async () => {
      productionStatus.resolve({ connection: connectedAWS });
    });
    expect(screen.getByLabelText('Role ARN')).toHaveValue('');
    expect(screen.queryByDisplayValue('Production AWS')).not.toBeInTheDocument();
  });

  it('ignores stale AWS CloudFormation start responses after switching environments', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
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
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: disconnectedAWS });
    const startResponse = deferred<AWSConnectorStartResponse>();
    vi.spyOn(api.apiClient, 'startAWSConnector').mockReturnValue(startResponse.promise);

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    const launchButton = await screen.findByRole('button', { name: /Launch stack/i });
    fireEvent.click(launchButton);
    await waitFor(() =>
      expect(api.apiClient.startAWSConnector).toHaveBeenCalledWith(
        expect.objectContaining({ project_id: 'production' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      startResponse.resolve({
        connection: connectedAWS,
        connector_id: 'aws-connector-1',
        external_id: 'stale-external-id',
        launch_url: 'https://console.aws.amazon.com/cloudformation',
        template_url: 'https://example.com/template.yaml',
        role_name: 'IdentrailReadOnly',
        stack_name: 'identrail-readonly-connector',
        policy_hash: 'sha256:example',
        permission_preview: [
          { service: 'IAM', actions: ['iam:GetRole'], resources: ['*'], reason: 'Inspect role metadata.' }
        ],
        permission_tiers: []
      });
    });

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('staging');
    expect(screen.getByLabelText('External ID')).toHaveValue('');
    expect(screen.queryByText(/AWS CloudFormation launch is ready/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Preview permissions/i })).not.toBeInTheDocument();
  });

  it('ignores stale AWS poll responses after switching environments', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
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
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ connection: projectID === 'production' ? connectedAWS : disconnectedAWS })
    );
    const pollResponse = deferred<{ connection: AWSConnectionStatus }>();
    vi.spyOn(api.apiClient, 'pollAWSConnector').mockReturnValue(pollResponse.promise);

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 3, name: /AWS read-only connector/i })).toBeInTheDocument();
    const refreshButton = within(screen.getByLabelText('AWS connector setup')).getByRole('button', {
      name: /Refresh status/i
    });
    fireEvent.click(refreshButton);
    await waitFor(() =>
      expect(api.apiClient.pollAWSConnector).toHaveBeenCalledWith(
        'aws-connector-1',
        'workspace-a',
        'production',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      pollResponse.resolve({
        connection: { ...connectedAWS, display_name: 'Production poll AWS', account_id: '111111111111' }
      });
    });

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('staging');
    expect(screen.queryByText('AWS connector is active.')).not.toBeInTheDocument();
    expect(screen.queryByText('Production poll AWS')).not.toBeInTheDocument();
  });

  it('ignores stale AWS validation responses after switching environments', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
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
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ connection: projectID === 'production' ? connectedAWS : disconnectedAWS })
    );
    const validationResponse = deferred<{ connection: AWSConnectionStatus }>();
    vi.spyOn(api.apiClient, 'validateAWSConnector').mockReturnValue(validationResponse.promise);

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    const submitButton = await screen.findByRole('button', { name: /Validate and save AWS/i });
    fireEvent.click(submitButton);
    await waitFor(() =>
      expect(api.apiClient.validateAWSConnector).toHaveBeenCalledWith(
        'aws-connector-1',
        expect.objectContaining({ project_id: 'production' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), { target: { value: 'staging' } });

    await act(async () => {
      validationResponse.resolve({
        connection: { ...connectedAWS, display_name: 'Validated production AWS', account_id: '111111111111' }
      });
    });

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('staging');
    expect(screen.queryByText('AWS connector is active.')).not.toBeInTheDocument();
    expect(screen.queryByText('Validated production AWS')).not.toBeInTheDocument();
  });

  it('loads AWS connect actions for the selected environment even when it is outside the first page', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    mockAWSBaseline(api);
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
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
    const getAWSProjectConnection = vi
      .spyOn(api.apiClient, 'getAWSProjectConnection')
      .mockResolvedValue({ connection: connectedAWS });

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=older-production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('older-production');
    expect(await screen.findByRole('heading', { level: 3, name: /AWS read-only connector/i })).toBeInTheDocument();
    // The connected-state primary CTA is the AWS overview link.
    expect(screen.getByRole('link', { name: /AWS overview/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws?environment=older-production'
    );
    // The page must still have fetched the AWS connection for the
    // requested environment (the engineering Setup payload / validation
    // harness / collector contract panels have been removed from the
    // customer UI but the connection fetch is unchanged).
    expect(listProjects).toHaveBeenCalled();
    expect(getAWSProjectConnection).toHaveBeenCalledWith(
      'workspace-a',
      'older-production',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('keeps requested environment selected when getProject check fails for a transient error', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
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
    vi.spyOn(api.apiClient, 'getProject').mockRejectedValue(new api.ApiError('temporary outage', 503));

    const { ProductDomainRoutePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/repositories?environment=older-production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/repositories" element={<ProductDomainRoutePage domain="github" routeID="repositories" />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('older-production');
    expect(screen.getByRole('link', { name: /Connect GitHub/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/github/connect?environment=older-production'
    );
    expect(await screen.findByText(/Unable to verify selected environment older-production/i)).toBeInTheDocument();
  });

  it('retries requested environment verification after transient getProject failures', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    const recentProjects = Array.from({ length: 50 }, (_, index) => ({
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: `recent-environment-${index + 1}`,
      name: `Recent Environment ${index + 1}`,
      slug: `recent-environment-${index + 1}`,
      description: '',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z'
    }));
    const olderProduction = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'older-production',
      name: 'Older Production',
      slug: 'older-production',
      description: 'Long-lived production boundary.',
      created_at: '2025-01-01T00:00:00Z',
      updated_at: '2025-01-02T00:00:00Z'
    };
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: recentProjects });
    const getProject = vi
      .spyOn(api.apiClient, 'getProject')
      .mockRejectedValueOnce(new api.ApiError('temporary outage', 503))
      .mockResolvedValueOnce({ project: olderProduction });

    const { ProductDomainRoutePage } = await import('./productShell');
    const renderRepositoriesPage = () =>
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

    const firstRender = renderRepositoriesPage();

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('older-production');
    expect(await screen.findByText(/Unable to verify selected environment older-production/i)).toBeInTheDocument();
    await waitFor(() => expect(getProject).toHaveBeenCalledTimes(1));
    firstRender.unmount();

    renderRepositoriesPage();

    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('older-production');
    await waitFor(() => expect(listProjects).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(getProject).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.queryByText(/Unable to verify selected environment older-production/i)).not.toBeInTheDocument()
    );
  });

  it('does not silently switch AWS connect to a fallback environment when getProject check fails transiently', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    mockAWSBaseline(api);
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'active-production',
          name: 'Active Production',
          slug: 'active-production',
          description: 'Active production boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getProject').mockRejectedValue(new api.ApiError('temporary outage', 503));
    const getAWSProjectConnection = vi
      .spyOn(api.apiClient, 'getAWSProjectConnection')
      .mockResolvedValue({ connection: disconnectedAWS });

    const { ProductAWSConnectPage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/connect?environment=older-production']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/aws/connect" element={<ProductAWSConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Connect AWS' })).toBeInTheDocument();
    expect(await screen.findByRole('combobox', { name: 'Environment' })).toHaveValue('older-production');
    expect(screen.getByText(/Unable to verify selected environment older-production/i)).toBeInTheDocument();
    expect(listProjects).toHaveBeenCalled();
    expect(getAWSProjectConnection).toHaveBeenCalledWith(
      'workspace-a',
      'older-production',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('falls back to an active environment when the requested environment is archived', async () => {
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [
        {
          tenant_id: 'tenant-a',
          workspace_id: 'workspace-a',
          project_id: 'active-production',
          name: 'Active Production',
          slug: 'active-production',
          description: 'Active production boundary.',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ]
    });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: 'archived-production',
        name: 'Archived Production',
        slug: 'archived-production',
        description: 'Retired boundary.',
        archived_at: '2026-01-03T00:00:00Z',
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2026-01-03T00:00:00Z'
      }
    });

    const { ProductDomainRoutePage } = await import('./productShell');

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/aws/identities?environment=archived-production']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/aws/identities"
            element={<ProductDomainRoutePage domain="aws" routeID="identities" />}
          />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('active-production'));
    expect(screen.getByRole('link', { name: /Connect AWS/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/connect?environment=active-production'
    );
    expect(screen.getByRole('link', { name: /AWS findings/i })).toHaveAttribute(
      'href',
      '/app/tenant-a/workspace-a/aws/findings?environment=active-production'
    );
  });

  it('creates a new unique environment key instead of overwriting an existing environment', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    const firstPageProjects = Array.from({ length: 50 }, (_, index) => ({
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: `recent-environment-${index + 1}`,
      name: `Recent Environment ${index + 1}`,
      slug: `recent-environment-${index + 1}`,
      description: '',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z'
    }));
    const existingProject = {
      tenant_id: 'tenant-a',
      workspace_id: 'workspace-a',
      project_id: 'production-platform',
      name: 'Production Platform',
      slug: 'production-platform',
      description: 'Existing production boundary.',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z'
    };
    vi.spyOn(api.apiClient, 'listProjects').mockImplementation(async (_workspaceID, filters: any) => {
      if (filters?.limit === 50) {
        return { items: firstPageProjects };
      }
      if (filters?.cursor === 'older-page') {
        return { items: [existingProject] };
      }
      return { items: firstPageProjects, next_cursor: 'older-page' };
    });
    vi.spyOn(api.apiClient, 'upsertProject').mockImplementation(async (_workspaceID, payload: any) => ({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: payload.project_id,
        name: payload.name,
        slug: payload.slug,
        description: payload.description ?? '',
        created_at: '2026-01-03T00:00:00Z',
        updated_at: '2026-01-03T00:00:00Z'
      }
    }));

    const { ProductProjectsPage } = await import('./productShell');
    function LocationProbe() {
      const location = useLocation();
      return <p data-testid="location">{`${location.pathname}${location.search}`}</p>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/projects?source=aws']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/projects"
            element={
              <>
                <LocationProbe />
                <ProductProjectsPage />
              </>
            }
          />
          <Route path="/app/:tenantID/:workspaceID/projects/:projectID" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Environments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Environment name/i), { target: { value: 'Production Platform' } });
    fireEvent.click(screen.getByRole('button', { name: /Create environment/i }));

    await waitFor(() =>
      expect(screen.getByTestId('location')).toHaveTextContent(
        '/app/tenant-a/workspace-a/projects/production-platform-2?source=aws'
      )
    );
    expect(api.apiClient.upsertProject).toHaveBeenCalledWith(
      'workspace-a',
      expect.objectContaining({ project_id: 'production-platform-2', slug: 'production-platform-2' }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
  });

  it('creates stable hidden keys for non-ASCII environment names', async () => {
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'upsertProject').mockImplementation(async (_workspaceID, payload: any) => ({
      project: {
        tenant_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: payload.project_id,
        name: payload.name,
        slug: payload.slug,
        description: payload.description ?? '',
        created_at: '2026-01-03T00:00:00Z',
        updated_at: '2026-01-03T00:00:00Z'
      }
    }));

    const { ProductProjectsPage } = await import('./productShell');
    function LocationProbe() {
      const location = useLocation();
      return <p data-testid="location">{`${location.pathname}${location.search}`}</p>;
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/projects?source=github']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/projects"
            element={
              <>
                <LocationProbe />
                <ProductProjectsPage />
              </>
            }
          />
          <Route path="/app/:tenantID/:workspaceID/projects/:projectID" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: 'Environments' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Environment name/i), { target: { value: '本番環境' } });
    fireEvent.click(screen.getByRole('button', { name: /Create environment/i }));

    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/projects/environment-'));
    const payload = (api.apiClient.upsertProject as any).mock.calls[0][1];
    expect(payload.project_id).toMatch(/^environment-[a-z0-9]+$/);
    expect(payload.project_id).not.toBe('default-environment');
  });

  it('opens nested GitHub AI risk routes from the sidebar domain flyout', async () => {
    mockConnectorFeatureFlags({ github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const { ProductShellLayout } = await import('./productShell');

    const { container } = render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/agentic-risk/mcp-tools']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductShellLayout />}>
            <Route path="github/agentic-risk/mcp-tools" element={<h2>MCP tools content</h2>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { level: 2, name: /MCP tools content/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'GitHub' }));

    const githubFlyout = screen.getByRole('dialog', { name: 'GitHub' });
    expect(within(githubFlyout).getAllByText('AI / Agentic Risk').length).toBeGreaterThan(0);
    expect(within(githubFlyout).getByRole('link', { name: 'GitHub AI / Agentic Risk MCP / tools' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(container.querySelector('details.idt-domain-flyout-nested')).toHaveAttribute('open');
  });
});


async function renderFindings(options: { repoScans?: RepoScanRecord[]; repoFindings?: Finding[] } = {}) {
  vi.resetModules();
  vi.doMock('./hooks/useMe', () => ({
    useMe: () => ({
      me: { ...loggedInWithoutWorkspace, role: 'owner' } as CurrentUserContext,
      loading: false,
      error: '',
      unauthenticated: false,
      refresh: vi.fn()
    })
  }));

  const api = await import('./api/client');
  const listRepoScans = vi
    .spyOn(api.apiClient, 'listRepoScans')
    .mockResolvedValue({ items: options.repoScans ?? [] });
  const listRepoFindings = vi
    .spyOn(api.apiClient, 'listRepoFindings')
    .mockImplementation(async (params) => {
      // Apply the server-side filters (severity/type) the component passes so
      // tests that exercise filtering observe a realistic empty result.
      let items = options.repoFindings ?? [];
      if (params?.severity) {
        items = items.filter((finding) => finding.severity === params.severity);
      }
      if (params?.type) {
        items = items.filter((finding) => finding.type === params.type);
      }
      return { items, summary: undefined };
    });
  vi.spyOn(api.apiClient, 'getRepoFindingsTrends').mockResolvedValue({ items: [] });
  vi.spyOn(api.apiClient, 'getRepoRiskGraph').mockRejectedValue(new Error('no graph'));

  const { ProductFindingsPage } = await import('./productShell');
  render(
    <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/findings']}>
      <Routes>
        <Route path="/app/:tenantID/:workspaceID/github/findings" element={<ProductFindingsPage />} />
      </Routes>
    </MemoryRouter>
  );

  return { listRepoScans, listRepoFindings };
}

describe('ProductFindingsPage states', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useMe');
    vi.resetModules();
  });

  it('shows a first-scan onboarding state when no scans have run', async () => {
    await renderFindings({ repoScans: [] });

    expect(await screen.findByText('Run your first repository scan')).toBeInTheDocument();
    // The zero-filled dashboard chrome must not render in the empty state.
    expect(screen.queryByText('Completed scans')).not.toBeInTheDocument();
  });

  it('surfaces a failure state instead of zeros when every scan failed', async () => {
    const failedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-failed',
      status: 'failed',
      finished_at: '2026-05-17T11:05:00Z',
      error_message: 'Repository not found or access revoked'
    };

    await renderFindings({ repoScans: [failedScan] });

    expect(await screen.findByText('Your last repository scan failed')).toBeInTheDocument();
    expect(screen.getByText(/Repository not found or access revoked/i)).toBeInTheDocument();
    expect(screen.queryByText('Completed scans')).not.toBeInTheDocument();
  });

  it('shows a clean "no exposure" state when a scan succeeded with zero findings', async () => {
    const succeededScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-succeeded',
      status: 'succeeded',
      finished_at: '2026-05-17T11:05:00Z',
      finding_count: 0
    };

    await renderFindings({ repoScans: [succeededScan] });

    expect(await screen.findByText('No exposure found')).toBeInTheDocument();
    // The consolidated KPI strip renders for a succeeded scan.
    expect(screen.getByText('Completed scans')).toBeInTheDocument();
    // With no findings and no active filters, the filter panel and the empty
    // detail pane are gated out (no redundant empty placeholders).
    expect(screen.queryByText('Filters and sorting')).not.toBeInTheDocument();
    expect(screen.queryByText('Select a finding')).not.toBeInTheDocument();
  });

  it('does not show failed state when a canceled scan is the latest', async () => {
    const failedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-failed-legacy',
      status: 'failed',
      finished_at: '2026-05-17T11:00:00Z',
      error_message: 'Repository not found or access revoked'
    };
    const canceledScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-canceled-latest',
      status: 'canceled',
      finished_at: '2026-05-17T11:05:00Z',
      error_message: 'User canceled scan from API'
    };

    await renderFindings({ repoScans: [canceledScan, failedScan] });

    expect(await screen.findByText('No completed scan results')).toBeInTheDocument();
    expect(screen.queryByText('Your last repository scan failed')).not.toBeInTheDocument();
  });

  it('shows "No completed scan results" while an active scan is still running', async () => {
    const failedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-failed-in-flight',
      status: 'failed',
      finished_at: '2026-05-17T11:03:00Z',
      error_message: 'Repository access revoked'
    };
    const queuedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-queued-in-flight',
      status: 'queued',
      finished_at: undefined
    };

    await renderFindings({ repoScans: [queuedScan, failedScan] });

    expect(await screen.findByText('No completed scan results')).toBeInTheDocument();
    expect(screen.queryByText('No exposure found')).not.toBeInTheDocument();
    expect(screen.queryByText('Your last repository scan failed')).not.toBeInTheDocument();
  });

  it('keeps findings visible when failed scans still return historical findings', async () => {
    const failedScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-failed-latest',
      status: 'failed',
      started_at: '2026-05-17T12:00:00Z',
      finished_at: '2026-05-17T12:01:00Z',
      error_message: 'Repository not found or access revoked'
    };
    const oldSucceededScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-succeeded-older',
      status: 'succeeded',
      started_at: '2026-05-17T11:00:00Z',
      finished_at: '2026-05-17T11:30:00Z',
      finding_count: 2
    };
    const historicFinding: Finding = {
      id: 'finding-legacy',
      scan_id: 'repo-scan-succeeded-older',
      type: 'secrets',
      severity: 'high',
      title: 'Legacy finding',
      human_summary: 'Legacy risky secret exposure',
      remediation: 'Rotate and clean up repository secret.',
      created_at: '2026-05-17T11:10:00Z'
    };

    await renderFindings({
      repoScans: [failedScan, oldSucceededScan],
      repoFindings: [historicFinding]
    });

    expect(screen.queryByText('Your last repository scan failed')).not.toBeInTheDocument();
    expect(await screen.findByText('Completed scans')).toBeInTheDocument();
    expect(await screen.findByText('Legacy finding')).toBeInTheDocument();
  });

  it('does not report cancellation as a failed scan', async () => {
    const canceledScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-canceled',
      status: 'canceled',
      finished_at: '2026-05-17T11:09:00Z',
      error_message: 'User canceled scan from API'
    };

    await renderFindings({ repoScans: [canceledScan] });

    expect(await screen.findByText('No completed scan results')).toBeInTheDocument();
    expect(screen.queryByText('Your last repository scan failed')).not.toBeInTheDocument();
  });

  it('restores focus to the triggering row when the finding detail dialog closes', async () => {
    const scan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-with-findings',
      status: 'succeeded',
      finished_at: '2026-05-17T11:06:00Z',
      finding_count: 1
    };

    const finding: Finding = {
      id: 'finding-1',
      scan_id: scan.id,
      type: 'aws_access_key',
      severity: 'critical',
      title: 'IAM role with wildcard trust',
      human_summary: 'AssumeRole trust policy allows any principal.',
      remediation: 'Tighten trust policy principals.',
      source_url: 'https://github.com/identrail/identrail/blob/main/policy.tf#L7',
      line_snippet: '@@ -1 +1 @@\n+ allow = true\n- allow = false',
      created_at: '2026-05-17T11:06:00Z'
    };

    await renderFindings({ repoScans: [scan], repoFindings: [finding] });

    const rowButton = (await screen.findAllByRole('listitem')).find((node) =>
      node.textContent?.includes('IAM role with wildcard trust')
    ) as HTMLButtonElement | undefined;
    expect(rowButton).toBeDefined();
    if (!rowButton) return;
    rowButton.focus();
    fireEvent.click(rowButton);

    const addedLine = await screen.findByText((_, element) =>
      Boolean(element?.classList.contains('idt-repo-finding-code-line') && element.textContent === '+ allow = true')
    );
    const removedLine = await screen.findByText((_, element) =>
      Boolean(element?.classList.contains('idt-repo-finding-code-line') && element.textContent === '- allow = false')
    );
    expect(screen.getByText('Evidence line')).toHaveClass('idt-repo-finding-code-label');
    expect(screen.getByText('@@ -1 +1 @@')).toHaveClass('idt-repo-finding-code-line');
    expect(addedLine).toHaveClass('idt-repo-finding-code-line', 'is-add');
    expect(removedLine).toHaveClass('idt-repo-finding-code-line', 'is-remove');
    expect(addedLine).not.toHaveClass('idt-repo-finding-code-label');
    expect(removedLine).not.toHaveClass('idt-repo-finding-code-label');
    expect(within(addedLine).getByText('+')).toHaveClass('idt-repo-finding-code-marker');
    expect(within(removedLine).getByText('-')).toHaveClass('idt-repo-finding-code-marker');

    const closeButton = await screen.findByRole('button', { name: /Close finding detail/i });
    fireEvent.click(closeButton);

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /Close finding detail/i })).not.toBeInTheDocument();
    });
    await waitFor(() => {
      expect(document.activeElement).toBe(rowButton);
    });
  });

  it('does not mark ordinary source lines that start with plus or dash prefixes as diffs', async () => {
    const scan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-with-yaml-source',
      status: 'succeeded',
      finished_at: '2026-05-17T11:06:00Z',
      finding_count: 1
    };

    const finding: Finding = {
      id: 'finding-yaml-list',
      scan_id: scan.id,
      type: 'workflow_permission',
      severity: 'medium',
      title: 'Workflow grants broad permissions',
      human_summary: 'A workflow permission entry needs review.',
      remediation: 'Limit workflow permissions.',
      source_url: 'https://github.com/identrail/identrail/blob/main/workflow.yml#L12',
      line_snippet: '+enabled\n- name: prod',
      created_at: '2026-05-17T11:06:00Z'
    };

    await renderFindings({ repoScans: [scan], repoFindings: [finding] });

    const rowButton = (await screen.findAllByRole('listitem')).find((node) =>
      node.textContent?.includes('Workflow grants broad permissions')
    ) as HTMLButtonElement | undefined;
    expect(rowButton).toBeDefined();
    if (!rowButton) return;
    fireEvent.click(rowButton);

    const plusSourceLine = await screen.findByText((_, element) =>
      Boolean(element?.classList.contains('idt-repo-finding-code-line') && element.textContent === '+enabled')
    );
    const yamlSourceLine = await screen.findByText((_, element) =>
      Boolean(element?.classList.contains('idt-repo-finding-code-line') && element.textContent === '- name: prod')
    );
    expect(plusSourceLine).not.toHaveClass('is-add');
    expect(yamlSourceLine).not.toHaveClass('is-remove');
    expect(plusSourceLine.querySelector('.idt-repo-finding-code-marker')).toBeNull();
    expect(yamlSourceLine.querySelector('.idt-repo-finding-code-marker')).toBeNull();
  });

  it('marks one-sided repository diff hunks as changed lines', async () => {
    const scan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-with-one-sided-diff',
      status: 'succeeded',
      finished_at: '2026-05-17T11:06:00Z',
      finding_count: 2
    };

    const additionFinding: Finding = {
      id: 'finding-add-only-diff',
      scan_id: scan.id,
      type: 'workflow_permission',
      severity: 'medium',
      title: 'Workflow adds broad permissions',
      human_summary: 'A workflow permission entry was added.',
      remediation: 'Limit workflow permissions.',
      source_url: 'https://github.com/identrail/identrail/blob/main/workflow.yml#L12',
      line_snippet: [
        'diff --git a/workflow.yml b/workflow.yml',
        'new file mode 100644',
        'index 0000000..1111111',
        '--- /dev/null',
        '+++ b/workflow.yml',
        '@@ -0,0 +1 @@',
        '+++count'
      ].join('\n'),
      created_at: '2026-05-17T11:06:00Z'
    };
    const removalFinding: Finding = {
      ...additionFinding,
      id: 'finding-remove-only-diff',
      title: 'Workflow removes guardrail',
      human_summary: 'A workflow guardrail was removed.',
      line_snippet: '@@ -1 +0,0 @@\n---count'
    };

    await renderFindings({ repoScans: [scan], repoFindings: [additionFinding, removalFinding] });

    const addRow = (await screen.findAllByRole('listitem')).find((node) =>
      node.textContent?.includes('Workflow adds broad permissions')
    ) as HTMLButtonElement | undefined;
    expect(addRow).toBeDefined();
    if (!addRow) return;
    fireEvent.click(addRow);

    const addedLine = await screen.findByText((_, element) =>
      Boolean(element?.classList.contains('idt-repo-finding-code-line') && element.textContent === '+++count')
    );
    expect(addedLine).toHaveClass('is-add');
    expect(within(addedLine).getByText('+')).toHaveClass('idt-repo-finding-code-marker');

    fireEvent.click(await screen.findByRole('button', { name: /Close finding detail/i }));
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /Close finding detail/i })).not.toBeInTheDocument();
    });

    const removeRow = (await screen.findAllByRole('listitem')).find((node) =>
      node.textContent?.includes('Workflow removes guardrail')
    ) as HTMLButtonElement | undefined;
    expect(removeRow).toBeDefined();
    if (!removeRow) return;
    fireEvent.click(removeRow);

    const removedLine = await screen.findByText((_, element) =>
      Boolean(element?.classList.contains('idt-repo-finding-code-line') && element.textContent === '---count')
    );
    expect(removedLine).toHaveClass('is-remove');
    expect(within(removedLine).getByText('-')).toHaveClass('idt-repo-finding-code-marker');
  });

  it('keeps visible filters when active filters match no findings', async () => {
    const scan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-with-findings',
      status: 'succeeded',
      finished_at: '2026-05-17T11:06:00Z',
      finding_count: 1
    };

    const finding: Finding = {
      id: 'finding-1',
      scan_id: scan.id,
      type: 'aws_access_key',
      severity: 'critical',
      title: 'IAM role with wildcard trust',
      human_summary: 'AssumeRole trust policy allows any principal.',
      remediation: 'Tighten trust policy principals.',
      created_at: '2026-05-17T11:06:00Z'
    };

    await renderFindings({
      repoScans: [scan],
      repoFindings: [finding]
    });

    expect((await screen.findAllByText('IAM role with wildcard trust')).length).toBeGreaterThan(0);

    expect(await screen.findByText('Filters and sorting')).toBeInTheDocument();

    const severityFilter = screen.getByLabelText('Severity');
    fireEvent.change(severityFilter, { target: { value: 'high' } });

    expect(await screen.findByRole('heading', { name: 'No findings match these filters' })).toBeInTheDocument();
    expect(screen.getByLabelText('Repository finding filters and sorting')).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: /IAM role with wildcard trust/i })).not.toBeInTheDocument();
  });
});

describe('GitHub domain pages (#1382)', () => {
  const productionProject = {
    tenant_id: 'tenant-a',
    workspace_id: 'workspace-a',
    project_id: 'production-platform',
    name: 'Production Platform',
    slug: 'production-platform',
    description: 'Production identity boundary.',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-02T00:00:00Z'
  };

  const succeededRepoScan: RepoScanRecord = {
    id: 'repo-scan-succeeded',
    repository: 'identrail/identrail',
    status: 'succeeded',
    started_at: '2026-05-17T10:50:00Z',
    finished_at: '2026-05-17T10:55:00Z',
    commits_scanned: 12,
    files_scanned: 340,
    finding_count: 3,
    truncated: false,
    scan_mode: 'quick'
  };

  const defaultScanPolicy: ScanPolicyRecord = {
    tenant_id: 'tenant-a',
    workspace_id: 'workspace-a',
    project_id: 'production-platform',
    policy_id: 'default',
    name: 'Default policy',
    enabled: true,
    trigger_mode: 'event',
    max_concurrent_scans: 1,
    history_limit: 500,
    max_findings: 200,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-02T00:00:00Z'
  };

  const defaultRepositoryPosture: GitHubRepositoryPosture = {
    repository: 'identrail/identrail',
    installation_id: 12345,
    collected_at: '2026-05-17T10:55:00Z',
    rate_limit: { limit: 5000, remaining: 4990 },
    checks: [
      {
        id: 'branch-protection',
        category: 'branch protection',
        state: 'insecure',
        reason: 'missing_required_reviews',
        summary: 'Default branch is missing required pull request reviews.'
      },
      {
        id: 'secret-scanning',
        category: 'security',
        state: 'secure',
        summary: 'Secret scanning is enabled.'
      }
    ]
  };

  const defaultOrganizationPosture: GitHubOrganizationPosture = {
    organization: 'identrail',
    installation_id: 12345,
    collected_at: '2026-05-17T10:56:00Z',
    checks: [
      {
        id: 'org-two-factor',
        category: 'organization security',
        state: 'secure',
        summary: 'Organization two-factor authentication is enforced.'
      }
    ]
  };

  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.resetModules();
  });

  async function renderGitHubPage(
    pageName: 'control-center' | 'connect' | 'repositories' | 'actions' | 'remediation',
    options: {
      githubConnection?: GitHubConnectionStatus | null;
      scans?: RepoScanRecord[];
      scanPolicies?: ScanPolicyRecord[];
      repositoryPosture?: GitHubRepositoryPosture;
      organizationPosture?: GitHubOrganizationPosture;
      repoFindings?: Finding[];
      remediationPreview?: RepoFindingRemediationPreview;
      remediationPublish?: RepoFindingRemediationPublishResponse;
      listRepoScans?: () => Promise<{ items: RepoScanRecord[]; next_cursor?: string }>;
      githubFeatureFlag?: boolean;
      githubBackend?: BackendFeatureState;
      runRepoScanError?: { message: string; status: number };
      cancelRepoScanError?: { message: string; status: number };
      initialEntry?: string;
      projects?: Array<typeof productionProject>;
    } = {}
  ) {
    mockConnectorFeatureFlags({ aws: false, github: options.githubFeatureFlag ?? true, kubernetes: false });
    mockBackendFeatures({ github: options.githubBackend ?? true });

    const api = await import('./api/client');
    const projects = options.projects ?? [productionProject];
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: projects });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projects.find((project) => project.project_id === projectID) ?? projects[0] ?? productionProject })
    );
    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValue({ connection: options.githubConnection ?? connectedGitHub });
    const listRepoScans = vi.spyOn(api.apiClient, 'listRepoScans');
    if (options.listRepoScans) {
      listRepoScans.mockImplementation(() => options.listRepoScans?.() ?? Promise.resolve({ items: [] }));
    } else {
      listRepoScans.mockResolvedValue({ items: options.scans ?? [] });
    }
    const listProjectScanPolicies = vi
      .spyOn(api.apiClient, 'listProjectScanPolicies')
      .mockResolvedValue({ items: options.scanPolicies ?? [] });
    const upsertProjectScanPolicy = vi
      .spyOn(api.apiClient, 'upsertProjectScanPolicy')
      .mockResolvedValue({ policy: options.scanPolicies?.[0] ?? defaultScanPolicy });
    const deleteProjectScanPolicy = vi.spyOn(api.apiClient, 'deleteProjectScanPolicy').mockResolvedValue(undefined);
    const getGitHubConnectorRepositoryPosture = vi
      .spyOn(api.apiClient, 'getGitHubConnectorRepositoryPosture')
      .mockResolvedValue({
        connector_id: 'github-app',
        provider: 'github_app',
        posture: options.repositoryPosture ?? defaultRepositoryPosture,
        organization_posture: options.organizationPosture ?? defaultOrganizationPosture
      });
    const listRepoFindings = vi
      .spyOn(api.apiClient, 'listRepoFindings')
      .mockResolvedValue({ items: options.repoFindings ?? [], summary: undefined });
    const previewRepoFindingRemediation = vi
      .spyOn(api.apiClient, 'previewRepoFindingRemediation')
      .mockResolvedValue(
        options.remediationPreview ?? {
          finding: options.repoFindings?.[0] ?? {
            id: 'finding-default',
            scan_id: 'repo-scan-default',
            type: 'secret_exposure',
            severity: 'high',
            title: 'Default remediation finding',
            human_summary: 'Default remediation finding summary.',
            remediation: 'Rotate and remove the exposed secret.',
            created_at: '2026-05-17T11:00:00Z'
          },
          remediation: {
            detector: 'secret_exposure',
            summary: 'Rotate and remove the exposed secret',
            risk_summary: 'The exposed credential can be replayed outside GitHub.',
            steps: ['Rotate the exposed credential', 'Remove the committed value'],
            safety_notes: ['Confirm the replacement secret is available before merging'],
            validation: ['Run the repository scan again'],
            secret_rotation: true,
            publishable: true,
            evidence: { finding_id: 'finding-default', scan_id: 'repo-scan-default' }
          },
          fix_pr_plan: {
            base_branch: 'main',
            branch_name: 'identrail/fix/finding-default',
            commit_message: 'Remove exposed secret',
            pr_title: 'Remove exposed secret',
            pr_body: 'Remediates the exposed repository secret.',
            files: [{ path: '.github/workflows/deploy.yml', content: 'env: {}' }],
            finding_id: 'finding-default',
            finding_type: 'secret_exposure'
          }
        }
      );
    const publishRepoFindingRemediation = vi
      .spyOn(api.apiClient, 'publishRepoFindingRemediation')
      .mockResolvedValue(
        options.remediationPublish ?? {
          finding: options.repoFindings?.[0] ?? {
            id: 'finding-default',
            scan_id: 'repo-scan-default',
            type: 'secret_exposure',
            severity: 'high',
            title: 'Default remediation finding',
            human_summary: 'Default remediation finding summary.',
            remediation: 'Rotate and remove the exposed secret.',
            created_at: '2026-05-17T11:00:00Z'
          },
          remediation: {
            detector: 'secret_exposure',
            summary: 'Rotate and remove the exposed secret',
            risk_summary: 'The exposed credential can be replayed outside GitHub.',
            steps: ['Rotate the exposed credential'],
            safety_notes: ['Confirm the replacement secret is available before merging'],
            validation: ['Run the repository scan again'],
            secret_rotation: true,
            publishable: true,
            evidence: { finding_id: 'finding-default', scan_id: 'repo-scan-default' }
          },
          publish: {
            pr_number: 42,
            pr_url: 'https://github.com/identrail/identrail/pull/42',
            branch_name: 'identrail/fix/finding-default',
            commit_sha: 'abc1234'
          }
        }
      );
    const runRepoScan = vi.spyOn(api.apiClient, 'runRepoScan');
    if (options.runRepoScanError) {
      runRepoScan.mockRejectedValue(new api.ApiError(options.runRepoScanError.message, options.runRepoScanError.status));
    } else {
      runRepoScan.mockResolvedValue({ repo_scan: queuedRepoScan });
    }
    const cancelRepoScan = vi.spyOn(api.apiClient, 'cancelRepoScan');
    if (options.cancelRepoScanError) {
      cancelRepoScan.mockRejectedValue(
        new api.ApiError(options.cancelRepoScanError.message, options.cancelRepoScanError.status)
      );
    } else {
      cancelRepoScan.mockResolvedValue({ repo_scan: canceledRepoScan });
    }
    const startGitHubConnector = vi.spyOn(api.apiClient, 'startGitHubConnector').mockResolvedValue({
      connection: {
        provider: 'github_app',
        connected: false,
        connector_id: 'github-app',
        display_name: 'Identrail',
        status: 'pending',
        health_status: 'unknown',
        webhook_secret_rotation_required: false,
        selected_repositories: []
      },
      connector_id: 'github-app',
      state: 'github-state',
      install_url: 'https://github.com/apps/identrail/installations/select_target?state=github-state',
      install_account_type: 'any',
      webhook_url: '/auth/webhooks/github',
      expires_at: '2026-05-17T10:10:00Z'
    });
    const upsertGitHubPATConnector = vi
      .spyOn(api.apiClient, 'upsertGitHubPATConnector')
      .mockResolvedValue({ connection: connectedGitHubPAT });

    const productShell = await import('./productShell');
    const page =
      pageName === 'control-center' ? <productShell.ProductGitHubControlCenterPage /> :
      pageName === 'connect' ? <productShell.ProductGitHubConnectPage /> :
      pageName === 'repositories' ? <productShell.ProductGitHubRepositoriesPage /> :
      pageName === 'remediation' ? <productShell.ProductGitHubRemediationPage /> :
      <productShell.ProductGitHubActionsPage />;

    const routePath =
      pageName === 'control-center' ? 'github' :
      pageName === 'connect' ? 'github/connect' :
      pageName === 'repositories' ? 'github/repositories' :
      pageName === 'remediation' ? 'github/remediation' :
      'github/actions';

    render(
      <MemoryRouter initialEntries={[options.initialEntry ?? `/app/tenant-a/workspace-a/${routePath}`]}>
        <Routes>
          <Route path={`/app/:tenantID/:workspaceID/${routePath}`} element={page} />
        </Routes>
      </MemoryRouter>
    );

    return {
      getGitHubConnectorStatus,
      listRepoScans,
      listRepoFindings,
      previewRepoFindingRemediation,
      publishRepoFindingRemediation,
      runRepoScan,
      cancelRepoScan,
      startGitHubConnector,
      listProjectScanPolicies,
      upsertProjectScanPolicy,
      deleteProjectScanPolicy,
      upsertGitHubPATConnector,
      getGitHubConnectorRepositoryPosture
    };
  }

  it('Control Center loads the GitHub connection and surfaces connection status', async () => {
    const mocks = await renderGitHubPage('control-center', { scans: [succeededRepoScan] });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await waitFor(() => expect(mocks.getGitHubConnectorStatus).toHaveBeenCalledWith(
      'workspace-a',
      'production-platform',
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    ));
    await screen.findByText(/Installation 12345/i);
    await waitFor(() => {
      const repos = screen
        .getAllByRole('link', { name: /^Repositories$/ })
        .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/repositories'));
      expect(repos).toBeDefined();
    });
    expect(screen.getByRole('heading', { level: 3, name: 'Recent scans' })).toBeInTheDocument();
    await waitFor(() =>
      expect(mocks.listRepoScans).toHaveBeenCalledWith(
        expect.objectContaining({ limit: 50, sort_by: 'started_at', sort_order: 'desc' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('Control Center clears cached dashboard data when the auth session resets', async () => {
    const firstRender = await renderGitHubPage('control-center', { scans: [succeededRepoScan] });

    await screen.findByText(/Installation 12345/i);
    await waitFor(() => expect(firstRender.listRepoScans).toHaveBeenCalledTimes(1));
    cleanup();
    vi.restoreAllMocks();

    const productShell = await import('./productShell');
    productShell.clearProductAuthSessionCacheForTests();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    const nextSessionStatus = deferred<{ connection: GitHubConnectionStatus }>();
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockReturnValue(nextSessionStatus.promise);
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github" element={<productShell.ProductGitHubControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    expect(screen.queryByText(/Installation 12345/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Loading GitHub status/i)).not.toBeInTheDocument();

    await act(async () => {
      nextSessionStatus.resolve({
        connection: {
          ...connectedGitHub,
          installation_id: 67890,
          selected_repositories: []
        }
      });
    });

    expect(await screen.findByText(/Installation 67890/i)).toBeInTheDocument();
  });

  it('Control Center fetches additional scan pages until selected-repository activity is available', async () => {
    const unrelatedRepoScans: RepoScanRecord[] = Array.from({ length: 3 }).map((_, index) => ({
      ...succeededRepoScan,
      id: `repo-scan-control-center-unrelated-${index}`,
      repository: `team-${index + 1}/unrelated`
    }));
    const selectedRepoScan: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-control-center-selected',
      repository: 'identrail/identrail',
      started_at: '2026-05-18T10:00:00Z',
      finished_at: '2026-05-18T10:05:00Z',
      finding_count: 2,
      files_scanned: 17
    };

    let pageCalls = 0;
    const mocks = await renderGitHubPage('control-center', {
      listRepoScans: () => {
        pageCalls += 1;
        if (pageCalls === 1) {
          return Promise.resolve({
            items: unrelatedRepoScans,
            next_cursor: 'repo-page-2'
          });
        }
        return Promise.resolve({
          items: [selectedRepoScan]
        });
      }
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await waitFor(() => expect(mocks.listRepoScans).toHaveBeenCalledTimes(2));
    expect(mocks.listRepoScans).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ cursor: 'repo-page-2', limit: 50 }),
      expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
    );
    expect(screen.getByRole('heading', { level: 3, name: 'Recent scans' })).toBeInTheDocument();
    expect(screen.getByText(/identrail\/identrail/i)).toBeInTheDocument();
  });

  it('Control Center prompts to connect when not connected', async () => {
    await renderGitHubPage('control-center', {
      githubConnection: {
        ...connectedGitHub,
        connected: false,
        account_login: undefined,
        installation_id: undefined,
        selected_repositories: []
      },
      scans: []
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByText(/Not connected for this environment\./i);
    await waitFor(() => {
      const heroConnect = screen
        .getAllByRole('link', { name: /Connect GitHub/i })
        .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/connect'));
      expect(heroConnect).toBeDefined();
    });
  });

  it('Control Center does not flash a disconnected state while the connection is still loading', async () => {
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    let resolveStatus: ((value: { connection: GitHubConnectionStatus }) => void) | undefined;
    const pendingStatus = new Promise<{ connection: GitHubConnectionStatus }>((resolve) => {
      resolveStatus = resolve;
    });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockReturnValue(pendingStatus);
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });

    const productShell = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github" element={<productShell.ProductGitHubControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    // While loading, the page must not claim the user is disconnected.
    expect(screen.queryByText(/Not connected for this environment\./i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText('GitHub action recommendation')).not.toBeInTheDocument();
    // The primary CTA in the header is omitted during the initial load —
    // the Sections grid still renders its own "Connect GitHub" navigation
    // card, which is fine.
    expect(document.querySelector('.idt-domain-header-actions')).toBeNull();
    expect(screen.queryByText(/Loading GitHub status/i)).not.toBeInTheDocument();

    // Resolve as disconnected; the page should now show the real disconnected UI.
    resolveStatus?.({
      connection: {
        ...connectedGitHub,
        connected: false,
        account_login: undefined,
        installation_id: undefined,
        selected_repositories: []
      }
    });
    await screen.findByText(/Not connected for this environment\./i);
    await waitFor(() => {
      const banner = screen.getByLabelText('GitHub action recommendation');
      expect(banner).toHaveAttribute('data-banner-id', 'connect');
    });
  });

  it('Control Center shows the unavailable shell when the GitHub connector is gated off', async () => {
    await renderGitHubPage('control-center', { githubFeatureFlag: false, githubBackend: false });

    await screen.findByRole('heading', { level: 2, name: 'GitHub Control Center' });
    await screen.findByRole('heading', { level: 3, name: /GitHub is not available on this API/i });
  });

  it('Connect page calls startGitHubConnector and opens the install URL', async () => {
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    const mocks = await renderGitHubPage('connect', {
      githubConnection: {
        ...connectedGitHub,
        connected: false,
        account_login: undefined,
        installation_id: undefined,
        selected_repositories: []
      }
    });

    const installButton = (await screen.findAllByRole('button', { name: 'Install GitHub App' }))[0];
    fireEvent.click(installButton);

    await waitFor(() =>
      expect(mocks.startGitHubConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          project_id: 'production-platform',
          install_account_type: 'any',
          redirect_uri: expect.stringMatching(/\/app\/github\/callback$/)
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await waitFor(() =>
      expect(openSpy).toHaveBeenCalledWith(
        'https://github.com/apps/identrail/installations/select_target?state=github-state',
        '_blank',
        'noopener,noreferrer'
      )
    );

    // Enterprise/PAT management now lives inline on the connect page (the
    // legacy per-project page was retired); the control opens the fallback form.
    const enterpriseButtons = screen.getAllByRole('button', { name: /Manage Enterprise \/ PAT/i });
    expect(enterpriseButtons.length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /Save enterprise fallback/i })).toBeInTheDocument();
    openSpy.mockRestore();
  });

  it('Connect page ignores stale GitHub App install starts after environment changes', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const installStart = deferred<{
      connection: GitHubConnectionStatus;
      connector_id: string;
      state: string;
      install_url: string;
      install_account_type: 'any';
      webhook_url: string;
      expires_at: string;
    }>();

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({
      connection: {
        ...connectedGitHub,
        connected: false,
        account_login: undefined,
        installation_id: undefined,
        selected_repositories: []
      }
    });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockResolvedValue({ items: [] });
    const startGitHubConnector = vi
      .spyOn(api.apiClient, 'startGitHubConnector')
      .mockImplementation(() => installStart.promise);

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    fireEvent.click((await screen.findAllByRole('button', { name: 'Install GitHub App' }))[0]);
    await waitFor(() =>
      expect(startGitHubConnector).toHaveBeenCalledWith(
        expect.objectContaining({ project_id: 'production-platform' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('staging-platform'));

    await act(async () => {
      installStart.resolve({
        connection: connectedGitHub,
        connector_id: 'github-app',
        state: 'production-state',
        install_url: 'https://github.com/apps/identrail/installations/select_target?state=production-state',
        install_account_type: 'any',
        webhook_url: '/auth/webhooks/github',
        expires_at: '2026-05-17T10:10:00Z'
      });
    });

    expect(openSpy).not.toHaveBeenCalled();
    expect(screen.queryByRole('link', { name: 'Open GitHub' })).not.toBeInTheDocument();
    expect(screen.queryByText(/production-state/i)).not.toBeInTheDocument();
    openSpy.mockRestore();
  });

  it('Connect page resets Enterprise PAT drafts when environments change before submit', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockResolvedValue({ items: [] });
    const upsertGitHubPATConnector = vi
      .spyOn(api.apiClient, 'upsertGitHubPATConnector')
      .mockResolvedValue({ connection: connectedGitHubPAT });

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    fireEvent.click((await screen.findAllByRole('button', { name: /Manage Enterprise \/ PAT/i }))[0]);
    fireEvent.change(await screen.findByLabelText(/Enterprise base URL/i), {
      target: { value: 'https://github.production.example' }
    });
    fireEvent.change(screen.getByLabelText(/Display name/i), { target: { value: 'Production GHES' } });
    fireEvent.change(screen.getByLabelText(/Personal access token/i), { target: { value: 'production-token' } });
    fireEvent.change(screen.getByLabelText(/Repository allowlist/i), { target: { value: 'prod/repo' } });

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });

    await waitFor(() => expect(screen.getByLabelText(/Personal access token/i)).toHaveValue(''));
    expect(screen.getByLabelText(/Enterprise base URL/i)).toHaveValue('');
    expect(screen.getByLabelText(/Display name/i)).toHaveValue('');
    expect(screen.getByLabelText(/Repository allowlist/i)).toHaveValue('');

    fireEvent.click(screen.getByRole('button', { name: /Save enterprise fallback/i }));

    expect(upsertGitHubPATConnector).not.toHaveBeenCalled();
  });

  it('Connect page ignores stale Enterprise PAT saves after environment changes', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const patSave = deferred<{ connection: GitHubConnectionStatus }>();

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockResolvedValue({ items: [] });
    const upsertGitHubPATConnector = vi
      .spyOn(api.apiClient, 'upsertGitHubPATConnector')
      .mockImplementation(() => patSave.promise);

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    fireEvent.click((await screen.findAllByRole('button', { name: /Manage Enterprise \/ PAT/i }))[0]);
    fireEvent.change(await screen.findByLabelText(/Enterprise base URL/i), {
      target: { value: 'https://github.production.example' }
    });
    fireEvent.change(screen.getByLabelText(/Display name/i), { target: { value: 'Production GHES' } });
    fireEvent.change(screen.getByLabelText(/Personal access token/i), { target: { value: 'production-token' } });
    fireEvent.change(screen.getByLabelText(/Repository allowlist/i), { target: { value: 'prod/repo' } });
    fireEvent.click(screen.getByRole('button', { name: /Save enterprise fallback/i }));

    await waitFor(() =>
      expect(upsertGitHubPATConnector).toHaveBeenCalledWith(
        expect.objectContaining({
          project_id: 'production-platform',
          base_url: 'https://github.production.example',
          token: 'production-token',
          selected_repositories: ['prod/repo']
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });
    await waitFor(() => expect(screen.getByLabelText(/Personal access token/i)).toHaveValue(''));

    await act(async () => {
      patSave.resolve({ connection: connectedGitHubPAT });
    });

    expect(screen.queryByText(/GitHub Enterprise connector validated and saved/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/Personal access token/i)).toHaveValue('');
  });

  it('Repositories page launches a scan via the existing API', async () => {
    const mocks = await renderGitHubPage('repositories', { scans: [] });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const queueButton = await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' });
    fireEvent.click(queueButton);

    await waitFor(() =>
      expect(mocks.runRepoScan).toHaveBeenCalledWith(
        expect.objectContaining({
          repository: 'identrail/identrail',
          project_id: 'production-platform',
          connector_id: 'github-app'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await screen.findByText(/Repository scan queued for identrail\/identrail/i);
  });

  it('Repositories page runs one-off scans with explicit limits when no repositories are selected', async () => {
    const mocks = await renderGitHubPage('repositories', {
      githubConnection: { ...connectedGitHubPAT, selected_repositories: [] },
      scans: []
    });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const oneOffPanel = await screen.findByRole('region', { name: 'One-off repository scan' });
    fireEvent.change(within(oneOffPanel).getByLabelText(/^Repository$/i), { target: { value: 'acme/private-repo' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/Scan mode/i), { target: { value: 'quick' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/History limit/i), { target: { value: '75' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/Max findings/i), { target: { value: '25' } });
    fireEvent.click(within(oneOffPanel).getByRole('button', { name: /Run scan/i }));

    await waitFor(() =>
      expect(mocks.runRepoScan).toHaveBeenCalledWith(
        expect.objectContaining({
          repository: 'acme/private-repo',
          scan_mode: 'quick',
          history_limit: 75,
          max_findings: 25
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(mocks.runRepoScan.mock.calls[0][0]).not.toHaveProperty('project_id');
    expect(mocks.runRepoScan.mock.calls[0][0]).not.toHaveProperty('connector_id');
    await screen.findByText(/Repository scan queued for acme\/private-repo/i);
  });

  it('Repositories page scopes one-off scans to the GitHub App connector when available', async () => {
    const mocks = await renderGitHubPage('repositories', { scans: [] });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const oneOffPanel = await screen.findByRole('region', { name: 'One-off repository scan' });
    fireEvent.change(within(oneOffPanel).getByLabelText(/^Repository$/i), { target: { value: 'identrail/identrail' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/History limit/i), { target: { value: '125' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/Max findings/i), { target: { value: '50' } });
    fireEvent.click(within(oneOffPanel).getByRole('button', { name: /Run scan/i }));

    await waitFor(() =>
      expect(mocks.runRepoScan).toHaveBeenCalledWith(
        expect.objectContaining({
          repository: 'identrail/identrail',
          scan_mode: 'deep',
          history_limit: 125,
          max_findings: 50,
          project_id: 'production-platform',
          connector_id: 'github-app'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await screen.findByText(/Repository scan queued for identrail\/identrail/i);
  });

  it('Repositories page resets one-off scan drafts when environments change', async () => {
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    await renderGitHubPage('repositories', {
      projects: [productionProject, stagingProject],
      scans: [],
      initialEntry: '/app/tenant-a/workspace-a/github/repositories?environment=production-platform'
    });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const oneOffPanel = await screen.findByRole('region', { name: 'One-off repository scan' });
    fireEvent.change(within(oneOffPanel).getByLabelText(/^Repository$/i), { target: { value: 'acme/production-repo' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/Scan mode/i), { target: { value: 'quick' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/History limit/i), { target: { value: '75' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/Max findings/i), { target: { value: '25' } });

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });

    const resetPanel = await screen.findByRole('region', { name: 'One-off repository scan' });
    await waitFor(() => expect(within(resetPanel).getByLabelText(/^Repository$/i)).toHaveValue(''));
    expect(within(resetPanel).getByLabelText(/Scan mode/i)).toHaveValue('deep');
    expect(within(resetPanel).getByLabelText(/History limit/i)).toHaveValue('500');
    expect(within(resetPanel).getByLabelText(/Max findings/i)).toHaveValue('200');
  });

  it('Repositories page ignores stale one-off scan completions after environment changes', async () => {
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const mocks = await renderGitHubPage('repositories', {
      projects: [productionProject, stagingProject],
      scans: [],
      initialEntry: '/app/tenant-a/workspace-a/github/repositories?environment=production-platform'
    });
    const oneOffScan = deferred<{ repo_scan: RepoScanRecord }>();
    mocks.runRepoScan.mockImplementation(() => oneOffScan.promise);

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const oneOffPanel = await screen.findByRole('region', { name: 'One-off repository scan' });
    fireEvent.change(within(oneOffPanel).getByLabelText(/^Repository$/i), { target: { value: 'acme/production-repo' } });
    fireEvent.click(within(oneOffPanel).getByRole('button', { name: /Run scan/i }));

    await waitFor(() =>
      expect(mocks.runRepoScan).toHaveBeenCalledWith(
        expect.objectContaining({
          repository: 'acme/production-repo',
          project_id: 'production-platform',
          connector_id: 'github-app'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });
    const resetPanel = await screen.findByRole('region', { name: 'One-off repository scan' });
    await waitFor(() => expect(within(resetPanel).getByLabelText(/^Repository$/i)).toHaveValue(''));

    await act(async () => {
      oneOffScan.resolve({ repo_scan: queuedRepoScan });
    });

    expect(screen.queryByText(/Repository scan queued for acme\/production-repo/i)).not.toBeInTheDocument();
    expect(within(resetPanel).getByLabelText(/^Repository$/i)).toHaveValue('');
  });

  it('Repositories page resets one-off scan state when the workspace scope changes', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'getGitHubConnectorRepositoryPosture').mockResolvedValue({
      connector_id: 'github-app',
      provider: 'github_app',
      posture: defaultRepositoryPosture,
      organization_posture: defaultOrganizationPosture
    });
    const oneOffScan = deferred<{ repo_scan: RepoScanRecord }>();
    const runRepoScan = vi.spyOn(api.apiClient, 'runRepoScan').mockImplementation(() => oneOffScan.promise);

    const { ProductGitHubRepositoriesPage } = await import('./productShell');
    function WorkspaceSwitchHarness() {
      const navigate = useNavigate();
      return (
        <>
          <button
            type="button"
            onClick={() => navigate('/app/tenant-a/workspace-b/github/repositories?environment=production-platform')}
          >
            Switch workspace
          </button>
          <ProductGitHubRepositoriesPage />
        </>
      );
    }

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/repositories?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/repositories" element={<WorkspaceSwitchHarness />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const oneOffPanel = await screen.findByRole('region', { name: 'One-off repository scan' });
    fireEvent.change(within(oneOffPanel).getByLabelText(/^Repository$/i), { target: { value: 'acme/workspace-a-repo' } });
    fireEvent.change(within(oneOffPanel).getByLabelText(/History limit/i), { target: { value: '75' } });
    fireEvent.click(within(oneOffPanel).getByRole('button', { name: /Run scan/i }));

    await waitFor(() =>
      expect(runRepoScan).toHaveBeenCalledWith(
        expect.objectContaining({
          repository: 'acme/workspace-a-repo',
          project_id: 'production-platform',
          connector_id: 'github-app'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.click(screen.getByRole('button', { name: 'Switch workspace' }));
    const resetPanel = await screen.findByRole('region', { name: 'One-off repository scan' });
    await waitFor(() => expect(within(resetPanel).getByLabelText(/^Repository$/i)).toHaveValue(''));
    expect(within(resetPanel).getByLabelText(/History limit/i)).toHaveValue('500');

    await act(async () => {
      oneOffScan.resolve({ repo_scan: queuedRepoScan });
    });

    expect(screen.queryByText(/Repository scan queued for acme\/workspace-a-repo/i)).not.toBeInTheDocument();
    expect(within(resetPanel).getByLabelText(/^Repository$/i)).toHaveValue('');
  });

  it('Repositories page keeps repository posture checks reachable', async () => {
    const mocks = await renderGitHubPage('repositories', { scans: [succeededRepoScan] });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const posturePanel = await screen.findByRole('region', { name: 'Repository posture' });
    expect(await within(posturePanel).findByText('Default branch is missing required pull request reviews.')).toBeInTheDocument();
    expect(within(posturePanel).getByLabelText('GitHub posture summary')).toHaveTextContent('Secure1');
    expect(within(posturePanel).getByText('Organization posture')).toBeInTheDocument();
    await waitFor(() =>
      expect(mocks.getGitHubConnectorRepositoryPosture).toHaveBeenCalledWith(
        'github-app',
        'workspace-a',
        'production-platform',
        'identrail/identrail',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('Repositories page bypasses in-flight refreshes after queueing a scan', async () => {
    const initialMocks = await renderGitHubPage('repositories', { scans: [] });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    await waitFor(() => expect(initialMocks.listRepoScans).toHaveBeenCalledTimes(1));
    cleanup();
    vi.restoreAllMocks();

    const pendingRefresh = deferred<{ items: RepoScanRecord[]; next_cursor?: string }>();
    const queuedAfterMutation: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-after-mutation'
    };
    let listCalls = 0;
    const mocks = await renderGitHubPage('repositories', {
      listRepoScans: () => {
        listCalls += 1;
        if (listCalls === 1) {
          return pendingRefresh.promise;
        }
        return Promise.resolve({ items: [queuedAfterMutation] });
      }
    });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    await waitFor(() => expect(mocks.listRepoScans).toHaveBeenCalledTimes(1));
    const queueButton = await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' });
    await waitFor(() => expect(queueButton).not.toBeDisabled());
    fireEvent.click(queueButton);

    await waitFor(() =>
      expect(mocks.runRepoScan).toHaveBeenCalledWith(
        expect.objectContaining({
          repository: 'identrail/identrail',
          project_id: 'production-platform',
          connector_id: 'github-app'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await waitFor(() => expect(mocks.listRepoScans).toHaveBeenCalledTimes(2));
    await screen.findByText(/Repository scan queued for identrail\/identrail/i);
    await screen.findByText(/scan in flight/i);

    await act(async () => {
      pendingRefresh.resolve({ items: [] });
    });

    expect(screen.getByLabelText('Selected repositories')).toHaveTextContent('scan in flight');
  });

  it('Repositories page cancels an active scan via the existing API', async () => {
    const mocks = await renderGitHubPage('repositories', { scans: [queuedRepoScan] });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const cancelButton = await screen.findByRole('button', { name: 'Cancel scan for identrail/identrail' });
    fireEvent.click(cancelButton);

    await waitFor(() =>
      expect(mocks.cancelRepoScan).toHaveBeenCalledWith(
        'repo-scan-queued',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await screen.findByText(/Repository scan canceled for identrail\/identrail/i);
  });

  it('Repositories page polls while repository scans are active', async () => {
    const setIntervalSpy = vi.spyOn(window, 'setInterval');
    const mocks = await renderGitHubPage('repositories', { scans: [queuedRepoScan] });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    await screen.findByText(/scan in flight/i);
    await waitFor(() => expect(mocks.listRepoScans).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), 8000)
    );
    const pollCallback = setIntervalSpy.mock.calls.find((call) => call[1] === 8000)?.[0];
    expect(pollCallback).toEqual(expect.any(Function));

    act(() => {
      (pollCallback as () => void)();
    });

    await waitFor(() => expect(mocks.listRepoScans).toHaveBeenCalledTimes(2));
  });

  it('Repositories page shows the empty state when no repositories are selected', async () => {
    await renderGitHubPage('repositories', {
      githubConnection: { ...connectedGitHub, selected_repositories: [] }
    });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    await screen.findByRole('heading', { level: 3, name: /Select repositories for Identrail to watch/i });
    await waitFor(() => {
      const selectLink = screen
        .getAllByRole('link')
        .find((link) => link.textContent?.includes('Select repositories'));
      expect(selectLink).toBeDefined();
      expect(selectLink?.getAttribute('href')).toMatch(/^\/app\/tenant-a\/workspace-a\/github\/connect/);
    });
  });

  it('Repositories page surfaces a scan error inline without breaking navigation', async () => {
    await renderGitHubPage('repositories', {
      runRepoScanError: { message: 'rate limited', status: 429 }
    });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    const queueButton = await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' });
    fireEvent.click(queueButton);

    await screen.findByRole('heading', { level: 3, name: /Repository scan error/i });
    // Navigation must still work after a scan error — the primary CTA in
    // the page header (GitHub findings link) stays reachable.
    const findingsLink = screen
      .getAllByRole('link', { name: /GitHub findings/i })
      .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/findings'));
    expect(findingsLink).toBeDefined();
  });

  it('Repositories page renders a compact subtitle and drops the Scan operations reference', async () => {
    await renderGitHubPage('repositories', { scans: [succeededRepoScan] });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    // Subtitle reflects the live repo count and scan totals — replaces
    // the long "Launch, monitor, and cancel repository scans..." tagline.
    await screen.findByText(/1 repository · 1 recent scan/i);
    // The "Selected repositories / 1 repository in scope" sub-header is
    // dropped — the section heading is just "Repositories".
    expect(screen.queryByText(/1 repository in scope/i)).not.toBeInTheDocument();
    // The "Reference / Scan operations" aside (with three meta-docs
    // bullets) is removed entirely.
    expect(screen.queryByRole('heading', { level: 3, name: 'Scan operations' })).not.toBeInTheDocument();
    expect(screen.queryByText(/Scans use the existing repository scan APIs\./i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Cancel is only available while a scan is queued or running\./i)).not.toBeInTheDocument();
    // The Activity section header is the tighter "Recent activity"
    // instead of "Activity / Recent repository scan activity".
    expect(screen.queryByRole('heading', { level: 3, name: /Recent repository scan activity/i })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 3, name: 'Recent activity' })).toBeInTheDocument();
  });

  it('Actions page renders the premium waiting-for-coverage shell', async () => {
    await renderGitHubPage('actions');

    await screen.findByRole('heading', { level: 2, name: 'GitHub Actions / OIDC' });
    await screen.findByRole('heading', { level: 3, name: /Workflow and OIDC posture is rolling out/i });
    expect(screen.getAllByText(/Workflow inventory/i).length).toBeGreaterThan(0);
    await waitFor(() => {
      const openReposLink = screen
        .getAllByRole('link', { name: /Open Repositories/i })
        .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/repositories'));
      expect(openReposLink).toBeDefined();
    });
    const homeLink = screen
      .getAllByRole('link', { name: /GitHub home/i })
      .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github'));
    expect(homeLink).toBeDefined();
  });

  it('Actions page renders the unavailable shell when the GitHub connector is gated off', async () => {
    await renderGitHubPage('actions', { githubFeatureFlag: false, githubBackend: false });

    await screen.findByRole('heading', { level: 2, name: 'GitHub Actions / OIDC' });
    await screen.findByRole('heading', { level: 3, name: /GitHub is not available on this API/i });
  });

  it('Remediation page shows the never-scanned state', async () => {
    await renderGitHubPage('remediation', { scans: [], repoFindings: [] });

    await screen.findByRole('heading', { level: 2, name: 'GitHub remediation' });
    await screen.findByRole('heading', { level: 3, name: /Run your first repository scan/i });
    const repositoriesLink = screen
      .getAllByRole('link', { name: /Open Repositories/i })
      .find((link) => link.getAttribute('href')?.startsWith('/app/tenant-a/workspace-a/github/repositories'));
    expect(repositoriesLink).toBeDefined();
  });

  it('Remediation page surfaces a failed scan state before showing remediation chrome', async () => {
    const failedScan: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-remediation-failed',
      status: 'failed',
      finding_count: 0,
      error_message: 'GitHub App installation access revoked'
    };

    await renderGitHubPage('remediation', { scans: [failedScan], repoFindings: [] });

    await screen.findByRole('heading', { level: 3, name: /Your last repository scan failed/i });
    expect(screen.getByText(/GitHub App installation access revoked/i)).toBeInTheDocument();
    expect(screen.queryByText('Actionable findings')).not.toBeInTheDocument();
  });

  it('Remediation page previews and publishes a fix PR only after approval gates pass', async () => {
    const finding: Finding = {
      id: 'finding-deployment-token',
      scan_id: succeededRepoScan.id,
      type: 'secret_exposure',
      severity: 'critical',
      confidence_score: 0.96,
      title: 'Workflow exposes deployment token',
      human_summary: 'A deployment token is committed into a GitHub Actions workflow.',
      remediation: 'Move the deployment token into GitHub Actions secrets and rotate it.',
      repository: 'identrail/identrail',
      file_path: '.github/workflows/deploy.yml',
      line_number: 18,
      detector: 'github_actions_secret',
      source_url: 'https://github.com/identrail/identrail/blob/main/.github/workflows/deploy.yml#L18',
      lifecycle_status: 'open',
      created_at: '2026-05-17T11:10:00Z'
    };
    const preview: RepoFindingRemediationPreview = {
      finding,
      remediation: {
        detector: 'github_actions_secret',
        summary: 'Rotate leaked deployment token',
        risk_summary: 'The token can be reused by anyone with repository history access.',
        steps: ['Create a GitHub Actions secret for the replacement token', 'Remove the inline token from deploy.yml'],
        safety_notes: ['Confirm the replacement secret exists before merging'],
        validation: ['Run the repository scan again', 'Confirm the workflow still deploys from the secret'],
        secret_rotation: true,
        publishable: true,
        evidence: {
          finding_id: finding.id,
          scan_id: finding.scan_id,
          repository: 'identrail/identrail',
          file_path: finding.file_path,
          line_number: finding.line_number
        }
      },
      fix_pr_plan: {
        base_branch: 'main',
        branch_name: 'identrail/fix/deployment-token',
        commit_message: 'Move deployment token into Actions secrets',
        pr_title: 'Move deployment token into Actions secrets',
        pr_body: 'Remediates the exposed deployment token finding.',
        files: [{ path: '.github/workflows/deploy.yml', content: 'env:\\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}' }],
        finding_id: finding.id,
        finding_type: finding.type
      }
    };
    const publish: RepoFindingRemediationPublishResponse = {
      finding,
      remediation: preview.remediation,
      publish: {
        pr_number: 42,
        pr_url: 'https://github.com/identrail/identrail/pull/42',
        branch_name: 'identrail/fix/deployment-token',
        commit_sha: 'abc1234'
      }
    };
    const mocks = await renderGitHubPage('remediation', {
      scans: [{ ...succeededRepoScan, finding_count: 1 }],
      repoFindings: [finding],
      remediationPreview: preview,
      remediationPublish: publish
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub remediation' });
    expect(await screen.findByText('Actionable findings')).toBeInTheDocument();
    expect(screen.getAllByText('Workflow exposes deployment token').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/.github\/workflows\/deploy.yml:18/i).length).toBeGreaterThan(0);

    const previewButton = await screen.findByRole('button', { name: /Preview fix plan/i });
    fireEvent.click(previewButton);

    await waitFor(() =>
      expect(mocks.previewRepoFindingRemediation).toHaveBeenCalledWith(
        finding.id,
        expect.objectContaining({
          repo_scan_id: succeededRepoScan.id,
          finding_url: finding.source_url
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(screen.getByLabelText('Current source content'), {
      target: { value: 'env:\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}' }
    });
    fireEvent.click(previewButton);
    await waitFor(() =>
      expect(mocks.previewRepoFindingRemediation).toHaveBeenCalledWith(
        finding.id,
        expect.objectContaining({
          repo_scan_id: succeededRepoScan.id,
          finding_url: finding.source_url,
          source_content: 'env:\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
          require_fix_plan: true
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByText('Rotate leaked deployment token')).toBeInTheDocument();
    expect(screen.getByText('Branch identrail/fix/deployment-token')).toBeInTheDocument();

    const publishButton = await screen.findByRole('button', { name: /Publish fix PR/i });
    expect(publishButton).toBeDisabled();
    expect(mocks.publishRepoFindingRemediation).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText('Current source content'), {
      target: { value: 'env:\\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}' }
    });
    fireEvent.change(screen.getByLabelText('GitHub token'), { target: { value: 'ghp_write_token' } });
    fireEvent.click(screen.getByLabelText('Approved for publish'));
    fireEvent.click(screen.getByLabelText('GitHub token is intentionally write-capable'));

    await waitFor(() => expect(publishButton).not.toBeDisabled());
    fireEvent.click(publishButton);

    await waitFor(() =>
      expect(mocks.publishRepoFindingRemediation).toHaveBeenCalledWith(
        finding.id,
        expect.objectContaining({
          repo_scan_id: succeededRepoScan.id,
          source_content: 'env:\\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
          base_branch: 'main',
          finding_url: finding.source_url,
          operator_approved: true,
          write_permissions_configured: true,
          github_token: 'ghp_write_token'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(await screen.findByText(/PR #42 opened/i)).toBeInTheDocument();
  });

  it('Control Center surfaces an error when listing repository scans fails', async () => {
    const api = await import('./api/client');
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockRejectedValue(
      new api.ApiError('rate limited', 429)
    );

    const productShell = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github" element={<productShell.ProductGitHubControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByRole('heading', { level: 3, name: /Unable to load GitHub status/i });
    // The error panel is the single source of truth — the page must not
    // also speculate a "run your first scan" recommendation or claim
    // "no repository scans yet" off a failed fetch.
    expect(screen.queryByLabelText('GitHub action recommendation')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 3, name: /No repository scans yet/i })).not.toBeInTheDocument();
  });

  it('Control Center reuses the last loaded dashboard while refreshing the same environment', async () => {
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValueOnce({ connection: connectedGitHub });
    const listRepoScans = vi
      .spyOn(api.apiClient, 'listRepoScans')
      .mockResolvedValueOnce({ items: [succeededRepoScan] });

    const productShell = await import('./productShell');
    const renderControlCenter = () =>
      render(
        <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github?environment=production-platform']}>
          <Routes>
            <Route path="/app/:tenantID/:workspaceID/github" element={<productShell.ProductGitHubControlCenterPage />} />
          </Routes>
        </MemoryRouter>
      );

    const firstRender = renderControlCenter();
    expect(await screen.findByRole('heading', { level: 3, name: 'Recent scans' })).toBeInTheDocument();
    await waitFor(() => expect(listRepoScans).toHaveBeenCalledTimes(1));
    firstRender.unmount();

    const pendingStatus = deferred<{ connection: GitHubConnectionStatus }>();
    const pendingScans = deferred<{ items: RepoScanRecord[] }>();
    getGitHubConnectorStatus.mockReturnValueOnce(pendingStatus.promise);
    listRepoScans.mockReturnValueOnce(pendingScans.promise);

    renderControlCenter();

    expect(screen.getByRole('heading', { level: 3, name: 'Recent scans' })).toBeInTheDocument();
    expect(screen.getByText(/Installation 12345/i)).toBeInTheDocument();
    expect(screen.queryByText(/Loading GitHub status/i)).not.toBeInTheDocument();
    await waitFor(() => expect(getGitHubConnectorStatus).toHaveBeenCalledTimes(2));

    await act(async () => {
      pendingStatus.resolve({ connection: connectedGitHub });
      pendingScans.resolve({ items: [succeededRepoScan] });
    });
  });

  it('Control Center keeps cached scans visible while surfacing same-environment refresh failures', async () => {
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValueOnce({ connection: connectedGitHub })
      .mockResolvedValueOnce({ connection: connectedGitHub });
    const listRepoScans = vi
      .spyOn(api.apiClient, 'listRepoScans')
      .mockResolvedValueOnce({ items: [succeededRepoScan] })
      .mockRejectedValueOnce(new api.ApiError('rate limited', 429));

    const productShell = await import('./productShell');
    const renderControlCenter = () =>
      render(
        <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github?environment=production-platform']}>
          <Routes>
            <Route path="/app/:tenantID/:workspaceID/github" element={<productShell.ProductGitHubControlCenterPage />} />
          </Routes>
        </MemoryRouter>
      );

    const firstRender = renderControlCenter();
    expect(await screen.findByRole('heading', { level: 3, name: 'Recent scans' })).toBeInTheDocument();
    await waitFor(() => expect(listRepoScans).toHaveBeenCalledTimes(1));
    firstRender.unmount();

    renderControlCenter();

    expect(screen.getByRole('heading', { level: 3, name: 'Recent scans' })).toBeInTheDocument();
    await screen.findByRole('heading', { level: 3, name: /Unable to load GitHub status/i });
    expect(screen.getByText(/rate limited/i)).toBeInTheDocument();
    await waitFor(() => expect(getGitHubConnectorStatus).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(listRepoScans).toHaveBeenCalledTimes(2));
  });

  it('Control Center reuses overview caches without showing a loading status', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'getOnboardingState').mockResolvedValue({
      state: {
        user_id: 'user-1',
        org_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: productionProject.project_id,
        current_step: 'complete',
        connector_skipped: false,
        scan_skipped: false,
        started_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }
    });
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: connectedKubernetes });
    const listRepoScans = vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [succeededRepoScan] });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [], summary: undefined });

    const { ProductOverviewPage, ProductGitHubControlCenterPage } = await import('./productShell');
    const overviewRender = render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('region', { name: 'Domain posture' });
    await waitFor(() => expect(listProjects).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(getGitHubConnectorStatus).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(listRepoScans).toHaveBeenCalledTimes(2));
    overviewRender.unmount();

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github" element={<ProductGitHubControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    expect(screen.getByText(/Installation 12345/i)).toBeInTheDocument();
    expect(screen.queryByText(/Loading GitHub status/i)).not.toBeInTheDocument();
    expect(listProjects).toHaveBeenCalledTimes(1);
    await waitFor(() =>
      expect(getGitHubConnectorStatus).toHaveBeenCalledWith(
        'workspace-a',
        'production-platform',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('Overview warms GitHub caches when backend availability resolves after mount', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    let githubBackend: BackendFeatureState = false;
    vi.doMock('./hooks/useBackendFeatures', async (importOriginal) => {
      const actual = await importOriginal<typeof import('./hooks/useBackendFeatures')>();
      return {
        ...actual,
        useBackendFeatures: () => ({
          features: {
            onboardingWizard: undefined,
            connectors: { github: githubBackend, aws: undefined, kubernetes: true },
            configReachable: true
          },
          loading: false
        })
      };
    });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'getOnboardingState').mockResolvedValue({
      state: {
        user_id: 'user-1',
        org_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: productionProject.project_id,
        current_step: 'complete',
        connector_skipped: false,
        scan_skipped: false,
        started_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }
    });
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValue({ connection: connectedGitHub });
    const listRepoScans = vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [succeededRepoScan] });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [], summary: undefined });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: connectedKubernetes });

    const { ProductOverviewPage } = await import('./productShell');
    const renderOverviewRoute = () => (
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );
    const overviewRender = render(renderOverviewRoute());

    await screen.findByRole('region', { name: 'Domain posture' });
    await waitFor(() => expect(listProjects).toHaveBeenCalledTimes(1));
    expect(getGitHubConnectorStatus).not.toHaveBeenCalled();

    githubBackend = true;
    overviewRender.rerender(renderOverviewRoute());

    await waitFor(() => expect(listProjects).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(getGitHubConnectorStatus).toHaveBeenCalledWith(
        'workspace-a',
        'production-platform',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    expect(listRepoScans).toHaveBeenCalled();
  });

  it('Overview skips dashboard cache warmups after the auth session resets', async () => {
    mockConnectorFeatureFlags({ aws: true, github: true, kubernetes: true });
    mockBackendFeatures({ github: true, kubernetes: true });
    const api = await import('./api/client');
    vi.spyOn(api.apiClient, 'getOnboardingState').mockResolvedValue({
      state: {
        user_id: 'user-1',
        org_id: 'tenant-a',
        workspace_id: 'workspace-a',
        project_id: productionProject.project_id,
        current_step: 'complete',
        connector_skipped: false,
        scan_skipped: false,
        started_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      }
    });
    const pendingProjects = deferred<{ items: typeof productionProject[] }>();
    const listProjects = vi.spyOn(api.apiClient, 'listProjects').mockReturnValue(pendingProjects.promise);
    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValue({ connection: connectedGitHub });
    const listRepoScans = vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [succeededRepoScan] });
    vi.spyOn(api.apiClient, 'listRepoFindings').mockResolvedValue({ items: [], summary: undefined });
    vi.spyOn(api.apiClient, 'getAWSProjectConnection').mockResolvedValue({ connection: connectedAWS });
    vi.spyOn(api.apiClient, 'getKubernetesProjectConnection').mockResolvedValue({ connection: connectedKubernetes });

    const { ProductOverviewPage, ProductGitHubControlCenterPage, clearProductAuthSessionCacheForTests } = await import('./productShell');
    const overviewRender = render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID" element={<ProductOverviewPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(listProjects).toHaveBeenCalledTimes(1));
    overviewRender.unmount();
    clearProductAuthSessionCacheForTests();

    await act(async () => {
      pendingProjects.resolve({ items: [productionProject] });
      await pendingProjects.promise;
      await Promise.resolve();
    });

    expect(getGitHubConnectorStatus).not.toHaveBeenCalled();
    expect(listRepoScans).not.toHaveBeenCalled();
    cleanup();
    vi.restoreAllMocks();

    const nextSessionStatus = deferred<{ connection: GitHubConnectionStatus }>();
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockReturnValue(nextSessionStatus.promise);
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });

    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github" element={<ProductGitHubControlCenterPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    expect(screen.queryByText(/Installation 12345/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Loading GitHub status/i)).not.toBeInTheDocument();

    await act(async () => {
      nextSessionStatus.resolve({
        connection: {
          ...connectedGitHub,
          installation_id: 67890,
          selected_repositories: []
        }
      });
    });

    expect(await screen.findByText(/Installation 67890/i)).toBeInTheDocument();
  });

  it('Control Center hides recent scans when no repositories are selected', async () => {
    const unrelatedScan: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-unrelated',
      repository: 'someone-else/other-repo'
    };
    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: [] },
      scans: [unrelatedScan]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    expect(screen.queryByText(/Last \d+ repository scans/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/someone-else\/other-repo/i)).not.toBeInTheDocument();
    await screen.findByText(/Pick repositories for Identrail to watch\./i);
  });

  it('Control Center surfaces the most recent failed scan in the banner', async () => {
    const olderSucceeded: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-older-success',
      repository: 'identrail/recent-fail',
      started_at: '2026-05-16T10:00:00Z',
      finished_at: '2026-05-16T10:05:00Z'
    };
    const newerFailed: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-newer-failed',
      repository: 'identrail/recent-fail',
      status: 'failed',
      started_at: '2026-05-17T12:00:00Z',
      finished_at: '2026-05-17T12:05:00Z',
      error_message: 'scan exploded',
      finding_count: 0
    };
    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: ['identrail/recent-fail'] },
      scans: [newerFailed, olderSucceeded]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByText(/Installation 12345/i);
    await waitFor(() => {
      expect(screen.getByLabelText('GitHub action recommendation')).toHaveAttribute(
        'data-banner-id',
        'review-failed-scan'
      );
    });
    const banner = screen.getByLabelText('GitHub action recommendation');
    expect(within(banner).getByText(/failed its last scan/i)).toBeInTheDocument();
    expect(within(banner).getByText(/scan exploded/i)).toBeInTheDocument();
  });

  it('Control Center ignores a stale failure once a newer successful scan exists', async () => {
    const olderFailed: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-older-fail',
      repository: 'identrail/recovered',
      status: 'failed',
      started_at: '2026-05-15T10:00:00Z',
      finished_at: '2026-05-15T10:05:00Z',
      error_message: 'scan exploded',
      finding_count: 0
    };
    const newerSucceeded: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-newer-success',
      repository: 'identrail/recovered',
      started_at: '2026-05-17T10:00:00Z',
      finished_at: '2026-05-17T10:05:00Z',
      finding_count: 0
    };
    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: ['identrail/recovered'] },
      scans: [newerSucceeded, olderFailed]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByText(/Installation 12345/i);
    await waitFor(() => {
      expect(screen.queryByLabelText('GitHub action recommendation')).not.toBeInTheDocument();
    });
  });

  it('Control Center surfaces a triage banner when latest scans have open findings', async () => {
    const repoWithFindings: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-latest-has-findings',
      repository: 'identrail/repo-a',
      started_at: '2026-05-20T10:00:00Z',
      finished_at: '2026-05-20T10:05:00Z',
      finding_count: 2
    };

    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: ['identrail/repo-a'] },
      scans: [repoWithFindings]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByText(/Installation 12345/i);
    await waitFor(() => {
      expect(screen.getByLabelText('GitHub action recommendation')).toHaveAttribute(
        'data-banner-id',
        'triage-findings'
      );
    });
    const banner = screen.getByLabelText('GitHub action recommendation');
    expect(within(banner).getByText(/Repository findings need triage\./)).toBeInTheDocument();
    expect(within(banner).getByRole('link', { name: /Review/i })).toHaveAttribute(
      'href',
      expect.stringMatching(/\/github\/findings/)
    );
  });

  it('Control Center triage banner ignores findings from older scans once the latest scan is clean', async () => {
    const repo = 'identrail/repo-cleared';
    const olderHadFindings: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'older-had-findings',
      repository: repo,
      started_at: '2026-05-19T10:00:00Z',
      finished_at: '2026-05-19T10:05:00Z',
      finding_count: 3
    };
    const latestClean: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'latest-clean',
      repository: repo,
      started_at: '2026-05-20T10:00:00Z',
      finished_at: '2026-05-20T10:05:00Z',
      finding_count: 0
    };

    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: [repo] },
      scans: [latestClean, olderHadFindings]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByText(/Installation 12345/i);
    await waitFor(() => {
      expect(screen.queryByLabelText('GitHub action recommendation')).not.toBeInTheDocument();
    });
  });

  it('Control Center triage banner survives a later canceled scan over a successful scan with findings', async () => {
    const repo = 'identrail/repo-canceled-after-findings';
    const succeededWithFindings: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'succeeded-with-findings',
      repository: repo,
      started_at: '2026-05-19T10:00:00Z',
      finished_at: '2026-05-19T10:05:00Z',
      finding_count: 3
    };
    const canceledAfter: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'canceled-after',
      repository: repo,
      status: 'canceled',
      started_at: '2026-05-20T10:00:00Z',
      finished_at: '2026-05-20T10:00:30Z',
      finding_count: 0,
      error_message: 'repository scan canceled by user'
    };

    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: [repo] },
      scans: [canceledAfter, succeededWithFindings]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByText(/Installation 12345/i);
    await waitFor(() => {
      expect(screen.getByLabelText('GitHub action recommendation')).toHaveAttribute(
        'data-banner-id',
        'triage-findings'
      );
    });
    const banner = screen.getByLabelText('GitHub action recommendation');
    expect(within(banner).getByText(/Repository findings need triage\./)).toBeInTheDocument();
  });

  it('Control Center shows a scan-in-progress banner instead of prompting to queue another', async () => {
    const queuedFirstScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'queued-first',
      repository: 'identrail/in-progress',
      status: 'running'
    };

    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: ['identrail/in-progress'] },
      scans: [queuedFirstScan]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByText(/Installation 12345/i);
    await waitFor(() => {
      expect(screen.getByLabelText('GitHub action recommendation')).toHaveAttribute(
        'data-banner-id',
        'scan-in-progress'
      );
    });
    const banner = screen.getByLabelText('GitHub action recommendation');
    expect(within(banner).getByText(/Scan in progress/i)).toBeInTheDocument();
    expect(within(banner).getByText('identrail/in-progress')).toBeInTheDocument();
    expect(within(banner).queryByText(/Queue the first repository scan/i)).not.toBeInTheDocument();
  });

  it('Control Center shows an active scan banner when a failed scan is being retried', async () => {
    const failedScan: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'failed-retry',
      repository: 'identrail/retrying-repo',
      status: 'failed',
      started_at: '2026-05-16T10:00:00Z',
      finished_at: '2026-05-16T10:05:00Z',
      finding_count: 0,
      error_message: 'scan exploded'
    };
    const retryScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'retry-in-progress',
      repository: 'identrail/retrying-repo',
      status: 'running'
    };

    await renderGitHubPage('control-center', {
      githubConnection: { ...connectedGitHub, selected_repositories: ['identrail/retrying-repo'] },
      scans: [retryScan, failedScan]
    });

    await screen.findByRole('heading', { level: 2, name: 'GitHub' });
    await screen.findByText(/Installation 12345/i);
    await waitFor(() => {
      expect(screen.getByLabelText('GitHub action recommendation')).toHaveAttribute(
        'data-banner-id',
        'scan-in-progress'
      );
    });
    const banner = screen.getByLabelText('GitHub action recommendation');
    expect(within(banner).queryByText(/failed its last scan/i)).not.toBeInTheDocument();
    expect(within(banner).getByText(/Scan in progress/i)).toBeInTheDocument();
    expect(within(banner).getByText('identrail/retrying-repo')).toBeInTheDocument();
  });

  it('Connect page renders an Open GitHub fallback link when the install popup is blocked', async () => {
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    await renderGitHubPage('connect', {
      githubConnection: {
        ...connectedGitHub,
        connected: false,
        account_login: undefined,
        installation_id: undefined,
        selected_repositories: []
      }
    });

    const installButton = (await screen.findAllByRole('button', { name: 'Install GitHub App' }))[0];
    fireEvent.click(installButton);

    const fallback = await screen.findByRole('link', { name: 'Open GitHub' });
    expect(fallback.getAttribute('href')).toBe(
      'https://github.com/apps/identrail/installations/select_target?state=github-state'
    );
    expect(openSpy).toHaveBeenCalled();
    openSpy.mockRestore();
  });

  it('Connect page shows the manage view with installation facts when already connected', async () => {
    await renderGitHubPage('connect', { githubConnection: connectedGitHub });

    await screen.findByRole('heading', { level: 2, name: 'Connect GitHub' });
    await screen.findByText(/Installation 12345/i);
    const installation = await screen.findByRole('region', { name: 'GitHub installation' });
    expect(within(installation).getByText('Account')).toBeInTheDocument();
    expect(within(installation).getByText('identrail')).toBeInTheDocument();
    expect(within(installation).getByText('Selected repositories')).toBeInTheDocument();
    // The reinstall affordance and the Enterprise/PAT management control are
    // both reachable from the manage view.
    expect(within(installation).getByRole('button', { name: 'Install GitHub App' })).toBeInTheDocument();
    expect(within(installation).getByRole('button', { name: /Manage Enterprise \/ PAT/i })).toBeInTheDocument();
    // The page must not also render the disconnected "Install the Identrail
    // GitHub App" install card on top of the manage view.
    expect(screen.queryByRole('region', { name: 'Install GitHub App' })).not.toBeInTheDocument();
  });

  it('Connect page keeps scan policy management reachable', async () => {
    const mocks = await renderGitHubPage('connect', {
      githubConnection: connectedGitHub,
      scanPolicies: [defaultScanPolicy]
    });

    await screen.findByRole('heading', { level: 2, name: 'Connect GitHub' });
    const policyPanel = await screen.findByRole('region', { name: 'Scan policy management' });
    expect(within(policyPanel).getByRole('heading', { level: 3, name: 'Scan policy' })).toBeInTheDocument();
    expect(within(policyPanel).getByText('Default policy')).toBeInTheDocument();
    await waitFor(() =>
      expect(mocks.listProjectScanPolicies).toHaveBeenCalledWith(
        'workspace-a',
        'production-platform',
        expect.objectContaining({ limit: 50, sort_by: 'updated_at', sort_order: 'desc' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(within(policyPanel).getByLabelText(/Trigger mode/i), { target: { value: 'hybrid' } });
    fireEvent.change(within(policyPanel).getByLabelText(/Cron schedule/i), { target: { value: '0 * * * *' } });
    fireEvent.click(within(policyPanel).getByRole('button', { name: /Save scan policy/i }));

    await waitFor(() =>
      expect(mocks.upsertProjectScanPolicy).toHaveBeenCalledWith(
        'workspace-a',
        'production-platform',
        expect.objectContaining({
          policy_id: 'default',
          trigger_mode: 'hybrid',
          cron: '0 * * * *'
        }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.click(within(policyPanel).getByRole('button', { name: /^Delete$/i }));

    await waitFor(() =>
      expect(mocks.deleteProjectScanPolicy).toHaveBeenCalledWith(
        'workspace-a',
        'production-platform',
        'default',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
  });

  it('Connect page ignores stale scan policy responses after environment changes', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const productionPolicyLoad = deferred<{ items: ScanPolicyRecord[] }>();
    const stagingPolicyLoad = deferred<{ items: ScanPolicyRecord[] }>();
    const productionPolicy: ScanPolicyRecord = {
      ...defaultScanPolicy,
      policy_id: 'production-only',
      name: 'Production stale policy'
    };
    const stagingPolicy: ScanPolicyRecord = {
      ...defaultScanPolicy,
      project_id: 'staging-platform',
      policy_id: 'staging-only',
      name: 'Staging policy'
    };

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    const listProjectScanPolicies = vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockImplementation(
      (_workspaceID, projectID) =>
        projectID === 'staging-platform' ? stagingPolicyLoad.promise : productionPolicyLoad.promise
    );

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() =>
      expect(listProjectScanPolicies).toHaveBeenCalledWith(
        'workspace-a',
        'production-platform',
        expect.anything(),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });
    await waitFor(() =>
      expect(listProjectScanPolicies).toHaveBeenCalledWith(
        'workspace-a',
        'staging-platform',
        expect.anything(),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    await act(async () => {
      stagingPolicyLoad.resolve({ items: [stagingPolicy] });
    });
    const policyPanel = await screen.findByRole('region', { name: 'Scan policy management' });
    expect(await within(policyPanel).findByText('Staging policy')).toBeInTheDocument();

    await act(async () => {
      productionPolicyLoad.resolve({ items: [productionPolicy] });
    });

    expect(within(policyPanel).getByText('Staging policy')).toBeInTheDocument();
    expect(within(policyPanel).queryByText('Production stale policy')).not.toBeInTheDocument();
  });

  it('Connect page resets scan policy drafts for empty environments', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const productionPolicy: ScanPolicyRecord = {
      ...defaultScanPolicy,
      policy_id: 'production-event-policy',
      name: 'Production event policy',
      trigger_mode: 'event'
    };

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ items: projectID === 'staging-platform' ? [] : [productionPolicy] })
    );

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByDisplayValue('Production event policy')).toBeInTheDocument();

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });

    await waitFor(() =>
      expect(within(screen.getByRole('region', { name: 'Scan policy management' })).getByLabelText(/Policy name/i))
        .toHaveValue('Default policy')
    );
    const currentPolicyPanel = screen.getByRole('region', { name: 'Scan policy management' });
    expect(screen.queryByDisplayValue('Production event policy')).not.toBeInTheDocument();
    expect(within(currentPolicyPanel).getByLabelText(/Trigger mode/i)).toHaveValue('manual');
  });

  it('Connect page resets scan policy drafts when environment policy loading fails', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const productionPolicy: ScanPolicyRecord = {
      ...defaultScanPolicy,
      policy_id: 'production-event-policy',
      name: 'Production event policy',
      trigger_mode: 'event'
    };

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockImplementation((_workspaceID, projectID) =>
      projectID === 'staging-platform'
        ? Promise.reject(new api.ApiError('scan policy unavailable', 503))
        : Promise.resolve({ items: [productionPolicy] })
    );

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByDisplayValue('Production event policy')).toBeInTheDocument();

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });

    await screen.findByRole('alert');
    const currentPolicyPanel = screen.getByRole('region', { name: 'Scan policy management' });
    expect(screen.queryByDisplayValue('Production event policy')).not.toBeInTheDocument();
    expect(within(currentPolicyPanel).getByLabelText(/Policy name/i)).toHaveValue('Default policy');
    expect(within(currentPolicyPanel).getByLabelText(/Trigger mode/i)).toHaveValue('manual');
  });

  it('Connect page ignores stale scan policy saves after environment changes', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const productionPolicy: ScanPolicyRecord = {
      ...defaultScanPolicy,
      policy_id: 'production-event-policy',
      name: 'Production event policy',
      trigger_mode: 'event'
    };
    const stagingPolicyLoad = deferred<{ items: ScanPolicyRecord[] }>();
    const savePolicy = deferred<{ policy: ScanPolicyRecord }>();

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    const listProjectScanPolicies = vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockImplementation(
      (_workspaceID, projectID) =>
        projectID === 'staging-platform' ? stagingPolicyLoad.promise : Promise.resolve({ items: [productionPolicy] })
    );
    const upsertProjectScanPolicy = vi
      .spyOn(api.apiClient, 'upsertProjectScanPolicy')
      .mockImplementation(() => savePolicy.promise);

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    const policyPanel = await screen.findByRole('region', { name: 'Scan policy management' });
    expect(await within(policyPanel).findByDisplayValue('Production event policy')).toBeInTheDocument();
    fireEvent.click(within(policyPanel).getByRole('button', { name: /Save scan policy/i }));

    await waitFor(() =>
      expect(upsertProjectScanPolicy).toHaveBeenCalledWith(
        'workspace-a',
        'production-platform',
        expect.objectContaining({ policy_id: 'production-event-policy' }),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });
    await waitFor(() =>
      expect(listProjectScanPolicies).toHaveBeenCalledWith(
        'workspace-a',
        'staging-platform',
        expect.anything(),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await act(async () => {
      stagingPolicyLoad.resolve({ items: [] });
    });
    await waitFor(() => expect(screen.getByLabelText(/Policy name/i)).toHaveValue('Default policy'));

    await act(async () => {
      savePolicy.resolve({ policy: { ...productionPolicy, name: 'Saved production policy' } });
    });

    expect(screen.queryByText('Scan policy saved.')).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue('Saved production policy')).not.toBeInTheDocument();
    expect(listProjectScanPolicies.mock.calls.filter((call) => call[1] === 'production-platform')).toHaveLength(1);
  });

  it('Connect page ignores stale scan policy deletes after environment changes', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const productionPolicy: ScanPolicyRecord = {
      ...defaultScanPolicy,
      policy_id: 'production-event-policy',
      name: 'Production event policy',
      trigger_mode: 'event'
    };
    const stagingPolicyLoad = deferred<{ items: ScanPolicyRecord[] }>();
    const deletePolicy = deferred<void>();

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    const listProjectScanPolicies = vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockImplementation(
      (_workspaceID, projectID) =>
        projectID === 'staging-platform' ? stagingPolicyLoad.promise : Promise.resolve({ items: [productionPolicy] })
    );
    const deleteProjectScanPolicy = vi
      .spyOn(api.apiClient, 'deleteProjectScanPolicy')
      .mockImplementation(() => deletePolicy.promise);

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    const policyPanel = await screen.findByRole('region', { name: 'Scan policy management' });
    expect(await within(policyPanel).findByText('Production event policy')).toBeInTheDocument();
    fireEvent.click(within(policyPanel).getByRole('button', { name: /^Delete$/i }));

    await waitFor(() =>
      expect(deleteProjectScanPolicy).toHaveBeenCalledWith(
        'workspace-a',
        'production-platform',
        'production-event-policy',
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });
    await waitFor(() =>
      expect(listProjectScanPolicies).toHaveBeenCalledWith(
        'workspace-a',
        'staging-platform',
        expect.anything(),
        expect.objectContaining({ tenantID: 'tenant-a', workspaceID: 'workspace-a' })
      )
    );
    await act(async () => {
      stagingPolicyLoad.resolve({ items: [] });
    });
    await waitFor(() => expect(screen.getByLabelText(/Policy name/i)).toHaveValue('Default policy'));

    await act(async () => {
      deletePolicy.resolve();
    });

    expect(screen.queryByText('Scan policy production-event-policy deleted.')).not.toBeInTheDocument();
    expect(listProjectScanPolicies.mock.calls.filter((call) => call[1] === 'production-platform')).toHaveLength(1);
  });

  it('Connect page clears old scan policy rows while loading a new environment', async () => {
    vi.resetModules();
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    const api = await import('./api/client');
    const stagingProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    const productionPolicy: ScanPolicyRecord = {
      ...defaultScanPolicy,
      policy_id: 'production-event-policy',
      name: 'Production event policy',
      trigger_mode: 'event'
    };
    const stagingPolicyLoad = deferred<{ items: ScanPolicyRecord[] }>();

    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject, stagingProject] });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation((_workspaceID, projectID) =>
      Promise.resolve({ project: projectID === 'staging-platform' ? stagingProject : productionProject })
    );
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockResolvedValue({ connection: connectedGitHub });
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });
    vi.spyOn(api.apiClient, 'listProjectScanPolicies').mockImplementation((_workspaceID, projectID) =>
      projectID === 'staging-platform' ? stagingPolicyLoad.promise : Promise.resolve({ items: [productionPolicy] })
    );

    const { ProductGitHubConnectPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/connect" element={<ProductGitHubConnectPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText('Production event policy')).toBeInTheDocument();

    fireEvent.change(await screen.findByRole('combobox', { name: 'Environment' }), {
      target: { value: 'staging-platform' }
    });

    await waitFor(() => expect(screen.queryByText('Production event policy')).not.toBeInTheDocument());
    expect(screen.queryByRole('button', { name: /^Delete$/i })).not.toBeInTheDocument();
  });

  it('Connect page hides the install/manage body when the connection status request fails', async () => {
    const api = await import('./api/client');
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({ items: [productionProject] });
    vi.spyOn(api.apiClient, 'getProject').mockResolvedValue({ project: productionProject });
    vi.spyOn(api.apiClient, 'getGitHubConnectorStatus').mockRejectedValue(
      new api.ApiError('rate limited', 429)
    );
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [] });

    const productShell = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/connect']}>
        <Routes>
          <Route
            path="/app/:tenantID/:workspaceID/github/connect"
            element={<productShell.ProductGitHubConnectPage />}
          />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'Connect GitHub' });
    await screen.findByRole('heading', { level: 3, name: /Unable to load connection status/i });
    expect(screen.queryByRole('region', { name: 'Install GitHub App' })).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'GitHub installation' })).not.toBeInTheDocument();
    // When the status request fails the connection state is unknown, so
    // the header must not claim "Not connected" and must not surface a
    // speculative install/open CTA — the error panel is the single
    // source of truth.
    expect(screen.queryByText(/Not connected for this environment\./i)).not.toBeInTheDocument();
    await screen.findByText(/Unable to load GitHub status\./i);
    expect(document.querySelector('.idt-domain-header-actions')).toBeNull();
    expect(
      screen.queryAllByRole('button', { name: /Install GitHub App/i })
    ).toHaveLength(0);
  });

  it('Repositories page activity timeline ignores scans for unselected repositories', async () => {
    const unrelatedScan: RepoScanRecord = {
      ...succeededRepoScan,
      id: 'repo-scan-unrelated',
      repository: 'someone-else/other-repo'
    };
    await renderGitHubPage('repositories', { scans: [unrelatedScan] });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    await screen.findByRole('heading', { level: 3, name: 'Recent activity' });
    const activity = screen.getByRole('region', { name: 'Recent repository scan activity' });
    expect(within(activity).getByRole('heading', { level: 3, name: /No repository scans recorded yet/i })).toBeInTheDocument();
    expect(screen.queryByText(/someone-else\/other-repo/i)).not.toBeInTheDocument();
  });

  it('Repositories page fetches additional scan pages until selected-repository activity is available', async () => {
    const unrelatedRepoScans: RepoScanRecord[] = Array.from({ length: 3 }).map((_, index) => ({
      ...succeededRepoScan,
      id: `repo-scan-unrelated-${index}`,
      repository: `team-${index + 1}/unrelated`
    }));
    const selectedRepoScan: RepoScanRecord = {
      ...queuedRepoScan,
      id: 'repo-scan-selected',
      repository: 'identrail/identrail',
      status: 'completed',
      started_at: '2026-05-18T10:00:00Z',
      finished_at: '2026-05-18T10:03:00Z',
      finding_count: 2,
      files_scanned: 17
    };

    let pageCalls = 0;
    const mocks = await renderGitHubPage('repositories', {
      listRepoScans: () => {
        pageCalls += 1;
        if (pageCalls === 1) {
          return Promise.resolve({
            items: unrelatedRepoScans,
            next_cursor: 'repo-page-2'
          });
        }
        return Promise.resolve({
          items: [selectedRepoScan]
        });
      }
    });

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    await waitFor(() => expect(mocks.listRepoScans).toHaveBeenCalledTimes(2));
    await waitFor(() => {
      const activity = screen.getByRole('region', { name: 'Recent repository scan activity' });
      expect(within(activity).getAllByText(/identrail\/identrail/i).length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText(/identrail\/identrail/i).length).toBeGreaterThan(1);
  });

  it('Repositories page clears stale GitHub connection data when a reloading environment status fails', async () => {
    const api = await import('./api/client');
    mockConnectorFeatureFlags({ aws: false, github: true, kubernetes: false });
    mockBackendFeatures({ github: true });

    const activeProject = productionProject;
    const staleProject = {
      ...productionProject,
      project_id: 'staging-platform',
      name: 'Staging Platform',
      slug: 'staging-platform'
    };
    vi.spyOn(api.apiClient, 'listProjects').mockResolvedValue({
      items: [activeProject, staleProject]
    });
    vi.spyOn(api.apiClient, 'getProject').mockImplementation(async (_workspaceID, projectID) => ({
      project:
        projectID === staleProject.project_id
          ? staleProject
          : activeProject
    }));

    const getGitHubConnectorStatus = vi
      .spyOn(api.apiClient, 'getGitHubConnectorStatus')
      .mockResolvedValueOnce({ connection: connectedGitHub })
      .mockRejectedValue(new api.ApiError('status endpoint unavailable', 503));
    vi.spyOn(api.apiClient, 'listRepoScans').mockResolvedValue({ items: [queuedRepoScan] });
    vi.spyOn(api.apiClient, 'runRepoScan').mockResolvedValue({ repo_scan: queuedRepoScan });
    vi.spyOn(api.apiClient, 'cancelRepoScan').mockResolvedValue({ repo_scan: canceledRepoScan });

    const { ProductGitHubRepositoriesPage } = await import('./productShell');
    render(
      <MemoryRouter initialEntries={['/app/tenant-a/workspace-a/github/repositories?environment=production-platform']}>
        <Routes>
          <Route path="/app/:tenantID/:workspaceID/github/repositories" element={<ProductGitHubRepositoriesPage />} />
        </Routes>
      </MemoryRouter>
    );

    await screen.findByRole('heading', { level: 2, name: 'Repositories' });
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Environment' })).toHaveValue('production-platform'));
    expect(await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' })).toBeInTheDocument();

    await act(async () => {
      fireEvent.change(screen.getByRole('combobox', { name: 'Environment' }), {
        target: { value: 'staging-platform' }
      });
    });

    await screen.findByRole('heading', { level: 3, name: /Unable to load repository status/i });
    // After the reloading status request fails the stale Queue scan
    // affordance is dropped and the body is suppressed so the error
    // panel stays the single source of truth — the page must not also
    // render a speculative "Connect GitHub to manage repositories"
    // empty state off an errored status.
    expect(screen.queryByRole('button', { name: 'Queue scan for identrail/identrail' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 3, name: /Connect GitHub to manage repositories/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Selected repositories' })).not.toBeInTheDocument();
    await screen.findByText(/Unable to load repositories\./i);

    expect(getGitHubConnectorStatus).toHaveBeenCalledTimes(2);
  });

  it('Repositories page disables Queue scan while environment data is reloading', async () => {
    const mocks = await renderGitHubPage('repositories', { scans: [] });

    expect(await screen.findByRole('button', { name: 'Queue scan for identrail/identrail' })).not.toBeDisabled();

    let resolveQueued: ((value: { repo_scan: RepoScanRecord }) => void) | null = null;
    let resolvePending: ((value: { items: RepoScanRecord[] }) => void) | null = null;
    mocks.runRepoScan.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveQueued = resolve;
        })
    );
    mocks.listRepoScans.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolvePending = resolve;
        })
    );

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Queue scan for identrail/identrail' }));
    });
    await waitFor(() => expect(mocks.runRepoScan).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Queue scan for identrail/identrail' })).toBeDisabled());
    expect(screen.getByRole('button', { name: 'Queue scan for identrail/identrail' })).toHaveTextContent(/Refreshing|Queuing/i);

    await act(async () => {
      resolveQueued?.({ repo_scan: queuedRepoScan });
      await Promise.resolve();
    });
    await act(async () => {
      resolvePending?.({ items: [] });
      await Promise.resolve();
    });
  });
});

// Workspace Danger Zone — PR 3 of #1420.
//
// These cover the owner-only workspace lifecycle controls appended to the
// existing Settings Danger Zone card: which rows show per role + lifecycle
// state, the type-to-confirm gate on Suspend/Delete, the checkbox confirm
// on the restorative Reactivate/Restore, and the inline sole-owner block
// (with deep link to the member-management screen) when the backend
// returns `409 sole_owner_requires_transfer`.
describe('Workspace Danger Zone (#1420)', () => {
  const ownerWorkspaceFixture = {
    tenant_id: 'tenant-a',
    workspace_id: 'workspace-a',
    display_name: 'Workspace A',
    slug: 'workspace-a',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  };
  const ownerMe: CurrentUserContext = {
    ...loggedInWithWorkspace,
    role: 'owner',
    workspace: ownerWorkspaceFixture
  };

  it('hides the workspace rows entirely for non-owner members', async () => {
    await renderProductSettingsPage();
    await screen.findByTestId('idt-suspend-account-row');
    expect(screen.queryByTestId('idt-suspend-workspace-row')).toBeNull();
    expect(screen.queryByTestId('idt-delete-workspace-row')).toBeNull();
    expect(screen.queryByTestId('idt-reactivate-workspace-row')).toBeNull();
    expect(screen.queryByTestId('idt-restore-workspace-row')).toBeNull();
  });

  it('shows Suspend + Delete workspace rows for owners on an active workspace', async () => {
    await renderProductSettingsPage({ me: ownerMe });
    await screen.findByTestId('idt-suspend-workspace-row');
    expect(screen.getByTestId('idt-delete-workspace-row')).toBeTruthy();
    expect(screen.queryByTestId('idt-reactivate-workspace-row')).toBeNull();
    expect(screen.queryByTestId('idt-restore-workspace-row')).toBeNull();
  });

  it('swaps Suspend → Reactivate when the workspace is already suspended', async () => {
    await renderProductSettingsPage({ me: ownerMe, workspaceStatus: 'suspended' });
    await screen.findByTestId('idt-reactivate-workspace-row');
    expect(screen.getByTestId('idt-delete-workspace-row')).toBeTruthy();
    expect(screen.queryByTestId('idt-suspend-workspace-row')).toBeNull();
  });

  it('collapses to a single Restore row when the workspace is soft-deleted', async () => {
    await renderProductSettingsPage({ me: ownerMe, workspaceStatus: 'deleted' });
    await screen.findByTestId('idt-restore-workspace-row');
    expect(screen.queryByTestId('idt-suspend-workspace-row')).toBeNull();
    expect(screen.queryByTestId('idt-reactivate-workspace-row')).toBeNull();
    expect(screen.queryByTestId('idt-delete-workspace-row')).toBeNull();
  });

  it('suspends the workspace after typing SUSPEND in the modal', async () => {
    const { suspendWorkspace } = await renderProductSettingsPage({ me: ownerMe });
    suspendWorkspace.mockResolvedValue({
      workspace: { ...ownerWorkspaceFixture, status: 'suspended' },
      status: 'suspended'
    });
    await screen.findByTestId('idt-suspend-workspace-row');

    await act(async () => {
      fireEvent.click(
        within(screen.getByTestId('idt-suspend-workspace-row')).getByRole('button')
      );
    });
    const modal = await screen.findByTestId('idt-danger-modal');
    const continueBtn = within(modal).getByTestId('idt-danger-modal-continue');
    // Gate stays armed until the user types the exact token.
    expect(continueBtn).toBeDisabled();
    await act(async () => {
      fireEvent.change(within(modal).getByTestId('idt-danger-modal-typed'), {
        target: { value: 'SUSPEND' }
      });
    });
    expect(continueBtn).not.toBeDisabled();
    await act(async () => {
      fireEvent.click(continueBtn);
    });
    await waitFor(() =>
      expect(suspendWorkspace).toHaveBeenCalledWith('workspace-a', expect.anything())
    );
    // Row swaps to Reactivate once the response lands.
    await screen.findByTestId('idt-reactivate-workspace-row');
  });

  it('still renders a fallback sole-owner blocker when affected_members is empty', async () => {
    // Regression for cubic PR #1456 P2: previously a 409 with a missing or
    // malformed affected_members array would set the stranded list to []
    // and the blocker (which keyed off length > 0) would not render at all,
    // leaving the actor with a closed pending state and no feedback.
    const { suspendWorkspace, api } = await renderProductSettingsPage({ me: ownerMe });
    await screen.findByTestId('idt-suspend-workspace-row');
    suspendWorkspace.mockRejectedValue(
      new api.ApiError('sole owner requires transfer', 409, {
        code: 'sole_owner_requires_transfer',
        payload: { code: 'sole_owner_requires_transfer' }
      })
    );

    await act(async () => {
      fireEvent.click(
        within(screen.getByTestId('idt-suspend-workspace-row')).getByRole('button')
      );
    });
    const modal = await screen.findByTestId('idt-danger-modal');
    await act(async () => {
      fireEvent.change(within(modal).getByTestId('idt-danger-modal-typed'), {
        target: { value: 'SUSPEND' }
      });
    });
    await act(async () => {
      fireEvent.click(within(modal).getByTestId('idt-danger-modal-continue'));
    });
    const block = await screen.findByTestId('idt-suspend-workspace-sole-owner-block');
    // Fallback copy must surface even with no affected-member list.
    expect(block.textContent).toMatch(/only one owner/i);
    expect(
      within(block).getByRole('link', { name: /manage members/i }).getAttribute('href')
    ).toBe('/app/tenant-a/workspace-a/workspaces');
  });

  it('renders the sole-owner inline block with a link to manage members', async () => {
    const { suspendWorkspace, api } = await renderProductSettingsPage({ me: ownerMe });
    await screen.findByTestId('idt-suspend-workspace-row');
    suspendWorkspace.mockRejectedValue(
      new api.ApiError(
        'workspace has additional active members but only one owner; transfer ownership before suspending or deleting',
        409,
        {
          code: 'sole_owner_requires_transfer',
          payload: {
            code: 'sole_owner_requires_transfer',
            affected_members: [
              {
                member_id: 'member-b',
                user_id: 'user-b',
                email: 'user-b@example.com',
                role: 'admin'
              }
            ]
          }
        }
      )
    );

    await act(async () => {
      fireEvent.click(
        within(screen.getByTestId('idt-suspend-workspace-row')).getByRole('button')
      );
    });
    const modal = await screen.findByTestId('idt-danger-modal');
    await act(async () => {
      fireEvent.change(within(modal).getByTestId('idt-danger-modal-typed'), {
        target: { value: 'SUSPEND' }
      });
    });
    await act(async () => {
      fireEvent.click(within(modal).getByTestId('idt-danger-modal-continue'));
    });
    const block = await screen.findByTestId('idt-suspend-workspace-sole-owner-block');
    expect(block.textContent).toContain('user-b@example.com');
    const manageLink = within(block).getByRole('link', { name: /manage members/i });
    expect(manageLink.getAttribute('href')).toBe('/app/tenant-a/workspace-a/workspaces');
  });

  it('keeps Delete workspace gated until the slug is typed exactly', async () => {
    const { deleteWorkspace } = await renderProductSettingsPage({ me: ownerMe });
    deleteWorkspace.mockResolvedValue({
      workspace: { ...ownerWorkspaceFixture, status: 'deleted', deleted_at: '2026-05-20T10:00:00Z' },
      status: 'deleted',
      hard_delete_after: '2026-06-19T10:00:00Z',
      grace_period_hours: 720
    });
    await screen.findByTestId('idt-delete-workspace-row');

    await act(async () => {
      fireEvent.click(
        within(screen.getByTestId('idt-delete-workspace-row')).getByRole('button')
      );
    });
    const modal = await screen.findByTestId('idt-danger-modal');
    const continueBtn = within(modal).getByTestId('idt-danger-modal-continue');
    expect(continueBtn).toBeDisabled();
    await act(async () => {
      fireEvent.change(within(modal).getByTestId('idt-danger-modal-typed'), {
        target: { value: 'wrong-slug' }
      });
    });
    expect(continueBtn).toBeDisabled();
    await act(async () => {
      fireEvent.change(within(modal).getByTestId('idt-danger-modal-typed'), {
        target: { value: 'workspace-a' }
      });
    });
    expect(continueBtn).not.toBeDisabled();
    await act(async () => {
      fireEvent.click(continueBtn);
    });
    await waitFor(() =>
      expect(deleteWorkspace).toHaveBeenCalledWith('workspace-a', expect.anything())
    );
    await screen.findByTestId('idt-restore-workspace-row');
  });

  it('reactivates a suspended workspace through the checkbox modal', async () => {
    const { reactivateWorkspace } = await renderProductSettingsPage({
      me: ownerMe,
      workspaceStatus: 'suspended'
    });
    reactivateWorkspace.mockResolvedValue({
      workspace: { ...ownerWorkspaceFixture, status: 'active' },
      status: 'active'
    });
    await screen.findByTestId('idt-reactivate-workspace-row');

    await act(async () => {
      fireEvent.click(
        within(screen.getByTestId('idt-reactivate-workspace-row')).getByRole('button')
      );
    });
    const modal = await screen.findByTestId('idt-danger-modal');
    await act(async () => {
      fireEvent.click(within(modal).getByTestId('idt-danger-modal-checkbox'));
    });
    await act(async () => {
      fireEvent.click(within(modal).getByTestId('idt-danger-modal-continue'));
    });
    await waitFor(() =>
      expect(reactivateWorkspace).toHaveBeenCalledWith('workspace-a', expect.anything())
    );
    await screen.findByTestId('idt-suspend-workspace-row');
  });

  it('restores a soft-deleted workspace through the checkbox modal', async () => {
    const { cancelWorkspaceDeletion } = await renderProductSettingsPage({
      me: ownerMe,
      workspaceStatus: 'deleted'
    });
    cancelWorkspaceDeletion.mockResolvedValue({
      workspace: { ...ownerWorkspaceFixture, status: 'active' },
      status: 'active'
    });
    await screen.findByTestId('idt-restore-workspace-row');

    await act(async () => {
      fireEvent.click(
        within(screen.getByTestId('idt-restore-workspace-row')).getByRole('button')
      );
    });
    const modal = await screen.findByTestId('idt-danger-modal');
    await act(async () => {
      fireEvent.click(within(modal).getByTestId('idt-danger-modal-checkbox'));
    });
    await act(async () => {
      fireEvent.click(within(modal).getByTestId('idt-danger-modal-continue'));
    });
    await waitFor(() =>
      expect(cancelWorkspaceDeletion).toHaveBeenCalledWith('workspace-a', expect.anything())
    );
    await screen.findByTestId('idt-suspend-workspace-row');
  });
});

// ---------------------------------------------------------------------------
// AWS section copy-redundancy regression
// ---------------------------------------------------------------------------
//
// PR #1582 stripped the AWS section of engineering-vibe copy: the marketing
// tagline on the overview, the eight-card KPI strip, every per-page
// `Current vs planned / Wired now / Planned coverage` block, the
// `Inventory contract` and `AWSRiskOperationScope` asides, the three
// `Issue sequencing / App validation / Collector contract` issue-tracker
// panels, and the `Coming wave / Coming later / Reserved surface /
// Inventory shell` status labels.
//
// This test reads productShell.tsx as source so that a future PR cannot
// quietly re-introduce any of those strings. The check is a substring
// match — if any banned phrase reappears anywhere in the file, this test
// fails with a clear pointer to which one. The list is intentionally
// scoped to *copy*; new code paths that happen to mention "wave" or
// "shell" in a function or type name are fine.

describe('AWS copy redundancy guard (#1582)', () => {

  // Strings that must never appear as customer-visible copy in the AWS
  // section. Anything wrapped in JSX literal quotes is fair game for the
  // check; type names and helper-function identifiers do not match
  // because they use camelCase or PascalCase.
  // The list is scoped to phrases that are unambiguously
  // engineering-roadmap-in-UI; phrases that double as legitimate
  // filter-option labels (e.g. 'Coming wave' is also an inventory
  // filter value), internal helper return values, or content-card copy
  // are intentionally NOT on this list — the per-constant assertions
  // below cover the page-shell constants where those phrases were the
  // actual redundancy.
  const bannedAWSCopyStrings: ReadonlyArray<string> = [
    // Header / overview chrome removed by #1582
    'AWS MACHINE IDENTITY',
    'AWS Control Center',
    'from one domain-owned surface',
    'Operate AWS connection health',
    // Issue-tracker panels removed from customer UI by #1582
    'AWS platform dependency index',
    'AWS live app validation harness',
    'AWS service collector contract',
    // Page-shell shells / scopes / asides removed by #1582
    'Coverage shell',
    'Inventory shell',
    'Reachability shell',
    'Reserved surface',
    'AWS capability expansion',
    'AWS capability map',
    'Setup payload',
    'Scoped contract',
    'Workspace contract',
    'Read-only account onboarding'
    // Note: short engineering-vibe phrases like "Not ingesting" / "Advisory
    // only" / "Coming wave" / "Wired now" / "Not yet available" are
    // intentionally not substring-banned because they double as legitimate
    // inventory filter labels or appear in cleanup comments. Their
    // reintroduction into the AWS_INVENTORY_PAGE_COPY and
    // AWS_RISK_OPERATION_PAGE_COPY shells is caught by the per-constant
    // assertions below.
  ];

  it.each(bannedAWSCopyStrings)(
    'productShell.tsx must not reintroduce the AWS copy redundancy %p',
    (phrase) => {
      // We match an opening single or double quote, optional intervening
      // whitespace, and the phrase, so we only catch the strings as
      // literal copy — not as parts of variable names.
      const literalForms = [`'${phrase}`, `"${phrase}`, `\`${phrase}`];
      const matched = literalForms.find((needle) => productShellSource.includes(needle));
      if (matched) {
        throw new Error(
          `AWS copy redundancy reintroduced: ${JSON.stringify(phrase)} was found as a string literal in productShell.tsx. ` +
            `PR #1582 removed this string family because it pushed engineering-roadmap language onto the customer UI. ` +
            `Use plain-English page copy and a real empty state instead.`
        );
      }
      expect(matched).toBeUndefined();
    }
  );

  it('AWS inventory copy entries keep the legacy roadmap-in-UI fields blank', () => {
    // The four AWSInventoryPageCopy entries were the source of every
    // `Wired now / Planned coverage / Statuslabel` repeat across the
    // Accounts / Identities / Agents / Resources sub-pages. The fields
    // still exist on the type so the surrounding shell continues to
    // compile, but their *values* must stay empty so the deleted panel
    // cannot accidentally reappear if a future PR re-renders them.
    const inventoryCopyBlock = productShellSource.match(
      /const AWS_INVENTORY_PAGE_COPY[\s\S]*?^};/m
    );
    expect(inventoryCopyBlock).not.toBeNull();
    const block = inventoryCopyBlock![0];
    // Every assignment to the four fields must be the empty string.
    for (const field of ['eyebrow', 'statusLabel', 'currentCapability', 'plannedCapability']) {
      const matches = [...block.matchAll(new RegExp(`${field}:\\s*'([^']*)'`, 'g'))];
      expect(matches.length).toBeGreaterThan(0);
      for (const match of matches) {
        expect(match[1]).toBe('');
      }
    }
  });

  it('AWS risk-operation copy entries keep the legacy roadmap-in-UI fields blank', () => {
    const riskCopyBlock = productShellSource.match(
      /const AWS_RISK_OPERATION_PAGE_COPY[\s\S]*?^};/m
    );
    expect(riskCopyBlock).not.toBeNull();
    const block = riskCopyBlock![0];
    for (const field of ['eyebrow', 'statusLabel', 'currentCapability', 'plannedCapability', 'nextAction']) {
      const matches = [...block.matchAll(new RegExp(`${field}:\\s*'([^']*)'`, 'g'))];
      expect(matches.length).toBeGreaterThan(0);
      for (const match of matches) {
        expect(match[1]).toBe('');
      }
    }
  });
});
