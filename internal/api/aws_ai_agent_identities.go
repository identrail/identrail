package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	awsAIAgentIdentityCurrentIssue = 1505
	awsAIAgentIdentityVersion      = "aws-ai-agent-identity-normalized-model-v1"
	awsAIAgentCredentialRefPrefix  = "aws:resource:credential-reference:"
	awsAIAgentToolNodePrefix       = "tool:agent:"
)

type AWSAIAgentIdentityInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

type AWSAIAgentCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSAIAgentIdentityInventoryResult struct {
	TenantID              string                         `json:"tenant_id"`
	WorkspaceID           string                         `json:"workspace_id"`
	ProjectID             string                         `json:"project_id"`
	ConnectorID           string                         `json:"connector_id,omitempty"`
	AccountID             string                         `json:"account_id,omitempty"`
	Region                string                         `json:"region,omitempty"`
	ParentIssueNumber     int                            `json:"parent_issue_number"`
	ParentIssueRef        string                         `json:"parent_issue_ref"`
	CurrentIssueNumber    int                            `json:"current_issue_number"`
	CurrentIssueRef       string                         `json:"current_issue_ref"`
	Version               string                         `json:"version"`
	Status                string                         `json:"status"`
	FixtureState          string                         `json:"fixture_state"`
	Confidence            float64                        `json:"confidence"`
	RecordCount           int                            `json:"record_count"`
	BedrockAgentCount     int                            `json:"bedrock_agent_count"`
	AgentCoreRuntimeCount int                            `json:"agentcore_runtime_count"`
	CustomAgentCount      int                            `json:"custom_agent_count"`
	ExternalAgentCount    int                            `json:"external_agent_count"`
	GatewayCount          int                            `json:"gateway_count"`
	RuntimeRoleCount      int                            `json:"runtime_role_count"`
	ProviderCount         int                            `json:"provider_count"`
	ModelCount            int                            `json:"model_count"`
	ToolCount             int                            `json:"tool_count"`
	CapabilityCount       int                            `json:"capability_count"`
	CredentialRefCount    int                            `json:"credential_reference_count"`
	RelationshipCount     int                            `json:"relationship_count"`
	FailureReasons        []string                       `json:"failure_reasons"`
	RemediationHints      []string                       `json:"remediation_hints"`
	EvidenceLinks         []string                       `json:"evidence_links"`
	CoverageGaps          []AWSAIAgentCoverageGap        `json:"coverage_gaps"`
	Records               []AWSAIAgentIdentityRecord     `json:"records"`
	Relationships         []AWSAIAgentIdentityRelation   `json:"relationships"`
	Diagnostics           []AWSAIAgentIdentityDiagnostic `json:"diagnostics"`
	GeneratedAt           time.Time                      `json:"generated_at"`
	UpdatedAt             time.Time                      `json:"updated_at"`
}

type AWSAIAgentIdentityRecord struct {
	AccountID               string            `json:"account_id"`
	Region                  string            `json:"region"`
	Service                 string            `json:"service"`
	AgentID                 string            `json:"agent_id"`
	AgentARN                string            `json:"agent_arn,omitempty"`
	AgentName               string            `json:"agent_name"`
	AgentType               string            `json:"agent_type"`
	Provider                string            `json:"provider,omitempty"`
	ModelID                 string            `json:"model_id,omitempty"`
	RuntimeRoleARN          string            `json:"runtime_role_arn,omitempty"`
	RuntimeRoleName         string            `json:"runtime_role_name,omitempty"`
	RuntimeRoleAccountID    string            `json:"runtime_role_account_id,omitempty"`
	GatewayID               string            `json:"gateway_id,omitempty"`
	GatewayARN              string            `json:"gateway_arn,omitempty"`
	ExternalProvider        string            `json:"external_provider,omitempty"`
	ToolNames               []string          `json:"tool_names,omitempty"`
	MemoryEnabled           bool              `json:"memory_enabled"`
	MemoryStoreRefs         []string          `json:"memory_store_refs,omitempty"`
	BrowserEnabled          bool              `json:"browser_enabled"`
	CodeInterpreterEnabled  bool              `json:"code_interpreter_enabled"`
	CapabilityNames         []string          `json:"capability_names,omitempty"`
	CredentialReferenceRefs []string          `json:"credential_reference_refs,omitempty"`
	SensitiveBoundary       string            `json:"sensitive_boundary"`
	CoverageStatus          string            `json:"coverage_status"`
	CoverageReason          string            `json:"coverage_reason,omitempty"`
	Source                  string            `json:"source"`
	EvidenceRef             string            `json:"evidence_ref"`
	AgentNodeID             string            `json:"agent_node_id"`
	RuntimeRoleNodeID       string            `json:"runtime_role_node_id,omitempty"`
	GatewayNodeID           string            `json:"gateway_node_id,omitempty"`
	RelationshipTypes       []string          `json:"relationship_types"`
	Confidence              float64           `json:"confidence"`
	CollectedAt             time.Time         `json:"collected_at"`
	Status                  string            `json:"status"`
	Tags                    map[string]string `json:"tags,omitempty"`
}

type AWSAIAgentIdentityRelation struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

type AWSAIAgentIdentityDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSAIAgentIdentityInventory(ctx context.Context, workspaceID string, projectID string, request AWSAIAgentIdentityInventoryRequest) (AWSAIAgentIdentityInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSAIAgentIdentityInventoryResult{}, err
	}
	var (
		connection    AWSConnectionStatus
		hasConnection bool
	)
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSAIAgentIdentityInventoryResult{}, err
	}
	return buildAWSAIAgentIdentityInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSAIAgentIdentityInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSAIAgentIdentityInventoryRequest, checkedAt time.Time) (AWSAIAgentIdentityInventoryResult, error) {
	fixtureState := normalizeAWSAIAgentIdentityFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSAIAgentIdentityInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsAIAgentIdentityFixtureRecords(accountID, region, fixtureState, checkedAt)
	records = emptyAWSAIAgentIdentityRecords(records)
	coverageGaps = emptyAWSAIAgentCoverageGaps(coverageGaps)
	for _, record := range records {
		if _, err := awscontract.NormalizeServiceCollectorRecord(awscontract.ServiceCollectorRecord{
			TenantID:      scope.TenantID,
			WorkspaceID:   project.WorkspaceID,
			ProjectID:     project.ProjectID,
			ConnectorID:   connectorID,
			AccountID:     record.AccountID,
			Region:        record.Region,
			Service:       record.Service,
			WorkloadID:    record.AgentID,
			WorkloadType:  record.AgentType,
			WorkloadName:  record.AgentName,
			RoleARN:       record.RuntimeRoleARN,
			Source:        record.Source,
			EvidenceRef:   record.EvidenceRef,
			Confidence:    record.Confidence,
			ScanID:        "aws-ai-agent-identity-fixture",
			CollectorName: "ai_agent_identity",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSAIAgentIdentityInventoryResult{}, fmt.Errorf("validate ai agent identity contract record: %w", err)
		}
	}
	status, confidence, failures, remediations := summarizeAWSAIAgentIdentityInventory(fixtureState, diagnostics)
	relationships := awsAIAgentIdentityRelationships(records)
	failures = emptyStrings(failures)
	remediations = emptyStrings(remediations)
	return AWSAIAgentIdentityInventoryResult{
		TenantID:              scope.TenantID,
		WorkspaceID:           project.WorkspaceID,
		ProjectID:             project.ProjectID,
		ConnectorID:           connectorID,
		AccountID:             accountID,
		Region:                region,
		ParentIssueNumber:     awsPlatformDependencyParentIssue,
		ParentIssueRef:        awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:    awsAIAgentIdentityCurrentIssue,
		CurrentIssueRef:       awsIssueRef(awsAIAgentIdentityCurrentIssue),
		Version:               awsAIAgentIdentityVersion,
		Status:                status,
		FixtureState:          fixtureState,
		Confidence:            confidence,
		RecordCount:           len(records),
		BedrockAgentCount:     awsAIAgentIdentityTypeCount(records, "bedrock_agent"),
		AgentCoreRuntimeCount: awsAIAgentIdentityTypeCount(records, "agentcore_runtime"),
		CustomAgentCount:      awsAIAgentIdentityTypeCount(records, "custom_agent"),
		ExternalAgentCount:    awsAIAgentIdentityTypeCount(records, "external_provider_agent"),
		GatewayCount:          awsAIAgentIdentityTypeCount(records, "agent_gateway"),
		RuntimeRoleCount:      awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.RuntimeRoleNodeID }),
		ProviderCount:         awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.Provider }),
		ModelCount:            awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.ModelID }),
		ToolCount:             awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.ToolNames }),
		CapabilityCount:       awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.CapabilityNames }),
		CredentialRefCount:    awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.CredentialReferenceRefs }),
		RelationshipCount:     len(relationships),
		FailureReasons:        failures,
		RemediationHints:      remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsAIAgentIdentityCurrentIssue),
			"/docs/aws-ai-agent-identities",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsAIAgentIdentityDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func emptyAWSAIAgentIdentityRecords(records []AWSAIAgentIdentityRecord) []AWSAIAgentIdentityRecord {
	if records == nil {
		return []AWSAIAgentIdentityRecord{}
	}
	return records
}

func emptyAWSAIAgentCoverageGaps(gaps []AWSAIAgentCoverageGap) []AWSAIAgentCoverageGap {
	if gaps == nil {
		return []AWSAIAgentCoverageGap{}
	}
	return gaps
}

func emptyStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func normalizeAWSAIAgentIdentityFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsAIAgentIdentityFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSAIAgentIdentityRecord, []providers.SourceError, []AWSAIAgentCoverageGap) {
	partition := awsPartitionForAPIRegion(region)
	role := func(name string) string { return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, name) }
	agentARN := func(service, id string) string {
		return fmt.Sprintf("arn:%s:%s:%s:%s:agent/%s", partition, service, region, accountID, id)
	}
	gatewayARN := fmt.Sprintf("arn:%s:bedrock:%s:%s:agent-gateway/payments-gateway", partition, region, accountID)
	gaps := []AWSAIAgentCoverageGap{{
		Capability:  "prompt_and_completion_contents",
		Status:      "intentionally_not_collected",
		Reason:      "Prompt text, completions, memory content, browser pages, code-interpreter output, database rows, and object contents are outside this metadata-only model.",
		Remediation: "Use runtime evidence references and operator-approved follow-up collection only when a future issue explicitly permits it.",
	}, {
		Capability:  "external_provider_secret_values",
		Status:      "intentionally_not_collected",
		Reason:      "External AI provider keys are represented as credential references only; secret values remain hidden.",
		Remediation: "Join to credential-reference metadata for rotation and ownership, never to secret values.",
	}}
	records := []AWSAIAgentIdentityRecord{
		awsAIAgentFixtureRecord(accountID, region, "bedrock_agent", "payments-risk-agent", "AGENTPAY1", agentARN("bedrock", "AGENTPAY1"), role("bedrock-payments-risk-agent"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "bedrock"
			r.Provider = "amazon-bedrock"
			r.ModelID = "anthropic.claude-3-5-sonnet-20240620-v1:0"
			r.ToolNames = []string{"payments-case-search", "fraud-review-action-group"}
			r.MemoryEnabled = true
			r.MemoryStoreRefs = []string{"bedrock-memory/payments-risk"}
			r.CapabilityNames = []string{"tool_use", "memory", "knowledge_base"}
		}),
		awsAIAgentFixtureRecord(accountID, region, "agentcore_runtime", "case-triage-runtime", "runtime-case-triage", agentARN("bedrock-agentcore", "runtime-case-triage"), role("agentcore-case-triage-runtime"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "agentcore"
			r.Provider = "amazon-bedrock-agentcore"
			r.ModelID = "us.amazon.nova-pro-v1:0"
			r.ToolNames = []string{"case-router", "policy-checker"}
			r.BrowserEnabled = true
			r.CodeInterpreterEnabled = true
			r.CapabilityNames = []string{"browser", "code_interpreter", "tool_use"}
		}),
		awsAIAgentFixtureRecord(accountID, region, "custom_agent", "invoice-reconciliation-agent", "custom-invoice-agent", fmt.Sprintf("arn:%s:lambda:%s:%s:function:invoice-reconciliation-agent", partition, region, accountID), role("lambda-invoice-agent"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "lambda"
			r.Provider = "custom"
			r.ModelID = "external:model-class-hidden"
			r.ToolNames = []string{"invoice-index", "ticket-writer"}
			r.CapabilityNames = []string{"tool_use"}
			r.CredentialReferenceRefs = []string{"secretsmanager:prod/ai/openai-key"}
			r.ExternalProvider = "external_ai_provider"
		}),
		awsAIAgentFixtureRecord(accountID, region, "external_provider_agent", "support-assistant", "external-support-agent", fmt.Sprintf("arn:%s:ecs:%s:%s:service/support/support-assistant", partition, region, accountID), role("ecs-support-agent-task"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "ecs"
			r.Provider = "external_provider"
			r.ModelID = "provider:model-redacted"
			r.ToolNames = []string{"support-search"}
			r.CapabilityNames = []string{"tool_use"}
			r.CredentialReferenceRefs = []string{"ssm:/prod/support/ai-provider-key"}
			r.ExternalProvider = "provider_key_reference"
		}),
		awsAIAgentFixtureRecord(accountID, region, "agent_gateway", "payments-gateway", "payments-gateway", gatewayARN, role("bedrock-agent-gateway-payments"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "bedrock"
			r.Provider = "amazon-bedrock"
			r.GatewayID = "payments-gateway"
			r.GatewayARN = gatewayARN
			r.ToolNames = []string{"payments-case-search", "fraud-review-action-group", "support-search"}
			r.CapabilityNames = []string{"gateway", "tool_routing"}
		}),
	}
	switch fixtureState {
	case "empty":
		return []AWSAIAgentIdentityRecord{}, nil, gaps
	case "degraded":
		records[2].Status = "degraded"
		records[2].CoverageStatus = "degraded"
		records[2].CoverageReason = "custom agent provider key is an unresolved credential reference"
		records[2].Confidence = 0.68
		return records, []providers.SourceError{{
			Collector: "aws_ai-agent/ai_agent_identity",
			SourceID:  records[2].AgentID,
			Code:      "ai_agent_credential_reference_unresolved",
			Message:   "custom agent has an external provider credential reference that did not resolve to collected metadata",
			Retryable: false,
		}}, gaps
	case "partial_failure":
		return records[:4], []providers.SourceError{{
			Collector: "aws_ai-agent/ai_agent_identity",
			SourceID:  fmt.Sprintf("service=ai-agent|account=%s|region=%s|source=agent_gateways", accountID, region),
			Code:      "ai_agent_gateway_list_failed",
			Message:   "agent gateway metadata could not be listed; retained Bedrock, AgentCore, custom, and external-provider-backed agent identities remain visible",
			Retryable: true,
		}}, gaps
	case "permission_denied":
		return []AWSAIAgentIdentityRecord{}, []providers.SourceError{{
			Collector: "aws_ai-agent/ai_agent_identity",
			SourceID:  fmt.Sprintf("service=ai-agent|account=%s|region=%s|source=list", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only AI agent metadata permission is missing",
			Retryable: false,
		}}, gaps
	default:
		return records, nil, gaps
	}
}

func awsAIAgentFixtureRecord(accountID string, region string, agentType string, agentName string, agentID string, agentARN string, roleARN string, checkedAt time.Time, mutate func(*AWSAIAgentIdentityRecord)) AWSAIAgentIdentityRecord {
	record := AWSAIAgentIdentityRecord{
		AccountID:               accountID,
		Region:                  region,
		Service:                 "ai-agent",
		AgentID:                 agentID,
		AgentARN:                agentARN,
		AgentName:               agentName,
		AgentType:               agentType,
		RuntimeRoleARN:          roleARN,
		RuntimeRoleName:         roleNameFromARNForAPI(roleARN),
		RuntimeRoleAccountID:    roleAccountIDFromARNForAPI(roleARN),
		SensitiveBoundary:       "metadata_only",
		CoverageStatus:          "covered",
		Source:                  "ai_agent_metadata",
		EvidenceRef:             agentARN,
		AgentNodeID:             awsAIAgentNodeID(accountID, region, agentType, agentID),
		RuntimeRoleNodeID:       awsIdentityNodeIDForAPI(roleARN),
		RelationshipTypes:       []string{"runs_as"},
		Confidence:              0.9,
		CollectedAt:             checkedAt,
		Status:                  "ready",
		Tags:                    map[string]string{"owner": "ai-platform", "classification": "metadata-only"},
		CapabilityNames:         []string{"identity"},
		ToolNames:               nil,
		MemoryStoreRefs:         nil,
		CredentialReferenceRefs: nil,
	}
	if mutate != nil {
		mutate(&record)
	}
	record.ToolNames = dedupeStrings(record.ToolNames)
	record.CapabilityNames = dedupeStrings(record.CapabilityNames)
	record.CredentialReferenceRefs = dedupeStrings(record.CredentialReferenceRefs)
	if len(record.CredentialReferenceRefs) > 0 {
		record.RelationshipTypes = dedupeStrings(append(record.RelationshipTypes, "uses_secret"))
	}
	if record.GatewayARN != "" {
		gatewayNodeID := awsAIAgentNodeID(accountID, region, "agent_gateway", firstNonEmptyAWSValue(record.GatewayID, record.GatewayARN))
		if record.AgentNodeID != gatewayNodeID {
			record.GatewayNodeID = gatewayNodeID
			record.RelationshipTypes = dedupeStrings(append(record.RelationshipTypes, "calls_tool"))
		}
	}
	return record
}

func summarizeAWSAIAgentIdentityInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35,
			[]string{"AI agent identity collection is blocked by missing read-only metadata permission"},
			[]string{"Grant metadata-only agent, runtime, gateway, and role-list permissions; do not grant prompt, invocation, browser, memory-content, or code-output reads."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72,
			[]string{"one or more agent credential references are unresolved"},
			[]string{"Join to credential-reference metadata for ownership and rotation; keep secret values hidden."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78,
			[]string{"one agent sub-listing failed while successful agent identity records remain visible"},
			[]string{"Retry the failed agent metadata call without discarding retained agent records."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82,
				[]string{"AI agent identity collection returned diagnostics"},
				[]string{"Review diagnostics before treating AI agent coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.91, nil, nil
	}
}

func awsAIAgentIdentityRelationships(records []AWSAIAgentIdentityRecord) []AWSAIAgentIdentityRelation {
	result := []AWSAIAgentIdentityRelation{}
	for _, record := range records {
		if record.AgentNodeID != "" && record.RuntimeRoleNodeID != "" {
			result = append(result, AWSAIAgentIdentityRelation{Type: "runs_as", FromNodeID: record.AgentNodeID, ToNodeID: record.RuntimeRoleNodeID, EvidenceRef: record.EvidenceRef})
		}
		toolNames := dedupeStrings(record.ToolNames)
		if record.AgentNodeID != "" && len(toolNames) > 0 {
			callsToolSource := firstNonEmptyAWSValue(record.GatewayNodeID, record.AgentNodeID)
			if strings.EqualFold(record.AgentType, "agent_gateway") {
				callsToolSource = record.AgentNodeID
			}
			if callsToolSource == "" {
				continue
			}
			for _, tool := range toolNames {
				tool = strings.TrimSpace(tool)
				if tool == "" {
					continue
				}
				result = append(result, AWSAIAgentIdentityRelation{
					Type:        "calls_tool",
					FromNodeID:  callsToolSource,
					ToNodeID:    awsAIAgentToolNodeID(callsToolSource, tool),
					EvidenceRef: record.EvidenceRef,
				})
			}
		}
		for _, ref := range record.CredentialReferenceRefs {
			ref = strings.TrimSpace(ref)
			if record.AgentNodeID != "" && ref != "" {
				result = append(result, AWSAIAgentIdentityRelation{Type: "uses_secret", FromNodeID: record.AgentNodeID, ToNodeID: awsCredentialReferenceNodeID(record.AgentNodeID, ref), EvidenceRef: record.EvidenceRef})
			}
		}
	}
	return result
}

func awsAIAgentToolNodeID(gatewayNodeID string, tool string) string {
	workload := strings.TrimSpace(strings.ToLower(gatewayNodeID))
	if workload == "" {
		workload = "gateway"
	}
	name := strings.TrimSpace(strings.ToLower(tool))
	if name == "" {
		name = "tool"
	}
	return awsAIAgentToolNodePrefix + strings.Join(normalizeStringList([]string{workload, name}), "|")
}

func awsCredentialReferenceNodeID(agentNodeID string, ref string) string {
	name, source := awsAIAgentCredentialReferenceParts(ref)
	agentNodeID = strings.TrimSpace(strings.ToLower(agentNodeID))
	if agentNodeID == "" {
		agentNodeID = "agent"
	}
	name = strings.TrimSpace(strings.ToLower(name))
	source = strings.TrimSpace(strings.ToLower(source))
	return awsAIAgentCredentialRefPrefix + strings.Join(normalizeStringList([]string{
		agentNodeID,
		awsAIAgentCredentialReferenceProvider(name, source),
		name,
		source,
	}), "|")
}

func awsAIAgentCredentialReferenceProvider(name, source string) string {
	probe := strings.ToLower(strings.TrimSpace(name + " " + source))
	switch {
	case containsAnyToken(probe, "openai", "open_ai", "gpt_"):
		return "openai"
	case containsAnyToken(probe, "anthropic", "claude"):
		return "anthropic"
	case containsAnyToken(probe, "bedrock"):
		return "bedrock"
	case strings.HasPrefix(probe, "secretsmanager:"):
		return "secretsmanager"
	case strings.HasPrefix(probe, "ssm:"):
		return "ssm"
	default:
		return "generic"
	}
}

func awsAIAgentCredentialReferenceParts(ref string) (string, string) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return "credential_reference", "unknown"
	}
	if idx := strings.Index(trimmed, "="); idx > 0 {
		name := strings.TrimSpace(trimmed[:idx])
		source := strings.TrimSpace(trimmed[idx+1:])
		if source == "" {
			source = "environment"
		}
		return sanitizeCredentialReferenceToken(name), sanitizeCredentialReferenceToken(source)
	}

	if !strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "/") {
		return sanitizeCredentialReferenceToken(trimmed), ""
	}
	name := trimmed
	if lastSlash := strings.LastIndex(trimmed, "/"); lastSlash >= 0 && lastSlash < len(trimmed)-1 {
		name = trimmed[lastSlash+1:]
	} else if colonIndex := strings.LastIndex(trimmed, ":"); colonIndex >= 0 && colonIndex < len(trimmed)-1 {
		name = trimmed[colonIndex+1:]
	}
	return sanitizeCredentialReferenceToken(name), sanitizeCredentialReferenceToken(trimmed)
}

func sanitizeCredentialReferenceToken(value string) string {
	return strings.ToLower(strings.NewReplacer(" ", "-", "/", "-", ":", "-", "#", "-").Replace(strings.TrimSpace(value)))
}

func containsAnyToken(haystack string, tokens ...string) bool {
	for _, token := range tokens {
		if token != "" && strings.Contains(haystack, token) {
			return true
		}
	}
	return false
}

func awsAIAgentIdentityTypeCount(records []AWSAIAgentIdentityRecord, agentType string) int {
	count := 0
	for _, record := range records {
		if record.AgentType == agentType {
			count++
		}
	}
	return count
}

func awsAIAgentIdentityUniqueCount(records []AWSAIAgentIdentityRecord, accessor func(AWSAIAgentIdentityRecord) string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		value := strings.TrimSpace(accessor(record))
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	return len(seen)
}

func awsAIAgentIdentityListCount(records []AWSAIAgentIdentityRecord, accessor func(AWSAIAgentIdentityRecord) []string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, value := range accessor(record) {
			trimmed := strings.TrimSpace(value)
			if trimmed != "" {
				seen[trimmed] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsAIAgentIdentityDiagnostics(diagnostics []providers.SourceError) []AWSAIAgentIdentityDiagnostic {
	result := make([]AWSAIAgentIdentityDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSAIAgentIdentityDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsAIAgentIdentityDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsAIAgentIdentityDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only AI agent list/describe permissions; do not add prompt, invoke, memory-content, browser-page, code-output, database-row, object-content, or secret-value reads."
	case "ai_agent_gateway_list_failed", "ai_agent_gateway_describe_failed", "ai_agent_identity_page_failed":
		return "Retry only the failed agent metadata call and keep successful normalized agent records visible."
	case "ai_agent_credential_reference_unresolved":
		return "Join to credential-reference metadata for ownership and rotation without exposing provider key values."
	default:
		return "Review the AI agent metadata diagnostic and retry after the scoped read-only metadata issue is corrected."
	}
}

func awsAIAgentNodeID(accountID string, region string, agentType string, agentID string) string {
	return fmt.Sprintf("aws:agent:%s:%s:%s/%s",
		firstNonEmptyAWSValue(accountID, "account"),
		firstNonEmptyAWSValue(region, "region"),
		firstNonEmptyAWSValue(agentType, "agent"),
		firstNonEmptyAWSValue(agentID, "unknown"),
	)
}

func awsPartitionForAPIRegion(region string) string {
	normalized := strings.ToLower(strings.TrimSpace(region))
	switch {
	case strings.HasPrefix(normalized, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(normalized, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}
