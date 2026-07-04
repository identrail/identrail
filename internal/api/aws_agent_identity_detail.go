package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	awsAgentIdentityDetailCurrentIssue = 1550
	awsAgentIdentityDetailVersion      = "aws-agent-identity-detail-page-v1"
	awsAgentIdentityDetailPolicyID     = "aws-agent-identity-detail-policy-v1"

	// awsAgentIdentityDetailLowConfidenceFloor marks agents whose inventory
	// confidence sits below the floor as low-confidence so the page can
	// surface candidate/uncertain agents explicitly instead of presenting
	// them like confirmed identities.
	awsAgentIdentityDetailLowConfidenceFloor = 0.7
)

// AWSAgentIdentityDetailRequest scopes the read-only agent identity detail
// page to one agent plus the operator filters shared by downstream surfaces.
type AWSAgentIdentityDetailRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	Agent        string `json:"agent,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Tab          string `json:"tab,omitempty"`
	Tool         string `json:"tool,omitempty"`
	Resource     string `json:"resource,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Status       string `json:"status,omitempty"`
}

// Reuse the machine-identity detail shapes for the sections both pages share
// so the two Wave 10 detail contracts stay consistent.
type AWSAgentIdentityDetailDiagnostic = AWSMachineIdentityDetailDiagnostic
type AWSAgentIdentityDetailCoverageGap = AWSMachineIdentityDetailCoverageGap
type AWSAgentIdentityDetailTab = AWSMachineIdentityDetailTab
type AWSAgentIdentityDetailRelationship = AWSMachineIdentityDetailRelationship
type AWSAgentIdentityGovernanceDecision = AWSMachineIdentityGovernanceDecision

// AWSAgentIdentityDetailAgent is the page-level agent header. Candidate and
// low-confidence agents are flagged explicitly so operators never mistake an
// inferred agent for a confirmed one.
type AWSAgentIdentityDetailAgent struct {
	Agent             string  `json:"agent"`
	AgentID           string  `json:"agent_id,omitempty"`
	AgentARN          string  `json:"agent_arn,omitempty"`
	AgentNodeID       string  `json:"agent_node_id,omitempty"`
	AgentName         string  `json:"agent_name,omitempty"`
	AgentType         string  `json:"agent_type,omitempty"`
	DisplayName       string  `json:"display_name"`
	Provider          string  `json:"provider,omitempty"`
	ModelID           string  `json:"model_id,omitempty"`
	Service           string  `json:"service,omitempty"`
	RuntimeVersion    string  `json:"runtime_version,omitempty"`
	RuntimeRoleARN    string  `json:"runtime_role_arn,omitempty"`
	RuntimeRoleName   string  `json:"runtime_role_name,omitempty"`
	RuntimeRoleNodeID string  `json:"runtime_role_node_id,omitempty"`
	GatewayID         string  `json:"gateway_id,omitempty"`
	GatewayNodeID     string  `json:"gateway_node_id,omitempty"`
	ExternalProvider  string  `json:"external_provider,omitempty"`
	AuthMode          string  `json:"auth_mode,omitempty"`
	AccountID         string  `json:"account_id,omitempty"`
	Region            string  `json:"region,omitempty"`
	Status            string  `json:"status"`
	Resolved          bool    `json:"resolved"`
	Candidate         bool    `json:"candidate"`
	LowConfidence     bool    `json:"low_confidence"`
	Confidence        float64 `json:"confidence"`
	CoverageStatus    string  `json:"coverage_status,omitempty"`
	CoverageReason    string  `json:"coverage_reason,omitempty"`
	EvidenceRef       string  `json:"evidence_ref,omitempty"`
	EvidenceBoundary  string  `json:"evidence_boundary"`
}

// AWSAgentIdentityToolSummary joins one declared or observed tool with its
// runtime evidence so the page can show declared-unused and
// observed-undeclared tools explicitly.
type AWSAgentIdentityToolSummary struct {
	ToolName      string    `json:"tool_name"`
	ToolTargetRef string    `json:"tool_target_ref,omitempty"`
	Declared      bool      `json:"declared"`
	Observed      bool      `json:"observed"`
	Status        string    `json:"status"`
	ObservedCount int       `json:"observed_count"`
	EvidenceRef   string    `json:"evidence_ref,omitempty"`
	LastObserved  time.Time `json:"last_observed,omitzero"`
}

// AWSAgentIdentityCapabilitySummary is one AgentCore capability
// (memory/browser/code-interpreter) with its metadata references only.
type AWSAgentIdentityCapabilitySummary struct {
	Capability       string   `json:"capability"`
	Enabled          bool     `json:"enabled"`
	ReferenceRefs    []string `json:"reference_refs,omitempty"`
	EncryptionKeyARN string   `json:"encryption_key_arn,omitempty"`
}

// AWSAgentIdentitySecretReference is one credential/provider-key reference
// the agent carries. Values are never resolved or inlined; the record is the
// reference metadata plus sensitivity classification.
type AWSAgentIdentitySecretReference struct {
	Reference     string  `json:"reference"`
	ReferenceName string  `json:"reference_name,omitempty"`
	ReferenceKind string  `json:"reference_kind"`
	Provider      string  `json:"provider,omitempty"`
	Sensitivity   string  `json:"sensitivity,omitempty"`
	Resolved      bool    `json:"resolved"`
	TargetNodeID  string  `json:"target_node_id,omitempty"`
	EvidenceRef   string  `json:"evidence_ref,omitempty"`
	Confidence    float64 `json:"confidence"`
}

// AWSAgentIdentityRuntimeCall is one observed (agent, tool) runtime
// correlation summary.
type AWSAgentIdentityRuntimeCall struct {
	CorrelationID string    `json:"correlation_id"`
	ToolName      string    `json:"tool_name,omitempty"`
	ToolTargetRef string    `json:"tool_target_ref,omitempty"`
	Status        string    `json:"status"`
	ObservedCount int       `json:"observed_count"`
	Outcomes      []string  `json:"outcomes,omitempty"`
	TargetARNs    []string  `json:"target_arns,omitempty"`
	EvidenceRef   string    `json:"evidence_ref,omitempty"`
	NextAction    string    `json:"next_action,omitempty"`
	LastObserved  time.Time `json:"last_observed,omitzero"`
}

// AWSAgentIdentityFindingSummary is one AI-agent risk finding scoped to the
// agent.
type AWSAgentIdentityFindingSummary struct {
	FindingID    string   `json:"finding_id"`
	RiskType     string   `json:"risk_type"`
	Severity     string   `json:"severity"`
	Status       string   `json:"status"`
	Score        int      `json:"score"`
	Rationale    string   `json:"rationale"`
	NextAction   string   `json:"next_action"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

// AWSAgentIdentityRecommendationSummary is one least-privilege
// recommendation scoped to the agent or its backing role.
type AWSAgentIdentityRecommendationSummary struct {
	RecommendationID string  `json:"recommendation_id"`
	Decision         string  `json:"decision"`
	Severity         string  `json:"severity"`
	Status           string  `json:"status"`
	Service          string  `json:"service"`
	DisplayName      string  `json:"display_name"`
	Rationale        string  `json:"rationale"`
	NextAction       string  `json:"next_action"`
	Score            int     `json:"score"`
	Confidence       float64 `json:"confidence"`
}

type AWSAgentIdentityDetailSummary struct {
	ToolCount               int `json:"tool_count"`
	DeclaredToolCount       int `json:"declared_tool_count"`
	ObservedToolCount       int `json:"observed_tool_count"`
	UndeclaredToolCount     int `json:"undeclared_tool_count"`
	CapabilityCount         int `json:"capability_count"`
	SecretReferenceCount    int `json:"secret_reference_count"`
	RuntimeCallCount        int `json:"runtime_call_count"`
	FindingCount            int `json:"finding_count"`
	RecommendationCount     int `json:"recommendation_count"`
	RemediationCaseCount    int `json:"remediation_case_count"`
	GovernanceDecisionCount int `json:"governance_decision_count"`
	RelationshipCount       int `json:"relationship_count"`
	EvidenceLinkCount       int `json:"evidence_link_count"`
	DiagnosticCount         int `json:"diagnostic_count"`
	CoverageGapCount        int `json:"coverage_gap_count"`
}

type AWSAgentIdentityDetailResult struct {
	TenantID            string                                  `json:"tenant_id"`
	WorkspaceID         string                                  `json:"workspace_id"`
	ProjectID           string                                  `json:"project_id"`
	ConnectorID         string                                  `json:"connector_id,omitempty"`
	AccountID           string                                  `json:"account_id,omitempty"`
	Region              string                                  `json:"region,omitempty"`
	ParentIssueNumber   int                                     `json:"parent_issue_number"`
	ParentIssueRef      string                                  `json:"parent_issue_ref"`
	CurrentIssueNumber  int                                     `json:"current_issue_number"`
	CurrentIssueRef     string                                  `json:"current_issue_ref"`
	Version             string                                  `json:"version"`
	Status              string                                  `json:"status"`
	FixtureState        string                                  `json:"fixture_state,omitempty"`
	Confidence          float64                                 `json:"confidence"`
	PolicyVersion       string                                  `json:"policy_version"`
	AppliedFilters      map[string]string                       `json:"applied_filters"`
	Agent               AWSAgentIdentityDetailAgent             `json:"agent"`
	Summary             AWSAgentIdentityDetailSummary           `json:"summary"`
	Tabs                []AWSAgentIdentityDetailTab             `json:"tabs"`
	Tools               []AWSAgentIdentityToolSummary           `json:"tools"`
	Capabilities        []AWSAgentIdentityCapabilitySummary     `json:"capabilities"`
	SecretReferences    []AWSAgentIdentitySecretReference       `json:"secret_references"`
	RuntimeCalls        []AWSAgentIdentityRuntimeCall           `json:"runtime_calls"`
	Findings            []AWSAgentIdentityFindingSummary        `json:"findings"`
	Recommendations     []AWSAgentIdentityRecommendationSummary `json:"recommendations"`
	GovernanceDecisions []AWSAgentIdentityGovernanceDecision    `json:"governance_decisions"`
	Relationships       []AWSAgentIdentityDetailRelationship    `json:"relationships"`
	RuntimeAccess       AWSAgentRuntimeAccessResult             `json:"runtime_access"`
	Risk                AWSAIAgentRiskResult                    `json:"risk"`
	Permissions         AWSLeastPrivilegeResult                 `json:"permissions"`
	RemediationCases    AWSRemediationCaseResult                `json:"remediation_cases"`
	Governance          AWSGovernanceAuditReportingResult       `json:"governance"`
	FailureReasons      []string                                `json:"failure_reasons"`
	RemediationHints    []string                                `json:"remediation_hints"`
	EvidenceLinks       []string                                `json:"evidence_links"`
	CoverageGaps        []AWSAgentIdentityDetailCoverageGap     `json:"coverage_gaps"`
	Diagnostics         []AWSAgentIdentityDetailDiagnostic      `json:"diagnostics"`
	GeneratedAt         time.Time                               `json:"generated_at"`
	UpdatedAt           time.Time                               `json:"updated_at"`
}

// GetAWSAgentIdentityDetail aggregates the read-only agent identity detail
// page: the AI-agent inventory record (provider/runtime, backing role,
// tools, memory/browser/code-interpreter capabilities, secret references),
// observed runtime tool calls, AI-agent risk findings, least-privilege
// recommendations, remediation cases, and governance decisions for one
// agent. The endpoint is metadata-only; secret values, prompt text, tool
// payloads, and workload data are never resolved or inlined.
func (s *Service) GetAWSAgentIdentityDetail(ctx context.Context, workspaceID string, projectID string, request AWSAgentIdentityDetailRequest) (AWSAgentIdentityDetailResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSAgentIdentityDetailResult{}, err
	}
	agent := strings.TrimSpace(request.Agent)
	if agent == "" {
		return AWSAgentIdentityDetailResult{}, ErrInvalidAWSConnectionRequest
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSAgentIdentityDetailResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSAgentIdentityDetailFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSAgentIdentityDetailResult{}, ErrInvalidAWSConnectionRequest
	}
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")

	inventory, err := s.GetAWSAIAgentIdentityInventory(ctx, workspaceID, projectID, AWSAIAgentIdentityInventoryRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
	})
	if err != nil {
		return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail inventory: %w", err)
	}
	record, resolved := awsAgentIdentityDetailResolve(agent, inventory.Records)

	// Downstream evidence filters are broad substring matches in some source
	// APIs, so only resolved inventory records may contribute real agent IDs.
	agentFilters := awsAgentIdentityDetailEvidenceAgentFilters(agent, record, resolved)
	agentFilter := firstString(agentFilters)
	runtimeAccess, err := s.GetAWSAgentRuntimeAccess(ctx, workspaceID, projectID, AWSAgentRuntimeAccessRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
		AgentID:      agentFilter,
		Tool:         request.Tool,
		Resource:     request.Resource,
		Status:       request.Status,
	})
	if err != nil {
		return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail runtime access: %w", err)
	}
	for _, alternateAgentFilter := range agentFilters[1:] {
		alternateRuntimeAccess, err := s.GetAWSAgentRuntimeAccess(ctx, workspaceID, projectID, AWSAgentRuntimeAccessRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			AgentID:      alternateAgentFilter,
			Tool:         request.Tool,
			Resource:     request.Resource,
			Status:       request.Status,
		})
		if err != nil {
			return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail alternate runtime access: %w", err)
		}
		runtimeAccess = awsAgentIdentityDetailMergeRuntimeAccessResults(runtimeAccess, alternateRuntimeAccess, agentFilters...)
	}
	runtimeAccess = awsAgentIdentityDetailScopeRuntimeAccess(runtimeAccess, record)
	risk, err := s.GetAWSAIAgentRisk(ctx, workspaceID, projectID, AWSAIAgentRiskRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
		AgentID:      agentFilter,
		Severity:     request.Severity,
		Status:       request.Status,
	})
	if err != nil {
		return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail risk: %w", err)
	}
	for _, alternateAgentFilter := range agentFilters[1:] {
		alternateRisk, err := s.GetAWSAIAgentRisk(ctx, workspaceID, projectID, AWSAIAgentRiskRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			AgentID:      alternateAgentFilter,
			Severity:     request.Severity,
			Status:       request.Status,
		})
		if err != nil {
			return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail alternate risk: %w", err)
		}
		risk = awsAgentIdentityDetailMergeRiskResults(risk, alternateRisk, agentFilters...)
	}
	risk = awsAgentIdentityDetailScopeRisk(risk, record)
	permissionsIdentity := awsAgentIdentityDetailPermissionIdentity(record, agentFilter)
	permissions, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
		Identity:     permissionsIdentity,
		Resource:     request.Resource,
		Severity:     request.Severity,
		Status:       request.Status,
	})
	if err != nil {
		return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail permissions: %w", err)
	}
	permissions = awsAgentIdentityDetailScopePermissions(permissions, record, permissionsIdentity)
	remediationRequest := AWSRemediationCaseRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
		Identity:     permissionsIdentity,
		Severity:     request.Severity,
		Status:       request.Status,
	}
	cases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, remediationRequest)
	if err != nil {
		return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail remediation cases: %w", err)
	}
	agentRemediationIdentity := awsAgentIdentityDetailRemediationAgentIdentity(record, agentFilter)
	if agentRemediationIdentity != "" && !strings.EqualFold(strings.TrimSpace(agentRemediationIdentity), strings.TrimSpace(permissionsIdentity)) {
		agentRemediationRequest := remediationRequest
		agentRemediationRequest.Identity = agentRemediationIdentity
		agentCases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, agentRemediationRequest)
		if err != nil {
			return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail agent remediation cases: %w", err)
		}
		cases = awsAgentIdentityDetailMergeRemediationCaseResults(cases, agentCases, permissionsIdentity, agentRemediationIdentity)
	}
	cases = awsAgentIdentityDetailScopeRemediationCases(cases, record, permissionsIdentity)
	governanceIdentityID, governanceAgentID := awsAgentIdentityDetailGovernanceFilters(record, agentFilter)
	governance, err := s.GetAWSGovernanceAuditReporting(ctx, workspaceID, projectID, AWSGovernanceAuditReportingRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
		IdentityID:   governanceIdentityID,
		AgentID:      governanceAgentID,
		State:        request.Status,
	})
	if err != nil {
		return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail governance: %w", err)
	}
	governanceIdentityFilters := []string{governanceIdentityID}
	governanceAgentFilters := []string{governanceAgentID}
	for _, alternate := range awsAgentIdentityDetailGovernanceAlternateFilters(record, resolved, governanceIdentityID, governanceAgentID) {
		alternateGovernance, err := s.GetAWSGovernanceAuditReporting(ctx, workspaceID, projectID, AWSGovernanceAuditReportingRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			IdentityID:   alternate.IdentityID,
			AgentID:      alternate.AgentID,
			State:        request.Status,
		})
		if err != nil {
			return AWSAgentIdentityDetailResult{}, fmt.Errorf("agent identity detail alternate governance: %w", err)
		}
		governanceIdentityFilters = append(governanceIdentityFilters, alternate.IdentityID)
		governanceAgentFilters = append(governanceAgentFilters, alternate.AgentID)
		governance = awsAgentIdentityDetailMergeGovernanceResults(governance, alternateGovernance, governanceIdentityFilters, governanceAgentFilters)
	}
	governance = awsAgentIdentityDetailScopeGovernance(governance, record)

	tools := awsAgentIdentityDetailTools(record, runtimeAccess.Records, request.Tool)
	capabilities := awsAgentIdentityDetailCapabilities(record)
	secretReferences := awsAgentIdentityDetailSecretReferences(record)
	runtimeCalls := awsAgentIdentityDetailRuntimeCalls(runtimeAccess.Records)
	findings := awsAgentIdentityDetailFindings(risk.Findings)
	recommendations := awsAgentIdentityDetailRecommendations(permissions.Recommendations)
	governanceDecisions := awsMachineIdentityGovernanceDecisions(governance.Records)
	relationships := awsAgentIdentityDetailRelationships(record, inventory, runtimeAccess)
	diagnostics := awsAgentIdentityDetailDiagnostics(inventory, runtimeAccess, risk, permissions, cases, governance)
	coverageGaps := awsAgentIdentityDetailCoverageGaps(resolved, agent, inventory, runtimeAccess, risk, permissions, cases, governance)
	evidenceLinks := awsAgentIdentityDetailEvidenceLinks(scope, project, record, inventory, runtimeAccess, risk, governance)
	status, confidence, failures, hints := summarizeAWSAgentIdentityDetail(fixtureState, resolved, record, diagnostics)
	agentSummary := awsAgentIdentityDetailAgent(agent, record, resolved, accountID, region)
	summary := AWSAgentIdentityDetailSummary{
		ToolCount:               len(tools),
		DeclaredToolCount:       awsAgentIdentityDetailCountTools(tools, func(tool AWSAgentIdentityToolSummary) bool { return tool.Declared }),
		ObservedToolCount:       awsAgentIdentityDetailCountTools(tools, func(tool AWSAgentIdentityToolSummary) bool { return tool.Observed }),
		UndeclaredToolCount:     awsAgentIdentityDetailCountTools(tools, func(tool AWSAgentIdentityToolSummary) bool { return tool.Observed && !tool.Declared }),
		CapabilityCount:         awsAgentIdentityDetailEnabledCapabilityCount(capabilities),
		SecretReferenceCount:    len(secretReferences),
		RuntimeCallCount:        len(runtimeCalls),
		FindingCount:            len(findings),
		RecommendationCount:     len(recommendations),
		RemediationCaseCount:    len(cases.Cases),
		GovernanceDecisionCount: len(governanceDecisions),
		RelationshipCount:       len(relationships),
		EvidenceLinkCount:       len(evidenceLinks),
		DiagnosticCount:         len(diagnostics),
		CoverageGapCount:        len(coverageGaps),
	}

	return AWSAgentIdentityDetailResult{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		AccountID:           accountID,
		Region:              region,
		ParentIssueNumber:   awsPlatformDependencyParentIssue,
		ParentIssueRef:      awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:  awsAgentIdentityDetailCurrentIssue,
		CurrentIssueRef:     awsIssueRef(awsAgentIdentityDetailCurrentIssue),
		Version:             awsAgentIdentityDetailVersion,
		Status:              status,
		FixtureState:        fixtureState,
		Confidence:          confidence,
		PolicyVersion:       awsAgentIdentityDetailPolicyID,
		AppliedFilters:      awsAgentIdentityDetailAppliedFilters(request, agentSummary.AgentNodeID),
		Agent:               agentSummary,
		Summary:             summary,
		Tabs:                awsAgentIdentityDetailTabs(summary, status),
		Tools:               tools,
		Capabilities:        capabilities,
		SecretReferences:    secretReferences,
		RuntimeCalls:        runtimeCalls,
		Findings:            findings,
		Recommendations:     recommendations,
		GovernanceDecisions: governanceDecisions,
		Relationships:       relationships,
		RuntimeAccess:       runtimeAccess,
		Risk:                risk,
		Permissions:         permissions,
		RemediationCases:    cases,
		Governance:          governance,
		FailureReasons:      dedupeStrings(append(failures, awsAgentIdentityDetailFailureReasons(inventory, runtimeAccess, risk, permissions, cases, governance)...)),
		RemediationHints:    dedupeStrings(append(hints, awsAgentIdentityDetailRemediationHints(inventory, runtimeAccess, risk, permissions, cases, governance)...)),
		EvidenceLinks:       evidenceLinks,
		CoverageGaps:        coverageGaps,
		Diagnostics:         diagnostics,
		GeneratedAt:         now,
		UpdatedAt:           now,
	}, nil
}

func normalizeAWSAgentIdentityDetailFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

// awsAgentIdentityDetailResolve finds the inventory record matching the
// requested agent token by ID, ARN, node ID, or name.
func awsAgentIdentityDetailResolve(agent string, records []AWSAIAgentIdentityRecord) (AWSAIAgentIdentityRecord, bool) {
	needle := strings.ToLower(strings.TrimSpace(agent))
	for _, record := range records {
		for _, candidate := range []string{record.AgentID, record.AgentARN, record.AgentNodeID, record.AgentName} {
			if candidate != "" && strings.ToLower(strings.TrimSpace(candidate)) == needle {
				return record, true
			}
		}
	}
	return AWSAIAgentIdentityRecord{}, false
}

func awsAgentIdentityDetailEvidenceAgentFilters(agent string, record AWSAIAgentIdentityRecord, resolved bool) []string {
	if !resolved {
		return []string{"aws-agent-identity-detail-unresolved:" + stableAWSBlastRadiusToken(agent)}
	}
	return emptyStrings(dedupeStrings([]string{record.AgentNodeID, record.AgentID, agent}))
}

func awsAgentIdentityDetailMergeRuntimeAccessResults(primary, secondary AWSAgentRuntimeAccessResult, agentFilters ...string) AWSAgentRuntimeAccessResult {
	primaryRecordsLen := len(primary.Records)
	secondaryRecordsLen := len(secondary.Records)
	primary.Records = awsAgentIdentityDetailDedupeRuntimeAccessRecords(append(append([]AWSAgentRuntimeAccessRecord{}, primary.Records...), secondary.Records...))
	primary.Relationships = awsAgentRuntimeAccessRelationships(primary.Records)
	primary.Summary = awsAgentIdentityDetailRuntimeAccessSummary(primary.Records, primary.Relationships)
	if primaryRecordsLen == 0 && secondaryRecordsLen > 0 {
		primary.Status = secondary.Status
		primary.Confidence = secondary.Confidence
	}
	primary.FailureReasons = dedupeStrings(append(append([]string{}, primary.FailureReasons...), secondary.FailureReasons...))
	primary.RemediationHints = dedupeStrings(append(append([]string{}, primary.RemediationHints...), secondary.RemediationHints...))
	primary.EvidenceLinks = dedupeStrings(append(append([]string{}, primary.EvidenceLinks...), secondary.EvidenceLinks...))
	primary.CoverageGaps = append(append([]AWSAgentRuntimeAccessCoverageGap{}, primary.CoverageGaps...), secondary.CoverageGaps...)
	primary.Diagnostics = append(append([]AWSAgentRuntimeAccessDiagnostic{}, primary.Diagnostics...), secondary.Diagnostics...)
	primary.AppliedFilters = awsAgentIdentityDetailMergeAgentAppliedFilters(primary.AppliedFilters, agentFilters...)
	return primary
}

func awsAgentIdentityDetailDedupeRuntimeAccessRecords(records []AWSAgentRuntimeAccessRecord) []AWSAgentRuntimeAccessRecord {
	out := make([]AWSAgentRuntimeAccessRecord, 0, len(records))
	seen := map[string]struct{}{}
	for _, record := range records {
		key := strings.ToLower(strings.TrimSpace(firstNonEmptyAWSValue(
			record.CorrelationID,
			record.EvidenceRef,
			strings.Join([]string{record.AgentNodeID, record.AgentID, record.ToolName, record.ToolTargetRef}, "|"),
		)))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, record)
	}
	return out
}

func awsAgentIdentityDetailMergeRiskResults(primary, secondary AWSAIAgentRiskResult, agentFilters ...string) AWSAIAgentRiskResult {
	primaryFindingsLen := len(primary.Findings)
	secondaryFindingsLen := len(secondary.Findings)
	primary.Findings = awsAIAgentRiskDedupeFindings(append(append([]AWSAIAgentRiskFinding{}, primary.Findings...), secondary.Findings...))
	primary.Relationships = awsAIAgentRiskRelationships(primary.Findings)
	primary.Summary = summarizeAWSAIAgentRisk(primary.Findings, primary.Findings, primary.Relationships)
	if primaryFindingsLen == 0 && secondaryFindingsLen > 0 {
		primary.Status = secondary.Status
		primary.Confidence = secondary.Confidence
	}
	primary.FailureReasons = dedupeStrings(append(append([]string{}, primary.FailureReasons...), secondary.FailureReasons...))
	primary.RemediationHints = dedupeStrings(append(append([]string{}, primary.RemediationHints...), secondary.RemediationHints...))
	primary.EvidenceLinks = dedupeStrings(append(append([]string{}, primary.EvidenceLinks...), secondary.EvidenceLinks...))
	primary.CoverageGaps = append(append([]AWSAIAgentRiskCoverageGap{}, primary.CoverageGaps...), secondary.CoverageGaps...)
	primary.Diagnostics = append(append([]AWSAIAgentRiskDiagnostic{}, primary.Diagnostics...), secondary.Diagnostics...)
	primary.AppliedFilters = awsAgentIdentityDetailMergeAgentAppliedFilters(primary.AppliedFilters, agentFilters...)
	return primary
}

func awsAgentIdentityDetailMergeAgentAppliedFilters(applied map[string]string, agentFilters ...string) map[string]string {
	filters := map[string]string{}
	for key, value := range applied {
		filters[key] = value
	}
	keys := emptyStrings(dedupeStrings(agentFilters))
	if len(keys) > 0 {
		filters["agent_id"] = keys[0]
	}
	if len(keys) > 1 {
		filters["agent_id_alternates"] = strings.Join(keys[1:], ",")
	}
	return filters
}

func awsAgentIdentityDetailScopeRuntimeAccess(result AWSAgentRuntimeAccessResult, record AWSAIAgentIdentityRecord) AWSAgentRuntimeAccessResult {
	scoped := make([]AWSAgentRuntimeAccessRecord, 0, len(result.Records))
	for _, candidate := range result.Records {
		if awsAgentIdentityDetailMatchesResolvedAgent(record, candidate.AgentNodeID, candidate.AgentID) {
			scoped = append(scoped, candidate)
		}
	}
	result.Records = scoped
	result.Relationships = awsAgentRuntimeAccessRelationships(scoped)
	result.Summary = awsAgentIdentityDetailRuntimeAccessSummary(scoped, result.Relationships)
	return result
}

func awsAgentIdentityDetailRuntimeAccessSummary(records []AWSAgentRuntimeAccessRecord, relationships []AWSAgentRuntimeAccessRelationship) AWSAgentRuntimeAccessSummary {
	summary := AWSAgentRuntimeAccessSummary{
		TotalCorrelations:    len(records),
		FilteredCorrelations: len(records),
		StatusCounts:         map[string]int{},
		RelationshipCount:    len(relationships),
	}
	agentIDs := map[string]struct{}{}
	toolNames := map[string]struct{}{}
	for _, record := range records {
		summary.StatusCounts[record.Status]++
		switch record.Status {
		case "confirmed":
			summary.ConfirmedCount++
		case "observed_without_declaration":
			summary.ObservedWithoutDeclCount++
		case "declared_unused":
			summary.DeclaredUnusedCount++
		}
		if !record.DeclaredInInventory && record.ObservedCount > 0 {
			summary.UndeclaredToolCount++
		}
		if record.DeclaredInInventory {
			summary.DeclaredToolCount++
		}
		summary.ObservedToolCallCount += record.ObservedCount
		if strings.TrimSpace(record.AgentNodeID) != "" {
			agentIDs[strings.ToLower(strings.TrimSpace(record.AgentNodeID))] = struct{}{}
		} else if strings.TrimSpace(record.AgentID) != "" {
			agentIDs[strings.ToLower(strings.TrimSpace(record.AgentID))] = struct{}{}
		}
		if strings.TrimSpace(record.ToolName) != "" {
			toolNames[strings.ToLower(strings.TrimSpace(record.ToolName))] = struct{}{}
		}
	}
	summary.AgentCount = len(agentIDs)
	summary.ToolCount = len(toolNames)
	return summary
}

func awsAgentIdentityDetailScopeRisk(result AWSAIAgentRiskResult, record AWSAIAgentIdentityRecord) AWSAIAgentRiskResult {
	scoped := make([]AWSAIAgentRiskFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if awsAgentIdentityDetailMatchesResolvedAgent(record, finding.AgentNodeID, finding.AgentID) {
			scoped = append(scoped, finding)
		}
	}
	result.Findings = scoped
	result.Relationships = awsAIAgentRiskRelationships(scoped)
	result.Summary = summarizeAWSAIAgentRisk(scoped, scoped, result.Relationships)
	return result
}

func awsAgentIdentityDetailMatchesResolvedAgent(record AWSAIAgentIdentityRecord, values ...string) bool {
	for _, expected := range []string{record.AgentNodeID, record.AgentID} {
		expected = strings.TrimSpace(expected)
		if expected == "" {
			continue
		}
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), expected) {
				return true
			}
		}
	}
	return false
}

func awsAgentIdentityDetailScopePermissions(result AWSLeastPrivilegeResult, record AWSAIAgentIdentityRecord, fallback string) AWSLeastPrivilegeResult {
	targets := awsAgentIdentityDetailPermissionIdentityCandidates(record, fallback)
	scoped := make([]AWSLeastPrivilegeRecommendation, 0, len(result.Recommendations))
	for _, recommendation := range result.Recommendations {
		if awsAgentIdentityDetailAnyExactMatch(targets, awsLeastPrivilegeIdentityMatchValues(recommendation)...) &&
			awsAgentIdentityDetailRecommendationMatchesAgentScope(record, recommendation) {
			scoped = append(scoped, recommendation)
		}
	}
	result.Recommendations = scoped
	result.Relationships = awsLeastPrivilegeRelationships(scoped)
	result.Summary = summarizeAWSLeastPrivilege(scoped, scoped, result.Relationships)
	return result
}

func awsAgentIdentityDetailScopeRemediationCases(result AWSRemediationCaseResult, record AWSAIAgentIdentityRecord, fallback string) AWSRemediationCaseResult {
	targets := awsAgentIdentityDetailRemediationCaseIdentityCandidates(record, fallback)
	scoped := make([]AWSRemediationCase, 0, len(result.Cases))
	for _, c := range result.Cases {
		if awsAgentIdentityDetailAnyExactMatch(targets, awsAgentIdentityDetailRemediationCaseIdentityValues(c)...) &&
			awsAgentIdentityDetailRemediationCaseMatchesAgentScope(record, c) {
			scoped = append(scoped, c)
		}
	}
	result.Cases = scoped
	result.Relationships = awsRemediationCaseRelationships(scoped)
	result.Summary = summarizeAWSRemediationCases(scoped, scoped, result.Relationships)
	return result
}

func awsAgentIdentityDetailMergeRemediationCaseResults(primary, secondary AWSRemediationCaseResult, identities ...string) AWSRemediationCaseResult {
	mergedCases := awsRemediationCaseDedupe(append(append([]AWSRemediationCase{}, primary.Cases...), secondary.Cases...))
	primary.Cases = mergedCases
	primary.Relationships = awsRemediationCaseRelationships(mergedCases)
	primary.Summary = summarizeAWSRemediationCases(mergedCases, mergedCases, primary.Relationships)
	primary.FailureReasons = dedupeStrings(append(append([]string{}, primary.FailureReasons...), secondary.FailureReasons...))
	primary.RemediationHints = dedupeStrings(append(append([]string{}, primary.RemediationHints...), secondary.RemediationHints...))
	primary.EvidenceLinks = dedupeStrings(append(append([]string{}, primary.EvidenceLinks...), secondary.EvidenceLinks...))
	primary.CoverageGaps = append(append([]AWSRemediationCaseCoverageGap{}, primary.CoverageGaps...), secondary.CoverageGaps...)
	filters := map[string]string{}
	for key, value := range primary.AppliedFilters {
		filters[key] = value
	}
	identityFilters := emptyStrings(dedupeStrings(identities))
	if len(identityFilters) > 0 {
		filters["identity"] = identityFilters[0]
	}
	if len(identityFilters) > 1 {
		filters["agent_identity"] = identityFilters[1]
	}
	primary.AppliedFilters = filters
	return primary
}

func awsAgentIdentityDetailRecommendationMatchesAgentScope(record AWSAIAgentIdentityRecord, recommendation AWSLeastPrivilegeRecommendation) bool {
	values := []string{}
	agentScoped := strings.EqualFold(normalizeAWSRuntimeEventFilterToken(recommendation.Service), "agent-runtime") ||
		strings.Contains(normalizeAWSRuntimeEventFilterToken(recommendation.RecommendationType), "agent")
	for _, evidence := range recommendation.Evidence {
		if strings.EqualFold(normalizeAWSRuntimeEventFilterToken(evidence.Source), "agent-runtime-access") {
			agentScoped = true
		}
	}
	values = append(values, recommendation.ImpactedNodes...)
	for _, step := range recommendation.ImpactedPath {
		if strings.EqualFold(strings.TrimSpace(step.NodeType), "ai_agent") {
			agentScoped = true
		}
		values = append(values, step.NodeID, step.Label)
	}
	if !agentScoped {
		return true
	}
	return awsAgentIdentityDetailMatchesResolvedAgent(record, values...)
}

func awsAgentIdentityDetailRemediationCaseMatchesAgentScope(record AWSAIAgentIdentityRecord, c AWSRemediationCase) bool {
	values := append([]string{}, c.ImpactedNodes...)
	agentScoped := false
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "aws:agent:") {
			agentScoped = true
			break
		}
	}
	for _, step := range c.ImpactedPath {
		if strings.EqualFold(strings.TrimSpace(step.NodeType), "ai_agent") {
			agentScoped = true
		}
		values = append(values, step.NodeID, step.Label)
	}
	if !agentScoped {
		return true
	}
	return awsAgentIdentityDetailMatchesResolvedAgent(record, values...)
}

func awsAgentIdentityDetailPermissionIdentityCandidates(record AWSAIAgentIdentityRecord, fallback string) []string {
	roleTargets := emptyStrings(dedupeStrings([]string{
		record.RuntimeRoleNodeID,
		awsIdentityNodeIDForAPI(record.RuntimeRoleARN),
		record.RuntimeRoleARN,
		record.RuntimeRoleName,
	}))
	if len(roleTargets) > 0 {
		return roleTargets
	}
	return emptyStrings(dedupeStrings([]string{record.AgentNodeID, record.AgentID, fallback}))
}

func awsAgentIdentityDetailRemediationCaseIdentityCandidates(record AWSAIAgentIdentityRecord, fallback string) []string {
	roleTargets := emptyStrings(dedupeStrings([]string{
		record.RuntimeRoleNodeID,
		awsIdentityNodeIDForAPI(record.RuntimeRoleARN),
		record.RuntimeRoleARN,
		record.RuntimeRoleName,
	}))
	agentTargets := emptyStrings(dedupeStrings([]string{
		record.AgentNodeID,
		record.AgentID,
		fallback,
	}))
	return emptyStrings(dedupeStrings(append(roleTargets, agentTargets...)))
}

func awsAgentIdentityDetailRemediationCaseIdentityValues(c AWSRemediationCase) []string {
	values := []string{c.IdentityNodeID, c.IdentityARN, c.IdentityName}
	if strings.EqualFold(c.SourceType, "aws_permission_boundary_scp") {
		values = append(values, c.ResourceNodeIDs...)
	}
	return dedupeStrings(values)
}

func awsAgentIdentityDetailAnyExactMatch(targets []string, values ...string) bool {
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), target) {
				return true
			}
		}
	}
	return false
}

func awsAgentIdentityDetailPermissionIdentity(record AWSAIAgentIdentityRecord, fallback string) string {
	return firstNonEmptyAWSValue(
		record.RuntimeRoleNodeID,
		awsIdentityNodeIDForAPI(record.RuntimeRoleARN),
		record.RuntimeRoleARN,
		record.RuntimeRoleName,
		record.AgentNodeID,
		fallback,
	)
}

func awsAgentIdentityDetailRemediationAgentIdentity(record AWSAIAgentIdentityRecord, fallback string) string {
	return firstNonEmptyAWSValue(record.AgentNodeID, record.AgentID, fallback)
}

func awsAgentIdentityDetailGovernanceFilters(record AWSAIAgentIdentityRecord, agentFilter string) (string, string) {
	roleIdentity := firstNonEmptyAWSValue(record.RuntimeRoleNodeID, awsIdentityNodeIDForAPI(record.RuntimeRoleARN))
	if roleIdentity != "" {
		return roleIdentity, ""
	}
	return "", agentFilter
}

// awsAgentIdentityDetailGovernanceFilter is one exact-scoped governance audit
// query. The governance filter matches identity_id and agent_id exactly, so a
// single primary query misses rows keyed by an alternate exact key (an
// agent-scoped advisory row for a role-backed agent, or a role row keyed by
// the raw role ARN instead of the identity node ID).
type awsAgentIdentityDetailGovernanceFilter struct {
	IdentityID string
	AgentID    string
}

func awsAgentIdentityDetailGovernanceAlternateFilters(record AWSAIAgentIdentityRecord, resolved bool, primaryIdentityID, primaryAgentID string) []awsAgentIdentityDetailGovernanceFilter {
	if !resolved {
		return nil
	}
	alternates := []awsAgentIdentityDetailGovernanceFilter{}
	for _, identity := range emptyStrings(dedupeStrings([]string{record.RuntimeRoleNodeID, awsIdentityNodeIDForAPI(record.RuntimeRoleARN), record.RuntimeRoleARN})) {
		if strings.EqualFold(identity, strings.TrimSpace(primaryIdentityID)) {
			continue
		}
		alternates = append(alternates, awsAgentIdentityDetailGovernanceFilter{IdentityID: identity})
	}
	for _, agentKey := range emptyStrings(dedupeStrings([]string{record.AgentNodeID, record.AgentID})) {
		if strings.EqualFold(agentKey, strings.TrimSpace(primaryAgentID)) {
			continue
		}
		alternates = append(alternates, awsAgentIdentityDetailGovernanceFilter{AgentID: agentKey})
	}
	return alternates
}

func awsAgentIdentityDetailMergeGovernanceResults(primary, secondary AWSGovernanceAuditReportingResult, identityFilters, agentFilters []string) AWSGovernanceAuditReportingResult {
	primaryRecordsLen := len(primary.Records)
	secondaryRecordsLen := len(secondary.Records)
	merged := make([]AWSGovernanceAuditReportRecord, 0, primaryRecordsLen+secondaryRecordsLen)
	seen := map[string]struct{}{}
	for _, record := range append(append([]AWSGovernanceAuditReportRecord{}, primary.Records...), secondary.Records...) {
		key := strings.ToLower(strings.TrimSpace(firstNonEmptyAWSValue(
			record.ReportID,
			strings.Join([]string{record.Category, record.SourceType, record.SourceID, record.State}, "|"),
		)))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, record)
	}
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].OccurredAt.Equal(merged[j].OccurredAt) {
			return merged[i].ReportID < merged[j].ReportID
		}
		return merged[i].OccurredAt.After(merged[j].OccurredAt)
	})
	primary.Records = merged
	primary.Summary = summarizeAWSGovernanceAuditReportRecords(merged, merged)
	if primaryRecordsLen == 0 && secondaryRecordsLen > 0 {
		primary.Status = secondary.Status
		primary.Confidence = secondary.Confidence
	}
	primary.FailureReasons = dedupeStrings(append(append([]string{}, primary.FailureReasons...), secondary.FailureReasons...))
	primary.RemediationHints = dedupeStrings(append(append([]string{}, primary.RemediationHints...), secondary.RemediationHints...))
	primary.EvidenceLinks = dedupeStrings(append(append([]string{}, primary.EvidenceLinks...), secondary.EvidenceLinks...))
	primary.CoverageGaps = append(append([]AWSGovernanceAuditReportingCoverageGap{}, primary.CoverageGaps...), secondary.CoverageGaps...)
	primary.Diagnostics = append(append([]AWSGovernanceAuditReportingDiagnostic{}, primary.Diagnostics...), secondary.Diagnostics...)
	primary.AppliedFilters = awsAgentIdentityDetailMergeGovernanceAppliedFilters(primary.AppliedFilters, identityFilters, agentFilters)
	return primary
}

func awsAgentIdentityDetailMergeGovernanceAppliedFilters(applied map[string]string, identityFilters, agentFilters []string) map[string]string {
	filters := map[string]string{}
	for key, value := range applied {
		filters[key] = value
	}
	identities := emptyStrings(dedupeStrings(identityFilters))
	if len(identities) > 0 {
		filters["identity_id"] = identities[0]
	}
	if len(identities) > 1 {
		filters["identity_id_alternates"] = strings.Join(identities[1:], ",")
	}
	agents := emptyStrings(dedupeStrings(agentFilters))
	if len(agents) > 0 {
		filters["agent_id"] = agents[0]
	}
	if len(agents) > 1 {
		filters["agent_id_alternates"] = strings.Join(agents[1:], ",")
	}
	return filters
}

// awsAgentIdentityDetailScopeGovernance drops agent-scoped governance rows
// that belong to a different agent — for example a sibling agent sharing the
// selected agent's runtime role, whose advisory rows carry the shared
// identity_id and therefore pass the identity-scoped query filter — while
// keeping truly role-wide rows that carry no agent key.
func awsAgentIdentityDetailScopeGovernance(result AWSGovernanceAuditReportingResult, record AWSAIAgentIdentityRecord) AWSGovernanceAuditReportingResult {
	scoped := make([]AWSGovernanceAuditReportRecord, 0, len(result.Records))
	for _, candidate := range result.Records {
		agentScoped := strings.TrimSpace(candidate.AgentID) != "" || strings.TrimSpace(candidate.AgentNodeID) != ""
		if agentScoped && !awsAgentIdentityDetailMatchesResolvedAgent(record, candidate.AgentNodeID, candidate.AgentID) {
			continue
		}
		scoped = append(scoped, candidate)
	}
	result.Records = scoped
	result.Summary = summarizeAWSGovernanceAuditReportRecords(scoped, scoped)
	return result
}

func awsAgentIdentityDetailAgent(agent string, record AWSAIAgentIdentityRecord, resolved bool, accountID, region string) AWSAgentIdentityDetailAgent {
	if !resolved {
		return AWSAgentIdentityDetailAgent{
			Agent:            agent,
			DisplayName:      agent,
			AccountID:        accountID,
			Region:           region,
			Status:           "unknown",
			Resolved:         false,
			Candidate:        true,
			LowConfidence:    true,
			EvidenceBoundary: awsAgentIdentityDetailEvidenceBoundary(),
		}
	}
	status := firstNonEmptyAWSValue(record.Status, "active")
	candidate := strings.EqualFold(status, "candidate") || strings.EqualFold(record.CoverageStatus, "degraded")
	return AWSAgentIdentityDetailAgent{
		Agent:             agent,
		AgentID:           record.AgentID,
		AgentARN:          record.AgentARN,
		AgentNodeID:       record.AgentNodeID,
		AgentName:         record.AgentName,
		AgentType:         record.AgentType,
		DisplayName:       firstNonEmptyAWSValue(record.AgentName, record.AgentID, agent),
		Provider:          record.Provider,
		ModelID:           record.ModelID,
		Service:           record.Service,
		RuntimeVersion:    record.RuntimeVersion,
		RuntimeRoleARN:    record.RuntimeRoleARN,
		RuntimeRoleName:   record.RuntimeRoleName,
		RuntimeRoleNodeID: record.RuntimeRoleNodeID,
		GatewayID:         record.GatewayID,
		GatewayNodeID:     record.GatewayNodeID,
		ExternalProvider:  record.ExternalProvider,
		AuthMode:          record.AuthMode,
		AccountID:         firstNonEmptyAWSValue(record.AccountID, accountID),
		Region:            firstNonEmptyAWSValue(record.Region, region),
		Status:            status,
		Resolved:          true,
		Candidate:         candidate,
		LowConfidence:     record.Confidence < awsAgentIdentityDetailLowConfidenceFloor,
		Confidence:        record.Confidence,
		CoverageStatus:    record.CoverageStatus,
		CoverageReason:    record.CoverageReason,
		EvidenceRef:       record.EvidenceRef,
		EvidenceBoundary:  awsAgentIdentityDetailEvidenceBoundary(),
	}
}

// awsAgentIdentityDetailTools merges declared inventory tools with observed
// runtime correlations so declared-unused and observed-undeclared tools are
// explicit rows.
func awsAgentIdentityDetailTools(record AWSAIAgentIdentityRecord, runtime []AWSAgentRuntimeAccessRecord, toolFilters ...string) []AWSAgentIdentityToolSummary {
	byName := map[string]*AWSAgentIdentityToolSummary{}
	order := []string{}
	targetRefs := map[string]string{}
	toolFilter := ""
	if len(toolFilters) > 0 {
		toolFilter = strings.TrimSpace(toolFilters[0])
	}
	for i, name := range record.ToolNames {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if i < len(record.ToolTargetRefs) {
			targetRefs[strings.ToLower(trimmed)] = record.ToolTargetRefs[i]
		}
		if toolFilter != "" && !awsRuntimeEventMatchesAny(toolFilter, trimmed, targetRefs[strings.ToLower(trimmed)]) {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := byName[key]; ok {
			continue
		}
		byName[key] = &AWSAgentIdentityToolSummary{
			ToolName:      trimmed,
			ToolTargetRef: targetRefs[key],
			Declared:      true,
			Status:        "declared_unused",
			EvidenceRef:   record.EvidenceRef,
		}
		order = append(order, key)
	}
	for _, correlation := range runtime {
		name := strings.TrimSpace(correlation.ToolName)
		if name == "" {
			continue
		}
		if toolFilter != "" && !awsRuntimeEventMatchesAny(toolFilter, name, correlation.ToolTargetRef) {
			continue
		}
		key := strings.ToLower(name)
		tool, ok := byName[key]
		if !ok {
			tool = &AWSAgentIdentityToolSummary{
				ToolName:      name,
				ToolTargetRef: correlation.ToolTargetRef,
				Status:        "observed_undeclared",
			}
			byName[key] = tool
			order = append(order, key)
		}
		if awsAgentIdentityDetailRuntimeToolObserved(correlation) {
			tool.Observed = true
			tool.ObservedCount += correlation.ObservedCount
		}
		if tool.Declared {
			tool.Status = firstNonEmptyAWSValue(correlation.Status, "confirmed")
		} else {
			tool.Status = firstNonEmptyAWSValue(correlation.Status, "observed_undeclared")
		}
		if tool.ToolTargetRef == "" {
			tool.ToolTargetRef = correlation.ToolTargetRef
		}
		if tool.EvidenceRef == "" {
			tool.EvidenceRef = correlation.EvidenceRef
		}
		if correlation.LastObservedAt.After(tool.LastObserved) {
			tool.LastObserved = correlation.LastObservedAt
		}
	}
	out := make([]AWSAgentIdentityToolSummary, 0, len(order))
	for _, key := range order {
		out = append(out, *byName[key])
	}
	return out
}

func awsAgentIdentityDetailRuntimeToolObserved(correlation AWSAgentRuntimeAccessRecord) bool {
	if strings.EqualFold(strings.TrimSpace(correlation.Status), "declared_unused") {
		return false
	}
	return correlation.ObservedCount > 0
}

func awsAgentIdentityDetailCountTools(tools []AWSAgentIdentityToolSummary, match func(AWSAgentIdentityToolSummary) bool) int {
	count := 0
	for _, tool := range tools {
		if match(tool) {
			count++
		}
	}
	return count
}

func awsAgentIdentityDetailCapabilities(record AWSAIAgentIdentityRecord) []AWSAgentIdentityCapabilitySummary {
	return []AWSAgentIdentityCapabilitySummary{
		{
			Capability:       "memory",
			Enabled:          record.MemoryEnabled || len(record.MemoryStoreRefs) > 0,
			ReferenceRefs:    emptyStrings(dedupeStrings(record.MemoryStoreRefs)),
			EncryptionKeyARN: record.EncryptionKeyARN,
		},
		{
			Capability:    "browser",
			Enabled:       record.BrowserEnabled,
			ReferenceRefs: awsAgentIdentityDetailCapabilityRefs(record, "browser"),
		},
		{
			Capability:    "code_interpreter",
			Enabled:       record.CodeInterpreterEnabled,
			ReferenceRefs: awsAgentIdentityDetailCapabilityRefs(record, "code_interpreter"),
		},
	}
}

// awsAgentIdentityDetailCapabilityRefs attributes storage references to the
// browser/code-interpreter capability record they belong to; the inventory
// carries capability-scoped records with a CapabilityKind marker.
func awsAgentIdentityDetailCapabilityRefs(record AWSAIAgentIdentityRecord, kind string) []string {
	if !strings.EqualFold(record.CapabilityKind, kind) {
		return nil
	}
	return emptyStrings(dedupeStrings(record.StorageReferenceRefs))
}

func awsAgentIdentityDetailEnabledCapabilityCount(capabilities []AWSAgentIdentityCapabilitySummary) int {
	count := 0
	for _, capability := range capabilities {
		if capability.Enabled {
			count++
		}
	}
	return count
}

func awsAgentIdentityDetailSecretReferences(record AWSAIAgentIdentityRecord) []AWSAgentIdentitySecretReference {
	out := []AWSAgentIdentitySecretReference{}
	seen := map[string]struct{}{}
	for _, reference := range record.ProviderKeyReferences {
		key := strings.ToLower(strings.TrimSpace(reference.Reference))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, AWSAgentIdentitySecretReference{
			Reference:     reference.Reference,
			ReferenceName: reference.ReferenceName,
			ReferenceKind: reference.ReferenceKind,
			Provider:      reference.Provider,
			Sensitivity:   reference.Sensitivity,
			Resolved:      reference.Resolved,
			TargetNodeID:  reference.TargetNodeID,
			EvidenceRef:   reference.EvidenceRef,
			Confidence:    reference.Confidence,
		})
	}
	for _, reference := range record.CredentialReferenceRefs {
		key := strings.ToLower(strings.TrimSpace(reference))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, AWSAgentIdentitySecretReference{
			Reference:     reference,
			ReferenceKind: "credential_reference",
			EvidenceRef:   record.EvidenceRef,
			Confidence:    record.Confidence,
		})
	}
	return out
}

func awsAgentIdentityDetailRuntimeCalls(records []AWSAgentRuntimeAccessRecord) []AWSAgentIdentityRuntimeCall {
	out := make([]AWSAgentIdentityRuntimeCall, 0, len(records))
	for _, record := range records {
		out = append(out, AWSAgentIdentityRuntimeCall{
			CorrelationID: record.CorrelationID,
			ToolName:      record.ToolName,
			ToolTargetRef: record.ToolTargetRef,
			Status:        record.Status,
			ObservedCount: record.ObservedCount,
			Outcomes:      emptyStrings(dedupeStrings(record.Outcomes)),
			TargetARNs:    emptyStrings(dedupeStrings(record.TargetResourceARNs)),
			EvidenceRef:   record.EvidenceRef,
			NextAction:    record.NextAction,
			LastObserved:  record.LastObservedAt,
		})
	}
	return out
}

func awsAgentIdentityDetailFindings(findings []AWSAIAgentRiskFinding) []AWSAgentIdentityFindingSummary {
	out := make([]AWSAgentIdentityFindingSummary, 0, len(findings))
	for _, finding := range findings {
		out = append(out, AWSAgentIdentityFindingSummary{
			FindingID:    finding.FindingID,
			RiskType:     finding.RiskType,
			Severity:     finding.Severity,
			Status:       finding.Status,
			Score:        finding.Score,
			Rationale:    finding.Rationale,
			NextAction:   finding.NextAction,
			EvidenceRefs: awsLeastPrivilegeEvidenceRefs(finding.Evidence),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].FindingID < out[j].FindingID
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func awsAgentIdentityDetailRecommendations(recommendations []AWSLeastPrivilegeRecommendation) []AWSAgentIdentityRecommendationSummary {
	out := make([]AWSAgentIdentityRecommendationSummary, 0, len(recommendations))
	for _, recommendation := range recommendations {
		out = append(out, AWSAgentIdentityRecommendationSummary{
			RecommendationID: recommendation.RecommendationID,
			Decision:         recommendation.Decision,
			Severity:         recommendation.Severity,
			Status:           recommendation.Status,
			Service:          recommendation.Service,
			DisplayName:      recommendation.DisplayName,
			Rationale:        recommendation.Rationale,
			NextAction:       recommendation.NextAction,
			Score:            recommendation.Score,
			Confidence:       recommendation.Confidence,
		})
	}
	return out
}

func awsAgentIdentityDetailRelationships(record AWSAIAgentIdentityRecord, inventory AWSAIAgentIdentityInventoryResult, runtime AWSAgentRuntimeAccessResult) []AWSAgentIdentityDetailRelationship {
	out := []AWSAgentIdentityDetailRelationship{}
	for _, relation := range awsAIAgentIdentityRelationshipsForRecord(record, inventory.Relationships) {
		out = append(out, AWSAgentIdentityDetailRelationship{
			Source:      "ai_agent_identities",
			Type:        relation.Type,
			FromNodeID:  relation.FromNodeID,
			ToNodeID:    relation.ToNodeID,
			EvidenceRef: relation.EvidenceRef,
		})
	}
	for _, relation := range runtime.Relationships {
		out = append(out, AWSAgentIdentityDetailRelationship{
			Source:      "agent_runtime_access",
			Type:        relation.Type,
			FromNodeID:  relation.FromNodeID,
			ToNodeID:    relation.ToNodeID,
			EvidenceRef: relation.EvidenceRef,
		})
	}
	return awsMachineIdentityDedupeRelationships(out)
}

func awsAgentIdentityDetailAppliedFilters(request AWSAgentIdentityDetailRequest, agentNodeID string) map[string]string {
	filters := map[string]string{}
	set := func(key, value string) {
		value = strings.TrimSpace(value)
		if value != "" && !strings.EqualFold(value, "all") {
			filters[key] = value
		}
	}
	set("agent", request.Agent)
	set("agent_node_id", agentNodeID)
	set("account_id", request.AccountID)
	set("region", request.Region)
	set("tab", request.Tab)
	set("tool", request.Tool)
	set("resource", request.Resource)
	set("severity", request.Severity)
	set("status", request.Status)
	return filters
}

func awsAgentIdentityDetailTabs(summary AWSAgentIdentityDetailSummary, status string) []AWSAgentIdentityDetailTab {
	tabStatus := status
	if tabStatus == "" {
		tabStatus = "success"
	}
	return []AWSAgentIdentityDetailTab{
		{ID: "overview", Label: "Overview", Status: tabStatus, Count: summary.ToolCount + summary.CapabilityCount},
		{ID: "tools", Label: "Tools", Status: tabStatus, Count: summary.ToolCount},
		{ID: "runtime", Label: "Runtime", Status: tabStatus, Count: summary.RuntimeCallCount},
		{ID: "secrets", Label: "Secrets", Status: tabStatus, Count: summary.SecretReferenceCount},
		{ID: "findings", Label: "Findings", Status: tabStatus, Count: summary.FindingCount},
		{ID: "recommendations", Label: "Recommendations", Status: tabStatus, Count: summary.RecommendationCount},
		{ID: "remediation", Label: "Remediation", Status: tabStatus, Count: summary.RemediationCaseCount},
		{ID: "governance", Label: "Governance", Status: tabStatus, Count: summary.GovernanceDecisionCount},
	}
}

func summarizeAWSAgentIdentityDetail(fixtureState string, resolved bool, record AWSAIAgentIdentityRecord, diagnostics []AWSAgentIdentityDetailDiagnostic) (string, float64, []string, []string) {
	failures := []string{}
	hints := []string{}
	switch fixtureState {
	case "permission_denied":
		return "permission_denied", 0.2, []string{"AWS connection is not authorized for this environment."}, []string{"Reconnect the AWS connector with read-only agent inventory permissions."}
	case "empty":
		return "empty", 0.5, failures, []string{"No agent identity evidence matched the selected account, region, and agent filters."}
	case "degraded", "partial_failure":
		failures = append(failures, "One or more agent evidence sources are degraded for this environment.")
		hints = append(hints, "Retry the degraded collectors before treating missing evidence as absence of risk.")
	}
	if !resolved {
		failures = append(failures, "The requested agent was not found in the AI agent inventory for this environment.")
		hints = append(hints, "Open the agent from the AWS agents inventory so the detail request carries a known agent ID, ARN, or node ID.")
		return "unknown", 0.3, failures, hints
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return "degraded", 0.7, failures, hints
		}
	}
	if fixtureState == "degraded" || fixtureState == "partial_failure" {
		return "degraded", 0.7, failures, hints
	}
	confidence := record.Confidence
	if confidence == 0 {
		confidence = 0.75
	}
	if record.Confidence > 0 && record.Confidence < awsAgentIdentityDetailLowConfidenceFloor {
		hints = append(hints, "Agent confidence is below the detail-page floor; refresh runtime evidence before acting on inferred bindings.")
	}
	return "success", confidence, failures, hints
}

func awsAgentIdentityDetailFailureReasons(inventory AWSAIAgentIdentityInventoryResult, runtime AWSAgentRuntimeAccessResult, risk AWSAIAgentRiskResult, permissions AWSLeastPrivilegeResult, cases AWSRemediationCaseResult, governance AWSGovernanceAuditReportingResult) []string {
	out := []string{}
	out = append(out, inventory.FailureReasons...)
	out = append(out, runtime.FailureReasons...)
	out = append(out, risk.FailureReasons...)
	out = append(out, permissions.FailureReasons...)
	out = append(out, cases.FailureReasons...)
	out = append(out, governance.FailureReasons...)
	return dedupeStrings(out)
}

func awsAgentIdentityDetailRemediationHints(inventory AWSAIAgentIdentityInventoryResult, runtime AWSAgentRuntimeAccessResult, risk AWSAIAgentRiskResult, permissions AWSLeastPrivilegeResult, cases AWSRemediationCaseResult, governance AWSGovernanceAuditReportingResult) []string {
	out := []string{}
	out = append(out, inventory.RemediationHints...)
	out = append(out, runtime.RemediationHints...)
	out = append(out, risk.RemediationHints...)
	out = append(out, permissions.RemediationHints...)
	out = append(out, cases.RemediationHints...)
	out = append(out, governance.RemediationHints...)
	return dedupeStrings(out)
}

func awsAgentIdentityDetailDiagnostics(inventory AWSAIAgentIdentityInventoryResult, runtime AWSAgentRuntimeAccessResult, risk AWSAIAgentRiskResult, permissions AWSLeastPrivilegeResult, cases AWSRemediationCaseResult, governance AWSGovernanceAuditReportingResult) []AWSAgentIdentityDetailDiagnostic {
	out := []AWSAgentIdentityDetailDiagnostic{}
	for _, diagnostic := range inventory.Diagnostics {
		out = append(out, AWSAgentIdentityDetailDiagnostic(diagnostic))
	}
	for _, diagnostic := range runtime.Diagnostics {
		out = append(out, AWSAgentIdentityDetailDiagnostic(diagnostic))
	}
	for _, diagnostic := range risk.Diagnostics {
		out = append(out, AWSAgentIdentityDetailDiagnostic(diagnostic))
	}
	out = append(out, awsMachineIdentityDetailDiagnostics(permissions, cases, governance)...)
	return awsMachineIdentityDedupeDiagnostics(out)
}

func awsAgentIdentityDetailCoverageGaps(resolved bool, agent string, inventory AWSAIAgentIdentityInventoryResult, runtime AWSAgentRuntimeAccessResult, risk AWSAIAgentRiskResult, permissions AWSLeastPrivilegeResult, cases AWSRemediationCaseResult, governance AWSGovernanceAuditReportingResult) []AWSAgentIdentityDetailCoverageGap {
	out := []AWSAgentIdentityDetailCoverageGap{}
	if !resolved {
		out = append(out, AWSAgentIdentityDetailCoverageGap{
			Capability:  "agent_inventory_resolution",
			Status:      "unknown",
			Reason:      fmt.Sprintf("Agent %q was not found in the AI agent inventory for this environment.", agent),
			Remediation: "Open the agent from the AWS agents inventory or verify the agent ID, ARN, or node ID.",
		})
	}
	for _, gap := range inventory.CoverageGaps {
		out = append(out, AWSAgentIdentityDetailCoverageGap(gap))
	}
	for _, gap := range runtime.CoverageGaps {
		out = append(out, AWSAgentIdentityDetailCoverageGap(gap))
	}
	for _, gap := range risk.CoverageGaps {
		out = append(out, AWSAgentIdentityDetailCoverageGap(gap))
	}
	out = append(out, awsMachineIdentityDetailCoverageGaps(permissions, cases, governance)...)
	return out
}

func awsAgentIdentityDetailEvidenceLinks(scope db.Scope, project db.TenancyProject, record AWSAIAgentIdentityRecord, inventory AWSAIAgentIdentityInventoryResult, runtime AWSAgentRuntimeAccessResult, risk AWSAIAgentRiskResult, governance AWSGovernanceAuditReportingResult) []string {
	links := []string{
		awsIssueURL(awsPlatformDependencyParentIssue),
		awsIssueURL(awsAgentIdentityDetailCurrentIssue),
		"/docs/aws-agent-identity-detail",
		"/docs/aws-ai-agent-identities",
		"/docs/aws-agent-runtime-access",
		"/docs/aws-ai-agent-risk",
		awsBaselineProjectEvidenceURL(scope, project),
	}
	if strings.TrimSpace(record.EvidenceRef) != "" {
		links = append(links, record.EvidenceRef)
	}
	links = append(links, inventory.EvidenceLinks...)
	links = append(links, runtime.EvidenceLinks...)
	links = append(links, risk.EvidenceLinks...)
	links = append(links, governance.EvidenceLinks...)
	return dedupeStrings(links)
}

func awsAgentIdentityDetailEvidenceBoundary() string {
	return "metadata_only_no_secret_values_no_prompt_text_no_tool_payloads_no_workload_data_tenant_workspace_project_connector_account_region_scoped"
}
