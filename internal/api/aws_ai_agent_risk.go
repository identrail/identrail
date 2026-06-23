package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsAIAgentRiskCurrentIssue = 1528
	awsAIAgentRiskVersion      = "aws-ai-agent-risk-engine-v1"
)

// AWSAIAgentRiskRequest scopes the deterministic AI agent risk engine to one
// AWS connector plus optional operator drill-down filters.
type AWSAIAgentRiskRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	RiskType     string `json:"risk_type,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Status       string `json:"status,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSAIAgentRiskEvidence = AWSLeastPrivilegeEvidence
type AWSAIAgentRiskPathStep = AWSLeastPrivilegePathStep
type AWSAIAgentRiskRemediationCasePreview = AWSLeastPrivilegeRemediationCasePreview
type AWSAIAgentRiskDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSAIAgentRiskCoverageGap = AWSLeastPrivilegeCoverageGap

type AWSAIAgentRiskRelationship struct {
	FindingID   string `json:"finding_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSAIAgentRiskFinding is the persisted-record-shaped intelligence contract
// emitted by the AI agent risk engine. It intentionally carries only metadata
// evidence refs and graph nodes, never prompts, completions, tool payloads,
// browser pages, code-interpreter output, database rows, object contents, or
// secret values.
type AWSAIAgentRiskFinding struct {
	FindingID          string                               `json:"finding_id"`
	CalculationVersion string                               `json:"calculation_version"`
	RiskType           string                               `json:"risk_type"`
	Severity           string                               `json:"severity"`
	Status             string                               `json:"status"`
	Score              int                                  `json:"score"`
	Confidence         float64                              `json:"confidence"`
	AccountID          string                               `json:"account_id"`
	Region             string                               `json:"region"`
	AgentNodeID        string                               `json:"agent_node_id"`
	AgentID            string                               `json:"agent_id,omitempty"`
	AgentName          string                               `json:"agent_name,omitempty"`
	AgentType          string                               `json:"agent_type,omitempty"`
	RuntimeRoleARN     string                               `json:"runtime_role_arn,omitempty"`
	RuntimeRoleNodeID  string                               `json:"runtime_role_node_id,omitempty"`
	Provider           string                               `json:"provider,omitempty"`
	ToolNames          []string                             `json:"tool_names,omitempty"`
	CapabilityNames    []string                             `json:"capability_names,omitempty"`
	SensitiveResources []string                             `json:"sensitive_resources,omitempty"`
	SourceSignals      []string                             `json:"source_signals"`
	Rationale          string                               `json:"rationale"`
	EvidenceBoundary   string                               `json:"evidence_boundary"`
	ImpactedNodes      []string                             `json:"impacted_nodes"`
	ImpactedPath       []AWSAIAgentRiskPathStep             `json:"impacted_path"`
	Evidence           []AWSAIAgentRiskEvidence             `json:"evidence"`
	NextAction         string                               `json:"next_action"`
	RemediationCase    AWSAIAgentRiskRemediationCasePreview `json:"remediation_case"`
	CreatedAt          time.Time                            `json:"created_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

type AWSAIAgentRiskSummary struct {
	TotalFindings              int            `json:"total_findings"`
	FilteredFindings           int            `json:"filtered_findings"`
	SeverityCounts             map[string]int `json:"severity_counts"`
	StatusCounts               map[string]int `json:"status_counts"`
	RiskTypeCounts             map[string]int `json:"risk_type_counts"`
	ExternalCredentialCount    int            `json:"external_credential_count"`
	BroadToolAccessCount       int            `json:"broad_tool_access_count"`
	SensitiveReachabilityCount int            `json:"sensitive_reachability_count"`
	OwnerlessAgentCount        int            `json:"ownerless_agent_count"`
	RuntimeObservedCount       int            `json:"runtime_observed_count"`
	BackingRoleScopeCount      int            `json:"backing_role_scope_count"`
	RelationshipCount          int            `json:"relationship_count"`
	HighestScore               int            `json:"highest_score"`
	AverageConfidencePct       int            `json:"average_confidence_pct"`
	RemediationPreviewCount    int            `json:"remediation_preview_count"`
}

type AWSAIAgentRiskResult struct {
	TenantID           string                       `json:"tenant_id"`
	WorkspaceID        string                       `json:"workspace_id"`
	ProjectID          string                       `json:"project_id"`
	ConnectorID        string                       `json:"connector_id,omitempty"`
	AccountID          string                       `json:"account_id,omitempty"`
	Region             string                       `json:"region,omitempty"`
	ParentIssueNumber  int                          `json:"parent_issue_number"`
	ParentIssueRef     string                       `json:"parent_issue_ref"`
	CurrentIssueNumber int                          `json:"current_issue_number"`
	CurrentIssueRef    string                       `json:"current_issue_ref"`
	Version            string                       `json:"version"`
	Status             string                       `json:"status"`
	FixtureState       string                       `json:"fixture_state,omitempty"`
	Confidence         float64                      `json:"confidence"`
	CalculationVersion string                       `json:"calculation_version"`
	AppliedFilters     map[string]string            `json:"applied_filters"`
	Summary            AWSAIAgentRiskSummary        `json:"summary"`
	Findings           []AWSAIAgentRiskFinding      `json:"findings"`
	Relationships      []AWSAIAgentRiskRelationship `json:"relationships"`
	Caveats            []string                     `json:"caveats"`
	FailureReasons     []string                     `json:"failure_reasons"`
	RemediationHints   []string                     `json:"remediation_hints"`
	EvidenceLinks      []string                     `json:"evidence_links"`
	CoverageGaps       []AWSAIAgentRiskCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSAIAgentRiskDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
}

type awsAIAgentRiskSources struct {
	agents      AWSAIAgentIdentityInventoryResult
	runtime     AWSAgentRuntimeAccessResult
	least       AWSLeastPrivilegeResult
	equivalence AWSSecretPermissionEquivalenceResult
}

func (s *Service) GetAWSAIAgentRisk(ctx context.Context, workspaceID string, projectID string, request AWSAIAgentRiskRequest) (AWSAIAgentRiskResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSAIAgentRiskResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSAIAgentRiskResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSAIAgentRiskFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSAIAgentRiskResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	sources, err := s.awsAIAgentRiskSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSAIAgentRiskResult{}, err
	}
	findings := awsAIAgentRiskFindings(sources, now)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Score > findings[j].Score
	})
	filtered, applied := filterAWSAIAgentRiskFindings(findings, request)
	relationships := awsAIAgentRiskRelationships(filtered)
	diagnostics := awsAIAgentRiskDiagnostics(sources)
	coverageGaps := awsAIAgentRiskCoverageGaps(sources)
	status, confidence := summarizeAWSAIAgentRiskStatus(sources, filtered, diagnostics)

	return AWSAIAgentRiskResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsAIAgentRiskCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsAIAgentRiskCurrentIssue),
		Version:            awsAIAgentRiskVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsAIAgentRiskVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSAIAgentRisk(findings, filtered, relationships),
		Findings:           filtered,
		Relationships:      relationships,
		Caveats:            awsAIAgentRiskCaveats(),
		FailureReasons:     awsAIAgentRiskFailureReasons(sources),
		RemediationHints:   awsAIAgentRiskRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsAIAgentRiskCurrentIssue),
			awsIssueURL(awsAIAgentIdentityCurrentIssue),
			awsIssueURL(awsAgentRuntimeAccessCurrentIssue),
			awsIssueURL(awsSecretPermissionEquivalenceCurrentIssue),
			"/docs/aws-ai-agent-risk-engine",
			"/docs/aws-ai-agent-identities",
			"/docs/aws-agent-runtime-access",
			"/docs/aws-secret-permission-equivalence-engine",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSAIAgentRiskFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "ready":
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func (s *Service) awsAIAgentRiskSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (awsAIAgentRiskSources, error) {
	agents, err := s.GetAWSAIAgentIdentityInventory(ctx, workspaceID, projectID, AWSAIAgentIdentityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsAIAgentRiskSources{}, fmt.Errorf("ai agent risk identity inventory: %w", err)
	}
	runtime, err := s.GetAWSAgentRuntimeAccess(ctx, workspaceID, projectID, AWSAgentRuntimeAccessRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsAIAgentRiskSources{}, fmt.Errorf("ai agent risk runtime access: %w", err)
	}
	least, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsAIAgentRiskSources{}, fmt.Errorf("ai agent risk least privilege: %w", err)
	}
	equivalence, err := s.GetAWSSecretPermissionEquivalence(ctx, workspaceID, projectID, AWSSecretPermissionEquivalenceRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsAIAgentRiskSources{}, fmt.Errorf("ai agent risk secret permission equivalence: %w", err)
	}
	return awsAIAgentRiskSources{agents: agents, runtime: runtime, least: least, equivalence: equivalence}, nil
}

func awsAIAgentRiskFindings(sources awsAIAgentRiskSources, now time.Time) []AWSAIAgentRiskFinding {
	findings := []AWSAIAgentRiskFinding{}
	agentsByRuntimeRole := map[string][]AWSAIAgentIdentityRecord{}
	agentNodeByID := map[string]string{}
	for _, agent := range sources.agents.Records {
		for _, roleKey := range []string{agent.RuntimeRoleNodeID, awsIdentityNodeIDForAPI(agent.RuntimeRoleARN)} {
			normalizedRoleKey := strings.ToLower(strings.TrimSpace(roleKey))
			if normalizedRoleKey == "" {
				continue
			}
			agentsByRuntimeRole[normalizedRoleKey] = appendAWSAIAgentRiskRoleAgent(agentsByRuntimeRole[normalizedRoleKey], agent)
		}
		for _, agentKey := range []string{agent.AgentID, agent.AgentARN, agent.AgentNodeID} {
			normalizedAgentKey := strings.ToLower(strings.TrimSpace(agentKey))
			if normalizedAgentKey == "" || agent.AgentNodeID == "" {
				continue
			}
			if _, ok := agentNodeByID[normalizedAgentKey]; !ok {
				agentNodeByID[normalizedAgentKey] = agent.AgentNodeID
			}
		}
		findings = append(findings, awsAIAgentRiskFindingsFromAgent(agent, now)...)
	}
	for _, record := range sources.runtime.Records {
		if finding, ok := awsAIAgentRiskFindingFromRuntime(record, now); ok {
			findings = append(findings, finding)
		}
	}
	for _, finding := range sources.equivalence.Findings {
		if derived, ok := awsAIAgentRiskFindingFromSecretEquivalence(finding, agentNodeByID, now); ok {
			findings = append(findings, derived)
		}
	}
	for _, recommendation := range sources.least.Recommendations {
		findings = append(findings, awsAIAgentRiskFindingsFromLeastPrivilege(recommendation, agentsByRuntimeRole, now)...)
	}
	return awsAIAgentRiskDedupeFindings(findings)
}

func appendAWSAIAgentRiskRoleAgent(agents []AWSAIAgentIdentityRecord, candidate AWSAIAgentIdentityRecord) []AWSAIAgentIdentityRecord {
	candidateKey := firstNonEmptyAWSValue(candidate.AgentNodeID, candidate.AgentID, candidate.AgentARN)
	for _, agent := range agents {
		if firstNonEmptyAWSValue(agent.AgentNodeID, agent.AgentID, agent.AgentARN) == candidateKey {
			return agents
		}
	}
	return append(agents, candidate)
}

func awsAIAgentRiskFindingsFromAgent(agent AWSAIAgentIdentityRecord, now time.Time) []AWSAIAgentRiskFinding {
	findings := []AWSAIAgentRiskFinding{}
	toolCount := len(dedupeStrings(append(append([]string{}, agent.ToolNames...), agent.AllowedActions...)))
	if toolCount >= 3 || strings.EqualFold(agent.AgentType, "agent_gateway") {
		score := clampBlastRadiusScore(58 + toolCount*5)
		findings = append(findings, awsAIAgentRiskFinding(AWSAIAgentRiskFinding{
			FindingID:          "aws-ai-agent-risk:" + stableAWSBlastRadiusToken("broad-tool-access", agent.AgentNodeID, strings.Join(agent.ToolNames, ",")),
			CalculationVersion: awsAIAgentRiskVersion,
			RiskType:           "broad_tool_access",
			Severity:           awsPrivilegeEscalationSeverity(score),
			Status:             awsPrivilegeEscalationFindingStatus(score, agent.Confidence),
			Score:              score,
			Confidence:         minFloat(firstNonZeroFloat(agent.Confidence, 0.78), 0.92),
			AccountID:          agent.AccountID,
			Region:             agent.Region,
			AgentNodeID:        agent.AgentNodeID,
			AgentID:            agent.AgentID,
			AgentName:          agent.AgentName,
			AgentType:          agent.AgentType,
			RuntimeRoleARN:     agent.RuntimeRoleARN,
			RuntimeRoleNodeID:  agent.RuntimeRoleNodeID,
			Provider:           agent.Provider,
			ToolNames:          agent.ToolNames,
			CapabilityNames:    agent.CapabilityNames,
			SourceSignals:      []string{"ai_agent_identities"},
			Rationale:          fmt.Sprintf("%s exposes %d declared tools or allowed actions, which increases agent action surface even before runtime use is observed.", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID), toolCount),
			EvidenceBoundary:   awsAIAgentRiskEvidenceBoundary(),
			ImpactedNodes:      awsAIAgentRiskImpactedNodes(agent.AgentNodeID, agent.RuntimeRoleNodeID),
			ImpactedPath:       awsAIAgentRiskAgentPath(agent, "tool_surface", fmt.Sprintf("%d declared tools/actions", toolCount)),
			Evidence:           []AWSAIAgentRiskEvidence{{Source: "ai_agent_identities", EvidenceRef: agent.EvidenceRef, Label: "Declared agent tool surface", Confidence: agent.Confidence, ObservedAt: agent.CollectedAt, Relationship: "declares_tools"}},
			NextAction:         "Review tool ownership and split or scope broad agent tool access before generating remediation diffs.",
			CreatedAt:          now,
			UpdatedAt:          now,
		}))
	}

	sensitive := awsAIAgentRiskSensitiveResources(agent)
	if len(sensitive) > 0 {
		score := 62 + len(sensitive)*6
		if agent.BrowserEnabled || agent.CodeInterpreterEnabled {
			score += 8
		}
		score = clampBlastRadiusScore(score)
		findings = append(findings, awsAIAgentRiskFinding(AWSAIAgentRiskFinding{
			FindingID:          "aws-ai-agent-risk:" + stableAWSBlastRadiusToken("sensitive-data-reachability", agent.AgentNodeID, strings.Join(sensitive, ",")),
			CalculationVersion: awsAIAgentRiskVersion,
			RiskType:           "sensitive_data_reachability",
			Severity:           awsPrivilegeEscalationSeverity(score),
			Status:             awsPrivilegeEscalationFindingStatus(score, agent.Confidence),
			Score:              score,
			Confidence:         minFloat(firstNonZeroFloat(agent.Confidence, 0.76), 0.9),
			AccountID:          agent.AccountID,
			Region:             agent.Region,
			AgentNodeID:        agent.AgentNodeID,
			AgentID:            agent.AgentID,
			AgentName:          agent.AgentName,
			AgentType:          agent.AgentType,
			RuntimeRoleARN:     agent.RuntimeRoleARN,
			RuntimeRoleNodeID:  agent.RuntimeRoleNodeID,
			Provider:           agent.Provider,
			ToolNames:          agent.ToolNames,
			CapabilityNames:    agent.CapabilityNames,
			SensitiveResources: sensitive,
			SourceSignals:      []string{"ai_agent_identities"},
			Rationale:          fmt.Sprintf("%s can reach sensitive agent capabilities or resource references: %s.", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID), strings.Join(sensitive, ", ")),
			EvidenceBoundary:   awsAIAgentRiskEvidenceBoundary(),
			ImpactedNodes:      awsAIAgentRiskImpactedNodes(append([]string{agent.AgentNodeID, agent.RuntimeRoleNodeID}, sensitive...)...),
			ImpactedPath:       awsAIAgentRiskAgentPath(agent, "sensitive_resource", strings.Join(sensitive, ", ")),
			Evidence:           []AWSAIAgentRiskEvidence{{Source: "ai_agent_identities", EvidenceRef: agent.EvidenceRef, Label: "Sensitive capability metadata", Confidence: agent.Confidence, ObservedAt: agent.CollectedAt, Relationship: "can_reach_sensitive_agent_capability"}},
			NextAction:         "Validate capability owners and restrict memory, browser, code-interpreter, storage, or KMS reachability to approved agents.",
			CreatedAt:          now,
			UpdatedAt:          now,
		}))
	}

	if awsAIAgentRiskOwnerless(agent) {
		score := 70
		if strings.EqualFold(agent.Status, "degraded") || strings.EqualFold(agent.CoverageStatus, "degraded") {
			score += 8
		}
		score = clampBlastRadiusScore(score)
		findings = append(findings, awsAIAgentRiskFinding(AWSAIAgentRiskFinding{
			FindingID:          "aws-ai-agent-risk:" + stableAWSBlastRadiusToken("ownerless-agent", agent.AgentNodeID),
			CalculationVersion: awsAIAgentRiskVersion,
			RiskType:           "ownerless_agent",
			Severity:           awsPrivilegeEscalationSeverity(score),
			Status:             "review",
			Score:              score,
			Confidence:         minFloat(firstNonZeroFloat(agent.Confidence, 0.7), 0.88),
			AccountID:          agent.AccountID,
			Region:             agent.Region,
			AgentNodeID:        agent.AgentNodeID,
			AgentID:            agent.AgentID,
			AgentName:          agent.AgentName,
			AgentType:          agent.AgentType,
			RuntimeRoleARN:     agent.RuntimeRoleARN,
			RuntimeRoleNodeID:  agent.RuntimeRoleNodeID,
			Provider:           agent.Provider,
			ToolNames:          agent.ToolNames,
			CapabilityNames:    agent.CapabilityNames,
			SourceSignals:      []string{"ai_agent_identities"},
			Rationale:          fmt.Sprintf("%s has no owner tag or has degraded ownership coverage, so remediation and approval cannot be routed deterministically.", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID)),
			EvidenceBoundary:   awsAIAgentRiskEvidenceBoundary(),
			ImpactedNodes:      awsAIAgentRiskImpactedNodes(agent.AgentNodeID, agent.RuntimeRoleNodeID),
			ImpactedPath:       awsAIAgentRiskAgentPath(agent, "owner", "missing owner"),
			Evidence:           []AWSAIAgentRiskEvidence{{Source: "ai_agent_identities", EvidenceRef: agent.EvidenceRef, Label: "Agent ownership metadata", Confidence: agent.Confidence, ObservedAt: agent.CollectedAt, Relationship: "missing_owner"}},
			NextAction:         "Assign an accountable owner before remediation case creation or policy diff generation.",
			CreatedAt:          now,
			UpdatedAt:          now,
		}))
	}

	for _, ref := range agent.ProviderKeyReferences {
		if !awsAIAgentProviderIsExternalAI(ref.Provider) {
			continue
		}
		secretRef := firstNonEmptyAWSValue(ref.TargetNodeID, ref.ReferenceName, ref.Reference)
		score := 78
		if !ref.Resolved {
			score += 4
		}
		score = clampBlastRadiusScore(score)
		findings = append(findings, awsAIAgentRiskFinding(AWSAIAgentRiskFinding{
			FindingID:          "aws-ai-agent-risk:" + stableAWSBlastRadiusToken("external-credential-exposure", agent.AgentNodeID, ref.Provider, secretRef),
			CalculationVersion: awsAIAgentRiskVersion,
			RiskType:           "external_credential_exposure",
			Severity:           awsPrivilegeEscalationSeverity(score),
			Status:             awsPrivilegeEscalationFindingStatus(score, ref.Confidence),
			Score:              score,
			Confidence:         minFloat(firstNonZeroFloat(ref.Confidence, agent.Confidence, 0.78), 0.92),
			AccountID:          agent.AccountID,
			Region:             agent.Region,
			AgentNodeID:        agent.AgentNodeID,
			AgentID:            agent.AgentID,
			AgentName:          agent.AgentName,
			AgentType:          agent.AgentType,
			RuntimeRoleARN:     agent.RuntimeRoleARN,
			RuntimeRoleNodeID:  agent.RuntimeRoleNodeID,
			Provider:           ref.Provider,
			ToolNames:          agent.ToolNames,
			CapabilityNames:    agent.CapabilityNames,
			SensitiveResources: []string{ref.TargetNodeID},
			SourceSignals:      []string{"ai_agent_identities"},
			Rationale:          fmt.Sprintf("%s references %s provider credential metadata via %s; the key value is not collected.", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID), formatAWSBlastRadiusLabel(ref.Provider), firstNonEmptyAWSValue(ref.ReferenceName, ref.ReferenceKind)),
			EvidenceBoundary:   awsAIAgentRiskEvidenceBoundary(),
			ImpactedNodes:      awsAIAgentRiskImpactedNodes(agent.AgentNodeID, agent.RuntimeRoleNodeID, ref.TargetNodeID),
			ImpactedPath:       awsAIAgentRiskAgentPath(agent, "provider_key_reference", firstNonEmptyAWSValue(ref.ReferenceName, ref.TargetNodeID)),
			Evidence:           []AWSAIAgentRiskEvidence{{Source: "ai_agent_identities", EvidenceRef: ref.EvidenceRef, Label: "Agent provider-key metadata", Confidence: ref.Confidence, ObservedAt: agent.CollectedAt, Relationship: "references_external_provider_key"}},
			NextAction:         "Rotate or scope the external provider credential and restrict every AWS identity that can read its reference.",
			CreatedAt:          now,
			UpdatedAt:          now,
		}))
	}
	return findings
}

func awsAIAgentRiskFindingFromRuntime(record AWSAgentRuntimeAccessRecord, now time.Time) (AWSAIAgentRiskFinding, bool) {
	if record.Status == "confirmed" && !awsStringSliceContains(record.Caveats, "observed_backing_role_differs_from_declared") && !awsStringSliceContains(record.Caveats, "observed_tool_call_failed") {
		return AWSAIAgentRiskFinding{}, false
	}
	riskType := "runtime_tool_anomaly"
	score := 66
	switch record.Status {
	case "observed_without_declaration":
		riskType = "undeclared_tool_runtime"
		score = 80
	case "declared_unused":
		riskType = "declared_unused_tool"
		score = 58
	}
	if awsStringSliceContains(record.Caveats, "observed_backing_role_differs_from_declared") {
		riskType = "backing_role_mismatch"
		score += 8
	}
	if awsStringSliceContains(record.Caveats, "observed_tool_call_failed") {
		score += 4
	}
	score = clampBlastRadiusScore(score)
	target := firstString(record.TargetResourceNodeIDs)
	backingRoleNode := firstNonEmptyAWSValue(firstString(record.BackingRoleNodeIDs), record.DeclaredBackingRoleNode)
	backingRoleARN := firstString(record.BackingRoleARNs)
	impactedPath := []AWSAIAgentRiskPathStep{
		awsLeastPrivilegePathStep(record.AgentNodeID, "ai_agent", firstNonEmptyAWSValue(record.AgentName, record.AgentID), record.AccountID, record.Region),
	}
	if backingRoleNode != "" {
		impactedPath = append(impactedPath, awsLeastPrivilegePathStep(backingRoleNode, "backing_role", firstNonEmptyAWSValue(shortAWSARN(backingRoleARN), backingRoleARN, backingRoleNode), record.AccountID, record.Region))
	}
	impactedPath = append(impactedPath, awsLeastPrivilegePathStep(firstNonEmptyAWSValue(target, firstString(record.TargetResourceARNs), record.ToolTargetRef), "runtime_target", firstNonEmptyAWSValue(record.ToolName, record.ToolTargetRef, target), record.AccountID, record.Region))
	return awsAIAgentRiskFinding(AWSAIAgentRiskFinding{
		FindingID:          "aws-ai-agent-risk:" + stableAWSBlastRadiusToken(riskType, record.CorrelationID),
		CalculationVersion: awsAIAgentRiskVersion,
		RiskType:           riskType,
		Severity:           awsPrivilegeEscalationSeverity(score),
		Status:             awsPrivilegeEscalationFindingStatus(score, record.Confidence),
		Score:              score,
		Confidence:         minFloat(firstNonZeroFloat(record.Confidence, 0.68), 0.9),
		AccountID:          record.AccountID,
		Region:             record.Region,
		AgentNodeID:        record.AgentNodeID,
		AgentID:            record.AgentID,
		AgentName:          record.AgentName,
		AgentType:          record.AgentType,
		RuntimeRoleARN:     backingRoleARN,
		RuntimeRoleNodeID:  backingRoleNode,
		ToolNames:          []string{record.ToolName},
		SensitiveResources: []string{target},
		SourceSignals:      []string{"agent_runtime_access"},
		Rationale:          fmt.Sprintf("Runtime correlation for %s/%s returned status=%s with caveats %s.", firstNonEmptyAWSValue(record.AgentName, record.AgentID), firstNonEmptyAWSValue(record.ToolName, "agent invocation"), record.Status, strings.Join(record.Caveats, ", ")),
		EvidenceBoundary:   awsAIAgentRiskEvidenceBoundary(),
		ImpactedNodes:      awsAIAgentRiskImpactedNodes(record.AgentNodeID, backingRoleNode, target),
		ImpactedPath:       impactedPath,
		Evidence:           []AWSAIAgentRiskEvidence{{Source: "agent_runtime_access", EvidenceRef: record.EvidenceRef, Label: "Agent runtime/tool-call correlation", Confidence: record.Confidence, ObservedAt: record.LastObservedAt, Relationship: record.Status}},
		NextAction:         record.NextAction,
		CreatedAt:          now,
		UpdatedAt:          now,
	}), true
}

func awsAIAgentRiskFindingFromSecretEquivalence(finding AWSSecretPermissionEquivalenceFinding, agentNodeByID map[string]string, now time.Time) (AWSAIAgentRiskFinding, bool) {
	if strings.TrimSpace(finding.AgentID) == "" && !strings.Contains(finding.EquivalenceType, "agent") {
		return AWSAIAgentRiskFinding{}, false
	}
	score := clampBlastRadiusScore(finding.Score + 4)
	agentNode := awsAIAgentRiskAgentNodeFromPath(finding.ImpactedPath)
	if agentNode == "" {
		agentNode = awsAIAgentRiskResolveAgentNode(finding.AgentID, agentNodeByID)
	}
	if agentNode == "" {
		return AWSAIAgentRiskFinding{}, false
	}
	secretRef := firstNonEmptyAWSValue(finding.SecretNodeID, finding.SecretARN, firstString(finding.ImpactedNodes), finding.IdentityNodeID)
	return awsAIAgentRiskFinding(AWSAIAgentRiskFinding{
		FindingID:          "aws-ai-agent-risk:" + stableAWSBlastRadiusToken("external-credential-exposure", agentNode, finding.Provider, secretRef),
		CalculationVersion: awsAIAgentRiskVersion,
		RiskType:           "external_credential_exposure",
		Severity:           awsPrivilegeEscalationSeverity(score),
		Status:             finding.Status,
		Score:              score,
		Confidence:         minFloat(finding.Confidence, 0.92),
		AccountID:          finding.AccountID,
		Region:             finding.Region,
		AgentNodeID:        agentNode,
		AgentID:            finding.AgentID,
		AgentName:          finding.AgentName,
		RuntimeRoleARN:     finding.PrincipalARN,
		RuntimeRoleNodeID:  finding.IdentityNodeID,
		Provider:           finding.Provider,
		SensitiveResources: []string{finding.SecretNodeID, finding.SecretARN},
		SourceSignals:      []string{"secret_permission_equivalence"},
		Rationale:          finding.Rationale,
		EvidenceBoundary:   awsAIAgentRiskEvidenceBoundary(),
		ImpactedNodes:      awsAIAgentRiskImpactedNodes(append([]string{agentNode, finding.IdentityNodeID, finding.SecretNodeID}, finding.ImpactedNodes...)...),
		ImpactedPath:       finding.ImpactedPath,
		Evidence:           finding.Evidence,
		NextAction:         finding.NextAction,
		CreatedAt:          now,
		UpdatedAt:          now,
	}), true
}

func awsAIAgentRiskFindingsFromLeastPrivilege(recommendation AWSLeastPrivilegeRecommendation, agents map[string][]AWSAIAgentIdentityRecord, now time.Time) []AWSAIAgentRiskFinding {
	if recommendation.Decision == "keep" {
		return nil
	}
	affectedAgents := agents[strings.ToLower(strings.TrimSpace(recommendation.IdentityNodeID))]
	if len(affectedAgents) == 0 {
		return nil
	}
	findings := make([]AWSAIAgentRiskFinding, 0, len(affectedAgents))
	score := clampBlastRadiusScore(recommendation.Score + 3)
	for _, agent := range affectedAgents {
		findings = append(findings, awsAIAgentRiskFinding(AWSAIAgentRiskFinding{
			FindingID:          "aws-ai-agent-risk:" + stableAWSBlastRadiusToken("backing-role-scope", recommendation.RecommendationID, agent.AgentNodeID),
			CalculationVersion: awsAIAgentRiskVersion,
			RiskType:           "backing_role_scope",
			Severity:           awsPrivilegeEscalationSeverity(score),
			Status:             recommendation.Status,
			Score:              score,
			Confidence:         minFloat(recommendation.Confidence, 0.9),
			AccountID:          recommendation.AccountID,
			Region:             recommendation.Region,
			AgentNodeID:        agent.AgentNodeID,
			AgentID:            agent.AgentID,
			AgentName:          agent.AgentName,
			AgentType:          agent.AgentType,
			RuntimeRoleARN:     agent.RuntimeRoleARN,
			RuntimeRoleNodeID:  recommendation.IdentityNodeID,
			Provider:           agent.Provider,
			ToolNames:          agent.ToolNames,
			CapabilityNames:    agent.CapabilityNames,
			SensitiveResources: []string{recommendation.ResourceNodeID, recommendation.ResourceARN},
			SourceSignals:      []string{"least_privilege"},
			Rationale:          fmt.Sprintf("The backing role for %s has least-privilege decision=%s for %s; agent risk inherits that role scope.", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID), recommendation.Decision, recommendation.DisplayName),
			EvidenceBoundary:   awsAIAgentRiskEvidenceBoundary(),
			ImpactedNodes:      awsAIAgentRiskImpactedNodes(append([]string{agent.AgentNodeID, recommendation.IdentityNodeID, recommendation.ResourceNodeID}, recommendation.ImpactedNodes...)...),
			ImpactedPath:       append([]AWSAIAgentRiskPathStep{awsLeastPrivilegePathStep(agent.AgentNodeID, "ai_agent", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID), agent.AccountID, agent.Region)}, recommendation.ImpactedPath...),
			Evidence:           recommendation.Evidence,
			NextAction:         recommendation.NextAction,
			CreatedAt:          now,
			UpdatedAt:          now,
		}))
	}
	return findings
}

func awsAIAgentRiskFinding(finding AWSAIAgentRiskFinding) AWSAIAgentRiskFinding {
	finding.ToolNames = dedupeStrings(finding.ToolNames)
	finding.CapabilityNames = dedupeStrings(finding.CapabilityNames)
	finding.SensitiveResources = dedupeStrings(finding.SensitiveResources)
	finding.SourceSignals = dedupeStrings(finding.SourceSignals)
	finding.ImpactedNodes = awsAIAgentRiskImpactedNodes(finding.ImpactedNodes...)
	evidenceRefs := []string{}
	for _, evidence := range finding.Evidence {
		if evidence.EvidenceRef != "" {
			evidenceRefs = append(evidenceRefs, evidence.EvidenceRef)
		}
	}
	finding.RemediationCase = AWSAIAgentRiskRemediationCasePreview{
		CaseID:             "aws-ai-agent-risk-preview:" + stableAWSBlastRadiusToken(finding.RiskType, finding.AgentNodeID, finding.FindingID),
		Title:              fmt.Sprintf("%s AI agent risk review", formatAWSBlastRadiusLabel(finding.RiskType)),
		RecommendedAction:  finding.NextAction,
		ApprovalRequired:   finding.Severity == "critical" || finding.Severity == "high",
		BlockingEvidence:   dedupeStrings(evidenceRefs),
		ImpactedNodeCount:  len(finding.ImpactedNodes),
		EstimatedRiskDrop:  minInt(finding.Score, 40),
		BreakagePrediction: "unknown",
		ReadOnlyProjection: true,
	}
	return finding
}

func awsAIAgentRiskDedupeFindings(findings []AWSAIAgentRiskFinding) []AWSAIAgentRiskFinding {
	seen := map[string]AWSAIAgentRiskFinding{}
	order := []string{}
	for _, finding := range findings {
		if finding.FindingID == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(finding.FindingID))
		if existing, ok := seen[key]; ok {
			seen[key] = awsAIAgentRiskMergeFindings(existing, finding)
			continue
		}
		seen[key] = finding
		order = append(order, key)
	}
	out := make([]AWSAIAgentRiskFinding, 0, len(order))
	for _, key := range order {
		out = append(out, seen[key])
	}
	return out
}

func awsAIAgentRiskMergeFindings(existing, incoming AWSAIAgentRiskFinding) AWSAIAgentRiskFinding {
	mergedSourceSignals := dedupeStrings(append(append([]string{}, existing.SourceSignals...), incoming.SourceSignals...))
	mergedToolNames := dedupeStrings(append(append([]string{}, existing.ToolNames...), incoming.ToolNames...))
	mergedCapabilityNames := dedupeStrings(append(append([]string{}, existing.CapabilityNames...), incoming.CapabilityNames...))
	mergedSensitiveResources := dedupeStrings(append(append([]string{}, existing.SensitiveResources...), incoming.SensitiveResources...))
	mergedEvidence := append(append([]AWSAIAgentRiskEvidence{}, existing.Evidence...), incoming.Evidence...)
	mergedImpactedNodes := awsAIAgentRiskImpactedNodes(append(append([]string{}, existing.ImpactedNodes...), incoming.ImpactedNodes...)...)

	merged := existing
	if incoming.Score > merged.Score {
		merged = incoming
	}
	if incoming.Confidence > merged.Confidence {
		merged.Confidence = incoming.Confidence
	}
	merged.SourceSignals = mergedSourceSignals
	merged.ToolNames = mergedToolNames
	merged.CapabilityNames = mergedCapabilityNames
	merged.SensitiveResources = mergedSensitiveResources
	merged.Evidence = mergedEvidence
	merged.ImpactedNodes = mergedImpactedNodes
	if merged.Status == "" {
		merged.Status = incoming.Status
	}
	return awsAIAgentRiskFinding(merged)
}

func filterAWSAIAgentRiskFindings(findings []AWSAIAgentRiskFinding, request AWSAIAgentRiskRequest) ([]AWSAIAgentRiskFinding, map[string]string) {
	filters := map[string]string{
		"account_id": strings.TrimSpace(request.AccountID),
		"region":     strings.TrimSpace(request.Region),
		"agent_id":   strings.TrimSpace(request.AgentID),
		"risk_type":  normalizeAWSRuntimeEventFilterToken(request.RiskType),
		"severity":   normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":     normalizeAWSRuntimeEventFilterToken(request.Status),
		"evidence":   strings.TrimSpace(request.Evidence),
		"search":     strings.TrimSpace(request.Search),
	}
	for key, value := range filters {
		if strings.TrimSpace(value) == "" || strings.EqualFold(value, "all") {
			delete(filters, key)
		}
	}
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSAIAgentRiskFinding, 0, len(findings))
	for _, finding := range findings {
		if filters["account_id"] != "" && filters["account_id"] != finding.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], finding.Region) {
			continue
		}
		if filters["risk_type"] != "" && filters["risk_type"] != normalizeAWSRuntimeEventFilterToken(finding.RiskType) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(finding.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(finding.Status) {
			continue
		}
		if filters["agent_id"] != "" && !strings.Contains(strings.ToLower(finding.AgentNodeID+" "+finding.AgentID+" "+finding.AgentName+" "+finding.RuntimeRoleARN), strings.ToLower(filters["agent_id"])) {
			continue
		}
		if filters["evidence"] != "" && !awsAIAgentRiskEvidenceFilterMatch(finding, filters["evidence"]) {
			continue
		}
		if filters["search"] != "" && !awsAIAgentRiskSearchFilterMatch(finding, filters["search"]) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, applied
}

func awsAIAgentRiskEvidenceFilterMatch(finding AWSAIAgentRiskFinding, evidenceFilter string) bool {
	switch normalizeAWSRuntimeEventFilterToken(evidenceFilter) {
	case "runtime-backed":
		return awsStringSliceContains(finding.SourceSignals, "agent_runtime_access") || awsStringSliceContains(finding.SourceSignals, "least_privilege")
	case "inventory-backed":
		return awsStringSliceContains(finding.SourceSignals, "ai_agent_identities")
	case "secret-backed":
		return awsStringSliceContains(finding.SourceSignals, "secret_permission_equivalence")
	default:
		for _, item := range finding.Evidence {
			if awsRuntimeEventMatchesAny(evidenceFilter, item.Source, item.Label, item.EvidenceRef, item.Relationship) {
				return true
			}
		}
		return false
	}
}

func awsAIAgentRiskSearchFilterMatch(finding AWSAIAgentRiskFinding, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	values := []string{finding.FindingID, finding.RiskType, finding.Severity, finding.Status, finding.AgentNodeID, finding.AgentID, finding.AgentName, finding.AgentType, finding.RuntimeRoleARN, finding.RuntimeRoleNodeID, finding.Provider, finding.Rationale, finding.NextAction}
	values = append(values, finding.ToolNames...)
	values = append(values, finding.CapabilityNames...)
	values = append(values, finding.SensitiveResources...)
	values = append(values, finding.SourceSignals...)
	values = append(values, finding.ImpactedNodes...)
	for _, item := range finding.Evidence {
		values = append(values, item.Source, item.EvidenceRef, item.Label, item.Relationship)
	}
	for _, item := range values {
		if strings.Contains(strings.ToLower(item), query) {
			return true
		}
	}
	return false
}

func awsAIAgentRiskRelationships(findings []AWSAIAgentRiskFinding) []AWSAIAgentRiskRelationship {
	relationships := []AWSAIAgentRiskRelationship{}
	for _, finding := range findings {
		if finding.AgentNodeID == "" {
			continue
		}
		for _, nodeID := range finding.ImpactedNodes {
			if nodeID == "" || nodeID == finding.AgentNodeID {
				continue
			}
			relationships = append(relationships, AWSAIAgentRiskRelationship{
				FindingID:   finding.FindingID,
				Type:        "ai_agent_risk_path",
				FromNodeID:  finding.AgentNodeID,
				ToNodeID:    nodeID,
				EvidenceRef: firstString(awsAIAgentRiskEvidenceRefs(finding.Evidence)),
			})
		}
	}
	return relationships
}

func summarizeAWSAIAgentRisk(allFindings []AWSAIAgentRiskFinding, filtered []AWSAIAgentRiskFinding, relationships []AWSAIAgentRiskRelationship) AWSAIAgentRiskSummary {
	summary := AWSAIAgentRiskSummary{
		TotalFindings:     len(allFindings),
		FilteredFindings:  len(filtered),
		SeverityCounts:    map[string]int{},
		StatusCounts:      map[string]int{},
		RiskTypeCounts:    map[string]int{},
		RelationshipCount: len(relationships),
	}
	confidenceTotal := 0.0
	for _, finding := range filtered {
		summary.SeverityCounts[finding.Severity]++
		summary.StatusCounts[finding.Status]++
		summary.RiskTypeCounts[finding.RiskType]++
		if finding.Score > summary.HighestScore {
			summary.HighestScore = finding.Score
		}
		confidenceTotal += finding.Confidence
		switch finding.RiskType {
		case "external_credential_exposure":
			summary.ExternalCredentialCount++
		case "broad_tool_access":
			summary.BroadToolAccessCount++
		case "sensitive_data_reachability":
			summary.SensitiveReachabilityCount++
		case "ownerless_agent":
			summary.OwnerlessAgentCount++
		case "backing_role_scope":
			summary.BackingRoleScopeCount++
		}
		if awsStringSliceContains(finding.SourceSignals, "agent_runtime_access") || awsStringSliceContains(finding.SourceSignals, "least_privilege") {
			summary.RuntimeObservedCount++
		}
		if finding.RemediationCase.CaseID != "" {
			summary.RemediationPreviewCount++
		}
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func summarizeAWSAIAgentRiskStatus(sources awsAIAgentRiskSources, filtered []AWSAIAgentRiskFinding, diagnostics []AWSAIAgentRiskDiagnostic) (string, float64) {
	statuses := []string{sources.agents.Status, sources.runtime.Status, sources.least.Status, sources.equivalence.Status}
	for _, status := range statuses {
		if status == awsPlatformDependencyStatusBlocked {
			return awsPlatformDependencyStatusBlocked, 0.35
		}
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	for _, status := range statuses {
		if status == awsPlatformDependencyStatusDegraded {
			return awsPlatformDependencyStatusDegraded, 0.76
		}
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.84
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsAIAgentRiskFailureReasons(sources awsAIAgentRiskSources) []string {
	out := []string{}
	for _, messages := range [][]string{
		sources.agents.FailureReasons,
		sources.runtime.FailureReasons,
		sources.least.FailureReasons,
		sources.equivalence.FailureReasons,
	} {
		out = append(out, messages...)
	}
	return dedupeStrings(out)
}

func awsAIAgentRiskRemediationHints(sources awsAIAgentRiskSources) []string {
	out := []string{"Treat broad tools, external provider keys, sensitive agent capabilities, and backing-role scope as one agent risk decision until an owner approves remediation."}
	for _, messages := range [][]string{
		sources.agents.RemediationHints,
		sources.runtime.RemediationHints,
		sources.least.RemediationHints,
		sources.equivalence.RemediationHints,
	} {
		out = append(out, messages...)
	}
	return dedupeStrings(out)
}

func awsAIAgentRiskCaveats() []string {
	return []string{
		"AI agent risk is inferred from metadata-only inventory, tool-call correlation, least-privilege, and secret-permission evidence.",
		"The engine never reads, stores, logs, or displays secret values, prompts, completions, browser pages, code-interpreter output, database rows, object contents, or tool payloads.",
		"Unknown, denied, unsupported, degraded, and partial evidence stays explicit instead of becoming deterministic truth.",
	}
}

func awsAIAgentRiskDiagnostics(sources awsAIAgentRiskSources) []AWSAIAgentRiskDiagnostic {
	out := []AWSAIAgentRiskDiagnostic{}
	appendDiag := func(collector, sourceID, code, message, remediation string, retryable bool) {
		if strings.TrimSpace(message) == "" && strings.TrimSpace(code) == "" {
			return
		}
		out = append(out, AWSAIAgentRiskDiagnostic{Collector: collector, SourceID: sourceID, Code: code, Message: message, Remediation: remediation, Retryable: retryable})
	}
	for _, d := range sources.agents.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.runtime.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.least.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.equivalence.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	return out
}

func awsAIAgentRiskCoverageGaps(sources awsAIAgentRiskSources) []AWSAIAgentRiskCoverageGap {
	out := []AWSAIAgentRiskCoverageGap{{
		Capability:  "agent_payload_collection",
		Status:      "unsupported",
		Reason:      "Prompts, completions, browser pages, code-interpreter output, database rows, object contents, tool payloads, and secret values are intentionally excluded.",
		Remediation: "Use metadata evidence refs and owner-approved follow-up collection only when a future issue explicitly permits it.",
	}}
	appendGap := func(capability, status, reason, remediation string) {
		out = append(out, AWSAIAgentRiskCoverageGap{Capability: capability, Status: status, Reason: reason, Remediation: remediation})
	}
	for _, g := range sources.agents.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.runtime.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.least.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.equivalence.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	return out
}

func awsAIAgentRiskSensitiveResources(agent AWSAIAgentIdentityRecord) []string {
	resources := []string{}
	if agent.MemoryEnabled {
		resources = append(resources, "agent_memory")
	}
	if agent.BrowserEnabled {
		resources = append(resources, "browser")
	}
	if agent.CodeInterpreterEnabled {
		resources = append(resources, "code_interpreter")
	}
	resources = append(resources, agent.MemoryStoreRefs...)
	resources = append(resources, agent.StorageReferenceRefs...)
	if agent.EncryptionKeyARN != "" {
		resources = append(resources, agent.EncryptionKeyARN)
	}
	return dedupeStrings(resources)
}

func awsAIAgentRiskOwnerless(agent AWSAIAgentIdentityRecord) bool {
	if owner := strings.TrimSpace(agent.Tags["owner"]); owner != "" {
		return false
	}
	return true
}

func awsAIAgentRiskAgentPath(agent AWSAIAgentIdentityRecord, targetType string, targetLabel string) []AWSAIAgentRiskPathStep {
	return []AWSAIAgentRiskPathStep{
		awsLeastPrivilegePathStep(agent.AgentNodeID, "ai_agent", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID), agent.AccountID, agent.Region),
		awsLeastPrivilegePathStep(firstNonEmptyAWSValue(agent.RuntimeRoleNodeID, awsIdentityNodeIDForAPI(agent.RuntimeRoleARN)), "runtime_role", firstNonEmptyAWSValue(shortAWSARN(agent.RuntimeRoleARN), agent.RuntimeRoleName), agent.AccountID, agent.Region),
		awsLeastPrivilegePathStep(targetLabel, targetType, targetLabel, agent.AccountID, agent.Region),
	}
}

func awsAIAgentRiskImpactedNodes(values ...string) []string {
	return emptyStrings(dedupeStrings(values))
}

func awsAIAgentRiskEvidenceRefs(evidence []AWSAIAgentRiskEvidence) []string {
	out := []string{}
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			out = append(out, item.EvidenceRef)
		}
	}
	return dedupeStrings(out)
}

func awsAIAgentRiskAgentNodeFromPath(path []AWSSecretPermissionEquivalencePathStep) string {
	for _, step := range path {
		if strings.EqualFold(step.NodeType, "ai_agent") && strings.TrimSpace(step.NodeID) != "" {
			return step.NodeID
		}
	}
	return ""
}

func awsAIAgentRiskResolveAgentNode(agentID string, agentNodeByID map[string]string) string {
	key := strings.ToLower(strings.TrimSpace(agentID))
	if key == "" {
		return ""
	}
	return agentNodeByID[key]
}

func awsAIAgentRiskEvidenceBoundary() string {
	return "metadata_only_no_secret_values_no_prompts_no_completions_no_tool_payloads"
}
