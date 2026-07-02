package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsAgentCoreGatewayPolicyAdvisoryCurrentIssue = 1545
	awsAgentCoreGatewayPolicyAdvisoryVersion      = "aws-agentcore-gateway-policy-advisory-v1"
	awsAgentCoreGatewayPolicyAdvisoryPolicyID     = "aws-agentcore-gateway-policy-advisory-policy-v1"
	awsAgentCoreGatewayPolicyAdvisoryModeAdvisory = "advisory"
	awsAgentCoreGatewayPolicyPilotStateCandidate  = "candidate"
	awsAgentCoreGatewayPolicyPilotStateReview     = "operator_review"
	awsAgentCoreGatewayPolicyPilotStateBlocked    = "blocked"
	awsAgentCoreGatewayPolicyEnforcementAdvisory  = "advisory_only"

	awsAgentCoreGatewayPolicyOutcomeAllowTools      = "allow_tools"
	awsAgentCoreGatewayPolicyOutcomeWarn            = "warn"
	awsAgentCoreGatewayPolicyOutcomeRequireApproval = "require_approval"
	awsAgentCoreGatewayPolicyOutcomeRestrictTools   = "restrict_tools"
	awsAgentCoreGatewayPolicyOutcomeBlockTools      = "block_tools"
)

// AWSAgentCoreGatewayPolicyAdvisoryRequest scopes the AgentCore gateway
// policy advisory projection to one AWS connector plus optional operator
// drill-down filters.
type AWSAgentCoreGatewayPolicyAdvisoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	RiskType     string `json:"risk_type,omitempty"`
	Severity     string `json:"severity,omitempty"`
	FindingID    string `json:"finding_id,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSAgentCoreGatewayPolicyAdvisoryEvidence = AWSLeastPrivilegeEvidence
type AWSAgentCoreGatewayPolicyAdvisoryPathStep = AWSLeastPrivilegePathStep
type AWSAgentCoreGatewayPolicyAdvisoryDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSAgentCoreGatewayPolicyAdvisoryCoverageGap = AWSLeastPrivilegeCoverageGap
type AWSAgentCoreGatewayPolicyAdvisoryAuditEntry = AWSRemediationApprovalAuditEntry

// AWSAgentCoreGatewayPolicyAdvisoryProvenance records the deterministic
// derivation path so operators can trace which policy version and rule
// produced the advisory.
type AWSAgentCoreGatewayPolicyAdvisoryProvenance struct {
	PolicyVersion string   `json:"policy_version"`
	PolicyRule    string   `json:"policy_rule"`
	Signals       []string `json:"signals,omitempty"`
}

// AWSAgentCoreGatewayPolicyAdvisoryInputHash records the deterministic
// hash of the inputs that produced the advisory. Operators use this to
// detect drift when upstream signals change.
type AWSAgentCoreGatewayPolicyAdvisoryInputHash struct {
	Value      string   `json:"value"`
	Components []string `json:"components,omitempty"`
}

// AWSAgentCoreGatewayPolicyAdvisoryRelationship surfaces advisory→graph
// node edges for downstream UI and audit consumers.
type AWSAgentCoreGatewayPolicyAdvisoryRelationship struct {
	AdvisoryID  string `json:"advisory_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSAgentCoreGatewayPolicyAdvisoryEntry is the persisted-record-shaped
// contract for one AgentCore gateway policy advisory. It never inlines
// prompt text, tool payloads, or workload data; tool restrictions,
// approvals, and warnings reference the agent's tool namespace by name.
type AWSAgentCoreGatewayPolicyAdvisoryEntry struct {
	AdvisoryID          string                                        `json:"advisory_id"`
	CalculationVersion  string                                        `json:"calculation_version"`
	Mode                string                                        `json:"mode"`
	Outcome             string                                        `json:"outcome"`
	PilotState          string                                        `json:"pilot_state"`
	EnforcementState    string                                        `json:"enforcement_state"`
	Confidence          float64                                       `json:"confidence"`
	Severity            string                                        `json:"severity"`
	Score               int                                           `json:"score"`
	Title               string                                        `json:"title"`
	Summary             string                                        `json:"summary"`
	Rationale           string                                        `json:"rationale"`
	AccountID           string                                        `json:"account_id,omitempty"`
	Region              string                                        `json:"region,omitempty"`
	AgentNodeID         string                                        `json:"agent_node_id"`
	AgentID             string                                        `json:"agent_id,omitempty"`
	AgentName           string                                        `json:"agent_name,omitempty"`
	AgentType           string                                        `json:"agent_type,omitempty"`
	Provider            string                                        `json:"provider,omitempty"`
	RuntimeRoleARN      string                                        `json:"runtime_role_arn,omitempty"`
	RuntimeRoleNodeID   string                                        `json:"runtime_role_node_id,omitempty"`
	FindingID           string                                        `json:"finding_id"`
	RiskType            string                                        `json:"risk_type"`
	AllowedToolNames    []string                                      `json:"allowed_tool_names,omitempty"`
	RestrictedToolNames []string                                      `json:"restricted_tool_names,omitempty"`
	BlockedToolNames    []string                                      `json:"blocked_tool_names,omitempty"`
	SensitiveResources  []string                                      `json:"sensitive_resources,omitempty"`
	RecommendedActions  []string                                      `json:"recommended_actions"`
	Provenance          AWSAgentCoreGatewayPolicyAdvisoryProvenance   `json:"provenance"`
	InputHash           AWSAgentCoreGatewayPolicyAdvisoryInputHash    `json:"input_hash"`
	Evidence            []AWSAgentCoreGatewayPolicyAdvisoryEvidence   `json:"evidence"`
	EvidenceBoundary    string                                        `json:"evidence_boundary"`
	ImpactedNodes       []string                                      `json:"impacted_nodes"`
	ImpactedPath        []AWSAgentCoreGatewayPolicyAdvisoryPathStep   `json:"impacted_path"`
	AuditTrail          []AWSAgentCoreGatewayPolicyAdvisoryAuditEntry `json:"audit_trail"`
	ReadOnlyProjection  bool                                          `json:"read_only_projection"`
	SourceSignals       []string                                      `json:"source_signals"`
	NextAction          string                                        `json:"next_action"`
	ProjectedAt         time.Time                                     `json:"projected_at"`
	CreatedAt           time.Time                                     `json:"created_at"`
	UpdatedAt           time.Time                                     `json:"updated_at"`
}

// AWSAgentCoreGatewayPolicyAdvisorySummary aggregates the unfiltered and
// filtered advisory set.
type AWSAgentCoreGatewayPolicyAdvisorySummary struct {
	TotalAdvisories        int            `json:"total_advisories"`
	FilteredAdvisories     int            `json:"filtered_advisories"`
	OutcomeCounts          map[string]int `json:"outcome_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	RiskTypeCounts         map[string]int `json:"risk_type_counts"`
	AllowToolsCount        int            `json:"allow_tools_count"`
	WarnCount              int            `json:"warn_count"`
	RequireApprovalCount   int            `json:"require_approval_count"`
	RestrictToolsCount     int            `json:"restrict_tools_count"`
	BlockToolsCount        int            `json:"block_tools_count"`
	RestrictedToolCount    int            `json:"restricted_tool_count"`
	SensitiveResourceCount int            `json:"sensitive_resource_count"`
	RelationshipCount      int            `json:"relationship_count"`
	HighestScore           int            `json:"highest_score"`
	AverageConfidencePct   int            `json:"average_confidence_pct"`
}

// AWSAgentCoreGatewayPolicyAdvisoryResult is the deterministic endpoint envelope.
type AWSAgentCoreGatewayPolicyAdvisoryResult struct {
	TenantID           string                                          `json:"tenant_id"`
	WorkspaceID        string                                          `json:"workspace_id"`
	ProjectID          string                                          `json:"project_id"`
	ConnectorID        string                                          `json:"connector_id,omitempty"`
	AccountID          string                                          `json:"account_id,omitempty"`
	Region             string                                          `json:"region,omitempty"`
	ParentIssueNumber  int                                             `json:"parent_issue_number"`
	ParentIssueRef     string                                          `json:"parent_issue_ref"`
	CurrentIssueNumber int                                             `json:"current_issue_number"`
	CurrentIssueRef    string                                          `json:"current_issue_ref"`
	Version            string                                          `json:"version"`
	Status             string                                          `json:"status"`
	FixtureState       string                                          `json:"fixture_state,omitempty"`
	Confidence         float64                                         `json:"confidence"`
	CalculationVersion string                                          `json:"calculation_version"`
	PolicyVersion      string                                          `json:"policy_version"`
	Mode               string                                          `json:"mode"`
	PilotState         string                                          `json:"pilot_state"`
	EnforcementState   string                                          `json:"enforcement_state"`
	AppliedFilters     map[string]string                               `json:"applied_filters"`
	Summary            AWSAgentCoreGatewayPolicyAdvisorySummary        `json:"summary"`
	Advisories         []AWSAgentCoreGatewayPolicyAdvisoryEntry        `json:"advisories"`
	Relationships      []AWSAgentCoreGatewayPolicyAdvisoryRelationship `json:"relationships"`
	Caveats            []string                                        `json:"caveats"`
	FailureReasons     []string                                        `json:"failure_reasons"`
	RemediationHints   []string                                        `json:"remediation_hints"`
	EvidenceLinks      []string                                        `json:"evidence_links"`
	CoverageGaps       []AWSAgentCoreGatewayPolicyAdvisoryCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSAgentCoreGatewayPolicyAdvisoryDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                                       `json:"generated_at"`
	UpdatedAt          time.Time                                       `json:"updated_at"`
}

// GetAWSAgentCoreGatewayPolicyAdvisory projects deterministic advisory
// AgentCore gateway/tool policy recommendations from the AI agent risk
// engine (#1528). Each advisory records the recommended outcome
// (allow_tools, warn, require_approval, restrict_tools, block_tools),
// the tool namespace subject to the recommendation, sensitive resource
// scope, deterministic input hash, provenance, and an immutable audit
// trail. The endpoint is advisory-only; Identrail never enforces the
// recommendation at this layer.
func (s *Service) GetAWSAgentCoreGatewayPolicyAdvisory(ctx context.Context, workspaceID string, projectID string, request AWSAgentCoreGatewayPolicyAdvisoryRequest) (AWSAgentCoreGatewayPolicyAdvisoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSAgentCoreGatewayPolicyAdvisoryResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSAgentCoreGatewayPolicyAdvisoryResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSAgentCoreGatewayPolicyAdvisoryFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSAgentCoreGatewayPolicyAdvisoryResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	upstream, err := s.GetAWSAIAgentRisk(ctx, workspaceID, projectID, AWSAIAgentRiskRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSAgentCoreGatewayPolicyAdvisoryResult{}, fmt.Errorf("agentcore gateway policy advisory upstream: %w", err)
	}

	advisories := awsAgentCoreGatewayPolicyAdvisoryEntries(upstream.Findings, now)
	sort.SliceStable(advisories, func(i, j int) bool {
		if advisories[i].Score == advisories[j].Score {
			return advisories[i].AdvisoryID < advisories[j].AdvisoryID
		}
		return advisories[i].Score > advisories[j].Score
	})
	filtered, applied := filterAWSAgentCoreGatewayPolicyAdvisories(advisories, request)
	relationships := awsAgentCoreGatewayPolicyAdvisoryRelationships(filtered)
	diagnostics := awsAgentCoreGatewayPolicyAdvisoryDiagnostics(upstream.Diagnostics)
	coverageGaps := awsAgentCoreGatewayPolicyAdvisoryCoverageGaps(upstream.CoverageGaps)
	status, confidence := summarizeAWSAgentCoreGatewayPolicyAdvisoryStatus(upstream.Status, filtered, diagnostics)

	return AWSAgentCoreGatewayPolicyAdvisoryResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsAgentCoreGatewayPolicyAdvisoryCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsAgentCoreGatewayPolicyAdvisoryCurrentIssue),
		Version:            awsAgentCoreGatewayPolicyAdvisoryVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsAgentCoreGatewayPolicyAdvisoryVersion,
		PolicyVersion:      awsAgentCoreGatewayPolicyAdvisoryPolicyID,
		Mode:               awsAgentCoreGatewayPolicyAdvisoryModeAdvisory,
		PilotState:         summarizeAWSAgentCoreGatewayPolicyPilotState(filtered),
		EnforcementState:   awsAgentCoreGatewayPolicyEnforcementAdvisory,
		AppliedFilters:     applied,
		Summary:            summarizeAWSAgentCoreGatewayPolicyAdvisories(advisories, filtered, relationships),
		Advisories:         filtered,
		Relationships:      relationships,
		Caveats:            awsAgentCoreGatewayPolicyAdvisoryCaveats(),
		FailureReasons:     dedupeStrings(upstream.FailureReasons),
		RemediationHints:   awsAgentCoreGatewayPolicyAdvisoryHints(upstream.RemediationHints),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsAgentCoreGatewayPolicyAdvisoryCurrentIssue),
			awsIssueURL(awsAIAgentRiskCurrentIssue),
			"/docs/aws-agentcore-gateway-policy-advisory",
			"/docs/aws-ai-agent-risk-engine",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSAgentCoreGatewayPolicyAdvisoryFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "", "success", "ready":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsAgentCoreGatewayPolicyAdvisoryEntries(findings []AWSAIAgentRiskFinding, now time.Time) []AWSAgentCoreGatewayPolicyAdvisoryEntry {
	entries := make([]AWSAgentCoreGatewayPolicyAdvisoryEntry, 0, len(findings))
	for _, finding := range findings {
		if !awsAgentCoreGatewayPolicyAdvisoryAdmits(finding) {
			continue
		}
		entries = append(entries, awsAgentCoreGatewayPolicyAdvisoryFromFinding(finding, now))
	}
	return entries
}

// awsAgentCoreGatewayPolicyAdvisoryAdmits requires an addressable agent so
// the advisory has a subject to attach to; findings without an agent node
// ID cannot be surfaced as a gateway policy recommendation.
func awsAgentCoreGatewayPolicyAdvisoryAdmits(finding AWSAIAgentRiskFinding) bool {
	return strings.TrimSpace(finding.AgentNodeID) != ""
}

func awsAgentCoreGatewayPolicyAdvisoryFromFinding(finding AWSAIAgentRiskFinding, now time.Time) AWSAgentCoreGatewayPolicyAdvisoryEntry {
	outcome, rule, rationale, confidence := awsAgentCoreGatewayPolicyAdvisoryClassify(finding)
	toolNames := emptyStrings(dedupeStrings(finding.ToolNames))
	sensitiveResources := emptyStrings(dedupeStrings(finding.SensitiveResources))
	allowed, restricted, blocked := awsAgentCoreGatewayPolicyAdvisoryToolPartition(outcome, toolNames)
	recommended := awsAgentCoreGatewayPolicyAdvisoryRecommendedActions(outcome, restricted, blocked, sensitiveResources)
	advisoryID := "aws-agentcore-gateway-policy-advisory:" + stableAWSBlastRadiusToken("advisory", finding.FindingID, finding.AgentNodeID)
	inputHash := awsAgentCoreGatewayPolicyAdvisoryInputHash(finding, outcome)
	provenance := AWSAgentCoreGatewayPolicyAdvisoryProvenance{
		PolicyVersion: awsAgentCoreGatewayPolicyAdvisoryPolicyID,
		PolicyRule:    rule,
		Signals: dedupeStrings([]string{
			"risk_type=" + finding.RiskType,
			"severity=" + finding.Severity,
			"status=" + finding.Status,
		}),
	}
	return AWSAgentCoreGatewayPolicyAdvisoryEntry{
		AdvisoryID:          advisoryID,
		CalculationVersion:  awsAgentCoreGatewayPolicyAdvisoryVersion,
		Mode:                awsAgentCoreGatewayPolicyAdvisoryModeAdvisory,
		Outcome:             outcome,
		PilotState:          awsAgentCoreGatewayPolicyAdvisoryPilotState(outcome),
		EnforcementState:    awsAgentCoreGatewayPolicyEnforcementAdvisory,
		Confidence:          confidence,
		Severity:            finding.Severity,
		Score:               finding.Score,
		Title:               fmt.Sprintf("AgentCore gateway policy advisory: %s", firstNonEmptyAWSValue(finding.AgentName, finding.AgentID, finding.AgentNodeID)),
		Summary:             fmt.Sprintf("Advisory-only AgentCore gateway policy recommendation for agent %s (outcome=%s). Identrail records the recommendation, provenance, and audit only; no live gateway or IAM write API is called at this layer.", firstNonEmptyAWSValue(finding.AgentNodeID, finding.AgentID), outcome),
		Rationale:           rationale,
		AccountID:           finding.AccountID,
		Region:              finding.Region,
		AgentNodeID:         finding.AgentNodeID,
		AgentID:             finding.AgentID,
		AgentName:           finding.AgentName,
		AgentType:           finding.AgentType,
		Provider:            finding.Provider,
		RuntimeRoleARN:      finding.RuntimeRoleARN,
		RuntimeRoleNodeID:   finding.RuntimeRoleNodeID,
		FindingID:           finding.FindingID,
		RiskType:            finding.RiskType,
		AllowedToolNames:    allowed,
		RestrictedToolNames: restricted,
		BlockedToolNames:    blocked,
		SensitiveResources:  sensitiveResources,
		RecommendedActions:  recommended,
		Provenance:          provenance,
		InputHash:           inputHash,
		Evidence:            finding.Evidence,
		EvidenceBoundary:    awsAgentCoreGatewayPolicyAdvisoryEvidenceBoundary(),
		ImpactedNodes:       emptyStrings(dedupeStrings(finding.ImpactedNodes)),
		ImpactedPath:        finding.ImpactedPath,
		AuditTrail:          awsAgentCoreGatewayPolicyAdvisoryAuditTrail(finding, outcome, rule, now),
		ReadOnlyProjection:  true,
		SourceSignals:       dedupeStrings(append([]string{"ai_agent_risk", "agentcore_gateway_policy_advisory"}, finding.SourceSignals...)),
		NextAction:          awsAgentCoreGatewayPolicyAdvisoryNextAction(outcome),
		ProjectedAt:         now,
		CreatedAt:           firstNonZeroAWSAgentCoreGatewayPolicyAdvisoryTime(finding.CreatedAt, now),
		UpdatedAt:           now,
	}
}

// awsAgentCoreGatewayPolicyAdvisoryClassify is the deterministic policy.
// Ordering matters: high-severity confirmed exposure wins over general
// tool-scope warnings so a compromised gateway is never recorded as
// `allow_tools`.
func awsAgentCoreGatewayPolicyAdvisoryClassify(finding AWSAIAgentRiskFinding) (outcome, rule, rationale string, confidence float64) {
	severity := strings.ToLower(strings.TrimSpace(finding.Severity))
	riskType := strings.ToLower(strings.TrimSpace(finding.RiskType))
	sensitiveCount := len(emptyStrings(finding.SensitiveResources))
	toolCount := len(emptyStrings(finding.ToolNames))

	if severity == "critical" && sensitiveCount > 0 {
		return awsAgentCoreGatewayPolicyOutcomeBlockTools, "critical_sensitive_reachability", "Critical-severity finding reaches sensitive resources; recommend blocking the affected tool calls until the reachability is remediated.", 0.92
	}
	switch riskType {
	case "external_credential", "external_credentials", "external_credential_exposure":
		return awsAgentCoreGatewayPolicyOutcomeRequireApproval, "external_credential_use", "Agent runtime uses external credentials; require operator approval before allowing gateway tool calls.", 0.88
	case "broad_tool_access", "broad_tool_scope":
		return awsAgentCoreGatewayPolicyOutcomeRestrictTools, "broad_tool_access", "Agent exposes a broad tool namespace; recommend restricting the tool scope to the observed usage set.", 0.85
	case "sensitive_reachability", "sensitive_data_reachability":
		return awsAgentCoreGatewayPolicyOutcomeRestrictTools, "sensitive_reachability", "Agent gateway can reach sensitive resources; recommend restricting the tool scope and requiring approvals on the exposed tool calls.", 0.85
	case "undeclared_tool_runtime", "backing_role_mismatch":
		return awsAgentCoreGatewayPolicyOutcomeRequireApproval, "runtime_governance_review", "Agent runtime evidence does not match the declared gateway or backing-role model; require operator approval before allowing the affected tool calls.", 0.82
	case "runtime_tool_anomaly", "declared_unused_tool", "backing_role_scope":
		return awsAgentCoreGatewayPolicyOutcomeRestrictTools, "runtime_tool_scope_review", "Agent runtime or backing-role evidence requires review; restrict the affected tool scope until the risk-engine finding is resolved.", 0.8
	case "ownerless_agent":
		return awsAgentCoreGatewayPolicyOutcomeWarn, "ownerless_agent", "Agent has no assigned owner; warn operators and assign an owner before broadening the tool scope.", 0.78
	}
	if severity == "critical" || severity == "high" {
		return awsAgentCoreGatewayPolicyOutcomeRequireApproval, "high_severity_finding", "High-severity agent risk finding; require operator approval before allowing gateway tool calls.", 0.8
	}
	if toolCount == 0 {
		return awsAgentCoreGatewayPolicyOutcomeWarn, "unknown_tool_scope", "Agent finding does not carry a resolved tool namespace; warn operators and refresh runtime evidence before allowing tool calls.", 0.72
	}
	return awsAgentCoreGatewayPolicyOutcomeAllowTools, "no_active_risk", "No active elevated risk on the agent gateway; allow the observed tool namespace with advisory monitoring.", 0.75
}

// awsAgentCoreGatewayPolicyAdvisoryToolPartition splits the finding's tool
// namespace into allowed, restricted, and blocked buckets based on outcome.
// The buckets stay disjoint so the app UI and downstream consumers can render
// the recommendation without overlap.
func awsAgentCoreGatewayPolicyAdvisoryToolPartition(outcome string, tools []string) (allowed, restricted, blocked []string) {
	switch outcome {
	case awsAgentCoreGatewayPolicyOutcomeBlockTools:
		return nil, nil, tools
	case awsAgentCoreGatewayPolicyOutcomeRestrictTools, awsAgentCoreGatewayPolicyOutcomeRequireApproval:
		return nil, tools, nil
	case awsAgentCoreGatewayPolicyOutcomeWarn:
		return tools, nil, nil
	case awsAgentCoreGatewayPolicyOutcomeAllowTools:
		return tools, nil, nil
	}
	return tools, nil, nil
}

func awsAgentCoreGatewayPolicyAdvisoryPilotState(outcome string) string {
	switch outcome {
	case awsAgentCoreGatewayPolicyOutcomeAllowTools:
		return awsAgentCoreGatewayPolicyPilotStateCandidate
	case awsAgentCoreGatewayPolicyOutcomeBlockTools:
		return awsAgentCoreGatewayPolicyPilotStateBlocked
	default:
		return awsAgentCoreGatewayPolicyPilotStateReview
	}
}

func summarizeAWSAgentCoreGatewayPolicyPilotState(entries []AWSAgentCoreGatewayPolicyAdvisoryEntry) string {
	for _, entry := range entries {
		if entry.PilotState == awsAgentCoreGatewayPolicyPilotStateBlocked {
			return awsAgentCoreGatewayPolicyPilotStateBlocked
		}
	}
	for _, entry := range entries {
		if entry.PilotState == awsAgentCoreGatewayPolicyPilotStateReview {
			return awsAgentCoreGatewayPolicyPilotStateReview
		}
	}
	return awsAgentCoreGatewayPolicyPilotStateCandidate
}

func awsAgentCoreGatewayPolicyAdvisoryRecommendedActions(outcome string, restricted, blocked, sensitiveResources []string) []string {
	actions := []string{}
	switch outcome {
	case awsAgentCoreGatewayPolicyOutcomeAllowTools:
		actions = append(actions, "Continue advisory monitoring of gateway tool calls; no operator action is required unless upstream signals change.")
	case awsAgentCoreGatewayPolicyOutcomeWarn:
		actions = append(actions, "Prioritize agent risk triage; refresh runtime evidence and assign an owner before broadening the tool scope.")
	case awsAgentCoreGatewayPolicyOutcomeRequireApproval:
		actions = append(actions, "Require operator approval on the affected gateway tool calls before allowing new sessions.")
		if len(restricted) > 0 {
			actions = append(actions, "Scope the approval to the affected tool namespace: "+strings.Join(restricted, ", "))
		}
	case awsAgentCoreGatewayPolicyOutcomeRestrictTools:
		actions = append(actions, "Restrict the gateway tool scope to the observed usage set only.")
		if len(restricted) > 0 {
			actions = append(actions, "Affected tools: "+strings.Join(restricted, ", "))
		}
	case awsAgentCoreGatewayPolicyOutcomeBlockTools:
		actions = append(actions, "Block the affected gateway tool calls until the sensitive reachability is remediated.")
		if len(blocked) > 0 {
			actions = append(actions, "Blocked tools: "+strings.Join(blocked, ", "))
		}
	}
	if len(sensitiveResources) > 0 && outcome != awsAgentCoreGatewayPolicyOutcomeAllowTools {
		actions = append(actions, "Sensitive reachability: "+strings.Join(sensitiveResources, ", "))
	}
	return actions
}

func awsAgentCoreGatewayPolicyAdvisoryInputHash(finding AWSAIAgentRiskFinding, outcome string) AWSAgentCoreGatewayPolicyAdvisoryInputHash {
	toolsDigest := awsAgentCoreGatewayPolicyAdvisoryListDigest(finding.ToolNames)
	sensitiveDigest := awsAgentCoreGatewayPolicyAdvisoryListDigest(finding.SensitiveResources)
	toolCount := len(normalizeOrderedStringList(dedupeStrings(finding.ToolNames)))
	sensitiveCount := len(normalizeOrderedStringList(dedupeStrings(finding.SensitiveResources)))
	value := stableAWSBlastRadiusToken(
		"agentcore-input",
		finding.FindingID,
		finding.AgentNodeID,
		finding.RiskType,
		finding.Severity,
		finding.Status,
		fmt.Sprintf("tools=%d", toolCount),
		"tools_digest="+toolsDigest,
		fmt.Sprintf("sensitive=%d", sensitiveCount),
		"sensitive_digest="+sensitiveDigest,
		outcome,
		awsAgentCoreGatewayPolicyAdvisoryVersion,
		awsAgentCoreGatewayPolicyAdvisoryPolicyID,
	)
	return AWSAgentCoreGatewayPolicyAdvisoryInputHash{
		Value: value,
		Components: []string{
			"finding_id=" + finding.FindingID,
			"agent_node_id=" + finding.AgentNodeID,
			"risk_type=" + finding.RiskType,
			"severity=" + finding.Severity,
			"status=" + finding.Status,
			fmt.Sprintf("tool_count=%d", toolCount),
			"tool_names_sha256=" + toolsDigest,
			fmt.Sprintf("sensitive_count=%d", sensitiveCount),
			"sensitive_resources_sha256=" + sensitiveDigest,
			"policy_version=" + awsAgentCoreGatewayPolicyAdvisoryPolicyID,
		},
	}
}

func awsAgentCoreGatewayPolicyAdvisoryListDigest(values []string) string {
	normalized := normalizeOrderedStringList(dedupeStrings(values))
	sort.Strings(normalized)
	sum := sha256.New()
	for _, value := range normalized {
		sum.Write([]byte(value))
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func awsAgentCoreGatewayPolicyAdvisoryNextAction(outcome string) string {
	switch outcome {
	case awsAgentCoreGatewayPolicyOutcomeAllowTools:
		return "Recommendation is `allow_tools`. Continue advisory monitoring; no operator action is required unless upstream signals change."
	case awsAgentCoreGatewayPolicyOutcomeWarn:
		return "Recommendation is `warn`. Prioritize agent risk triage and refresh runtime evidence before broadening the tool scope."
	case awsAgentCoreGatewayPolicyOutcomeRequireApproval:
		return "Recommendation is `require_approval`. Route the agent gateway session through the operator approval workflow before allowing tool calls."
	case awsAgentCoreGatewayPolicyOutcomeRestrictTools:
		return "Recommendation is `restrict_tools`. Constrain the gateway tool scope to the observed usage set before allowing new sessions."
	case awsAgentCoreGatewayPolicyOutcomeBlockTools:
		return "Recommendation is `block_tools`. Disable the affected gateway tool calls until sensitive reachability is remediated."
	}
	return "Inspect the advisory entry for the projected next action."
}

func awsAgentCoreGatewayPolicyAdvisoryAuditTrail(finding AWSAIAgentRiskFinding, outcome, rule string, now time.Time) []AWSAgentCoreGatewayPolicyAdvisoryAuditEntry {
	return []AWSAgentCoreGatewayPolicyAdvisoryAuditEntry{{
		EventID:    stableAWSBlastRadiusToken("agentcore-advisory-projected", finding.FindingID, outcome, rule),
		Actor:      "identrail-agentcore-gateway-policy-advisor",
		EventType:  "agentcore_gateway_policy_advisory_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Finding=%s outcome=%s rule=%s policy_version=%s; Identrail did not call any AWS write API at this layer.", finding.FindingID, outcome, rule, awsAgentCoreGatewayPolicyAdvisoryPolicyID),
	}}
}

func awsAgentCoreGatewayPolicyAdvisoryRelationships(entries []AWSAgentCoreGatewayPolicyAdvisoryEntry) []AWSAgentCoreGatewayPolicyAdvisoryRelationship {
	relationships := []AWSAgentCoreGatewayPolicyAdvisoryRelationship{}
	for _, entry := range entries {
		if strings.TrimSpace(entry.AgentNodeID) != "" {
			relationships = append(relationships, AWSAgentCoreGatewayPolicyAdvisoryRelationship{
				AdvisoryID: entry.AdvisoryID,
				Type:       "advises_agent_gateway",
				FromNodeID: entry.AdvisoryID,
				ToNodeID:   entry.AgentNodeID,
			})
		}
		if strings.TrimSpace(entry.RuntimeRoleNodeID) != "" {
			relationships = append(relationships, AWSAgentCoreGatewayPolicyAdvisoryRelationship{
				AdvisoryID: entry.AdvisoryID,
				Type:       "advises_runtime_role",
				FromNodeID: entry.AdvisoryID,
				ToNodeID:   entry.RuntimeRoleNodeID,
			})
		}
		for _, resource := range entry.SensitiveResources {
			if strings.TrimSpace(resource) == "" {
				continue
			}
			relationships = append(relationships, AWSAgentCoreGatewayPolicyAdvisoryRelationship{
				AdvisoryID: entry.AdvisoryID,
				Type:       "scopes_sensitive_resource",
				FromNodeID: entry.AdvisoryID,
				ToNodeID:   resource,
			})
		}
	}
	return relationships
}

func summarizeAWSAgentCoreGatewayPolicyAdvisories(all, filtered []AWSAgentCoreGatewayPolicyAdvisoryEntry, relationships []AWSAgentCoreGatewayPolicyAdvisoryRelationship) AWSAgentCoreGatewayPolicyAdvisorySummary {
	summary := AWSAgentCoreGatewayPolicyAdvisorySummary{
		TotalAdvisories:    len(all),
		FilteredAdvisories: len(filtered),
		OutcomeCounts:      map[string]int{},
		SeverityCounts:     map[string]int{},
		RiskTypeCounts:     map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		summary.OutcomeCounts[entry.Outcome]++
		if entry.Severity != "" {
			summary.SeverityCounts[entry.Severity]++
		}
		if entry.RiskType != "" {
			summary.RiskTypeCounts[entry.RiskType]++
		}
		switch entry.Outcome {
		case awsAgentCoreGatewayPolicyOutcomeAllowTools:
			summary.AllowToolsCount++
		case awsAgentCoreGatewayPolicyOutcomeWarn:
			summary.WarnCount++
		case awsAgentCoreGatewayPolicyOutcomeRequireApproval:
			summary.RequireApprovalCount++
		case awsAgentCoreGatewayPolicyOutcomeRestrictTools:
			summary.RestrictToolsCount++
		case awsAgentCoreGatewayPolicyOutcomeBlockTools:
			summary.BlockToolsCount++
		}
		summary.RestrictedToolCount += len(entry.RestrictedToolNames) + len(entry.BlockedToolNames)
		summary.SensitiveResourceCount += len(entry.SensitiveResources)
		if entry.Score > summary.HighestScore {
			summary.HighestScore = entry.Score
		}
		confidenceTotal += entry.Confidence
	}
	summary.RelationshipCount = len(relationships)
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func filterAWSAgentCoreGatewayPolicyAdvisories(entries []AWSAgentCoreGatewayPolicyAdvisoryEntry, request AWSAgentCoreGatewayPolicyAdvisoryRequest) ([]AWSAgentCoreGatewayPolicyAdvisoryEntry, map[string]string) {
	filters := map[string]string{
		"account_id": strings.TrimSpace(request.AccountID),
		"region":     strings.TrimSpace(request.Region),
		"agent_id":   strings.TrimSpace(request.AgentID),
		"outcome":    normalizeAWSRuntimeEventFilterToken(request.Outcome),
		"risk_type":  strings.ToLower(strings.TrimSpace(request.RiskType)),
		"severity":   normalizeAWSRuntimeEventFilterToken(request.Severity),
		"finding_id": strings.TrimSpace(request.FindingID),
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
	filtered := make([]AWSAgentCoreGatewayPolicyAdvisoryEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && !strings.EqualFold(filters["account_id"], strings.TrimSpace(entry.AccountID)) {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], strings.TrimSpace(entry.Region)) {
			continue
		}
		if filters["agent_id"] != "" && !strings.EqualFold(filters["agent_id"], strings.TrimSpace(entry.AgentID)) && !strings.EqualFold(filters["agent_id"], strings.TrimSpace(entry.AgentNodeID)) {
			continue
		}
		if filters["outcome"] != "" && filters["outcome"] != normalizeAWSRuntimeEventFilterToken(entry.Outcome) {
			continue
		}
		if filters["risk_type"] != "" && !strings.EqualFold(filters["risk_type"], entry.RiskType) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["finding_id"] != "" && !strings.EqualFold(filters["finding_id"], entry.FindingID) {
			continue
		}
		if filters["search"] != "" && !awsAgentCoreGatewayPolicyAdvisorySearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsAgentCoreGatewayPolicyAdvisorySearchMatch(entry AWSAgentCoreGatewayPolicyAdvisoryEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.AdvisoryID, entry.Outcome, entry.Severity, entry.Title, entry.Summary,
		entry.Rationale, entry.AgentNodeID, entry.AgentID, entry.AgentName, entry.AgentType,
		entry.Provider, entry.RuntimeRoleARN, entry.RuntimeRoleNodeID, entry.FindingID,
		entry.RiskType, entry.NextAction, entry.Provenance.PolicyRule, entry.Provenance.PolicyVersion,
	}
	values = append(values, entry.AllowedToolNames...)
	values = append(values, entry.RestrictedToolNames...)
	values = append(values, entry.BlockedToolNames...)
	values = append(values, entry.SensitiveResources...)
	values = append(values, entry.RecommendedActions...)
	values = append(values, entry.SourceSignals...)
	values = append(values, entry.Provenance.Signals...)
	for _, evidence := range entry.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef)
	}
	for _, audit := range entry.AuditTrail {
		values = append(values, audit.EventType, audit.Actor, audit.Notes)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSAgentCoreGatewayPolicyAdvisoryStatus(upstream string, filtered []AWSAgentCoreGatewayPolicyAdvisoryEntry, diagnostics []AWSAgentCoreGatewayPolicyAdvisoryDiagnostic) (string, float64) {
	if upstream == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if upstream == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsAgentCoreGatewayPolicyAdvisoryCaveats() []string {
	return []string{
		"AgentCore gateway policy advisories are read-only recommendations; Identrail never enforces the outcome at this layer.",
		"Prompt text, tool payloads, and workload data are never inlined; tool restrictions reference the tool namespace by name only.",
		"Critical-severity findings that reach sensitive resources always classify as block_tools; the policy prevents a compromised gateway from being recorded as allow_tools.",
	}
}

func awsAgentCoreGatewayPolicyAdvisoryHints(source []string) []string {
	hints := []string{
		"Treat this endpoint as advisory input to AgentCore gateway policy decision points; downstream governance executors decide whether and how to enforce.",
		"If a recommendation moves to `block_tools`, investigate the sensitive reachability finding before re-opening the tool namespace.",
		"When the policy version changes, expect advisory IDs and input hashes to change; log both for audit.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsAgentCoreGatewayPolicyAdvisoryDiagnostics(source []AWSAIAgentRiskDiagnostic) []AWSAgentCoreGatewayPolicyAdvisoryDiagnostic {
	out := make([]AWSAgentCoreGatewayPolicyAdvisoryDiagnostic, 0, len(source))
	for _, diagnostic := range source {
		out = append(out, AWSAgentCoreGatewayPolicyAdvisoryDiagnostic(diagnostic))
	}
	return out
}

func awsAgentCoreGatewayPolicyAdvisoryCoverageGaps(source []AWSAIAgentRiskCoverageGap) []AWSAgentCoreGatewayPolicyAdvisoryCoverageGap {
	out := make([]AWSAgentCoreGatewayPolicyAdvisoryCoverageGap, 0, len(source))
	for _, gap := range source {
		out = append(out, AWSAgentCoreGatewayPolicyAdvisoryCoverageGap(gap))
	}
	return out
}

func awsAgentCoreGatewayPolicyAdvisoryEvidenceBoundary() string {
	return "metadata_only_no_prompt_text_no_tool_payloads_no_workload_data_tenant_workspace_project_connector_account_region_scoped"
}

func firstNonZeroAWSAgentCoreGatewayPolicyAdvisoryTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
