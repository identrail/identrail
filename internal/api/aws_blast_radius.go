package api

import (
	"context"
	"fmt"
	"github.com/identrail/identrail/internal/runtime/agentaccess"
	"sort"
	"strings"
	"time"
)

const (
	awsBlastRadiusCurrentIssue = 1521
	awsBlastRadiusVersion      = "aws-blast-radius-engine-v1"
)

// AWSBlastRadiusRequest scopes the blast-radius calculation to an AWS
// connector and optional drill-down filters. Empty fixture_state attempts live
// evidence when available; explicit fixture_state keeps tests and demos
// deterministic.
type AWSBlastRadiusRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Identity     string `json:"identity,omitempty"`
	Resource     string `json:"resource,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Status       string `json:"status,omitempty"`
	RiskType     string `json:"risk_type,omitempty"`
}

// AWSBlastRadiusEvidence is a metadata-only pointer to source evidence. It
// intentionally carries no secret values, prompt text, completion text, or tool
// payloads.
type AWSBlastRadiusEvidence struct {
	Source       string    `json:"source"`
	EvidenceRef  string    `json:"evidence_ref"`
	Label        string    `json:"label"`
	Confidence   float64   `json:"confidence"`
	ObservedAt   time.Time `json:"observed_at,omitzero"`
	Relationship string    `json:"relationship,omitempty"`
}

// AWSBlastRadiusPathStep is one explainable graph node in an impacted path.
type AWSBlastRadiusPathStep struct {
	NodeID    string `json:"node_id"`
	NodeType  string `json:"node_type"`
	Label     string `json:"label"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
}

// AWSBlastRadiusRelationship is an edge the graph view can join against.
type AWSBlastRadiusRelationship struct {
	FindingID   string `json:"finding_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSBlastRadiusRemediationCasePreview is the read-only planning shape the app
// can use to start a remediation case without mutating server state.
type AWSBlastRadiusRemediationCasePreview struct {
	CaseID             string   `json:"case_id"`
	Title              string   `json:"title"`
	RecommendedAction  string   `json:"recommended_action"`
	ApprovalRequired   bool     `json:"approval_required"`
	BlockingEvidence   []string `json:"blocking_evidence,omitempty"`
	ImpactedNodeCount  int      `json:"impacted_node_count"`
	EstimatedRiskDrop  int      `json:"estimated_risk_drop"`
	ReadOnlyProjection bool     `json:"read_only_projection"`
}

// AWSBlastRadiusFinding is a persisted-record-shaped intelligence result. The
// API owns stable IDs, versioning, score/rationale, evidence, impacted graph
// nodes, and a remediation preview so findings, graph, and remediation surfaces
// can consume the same contract.
type AWSBlastRadiusFinding struct {
	FindingID          string                               `json:"finding_id"`
	CalculationVersion string                               `json:"calculation_version"`
	RiskType           string                               `json:"risk_type"`
	Severity           string                               `json:"severity"`
	Status             string                               `json:"status"`
	Score              int                                  `json:"score"`
	Confidence         float64                              `json:"confidence"`
	AccountID          string                               `json:"account_id"`
	Region             string                               `json:"region"`
	IdentityNodeID     string                               `json:"identity_node_id"`
	PrincipalARN       string                               `json:"principal_arn,omitempty"`
	DisplayName        string                               `json:"display_name"`
	Rationale          string                               `json:"rationale"`
	ImpactedNodes      []string                             `json:"impacted_nodes"`
	ImpactedPath       []AWSBlastRadiusPathStep             `json:"impacted_path"`
	SensitiveNodes     []string                             `json:"sensitive_nodes,omitempty"`
	CrossAccountEdges  []string                             `json:"cross_account_edges,omitempty"`
	RuntimeActions     []string                             `json:"runtime_actions,omitempty"`
	AgentToolPaths     []string                             `json:"agent_tool_paths,omitempty"`
	Evidence           []AWSBlastRadiusEvidence             `json:"evidence"`
	NextAction         string                               `json:"next_action"`
	RemediationCase    AWSBlastRadiusRemediationCasePreview `json:"remediation_case"`
	CreatedAt          time.Time                            `json:"created_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

// AWSBlastRadiusSummary aggregates the unfiltered and filtered finding set.
type AWSBlastRadiusSummary struct {
	TotalFindings           int            `json:"total_findings"`
	FilteredFindings        int            `json:"filtered_findings"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	StatusCounts            map[string]int `json:"status_counts"`
	RiskTypeCounts          map[string]int `json:"risk_type_counts"`
	CriticalCount           int            `json:"critical_count"`
	HighCount               int            `json:"high_count"`
	SensitiveNodeCount      int            `json:"sensitive_node_count"`
	CrossAccountEdgeCount   int            `json:"cross_account_edge_count"`
	RuntimeActionCount      int            `json:"runtime_action_count"`
	AgentToolPathCount      int            `json:"agent_tool_path_count"`
	RelationshipCount       int            `json:"relationship_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
	RemediationPreviewCount int            `json:"remediation_preview_count"`
}

// AWSBlastRadiusDiagnostic reports source calculation failures.
type AWSBlastRadiusDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSBlastRadiusCoverageGap names missing or degraded evidence.
type AWSBlastRadiusCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSBlastRadiusResult is the deterministic blast-radius intelligence envelope.
type AWSBlastRadiusResult struct {
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
	Summary            AWSBlastRadiusSummary        `json:"summary"`
	Findings           []AWSBlastRadiusFinding      `json:"findings"`
	Relationships      []AWSBlastRadiusRelationship `json:"relationships"`
	Caveats            []string                     `json:"caveats"`
	FailureReasons     []string                     `json:"failure_reasons"`
	RemediationHints   []string                     `json:"remediation_hints"`
	EvidenceLinks      []string                     `json:"evidence_links"`
	CoverageGaps       []AWSBlastRadiusCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSBlastRadiusDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
}

// GetAWSBlastRadius calculates ranked blast-radius intelligence from existing
// inventory, static reachability, runtime access, and agent/tool correlation
// sources. It preserves uncertainty: absent evidence degrades confidence instead
// of becoming deterministic truth.
func (s *Service) GetAWSBlastRadius(ctx context.Context, workspaceID string, projectID string, request AWSBlastRadiusRequest) (AWSBlastRadiusResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSBlastRadiusResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSBlastRadiusResult{}, err
	}
	now := s.Now().UTC()

	fixtureState := normalizeAWSBlastRadiusFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSBlastRadiusResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")

	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	secrets, s3, agents, err := s.awsBlastRadiusSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSBlastRadiusResult{}, err
	}

	findings := awsBlastRadiusFindings(secrets, s3, agents, now)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Score > findings[j].Score
	})
	filtered, applied := filterAWSBlastRadiusFindings(findings, request)
	relationships := awsBlastRadiusRelationships(filtered)
	diagnostics := awsBlastRadiusDiagnostics(secrets, s3, agents)
	coverageGaps := awsBlastRadiusCoverageGaps(secrets, s3, agents)
	status, confidence := summarizeAWSBlastRadiusStatus([]string{secrets.Status, s3.Status, agents.Status}, filtered, diagnostics)
	summary := summarizeAWSBlastRadius(findings, filtered, relationships)

	return AWSBlastRadiusResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsBlastRadiusCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsBlastRadiusCurrentIssue),
		Version:            awsBlastRadiusVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsBlastRadiusVersion,
		AppliedFilters:     applied,
		Summary:            summary,
		Findings:           filtered,
		Relationships:      relationships,
		Caveats:            awsBlastRadiusCaveats(secrets, s3, agents),
		FailureReasons:     awsBlastRadiusFailureReasons(secrets, s3, agents),
		RemediationHints:   awsBlastRadiusRemediationHints(secrets, s3, agents),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsBlastRadiusCurrentIssue),
			awsIssueURL(awsSecretsKMSRuntimeAccessCurrentIssue),
			awsIssueURL(awsS3RuntimeAccessCurrentIssue),
			awsIssueURL(awsAgentRuntimeAccessCurrentIssue),
			"/docs/aws-blast-radius-engine",
			"/docs/aws-risk-engine",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSBlastRadiusFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsBlastRadiusSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (AWSSecretsKMSRuntimeAccessResult, AWSS3RuntimeAccessResult, AWSAgentRuntimeAccessResult, error) {
	secrets, err := s.GetAWSSecretsKMSRuntimeAccess(ctx, workspaceID, projectID, AWSSecretsKMSRuntimeAccessRequest{
		ConnectorID:  connectorID,
		FixtureState: fixtureState,
	})
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, AWSS3RuntimeAccessResult{}, AWSAgentRuntimeAccessResult{}, fmt.Errorf("calculate secrets/kms blast radius: %w", err)
	}
	s3, err := s.GetAWSS3RuntimeAccess(ctx, workspaceID, projectID, AWSS3RuntimeAccessRequest{
		ConnectorID:  connectorID,
		FixtureState: fixtureState,
	})
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, AWSS3RuntimeAccessResult{}, AWSAgentRuntimeAccessResult{}, fmt.Errorf("calculate s3 blast radius: %w", err)
	}
	agents, err := s.GetAWSAgentRuntimeAccess(ctx, workspaceID, projectID, AWSAgentRuntimeAccessRequest{
		ConnectorID:  connectorID,
		FixtureState: fixtureState,
	})
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, AWSS3RuntimeAccessResult{}, AWSAgentRuntimeAccessResult{}, fmt.Errorf("calculate agent blast radius: %w", err)
	}
	return secrets, s3, agents, nil
}

func awsBlastRadiusFindings(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult, now time.Time) []AWSBlastRadiusFinding {
	findings := []AWSBlastRadiusFinding{}
	for _, record := range secrets.Records {
		findings = append(findings, awsBlastRadiusFindingFromSecret(record, now))
	}
	for _, record := range s3.Records {
		findings = append(findings, awsBlastRadiusFindingFromS3(record, now))
	}
	for _, record := range agents.Records {
		findings = append(findings, awsBlastRadiusFindingFromAgent(record, now))
	}
	return findings
}

func awsBlastRadiusFindingFromSecret(record AWSSecretsKMSRuntimeAccessRecord, now time.Time) AWSBlastRadiusFinding {
	resourceLabel := firstNonEmptyAWSValue(record.ResourceName, record.ResourceARN, record.ResourceNodeID)
	score := 68
	riskType := "sensitive-secret-runtime-access"
	severity := "high"
	if record.CrossAccount {
		score += 12
		riskType = "cross-account-secret-runtime-access"
		severity = "critical"
	}
	if record.Status == "observed_without_grant" {
		score += 10
	}
	score = clampBlastRadiusScore(score)
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, fmt.Sprintf("secrets-kms-runtime-access://%s", record.CorrelationID))
	return AWSBlastRadiusFinding{
		FindingID:          "aws-blast-radius:" + record.CorrelationID,
		CalculationVersion: awsBlastRadiusVersion,
		RiskType:           riskType,
		Severity:           severity,
		Status:             awsBlastRadiusFindingStatus(record.Status),
		Score:              score,
		Confidence:         record.Confidence,
		AccountID:          record.AccountID,
		Region:             record.Region,
		IdentityNodeID:     record.IdentityNodeID,
		PrincipalARN:       record.PrincipalARN,
		DisplayName:        firstNonEmptyAWSValue(shortAWSARN(record.PrincipalARN), record.IdentityNodeID),
		Rationale:          fmt.Sprintf("Identity can reach sensitive %s %q with %s runtime/static correlation.", record.ResourceKind, resourceLabel, record.Status),
		ImpactedNodes:      dedupeStrings([]string{record.IdentityNodeID, record.ResourceNodeID, record.AgentNodeID}),
		ImpactedPath: []AWSBlastRadiusPathStep{
			{NodeID: record.IdentityNodeID, NodeType: "identity", Label: firstNonEmptyAWSValue(shortAWSARN(record.PrincipalARN), record.IdentityNodeID), AccountID: record.AccountID, Region: record.Region},
			{NodeID: record.ResourceNodeID, NodeType: record.ResourceKind, Label: resourceLabel, AccountID: record.AccountID, Region: record.Region},
		},
		SensitiveNodes:    dedupeStrings([]string{record.ResourceNodeID}),
		CrossAccountEdges: crossAccountEdge(record.CrossAccount, record.IdentityNodeID, record.ResourceNodeID),
		RuntimeActions:    dedupeStrings(record.Actions),
		AgentToolPaths:    dedupeStrings([]string{record.AgentNodeID}),
		Evidence:          []AWSBlastRadiusEvidence{{Source: "secrets_kms_runtime_access", EvidenceRef: evidenceRef, Label: "Secrets Manager / KMS runtime access", Confidence: record.Confidence, ObservedAt: record.LastObservedAt, Relationship: record.Status}},
		NextAction:        "Validate owner-approved secret/KMS access, then remove unused grants or constrain runtime conditions before automation.",
		RemediationCase:   awsBlastRadiusRemediationCase("secret-runtime-access", severity, score, record.IdentityNodeID, []string{evidenceRef}),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func awsBlastRadiusFindingFromS3(record AWSS3RuntimeAccessRecord, now time.Time) AWSBlastRadiusFinding {
	resourceLabel := firstNonEmptyAWSValue(record.BucketName, record.BucketARN, record.ResourceNodeID)
	score := 58
	riskType := "s3-runtime-access"
	severity := "medium"
	if normalizeAWSRuntimeEventFilterToken(record.Sensitivity) == "high" || normalizeAWSRuntimeEventFilterToken(record.Exposure) == "external" {
		score += 18
		severity = "high"
		riskType = "sensitive-s3-runtime-access"
	}
	if record.CrossAccount {
		score += 10
		riskType = "cross-account-s3-runtime-access"
	}
	if record.Status == "observed_without_grant" {
		score += 8
	}
	score = clampBlastRadiusScore(score)
	if score >= 85 {
		severity = "critical"
	}
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, fmt.Sprintf("s3-runtime-access://%s", record.CorrelationID))
	return AWSBlastRadiusFinding{
		FindingID:          "aws-blast-radius:" + record.CorrelationID,
		CalculationVersion: awsBlastRadiusVersion,
		RiskType:           riskType,
		Severity:           severity,
		Status:             awsBlastRadiusFindingStatus(record.Status),
		Score:              score,
		Confidence:         record.Confidence,
		AccountID:          record.AccountID,
		Region:             record.Region,
		IdentityNodeID:     record.IdentityNodeID,
		PrincipalARN:       record.PrincipalARN,
		DisplayName:        firstNonEmptyAWSValue(shortAWSARN(record.PrincipalARN), record.IdentityNodeID),
		Rationale:          fmt.Sprintf("Identity has %s S3 access to %q; sensitivity=%s exposure=%s status=%s.", strings.Join(record.ObservedModes, "/"), resourceLabel, firstNonEmptyAWSValue(record.Sensitivity, "unknown"), firstNonEmptyAWSValue(record.Exposure, "unknown"), record.Status),
		ImpactedNodes:      dedupeStrings([]string{record.IdentityNodeID, record.ResourceNodeID, record.AgentNodeID}),
		ImpactedPath: []AWSBlastRadiusPathStep{
			{NodeID: record.IdentityNodeID, NodeType: "identity", Label: firstNonEmptyAWSValue(shortAWSARN(record.PrincipalARN), record.IdentityNodeID), AccountID: record.AccountID, Region: record.Region},
			{NodeID: record.ResourceNodeID, NodeType: "s3_bucket", Label: resourceLabel, AccountID: record.AccountID, Region: record.Region},
		},
		SensitiveNodes:    sensitiveS3Node(record),
		CrossAccountEdges: crossAccountEdge(record.CrossAccount, record.IdentityNodeID, record.ResourceNodeID),
		RuntimeActions:    dedupeStrings(append(append([]string{}, record.Actions...), record.ObservedModes...)),
		AgentToolPaths:    dedupeStrings([]string{record.AgentNodeID}),
		Evidence:          []AWSBlastRadiusEvidence{{Source: "s3_runtime_access", EvidenceRef: evidenceRef, Label: "S3 runtime access", Confidence: record.Confidence, ObservedAt: record.LastObservedAt, Relationship: record.Status}},
		NextAction:        "Confirm the data owner and reduce bucket actions, prefixes, or cross-account grants before scheduling automated deny changes.",
		RemediationCase:   awsBlastRadiusRemediationCase("s3-runtime-access", severity, score, record.IdentityNodeID, []string{evidenceRef}),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func awsBlastRadiusFindingFromAgent(record AWSAgentRuntimeAccessRecord, now time.Time) AWSBlastRadiusFinding {
	roleNodes := dedupeStrings(append(append([]string{}, record.BackingRoleNodeIDs...), record.DeclaredBackingRoleNode))
	if len(roleNodes) == 0 {
		roleNodes = dedupeStrings([]string{record.AgentNodeID})
	}
	roleNode := firstNonEmptyAWSValue(firstString(roleNodes), record.AgentNodeID)
	roleARN := firstNonEmptyAWSValue(firstString(record.BackingRoleARNs), record.DeclaredBackingRole)
	targetSteps := awsBlastRadiusAgentTargetSteps(record.TargetResourceNodeIDs, record.TargetResourceARNs, record.AccountID, record.Region)
	score := 52
	severity := "medium"
	riskType := "agent-tool-path"
	switch normalizeAWSRuntimeEventFilterToken(record.Status) {
	case "observed-without-declaration":
		score = 78
		severity = "high"
		riskType = "undeclared-agent-tool-path"
	case "declared-unused":
		score = 46
		riskType = "unused-agent-tool-path"
	case "confirmed":
		if len(record.Caveats) > 0 {
			score = 64
			severity = "high"
			riskType = "agent-tool-path-with-caveats"
		}
	}
	if awsStringSliceContains(record.Caveats, agentaccess.CaveatBackingRoleMismatch) {
		score += 8
	}
	score = clampBlastRadiusScore(score)
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, fmt.Sprintf("agent-runtime-access://%s", record.CorrelationID))
	impactedNodes := dedupeStrings(append(append(roleNodes, record.AgentNodeID), append(record.TargetResourceNodeIDs, record.TargetResourceARNs...)...))
	return AWSBlastRadiusFinding{
		FindingID:          "aws-blast-radius:" + record.CorrelationID,
		CalculationVersion: awsBlastRadiusVersion,
		RiskType:           riskType,
		Severity:           severity,
		Status:             awsBlastRadiusFindingStatus(record.Status),
		Score:              score,
		Confidence:         record.Confidence,
		AccountID:          record.AccountID,
		Region:             record.Region,
		IdentityNodeID:     roleNode,
		PrincipalARN:       roleARN,
		DisplayName:        firstNonEmptyAWSValue(record.AgentName, record.AgentID, shortAWSARN(roleARN), roleNode),
		Rationale:          fmt.Sprintf("Agent %q tool %q is %s and expands the identity path to %d target node(s).", firstNonEmptyAWSValue(record.AgentName, record.AgentID, record.AgentNodeID), firstNonEmptyAWSValue(record.ToolName, "unknown-tool"), record.Status, len(targetSteps)),
		ImpactedNodes:      impactedNodes,
		ImpactedPath: awsBlastRadiusAgentIdentityRolePath(
			roleNodes,
			targetSteps,
			firstNonEmptyAWSValue(shortAWSARN(roleARN), record.AgentNodeID),
			record.AgentNodeID,
			record.AgentName,
			record.AgentID,
			record.AccountID,
			record.Region,
		),
		RuntimeActions: dedupeStrings(record.Outcomes),
		AgentToolPaths: dedupeStrings([]string{
			strings.TrimSpace(record.AgentNodeID + " -> " + firstNonEmptyAWSValue(record.ToolName, record.ToolTargetRef)),
		}),
		Evidence:        []AWSBlastRadiusEvidence{{Source: "agent_runtime_access", EvidenceRef: evidenceRef, Label: "Agent runtime / tool path", Confidence: record.Confidence, ObservedAt: record.LastObservedAt, Relationship: record.Status}},
		NextAction:      "Confirm whether the agent/tool path is expected, then remove undeclared tools or stale declarations before policy automation.",
		RemediationCase: awsBlastRadiusRemediationCase("agent-tool-path", severity, score, roleNode, []string{evidenceRef}),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func awsBlastRadiusAgentTargetSteps(targetResourceNodeIDs []string, targetResourceARNs []string, accountID string, region string) []AWSBlastRadiusPathStep {
	targetSteps := dedupeStrings(append(append([]string{}, targetResourceNodeIDs...), targetResourceARNs...))
	if len(targetSteps) == 0 {
		return nil
	}
	steps := make([]AWSBlastRadiusPathStep, 0, len(targetSteps))
	for _, targetNode := range targetSteps {
		steps = append(steps, AWSBlastRadiusPathStep{
			NodeID:    targetNode,
			NodeType:  "target_resource",
			Label:     strings.TrimSpace(targetNode),
			AccountID: strings.TrimSpace(accountID),
			Region:    strings.TrimSpace(region),
		})
	}
	return steps
}

func awsBlastRadiusAgentIdentityRolePath(roleNodes []string, targetSteps []AWSBlastRadiusPathStep, roleLabel string, agentNodeID string, agentName string, agentID string, accountID string, region string) []AWSBlastRadiusPathStep {
	if len(roleNodes) == 0 {
		return nil
	}
	agentStep := AWSBlastRadiusPathStep{
		NodeID:    agentNodeID,
		NodeType:  "ai_agent",
		Label:     firstNonEmptyAWSValue(agentName, agentID, agentNodeID),
		AccountID: strings.TrimSpace(accountID),
		Region:    strings.TrimSpace(region),
	}
	paths := make([]AWSBlastRadiusPathStep, 0, len(roleNodes)*(len(targetSteps)+1))
	for _, roleNode := range roleNodes {
		paths = append(paths, AWSBlastRadiusPathStep{
			NodeID:    roleNode,
			NodeType:  "identity",
			Label:     firstNonEmptyAWSValue(shortAWSARN(roleNode), roleLabel),
			AccountID: strings.TrimSpace(accountID),
			Region:    strings.TrimSpace(region),
		})
		if len(targetSteps) == 0 {
			paths = append(paths, agentStep)
			continue
		}
		for _, targetStep := range targetSteps {
			paths = append(paths, agentStep, targetStep)
		}
	}
	return paths
}

func awsBlastRadiusFindingStatus(sourceStatus string) string {
	switch normalizeAWSRuntimeEventFilterToken(sourceStatus) {
	case "observed-without-grant", "observed-without-declaration":
		return "action_required"
	case "declared-unused", "granted-unused":
		return "review"
	case "confirmed":
		return "monitor"
	default:
		return "review"
	}
}

func awsBlastRadiusRemediationCase(kind, severity string, score int, identityNodeID string, evidence []string) AWSBlastRadiusRemediationCasePreview {
	action := "Review owner approval and create a least-privilege remediation case."
	switch kind {
	case "secret-runtime-access":
		action = "Create a case to remove stale secret/KMS grants or add scoped conditions."
	case "s3-runtime-access":
		action = "Create a case to reduce bucket actions, prefixes, or external account grants."
	case "agent-tool-path":
		action = "Create a case to remove undeclared/stale agent tool access after owner approval."
	}
	return AWSBlastRadiusRemediationCasePreview{
		CaseID:             "aws-remediation-preview:" + stableAWSBlastRadiusToken(kind, identityNodeID),
		Title:              fmt.Sprintf("%s blast-radius remediation", formatAWSBlastRadiusLabel(kind)),
		RecommendedAction:  action,
		ApprovalRequired:   severity == "critical" || severity == "high",
		BlockingEvidence:   dedupeStrings(evidence),
		ImpactedNodeCount:  1,
		EstimatedRiskDrop:  minInt(score, 35),
		ReadOnlyProjection: true,
	}
}

func filterAWSBlastRadiusFindings(findings []AWSBlastRadiusFinding, request AWSBlastRadiusRequest) ([]AWSBlastRadiusFinding, map[string]string) {
	filters := map[string]string{
		"account_id": strings.TrimSpace(request.AccountID),
		"region":     strings.TrimSpace(request.Region),
		"identity":   strings.TrimSpace(request.Identity),
		"resource":   strings.TrimSpace(request.Resource),
		"severity":   normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":     normalizeAWSRuntimeEventFilterToken(request.Status),
		"risk_type":  normalizeAWSRuntimeEventFilterToken(request.RiskType),
	}
	for key, value := range filters {
		token := strings.TrimSpace(value)
		if token == "" || strings.EqualFold(token, "all") {
			delete(filters, key)
		}
	}
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSBlastRadiusFinding, 0, len(findings))
	for _, finding := range findings {
		if filters["account_id"] != "" && filters["account_id"] != finding.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], finding.Region) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(finding.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(finding.Status) {
			continue
		}
		if filters["risk_type"] != "" && filters["risk_type"] != normalizeAWSRuntimeEventFilterToken(finding.RiskType) {
			continue
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], awsBlastRadiusIdentityMatchValues(finding)...) {
			continue
		}
		if filters["resource"] != "" && !awsRuntimeEventMatchesAny(filters["resource"], awsBlastRadiusResourceMatchValues(finding)...) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, applied
}

func awsBlastRadiusResourceMatchValues(finding AWSBlastRadiusFinding) []string {
	candidates := append(append([]string{}, finding.ImpactedNodes...), finding.SensitiveNodes...)
	for _, step := range finding.ImpactedPath {
		candidates = append(candidates, step.NodeID, step.Label)
	}
	return dedupeStrings(candidates)
}

func awsBlastRadiusIdentityMatchValues(finding AWSBlastRadiusFinding) []string {
	candidates := []string{finding.IdentityNodeID, finding.PrincipalARN, finding.DisplayName}
	for _, step := range finding.ImpactedPath {
		if strings.EqualFold(strings.TrimSpace(step.NodeType), "identity") {
			candidates = append(candidates, step.NodeID, step.Label)
		}
	}
	return dedupeStrings(candidates)
}

func awsBlastRadiusRelationships(findings []AWSBlastRadiusFinding) []AWSBlastRadiusRelationship {
	relationships := []AWSBlastRadiusRelationship{}
	for _, finding := range findings {
		for i := 0; i+1 < len(finding.ImpactedPath); i++ {
			fromNode := finding.ImpactedPath[i]
			toNode := finding.ImpactedPath[i+1]
			from := strings.TrimSpace(fromNode.NodeID)
			to := strings.TrimSpace(toNode.NodeID)
			if from == "" || to == "" {
				continue
			}
			fromType := strings.TrimSpace(fromNode.NodeType)
			toType := strings.TrimSpace(toNode.NodeType)
			if !awsBlastRadiusAllowsPathTransition(finding.RiskType, fromType, toType) {
				continue
			}
			relationships = append(relationships, AWSBlastRadiusRelationship{
				FindingID:   finding.FindingID,
				Type:        "blast_radius_path",
				FromNodeID:  from,
				ToNodeID:    to,
				EvidenceRef: firstEvidenceRef(finding.Evidence),
			})
		}
		for _, edge := range finding.CrossAccountEdges {
			parts := strings.Split(edge, "->")
			if len(parts) != 2 {
				continue
			}
			relationships = append(relationships, AWSBlastRadiusRelationship{
				FindingID:   finding.FindingID,
				Type:        "cross_account_blast_radius",
				FromNodeID:  strings.TrimSpace(parts[0]),
				ToNodeID:    strings.TrimSpace(parts[1]),
				EvidenceRef: firstEvidenceRef(finding.Evidence),
			})
		}
	}
	return relationships
}

func awsBlastRadiusAllowsPathTransition(findingType string, fromType string, toType string) bool {
	switch normalizeAWSRuntimeEventFilterToken(findingType) {
	case "agent-tool-path", "agent-tool-path-with-caveats", "undeclared-agent-tool-path", "unused-agent-tool-path":
		return (fromType == "identity" && toType == "ai_agent") || (fromType == "ai_agent" && toType == "target_resource")
	default:
		return true
	}
}

func summarizeAWSBlastRadius(allFindings []AWSBlastRadiusFinding, filtered []AWSBlastRadiusFinding, relationships []AWSBlastRadiusRelationship) AWSBlastRadiusSummary {
	severityCounts := map[string]int{}
	statusCounts := map[string]int{}
	riskTypeCounts := map[string]int{}
	sensitiveNodes := map[string]struct{}{}
	crossAccountEdges := map[string]struct{}{}
	totalRuntimeActions := 0
	totalAgentPaths := 0
	totalConfidence := 0.0
	highest := 0
	remediationCases := map[string]struct{}{}
	for _, finding := range allFindings {
		severityCounts[finding.Severity]++
		statusCounts[finding.Status]++
		riskTypeCounts[finding.RiskType]++
		for _, node := range finding.SensitiveNodes {
			sensitiveNodes[node] = struct{}{}
		}
		for _, edge := range finding.CrossAccountEdges {
			crossAccountEdges[edge] = struct{}{}
		}
		totalRuntimeActions += len(finding.RuntimeActions)
		totalAgentPaths += len(finding.AgentToolPaths)
		totalConfidence += finding.Confidence
		if finding.Score > highest {
			highest = finding.Score
		}
		if finding.RemediationCase.CaseID != "" {
			remediationCases[finding.RemediationCase.CaseID] = struct{}{}
		}
	}
	averageConfidence := 0
	if len(allFindings) > 0 {
		averageConfidence = int((totalConfidence / float64(len(allFindings))) * 100)
	}
	return AWSBlastRadiusSummary{
		TotalFindings:           len(allFindings),
		FilteredFindings:        len(filtered),
		SeverityCounts:          severityCounts,
		StatusCounts:            statusCounts,
		RiskTypeCounts:          riskTypeCounts,
		CriticalCount:           severityCounts["critical"],
		HighCount:               severityCounts["high"],
		SensitiveNodeCount:      len(sensitiveNodes),
		CrossAccountEdgeCount:   len(crossAccountEdges),
		RuntimeActionCount:      totalRuntimeActions,
		AgentToolPathCount:      totalAgentPaths,
		RelationshipCount:       len(relationships),
		HighestScore:            highest,
		AverageConfidencePct:    averageConfidence,
		RemediationPreviewCount: len(remediationCases),
	}
}

func summarizeAWSBlastRadiusStatus(sourceStatuses []string, filtered []AWSBlastRadiusFinding, diagnostics []AWSBlastRadiusDiagnostic) (string, float64) {
	allBlocked := len(sourceStatuses) > 0
	anyDegraded := len(diagnostics) > 0
	for _, status := range sourceStatuses {
		switch status {
		case awsPlatformDependencyStatusBlocked:
			anyDegraded = true
		case awsPlatformDependencyStatusDegraded:
			allBlocked = false
			anyDegraded = true
		default:
			allBlocked = false
		}
	}
	if allBlocked {
		return awsPlatformDependencyStatusBlocked, 0
	}
	if len(filtered) == 0 || anyDegraded {
		return awsPlatformDependencyStatusDegraded, 0.68
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsBlastRadiusDiagnostics(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult) []AWSBlastRadiusDiagnostic {
	out := []AWSBlastRadiusDiagnostic{}
	for _, diagnostic := range secrets.Diagnostics {
		out = append(out, AWSBlastRadiusDiagnostic(diagnostic))
	}
	for _, diagnostic := range s3.Diagnostics {
		out = append(out, AWSBlastRadiusDiagnostic(diagnostic))
	}
	for _, diagnostic := range agents.Diagnostics {
		out = append(out, AWSBlastRadiusDiagnostic(diagnostic))
	}
	return out
}

func awsBlastRadiusCoverageGaps(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult) []AWSBlastRadiusCoverageGap {
	out := []AWSBlastRadiusCoverageGap{{
		Capability:  "blast_radius_persistence",
		Status:      "ready",
		Reason:      "The API emits stable finding IDs, calculation version, evidence, impacted path, and remediation preview fields for downstream persistence/graph consumers.",
		Remediation: "Persist these intelligence records into the shared findings store when the dedicated AWS findings table lands.",
	}}
	for _, gap := range secrets.CoverageGaps {
		out = append(out, AWSBlastRadiusCoverageGap(gap))
	}
	for _, gap := range s3.CoverageGaps {
		out = append(out, AWSBlastRadiusCoverageGap(gap))
	}
	for _, gap := range agents.CoverageGaps {
		out = append(out, AWSBlastRadiusCoverageGap(gap))
	}
	return out
}

func awsBlastRadiusCaveats(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult) []string {
	return dedupeStrings(append(append(secrets.Caveats, s3.Caveats...), append(agents.Caveats, "Unknown runtime evidence lowers confidence; it never upgrades severity by itself.")...))
}

func awsBlastRadiusFailureReasons(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult) []string {
	return emptyStrings(dedupeStrings(append(append(secrets.FailureReasons, s3.FailureReasons...), agents.FailureReasons...)))
}

func awsBlastRadiusRemediationHints(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult) []string {
	return emptyStrings(dedupeStrings(append(append(append(secrets.RemediationHints, s3.RemediationHints...), agents.RemediationHints...), "Use the remediation preview as a read-only plan until an owner approves policy changes.")))
}

func crossAccountEdge(enabled bool, from string, to string) []string {
	if !enabled || strings.TrimSpace(from) == "" || strings.TrimSpace(to) == "" {
		return nil
	}
	return []string{strings.TrimSpace(from) + " -> " + strings.TrimSpace(to)}
}

func sensitiveS3Node(record AWSS3RuntimeAccessRecord) []string {
	if normalizeAWSRuntimeEventFilterToken(record.Sensitivity) == "high" || normalizeAWSRuntimeEventFilterToken(record.Exposure) == "external" {
		return dedupeStrings([]string{record.ResourceNodeID})
	}
	return nil
}

func shortAWSARN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.LastIndex(value, "/"); idx >= 0 && idx+1 < len(value) {
		return value[idx+1:]
	}
	if idx := strings.LastIndex(value, ":"); idx >= 0 && idx+1 < len(value) {
		return value[idx+1:]
	}
	return value
}

func firstString(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstEvidenceRef(evidence []AWSBlastRadiusEvidence) string {
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			return item.EvidenceRef
		}
	}
	return ""
}

func awsStringSliceContains(values []string, want string) bool {
	want = normalizeAWSRuntimeEventFilterToken(want)
	for _, value := range values {
		if normalizeAWSRuntimeEventFilterToken(value) == want {
			return true
		}
	}
	return false
}

func stableAWSBlastRadiusToken(parts ...string) string {
	return strings.ReplaceAll(strings.Trim(strings.ToLower(strings.Join(parts, "-")), "-"), " ", "-")
}

func formatAWSBlastRadiusLabel(token string) string {
	return strings.ReplaceAll(strings.TrimSpace(token), "-", " ")
}

func clampBlastRadiusScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
