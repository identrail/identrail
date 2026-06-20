package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsLeastPrivilegeCurrentIssue = 1522
	awsLeastPrivilegeVersion      = "aws-least-privilege-recommendation-engine-v1"
)

// AWSLeastPrivilegeRequest scopes the least-privilege calculation to an AWS
// connector and optional drill-down filters. Empty fixture_state attempts live
// evidence when available; explicit fixture_state keeps tests and demos
// deterministic.
type AWSLeastPrivilegeRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Identity     string `json:"identity,omitempty"`
	Resource     string `json:"resource,omitempty"`
	Service      string `json:"service,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Status       string `json:"status,omitempty"`
	Decision     string `json:"decision,omitempty"`
}

// AWSLeastPrivilegeEvidence is a metadata-only pointer to source evidence. It
// intentionally carries no secret values, prompts, completions, object bodies,
// database rows, or customer payloads.
type AWSLeastPrivilegeEvidence struct {
	Source       string    `json:"source"`
	EvidenceRef  string    `json:"evidence_ref"`
	Label        string    `json:"label"`
	Confidence   float64   `json:"confidence"`
	ObservedAt   time.Time `json:"observed_at,omitzero"`
	Relationship string    `json:"relationship,omitempty"`
}

// AWSLeastPrivilegePathStep is one explainable node in a recommendation path.
type AWSLeastPrivilegePathStep struct {
	NodeID    string `json:"node_id"`
	NodeType  string `json:"node_type"`
	Label     string `json:"label"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
}

// AWSLeastPrivilegeRelationship is an edge the graph view can join against.
type AWSLeastPrivilegeRelationship struct {
	RecommendationID string `json:"recommendation_id"`
	Type             string `json:"type"`
	FromNodeID       string `json:"from_node_id"`
	ToNodeID         string `json:"to_node_id"`
	EvidenceRef      string `json:"evidence_ref"`
}

// AWSLeastPrivilegeRemediationCasePreview is the read-only planning shape the
// app can use to start a remediation case without mutating AWS or Identrail
// state.
type AWSLeastPrivilegeRemediationCasePreview struct {
	CaseID             string   `json:"case_id"`
	Title              string   `json:"title"`
	RecommendedAction  string   `json:"recommended_action"`
	ApprovalRequired   bool     `json:"approval_required"`
	BlockingEvidence   []string `json:"blocking_evidence,omitempty"`
	ImpactedNodeCount  int      `json:"impacted_node_count"`
	EstimatedRiskDrop  int      `json:"estimated_risk_drop"`
	BreakagePrediction string   `json:"breakage_prediction"`
	ReadOnlyProjection bool     `json:"read_only_projection"`
}

// AWSLeastPrivilegeRecommendation is a persisted-record-shaped intelligence
// result. It preserves the keep/remove/review decision, confidence, breakage
// prediction, rationale, impacted graph path, and remediation preview in one
// deterministic contract.
type AWSLeastPrivilegeRecommendation struct {
	RecommendationID   string                                  `json:"recommendation_id"`
	CalculationVersion string                                  `json:"calculation_version"`
	RecommendationType string                                  `json:"recommendation_type"`
	Decision           string                                  `json:"decision"`
	Severity           string                                  `json:"severity"`
	Status             string                                  `json:"status"`
	Score              int                                     `json:"score"`
	Confidence         float64                                 `json:"confidence"`
	AccountID          string                                  `json:"account_id"`
	Region             string                                  `json:"region"`
	Service            string                                  `json:"service"`
	IdentityNodeID     string                                  `json:"identity_node_id"`
	PrincipalARN       string                                  `json:"principal_arn,omitempty"`
	ResourceNodeID     string                                  `json:"resource_node_id,omitempty"`
	ResourceARN        string                                  `json:"resource_arn,omitempty"`
	DisplayName        string                                  `json:"display_name"`
	Rationale          string                                  `json:"rationale"`
	BreakagePrediction string                                  `json:"breakage_prediction"`
	BreakageRationale  string                                  `json:"breakage_rationale"`
	KeepActions        []string                                `json:"keep_actions,omitempty"`
	RemoveActions      []string                                `json:"remove_actions,omitempty"`
	ObservedActions    []string                                `json:"observed_actions,omitempty"`
	GrantedActions     []string                                `json:"granted_actions,omitempty"`
	ImpactedNodes      []string                                `json:"impacted_nodes"`
	ImpactedPath       []AWSLeastPrivilegePathStep             `json:"impacted_path"`
	Evidence           []AWSLeastPrivilegeEvidence             `json:"evidence"`
	NextAction         string                                  `json:"next_action"`
	RemediationCase    AWSLeastPrivilegeRemediationCasePreview `json:"remediation_case"`
	CreatedAt          time.Time                               `json:"created_at"`
	UpdatedAt          time.Time                               `json:"updated_at"`
}

// AWSLeastPrivilegeSummary aggregates the unfiltered and filtered set.
type AWSLeastPrivilegeSummary struct {
	TotalRecommendations     int            `json:"total_recommendations"`
	FilteredRecommendations  int            `json:"filtered_recommendations"`
	DecisionCounts           map[string]int `json:"decision_counts"`
	SeverityCounts           map[string]int `json:"severity_counts"`
	StatusCounts             map[string]int `json:"status_counts"`
	ServiceCounts            map[string]int `json:"service_counts"`
	RemoveCount              int            `json:"remove_count"`
	KeepCount                int            `json:"keep_count"`
	ReviewCount              int            `json:"review_count"`
	LowBreakageCount         int            `json:"low_breakage_count"`
	UnknownBreakageCount     int            `json:"unknown_breakage_count"`
	RuntimeEvidenceCount     int            `json:"runtime_evidence_count"`
	RelationshipCount        int            `json:"relationship_count"`
	HighestScore             int            `json:"highest_score"`
	AverageConfidencePct     int            `json:"average_confidence_pct"`
	RemediationPreviewCount  int            `json:"remediation_preview_count"`
	PermissionDeniedEvidence int            `json:"permission_denied_evidence_count"`
}

// AWSLeastPrivilegeDiagnostic reports source calculation failures.
type AWSLeastPrivilegeDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSLeastPrivilegeCoverageGap names missing or degraded evidence.
type AWSLeastPrivilegeCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSLeastPrivilegeResult is the deterministic least-privilege envelope.
type AWSLeastPrivilegeResult struct {
	TenantID           string                            `json:"tenant_id"`
	WorkspaceID        string                            `json:"workspace_id"`
	ProjectID          string                            `json:"project_id"`
	ConnectorID        string                            `json:"connector_id,omitempty"`
	AccountID          string                            `json:"account_id,omitempty"`
	Region             string                            `json:"region,omitempty"`
	ParentIssueNumber  int                               `json:"parent_issue_number"`
	ParentIssueRef     string                            `json:"parent_issue_ref"`
	CurrentIssueNumber int                               `json:"current_issue_number"`
	CurrentIssueRef    string                            `json:"current_issue_ref"`
	Version            string                            `json:"version"`
	Status             string                            `json:"status"`
	FixtureState       string                            `json:"fixture_state,omitempty"`
	Confidence         float64                           `json:"confidence"`
	CalculationVersion string                            `json:"calculation_version"`
	AppliedFilters     map[string]string                 `json:"applied_filters"`
	Summary            AWSLeastPrivilegeSummary          `json:"summary"`
	Recommendations    []AWSLeastPrivilegeRecommendation `json:"recommendations"`
	Relationships      []AWSLeastPrivilegeRelationship   `json:"relationships"`
	Caveats            []string                          `json:"caveats"`
	FailureReasons     []string                          `json:"failure_reasons"`
	RemediationHints   []string                          `json:"remediation_hints"`
	EvidenceLinks      []string                          `json:"evidence_links"`
	CoverageGaps       []AWSLeastPrivilegeCoverageGap    `json:"coverage_gaps"`
	Diagnostics        []AWSLeastPrivilegeDiagnostic     `json:"diagnostics"`
	GeneratedAt        time.Time                         `json:"generated_at"`
	UpdatedAt          time.Time                         `json:"updated_at"`
}

// GetAWSLeastPrivilegeRecommendations calculates keep/remove/review
// recommendations from static grants, runtime evidence, IAM last-used, Access
// Analyzer, and agent/tool correlation. Unknown evidence becomes an explicit
// review state rather than a deterministic remove decision.
func (s *Service) GetAWSLeastPrivilegeRecommendations(ctx context.Context, workspaceID string, projectID string, request AWSLeastPrivilegeRequest) (AWSLeastPrivilegeResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSLeastPrivilegeResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSLeastPrivilegeResult{}, err
	}
	now := s.Now().UTC()

	fixtureState := normalizeAWSLeastPrivilegeFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSLeastPrivilegeResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := strings.TrimSpace(request.ConnectorID)
	if connectorID == "" {
		connectorID = strings.TrimSpace(connection.ConnectorID)
	}

	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	suppressRuntimeFixtures := strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected
	secrets, s3, agents, runtime, err := s.awsLeastPrivilegeSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState, suppressRuntimeFixtures)
	if err != nil {
		return AWSLeastPrivilegeResult{}, err
	}

	recommendations := awsLeastPrivilegeRecommendations(secrets, s3, agents, runtime, now)
	sort.SliceStable(recommendations, func(i, j int) bool {
		if recommendations[i].Score == recommendations[j].Score {
			return recommendations[i].RecommendationID < recommendations[j].RecommendationID
		}
		return recommendations[i].Score > recommendations[j].Score
	})
	filtered, applied := filterAWSLeastPrivilegeRecommendations(recommendations, request)
	relationships := awsLeastPrivilegeRelationships(filtered)
	diagnostics := awsLeastPrivilegeDiagnostics(secrets, s3, agents, runtime)
	coverageGaps := awsLeastPrivilegeCoverageGaps(secrets, s3, agents, runtime)
	status, confidence := summarizeAWSLeastPrivilegeStatus([]string{secrets.Status, s3.Status, agents.Status, runtime.Status}, filtered, diagnostics)
	summary := summarizeAWSLeastPrivilege(recommendations, filtered, relationships)

	return AWSLeastPrivilegeResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsLeastPrivilegeCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsLeastPrivilegeCurrentIssue),
		Version:            awsLeastPrivilegeVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsLeastPrivilegeVersion,
		AppliedFilters:     applied,
		Summary:            summary,
		Recommendations:    filtered,
		Relationships:      relationships,
		Caveats:            awsLeastPrivilegeCaveats(secrets, s3, agents, runtime),
		FailureReasons:     awsLeastPrivilegeFailureReasons(secrets, s3, agents, runtime),
		RemediationHints:   awsLeastPrivilegeRemediationHints(secrets, s3, agents, runtime),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			awsIssueURL(awsRuntimeEventsCurrentIssue),
			awsIssueURL(awsBlastRadiusCurrentIssue),
			"/docs/aws-least-privilege-engine",
			"/docs/aws-runtime-events",
			"/docs/aws-blast-radius-engine",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSLeastPrivilegeFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsLeastPrivilegeSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string, suppressRuntimeFixtures bool) (AWSSecretsKMSRuntimeAccessResult, AWSS3RuntimeAccessResult, AWSAgentRuntimeAccessResult, AWSRuntimeEventResult, error) {
	secrets, err := s.GetAWSSecretsKMSRuntimeAccess(ctx, workspaceID, projectID, AWSSecretsKMSRuntimeAccessRequest{
		ConnectorID:  connectorID,
		FixtureState: fixtureState,
	})
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, AWSS3RuntimeAccessResult{}, AWSAgentRuntimeAccessResult{}, AWSRuntimeEventResult{}, fmt.Errorf("calculate secrets/kms least privilege: %w", err)
	}
	s3, err := s.GetAWSS3RuntimeAccess(ctx, workspaceID, projectID, AWSS3RuntimeAccessRequest{
		ConnectorID:  connectorID,
		FixtureState: fixtureState,
	})
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, AWSS3RuntimeAccessResult{}, AWSAgentRuntimeAccessResult{}, AWSRuntimeEventResult{}, fmt.Errorf("calculate s3 least privilege: %w", err)
	}
	agents, err := s.GetAWSAgentRuntimeAccess(ctx, workspaceID, projectID, AWSAgentRuntimeAccessRequest{
		ConnectorID:  connectorID,
		FixtureState: fixtureState,
	})
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, AWSS3RuntimeAccessResult{}, AWSAgentRuntimeAccessResult{}, AWSRuntimeEventResult{}, fmt.Errorf("calculate agent least privilege: %w", err)
	}
	runtime, err := s.GetAWSRuntimeEvents(ctx, workspaceID, projectID, AWSRuntimeEventRequest{
		ConnectorID:            connectorID,
		FixtureState:           fixtureState,
		SuppressFixtureRecords: suppressRuntimeFixtures,
	})
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, AWSS3RuntimeAccessResult{}, AWSAgentRuntimeAccessResult{}, AWSRuntimeEventResult{}, fmt.Errorf("calculate runtime signal least privilege: %w", err)
	}
	return secrets, s3, agents, runtime, nil
}

func awsLeastPrivilegeRecommendations(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult, runtime AWSRuntimeEventResult, now time.Time) []AWSLeastPrivilegeRecommendation {
	recommendations := []AWSLeastPrivilegeRecommendation{}
	for _, record := range secrets.Records {
		recommendations = append(recommendations, awsLeastPrivilegeRecommendationFromSecret(record, now))
	}
	for _, record := range s3.Records {
		recommendations = append(recommendations, awsLeastPrivilegeRecommendationFromS3(record, now)...)
	}
	for _, record := range agents.Records {
		recommendations = append(recommendations, awsLeastPrivilegeRecommendationFromAgent(record, now))
	}
	for _, record := range runtime.Records {
		if recommendation, ok := awsLeastPrivilegeRecommendationFromRuntimeSignal(record, now); ok {
			recommendations = append(recommendations, recommendation)
		}
	}
	return recommendations
}

func awsLeastPrivilegeRecommendationFromSecret(record AWSSecretsKMSRuntimeAccessRecord, now time.Time) AWSLeastPrivilegeRecommendation {
	resourceLabel := firstNonEmptyAWSValue(record.ResourceName, record.ResourceARN, record.ResourceNodeID)
	actions := awsLeastPrivilegeSecretActions(record)
	decision, status, recommendationType, severity, score := awsLeastPrivilegeDecisionForGrantStatus(record.Status, "secret-kms")
	breakage := awsLeastPrivilegeBreakagePrediction(decision, record.Status, record.Confidence, record.ObservedCount, record.Caveats)
	keepActions, removeActions := awsLeastPrivilegeKeepRemoveActions(decision, actions)
	if decision == "remove" {
		removeActions = actions
	}
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, firstString(record.EvidenceRefs), fmt.Sprintf("secrets-kms-runtime-access://%s", record.CorrelationID))
	rationale := fmt.Sprintf("%s access for %q is %s with %d observed event(s) and %d static grant action(s).", strings.ToUpper(record.ResourceKind), resourceLabel, record.Status, record.ObservedCount, len(actions))
	if decision == "remove" {
		rationale = fmt.Sprintf("Static %s grant to %q has no matching runtime evidence in the scoped window.", record.ResourceKind, resourceLabel)
	}
	return AWSLeastPrivilegeRecommendation{
		RecommendationID:   "aws-least-privilege:" + record.CorrelationID,
		CalculationVersion: awsLeastPrivilegeVersion,
		RecommendationType: recommendationType,
		Decision:           decision,
		Severity:           severity,
		Status:             status,
		Score:              score,
		Confidence:         record.Confidence,
		AccountID:          record.AccountID,
		Region:             record.Region,
		Service:            awsLeastPrivilegeServiceForSecret(record.ResourceKind, actions),
		IdentityNodeID:     record.IdentityNodeID,
		PrincipalARN:       record.PrincipalARN,
		ResourceNodeID:     record.ResourceNodeID,
		ResourceARN:        record.ResourceARN,
		DisplayName:        firstNonEmptyAWSValue(shortAWSARN(record.PrincipalARN), record.IdentityNodeID),
		Rationale:          rationale,
		BreakagePrediction: breakage,
		BreakageRationale:  awsLeastPrivilegeBreakageRationale(decision, breakage, record.ObservedCount, record.Caveats),
		KeepActions:        keepActions,
		RemoveActions:      removeActions,
		ObservedActions:    awsLeastPrivilegeObservedActions(record.ObservedCount, actions),
		GrantedActions:     actions,
		ImpactedNodes:      dedupeStrings([]string{record.IdentityNodeID, record.ResourceNodeID, record.AgentNodeID}),
		ImpactedPath: []AWSLeastPrivilegePathStep{
			awsLeastPrivilegePathStep(record.IdentityNodeID, "identity", firstNonEmptyAWSValue(shortAWSARN(record.PrincipalARN), record.IdentityNodeID), record.AccountID, record.Region),
			awsLeastPrivilegePathStep(record.ResourceNodeID, record.ResourceKind, resourceLabel, record.AccountID, record.Region),
		},
		Evidence:        []AWSLeastPrivilegeEvidence{{Source: "secrets_kms_runtime_access", EvidenceRef: evidenceRef, Label: "Secrets Manager / KMS runtime access", Confidence: record.Confidence, ObservedAt: record.LastObservedAt, Relationship: record.Status}},
		NextAction:      awsLeastPrivilegeNextAction(decision, "secret/KMS", breakage),
		RemediationCase: awsLeastPrivilegeRemediationCase(recommendationType, decision, severity, score, breakage, record.IdentityNodeID, []string{evidenceRef}),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func awsLeastPrivilegeRecommendationFromS3(record AWSS3RuntimeAccessRecord, now time.Time) []AWSLeastPrivilegeRecommendation {
	resourceLabel := firstNonEmptyAWSValue(record.BucketName, record.BucketARN, record.ResourceNodeID)
	grantedActions := awsLeastPrivilegeS3Actions(record)
	observedActions := awsLeastPrivilegeS3ObservedActions(record)
	unusedActions := subtractStringSet(grantedActions, observedActions)
	recommendations := []AWSLeastPrivilegeRecommendation{}
	if len(unusedActions) > 0 && normalizeAWSRuntimeEventFilterToken(record.Status) == "confirmed" {
		recommendations = append(recommendations, awsLeastPrivilegeS3Recommendation(record, now, "remove", "review", "reduce-unused-s3-actions", awsLeastPrivilegeS3Severity(record, 64), 64, unusedActions, observedActions, grantedActions, resourceLabel))
		return recommendations
	}
	decision, status, recommendationType, severity, score := awsLeastPrivilegeDecisionForGrantStatus(record.Status, "s3")
	if normalizeAWSRuntimeEventFilterToken(record.Sensitivity) == "high" || normalizeAWSRuntimeEventFilterToken(record.Exposure) == "external" {
		score = minInt(score+8, 100)
		if severity == "medium" {
			severity = "high"
		}
	}
	removeActions := []string{}
	if decision == "remove" {
		removeActions = grantedActions
	}
	recommendations = append(recommendations, awsLeastPrivilegeS3Recommendation(record, now, decision, status, recommendationType, severity, score, removeActions, observedActions, grantedActions, resourceLabel))
	return recommendations
}

func awsLeastPrivilegeS3Recommendation(record AWSS3RuntimeAccessRecord, now time.Time, decision string, status string, recommendationType string, severity string, score int, removeActions []string, observedActions []string, grantedActions []string, resourceLabel string) AWSLeastPrivilegeRecommendation {
	breakage := awsLeastPrivilegeBreakagePrediction(decision, record.Status, record.Confidence, record.ObservedCount, record.Caveats)
	if recommendationType == "reduce-unused-s3-actions" && breakage == "low" {
		breakage = "medium"
	}
	keepActions := observedActions
	if decision == "keep" {
		keepActions = grantedActions
	}
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, firstString(record.EvidenceRefs), fmt.Sprintf("s3-runtime-access://%s", record.CorrelationID))
	rationale := fmt.Sprintf("S3 access to %q is %s; observed modes=%s granted modes=%s sensitivity=%s exposure=%s.", resourceLabel, record.Status, strings.Join(record.ObservedModes, "/"), strings.Join(record.GrantedModes, "/"), firstNonEmptyAWSValue(record.Sensitivity, "unknown"), firstNonEmptyAWSValue(record.Exposure, "unknown"))
	if recommendationType == "reduce-unused-s3-actions" {
		rationale = fmt.Sprintf("S3 grant to %q includes action modes with no matching runtime evidence: %s.", resourceLabel, strings.Join(removeActions, ", "))
	}
	return AWSLeastPrivilegeRecommendation{
		RecommendationID:   "aws-least-privilege:" + stableAWSBlastRadiusToken(record.CorrelationID, recommendationType),
		CalculationVersion: awsLeastPrivilegeVersion,
		RecommendationType: recommendationType,
		Decision:           decision,
		Severity:           severity,
		Status:             status,
		Score:              clampBlastRadiusScore(score),
		Confidence:         record.Confidence,
		AccountID:          record.AccountID,
		Region:             record.Region,
		Service:            "s3",
		IdentityNodeID:     record.IdentityNodeID,
		PrincipalARN:       record.PrincipalARN,
		ResourceNodeID:     record.ResourceNodeID,
		ResourceARN:        record.BucketARN,
		DisplayName:        firstNonEmptyAWSValue(shortAWSARN(record.PrincipalARN), record.IdentityNodeID),
		Rationale:          rationale,
		BreakagePrediction: breakage,
		BreakageRationale:  awsLeastPrivilegeBreakageRationale(decision, breakage, record.ObservedCount, record.Caveats),
		KeepActions:        dedupeStrings(keepActions),
		RemoveActions:      dedupeStrings(removeActions),
		ObservedActions:    observedActions,
		GrantedActions:     grantedActions,
		ImpactedNodes:      dedupeStrings([]string{record.IdentityNodeID, record.ResourceNodeID, record.AgentNodeID}),
		ImpactedPath: []AWSLeastPrivilegePathStep{
			awsLeastPrivilegePathStep(record.IdentityNodeID, "identity", firstNonEmptyAWSValue(shortAWSARN(record.PrincipalARN), record.IdentityNodeID), record.AccountID, record.Region),
			awsLeastPrivilegePathStep(record.ResourceNodeID, "s3_bucket", resourceLabel, record.AccountID, record.Region),
		},
		Evidence:        []AWSLeastPrivilegeEvidence{{Source: "s3_runtime_access", EvidenceRef: evidenceRef, Label: "S3 runtime access", Confidence: record.Confidence, ObservedAt: record.LastObservedAt, Relationship: record.Status}},
		NextAction:      awsLeastPrivilegeNextAction(decision, "S3", breakage),
		RemediationCase: awsLeastPrivilegeRemediationCase(recommendationType, decision, severity, score, breakage, record.IdentityNodeID, []string{evidenceRef}),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func awsLeastPrivilegeRecommendationFromAgent(record AWSAgentRuntimeAccessRecord, now time.Time) AWSLeastPrivilegeRecommendation {
	roleNode := firstNonEmptyAWSValue(firstString(record.BackingRoleNodeIDs), record.DeclaredBackingRoleNode, record.AgentNodeID)
	roleARN := firstNonEmptyAWSValue(firstString(record.BackingRoleARNs), record.DeclaredBackingRole)
	decision, status, recommendationType, severity, score := awsLeastPrivilegeDecisionForAgentStatus(record.Status)
	breakage := awsLeastPrivilegeBreakagePrediction(decision, record.Status, record.Confidence, record.ObservedCount, record.Caveats)
	toolAction := "agent-tool:" + firstNonEmptyAWSValue(record.ToolName, record.ToolTargetRef, record.AgentID, record.AgentNodeID)
	removeActions := []string{}
	keepActions := []string{}
	if decision == "remove" {
		removeActions = []string{toolAction}
	} else {
		keepActions = []string{toolAction}
	}
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, firstString(record.EvidenceRefs), fmt.Sprintf("agent-runtime-access://%s", record.CorrelationID))
	targetSteps := awsLeastPrivilegeAgentTargetSteps(record.TargetResourceNodeIDs, record.TargetResourceARNs, record.AccountID, record.Region)
	return AWSLeastPrivilegeRecommendation{
		RecommendationID:   "aws-least-privilege:" + record.CorrelationID,
		CalculationVersion: awsLeastPrivilegeVersion,
		RecommendationType: recommendationType,
		Decision:           decision,
		Severity:           severity,
		Status:             status,
		Score:              score,
		Confidence:         record.Confidence,
		AccountID:          record.AccountID,
		Region:             record.Region,
		Service:            "agent-runtime",
		IdentityNodeID:     roleNode,
		PrincipalARN:       roleARN,
		ResourceNodeID:     firstString(record.TargetResourceNodeIDs),
		ResourceARN:        firstString(record.TargetResourceARNs),
		DisplayName:        firstNonEmptyAWSValue(record.AgentName, record.AgentID, shortAWSARN(roleARN), roleNode),
		Rationale:          fmt.Sprintf("Agent %q tool %q is %s with %d observed call(s).", firstNonEmptyAWSValue(record.AgentName, record.AgentID, record.AgentNodeID), firstNonEmptyAWSValue(record.ToolName, "unknown-tool"), record.Status, record.ObservedCount),
		BreakagePrediction: breakage,
		BreakageRationale:  awsLeastPrivilegeBreakageRationale(decision, breakage, record.ObservedCount, record.Caveats),
		KeepActions:        keepActions,
		RemoveActions:      removeActions,
		ObservedActions:    awsLeastPrivilegeObservedActions(record.ObservedCount, []string{toolAction}),
		GrantedActions:     []string{toolAction},
		ImpactedNodes:      dedupeStrings(append(append([]string{roleNode, record.AgentNodeID}, record.TargetResourceNodeIDs...), record.TargetResourceARNs...)),
		ImpactedPath:       awsLeastPrivilegeAgentPath(roleNode, roleARN, record.AgentNodeID, record.AgentName, record.AgentID, targetSteps, record.AccountID, record.Region),
		Evidence:           []AWSLeastPrivilegeEvidence{{Source: "agent_runtime_access", EvidenceRef: evidenceRef, Label: "Agent runtime / tool path", Confidence: record.Confidence, ObservedAt: record.LastObservedAt, Relationship: record.Status}},
		NextAction:         awsLeastPrivilegeNextAction(decision, "agent tool", breakage),
		RemediationCase:    awsLeastPrivilegeRemediationCase(recommendationType, decision, severity, score, breakage, roleNode, []string{evidenceRef}),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func awsLeastPrivilegeRecommendationFromRuntimeSignal(record AWSRuntimeEventRecord, now time.Time) (AWSLeastPrivilegeRecommendation, bool) {
	category := normalizeAWSRuntimeEventFilterToken(firstNonEmptyAWSValue(record.SignalCategory, record.EventType))
	switch category {
	case "iam-last-used":
		if normalizeAWSRuntimeEventFilterToken(record.Status) != "stale" {
			return AWSLeastPrivilegeRecommendation{}, false
		}
		service := normalizeAWSRuntimeEventFilterToken(firstNonEmptyAWSValue(record.TargetResourceName, serviceFromAWSAction(record.Action), record.EventSource))
		action := awsLeastPrivilegeServiceAction(service)
		evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, fmt.Sprintf("runtime-evidence://%s", record.EventID))
		decision := "remove"
		recommendationType := "remove-stale-service-access"
		severity := "medium"
		score := 70
		breakage := "low"
		removeActions := []string{action}
		if record.Confidence < 0.75 {
			decision = "review"
			recommendationType = "review-stale-service-access"
			score = 55
			breakage = "unknown"
			removeActions = nil
		}
		keepActions, _ := awsLeastPrivilegeKeepRemoveActions(decision, []string{action})
		return AWSLeastPrivilegeRecommendation{
			RecommendationID:   "aws-least-privilege:" + record.EventID,
			CalculationVersion: awsLeastPrivilegeVersion,
			RecommendationType: recommendationType,
			Decision:           decision,
			Severity:           severity,
			Status:             "review",
			Score:              score,
			Confidence:         record.Confidence,
			AccountID:          record.AccountID,
			Region:             record.Region,
			Service:            service,
			IdentityNodeID:     record.ActorIdentityNodeID,
			PrincipalARN:       record.ActorPrincipalARN,
			ResourceNodeID:     record.ResourceNodeID,
			ResourceARN:        record.TargetResourceARN,
			DisplayName:        firstNonEmptyAWSValue(shortAWSARN(record.ActorPrincipalARN), record.ActorIdentityNodeID),
			Rationale:          fmt.Sprintf("IAM last-used reports no recent %s service access for this identity in the scoped signal window.", firstNonEmptyAWSValue(service, "AWS")),
			BreakagePrediction: breakage,
			BreakageRationale:  "IAM last-used is metadata-only evidence; verify business owner and CloudTrail coverage before removing service actions.",
			KeepActions:        keepActions,
			RemoveActions:      removeActions,
			GrantedActions:     []string{action},
			ImpactedNodes:      dedupeStrings([]string{record.ActorIdentityNodeID, record.ResourceNodeID}),
			ImpactedPath: []AWSLeastPrivilegePathStep{
				awsLeastPrivilegePathStep(record.ActorIdentityNodeID, "identity", firstNonEmptyAWSValue(shortAWSARN(record.ActorPrincipalARN), record.ActorIdentityNodeID), record.AccountID, record.Region),
				awsLeastPrivilegePathStep(record.ResourceNodeID, "aws_service", firstNonEmptyAWSValue(record.TargetResourceName, service), record.AccountID, record.Region),
			},
			Evidence:        []AWSLeastPrivilegeEvidence{{Source: "iam_last_used", EvidenceRef: evidenceRef, Label: "IAM last-used signal", Confidence: record.Confidence, ObservedAt: record.ObservedAt, Relationship: record.Status}},
			NextAction:      awsLeastPrivilegeNextAction(decision, "IAM service", breakage),
			RemediationCase: awsLeastPrivilegeRemediationCase(recommendationType, decision, severity, score, breakage, record.ActorIdentityNodeID, []string{evidenceRef}),
			CreatedAt:       now,
			UpdatedAt:       now,
		}, true
	case "access-analyzer":
		evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, fmt.Sprintf("runtime-evidence://%s", record.EventID))
		service := normalizeAWSRuntimeEventFilterToken(firstNonEmptyAWSValue(serviceFromAWSAction(record.Action), record.EventSource, record.TargetResourceType))
		return AWSLeastPrivilegeRecommendation{
			RecommendationID:   "aws-least-privilege:" + record.EventID,
			CalculationVersion: awsLeastPrivilegeVersion,
			RecommendationType: "review-external-access",
			Decision:           "review",
			Severity:           "high",
			Status:             "action_required",
			Score:              78,
			Confidence:         record.Confidence,
			AccountID:          record.AccountID,
			Region:             record.Region,
			Service:            service,
			IdentityNodeID:     record.ActorIdentityNodeID,
			PrincipalARN:       record.ActorPrincipalARN,
			ResourceNodeID:     record.ResourceNodeID,
			ResourceARN:        record.TargetResourceARN,
			DisplayName:        firstNonEmptyAWSValue(shortAWSARN(record.ActorPrincipalARN), record.ActorIdentityNodeID),
			Rationale:          fmt.Sprintf("Access Analyzer reported externally reachable %s access to %q; do not auto-remove until ownership and analyzer scope are confirmed.", firstNonEmptyAWSValue(service, "resource"), firstNonEmptyAWSValue(record.TargetResourceName, record.TargetResourceARN, record.ResourceNodeID)),
			BreakagePrediction: "unknown",
			BreakageRationale:  "Access Analyzer proves reachability, not application intent; owner review is required before generating a policy diff.",
			KeepActions:        []string{record.Action},
			ObservedActions:    []string{record.Action},
			GrantedActions:     []string{record.Action},
			ImpactedNodes:      dedupeStrings([]string{record.ActorIdentityNodeID, record.ResourceNodeID}),
			ImpactedPath: []AWSLeastPrivilegePathStep{
				awsLeastPrivilegePathStep(record.ActorIdentityNodeID, "identity", firstNonEmptyAWSValue(shortAWSARN(record.ActorPrincipalARN), record.ActorIdentityNodeID), record.AccountID, record.Region),
				awsLeastPrivilegePathStep(record.ResourceNodeID, firstNonEmptyAWSValue(record.TargetResourceType, "resource"), firstNonEmptyAWSValue(record.TargetResourceName, record.TargetResourceARN, record.ResourceNodeID), record.AccountID, record.Region),
			},
			Evidence:        []AWSLeastPrivilegeEvidence{{Source: "access_analyzer", EvidenceRef: evidenceRef, Label: "Access Analyzer finding", Confidence: record.Confidence, ObservedAt: record.ObservedAt, Relationship: record.Status}},
			NextAction:      "Confirm analyzer scope, resource owner, and expected external principal before creating a least-privilege case.",
			RemediationCase: awsLeastPrivilegeRemediationCase("review-external-access", "review", "high", 78, "unknown", record.ActorIdentityNodeID, []string{evidenceRef}),
			CreatedAt:       now,
			UpdatedAt:       now,
		}, true
	default:
		return AWSLeastPrivilegeRecommendation{}, false
	}
}

func awsLeastPrivilegeDecisionForGrantStatus(status string, source string) (string, string, string, string, int) {
	switch normalizeAWSRuntimeEventFilterToken(status) {
	case "granted-unused", "declared-unused":
		severity := "medium"
		score := 68
		if source == "secret-kms" {
			severity = "high"
			score = 82
		}
		return "remove", "review", "remove-unused-" + source + "-grant", severity, score
	case "observed-without-grant", "observed-without-declaration":
		return "keep", "action_required", "authorize-observed-" + source + "-access", "high", 78
	case "confirmed":
		return "keep", "monitor", "keep-observed-" + source + "-access", "low", 38
	default:
		return "review", "review", "review-" + source + "-access", "medium", 55
	}
}

func awsLeastPrivilegeDecisionForAgentStatus(status string) (string, string, string, string, int) {
	switch normalizeAWSRuntimeEventFilterToken(status) {
	case "declared-unused":
		return "remove", "review", "remove-unused-agent-tool", "medium", 62
	case "observed-without-declaration":
		return "review", "action_required", "review-undeclared-agent-tool", "high", 82
	case "confirmed":
		return "keep", "monitor", "keep-observed-agent-tool", "low", 36
	default:
		return "review", "review", "review-agent-tool", "medium", 55
	}
}

func awsLeastPrivilegeBreakagePrediction(decision string, status string, confidence float64, observedCount int, caveats []string) string {
	if decision == "keep" {
		return "high"
	}
	if decision == "review" {
		return "unknown"
	}
	if observedCount > 0 || normalizeAWSRuntimeEventFilterToken(status) == "observed-without-grant" || normalizeAWSRuntimeEventFilterToken(status) == "observed-without-declaration" {
		return "high"
	}
	if len(caveats) > 0 || confidence < 0.65 {
		return "unknown"
	}
	if confidence < 0.82 {
		return "medium"
	}
	return "low"
}

func awsLeastPrivilegeBreakageRationale(decision string, breakage string, observedCount int, caveats []string) string {
	if decision == "keep" {
		return "Runtime evidence shows this access is used; removing it would likely break the workload."
	}
	if decision == "review" {
		return "Evidence is not sufficient for deterministic removal; operator review is required."
	}
	if observedCount == 0 && len(caveats) == 0 && breakage == "low" {
		return "No matching runtime use was observed in the scoped evidence window, and source confidence is high."
	}
	if len(caveats) > 0 {
		return "Source caveats are present, so the recommendation must be reviewed before policy changes."
	}
	return "Runtime use was not observed, but evidence coverage is not strong enough for a low-breakage prediction."
}

func awsLeastPrivilegeKeepRemoveActions(decision string, actions []string) ([]string, []string) {
	switch decision {
	case "keep":
		return dedupeStrings(actions), nil
	case "remove":
		return nil, dedupeStrings(actions)
	default:
		return dedupeStrings(actions), nil
	}
}

func awsLeastPrivilegeObservedActions(observedCount int, actions []string) []string {
	if observedCount <= 0 {
		return nil
	}
	return dedupeStrings(actions)
}

func awsLeastPrivilegeSecretActions(record AWSSecretsKMSRuntimeAccessRecord) []string {
	actions := dedupeStrings(record.Actions)
	if len(actions) > 0 {
		return actions
	}
	switch normalizeAWSRuntimeEventFilterToken(record.ResourceKind) {
	case "kms-key", "kms_key", "kms":
		return []string{"kms:Decrypt"}
	default:
		return []string{"secretsmanager:GetSecretValue"}
	}
}

func awsLeastPrivilegeS3Actions(record AWSS3RuntimeAccessRecord) []string {
	actions := dedupeStrings(record.Actions)
	if len(actions) > 0 {
		return actions
	}
	return awsLeastPrivilegeS3ModeActions(record.GrantedModes)
}

func awsLeastPrivilegeS3ObservedActions(record AWSS3RuntimeAccessRecord) []string {
	actions := awsLeastPrivilegeS3ModeActions(record.ObservedModes)
	if len(actions) > 0 {
		return actions
	}
	return awsLeastPrivilegeObservedActions(record.ObservedCount, record.Actions)
}

func awsLeastPrivilegeS3ModeActions(modes []string) []string {
	actions := []string{}
	for _, mode := range modes {
		switch normalizeAWSRuntimeEventFilterToken(mode) {
		case "read":
			actions = append(actions, "s3:GetObject")
		case "write":
			actions = append(actions, "s3:PutObject")
		case "list":
			actions = append(actions, "s3:ListBucket")
		}
	}
	return dedupeStrings(actions)
}

func awsLeastPrivilegeS3Severity(record AWSS3RuntimeAccessRecord, score int) string {
	if score >= 85 {
		return "critical"
	}
	if normalizeAWSRuntimeEventFilterToken(record.Sensitivity) == "high" || normalizeAWSRuntimeEventFilterToken(record.Exposure) == "external" || score >= 70 {
		return "high"
	}
	if score >= 45 {
		return "medium"
	}
	return "low"
}

func awsLeastPrivilegeServiceForSecret(kind string, actions []string) string {
	for _, action := range actions {
		if service := serviceFromAWSAction(action); service != "" {
			return service
		}
	}
	switch normalizeAWSRuntimeEventFilterToken(kind) {
	case "kms-key", "kms_key", "kms":
		return "kms"
	default:
		return "secretsmanager"
	}
}

func serviceFromAWSAction(action string) string {
	action = strings.TrimSpace(action)
	if idx := strings.Index(action, ":"); idx > 0 {
		return normalizeAWSRuntimeEventFilterToken(action[:idx])
	}
	return ""
}

func awsLeastPrivilegeServiceAction(service string) string {
	service = normalizeAWSRuntimeEventFilterToken(service)
	if service == "" {
		return "aws-service:*"
	}
	return service + ":*"
}

func awsLeastPrivilegePathStep(nodeID string, nodeType string, label string, accountID string, region string) AWSLeastPrivilegePathStep {
	return AWSLeastPrivilegePathStep{
		NodeID:    strings.TrimSpace(nodeID),
		NodeType:  strings.TrimSpace(nodeType),
		Label:     firstNonEmptyAWSValue(label, nodeID),
		AccountID: strings.TrimSpace(accountID),
		Region:    strings.TrimSpace(region),
	}
}

func awsLeastPrivilegeAgentTargetSteps(targetResourceNodeIDs []string, targetResourceARNs []string, accountID string, region string) []AWSLeastPrivilegePathStep {
	targets := dedupeStrings(append(append([]string{}, targetResourceNodeIDs...), targetResourceARNs...))
	steps := make([]AWSLeastPrivilegePathStep, 0, len(targets))
	for _, target := range targets {
		steps = append(steps, awsLeastPrivilegePathStep(target, "target_resource", target, accountID, region))
	}
	return steps
}

func awsLeastPrivilegeAgentPath(roleNode string, roleARN string, agentNodeID string, agentName string, agentID string, targetSteps []AWSLeastPrivilegePathStep, accountID string, region string) []AWSLeastPrivilegePathStep {
	path := []AWSLeastPrivilegePathStep{
		awsLeastPrivilegePathStep(roleNode, "identity", firstNonEmptyAWSValue(shortAWSARN(roleARN), roleNode), accountID, region),
		awsLeastPrivilegePathStep(agentNodeID, "ai_agent", firstNonEmptyAWSValue(agentName, agentID, agentNodeID), accountID, region),
	}
	return append(path, targetSteps...)
}

func awsLeastPrivilegeNextAction(decision string, scope string, breakage string) string {
	switch decision {
	case "remove":
		return fmt.Sprintf("Open a read-only least-privilege case for %s, require owner approval, and verify %s breakage prediction before policy diff generation.", scope, breakage)
	case "keep":
		return fmt.Sprintf("Keep observed %s access and document the evidence before considering narrower resource or condition scopes.", scope)
	default:
		return fmt.Sprintf("Review %s evidence boundaries before generating a keep/remove decision.", scope)
	}
}

func awsLeastPrivilegeRemediationCase(kind, decision, severity string, score int, breakage string, identityNodeID string, evidence []string) AWSLeastPrivilegeRemediationCasePreview {
	action := "Review evidence and create a least-privilege remediation case."
	switch decision {
	case "remove":
		action = "Create a read-only case to remove unused grants after owner approval."
	case "keep":
		action = "Record keep decision with evidence, owner, and scoped follow-up."
	case "review":
		action = "Create a review case; do not generate a policy diff until evidence is confirmed."
	}
	return AWSLeastPrivilegeRemediationCasePreview{
		CaseID:             "aws-least-privilege-preview:" + stableAWSBlastRadiusToken(kind, identityNodeID),
		Title:              fmt.Sprintf("%s least-privilege %s", formatAWSBlastRadiusLabel(kind), decision),
		RecommendedAction:  action,
		ApprovalRequired:   severity == "critical" || severity == "high" || decision == "remove",
		BlockingEvidence:   dedupeStrings(evidence),
		ImpactedNodeCount:  1,
		EstimatedRiskDrop:  minInt(score, 40),
		BreakagePrediction: breakage,
		ReadOnlyProjection: true,
	}
}

func filterAWSLeastPrivilegeRecommendations(recommendations []AWSLeastPrivilegeRecommendation, request AWSLeastPrivilegeRequest) ([]AWSLeastPrivilegeRecommendation, map[string]string) {
	filters := map[string]string{
		"account_id": strings.TrimSpace(request.AccountID),
		"region":     strings.TrimSpace(request.Region),
		"identity":   strings.TrimSpace(request.Identity),
		"resource":   strings.TrimSpace(request.Resource),
		"service":    normalizeAWSRuntimeEventFilterToken(request.Service),
		"severity":   normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":     normalizeAWSRuntimeEventFilterToken(request.Status),
		"decision":   normalizeAWSRuntimeEventFilterToken(request.Decision),
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
	filtered := make([]AWSLeastPrivilegeRecommendation, 0, len(recommendations))
	for _, recommendation := range recommendations {
		if filters["account_id"] != "" && filters["account_id"] != recommendation.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], recommendation.Region) {
			continue
		}
		if filters["service"] != "" && filters["service"] != normalizeAWSRuntimeEventFilterToken(recommendation.Service) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(recommendation.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(recommendation.Status) {
			continue
		}
		if filters["decision"] != "" && filters["decision"] != normalizeAWSRuntimeEventFilterToken(recommendation.Decision) {
			continue
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], awsLeastPrivilegeIdentityMatchValues(recommendation)...) {
			continue
		}
		if filters["resource"] != "" && !awsRuntimeEventMatchesAny(filters["resource"], awsLeastPrivilegeResourceMatchValues(recommendation)...) {
			continue
		}
		filtered = append(filtered, recommendation)
	}
	return filtered, applied
}

func awsLeastPrivilegeIdentityMatchValues(recommendation AWSLeastPrivilegeRecommendation) []string {
	candidates := []string{recommendation.IdentityNodeID, recommendation.PrincipalARN, recommendation.DisplayName}
	for _, step := range recommendation.ImpactedPath {
		if strings.EqualFold(strings.TrimSpace(step.NodeType), "identity") {
			candidates = append(candidates, step.NodeID, step.Label)
		}
	}
	return dedupeStrings(candidates)
}

func awsLeastPrivilegeResourceMatchValues(recommendation AWSLeastPrivilegeRecommendation) []string {
	candidates := []string{recommendation.ResourceNodeID, recommendation.ResourceARN}
	candidates = append(candidates, recommendation.ImpactedNodes...)
	for _, step := range recommendation.ImpactedPath {
		candidates = append(candidates, step.NodeID, step.Label)
	}
	return dedupeStrings(candidates)
}

func awsLeastPrivilegeRelationships(recommendations []AWSLeastPrivilegeRecommendation) []AWSLeastPrivilegeRelationship {
	relationships := []AWSLeastPrivilegeRelationship{}
	for _, recommendation := range recommendations {
		for i := 0; i+1 < len(recommendation.ImpactedPath); i++ {
			from := strings.TrimSpace(recommendation.ImpactedPath[i].NodeID)
			to := strings.TrimSpace(recommendation.ImpactedPath[i+1].NodeID)
			if from == "" || to == "" {
				continue
			}
			relationships = append(relationships, AWSLeastPrivilegeRelationship{
				RecommendationID: recommendation.RecommendationID,
				Type:             "least_privilege_scope",
				FromNodeID:       from,
				ToNodeID:         to,
				EvidenceRef:      firstLeastPrivilegeEvidenceRef(recommendation.Evidence),
			})
		}
	}
	return relationships
}

func summarizeAWSLeastPrivilege(allRecommendations []AWSLeastPrivilegeRecommendation, filtered []AWSLeastPrivilegeRecommendation, relationships []AWSLeastPrivilegeRelationship) AWSLeastPrivilegeSummary {
	decisionCounts := map[string]int{}
	severityCounts := map[string]int{}
	statusCounts := map[string]int{}
	serviceCounts := map[string]int{}
	totalConfidence := 0.0
	highest := 0
	runtimeEvidence := 0
	remediationCases := map[string]struct{}{}
	for _, recommendation := range allRecommendations {
		decisionCounts[recommendation.Decision]++
		severityCounts[recommendation.Severity]++
		statusCounts[recommendation.Status]++
		serviceCounts[recommendation.Service]++
		totalConfidence += recommendation.Confidence
		if recommendation.Score > highest {
			highest = recommendation.Score
		}
		if recommendation.BreakagePrediction == "low" {
			// counted below from map for clarity
		}
		for _, evidence := range recommendation.Evidence {
			if strings.TrimSpace(evidence.EvidenceRef) != "" {
				runtimeEvidence++
			}
		}
		if recommendation.RemediationCase.CaseID != "" {
			remediationCases[recommendation.RemediationCase.CaseID] = struct{}{}
		}
	}
	averageConfidence := 0
	if len(allRecommendations) > 0 {
		averageConfidence = int((totalConfidence / float64(len(allRecommendations))) * 100)
	}
	return AWSLeastPrivilegeSummary{
		TotalRecommendations:     len(allRecommendations),
		FilteredRecommendations:  len(filtered),
		DecisionCounts:           decisionCounts,
		SeverityCounts:           severityCounts,
		StatusCounts:             statusCounts,
		ServiceCounts:            serviceCounts,
		RemoveCount:              decisionCounts["remove"],
		KeepCount:                decisionCounts["keep"],
		ReviewCount:              decisionCounts["review"],
		LowBreakageCount:         countLeastPrivilegeBreakage(allRecommendations, "low"),
		UnknownBreakageCount:     countLeastPrivilegeBreakage(allRecommendations, "unknown"),
		RuntimeEvidenceCount:     runtimeEvidence,
		RelationshipCount:        len(relationships),
		HighestScore:             highest,
		AverageConfidencePct:     averageConfidence,
		RemediationPreviewCount:  len(remediationCases),
		PermissionDeniedEvidence: statusCounts["permission-denied"],
	}
}

func countLeastPrivilegeBreakage(recommendations []AWSLeastPrivilegeRecommendation, breakage string) int {
	count := 0
	for _, recommendation := range recommendations {
		if normalizeAWSRuntimeEventFilterToken(recommendation.BreakagePrediction) == normalizeAWSRuntimeEventFilterToken(breakage) {
			count++
		}
	}
	return count
}

func summarizeAWSLeastPrivilegeStatus(sourceStatuses []string, filtered []AWSLeastPrivilegeRecommendation, diagnostics []AWSLeastPrivilegeDiagnostic) (string, float64) {
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
		return awsPlatformDependencyStatusDegraded, 0.7
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsLeastPrivilegeDiagnostics(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult, runtime AWSRuntimeEventResult) []AWSLeastPrivilegeDiagnostic {
	out := []AWSLeastPrivilegeDiagnostic{}
	for _, diagnostic := range secrets.Diagnostics {
		out = append(out, AWSLeastPrivilegeDiagnostic(diagnostic))
	}
	for _, diagnostic := range s3.Diagnostics {
		out = append(out, AWSLeastPrivilegeDiagnostic(diagnostic))
	}
	for _, diagnostic := range agents.Diagnostics {
		out = append(out, AWSLeastPrivilegeDiagnostic(diagnostic))
	}
	for _, diagnostic := range runtime.Diagnostics {
		out = append(out, AWSLeastPrivilegeDiagnostic(diagnostic))
	}
	return out
}

func awsLeastPrivilegeCoverageGaps(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult, runtime AWSRuntimeEventResult) []AWSLeastPrivilegeCoverageGap {
	out := []AWSLeastPrivilegeCoverageGap{{
		Capability:  "least_privilege_persistence",
		Status:      "ready",
		Reason:      "The API emits stable recommendation IDs, calculation version, evidence, keep/remove actions, breakage prediction, and remediation preview fields for downstream persistence/graph consumers.",
		Remediation: "Persist these intelligence records into the shared findings store when the dedicated AWS findings table lands.",
	}}
	for _, gap := range secrets.CoverageGaps {
		out = append(out, AWSLeastPrivilegeCoverageGap(gap))
	}
	for _, gap := range s3.CoverageGaps {
		out = append(out, AWSLeastPrivilegeCoverageGap(gap))
	}
	for _, gap := range agents.CoverageGaps {
		out = append(out, AWSLeastPrivilegeCoverageGap(gap))
	}
	for _, gap := range runtime.CoverageGaps {
		out = append(out, AWSLeastPrivilegeCoverageGap(gap))
	}
	return out
}

func awsLeastPrivilegeCaveats(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult, _ AWSRuntimeEventResult) []string {
	return dedupeStrings(append(append(append(secrets.Caveats, s3.Caveats...), agents.Caveats...), "Unknown or partial runtime evidence creates review recommendations; it never becomes an automatic remove decision."))
}

func awsLeastPrivilegeFailureReasons(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult, runtime AWSRuntimeEventResult) []string {
	return emptyStrings(dedupeStrings(append(append(append(secrets.FailureReasons, s3.FailureReasons...), agents.FailureReasons...), runtime.FailureReasons...)))
}

func awsLeastPrivilegeRemediationHints(secrets AWSSecretsKMSRuntimeAccessResult, s3 AWSS3RuntimeAccessResult, agents AWSAgentRuntimeAccessResult, runtime AWSRuntimeEventResult) []string {
	return emptyStrings(dedupeStrings(append(append(append(append(secrets.RemediationHints, s3.RemediationHints...), agents.RemediationHints...), runtime.RemediationHints...), "Use the least-privilege remediation preview as a read-only plan until owner approval and policy diff generation are available.")))
}

func firstLeastPrivilegeEvidenceRef(evidence []AWSLeastPrivilegeEvidence) string {
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			return item.EvidenceRef
		}
	}
	return ""
}

func subtractStringSet(all []string, used []string) []string {
	usedSet := map[string]struct{}{}
	for _, value := range used {
		token := normalizeAWSRuntimeEventFilterToken(value)
		if token != "" {
			usedSet[token] = struct{}{}
		}
	}
	out := []string{}
	for _, value := range all {
		token := normalizeAWSRuntimeEventFilterToken(value)
		if token == "" {
			continue
		}
		if _, ok := usedSet[token]; !ok {
			out = append(out, value)
		}
	}
	return dedupeStrings(out)
}
