package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsGovernanceAuditReportingCurrentIssue = 1548
	awsGovernanceAuditReportingVersion      = "aws-governance-audit-reporting-v1"
	awsGovernanceAuditReportingPolicyID     = "aws-governance-audit-reporting-policy-v1"

	awsGovernanceAuditCategoryDecision           = "decision"
	awsGovernanceAuditCategoryApproval           = "approval"
	awsGovernanceAuditCategoryRemediation        = "remediation"
	awsGovernanceAuditCategoryEnforcementOutcome = "enforcement_outcome"
	awsGovernanceAuditCategoryException          = "exception"
)

// AWSGovernanceAuditReportingRequest scopes the report to one AWS connector
// plus operator drill-down filters. Time filters are RFC3339 timestamps.
type AWSGovernanceAuditReportingRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	OU           string `json:"ou,omitempty"`
	IdentityID   string `json:"identity_id,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	DecisionType string `json:"decision_type,omitempty"`
	Approver     string `json:"approver,omitempty"`
	Category     string `json:"category,omitempty"`
	State        string `json:"state,omitempty"`
	SourceType   string `json:"source_type,omitempty"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSGovernanceAuditReportingAuditEntry = AWSRemediationApprovalAuditEntry
type AWSGovernanceAuditReportingCoverageGap = AWSRemediationApprovalCoverageGap
type AWSGovernanceAuditReportingDiagnostic = AWSRemediationApprovalDiagnostic

// AWSGovernanceAuditEvidenceSummary is an export-safe evidence pointer. It
// carries refs and labels only; sensitive payloads stay out of the report.
type AWSGovernanceAuditEvidenceSummary struct {
	Source      string `json:"source"`
	Label       string `json:"label"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	Exportable  bool   `json:"exportable"`
	Redacted    bool   `json:"redacted"`
}

// AWSGovernanceAuditReportRecord is one row in the exportable governance audit
// report. It normalizes decisions, approvals, remediations, enforcement
// outcomes, and exceptions without changing the source contracts.
type AWSGovernanceAuditReportRecord struct {
	ReportID           string                                  `json:"report_id"`
	CalculationVersion string                                  `json:"calculation_version"`
	PolicyVersion      string                                  `json:"policy_version"`
	Category           string                                  `json:"category"`
	SourceType         string                                  `json:"source_type"`
	SourceID           string                                  `json:"source_id"`
	DecisionType       string                                  `json:"decision_type"`
	Outcome            string                                  `json:"outcome,omitempty"`
	State              string                                  `json:"state"`
	Mode               string                                  `json:"mode,omitempty"`
	Actor              string                                  `json:"actor,omitempty"`
	Approver           string                                  `json:"approver,omitempty"`
	AccountID          string                                  `json:"account_id,omitempty"`
	TargetAccountIDs   []string                                `json:"target_account_ids,omitempty"`
	Region             string                                  `json:"region,omitempty"`
	OU                 string                                  `json:"ou,omitempty"`
	IdentityNodeID     string                                  `json:"identity_node_id,omitempty"`
	AgentID            string                                  `json:"agent_id,omitempty"`
	AgentNodeID        string                                  `json:"agent_node_id,omitempty"`
	Action             string                                  `json:"action,omitempty"`
	Confidence         float64                                 `json:"confidence"`
	Score              int                                     `json:"score"`
	Title              string                                  `json:"title"`
	Summary            string                                  `json:"summary"`
	Rationale          string                                  `json:"rationale,omitempty"`
	InputHash          string                                  `json:"input_hash,omitempty"`
	EvidenceSummary    []AWSGovernanceAuditEvidenceSummary     `json:"evidence_summary"`
	EvidenceLinks      []string                                `json:"evidence_links"`
	EvidenceBoundary   string                                  `json:"evidence_boundary"`
	AuditTrail         []AWSGovernanceAuditReportingAuditEntry `json:"audit_trail"`
	ReadOnlyProjection bool                                    `json:"read_only_projection"`
	Exception          bool                                    `json:"exception"`
	NextAction         string                                  `json:"next_action"`
	OccurredAt         time.Time                               `json:"occurred_at"`
	UpdatedAt          time.Time                               `json:"updated_at"`
}

// AWSGovernanceAuditReportingSummary aggregates the complete and filtered
// report set for operator review and export screens.
type AWSGovernanceAuditReportingSummary struct {
	TotalRecords            int            `json:"total_records"`
	FilteredRecords         int            `json:"filtered_records"`
	CategoryCounts          map[string]int `json:"category_counts"`
	DecisionTypeCounts      map[string]int `json:"decision_type_counts"`
	StateCounts             map[string]int `json:"state_counts"`
	SourceTypeCounts        map[string]int `json:"source_type_counts"`
	AccountCounts           map[string]int `json:"account_counts"`
	DecisionCount           int            `json:"decision_count"`
	ApprovalCount           int            `json:"approval_count"`
	RemediationCount        int            `json:"remediation_count"`
	EnforcementOutcomeCount int            `json:"enforcement_outcome_count"`
	ExceptionCount          int            `json:"exception_count"`
	ExportableEvidenceCount int            `json:"exportable_evidence_count"`
	AuditEntryCount         int            `json:"audit_entry_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
}

// AWSGovernanceAuditReportingResult is the deterministic endpoint envelope.
type AWSGovernanceAuditReportingResult struct {
	TenantID           string                                   `json:"tenant_id"`
	WorkspaceID        string                                   `json:"workspace_id"`
	ProjectID          string                                   `json:"project_id"`
	ConnectorID        string                                   `json:"connector_id,omitempty"`
	AccountID          string                                   `json:"account_id,omitempty"`
	Region             string                                   `json:"region,omitempty"`
	ParentIssueNumber  int                                      `json:"parent_issue_number"`
	ParentIssueRef     string                                   `json:"parent_issue_ref"`
	CurrentIssueNumber int                                      `json:"current_issue_number"`
	CurrentIssueRef    string                                   `json:"current_issue_ref"`
	Version            string                                   `json:"version"`
	Status             string                                   `json:"status"`
	FixtureState       string                                   `json:"fixture_state,omitempty"`
	Confidence         float64                                  `json:"confidence"`
	CalculationVersion string                                   `json:"calculation_version"`
	PolicyVersion      string                                   `json:"policy_version"`
	AppliedFilters     map[string]string                        `json:"applied_filters"`
	Summary            AWSGovernanceAuditReportingSummary       `json:"summary"`
	Records            []AWSGovernanceAuditReportRecord         `json:"records"`
	Caveats            []string                                 `json:"caveats"`
	FailureReasons     []string                                 `json:"failure_reasons"`
	RemediationHints   []string                                 `json:"remediation_hints"`
	EvidenceLinks      []string                                 `json:"evidence_links"`
	CoverageGaps       []AWSGovernanceAuditReportingCoverageGap `json:"coverage_gaps"`
	Diagnostics        []AWSGovernanceAuditReportingDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                                `json:"generated_at"`
	UpdatedAt          time.Time                                `json:"updated_at"`
}

// GetAWSGovernanceAuditReporting composes existing governance projections into
// exportable audit rows. It does not call AWS write APIs and does not inline
// rendered policy bodies, secret values, prompts, completions, database rows,
// object contents, or workload payloads.
func (s *Service) GetAWSGovernanceAuditReporting(ctx context.Context, workspaceID string, projectID string, request AWSGovernanceAuditReportingRequest) (AWSGovernanceAuditReportingResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSGovernanceAuditReportingFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSGovernanceAuditReportingResult{}, ErrInvalidAWSConnectionRequest
	}
	from, to, err := parseAWSGovernanceAuditReportingTimeRange(request.From, request.To)
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	advisory, err := s.GetAWSAdvisoryAuthorization(ctx, workspaceID, projectID, AWSAdvisoryAuthorizationRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, fmt.Errorf("governance audit advisory authorization: %w", err)
	}
	agentcore, err := s.GetAWSAgentCoreGatewayPolicyAdvisory(ctx, workspaceID, projectID, AWSAgentCoreGatewayPolicyAdvisoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, fmt.Errorf("governance audit agentcore advisory: %w", err)
	}
	approvals, err := s.GetAWSRemediationApprovalQueue(ctx, workspaceID, projectID, AWSRemediationApprovalRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, fmt.Errorf("governance audit approvals: %w", err)
	}
	verification, err := s.GetAWSPostRemediationVerification(ctx, workspaceID, projectID, AWSPostRemediationVerificationRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, fmt.Errorf("governance audit remediations: %w", err)
	}
	scpExecutor, err := s.GetAWSScpGuardrailExecutor(ctx, workspaceID, projectID, AWSScpGuardrailExecutorRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, fmt.Errorf("governance audit scp executor: %w", err)
	}
	pilot, err := s.GetAWSLimitedEnforcementPilot(ctx, workspaceID, projectID, AWSLimitedEnforcementPilotRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSGovernanceAuditReportingResult{}, fmt.Errorf("governance audit enforcement pilot: %w", err)
	}

	diagnostics := awsGovernanceAuditReportingDiagnostics(advisory.Diagnostics, agentcore.Diagnostics, approvals.Diagnostics, verification.Diagnostics, scpExecutor.Diagnostics, pilot.Diagnostics)
	records := []AWSGovernanceAuditReportRecord{}
	records = append(records, awsGovernanceAuditRecordsFromAdvisory(advisory.Decisions)...)
	records = append(records, awsGovernanceAuditRecordsFromAgentCore(agentcore.Advisories)...)
	records = append(records, awsGovernanceAuditRecordsFromApprovals(approvals.Entries)...)
	records = append(records, awsGovernanceAuditRecordsFromVerification(verification.Entries)...)
	records = append(records, awsGovernanceAuditRecordsFromScpExecutions(scpExecutor.Entries)...)
	records = append(records, awsGovernanceAuditRecordsFromPilot(pilot.Decisions)...)
	records = append(records, awsGovernanceAuditExceptionRecords(diagnostics, now)...)
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].OccurredAt.Equal(records[j].OccurredAt) {
			return records[i].ReportID < records[j].ReportID
		}
		return records[i].OccurredAt.After(records[j].OccurredAt)
	})

	filtered, applied := filterAWSGovernanceAuditReportRecords(records, request, from, to)
	status, confidence := summarizeAWSGovernanceAuditReportingStatus(filtered, advisory.Status, agentcore.Status, approvals.Status, verification.Status, scpExecutor.Status, pilot.Status)
	return AWSGovernanceAuditReportingResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsGovernanceAuditReportingCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsGovernanceAuditReportingCurrentIssue),
		Version:            awsGovernanceAuditReportingVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsGovernanceAuditReportingVersion,
		PolicyVersion:      awsGovernanceAuditReportingPolicyID,
		AppliedFilters:     applied,
		Summary:            summarizeAWSGovernanceAuditReportRecords(records, filtered),
		Records:            filtered,
		Caveats:            awsGovernanceAuditReportingCaveats(),
		FailureReasons:     dedupeStrings(append(append(append(append(append([]string{}, advisory.FailureReasons...), agentcore.FailureReasons...), approvals.FailureReasons...), verification.FailureReasons...), append(scpExecutor.FailureReasons, pilot.FailureReasons...)...)),
		RemediationHints:   awsGovernanceAuditReportingRemediationHints(),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsGovernanceAuditReportingCurrentIssue),
			awsIssueURL(awsAdvisoryAuthorizationCurrentIssue),
			awsIssueURL(awsAgentCoreGatewayPolicyAdvisoryCurrentIssue),
			awsIssueURL(awsLimitedEnforcementPilotCurrentIssue),
			"/docs/aws-governance-audit-reporting",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: awsGovernanceAuditReportingCoverageGaps(advisory.CoverageGaps, agentcore.CoverageGaps, approvals.CoverageGaps, verification.CoverageGaps, scpExecutor.CoverageGaps, pilot.CoverageGaps),
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSGovernanceAuditReportingFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func parseAWSGovernanceAuditReportingTimeRange(fromRaw, toRaw string) (time.Time, time.Time, error) {
	from, err := parseAWSGovernanceAuditReportingTime(fromRaw)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	to, err := parseAWSGovernanceAuditReportingTime(toRaw)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !from.IsZero() && !to.IsZero() && from.After(to) {
		return time.Time{}, time.Time{}, fmt.Errorf("from after to")
	}
	return from, to, nil
}

func parseAWSGovernanceAuditReportingTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func awsGovernanceAuditRecordsFromAdvisory(decisions []AWSAdvisoryAuthorizationDecision) []AWSGovernanceAuditReportRecord {
	records := make([]AWSGovernanceAuditReportRecord, 0, len(decisions))
	for _, decision := range decisions {
		occurred := firstAWSGovernanceAuditTime(decision.DecidedAt, firstAWSGovernanceAuditEntryTime(decision.AuditTrail), decision.UpdatedAt)
		records = append(records, AWSGovernanceAuditReportRecord{
			ReportID:           "aws-governance-audit:" + stableAWSBlastRadiusToken("audit-advisory", decision.DecisionID, decision.Outcome, decision.InputHash.Value),
			CalculationVersion: awsGovernanceAuditReportingVersion,
			PolicyVersion:      firstNonEmptyAWSValue(decision.Provenance.PolicyVersion, awsAdvisoryAuthorizationPolicyID),
			Category:           awsGovernanceAuditCategoryDecision,
			SourceType:         "advisory_authorization",
			SourceID:           decision.DecisionID,
			DecisionType:       "advisory_authorization",
			Outcome:            decision.Outcome,
			State:              decision.Outcome,
			Mode:               decision.Mode,
			Actor:              firstAWSGovernanceAuditActor(decision.AuditTrail, "identrail-advisory-authorization"),
			AccountID:          decision.AccountID,
			TargetAccountIDs:   decision.TargetAccountIDs,
			Region:             decision.Region,
			IdentityNodeID:     firstNonEmptyAWSValue(decision.PrincipalNodeID, decision.PrincipalARN),
			Action:             decision.Action,
			Confidence:         decision.Confidence,
			Score:              decision.Score,
			Title:              decision.Title,
			Summary:            decision.Summary,
			Rationale:          decision.Rationale,
			InputHash:          decision.InputHash.Value,
			EvidenceSummary:    awsGovernanceAuditEvidenceFromAdvisory(decision.Evidence),
			EvidenceLinks:      decision.EvidenceLinks,
			EvidenceBoundary:   awsGovernanceAuditReportingEvidenceBoundary(),
			AuditTrail:         decision.AuditTrail,
			ReadOnlyProjection: decision.ReadOnlyProjection,
			Exception:          decision.KillSwitchEngaged || decision.Outcome == awsAdvisoryAuthorizationOutcomeQuarantine,
			NextAction:         decision.NextAction,
			OccurredAt:         occurred,
			UpdatedAt:          firstAWSGovernanceAuditTime(decision.UpdatedAt, occurred),
		})
	}
	return records
}

func awsGovernanceAuditRecordsFromAgentCore(advisories []AWSAgentCoreGatewayPolicyAdvisoryEntry) []AWSGovernanceAuditReportRecord {
	records := make([]AWSGovernanceAuditReportRecord, 0, len(advisories))
	for _, advisory := range advisories {
		occurred := firstAWSGovernanceAuditTime(advisory.ProjectedAt, firstAWSGovernanceAuditEntryTime(advisory.AuditTrail), advisory.CreatedAt, advisory.UpdatedAt)
		records = append(records, AWSGovernanceAuditReportRecord{
			ReportID:           "aws-governance-audit:" + stableAWSBlastRadiusToken("audit-agentcore", advisory.AdvisoryID, advisory.Outcome, advisory.InputHash.Value),
			CalculationVersion: awsGovernanceAuditReportingVersion,
			PolicyVersion:      firstNonEmptyAWSValue(advisory.Provenance.PolicyVersion, awsAgentCoreGatewayPolicyAdvisoryPolicyID),
			Category:           awsGovernanceAuditCategoryDecision,
			SourceType:         "agentcore_gateway_policy_advisory",
			SourceID:           advisory.AdvisoryID,
			DecisionType:       "agentcore_gateway_policy_advisory",
			Outcome:            advisory.Outcome,
			State:              firstNonEmptyAWSValue(advisory.EnforcementState, advisory.PilotState, advisory.Outcome),
			Mode:               advisory.Mode,
			Actor:              firstAWSGovernanceAuditActor(advisory.AuditTrail, "identrail-agentcore-gateway-policy-advisory"),
			AccountID:          advisory.AccountID,
			Region:             advisory.Region,
			AgentID:            advisory.AgentID,
			AgentNodeID:        firstNonEmptyAWSValue(advisory.AgentNodeID, advisory.AgentID),
			IdentityNodeID:     advisory.RuntimeRoleNodeID,
			Confidence:         advisory.Confidence,
			Score:              advisory.Score,
			Title:              advisory.Title,
			Summary:            advisory.Summary,
			Rationale:          advisory.Rationale,
			InputHash:          advisory.InputHash.Value,
			EvidenceSummary:    awsGovernanceAuditEvidenceFromLeastPrivilege(advisory.Evidence),
			EvidenceLinks:      awsGovernanceAuditEvidenceRefsFromLeastPrivilege(advisory.Evidence),
			EvidenceBoundary:   awsGovernanceAuditReportingEvidenceBoundary(),
			AuditTrail:         advisory.AuditTrail,
			ReadOnlyProjection: advisory.ReadOnlyProjection,
			Exception:          advisory.Outcome == awsAgentCoreGatewayPolicyOutcomeBlockTools,
			NextAction:         advisory.NextAction,
			OccurredAt:         occurred,
			UpdatedAt:          firstAWSGovernanceAuditTime(advisory.UpdatedAt, occurred),
		})
	}
	return records
}

func awsGovernanceAuditRecordsFromApprovals(entries []AWSRemediationApprovalEntry) []AWSGovernanceAuditReportRecord {
	records := make([]AWSGovernanceAuditReportRecord, 0, len(entries))
	for _, entry := range entries {
		approverRoles := []string{}
		for _, approver := range entry.RequiredApprovers {
			approverRoles = append(approverRoles, approver.Role)
		}
		occurred := firstAWSGovernanceAuditTime(entry.RequestedAt, firstAWSGovernanceAuditEntryTime(entry.AuditTrail), entry.CreatedAt, entry.UpdatedAt)
		records = append(records, AWSGovernanceAuditReportRecord{
			ReportID:           "aws-governance-audit:" + stableAWSBlastRadiusToken("audit-approval", entry.ApprovalID, entry.State, entry.IdempotencyKey),
			CalculationVersion: awsGovernanceAuditReportingVersion,
			PolicyVersion:      awsRemediationApprovalVersion,
			Category:           awsGovernanceAuditCategoryApproval,
			SourceType:         entry.SourceType,
			SourceID:           entry.ApprovalID,
			DecisionType:       "remediation_approval",
			Outcome:            entry.State,
			State:              entry.State,
			Actor:              firstNonEmptyAWSValue(entry.Requestor.Label, firstAWSGovernanceAuditActor(entry.AuditTrail, "identrail-remediation-approval")),
			Approver:           strings.Join(dedupeStrings(approverRoles), ","),
			AccountID:          entry.AccountID,
			TargetAccountIDs:   entry.Scope.AccountIDs,
			Region:             entry.Region,
			IdentityNodeID:     firstString(entry.Scope.IdentityNodeIDs),
			Confidence:         entry.Confidence,
			Score:              entry.Score,
			Title:              entry.Title,
			Summary:            entry.Summary,
			InputHash:          entry.IdempotencyKey,
			EvidenceSummary:    awsGovernanceAuditEvidenceFromRemediation(entry.Evidence),
			EvidenceLinks:      awsGovernanceAuditEvidenceRefsFromRemediation(entry.Evidence),
			EvidenceBoundary:   awsGovernanceAuditReportingEvidenceBoundary(),
			AuditTrail:         entry.AuditTrail,
			ReadOnlyProjection: entry.ReadOnlyProjection,
			Exception:          entry.KillSwitchEngaged || entry.State == awsRemediationApprovalStateBlocked || entry.State == awsRemediationApprovalStateDenied || entry.State == awsRemediationApprovalStateExpired,
			NextAction:         entry.NextAction,
			OccurredAt:         occurred,
			UpdatedAt:          firstAWSGovernanceAuditTime(entry.UpdatedAt, occurred),
		})
	}
	return records
}

func awsGovernanceAuditRecordsFromVerification(entries []AWSPostRemediationVerificationEntry) []AWSGovernanceAuditReportRecord {
	records := make([]AWSGovernanceAuditReportRecord, 0, len(entries))
	for _, entry := range entries {
		occurred := firstAWSGovernanceAuditTime(entry.ProjectedAt, firstAWSGovernanceAuditEntryTime(entry.AuditTrail), entry.CreatedAt, entry.UpdatedAt)
		records = append(records, AWSGovernanceAuditReportRecord{
			ReportID:           "aws-governance-audit:" + stableAWSBlastRadiusToken("audit-remediation", entry.VerificationID, entry.State, entry.IdempotencyKey),
			CalculationVersion: awsGovernanceAuditReportingVersion,
			PolicyVersion:      awsPostRemediationVerificationVersion,
			Category:           awsGovernanceAuditCategoryRemediation,
			SourceType:         entry.SourceType,
			SourceID:           entry.VerificationID,
			DecisionType:       "post_remediation_verification",
			Outcome:            entry.State,
			State:              entry.State,
			Actor:              firstAWSGovernanceAuditActor(entry.AuditTrail, "identrail-post-remediation-verification"),
			AccountID:          entry.AccountID,
			TargetAccountIDs:   entry.TargetAccountIDs,
			Region:             entry.Region,
			IdentityNodeID:     entry.TargetResource,
			Action:             entry.Operation,
			Confidence:         entry.Confidence,
			Score:              entry.Score,
			Title:              entry.Title,
			Summary:            entry.Summary,
			InputHash:          entry.IdempotencyKey,
			EvidenceSummary:    awsGovernanceAuditEvidenceFromLinks(entry.SourceSignals, entry.EvidenceLinks),
			EvidenceLinks:      entry.EvidenceLinks,
			EvidenceBoundary:   awsGovernanceAuditReportingEvidenceBoundary(),
			AuditTrail:         entry.AuditTrail,
			ReadOnlyProjection: entry.ReadOnlyProjection,
			Exception:          entry.KillSwitchEngaged || entry.State == awsPostRemediationVerificationStateFailed || entry.State == awsPostRemediationVerificationStateRollback || entry.State == awsPostRemediationVerificationStateBlocked,
			NextAction:         entry.NextAction,
			OccurredAt:         occurred,
			UpdatedAt:          firstAWSGovernanceAuditTime(entry.UpdatedAt, occurred),
		})
	}
	return records
}

func awsGovernanceAuditRecordsFromScpExecutions(entries []AWSScpGuardrailExecutorEntry) []AWSGovernanceAuditReportRecord {
	records := make([]AWSGovernanceAuditReportRecord, 0, len(entries))
	for _, entry := range entries {
		occurred := firstAWSGovernanceAuditTime(entry.ProjectedAt, firstAWSGovernanceAuditEntryTime(entry.AuditTrail), entry.CreatedAt, entry.UpdatedAt)
		records = append(records, AWSGovernanceAuditReportRecord{
			ReportID:           "aws-governance-audit:" + stableAWSBlastRadiusToken("audit-scp-executor", entry.ExecutionID, entry.State, entry.IdempotencyKey),
			CalculationVersion: awsGovernanceAuditReportingVersion,
			PolicyVersion:      awsScpGuardrailExecutorVersion,
			Category:           awsGovernanceAuditCategoryRemediation,
			SourceType:         "scp_guardrail_executor",
			SourceID:           entry.ExecutionID,
			DecisionType:       "scp_guardrail_executor",
			Outcome:            entry.State,
			State:              entry.State,
			Actor:              firstAWSGovernanceAuditActor(entry.AuditTrail, "identrail-scp-guardrail-executor"),
			AccountID:          entry.AccountID,
			TargetAccountIDs:   entry.TargetAccountIDs,
			Region:             entry.Region,
			OU:                 strings.Join(entry.TargetOUPaths, ","),
			Action:             entry.Operation,
			Confidence:         entry.Confidence,
			Score:              entry.Score,
			Title:              entry.Title,
			Summary:            entry.Summary,
			InputHash:          entry.IdempotencyKey,
			EvidenceSummary:    awsGovernanceAuditEvidenceFromLeastPrivilege(entry.Evidence),
			EvidenceLinks:      awsGovernanceAuditEvidenceRefsFromLeastPrivilege(entry.Evidence),
			EvidenceBoundary:   awsGovernanceAuditReportingEvidenceBoundary(),
			AuditTrail:         entry.AuditTrail,
			ReadOnlyProjection: entry.ReadOnlyProjection,
			Exception:          entry.KillSwitchEngaged || !entry.ReadyForLiveApply || entry.State == awsScpGuardrailExecutorStateBlocked,
			NextAction:         entry.NextAction,
			OccurredAt:         occurred,
			UpdatedAt:          firstAWSGovernanceAuditTime(entry.UpdatedAt, occurred),
		})
	}
	return records
}

func awsGovernanceAuditRecordsFromPilot(decisions []AWSLimitedEnforcementPilotDecision) []AWSGovernanceAuditReportRecord {
	records := make([]AWSGovernanceAuditReportRecord, 0, len(decisions))
	for _, decision := range decisions {
		occurred := firstAWSGovernanceAuditTime(decision.ProjectedAt, firstAWSGovernanceAuditEntryTime(decision.AuditTrail), decision.UpdatedAt)
		records = append(records, AWSGovernanceAuditReportRecord{
			ReportID:           "aws-governance-audit:" + stableAWSBlastRadiusToken("audit-enforcement", decision.PilotID, decision.PilotState, decision.InputHash),
			CalculationVersion: awsGovernanceAuditReportingVersion,
			PolicyVersion:      decision.PolicyVersion,
			Category:           awsGovernanceAuditCategoryEnforcementOutcome,
			SourceType:         decision.SourceType,
			SourceID:           decision.PilotID,
			DecisionType:       "limited_enforcement_pilot",
			Outcome:            decision.Outcome,
			State:              decision.PilotState,
			Mode:               decision.Mode,
			Actor:              firstAWSGovernanceAuditActor(decision.AuditTrail, "identrail-limited-enforcement-pilot"),
			AccountID:          decision.AccountID,
			TargetAccountIDs:   decision.TargetAccountIDs,
			Region:             decision.Region,
			IdentityNodeID:     decision.PrincipalNodeID,
			Action:             decision.Action,
			Confidence:         decision.Confidence,
			Score:              decision.Score,
			Title:              decision.Title,
			Summary:            decision.Summary,
			Rationale:          decision.Rationale,
			InputHash:          decision.InputHash,
			EvidenceSummary:    awsGovernanceAuditEvidenceFromLinks(nil, decision.EvidenceLinks),
			EvidenceLinks:      decision.EvidenceLinks,
			EvidenceBoundary:   awsGovernanceAuditReportingEvidenceBoundary(),
			AuditTrail:         decision.AuditTrail,
			ReadOnlyProjection: decision.ReadOnlyProjection,
			Exception:          !decision.Eligible || decision.PilotState == awsLimitedEnforcementPilotStateOverrideHold || decision.PilotState == awsLimitedEnforcementPilotStateKillSwitched,
			NextAction:         decision.NextAction,
			OccurredAt:         occurred,
			UpdatedAt:          firstAWSGovernanceAuditTime(decision.UpdatedAt, occurred),
		})
	}
	return records
}

func awsGovernanceAuditExceptionRecords(diagnostics []AWSGovernanceAuditReportingDiagnostic, now time.Time) []AWSGovernanceAuditReportRecord {
	records := []AWSGovernanceAuditReportRecord{}
	for _, diagnostic := range diagnostics {
		if strings.TrimSpace(diagnostic.Code) == "" && strings.TrimSpace(diagnostic.Message) == "" {
			continue
		}
		reportID := "aws-governance-audit:" + stableAWSBlastRadiusToken("audit-exception", diagnostic.Collector, diagnostic.SourceID, diagnostic.Code, diagnostic.Message)
		records = append(records, AWSGovernanceAuditReportRecord{
			ReportID:           reportID,
			CalculationVersion: awsGovernanceAuditReportingVersion,
			PolicyVersion:      awsGovernanceAuditReportingPolicyID,
			Category:           awsGovernanceAuditCategoryException,
			SourceType:         firstNonEmptyAWSValue(diagnostic.Collector, "diagnostic"),
			SourceID:           firstNonEmptyAWSValue(diagnostic.SourceID, reportID),
			DecisionType:       "diagnostic_exception",
			State:              firstNonEmptyAWSValue(diagnostic.Code, "diagnostic"),
			Actor:              "identrail-governance-audit-reporting",
			Title:              fmt.Sprintf("Governance audit exception: %s", firstNonEmptyAWSValue(diagnostic.Code, "diagnostic")),
			Summary:            diagnostic.Message,
			EvidenceSummary:    []AWSGovernanceAuditEvidenceSummary{},
			EvidenceLinks:      []string{},
			EvidenceBoundary:   awsGovernanceAuditReportingEvidenceBoundary(),
			ReadOnlyProjection: true,
			Exception:          true,
			NextAction:         "Review the diagnostic and refresh upstream evidence before relying on the affected report row.",
			OccurredAt:         now,
			UpdatedAt:          now,
		})
	}
	return records
}

func filterAWSGovernanceAuditReportRecords(records []AWSGovernanceAuditReportRecord, request AWSGovernanceAuditReportingRequest, from, to time.Time) ([]AWSGovernanceAuditReportRecord, map[string]string) {
	filters := map[string]string{
		"account_id":    strings.TrimSpace(request.AccountID),
		"region":        strings.TrimSpace(request.Region),
		"ou":            normalizeAWSRuntimeEventFilterToken(request.OU),
		"identity_id":   strings.TrimSpace(request.IdentityID),
		"agent_id":      strings.TrimSpace(request.AgentID),
		"decision_type": normalizeAWSRuntimeEventFilterToken(request.DecisionType),
		"approver":      normalizeAWSRuntimeEventFilterToken(request.Approver),
		"category":      normalizeAWSRuntimeEventFilterToken(request.Category),
		"state":         normalizeAWSRuntimeEventFilterToken(request.State),
		"source_type":   normalizeAWSRuntimeEventFilterToken(request.SourceType),
		"from":          strings.TrimSpace(request.From),
		"to":            strings.TrimSpace(request.To),
		"search":        strings.TrimSpace(request.Search),
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
	filtered := make([]AWSGovernanceAuditReportRecord, 0, len(records))
	for _, record := range records {
		if filters["account_id"] != "" && !awsGovernanceAuditAccountMatch(record, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], strings.TrimSpace(record.Region)) {
			continue
		}
		if filters["ou"] != "" && !strings.Contains(normalizeAWSRuntimeEventFilterToken(record.OU), filters["ou"]) {
			continue
		}
		if filters["identity_id"] != "" && !strings.EqualFold(filters["identity_id"], record.IdentityNodeID) {
			continue
		}
		if filters["agent_id"] != "" && !strings.EqualFold(filters["agent_id"], record.AgentNodeID) && !strings.EqualFold(filters["agent_id"], record.AgentID) {
			continue
		}
		if filters["decision_type"] != "" && filters["decision_type"] != normalizeAWSRuntimeEventFilterToken(record.DecisionType) {
			continue
		}
		if filters["approver"] != "" && !strings.Contains(normalizeAWSRuntimeEventFilterToken(record.Approver), filters["approver"]) {
			continue
		}
		if filters["category"] != "" {
			category := normalizeAWSRuntimeEventFilterToken(record.Category)
			if filters["category"] == awsGovernanceAuditCategoryException {
				if category != awsGovernanceAuditCategoryException && !record.Exception {
					continue
				}
			} else if filters["category"] != category {
				continue
			}
		}
		if filters["state"] != "" && filters["state"] != normalizeAWSRuntimeEventFilterToken(record.State) {
			continue
		}
		if filters["source_type"] != "" && filters["source_type"] != normalizeAWSRuntimeEventFilterToken(record.SourceType) {
			continue
		}
		if !from.IsZero() && record.OccurredAt.Before(from) {
			continue
		}
		if !to.IsZero() && record.OccurredAt.After(to) {
			continue
		}
		if filters["search"] != "" && !awsGovernanceAuditSearchMatch(record, filters["search"]) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered, applied
}

func awsGovernanceAuditAccountMatch(record AWSGovernanceAuditReportRecord, accountID string) bool {
	if strings.EqualFold(strings.TrimSpace(record.AccountID), strings.TrimSpace(accountID)) {
		return true
	}
	for _, target := range record.TargetAccountIDs {
		if strings.EqualFold(strings.TrimSpace(target), strings.TrimSpace(accountID)) {
			return true
		}
	}
	return false
}

func awsGovernanceAuditSearchMatch(record AWSGovernanceAuditReportRecord, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		record.ReportID, record.Category, record.SourceType, record.SourceID, record.DecisionType,
		record.Outcome, record.State, record.Mode, record.Actor, record.Approver, record.AccountID,
		record.Region, record.OU, record.IdentityNodeID, record.AgentID, record.AgentNodeID, record.Action,
		record.Title, record.Summary, record.Rationale, record.InputHash, record.NextAction,
	}
	values = append(values, record.TargetAccountIDs...)
	values = append(values, record.EvidenceLinks...)
	for _, evidence := range record.EvidenceSummary {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef)
	}
	for _, audit := range record.AuditTrail {
		values = append(values, audit.EventType, audit.Actor, audit.Notes, audit.EvidenceRef)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSGovernanceAuditReportRecords(all, filtered []AWSGovernanceAuditReportRecord) AWSGovernanceAuditReportingSummary {
	summary := AWSGovernanceAuditReportingSummary{
		TotalRecords:       len(all),
		FilteredRecords:    len(filtered),
		CategoryCounts:     map[string]int{},
		DecisionTypeCounts: map[string]int{},
		StateCounts:        map[string]int{},
		SourceTypeCounts:   map[string]int{},
		AccountCounts:      map[string]int{},
	}
	confidenceTotal := 0.0
	for _, record := range filtered {
		summary.CategoryCounts[record.Category]++
		summary.DecisionTypeCounts[record.DecisionType]++
		summary.StateCounts[record.State]++
		summary.SourceTypeCounts[record.SourceType]++
		if strings.TrimSpace(record.AccountID) != "" {
			summary.AccountCounts[record.AccountID]++
		}
		switch record.Category {
		case awsGovernanceAuditCategoryDecision:
			summary.DecisionCount++
		case awsGovernanceAuditCategoryApproval:
			summary.ApprovalCount++
		case awsGovernanceAuditCategoryRemediation:
			summary.RemediationCount++
		case awsGovernanceAuditCategoryEnforcementOutcome:
			summary.EnforcementOutcomeCount++
		case awsGovernanceAuditCategoryException:
			summary.ExceptionCount++
		}
		if record.Exception && record.Category != awsGovernanceAuditCategoryException {
			summary.ExceptionCount++
		}
		for _, evidence := range record.EvidenceSummary {
			if evidence.Exportable {
				summary.ExportableEvidenceCount++
			}
		}
		summary.AuditEntryCount += len(record.AuditTrail)
		if record.Score > summary.HighestScore {
			summary.HighestScore = record.Score
		}
		confidenceTotal += record.Confidence
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func summarizeAWSGovernanceAuditReportingStatus(filtered []AWSGovernanceAuditReportRecord, statuses ...string) (string, float64) {
	for _, status := range statuses {
		if status == awsPlatformDependencyStatusBlocked {
			return awsPlatformDependencyStatusBlocked, 0.35
		}
	}
	for _, status := range statuses {
		if status == awsPlatformDependencyStatusDegraded {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsGovernanceAuditEvidenceFromAdvisory(items []AWSAdvisoryAuthorizationEvidence) []AWSGovernanceAuditEvidenceSummary {
	out := make([]AWSGovernanceAuditEvidenceSummary, 0, len(items))
	for _, item := range items {
		out = append(out, AWSGovernanceAuditEvidenceSummary{Source: item.Source, Label: item.Label, EvidenceRef: item.EvidenceRef, Exportable: true, Redacted: true})
	}
	return out
}

func awsGovernanceAuditEvidenceFromLeastPrivilege(items []AWSLeastPrivilegeEvidence) []AWSGovernanceAuditEvidenceSummary {
	out := make([]AWSGovernanceAuditEvidenceSummary, 0, len(items))
	for _, item := range items {
		out = append(out, AWSGovernanceAuditEvidenceSummary{Source: item.Source, Label: item.Label, EvidenceRef: item.EvidenceRef, Exportable: true, Redacted: true})
	}
	return out
}

func awsGovernanceAuditEvidenceFromRemediation(items []AWSRemediationApprovalEvidence) []AWSGovernanceAuditEvidenceSummary {
	out := make([]AWSGovernanceAuditEvidenceSummary, 0, len(items))
	for _, item := range items {
		out = append(out, AWSGovernanceAuditEvidenceSummary{Source: item.Source, Label: item.Label, EvidenceRef: item.EvidenceRef, Exportable: true, Redacted: true})
	}
	return out
}

func awsGovernanceAuditEvidenceFromLinks(labels []string, links []string) []AWSGovernanceAuditEvidenceSummary {
	out := make([]AWSGovernanceAuditEvidenceSummary, 0, len(links))
	for idx, link := range links {
		if strings.TrimSpace(link) == "" {
			continue
		}
		label := "evidence_ref"
		if idx < len(labels) && strings.TrimSpace(labels[idx]) != "" {
			label = labels[idx]
		}
		out = append(out, AWSGovernanceAuditEvidenceSummary{Source: "source_link", Label: label, EvidenceRef: link, Exportable: true, Redacted: true})
	}
	return out
}

func awsGovernanceAuditEvidenceRefsFromLeastPrivilege(items []AWSLeastPrivilegeEvidence) []string {
	refs := []string{}
	for _, item := range items {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			refs = append(refs, item.EvidenceRef)
		}
	}
	return dedupeStrings(refs)
}

func awsGovernanceAuditEvidenceRefsFromRemediation(items []AWSRemediationApprovalEvidence) []string {
	refs := []string{}
	for _, item := range items {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			refs = append(refs, item.EvidenceRef)
		}
	}
	return dedupeStrings(refs)
}

func firstAWSGovernanceAuditActor(entries []AWSGovernanceAuditReportingAuditEntry, fallback string) string {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Actor) != "" {
			return entry.Actor
		}
	}
	return fallback
}

func firstAWSGovernanceAuditEntryTime(entries []AWSGovernanceAuditReportingAuditEntry) time.Time {
	for _, entry := range entries {
		if !entry.OccurredAt.IsZero() {
			return entry.OccurredAt
		}
	}
	return time.Time{}
}

func firstAWSGovernanceAuditTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Time{}
}

func awsGovernanceAuditReportingCoverageGaps(groups ...[]AWSGovernanceAuditReportingCoverageGap) []AWSGovernanceAuditReportingCoverageGap {
	out := []AWSGovernanceAuditReportingCoverageGap{}
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

func awsGovernanceAuditReportingDiagnostics(groups ...[]AWSGovernanceAuditReportingDiagnostic) []AWSGovernanceAuditReportingDiagnostic {
	out := []AWSGovernanceAuditReportingDiagnostic{}
	seen := map[string]bool{}
	for _, group := range groups {
		for _, diagnostic := range group {
			key := strings.Join([]string{
				strings.ToLower(strings.TrimSpace(diagnostic.Collector)),
				strings.ToLower(strings.TrimSpace(diagnostic.SourceID)),
				strings.ToLower(strings.TrimSpace(diagnostic.Code)),
				strings.ToLower(strings.TrimSpace(diagnostic.Message)),
			}, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, diagnostic)
		}
	}
	return out
}

func awsGovernanceAuditReportingCaveats() []string {
	return []string{
		"Governance audit reporting is a metadata-only composition over existing Identrail AWS governance projections; it does not execute or mutate AWS controls.",
		"Evidence summaries are export-safe refs and labels only; Identrail does not include secret values, rendered policy bodies, prompts, completions, database rows, object contents, or workload payloads.",
		"Unknown, permission-denied, degraded, partially failed, kill-switch, rollback, and hold states remain explicit report states and are counted as exceptions where applicable.",
	}
}

func awsGovernanceAuditReportingRemediationHints() []string {
	return []string{
		"Filter by category, decision_type, state, account, identity, agent, approver, and time before exporting evidence summaries for an audit package.",
		"Use the input hash, policy version, source ID, evidence refs, and audit trail on each row to prove which inputs produced the reported decision.",
		"Review exception rows before using the report for enforcement planning; exceptions mean the upstream evidence or safety state needs operator attention.",
	}
}

func awsGovernanceAuditReportingEvidenceBoundary() string {
	return "metadata_only_exportable_refs_no_secret_values_no_rendered_policy_bodies_no_customer_payloads_tenant_workspace_project_connector_account_region_scoped"
}
