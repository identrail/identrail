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
	awsIAMPassRoleRelationshipCurrentIssue = 1487
	awsIAMPassRoleRelationshipVersion      = "aws-iam-passrole-relationship-inventory-v1"
)

// AWSIAMPassRoleRelationshipInventoryRequest is the operator-facing request.
type AWSIAMPassRoleRelationshipInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSIAMPassRoleCoverageGap names a PassRole shape Identrail intentionally
// does not collect this wave, with the reason and remediation the operator
// should rely on.
type AWSIAMPassRoleCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSIAMPassRoleRelationshipInventoryResult is the deterministic envelope this
// endpoint returns.
type AWSIAMPassRoleRelationshipInventoryResult struct {
	TenantID            string                                 `json:"tenant_id"`
	WorkspaceID         string                                 `json:"workspace_id"`
	ProjectID           string                                 `json:"project_id"`
	ConnectorID         string                                 `json:"connector_id,omitempty"`
	AccountID           string                                 `json:"account_id,omitempty"`
	Region              string                                 `json:"region,omitempty"`
	ParentIssueNumber   int                                    `json:"parent_issue_number"`
	ParentIssueRef      string                                 `json:"parent_issue_ref"`
	CurrentIssueNumber  int                                    `json:"current_issue_number"`
	CurrentIssueRef     string                                 `json:"current_issue_ref"`
	Version             string                                 `json:"version"`
	Status              string                                 `json:"status"`
	FixtureState        string                                 `json:"fixture_state"`
	Confidence          float64                                `json:"confidence"`
	RecordCount         int                                    `json:"record_count"`
	SourceRoleCount     int                                    `json:"source_role_count"`
	TargetRoleCount     int                                    `json:"target_role_count"`
	WildcardTargetCount int                                    `json:"wildcard_target_count"`
	DenyStatementCount  int                                    `json:"deny_statement_count"`
	ServiceScopedCount  int                                    `json:"service_scoped_count"`
	UnscopedCount       int                                    `json:"unscoped_count"`
	RelationshipCount   int                                    `json:"relationship_count"`
	FailureReasons      []string                               `json:"failure_reasons"`
	RemediationHints    []string                               `json:"remediation_hints"`
	EvidenceLinks       []string                               `json:"evidence_links"`
	CoverageGaps        []AWSIAMPassRoleCoverageGap            `json:"coverage_gaps"`
	Records             []AWSIAMPassRoleRelationshipRecord     `json:"records"`
	Relationships       []AWSIAMPassRoleRelationshipEdge       `json:"relationships"`
	Diagnostics         []AWSIAMPassRoleRelationshipDiagnostic `json:"diagnostics"`
	GeneratedAt         time.Time                              `json:"generated_at"`
	UpdatedAt           time.Time                              `json:"updated_at"`
}

// AWSIAMPassRoleRelationshipRecord is one extracted PassRole grant exposed by
// the API.
type AWSIAMPassRoleRelationshipRecord struct {
	AccountID          string            `json:"account_id"`
	Region             string            `json:"region,omitempty"`
	Service            string            `json:"service"`
	WorkloadID         string            `json:"workload_id"`
	WorkloadType       string            `json:"workload_type"`
	WorkloadName       string            `json:"workload_name"`
	SourceRoleARN      string            `json:"source_role_arn"`
	SourceRoleName     string            `json:"source_role_name,omitempty"`
	SourceRolePath     string            `json:"source_role_path,omitempty"`
	TargetResource     string            `json:"target_resource"`
	TargetWildcardKind string            `json:"target_wildcard_kind"`
	PolicyName         string            `json:"policy_name,omitempty"`
	StatementSid       string            `json:"statement_sid,omitempty"`
	ActionExpression   string            `json:"action_expression"`
	Effect             string            `json:"effect"`
	PassedToService    string            `json:"passed_to_service,omitempty"`
	ConditionOperator  string            `json:"condition_operator,omitempty"`
	NotAction          bool              `json:"not_action,omitempty"`
	NotResource        bool              `json:"not_resource,omitempty"`
	OtherConditionKeys []string          `json:"other_condition_keys,omitempty"`
	UnresolvedTarget   bool              `json:"unresolved_target"`
	Tags               map[string]string `json:"tags,omitempty"`
	Source             string            `json:"source"`
	EvidenceRef        string            `json:"evidence_ref"`
	FromNodeID         string            `json:"from_node_id"`
	ToNodeID           string            `json:"to_node_id,omitempty"`
	RelationshipType   string            `json:"relationship_type"`
	Confidence         float64           `json:"confidence"`
	CollectedAt        time.Time         `json:"collected_at"`
	Status             string            `json:"status"`
}

// AWSIAMPassRoleRelationshipEdge is a single graph edge produced by the
// PassRole collector.
type AWSIAMPassRoleRelationshipEdge struct {
	Type            string `json:"type"`
	FromNodeID      string `json:"from_node_id"`
	ToNodeID        string `json:"to_node_id,omitempty"`
	EvidenceRef     string `json:"evidence_ref"`
	Effect          string `json:"effect"`
	PassedToService string `json:"passed_to_service,omitempty"`
}

// AWSIAMPassRoleRelationshipDiagnostic is a structured collector diagnostic
// with an operator-facing remediation hint.
type AWSIAMPassRoleRelationshipDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSIAMPassRoleRelationshipInventory returns the PassRole relationship
// inventory for the supplied scope, honoring connector status and the
// optional fixture_state override.
func (s *Service) GetAWSIAMPassRoleRelationshipInventory(ctx context.Context, workspaceID string, projectID string, request AWSIAMPassRoleRelationshipInventoryRequest) (AWSIAMPassRoleRelationshipInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSIAMPassRoleRelationshipInventoryResult{}, err
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
		return AWSIAMPassRoleRelationshipInventoryResult{}, err
	}
	return buildAWSIAMPassRoleRelationshipInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSIAMPassRoleRelationshipInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSIAMPassRoleRelationshipInventoryRequest, checkedAt time.Time) (AWSIAMPassRoleRelationshipInventoryResult, error) {
	fixtureState := normalizeAWSIAMPassRoleRelationshipFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSIAMPassRoleRelationshipInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsIAMPassRoleRelationshipFixtureRecords(accountID, region, fixtureState, checkedAt)
	for _, record := range records {
		if strings.TrimSpace(record.SourceRoleARN) == "" {
			continue
		}
		if _, err := awscontract.NormalizeServiceCollectorRecord(awscontract.ServiceCollectorRecord{
			TenantID:      scope.TenantID,
			WorkspaceID:   project.WorkspaceID,
			ProjectID:     project.ProjectID,
			ConnectorID:   connectorID,
			AccountID:     record.AccountID,
			Region:        record.Region,
			Service:       record.Service,
			WorkloadID:    record.WorkloadID,
			WorkloadType:  record.WorkloadType,
			WorkloadName:  record.WorkloadName,
			RoleARN:       record.SourceRoleARN,
			Source:        record.Source,
			EvidenceRef:   record.EvidenceRef,
			Confidence:    record.Confidence,
			ScanID:        "aws-iam-passrole-relationship-fixture",
			CollectorName: "iam_passrole_relationship",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSIAMPassRoleRelationshipInventoryResult{}, fmt.Errorf("validate iam passrole relationship contract record: %w", err)
		}
	}
	status, confidence, failures, remediations := summarizeAWSIAMPassRoleRelationshipInventory(fixtureState, diagnostics, records)
	relationships := awsIAMPassRoleRelationshipEdges(records)
	return AWSIAMPassRoleRelationshipInventoryResult{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		AccountID:           accountID,
		Region:              region,
		ParentIssueNumber:   awsPlatformDependencyParentIssue,
		ParentIssueRef:      awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:  awsIAMPassRoleRelationshipCurrentIssue,
		CurrentIssueRef:     awsIssueRef(awsIAMPassRoleRelationshipCurrentIssue),
		Version:             awsIAMPassRoleRelationshipVersion,
		Status:              status,
		FixtureState:        fixtureState,
		Confidence:          confidence,
		RecordCount:         len(records),
		SourceRoleCount:     awsIAMPassRoleSourceRoleCount(records),
		TargetRoleCount:     awsIAMPassRoleTargetRoleCount(records),
		WildcardTargetCount: awsIAMPassRoleWildcardTargetCount(records),
		DenyStatementCount:  awsIAMPassRoleDenyCount(records),
		ServiceScopedCount:  awsIAMPassRoleServiceScopedCount(records),
		UnscopedCount:       awsIAMPassRoleUnscopedCount(records),
		RelationshipCount:   len(relationships),
		FailureReasons:      failures,
		RemediationHints:    remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsIAMPassRoleRelationshipCurrentIssue),
			"/docs/aws-iam-passrole-relationships",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsIAMPassRoleRelationshipDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSIAMPassRoleRelationshipFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsIAMPassRoleRelationshipFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSIAMPassRoleRelationshipRecord, []providers.SourceError, []AWSIAMPassRoleCoverageGap) {
	gaps := []AWSIAMPassRoleCoverageGap{{
		Capability:  "passrole_session_tagging",
		Status:      "unsupported",
		Reason:      "Session tagging on iam:PassRole grants (aws:RequestTag, iam:TagSession) is not modelled in this wave; only iam:PassedToService conditions are surfaced.",
		Remediation: "Treat session-tag-bound PassRole grants as unscoped for blast-radius reasoning until the condition mapper ships.",
	}, {
		Capability:  "service_linked_roles",
		Status:      "unsupported",
		Reason:      "Service-linked roles (path /aws-service-role/) are excluded because AWS provisions them implicitly and they are not pass-able through customer policies.",
		Remediation: "Filter service-linked roles from PassRole follow-ups; coverage gap is documented and not a collector failure.",
	}}
	partition := awsIAMPassRolePartitionForRegion(region)
	deployRoleARN := fmt.Sprintf("arn:%s:iam::%s:role/platform-deploy", partition, accountID)
	pipelineRoleARN := fmt.Sprintf("arn:%s:iam::%s:role/codepipeline-deploy", partition, accountID)
	wildcardRoleARN := fmt.Sprintf("arn:%s:iam::%s:role/data-ops", partition, accountID)
	starRoleARN := fmt.Sprintf("arn:%s:iam::%s:role/security-admin", partition, accountID)
	denyRoleARN := fmt.Sprintf("arn:%s:iam::%s:role/audit-readonly", partition, accountID)
	lambdaTargetARN := fmt.Sprintf("arn:%s:iam::%s:role/payments-lambda", partition, accountID)
	ecsTargetARN := fmt.Sprintf("arn:%s:iam::%s:role/payments-ecs-task", partition, accountID)
	wildcardTargetARN := fmt.Sprintf("arn:%s:iam::%s:role/data-ops-*", partition, accountID)
	starTarget := "*"
	denyTargetARN := fmt.Sprintf("arn:%s:iam::%s:role/break-glass", partition, accountID)

	records := []AWSIAMPassRoleRelationshipRecord{
		awsIAMPassRoleFixtureRecord(accountID, region, deployRoleARN, "platform-deploy", lambdaTargetARN, "PassPaymentsLambda", "iam:PassRole", "Allow", "lambda.amazonaws.com", "StringEquals", checkedAt, partition),
		awsIAMPassRoleFixtureRecord(accountID, region, pipelineRoleARN, "codepipeline-deploy", ecsTargetARN, "PassPaymentsEcs", "iam:PassRole", "Allow", "ecs-tasks.amazonaws.com", "StringEquals", checkedAt, partition),
		awsIAMPassRoleFixtureRecord(accountID, region, wildcardRoleARN, "data-ops", wildcardTargetARN, "PassDataOpsRoles", "iam:PassRole", "Allow", "", "", checkedAt, partition),
		awsIAMPassRoleFixtureRecord(accountID, region, starRoleARN, "security-admin", starTarget, "PassAny", "iam:PassRole", "Allow", "", "", checkedAt, partition),
		awsIAMPassRoleFixtureRecord(accountID, region, denyRoleARN, "audit-readonly", denyTargetARN, "DenyBreakGlassPass", "iam:PassRole", "Deny", "", "", checkedAt, partition),
	}
	switch fixtureState {
	case "empty":
		return nil, nil, gaps
	case "degraded":
		// Mark the wildcard grant as unresolved with low confidence to
		// illustrate the degraded preview state. Match by source role name
		// (not index) so future record reorders cannot silently flip the
		// wrong record.
		for i := range records {
			if records[i].SourceRoleName != "data-ops" {
				continue
			}
			records[i].Confidence = 0.6
			records[i].Status = "degraded"
			break
		}
		return records, []providers.SourceError{{
			Collector: "aws_iam_passrole/iam_passrole_relationship",
			SourceID:  wildcardRoleARN,
			Code:      "iam_passrole_wildcard_target",
			Message:   "One PassRole grant targets a path-scoped wildcard; downstream consumers should treat it as unresolved",
			Retryable: false,
		}}, gaps
	case "partial_failure":
		return records[:3], []providers.SourceError{{
			Collector: "aws_iam_passrole/iam_passrole_relationship",
			SourceID:  fmt.Sprintf("service=iam-passrole|account=%s|region=%s|source=listroles", accountID, region),
			Code:      "iam_passrole_page_failed",
			Message:   "One IAM ListRoles page failed; partial PassRole evidence remains visible",
			Retryable: true,
		}}, gaps
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_iam_passrole/iam_passrole_relationship",
			SourceID:  fmt.Sprintf("service=iam-passrole|account=%s|region=%s|source=listroles", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only IAM ListRoles/ListRolePolicies/GetRolePolicy permission is missing",
			Retryable: false,
		}}, gaps
	default:
		return records, nil, gaps
	}
}

func awsIAMPassRoleFixtureRecord(accountID, region, sourceARN, sourceName, target, sid, action, effect, service, conditionOp string, checkedAt time.Time, partition string) AWSIAMPassRoleRelationshipRecord {
	wildcardKind := awsIAMPassRoleWildcardKind(target)
	unresolved := wildcardKind != "specific"
	confidence := awsIAMPassRoleConfidenceFor(wildcardKind)
	record := AWSIAMPassRoleRelationshipRecord{
		AccountID:          accountID,
		Region:             region,
		Service:            "iam-passrole",
		WorkloadID:         strings.Join([]string{sourceARN, "policy=" + sid, target, effect, service}, "|"),
		WorkloadType:       "iam_passrole_relationship",
		WorkloadName:       sourceName,
		SourceRoleARN:      sourceARN,
		SourceRoleName:     sourceName,
		SourceRolePath:     "/",
		TargetResource:     target,
		TargetWildcardKind: wildcardKind,
		PolicyName:         sourceName + "-passrole-policy",
		StatementSid:       sid,
		ActionExpression:   action,
		Effect:             effect,
		PassedToService:    service,
		ConditionOperator:  conditionOp,
		UnresolvedTarget:   unresolved,
		Tags:               map[string]string{"owner": "platform-iam"},
		Source:             "iam_policy_document",
		EvidenceRef:        sourceARN + "#policy=" + sourceName + "-passrole-policy#sid=" + sid,
		FromNodeID:         awsIdentityNodeIDForAPI(sourceARN),
		RelationshipType:   "can_pass_role",
		Confidence:         confidence,
		CollectedAt:        checkedAt,
		Status:             "ready",
	}
	if !unresolved {
		record.ToNodeID = awsIdentityNodeIDForAPI(target)
	}
	if effect == "Deny" {
		record.Status = "deny"
	}
	_ = partition
	return record
}

// awsIAMPassRoleRelationshipEdges projects records into graph edges. Only
// concrete (target_wildcard_kind=specific), allow-effect grants with both
// endpoints resolved are emitted. Wildcard targets stay as record metadata
// because synthesizing edges to "*" or "arn:aws:iam::*:role/*" would create
// non-actionable fan-out in downstream graph queries. Deny statements are
// equally suppressed here — they are documented evidence, not capabilities
// — and downstream net-effect computation reads them from the record list,
// not the edge list.
func awsIAMPassRoleRelationshipEdges(records []AWSIAMPassRoleRelationshipRecord) []AWSIAMPassRoleRelationshipEdge {
	result := make([]AWSIAMPassRoleRelationshipEdge, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		if record.UnresolvedTarget {
			continue
		}
		if !strings.EqualFold(record.Effect, "Allow") {
			continue
		}
		result = append(result, AWSIAMPassRoleRelationshipEdge{
			Type:            record.RelationshipType,
			FromNodeID:      record.FromNodeID,
			ToNodeID:        record.ToNodeID,
			EvidenceRef:     record.EvidenceRef,
			Effect:          record.Effect,
			PassedToService: record.PassedToService,
		})
	}
	return result
}

func summarizeAWSIAMPassRoleRelationshipInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSIAMPassRoleRelationshipRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35,
			[]string{"iam passrole collection is blocked by missing read-only IAM permission"},
			[]string{"Grant iam:ListRoles, iam:ListRolePolicies, iam:GetRolePolicy, iam:ListAttachedRolePolicies, iam:GetPolicy, iam:GetPolicyVersion; do not enable write/decrypt APIs."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.7,
			[]string{"one or more PassRole grants use wildcard or unscoped resources"},
			[]string{"Tighten wildcard PassRole grants to specific role ARNs and add iam:PassedToService where possible before treating coverage as complete."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78,
			[]string{"one ListRoles page failed while previously-collected PassRole grants remain visible"},
			[]string{"Retry the failed IAM ListRoles page without discarding successful PassRole evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82,
				[]string{"iam passrole collection returned diagnostics"},
				[]string{"Review diagnostics before treating PassRole coverage as complete."}
		}
		if len(records) == 0 {
			return awsPlatformDependencyStatusReady, 0.93, nil, nil
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, nil
	}
}

func awsIAMPassRoleSourceRoleCount(records []AWSIAMPassRoleRelationshipRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if arn := strings.TrimSpace(record.SourceRoleARN); arn != "" {
			seen[arn] = struct{}{}
		}
	}
	return len(seen)
}

func awsIAMPassRoleTargetRoleCount(records []AWSIAMPassRoleRelationshipRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if record.UnresolvedTarget {
			continue
		}
		if arn := strings.TrimSpace(record.TargetResource); arn != "" {
			seen[arn] = struct{}{}
		}
	}
	return len(seen)
}

func awsIAMPassRoleWildcardTargetCount(records []AWSIAMPassRoleRelationshipRecord) int {
	count := 0
	for _, record := range records {
		if record.UnresolvedTarget {
			count++
		}
	}
	return count
}

func awsIAMPassRoleDenyCount(records []AWSIAMPassRoleRelationshipRecord) int {
	count := 0
	for _, record := range records {
		if strings.EqualFold(record.Effect, "Deny") {
			count++
		}
	}
	return count
}

func awsIAMPassRoleServiceScopedCount(records []AWSIAMPassRoleRelationshipRecord) int {
	count := 0
	for _, record := range records {
		if strings.TrimSpace(record.PassedToService) != "" {
			count++
		}
	}
	return count
}

func awsIAMPassRoleUnscopedCount(records []AWSIAMPassRoleRelationshipRecord) int {
	count := 0
	for _, record := range records {
		if strings.TrimSpace(record.PassedToService) == "" {
			count++
		}
	}
	return count
}

func awsIAMPassRoleRelationshipDiagnostics(diagnostics []providers.SourceError) []AWSIAMPassRoleRelationshipDiagnostic {
	result := make([]AWSIAMPassRoleRelationshipDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSIAMPassRoleRelationshipDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsIAMPassRoleRelationshipDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsIAMPassRoleRelationshipDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant iam:ListRoles, iam:ListRolePolicies, iam:GetRolePolicy, iam:ListAttachedRolePolicies, iam:GetPolicy, iam:GetPolicyVersion; do not enable write/decrypt APIs."
	case "iam_passrole_wildcard_target":
		return "Tighten the PassRole grant to specific role ARNs and add iam:PassedToService where possible."
	case "iam_passrole_page_failed", "iam_passrole_page_limit_exceeded":
		return "Retry only the failed IAM ListRoles call and keep previously-collected PassRole evidence visible."
	case "iam_passrole_policy_parse_failed":
		return "Audit the policy document for invalid JSON; the collector skips unparseable policies rather than guessing."
	case "malformed_iam_passrole_record":
		return "Inspect the source role's policy and confirm a valid iam:PassRole statement."
	default:
		return "Review the IAM PassRole collector diagnostic and retry after the scoped IAM permission issue is corrected."
	}
}

// awsIAMPassRoleWildcardKind classifies a PassRole target into one of
// specific (a concrete IAM role ARN), path_wildcard, account_wildcard, all (a
// bare "*"), or malformed (anything else — e.g. a typo'd resource, a
// non-IAM ARN such as an S3 bucket or Lambda function). Only IAM role ARNs
// resolve as "specific" so the API never emits a graph edge to a non-role
// resource that happens to be a valid ARN of another service.
func awsIAMPassRoleWildcardKind(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "*" {
		return "all"
	}
	if !strings.HasPrefix(trimmed, "arn:") {
		return "malformed"
	}
	parts := strings.SplitN(trimmed, ":", 6)
	if len(parts) != 6 {
		return "malformed"
	}
	if !strings.EqualFold(parts[2], "iam") {
		return "malformed"
	}
	resource := parts[5]
	if !strings.HasPrefix(resource, "role/") {
		return "malformed"
	}
	if !strings.Contains(trimmed, "*") {
		return "specific"
	}
	if parts[4] == "*" {
		return "account_wildcard"
	}
	return "path_wildcard"
}

func awsIAMPassRoleConfidenceFor(wildcardKind string) float64 {
	switch wildcardKind {
	case "specific":
		return 0.95
	case "path_wildcard":
		return 0.78
	case "account_wildcard":
		return 0.7
	case "malformed":
		return 0.3
	default:
		return 0.55
	}
}

func awsIAMPassRolePartitionForRegion(region string) string {
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
