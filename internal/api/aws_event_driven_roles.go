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
	awsEventDrivenRoleCurrentIssue = 1484
	awsEventDrivenRoleVersion      = "aws-event-driven-role-inventory-v1"
)

type AWSEventDrivenRoleInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

type AWSEventDrivenRoleInventoryResult struct {
	TenantID           string                           `json:"tenant_id"`
	WorkspaceID        string                           `json:"workspace_id"`
	ProjectID          string                           `json:"project_id"`
	ConnectorID        string                           `json:"connector_id,omitempty"`
	AccountID          string                           `json:"account_id,omitempty"`
	Region             string                           `json:"region,omitempty"`
	ParentIssueNumber  int                              `json:"parent_issue_number"`
	ParentIssueRef     string                           `json:"parent_issue_ref"`
	CurrentIssueNumber int                              `json:"current_issue_number"`
	CurrentIssueRef    string                           `json:"current_issue_ref"`
	Version            string                           `json:"version"`
	Status             string                           `json:"status"`
	FixtureState       string                           `json:"fixture_state"`
	Confidence         float64                          `json:"confidence"`
	RecordCount        int                              `json:"record_count"`
	RuleCount          int                              `json:"rule_count"`
	ScheduleCount      int                              `json:"schedule_count"`
	PipeCount          int                              `json:"pipe_count"`
	TargetCount        int                              `json:"target_count"`
	DeadLetterCount    int                              `json:"dead_letter_count"`
	DisabledCount      int                              `json:"disabled_count"`
	IdentityCount      int                              `json:"identity_count"`
	ResourceCount      int                              `json:"resource_count"`
	RelationshipCount  int                              `json:"relationship_count"`
	FailureReasons     []string                         `json:"failure_reasons"`
	RemediationHints   []string                         `json:"remediation_hints"`
	EvidenceLinks      []string                         `json:"evidence_links"`
	Records            []AWSEventDrivenRoleRecord       `json:"records"`
	Relationships      []AWSEventDrivenRoleRelationship `json:"relationships"`
	Diagnostics        []AWSEventDrivenRoleDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                        `json:"generated_at"`
	UpdatedAt          time.Time                        `json:"updated_at"`
}

type AWSEventDrivenRoleRecord struct {
	AccountID              string            `json:"account_id"`
	Region                 string            `json:"region"`
	Service                string            `json:"service"`
	WorkloadID             string            `json:"workload_id"`
	WorkloadType           string            `json:"workload_type"`
	WorkloadName           string            `json:"workload_name"`
	RoleARN                string            `json:"role_arn,omitempty"`
	RoleName               string            `json:"role_name,omitempty"`
	RoleKind               string            `json:"role_kind,omitempty"`
	RoleAccountID          string            `json:"role_account_id,omitempty"`
	WorkloadARN            string            `json:"workload_arn,omitempty"`
	EventBusName           string            `json:"event_bus_name,omitempty"`
	EventBusARN            string            `json:"event_bus_arn,omitempty"`
	ScheduleGroupName      string            `json:"schedule_group_name,omitempty"`
	ScheduleExpression     string            `json:"schedule_expression,omitempty"`
	ScheduleTimezone       string            `json:"schedule_timezone,omitempty"`
	PipeSourceARN          string            `json:"pipe_source_arn,omitempty"`
	PipeTargetARN          string            `json:"pipe_target_arn,omitempty"`
	PipeEnrichmentARN      string            `json:"pipe_enrichment_arn,omitempty"`
	TargetARN              string            `json:"target_arn,omitempty"`
	TargetID               string            `json:"target_id,omitempty"`
	TargetService          string            `json:"target_service,omitempty"`
	DeadLetterARNs         []string          `json:"dead_letter_arns,omitempty"`
	RetryMaximumAgeSeconds int32             `json:"retry_maximum_age_seconds,omitempty"`
	RetryMaximumAttempts   int32             `json:"retry_maximum_attempts,omitempty"`
	EventPatternSHA256     string            `json:"event_pattern_sha256,omitempty"`
	InputTransformerSHA256 string            `json:"input_transformer_sha256,omitempty"`
	InputPathConfigured    bool              `json:"input_path_configured,omitempty"`
	TargetInputConfigured  bool              `json:"target_input_configured,omitempty"`
	ExecutionDataLogging   bool              `json:"execution_data_logging,omitempty"`
	LogDestinationARNs     []string          `json:"log_destination_arns,omitempty"`
	KMSKeyARN              string            `json:"kms_key_arn,omitempty"`
	Active                 bool              `json:"active"`
	Disabled               bool              `json:"disabled"`
	StateReason            string            `json:"state_reason,omitempty"`
	Tags                   map[string]string `json:"tags,omitempty"`
	Source                 string            `json:"source"`
	EvidenceRef            string            `json:"evidence_ref"`
	FromNodeID             string            `json:"from_node_id"`
	ToNodeID               string            `json:"to_node_id,omitempty"`
	RelationshipType       string            `json:"relationship_type"`
	Confidence             float64           `json:"confidence"`
	CollectedAt            time.Time         `json:"collected_at"`
	Status                 string            `json:"status"`
}

type AWSEventDrivenRoleRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

type AWSEventDrivenRoleDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSEventDrivenRoleInventory(ctx context.Context, workspaceID string, projectID string, request AWSEventDrivenRoleInventoryRequest) (AWSEventDrivenRoleInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSEventDrivenRoleInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSEventDrivenRoleInventoryResult{}, err
	}
	return buildAWSEventDrivenRoleInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSEventDrivenRoleInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSEventDrivenRoleInventoryRequest, checkedAt time.Time) (AWSEventDrivenRoleInventoryResult, error) {
	fixtureState := normalizeAWSEventDrivenRoleFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSEventDrivenRoleInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics := awsEventDrivenRoleFixtureRecords(accountID, region, fixtureState, checkedAt)

	for _, record := range records {
		if strings.TrimSpace(record.RoleARN) == "" {
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
			RoleARN:       record.RoleARN,
			Source:        record.Source,
			EvidenceRef:   record.EvidenceRef,
			Confidence:    record.Confidence,
			ScanID:        "aws-event-driven-role-fixture",
			CollectorName: "event_driven_role",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSEventDrivenRoleInventoryResult{}, fmt.Errorf("validate event-driven role contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSEventDrivenRoleInventory(fixtureState, diagnostics)
	relationships := awsEventDrivenRoleRelationships(records)
	return AWSEventDrivenRoleInventoryResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsEventDrivenRoleCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsEventDrivenRoleCurrentIssue),
		Version:            awsEventDrivenRoleVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		RecordCount:        len(records),
		RuleCount:          awsEventDrivenRoleTypeCount(records, "eventbridge_rule"),
		ScheduleCount:      awsEventDrivenRoleTypeCount(records, "scheduler_schedule"),
		PipeCount:          awsEventDrivenRoleTypeCount(records, "eventbridge_pipe"),
		TargetCount:        awsEventDrivenRoleTargetCount(records),
		DeadLetterCount:    awsEventDrivenRoleDeadLetterCount(records),
		DisabledCount:      awsEventDrivenRoleDisabledCount(records),
		IdentityCount:      awsEventDrivenRoleIdentityCount(records),
		ResourceCount:      awsEventDrivenRoleResourceCount(records),
		RelationshipCount:  len(relationships),
		FailureReasons:     failures,
		RemediationHints:   remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsEventDrivenRoleCurrentIssue),
			"/docs/aws-event-driven-roles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsEventDrivenRoleDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSEventDrivenRoleFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "", "success":
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsEventDrivenRoleFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSEventDrivenRoleRecord, []providers.SourceError) {
	ruleARN := fmt.Sprintf("arn:aws:events:%s:%s:rule/default/customer-created", region, accountID)
	targetARN := fmt.Sprintf("arn:aws:lambda:%s:%s:function:sync-customer", region, accountID)
	dlqARN := fmt.Sprintf("arn:aws:sqs:%s:%s:eventbridge-customer-created-dlq", region, accountID)
	ruleRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/eventbridge-customer-created-target", accountID)
	scheduleARN := fmt.Sprintf("arn:aws:scheduler:%s:%s:schedule/default/daily-entitlement-refresh", region, accountID)
	scheduleRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/scheduler-entitlement-refresh", accountID)
	pipeARN := fmt.Sprintf("arn:aws:pipes:%s:%s:pipe/audit-stream-to-queue", region, accountID)
	pipeRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/pipes-audit-stream-reader", accountID)

	records := []AWSEventDrivenRoleRecord{
		{
			AccountID:              accountID,
			Region:                 region,
			Service:                "eventbridge",
			WorkloadID:             ruleARN,
			WorkloadType:           "eventbridge_rule",
			WorkloadName:           "customer-created",
			RoleARN:                ruleRoleARN,
			RoleName:               roleNameFromARNForAPI(ruleRoleARN),
			RoleKind:               "eventbridge_target_role",
			RoleAccountID:          roleAccountIDFromARNForAPI(ruleRoleARN),
			WorkloadARN:            ruleARN,
			EventBusName:           "default",
			TargetARN:              targetARN,
			TargetID:               "sync-customer",
			TargetService:          "lambda",
			DeadLetterARNs:         []string{dlqARN},
			RetryMaximumAgeSeconds: 3600,
			RetryMaximumAttempts:   3,
			EventPatternSHA256:     "9d9bba4cf177f8d7f13910a47099fe6b7e9ea4b9a3d573624a94b0e454c0614c",
			InputTransformerSHA256: "d8f61d4c6f1d859940c4942b5713d84ef56359d1a52d0f49f7f1aa8da1b3d5a8",
			Active:                 true,
			Tags:                   map[string]string{"owner": "platform", "service": "customer"},
			Source:                 "listrules/listtargetsbyrule",
			EvidenceRef:            ruleARN,
			FromNodeID:             awsEventDrivenNodeID(accountID, region, "eventbridge-rule", ruleARN),
			ToNodeID:               awsIdentityNodeIDForAPI(ruleRoleARN),
			RelationshipType:       "runs_as",
			Confidence:             0.94,
			CollectedAt:            checkedAt,
			Status:                 "ready",
		},
		{
			AccountID:          accountID,
			Region:             region,
			Service:            "scheduler",
			WorkloadID:         scheduleARN,
			WorkloadType:       "scheduler_schedule",
			WorkloadName:       "daily-entitlement-refresh",
			RoleARN:            scheduleRoleARN,
			RoleName:           roleNameFromARNForAPI(scheduleRoleARN),
			RoleKind:           "scheduler_schedule_role",
			RoleAccountID:      roleAccountIDFromARNForAPI(scheduleRoleARN),
			WorkloadARN:        scheduleARN,
			ScheduleGroupName:  "default",
			ScheduleExpression: "rate(1 day)",
			ScheduleTimezone:   "UTC",
			TargetARN:          fmt.Sprintf("arn:aws:states:%s:%s:stateMachine:refresh-entitlements", region, accountID),
			TargetService:      "states",
			DeadLetterARNs:     []string{fmt.Sprintf("arn:aws:sqs:%s:%s:scheduler-entitlement-dlq", region, accountID)},
			Disabled:           true,
			StateReason:        "schedule disabled by operator",
			Tags:               map[string]string{"owner": "identity", "service": "entitlements"},
			Source:             "getschedule",
			EvidenceRef:        scheduleARN,
			FromNodeID:         awsEventDrivenNodeID(accountID, region, "scheduler-schedule", scheduleARN),
			ToNodeID:           awsIdentityNodeIDForAPI(scheduleRoleARN),
			RelationshipType:   "runs_as",
			Confidence:         0.72,
			CollectedAt:        checkedAt,
			Status:             "disabled",
		},
		{
			AccountID:          accountID,
			Region:             region,
			Service:            "pipes",
			WorkloadID:         pipeARN,
			WorkloadType:       "eventbridge_pipe",
			WorkloadName:       "audit-stream-to-queue",
			RoleARN:            pipeRoleARN,
			RoleName:           roleNameFromARNForAPI(pipeRoleARN),
			RoleKind:           "pipe_execution_role",
			RoleAccountID:      roleAccountIDFromARNForAPI(pipeRoleARN),
			WorkloadARN:        pipeARN,
			PipeSourceARN:      fmt.Sprintf("arn:aws:kinesis:%s:%s:stream/audit-events", region, accountID),
			PipeTargetARN:      fmt.Sprintf("arn:aws:sqs:%s:%s:audit-enrichment", region, accountID),
			PipeEnrichmentARN:  fmt.Sprintf("arn:aws:lambda:%s:%s:function:enrich-audit-event", region, accountID),
			TargetService:      "sqs",
			DeadLetterARNs:     []string{fmt.Sprintf("arn:aws:sqs:%s:%s:pipes-audit-dlq", region, accountID)},
			LogDestinationARNs: []string{fmt.Sprintf("arn:aws:logs:%s:%s:log-group:/aws/vendedlogs/pipes/audit-stream-to-queue:*", region, accountID)},
			Active:             true,
			Tags:               map[string]string{"owner": "security", "service": "audit"},
			Source:             "describepipe",
			EvidenceRef:        pipeARN,
			FromNodeID:         awsEventDrivenNodeID(accountID, region, "eventbridge-pipe", pipeARN),
			ToNodeID:           awsIdentityNodeIDForAPI(pipeRoleARN),
			RelationshipType:   "runs_as",
			Confidence:         0.94,
			CollectedAt:        checkedAt,
			Status:             "ready",
		},
	}
	switch fixtureState {
	case "empty":
		return nil, nil
	case "degraded":
		records[2].ExecutionDataLogging = true
		records[2].Status = "degraded"
		records[2].Confidence = 0.86
		return records, []providers.SourceError{{
			Collector: "aws_eventbridge/event_driven_role",
			SourceID:  pipeARN,
			Code:      "pipe_execution_data_logging_enabled",
			Message:   "EventBridge Pipes role evidence is visible, but execution-data logging is enabled",
			Retryable: false,
		}}
	case "partial_failure":
		return records[:2], []providers.SourceError{{
			Collector: "aws_eventbridge/event_driven_role",
			SourceID:  fmt.Sprintf("service=pipes|account=%s|region=%s|source=describepipe", accountID, region),
			Code:      "pipe_describe_failed",
			Message:   "One EventBridge Pipe could not be described; successful rule and schedule role evidence remains visible",
			Retryable: true,
		}}
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_eventbridge/event_driven_role",
			SourceID:  fmt.Sprintf("service=eventbridge|account=%s|region=%s|source=list", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only EventBridge, Scheduler, or Pipes metadata permission is missing",
			Retryable: false,
		}}
	default:
		return records, nil
	}
}

func summarizeAWSEventDrivenRoleInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"event-driven role collection is blocked by missing read-only permission"}, []string{"Grant metadata-only events, scheduler, and pipes read permissions; do not add payload, secret, or execution-history reads."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.7, []string{"one or more event-driven workloads have execution-data logging enabled"}, []string{"Keep role evidence visible and review logging settings before treating event-driven evidence as complete."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78, []string{"one event-driven metadata partition failed while successful role records remain visible"}, []string{"Retry the failed EventBridge, Scheduler, or Pipes metadata call without discarding successful role evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82, []string{"event-driven role collection returned diagnostics"}, []string{"Review diagnostics before treating event-driven coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.94, nil, nil
	}
}

func awsEventDrivenRoleRelationships(records []AWSEventDrivenRoleRecord) []AWSEventDrivenRoleRelationship {
	result := make([]AWSEventDrivenRoleRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		result = append(result, AWSEventDrivenRoleRelationship{Type: "runs_as", FromNodeID: record.FromNodeID, ToNodeID: record.ToNodeID, EvidenceRef: record.EvidenceRef})
	}
	return result
}

func awsEventDrivenRoleTypeCount(records []AWSEventDrivenRoleRecord, workloadType string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if record.WorkloadType == workloadType && strings.TrimSpace(record.WorkloadARN) != "" {
			seen[record.WorkloadARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsEventDrivenRoleTargetCount(records []AWSEventDrivenRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, ref := range []string{record.TargetARN, record.PipeTargetARN} {
			if strings.TrimSpace(ref) != "" {
				seen[ref] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsEventDrivenRoleDeadLetterCount(records []AWSEventDrivenRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, arn := range record.DeadLetterARNs {
			if strings.TrimSpace(arn) != "" {
				seen[arn] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsEventDrivenRoleDisabledCount(records []AWSEventDrivenRoleRecord) int {
	count := 0
	for _, record := range records {
		if record.Disabled {
			count++
		}
	}
	return count
}

func awsEventDrivenRoleIdentityCount(records []AWSEventDrivenRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) != "" {
			seen[record.ToNodeID] = struct{}{}
		}
	}
	return len(seen)
}

func awsEventDrivenRoleResourceCount(records []AWSEventDrivenRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.WorkloadARN) != "" {
			seen[record.WorkloadARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsEventDrivenRoleDiagnostics(diagnostics []providers.SourceError) []AWSEventDrivenRoleDiagnostic {
	result := make([]AWSEventDrivenRoleDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSEventDrivenRoleDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsEventDrivenRoleDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsEventDrivenRoleDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only events, scheduler, and pipes read permissions; do not add payload, secret-value, or execution-history reads."
	case "pipe_execution_data_logging_enabled":
		return "Review EventBridge Pipes logging before using pipe evidence for data-exposure decisions."
	case "event_driven_role_page_failed", "malformed_source_record", "eventbridge_rules_failed", "eventbridge_rule_list_failed", "eventbridge_targets_failed", "scheduler_schedules_failed", "scheduler_schedule_name_missing", "scheduler_schedule_get_failed", "scheduler_schedule_target_missing", "pipes_failed", "pipe_name_missing", "pipe_describe_failed":
		return "Retry only the failed event-driven metadata call and keep successful role records visible."
	case "missing_event_driven_role":
		return "Inspect the rule target, schedule target, or pipe execution role configuration before using it for least-privilege reasoning."
	default:
		return "Review the EventBridge, Scheduler, or Pipes collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsEventDrivenNodeID(accountID string, region string, workloadType string, workloadRef string) string {
	return fmt.Sprintf("aws:workload:event-driven:%s:%s:%s/%s", firstNonEmptyAWSValue(accountID, "account"), firstNonEmptyAWSValue(region, "region"), firstNonEmptyAWSValue(workloadType, "workload"), firstNonEmptyAWSValue(workloadRef, "event-driven"))
}
