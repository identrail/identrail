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
	awsStepFunctionsStateMachineRoleCurrentIssue = 1483
	awsStepFunctionsStateMachineRoleVersion      = "aws-stepfunctions-state-machine-role-inventory-v1"
)

type AWSStepFunctionsStateMachineRoleInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

type AWSStepFunctionsStateMachineRoleInventoryResult struct {
	TenantID                string                                         `json:"tenant_id"`
	WorkspaceID             string                                         `json:"workspace_id"`
	ProjectID               string                                         `json:"project_id"`
	ConnectorID             string                                         `json:"connector_id,omitempty"`
	AccountID               string                                         `json:"account_id,omitempty"`
	Region                  string                                         `json:"region,omitempty"`
	ParentIssueNumber       int                                            `json:"parent_issue_number"`
	ParentIssueRef          string                                         `json:"parent_issue_ref"`
	CurrentIssueNumber      int                                            `json:"current_issue_number"`
	CurrentIssueRef         string                                         `json:"current_issue_ref"`
	Version                 string                                         `json:"version"`
	Status                  string                                         `json:"status"`
	FixtureState            string                                         `json:"fixture_state"`
	Confidence              float64                                        `json:"confidence"`
	RecordCount             int                                            `json:"record_count"`
	StateMachineCount       int                                            `json:"state_machine_count"`
	NestedWorkflowCount     int                                            `json:"nested_workflow_count"`
	TaskResourceCount       int                                            `json:"task_resource_count"`
	ServiceIntegrationCount int                                            `json:"service_integration_count"`
	LogGroupCount           int                                            `json:"log_group_count"`
	IdentityCount           int                                            `json:"identity_count"`
	ResourceCount           int                                            `json:"resource_count"`
	RelationshipCount       int                                            `json:"relationship_count"`
	FailureReasons          []string                                       `json:"failure_reasons"`
	RemediationHints        []string                                       `json:"remediation_hints"`
	EvidenceLinks           []string                                       `json:"evidence_links"`
	Records                 []AWSStepFunctionsStateMachineRoleRecord       `json:"records"`
	Relationships           []AWSStepFunctionsStateMachineRoleRelationship `json:"relationships"`
	Diagnostics             []AWSStepFunctionsStateMachineRoleDiagnostic   `json:"diagnostics"`
	GeneratedAt             time.Time                                      `json:"generated_at"`
	UpdatedAt               time.Time                                      `json:"updated_at"`
}

type AWSStepFunctionsStateMachineRoleRecord struct {
	AccountID                   string            `json:"account_id"`
	Region                      string            `json:"region"`
	Service                     string            `json:"service"`
	WorkloadID                  string            `json:"workload_id"`
	WorkloadType                string            `json:"workload_type"`
	WorkloadName                string            `json:"workload_name"`
	RoleARN                     string            `json:"role_arn,omitempty"`
	RoleName                    string            `json:"role_name,omitempty"`
	RoleAccountID               string            `json:"role_account_id,omitempty"`
	StateMachineARN             string            `json:"state_machine_arn,omitempty"`
	StateMachineName            string            `json:"state_machine_name,omitempty"`
	StateMachineType            string            `json:"state_machine_type,omitempty"`
	StateMachineStatus          string            `json:"state_machine_status,omitempty"`
	RevisionID                  string            `json:"revision_id,omitempty"`
	DefinitionSHA256            string            `json:"definition_sha256,omitempty"`
	DefinitionResourceARNs      []string          `json:"definition_resource_arns,omitempty"`
	TaskResourceARNs            []string          `json:"task_resource_arns,omitempty"`
	ServiceIntegrationResources []string          `json:"service_integration_resources,omitempty"`
	NestedStateMachineARNs      []string          `json:"nested_state_machine_arns,omitempty"`
	LoggingLevel                string            `json:"logging_level,omitempty"`
	LoggingIncludeExecutionData bool              `json:"logging_include_execution_data,omitempty"`
	LogGroupARNs                []string          `json:"log_group_arns,omitempty"`
	TracingEnabled              bool              `json:"tracing_enabled,omitempty"`
	EncryptionType              string            `json:"encryption_type,omitempty"`
	KMSKeyARN                   string            `json:"kms_key_arn,omitempty"`
	Tags                        map[string]string `json:"tags,omitempty"`
	Source                      string            `json:"source"`
	EvidenceRef                 string            `json:"evidence_ref"`
	FromNodeID                  string            `json:"from_node_id"`
	ToNodeID                    string            `json:"to_node_id,omitempty"`
	RelationshipType            string            `json:"relationship_type"`
	Confidence                  float64           `json:"confidence"`
	CollectedAt                 time.Time         `json:"collected_at"`
	Status                      string            `json:"status"`
}

type AWSStepFunctionsStateMachineRoleRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

type AWSStepFunctionsStateMachineRoleDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSStepFunctionsStateMachineRoleInventory(ctx context.Context, workspaceID string, projectID string, request AWSStepFunctionsStateMachineRoleInventoryRequest) (AWSStepFunctionsStateMachineRoleInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSStepFunctionsStateMachineRoleInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSStepFunctionsStateMachineRoleInventoryResult{}, err
	}
	return buildAWSStepFunctionsStateMachineRoleInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSStepFunctionsStateMachineRoleInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSStepFunctionsStateMachineRoleInventoryRequest, checkedAt time.Time) (AWSStepFunctionsStateMachineRoleInventoryResult, error) {
	fixtureState := normalizeAWSStepFunctionsStateMachineRoleFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSStepFunctionsStateMachineRoleInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics := awsStepFunctionsStateMachineRoleFixtureRecords(accountID, region, fixtureState, checkedAt)

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
			ScanID:        "aws-stepfunctions-state-machine-role-fixture",
			CollectorName: "stepfunctions_state_machine_role",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSStepFunctionsStateMachineRoleInventoryResult{}, fmt.Errorf("validate stepfunctions state machine role contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSStepFunctionsStateMachineRoleInventory(fixtureState, diagnostics)
	relationships := awsStepFunctionsStateMachineRoleRelationships(records)
	return AWSStepFunctionsStateMachineRoleInventoryResult{
		TenantID:                scope.TenantID,
		WorkspaceID:             project.WorkspaceID,
		ProjectID:               project.ProjectID,
		ConnectorID:             connectorID,
		AccountID:               accountID,
		Region:                  region,
		ParentIssueNumber:       awsPlatformDependencyParentIssue,
		ParentIssueRef:          awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:      awsStepFunctionsStateMachineRoleCurrentIssue,
		CurrentIssueRef:         awsIssueRef(awsStepFunctionsStateMachineRoleCurrentIssue),
		Version:                 awsStepFunctionsStateMachineRoleVersion,
		Status:                  status,
		FixtureState:            fixtureState,
		Confidence:              confidence,
		RecordCount:             len(records),
		StateMachineCount:       awsStepFunctionsStateMachineRoleStateMachineCount(records),
		NestedWorkflowCount:     awsStepFunctionsStateMachineRoleNestedWorkflowCount(records),
		TaskResourceCount:       awsStepFunctionsStateMachineRoleTaskResourceCount(records),
		ServiceIntegrationCount: awsStepFunctionsStateMachineRoleServiceIntegrationCount(records),
		LogGroupCount:           awsStepFunctionsStateMachineRoleLogGroupCount(records),
		IdentityCount:           awsStepFunctionsStateMachineRoleIdentityCount(records),
		ResourceCount:           awsStepFunctionsStateMachineRoleResourceCount(records),
		RelationshipCount:       len(relationships),
		FailureReasons:          failures,
		RemediationHints:        remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsStepFunctionsStateMachineRoleCurrentIssue),
			"/docs/aws-stepfunctions-state-machine-roles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsStepFunctionsStateMachineRoleDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSStepFunctionsStateMachineRoleFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsStepFunctionsStateMachineRoleFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSStepFunctionsStateMachineRoleRecord, []providers.SourceError) {
	stateMachineName := "payments-orchestrator"
	stateMachineARN := fmt.Sprintf("arn:aws:states:%s:%s:stateMachine:%s", region, accountID, stateMachineName)
	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-stepfunctions-execution", accountID)
	lambdaARN := fmt.Sprintf("arn:aws:lambda:%s:%s:function:charge-card", region, accountID)
	nestedARN := fmt.Sprintf("arn:aws:states:%s:%s:stateMachine:payment-risk-check", region, accountID)
	logGroupARN := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:/aws/vendedlogs/states/payments-orchestrator:*", region, accountID)
	base := AWSStepFunctionsStateMachineRoleRecord{
		AccountID:                   accountID,
		Region:                      region,
		Service:                     "stepfunctions",
		WorkloadID:                  stateMachineARN,
		WorkloadType:                "stepfunctions_state_machine",
		WorkloadName:                stateMachineName,
		RoleARN:                     roleARN,
		RoleName:                    roleNameFromARNForAPI(roleARN),
		RoleAccountID:               roleAccountIDFromARNForAPI(roleARN),
		StateMachineARN:             stateMachineARN,
		StateMachineName:            stateMachineName,
		StateMachineType:            "STANDARD",
		StateMachineStatus:          "ACTIVE",
		RevisionID:                  "payments-orchestrator-7",
		DefinitionSHA256:            "8d2ed0fd38f81ac4375a9db4b6f556cae77e3d45d54377ac97b7c8a216b9ef4d",
		DefinitionResourceARNs:      []string{lambdaARN, nestedARN},
		TaskResourceARNs:            []string{"arn:aws:states:::lambda:invoke", "arn:aws:states:::states:startExecution"},
		ServiceIntegrationResources: []string{"lambda", "states"},
		NestedStateMachineARNs:      []string{nestedARN},
		LoggingLevel:                "ALL",
		LoggingIncludeExecutionData: false,
		LogGroupARNs:                []string{logGroupARN},
		TracingEnabled:              true,
		EncryptionType:              "AWS_OWNED_KEY",
		Tags:                        map[string]string{"owner": "platform", "service": "payments"},
		Source:                      "describestatemachine",
		EvidenceRef:                 stateMachineARN,
		FromNodeID:                  awsStepFunctionsNodeID(accountID, region, stateMachineARN),
		ToNodeID:                    awsIdentityNodeIDForAPI(roleARN),
		RelationshipType:            "runs_as",
		Confidence:                  0.96,
		CollectedAt:                 checkedAt,
		Status:                      "ready",
	}
	switch fixtureState {
	case "empty":
		return nil, nil
	case "degraded":
		degraded := base
		degraded.LoggingIncludeExecutionData = true
		degraded.Status = "degraded"
		degraded.Confidence = 0.9
		return []AWSStepFunctionsStateMachineRoleRecord{degraded}, []providers.SourceError{{
			Collector: "aws_stepfunctions/stepfunctions_state_machine_role",
			SourceID:  stateMachineARN,
			Code:      "logging_execution_data_enabled",
			Message:   "Step Functions state-machine evidence is visible, but execution-data logging is enabled",
			Retryable: false,
		}}
	case "partial_failure":
		return []AWSStepFunctionsStateMachineRoleRecord{base}, []providers.SourceError{{
			Collector: "aws_stepfunctions/stepfunctions_state_machine_role",
			SourceID:  fmt.Sprintf("service=stepfunctions|account=%s|region=%s|source=describestatemachine", accountID, region),
			Code:      "state_machine_describe_failed",
			Message:   "One Step Functions state machine could not be described; successful role evidence remains visible",
			Retryable: true,
		}}
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_stepfunctions/stepfunctions_state_machine_role",
			SourceID:  fmt.Sprintf("service=stepfunctions|account=%s|region=%s|source=liststatemachines", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only Step Functions ListStateMachines, DescribeStateMachine, or ListTagsForResource permission is missing",
			Retryable: false,
		}}
	default:
		return []AWSStepFunctionsStateMachineRoleRecord{base}, nil
	}
}

func summarizeAWSStepFunctionsStateMachineRoleInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"stepfunctions state-machine role collection is blocked by missing read-only permission"}, []string{"Grant states:ListStateMachines, states:DescribeStateMachine, and states:ListTagsForResource for metadata-only collection."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.68, []string{"one or more Step Functions state machines have execution-data logging enabled"}, []string{"Keep role evidence visible and review logging settings before treating workflow evidence as complete."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.76, []string{"one Step Functions metadata partition failed while successful state-machine role records remain visible"}, []string{"Retry the failed Step Functions metadata call without discarding successful role evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.8, []string{"stepfunctions state-machine role collection returned diagnostics"}, []string{"Review diagnostics before treating Step Functions coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.96, nil, nil
	}
}

func awsStepFunctionsStateMachineRoleRelationships(records []AWSStepFunctionsStateMachineRoleRecord) []AWSStepFunctionsStateMachineRoleRelationship {
	result := make([]AWSStepFunctionsStateMachineRoleRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		result = append(result, AWSStepFunctionsStateMachineRoleRelationship{
			Type:        "runs_as",
			FromNodeID:  record.FromNodeID,
			ToNodeID:    record.ToNodeID,
			EvidenceRef: record.EvidenceRef,
		})
	}
	return result
}

func awsStepFunctionsStateMachineRoleStateMachineCount(records []AWSStepFunctionsStateMachineRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.StateMachineARN) != "" {
			seen[record.StateMachineARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsStepFunctionsStateMachineRoleNestedWorkflowCount(records []AWSStepFunctionsStateMachineRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, arn := range record.NestedStateMachineARNs {
			if strings.TrimSpace(arn) != "" {
				seen[arn] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsStepFunctionsStateMachineRoleTaskResourceCount(records []AWSStepFunctionsStateMachineRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, arn := range record.TaskResourceARNs {
			if strings.TrimSpace(arn) != "" {
				seen[arn] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsStepFunctionsStateMachineRoleServiceIntegrationCount(records []AWSStepFunctionsStateMachineRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, integration := range record.ServiceIntegrationResources {
			if strings.TrimSpace(integration) != "" {
				seen[integration] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsStepFunctionsStateMachineRoleLogGroupCount(records []AWSStepFunctionsStateMachineRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, arn := range record.LogGroupARNs {
			if strings.TrimSpace(arn) != "" {
				seen[arn] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsStepFunctionsStateMachineRoleIdentityCount(records []AWSStepFunctionsStateMachineRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) != "" {
			seen[record.ToNodeID] = struct{}{}
		}
	}
	return len(seen)
}

func awsStepFunctionsStateMachineRoleResourceCount(records []AWSStepFunctionsStateMachineRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.StateMachineARN) != "" {
			seen[record.StateMachineARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsStepFunctionsStateMachineRoleDiagnostics(diagnostics []providers.SourceError) []AWSStepFunctionsStateMachineRoleDiagnostic {
	result := make([]AWSStepFunctionsStateMachineRoleDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSStepFunctionsStateMachineRoleDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsStepFunctionsStateMachineRoleDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsStepFunctionsStateMachineRoleDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only Step Functions read permissions; do not add execution history, payload, object, or secret-value reads."
	case "logging_execution_data_enabled":
		return "Review Step Functions logging before using workflow evidence for data-exposure decisions."
	case "state_machine_definition_unavailable":
		return "Grant kms:Decrypt only if definition-derived task-resource evidence is required; otherwise keep metadata-only role evidence visible."
	case "state_machine_describe_failed", "state_machine_not_found", "state_machine_tags_failed":
		return "Retry only the failed Step Functions metadata call and keep successful state-machine role records visible."
	case "missing_stepfunctions_execution_role":
		return "Inspect the state machine execution role configuration before using it for least-privilege reasoning."
	default:
		return "Review the Step Functions collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsStepFunctionsNodeID(accountID string, region string, stateMachineRef string) string {
	return fmt.Sprintf("aws:workload:stepfunctions:%s:%s:state-machine/%s", firstNonEmptyAWSValue(accountID, "account"), firstNonEmptyAWSValue(region, "region"), firstNonEmptyAWSValue(stateMachineRef, "state-machine"))
}
