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
	awsECSTaskRoleCurrentIssue = 1478
	awsECSTaskRoleVersion      = "aws-ecs-task-role-inventory-v1"
)

// AWSECSTaskRoleInventoryRequest controls the deterministic inventory state.
type AWSECSTaskRoleInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSECSTaskRoleInventoryResult exposes scoped ECS task/execution role evidence.
type AWSECSTaskRoleInventoryResult struct {
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
	FixtureState       string                       `json:"fixture_state"`
	Confidence         float64                      `json:"confidence"`
	RecordCount        int                          `json:"record_count"`
	TaskRoleCount      int                          `json:"task_role_count"`
	ExecutionRoleCount int                          `json:"execution_role_count"`
	WorkloadCount      int                          `json:"workload_count"`
	IdentityCount      int                          `json:"identity_count"`
	ResourceCount      int                          `json:"resource_count"`
	RelationshipCount  int                          `json:"relationship_count"`
	FailureReasons     []string                     `json:"failure_reasons"`
	RemediationHints   []string                     `json:"remediation_hints"`
	EvidenceLinks      []string                     `json:"evidence_links"`
	Records            []AWSECSTaskRoleRecord       `json:"records"`
	Relationships      []AWSECSTaskRoleRelationship `json:"relationships"`
	Diagnostics        []AWSECSTaskRoleDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
}

// AWSECSTaskRoleRecord is the operator-facing row for one ECS workload/role link.
type AWSECSTaskRoleRecord struct {
	AccountID              string            `json:"account_id"`
	Region                 string            `json:"region"`
	Service                string            `json:"service"`
	WorkloadID             string            `json:"workload_id"`
	WorkloadType           string            `json:"workload_type"`
	WorkloadName           string            `json:"workload_name"`
	RoleKind               string            `json:"role_kind"`
	RoleARN                string            `json:"role_arn,omitempty"`
	RoleName               string            `json:"role_name,omitempty"`
	ClusterARN             string            `json:"cluster_arn,omitempty"`
	ClusterName            string            `json:"cluster_name,omitempty"`
	ServiceARN             string            `json:"service_arn,omitempty"`
	ServiceName            string            `json:"service_name,omitempty"`
	ServiceStatus          string            `json:"service_status,omitempty"`
	TaskDefinitionARN      string            `json:"task_definition_arn,omitempty"`
	TaskDefinitionFamily   string            `json:"task_definition_family,omitempty"`
	TaskDefinitionRevision string            `json:"task_definition_revision,omitempty"`
	TaskDefinitionStatus   string            `json:"task_definition_status,omitempty"`
	TaskRoleARN            string            `json:"task_role_arn,omitempty"`
	ExecutionRoleARN       string            `json:"execution_role_arn,omitempty"`
	LaunchType             string            `json:"launch_type,omitempty"`
	SchedulingStrategy     string            `json:"scheduling_strategy,omitempty"`
	DesiredCount           int32             `json:"desired_count,omitempty"`
	RunningCount           int32             `json:"running_count,omitempty"`
	PendingCount           int32             `json:"pending_count,omitempty"`
	Compatibilities        []string          `json:"compatibilities,omitempty"`
	ContainerImages        []string          `json:"container_images,omitempty"`
	SecretRefs             []string          `json:"secret_refs,omitempty"`
	EnvironmentKeys        []string          `json:"environment_keys,omitempty"`
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

// AWSECSTaskRoleRelationship is the graph evidence exposed by the API.
type AWSECSTaskRoleRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSECSTaskRoleDiagnostic is one explicit non-success state.
type AWSECSTaskRoleDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSECSTaskRoleInventory returns scoped deterministic ECS task/execution role inventory.
func (s *Service) GetAWSECSTaskRoleInventory(ctx context.Context, workspaceID string, projectID string, request AWSECSTaskRoleInventoryRequest) (AWSECSTaskRoleInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSECSTaskRoleInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSECSTaskRoleInventoryResult{}, err
	}
	return buildAWSECSTaskRoleInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSECSTaskRoleInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSECSTaskRoleInventoryRequest, checkedAt time.Time) (AWSECSTaskRoleInventoryResult, error) {
	fixtureState := normalizeAWSECSTaskRoleFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSECSTaskRoleInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics := awsECSTaskRoleFixtureRecords(scope, project, connectorID, accountID, region, fixtureState, checkedAt)

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
			ScanID:        "aws-ecs-task-role-fixture",
			CollectorName: "ecs_task_role",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSECSTaskRoleInventoryResult{}, fmt.Errorf("validate ecs task role contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSECSTaskRoleInventory(fixtureState, diagnostics)
	relationships := awsECSTaskRoleRelationships(records)
	result := AWSECSTaskRoleInventoryResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsECSTaskRoleCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsECSTaskRoleCurrentIssue),
		Version:            awsECSTaskRoleVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		RecordCount:        len(records),
		TaskRoleCount:      awsECSTaskRoleKindCount(records, "task_role"),
		ExecutionRoleCount: awsECSTaskRoleKindCount(records, "execution_role"),
		WorkloadCount:      awsECSTaskRoleWorkloadCount(records),
		IdentityCount:      awsECSTaskRoleIdentityCount(records),
		ResourceCount:      awsECSTaskRoleResourceCount(records),
		RelationshipCount:  len(relationships),
		FailureReasons:     failures,
		RemediationHints:   remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsECSTaskRoleCurrentIssue),
			"/docs/aws-ecs-task-roles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsECSTaskRoleDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}
	return result, nil
}

func normalizeAWSECSTaskRoleFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsECSTaskRoleFixtureRecords(scope db.Scope, project db.TenancyProject, connectorID string, accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSECSTaskRoleRecord, []providers.SourceError) {
	baseRecord := func(roleKind string, workloadID string, workloadType string, workloadName string, roleARN string, source string, evidenceRef string) AWSECSTaskRoleRecord {
		roleName := roleNameFromARNForAPI(roleARN)
		relationshipType := "runs_as"
		if strings.EqualFold(roleKind, "execution_role") {
			relationshipType = "attached_to"
		}
		status := "ready"
		if strings.TrimSpace(roleARN) == "" {
			status = "degraded"
		}
		return AWSECSTaskRoleRecord{
			AccountID:        accountID,
			Region:           region,
			Service:          "ecs",
			WorkloadID:       workloadID,
			WorkloadType:     workloadType,
			WorkloadName:     workloadName,
			RoleKind:         roleKind,
			RoleARN:          roleARN,
			RoleName:         roleName,
			Tags:             map[string]string{"owner": "platform", "service": "payments"},
			Source:           source,
			EvidenceRef:      evidenceRef,
			FromNodeID:       awsECSWorkloadNodeID(accountID, region, workloadType, workloadID),
			ToNodeID:         awsIdentityNodeIDForAPI(roleARN),
			RelationshipType: relationshipType,
			Confidence:       0.96,
			CollectedAt:      checkedAt,
			Status:           status,
		}
	}

	clusterARN := fmt.Sprintf("arn:aws:ecs:%s:%s:cluster/prod-cluster", region, accountID)
	serviceARN := fmt.Sprintf("arn:aws:ecs:%s:%s:service/prod-cluster/payments-api", region, accountID)
	taskDefinitionARN := fmt.Sprintf("arn:aws:ecs:%s:%s:task-definition/payments-api:42", region, accountID)
	taskRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-ecs-task", accountID)
	executionRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-ecs-execution", accountID)
	taskRole := baseRecord("task_role", serviceARN, "ecs_service", "payments-api", taskRoleARN, "describeservices", serviceARN)
	executionRole := baseRecord("execution_role", serviceARN, "ecs_service", "payments-api", executionRoleARN, "describeservices", serviceARN)
	decorateServiceRecord := func(record *AWSECSTaskRoleRecord) {
		record.ClusterARN = clusterARN
		record.ClusterName = "prod-cluster"
		record.ServiceARN = serviceARN
		record.ServiceName = "payments-api"
		record.ServiceStatus = "ACTIVE"
		record.TaskDefinitionARN = taskDefinitionARN
		record.TaskDefinitionFamily = "payments-api"
		record.TaskDefinitionRevision = "42"
		record.TaskDefinitionStatus = "ACTIVE"
		record.TaskRoleARN = taskRoleARN
		record.ExecutionRoleARN = executionRoleARN
		record.LaunchType = "FARGATE"
		record.SchedulingStrategy = "REPLICA"
		record.DesiredCount = 3
		record.RunningCount = 3
		record.Compatibilities = []string{"FARGATE"}
		record.ContainerImages = []string{fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/payments-api:2026-06-04", accountID, region)}
		record.SecretRefs = []string{fmt.Sprintf("DATABASE_PASSWORD=arn:aws:secretsmanager:%s:%s:secret:payments/db", region, accountID)}
		record.EnvironmentKeys = []string{"APP_ENV", "LOG_LEVEL"}
	}
	decorateServiceRecord(&taskRole)
	decorateServiceRecord(&executionRole)
	executionRole.Confidence = 0.9

	inactiveTaskDefinitionARN := fmt.Sprintf("arn:aws:ecs:%s:%s:task-definition/legacy-worker:7", region, accountID)
	inactiveRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/legacy-worker-task", accountID)
	inactive := baseRecord("task_role", inactiveTaskDefinitionARN, "ecs_task_definition", "legacy-worker", inactiveRoleARN, "describetaskdefinition", inactiveTaskDefinitionARN)
	inactive.TaskDefinitionARN = inactiveTaskDefinitionARN
	inactive.TaskDefinitionFamily = "legacy-worker"
	inactive.TaskDefinitionRevision = "7"
	inactive.TaskDefinitionStatus = "INACTIVE"
	inactive.TaskRoleARN = inactiveRoleARN
	inactive.Compatibilities = []string{"EC2"}
	inactive.ContainerImages = []string{fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/legacy-worker:7", accountID, region)}
	inactive.EnvironmentKeys = []string{"QUEUE_NAME"}

	switch fixtureState {
	case "empty":
		return nil, nil
	case "degraded":
		degraded := taskRole
		degraded.ExecutionRoleARN = ""
		return []AWSECSTaskRoleRecord{degraded}, []providers.SourceError{{
			Collector: "aws_ecs/ecs_task_role",
			SourceID:  taskDefinitionARN,
			Code:      "missing_execution_role",
			Message:   "ECS task definition has a task role but no execution role metadata",
			Retryable: false,
		}}
	case "partial_failure":
		return []AWSECSTaskRoleRecord{taskRole, executionRole}, []providers.SourceError{{
			Collector: "aws_ecs/ecs_task_role",
			SourceID:  fmt.Sprintf("service=ecs|account=%s|region=%s|source=cluster/prod-cluster", accountID, region),
			Code:      "cluster_service_list_failed",
			Message:   "One ECS cluster could not list services; successful service role evidence remains visible",
			Retryable: true,
		}}
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_ecs/ecs_task_role",
			SourceID:  fmt.Sprintf("service=ecs|account=%s|region=%s|source=listclusters", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only ECS ListClusters, DescribeServices, or DescribeTaskDefinition permission is missing",
			Retryable: false,
		}}
	default:
		return []AWSECSTaskRoleRecord{taskRole, executionRole, inactive}, nil
	}
}

func summarizeAWSECSTaskRoleInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"ecs task role collection is blocked by missing read-only permission"}, []string{"Grant ecs:ListClusters, ecs:ListServices, ecs:DescribeServices, ecs:ListTaskDefinitions, and ecs:DescribeTaskDefinition for metadata-only collection."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.66, []string{"one or more ECS task definitions are missing task or execution role evidence"}, []string{"Keep successful ECS task-role evidence visible and inspect task definitions without role ARNs before using coverage for least-privilege reasoning."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.74, []string{"one ECS cluster or task-definition partition failed while successful records remain visible"}, []string{"Retry the failed cluster, account, region, or task-definition status without discarding successful ECS workload evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.8, []string{"ecs task role collection returned diagnostics"}, []string{"Review diagnostics before treating ECS coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.97, nil, nil
	}
}

func awsECSTaskRoleRelationships(records []AWSECSTaskRoleRecord) []AWSECSTaskRoleRelationship {
	result := make([]AWSECSTaskRoleRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		relationshipType := record.RelationshipType
		if relationshipType == "" {
			relationshipType = "runs_as"
			if strings.EqualFold(record.RoleKind, "execution_role") {
				relationshipType = "attached_to"
			}
		}
		result = append(result, AWSECSTaskRoleRelationship{
			Type:        relationshipType,
			FromNodeID:  record.FromNodeID,
			ToNodeID:    record.ToNodeID,
			EvidenceRef: record.EvidenceRef,
		})
	}
	return result
}

func awsECSTaskRoleKindCount(records []AWSECSTaskRoleRecord, roleKind string) int {
	count := 0
	for _, record := range records {
		if strings.EqualFold(record.RoleKind, roleKind) && strings.TrimSpace(record.RoleARN) != "" {
			count++
		}
	}
	return count
}

func awsECSTaskRoleWorkloadCount(records []AWSECSTaskRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" {
			continue
		}
		seen[record.FromNodeID] = struct{}{}
	}
	return len(seen)
}

func awsECSTaskRoleIdentityCount(records []AWSECSTaskRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		seen[record.ToNodeID] = struct{}{}
	}
	return len(seen)
}

func awsECSTaskRoleResourceCount(records []AWSECSTaskRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ServiceARN) != "" {
			seen["service:"+record.ServiceARN] = struct{}{}
		}
		if strings.TrimSpace(record.TaskDefinitionARN) != "" {
			seen["task-definition:"+record.TaskDefinitionARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsECSTaskRoleDiagnostics(diagnostics []providers.SourceError) []AWSECSTaskRoleDiagnostic {
	result := make([]AWSECSTaskRoleDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSECSTaskRoleDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsECSTaskRoleDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsECSTaskRoleDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only ECS read permissions; do not add data-plane reads or secret-value access."
	case "missing_execution_role", "missing_ecs_task_roles", "missing_ecs_role":
		return "Inspect the ECS task definition role fields and keep the incomplete workload out of complete-coverage decisions until role evidence is restored."
	case "cluster_service_list_failed", "cluster_services_describe_failed", "task_definition_describe_failed", "task_definition_list_failed", "service_collection_failed":
		return "Retry only the failed ECS cluster, account, region, or task-definition partition and keep successful records visible."
	default:
		return "Review the ECS collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsECSWorkloadNodeID(accountID string, region string, workloadType string, workloadID string) string {
	account := strings.TrimSpace(accountID)
	if account == "" {
		account = "account"
	}
	trimmedRegion := strings.TrimSpace(region)
	if trimmedRegion == "" {
		trimmedRegion = "region"
	}
	normalizedWorkloadID := strings.TrimSpace(workloadID)
	if normalizedWorkloadID == "" {
		normalizedWorkloadID = "workload"
	}
	normalizedWorkloadType := strings.TrimSpace(workloadType)
	if normalizedWorkloadType == "" {
		normalizedWorkloadType = "workload"
	}
	return fmt.Sprintf("aws:workload:ecs:%s:%s:%s/%s", account, trimmedRegion, normalizedWorkloadType, normalizedWorkloadID)
}
