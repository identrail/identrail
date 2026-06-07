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
	awsManagedComputeRoleCurrentIssue = 1485
	awsManagedComputeRoleVersion      = "aws-managed-compute-role-inventory-v1"
)

type AWSManagedComputeRoleInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

type AWSManagedComputeCoverageGap struct {
	Service     string `json:"service"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSManagedComputeRoleInventoryResult struct {
	TenantID                string                              `json:"tenant_id"`
	WorkspaceID             string                              `json:"workspace_id"`
	ProjectID               string                              `json:"project_id"`
	ConnectorID             string                              `json:"connector_id,omitempty"`
	AccountID               string                              `json:"account_id,omitempty"`
	Region                  string                              `json:"region,omitempty"`
	ParentIssueNumber       int                                 `json:"parent_issue_number"`
	ParentIssueRef          string                              `json:"parent_issue_ref"`
	CurrentIssueNumber      int                                 `json:"current_issue_number"`
	CurrentIssueRef         string                              `json:"current_issue_ref"`
	Version                 string                              `json:"version"`
	Status                  string                              `json:"status"`
	FixtureState            string                              `json:"fixture_state"`
	Confidence              float64                             `json:"confidence"`
	RecordCount             int                                 `json:"record_count"`
	ServiceCount            int                                 `json:"service_count"`
	AppRunnerCount          int                                 `json:"app_runner_count"`
	BatchCount              int                                 `json:"batch_count"`
	GlueCount               int                                 `json:"glue_count"`
	EMRCount                int                                 `json:"emr_count"`
	UnsupportedServiceCount int                                 `json:"unsupported_service_count"`
	DisabledCount           int                                 `json:"disabled_count"`
	IdentityCount           int                                 `json:"identity_count"`
	ResourceCount           int                                 `json:"resource_count"`
	RelationshipCount       int                                 `json:"relationship_count"`
	FailureReasons          []string                            `json:"failure_reasons"`
	RemediationHints        []string                            `json:"remediation_hints"`
	EvidenceLinks           []string                            `json:"evidence_links"`
	CoverageGaps            []AWSManagedComputeCoverageGap      `json:"coverage_gaps"`
	Records                 []AWSManagedComputeRoleRecord       `json:"records"`
	Relationships           []AWSManagedComputeRoleRelationship `json:"relationships"`
	Diagnostics             []AWSManagedComputeRoleDiagnostic   `json:"diagnostics"`
	GeneratedAt             time.Time                           `json:"generated_at"`
	UpdatedAt               time.Time                           `json:"updated_at"`
}

type AWSManagedComputeRoleRecord struct {
	AccountID          string            `json:"account_id"`
	Region             string            `json:"region"`
	Service            string            `json:"service"`
	WorkloadID         string            `json:"workload_id"`
	WorkloadType       string            `json:"workload_type"`
	WorkloadName       string            `json:"workload_name"`
	RoleARN            string            `json:"role_arn,omitempty"`
	RoleName           string            `json:"role_name,omitempty"`
	RoleKind           string            `json:"role_kind,omitempty"`
	RoleAccountID      string            `json:"role_account_id,omitempty"`
	WorkloadARN        string            `json:"workload_arn,omitempty"`
	ResourceARN        string            `json:"resource_arn,omitempty"`
	ResourceType       string            `json:"resource_type,omitempty"`
	ResourceStatus     string            `json:"resource_status,omitempty"`
	ComputeEngine      string            `json:"compute_engine,omitempty"`
	QueueARN           string            `json:"queue_arn,omitempty"`
	ClusterARN         string            `json:"cluster_arn,omitempty"`
	JobDefinitionARN   string            `json:"job_definition_arn,omitempty"`
	Revision           int32             `json:"revision,omitempty"`
	UnsupportedService string            `json:"unsupported_service,omitempty"`
	CoverageStatus     string            `json:"coverage_status"`
	CoverageReason     string            `json:"coverage_reason,omitempty"`
	Active             bool              `json:"active"`
	Disabled           bool              `json:"disabled"`
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

type AWSManagedComputeRoleRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

type AWSManagedComputeRoleDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSManagedComputeRoleInventory(ctx context.Context, workspaceID string, projectID string, request AWSManagedComputeRoleInventoryRequest) (AWSManagedComputeRoleInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSManagedComputeRoleInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSManagedComputeRoleInventoryResult{}, err
	}
	return buildAWSManagedComputeRoleInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSManagedComputeRoleInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSManagedComputeRoleInventoryRequest, checkedAt time.Time) (AWSManagedComputeRoleInventoryResult, error) {
	fixtureState := normalizeAWSManagedComputeRoleFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSManagedComputeRoleInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsManagedComputeRoleFixtureRecords(accountID, region, fixtureState, checkedAt)
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
			ScanID:        "aws-managed-compute-role-fixture",
			CollectorName: "managed_compute_role",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSManagedComputeRoleInventoryResult{}, fmt.Errorf("validate managed compute role contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSManagedComputeRoleInventory(fixtureState, diagnostics)
	relationships := awsManagedComputeRoleRelationships(records)
	return AWSManagedComputeRoleInventoryResult{
		TenantID:                scope.TenantID,
		WorkspaceID:             project.WorkspaceID,
		ProjectID:               project.ProjectID,
		ConnectorID:             connectorID,
		AccountID:               accountID,
		Region:                  region,
		ParentIssueNumber:       awsPlatformDependencyParentIssue,
		ParentIssueRef:          awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:      awsManagedComputeRoleCurrentIssue,
		CurrentIssueRef:         awsIssueRef(awsManagedComputeRoleCurrentIssue),
		Version:                 awsManagedComputeRoleVersion,
		Status:                  status,
		FixtureState:            fixtureState,
		Confidence:              confidence,
		RecordCount:             len(records),
		ServiceCount:            awsManagedComputeRoleServiceCount(records),
		AppRunnerCount:          awsManagedComputeRoleServiceRecordCount(records, "apprunner"),
		BatchCount:              awsManagedComputeRoleServiceRecordCount(records, "batch"),
		GlueCount:               awsManagedComputeRoleServiceRecordCount(records, "glue"),
		EMRCount:                awsManagedComputeRoleServiceRecordCount(records, "emr"),
		UnsupportedServiceCount: len(coverageGaps),
		DisabledCount:           awsManagedComputeRoleDisabledCount(records),
		IdentityCount:           awsManagedComputeRoleIdentityCount(records),
		ResourceCount:           awsManagedComputeRoleResourceCount(records),
		RelationshipCount:       len(relationships),
		FailureReasons:          failures,
		RemediationHints:        remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsManagedComputeRoleCurrentIssue),
			"/docs/aws-managed-compute-roles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsManagedComputeRoleDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSManagedComputeRoleFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsManagedComputeRoleFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSManagedComputeRoleRecord, []providers.SourceError, []AWSManagedComputeCoverageGap) {
	gaps := []AWSManagedComputeCoverageGap{{
		Service:     "mwaa",
		Status:      "unsupported",
		Reason:      "MWAA role discovery needs service-specific environment metadata and is tracked as a coverage gap for this wave.",
		Remediation: "Keep MWAA visible as unsupported until a dedicated metadata-only collector is added.",
	}}
	appRunnerARN := fmt.Sprintf("arn:aws:apprunner:%s:%s:service/payments-api/1", region, accountID)
	batchEnvARN := fmt.Sprintf("arn:aws:batch:%s:%s:compute-environment/import-workers", region, accountID)
	batchJobARN := fmt.Sprintf("arn:aws:batch:%s:%s:job-definition/customer-import:5", region, accountID)
	glueJobARN := fmt.Sprintf("arn:aws:glue:%s:%s:job/customer-import", region, accountID)
	glueCrawlerARN := fmt.Sprintf("arn:aws:glue:%s:%s:crawler/customer-crawler", region, accountID)
	emrARN := fmt.Sprintf("arn:aws:elasticmapreduce:%s:%s:cluster/j-2AXXXXXXGAPLF", region, accountID)
	records := []AWSManagedComputeRoleRecord{
		awsManagedComputeRoleFixtureRecord(accountID, region, "apprunner", "apprunner_service", "payments-api", appRunnerARN, fmt.Sprintf("arn:aws:iam::%s:role/apprunner-payments-instance", accountID), "apprunner_instance_role", "RUNNING", "container", true, false, checkedAt),
		awsManagedComputeRoleFixtureRecord(accountID, region, "apprunner", "apprunner_service", "payments-api", appRunnerARN, fmt.Sprintf("arn:aws:iam::%s:role/apprunner-ecr-access", accountID), "apprunner_access_role", "RUNNING", "container", true, false, checkedAt),
		awsManagedComputeRoleFixtureRecord(accountID, region, "batch", "batch_compute_environment", "import-workers", batchEnvARN, fmt.Sprintf("arn:aws:iam::%s:role/batch-service-role", accountID), "batch_service_role", "VALID", "ecs", true, false, checkedAt),
		awsManagedComputeRoleFixtureRecord(accountID, region, "batch", "batch_job_definition", "customer-import", batchJobARN, fmt.Sprintf("arn:aws:iam::%s:role/batch-customer-import", accountID), "batch_job_role", "ACTIVE", "ecs", true, false, checkedAt),
		awsManagedComputeRoleFixtureRecord(accountID, region, "batch", "batch_job_definition", "customer-import", batchJobARN, fmt.Sprintf("arn:aws:iam::%s:role/batch-customer-import-execution", accountID), "batch_execution_role", "ACTIVE", "ecs", true, false, checkedAt),
		awsManagedComputeRoleFixtureRecord(accountID, region, "glue", "glue_job", "customer-import", glueJobARN, fmt.Sprintf("arn:aws:iam::%s:role/glue-customer-import", accountID), "glue_job_role", "READY", "glueetl", true, false, checkedAt),
		awsManagedComputeRoleFixtureRecord(accountID, region, "glue", "glue_crawler", "customer-crawler", glueCrawlerARN, fmt.Sprintf("arn:aws:iam::%s:role/glue-customer-crawler", accountID), "glue_crawler_role", "READY", "", true, false, checkedAt),
		awsManagedComputeRoleFixtureRecord(accountID, region, "emr", "emr_cluster", "analytics", emrARN, fmt.Sprintf("arn:aws:iam::%s:role/emr-default-role", accountID), "emr_service_role", "RUNNING", "emr", true, false, checkedAt),
		awsManagedComputeRoleFixtureRecord(accountID, region, "emr", "emr_cluster", "analytics", emrARN, fmt.Sprintf("arn:aws:iam::%s:role/emr-autoscaling-role", accountID), "emr_autoscaling_role", "RUNNING", "emr", true, false, checkedAt),
	}
	records[3].JobDefinitionARN = batchJobARN
	records[3].Revision = 5
	records[4].JobDefinitionARN = batchJobARN
	records[4].Revision = 5
	records[7].ClusterARN = emrARN
	records[8].ClusterARN = emrARN
	switch fixtureState {
	case "empty":
		return nil, nil, gaps
	case "degraded":
		records[6].Status = "disabled"
		records[6].Active = false
		records[6].Disabled = true
		records[6].Confidence = 0.72
		return records, []providers.SourceError{{Collector: "aws_managed_compute/managed_compute_role", SourceID: glueCrawlerARN, Code: "managed_compute_workload_disabled", Message: "One Glue crawler role is visible, but the crawler is disabled", Retryable: false}}, gaps
	case "partial_failure":
		return records[:6], []providers.SourceError{{Collector: "aws_managed_compute/managed_compute_role", SourceID: fmt.Sprintf("service=emr|account=%s|region=%s|source=listclusters", accountID, region), Code: "emr_failed", Message: "EMR clusters could not be listed; App Runner, Batch, and Glue role evidence remains visible", Retryable: true}}, gaps
	case "permission_denied":
		return nil, []providers.SourceError{{Collector: "aws_managed_compute/managed_compute_role", SourceID: fmt.Sprintf("service=managed-compute|account=%s|region=%s|source=list", accountID, region), Code: "permission_denied", Message: "Read-only managed compute metadata permission is missing", Retryable: false}}, gaps
	default:
		return records, nil, gaps
	}
}

func awsManagedComputeRoleFixtureRecord(accountID string, region string, service string, workloadType string, workloadName string, workloadARN string, roleARN string, roleKind string, resourceStatus string, computeEngine string, active bool, disabled bool, checkedAt time.Time) AWSManagedComputeRoleRecord {
	return AWSManagedComputeRoleRecord{
		AccountID:        accountID,
		Region:           region,
		Service:          service,
		WorkloadID:       workloadARN,
		WorkloadType:     workloadType,
		WorkloadName:     workloadName,
		RoleARN:          roleARN,
		RoleName:         roleNameFromARNForAPI(roleARN),
		RoleKind:         roleKind,
		RoleAccountID:    roleAccountIDFromARNForAPI(roleARN),
		WorkloadARN:      workloadARN,
		ResourceARN:      workloadARN,
		ResourceType:     workloadType,
		ResourceStatus:   resourceStatus,
		ComputeEngine:    computeEngine,
		CoverageStatus:   "covered",
		Active:           active,
		Disabled:         disabled,
		Tags:             map[string]string{"owner": "platform", "service": service},
		Source:           service + "_metadata",
		EvidenceRef:      workloadARN,
		FromNodeID:       awsManagedComputeNodeID(accountID, region, workloadType, workloadARN, roleKind),
		ToNodeID:         awsIdentityNodeIDForAPI(roleARN),
		RelationshipType: awsManagedComputeRoleRelationshipType(roleKind),
		Confidence:       0.93,
		CollectedAt:      checkedAt,
		Status:           "ready",
	}
}

func awsManagedComputeRoleRelationshipType(roleKind string) string {
	normalized := strings.ToLower(strings.TrimSpace(roleKind))
	switch {
	case strings.Contains(normalized, "execution_role"), strings.Contains(normalized, "access_role"):
		return "attached_to"
	default:
		return "runs_as"
	}
}

func summarizeAWSManagedComputeRoleInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"managed compute role collection is blocked by missing read-only permission"}, []string{"Grant metadata-only App Runner, Batch, Glue, and EMR read permissions; do not add logs, payload, secret, or execution-history reads."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.7, []string{"one or more managed compute workloads are disabled or degraded"}, []string{"Keep role evidence visible and review workload status before treating managed compute evidence as complete."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78, []string{"one managed compute service partition failed while successful role records remain visible"}, []string{"Retry the failed managed compute metadata call without discarding successful role evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82, []string{"managed compute role collection returned diagnostics"}, []string{"Review diagnostics before treating managed compute coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, nil
	}
}

func awsManagedComputeRoleRelationships(records []AWSManagedComputeRoleRecord) []AWSManagedComputeRoleRelationship {
	result := make([]AWSManagedComputeRoleRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		result = append(result, AWSManagedComputeRoleRelationship{Type: record.RelationshipType, FromNodeID: record.FromNodeID, ToNodeID: record.ToNodeID, EvidenceRef: record.EvidenceRef})
	}
	return result
}

func awsManagedComputeRoleServiceRecordCount(records []AWSManagedComputeRoleRecord, service string) int {
	count := 0
	for _, record := range records {
		if record.Service == service {
			count++
		}
	}
	return count
}

func awsManagedComputeRoleServiceCount(records []AWSManagedComputeRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.Service) != "" {
			seen[record.Service] = struct{}{}
		}
	}
	return len(seen)
}

func awsManagedComputeRoleDisabledCount(records []AWSManagedComputeRoleRecord) int {
	count := 0
	for _, record := range records {
		if record.Disabled {
			count++
		}
	}
	return count
}

func awsManagedComputeRoleIdentityCount(records []AWSManagedComputeRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) != "" {
			seen[record.ToNodeID] = struct{}{}
		}
	}
	return len(seen)
}

func awsManagedComputeRoleResourceCount(records []AWSManagedComputeRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ResourceARN) != "" {
			seen[record.ResourceARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsManagedComputeRoleDiagnostics(diagnostics []providers.SourceError) []AWSManagedComputeRoleDiagnostic {
	result := make([]AWSManagedComputeRoleDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSManagedComputeRoleDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsManagedComputeRoleDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsManagedComputeRoleDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only App Runner, Batch, Glue, and EMR read permissions; do not add logs, payload, secret-value, or execution-history reads."
	case "managed_compute_workload_disabled":
		return "Keep the disabled workload visible and confirm whether the role should remain attached before least-privilege decisions."
	case "managed_compute_role_page_failed", "apprunner_services_failed", "apprunner_service_describe_failed", "batch_failed", "batch_job_definitions_failed", "glue_failed", "glue_crawlers_failed", "emr_failed", "emr_cluster_describe_failed":
		return "Retry only the failed managed compute metadata call and keep successful role records visible."
	case "missing_managed_compute_role":
		return "Inspect the managed compute workload role configuration before using it for least-privilege reasoning."
	default:
		return "Review the managed compute collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsManagedComputeNodeID(accountID string, region string, workloadType string, workloadRef string, roleKind string) string {
	return fmt.Sprintf("aws:workload:managed-compute:%s:%s:%s/%s/%s", firstNonEmptyAWSValue(accountID, "account"), firstNonEmptyAWSValue(region, "region"), firstNonEmptyAWSValue(workloadType, "workload"), firstNonEmptyAWSValue(workloadRef, "managed-compute"), firstNonEmptyAWSValue(roleKind, "role"))
}
