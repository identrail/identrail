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
	awsSageMakerWorkloadRoleCurrentIssue = 1486
	awsSageMakerWorkloadRoleVersion      = "aws-sagemaker-workload-role-inventory-v1"
)

// AWSSageMakerWorkloadRoleInventoryRequest is the operator-facing request to
// fetch SageMaker workload role inventory. fixture_state lets operators
// preview each documented collector state (success, empty, degraded,
// permission_denied, partial_failure) without touching AWS.
type AWSSageMakerWorkloadRoleInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSSageMakerCoverageGap names a SageMaker resource type Identrail
// intentionally does not collect this wave, with the reason and remediation
// the operator should rely on.
type AWSSageMakerCoverageGap struct {
	WorkloadType string `json:"workload_type"`
	Status       string `json:"status"`
	Reason       string `json:"reason"`
	Remediation  string `json:"remediation,omitempty"`
}

// AWSSageMakerWorkloadRoleInventoryResult is the deterministic envelope this
// endpoint returns. It mirrors the shape of the AWS managed-compute inventory
// so the AWS shell can render it with the same loading/empty/error states.
type AWSSageMakerWorkloadRoleInventoryResult struct {
	TenantID           string                                 `json:"tenant_id"`
	WorkspaceID        string                                 `json:"workspace_id"`
	ProjectID          string                                 `json:"project_id"`
	ConnectorID        string                                 `json:"connector_id,omitempty"`
	AccountID          string                                 `json:"account_id,omitempty"`
	Region             string                                 `json:"region,omitempty"`
	ParentIssueNumber  int                                    `json:"parent_issue_number"`
	ParentIssueRef     string                                 `json:"parent_issue_ref"`
	CurrentIssueNumber int                                    `json:"current_issue_number"`
	CurrentIssueRef    string                                 `json:"current_issue_ref"`
	Version            string                                 `json:"version"`
	Status             string                                 `json:"status"`
	FixtureState       string                                 `json:"fixture_state"`
	Confidence         float64                                `json:"confidence"`
	RecordCount        int                                    `json:"record_count"`
	WorkloadTypeCount  int                                    `json:"workload_type_count"`
	NotebookCount      int                                    `json:"notebook_count"`
	TrainingJobCount   int                                    `json:"training_job_count"`
	ProcessingJobCount int                                    `json:"processing_job_count"`
	TransformJobCount  int                                    `json:"transform_job_count"`
	ModelCount         int                                    `json:"model_count"`
	EndpointCount      int                                    `json:"endpoint_count"`
	PipelineCount      int                                    `json:"pipeline_count"`
	DomainCount        int                                    `json:"domain_count"`
	S3ReferenceCount   int                                    `json:"s3_reference_count"`
	ECRImageCount      int                                    `json:"ecr_image_count"`
	KMSKeyCount        int                                    `json:"kms_key_count"`
	IdentityCount      int                                    `json:"identity_count"`
	ResourceCount      int                                    `json:"resource_count"`
	RelationshipCount  int                                    `json:"relationship_count"`
	FailureReasons     []string                               `json:"failure_reasons"`
	RemediationHints   []string                               `json:"remediation_hints"`
	EvidenceLinks      []string                               `json:"evidence_links"`
	CoverageGaps       []AWSSageMakerCoverageGap              `json:"coverage_gaps"`
	Records            []AWSSageMakerWorkloadRoleRecord       `json:"records"`
	Relationships      []AWSSageMakerWorkloadRoleRelationship `json:"relationships"`
	Diagnostics        []AWSSageMakerWorkloadRoleDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                              `json:"generated_at"`
	UpdatedAt          time.Time                              `json:"updated_at"`
}

// AWSSageMakerWorkloadRoleRecord is one normalized SageMaker workload→role
// association exposed by the API. It carries enough S3/ECR/KMS context for
// downstream blast-radius reasoning while staying payload-safe (no notebook,
// payload, or model contents).
type AWSSageMakerWorkloadRoleRecord struct {
	AccountID        string            `json:"account_id"`
	Region           string            `json:"region"`
	Service          string            `json:"service"`
	WorkloadID       string            `json:"workload_id"`
	WorkloadType     string            `json:"workload_type"`
	WorkloadName     string            `json:"workload_name"`
	RoleARN          string            `json:"role_arn,omitempty"`
	RoleName         string            `json:"role_name,omitempty"`
	RoleKind         string            `json:"role_kind,omitempty"`
	RoleAccountID    string            `json:"role_account_id,omitempty"`
	WorkloadARN      string            `json:"workload_arn,omitempty"`
	ResourceARN      string            `json:"resource_arn,omitempty"`
	ResourceType     string            `json:"resource_type,omitempty"`
	ResourceStatus   string            `json:"resource_status,omitempty"`
	DomainID         string            `json:"domain_id,omitempty"`
	DomainARN        string            `json:"domain_arn,omitempty"`
	UserProfile      string            `json:"user_profile,omitempty"`
	SpaceName        string            `json:"space_name,omitempty"`
	PipelineARN      string            `json:"pipeline_arn,omitempty"`
	ModelARN         string            `json:"model_arn,omitempty"`
	EndpointConfig   string            `json:"endpoint_config,omitempty"`
	NetworkMode      string            `json:"network_mode,omitempty"`
	ImageURIs        []string          `json:"image_uris,omitempty"`
	S3References     []string          `json:"s3_references,omitempty"`
	KMSKeyARNs       []string          `json:"kms_key_arns,omitempty"`
	CoverageStatus   string            `json:"coverage_status"`
	CoverageReason   string            `json:"coverage_reason,omitempty"`
	Active           bool              `json:"active"`
	Disabled         bool              `json:"disabled"`
	Tags             map[string]string `json:"tags,omitempty"`
	Source           string            `json:"source"`
	EvidenceRef      string            `json:"evidence_ref"`
	FromNodeID       string            `json:"from_node_id"`
	ToNodeID         string            `json:"to_node_id,omitempty"`
	RelationshipType string            `json:"relationship_type"`
	Confidence       float64           `json:"confidence"`
	CollectedAt      time.Time         `json:"collected_at"`
	Status           string            `json:"status"`
}

// AWSSageMakerWorkloadRoleRelationship is a single graph edge produced by the
// SageMaker collector, mapping a workload node to the IAM identity it runs as
// or is attached to.
type AWSSageMakerWorkloadRoleRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSSageMakerWorkloadRoleDiagnostic is a structured collector diagnostic with
// an operator-facing remediation hint.
type AWSSageMakerWorkloadRoleDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSSageMakerWorkloadRoleInventory returns the SageMaker workload role
// inventory for the supplied scope, honoring connector status and the
// optional fixture_state override.
func (s *Service) GetAWSSageMakerWorkloadRoleInventory(ctx context.Context, workspaceID string, projectID string, request AWSSageMakerWorkloadRoleInventoryRequest) (AWSSageMakerWorkloadRoleInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSSageMakerWorkloadRoleInventoryResult{}, err
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
		return AWSSageMakerWorkloadRoleInventoryResult{}, err
	}
	return buildAWSSageMakerWorkloadRoleInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSSageMakerWorkloadRoleInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSSageMakerWorkloadRoleInventoryRequest, checkedAt time.Time) (AWSSageMakerWorkloadRoleInventoryResult, error) {
	fixtureState := normalizeAWSSageMakerWorkloadRoleFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSSageMakerWorkloadRoleInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsSageMakerWorkloadRoleFixtureRecords(accountID, region, fixtureState, checkedAt)
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
			ScanID:        "aws-sagemaker-workload-role-fixture",
			CollectorName: "sagemaker_workload_role",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSSageMakerWorkloadRoleInventoryResult{}, fmt.Errorf("validate sagemaker workload role contract record: %w", err)
		}
	}
	status, confidence, failures, remediations := summarizeAWSSageMakerWorkloadRoleInventory(fixtureState, diagnostics)
	relationships := awsSageMakerWorkloadRoleRelationships(records)
	return AWSSageMakerWorkloadRoleInventoryResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsSageMakerWorkloadRoleCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsSageMakerWorkloadRoleCurrentIssue),
		Version:            awsSageMakerWorkloadRoleVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		RecordCount:        len(records),
		WorkloadTypeCount:  awsSageMakerWorkloadRoleWorkloadTypeCount(records),
		NotebookCount:      awsSageMakerWorkloadRoleTypeRecordCount(records, "sagemaker_notebook_instance"),
		TrainingJobCount:   awsSageMakerWorkloadRoleTypeRecordCount(records, "sagemaker_training_job"),
		ProcessingJobCount: awsSageMakerWorkloadRoleTypeRecordCount(records, "sagemaker_processing_job"),
		TransformJobCount:  awsSageMakerWorkloadRoleTypeRecordCount(records, "sagemaker_transform_job"),
		ModelCount:         awsSageMakerWorkloadRoleTypeRecordCount(records, "sagemaker_model"),
		EndpointCount:      awsSageMakerWorkloadRoleTypeRecordCount(records, "sagemaker_endpoint"),
		PipelineCount:      awsSageMakerWorkloadRoleTypeRecordCount(records, "sagemaker_pipeline"),
		DomainCount:        awsSageMakerWorkloadRoleTypeRecordCount(records, "sagemaker_domain"),
		S3ReferenceCount:   awsSageMakerWorkloadRoleEvidenceCount(records, func(r AWSSageMakerWorkloadRoleRecord) []string { return r.S3References }),
		ECRImageCount:      awsSageMakerWorkloadRoleEvidenceCount(records, func(r AWSSageMakerWorkloadRoleRecord) []string { return r.ImageURIs }),
		KMSKeyCount:        awsSageMakerWorkloadRoleEvidenceCount(records, func(r AWSSageMakerWorkloadRoleRecord) []string { return r.KMSKeyARNs }),
		IdentityCount:      awsSageMakerWorkloadRoleIdentityCount(records),
		ResourceCount:      awsSageMakerWorkloadRoleResourceCount(records),
		RelationshipCount:  len(relationships),
		FailureReasons:     failures,
		RemediationHints:   remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsSageMakerWorkloadRoleCurrentIssue),
			"/docs/aws-sagemaker-workload-roles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsSageMakerWorkloadRoleDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSSageMakerWorkloadRoleFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		// No explicit override — fall back to the connector state so an
		// unconnected connector surfaces a permission_denied preview.
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "empty", "degraded", "partial_failure", "permission_denied":
		// Explicit fixture_state values always win so operators can preview
		// every documented state regardless of the connector's current
		// health.
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsSageMakerWorkloadRoleFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSSageMakerWorkloadRoleRecord, []providers.SourceError, []AWSSageMakerCoverageGap) {
	gaps := []AWSSageMakerCoverageGap{{
		WorkloadType: "sagemaker_user_profile",
		Status:       "unsupported",
		Reason:       "SageMaker Studio user-profile execution roles need per-user describe traversal and are tracked as a coverage gap until a dedicated metadata-only collector is added.",
		Remediation:  "Keep user-profile coverage marked unsupported until the per-user collector ships; rely on the domain default execution role for blast-radius reasoning today.",
	}, {
		WorkloadType: "sagemaker_studio_space",
		Status:       "unsupported",
		Reason:       "SageMaker Studio shared spaces are not enumerated in this wave to keep the surface metadata-only and avoid reading notebook contents.",
		Remediation:  "Track shared-space role coverage in a follow-up issue; do not enable list/describe on shared-space notebooks here.",
	}}
	partition := awsSageMakerPartitionForRegion(region)
	ecrHost := awsSageMakerECRRegistryHost(accountID, region, partition)
	notebookARN := fmt.Sprintf("arn:%s:sagemaker:%s:%s:notebook-instance/payments-eval", partition, region, accountID)
	trainingARN := fmt.Sprintf("arn:%s:sagemaker:%s:%s:training-job/payments-train-2026", partition, region, accountID)
	processingARN := fmt.Sprintf("arn:%s:sagemaker:%s:%s:processing-job/payments-features-2026", partition, region, accountID)
	transformARN := fmt.Sprintf("arn:%s:sagemaker:%s:%s:transform-job/payments-score-2026", partition, region, accountID)
	modelARN := fmt.Sprintf("arn:%s:sagemaker:%s:%s:model/payments-risk-classifier", partition, region, accountID)
	endpointARN := fmt.Sprintf("arn:%s:sagemaker:%s:%s:endpoint/payments-risk-classifier", partition, region, accountID)
	pipelineARN := fmt.Sprintf("arn:%s:sagemaker:%s:%s:pipeline/payments-mlops", partition, region, accountID)
	domainARN := fmt.Sprintf("arn:%s:sagemaker:%s:%s:domain/d-payments", partition, region, accountID)
	records := []AWSSageMakerWorkloadRoleRecord{
		awsSageMakerWorkloadRoleFixtureRecord(accountID, region, "sagemaker_notebook_instance", "payments-eval", notebookARN, fmt.Sprintf("arn:%s:iam::%s:role/sagemaker-payments-notebook", partition, accountID), "sagemaker_notebook_execution_role", "InService", checkedAt, func(r *AWSSageMakerWorkloadRoleRecord) {
			r.KMSKeyARNs = []string{fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-notebook", partition, region, accountID)}
		}),
		awsSageMakerWorkloadRoleFixtureRecord(accountID, region, "sagemaker_training_job", "payments-train-2026", trainingARN, fmt.Sprintf("arn:%s:iam::%s:role/sagemaker-payments-training", partition, accountID), "sagemaker_training_execution_role", "InProgress", checkedAt, func(r *AWSSageMakerWorkloadRoleRecord) {
			r.ImageURIs = []string{ecrHost + "/payments-training:2026-04"}
			r.S3References = []string{fmt.Sprintf("s3://payments-feature-store/train/%s/", accountID), fmt.Sprintf("s3://payments-models/train-out/%s/", accountID)}
			r.KMSKeyARNs = []string{fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-train-out", partition, region, accountID), fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-train-volume", partition, region, accountID)}
			r.NetworkMode = "vpc"
		}),
		awsSageMakerWorkloadRoleFixtureRecord(accountID, region, "sagemaker_processing_job", "payments-features-2026", processingARN, fmt.Sprintf("arn:%s:iam::%s:role/sagemaker-payments-processing", partition, accountID), "sagemaker_processing_execution_role", "InProgress", checkedAt, func(r *AWSSageMakerWorkloadRoleRecord) {
			r.ImageURIs = []string{ecrHost + "/payments-features:2026-04"}
			r.S3References = []string{fmt.Sprintf("s3://payments-feature-store/raw/%s/", accountID), fmt.Sprintf("s3://payments-feature-store/processed/%s/", accountID)}
			r.KMSKeyARNs = []string{fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-features-volume", partition, region, accountID), fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-features-out", partition, region, accountID)}
		}),
		awsSageMakerWorkloadRoleFixtureRecord(accountID, region, "sagemaker_transform_job", "payments-score-2026", transformARN, fmt.Sprintf("arn:%s:iam::%s:role/sagemaker-payments-model", partition, accountID), "sagemaker_batch_transform_execution_role", "InProgress", checkedAt, func(r *AWSSageMakerWorkloadRoleRecord) {
			r.S3References = []string{fmt.Sprintf("s3://payments-feature-store/score/in/%s/", accountID), fmt.Sprintf("s3://payments-feature-store/score/out/%s/", accountID)}
			r.KMSKeyARNs = []string{fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-score-out", partition, region, accountID)}
			r.ModelARN = modelARN
		}),
		awsSageMakerWorkloadRoleFixtureRecord(accountID, region, "sagemaker_model", "payments-risk-classifier", modelARN, fmt.Sprintf("arn:%s:iam::%s:role/sagemaker-payments-model", partition, accountID), "sagemaker_model_execution_role", "InService", checkedAt, func(r *AWSSageMakerWorkloadRoleRecord) {
			r.ImageURIs = []string{ecrHost + "/payments-classifier:2026-04"}
			r.S3References = []string{"s3://payments-models/payments-risk-classifier/"}
			r.ModelARN = modelARN
			r.NetworkMode = "vpc"
		}),
		awsSageMakerWorkloadRoleFixtureRecord(accountID, region, "sagemaker_endpoint", "payments-risk-classifier", endpointARN, fmt.Sprintf("arn:%s:iam::%s:role/sagemaker-payments-model", partition, accountID), "sagemaker_endpoint_execution_role", "InService", checkedAt, func(r *AWSSageMakerWorkloadRoleRecord) {
			r.EndpointConfig = "payments-risk-classifier-config"
			r.ModelARN = modelARN
			r.KMSKeyARNs = []string{fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-endpoint", partition, region, accountID)}
		}),
		awsSageMakerWorkloadRoleFixtureRecord(accountID, region, "sagemaker_pipeline", "payments-mlops", pipelineARN, fmt.Sprintf("arn:%s:iam::%s:role/sagemaker-payments-pipeline", partition, accountID), "sagemaker_pipeline_execution_role", "Active", checkedAt, func(r *AWSSageMakerWorkloadRoleRecord) {
			r.PipelineARN = pipelineARN
		}),
		awsSageMakerWorkloadRoleFixtureRecord(accountID, region, "sagemaker_domain", "d-payments", domainARN, fmt.Sprintf("arn:%s:iam::%s:role/sagemaker-payments-domain-default", partition, accountID), "sagemaker_domain_execution_role", "InService", checkedAt, func(r *AWSSageMakerWorkloadRoleRecord) {
			r.DomainID = "d-payments"
			r.DomainARN = domainARN
			r.KMSKeyARNs = []string{fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-domain", partition, region, accountID)}
		}),
	}
	switch fixtureState {
	case "empty":
		return nil, nil, gaps
	case "degraded":
		// Mark the notebook by workload type instead of by index so a future
		// fixture reorder cannot silently flip the wrong workload to the
		// stopped/disabled state.
		for i := range records {
			if records[i].WorkloadType != "sagemaker_notebook_instance" {
				continue
			}
			records[i].Status = "stopped"
			records[i].Active = false
			records[i].Disabled = true
			records[i].Confidence = 0.72
			records[i].ResourceStatus = "Stopped"
			break
		}
		return records, []providers.SourceError{{
			Collector: "aws_sagemaker/sagemaker_workload_role",
			SourceID:  notebookARN,
			Code:      "sagemaker_workload_disabled",
			Message:   "One SageMaker notebook is stopped; its execution role is retained for blast-radius reasoning",
			Retryable: false,
		}}, gaps
	case "partial_failure":
		// The seeded records are ordered notebook, training, processing,
		// transform, model, endpoint, pipeline, domain. Only the pipeline
		// listing fails in this fixture, so drop just that record and keep
		// the domain (and every other workload type) visible.
		surviving := append(append([]AWSSageMakerWorkloadRoleRecord{}, records[:6]...), records[7:]...)
		return surviving, []providers.SourceError{{
			Collector: "aws_sagemaker/sagemaker_workload_role",
			SourceID:  fmt.Sprintf("service=sagemaker|account=%s|region=%s|source=listpipelines", accountID, region),
			Code:      "sagemaker_pipelines_failed",
			Message:   "SageMaker pipelines could not be listed; notebook, training, processing, transform, model, endpoint, and domain role evidence remains visible",
			Retryable: true,
		}}, gaps
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_sagemaker/sagemaker_workload_role",
			SourceID:  fmt.Sprintf("service=sagemaker|account=%s|region=%s|source=list", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only SageMaker metadata permission is missing",
			Retryable: false,
		}}, gaps
	default:
		return records, nil, gaps
	}
}

func awsSageMakerWorkloadRoleFixtureRecord(accountID string, region string, workloadType string, workloadName string, workloadARN string, roleARN string, roleKind string, resourceStatus string, checkedAt time.Time, mutate func(*AWSSageMakerWorkloadRoleRecord)) AWSSageMakerWorkloadRoleRecord {
	record := AWSSageMakerWorkloadRoleRecord{
		AccountID:        accountID,
		Region:           region,
		Service:          "sagemaker",
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
		CoverageStatus:   "covered",
		Active:           !strings.EqualFold(resourceStatus, "Stopped") && !strings.EqualFold(resourceStatus, "Failed") && !strings.EqualFold(resourceStatus, "Deleting"),
		Disabled:         strings.EqualFold(resourceStatus, "Stopped"),
		Tags:             map[string]string{"owner": "ml-platform", "service": "sagemaker"},
		Source:           "sagemaker_metadata",
		EvidenceRef:      workloadARN,
		FromNodeID:       awsSageMakerNodeID(accountID, region, workloadType, workloadARN, roleKind),
		ToNodeID:         awsIdentityNodeIDForAPI(roleARN),
		RelationshipType: awsSageMakerWorkloadRoleRelationshipType(roleKind),
		Confidence:       0.93,
		CollectedAt:      checkedAt,
		Status:           "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	return record
}

func awsSageMakerWorkloadRoleRelationshipType(roleKind string) string {
	normalized := strings.ToLower(strings.TrimSpace(roleKind))
	switch {
	case strings.Contains(normalized, "endpoint_execution_role"), strings.Contains(normalized, "batch_transform_execution_role"):
		return "attached_to"
	default:
		return "runs_as"
	}
}

func summarizeAWSSageMakerWorkloadRoleInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35,
			[]string{"sagemaker workload role collection is blocked by missing read-only permission"},
			[]string{"Grant metadata-only SageMaker read permissions (List/Describe on notebooks, training, processing, transform, models, endpoints, pipelines, domains); do not enable PresignedNotebook, payload, or model-data reads."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.7,
			[]string{"one or more sagemaker workloads are stopped or disabled"},
			[]string{"Keep the role evidence visible and confirm whether the role should remain attached before least-privilege decisions."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78,
			[]string{"one sagemaker sub-listing failed while successful workload role records remain visible"},
			[]string{"Retry the failed sagemaker metadata call without discarding successful role evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82,
				[]string{"sagemaker workload role collection returned diagnostics"},
				[]string{"Review diagnostics before treating sagemaker coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, nil
	}
}

func awsSageMakerWorkloadRoleRelationships(records []AWSSageMakerWorkloadRoleRecord) []AWSSageMakerWorkloadRoleRelationship {
	result := make([]AWSSageMakerWorkloadRoleRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		result = append(result, AWSSageMakerWorkloadRoleRelationship{
			Type:        record.RelationshipType,
			FromNodeID:  record.FromNodeID,
			ToNodeID:    record.ToNodeID,
			EvidenceRef: record.EvidenceRef,
		})
	}
	return result
}

func awsSageMakerWorkloadRoleTypeRecordCount(records []AWSSageMakerWorkloadRoleRecord, workloadType string) int {
	count := 0
	for _, record := range records {
		if record.WorkloadType == workloadType {
			count++
		}
	}
	return count
}

func awsSageMakerWorkloadRoleWorkloadTypeCount(records []AWSSageMakerWorkloadRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.WorkloadType) != "" {
			seen[record.WorkloadType] = struct{}{}
		}
	}
	return len(seen)
}

func awsSageMakerWorkloadRoleEvidenceCount(records []AWSSageMakerWorkloadRoleRecord, accessor func(AWSSageMakerWorkloadRoleRecord) []string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, value := range accessor(record) {
			trimmed := strings.TrimSpace(value)
			if trimmed != "" {
				seen[trimmed] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsSageMakerWorkloadRoleIdentityCount(records []AWSSageMakerWorkloadRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) != "" {
			seen[record.ToNodeID] = struct{}{}
		}
	}
	return len(seen)
}

func awsSageMakerWorkloadRoleResourceCount(records []AWSSageMakerWorkloadRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ResourceARN) != "" {
			seen[record.ResourceARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsSageMakerWorkloadRoleDiagnostics(diagnostics []providers.SourceError) []AWSSageMakerWorkloadRoleDiagnostic {
	result := make([]AWSSageMakerWorkloadRoleDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSSageMakerWorkloadRoleDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsSageMakerWorkloadRoleDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsSageMakerWorkloadRoleDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only SageMaker read permissions (List/Describe on notebooks, training, processing, transform, models, endpoints, pipelines, domains); do not enable PresignedNotebook, payload, or model-data reads."
	case "sagemaker_workload_disabled":
		return "Keep the stopped workload visible and confirm whether the role should remain attached before least-privilege decisions."
	case "sagemaker_workload_role_page_failed",
		"sagemaker_notebooks_failed", "sagemaker_notebook_describe_failed",
		"sagemaker_training_jobs_failed", "sagemaker_training_job_describe_failed",
		"sagemaker_processing_jobs_failed", "sagemaker_processing_job_describe_failed",
		"sagemaker_transform_jobs_failed", "sagemaker_transform_job_describe_failed",
		"sagemaker_models_failed", "sagemaker_model_describe_failed",
		"sagemaker_endpoints_failed", "sagemaker_endpoint_describe_failed",
		"sagemaker_pipelines_failed", "sagemaker_pipeline_describe_failed",
		"sagemaker_domains_failed", "sagemaker_domain_describe_failed":
		return "Retry only the failed SageMaker metadata call and keep successful role records visible."
	case "missing_sagemaker_role":
		return "Inspect the SageMaker workload role configuration before using it for least-privilege reasoning."
	default:
		return "Review the SageMaker collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsSageMakerNodeID(accountID string, region string, workloadType string, workloadRef string, roleKind string) string {
	return fmt.Sprintf("aws:workload:sagemaker:%s:%s:%s/%s/%s",
		firstNonEmptyAWSValue(accountID, "account"),
		firstNonEmptyAWSValue(region, "region"),
		firstNonEmptyAWSValue(workloadType, "workload"),
		firstNonEmptyAWSValue(workloadRef, "sagemaker"),
		firstNonEmptyAWSValue(roleKind, "role"),
	)
}

// awsSageMakerPartitionForRegion returns the ARN partition (aws,
// aws-us-gov, aws-cn) for the supplied AWS region so synthesized fixture
// ARNs match the partition the operator's connector points at.
func awsSageMakerPartitionForRegion(region string) string {
	// Lower-case the input so mixed/upper-case region values still resolve to
	// the right partition (the AWS SDK accepts "US-GOV-WEST-1" but the
	// partition mapping is case-sensitive).
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

// awsSageMakerECRRegistryHost returns the public ECR registry host for the
// supplied region. China uses the .com.cn suffix while every other partition
// uses .amazonaws.com.
func awsSageMakerECRRegistryHost(accountID string, region string, partition string) string {
	suffix := "amazonaws.com"
	if partition == "aws-cn" {
		suffix = "amazonaws.com.cn"
	}
	return fmt.Sprintf("%s.dkr.ecr.%s.%s", accountID, region, suffix)
}
