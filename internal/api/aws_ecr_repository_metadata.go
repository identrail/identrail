package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers"
)

const (
	awsECRRepositoryMetadataCurrentIssue = 1492
	awsECRRepositoryMetadataVersion      = "aws-ecr-repository-metadata-inventory-v1"
)

type AWSECRRepositoryMetadataInventoryRequest struct {
	ConnectorID    string `json:"connector_id,omitempty"`
	FixtureState   string `json:"fixture_state,omitempty"`
	RepositoryName string `json:"repository_name,omitempty"`
	Identity       string `json:"identity,omitempty"`
}

type AWSECRRepositoryCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSECRRepositoryMetadataInventoryResult struct {
	TenantID                    string                               `json:"tenant_id"`
	WorkspaceID                 string                               `json:"workspace_id"`
	ProjectID                   string                               `json:"project_id"`
	ConnectorID                 string                               `json:"connector_id,omitempty"`
	AccountID                   string                               `json:"account_id,omitempty"`
	Region                      string                               `json:"region,omitempty"`
	ParentIssueNumber           int                                  `json:"parent_issue_number"`
	ParentIssueRef              string                               `json:"parent_issue_ref"`
	CurrentIssueNumber          int                                  `json:"current_issue_number"`
	CurrentIssueRef             string                               `json:"current_issue_ref"`
	Version                     string                               `json:"version"`
	Status                      string                               `json:"status"`
	FixtureState                string                               `json:"fixture_state"`
	Confidence                  float64                              `json:"confidence"`
	RepositoryCount             int                                  `json:"repository_count"`
	ReferencedRepositoryCount   int                                  `json:"referenced_repository_count"`
	UnreferencedRepositoryCount int                                  `json:"unreferenced_repository_count"`
	MutableRepositoryCount      int                                  `json:"mutable_repository_count"`
	UnscannedRepositoryCount    int                                  `json:"unscanned_repository_count"`
	RepositoryPolicyCount       int                                  `json:"repository_policy_count"`
	LifecyclePolicyCount        int                                  `json:"lifecycle_policy_count"`
	RelationshipCount           int                                  `json:"relationship_count"`
	UnresolvedReferenceCount    int                                  `json:"unresolved_reference_count"`
	FailureReasons              []string                             `json:"failure_reasons"`
	RemediationHints            []string                             `json:"remediation_hints"`
	EvidenceLinks               []string                             `json:"evidence_links"`
	CoverageGaps                []AWSECRRepositoryCoverageGap        `json:"coverage_gaps"`
	Records                     []AWSECRRepositoryMetadataRecord     `json:"records"`
	Relationships               []AWSECRRepositoryReferenceEdge      `json:"relationships"`
	Diagnostics                 []AWSECRRepositoryMetadataDiagnostic `json:"diagnostics"`
	GeneratedAt                 time.Time                            `json:"generated_at"`
	UpdatedAt                   time.Time                            `json:"updated_at"`
}

type AWSECRRepositoryMetadataRecord struct {
	AccountID                  string                         `json:"account_id"`
	Region                     string                         `json:"region"`
	Service                    string                         `json:"service"`
	RepositoryARN              string                         `json:"repository_arn"`
	RepositoryName             string                         `json:"repository_name"`
	RegistryID                 string                         `json:"registry_id,omitempty"`
	RepositoryURI              string                         `json:"repository_uri"`
	ImageTagMutability         string                         `json:"image_tag_mutability"`
	EncryptionType             string                         `json:"encryption_type,omitempty"`
	KMSKeyID                   string                         `json:"kms_key_id,omitempty"`
	ScanOnPush                 bool                           `json:"scan_on_push"`
	EnhancedScanningKnown      bool                           `json:"enhanced_scanning_known"`
	EnhancedScanningEnabled    bool                           `json:"enhanced_scanning_enabled"`
	HasRepositoryPolicy        bool                           `json:"has_repository_policy"`
	RepositoryPolicyStatements int                            `json:"repository_policy_statement_count"`
	HasLifecyclePolicy         bool                           `json:"has_lifecycle_policy"`
	LifecycleRuleCount         int                            `json:"lifecycle_rule_count"`
	ImageCount                 int                            `json:"image_count"`
	TaggedImageCount           int                            `json:"tagged_image_count"`
	UntaggedImageCount         int                            `json:"untagged_image_count"`
	LastPushedAt               string                         `json:"last_pushed_at,omitempty"`
	CreatedAt                  string                         `json:"created_at,omitempty"`
	Tags                       map[string]string              `json:"tags,omitempty"`
	SensitivityClassification  string                         `json:"sensitivity_classification"`
	ExposureClassification     string                         `json:"exposure_classification"`
	ExposureReasons            []string                       `json:"exposure_reasons,omitempty"`
	ReferencedBy               []AWSECRImageWorkloadReference `json:"referenced_by,omitempty"`
	UnresolvedReferences       []AWSECRImageWorkloadReference `json:"unresolved_references,omitempty"`
	Source                     string                         `json:"source"`
	EvidenceRef                string                         `json:"evidence_ref"`
	FromNodeID                 string                         `json:"from_node_id"`
	RelationshipType           string                         `json:"relationship_type"`
	Confidence                 float64                        `json:"confidence"`
	CollectedAt                time.Time                      `json:"collected_at"`
	Status                     string                         `json:"status"`
}

type AWSECRImageWorkloadReference struct {
	SourceService string  `json:"source_service,omitempty"`
	WorkloadID    string  `json:"workload_id,omitempty"`
	WorkloadType  string  `json:"workload_type,omitempty"`
	WorkloadName  string  `json:"workload_name,omitempty"`
	ResourceARN   string  `json:"resource_arn,omitempty"`
	ResourceID    string  `json:"resource_id,omitempty"`
	ImageURI      string  `json:"image_uri"`
	ReferenceKind string  `json:"reference_kind"`
	Confidence    float64 `json:"confidence"`
}

type AWSECRRepositoryReferenceEdge struct {
	Type        string  `json:"type"`
	FromNodeID  string  `json:"from_node_id"`
	ToNodeID    string  `json:"to_node_id"`
	EvidenceRef string  `json:"evidence_ref"`
	Source      string  `json:"source"`
	Confidence  float64 `json:"confidence"`
}

type AWSECRRepositoryMetadataDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSECRRepositoryMetadataInventory(ctx context.Context, workspaceID string, projectID string, request AWSECRRepositoryMetadataInventoryRequest) (AWSECRRepositoryMetadataInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSECRRepositoryMetadataInventoryResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSECRRepositoryMetadataInventoryResult{}, err
	}
	return buildAWSECRRepositoryMetadataInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSECRRepositoryMetadataInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSECRRepositoryMetadataInventoryRequest, checkedAt time.Time) (AWSECRRepositoryMetadataInventoryResult, error) {
	fixtureState := normalizeAWSECRRepositoryMetadataFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSECRRepositoryMetadataInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsECRRepositoryMetadataFixtureRecords(accountID, region, fixtureState, checkedAt)
	records = filterAWSECRRepositoryRecords(records, strings.TrimSpace(request.RepositoryName), strings.TrimSpace(request.Identity))
	status, confidence, failures, remediations := summarizeAWSECRRepositoryMetadataInventory(fixtureState, diagnostics, records)
	relationships := awsECRRepositoryReferenceEdges(records)
	return AWSECRRepositoryMetadataInventoryResult{
		TenantID:                    scope.TenantID,
		WorkspaceID:                 project.WorkspaceID,
		ProjectID:                   project.ProjectID,
		ConnectorID:                 connectorID,
		AccountID:                   accountID,
		Region:                      region,
		ParentIssueNumber:           awsPlatformDependencyParentIssue,
		ParentIssueRef:              awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:          awsECRRepositoryMetadataCurrentIssue,
		CurrentIssueRef:             awsIssueRef(awsECRRepositoryMetadataCurrentIssue),
		Version:                     awsECRRepositoryMetadataVersion,
		Status:                      status,
		FixtureState:                fixtureState,
		Confidence:                  confidence,
		RepositoryCount:             len(records),
		ReferencedRepositoryCount:   countECRRepositories(records, func(r AWSECRRepositoryMetadataRecord) bool { return len(r.ReferencedBy) > 0 }),
		UnreferencedRepositoryCount: countECRRepositories(records, func(r AWSECRRepositoryMetadataRecord) bool { return len(r.ReferencedBy) == 0 }),
		MutableRepositoryCount:      countECRRepositories(records, func(r AWSECRRepositoryMetadataRecord) bool { return r.ImageTagMutability != "immutable" }),
		UnscannedRepositoryCount:    countECRRepositories(records, func(r AWSECRRepositoryMetadataRecord) bool { return !r.ScanOnPush && !r.EnhancedScanningEnabled }),
		RepositoryPolicyCount:       countECRRepositories(records, func(r AWSECRRepositoryMetadataRecord) bool { return r.HasRepositoryPolicy }),
		LifecyclePolicyCount:        countECRRepositories(records, func(r AWSECRRepositoryMetadataRecord) bool { return r.HasLifecyclePolicy }),
		RelationshipCount:           len(relationships),
		UnresolvedReferenceCount:    countECRRepositoryRefs(records, true),
		FailureReasons:              failures,
		RemediationHints:            remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsECRRepositoryMetadataCurrentIssue),
			"/docs/aws-ecr-repository-metadata",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsECRRepositoryMetadataDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSECRRepositoryMetadataFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func filterAWSECRRepositoryRecords(records []AWSECRRepositoryMetadataRecord, repositoryName string, identity string) []AWSECRRepositoryMetadataRecord {
	if repositoryName == "" && identity == "" {
		return records
	}
	repositoryName = strings.ToLower(repositoryName)
	identity = strings.ToLower(identity)
	filtered := make([]AWSECRRepositoryMetadataRecord, 0, len(records))
	for _, record := range records {
		if repositoryName != "" && !strings.Contains(strings.ToLower(strings.Join([]string{record.RepositoryName, record.RepositoryURI, record.RepositoryARN}, " ")), repositoryName) {
			continue
		}
		if identity != "" && !ecrRepositoryRecordMatchesIdentity(record, identity) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func ecrRepositoryRecordMatchesIdentity(record AWSECRRepositoryMetadataRecord, identity string) bool {
	for _, refs := range [][]AWSECRImageWorkloadReference{record.ReferencedBy, record.UnresolvedReferences} {
		for _, ref := range refs {
			haystack := strings.ToLower(strings.Join([]string{ref.SourceService, ref.WorkloadID, ref.WorkloadName, ref.ResourceARN, ref.ResourceID, ref.ImageURI}, " "))
			if strings.Contains(haystack, identity) {
				return true
			}
		}
	}
	return false
}

func awsECRRepositoryMetadataFixtureRecords(accountID, region, fixtureState string, checkedAt time.Time) ([]AWSECRRepositoryMetadataRecord, []providers.SourceError, []AWSECRRepositoryCoverageGap) {
	gaps := []AWSECRRepositoryCoverageGap{{
		Capability:  "image_payload_collection",
		Status:      "unsupported",
		Reason:      "This collector never calls BatchGetImage, GetDownloadUrlForLayer, or image manifest APIs and never stores image layers, manifests, SBOMs, or payloads.",
		Remediation: "Inspect image contents and SBOMs through existing container security tooling outside Identrail.",
	}, {
		Capability:  "scan_finding_detail_collection",
		Status:      "unsupported",
		Reason:      "The inventory records scan configuration and summary counts only; it does not collect vulnerability finding detail payloads.",
		Remediation: "Use ECR or Inspector finding workflows for vulnerability detail review.",
	}}
	switch fixtureState {
	case "permission_denied":
		return nil, []providers.SourceError{{Collector: "ecr_repository_metadata", Code: "ecr_repository_metadata_page_failed", Message: "AccessDenied: missing ecr:DescribeRepositories", Retryable: false}}, gaps
	case "empty":
		return nil, nil, gaps
	}
	partition := awsSecretsManagerPartitionForRegion(region)
	paymentsARN := fmt.Sprintf("arn:%s:ecr:%s:%s:repository/payments/api", partition, region, accountID)
	jobsARN := fmt.Sprintf("arn:%s:ecr:%s:%s:repository/payments/jobs", partition, region, accountID)
	legacyARN := fmt.Sprintf("arn:%s:ecr:%s:%s:repository/legacy/exporter", partition, region, accountID)
	paymentsURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/payments/api", accountID, region)
	jobsURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/payments/jobs", accountID, region)
	legacyURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/legacy/exporter", accountID, region)
	records := []AWSECRRepositoryMetadataRecord{
		awsECRRepositoryMetadataFixtureRecord(accountID, region, "payments/api", paymentsARN, paymentsURI, checkedAt, func(r *AWSECRRepositoryMetadataRecord) {
			r.ImageTagMutability = "immutable"
			r.EncryptionType = "kms"
			r.KMSKeyID = "alias/payments-images"
			r.ScanOnPush = true
			r.EnhancedScanningKnown = true
			r.EnhancedScanningEnabled = true
			r.HasRepositoryPolicy = true
			r.RepositoryPolicyStatements = 2
			r.HasLifecyclePolicy = true
			r.LifecycleRuleCount = 2
			r.ImageCount = 24
			r.TaggedImageCount = 20
			r.UntaggedImageCount = 4
			r.ReferencedBy = []AWSECRImageWorkloadReference{{
				SourceService: "ecs",
				WorkloadID:    fmt.Sprintf("arn:%s:ecs:%s:%s:service/prod/payments", partition, region, accountID),
				WorkloadType:  "ecs_service",
				WorkloadName:  "payments",
				ResourceARN:   fmt.Sprintf("arn:%s:ecs:%s:%s:task-definition/payments:4", partition, region, accountID),
				ImageURI:      paymentsURI + ":prod",
				ReferenceKind: "container_image",
				Confidence:    0.94,
			}}
			r.SensitivityClassification = "runtime_image_repository"
			r.ExposureClassification = "referenced_policy_controlled"
			r.ExposureReasons = []string{"repository_policy_present", "referenced_by_workloads"}
			r.Confidence = 0.94
		}),
		awsECRRepositoryMetadataFixtureRecord(accountID, region, "payments/jobs", jobsARN, jobsURI, checkedAt, func(r *AWSECRRepositoryMetadataRecord) {
			r.ImageTagMutability = "mutable"
			r.ScanOnPush = false
			r.EnhancedScanningKnown = true
			r.EnhancedScanningEnabled = false
			r.ImageCount = 8
			r.TaggedImageCount = 8
			r.ReferencedBy = []AWSECRImageWorkloadReference{{
				SourceService: "codebuild",
				WorkloadID:    fmt.Sprintf("arn:%s:codebuild:%s:%s:project/payments-build", partition, region, accountID),
				WorkloadType:  "codebuild_project",
				WorkloadName:  "payments-build",
				ImageURI:      jobsURI + ":latest",
				ReferenceKind: "build_image",
				Confidence:    0.9,
			}}
			r.SensitivityClassification = "runtime_image_repository"
			r.ExposureClassification = "mutable_unscanned"
			r.ExposureReasons = []string{"mutable_tags", "scan_on_push_disabled", "referenced_by_workloads"}
			r.Confidence = 0.9
		}),
		awsECRRepositoryMetadataFixtureRecord(accountID, region, "legacy/exporter", legacyARN, legacyURI, checkedAt, func(r *AWSECRRepositoryMetadataRecord) {
			r.ImageTagMutability = "mutable"
			r.ScanOnPush = false
			r.UnresolvedReferences = []AWSECRImageWorkloadReference{{
				SourceService: "sagemaker",
				WorkloadName:  "legacy-export",
				ImageURI:      "legacy/exporter:prod",
				ReferenceKind: "container_image",
				Confidence:    0.7,
			}}
			r.ExposureClassification = "mutable_unscanned"
			r.ExposureReasons = []string{"mutable_tags", "scan_on_push_disabled"}
		}),
	}
	diagnostics := []providers.SourceError{}
	if fixtureState == "degraded" {
		records[0].Tags = nil
		records[0].Status = "degraded"
		records[0].ExposureReasons = append(records[0].ExposureReasons, "tag_metadata_unavailable")
		diagnostics = append(diagnostics, providers.SourceError{Collector: "ecr_repository_metadata", SourceID: paymentsARN, Code: "ecr_tags_failed", Message: "AccessDenied: ecr:ListTagsForResource", Retryable: true})
	}
	if fixtureState == "partial_failure" {
		records = records[:2]
		diagnostics = append(diagnostics, providers.SourceError{Collector: "ecr_repository_metadata", SourceID: legacyARN, Code: "ecr_repository_metadata_page_failed", Message: "ThrottlingException: DescribeRepositories page 2", Retryable: true})
	}
	return records, diagnostics, gaps
}

func awsECRRepositoryMetadataFixtureRecord(accountID, region, name, arn, uri string, checkedAt time.Time, mutate func(*AWSECRRepositoryMetadataRecord)) AWSECRRepositoryMetadataRecord {
	record := AWSECRRepositoryMetadataRecord{
		AccountID:                 accountID,
		Region:                    region,
		Service:                   "ecr",
		RepositoryARN:             arn,
		RepositoryName:            name,
		RegistryID:                accountID,
		RepositoryURI:             uri,
		ImageTagMutability:        "immutable",
		EncryptionType:            "aes256",
		ScanOnPush:                true,
		EnhancedScanningKnown:     true,
		EnhancedScanningEnabled:   false,
		ImageCount:                3,
		TaggedImageCount:          3,
		LastPushedAt:              "2026-06-10T12:00:00Z",
		CreatedAt:                 "2026-01-10T12:00:00Z",
		Tags:                      map[string]string{"owner": "payments"},
		SensitivityClassification: "image_repository",
		ExposureClassification:    "metadata_only",
		ExposureReasons:           []string{},
		Source:                    "ecr_repository_metadata",
		EvidenceRef:               arn,
		FromNodeID:                "aws:resource:ecr-repository:" + arn,
		RelationshipType:          "metadata",
		Confidence:                0.88,
		CollectedAt:               checkedAt,
		Status:                    "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	return record
}

func awsECRRepositoryReferenceEdges(records []AWSECRRepositoryMetadataRecord) []AWSECRRepositoryReferenceEdge {
	edges := []AWSECRRepositoryReferenceEdge{}
	for _, record := range records {
		toNode := "aws:resource:ecr-repository:" + record.RepositoryARN
		for _, ref := range record.ReferencedBy {
			fromNode := firstNonEmptyAWSValue(ref.WorkloadID, ref.ResourceID, ref.ResourceARN)
			if strings.TrimSpace(fromNode) == "" {
				continue
			}
			edges = append(edges, AWSECRRepositoryReferenceEdge{
				Type:        "uses_image",
				FromNodeID:  fromNode,
				ToNodeID:    toNode,
				EvidenceRef: ref.ImageURI,
				Source:      ref.SourceService,
				Confidence:  ref.Confidence,
			})
		}
	}
	return edges
}

func summarizeAWSECRRepositoryMetadataInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSECRRepositoryMetadataRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.3, []string{"ECR repository metadata collection is permission denied."}, []string{"Grant metadata-only ECR reads such as DescribeRepositories, DescribeImages, GetRepositoryPolicy, GetLifecyclePolicy, GetRegistryScanningConfiguration, and ListTagsForResource."}
	case "partial_failure", "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72, awsSecretsManagerSourceErrorMessages(diagnostics), []string{"Review diagnostics and rerun after metadata-only ECR permissions are available."}
	default:
		if len(records) == 0 {
			return awsPlatformDependencyStatusReady, 0.82, nil, []string{"No ECR repositories were found for this account, region, and filters."}
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, []string{"Use image references to prioritize mutable or unscanned repositories that feed runtime workloads."}
	}
}

func awsECRRepositoryMetadataDiagnostics(diagnostics []providers.SourceError) []AWSECRRepositoryMetadataDiagnostic {
	result := make([]AWSECRRepositoryMetadataDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSECRRepositoryMetadataDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: "Confirm metadata-only ECR IAM permissions; do not add BatchGetImage, GetDownloadUrlForLayer, image manifest, or scan finding detail actions for this collector.",
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func countECRRepositories(records []AWSECRRepositoryMetadataRecord, pred func(AWSECRRepositoryMetadataRecord) bool) int {
	count := 0
	for _, record := range records {
		if pred(record) {
			count++
		}
	}
	return count
}

func countECRRepositoryRefs(records []AWSECRRepositoryMetadataRecord, unresolved bool) int {
	count := 0
	for _, record := range records {
		refs := record.ReferencedBy
		if unresolved {
			refs = record.UnresolvedReferences
		}
		count += len(refs)
	}
	return count
}
