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
	awsSSMParameterMetadataCurrentIssue = 1491
	awsSSMParameterMetadataVersion      = "aws-ssm-parameter-metadata-inventory-v1"
)

type AWSSSMParameterMetadataInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	// ParameterType filters records to one canonical parameter type
	// (string, string_list, secure_string).
	ParameterType string `json:"parameter_type,omitempty"`
	// Identity filters records to those last modified by, or referenced
	// from, the supplied identity or workload identifier substring.
	Identity string `json:"identity,omitempty"`
}

type AWSSSMParameterCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSSSMParameterMetadataInventoryResult struct {
	TenantID                   string                              `json:"tenant_id"`
	WorkspaceID                string                              `json:"workspace_id"`
	ProjectID                  string                              `json:"project_id"`
	ConnectorID                string                              `json:"connector_id,omitempty"`
	AccountID                  string                              `json:"account_id,omitempty"`
	Region                     string                              `json:"region,omitempty"`
	ParentIssueNumber          int                                 `json:"parent_issue_number"`
	ParentIssueRef             string                              `json:"parent_issue_ref"`
	CurrentIssueNumber         int                                 `json:"current_issue_number"`
	CurrentIssueRef            string                              `json:"current_issue_ref"`
	Version                    string                              `json:"version"`
	Status                     string                              `json:"status"`
	FixtureState               string                              `json:"fixture_state"`
	Confidence                 float64                             `json:"confidence"`
	ParameterCount             int                                 `json:"parameter_count"`
	SecureStringCount          int                                 `json:"secure_string_count"`
	CustomerKMSCount           int                                 `json:"customer_kms_count"`
	ReferencedParameterCount   int                                 `json:"referenced_parameter_count"`
	UnreferencedParameterCount int                                 `json:"unreferenced_parameter_count"`
	PlainTextReferencedCount   int                                 `json:"plain_text_referenced_count"`
	ExpiringParameterCount     int                                 `json:"expiring_parameter_count"`
	AdvancedTierCount          int                                 `json:"advanced_tier_count"`
	RelationshipCount          int                                 `json:"relationship_count"`
	UnresolvedReferenceCount   int                                 `json:"unresolved_reference_count"`
	FailureReasons             []string                            `json:"failure_reasons"`
	RemediationHints           []string                            `json:"remediation_hints"`
	EvidenceLinks              []string                            `json:"evidence_links"`
	CoverageGaps               []AWSSSMParameterCoverageGap        `json:"coverage_gaps"`
	Records                    []AWSSSMParameterMetadataRecord     `json:"records"`
	Relationships              []AWSSSMParameterReferenceEdge      `json:"relationships"`
	Diagnostics                []AWSSSMParameterMetadataDiagnostic `json:"diagnostics"`
	GeneratedAt                time.Time                           `json:"generated_at"`
	UpdatedAt                  time.Time                           `json:"updated_at"`
}

type AWSSSMParameterMetadataRecord struct {
	AccountID                 string                             `json:"account_id"`
	Region                    string                             `json:"region"`
	Service                   string                             `json:"service"`
	ParameterARN              string                             `json:"parameter_arn"`
	ParameterName             string                             `json:"parameter_name"`
	ParameterPath             string                             `json:"parameter_path,omitempty"`
	PathDepth                 int                                `json:"path_depth,omitempty"`
	ParameterType             string                             `json:"parameter_type"`
	Tier                      string                             `json:"tier"`
	DataType                  string                             `json:"data_type,omitempty"`
	Version                   int64                              `json:"version,omitempty"`
	DescriptionPresent        bool                               `json:"description_present"`
	AllowedPatternPresent     bool                               `json:"allowed_pattern_present"`
	KMSKeyID                  string                             `json:"kms_key_id,omitempty"`
	KMSKeyARN                 string                             `json:"kms_key_arn,omitempty"`
	LastModifiedAt            string                             `json:"last_modified_at,omitempty"`
	LastModifiedBy            string                             `json:"last_modified_by,omitempty"`
	Policies                  []AWSSSMParameterPolicy            `json:"parameter_policies,omitempty"`
	Tags                      map[string]string                  `json:"tags,omitempty"`
	Sensitive                 bool                               `json:"sensitive"`
	SensitivityClassification string                             `json:"sensitivity_classification"`
	ExposureClassification    string                             `json:"exposure_classification"`
	ExposureReasons           []string                           `json:"exposure_reasons,omitempty"`
	ReferencedBy              []AWSSSMParameterWorkloadReference `json:"referenced_by,omitempty"`
	UnresolvedReferences      []AWSSSMParameterWorkloadReference `json:"unresolved_references,omitempty"`
	Source                    string                             `json:"source"`
	EvidenceRef               string                             `json:"evidence_ref"`
	FromNodeID                string                             `json:"from_node_id"`
	RelationshipType          string                             `json:"relationship_type"`
	Confidence                float64                            `json:"confidence"`
	CollectedAt               time.Time                          `json:"collected_at"`
	Status                    string                             `json:"status"`
}

type AWSSSMParameterPolicy struct {
	PolicyType   string `json:"policy_type,omitempty"`
	PolicyStatus string `json:"policy_status,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

type AWSSSMParameterWorkloadReference struct {
	SourceService string  `json:"source_service,omitempty"`
	WorkloadID    string  `json:"workload_id,omitempty"`
	WorkloadType  string  `json:"workload_type,omitempty"`
	WorkloadName  string  `json:"workload_name,omitempty"`
	ResourceARN   string  `json:"resource_arn,omitempty"`
	ResourceID    string  `json:"resource_id,omitempty"`
	Reference     string  `json:"reference"`
	ReferenceKind string  `json:"reference_kind"`
	Confidence    float64 `json:"confidence"`
}

type AWSSSMParameterReferenceEdge struct {
	Type        string  `json:"type"`
	FromNodeID  string  `json:"from_node_id"`
	ToNodeID    string  `json:"to_node_id"`
	EvidenceRef string  `json:"evidence_ref"`
	Source      string  `json:"source"`
	Confidence  float64 `json:"confidence"`
}

type AWSSSMParameterMetadataDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSSSMParameterMetadataInventory(ctx context.Context, workspaceID string, projectID string, request AWSSSMParameterMetadataInventoryRequest) (AWSSSMParameterMetadataInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSSSMParameterMetadataInventoryResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSSSMParameterMetadataInventoryResult{}, err
	}
	return buildAWSSSMParameterMetadataInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSSSMParameterMetadataInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSSSMParameterMetadataInventoryRequest, checkedAt time.Time) (AWSSSMParameterMetadataInventoryResult, error) {
	fixtureState := normalizeAWSSSMParameterMetadataFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSSSMParameterMetadataInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	parameterTypeFilter, ok := normalizeAWSSSMParameterTypeFilter(request.ParameterType)
	if !ok {
		return AWSSSMParameterMetadataInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsSSMParameterMetadataFixtureRecords(accountID, region, fixtureState, checkedAt)
	records = filterAWSSSMParameterRecords(records, parameterTypeFilter, strings.TrimSpace(request.Identity))
	status, confidence, failures, remediations := summarizeAWSSSMParameterMetadataInventory(fixtureState, diagnostics, records)
	relationships := awsSSMParameterReferenceEdges(records)
	return AWSSSMParameterMetadataInventoryResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsSSMParameterMetadataCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsSSMParameterMetadataCurrentIssue),
		Version:            awsSSMParameterMetadataVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		ParameterCount:     len(records),
		SecureStringCount: countSSMParameters(records, func(r AWSSSMParameterMetadataRecord) bool {
			return r.ParameterType == "secure_string"
		}),
		CustomerKMSCount: countSSMParameters(records, func(r AWSSSMParameterMetadataRecord) bool {
			return r.SensitivityClassification == "secure_string_customer_kms"
		}),
		ReferencedParameterCount: countSSMParameters(records, func(r AWSSSMParameterMetadataRecord) bool {
			return len(r.ReferencedBy) > 0
		}),
		UnreferencedParameterCount: countSSMParameters(records, func(r AWSSSMParameterMetadataRecord) bool {
			return len(r.ReferencedBy) == 0
		}),
		PlainTextReferencedCount: countSSMParameters(records, func(r AWSSSMParameterMetadataRecord) bool {
			return len(r.ReferencedBy) > 0 && r.ParameterType != "secure_string"
		}),
		ExpiringParameterCount: countSSMParameters(records, func(r AWSSSMParameterMetadataRecord) bool {
			for _, policy := range r.Policies {
				if strings.EqualFold(policy.PolicyType, "Expiration") {
					return true
				}
			}
			return false
		}),
		AdvancedTierCount: countSSMParameters(records, func(r AWSSSMParameterMetadataRecord) bool {
			return r.Tier == "advanced"
		}),
		RelationshipCount:        len(relationships),
		UnresolvedReferenceCount: countSSMParameterRefs(records, true),
		FailureReasons:           failures,
		RemediationHints:         remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsSSMParameterMetadataCurrentIssue),
			"/docs/aws-ssm-parameter-metadata",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsSSMParameterMetadataDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSSSMParameterMetadataFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func normalizeAWSSSMParameterTypeFilter(requested string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		return "", true
	case "string", "string_list", "secure_string":
		return strings.ToLower(strings.TrimSpace(requested)), true
	default:
		return "", false
	}
}

// filterAWSSSMParameterRecords applies the operator-facing record filters.
// Identity matches the last-modified principal or any referencing workload
// identifier, case-insensitively, by substring.
func filterAWSSSMParameterRecords(records []AWSSSMParameterMetadataRecord, parameterType string, identity string) []AWSSSMParameterMetadataRecord {
	if parameterType == "" && identity == "" {
		return records
	}
	identity = strings.ToLower(identity)
	filtered := make([]AWSSSMParameterMetadataRecord, 0, len(records))
	for _, record := range records {
		if parameterType != "" && record.ParameterType != parameterType {
			continue
		}
		if identity != "" && !ssmParameterRecordMatchesIdentity(record, identity) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func ssmParameterRecordMatchesIdentity(record AWSSSMParameterMetadataRecord, identity string) bool {
	if strings.Contains(strings.ToLower(record.LastModifiedBy), identity) {
		return true
	}
	for _, refs := range [][]AWSSSMParameterWorkloadReference{record.ReferencedBy, record.UnresolvedReferences} {
		for _, ref := range refs {
			haystack := strings.ToLower(strings.Join([]string{ref.WorkloadID, ref.WorkloadName, ref.ResourceARN}, " "))
			if strings.Contains(haystack, identity) {
				return true
			}
		}
	}
	return false
}

func awsSSMParameterMetadataFixtureRecords(accountID, region, fixtureState string, checkedAt time.Time) ([]AWSSSMParameterMetadataRecord, []providers.SourceError, []AWSSSMParameterCoverageGap) {
	gaps := []AWSSSMParameterCoverageGap{{
		Capability:  "parameter_value_collection",
		Status:      "unsupported",
		Reason:      "This collector never calls GetParameter, GetParameters, GetParametersByPath, or GetParameterHistory and never stores parameter values.",
		Remediation: "Inspect parameter values through existing change-management tooling outside Identrail.",
	}, {
		Capability:  "ram_shared_parameter_visibility",
		Status:      "unsupported",
		Reason:      "Advanced-tier parameters shared through AWS RAM are not enumerated; only parameters owned by the connected account are inventoried.",
		Remediation: "Review AWS RAM resource shares directly for cross-account parameter sharing.",
	}}
	switch fixtureState {
	case "permission_denied":
		return nil, []providers.SourceError{{Collector: "ssm_parameter_metadata", Code: "ssm_parameter_metadata_page_failed", Message: "AccessDenied: missing ssm:DescribeParameters", Retryable: false}}, gaps
	case "empty":
		return nil, nil, gaps
	}
	partition := awsSecretsManagerPartitionForRegion(region)
	dbPasswordARN := fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/payments/db/password", partition, region, accountID)
	dbHostARN := fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/payments/db/host", partition, region, accountID)
	legacyTokenARN := fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/legacy/export-token", partition, region, accountID)
	records := []AWSSSMParameterMetadataRecord{
		awsSSMParameterMetadataFixtureRecord(accountID, region, "/payments/db/password", dbPasswordARN, checkedAt, func(r *AWSSSMParameterMetadataRecord) {
			r.ParameterPath = "/payments/db"
			r.PathDepth = 3
			r.ParameterType = "secure_string"
			r.Tier = "advanced"
			r.Sensitive = true
			r.SensitivityClassification = "secure_string_customer_kms"
			r.KMSKeyID = "alias/payments-parameters"
			r.KMSKeyARN = fmt.Sprintf("arn:%s:kms:%s:%s:alias/payments-parameters", partition, region, accountID)
			r.LastModifiedBy = fmt.Sprintf("arn:%s:iam::%s:role/payments-deployer", partition, accountID)
			r.ReferencedBy = []AWSSSMParameterWorkloadReference{{
				SourceService: "ecs",
				WorkloadID:    fmt.Sprintf("arn:%s:ecs:%s:%s:service/prod/payments", partition, region, accountID),
				WorkloadType:  "ecs_service",
				WorkloadName:  "payments",
				ResourceARN:   fmt.Sprintf("arn:%s:ecs:%s:%s:task-definition/payments:4", partition, region, accountID),
				Reference:     "DATABASE_PASSWORD=" + dbPasswordARN,
				ReferenceKind: "arn",
				Confidence:    0.94,
			}}
			r.ExposureClassification = "referenced_by_workload"
			r.ExposureReasons = []string{"workload_references_parameter", "secure_string_kms_encrypted", "customer_kms_key_referenced"}
			r.Confidence = 0.9
		}),
		awsSSMParameterMetadataFixtureRecord(accountID, region, "/payments/db/host", dbHostARN, checkedAt, func(r *AWSSSMParameterMetadataRecord) {
			r.ParameterPath = "/payments/db"
			r.PathDepth = 3
			r.ParameterType = "string"
			r.SensitivityClassification = "plain_text"
			r.LastModifiedBy = fmt.Sprintf("arn:%s:iam::%s:role/payments-deployer", partition, accountID)
			r.ReferencedBy = []AWSSSMParameterWorkloadReference{{
				SourceService: "codebuild",
				WorkloadID:    fmt.Sprintf("arn:%s:codebuild:%s:%s:project/payments-build", partition, region, accountID),
				WorkloadType:  "codebuild_project",
				WorkloadName:  "payments-build",
				Reference:     "DB_HOST=PARAMETER_STORE:/payments/db/host",
				ReferenceKind: "name",
				Confidence:    0.9,
			}}
			r.ExposureClassification = "referenced_by_workload"
			r.ExposureReasons = []string{"workload_references_parameter", "plain_text_parameter_referenced_as_secret"}
			r.Confidence = 0.9
		}),
		awsSSMParameterMetadataFixtureRecord(accountID, region, "/legacy/export-token", legacyTokenARN, checkedAt, func(r *AWSSSMParameterMetadataRecord) {
			r.ParameterPath = "/legacy"
			r.PathDepth = 2
			r.ParameterType = "secure_string"
			r.Sensitive = true
			r.SensitivityClassification = "secure_string_aws_managed_kms"
			r.KMSKeyID = "alias/aws/ssm"
			r.Policies = []AWSSSMParameterPolicy{{PolicyType: "Expiration", PolicyStatus: "pending", ExpiresAt: "2026-12-02T21:34:33Z"}}
			r.UnresolvedReferences = []AWSSSMParameterWorkloadReference{{
				SourceService: "codebuild",
				WorkloadName:  "legacy-export",
				Reference:     "EXPORT_TOKEN=PARAMETER_STORE:legacy-export-token",
				ReferenceKind: "name",
				Confidence:    0.72,
			}}
			r.ExposureClassification = "scheduled_expiration"
			r.ExposureReasons = []string{"secure_string_kms_encrypted", "expiration_policy_present"}
			r.Confidence = 0.87
		}),
	}
	diagnostics := []providers.SourceError{}
	if fixtureState == "degraded" {
		records[0].Tags = nil
		records[0].Status = "degraded"
		records[0].ExposureReasons = append(records[0].ExposureReasons, "tag_metadata_unavailable")
		diagnostics = append(diagnostics, providers.SourceError{Collector: "ssm_parameter_metadata", SourceID: dbPasswordARN, Code: "ssm_parameter_tags_failed", Message: "AccessDenied: ssm:ListTagsForResource", Retryable: true})
	}
	if fixtureState == "partial_failure" {
		records = records[:2]
		diagnostics = append(diagnostics, providers.SourceError{Collector: "ssm_parameter_metadata", SourceID: legacyTokenARN, Code: "ssm_parameter_metadata_page_failed", Message: "ThrottlingException: DescribeParameters page 2", Retryable: true})
	}
	return records, diagnostics, gaps
}

func awsSSMParameterMetadataFixtureRecord(accountID, region, name, arn string, checkedAt time.Time, mutate func(*AWSSSMParameterMetadataRecord)) AWSSSMParameterMetadataRecord {
	record := AWSSSMParameterMetadataRecord{
		AccountID:                 accountID,
		Region:                    region,
		Service:                   "ssm",
		ParameterARN:              arn,
		ParameterName:             name,
		ParameterType:             "string",
		Tier:                      "standard",
		DataType:                  "text",
		Version:                   3,
		DescriptionPresent:        true,
		AllowedPatternPresent:     false,
		LastModifiedAt:            "2026-06-08T12:00:00Z",
		Tags:                      map[string]string{"owner": "payments"},
		SensitivityClassification: "plain_text",
		ExposureClassification:    "private",
		ExposureReasons:           []string{},
		Source:                    "ssm_parameter_metadata",
		EvidenceRef:               arn,
		FromNodeID:                "aws:resource:ssm-parameter:" + arn,
		RelationshipType:          "metadata",
		Confidence:                0.85,
		CollectedAt:               checkedAt,
		Status:                    "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	return record
}

func awsSSMParameterReferenceEdges(records []AWSSSMParameterMetadataRecord) []AWSSSMParameterReferenceEdge {
	edges := []AWSSSMParameterReferenceEdge{}
	for _, record := range records {
		toNode := "aws:resource:ssm-parameter:" + record.ParameterARN
		for _, ref := range record.ReferencedBy {
			fromNode := firstNonEmptyAWSValue(ref.WorkloadID, ref.ResourceID, ref.ResourceARN)
			if strings.TrimSpace(fromNode) == "" {
				continue
			}
			edges = append(edges, AWSSSMParameterReferenceEdge{
				Type:        "uses_secret",
				FromNodeID:  fromNode,
				ToNodeID:    toNode,
				EvidenceRef: ref.Reference,
				Source:      ref.SourceService,
				Confidence:  ref.Confidence,
			})
		}
	}
	return edges
}

func summarizeAWSSSMParameterMetadataInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSSSMParameterMetadataRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.3, []string{"SSM parameter metadata collection is permission denied."}, []string{"Grant ssm:DescribeParameters and ssm:ListTagsForResource without any ssm:GetParameter* action."}
	case "partial_failure", "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72, awsSecretsManagerSourceErrorMessages(diagnostics), []string{"Review the diagnostics and rerun after metadata-only SSM permissions are available."}
	default:
		if len(records) == 0 {
			return awsPlatformDependencyStatusReady, 0.82, nil, []string{"No SSM parameters were found for this account, region, and filters."}
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, []string{"Use these references to prioritize SecureString hygiene and move plaintext credentials into SecureString or Secrets Manager."}
	}
}

func awsSSMParameterMetadataDiagnostics(diagnostics []providers.SourceError) []AWSSSMParameterMetadataDiagnostic {
	result := make([]AWSSSMParameterMetadataDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSSSMParameterMetadataDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: "Confirm metadata-only SSM IAM permissions; do not add GetParameter, GetParameters, GetParametersByPath, or GetParameterHistory for this collector.",
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func countSSMParameters(records []AWSSSMParameterMetadataRecord, pred func(AWSSSMParameterMetadataRecord) bool) int {
	count := 0
	for _, record := range records {
		if pred(record) {
			count++
		}
	}
	return count
}

func countSSMParameterRefs(records []AWSSSMParameterMetadataRecord, unresolved bool) int {
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
