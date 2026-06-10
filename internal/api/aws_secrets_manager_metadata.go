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
	awsSecretsManagerMetadataCurrentIssue = 1490
	awsSecretsManagerMetadataVersion      = "aws-secrets-manager-metadata-inventory-v1"
)

type AWSSecretsManagerMetadataInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

type AWSSecretsManagerCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSSecretsManagerMetadataInventoryResult struct {
	TenantID                 string                                `json:"tenant_id"`
	WorkspaceID              string                                `json:"workspace_id"`
	ProjectID                string                                `json:"project_id"`
	ConnectorID              string                                `json:"connector_id,omitempty"`
	AccountID                string                                `json:"account_id,omitempty"`
	Region                   string                                `json:"region,omitempty"`
	ParentIssueNumber        int                                   `json:"parent_issue_number"`
	ParentIssueRef           string                                `json:"parent_issue_ref"`
	CurrentIssueNumber       int                                   `json:"current_issue_number"`
	CurrentIssueRef          string                                `json:"current_issue_ref"`
	Version                  string                                `json:"version"`
	Status                   string                                `json:"status"`
	FixtureState             string                                `json:"fixture_state"`
	Confidence               float64                               `json:"confidence"`
	SecretCount              int                                   `json:"secret_count"`
	ReferencedSecretCount    int                                   `json:"referenced_secret_count"`
	UnreferencedSecretCount  int                                   `json:"unreferenced_secret_count"`
	RotationEnabledCount     int                                   `json:"rotation_enabled_count"`
	MissingRotationCount     int                                   `json:"missing_rotation_count"`
	ResourcePolicyCount      int                                   `json:"resource_policy_count"`
	PublicSecretCount        int                                   `json:"public_secret_count"`
	CrossAccountSecretCount  int                                   `json:"cross_account_secret_count"`
	KMSReferencedCount       int                                   `json:"kms_referenced_count"`
	RelationshipCount        int                                   `json:"relationship_count"`
	UnresolvedReferenceCount int                                   `json:"unresolved_reference_count"`
	FailureReasons           []string                              `json:"failure_reasons"`
	RemediationHints         []string                              `json:"remediation_hints"`
	EvidenceLinks            []string                              `json:"evidence_links"`
	CoverageGaps             []AWSSecretsManagerCoverageGap        `json:"coverage_gaps"`
	Records                  []AWSSecretsManagerMetadataRecord     `json:"records"`
	Relationships            []AWSSecretsManagerReferenceEdge      `json:"relationships"`
	Diagnostics              []AWSSecretsManagerMetadataDiagnostic `json:"diagnostics"`
	GeneratedAt              time.Time                             `json:"generated_at"`
	UpdatedAt                time.Time                             `json:"updated_at"`
}

type AWSSecretsManagerMetadataRecord struct {
	AccountID                    string                               `json:"account_id"`
	Region                       string                               `json:"region"`
	Service                      string                               `json:"service"`
	SecretARN                    string                               `json:"secret_arn"`
	SecretName                   string                               `json:"secret_name"`
	DescriptionPresent           bool                                 `json:"description_present"`
	KMSKeyID                     string                               `json:"kms_key_id,omitempty"`
	KMSKeyARN                    string                               `json:"kms_key_arn,omitempty"`
	OwningService                string                               `json:"owning_service,omitempty"`
	PrimaryRegion                string                               `json:"primary_region,omitempty"`
	SecretStatus                 string                               `json:"secret_status"`
	RotationEnabled              bool                                 `json:"rotation_enabled"`
	RotationLambdaARN            string                               `json:"rotation_lambda_arn,omitempty"`
	RotationInterval             int64                                `json:"rotation_interval_days,omitempty"`
	CreatedAt                    string                               `json:"created_at,omitempty"`
	LastChangedAt                string                               `json:"last_changed_at,omitempty"`
	LastAccessedAt               string                               `json:"last_accessed_at,omitempty"`
	LastRotatedAt                string                               `json:"last_rotated_at,omitempty"`
	DeletedAt                    string                               `json:"deleted_at,omitempty"`
	HasResourcePolicy            bool                                 `json:"has_resource_policy"`
	ResourcePolicyStatementCount int                                  `json:"resource_policy_statement_count"`
	IdentityGrants               []AWSSecretsManagerIdentityGrant     `json:"identity_grants,omitempty"`
	VersionStages                []AWSSecretsManagerVersionStage      `json:"version_stages,omitempty"`
	ReplicaRegions               []AWSSecretsManagerReplicaRegion     `json:"replica_regions,omitempty"`
	Tags                         map[string]string                    `json:"tags,omitempty"`
	ExposureClassification       string                               `json:"exposure_classification"`
	ExposureReasons              []string                             `json:"exposure_reasons,omitempty"`
	ReferencedBy                 []AWSSecretsManagerWorkloadReference `json:"referenced_by,omitempty"`
	UnresolvedReferences         []AWSSecretsManagerWorkloadReference `json:"unresolved_references,omitempty"`
	Source                       string                               `json:"source"`
	EvidenceRef                  string                               `json:"evidence_ref"`
	FromNodeID                   string                               `json:"from_node_id"`
	RelationshipType             string                               `json:"relationship_type"`
	Confidence                   float64                              `json:"confidence"`
	CollectedAt                  time.Time                            `json:"collected_at"`
	Status                       string                               `json:"status"`
}

type AWSSecretsManagerIdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"`
	Effect            string   `json:"effect"`
	Actions           []string `json:"actions,omitempty"`
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

type AWSSecretsManagerVersionStage struct {
	VersionID    string   `json:"version_id,omitempty"`
	Stages       []string `json:"stages,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	LastAccessed string   `json:"last_accessed_at,omitempty"`
	KMSKeyIDs    []string `json:"kms_key_ids,omitempty"`
}

type AWSSecretsManagerReplicaRegion struct {
	Region         string `json:"region,omitempty"`
	KMSKeyID       string `json:"kms_key_id,omitempty"`
	Status         string `json:"status,omitempty"`
	StatusMessage  string `json:"status_message,omitempty"`
	LastAccessedAt string `json:"last_accessed_at,omitempty"`
}

type AWSSecretsManagerWorkloadReference struct {
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

type AWSSecretsManagerReferenceEdge struct {
	Type        string  `json:"type"`
	FromNodeID  string  `json:"from_node_id"`
	ToNodeID    string  `json:"to_node_id"`
	EvidenceRef string  `json:"evidence_ref"`
	Source      string  `json:"source"`
	Confidence  float64 `json:"confidence"`
}

type AWSSecretsManagerMetadataDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSSecretsManagerMetadataInventory(ctx context.Context, workspaceID string, projectID string, request AWSSecretsManagerMetadataInventoryRequest) (AWSSecretsManagerMetadataInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSSecretsManagerMetadataInventoryResult{}, err
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
		return AWSSecretsManagerMetadataInventoryResult{}, err
	}
	return buildAWSSecretsManagerMetadataInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSSecretsManagerMetadataInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSSecretsManagerMetadataInventoryRequest, checkedAt time.Time) (AWSSecretsManagerMetadataInventoryResult, error) {
	fixtureState := normalizeAWSSecretsManagerMetadataFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSSecretsManagerMetadataInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsSecretsManagerMetadataFixtureRecords(accountID, region, fixtureState, checkedAt)
	status, confidence, failures, remediations := summarizeAWSSecretsManagerMetadataInventory(fixtureState, diagnostics, records)
	relationships := awsSecretsManagerReferenceEdges(records)
	return AWSSecretsManagerMetadataInventoryResult{
		TenantID:                scope.TenantID,
		WorkspaceID:             project.WorkspaceID,
		ProjectID:               project.ProjectID,
		ConnectorID:             connectorID,
		AccountID:               accountID,
		Region:                  region,
		ParentIssueNumber:       awsPlatformDependencyParentIssue,
		ParentIssueRef:          awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:      awsSecretsManagerMetadataCurrentIssue,
		CurrentIssueRef:         awsIssueRef(awsSecretsManagerMetadataCurrentIssue),
		Version:                 awsSecretsManagerMetadataVersion,
		Status:                  status,
		FixtureState:            fixtureState,
		Confidence:              confidence,
		SecretCount:             len(records),
		ReferencedSecretCount:   countSecrets(records, func(r AWSSecretsManagerMetadataRecord) bool { return len(r.ReferencedBy) > 0 }),
		UnreferencedSecretCount: countSecrets(records, func(r AWSSecretsManagerMetadataRecord) bool { return len(r.ReferencedBy) == 0 }),
		RotationEnabledCount:    countSecrets(records, func(r AWSSecretsManagerMetadataRecord) bool { return r.RotationEnabled }),
		MissingRotationCount:    countSecrets(records, func(r AWSSecretsManagerMetadataRecord) bool { return !r.RotationEnabled && r.SecretStatus == "active" }),
		ResourcePolicyCount:     countSecrets(records, func(r AWSSecretsManagerMetadataRecord) bool { return r.HasResourcePolicy }),
		PublicSecretCount:       countSecrets(records, func(r AWSSecretsManagerMetadataRecord) bool { return r.ExposureClassification == "public" }),
		CrossAccountSecretCount: countSecrets(records, func(r AWSSecretsManagerMetadataRecord) bool { return r.ExposureClassification == "cross_account" }),
		KMSReferencedCount: countSecrets(records, func(r AWSSecretsManagerMetadataRecord) bool {
			return strings.TrimSpace(r.KMSKeyARN) != "" || strings.TrimSpace(r.KMSKeyID) != ""
		}),
		RelationshipCount:        len(relationships),
		UnresolvedReferenceCount: countSecretRefs(records, func(r AWSSecretsManagerWorkloadReference) bool { return true }, true),
		FailureReasons:           failures,
		RemediationHints:         remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsSecretsManagerMetadataCurrentIssue),
			"/docs/aws-secrets-manager-metadata",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsSecretsManagerMetadataDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSSecretsManagerMetadataFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsSecretsManagerMetadataFixtureRecords(accountID, region, fixtureState string, checkedAt time.Time) ([]AWSSecretsManagerMetadataRecord, []providers.SourceError, []AWSSecretsManagerCoverageGap) {
	gaps := []AWSSecretsManagerCoverageGap{{
		Capability:  "secret_value_collection",
		Status:      "unsupported",
		Reason:      "This collector never calls GetSecretValue and never stores SecretString or SecretBinary.",
		Remediation: "Use existing secret-management rotation procedures for value inspection outside Identrail.",
	}, {
		Capability:  "parameter_store_value_collection",
		Status:      "unsupported",
		Reason:      "SSM Parameter Store metadata is tracked separately; this issue only models Secrets Manager metadata and references.",
		Remediation: "Treat SSM references as unresolved until the dedicated SSM metadata collector lands.",
	}}
	switch fixtureState {
	case "permission_denied":
		return nil, []providers.SourceError{{Collector: "secrets_manager_metadata", Code: "secrets_manager_metadata_page_failed", Message: "AccessDenied: missing secretsmanager:ListSecrets", Retryable: false}}, gaps
	case "empty":
		return nil, nil, gaps
	}
	partition := awsSecretsManagerPartitionForRegion(region)
	dbARN := fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:payments/db-AbCdEf", partition, region, accountID)
	apiARN := fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:shared/api-token-GhIjKl", partition, region, accountID)
	partnerARN := fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:partner/webhook-MnOpQr", partition, region, accountID)
	records := []AWSSecretsManagerMetadataRecord{
		awsSecretsManagerMetadataFixtureRecord(accountID, region, "payments/db", dbARN, checkedAt, func(r *AWSSecretsManagerMetadataRecord) {
			r.RotationEnabled = true
			r.RotationInterval = 30
			r.KMSKeyID = "alias/payments-secrets"
			r.KMSKeyARN = fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-secrets", partition, region, accountID)
			r.ReferencedBy = []AWSSecretsManagerWorkloadReference{{
				SourceService: "ecs",
				WorkloadID:    fmt.Sprintf("arn:%s:ecs:%s:%s:service/prod/payments", partition, region, accountID),
				WorkloadType:  "ecs_service",
				WorkloadName:  "payments",
				ResourceARN:   fmt.Sprintf("arn:%s:ecs:%s:%s:task-definition/payments:4", partition, region, accountID),
				Reference:     "DATABASE_PASSWORD=" + dbARN,
				ReferenceKind: "arn",
				Confidence:    0.94,
			}}
			r.ExposureClassification = "referenced_by_workload"
			r.ExposureReasons = []string{"workload_references_secret", "rotation_enabled", "customer_kms_key_referenced"}
		}),
		awsSecretsManagerMetadataFixtureRecord(accountID, region, "shared/api-token", apiARN, checkedAt, func(r *AWSSecretsManagerMetadataRecord) {
			r.HasResourcePolicy = true
			r.ResourcePolicyStatementCount = 1
			r.IdentityGrants = []AWSSecretsManagerIdentityGrant{{PrincipalARN: "*", PrincipalType: "*", Effect: "Allow", Actions: []string{"secretsmanager:DescribeSecret"}, IsPublic: true, WildcardPrincipal: true}}
			r.ExposureClassification = "public"
			r.ExposureReasons = []string{"resource_policy_allow_to_wildcard_principal"}
		}),
		awsSecretsManagerMetadataFixtureRecord(accountID, region, "partner/webhook", partnerARN, checkedAt, func(r *AWSSecretsManagerMetadataRecord) {
			r.HasResourcePolicy = true
			r.ResourcePolicyStatementCount = 1
			r.IdentityGrants = []AWSSecretsManagerIdentityGrant{{PrincipalARN: "arn:aws:iam::999999999999:role/partner-reader", PrincipalType: "aws", Effect: "Allow", Actions: []string{"secretsmanager:DescribeSecret"}, IsCrossAccount: true}}
			r.UnresolvedReferences = []AWSSecretsManagerWorkloadReference{{SourceService: "codebuild", WorkloadName: "partner-sync", Reference: "PARTNER_SECRET=partner/webhook", ReferenceKind: "name", Confidence: 0.72}}
			r.ExposureClassification = "cross_account"
			r.ExposureReasons = []string{"resource_policy_allow_to_cross_account_principal"}
		}),
	}
	diagnostics := []providers.SourceError{}
	if fixtureState == "degraded" {
		records[0].RotationEnabled = false
		records[0].Status = "degraded"
		records[0].ExposureReasons = append(records[0].ExposureReasons, "rotation_status_unavailable")
		diagnostics = append(diagnostics, providers.SourceError{Collector: "secrets_manager_metadata", SourceID: dbARN, Code: "secrets_manager_versions_failed", Message: "AccessDenied: ListSecretVersionIds", Retryable: true})
	}
	if fixtureState == "partial_failure" {
		records = records[:2]
		diagnostics = append(diagnostics, providers.SourceError{Collector: "secrets_manager_metadata", SourceID: partnerARN, Code: "secrets_manager_describe_secret_failed", Message: "AccessDenied: DescribeSecret", Retryable: true})
	}
	return records, diagnostics, gaps
}

func awsSecretsManagerMetadataFixtureRecord(accountID, region, name, arn string, checkedAt time.Time, mutate func(*AWSSecretsManagerMetadataRecord)) AWSSecretsManagerMetadataRecord {
	record := AWSSecretsManagerMetadataRecord{
		AccountID:              accountID,
		Region:                 region,
		Service:                "secretsmanager",
		SecretARN:              arn,
		SecretName:             name,
		DescriptionPresent:     true,
		SecretStatus:           "active",
		CreatedAt:              "2026-06-01T12:00:00Z",
		LastChangedAt:          "2026-06-08T12:00:00Z",
		LastAccessedAt:         "2026-06-09",
		VersionStages:          []AWSSecretsManagerVersionStage{{VersionID: "version-current", Stages: []string{"AWSCURRENT"}, CreatedAt: "2026-06-08T12:00:00Z"}},
		Tags:                   map[string]string{"owner": "payments"},
		ExposureClassification: "private",
		ExposureReasons:        []string{},
		Source:                 "secrets_manager_metadata",
		EvidenceRef:            arn,
		FromNodeID:             "aws:resource:secrets-manager-secret:" + arn,
		RelationshipType:       "metadata",
		Confidence:             0.86,
		CollectedAt:            checkedAt,
		Status:                 "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	return record
}

func awsSecretsManagerReferenceEdges(records []AWSSecretsManagerMetadataRecord) []AWSSecretsManagerReferenceEdge {
	edges := []AWSSecretsManagerReferenceEdge{}
	for _, record := range records {
		toNode := "aws:resource:secrets-manager-secret:" + record.SecretARN
		for _, ref := range record.ReferencedBy {
			fromNode := firstNonEmptyAWSValue(ref.WorkloadID, ref.ResourceID, ref.ResourceARN)
			if strings.TrimSpace(fromNode) == "" {
				continue
			}
			edges = append(edges, AWSSecretsManagerReferenceEdge{
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

func summarizeAWSSecretsManagerMetadataInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSSecretsManagerMetadataRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.3, []string{"Secrets Manager metadata collection is permission denied."}, []string{"Grant ListSecrets, DescribeSecret, GetResourcePolicy, and ListSecretVersionIds without GetSecretValue."}
	case "partial_failure", "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72, awsSecretsManagerSourceErrorMessages(diagnostics), []string{"Review the diagnostics and rerun after metadata-only Secrets Manager permissions are available."}
	default:
		if len(records) == 0 {
			return awsPlatformDependencyStatusReady, 0.82, nil, []string{"No Secrets Manager secrets were found for this account and region."}
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, []string{"Use these references to prioritize workload secret reachability and rotation follow-up."}
	}
}

func awsSecretsManagerMetadataDiagnostics(diagnostics []providers.SourceError) []AWSSecretsManagerMetadataDiagnostic {
	result := make([]AWSSecretsManagerMetadataDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSSecretsManagerMetadataDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: "Confirm metadata-only Secrets Manager IAM permissions; do not add GetSecretValue for this collector.",
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func countSecrets(records []AWSSecretsManagerMetadataRecord, pred func(AWSSecretsManagerMetadataRecord) bool) int {
	count := 0
	for _, record := range records {
		if pred(record) {
			count++
		}
	}
	return count
}

func countSecretRefs(records []AWSSecretsManagerMetadataRecord, pred func(AWSSecretsManagerWorkloadReference) bool, unresolved bool) int {
	count := 0
	for _, record := range records {
		refs := record.ReferencedBy
		if unresolved {
			refs = record.UnresolvedReferences
		}
		for _, ref := range refs {
			if pred(ref) {
				count++
			}
		}
	}
	return count
}

func awsSecretsManagerSourceErrorMessages(diagnostics []providers.SourceError) []string {
	messages := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if message := strings.TrimSpace(diagnostic.Message); message != "" {
			messages = append(messages, message)
		}
	}
	return dedupeStrings(messages)
}

func awsSecretsManagerPartitionForRegion(region string) string {
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
