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
	awsCodeBuildServiceRoleCurrentIssue = 1481
	awsCodeBuildServiceRoleVersion      = "aws-codebuild-service-role-inventory-v1"
)

// AWSCodeBuildServiceRoleInventoryRequest controls the deterministic inventory state.
type AWSCodeBuildServiceRoleInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSCodeBuildServiceRoleInventoryResult exposes scoped CodeBuild service-role evidence.
type AWSCodeBuildServiceRoleInventoryResult struct {
	TenantID               string                                `json:"tenant_id"`
	WorkspaceID            string                                `json:"workspace_id"`
	ProjectID              string                                `json:"project_id"`
	ConnectorID            string                                `json:"connector_id,omitempty"`
	AccountID              string                                `json:"account_id,omitempty"`
	Region                 string                                `json:"region,omitempty"`
	ParentIssueNumber      int                                   `json:"parent_issue_number"`
	ParentIssueRef         string                                `json:"parent_issue_ref"`
	CurrentIssueNumber     int                                   `json:"current_issue_number"`
	CurrentIssueRef        string                                `json:"current_issue_ref"`
	Version                string                                `json:"version"`
	Status                 string                                `json:"status"`
	FixtureState           string                                `json:"fixture_state"`
	Confidence             float64                               `json:"confidence"`
	RecordCount            int                                   `json:"record_count"`
	ProjectCount           int                                   `json:"project_count"`
	IdentityCount          int                                   `json:"identity_count"`
	ResourceCount          int                                   `json:"resource_count"`
	RelationshipCount      int                                   `json:"relationship_count"`
	SecretRefCount         int                                   `json:"secret_ref_count"`
	VPCProjectCount        int                                   `json:"vpc_project_count"`
	PublicProjectCount     int                                   `json:"public_project_count"`
	PrivilegedProjectCount int                                   `json:"privileged_project_count"`
	FailureReasons         []string                              `json:"failure_reasons"`
	RemediationHints       []string                              `json:"remediation_hints"`
	EvidenceLinks          []string                              `json:"evidence_links"`
	Records                []AWSCodeBuildServiceRoleRecord       `json:"records"`
	Relationships          []AWSCodeBuildServiceRoleRelationship `json:"relationships"`
	Diagnostics            []AWSCodeBuildServiceRoleDiagnostic   `json:"diagnostics"`
	GeneratedAt            time.Time                             `json:"generated_at"`
	UpdatedAt              time.Time                             `json:"updated_at"`
}

// AWSCodeBuildServiceRoleRecord is the operator-facing row for one CodeBuild project/role link.
type AWSCodeBuildServiceRoleRecord struct {
	AccountID                string            `json:"account_id"`
	Region                   string            `json:"region"`
	Service                  string            `json:"service"`
	WorkloadID               string            `json:"workload_id"`
	WorkloadType             string            `json:"workload_type"`
	WorkloadName             string            `json:"workload_name"`
	RoleARN                  string            `json:"role_arn,omitempty"`
	RoleName                 string            `json:"role_name,omitempty"`
	ProjectARN               string            `json:"project_arn,omitempty"`
	ProjectName              string            `json:"project_name,omitempty"`
	ProjectDescription       string            `json:"project_description,omitempty"`
	ProjectVisibility        string            `json:"project_visibility,omitempty"`
	SourceType               string            `json:"source_type,omitempty"`
	SourceLocation           string            `json:"source_location,omitempty"`
	SourceAuthType           string            `json:"source_auth_type,omitempty"`
	SourceVersion            string            `json:"source_version,omitempty"`
	SourceIdentifiers        []string          `json:"source_identifiers,omitempty"`
	ArtifactTypes            []string          `json:"artifact_types,omitempty"`
	ArtifactLocations        []string          `json:"artifact_locations,omitempty"`
	EnvironmentType          string            `json:"environment_type,omitempty"`
	ComputeType              string            `json:"compute_type,omitempty"`
	Image                    string            `json:"image,omitempty"`
	ImagePullCredentialsType string            `json:"image_pull_credentials_type,omitempty"`
	PrivilegedMode           bool              `json:"privileged_mode,omitempty"`
	KMSKeyARN                string            `json:"kms_key_arn,omitempty"`
	CacheType                string            `json:"cache_type,omitempty"`
	CacheLocation            string            `json:"cache_location,omitempty"`
	LogTypes                 []string          `json:"log_types,omitempty"`
	VPCID                    string            `json:"vpc_id,omitempty"`
	SubnetIDs                []string          `json:"subnet_ids,omitempty"`
	SecurityGroupIDs         []string          `json:"security_group_ids,omitempty"`
	EnvironmentKeys          []string          `json:"environment_keys,omitempty"`
	SecretRefs               []string          `json:"secret_refs,omitempty"`
	Tags                     map[string]string `json:"tags,omitempty"`
	Source                   string            `json:"source"`
	EvidenceRef              string            `json:"evidence_ref"`
	FromNodeID               string            `json:"from_node_id"`
	ToNodeID                 string            `json:"to_node_id,omitempty"`
	RelationshipType         string            `json:"relationship_type"`
	Confidence               float64           `json:"confidence"`
	CollectedAt              time.Time         `json:"collected_at"`
	Status                   string            `json:"status"`
}

// AWSCodeBuildServiceRoleRelationship is the graph evidence exposed by the API.
type AWSCodeBuildServiceRoleRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSCodeBuildServiceRoleDiagnostic is one explicit non-success state.
type AWSCodeBuildServiceRoleDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSCodeBuildServiceRoleInventory returns scoped deterministic CodeBuild service-role inventory.
func (s *Service) GetAWSCodeBuildServiceRoleInventory(ctx context.Context, workspaceID string, projectID string, request AWSCodeBuildServiceRoleInventoryRequest) (AWSCodeBuildServiceRoleInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSCodeBuildServiceRoleInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSCodeBuildServiceRoleInventoryResult{}, err
	}
	return buildAWSCodeBuildServiceRoleInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSCodeBuildServiceRoleInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSCodeBuildServiceRoleInventoryRequest, checkedAt time.Time) (AWSCodeBuildServiceRoleInventoryResult, error) {
	fixtureState := normalizeAWSCodeBuildServiceRoleFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSCodeBuildServiceRoleInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics := awsCodeBuildServiceRoleFixtureRecords(scope, project, connectorID, accountID, region, fixtureState, checkedAt)

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
			ScanID:        "aws-codebuild-service-role-fixture",
			CollectorName: "codebuild_service_role",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSCodeBuildServiceRoleInventoryResult{}, fmt.Errorf("validate codebuild service role contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSCodeBuildServiceRoleInventory(fixtureState, diagnostics)
	relationships := awsCodeBuildServiceRoleRelationships(records)
	result := AWSCodeBuildServiceRoleInventoryResult{
		TenantID:               scope.TenantID,
		WorkspaceID:            project.WorkspaceID,
		ProjectID:              project.ProjectID,
		ConnectorID:            connectorID,
		AccountID:              accountID,
		Region:                 region,
		ParentIssueNumber:      awsPlatformDependencyParentIssue,
		ParentIssueRef:         awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:     awsCodeBuildServiceRoleCurrentIssue,
		CurrentIssueRef:        awsIssueRef(awsCodeBuildServiceRoleCurrentIssue),
		Version:                awsCodeBuildServiceRoleVersion,
		Status:                 status,
		FixtureState:           fixtureState,
		Confidence:             confidence,
		RecordCount:            len(records),
		ProjectCount:           awsCodeBuildServiceRoleProjectCount(records),
		IdentityCount:          awsCodeBuildServiceRoleIdentityCount(records),
		ResourceCount:          awsCodeBuildServiceRoleResourceCount(records),
		RelationshipCount:      len(relationships),
		SecretRefCount:         awsCodeBuildServiceRoleSecretRefCount(records),
		VPCProjectCount:        awsCodeBuildServiceRoleVPCProjectCount(records),
		PublicProjectCount:     awsCodeBuildServiceRolePublicProjectCount(records),
		PrivilegedProjectCount: awsCodeBuildServiceRolePrivilegedProjectCount(records),
		FailureReasons:         failures,
		RemediationHints:       remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsCodeBuildServiceRoleCurrentIssue),
			"/docs/aws-codebuild-service-roles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsCodeBuildServiceRoleDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}
	return result, nil
}

func normalizeAWSCodeBuildServiceRoleFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsCodeBuildServiceRoleFixtureRecords(_ db.Scope, _ db.TenancyProject, _ string, accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSCodeBuildServiceRoleRecord, []providers.SourceError) {
	baseRecord := func(projectName string, roleARN string) AWSCodeBuildServiceRoleRecord {
		projectARN := fmt.Sprintf("arn:aws:codebuild:%s:%s:project/%s", region, accountID, projectName)
		status := "ready"
		if strings.TrimSpace(roleARN) == "" {
			status = "degraded"
		}
		return AWSCodeBuildServiceRoleRecord{
			AccountID:         accountID,
			Region:            region,
			Service:           "codebuild",
			WorkloadID:        projectARN,
			WorkloadType:      "codebuild_project",
			WorkloadName:      projectName,
			RoleARN:           roleARN,
			RoleName:          roleNameFromARNForAPI(roleARN),
			ProjectARN:        projectARN,
			ProjectName:       projectName,
			ProjectVisibility: "PRIVATE",
			Source:            "batchgetprojects",
			EvidenceRef:       projectARN,
			FromNodeID:        awsCodeBuildProjectNodeID(accountID, region, projectARN),
			ToNodeID:          awsIdentityNodeIDForAPI(roleARN),
			RelationshipType:  "runs_as",
			Confidence:        0.96,
			CollectedAt:       checkedAt,
			Status:            status,
		}
	}

	buildRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-codebuild-service", accountID)
	build := baseRecord("payments-build", buildRoleARN)
	build.ProjectDescription = "Builds the payments service"
	build.SourceType = "GITHUB"
	build.SourceLocation = "https://github.com/example/payments"
	build.SourceAuthType = "CODECONNECTIONS"
	build.SourceVersion = "main"
	build.SourceIdentifiers = []string{"GITHUB=https://github.com/example/payments"}
	build.ArtifactTypes = []string{"S3"}
	build.ArtifactLocations = []string{"payments-build-artifacts"}
	build.EnvironmentType = "LINUX_CONTAINER"
	build.ComputeType = "BUILD_GENERAL1_SMALL"
	build.Image = "aws/codebuild/standard:7.0"
	build.ImagePullCredentialsType = "CODEBUILD"
	build.KMSKeyARN = fmt.Sprintf("arn:aws:kms:%s:%s:key/codebuild-artifacts", region, accountID)
	build.CacheType = "LOCAL"
	build.LogTypes = []string{"cloudwatch"}
	build.VPCID = "vpc-prod"
	build.SubnetIDs = []string{"subnet-a", "subnet-b"}
	build.SecurityGroupIDs = []string{"sg-codebuild-payments"}
	build.EnvironmentKeys = []string{"APP_ENV", "DATABASE_PASSWORD", "NPM_TOKEN"}
	build.SecretRefs = []string{
		fmt.Sprintf("DATABASE_PASSWORD=SECRETS_MANAGER:arn:aws:secretsmanager:%s:%s:secret:codebuild/payments-db", region, accountID),
		"NPM_TOKEN=PARAMETER_STORE:/ci/npm/token",
	}
	build.Tags = map[string]string{"owner": "platform", "service": "payments"}
	build.Confidence = 0.94

	lintRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/frontend-codebuild-service", accountID)
	lint := baseRecord("frontend-lint", lintRoleARN)
	lint.SourceType = "CODEPIPELINE"
	lint.ArtifactTypes = []string{"CODEPIPELINE"}
	lint.EnvironmentType = "LINUX_CONTAINER"
	lint.ComputeType = "BUILD_GENERAL1_SMALL"
	lint.Image = "aws/codebuild/amazonlinux-x86_64-standard:5.0"
	lint.EnvironmentKeys = []string{"APP_ENV"}
	lint.LogTypes = []string{"cloudwatch"}
	lint.Tags = map[string]string{"owner": "web", "service": "frontend"}

	degraded := build
	degraded.ProjectVisibility = "PUBLIC_READ"
	degraded.PrivilegedMode = true
	degraded.Status = "degraded"
	degraded.Confidence = 0.88

	switch fixtureState {
	case "empty":
		return nil, nil
	case "degraded":
		return []AWSCodeBuildServiceRoleRecord{degraded}, []providers.SourceError{{
			Collector: "aws_codebuild/codebuild_service_role",
			SourceID:  degraded.ProjectARN,
			Code:      "privileged_or_public_project",
			Message:   "CodeBuild service-role evidence is visible, but the project is public or uses privileged builds",
			Retryable: false,
		}}
	case "partial_failure":
		return []AWSCodeBuildServiceRoleRecord{build}, []providers.SourceError{{
			Collector: "aws_codebuild/codebuild_service_role",
			SourceID:  fmt.Sprintf("service=codebuild|account=%s|region=%s|source=batchgetprojects", accountID, region),
			Code:      "project_batch_get_failed",
			Message:   "One CodeBuild project metadata batch could not be listed; successful service-role evidence remains visible",
			Retryable: true,
		}}
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_codebuild/codebuild_service_role",
			SourceID:  fmt.Sprintf("service=codebuild|account=%s|region=%s|source=listprojects", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only CodeBuild ListProjects or BatchGetProjects permission is missing",
			Retryable: false,
		}}
	default:
		return []AWSCodeBuildServiceRoleRecord{build, lint}, nil
	}
}

func summarizeAWSCodeBuildServiceRoleInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"codebuild service role collection is blocked by missing read-only permission"}, []string{"Grant codebuild:ListProjects and codebuild:BatchGetProjects for metadata-only collection."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.68, []string{"one or more CodeBuild projects are public or use privileged builds"}, []string{"Keep service-role evidence visible and review public/privileged project settings before treating blast radius as low."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.76, []string{"one CodeBuild metadata partition failed while successful project-role records remain visible"}, []string{"Retry the failed CodeBuild metadata call without discarding successful service-role evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.8, []string{"codebuild service role collection returned diagnostics"}, []string{"Review diagnostics before treating CodeBuild coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.97, nil, nil
	}
}

func awsCodeBuildServiceRoleRelationships(records []AWSCodeBuildServiceRoleRecord) []AWSCodeBuildServiceRoleRelationship {
	result := make([]AWSCodeBuildServiceRoleRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		result = append(result, AWSCodeBuildServiceRoleRelationship{
			Type:        "runs_as",
			FromNodeID:  record.FromNodeID,
			ToNodeID:    record.ToNodeID,
			EvidenceRef: record.EvidenceRef,
		})
	}
	return result
}

func awsCodeBuildServiceRoleProjectCount(records []AWSCodeBuildServiceRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) != "" {
			seen[record.FromNodeID] = struct{}{}
		}
	}
	return len(seen)
}

func awsCodeBuildServiceRoleIdentityCount(records []AWSCodeBuildServiceRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) != "" {
			seen[record.ToNodeID] = struct{}{}
		}
	}
	return len(seen)
}

func awsCodeBuildServiceRoleResourceCount(records []AWSCodeBuildServiceRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ProjectARN) != "" {
			seen[record.ProjectARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsCodeBuildServiceRoleSecretRefCount(records []AWSCodeBuildServiceRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, ref := range record.SecretRefs {
			if strings.TrimSpace(ref) != "" {
				seen[ref] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsCodeBuildServiceRoleVPCProjectCount(records []AWSCodeBuildServiceRoleRecord) int {
	count := 0
	for _, record := range records {
		if strings.TrimSpace(record.VPCID) != "" {
			count++
		}
	}
	return count
}

func awsCodeBuildServiceRolePublicProjectCount(records []AWSCodeBuildServiceRoleRecord) int {
	count := 0
	for _, record := range records {
		if strings.EqualFold(record.ProjectVisibility, "PUBLIC_READ") {
			count++
		}
	}
	return count
}

func awsCodeBuildServiceRolePrivilegedProjectCount(records []AWSCodeBuildServiceRoleRecord) int {
	count := 0
	for _, record := range records {
		if record.PrivilegedMode {
			count++
		}
	}
	return count
}

func awsCodeBuildServiceRoleDiagnostics(diagnostics []providers.SourceError) []AWSCodeBuildServiceRoleDiagnostic {
	result := make([]AWSCodeBuildServiceRoleDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSCodeBuildServiceRoleDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsCodeBuildServiceRoleDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsCodeBuildServiceRoleDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only CodeBuild read permissions; do not add build log, source, artifact, or secret-value reads."
	case "privileged_or_public_project":
		return "Review public visibility and privileged build settings before using the service role in least-privilege reasoning."
	case "project_batch_get_failed", "project_not_found":
		return "Retry only the failed CodeBuild metadata call and keep successful project-role records visible."
	case "missing_codebuild_service_role":
		return "Inspect the CodeBuild project service role configuration before using it for least-privilege reasoning."
	default:
		return "Review the CodeBuild collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsCodeBuildProjectNodeID(accountID string, region string, projectARN string) string {
	account := strings.TrimSpace(accountID)
	if account == "" {
		account = "account"
	}
	trimmedRegion := strings.TrimSpace(region)
	if trimmedRegion == "" {
		trimmedRegion = "region"
	}
	normalizedProjectARN := strings.TrimSpace(projectARN)
	if normalizedProjectARN == "" {
		normalizedProjectARN = "project"
	}
	return fmt.Sprintf("aws:workload:codebuild:%s:%s:project/%s", account, trimmedRegion, normalizedProjectARN)
}
