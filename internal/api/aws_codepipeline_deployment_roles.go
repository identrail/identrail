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
	awsCodePipelineDeploymentRoleCurrentIssue = 1482
	awsCodePipelineDeploymentRoleVersion      = "aws-codepipeline-deployment-role-inventory-v1"
)

type AWSCodePipelineDeploymentRoleInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

type AWSCodePipelineDeploymentRoleInventoryResult struct {
	TenantID                     string                                      `json:"tenant_id"`
	WorkspaceID                  string                                      `json:"workspace_id"`
	ProjectID                    string                                      `json:"project_id"`
	ConnectorID                  string                                      `json:"connector_id,omitempty"`
	AccountID                    string                                      `json:"account_id,omitempty"`
	Region                       string                                      `json:"region,omitempty"`
	ParentIssueNumber            int                                         `json:"parent_issue_number"`
	ParentIssueRef               string                                      `json:"parent_issue_ref"`
	CurrentIssueNumber           int                                         `json:"current_issue_number"`
	CurrentIssueRef              string                                      `json:"current_issue_ref"`
	Version                      string                                      `json:"version"`
	Status                       string                                      `json:"status"`
	FixtureState                 string                                      `json:"fixture_state"`
	Confidence                   float64                                     `json:"confidence"`
	RecordCount                  int                                         `json:"record_count"`
	PipelineCount                int                                         `json:"pipeline_count"`
	ActionRoleCount              int                                         `json:"action_role_count"`
	CrossAccountRoleCount        int                                         `json:"cross_account_role_count"`
	CrossRegionActionCount       int                                         `json:"cross_region_action_count"`
	DisabledStageTransitionCount int                                         `json:"disabled_stage_transition_count"`
	PassRoleAdjacentCount        int                                         `json:"pass_role_adjacent_count"`
	IdentityCount                int                                         `json:"identity_count"`
	ResourceCount                int                                         `json:"resource_count"`
	RelationshipCount            int                                         `json:"relationship_count"`
	FailureReasons               []string                                    `json:"failure_reasons"`
	RemediationHints             []string                                    `json:"remediation_hints"`
	EvidenceLinks                []string                                    `json:"evidence_links"`
	Records                      []AWSCodePipelineDeploymentRoleRecord       `json:"records"`
	Relationships                []AWSCodePipelineDeploymentRoleRelationship `json:"relationships"`
	Diagnostics                  []AWSCodePipelineDeploymentRoleDiagnostic   `json:"diagnostics"`
	GeneratedAt                  time.Time                                   `json:"generated_at"`
	UpdatedAt                    time.Time                                   `json:"updated_at"`
}

type AWSCodePipelineDeploymentRoleRecord struct {
	AccountID                 string            `json:"account_id"`
	Region                    string            `json:"region"`
	Service                   string            `json:"service"`
	WorkloadID                string            `json:"workload_id"`
	WorkloadType              string            `json:"workload_type"`
	WorkloadName              string            `json:"workload_name"`
	RoleARN                   string            `json:"role_arn,omitempty"`
	RoleName                  string            `json:"role_name,omitempty"`
	RoleAccountID             string            `json:"role_account_id,omitempty"`
	RoleKind                  string            `json:"role_kind,omitempty"`
	PipelineARN               string            `json:"pipeline_arn,omitempty"`
	PipelineName              string            `json:"pipeline_name,omitempty"`
	PipelineVersion           int32             `json:"pipeline_version,omitempty"`
	PipelineType              string            `json:"pipeline_type,omitempty"`
	ExecutionMode             string            `json:"execution_mode,omitempty"`
	StageName                 string            `json:"stage_name,omitempty"`
	ActionName                string            `json:"action_name,omitempty"`
	ActionCategory            string            `json:"action_category,omitempty"`
	ActionOwner               string            `json:"action_owner,omitempty"`
	ActionProvider            string            `json:"action_provider,omitempty"`
	ActionVersion             string            `json:"action_version,omitempty"`
	ActionRegion              string            `json:"action_region,omitempty"`
	RunOrder                  int32             `json:"run_order,omitempty"`
	Namespace                 string            `json:"namespace,omitempty"`
	InputArtifactNames        []string          `json:"input_artifact_names,omitempty"`
	OutputArtifactNames       []string          `json:"output_artifact_names,omitempty"`
	ArtifactStoreTypes        []string          `json:"artifact_store_types,omitempty"`
	ArtifactStoreLocations    []string          `json:"artifact_store_locations,omitempty"`
	ArtifactStoreRegions      []string          `json:"artifact_store_regions,omitempty"`
	ArtifactKMSKeyARNs        []string          `json:"artifact_kms_key_arns,omitempty"`
	ConfigurationKeys         []string          `json:"configuration_keys,omitempty"`
	ProviderIdentifiers       []string          `json:"provider_identifiers,omitempty"`
	DisabledStageTransitions  []string          `json:"disabled_stage_transitions,omitempty"`
	CrossRegionArtifactStores bool              `json:"cross_region_artifact_stores,omitempty"`
	CrossRegionAction         bool              `json:"cross_region_action,omitempty"`
	CrossAccountRole          bool              `json:"cross_account_role,omitempty"`
	PassRoleAdjacent          bool              `json:"pass_role_adjacent,omitempty"`
	Tags                      map[string]string `json:"tags,omitempty"`
	Source                    string            `json:"source"`
	EvidenceRef               string            `json:"evidence_ref"`
	FromNodeID                string            `json:"from_node_id"`
	ToNodeID                  string            `json:"to_node_id,omitempty"`
	RelationshipType          string            `json:"relationship_type"`
	Confidence                float64           `json:"confidence"`
	CollectedAt               time.Time         `json:"collected_at"`
	Status                    string            `json:"status"`
}

type AWSCodePipelineDeploymentRoleRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

type AWSCodePipelineDeploymentRoleDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSCodePipelineDeploymentRoleInventory(ctx context.Context, workspaceID string, projectID string, request AWSCodePipelineDeploymentRoleInventoryRequest) (AWSCodePipelineDeploymentRoleInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSCodePipelineDeploymentRoleInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSCodePipelineDeploymentRoleInventoryResult{}, err
	}
	return buildAWSCodePipelineDeploymentRoleInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSCodePipelineDeploymentRoleInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSCodePipelineDeploymentRoleInventoryRequest, checkedAt time.Time) (AWSCodePipelineDeploymentRoleInventoryResult, error) {
	fixtureState := normalizeAWSCodePipelineDeploymentRoleFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSCodePipelineDeploymentRoleInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics := awsCodePipelineDeploymentRoleFixtureRecords(accountID, region, fixtureState, checkedAt)

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
			ScanID:        "aws-codepipeline-deployment-role-fixture",
			CollectorName: "codepipeline_deployment_role",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSCodePipelineDeploymentRoleInventoryResult{}, fmt.Errorf("validate codepipeline deployment role contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSCodePipelineDeploymentRoleInventory(fixtureState, diagnostics)
	relationships := awsCodePipelineDeploymentRoleRelationships(records)
	return AWSCodePipelineDeploymentRoleInventoryResult{
		TenantID:                     scope.TenantID,
		WorkspaceID:                  project.WorkspaceID,
		ProjectID:                    project.ProjectID,
		ConnectorID:                  connectorID,
		AccountID:                    accountID,
		Region:                       region,
		ParentIssueNumber:            awsPlatformDependencyParentIssue,
		ParentIssueRef:               awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:           awsCodePipelineDeploymentRoleCurrentIssue,
		CurrentIssueRef:              awsIssueRef(awsCodePipelineDeploymentRoleCurrentIssue),
		Version:                      awsCodePipelineDeploymentRoleVersion,
		Status:                       status,
		FixtureState:                 fixtureState,
		Confidence:                   confidence,
		RecordCount:                  len(records),
		PipelineCount:                awsCodePipelineDeploymentRolePipelineCount(records),
		ActionRoleCount:              awsCodePipelineDeploymentRoleActionRoleCount(records),
		CrossAccountRoleCount:        awsCodePipelineDeploymentRoleCrossAccountCount(records),
		CrossRegionActionCount:       awsCodePipelineDeploymentRoleCrossRegionActionCount(records),
		DisabledStageTransitionCount: awsCodePipelineDeploymentRoleDisabledTransitionCount(records),
		PassRoleAdjacentCount:        awsCodePipelineDeploymentRolePassRoleAdjacentCount(records),
		IdentityCount:                awsCodePipelineDeploymentRoleIdentityCount(records),
		ResourceCount:                awsCodePipelineDeploymentRoleResourceCount(records),
		RelationshipCount:            len(relationships),
		FailureReasons:               failures,
		RemediationHints:             remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsCodePipelineDeploymentRoleCurrentIssue),
			"/docs/aws-codepipeline-deployment-roles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsCodePipelineDeploymentRoleDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSCodePipelineDeploymentRoleFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsCodePipelineDeploymentRoleFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSCodePipelineDeploymentRoleRecord, []providers.SourceError) {
	pipelineName := "payments-release"
	pipelineARN := fmt.Sprintf("arn:aws:codepipeline:%s:%s:%s", region, accountID, pipelineName)
	pipelineRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-codepipeline-service", accountID)
	base := AWSCodePipelineDeploymentRoleRecord{
		AccountID:                 accountID,
		Region:                    region,
		Service:                   "codepipeline",
		WorkloadID:                pipelineARN,
		WorkloadType:              "codepipeline_pipeline",
		WorkloadName:              pipelineName,
		RoleARN:                   pipelineRoleARN,
		RoleName:                  roleNameFromARNForAPI(pipelineRoleARN),
		RoleKind:                  "pipeline_service_role",
		PipelineARN:               pipelineARN,
		PipelineName:              pipelineName,
		PipelineVersion:           3,
		PipelineType:              "V2",
		ExecutionMode:             "QUEUED",
		ArtifactStoreTypes:        []string{"S3"},
		ArtifactStoreLocations:    []string{"payments-pipeline-artifacts-east", "payments-pipeline-artifacts-west"},
		ArtifactStoreRegions:      []string{region, "us-west-2"},
		ArtifactKMSKeyARNs:        []string{fmt.Sprintf("arn:aws:kms:%s:%s:key/pipeline-artifacts", region, accountID)},
		CrossRegionArtifactStores: true,
		PassRoleAdjacent:          true,
		Tags:                      map[string]string{"owner": "platform", "service": "payments"},
		Source:                    "getpipeline",
		EvidenceRef:               pipelineARN,
		FromNodeID:                awsCodePipelineNodeID(accountID, region, pipelineARN, "pipeline_service_role"),
		ToNodeID:                  awsIdentityNodeIDForAPI(pipelineRoleARN),
		RelationshipType:          "runs_as",
		Confidence:                0.96,
		CollectedAt:               checkedAt,
		Status:                    "ready",
	}
	actionRoleARN := "arn:aws:iam::210987654321:role/payments-prod-deploy-action"
	action := base
	action.WorkloadID = pipelineARN + "/Deploy/Prod"
	action.WorkloadType = "codepipeline_action"
	action.WorkloadName = "payments-release / Deploy / Prod"
	action.RoleARN = actionRoleARN
	action.RoleName = roleNameFromARNForAPI(actionRoleARN)
	action.RoleAccountID = roleAccountIDFromARNForAPI(actionRoleARN)
	action.RoleKind = "action_role"
	action.StageName = "Deploy"
	action.ActionName = "Prod"
	action.ActionCategory = "Deploy"
	action.ActionOwner = "AWS"
	action.ActionProvider = "CodeDeploy"
	action.ActionVersion = "1"
	action.ActionRegion = "us-west-2"
	action.RunOrder = 1
	action.InputArtifactNames = []string{"BuildArtifact"}
	action.ConfigurationKeys = []string{"ApplicationName", "DeploymentGroupName"}
	action.ProviderIdentifiers = []string{"Deploy/AWS/CodeDeploy/1"}
	action.CrossRegionAction = true
	action.CrossAccountRole = true
	action.EvidenceRef = pipelineARN + "#stage/Deploy/action/Prod"
	action.FromNodeID = awsCodePipelineNodeID(action.AccountID, region, action.WorkloadID, "action_role")
	action.ToNodeID = awsIdentityNodeIDForAPI(actionRoleARN)
	action.Confidence = 0.9

	switch fixtureState {
	case "empty":
		return nil, nil
	case "degraded":
		degraded := base
		degraded.DisabledStageTransitions = []string{"Deploy: freeze window"}
		degraded.Status = "degraded"
		degraded.Confidence = 0.88
		return []AWSCodePipelineDeploymentRoleRecord{degraded}, []providers.SourceError{{
			Collector: "aws_codepipeline/codepipeline_deployment_role",
			SourceID:  pipelineARN,
			Code:      "disabled_stage_transition",
			Message:   "CodePipeline deployment-role evidence is visible, but one stage transition is disabled",
			Retryable: false,
		}}
	case "partial_failure":
		return []AWSCodePipelineDeploymentRoleRecord{base}, []providers.SourceError{{
			Collector: "aws_codepipeline/codepipeline_deployment_role",
			SourceID:  fmt.Sprintf("service=codepipeline|account=%s|region=%s|source=getpipeline", accountID, region),
			Code:      "pipeline_get_failed",
			Message:   "One CodePipeline pipeline could not be described; successful deployment-role evidence remains visible",
			Retryable: true,
		}}
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_codepipeline/codepipeline_deployment_role",
			SourceID:  fmt.Sprintf("service=codepipeline|account=%s|region=%s|source=listpipelines", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only CodePipeline ListPipelines, GetPipeline, or GetPipelineState permission is missing",
			Retryable: false,
		}}
	default:
		return []AWSCodePipelineDeploymentRoleRecord{base, action}, nil
	}
}

func summarizeAWSCodePipelineDeploymentRoleInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"codepipeline deployment role collection is blocked by missing read-only permission"}, []string{"Grant codepipeline:ListPipelines, codepipeline:GetPipeline, and codepipeline:GetPipelineState for metadata-only collection."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.68, []string{"one or more CodePipeline stages have disabled transitions"}, []string{"Keep deployment-role evidence visible and inspect disabled transitions before treating deploy-role coverage as complete."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.76, []string{"one CodePipeline metadata partition failed while successful deployment-role records remain visible"}, []string{"Retry the failed CodePipeline metadata call without discarding successful deployment-role evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.8, []string{"codepipeline deployment role collection returned diagnostics"}, []string{"Review diagnostics before treating CodePipeline coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.96, nil, nil
	}
}

func awsCodePipelineDeploymentRoleRelationships(records []AWSCodePipelineDeploymentRoleRecord) []AWSCodePipelineDeploymentRoleRelationship {
	result := make([]AWSCodePipelineDeploymentRoleRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		result = append(result, AWSCodePipelineDeploymentRoleRelationship{
			Type:        "runs_as",
			FromNodeID:  record.FromNodeID,
			ToNodeID:    record.ToNodeID,
			EvidenceRef: record.EvidenceRef,
		})
	}
	return result
}

func awsCodePipelineDeploymentRolePipelineCount(records []AWSCodePipelineDeploymentRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.PipelineARN) != "" {
			seen[record.PipelineARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsCodePipelineDeploymentRoleActionRoleCount(records []AWSCodePipelineDeploymentRoleRecord) int {
	count := 0
	for _, record := range records {
		if strings.EqualFold(record.RoleKind, "action_role") {
			count++
		}
	}
	return count
}

func awsCodePipelineDeploymentRoleCrossAccountCount(records []AWSCodePipelineDeploymentRoleRecord) int {
	count := 0
	for _, record := range records {
		if record.CrossAccountRole {
			count++
		}
	}
	return count
}

func awsCodePipelineDeploymentRoleCrossRegionActionCount(records []AWSCodePipelineDeploymentRoleRecord) int {
	count := 0
	for _, record := range records {
		if record.CrossRegionAction {
			count++
		}
	}
	return count
}

func awsCodePipelineDeploymentRoleDisabledTransitionCount(records []AWSCodePipelineDeploymentRoleRecord) int {
	count := 0
	for _, record := range records {
		count += len(record.DisabledStageTransitions)
	}
	return count
}

func awsCodePipelineDeploymentRolePassRoleAdjacentCount(records []AWSCodePipelineDeploymentRoleRecord) int {
	count := 0
	for _, record := range records {
		if record.PassRoleAdjacent {
			count++
		}
	}
	return count
}

func awsCodePipelineDeploymentRoleIdentityCount(records []AWSCodePipelineDeploymentRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) != "" {
			seen[record.ToNodeID] = struct{}{}
		}
	}
	return len(seen)
}

func awsCodePipelineDeploymentRoleResourceCount(records []AWSCodePipelineDeploymentRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.PipelineARN) != "" {
			seen[record.PipelineARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsCodePipelineDeploymentRoleDiagnostics(diagnostics []providers.SourceError) []AWSCodePipelineDeploymentRoleDiagnostic {
	result := make([]AWSCodePipelineDeploymentRoleDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSCodePipelineDeploymentRoleDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsCodePipelineDeploymentRoleDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsCodePipelineDeploymentRoleDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only CodePipeline read permissions; do not add artifact, source, action output, or secret-value reads."
	case "disabled_stage_transition":
		return "Review disabled stage transitions before using deployment-role evidence for release-governance decisions."
	case "pipeline_get_failed", "pipeline_state_get_failed", "pipeline_not_found":
		return "Retry only the failed CodePipeline metadata call and keep successful deployment-role records visible."
	case "missing_codepipeline_deployment_role":
		return "Inspect the CodePipeline pipeline or action role configuration before using it for least-privilege reasoning."
	default:
		return "Review the CodePipeline collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsCodePipelineNodeID(accountID string, region string, pipelineRef string, roleKind string) string {
	account := firstNonEmptyAWSValue(accountID, "account")
	trimmedRegion := firstNonEmptyAWSValue(region, "region")
	normalizedRef := firstNonEmptyAWSValue(pipelineRef, "pipeline")
	normalizedRoleKind := firstNonEmptyAWSValue(roleKind, "role")
	return fmt.Sprintf("aws:workload:codepipeline:%s:%s:pipeline/%s/%s", account, trimmedRegion, normalizedRef, normalizedRoleKind)
}

func roleAccountIDFromARNForAPI(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) >= 5 {
		return strings.TrimSpace(parts[4])
	}
	return ""
}
