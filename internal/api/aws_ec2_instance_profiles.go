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
	awsEC2InstanceProfileCurrentIssue = 1477
	awsEC2InstanceProfileVersion      = "aws-ec2-instance-profile-inventory-v1"
)

// AWSEC2InstanceProfileInventoryRequest controls the deterministic inventory state.
type AWSEC2InstanceProfileInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSEC2InstanceProfileInventoryResult exposes scoped EC2 instance-profile identity evidence.
type AWSEC2InstanceProfileInventoryResult struct {
	TenantID           string                              `json:"tenant_id"`
	WorkspaceID        string                              `json:"workspace_id"`
	ProjectID          string                              `json:"project_id"`
	ConnectorID        string                              `json:"connector_id,omitempty"`
	AccountID          string                              `json:"account_id,omitempty"`
	Region             string                              `json:"region,omitempty"`
	ParentIssueNumber  int                                 `json:"parent_issue_number"`
	ParentIssueRef     string                              `json:"parent_issue_ref"`
	CurrentIssueNumber int                                 `json:"current_issue_number"`
	CurrentIssueRef    string                              `json:"current_issue_ref"`
	Version            string                              `json:"version"`
	Status             string                              `json:"status"`
	FixtureState       string                              `json:"fixture_state"`
	Confidence         float64                             `json:"confidence"`
	RecordCount        int                                 `json:"record_count"`
	WorkloadCount      int                                 `json:"workload_count"`
	IdentityCount      int                                 `json:"identity_count"`
	ResourceCount      int                                 `json:"resource_count"`
	RelationshipCount  int                                 `json:"relationship_count"`
	FailureReasons     []string                            `json:"failure_reasons"`
	RemediationHints   []string                            `json:"remediation_hints"`
	EvidenceLinks      []string                            `json:"evidence_links"`
	Records            []AWSEC2InstanceProfileRecord       `json:"records"`
	Relationships      []AWSEC2InstanceProfileRelationship `json:"relationships"`
	Diagnostics        []AWSEC2InstanceProfileDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                           `json:"generated_at"`
	UpdatedAt          time.Time                           `json:"updated_at"`
}

// AWSEC2InstanceProfileRecord is the operator-facing row for one workload/profile/role link.
type AWSEC2InstanceProfileRecord struct {
	AccountID             string            `json:"account_id"`
	Region                string            `json:"region"`
	Service               string            `json:"service"`
	WorkloadID            string            `json:"workload_id"`
	WorkloadType          string            `json:"workload_type"`
	WorkloadName          string            `json:"workload_name"`
	RoleARN               string            `json:"role_arn,omitempty"`
	RoleName              string            `json:"role_name,omitempty"`
	InstanceID            string            `json:"instance_id,omitempty"`
	InstanceARN           string            `json:"instance_arn,omitempty"`
	InstanceName          string            `json:"instance_name,omitempty"`
	InstanceState         string            `json:"instance_state,omitempty"`
	InstanceProfileARN    string            `json:"instance_profile_arn,omitempty"`
	InstanceProfileID     string            `json:"instance_profile_id,omitempty"`
	InstanceProfileName   string            `json:"instance_profile_name,omitempty"`
	LaunchTemplateID      string            `json:"launch_template_id,omitempty"`
	LaunchTemplateName    string            `json:"launch_template_name,omitempty"`
	LaunchTemplateVersion string            `json:"launch_template_version,omitempty"`
	IMDSEndpoint          string            `json:"imds_endpoint,omitempty"`
	IMDSHTTPTokens        string            `json:"imds_http_tokens,omitempty"`
	IMDSHopLimit          int32             `json:"imds_hop_limit,omitempty"`
	Tags                  map[string]string `json:"tags,omitempty"`
	Source                string            `json:"source"`
	EvidenceRef           string            `json:"evidence_ref"`
	FromNodeID            string            `json:"from_node_id"`
	ToNodeID              string            `json:"to_node_id,omitempty"`
	Confidence            float64           `json:"confidence"`
	CollectedAt           time.Time         `json:"collected_at"`
	Status                string            `json:"status"`
}

// AWSEC2InstanceProfileRelationship is the graph evidence exposed by the API.
type AWSEC2InstanceProfileRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSEC2InstanceProfileDiagnostic is one explicit non-success state.
type AWSEC2InstanceProfileDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSEC2InstanceProfileInventory returns scoped deterministic EC2 instance-profile inventory.
func (s *Service) GetAWSEC2InstanceProfileInventory(ctx context.Context, workspaceID string, projectID string, request AWSEC2InstanceProfileInventoryRequest) (AWSEC2InstanceProfileInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSEC2InstanceProfileInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSEC2InstanceProfileInventoryResult{}, err
	}
	return buildAWSEC2InstanceProfileInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSEC2InstanceProfileInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSEC2InstanceProfileInventoryRequest, checkedAt time.Time) (AWSEC2InstanceProfileInventoryResult, error) {
	fixtureState := normalizeAWSEC2InstanceProfileFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSEC2InstanceProfileInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics := awsEC2InstanceProfileFixtureRecords(scope, project, connectorID, accountID, region, fixtureState, checkedAt)

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
			ScanID:        "aws-ec2-instance-profile-fixture",
			CollectorName: "ec2_instance_profile",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSEC2InstanceProfileInventoryResult{}, fmt.Errorf("validate ec2 instance profile contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSEC2InstanceProfileInventory(fixtureState, diagnostics)
	relationships := awsEC2InstanceProfileRelationships(records)
	result := AWSEC2InstanceProfileInventoryResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsEC2InstanceProfileCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsEC2InstanceProfileCurrentIssue),
		Version:            awsEC2InstanceProfileVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		RecordCount:        len(records),
		WorkloadCount:      awsEC2InstanceProfileWorkloadCount(records),
		IdentityCount:      awsEC2InstanceProfileIdentityCount(records),
		ResourceCount:      awsEC2InstanceProfileResourceCount(records),
		RelationshipCount:  len(relationships),
		FailureReasons:     failures,
		RemediationHints:   remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsEC2InstanceProfileCurrentIssue),
			"/docs/aws-ec2-instance-profiles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsEC2InstanceProfileDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}
	return result, nil
}

func normalizeAWSEC2InstanceProfileFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsEC2InstanceProfileFixtureRecords(scope db.Scope, project db.TenancyProject, connectorID string, accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSEC2InstanceProfileRecord, []providers.SourceError) {
	baseRecord := func(workloadID string, workloadType string, workloadName string, roleARN string, source string, evidenceRef string) AWSEC2InstanceProfileRecord {
		roleName := roleNameFromARNForAPI(roleARN)
		status := "ready"
		if strings.TrimSpace(roleARN) == "" {
			status = "degraded"
		}
		return AWSEC2InstanceProfileRecord{
			AccountID:    accountID,
			Region:       region,
			Service:      "ec2",
			WorkloadID:   workloadID,
			WorkloadType: workloadType,
			WorkloadName: workloadName,
			RoleARN:      roleARN,
			RoleName:     roleName,
			Tags:         map[string]string{"owner": "platform", "service": "payments"},
			Source:       source,
			EvidenceRef:  evidenceRef,
			FromNodeID:   awsEC2WorkloadNodeID(accountID, region, workloadType, workloadID),
			ToNodeID:     awsIdentityNodeIDForAPI(roleARN),
			Confidence:   0.96,
			CollectedAt:  checkedAt,
			Status:       status,
		}
	}

	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-ec2-instance-profile", accountID)
	profileARN := fmt.Sprintf("arn:aws:iam::%s:instance-profile/payments-ec2-profile", accountID)
	instanceARN := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/i-0477ec2profile", region, accountID)
	instance := baseRecord("i-0477ec2profile", "ec2_instance", "payments-api", roleARN, "describeinstances", instanceARN)
	instance.InstanceID = "i-0477ec2profile"
	instance.InstanceARN = instanceARN
	instance.InstanceName = "payments-api"
	instance.InstanceState = "running"
	instance.InstanceProfileARN = profileARN
	instance.InstanceProfileID = "AIPAJ477EXAMPLE"
	instance.InstanceProfileName = "payments-ec2-profile"
	instance.IMDSEndpoint = "enabled"
	instance.IMDSHTTPTokens = "required"
	instance.IMDSHopLimit = 2

	templateRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/web-launch-template-role", accountID)
	templateProfileARN := fmt.Sprintf("arn:aws:iam::%s:instance-profile/web-launch-template-profile", accountID)
	template := baseRecord("lt-0477template:3", "ec2_launch_template", "web-launch-template", templateRoleARN, "describelaunchtemplateversions", "lt-0477template")
	template.InstanceProfileARN = templateProfileARN
	template.InstanceProfileName = "web-launch-template-profile"
	template.LaunchTemplateID = "lt-0477template"
	template.LaunchTemplateName = "web-launch-template"
	template.LaunchTemplateVersion = "3"
	template.Confidence = 0.9

	switch fixtureState {
	case "empty":
		return nil, nil
	case "degraded":
		degraded := instance
		degraded.RoleARN = ""
		degraded.RoleName = ""
		degraded.ToNodeID = ""
		degraded.Confidence = 0.55
		degraded.Status = "degraded"
		return []AWSEC2InstanceProfileRecord{degraded}, []providers.SourceError{{
			Collector: "aws_ec2/ec2_instance_profile",
			SourceID:  degraded.InstanceProfileARN,
			Code:      "missing_instance_profile_role",
			Message:   "EC2 instance profile did not resolve to an IAM role",
			Retryable: false,
		}}
	case "partial_failure":
		return []AWSEC2InstanceProfileRecord{instance}, []providers.SourceError{{
			Collector: "aws_ec2/ec2_instance_profile",
			SourceID:  fmt.Sprintf("service=ec2|account=%s|region=%s|source=launch-templates", accountID, region),
			Code:      "service_collection_failed",
			Message:   "Launch template role references could not be collected for this region partition",
			Retryable: true,
		}}
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_ec2/ec2_instance_profile",
			SourceID:  fmt.Sprintf("service=ec2|account=%s|region=%s|source=describeinstances", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only EC2 DescribeInstances or IAM GetInstanceProfile permission is missing",
			Retryable: false,
		}}
	default:
		return []AWSEC2InstanceProfileRecord{instance, template}, nil
	}
}

func summarizeAWSEC2InstanceProfileInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"ec2 instance profile collection is blocked by missing read-only permission"}, []string{"Grant ec2:DescribeInstances, ec2:DescribeLaunchTemplates, ec2:DescribeLaunchTemplateVersions, and iam:GetInstanceProfile for metadata-only collection."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.62, []string{"one or more EC2 instance profiles did not resolve to a role"}, []string{"Keep the workload visible and retry IAM instance-profile role resolution before using it for least-privilege reasoning."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.72, []string{"one EC2 partition failed while successful instance-profile records remain visible"}, []string{"Retry the failed account, region, or launch-template partition without discarding successful EC2 workload evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.8, []string{"ec2 instance profile collection returned diagnostics"}, []string{"Review diagnostics before treating EC2 coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.97, nil, nil
	}
}

func awsEC2InstanceProfileRelationships(records []AWSEC2InstanceProfileRecord) []AWSEC2InstanceProfileRelationship {
	result := make([]AWSEC2InstanceProfileRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		relationshipType := "runs_as"
		if strings.EqualFold(record.WorkloadType, "ec2_launch_template") {
			relationshipType = "attached_to"
		}
		result = append(result, AWSEC2InstanceProfileRelationship{
			Type:        relationshipType,
			FromNodeID:  record.FromNodeID,
			ToNodeID:    record.ToNodeID,
			EvidenceRef: record.EvidenceRef,
		})
	}
	return result
}

func awsEC2InstanceProfileWorkloadCount(records []AWSEC2InstanceProfileRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" {
			continue
		}
		seen[record.FromNodeID] = struct{}{}
	}
	return len(seen)
}

func awsEC2InstanceProfileIdentityCount(records []AWSEC2InstanceProfileRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		seen[record.ToNodeID] = struct{}{}
	}
	return len(seen)
}

func awsEC2InstanceProfileResourceCount(records []AWSEC2InstanceProfileRecord) int {
	count := 0
	for _, record := range records {
		if strings.TrimSpace(record.InstanceID) != "" {
			count++
		}
		if strings.TrimSpace(record.InstanceProfileARN) != "" {
			count++
		}
	}
	return count
}

func awsEC2InstanceProfileDiagnostics(diagnostics []providers.SourceError) []AWSEC2InstanceProfileDiagnostic {
	result := make([]AWSEC2InstanceProfileDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSEC2InstanceProfileDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsEC2InstanceProfileDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsEC2InstanceProfileDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only EC2 and IAM instance-profile read permissions; do not add data-plane or secret-value reads."
	case "missing_instance_profile_role":
		return "Verify the instance profile still exists and contains the expected role before using it in graph reasoning."
	case "service_collection_failed":
		return "Retry only the failed account, region, or service partition and keep successful records visible."
	default:
		return "Review the collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func roleNameFromARNForAPI(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 || idx == len(trimmed)-1 {
		return trimmed
	}
	return trimmed[idx+1:]
}

func awsIdentityNodeIDForAPI(roleARN string) string {
	if strings.TrimSpace(roleARN) == "" {
		return ""
	}
	return "aws:identity:" + strings.TrimSpace(roleARN)
}

func awsEC2WorkloadNodeID(accountID string, region string, workloadType string, workloadID string) string {
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
	prefix := "instance"
	if strings.EqualFold(workloadType, "ec2_launch_template") {
		prefix = "launch-template"
	}
	return fmt.Sprintf("aws:workload:ec2:%s:%s:%s/%s", account, trimmedRegion, prefix, normalizedWorkloadID)
}
