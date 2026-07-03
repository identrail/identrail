package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsMachineIdentityDetailCurrentIssue = 1549
	awsMachineIdentityDetailVersion      = "aws-machine-identity-detail-page-v1"
	awsMachineIdentityDetailPolicyID     = "aws-machine-identity-detail-policy-v1"
)

// AWSMachineIdentityDetailRequest scopes the read-only machine identity detail
// page to one identity plus the operator filters shared by downstream surfaces.
type AWSMachineIdentityDetailRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	Identity     string `json:"identity,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Tab          string `json:"tab,omitempty"`
	Service      string `json:"service,omitempty"`
	Resource     string `json:"resource,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Status       string `json:"status,omitempty"`
}

type AWSMachineIdentityDetailIdentity struct {
	Identity         string  `json:"identity"`
	IdentityNodeID   string  `json:"identity_node_id"`
	PrincipalARN     string  `json:"principal_arn,omitempty"`
	RoleName         string  `json:"role_name,omitempty"`
	DisplayName      string  `json:"display_name"`
	AccountID        string  `json:"account_id,omitempty"`
	Region           string  `json:"region,omitempty"`
	Status           string  `json:"status"`
	Confidence       float64 `json:"confidence"`
	EvidenceBoundary string  `json:"evidence_boundary"`
}

type AWSMachineIdentityWorkloadBinding struct {
	BindingID        string    `json:"binding_id"`
	Service          string    `json:"service"`
	WorkloadID       string    `json:"workload_id,omitempty"`
	WorkloadType     string    `json:"workload_type,omitempty"`
	WorkloadName     string    `json:"workload_name,omitempty"`
	RoleARN          string    `json:"role_arn,omitempty"`
	RoleName         string    `json:"role_name,omitempty"`
	RoleKind         string    `json:"role_kind,omitempty"`
	RelationshipType string    `json:"relationship_type,omitempty"`
	FromNodeID       string    `json:"from_node_id,omitempty"`
	ToNodeID         string    `json:"to_node_id,omitempty"`
	EvidenceRef      string    `json:"evidence_ref,omitempty"`
	Status           string    `json:"status"`
	Confidence       float64   `json:"confidence"`
	CollectedAt      time.Time `json:"collected_at,omitzero"`
}

type AWSMachineIdentityPermissionSummary struct {
	RecommendationID string   `json:"recommendation_id"`
	Decision         string   `json:"decision"`
	Severity         string   `json:"severity"`
	Status           string   `json:"status"`
	Service          string   `json:"service"`
	ResourceARN      string   `json:"resource_arn,omitempty"`
	DisplayName      string   `json:"display_name"`
	Actions          []string `json:"actions,omitempty"`
	Rationale        string   `json:"rationale"`
	NextAction       string   `json:"next_action"`
	Score            int      `json:"score"`
}

type AWSMachineIdentityResourceSummary struct {
	ResourceID   string    `json:"resource_id"`
	ResourceARN  string    `json:"resource_arn,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	Label        string    `json:"label"`
	Source       string    `json:"source"`
	EvidenceRef  string    `json:"evidence_ref,omitempty"`
	ObservedAt   time.Time `json:"observed_at,omitzero"`
}

type AWSMachineIdentityFindingSummary struct {
	FindingID    string   `json:"finding_id"`
	Source       string   `json:"source"`
	FindingType  string   `json:"finding_type"`
	Severity     string   `json:"severity"`
	Status       string   `json:"status"`
	Score        int      `json:"score"`
	Title        string   `json:"title"`
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	NextAction   string   `json:"next_action"`
}

type AWSMachineIdentityGovernanceDecision struct {
	ReportID     string    `json:"report_id"`
	Category     string    `json:"category"`
	DecisionType string    `json:"decision_type"`
	State        string    `json:"state"`
	Title        string    `json:"title"`
	Summary      string    `json:"summary"`
	Actor        string    `json:"actor,omitempty"`
	Approver     string    `json:"approver,omitempty"`
	EvidenceRefs []string  `json:"evidence_refs,omitempty"`
	OccurredAt   time.Time `json:"occurred_at,omitzero"`
}

type AWSMachineIdentityDetailRelationship struct {
	Source      string `json:"source"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

type AWSMachineIdentityDetailTab struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type AWSMachineIdentityDetailDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

type AWSMachineIdentityDetailCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSMachineIdentityDetailSummary struct {
	WorkloadBindingCount          int `json:"workload_binding_count"`
	RuntimeEventCount             int `json:"runtime_event_count"`
	PermissionRecommendationCount int `json:"permission_recommendation_count"`
	SecretFindingCount            int `json:"secret_finding_count"`
	FindingCount                  int `json:"finding_count"`
	RemediationCaseCount          int `json:"remediation_case_count"`
	GovernanceDecisionCount       int `json:"governance_decision_count"`
	ResourceReachedCount          int `json:"resource_reached_count"`
	RelationshipCount             int `json:"relationship_count"`
	EvidenceLinkCount             int `json:"evidence_link_count"`
	DiagnosticCount               int `json:"diagnostic_count"`
	CoverageGapCount              int `json:"coverage_gap_count"`
}

type AWSMachineIdentityDetailResult struct {
	TenantID            string                                 `json:"tenant_id"`
	WorkspaceID         string                                 `json:"workspace_id"`
	ProjectID           string                                 `json:"project_id"`
	ConnectorID         string                                 `json:"connector_id,omitempty"`
	AccountID           string                                 `json:"account_id,omitempty"`
	Region              string                                 `json:"region,omitempty"`
	ParentIssueNumber   int                                    `json:"parent_issue_number"`
	ParentIssueRef      string                                 `json:"parent_issue_ref"`
	CurrentIssueNumber  int                                    `json:"current_issue_number"`
	CurrentIssueRef     string                                 `json:"current_issue_ref"`
	Version             string                                 `json:"version"`
	Status              string                                 `json:"status"`
	FixtureState        string                                 `json:"fixture_state,omitempty"`
	Confidence          float64                                `json:"confidence"`
	PolicyVersion       string                                 `json:"policy_version"`
	AppliedFilters      map[string]string                      `json:"applied_filters"`
	Identity            AWSMachineIdentityDetailIdentity       `json:"identity"`
	Summary             AWSMachineIdentityDetailSummary        `json:"summary"`
	Tabs                []AWSMachineIdentityDetailTab          `json:"tabs"`
	WorkloadBindings    []AWSMachineIdentityWorkloadBinding    `json:"workload_bindings"`
	PermissionSummaries []AWSMachineIdentityPermissionSummary  `json:"permission_summaries"`
	ResourcesReached    []AWSMachineIdentityResourceSummary    `json:"resources_reached"`
	Findings            []AWSMachineIdentityFindingSummary     `json:"findings"`
	GovernanceDecisions []AWSMachineIdentityGovernanceDecision `json:"governance_decisions"`
	Relationships       []AWSMachineIdentityDetailRelationship `json:"relationships"`
	Runtime             AWSRuntimeEventResult                  `json:"runtime"`
	Permissions         AWSLeastPrivilegeResult                `json:"permissions"`
	Secrets             AWSSecretPermissionEquivalenceResult   `json:"secrets"`
	BlastRadius         AWSBlastRadiusResult                   `json:"blast_radius"`
	IdentitySprawl      AWSIdentitySprawlResult                `json:"identity_sprawl"`
	RemediationCases    AWSRemediationCaseResult               `json:"remediation_cases"`
	Governance          AWSGovernanceAuditReportingResult      `json:"governance"`
	FailureReasons      []string                               `json:"failure_reasons"`
	RemediationHints    []string                               `json:"remediation_hints"`
	EvidenceLinks       []string                               `json:"evidence_links"`
	CoverageGaps        []AWSMachineIdentityDetailCoverageGap  `json:"coverage_gaps"`
	Diagnostics         []AWSMachineIdentityDetailDiagnostic   `json:"diagnostics"`
	GeneratedAt         time.Time                              `json:"generated_at"`
	UpdatedAt           time.Time                              `json:"updated_at"`
}

func (s *Service) GetAWSMachineIdentityDetail(ctx context.Context, workspaceID string, projectID string, request AWSMachineIdentityDetailRequest) (AWSMachineIdentityDetailResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSMachineIdentityDetailResult{}, err
	}
	identity := strings.TrimSpace(request.Identity)
	if identity == "" {
		return AWSMachineIdentityDetailResult{}, ErrInvalidAWSConnectionRequest
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSMachineIdentityDetailResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSMachineIdentityDetailFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSMachineIdentityDetailResult{}, ErrInvalidAWSConnectionRequest
	}
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	ec2, err := s.GetAWSEC2InstanceProfileInventory(ctx, workspaceID, projectID, AWSEC2InstanceProfileInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail ec2 inventory: %w", err)
	}
	ecs, err := s.GetAWSECSTaskRoleInventory(ctx, workspaceID, projectID, AWSECSTaskRoleInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail ecs inventory: %w", err)
	}
	lambda, err := s.GetAWSLambdaExecutionRoleInventory(ctx, workspaceID, projectID, AWSLambdaExecutionRoleInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail lambda inventory: %w", err)
	}
	codeBuild, err := s.GetAWSCodeBuildServiceRoleInventory(ctx, workspaceID, projectID, AWSCodeBuildServiceRoleInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail codebuild inventory: %w", err)
	}
	codePipeline, err := s.GetAWSCodePipelineDeploymentRoleInventory(ctx, workspaceID, projectID, AWSCodePipelineDeploymentRoleInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail codepipeline inventory: %w", err)
	}
	stepFunctions, err := s.GetAWSStepFunctionsStateMachineRoleInventory(ctx, workspaceID, projectID, AWSStepFunctionsStateMachineRoleInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail stepfunctions inventory: %w", err)
	}
	eventDriven, err := s.GetAWSEventDrivenRoleInventory(ctx, workspaceID, projectID, AWSEventDrivenRoleInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail event-driven inventory: %w", err)
	}
	managedCompute, err := s.GetAWSManagedComputeRoleInventory(ctx, workspaceID, projectID, AWSManagedComputeRoleInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail managed compute inventory: %w", err)
	}
	eks, err := s.GetAWSEKSWorkloadIdentityInventory(ctx, workspaceID, projectID, AWSEKSWorkloadIdentityInventoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail eks inventory: %w", err)
	}

	bindingScope := awsMachineIdentityDetailBindingScopeFor(request)
	bindings := awsMachineIdentityDetailBindings(identity, bindingScope, ec2, ecs, lambda, codeBuild, codePipeline, stepFunctions, eventDriven, managedCompute, eks)
	identityScope := awsMachineIdentityDetailScopeFor(identity, bindings)
	loadDownstream := func(downstreamIdentity string) (AWSRuntimeEventResult, AWSLeastPrivilegeResult, AWSSecretPermissionEquivalenceResult, AWSBlastRadiusResult, AWSIdentitySprawlResult, AWSRemediationCaseResult, error) {
		runtime, err := s.GetAWSRuntimeEvents(ctx, workspaceID, projectID, AWSRuntimeEventRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			Identity:     downstreamIdentity,
			Resource:     request.Resource,
			Status:       request.Status,
		})
		if err != nil {
			return AWSRuntimeEventResult{}, AWSLeastPrivilegeResult{}, AWSSecretPermissionEquivalenceResult{}, AWSBlastRadiusResult{}, AWSIdentitySprawlResult{}, AWSRemediationCaseResult{}, fmt.Errorf("machine identity detail runtime: %w", err)
		}
		permissions, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			Identity:     downstreamIdentity,
			Resource:     request.Resource,
			Service:      request.Service,
			Severity:     request.Severity,
			Status:       request.Status,
		})
		if err != nil {
			return AWSRuntimeEventResult{}, AWSLeastPrivilegeResult{}, AWSSecretPermissionEquivalenceResult{}, AWSBlastRadiusResult{}, AWSIdentitySprawlResult{}, AWSRemediationCaseResult{}, fmt.Errorf("machine identity detail permissions: %w", err)
		}
		secrets, err := s.GetAWSSecretPermissionEquivalence(ctx, workspaceID, projectID, AWSSecretPermissionEquivalenceRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			Identity:     downstreamIdentity,
			Secret:       request.Resource,
			Severity:     request.Severity,
			Status:       request.Status,
		})
		if err != nil {
			return AWSRuntimeEventResult{}, AWSLeastPrivilegeResult{}, AWSSecretPermissionEquivalenceResult{}, AWSBlastRadiusResult{}, AWSIdentitySprawlResult{}, AWSRemediationCaseResult{}, fmt.Errorf("machine identity detail secrets: %w", err)
		}
		blast, err := s.GetAWSBlastRadius(ctx, workspaceID, projectID, AWSBlastRadiusRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			Identity:     downstreamIdentity,
			Resource:     request.Resource,
			Severity:     request.Severity,
			Status:       request.Status,
		})
		if err != nil {
			return AWSRuntimeEventResult{}, AWSLeastPrivilegeResult{}, AWSSecretPermissionEquivalenceResult{}, AWSBlastRadiusResult{}, AWSIdentitySprawlResult{}, AWSRemediationCaseResult{}, fmt.Errorf("machine identity detail blast radius: %w", err)
		}
		sprawl, err := s.GetAWSIdentitySprawl(ctx, workspaceID, projectID, AWSIdentitySprawlRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			Identity:     downstreamIdentity,
			Severity:     request.Severity,
			Status:       request.Status,
		})
		if err != nil {
			return AWSRuntimeEventResult{}, AWSLeastPrivilegeResult{}, AWSSecretPermissionEquivalenceResult{}, AWSBlastRadiusResult{}, AWSIdentitySprawlResult{}, AWSRemediationCaseResult{}, fmt.Errorf("machine identity detail sprawl: %w", err)
		}
		cases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, AWSRemediationCaseRequest{
			ConnectorID:  connectorID,
			FixtureState: sourceFixtureState,
			AccountID:    request.AccountID,
			Region:       request.Region,
			Identity:     downstreamIdentity,
			Severity:     request.Severity,
			Status:       request.Status,
		})
		if err != nil {
			return AWSRuntimeEventResult{}, AWSLeastPrivilegeResult{}, AWSSecretPermissionEquivalenceResult{}, AWSBlastRadiusResult{}, AWSIdentitySprawlResult{}, AWSRemediationCaseResult{}, fmt.Errorf("machine identity detail remediation cases: %w", err)
		}
		return runtime, permissions, secrets, blast, sprawl, cases, nil
	}
	downstreamIdentity := identityScope.DownstreamIdentity
	runtime, permissions, secrets, blast, sprawl, cases, err := loadDownstream(downstreamIdentity)
	if err != nil {
		return AWSMachineIdentityDetailResult{}, err
	}
	identityScope = awsMachineIdentityDetailScopeWithEvidence(identityScope, runtime, permissions, secrets, blast, sprawl, cases)
	if identityScope.DownstreamIdentity != "" && identityScope.DownstreamIdentity != downstreamIdentity {
		runtime, permissions, secrets, blast, sprawl, cases, err = loadDownstream(identityScope.DownstreamIdentity)
		if err != nil {
			return AWSMachineIdentityDetailResult{}, err
		}
	}
	runtime, permissions, secrets, blast, sprawl, cases = awsMachineIdentityDetailFilterDownstreamEvidence(identityScope, runtime, permissions, secrets, blast, sprawl, cases)
	identityNodeID := identityScope.NodeID
	governanceIdentityID := awsMachineIdentityDetailGovernanceIdentityID(identityScope)
	governance, err := s.GetAWSGovernanceAuditReporting(ctx, workspaceID, projectID, AWSGovernanceAuditReportingRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
		IdentityID:   governanceIdentityID,
		State:        request.Status,
	})
	if err != nil {
		return AWSMachineIdentityDetailResult{}, fmt.Errorf("machine identity detail governance: %w", err)
	}

	permissionSummaries := awsMachineIdentityPermissionSummaries(permissions.Recommendations)
	resourcesReached := awsMachineIdentityResourcesReached(runtime, permissions, secrets, blast)
	findings := awsMachineIdentityFindingSummaries(secrets, blast, sprawl)
	governanceDecisions := awsMachineIdentityGovernanceDecisions(governance.Records)
	relationships := awsMachineIdentityDetailRelationships(bindings, runtime, permissions, secrets, blast, sprawl, cases, governance)
	diagnostics := awsMachineIdentityDetailDiagnostics(ec2, ecs, lambda, codeBuild, codePipeline, stepFunctions, eventDriven, managedCompute, eks, runtime, permissions, secrets, blast, sprawl, cases, governance)
	coverageGaps := awsMachineIdentityDetailCoverageGaps(runtime, permissions, secrets, blast, sprawl, cases, governance)
	evidenceLinks := awsMachineIdentityDetailEvidenceLinks(identity, ec2, ecs, lambda, codeBuild, codePipeline, stepFunctions, eventDriven, managedCompute, eks, runtime, permissions, secrets, blast, sprawl, cases, governance)
	status, confidence, failures, remediations := summarizeAWSMachineIdentityDetail(fixtureState, bindings, runtime, permissions, secrets, blast, sprawl, cases, governance, diagnostics)
	identitySummary := awsMachineIdentityDetailIdentity(identity, identityNodeID, accountID, region, status, confidence, bindings, runtime, permissions, secrets, blast, sprawl, cases)
	summary := AWSMachineIdentityDetailSummary{
		WorkloadBindingCount:          len(bindings),
		RuntimeEventCount:             len(runtime.Records),
		PermissionRecommendationCount: len(permissions.Recommendations),
		SecretFindingCount:            len(secrets.Findings),
		FindingCount:                  len(findings),
		RemediationCaseCount:          len(cases.Cases),
		GovernanceDecisionCount:       len(governanceDecisions),
		ResourceReachedCount:          len(resourcesReached),
		RelationshipCount:             len(relationships),
		EvidenceLinkCount:             len(evidenceLinks),
		DiagnosticCount:               len(diagnostics),
		CoverageGapCount:              len(coverageGaps),
	}

	return AWSMachineIdentityDetailResult{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		AccountID:           accountID,
		Region:              region,
		ParentIssueNumber:   awsPlatformDependencyParentIssue,
		ParentIssueRef:      awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:  awsMachineIdentityDetailCurrentIssue,
		CurrentIssueRef:     awsIssueRef(awsMachineIdentityDetailCurrentIssue),
		Version:             awsMachineIdentityDetailVersion,
		Status:              status,
		FixtureState:        fixtureState,
		Confidence:          confidence,
		PolicyVersion:       awsMachineIdentityDetailPolicyID,
		AppliedFilters:      awsMachineIdentityDetailAppliedFilters(request, identityNodeID),
		Identity:            identitySummary,
		Summary:             summary,
		Tabs:                awsMachineIdentityDetailTabs(summary, status),
		WorkloadBindings:    bindings,
		PermissionSummaries: permissionSummaries,
		ResourcesReached:    resourcesReached,
		Findings:            findings,
		GovernanceDecisions: governanceDecisions,
		Relationships:       relationships,
		Runtime:             runtime,
		Permissions:         permissions,
		Secrets:             secrets,
		BlastRadius:         blast,
		IdentitySprawl:      sprawl,
		RemediationCases:    cases,
		Governance:          governance,
		FailureReasons:      dedupeStrings(append(failures, awsMachineIdentityDetailFailureReasons(runtime, permissions, secrets, blast, sprawl, cases, governance)...)),
		RemediationHints:    dedupeStrings(append(remediations, awsMachineIdentityDetailRemediationHints(runtime, permissions, secrets, blast, sprawl, cases, governance)...)),
		EvidenceLinks:       evidenceLinks,
		CoverageGaps:        coverageGaps,
		Diagnostics:         diagnostics,
		GeneratedAt:         now,
		UpdatedAt:           now,
	}, nil
}

func normalizeAWSMachineIdentityDetailFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsMachineIdentityDetailNodeID(identity string) string {
	identity = strings.TrimSpace(identity)
	if strings.HasPrefix(strings.ToLower(identity), "arn:") {
		return awsIdentityNodeIDForAPI(identity)
	}
	return identity
}

func awsMachineIdentityDetailFilterToken(identity string) string {
	identity = strings.TrimSpace(identity)
	if strings.HasPrefix(strings.ToLower(identity), "arn:") {
		return identity
	}
	if strings.HasPrefix(strings.ToLower(identity), "aws:identity:arn:") {
		arn := strings.TrimPrefix(identity, "aws:identity:")
		return firstNonEmptyAWSValue(arn, identity)
	}
	return identity
}

type awsMachineIdentityDetailScope struct {
	NodeID             string
	PrincipalARN       string
	RoleName           string
	DownstreamIdentity string
}

type awsMachineIdentityDetailBindingScope struct {
	AccountID string
	Region    string
}

func awsMachineIdentityDetailBindingScopeFor(request AWSMachineIdentityDetailRequest) awsMachineIdentityDetailBindingScope {
	return awsMachineIdentityDetailBindingScope{
		AccountID: awsMachineIdentityDetailOptionalScopeValue(request.AccountID),
		Region:    awsMachineIdentityDetailOptionalScopeValue(request.Region),
	}
}

func awsMachineIdentityDetailOptionalScopeValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "all") {
		return ""
	}
	return value
}

func (scope awsMachineIdentityDetailBindingScope) accepts(accountID, region string) bool {
	if scope.AccountID != "" && !strings.EqualFold(strings.TrimSpace(accountID), scope.AccountID) {
		return false
	}
	if scope.Region != "" && !strings.EqualFold(strings.TrimSpace(region), scope.Region) {
		return false
	}
	return true
}

func awsMachineIdentityDetailScopeFor(identity string, bindings []AWSMachineIdentityWorkloadBinding) awsMachineIdentityDetailScope {
	identity = strings.TrimSpace(identity)
	nodeID := ""
	principalARN := ""
	roleName := ""
	switch {
	case strings.HasPrefix(strings.ToLower(identity), "arn:"):
		nodeID = awsIdentityNodeIDForAPI(identity)
		principalARN = identity
		roleName = shortAWSARN(identity)
	case strings.HasPrefix(strings.ToLower(identity), "aws:identity:arn:"):
		nodeID = identity
		arn := strings.TrimPrefix(identity, "aws:identity:")
		principalARN = arn
		roleName = shortAWSARN(arn)
	default:
		roleName = identity
	}
	for _, binding := range bindings {
		principalARN = firstNonEmptyAWSValue(principalARN, binding.RoleARN)
		nodeID = firstNonEmptyAWSValue(nodeID, binding.ToNodeID)
		roleName = firstNonEmptyAWSValue(roleName, binding.RoleName, shortAWSARN(binding.RoleARN))
	}
	if nodeID == "" && principalARN != "" {
		nodeID = awsIdentityNodeIDForAPI(principalARN)
	}
	downstreamIdentity := firstNonEmptyAWSValue(principalARN, nodeID, roleName, identity)
	return awsMachineIdentityDetailScope{
		NodeID:             nodeID,
		PrincipalARN:       principalARN,
		RoleName:           roleName,
		DownstreamIdentity: downstreamIdentity,
	}
}

func awsMachineIdentityDetailScopeWithEvidence(scope awsMachineIdentityDetailScope, runtime AWSRuntimeEventResult, permissions AWSLeastPrivilegeResult, secrets AWSSecretPermissionEquivalenceResult, blast AWSBlastRadiusResult, sprawl AWSIdentitySprawlResult, cases AWSRemediationCaseResult) awsMachineIdentityDetailScope {
	add := func(principalARN, nodeID, roleName string) {
		if scope.PrincipalARN != "" && scope.NodeID != "" {
			return
		}
		if !awsMachineIdentityDetailScopeAccepts(scope, principalARN, nodeID, roleName) {
			return
		}
		scope.PrincipalARN = firstNonEmptyAWSValue(scope.PrincipalARN, principalARN)
		scope.NodeID = firstNonEmptyAWSValue(scope.NodeID, nodeID)
		scope.RoleName = firstNonEmptyAWSValue(scope.RoleName, roleName, shortAWSARN(principalARN))
	}
	for _, record := range runtime.Records {
		add(record.ActorPrincipalARN, record.ActorIdentityNodeID, shortAWSARN(record.ActorPrincipalARN))
		add(record.Session.PrincipalARN, "", shortAWSARN(record.Session.PrincipalARN))
		add(record.Session.AssumedRoleARN, "", shortAWSARN(record.Session.AssumedRoleARN))
		add(record.Session.OriginalActorARN, record.Session.OriginalActorNodeID, shortAWSARN(record.Session.OriginalActorARN))
		add(record.Session.SessionIssuerARN, record.Session.OriginalActorNodeID, shortAWSARN(record.Session.SessionIssuerARN))
		add(record.Session.ChainedFromPrincipalARN, record.Session.ChainedFromNodeID, shortAWSARN(record.Session.ChainedFromPrincipalARN))
	}
	for _, recommendation := range permissions.Recommendations {
		add(recommendation.PrincipalARN, recommendation.IdentityNodeID, shortAWSARN(recommendation.PrincipalARN))
	}
	for _, finding := range secrets.Findings {
		add(finding.PrincipalARN, finding.IdentityNodeID, "")
	}
	for _, finding := range blast.Findings {
		add(finding.PrincipalARN, finding.IdentityNodeID, shortAWSARN(finding.PrincipalARN))
	}
	for _, finding := range sprawl.Findings {
		add(finding.PrincipalARN, finding.IdentityNodeID, finding.RoleName)
	}
	for _, c := range cases.Cases {
		add(c.IdentityARN, c.IdentityNodeID, c.IdentityName)
	}
	if scope.NodeID == "" && scope.PrincipalARN != "" {
		scope.NodeID = awsIdentityNodeIDForAPI(scope.PrincipalARN)
	}
	if scope.NodeID == "" && scope.PrincipalARN == "" && scope.RoleName != "" {
		scope.DownstreamIdentity = "aws:identity:unresolved:" + stableAWSBlastRadiusToken(scope.RoleName)
		return scope
	}
	scope.DownstreamIdentity = firstNonEmptyAWSValue(scope.PrincipalARN, scope.NodeID, scope.RoleName)
	return scope
}

func awsMachineIdentityDetailGovernanceIdentityID(scope awsMachineIdentityDetailScope) string {
	if strings.TrimSpace(scope.NodeID) != "" {
		return strings.TrimSpace(scope.NodeID)
	}
	if strings.HasPrefix(scope.DownstreamIdentity, "aws:identity:unresolved:") {
		return scope.DownstreamIdentity
	}
	return ""
}

func awsMachineIdentityDetailFilterDownstreamEvidence(scope awsMachineIdentityDetailScope, runtime AWSRuntimeEventResult, permissions AWSLeastPrivilegeResult, secrets AWSSecretPermissionEquivalenceResult, blast AWSBlastRadiusResult, sprawl AWSIdentitySprawlResult, cases AWSRemediationCaseResult) (AWSRuntimeEventResult, AWSLeastPrivilegeResult, AWSSecretPermissionEquivalenceResult, AWSBlastRadiusResult, AWSIdentitySprawlResult, AWSRemediationCaseResult) {
	runtime = awsMachineIdentityDetailFilterRuntimeEvents(scope, runtime)
	permissions = awsMachineIdentityDetailFilterLeastPrivilege(scope, permissions)
	secrets = awsMachineIdentityDetailFilterSecrets(scope, secrets)
	blast = awsMachineIdentityDetailFilterBlastRadius(scope, blast)
	sprawl = awsMachineIdentityDetailFilterSprawl(scope, sprawl)
	cases = awsMachineIdentityDetailFilterRemediationCases(scope, cases)
	return runtime, permissions, secrets, blast, sprawl, cases
}

func awsMachineIdentityDetailFilterRuntimeEvents(scope awsMachineIdentityDetailScope, result AWSRuntimeEventResult) AWSRuntimeEventResult {
	allRecords := result.Records
	records := make([]AWSRuntimeEventRecord, 0, len(result.Records))
	for _, record := range result.Records {
		if !awsMachineIdentityDetailScopeMatches(scope,
			record.ActorPrincipalARN,
			record.ActorIdentityNodeID,
			record.Session.PrincipalARN,
			record.Session.AssumedRoleARN,
			record.Session.SessionIssuerARN,
			record.Session.OriginalActorARN,
			record.Session.OriginalActorNodeID,
			record.Session.ChainedFromPrincipalARN,
			record.Session.ChainedFromNodeID,
		) {
			continue
		}
		records = append(records, record)
	}
	result.Records = records
	result.Relationships = awsRuntimeEventRelationships(records)
	result.Diagnostics = scopeAWSRuntimeEventDiagnostics(result.Diagnostics, allRecords, records)
	result.Status, result.Confidence, result.FailureReasons, result.RemediationHints = summarizeAWSRuntimeEventStatus(result.FixtureState, result.Diagnostics, records)
	result.Summary = summarizeAWSRuntimeEvents(records, len(records), len(result.Relationships))
	return result
}

func awsMachineIdentityDetailFilterLeastPrivilege(scope awsMachineIdentityDetailScope, result AWSLeastPrivilegeResult) AWSLeastPrivilegeResult {
	recommendations := make([]AWSLeastPrivilegeRecommendation, 0, len(result.Recommendations))
	for _, recommendation := range result.Recommendations {
		if !awsMachineIdentityDetailScopeMatches(scope, awsLeastPrivilegeIdentityMatchValues(recommendation)...) {
			continue
		}
		recommendations = append(recommendations, recommendation)
	}
	result.Recommendations = recommendations
	result.Relationships = awsLeastPrivilegeRelationships(recommendations)
	result.Summary = summarizeAWSLeastPrivilege(recommendations, recommendations, result.Relationships)
	return result
}

func awsMachineIdentityDetailFilterSecrets(scope awsMachineIdentityDetailScope, result AWSSecretPermissionEquivalenceResult) AWSSecretPermissionEquivalenceResult {
	findings := make([]AWSSecretPermissionEquivalenceFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if !awsMachineIdentityDetailScopeMatches(scope, awsMachineIdentityDetailSecretIdentityValues(finding)...) {
			continue
		}
		findings = append(findings, finding)
	}
	result.Findings = findings
	result.Relationships = awsSecretPermissionEquivalenceRelationships(findings)
	result.Summary = summarizeAWSSecretPermissionEquivalence(findings, findings, result.Relationships)
	return result
}

func awsMachineIdentityDetailFilterBlastRadius(scope awsMachineIdentityDetailScope, result AWSBlastRadiusResult) AWSBlastRadiusResult {
	findings := make([]AWSBlastRadiusFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if !awsMachineIdentityDetailScopeMatches(scope, awsBlastRadiusIdentityMatchValues(finding)...) {
			continue
		}
		findings = append(findings, finding)
	}
	result.Findings = findings
	result.Relationships = awsBlastRadiusRelationships(findings)
	result.Summary = summarizeAWSBlastRadius(findings, findings, result.Relationships)
	return result
}

func awsMachineIdentityDetailFilterSprawl(scope awsMachineIdentityDetailScope, result AWSIdentitySprawlResult) AWSIdentitySprawlResult {
	findings := make([]AWSIdentitySprawlFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if !awsMachineIdentityDetailScopeMatches(scope, awsMachineIdentityDetailSprawlIdentityValues(finding)...) {
			continue
		}
		findings = append(findings, finding)
	}
	result.Findings = findings
	result.Clusters = awsMachineIdentityDetailFilterSprawlClusters(scope, result.Clusters, findings)
	result.Relationships = awsIdentitySprawlRelationships(findings)
	result.Summary = summarizeAWSIdentitySprawl(findings, result.Clusters, findings, result.Relationships, awsMachineIdentityDetailSprawlAggregates(findings))
	return result
}

func awsMachineIdentityDetailFilterRemediationCases(scope awsMachineIdentityDetailScope, result AWSRemediationCaseResult) AWSRemediationCaseResult {
	cases := make([]AWSRemediationCase, 0, len(result.Cases))
	for _, c := range result.Cases {
		if !awsMachineIdentityDetailScopeMatches(scope, awsMachineIdentityDetailRemediationCaseIdentityValues(c)...) {
			continue
		}
		cases = append(cases, c)
	}
	result.Cases = cases
	result.Relationships = awsRemediationCaseRelationships(cases)
	result.Summary = summarizeAWSRemediationCases(cases, cases, result.Relationships)
	return result
}

func awsMachineIdentityDetailScopeMatches(scope awsMachineIdentityDetailScope, values ...string) bool {
	if strings.TrimSpace(scope.PrincipalARN) != "" {
		return awsMachineIdentityMatches(scope.PrincipalARN, values...)
	}
	if strings.TrimSpace(scope.NodeID) != "" {
		return awsMachineIdentityMatches(scope.NodeID, values...)
	}
	if strings.TrimSpace(scope.RoleName) != "" {
		return awsMachineIdentityRoleNameMatches(scope.RoleName, values...)
	}
	return false
}

func awsMachineIdentityDetailSecretIdentityValues(finding AWSSecretPermissionEquivalenceFinding) []string {
	values := []string{
		finding.IdentityNodeID,
		finding.PrincipalARN,
		finding.WorkloadID,
		finding.WorkloadName,
		finding.AgentID,
		finding.AgentName,
	}
	for _, step := range finding.ImpactedPath {
		if strings.EqualFold(strings.TrimSpace(step.NodeType), "identity") {
			values = append(values, step.NodeID, step.Label)
		}
	}
	return dedupeStrings(values)
}

func awsMachineIdentityDetailSprawlIdentityValues(finding AWSIdentitySprawlFinding) []string {
	values := []string{
		finding.IdentityNodeID,
		finding.PrincipalARN,
		finding.RoleName,
		finding.DisplayName,
	}
	for _, step := range finding.ImpactedPath {
		if strings.EqualFold(strings.TrimSpace(step.NodeType), "identity") {
			values = append(values, step.NodeID, step.Label)
		}
	}
	return dedupeStrings(values)
}

func awsMachineIdentityDetailRemediationCaseIdentityValues(c AWSRemediationCase) []string {
	values := []string{
		c.IdentityNodeID,
		c.IdentityARN,
		c.IdentityName,
	}
	for _, step := range c.ImpactedPath {
		if strings.EqualFold(strings.TrimSpace(step.NodeType), "identity") {
			values = append(values, step.NodeID, step.Label)
		}
	}
	return dedupeStrings(values)
}

func awsMachineIdentityDetailFilterSprawlClusters(scope awsMachineIdentityDetailScope, clusters []AWSIdentitySprawlCluster, findings []AWSIdentitySprawlFinding) []AWSIdentitySprawlCluster {
	clusterIDs := map[string]struct{}{}
	identityNodeIDs := map[string]struct{}{}
	for _, finding := range findings {
		if finding.ClusterID != "" {
			clusterIDs[finding.ClusterID] = struct{}{}
		}
		if finding.IdentityNodeID != "" {
			identityNodeIDs[finding.IdentityNodeID] = struct{}{}
		}
	}
	out := make([]AWSIdentitySprawlCluster, 0, len(clusters))
	for _, cluster := range clusters {
		if _, ok := clusterIDs[cluster.ClusterID]; !ok {
			continue
		}
		ids := make([]string, 0, len(cluster.IdentityNodeIDs))
		for _, nodeID := range cluster.IdentityNodeIDs {
			if _, ok := identityNodeIDs[nodeID]; ok || awsMachineIdentityDetailScopeMatches(scope, nodeID) {
				ids = append(ids, nodeID)
			}
		}
		if len(ids) == 0 {
			continue
		}
		cluster.IdentityNodeIDs = ids
		out = append(out, cluster)
	}
	return out
}

func awsMachineIdentityDetailSprawlAggregates(findings []AWSIdentitySprawlFinding) map[string]*identitySprawlAggregate {
	aggregates := map[string]*identitySprawlAggregate{}
	for _, finding := range findings {
		key := firstNonEmptyAWSValue(finding.IdentityNodeID, finding.PrincipalARN, finding.RoleName, finding.DisplayName, finding.FindingID)
		if key == "" {
			continue
		}
		aggregate, ok := aggregates[key]
		if !ok {
			aggregate = &identitySprawlAggregate{
				roleARN:         finding.PrincipalARN,
				roleName:        finding.RoleName,
				accountID:       finding.AccountID,
				region:          finding.Region,
				owner:           finding.OwnerLabel,
				ownerSource:     finding.OwnerSource,
				workloadNodeIDs: map[string]struct{}{},
				workloadTypes:   map[string]struct{}{},
			}
			aggregates[key] = aggregate
		}
		for _, nodeID := range finding.WorkloadNodeIDs {
			if strings.TrimSpace(nodeID) != "" {
				aggregate.workloadNodeIDs[nodeID] = struct{}{}
			}
		}
		for _, workloadType := range finding.WorkloadTypes {
			if strings.TrimSpace(workloadType) != "" {
				aggregate.workloadTypes[workloadType] = struct{}{}
			}
		}
	}
	return aggregates
}

func awsMachineIdentityDetailScopeAccepts(scope awsMachineIdentityDetailScope, principalARN, nodeID, roleName string) bool {
	if scope.PrincipalARN != "" {
		return awsMachineIdentityMatches(scope.PrincipalARN, principalARN, nodeID, roleName)
	}
	if scope.NodeID != "" {
		return awsMachineIdentityMatches(scope.NodeID, principalARN, nodeID, roleName)
	}
	if scope.RoleName != "" {
		return awsMachineIdentityRoleNameMatches(scope.RoleName, principalARN, nodeID, roleName)
	}
	return false
}

func awsMachineIdentityRoleNameMatches(roleName string, candidates ...string) bool {
	roleName = strings.ToLower(strings.TrimSpace(roleName))
	if roleName == "" {
		return true
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		candidateLower := strings.ToLower(candidate)
		switch {
		case candidateLower == roleName:
			return true
		case strings.HasPrefix(candidateLower, "arn:") && strings.ToLower(shortAWSARN(candidate)) == roleName:
			return true
		case strings.HasPrefix(candidateLower, "aws:identity:arn:"):
			arn := strings.TrimPrefix(candidate, "aws:identity:")
			if strings.ToLower(shortAWSARN(arn)) == roleName {
				return true
			}
		}
	}
	return false
}

func awsMachineIdentityDetailAppliedFilters(request AWSMachineIdentityDetailRequest, identityNodeID string) map[string]string {
	filters := map[string]string{
		"connector_id":     strings.TrimSpace(request.ConnectorID),
		"fixture_state":    strings.TrimSpace(request.FixtureState),
		"identity":         strings.TrimSpace(request.Identity),
		"identity_node_id": strings.TrimSpace(identityNodeID),
		"account_id":       strings.TrimSpace(request.AccountID),
		"region":           strings.TrimSpace(request.Region),
		"tab":              normalizeAWSRuntimeEventFilterToken(request.Tab),
		"service":          normalizeAWSRuntimeEventFilterToken(request.Service),
		"resource":         strings.TrimSpace(request.Resource),
		"severity":         normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":           normalizeAWSRuntimeEventFilterToken(request.Status),
	}
	for key, value := range filters {
		if strings.TrimSpace(value) == "" || strings.EqualFold(value, "all") {
			delete(filters, key)
		}
	}
	return filters
}

func awsMachineIdentityDetailBindings(
	identity string,
	bindingScope awsMachineIdentityDetailBindingScope,
	ec2 AWSEC2InstanceProfileInventoryResult,
	ecs AWSECSTaskRoleInventoryResult,
	lambda AWSLambdaExecutionRoleInventoryResult,
	codeBuild AWSCodeBuildServiceRoleInventoryResult,
	codePipeline AWSCodePipelineDeploymentRoleInventoryResult,
	stepFunctions AWSStepFunctionsStateMachineRoleInventoryResult,
	eventDriven AWSEventDrivenRoleInventoryResult,
	managedCompute AWSManagedComputeRoleInventoryResult,
	eks AWSEKSWorkloadIdentityInventoryResult,
) []AWSMachineIdentityWorkloadBinding {
	bindings := []AWSMachineIdentityWorkloadBinding{}
	for _, record := range ec2.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.InstanceProfileARN, record.InstanceProfileName, record.WorkloadID, record.WorkloadName) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding("ec2", record.WorkloadID, record.WorkloadType, firstNonEmptyAWSValue(record.InstanceName, record.LaunchTemplateName, record.WorkloadName), record.RoleARN, record.RoleName, "instance_profile", "runs_as", record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	for _, record := range ecs.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.TaskRoleARN, record.ExecutionRoleARN, record.WorkloadID, record.WorkloadName, record.ServiceName, record.TaskDefinitionFamily) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding("ecs", record.WorkloadID, record.WorkloadType, firstNonEmptyAWSValue(record.ServiceName, record.TaskDefinitionFamily, record.WorkloadName), record.RoleARN, record.RoleName, record.RoleKind, record.RelationshipType, record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	for _, record := range lambda.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.FunctionARN, record.FunctionName, record.WorkloadID, record.WorkloadName) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding("lambda", record.WorkloadID, record.WorkloadType, firstNonEmptyAWSValue(record.FunctionName, record.WorkloadName), record.RoleARN, record.RoleName, "execution_role", record.RelationshipType, record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	for _, record := range codeBuild.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.ProjectARN, record.ProjectName, record.WorkloadID, record.WorkloadName) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding("codebuild", record.WorkloadID, record.WorkloadType, firstNonEmptyAWSValue(record.ProjectName, record.WorkloadName), record.RoleARN, record.RoleName, "service_role", record.RelationshipType, record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	for _, record := range codePipeline.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.PipelineARN, record.PipelineName, record.WorkloadID, record.WorkloadName) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding("codepipeline", record.WorkloadID, record.WorkloadType, firstNonEmptyAWSValue(record.PipelineName, record.WorkloadName), record.RoleARN, record.RoleName, record.RoleKind, record.RelationshipType, record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	for _, record := range stepFunctions.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.StateMachineARN, record.StateMachineName, record.WorkloadID, record.WorkloadName) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding("stepfunctions", record.WorkloadID, record.WorkloadType, firstNonEmptyAWSValue(record.StateMachineName, record.WorkloadName), record.RoleARN, record.RoleName, "state_machine_role", record.RelationshipType, record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	for _, record := range eventDriven.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.WorkloadARN, record.WorkloadName, record.WorkloadID, record.TargetARN) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding(record.Service, record.WorkloadID, record.WorkloadType, record.WorkloadName, record.RoleARN, record.RoleName, record.RoleKind, record.RelationshipType, record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	for _, record := range managedCompute.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.WorkloadARN, record.WorkloadName, record.WorkloadID, record.ResourceARN) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding(record.Service, record.WorkloadID, record.WorkloadType, record.WorkloadName, record.RoleARN, record.RoleName, record.RoleKind, record.RelationshipType, record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	for _, record := range eks.Records {
		if !bindingScope.accepts(record.AccountID, record.Region) || !awsMachineIdentityMatches(identity, record.RoleARN, record.RoleName, record.ToNodeID, record.TargetRoleARN, record.NodeRoleARN, record.PodExecutionRoleARN, record.WorkloadID, record.WorkloadName, record.KubernetesSubject, record.ServiceAccount) {
			continue
		}
		bindings = append(bindings, awsMachineIdentityBinding("eks", record.WorkloadID, record.WorkloadType, firstNonEmptyAWSValue(record.KubernetesSubject, record.ServiceAccount, record.WorkloadName), record.RoleARN, record.RoleName, record.RoleKind, record.RelationshipType, record.FromNodeID, record.ToNodeID, record.EvidenceRef, record.Status, record.Confidence, record.CollectedAt))
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		if bindings[i].Service == bindings[j].Service {
			return bindings[i].BindingID < bindings[j].BindingID
		}
		return bindings[i].Service < bindings[j].Service
	})
	return bindings
}

func awsMachineIdentityBinding(service, workloadID, workloadType, workloadName, roleARN, roleName, roleKind, relationshipType, fromNodeID, toNodeID, evidenceRef, status string, confidence float64, collectedAt time.Time) AWSMachineIdentityWorkloadBinding {
	return AWSMachineIdentityWorkloadBinding{
		BindingID:        "aws-machine-identity-binding:" + stableAWSBlastRadiusToken(service, workloadID, roleARN, roleName, fromNodeID, toNodeID, evidenceRef),
		Service:          service,
		WorkloadID:       workloadID,
		WorkloadType:     workloadType,
		WorkloadName:     workloadName,
		RoleARN:          roleARN,
		RoleName:         roleName,
		RoleKind:         roleKind,
		RelationshipType: relationshipType,
		FromNodeID:       fromNodeID,
		ToNodeID:         toNodeID,
		EvidenceRef:      evidenceRef,
		Status:           status,
		Confidence:       confidence,
		CollectedAt:      collectedAt,
	}
}

func awsMachineIdentityMatches(identity string, candidates ...string) bool {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return true
	}
	identityLower := strings.ToLower(identity)
	nodeIDLower := strings.ToLower(awsMachineIdentityDetailNodeID(identity))
	shortLower := strings.ToLower(awsMachineIdentityDetailFilterToken(identity))
	for _, candidate := range candidates {
		candidateLower := strings.ToLower(strings.TrimSpace(candidate))
		if candidateLower == "" {
			continue
		}
		if candidateLower == identityLower || candidateLower == nodeIDLower || candidateLower == shortLower {
			return true
		}
		if strings.HasPrefix(identityLower, "arn:") && strings.HasPrefix(candidateLower, "aws:identity:") && strings.TrimPrefix(candidateLower, "aws:identity:") == identityLower {
			return true
		}
		if strings.HasPrefix(identityLower, "aws:identity:arn:") && strings.HasPrefix(candidateLower, "arn:") && strings.TrimPrefix(identityLower, "aws:identity:") == candidateLower {
			return true
		}
	}
	return false
}

func awsMachineIdentityPermissionSummaries(recommendations []AWSLeastPrivilegeRecommendation) []AWSMachineIdentityPermissionSummary {
	out := make([]AWSMachineIdentityPermissionSummary, 0, len(recommendations))
	for _, recommendation := range recommendations {
		actions := dedupeStrings(append(append(append([]string{}, recommendation.GrantedActions...), recommendation.ObservedActions...), append(recommendation.KeepActions, recommendation.RemoveActions...)...))
		out = append(out, AWSMachineIdentityPermissionSummary{
			RecommendationID: recommendation.RecommendationID,
			Decision:         recommendation.Decision,
			Severity:         recommendation.Severity,
			Status:           recommendation.Status,
			Service:          recommendation.Service,
			ResourceARN:      recommendation.ResourceARN,
			DisplayName:      recommendation.DisplayName,
			Actions:          actions,
			Rationale:        recommendation.Rationale,
			NextAction:       recommendation.NextAction,
			Score:            recommendation.Score,
		})
	}
	return out
}

func awsMachineIdentityResourcesReached(runtime AWSRuntimeEventResult, permissions AWSLeastPrivilegeResult, secrets AWSSecretPermissionEquivalenceResult, blast AWSBlastRadiusResult) []AWSMachineIdentityResourceSummary {
	out := []AWSMachineIdentityResourceSummary{}
	seen := map[string]bool{}
	add := func(source, id, arn, resourceType, label, evidenceRef string, observedAt time.Time) {
		key := strings.ToLower(strings.TrimSpace(firstNonEmptyAWSValue(id, arn, label)))
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, AWSMachineIdentityResourceSummary{ResourceID: id, ResourceARN: arn, ResourceType: resourceType, Label: firstNonEmptyAWSValue(label, shortAWSARN(arn), id), Source: source, EvidenceRef: evidenceRef, ObservedAt: observedAt})
	}
	for _, record := range runtime.Records {
		add("runtime", record.ResourceNodeID, record.TargetResourceARN, record.TargetResourceType, record.TargetResourceName, record.EvidenceRef, record.ObservedAt)
	}
	for _, recommendation := range permissions.Recommendations {
		add("permissions", recommendation.ResourceNodeID, recommendation.ResourceARN, recommendation.Service, recommendation.DisplayName, firstLeastPrivilegeEvidenceRef(recommendation.Evidence), recommendation.UpdatedAt)
	}
	for _, finding := range secrets.Findings {
		add("secrets", finding.SecretNodeID, finding.SecretARN, "secret", finding.SecretLabel, firstLeastPrivilegeEvidenceRef(finding.Evidence), finding.UpdatedAt)
	}
	for _, finding := range blast.Findings {
		for _, node := range finding.SensitiveNodes {
			add("blast_radius", node, "", "sensitive_resource", node, firstBlastRadiusEvidenceRef(finding.Evidence), finding.UpdatedAt)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source == out[j].Source {
			return out[i].Label < out[j].Label
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func awsMachineIdentityFindingSummaries(secrets AWSSecretPermissionEquivalenceResult, blast AWSBlastRadiusResult, sprawl AWSIdentitySprawlResult) []AWSMachineIdentityFindingSummary {
	out := []AWSMachineIdentityFindingSummary{}
	for _, finding := range blast.Findings {
		out = append(out, AWSMachineIdentityFindingSummary{
			FindingID:    finding.FindingID,
			Source:       "blast_radius",
			FindingType:  finding.RiskType,
			Severity:     finding.Severity,
			Status:       finding.Status,
			Score:        finding.Score,
			Title:        finding.DisplayName,
			Summary:      finding.Rationale,
			EvidenceRefs: awsBlastRadiusEvidenceRefs(finding.Evidence),
			NextAction:   finding.NextAction,
		})
	}
	for _, finding := range sprawl.Findings {
		out = append(out, AWSMachineIdentityFindingSummary{
			FindingID:    finding.FindingID,
			Source:       "identity_sprawl",
			FindingType:  finding.FindingType,
			Severity:     finding.Severity,
			Status:       finding.Status,
			Score:        finding.Score,
			Title:        finding.DisplayName,
			Summary:      finding.Rationale,
			EvidenceRefs: awsLeastPrivilegeEvidenceRefs(finding.Evidence),
			NextAction:   finding.NextAction,
		})
	}
	for _, finding := range secrets.Findings {
		out = append(out, AWSMachineIdentityFindingSummary{
			FindingID:    finding.FindingID,
			Source:       "secret_permission_equivalence",
			FindingType:  finding.EquivalenceType,
			Severity:     finding.Severity,
			Status:       finding.Status,
			Score:        finding.Score,
			Title:        finding.SecretLabel,
			Summary:      finding.Rationale,
			EvidenceRefs: awsLeastPrivilegeEvidenceRefs(finding.Evidence),
			NextAction:   finding.NextAction,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].FindingID < out[j].FindingID
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func awsMachineIdentityGovernanceDecisions(records []AWSGovernanceAuditReportRecord) []AWSMachineIdentityGovernanceDecision {
	out := make([]AWSMachineIdentityGovernanceDecision, 0, len(records))
	for _, record := range records {
		out = append(out, AWSMachineIdentityGovernanceDecision{
			ReportID:     record.ReportID,
			Category:     record.Category,
			DecisionType: record.DecisionType,
			State:        record.State,
			Title:        record.Title,
			Summary:      record.Summary,
			Actor:        record.Actor,
			Approver:     record.Approver,
			EvidenceRefs: append([]string{}, record.EvidenceLinks...),
			OccurredAt:   record.OccurredAt,
		})
	}
	return out
}

func awsMachineIdentityDetailRelationships(bindings []AWSMachineIdentityWorkloadBinding, runtime AWSRuntimeEventResult, permissions AWSLeastPrivilegeResult, secrets AWSSecretPermissionEquivalenceResult, blast AWSBlastRadiusResult, sprawl AWSIdentitySprawlResult, cases AWSRemediationCaseResult, governance AWSGovernanceAuditReportingResult) []AWSMachineIdentityDetailRelationship {
	out := []AWSMachineIdentityDetailRelationship{}
	add := func(source, typ, from, to, evidence string) {
		if strings.TrimSpace(from) == "" || strings.TrimSpace(to) == "" {
			return
		}
		out = append(out, AWSMachineIdentityDetailRelationship{Source: source, Type: typ, FromNodeID: from, ToNodeID: to, EvidenceRef: evidence})
	}
	for _, binding := range bindings {
		add("workload_binding", firstNonEmptyAWSValue(binding.RelationshipType, "runs_as"), binding.FromNodeID, binding.ToNodeID, binding.EvidenceRef)
	}
	for _, rel := range runtime.Relationships {
		add("runtime", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
	}
	for _, rel := range permissions.Relationships {
		add("permissions", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
	}
	for _, rel := range secrets.Relationships {
		add("secrets", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
	}
	for _, rel := range blast.Relationships {
		add("blast_radius", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
	}
	for _, rel := range sprawl.Relationships {
		add("identity_sprawl", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
	}
	for _, rel := range cases.Relationships {
		add("remediation_cases", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
	}
	for _, record := range governance.Records {
		for _, evidence := range record.EvidenceLinks {
			add("governance", record.Category, record.IdentityNodeID, record.SourceID, evidence)
		}
	}
	return awsMachineIdentityDedupeRelationships(out)
}

func awsMachineIdentityDedupeRelationships(items []AWSMachineIdentityDetailRelationship) []AWSMachineIdentityDetailRelationship {
	seen := map[string]bool{}
	out := []AWSMachineIdentityDetailRelationship{}
	for _, item := range items {
		key := strings.Join([]string{item.Source, item.Type, item.FromNodeID, item.ToNodeID, item.EvidenceRef}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func awsMachineIdentityDetailIdentity(identity string, identityNodeID string, accountID string, region string, status string, confidence float64, bindings []AWSMachineIdentityWorkloadBinding, runtime AWSRuntimeEventResult, permissions AWSLeastPrivilegeResult, secrets AWSSecretPermissionEquivalenceResult, blast AWSBlastRadiusResult, sprawl AWSIdentitySprawlResult, cases AWSRemediationCaseResult) AWSMachineIdentityDetailIdentity {
	principalARN := ""
	roleName := ""
	if strings.HasPrefix(strings.ToLower(identity), "arn:") {
		principalARN = identity
	}
	for _, binding := range bindings {
		principalARN = firstNonEmptyAWSValue(principalARN, binding.RoleARN)
		roleName = firstNonEmptyAWSValue(roleName, binding.RoleName)
	}
	for _, record := range runtime.Records {
		principalARN = firstNonEmptyAWSValue(principalARN, record.ActorPrincipalARN, record.Session.SessionIssuerARN, record.Session.AssumedRoleARN)
	}
	for _, recommendation := range permissions.Recommendations {
		principalARN = firstNonEmptyAWSValue(principalARN, recommendation.PrincipalARN)
		roleName = firstNonEmptyAWSValue(roleName, shortAWSARN(recommendation.PrincipalARN))
	}
	for _, finding := range secrets.Findings {
		principalARN = firstNonEmptyAWSValue(principalARN, finding.PrincipalARN)
	}
	for _, finding := range blast.Findings {
		principalARN = firstNonEmptyAWSValue(principalARN, finding.PrincipalARN)
	}
	for _, finding := range sprawl.Findings {
		principalARN = firstNonEmptyAWSValue(principalARN, finding.PrincipalARN)
		roleName = firstNonEmptyAWSValue(roleName, finding.RoleName)
	}
	for _, c := range cases.Cases {
		principalARN = firstNonEmptyAWSValue(principalARN, c.IdentityARN)
		roleName = firstNonEmptyAWSValue(roleName, c.IdentityName)
	}
	roleName = firstNonEmptyAWSValue(roleName, shortAWSARN(principalARN), shortAWSARN(identity))
	displayName := firstNonEmptyAWSValue(roleName, principalARN, identityNodeID, identity)
	return AWSMachineIdentityDetailIdentity{
		Identity:         identity,
		IdentityNodeID:   identityNodeID,
		PrincipalARN:     principalARN,
		RoleName:         roleName,
		DisplayName:      displayName,
		AccountID:        accountID,
		Region:           region,
		Status:           status,
		Confidence:       confidence,
		EvidenceBoundary: "metadata_only_no_secret_values_no_policy_bodies_no_payloads",
	}
}

func summarizeAWSMachineIdentityDetail(fixtureState string, bindings []AWSMachineIdentityWorkloadBinding, runtime AWSRuntimeEventResult, permissions AWSLeastPrivilegeResult, secrets AWSSecretPermissionEquivalenceResult, blast AWSBlastRadiusResult, sprawl AWSIdentitySprawlResult, cases AWSRemediationCaseResult, governance AWSGovernanceAuditReportingResult, diagnostics []AWSMachineIdentityDetailDiagnostic) (string, float64, []string, []string) {
	dataCount := len(bindings) + len(runtime.Records) + len(permissions.Recommendations) + len(secrets.Findings) + len(blast.Findings) + len(sprawl.Findings) + len(cases.Cases) + len(governance.Records)
	statuses := []string{runtime.Status, permissions.Status, secrets.Status, blast.Status, sprawl.Status, cases.Status, governance.Status}
	failures := []string{}
	hints := []string{}
	if fixtureState == "permission_denied" {
		failures = append(failures, "Identity detail evidence is blocked by AWS permission checks for this connector.")
		hints = append(hints, "Validate the connector role permissions and retry the detail page.")
		return "blocked", 0.35, failures, hints
	}
	if dataCount == 0 {
		return "empty", 0.72, []string{"No matching workload, runtime, risk, remediation, or governance evidence was found for this identity."}, []string{"Check the identity ARN or select a role from the AWS identity inventory."}
	}
	for _, status := range statuses {
		if normalizeAWSRuntimeEventFilterToken(status) == "blocked" {
			return "degraded", 0.62, failures, hints
		}
	}
	for _, status := range statuses {
		if normalizeAWSRuntimeEventFilterToken(status) == "degraded" {
			return "degraded", 0.72, failures, hints
		}
	}
	if len(diagnostics) > 0 || fixtureState == "degraded" || fixtureState == "partial_failure" {
		return "degraded", 0.74, failures, hints
	}
	return "ready", 0.91, failures, hints
}

func awsMachineIdentityDetailTabs(summary AWSMachineIdentityDetailSummary, status string) []AWSMachineIdentityDetailTab {
	tabStatus := func(count int) string {
		if count == 0 {
			return "empty"
		}
		return status
	}
	return []AWSMachineIdentityDetailTab{
		{ID: "graph", Label: "Graph", Status: tabStatus(summary.RelationshipCount), Count: summary.RelationshipCount},
		{ID: "runtime", Label: "Runtime", Status: tabStatus(summary.RuntimeEventCount), Count: summary.RuntimeEventCount},
		{ID: "permissions", Label: "Permissions", Status: tabStatus(summary.PermissionRecommendationCount), Count: summary.PermissionRecommendationCount},
		{ID: "secrets", Label: "Secrets", Status: tabStatus(summary.SecretFindingCount), Count: summary.SecretFindingCount},
		{ID: "fixes", Label: "Fixes", Status: tabStatus(summary.RemediationCaseCount), Count: summary.RemediationCaseCount},
		{ID: "governance", Label: "Governance", Status: tabStatus(summary.GovernanceDecisionCount), Count: summary.GovernanceDecisionCount},
	}
}

func awsMachineIdentityDetailEvidenceLinks(identity string, inventories ...interface{}) []string {
	links := []string{
		awsIssueURL(awsPlatformDependencyParentIssue),
		awsIssueURL(awsMachineIdentityDetailCurrentIssue),
		"/docs/aws-machine-identity-detail",
		"/docs/aws-service-collector-contract",
	}
	for _, item := range inventories {
		switch v := item.(type) {
		case AWSEC2InstanceProfileInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSECSTaskRoleInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSLambdaExecutionRoleInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSCodeBuildServiceRoleInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSCodePipelineDeploymentRoleInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSStepFunctionsStateMachineRoleInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSEventDrivenRoleInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSManagedComputeRoleInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSEKSWorkloadIdentityInventoryResult:
			links = append(links, v.EvidenceLinks...)
		case AWSRuntimeEventResult:
			links = append(links, v.EvidenceLinks...)
		case AWSLeastPrivilegeResult:
			links = append(links, v.EvidenceLinks...)
		case AWSSecretPermissionEquivalenceResult:
			links = append(links, v.EvidenceLinks...)
		case AWSBlastRadiusResult:
			links = append(links, v.EvidenceLinks...)
		case AWSIdentitySprawlResult:
			links = append(links, v.EvidenceLinks...)
		case AWSRemediationCaseResult:
			links = append(links, v.EvidenceLinks...)
		case AWSGovernanceAuditReportingResult:
			links = append(links, v.EvidenceLinks...)
		}
	}
	links = append(links, identity, awsMachineIdentityDetailNodeID(identity))
	return dedupeStrings(links)
}

func awsMachineIdentityDetailFailureReasons(results ...interface{}) []string {
	out := []string{}
	for _, item := range results {
		switch v := item.(type) {
		case AWSRuntimeEventResult:
			out = append(out, v.FailureReasons...)
		case AWSLeastPrivilegeResult:
			out = append(out, v.FailureReasons...)
		case AWSSecretPermissionEquivalenceResult:
			out = append(out, v.FailureReasons...)
		case AWSBlastRadiusResult:
			out = append(out, v.FailureReasons...)
		case AWSIdentitySprawlResult:
			out = append(out, v.FailureReasons...)
		case AWSRemediationCaseResult:
			out = append(out, v.FailureReasons...)
		case AWSGovernanceAuditReportingResult:
			out = append(out, v.FailureReasons...)
		}
	}
	return dedupeStrings(out)
}

func awsMachineIdentityDetailRemediationHints(results ...interface{}) []string {
	out := []string{}
	for _, item := range results {
		switch v := item.(type) {
		case AWSRuntimeEventResult:
			out = append(out, v.RemediationHints...)
		case AWSLeastPrivilegeResult:
			out = append(out, v.RemediationHints...)
		case AWSSecretPermissionEquivalenceResult:
			out = append(out, v.RemediationHints...)
		case AWSBlastRadiusResult:
			out = append(out, v.RemediationHints...)
		case AWSIdentitySprawlResult:
			out = append(out, v.RemediationHints...)
		case AWSRemediationCaseResult:
			out = append(out, v.RemediationHints...)
		case AWSGovernanceAuditReportingResult:
			out = append(out, v.RemediationHints...)
		}
	}
	return dedupeStrings(out)
}

func awsMachineIdentityDetailDiagnostics(results ...interface{}) []AWSMachineIdentityDetailDiagnostic {
	out := []AWSMachineIdentityDetailDiagnostic{}
	add := func(collector, sourceID, code, message, remediation string, retryable bool) {
		if strings.TrimSpace(code) == "" && strings.TrimSpace(message) == "" {
			return
		}
		out = append(out, AWSMachineIdentityDetailDiagnostic{Collector: collector, SourceID: sourceID, Code: code, Message: message, Remediation: remediation, Retryable: retryable})
	}
	for _, item := range results {
		switch v := item.(type) {
		case AWSEC2InstanceProfileInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSECSTaskRoleInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSLambdaExecutionRoleInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSCodeBuildServiceRoleInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSCodePipelineDeploymentRoleInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSStepFunctionsStateMachineRoleInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSEventDrivenRoleInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSManagedComputeRoleInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSEKSWorkloadIdentityInventoryResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSRuntimeEventResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSLeastPrivilegeResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSSecretPermissionEquivalenceResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSBlastRadiusResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSIdentitySprawlResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSRemediationCaseResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		case AWSGovernanceAuditReportingResult:
			for _, d := range v.Diagnostics {
				add(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
			}
		}
	}
	return awsMachineIdentityDedupeDiagnostics(out)
}

func awsMachineIdentityDedupeDiagnostics(items []AWSMachineIdentityDetailDiagnostic) []AWSMachineIdentityDetailDiagnostic {
	seen := map[string]bool{}
	out := []AWSMachineIdentityDetailDiagnostic{}
	for _, item := range items {
		key := strings.Join([]string{strings.ToLower(item.Collector), strings.ToLower(item.SourceID), strings.ToLower(item.Code), strings.ToLower(item.Message)}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func awsMachineIdentityDetailCoverageGaps(results ...interface{}) []AWSMachineIdentityDetailCoverageGap {
	out := []AWSMachineIdentityDetailCoverageGap{}
	seen := map[string]bool{}
	add := func(capability, status, reason, remediation string) {
		if strings.TrimSpace(capability) == "" && strings.TrimSpace(reason) == "" {
			return
		}
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(capability)),
			strings.ToLower(strings.TrimSpace(status)),
			strings.ToLower(strings.TrimSpace(reason)),
			strings.ToLower(strings.TrimSpace(remediation)),
		}, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, AWSMachineIdentityDetailCoverageGap{Capability: capability, Status: status, Reason: reason, Remediation: remediation})
	}
	for _, item := range results {
		switch v := item.(type) {
		case AWSRuntimeEventResult:
			for _, gap := range v.CoverageGaps {
				add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
			}
		case AWSLeastPrivilegeResult:
			for _, gap := range v.CoverageGaps {
				add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
			}
		case AWSSecretPermissionEquivalenceResult:
			for _, gap := range v.CoverageGaps {
				add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
			}
		case AWSBlastRadiusResult:
			for _, gap := range v.CoverageGaps {
				add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
			}
		case AWSIdentitySprawlResult:
			for _, gap := range v.CoverageGaps {
				add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
			}
		case AWSRemediationCaseResult:
			for _, gap := range v.CoverageGaps {
				add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
			}
		case AWSGovernanceAuditReportingResult:
			for _, gap := range v.CoverageGaps {
				add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
			}
		}
	}
	return out
}

func awsLeastPrivilegeEvidenceRefs(items []AWSLeastPrivilegeEvidence) []string {
	out := []string{}
	for _, item := range items {
		out = append(out, item.EvidenceRef)
	}
	return dedupeStrings(out)
}

func awsBlastRadiusEvidenceRefs(items []AWSBlastRadiusEvidence) []string {
	out := []string{}
	for _, item := range items {
		out = append(out, item.EvidenceRef)
	}
	return dedupeStrings(out)
}

func firstBlastRadiusEvidenceRef(items []AWSBlastRadiusEvidence) string {
	for _, item := range items {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			return item.EvidenceRef
		}
	}
	return ""
}
