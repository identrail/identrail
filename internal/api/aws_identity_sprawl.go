package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsIdentitySprawlCurrentIssue = 1524
	awsIdentitySprawlVersion      = "aws-identity-sprawl-engine-v1"
)

// AWSIdentitySprawlRequest scopes the sprawl calculation to AWS evidence and
// optional operator drill-down filters.
type AWSIdentitySprawlRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Identity     string `json:"identity,omitempty"`
	Owner        string `json:"owner,omitempty"`
	Cluster      string `json:"cluster,omitempty"`
	FindingType  string `json:"finding_type,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Status       string `json:"status,omitempty"`
}

// Reuse the least-privilege evidence/path/preview/diagnostic/coverage-gap
// types so consumers can render every Wave 6.x engine with the same shape.
type AWSIdentitySprawlEvidence = AWSLeastPrivilegeEvidence
type AWSIdentitySprawlPathStep = AWSLeastPrivilegePathStep
type AWSIdentitySprawlRemediationCasePreview = AWSLeastPrivilegeRemediationCasePreview
type AWSIdentitySprawlDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSIdentitySprawlCoverageGap = AWSLeastPrivilegeCoverageGap

// AWSIdentitySprawlRelationship lets graph consumers join sprawl findings back
// to identity, workload, owner-cluster, and evidence nodes.
type AWSIdentitySprawlRelationship struct {
	FindingID   string `json:"finding_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSIdentitySprawlCluster groups identities the engine considered together
// (e.g. duplicates with similar policy/workload signatures, or members of a
// shared role's blast radius).
type AWSIdentitySprawlCluster struct {
	ClusterID       string   `json:"cluster_id"`
	ClusterKind     string   `json:"cluster_kind"`
	IdentityNodeIDs []string `json:"identity_node_ids"`
	WorkloadTypes   []string `json:"workload_types,omitempty"`
	SignatureHint   string   `json:"signature_hint,omitempty"`
}

// AWSIdentitySprawlFinding is the persisted-record-shaped output for the four
// sprawl finding types: stale, ownerless, duplicate, shared.
type AWSIdentitySprawlFinding struct {
	FindingID          string                                  `json:"finding_id"`
	CalculationVersion string                                  `json:"calculation_version"`
	FindingType        string                                  `json:"finding_type"`
	Severity           string                                  `json:"severity"`
	Status             string                                  `json:"status"`
	Score              int                                     `json:"score"`
	Confidence         float64                                 `json:"confidence"`
	AccountID          string                                  `json:"account_id"`
	Region             string                                  `json:"region"`
	IdentityNodeID     string                                  `json:"identity_node_id"`
	PrincipalARN       string                                  `json:"principal_arn,omitempty"`
	RoleName           string                                  `json:"role_name,omitempty"`
	DisplayName        string                                  `json:"display_name"`
	OwnerLabel         string                                  `json:"owner_label,omitempty"`
	OwnerSource        string                                  `json:"owner_source"`
	WorkloadTypes      []string                                `json:"workload_types,omitempty"`
	WorkloadNodeIDs    []string                                `json:"workload_node_ids,omitempty"`
	ClusterID          string                                  `json:"cluster_id,omitempty"`
	ClusterKind        string                                  `json:"cluster_kind,omitempty"`
	Rationale          string                                  `json:"rationale"`
	ImpactedNodes      []string                                `json:"impacted_nodes"`
	ImpactedPath       []AWSIdentitySprawlPathStep             `json:"impacted_path"`
	Evidence           []AWSIdentitySprawlEvidence             `json:"evidence"`
	NextAction         string                                  `json:"next_action"`
	RemediationCase    AWSIdentitySprawlRemediationCasePreview `json:"remediation_case"`
	CreatedAt          time.Time                               `json:"created_at"`
	UpdatedAt          time.Time                               `json:"updated_at"`
}

// AWSIdentitySprawlSummary aggregates the unfiltered and filtered finding set.
type AWSIdentitySprawlSummary struct {
	TotalFindings           int            `json:"total_findings"`
	FilteredFindings        int            `json:"filtered_findings"`
	FindingTypeCounts       map[string]int `json:"finding_type_counts"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	StatusCounts            map[string]int `json:"status_counts"`
	OwnerSourceCounts       map[string]int `json:"owner_source_counts"`
	StaleIdentityCount      int            `json:"stale_identity_count"`
	OwnerlessIdentityCount  int            `json:"ownerless_identity_count"`
	DuplicateClusterCount   int            `json:"duplicate_cluster_count"`
	SharedRoleCount         int            `json:"shared_role_count"`
	UniqueIdentityCount     int            `json:"unique_identity_count"`
	UniqueWorkloadCount     int            `json:"unique_workload_count"`
	RelationshipCount       int            `json:"relationship_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
	RemediationPreviewCount int            `json:"remediation_preview_count"`
}

// AWSIdentitySprawlResult is the deterministic envelope.
type AWSIdentitySprawlResult struct {
	TenantID           string                          `json:"tenant_id"`
	WorkspaceID        string                          `json:"workspace_id"`
	ProjectID          string                          `json:"project_id"`
	ConnectorID        string                          `json:"connector_id,omitempty"`
	AccountID          string                          `json:"account_id,omitempty"`
	Region             string                          `json:"region,omitempty"`
	ParentIssueNumber  int                             `json:"parent_issue_number"`
	ParentIssueRef     string                          `json:"parent_issue_ref"`
	CurrentIssueNumber int                             `json:"current_issue_number"`
	CurrentIssueRef    string                          `json:"current_issue_ref"`
	Version            string                          `json:"version"`
	Status             string                          `json:"status"`
	FixtureState       string                          `json:"fixture_state,omitempty"`
	Confidence         float64                         `json:"confidence"`
	CalculationVersion string                          `json:"calculation_version"`
	AppliedFilters     map[string]string               `json:"applied_filters"`
	Summary            AWSIdentitySprawlSummary        `json:"summary"`
	Findings           []AWSIdentitySprawlFinding      `json:"findings"`
	Clusters           []AWSIdentitySprawlCluster      `json:"clusters"`
	Relationships      []AWSIdentitySprawlRelationship `json:"relationships"`
	Caveats            []string                        `json:"caveats"`
	FailureReasons     []string                        `json:"failure_reasons"`
	RemediationHints   []string                        `json:"remediation_hints"`
	EvidenceLinks      []string                        `json:"evidence_links"`
	CoverageGaps       []AWSIdentitySprawlCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSIdentitySprawlDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                       `json:"generated_at"`
	UpdatedAt          time.Time                       `json:"updated_at"`
}

// identitySprawlAggregate is the internal per-role view assembled across every
// identity-bearing inventory before classification. It deliberately holds only
// metadata fields — never principal credentials or workload payloads.
type identitySprawlAggregate struct {
	roleARN         string
	roleName        string
	accountID       string
	region          string
	owner           string
	ownerSource     string
	workloadNodeIDs map[string]struct{}
	workloadTypes   map[string]struct{}
	workloadLabels  map[string]struct{}
	tagKeys         map[string]struct{}
	evidenceRefs    map[string]struct{}
	observed        bool
	observedAt      time.Time
}

// GetAWSIdentitySprawl calculates ranked sprawl findings (stale, ownerless,
// duplicate, shared) from existing IAM identity-bearing inventories joined
// with runtime-access correlations. It preserves uncertainty: absent or
// degraded evidence holds findings in `review` status rather than promoting
// them to cleanup candidates.
func (s *Service) GetAWSIdentitySprawl(ctx context.Context, workspaceID string, projectID string, request AWSIdentitySprawlRequest) (AWSIdentitySprawlResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSIdentitySprawlResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSIdentitySprawlResult{}, err
	}
	now := s.Now().UTC()

	fixtureState := normalizeAWSIdentitySprawlFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSIdentitySprawlResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))

	sourceFixtureState := fixtureState
	sourceReaderFixtureState := fixtureState
	liveInventoryUnavailable := false
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
		sourceReaderFixtureState = "empty"
		liveInventoryUnavailable = true
	}

	aggregates, diagnostics, coverageGaps, failureReasons, remediationHints, sourceStatuses, err := s.awsIdentitySprawlSourceSignals(ctx, workspaceID, projectID, connectorID, sourceReaderFixtureState)
	if err != nil {
		return AWSIdentitySprawlResult{}, err
	}
	if liveInventoryUnavailable {
		diagnostics = append(diagnostics, AWSIdentitySprawlDiagnostic{
			Collector:   "aws_identity_sprawl",
			SourceID:    connectorID,
			Code:        "identity_inventory_live_unavailable",
			Message:     "Live identity-bearing inventory is not available yet, so identity-sprawl findings are suppressed instead of using deterministic fixture rows.",
			Remediation: "Enable persisted EC2/Lambda/ECS identity inventory ingestion for this connector before treating an empty identity-sprawl response as no sprawl.",
			Retryable:   true,
		})
		coverageGaps = append(coverageGaps, AWSIdentitySprawlCoverageGap{
			Capability:  "identity_sprawl_live_inventory",
			Status:      "unavailable",
			Reason:      "Connected live calls do not compose deterministic fixture inventories; live identity inventory must be present before sprawl findings can be calculated.",
			Remediation: "Run or enable the identity-bearing inventory collectors for EC2 instance profiles, Lambda execution roles, and ECS task roles.",
		})
		failureReasons = append(failureReasons, "live identity-bearing inventory is unavailable")
		remediationHints = append(remediationHints, "Enable live identity inventory ingestion before interpreting an empty identity-sprawl response as no sprawl.")
	}

	findings, clusters := awsIdentitySprawlFindingsAndClusters(aggregates, now)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Score > findings[j].Score
	})
	filtered, applied := filterAWSIdentitySprawlFindings(findings, request)
	relationships := awsIdentitySprawlRelationships(filtered)
	summary := summarizeAWSIdentitySprawl(findings, clusters, filtered, relationships, aggregates)
	status, confidence := summarizeAWSIdentitySprawlStatus(sourceStatuses, filtered, diagnostics)

	return AWSIdentitySprawlResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsIdentitySprawlCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsIdentitySprawlCurrentIssue),
		Version:            awsIdentitySprawlVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsIdentitySprawlVersion,
		AppliedFilters:     applied,
		Summary:            summary,
		Findings:           filtered,
		Clusters:           clusters,
		Relationships:      relationships,
		Caveats:            awsIdentitySprawlCaveats(),
		FailureReasons:     emptyStrings(dedupeStrings(failureReasons)),
		RemediationHints:   emptyStrings(dedupeStrings(append(remediationHints, "Confirm owner approval before turning duplicate or shared-role findings into IAM consolidation work."))),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsIdentitySprawlCurrentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			"/docs/aws-identity-sprawl-engine",
			"/docs/aws-risk-engine",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: awsIdentitySprawlCoverageGapsForResult(coverageGaps),
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSIdentitySprawlFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "ready":
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

// awsIdentitySprawlSourceSignals composes the IAM identity-bearing inventories
// plus the runtime-access correlations into a per-role aggregate. It propagates
// diagnostics/coverage gaps so degraded source coverage degrades the envelope
// rather than masking it.
func (s *Service) awsIdentitySprawlSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (map[string]*identitySprawlAggregate, []AWSIdentitySprawlDiagnostic, []AWSIdentitySprawlCoverageGap, []string, []string, []string, error) {
	aggregates := map[string]*identitySprawlAggregate{}
	diagnostics := []AWSIdentitySprawlDiagnostic{}
	coverageGaps := []AWSIdentitySprawlCoverageGap{}
	failureReasons := []string{}
	remediationHints := []string{}
	sourceStatuses := []string{}

	ec2, err := s.GetAWSEC2InstanceProfileInventory(ctx, workspaceID, projectID, AWSEC2InstanceProfileInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("identity sprawl ec2 inventory: %w", err)
	}
	for _, record := range ec2.Records {
		mergeIdentitySprawlRecord(aggregates, record.RoleARN, record.RoleName, record.AccountID, record.Region, record.WorkloadType, record.WorkloadName, record.FromNodeID, record.Tags, record.EvidenceRef)
	}
	sourceStatuses = append(sourceStatuses, ec2.Status)
	for _, diagnostic := range ec2.Diagnostics {
		diagnostics = append(diagnostics, AWSIdentitySprawlDiagnostic(diagnostic))
	}
	failureReasons = append(failureReasons, ec2.FailureReasons...)
	remediationHints = append(remediationHints, ec2.RemediationHints...)

	lambda, err := s.GetAWSLambdaExecutionRoleInventory(ctx, workspaceID, projectID, AWSLambdaExecutionRoleInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("identity sprawl lambda inventory: %w", err)
	}
	for _, record := range lambda.Records {
		mergeIdentitySprawlRecord(aggregates, record.RoleARN, record.RoleName, record.AccountID, record.Region, record.WorkloadType, record.WorkloadName, record.FromNodeID, record.Tags, record.EvidenceRef)
	}
	sourceStatuses = append(sourceStatuses, lambda.Status)
	for _, diagnostic := range lambda.Diagnostics {
		diagnostics = append(diagnostics, AWSIdentitySprawlDiagnostic(diagnostic))
	}
	failureReasons = append(failureReasons, lambda.FailureReasons...)
	remediationHints = append(remediationHints, lambda.RemediationHints...)

	ecs, err := s.GetAWSECSTaskRoleInventory(ctx, workspaceID, projectID, AWSECSTaskRoleInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("identity sprawl ecs inventory: %w", err)
	}
	for _, record := range ecs.Records {
		// ECS records can carry both a task role and an execution role; both
		// are independent identity attachments worth surfacing.
		mergeIdentitySprawlRecord(aggregates, firstNonEmptyAWSValue(record.TaskRoleARN, record.RoleARN), record.RoleName, record.AccountID, record.Region, record.WorkloadType, record.WorkloadName, record.FromNodeID, record.Tags, record.EvidenceRef)
		if strings.TrimSpace(record.ExecutionRoleARN) != "" {
			mergeIdentitySprawlRecord(aggregates, record.ExecutionRoleARN, "", record.AccountID, record.Region, record.WorkloadType, record.WorkloadName, record.FromNodeID, record.Tags, record.EvidenceRef)
		}
	}
	sourceStatuses = append(sourceStatuses, ecs.Status)
	for _, diagnostic := range ecs.Diagnostics {
		diagnostics = append(diagnostics, AWSIdentitySprawlDiagnostic(diagnostic))
	}
	failureReasons = append(failureReasons, ecs.FailureReasons...)
	remediationHints = append(remediationHints, ecs.RemediationHints...)

	// Runtime-access correlations mark roles as observed in the evidence
	// window. A role with declared workload attachments AND no observed
	// activity becomes a stale candidate.
	secrets, err := s.GetAWSSecretsKMSRuntimeAccess(ctx, workspaceID, projectID, AWSSecretsKMSRuntimeAccessRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("identity sprawl secrets correlation: %w", err)
	}
	markIdentitySprawlObserved(aggregates, awsIdentitySprawlObservedRolesFromSecrets(secrets.Records))
	s3, err := s.GetAWSS3RuntimeAccess(ctx, workspaceID, projectID, AWSS3RuntimeAccessRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("identity sprawl s3 correlation: %w", err)
	}
	markIdentitySprawlObserved(aggregates, awsIdentitySprawlObservedRolesFromS3(s3.Records))
	agents, err := s.GetAWSAgentRuntimeAccess(ctx, workspaceID, projectID, AWSAgentRuntimeAccessRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("identity sprawl agent correlation: %w", err)
	}
	markIdentitySprawlObserved(aggregates, awsIdentitySprawlObservedRolesFromAgents(agents.Records))

	// Forward correlation/inventory diagnostics + coverage gaps so the sprawl
	// envelope inherits the worst-of source status.
	sourceStatuses = append(sourceStatuses, secrets.Status, s3.Status, agents.Status)
	for _, diagnostic := range secrets.Diagnostics {
		diagnostics = append(diagnostics, AWSIdentitySprawlDiagnostic(diagnostic))
	}
	for _, diagnostic := range s3.Diagnostics {
		diagnostics = append(diagnostics, AWSIdentitySprawlDiagnostic(diagnostic))
	}
	for _, diagnostic := range agents.Diagnostics {
		diagnostics = append(diagnostics, AWSIdentitySprawlDiagnostic(diagnostic))
	}
	for _, gap := range secrets.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSIdentitySprawlCoverageGap(gap))
	}
	for _, gap := range s3.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSIdentitySprawlCoverageGap(gap))
	}
	for _, gap := range agents.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSIdentitySprawlCoverageGap(gap))
	}
	failureReasons = append(failureReasons, secrets.FailureReasons...)
	failureReasons = append(failureReasons, s3.FailureReasons...)
	failureReasons = append(failureReasons, agents.FailureReasons...)
	remediationHints = append(remediationHints, secrets.RemediationHints...)
	remediationHints = append(remediationHints, s3.RemediationHints...)
	remediationHints = append(remediationHints, agents.RemediationHints...)

	return aggregates, diagnostics, coverageGaps, failureReasons, remediationHints, sourceStatuses, nil
}

func mergeIdentitySprawlRecord(aggregates map[string]*identitySprawlAggregate, roleARN, roleName, accountID, region, workloadType, workloadName, workloadNodeID string, tags map[string]string, evidenceRef string) {
	roleARN = strings.TrimSpace(roleARN)
	if roleARN == "" {
		return
	}
	key := identitySprawlKey(roleARN)
	aggregate, ok := aggregates[key]
	if !ok {
		aggregate = &identitySprawlAggregate{
			roleARN:         roleARN,
			roleName:        firstNonEmptyAWSValue(roleName, identitySprawlRoleNameFromARN(roleARN)),
			accountID:       accountID,
			region:          region,
			workloadNodeIDs: map[string]struct{}{},
			workloadTypes:   map[string]struct{}{},
			workloadLabels:  map[string]struct{}{},
			tagKeys:         map[string]struct{}{},
			evidenceRefs:    map[string]struct{}{},
		}
		aggregates[key] = aggregate
	}
	if aggregate.roleName == "" {
		aggregate.roleName = firstNonEmptyAWSValue(roleName, identitySprawlRoleNameFromARN(roleARN))
	}
	if aggregate.accountID == "" {
		aggregate.accountID = strings.TrimSpace(accountID)
	}
	if aggregate.region == "" {
		aggregate.region = strings.TrimSpace(region)
	}
	if t := strings.TrimSpace(workloadType); t != "" {
		aggregate.workloadTypes[strings.ToLower(t)] = struct{}{}
	}
	if id := strings.TrimSpace(workloadNodeID); id != "" {
		aggregate.workloadNodeIDs[id] = struct{}{}
	}
	if label := strings.TrimSpace(workloadName); label != "" {
		aggregate.workloadLabels[label] = struct{}{}
	}
	for key := range tags {
		if trimmed := strings.ToLower(strings.TrimSpace(key)); trimmed != "" {
			aggregate.tagKeys[trimmed] = struct{}{}
		}
	}
	owner, source := identitySprawlOwnerFromTags(tags)
	if aggregate.owner == "" && owner != "" {
		aggregate.owner = owner
		aggregate.ownerSource = source
	}
	if ref := strings.TrimSpace(evidenceRef); ref != "" {
		aggregate.evidenceRefs[ref] = struct{}{}
	}
}

// markIdentitySprawlObserved records that one or more observed roles were
// seen in runtime access correlations. Mapping is metadata-only: the engine
// never reads payload data, just the role ARN that owned the access.
func markIdentitySprawlObserved(aggregates map[string]*identitySprawlAggregate, observed map[string]time.Time) {
	for roleARN, observedAt := range observed {
		key := identitySprawlKey(roleARN)
		aggregate, ok := aggregates[key]
		if !ok {
			continue
		}
		aggregate.observed = true
		if observedAt.After(aggregate.observedAt) {
			aggregate.observedAt = observedAt
		}
	}
}

func awsIdentitySprawlObservedRolesFromSecrets(records []AWSSecretsKMSRuntimeAccessRecord) map[string]time.Time {
	out := map[string]time.Time{}
	for _, record := range records {
		if strings.TrimSpace(record.PrincipalARN) == "" || record.ObservedCount == 0 {
			continue
		}
		key := identitySprawlKey(record.PrincipalARN)
		if existing := out[key]; record.LastObservedAt.After(existing) {
			out[key] = record.LastObservedAt
		}
	}
	return out
}

func awsIdentitySprawlObservedRolesFromS3(records []AWSS3RuntimeAccessRecord) map[string]time.Time {
	out := map[string]time.Time{}
	for _, record := range records {
		if strings.TrimSpace(record.PrincipalARN) == "" || record.ObservedCount == 0 {
			continue
		}
		key := identitySprawlKey(record.PrincipalARN)
		if existing := out[key]; record.LastObservedAt.After(existing) {
			out[key] = record.LastObservedAt
		}
	}
	return out
}

func awsIdentitySprawlObservedRolesFromAgents(records []AWSAgentRuntimeAccessRecord) map[string]time.Time {
	out := map[string]time.Time{}
	for _, record := range records {
		if record.ObservedCount == 0 {
			continue
		}
		for _, arn := range record.BackingRoleARNs {
			if strings.TrimSpace(arn) == "" {
				continue
			}
			key := identitySprawlKey(arn)
			if existing := out[key]; record.LastObservedAt.After(existing) {
				out[key] = record.LastObservedAt
			}
		}
	}
	return out
}

// identitySprawlOwnerFromTags inspects a role's tags for a documented owner
// using the conventional tag keys teams use. Returns the owner label and the
// tag key it came from. Returns ("", "") when none is present.
func identitySprawlOwnerFromTags(tags map[string]string) (string, string) {
	for _, candidate := range []string{"owner", "team", "service", "Owner", "Team", "Service", "identrail:owner"} {
		if value := strings.TrimSpace(tags[candidate]); value != "" {
			return value, candidate
		}
	}
	for key, value := range tags {
		trimmedKey := strings.ToLower(strings.TrimSpace(key))
		if trimmedKey == "owner" || trimmedKey == "team" || trimmedKey == "service" {
			if trimmedValue := strings.TrimSpace(value); trimmedValue != "" {
				return trimmedValue, key
			}
		}
	}
	return "", ""
}

func identitySprawlKey(roleARN string) string {
	return strings.ToLower(strings.TrimSpace(roleARN))
}

func identitySprawlRoleNameFromARN(roleARN string) string {
	trimmed := strings.TrimSpace(roleARN)
	if trimmed == "" {
		return ""
	}
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 && idx+1 < len(trimmed) {
		return trimmed[idx+1:]
	}
	if idx := strings.LastIndex(trimmed, ":"); idx >= 0 && idx+1 < len(trimmed) {
		return trimmed[idx+1:]
	}
	return trimmed
}

// awsIdentitySprawlFindingsAndClusters turns the aggregate per-role view into
// findings and the cluster index. Findings are emitted at most once per
// (role, finding_type), and a single role can appear in multiple finding
// types (e.g. a shared role that is also ownerless).
func awsIdentitySprawlFindingsAndClusters(aggregates map[string]*identitySprawlAggregate, now time.Time) ([]AWSIdentitySprawlFinding, []AWSIdentitySprawlCluster) {
	keys := make([]string, 0, len(aggregates))
	for key := range aggregates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	findings := []AWSIdentitySprawlFinding{}
	clusters := []AWSIdentitySprawlCluster{}

	// Detect duplicates: cluster by signature
	// (sorted-workload-types|name-fragment). Index by the same role-ARN
	// key the outer aggregate loop uses so the membership lookup joins
	// cleanly — the cluster carries identity *node ids* for graph output,
	// while the lookup needs the role ARN that built each member.
	duplicateClusters, clusterRoleARNs := awsIdentitySprawlDuplicateClusters(aggregates, keys)
	clusterByRole := map[string]AWSIdentitySprawlCluster{}
	for i, cluster := range duplicateClusters {
		clusters = append(clusters, cluster)
		for _, roleARN := range clusterRoleARNs[i] {
			clusterByRole[identitySprawlKey(roleARN)] = cluster
		}
	}

	for _, key := range keys {
		aggregate := aggregates[key]
		identityNodeID := awsIdentityNodeIDForAPI(aggregate.roleARN)
		display := firstNonEmptyAWSValue(aggregate.roleName, shortAWSARN(aggregate.roleARN), identityNodeID)
		baseWorkloadTypes := sortedKeysFromSet(aggregate.workloadTypes)
		baseWorkloadNodes := sortedKeysFromSet(aggregate.workloadNodeIDs)
		evidenceRefs := sortedKeysFromSet(aggregate.evidenceRefs)
		evidenceForRole := awsIdentitySprawlEvidence(aggregate, evidenceRefs)

		// 1. shared: a single role attached to multiple distinct workload
		// types (e.g. lambda + ecs + ec2). Excessive sharing widens blast
		// radius and obscures ownership.
		if len(baseWorkloadTypes) >= 2 {
			findings = append(findings, awsIdentitySprawlSharedFinding(aggregate, identityNodeID, display, baseWorkloadTypes, baseWorkloadNodes, evidenceForRole, now))
		}

		// 2. stale: declared workload attachments AND no observed runtime
		// activity. With no attachments at all we have nothing to claim.
		if !aggregate.observed && len(baseWorkloadNodes) > 0 {
			findings = append(findings, awsIdentitySprawlStaleFinding(aggregate, identityNodeID, display, baseWorkloadTypes, baseWorkloadNodes, evidenceForRole, now))
		}

		// 3. ownerless: no documented owner via standard tag keys.
		if aggregate.owner == "" {
			findings = append(findings, awsIdentitySprawlOwnerlessFinding(aggregate, identityNodeID, display, baseWorkloadTypes, baseWorkloadNodes, evidenceForRole, now))
		}

		// 4. duplicate: this role is a member of a duplicate cluster of size >= 2.
		if cluster, ok := clusterByRole[key]; ok {
			findings = append(findings, awsIdentitySprawlDuplicateFinding(aggregate, identityNodeID, display, cluster, baseWorkloadTypes, baseWorkloadNodes, evidenceForRole, now))
		}
	}
	return findings, clusters
}

// awsIdentitySprawlDuplicateClusters groups roles by a coarse policy/workload
// signature. We intentionally do not parse IAM policy documents here — we
// cluster by the *attachment surface* (workload type set + role name token
// overlap), which is itself a strong duplicate signal for machine identities.
// Clusters with fewer than 2 members are not surfaced.
func awsIdentitySprawlDuplicateClusters(aggregates map[string]*identitySprawlAggregate, keys []string) ([]AWSIdentitySprawlCluster, [][]string) {
	bySignature := map[string][]string{}
	for _, key := range keys {
		aggregate := aggregates[key]
		signature := awsIdentitySprawlSignature(aggregate)
		if signature == "" {
			continue
		}
		bySignature[signature] = append(bySignature[signature], key)
	}
	signatures := make([]string, 0, len(bySignature))
	for signature := range bySignature {
		signatures = append(signatures, signature)
	}
	sort.Strings(signatures)
	clusters := make([]AWSIdentitySprawlCluster, 0, len(bySignature))
	clusterMembers := make([][]string, 0, len(bySignature))
	for _, signature := range signatures {
		members := bySignature[signature]
		if len(members) < 2 {
			continue
		}
		identityNodes := make([]string, 0, len(members))
		memberRoleARNs := make([]string, 0, len(members))
		workloadTypes := map[string]struct{}{}
		for _, member := range members {
			aggregate := aggregates[member]
			identityNodes = append(identityNodes, awsIdentityNodeIDForAPI(aggregate.roleARN))
			memberRoleARNs = append(memberRoleARNs, aggregate.roleARN)
			for workloadType := range aggregate.workloadTypes {
				workloadTypes[workloadType] = struct{}{}
			}
		}
		sort.Strings(identityNodes)
		clusters = append(clusters, AWSIdentitySprawlCluster{
			ClusterID:       "aws-identity-sprawl-cluster:" + stableAWSBlastRadiusToken("duplicate", signature),
			ClusterKind:     "duplicate_role_signature",
			IdentityNodeIDs: identityNodes,
			WorkloadTypes:   sortedKeysFromSet(workloadTypes),
			SignatureHint:   signature,
		})
		clusterMembers = append(clusterMembers, memberRoleARNs)
	}
	return clusters, clusterMembers
}

func awsIdentitySprawlSignature(aggregate *identitySprawlAggregate) string {
	workloadTypes := sortedKeysFromSet(aggregate.workloadTypes)
	if len(workloadTypes) == 0 {
		return ""
	}
	roleToken := awsIdentitySprawlNameFragment(aggregate.roleName)
	if roleToken == "" {
		return ""
	}
	return strings.Join(workloadTypes, "+") + "|" + roleToken
}

// awsIdentitySprawlNameFragment extracts a normalized stem from a role name
// by dropping common environment / role suffixes ("execution", "task",
// "runtime", "role", env tokens). This keeps "payments-lambda-execution" and
// "payments-lambda-runtime" in the same duplicate cluster without merging
// genuinely distinct roles.
func awsIdentitySprawlNameFragment(roleName string) string {
	name := strings.ToLower(strings.TrimSpace(roleName))
	if name == "" {
		return ""
	}
	for _, suffix := range []string{
		"-execution", "-task", "-runtime", "-role",
		"-prod", "-staging", "-stg", "-dev", "-test",
	} {
		name = strings.TrimSuffix(name, suffix)
	}
	tokens := strings.Split(name, "-")
	if len(tokens) == 0 {
		return name
	}
	return tokens[0]
}

func awsIdentitySprawlEvidence(aggregate *identitySprawlAggregate, evidenceRefs []string) []AWSIdentitySprawlEvidence {
	evidence := make([]AWSIdentitySprawlEvidence, 0, len(evidenceRefs)+1)
	for _, ref := range evidenceRefs {
		evidence = append(evidence, AWSIdentitySprawlEvidence{
			Source:      "iam_identity_inventory",
			EvidenceRef: ref,
			Label:       "Identity inventory attachment",
			Confidence:  0.85,
		})
	}
	if aggregate.observed {
		evidence = append(evidence, AWSIdentitySprawlEvidence{
			Source:       "runtime_access_correlation",
			EvidenceRef:  fmt.Sprintf("runtime-evidence://%s", identitySprawlKey(aggregate.roleARN)),
			Label:        "Observed runtime access",
			Confidence:   0.9,
			ObservedAt:   aggregate.observedAt,
			Relationship: "observed",
		})
	}
	return evidence
}

func awsIdentitySprawlSharedFinding(aggregate *identitySprawlAggregate, identityNodeID, display string, workloadTypes, workloadNodes []string, evidence []AWSIdentitySprawlEvidence, now time.Time) AWSIdentitySprawlFinding {
	severity := "medium"
	score := 56
	if len(workloadTypes) >= 3 {
		severity = "high"
		score = 72
	}
	if aggregate.owner == "" {
		score += 6
	}
	score = clampBlastRadiusScore(score)
	finding := awsIdentitySprawlBaseFinding(aggregate, "shared_role", severity, score, identityNodeID, display, workloadTypes, workloadNodes, evidence, now)
	finding.Rationale = fmt.Sprintf("Role %q is attached to %d distinct workload types (%s); shared roles increase blast radius and obscure ownership.", display, len(workloadTypes), strings.Join(workloadTypes, ", "))
	finding.NextAction = "Confirm whether the shared role is intentional; if not, split into per-workload-type roles before consolidating other findings."
	finding.RemediationCase = awsIdentitySprawlRemediationCase("shared_role", severity, score, identityNodeID, evidence)
	return finding
}

func awsIdentitySprawlStaleFinding(aggregate *identitySprawlAggregate, identityNodeID, display string, workloadTypes, workloadNodes []string, evidence []AWSIdentitySprawlEvidence, now time.Time) AWSIdentitySprawlFinding {
	severity := "medium"
	score := 60
	if aggregate.owner == "" {
		score += 8
	}
	if len(workloadNodes) >= 3 {
		score += 6
	}
	score = clampBlastRadiusScore(score)
	finding := awsIdentitySprawlBaseFinding(aggregate, "stale_identity", severity, score, identityNodeID, display, workloadTypes, workloadNodes, evidence, now)
	finding.Status = "review"
	finding.Rationale = fmt.Sprintf("Role %q is attached to %d workload(s) but has no observed runtime access in the scoped evidence window.", display, len(workloadNodes))
	finding.NextAction = "Ask the owner to confirm whether the role is still required, or treat as a cleanup candidate after runtime coverage is confirmed."
	finding.RemediationCase = awsIdentitySprawlRemediationCase("stale_identity", severity, score, identityNodeID, evidence)
	return finding
}

func awsIdentitySprawlOwnerlessFinding(aggregate *identitySprawlAggregate, identityNodeID, display string, workloadTypes, workloadNodes []string, evidence []AWSIdentitySprawlEvidence, now time.Time) AWSIdentitySprawlFinding {
	severity := "medium"
	score := 48
	if len(workloadTypes) >= 2 {
		score += 6
	}
	if !aggregate.observed {
		score += 4
	}
	score = clampBlastRadiusScore(score)
	finding := awsIdentitySprawlBaseFinding(aggregate, "ownerless_identity", severity, score, identityNodeID, display, workloadTypes, workloadNodes, evidence, now)
	finding.OwnerSource = "no_owner_tag"
	finding.Rationale = fmt.Sprintf("Role %q has no owner/team/service tag, so cleanup or consolidation cannot route to a documented owner.", display)
	finding.NextAction = "Tag the role with owner/team/service or remove it after confirming no workload depends on it."
	finding.RemediationCase = awsIdentitySprawlRemediationCase("ownerless_identity", severity, score, identityNodeID, evidence)
	return finding
}

func awsIdentitySprawlDuplicateFinding(aggregate *identitySprawlAggregate, identityNodeID, display string, cluster AWSIdentitySprawlCluster, workloadTypes, workloadNodes []string, evidence []AWSIdentitySprawlEvidence, now time.Time) AWSIdentitySprawlFinding {
	severity := "medium"
	score := 52
	if len(cluster.IdentityNodeIDs) >= 3 {
		score += 8
	}
	score = clampBlastRadiusScore(score)
	finding := awsIdentitySprawlBaseFinding(aggregate, "duplicate_identity", severity, score, identityNodeID, display, workloadTypes, workloadNodes, evidence, now)
	finding.ClusterID = cluster.ClusterID
	finding.ClusterKind = cluster.ClusterKind
	finding.Rationale = fmt.Sprintf("Role %q shares an attachment signature with %d other role(s) (signature %q); consolidate after owner approval.", display, len(cluster.IdentityNodeIDs)-1, cluster.SignatureHint)
	finding.NextAction = "Compare the cluster members' actions and conditions, then merge into a single role after the owner approves."
	finding.RemediationCase = awsIdentitySprawlRemediationCase("duplicate_identity", severity, score, identityNodeID, evidence)
	return finding
}

func awsIdentitySprawlBaseFinding(aggregate *identitySprawlAggregate, findingType, severity string, score int, identityNodeID, display string, workloadTypes, workloadNodes []string, evidence []AWSIdentitySprawlEvidence, now time.Time) AWSIdentitySprawlFinding {
	impactedNodes := dedupeStrings(append([]string{identityNodeID}, workloadNodes...))
	impactedPath := []AWSIdentitySprawlPathStep{
		{NodeID: identityNodeID, NodeType: "identity", Label: display, AccountID: aggregate.accountID, Region: aggregate.region},
	}
	for _, workloadNode := range workloadNodes {
		impactedPath = append(impactedPath, AWSIdentitySprawlPathStep{
			NodeID:    workloadNode,
			NodeType:  "workload",
			Label:     shortAWSARN(workloadNode),
			AccountID: aggregate.accountID,
			Region:    aggregate.region,
		})
	}
	ownerSource := aggregate.ownerSource
	if aggregate.owner == "" {
		ownerSource = "no_owner_tag"
	}
	confidence := 0.82
	if aggregate.observed {
		confidence = 0.88
	}
	return AWSIdentitySprawlFinding{
		FindingID:          "aws-identity-sprawl:" + stableAWSBlastRadiusToken(findingType, aggregate.roleARN),
		CalculationVersion: awsIdentitySprawlVersion,
		FindingType:        findingType,
		Severity:           severity,
		Status:             "review",
		Score:              score,
		Confidence:         confidence,
		AccountID:          aggregate.accountID,
		Region:             aggregate.region,
		IdentityNodeID:     identityNodeID,
		PrincipalARN:       aggregate.roleARN,
		RoleName:           aggregate.roleName,
		DisplayName:        display,
		OwnerLabel:         aggregate.owner,
		OwnerSource:        ownerSource,
		WorkloadTypes:      workloadTypes,
		WorkloadNodeIDs:    workloadNodes,
		ImpactedNodes:      impactedNodes,
		ImpactedPath:       impactedPath,
		Evidence:           evidence,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func awsIdentitySprawlRemediationCase(kind, severity string, score int, identityNodeID string, evidence []AWSIdentitySprawlEvidence) AWSIdentitySprawlRemediationCasePreview {
	action := "Confirm owner approval and create a read-only sprawl cleanup case."
	switch kind {
	case "shared_role":
		action = "Create a case to split the shared role into per-workload-type roles after owner approval."
	case "stale_identity":
		action = "Create a cleanup case for the stale role; confirm runtime coverage before any policy change."
	case "ownerless_identity":
		action = "Create a case to assign owner/team/service tagging or remove the role after owner discovery."
	case "duplicate_identity":
		action = "Create a consolidation case to merge the duplicate role cluster after owner approval."
	}
	evidenceRefs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if ref := strings.TrimSpace(item.EvidenceRef); ref != "" {
			evidenceRefs = append(evidenceRefs, ref)
		}
	}
	preview := AWSIdentitySprawlRemediationCasePreview{
		CaseID:             "aws-identity-sprawl-preview:" + stableAWSBlastRadiusToken(kind, identityNodeID),
		Title:              fmt.Sprintf("%s sprawl remediation", formatAWSBlastRadiusLabel(kind)),
		RecommendedAction:  action,
		ApprovalRequired:   severity == "critical" || severity == "high",
		BlockingEvidence:   dedupeStrings(evidenceRefs),
		ImpactedNodeCount:  1,
		EstimatedRiskDrop:  minInt(score, 30),
		ReadOnlyProjection: true,
	}
	return preview
}

func filterAWSIdentitySprawlFindings(findings []AWSIdentitySprawlFinding, request AWSIdentitySprawlRequest) ([]AWSIdentitySprawlFinding, map[string]string) {
	filters := map[string]string{
		"account_id":   strings.TrimSpace(request.AccountID),
		"region":       strings.TrimSpace(request.Region),
		"identity":     strings.TrimSpace(request.Identity),
		"owner":        strings.TrimSpace(request.Owner),
		"cluster":      strings.TrimSpace(request.Cluster),
		"finding_type": normalizeAWSRuntimeEventFilterToken(request.FindingType),
		"severity":     normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":       normalizeAWSRuntimeEventFilterToken(request.Status),
	}
	for key, value := range filters {
		token := strings.TrimSpace(value)
		if token == "" || strings.EqualFold(token, "all") {
			delete(filters, key)
		}
	}
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSIdentitySprawlFinding, 0, len(findings))
	for _, finding := range findings {
		if filters["account_id"] != "" && filters["account_id"] != finding.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], finding.Region) {
			continue
		}
		if filters["finding_type"] != "" && filters["finding_type"] != normalizeAWSRuntimeEventFilterToken(finding.FindingType) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(finding.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(finding.Status) {
			continue
		}
		if filters["cluster"] != "" && !awsRuntimeEventMatchesAny(filters["cluster"], finding.ClusterID, finding.ClusterKind) {
			continue
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], finding.IdentityNodeID, finding.PrincipalARN, finding.DisplayName, finding.RoleName) {
			continue
		}
		// Owner filter is forgiving: a request for ownerless identities
		// (?owner=none) maps directly to OwnerSource=no_owner_tag.
		if filters["owner"] != "" {
			ownerFilter := strings.ToLower(filters["owner"])
			if ownerFilter == "none" || ownerFilter == "ownerless" {
				if finding.OwnerSource != "no_owner_tag" {
					continue
				}
			} else if !awsRuntimeEventMatchesAny(filters["owner"], finding.OwnerLabel, finding.OwnerSource) {
				continue
			}
		}
		filtered = append(filtered, finding)
	}
	return filtered, applied
}

func awsIdentitySprawlRelationships(findings []AWSIdentitySprawlFinding) []AWSIdentitySprawlRelationship {
	relationships := []AWSIdentitySprawlRelationship{}
	for _, finding := range findings {
		from := strings.TrimSpace(finding.IdentityNodeID)
		for _, step := range finding.ImpactedPath[1:] {
			to := strings.TrimSpace(step.NodeID)
			if from == "" || to == "" {
				continue
			}
			relationships = append(relationships, AWSIdentitySprawlRelationship{
				FindingID:   finding.FindingID,
				Type:        "identity_sprawl_attachment",
				FromNodeID:  from,
				ToNodeID:    to,
				EvidenceRef: firstLeastPrivilegeEvidenceRef(finding.Evidence),
			})
		}
		if finding.ClusterID != "" {
			relationships = append(relationships, AWSIdentitySprawlRelationship{
				FindingID:   finding.FindingID,
				Type:        "identity_sprawl_cluster_member",
				FromNodeID:  finding.IdentityNodeID,
				ToNodeID:    finding.ClusterID,
				EvidenceRef: firstLeastPrivilegeEvidenceRef(finding.Evidence),
			})
		}
	}
	return relationships
}

func summarizeAWSIdentitySprawl(allFindings []AWSIdentitySprawlFinding, clusters []AWSIdentitySprawlCluster, filtered []AWSIdentitySprawlFinding, relationships []AWSIdentitySprawlRelationship, aggregates map[string]*identitySprawlAggregate) AWSIdentitySprawlSummary {
	findingTypeCounts := map[string]int{}
	severityCounts := map[string]int{}
	statusCounts := map[string]int{}
	ownerSourceCounts := map[string]int{}
	totalConfidence := 0.0
	highest := 0
	remediationCases := map[string]struct{}{}
	for _, finding := range allFindings {
		findingTypeCounts[finding.FindingType]++
		severityCounts[finding.Severity]++
		statusCounts[finding.Status]++
		ownerSourceCounts[finding.OwnerSource]++
		totalConfidence += finding.Confidence
		if finding.Score > highest {
			highest = finding.Score
		}
		if finding.RemediationCase.CaseID != "" {
			remediationCases[finding.RemediationCase.CaseID] = struct{}{}
		}
	}
	averageConfidence := 0
	if len(allFindings) > 0 {
		averageConfidence = int((totalConfidence / float64(len(allFindings))) * 100)
	}
	workloads := map[string]struct{}{}
	for _, aggregate := range aggregates {
		for node := range aggregate.workloadNodeIDs {
			workloads[node] = struct{}{}
		}
	}
	return AWSIdentitySprawlSummary{
		TotalFindings:           len(allFindings),
		FilteredFindings:        len(filtered),
		FindingTypeCounts:       findingTypeCounts,
		SeverityCounts:          severityCounts,
		StatusCounts:            statusCounts,
		OwnerSourceCounts:       ownerSourceCounts,
		StaleIdentityCount:      findingTypeCounts["stale_identity"],
		OwnerlessIdentityCount:  findingTypeCounts["ownerless_identity"],
		DuplicateClusterCount:   len(clusters),
		SharedRoleCount:         findingTypeCounts["shared_role"],
		UniqueIdentityCount:     len(aggregates),
		UniqueWorkloadCount:     len(workloads),
		RelationshipCount:       len(relationships),
		HighestScore:            highest,
		AverageConfidencePct:    averageConfidence,
		RemediationPreviewCount: len(remediationCases),
	}
}

func summarizeAWSIdentitySprawlStatus(sourceStatuses []string, filtered []AWSIdentitySprawlFinding, diagnostics []AWSIdentitySprawlDiagnostic) (string, float64) {
	allBlocked := len(sourceStatuses) > 0
	anyDegraded := len(diagnostics) > 0
	for _, status := range sourceStatuses {
		switch status {
		case awsPlatformDependencyStatusBlocked:
			anyDegraded = true
		case awsPlatformDependencyStatusDegraded:
			allBlocked = false
			anyDegraded = true
		default:
			allBlocked = false
		}
	}
	if allBlocked {
		return awsPlatformDependencyStatusBlocked, 0
	}
	if anyDegraded {
		return awsPlatformDependencyStatusDegraded, 0.7
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsIdentitySprawlCaveats() []string {
	return []string{
		"Sprawl findings cluster identities by attachment surface (workload types + role-name fragment). They do not parse IAM policy documents; a low-similarity name match is not a duplicate.",
		"Ownerless findings depend on operator tag hygiene. An untagged role is flagged even when an out-of-band runbook documents the owner.",
		"Stale findings degrade to review when runtime coverage is incomplete (e.g. CloudTrail data events missing); they never become cleanup candidates on uncertain telemetry.",
	}
}

func awsIdentitySprawlCoverageGapsForResult(source []AWSIdentitySprawlCoverageGap) []AWSIdentitySprawlCoverageGap {
	out := []AWSIdentitySprawlCoverageGap{{
		Capability:  "identity_sprawl_persistence",
		Status:      "ready",
		Reason:      "The API emits stable finding IDs, calculation version, finding type, owner context, cluster signature, evidence, and remediation preview fields for downstream persistence/graph consumers.",
		Remediation: "Persist these findings into the shared AWS intelligence store when the dedicated findings table lands.",
	}}
	out = append(out, source...)
	return out
}

func sortedKeysFromSet(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
