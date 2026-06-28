package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsCrossAccountTrustCurrentIssue = 1526
	awsCrossAccountTrustVersion      = "aws-cross-account-trust-engine-v1"
)

// AWSCrossAccountTrustRequest scopes the read-only external-access reasoning
// engine to an AWS connector and optional operator drill-down filters.
type AWSCrossAccountTrustRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Service      string `json:"service,omitempty"`
	Principal    string `json:"principal,omitempty"`
	Resource     string `json:"resource,omitempty"`
	FindingType  string `json:"finding_type,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Status       string `json:"status,omitempty"`
	OU           string `json:"ou,omitempty"`
}

type AWSCrossAccountTrustEvidence = AWSLeastPrivilegeEvidence
type AWSCrossAccountTrustPathStep = AWSLeastPrivilegePathStep
type AWSCrossAccountTrustRemediationCasePreview = AWSLeastPrivilegeRemediationCasePreview
type AWSCrossAccountTrustDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSCrossAccountTrustCoverageGap = AWSLeastPrivilegeCoverageGap

// AWSCrossAccountTrustRelationship lets graph consumers join a finding back to
// the external principal, affected resource, and source evidence.
type AWSCrossAccountTrustRelationship struct {
	FindingID   string `json:"finding_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSCrossAccountTrustFinding is the deterministic, metadata-only decision
// shape for public principals, cross-account grants, Access Analyzer external
// access, runtime STS assumptions, and cross-account graph paths.
type AWSCrossAccountTrustFinding struct {
	FindingID                 string                                     `json:"finding_id"`
	CalculationVersion        string                                     `json:"calculation_version"`
	FindingType               string                                     `json:"finding_type"`
	Severity                  string                                     `json:"severity"`
	Status                    string                                     `json:"status"`
	Score                     int                                        `json:"score"`
	Confidence                float64                                    `json:"confidence"`
	AccountID                 string                                     `json:"account_id"`
	Region                    string                                     `json:"region"`
	Service                   string                                     `json:"service"`
	ResourceType              string                                     `json:"resource_type"`
	ResourceARN               string                                     `json:"resource_arn,omitempty"`
	ResourceNodeID            string                                     `json:"resource_node_id,omitempty"`
	ResourceLabel             string                                     `json:"resource_label"`
	ExternalPrincipalARN      string                                     `json:"external_principal_arn,omitempty"`
	ExternalPrincipalAccount  string                                     `json:"external_principal_account,omitempty"`
	ExternalPrincipalOUPath   string                                     `json:"external_principal_ou_path,omitempty"`
	TrustedWithinOrganization bool                                       `json:"trusted_within_organization"`
	PublicPrincipal           bool                                       `json:"public_principal"`
	HasCondition              bool                                       `json:"has_condition"`
	ConditionKeys             []string                                   `json:"condition_keys,omitempty"`
	PolicySources             []string                                   `json:"policy_sources,omitempty"`
	RuntimeObserved           bool                                       `json:"runtime_observed"`
	AnalyzerBacked            bool                                       `json:"analyzer_backed"`
	Rationale                 string                                     `json:"rationale"`
	HardeningDirection        string                                     `json:"hardening_direction"`
	ImpactedNodes             []string                                   `json:"impacted_nodes"`
	ImpactedPath              []AWSCrossAccountTrustPathStep             `json:"impacted_path"`
	Evidence                  []AWSCrossAccountTrustEvidence             `json:"evidence"`
	NextAction                string                                     `json:"next_action"`
	RemediationCase           AWSCrossAccountTrustRemediationCasePreview `json:"remediation_case"`
	CreatedAt                 time.Time                                  `json:"created_at"`
	UpdatedAt                 time.Time                                  `json:"updated_at"`
}

type AWSCrossAccountTrustSummary struct {
	TotalFindings           int            `json:"total_findings"`
	FilteredFindings        int            `json:"filtered_findings"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	StatusCounts            map[string]int `json:"status_counts"`
	FindingTypeCounts       map[string]int `json:"finding_type_counts"`
	ServiceCounts           map[string]int `json:"service_counts"`
	CriticalCount           int            `json:"critical_count"`
	HighCount               int            `json:"high_count"`
	PublicPrincipalCount    int            `json:"public_principal_count"`
	CrossAccountGrantCount  int            `json:"cross_account_grant_count"`
	RuntimeObservedCount    int            `json:"runtime_observed_count"`
	AnalyzerBackedCount     int            `json:"analyzer_backed_count"`
	UnconditionalGrantCount int            `json:"unconditional_grant_count"`
	RelationshipCount       int            `json:"relationship_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
	RemediationPreviewCount int            `json:"remediation_preview_count"`
}

// AWSCrossAccountTrustResult is the deterministic cross-account trust envelope.
type AWSCrossAccountTrustResult struct {
	TenantID           string                             `json:"tenant_id"`
	WorkspaceID        string                             `json:"workspace_id"`
	ProjectID          string                             `json:"project_id"`
	ConnectorID        string                             `json:"connector_id,omitempty"`
	AccountID          string                             `json:"account_id,omitempty"`
	Region             string                             `json:"region,omitempty"`
	ParentIssueNumber  int                                `json:"parent_issue_number"`
	ParentIssueRef     string                             `json:"parent_issue_ref"`
	CurrentIssueNumber int                                `json:"current_issue_number"`
	CurrentIssueRef    string                             `json:"current_issue_ref"`
	Version            string                             `json:"version"`
	Status             string                             `json:"status"`
	FixtureState       string                             `json:"fixture_state,omitempty"`
	Confidence         float64                            `json:"confidence"`
	CalculationVersion string                             `json:"calculation_version"`
	AppliedFilters     map[string]string                  `json:"applied_filters"`
	Summary            AWSCrossAccountTrustSummary        `json:"summary"`
	Findings           []AWSCrossAccountTrustFinding      `json:"findings"`
	Relationships      []AWSCrossAccountTrustRelationship `json:"relationships"`
	Caveats            []string                           `json:"caveats"`
	FailureReasons     []string                           `json:"failure_reasons"`
	RemediationHints   []string                           `json:"remediation_hints"`
	EvidenceLinks      []string                           `json:"evidence_links"`
	CoverageGaps       []AWSCrossAccountTrustCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSCrossAccountTrustDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                          `json:"generated_at"`
	UpdatedAt          time.Time                          `json:"updated_at"`
}

type awsCrossAccountTrustSources struct {
	organizations AWSOrganizationsTopologyResult
	s3            AWSS3BucketReachabilityInventoryResult
	kms           AWSKMSDecryptReachabilityInventoryResult
	secrets       AWSSecretsManagerMetadataInventoryResult
	sqsSNS        AWSSQSSNSReachabilityInventoryResult
	dynamoRDS     AWSDynamoDBRDSReachabilityInventoryResult
	runtime       AWSRuntimeEventResult
	least         AWSLeastPrivilegeResult
	blast         AWSBlastRadiusResult
}

type awsCrossAccountTrustGrantInput struct {
	source            string
	service           string
	resourceType      string
	resourceARN       string
	resourceNodeID    string
	resourceLabel     string
	accountID         string
	region            string
	principalARN      string
	effect            string
	actions           []string
	capabilities      []string
	notAction         bool
	conditionKeys     []string
	hasCondition      bool
	publicPrincipal   bool
	crossAccount      bool
	wildcardPrincipal bool
	statementSid      string
	denyGrants        []awsCrossAccountTrustExplicitDenyGrant
	evidenceRef       string
	confidence        float64
	observedAt        time.Time
	status            string
}

type awsCrossAccountTrustExplicitDenyGrant struct {
	principalARN      string
	wildcardPrincipal bool
	actions           []string
	capabilities      []string
	notAction         bool
	hasCondition      bool
}

func (s *Service) GetAWSCrossAccountTrust(ctx context.Context, workspaceID string, projectID string, request AWSCrossAccountTrustRequest) (AWSCrossAccountTrustResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSCrossAccountTrustResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSCrossAccountTrustResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSCrossAccountTrustFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSCrossAccountTrustResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	fixtureBackedSourceState := fixtureState
	runtimeFixtureState := fixtureState
	responseFixtureState := fixtureState
	suppressRuntimeFixtures := false
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		fixtureBackedSourceState = "empty"
		runtimeFixtureState = ""
		responseFixtureState = ""
		suppressRuntimeFixtures = true
	}

	sources, err := s.awsCrossAccountTrustSourceSignals(ctx, workspaceID, projectID, connectorID, fixtureBackedSourceState, runtimeFixtureState, suppressRuntimeFixtures)
	if err != nil {
		return AWSCrossAccountTrustResult{}, err
	}
	findings := awsCrossAccountTrustFindings(sources, now)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Score > findings[j].Score
	})
	filtered, applied := filterAWSCrossAccountTrustFindings(findings, request)
	relationships := awsCrossAccountTrustRelationships(filtered)
	diagnostics := awsCrossAccountTrustDiagnostics(sources)
	coverageGaps := awsCrossAccountTrustCoverageGaps(sources)
	status, confidence := summarizeAWSCrossAccountTrustStatus(sources, diagnostics)

	return AWSCrossAccountTrustResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsCrossAccountTrustCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsCrossAccountTrustCurrentIssue),
		Version:            awsCrossAccountTrustVersion,
		Status:             status,
		FixtureState:       responseFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsCrossAccountTrustVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSCrossAccountTrust(findings, filtered, relationships),
		Findings:           filtered,
		Relationships:      relationships,
		Caveats:            awsCrossAccountTrustCaveats(),
		FailureReasons:     awsCrossAccountTrustFailureReasons(sources),
		RemediationHints:   awsCrossAccountTrustRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsCrossAccountTrustCurrentIssue),
			awsIssueURL(awsOrganizationsTopologyCurrentIssue),
			awsIssueURL(awsRuntimeEventsCurrentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			"/docs/aws-cross-account-trust-engine",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSCrossAccountTrustFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsCrossAccountTrustSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureBackedSourceState string, runtimeFixtureState string, suppressRuntimeFixtures bool) (awsCrossAccountTrustSources, error) {
	organizations, err := s.GetAWSOrganizationsTopology(ctx, workspaceID, projectID, AWSOrganizationsTopologyRequest{ConnectorID: connectorID, FixtureState: fixtureBackedSourceState})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust organizations topology: %w", err)
	}
	s3, err := s.GetAWSS3BucketReachabilityInventory(ctx, workspaceID, projectID, AWSS3BucketReachabilityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureBackedSourceState})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust s3 reachability: %w", err)
	}
	kms, err := s.GetAWSKMSDecryptReachabilityInventory(ctx, workspaceID, projectID, AWSKMSDecryptReachabilityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureBackedSourceState})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust kms reachability: %w", err)
	}
	secrets, err := s.GetAWSSecretsManagerMetadataInventory(ctx, workspaceID, projectID, AWSSecretsManagerMetadataInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureBackedSourceState})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust secrets metadata: %w", err)
	}
	sqsSNS, err := s.GetAWSSQSSNSReachabilityInventory(ctx, workspaceID, projectID, AWSSQSSNSReachabilityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureBackedSourceState})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust sqs/sns reachability: %w", err)
	}
	dynamoRDS, err := s.GetAWSDynamoDBRDSReachabilityInventory(ctx, workspaceID, projectID, AWSDynamoDBRDSReachabilityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureBackedSourceState})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust dynamodb/rds reachability: %w", err)
	}
	runtime, err := s.GetAWSRuntimeEvents(ctx, workspaceID, projectID, AWSRuntimeEventRequest{ConnectorID: connectorID, FixtureState: runtimeFixtureState, EventType: "sts-session", SuppressFixtureRecords: suppressRuntimeFixtures})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust runtime events: %w", err)
	}
	least, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{ConnectorID: connectorID, FixtureState: fixtureBackedSourceState})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust least privilege: %w", err)
	}
	blast, err := s.GetAWSBlastRadius(ctx, workspaceID, projectID, AWSBlastRadiusRequest{ConnectorID: connectorID, FixtureState: fixtureBackedSourceState})
	if err != nil {
		return awsCrossAccountTrustSources{}, fmt.Errorf("cross-account trust blast radius: %w", err)
	}
	return awsCrossAccountTrustSources{organizations: organizations, s3: s3, kms: kms, secrets: secrets, sqsSNS: sqsSNS, dynamoRDS: dynamoRDS, runtime: runtime, least: least, blast: blast}, nil
}

func awsCrossAccountTrustFindings(sources awsCrossAccountTrustSources, now time.Time) []AWSCrossAccountTrustFinding {
	accounts := awsCrossAccountTrustOrganizationAccounts(sources.organizations)
	findings := []AWSCrossAccountTrustFinding{}
	for _, record := range sources.s3.Records {
		denyGrants := awsCrossAccountTrustDenyGrantsFromS3(record.IdentityGrants)
		for _, grant := range record.IdentityGrants {
			findings = append(findings, awsCrossAccountTrustFindingFromGrant(awsCrossAccountTrustGrantInput{
				source: "s3_bucket_reachability", service: "s3", resourceType: "s3_bucket", resourceARN: record.BucketARN, resourceNodeID: record.FromNodeID, resourceLabel: firstNonEmptyAWSValue(record.BucketName, record.BucketARN), accountID: record.AccountID, region: record.Region, principalARN: grant.PrincipalARN, effect: grant.Effect, actions: grant.Actions, notAction: grant.NotAction, conditionKeys: grant.ConditionKeys, hasCondition: grant.HasCondition, publicPrincipal: grant.IsPublic, crossAccount: grant.IsCrossAccount, wildcardPrincipal: grant.WildcardPrincipal, statementSid: grant.StatementSid, denyGrants: denyGrants, evidenceRef: record.EvidenceRef, confidence: record.Confidence, observedAt: record.CollectedAt, status: record.Status,
			}, accounts, now)...)
		}
	}
	for _, record := range sources.kms.Records {
		denyGrants := awsCrossAccountTrustDenyGrantsFromKMS(record.IdentityGrants)
		for _, grant := range record.IdentityGrants {
			findings = append(findings, awsCrossAccountTrustFindingFromGrant(awsCrossAccountTrustGrantInput{
				source: "kms_decrypt_reachability", service: "kms", resourceType: "kms_key", resourceARN: record.KeyARN, resourceNodeID: record.FromNodeID, resourceLabel: firstNonEmptyAWSValue(record.Description, firstString(record.Aliases), record.KeyARN, record.KeyID), accountID: record.AccountID, region: record.Region, principalARN: grant.PrincipalARN, effect: grant.Effect, actions: grant.Actions, capabilities: grant.Capabilities, notAction: grant.NotAction, conditionKeys: grant.ConditionKeys, hasCondition: grant.HasCondition, publicPrincipal: grant.IsPublic, crossAccount: grant.IsCrossAccount, wildcardPrincipal: grant.WildcardPrincipal, statementSid: grant.StatementSid, denyGrants: denyGrants, evidenceRef: record.EvidenceRef, confidence: record.Confidence, observedAt: record.CollectedAt, status: record.Status,
			}, accounts, now)...)
		}
		for _, grant := range record.Grants {
			findings = append(findings, awsCrossAccountTrustFindingFromGrant(awsCrossAccountTrustGrantInput{
				source: "kms_live_grant", service: "kms", resourceType: "kms_key", resourceARN: record.KeyARN, resourceNodeID: record.FromNodeID, resourceLabel: firstNonEmptyAWSValue(record.Description, firstString(record.Aliases), record.KeyARN, record.KeyID), accountID: record.AccountID, region: record.Region, principalARN: grant.GranteePrincipal, effect: "Allow", actions: grant.Operations, capabilities: grant.Capabilities, conditionKeys: append(append([]string{}, grant.EncryptionContextKeys...), grant.EncryptionContextSubsetKeys...), hasCondition: grant.HasConstraints, crossAccount: grant.IsCrossAccount, denyGrants: denyGrants, evidenceRef: record.EvidenceRef, confidence: record.Confidence, observedAt: record.CollectedAt, status: record.Status,
			}, accounts, now)...)
		}
	}
	for _, record := range sources.secrets.Records {
		denyGrants := awsCrossAccountTrustDenyGrantsFromSecrets(record.IdentityGrants)
		for _, grant := range record.IdentityGrants {
			findings = append(findings, awsCrossAccountTrustFindingFromGrant(awsCrossAccountTrustGrantInput{
				source: "secrets_manager_metadata", service: "secretsmanager", resourceType: "secret", resourceARN: record.SecretARN, resourceNodeID: record.FromNodeID, resourceLabel: firstNonEmptyAWSValue(record.SecretName, record.SecretARN), accountID: record.AccountID, region: record.Region, principalARN: grant.PrincipalARN, effect: grant.Effect, actions: grant.Actions, conditionKeys: grant.ConditionKeys, hasCondition: grant.HasCondition, publicPrincipal: grant.IsPublic, crossAccount: grant.IsCrossAccount, wildcardPrincipal: grant.WildcardPrincipal, statementSid: grant.StatementSid, denyGrants: denyGrants, evidenceRef: record.EvidenceRef, confidence: record.Confidence, observedAt: record.CollectedAt, status: record.Status,
			}, accounts, now)...)
		}
	}
	for _, record := range sources.sqsSNS.Records {
		denyGrants := awsCrossAccountTrustDenyGrantsFromSQSSNS(record.IdentityGrants)
		for _, grant := range record.IdentityGrants {
			findings = append(findings, awsCrossAccountTrustFindingFromGrant(awsCrossAccountTrustGrantInput{
				source: "sqs_sns_reachability", service: record.Service, resourceType: record.ResourceType, resourceARN: record.ResourceARN, resourceNodeID: record.FromNodeID, resourceLabel: firstNonEmptyAWSValue(record.ResourceName, record.ResourceARN), accountID: record.AccountID, region: record.Region, principalARN: grant.PrincipalARN, effect: grant.Effect, actions: grant.Actions, capabilities: grant.Capabilities, notAction: grant.NotAction, conditionKeys: grant.ConditionKeys, hasCondition: grant.HasCondition, publicPrincipal: grant.IsPublic, crossAccount: grant.IsCrossAccount, wildcardPrincipal: grant.WildcardPrincipal, statementSid: grant.StatementSid, denyGrants: denyGrants, evidenceRef: record.EvidenceRef, confidence: record.Confidence, observedAt: record.CollectedAt, status: record.Status,
			}, accounts, now)...)
		}
	}
	for _, record := range sources.dynamoRDS.Records {
		denyGrants := awsCrossAccountTrustDenyGrantsFromDynamoRDS(record.IdentityGrants)
		for _, grant := range record.IdentityGrants {
			findings = append(findings, awsCrossAccountTrustFindingFromGrant(awsCrossAccountTrustGrantInput{
				source: "dynamodb_rds_reachability", service: record.Service, resourceType: record.ResourceType, resourceARN: record.ResourceARN, resourceNodeID: record.FromNodeID, resourceLabel: firstNonEmptyAWSValue(record.ResourceName, record.ResourceARN), accountID: record.AccountID, region: record.Region, principalARN: grant.PrincipalARN, effect: grant.Effect, actions: grant.Actions, capabilities: grant.Capabilities, notAction: grant.NotAction, conditionKeys: grant.ConditionKeys, hasCondition: grant.HasCondition, publicPrincipal: grant.IsPublic, crossAccount: grant.IsCrossAccount, wildcardPrincipal: grant.WildcardPrincipal, statementSid: grant.StatementSid, denyGrants: denyGrants, evidenceRef: record.EvidenceRef, confidence: record.Confidence, observedAt: record.CollectedAt, status: record.Status,
			}, accounts, now)...)
		}
	}
	for _, record := range sources.runtime.Records {
		if finding, ok := awsCrossAccountTrustFindingFromRuntimeAssumption(record, accounts, now); ok {
			findings = append(findings, finding)
		}
	}
	for _, recommendation := range sources.least.Recommendations {
		if finding, ok := awsCrossAccountTrustFindingFromLeastPrivilege(recommendation, accounts, now); ok {
			findings = append(findings, finding)
		}
	}
	for _, finding := range sources.blast.Findings {
		if trustFinding, ok := awsCrossAccountTrustFindingFromBlastRadius(finding, accounts, now); ok {
			findings = append(findings, trustFinding)
		}
	}
	return awsCrossAccountTrustDedupeFindings(findings)
}

func awsCrossAccountTrustFindingFromGrant(input awsCrossAccountTrustGrantInput, accounts map[string]AWSOrganizationsTopologyAccount, now time.Time) []AWSCrossAccountTrustFinding {
	if !strings.EqualFold(firstNonEmptyAWSValue(input.effect, "Allow"), "Allow") {
		return nil
	}
	if awsCrossAccountTrustGrantHasExplicitDeny(input) {
		return nil
	}
	input.publicPrincipal = input.publicPrincipal || input.wildcardPrincipal || strings.TrimSpace(input.principalARN) == "*"
	input.crossAccount = input.crossAccount || awsCrossAccountTrustPrincipalIsExternal(input.principalARN, input.accountID)
	if !input.publicPrincipal && !input.crossAccount {
		return nil
	}
	kind := "cross_account_resource_access"
	score := 78
	if input.publicPrincipal {
		kind = "public_resource_trust"
		score = 88
	}
	if !input.hasCondition {
		score += 8
	}
	score = clampBlastRadiusScore(score)
	principalAccount := awsCrossAccountTrustPrincipalAccount(input.principalARN)
	accountContext := accounts[principalAccount]
	status := "review"
	if score >= 88 {
		status = "action_required"
	}
	principalLabel := firstNonEmptyAWSValue(shortAWSARN(input.principalARN), input.principalARN, "public principal")
	resourceLabel := firstNonEmptyAWSValue(input.resourceLabel, input.resourceARN, input.resourceNodeID)
	evidenceRef := firstNonEmptyAWSValue(input.evidenceRef, fmt.Sprintf("%s://%s", input.source, stableAWSBlastRadiusToken(input.resourceARN, input.principalARN)))
	policySources := dedupeStrings(append(append([]string{}, input.actions...), input.capabilities...))
	if input.statementSid != "" {
		policySources = append(policySources, input.statementSid)
	}
	nextAction := "Confirm the external principal owner, then restrict the resource policy to approved account, principal, condition, and organization boundaries."
	if input.publicPrincipal {
		nextAction = "Remove wildcard public trust or add a narrow principal plus required condition before approving downstream remediation."
	}
	finding := AWSCrossAccountTrustFinding{
		FindingID:                 "aws-cross-account-trust:" + stableAWSBlastRadiusToken(kind, input.resourceARN, input.principalARN, strings.Join(policySources, ",")),
		CalculationVersion:        awsCrossAccountTrustVersion,
		FindingType:               kind,
		Severity:                  awsPrivilegeEscalationSeverity(score),
		Status:                    status,
		Score:                     score,
		Confidence:                minFloat(firstNonZeroFloat(input.confidence, 0.86), 0.94),
		AccountID:                 input.accountID,
		Region:                    input.region,
		Service:                   firstNonEmptyAWSValue(input.service, serviceFromAWSAction(firstString(input.actions))),
		ResourceType:              input.resourceType,
		ResourceARN:               input.resourceARN,
		ResourceNodeID:            input.resourceNodeID,
		ResourceLabel:             resourceLabel,
		ExternalPrincipalARN:      input.principalARN,
		ExternalPrincipalAccount:  principalAccount,
		ExternalPrincipalOUPath:   accountContext.OUPath,
		TrustedWithinOrganization: accountContext.AccountID != "",
		PublicPrincipal:           input.publicPrincipal,
		HasCondition:              input.hasCondition,
		ConditionKeys:             dedupeStrings(input.conditionKeys),
		PolicySources:             policySources,
		Rationale:                 fmt.Sprintf("%s %q trusts %s through %s with condition=%t.", strings.ToUpper(firstNonEmptyAWSValue(input.service, "resource")), resourceLabel, principalLabel, strings.Join(policySources, ", "), input.hasCondition),
		HardeningDirection:        awsCrossAccountTrustHardeningDirection(input.publicPrincipal, input.hasCondition, accountContext.AccountID != ""),
		ImpactedNodes:             dedupeStrings([]string{awsIdentityNodeIDForAPI(input.principalARN), input.resourceNodeID}),
		ImpactedPath: []AWSCrossAccountTrustPathStep{
			awsLeastPrivilegePathStep(awsIdentityNodeIDForAPI(input.principalARN), "external_principal", principalLabel, principalAccount, input.region),
			awsLeastPrivilegePathStep(input.resourceNodeID, input.resourceType, resourceLabel, input.accountID, input.region),
		},
		Evidence:        []AWSCrossAccountTrustEvidence{{Source: input.source, EvidenceRef: evidenceRef, Label: "External resource trust", Confidence: input.confidence, ObservedAt: input.observedAt, Relationship: kind}},
		NextAction:      nextAction,
		RemediationCase: awsCrossAccountTrustRemediationCase(kind, status, score, awsIdentityNodeIDForAPI(input.principalARN), []string{evidenceRef}),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	return []AWSCrossAccountTrustFinding{finding}
}

func awsCrossAccountTrustGrantHasExplicitDeny(input awsCrossAccountTrustGrantInput) bool {
	if input.notAction {
		return false
	}
	for _, deny := range input.denyGrants {
		if deny.hasCondition {
			continue
		}
		if !awsPrivilegeEscalationIdentityGrantPrincipalsMatch(input.principalARN, deny.principalARN, deny.wildcardPrincipal) {
			continue
		}
		if awsCrossAccountTrustActionsFullyDenied(input.service, input.actions, input.capabilities, deny.actions, deny.capabilities, deny.notAction) {
			return true
		}
	}
	return false
}

func awsCrossAccountTrustActionsFullyDenied(service string, allowActions []string, allowCapabilities []string, denyActions []string, denyCapabilities []string, denyNotAction bool) bool {
	allow := awsCrossAccountTrustNormalizePolicyActions(service, allowActions, allowCapabilities)
	deny := awsCrossAccountTrustNormalizePolicyActions(service, denyActions, denyCapabilities)
	if len(allow) == 0 {
		return len(deny) == 0 || (denyNotAction && !awsCrossAccountTrustActionCoveredByAny("", deny))
	}
	for _, action := range allow {
		if denyNotAction {
			if awsCrossAccountTrustActionCoveredByAny(action, deny) {
				return false
			}
			continue
		}
		if !awsCrossAccountTrustActionCoveredByAny(action, deny) {
			return false
		}
	}
	return true
}

func awsCrossAccountTrustNormalizePolicyActions(service string, actions []string, capabilities []string) []string {
	out := []string{}
	normalizedService := normalizeAWSRuntimeEventFilterToken(service)
	appendAction := func(action string) {
		trimmed := strings.ToLower(strings.TrimSpace(action))
		if trimmed == "" {
			return
		}
		out = append(out, trimmed)
		if normalizedService != "" && !strings.Contains(trimmed, ":") {
			out = append(out, normalizedService+":"+trimmed)
		}
	}
	for _, action := range actions {
		appendAction(action)
	}
	for _, capability := range capabilities {
		appendAction(capability)
	}
	return dedupeStrings(out)
}

func awsCrossAccountTrustActionCoveredByAny(action string, patterns []string) bool {
	for _, pattern := range patterns {
		trimmedPattern := strings.ToLower(strings.TrimSpace(pattern))
		trimmedAction := strings.ToLower(strings.TrimSpace(action))
		if trimmedPattern == "" {
			continue
		}
		if trimmedAction == "" {
			return trimmedPattern == "*"
		}
		if awsActionPatternMatches(trimmedPattern, trimmedAction) {
			return true
		}
	}
	return false
}

func awsCrossAccountTrustDenyGrantsFromS3(grants []AWSS3IdentityGrant) []awsCrossAccountTrustExplicitDenyGrant {
	out := []awsCrossAccountTrustExplicitDenyGrant{}
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			out = append(out, awsCrossAccountTrustExplicitDenyGrant{
				principalARN:      grant.PrincipalARN,
				wildcardPrincipal: grant.WildcardPrincipal,
				actions:           grant.Actions,
				notAction:         grant.NotAction,
				hasCondition:      grant.HasCondition || len(grant.ConditionKeys) > 0,
			})
		}
	}
	return out
}

func awsCrossAccountTrustDenyGrantsFromKMS(grants []AWSKMSIdentityGrant) []awsCrossAccountTrustExplicitDenyGrant {
	out := []awsCrossAccountTrustExplicitDenyGrant{}
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			out = append(out, awsCrossAccountTrustExplicitDenyGrant{
				principalARN:      grant.PrincipalARN,
				wildcardPrincipal: grant.WildcardPrincipal,
				actions:           grant.Actions,
				capabilities:      grant.Capabilities,
				notAction:         grant.NotAction,
				hasCondition:      grant.HasCondition || len(grant.ConditionKeys) > 0,
			})
		}
	}
	return out
}

func awsCrossAccountTrustDenyGrantsFromSecrets(grants []AWSSecretsManagerIdentityGrant) []awsCrossAccountTrustExplicitDenyGrant {
	out := []awsCrossAccountTrustExplicitDenyGrant{}
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			out = append(out, awsCrossAccountTrustExplicitDenyGrant{
				principalARN:      grant.PrincipalARN,
				wildcardPrincipal: grant.WildcardPrincipal,
				actions:           grant.Actions,
				hasCondition:      grant.HasCondition || len(grant.ConditionKeys) > 0,
			})
		}
	}
	return out
}

func awsCrossAccountTrustDenyGrantsFromSQSSNS(grants []AWSSQSSNSIdentityGrant) []awsCrossAccountTrustExplicitDenyGrant {
	out := []awsCrossAccountTrustExplicitDenyGrant{}
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			out = append(out, awsCrossAccountTrustExplicitDenyGrant{
				principalARN:      grant.PrincipalARN,
				wildcardPrincipal: grant.WildcardPrincipal,
				actions:           grant.Actions,
				capabilities:      grant.Capabilities,
				notAction:         grant.NotAction,
				hasCondition:      grant.HasCondition || len(grant.ConditionKeys) > 0,
			})
		}
	}
	return out
}

func awsCrossAccountTrustDenyGrantsFromDynamoRDS(grants []AWSDynamoDBRDSIdentityGrant) []awsCrossAccountTrustExplicitDenyGrant {
	out := []awsCrossAccountTrustExplicitDenyGrant{}
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			out = append(out, awsCrossAccountTrustExplicitDenyGrant{
				principalARN:      grant.PrincipalARN,
				wildcardPrincipal: grant.WildcardPrincipal,
				actions:           grant.Actions,
				capabilities:      grant.Capabilities,
				notAction:         grant.NotAction,
				hasCondition:      grant.HasCondition || len(grant.ConditionKeys) > 0,
			})
		}
	}
	return out
}

func awsCrossAccountTrustFindingFromRuntimeAssumption(record AWSRuntimeEventRecord, accounts map[string]AWSOrganizationsTopologyAccount, now time.Time) (AWSCrossAccountTrustFinding, bool) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(record.Action)), "sts:assumerole") && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(record.EventName)), "assumerole") {
		return AWSCrossAccountTrustFinding{}, false
	}
	targetARN := firstNonEmptyAWSValue(record.Session.AssumedRoleARN, record.TargetResourceARN)
	targetAccount := awsCrossAccountTrustPrincipalAccount(targetARN)
	principal := firstNonEmptyAWSValue(record.Session.OriginalActorARN, record.ActorPrincipalARN)
	actorAccount := awsCrossAccountTrustPrincipalAccount(principal)
	if targetAccount == "" || principal == "" {
		return AWSCrossAccountTrustFinding{}, false
	}
	if actorAccount == "" {
		if !awsCrossAccountTrustRuntimeAllowsAccountlessActor(record) {
			return AWSCrossAccountTrustFinding{}, false
		}
	} else if targetAccount == actorAccount {
		if !awsCrossAccountTrustRuntimeAllowsSameAccountProviderARN(record, principal) {
			return AWSCrossAccountTrustFinding{}, false
		}
		actorAccount = ""
	}
	accountContext := accounts[actorAccount]
	score := 82
	if record.Session.SourceIdentity == "" {
		score += 6
	}
	score = clampBlastRadiusScore(score)
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, fmt.Sprintf("runtime-evidence://%s", record.EventID))
	return AWSCrossAccountTrustFinding{
		FindingID:                 "aws-cross-account-trust:" + stableAWSBlastRadiusToken("runtime_cross_account_assumption", record.EventID, principal, targetARN),
		CalculationVersion:        awsCrossAccountTrustVersion,
		FindingType:               "runtime_cross_account_assumption",
		Severity:                  awsPrivilegeEscalationSeverity(score),
		Status:                    awsPrivilegeEscalationFindingStatus(score, record.Confidence),
		Score:                     score,
		Confidence:                minFloat(record.Confidence, 0.92),
		AccountID:                 targetAccount,
		Region:                    record.Region,
		Service:                   "sts",
		ResourceType:              "iam_role",
		ResourceARN:               targetARN,
		ResourceNodeID:            firstNonEmptyAWSValue(record.ResourceNodeID, awsIdentityNodeIDForAPI(targetARN)),
		ResourceLabel:             firstNonEmptyAWSValue(shortAWSARN(targetARN), targetARN),
		ExternalPrincipalARN:      principal,
		ExternalPrincipalAccount:  actorAccount,
		ExternalPrincipalOUPath:   accountContext.OUPath,
		TrustedWithinOrganization: accountContext.AccountID != "",
		HasCondition:              record.Session.SourceIdentity != "",
		ConditionKeys:             awsCrossAccountTrustRuntimeConditionKeys(record),
		RuntimeObserved:           true,
		Rationale:                 fmt.Sprintf("Runtime evidence shows %s assuming %s across accounts.", firstNonEmptyAWSValue(shortAWSARN(principal), principal), firstNonEmptyAWSValue(shortAWSARN(targetARN), targetARN)),
		HardeningDirection:        "Review trust policy principal scope, source identity, external ID, and session-tag requirements for this observed cross-account assumption.",
		ImpactedNodes:             dedupeStrings([]string{awsIdentityNodeIDForAPI(principal), awsIdentityNodeIDForAPI(targetARN)}),
		ImpactedPath: []AWSCrossAccountTrustPathStep{
			awsLeastPrivilegePathStep(awsIdentityNodeIDForAPI(principal), "external_principal", firstNonEmptyAWSValue(shortAWSARN(principal), principal), actorAccount, record.Region),
			awsLeastPrivilegePathStep(awsIdentityNodeIDForAPI(targetARN), "iam_role", firstNonEmptyAWSValue(shortAWSARN(targetARN), targetARN), targetAccount, record.Region),
		},
		Evidence:        []AWSCrossAccountTrustEvidence{{Source: "runtime_events", EvidenceRef: evidenceRef, Label: "Observed STS AssumeRole", Confidence: record.Confidence, ObservedAt: record.ObservedAt, Relationship: "runtime_cross_account_assumption"}},
		NextAction:      "Confirm the session owner and add required trust-policy conditions before approving automated hardening.",
		RemediationCase: awsCrossAccountTrustRemediationCase("runtime-cross-account-assumption", "action_required", score, awsIdentityNodeIDForAPI(principal), []string{evidenceRef}),
		CreatedAt:       now,
		UpdatedAt:       now,
	}, true
}

func awsCrossAccountTrustRuntimeAllowsAccountlessActor(record AWSRuntimeEventRecord) bool {
	action := strings.ToLower(strings.TrimSpace(record.Action))
	eventName := strings.ToLower(strings.TrimSpace(record.EventName))
	return strings.Contains(action, "assumerolewithsaml") ||
		strings.Contains(eventName, "assumerolewithsaml") ||
		strings.Contains(action, "assumerolewithwebidentity") ||
		strings.Contains(eventName, "assumerolewithwebidentity")
}

func awsCrossAccountTrustRuntimeAllowsSameAccountProviderARN(record AWSRuntimeEventRecord, principal string) bool {
	if !awsCrossAccountTrustRuntimeAllowsAccountlessActor(record) {
		return false
	}
	parts := strings.SplitN(strings.TrimSpace(principal), ":", 6)
	if len(parts) < 6 {
		return false
	}
	resource := strings.ToLower(strings.TrimSpace(parts[5]))
	return strings.HasPrefix(resource, "saml-provider/") || strings.HasPrefix(resource, "oidc-provider/")
}

func awsCrossAccountTrustFindingFromLeastPrivilege(recommendation AWSLeastPrivilegeRecommendation, accounts map[string]AWSOrganizationsTopologyAccount, now time.Time) (AWSCrossAccountTrustFinding, bool) {
	if normalizeAWSRuntimeEventFilterToken(recommendation.RecommendationType) != "review-external-access" {
		return AWSCrossAccountTrustFinding{}, false
	}
	principalAccount := awsCrossAccountTrustPrincipalAccount(recommendation.PrincipalARN)
	accountContext := accounts[principalAccount]
	evidenceRef := firstString(awsCrossAccountTrustEvidenceRefs([]AWSCrossAccountTrustEvidence(recommendation.Evidence)))
	if evidenceRef == "" {
		evidenceRef = "least-privilege://" + recommendation.RecommendationID
	}
	score := clampBlastRadiusScore(recommendation.Score + 4)
	return AWSCrossAccountTrustFinding{
		FindingID:                 "aws-cross-account-trust:" + stableAWSBlastRadiusToken("access_analyzer_external_access", recommendation.RecommendationID),
		CalculationVersion:        awsCrossAccountTrustVersion,
		FindingType:               "access_analyzer_external_access",
		Severity:                  awsPrivilegeEscalationSeverity(score),
		Status:                    recommendation.Status,
		Score:                     score,
		Confidence:                recommendation.Confidence,
		AccountID:                 recommendation.AccountID,
		Region:                    recommendation.Region,
		Service:                   recommendation.Service,
		ResourceType:              firstNonEmptyAWSValue(recommendation.Service, "resource"),
		ResourceARN:               recommendation.ResourceARN,
		ResourceNodeID:            recommendation.ResourceNodeID,
		ResourceLabel:             firstNonEmptyAWSValue(recommendation.ResourceARN, recommendation.ResourceNodeID, recommendation.Service),
		ExternalPrincipalARN:      recommendation.PrincipalARN,
		ExternalPrincipalAccount:  principalAccount,
		ExternalPrincipalOUPath:   accountContext.OUPath,
		TrustedWithinOrganization: accountContext.AccountID != "",
		PolicySources:             recommendation.GrantedActions,
		AnalyzerBacked:            true,
		Rationale:                 recommendation.Rationale,
		HardeningDirection:        "Validate Access Analyzer scope and expected external principal, then narrow or remove the external-access grant.",
		ImpactedNodes:             recommendation.ImpactedNodes,
		ImpactedPath:              []AWSCrossAccountTrustPathStep(recommendation.ImpactedPath),
		Evidence:                  []AWSCrossAccountTrustEvidence(recommendation.Evidence),
		NextAction:                recommendation.NextAction,
		RemediationCase:           awsCrossAccountTrustRemediationCase("access-analyzer-external-access", recommendation.Status, score, recommendation.IdentityNodeID, []string{evidenceRef}),
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}, true
}

func awsCrossAccountTrustFindingFromBlastRadius(finding AWSBlastRadiusFinding, accounts map[string]AWSOrganizationsTopologyAccount, now time.Time) (AWSCrossAccountTrustFinding, bool) {
	if len(finding.CrossAccountEdges) == 0 {
		return AWSCrossAccountTrustFinding{}, false
	}
	principalAccount := awsCrossAccountTrustPrincipalAccount(finding.PrincipalARN)
	accountContext := accounts[principalAccount]
	evidenceRef := firstEvidenceRef(finding.Evidence)
	score := clampBlastRadiusScore(finding.Score + 3)
	return AWSCrossAccountTrustFinding{
		FindingID:                 "aws-cross-account-trust:" + stableAWSBlastRadiusToken("cross_account_graph_path", finding.FindingID),
		CalculationVersion:        awsCrossAccountTrustVersion,
		FindingType:               "cross_account_graph_path",
		Severity:                  awsPrivilegeEscalationSeverity(score),
		Status:                    finding.Status,
		Score:                     score,
		Confidence:                finding.Confidence,
		AccountID:                 finding.AccountID,
		Region:                    finding.Region,
		Service:                   firstNonEmptyAWSValue(serviceFromAWSAction(firstString(finding.RuntimeActions)), "aws"),
		ResourceType:              "graph_path",
		ResourceNodeID:            lastString(finding.ImpactedNodes),
		ResourceLabel:             firstNonEmptyAWSValue(lastString(finding.ImpactedNodes), finding.RiskType),
		ExternalPrincipalARN:      finding.PrincipalARN,
		ExternalPrincipalAccount:  principalAccount,
		ExternalPrincipalOUPath:   accountContext.OUPath,
		TrustedWithinOrganization: accountContext.AccountID != "",
		RuntimeObserved:           true,
		Rationale:                 finding.Rationale,
		HardeningDirection:        "Review the cross-account graph edge and narrow the upstream trust, resource grant, or runtime path that created it.",
		ImpactedNodes:             finding.ImpactedNodes,
		ImpactedPath:              awsCrossAccountTrustPathFromBlastRadius(finding.ImpactedPath),
		Evidence:                  awsCrossAccountTrustEvidenceFromBlastRadius(finding.Evidence),
		NextAction:                finding.NextAction,
		RemediationCase:           awsCrossAccountTrustRemediationCase("cross-account-graph-path", finding.Status, score, finding.IdentityNodeID, []string{evidenceRef}),
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}, true
}

func awsCrossAccountTrustDedupeFindings(findings []AWSCrossAccountTrustFinding) []AWSCrossAccountTrustFinding {
	seen := map[string]AWSCrossAccountTrustFinding{}
	seenOrder := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.FindingID == "" {
			continue
		}
		if _, ok := seen[finding.FindingID]; !ok {
			seenOrder = append(seenOrder, finding.FindingID)
		}
		if existing, ok := seen[finding.FindingID]; ok && existing.Score >= finding.Score {
			continue
		}
		seen[finding.FindingID] = finding
	}
	corroborated := map[string]AWSCrossAccountTrustFinding{}
	corroboratedOrder := make([]string, 0, len(seenOrder))
	for _, findingID := range seenOrder {
		finding, ok := seen[findingID]
		if !ok {
			continue
		}
		key := awsCrossAccountTrustCorroborationKey(finding)
		if key == "" {
			key = "finding:" + finding.FindingID
		}
		if _, ok := corroborated[key]; !ok {
			corroboratedOrder = append(corroboratedOrder, key)
			corroborated[key] = finding
			continue
		}
		if existing, ok := corroborated[key]; ok {
			corroborated[key] = awsCrossAccountTrustMergeCorroboratingFindings(existing, finding)
		}
	}
	out := make([]AWSCrossAccountTrustFinding, 0, len(corroborated))
	for _, key := range corroboratedOrder {
		if finding, ok := corroborated[key]; ok {
			out = append(out, finding)
		}
	}
	return out
}

func awsCrossAccountTrustCorroborationKey(finding AWSCrossAccountTrustFinding) string {
	principal := strings.ToLower(strings.TrimSpace(firstNonEmptyAWSValue(finding.ExternalPrincipalARN, finding.ExternalPrincipalAccount)))
	resource := strings.ToLower(strings.TrimSpace(firstNonEmptyAWSValue(finding.ResourceARN, finding.ResourceNodeID)))
	if principal == "" || resource == "" {
		return ""
	}
	return principal + "|" + resource
}

func awsCrossAccountTrustMergeCorroboratingFindings(existing, incoming AWSCrossAccountTrustFinding) AWSCrossAccountTrustFinding {
	base, other := existing, incoming
	if awsCrossAccountTrustPrefersCorroborationBase(incoming, existing) {
		base, other = incoming, existing
	}
	base.RuntimeObserved = base.RuntimeObserved || other.RuntimeObserved
	base.AnalyzerBacked = base.AnalyzerBacked || other.AnalyzerBacked
	base.PublicPrincipal = base.PublicPrincipal || other.PublicPrincipal
	base.TrustedWithinOrganization = base.TrustedWithinOrganization || other.TrustedWithinOrganization
	base.HasCondition = base.HasCondition && other.HasCondition
	base.ConditionKeys = dedupeStrings(append(base.ConditionKeys, other.ConditionKeys...))
	base.PolicySources = dedupeStrings(append(base.PolicySources, other.PolicySources...))
	base.ImpactedNodes = dedupeStrings(append(base.ImpactedNodes, other.ImpactedNodes...))
	base.Evidence = append(base.Evidence, other.Evidence...)
	if len(base.ImpactedPath) == 0 {
		base.ImpactedPath = other.ImpactedPath
	}
	if base.ExternalPrincipalAccount == "" {
		base.ExternalPrincipalAccount = other.ExternalPrincipalAccount
	}
	if base.ExternalPrincipalOUPath == "" {
		base.ExternalPrincipalOUPath = other.ExternalPrincipalOUPath
	}
	if base.Service == "" {
		base.Service = other.Service
	}
	if base.ResourceType == "" {
		base.ResourceType = other.ResourceType
	}
	if base.ResourceARN == "" {
		base.ResourceARN = other.ResourceARN
	}
	if base.ResourceNodeID == "" {
		base.ResourceNodeID = other.ResourceNodeID
	}
	if base.ResourceLabel == "" {
		base.ResourceLabel = other.ResourceLabel
	}
	if base.Confidence < other.Confidence {
		base.Confidence = other.Confidence
	}
	if other.Score > base.Score {
		base.Score = other.Score
		base.Severity = awsPrivilegeEscalationSeverity(base.Score)
	}
	base.Status = awsPrivilegeEscalationFindingStatus(base.Score, base.Confidence)
	if other.UpdatedAt.After(base.UpdatedAt) {
		base.UpdatedAt = other.UpdatedAt
	}
	return base
}

func awsCrossAccountTrustPrefersCorroborationBase(candidate, current AWSCrossAccountTrustFinding) bool {
	candidateIAMRole := awsCrossAccountTrustFindingTargetsIAMRole(candidate)
	currentIAMRole := awsCrossAccountTrustFindingTargetsIAMRole(current)
	if candidate.RuntimeObserved && candidateIAMRole && !(current.RuntimeObserved && currentIAMRole) {
		return true
	}
	if current.RuntimeObserved && currentIAMRole && !(candidate.RuntimeObserved && candidateIAMRole) {
		return false
	}
	if candidateIAMRole && !currentIAMRole {
		return true
	}
	if candidate.Score != current.Score {
		return candidate.Score > current.Score && !(current.RuntimeObserved && currentIAMRole)
	}
	return candidate.FindingID < current.FindingID
}

func awsCrossAccountTrustFindingTargetsIAMRole(finding AWSCrossAccountTrustFinding) bool {
	resourceType := normalizeAWSRuntimeEventFilterToken(finding.ResourceType)
	resourceARN := strings.ToLower(strings.TrimSpace(finding.ResourceARN))
	return resourceType == "iam-role" || resourceType == "iam_role" || strings.Contains(resourceARN, ":role/")
}

func filterAWSCrossAccountTrustFindings(findings []AWSCrossAccountTrustFinding, request AWSCrossAccountTrustRequest) ([]AWSCrossAccountTrustFinding, map[string]string) {
	filters := map[string]string{
		"account_id":   strings.TrimSpace(request.AccountID),
		"region":       strings.TrimSpace(request.Region),
		"service":      normalizeAWSRuntimeEventFilterToken(request.Service),
		"principal":    strings.TrimSpace(request.Principal),
		"resource":     strings.TrimSpace(request.Resource),
		"finding_type": normalizeAWSRuntimeEventFilterToken(request.FindingType),
		"severity":     normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":       normalizeAWSRuntimeEventFilterToken(request.Status),
		"ou":           strings.TrimSpace(request.OU),
	}
	for key, value := range filters {
		if strings.TrimSpace(value) == "" || strings.EqualFold(value, "all") {
			delete(filters, key)
		}
	}
	filtered := make([]AWSCrossAccountTrustFinding, 0, len(findings))
	for _, finding := range findings {
		if filters["account_id"] != "" && !awsRuntimeEventMatchesAny(filters["account_id"], finding.AccountID) {
			continue
		}
		if filters["region"] != "" && !awsRuntimeEventMatchesAny(filters["region"], finding.Region) {
			continue
		}
		if filters["service"] != "" && normalizeAWSRuntimeEventFilterToken(finding.Service) != filters["service"] {
			continue
		}
		if filters["principal"] != "" && !awsRuntimeEventMatchesAny(filters["principal"], finding.ExternalPrincipalARN, finding.ExternalPrincipalAccount, finding.ExternalPrincipalOUPath) {
			continue
		}
		if filters["resource"] != "" && !awsRuntimeEventMatchesAny(filters["resource"], finding.ResourceARN, finding.ResourceNodeID, finding.ResourceLabel) {
			continue
		}
		if filters["finding_type"] != "" && normalizeAWSRuntimeEventFilterToken(finding.FindingType) != filters["finding_type"] {
			continue
		}
		if filters["severity"] != "" && normalizeAWSRuntimeEventFilterToken(finding.Severity) != filters["severity"] {
			continue
		}
		if filters["status"] != "" && normalizeAWSRuntimeEventFilterToken(finding.Status) != filters["status"] {
			continue
		}
		if filters["ou"] != "" && !awsRuntimeEventMatchesAny(filters["ou"], finding.ExternalPrincipalOUPath) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, filters
}

func awsCrossAccountTrustRelationships(findings []AWSCrossAccountTrustFinding) []AWSCrossAccountTrustRelationship {
	relationships := []AWSCrossAccountTrustRelationship{}
	for _, finding := range findings {
		evidenceRef := firstString(awsCrossAccountTrustEvidenceRefs(finding.Evidence))
		for i := 1; i < len(finding.ImpactedPath); i++ {
			from := strings.TrimSpace(finding.ImpactedPath[i-1].NodeID)
			to := strings.TrimSpace(finding.ImpactedPath[i].NodeID)
			if from == "" || to == "" || from == "*" || to == "*" {
				continue
			}
			relationships = append(relationships, AWSCrossAccountTrustRelationship{FindingID: finding.FindingID, Type: "cross_account_trust_path", FromNodeID: from, ToNodeID: to, EvidenceRef: evidenceRef})
		}
	}
	return relationships
}

func summarizeAWSCrossAccountTrust(allFindings []AWSCrossAccountTrustFinding, filtered []AWSCrossAccountTrustFinding, relationships []AWSCrossAccountTrustRelationship) AWSCrossAccountTrustSummary {
	severityCounts := map[string]int{}
	statusCounts := map[string]int{}
	typeCounts := map[string]int{}
	serviceCounts := map[string]int{}
	totalConfidence := 0.0
	highest := 0
	publicCount := 0
	runtimeCount := 0
	analyzerCount := 0
	unconditionalCount := 0
	for _, finding := range filtered {
		severityCounts[finding.Severity]++
		statusCounts[finding.Status]++
		typeCounts[finding.FindingType]++
		serviceCounts[finding.Service]++
		totalConfidence += finding.Confidence
		if finding.Score > highest {
			highest = finding.Score
		}
		if finding.PublicPrincipal {
			publicCount++
		}
		if finding.RuntimeObserved {
			runtimeCount++
		}
		if finding.AnalyzerBacked {
			analyzerCount++
		}
		if !finding.HasCondition && (finding.FindingType == "cross_account_resource_access" || finding.FindingType == "public_resource_trust") {
			unconditionalCount++
		}
	}
	avg := 0
	if len(filtered) > 0 {
		avg = int((totalConfidence / float64(len(filtered))) * 100)
	}
	return AWSCrossAccountTrustSummary{
		TotalFindings:           len(allFindings),
		FilteredFindings:        len(filtered),
		SeverityCounts:          severityCounts,
		StatusCounts:            statusCounts,
		FindingTypeCounts:       typeCounts,
		ServiceCounts:           serviceCounts,
		CriticalCount:           severityCounts["critical"],
		HighCount:               severityCounts["high"],
		PublicPrincipalCount:    publicCount,
		CrossAccountGrantCount:  typeCounts["cross_account_resource_access"],
		RuntimeObservedCount:    runtimeCount,
		AnalyzerBackedCount:     analyzerCount,
		UnconditionalGrantCount: unconditionalCount,
		RelationshipCount:       len(relationships),
		HighestScore:            highest,
		AverageConfidencePct:    avg,
		RemediationPreviewCount: len(filtered),
	}
}

func summarizeAWSCrossAccountTrustStatus(sources awsCrossAccountTrustSources, diagnostics []AWSCrossAccountTrustDiagnostic) (string, float64) {
	if awsCrossAccountTrustSourcesAreEmptyFixtures(sources) && len(diagnostics) == 0 {
		return "ready", 0.9
	}
	statuses := []string{sources.organizations.Status, sources.s3.Status, sources.kms.Status, sources.secrets.Status, sources.sqsSNS.Status, sources.dynamoRDS.Status, sources.runtime.Status, sources.least.Status, sources.blast.Status}
	blocked := 0
	for _, status := range statuses {
		switch normalizeAWSRuntimeEventFilterToken(status) {
		case "blocked", "permission-denied":
			blocked++
		case "degraded", "partial-failure", "capability-unavailable":
			return "degraded", 0.68
		}
	}
	if blocked == len(statuses) {
		return "blocked", 0
	}
	if blocked > 0 || len(diagnostics) > 0 {
		return "degraded", 0.72
	}
	return "ready", 0.9
}

func awsCrossAccountTrustSourcesAreEmptyFixtures(sources awsCrossAccountTrustSources) bool {
	states := []string{
		sources.organizations.FixtureState,
		sources.s3.FixtureState,
		sources.kms.FixtureState,
		sources.secrets.FixtureState,
		sources.sqsSNS.FixtureState,
		sources.dynamoRDS.FixtureState,
		sources.runtime.FixtureState,
		sources.least.FixtureState,
		sources.blast.FixtureState,
	}
	for _, state := range states {
		if normalizeAWSRuntimeEventFilterToken(state) != "empty" {
			return false
		}
	}
	return true
}

func awsCrossAccountTrustDiagnostics(sources awsCrossAccountTrustSources) []AWSCrossAccountTrustDiagnostic {
	out := []AWSCrossAccountTrustDiagnostic{}
	for _, diagnostic := range sources.organizations.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic{Collector: diagnostic.Source, SourceID: diagnostic.Scope, Code: diagnostic.Code, Message: diagnostic.Message, Remediation: diagnostic.Remediation, Retryable: diagnostic.Retryable})
	}
	for _, diagnostic := range sources.least.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic(diagnostic))
	}
	for _, diagnostic := range sources.blast.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic(diagnostic))
	}
	for _, diagnostic := range sources.runtime.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic{Collector: diagnostic.Collector, SourceID: diagnostic.SourceID, Code: diagnostic.Code, Message: diagnostic.Message, Remediation: diagnostic.Remediation, Retryable: diagnostic.Retryable})
	}
	for _, diagnostic := range sources.s3.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic{Collector: diagnostic.Collector, SourceID: diagnostic.SourceID, Code: diagnostic.Code, Message: diagnostic.Message, Remediation: diagnostic.Remediation, Retryable: diagnostic.Retryable})
	}
	for _, diagnostic := range sources.kms.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic{Collector: diagnostic.Collector, SourceID: diagnostic.SourceID, Code: diagnostic.Code, Message: diagnostic.Message, Remediation: diagnostic.Remediation, Retryable: diagnostic.Retryable})
	}
	for _, diagnostic := range sources.secrets.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic{Collector: diagnostic.Collector, SourceID: diagnostic.SourceID, Code: diagnostic.Code, Message: diagnostic.Message, Remediation: diagnostic.Remediation, Retryable: diagnostic.Retryable})
	}
	for _, diagnostic := range sources.sqsSNS.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic{Collector: diagnostic.Collector, SourceID: diagnostic.SourceID, Code: diagnostic.Code, Message: diagnostic.Message, Remediation: diagnostic.Remediation, Retryable: diagnostic.Retryable})
	}
	for _, diagnostic := range sources.dynamoRDS.Diagnostics {
		out = append(out, AWSCrossAccountTrustDiagnostic{Collector: diagnostic.Collector, SourceID: diagnostic.SourceID, Code: diagnostic.Code, Message: diagnostic.Message, Remediation: diagnostic.Remediation, Retryable: diagnostic.Retryable})
	}
	return out
}

func awsCrossAccountTrustCoverageGaps(sources awsCrossAccountTrustSources) []AWSCrossAccountTrustCoverageGap {
	out := []AWSCrossAccountTrustCoverageGap{{
		Capability:  "raw_trust_policy_simulation",
		Status:      "planned_downstream",
		Reason:      "This engine reasons over normalized trust, resource-policy, runtime, Organizations, Access Analyzer, and graph evidence; it does not execute AWS mutations or policy simulation.",
		Remediation: "Use the trust-policy hardening planner for approved remediation previews after this engine identifies candidate external access.",
	}}
	for _, gap := range sources.least.CoverageGaps {
		out = append(out, AWSCrossAccountTrustCoverageGap(gap))
	}
	for _, gap := range sources.blast.CoverageGaps {
		out = append(out, AWSCrossAccountTrustCoverageGap(gap))
	}
	for _, gap := range sources.runtime.CoverageGaps {
		out = append(out, AWSCrossAccountTrustCoverageGap{Capability: gap.Capability, Status: gap.Status, Reason: gap.Reason, Remediation: gap.Remediation})
	}
	return out
}

func awsCrossAccountTrustCaveats() []string {
	return []string{
		"Cross-account trust findings are inferred from metadata-only Organizations, resource policy, Access Analyzer, runtime, and graph evidence.",
		"Unknown, unsupported, permission-denied, and partially failed evidence lowers confidence and is never treated as proof that external access is absent.",
		"Remediation cases are read-only previews; this engine does not mutate trust policies, resource policies, SCPs, or customer payloads.",
	}
}

func awsCrossAccountTrustFailureReasons(sources awsCrossAccountTrustSources) []string {
	return emptyStrings(dedupeStrings(append(append(append(append(append(append(append(sources.organizations.FailureReasons, sources.s3.FailureReasons...), sources.kms.FailureReasons...), sources.secrets.FailureReasons...), sources.sqsSNS.FailureReasons...), sources.dynamoRDS.FailureReasons...), sources.runtime.FailureReasons...), append(sources.least.FailureReasons, sources.blast.FailureReasons...)...)))
}

func awsCrossAccountTrustRemediationHints(sources awsCrossAccountTrustSources) []string {
	hints := append(append(append(append(append(append(append(sources.organizations.RemediationHints, sources.s3.RemediationHints...), sources.kms.RemediationHints...), sources.secrets.RemediationHints...), sources.sqsSNS.RemediationHints...), sources.dynamoRDS.RemediationHints...), sources.runtime.RemediationHints...), append(sources.least.RemediationHints, sources.blast.RemediationHints...)...)
	hints = append(hints, "Review external principals against approved account, OU, external ID, and runtime-use evidence before creating trust-policy hardening cases.")
	return emptyStrings(dedupeStrings(hints))
}

func awsCrossAccountTrustRemediationCase(kind, status string, score int, identityNodeID string, evidence []string) AWSCrossAccountTrustRemediationCasePreview {
	return AWSCrossAccountTrustRemediationCasePreview{
		CaseID:             "aws-cross-account-trust-preview:" + stableAWSBlastRadiusToken(kind, identityNodeID),
		Title:              fmt.Sprintf("%s trust hardening", formatAWSBlastRadiusLabel(kind)),
		RecommendedAction:  "Create an owner-approved trust/resource-policy hardening preview; do not mutate AWS until the external principal and evidence boundary are confirmed.",
		ApprovalRequired:   status == "action_required" || score >= 72,
		BlockingEvidence:   evidence,
		ImpactedNodeCount:  1,
		EstimatedRiskDrop:  minInt(score, 35),
		BreakagePrediction: "unknown",
		ReadOnlyProjection: true,
	}
}

func awsCrossAccountTrustHardeningDirection(publicPrincipal, hasCondition, trustedWithinOrg bool) string {
	switch {
	case publicPrincipal && !hasCondition:
		return "Replace wildcard trust with explicit principals and required conditions such as organization, external ID, source ARN, or source account."
	case publicPrincipal:
		return "Confirm every condition is expected, then replace wildcard trust with explicit approved principals where possible."
	case trustedWithinOrg && !hasCondition:
		return "Constrain same-organization external access to approved OU/account paths and add source-account or external-ID conditions."
	case !hasCondition:
		return "Add an external ID or equivalent source condition and narrow the principal to the approved external account or role."
	default:
		return "Validate the existing conditions and remove any unused external principal or action scope."
	}
}

func awsCrossAccountTrustOrganizationAccounts(topology AWSOrganizationsTopologyResult) map[string]AWSOrganizationsTopologyAccount {
	accounts := map[string]AWSOrganizationsTopologyAccount{}
	for _, account := range topology.Accounts {
		if strings.TrimSpace(account.AccountID) != "" {
			accounts[account.AccountID] = account
		}
	}
	return accounts
}

func awsCrossAccountTrustPrincipalIsExternal(principalARN string, ownerAccountID string) bool {
	accountID := awsCrossAccountTrustPrincipalAccount(principalARN)
	return accountID != "" && ownerAccountID != "" && accountID != ownerAccountID
}

func awsCrossAccountTrustPrincipalAccount(principalARN string) string {
	parts := strings.Split(strings.TrimSpace(principalARN), ":")
	if len(parts) > 4 && len(parts[4]) == 12 {
		return parts[4]
	}
	token := strings.TrimSpace(principalARN)
	if len(token) == 12 {
		allDigits := true
		for _, r := range token {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return token
		}
	}
	return ""
}

func awsCrossAccountTrustRuntimeConditionKeys(record AWSRuntimeEventRecord) []string {
	keys := []string{}
	if strings.TrimSpace(record.Session.SourceIdentity) != "" {
		keys = append(keys, "sts:SourceIdentity")
	}
	if len(record.Session.SessionTagKeys) > 0 {
		keys = append(keys, "aws:PrincipalTag")
	}
	return dedupeStrings(keys)
}

func awsCrossAccountTrustPathFromBlastRadius(path []AWSBlastRadiusPathStep) []AWSCrossAccountTrustPathStep {
	out := make([]AWSCrossAccountTrustPathStep, 0, len(path))
	for _, step := range path {
		out = append(out, AWSCrossAccountTrustPathStep{
			NodeID:    step.NodeID,
			NodeType:  step.NodeType,
			Label:     step.Label,
			AccountID: step.AccountID,
			Region:    step.Region,
		})
	}
	return out
}

func awsCrossAccountTrustEvidenceFromBlastRadius(evidence []AWSBlastRadiusEvidence) []AWSCrossAccountTrustEvidence {
	out := make([]AWSCrossAccountTrustEvidence, 0, len(evidence))
	for _, item := range evidence {
		out = append(out, AWSCrossAccountTrustEvidence{
			Source:       item.Source,
			EvidenceRef:  item.EvidenceRef,
			Label:        item.Label,
			Confidence:   item.Confidence,
			ObservedAt:   item.ObservedAt,
			Relationship: item.Relationship,
		})
	}
	return out
}

func awsCrossAccountTrustEvidenceRefs(evidence []AWSCrossAccountTrustEvidence) []string {
	out := []string{}
	for _, item := range evidence {
		out = append(out, item.EvidenceRef)
	}
	return out
}

func firstNonZeroFloat(values ...float64) float64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
