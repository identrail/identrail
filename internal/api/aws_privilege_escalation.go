package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsPrivilegeEscalationCurrentIssue = 1525
	awsPrivilegeEscalationVersion      = "aws-privilege-escalation-engine-v1"
)

// AWSPrivilegeEscalationRequest scopes the read-only escalation-path
// calculation to AWS evidence and optional drill-down filters.
type AWSPrivilegeEscalationRequest struct {
	ConnectorID    string `json:"connector_id,omitempty"`
	FixtureState   string `json:"fixture_state,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	Region         string `json:"region,omitempty"`
	Identity       string `json:"identity,omitempty"`
	Target         string `json:"target,omitempty"`
	EscalationType string `json:"escalation_type,omitempty"`
	Severity       string `json:"severity,omitempty"`
	Status         string `json:"status,omitempty"`
}

type AWSPrivilegeEscalationEvidence = AWSLeastPrivilegeEvidence
type AWSPrivilegeEscalationPathStep = AWSLeastPrivilegePathStep
type AWSPrivilegeEscalationRemediationCasePreview = AWSLeastPrivilegeRemediationCasePreview
type AWSPrivilegeEscalationDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSPrivilegeEscalationCoverageGap = AWSLeastPrivilegeCoverageGap

// AWSPrivilegeEscalationRelationship lets graph consumers join a finding back
// to the source identity, escalation primitive, and impacted target.
type AWSPrivilegeEscalationRelationship struct {
	FindingID   string `json:"finding_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSPrivilegeEscalationFinding is the deterministic finding shape for
// PassRole, policy attachment, trust, admin, KMS/secrets, and cross-account
// escalation paths. It is read-only and carries evidence pointers only.
type AWSPrivilegeEscalationFinding struct {
	FindingID          string                                       `json:"finding_id"`
	CalculationVersion string                                       `json:"calculation_version"`
	EscalationType     string                                       `json:"escalation_type"`
	Severity           string                                       `json:"severity"`
	Status             string                                       `json:"status"`
	Score              int                                          `json:"score"`
	Confidence         float64                                      `json:"confidence"`
	AccountID          string                                       `json:"account_id"`
	Region             string                                       `json:"region"`
	IdentityNodeID     string                                       `json:"identity_node_id"`
	PrincipalARN       string                                       `json:"principal_arn,omitempty"`
	TargetNodeID       string                                       `json:"target_node_id,omitempty"`
	TargetLabel        string                                       `json:"target_label"`
	DisplayName        string                                       `json:"display_name"`
	Rationale          string                                       `json:"rationale"`
	Exploitability     string                                       `json:"exploitability"`
	RuntimeContext     string                                       `json:"runtime_context"`
	PolicySources      []string                                     `json:"policy_sources,omitempty"`
	ImpactedNodes      []string                                     `json:"impacted_nodes"`
	ImpactedPath       []AWSPrivilegeEscalationPathStep             `json:"impacted_path"`
	Evidence           []AWSPrivilegeEscalationEvidence             `json:"evidence"`
	NextAction         string                                       `json:"next_action"`
	RemediationCase    AWSPrivilegeEscalationRemediationCasePreview `json:"remediation_case"`
	CreatedAt          time.Time                                    `json:"created_at"`
	UpdatedAt          time.Time                                    `json:"updated_at"`
}

// AWSPrivilegeEscalationSummary aggregates unfiltered and filtered paths.
type AWSPrivilegeEscalationSummary struct {
	TotalFindings           int            `json:"total_findings"`
	FilteredFindings        int            `json:"filtered_findings"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	StatusCounts            map[string]int `json:"status_counts"`
	EscalationTypeCounts    map[string]int `json:"escalation_type_counts"`
	CriticalCount           int            `json:"critical_count"`
	HighCount               int            `json:"high_count"`
	CrossAccountPathCount   int            `json:"cross_account_path_count"`
	PassRolePathCount       int            `json:"passrole_path_count"`
	AdminEquivalentCount    int            `json:"admin_equivalent_count"`
	RelationshipCount       int            `json:"relationship_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
	RemediationPreviewCount int            `json:"remediation_preview_count"`
}

// AWSPrivilegeEscalationResult is the deterministic engine envelope.
type AWSPrivilegeEscalationResult struct {
	TenantID           string                               `json:"tenant_id"`
	WorkspaceID        string                               `json:"workspace_id"`
	ProjectID          string                               `json:"project_id"`
	ConnectorID        string                               `json:"connector_id,omitempty"`
	AccountID          string                               `json:"account_id,omitempty"`
	Region             string                               `json:"region,omitempty"`
	ParentIssueNumber  int                                  `json:"parent_issue_number"`
	ParentIssueRef     string                               `json:"parent_issue_ref"`
	CurrentIssueNumber int                                  `json:"current_issue_number"`
	CurrentIssueRef    string                               `json:"current_issue_ref"`
	Version            string                               `json:"version"`
	Status             string                               `json:"status"`
	FixtureState       string                               `json:"fixture_state,omitempty"`
	Confidence         float64                              `json:"confidence"`
	CalculationVersion string                               `json:"calculation_version"`
	AppliedFilters     map[string]string                    `json:"applied_filters"`
	Summary            AWSPrivilegeEscalationSummary        `json:"summary"`
	Findings           []AWSPrivilegeEscalationFinding      `json:"findings"`
	Relationships      []AWSPrivilegeEscalationRelationship `json:"relationships"`
	Caveats            []string                             `json:"caveats"`
	FailureReasons     []string                             `json:"failure_reasons"`
	RemediationHints   []string                             `json:"remediation_hints"`
	EvidenceLinks      []string                             `json:"evidence_links"`
	CoverageGaps       []AWSPrivilegeEscalationCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSPrivilegeEscalationDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                            `json:"generated_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

func (s *Service) GetAWSPrivilegeEscalation(ctx context.Context, workspaceID string, projectID string, request AWSPrivilegeEscalationRequest) (AWSPrivilegeEscalationResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSPrivilegeEscalationResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSPrivilegeEscalationResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSPrivilegeEscalationFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSPrivilegeEscalationResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	passRole, kms, secrets, leastPrivilege, blastRadius, err := s.awsPrivilegeEscalationSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSPrivilegeEscalationResult{}, err
	}
	findings := awsPrivilegeEscalationFindings(passRole, kms, secrets, leastPrivilege, blastRadius, now)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Score > findings[j].Score
	})
	filtered, applied := filterAWSPrivilegeEscalationFindings(findings, request)
	relationships := awsPrivilegeEscalationRelationships(filtered)
	diagnostics := awsPrivilegeEscalationDiagnostics(passRole, kms, secrets, leastPrivilege, blastRadius)
	coverageGaps := awsPrivilegeEscalationCoverageGaps(passRole, kms, secrets, leastPrivilege, blastRadius)
	status, confidence := summarizeAWSPrivilegeEscalationStatus([]string{passRole.Status, kms.Status, secrets.Status, leastPrivilege.Status, blastRadius.Status}, diagnostics)
	summary := summarizeAWSPrivilegeEscalation(findings, filtered, relationships)

	return AWSPrivilegeEscalationResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsPrivilegeEscalationCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsPrivilegeEscalationCurrentIssue),
		Version:            awsPrivilegeEscalationVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsPrivilegeEscalationVersion,
		AppliedFilters:     applied,
		Summary:            summary,
		Findings:           filtered,
		Relationships:      relationships,
		Caveats:            awsPrivilegeEscalationCaveats(),
		FailureReasons:     awsPrivilegeEscalationFailureReasons(passRole, kms, secrets, leastPrivilege, blastRadius),
		RemediationHints:   awsPrivilegeEscalationRemediationHints(passRole, kms, secrets, leastPrivilege, blastRadius),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPrivilegeEscalationCurrentIssue),
			awsIssueURL(awsIAMPassRoleRelationshipCurrentIssue),
			awsIssueURL(awsBlastRadiusCurrentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			"/docs/aws-privilege-escalation-engine",
			"/docs/aws-iam-passrole-relationships",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSPrivilegeEscalationFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsPrivilegeEscalationSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (AWSIAMPassRoleRelationshipInventoryResult, AWSKMSDecryptReachabilityInventoryResult, AWSSecretsManagerMetadataInventoryResult, AWSLeastPrivilegeResult, AWSBlastRadiusResult, error) {
	passRole, err := s.GetAWSIAMPassRoleRelationshipInventory(ctx, workspaceID, projectID, AWSIAMPassRoleRelationshipInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return AWSIAMPassRoleRelationshipInventoryResult{}, AWSKMSDecryptReachabilityInventoryResult{}, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, fmt.Errorf("privilege escalation passrole relationships: %w", err)
	}
	kms, err := s.GetAWSKMSDecryptReachabilityInventory(ctx, workspaceID, projectID, AWSKMSDecryptReachabilityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return AWSIAMPassRoleRelationshipInventoryResult{}, AWSKMSDecryptReachabilityInventoryResult{}, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, fmt.Errorf("privilege escalation kms reachability: %w", err)
	}
	secrets, err := s.GetAWSSecretsManagerMetadataInventory(ctx, workspaceID, projectID, AWSSecretsManagerMetadataInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return AWSIAMPassRoleRelationshipInventoryResult{}, AWSKMSDecryptReachabilityInventoryResult{}, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, fmt.Errorf("privilege escalation secrets metadata: %w", err)
	}
	leastPrivilege, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return AWSIAMPassRoleRelationshipInventoryResult{}, AWSKMSDecryptReachabilityInventoryResult{}, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, fmt.Errorf("privilege escalation least privilege: %w", err)
	}
	blastRadius, err := s.GetAWSBlastRadius(ctx, workspaceID, projectID, AWSBlastRadiusRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return AWSIAMPassRoleRelationshipInventoryResult{}, AWSKMSDecryptReachabilityInventoryResult{}, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, fmt.Errorf("privilege escalation blast radius: %w", err)
	}
	return passRole, kms, secrets, leastPrivilege, blastRadius, nil
}

func awsPrivilegeEscalationFindings(passRole AWSIAMPassRoleRelationshipInventoryResult, kms AWSKMSDecryptReachabilityInventoryResult, secrets AWSSecretsManagerMetadataInventoryResult, leastPrivilege AWSLeastPrivilegeResult, blastRadius AWSBlastRadiusResult, now time.Time) []AWSPrivilegeEscalationFinding {
	findings := []AWSPrivilegeEscalationFinding{}
	for _, record := range passRole.Records {
		if strings.EqualFold(record.Effect, "Allow") {
			findings = append(findings, awsPrivilegeEscalationFindingFromPassRole(record, now))
		}
	}
	for _, record := range kms.Records {
		for _, grant := range record.IdentityGrants {
			if strings.EqualFold(grant.Effect, "Allow") && awsPrivilegeEscalationGrantHasAdminSignal(grant.Actions, grant.Capabilities) {
				findings = append(findings, awsPrivilegeEscalationFindingFromKMSGrant(record, grant, now))
			}
		}
	}
	for _, record := range secrets.Records {
		for _, grant := range record.IdentityGrants {
			if strings.EqualFold(grant.Effect, "Allow") && awsPrivilegeEscalationGrantHasAdminSignal(grant.Actions, nil) {
				findings = append(findings, awsPrivilegeEscalationFindingFromSecretGrant(record, grant, now))
			}
		}
	}
	for _, recommendation := range leastPrivilege.Recommendations {
		if awsPrivilegeEscalationRecommendationQualifies(recommendation) {
			findings = append(findings, awsPrivilegeEscalationFindingFromLeastPrivilege(recommendation, now))
		}
	}
	for _, finding := range blastRadius.Findings {
		if finding.Severity == "critical" || len(finding.CrossAccountEdges) > 0 {
			findings = append(findings, awsPrivilegeEscalationFindingFromBlastRadius(finding, now))
		}
	}
	return findings
}

func awsPrivilegeEscalationFindingFromPassRole(record AWSIAMPassRoleRelationshipRecord, now time.Time) AWSPrivilegeEscalationFinding {
	score := 66
	escalationType := "passrole_service_escalation"
	if record.TargetWildcardKind != "specific" {
		score += 14
		escalationType = "passrole_wildcard_escalation"
	}
	if strings.TrimSpace(record.PassedToService) == "" {
		score += 8
		escalationType = "passrole_unscoped_trust_path"
	}
	if record.NotAction || record.NotResource {
		score += 5
	}
	score = clampBlastRadiusScore(score)
	severity := awsPrivilegeEscalationSeverity(score)
	target := firstNonEmptyAWSValue(record.ToNodeID, record.TargetResource)
	evidence := AWSPrivilegeEscalationEvidence{Source: "iam_passrole_relationship", EvidenceRef: record.EvidenceRef, Label: "IAM PassRole relationship", Confidence: record.Confidence, ObservedAt: record.CollectedAt, Relationship: record.RelationshipType}
	return awsPrivilegeEscalationFinding(AWSPrivilegeEscalationFinding{
		FindingID:          "aws-privilege-escalation:" + stableAWSBlastRadiusToken(record.SourceRoleARN, record.TargetResource, record.PolicyName, record.StatementSid),
		CalculationVersion: awsPrivilegeEscalationVersion,
		EscalationType:     escalationType,
		Severity:           severity,
		Status:             awsPrivilegeEscalationFindingStatus(score, record.Confidence),
		Score:              score,
		Confidence:         record.Confidence,
		AccountID:          record.AccountID,
		Region:             record.Region,
		IdentityNodeID:     record.FromNodeID,
		PrincipalARN:       record.SourceRoleARN,
		TargetNodeID:       target,
		TargetLabel:        firstNonEmptyAWSValue(shortAWSARN(record.TargetResource), record.TargetResource, "wildcard role target"),
		DisplayName:        firstNonEmptyAWSValue(record.SourceRoleName, shortAWSARN(record.SourceRoleARN), record.FromNodeID),
		Rationale:          fmt.Sprintf("Role can pass %s through %s; target scope=%s service=%s.", firstNonEmptyAWSValue(record.TargetResource, "a wildcard role"), firstNonEmptyAWSValue(record.PolicyName, "an IAM policy"), record.TargetWildcardKind, firstNonEmptyAWSValue(record.PassedToService, "unscoped")),
		Exploitability:     awsPrivilegeEscalationExploitability(score),
		RuntimeContext:     "static PassRole grant",
		PolicySources:      dedupeStrings([]string{record.PolicyName, record.StatementSid, record.ActionExpression}),
		ImpactedNodes:      dedupeStrings([]string{record.FromNodeID, target}),
		ImpactedPath: []AWSPrivilegeEscalationPathStep{
			{NodeID: record.FromNodeID, NodeType: "identity", Label: firstNonEmptyAWSValue(record.SourceRoleName, shortAWSARN(record.SourceRoleARN)), AccountID: record.AccountID, Region: record.Region},
			{NodeID: target, NodeType: "iam_role", Label: firstNonEmptyAWSValue(shortAWSARN(record.TargetResource), record.TargetResource), AccountID: record.AccountID, Region: record.Region},
		},
		Evidence:   []AWSPrivilegeEscalationEvidence{evidence},
		NextAction: "Constrain iam:PassRole to specific approved role ARNs and iam:PassedToService conditions before remediation automation.",
		CreatedAt:  now,
		UpdatedAt:  now,
	})
}

func awsPrivilegeEscalationFindingFromKMSGrant(record AWSKMSDecryptReachabilityRecord, grant AWSKMSIdentityGrant, now time.Time) AWSPrivilegeEscalationFinding {
	score := 74
	if grant.IsCrossAccount || record.ExposureClassification == "cross_account" {
		score += 12
	}
	if grant.IsPublic || grant.WildcardPrincipal || record.ExposureClassification == "public" {
		score += 10
	}
	if !grant.HasCondition {
		score += 4
	}
	score = clampBlastRadiusScore(score)
	principal := firstNonEmptyAWSValue(grant.PrincipalARN, "wildcard-principal")
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, "kms-decrypt-reachability:"+record.KeyARN)
	return awsPrivilegeEscalationFinding(AWSPrivilegeEscalationFinding{
		FindingID:          "aws-privilege-escalation:" + stableAWSBlastRadiusToken(principal, record.KeyARN, strings.Join(grant.Actions, ",")),
		CalculationVersion: awsPrivilegeEscalationVersion,
		EscalationType:     "kms_admin_equivalence",
		Severity:           awsPrivilegeEscalationSeverity(score),
		Status:             awsPrivilegeEscalationFindingStatus(score, record.Confidence),
		Score:              score,
		Confidence:         minFloat(record.Confidence, 0.88),
		AccountID:          record.AccountID,
		Region:             record.Region,
		IdentityNodeID:     awsIdentityNodeIDForAPI(principal),
		PrincipalARN:       principal,
		TargetNodeID:       record.FromNodeID,
		TargetLabel:        firstNonEmptyAWSValue(record.Description, record.KeyARN, record.KeyID),
		DisplayName:        shortAWSARN(principal),
		Rationale:          fmt.Sprintf("Principal has KMS key-policy or grant capabilities %s on %s; exposure=%s.", strings.Join(grant.Actions, ", "), firstNonEmptyAWSValue(record.Description, record.KeyID), record.ExposureClassification),
		Exploitability:     awsPrivilegeEscalationExploitability(score),
		RuntimeContext:     "KMS key-policy/admin equivalence",
		PolicySources:      dedupeStrings(append(grant.Actions, grant.Capabilities...)),
		ImpactedNodes:      dedupeStrings([]string{awsIdentityNodeIDForAPI(principal), record.FromNodeID}),
		ImpactedPath: []AWSPrivilegeEscalationPathStep{
			{NodeID: awsIdentityNodeIDForAPI(principal), NodeType: "identity", Label: shortAWSARN(principal), AccountID: record.AccountID, Region: record.Region},
			{NodeID: record.FromNodeID, NodeType: "kms_key", Label: firstNonEmptyAWSValue(record.Description, record.KeyARN), AccountID: record.AccountID, Region: record.Region},
		},
		Evidence:   []AWSPrivilegeEscalationEvidence{{Source: "kms_decrypt_reachability", EvidenceRef: evidenceRef, Label: "KMS key-policy/admin reachability", Confidence: record.Confidence, ObservedAt: record.CollectedAt, Relationship: "can_admin_or_decrypt_key"}},
		NextAction: "Review key policy and live grants; remove wildcard, public, or cross-account admin-equivalent permissions after owner approval.",
		CreatedAt:  now,
		UpdatedAt:  now,
	})
}

func awsPrivilegeEscalationFindingFromSecretGrant(record AWSSecretsManagerMetadataRecord, grant AWSSecretsManagerIdentityGrant, now time.Time) AWSPrivilegeEscalationFinding {
	score := 68
	if grant.IsCrossAccount || record.ExposureClassification == "cross_account" {
		score += 12
	}
	if grant.IsPublic || grant.WildcardPrincipal || record.ExposureClassification == "public" {
		score += 10
	}
	if !grant.HasCondition {
		score += 4
	}
	score = clampBlastRadiusScore(score)
	principal := firstNonEmptyAWSValue(grant.PrincipalARN, "wildcard-principal")
	return awsPrivilegeEscalationFinding(AWSPrivilegeEscalationFinding{
		FindingID:          "aws-privilege-escalation:" + stableAWSBlastRadiusToken(principal, record.SecretARN, strings.Join(grant.Actions, ",")),
		CalculationVersion: awsPrivilegeEscalationVersion,
		EscalationType:     "secrets_admin_equivalence",
		Severity:           awsPrivilegeEscalationSeverity(score),
		Status:             awsPrivilegeEscalationFindingStatus(score, record.Confidence),
		Score:              score,
		Confidence:         minFloat(record.Confidence, 0.86),
		AccountID:          record.AccountID,
		Region:             record.Region,
		IdentityNodeID:     awsIdentityNodeIDForAPI(principal),
		PrincipalARN:       principal,
		TargetNodeID:       record.FromNodeID,
		TargetLabel:        firstNonEmptyAWSValue(record.SecretName, record.SecretARN),
		DisplayName:        shortAWSARN(principal),
		Rationale:          fmt.Sprintf("Principal can administer or read sensitive secret metadata %s through actions %s; exposure=%s.", firstNonEmptyAWSValue(record.SecretName, record.SecretARN), strings.Join(grant.Actions, ", "), record.ExposureClassification),
		Exploitability:     awsPrivilegeEscalationExploitability(score),
		RuntimeContext:     "Secrets Manager policy equivalence",
		PolicySources:      dedupeStrings(grant.Actions),
		ImpactedNodes:      dedupeStrings([]string{awsIdentityNodeIDForAPI(principal), record.FromNodeID}),
		ImpactedPath: []AWSPrivilegeEscalationPathStep{
			{NodeID: awsIdentityNodeIDForAPI(principal), NodeType: "identity", Label: shortAWSARN(principal), AccountID: record.AccountID, Region: record.Region},
			{NodeID: record.FromNodeID, NodeType: "secret", Label: firstNonEmptyAWSValue(record.SecretName, record.SecretARN), AccountID: record.AccountID, Region: record.Region},
		},
		Evidence:   []AWSPrivilegeEscalationEvidence{{Source: "secrets_manager_metadata", EvidenceRef: record.EvidenceRef, Label: "Secrets Manager resource policy", Confidence: record.Confidence, ObservedAt: record.CollectedAt, Relationship: "can_admin_or_read_secret"}},
		NextAction: "Review the secret resource policy and KMS linkage; remove cross-account or wildcard grants before enabling remediation.",
		CreatedAt:  now,
		UpdatedAt:  now,
	})
}

func awsPrivilegeEscalationFindingFromLeastPrivilege(recommendation AWSLeastPrivilegeRecommendation, now time.Time) AWSPrivilegeEscalationFinding {
	score := clampBlastRadiusScore(recommendation.Score + 8)
	target := firstNonEmptyAWSValue(recommendation.ResourceNodeID, recommendation.ResourceARN, recommendation.Service)
	return awsPrivilegeEscalationFinding(AWSPrivilegeEscalationFinding{
		FindingID:          "aws-privilege-escalation:" + stableAWSBlastRadiusToken(recommendation.RecommendationID, "policy-attachment"),
		CalculationVersion: awsPrivilegeEscalationVersion,
		EscalationType:     "policy_attachment_escalation",
		Severity:           awsPrivilegeEscalationSeverity(score),
		Status:             awsPrivilegeEscalationFindingStatus(score, recommendation.Confidence),
		Score:              score,
		Confidence:         recommendation.Confidence,
		AccountID:          recommendation.AccountID,
		Region:             recommendation.Region,
		IdentityNodeID:     recommendation.IdentityNodeID,
		PrincipalARN:       recommendation.PrincipalARN,
		TargetNodeID:       target,
		TargetLabel:        firstNonEmptyAWSValue(recommendation.Service, target),
		DisplayName:        recommendation.DisplayName,
		Rationale:          fmt.Sprintf("Least-privilege engine found escalation-capable granted actions %s with decision=%s and breakage=%s.", strings.Join(recommendation.GrantedActions, ", "), recommendation.Decision, recommendation.BreakagePrediction),
		Exploitability:     awsPrivilegeEscalationExploitability(score),
		RuntimeContext:     "least-privilege policy attachment reasoning",
		PolicySources:      dedupeStrings(append(append([]string{}, recommendation.GrantedActions...), recommendation.RemoveActions...)),
		ImpactedNodes:      recommendation.ImpactedNodes,
		ImpactedPath:       []AWSPrivilegeEscalationPathStep(recommendation.ImpactedPath),
		Evidence:           []AWSPrivilegeEscalationEvidence(recommendation.Evidence),
		NextAction:         "Open an owner-approved least-privilege case to remove escalation-capable actions or split the role.",
		CreatedAt:          now,
		UpdatedAt:          now,
	})
}

func awsPrivilegeEscalationFindingFromBlastRadius(finding AWSBlastRadiusFinding, now time.Time) AWSPrivilegeEscalationFinding {
	score := clampBlastRadiusScore(finding.Score + 5)
	target := firstNonEmptyAWSValue(lastString(finding.ImpactedNodes), finding.IdentityNodeID)
	return awsPrivilegeEscalationFinding(AWSPrivilegeEscalationFinding{
		FindingID:          "aws-privilege-escalation:" + stableAWSBlastRadiusToken(finding.FindingID, "cross-account"),
		CalculationVersion: awsPrivilegeEscalationVersion,
		EscalationType:     "cross_account_escalation_path",
		Severity:           awsPrivilegeEscalationSeverity(score),
		Status:             awsPrivilegeEscalationFindingStatus(score, finding.Confidence),
		Score:              score,
		Confidence:         finding.Confidence,
		AccountID:          finding.AccountID,
		Region:             finding.Region,
		IdentityNodeID:     finding.IdentityNodeID,
		PrincipalARN:       finding.PrincipalARN,
		TargetNodeID:       target,
		TargetLabel:        target,
		DisplayName:        finding.DisplayName,
		Rationale:          fmt.Sprintf("Blast-radius engine found %s with critical or cross-account impact and %d impacted graph nodes.", finding.RiskType, len(finding.ImpactedNodes)),
		Exploitability:     awsPrivilegeEscalationExploitability(score),
		RuntimeContext:     "blast-radius cross-account/runtime path",
		PolicySources:      dedupeStrings(finding.RuntimeActions),
		ImpactedNodes:      finding.ImpactedNodes,
		ImpactedPath:       awsPrivilegeEscalationPathFromBlastRadius(finding.ImpactedPath),
		Evidence:           awsPrivilegeEscalationEvidenceFromBlastRadius(finding.Evidence),
		NextAction:         "Validate the cross-account path and remove unused or unapproved grants before approving remediation.",
		CreatedAt:          now,
		UpdatedAt:          now,
	})
}

func awsPrivilegeEscalationFinding(finding AWSPrivilegeEscalationFinding) AWSPrivilegeEscalationFinding {
	finding.RemediationCase = AWSPrivilegeEscalationRemediationCasePreview{
		CaseID:             "aws-privilege-escalation-preview:" + stableAWSBlastRadiusToken(finding.EscalationType, finding.IdentityNodeID, finding.TargetNodeID),
		Title:              fmt.Sprintf("%s privilege-escalation review", formatAWSBlastRadiusLabel(finding.EscalationType)),
		RecommendedAction:  finding.NextAction,
		ApprovalRequired:   finding.Severity == "critical" || finding.Severity == "high",
		BlockingEvidence:   awsPrivilegeEscalationEvidenceRefs(finding.Evidence),
		ImpactedNodeCount:  len(finding.ImpactedNodes),
		EstimatedRiskDrop:  minInt(finding.Score, 40),
		BreakagePrediction: "unknown",
		ReadOnlyProjection: true,
	}
	return finding
}

func filterAWSPrivilegeEscalationFindings(findings []AWSPrivilegeEscalationFinding, request AWSPrivilegeEscalationRequest) ([]AWSPrivilegeEscalationFinding, map[string]string) {
	filters := map[string]string{
		"account_id":      strings.TrimSpace(request.AccountID),
		"region":          strings.TrimSpace(request.Region),
		"identity":        strings.TrimSpace(request.Identity),
		"target":          strings.TrimSpace(request.Target),
		"escalation_type": normalizeAWSRuntimeEventFilterToken(request.EscalationType),
		"severity":        normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":          normalizeAWSRuntimeEventFilterToken(request.Status),
	}
	for key, value := range filters {
		if strings.TrimSpace(value) == "" || strings.EqualFold(value, "all") {
			delete(filters, key)
		}
	}
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSPrivilegeEscalationFinding, 0, len(findings))
	for _, finding := range findings {
		if filters["account_id"] != "" && filters["account_id"] != finding.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], finding.Region) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(finding.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(finding.Status) {
			continue
		}
		if filters["escalation_type"] != "" && filters["escalation_type"] != normalizeAWSRuntimeEventFilterToken(finding.EscalationType) {
			continue
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], finding.IdentityNodeID, finding.PrincipalARN, finding.DisplayName) {
			continue
		}
		if filters["target"] != "" && !awsRuntimeEventMatchesAny(filters["target"], finding.TargetNodeID, finding.TargetLabel, strings.Join(finding.ImpactedNodes, " ")) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, applied
}

func awsPrivilegeEscalationRelationships(findings []AWSPrivilegeEscalationFinding) []AWSPrivilegeEscalationRelationship {
	relationships := []AWSPrivilegeEscalationRelationship{}
	for _, finding := range findings {
		evidenceRef := firstLeastPrivilegeEvidenceRef(finding.Evidence)
		for i := 0; i+1 < len(finding.ImpactedPath); i++ {
			from := strings.TrimSpace(finding.ImpactedPath[i].NodeID)
			to := strings.TrimSpace(finding.ImpactedPath[i+1].NodeID)
			if from == "" || to == "" {
				continue
			}
			relationships = append(relationships, AWSPrivilegeEscalationRelationship{FindingID: finding.FindingID, Type: "privilege_escalation_path", FromNodeID: from, ToNodeID: to, EvidenceRef: evidenceRef})
		}
	}
	return relationships
}

func summarizeAWSPrivilegeEscalation(allFindings []AWSPrivilegeEscalationFinding, filtered []AWSPrivilegeEscalationFinding, relationships []AWSPrivilegeEscalationRelationship) AWSPrivilegeEscalationSummary {
	severityCounts := map[string]int{}
	statusCounts := map[string]int{}
	typeCounts := map[string]int{}
	totalConfidence := 0.0
	highest := 0
	remediationCases := map[string]struct{}{}
	for _, finding := range allFindings {
		severityCounts[finding.Severity]++
		statusCounts[finding.Status]++
		typeCounts[finding.EscalationType]++
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
	return AWSPrivilegeEscalationSummary{
		TotalFindings:           len(allFindings),
		FilteredFindings:        len(filtered),
		SeverityCounts:          severityCounts,
		StatusCounts:            statusCounts,
		EscalationTypeCounts:    typeCounts,
		CriticalCount:           severityCounts["critical"],
		HighCount:               severityCounts["high"],
		CrossAccountPathCount:   typeCounts["cross_account_escalation_path"],
		PassRolePathCount:       typeCounts["passrole_service_escalation"] + typeCounts["passrole_wildcard_escalation"] + typeCounts["passrole_unscoped_trust_path"],
		AdminEquivalentCount:    typeCounts["kms_admin_equivalence"] + typeCounts["secrets_admin_equivalence"] + typeCounts["policy_attachment_escalation"],
		RelationshipCount:       len(relationships),
		HighestScore:            highest,
		AverageConfidencePct:    averageConfidence,
		RemediationPreviewCount: len(remediationCases),
	}
}

func summarizeAWSPrivilegeEscalationStatus(sourceStatuses []string, diagnostics []AWSPrivilegeEscalationDiagnostic) (string, float64) {
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
		return awsPlatformDependencyStatusDegraded, 0.72
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsPrivilegeEscalationDiagnostics(passRole AWSIAMPassRoleRelationshipInventoryResult, kms AWSKMSDecryptReachabilityInventoryResult, secrets AWSSecretsManagerMetadataInventoryResult, leastPrivilege AWSLeastPrivilegeResult, blastRadius AWSBlastRadiusResult) []AWSPrivilegeEscalationDiagnostic {
	out := []AWSPrivilegeEscalationDiagnostic{}
	for _, diagnostic := range passRole.Diagnostics {
		out = append(out, AWSPrivilegeEscalationDiagnostic(diagnostic))
	}
	for _, diagnostic := range kms.Diagnostics {
		out = append(out, AWSPrivilegeEscalationDiagnostic(diagnostic))
	}
	for _, diagnostic := range secrets.Diagnostics {
		out = append(out, AWSPrivilegeEscalationDiagnostic(diagnostic))
	}
	for _, diagnostic := range leastPrivilege.Diagnostics {
		out = append(out, AWSPrivilegeEscalationDiagnostic(diagnostic))
	}
	for _, diagnostic := range blastRadius.Diagnostics {
		out = append(out, awsPrivilegeEscalationDiagnosticFromBlastRadius(diagnostic))
	}
	return out
}

func awsPrivilegeEscalationCoverageGaps(passRole AWSIAMPassRoleRelationshipInventoryResult, kms AWSKMSDecryptReachabilityInventoryResult, secrets AWSSecretsManagerMetadataInventoryResult, leastPrivilege AWSLeastPrivilegeResult, blastRadius AWSBlastRadiusResult) []AWSPrivilegeEscalationCoverageGap {
	out := []AWSPrivilegeEscalationCoverageGap{{
		Capability:  "privilege_escalation_persistence",
		Status:      "ready",
		Reason:      "The API emits stable finding IDs, calculation version, graph path, evidence, confidence, and remediation preview fields for downstream persistence and governance.",
		Remediation: "Persist these findings into the shared AWS findings store when the dedicated table lands.",
	}}
	for _, gap := range passRole.CoverageGaps {
		out = append(out, AWSPrivilegeEscalationCoverageGap(gap))
	}
	for _, gap := range kms.CoverageGaps {
		out = append(out, AWSPrivilegeEscalationCoverageGap(gap))
	}
	for _, gap := range secrets.CoverageGaps {
		out = append(out, AWSPrivilegeEscalationCoverageGap(gap))
	}
	for _, gap := range leastPrivilege.CoverageGaps {
		out = append(out, AWSPrivilegeEscalationCoverageGap(gap))
	}
	for _, gap := range blastRadius.CoverageGaps {
		out = append(out, awsPrivilegeEscalationCoverageGapFromBlastRadius(gap))
	}
	return out
}

func awsPrivilegeEscalationPathFromBlastRadius(path []AWSBlastRadiusPathStep) []AWSPrivilegeEscalationPathStep {
	out := make([]AWSPrivilegeEscalationPathStep, 0, len(path))
	for _, step := range path {
		out = append(out, AWSPrivilegeEscalationPathStep{
			NodeID:    step.NodeID,
			NodeType:  step.NodeType,
			Label:     step.Label,
			AccountID: step.AccountID,
			Region:    step.Region,
		})
	}
	return out
}

func awsPrivilegeEscalationEvidenceFromBlastRadius(evidence []AWSBlastRadiusEvidence) []AWSPrivilegeEscalationEvidence {
	out := make([]AWSPrivilegeEscalationEvidence, 0, len(evidence))
	for _, item := range evidence {
		out = append(out, AWSPrivilegeEscalationEvidence{
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

func awsPrivilegeEscalationDiagnosticFromBlastRadius(diagnostic AWSBlastRadiusDiagnostic) AWSPrivilegeEscalationDiagnostic {
	return AWSPrivilegeEscalationDiagnostic{
		Collector:   diagnostic.Collector,
		SourceID:    diagnostic.SourceID,
		Code:        diagnostic.Code,
		Message:     diagnostic.Message,
		Remediation: diagnostic.Remediation,
		Retryable:   diagnostic.Retryable,
	}
}

func awsPrivilegeEscalationCoverageGapFromBlastRadius(gap AWSBlastRadiusCoverageGap) AWSPrivilegeEscalationCoverageGap {
	return AWSPrivilegeEscalationCoverageGap{
		Capability:  gap.Capability,
		Status:      gap.Status,
		Reason:      gap.Reason,
		Remediation: gap.Remediation,
	}
}

func awsPrivilegeEscalationFailureReasons(passRole AWSIAMPassRoleRelationshipInventoryResult, kms AWSKMSDecryptReachabilityInventoryResult, secrets AWSSecretsManagerMetadataInventoryResult, leastPrivilege AWSLeastPrivilegeResult, blastRadius AWSBlastRadiusResult) []string {
	return emptyStrings(dedupeStrings(append(append(append(append(passRole.FailureReasons, kms.FailureReasons...), secrets.FailureReasons...), leastPrivilege.FailureReasons...), blastRadius.FailureReasons...)))
}

func awsPrivilegeEscalationRemediationHints(passRole AWSIAMPassRoleRelationshipInventoryResult, kms AWSKMSDecryptReachabilityInventoryResult, secrets AWSSecretsManagerMetadataInventoryResult, leastPrivilege AWSLeastPrivilegeResult, blastRadius AWSBlastRadiusResult) []string {
	return emptyStrings(dedupeStrings(append(append(append(append(append(passRole.RemediationHints, kms.RemediationHints...), secrets.RemediationHints...), leastPrivilege.RemediationHints...), blastRadius.RemediationHints...), "Use read-only remediation previews until a role owner approves policy or trust changes.")))
}

func awsPrivilegeEscalationCaveats() []string {
	return []string{
		"Privilege-escalation findings are inferred from metadata-only IAM, PassRole, key-policy, secret-policy, runtime, and blast-radius evidence; they do not execute AWS mutations.",
		"Unknown, degraded, and permission-denied evidence lowers envelope confidence and must not be interpreted as absence of escalation paths.",
		"Remediation previews are read-only planning records; no policy, trust, grant, or secret mutation is performed by this engine.",
	}
}

func awsPrivilegeEscalationRecommendationQualifies(recommendation AWSLeastPrivilegeRecommendation) bool {
	actions := append(append([]string{}, recommendation.GrantedActions...), recommendation.RemoveActions...)
	for _, action := range actions {
		token := strings.ToLower(strings.TrimSpace(action))
		if token == "*" || token == "iam:*" || token == "iam:passrole" || token == "iam:attachrolepolicy" || token == "sts:assumerole" {
			return recommendation.Decision == "remove" || recommendation.Decision == "review"
		}
	}
	return false
}

func awsPrivilegeEscalationGrantHasAdminSignal(actions []string, capabilities []string) bool {
	for _, value := range append(append([]string{}, actions...), capabilities...) {
		token := strings.ToLower(strings.TrimSpace(value))
		if token == "*" || strings.HasSuffix(token, ":*") || strings.Contains(token, "admin") || strings.Contains(token, "decrypt") || strings.Contains(token, "getsecretvalue") || strings.Contains(token, "putresourcepolicy") {
			return true
		}
	}
	return false
}

func awsPrivilegeEscalationSeverity(score int) string {
	switch {
	case score >= 88:
		return "critical"
	case score >= 72:
		return "high"
	case score >= 50:
		return "medium"
	default:
		return "low"
	}
}

func awsPrivilegeEscalationFindingStatus(score int, confidence float64) string {
	if score >= 82 && confidence >= 0.7 {
		return "action_required"
	}
	return "review"
}

func awsPrivilegeEscalationExploitability(score int) string {
	switch {
	case score >= 88:
		return "high"
	case score >= 72:
		return "medium"
	default:
		return "low"
	}
}

func awsPrivilegeEscalationEvidenceRefs(evidence []AWSPrivilegeEscalationEvidence) []string {
	out := []string{}
	for _, item := range evidence {
		out = append(out, item.EvidenceRef)
	}
	return emptyStrings(dedupeStrings(out))
}

func lastString(values []string) string {
	for i := len(values) - 1; i >= 0; i-- {
		if strings.TrimSpace(values[i]) != "" {
			return strings.TrimSpace(values[i])
		}
	}
	return ""
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
