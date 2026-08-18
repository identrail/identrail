package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsSecretPermissionEquivalenceCurrentIssue = 1527
	awsSecretPermissionEquivalenceVersion      = "aws-secret-permission-equivalence-engine-v1"
)

// AWSSecretPermissionEquivalenceRequest scopes the metadata-only
// secret-to-permission calculation to one AWS connector and optional drill-down
// filters.
type AWSSecretPermissionEquivalenceRequest struct {
	ConnectorID     string `json:"connector_id,omitempty"`
	FixtureState    string `json:"fixture_state,omitempty"`
	AccountID       string `json:"account_id,omitempty"`
	Region          string `json:"region,omitempty"`
	Identity        string `json:"identity,omitempty"`
	Secret          string `json:"secret,omitempty"`
	Provider        string `json:"provider,omitempty"`
	EquivalenceType string `json:"equivalence_type,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Status          string `json:"status,omitempty"`
	Evidence        string `json:"evidence,omitempty"`
	Search          string `json:"search,omitempty"`
}

type AWSSecretPermissionEquivalenceEvidence = AWSLeastPrivilegeEvidence
type AWSSecretPermissionEquivalencePathStep = AWSLeastPrivilegePathStep
type AWSSecretPermissionEquivalenceRemediationCasePreview = AWSLeastPrivilegeRemediationCasePreview
type AWSSecretPermissionEquivalenceDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSSecretPermissionEquivalenceCoverageGap = AWSLeastPrivilegeCoverageGap

type AWSSecretPermissionEquivalenceRelationship struct {
	FindingID   string `json:"finding_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSSecretPermissionEquivalenceFinding is the operator-visible decision shape
// for identities or workloads that can read a credential-bearing secret and
// therefore inherit the secret's external or cloud permissions.
type AWSSecretPermissionEquivalenceFinding struct {
	FindingID             string                                               `json:"finding_id"`
	CalculationVersion    string                                               `json:"calculation_version"`
	EquivalenceType       string                                               `json:"equivalence_type"`
	Severity              string                                               `json:"severity"`
	Status                string                                               `json:"status"`
	Score                 int                                                  `json:"score"`
	Confidence            float64                                              `json:"confidence"`
	AccountID             string                                               `json:"account_id"`
	Region                string                                               `json:"region"`
	IdentityNodeID        string                                               `json:"identity_node_id"`
	PrincipalARN          string                                               `json:"principal_arn,omitempty"`
	WorkloadID            string                                               `json:"workload_id,omitempty"`
	WorkloadName          string                                               `json:"workload_name,omitempty"`
	AgentID               string                                               `json:"agent_id,omitempty"`
	AgentName             string                                               `json:"agent_name,omitempty"`
	SecretNodeID          string                                               `json:"secret_node_id"`
	SecretARN             string                                               `json:"secret_arn,omitempty"`
	SecretLabel           string                                               `json:"secret_label"`
	Provider              string                                               `json:"provider"`
	ProviderKeyReference  string                                               `json:"provider_key_reference,omitempty"`
	EquivalentPermissions []string                                             `json:"equivalent_permissions"`
	ImpliedActions        []string                                             `json:"implied_actions,omitempty"`
	SourceSignals         []string                                             `json:"source_signals"`
	Rationale             string                                               `json:"rationale"`
	EvidenceBoundary      string                                               `json:"evidence_boundary"`
	ImpactedNodes         []string                                             `json:"impacted_nodes"`
	ImpactedPath          []AWSSecretPermissionEquivalencePathStep             `json:"impacted_path"`
	Evidence              []AWSSecretPermissionEquivalenceEvidence             `json:"evidence"`
	NextAction            string                                               `json:"next_action"`
	RemediationCase       AWSSecretPermissionEquivalenceRemediationCasePreview `json:"remediation_case"`
	UnresolvedReference   bool                                                 `json:"unresolved_reference,omitempty"`
	CreatedAt             time.Time                                            `json:"created_at"`
	UpdatedAt             time.Time                                            `json:"updated_at"`
}

type AWSSecretPermissionEquivalenceSummary struct {
	TotalFindings            int            `json:"total_findings"`
	FilteredFindings         int            `json:"filtered_findings"`
	SeverityCounts           map[string]int `json:"severity_counts"`
	StatusCounts             map[string]int `json:"status_counts"`
	EquivalenceTypeCounts    map[string]int `json:"equivalence_type_counts"`
	ProviderCounts           map[string]int `json:"provider_counts"`
	ExternalProviderKeyCount int            `json:"external_provider_key_count"`
	AWSManagedSecretCount    int            `json:"aws_managed_secret_count"`
	RuntimeObservedCount     int            `json:"runtime_observed_count"`
	KMSBackedCount           int            `json:"kms_backed_count"`
	UnresolvedReferenceCount int            `json:"unresolved_reference_count"`
	RelationshipCount        int            `json:"relationship_count"`
	HighestScore             int            `json:"highest_score"`
	AverageConfidencePct     int            `json:"average_confidence_pct"`
	RemediationPreviewCount  int            `json:"remediation_preview_count"`
}

type AWSSecretPermissionEquivalenceResult struct {
	TenantID           string                                       `json:"tenant_id"`
	WorkspaceID        string                                       `json:"workspace_id"`
	ProjectID          string                                       `json:"project_id"`
	ConnectorID        string                                       `json:"connector_id,omitempty"`
	AccountID          string                                       `json:"account_id,omitempty"`
	Region             string                                       `json:"region,omitempty"`
	ParentIssueNumber  int                                          `json:"parent_issue_number"`
	ParentIssueRef     string                                       `json:"parent_issue_ref"`
	CurrentIssueNumber int                                          `json:"current_issue_number"`
	CurrentIssueRef    string                                       `json:"current_issue_ref"`
	Version            string                                       `json:"version"`
	Status             string                                       `json:"status"`
	FixtureState       string                                       `json:"fixture_state,omitempty"`
	Confidence         float64                                      `json:"confidence"`
	CalculationVersion string                                       `json:"calculation_version"`
	AppliedFilters     map[string]string                            `json:"applied_filters"`
	Summary            AWSSecretPermissionEquivalenceSummary        `json:"summary"`
	Findings           []AWSSecretPermissionEquivalenceFinding      `json:"findings"`
	Relationships      []AWSSecretPermissionEquivalenceRelationship `json:"relationships"`
	Caveats            []string                                     `json:"caveats"`
	FailureReasons     []string                                     `json:"failure_reasons"`
	RemediationHints   []string                                     `json:"remediation_hints"`
	EvidenceLinks      []string                                     `json:"evidence_links"`
	CoverageGaps       []AWSSecretPermissionEquivalenceCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSSecretPermissionEquivalenceDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                                    `json:"generated_at"`
	UpdatedAt          time.Time                                    `json:"updated_at"`
}

type awsSecretPermissionEquivalenceSources struct {
	credentials AWSCredentialReferencesInventoryResult
	secrets     AWSSecretsManagerMetadataInventoryResult
	kms         AWSKMSDecryptReachabilityInventoryResult
	runtime     AWSSecretsKMSRuntimeAccessResult
	agents      AWSAIAgentIdentityInventoryResult
	blast       AWSBlastRadiusResult
	escalation  AWSPrivilegeEscalationResult
}

func (s *Service) GetAWSSecretPermissionEquivalence(ctx context.Context, workspaceID string, projectID string, request AWSSecretPermissionEquivalenceRequest) (AWSSecretPermissionEquivalenceResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSSecretPermissionEquivalenceResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSSecretPermissionEquivalenceResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSSecretPermissionEquivalenceFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSSecretPermissionEquivalenceResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	runtimeFixtureState := fixtureState
	responseFixtureState := fixtureState
	liveInventoryUnavailable := false
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		// The source inventories currently have fixture builders for their
		// explicit demo states, but they do not yet have live collectors for
		// every input required by this correlation. Keep live requests from
		// promoting those deterministic records into customer findings.
		sourceFixtureState = "empty"
		// Runtime access has a live CloudTrail delivery path when the connector
		// advertises runtime_evidence. Leave that request unforced so the
		// runtime collector can choose its live inputs instead of being treated
		// like a fixture-only inventory.
		runtimeFixtureState = ""
		responseFixtureState = ""
		liveInventoryUnavailable = true
	}

	sources, err := s.awsSecretPermissionEquivalenceSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState, runtimeFixtureState)
	if err != nil {
		return AWSSecretPermissionEquivalenceResult{}, err
	}
	findings := awsSecretPermissionEquivalenceFindings(sources, now)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Score > findings[j].Score
	})
	filtered, applied := filterAWSSecretPermissionEquivalenceFindings(findings, request)
	relationships := awsSecretPermissionEquivalenceRelationships(filtered)
	diagnostics := awsSecretPermissionEquivalenceDiagnostics(sources)
	coverageGaps := awsSecretPermissionEquivalenceCoverageGaps(sources)
	failureReasons := awsSecretPermissionEquivalenceFailureReasons(sources)
	remediationHints := awsSecretPermissionEquivalenceRemediationHints(sources)
	if liveInventoryUnavailable {
		diagnostics = append(diagnostics, AWSSecretPermissionEquivalenceDiagnostic{
			Collector:   "aws_secret_permission_equivalence",
			SourceID:    connectorID,
			Code:        "live_inventory_unavailable",
			Message:     "Live credential, secret, KMS, and workload inventory is not available yet; deterministic fixture findings were suppressed.",
			Remediation: "Enable the live AWS inventory collectors before treating an empty equivalence response as proof that no risks exist.",
			Retryable:   true,
		})
		coverageGaps = append(coverageGaps, AWSSecretPermissionEquivalenceCoverageGap{
			Capability:  "secret_permission_live_inventory",
			Status:      "unavailable",
			Reason:      "The connected account does not yet have live source records for every input used by secret-to-permission equivalence.",
			Remediation: "Run or enable the live credential-reference, Secrets Manager, KMS, and workload inventory collectors for this connector.",
		})
		failureReasons = append(failureReasons, "live secret-permission inventory is unavailable")
		remediationHints = append(remediationHints, "Enable live AWS inventory collectors before interpreting an empty equivalence response as no risk.")
	}
	status, confidence := summarizeAWSSecretPermissionEquivalenceStatus(sources, filtered, diagnostics)

	return AWSSecretPermissionEquivalenceResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsSecretPermissionEquivalenceCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsSecretPermissionEquivalenceCurrentIssue),
		Version:            awsSecretPermissionEquivalenceVersion,
		Status:             status,
		FixtureState:       responseFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsSecretPermissionEquivalenceVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSSecretPermissionEquivalence(findings, filtered, relationships),
		Findings:           filtered,
		Relationships:      relationships,
		Caveats:            awsSecretPermissionEquivalenceCaveats(),
		FailureReasons:     dedupeStrings(failureReasons),
		RemediationHints:   dedupeStrings(remediationHints),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsSecretPermissionEquivalenceCurrentIssue),
			awsIssueURL(awsCredentialReferencesCurrentIssue),
			awsIssueURL(awsSecretsKMSRuntimeAccessCurrentIssue),
			awsIssueURL(awsBlastRadiusCurrentIssue),
			awsIssueURL(awsPrivilegeEscalationCurrentIssue),
			"/docs/aws-secret-permission-equivalence-engine",
			"/docs/aws-credential-references",
			"/docs/aws-secrets-kms-runtime-access",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSSecretPermissionEquivalenceFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsSecretPermissionEquivalenceSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState, runtimeFixtureState string) (awsSecretPermissionEquivalenceSources, error) {
	credentials, err := s.GetAWSCredentialReferencesInventory(ctx, workspaceID, projectID, AWSCredentialReferencesInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretPermissionEquivalenceSources{}, fmt.Errorf("secret permission equivalence credential references: %w", err)
	}
	secrets, err := s.GetAWSSecretsManagerMetadataInventory(ctx, workspaceID, projectID, AWSSecretsManagerMetadataInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretPermissionEquivalenceSources{}, fmt.Errorf("secret permission equivalence secrets metadata: %w", err)
	}
	kms, err := s.GetAWSKMSDecryptReachabilityInventory(ctx, workspaceID, projectID, AWSKMSDecryptReachabilityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretPermissionEquivalenceSources{}, fmt.Errorf("secret permission equivalence kms reachability: %w", err)
	}
	runtime, err := s.GetAWSSecretsKMSRuntimeAccess(ctx, workspaceID, projectID, AWSSecretsKMSRuntimeAccessRequest{ConnectorID: connectorID, FixtureState: runtimeFixtureState})
	if err != nil {
		return awsSecretPermissionEquivalenceSources{}, fmt.Errorf("secret permission equivalence runtime access: %w", err)
	}
	agents, err := s.GetAWSAIAgentIdentityInventory(ctx, workspaceID, projectID, AWSAIAgentIdentityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretPermissionEquivalenceSources{}, fmt.Errorf("secret permission equivalence ai agent inventory: %w", err)
	}
	blast, err := s.GetAWSBlastRadius(ctx, workspaceID, projectID, AWSBlastRadiusRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretPermissionEquivalenceSources{}, fmt.Errorf("secret permission equivalence blast radius: %w", err)
	}
	escalation, err := s.GetAWSPrivilegeEscalation(ctx, workspaceID, projectID, AWSPrivilegeEscalationRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretPermissionEquivalenceSources{}, fmt.Errorf("secret permission equivalence privilege escalation: %w", err)
	}
	return awsSecretPermissionEquivalenceSources{credentials: credentials, secrets: secrets, kms: kms, runtime: runtime, agents: agents, blast: blast, escalation: escalation}, nil
}

func awsSecretPermissionEquivalenceFindings(sources awsSecretPermissionEquivalenceSources, now time.Time) []AWSSecretPermissionEquivalenceFinding {
	findings := []AWSSecretPermissionEquivalenceFinding{}
	secretByARN, secretByNode, secretsByKMS := awsSecretPermissionSecretIndexes(sources.secrets)
	for _, record := range sources.credentials.Records {
		if finding, ok := awsSecretPermissionFindingFromCredentialReference(record, secretByARN, secretByNode, now); ok {
			findings = append(findings, finding)
		}
	}
	for _, secret := range sources.secrets.Records {
		denyGrants := awsSecretPermissionSecretDenyGrants(secret.IdentityGrants)
		for _, grant := range secret.IdentityGrants {
			if finding, ok := awsSecretPermissionFindingFromSecretGrant(secret, grant, denyGrants, now); ok {
				findings = append(findings, finding)
			}
		}
	}
	for _, key := range sources.kms.Records {
		for _, secret := range secretsByKMS[strings.ToLower(strings.TrimSpace(key.KeyARN))] {
			denyGrants := awsSecretPermissionKMSDenyGrants(key.IdentityGrants)
			for _, grant := range key.IdentityGrants {
				if finding, ok := awsSecretPermissionFindingFromKMSGrant(key, secret, grant, denyGrants, now); ok {
					findings = append(findings, finding)
				}
			}
			for _, grant := range key.Grants {
				if finding, ok := awsSecretPermissionFindingFromKMSLiveGrant(key, secret, grant, denyGrants, now); ok {
					findings = append(findings, finding)
				}
			}
		}
	}
	for _, record := range sources.runtime.Records {
		if finding, ok := awsSecretPermissionFindingFromRuntime(record, secretByARN, secretByNode, secretsByKMS, now); ok {
			findings = append(findings, finding)
		}
	}
	for _, agent := range sources.agents.Records {
		findings = append(findings, awsSecretPermissionFindingsFromAgent(agent, secretByARN, secretByNode, now)...)
	}
	for _, finding := range sources.blast.Findings {
		if derived, ok := awsSecretPermissionFindingFromBlastRadius(finding, now); ok {
			findings = append(findings, derived)
		}
	}
	for _, finding := range sources.escalation.Findings {
		if derived, ok := awsSecretPermissionFindingFromPrivilegeEscalation(finding, now); ok {
			findings = append(findings, derived)
		}
	}
	return awsSecretPermissionDedupeFindings(findings)
}

func awsSecretPermissionFindingFromCredentialReference(record AWSCredentialReferenceRecord, secretByARN map[string]AWSSecretsManagerMetadataRecord, secretByNode map[string]AWSSecretsManagerMetadataRecord, now time.Time) (AWSSecretPermissionEquivalenceFinding, bool) {
	provider := awsSecretPermissionProvider(record.Provider, record.ReferenceName, record.Reference, record.Sensitivity)
	if !awsSecretPermissionProviderIsPermissionBearing(provider, record.Sensitivity) {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	secret := awsSecretPermissionSecretForCredentialReference(record, secretByARN, secretByNode)
	secretNodeID := firstNonEmptyAWSValue(record.TargetNodeID, secret.FromNodeID, "aws:credential-reference:"+stableAWSBlastRadiusToken(record.WorkloadID, record.ReferenceName))
	secretLabel := firstNonEmptyAWSValue(secret.SecretName, record.ReferenceName, record.ReferenceKind, "credential reference")
	score := awsSecretPermissionProviderScore(provider)
	if record.Resolved {
		score += 6
	}
	if record.Unresolved {
		score -= 8
	}
	score = clampBlastRadiusScore(score)
	confidence := minFloat(firstNonZeroFloat(record.Confidence, record.ProviderConfidence, 0.72), 0.95)
	if record.Unresolved {
		confidence = minFloat(confidence, 0.78)
	}
	identity := firstNonEmptyAWSValue(record.WorkloadID, record.ResourceID)
	evidenceRef := firstNonEmptyAWSValue(record.EvidenceRef, record.ReferenceName, record.Reference)
	return awsSecretPermissionFinding(AWSSecretPermissionEquivalenceFinding{
		FindingID:             "aws-secret-permission-equivalence:" + stableAWSBlastRadiusToken("credential", record.WorkloadID, record.TargetNodeID, provider, record.ReferenceName),
		CalculationVersion:    awsSecretPermissionEquivalenceVersion,
		EquivalenceType:       "workload_provider_key_equivalence",
		Severity:              awsPrivilegeEscalationSeverity(score),
		Status:                awsSecretPermissionFindingStatus(score, confidence, record.Unresolved),
		Score:                 score,
		Confidence:            confidence,
		AccountID:             record.AccountID,
		Region:                record.Region,
		IdentityNodeID:        identity,
		WorkloadID:            record.WorkloadID,
		WorkloadName:          record.WorkloadName,
		SecretNodeID:          secretNodeID,
		SecretARN:             secret.SecretARN,
		SecretLabel:           secretLabel,
		Provider:              provider,
		ProviderKeyReference:  record.ReferenceName,
		EquivalentPermissions: awsSecretPermissionProviderPermissions(provider),
		SourceSignals:         []string{"credential_references"},
		Rationale:             fmt.Sprintf("%s references %s credential metadata for %s; the engine treats the referenced credential as permission-bearing without reading its value.", firstNonEmptyAWSValue(record.WorkloadName, record.WorkloadID), formatAWSBlastRadiusLabel(provider), secretLabel),
		EvidenceBoundary:      awsSecretPermissionEvidenceBoundary(),
		UnresolvedReference:   record.Unresolved,
		ImpactedNodes:         dedupeStrings([]string{identity, secretNodeID}),
		ImpactedPath: []AWSSecretPermissionEquivalencePathStep{
			awsLeastPrivilegePathStep(identity, record.ResourceType, firstNonEmptyAWSValue(record.WorkloadName, record.WorkloadID), record.AccountID, record.Region),
			awsLeastPrivilegePathStep(secretNodeID, "permission_bearing_secret", secretLabel, record.AccountID, record.Region),
		},
		Evidence:   []AWSSecretPermissionEquivalenceEvidence{{Source: "credential_references", EvidenceRef: evidenceRef, Label: "Credential reference metadata", Confidence: confidence, ObservedAt: record.CollectedAt, Relationship: "uses_permission_bearing_secret"}},
		NextAction: awsSecretPermissionNextAction(provider, record.Unresolved),
		CreatedAt:  now,
		UpdatedAt:  now,
	}), true
}

func awsSecretPermissionFindingFromSecretGrant(secret AWSSecretsManagerMetadataRecord, grant AWSSecretsManagerIdentityGrant, denyGrants []AWSSecretsManagerIdentityGrant, now time.Time) (AWSSecretPermissionEquivalenceFinding, bool) {
	if !strings.EqualFold(firstNonEmptyAWSValue(grant.Effect, "Allow"), "Allow") {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	if awsSecretPermissionSecretGrantDenied(grant, denyGrants) || !awsSecretPermissionSecretGrantCanRead(grant) {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	provider := awsSecretPermissionProvider("", secret.SecretName, secret.SecretARN, secret.SensitivityClassification)
	if !awsSecretPermissionProviderIsPermissionBearing(provider, secret.SensitivityClassification) && !secret.Sensitive {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	score := 68
	if grant.IsCrossAccount || secret.ExposureClassification == "cross_account" {
		score += 12
	}
	if grant.IsPublic || grant.WildcardPrincipal || secret.ExposureClassification == "public" {
		score += 14
	}
	if !grant.HasCondition {
		score += 5
	}
	score = clampBlastRadiusScore(score)
	principal := firstNonEmptyAWSValue(grant.PrincipalARN, "wildcard-principal")
	identity := awsIdentityNodeIDForAPI(principal)
	secretLabel := firstNonEmptyAWSValue(secret.SecretName, secret.SecretARN)
	return awsSecretPermissionFinding(AWSSecretPermissionEquivalenceFinding{
		FindingID:             "aws-secret-permission-equivalence:" + stableAWSBlastRadiusToken("secret-grant", principal, secret.SecretARN, strings.Join(grant.Actions, ",")),
		CalculationVersion:    awsSecretPermissionEquivalenceVersion,
		EquivalenceType:       "secret_read_policy_equivalence",
		Severity:              awsPrivilegeEscalationSeverity(score),
		Status:                awsPrivilegeEscalationFindingStatus(score, secret.Confidence),
		Score:                 score,
		Confidence:            minFloat(firstNonZeroFloat(secret.Confidence, 0.82), 0.92),
		AccountID:             secret.AccountID,
		Region:                secret.Region,
		IdentityNodeID:        identity,
		PrincipalARN:          principal,
		SecretNodeID:          secret.FromNodeID,
		SecretARN:             secret.SecretARN,
		SecretLabel:           secretLabel,
		Provider:              provider,
		EquivalentPermissions: awsSecretPermissionProviderPermissions(provider),
		ImpliedActions:        grant.Actions,
		SourceSignals:         []string{"secrets_manager_metadata"},
		Rationale:             fmt.Sprintf("%s can read permission-bearing secret metadata %s through actions %s; secret values remain outside the evidence boundary.", firstNonEmptyAWSValue(shortAWSARN(principal), principal), secretLabel, strings.Join(grant.Actions, ", ")),
		EvidenceBoundary:      awsSecretPermissionEvidenceBoundary(),
		ImpactedNodes:         dedupeStrings([]string{identity, secret.FromNodeID}),
		ImpactedPath: []AWSSecretPermissionEquivalencePathStep{
			awsLeastPrivilegePathStep(identity, "identity", firstNonEmptyAWSValue(shortAWSARN(principal), principal), secret.AccountID, secret.Region),
			awsLeastPrivilegePathStep(secret.FromNodeID, "permission_bearing_secret", secretLabel, secret.AccountID, secret.Region),
		},
		Evidence:   []AWSSecretPermissionEquivalenceEvidence{{Source: "secrets_manager_metadata", EvidenceRef: secret.EvidenceRef, Label: "Secrets Manager read grant", Confidence: secret.Confidence, ObservedAt: secret.CollectedAt, Relationship: "can_read_permission_bearing_secret"}},
		NextAction: "Validate the secret owner and restrict GetSecretValue/resource-policy access before using downstream remediation.",
		CreatedAt:  now,
		UpdatedAt:  now,
	}), true
}

func awsSecretPermissionFindingFromKMSGrant(key AWSKMSDecryptReachabilityRecord, secret AWSSecretsManagerMetadataRecord, grant AWSKMSIdentityGrant, denyGrants []AWSKMSIdentityGrant, now time.Time) (AWSSecretPermissionEquivalenceFinding, bool) {
	if !strings.EqualFold(firstNonEmptyAWSValue(grant.Effect, "Allow"), "Allow") {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	if awsSecretPermissionKMSDenyBlocksDecrypt(grant.PrincipalARN, grant.WildcardPrincipal, denyGrants) || !awsSecretPermissionKMSGrantCanDecrypt(grant.Actions, grant.Capabilities) {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	score := 64
	if grant.IsCrossAccount || key.ExposureClassification == "cross_account" {
		score += 12
	}
	if grant.IsPublic || grant.WildcardPrincipal || key.ExposureClassification == "public" {
		score += 14
	}
	score = clampBlastRadiusScore(score)
	principal := firstNonEmptyAWSValue(grant.PrincipalARN, "wildcard-principal")
	return awsSecretPermissionKMSFinding(key, secret, principal, grant.Actions, grant.Capabilities, grant.HasCondition, score, minFloat(key.Confidence, 0.86), "kms_decrypt_secret_equivalence", "kms_decrypt_reachability", now)
}

func awsSecretPermissionFindingFromKMSLiveGrant(key AWSKMSDecryptReachabilityRecord, secret AWSSecretsManagerMetadataRecord, grant AWSKMSGrant, denyGrants []AWSKMSIdentityGrant, now time.Time) (AWSSecretPermissionEquivalenceFinding, bool) {
	if strings.TrimSpace(grant.GranteePrincipal) == "" || !awsSecretPermissionKMSGrantCanDecrypt(grant.Operations, grant.Capabilities) {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	if awsSecretPermissionKMSDenyBlocksDecrypt(grant.GranteePrincipal, false, denyGrants) {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	score := 66
	if grant.IsCrossAccount || key.ExposureClassification == "cross_account" {
		score += 12
	}
	if !grant.HasConstraints {
		score += 5
	}
	return awsSecretPermissionKMSFinding(key, secret, grant.GranteePrincipal, grant.Operations, grant.Capabilities, grant.HasConstraints, clampBlastRadiusScore(score), minFloat(key.Confidence, 0.88), "kms_live_grant_secret_equivalence", "kms_live_grant", now)
}

func awsSecretPermissionKMSFinding(key AWSKMSDecryptReachabilityRecord, secret AWSSecretsManagerMetadataRecord, principal string, actions []string, capabilities []string, conditioned bool, score int, confidence float64, equivalenceType string, source string, now time.Time) (AWSSecretPermissionEquivalenceFinding, bool) {
	provider := awsSecretPermissionProvider("", secret.SecretName, secret.SecretARN, secret.SensitivityClassification)
	if !awsSecretPermissionProviderIsPermissionBearing(provider, secret.SensitivityClassification) && !secret.Sensitive {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	identity := awsIdentityNodeIDForAPI(principal)
	secretLabel := firstNonEmptyAWSValue(secret.SecretName, secret.SecretARN)
	policySources := dedupeStrings(append(append([]string{}, actions...), capabilities...))
	return awsSecretPermissionFinding(AWSSecretPermissionEquivalenceFinding{
		FindingID:             "aws-secret-permission-equivalence:" + stableAWSBlastRadiusToken(equivalenceType, principal, key.KeyARN, secret.SecretARN),
		CalculationVersion:    awsSecretPermissionEquivalenceVersion,
		EquivalenceType:       equivalenceType,
		Severity:              awsPrivilegeEscalationSeverity(score),
		Status:                awsPrivilegeEscalationFindingStatus(score, confidence),
		Score:                 score,
		Confidence:            confidence,
		AccountID:             secret.AccountID,
		Region:                secret.Region,
		IdentityNodeID:        identity,
		PrincipalARN:          principal,
		SecretNodeID:          secret.FromNodeID,
		SecretARN:             secret.SecretARN,
		SecretLabel:           secretLabel,
		Provider:              provider,
		EquivalentPermissions: awsSecretPermissionProviderPermissions(provider),
		ImpliedActions:        policySources,
		SourceSignals:         []string{source, "secrets_manager_metadata"},
		Rationale:             fmt.Sprintf("%s can use KMS permissions %s on %s, which protects permission-bearing secret %s; conditioned=%t.", firstNonEmptyAWSValue(shortAWSARN(principal), principal), strings.Join(policySources, ", "), firstNonEmptyAWSValue(key.Description, key.KeyID), secretLabel, conditioned),
		EvidenceBoundary:      awsSecretPermissionEvidenceBoundary(),
		ImpactedNodes:         dedupeStrings([]string{identity, key.FromNodeID, secret.FromNodeID}),
		ImpactedPath: []AWSSecretPermissionEquivalencePathStep{
			awsLeastPrivilegePathStep(identity, "identity", firstNonEmptyAWSValue(shortAWSARN(principal), principal), secret.AccountID, secret.Region),
			awsLeastPrivilegePathStep(key.FromNodeID, "kms_key", firstNonEmptyAWSValue(key.Description, key.KeyARN), key.AccountID, key.Region),
			awsLeastPrivilegePathStep(secret.FromNodeID, "permission_bearing_secret", secretLabel, secret.AccountID, secret.Region),
		},
		Evidence: []AWSSecretPermissionEquivalenceEvidence{
			{Source: source, EvidenceRef: key.EvidenceRef, Label: "KMS decrypt/admin reachability", Confidence: key.Confidence, ObservedAt: key.CollectedAt, Relationship: "can_decrypt_secret_key"},
			{Source: "secrets_manager_metadata", EvidenceRef: secret.EvidenceRef, Label: "Secret KMS metadata", Confidence: secret.Confidence, ObservedAt: secret.CollectedAt, Relationship: "protects_permission_bearing_secret"},
		},
		NextAction: "Validate the secret/KMS owner boundary and remove broad decrypt grants before treating this credential as controlled.",
		CreatedAt:  now,
		UpdatedAt:  now,
	}), true
}

func awsSecretPermissionFindingFromRuntime(record AWSSecretsKMSRuntimeAccessRecord, secretByARN map[string]AWSSecretsManagerMetadataRecord, secretByNode map[string]AWSSecretsManagerMetadataRecord, secretsByKMS map[string][]AWSSecretsManagerMetadataRecord, now time.Time) (AWSSecretPermissionEquivalenceFinding, bool) {
	if record.Status == "granted_unused" {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	secret, ok := awsSecretPermissionSecretForRuntime(record, secretByARN, secretByNode, secretsByKMS)
	provider := awsSecretPermissionProvider("", firstNonEmptyAWSValue(secret.SecretName, record.ResourceName), firstNonEmptyAWSValue(secret.SecretARN, record.ResourceARN), secret.SensitivityClassification)
	if !ok && record.ResourceKind == "kms_key" {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	if !awsSecretPermissionProviderIsPermissionBearing(provider, secret.SensitivityClassification) && !secret.Sensitive && record.ResourceKind != "secret" {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	score := 76
	if record.Status == "observed_without_grant" {
		score += 10
	}
	if record.CrossAccount {
		score += 8
	}
	score = clampBlastRadiusScore(score)
	secretNode := firstNonEmptyAWSValue(secret.FromNodeID, record.ResourceNodeID)
	secretARN := firstNonEmptyAWSValue(secret.SecretARN, record.ResourceARN)
	secretLabel := firstNonEmptyAWSValue(secret.SecretName, record.ResourceName, record.ResourceARN)
	principal := firstNonEmptyAWSValue(record.PrincipalARN, record.IdentityNodeID)
	identity := firstNonEmptyAWSValue(record.IdentityNodeID, awsIdentityNodeIDForAPI(principal))
	return awsSecretPermissionFinding(AWSSecretPermissionEquivalenceFinding{
		FindingID:             "aws-secret-permission-equivalence:" + stableAWSBlastRadiusToken("runtime", record.CorrelationID, secretARN),
		CalculationVersion:    awsSecretPermissionEquivalenceVersion,
		EquivalenceType:       "runtime_secret_access_equivalence",
		Severity:              awsPrivilegeEscalationSeverity(score),
		Status:                awsPrivilegeEscalationFindingStatus(score, record.Confidence),
		Score:                 score,
		Confidence:            minFloat(record.Confidence, 0.94),
		AccountID:             record.AccountID,
		Region:                record.Region,
		IdentityNodeID:        identity,
		PrincipalARN:          record.PrincipalARN,
		AgentID:               record.AgentID,
		SecretNodeID:          secretNode,
		SecretARN:             secretARN,
		SecretLabel:           secretLabel,
		Provider:              provider,
		EquivalentPermissions: awsSecretPermissionProviderPermissions(provider),
		ImpliedActions:        record.Actions,
		SourceSignals:         []string{"secrets_kms_runtime_access"},
		Rationale:             fmt.Sprintf("Runtime evidence observed %s accessing permission-bearing %s %s with status=%s.", firstNonEmptyAWSValue(shortAWSARN(principal), principal), formatAWSBlastRadiusLabel(record.ResourceKind), secretLabel, record.Status),
		EvidenceBoundary:      awsSecretPermissionEvidenceBoundary(),
		ImpactedNodes:         dedupeStrings([]string{identity, secretNode}),
		ImpactedPath: []AWSSecretPermissionEquivalencePathStep{
			awsLeastPrivilegePathStep(identity, "identity", firstNonEmptyAWSValue(shortAWSARN(principal), principal), record.AccountID, record.Region),
			awsLeastPrivilegePathStep(secretNode, "permission_bearing_secret", secretLabel, record.AccountID, record.Region),
		},
		Evidence:   []AWSSecretPermissionEquivalenceEvidence{{Source: "secrets_kms_runtime_access", EvidenceRef: record.EvidenceRef, Label: "Observed secret/KMS runtime access", Confidence: record.Confidence, ObservedAt: record.LastObservedAt, Relationship: "observed_permission_bearing_secret_access"}},
		NextAction: "Confirm this runtime access is expected, then rotate or scope the credential and its reader identity as one permission boundary.",
		CreatedAt:  now,
		UpdatedAt:  now,
	}), true
}

func awsSecretPermissionFindingsFromAgent(agent AWSAIAgentIdentityRecord, secretByARN map[string]AWSSecretsManagerMetadataRecord, secretByNode map[string]AWSSecretsManagerMetadataRecord, now time.Time) []AWSSecretPermissionEquivalenceFinding {
	findings := []AWSSecretPermissionEquivalenceFinding{}
	for _, ref := range agent.ProviderKeyReferences {
		provider := awsSecretPermissionProvider(ref.Provider, ref.ReferenceName, ref.Reference, ref.Sensitivity)
		if !awsSecretPermissionProviderIsPermissionBearing(provider, ref.Sensitivity) {
			continue
		}
		secret := awsSecretPermissionSecretForAgentReference(ref, secretByARN, secretByNode)
		secretNode := firstNonEmptyAWSValue(ref.TargetNodeID, secret.FromNodeID, "aws:credential-reference:"+stableAWSBlastRadiusToken(agent.AgentID, ref.ReferenceName))
		secretLabel := firstNonEmptyAWSValue(secret.SecretName, ref.ReferenceName, ref.ReferenceKind, "provider key reference")
		score := awsSecretPermissionProviderScore(provider) + 8
		if !ref.Resolved {
			score -= 8
		}
		score = clampBlastRadiusScore(score)
		confidence := minFloat(firstNonZeroFloat(ref.Confidence, agent.Confidence, 0.78), 0.94)
		if !ref.Resolved {
			confidence = minFloat(confidence, 0.8)
		}
		identity := firstNonEmptyAWSValue(agent.RuntimeRoleNodeID, awsIdentityNodeIDForAPI(agent.RuntimeRoleARN), agent.AgentNodeID)
		findings = append(findings, awsSecretPermissionFinding(AWSSecretPermissionEquivalenceFinding{
			FindingID:             "aws-secret-permission-equivalence:" + stableAWSBlastRadiusToken("agent-provider-key", agent.AgentID, secretNode, provider),
			CalculationVersion:    awsSecretPermissionEquivalenceVersion,
			EquivalenceType:       "agent_provider_key_equivalence",
			Severity:              awsPrivilegeEscalationSeverity(score),
			Status:                awsSecretPermissionFindingStatus(score, confidence, !ref.Resolved),
			Score:                 score,
			Confidence:            confidence,
			AccountID:             agent.AccountID,
			Region:                agent.Region,
			IdentityNodeID:        identity,
			PrincipalARN:          agent.RuntimeRoleARN,
			AgentID:               agent.AgentID,
			AgentName:             agent.AgentName,
			SecretNodeID:          secretNode,
			SecretARN:             secret.SecretARN,
			SecretLabel:           secretLabel,
			Provider:              provider,
			ProviderKeyReference:  ref.ReferenceName,
			EquivalentPermissions: awsSecretPermissionProviderPermissions(provider),
			SourceSignals:         []string{"ai_agent_identities"},
			Rationale:             fmt.Sprintf("Agent %s has a %s provider-key reference; anyone controlling the agent runtime can inherit that provider permission without Identrail reading the key value.", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID), formatAWSBlastRadiusLabel(provider)),
			EvidenceBoundary:      awsSecretPermissionEvidenceBoundary(),
			ImpactedNodes:         dedupeStrings([]string{identity, agent.AgentNodeID, secretNode}),
			ImpactedPath: []AWSSecretPermissionEquivalencePathStep{
				awsLeastPrivilegePathStep(identity, "identity", firstNonEmptyAWSValue(shortAWSARN(agent.RuntimeRoleARN), agent.RuntimeRoleName, agent.AgentName), agent.AccountID, agent.Region),
				awsLeastPrivilegePathStep(agent.AgentNodeID, "ai_agent", firstNonEmptyAWSValue(agent.AgentName, agent.AgentID), agent.AccountID, agent.Region),
				awsLeastPrivilegePathStep(secretNode, "permission_bearing_secret", secretLabel, agent.AccountID, agent.Region),
			},
			UnresolvedReference: !ref.Resolved,
			Evidence:            []AWSSecretPermissionEquivalenceEvidence{{Source: "ai_agent_identities", EvidenceRef: firstNonEmptyAWSValue(ref.EvidenceRef, agent.EvidenceRef), Label: "Agent provider-key metadata", Confidence: confidence, ObservedAt: agent.CollectedAt, Relationship: "agent_uses_permission_bearing_secret"}},
			NextAction:          awsSecretPermissionNextAction(provider, !ref.Resolved),
			CreatedAt:           now,
			UpdatedAt:           now,
		}))
	}
	return findings
}

func awsSecretPermissionFindingFromBlastRadius(finding AWSBlastRadiusFinding, now time.Time) (AWSSecretPermissionEquivalenceFinding, bool) {
	if !awsSecretPermissionBlastFindingUsesSecret(finding) {
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	score := clampBlastRadiusScore(finding.Score + 4)
	target := firstNonEmptyAWSValue(lastString(finding.SensitiveNodes), lastString(finding.ImpactedNodes), finding.IdentityNodeID)
	return awsSecretPermissionFinding(AWSSecretPermissionEquivalenceFinding{
		FindingID:             "aws-secret-permission-equivalence:" + stableAWSBlastRadiusToken("blast-radius", finding.FindingID),
		CalculationVersion:    awsSecretPermissionEquivalenceVersion,
		EquivalenceType:       "blast_radius_secret_equivalence",
		Severity:              awsPrivilegeEscalationSeverity(score),
		Status:                awsPrivilegeEscalationFindingStatus(score, finding.Confidence),
		Score:                 score,
		Confidence:            minFloat(finding.Confidence, 0.9),
		AccountID:             finding.AccountID,
		Region:                finding.Region,
		IdentityNodeID:        finding.IdentityNodeID,
		PrincipalARN:          finding.PrincipalARN,
		SecretNodeID:          target,
		SecretLabel:           target,
		Provider:              "aws_secret",
		EquivalentPermissions: awsSecretPermissionProviderPermissions("aws_secret"),
		ImpliedActions:        finding.RuntimeActions,
		SourceSignals:         []string{"blast_radius"},
		Rationale:             fmt.Sprintf("Blast-radius intelligence includes permission-bearing secret or KMS evidence on %s with score %d.", finding.DisplayName, finding.Score),
		EvidenceBoundary:      awsSecretPermissionEvidenceBoundary(),
		ImpactedNodes:         finding.ImpactedNodes,
		ImpactedPath:          []AWSSecretPermissionEquivalencePathStep(awsPrivilegeEscalationPathFromBlastRadius(finding.ImpactedPath)),
		Evidence:              []AWSSecretPermissionEquivalenceEvidence(awsPrivilegeEscalationEvidenceFromBlastRadius(finding.Evidence)),
		NextAction:            "Use the blast-radius path to decide whether the secret reader identity and credential owner need separate remediation cases.",
		CreatedAt:             now,
		UpdatedAt:             now,
	}), true
}

func awsSecretPermissionFindingFromPrivilegeEscalation(finding AWSPrivilegeEscalationFinding, now time.Time) (AWSSecretPermissionEquivalenceFinding, bool) {
	switch finding.EscalationType {
	case "secrets_admin_equivalence", "kms_admin_equivalence":
	default:
		return AWSSecretPermissionEquivalenceFinding{}, false
	}
	score := clampBlastRadiusScore(finding.Score + 3)
	target := firstNonEmptyAWSValue(finding.TargetNodeID, finding.TargetLabel)
	return awsSecretPermissionFinding(AWSSecretPermissionEquivalenceFinding{
		FindingID:             "aws-secret-permission-equivalence:" + stableAWSBlastRadiusToken("privilege-escalation", finding.FindingID),
		CalculationVersion:    awsSecretPermissionEquivalenceVersion,
		EquivalenceType:       "admin_equivalent_secret_permission",
		Severity:              awsPrivilegeEscalationSeverity(score),
		Status:                awsPrivilegeEscalationFindingStatus(score, finding.Confidence),
		Score:                 score,
		Confidence:            minFloat(finding.Confidence, 0.88),
		AccountID:             finding.AccountID,
		Region:                finding.Region,
		IdentityNodeID:        finding.IdentityNodeID,
		PrincipalARN:          finding.PrincipalARN,
		SecretNodeID:          target,
		SecretLabel:           firstNonEmptyAWSValue(finding.TargetLabel, target),
		Provider:              "aws_secret",
		EquivalentPermissions: awsSecretPermissionProviderPermissions("aws_secret"),
		ImpliedActions:        finding.PolicySources,
		SourceSignals:         []string{"privilege_escalation"},
		Rationale:             "Privilege-escalation reasoning found admin or read equivalence over a secret/KMS resource; this engine exposes the secret-as-permission decision directly.",
		EvidenceBoundary:      awsSecretPermissionEvidenceBoundary(),
		ImpactedNodes:         finding.ImpactedNodes,
		ImpactedPath:          []AWSSecretPermissionEquivalencePathStep(finding.ImpactedPath),
		Evidence:              []AWSSecretPermissionEquivalenceEvidence(finding.Evidence),
		NextAction:            "Review this alongside the privilege-escalation case and scope the secret or key grant before remediation.",
		CreatedAt:             now,
		UpdatedAt:             now,
	}), true
}

func awsSecretPermissionFinding(finding AWSSecretPermissionEquivalenceFinding) AWSSecretPermissionEquivalenceFinding {
	finding.Provider = firstNonEmptyAWSValue(finding.Provider, "generic_secret")
	finding.EquivalentPermissions = dedupeStrings(finding.EquivalentPermissions)
	finding.ImpliedActions = dedupeStrings(finding.ImpliedActions)
	finding.SourceSignals = dedupeStrings(finding.SourceSignals)
	finding.ImpactedNodes = dedupeStrings(finding.ImpactedNodes)
	evidenceRefs := awsSecretPermissionEvidenceRefs(finding.Evidence)
	finding.RemediationCase = AWSSecretPermissionEquivalenceRemediationCasePreview{
		CaseID:             "aws-secret-permission-equivalence-preview:" + stableAWSBlastRadiusToken(finding.EquivalenceType, finding.IdentityNodeID, finding.SecretNodeID),
		Title:              fmt.Sprintf("%s secret-permission review", formatAWSBlastRadiusLabel(finding.EquivalenceType)),
		RecommendedAction:  finding.NextAction,
		ApprovalRequired:   finding.Severity == "critical" || finding.Severity == "high",
		BlockingEvidence:   evidenceRefs,
		ImpactedNodeCount:  len(finding.ImpactedNodes),
		EstimatedRiskDrop:  minInt(finding.Score, 42),
		BreakagePrediction: "unknown",
		ReadOnlyProjection: true,
	}
	return finding
}

func filterAWSSecretPermissionEquivalenceFindings(findings []AWSSecretPermissionEquivalenceFinding, request AWSSecretPermissionEquivalenceRequest) ([]AWSSecretPermissionEquivalenceFinding, map[string]string) {
	filters := map[string]string{
		"account_id":       strings.TrimSpace(request.AccountID),
		"region":           strings.TrimSpace(request.Region),
		"identity":         strings.TrimSpace(request.Identity),
		"secret":           strings.TrimSpace(request.Secret),
		"provider":         awsSecretPermissionProviderFilterToken(request.Provider),
		"equivalence_type": normalizeAWSRuntimeEventFilterToken(request.EquivalenceType),
		"severity":         normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":           normalizeAWSRuntimeEventFilterToken(request.Status),
		"evidence":         strings.TrimSpace(request.Evidence),
		"search":           strings.TrimSpace(request.Search),
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
	filtered := make([]AWSSecretPermissionEquivalenceFinding, 0, len(findings))
	for _, finding := range findings {
		if filters["account_id"] != "" && filters["account_id"] != finding.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], finding.Region) {
			continue
		}
		if filters["provider"] != "" && filters["provider"] != awsSecretPermissionProviderFilterToken(finding.Provider) {
			continue
		}
		if filters["equivalence_type"] != "" && filters["equivalence_type"] != normalizeAWSRuntimeEventFilterToken(finding.EquivalenceType) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(finding.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(finding.Status) {
			continue
		}
		if filters["identity"] != "" && !strings.Contains(strings.ToLower(finding.IdentityNodeID+" "+finding.PrincipalARN+" "+finding.WorkloadID+" "+finding.WorkloadName+" "+finding.AgentID+" "+finding.AgentName), strings.ToLower(filters["identity"])) {
			continue
		}
		if filters["secret"] != "" && !strings.Contains(strings.ToLower(finding.SecretNodeID+" "+finding.SecretARN+" "+finding.SecretLabel+" "+finding.ProviderKeyReference), strings.ToLower(filters["secret"])) {
			continue
		}
		if filters["evidence"] != "" && !awsSecretPermissionEvidenceFilterMatch(finding, filters["evidence"]) {
			continue
		}
		if filters["search"] != "" && !awsSecretPermissionSearchFilterMatch(finding, filters["search"]) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, applied
}

func awsSecretPermissionEvidenceFilterMatch(finding AWSSecretPermissionEquivalenceFinding, evidenceFilter string) bool {
	switch normalizeAWSRuntimeEventFilterToken(evidenceFilter) {
	case "runtime-backed":
		return awsSecretPermissionFindingHasRuntimeEvidence(finding)
	case "inventory-backed":
		return awsSecretPermissionFindingHasInventoryEvidence(finding)
	case "unavailable":
		return len(finding.Evidence) == 0
	default:
		for _, item := range finding.Evidence {
			if awsRuntimeEventMatchesAny(evidenceFilter, item.Source, item.Label, item.EvidenceRef, item.Relationship) {
				return true
			}
		}
		return false
	}
}

func awsSecretPermissionFindingHasRuntimeEvidence(finding AWSSecretPermissionEquivalenceFinding) bool {
	for _, item := range finding.Evidence {
		if strings.EqualFold(strings.TrimSpace(item.Source), "secrets_kms_runtime_access") {
			return true
		}
	}
	return false
}

func awsSecretPermissionFindingHasInventoryEvidence(finding AWSSecretPermissionEquivalenceFinding) bool {
	for _, item := range finding.Evidence {
		if strings.EqualFold(strings.TrimSpace(item.Source), "secrets_kms_runtime_access") {
			continue
		}
		if strings.TrimSpace(item.Source) != "" {
			return true
		}
	}
	return false
}

func awsSecretPermissionSearchFilterMatch(finding AWSSecretPermissionEquivalenceFinding, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	for _, item := range awsSecretPermissionSearchValues(finding) {
		if strings.Contains(strings.ToLower(item), query) {
			return true
		}
	}
	return false
}

func awsSecretPermissionSearchValues(finding AWSSecretPermissionEquivalenceFinding) []string {
	candidates := []string{
		finding.AccountID,
		finding.Region,
		finding.IdentityNodeID,
		finding.PrincipalARN,
		finding.WorkloadID,
		finding.WorkloadName,
		finding.AgentID,
		finding.AgentName,
		finding.SecretNodeID,
		finding.SecretARN,
		finding.SecretLabel,
		finding.Provider,
		finding.ProviderKeyReference,
		finding.EquivalenceType,
		finding.Severity,
		finding.Status,
		finding.Rationale,
		finding.EvidenceBoundary,
	}
	candidates = append(candidates, finding.EquivalentPermissions...)
	candidates = append(candidates, finding.ImpliedActions...)
	candidates = append(candidates, finding.SourceSignals...)
	candidates = append(candidates, finding.ImpactedNodes...)
	for _, item := range finding.Evidence {
		candidates = append(candidates, item.Source, item.EvidenceRef, item.Label, item.Relationship)
	}
	for _, item := range finding.ImpactedPath {
		candidates = append(candidates, item.NodeID, item.NodeType, item.Label, item.AccountID, item.Region)
	}
	return dedupeStrings(candidates)
}

func awsSecretPermissionEquivalenceRelationships(findings []AWSSecretPermissionEquivalenceFinding) []AWSSecretPermissionEquivalenceRelationship {
	relationships := []AWSSecretPermissionEquivalenceRelationship{}
	for _, finding := range findings {
		if finding.IdentityNodeID == "" || finding.SecretNodeID == "" {
			continue
		}
		relationships = append(relationships, AWSSecretPermissionEquivalenceRelationship{
			FindingID:   finding.FindingID,
			Type:        "secret_permission_equivalence",
			FromNodeID:  finding.IdentityNodeID,
			ToNodeID:    finding.SecretNodeID,
			EvidenceRef: firstString(awsSecretPermissionEvidenceRefs(finding.Evidence)),
		})
	}
	return relationships
}

func summarizeAWSSecretPermissionEquivalence(allFindings []AWSSecretPermissionEquivalenceFinding, filtered []AWSSecretPermissionEquivalenceFinding, relationships []AWSSecretPermissionEquivalenceRelationship) AWSSecretPermissionEquivalenceSummary {
	summary := AWSSecretPermissionEquivalenceSummary{
		TotalFindings:         len(allFindings),
		FilteredFindings:      len(filtered),
		SeverityCounts:        map[string]int{},
		StatusCounts:          map[string]int{},
		EquivalenceTypeCounts: map[string]int{},
		ProviderCounts:        map[string]int{},
		RelationshipCount:     len(relationships),
	}
	confidenceTotal := 0.0
	for _, finding := range filtered {
		summary.SeverityCounts[finding.Severity]++
		summary.StatusCounts[finding.Status]++
		summary.EquivalenceTypeCounts[finding.EquivalenceType]++
		summary.ProviderCounts[finding.Provider]++
		if finding.Score > summary.HighestScore {
			summary.HighestScore = finding.Score
		}
		confidenceTotal += finding.Confidence
		if awsSecretPermissionProviderIsExternal(finding.Provider) {
			summary.ExternalProviderKeyCount++
		}
		if finding.Provider == "aws_secret" || finding.Provider == credentialProviderSecretsManager || finding.Provider == credentialProviderSSM {
			summary.AWSManagedSecretCount++
		}
		if awsStringSliceContains(finding.SourceSignals, "secrets_kms_runtime_access") {
			summary.RuntimeObservedCount++
		}
		if strings.Contains(finding.EquivalenceType, "kms") {
			summary.KMSBackedCount++
		}
		if finding.UnresolvedReference {
			summary.UnresolvedReferenceCount++
		}
		if finding.RemediationCase.CaseID != "" {
			summary.RemediationPreviewCount++
		}
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func summarizeAWSSecretPermissionEquivalenceStatus(sources awsSecretPermissionEquivalenceSources, filtered []AWSSecretPermissionEquivalenceFinding, diagnostics []AWSSecretPermissionEquivalenceDiagnostic) (string, float64) {
	statuses := []string{sources.credentials.Status, sources.secrets.Status, sources.kms.Status, sources.runtime.Status, sources.agents.Status, sources.blast.Status, sources.escalation.Status}
	for _, status := range statuses {
		if status == awsPlatformDependencyStatusBlocked {
			return awsPlatformDependencyStatusBlocked, 0.35
		}
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	for _, status := range statuses {
		if status == awsPlatformDependencyStatusDegraded {
			return awsPlatformDependencyStatusDegraded, 0.76
		}
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.84
	}
	return awsPlatformDependencyStatusReady, 0.91
}

func awsSecretPermissionEquivalenceFailureReasons(sources awsSecretPermissionEquivalenceSources) []string {
	out := []string{}
	for _, messages := range [][]string{
		sources.credentials.FailureReasons,
		sources.secrets.FailureReasons,
		sources.kms.FailureReasons,
		sources.runtime.FailureReasons,
		sources.agents.FailureReasons,
		sources.blast.FailureReasons,
		sources.escalation.FailureReasons,
	} {
		out = append(out, messages...)
	}
	return dedupeStrings(out)
}

func awsSecretPermissionEquivalenceRemediationHints(sources awsSecretPermissionEquivalenceSources) []string {
	out := []string{"Treat every readable provider key, AWS secret, and decryptable KMS-backed credential as permission-bearing until the owner rotates or scopes it."}
	for _, messages := range [][]string{
		sources.credentials.RemediationHints,
		sources.secrets.RemediationHints,
		sources.kms.RemediationHints,
		sources.runtime.RemediationHints,
		sources.agents.RemediationHints,
		sources.blast.RemediationHints,
		sources.escalation.RemediationHints,
	} {
		out = append(out, messages...)
	}
	return dedupeStrings(out)
}

func awsSecretPermissionEquivalenceCaveats() []string {
	return []string{
		"Secret-to-permission equivalence is inferred from metadata-only references, resource policies, KMS grants, runtime access, and graph evidence.",
		"The engine never reads, stores, logs, or displays secret values, prompts, completions, object contents, or customer payloads.",
		"Unknown, denied, unsupported, degraded, and partial evidence stays explicit instead of becoming deterministic truth.",
	}
}

func awsSecretPermissionEquivalenceDiagnostics(sources awsSecretPermissionEquivalenceSources) []AWSSecretPermissionEquivalenceDiagnostic {
	out := []AWSSecretPermissionEquivalenceDiagnostic{}
	appendDiag := func(collector, sourceID, code, message, remediation string, retryable bool) {
		if strings.TrimSpace(message) == "" && strings.TrimSpace(code) == "" {
			return
		}
		out = append(out, AWSSecretPermissionEquivalenceDiagnostic{Collector: collector, SourceID: sourceID, Code: code, Message: message, Remediation: remediation, Retryable: retryable})
	}
	for _, d := range sources.credentials.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.secrets.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.kms.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.runtime.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.agents.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.blast.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.escalation.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	return out
}

func awsSecretPermissionEquivalenceCoverageGaps(sources awsSecretPermissionEquivalenceSources) []AWSSecretPermissionEquivalenceCoverageGap {
	out := []AWSSecretPermissionEquivalenceCoverageGap{{
		Capability:  "secret_value_collection",
		Status:      "unsupported",
		Reason:      "Secret values are intentionally excluded; the engine uses metadata, policies, grants, references, runtime event IDs, and graph evidence only.",
		Remediation: "Use the owning secret manager and approved rotation workflow to inspect or rotate values outside Identrail.",
	}}
	appendGap := func(capability, status, reason, remediation string) {
		out = append(out, AWSSecretPermissionEquivalenceCoverageGap{Capability: capability, Status: status, Reason: reason, Remediation: remediation})
	}
	for _, g := range sources.credentials.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.secrets.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.kms.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.runtime.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.agents.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.blast.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.escalation.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	return out
}

func awsSecretPermissionSecretIndexes(secrets AWSSecretsManagerMetadataInventoryResult) (map[string]AWSSecretsManagerMetadataRecord, map[string]AWSSecretsManagerMetadataRecord, map[string][]AWSSecretsManagerMetadataRecord) {
	byARN := map[string]AWSSecretsManagerMetadataRecord{}
	byNode := map[string]AWSSecretsManagerMetadataRecord{}
	byKMS := map[string][]AWSSecretsManagerMetadataRecord{}
	for _, secret := range secrets.Records {
		if secret.SecretARN != "" {
			byARN[strings.ToLower(secret.SecretARN)] = secret
		}
		if secret.FromNodeID != "" {
			byNode[strings.ToLower(secret.FromNodeID)] = secret
		}
		for _, ref := range []string{secret.KMSKeyARN, secret.KMSKeyID} {
			key := strings.ToLower(strings.TrimSpace(ref))
			if key != "" {
				byKMS[key] = append(byKMS[key], secret)
			}
		}
	}
	return byARN, byNode, byKMS
}

func awsSecretPermissionSecretForCredentialReference(record AWSCredentialReferenceRecord, byARN map[string]AWSSecretsManagerMetadataRecord, byNode map[string]AWSSecretsManagerMetadataRecord) AWSSecretsManagerMetadataRecord {
	if secret, ok := byNode[strings.ToLower(strings.TrimSpace(record.TargetNodeID))]; ok {
		return secret
	}
	for arn, secret := range byARN {
		if strings.Contains(strings.ToLower(record.Reference), arn) {
			return secret
		}
	}
	return AWSSecretsManagerMetadataRecord{}
}

func awsSecretPermissionSecretForAgentReference(ref AWSAIAgentProviderKeyReference, byARN map[string]AWSSecretsManagerMetadataRecord, byNode map[string]AWSSecretsManagerMetadataRecord) AWSSecretsManagerMetadataRecord {
	if secret, ok := byNode[strings.ToLower(strings.TrimSpace(ref.TargetNodeID))]; ok {
		return secret
	}
	for arn, secret := range byARN {
		if strings.Contains(strings.ToLower(ref.Reference), arn) {
			return secret
		}
	}
	return AWSSecretsManagerMetadataRecord{}
}

func awsSecretPermissionSecretForRuntime(record AWSSecretsKMSRuntimeAccessRecord, byARN map[string]AWSSecretsManagerMetadataRecord, byNode map[string]AWSSecretsManagerMetadataRecord, byKMS map[string][]AWSSecretsManagerMetadataRecord) (AWSSecretsManagerMetadataRecord, bool) {
	if secret, ok := byNode[strings.ToLower(strings.TrimSpace(record.ResourceNodeID))]; ok {
		return secret, true
	}
	if secret, ok := byARN[strings.ToLower(strings.TrimSpace(record.ResourceARN))]; ok {
		return secret, true
	}
	if strings.EqualFold(record.ResourceKind, "kms_key") {
		secrets := byKMS[strings.ToLower(strings.TrimSpace(record.ResourceARN))]
		if len(secrets) > 0 {
			return secrets[0], true
		}
	}
	return AWSSecretsManagerMetadataRecord{}, false
}

func awsSecretPermissionSecretDenyGrants(grants []AWSSecretsManagerIdentityGrant) []AWSSecretsManagerIdentityGrant {
	out := []AWSSecretsManagerIdentityGrant{}
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			out = append(out, grant)
		}
	}
	return out
}

func awsSecretPermissionKMSDenyGrants(grants []AWSKMSIdentityGrant) []AWSKMSIdentityGrant {
	out := []AWSKMSIdentityGrant{}
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			out = append(out, grant)
		}
	}
	return out
}

// awsSecretPermissionSecretReadAPIs is the closed set of secrets-manager read
// APIs that, on their own, are sufficient to read a secret value.
var awsSecretPermissionSecretReadAPIs = []string{
	"secretsmanager:getsecretvalue",
	"secretsmanager:batchgetsecretvalue",
}

// awsSecretPermissionSecretGrantReadAPIs returns the concrete read APIs the
// grant's action list authorizes. A wildcard or secretsmanager:* grant
// expands to every read API; a narrower grant only contributes the APIs it
// actually matches. The returned set is what callers must verify is covered
// by denies before treating the grant as fully suppressed.
func awsSecretPermissionSecretGrantReadAPIs(grant AWSSecretsManagerIdentityGrant) []string {
	allowed := map[string]bool{}
	for _, raw := range grant.Actions {
		action := strings.ToLower(strings.TrimSpace(raw))
		if action == "" {
			continue
		}
		if action == "*" {
			for _, api := range awsSecretPermissionSecretReadAPIs {
				allowed[api] = true
			}
			continue
		}
		for _, api := range awsSecretPermissionSecretReadAPIs {
			if action == api || awsActionPatternMatches(action, api) {
				allowed[api] = true
			}
		}
	}
	if len(allowed) == 0 && len(grant.Actions) == 0 && grant.WildcardPrincipal {
		for _, api := range awsSecretPermissionSecretReadAPIs {
			allowed[api] = true
		}
	}
	out := make([]string, 0, len(allowed))
	for api := range allowed {
		out = append(out, api)
	}
	sort.Strings(out)
	return out
}

// awsSecretPermissionSecretGrantDenied returns true only when every read API
// the allow grant authorizes is denied for the same principal. A deny that
// only covers BatchGetSecretValue must not suppress a finding when
// GetSecretValue would still be enough to read the secret.
func awsSecretPermissionSecretGrantDenied(grant AWSSecretsManagerIdentityGrant, denyGrants []AWSSecretsManagerIdentityGrant) bool {
	readAPIs := awsSecretPermissionSecretGrantReadAPIs(grant)
	if len(readAPIs) == 0 {
		return false
	}
	for _, api := range readAPIs {
		if !awsSecretPermissionAnyDenyCoversSecretAction(grant, denyGrants, api) {
			return false
		}
	}
	return true
}

func awsSecretPermissionAnyDenyCoversSecretAction(grant AWSSecretsManagerIdentityGrant, denyGrants []AWSSecretsManagerIdentityGrant, action string) bool {
	for _, deny := range denyGrants {
		if !awsPrivilegeEscalationIdentityGrantPrincipalsMatch(grant.PrincipalARN, deny.PrincipalARN, deny.WildcardPrincipal) {
			continue
		}
		for _, raw := range deny.Actions {
			da := strings.ToLower(strings.TrimSpace(raw))
			if da == "" {
				continue
			}
			if da == "*" || da == action || awsActionPatternMatches(da, action) {
				return true
			}
		}
	}
	return false
}

// awsSecretPermissionKMSDenyBlocksDecrypt returns true only when a deny grant
// for the same principal denies a decrypt action concretely. A broad allow
// (kms:*) combined with a deny on an unrelated action (kms:Encrypt) must not
// suppress the decrypt-equivalence finding because kms:Decrypt remains
// reachable for the principal.
func awsSecretPermissionKMSDenyBlocksDecrypt(principalARN string, wildcardPrincipal bool, denyGrants []AWSKMSIdentityGrant) bool {
	for _, deny := range denyGrants {
		if !strings.EqualFold(firstNonEmptyAWSValue(deny.Effect, "Deny"), "Deny") {
			continue
		}
		if !awsPrivilegeEscalationIdentityGrantPrincipalsMatch(principalARN, deny.PrincipalARN, deny.WildcardPrincipal) {
			if !wildcardPrincipal {
				continue
			}
		}
		if awsSecretPermissionKMSGrantCanDecrypt(deny.Actions, deny.Capabilities) {
			return true
		}
	}
	return false
}

func awsSecretPermissionSecretGrantCanRead(grant AWSSecretsManagerIdentityGrant) bool {
	for _, action := range grant.Actions {
		action = strings.ToLower(strings.TrimSpace(action))
		if action == "*" || awsActionPatternMatches(action, "secretsmanager:getsecretvalue") || awsActionPatternMatches(action, "secretsmanager:*") {
			return true
		}
		if strings.Contains(action, "getsecretvalue") || strings.Contains(action, "batchgetsecretvalue") {
			return true
		}
	}
	return len(grant.Actions) == 0 && grant.WildcardPrincipal
}

func awsSecretPermissionKMSGrantCanDecrypt(actions []string, capabilities []string) bool {
	for _, action := range append(append([]string{}, actions...), capabilities...) {
		action = strings.ToLower(strings.TrimSpace(action))
		if action == "*" || action == "decrypt" || awsActionPatternMatches(action, "kms:decrypt") || strings.Contains(action, "decrypt") {
			return true
		}
	}
	return false
}

func awsSecretPermissionProvider(provider, name, ref, sensitivity string) string {
	provider = awsSecretPermissionCanonicalProvider(provider)
	if provider != "" && provider != "generic" {
		return provider
	}
	haystack := strings.ToLower(strings.Join([]string{name, ref, sensitivity}, " "))
	switch {
	case strings.Contains(haystack, "openai"):
		return credentialProviderOpenAI
	case strings.Contains(haystack, "anthropic") || strings.Contains(haystack, "claude"):
		return credentialProviderAnthropic
	case strings.Contains(haystack, "bedrock"):
		return credentialProviderBedrock
	case strings.Contains(haystack, "github") || strings.Contains(haystack, "ghp_"):
		return credentialProviderGitHub
	case strings.Contains(haystack, "slack"):
		return credentialProviderSlack
	case strings.Contains(haystack, "database") || strings.Contains(haystack, "db_") || strings.Contains(haystack, "connection"):
		return credentialProviderDatabase
	case strings.Contains(haystack, "webhook"):
		return credentialProviderWebhook
	case strings.Contains(haystack, "secretsmanager") || strings.Contains(haystack, "secret"):
		return "aws_secret"
	default:
		return credentialProviderGeneric
	}
}

func awsSecretPermissionCanonicalProvider(provider string) string {
	provider = normalizeAWSRuntimeEventFilterToken(provider)
	switch provider {
	case "secretsmanager", "secrets-manager", "aws-secretsmanager", "aws-secrets-manager":
		return credentialProviderSecretsManager
	case "ssm", "aws-ssm", "parameter-store", "parameterstore", "ssm-parameter":
		return credentialProviderSSM
	case "aws-secret":
		return "aws_secret"
	default:
		return provider
	}
}

func awsSecretPermissionProviderFilterToken(provider string) string {
	return normalizeAWSRuntimeEventFilterToken(awsSecretPermissionCanonicalProvider(provider))
}

func awsSecretPermissionProviderIsPermissionBearing(provider string, sensitivity string) bool {
	if awsSecretPermissionProviderIsExternal(provider) || provider == "aws_secret" || provider == credentialProviderSecretsManager || provider == credentialProviderSSM {
		return true
	}
	sensitivity = strings.ToLower(strings.TrimSpace(sensitivity))
	return strings.Contains(sensitivity, "api_key") || strings.Contains(sensitivity, "token") || strings.Contains(sensitivity, "credential") || strings.Contains(sensitivity, "secret")
}

func awsSecretPermissionProviderIsExternal(provider string) bool {
	switch provider {
	case credentialProviderOpenAI, credentialProviderAnthropic, credentialProviderBedrock, credentialProviderGitHub, credentialProviderSlack, credentialProviderDatabase, credentialProviderWebhook:
		return true
	default:
		return false
	}
}

func awsSecretPermissionProviderScore(provider string) int {
	switch provider {
	case credentialProviderOpenAI, credentialProviderAnthropic, credentialProviderBedrock:
		return 72
	case credentialProviderGitHub:
		return 74
	case credentialProviderDatabase:
		return 70
	case credentialProviderSlack, credentialProviderWebhook:
		return 62
	case "aws_secret", credentialProviderSecretsManager, credentialProviderSSM:
		return 66
	default:
		return 58
	}
}

func awsSecretPermissionProviderPermissions(provider string) []string {
	switch provider {
	case credentialProviderOpenAI:
		return []string{"openai:api_request", "openai:model_inference"}
	case credentialProviderAnthropic:
		return []string{"anthropic:api_request", "anthropic:model_inference"}
	case credentialProviderBedrock:
		return []string{"bedrock:InvokeModel", "bedrock:InvokeAgent"}
	case credentialProviderGitHub:
		return []string{"github:api_request", "github:repository_access"}
	case credentialProviderSlack:
		return []string{"slack:api_request", "slack:webhook_post"}
	case credentialProviderDatabase:
		return []string{"database:connect", "database:query"}
	case credentialProviderWebhook:
		return []string{"webhook:invoke"}
	case "aws_secret", credentialProviderSecretsManager:
		return []string{"secretsmanager:GetSecretValue", "credential:use_secret_material"}
	case credentialProviderSSM:
		return []string{"ssm:GetParameter", "credential:use_parameter_value"}
	default:
		return []string{"credential:use_secret_material"}
	}
}

func awsSecretPermissionFindingStatus(score int, confidence float64, unresolved bool) string {
	if unresolved || confidence < 0.7 {
		return "review"
	}
	return awsPrivilegeEscalationFindingStatus(score, confidence)
}

func awsSecretPermissionNextAction(provider string, unresolved bool) string {
	if unresolved {
		return "Resolve the credential reference to its owning secret store before treating the equivalence as deterministic."
	}
	if awsSecretPermissionProviderIsExternal(provider) {
		return "Rotate or scope the provider credential and restrict every identity that can read it as one permission boundary."
	}
	return "Validate the secret owner, reader identities, and KMS boundary before opening a remediation case."
}

func awsSecretPermissionEvidenceBoundary() string {
	return "metadata_only_no_secret_values_no_payloads"
}

func awsSecretPermissionEvidenceRefs(evidence []AWSSecretPermissionEquivalenceEvidence) []string {
	out := []string{}
	for _, item := range evidence {
		out = append(out, item.EvidenceRef)
	}
	return dedupeStrings(out)
}

func awsSecretPermissionBlastFindingUsesSecret(finding AWSBlastRadiusFinding) bool {
	haystack := strings.ToLower(strings.Join(append(append(append([]string{finding.RiskType}, finding.SensitiveNodes...), finding.RuntimeActions...), finding.AgentToolPaths...), " "))
	return strings.Contains(haystack, "secret") || strings.Contains(haystack, "kms") || strings.Contains(haystack, "credential")
}

func awsSecretPermissionDedupeFindings(findings []AWSSecretPermissionEquivalenceFinding) []AWSSecretPermissionEquivalenceFinding {
	out := []AWSSecretPermissionEquivalenceFinding{}
	seen := map[string]int{}
	for _, finding := range findings {
		key := strings.ToLower(strings.Join([]string{finding.IdentityNodeID, finding.SecretNodeID, finding.Provider, finding.EquivalenceType}, "|"))
		if idx, ok := seen[key]; ok {
			if finding.Score > out[idx].Score || (finding.Score == out[idx].Score && len(finding.SourceSignals) > len(out[idx].SourceSignals)) {
				merged := finding
				merged.SourceSignals = dedupeStrings(append(merged.SourceSignals, out[idx].SourceSignals...))
				merged.Evidence = append(merged.Evidence, out[idx].Evidence...)
				merged.ImpactedNodes = dedupeStrings(append(merged.ImpactedNodes, out[idx].ImpactedNodes...))
				merged.UnresolvedReference = merged.UnresolvedReference || out[idx].UnresolvedReference
				out[idx] = awsSecretPermissionFinding(merged)
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, finding)
	}
	return out
}
