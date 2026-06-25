package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsSecretKeyRotationCurrentIssue = 1533
	awsCredentialRotationVersion     = "aws-credential-rotation-planner-v1"
)

// AWSSecretKeyRotationRequest scopes the deterministic secret and key
// rotation planner to one AWS connector plus optional operator drill-down
// filters.
type AWSSecretKeyRotationRequest struct {
	ConnectorID   string `json:"connector_id,omitempty"`
	FixtureState  string `json:"fixture_state,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	Region        string `json:"region,omitempty"`
	RotationType  string `json:"rotation_type,omitempty"`
	Provider      string `json:"provider,omitempty"`
	Owner         string `json:"owner,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Status        string `json:"status,omitempty"`
	ReadyForApply string `json:"ready_for_apply,omitempty"`
	Search        string `json:"search,omitempty"`
}

type AWSSecretKeyRotationEvidence = AWSLeastPrivilegeEvidence
type AWSSecretKeyRotationPathStep = AWSLeastPrivilegePathStep
type AWSSecretKeyRotationDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSSecretKeyRotationCoverageGap = AWSLeastPrivilegeCoverageGap

type AWSSecretKeyRotationOwnerHandoff struct {
	Owner          string   `json:"owner"`
	Assigned       bool     `json:"assigned"`
	ApprovalState  string   `json:"approval_state"`
	RequiredActors []string `json:"required_actors,omitempty"`
	Instructions   []string `json:"instructions,omitempty"`
}

type AWSSecretKeyRotationTargetRef struct {
	RefType     string `json:"ref_type"`
	NodeID      string `json:"node_id,omitempty"`
	ARN         string `json:"arn,omitempty"`
	Label       string `json:"label"`
	Provider    string `json:"provider,omitempty"`
	MetadataRef string `json:"metadata_ref,omitempty"`
}

type AWSSecretKeyRotationWorkload struct {
	WorkloadID   string `json:"workload_id,omitempty"`
	WorkloadName string `json:"workload_name,omitempty"`
	WorkloadType string `json:"workload_type,omitempty"`
	ResourceARN  string `json:"resource_arn,omitempty"`
	Owner        string `json:"owner,omitempty"`
	RefreshOrder int    `json:"refresh_order"`
}

type AWSSecretKeyRotationStep struct {
	Order       int      `json:"order"`
	Phase       string   `json:"phase"`
	Action      string   `json:"action"`
	Actor       string   `json:"actor,omitempty"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
	BlocksOn    []string `json:"blocks_on,omitempty"`
}

type AWSSecretKeyRotationReadinessGate struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

type AWSSecretKeyRotationPlan struct {
	PlanID             string                              `json:"plan_id"`
	CalculationVersion string                              `json:"calculation_version"`
	RotationType       string                              `json:"rotation_type"`
	Severity           string                              `json:"severity"`
	Status             string                              `json:"status"`
	Score              int                                 `json:"score"`
	Confidence         float64                             `json:"confidence"`
	Title              string                              `json:"title"`
	Summary            string                              `json:"summary"`
	AccountID          string                              `json:"account_id"`
	Region             string                              `json:"region"`
	Provider           string                              `json:"provider,omitempty"`
	OwnerHandoff       AWSSecretKeyRotationOwnerHandoff    `json:"owner_handoff"`
	SourceFindingIDs   []string                            `json:"source_finding_ids"`
	TargetSecrets      []AWSSecretKeyRotationTargetRef     `json:"target_secrets,omitempty"`
	TargetKeys         []AWSSecretKeyRotationTargetRef     `json:"target_keys,omitempty"`
	DependentWorkloads []AWSSecretKeyRotationWorkload      `json:"dependent_workloads,omitempty"`
	RotationOrder      []AWSSecretKeyRotationStep          `json:"rotation_order"`
	DiffIntent         AWSRemediationDiffIntent            `json:"diff_intent"`
	Tradeoffs          []AWSRemediationTradeoff            `json:"tradeoffs"`
	RollbackPlan       AWSRemediationRollbackPlan          `json:"rollback_plan"`
	VerificationPlan   AWSRemediationVerificationPlan      `json:"verification_plan"`
	ReadinessGates     []AWSSecretKeyRotationReadinessGate `json:"readiness_gates"`
	ReadyForApply      bool                                `json:"ready_for_apply"`
	ReadOnlyProjection bool                                `json:"read_only_projection"`
	SourceSignals      []string                            `json:"source_signals"`
	Evidence           []AWSSecretKeyRotationEvidence      `json:"evidence"`
	EvidenceBoundary   string                              `json:"evidence_boundary"`
	ImpactedNodes      []string                            `json:"impacted_nodes"`
	ImpactedPath       []AWSSecretKeyRotationPathStep      `json:"impacted_path"`
	NextAction         string                              `json:"next_action"`
	CreatedAt          time.Time                           `json:"created_at"`
	UpdatedAt          time.Time                           `json:"updated_at"`
}

type AWSSecretKeyRotationRelationship struct {
	PlanID      string `json:"plan_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

type AWSSecretKeyRotationSummary struct {
	TotalPlans             int            `json:"total_plans"`
	FilteredPlans          int            `json:"filtered_plans"`
	RotationTypeCounts     map[string]int `json:"rotation_type_counts"`
	ProviderCounts         map[string]int `json:"provider_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	StatusCounts           map[string]int `json:"status_counts"`
	OwnerAssignedCount     int            `json:"owner_assigned_count"`
	OwnerlessCount         int            `json:"ownerless_count"`
	ReadyForApplyCount     int            `json:"ready_for_apply_count"`
	TargetSecretCount      int            `json:"target_secret_count"`
	TargetKeyCount         int            `json:"target_key_count"`
	DependentWorkloadCount int            `json:"dependent_workload_count"`
	RelationshipCount      int            `json:"relationship_count"`
	HighestScore           int            `json:"highest_score"`
	AverageConfidencePct   int            `json:"average_confidence_pct"`
}

type AWSSecretKeyRotationResult struct {
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
	Summary            AWSSecretKeyRotationSummary        `json:"summary"`
	Plans              []AWSSecretKeyRotationPlan         `json:"plans"`
	Relationships      []AWSSecretKeyRotationRelationship `json:"relationships"`
	Caveats            []string                           `json:"caveats"`
	FailureReasons     []string                           `json:"failure_reasons"`
	RemediationHints   []string                           `json:"remediation_hints"`
	EvidenceLinks      []string                           `json:"evidence_links"`
	CoverageGaps       []AWSSecretKeyRotationCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSSecretKeyRotationDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                          `json:"generated_at"`
	UpdatedAt          time.Time                          `json:"updated_at"`
}

type awsSecretKeyRotationSources struct {
	equivalence AWSSecretPermissionEquivalenceResult
	secrets     AWSSecretsManagerMetadataInventoryResult
	kms         AWSKMSDecryptReachabilityInventoryResult
	cases       AWSRemediationCaseResult
}

// GetAWSSecretKeyRotationPlans composes ranked, read-only rotation workflows
// from secret-permission equivalence, Secrets Manager metadata, KMS
// reachability, and remediation case evidence. It never reads, returns,
// rotates, or persists secret values.
func (s *Service) GetAWSSecretKeyRotationPlans(ctx context.Context, workspaceID string, projectID string, request AWSSecretKeyRotationRequest) (AWSSecretKeyRotationResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSSecretKeyRotationResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSSecretKeyRotationResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSSecretKeyRotationFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSSecretKeyRotationResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	sources, err := s.awsSecretKeyRotationSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSSecretKeyRotationResult{}, err
	}
	plans := awsSecretKeyRotationPlans(sources, now)
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Score == plans[j].Score {
			return plans[i].PlanID < plans[j].PlanID
		}
		return plans[i].Score > plans[j].Score
	})
	filtered, applied := filterAWSSecretKeyRotationPlans(plans, request)
	relationships := awsSecretKeyRotationRelationships(filtered)
	diagnostics := awsSecretKeyRotationDiagnostics(sources)
	coverageGaps := awsSecretKeyRotationCoverageGaps(sources)
	status, confidence := summarizeAWSSecretKeyRotationStatus(sources, filtered, diagnostics)

	return AWSSecretKeyRotationResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsSecretKeyRotationCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsSecretKeyRotationCurrentIssue),
		Version:            awsCredentialRotationVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsCredentialRotationVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSSecretKeyRotationPlans(plans, filtered, relationships),
		Plans:              filtered,
		Relationships:      relationships,
		Caveats:            awsSecretKeyRotationCaveats(),
		FailureReasons:     awsSecretKeyRotationFailureReasons(sources),
		RemediationHints:   awsSecretKeyRotationRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsSecretKeyRotationCurrentIssue),
			awsIssueURL(awsSecretPermissionEquivalenceCurrentIssue),
			awsIssueURL(awsSecretsManagerMetadataCurrentIssue),
			awsIssueURL(awsKMSDecryptReachabilityCurrentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			"/docs/aws-secret-key-rotation-planner",
			"/docs/aws-secret-permission-equivalence-engine",
			"/docs/aws-secrets-manager-metadata",
			"/docs/aws-kms-decrypt-reachability",
			"/docs/aws-remediation-case-model",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSSecretKeyRotationFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsSecretKeyRotationSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (awsSecretKeyRotationSources, error) {
	equivalence, err := s.GetAWSSecretPermissionEquivalence(ctx, workspaceID, projectID, AWSSecretPermissionEquivalenceRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretKeyRotationSources{}, fmt.Errorf("secret key rotation equivalence: %w", err)
	}
	secrets, err := s.GetAWSSecretsManagerMetadataInventory(ctx, workspaceID, projectID, AWSSecretsManagerMetadataInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretKeyRotationSources{}, fmt.Errorf("secret key rotation secrets metadata: %w", err)
	}
	kms, err := s.GetAWSKMSDecryptReachabilityInventory(ctx, workspaceID, projectID, AWSKMSDecryptReachabilityInventoryRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsSecretKeyRotationSources{}, fmt.Errorf("secret key rotation kms reachability: %w", err)
	}
	cases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, AWSRemediationCaseRequest{ConnectorID: connectorID, FixtureState: fixtureState, SourceType: "secret_permission_equivalence"})
	if err != nil {
		return awsSecretKeyRotationSources{}, fmt.Errorf("secret key rotation remediation cases: %w", err)
	}
	return awsSecretKeyRotationSources{equivalence: equivalence, secrets: secrets, kms: kms, cases: cases}, nil
}

func awsSecretKeyRotationPlans(sources awsSecretKeyRotationSources, now time.Time) []AWSSecretKeyRotationPlan {
	plans := []AWSSecretKeyRotationPlan{}
	secretsByARN, secretsByNode, secretsByKMS := awsSecretPermissionSecretIndexes(sources.secrets)
	kmsByARN := awsSecretKeyRotationKMSIndex(sources.kms)
	caseByFinding := awsSecretKeyRotationCaseIndex(sources.cases)
	for _, finding := range sources.equivalence.Findings {
		if p, ok := awsSecretKeyRotationPlanFromEquivalence(finding, secretsByARN, secretsByNode, kmsByARN, caseByFinding, now); ok {
			plans = append(plans, p)
		}
	}
	seen := map[string]struct{}{}
	for _, plan := range plans {
		for _, target := range plan.TargetSecrets {
			if target.ARN != "" {
				seen[strings.ToLower(target.ARN)] = struct{}{}
			}
			if target.NodeID != "" {
				seen[strings.ToLower(target.NodeID)] = struct{}{}
			}
		}
	}
	for _, secret := range sources.secrets.Records {
		if strings.TrimSpace(secret.SecretStatus) != "active" || secret.RotationEnabled {
			continue
		}
		if _, ok := seen[strings.ToLower(secret.SecretARN)]; ok {
			continue
		}
		if _, ok := seen[strings.ToLower(secret.FromNodeID)]; ok {
			continue
		}
		plans = append(plans, awsSecretKeyRotationPlanFromMetadata(secret, secretsByKMS, kmsByARN, now))
	}
	return plans
}

func awsSecretKeyRotationPlanFromEquivalence(finding AWSSecretPermissionEquivalenceFinding, secretsByARN, secretsByNode map[string]AWSSecretsManagerMetadataRecord, kmsByARN map[string]AWSKMSDecryptReachabilityRecord, caseByFinding map[string]AWSRemediationCase, now time.Time) (AWSSecretKeyRotationPlan, bool) {
	if finding.FindingID == "" {
		return AWSSecretKeyRotationPlan{}, false
	}
	secret := secretsByNode[strings.ToLower(strings.TrimSpace(finding.SecretNodeID))]
	if secret.SecretARN == "" && finding.SecretARN != "" {
		secret = secretsByARN[strings.ToLower(strings.TrimSpace(finding.SecretARN))]
	}
	rotationType := awsSecretKeyRotationType(finding, secret)
	evidenceRef := evidenceRefFromEquivalence(finding)
	owner, ownerAssigned := awsRemediationOwnerFromEquivalence(finding)
	approvalState := awsRemediationApprovalState(true, ownerAssigned, finding.Status)
	diff := AWSRemediationDiffIntent{
		Kind:               "secret_rotation",
		BeforeRef:          evidenceRef,
		AfterRef:           "rotation://" + finding.FindingID + "/new-version-reference",
		DiffSummary:        fmt.Sprintf("Rotate %s and update dependent workloads; no credential value is read or stored.", firstNonEmptyAWSValue(finding.SecretLabel, finding.SecretARN, finding.Provider)),
		ReadOnlyProjection: true,
	}
	if rotationType == "kms_related" {
		diff.Kind = "kms_grant_diff"
		diff.AfterRef = "rotation://" + finding.FindingID + "/kms-scope-and-verify"
		diff.DiffSummary = "Re-key or scope the KMS-related path before verifying the secret remains readable only by approved workloads."
	}
	targetSecrets := []AWSSecretKeyRotationTargetRef{awsSecretKeyRotationTargetFromFinding(finding, secret)}
	targetKeys := awsSecretKeyRotationTargetsForKMS(secret, kmsByARN)
	workloads := awsSecretKeyRotationWorkloads(secret, finding)
	plan := AWSSecretKeyRotationPlan{
		PlanID:             "aws-secret-key-rotation:" + stableAWSBlastRadiusToken("equivalence", finding.FindingID),
		CalculationVersion: awsCredentialRotationVersion,
		RotationType:       rotationType,
		Severity:           finding.Severity,
		Status:             finding.Status,
		Score:              finding.Score,
		Confidence:         finding.Confidence,
		Title:              awsSecretKeyRotationTitle(rotationType, firstNonEmptyAWSValue(finding.SecretLabel, secret.SecretName, finding.Provider)),
		Summary:            finding.Rationale,
		AccountID:          firstNonEmptyAWSValue(finding.AccountID, secret.AccountID),
		Region:             firstNonEmptyAWSValue(finding.Region, secret.Region),
		Provider:           finding.Provider,
		OwnerHandoff:       awsSecretKeyRotationOwnerHandoff(owner, ownerAssigned, approvalState, rotationType),
		SourceFindingIDs:   []string{finding.FindingID},
		TargetSecrets:      targetSecrets,
		TargetKeys:         targetKeys,
		DependentWorkloads: workloads,
		RotationOrder:      awsSecretKeyRotationOrder(rotationType, owner, evidenceRef, workloads),
		DiffIntent:         diff,
		Tradeoffs:          awsSecretKeyRotationTradeoffs(rotationType, finding.Severity, len(workloads)),
		RollbackPlan:       awsSecretKeyRotationRollback(rotationType, evidenceRef),
		VerificationPlan:   awsSecretKeyRotationVerification(rotationType, evidenceRef),
		SourceSignals:      dedupeStrings(append([]string{"secret_permission_equivalence"}, finding.SourceSignals...)),
		Evidence:           finding.Evidence,
		EvidenceBoundary:   awsSecretKeyRotationEvidenceBoundary(),
		ImpactedNodes:      emptyStrings(dedupeStrings(append(append([]string{finding.SecretNodeID, finding.IdentityNodeID}, finding.ImpactedNodes...), awsSecretKeyRotationTargetNodeIDs(targetKeys)...))),
		ImpactedPath:       finding.ImpactedPath,
		NextAction:         "Assign the owner handoff, execute the rotation outside Identrail, then link dry-run/apply/verify evidence to the remediation case.",
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if c, ok := caseByFinding[finding.FindingID]; ok {
		plan.SourceFindingIDs = dedupeStrings(append(plan.SourceFindingIDs, c.CaseID))
		plan.OwnerHandoff.Owner = firstNonEmptyAWSValue(plan.OwnerHandoff.Owner, c.Owner)
		plan.OwnerHandoff.Assigned = plan.OwnerHandoff.Assigned || c.OwnerAssigned
		plan.OwnerHandoff.ApprovalState = firstNonEmptyAWSValue(c.ApprovalState, plan.OwnerHandoff.ApprovalState)
		plan.ReadinessGates = append(plan.ReadinessGates, AWSSecretKeyRotationReadinessGate{Name: "remediation_case", Status: c.Lifecycle, Rationale: "Rotation plan is linked to the remediation case lifecycle."})
	}
	return finalizeAWSSecretKeyRotationPlan(plan), true
}

func awsSecretKeyRotationPlanFromMetadata(secret AWSSecretsManagerMetadataRecord, secretsByKMS map[string][]AWSSecretsManagerMetadataRecord, kmsByARN map[string]AWSKMSDecryptReachabilityRecord, now time.Time) AWSSecretKeyRotationPlan {
	evidenceRef := firstNonEmptyAWSValue(secret.EvidenceRef, "secrets-manager-metadata://"+secret.SecretARN)
	actualOwner := firstNonEmptyAWSValue(secret.Tags["owner"], secret.OwningService)
	owner := firstNonEmptyAWSValue(actualOwner, "application-owner")
	provider := firstNonEmptyAWSValue(secret.OwningService, secret.Service)
	workloads := awsSecretKeyRotationWorkloads(secret, AWSSecretPermissionEquivalenceFinding{})
	plan := AWSSecretKeyRotationPlan{
		PlanID:             "aws-secret-key-rotation:" + stableAWSBlastRadiusToken("secret-metadata", firstNonEmptyAWSValue(secret.SecretARN, secret.SecretName)),
		CalculationVersion: awsCredentialRotationVersion,
		RotationType:       "secrets_manager_secret",
		Severity:           awsSecretKeyRotationSeverityForSecret(secret),
		Status:             "review",
		Score:              awsSecretKeyRotationScoreForSecret(secret),
		Confidence:         secret.Confidence,
		Title:              awsSecretKeyRotationTitle("secrets_manager_secret", secret.SecretName),
		Summary:            "Secrets Manager metadata shows an active referenced secret without automatic rotation enabled.",
		AccountID:          secret.AccountID,
		Region:             secret.Region,
		Provider:           provider,
		OwnerHandoff:       awsSecretKeyRotationOwnerHandoff(owner, strings.TrimSpace(actualOwner) != "", "pending_owner_review", "secrets_manager_secret"),
		SourceFindingIDs:   []string{firstNonEmptyAWSValue(secret.EvidenceRef, secret.SecretARN)},
		TargetSecrets:      []AWSSecretKeyRotationTargetRef{awsSecretKeyRotationTargetFromSecret(secret)},
		TargetKeys:         awsSecretKeyRotationTargetsForKMS(secret, kmsByARN),
		DependentWorkloads: workloads,
		RotationOrder:      awsSecretKeyRotationOrder("secrets_manager_secret", owner, evidenceRef, workloads),
		DiffIntent: AWSRemediationDiffIntent{
			Kind:               "secret_rotation",
			BeforeRef:          evidenceRef,
			AfterRef:           "rotation://" + firstNonEmptyAWSValue(secret.FromNodeID, secret.SecretARN) + "/new-version-reference",
			DiffSummary:        "Enable or perform owner-approved rotation for the referenced secret and update dependent workloads.",
			ReadOnlyProjection: true,
		},
		Tradeoffs:        awsSecretKeyRotationTradeoffs("secrets_manager_secret", awsSecretKeyRotationSeverityForSecret(secret), len(workloads)),
		RollbackPlan:     awsSecretKeyRotationRollback("secrets_manager_secret", evidenceRef),
		VerificationPlan: awsSecretKeyRotationVerification("secrets_manager_secret", evidenceRef),
		SourceSignals:    []string{"secrets_manager_metadata"},
		Evidence: []AWSSecretKeyRotationEvidence{{
			Source:       "secrets_manager_metadata",
			Label:        secret.SecretName,
			EvidenceRef:  evidenceRef,
			Relationship: "secret_requires_rotation_plan",
		}},
		EvidenceBoundary: awsSecretKeyRotationEvidenceBoundary(),
		ImpactedNodes:    emptyStrings(dedupeStrings(append([]string{secret.FromNodeID}, awsSecretKeyRotationTargetNodeIDs(awsSecretKeyRotationTargetsForKMS(secret, kmsByARN))...))),
		NextAction:       "Confirm the owning service can refresh the new secret version before enabling or executing rotation.",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	kmsRef := awsSecretKeyRotationKMSRef(secret)
	if kmsRef != "" && len(secretsByKMS[kmsRef]) > 1 {
		plan.ReadinessGates = append(plan.ReadinessGates, AWSSecretKeyRotationReadinessGate{Name: "shared_kms_key", Status: "review", Rationale: "Multiple secrets use the same KMS key; stage rotation and verification per dependent secret."})
	}
	return finalizeAWSSecretKeyRotationPlan(plan)
}

func finalizeAWSSecretKeyRotationPlan(plan AWSSecretKeyRotationPlan) AWSSecretKeyRotationPlan {
	plan.SourceFindingIDs = dedupeStrings(plan.SourceFindingIDs)
	plan.SourceSignals = dedupeStrings(plan.SourceSignals)
	plan.ImpactedNodes = emptyStrings(dedupeStrings(plan.ImpactedNodes))
	plan.ReadOnlyProjection = true
	plan.DiffIntent.ReadOnlyProjection = true
	if plan.Confidence == 0 {
		plan.Confidence = 0.72
	}
	if plan.Status == "" {
		plan.Status = "review"
	}
	plan.ReadinessGates = append(plan.ReadinessGates, AWSSecretKeyRotationReadinessGate{Name: "no_secret_values", Status: "passed", Rationale: "Plan uses metadata refs only and does not contain secret values."})
	plan.ReadinessGates = append(plan.ReadinessGates, AWSSecretKeyRotationReadinessGate{Name: "owner_handoff", Status: awsSecretKeyRotationGateStatus(plan.OwnerHandoff.Assigned), Rationale: "Owner must approve rotation order and workload refresh before apply."})
	plan.ReadyForApply = plan.OwnerHandoff.Assigned && plan.Confidence >= 0.75 && plan.Severity != "critical" && plan.Status != awsPlatformDependencyStatusBlocked
	for _, gate := range plan.ReadinessGates {
		if gate.Status == "blocked" {
			plan.ReadyForApply = false
		}
	}
	return plan
}

func awsSecretKeyRotationType(finding AWSSecretPermissionEquivalenceFinding, secret AWSSecretsManagerMetadataRecord) string {
	normalized := normalizeAWSRuntimeEventFilterToken(finding.EquivalenceType)
	secretRef := strings.ToLower(strings.Join([]string{finding.SecretNodeID, finding.SecretARN, finding.SecretLabel, secret.KMSKeyARN, strings.Join(finding.SourceSignals, " ")}, " "))
	if strings.Contains(normalized, "kms") || strings.Contains(secretRef, "kms") {
		return "kms_related"
	}
	if awsSecretKeyRotationIsProviderKeyFinding(normalized, finding.Provider) {
		return "provider_key"
	}
	return "secrets_manager_secret"
}

func awsSecretKeyRotationIsProviderKeyFinding(normalizedEquivalenceType string, provider string) bool {
	if strings.Contains(normalizedEquivalenceType, "provider-key") {
		return true
	}
	return awsSecretPermissionProviderIsExternal(awsSecretPermissionCanonicalProvider(provider))
}

func awsSecretKeyRotationTargetFromFinding(finding AWSSecretPermissionEquivalenceFinding, secret AWSSecretsManagerMetadataRecord) AWSSecretKeyRotationTargetRef {
	if secret.SecretARN != "" || secret.SecretName != "" {
		return awsSecretKeyRotationTargetFromSecret(secret)
	}
	return AWSSecretKeyRotationTargetRef{
		RefType:     "secret",
		NodeID:      finding.SecretNodeID,
		ARN:         finding.SecretARN,
		Label:       firstNonEmptyAWSValue(finding.SecretLabel, shortAWSARN(finding.SecretARN), finding.Provider, "secret reference"),
		Provider:    finding.Provider,
		MetadataRef: evidenceRefFromEquivalence(finding),
	}
}

func awsSecretKeyRotationTargetFromSecret(secret AWSSecretsManagerMetadataRecord) AWSSecretKeyRotationTargetRef {
	return AWSSecretKeyRotationTargetRef{
		RefType:     "secret",
		NodeID:      secret.FromNodeID,
		ARN:         secret.SecretARN,
		Label:       firstNonEmptyAWSValue(secret.SecretName, shortAWSARN(secret.SecretARN), "secret reference"),
		Provider:    firstNonEmptyAWSValue(secret.OwningService, secret.Service),
		MetadataRef: secret.EvidenceRef,
	}
}

func awsSecretKeyRotationTargetsForKMS(secret AWSSecretsManagerMetadataRecord, kmsByARN map[string]AWSKMSDecryptReachabilityRecord) []AWSSecretKeyRotationTargetRef {
	kmsRef := awsSecretKeyRotationKMSRef(secret)
	if kmsRef == "" {
		return nil
	}
	record := kmsByARN[kmsRef]
	arn := firstNonEmptyAWSValue(secret.KMSKeyARN, record.KeyARN)
	return []AWSSecretKeyRotationTargetRef{{
		RefType:     "kms_key",
		NodeID:      record.FromNodeID,
		ARN:         arn,
		Label:       firstNonEmptyAWSValue(firstString(record.Aliases), record.KeyID, secret.KMSKeyID, shortAWSARN(arn), "kms key"),
		MetadataRef: firstNonEmptyAWSValue(record.EvidenceRef, secret.EvidenceRef),
	}}
}

func awsSecretKeyRotationWorkloads(secret AWSSecretsManagerMetadataRecord, finding AWSSecretPermissionEquivalenceFinding) []AWSSecretKeyRotationWorkload {
	out := []AWSSecretKeyRotationWorkload{}
	for idx, ref := range secret.ReferencedBy {
		out = append(out, AWSSecretKeyRotationWorkload{
			WorkloadID:   ref.WorkloadID,
			WorkloadName: ref.WorkloadName,
			WorkloadType: ref.WorkloadType,
			ResourceARN:  ref.ResourceARN,
			Owner:        firstNonEmptyAWSValue(secret.Tags["owner"], secret.OwningService),
			RefreshOrder: idx + 1,
		})
	}
	findingWorkloadID := firstNonEmptyAWSValue(finding.WorkloadID, finding.AgentID, finding.IdentityNodeID)
	if findingWorkloadID != "" && !awsSecretKeyRotationHasWorkload(out, findingWorkloadID) {
		out = append(out, AWSSecretKeyRotationWorkload{
			WorkloadID:   findingWorkloadID,
			WorkloadName: firstNonEmptyAWSValue(finding.WorkloadName, finding.AgentName),
			WorkloadType: firstNonEmptyAWSValue(awsRemediationEquivalenceIdentityType(finding), "workload"),
			Owner:        "application-owner",
			RefreshOrder: len(out) + 1,
		})
	}
	return out
}

func awsSecretKeyRotationHasWorkload(workloads []AWSSecretKeyRotationWorkload, workloadID string) bool {
	workloadID = strings.TrimSpace(workloadID)
	if workloadID == "" {
		return false
	}
	for _, workload := range workloads {
		if strings.EqualFold(strings.TrimSpace(workload.WorkloadID), workloadID) {
			return true
		}
	}
	return false
}

func awsSecretKeyRotationOrder(rotationType, owner, evidenceRef string, workloads []AWSSecretKeyRotationWorkload) []AWSSecretKeyRotationStep {
	actor := firstNonEmptyAWSValue(owner, "application-owner")
	steps := []AWSSecretKeyRotationStep{
		{Order: 1, Phase: "prepare", Action: "Confirm owner, maintenance window, dependent workloads, and fallback plan.", Actor: actor, EvidenceRef: evidenceRef},
		{Order: 2, Phase: "dry_run", Action: "Dry-run the workload refresh path using metadata refs and approved staging credentials outside Identrail.", Actor: actor, EvidenceRef: evidenceRef, BlocksOn: []string{"prepare"}},
		{Order: 3, Phase: "apply", Action: "Rotate the provider key or Secrets Manager version in the owning system; Identrail does not read or rotate the value.", Actor: actor, EvidenceRef: evidenceRef, BlocksOn: []string{"dry_run"}},
		{Order: 4, Phase: "refresh", Action: fmt.Sprintf("Refresh %d dependent workload(s) in captured order.", len(workloads)), Actor: actor, EvidenceRef: evidenceRef, BlocksOn: []string{"apply"}},
		{Order: 5, Phase: "verify", Action: "Re-run metadata and reachability checks; link verification evidence to the case.", Actor: "security", EvidenceRef: evidenceRef, BlocksOn: []string{"refresh"}},
	}
	if rotationType == "kms_related" {
		steps[2].Action = "Re-key or scope the KMS-related path in the owning AWS account; Identrail records only metadata evidence refs."
	}
	return steps
}

func awsSecretKeyRotationOwnerHandoff(owner string, assigned bool, approvalState string, rotationType string) AWSSecretKeyRotationOwnerHandoff {
	actors := []string{"application-owner", "security-reviewer"}
	if rotationType == "kms_related" {
		actors = append(actors, "kms-key-owner")
	}
	return AWSSecretKeyRotationOwnerHandoff{
		Owner:          firstNonEmptyAWSValue(owner, "unassigned"),
		Assigned:       assigned,
		ApprovalState:  approvalState,
		RequiredActors: dedupeStrings(actors),
		Instructions: []string{
			"Confirm no dependent workload keeps the previous credential after refresh.",
			"Attach dry-run, apply, verify, and rollback evidence links to the remediation case.",
		},
	}
}

func awsSecretKeyRotationTradeoffs(rotationType, severity string, workloadCount int) []AWSRemediationTradeoff {
	out := []AWSRemediationTradeoff{
		{Dimension: "credential_exposure", Direction: "improves", Description: "Rotation invalidates the previous secret/key reference once dependents are refreshed.", Severity: severity},
		{Dimension: "workload_refresh", Direction: "worsens", Description: fmt.Sprintf("%d dependent workload(s) must refresh without retaining stale credentials.", workloadCount), Severity: "medium"},
	}
	if rotationType == "kms_related" {
		out = append(out, AWSRemediationTradeoff{Dimension: "kms_reachability", Direction: "improves", Description: "KMS grants/key policy reachability is re-verified after rotation.", Severity: "medium"})
	}
	return out
}

func awsSecretKeyRotationRollback(rotationType, evidenceRef string) AWSRemediationRollbackPlan {
	if rotationType == "kms_related" {
		return AWSRemediationRollbackPlan{
			Strategy:    "restore_previous_kms_reference",
			Steps:       []string{"Restore the previous KMS key alias/grant metadata in the owning AWS account.", "Re-run KMS decrypt reachability and secret metadata inventory to verify restored access."},
			EvidenceRef: evidenceRef,
		}
	}
	return AWSRemediationRollbackPlan{
		Strategy:    "restore_previous_secret_version",
		Steps:       []string{"Restore the previous secret version/reference in the owning system if workload refresh regresses.", "Re-run secret-permission equivalence and workload health checks before retrying rotation."},
		EvidenceRef: evidenceRef,
	}
}

func awsSecretKeyRotationVerification(rotationType, evidenceRef string) AWSRemediationVerificationPlan {
	signals := []string{"secrets_manager_metadata:rotation-recorded", "secret_permission_equivalence:no-equivalent-stale-access"}
	if rotationType == "kms_related" {
		signals = append(signals, "kms_decrypt_reachability:scoped")
	}
	return AWSRemediationVerificationPlan{
		Strategy:       "rotation_re_evaluate",
		Steps:          []string{"Confirm the previous credential/key reference is no longer active for captured workloads.", "Re-run secret-permission equivalence, Secrets Manager metadata, and KMS reachability checks.", "Attach verification evidence links to the remediation case."},
		SuccessSignals: signals,
		FailureSignals: []string{"secret_permission_equivalence:stale-reference-observed", "workload_refresh:failed"},
		EvidenceRef:    evidenceRef,
	}
}

func awsSecretKeyRotationTitle(rotationType, label string) string {
	switch rotationType {
	case "provider_key":
		return fmt.Sprintf("Provider key rotation: %s", firstNonEmptyAWSValue(label, "external provider key"))
	case "kms_related":
		return fmt.Sprintf("KMS-backed secret rotation: %s", firstNonEmptyAWSValue(label, "kms-backed secret"))
	default:
		return fmt.Sprintf("Secrets Manager rotation: %s", firstNonEmptyAWSValue(label, "secret"))
	}
}

func awsSecretKeyRotationSeverityForSecret(secret AWSSecretsManagerMetadataRecord) string {
	if secret.ExposureClassification == "public" || secret.ExposureClassification == "cross_account" {
		return "high"
	}
	if len(secret.ReferencedBy) > 0 {
		return "medium"
	}
	return "low"
}

func awsSecretKeyRotationScoreForSecret(secret AWSSecretsManagerMetadataRecord) int {
	score := 60
	if len(secret.ReferencedBy) > 0 {
		score += 10
	}
	if secret.ExposureClassification == "cross_account" {
		score += 12
	}
	if secret.ExposureClassification == "public" {
		score += 18
	}
	if score > 95 {
		return 95
	}
	return score
}

func awsSecretKeyRotationKMSIndex(kms AWSKMSDecryptReachabilityInventoryResult) map[string]AWSKMSDecryptReachabilityRecord {
	out := map[string]AWSKMSDecryptReachabilityRecord{}
	for _, record := range kms.Records {
		for _, ref := range awsSecretKeyRotationKMSRecordRefs(record) {
			out[ref] = record
		}
	}
	return out
}

func awsSecretKeyRotationKMSRef(secret AWSSecretsManagerMetadataRecord) string {
	return strings.ToLower(strings.TrimSpace(firstNonEmptyAWSValue(secret.KMSKeyARN, secret.KMSKeyID)))
}

func awsSecretKeyRotationKMSRecordRefs(record AWSKMSDecryptReachabilityRecord) []string {
	refs := []string{}
	for _, ref := range append([]string{record.KeyARN, record.KeyID}, record.Aliases...) {
		ref = strings.ToLower(strings.TrimSpace(ref))
		if ref != "" {
			refs = append(refs, ref)
		}
	}
	return dedupeStrings(refs)
}

func awsSecretKeyRotationCaseIndex(cases AWSRemediationCaseResult) map[string]AWSRemediationCase {
	out := map[string]AWSRemediationCase{}
	for _, c := range cases.Cases {
		if c.SourceFindingID != "" {
			out[c.SourceFindingID] = c
		}
	}
	return out
}

func awsSecretKeyRotationTargetNodeIDs(targets []AWSSecretKeyRotationTargetRef) []string {
	out := []string{}
	for _, target := range targets {
		out = append(out, target.NodeID, target.ARN, target.Label)
	}
	return out
}

func awsSecretKeyRotationGateStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

func awsSecretKeyRotationRelationships(plans []AWSSecretKeyRotationPlan) []AWSSecretKeyRotationRelationship {
	out := []AWSSecretKeyRotationRelationship{}
	for _, plan := range plans {
		evidenceRef := firstString(awsRemediationEvidenceRefs(plan.Evidence))
		for _, target := range plan.TargetSecrets {
			if target.NodeID == "" {
				continue
			}
			out = append(out, AWSSecretKeyRotationRelationship{PlanID: plan.PlanID, Type: "rotation_targets_secret", FromNodeID: plan.PlanID, ToNodeID: target.NodeID, EvidenceRef: evidenceRef})
		}
		for _, target := range plan.TargetKeys {
			toNodeID := firstNonEmptyAWSValue(target.NodeID, target.ARN, target.Label)
			if toNodeID == "" {
				continue
			}
			out = append(out, AWSSecretKeyRotationRelationship{PlanID: plan.PlanID, Type: "rotation_targets_kms_key", FromNodeID: plan.PlanID, ToNodeID: toNodeID, EvidenceRef: evidenceRef})
		}
		for _, workload := range plan.DependentWorkloads {
			if workload.WorkloadID == "" {
				continue
			}
			out = append(out, AWSSecretKeyRotationRelationship{PlanID: plan.PlanID, Type: "rotation_refreshes_workload", FromNodeID: plan.PlanID, ToNodeID: workload.WorkloadID, EvidenceRef: evidenceRef})
		}
	}
	return out
}

func summarizeAWSSecretKeyRotationPlans(all, filtered []AWSSecretKeyRotationPlan, relationships []AWSSecretKeyRotationRelationship) AWSSecretKeyRotationSummary {
	summary := AWSSecretKeyRotationSummary{
		TotalPlans:         len(all),
		FilteredPlans:      len(filtered),
		RotationTypeCounts: map[string]int{},
		ProviderCounts:     map[string]int{},
		SeverityCounts:     map[string]int{},
		StatusCounts:       map[string]int{},
		RelationshipCount:  len(relationships),
	}
	confidenceTotal := 0.0
	for _, plan := range filtered {
		summary.RotationTypeCounts[plan.RotationType]++
		summary.ProviderCounts[plan.Provider]++
		summary.SeverityCounts[plan.Severity]++
		summary.StatusCounts[plan.Status]++
		if plan.OwnerHandoff.Assigned {
			summary.OwnerAssignedCount++
		} else {
			summary.OwnerlessCount++
		}
		if plan.ReadyForApply {
			summary.ReadyForApplyCount++
		}
		summary.TargetSecretCount += len(plan.TargetSecrets)
		summary.TargetKeyCount += len(plan.TargetKeys)
		summary.DependentWorkloadCount += len(plan.DependentWorkloads)
		if plan.Score > summary.HighestScore {
			summary.HighestScore = plan.Score
		}
		confidenceTotal += plan.Confidence
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func filterAWSSecretKeyRotationPlans(plans []AWSSecretKeyRotationPlan, request AWSSecretKeyRotationRequest) ([]AWSSecretKeyRotationPlan, map[string]string) {
	filters := map[string]string{
		"account_id":      strings.TrimSpace(request.AccountID),
		"region":          strings.TrimSpace(request.Region),
		"rotation_type":   normalizeAWSRuntimeEventFilterToken(request.RotationType),
		"provider":        normalizeAWSRuntimeEventFilterToken(request.Provider),
		"owner":           normalizeAWSRuntimeEventFilterToken(request.Owner),
		"severity":        normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":          normalizeAWSRuntimeEventFilterToken(request.Status),
		"ready_for_apply": strings.ToLower(strings.TrimSpace(request.ReadyForApply)),
		"search":          strings.TrimSpace(request.Search),
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
	filtered := make([]AWSSecretKeyRotationPlan, 0, len(plans))
	for _, plan := range plans {
		if filters["account_id"] != "" && filters["account_id"] != plan.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], plan.Region) {
			continue
		}
		if filters["rotation_type"] != "" && filters["rotation_type"] != normalizeAWSRuntimeEventFilterToken(plan.RotationType) {
			continue
		}
		if filters["provider"] != "" && filters["provider"] != normalizeAWSRuntimeEventFilterToken(plan.Provider) {
			continue
		}
		if filters["owner"] != "" && filters["owner"] != normalizeAWSRuntimeEventFilterToken(plan.OwnerHandoff.Owner) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(plan.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(plan.Status) {
			continue
		}
		if filters["ready_for_apply"] != "" {
			want := filters["ready_for_apply"]
			if (want == "true" || want == "yes") != plan.ReadyForApply {
				continue
			}
		}
		if filters["search"] != "" && !awsSecretKeyRotationSearchMatch(plan, filters["search"]) {
			continue
		}
		filtered = append(filtered, plan)
	}
	return filtered, applied
}

func awsSecretKeyRotationSearchMatch(plan AWSSecretKeyRotationPlan, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	values := []string{plan.PlanID, plan.RotationType, plan.Title, plan.Summary, plan.Provider, plan.OwnerHandoff.Owner, plan.OwnerHandoff.ApprovalState, plan.DiffIntent.Kind, plan.DiffIntent.DiffSummary, plan.RollbackPlan.Strategy, plan.VerificationPlan.Strategy, plan.NextAction}
	values = append(values, plan.SourceFindingIDs...)
	values = append(values, plan.SourceSignals...)
	values = append(values, plan.RollbackPlan.Steps...)
	values = append(values, plan.VerificationPlan.Steps...)
	values = append(values, plan.VerificationPlan.SuccessSignals...)
	values = append(values, plan.VerificationPlan.FailureSignals...)
	for _, target := range plan.TargetSecrets {
		values = append(values, target.RefType, target.NodeID, target.ARN, target.Label, target.Provider, target.MetadataRef)
	}
	for _, target := range plan.TargetKeys {
		values = append(values, target.RefType, target.NodeID, target.ARN, target.Label, target.MetadataRef)
	}
	for _, workload := range plan.DependentWorkloads {
		values = append(values, workload.WorkloadID, workload.WorkloadName, workload.WorkloadType, workload.ResourceARN, workload.Owner)
	}
	for _, step := range plan.RotationOrder {
		values = append(values, step.Phase, step.Action, step.Actor, step.EvidenceRef)
		values = append(values, step.BlocksOn...)
	}
	for _, gate := range plan.ReadinessGates {
		values = append(values, gate.Name, gate.Status, gate.Rationale)
	}
	for _, evidence := range plan.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef, evidence.Relationship)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSSecretKeyRotationStatus(sources awsSecretKeyRotationSources, filtered []AWSSecretKeyRotationPlan, diagnostics []AWSSecretKeyRotationDiagnostic) (string, float64) {
	for _, status := range []string{sources.equivalence.Status, sources.secrets.Status, sources.kms.Status, sources.cases.Status} {
		if status == awsPlatformDependencyStatusBlocked {
			return awsPlatformDependencyStatusBlocked, 0.35
		}
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	for _, status := range []string{sources.equivalence.Status, sources.secrets.Status, sources.kms.Status, sources.cases.Status} {
		if status == awsPlatformDependencyStatusDegraded {
			return awsPlatformDependencyStatusDegraded, 0.76
		}
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsSecretKeyRotationFailureReasons(sources awsSecretKeyRotationSources) []string {
	out := []string{}
	out = append(out, sources.equivalence.FailureReasons...)
	out = append(out, sources.secrets.FailureReasons...)
	out = append(out, sources.kms.FailureReasons...)
	out = append(out, sources.cases.FailureReasons...)
	return dedupeStrings(out)
}

func awsSecretKeyRotationRemediationHints(sources awsSecretKeyRotationSources) []string {
	out := []string{
		"Rotation plans are read-only workflow projections; execute rotation only in the owning AWS/provider system after approval.",
		"Attach dry-run, apply, verify, and rollback evidence links to the linked remediation case.",
	}
	out = append(out, sources.equivalence.RemediationHints...)
	out = append(out, sources.secrets.RemediationHints...)
	out = append(out, sources.kms.RemediationHints...)
	out = append(out, sources.cases.RemediationHints...)
	return dedupeStrings(out)
}

func awsSecretKeyRotationCaveats() []string {
	return []string{
		"Plans never read, expose, log, rotate, or persist secret values; only metadata refs and evidence links are returned.",
		"ready_for_apply is a deterministic planning signal, not execution approval.",
		"Provider-key, Secrets Manager, and KMS-related plans must be executed by the owning system and verified after workload refresh.",
	}
}

func awsSecretKeyRotationDiagnostics(sources awsSecretKeyRotationSources) []AWSSecretKeyRotationDiagnostic {
	out := []AWSSecretKeyRotationDiagnostic{}
	out = append(out, sources.equivalence.Diagnostics...)
	for _, d := range sources.secrets.Diagnostics {
		out = append(out, AWSSecretKeyRotationDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	for _, d := range sources.kms.Diagnostics {
		out = append(out, AWSSecretKeyRotationDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	out = append(out, sources.cases.Diagnostics...)
	return out
}

func awsSecretKeyRotationCoverageGaps(sources awsSecretKeyRotationSources) []AWSSecretKeyRotationCoverageGap {
	out := []AWSSecretKeyRotationCoverageGap{{
		Capability:  "secret_value_rotation",
		Status:      "unsupported",
		Reason:      "Identrail plans workflow order and evidence refs only; it never reads or rotates secret/key material.",
		Remediation: "Use the owning provider, Secrets Manager, or KMS workflow to perform approved rotation.",
	}}
	out = append(out, sources.equivalence.CoverageGaps...)
	for _, g := range sources.secrets.CoverageGaps {
		out = append(out, AWSSecretKeyRotationCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	for _, g := range sources.kms.CoverageGaps {
		out = append(out, AWSSecretKeyRotationCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	out = append(out, sources.cases.CoverageGaps...)
	return out
}

func awsSecretKeyRotationEvidenceBoundary() string {
	return "metadata-only: evidence refs, graph nodes, rotation workflow metadata, owner handoff, and verification links only; no secret values, rendered policy bodies, prompts, completions, payloads, or database rows."
}
