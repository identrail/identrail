package api

import (
	"strings"
	"testing"
	"time"
)

func newPrivilegeEscalationService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSPrivilegeEscalationBuildsFindingContract(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	svc, ws := newPrivilegeEscalationService(t, "project-privilege-escalation", now)

	result, err := svc.GetAWSPrivilegeEscalation(defaultScopeContext(), ws, "project-privilege-escalation", AWSPrivilegeEscalationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get privilege escalation: %v", err)
	}
	if result.CurrentIssueRef != "#1525" || result.Version != awsPrivilegeEscalationVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready status, got %q with diagnostics=%+v", result.Status, result.Diagnostics)
	}
	if len(result.Findings) == 0 || result.Summary.TotalFindings != len(result.Findings) {
		t.Fatalf("expected findings summary to match payload: %+v", result.Summary)
	}
	if result.Summary.PassRolePathCount == 0 || result.Summary.AdminEquivalentCount == 0 {
		t.Fatalf("expected passrole and admin-equivalent paths: %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected graph relationships: %+v", result.Relationships)
	}
	if result.Summary.RemediationPreviewCount == 0 || len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected remediation previews, caveats, and coverage gaps: summary=%+v caveats=%v gaps=%v", result.Summary, result.Caveats, result.CoverageGaps)
	}
	for i := 1; i < len(result.Findings); i++ {
		if result.Findings[i-1].Score < result.Findings[i].Score {
			t.Fatalf("findings are not ranked by descending score: %+v", result.Findings)
		}
	}
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsPrivilegeEscalationVersion {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.EscalationType == "" || finding.Severity == "" || finding.Status == "" || finding.Rationale == "" {
			t.Fatalf("finding missing classification fields: %+v", finding)
		}
		if finding.Score <= 0 || finding.Confidence <= 0 {
			t.Fatalf("finding missing score/confidence: %+v", finding)
		}
		if finding.IdentityNodeID == "" || finding.TargetLabel == "" || len(finding.ImpactedPath) < 2 || len(finding.Evidence) == 0 {
			t.Fatalf("finding missing path/evidence fields: %+v", finding)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
	}
}

func TestGetAWSPrivilegeEscalationFiltersByTypeSeverityIdentityAndTarget(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 5, 0, 0, time.UTC)
	svc, ws := newPrivilegeEscalationService(t, "project-privilege-escalation-filters", now)

	passRole, err := svc.GetAWSPrivilegeEscalation(defaultScopeContext(), ws, "project-privilege-escalation-filters", AWSPrivilegeEscalationRequest{
		ConnectorID:    "aws-prod",
		FixtureState:   "success",
		EscalationType: "passrole_unscoped_trust_path",
	})
	if err != nil {
		t.Fatalf("passrole filter: %v", err)
	}
	if len(passRole.Findings) == 0 {
		t.Fatalf("expected wildcard PassRole findings")
	}
	for _, finding := range passRole.Findings {
		if finding.EscalationType != "passrole_unscoped_trust_path" {
			t.Fatalf("escalation_type filter leaked: %+v", finding)
		}
	}
	if passRole.AppliedFilters["escalation_type"] != "passrole-unscoped-trust-path" {
		t.Fatalf("expected normalized escalation_type filter, got %+v", passRole.AppliedFilters)
	}

	critical, err := svc.GetAWSPrivilegeEscalation(defaultScopeContext(), ws, "project-privilege-escalation-filters", AWSPrivilegeEscalationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "critical",
	})
	if err != nil {
		t.Fatalf("critical filter: %v", err)
	}
	if len(critical.Findings) == 0 {
		t.Fatalf("expected critical privilege escalation findings")
	}
	for _, finding := range critical.Findings {
		if finding.Severity != "critical" {
			t.Fatalf("severity filter leaked: %+v", finding)
		}
	}

	identity, err := svc.GetAWSPrivilegeEscalation(defaultScopeContext(), ws, "project-privilege-escalation-filters", AWSPrivilegeEscalationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     "security-admin",
		Target:       "*",
	})
	if err != nil {
		t.Fatalf("identity/target filter: %v", err)
	}
	if len(identity.Findings) == 0 {
		t.Fatalf("expected security-admin wildcard target finding")
	}
	for _, finding := range identity.Findings {
		if !strings.Contains(finding.DisplayName, "security-admin") && !strings.Contains(finding.PrincipalARN, "security-admin") {
			t.Fatalf("identity filter leaked: %+v", finding)
		}
		if !strings.Contains(strings.Join(finding.ImpactedNodes, " "), "*") && !strings.Contains(finding.TargetLabel, "*") {
			t.Fatalf("target filter leaked: %+v", finding)
		}
	}
}

func TestGetAWSPrivilegeEscalationFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 10, 0, 0, time.UTC)
	svc, ws := newPrivilegeEscalationService(t, "project-privilege-escalation-states", now)

	denied, err := svc.GetAWSPrivilegeEscalation(defaultScopeContext(), ws, "project-privilege-escalation-states", AWSPrivilegeEscalationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || denied.Confidence != 0 {
		t.Fatalf("expected blocked permission-denied state with zero confidence: %+v", denied)
	}
	if len(denied.Findings) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must suppress findings and surface diagnostics: %+v", denied)
	}

	degraded, err := svc.GetAWSPrivilegeEscalation(defaultScopeContext(), ws, "project-privilege-escalation-states", AWSPrivilegeEscalationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("degraded: %v", err)
	}
	if degraded.Status != "degraded" || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded status with diagnostics: %+v", degraded)
	}
	if len(degraded.Findings) == 0 {
		t.Fatalf("degraded sources should keep partial evidence visible: %+v", degraded)
	}

	empty, err := svc.GetAWSPrivilegeEscalation(defaultScopeContext(), ws, "project-privilege-escalation-states", AWSPrivilegeEscalationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Findings) != 0 || empty.Summary.TotalFindings != 0 || len(empty.FailureReasons) == 0 {
		t.Fatalf("empty fixture should be a degraded no-evidence result: %+v", empty)
	}
}

func TestAWSPrivilegeEscalationRelationshipsUsePathEdges(t *testing.T) {
	relationships := awsPrivilegeEscalationRelationships([]AWSPrivilegeEscalationFinding{{
		FindingID:      "finding-1",
		IdentityNodeID: "aws:identity:role/source",
		ImpactedPath: []AWSPrivilegeEscalationPathStep{
			{NodeID: "aws:identity:role/source", NodeType: "identity"},
			{NodeID: "aws:iam-role/target", NodeType: "iam_role"},
			{NodeID: "aws:kms:key/example", NodeType: "kms_key"},
		},
		Evidence: []AWSPrivilegeEscalationEvidence{{EvidenceRef: "evidence://privilege-escalation"}},
	}})

	if len(relationships) != 2 {
		t.Fatalf("expected two path relationships, got %+v", relationships)
	}
	for _, relationship := range relationships {
		if relationship.Type != "privilege_escalation_path" || relationship.EvidenceRef != "evidence://privilege-escalation" {
			t.Fatalf("unexpected relationship contract: %+v", relationship)
		}
	}
	if relationships[0].FromNodeID != "aws:identity:role/source" || relationships[0].ToNodeID != "aws:iam-role/target" {
		t.Fatalf("first edge should preserve path order: %+v", relationships)
	}
	if relationships[1].FromNodeID != "aws:iam-role/target" || relationships[1].ToNodeID != "aws:kms:key/example" {
		t.Fatalf("second edge should preserve path order: %+v", relationships)
	}
}

func TestAWSPrivilegeEscalationRelationshipsSkipWildcardPassroleTargets(t *testing.T) {
	relationships := awsPrivilegeEscalationRelationships([]AWSPrivilegeEscalationFinding{{
		FindingID:      "finding-2",
		IdentityNodeID: "aws:identity:role/source",
		ImpactedPath: []AWSPrivilegeEscalationPathStep{
			{NodeID: "aws:identity:role/source", NodeType: "identity", Label: "security-admin"},
			{NodeID: "*", NodeType: "iam_role", Label: "wildcard role target"},
		},
		Evidence: []AWSPrivilegeEscalationEvidence{{EvidenceRef: "evidence://privilege-escalation"}},
	}})

	if len(relationships) != 0 {
		t.Fatalf("expected wildcard passrole target to skip graph edge emission, got %+v", relationships)
	}
}

func TestAWSPrivilegeEscalationFindingsIncludesLiveKMSGrant(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 15, 0, 0, time.UTC)
	kms := AWSKMSDecryptReachabilityInventoryResult{
		Records: []AWSKMSDecryptReachabilityRecord{{
			AccountID:              "123456789012",
			Region:                 "us-east-1",
			KeyARN:                 "arn:aws:kms:us-east-1:123456789012:key/live-grant",
			KeyID:                  "live-grant",
			Description:            "payments key",
			ExposureClassification: "restricted",
			FromNodeID:             "aws:resource:kms-key/arn:aws:kms:us-east-1:123456789012:key/live-grant",
			Confidence:             0.88,
			EvidenceRef:            "evidence://kms-grant",
			CollectedAt:            now,
			Grants: []AWSKMSGrant{{
				GranteePrincipal:     "arn:aws:iam::123456789012:role/live-grant-role",
				GranteePrincipalType: "aws",
				Operations:           []string{"Decrypt"},
				Capabilities:         []string{"decrypt"},
				HasConstraints:       true,
			}},
		}},
	}

	findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, kms, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
	if len(findings) == 0 {
		t.Fatalf("expected at least one privilege-escalation finding for live KMS grant")
	}
	foundLiveGrant := false
	for _, finding := range findings {
		if finding.EscalationType == "kms_admin_equivalence" && finding.PrincipalARN == "arn:aws:iam::123456789012:role/live-grant-role" {
			foundLiveGrant = true
			if finding.RuntimeContext != "KMS grant/admin equivalence" {
				t.Fatalf("unexpected runtime context for live KMS grant finding: %s", finding.RuntimeContext)
			}
		}
	}
	if !foundLiveGrant {
		t.Fatalf("expected live KMS grant to be converted to kms_admin_equivalence: %+v", findings)
	}
}

func TestAWSPrivilegeEscalationFindingsRespectsExplicitDenyOnPassRole(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 20, 0, 0, time.UTC)
	sourceNode := "aws:identity:arn:aws:iam::123456789012:role/source"
	targetNode := "aws:identity:arn:aws:iam::123456789012:role/target"
	targetARN := "arn:aws:iam::123456789012:role/target"

	allowRecord := AWSIAMPassRoleRelationshipRecord{
		FromNodeID:         sourceNode,
		ToNodeID:           targetNode,
		SourceRoleARN:      "arn:aws:iam::123456789012:role/source",
		TargetResource:     targetARN,
		TargetWildcardKind: "specific",
		ActionExpression:   "iam:PassRole",
		Effect:             "Allow",
		PolicyName:         "AllowPass",
		StatementSid:       "PassAllowed",
		CollectedAt:        now,
		Confidence:         0.88,
	}

	t.Run("exact action match deny suppresses finding", func(t *testing.T) {
		passRole := AWSIAMPassRoleRelationshipInventoryResult{
			Records: []AWSIAMPassRoleRelationshipRecord{
				allowRecord,
				{
					FromNodeID:         sourceNode,
					ToNodeID:           targetNode,
					SourceRoleARN:      "arn:aws:iam::123456789012:role/source",
					TargetResource:     targetARN,
					TargetWildcardKind: "specific",
					ActionExpression:   "iam:PassRole",
					Effect:             "Deny",
					PolicyName:         "DenyPass",
					StatementSid:       "PassDenied",
					CollectedAt:        now,
					Confidence:         0.88,
				},
			},
		}
		findings := awsPrivilegeEscalationFindings(passRole, AWSKMSDecryptReachabilityInventoryResult{}, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 0 {
			t.Fatalf("expected allowfinding to be suppressed by explicit deny, got %+v", findings)
		}
	})

	t.Run("non-overlapping deny action preserves passrole finding", func(t *testing.T) {
		passRole := AWSIAMPassRoleRelationshipInventoryResult{
			Records: []AWSIAMPassRoleRelationshipRecord{
				allowRecord,
				{
					FromNodeID:         sourceNode,
					ToNodeID:           targetNode,
					SourceRoleARN:      "arn:aws:iam::123456789012:role/source",
					TargetResource:     targetARN,
					TargetWildcardKind: "specific",
					ActionExpression:   "ec2:StartInstances",
					Effect:             "Deny",
					PolicyName:         "DenyStartInstances",
					StatementSid:       "DenyNonPass",
					CollectedAt:        now,
					Confidence:         0.88,
				},
			},
		}
		findings := awsPrivilegeEscalationFindings(passRole, AWSKMSDecryptReachabilityInventoryResult{}, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 1 {
			t.Fatalf("expected passrole finding to remain when deny action does not overlap allow, got %+v", findings)
		}
		if !strings.HasPrefix(findings[0].EscalationType, "passrole_") {
			t.Fatalf("expected passrole escalation type when only passrole allow remains, got %+v", findings[0].EscalationType)
		}
	})

	t.Run("wildcard deny target suppresses matching passrole finding", func(t *testing.T) {
		passRole := AWSIAMPassRoleRelationshipInventoryResult{
			Records: []AWSIAMPassRoleRelationshipRecord{
				allowRecord,
				{
					FromNodeID:         sourceNode,
					ToNodeID:           targetNode,
					SourceRoleARN:      "arn:aws:iam::123456789012:role/source",
					TargetResource:     "*",
					TargetWildcardKind: "all",
					ActionExpression:   "iam:PassRole",
					Effect:             "Deny",
					PolicyName:         "DenyPassAll",
					StatementSid:       "PassDeniedAll",
					CollectedAt:        now,
					Confidence:         0.88,
				},
			},
		}
		findings := awsPrivilegeEscalationFindings(passRole, AWSKMSDecryptReachabilityInventoryResult{}, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 0 {
			t.Fatalf("expected wildcard deny to suppress passrole finding, got %+v", findings)
		}
	})
}

func TestAWSPrivilegeEscalationFindingsRespectsExplicitDenyOnKMSIdentityGrant(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 30, 0, 0, time.UTC)
	accountID := "123456789012"
	region := "us-east-1"
	keyARN := "arn:aws:kms:us-east-1:123456789012:key/99990000-1111-2222-3333-444455556666"
	roleARN := "arn:aws:iam::123456789012:role/source"

	deniedGrant := AWSKMSIdentityGrant{
		PrincipalARN:  roleARN,
		PrincipalType: "aws",
		Effect:        "Allow",
		Actions:       []string{"kms:Decrypt"},
		Capabilities:  []string{"decrypt"},
		StatementSid:  "AllowDecryptOnly",
	}
	denyAllGrant := AWSKMSIdentityGrant{
		PrincipalARN:      "*",
		Effect:            "Deny",
		Actions:           []string{"kms:*"},
		Capabilities:      []string{"admin", "decrypt", "encrypt"},
		WildcardPrincipal: true,
		StatementSid:      "DenyAll",
	}

	t.Run("wildcard deny blocks matching identity grant", func(t *testing.T) {
		kms := AWSKMSDecryptReachabilityInventoryResult{
			Records: []AWSKMSDecryptReachabilityRecord{{
				AccountID:              accountID,
				Region:                 region,
				KeyARN:                 keyARN,
				KeyID:                  "restrictive-example",
				Description:            "restricted key",
				ExposureClassification: "private",
				FromNodeID:             "aws:resource:kms-key/" + keyARN,
				Confidence:             0.91,
				EvidenceRef:            "evidence://kms-grant",
				CollectedAt:            now,
				IdentityGrants: []AWSKMSIdentityGrant{{
					PrincipalARN:  roleARN,
					PrincipalType: "aws",
					Effect:        "Allow",
					Actions:       []string{"kms:*"},
					Capabilities:  []string{"admin", "decrypt", "encrypt", "grant", "sign"},
					StatementSid:  "AllowAll",
				}, denyAllGrant},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, kms, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 0 {
			t.Fatalf("expected explicit wildcard deny to suppress matching KMS grant finding, got %+v", findings)
		}
	})

	t.Run("non-overlapping deny action preserves KMS grant finding", func(t *testing.T) {
		kms := AWSKMSDecryptReachabilityInventoryResult{
			Records: []AWSKMSDecryptReachabilityRecord{{
				AccountID:              accountID,
				Region:                 region,
				KeyARN:                 keyARN,
				KeyID:                  "allow-only",
				Description:            "selectively accessible key",
				ExposureClassification: "private",
				FromNodeID:             "aws:resource:kms-key/" + keyARN,
				Confidence:             0.91,
				EvidenceRef:            "evidence://kms-grant",
				CollectedAt:            now,
				IdentityGrants: []AWSKMSIdentityGrant{deniedGrant, {
					PrincipalARN:      roleARN,
					PrincipalType:     "aws",
					Effect:            "Deny",
					Actions:           []string{"kms:GenerateDataKey"},
					Capabilities:      []string{"decrypt", "encrypt"},
					WildcardPrincipal: false,
					StatementSid:      "UnrelatedDeny",
				}},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, kms, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 1 {
			t.Fatalf("expected decrypt allow finding to remain, got %+v", findings)
		}
		if findings[0].PrincipalARN != deniedGrant.PrincipalARN {
			t.Fatalf("expected finding for deniedGrant principal, got %+v", findings[0])
		}
	})

	t.Run("non-matching deny principal preserves finding", func(t *testing.T) {
		kms := AWSKMSDecryptReachabilityInventoryResult{
			Records: []AWSKMSDecryptReachabilityRecord{{
				AccountID:              accountID,
				Region:                 region,
				KeyARN:                 keyARN,
				KeyID:                  "different-principal",
				Description:            "other-principal key",
				ExposureClassification: "private",
				FromNodeID:             "aws:resource:kms-key/" + keyARN,
				Confidence:             0.91,
				EvidenceRef:            "evidence://kms-grant",
				CollectedAt:            now,
				IdentityGrants: []AWSKMSIdentityGrant{{
					PrincipalARN:  roleARN,
					PrincipalType: "aws",
					Effect:        "Allow",
					Actions:       []string{"kms:*"},
					Capabilities:  []string{"admin", "decrypt"},
					StatementSid:  "AllowAll",
				}, {
					PrincipalARN:  "arn:aws:iam::123456789012:role/other",
					PrincipalType: "aws",
					Effect:        "Deny",
					Actions:       []string{"kms:*"},
					Capabilities:  []string{"admin", "decrypt"},
					StatementSid:  "UnrelatedPrincipalDeny",
				}},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, kms, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 1 {
			t.Fatalf("expected allow finding for unmatched deny principal, got %+v", findings)
		}
	})

	t.Run("deny from a different key does not suppress grant", func(t *testing.T) {
		kms := AWSKMSDecryptReachabilityInventoryResult{
			Records: []AWSKMSDecryptReachabilityRecord{{
				AccountID:              accountID,
				Region:                 region,
				KeyARN:                 keyARN,
				KeyID:                  "allow-key",
				Description:            "target key",
				ExposureClassification: "private",
				FromNodeID:             "aws:resource:kms-key/" + keyARN,
				Confidence:             0.91,
				EvidenceRef:            "evidence://kms-grant-allow",
				CollectedAt:            now,
				IdentityGrants: []AWSKMSIdentityGrant{{
					PrincipalARN:  roleARN,
					PrincipalType: "aws",
					Effect:        "Allow",
					Actions:       []string{"kms:*"},
					Capabilities:  []string{"admin", "decrypt"},
					StatementSid:  "AllowAll",
				}},
			}, {
				AccountID:              accountID,
				Region:                 region,
				KeyARN:                 "arn:aws:kms:us-east-1:123456789012:key/00000000-1111-2222-3333-444455556666",
				KeyID:                  "deny-key",
				Description:            "deny-only key",
				ExposureClassification: "private",
				FromNodeID:             "aws:resource:kms-key/arn:aws:kms:us-east-1:123456789012:key/00000000-1111-2222-3333-444455556666",
				Confidence:             0.91,
				EvidenceRef:            "evidence://kms-grant-deny",
				CollectedAt:            now,
				IdentityGrants: []AWSKMSIdentityGrant{{
					PrincipalARN:  roleARN,
					PrincipalType: "aws",
					Effect:        "Deny",
					Actions:       []string{"kms:*"},
					Capabilities:  []string{"admin", "decrypt"},
					StatementSid:  "BlockOtherKey",
				}},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, kms, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 1 {
			t.Fatalf("expected only the allow key to yield a finding, got %+v", findings)
		}
		if findings[0].TargetNodeID != "aws:resource:kms-key/"+keyARN {
			t.Fatalf("expected finding to target first key, got %+v", findings[0])
		}
	})

	t.Run("live grant is suppressed when explicit deny matches grantee", func(t *testing.T) {
		kms := AWSKMSDecryptReachabilityInventoryResult{
			Records: []AWSKMSDecryptReachabilityRecord{{
				AccountID:              accountID,
				Region:                 region,
				KeyARN:                 keyARN,
				KeyID:                  "live-denied",
				Description:            "live grant with key policy deny",
				ExposureClassification: "private",
				FromNodeID:             "aws:resource:kms-key/" + keyARN,
				Confidence:             0.91,
				EvidenceRef:            "evidence://kms-live-grant",
				CollectedAt:            now,
				IdentityGrants: []AWSKMSIdentityGrant{{
					PrincipalARN:      "*",
					Effect:            "Deny",
					Actions:           []string{"kms:*"},
					Capabilities:      []string{"admin", "decrypt"},
					WildcardPrincipal: true,
					StatementSid:      "DenyAllLive",
				}},
				Grants: []AWSKMSGrant{{
					GrantID:              "grant-live-1",
					GranteePrincipal:     roleARN,
					GranteePrincipalType: "aws",
					Operations:           []string{"Decrypt"},
					Capabilities:         []string{"decrypt"},
					HasConstraints:       true,
				}},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, kms, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 0 {
			t.Fatalf("expected live grant to be suppressed by matching explicit deny, got %+v", findings)
		}
	})

	t.Run("live grant with non-overlapping explicit deny remains", func(t *testing.T) {
		kms := AWSKMSDecryptReachabilityInventoryResult{
			Records: []AWSKMSDecryptReachabilityRecord{{
				AccountID:              accountID,
				Region:                 region,
				KeyARN:                 keyARN,
				KeyID:                  "live-allowed",
				Description:            "live grant without matching deny",
				ExposureClassification: "private",
				FromNodeID:             "aws:resource:kms-key/" + keyARN,
				Confidence:             0.91,
				EvidenceRef:            "evidence://kms-live-grant",
				CollectedAt:            now,
				IdentityGrants: []AWSKMSIdentityGrant{{
					PrincipalARN:      "*",
					Effect:            "Deny",
					Actions:           []string{"kms:GenerateDataKey"},
					Capabilities:      []string{"decrypt", "encrypt"},
					WildcardPrincipal: true,
					StatementSid:      "DenyOtherOperation",
				}},
				Grants: []AWSKMSGrant{{
					GrantID:              "grant-live-2",
					GranteePrincipal:     roleARN,
					GranteePrincipalType: "aws",
					Operations:           []string{"Decrypt"},
					Capabilities:         []string{"decrypt"},
					HasConstraints:       true,
				}},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, kms, AWSSecretsManagerMetadataInventoryResult{}, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 1 {
			t.Fatalf("expected live grant finding to remain when deny does not overlap actions, got %+v", findings)
		}
		if findings[0].EscalationType != "kms_admin_equivalence" || findings[0].PrincipalARN != roleARN {
			t.Fatalf("expected live KMS admin finding for role principal, got %+v", findings[0])
		}
	})
}

func TestAWSPrivilegeEscalationFindingsRespectsExplicitDenyOnSecretIdentityGrant(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 45, 0, 0, time.UTC)
	accountID := "123456789012"
	region := "us-east-1"
	secretARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:restricted-secret"
	roleARN := "arn:aws:iam::123456789012:role/source"
	secretNodeID := "aws:resource:secret:" + secretARN

	t.Run("wildcard deny suppresses matching secret grant", func(t *testing.T) {
		secrets := AWSSecretsManagerMetadataInventoryResult{
			Records: []AWSSecretsManagerMetadataRecord{{
				AccountID:              accountID,
				Region:                 region,
				SecretARN:              secretARN,
				SecretName:             "restricted-secret",
				ExposureClassification: "private",
				FromNodeID:             secretNodeID,
				Confidence:             0.9,
				EvidenceRef:            "evidence://secrets",
				CollectedAt:            now,
				IdentityGrants: []AWSSecretsManagerIdentityGrant{
					{
						PrincipalARN:  roleARN,
						PrincipalType: "aws",
						Effect:        "Allow",
						Actions:       []string{"secretsmanager:GetSecretValue"},
						StatementSid:  "AllowSecretRead",
					},
					{
						PrincipalARN:      "*",
						Effect:            "Deny",
						Actions:           []string{"secretsmanager:Get*"},
						WildcardPrincipal: true,
						StatementSid:      "DenyAllSecretRead",
					},
				},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, AWSKMSDecryptReachabilityInventoryResult{}, secrets, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 0 {
			t.Fatalf("expected explicit wildcard deny to suppress secret grant finding, got %+v", findings)
		}
	})

	t.Run("wildcard secret read actions are recognized", func(t *testing.T) {
		secrets := AWSSecretsManagerMetadataInventoryResult{
			Records: []AWSSecretsManagerMetadataRecord{{
				AccountID:              accountID,
				Region:                 region,
				SecretARN:              secretARN,
				SecretName:             "restricted-secret",
				ExposureClassification: "private",
				FromNodeID:             secretNodeID,
				Confidence:             0.9,
				EvidenceRef:            "evidence://secrets",
				CollectedAt:            now,
				IdentityGrants: []AWSSecretsManagerIdentityGrant{{
					PrincipalARN:  roleARN,
					PrincipalType: "aws",
					Effect:        "Allow",
					Actions:       []string{"secretsmanager:Get*"},
					StatementSid:  "AllowSecretReadWildcard",
				}},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, AWSKMSDecryptReachabilityInventoryResult{}, secrets, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 1 {
			t.Fatalf("expected wildcard read action to produce a secret escalation finding, got %+v", findings)
		}
		if findings[0].TargetNodeID != secretNodeID || findings[0].EscalationType != "secrets_admin_equivalence" {
			t.Fatalf("expected secret escalation finding with target node id, got %+v", findings[0])
		}
	})

	t.Run("non-overlapping deny does not suppress secret grant", func(t *testing.T) {
		secrets := AWSSecretsManagerMetadataInventoryResult{
			Records: []AWSSecretsManagerMetadataRecord{{
				AccountID:              accountID,
				Region:                 region,
				SecretARN:              secretARN,
				SecretName:             "restricted-secret",
				ExposureClassification: "private",
				FromNodeID:             secretNodeID,
				Confidence:             0.9,
				EvidenceRef:            "evidence://secrets",
				CollectedAt:            now,
				IdentityGrants: []AWSSecretsManagerIdentityGrant{
					{
						PrincipalARN:  roleARN,
						PrincipalType: "aws",
						Effect:        "Allow",
						Actions:       []string{"secretsmanager:Get*"},
						StatementSid:  "AllowSecretRead",
					},
					{
						PrincipalARN: "arn:aws:iam::123456789012:role/other",
						Effect:       "Deny",
						Actions:      []string{"secretsmanager:*"},
						StatementSid: "UnrelatedDeny",
					},
				},
			}},
		}
		findings := awsPrivilegeEscalationFindings(AWSIAMPassRoleRelationshipInventoryResult{}, AWSKMSDecryptReachabilityInventoryResult{}, secrets, AWSLeastPrivilegeResult{}, AWSBlastRadiusResult{}, now)
		if len(findings) != 1 {
			t.Fatalf("expected unrelated deny principal to preserve secret grant finding, got %+v", findings)
		}
	})
}

func TestAWSPrivilegeEscalationRecommendationQualifiesLeastPrivilegeWildcards(t *testing.T) {
	t.Run("wildcard escalation actions qualify for remove decisions", func(t *testing.T) {
		recommendation := AWSLeastPrivilegeRecommendation{
			Decision:       "remove",
			GrantedActions: []string{"sts:*"},
		}
		if !awsPrivilegeEscalationRecommendationQualifies(recommendation) {
			t.Fatalf("expected wildcard sts:* to qualify")
		}
	})

	t.Run("wildcard pass role patterns qualify for remove decisions", func(t *testing.T) {
		recommendation := AWSLeastPrivilegeRecommendation{
			Decision:       "remove",
			GrantedActions: []string{"iam:Pass*"},
		}
		if !awsPrivilegeEscalationRecommendationQualifies(recommendation) {
			t.Fatalf("expected wildcard iam:Pass* to qualify")
		}
	})

	t.Run("wildcard attach role patterns qualify for remove decisions", func(t *testing.T) {
		recommendation := AWSLeastPrivilegeRecommendation{
			Decision:       "review",
			GrantedActions: []string{"iam:Attach*"},
		}
		if !awsPrivilegeEscalationRecommendationQualifies(recommendation) {
			t.Fatalf("expected wildcard iam:Attach* to qualify")
		}
	})

	t.Run("non-escalation wildcard actions do not qualify", func(t *testing.T) {
		recommendation := AWSLeastPrivilegeRecommendation{
			Decision:       "remove",
			GrantedActions: []string{"ec2:startinstances"},
		}
		if awsPrivilegeEscalationRecommendationQualifies(recommendation) {
			t.Fatalf("expected non-escalation action to not qualify")
		}
	})

	t.Run("wildcard escalations only require review/remove decisions", func(t *testing.T) {
		recommendation := AWSLeastPrivilegeRecommendation{
			Decision:       "keep",
			GrantedActions: []string{"sts:*"},
		}
		if awsPrivilegeEscalationRecommendationQualifies(recommendation) {
			t.Fatalf("expected keep decision not to qualify even for escalation action")
		}
	})
}
