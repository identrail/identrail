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
