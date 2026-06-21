package api

import (
	"strings"
	"testing"
	"time"
)

func newCrossAccountTrustService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSCrossAccountTrustBuildsFindingContract(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 0, 0, 0, time.UTC)
	svc, ws := newCrossAccountTrustService(t, "project-cross-account-trust", now)

	result, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get cross-account trust: %v", err)
	}
	if result.CurrentIssueRef != "#1526" || result.Version != awsCrossAccountTrustVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready status, got %q with diagnostics=%+v", result.Status, result.Diagnostics)
	}
	if len(result.Findings) == 0 || result.Summary.TotalFindings != len(result.Findings) {
		t.Fatalf("expected findings summary to match payload: %+v", result.Summary)
	}
	if result.Summary.PublicPrincipalCount == 0 || result.Summary.CrossAccountGrantCount == 0 {
		t.Fatalf("expected public and cross-account grant findings: %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected graph relationships: %+v", result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 || len(result.EvidenceLinks) == 0 {
		t.Fatalf("expected caveats, coverage gaps, and evidence links: %+v", result)
	}
	for i := 1; i < len(result.Findings); i++ {
		if result.Findings[i-1].Score < result.Findings[i].Score {
			t.Fatalf("findings are not ranked by descending score: %+v", result.Findings)
		}
	}
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsCrossAccountTrustVersion {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.FindingType == "" || finding.Severity == "" || finding.Status == "" || finding.Rationale == "" {
			t.Fatalf("finding missing classification fields: %+v", finding)
		}
		if finding.Score <= 0 || finding.Confidence <= 0 {
			t.Fatalf("finding missing score/confidence: %+v", finding)
		}
		if finding.ResourceLabel == "" || len(finding.ImpactedPath) < 2 || len(finding.Evidence) == 0 {
			t.Fatalf("finding missing path/evidence fields: %+v", finding)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
	}
}

func TestGetAWSCrossAccountTrustFiltersByTypeServicePrincipalAndResource(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 5, 0, 0, time.UTC)
	svc, ws := newCrossAccountTrustService(t, "project-cross-account-trust-filters", now)

	kms, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-filters", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Service:      "kms",
		FindingType:  "cross_account_resource_access",
		Principal:    "partner-ingest",
		Resource:     "partner-feed",
	})
	if err != nil {
		t.Fatalf("kms filter: %v", err)
	}
	if len(kms.Findings) == 0 {
		t.Fatalf("expected filtered KMS cross-account findings")
	}
	for _, finding := range kms.Findings {
		if finding.Service != "kms" || finding.FindingType != "cross_account_resource_access" {
			t.Fatalf("filter leaked unrelated finding: %+v", finding)
		}
		if !strings.Contains(finding.ExternalPrincipalARN, "partner-ingest") {
			t.Fatalf("principal filter leaked: %+v", finding)
		}
		if !strings.Contains(strings.ToLower(finding.ResourceLabel), "partner") && !strings.Contains(strings.ToLower(finding.ResourceARN), "partner") {
			t.Fatalf("resource filter leaked: %+v", finding)
		}
	}
	if kms.AppliedFilters["service"] != "kms" || kms.AppliedFilters["finding_type"] != "cross-account-resource-access" {
		t.Fatalf("expected normalized applied filters, got %+v", kms.AppliedFilters)
	}
}

func TestGetAWSCrossAccountTrustFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 10, 0, 0, time.UTC)
	svc, ws := newCrossAccountTrustService(t, "project-cross-account-trust-states", now)

	denied, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-states", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || denied.Confidence != 0 || len(denied.Findings) != 0 {
		t.Fatalf("expected blocked permission-denied state with no findings: %+v", denied)
	}

	degraded, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-states", AWSCrossAccountTrustRequest{
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
		t.Fatalf("degraded sources should keep partial external-access evidence visible: %+v", degraded)
	}

	empty, err := svc.GetAWSCrossAccountTrust(defaultScopeContext(), ws, "project-cross-account-trust-states", AWSCrossAccountTrustRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "ready" || len(empty.Findings) != 0 || empty.Summary.TotalFindings != 0 {
		t.Fatalf("empty fixture should be a ready no-findings result: %+v", empty)
	}
}

func TestAWSCrossAccountTrustRuntimeAssumptionFinding(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 15, 0, 0, time.UTC)
	record := AWSRuntimeEventRecord{
		EventID:             "evt-cross-account-assume",
		AccountID:           "222222222222",
		Region:              "us-east-1",
		EventName:           "AssumeRole",
		Action:              "sts:AssumeRole",
		ActorPrincipalARN:   "arn:aws:iam::111111111111:role/partner-deployer",
		ActorIdentityNodeID: "aws:identity:arn:aws:iam::111111111111:role/partner-deployer",
		Session: AWSRuntimeEventSession{
			OriginalActorARN: "arn:aws:iam::111111111111:role/partner-deployer",
			AssumedRoleARN:   "arn:aws:iam::222222222222:role/prod-deploy",
			SourceIdentity:   "partner-change-123",
		},
		EvidenceRef: "runtime-evidence://evt-cross-account-assume",
		Confidence:  0.9,
		ObservedAt:  now,
	}

	finding, ok := awsCrossAccountTrustFindingFromRuntimeAssumption(record, nil, now)
	if !ok {
		t.Fatalf("expected cross-account AssumeRole runtime event to produce finding")
	}
	if finding.FindingType != "runtime_cross_account_assumption" || !finding.RuntimeObserved {
		t.Fatalf("unexpected runtime finding: %+v", finding)
	}
	if finding.ExternalPrincipalAccount != "111111111111" || finding.AccountID != "222222222222" {
		t.Fatalf("expected actor/target accounts to be preserved, got %+v", finding)
	}
	if !finding.HasCondition || len(finding.ConditionKeys) == 0 {
		t.Fatalf("expected SourceIdentity to be surfaced as trust context, got %+v", finding)
	}
}
