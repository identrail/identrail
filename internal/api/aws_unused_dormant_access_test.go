package api

import (
	"testing"
	"time"
)

func TestGetAWSUnusedDormantAccessBuildsFindingContract(t *testing.T) {
	now := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	svc, ws := newLeastPrivilegeService(t, "project-unused-dormant-access", now)

	result, err := svc.GetAWSUnusedDormantAccessFindings(defaultScopeContext(), ws, "project-unused-dormant-access", AWSUnusedDormantAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get unused dormant access findings: %v", err)
	}
	if result.CurrentIssueRef != "#1523" || result.Version != awsUnusedDormantAccessVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Findings) == 0 || result.Summary.TotalFindings != len(result.Findings) {
		t.Fatalf("expected findings summary to match payload: %+v", result.Summary)
	}
	if result.Findings[0].Score < result.Findings[len(result.Findings)-1].Score {
		t.Fatalf("findings are not ranked by descending score: %+v", result.Findings)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected graph relationships: %+v", result.Relationships)
	}
	if result.Summary.RemediationPreviewCount == 0 || result.Summary.CleanupCandidateCount == 0 {
		t.Fatalf("expected cleanup candidates and remediation previews: %+v", result.Summary)
	}

	hasNeverUsed := false
	hasStaleOrUnknown := false
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsUnusedDormantAccessVersion || finding.Rationale == "" {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.DormancyState == "" || finding.PolicyScope == "" || finding.OwnerContext == "" || len(finding.Evidence) == 0 {
			t.Fatalf("finding missing dormant-access fields: %+v", finding)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
		switch finding.DormancyState {
		case "never_used":
			hasNeverUsed = true
			if len(finding.CandidateActions) == 0 {
				t.Fatalf("never-used finding must name candidate actions: %+v", finding)
			}
		case "stale", "unknown":
			hasStaleOrUnknown = true
		}
	}
	if !hasNeverUsed || !hasStaleOrUnknown {
		t.Fatalf("expected never-used plus stale/unknown findings, got %+v", result.Summary.DormancyStateCounts)
	}
}

func TestGetAWSUnusedDormantAccessFiltersDormancyState(t *testing.T) {
	now := time.Date(2026, 6, 20, 9, 10, 0, 0, time.UTC)
	svc, ws := newLeastPrivilegeService(t, "project-unused-dormant-filters", now)

	result, err := svc.GetAWSUnusedDormantAccessFindings(defaultScopeContext(), ws, "project-unused-dormant-filters", AWSUnusedDormantAccessRequest{
		ConnectorID:   "aws-prod",
		FixtureState:  "success",
		DormancyState: "never_used",
	})
	if err != nil {
		t.Fatalf("filter unused dormant access findings: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected never-used resource findings")
	}
	for _, finding := range result.Findings {
		if finding.DormancyState != "never_used" {
			t.Fatalf("dormancy filter leaked %+v", finding)
		}
	}
	if result.AppliedFilters["dormancy_state"] != "never-used" {
		t.Fatalf("expected applied dormancy filter, got %+v", result.AppliedFilters)
	}

	cleanup, err := svc.GetAWSUnusedDormantAccessFindings(defaultScopeContext(), ws, "project-unused-dormant-filters", AWSUnusedDormantAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Status:       "cleanup_candidate",
	})
	if err != nil {
		t.Fatalf("filter cleanup candidates: %v", err)
	}
	if len(cleanup.Findings) == 0 {
		t.Fatal("expected cleanup candidate findings")
	}
	for _, finding := range cleanup.Findings {
		if finding.Status != "cleanup_candidate" {
			t.Fatalf("cleanup status filter leaked %+v", finding)
		}
	}
	if cleanup.AppliedFilters["status"] != "cleanup-candidate" {
		t.Fatalf("expected applied cleanup status filter, got %+v", cleanup.AppliedFilters)
	}
}

func TestAWSUnusedDormantAccessQualificationSkipsActiveReviewSignals(t *testing.T) {
	now := time.Date(2026, 6, 20, 9, 15, 0, 0, time.UTC)
	activeAnalyzer := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "aws-least-privilege:access-analyzer",
		RecommendationType: "review-external-access",
		Decision:           "review",
		BreakagePrediction: "unknown",
		ObservedActions:    []string{"secretsmanager:GetSecretValue"},
		Evidence:           []AWSLeastPrivilegeEvidence{{Source: "access_analyzer", Relationship: "observed", ObservedAt: now}},
		CalculationVersion: awsLeastPrivilegeVersion,
	}
	if awsUnusedDormantRecommendationQualifies(activeAnalyzer) {
		t.Fatalf("active Access Analyzer review signal must not qualify as dormant access: %+v", activeAnalyzer)
	}

	staleIAM := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "aws-least-privilege:iam-last-used",
		RecommendationType: "review-stale-service-access",
		Decision:           "review",
		BreakagePrediction: "unknown",
		Evidence:           []AWSLeastPrivilegeEvidence{{Source: "iam_last_used", Relationship: "stale", ObservedAt: now.Add(-120 * 24 * time.Hour)}},
		CalculationVersion: awsLeastPrivilegeVersion,
	}
	if !awsUnusedDormantRecommendationQualifies(staleIAM) {
		t.Fatalf("stale IAM review signal should qualify as dormant access: %+v", staleIAM)
	}
}

func TestGetAWSUnusedDormantAccessPermissionDeniedAndEmptyStatesAreExplicit(t *testing.T) {
	now := time.Date(2026, 6, 20, 9, 20, 0, 0, time.UTC)
	svc, ws := newLeastPrivilegeService(t, "project-unused-dormant-states", now)

	denied, err := svc.GetAWSUnusedDormantAccessFindings(defaultScopeContext(), ws, "project-unused-dormant-states", AWSUnusedDormantAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || denied.Confidence != 0 || len(denied.Findings) != 0 {
		t.Fatalf("expected blocked permission-denied state, got %+v", denied)
	}
	if len(denied.Diagnostics) == 0 || len(denied.CoverageGaps) == 0 {
		t.Fatalf("expected diagnostics and coverage gaps for denied state")
	}

	empty, err := svc.GetAWSUnusedDormantAccessFindings(defaultScopeContext(), ws, "project-unused-dormant-states", AWSUnusedDormantAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Findings) != 0 || empty.Summary.TotalFindings != 0 {
		t.Fatalf("expected degraded empty state, got %+v", empty)
	}
}
