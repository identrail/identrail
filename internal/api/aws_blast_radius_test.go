package api

import (
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func newBlastRadiusService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, project)
	seedAWSConnectorForScanTest(t, store, ctx, project, "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	return svc, "default"
}

func TestGetAWSBlastRadiusBuildsRankedIntelligenceContract(t *testing.T) {
	now := time.Date(2026, 6, 19, 20, 0, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-blast-radius", now)

	result, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get blast radius: %v", err)
	}
	if result.CurrentIssueRef != "#1521" || result.Version != awsBlastRadiusVersion || result.Status != "ready" {
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
	if result.Summary.RemediationPreviewCount == 0 {
		t.Fatalf("expected remediation previews: %+v", result.Summary)
	}
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsBlastRadiusVersion || finding.Rationale == "" {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.Score <= 0 || finding.Confidence <= 0 || len(finding.ImpactedPath) < 2 || len(finding.Evidence) == 0 {
			t.Fatalf("finding missing score/path/evidence: %+v", finding)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
	}
}

func TestGetAWSBlastRadiusFiltersBySeverityStatusRiskAndIdentity(t *testing.T) {
	now := time.Date(2026, 6, 19, 20, 5, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-blast-radius-filters", now)

	critical, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-filters", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "critical",
	})
	if err != nil {
		t.Fatalf("critical filter: %v", err)
	}
	if len(critical.Findings) == 0 {
		t.Fatalf("expected critical findings")
	}
	for _, finding := range critical.Findings {
		if finding.Severity != "critical" {
			t.Fatalf("severity filter leaked %+v", finding)
		}
	}
	if critical.AppliedFilters["severity"] != "critical" {
		t.Fatalf("expected severity applied filter, got %+v", critical.AppliedFilters)
	}

	agent, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-filters", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		RiskType:     "undeclared-agent-tool-path",
		Status:       "action_required",
	})
	if err != nil {
		t.Fatalf("agent filter: %v", err)
	}
	if len(agent.Findings) == 0 {
		all, allErr := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-filters", AWSBlastRadiusRequest{ConnectorID: "aws-prod", FixtureState: "success"})
		if allErr != nil {
			t.Fatalf("expected undeclared agent tool finding; also failed to load unfiltered result: %v", allErr)
		}
		t.Fatalf("expected undeclared agent tool finding; risk counts=%+v status counts=%+v", all.Summary.RiskTypeCounts, all.Summary.StatusCounts)
	}
	for _, finding := range agent.Findings {
		if finding.RiskType != "undeclared-agent-tool-path" || finding.Status != "action_required" {
			t.Fatalf("risk/status filter leaked %+v", finding)
		}
	}

	identity, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-filters", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     "case-triage-runtime",
	})
	if err != nil {
		t.Fatalf("identity filter: %v", err)
	}
	if len(identity.Findings) == 0 {
		t.Fatalf("expected identity-matched findings")
	}
	for _, finding := range identity.Findings {
		if !awsRuntimeEventMatchesAny("case-triage-runtime", finding.IdentityNodeID, finding.PrincipalARN, finding.DisplayName) {
			t.Fatalf("identity filter leaked %+v", finding)
		}
	}
}

func TestGetAWSBlastRadiusPermissionDeniedAndEmptyStatesAreExplicit(t *testing.T) {
	now := time.Date(2026, 6, 19, 20, 10, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-blast-radius-states", now)

	denied, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-states", AWSBlastRadiusRequest{
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

	empty, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-states", AWSBlastRadiusRequest{
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

func TestNormalizeAWSBlastRadiusFixtureState(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSBlastRadiusFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected denied for disconnected default, got %q", got)
	}
	if got := normalizeAWSBlastRadiusFixtureState("EMPTY", AWSConnectionStatus{}, false); got != "empty" {
		t.Fatalf("expected normalized empty, got %q", got)
	}
	if got := normalizeAWSBlastRadiusFixtureState("bogus", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected invalid fixture state to return empty token, got %q", got)
	}
}
