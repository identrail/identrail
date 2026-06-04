package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func TestGetAWSPlatformDependencyIndexBuildsCanonicalLedger(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 11, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSPlatformDependencyIndex(ctx, "default", "project-a", AWSPlatformDependencyIndexRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get dependency index: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready index, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1474" {
		t.Fatalf("unexpected parent/current refs: %+v", result)
	}
	if result.IssueCount != 85 || result.WaveCount != 11 {
		t.Fatalf("unexpected ledger shape: issues=%d waves=%d", result.IssueCount, result.WaveCount)
	}
	if got, want := strings.Join(result.CompletedIssueRefs, ","), "#1473"; got != want {
		t.Fatalf("completed refs = %q, want %q", got, want)
	}
	if got, want := strings.Join(result.ReadyIssueRefs, ","), "#1474,#1475"; got != want {
		t.Fatalf("ready refs = %q, want %q", got, want)
	}
	if result.BlockedIssueCount != 82 || !containsString(result.BlockedIssueRefs, "#1476") {
		t.Fatalf("expected downstream issues blocked by incomplete blockers, got count=%d refs=%v", result.BlockedIssueCount, result.BlockedIssueRefs)
	}
	for _, check := range result.Checks {
		if check.Status != awsPlatformDependencyStatusReady {
			t.Fatalf("expected check %s to pass, got %+v", check.Name, check)
		}
	}
	current := requireAWSPlatformDependencyIssue(t, result.Issues, "#1474")
	if !current.ReadyForPR || current.DependencyStatus != awsPlatformIssueStateReady {
		t.Fatalf("expected current issue ready for PR, got %+v", current)
	}
	blocked := requireAWSPlatformDependencyIssue(t, result.Issues, "#1476")
	if blocked.ReadyForPR || blocked.DependencyStatus != awsPlatformIssueStateBlocked || !containsString(blocked.FailureReasons, "waiting on #1475") {
		t.Fatalf("expected #1476 to wait on #1475, got %+v", blocked)
	}
	for _, issue := range result.Issues {
		for _, blockerRef := range issue.BlockerRefs {
			if !strings.HasPrefix(blockerRef, "#") {
				t.Fatalf("blocker ref %q for %s does not use #1234 format", blockerRef, issue.IssueRef)
			}
		}
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestRouterAWSPlatformDependencyIndex(t *testing.T) {
	r := newAWSConnectionTestRouter(t, &fakeAWSConnectorValidator{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/dependency-index", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected dependency index 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var body struct {
		Index AWSPlatformDependencyIndexResult `json:"index"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode dependency index response: %v", err)
	}
	if body.Index.IssueCount != 85 || body.Index.ParentIssueRef != "#1472" || body.Index.CurrentIssueRef != "#1474" {
		t.Fatalf("unexpected dependency index payload: %+v", body.Index)
	}
	if !containsString(body.Index.ReadyIssueRefs, "#1474") || body.Index.Status != awsPlatformDependencyStatusReady {
		t.Fatalf("expected current issue ready in router payload, got %+v", body.Index)
	}
}

func requireAWSPlatformDependencyIssue(t *testing.T, issues []AWSPlatformDependencyIssue, ref string) AWSPlatformDependencyIssue {
	t.Helper()
	for _, issue := range issues {
		if issue.IssueRef == ref {
			return issue
		}
	}
	t.Fatalf("dependency issue %s not found", ref)
	return AWSPlatformDependencyIssue{}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
