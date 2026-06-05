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
	if got, want := strings.Join(result.CompletedIssueRefs, ","), "#1473,#1474,#1475,#1476,#1477,#1478,#1479"; got != want {
		t.Fatalf("completed refs = %q, want %q", got, want)
	}
	wantReadyRefs := "#1480,#1481,#1482,#1483,#1484,#1485,#1486,#1487,#1488,#1489,#1490,#1491,#1492,#1493,#1494,#1495,#1496"
	if got := strings.Join(result.ReadyIssueRefs, ","); got != wantReadyRefs {
		t.Fatalf("ready refs = %q, want %q", got, wantReadyRefs)
	}
	if result.BlockedIssueCount != 61 || !containsString(result.BlockedIssueRefs, "#1497") {
		t.Fatalf("expected downstream issues blocked by incomplete blockers, got count=%d refs=%v", result.BlockedIssueCount, result.BlockedIssueRefs)
	}
	for _, check := range result.Checks {
		if check.Status != awsPlatformDependencyStatusReady {
			t.Fatalf("expected check %s to pass, got %+v", check.Name, check)
		}
	}
	current := requireAWSPlatformDependencyIssue(t, result.Issues, "#1474")
	if current.ReadyForPR || current.DependencyStatus != awsPlatformIssueStateCompleted {
		t.Fatalf("expected current issue completed after merge, got %+v", current)
	}
	completed := requireAWSPlatformDependencyIssue(t, result.Issues, "#1476")
	if completed.ReadyForPR || completed.DependencyStatus != awsPlatformIssueStateCompleted {
		t.Fatalf("expected #1476 to be completed after this PR, got %+v", completed)
	}
	completedEC2 := requireAWSPlatformDependencyIssue(t, result.Issues, "#1477")
	if completedEC2.ReadyForPR || completedEC2.DependencyStatus != awsPlatformIssueStateCompleted {
		t.Fatalf("expected #1477 to be completed after this PR, got %+v", completedEC2)
	}
	completedECS := requireAWSPlatformDependencyIssue(t, result.Issues, "#1478")
	if completedECS.ReadyForPR || completedECS.DependencyStatus != awsPlatformIssueStateCompleted {
		t.Fatalf("expected #1478 to be completed after this PR, got %+v", completedECS)
	}
	completedLambda := requireAWSPlatformDependencyIssue(t, result.Issues, "#1479")
	if completedLambda.ReadyForPR || completedLambda.DependencyStatus != awsPlatformIssueStateCompleted {
		t.Fatalf("expected #1479 to be completed after this PR, got %+v", completedLambda)
	}
	ready := requireAWSPlatformDependencyIssue(t, result.Issues, "#1480")
	if !ready.ReadyForPR || ready.DependencyStatus != awsPlatformIssueStateReady || len(ready.FailureReasons) != 0 {
		t.Fatalf("expected #1480 to be ready after #1479 completed, got %+v", ready)
	}
	blocked := requireAWSPlatformDependencyIssue(t, result.Issues, "#1497")
	if blocked.ReadyForPR || blocked.DependencyStatus != awsPlatformIssueStateBlocked || !containsString(blocked.FailureReasons, "waiting on #1496") {
		t.Fatalf("expected #1497 to wait on #1496, got %+v", blocked)
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

func TestBuildAWSPlatformDependencyIssuesBlocksRowsWithMalformedBlockers(t *testing.T) {
	rows, parseFailures := parseAWSPlatformDependencyLedger(`
### Wave 0: Clean baseline and epic setup
- #1473 - AWS platform baseline verification gate (blocked by: none)
- #1474 - AWS platform issue dependency index (blocked by: 1473)
`)
	if len(parseFailures) == 0 {
		t.Fatalf("expected malformed blocker parse failure")
	}

	issues, validationFailures := buildAWSPlatformDependencyIssues(rows)
	if len(validationFailures) != 0 {
		t.Fatalf("did not expect graph validation failures, got %+v", validationFailures)
	}
	current := requireAWSPlatformDependencyIssue(t, issues, "#1474")
	if current.ReadyForPR || current.DependencyStatus != awsPlatformIssueStateBlocked {
		t.Fatalf("malformed blocker issue should be blocked, got %+v", current)
	}
	if !containsString(current.FailureReasons, `#1474 has malformed blocker refs "1473"`) {
		t.Fatalf("expected issue failure reason to carry blocker parse error, got %+v", current.FailureReasons)
	}

	checks := awsPlatformDependencyChecks(rows, issues, parseFailures, time.Date(2026, 6, 4, 12, 30, 0, 0, time.UTC))
	currentCheck := requireAWSPlatformDependencyCheck(t, checks, "current_issue_readiness")
	if currentCheck.Status != awsPlatformDependencyStatusBlocked {
		t.Fatalf("current readiness check should be blocked for malformed current issue, got %+v", currentCheck)
	}
}

func TestAWSPlatformCurrentIssueReadyTreatsCompletedIssueAsSatisfied(t *testing.T) {
	issues := []AWSPlatformDependencyIssue{{
		IssueNumber:      awsPlatformDependencyCurrentIssue,
		IssueRef:         awsIssueRef(awsPlatformDependencyCurrentIssue),
		DependencyStatus: awsPlatformIssueStateCompleted,
		ReadyForPR:       false,
	}}
	if !awsPlatformCurrentIssueReady(issues) {
		t.Fatalf("completed current issue should satisfy readiness check")
	}
	issues[0].DependencyStatus = awsPlatformIssueStateBlocked
	if awsPlatformCurrentIssueReady(issues) {
		t.Fatalf("blocked current issue should not satisfy readiness check")
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
	if !containsString(body.Index.CompletedIssueRefs, "#1479") || !containsString(body.Index.ReadyIssueRefs, "#1480") || body.Index.Status != awsPlatformDependencyStatusReady {
		t.Fatalf("expected merged issue and next ready issue in router payload, got %+v", body.Index)
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

func requireAWSPlatformDependencyCheck(t *testing.T, checks []AWSPlatformDependencyCheck, name string) AWSPlatformDependencyCheck {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("dependency check %s not found", name)
	return AWSPlatformDependencyCheck{}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
