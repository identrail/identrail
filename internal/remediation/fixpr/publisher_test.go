package fixpr

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type recordedRequest struct {
	Method string
	Path   string
	Body   map[string]any
	Auth   string
}

func newFakeGitHubServer(t *testing.T) (*httptest.Server, *[]recordedRequest, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var requests []recordedRequest

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		var parsed map[string]any
		if len(body) > 0 {
			_ = json.Unmarshal(body, &parsed)
		}
		mu.Lock()
		requests = append(requests, recordedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Body:   parsed,
			Auth:   r.Header.Get("Authorization"),
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_, _ = w.Write([]byte(`{"object":{"sha":"base-sha-001","type":"commit"}}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/git/commits/"):
			_, _ = w.Write([]byte(`{"sha":"base-sha-001","tree":{"sha":"base-tree-001"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/blobs"):
			content, _ := parsed["content"].(string)
			sha := "blob-" + shortHash(content)
			writeJSON(w, map[string]any{"sha": sha})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/trees"):
			writeJSON(w, map[string]any{"sha": "tree-sha-001"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/commits"):
			writeJSON(w, map[string]any{"sha": "commit-sha-001"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			writeJSON(w, map[string]any{"ref": parsed["ref"]})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			writeJSON(w, map[string]any{
				"number":   42,
				"html_url": "https://github.example.com/acme/repo/pull/42",
			})
		default:
			http.Error(w, "unexpected request: "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	return srv, &requests, &mu
}

func writeJSON(w http.ResponseWriter, body map[string]any) {
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(body)
}

func shortHash(s string) string {
	sum := 0
	for _, c := range s {
		sum = (sum*131 + int(c)) & 0xffff
	}
	return jsonHex(sum)
}

func jsonHex(n int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 4)
	for i := 3; i >= 0; i-- {
		out[i] = hex[n&0xf]
		n >>= 4
	}
	return string(out)
}

func TestGitHubPublisher_Publish_HappyPath(t *testing.T) {
	srv, recorded, mu := newFakeGitHubServer(t)

	plan := FixPRPlan{
		BaseBranch:    "main",
		BranchName:    "identrail/fix/finding-1",
		CommitMessage: "identrail: fix something",
		PRTitle:       "identrail: fix overprivileged role",
		PRBody:        "trace: finding-1",
		FindingID:     "finding-1",
		FindingType:   "overprivileged_identity",
		Files: []PlanFile{
			{Path: ".identrail/remediations/finding-1/README.md", Content: "# Remediation\n"},
			{Path: ".identrail/remediations/finding-1/patch.json", Content: `{"Version":"2012-10-17"}` + "\n"},
		},
	}

	publisher := GitHubPublisher{APIBaseURL: srv.URL}
	result, err := publisher.Publish(context.Background(), "acme", "repo", "tok-xyz", plan)
	if err != nil {
		t.Fatalf("Publish returned error: %v", err)
	}
	if result.PRNumber != 42 {
		t.Errorf("PR number: want 42, got %d", result.PRNumber)
	}
	if result.PRURL != "https://github.example.com/acme/repo/pull/42" {
		t.Errorf("PR URL unexpected: %s", result.PRURL)
	}
	if result.BranchName != "identrail/fix/finding-1" {
		t.Errorf("branch name unexpected: %s", result.BranchName)
	}
	if result.CommitSHA != "commit-sha-001" {
		t.Errorf("commit SHA unexpected: %s", result.CommitSHA)
	}

	mu.Lock()
	defer mu.Unlock()
	wantSequence := []struct {
		method   string
		pathPart string
	}{
		{http.MethodGet, "/git/ref/heads/main"},
		{http.MethodGet, "/git/commits/base-sha-001"},
		{http.MethodPost, "/git/blobs"},
		{http.MethodPost, "/git/blobs"},
		{http.MethodPost, "/git/trees"},
		{http.MethodPost, "/git/commits"},
		{http.MethodPost, "/git/refs"},
		{http.MethodPost, "/pulls"},
	}
	if len(*recorded) != len(wantSequence) {
		t.Fatalf("expected %d requests, got %d: %+v", len(wantSequence), len(*recorded), *recorded)
	}
	for i, want := range wantSequence {
		got := (*recorded)[i]
		if got.Method != want.method || !strings.Contains(got.Path, want.pathPart) {
			t.Errorf("request %d: want %s %s, got %s %s", i, want.method, want.pathPart, got.Method, got.Path)
		}
		if got.Auth != "Bearer tok-xyz" {
			t.Errorf("request %d: missing/wrong auth header: %s", i, got.Auth)
		}
	}

	// Verify the tree create included both files.
	treeReq := (*recorded)[4]
	entries, ok := treeReq.Body["tree"].([]any)
	if !ok {
		t.Fatalf("tree body missing 'tree' array: %+v", treeReq.Body)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 tree entries, got %d", len(entries))
	}

	// Verify ref creation used refs/heads prefix.
	refReq := (*recorded)[6]
	ref, _ := refReq.Body["ref"].(string)
	if ref != "refs/heads/identrail/fix/finding-1" {
		t.Errorf("unexpected ref: %s", ref)
	}

	// Verify PR creation carried plan metadata.
	prReq := (*recorded)[7]
	if title, _ := prReq.Body["title"].(string); title != plan.PRTitle {
		t.Errorf("PR title: want %s, got %s", plan.PRTitle, title)
	}
	if head, _ := prReq.Body["head"].(string); head != plan.BranchName {
		t.Errorf("PR head: want %s, got %s", plan.BranchName, head)
	}
	if base, _ := prReq.Body["base"].(string); base != plan.BaseBranch {
		t.Errorf("PR base: want %s, got %s", plan.BaseBranch, base)
	}
}

func TestGitHubPublisher_Publish_RejectsMissingInputs(t *testing.T) {
	publisher := GitHubPublisher{APIBaseURL: "http://example.invalid"}
	cases := []struct {
		name  string
		owner string
		repo  string
		token string
		plan  FixPRPlan
	}{
		{"missing_owner", "", "repo", "tok", FixPRPlan{Files: []PlanFile{{Path: "a"}}}},
		{"missing_repo", "acme", "", "tok", FixPRPlan{Files: []PlanFile{{Path: "a"}}}},
		{"missing_token", "acme", "repo", "", FixPRPlan{Files: []PlanFile{{Path: "a"}}}},
		{"empty_files", "acme", "repo", "tok", FixPRPlan{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := publisher.Publish(context.Background(), tc.owner, tc.repo, tc.token, tc.plan)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestGitHubPublisher_Publish_PreservesSlashesInBaseBranchRef(t *testing.T) {
	srv, recorded, mu := newFakeGitHubServer(t)

	plan := FixPRPlan{
		BaseBranch:    "release/2026.05",
		BranchName:    "identrail/fix/finding-2",
		CommitMessage: "identrail: fix",
		PRTitle:       "title",
		PRBody:        "body",
		Files:         []PlanFile{{Path: "x", Content: "y"}},
	}
	publisher := GitHubPublisher{APIBaseURL: srv.URL}
	if _, err := publisher.Publish(context.Background(), "acme", "repo", "tok", plan); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	first := (*recorded)[0]
	want := "/repos/acme/repo/git/ref/heads/release/2026.05"
	if first.Path != want {
		t.Errorf("base ref path: want %s, got %s", want, first.Path)
	}
	if strings.Contains(first.Path, "%2F") {
		t.Errorf("base branch slash was URL-encoded: %s", first.Path)
	}
}

func TestEscapeRefPath_PreservesSlashesEscapesSegments(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"main", "main"},
		{"release/2026.05", "release/2026.05"},
		{"feature/with space", "feature/with%20space"},
		{"a/b/c", "a/b/c"},
	}
	for _, tc := range cases {
		got := escapeRefPath(tc.in)
		if got != tc.want {
			t.Errorf("escapeRefPath(%q): want %q, got %q", tc.in, tc.want, got)
		}
	}
}

func TestGitHubPublisher_Publish_ReturnsErrorOnAPIFailure(t *testing.T) {
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"ref not found"}`, http.StatusNotFound)
	}))
	t.Cleanup(failServer.Close)

	publisher := GitHubPublisher{APIBaseURL: failServer.URL}
	_, err := publisher.Publish(context.Background(), "acme", "repo", "tok", FixPRPlan{
		BaseBranch: "missing",
		BranchName: "identrail/fix/x",
		Files:      []PlanFile{{Path: "x", Content: "y"}},
	})
	if err == nil {
		t.Fatal("expected error from failing GitHub API")
	}
	if !strings.Contains(err.Error(), "read base branch") {
		t.Errorf("expected wrapped error, got: %v", err)
	}
}
