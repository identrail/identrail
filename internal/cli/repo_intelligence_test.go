package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/config"
	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/findings/standards"
	"github.com/identrail/identrail/internal/remediation/fixpr"
)

func TestExecuteRepoScanQueueCallsAPI(t *testing.T) {
	cfg := config.Config{DefaultTenantID: "tenant-a", DefaultWorkspaceID: "workspace-a"}
	startedAt := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/v1/repo-scans" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		assertRepoIntelligenceHeaders(t, r)
		var request api.RepoScanRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode queue request: %v", err)
		}
		if request.Repository != "identrail/identrail" || request.ProjectID != "project-1" || request.ConnectorID != "github-app" {
			t.Fatalf("unexpected queue request: %+v", request)
		}
		if request.ScanMode != "delta" || request.HeadRevision != "abc123" || len(request.ChangedPaths) != 1 || request.ChangedPaths[0] != ".github/workflows/ci.yml" {
			t.Fatalf("unexpected delta request metadata: %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(repoScanCLIResponse{
			RepoScan: db.RepoScanRecord{
				ID:         "11111111-1111-1111-1111-111111111111",
				Repository: "identrail/identrail",
				Status:     "queued",
				StartedAt:  startedAt,
				ScanMode:   "delta",
			},
		})
	}))
	defer server.Close()

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"repo-scan", "queue",
		"--api-url", server.URL,
		"--api-key", "admin-key",
		"--tenant-id", "tenant-a",
		"--workspace-id", "workspace-a",
		"--timeout", "0",
		"--repo", "identrail/identrail",
		"--project-id", "project-1",
		"--connector-id", "github-app",
		"--scan-mode", "delta",
		"--head-revision", "abc123",
		"--changed-path", ".github/workflows/ci.yml",
		"--history-limit", "50",
		"--max-findings", "20",
	}, &out)
	if err != nil {
		t.Fatalf("repo scan queue failed: %v", err)
	}
	if !strings.Contains(out.String(), "Repo scan queued: id=11111111-1111-1111-1111-111111111111 repo=identrail/identrail status=queued mode=delta") {
		t.Fatalf("unexpected queue output: %q", out.String())
	}
}

func TestNormalizeCLIAPITimeoutFallsBackForNonPositiveValues(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		if got := normalizeCLIAPITimeout(timeout); got != defaultCLIAPITimeout {
			t.Fatalf("expected default timeout for %s, got %s", timeout, got)
		}
	}
	if got := normalizeCLIAPITimeout(3 * time.Second); got != 3*time.Second {
		t.Fatalf("expected explicit timeout, got %s", got)
	}
}

func TestExecuteRepoScanListShowAndCancel(t *testing.T) {
	cfg := config.Config{DefaultTenantID: "tenant-a", DefaultWorkspaceID: "workspace-a"}
	startedAt := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	scan := db.RepoScanRecord{
		ID:             "22222222-2222-2222-2222-222222222222",
		Repository:     "identrail/identrail",
		Status:         "running",
		StartedAt:      startedAt,
		CommitsScanned: 5,
		FilesScanned:   7,
		FindingCount:   2,
		ScanMode:       "deep",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertRepoIntelligenceHeaders(t, r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/repo-scans":
			if r.URL.Query().Get("limit") != "2" {
				t.Fatalf("expected limit query, got %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(repoScanPageCLIResponse{Items: []db.RepoScanRecord{scan}, NextCursor: "2"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/repo-scans/"+scan.ID:
			_ = json.NewEncoder(w).Encode(scan)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/repo-scans/"+scan.ID+"/cancel":
			scan.Status = "failed"
			_ = json.NewEncoder(w).Encode(repoScanCLIResponse{RepoScan: scan})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "list", args: []string{"repo-scan", "list", "--api-url", server.URL, "--api-key", "admin-key", "--tenant-id", "tenant-a", "--workspace-id", "workspace-a", "--limit", "2"}, want: "Repo scans: 1"},
		{name: "show", args: []string{"repo-scan", "show", scan.ID, "--api-url", server.URL, "--api-key", "admin-key", "--tenant-id", "tenant-a", "--workspace-id", "workspace-a"}, want: scan.ID},
		{name: "cancel", args: []string{"repo-scan", "cancel", scan.ID, "--api-url", server.URL, "--api-key", "admin-key", "--tenant-id", "tenant-a", "--workspace-id", "workspace-a"}, want: "Repo scan canceled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := Execute(cfg, tc.args, &out); err != nil {
				t.Fatalf("%s failed: %v", tc.name, err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("expected %q in output, got %q", tc.want, out.String())
			}
		})
	}
}

func TestExecuteRepoFindingsAndRiskGraphCommands(t *testing.T) {
	cfg := config.Config{DefaultTenantID: "tenant-a", DefaultWorkspaceID: "workspace-a"}
	now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	finding := domain.Finding{
		ID:              "finding-1",
		ScanID:          "33333333-3333-3333-3333-333333333333",
		Type:            domain.FindingRepoMisconfig,
		Severity:        domain.SeverityHigh,
		ConfidenceScore: 0.91,
		Title:           "Workflow token can write broadly",
		HumanSummary:    "The workflow grants broad write permissions.",
		Repository:      "identrail/identrail",
		FilePath:        ".github/workflows/ci.yml",
		LineNumber:      9,
		Detector:        "workflow_broad_token_permissions",
		LifecycleStatus: domain.RepoFindingLifecycleOpen,
		Owner:           "platform",
		CreatedAt:       now,
	}
	graph := domain.RepoRiskGraph{
		Repository: "identrail/identrail",
		Summary: domain.RepoRiskGraphSummary{
			FindingCount:     1,
			NodeCount:        2,
			EdgeCount:        1,
			HighRiskFindings: 1,
		},
		Scores: []domain.RepoRiskGraphFindingScore{{
			FindingID:  finding.ID,
			Score:      88,
			Severity:   domain.SeverityHigh,
			Confidence: 0.91,
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertRepoIntelligenceHeaders(t, r)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/repo-findings":
			if r.URL.Query().Get("repository") != "identrail/identrail" || r.URL.Query().Get("repo_lifecycle_status") != "open" {
				t.Fatalf("unexpected findings query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(repoFindingPageCLIResponse{
				Items: []domain.Finding{finding},
				Summary: &api.RepoFindingsSummary{
					TotalOpen:  1,
					ByOwner:    map[string]int{"platform": 1},
					ByDetector: map[string]int{"workflow_broad_token_permissions": 1},
					BySeverity: map[string]int{"high": 1},
				},
			})
		case "/v1/repo-risk-graph":
			if r.URL.Query().Get("repository") != "identrail/identrail" {
				t.Fatalf("unexpected graph query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(graph)
		default:
			t.Fatalf("unexpected request %s", r.URL.String())
		}
	}))
	defer server.Close()

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "findings", args: []string{"repo-findings", "list", "--api-url", server.URL, "--api-key", "admin-key", "--tenant-id", "tenant-a", "--workspace-id", "workspace-a", "--repo", "identrail/identrail", "--status", "open"}, want: "Workflow token can write broadly"},
		{name: "graph", args: []string{"repo-risk-graph", "--api-url", server.URL, "--api-key", "admin-key", "--tenant-id", "tenant-a", "--workspace-id", "workspace-a", "--repo", "identrail/identrail"}, want: "Repo risk graph: repo=identrail/identrail findings=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := Execute(cfg, tc.args, &out); err != nil {
				t.Fatalf("%s failed: %v", tc.name, err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("expected %q in output, got %q", tc.want, out.String())
			}
		})
	}
}

func TestExecuteRepoPostureAndRemediationCommands(t *testing.T) {
	cfg := config.Config{DefaultTenantID: "tenant-a", DefaultWorkspaceID: "workspace-a"}
	now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertRepoIntelligenceHeaders(t, r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/connectors/github/github-app/posture":
			if r.URL.Query().Get("workspace_id") != "workspace-a" || r.URL.Query().Get("project_id") != "project-1" || r.URL.Query().Get("repository") != "identrail/identrail" {
				t.Fatalf("unexpected posture query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(api.GitHubRepositoryPostureResponse{
				ConnectorID: "github-app",
				Provider:    "github_app",
				Posture: githubconnector.RepositoryPosture{
					Repository:  "identrail/identrail",
					CollectedAt: now,
					Checks: []githubconnector.RepositoryPostureCheck{{
						ID:       "branch_protection",
						Category: "default_branch",
						State:    githubconnector.RepositoryPostureStateInsecure,
						Summary:  "Default branch protection is missing required reviews.",
						Reason:   "required pull request reviews are disabled",
					}},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/repo-findings/finding-1/remediation/preview":
			if r.URL.Query().Get("repo_scan_id") != "33333333-3333-3333-3333-333333333333" {
				t.Fatalf("unexpected remediation query: %s", r.URL.RawQuery)
			}
			var request api.RepoFindingRemediationPreviewRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode remediation request: %v", err)
			}
			if request.BaseBranch != "dev" || !request.RequireFixPlan {
				t.Fatalf("unexpected remediation request: %+v", request)
			}
			_ = json.NewEncoder(w).Encode(api.RepoFindingRemediationPreview{
				Finding: domain.Finding{
					ID:        "finding-1",
					Type:      domain.FindingRepoMisconfig,
					Severity:  domain.SeverityHigh,
					Title:     "Workflow token can write broadly",
					CreatedAt: now,
				},
				Remediation: standards.RepoExposureRemediation{
					Detector:    "workflow_write_all_permissions",
					RiskSummary: "Workflow token permissions are too broad.",
					Steps:       []string{"Set workflow permissions to read by default."},
					SafetyNotes: []string{"Review deploy jobs before applying."},
					Publishable: true,
				},
				FixPRPlan: &fixpr.FixPRPlan{
					BaseBranch: "dev",
					BranchName: "identrail/fix/finding-1",
					PRTitle:    "Harden workflow permissions",
					Files:      []fixpr.PlanFile{{Path: ".github/workflows/ci.yml", Content: "permissions: read-all\n"}},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/repo-findings/finding-1/remediation/publish":
			if r.URL.Query().Get("repo_scan_id") != "33333333-3333-3333-3333-333333333333" {
				t.Fatalf("unexpected publish query: %s", r.URL.RawQuery)
			}
			var request api.RepoFindingRemediationPublishRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode publish request: %v", err)
			}
			if request.BaseBranch != "dev" || !request.OperatorApproved || !request.WritePermissionsConfigured || request.GitHubToken != "ghs_write_token" {
				t.Fatalf("unexpected publish request: %+v", request)
			}
			_ = json.NewEncoder(w).Encode(api.RepoFindingRemediationPublishResponse{
				Finding: domain.Finding{
					ID:        "finding-1",
					Type:      domain.FindingRepoMisconfig,
					Severity:  domain.SeverityHigh,
					Title:     "Workflow token can write broadly",
					CreatedAt: now,
				},
				Remediation: standards.RepoExposureRemediation{Detector: "workflow_write_all_permissions"},
				Publish: fixpr.PublishResult{
					PRNumber:   42,
					PRURL:      "https://github.com/identrail/identrail/pull/42",
					BranchName: "identrail/fix/finding-1",
					CommitSHA:  "abc123",
				},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "posture", args: []string{"repo-posture", "--api-url", server.URL, "--api-key", "admin-key", "--tenant-id", "tenant-a", "--workspace-id", "workspace-a", "--connector-id", "github-app", "--project-id", "project-1", "--repo", "identrail/identrail"}, want: "GitHub posture: repo=identrail/identrail connector=github-app"},
		{name: "remediation", args: []string{"repo-remediation", "preview", "finding-1", "--api-url", server.URL, "--api-key", "admin-key", "--tenant-id", "tenant-a", "--workspace-id", "workspace-a", "--repo-scan-id", "33333333-3333-3333-3333-333333333333", "--base-branch", "dev", "--require-fix-plan"}, want: "Fix PR plan: branch=identrail/fix/finding-1 base=dev files=1"},
		{name: "publish", args: []string{"repo-remediation", "publish", "finding-1", "--api-url", server.URL, "--api-key", "admin-key", "--tenant-id", "tenant-a", "--workspace-id", "workspace-a", "--repo-scan-id", "33333333-3333-3333-3333-333333333333", "--base-branch", "dev", "--source-content", "name: ci\npermissions: write-all\n", "--github-token", "ghs_write_token", "--approve", "--write-permissions-configured"}, want: "Repo remediation published: finding=finding-1 detector=workflow_write_all_permissions pr=42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := Execute(cfg, tc.args, &out); err != nil {
				t.Fatalf("%s failed: %v", tc.name, err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("expected %q in output, got %q", tc.want, out.String())
			}
		})
	}
}

func assertRepoIntelligenceHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	if got := strings.TrimSpace(r.Header.Get("X-API-Key")); got != "admin-key" {
		t.Fatalf("expected api key header, got %q", got)
	}
	if got := strings.TrimSpace(r.Header.Get("X-Identrail-Tenant-ID")); got != "tenant-a" {
		t.Fatalf("expected tenant header, got %q", got)
	}
	if got := strings.TrimSpace(r.Header.Get("X-Identrail-Workspace-ID")); got != "workspace-a" {
		t.Fatalf("expected workspace header, got %q", got)
	}
}
