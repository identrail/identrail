package fixpr

import (
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/findings/standards"
)

func sampleFinding() domain.Finding {
	return domain.Finding{
		ID:           "finding-abc-123",
		ScanID:       "scan-42",
		Type:         domain.FindingOverPrivileged,
		Severity:     domain.SeverityHigh,
		Title:        "Overprivileged role: WorkerRole",
		HumanSummary: "This role has wildcard permissions on multiple services.",
		Path:         []string{"aws:iam::123456789012:role/WorkerRole"},
	}
}

func TestBuildPlan_ProducesDeterministicFields(t *testing.T) {
	template, ok := standards.SuggestPatch(sampleFinding())
	if !ok {
		t.Fatal("expected patch for sample finding")
	}
	plan, err := BuildPlan(sampleFinding(), template, PlanOptions{
		BaseBranch: "main",
		FindingURL: "https://app.example.com/findings/finding-abc-123",
	})
	if err != nil {
		t.Fatalf("BuildPlan returned error: %v", err)
	}

	if plan.BaseBranch != "main" {
		t.Errorf("BaseBranch: want main, got %s", plan.BaseBranch)
	}
	if plan.BranchName != "identrail/fix/finding-abc-123" {
		t.Errorf("BranchName: want identrail/fix/finding-abc-123, got %s", plan.BranchName)
	}
	if plan.FindingID != "finding-abc-123" {
		t.Errorf("FindingID: want finding-abc-123, got %s", plan.FindingID)
	}
	if !strings.Contains(plan.PRTitle, "identrail") {
		t.Errorf("PRTitle missing identrail prefix: %s", plan.PRTitle)
	}
	if !strings.Contains(plan.PRBody, "finding-abc-123") {
		t.Errorf("PRBody missing finding ID traceability")
	}
	if !strings.Contains(plan.PRBody, "scan-42") {
		t.Errorf("PRBody missing scan ID traceability")
	}
	if !strings.Contains(plan.PRBody, "https://app.example.com/findings/finding-abc-123") {
		t.Errorf("PRBody missing finding URL")
	}
	if !strings.Contains(plan.CommitMessage, "finding-abc-123") {
		t.Errorf("CommitMessage missing finding ID")
	}
}

func TestBuildPlan_DeterministicAcrossCalls(t *testing.T) {
	template, _ := standards.SuggestPatch(sampleFinding())
	opts := PlanOptions{BaseBranch: "main"}
	first, err := BuildPlan(sampleFinding(), template, opts)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	second, err := BuildPlan(sampleFinding(), template, opts)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if first.BranchName != second.BranchName {
		t.Errorf("branch name not deterministic: %q vs %q", first.BranchName, second.BranchName)
	}
	if first.CommitMessage != second.CommitMessage {
		t.Errorf("commit message not deterministic")
	}
	if first.PRBody != second.PRBody {
		t.Errorf("PR body not deterministic")
	}
	if len(first.Files) != len(second.Files) {
		t.Fatalf("file count differs: %d vs %d", len(first.Files), len(second.Files))
	}
	for i := range first.Files {
		if first.Files[i].Path != second.Files[i].Path || first.Files[i].Content != second.Files[i].Content {
			t.Errorf("file %d differs between calls", i)
		}
	}
}

func TestBuildPlan_WritesPatchFileWithCorrectExtension(t *testing.T) {
	cases := []struct {
		name     string
		finding  domain.Finding
		wantExt  string
		mustHave string
	}{
		{
			name:     "aws_json_template",
			finding:  domain.Finding{ID: "f1", Type: domain.FindingOverPrivileged, Path: []string{"aws:iam::1:role/X"}},
			wantExt:  ".json",
			mustHave: "Version",
		},
		{
			name:     "k8s_yaml_template",
			finding:  domain.Finding{ID: "f2", Type: domain.FindingOverPrivileged, Path: []string{"k8s:sa:ns/n"}},
			wantExt:  ".yaml",
			mustHave: "apiVersion",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			template, _ := standards.SuggestPatch(tc.finding)
			plan, err := BuildPlan(tc.finding, template, PlanOptions{})
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			foundPatch := false
			for _, f := range plan.Files {
				if strings.HasSuffix(f.Path, "patch"+tc.wantExt) {
					foundPatch = true
					if !strings.Contains(f.Content, tc.mustHave) {
						t.Errorf("patch %s missing expected content %q", f.Path, tc.mustHave)
					}
				}
			}
			if !foundPatch {
				paths := []string{}
				for _, f := range plan.Files {
					paths = append(paths, f.Path)
				}
				t.Errorf("expected file ending in patch%s, got: %v", tc.wantExt, paths)
			}
		})
	}
}

func TestBuildPlan_AlwaysWritesReadme(t *testing.T) {
	template, _ := standards.SuggestPatch(sampleFinding())
	plan, err := BuildPlan(sampleFinding(), template, PlanOptions{})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	foundReadme := false
	for _, f := range plan.Files {
		if strings.HasSuffix(f.Path, "/README.md") {
			foundReadme = true
			if !strings.Contains(f.Content, "finding-abc-123") {
				t.Errorf("README missing finding id")
			}
			if !strings.Contains(f.Content, "preview-only") {
				t.Errorf("README missing preview-only disclaimer")
			}
		}
	}
	if !foundReadme {
		t.Error("expected README.md in plan files")
	}
}

func TestBuildPlan_BranchSlugIsSafe(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"finding/abc:123", "identrail/fix/finding-abc-123"},
		{"  FINDING-X  ", "identrail/fix/finding-x"},
		{"ARN:aws:iam::1:role/My Role", "identrail/fix/arn-aws-iam-1-role-my-role"},
		// git-check-ref-format rejects refs starting with "." or containing "..".
		{".hidden-finding", "identrail/fix/hidden-finding"},
		{"..relative", "identrail/fix/relative"},
		{"finding..with..dots", "identrail/fix/finding-with-dots"},
		{"trailing-dot.", "identrail/fix/trailing-dot"},
		{"finding.lock", "identrail/fix/finding-lock"},
		{"...", "identrail/fix/finding"},
	}
	template := standards.PatchTemplate{Summary: "test"}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			finding := domain.Finding{ID: tc.id, Type: domain.FindingOverPrivileged}
			plan, err := BuildPlan(finding, template, PlanOptions{})
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			if plan.BranchName != tc.want {
				t.Errorf("branch: want %s, got %s", tc.want, plan.BranchName)
			}
		})
	}
}

func TestBuildPlan_RejectsMissingFindingID(t *testing.T) {
	_, err := BuildPlan(domain.Finding{}, standards.PatchTemplate{Summary: "x"}, PlanOptions{})
	if err == nil {
		t.Error("expected error for missing finding id")
	}
}

func TestBuildPlan_RejectsEmptyTemplate(t *testing.T) {
	_, err := BuildPlan(domain.Finding{ID: "f1"}, standards.PatchTemplate{}, PlanOptions{})
	if err == nil {
		t.Error("expected error for empty template summary")
	}
}

func TestBuildPlan_DefaultsBaseBranch(t *testing.T) {
	template, _ := standards.SuggestPatch(sampleFinding())
	plan, _ := BuildPlan(sampleFinding(), template, PlanOptions{})
	if plan.BaseBranch != "main" {
		t.Errorf("expected default base main, got %s", plan.BaseBranch)
	}
}

func TestBuildPlan_CustomBranchPrefix(t *testing.T) {
	template, _ := standards.SuggestPatch(sampleFinding())
	plan, _ := BuildPlan(sampleFinding(), template, PlanOptions{BranchPrefix: "bots/identrail"})
	if !strings.HasPrefix(plan.BranchName, "bots/identrail/") {
		t.Errorf("expected custom prefix, got %s", plan.BranchName)
	}
}

func TestBuildPlan_NoTemplateBodyStillProducesPlan(t *testing.T) {
	finding := domain.Finding{ID: "f-stale", Type: domain.FindingStaleIdentity}
	template, _ := standards.SuggestPatch(finding)
	if template.Template != "" {
		t.Fatalf("expected stale identity template to be empty for this assertion")
	}
	plan, err := BuildPlan(finding, template, PlanOptions{})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for _, f := range plan.Files {
		if strings.HasSuffix(f.Path, "/README.md") {
			return
		}
	}
	t.Error("expected README.md even when patch template body is empty")
}
