package fixpr

import (
	"errors"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/domain"
)

func repoMisconfigFinding(detector string) domain.Finding {
	return domain.Finding{
		ID:           "repo-finding-1",
		ScanID:       "repo-scan-1",
		Type:         domain.FindingRepoMisconfig,
		Severity:     domain.SeverityHigh,
		Title:        "Repository misconfiguration",
		HumanSummary: "Repository automation grants too much trust.",
		Repository:   "owner/repo",
		Commit:       "abc123",
		FilePath:     ".github/workflows/ci.yml",
		LineNumber:   4,
		Detector:     detector,
	}
}

func TestBuildRepoExposureFixPRPlanModifiesOnlyAffectedWorkflowFile(t *testing.T) {
	finding := repoMisconfigFinding("workflow_write_all_permissions")
	source := "name: ci\non: push\njobs:\n  permissions: write-all\n  build:\n    runs-on: ubuntu-latest\n"

	plan, remediation, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{
		BaseBranch:   "dev",
		BranchPrefix: "identrail/remediate",
		FindingURL:   "https://app.example.com/findings/repo-finding-1",
	})
	if err != nil {
		t.Fatalf("BuildRepoExposureFixPRPlan returned error: %v", err)
	}
	if !remediation.Publishable {
		t.Fatalf("expected publishable remediation, got %+v", remediation)
	}
	if plan.BaseBranch != "dev" {
		t.Fatalf("expected base branch dev, got %s", plan.BaseBranch)
	}
	if plan.BranchName != "identrail/remediate/repo-finding-1" {
		t.Fatalf("unexpected branch name %s", plan.BranchName)
	}
	if len(plan.Files) != 1 {
		t.Fatalf("expected exactly one affected file, got %+v", plan.Files)
	}
	if plan.Files[0].Path != ".github/workflows/ci.yml" {
		t.Fatalf("expected affected workflow path, got %s", plan.Files[0].Path)
	}
	if strings.Contains(plan.Files[0].Path, ".identrail/remediations") {
		t.Fatalf("repo exposure plans must not write advisory files: %+v", plan.Files)
	}
	if !strings.Contains(plan.Files[0].Content, "  permissions:\n    contents: read\n") {
		t.Fatalf("expected indented least-privilege permission replacement, got:\n%s", plan.Files[0].Content)
	}
	for _, required := range []string{
		"Finding ID: `repo-finding-1`",
		"Scan ID: `repo-scan-1`",
		"Detector: `workflow_write_all_permissions`",
		"Validation notes",
		"Safety notes",
		"https://app.example.com/findings/repo-finding-1",
	} {
		if !strings.Contains(plan.PRBody, required) {
			t.Fatalf("PR body missing %q:\n%s", required, plan.PRBody)
		}
	}
}

func TestBuildRepoExposureFixPRPlanAppliesRegexPatch(t *testing.T) {
	finding := repoMisconfigFinding("terraform_public_s3_acl")
	finding.FilePath = "terraform/main.tf"
	finding.LineNumber = 2
	source := "resource \"aws_s3_bucket\" \"public\" {\n  acl = \"public-read-write\"\n}\n"

	plan, _, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{})
	if err != nil {
		t.Fatalf("BuildRepoExposureFixPRPlan returned error: %v", err)
	}
	if !strings.Contains(plan.Files[0].Content, "  acl = \"private\"") {
		t.Fatalf("expected ACL replacement, got:\n%s", plan.Files[0].Content)
	}
	if strings.Contains(plan.Files[0].Content, "public-read") {
		t.Fatalf("public ACL still present:\n%s", plan.Files[0].Content)
	}
}

func TestBuildRepoExposureFixPRPlanAppliesRegexPatchWithInlineComment(t *testing.T) {
	finding := repoMisconfigFinding("terraform_public_s3_acl")
	finding.FilePath = "terraform/main.tf"
	finding.LineNumber = 2
	source := "resource \"aws_s3_bucket\" \"public\" {\n  acl = \"public-read\" # temporary exception\n}\n"

	plan, _, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{})
	if err != nil {
		t.Fatalf("BuildRepoExposureFixPRPlan returned error: %v", err)
	}
	if !strings.Contains(plan.Files[0].Content, "  acl = \"private\" # temporary exception") {
		t.Fatalf("expected ACL replacement to preserve inline comment, got:\n%s", plan.Files[0].Content)
	}
	if strings.Contains(plan.Files[0].Content, "public-read") {
		t.Fatalf("public ACL still present:\n%s", plan.Files[0].Content)
	}
}

func TestBuildRepoExposureFixPRPlanAppliesLiteralPatchWithInlineComment(t *testing.T) {
	finding := repoMisconfigFinding("k8s_privileged_true")
	finding.FilePath = "deploy/app.yaml"
	finding.LineNumber = 2
	source := "securityContext:\n  privileged: true # legacy exception\n"

	plan, _, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{})
	if err != nil {
		t.Fatalf("BuildRepoExposureFixPRPlan returned error: %v", err)
	}
	if !strings.Contains(plan.Files[0].Content, "  privileged: false # legacy exception") {
		t.Fatalf("expected literal replacement to preserve inline comment, got:\n%s", plan.Files[0].Content)
	}
	if strings.Contains(plan.Files[0].Content, "privileged: true") {
		t.Fatalf("privileged container flag still present:\n%s", plan.Files[0].Content)
	}
}

func TestBuildRepoExposureFixPRPlanPatchesOnlyFindingLineWhenRepeated(t *testing.T) {
	finding := repoMisconfigFinding("workflow_write_all_permissions")
	finding.LineNumber = 3
	source := "permissions: write-all\njobs:\n  permissions: write-all\n"

	plan, _, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{})
	if err != nil {
		t.Fatalf("BuildRepoExposureFixPRPlan returned error: %v", err)
	}
	if !strings.Contains(plan.Files[0].Content, "permissions: write-all\njobs:\n  permissions:\n    contents: read\n") {
		t.Fatalf("expected only the finding line to be patched, got:\n%s", plan.Files[0].Content)
	}
}

func TestBuildRepoExposureFixPRPlanPatchesMappedWriteAllPermissions(t *testing.T) {
	cases := []struct {
		name       string
		lineNumber int
		source     string
		want       string
	}{
		{
			name:       "block_mapping",
			lineNumber: 2,
			source:     "name: ci\npermissions:\n  contents: write-all\n  issues: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
			want:       "name: ci\npermissions:\n  contents: read\n  issues: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
		},
		{
			name:       "block_child_line",
			lineNumber: 3,
			source:     "name: ci\npermissions:\n  contents: write-all\n  packages: read\n",
			want:       "name: ci\npermissions:\n  contents: read\n  packages: read\n",
		},
		{
			name:       "flow_mapping",
			lineNumber: 2,
			source:     "name: ci\npermissions: { contents: write-all, issues: read }\n",
			want:       "name: ci\npermissions: { contents: read, issues: read }\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding := repoMisconfigFinding("workflow_write_all_permissions")
			finding.LineNumber = tc.lineNumber

			plan, _, err := BuildRepoExposureFixPRPlan(finding, tc.source, PlanOptions{})
			if err != nil {
				t.Fatalf("BuildRepoExposureFixPRPlan returned error: %v", err)
			}
			if plan.Files[0].Content != tc.want {
				t.Fatalf("unexpected patched content:\nwant:\n%s\ngot:\n%s", tc.want, plan.Files[0].Content)
			}
		})
	}
}

func TestBuildRepoExposureFixPRPlanDoesNotFallbackWhenFindingLineMismatches(t *testing.T) {
	finding := repoMisconfigFinding("workflow_write_all_permissions")
	finding.LineNumber = 3
	source := "permissions: write-all\njobs:\n  permissions: read-all\n"

	_, _, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{})
	if !errors.Is(err, ErrRepoExposurePatchApplyFailed) {
		t.Fatalf("expected patch apply failure instead of global fallback, got %v", err)
	}
}

func TestBuildRepoExposureFixPRPlanRejectsCaseChangedLiteralMatch(t *testing.T) {
	finding := repoMisconfigFinding("workflow_write_all_permissions")
	finding.LineNumber = 1
	source := "Permissions: write-all\n"

	_, _, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{})
	if !errors.Is(err, ErrRepoExposurePatchApplyFailed) {
		t.Fatalf("expected case-sensitive literal mismatch to fail, got %v", err)
	}
}

func TestBuildRepoExposureFixPRPlanRejectsMissingFindingLine(t *testing.T) {
	finding := repoMisconfigFinding("workflow_write_all_permissions")
	finding.LineNumber = 0
	source := "permissions: write-all\njobs:\n  permissions: write-all\n"

	_, _, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{})
	if !errors.Is(err, ErrRepoExposurePatchApplyFailed) {
		t.Fatalf("expected missing finding line to fail instead of first-match patching, got %v", err)
	}
}

func TestBuildRepoExposureFixPRPlanPatchesPullRequestTargetSyntaxes(t *testing.T) {
	cases := []struct {
		name       string
		lineNumber int
		source     string
		want       string
	}{
		{
			name:       "mapping_key",
			lineNumber: 3,
			source:     "name: ci\non:\n  pull_request_target:\n    branches: [main]\n",
			want:       "name: ci\non:\n  pull_request:\n    branches: [main]\n",
		},
		{
			name:       "double_quoted_mapping_key",
			lineNumber: 3,
			source:     "name: ci\non:\n  \"pull_request_target\":\n    branches: [main]\n",
			want:       "name: ci\non:\n  pull_request:\n    branches: [main]\n",
		},
		{
			name:       "single_quoted_mapping_key",
			lineNumber: 3,
			source:     "name: ci\non:\n  'pull_request_target':\n    branches: [main]\n",
			want:       "name: ci\non:\n  pull_request:\n    branches: [main]\n",
		},
		{
			name:       "scalar",
			lineNumber: 2,
			source:     "name: ci\non: pull_request_target\n",
			want:       "name: ci\non: pull_request\n",
		},
		{
			name:       "quoted_scalar",
			lineNumber: 2,
			source:     "name: ci\non: \"pull_request_target\"\n",
			want:       "name: ci\non: pull_request\n",
		},
		{
			name:       "flow_sequence",
			lineNumber: 2,
			source:     "name: ci\non: [push, pull_request_target]\n",
			want:       "name: ci\non: [push, pull_request]\n",
		},
		{
			name:       "block_sequence_from_parent_line",
			lineNumber: 2,
			source:     "name: ci\non:\n  - push\n  - pull_request_target\n",
			want:       "name: ci\non:\n  - push\n  - pull_request\n",
		},
		{
			name:       "quoted_block_sequence_from_parent_line",
			lineNumber: 2,
			source:     "name: ci\non:\n  - push\n  - \"pull_request_target\"\n",
			want:       "name: ci\non:\n  - push\n  - pull_request\n",
		},
		{
			name:       "block_sequence_from_first_item_line",
			lineNumber: 3,
			source:     "name: ci\non:\n  - push\n  - pull_request_target\n",
			want:       "name: ci\non:\n  - push\n  - pull_request\n",
		},
		{
			name:       "block_mapping_from_parent_line_skips_comment_and_filter_value",
			lineNumber: 2,
			source:     "name: ci\non:\n  # pull_request_target legacy path\n  pull_request:\n    branches: [pull_request_target]\n  pull_request_target:\n    branches: [main]\n",
			want:       "name: ci\non:\n  # pull_request_target legacy path\n  pull_request:\n    branches: [pull_request_target]\n",
		},
		{
			name:       "block_mapping_from_target_line_removes_duplicate_replacement_trigger",
			lineNumber: 5,
			source:     "name: ci\non:\n  pull_request:\n    branches: [main]\n  pull_request_target:\n    branches: [release]\n",
			want:       "name: ci\non:\n  pull_request:\n    branches: [main]\n",
		},
		{
			name:       "block_mapping_removes_target_when_replacement_trigger_appears_later",
			lineNumber: 2,
			source:     "name: ci\non:\n  pull_request_target:\n    branches: [release]\n  pull_request:\n    branches: [main]\n",
			want:       "name: ci\non:\n  pull_request:\n    branches: [main]\n",
		},
		{
			name:       "block_sequence_from_parent_line_removes_duplicate_replacement_trigger",
			lineNumber: 2,
			source:     "name: ci\non:\n  - pull_request\n  - pull_request_target\n",
			want:       "name: ci\non:\n  - pull_request\n",
		},
		{
			name:       "block_mapping_from_parent_line_skips_nested_input_key",
			lineNumber: 2,
			source:     "name: ci\non:\n  workflow_dispatch:\n    inputs:\n      pull_request_target:\n        description: target branch\n  pull_request_target:\n    branches: [main]\n",
			want:       "name: ci\non:\n  workflow_dispatch:\n    inputs:\n      pull_request_target:\n        description: target branch\n  pull_request:\n    branches: [main]\n",
		},
		{
			name:       "block_sequence_from_parent_line_skips_comment",
			lineNumber: 2,
			source:     "name: ci\non:\n  # pull_request_target legacy path\n  - pull_request_target\n",
			want:       "name: ci\non:\n  # pull_request_target legacy path\n  - pull_request\n",
		},
		{
			name:       "flow_mapping_only_patches_top_level_trigger_key",
			lineNumber: 2,
			source:     "name: ci\non: { pull_request: { branches: [pull_request_target] }, pull_request_target: { branches: [main] } }\n",
			want:       "name: ci\non: { pull_request: { branches: [pull_request_target] }, pull_request: { branches: [main] } }\n",
		},
		{
			name:       "flow_mapping_patches_double_quoted_top_level_trigger_key",
			lineNumber: 2,
			source:     "name: ci\non: { pull_request: { branches: [pull_request_target] }, \"pull_request_target\": { branches: [main] } }\n",
			want:       "name: ci\non: { pull_request: { branches: [pull_request_target] }, pull_request: { branches: [main] } }\n",
		},
		{
			name:       "flow_mapping_patches_single_quoted_top_level_trigger_key",
			lineNumber: 2,
			source:     "name: ci\non: { pull_request: { branches: [pull_request_target] }, 'pull_request_target': { branches: [main] } }\n",
			want:       "name: ci\non: { pull_request: { branches: [pull_request_target] }, pull_request: { branches: [main] } }\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding := repoMisconfigFinding("workflow_pull_request_target")
			finding.LineNumber = tc.lineNumber

			plan, _, err := BuildRepoExposureFixPRPlan(finding, tc.source, PlanOptions{})
			if err != nil {
				t.Fatalf("BuildRepoExposureFixPRPlan returned error: %v", err)
			}
			if plan.Files[0].Content != tc.want {
				t.Fatalf("unexpected patched content:\nwant:\n%s\ngot:\n%s", tc.want, plan.Files[0].Content)
			}
		})
	}
}

func TestBuildRepoExposureFixPRPlanRejectsNestedPullRequestTargetFallback(t *testing.T) {
	finding := repoMisconfigFinding("workflow_pull_request_target")
	finding.LineNumber = 2
	source := "name: ci\non:\n  workflow_dispatch:\n    inputs:\n      pull_request_target:\n        description: target branch\n"

	_, _, err := BuildRepoExposureFixPRPlan(finding, source, PlanOptions{})
	if !errors.Is(err, ErrRepoExposurePatchApplyFailed) {
		t.Fatalf("expected nested trigger fallback to fail, got %v", err)
	}
}

func TestBuildRepoExposureFixPRPlanRejectsSecretFindings(t *testing.T) {
	_, remediation, err := BuildRepoExposureFixPRPlan(domain.Finding{
		ID:         "secret-1",
		Type:       domain.FindingSecretExposure,
		Detector:   "github_token",
		FilePath:   "app.env",
		LineNumber: 1,
	}, "GITHUB_TOKEN=ghp_example\n", PlanOptions{})
	if !errors.Is(err, ErrRepoExposureRemediationUnsafe) {
		t.Fatalf("expected unsafe remediation error, got %v", err)
	}
	if !remediation.SecretRotation || remediation.Patch != nil {
		t.Fatalf("expected rotation-only remediation, got %+v", remediation)
	}
}

func TestBuildRepoExposureFixPRPlanRejectsPlaceholderPatches(t *testing.T) {
	finding := repoMisconfigFinding("docker_latest_tag")
	finding.FilePath = "Dockerfile"
	finding.LineNumber = 1
	_, remediation, err := BuildRepoExposureFixPRPlan(finding, "FROM golang:latest\n", PlanOptions{})
	if !errors.Is(err, ErrRepoExposureRemediationUnsafe) {
		t.Fatalf("expected unsafe remediation error, got %v", err)
	}
	if remediation.Patch == nil || !remediation.Patch.Placeholder {
		t.Fatalf("expected placeholder remediation patch, got %+v", remediation.Patch)
	}
	if remediation.PublishBlockedReason == "" {
		t.Fatal("expected publish blocked reason")
	}
}

func TestBuildRepoExposureFixPRPlanRejectsStaleSourceContent(t *testing.T) {
	finding := repoMisconfigFinding("k8s_privileged_true")
	finding.FilePath = "deploy/app.yaml"
	finding.LineNumber = 3
	_, _, err := BuildRepoExposureFixPRPlan(finding, "securityContext:\n  allowPrivilegeEscalation: false\n", PlanOptions{})
	if !errors.Is(err, ErrRepoExposurePatchApplyFailed) {
		t.Fatalf("expected patch apply failure, got %v", err)
	}
}

func TestBuildRepoExposureFixPRPlanRejectsUnsafeTargetPath(t *testing.T) {
	for _, filePath := range []string{
		"../outside.yaml",
		"..",
		"deploy/../outside.yaml",
		"deploy/..",
		"/etc/app.yaml",
		"/deploy/app.yaml",
		"C:/tmp/app.yaml",
		"c:/tmp/app.yaml",
		`..\outside.yaml`,
		`deploy\..\outside.yaml`,
		`deploy\..`,
		`C:\tmp\app.yaml`,
		`\absolute.yaml`,
	} {
		t.Run(filePath, func(t *testing.T) {
			finding := repoMisconfigFinding("k8s_privileged_true")
			finding.FilePath = filePath
			_, _, err := BuildRepoExposureFixPRPlan(finding, "privileged: true\n", PlanOptions{})
			if !errors.Is(err, ErrRepoExposurePatchApplyFailed) {
				t.Fatalf("expected path validation failure, got %v", err)
			}
		})
	}
}

func TestBuildRepoExposureFixPRPlanRejectsUnsafeFallbackPath(t *testing.T) {
	finding := repoMisconfigFinding("k8s_privileged_true")
	finding.FilePath = ""
	finding.Path = []string{"/etc/app.yaml"}

	_, _, err := BuildRepoExposureFixPRPlan(finding, "privileged: true\n", PlanOptions{})
	if !errors.Is(err, ErrRepoExposurePatchApplyFailed) {
		t.Fatalf("expected fallback path validation failure, got %v", err)
	}
}
