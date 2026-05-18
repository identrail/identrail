package repoexposure

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

const testSecretValue = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"

func testGitHubToken() string {
	return strings.Join([]string{"ghp", "_0123456789abcdef0123456789abcdef0123"}, "")
}

func TestScanRepositoryDetectsSecretInCommitHistory(t *testing.T) {
	repoPath, firstCommit := initTestRepoWithHistorySecret(t)

	scanner := NewScanner(nil,
		WithHistoryLimit(100),
		WithMaxFindings(50),
		WithNow(func() time.Time { return time.Date(2026, 3, 17, 13, 0, 0, 0, time.UTC) }),
	)

	result, err := scanner.ScanRepository(context.Background(), repoPath)
	if err != nil {
		t.Fatalf("scan repository failed: %v", err)
	}
	if result.CommitsScanned < 2 {
		t.Fatalf("expected at least 2 commits scanned, got %d", result.CommitsScanned)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}

	var secretFinding domain.Finding
	found := false
	for _, finding := range result.Findings {
		if finding.Type == domain.FindingSecretExposure {
			secretFinding = finding
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected secret exposure finding, got %+v", result.Findings)
	}

	evidence := secretFinding.Evidence
	if got := evidence["commit"]; got != firstCommit {
		t.Fatalf("expected first commit %q, got %v", firstCommit, got)
	}
	if secretFinding.Commit != firstCommit || secretFinding.FilePath == "" || secretFinding.LineNumber == 0 || secretFinding.Detector == "" {
		t.Fatalf("expected structured repo metadata, got %+v", secretFinding)
	}
	redacted, _ := evidence["redacted_line_snip"].(string)
	if strings.Contains(redacted, testSecretValue) {
		t.Fatalf("expected redacted evidence, got %q", redacted)
	}
	if strings.Contains(secretFinding.LineSnippet, testSecretValue) {
		t.Fatalf("expected redacted structured snippet, got %q", secretFinding.LineSnippet)
	}
	if secretFinding.LineSnippetRedacted == nil || !*secretFinding.LineSnippetRedacted {
		t.Fatalf("expected structured redacted flag, got %+v", secretFinding.LineSnippetRedacted)
	}
	if rawStored, _ := evidence["raw_secret_stored"].(bool); rawStored {
		t.Fatal("raw_secret_stored must be false")
	}
	if got := evidence["detector_version"]; got != "2026.05" {
		t.Fatalf("expected detector version in finding evidence, got %v", got)
	}
	if got := evidence["detector_category"]; got != "cloud_credentials" {
		t.Fatalf("expected detector category in finding evidence, got %v", got)
	}
	if got := evidence["detector_provider"]; got != "AWS" {
		t.Fatalf("expected detector provider in finding evidence, got %v", got)
	}
}

func TestScanRepositoryClassifiesAllowlistedSecretFingerprint(t *testing.T) {
	repoPath, _ := initTestRepoWithHistorySecret(t)
	allowlist := "secret-fingerprint: " + hashSHA256(testSecretValue) + "\n"
	if err := os.WriteFile(filepath.Join(repoPath, ".identrailignore"), []byte(allowlist), 0o600); err != nil {
		t.Fatalf("write identrail ignore file: %v", err)
	}
	runGit(t, repoPath, "add", ".identrailignore")
	runGit(t, repoPath, "commit", "-q", "-m", "allowlist known fixture secret")

	scanner := NewScanner(nil,
		WithHistoryLimit(100),
		WithMaxFindings(50),
		WithNow(func() time.Time { return time.Date(2026, 5, 18, 13, 0, 0, 0, time.UTC) }),
	)

	result, err := scanner.ScanRepository(context.Background(), repoPath)
	if err != nil {
		t.Fatalf("scan repository failed: %v", err)
	}

	var secretFinding domain.Finding
	for _, finding := range result.Findings {
		if finding.Type == domain.FindingSecretExposure && finding.Detector == "aws_secret_access_key" {
			secretFinding = finding
			break
		}
	}
	if secretFinding.ID == "" {
		t.Fatalf("expected allowlisted secret finding, got %+v", result.Findings)
	}
	if got := secretFinding.Evidence["confidence_state"]; got != secretClassificationAllowlisted {
		t.Fatalf("expected allowlisted confidence state, got %v in %+v", got, secretFinding.Evidence)
	}
	if got, _ := secretFinding.Evidence["secret_allowlisted"].(bool); !got {
		t.Fatalf("expected secret_allowlisted evidence flag, got %+v", secretFinding.Evidence)
	}
	if secretFinding.ConfidenceScore != 0.05 {
		t.Fatalf("expected allowlisted confidence score 0.05, got %.2f", secretFinding.ConfidenceScore)
	}
}

func TestScanRepositoryDetectsHeadMisconfiguration(t *testing.T) {
	repoPath, headCommit := initTestRepoWithHeadMisconfig(t)
	scanner := NewScanner(nil, WithHistoryLimit(10), WithMaxFindings(20))

	result, err := scanner.ScanRepository(context.Background(), repoPath)
	if err != nil {
		t.Fatalf("scan repository failed: %v", err)
	}
	if result.FilesScanned == 0 {
		t.Fatal("expected misconfiguration files to be scanned")
	}

	found := false
	for _, finding := range result.Findings {
		if finding.Type != domain.FindingRepoMisconfig {
			continue
		}
		path, _ := finding.Evidence["file_path"].(string)
		if strings.HasSuffix(path, "workflow.yml") {
			if finding.Commit != headCommit || finding.FilePath == "" || finding.LineNumber == 0 || finding.Detector == "" || finding.LineSnippet == "" {
				t.Fatalf("expected structured repo misconfig metadata, got %+v", finding)
			}
			if finding.LineSnippetRedacted == nil || *finding.LineSnippetRedacted {
				t.Fatalf("expected non-redacted structured snippet flag, got %+v", finding.LineSnippetRedacted)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected repo misconfiguration finding, got %+v", result.Findings)
	}
}

func TestDetectMisconfigFindingsParsesWorkflowSignals(t *testing.T) {
	content := []byte(`name: ci
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    permissions:
      contents: write-all
      packages: read
    runs-on: ubuntu-latest
    steps:
      - run: echo ci
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ci.yml", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) < 2 {
		t.Fatalf("expected at least two workflow findings, got %d", len(findings))
	}

	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.Detector] = true
		if finding.LineNumber == 0 {
			t.Fatalf("expected finding line number to be populated: %+v", finding)
		}
	}
	if !seen["workflow_pull_request_target"] {
		t.Fatalf("expected workflow_pull_request_target detection, got %+v", findings)
	}
	if !seen["workflow_write_all_permissions"] {
		t.Fatalf("expected workflow_write_all_permissions detection, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsParsesPrivilegedYamlSettings(t *testing.T) {
	content := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: sample
spec:
  containers:
    - name: app
      securityContext:
        privileged: true
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "manifests/pod.yaml", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) == 0 {
		t.Fatal("expected k8s privileged finding")
	}

	found := false
	for _, finding := range findings {
		if finding.Detector == "k8s_privileged_true" {
			found = true
			if finding.LineNumber == 0 {
				t.Fatalf("expected non-zero line number: %+v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("expected k8s_privileged_true finding, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsParsesTerraformSignals(t *testing.T) {
	content := []byte(`resource "aws_s3_bucket" "public" {
  acl = "public-read"
}

resource "aws_s3_bucket_acl" "public_acl" {
  bucket = "my-public-bucket"
  acl    = "public-read-write"
}

resource "aws_security_group" "sg" {
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
      "0.0.0.0/0",
      "10.0.0.0/16",
    ]
  }
}

resource "aws_security_group_rule" "sg_rule" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["::/0"]
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = "sg-12345"
}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "terraform/main.tf", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) < 4 {
		t.Fatalf("expected at least four terraform findings, got %d", len(findings))
	}

	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.Detector] = true
	}
	if !seen["terraform_public_s3_acl"] {
		t.Fatalf("expected terraform_public_s3_acl finding, got %+v", findings)
	}
	if !seen["terraform_open_ssh_rdp"] {
		t.Fatalf("expected terraform_open_ssh_rdp finding, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsSupportsDynamicIngressTerraformSignals(t *testing.T) {
	content := []byte(`resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [1]
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "terraform/main.tf", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) == 0 {
		t.Fatal("expected dynamic ingress terraform finding")
	}

	found := false
	for _, finding := range findings {
		if finding.Detector == "terraform_open_ssh_rdp" {
			found = true
			if finding.LineNumber == 0 {
				t.Fatalf("expected non-zero line number: %+v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("expected terraform_open_ssh_rdp finding, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsSupportsResourceAttributeIngressTerraformSignals(t *testing.T) {
	content := []byte(`resource "aws_security_group" "sg" {
  ingress = [
    {
      from_port = 22
      to_port   = 22
      protocol  = "tcp"
      cidr_blocks = ["10.0.0.0/16", "0.0.0.0/0"]
    },
  ]
}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "terraform/main.tf", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) == 0 {
		t.Fatal("expected resource ingress terraform finding")
	}

	found := false
	for _, finding := range findings {
		if finding.Detector == "terraform_open_ssh_rdp" {
			found = true
			if finding.LineNumber == 0 {
				t.Fatalf("expected non-zero line number: %+v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("expected terraform_open_ssh_rdp finding, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsSupportsResourceAttributeIngressWithVariableCidrTerraformSignals(t *testing.T) {
	content := []byte(`resource "aws_security_group" "sg" {
  ingress = [
    {
      from_port = 3389
      to_port   = 3389
      cidr_blocks = ["10.0.0.0/16", "::/0", var.office_cidr]
    },
  ]
}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "terraform/main.tf", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) == 0 {
		t.Fatal("expected resource attribute terraform finding with variable cidr")
	}

	found := false
	for _, finding := range findings {
		if finding.Detector == "terraform_open_ssh_rdp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected terraform_open_ssh_rdp finding, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsSupportsModuleIngressTerraformSignals(t *testing.T) {
	content := []byte(`module "sg" {
  ingress = [
    {
      from_port = 3389
      to_port   = 3389
      protocol  = "tcp"
      cidr_blocks = ["10.0.0.0/16", "::/0"]
    }
  ]
}
`)
	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "terraform/module.tf", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) == 0 {
		t.Fatal("expected module ingress terraform finding")
	}

	found := false
	for _, finding := range findings {
		if finding.Detector == "terraform_open_ssh_rdp" {
			found = true
			if finding.LineNumber == 0 {
				t.Fatalf("expected non-zero line number: %+v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("expected terraform_open_ssh_rdp finding, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsSupportsMixedCidrTupleTerraformSignals(t *testing.T) {
	content := []byte(`resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [1]
    content {
      from_port   = 3389
      to_port     = 3389
      cidr_blocks = ["10.0.0.0/16", var.office_cidr, "::/0"]
    }
  }
}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "terraform/main.tf", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) == 0 {
		t.Fatal("expected mixed-cidr terraform finding")
	}

	found := false
	for _, finding := range findings {
		if finding.Detector == "terraform_open_ssh_rdp" {
			found = true
			if finding.LineNumber == 0 {
				t.Fatalf("expected non-zero line number: %+v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("expected terraform_open_ssh_rdp finding, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsSupportsDockerfileVariants(t *testing.T) {
	content := []byte(`FROM --platform=linux/amd64 nginx:latest
FROM python:3.12
`)
	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "Dockerfile.prod", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) == 0 {
		t.Fatal("expected dockerfile variant finding")
	}

	found := false
	for _, finding := range findings {
		if finding.Detector == "docker_latest_tag" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected docker_latest_tag finding, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsParsesDockerfileFromLine(t *testing.T) {
	content := []byte(`FROM golang:latest
FROM --platform=linux/amd64 nginx:1.25
FROM busybox:latest AS runtime
FROM registry:5000/team/app:latest@sha256:abc123
	FROM python
	FROM node:20
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "Dockerfile", content, time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC))
	if len(findings) == 0 {
		t.Fatalf("expected docker latest findings")
	}

	found := 0
	for _, finding := range findings {
		if finding.Detector == "docker_latest_tag" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("expected 2 docker latest findings, got %d", found)
	}
}

func TestIsDockerfileBaseImagePinnedToLatestIgnoresDigestTaggedImages(t *testing.T) {
	if !isDockerfileBaseImagePinnedToLatest("FROM golang:latest") {
		t.Fatal("expected latest tag to be treated as mutable")
	}
	if isDockerfileBaseImagePinnedToLatest("FROM registry.example.com/team/app:latest@sha256:abcdef") {
		t.Fatal("expected digest-pinned latest image to be excluded from latest mutable tag checks")
	}
	if isDockerfileBaseImagePinnedToLatest("FROM node:20") {
		t.Fatal("expected non-latest tag not to trigger latest mutable check")
	}
}

func TestScanRepositoryHonorsMaxFindings(t *testing.T) {
	repoPath, _ := initTestRepoWithHeadMisconfig(t)
	scanner := NewScanner(nil, WithHistoryLimit(10), WithMaxFindings(1))

	result, err := scanner.ScanRepository(context.Background(), repoPath)
	if err != nil {
		t.Fatalf("scan repository failed: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding due to cap, got %d", len(result.Findings))
	}
	if !result.Truncated {
		t.Fatal("expected truncated result")
	}
}

func TestScanRepositoryRedactsMultipleSecretsAndSkipsMalformedHeadFiles(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")

	combinedSecretLine := "AWS_SECRET_ACCESS_KEY=" + testSecretValue + " GITHUB_TOKEN=" + testGitHubToken() + "\n"
	if err := os.WriteFile(filepath.Join(repo, "secrets.env"), []byte(combinedSecretLine), 0o600); err != nil {
		t.Fatalf("write secrets fixture: %v", err)
	}

	workflowDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "oversized.yml"), []byte(strings.Repeat("a", maxFileSizeBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized workflow fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "binary.yml"), []byte{0xff, 0xfe, 0xfd}, 0o600); err != nil {
		t.Fatalf("write binary workflow fixture: %v", err)
	}

	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-q", "-m", "add mixed secret + malformed workflow fixtures")

	scanner := NewScanner(nil,
		WithHistoryLimit(10),
		WithMaxFindings(20),
		WithNow(func() time.Time { return time.Date(2026, 3, 17, 16, 0, 0, 0, time.UTC) }),
	)

	result, err := scanner.ScanRepository(context.Background(), repo)
	if err != nil {
		t.Fatalf("scan repository failed: %v", err)
	}
	if result.FilesScanned != 0 {
		t.Fatalf("expected malformed HEAD files to be skipped, got files_scanned=%d", result.FilesScanned)
	}

	secretFindings := make([]domain.Finding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if finding.Type == domain.FindingSecretExposure {
			secretFindings = append(secretFindings, finding)
		}
	}
	if len(secretFindings) < 2 {
		t.Fatalf("expected multiple secret findings from one line, got %+v", secretFindings)
	}

	rawGitHubToken := testGitHubToken()
	for _, finding := range secretFindings {
		redacted, _ := finding.Evidence["redacted_line_snip"].(string)
		if strings.Contains(redacted, testSecretValue) || strings.Contains(redacted, rawGitHubToken) {
			t.Fatalf("expected redacted line snippet to remove all secret values, got %q", redacted)
		}
		if rawStored, _ := finding.Evidence["raw_secret_stored"].(bool); rawStored {
			t.Fatalf("raw_secret_stored must remain false for finding %+v", finding)
		}
	}

	repeat, err := scanner.ScanRepository(context.Background(), repo)
	if err != nil {
		t.Fatalf("second scan repository failed: %v", err)
	}
	if len(repeat.Findings) != len(result.Findings) {
		t.Fatalf("expected deterministic finding count, got first=%d second=%d", len(result.Findings), len(repeat.Findings))
	}
	for idx := range result.Findings {
		if result.Findings[idx].ID != repeat.Findings[idx].ID {
			t.Fatalf("expected deterministic finding ordering, mismatch at index %d first=%s second=%s", idx, result.Findings[idx].ID, repeat.Findings[idx].ID)
		}
	}
}

func TestNormalizeRepositoryInput(t *testing.T) {
	if got := normalizeRepositoryInput("owner/repo"); got != "https://github.com/owner/repo.git" {
		t.Fatalf("unexpected repository normalization %q", got)
	}
	if got := normalizeRepositoryInput("https://github.com/owner/repo.git"); got != "https://github.com/owner/repo.git" {
		t.Fatalf("unexpected repository normalization %q", got)
	}
}

func TestParseAddedLines(t *testing.T) {
	patch := []byte(`diff --git a/a.txt b/a.txt
index 111..222 100644
--- a/a.txt
+++ b/a.txt
@@ -0,0 +1,2 @@
+hello
+world
`)
	lines := parseAddedLines(patch)
	if len(lines) != 2 {
		t.Fatalf("expected 2 added lines, got %d", len(lines))
	}
	if lines[0].Path != "a.txt" || lines[0].Line != 1 || lines[0].Text != "hello" {
		t.Fatalf("unexpected first added line %+v", lines[0])
	}
}

func TestLocalRepositoryDetection(t *testing.T) {
	worktree, _ := initTestRepoWithHistorySecret(t)
	loc, ok := localRepository(worktree)
	if !ok || loc.Bare {
		t.Fatalf("expected worktree repository detection, got %+v ok=%t", loc, ok)
	}

	bare := filepath.Join(t.TempDir(), "bare.git")
	runGitCommand(t, "git", "clone", "--quiet", "--bare", worktree, bare)
	loc, ok = localRepository(bare)
	if !ok || !loc.Bare {
		t.Fatalf("expected bare repository detection, got %+v ok=%t", loc, ok)
	}

	if _, ok := localRepository(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("expected missing path to be rejected")
	}
}

func TestIsLocalRepositoryTarget(t *testing.T) {
	worktree, _ := initTestRepoWithHistorySecret(t)
	if !IsLocalRepositoryTarget(worktree) {
		t.Fatal("expected worktree path to be recognized as local repository target")
	}
	if IsLocalRepositoryTarget("owner/repo") {
		t.Fatal("expected owner/repo shorthand to not be treated as a local repository target")
	}
}

func TestPrepareRepositoryCloneFailure(t *testing.T) {
	scanner := NewScanner(func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("clone failed")
	})
	_, cleanup, err := scanner.prepareRepository(context.Background(), "owner/repo")
	if cleanup != nil {
		cleanup()
	}
	if err == nil {
		t.Fatal("expected clone error")
	}
}

func TestPrepareRepositoryRejectsInsecureHTTPRepositoryURL(t *testing.T) {
	cloneCalled := false
	scanner := NewScanner(func(context.Context, string, ...string) ([]byte, error) {
		cloneCalled = true
		return nil, nil
	})

	_, cleanup, err := scanner.prepareRepository(context.Background(), "http://github.com/owner/repo.git")
	if cleanup != nil {
		cleanup()
	}
	if err == nil {
		t.Fatal("expected insecure repository URL to be rejected")
	}
	if !strings.Contains(err.Error(), "insecure repository url scheme http is not allowed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if cloneCalled {
		t.Fatal("expected clone command not to run for insecure repository URL")
	}
}

func TestCloneMirrorUsesAskPassCredentialWithoutCommandArgLeak(t *testing.T) {
	const secret = "ghs_secret_token"
	var gotEnv []string
	var gotArgs []string
	scanner := NewScanner(
		func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("expected authenticated clone to use env command runner")
			return nil, nil
		},
		WithHTTPSCloneCredential(HTTPSCloneCredential{
			Host:     "github.com",
			Username: "x-access-token",
			Password: secret,
		}),
		WithEnvCommandRunner(func(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
			gotEnv = append([]string(nil), env...)
			gotArgs = append([]string{name}, args...)
			askPass := envValue(env, "GIT_ASKPASS")
			if askPass == "" {
				t.Fatal("expected GIT_ASKPASS to be configured")
			}
			if _, err := os.Stat(askPass); err != nil {
				t.Fatalf("expected askpass helper to exist during clone: %v", err)
			}
			return []byte("ok"), nil
		}),
	)

	err := scanner.cloneMirror(context.Background(), t.TempDir(), "https://github.com/owner/repo.git", filepath.Join(t.TempDir(), "repo.git"))
	if err != nil {
		t.Fatalf("clone mirror: %v", err)
	}
	if strings.Contains(strings.Join(gotArgs, " "), secret) {
		t.Fatalf("clone command arguments leaked token: %+v", gotArgs)
	}
	if envValue(gotEnv, "IDENTRAIL_GIT_USERNAME") != "x-access-token" || envValue(gotEnv, "IDENTRAIL_GIT_PASSWORD") != secret {
		t.Fatalf("expected clone credential in environment, got %+v", gotEnv)
	}
	if envValue(gotEnv, "GIT_TERMINAL_PROMPT") != "0" {
		t.Fatalf("expected terminal prompts to be disabled, got %+v", gotEnv)
	}
}

func TestCloneMirrorRedactsCredentialFromErrors(t *testing.T) {
	const secret = "ghs_secret_token"
	scanner := NewScanner(nil,
		WithHTTPSCloneCredential(HTTPSCloneCredential{
			Host:     "github.com",
			Username: "x-access-token",
			Password: secret,
		}),
		WithEnvCommandRunner(func(context.Context, []string, string, ...string) ([]byte, error) {
			return nil, errors.New("remote rejected token " + secret)
		}),
	)

	err := scanner.cloneMirror(context.Background(), t.TempDir(), "https://github.com/owner/repo.git", filepath.Join(t.TempDir(), "repo.git"))
	if err == nil {
		t.Fatal("expected clone error")
	}
	if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("expected redacted clone error, got %v", err)
	}
}

func TestCloneMirrorRejectsCredentialHostMismatch(t *testing.T) {
	called := false
	scanner := NewScanner(nil,
		WithHTTPSCloneCredential(HTTPSCloneCredential{
			Host:     "github.com",
			Username: "x-access-token",
			Password: "ghs_secret_token",
		}),
		WithEnvCommandRunner(func(context.Context, []string, string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		}),
	)

	err := scanner.cloneMirror(context.Background(), t.TempDir(), "https://gitlab.com/owner/repo.git", filepath.Join(t.TempDir(), "repo.git"))
	if err == nil {
		t.Fatal("expected credential host mismatch to fail")
	}
	if called {
		t.Fatal("expected clone command not to run for credential host mismatch")
	}
}

func TestValidateCloneURL(t *testing.T) {
	originalLookup := repositoryHostLookupIPs
	repositoryHostLookupIPs = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "github.com":
			return []net.IP{net.ParseIP("140.82.112.3")}, nil
		case "example.com":
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		case "127.0.0.1.nip.io":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		case "10.0.0.8.nip.io":
			return []net.IP{net.ParseIP("10.0.0.8")}, nil
		default:
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
	}
	t.Cleanup(func() {
		repositoryHostLookupIPs = originalLookup
	})

	tests := []struct {
		name      string
		target    string
		expectErr bool
	}{
		{name: "github shorthand", target: "https://github.com/owner/repo.git"},
		{name: "ssh url", target: "ssh://git@github.com/owner/repo.git"},
		{name: "git scp form", target: "git@github.com:owner/repo.git"},
		{name: "insecure http", target: "http://github.com/owner/repo.git", expectErr: true},
		{name: "unsupported file scheme", target: "file:///tmp/repo.git", expectErr: true},
		{name: "credentials in https url", target: "https://token@example.com/owner/repo.git", expectErr: true},
		{name: "credentials in ssh url", target: "ssh://git:password@example.com/owner/repo.git", expectErr: true},
		{name: "loopback ip host", target: "https://127.0.0.1/owner/repo.git", expectErr: true},
		{name: "private ip host", target: "https://10.0.0.8/owner/repo.git", expectErr: true},
		{name: "shared address ip host", target: "https://100.64.0.1/owner/repo.git", expectErr: true},
		{name: "link-local ip host", target: "https://169.254.169.254/owner/repo.git", expectErr: true},
		{name: "multicast ip host", target: "https://224.0.0.1/owner/repo.git", expectErr: true},
		{name: "unspecified ip host", target: "https://0.0.0.0/owner/repo.git", expectErr: true},
		{name: "localhost host", target: "ssh://git@localhost/owner/repo.git", expectErr: true},
		{name: "scp localhost host", target: "git@localhost:owner/repo.git", expectErr: true},
		{name: "scp host without user", target: "10.0.0.8:owner/repo.git", expectErr: true},
		{name: "localhost fqdn host", target: "ssh://git@localhost./owner/repo.git", expectErr: true},
		{name: "scp bracketed ipv6 loopback host", target: "git@[::1]:owner/repo.git", expectErr: true},
		{name: "scoped ipv6 link-local host", target: "ssh://git@[fe80::1%25lo]/owner/repo.git", expectErr: true},
		{name: "decimal loopback host", target: "ssh://git@2130706433/owner/repo.git", expectErr: true},
		{name: "hex loopback host", target: "ssh://git@0x7f000001/owner/repo.git", expectErr: true},
		{name: "octal dotted loopback host", target: "ssh://git@0177.0.0.1/owner/repo.git", expectErr: true},
		{name: "short dotted loopback host", target: "ssh://git@127.1/owner/repo.git", expectErr: true},
		{name: "hostname resolving to loopback", target: "https://127.0.0.1.nip.io/owner/repo.git", expectErr: true},
		{name: "hostname resolving to private ip", target: "https://10.0.0.8.nip.io/owner/repo.git", expectErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCloneURL(tc.target)
			if tc.expectErr && err == nil {
				t.Fatalf("expected error for %q", tc.target)
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("expected no error for %q, got %v", tc.target, err)
			}
		})
	}
}

func TestGitInvocationModes(t *testing.T) {
	var got [][]string
	scanner := NewScanner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append(got, append([]string{name}, args...))
		return []byte("ok"), nil
	})

	if _, err := scanner.git(context.Background(), repositoryLocation{Path: "/tmp/repo", Bare: false}, "rev-list", "--all"); err != nil {
		t.Fatalf("git invocation failed: %v", err)
	}
	if _, err := scanner.git(context.Background(), repositoryLocation{Path: "/tmp/repo.git", Bare: true}, "rev-list", "--all"); err != nil {
		t.Fatalf("git invocation failed: %v", err)
	}

	expectedFirst := []string{"git", "-C", "/tmp/repo", "rev-list", "--all"}
	if !reflect.DeepEqual(got[0], expectedFirst) {
		t.Fatalf("unexpected worktree invocation %+v", got[0])
	}
	expectedSecond := []string{"git", "--git-dir", "/tmp/repo.git", "rev-list", "--all"}
	if !reflect.DeepEqual(got[1], expectedSecond) {
		t.Fatalf("unexpected bare invocation %+v", got[1])
	}
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}

func TestHelperFunctions(t *testing.T) {
	if got := redactedToken("abcd"); got != "[REDACTED]" {
		t.Fatalf("unexpected redacted token %q", got)
	}
	if got := redactedToken("abcdefghijkl"); !strings.Contains(got, "[REDACTED:abcd...ijkl]") {
		t.Fatalf("unexpected redacted token %q", got)
	}
	if got := lineForOffset("a\nb\nc", 3); got != 2 {
		t.Fatalf("unexpected line for offset %d", got)
	}
	if !shouldInspectMisconfiguration(".github/workflows/ci.yml") {
		t.Fatal("expected workflow file to be inspected")
	}
	if shouldInspectMisconfiguration("README.md") {
		t.Fatal("did not expect markdown file inspection")
	}
	if severityRank(domain.SeverityCritical) >= severityRank(domain.SeverityHigh) {
		t.Fatal("expected critical severity to rank above high")
	}
	if id := hashDeterministicID("repo", "path", "1"); len(id) != 64 {
		t.Fatalf("expected sha256 deterministic id length 64, got %d", len(id))
	}
	if hashDeterministicID("repo", "path", "1") != hashDeterministicID("repo", "path", "1") {
		t.Fatal("expected deterministic id hash output for same inputs")
	}
	if hashDeterministicID("repo", "path", "1") == hashDeterministicID("repo", "path", "2") {
		t.Fatal("expected different deterministic id hashes for different inputs")
	}
}

func initTestRepoWithHistorySecret(t *testing.T) (string, string) {
	t.Helper()
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")

	secretPath := filepath.Join(repo, "app.env")
	if err := os.WriteFile(secretPath, []byte("AWS_SECRET_ACCESS_KEY="+testSecretValue+"\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	runGit(t, repo, "add", "app.env")
	runGit(t, repo, "commit", "-q", "-m", "add secret")
	firstCommit := strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))

	if err := os.WriteFile(secretPath, []byte("AWS_SECRET_ACCESS_KEY=redacted\n"), 0o600); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}
	runGit(t, repo, "add", "app.env")
	runGit(t, repo, "commit", "-q", "-m", "remove secret")

	return repo, firstCommit
}

func initTestRepoWithHeadMisconfig(t *testing.T) (string, string) {
	t.Helper()
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")

	workflowDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow dir: %v", err)
	}
	workflow := `name: ci
on:
  pull_request_target:
jobs:
  test:
    permissions: write-all
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`
	if err := os.WriteFile(filepath.Join(workflowDir, "workflow.yml"), []byte(workflow), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	terraform := `resource "aws_security_group" "sg" {
  from_port = 22
  to_port = 22
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}`
	if err := os.WriteFile(filepath.Join(repo, "main.tf"), []byte(terraform), 0o600); err != nil {
		t.Fatalf("write terraform: %v", err)
	}

	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-q", "-m", "add misconfig")
	return repo, strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=identrail-test",
		"GIT_AUTHOR_EMAIL=identrail-test@example.com",
		"GIT_COMMITTER_NAME=identrail-test",
		"GIT_COMMITTER_EMAIL=identrail-test@example.com",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
	return string(output)
}

func runGitCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=identrail-test",
		"GIT_AUTHOR_EMAIL=identrail-test@example.com",
		"GIT_COMMITTER_NAME=identrail-test",
		"GIT_COMMITTER_EMAIL=identrail-test@example.com",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, string(output))
	}
	return string(output)
}
