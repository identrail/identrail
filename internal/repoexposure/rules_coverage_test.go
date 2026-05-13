package repoexposure

import (
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"gopkg.in/yaml.v3"
)

func TestDetectMisconfigFindingsWithParsersRejectUnsupportedFileExtensions(t *testing.T) {
	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "notes.md", []byte("some random text"), time.Time{})
	if len(findings) != 0 {
		t.Fatalf("expected no findings for unsupported extension, got %d", len(findings))
	}
}

func TestDetectMisconfigFindingsWithParsersRejectInvalidParsers(t *testing.T) {
	invalidYAML := []byte("name: [\n")
	if findings, ok := detectMisconfigFindingsWithParsers("octo-org/octo-repo", "HEAD", ".github/workflows/ci.yml", invalidYAML, map[string]struct{}{}, time.Time{}); ok {
		t.Fatalf("expected parser gate to fail on invalid YAML, got found=true with %d findings", len(findings))
	}

	invalidTerraform := []byte("resource \"aws_s3_bucket\" \"bad\" { acl = [\"public\"]\n")
	if findings, ok := detectMisconfigFindingsWithParsers("octo-org/octo-repo", "HEAD", "terraform/main.tf", invalidTerraform, map[string]struct{}{}, time.Time{}); ok {
		t.Fatalf("expected parser gate to fail on invalid Terraform, got found=true with %d findings", len(findings))
	}
}

func TestYAMLMisconfigParserEdgeCases(t *testing.T) {
	workflows := []byte(`on:
- pull_request_target
jobs:
  build:
    permissions:
      contents: write
      packages: write-all
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ci.yml", workflows, time.Time{})
	if len(findings) < 2 {
		t.Fatalf("expected parser-based workflow findings, got %d", len(findings))
	}

	foundPerm := false
	foundOn := false
	for _, finding := range findings {
		switch finding.Detector {
		case "workflow_pull_request_target":
			foundOn = true
		case "workflow_write_all_permissions":
			foundPerm = true
		}
	}
	if !foundOn || !foundPerm {
		t.Fatalf("expected workflow findings, got %+v", findings)
	}

	if yamlBoolIsTrue(&yaml.Node{}) {
		t.Fatal("expected scalar-only yamlBoolIsTrue to fail for non-scalar node")
	}
}

func TestTerraformAndDockerHelpers(t *testing.T) {
	ast, diag := hclsyntax.ParseConfig([]byte(`resource "aws_security_group_rule" "rule" {
  type = "ingress"
  from_port = 22
  to_port = 22
  cidr_blocks = ["0.0.0.0/0"]
  self = true
}`), "terraform/main.tf", hcl.InitialPos)
	if diag.HasErrors() {
		t.Fatalf("unexpected terraform parse error: %v", diag)
	}
	body, ok := ast.Body.(*hclsyntax.Body)
	if !ok {
		t.Fatal("failed to cast terraform body")
	}
	attrs := body.Blocks[0].Body.Attributes
	if attrs == nil {
		t.Fatal("expected terraform attributes")
	}
	ruleType, ok := terraformStringAttribute(attrs["type"])
	if !ok {
		t.Fatal("expected type attribute to parse as string")
	}
	if ruleType != "ingress" {
		t.Fatalf("expected ingress rule type, got %s", ruleType)
	}
	if _, ok := terraformStringAttribute(attrs["self"]); ok {
		t.Fatal("expected bool attribute to fail string parse")
	}
	if !containsSensitivePortRange(22, 22, true, true) {
		t.Fatal("expected port range function to identify SSH port")
	}
	if containsSensitivePortRange(0, 0, true, false) {
		t.Fatal("expected non-sensitive port range")
	}
	if !containsSensitivePortRange(3389, 3389, false, true) {
		t.Fatal("expected to_port-only sensitive detection")
	}
	if containsSensitivePortRange(100, 101, true, true) {
		t.Fatal("expected non-sensitive port range")
	}
	if !containsPublicCidr(attrs["cidr_blocks"]) {
		t.Fatal("expected parser to detect public cidr block")
	}
	if containsPublicCidr(attrs["self"]) {
		t.Fatal("expected bool cidr attribute to fail public cidr check")
	}
	if terraformAttributeLine(nil) != 1 {
		t.Fatalf("expected default line 1, got %d", terraformAttributeLine(nil))
	}
	if got := terraformAttributeLine(attrs["from_port"]); got != 3 {
		t.Fatalf("expected terraform from_port line 3, got %d", got)
	}

	content := []byte("FROM ubuntu:latest@sha256:abc\nFROM node:20\n")
	seen := map[string]struct{}{}
	mutables := detectDockerfileMisconfigFindings("octo-org/octo-repo", "HEAD", "Dockerfile", content, seen, time.Time{})
	if len(mutables) != 0 {
		t.Fatalf("expected digest-pinned image and non-latest tags to produce zero findings, got %d", len(mutables))
	}

	content = []byte("FROM nginx:latest\nFROM nginx:1.20\n")
	findings := detectDockerfileMisconfigFindings("octo-org/octo-repo", "HEAD", "Dockerfile", content, seen, time.Time{})
	if len(findings) != 1 {
		t.Fatalf("expected one mutable latest finding, got %d", len(findings))
	}
}

func TestScannerRuleHelpers(t *testing.T) {
	if !shouldInspectMisconfiguration(".github/workflows/ci.yml") {
		t.Fatal("expected workflows path to be inspectable")
	}
	if !shouldInspectMisconfiguration("Dockerfile.test") {
		t.Fatal("expected dockerfile variant to be inspectable")
	}
	if !shouldInspectMisconfiguration("main.tf") {
		t.Fatal("expected terraform path to be inspectable")
	}
	if shouldInspectMisconfiguration("README.md") {
		t.Fatal("expected non-misconfiguration path to be skipped")
	}
	if shouldInspectMisconfiguration("") {
		t.Fatal("expected empty path to be skipped")
	}

	if lineForOffset("", 0) != 1 {
		t.Fatalf("expected lineForOffset empty content default")
	}
	if lineForOffset("a\nb\nc", 2) != 2 {
		t.Fatalf("expected lineForOffset for non-boundary offset")
	}
	if lineForOffset("a\nb\nc", 4) != 3 {
		t.Fatalf("expected lineForOffset for third line")
	}

	if !isDockerfileBaseImagePinnedToLatest("FROM nginx:latest") {
		t.Fatal("expected latest tag to be detected as mutable")
	}
	if isDockerfileBaseImagePinnedToLatest("FROM nginx:latest@sha256:abc") {
		t.Fatal("expected digest-pinned latest image to be ignored")
	}
	if !yamlBoolIsTrue(&yaml.Node{Kind: yaml.ScalarNode, Value: "Yes"}) {
		t.Fatal("expected yaml bool true for yes/true")
	}
	if yamlBoolIsTrue(&yaml.Node{Kind: yaml.ScalarNode, Value: "false"}) {
		t.Fatal("expected yamlBoolIsTrue to be false")
	}
}
