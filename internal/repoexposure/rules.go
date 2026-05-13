package repoexposure

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"

	"github.com/identrail/identrail/internal/domain"
)

type secretRule struct {
	ID          string
	Severity    domain.FindingSeverity
	Title       string
	Summary     string
	Remediation string
	Pattern     *regexp.Regexp
}

var secretRules = []secretRule{
	{
		ID:          "aws_access_key_id",
		Severity:    domain.SeverityHigh,
		Title:       "Potential AWS access key exposed in commit history",
		Summary:     "A line added in commit history appears to contain an AWS access key identifier.",
		Remediation: "Rotate the key, purge secrets from history, and move credentials to a secret manager.",
		Pattern:     regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		ID:          "aws_secret_access_key",
		Severity:    domain.SeverityCritical,
		Title:       "Potential AWS secret key exposed in commit history",
		Summary:     "A line added in commit history appears to contain an AWS secret access key.",
		Remediation: "Rotate affected credentials immediately and replace static secrets with short-lived credentials.",
		Pattern:     regexp.MustCompile(`(?i)\baws(?:_| |\.)?(?:secret(?:_| |\.)?)?access(?:_| |\.)?key(?:_| |\.)?=?\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
	},
	{
		ID:          "github_token",
		Severity:    domain.SeverityCritical,
		Title:       "Potential GitHub token exposed in commit history",
		Summary:     "A line added in commit history appears to contain a GitHub token.",
		Remediation: "Revoke the token immediately, rotate dependent credentials, and enforce secret scanning in CI.",
		Pattern:     regexp.MustCompile(`\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})\b`),
	},
	{
		ID:          "slack_token",
		Severity:    domain.SeverityHigh,
		Title:       "Potential Slack token exposed in commit history",
		Summary:     "A line added in commit history appears to contain a Slack token.",
		Remediation: "Revoke and rotate the token in Slack, then remove token usage from repository files.",
		Pattern:     regexp.MustCompile(`\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b`),
	},
	{
		ID:          "private_key_material",
		Severity:    domain.SeverityCritical,
		Title:       "Private key material exposed in commit history",
		Summary:     "A line added in commit history contains private key header material.",
		Remediation: "Revoke and rotate affected keys, remove key files from history, and store keys in a vault/KMS.",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	},
}

type lineMisconfigRule struct {
	ID          string
	Severity    domain.FindingSeverity
	Title       string
	Summary     string
	Remediation string
	Pattern     *regexp.Regexp
}

type fileMisconfigRule struct {
	ID          string
	Severity    domain.FindingSeverity
	Title       string
	Summary     string
	Remediation string
	Pattern     *regexp.Regexp
}

var lineMisconfigRules = []lineMisconfigRule{
	{
		ID:          "workflow_write_all_permissions",
		Severity:    domain.SeverityHigh,
		Title:       "GitHub workflow grants broad write permissions",
		Summary:     "Workflow permissions are set to write-all, increasing automation blast radius.",
		Remediation: "Restrict workflow permissions to least-privilege per job and avoid global write-all.",
		Pattern:     regexp.MustCompile(`(?i)^\s*permissions:\s*write-all\s*$`),
	},
	{
		ID:          "workflow_pull_request_target",
		Severity:    domain.SeverityMedium,
		Title:       "GitHub workflow uses pull_request_target trigger",
		Summary:     "pull_request_target can execute with elevated token context if not strictly controlled.",
		Remediation: "Use pull_request where possible, pin actions, and harden token permissions for untrusted PR code.",
		Pattern:     regexp.MustCompile(`(?i)^\s*pull_request_target\s*:\s*$`),
	},
	{
		ID:          "k8s_privileged_true",
		Severity:    domain.SeverityHigh,
		Title:       "Kubernetes manifest enables privileged container",
		Summary:     "A container runs with privileged=true, which can bypass workload isolation boundaries.",
		Remediation: "Set privileged=false and apply Pod Security standards with least-privilege securityContext.",
		Pattern:     regexp.MustCompile(`(?i)^\s*privileged:\s*true\s*$`),
	},
	{
		ID:          "terraform_public_s3_acl",
		Severity:    domain.SeverityHigh,
		Title:       "Terraform config enables public S3 ACL",
		Summary:     "Terraform file sets a public S3 ACL, which can expose data externally.",
		Remediation: "Use private ACLs and explicit bucket policies with least-privilege principals.",
		Pattern:     regexp.MustCompile(`(?i)^\s*acl\s*=\s*"public-(?:read|read-write)"\s*$`),
	},
	{
		ID:          "docker_latest_tag",
		Severity:    domain.SeverityMedium,
		Title:       "Docker image uses mutable latest tag",
		Summary:     "Using :latest weakens supply-chain determinism and patch traceability.",
		Remediation: "Pin base images by immutable version/digest and review updates through CI.",
		Pattern:     regexp.MustCompile(`(?i)^FROM\s+\S+:latest(?:\s+AS\s+\S+)?\s*$`),
	},
}

var fileMisconfigRules = []fileMisconfigRule{
	{
		ID:          "terraform_open_ssh_rdp",
		Severity:    domain.SeverityHigh,
		Title:       "Terraform security group exposes SSH/RDP to the internet",
		Summary:     "Config appears to allow 0.0.0.0/0 access to privileged management ports.",
		Remediation: "Restrict source CIDRs and route administrative access through bastion/VPN controls.",
		Pattern:     regexp.MustCompile(`(?is)from_port\s*=\s*(22|3389).*?(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*(?:0\.0\.0\.0/0|::/0)`),
	},
}

func detectSecretFindings(repo string, commit string, path string, line int, text string, detectedAt time.Time) []domain.Finding {
	normalized := strings.TrimSpace(text)
	if normalized == "" {
		return nil
	}
	type detectedSecret struct {
		rule  secretRule
		match string
	}
	detected := make([]detectedSecret, 0, len(secretRules))
	sanitizedLine := normalized
	for _, rule := range secretRules {
		match := rule.Pattern.FindString(normalized)
		if strings.TrimSpace(match) == "" {
			continue
		}
		detected = append(detected, detectedSecret{rule: rule, match: match})
		sanitizedLine = redactMatch(sanitizedLine, match)
	}

	findings := make([]domain.Finding, 0, len(detected))
	for _, item := range detected {
		fingerprint := hashSHA256(item.match)
		id := hashDeterministicID("repo-secret", repo, commit, path, strconv.Itoa(line), item.rule.ID, fingerprint)
		findings = append(findings, domain.Finding{
			ID:                  "finding:" + id,
			Type:                domain.FindingSecretExposure,
			Severity:            item.rule.Severity,
			Title:               item.rule.Title,
			HumanSummary:        item.rule.Summary,
			Path:                []string{path},
			Commit:              commit,
			FilePath:            path,
			LineNumber:          line,
			Detector:            item.rule.ID,
			LineSnippet:         sanitizedLine,
			LineSnippetRedacted: boolPtr(true),
			Evidence: map[string]any{
				"repository":            repo,
				"commit":                commit,
				"file_path":             path,
				"line_number":           line,
				"detector":              item.rule.ID,
				"line_snippet":          sanitizedLine,
				"line_snippet_redacted": true,
				"secret_fingerprint":    fingerprint,
				"redacted_line_snip":    sanitizedLine,
				"history_source":        "commit_diff",
				"raw_secret_stored":     false,
				"secret_value_masked":   true,
			},
			Remediation: item.rule.Remediation,
			CreatedAt:   detectedAt,
		})
	}
	return findings
}

func detectMisconfigFindings(repo string, commit string, path string, content []byte, detectedAt time.Time) []domain.Finding {
	data := string(content)
	findings := []domain.Finding{}
	seen := map[string]struct{}{}
	revision := strings.TrimSpace(commit)
	if revision == "" {
		revision = "HEAD"
	}

	parserFindings, parserUsed := detectMisconfigFindingsWithParsers(repo, revision, path, content, seen, detectedAt)
	findings = append(findings, parserFindings...)

	for _, rule := range lineMisconfigRules {
		if parserUsed && shouldSkipLineRuleByParser(rule.ID, path) {
			continue
		}
		for index, line := range strings.Split(data, "\n") {
			lineNumber := index + 1
			if !rule.Pattern.MatchString(line) {
				continue
			}
			appendMisconfigFinding(&findings, seen, repo, revision, path, lineNumber, rule.ID, rule.Severity, rule.Title, rule.Summary, rule.Remediation, strings.TrimSpace(line), detectedAt,
				map[string]any{
					"line_snippet":          strings.TrimSpace(line),
					"line_snippet_redacted": false,
					"history_source":        "head_snapshot",
					"raw_secret_data":       false,
				})
		}
	}

	for _, rule := range fileMisconfigRules {
		if parserUsed && shouldSkipFileRuleByParser(rule.ID, path) {
			continue
		}
		loc := rule.Pattern.FindStringIndex(data)
		if len(loc) != 2 {
			continue
		}
		lineNumber := lineForOffset(data, loc[0])
		matchText := strings.TrimSpace(rule.Pattern.FindString(data))
		if len(matchText) > 240 {
			matchText = matchText[:240] + "..."
		}
		appendMisconfigFinding(&findings, seen, repo, revision, path, lineNumber, rule.ID, rule.Severity, rule.Title, rule.Summary, rule.Remediation, matchText, detectedAt,
			map[string]any{
				"line_snippet":          matchText,
				"line_snippet_redacted": false,
				"match_snippet":         matchText,
				"history_source":        "head_snapshot",
				"raw_secret_data":       false,
			})
	}

	return findings
}

func detectMisconfigFindingsWithParsers(repo string, commit string, path string, content []byte, seen map[string]struct{}, detectedAt time.Time) ([]domain.Finding, bool) {
	findings := []domain.Finding{}
	pathLower := strings.ToLower(strings.TrimSpace(path))
	if pathLower == "" {
		return findings, false
	}

	found := false
	if isYAMLFile(pathLower) {
		parsedFindings, ok := detectYAMLMisconfigFindings(repo, commit, path, content, seen, detectedAt)
		if !ok {
			return findings, false
		}
		findings = append(findings, parsedFindings...)
		found = true
	}

	if isTerraformFile(pathLower) {
		parsedFindings, ok := detectTerraformMisconfigFindings(repo, commit, path, content, seen, detectedAt)
		if !ok {
			return findings, false
		}
		findings = append(findings, parsedFindings...)
		found = true
	}

	if isDockerfilePath(pathLower) {
		findings = append(findings, detectDockerfileMisconfigFindings(repo, commit, path, content, seen, detectedAt)...)
		found = true
	}

	return findings, found
}

func isYAMLFile(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

func isTerraformFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(path)), ".tf")
}

func isDockerfilePath(path string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	return strings.HasPrefix(base, "dockerfile")
}

func shouldSkipLineRuleByParser(ruleID string, path string) bool {
	pathLower := strings.ToLower(strings.TrimSpace(path))
	if isYAMLFile(pathLower) {
		switch ruleID {
		case "workflow_write_all_permissions", "workflow_pull_request_target", "k8s_privileged_true":
			return true
		}
	}
	if isTerraformFile(pathLower) {
		switch ruleID {
		case "terraform_public_s3_acl":
			return true
		}
	}
	if isDockerfilePath(pathLower) {
		return ruleID == "docker_latest_tag"
	}
	return false
}

func shouldSkipFileRuleByParser(ruleID string, path string) bool {
	pathLower := strings.ToLower(strings.TrimSpace(path))
	if isTerraformFile(pathLower) {
		switch ruleID {
		case "terraform_open_ssh_rdp":
			return true
		}
	}
	if isDockerfilePath(pathLower) {
		return ruleID == "docker_latest_tag"
	}
	return false
}

func appendMisconfigFinding(
	findings *[]domain.Finding,
	seen map[string]struct{},
	repo string,
	revision string,
	path string,
	line int,
	ruleID string,
	severity domain.FindingSeverity,
	title string,
	summary string,
	remediation string,
	snippet string,
	detectedAt time.Time,
	extraEvidence map[string]any,
) {
	key := fmt.Sprintf("%s:%d:%s", path, line, ruleID)
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}

	evidence := map[string]any{
		"repository":      repo,
		"commit":          revision,
		"file_path":       path,
		"line_number":     line,
		"detector":        ruleID,
		"line_snippet":    snippet,
		"history_source":  "head_snapshot",
		"raw_secret_data": false,
	}
	for key, value := range extraEvidence {
		evidence[key] = value
	}

	id := hashDeterministicID("repo-misconfig", repo, path, strconv.Itoa(line), ruleID, snippet)
	*findings = append(*findings, domain.Finding{
		ID:                  "finding:" + id,
		Type:                domain.FindingRepoMisconfig,
		Severity:            severity,
		Title:               title,
		HumanSummary:        summary,
		Path:                []string{path},
		Commit:              revision,
		FilePath:            path,
		LineNumber:          line,
		Detector:            ruleID,
		LineSnippet:         snippet,
		LineSnippetRedacted: boolPtr(false),
		Evidence:            evidence,
		Remediation:         remediation,
		CreatedAt:           detectedAt,
	})
}

func detectYAMLMisconfigFindings(
	repo string,
	commit string,
	path string,
	content []byte,
	seen map[string]struct{},
	detectedAt time.Time,
) ([]domain.Finding, bool) {
	findings := []domain.Finding{}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	documentParsed := false

	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		documentParsed = true

		ast := &document
		if ast == nil {
			continue
		}
		if ast.Kind == 0 {
			continue
		}
		if ast.Kind == yaml.DocumentNode {
			if len(ast.Content) == 0 {
				continue
			}
			ast = ast.Content[0]
		}

		if ast.Kind != yaml.MappingNode {
			continue
		}

		for i := 0; i+1 < len(ast.Content); i += 2 {
			key := ast.Content[i]
			value := ast.Content[i+1]
			if key == nil || value == nil {
				continue
			}
			keyLower := strings.ToLower(strings.TrimSpace(key.Value))
			switch keyLower {
			case "on":
				if yamlOnUsesPullRequestTarget(value) {
					appendMisconfigFinding(&findings, seen, repo, commit, path, value.Line, "workflow_pull_request_target", domain.SeverityMedium,
						"GitHub workflow uses pull_request_target trigger", "pull_request_target can execute with elevated token context if not strictly controlled.",
						"Use pull_request where possible, pin actions, and harden token permissions for untrusted PR code.",
						"on: pull_request_target", detectedAt, map[string]any{
							"line_snippet":          "on: pull_request_target",
							"line_snippet_redacted": false,
							"history_source":        "head_snapshot",
							"match_snippet":         "on: pull_request_target",
						})
				}
			case "permissions":
				if yamlPermissionsWriteAll(value) {
					appendMisconfigFinding(&findings, seen, repo, commit, path, value.Line, "workflow_write_all_permissions", domain.SeverityHigh,
						"GitHub workflow grants broad write permissions", "Workflow permissions are set to write-all, increasing automation blast radius.",
						"Restrict workflow permissions to least-privilege per job and avoid global write-all.",
						"permissions: write-all", detectedAt, map[string]any{
							"line_snippet":          "permissions: write-all",
							"line_snippet_redacted": false,
							"history_source":        "head_snapshot",
							"match_snippet":         "permissions: write-all",
						})
				}
			case "jobs":
				if value.Kind == yaml.MappingNode {
					for idx := 0; idx+1 < len(value.Content); idx += 2 {
						job := value.Content[idx+1]
						if job == nil || job.Kind != yaml.MappingNode {
							continue
						}
						for j := 0; j+1 < len(job.Content); j += 2 {
							jobKey := job.Content[j]
							jobValue := job.Content[j+1]
							if jobKey == nil || jobValue == nil {
								continue
							}
							if strings.EqualFold(strings.TrimSpace(jobKey.Value), "permissions") && yamlPermissionsWriteAll(jobValue) {
								appendMisconfigFinding(&findings, seen, repo, commit, path, jobValue.Line, "workflow_write_all_permissions", domain.SeverityHigh,
									"GitHub workflow grants broad write permissions", "Workflow permissions are set to write-all, increasing automation blast radius.",
									"Restrict workflow permissions to least-privilege per job and avoid global write-all.",
									"permissions: write-all", detectedAt, map[string]any{
										"line_snippet":          "permissions: write-all",
										"line_snippet_redacted": false,
										"history_source":        "head_snapshot",
										"match_snippet":         "permissions: write-all",
									})
							}
						}
					}
				}
			}
		}

		findings = append(findings, findYAMLPrivilegedFindings(repo, commit, path, ast, seen, detectedAt)...)
	}

	if !documentParsed {
		return nil, false
	}

	return findings, true
}

func findYAMLPrivilegedFindings(
	repo string,
	commit string,
	path string,
	node *yaml.Node,
	seen map[string]struct{},
	detectedAt time.Time,
) []domain.Finding {
	findings := []domain.Finding{}
	walkYAMLPrivilegedNodes(repo, commit, path, node, seen, &findings, detectedAt)
	return findings
}

func walkYAMLPrivilegedNodes(
	repo string,
	commit string,
	path string,
	node *yaml.Node,
	seen map[string]struct{},
	findings *[]domain.Finding,
	detectedAt time.Time,
) {
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			if key == nil || value == nil {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(key.Value), "privileged") && yamlBoolIsTrue(value) {
				appendMisconfigFinding(findings, seen, repo, commit, path, value.Line, "k8s_privileged_true", domain.SeverityHigh,
					"Kubernetes manifest enables privileged container", "A container runs with privileged=true, which can bypass workload isolation boundaries.",
					"Set privileged=false and apply Pod Security standards with least-privilege securityContext.",
					"privileged: true", detectedAt, map[string]any{
						"line_snippet":          "privileged: true",
						"line_snippet_redacted": false,
						"history_source":        "head_snapshot",
						"match_snippet":         "privileged: true",
					})
			}
			walkYAMLPrivilegedNodes(repo, commit, path, value, seen, findings, detectedAt)
		}
		return
	}

	if node.Kind == yaml.SequenceNode {
		for _, child := range node.Content {
			walkYAMLPrivilegedNodes(repo, commit, path, child, seen, findings, detectedAt)
		}
	}
}

func yamlBoolIsTrue(node *yaml.Node) bool {
	if node.Kind != yaml.ScalarNode {
		return false
	}
	value := strings.TrimSpace(strings.ToLower(node.Value))
	return value == "true" || value == "yes"
}

func yamlOnUsesPullRequestTarget(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return strings.EqualFold(strings.TrimSpace(node.Value), "pull_request_target")
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item == nil {
				continue
			}
			if item.Kind == yaml.ScalarNode && strings.EqualFold(strings.TrimSpace(item.Value), "pull_request_target") {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key == nil {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(key.Value), "pull_request_target") {
				return true
			}
		}
	}
	return false
}

func yamlPermissionsWriteAll(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode {
		return strings.EqualFold(strings.TrimSpace(node.Value), "write-all")
	}
	if node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		value := node.Content[i+1]
		if value != nil && value.Kind == yaml.ScalarNode {
			if strings.EqualFold(strings.TrimSpace(value.Value), "write-all") {
				return true
			}
		}
	}
	return false
}

func detectTerraformMisconfigFindings(
	repo string,
	commit string,
	path string,
	content []byte,
	seen map[string]struct{},
	detectedAt time.Time,
) ([]domain.Finding, bool) {
	parsed, diags := hclsyntax.ParseConfig(content, path, hcl.InitialPos)
	if parsed == nil || len(diags) > 0 {
		for _, diag := range diags {
			if diag.Severity >= hcl.DiagError {
				return nil, false
			}
		}
	}
	if parsed == nil {
		return nil, false
	}
	body, ok := parsed.Body.(*hclsyntax.Body)
	if !ok {
		return nil, false
	}

	findings := []domain.Finding{}
	for _, block := range body.Blocks {
		if block.Type != "resource" && block.Type != "module" {
			continue
		}
		if block.Type == "resource" && len(block.Labels) < 2 {
			continue
		}
		if block.Type == "module" {
			if ingressAttribute := block.Body.Attributes["ingress"]; ingressAttribute != nil {
				appendTerraformOpenSSHRDPenaltyFindingFromIngressAttribute(&findings, seen, repo, commit, path, ingressAttribute, detectedAt)
			}
			continue
		}

		resourceType := strings.ToLower(strings.TrimSpace(block.Labels[0]))
		switch resourceType {
		case "aws_s3_bucket":
			acl, ok := terraformStringAttribute(block.Body.Attributes["acl"])
			if !ok {
				continue
			}
			if acl == "public-read" || acl == "public-read-write" {
				lineNumber := terraformAttributeLine(block.Body.Attributes["acl"])
				appendMisconfigFinding(&findings, seen, repo, commit, path, lineNumber, "terraform_public_s3_acl", domain.SeverityHigh,
					"Terraform config enables public S3 ACL", "Terraform file sets a public S3 ACL, which can expose data externally.",
					"Use private ACLs and explicit bucket policies with least-privilege principals.",
					fmt.Sprintf("acl = %q", acl), detectedAt, map[string]any{
						"line_snippet":          fmt.Sprintf("acl = %q", acl),
						"line_snippet_redacted": false,
						"history_source":        "head_snapshot",
						"match_snippet":         fmt.Sprintf("acl = %q", acl),
					})
			}

		case "aws_s3_bucket_acl":
			acl, ok := terraformStringAttribute(block.Body.Attributes["acl"])
			if !ok {
				continue
			}
			if acl == "public-read" || acl == "public-read-write" {
				lineNumber := terraformAttributeLine(block.Body.Attributes["acl"])
				appendMisconfigFinding(&findings, seen, repo, commit, path, lineNumber, "terraform_public_s3_acl", domain.SeverityHigh,
					"Terraform config enables public S3 ACL", "Terraform file sets a public S3 ACL, which can expose data externally.",
					"Use private ACLs and explicit bucket policies with least-privilege principals.",
					fmt.Sprintf("acl = %q", acl), detectedAt, map[string]any{
						"line_snippet":          fmt.Sprintf("acl = %q", acl),
						"line_snippet_redacted": false,
						"history_source":        "head_snapshot",
						"match_snippet":         fmt.Sprintf("acl = %q", acl),
					})
			}

		case "aws_security_group":
			if ingressAttribute := block.Body.Attributes["ingress"]; ingressAttribute != nil {
				appendTerraformOpenSSHRDPenaltyFindingFromIngressAttribute(&findings, seen, repo, commit, path, ingressAttribute, detectedAt)
			}
			for _, child := range block.Body.Blocks {
				if child.Type == "ingress" {
					appendTerraformOpenSSHRDPPenaltyFinding(&findings, seen, repo, commit, path, child.Body.Attributes, detectedAt)
					continue
				}
				if child.Type != "dynamic" || len(child.Labels) == 0 {
					continue
				}
				if child.Labels[0] != "ingress" {
					continue
				}
				for _, dynamicChild := range child.Body.Blocks {
					if dynamicChild.Type == "content" {
						appendTerraformOpenSSHRDPPenaltyFinding(&findings, seen, repo, commit, path, dynamicChild.Body.Attributes, detectedAt)
					}
				}
			}
		case "aws_security_group_rule":
			ruleType, ok := terraformStringAttribute(block.Body.Attributes["type"])
			if !ok {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(ruleType), "ingress") {
				continue
			}

			fromPort, fromFound := terraformIntAttribute(block.Body.Attributes["from_port"])
			toPort, toFound := terraformIntAttribute(block.Body.Attributes["to_port"])
			if !fromFound && !toFound {
				continue
			}
			if !containsSensitivePortRange(fromPort, toPort, fromFound, toFound) {
				continue
			}
			if !containsPublicCidr(block.Body.Attributes["cidr_blocks"]) && !containsPublicCidr(block.Body.Attributes["ipv6_cidr_blocks"]) {
				continue
			}

			lineNumber := terraformAttributeLine(block.Body.Attributes["from_port"])
			if !fromFound && block.Body.Attributes["to_port"] != nil {
				lineNumber = terraformAttributeLine(block.Body.Attributes["to_port"])
			}

			appendMisconfigFinding(&findings, seen, repo, commit, path, lineNumber, "terraform_open_ssh_rdp", domain.SeverityHigh,
				"Terraform security group exposes SSH/RDP to the internet", "Config appears to allow 0.0.0.0/0 access to privileged management ports.",
				"Restrict source CIDRs and route administrative access through bastion/VPN controls.",
				"security group rule exposes internet-managed ports", detectedAt, map[string]any{
					"line_snippet":          "resource \"aws_security_group_rule\" exposes internet-managed ports",
					"line_snippet_redacted": false,
					"history_source":        "head_snapshot",
					"match_snippet":         "resource \"aws_security_group_rule\"",
				})
		}
	}

	return findings, true
}

func appendTerraformOpenSSHRDPenaltyFindingFromIngressAttribute(
	findings *[]domain.Finding,
	seen map[string]struct{},
	repo string,
	commit string,
	path string,
	ingressAttribute *hclsyntax.Attribute,
	detectedAt time.Time,
) bool {
	if ingressAttribute == nil {
		return false
	}
	// Preserve literal inspection when some sub-values are unknown (for example `var.X`
	// alongside concrete CIDR/port literals).
	value, _ := ingressAttribute.Expr.Value(nil)
	if !value.IsKnown() || value.IsNull() {
		return false
	}

	lineNumber := terraformAttributeLine(ingressAttribute)
	if value.Type().IsObjectType() {
		return appendTerraformOpenSSHRDPenaltyFindingFromCtyObject(findings, seen, repo, commit, path, value, lineNumber, detectedAt)
	}

	found := false
	if value.Type().IsTupleType() || value.Type().IsListType() || value.Type().IsSetType() {
		it := value.ElementIterator()
		for it.Next() {
			_, childValue := it.Element()
			if !childValue.IsKnown() || childValue.IsNull() {
				continue
			}
			if appendTerraformOpenSSHRDPenaltyFindingFromCtyObject(findings, seen, repo, commit, path, childValue, lineNumber, detectedAt) {
				found = true
			}
		}
	}
	return found
}

func appendTerraformOpenSSHRDPenaltyFindingFromCtyObject(
	findings *[]domain.Finding,
	seen map[string]struct{},
	repo string,
	commit string,
	path string,
	value cty.Value,
	lineNumber int,
	detectedAt time.Time,
) bool {
	if !value.IsKnown() || value.IsNull() || !value.Type().IsObjectType() {
		return false
	}

	attrs := value.AsValueMap()
	if len(attrs) == 0 {
		return false
	}

	fromPort, fromFound := ctyIntAttribute(attrs["from_port"])
	toPort, toFound := ctyIntAttribute(attrs["to_port"])
	if !containsSensitivePortRange(fromPort, toPort, fromFound, toFound) {
		return false
	}
	publicIPv4 := containsPublicCidrCtyValue(attrs["cidr_blocks"])
	publicIPv6 := containsPublicCidrCtyValue(attrs["ipv6_cidr_blocks"])
	if !publicIPv4 && !publicIPv6 {
		return false
	}

	appendMisconfigFinding(findings, seen, repo, commit, path, lineNumber, "terraform_open_ssh_rdp", domain.SeverityHigh,
		"Terraform security group exposes SSH/RDP to the internet", "Config appears to allow 0.0.0.0/0 access to privileged management ports.",
		"Restrict source CIDRs and route administrative access through bastion/VPN controls.",
		"security group rule exposes internet-managed ports", detectedAt, map[string]any{
			"line_snippet":          "security group rule exposes internet-managed ports",
			"line_snippet_redacted": false,
			"history_source":        "head_snapshot",
			"match_snippet":         "module ingress",
		})
	return true
}

func appendTerraformOpenSSHRDPPenaltyFinding(
	findings *[]domain.Finding,
	seen map[string]struct{},
	repo string,
	commit string,
	path string,
	attributes map[string]*hclsyntax.Attribute,
	detectedAt time.Time,
) bool {
	fromPort, fromFound := terraformIntAttribute(attributes["from_port"])
	toPort, toFound := terraformIntAttribute(attributes["to_port"])
	if !fromFound && !toFound {
		return false
	}
	if !containsSensitivePortRange(fromPort, toPort, fromFound, toFound) {
		return false
	}
	if !containsPublicCidr(attributes["cidr_blocks"]) && !containsPublicCidr(attributes["ipv6_cidr_blocks"]) {
		return false
	}

	lineNumber := terraformAttributeLine(attributes["from_port"])
	if !fromFound && attributes["to_port"] != nil {
		lineNumber = terraformAttributeLine(attributes["to_port"])
	}

	appendMisconfigFinding(findings, seen, repo, commit, path, lineNumber, "terraform_open_ssh_rdp", domain.SeverityHigh,
		"Terraform security group exposes SSH/RDP to the internet", "Config appears to allow 0.0.0.0/0 access to privileged management ports.",
		"Restrict source CIDRs and route administrative access through bastion/VPN controls.",
		"security group rule exposes internet-managed ports", detectedAt, map[string]any{
			"line_snippet":          "security group rule exposes internet-managed ports",
			"line_snippet_redacted": false,
			"history_source":        "head_snapshot",
			"match_snippet":         "ingress",
		})
	return true
}

func terraformAttributeLine(attribute *hclsyntax.Attribute) int {
	if attribute == nil {
		return 1
	}
	if attribute.Expr == nil {
		return attribute.NameRange.Start.Line
	}
	if attribute.Expr.Range().Empty() {
		return attribute.NameRange.Start.Line
	}
	return attribute.Expr.Range().Start.Line
}

func terraformStringAttribute(attribute *hclsyntax.Attribute) (string, bool) {
	if attribute == nil {
		return "", false
	}
	value, diagnostics := attribute.Expr.Value(nil)
	if diagnostics.HasErrors() {
		return "", false
	}
	if !value.IsKnown() || value.IsNull() {
		return "", false
	}
	if value.Type() != cty.String {
		return "", false
	}
	return strings.TrimSpace(value.AsString()), true
}

func terraformIntAttribute(attribute *hclsyntax.Attribute) (int, bool) {
	if attribute == nil {
		return 0, false
	}
	value, diagnostics := attribute.Expr.Value(nil)
	if diagnostics.HasErrors() {
		return 0, false
	}
	if !value.IsKnown() || value.IsNull() {
		return 0, false
	}
	if value.Type() != cty.Number {
		return 0, false
	}
	f32, _ := value.AsBigFloat().Float64()
	if math.Trunc(f32) != f32 {
		return 0, false
	}
	return int(f32), true
}

func containsSensitivePortRange(fromPort int, toPort int, fromFound bool, toFound bool) bool {
	if !fromFound && !toFound {
		return false
	}
	if !fromFound {
		fromPort = toPort
	}
	if !toFound {
		toPort = fromPort
	}
	for _, port := range []int{22, 3389} {
		if fromPort <= port && port <= toPort {
			return true
		}
	}
	return false
}

func ctyIntAttribute(attribute cty.Value) (int, bool) {
	if !attribute.IsKnown() || attribute.IsNull() {
		return 0, false
	}
	if attribute.Type() != cty.Number {
		return 0, false
	}
	f32, _ := attribute.AsBigFloat().Float64()
	if math.Trunc(f32) != f32 {
		return 0, false
	}
	return int(f32), true
}

func containsPublicCidrCtyValue(attribute cty.Value) bool {
	if !attribute.IsKnown() || attribute.IsNull() {
		return false
	}

	if attribute.Type() == cty.String {
		return isPublicCidr(strings.TrimSpace(strings.ToLower(attribute.AsString())))
	}

	if attribute.Type().IsTupleType() || attribute.Type().IsListType() || attribute.Type().IsSetType() {
		it := attribute.ElementIterator()
		for it.Next() {
			_, childValue := it.Element()
			if !childValue.IsKnown() || childValue.IsNull() || childValue.Type() != cty.String {
				continue
			}
			if isPublicCidr(strings.TrimSpace(strings.ToLower(childValue.AsString()))) {
				return true
			}
		}
	}

	return false
}

func isPublicCidr(value string) bool {
	return value == "0.0.0.0/0" || value == "::/0"
}

func containsPublicCidr(attribute *hclsyntax.Attribute) bool {
	if attribute == nil {
		return false
	}
	values, ok := terraformStringListAttribute(attribute)
	if !ok {
		return false
	}
	for _, value := range values {
		clean := strings.TrimSpace(strings.ToLower(value))
		if clean == "0.0.0.0/0" || clean == "::/0" {
			return true
		}
	}
	return false
}

func terraformStringListAttribute(attribute *hclsyntax.Attribute) ([]string, bool) {
	if attribute == nil {
		return nil, false
	}
	return terraformStringListExpr(attribute.Expr)
}

func terraformStringListExpr(expression hclsyntax.Expression) ([]string, bool) {
	if expression == nil {
		return nil, false
	}

	value, diagnostics := expression.Value(nil)
	if !diagnostics.HasErrors() && value.IsKnown() && !value.IsNull() {
		if value.Type() == cty.String {
			return []string{strings.TrimSpace(value.AsString())}, true
		}
		if value.Type().IsTupleType() || value.Type().IsListType() || value.Type().IsSetType() {
			ret := make([]string, 0)
			iterator := value.ElementIterator()
			for iterator.Next() {
				_, childValue := iterator.Element()
				if !childValue.IsKnown() || childValue.IsNull() || childValue.Type() != cty.String {
					return nil, false
				}
				ret = append(ret, strings.TrimSpace(childValue.AsString()))
			}
			if len(ret) > 0 {
				return ret, true
			}
		}
	}

	if tupleExpr, isTupleExpr := expression.(*hclsyntax.TupleConsExpr); isTupleExpr {
		values := make([]string, 0, len(tupleExpr.Exprs))
		for _, expr := range tupleExpr.Exprs {
			childValue, childDiagnostics := expr.Value(nil)
			if childDiagnostics.HasErrors() || !childValue.IsKnown() || childValue.IsNull() {
				continue
			}
			if childValue.Type() == cty.String {
				values = append(values, strings.TrimSpace(childValue.AsString()))
			}
		}
		if len(values) > 0 {
			return values, true
		}
	}

	return nil, false
}

func detectDockerfileMisconfigFindings(
	repo string,
	commit string,
	path string,
	content []byte,
	seen map[string]struct{},
	detectedAt time.Time,
) []domain.Finding {
	findings := []domain.Finding{}
	reader := bufio.NewReader(bytes.NewReader(content))
	lineNumber := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if len(line) == 0 {
					break
				}
			} else {
				break
			}
		}

		lineNumber++
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if err == io.EOF {
				break
			}
			continue
		}

		if isDockerfileBaseImagePinnedToLatest(trimmed) {
			appendMisconfigFinding(&findings, seen, repo, commit, path, lineNumber, "docker_latest_tag", domain.SeverityMedium,
				"Docker image uses mutable latest tag", "Using :latest weakens supply-chain determinism and patch traceability.",
				"Pin base images by immutable version/digest and review updates through CI.",
				trimmed, detectedAt, map[string]any{
					"line_snippet":          trimmed,
					"line_snippet_redacted": false,
					"history_source":        "head_snapshot",
					"match_snippet":         "latest",
				})
		}

		if err == io.EOF {
			break
		}
	}

	return findings
}

func isDockerfileBaseImagePinnedToLatest(line string) bool {
	commentless := line
	if idx := strings.Index(commentless, "#"); idx >= 0 {
		commentless = commentless[:idx]
	}
	commentless = strings.TrimSpace(commentless)
	if commentless == "" {
		return false
	}

	parts := strings.Fields(commentless)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "FROM") {
		return false
	}

	imageIndex := 1
	for imageIndex < len(parts) {
		if strings.EqualFold(parts[imageIndex], "as") {
			return false
		}
		if !strings.HasPrefix(parts[imageIndex], "--") {
			break
		}
		if strings.Contains(parts[imageIndex], "=") {
			imageIndex++
			continue
		}
		imageIndex += 2
	}
	if imageIndex >= len(parts) {
		return false
	}

	image := strings.TrimSpace(parts[imageIndex])
	if image == "" {
		return false
	}
	if strings.Contains(image, "@") {
		return false
	}
	segments := strings.Split(image, "/")
	base := segments[len(segments)-1]
	if !strings.Contains(base, ":") {
		return false
	}
	partsByTag := strings.Split(base, ":")
	if len(partsByTag) < 2 {
		return false
	}
	tag := partsByTag[len(partsByTag)-1]
	return strings.EqualFold(strings.TrimSpace(tag), "latest")
}

func boolPtr(value bool) *bool {
	return &value
}

func shouldInspectMisconfiguration(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(lower))
	if strings.HasPrefix(lower, ".github/workflows/") {
		return true
	}
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") {
		return true
	}
	for _, ext := range []string{".tf", ".yml", ".yaml"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func lineForOffset(content string, offset int) int {
	if offset <= 0 {
		return 1
	}
	return bytes.Count([]byte(content[:offset]), []byte("\n")) + 1
}
