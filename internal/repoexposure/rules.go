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

type secretDetectorPattern struct {
	Regexp       *regexp.Regexp
	CaptureGroup int
	MinLength    int
	MaxLength    int
	EntropyMin   float64
	EntropyMax   float64
}

type secretDetector struct {
	ID          string
	Severity    domain.FindingSeverity
	Confidence  float64
	Title       string
	Summary     string
	Remediation string
	Provider    string
	Category    string
	Version     string
	Examples    []string
	Patterns    []secretDetectorPattern
}

const (
	secretConfidenceClassifierVersion = "2026.05"

	secretClassificationHighConfidence    = "high_confidence"
	secretClassificationMediumConfidence  = "medium_confidence"
	secretClassificationSamplePlaceholder = "sample_or_placeholder"
	secretClassificationTestFixture       = "test_fixture"
	secretClassificationAllowlisted       = "allowlisted"
)

type secretFindingPolicy struct {
	AllowlistedFingerprints map[string]struct{}
}

type secretFindingOptions struct {
	Policy secretFindingPolicy
}

type secretFindingOption func(*secretFindingOptions)

func withSecretFindingPolicy(policy secretFindingPolicy) secretFindingOption {
	return func(options *secretFindingOptions) {
		options.Policy = policy
	}
}

type secretConfidenceClassification struct {
	State       string
	Score       float64
	Reasons     []string
	Allowlisted bool
}

var secretFingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

var secretDetectorRegistry = []secretDetector{
	{
		ID:          "aws_access_key_id",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.98,
		Title:       "Potential AWS access key exposed in commit history",
		Provider:    "AWS",
		Category:    "cloud_credentials",
		Summary:     "A line added in commit history appears to contain an AWS access key identifier.",
		Remediation: "Rotate the key, purge secrets from history, and move credentials to a secret manager.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
				MinLength: 20,
			},
		},
	},
	{
		ID:          "aws_secret_access_key",
		Version:     "2026.05",
		Severity:    domain.SeverityCritical,
		Confidence:  0.96,
		Title:       "Potential AWS secret key exposed in commit history",
		Provider:    "AWS",
		Category:    "cloud_credentials",
		Summary:     "A line added in commit history appears to contain an AWS secret access key.",
		Remediation: "Rotate affected credentials immediately and replace static secrets with short-lived credentials.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:       regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret|aws_access_key_secret)\b\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
				CaptureGroup: 1,
				MinLength:    40,
				MaxLength:    120,
			},
		},
	},
	{
		ID:          "github_token",
		Version:     "2026.05",
		Severity:    domain.SeverityCritical,
		Confidence:  0.98,
		Title:       "Potential GitHub token exposed in commit history",
		Provider:    "GitHub",
		Category:    "source_control",
		Summary:     "A line added in commit history appears to contain a GitHub token.",
		Remediation: "Revoke the token immediately, rotate dependent credentials, and enforce secret scanning in CI.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
			{Regexp: regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`)},
			{Regexp: regexp.MustCompile(`\bghu_[A-Za-z0-9]{36}\b`)},
			{Regexp: regexp.MustCompile(`\bghr_[A-Za-z0-9]{36}\b`)},
			{Regexp: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{40,}\b`)},
		},
	},
	{
		ID:          "github_app_token",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.95,
		Title:       "Potential GitHub App token exposed in commit history",
		Provider:    "GitHub",
		Category:    "source_control",
		Summary:     "A line added in commit history appears to contain a GitHub App token.",
		Remediation: "Rotate GitHub App credentials and replace with vault-backed credentials.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bghs_[A-Za-z0-9]{40,}\b`)},
		},
	},
	{
		ID:          "slack_token",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.92,
		Title:       "Potential Slack token exposed in commit history",
		Provider:    "Slack",
		Category:    "collaboration",
		Summary:     "A line added in commit history appears to contain a Slack token.",
		Remediation: "Revoke and rotate the token in Slack, then remove token usage from repository files.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bxox(?:b|p|o|r|s|a|x)-[A-Za-z0-9-]{10,}\b`)},
		},
	},
	{
		ID:          "gitlab_token",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.92,
		Title:       "Potential GitLab token exposed in commit history",
		Provider:    "GitLab",
		Category:    "source_control",
		Summary:     "A line added in commit history appears to contain a GitLab token.",
		Remediation: "Revoke the token and rotate with repository-integrated credential rotation where possible.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
		},
	},
	{
		ID:          "azure_service_secret",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.90,
		Title:       "Potential Azure application secret exposed in commit history",
		Provider:    "Azure",
		Category:    "cloud_credentials",
		Summary:     "A line added in commit history appears to contain an Azure application secret.",
		Remediation: "Rotate application secrets and use managed identities where possible.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:       regexp.MustCompile(`(?i)(?:azure_client_secret|AZURE_CLIENT_SECRET)\s*[:=]\s*['"]?([A-Za-z0-9~!@#$%^&*()_+=\-]{35,})['"]?`),
				CaptureGroup: 1,
				MinLength:    35,
				EntropyMin:   3.3,
			},
		},
	},
	{
		ID:          "gcp_api_key",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.92,
		Title:       "Potential Google API key exposed in commit history",
		Provider:    "Google",
		Category:    "cloud_credentials",
		Summary:     "A line added in commit history appears to contain a Google API key.",
		Remediation: "Rotate the API key immediately and scope/limit the affected project APIs.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bAIza[0-9A-Za-z-_]{35}\b`)},
		},
	},
	{
		ID:          "stripe_api_key",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.94,
		Title:       "Potential Stripe key exposed in commit history",
		Provider:    "Stripe",
		Category:    "payments",
		Summary:     "A line added in commit history appears to contain Stripe keys.",
		Remediation: "Revoke leaked Stripe keys and rotate restricted tokens.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b`)},
			{Regexp: regexp.MustCompile(`\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b`)},
		},
	},
	{
		ID:          "openai_api_key",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.94,
		Title:       "Potential OpenAI token exposed in commit history",
		Provider:    "OpenAI",
		Category:    "ai_api",
		Summary:     "A line added in commit history appears to contain an OpenAI API key.",
		Remediation: "Revoke the key and regenerate a replacement with scoped limits.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bsk-[A-Za-z0-9]{48,}\b`)},
			{Regexp: regexp.MustCompile(`\bsk-proj-[A-Za-z0-9]{40,}\b`)},
		},
	},
	{
		ID:          "workos_api_key",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.92,
		Title:       "Potential WorkOS token exposed in commit history",
		Provider:    "WorkOS",
		Category:    "identity_platform",
		Summary:     "A line added in commit history appears to contain a WorkOS key or token.",
		Remediation: "Revoke leaked WorkOS credentials and replace with secure vault-backed secrets.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:     regexp.MustCompile(`\bworkos_(?:live|test)_[A-Za-z0-9_-]{20,}\b`),
				MinLength:  30,
				EntropyMin: 3.3,
			},
		},
	},
	{
		ID:          "vercel_token",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.92,
		Title:       "Potential Vercel token exposed in commit history",
		Provider:    "Vercel",
		Category:    "deployment_platform",
		Summary:     "A line added in commit history appears to contain a Vercel token.",
		Remediation: "Rotate the token and remove static tokens from repository history.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bvercel_pat_[A-Za-z0-9-_=]{24,}\b`)},
		},
	},
	{
		ID:          "npm_token",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.86,
		Title:       "Potential npm access token exposed in commit history",
		Provider:    "npm",
		Category:    "package_registry",
		Summary:     "A line added in commit history appears to contain an npm token.",
		Remediation: "Revoke the token and regenerate access tokens with publish scope minimized.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:       regexp.MustCompile(`(?i)\b(?:npm_)?(?:token|_authtoken|_auth)\b\s*[:=]\s*['"]?([A-Za-z0-9_]{16,})['"]?`),
				CaptureGroup: 1,
			},
		},
	},
	{
		ID:          "dockerhub_token",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.90,
		Title:       "Potential Docker Hub token exposed in commit history",
		Provider:    "Docker Hub",
		Category:    "container_registry",
		Summary:     "A line added in commit history appears to contain a Docker Hub token.",
		Remediation: "Revoke and regenerate credentials; enforce Docker Hub token rotation.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9=_-]{30,}\b`)},
		},
	},
	{
		ID:          "private_key_material",
		Version:     "2026.05",
		Severity:    domain.SeverityCritical,
		Confidence:  0.99,
		Title:       "Private key material exposed in commit history",
		Provider:    "General",
		Category:    "credential_storage",
		Summary:     "A line added in commit history contains private key header material.",
		Remediation: "Revoke and rotate affected keys, remove key files from history, and store keys in a vault/KMS.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)},
		},
	},
	{
		ID:          "tls_key_material",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.72,
		Title:       "TLS material exposed in commit history",
		Provider:    "General",
		Category:    "infrastructure_security",
		Summary:     "A line added in commit history appears to contain TLS key or certificate material.",
		Remediation: "Reissue TLS certificates/keys and remove static private material from source control.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)},
		},
	},
	{
		ID:          "jwt_token",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.82,
		Title:       "Potential JWT exposed in commit history",
		Provider:    "General",
		Category:    "identity_tokens",
		Summary:     "A line added in commit history appears to contain a JWT-like bearer value.",
		Remediation: "Rotate signing keys and revoke sessions using this token family.",
		Patterns: []secretDetectorPattern{
			{Regexp: regexp.MustCompile(`\beyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]{10,}\b`)},
		},
	},
	{
		ID:          "database_connection_url",
		Version:     "2026.05",
		Severity:    domain.SeverityMedium,
		Confidence:  0.86,
		Title:       "Potential database URL with embedded credentials",
		Provider:    "General",
		Category:    "configuration",
		Summary:     "A line added in commit history appears to include a database URL with inline credentials.",
		Remediation: "Move connection credentials to a secret store and use short-lived runtime env injection.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:     regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mysql2|mssql|redis|mongodb|mongodb\+srv|cockroach|oracle)://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+`),
				MinLength:  24,
				EntropyMin: 2.8,
			},
		},
	},
	{
		ID:          "oauth_client_secret",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.80,
		Title:       "Potential OAuth client secret exposed in commit history",
		Provider:    "General",
		Category:    "identity_tokens",
		Summary:     "A line added in commit history appears to contain an OAuth client secret.",
		Remediation: "Regenerate client secrets and remove hardcoded values from repository files.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:       regexp.MustCompile(`(?i)\b(?:client_secret|oauth_secret)\s*[:=]\s*['"]?([A-Za-z0-9-_.=]{20,})['"]?`),
				CaptureGroup: 1,
				MinLength:    20,
				EntropyMin:   3.1,
			},
		},
	},
	{
		ID:          "webhook_secret",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.78,
		Title:       "Potential webhook signing secret exposed in commit history",
		Provider:    "General",
		Category:    "webhooks",
		Summary:     "A line added in commit history appears to include webhook signing secret material.",
		Remediation: "Regenerate webhook secrets and verify endpoint webhook validation logic.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:       regexp.MustCompile(`(?i)\bwebhook(?:_?)secret\b\s*[:=]\s*['"]?([A-Za-z0-9\-_]{16,})['"]?`),
				CaptureGroup: 1,
				MinLength:    16,
				EntropyMin:   2.8,
			},
		},
	},
	{
		ID:          "ci_cd_token",
		Version:     "2026.05",
		Severity:    domain.SeverityHigh,
		Confidence:  0.82,
		Title:       "Potential CI/CD token exposed in commit history",
		Provider:    "General",
		Category:    "ci_cd",
		Summary:     "A line added in commit history appears to contain CI/CD platform token material.",
		Remediation: "Rotate the token and move CI/CD secrets to runner-protected variable vaults.",
		Patterns: []secretDetectorPattern{
			{
				Regexp:       regexp.MustCompile(`(?i)\b(?:CI_JOB_TOKEN|ACTIONS_RUNTIME_TOKEN|CIRCLE_TOKEN|TRAVIS_TOKEN|GITLAB_CI_TOKEN|CODECOV_TOKEN)\b\s*[:=]\s*['"]?([A-Za-z0-9-_=]{16,})['"]?`),
				CaptureGroup: 1,
				MinLength:    16,
			},
		},
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

func detectSecretFindings(repo string, commit string, path string, line int, text string, detectedAt time.Time, options ...secretFindingOption) []domain.Finding {
	normalized := strings.TrimSpace(text)
	if normalized == "" {
		return nil
	}
	secretOptions := secretFindingOptions{}
	for _, option := range options {
		if option != nil {
			option(&secretOptions)
		}
	}
	type detectedSecret struct {
		rule  secretDetector
		match string
		value string
	}
	detected := make([]detectedSecret, 0, len(secretDetectorRegistry))
	sanitizedLine := normalized
	for _, rule := range secretDetectorRegistry {
		match, value := detectSecretMatch(normalized, rule)
		if strings.TrimSpace(match) == "" {
			continue
		}
		detected = append(detected, detectedSecret{rule: rule, match: match, value: value})
		sanitizedLine = redactMatch(sanitizedLine, match)
	}

	findings := make([]domain.Finding, 0, len(detected))
	for _, item := range detected {
		secretMaterial := strings.TrimSpace(item.value)
		if secretMaterial == "" {
			secretMaterial = item.match
		}
		fingerprint := hashSHA256(secretMaterial)
		classification := classifySecretMatch(item.rule, path, item.match, secretMaterial, fingerprint, secretOptions.Policy)
		id := hashDeterministicID("repo-secret", repo, commit, path, strconv.Itoa(line), item.rule.ID, fingerprint)
		findings = append(findings, domain.Finding{
			ID:                  "finding:" + id,
			Type:                domain.FindingSecretExposure,
			Severity:            item.rule.Severity,
			ConfidenceScore:     classification.Score,
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
				"detector_version":      item.rule.Version,
				"detector_category":     item.rule.Category,
				"detector_provider":     item.rule.Provider,
				"history_source":        "commit_diff",
				"raw_secret_stored":     false,
				"secret_value_masked":   true,
				"confidence_score":      classification.Score,
				"confidence_state":      classification.State,
				"confidence_reasons":    classification.Reasons,
				"confidence_source":     "repo_secret_classifier_v" + secretConfidenceClassifierVersion,
				"secret_allowlisted":    classification.Allowlisted,
			},
			Remediation: item.rule.Remediation,
			CreatedAt:   detectedAt,
		})
	}
	return findings
}

func parseSecretFindingPolicy(content []byte) secretFindingPolicy {
	policy := secretFindingPolicy{AllowlistedFingerprints: map[string]struct{}{}}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if index := strings.Index(line, "#"); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		fingerprint := normalizeSecretFingerprint(line)
		if fingerprint == "" {
			continue
		}
		policy.AllowlistedFingerprints[fingerprint] = struct{}{}
	}
	if len(policy.AllowlistedFingerprints) == 0 {
		policy.AllowlistedFingerprints = nil
	}
	return policy
}

func normalizeSecretFingerprint(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"secret-fingerprint:", "secret_fingerprint:", "secret-fingerprint=", "secret_fingerprint=", "sha256:", "sha256=", "secret:", "secret="} {
		if strings.HasPrefix(normalized, prefix) {
			normalized = strings.TrimSpace(strings.TrimPrefix(normalized, prefix))
			break
		}
	}
	if secretFingerprintPattern.MatchString(normalized) {
		return normalized
	}
	return ""
}

func classifySecretMatch(rule secretDetector, filePath string, line string, secretMaterial string, fingerprint string, policy secretFindingPolicy) secretConfidenceClassification {
	reasons := []string{"detector:" + rule.ID, fmt.Sprintf("detector_confidence:%.2f", baseSecretDetectorConfidence(rule))}
	if _, allowlisted := policy.AllowlistedFingerprints[strings.ToLower(strings.TrimSpace(fingerprint))]; allowlisted {
		return secretConfidenceClassification{
			State:       secretClassificationAllowlisted,
			Score:       0.05,
			Reasons:     append(reasons, "fingerprint_allowlisted"),
			Allowlisted: true,
		}
	}

	score := baseSecretDetectorConfidence(rule)
	state := ""
	testFixturePath := isSecretTestFixturePath(filePath)
	samplePath := isSecretSamplePath(filePath)
	if !testFixturePath && !samplePath && isProductionSecretPath(filePath) {
		score += 0.03
		reasons = append(reasons, "path_context:production_secret_file")
	}
	if testFixturePath {
		state = secretClassificationTestFixture
		score = math.Min(score, 0.35)
		reasons = append(reasons, "path_context:test_fixture")
	}
	if samplePath {
		if state == "" {
			state = secretClassificationSamplePlaceholder
		}
		score = math.Min(score, 0.40)
		reasons = append(reasons, "path_context:sample_or_docs")
	}

	placeholderReasons := secretPlaceholderReasons(line, secretMaterial)
	if len(placeholderReasons) > 0 {
		if state == "" {
			state = secretClassificationSamplePlaceholder
		}
		score = math.Min(score, 0.25)
		reasons = append(reasons, placeholderReasons...)
	}

	score = roundSecretConfidenceScore(clampSecretConfidence(score))
	if state == "" {
		if score >= 0.85 {
			state = secretClassificationHighConfidence
		} else {
			state = secretClassificationMediumConfidence
		}
	}
	return secretConfidenceClassification{State: state, Score: score, Reasons: reasons}
}

func baseSecretDetectorConfidence(rule secretDetector) float64 {
	if rule.Confidence > 0 {
		return clampSecretConfidence(rule.Confidence)
	}
	switch rule.Severity {
	case domain.SeverityCritical:
		return 0.94
	case domain.SeverityHigh:
		return 0.86
	case domain.SeverityMedium:
		return 0.74
	default:
		return 0.65
	}
}

func clampSecretConfidence(score float64) float64 {
	if score < 0.01 {
		return 0.01
	}
	if score > 0.99 {
		return 0.99
	}
	return score
}

func roundSecretConfidenceScore(score float64) float64 {
	return math.Round(score*100) / 100
}

func isSecretTestFixturePath(filePath string) bool {
	normalized := normalizeSecretPath(filePath)
	base := filepath.Base(normalized)
	return strings.HasSuffix(base, "_test.go") ||
		strings.HasPrefix(normalized, "testdata/") ||
		strings.HasPrefix(normalized, "tests/") ||
		strings.HasPrefix(normalized, "fixtures/") ||
		strings.HasPrefix(normalized, "fixture/") ||
		strings.HasPrefix(normalized, "__fixtures__/") ||
		strings.Contains(normalized, "/testdata/") ||
		strings.Contains(normalized, "/tests/") ||
		strings.Contains(normalized, "/fixtures/") ||
		strings.Contains(normalized, "/fixture/") ||
		strings.Contains(normalized, "/__fixtures__/")
}

func isSecretSamplePath(filePath string) bool {
	normalized := normalizeSecretPath(filePath)
	base := filepath.Base(normalized)
	return strings.HasPrefix(normalized, "docs/") ||
		strings.HasPrefix(normalized, "examples/") ||
		strings.HasPrefix(normalized, "example/") ||
		strings.HasPrefix(normalized, "samples/") ||
		strings.HasPrefix(normalized, "sample/") ||
		strings.Contains(normalized, "/docs/") ||
		strings.Contains(normalized, "/examples/") ||
		strings.Contains(normalized, "/example/") ||
		strings.Contains(normalized, "/samples/") ||
		strings.Contains(normalized, "/sample/") ||
		base == "readme.md" ||
		base == ".env.example" ||
		base == ".env.sample" ||
		base == "env.example" ||
		base == "env.sample" ||
		strings.HasSuffix(base, ".example") ||
		strings.HasSuffix(base, ".sample")
}

func isProductionSecretPath(filePath string) bool {
	normalized := normalizeSecretPath(filePath)
	base := filepath.Base(normalized)
	switch base {
	case ".env", "app.env", "secrets.env", "secret.env", "credentials.env", "config.env":
		return true
	}
	return strings.HasPrefix(normalized, "secrets/") ||
		strings.HasPrefix(normalized, "credentials/") ||
		strings.Contains(normalized, "/secrets/") ||
		strings.Contains(normalized, "/credentials/")
}

func normalizeSecretPath(filePath string) string {
	normalized := filepath.ToSlash(strings.TrimSpace(filePath))
	normalized = strings.TrimPrefix(normalized, "./")
	return strings.ToLower(normalized)
}

func secretPlaceholderReasons(line string, secretMaterial string) []string {
	lowerMaterial := strings.ToLower(strings.TrimSpace(secretMaterial))
	lowerLine := strings.ToLower(strings.TrimSpace(line))
	reasons := []string{}
	for _, marker := range []string{"example", "changeme", "change_me", "dummy", "fake", "sample", "placeholder", "notasecret", "not_a_secret", "replace_me", "your_", "todo", "testsecret", "test_secret", "test-secret", "sk_test_", "pk_test_"} {
		if strings.Contains(lowerMaterial, marker) || strings.Contains(lowerLine, marker) {
			reasons = append(reasons, "value_marker:"+marker)
			break
		}
	}

	compact := compactSecretValue(secretMaterial)
	if len(compact) >= 12 && isRepeatedOrLowVarietySecret(compact) {
		reasons = append(reasons, "value_shape:repeated_or_low_variety")
	}
	if len(compact) >= 16 && containsSequentialSecretPattern(compact) {
		reasons = append(reasons, "value_shape:sequential")
	}
	if len(compact) >= 16 && entropy(secretMaterial) < 2.6 && !strings.Contains(lowerMaterial, "-----begin ") {
		reasons = append(reasons, "value_entropy:low")
	}
	return reasons
}

func compactSecretValue(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func isRepeatedOrLowVarietySecret(compact string) bool {
	seen := map[rune]struct{}{}
	for _, r := range compact {
		seen[r] = struct{}{}
	}
	if len(seen) <= 3 {
		return true
	}
	for size := 2; size <= 8; size++ {
		if len(compact)%size != 0 {
			continue
		}
		prefix := compact[:size]
		if strings.Repeat(prefix, len(compact)/size) == compact {
			return true
		}
	}
	return false
}

func containsSequentialSecretPattern(compact string) bool {
	for _, pattern := range []string{
		"0123456789abcdef",
		"abcdef0123456789",
		"1234567890abcdef",
		"abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnop",
	} {
		if strings.Contains(compact, pattern) {
			return true
		}
	}
	return false
}

func detectSecretMatch(text string, rule secretDetector) (match string, value string) {
	for _, pattern := range rule.Patterns {
		found, value := pattern.match(text)
		if strings.TrimSpace(found) != "" {
			return found, value
		}
	}
	return "", ""
}

func (pattern secretDetectorPattern) match(text string) (match string, value string) {
	submatches := pattern.Regexp.FindStringSubmatch(text)
	if len(submatches) == 0 {
		return "", ""
	}

	fullMatch := strings.TrimSpace(submatches[0])
	if fullMatch == "" {
		return "", ""
	}
	idx := 0
	if pattern.CaptureGroup > 0 && pattern.CaptureGroup < len(submatches) {
		idx = pattern.CaptureGroup
	}

	candidate := strings.TrimSpace(submatches[idx])
	if candidate == "" {
		candidate = fullMatch
	}

	if pattern.MinLength > 0 && len(candidate) < pattern.MinLength {
		return "", ""
	}
	if pattern.MaxLength > 0 && len(candidate) > pattern.MaxLength {
		return "", ""
	}
	if pattern.EntropyMin > 0 && entropy(candidate) < pattern.EntropyMin {
		return "", ""
	}
	if pattern.EntropyMax > 0 && entropy(candidate) > pattern.EntropyMax {
		return "", ""
	}

	return fullMatch, candidate
}

func entropy(value string) float64 {
	if len(value) <= 1 {
		return 0
	}

	frequencies := map[rune]int{}
	for _, r := range value {
		frequencies[r]++
	}

	n := float64(len(value))
	entropy := 0.0
	for _, count := range frequencies {
		probability := float64(count) / n
		entropy -= probability * math.Log2(probability)
	}
	return entropy
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
