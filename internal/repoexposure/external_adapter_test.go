package repoexposure

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestIngestSARIFNormalizesEvidenceSeverityAndDedupe(t *testing.T) {
	content := []byte(`{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Semgrep",
        "semanticVersion": "1.99.0",
        "rules": [{
          "id": "go.lang.security.audit.crypto.math_random",
          "name": "Weak random number generator",
          "shortDescription": {"text": "Weak random number generator"},
          "help": {"text": "Use crypto/rand for security-sensitive values."},
          "properties": {"precision": "high", "security-severity": "8.1", "tags": ["security"]}
        }]
      }
    },
    "results": [
      {
        "ruleId": "go.lang.security.audit.crypto.math_random",
        "level": "warning",
        "message": {"text": "math/rand is not safe for security-sensitive identifiers."},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "internal/token.go"},
            "region": {"startLine": 42, "startColumn": 7, "snippet": {"text": "id := rand.Int()"}}
          }
        }]
      },
      {
        "ruleId": "go.lang.security.audit.crypto.math_random",
        "level": "warning",
        "message": {"text": "math/rand is not safe for security-sensitive identifiers."},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "internal/token.go"},
            "region": {"startLine": 42, "startColumn": 7, "snippet": {"text": "id := rand.Int()"}}
          }
        }]
      }
    ]
  }]
}`)
	detectedAt := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	findings, err := IngestSARIF(context.Background(), "owner/repo", "abc123", content, detectedAt)
	if err != nil {
		t.Fatalf("ingest SARIF: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected duplicate SARIF results to collapse to one finding, got %d: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.Type != domain.FindingRepoMisconfig || finding.Severity != domain.SeverityHigh {
		t.Fatalf("unexpected finding classification: %+v", finding)
	}
	if finding.ConfidenceScore != 0.90 {
		t.Fatalf("expected high precision confidence, got %.2f", finding.ConfidenceScore)
	}
	if finding.LineSnippetRedacted == nil || *finding.LineSnippetRedacted {
		t.Fatalf("expected non-secret SARIF snippet to remain visible, got %+v", finding.LineSnippetRedacted)
	}
	if got := finding.Evidence["adapter_name"]; got != "Semgrep" {
		t.Fatalf("expected adapter name Semgrep, got %v", got)
	}
	if got := finding.Evidence["adapter_version"]; got != "1.99.0" {
		t.Fatalf("expected adapter version, got %v", got)
	}
	if got := finding.Evidence["adapter_rule_id"]; got != "go.lang.security.audit.crypto.math_random" {
		t.Fatalf("expected rule id in evidence, got %v", got)
	}
	if got := finding.Evidence["adapter_location_line"]; got != 42 {
		t.Fatalf("expected location line in evidence, got %v", got)
	}
	if got, _ := finding.Evidence["raw_adapter_result_stored"].(bool); got {
		t.Fatal("adapter findings must not store raw external result payloads")
	}
}

func TestIngestSARIFRedactsSecretLikeEvidence(t *testing.T) {
	rawSecret := strings.Join([]string{"ghp_", "0123456789abcdef0123456789abcdef0123"}, "")
	content := []byte(`{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Gitleaks",
        "version": "8.18.0",
        "rules": [{
          "id": "gitleaks.generic-api-key",
          "name": "Generic API secret",
          "properties": {"tags": ["secrets", "credential"]}
        }]
      }
    },
    "results": [{
      "ruleId": "gitleaks.generic-api-key",
      "level": "error",
      "message": {"text": "hard-coded token ` + rawSecret + `"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": ".env"},
          "region": {"startLine": 3, "snippet": {"text": "GITHUB_TOKEN=` + rawSecret + `"}}
        }
      }]
    }]
  }]
}`)
	findings, err := IngestSARIF(context.Background(), "owner/repo", "abc123", content, time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ingest SARIF: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != domain.FindingSecretExposure {
		t.Fatalf("expected secret exposure finding, got %+v", finding)
	}
	if strings.Contains(finding.LineSnippet, rawSecret) || strings.Contains(finding.HumanSummary, rawSecret) {
		t.Fatalf("secret-like adapter evidence leaked raw secret: %+v", finding)
	}
	if finding.LineSnippetRedacted == nil || !*finding.LineSnippetRedacted {
		t.Fatalf("expected redacted snippet flag, got %+v", finding.LineSnippetRedacted)
	}
	if _, exists := finding.Evidence["adapter_message"]; exists {
		t.Fatalf("secret-like adapter message must not be stored verbatim: %+v", finding.Evidence)
	}
	if got, _ := finding.Evidence["raw_secret_stored"].(bool); got {
		t.Fatal("raw_secret_stored must be false")
	}
	if got, _ := finding.Evidence["secret_value_masked"].(bool); !got {
		t.Fatalf("expected secret_value_masked evidence flag, got %+v", finding.Evidence)
	}
}

func TestGitHubCodeScanningAlertsNormalizeToRepoFindings(t *testing.T) {
	alerts := []GitHubCodeScanningAlert{
		{
			Number: 7,
			State:  "open",
			Rule: GitHubCodeScanningRule{
				ID:                    "js/sql-injection",
				Name:                  "SQL query built from user-controlled sources",
				Severity:              "warning",
				SecuritySeverityLevel: "high",
				Tags:                  []string{"security", "external/cwe/cwe-089"},
			},
			Tool: GitHubCodeScanningTool{Name: "CodeQL", Version: "2.17.0"},
			MostRecentInstance: GitHubCodeScanningAlertInstance{
				State:     "open",
				CommitSHA: "def456",
				Message:   GitHubCodeScanningMessage{Text: "Query string includes user input."},
				Location:  GitHubCodeScanningLocation{Path: "src/db.ts", StartLine: 88, StartColumn: 11},
			},
			HTMLURL: "https://github.com/owner/repo/security/code-scanning/7",
		},
	}
	findings, err := NormalizeGitHubCodeScanningAlerts(context.Background(), "owner/repo", "abc123", alerts, time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("normalize alerts: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != domain.FindingRepoMisconfig || finding.Severity != domain.SeverityHigh {
		t.Fatalf("unexpected GitHub code scanning finding: %+v", finding)
	}
	if finding.SourceURL != alerts[0].HTMLURL {
		t.Fatalf("expected source URL to be preserved, got %q", finding.SourceURL)
	}
	if got := finding.Evidence["adapter_tool_name"]; got != "CodeQL" {
		t.Fatalf("expected CodeQL tool evidence, got %v", got)
	}
	if got := finding.Evidence["adapter_rule_id"]; got != "js/sql-injection" {
		t.Fatalf("expected rule id evidence, got %v", got)
	}
}

func TestMergeExternalFindingsDedupeNativeAndAdapterFlood(t *testing.T) {
	native := domain.Finding{
		ID:          "finding:native",
		Type:        domain.FindingRepoMisconfig,
		Repository:  "owner/repo",
		FilePath:    ".github/workflows/ci.yml",
		LineNumber:  9,
		Detector:    "workflow_write_all_permissions",
		LineSnippet: "permissions: write-all",
		Evidence: map[string]any{
			"repository":   "owner/repo",
			"file_path":    ".github/workflows/ci.yml",
			"line_number":  9,
			"detector":     "workflow_write_all_permissions",
			"line_snippet": "permissions: write-all",
		},
	}
	external := domain.Finding{
		ID:          "finding:adapter",
		Type:        domain.FindingRepoMisconfig,
		Repository:  "owner/repo",
		FilePath:    ".github/workflows/ci.yml",
		LineNumber:  9,
		Detector:    "sarif:semgrep:github-actions-write-all",
		LineSnippet: "permissions: write-all",
		Evidence: map[string]any{
			"adapter_name": "Semgrep",
		},
	}
	merged, truncated := MergeExternalFindings([]domain.Finding{native}, []domain.Finding{external}, 10)
	if truncated {
		t.Fatal("did not expect merge to truncate")
	}
	if len(merged) != 1 {
		t.Fatalf("expected native/adapter duplicate to collapse, got %+v", merged)
	}
}

type staticExternalAdapter struct {
	findings []domain.Finding
}

func (s staticExternalAdapter) Name() string { return "static-test" }

func (s staticExternalAdapter) Version() string { return "test" }

func (s staticExternalAdapter) Findings(context.Context, ExternalAdapterInput) ([]domain.Finding, error) {
	return s.findings, nil
}

func TestScanRepositoryRunsOptInExternalAdapters(t *testing.T) {
	repoPath, headCommit := initTestRepoWithHeadMisconfig(t)
	external := domain.Finding{
		ID:          "finding:external-only",
		Type:        domain.FindingRepoMisconfig,
		Severity:    domain.SeverityLow,
		Repository:  repoPath,
		Commit:      headCommit,
		FilePath:    "README.md",
		LineNumber:  1,
		Detector:    "sarif:example:readme-rule",
		LineSnippet: "README finding",
		Evidence: map[string]any{
			"adapter_name": "Example",
		},
		CreatedAt: time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
	}
	scanner := NewScanner(nil,
		WithHistoryLimit(10),
		WithMaxFindings(20),
		WithExternalAdapters(staticExternalAdapter{findings: []domain.Finding{external}}),
	)
	result, err := scanner.ScanRepository(context.Background(), repoPath)
	if err != nil {
		t.Fatalf("scan repository: %v", err)
	}
	found := false
	for _, finding := range result.Findings {
		if finding.ID == "finding:external-only" {
			found = true
			if got := finding.Evidence["raw_adapter_result_stored"]; got != false {
				t.Fatalf("expected adapter safety evidence, got %v", got)
			}
		}
	}
	if !found {
		t.Fatalf("expected external adapter finding in scan result, got %+v", result.Findings)
	}
}
