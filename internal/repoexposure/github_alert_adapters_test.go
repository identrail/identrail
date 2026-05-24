package repoexposure

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestGitHubSecretScanningAlertsNormalizeAndRedact(t *testing.T) {
	alerts := []GitHubSecretScanningAlert{
		{
			Number:                3,
			State:                 "open",
			SecretType:            "github_personal_access_token",
			SecretTypeDisplayName: "GitHub Personal Access Token",
			Validity:              "active",
			HTMLURL:               "https://github.com/owner/repo/security/secret-scanning/3",
		},
	}
	findings, err := NormalizeGitHubSecretScanningAlerts(context.Background(), "owner/repo", "abc123", alerts, time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("normalize secret scanning alerts: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != domain.FindingSecretExposure {
		t.Fatalf("expected secret exposure finding, got %+v", finding)
	}
	if finding.Severity != domain.SeverityCritical {
		t.Fatalf("expected active secret to map to critical, got %s", finding.Severity)
	}
	if finding.LineSnippet != redactedExternalSecretEvidence {
		t.Fatalf("expected redacted snippet marker, got %q", finding.LineSnippet)
	}
	if finding.LineSnippetRedacted == nil || !*finding.LineSnippetRedacted {
		t.Fatalf("expected redacted snippet flag, got %+v", finding.LineSnippetRedacted)
	}
	if finding.SourceURL != alerts[0].HTMLURL {
		t.Fatalf("expected source url preserved, got %q", finding.SourceURL)
	}
	if got, _ := finding.Evidence["raw_secret_stored"].(bool); got {
		t.Fatal("raw_secret_stored must be false")
	}
	if got, _ := finding.Evidence["secret_value_masked"].(bool); !got {
		t.Fatalf("expected secret_value_masked flag, got %+v", finding.Evidence)
	}
	if got := finding.Evidence["adapter_secret_type"]; got != "github_personal_access_token" {
		t.Fatalf("expected secret type evidence, got %v", got)
	}
	if got := finding.Evidence["adapter_source_type"]; got != adapterSourceGitHubSecretScanning {
		t.Fatalf("expected adapter source type, got %v", got)
	}
}

func TestGitHubSecretScanningSeverityMappingAndSkips(t *testing.T) {
	cases := map[string]domain.FindingSeverity{
		"active":   domain.SeverityCritical,
		"inactive": domain.SeverityHigh,
		"unknown":  domain.SeverityHigh,
		"":         domain.SeverityHigh,
	}
	number := 1
	for validity, want := range cases {
		alerts := []GitHubSecretScanningAlert{{Number: number, State: "open", SecretType: "generic", Validity: validity}}
		number++
		findings, err := NormalizeGitHubSecretScanningAlerts(context.Background(), "owner/repo", "", alerts, time.Now())
		if err != nil {
			t.Fatalf("normalize (%q): %v", validity, err)
		}
		if len(findings) != 1 {
			t.Fatalf("validity %q: expected one finding, got %d", validity, len(findings))
		}
		if findings[0].Severity != want {
			t.Fatalf("validity %q: expected %s, got %s", validity, want, findings[0].Severity)
		}
	}

	resolved := []GitHubSecretScanningAlert{{Number: 99, State: "resolved", SecretType: "generic"}}
	findings, err := NormalizeGitHubSecretScanningAlerts(context.Background(), "owner/repo", "", resolved, time.Now())
	if err != nil {
		t.Fatalf("normalize resolved: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected resolved alerts to be skipped, got %d", len(findings))
	}
}

func TestGitHubSecretScanningAlertsDedupe(t *testing.T) {
	alert := GitHubSecretScanningAlert{Number: 5, State: "open", SecretType: "stripe_api_key", Validity: "active"}
	findings, err := NormalizeGitHubSecretScanningAlerts(context.Background(), "owner/repo", "", []GitHubSecretScanningAlert{alert, alert}, time.Now())
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected duplicate alerts to collapse to one, got %d", len(findings))
	}
}

func TestGitHubDependabotAlertsNormalizeEvidence(t *testing.T) {
	alerts := []GitHubDependabotAlert{
		{
			Number: 7,
			State:  "open",
			Dependency: GitHubDependabotDependency{
				Package:      GitHubDependabotPackage{Ecosystem: "pip", Name: "django"},
				ManifestPath: "requirements.txt",
				Scope:        "runtime",
			},
			SecurityAdvisory: GitHubDependabotAdvisory{
				GHSAID:   "GHSA-xxxx-yyyy-zzzz",
				CVEID:    "CVE-2024-0001",
				Summary:  "SQL injection in django",
				Severity: "high",
				Identifiers: []GitHubDependabotAdvisoryIdentity{
					{Type: "GHSA", Value: "GHSA-xxxx-yyyy-zzzz"},
					{Type: "CVE", Value: "CVE-2024-0001"},
				},
			},
			SecurityVulnerability: GitHubDependabotVulnerable{
				Package:                GitHubDependabotPackage{Ecosystem: "pip", Name: "django"},
				Severity:               "high",
				VulnerableVersionRange: "< 4.2.1",
				FirstPatchedVersion:    GitHubDependabotPatch{Identifier: "4.2.1"},
			},
			HTMLURL: "https://github.com/owner/repo/security/dependabot/7",
		},
	}
	findings, err := NormalizeGitHubDependabotAlerts(context.Background(), "owner/repo", "abc123", alerts, time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("normalize dependabot alerts: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != domain.FindingRepoMisconfig || finding.Severity != domain.SeverityHigh {
		t.Fatalf("unexpected dependabot finding classification: %+v", finding)
	}
	if finding.FilePath != "requirements.txt" {
		t.Fatalf("expected manifest path as file path, got %q", finding.FilePath)
	}
	if finding.SourceURL != alerts[0].HTMLURL {
		t.Fatalf("expected source url preserved, got %q", finding.SourceURL)
	}
	if got := finding.Evidence["adapter_ecosystem"]; got != "pip" {
		t.Fatalf("expected ecosystem evidence, got %v", got)
	}
	if got := finding.Evidence["adapter_package"]; got != "django" {
		t.Fatalf("expected package evidence, got %v", got)
	}
	if got := finding.Evidence["adapter_advisory_ghsa"]; got != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("expected GHSA evidence, got %v", got)
	}
	if got := finding.Evidence["adapter_advisory_cve"]; got != "CVE-2024-0001" {
		t.Fatalf("expected CVE evidence, got %v", got)
	}
	if got := finding.Evidence["adapter_vulnerable_range"]; got != "< 4.2.1" {
		t.Fatalf("expected vulnerable range evidence, got %v", got)
	}
	if got := finding.Evidence["adapter_first_patched_version"]; got != "4.2.1" {
		t.Fatalf("expected fixed version evidence, got %v", got)
	}
	identifiers, ok := finding.Evidence["adapter_advisory_identifiers"].([]string)
	if !ok || len(identifiers) != 2 {
		t.Fatalf("expected two advisory identifiers, got %+v", finding.Evidence["adapter_advisory_identifiers"])
	}
	if got, _ := finding.Evidence["raw_adapter_result_stored"].(bool); got {
		t.Fatal("dependabot findings must not store raw external result payloads")
	}
	if !strings.Contains(finding.Remediation, "4.2.1") {
		t.Fatalf("expected remediation to mention fixed version, got %q", finding.Remediation)
	}
}

func TestGitHubDependabotSeverityMappingAndSkips(t *testing.T) {
	cases := map[string]domain.FindingSeverity{
		"critical": domain.SeverityCritical,
		"high":     domain.SeverityHigh,
		"moderate": domain.SeverityMedium,
		"medium":   domain.SeverityMedium,
		"low":      domain.SeverityLow,
		"":         domain.SeverityMedium,
	}
	number := 1
	for severity, want := range cases {
		alerts := []GitHubDependabotAlert{{
			Number:           number,
			State:            "open",
			Dependency:       GitHubDependabotDependency{Package: GitHubDependabotPackage{Ecosystem: "npm", Name: "pkg"}},
			SecurityAdvisory: GitHubDependabotAdvisory{GHSAID: "GHSA-test", Severity: severity},
		}}
		number++
		findings, err := NormalizeGitHubDependabotAlerts(context.Background(), "owner/repo", "", alerts, time.Now())
		if err != nil {
			t.Fatalf("normalize (%q): %v", severity, err)
		}
		if len(findings) != 1 {
			t.Fatalf("severity %q: expected one finding, got %d", severity, len(findings))
		}
		if findings[0].Severity != want {
			t.Fatalf("severity %q: expected %s, got %s", severity, want, findings[0].Severity)
		}
	}

	for _, state := range []string{"fixed", "dismissed"} {
		alerts := []GitHubDependabotAlert{{
			Number:           500,
			State:            state,
			Dependency:       GitHubDependabotDependency{Package: GitHubDependabotPackage{Name: "pkg"}},
			SecurityAdvisory: GitHubDependabotAdvisory{GHSAID: "GHSA-test", Severity: "high"},
		}}
		findings, err := NormalizeGitHubDependabotAlerts(context.Background(), "owner/repo", "", alerts, time.Now())
		if err != nil {
			t.Fatalf("normalize %q: %v", state, err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected %q alerts to be skipped, got %d", state, len(findings))
		}
	}
}

func TestGitHubDependabotAlertsDedupe(t *testing.T) {
	alert := GitHubDependabotAlert{
		Number:           11,
		State:            "open",
		Dependency:       GitHubDependabotDependency{Package: GitHubDependabotPackage{Ecosystem: "go", Name: "golang.org/x/net"}, ManifestPath: "go.mod"},
		SecurityAdvisory: GitHubDependabotAdvisory{GHSAID: "GHSA-dup", Severity: "high"},
	}
	findings, err := NormalizeGitHubDependabotAlerts(context.Background(), "owner/repo", "", []GitHubDependabotAlert{alert, alert}, time.Now())
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected duplicate alerts to collapse to one, got %d", len(findings))
	}
}
