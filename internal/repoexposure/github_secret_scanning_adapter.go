package repoexposure

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

const adapterSourceGitHubSecretScanning = "github_secret_scanning"

// GitHubSecretScanningAlert is the subset of GitHub's secret-scanning alert API
// needed to normalize alerts into Identrail repo findings. The raw secret value
// is intentionally absent: it is never fetched, deserialized, or stored.
type GitHubSecretScanningAlert struct {
	Number                int    `json:"number"`
	State                 string `json:"state"`
	SecretType            string `json:"secret_type"`
	SecretTypeDisplayName string `json:"secret_type_display_name"`
	Validity              string `json:"validity"`
	Resolution            string `json:"resolution"`
	PushProtectionBypass  bool   `json:"push_protection_bypassed"`
	HTMLURL               string `json:"html_url"`
}

// GitHubSecretScanningAlertAdapter imports GitHub secret-scanning alerts that
// were already fetched through the GitHub App connector.
type GitHubSecretScanningAlertAdapter struct {
	alerts []GitHubSecretScanningAlert
}

func NewGitHubSecretScanningAlertAdapter(alerts []GitHubSecretScanningAlert) GitHubSecretScanningAlertAdapter {
	return GitHubSecretScanningAlertAdapter{alerts: append([]GitHubSecretScanningAlert(nil), alerts...)}
}

func (a GitHubSecretScanningAlertAdapter) Name() string {
	return adapterSourceGitHubSecretScanning
}

func (a GitHubSecretScanningAlertAdapter) Version() string {
	return externalAdapterVersion
}

func (a GitHubSecretScanningAlertAdapter) Findings(ctx context.Context, input ExternalAdapterInput) ([]domain.Finding, error) {
	return NormalizeGitHubSecretScanningAlerts(ctx, input.Repository, input.Commit, a.alerts, input.DetectedAt)
}

// NormalizeGitHubSecretScanningAlerts converts GitHub secret-scanning alerts
// into redacted secret-exposure repo findings. No raw secret material is ever
// stored: the snippet is a redacted marker and only the secret type label,
// validity, and alert metadata are kept as evidence.
func NormalizeGitHubSecretScanningAlerts(ctx context.Context, repository string, commit string, alerts []GitHubSecretScanningAlert, detectedAt time.Time) ([]domain.Finding, error) {
	findings := []domain.Finding{}
	seen := map[string]struct{}{}
	for _, alert := range alerts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		finding, ok := githubSecretScanningAlertToFinding(repository, commit, alert, detectedAt)
		if !ok {
			continue
		}
		duplicate := false
		for _, key := range repoFindingDedupeKeys(finding) {
			if _, exists := seen[key]; exists {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		findings = append(findings, finding)
		for _, key := range repoFindingDedupeKeys(finding) {
			seen[key] = struct{}{}
		}
	}
	return findings, nil
}

func githubSecretScanningAlertToFinding(repository string, commit string, alert GitHubSecretScanningAlert, detectedAt time.Time) (domain.Finding, bool) {
	if strings.EqualFold(strings.TrimSpace(alert.State), "resolved") {
		return domain.Finding{}, false
	}
	secretType := strings.TrimSpace(alert.SecretType)
	displayName := firstNonEmpty(alert.SecretTypeDisplayName, secretType, "secret")
	ruleID := firstNonEmpty(secretType, strconv.Itoa(alert.Number), "unknown")
	detector := adapterDetectorID(adapterSourceGitHubSecretScanning, "github-secret-scanning", ruleID)
	validity := strings.ToLower(strings.TrimSpace(alert.Validity))
	severity, severitySource := githubSecretScanningSeverity(validity)
	confidence := githubSecretScanningConfidence(validity)
	dedupeKey := strings.Join([]string{
		adapterSourceGitHubSecretScanning,
		strings.ToLower(strings.TrimSpace(repository)),
		strings.ToLower(ruleID),
		strconv.Itoa(alert.Number),
	}, "|")

	evidence := map[string]any{
		"repository":                repository,
		"line_snippet":              redactedExternalSecretEvidence,
		"line_snippet_redacted":     true,
		"detector":                  detector,
		"adapter_name":              adapterSourceGitHubSecretScanning,
		"adapter_version":           externalAdapterVersion,
		"adapter_source_type":       adapterSourceGitHubSecretScanning,
		"adapter_tool_name":         "github-secret-scanning",
		"adapter_rule_id":           ruleID,
		"adapter_rule_name":         displayName,
		"adapter_secret_type":       secretType,
		"adapter_alert_number":      alert.Number,
		"adapter_alert_state":       strings.TrimSpace(alert.State),
		"adapter_secret_validity":   validity,
		"adapter_confidence":        confidence,
		"adapter_confidence_source": "github_secret_scanning_validity",
		"adapter_severity_source":   severitySource,
		"adapter_dedupe_key":        dedupeKey,
		"adapter_message_redacted":  true,
		"history_source":            externalAdapterHistorySource,
		"raw_secret_stored":         false,
		"secret_value_masked":       true,
		"raw_adapter_result_stored": false,
	}
	if commit != "" {
		evidence["commit"] = commit
	}
	if strings.TrimSpace(alert.Resolution) != "" {
		evidence["adapter_alert_resolution"] = strings.TrimSpace(alert.Resolution)
	}
	if alert.PushProtectionBypass {
		evidence["adapter_push_protection_bypassed"] = true
	}
	if alert.HTMLURL != "" {
		evidence["adapter_alert_url"] = alert.HTMLURL
	}

	id := "finding:" + hashDeterministicID(
		"repo-adapter",
		adapterSourceGitHubSecretScanning,
		repository,
		strconv.Itoa(alert.Number),
		ruleID,
	)
	return domain.Finding{
		ID:                  id,
		Type:                domain.FindingSecretExposure,
		Severity:            severity,
		ConfidenceScore:     confidence,
		Title:               "GitHub secret scanning: " + displayName,
		HumanSummary:        "GitHub secret scanning reported an open secret-exposure alert; raw secret material was not stored.",
		Path:                nil,
		Repository:          repository,
		Commit:              commit,
		Detector:            detector,
		LineSnippet:         redactedExternalSecretEvidence,
		LineSnippetRedacted: boolPtr(true),
		SourceURL:           strings.TrimSpace(alert.HTMLURL),
		Evidence:            evidence,
		Remediation:         "Rotate and revoke the exposed credential, then remove it from repository history where needed and move it to a secret manager.",
		CreatedAt:           detectedAt,
	}, true
}

func githubSecretScanningSeverity(validity string) (domain.FindingSeverity, string) {
	switch validity {
	case "active":
		return domain.SeverityCritical, "secret_scanning_validity"
	case "inactive":
		return domain.SeverityHigh, "secret_scanning_validity"
	default:
		return domain.SeverityHigh, "default"
	}
}

func githubSecretScanningConfidence(validity string) float64 {
	if validity == "active" {
		return 0.99
	}
	return 0.90
}

var _ ExternalFindingAdapter = GitHubSecretScanningAlertAdapter{}
