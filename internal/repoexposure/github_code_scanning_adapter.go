package repoexposure

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

const adapterSourceGitHubCodeScanning = "github_code_scanning"

// GitHubCodeScanningAlert is the subset of GitHub's code-scanning alert API
// needed to normalize alerts into Identrail repo findings.
type GitHubCodeScanningAlert struct {
	Number             int                             `json:"number"`
	State              string                          `json:"state"`
	Rule               GitHubCodeScanningRule          `json:"rule"`
	Tool               GitHubCodeScanningTool          `json:"tool"`
	MostRecentInstance GitHubCodeScanningAlertInstance `json:"most_recent_instance"`
	HTMLURL            string                          `json:"html_url"`
}

type GitHubCodeScanningRule struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Severity              string   `json:"severity"`
	Description           string   `json:"description"`
	SecuritySeverityLevel string   `json:"security_severity_level"`
	Tags                  []string `json:"tags"`
}

type GitHubCodeScanningTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type GitHubCodeScanningAlertInstance struct {
	Ref         string                     `json:"ref"`
	AnalysisKey string                     `json:"analysis_key"`
	Category    string                     `json:"category"`
	State       string                     `json:"state"`
	CommitSHA   string                     `json:"commit_sha"`
	Message     GitHubCodeScanningMessage  `json:"message"`
	Location    GitHubCodeScanningLocation `json:"location"`
}

type GitHubCodeScanningMessage struct {
	Text string `json:"text"`
}

type GitHubCodeScanningLocation struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`
}

// GitHubCodeScanningAlertAdapter imports GitHub code-scanning alerts that were
// already fetched through the GitHub App connector.
type GitHubCodeScanningAlertAdapter struct {
	alerts []GitHubCodeScanningAlert
}

func NewGitHubCodeScanningAlertAdapter(alerts []GitHubCodeScanningAlert) GitHubCodeScanningAlertAdapter {
	return GitHubCodeScanningAlertAdapter{alerts: append([]GitHubCodeScanningAlert(nil), alerts...)}
}

func (a GitHubCodeScanningAlertAdapter) Name() string {
	return adapterSourceGitHubCodeScanning
}

func (a GitHubCodeScanningAlertAdapter) Version() string {
	return externalAdapterVersion
}

func (a GitHubCodeScanningAlertAdapter) Findings(ctx context.Context, input ExternalAdapterInput) ([]domain.Finding, error) {
	return NormalizeGitHubCodeScanningAlerts(ctx, input.Repository, input.Commit, a.alerts, input.DetectedAt)
}

// NormalizeGitHubCodeScanningAlerts converts GitHub code-scanning alerts into
// the same repo-finding model used by native repository scanning.
func NormalizeGitHubCodeScanningAlerts(ctx context.Context, repository string, commit string, alerts []GitHubCodeScanningAlert, detectedAt time.Time) ([]domain.Finding, error) {
	findings := []domain.Finding{}
	seen := map[string]struct{}{}
	for _, alert := range alerts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		finding, ok := githubCodeScanningAlertToFinding(repository, commit, alert, detectedAt)
		if !ok {
			continue
		}
		for _, key := range repoFindingDedupeKeys(finding) {
			if _, exists := seen[key]; exists {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		findings = append(findings, finding)
		for _, key := range repoFindingDedupeKeys(finding) {
			seen[key] = struct{}{}
		}
	}
	return findings, nil
}

func githubCodeScanningAlertToFinding(repository string, commit string, alert GitHubCodeScanningAlert, detectedAt time.Time) (domain.Finding, bool) {
	path := normalizeAdapterPath(alert.MostRecentInstance.Location.Path)
	line := alert.MostRecentInstance.Location.StartLine
	if path == "" || line <= 0 {
		return domain.Finding{}, false
	}
	ruleID := firstNonEmpty(alert.Rule.ID, alert.Rule.Name, strconv.Itoa(alert.Number), "unknown")
	toolName := firstNonEmpty(alert.Tool.Name, "github-code-scanning")
	toolVersion := firstNonEmpty(alert.Tool.Version, externalAdapterVersion)
	alertCommit := firstNonEmpty(alert.MostRecentInstance.CommitSHA, commit)
	secretLike := isSecretLikeAdapterResult(ruleID, alert.Rule.Name, alert.Rule.Description, alert.MostRecentInstance.Message.Text, alert.Rule.Tags)
	severity, severitySource := githubCodeScanningSeverity(alert)
	confidence := githubCodeScanningConfidence(alert.Rule.SecuritySeverityLevel, alert.Rule.Severity)
	detector := adapterDetectorID(adapterSourceGitHubCodeScanning, toolName, ruleID)
	message := sanitizeAdapterText(firstNonEmpty(alert.MostRecentInstance.Message.Text, alert.Rule.Description))
	snippet := message
	findingType := domain.FindingRepoMisconfig
	lineRedacted := false
	title := "GitHub code scanning: " + firstNonEmpty(alert.Rule.Name, ruleID)
	summary := firstNonEmpty(message, "GitHub code scanning reported an open repository alert.")
	remediation := "Review the GitHub code-scanning alert and remediate the affected repository path."
	if secretLike {
		findingType = domain.FindingSecretExposure
		lineRedacted = true
		snippet = redactedExternalSecretEvidence
		summary = "GitHub code scanning reported a secret-like repository alert; raw secret material was not stored."
		remediation = "Rotate the affected credential, remove it from repository history where needed, and move it to a secret manager."
	}

	evidence := map[string]any{
		"repository":                repository,
		"commit":                    alertCommit,
		"file_path":                 path,
		"line_number":               line,
		"line_snippet":              snippet,
		"line_snippet_redacted":     lineRedacted,
		"detector":                  detector,
		"adapter_name":              adapterSourceGitHubCodeScanning,
		"adapter_version":           externalAdapterVersion,
		"adapter_source_type":       adapterSourceGitHubCodeScanning,
		"adapter_tool_name":         toolName,
		"adapter_tool_version":      toolVersion,
		"adapter_rule_id":           ruleID,
		"adapter_rule_name":         firstNonEmpty(alert.Rule.Name, alert.Rule.Description),
		"adapter_alert_number":      alert.Number,
		"adapter_alert_state":       strings.TrimSpace(alert.State),
		"adapter_instance_state":    strings.TrimSpace(alert.MostRecentInstance.State),
		"adapter_confidence":        confidence,
		"adapter_confidence_source": "github_code_scanning_rule",
		"adapter_severity_source":   severitySource,
		"adapter_location_path":     path,
		"adapter_location_line":     line,
		"adapter_location_column":   alert.MostRecentInstance.Location.StartColumn,
		"adapter_dedupe_key":        externalAdapterDedupeKey(repository, findingType, path, line, detector, snippet),
		"history_source":            externalAdapterHistorySource,
		"raw_secret_stored":         false,
		"raw_adapter_result_stored": false,
	}
	if !secretLike && message != "" {
		evidence["adapter_message"] = message
	}
	if secretLike {
		evidence["adapter_message_redacted"] = true
		evidence["secret_value_masked"] = true
	}
	if alert.HTMLURL != "" {
		evidence["adapter_alert_url"] = alert.HTMLURL
	}

	id := "finding:" + hashDeterministicID(
		"repo-adapter",
		adapterSourceGitHubCodeScanning,
		repository,
		strconv.Itoa(alert.Number),
		path,
		strconv.Itoa(line),
		detector,
		hashSHA256(firstNonEmpty(alert.MostRecentInstance.Message.Text, alert.Rule.Description, ruleID)),
	)
	return domain.Finding{
		ID:                  id,
		Type:                findingType,
		Severity:            severity,
		ConfidenceScore:     confidence,
		Title:               title,
		HumanSummary:        summary,
		Path:                []string{path},
		Repository:          repository,
		Commit:              alertCommit,
		FilePath:            path,
		LineNumber:          line,
		Detector:            detector,
		LineSnippet:         snippet,
		LineSnippetRedacted: boolPtr(lineRedacted),
		SourceURL:           strings.TrimSpace(alert.HTMLURL),
		Evidence:            evidence,
		Remediation:         remediation,
		CreatedAt:           detectedAt,
	}, true
}

func githubCodeScanningSeverity(alert GitHubCodeScanningAlert) (domain.FindingSeverity, string) {
	switch strings.ToLower(strings.TrimSpace(alert.Rule.SecuritySeverityLevel)) {
	case "critical":
		return domain.SeverityCritical, "security_severity_level"
	case "high":
		return domain.SeverityHigh, "security_severity_level"
	case "medium", "moderate":
		return domain.SeverityMedium, "security_severity_level"
	case "low":
		return domain.SeverityLow, "security_severity_level"
	}
	switch strings.ToLower(strings.TrimSpace(alert.Rule.Severity)) {
	case "critical":
		return domain.SeverityCritical, "rule_severity"
	case "error", "high":
		return domain.SeverityHigh, "rule_severity"
	case "warning", "medium":
		return domain.SeverityMedium, "rule_severity"
	case "note", "recommendation", "low":
		return domain.SeverityLow, "rule_severity"
	case "none", "info", "informational":
		return domain.SeverityInfo, "rule_severity"
	default:
		return domain.SeverityMedium, "default"
	}
}

func githubCodeScanningConfidence(securitySeverityLevel string, severity string) float64 {
	if strings.TrimSpace(securitySeverityLevel) != "" {
		return 0.90
	}
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "error", "warning":
		return 0.80
	case "note", "recommendation":
		return 0.65
	default:
		return 0.70
	}
}

var _ ExternalFindingAdapter = SARIFAdapter{}
var _ ExternalFindingAdapter = GitHubCodeScanningAlertAdapter{}
