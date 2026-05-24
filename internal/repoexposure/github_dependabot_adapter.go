package repoexposure

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

const adapterSourceGitHubDependabot = "github_dependabot"

// GitHubDependabotAlert is the subset of GitHub's Dependabot alert API needed to
// normalize alerts into Identrail repo findings. None of these fields carry
// secret material.
type GitHubDependabotAlert struct {
	Number                int                        `json:"number"`
	State                 string                     `json:"state"`
	Dependency            GitHubDependabotDependency `json:"dependency"`
	SecurityAdvisory      GitHubDependabotAdvisory   `json:"security_advisory"`
	SecurityVulnerability GitHubDependabotVulnerable `json:"security_vulnerability"`
	HTMLURL               string                     `json:"html_url"`
}

type GitHubDependabotDependency struct {
	Package      GitHubDependabotPackage `json:"package"`
	ManifestPath string                  `json:"manifest_path"`
	Scope        string                  `json:"scope"`
}

type GitHubDependabotPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type GitHubDependabotAdvisory struct {
	GHSAID      string                             `json:"ghsa_id"`
	CVEID       string                             `json:"cve_id"`
	Summary     string                             `json:"summary"`
	Severity    string                             `json:"severity"`
	Identifiers []GitHubDependabotAdvisoryIdentity `json:"identifiers"`
}

type GitHubDependabotAdvisoryIdentity struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type GitHubDependabotVulnerable struct {
	Package                GitHubDependabotPackage `json:"package"`
	Severity               string                  `json:"severity"`
	VulnerableVersionRange string                  `json:"vulnerable_version_range"`
	FirstPatchedVersion    GitHubDependabotPatch   `json:"first_patched_version"`
}

type GitHubDependabotPatch struct {
	Identifier string `json:"identifier"`
}

// GitHubDependabotAlertAdapter imports GitHub Dependabot alerts that were
// already fetched through the GitHub App connector.
type GitHubDependabotAlertAdapter struct {
	alerts []GitHubDependabotAlert
}

func NewGitHubDependabotAlertAdapter(alerts []GitHubDependabotAlert) GitHubDependabotAlertAdapter {
	return GitHubDependabotAlertAdapter{alerts: append([]GitHubDependabotAlert(nil), alerts...)}
}

func (a GitHubDependabotAlertAdapter) Name() string {
	return adapterSourceGitHubDependabot
}

func (a GitHubDependabotAlertAdapter) Version() string {
	return externalAdapterVersion
}

func (a GitHubDependabotAlertAdapter) Findings(ctx context.Context, input ExternalAdapterInput) ([]domain.Finding, error) {
	return NormalizeGitHubDependabotAlerts(ctx, input.Repository, input.Commit, a.alerts, input.DetectedAt)
}

// NormalizeGitHubDependabotAlerts converts GitHub Dependabot vulnerability
// alerts into repository findings with non-secret package, advisory, and
// severity evidence.
func NormalizeGitHubDependabotAlerts(ctx context.Context, repository string, commit string, alerts []GitHubDependabotAlert, detectedAt time.Time) ([]domain.Finding, error) {
	findings := []domain.Finding{}
	seen := map[string]struct{}{}
	for _, alert := range alerts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		finding, ok := githubDependabotAlertToFinding(repository, commit, alert, detectedAt)
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

func githubDependabotAlertToFinding(repository string, commit string, alert GitHubDependabotAlert, detectedAt time.Time) (domain.Finding, bool) {
	if strings.EqualFold(strings.TrimSpace(alert.State), "fixed") || strings.EqualFold(strings.TrimSpace(alert.State), "dismissed") {
		return domain.Finding{}, false
	}
	ecosystem := firstNonEmpty(alert.Dependency.Package.Ecosystem, alert.SecurityVulnerability.Package.Ecosystem)
	packageName := firstNonEmpty(alert.Dependency.Package.Name, alert.SecurityVulnerability.Package.Name)
	ghsaID := strings.TrimSpace(alert.SecurityAdvisory.GHSAID)
	cveID := strings.TrimSpace(alert.SecurityAdvisory.CVEID)
	advisoryID := firstNonEmpty(ghsaID, cveID, strconv.Itoa(alert.Number))
	if packageName == "" && advisoryID == "" {
		return domain.Finding{}, false
	}
	manifest := normalizeAdapterPath(alert.Dependency.ManifestPath)
	ruleID := strings.ToLower(strings.Join(nonEmptyStrings(ecosystem, packageName, advisoryID), ":"))
	detector := adapterDetectorID(adapterSourceGitHubDependabot, firstNonEmpty(ecosystem, "dependabot"), advisoryID)
	severity, severitySource := githubDependabotSeverity(alert)
	confidence := githubDependabotConfidence(alert)
	fixedVersion := strings.TrimSpace(alert.SecurityVulnerability.FirstPatchedVersion.Identifier)
	vulnerableRange := strings.TrimSpace(alert.SecurityVulnerability.VulnerableVersionRange)
	summary := sanitizeAdapterText(firstNonEmpty(alert.SecurityAdvisory.Summary, "GitHub Dependabot reported a vulnerable dependency."))

	titlePackage := firstNonEmpty(packageName, advisoryID, "dependency")
	title := "Vulnerable dependency: " + titlePackage
	if advisoryID != "" && advisoryID != titlePackage {
		title += " (" + advisoryID + ")"
	}
	remediation := "Review the GitHub Dependabot advisory and upgrade the affected dependency."
	if fixedVersion != "" {
		remediation = "Upgrade " + firstNonEmpty(packageName, "the affected dependency") + " to " + fixedVersion + " or later, then re-run the scan."
	}

	dedupeKey := strings.Join([]string{
		adapterSourceGitHubDependabot,
		strings.ToLower(strings.TrimSpace(repository)),
		strings.ToLower(ruleID),
		manifest,
		strconv.Itoa(alert.Number),
	}, "|")

	evidence := map[string]any{
		"repository":                   repository,
		"detector":                     detector,
		"adapter_name":                 adapterSourceGitHubDependabot,
		"adapter_version":              externalAdapterVersion,
		"adapter_source_type":          adapterSourceGitHubDependabot,
		"adapter_tool_name":            "github-dependabot",
		"adapter_rule_id":              ruleID,
		"adapter_rule_name":            summary,
		"adapter_alert_number":         alert.Number,
		"adapter_alert_state":          strings.TrimSpace(alert.State),
		"adapter_ecosystem":            ecosystem,
		"adapter_package":              packageName,
		"adapter_dependency_scope":     strings.TrimSpace(alert.Dependency.Scope),
		"adapter_advisory_ghsa":        ghsaID,
		"adapter_advisory_cve":         cveID,
		"adapter_advisory_severity":    strings.ToLower(strings.TrimSpace(firstNonEmpty(alert.SecurityAdvisory.Severity, alert.SecurityVulnerability.Severity))),
		"adapter_advisory_identifiers": githubDependabotIdentifiers(alert.SecurityAdvisory.Identifiers),
		"adapter_confidence":           confidence,
		"adapter_confidence_source":    "github_dependabot_advisory",
		"adapter_severity_source":      severitySource,
		"adapter_dedupe_key":           dedupeKey,
		"history_source":               externalAdapterHistorySource,
		"raw_secret_stored":            false,
		"raw_adapter_result_stored":    false,
	}
	if manifest != "" {
		evidence["adapter_manifest_path"] = manifest
		evidence["file_path"] = manifest
	}
	if vulnerableRange != "" {
		evidence["adapter_vulnerable_range"] = vulnerableRange
	}
	if fixedVersion != "" {
		evidence["adapter_first_patched_version"] = fixedVersion
	}
	if commit != "" {
		evidence["commit"] = commit
	}
	if alert.HTMLURL != "" {
		evidence["adapter_alert_url"] = alert.HTMLURL
	}

	id := "finding:" + hashDeterministicID(
		"repo-adapter",
		adapterSourceGitHubDependabot,
		repository,
		strconv.Itoa(alert.Number),
		ruleID,
		manifest,
	)
	finding := domain.Finding{
		ID:              id,
		Type:            domain.FindingRepoMisconfig,
		Severity:        severity,
		ConfidenceScore: confidence,
		Title:           title,
		HumanSummary:    summary,
		Repository:      repository,
		Commit:          commit,
		Detector:        detector,
		SourceURL:       strings.TrimSpace(alert.HTMLURL),
		Evidence:        evidence,
		Remediation:     remediation,
		CreatedAt:       detectedAt,
	}
	if manifest != "" {
		finding.FilePath = manifest
		finding.Path = []string{manifest}
	}
	return finding, true
}

func githubDependabotIdentifiers(identifiers []GitHubDependabotAdvisoryIdentity) []string {
	values := make([]string, 0, len(identifiers))
	seen := map[string]struct{}{}
	for _, identifier := range identifiers {
		value := strings.TrimSpace(identifier.Value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func githubDependabotSeverity(alert GitHubDependabotAlert) (domain.FindingSeverity, string) {
	severity := strings.ToLower(strings.TrimSpace(alert.SecurityAdvisory.Severity))
	source := "advisory_severity"
	if severity == "" {
		severity = strings.ToLower(strings.TrimSpace(alert.SecurityVulnerability.Severity))
		source = "vulnerability_severity"
	}
	switch severity {
	case "critical":
		return domain.SeverityCritical, source
	case "high":
		return domain.SeverityHigh, source
	case "medium", "moderate":
		return domain.SeverityMedium, source
	case "low":
		return domain.SeverityLow, source
	default:
		return domain.SeverityMedium, "default"
	}
}

func githubDependabotConfidence(alert GitHubDependabotAlert) float64 {
	switch strings.ToLower(strings.TrimSpace(firstNonEmpty(alert.SecurityAdvisory.Severity, alert.SecurityVulnerability.Severity))) {
	case "critical", "high":
		return 0.95
	case "medium", "moderate":
		return 0.85
	case "low":
		return 0.75
	default:
		return 0.80
	}
}

var _ ExternalFindingAdapter = GitHubDependabotAlertAdapter{}
