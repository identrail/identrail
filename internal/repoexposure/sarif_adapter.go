package repoexposure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

const (
	adapterSourceSARIF             = "sarif"
	redactedExternalSecretEvidence = "[redacted external secret evidence]"
	maxAdapterEvidenceTextLength   = 500
)

var adapterDetectorCleaner = regexp.MustCompile(`[^a-z0-9._:-]+`)

// SARIFAdapter imports SARIF 2.1.0 results into repo findings.
type SARIFAdapter struct {
	content []byte
}

// NewSARIFAdapter returns an opt-in adapter for already-produced SARIF output.
func NewSARIFAdapter(content []byte) SARIFAdapter {
	return SARIFAdapter{content: append([]byte(nil), content...)}
}

func (a SARIFAdapter) Name() string {
	return adapterSourceSARIF
}

func (a SARIFAdapter) Version() string {
	return externalAdapterVersion
}

func (a SARIFAdapter) Findings(ctx context.Context, input ExternalAdapterInput) ([]domain.Finding, error) {
	return IngestSARIF(ctx, input.Repository, input.Commit, a.content, input.DetectedAt)
}

// IngestSARIF converts SARIF results into normalized Identrail repo findings.
func IngestSARIF(ctx context.Context, repository string, commit string, content []byte, detectedAt time.Time) ([]domain.Finding, error) {
	var log sarifLog
	if err := json.Unmarshal(content, &log); err != nil {
		return nil, fmt.Errorf("decode SARIF: %w", err)
	}
	if strings.TrimSpace(log.Version) != "" && strings.TrimSpace(log.Version) != "2.1.0" {
		return nil, fmt.Errorf("unsupported SARIF version %q", log.Version)
	}
	findings := []domain.Finding{}
	seen := map[string]struct{}{}
	for _, run := range log.Runs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rules := sarifRulesByID(run.Tool.Driver.Rules)
		toolName := firstNonEmpty(run.Tool.Driver.Name, adapterSourceSARIF)
		toolVersion := firstNonEmpty(run.Tool.Driver.SemanticVersion, run.Tool.Driver.Version, externalAdapterVersion)
		for _, result := range run.Results {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			rule := rules[result.RuleID]
			if rule.ID == "" {
				rule.ID = result.RuleID
			}
			finding, ok := sarifResultToFinding(repository, commit, toolName, toolVersion, rule, result, detectedAt)
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
	}
	return findings, nil
}

type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifMessage   `json:"shortDescription"`
	FullDescription      sarifMessage   `json:"fullDescription"`
	Help                 sarifMessage   `json:"help"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int          `json:"startLine"`
	StartColumn int          `json:"startColumn"`
	EndLine     int          `json:"endLine"`
	EndColumn   int          `json:"endColumn"`
	Snippet     sarifMessage `json:"snippet"`
}

func sarifRulesByID(rules []sarifRule) map[string]sarifRule {
	byID := make(map[string]sarifRule, len(rules))
	for _, rule := range rules {
		if strings.TrimSpace(rule.ID) != "" {
			byID[rule.ID] = rule
		}
	}
	return byID
}

func sarifResultToFinding(repository string, commit string, toolName string, toolVersion string, rule sarifRule, result sarifResult, detectedAt time.Time) (domain.Finding, bool) {
	if len(result.Locations) == 0 {
		return domain.Finding{}, false
	}
	location := result.Locations[0].PhysicalLocation
	filePath := normalizeAdapterPath(location.ArtifactLocation.URI)
	line := location.Region.StartLine
	if filePath == "" || line <= 0 {
		return domain.Finding{}, false
	}
	ruleID := firstNonEmpty(result.RuleID, rule.ID, "unknown")
	secretLike := isSecretLikeAdapterResult(ruleID, rule.Name, result.Message.Text, sarifTags(rule.Properties), sarifTags(result.Properties))
	severity, severitySource := sarifSeverity(result, rule)
	confidence, confidenceSource := sarifConfidence(result.Properties, rule.Properties)
	detector := adapterDetectorID(adapterSourceSARIF, toolName, ruleID)
	message := sanitizeAdapterText(firstNonEmpty(result.Message.Text, rule.ShortDescription.Text, rule.FullDescription.Text))
	snippet := sanitizeAdapterText(firstNonEmpty(location.Region.Snippet.Text, result.Message.Text, rule.ShortDescription.Text))
	findingType := domain.FindingRepoMisconfig
	lineRedacted := false
	title := firstNonEmpty(rule.Name, rule.ShortDescription.Text, ruleID)
	summary := firstNonEmpty(message, "External scanner reported a repository finding.")
	remediation := firstNonEmpty(sanitizeAdapterText(rule.Help.Text), "Review the external scanner guidance and remediate the affected repository path.")
	if secretLike {
		findingType = domain.FindingSecretExposure
		lineRedacted = true
		snippet = redactedExternalSecretEvidence
		summary = "External scanner reported a secret-like repository finding; raw secret material was not stored."
		remediation = "Rotate the affected credential, remove it from repository history where needed, and move it to a secret manager."
	}

	evidence := map[string]any{
		"repository":                repository,
		"commit":                    commit,
		"file_path":                 filePath,
		"line_number":               line,
		"line_snippet":              snippet,
		"line_snippet_redacted":     lineRedacted,
		"detector":                  detector,
		"adapter_name":              toolName,
		"adapter_version":           toolVersion,
		"adapter_source_type":       adapterSourceSARIF,
		"adapter_rule_id":           ruleID,
		"adapter_rule_name":         firstNonEmpty(rule.Name, rule.ShortDescription.Text),
		"adapter_result_level":      strings.TrimSpace(result.Level),
		"adapter_confidence":        confidence,
		"adapter_confidence_source": confidenceSource,
		"adapter_severity_source":   severitySource,
		"adapter_location_path":     filePath,
		"adapter_location_line":     line,
		"adapter_location_column":   location.Region.StartColumn,
		"adapter_dedupe_key":        externalAdapterDedupeKey(repository, findingType, filePath, line, detector, snippet),
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

	id := "finding:" + hashDeterministicID(
		"repo-adapter",
		adapterSourceSARIF,
		repository,
		filePath,
		strconv.Itoa(line),
		detector,
		hashSHA256(firstNonEmpty(result.Message.Text, location.Region.Snippet.Text, ruleID)),
	)
	return domain.Finding{
		ID:                  id,
		Type:                findingType,
		Severity:            severity,
		ConfidenceScore:     confidence,
		Title:               title,
		HumanSummary:        summary,
		Path:                []string{filePath},
		Repository:          repository,
		Commit:              commit,
		FilePath:            filePath,
		LineNumber:          line,
		Detector:            detector,
		LineSnippet:         snippet,
		LineSnippetRedacted: boolPtr(lineRedacted),
		Evidence:            evidence,
		Remediation:         remediation,
		CreatedAt:           detectedAt,
	}, true
}

func sarifSeverity(result sarifResult, rule sarifRule) (domain.FindingSeverity, string) {
	if score, ok := firstSecurityScore(result.Properties, rule.Properties); ok {
		switch {
		case score >= 9:
			return domain.SeverityCritical, "security-severity"
		case score >= 7:
			return domain.SeverityHigh, "security-severity"
		case score >= 4:
			return domain.SeverityMedium, "security-severity"
		case score > 0:
			return domain.SeverityLow, "security-severity"
		default:
			return domain.SeverityInfo, "security-severity"
		}
	}
	level := strings.ToLower(firstNonEmpty(
		sarifPropertyString(result.Properties, "problem.severity", "severity"),
		result.Level,
		rule.DefaultConfiguration.Level,
	))
	switch level {
	case "critical":
		return domain.SeverityCritical, "level"
	case "error", "high":
		return domain.SeverityHigh, "level"
	case "warning", "medium":
		return domain.SeverityMedium, "level"
	case "note", "recommendation", "low":
		return domain.SeverityLow, "level"
	case "none", "info", "informational":
		return domain.SeverityInfo, "level"
	default:
		return domain.SeverityMedium, "default"
	}
}

func sarifConfidence(resultProperties map[string]any, ruleProperties map[string]any) (float64, string) {
	precision := strings.ToLower(firstNonEmpty(
		sarifPropertyString(resultProperties, "precision"),
		sarifPropertyString(ruleProperties, "precision"),
	))
	switch precision {
	case "very-high", "very_high":
		return 0.95, "precision"
	case "high":
		return 0.90, "precision"
	case "medium", "moderate":
		return 0.75, "precision"
	case "low":
		return 0.50, "precision"
	default:
		return 0.70, "adapter_default"
	}
}

func firstSecurityScore(propertySets ...map[string]any) (float64, bool) {
	for _, properties := range propertySets {
		for _, key := range []string{"security-severity", "security_severity", "securitySeverity"} {
			raw, ok := properties[key]
			if !ok || raw == nil {
				continue
			}
			switch value := raw.(type) {
			case float64:
				return value, true
			case json.Number:
				score, err := value.Float64()
				return score, err == nil
			case string:
				score, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				return score, err == nil
			}
		}
	}
	return 0, false
}

func sarifPropertyString(properties map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := properties[name]; ok && value != nil {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func sarifTags(properties map[string]any) []string {
	raw, ok := properties["tags"]
	if !ok || raw == nil {
		return nil
	}
	switch tags := raw.(type) {
	case []string:
		return tags
	case []any:
		values := make([]string, 0, len(tags))
		for _, tag := range tags {
			if value := strings.TrimSpace(fmt.Sprint(tag)); value != "" {
				values = append(values, value)
			}
		}
		return values
	case string:
		return strings.Split(tags, ",")
	default:
		return nil
	}
}

func isSecretLikeAdapterResult(values ...any) bool {
	for _, value := range values {
		switch typed := value.(type) {
		case []string:
			for _, item := range typed {
				if isSecretLikeAdapterText(item) {
					return true
				}
			}
		default:
			if isSecretLikeAdapterText(fmt.Sprint(typed)) {
				return true
			}
		}
	}
	return false
}

func isSecretLikeAdapterText(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"secret", "credential", "password", "passwd", "token", "private key",
		"private_key", "api-key", "api_key", "apikey", "access key",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func normalizeAdapterPath(value string) string {
	path := strings.TrimSpace(value)
	if path == "" {
		return ""
	}
	if parsed, err := url.Parse(path); err == nil && parsed.Scheme == "file" {
		path = parsed.Path
	}
	path = strings.ReplaceAll(path, "\\", "/")
	for _, prefix := range []string{"/github/workspace/", "/workspace/"} {
		if idx := strings.Index(path, prefix); idx >= 0 {
			path = path[idx+len(prefix):]
			break
		}
	}
	path = strings.TrimPrefix(path, "./")
	return strings.TrimSpace(path)
}

func sanitizeAdapterText(value string) string {
	text := strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if len(text) <= maxAdapterEvidenceTextLength {
		return text
	}
	return text[:maxAdapterEvidenceTextLength] + "..."
}

func adapterDetectorID(source string, tool string, ruleID string) string {
	parts := []string{source, tool, ruleID}
	for i, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		part = adapterDetectorCleaner.ReplaceAllString(part, "_")
		parts[i] = strings.Trim(part, "_")
	}
	return firstNonEmpty(strings.Join(nonEmptyStrings(parts...), ":"), source+":unknown")
}

func externalAdapterDedupeKey(repository string, findingType domain.FindingType, filePath string, line int, detector string, snippet string) string {
	return strings.Join([]string{
		string(findingType),
		strings.ToLower(strings.TrimSpace(repository)),
		strings.TrimSpace(filePath),
		strconv.Itoa(line),
		strings.ToLower(strings.TrimSpace(detector)),
		hashSHA256(compactFindingText(snippet)),
	}, "|")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
