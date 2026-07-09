package domain

import (
	"encoding/json"
	"maps"
	"math"
	"strconv"
	"strings"
	"time"
)

// NormalizeRepoFindingMetadata keeps structured repo-finding fields and legacy
// evidence keys in sync so persisted findings do not need a storage migration.
func NormalizeRepoFindingMetadata(finding *Finding) {
	if finding == nil {
		return
	}
	hasFields := finding.Repository != "" ||
		finding.Commit != "" ||
		finding.FilePath != "" ||
		finding.LineNumber > 0 ||
		finding.Detector != "" ||
		finding.LineSnippet != "" ||
		finding.LineSnippetRedacted != nil ||
		finding.LifecycleKey != "" ||
		finding.LifecycleStatus != "" ||
		finding.Owner != "" ||
		finding.FirstSeenAt != nil ||
		finding.LastSeenAt != nil ||
		finding.FixedAt != nil ||
		finding.ReopenedAt != nil ||
		finding.DismissedAt != nil ||
		finding.SuppressionExpiresAt != nil ||
		finding.RuleVersion != "" ||
		finding.DetectorVersion != "" ||
		finding.AdapterSource != "" ||
		finding.ConfidenceState != "" ||
		finding.VerificationStatus != "" ||
		finding.ScanMode != "" ||
		finding.EvidenceVersion != ""
	hasEvidence := hasRepoFindingEvidence(finding.Evidence)
	if !hasFields && !hasEvidence && finding.Type != FindingSecretExposure && finding.Type != FindingRepoMisconfig {
		return
	}
	if len(finding.Evidence) > 0 {
		finding.Evidence = maps.Clone(finding.Evidence)
	}

	if finding.Repository == "" {
		finding.Repository = stringFromAny(finding.Evidence["repository"])
	}
	if finding.Commit == "" {
		finding.Commit = stringFromAny(finding.Evidence["commit"])
	}
	if finding.FilePath == "" {
		finding.FilePath = stringFromAny(finding.Evidence["file_path"])
		if finding.FilePath == "" && len(finding.Path) == 1 {
			finding.FilePath = finding.Path[0]
		}
	}
	if finding.LineNumber != 0 {
		finding.LineNumber = EvidenceLineNumberFromAny(finding.LineNumber)
	}
	if finding.LineNumber == 0 {
		finding.LineNumber = EvidenceLineNumberFromAny(finding.Evidence["line_number"])
	}
	if finding.Detector == "" {
		finding.Detector = stringFromAny(finding.Evidence["detector"])
	}
	if finding.ConfidenceScore == 0 {
		if confidence, ok := floatFromAny(finding.Evidence["confidence_score"]); ok {
			finding.ConfidenceScore = confidence
		}
	}
	if finding.LifecycleKey == "" {
		finding.LifecycleKey = stringFromAny(finding.Evidence["lifecycle_key"])
	}
	if finding.LifecycleStatus == "" {
		finding.LifecycleStatus = NormalizeRepoFindingLifecycleStatus(stringFromAny(finding.Evidence["lifecycle_status"]))
	}
	if finding.Owner == "" {
		for _, key := range []string{"owner", "owner_hint", "owner_team", "codeowners", "assignee"} {
			if owner := stringFromAny(finding.Evidence[key]); owner != "" {
				finding.Owner = owner
				break
			}
		}
	}
	if finding.FirstSeenAt == nil {
		finding.FirstSeenAt = timeFromAny(finding.Evidence["first_seen_at"])
	}
	if finding.LastSeenAt == nil {
		finding.LastSeenAt = timeFromAny(finding.Evidence["last_seen_at"])
	}
	if finding.FixedAt == nil {
		finding.FixedAt = timeFromAny(finding.Evidence["fixed_at"])
	}
	if finding.ReopenedAt == nil {
		finding.ReopenedAt = timeFromAny(finding.Evidence["reopened_at"])
	}
	if finding.DismissedAt == nil {
		finding.DismissedAt = timeFromAny(finding.Evidence["dismissed_at"])
	}
	if finding.SuppressionExpiresAt == nil {
		finding.SuppressionExpiresAt = timeFromAny(finding.Evidence["suppression_expires_at"])
	}
	if finding.RuleVersion == "" {
		finding.RuleVersion = stringFromAny(finding.Evidence["rule_version"])
	}
	if finding.DetectorVersion == "" {
		finding.DetectorVersion = stringFromAny(finding.Evidence["detector_version"])
	}
	if finding.AdapterSource == "" {
		finding.AdapterSource = stringFromAny(finding.Evidence["adapter_source"])
	}
	if finding.ConfidenceState == "" {
		finding.ConfidenceState = stringFromAny(finding.Evidence["confidence_state"])
	}
	if finding.VerificationStatus == "" {
		finding.VerificationStatus = stringFromAny(finding.Evidence["verification_status"])
	}
	if finding.ScanMode == "" {
		finding.ScanMode = stringFromAny(finding.Evidence["scan_mode"])
	}
	if finding.EvidenceVersion == "" {
		finding.EvidenceVersion = stringFromAny(finding.Evidence["evidence_version"])
	}
	if finding.LineSnippet == "" {
		for _, key := range []string{"line_snippet", "redacted_line_snip", "match_snippet"} {
			if snippet := stringFromAny(finding.Evidence[key]); snippet != "" {
				finding.LineSnippet = snippet
				break
			}
		}
	}
	if finding.LineSnippetRedacted == nil {
		if redacted, ok := boolFromAny(finding.Evidence["line_snippet_redacted"]); ok {
			finding.LineSnippetRedacted = boolPtr(redacted)
		} else if stringFromAny(finding.Evidence["redacted_line_snip"]) != "" {
			finding.LineSnippetRedacted = boolPtr(true)
		} else if finding.LineSnippet != "" {
			finding.LineSnippetRedacted = boolPtr(false)
		}
	}

	if finding.FilePath != "" && len(finding.Path) == 0 {
		finding.Path = []string{finding.FilePath}
	}
	if finding.LifecycleStatus == "" {
		finding.LifecycleStatus = RepoFindingLifecycleOpen
	}
	if finding.LifecycleKey == "" {
		finding.LifecycleKey = RepoFindingLifecycleKey(*finding)
	}
	if !finding.CreatedAt.IsZero() {
		if finding.FirstSeenAt == nil {
			value := finding.CreatedAt.UTC()
			finding.FirstSeenAt = &value
		}
		if finding.LastSeenAt == nil {
			value := finding.CreatedAt.UTC()
			finding.LastSeenAt = &value
		}
	}

	if finding.Evidence == nil && (hasFields || finding.FilePath != "" || finding.LineSnippet != "") {
		finding.Evidence = map[string]any{}
	}
	if finding.Evidence == nil {
		return
	}
	if finding.Repository != "" {
		finding.Evidence["repository"] = finding.Repository
	}
	if finding.Commit != "" {
		finding.Evidence["commit"] = finding.Commit
	}
	if finding.FilePath != "" {
		finding.Evidence["file_path"] = finding.FilePath
	}
	if finding.LineNumber > 0 {
		finding.Evidence["line_number"] = finding.LineNumber
	} else {
		delete(finding.Evidence, "line_number")
	}
	if finding.Detector != "" {
		finding.Evidence["detector"] = finding.Detector
	}
	if finding.ConfidenceScore > 0 {
		finding.Evidence["confidence_score"] = finding.ConfidenceScore
	}
	if finding.LifecycleKey != "" {
		finding.Evidence["lifecycle_key"] = finding.LifecycleKey
	}
	if finding.LifecycleStatus != "" {
		finding.Evidence["lifecycle_status"] = finding.LifecycleStatus
	}
	if finding.Owner != "" {
		finding.Evidence["owner"] = finding.Owner
	}
	putEvidenceTime(finding.Evidence, "first_seen_at", finding.FirstSeenAt)
	putEvidenceTime(finding.Evidence, "last_seen_at", finding.LastSeenAt)
	putEvidenceTime(finding.Evidence, "fixed_at", finding.FixedAt)
	putEvidenceTime(finding.Evidence, "reopened_at", finding.ReopenedAt)
	putEvidenceTime(finding.Evidence, "dismissed_at", finding.DismissedAt)
	putEvidenceTime(finding.Evidence, "suppression_expires_at", finding.SuppressionExpiresAt)
	if finding.RuleVersion != "" {
		finding.Evidence["rule_version"] = finding.RuleVersion
	}
	if finding.DetectorVersion != "" {
		finding.Evidence["detector_version"] = finding.DetectorVersion
	}
	if finding.AdapterSource != "" {
		finding.Evidence["adapter_source"] = finding.AdapterSource
	}
	if finding.ConfidenceState != "" {
		finding.Evidence["confidence_state"] = finding.ConfidenceState
	}
	if finding.VerificationStatus != "" {
		finding.Evidence["verification_status"] = finding.VerificationStatus
	}
	if finding.ScanMode != "" {
		finding.Evidence["scan_mode"] = finding.ScanMode
	}
	if finding.EvidenceVersion != "" {
		finding.Evidence["evidence_version"] = finding.EvidenceVersion
	}
	if finding.LineSnippet != "" {
		finding.Evidence["line_snippet"] = finding.LineSnippet
		if finding.LineSnippetRedacted != nil && *finding.LineSnippetRedacted {
			finding.Evidence["redacted_line_snip"] = finding.LineSnippet
		}
	}
	if finding.LineSnippetRedacted != nil {
		finding.Evidence["line_snippet_redacted"] = *finding.LineSnippetRedacted
	}
}

func hasRepoFindingEvidence(evidence map[string]any) bool {
	if len(evidence) == 0 {
		return false
	}
	for _, key := range []string{"commit", "file_path", "line_number", "detector", "line_snippet", "line_snippet_redacted", "redacted_line_snip", "match_snippet", "lifecycle_key", "lifecycle_status", "owner", "first_seen_at", "last_seen_at", "fixed_at", "reopened_at", "dismissed_at", "suppression_expires_at", "rule_version", "detector_version", "adapter_source", "confidence_state", "verification_status", "scan_mode", "evidence_version"} {
		if _, ok := evidence[key]; ok {
			return true
		}
	}
	return false
}

// NormalizeRepoFindingLifecycleStatus returns a known repo finding lifecycle
// value, or the empty value when the caller provided no recognizable state.
func NormalizeRepoFindingLifecycleStatus(raw string) RepoFindingLifecycleStatus {
	switch RepoFindingLifecycleStatus(strings.ToLower(strings.TrimSpace(raw))) {
	case RepoFindingLifecycleOpen:
		return RepoFindingLifecycleOpen
	case RepoFindingLifecycleFixed:
		return RepoFindingLifecycleFixed
	case RepoFindingLifecycleReopened:
		return RepoFindingLifecycleReopened
	case RepoFindingLifecycleSuppressed:
		return RepoFindingLifecycleSuppressed
	case RepoFindingLifecycleRiskAccepted:
		return RepoFindingLifecycleRiskAccepted
	case RepoFindingLifecycleFalsePositive:
		return RepoFindingLifecycleFalsePositive
	default:
		return ""
	}
}

// RepoFindingLifecycleKey returns the scanner-stable identity used to connect a
// repo finding across repeated scans. It avoids commit-scoped IDs when stronger
// evidence such as a secret fingerprint is available.
func RepoFindingLifecycleKey(finding Finding) string {
	repository := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
		finding.Repository,
		stringFromAny(finding.Evidence["repository"]),
	)))
	detector := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
		finding.Detector,
		stringFromAny(finding.Evidence["detector"]),
	)))
	filePath := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
		finding.FilePath,
		stringFromAny(finding.Evidence["file_path"]),
	)))
	fingerprint := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
		stringFromAny(finding.Evidence["secret_fingerprint"]),
		stringFromAny(finding.Evidence["match_fingerprint"]),
		stringFromAny(finding.Evidence["finding_fingerprint"]),
		stringFromAny(finding.Evidence["fingerprint"]),
	)))
	parts := []string{"repo_finding", repository, string(finding.Type), detector}
	if fingerprint != "" {
		parts = append(parts, "fingerprint", fingerprint, filePath)
		return strings.Join(parts, "\x1f")
	}
	lineNumber := finding.LineNumber
	if lineNumber == 0 {
		lineNumber = EvidenceLineNumberFromAny(finding.Evidence["line_number"])
	}
	if filePath != "" || lineNumber > 0 || detector != "" {
		parts = append(parts, filePath, strconv.Itoa(lineNumber), strings.ToLower(strings.TrimSpace(finding.Title)))
		return strings.Join(parts, "\x1f")
	}
	return strings.Join(append(parts, strings.TrimSpace(finding.ID)), "\x1f")
}

// ApplyRepoFindingTriageToLifecycle overlays operator workflow state onto the
// scanner lifecycle that was persisted from repo scans.
func ApplyRepoFindingTriageToLifecycle(finding *Finding) {
	if finding == nil {
		return
	}
	switch finding.Triage.Status {
	case FindingLifecycleSuppressed:
		finding.LifecycleStatus = RepoFindingLifecycleSuppressed
		finding.SuppressionExpiresAt = cloneTimePointer(finding.Triage.SuppressionExpiresAt)
		if finding.DismissedAt == nil && finding.Triage.UpdatedAt != nil {
			finding.DismissedAt = cloneTimePointer(finding.Triage.UpdatedAt)
		}
	case FindingLifecycleResolved:
		if finding.LifecycleStatus == "" || finding.LifecycleStatus == RepoFindingLifecycleOpen || finding.LifecycleStatus == RepoFindingLifecycleReopened {
			finding.LifecycleStatus = RepoFindingLifecycleFixed
		}
		if finding.FixedAt == nil && finding.Triage.ResolvedAt != nil {
			finding.FixedAt = cloneTimePointer(finding.Triage.ResolvedAt)
		}
	}
	if finding.Owner == "" && strings.TrimSpace(finding.Triage.Assignee) != "" {
		finding.Owner = strings.TrimSpace(finding.Triage.Assignee)
	}
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

// EvidenceLineNumberFromAny coerces untrusted scanner line-number evidence into
// a portable int. Invalid, negative, fractional, or oversized values normalize
// to zero, matching the repo finding "unknown line" convention.
func EvidenceLineNumberFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return boundedEvidenceLineNumber(int64(typed))
	case int32:
		return boundedEvidenceLineNumber(int64(typed))
	case int64:
		return boundedEvidenceLineNumber(typed)
	case float64:
		return boundedEvidenceLineNumberFloat(typed)
	case json.Number:
		number, err := strconv.ParseInt(typed.String(), 10, 32)
		if err == nil {
			return boundedEvidenceLineNumber(number)
		}
	case string:
		number, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 32)
		if err == nil {
			return boundedEvidenceLineNumber(number)
		}
	default:
		return 0
	}
	return 0
}

func boundedEvidenceLineNumber(value int64) int {
	if value < 0 || value > math.MaxInt32 {
		return 0
	}
	number, err := strconv.Atoi(strconv.FormatInt(value, 10))
	if err != nil {
		return 0
	}
	return number
}

func boundedEvidenceLineNumberFloat(value float64) int {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > math.MaxInt32 || math.Trunc(value) != value {
		return 0
	}
	number, err := strconv.Atoi(strconv.FormatFloat(value, 'f', 0, 64))
	if err != nil {
		return 0
	}
	return number
}

func floatFromAny(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		number, err := typed.Float64()
		return number, err == nil
	default:
		return 0, false
	}
}

func boolFromAny(value any) (bool, bool) {
	typed, ok := value.(bool)
	return typed, ok
}

func boolPtr(value bool) *bool {
	return &value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func timeFromAny(value any) *time.Time {
	switch typed := value.(type) {
	case time.Time:
		normalized := typed.UTC()
		return &normalized
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			parsed, err := time.Parse(layout, trimmed)
			if err == nil {
				normalized := parsed.UTC()
				return &normalized
			}
		}
	default:
		return nil
	}
	return nil
}

func putEvidenceTime(evidence map[string]any, key string, value *time.Time) {
	if evidence == nil || value == nil || value.IsZero() {
		return
	}
	evidence[key] = value.UTC().Format(time.RFC3339)
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}
