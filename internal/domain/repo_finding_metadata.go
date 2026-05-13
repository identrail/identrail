package domain

import (
	"encoding/json"
	"maps"
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
		finding.LineSnippetRedacted != nil
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
	if finding.LineNumber == 0 {
		finding.LineNumber = intFromAny(finding.Evidence["line_number"])
	}
	if finding.Detector == "" {
		finding.Detector = stringFromAny(finding.Evidence["detector"])
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
	}
	if finding.Detector != "" {
		finding.Evidence["detector"] = finding.Detector
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
	for _, key := range []string{"commit", "file_path", "line_number", "detector", "line_snippet", "line_snippet_redacted", "redacted_line_snip", "match_snippet"} {
		if _, ok := evidence[key]; ok {
			return true
		}
	}
	return false
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func intFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		number, err := typed.Int64()
		if err == nil {
			return int(number)
		}
	default:
		return 0
	}
	return 0
}

func boolFromAny(value any) (bool, bool) {
	typed, ok := value.(bool)
	return typed, ok
}

func boolPtr(value bool) *bool {
	return &value
}
