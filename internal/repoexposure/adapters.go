package repoexposure

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

const (
	externalAdapterHistorySource = "external_adapter"
	externalAdapterVersion       = "2026.05"
)

// ExternalAdapterInput gives an adapter the scan context needed to normalize
// imported findings without granting it repository execution privileges.
type ExternalAdapterInput struct {
	Repository string
	Commit     string
	DetectedAt time.Time
}

// ExternalFindingAdapter imports already-produced scanner output into
// Identrail repo findings. Adapters are opt-in; Scanner runs none by default.
type ExternalFindingAdapter interface {
	Name() string
	Version() string
	Findings(ctx context.Context, input ExternalAdapterInput) ([]domain.Finding, error)
}

// WithExternalAdapters adds opt-in external finding adapters to a scanner.
// Identrail does not execute external binaries unless callers provide an
// adapter that does so under their own explicit controls.
func WithExternalAdapters(adapters ...ExternalFindingAdapter) Option {
	return func(s *Scanner) {
		for _, adapter := range adapters {
			if adapter != nil {
				s.adapters = append(s.adapters, adapter)
			}
		}
	}
}

// MergeExternalFindings merges adapter findings into an existing finding set
// while enforcing the same stable dedupe and cap behavior used by Scanner.
func MergeExternalFindings(existing []domain.Finding, external []domain.Finding, maxFindings int) ([]domain.Finding, bool) {
	return appendExternalFindings(existing, external, map[string]struct{}{}, maxFindings)
}

func appendExternalFindings(existing []domain.Finding, external []domain.Finding, seen map[string]struct{}, maxFindings int) ([]domain.Finding, bool) {
	if maxFindings <= 0 {
		maxFindings = defaultMaxFindings
	}
	if len(existing) >= maxFindings {
		return existing, true
	}
	known := map[string]struct{}{}
	for key := range seen {
		known[key] = struct{}{}
	}
	for _, finding := range existing {
		for _, key := range repoFindingDedupeKeys(finding) {
			known[key] = struct{}{}
		}
	}

	merged := existing
	for _, finding := range external {
		finding = normalizeExternalFinding(finding)
		if finding.ID == "" {
			finding.ID = deterministicExternalFindingID(finding)
		}
		keys := repoFindingDedupeKeys(finding)
		duplicate := false
		for _, key := range keys {
			if _, ok := known[key]; ok {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		merged = append(merged, finding)
		for _, key := range keys {
			known[key] = struct{}{}
			seen[key] = struct{}{}
		}
		if finding.ID != "" {
			seen[finding.ID] = struct{}{}
		}
		if len(merged) >= maxFindings {
			return merged, true
		}
	}
	return merged, false
}

func normalizeExternalFinding(finding domain.Finding) domain.Finding {
	if finding.Evidence == nil {
		finding.Evidence = map[string]any{}
	}
	if _, ok := finding.Evidence["history_source"]; !ok {
		finding.Evidence["history_source"] = externalAdapterHistorySource
	}
	if _, ok := finding.Evidence["raw_adapter_result_stored"]; !ok {
		finding.Evidence["raw_adapter_result_stored"] = false
	}
	if finding.Repository == "" {
		finding.Repository = evidenceString(finding.Evidence, "repository")
	}
	if finding.FilePath == "" {
		finding.FilePath = evidenceString(finding.Evidence, "file_path")
	}
	if finding.LineNumber == 0 {
		finding.LineNumber = evidenceInt(finding.Evidence, "line_number")
	}
	if finding.Detector == "" {
		finding.Detector = evidenceString(finding.Evidence, "detector")
	}
	if finding.Commit == "" {
		finding.Commit = evidenceString(finding.Evidence, "commit")
	}
	if finding.LineSnippet == "" {
		finding.LineSnippet = evidenceString(finding.Evidence, "line_snippet")
	}
	return finding
}

func deterministicExternalFindingID(finding domain.Finding) string {
	return "finding:" + hashDeterministicID(
		"repo-adapter",
		string(finding.Type),
		finding.Repository,
		finding.FilePath,
		strconv.Itoa(finding.LineNumber),
		finding.Detector,
		hashSHA256(finding.LineSnippet),
	)
}

func repoFindingDedupeKeys(finding domain.Finding) []string {
	normalized := findingContextFrom(finding)
	keys := []string{}
	if strings.TrimSpace(normalized.ID) != "" {
		keys = append(keys, "id:"+strings.TrimSpace(normalized.ID))
	}
	if key := evidenceString(finding.Evidence, "adapter_dedupe_key"); key != "" {
		keys = append(keys, "adapter:"+key)
	}
	repository := strings.ToLower(strings.TrimSpace(normalized.Repository))
	filePath := strings.TrimSpace(normalized.FilePath)
	line := normalized.LineNumber
	detector := strings.ToLower(strings.TrimSpace(normalized.Detector))
	if repository != "" && filePath != "" && line > 0 && detector != "" {
		keys = append(keys, fmt.Sprintf("detector:%s:%s:%d:%s:%s", normalized.Type, repository, line, filePath, detector))
	}
	snippet := compactFindingText(normalized.LineSnippet)
	if repository != "" && filePath != "" && line > 0 && snippet != "" {
		keys = append(keys, fmt.Sprintf("line:%s:%s:%d:%s:%s", normalized.Type, repository, line, filePath, hashSHA256(snippet)))
	}
	return keys
}

type findingContext struct {
	ID          string
	Type        domain.FindingType
	Repository  string
	FilePath    string
	LineNumber  int
	Detector    string
	LineSnippet string
}

func findingContextFrom(finding domain.Finding) findingContext {
	context := findingContext{
		ID:          finding.ID,
		Type:        finding.Type,
		Repository:  finding.Repository,
		FilePath:    finding.FilePath,
		LineNumber:  finding.LineNumber,
		Detector:    finding.Detector,
		LineSnippet: finding.LineSnippet,
	}
	if context.Repository == "" {
		context.Repository = evidenceString(finding.Evidence, "repository")
	}
	if context.FilePath == "" {
		context.FilePath = evidenceString(finding.Evidence, "file_path")
	}
	if context.LineNumber == 0 {
		context.LineNumber = evidenceInt(finding.Evidence, "line_number")
	}
	if context.Detector == "" {
		context.Detector = evidenceString(finding.Evidence, "detector")
	}
	if context.LineSnippet == "" {
		context.LineSnippet = evidenceString(finding.Evidence, "line_snippet")
	}
	return context
}

func evidenceString(evidence map[string]any, key string) string {
	if evidence == nil {
		return ""
	}
	value, ok := evidence[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func evidenceInt(evidence map[string]any, key string) int {
	if evidence == nil {
		return 0
	}
	value, ok := evidence[key]
	if !ok || value == nil {
		return 0
	}
	return domain.EvidenceLineNumberFromAny(value)
}

func compactFindingText(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}
