package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

const (
	findingBaselineSchemaVersion        = "v1"
	findingBaselineImportMatchThreshold = 0.95
	findingBaselineImportPageSize       = 1000
)

// ErrInvalidFindingBaselineRequest indicates invalid baseline export/import input.
var ErrInvalidFindingBaselineRequest = errors.New("invalid finding baseline request")

// FindingBaseline captures one portable false-positive suppression baseline.
type FindingBaseline struct {
	SchemaVersion string                 `json:"schema_version"`
	MatchMode     string                 `json:"match_mode"`
	ExportedAt    time.Time              `json:"exported_at"`
	SourceScanID  string                 `json:"source_scan_id,omitempty"`
	Items         []FindingBaselineEntry `json:"items"`
}

// FindingBaselineEntry stores one exact finding match target plus suppression metadata.
type FindingBaselineEntry struct {
	FindingID            string                 `json:"finding_id"`
	Type                 domain.FindingType     `json:"type"`
	Severity             domain.FindingSeverity `json:"severity"`
	ConfidenceScore      float64                `json:"confidence_score,omitempty"`
	Title                string                 `json:"title"`
	HumanSummary         string                 `json:"human_summary"`
	Path                 []string               `json:"path,omitempty"`
	Repository           string                 `json:"repository,omitempty"`
	FilePath             string                 `json:"file_path,omitempty"`
	Detector             string                 `json:"detector,omitempty"`
	MatchFingerprint     string                 `json:"match_fingerprint"`
	SuppressionExpiresAt *time.Time             `json:"suppression_expires_at,omitempty"`
	Assignee             string                 `json:"assignee,omitempty"`
}

// FindingBaselineImportRequest captures one baseline application request.
type FindingBaselineImportRequest struct {
	ScanID   string          `json:"scan_id,omitempty"`
	Baseline FindingBaseline `json:"baseline"`
	Comment  string          `json:"comment,omitempty"`
}

// FindingBaselineImportResult returns baseline import outcomes per entry.
type FindingBaselineImportResult struct {
	ScanID       string                      `json:"scan_id"`
	ImportedAt   time.Time                   `json:"imported_at"`
	AppliedCount int                         `json:"applied_count"`
	SkippedCount int                         `json:"skipped_count"`
	Items        []FindingBaselineImportItem `json:"items"`
}

// FindingBaselineImportItem reports one entry application decision.
type FindingBaselineImportItem struct {
	BaselineFindingID    string     `json:"baseline_finding_id"`
	FindingID            string     `json:"finding_id,omitempty"`
	MatchConfidenceScore float64    `json:"match_confidence_score,omitempty"`
	Status               string     `json:"status"`
	Reason               string     `json:"reason,omitempty"`
	SuppressionExpiresAt *time.Time `json:"suppression_expires_at,omitempty"`
}

func (s *Service) ExportFindingBaseline(ctx context.Context, scanID string, limit int) (FindingBaseline, error) {
	ctx = s.scopeContext(ctx)
	normalizedScanID := strings.TrimSpace(scanID)
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return FindingBaseline{}, err
		}
		normalizedScanID = latest
	}
	findings, err := s.ListFindingsFiltered(ctx, limit, FindingsFilter{
		ScanID:          normalizedScanID,
		LifecycleStatus: string(domain.FindingLifecycleSuppressed),
		SortBy:          "created_at",
		SortDesc:        true,
	})
	if err != nil {
		return FindingBaseline{}, err
	}
	items := make([]FindingBaselineEntry, 0, len(findings))
	for _, finding := range findings {
		items = append(items, findingBaselineEntryFromFinding(finding))
	}
	sortFindingBaselineEntries(items)
	return FindingBaseline{
		SchemaVersion: findingBaselineSchemaVersion,
		MatchMode:     "exact_fingerprint_v1",
		ExportedAt:    s.Now().UTC(),
		SourceScanID:  normalizedScanID,
		Items:         items,
	}, nil
}

func (s *Service) ImportFindingBaseline(ctx context.Context, request FindingBaselineImportRequest, actor string) (FindingBaselineImportResult, error) {
	ctx = s.scopeContext(ctx)
	if err := validateFindingBaselineImportRequest(request); err != nil {
		return FindingBaselineImportResult{}, err
	}
	now := s.Now().UTC()
	normalizedScanID := strings.TrimSpace(request.ScanID)
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return FindingBaselineImportResult{}, err
		}
		normalizedScanID = latest
	}
	findingsByID, findingsByFingerprint, err := s.loadTargetFindingsForBaselineImport(ctx, normalizedScanID, now)
	if err != nil {
		return FindingBaselineImportResult{}, err
	}

	result := FindingBaselineImportResult{
		ScanID:     normalizedScanID,
		ImportedAt: now,
		Items:      make([]FindingBaselineImportItem, 0, len(request.Baseline.Items)),
	}
	comment := strings.TrimSpace(request.Comment)
	if comment == "" {
		comment = "suppressed from imported finding baseline"
	}
	suppressedStatus := string(domain.FindingLifecycleSuppressed)

	for _, entry := range request.Baseline.Items {
		itemResult := FindingBaselineImportItem{
			BaselineFindingID:    strings.TrimSpace(entry.FindingID),
			SuppressionExpiresAt: cloneTimePointer(entry.SuppressionExpiresAt),
			Status:               "skipped",
		}
		if entry.SuppressionExpiresAt == nil {
			itemResult.Reason = "suppression expiry missing"
			result.Items = append(result.Items, itemResult)
			result.SkippedCount++
			continue
		}
		if !entry.SuppressionExpiresAt.After(now) {
			itemResult.Reason = "suppression expiry already elapsed"
			result.Items = append(result.Items, itemResult)
			result.SkippedCount++
			continue
		}

		finding, reason, ok := resolveBaselineImportFinding(entry, findingsByID, findingsByFingerprint)
		if !ok {
			itemResult.Reason = reason
			result.Items = append(result.Items, itemResult)
			result.SkippedCount++
			continue
		}
		itemResult.FindingID = finding.ID
		itemResult.MatchConfidenceScore = scoreFindingBaselineMatch(entry, finding)
		if itemResult.MatchConfidenceScore < findingBaselineImportMatchThreshold {
			itemResult.Reason = "baseline match confidence below required threshold"
			result.Items = append(result.Items, itemResult)
			result.SkippedCount++
			continue
		}

		if finding.Triage.Status == domain.FindingLifecycleSuppressed &&
			timePointersEqual(finding.Triage.SuppressionExpiresAt, entry.SuppressionExpiresAt) &&
			strings.TrimSpace(finding.Triage.Assignee) == strings.TrimSpace(entry.Assignee) {
			itemResult.Reason = "finding already suppressed with matching expiry"
			result.Items = append(result.Items, itemResult)
			result.SkippedCount++
			continue
		}

		expiry := entry.SuppressionExpiresAt.UTC().Format(time.RFC3339)
		triageRequest := FindingTriageRequest{
			Status:               &suppressedStatus,
			SuppressionExpiresAt: &expiry,
			Comment:              comment,
		}
		if strings.TrimSpace(entry.Assignee) != "" {
			assignee := strings.TrimSpace(entry.Assignee)
			triageRequest.Assignee = &assignee
		}
		updated, err := s.TriageFinding(ctx, finding.ID, normalizedScanID, triageRequest, actor)
		if err != nil {
			if errors.Is(err, ErrInvalidFindingTriageRequest) {
				itemResult.Reason = "finding triage update rejected"
				result.Items = append(result.Items, itemResult)
				result.SkippedCount++
				continue
			}
			return FindingBaselineImportResult{}, err
		}
		itemResult.FindingID = updated.ID
		itemResult.SuppressionExpiresAt = cloneTimePointer(updated.Triage.SuppressionExpiresAt)
		itemResult.Status = "applied"
		itemResult.Reason = ""
		result.Items = append(result.Items, itemResult)
		result.AppliedCount++
	}

	return result, nil
}

func (s *Service) loadTargetFindingsForBaselineImport(
	ctx context.Context,
	scanID string,
	now time.Time,
) (map[string]domain.Finding, map[string][]domain.Finding, error) {
	findingsByID := map[string]domain.Finding{}
	findingsByFingerprint := map[string][]domain.Finding{}
	offset := 0

	for {
		page, err := s.Store.ListFindingsFiltered(ctx, db.FindingListFilter{
			ScanID:   scanID,
			SortBy:   "created_at",
			SortDesc: true,
			Limit:    findingBaselineImportPageSize,
			Offset:   offset,
			Now:      now,
		})
		if err != nil {
			return nil, nil, err
		}
		if len(page) == 0 {
			break
		}

		hasMore := len(page) > findingBaselineImportPageSize
		if hasMore {
			page = page[:findingBaselineImportPageSize]
		}
		for _, finding := range enrichFindings(page) {
			findingsByID[strings.TrimSpace(finding.ID)] = finding
			fingerprint := findingBaselineFingerprint(finding)
			if fingerprint == "" {
				continue
			}
			findingsByFingerprint[fingerprint] = append(findingsByFingerprint[fingerprint], finding)
		}
		if !hasMore {
			break
		}
		offset += findingBaselineImportPageSize
	}

	return findingsByID, findingsByFingerprint, nil
}

func scoreFindingConfidence(finding domain.Finding) float64 {
	if isRepoSecretClassifierFinding(finding) {
		if score, ok := normalizeFindingConfidenceScore(finding.ConfidenceScore); ok {
			return score
		}
		if score, ok := findingEvidenceFloat(finding.Evidence, "confidence_score"); ok {
			if normalized, ok := normalizeFindingConfidenceScore(score); ok {
				return normalized
			}
		}
	}
	score := 0.70
	switch finding.Type {
	case domain.FindingOwnerless:
		score = 0.92
	case domain.FindingRiskyTrustPolicy:
		score = 0.88
	case domain.FindingEscalationPath:
		score = 0.86
	case domain.FindingOverPrivileged:
		score = 0.78
	case domain.FindingStaleIdentity:
		score = 0.74
	case domain.FindingSecretExposure:
		score = 0.96
	case domain.FindingRepoMisconfig:
		score = 0.84
	}
	if len(finding.Path) > 0 {
		score += 0.03
	}
	if len(finding.Evidence) > 0 {
		score += 0.03
	}
	if strings.TrimSpace(finding.Repository) != "" || strings.TrimSpace(finding.FilePath) != "" {
		score += 0.02
	}
	if score > 0.99 {
		score = 0.99
	}
	return roundConfidenceScore(score)
}

func isRepoSecretClassifierFinding(finding domain.Finding) bool {
	if finding.Type != domain.FindingSecretExposure {
		return false
	}
	if len(finding.Evidence) == 0 {
		return false
	}
	source, _ := finding.Evidence["confidence_source"].(string)
	if strings.HasPrefix(source, "repo_secret_classifier_v") {
		return true
	}
	state, _ := finding.Evidence["confidence_state"].(string)
	return strings.TrimSpace(state) != "" && (strings.TrimSpace(finding.Repository) != "" || strings.TrimSpace(finding.FilePath) != "" || strings.TrimSpace(finding.Detector) != "")
}

func findingEvidenceFloat(evidence map[string]any, key string) (float64, bool) {
	if len(evidence) == 0 {
		return 0, false
	}
	switch typed := evidence[key].(type) {
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
		value, err := typed.Float64()
		return value, err == nil
	default:
		return 0, false
	}
}

func normalizeFindingConfidenceScore(score float64) (float64, bool) {
	if score <= 0 || math.IsNaN(score) || math.IsInf(score, 0) {
		return 0, false
	}
	if score > 0.99 {
		score = 0.99
	}
	return roundConfidenceScore(score), true
}

func scoreFindingBaselineMatch(entry FindingBaselineEntry, finding domain.Finding) float64 {
	fingerprint := findingBaselineFingerprint(finding)
	if fingerprint != "" && strings.TrimSpace(entry.MatchFingerprint) == fingerprint {
		if strings.TrimSpace(entry.FindingID) == strings.TrimSpace(finding.ID) {
			return 1.00
		}
		return 0.97
	}
	score := 0.0
	if strings.TrimSpace(entry.FindingID) == strings.TrimSpace(finding.ID) {
		score += 0.40
	}
	if entry.Type == finding.Type {
		score += 0.15
	}
	if entry.Severity == finding.Severity {
		score += 0.10
	}
	if normalizeComparableText(entry.Title) == normalizeComparableText(finding.Title) {
		score += 0.10
	}
	if slices.Equal(entry.Path, finding.Path) {
		score += 0.10
	}
	if strings.TrimSpace(entry.MatchFingerprint) == findingBaselineFingerprint(finding) {
		score += 0.15
	}
	return roundConfidenceScore(score)
}

func findingBaselineEntryFromFinding(finding domain.Finding) FindingBaselineEntry {
	return FindingBaselineEntry{
		FindingID:            finding.ID,
		Type:                 finding.Type,
		Severity:             finding.Severity,
		ConfidenceScore:      scoreFindingConfidence(finding),
		Title:                finding.Title,
		HumanSummary:         finding.HumanSummary,
		Path:                 append([]string(nil), finding.Path...),
		Repository:           finding.Repository,
		FilePath:             finding.FilePath,
		Detector:             finding.Detector,
		MatchFingerprint:     findingBaselineFingerprint(finding),
		SuppressionExpiresAt: cloneTimePointer(finding.Triage.SuppressionExpiresAt),
		Assignee:             finding.Triage.Assignee,
	}
}

func findingBaselineFingerprint(finding domain.Finding) string {
	payload := struct {
		Type         domain.FindingType     `json:"type"`
		Severity     domain.FindingSeverity `json:"severity"`
		Title        string                 `json:"title"`
		HumanSummary string                 `json:"human_summary"`
		Path         []string               `json:"path,omitempty"`
		Repository   string                 `json:"repository,omitempty"`
		FilePath     string                 `json:"file_path,omitempty"`
		Detector     string                 `json:"detector,omitempty"`
		Evidence     map[string]any         `json:"evidence,omitempty"`
		Remediation  string                 `json:"remediation,omitempty"`
	}{
		Type:         finding.Type,
		Severity:     finding.Severity,
		Title:        strings.TrimSpace(finding.Title),
		HumanSummary: strings.TrimSpace(finding.HumanSummary),
		Path:         append([]string(nil), finding.Path...),
		Repository:   strings.TrimSpace(finding.Repository),
		FilePath:     strings.TrimSpace(finding.FilePath),
		Detector:     strings.TrimSpace(finding.Detector),
		Evidence:     finding.Evidence,
		Remediation:  strings.TrimSpace(finding.Remediation),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func validateFindingBaselineImportRequest(request FindingBaselineImportRequest) error {
	if strings.TrimSpace(request.Baseline.SchemaVersion) != findingBaselineSchemaVersion {
		return ErrInvalidFindingBaselineRequest
	}
	if len(request.Baseline.Items) == 0 {
		return ErrInvalidFindingBaselineRequest
	}
	for _, entry := range request.Baseline.Items {
		if strings.TrimSpace(entry.FindingID) == "" || strings.TrimSpace(entry.MatchFingerprint) == "" {
			return ErrInvalidFindingBaselineRequest
		}
	}
	return nil
}

func sortFindingBaselineEntries(items []FindingBaselineEntry) {
	slices.SortFunc(items, func(a, b FindingBaselineEntry) int {
		if a.FindingID == b.FindingID {
			return strings.Compare(a.Title, b.Title)
		}
		return strings.Compare(a.FindingID, b.FindingID)
	})
}

func roundConfidenceScore(value float64) float64 {
	return math.Round(value*100) / 100
}

func normalizeComparableText(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := value.UTC()
	return &copied
}

func resolveBaselineImportFinding(
	entry FindingBaselineEntry,
	findingsByID map[string]domain.Finding,
	findingsByFingerprint map[string][]domain.Finding,
) (domain.Finding, string, bool) {
	if finding, exists := findingsByID[strings.TrimSpace(entry.FindingID)]; exists {
		return finding, "", true
	}
	matches := findingsByFingerprint[strings.TrimSpace(entry.MatchFingerprint)]
	switch len(matches) {
	case 0:
		return domain.Finding{}, "finding not present in target scan", false
	case 1:
		return matches[0], "", true
	default:
		return domain.Finding{}, "multiple exact baseline matches found in target scan", false
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
