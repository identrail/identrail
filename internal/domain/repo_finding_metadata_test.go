package domain

import (
	"encoding/json"
	"math"
	"strconv"
	"testing"
	"time"
)

func TestNormalizeRepoFindingMetadataBackfillsFieldsFromEvidence(t *testing.T) {
	finding := Finding{
		Type: FindingSecretExposure,
		Path: []string{"config/app.env"},
		Evidence: map[string]any{
			"repository":         "owner/repo",
			"commit":             "abc123",
			"file_path":          "config/app.env",
			"line_number":        float64(42),
			"detector":           "github-token",
			"confidence_score":   0.37,
			"redacted_line_snip": "GITHUB_TOKEN=ghp_****",
		},
	}

	NormalizeRepoFindingMetadata(&finding)

	if finding.Repository != "owner/repo" || finding.Commit != "abc123" || finding.FilePath != "config/app.env" || finding.LineNumber != 42 || finding.Detector != "github-token" {
		t.Fatalf("unexpected metadata after normalization: %+v", finding)
	}
	if finding.LineSnippet != "GITHUB_TOKEN=ghp_****" {
		t.Fatalf("expected normalized snippet, got %q", finding.LineSnippet)
	}
	if finding.LineSnippetRedacted == nil || !*finding.LineSnippetRedacted {
		t.Fatalf("expected redacted snippet flag, got %+v", finding.LineSnippetRedacted)
	}
	if finding.ConfidenceScore != 0.37 {
		t.Fatalf("expected confidence score to backfill from evidence, got %.2f", finding.ConfidenceScore)
	}
	if got := finding.Evidence["line_snippet"]; got != "GITHUB_TOKEN=ghp_****" {
		t.Fatalf("expected canonical line_snippet evidence, got %v", got)
	}
}

func TestNormalizeRepoFindingMetadataRejectsUnsafeLineNumbers(t *testing.T) {
	for name, value := range map[string]any{
		"negative int64":     int64(-1),
		"oversized int64":    int64(math.MaxInt32) + 1,
		"fractional float":   42.5,
		"oversized float":    float64(math.MaxInt32) + 1,
		"nan":                math.NaN(),
		"positive infinity":  math.Inf(1),
		"oversized json":     json.Number("2147483648"),
		"non-numeric string": "abc",
		"negative string":    "-1",
		"empty string":       "",
		"oversized string":   " 2147483648 ",
	} {
		t.Run(name, func(t *testing.T) {
			finding := Finding{
				Type: FindingRepoMisconfig,
				Evidence: map[string]any{
					"line_number": value,
				},
			}

			NormalizeRepoFindingMetadata(&finding)

			if finding.LineNumber != 0 {
				t.Fatalf("expected unsafe line number to normalize to 0, got %d", finding.LineNumber)
			}
			if _, exists := finding.Evidence["line_number"]; exists {
				t.Fatalf("expected unsafe line_number evidence to be removed, got %+v", finding.Evidence)
			}
		})
	}
}

func TestNormalizeRepoFindingMetadataCanonicalizesStringLineNumber(t *testing.T) {
	finding := Finding{
		Type: FindingRepoMisconfig,
		Evidence: map[string]any{
			"line_number": " 42 ",
		},
	}

	NormalizeRepoFindingMetadata(&finding)

	if finding.LineNumber != 42 {
		t.Fatalf("expected string line number to normalize to 42, got %d", finding.LineNumber)
	}
	if got := finding.Evidence["line_number"]; got != 42 {
		t.Fatalf("expected canonical integer line_number evidence, got %v", got)
	}
}

func TestNormalizeRepoFindingMetadataRejectsUnsafeStructuredLineNumber(t *testing.T) {
	if strconv.IntSize <= 32 {
		t.Skip("oversized structured int line number requires a 64-bit int")
	}
	finding := Finding{
		Type:       FindingRepoMisconfig,
		LineNumber: int(int64(math.MaxInt32) + 1),
		Evidence: map[string]any{
			"line_number": int64(math.MaxInt32) + 1,
		},
	}

	NormalizeRepoFindingMetadata(&finding)

	if finding.LineNumber != 0 {
		t.Fatalf("expected unsafe structured line number to normalize to 0, got %d", finding.LineNumber)
	}
	if _, exists := finding.Evidence["line_number"]; exists {
		t.Fatalf("expected unsafe structured line_number evidence to be removed, got %+v", finding.Evidence)
	}
}

func TestNormalizeRepoFindingMetadataBackfillsEvidenceFromFields(t *testing.T) {
	redacted := false
	finding := Finding{
		Type:                FindingRepoMisconfig,
		Repository:          "git@github.com:owner/repo.git",
		Commit:              "HEAD",
		FilePath:            ".github/workflows/release.yml",
		LineNumber:          18,
		Detector:            "gh-actions-write-all",
		ConfidenceScore:     0.84,
		LineSnippet:         "permissions: write-all",
		LineSnippetRedacted: &redacted,
	}

	NormalizeRepoFindingMetadata(&finding)

	if len(finding.Path) != 1 || finding.Path[0] != ".github/workflows/release.yml" {
		t.Fatalf("expected path to be backfilled, got %+v", finding.Path)
	}
	if got := finding.Evidence["repository"]; got != "git@github.com:owner/repo.git" {
		t.Fatalf("expected repository evidence, got %v", got)
	}
	if got := finding.Evidence["commit"]; got != "HEAD" {
		t.Fatalf("expected commit evidence, got %v", got)
	}
	if got := finding.Evidence["line_snippet"]; got != "permissions: write-all" {
		t.Fatalf("expected line_snippet evidence, got %v", got)
	}
	if got := finding.Evidence["line_snippet_redacted"]; got != false {
		t.Fatalf("expected non-redacted evidence flag, got %v", got)
	}
	if got := finding.Evidence["confidence_score"]; got != 0.84 {
		t.Fatalf("expected confidence evidence, got %v", got)
	}
}

func TestNormalizeRepoFindingMetadataClonesEvidenceBeforeCanonicalization(t *testing.T) {
	originalEvidence := map[string]any{
		"repository":         "owner/repo",
		"commit":             "abc123",
		"file_path":          "config/app.env",
		"line_number":        42,
		"detector":           "github-token",
		"redacted_line_snip": "GITHUB_TOKEN=ghp_****",
	}
	finding := Finding{
		Type:     FindingSecretExposure,
		Evidence: originalEvidence,
	}

	NormalizeRepoFindingMetadata(&finding)

	if _, exists := originalEvidence["line_snippet"]; exists {
		t.Fatalf("expected original evidence map to remain unchanged, got %+v", originalEvidence)
	}
	if _, exists := originalEvidence["repository"]; !exists {
		t.Fatalf("expected original repository evidence to remain unchanged, got %+v", originalEvidence)
	}
	if finding.Evidence["line_snippet"] != "GITHUB_TOKEN=ghp_****" {
		t.Fatalf("expected normalized evidence to contain canonical line_snippet, got %+v", finding.Evidence)
	}
}

func TestNormalizeRepoFindingLifecycleMetadataAndTriageOverlay(t *testing.T) {
	firstSeen := time.Date(2026, 5, 20, 9, 0, 0, 123, time.UTC)
	lastSeen := firstSeen.Add(2 * time.Hour)
	finding := Finding{
		ID:        "repo-finding-1",
		Type:      FindingSecretExposure,
		CreatedAt: firstSeen.Add(-time.Hour),
		Evidence: map[string]any{
			"repository":         "Owner/Repo",
			"detector":           "github-token",
			"file_path":          "config/app.env",
			"line_number":        json.Number("9"),
			"secret_fingerprint": "fp-token",
			"confidence_score":   json.Number("0.73"),
			"lifecycle_status":   "REOPENED",
			"owner_hint":         "platform",
			"first_seen_at":      firstSeen.Format(time.RFC3339Nano),
			"last_seen_at":       lastSeen,
			"scan_mode":          "deep",
			"evidence_version":   "v2",
		},
	}

	NormalizeRepoFindingMetadata(&finding)

	if finding.LifecycleStatus != RepoFindingLifecycleReopened {
		t.Fatalf("expected reopened lifecycle status, got %q", finding.LifecycleStatus)
	}
	if finding.Owner != "platform" || finding.LineNumber != 9 || finding.ConfidenceScore != 0.73 {
		t.Fatalf("expected owner, line, and confidence from evidence, got %+v", finding)
	}
	if finding.FirstSeenAt == nil || !finding.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("expected first_seen_at from evidence, got %+v", finding.FirstSeenAt)
	}
	if finding.LastSeenAt == nil || !finding.LastSeenAt.Equal(lastSeen) {
		t.Fatalf("expected last_seen_at from evidence, got %+v", finding.LastSeenAt)
	}
	if finding.ScanMode != "deep" || finding.EvidenceVersion != "v2" {
		t.Fatalf("expected lifecycle version metadata, got scan_mode=%q evidence_version=%q", finding.ScanMode, finding.EvidenceVersion)
	}
	if finding.LifecycleKey == "" || finding.Evidence["lifecycle_key"] != finding.LifecycleKey {
		t.Fatalf("expected stable lifecycle key to be mirrored into evidence, got key=%q evidence=%+v", finding.LifecycleKey, finding.Evidence)
	}

	for raw, want := range map[string]RepoFindingLifecycleStatus{
		"open":           RepoFindingLifecycleOpen,
		"fixed":          RepoFindingLifecycleFixed,
		"reopened":       RepoFindingLifecycleReopened,
		"suppressed":     RepoFindingLifecycleSuppressed,
		"risk_accepted":  RepoFindingLifecycleRiskAccepted,
		"false_positive": RepoFindingLifecycleFalsePositive,
		"unknown":        "",
	} {
		if got := NormalizeRepoFindingLifecycleStatus(raw); got != want {
			t.Fatalf("NormalizeRepoFindingLifecycleStatus(%q) = %q, want %q", raw, got, want)
		}
	}

	suppressionExpiry := firstSeen.Add(7 * 24 * time.Hour)
	triageUpdated := firstSeen.Add(30 * time.Minute)
	suppressed := Finding{
		LifecycleStatus: RepoFindingLifecycleOpen,
		Triage: FindingTriage{
			Status:               FindingLifecycleSuppressed,
			Assignee:             "appsec",
			UpdatedAt:            &triageUpdated,
			SuppressionExpiresAt: &suppressionExpiry,
		},
	}
	ApplyRepoFindingTriageToLifecycle(&suppressed)
	if suppressed.LifecycleStatus != RepoFindingLifecycleSuppressed || suppressed.Owner != "appsec" {
		t.Fatalf("expected suppression overlay to set lifecycle and owner, got %+v", suppressed)
	}
	if suppressed.DismissedAt == nil || !suppressed.DismissedAt.Equal(triageUpdated) {
		t.Fatalf("expected dismissed_at from triage update time, got %+v", suppressed.DismissedAt)
	}
	if suppressed.SuppressionExpiresAt == nil || !suppressed.SuppressionExpiresAt.Equal(suppressionExpiry) {
		t.Fatalf("expected suppression expiry overlay, got %+v", suppressed.SuppressionExpiresAt)
	}

	resolvedAt := firstSeen.Add(48 * time.Hour)
	resolved := Finding{
		LifecycleStatus: RepoFindingLifecycleReopened,
		Triage: FindingTriage{
			Status:     FindingLifecycleResolved,
			ResolvedAt: &resolvedAt,
		},
	}
	ApplyRepoFindingTriageToLifecycle(&resolved)
	if resolved.LifecycleStatus != RepoFindingLifecycleFixed {
		t.Fatalf("expected resolved triage to mark reopened repo finding fixed, got %q", resolved.LifecycleStatus)
	}
	if resolved.FixedAt == nil || !resolved.FixedAt.Equal(resolvedAt) {
		t.Fatalf("expected fixed_at from triage resolved time, got %+v", resolved.FixedAt)
	}
}
