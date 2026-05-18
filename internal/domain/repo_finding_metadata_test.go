package domain

import "testing"

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
