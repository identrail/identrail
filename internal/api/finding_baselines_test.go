package api

import (
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestScoreFindingBaselineMatch(t *testing.T) {
	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	base := domain.Finding{
		ID:           "finding-1",
		Type:         domain.FindingOwnerless,
		Severity:     domain.SeverityHigh,
		Title:        "Ownerless identity: payments-role",
		HumanSummary: "No ownership metadata is attached to this identity.",
		Path:         []string{"identity:payments-role"},
		Evidence:     map[string]any{"identity_id": "identity:payments-role"},
		CreatedAt:    now,
	}
	entry := findingBaselineEntryFromFinding(base)

	if score := scoreFindingBaselineMatch(entry, base); score != 1 {
		t.Fatalf("expected exact id+fingerprint match score 1.00, got %.2f", score)
	}

	renumbered := base
	renumbered.ID = "finding-2"
	if score := scoreFindingBaselineMatch(entry, renumbered); score != 0.97 {
		t.Fatalf("expected exact fingerprint fallback score 0.97, got %.2f", score)
	}

	changed := base
	changed.HumanSummary = "Ownership metadata is still missing after the latest scan."
	if score := scoreFindingBaselineMatch(entry, changed); score >= findingBaselineImportMatchThreshold {
		t.Fatalf("expected changed variant score below threshold, got %.2f", score)
	}
}

func TestValidateFindingBaselineImportRequestRejectsInvalidShapes(t *testing.T) {
	valid := FindingBaselineImportRequest{
		Baseline: FindingBaseline{
			SchemaVersion: findingBaselineSchemaVersion,
			Items: []FindingBaselineEntry{{
				FindingID:        "finding-1",
				MatchFingerprint: "abc123",
			}},
		},
	}
	if err := validateFindingBaselineImportRequest(valid); err != nil {
		t.Fatalf("expected valid baseline import request, got %v", err)
	}

	cases := []FindingBaselineImportRequest{
		{},
		{Baseline: FindingBaseline{SchemaVersion: "v0", Items: valid.Baseline.Items}},
		{Baseline: FindingBaseline{SchemaVersion: findingBaselineSchemaVersion}},
		{Baseline: FindingBaseline{SchemaVersion: findingBaselineSchemaVersion, Items: []FindingBaselineEntry{{MatchFingerprint: "abc123"}}}},
		{Baseline: FindingBaseline{SchemaVersion: findingBaselineSchemaVersion, Items: []FindingBaselineEntry{{FindingID: "finding-1"}}}},
	}
	for _, tc := range cases {
		if err := validateFindingBaselineImportRequest(tc); !errors.Is(err, ErrInvalidFindingBaselineRequest) {
			t.Fatalf("expected invalid request error for %+v, got %v", tc, err)
		}
	}
}

func TestResolveBaselineImportFinding(t *testing.T) {
	findingByID := domain.Finding{ID: "finding-1"}
	findingByFingerprint := domain.Finding{ID: "finding-2"}

	byID, reason, ok := resolveBaselineImportFinding(
		FindingBaselineEntry{FindingID: "finding-1", MatchFingerprint: "fp-1"},
		map[string]domain.Finding{"finding-1": findingByID},
		map[string][]domain.Finding{},
	)
	if !ok || reason != "" || byID.ID != "finding-1" {
		t.Fatalf("expected id lookup to win, got finding=%+v reason=%q ok=%v", byID, reason, ok)
	}

	byFingerprint, reason, ok := resolveBaselineImportFinding(
		FindingBaselineEntry{FindingID: "missing", MatchFingerprint: "fp-1"},
		map[string]domain.Finding{},
		map[string][]domain.Finding{"fp-1": {findingByFingerprint}},
	)
	if !ok || reason != "" || byFingerprint.ID != "finding-2" {
		t.Fatalf("expected fingerprint fallback to resolve, got finding=%+v reason=%q ok=%v", byFingerprint, reason, ok)
	}

	if _, reason, ok := resolveBaselineImportFinding(
		FindingBaselineEntry{FindingID: "missing", MatchFingerprint: "missing"},
		map[string]domain.Finding{},
		map[string][]domain.Finding{},
	); ok || reason != "finding not present in target scan" {
		t.Fatalf("expected missing finding reason, got reason=%q ok=%v", reason, ok)
	}

	if _, reason, ok := resolveBaselineImportFinding(
		FindingBaselineEntry{FindingID: "missing", MatchFingerprint: "fp-2"},
		map[string]domain.Finding{},
		map[string][]domain.Finding{"fp-2": {findingByFingerprint, findingByID}},
	); ok || reason != "multiple exact baseline matches found in target scan" {
		t.Fatalf("expected ambiguous fingerprint reason, got reason=%q ok=%v", reason, ok)
	}
}

func TestSortFindingBaselineEntriesAndHelpers(t *testing.T) {
	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	items := []FindingBaselineEntry{
		{FindingID: "finding-2", Title: "zeta"},
		{FindingID: "finding-1", Title: "omega"},
		{FindingID: "finding-1", Title: "alpha"},
	}
	sortFindingBaselineEntries(items)
	if items[0].Title != "alpha" || items[1].Title != "omega" || items[2].FindingID != "finding-2" {
		t.Fatalf("unexpected baseline sort order: %+v", items)
	}

	cloned := cloneTimePointer(&now)
	if cloned == nil || !cloned.Equal(now) || cloned == &now {
		t.Fatalf("expected cloned time pointer, got %+v", cloned)
	}
	if cloneTimePointer(nil) != nil {
		t.Fatal("expected nil clone for nil input")
	}

	if got := normalizeComparableText("  Risky Trust  "); got != "risky trust" {
		t.Fatalf("unexpected comparable text normalization %q", got)
	}
	if got := max(2, 5); got != 5 {
		t.Fatalf("expected max helper to return 5, got %d", got)
	}
}
