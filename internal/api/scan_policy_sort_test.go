package api

import (
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func TestSortScanPolicies(t *testing.T) {
	base := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name    string
		sortBy  string
		desc    bool
		wantIDs []string
	}{
		{
			name:    "created_at default ascending",
			sortBy:  "",
			wantIDs: []string{"policy-b", "policy-a", "policy-c"},
		},
		{
			name:    "policy_id descending",
			sortBy:  "policy_id",
			desc:    true,
			wantIDs: []string{"policy-c", "policy-b", "policy-a"},
		},
		{
			name:    "name ascending with policy id tie break",
			sortBy:  "name",
			wantIDs: []string{"policy-a", "policy-c", "policy-b"},
		},
		{
			name:    "trigger_mode ascending",
			sortBy:  "trigger_mode",
			wantIDs: []string{"policy-c", "policy-a", "policy-b"},
		},
		{
			name:    "updated_at descending",
			sortBy:  "updated_at",
			desc:    true,
			wantIDs: []string{"policy-b", "policy-a", "policy-c"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := []db.TenancyScanPolicy{
				{
					PolicyID:    "policy-a",
					Name:        "baseline",
					TriggerMode: domain.ScanTriggerModeManual,
					CreatedAt:   base.Add(1 * time.Hour),
					UpdatedAt:   base.Add(2 * time.Hour),
				},
				{
					PolicyID:    "policy-b",
					Name:        "release",
					TriggerMode: domain.ScanTriggerModeScheduled,
					CreatedAt:   base,
					UpdatedAt:   base.Add(3 * time.Hour),
				},
				{
					PolicyID:    "policy-c",
					Name:        "baseline",
					TriggerMode: domain.ScanTriggerModeEvent,
					CreatedAt:   base.Add(2 * time.Hour),
					UpdatedAt:   base.Add(1 * time.Hour),
				},
			}

			sortScanPolicies(items, tc.sortBy, tc.desc)

			for idx, wantID := range tc.wantIDs {
				if gotID := items[idx].PolicyID; gotID != wantID {
					t.Fatalf("item %d = %q, want %q", idx, gotID, wantID)
				}
			}
		})
	}
}
