package db

import (
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestNormalizeTenancyScanPolicyForWriteValidation(t *testing.T) {
	valid := TenancyScanPolicy{
		TenantID:    "tenant",
		WorkspaceID: "workspace",
		ProjectID:   "project",
		PolicyID:    "policy",
		Name:        "baseline",
	}

	for _, tc := range []struct {
		name   string
		mutate func(*TenancyScanPolicy)
		want   string
	}{
		{
			name: "tenant required",
			mutate: func(policy *TenancyScanPolicy) {
				policy.TenantID = " "
			},
			want: "tenant id is required",
		},
		{
			name: "workspace required",
			mutate: func(policy *TenancyScanPolicy) {
				policy.WorkspaceID = " "
			},
			want: "workspace id is required",
		},
		{
			name: "project required",
			mutate: func(policy *TenancyScanPolicy) {
				policy.ProjectID = " "
			},
			want: "project id is required",
		},
		{
			name: "policy required",
			mutate: func(policy *TenancyScanPolicy) {
				policy.PolicyID = " "
			},
			want: "policy id is required",
		},
		{
			name: "name required",
			mutate: func(policy *TenancyScanPolicy) {
				policy.Name = " "
			},
			want: "scan policy name is required",
		},
		{
			name: "valid trigger mode required",
			mutate: func(policy *TenancyScanPolicy) {
				policy.TriggerMode = domain.ScanTriggerMode("sometimes")
			},
			want: "invalid scan policy trigger mode",
		},
		{
			name: "cron required for scheduled",
			mutate: func(policy *TenancyScanPolicy) {
				policy.TriggerMode = domain.ScanTriggerModeScheduled
			},
			want: "scan policy cron is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := valid
			tc.mutate(&policy)

			_, err := NormalizeTenancyScanPolicyForWrite(policy)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestNormalizeTenancyScanPolicyForWriteCanonicalizes(t *testing.T) {
	created := time.Date(2026, 5, 12, 13, 0, 0, 0, time.FixedZone("scan-policy-test", 3600))
	updated := created.Add(time.Hour)

	got, err := NormalizeTenancyScanPolicyForWrite(TenancyScanPolicy{
		TenantID:    " tenant ",
		WorkspaceID: " workspace ",
		ProjectID:   " project ",
		PolicyID:    " policy ",
		Name:        " Baseline ",
		TriggerMode: domain.ScanTriggerMode(" HYBRID "),
		Cron:        " */15 * * * * ",
		CreatedAt:   created,
		UpdatedAt:   updated,
	})
	if err != nil {
		t.Fatalf("NormalizeTenancyScanPolicyForWrite() error = %v", err)
	}

	if got.TenantID != "tenant" || got.WorkspaceID != "workspace" || got.ProjectID != "project" || got.PolicyID != "policy" {
		t.Fatalf("ids were not trimmed: %#v", got)
	}
	if got.Name != "Baseline" {
		t.Fatalf("Name = %q, want Baseline", got.Name)
	}
	if got.TriggerMode != domain.ScanTriggerModeHybrid {
		t.Fatalf("TriggerMode = %q, want %q", got.TriggerMode, domain.ScanTriggerModeHybrid)
	}
	if got.Cron != "*/15 * * * *" {
		t.Fatalf("Cron = %q, want trimmed cron", got.Cron)
	}
	if got.MaxConcurrentScans != 1 {
		t.Fatalf("MaxConcurrentScans = %d, want default 1", got.MaxConcurrentScans)
	}
	if got.HistoryLimit <= 0 || got.MaxFindings <= 0 {
		t.Fatalf("limits were not defaulted: history=%d findings=%d", got.HistoryLimit, got.MaxFindings)
	}
	if got.CreatedAt.Location() != time.UTC || got.UpdatedAt.Location() != time.UTC {
		t.Fatalf("timestamps were not normalized to UTC: created=%s updated=%s", got.CreatedAt.Location(), got.UpdatedAt.Location())
	}
}

func TestNormalizeTenancyScanPolicyForWriteDefaultsManualPolicy(t *testing.T) {
	got, err := NormalizeTenancyScanPolicyForWrite(TenancyScanPolicy{
		TenantID:    "tenant",
		WorkspaceID: "workspace",
		ProjectID:   "project",
		PolicyID:    "manual",
		Name:        "Manual scan",
		Cron:        "0 * * * *",
	})
	if err != nil {
		t.Fatalf("NormalizeTenancyScanPolicyForWrite() error = %v", err)
	}

	if got.TriggerMode != domain.ScanTriggerModeManual {
		t.Fatalf("TriggerMode = %q, want %q", got.TriggerMode, domain.ScanTriggerModeManual)
	}
	if got.Cron != "" {
		t.Fatalf("Cron = %q, want empty cron for manual policy", got.Cron)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("timestamps were not defaulted: created=%s updated=%s", got.CreatedAt, got.UpdatedAt)
	}
	if !got.UpdatedAt.Equal(got.CreatedAt) {
		t.Fatalf("UpdatedAt = %s, want CreatedAt %s", got.UpdatedAt, got.CreatedAt)
	}
}
