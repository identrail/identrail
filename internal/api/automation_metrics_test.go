package api

import (
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAutomationMetricLabelsAreBounded(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "source scheduled", got: automationSourceLabel(" scheduled "), want: "scheduled"},
		{name: "source unknown", got: automationSourceLabel("tenant-a"), want: "other"},
		{name: "connector github", got: automationConnectorLabel(" GitHub "), want: "github"},
		{name: "connector unknown", got: automationConnectorLabel("owner/repo"), want: "other"},
		{name: "outcome partial", got: automationOutcomeLabel(" partial "), want: "partial"},
		{name: "outcome unknown", got: automationOutcomeLabel("custom"), want: "other"},
		{name: "queue repo", got: automationQueueLabel(" repo_scan "), want: "repo_scan"},
		{name: "queue unknown", got: automationQueueLabel("tenant-queue"), want: "other"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestRecordAutomationMetrics(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.Metrics = telemetry.NewMetrics()

	svc.recordAutomationRun("event", "github", "queued")
	svc.recordAutomationRuns("scheduled", "github", "skipped", 2)
	svc.recordAutomationRuns("scheduled", "github", "failed", 0)
	svc.recordAutomationLag("api_queue", "scan", -5*time.Second)
	svc.recordAutomationLag("api_queue", "repo_scan", 1500*time.Millisecond)

	if got := testutil.ToFloat64(svc.Metrics.AutomationRunsTotal.WithLabelValues("event", "github", "queued")); got != 1 {
		t.Fatalf("event github queued metric = %v, want 1", got)
	}
	if got := testutil.ToFloat64(svc.Metrics.AutomationRunsTotal.WithLabelValues("scheduled", "github", "skipped")); got != 2 {
		t.Fatalf("scheduled github skipped metric = %v, want 2", got)
	}
	if got := testutil.ToFloat64(svc.Metrics.AutomationRunsTotal.WithLabelValues("scheduled", "github", "failed")); got != 0 {
		t.Fatalf("scheduled github failed metric = %v, want 0", got)
	}
	if got := testutil.CollectAndCount(svc.Metrics.AutomationLagMS); got == 0 {
		t.Fatal("expected automation lag metric to be collected")
	}
}
