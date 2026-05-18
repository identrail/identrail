package worker

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/config"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRunWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := config.Config{
		AllowMemoryStore:  true,
		LogLevel:          "info",
		ServiceName:       "identrail-test",
		Provider:          "aws",
		ScanInterval:      10 * time.Millisecond,
		WorkerScanEnabled: true,
		WorkerRunNow:      false,
		AWSFixturePath:    []string{"testdata/aws/role_with_policies.json"},
		APIKeys:           []string{"test-read"},
		WriteAPIKeys:      []string{"test-read"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunFailsWhenStartupScanCannotReadFixtures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		AllowMemoryStore:  true,
		LogLevel:          "info",
		ServiceName:       "identrail-test",
		Provider:          "aws",
		ScanInterval:      10 * time.Millisecond,
		WorkerScanEnabled: true,
		WorkerRunNow:      true,
		AWSFixturePath:    []string{"/path/does/not/exist.json"},
		APIKeys:           []string{"test-read"},
		WriteAPIKeys:      []string{"test-read"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err == nil {
		t.Fatal("expected startup scan error")
	}
}

func TestRunFailsWithInvalidStoreConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		LogLevel:          "info",
		ServiceName:       "identrail-test",
		Provider:          "aws",
		ScanInterval:      10 * time.Millisecond,
		WorkerScanEnabled: true,
		WorkerRunNow:      false,
		AWSFixturePath:    []string{"testdata/aws/role_with_policies.json"},
		DatabaseURL:       "postgres://user:pass@127.0.0.1:1/identrail?sslmode=disable&connect_timeout=1",
		APIKeys:           []string{"test-read"},
		WriteAPIKeys:      []string{"test-read"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err == nil {
		t.Fatal("expected store initialization error")
	}
}

func TestRunFailsWithInvalidSecurityConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		LogLevel:          "info",
		ServiceName:       "identrail-test",
		Provider:          "aws",
		ScanInterval:      10 * time.Millisecond,
		WorkerScanEnabled: true,
		WorkerRunNow:      false,
		AWSFixturePath:    []string{"testdata/aws/role_with_policies.json"},
		APIKeys:           []string{"reader"},
		WriteAPIKeys:      []string{"writer"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err == nil {
		t.Fatal("expected security validation error")
	}
}

func TestRunWithCancelledContextAndRepoWorkerEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := config.Config{
		AllowMemoryStore:       true,
		LogLevel:               "info",
		ServiceName:            "identrail-test",
		Provider:               "aws",
		ScanInterval:           10 * time.Millisecond,
		WorkerScanEnabled:      true,
		WorkerRunNow:           false,
		AWSFixturePath:         []string{"testdata/aws/role_with_policies.json"},
		APIKeys:                []string{"test-read"},
		WriteAPIKeys:           []string{"test-read"},
		RepoScanEnabled:        true,
		RepoScanAllowlist:      []string{"owner/repo"},
		WorkerRepoScanEnabled:  true,
		WorkerRepoScanRunNow:   false,
		WorkerRepoScanInterval: 15 * time.Minute,
		WorkerRepoScanTargets:  []string{"owner/repo"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunFailsWhenWorkerRepoStartupScanTargetIsInvalid(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		LogLevel:               "info",
		ServiceName:            "identrail-test",
		Provider:               "aws",
		ScanInterval:           10 * time.Millisecond,
		WorkerScanEnabled:      true,
		WorkerRunNow:           false,
		AWSFixturePath:         []string{"testdata/aws/role_with_policies.json"},
		APIKeys:                []string{"test-read"},
		WriteAPIKeys:           []string{"test-read"},
		RepoScanEnabled:        true,
		RepoScanAllowlist:      []string{"*"},
		WorkerRepoScanEnabled:  true,
		WorkerRepoScanRunNow:   true,
		WorkerRepoScanInterval: 15 * time.Minute,
		WorkerRepoScanTargets:  []string{"/path/does/not/exist"},
		WorkerRepoScanHistory:  1,
		WorkerRepoScanFindings: 10,
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err == nil {
		t.Fatal("expected worker repo startup scan error")
	}
}

func TestWithTimeoutIfNoneAddsDeadline(t *testing.T) {
	ctx, cancel := withTimeoutIfNone(context.Background(), 250*time.Millisecond)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected timeout helper to add a deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 500*time.Millisecond {
		t.Fatalf("unexpected timeout window: %v", remaining)
	}
}

func TestWithTimeoutIfNonePreservesExistingDeadline(t *testing.T) {
	parent, parentCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer parentCancel()
	parentDeadline, _ := parent.Deadline()

	ctx, cancel := withTimeoutIfNone(parent, 250*time.Millisecond)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected existing parent deadline to be preserved")
	}
	if !deadline.Equal(parentDeadline) {
		t.Fatalf("expected deadline %v, got %v", parentDeadline, deadline)
	}
}

func TestWithJobTimeoutWrapsQueueProcessing(t *testing.T) {
	wrapped := withJobTimeout(func(ctx context.Context) (bool, error) {
		_, ok := ctx.Deadline()
		return ok, nil
	}, 250*time.Millisecond)

	processed, err := wrapped(context.Background())
	if err != nil {
		t.Fatalf("wrapped queue process returned error: %v", err)
	}
	if !processed {
		t.Fatal("expected wrapped queue process to receive a deadline")
	}
}

func TestProcessAPIQueueBatchReturnsErrorWhenProcessingFails(t *testing.T) {
	scanErrors := 0
	repoErrors := 0
	err := processAPIQueueBatch(
		context.Background(),
		1,
		func(context.Context) (bool, error) { return false, errors.New("scan failure") },
		func(context.Context) (bool, error) { return false, errors.New("repo failure") },
		func(error) { scanErrors++ },
		func(error) { repoErrors++ },
	)
	if err == nil {
		t.Fatal("expected queue batch error")
	}
	if !strings.Contains(err.Error(), "api queue batch failed for 2 job(s)") {
		t.Fatalf("unexpected queue batch error: %v", err)
	}
	if scanErrors != 1 || repoErrors != 1 {
		t.Fatalf("expected one callback per processing error, got scan=%d repo=%d", scanErrors, repoErrors)
	}
}

func TestProcessAPIQueueBatchReturnsNilWhenNoFailures(t *testing.T) {
	err := processAPIQueueBatch(
		context.Background(),
		2,
		func(context.Context) (bool, error) { return false, nil },
		func(context.Context) (bool, error) { return false, nil },
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestProcessAPIQueueBatchRepoFailuresContinueWithinBatch(t *testing.T) {
	repoCalls := 0
	repoErrors := 0

	err := processAPIQueueBatch(
		context.Background(),
		3,
		func(context.Context) (bool, error) { return false, nil },
		func(context.Context) (bool, error) {
			repoCalls++
			if repoCalls == 1 {
				return true, errors.New("repo-a failed")
			}
			if repoCalls == 2 {
				return true, nil
			}
			return false, nil
		},
		nil,
		func(error) { repoErrors++ },
	)
	if err == nil {
		t.Fatal("expected queue batch error")
	}
	if repoCalls < 2 {
		t.Fatalf("expected repo queue to continue after first failure, got %d calls", repoCalls)
	}
	if repoErrors != 1 {
		t.Fatalf("expected one repo error callback, got %d", repoErrors)
	}
	if !strings.Contains(err.Error(), "api queue batch failed for 1 job(s)") {
		t.Fatalf("unexpected queue batch error: %v", err)
	}
}

func TestWorkerAutomationMetricLabelsAreBounded(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "source scheduled", got: workerAutomationSourceLabel(" scheduled "), want: "scheduled"},
		{name: "source unknown", got: workerAutomationSourceLabel("workspace-a"), want: "other"},
		{name: "connector aws", got: workerAutomationConnectorLabel(" AWS "), want: "aws"},
		{name: "connector unknown", got: workerAutomationConnectorLabel("owner/repo"), want: "other"},
		{name: "outcome requeued", got: workerAutomationOutcomeLabel(" requeued "), want: "requeued"},
		{name: "outcome unknown", got: workerAutomationOutcomeLabel("custom"), want: "other"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestRecordWorkerAutomationRun(t *testing.T) {
	metrics := telemetry.NewMetrics()

	recordWorkerAutomationRun(metrics, "scheduled", "aws", "succeeded")
	recordWorkerAutomationRun(metrics, "scheduled", "kubernetes", "partial")
	recordWorkerAutomationRun(nil, "scheduled", "aws", "failed")

	if got := testutil.ToFloat64(metrics.AutomationRunsTotal.WithLabelValues("scheduled", "aws", "succeeded")); got != 1 {
		t.Fatalf("scheduled aws succeeded metric = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.AutomationRunsTotal.WithLabelValues("scheduled", "kubernetes", "partial")); got != 1 {
		t.Fatalf("scheduled kubernetes partial metric = %v, want 1", got)
	}
}
