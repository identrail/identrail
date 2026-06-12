package awscontract

import (
	"testing"
	"time"
)

func TestPlanFanOutExecutionBoundsConcurrency(t *testing.T) {
	now := time.Date(2026, 6, 12, 13, 30, 0, 0, time.UTC)
	config := sampleCoverageConfig()
	config.Services = []CoverageService{
		{Service: "iam", Enabled: true, Priority: CoveragePriorityCritical, Global: true},
		{Service: "ec2", Enabled: true, Priority: CoveragePriorityHigh},
		{Service: "lambda", Enabled: true, Priority: CoveragePriorityHigh},
	}
	coverage, err := PlanCoverage(config, now)
	if err != nil {
		t.Fatalf("plan coverage: %v", err)
	}

	execution, err := PlanFanOutExecution(FanOutExecutionConfig{
		Plan:           coverage,
		MaxConcurrency: 2,
		MaxAttempts:    3,
		StartedAt:      now,
	})
	if err != nil {
		t.Fatalf("plan fan-out execution: %v", err)
	}

	if execution.Version != FanOutExecutorVersion {
		t.Fatalf("unexpected version %q", execution.Version)
	}
	if execution.Summary.ConcurrencyLimit != 2 || execution.Summary.InProgressTargets != 2 {
		t.Fatalf("expected two running targets, got %+v", execution.Summary)
	}
	if execution.Summary.QueuedTargets == 0 {
		t.Fatalf("expected remaining executable targets to stay queued: %+v", execution.Summary)
	}
	for _, target := range execution.Targets {
		if target.ConcurrencySlot > 2 {
			t.Fatalf("target exceeded concurrency limit: %+v", target)
		}
		if target.WorkerState == CoverageStateInProgress && target.Checkpoint == "" {
			t.Fatalf("in-progress target should carry a checkpoint: %+v", target)
		}
	}
}

func TestPlanFanOutExecutionCountsResumedWorkAgainstConcurrency(t *testing.T) {
	now := time.Date(2026, 6, 12, 13, 45, 0, 0, time.UTC)
	config := sampleCoverageConfig()
	config.Services = []CoverageService{
		{Service: "iam", Enabled: true, Priority: CoveragePriorityCritical, Global: true},
		{Service: "lambda", Enabled: true, Priority: CoveragePriorityHigh},
	}
	config.Checkpoints = []CoverageCheckpoint{
		{AccountID: "111111111111", Region: "eu-west-1", Service: "lambda", State: CoverageStateInProgress, Cursor: "lambda-page-2", Attempts: 1},
	}
	coverage, err := PlanCoverage(config, now)
	if err != nil {
		t.Fatalf("plan coverage: %v", err)
	}

	execution, err := PlanFanOutExecution(FanOutExecutionConfig{
		Plan:           coverage,
		MaxConcurrency: 1,
		MaxAttempts:    3,
		StartedAt:      now,
	})
	if err != nil {
		t.Fatalf("plan fan-out execution: %v", err)
	}

	if execution.Summary.ConcurrencyLimit != 1 || execution.Summary.InProgressTargets != 1 {
		t.Fatalf("expected exactly one resumed target to occupy the worker slot, got %+v", execution.Summary)
	}
	if execution.Summary.QueuedTargets == 0 {
		t.Fatalf("expected new executable targets to remain queued while resumed work is running: %+v", execution.Summary)
	}
	var resumed FanOutExecutionTarget
	for _, target := range execution.Targets {
		if target.Key == "111111111111|eu-west-1|lambda" {
			resumed = target
			break
		}
	}
	if resumed.WorkerState != CoverageStateInProgress || resumed.ConcurrencySlot != 1 || resumed.Checkpoint != "lambda-page-2" || resumed.Attempts != 1 {
		t.Fatalf("resumed target should keep its checkpoint and consume the only slot: %+v", resumed)
	}
	for _, target := range execution.Targets {
		if target.Key != resumed.Key && target.WorkerState == CoverageStateInProgress {
			t.Fatalf("new target started even though resumed work already consumed concurrency: %+v", target)
		}
	}
}

func TestPlanFanOutExecutionKeepsFailuresTargetScoped(t *testing.T) {
	now := time.Date(2026, 6, 12, 14, 0, 0, 0, time.UTC)
	coverage, err := PlanCoverage(CoveragePlanConfig{
		ConnectorID: "aws-prod",
		Accounts:    []CoverageAccount{{AccountID: "111111111111", Enabled: true}},
		Regions:     []CoverageRegion{{Region: "us-east-1", Enabled: true}},
		Services: []CoverageService{
			{Service: "iam", Enabled: true, Global: true},
			{Service: "lambda", Enabled: true},
			{Service: "ecs", Enabled: true},
		},
	}, now)
	if err != nil {
		t.Fatalf("plan coverage: %v", err)
	}

	execution, err := PlanFanOutExecution(FanOutExecutionConfig{
		Plan:               coverage,
		MaxConcurrency:     3,
		MaxAttempts:        3,
		ThrottleRetryAfter: 30 * time.Second,
		StartedAt:          now,
		Outcomes: []FanOutTargetOutcome{
			{Key: "111111111111|us-east-1|iam", Outcome: FanOutExecutionOutcomeCovered, ObservedAt: now},
			{Key: "111111111111|us-east-1|lambda", Outcome: FanOutExecutionOutcomeThrottled, Cursor: "lambda-page-2", FailureReason: "Throttling: lambda ListFunctions", Retryable: true, ObservedAt: now},
			{Key: "111111111111|us-east-1|ecs", Outcome: FanOutExecutionOutcomePermissionDenied, FailureReason: "AccessDenied: ecs ListClusters", ObservedAt: now},
		},
	})
	if err != nil {
		t.Fatalf("plan fan-out execution: %v", err)
	}

	if execution.Summary.CoveredTargets != 1 || execution.Summary.FailedTargets != 1 || execution.Summary.PermissionDeniedTargets != 1 {
		t.Fatalf("unexpected execution summary: %+v", execution.Summary)
	}
	if execution.Summary.ThrottledTargets != 1 || execution.Summary.RetryableTargets != 1 {
		t.Fatalf("expected exactly one retryable throttled target: %+v", execution.Summary)
	}
	targetByKey := map[string]FanOutExecutionTarget{}
	for _, target := range execution.Targets {
		targetByKey[target.Key] = target
	}
	throttled := targetByKey["111111111111|us-east-1|lambda"]
	if throttled.WorkerState != CoverageStateFailed || !throttled.Retryable || throttled.Checkpoint != "lambda-page-2" || throttled.RetryAfter == "" {
		t.Fatalf("expected retryable throttled target with checkpoint: %+v", throttled)
	}
	denied := targetByKey["111111111111|us-east-1|ecs"]
	if denied.WorkerState != CoverageStatePermissionDenied || denied.Retryable {
		t.Fatalf("permission denied should be explicit and non-retryable: %+v", denied)
	}
}

func TestPlanFanOutExecutionSkipsNonExecutableTargets(t *testing.T) {
	now := time.Date(2026, 6, 12, 14, 30, 0, 0, time.UTC)
	coverage, err := PlanCoverage(CoveragePlanConfig{
		ConnectorID: "aws-prod",
		Accounts:    []CoverageAccount{{AccountID: "111111111111", Enabled: true}},
		Regions:     []CoverageRegion{{Region: "us-east-1", Enabled: true}, {Region: "eu-west-1", Enabled: true, OptIn: true}},
		Services:    []CoverageService{{Service: "lambda", Enabled: true}},
		ServiceAvailability: []CoverageAccountServiceAvailability{{
			AccountID: "111111111111",
			Region:    "us-east-1",
			Service:   "lambda",
			State:     CoverageStateUnsupported,
			Reason:    "lambda unsupported in fixture service scope",
		}},
	}, now)
	if err != nil {
		t.Fatalf("plan coverage: %v", err)
	}

	execution, err := PlanFanOutExecution(FanOutExecutionConfig{Plan: coverage, MaxConcurrency: 2, StartedAt: now})
	if err != nil {
		t.Fatalf("plan fan-out execution: %v", err)
	}

	if execution.Summary.SkippedTargets != 2 || execution.Summary.ExecutableTargets != 0 {
		t.Fatalf("blocked and unsupported targets should be skipped, got %+v", execution.Summary)
	}
	for _, target := range execution.Targets {
		if target.WorkerState == CoverageStateInProgress || target.WorkerState == CoverageStatePending {
			t.Fatalf("non-executable target was queued: %+v", target)
		}
	}
}
