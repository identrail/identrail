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

func TestPlanFanOutExecutionPrioritizesResumedWorkBeforeNewTargets(t *testing.T) {
	now := time.Date(2026, 6, 12, 13, 50, 0, 0, time.UTC)
	plan := CoveragePlan{
		ConnectorID: "aws-prod",
		GeneratedAt: now,
		Targets: []CoverageTarget{
			{
				Key:         "111111111111|us-east-1|iam",
				AccountID:   "111111111111",
				Region:      "us-east-1",
				Service:     "iam",
				Enabled:     true,
				Priority:    CoveragePriorityCritical,
				State:       CoverageStatePlanned,
				EvidenceRef: "aws://aws-prod/111111111111/us-east-1/iam",
			},
			{
				Key:         "111111111111|eu-west-1|lambda",
				AccountID:   "111111111111",
				Region:      "eu-west-1",
				Service:     "lambda",
				Enabled:     true,
				Priority:    CoveragePriorityHigh,
				State:       CoverageStateInProgress,
				Cursor:      "lambda-page-2",
				Attempts:    1,
				EvidenceRef: "aws://aws-prod/111111111111/eu-west-1/lambda",
			},
		},
	}

	execution, err := PlanFanOutExecution(FanOutExecutionConfig{
		Plan:           plan,
		MaxConcurrency: 1,
		MaxAttempts:    3,
		StartedAt:      now,
	})
	if err != nil {
		t.Fatalf("plan fan-out execution: %v", err)
	}

	targetByKey := map[string]FanOutExecutionTarget{}
	for _, target := range execution.Targets {
		targetByKey[target.Key] = target
	}
	resumed := targetByKey["111111111111|eu-west-1|lambda"]
	if resumed.WorkerState != CoverageStateInProgress || resumed.ConcurrencySlot != 1 {
		t.Fatalf("resumed checkpoint should reserve the first slot before new work: %+v", resumed)
	}
	planned := targetByKey["111111111111|us-east-1|iam"]
	if planned.WorkerState != CoverageStatePending || planned.ConcurrencySlot != 0 {
		t.Fatalf("new work should stay queued while resumed work is active: %+v", planned)
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
		Plan:           coverage,
		MaxConcurrency: 3,
		MaxAttempts:    3,
		StartedAt:      now,
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
	if throttled.WorkerState != CoverageStateFailed || !throttled.Retryable || !throttled.Throttled || throttled.Checkpoint != "lambda-page-2" || throttled.RetryAfter != "" {
		t.Fatalf("expected retryable throttled target with checkpoint and no retry-after requirement: %+v", throttled)
	}
	denied := targetByKey["111111111111|us-east-1|ecs"]
	if denied.WorkerState != CoverageStatePermissionDenied || denied.Retryable {
		t.Fatalf("permission denied should be explicit and non-retryable: %+v", denied)
	}
}

func TestPlanFanOutExecutionHonorsReplayedFailureAttemptLimit(t *testing.T) {
	now := time.Date(2026, 6, 12, 14, 15, 0, 0, time.UTC)
	coverage, err := PlanCoverage(CoveragePlanConfig{
		ConnectorID: "aws-prod",
		Accounts:    []CoverageAccount{{AccountID: "111111111111", Enabled: true}},
		Regions:     []CoverageRegion{{Region: "us-east-1", Enabled: true}},
		Services:    []CoverageService{{Service: "lambda", Enabled: true}, {Service: "ecs", Enabled: true}},
		Checkpoints: []CoverageCheckpoint{
			{
				AccountID:     "111111111111",
				Region:        "us-east-1",
				Service:       "lambda",
				State:         CoverageStateFailed,
				FailureReason: "Throttling: lambda ListFunctions",
				Attempts:      3,
			},
			{
				AccountID:     "111111111111",
				Region:        "us-east-1",
				Service:       "ecs",
				State:         CoverageStatePartial,
				FailureReason: "partial page timeout",
				Attempts:      3,
			},
		},
	}, now)
	if err != nil {
		t.Fatalf("plan coverage: %v", err)
	}

	execution, err := PlanFanOutExecution(FanOutExecutionConfig{
		Plan:        coverage,
		MaxAttempts: 3,
		StartedAt:   now,
	})
	if err != nil {
		t.Fatalf("plan fan-out execution: %v", err)
	}
	if execution.Summary.FailedTargets != 1 || execution.Summary.PartialTargets != 1 || execution.Summary.RetryableTargets != 0 {
		t.Fatalf("failed and partial checkpoints at max attempts should be terminal, got %+v", execution.Summary)
	}
	targetByKey := map[string]FanOutExecutionTarget{}
	for _, target := range execution.Targets {
		targetByKey[target.Key] = target
	}
	failed := targetByKey["111111111111|us-east-1|lambda"]
	if failed.WorkerState != CoverageStateFailed || failed.Retryable || failed.Attempts != 3 {
		t.Fatalf("replayed failure should stay non-retryable at max attempts: %+v", failed)
	}
	partial := targetByKey["111111111111|us-east-1|ecs"]
	if partial.WorkerState != CoverageStatePartial || partial.Retryable || partial.Attempts != 3 {
		t.Fatalf("replayed partial should stay non-retryable at max attempts: %+v", partial)
	}
}

func TestPlanFanOutExecutionHonorsFreshPartialAttemptLimit(t *testing.T) {
	now := time.Date(2026, 6, 12, 14, 20, 0, 0, time.UTC)
	plan := CoveragePlan{
		ConnectorID: "aws-prod",
		GeneratedAt: now,
		Targets: []CoverageTarget{{
			Key:         "111111111111|us-east-1|lambda",
			AccountID:   "111111111111",
			Region:      "us-east-1",
			Service:     "lambda",
			Enabled:     true,
			Priority:    CoveragePriorityHigh,
			State:       CoverageStatePlanned,
			Attempts:    2,
			EvidenceRef: "aws://aws-prod/111111111111/us-east-1/lambda",
		}},
	}

	execution, err := PlanFanOutExecution(FanOutExecutionConfig{
		Plan:        plan,
		MaxAttempts: 3,
		StartedAt:   now,
		Outcomes: []FanOutTargetOutcome{{
			Key:           "111111111111|us-east-1|lambda",
			Outcome:       FanOutExecutionOutcomePartial,
			Cursor:        "lambda-page-3",
			FailureReason: "partial page timeout",
			Retryable:     true,
			ObservedAt:    now,
		}},
	})
	if err != nil {
		t.Fatalf("plan fan-out execution: %v", err)
	}
	if execution.Summary.PartialTargets != 1 || execution.Summary.RetryableTargets != 0 {
		t.Fatalf("fresh partial outcome at max attempts should be terminal, got %+v", execution.Summary)
	}
	target := execution.Targets[0]
	if target.WorkerState != CoverageStatePartial || target.Retryable || target.Attempts != 3 {
		t.Fatalf("fresh partial should stop retrying at max attempts: %+v", target)
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
