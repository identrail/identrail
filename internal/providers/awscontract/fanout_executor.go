package awscontract

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// FanOutExecutorVersion is the stable contract operators and APIs cite for
// account/region/service execution state.
const FanOutExecutorVersion = "aws-account-region-fanout-executor-v1"

// FanOutExecutionOutcome is the simulated or persisted worker outcome for one
// target attempt.
type FanOutExecutionOutcome string

const (
	FanOutExecutionOutcomeCovered          FanOutExecutionOutcome = "covered"
	FanOutExecutionOutcomePartial          FanOutExecutionOutcome = "partial"
	FanOutExecutionOutcomeFailed           FanOutExecutionOutcome = "failed"
	FanOutExecutionOutcomePermissionDenied FanOutExecutionOutcome = "permission_denied"
	FanOutExecutionOutcomeThrottled        FanOutExecutionOutcome = "throttled"
)

// FanOutExecutionConfig controls bounded fan-out over a coverage plan.
type FanOutExecutionConfig struct {
	Plan               CoveragePlan
	MaxConcurrency     int
	MaxAttempts        int
	ThrottleRetryAfter time.Duration
	Outcomes           []FanOutTargetOutcome
	StartedAt          time.Time
}

// FanOutTargetOutcome supplies known execution results for deterministic worker
// planning and persisted-state replay.
type FanOutTargetOutcome struct {
	Key           string
	Outcome       FanOutExecutionOutcome
	Cursor        string
	FailureReason string
	Retryable     bool
	ObservedAt    time.Time
}

// FanOutExecutionTarget is one executable worker unit with its scheduling and
// checkpoint state.
type FanOutExecutionTarget struct {
	Key             string           `json:"key"`
	AccountID       string           `json:"account_id"`
	Region          string           `json:"region"`
	Service         string           `json:"service"`
	Priority        CoveragePriority `json:"priority"`
	State           CoverageState    `json:"state"`
	WorkerState     CoverageState    `json:"worker_state"`
	Enabled         bool             `json:"enabled"`
	Attempts        int              `json:"attempts"`
	MaxAttempts     int              `json:"max_attempts"`
	ConcurrencySlot int              `json:"concurrency_slot"`
	Checkpoint      string           `json:"checkpoint,omitempty"`
	Retryable       bool             `json:"retryable"`
	Throttled       bool             `json:"throttled"`
	RetryAfter      string           `json:"retry_after,omitempty"`
	FailureReason   string           `json:"failure_reason,omitempty"`
	EvidenceRef     string           `json:"evidence_ref"`
	NextAction      string           `json:"next_action"`
	ObservedAt      time.Time        `json:"observed_at,omitempty"`
}

// FanOutExecutionSummary aggregates worker-visible execution state.
type FanOutExecutionSummary struct {
	TotalTargets            int `json:"total_targets"`
	ExecutableTargets       int `json:"executable_targets"`
	SkippedTargets          int `json:"skipped_targets"`
	QueuedTargets           int `json:"queued_targets"`
	InProgressTargets       int `json:"in_progress_targets"`
	CoveredTargets          int `json:"covered_targets"`
	PartialTargets          int `json:"partial_targets"`
	FailedTargets           int `json:"failed_targets"`
	PermissionDeniedTargets int `json:"permission_denied_targets"`
	ThrottledTargets        int `json:"throttled_targets"`
	RetryableTargets        int `json:"retryable_targets"`
	ConcurrencyLimit        int `json:"concurrency_limit"`
	MaxAttempts             int `json:"max_attempts"`
}

// FanOutExecutionPlan is the deterministic worker execution view.
type FanOutExecutionPlan struct {
	Version   string                  `json:"version"`
	Targets   []FanOutExecutionTarget `json:"targets"`
	Summary   FanOutExecutionSummary  `json:"summary"`
	StartedAt time.Time               `json:"started_at"`
	UpdatedAt time.Time               `json:"updated_at"`
}

// PlanFanOutExecution maps a coverage plan onto bounded worker state. It does
// not call AWS, mutate AWS, or inspect customer payloads.
func PlanFanOutExecution(config FanOutExecutionConfig) (FanOutExecutionPlan, error) {
	concurrency := config.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	attempts := config.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}
	startedAt := config.StartedAt
	if startedAt.IsZero() {
		startedAt = config.Plan.GeneratedAt
	}
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	outcomes, err := indexFanOutOutcomes(config.Outcomes)
	if err != nil {
		return FanOutExecutionPlan{}, err
	}

	targets := make([]FanOutExecutionTarget, 0, len(config.Plan.Targets))
	summary := FanOutExecutionSummary{
		TotalTargets:     len(config.Plan.Targets),
		ConcurrencyLimit: concurrency,
		MaxAttempts:      attempts,
	}
	runningSlot := 0
	planned := make(map[string]struct{}, len(config.Plan.Targets))
	appendTarget := func(coverageTarget CoverageTarget) {
		target := buildFanOutExecutionTarget(coverageTarget, outcomes[coverageTarget.Key], attempts, config.ThrottleRetryAfter, &runningSlot, concurrency, startedAt)
		targets = append(targets, target)
		summarizeFanOutExecutionTarget(&summary, target)
		planned[coverageTarget.Key] = struct{}{}
	}
	for _, coverageTarget := range config.Plan.Targets {
		if coverageTarget.State == CoverageStateInProgress && outcomes[coverageTarget.Key].Key == "" {
			appendTarget(coverageTarget)
		}
	}
	for _, coverageTarget := range config.Plan.Targets {
		if _, ok := planned[coverageTarget.Key]; ok {
			continue
		}
		appendTarget(coverageTarget)
	}

	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].ConcurrencySlot != targets[j].ConcurrencySlot {
			return targets[i].ConcurrencySlot < targets[j].ConcurrencySlot
		}
		return targets[i].Key < targets[j].Key
	})

	return FanOutExecutionPlan{
		Version:   FanOutExecutorVersion,
		Targets:   targets,
		Summary:   summary,
		StartedAt: startedAt.UTC(),
		UpdatedAt: startedAt.UTC(),
	}, nil
}

func buildFanOutExecutionTarget(target CoverageTarget, outcome FanOutTargetOutcome, maxAttempts int, throttleRetryAfter time.Duration, runningSlot *int, concurrency int, observedAt time.Time) FanOutExecutionTarget {
	execution := FanOutExecutionTarget{
		Key:         target.Key,
		AccountID:   target.AccountID,
		Region:      target.Region,
		Service:     target.Service,
		Priority:    target.Priority,
		State:       target.State,
		WorkerState: target.State,
		Enabled:     target.Enabled,
		Attempts:    target.Attempts,
		MaxAttempts: maxAttempts,
		EvidenceRef: target.EvidenceRef,
		ObservedAt:  target.ObservedAt,
	}
	if execution.ObservedAt.IsZero() {
		execution.ObservedAt = observedAt.UTC()
	}
	if target.Cursor != "" {
		execution.Checkpoint = target.Cursor
	}
	if target.FailureReason != "" {
		execution.FailureReason = target.FailureReason
	}

	if !target.Enabled || target.State == CoverageStateDisabled || target.State == CoverageStateUnsupported || target.State == CoverageStateBlocked {
		execution.WorkerState = target.State
		execution.NextAction = fanOutSkippedNextAction(target.State)
		return execution
	}

	if outcome.Key != "" {
		applyFanOutOutcome(&execution, outcome, maxAttempts, throttleRetryAfter)
		return execution
	}

	switch target.State {
	case CoverageStateCovered, CoverageStatePermissionDenied, CoverageStateFailed, CoverageStatePartial:
		execution.WorkerState = target.State
		execution.Retryable = target.State == CoverageStateFailed || target.State == CoverageStatePartial
		if execution.Retryable && execution.Attempts >= maxAttempts {
			execution.Retryable = false
		}
	case CoverageStateInProgress:
		execution.Retryable = true
		if execution.Checkpoint == "" {
			execution.Checkpoint = target.Key + ":cursor"
		}
		if *runningSlot < concurrency {
			*runningSlot++
			execution.ConcurrencySlot = *runningSlot
			execution.WorkerState = CoverageStateInProgress
		} else {
			execution.WorkerState = CoverageStatePending
		}
	default:
		if *runningSlot < concurrency {
			*runningSlot++
			execution.ConcurrencySlot = *runningSlot
			execution.WorkerState = CoverageStateInProgress
			execution.Retryable = true
			execution.Attempts++
			execution.Checkpoint = target.Key + ":started"
		} else {
			execution.WorkerState = CoverageStatePending
			execution.Retryable = true
		}
	}
	execution.NextAction = fanOutNextAction(execution)
	return execution
}

func applyFanOutOutcome(target *FanOutExecutionTarget, outcome FanOutTargetOutcome, maxAttempts int, throttleRetryAfter time.Duration) {
	if outcome.Cursor != "" {
		target.Checkpoint = strings.TrimSpace(outcome.Cursor)
	}
	if outcome.FailureReason != "" {
		target.FailureReason = strings.TrimSpace(outcome.FailureReason)
	}
	if !outcome.ObservedAt.IsZero() {
		target.ObservedAt = outcome.ObservedAt.UTC()
	}
	switch outcome.Outcome {
	case FanOutExecutionOutcomeCovered:
		target.WorkerState = CoverageStateCovered
		target.State = CoverageStateCovered
		target.Retryable = false
		target.FailureReason = ""
	case FanOutExecutionOutcomePartial:
		target.WorkerState = CoverageStatePartial
		target.State = CoverageStatePartial
		target.Retryable = true
	case FanOutExecutionOutcomePermissionDenied:
		target.WorkerState = CoverageStatePermissionDenied
		target.State = CoverageStatePermissionDenied
		target.Retryable = false
	case FanOutExecutionOutcomeThrottled:
		target.WorkerState = CoverageStateFailed
		target.State = CoverageStateFailed
		target.Retryable = true
		target.Throttled = true
		if throttleRetryAfter > 0 {
			target.RetryAfter = throttleRetryAfter.String()
		}
	case FanOutExecutionOutcomeFailed:
		target.WorkerState = CoverageStateFailed
		target.State = CoverageStateFailed
		target.Retryable = outcome.Retryable
	default:
		target.WorkerState = CoverageStateFailed
		target.State = CoverageStateFailed
		target.Retryable = true
	}
	target.Attempts++
	if target.Attempts >= maxAttempts && (target.WorkerState == CoverageStateFailed || target.WorkerState == CoverageStatePartial) {
		target.Retryable = false
	}
	target.NextAction = fanOutNextAction(*target)
}

func fanOutSkippedNextAction(state CoverageState) string {
	switch state {
	case CoverageStateBlocked:
		return "Resolve account onboarding or region prerequisites before queueing this target."
	case CoverageStateUnsupported:
		return "Keep unsupported account/region/service targets out of the worker queue."
	case CoverageStateDisabled:
		return "Enable the target in coverage configuration before queueing."
	default:
		return "Target is not executable in its current coverage state."
	}
}

func fanOutNextAction(target FanOutExecutionTarget) string {
	switch target.WorkerState {
	case CoverageStateCovered:
		return "Persist covered checkpoint and continue with the next target."
	case CoverageStateInProgress:
		return "Worker is collecting this target within the concurrency limit."
	case CoverageStatePending:
		return "Keep queued until a worker slot is available."
	case CoverageStatePartial:
		return "Persist partial evidence and resume from the checkpoint on rerun."
	case CoverageStateFailed:
		if target.Retryable {
			return "Retry with bounded backoff and preserve the checkpoint."
		}
		return "Record terminal failure and require operator review before rerun."
	case CoverageStatePermissionDenied:
		return "Record permission denied and wait for read-only role remediation."
	default:
		return "Queue target for the next bounded fan-out execution."
	}
}

func summarizeFanOutExecutionTarget(summary *FanOutExecutionSummary, target FanOutExecutionTarget) {
	if target.Enabled && target.WorkerState != CoverageStateBlocked && target.WorkerState != CoverageStateUnsupported && target.WorkerState != CoverageStateDisabled {
		summary.ExecutableTargets++
	} else {
		summary.SkippedTargets++
	}
	if target.Retryable {
		summary.RetryableTargets++
	}
	switch target.WorkerState {
	case CoverageStatePending:
		summary.QueuedTargets++
	case CoverageStateInProgress:
		summary.InProgressTargets++
	case CoverageStateCovered:
		summary.CoveredTargets++
	case CoverageStatePartial:
		summary.PartialTargets++
	case CoverageStateFailed:
		summary.FailedTargets++
		if target.Throttled {
			summary.ThrottledTargets++
		}
	case CoverageStatePermissionDenied:
		summary.PermissionDeniedTargets++
	}
}

func indexFanOutOutcomes(input []FanOutTargetOutcome) (map[string]FanOutTargetOutcome, error) {
	index := make(map[string]FanOutTargetOutcome, len(input))
	for _, outcome := range input {
		key := strings.TrimSpace(outcome.Key)
		if key == "" {
			return nil, fmt.Errorf("fan-out outcome key is required")
		}
		outcome.Key = key
		outcome.Cursor = strings.TrimSpace(outcome.Cursor)
		outcome.FailureReason = strings.TrimSpace(outcome.FailureReason)
		index[key] = outcome
	}
	return index, nil
}
