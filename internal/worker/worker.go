package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/config"
	"github.com/identrail/identrail/internal/runtime"
	"github.com/identrail/identrail/internal/scheduler"
	"github.com/identrail/identrail/internal/telemetry"
)

const (
	defaultWorkerTriggerMaxAttempts = 3
	defaultWorkerRetryBackoff       = 2 * time.Second
	defaultWorkerQueueMaxAttempts   = 1
	defaultWorkerScanTimeout        = 10 * time.Minute
	defaultWorkerRepoScanTimeout    = 30 * time.Minute
)

type queueProcessFunc func(context.Context) (bool, error)

// Run starts the scheduled worker loop and exits on signal or context cancellation.
func Run(ctx context.Context, cfg config.Config, signals <-chan os.Signal) error {
	logger, err := telemetry.NewLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()
	if err := config.ValidateSecurity(cfg); err != nil {
		return fmt.Errorf("validate security config: %w", err)
	}
	for _, warning := range config.SecurityWarnings(cfg) {
		logger.Warn("security configuration warning", telemetry.String("detail", warning))
	}
	for _, diagnostic := range config.StartupDiagnostics(cfg) {
		logger.Info("startup configuration diagnostic", telemetry.String("detail", diagnostic))
	}

	traceShutdown, err := telemetry.SetupTracing(ctx, cfg.ServiceName+"-worker")
	if err != nil {
		return fmt.Errorf("initialize tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = traceShutdown(shutdownCtx)
	}()

	svc, closeStore, err := runtime.BuildScanServiceWithContext(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closeStore() }()
	metrics := telemetry.NewMetrics()
	svc.Metrics = metrics
	svc.OnAlertError = func(alertErr error) {
		logger.Warn("scan alert delivery failed", telemetry.ZapError(alertErr))
	}
	writeHeartbeat := func() {
		if err := writeWorkerHeartbeat(cfg.WorkerHeartbeatPath); err != nil {
			logger.Warn("worker heartbeat write failed", telemetry.ZapError(err))
		}
	}
	writeHeartbeat()

	cloudTrigger := func(runCtx context.Context) error {
		writeHeartbeat()
		scanCtx, cancel := withTimeoutIfNone(runCtx, defaultWorkerScanTimeout)
		defer cancel()
		result, runErr := svc.RunScan(scanCtx)
		if runErr != nil {
			if errors.Is(runErr, api.ErrScanInProgress) {
				logger.Info("scan skipped because another run is in progress", telemetry.StandardLogFields("worker", "scheduled_scan", telemetry.String("provider", cfg.Provider), telemetry.String("outcome", "skipped_in_progress"))...)
				return nil
			}
			logger.Error("scheduled scan failed", telemetry.StandardLogFields("worker", "scheduled_scan", telemetry.String("provider", cfg.Provider), telemetry.String("outcome", "failed"), telemetry.ZapError(runErr))...)
			return runErr
		}
		logger.Info("scheduled scan completed", telemetry.StandardLogFields("worker", "scheduled_scan", telemetry.String("provider", cfg.Provider), telemetry.String("scan_id", result.Scan.ID), telemetry.String("outcome", "completed"))...)
		return nil
	}
	repoTrigger := func(runCtx context.Context) error {
		writeHeartbeat()
		failures := 0
		for _, target := range cfg.WorkerRepoScanTargets {
			repoCtx, cancel := withTimeoutIfNone(runCtx, defaultWorkerRepoScanTimeout)
			repoRun, runErr := svc.RunRepoScanPersisted(repoCtx, api.RepoScanRequest{
				Repository:   target,
				HistoryLimit: cfg.WorkerRepoScanHistory,
				MaxFindings:  cfg.WorkerRepoScanFindings,
			})
			cancel()
			if runErr != nil {
				if errors.Is(runErr, api.ErrRepoScanInProgress) {
					logger.Info("repo scan skipped because another run is in progress", telemetry.StandardLogFields("worker", "scheduled_repo_scan", telemetry.String("repository", target), telemetry.String("outcome", "skipped_in_progress"))...)
					continue
				}
				failures++
				logger.Error("scheduled repo scan failed", telemetry.StandardLogFields("worker", "scheduled_repo_scan", telemetry.String("repository", target), telemetry.String("outcome", "failed"), telemetry.ZapError(runErr))...)
				continue
			}
			logger.Info(
				"scheduled repo scan completed",
				telemetry.StandardLogFields("worker", "scheduled_repo_scan",
					telemetry.String("repository", target),
					telemetry.String("repo_scan_id", repoRun.RepoScan.ID),
					telemetry.String("outcome", "completed"),
				)...,
			)
		}
		if failures > 0 {
			return fmt.Errorf("repo scan batch failed for %d target(s)", failures)
		}
		return nil
	}
	queueBatchSize := cfg.WorkerAPIJobQueueBatchSize
	if queueBatchSize <= 0 {
		queueBatchSize = 1
	}
	apiQueueTrigger := func(runCtx context.Context) error {
		writeHeartbeat()
		return processAPIQueueBatch(
			runCtx,
			queueBatchSize,
			withJobTimeout(svc.ProcessNextQueuedScan, defaultWorkerScanTimeout),
			withJobTimeout(svc.ProcessNextQueuedRepoScan, defaultWorkerRepoScanTimeout),
			func(err error) {
				logger.Error("queued scan processing failed", telemetry.StandardLogFields("worker", "api_queue_scan", telemetry.String("outcome", "failed"), telemetry.ZapError(err))...)
			},
			func(err error) {
				logger.Error("queued repo scan processing failed", telemetry.StandardLogFields("worker", "api_queue_repo_scan", telemetry.String("outcome", "failed"), telemetry.ZapError(err))...)
			},
		)
	}
	scanPolicyTrigger := func(runCtx context.Context) error {
		writeHeartbeat()
		result, runErr := svc.EnqueueDueScanPolicies(runCtx)
		if runErr != nil {
			logger.Error("scan policy scheduler failed", telemetry.StandardLogFields("worker", "scan_policy_scheduler", telemetry.String("outcome", "failed"), telemetry.ZapError(runErr))...)
			return runErr
		}
		logger.Info(
			"scan policy scheduler completed",
			telemetry.StandardLogFields("worker", "scan_policy_scheduler",
				telemetry.String("policies_checked", fmt.Sprint(result.PoliciesChecked)),
				telemetry.String("policies_due", fmt.Sprint(result.PoliciesDue)),
				telemetry.String("policies_claimed", fmt.Sprint(result.PoliciesClaimed)),
				telemetry.String("queued_scans", fmt.Sprint(result.QueuedScans)),
				telemetry.String("skipped_scans", fmt.Sprint(result.SkippedScans)),
				telemetry.String("outcome", "completed"),
			)...,
		)
		return nil
	}

	type scheduledRunner struct {
		name   string
		runNow bool
		runner scheduler.Runner
	}

	scanPolicyRunnerKey := "scan-policy-scheduler"
	if namespace := strings.TrimSpace(svc.LockNamespace); namespace != "" {
		scanPolicyRunnerKey = namespace + ":" + scanPolicyRunnerKey
	}

	runners := []scheduledRunner{{
		name:   "cloud",
		runNow: cfg.WorkerRunNow,
		runner: scheduler.Runner{
			Interval:     cfg.ScanInterval,
			Key:          "scan:" + cfg.Provider,
			Trigger:      cloudTrigger,
			MaxAttempts:  defaultWorkerTriggerMaxAttempts,
			RetryBackoff: defaultWorkerRetryBackoff,
			OnDeadLetter: func(_ context.Context, err error) {
				metrics.WorkerDeadLettersTotal.WithLabelValues("cloud").Inc()
				logger.Error("cloud trigger exhausted retries; dead-letter event emitted", telemetry.ZapError(err))
			},
			OnError: func(_ context.Context, err error) {
				metrics.WorkerRetriesTotal.WithLabelValues("cloud").Inc()
				logger.Error("cloud runner iteration failed", telemetry.ZapError(err))
			},
		},
	}}
	if cfg.WorkerRepoScanEnabled {
		runners = append(runners, scheduledRunner{
			name:   "repo",
			runNow: cfg.WorkerRepoScanRunNow,
			runner: scheduler.Runner{
				Interval:     cfg.WorkerRepoScanInterval,
				Key:          "repo-scan",
				Trigger:      repoTrigger,
				MaxAttempts:  defaultWorkerTriggerMaxAttempts,
				RetryBackoff: defaultWorkerRetryBackoff,
				OnDeadLetter: func(_ context.Context, err error) {
					metrics.WorkerDeadLettersTotal.WithLabelValues("repo").Inc()
					logger.Error("repo trigger exhausted retries; dead-letter event emitted", telemetry.ZapError(err))
				},
				OnError: func(_ context.Context, err error) {
					metrics.WorkerRetriesTotal.WithLabelValues("repo").Inc()
					logger.Error("repo runner iteration failed", telemetry.ZapError(err))
				},
			},
		})
	}
	if cfg.WorkerAPIJobQueueEnabled {
		runners = append(runners, scheduledRunner{
			name:   "api-queue",
			runNow: false,
			runner: scheduler.Runner{
				Interval:     cfg.WorkerAPIJobQueueInterval,
				Key:          "api-job-queue",
				Trigger:      apiQueueTrigger,
				MaxAttempts:  defaultWorkerQueueMaxAttempts,
				RetryBackoff: defaultWorkerRetryBackoff,
				OnDeadLetter: func(_ context.Context, err error) {
					metrics.WorkerDeadLettersTotal.WithLabelValues("api_queue").Inc()
					logger.Error("api job queue trigger exhausted retries; dead-letter event emitted", telemetry.ZapError(err))
				},
				OnError: func(_ context.Context, err error) {
					metrics.WorkerRetriesTotal.WithLabelValues("api_queue").Inc()
					logger.Error("api queue runner iteration failed", telemetry.ZapError(err))
				},
			},
		})
	}
	if cfg.WorkerScanPolicyEnabled {
		runners = append(runners, scheduledRunner{
			name:   "scan-policy",
			runNow: false,
			runner: scheduler.Runner{
				Interval:     cfg.WorkerScanPolicyInterval,
				Key:          scanPolicyRunnerKey,
				Locker:       svc.Locker,
				Trigger:      scanPolicyTrigger,
				MaxAttempts:  defaultWorkerQueueMaxAttempts,
				RetryBackoff: defaultWorkerRetryBackoff,
				OnDeadLetter: func(_ context.Context, err error) {
					metrics.WorkerDeadLettersTotal.WithLabelValues("scan_policy").Inc()
					logger.Error("scan policy scheduler exhausted retries; dead-letter event emitted", telemetry.ZapError(err))
				},
				OnError: func(_ context.Context, err error) {
					metrics.WorkerRetriesTotal.WithLabelValues("scan_policy").Inc()
					logger.Error("scan policy scheduler iteration failed", telemetry.ZapError(err))
				},
			},
		})
	}

	for _, item := range runners {
		if !item.runNow {
			continue
		}
		if err := item.runner.RunOnce(ctx); err != nil {
			return fmt.Errorf("%s startup run: %w", item.name, err)
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(runners))
	for _, item := range runners {
		runSpec := item
		go func() {
			err := runSpec.runner.Start(runCtx)
			if err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("%s runner failed: %w", runSpec.name, err)
				return
			}
			errCh <- nil
		}()
	}

	select {
	case <-ctx.Done():
		cancel()
		return nil
	case <-signals:
		cancel()
		return nil
	case runErr := <-errCh:
		return runErr
	}
}

func writeWorkerHeartbeat(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	payload := []byte(time.Now().UTC().Format(time.RFC3339Nano) + "\n")
	return os.WriteFile(path, payload, 0o600)
}

func withTimeoutIfNone(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline || timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func withJobTimeout(fn queueProcessFunc, timeout time.Duration) queueProcessFunc {
	if fn == nil {
		return nil
	}
	return func(ctx context.Context) (bool, error) {
		jobCtx, cancel := withTimeoutIfNone(ctx, timeout)
		defer cancel()
		return fn(jobCtx)
	}
}

func processAPIQueueBatch(
	ctx context.Context,
	batchSize int,
	processScan queueProcessFunc,
	processRepoScan queueProcessFunc,
	onScanError func(error),
	onRepoError func(error),
) error {
	if batchSize <= 0 {
		batchSize = 1
	}
	type batchResult struct {
		failures int
		firstErr error
	}
	runBatch := func(process queueProcessFunc, onError func(error)) batchResult {
		result := batchResult{}
		for i := 0; i < batchSize; i++ {
			processed, err := process(ctx)
			if err != nil {
				result.failures++
				if result.firstErr == nil {
					result.firstErr = err
				}
				if onError != nil {
					onError(err)
				}
				continue
			}
			if !processed {
				break
			}
		}
		return result
	}
	scanCh := make(chan batchResult, 1)
	repoCh := make(chan batchResult, 1)
	go func() { scanCh <- runBatch(processScan, onScanError) }()
	go func() { repoCh <- runBatch(processRepoScan, onRepoError) }()
	scanResult := <-scanCh
	repoResult := <-repoCh
	failures := scanResult.failures + repoResult.failures
	firstErr := scanResult.firstErr
	if firstErr == nil {
		firstErr = repoResult.firstErr
	}
	if failures > 0 {
		return fmt.Errorf("api queue batch failed for %d job(s): %w", failures, firstErr)
	}
	return nil
}
