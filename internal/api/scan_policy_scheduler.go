package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/scheduler"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

const defaultScanPolicyScheduleLimit = 500

type scanPolicyScheduleStore interface {
	ListScheduledTenancyScanPolicies(ctx context.Context, limit int, offset int) ([]db.TenancyScanPolicy, error)
	ClaimTenancyScanPolicySchedule(ctx context.Context, workspaceID string, projectID string, policyID string, scheduledAt time.Time, now time.Time) (bool, error)
}

// ScanPolicyScheduleResult summarizes one scheduler pass.
type ScanPolicyScheduleResult struct {
	PoliciesChecked int `json:"policies_checked"`
	PoliciesDue     int `json:"policies_due"`
	PoliciesClaimed int `json:"policies_claimed"`
	QueuedScans     int `json:"queued_scans"`
	SkippedScans    int `json:"skipped_scans"`
}

// EnqueueDueScanPolicies finds due scheduled scan policies and enqueues repo scans.
func (s *Service) EnqueueDueScanPolicies(ctx context.Context) (ScanPolicyScheduleResult, error) {
	return s.EnqueueDueScanPoliciesAt(ctx, s.Now().UTC())
}

// EnqueueDueScanPoliciesAt is the deterministic variant used by tests.
func (s *Service) EnqueueDueScanPoliciesAt(ctx context.Context, now time.Time) (ScanPolicyScheduleResult, error) {
	ctx, span := otel.Tracer("identrail/automation").Start(ctx, "automation.scan_policy_scheduler")
	defer span.End()

	store, ok := s.Store.(scanPolicyScheduleStore)
	if !ok {
		span.SetStatus(codes.Error, "scan policy store unavailable")
		return ScanPolicyScheduleResult{}, ErrScanPolicyStoreUnavailable
	}
	now = now.UTC()
	result := ScanPolicyScheduleResult{}
	for offset := 0; ; offset += defaultScanPolicyScheduleLimit {
		policies, err := store.ListScheduledTenancyScanPolicies(ctx, defaultScanPolicyScheduleLimit, offset)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "list scheduled policies failed")
			return result, err
		}
		result.PoliciesChecked += len(policies)
		for _, policy := range policies {
			scheduledAt, due, err := dueScanPolicyTick(policy, now)
			if err != nil {
				result.SkippedScans++
				s.recordAutomationRun("scheduled", "github", "skipped")
				continue
			}
			if !due {
				continue
			}
			result.PoliciesDue++
			s.recordAutomationLag("scheduled", "repo_scan", now.Sub(scheduledAt.UTC()))
			policyResult, err := s.enqueueDueScanPolicy(ctx, store, policy, scheduledAt, now)
			if err != nil {
				s.recordAutomationRun("scheduled", "github", "failed")
				span.RecordError(err)
				span.SetStatus(codes.Error, "enqueue scheduled policy failed")
				return result, err
			}
			result.PoliciesClaimed += policyResult.PoliciesClaimed
			result.QueuedScans += policyResult.QueuedScans
			result.SkippedScans += policyResult.SkippedScans
			s.recordAutomationRuns("scheduled", "github", "queued", policyResult.QueuedScans)
			s.recordAutomationRuns("scheduled", "github", "skipped", policyResult.SkippedScans)
		}
		if len(policies) < defaultScanPolicyScheduleLimit {
			break
		}
	}
	span.SetAttributes(
		attribute.Int("automation.policies_checked", result.PoliciesChecked),
		attribute.Int("automation.policies_due", result.PoliciesDue),
		attribute.Int("automation.policies_claimed", result.PoliciesClaimed),
		attribute.Int("automation.queued_scans", result.QueuedScans),
		attribute.Int("automation.skipped_scans", result.SkippedScans),
	)
	return result, nil
}

func (s *Service) enqueueDueScanPolicy(ctx context.Context, store scanPolicyScheduleStore, policy db.TenancyScanPolicy, scheduledAt time.Time, now time.Time) (ScanPolicyScheduleResult, error) {
	lockKey := s.lockKey(fmt.Sprintf("scan-policy:%s:%s:%s:%s", policy.TenantID, policy.WorkspaceID, policy.ProjectID, policy.PolicyID))
	if s.Locker != nil {
		release, acquired := s.Locker.TryAcquire(ctx, lockKey)
		if !acquired {
			return ScanPolicyScheduleResult{SkippedScans: 1}, nil
		}
		defer release(context.Background())
	}

	scope := db.Scope{TenantID: policy.TenantID, WorkspaceID: policy.WorkspaceID}
	scopedCtx := db.WithScope(ctx, scope)

	result := ScanPolicyScheduleResult{}
	processed := 0
	if !s.RepoScanEnabled {
		return ScanPolicyScheduleResult{SkippedScans: 1}, nil
	}
	claimed, err := store.ClaimTenancyScanPolicySchedule(scopedCtx, policy.WorkspaceID, policy.ProjectID, policy.PolicyID, scheduledAt, now)
	if err != nil {
		return result, err
	}
	if !claimed {
		return ScanPolicyScheduleResult{SkippedScans: 1}, nil
	}
	result.PoliciesClaimed = 1

	status, err := s.GetGitHubConnection(scopedCtx, policy.WorkspaceID, policy.ProjectID)
	if err != nil {
		return result, err
	}

	maxConcurrent := policy.MaxConcurrentScans
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	for _, repository := range status.SelectedRepositories {
		if processed >= maxConcurrent {
			break
		}

		request := RepoScanRequest{
			Repository:   repository,
			HistoryLimit: policy.HistoryLimit,
			MaxFindings:  policy.MaxFindings,
		}
		if strings.EqualFold(status.Provider, "github_app") {
			request.ProjectID = policy.ProjectID
			request.ConnectorID = firstNonEmptyString(status.ConnectorID, githubConnectorID)
		}
		_, err := s.EnqueueRepoScan(scopedCtx, request)
		if err != nil {
			if isExpectedScheduledRepoSkip(err) {
				result.SkippedScans++
				if skipConsumesPolicyConcurrency(err) {
					processed++
				}
				continue
			}
			return result, err
		}
		result.QueuedScans++
		processed++
	}
	return result, nil
}

func dueScanPolicyTick(policy db.TenancyScanPolicy, now time.Time) (time.Time, bool, error) {
	schedule, err := scheduler.ParseCronSchedule(policy.Cron)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parse scan policy cron %q: %w", policy.PolicyID, err)
	}
	after := policy.CreatedAt
	if policy.LastScheduledAt != nil {
		after = *policy.LastScheduledAt
	} else if after.IsZero() {
		after = now.Add(-time.Minute)
	} else {
		after = after.Add(-time.Minute)
	}
	tick, ok := schedule.LatestAfter(after, now)
	return tick, ok, nil
}

func isExpectedScheduledRepoSkip(err error) bool {
	return errors.Is(err, ErrRepoScanInProgress) ||
		errors.Is(err, ErrRepoScanQueueFull) ||
		errors.Is(err, ErrRepoScanDisabled) ||
		errors.Is(err, ErrRepoTargetNotAllowed) ||
		strings.Contains(strings.ToLower(err.Error()), "not connected")
}

func skipConsumesPolicyConcurrency(err error) bool {
	return errors.Is(err, ErrRepoScanInProgress) ||
		errors.Is(err, ErrRepoScanQueueFull)
}
