package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/scheduler"
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
	store, ok := s.Store.(scanPolicyScheduleStore)
	if !ok {
		return ScanPolicyScheduleResult{}, ErrScanPolicyStoreUnavailable
	}
	now = now.UTC()
	result := ScanPolicyScheduleResult{}
	for offset := 0; ; offset += defaultScanPolicyScheduleLimit {
		policies, err := store.ListScheduledTenancyScanPolicies(ctx, defaultScanPolicyScheduleLimit, offset)
		if err != nil {
			return result, err
		}
		result.PoliciesChecked += len(policies)
		for _, policy := range policies {
			scheduledAt, due, err := dueScanPolicyTick(policy, now)
			if err != nil {
				result.SkippedScans++
				continue
			}
			if !due {
				continue
			}
			result.PoliciesDue++
			policyResult, err := s.enqueueDueScanPolicy(ctx, store, policy, scheduledAt, now)
			if err != nil {
				return result, err
			}
			result.PoliciesClaimed += policyResult.PoliciesClaimed
			result.QueuedScans += policyResult.QueuedScans
			result.SkippedScans += policyResult.SkippedScans
		}
		if len(policies) < defaultScanPolicyScheduleLimit {
			break
		}
	}
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
		_, err := s.EnqueueRepoScan(scopedCtx, RepoScanRequest{
			Repository:   repository,
			HistoryLimit: policy.HistoryLimit,
			MaxFindings:  policy.MaxFindings,
		})
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
