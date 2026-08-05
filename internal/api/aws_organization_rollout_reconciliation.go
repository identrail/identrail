package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	awsOrganizationRolloutValidationConcurrency = 16
	awsOrganizationRolloutRegistrationTimeout   = 15 * time.Minute
	awsOrganizationRolloutRevalidationInterval  = 24 * time.Hour
)

// AWSOrganizationRolloutRetryRequest selects retryable target rows. Empty
// selectors retry every eligible failed target in the rollout; selectors are
// always matched against rows already present in the approved envelope and
// can never broaden its account or region scope.
type AWSOrganizationRolloutRetryRequest struct {
	AccountIDs []string `json:"account_ids,omitempty"`
	Regions    []string `json:"regions,omitempty"`
}

// AWSOrganizationRolloutReconcileResult records one bounded reconciliation
// pass. The API returns the refreshed status separately, while this result is
// useful to worker logs and tests without exposing provider payloads.
type AWSOrganizationRolloutReconcileResult struct {
	RolloutID        string `json:"rollout_id"`
	TargetsExamined  int    `json:"targets_examined"`
	TargetsValidated int    `json:"targets_validated"`
	TargetsConnected int    `json:"targets_connected"`
	TargetsFailed    int    `json:"targets_failed"`
	TargetsDeferred  int    `json:"targets_deferred"`
}

// ReconcileAWSOrganizationRollout validates registered member roles and
// derives the aggregate rollout state from exact target rows. It is safe to
// call repeatedly: target writes are promote-only, validation is bounded, and
// optimistic versions prevent one worker pass from overwriting another.
func (s *Service) ReconcileAWSOrganizationRollout(ctx context.Context, workspaceID string, projectID string, rolloutID string) (AWSOrganizationRolloutReconcileResult, AWSOrganizationRolloutStatus, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSOrganizationRolloutReconcileResult{}, AWSOrganizationRolloutStatus{}, err
	}
	store, err := s.awsOrganizationRolloutStore()
	if err != nil {
		return AWSOrganizationRolloutReconcileResult{}, AWSOrganizationRolloutStatus{}, err
	}
	rollout, err := store.GetAWSOrganizationRollout(ctx, project.WorkspaceID, project.ProjectID, rolloutID)
	if err != nil {
		return AWSOrganizationRolloutReconcileResult{}, AWSOrganizationRolloutStatus{}, err
	}
	result, err := s.reconcileAWSOrganizationRollout(ctx, store, rollout)
	if err != nil {
		return result, AWSOrganizationRolloutStatus{}, err
	}
	refreshed, err := store.GetAWSOrganizationRollout(ctx, project.WorkspaceID, project.ProjectID, rollout.RolloutID)
	if err != nil {
		return result, AWSOrganizationRolloutStatus{}, err
	}
	status, err := s.buildAWSOrganizationRolloutStatus(ctx, store, refreshed, false)
	return result, status, err
}

// ReconcileAWSOrganizationRollouts runs the worker-facing cross-scope pass.
// Each envelope is re-scoped from persisted tenant/workspace fields before
// target reads or writes; a single broken envelope is reported while other
// tenants continue to reconcile.
func (s *Service) ReconcileAWSOrganizationRollouts(ctx context.Context, limit int) (int, error) {
	store, err := s.awsOrganizationRolloutStore()
	if err != nil {
		return 0, err
	}
	rollouts, err := store.ListActiveAWSOrganizationRollouts(ctx, limit)
	if err != nil {
		return 0, err
	}
	processed := 0
	var firstErr error
	for _, rollout := range rollouts {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		scopedCtx := db.WithScope(ctx, db.Scope{TenantID: rollout.TenantID, WorkspaceID: rollout.WorkspaceID})
		if _, err := s.reconcileAWSOrganizationRollout(scopedCtx, store, rollout); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("reconcile rollout %s: %w", rollout.RolloutID, err)
			}
			continue
		}
		processed++
	}
	return processed, firstErr
}

// RetryAWSOrganizationRollout reactivates the parent envelope before resetting
// any failed, retryable target rows. The parent update is the lifecycle gate:
// it atomically reclaims the active connector slot, so a replacement rollout
// cannot win that slot after target rows have already been moved in flight.
// The explicit target transition is still required because normal upserts
// reject terminal-to-in-flight downgrades, protecting connected targets from
// late registration events.
func (s *Service) RetryAWSOrganizationRollout(ctx context.Context, workspaceID string, projectID string, rolloutID string, request AWSOrganizationRolloutRetryRequest) (AWSOrganizationRolloutStatus, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	store, err := s.awsOrganizationRolloutStore()
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	rollout, err := store.GetAWSOrganizationRollout(ctx, project.WorkspaceID, project.ProjectID, rolloutID)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	now := s.Now().UTC()
	if !now.Before(rollout.ExpiresAt) || rollout.Status == db.AWSOrganizationRolloutStatusExpired {
		return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutExpired
	}
	if rollout.Status == db.AWSOrganizationRolloutStatusCompleted || rollout.Status == db.AWSOrganizationRolloutStatusCanceled {
		return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutNoRetryableTargets
	}
	accountFilter := normalizedAWSOrganizationRolloutFilter(request.AccountIDs, false)
	regionFilter := normalizedAWSOrganizationRolloutFilter(request.Regions, true)
	targets, err := store.ListAWSOrganizationRolloutTargets(ctx, project.WorkspaceID, project.ProjectID, rollout.RolloutID)
	if err != nil {
		return AWSOrganizationRolloutStatus{}, err
	}
	retryTargets := make([]db.AWSOrganizationRolloutTarget, 0)
	for _, target := range targets {
		if target.State != db.AWSOrganizationRolloutTargetFailed && target.State != db.AWSOrganizationRolloutTargetPartial || !target.Retryable {
			continue
		}
		if len(accountFilter) > 0 {
			if _, ok := accountFilter[target.AccountID]; !ok {
				continue
			}
		}
		if len(regionFilter) > 0 {
			if _, ok := regionFilter[target.Region]; !ok {
				continue
			}
		}
		retryTargets = append(retryTargets, target)
	}
	if len(retryTargets) == 0 {
		return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutNoRetryableTargets
	}

	reactivated := false
	if rollout.Status != db.AWSOrganizationRolloutStatusInProgress {
		rollout.Status = db.AWSOrganizationRolloutStatusInProgress
		rollout.FailureCode = ""
		rollout.FailureMessage = ""
		rollout.UpdatedAt = s.Now().UTC()
		updated, err := store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version)
		if err != nil {
			if errors.Is(err, db.ErrConflict) {
				return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutRetryConflict
			}
			return AWSOrganizationRolloutStatus{}, err
		}
		rollout = updated
		reactivated = true
	}

	reset := 0
	for _, target := range retryTargets {
		if _, err := store.ResetAWSOrganizationRolloutTarget(ctx, target, target.Version); err != nil {
			if errors.Is(err, db.ErrConflict) {
				continue
			}
			return AWSOrganizationRolloutStatus{}, err
		}
		reset++
	}
	if reset == 0 {
		if reactivated {
			return s.GetAWSOrganizationRolloutStatus(ctx, project.WorkspaceID, project.ProjectID, rollout.RolloutID)
		}
		return AWSOrganizationRolloutStatus{}, ErrAWSOrganizationRolloutNoRetryableTargets
	}
	return s.GetAWSOrganizationRolloutStatus(ctx, project.WorkspaceID, project.ProjectID, rollout.RolloutID)
}

var (
	ErrAWSOrganizationRolloutExpired            = errors.New("aws organization rollout expired")
	ErrAWSOrganizationRolloutNoRetryableTargets = errors.New("aws organization rollout has no retryable targets")
	ErrAWSOrganizationRolloutRetryConflict      = errors.New("aws organization rollout cannot be retried while another rollout is active")
)

func (s *Service) reconcileAWSOrganizationRollout(ctx context.Context, store db.AWSOrganizationRolloutStore, rollout db.AWSOrganizationRollout) (AWSOrganizationRolloutReconcileResult, error) {
	if rollout.Status == db.AWSOrganizationRolloutStatusCompleted || rollout.Status == db.AWSOrganizationRolloutStatusCanceled {
		return AWSOrganizationRolloutReconcileResult{}, nil
	}
	now := s.Now().UTC()
	if !now.Before(rollout.ExpiresAt) {
		rollout.Status = db.AWSOrganizationRolloutStatusExpired
		rollout.FailureCode = "rollout_envelope_expired"
		rollout.FailureMessage = "The rollout envelope elapsed its 24-hour window before all targets connected."
		rollout.UpdatedAt = now
		_, err := store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version)
		return AWSOrganizationRolloutReconcileResult{}, err
	}

	targets, err := store.ListAWSOrganizationRolloutTargets(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.RolloutID)
	if err != nil {
		return AWSOrganizationRolloutReconcileResult{}, err
	}
	result := AWSOrganizationRolloutReconcileResult{RolloutID: rollout.RolloutID, TargetsExamined: len(targets)}
	sem := make(chan struct{}, awsOrganizationRolloutValidationConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, target := range targets {
		target := target
		if target.State == db.AWSOrganizationRolloutTargetExcluded || target.State == db.AWSOrganizationRolloutTargetRemoved {
			continue
		}
		if target.IsManagement {
			connected, updateErr := s.reconcileAWSOrganizationRolloutManagementTarget(ctx, store, rollout, target, now)
			if updateErr != nil {
				return result, updateErr
			}
			if connected {
				result.TargetsConnected++
			} else {
				result.TargetsFailed++
			}
			continue
		}
		if target.RoleARN == "" {
			if target.LastTransitionAt.Before(now.Add(-awsOrganizationRolloutRegistrationTimeout)) && target.State != db.AWSOrganizationRolloutTargetFailed {
				target.State = db.AWSOrganizationRolloutTargetFailed
				target.FailureCode = "registration_missing"
				target.FailureMessage = "No authenticated member-account registration arrived before the retry window."
				target.Retryable = true
				target.LastTransitionAt = now
				if _, err := store.UpsertAWSOrganizationRolloutTarget(ctx, target); err != nil {
					return result, err
				}
				result.TargetsFailed++
			} else {
				result.TargetsDeferred++
			}
			continue
		}
		if target.State == db.AWSOrganizationRolloutTargetConnected && target.LastValidationAt != nil && now.Sub(*target.LastValidationAt) < awsOrganizationRolloutRevalidationInterval {
			result.TargetsDeferred++
			continue
		}
		if target.State != db.AWSOrganizationRolloutTargetValidating && target.State != db.AWSOrganizationRolloutTargetRegistering && target.State != db.AWSOrganizationRolloutTargetConnected {
			result.TargetsDeferred++
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				if firstErr == nil {
					firstErr = ctx.Err()
				}
				mu.Unlock()
				return
			}
			defer func() { <-sem }()
			connected, validationErr := s.reconcileAWSOrganizationRolloutMemberTarget(ctx, store, rollout, target, now)
			mu.Lock()
			defer mu.Unlock()
			if validationErr != nil {
				if firstErr == nil {
					firstErr = validationErr
				}
				result.TargetsFailed++
				return
			}
			result.TargetsValidated++
			if connected {
				result.TargetsConnected++
			} else {
				result.TargetsFailed++
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return result, firstErr
	}
	if err := s.aggregateAWSOrganizationRolloutStatus(ctx, store, rollout); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Service) reconcileAWSOrganizationRolloutManagementTarget(ctx context.Context, store db.AWSOrganizationRolloutStore, rollout db.AWSOrganizationRollout, target db.AWSOrganizationRolloutTarget, now time.Time) (bool, error) {
	stored, err := s.Store.GetTenancyConnector(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.ControllingConnectorID)
	if err != nil {
		return false, err
	}
	connection := s.awsConnectionStatusFromStored(ctx, stored)
	target.LastValidationAt = &now
	target.LastTransitionAt = now
	target.UpdatedAt = now
	if connection.Connected && strings.TrimSpace(connection.AccountID) == rollout.ManagementAccountID {
		target.State = db.AWSOrganizationRolloutTargetConnected
		target.FailureCode = ""
		target.FailureMessage = ""
		target.Retryable = false
		target.RoleARN = connection.RoleARN
		target.EvidenceRef = "aws-controlling-connector:" + rollout.ControllingConnectorID
	} else {
		target.State = db.AWSOrganizationRolloutTargetFailed
		target.FailureCode = "controlling_connector_unhealthy"
		target.FailureMessage = "The controlling AWS connector is no longer validated for the approved management account."
		target.Retryable = true
	}
	_, err = store.UpsertAWSOrganizationRolloutTarget(ctx, target)
	return target.State == db.AWSOrganizationRolloutTargetConnected, err
}

func (s *Service) reconcileAWSOrganizationRolloutMemberTarget(ctx context.Context, store db.AWSOrganizationRolloutStore, rollout db.AWSOrganizationRollout, target db.AWSOrganizationRolloutTarget, now time.Time) (bool, error) {
	if s.AWSConnectorValidator == nil {
		return false, s.recordAWSOrganizationRolloutValidationFailure(ctx, store, target, now, "validator_unavailable", "Member-role validation is not configured in this deployment.", true)
	}
	secret, err := s.awsOrganizationRolloutSecret(rollout)
	if err != nil {
		return false, s.recordAWSOrganizationRolloutValidationFailure(ctx, store, target, now, "validator_unavailable", "Member-role validation could not derive its scoped credential.", true)
	}
	validation, err := s.AWSConnectorValidator.ValidateAWSConnection(ctx, AWSConnectionValidationRequest{
		RoleARN:     target.RoleARN,
		ExternalID:  secret,
		Region:      target.Region,
		SessionName: "identrail-rollout-validation",
	})
	if err != nil {
		return false, s.recordAWSOrganizationRolloutValidationFailure(ctx, store, target, now, "aws_validation_error", "AWS member-role validation could not complete.", true)
	}
	for _, diagnostic := range validation.Diagnostics {
		if strings.TrimSpace(diagnostic.Code) == "" {
			continue
		}
		return false, s.recordAWSOrganizationRolloutValidationFailure(ctx, store, target, now, diagnostic.Code, "AWS member-role validation reported an actionable diagnostic.", rolloutValidationDiagnosticRetryable(diagnostic))
	}
	if strings.TrimSpace(validation.AccountID) != target.AccountID {
		return false, s.recordAWSOrganizationRolloutValidationFailure(ctx, store, target, now, "aws_validation_account_mismatch", "STS identity proof did not match the approved target account.", false)
	}
	if len(validation.PermissionChecks) == 0 {
		return false, s.recordAWSOrganizationRolloutValidationFailure(ctx, store, target, now, "aws_validation_incomplete", "AWS member-role validation did not return the required STS and IAM read checks.", true)
	}
	hasSTSCheck := false
	hasIAMCheck := false
	for _, check := range validation.PermissionChecks {
		checkName := strings.ToLower(strings.TrimSpace(check.Name))
		if checkName == "sts:assumerole" {
			hasSTSCheck = true
		}
		if strings.HasPrefix(checkName, "iam:") {
			hasIAMCheck = true
		}
		if check.Passed {
			continue
		}
		code := "aws_member_permission_denied"
		if strings.TrimSpace(check.Name) == "sts:AssumeRole" {
			code = "aws_member_assume_role_failed"
		}
		// Trust and permission failures are repairable configuration failures:
		// once the member role is corrected, the operator must be able to use
		// Retry failed targets without starting a replacement rollout. Account
		// mismatches remain non-retryable because they disprove target scope.
		return false, s.recordAWSOrganizationRolloutValidationFailure(ctx, store, target, now, code, "The member role could not satisfy the read-only validation contract.", true)
	}
	if !hasSTSCheck || !hasIAMCheck {
		return false, s.recordAWSOrganizationRolloutValidationFailure(ctx, store, target, now, "aws_validation_incomplete", "AWS member-role validation did not return both the STS assume-role and IAM read checks.", true)
	}
	target.State = db.AWSOrganizationRolloutTargetConnected
	target.FailureCode = ""
	target.FailureMessage = ""
	target.Retryable = false
	target.LastValidationAt = &now
	target.LastTransitionAt = now
	target.UpdatedAt = now
	target.EvidenceRef = "aws-sts:" + target.AccountID + "/" + target.Region
	if _, err := store.UpsertAWSOrganizationRolloutTarget(ctx, target); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) recordAWSOrganizationRolloutValidationFailure(ctx context.Context, store db.AWSOrganizationRolloutStore, target db.AWSOrganizationRolloutTarget, now time.Time, code string, message string, retryable bool) error {
	target.State = db.AWSOrganizationRolloutTargetFailed
	target.FailureCode = strings.TrimSpace(code)
	target.FailureMessage = strings.TrimSpace(message)
	target.Retryable = retryable
	target.LastValidationAt = &now
	target.LastTransitionAt = now
	target.UpdatedAt = now
	_, err := store.UpsertAWSOrganizationRolloutTarget(ctx, target)
	return err
}

func (s *Service) aggregateAWSOrganizationRolloutStatus(ctx context.Context, store db.AWSOrganizationRolloutStore, rollout db.AWSOrganizationRollout) error {
	targets, err := store.ListAWSOrganizationRolloutTargets(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.RolloutID)
	if err != nil {
		return err
	}
	nonExcluded := 0
	connected := 0
	failed := 0
	nonTerminal := 0
	for _, target := range targets {
		if target.State == db.AWSOrganizationRolloutTargetExcluded || target.State == db.AWSOrganizationRolloutTargetRemoved {
			continue
		}
		nonExcluded++
		switch target.State {
		case db.AWSOrganizationRolloutTargetConnected:
			connected++
		case db.AWSOrganizationRolloutTargetFailed, db.AWSOrganizationRolloutTargetPartial, db.AWSOrganizationRolloutTargetSuspended:
			failed++
		default:
			nonTerminal++
		}
	}
	nextStatus := rollout.Status
	switch {
	case nonExcluded > 0 && connected == nonExcluded:
		nextStatus = db.AWSOrganizationRolloutStatusCompleted
	case nonTerminal == 0 && failed > 0 && connected > 0:
		nextStatus = db.AWSOrganizationRolloutStatusPartial
	case nonTerminal == 0 && failed > 0:
		nextStatus = db.AWSOrganizationRolloutStatusFailed
	case nonTerminal > 0:
		nextStatus = db.AWSOrganizationRolloutStatusReconciling
	}
	rollout.Status = nextStatus
	// updated_at is also the worker lease cursor. Touch the envelope even
	// when its aggregate status is unchanged so a deferred pass rotates it
	// behind other active envelopes instead of starving later batches.
	rollout.UpdatedAt = s.Now().UTC()
	if nextStatus == db.AWSOrganizationRolloutStatusCompleted {
		rollout.FailureCode = ""
		rollout.FailureMessage = ""
	}
	_, err = store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version)
	return err
}

func normalizedAWSOrganizationRolloutFilter(values []string, lower bool) map[string]struct{} {
	filter := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if lower {
			normalized = strings.ToLower(normalized)
		}
		if normalized != "" {
			filter[normalized] = struct{}{}
		}
	}
	return filter
}

func rolloutValidationDiagnosticRetryable(diagnostic AWSConnectionDiagnostic) bool {
	if diagnostic.Retryable {
		return true
	}
	code := strings.ToLower(strings.TrimSpace(diagnostic.Code))
	switch code {
	case "aws_identity_metadata_unexpected", "aws_identity_metadata_failed", "identity_metadata_unexpected":
		// GetCallerIdentity has already failed after AssumeRole. The member
		// account and role have not been disproven, so the operator must be
		// able to retry after endpoint or session-credential recovery.
		return true
	}
	return strings.Contains(code, "thrott") || strings.Contains(code, "timeout") || strings.Contains(code, "unavailable") || strings.Contains(code, "network") || strings.Contains(code, "expired")
}
