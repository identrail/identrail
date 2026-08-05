package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func startAWSRolloutForReconciliationTest(t *testing.T, selected ...string) (*Service, context.Context, db.AWSOrganizationRollout) {
	t.Helper()
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     selected,
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	store, ok := svc.Store.(db.AWSOrganizationRolloutStore)
	if !ok {
		t.Fatal("expected organization rollout store")
	}
	rollout, err := store.GetAWSOrganizationRollout(ctx, "workspace-a", "project-1", status.RolloutID)
	if err != nil {
		t.Fatalf("load rollout: %v", err)
	}
	return svc, ctx, rollout
}

func setAWSRolloutMemberTarget(t *testing.T, svc *Service, ctx context.Context, rollout db.AWSOrganizationRollout, accountID string, state string, roleARN string) db.AWSOrganizationRolloutTarget {
	t.Helper()
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	target, err := store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, accountID, "us-east-1")
	if err != nil {
		t.Fatalf("load member target %s: %v", accountID, err)
	}
	target.State = state
	target.RoleARN = roleARN
	target.LastTransitionAt = svc.Now().UTC()
	target.UpdatedAt = svc.Now().UTC()
	updated, err := store.UpsertAWSOrganizationRolloutTarget(ctx, target)
	if err != nil {
		t.Fatalf("update member target %s: %v", accountID, err)
	}
	return updated
}

func keepAWSRolloutRetryableForTest(t *testing.T, svc *Service, ctx context.Context, rollout db.AWSOrganizationRollout) db.AWSOrganizationRollout {
	t.Helper()
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	current, err := store.GetAWSOrganizationRollout(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.RolloutID)
	if err != nil {
		t.Fatalf("reload rollout for retry window: %v", err)
	}
	rollout = current
	rollout.ExpiresAt = time.Now().UTC().Add(time.Hour)
	updated, err := store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version)
	if err != nil {
		t.Fatalf("extend rollout retry window: %v", err)
	}
	return updated
}

func TestReconcileAWSOrganizationRolloutConnectsValidatedMembers(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{result: AWSConnectionValidationResult{
		AccountID: "222222222222",
		PermissionChecks: []AWSConnectionPermissionCheck{
			{Name: "sts:AssumeRole", Passed: true},
			{Name: "iam:ListRoles", Passed: true},
		},
	}}

	result, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile rollout: %v", err)
	}
	if result.TargetsValidated != 1 || result.TargetsConnected != 2 || result.TargetsFailed != 0 {
		t.Fatalf("unexpected reconciliation result: %+v", result)
	}
	if status.Status != db.AWSOrganizationRolloutStatusCompleted || status.Summary.ConnectedTargets != 2 {
		t.Fatalf("expected completed rollout with two connected targets, got status=%q summary=%+v", status.Status, status.Summary)
	}
	target, err := svc.Store.(db.AWSOrganizationRolloutStore).GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load validated target: %v", err)
	}
	if target.State != db.AWSOrganizationRolloutTargetConnected || target.EvidenceRef != "aws-sts:222222222222/us-east-1" || target.Retryable {
		t.Fatalf("expected durable connected validation evidence, got %+v", target)
	}
}

func TestReconcileAWSOrganizationRolloutRejectsMismatchedSTSIdentity(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{result: AWSConnectionValidationResult{AccountID: "333333333333"}}

	result, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile rollout: %v", err)
	}
	if result.TargetsFailed != 1 || status.Status != db.AWSOrganizationRolloutStatusPartial {
		t.Fatalf("expected one failed member and partial rollout, got result=%+v status=%q", result, status.Status)
	}
	target, err := svc.Store.(db.AWSOrganizationRolloutStore).GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load mismatched target: %v", err)
	}
	if target.FailureCode != "aws_validation_account_mismatch" || target.Retryable {
		t.Fatalf("expected non-retryable identity mismatch, got %+v", target)
	}
}

func TestReconcileAWSOrganizationRolloutPreservesRetryableValidatorDiagnostic(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{result: AWSConnectionValidationResult{
		Diagnostics: []AWSConnectionDiagnostic{{Code: "aws_identity_metadata_unexpected"}},
	}}

	_, _, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile rollout: %v", err)
	}
	target, err := svc.Store.(db.AWSOrganizationRolloutStore).GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load diagnostic target: %v", err)
	}
	if target.FailureCode != "aws_identity_metadata_unexpected" || !target.Retryable {
		t.Fatalf("expected retryable validator diagnostic before account mismatch handling, got %+v", target)
	}
}

func TestReconcileAWSOrganizationRolloutRecordsTransientValidationFailure(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{err: errors.New("temporary sts failure")}

	_, _, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile rollout: %v", err)
	}
	target, err := svc.Store.(db.AWSOrganizationRolloutStore).GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load transient-failure target: %v", err)
	}
	if target.FailureCode != "aws_validation_error" || !target.Retryable {
		t.Fatalf("expected retryable transient validation failure, got %+v", target)
	}
}

func TestReconcileAWSOrganizationRolloutKeepsPermissionFailuresRetryable(t *testing.T) {
	tests := []struct {
		name        string
		checks      []AWSConnectionPermissionCheck
		failureCode string
	}{
		{
			name: "assume role trust failure",
			checks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: false},
				{Name: "iam:ListRoles", Passed: true},
			},
			failureCode: "aws_member_assume_role_failed",
		},
		{
			name: "iam read permission failure",
			checks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true},
				{Name: "iam:ListRoles", Passed: false},
			},
			failureCode: "aws_member_permission_denied",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
			setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
			svc.AWSConnectorValidator = &fakeAWSConnectorValidator{result: AWSConnectionValidationResult{
				AccountID:        "222222222222",
				PermissionChecks: testCase.checks,
			}}

			_, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
			if err != nil {
				t.Fatalf("reconcile rollout: %v", err)
			}
			if status.Status != db.AWSOrganizationRolloutStatusPartial {
				t.Fatalf("expected partial rollout after permission failure, got %q", status.Status)
			}
			store := svc.Store.(db.AWSOrganizationRolloutStore)
			target, err := store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
			if err != nil {
				t.Fatalf("load failed target: %v", err)
			}
			if target.FailureCode != testCase.failureCode || !target.Retryable {
				t.Fatalf("expected repairable permission failure, got %+v", target)
			}

			rollout = keepAWSRolloutRetryableForTest(t, svc, ctx, rollout)
			if _, err := svc.RetryAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID, AWSOrganizationRolloutRetryRequest{AccountIDs: []string{"222222222222"}}); err != nil {
				t.Fatalf("retry repaired permission target: %v", err)
			}
			retried, err := store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
			if err != nil {
				t.Fatalf("load retried target: %v", err)
			}
			if retried.State != db.AWSOrganizationRolloutTargetValidating || retried.FailureCode != "" {
				t.Fatalf("expected permission target to be reset for retry, got %+v", retried)
			}
		})
	}
}

func TestReconcileAWSOrganizationRolloutRecordsValidatorUnavailable(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")

	_, _, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile rollout: %v", err)
	}
	target, err := svc.Store.(db.AWSOrganizationRolloutStore).GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load unavailable-validator target: %v", err)
	}
	if target.FailureCode != "validator_unavailable" || !target.Retryable {
		t.Fatalf("expected retryable validator-unavailable failure, got %+v", target)
	}
}

func TestReconcileAWSOrganizationRolloutMarksMissingRegistrationRetryable(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	target, err := store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load pending target: %v", err)
	}
	target.LastTransitionAt = svc.Now().UTC().Add(-16 * time.Minute)
	target.UpdatedAt = target.LastTransitionAt
	if _, err := store.UpsertAWSOrganizationRolloutTarget(ctx, target); err != nil {
		t.Fatalf("age pending target: %v", err)
	}

	_, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile rollout: %v", err)
	}
	if status.Status != db.AWSOrganizationRolloutStatusPartial {
		t.Fatalf("expected partial rollout after missing registration, got %q", status.Status)
	}
	target, err = store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("reload missing-registration target: %v", err)
	}
	if target.State != db.AWSOrganizationRolloutTargetFailed || target.FailureCode != "registration_missing" || !target.Retryable {
		t.Fatalf("expected retryable registration failure, got %+v", target)
	}

	rollout = keepAWSRolloutRetryableForTest(t, svc, ctx, rollout)
	status, err = svc.RetryAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID, AWSOrganizationRolloutRetryRequest{AccountIDs: []string{"222222222222"}})
	if err != nil {
		t.Fatalf("retry rollout: %v", err)
	}
	if status.Status != db.AWSOrganizationRolloutStatusInProgress {
		t.Fatalf("expected in-progress status after retry, got %q", status.Status)
	}
	target, err = store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("reload retried target: %v", err)
	}
	if target.State != db.AWSOrganizationRolloutTargetPending || target.FailureCode != "" || !target.Retryable {
		t.Fatalf("expected clean pending retry state, got %+v", target)
	}
}

func TestReconcileAWSOrganizationRolloutTimesOutLateRegisteringTarget(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	target := setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetRegistering, "")
	target.LastTransitionAt = svc.Now().UTC().Add(-16 * time.Minute)
	target.UpdatedAt = target.LastTransitionAt
	if _, err := store.UpsertAWSOrganizationRolloutTarget(ctx, target); err != nil {
		t.Fatalf("age registering target: %v", err)
	}

	_, _, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile rollout: %v", err)
	}
	target, err = store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("reload registering target: %v", err)
	}
	if target.State != db.AWSOrganizationRolloutTargetFailed || target.FailureCode != "registration_missing" || !target.Retryable {
		t.Fatalf("expected late registering target to become retryable, got %+v", target)
	}
}

func TestReconcileAWSOrganizationRolloutExpiresAtBoundary(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout.ExpiresAt = svc.Now().UTC()
	if _, err := store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version); err != nil {
		t.Fatalf("expire rollout: %v", err)
	}

	_, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile expired rollout: %v", err)
	}
	if status.Status != db.AWSOrganizationRolloutStatusExpired || status.FailureCode != "rollout_envelope_expired" {
		t.Fatalf("expected exact-boundary expiry, got status=%q code=%q", status.Status, status.FailureCode)
	}
}

func TestReconcileAWSOrganizationRolloutsRescopesEachEnvelope(t *testing.T) {
	svc, ctxA, rolloutA := startAWSRolloutForReconciliationTest(t, "222222222222")
	ctxB := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	seedDefaultProject(t, svc.Store, ctxB, "project-1")
	seedAWSRolloutControllingConnector(t, svc.Store, ctxB, "aws-mgmt-b", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	statusB, err := svc.StartAWSOrganizationRollout(ctxB, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-b",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt-b",
		OrganizationID:         "o-fixture002",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start second-scope rollout: %v", err)
	}

	processed, err := svc.ReconcileAWSOrganizationRollouts(context.Background(), 10)
	if err != nil {
		t.Fatalf("reconcile cross-scope rollouts: %v", err)
	}
	if processed != 2 {
		t.Fatalf("expected two cross-scope rollouts processed, got %d", processed)
	}
	for _, testCase := range []struct {
		name      string
		ctx       context.Context
		workspace string
		rollout   string
	}{
		{name: "tenant-a", ctx: ctxA, workspace: "workspace-a", rollout: rolloutA.RolloutID},
		{name: "tenant-b", ctx: ctxB, workspace: "workspace-b", rollout: statusB.RolloutID},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			status, err := svc.GetAWSOrganizationRolloutStatus(testCase.ctx, testCase.workspace, "project-1", testCase.rollout)
			if err != nil {
				t.Fatalf("get %s rollout status: %v", testCase.name, err)
			}
			if status.Status != db.AWSOrganizationRolloutStatusReconciling {
				t.Fatalf("expected %s rollout to remain reconciling with pending members, got %q", testCase.name, status.Status)
			}
		})
	}
}

func TestReconcileAWSOrganizationRolloutsHonorsCanceledContext(t *testing.T) {
	svc, _, _ := startAWSRolloutForReconciliationTest(t, "222222222222")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	processed, err := svc.ReconcileAWSOrganizationRollouts(ctx, 10)
	if !errors.Is(err, context.Canceled) || processed != 0 {
		t.Fatalf("expected canceled worker pass with no processing, got processed=%d err=%v", processed, err)
	}
}

func TestReconcileAWSOrganizationRolloutTouchesUpdatedAtWhenStatusUnchanged(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	current, err := store.GetAWSOrganizationRollout(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.RolloutID)
	if err != nil {
		t.Fatalf("reload rollout: %v", err)
	}
	current.Status = db.AWSOrganizationRolloutStatusReconciling
	current.UpdatedAt = svc.Now().UTC()
	current, err = store.UpdateAWSOrganizationRollout(ctx, current, current.Version)
	if err != nil {
		t.Fatalf("mark rollout reconciling: %v", err)
	}
	passTime := svc.Now().UTC().Add(time.Minute)
	svc.Now = func() time.Time { return passTime }

	_, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", current.RolloutID)
	if err != nil {
		t.Fatalf("reconcile deferred rollout: %v", err)
	}
	if status.Status != db.AWSOrganizationRolloutStatusReconciling {
		t.Fatalf("expected status to remain reconciling, got %q", status.Status)
	}
	refreshed, err := store.GetAWSOrganizationRollout(ctx, current.WorkspaceID, current.ProjectID, current.RolloutID)
	if err != nil {
		t.Fatalf("reload touched rollout: %v", err)
	}
	if !refreshed.UpdatedAt.Equal(passTime) {
		t.Fatalf("expected deferred pass to advance updated_at to %v, got %v", passTime, refreshed.UpdatedAt)
	}
}

func TestRetryAWSOrganizationRolloutDoesNotResetNonRetryableTargets(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222", "333333333333")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout = keepAWSRolloutRetryableForTest(t, svc, ctx, rollout)
	retryable := setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetFailed, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	retryable.FailureCode = "aws_validation_error"
	retryable.FailureMessage = "temporary validation failure"
	retryable.Retryable = true
	if _, err := store.UpsertAWSOrganizationRolloutTarget(ctx, retryable); err != nil {
		t.Fatalf("seed retryable target: %v", err)
	}
	nonRetryable := setAWSRolloutMemberTarget(t, svc, ctx, rollout, "333333333333", db.AWSOrganizationRolloutTargetFailed, "arn:aws:iam::333333333333:role/IdentrailReadOnly")
	nonRetryable.FailureCode = "aws_validation_account_mismatch"
	nonRetryable.FailureMessage = "identity mismatch"
	nonRetryable.Retryable = false
	if _, err := store.UpsertAWSOrganizationRolloutTarget(ctx, nonRetryable); err != nil {
		t.Fatalf("seed non-retryable target: %v", err)
	}

	if _, err := svc.RetryAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID, AWSOrganizationRolloutRetryRequest{}); err != nil {
		t.Fatalf("retry rollout: %v", err)
	}
	retried, err := store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load retried target: %v", err)
	}
	if retried.State != db.AWSOrganizationRolloutTargetValidating || retried.FailureCode != "" {
		t.Fatalf("expected role-bearing retryable target reset to validation, got %+v", retried)
	}
	untouched, err := store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "333333333333", "us-east-1")
	if err != nil {
		t.Fatalf("load non-retryable target: %v", err)
	}
	if untouched.State != db.AWSOrganizationRolloutTargetFailed || untouched.FailureCode != "aws_validation_account_mismatch" || untouched.Retryable {
		t.Fatalf("expected non-retryable target preserved, got %+v", untouched)
	}
}

func TestResetAWSOrganizationRolloutTargetRejectsTerminalParent(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	target := setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetFailed, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	target.FailureCode = "aws_validation_error"
	target.FailureMessage = "temporary validation failure"
	target.Retryable = true
	target, err := store.UpsertAWSOrganizationRolloutTarget(ctx, target)
	if err != nil {
		t.Fatalf("seed retryable target: %v", err)
	}
	current, err := store.GetAWSOrganizationRollout(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.RolloutID)
	if err != nil {
		t.Fatalf("reload rollout: %v", err)
	}
	current.Status = db.AWSOrganizationRolloutStatusCanceled
	current.UpdatedAt = svc.Now().UTC()
	if _, err := store.UpdateAWSOrganizationRollout(ctx, current, current.Version); err != nil {
		t.Fatalf("terminalize rollout: %v", err)
	}
	if _, err := store.ResetAWSOrganizationRolloutTarget(ctx, target, target.Version); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("expected terminal parent reset to conflict, got %v", err)
	}
}

func TestRetryAWSOrganizationRolloutRejectsReplacementBeforeResettingTargets(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	target := setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetFailed, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	target.FailureCode = "aws_validation_error"
	target.FailureMessage = "temporary validation failure"
	target.Retryable = true
	target, err := store.UpsertAWSOrganizationRolloutTarget(ctx, target)
	if err != nil {
		t.Fatalf("seed retryable target: %v", err)
	}
	current, err := store.GetAWSOrganizationRollout(ctx, rollout.WorkspaceID, rollout.ProjectID, rollout.RolloutID)
	if err != nil {
		t.Fatalf("reload rollout: %v", err)
	}
	current.Status = db.AWSOrganizationRolloutStatusPartial
	current.UpdatedAt = svc.Now().UTC()
	if _, err := store.UpdateAWSOrganizationRollout(ctx, current, current.Version); err != nil {
		t.Fatalf("mark rollout partial: %v", err)
	}

	if _, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture002",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"333333333333"},
		TargetRegions:          []string{"us-east-1"},
	}); err != nil {
		t.Fatalf("start replacement rollout: %v", err)
	}

	if _, err := svc.RetryAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID, AWSOrganizationRolloutRetryRequest{}); !errors.Is(err, ErrAWSOrganizationRolloutRetryConflict) {
		t.Fatalf("expected clean retry conflict, got %v", err)
	}
	unchanged, err := store.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, target.AccountID, target.Region)
	if err != nil {
		t.Fatalf("reload target after rejected retry: %v", err)
	}
	if unchanged.State != db.AWSOrganizationRolloutTargetFailed || unchanged.FailureCode != "aws_validation_error" || !unchanged.Retryable {
		t.Fatalf("expected target to remain retryable and failed, got %+v", unchanged)
	}
}
