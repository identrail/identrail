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

func TestReconcileAWSOrganizationRolloutStopsAfterControllingConnectorPause(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	validator := &fakeAWSConnectorValidator{result: AWSConnectionValidationResult{
		AccountID: "222222222222",
		PermissionChecks: []AWSConnectionPermissionCheck{
			{Name: "sts:AssumeRole", Passed: true},
			{Name: "iam:ListRoles", Passed: true},
		},
	}}
	svc.AWSConnectorValidator = validator

	lifecycleStore, ok := svc.Store.(db.TenancyConnectorLifecycleStore)
	if !ok {
		t.Fatal("expected connector lifecycle store")
	}
	if _, err := lifecycleStore.SetTenancyConnectorDisabled(ctx, "workspace-a", "project-1", "aws-mgmt", true, svc.Now().UTC()); err != nil {
		t.Fatalf("pause controlling connector: %v", err)
	}

	result, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reconcile paused rollout: %v", err)
	}
	if result.TargetsValidated != 0 || validator.calls != 0 {
		t.Fatalf("paused rollout must not invoke member validation: result=%+v calls=%d", result, validator.calls)
	}
	if status.Status != db.AWSOrganizationRolloutStatusCanceled || status.FailureCode != "controlling_connector_lifecycle_changed" {
		t.Fatalf("expected paused rollout to be canceled, got %+v", status)
	}
	target, err := svc.Store.(db.AWSOrganizationRolloutStore).GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("reload paused rollout target: %v", err)
	}
	if target.State != db.AWSOrganizationRolloutTargetValidating {
		t.Fatalf("paused rollout must not mutate target state, got %+v", target)
	}
}

func TestReconcileAWSOrganizationRolloutPreservesRolloutAfterTransientControllingHealthLoss(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	validator := &fakeAWSConnectorValidator{}
	svc.AWSConnectorValidator = validator

	stored, err := svc.Store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-mgmt")
	if err != nil {
		t.Fatalf("load controlling connector: %v", err)
	}
	stored.State.HealthStatus = "error"
	stored.State.UpdatedAt = svc.Now().UTC()
	if err := svc.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
		t.Fatalf("record transient controlling health loss: %v", err)
	}

	result, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if !errors.Is(err, ErrAWSOrganizationRolloutControllingUnready) {
		t.Fatalf("expected transient controlling health loss to remain retryable, got result=%+v status=%+v err=%v", result, status, err)
	}
	if validator.calls != 0 {
		t.Fatalf("unready controlling connector must not invoke member validation: calls=%d", validator.calls)
	}
	if status.Status != "" {
		t.Fatalf("expected no status payload when reconciliation is retryable, got %+v", status)
	}
	current, err := svc.Store.(db.AWSOrganizationRolloutStore).GetAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("reload rollout after transient health loss: %v", err)
	}
	if current.Status != rollout.Status || current.FailureCode != rollout.FailureCode {
		t.Fatalf("transient health loss must not cancel rollout: before=%+v after=%+v", rollout, current)
	}
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

func TestReconcileAWSOrganizationRolloutsContinuesMonitoringCompletedConnection(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{result: AWSConnectionValidationResult{
		AccountID: "222222222222",
		PermissionChecks: []AWSConnectionPermissionCheck{
			{Name: "sts:AssumeRole", Passed: true},
			{Name: "iam:ListRoles", Passed: true},
		},
	}}
	_, completed, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("complete rollout: %v", err)
	}
	if completed.Status != db.AWSOrganizationRolloutStatusCompleted {
		t.Fatalf("expected completed rollout before drift, got %q", completed.Status)
	}

	inventory := &staticAWSOrganizationInventory{snapshot: liveAWSOrganizationSnapshot()}
	inventory.snapshot.StackInstances = []AWSOrganizationStackInstance{{
		AccountID: "222222222222", Region: "us-east-1", StackSetID: "stackset-1", StackID: "stack-1", Status: "current", DriftStatus: "drifted",
	}}
	svc.AWSOrganizationInventoryFactory = func(context.Context, AWSConnectionStatus) (AWSOrganizationInventory, error) {
		return inventory, nil
	}

	processed, err := svc.ReconcileAWSOrganizationRollouts(context.Background(), 10)
	if err != nil {
		t.Fatalf("monitor completed rollout: %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected completed connection to remain monitored, processed %d rollouts", processed)
	}
	status, err := svc.GetAWSOrganizationRolloutStatus(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("load drifted rollout: %v", err)
	}
	if status.Status != db.AWSOrganizationRolloutStatusPartial {
		t.Fatalf("expected drift to reopen completed rollout as partial, got status=%q summary=%+v targets=%+v", status.Status, status.Summary, status.Targets)
	}
	for _, target := range status.Targets {
		if target.AccountID == "222222222222" && (target.State != db.AWSOrganizationRolloutTargetFailed || target.FailureCode != "stack_instance_drifted") {
			t.Fatalf("expected completed target drift to be recorded, got %+v", target)
		}
	}
}

func TestListMonitoredAWSOrganizationRolloutsPrefersNewestConnectorRollout(t *testing.T) {
	svc, ctx, first := startAWSRolloutForReconciliationTest(t, "222222222222")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
	first.Status = db.AWSOrganizationRolloutStatusCompleted
	first.UpdatedAt = svc.Now().UTC()
	if _, err := store.UpdateAWSOrganizationRollout(ctx, first, first.Version); err != nil {
		t.Fatalf("complete first rollout: %v", err)
	}
	svc.Now = func() time.Time { return first.CreatedAt.Add(time.Minute) }
	second, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID: "workspace-a", ProjectID: "project-1", ControllingConnectorID: "aws-mgmt",
		OrganizationID: "o-fixture001", ManagementAccountID: "111111111111",
		SelectedAccountIDs: []string{"333333333333"}, TargetRegions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start replacement rollout: %v", err)
	}

	monitored, err := store.ListMonitoredAWSOrganizationRollouts(context.Background(), 10)
	if err != nil {
		t.Fatalf("list monitored rollouts: %v", err)
	}
	if len(monitored) != 1 || monitored[0].RolloutID != second.RolloutID {
		t.Fatalf("expected only newest connector rollout %q, got %+v", second.RolloutID, monitored)
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

// TestApplyAWSOrganizationStackInstanceLifecycle locks in the two transitions
// that keep a reopened target moving. A Connected target reopened as Deploying
// by an active StackSet operation must return to Validating once the instance
// reports current again, otherwise it sits in Deploying forever and the
// rollout never leaves reconciling. LastTransitionAt must only move when the
// state actually changes, so the registration timeout is not reset each pass.
func TestApplyAWSOrganizationStackInstanceLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	earlier := now.Add(-90 * time.Minute)

	t.Run("deploying with current instance returns to validating", func(t *testing.T) {
		target := db.AWSOrganizationRolloutTarget{
			AccountID: "333333333333", Region: "us-east-1",
			State: db.AWSOrganizationRolloutTargetDeploying, RoleARN: "arn:aws:iam::333333333333:role/identrail",
			LastTransitionAt: earlier,
		}
		applyAWSOrganizationStackInstance(&target, AWSOrganizationStackInstance{Status: "current"}, now)
		if target.State != db.AWSOrganizationRolloutTargetValidating {
			t.Fatalf("expected validating, got %q", target.State)
		}
		if !target.LastTransitionAt.Equal(now) {
			t.Fatalf("expected transition stamped at now, got %s", target.LastTransitionAt)
		}
	})

	t.Run("unchanged registering state preserves transition time", func(t *testing.T) {
		target := db.AWSOrganizationRolloutTarget{
			AccountID: "333333333333", Region: "us-east-1",
			State: db.AWSOrganizationRolloutTargetRegistering, RoleARN: "",
			LastTransitionAt: earlier,
		}
		applyAWSOrganizationStackInstance(&target, AWSOrganizationStackInstance{Status: "current"}, now)
		if target.State != db.AWSOrganizationRolloutTargetRegistering {
			t.Fatalf("expected registering, got %q", target.State)
		}
		if !target.LastTransitionAt.Equal(earlier) {
			t.Fatalf("expected preserved transition time %s, got %s", earlier, target.LastTransitionAt)
		}
	})

	t.Run("connected reopens as deploying on running operation", func(t *testing.T) {
		target := db.AWSOrganizationRolloutTarget{
			AccountID: "333333333333", Region: "us-east-1",
			State: db.AWSOrganizationRolloutTargetConnected, RoleARN: "arn:aws:iam::333333333333:role/identrail",
			LastTransitionAt: earlier,
		}
		applyAWSOrganizationStackInstance(&target, AWSOrganizationStackInstance{Status: "outdated", DetailedStatus: "running"}, now)
		if target.State != db.AWSOrganizationRolloutTargetDeploying {
			t.Fatalf("expected deploying, got %q", target.State)
		}
		if !target.LastTransitionAt.Equal(now) {
			t.Fatalf("expected transition stamped at now, got %s", target.LastTransitionAt)
		}
	})
}

// TestAWSOrganizationRolloutExemptFromEnvelopeExpiry documents that durable
// outcomes are never re-expired. Now that failed and partial rollouts stay in
// the monitored set, re-expiring them would replace a real failure reason with
// "expired" and drop them from drift monitoring 24 hours after creation.
func TestAWSOrganizationRolloutExemptFromEnvelopeExpiry(t *testing.T) {
	exempt := map[string]bool{
		db.AWSOrganizationRolloutStatusCompleted:   true,
		db.AWSOrganizationRolloutStatusFailed:      true,
		db.AWSOrganizationRolloutStatusPartial:     true,
		db.AWSOrganizationRolloutStatusCreated:     false,
		db.AWSOrganizationRolloutStatusLaunching:   false,
		db.AWSOrganizationRolloutStatusInProgress:  false,
		db.AWSOrganizationRolloutStatusReconciling: false,
	}
	for status, want := range exempt {
		if got := awsOrganizationRolloutExemptFromEnvelopeExpiry(status); got != want {
			t.Fatalf("exempt(%q) = %v; want %v", status, got, want)
		}
	}
}

// TestReconcileAWSOrganizationRolloutDegradesOnInventoryFailure proves a
// transient Organizations/StackSet discovery failure no longer aborts the
// whole pass. Target validation must still run against the stored target set,
// with the discovery failure surfaced on the result instead.
func TestReconcileAWSOrganizationRolloutDegradesOnInventoryFailure(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222")
	setAWSRolloutMemberTarget(t, svc, ctx, rollout, "222222222222", db.AWSOrganizationRolloutTargetValidating, "arn:aws:iam::222222222222:role/IdentrailReadOnly")
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{result: AWSConnectionValidationResult{
		AccountID: "222222222222",
		PermissionChecks: []AWSConnectionPermissionCheck{
			{Name: "sts:AssumeRole", Passed: true},
			{Name: "iam:ListRoles", Passed: true},
		},
	}}
	svc.AWSOrganizationInventoryFactory = func(context.Context, AWSConnectionStatus) (AWSOrganizationInventory, error) {
		return nil, errors.New("throttled by aws organizations")
	}

	result, status, err := svc.ReconcileAWSOrganizationRollout(ctx, "workspace-a", "project-1", rollout.RolloutID)
	if err != nil {
		t.Fatalf("expected reconciliation to degrade rather than fail: %v", err)
	}
	if !result.InventoryDegraded || result.InventoryFailureReason == "" {
		t.Fatalf("expected inventory degradation to be reported, got %+v", result)
	}
	if result.TargetsValidated == 0 {
		t.Fatalf("expected member validation to still run, got %+v", result)
	}
	if status.Status != db.AWSOrganizationRolloutStatusCompleted {
		t.Fatalf("expected validated targets to still aggregate, got %q", status.Status)
	}
}
