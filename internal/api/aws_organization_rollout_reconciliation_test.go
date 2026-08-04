package api

import (
	"context"
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

func TestRetryAWSOrganizationRolloutDoesNotResetNonRetryableTargets(t *testing.T) {
	svc, ctx, rollout := startAWSRolloutForReconciliationTest(t, "222222222222", "333333333333")
	store := svc.Store.(db.AWSOrganizationRolloutStore)
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
