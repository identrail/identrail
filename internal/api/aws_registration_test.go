package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
)

type recordingAWSCloudFormationResponder struct {
	responses []awsCloudFormationCustomResourceResponse
}

func (r *recordingAWSCloudFormationResponder) Respond(_ context.Context, _ string, response awsCloudFormationCustomResourceResponse) error {
	r.responses = append(r.responses, response)
	return nil
}

type awsRegistrationRaceStore struct {
	db.Store
	db.AWSConnectorOnboardingAttemptStore
	interceptUpdate func(context.Context, db.AWSConnectorOnboardingAttempt, int64) (db.AWSConnectorOnboardingAttempt, error, bool)
}

func (s *awsRegistrationRaceStore) UpdateAWSConnectorOnboardingAttempt(ctx context.Context, attempt db.AWSConnectorOnboardingAttempt, expectedVersion int64) (db.AWSConnectorOnboardingAttempt, error) {
	if s.interceptUpdate != nil {
		if updated, err, handled := s.interceptUpdate(ctx, attempt, expectedVersion); handled {
			return updated, err
		}
	}
	return s.AWSConnectorOnboardingAttemptStore.UpdateAWSConnectorOnboardingAttempt(ctx, attempt, expectedVersion)
}

func TestAWSRegistrationConnectsWithoutRoleCopyPaste(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
	registration := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType:       "Create",
		ResponseURL:       "https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/response?signature=test",
		StackID:           stackID,
		RequestID:         "registration-request",
		ResourceType:      "Custom::IdentrailAWSConnectorRegistration",
		LogicalResourceID: "IdentrailConnectorRegistration",
		ResourceProperties: map[string]any{
			"Phase":           "Register",
			"AttemptId":       attempt.AttemptID,
			"ExternalId":      externalID,
			"RoleArn":         "arn:aws:iam::123456789012:role/IdentrailReadOnly",
			"TemplateVersion": awsConnectorTemplateVersion,
		},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, registration); err != nil {
		t.Fatalf("process role registration: %v", err)
	}
	status, err := svc.PollAWSConnector(ctx, started.ConnectorID, AWSConnectorPollRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("poll connector: %v", err)
	}
	if !status.Connected || status.OnboardingStatus != AWSConnectorOnboardingConnected || status.AccountID != "123456789012" || status.LastValidatedAt == nil {
		t.Fatalf("expected automatically connected role, got %+v", status)
	}
	attempt, err = store.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", attempt.AttemptID)
	if err != nil || attempt.Status != db.AWSConnectorOnboardingAttemptConnected {
		t.Fatalf("expected connected attempt, got %+v err=%v", attempt, err)
	}
}

func TestAWSRegistrationAllowsAuthenticatedBoundStackUpdateAfterAttemptExpiry(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	registration := awsRegistrationRequest(stackID, "Create", "registration-create", "Register", attempt.AttemptID)
	registration.ResourceProperties["ExternalId"] = externalID
	registration.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	registration.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, registration)); err != nil {
		t.Fatalf("complete initial registration: %v", err)
	}

	svc.Now = func() time.Time { return attempt.ExpiresAt.Add(time.Hour) }
	bootstrapToken, err := svc.awsRegistrationToken(attempt)
	if err != nil {
		t.Fatalf("derive bootstrap token: %v", err)
	}
	bootstrapUpdate := awsRegistrationRequest(stackID, "Update", "bootstrap-update", "Bootstrap", attempt.AttemptID)
	bootstrapUpdate.ResourceProperties["RegistrationToken"] = bootstrapToken
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, bootstrapUpdate)); err != nil {
		t.Fatalf("authenticated bootstrap update after onboarding window: %v", err)
	}
	registrationUpdate := awsRegistrationRequest(stackID, "Update", "registration-update", "Register", attempt.AttemptID)
	registrationUpdate.ResourceProperties["ExternalId"] = externalID
	registrationUpdate.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	registrationUpdate.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, registrationUpdate)); err != nil {
		t.Fatalf("authenticated registration update after onboarding window: %v", err)
	}
	status, err := svc.PollAWSConnector(ctx, started.ConnectorID, AWSConnectorPollRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil || !status.Connected || status.OnboardingStatus != AWSConnectorOnboardingConnected {
		t.Fatalf("expected updated bound stack to remain connected, got %+v err=%v", status, err)
	}
}

func TestAWSRegistrationRenewsAttemptDeadlineOnBoundStackUpdate(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	_, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	initial := awsRegistrationRequest(stackID, "Create", "registration-create", "Register", attempt.AttemptID)
	initial.ResourceProperties["ExternalId"] = externalID
	initial.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	initial.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, initial)); err != nil {
		t.Fatalf("complete initial registration: %v", err)
	}

	// Push the clock past the original two-hour deadline so the bound-Update
	// path is exercised. A concurrent PollAWSConnector must not observe the
	// still-expired ExpiresAt while validation is in flight.
	pastExpiry := attempt.ExpiresAt.Add(time.Hour)
	svc.Now = func() time.Time { return pastExpiry }

	bootstrapToken, err := svc.awsRegistrationToken(attempt)
	if err != nil {
		t.Fatalf("derive bootstrap token: %v", err)
	}
	bootstrapUpdate := awsRegistrationRequest(stackID, "Update", "bootstrap-update", "Bootstrap", attempt.AttemptID)
	bootstrapUpdate.ResourceProperties["RegistrationToken"] = bootstrapToken
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, bootstrapUpdate)); err != nil {
		t.Fatalf("authenticated bootstrap update after onboarding window: %v", err)
	}
	registrationUpdate := awsRegistrationRequest(stackID, "Update", "registration-update", "Register", attempt.AttemptID)
	registrationUpdate.ResourceProperties["ExternalId"] = externalID
	registrationUpdate.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	registrationUpdate.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, registrationUpdate)); err != nil {
		t.Fatalf("authenticated registration update after onboarding window: %v", err)
	}

	store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
	reloaded, err := store.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", attempt.AttemptID)
	if err != nil {
		t.Fatalf("reload attempt: %v", err)
	}
	if !reloaded.ExpiresAt.After(pastExpiry) {
		t.Fatalf("expected bound-Update to renew ExpiresAt past %s, got %s", pastExpiry, reloaded.ExpiresAt)
	}
}

func TestReserveAWSRegistrationBootstrapRejectsTerminalAttemptOnConflict(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	svc.AWSCloudFormationResponder = &recordingAWSCloudFormationResponder{}
	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
	attempt, err := store.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil {
		t.Fatalf("load active attempt: %v", err)
	}

	// The caller's in-memory copy of the attempt still shows an empty
	// BootstrapRequestID (that's how the outer processAWSRegistrationBootstrap
	// decides to attempt a reservation). We simulate a concurrent reservation
	// that raced and won the version race, but was then terminalized by a
	// stack-Delete cancellation before we got here. The reloaded row therefore
	// shares our BootstrapRequestID / StackID / AccountID / Partition but is
	// already `failed`.
	fingerprint := attempt
	fingerprint.Status = db.AWSConnectorOnboardingAttemptRegistering
	fingerprint.StackID = "arn:aws:cloudformation:us-east-1:123456789012:stack/identrail/12345678-abcd-1234-abcd-123456789012"
	fingerprint.AWSAccountID = "123456789012"
	fingerprint.AWSPartition = "aws"
	fingerprint.BootstrapRequestID = "bootstrap-create-1"
	if _, err := store.UpdateAWSConnectorOnboardingAttempt(ctx, fingerprint, attempt.Version); err != nil {
		t.Fatalf("seed reserved attempt: %v", err)
	}
	terminal, err := store.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", attempt.AttemptID)
	if err != nil {
		t.Fatalf("reload seeded attempt: %v", err)
	}
	terminal.Status = db.AWSConnectorOnboardingAttemptFailed
	terminal.FailureCode = "registration_stack_deleted"
	terminal.FailureMessage = "The AWS stack was deleted before Identrail could finish setting up the connection. Start a new connection."
	if _, err := store.UpdateAWSConnectorOnboardingAttempt(ctx, terminal, terminal.Version); err != nil {
		t.Fatalf("terminalize attempt: %v", err)
	}

	// A late-arriving Bootstrap Create with the same fingerprint would call
	// reserveAWSRegistrationBootstrap with a stale (pre-terminalization)
	// version. The reload should refuse to accept the terminal row.
	stale := attempt
	stale.Status = db.AWSConnectorOnboardingAttemptRegistering
	stale.StackID = fingerprint.StackID
	stale.AWSAccountID = fingerprint.AWSAccountID
	stale.AWSPartition = fingerprint.AWSPartition
	stale.BootstrapRequestID = fingerprint.BootstrapRequestID
	if _, err := svc.reserveAWSRegistrationBootstrap(ctx, store, stale); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("expected reservation on a terminalized attempt to conflict, got %v", err)
	}
	still, err := store.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", attempt.AttemptID)
	if err != nil {
		t.Fatalf("reload post-reserve attempt: %v", err)
	}
	if still.Status != db.AWSConnectorOnboardingAttemptFailed || still.FailureCode != "registration_stack_deleted" {
		t.Fatalf("terminal attempt must remain failed, got status=%s code=%s", still.Status, still.FailureCode)
	}
}

func TestAWSRegistrationRejectsUnauthenticatedBoundStackUpdateAfterAttemptExpiry(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	_, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	registration := awsRegistrationRequest(stackID, "Create", "registration-create", "Register", attempt.AttemptID)
	registration.ResourceProperties["ExternalId"] = externalID
	registration.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	registration.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, registration)); err != nil {
		t.Fatalf("complete initial registration: %v", err)
	}

	svc.Now = func() time.Time { return attempt.ExpiresAt.Add(time.Hour) }
	bootstrapUpdate := awsRegistrationRequest(stackID, "Update", "bootstrap-update", "Bootstrap", attempt.AttemptID)
	bootstrapUpdate.ResourceProperties["RegistrationToken"] = "wrong-registration-token"
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, bootstrapUpdate)); err == nil {
		t.Fatal("expected invalid lifecycle credential to reject a bound stack update")
	}
	if got := responder.responses[len(responder.responses)-1].Status; got != "FAILED" {
		t.Fatalf("expected bounded failure for invalid update credential, got %q", got)
	}
}

func TestAWSRegistrationValidationFailureBecomesNeedsFix(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{err: errors.New("sts unavailable")}
	registration := awsRegistrationRequest(stackID, "Create", "registration-failure", "Register", attempt.AttemptID)
	registration.ResourceProperties["ExternalId"] = externalID
	registration.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	registration.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, registration)); err != nil {
		t.Fatalf("registration failure should be recorded after releasing CloudFormation: %v", err)
	}
	status, err := svc.PollAWSConnector(ctx, started.ConnectorID, AWSConnectorPollRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("poll failed connector: %v", err)
	}
	if status.OnboardingStatus != AWSConnectorOnboardingNeedsFix || status.HealthStatus != "error" || status.LastValidatedAt != nil {
		t.Fatalf("expected honest needs-fix state without validation timestamp, got %+v", status)
	}
}

func TestAWSRegistrationValidationConflictReconcilesDeletedStackState(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	baseStore := svc.Store
	baseAttempts := baseStore.(db.AWSConnectorOnboardingAttemptStore)
	raceStore := &awsRegistrationRaceStore{Store: baseStore, AWSConnectorOnboardingAttemptStore: baseAttempts}
	raceStore.interceptUpdate = func(ctx context.Context, candidate db.AWSConnectorOnboardingAttempt, expectedVersion int64) (db.AWSConnectorOnboardingAttempt, error, bool) {
		if candidate.Status != db.AWSConnectorOnboardingAttemptConnected {
			return db.AWSConnectorOnboardingAttempt{}, nil, false
		}
		winner := candidate
		winner.Status = db.AWSConnectorOnboardingAttemptFailed
		winner.FailureCode = "registration_stack_deleted"
		winner.FailureMessage = "The AWS stack was deleted. Start a new connection."
		winner.ValidatedAt = nil
		if _, err := baseAttempts.UpdateAWSConnectorOnboardingAttempt(ctx, winner, expectedVersion); err != nil {
			t.Fatalf("install concurrent delete winner: %v", err)
		}
		return db.AWSConnectorOnboardingAttempt{}, db.ErrConflict, true
	}
	svc.Store = raceStore

	registration := awsRegistrationRequest(stackID, "Create", "registration-race", "Register", attempt.AttemptID)
	registration.ResourceProperties["ExternalId"] = externalID
	registration.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	registration.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, registration)); err != nil {
		t.Fatalf("registration conflict should reconcile to the winning delete: %v", err)
	}

	persistedAttempt, err := baseAttempts.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", attempt.AttemptID)
	if err != nil || persistedAttempt.Status != db.AWSConnectorOnboardingAttemptFailed {
		t.Fatalf("expected delete to win attempt race, got %+v err=%v", persistedAttempt, err)
	}
	persisted, err := baseStore.GetTenancyConnector(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil || persisted.Connector.Status != domain.ConnectorStatusDegraded || persisted.State.LastErrorCode != "registration_stack_deleted" {
		t.Fatalf("expected connector to converge on deleted-stack failure, got %+v err=%v", persisted, err)
	}
}

func TestAWSConnectorExpiryConflictRestoresWinningConnectedState(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, initialAttempt, _, _ := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	baseStore := svc.Store
	baseAttempts := baseStore.(db.AWSConnectorOnboardingAttemptStore)
	raceStore := &awsRegistrationRaceStore{Store: baseStore, AWSConnectorOnboardingAttemptStore: baseAttempts}
	raceStore.interceptUpdate = func(ctx context.Context, candidate db.AWSConnectorOnboardingAttempt, expectedVersion int64) (db.AWSConnectorOnboardingAttempt, error, bool) {
		if candidate.Status != db.AWSConnectorOnboardingAttemptExpired {
			return db.AWSConnectorOnboardingAttempt{}, nil, false
		}
		winner := candidate
		winner.Status = db.AWSConnectorOnboardingAttemptConnected
		winner.RoleARN = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
		winner.FailureCode = ""
		winner.FailureMessage = ""
		validatedAt := initialAttempt.ExpiresAt
		winner.ValidatedAt = &validatedAt
		if _, err := baseAttempts.UpdateAWSConnectorOnboardingAttempt(ctx, winner, expectedVersion); err != nil {
			t.Fatalf("install concurrent validation winner: %v", err)
		}
		return db.AWSConnectorOnboardingAttempt{}, db.ErrConflict, true
	}
	svc.Store = raceStore
	svc.Now = func() time.Time { return initialAttempt.ExpiresAt.Add(time.Minute) }

	status, err := svc.PollAWSConnector(ctx, started.ConnectorID, AWSConnectorPollRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("poll connector across expiry conflict: %v", err)
	}
	if !status.Connected || status.OnboardingStatus != AWSConnectorOnboardingConnected || status.HealthStatus != "healthy" {
		t.Fatalf("expected connector to converge on winning validation, got %+v", status)
	}
	persistedAttempt, err := baseAttempts.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", initialAttempt.AttemptID)
	if err != nil || persistedAttempt.Status != db.AWSConnectorOnboardingAttemptConnected {
		t.Fatalf("expected connected attempt to win expiry race, got %+v err=%v", persistedAttempt, err)
	}
}

func TestAWSRegistrationRejectsWrongToken(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
	attempt, err := store.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil {
		t.Fatalf("load attempt: %v", err)
	}
	message := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType:        "Create",
		ResponseURL:        "https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/response",
		StackID:            "arn:aws:cloudformation:us-east-1:123456789012:stack/identrail/12345678-abcd-1234-abcd-123456789012",
		RequestID:          "wrong-token",
		ResourceType:       "Custom::IdentrailAWSConnectorBootstrap",
		LogicalResourceID:  "IdentrailRegistrationBootstrap",
		ResourceProperties: map[string]any{"Phase": "Bootstrap", "AttemptId": attempt.AttemptID, "RegistrationToken": "wrong"},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, message); err == nil {
		t.Fatal("expected wrong token to fail")
	}
	if len(responder.responses) != 1 || responder.responses[0].Status != "FAILED" || responder.responses[0].Data != nil {
		t.Fatalf("unexpected safe failure response: %+v", responder.responses)
	}
}

func TestAWSRegistrationRejectsBoundBootstrapUpdateWithoutToken(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	_, attempt, stackID, _ := startAndBootstrapAWSRegistration(t, svc, ctx, responder)

	// Bound Bootstrap Update targeting the same stack — but sending a wrong
	// (or missing) RegistrationToken. An attacker who observed the stack
	// ARN and attempt id must not be able to bypass the token check by
	// publishing an Update instead of a Create.
	forged := awsRegistrationRequest(stackID, "Update", "forged-bootstrap-update", "Bootstrap", attempt.AttemptID)
	forged.ResourceProperties["RegistrationToken"] = "attacker-supplied"
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, forged)); err == nil {
		t.Fatal("expected bound bootstrap update without a valid token to be rejected")
	}
	last := responder.responses[len(responder.responses)-1]
	if last.Status != "FAILED" || last.Data != nil {
		t.Fatalf("expected a safe FAILED response, got %+v", last)
	}
}

func TestAWSRegistrationRejectsUntrustedTopicAndExpiredAttempt(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		topicARN  string
		expireNow bool
	}{
		{name: "untrusted topic", topicARN: "arn:aws:sns:us-east-1:111111111111:untrusted-registration"},
		{name: "expired attempt", topicARN: testAWSRegistrationTopicARN, expireNow: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			svc, ctx := newAWSRegistrationTestService(t)
			responder := &recordingAWSCloudFormationResponder{}
			svc.AWSCloudFormationResponder = responder
			started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
			if err != nil {
				t.Fatalf("start aws connector: %v", err)
			}
			store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
			attempt, err := store.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID)
			if err != nil {
				t.Fatalf("load attempt: %v", err)
			}
			token, err := svc.awsRegistrationToken(attempt)
			if err != nil {
				t.Fatalf("derive registration token: %v", err)
			}
			if testCase.expireNow {
				svc.Now = func() time.Time { return attempt.ExpiresAt.Add(time.Second) }
			}
			request := awsRegistrationRequest(
				"arn:aws:cloudformation:us-east-1:123456789012:stack/identrail/12345678-abcd-1234-abcd-123456789012",
				"Create",
				"bootstrap-request",
				"Bootstrap",
				attempt.AttemptID,
			)
			request.ResourceProperties["RegistrationToken"] = token
			if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testCase.topicARN, request)); err == nil {
				t.Fatal("expected registration request to fail closed")
			}
			if testCase.expireNow && (len(responder.responses) != 1 || responder.responses[0].Status != "FAILED") {
				t.Fatalf("expected bounded CloudFormation failure response, got %+v", responder.responses)
			}
			if !testCase.expireNow && len(responder.responses) != 0 {
				t.Fatalf("untrusted topic must be rejected before following a response URL, got %+v", responder.responses)
			}
		})
	}
}

func TestAWSRegistrationRejectsOutOfOrderAndReplayedRequests(t *testing.T) {
	t.Run("registration before bootstrap", func(t *testing.T) {
		svc, ctx := newAWSRegistrationTestService(t)
		responder := &recordingAWSCloudFormationResponder{}
		svc.AWSCloudFormationResponder = responder
		started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
		if err != nil {
			t.Fatalf("start aws connector: %v", err)
		}
		store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
		attempt, err := store.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID)
		if err != nil {
			t.Fatalf("load attempt: %v", err)
		}
		request := awsRegistrationRequest(
			"arn:aws:cloudformation:us-east-1:123456789012:stack/identrail/12345678-abcd-1234-abcd-123456789012",
			"Create",
			"registration-request",
			"Register",
			attempt.AttemptID,
		)
		request.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
		request.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
		if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, request)); err == nil {
			t.Fatal("expected registration before bootstrap to fail")
		}
	})

	t.Run("second bootstrap create", func(t *testing.T) {
		svc, ctx := newAWSRegistrationTestService(t)
		responder := &recordingAWSCloudFormationResponder{}
		svc.AWSCloudFormationResponder = responder
		_, attempt, stackID, _ := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
		store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
		stored, err := store.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", attempt.AttemptID)
		if err != nil {
			t.Fatalf("reload attempt: %v", err)
		}
		token, err := svc.awsRegistrationToken(stored)
		if err != nil {
			t.Fatalf("derive registration token: %v", err)
		}
		replay := awsRegistrationRequest(stackID, "Create", "different-bootstrap-request", "Bootstrap", attempt.AttemptID)
		replay.ResourceProperties["RegistrationToken"] = token
		if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, replay)); err == nil {
			t.Fatal("expected second bootstrap create to be rejected as replay")
		}
	})
}

func TestAWSRegistrationUpdateRedeliveryIsIdempotent(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		validationErr error
	}{
		{name: "connected"},
		{name: "needs fix", validationErr: errors.New("sts unavailable")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			svc, ctx := newAWSRegistrationTestService(t)
			responder := &recordingAWSCloudFormationResponder{}
			svc.AWSCloudFormationResponder = responder
			_, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
			validator := svc.AWSConnectorValidator.(*fakeAWSConnectorValidator)

			create := awsRegistrationRequest(stackID, "Create", "registration-create", "Register", attempt.AttemptID)
			create.ResourceProperties["ExternalId"] = externalID
			create.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
			create.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
			if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, create)); err != nil {
				t.Fatalf("complete initial registration: %v", err)
			}

			validator.err = testCase.validationErr
			update := awsRegistrationRequest(stackID, "Update", "registration-update", "Register", attempt.AttemptID)
			update.ResourceProperties["ExternalId"] = externalID
			update.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
			update.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
			message := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, update)
			responsesBefore := len(responder.responses)
			validationsBefore := validator.calls
			if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, message); err != nil {
				t.Fatalf("process registration update: %v", err)
			}
			if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, message); err != nil {
				t.Fatalf("redeliver registration update: %v", err)
			}
			if got := len(responder.responses) - responsesBefore; got != 1 {
				t.Fatalf("expected one CloudFormation callback for a redelivered update, got %d", got)
			}
			if got := validator.calls - validationsBefore; got != 1 {
				t.Fatalf("expected one validation for a redelivered update, got %d", got)
			}
		})
	}
}

func TestAWSRegistrationRejectsPhaseResourceMismatch(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
	attempt, err := store.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil {
		t.Fatalf("load attempt: %v", err)
	}
	token, err := svc.awsRegistrationToken(attempt)
	if err != nil {
		t.Fatalf("derive registration token: %v", err)
	}
	request := awsRegistrationRequest(
		"arn:aws:cloudformation:us-east-1:123456789012:stack/identrail/12345678-abcd-1234-abcd-123456789012",
		"Create",
		"phase-resource-mismatch",
		"Bootstrap",
		attempt.AttemptID,
	)
	request.ResourceType = "Custom::IdentrailAWSConnectorRegistration"
	request.ResourceProperties["RegistrationToken"] = token
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, request)); err == nil {
		t.Fatal("expected mismatched phase and resource type to fail closed")
	}
	if len(responder.responses) != 1 || responder.responses[0].Status != "FAILED" {
		t.Fatalf("expected bounded CloudFormation failure, got %+v", responder.responses)
	}
}

func TestAWSRegistrationRejectsRoleFromDifferentAccount(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	_, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	request := awsRegistrationRequest(stackID, "Create", "wrong-account-registration", "Register", attempt.AttemptID)
	request.ResourceProperties["ExternalId"] = externalID
	request.ResourceProperties["RoleArn"] = "arn:aws:iam::210987654321:role/IdentrailReadOnly"
	request.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, request)); err == nil {
		t.Fatal("expected role from a different AWS account to be rejected")
	}
	if got := responder.responses[len(responder.responses)-1].Status; got != "FAILED" {
		t.Fatalf("expected bounded CloudFormation failure response, got %q", got)
	}
}

func TestAWSRegistrationDeleteAlwaysReleasesCloudFormation(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	request := awsRegistrationRequest(
		"arn:aws:cloudformation:us-east-1:123456789012:stack/identrail/12345678-abcd-1234-abcd-123456789012",
		"Delete",
		"delete-request",
		"Register",
		"attempt-no-longer-present",
	)
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, request)); err != nil {
		t.Fatalf("delete must not block customer stack removal: %v", err)
	}
	if len(responder.responses) != 1 || responder.responses[0].Status != "SUCCESS" {
		t.Fatalf("expected successful delete response, got %+v", responder.responses)
	}
}

func TestAWSRegistrationDeleteRequiresCredentialAndPersistsTerminalState(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, attempt, stackID, _ := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)

	forged := awsRegistrationRequest(stackID, "Delete", "forged-delete", "Bootstrap", attempt.AttemptID)
	forged.ResourceProperties["RegistrationToken"] = "attacker-supplied"
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, forged)); err != nil {
		t.Fatalf("forged delete should release CloudFormation without changing state: %v", err)
	}
	unchanged, err := store.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", attempt.AttemptID)
	if err != nil || unchanged.Status != db.AWSConnectorOnboardingAttemptRegistering {
		t.Fatalf("forged delete changed onboarding attempt: %+v err=%v", unchanged, err)
	}

	token, err := svc.awsRegistrationToken(attempt)
	if err != nil {
		t.Fatalf("derive delete credential: %v", err)
	}
	valid := awsRegistrationRequest(stackID, "Delete", "valid-delete", "Bootstrap", attempt.AttemptID)
	valid.ResourceProperties["RegistrationToken"] = token
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, valid)); err != nil {
		t.Fatalf("process authenticated stack delete: %v", err)
	}
	failed, err := store.GetAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", attempt.AttemptID)
	if err != nil || failed.Status != db.AWSConnectorOnboardingAttemptFailed || failed.FailureCode != "registration_stack_deleted" {
		t.Fatalf("expected terminalized onboarding attempt, got %+v err=%v", failed, err)
	}
	status, err := svc.PollAWSConnector(ctx, started.ConnectorID, AWSConnectorPollRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("poll deleted connector: %v", err)
	}
	if status.OnboardingStatus != AWSConnectorOnboardingFailed || status.HealthStatus != "error" {
		t.Fatalf("expected connector failure to match deleted stack, got %+v", status)
	}
	persisted, err := svc.Store.GetTenancyConnector(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil || persisted.State.LastErrorCode != "registration_stack_deleted" {
		t.Fatalf("expected persisted stack deletion diagnostic, got %+v err=%v", persisted.State, err)
	}
}

func TestAWSRegistrationConnectedStackDeleteUsesExternalIDCredential(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	responder := &recordingAWSCloudFormationResponder{}
	svc.AWSCloudFormationResponder = responder
	started, attempt, stackID, externalID := startAndBootstrapAWSRegistration(t, svc, ctx, responder)
	registration := awsRegistrationRequest(stackID, "Create", "registration-create", "Register", attempt.AttemptID)
	registration.ResourceProperties["ExternalId"] = externalID
	registration.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	registration.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, registration)); err != nil {
		t.Fatalf("connect role before delete: %v", err)
	}

	forged := awsRegistrationRequest(stackID, "Delete", "forged-register-delete", "Register", attempt.AttemptID)
	forged.ResourceProperties["ExternalId"] = "wrong-external-id"
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, forged)); err != nil {
		t.Fatalf("forged connected delete should be ignored safely: %v", err)
	}
	status, err := svc.PollAWSConnector(ctx, started.ConnectorID, AWSConnectorPollRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil || !status.Connected {
		t.Fatalf("forged delete disconnected connector: %+v err=%v", status, err)
	}

	valid := awsRegistrationRequest(stackID, "Delete", "valid-register-delete", "Register", attempt.AttemptID)
	valid.ResourceProperties["ExternalId"] = externalID
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, valid)); err != nil {
		t.Fatalf("process connected stack delete: %v", err)
	}
	status, err = svc.PollAWSConnector(ctx, started.ConnectorID, AWSConnectorPollRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil || status.Connected || status.OnboardingStatus != AWSConnectorOnboardingFailed {
		t.Fatalf("expected connected stack deletion to invalidate connector, got %+v err=%v", status, err)
	}
	persisted, err := svc.Store.GetTenancyConnector(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil || persisted.State.LastErrorCode != "registration_stack_deleted" {
		t.Fatalf("expected persisted connected-stack deletion diagnostic, got %+v err=%v", persisted.State, err)
	}
}

func TestAWSConnectorRepairHydrationDoesNotRenewAttemptAndExplicitRelaunchResetsState(t *testing.T) {
	svc, ctx := newAWSRegistrationTestService(t)
	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{WorkspaceID: "workspace-a", ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("start connector: %v", err)
	}
	attemptStore := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
	attempt, err := attemptStore.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil {
		t.Fatalf("load active attempt: %v", err)
	}
	attempt.Status = db.AWSConnectorOnboardingAttemptNeedsFix
	attempt.FailureCode = "assume_role_failed"
	attempt.FailureMessage = "Repair the trust policy."
	if _, err := attemptStore.UpdateAWSConnectorOnboardingAttempt(ctx, attempt, attempt.Version); err != nil {
		t.Fatalf("mark attempt needs fix: %v", err)
	}
	stored, err := svc.Store.GetTenancyConnector(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil {
		t.Fatalf("load connector: %v", err)
	}
	setup := awsMetadataSetupContract(stored.State.Metadata, AWSConnectorScopeSingleAccount, AWSConnectorDeploymentCloudFormation)
	applyAWSConnectorSetupMetadata(stored.State.Metadata, setup, AWSConnectorOnboardingNeedsFix)
	stored.Connector.Status = domain.ConnectorStatusDegraded
	stored.State.HealthStatus = "error"
	stored.State.LastErrorCode = "assume_role_failed"
	stored.State.LastErrorMessage = "Repair the trust policy."
	if err := svc.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
		t.Fatalf("persist repair state: %v", err)
	}

	hydrated, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: started.ConnectorID,
		RepairOnly:  true,
	})
	if err != nil {
		t.Fatalf("hydrate repair material: %v", err)
	}
	if hydrated.LaunchURL != "" || hydrated.ExternalID == "" || hydrated.OnboardingStatus != AWSConnectorOnboardingNeedsFix {
		t.Fatalf("repair hydration must preserve state and omit launch, got %+v", hydrated)
	}
	if _, err := attemptStore.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("repair hydration silently renewed an attempt: %v", err)
	}

	relaunched, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: started.ConnectorID,
	})
	if err != nil {
		t.Fatalf("explicitly relaunch connector: %v", err)
	}
	if relaunched.LaunchURL == "" || relaunched.OnboardingStatus != AWSConnectorOnboardingWaitingForAWS || relaunched.Connection.HealthStatus != "unknown" {
		t.Fatalf("explicit relaunch must reset to waiting state, got %+v", relaunched)
	}
	newAttempt, err := attemptStore.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil || newAttempt.AttemptID == attempt.AttemptID || newAttempt.Status != db.AWSConnectorOnboardingAttemptWaiting {
		t.Fatalf("expected a fresh explicit onboarding attempt, got %+v err=%v", newAttempt, err)
	}
}

func TestAWSRegistrationResponseURLAllowlist(t *testing.T) {
	for _, rawURL := range []string{
		"http://bucket.s3.amazonaws.com/response",
		"https://s3.amazonaws.com.evil.example/response",
		"https://user@example.s3.amazonaws.com/response",
	} {
		if err := validateAWSCloudFormationResponseURL(rawURL); err == nil {
			t.Fatalf("expected response url to be rejected: %s", rawURL)
		}
	}
	if err := validateAWSCloudFormationResponseURL("https://bucket.s3.us-east-1.amazonaws.com/response?signature=test"); err != nil {
		t.Fatalf("expected AWS S3 response URL to pass: %v", err)
	}
	if err := validateAWSCloudFormationResponseURL("https://cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com/response?signature=test"); err != nil {
		t.Fatalf("expected legacy regional AWS S3 response URL to pass: %v", err)
	}
}

func startAndBootstrapAWSRegistration(t *testing.T, svc *Service, ctx context.Context, responder *recordingAWSCloudFormationResponder) (AWSConnectorStartResponse, db.AWSConnectorOnboardingAttempt, string, string) {
	t.Helper()
	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	if started.ExternalID != "" || started.Connection.LastValidatedAt != nil {
		t.Fatalf("automatic start exposed a secret or false validation time: %+v", started)
	}
	launchURL, err := url.Parse(started.LaunchURL)
	if err != nil || !containsAWSLaunchParameter(launchURL.Fragment, "param_RegistrationToken=") || containsAWSLaunchParameter(launchURL.Fragment, "param_ExternalId=") {
		t.Fatalf("unexpected automatic launch url: %q", started.LaunchURL)
	}
	store := svc.Store.(db.AWSConnectorOnboardingAttemptStore)
	attempt, err := store.GetActiveAWSConnectorOnboardingAttempt(ctx, "workspace-a", "project-1", started.ConnectorID)
	if err != nil {
		t.Fatalf("load onboarding attempt: %v", err)
	}
	if len(attempt.TokenHash) != 32 {
		t.Fatalf("expected only a sha-256 token hash at rest, got %d bytes", len(attempt.TokenHash))
	}
	token, err := svc.awsRegistrationToken(attempt)
	if err != nil {
		t.Fatalf("derive registration token: %v", err)
	}
	stackID := "arn:aws:cloudformation:us-east-1:123456789012:stack/identrail-readonly-connector/12345678-abcd-1234-abcd-123456789012"
	bootstrap := awsRegistrationRequest(stackID, "Create", "bootstrap-request", "Bootstrap", attempt.AttemptID)
	bootstrap.ResourceProperties["RegistrationToken"] = token
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, bootstrap)); err != nil {
		t.Fatalf("process bootstrap: %v", err)
	}
	if len(responder.responses) == 0 || responder.responses[len(responder.responses)-1].Status != "SUCCESS" || responder.responses[len(responder.responses)-1].NoEcho || responder.responses[len(responder.responses)-1].Data["ExternalId"] == "" {
		t.Fatalf("unexpected bootstrap response: %+v", responder.responses)
	}
	externalID := responder.responses[len(responder.responses)-1].Data["ExternalId"].(string)
	return started, attempt, stackID, externalID
}

func awsRegistrationRequest(stackID string, requestType string, requestID string, phase string, attemptID string) awsCloudFormationCustomResourceRequest {
	resourceType := "Custom::IdentrailAWSConnectorRegistration"
	logicalID := "IdentrailConnectorRegistration"
	if phase == "Bootstrap" {
		resourceType = "Custom::IdentrailAWSConnectorBootstrap"
		logicalID = "IdentrailRegistrationBootstrap"
	}
	return awsCloudFormationCustomResourceRequest{
		RequestType:       requestType,
		ResponseURL:       "https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/response?signature=test",
		StackID:           stackID,
		RequestID:         requestID,
		ResourceType:      resourceType,
		LogicalResourceID: logicalID,
		ResourceProperties: map[string]any{
			"Phase":     phase,
			"AttemptId": attemptID,
		},
	}
}

func newAWSRegistrationTestService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{9}, 32)}})
	if err != nil {
		t.Fatalf("create secret manager: %v", err)
	}
	now := time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, routerScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"
	svc.AWSRegistrationTopicARNs = map[string]string{"us-east-1": testAWSRegistrationTopicARN}
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{result: AWSConnectionValidationResult{
		AccountID:    "123456789012",
		PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
		UserID:       "AROATEST:identrail-connector-validation",
		Region:       "us-east-1",
		PermissionChecks: []AWSConnectionPermissionCheck{
			{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
			{Name: "sts:GetCallerIdentity", Passed: true, Message: "AWS account identity matched."},
		},
	}}
	return svc, ctx
}

func awsRegistrationTestMessage(t *testing.T, topicARN string, request awsCloudFormationCustomResourceRequest) string {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal cloudformation request: %v", err)
	}
	envelope, err := json.Marshal(awsSNSEnvelope{Type: "Notification", TopicARN: topicARN, Message: string(payload), SignatureVersion: "1"})
	if err != nil {
		t.Fatalf("marshal sns envelope: %v", err)
	}
	return string(envelope)
}

func containsAWSLaunchParameter(fragment string, parameter string) bool {
	return len(fragment) >= len(parameter) && bytes.Contains([]byte(fragment), []byte(parameter))
}
