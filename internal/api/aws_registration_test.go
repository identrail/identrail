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
	"github.com/identrail/identrail/internal/secretstore"
)

type recordingAWSCloudFormationResponder struct {
	responses []awsCloudFormationCustomResourceResponse
}

func (r *recordingAWSCloudFormationResponder) Respond(_ context.Context, _ string, response awsCloudFormationCustomResourceResponse) error {
	r.responses = append(r.responses, response)
	return nil
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

func TestAWSRegistrationAllowsBoundStackUpdateAfterAttemptExpiry(t *testing.T) {
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
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, bootstrapUpdate)); err != nil {
		t.Fatalf("process bootstrap update after expiry: %v", err)
	}
	updatedExternalID := responder.responses[len(responder.responses)-1].Data["ExternalId"]
	registrationUpdate := awsRegistrationRequest(stackID, "Update", "registration-update", "Register", attempt.AttemptID)
	registrationUpdate.ResourceProperties["ExternalId"] = updatedExternalID
	registrationUpdate.ResourceProperties["RoleArn"] = "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	registrationUpdate.ResourceProperties["TemplateVersion"] = awsConnectorTemplateVersion
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, registrationUpdate)); err != nil {
		t.Fatalf("process registration update after expiry: %v", err)
	}
	if got := responder.responses[len(responder.responses)-1].Status; got != "SUCCESS" {
		t.Fatalf("expected successful update response, got %q", got)
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
	if len(responder.responses) == 0 || responder.responses[len(responder.responses)-1].Status != "SUCCESS" || !responder.responses[len(responder.responses)-1].NoEcho || responder.responses[len(responder.responses)-1].Data["ExternalId"] == "" {
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
