package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
)

func newAWSOrganizationRolloutTestService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{9}, 32)}})
	if err != nil {
		t.Fatalf("create secret manager: %v", err)
	}
	now := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, routerScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"
	svc.AWSRegistrationTopicARNs = map[string]string{"us-east-1": testAWSRegistrationTopicARN}
	return svc, ctx
}

func seedAWSRolloutControllingConnector(t *testing.T, store db.Store, ctx context.Context, connectorID string, accountID string, health string, connectorStatus domain.ConnectorStatus, updatedAt time.Time) {
	t.Helper()
	scope, err := db.RequireScope(ctx)
	if err != nil {
		t.Fatalf("resolve scope: %v", err)
	}
	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		ProjectID:   "project-1",
		ConnectorID: connectorID,
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "AWS " + connectorID,
		Status:      connectorStatus,
		CreatedAt:   updatedAt,
		UpdatedAt:   updatedAt,
	}, db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  scope.WorkspaceID,
		ProjectID:    "project-1",
		ConnectorID:  connectorID,
		HealthStatus: health,
		Metadata: map[string]any{
			"role_arn":          "arn:aws:iam::" + accountID + ":role/IdentrailReadOnly",
			"region":            "us-east-1",
			"account_id":        accountID,
			"scope_type":        "organization",
			"deployment_method": "stackset_service_managed",
		},
		ObservedAt: updatedAt,
		UpdatedAt:  updatedAt,
	}); err != nil {
		t.Fatalf("seed controlling connector: %v", err)
	}
}

func TestStartAWSOrganizationRolloutRefusesUnvalidatedControllingConnector(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "unknown", domain.ConnectorStatusPending, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	_, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		TargetRegions:          []string{"us-east-1"},
	})
	if !errors.Is(err, ErrAWSOrganizationRolloutControllingUnready) {
		t.Fatalf("expected ErrAWSOrganizationRolloutControllingUnready, got %v", err)
	}
}

func TestStartAWSOrganizationRolloutRefusesMismatchedManagementAccount(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	_, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "222222222222",
		TargetRegions:          []string{"us-east-1"},
	})
	if !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected ErrInvalidAWSConnectionRequest, got %v", err)
	}
}

func TestStartAWSOrganizationRolloutSeedsExpectedTargets(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222", "333333333333"},
		ExcludedAccountIDs:     []string{"333333333333"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	if status.Status != db.AWSOrganizationRolloutStatusCreated {
		t.Fatalf("expected created status, got %q", status.Status)
	}
	// Management + two selected = 3 targets in the single supported region.
	if status.Summary.ExpectedTargets != 3 {
		t.Fatalf("expected 3 expected targets, got %d", status.Summary.ExpectedTargets)
	}
	excluded := 0
	pending := 0
	for _, target := range status.Targets {
		if target.State == db.AWSOrganizationRolloutTargetExcluded {
			excluded++
		}
		if target.State == db.AWSOrganizationRolloutTargetPending {
			pending++
		}
	}
	if excluded != 1 {
		t.Fatalf("expected 1 excluded target, got %d", excluded)
	}
	if pending != 2 {
		t.Fatalf("expected 2 pending targets, got %d", pending)
	}
	// Management target is present and marked management.
	foundManagement := false
	for _, target := range status.Targets {
		if target.AccountID == "111111111111" && target.IsManagement {
			foundManagement = true
			break
		}
	}
	if !foundManagement {
		t.Fatal("expected management account seeded as its own target")
	}
	if status.LaunchURL == "" {
		t.Fatal("expected launch URL to be populated")
	}
}

func TestStartAWSOrganizationRolloutRejectsSecondActiveRollout(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	request := AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	}
	if _, err := svc.StartAWSOrganizationRollout(ctx, request); err != nil {
		t.Fatalf("first rollout: %v", err)
	}
	_, err := svc.StartAWSOrganizationRollout(ctx, request)
	if err == nil {
		t.Fatal("expected second active rollout to be rejected")
	}
}

func TestProcessAWSOrganizationRolloutMemberRegistrationValidatesTarget(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	svc.AWSCloudFormationResponder = newRecordingCFNResponder()

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}

	rolloutStore, _ := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout, err := rolloutStore.GetAWSOrganizationRolloutAnyScope(ctx, status.RolloutID)
	if err != nil {
		t.Fatalf("load rollout: %v", err)
	}
	secret, err := svc.AWSOrganizationRolloutSecretForRollout(rollout)
	if err != nil {
		t.Fatalf("derive secret: %v", err)
	}
	// The persisted hash must equal SHA-256(secret) so registration is
	// authenticated by exact match and never by prefix or timing side channel.
	sum := sha256.Sum256([]byte(secret))
	if !bytes.Equal(sum[:], rollout.RegistrationSecretHash) {
		t.Fatal("registration secret hash mismatch with derived secret")
	}

	body := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType:       "Create",
		ResponseURL:       "https://cloudformation-custom-resource-response-us-east-1.s3.amazonaws.com/response",
		StackID:           "arn:aws:cloudformation:us-east-1:222222222222:stack/StackSet-identrail-readonly-connector-stackset-instance/uuid-1",
		RequestID:         "req-1",
		LogicalResourceID: "IdentrailRolloutRegistration",
		ResourceType:      "Custom::IdentrailAWSConnectorRegistration",
		ResourceProperties: map[string]any{
			"Phase":               "Register",
			"RolloutId":           rollout.RolloutID,
			"RegistrationSecret":  secret,
			"OrganizationId":      rollout.OrganizationID,
			"StackSetName":        rollout.StackSetName,
			"ManagementAccountId": rollout.ManagementAccountID,
			"RoleArn":             "arn:aws:iam::222222222222:role/IdentrailReadOnly",
			"TemplateVersion":     awsConnectorTemplateVersion,
		},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err != nil {
		t.Fatalf("process member registration: %v", err)
	}

	target, err := rolloutStore.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load target: %v", err)
	}
	if target.State != db.AWSOrganizationRolloutTargetValidating {
		t.Fatalf("expected target validating, got %q", target.State)
	}
	if target.RoleARN != "arn:aws:iam::222222222222:role/IdentrailReadOnly" {
		t.Fatalf("expected role arn persisted, got %q", target.RoleARN)
	}

	// Duplicate delivery must not fork a second target row.
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err != nil {
		t.Fatalf("duplicate member registration: %v", err)
	}
	target2, err := rolloutStore.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load target after replay: %v", err)
	}
	if target2.Version < target.Version {
		t.Fatalf("expected non-decreasing version on replay")
	}

	// Rollout must have progressed out of `created` once an event landed.
	rolloutAfter, err := rolloutStore.GetAWSOrganizationRolloutAnyScope(ctx, rollout.RolloutID)
	if err != nil {
		t.Fatalf("reload rollout: %v", err)
	}
	if rolloutAfter.Status != db.AWSOrganizationRolloutStatusInProgress {
		t.Fatalf("expected rollout in_progress, got %q", rolloutAfter.Status)
	}
}

func TestProcessAWSOrganizationRolloutMemberRegistrationRejectsUnrelatedAccount(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	svc.AWSCloudFormationResponder = newRecordingCFNResponder()

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	rolloutStore, _ := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout, err := rolloutStore.GetAWSOrganizationRolloutAnyScope(ctx, status.RolloutID)
	if err != nil {
		t.Fatalf("load rollout: %v", err)
	}
	secret, err := svc.AWSOrganizationRolloutSecretForRollout(rollout)
	if err != nil {
		t.Fatalf("derive secret: %v", err)
	}

	body := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType:       "Create",
		ResponseURL:       "https://cloudformation-custom-resource-response-us-east-1.s3.amazonaws.com/response",
		StackID:           "arn:aws:cloudformation:us-east-1:444444444444:stack/StackSet-identrail-readonly-connector-stackset-instance/uuid-4",
		RequestID:         "req-4",
		LogicalResourceID: "IdentrailRolloutRegistration",
		ResourceType:      "Custom::IdentrailAWSConnectorRegistration",
		ResourceProperties: map[string]any{
			"Phase":               "Register",
			"RolloutId":           rollout.RolloutID,
			"RegistrationSecret":  secret,
			"OrganizationId":      rollout.OrganizationID,
			"StackSetName":        rollout.StackSetName,
			"ManagementAccountId": rollout.ManagementAccountID,
			"RoleArn":             "arn:aws:iam::444444444444:role/IdentrailReadOnly",
			"TemplateVersion":     awsConnectorTemplateVersion,
		},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err == nil {
		t.Fatal("expected registration from unrelated account to be rejected")
	}
}

func TestProcessAWSOrganizationRolloutMemberRegistrationRejectsBadSecret(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	svc.AWSCloudFormationResponder = newRecordingCFNResponder()

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}

	body := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType:       "Create",
		ResponseURL:       "https://cloudformation-custom-resource-response-us-east-1.s3.amazonaws.com/response",
		StackID:           "arn:aws:cloudformation:us-east-1:222222222222:stack/StackSet-identrail-readonly-connector-stackset-instance/uuid-1",
		RequestID:         "req-1",
		LogicalResourceID: "IdentrailRolloutRegistration",
		ResourceType:      "Custom::IdentrailAWSConnectorRegistration",
		ResourceProperties: map[string]any{
			"Phase":               "Register",
			"RolloutId":           status.RolloutID,
			"RegistrationSecret":  base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("A", 32))),
			"OrganizationId":      status.OrganizationID,
			"StackSetName":        status.StackSetName,
			"ManagementAccountId": status.ManagementAccountID,
			"RoleArn":             "arn:aws:iam::222222222222:role/IdentrailReadOnly",
			"TemplateVersion":     awsConnectorTemplateVersion,
		},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err == nil {
		t.Fatal("expected registration with wrong secret to be rejected")
	}
}

func TestProcessAWSOrganizationRolloutMemberRegistrationRejectsWrongRoleName(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	svc.AWSCloudFormationResponder = newRecordingCFNResponder()

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	rolloutStore, _ := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout, err := rolloutStore.GetAWSOrganizationRolloutAnyScope(ctx, status.RolloutID)
	if err != nil {
		t.Fatalf("load rollout: %v", err)
	}
	secret, err := svc.AWSOrganizationRolloutSecretForRollout(rollout)
	if err != nil {
		t.Fatalf("derive secret: %v", err)
	}
	body := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType:       "Create",
		ResponseURL:       "https://cloudformation-custom-resource-response-us-east-1.s3.amazonaws.com/response",
		StackID:           "arn:aws:cloudformation:us-east-1:222222222222:stack/StackSet-identrail-readonly-connector-stackset-instance/uuid-1",
		RequestID:         "req-1",
		LogicalResourceID: "IdentrailRolloutRegistration",
		ResourceType:      "Custom::IdentrailAWSConnectorRegistration",
		ResourceProperties: map[string]any{
			"Phase":               "Register",
			"RolloutId":           rollout.RolloutID,
			"RegistrationSecret":  secret,
			"OrganizationId":      rollout.OrganizationID,
			"StackSetName":        rollout.StackSetName,
			"ManagementAccountId": rollout.ManagementAccountID,
			"RoleArn":             "arn:aws:iam::222222222222:role/AttackerControlledRole",
			"TemplateVersion":     awsConnectorTemplateVersion,
		},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err == nil {
		t.Fatal("expected registration with substituted role name to be rejected")
	}
}

func TestStartAWSOrganizationRolloutRejectsOUOnlyScope(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	_, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedOUIDs:          []string{"ou-prod"},
		TargetRegions:          []string{"us-east-1"},
	})
	if !errors.Is(err, ErrAWSOrganizationRolloutOUMembershipUnsupported) {
		t.Fatalf("expected OU-only rejection, got %v", err)
	}
}

func TestStartAWSOrganizationRolloutRejectsMixedPartitions(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	_, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1", "us-gov-west-1"},
	})
	if !errors.Is(err, ErrAWSOrganizationRolloutMixedPartition) {
		t.Fatalf("expected mixed-partition rejection, got %v", err)
	}
}

func TestStartAWSOrganizationRolloutRejectsNonNumericAccountID(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	_, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		// Twelve chars but not all digits: today's char-length check would
		// admit this; the digit-check regex rejects it.
		SelectedAccountIDs: []string{"22222222222X"},
		TargetRegions:      []string{"us-east-1"},
	})
	if !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected non-numeric account ID rejection, got %v", err)
	}
}

func TestStartAWSOrganizationRolloutLaunchURLCarriesRolloutParams(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222", "333333333333"},
		ExcludedAccountIDs:     []string{"333333333333"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	if status.LaunchURL == "" {
		t.Fatal("expected launch URL")
	}
	// Every rollout parameter the CFN template's UseRolloutRegistration
	// condition depends on must be present, or member instances will never
	// send registration events. Excluded accounts must reach AWS as a
	// difference filter, otherwise the operator's exclusion is silently
	// dropped.
	for _, needle := range []string{
		"param_RegistrationProviderArn",
		"param_RolloutId",
		"param_RolloutRegistrationSecret",
		"param_RolloutOrganizationId",
		"param_RolloutManagementAccountId",
		"param_RolloutStackSetName",
		"excludedAccounts=333333333333",
		"accountFilterType=DIFFERENCE",
	} {
		if !strings.Contains(status.LaunchURL, needle) {
			t.Fatalf("launch URL missing %q: %s", needle, status.LaunchURL)
		}
	}
	if strings.Contains(status.LaunchURL, "param_RolloutRegistrationSecret=&") ||
		strings.HasSuffix(status.LaunchURL, "param_RolloutRegistrationSecret=") {
		t.Fatalf("rollout secret must be populated: %s", status.LaunchURL)
	}
}

// recordingCFNResponder swallows CloudFormation callback deliveries so
// registration flows can be exercised without any outbound HTTP.
type recordingCFNResponder struct {
	entries []awsCloudFormationCustomResourceResponse
}

func newRecordingCFNResponder() *recordingCFNResponder {
	return &recordingCFNResponder{}
}

func (r *recordingCFNResponder) Respond(_ context.Context, _ string, response awsCloudFormationCustomResourceResponse) error {
	r.entries = append(r.entries, response)
	return nil
}

func TestProcessAWSOrganizationRolloutMemberRegistrationRejectsUnrelatedStack(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	svc.AWSCloudFormationResponder = newRecordingCFNResponder()

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	rolloutStore, _ := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout, err := rolloutStore.GetAWSOrganizationRolloutAnyScope(ctx, status.RolloutID)
	if err != nil {
		t.Fatalf("load rollout: %v", err)
	}
	secret, err := svc.AWSOrganizationRolloutSecretForRollout(rollout)
	if err != nil {
		t.Fatalf("derive secret: %v", err)
	}
	body := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType: "Create",
		ResponseURL: "https://cloudformation-custom-resource-response-us-east-1.s3.amazonaws.com/response",
		// Stack name does not start with `StackSet-<stackset-name>-` so
		// it is not a StackSet-managed instance of the approved StackSet.
		StackID:           "arn:aws:cloudformation:us-east-1:222222222222:stack/attacker-stack/uuid",
		RequestID:         "req-x",
		LogicalResourceID: "IdentrailRolloutRegistration",
		ResourceType:      "Custom::IdentrailAWSConnectorRegistration",
		ResourceProperties: map[string]any{
			"Phase":               "Register",
			"RolloutId":           rollout.RolloutID,
			"RegistrationSecret":  secret,
			"OrganizationId":      rollout.OrganizationID,
			"StackSetName":        rollout.StackSetName,
			"ManagementAccountId": rollout.ManagementAccountID,
			"RoleArn":             "arn:aws:iam::222222222222:role/IdentrailReadOnly",
			"TemplateVersion":     awsConnectorTemplateVersion,
		},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err == nil {
		t.Fatal("expected registration from unrelated stack to be rejected")
	}
}

func TestProcessAWSOrganizationRolloutMemberRegistrationSecondDeliveryIsNoOp(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	responder := newRecordingCFNResponder()
	svc.AWSCloudFormationResponder = responder

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	rolloutStore, _ := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout, err := rolloutStore.GetAWSOrganizationRolloutAnyScope(ctx, status.RolloutID)
	if err != nil {
		t.Fatalf("load rollout: %v", err)
	}
	secret, err := svc.AWSOrganizationRolloutSecretForRollout(rollout)
	if err != nil {
		t.Fatalf("derive secret: %v", err)
	}
	body := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType:       "Create",
		ResponseURL:       "https://cloudformation-custom-resource-response-us-east-1.s3.amazonaws.com/response",
		StackID:           "arn:aws:cloudformation:us-east-1:222222222222:stack/StackSet-identrail-readonly-connector-stackset-instance/uuid-1",
		RequestID:         "req-dup-1",
		LogicalResourceID: "IdentrailRolloutRegistration",
		ResourceType:      "Custom::IdentrailAWSConnectorRegistration",
		ResourceProperties: map[string]any{
			"Phase":               "Register",
			"RolloutId":           rollout.RolloutID,
			"RegistrationSecret":  secret,
			"OrganizationId":      rollout.OrganizationID,
			"StackSetName":        rollout.StackSetName,
			"ManagementAccountId": rollout.ManagementAccountID,
			"RoleArn":             "arn:aws:iam::222222222222:role/IdentrailReadOnly",
			"TemplateVersion":     awsConnectorTemplateVersion,
		},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	firstCallbacks := len(responder.entries)
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err != nil {
		t.Fatalf("duplicate delivery: %v", err)
	}
	// The redelivery must not send a second CFN callback for the same
	// request-id, which the pre-signed URL cannot accept twice.
	if len(responder.entries) != firstCallbacks {
		t.Fatalf("expected redelivery to skip callback, got %d entries (was %d)", len(responder.entries), firstCallbacks)
	}
}

func TestProcessAWSOrganizationRolloutMemberDeleteMarksRemoved(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	svc.AWSCloudFormationResponder = newRecordingCFNResponder()

	status, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	rolloutStore, _ := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout, err := rolloutStore.GetAWSOrganizationRolloutAnyScope(ctx, status.RolloutID)
	if err != nil {
		t.Fatalf("load rollout: %v", err)
	}
	rolloutSecret, err := svc.awsOrganizationRolloutSecret(rollout)
	if err != nil {
		t.Fatalf("derive rollout secret: %v", err)
	}
	body := awsRegistrationTestMessage(t, testAWSRegistrationTopicARN, awsCloudFormationCustomResourceRequest{
		RequestType:       "Delete",
		ResponseURL:       "https://cloudformation-custom-resource-response-us-east-1.s3.amazonaws.com/response",
		StackID:           "arn:aws:cloudformation:us-east-1:222222222222:stack/StackSet-identrail-readonly-connector-stackset-instance/uuid-1",
		RequestID:         "req-del-1",
		LogicalResourceID: "IdentrailRolloutRegistration",
		ResourceType:      "Custom::IdentrailAWSConnectorRegistration",
		ResourceProperties: map[string]any{
			"Phase":              "Register",
			"RolloutId":          rollout.RolloutID,
			"RegistrationSecret": rolloutSecret,
			"OrganizationId":     rollout.OrganizationID,
			"StackSetName":       rollout.StackSetName,
			"TemplateVersion":    rollout.TemplateVersion,
			"RoleArn":            "arn:aws:iam::222222222222:role/IdentrailReadOnly",
		},
	})
	if err := svc.ProcessAWSConnectorRegistrationMessage(ctx, body); err != nil {
		t.Fatalf("delete delivery: %v", err)
	}
	target, err := rolloutStore.GetAWSOrganizationRolloutTarget(ctx, rollout.RolloutID, "222222222222", "us-east-1")
	if err != nil {
		t.Fatalf("load target after delete: %v", err)
	}
	if target.State != db.AWSOrganizationRolloutTargetRemoved {
		t.Fatalf("expected target removed, got %q", target.State)
	}
}

func TestGetAWSOrganizationRolloutStatusRedactsSecretFromLaunchURL(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	startStatus, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start rollout: %v", err)
	}
	rolloutStore, _ := svc.Store.(db.AWSOrganizationRolloutStore)
	rollout, err := rolloutStore.GetAWSOrganizationRolloutAnyScope(ctx, startStatus.RolloutID)
	if err != nil {
		t.Fatalf("load rollout: %v", err)
	}
	secret, err := svc.AWSOrganizationRolloutSecretForRollout(rollout)
	if err != nil {
		t.Fatalf("derive secret: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	// The start response (tenancy.write) must include the secret so the
	// operator can actually launch AWS.
	if !strings.Contains(startStatus.LaunchURL, secret) {
		t.Fatal("expected start launch URL to embed the rollout secret")
	}
	// The read path (tenancy.read) must not leak the secret or the
	// RolloutId to a viewer who cannot legitimately launch the StackSet.
	getStatus, err := svc.GetAWSOrganizationRolloutStatus(ctx, "workspace-a", "project-1", startStatus.RolloutID)
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	if strings.Contains(getStatus.LaunchURL, secret) {
		t.Fatalf("read launch URL leaked rollout secret: %s", getStatus.LaunchURL)
	}
	if strings.Contains(getStatus.LaunchURL, rollout.RolloutID) {
		t.Fatalf("read launch URL leaked rollout id: %s", getStatus.LaunchURL)
	}
}

func TestStartAWSOrganizationRolloutRefusesMissingLaunchConfig(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	// Clear the account ID so the launch-configuration precondition fails
	// with a service-unavailable sentinel instead of creating a live
	// envelope that would hold the one-active connector lock.
	svc.AWSAccountID = ""

	_, err := svc.StartAWSOrganizationRollout(ctx, AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	})
	if !errors.Is(err, ErrAWSConnectorConfigUnavailable) {
		t.Fatalf("expected ErrAWSConnectorConfigUnavailable, got %v", err)
	}
}

func TestStartAWSOrganizationRolloutSweepsExpiredEnvelope(t *testing.T) {
	svc, ctx := newAWSOrganizationRolloutTestService(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))

	request := AWSOrganizationRolloutStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ControllingConnectorID: "aws-mgmt",
		OrganizationID:         "o-fixture001",
		ManagementAccountID:    "111111111111",
		SelectedAccountIDs:     []string{"222222222222"},
		TargetRegions:          []string{"us-east-1"},
	}
	if _, err := svc.StartAWSOrganizationRollout(ctx, request); err != nil {
		t.Fatalf("first rollout: %v", err)
	}
	// Advance the clock past the 24h envelope window. Without a sweep, the
	// one-active-per-controlling-connector lock would still be held and the
	// second start would return ErrConflict.
	svc.Now = func() time.Time { return time.Date(2026, 7, 31, 11, 0, 0, 0, time.UTC) }
	if _, err := svc.StartAWSOrganizationRollout(ctx, request); err != nil {
		t.Fatalf("expected second rollout after expiry sweep, got %v", err)
	}
}

var _ = json.Marshal // json import is referenced elsewhere; keep the reference explicit for future edits.
