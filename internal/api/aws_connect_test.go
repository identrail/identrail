package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

const (
	testAWSCloudFormationTemplateChecksum = "sha256:458d7e9ae2b2b3e5513709b6dd3b63da4190918db335508fa5e9ae307a978fe2"
	testAWSCloudFormationTemplateURL      = "https://cdn.identrail.example/connectors/aws/sha256/458d7e9ae2b2b3e5513709b6dd3b63da4190918db335508fa5e9ae307a978fe2/identrail-readonly.yaml"
)

type fakeAWSConnectorValidator struct {
	result AWSConnectionValidationResult
	err    error
	seen   AWSConnectionValidationRequest
}

func (f *fakeAWSConnectorValidator) ValidateAWSConnection(ctx context.Context, request AWSConnectionValidationRequest) (AWSConnectionValidationResult, error) {
	f.seen = request
	return f.result, f.err
}

func TestRouterAWSConnectionOnboardingActive(t *testing.T) {
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-west-2",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
				{Name: "iam:ListRoles", Passed: true, Message: "IAM role listing permission is available."},
			},
		},
	}
	r := newAWSConnectionTestRouter(t, validator)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", `{
		"connector_id":"aws-prod",
		"display_name":"Production AWS",
		"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly",
		"external_id":"tenant-external-id",
		"region":"us-west-2"
	}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected active connection 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var body struct {
		Connection AWSConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Connection.Connected || body.Connection.Status != domain.ConnectorStatusActive || body.Connection.HealthStatus != "healthy" {
		t.Fatalf("expected active healthy connection, got %+v", body.Connection)
	}
	if body.Connection.AccountID != "123456789012" || !body.Connection.ExternalIDConfigured {
		t.Fatalf("expected account metadata and external id flag, got %+v", body.Connection)
	}
	if validator.seen.ExternalID != "tenant-external-id" || validator.seen.Region != "us-west-2" {
		t.Fatalf("validator did not receive normalized request: %+v", validator.seen)
	}

	statusResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", "")
	if statusResp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", statusResp.Code, statusResp.Body.String())
	}
}

func TestRouterAWSConnectionRejectsUnsupportedScopeOverride(t *testing.T) {
	r := newAWSConnectionTestRouter(t, &fakeAWSConnectorValidator{})

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", `{
		"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly",
		"region":"us-east-1",
		"scope_type":"organization",
		"deployment_method":"stackset_service_managed",
		"target_regions":["us-east-1"],
		"auto_onboard_new_accounts":true
	}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected unsupported scope override 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRouterAWSConnectionKeepsLegacyManualScope(t *testing.T) {
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-west-2",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
				{Name: "iam:ListRoles", Passed: true, Message: "IAM role listing permission is available."},
			},
		},
	}
	r := newAWSConnectionTestRouter(t, validator)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", `{
		"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly",
		"region":"us-west-2",
		"scope_type":"manual_role",
		"deployment_method":"manual"
	}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected manual scope upsert 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var body struct {
		Connection AWSConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Connection.ScopeType != AWSConnectorScopeManualRole || body.Connection.DeploymentMethod != AWSConnectorDeploymentManual {
		t.Fatalf("expected legacy manual setup, got scope=%q method=%q", body.Connection.ScopeType, body.Connection.DeploymentMethod)
	}
}

func TestAWSConnectorManualStartAndValidateUsesStoredExternalID(t *testing.T) {
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/CustomerManagedIdentrail/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-west-2",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
				{Name: "iam:ListRoles", Passed: true, Message: "IAM role listing permission is available."},
			},
		},
	}
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSConnectorValidator = validator
	svc.AWSAccountID = "999999999999"

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      "aws-manual-prod",
		DisplayName:      "Customer-managed AWS",
		Region:           "us-west-2",
		ScopeType:        AWSConnectorScopeManualRole,
		DeploymentMethod: AWSConnectorDeploymentManual,
	})
	if err != nil {
		t.Fatalf("start manual aws connector: %v", err)
	}
	if started.ExternalID == "" || started.LaunchURL != "" || started.TemplateURL != "" || started.IdentrailAccountID != "999999999999" {
		t.Fatalf("expected manual setup external id without launch metadata, got %+v", started)
	}
	if started.ScopeType != AWSConnectorScopeManualRole || started.DeploymentMethod != AWSConnectorDeploymentManual {
		t.Fatalf("expected manual setup contract, got scope=%q method=%q", started.ScopeType, started.DeploymentMethod)
	}
	if !slices.Contains(started.NextActions, AWSConnectorNextActionValidateRole) || slices.Contains(started.NextActions, AWSConnectorNextActionLaunchStack) {
		t.Fatalf("expected manual setup next actions to validate role without launch stack, got %+v", started.NextActions)
	}

	validated, err := svc.ValidateAWSConnector(ctx, started.ConnectorID, AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::123456789012:role/CustomerManagedIdentrail",
		Region:      "us-west-2",
	})
	if err != nil {
		t.Fatalf("validate manual aws connector: %v", err)
	}
	if !validated.Connected || validated.ScopeType != AWSConnectorScopeManualRole || validated.DeploymentMethod != AWSConnectorDeploymentManual {
		t.Fatalf("expected connected manual connector, got %+v", validated)
	}
	if validated.ExternalID != "" {
		t.Fatalf("public validate response must not expose external id, got %q", validated.ExternalID)
	}
	if validator.seen.ExternalID != started.ExternalID {
		t.Fatalf("expected validation to use stored external id, got %q want %q", validator.seen.ExternalID, started.ExternalID)
	}

	resumed, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      started.ConnectorID,
		ScopeType:        AWSConnectorScopeManualRole,
		DeploymentMethod: AWSConnectorDeploymentManual,
	})
	if err != nil {
		t.Fatalf("resume manual aws connector: %v", err)
	}
	if resumed.ExternalID != started.ExternalID || resumed.LaunchURL != "" {
		t.Fatalf("expected manual resume to preserve external id without launch URL, got %+v", resumed)
	}
}

func TestAWSConnectorManualStartRecoversMissingExternalIDEnvelope(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/CustomerManagedIdentrail/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-west-2",
		},
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSConnectorValidator = validator
	svc.AWSAccountID = "999999999999"

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      "aws-manual-prod",
		DisplayName:      "Customer-managed AWS",
		Region:           "us-west-2",
		ScopeType:        AWSConnectorScopeManualRole,
		DeploymentMethod: AWSConnectorDeploymentManual,
	})
	if err != nil {
		t.Fatalf("start manual aws connector: %v", err)
	}
	if err := store.DeleteTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "aws-manual-prod", awsExternalIDSecretName); err != nil {
		t.Fatalf("delete manual external id envelope: %v", err)
	}

	recovered, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      started.ConnectorID,
		ScopeType:        AWSConnectorScopeManualRole,
		DeploymentMethod: AWSConnectorDeploymentManual,
	})
	if err != nil {
		t.Fatalf("recover manual aws connector external id: %v", err)
	}
	if recovered.ExternalID == "" || recovered.ExternalID == started.ExternalID || recovered.LaunchURL != "" {
		t.Fatalf("expected regenerated manual external id without launch URL, started=%+v recovered=%+v", started, recovered)
	}

	validated, err := svc.ValidateAWSConnector(ctx, recovered.ConnectorID, AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::123456789012:role/CustomerManagedIdentrail",
		Region:      "us-west-2",
	})
	if err != nil {
		t.Fatalf("validate recovered manual aws connector: %v", err)
	}
	if validated.ExternalID != "" {
		t.Fatalf("public validate response must not expose recovered external id, got %q", validated.ExternalID)
	}
	if validator.seen.ExternalID != recovered.ExternalID {
		t.Fatalf("expected validation to use recovered external id, got %q want %q", validator.seen.ExternalID, recovered.ExternalID)
	}
}

func TestAWSConnectionPersistsAcrossServiceInstances(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-west-2",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
				{Name: "iam:ReadRolePolicies", Passed: true, Message: "IAM role and policy read permissions are available."},
			},
		},
	}
	first := NewService(store, routerScanner{}, "aws")
	first.AWSConnectorValidator = validator
	first.ConnectorSecretManager = manager
	if _, err := first.UpsertAWSConnection(ctx, "workspace-a", "project-1", AWSConnectionUpsertRequest{
		DisplayName: "Production AWS",
		RoleARN:     "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		ExternalID:  "tenant-external-id",
		Region:      "us-west-2",
	}); err != nil {
		t.Fatalf("upsert aws connection: %v", err)
	}

	second := NewService(store, routerScanner{}, "aws")
	second.ConnectorSecretManager = manager
	status, err := second.GetAWSConnection(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get aws connection after service restart: %v", err)
	}
	if !status.Connected || status.ConnectorID != "aws-123456789012" {
		t.Fatalf("expected persisted active connection, got %+v", status)
	}
	if status.RoleARN != "arn:aws:iam::123456789012:role/IdentrailReadOnly" || !status.ExternalIDConfigured || status.ExternalID != "tenant-external-id" {
		t.Fatalf("expected persisted role metadata, got %+v", status)
	}
}

func TestGetAWSConnectionTreatsLegacyRoleMetadataAsManualScope(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	now := time.Date(2026, 7, 12, 15, 0, 0, 0, time.UTC)
	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-123456789012",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Legacy AWS",
		Status:      domain.ConnectorStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, db.TenancyConnectorState{
		TenantID:     "tenant-a",
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "aws-123456789012",
		HealthStatus: "healthy",
		Metadata: map[string]any{
			"role_arn":    "arn:aws:iam::123456789012:role/IdentrailReadOnly",
			"account_id":  "123456789012",
			"region":      "us-west-2",
			"external_id": "tenant-external-id",
		},
		ObservedAt: now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("seed legacy connector: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	status, err := svc.GetAWSConnection(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get legacy aws connection: %v", err)
	}
	if status.ScopeType != AWSConnectorScopeManualRole || status.DeploymentMethod != AWSConnectorDeploymentManual {
		t.Fatalf("expected legacy direct-role setup, got scope=%q method=%q", status.ScopeType, status.DeploymentMethod)
	}
	if status.LaunchURL != "" || status.TemplateURL != "" {
		t.Fatalf("expected legacy direct-role record without launch metadata, got launch=%q template=%q", status.LaunchURL, status.TemplateURL)
	}
}

func TestAWSConnectorStartRejectsLegacyManualConnectorResume(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	now := time.Date(2026, 7, 12, 15, 0, 0, 0, time.UTC)
	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-legacy",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Legacy AWS",
		Status:      domain.ConnectorStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, db.TenancyConnectorState{
		TenantID:     "tenant-a",
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "aws-legacy",
		HealthStatus: "healthy",
		Metadata: map[string]any{
			"role_arn":    "arn:aws:iam::123456789012:role/IdentrailReadOnly",
			"account_id":  "123456789012",
			"region":      "us-west-2",
			"external_id": "tenant-external-id",
		},
		ObservedAt: now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("seed legacy connector: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSAccountID = "999999999999"
	if _, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-legacy",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	}); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected legacy manual connector resume to be rejected, got %v", err)
	}

	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-legacy")
	if err != nil {
		t.Fatalf("load legacy connector: %v", err)
	}
	if stored.Connector.SecretProvider != "" || stored.Connector.SecretRefID != "" {
		t.Fatalf("expected rejected resume not to add secret refs, got %+v", stored.Connector)
	}
	if stored.State.Metadata["launch_url"] != nil || stored.State.Metadata["template_url"] != nil {
		t.Fatalf("expected rejected resume not to add launch metadata, got %+v", stored.State.Metadata)
	}
	if _, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "aws-legacy", awsExternalIDSecretName); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected rejected resume not to persist external id envelope, got %v", err)
	}
}

func TestAWSConnectionClearsPersistedExternalID(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-west-2",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
			},
		},
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = validator
	svc.ConnectorSecretManager = manager
	request := AWSConnectionUpsertRequest{
		DisplayName: "Production AWS",
		RoleARN:     "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		ExternalID:  "tenant-external-id",
		Region:      "us-west-2",
	}
	first, err := svc.UpsertAWSConnection(ctx, "workspace-a", "project-1", request)
	if err != nil {
		t.Fatalf("upsert aws connection with external id: %v", err)
	}
	if !first.ExternalIDConfigured || first.ExternalID != "tenant-external-id" {
		t.Fatalf("expected initial external id to be configured, got %+v", first)
	}

	request.ExternalID = ""
	cleared, err := svc.UpsertAWSConnection(ctx, "workspace-a", "project-1", request)
	if err != nil {
		t.Fatalf("clear aws external id: %v", err)
	}
	if cleared.ExternalIDConfigured || cleared.ExternalID != "" {
		t.Fatalf("expected cleared external id, got %+v", cleared)
	}
	if _, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "aws-123456789012", awsExternalIDSecretName); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected cleared external id envelope, got %v", err)
	}

	reloaded, err := svc.GetAWSConnection(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("reload aws connection: %v", err)
	}
	if reloaded.ExternalIDConfigured || reloaded.ExternalID != "" {
		t.Fatalf("expected reloaded connection to keep external id cleared, got %+v", reloaded)
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-123456789012")
	if err != nil {
		t.Fatalf("load stored connector: %v", err)
	}
	if stored.Connector.SecretProvider != "" || stored.Connector.SecretRefID != "" {
		t.Fatalf("expected connector secret reference to be cleared, got %+v", stored.Connector)
	}
}

func TestAWSAccountRegionCoverageServiceMethods(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(store, routerScanner{}, "aws")
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)

	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Production AWS",
		Status:      domain.ConnectorStatusActive,
	}, db.TenancyConnectorState{
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "aws-prod",
		HealthStatus: "healthy",
	}); err != nil {
		t.Fatalf("seed connector: %v", err)
	}

	coverage, err := svc.UpsertAWSAccountRegionCoverage(ctx, "workspace-a", "project-1", db.AWSAccountRegionCoverage{
		ConnectorID:          "aws-prod",
		AccountID:            "123456789012",
		AccountAlias:         "Production",
		OrganizationID:       "o-example",
		OUPath:               "root/prod",
		Partition:            "aws",
		Region:               "us-east-1",
		RoleARN:              "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		CoverageStatus:       db.AWSAccountRegionCoverageCovered,
		LastSuccessfulScanAt: &now,
		ScanCursor: map[string]any{
			"next_token": "abc",
		},
	})
	if err != nil {
		t.Fatalf("upsert coverage: %v", err)
	}
	if got, want := coverage.TenantID, "tenant-a"; got != want {
		t.Fatalf("tenant id = %q, want %q", got, want)
	}
	if got, want := coverage.WorkspaceID, "workspace-a"; got != want {
		t.Fatalf("workspace id = %q, want %q", got, want)
	}
	if got, want := coverage.ProjectID, "project-1"; got != want {
		t.Fatalf("project id = %q, want %q", got, want)
	}
	if got, want := coverage.CoverageStatus, db.AWSAccountRegionCoverageCovered; got != want {
		t.Fatalf("coverage status = %q, want %q", got, want)
	}

	records, err := svc.ListAWSAccountRegionCoverages(ctx, "workspace-a", "project-1", db.AWSAccountRegionCoverageFilter{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("list coverage: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	if got, want := records[0].AccountID, "123456789012"; got != want {
		t.Fatalf("account id = %q, want %q", got, want)
	}
	if got, want := records[0].Region, "us-east-1"; got != want {
		t.Fatalf("region = %q, want %q", got, want)
	}

	_, err = svc.UpsertAWSAccountRegionCoverage(ctx, "workspace-a", "project-1", db.AWSAccountRegionCoverage{
		AccountID: "123456789012",
		Region:    "us-west-2",
	})
	if !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("missing connector err = %v, want ErrInvalidAWSConnectionRequest", err)
	}
}

func TestRouterAWSConnectionOnboardingReturnsTrustRemediation(t *testing.T) {
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			PermissionChecks: []AWSConnectionPermissionCheck{{
				Name:        "sts:AssumeRole",
				Passed:      false,
				Message:     "AWS rejected sts:AssumeRole for the connector role.",
				Remediation: "Update the role trust policy to allow this deployment to call sts:AssumeRole.",
			}},
			Diagnostics: []AWSConnectionDiagnostic{{
				Code:        "aws_access_denied",
				Message:     "Unable to assume the AWS connector role.",
				Remediation: "Update the role trust policy to allow this deployment to call sts:AssumeRole.",
			}},
		},
	}
	r := newAWSConnectionTestRouter(t, validator)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", `{
		"role_arn":"arn:aws:iam::123456789012:role/BadTrustRole"
	}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected diagnostic response 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var body struct {
		Connection AWSConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Connection.Connected || body.Connection.Status != domain.ConnectorStatusDegraded || body.Connection.HealthStatus != "error" {
		t.Fatalf("expected degraded connection, got %+v", body.Connection)
	}
	if body.Connection.RemediationMessage == "" || len(body.Connection.Diagnostics) != 1 {
		t.Fatalf("expected remediation diagnostics, got %+v", body.Connection)
	}
}

func TestRouterAWSConnectionDiagnosticsRedactExternalID(t *testing.T) {
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			PermissionChecks: []AWSConnectionPermissionCheck{{
				Name:        "sts:AssumeRole",
				Passed:      false,
				Message:     "AWS rejected External ID secret-external-id-value.",
				Remediation: "Replace secret-external-id-value in the trust policy.",
			}},
			Diagnostics: []AWSConnectionDiagnostic{{
				Code:        "external_id_mismatch",
				Message:     "Trust policy expected a different External ID than secret-external-id-value.",
				Remediation: "Copy secret-external-id-value from setup context only.",
				EvidenceRef: "aws-connector:secret-external-id-value",
			}},
		},
	}
	r := newAWSConnectionTestRouter(t, validator)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", `{
		"role_arn":"arn:aws:iam::123456789012:role/BadTrustRole",
		"external_id":"secret-external-id-value"
	}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected diagnostic response 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "secret-external-id-value") {
		t.Fatalf("diagnostics must redact external id, got %s", resp.Body.String())
	}

	var body struct {
		Connection AWSConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var externalIDDiagnostic *AWSConnectionDiagnostic
	for index := range body.Connection.Diagnostics {
		if body.Connection.Diagnostics[index].Code == "external_id_mismatch" {
			externalIDDiagnostic = &body.Connection.Diagnostics[index]
			break
		}
	}
	if externalIDDiagnostic == nil {
		t.Fatalf("expected external-id diagnostic, got %+v", body.Connection.Diagnostics)
	}
	if !strings.Contains(externalIDDiagnostic.Message, "[redacted]") {
		t.Fatalf("expected redacted diagnostic text, got %+v", *externalIDDiagnostic)
	}
	if !strings.Contains(externalIDDiagnostic.EvidenceRef, "[redacted]") {
		t.Fatalf("expected redacted diagnostic evidence ref, got %+v", *externalIDDiagnostic)
	}
}

func TestAWSSetupDiagnosticCodePrefersExplicitCodes(t *testing.T) {
	cases := []struct {
		name string
		code string
		text string
		want string
	}{
		{
			name: "access denied maps before external id prose",
			code: "aws_access_denied",
			text: "AWS denied AssumeRole; update the trust policy External ID condition if your organization requires one.",
			want: "assume_role_failed",
		},
		{
			name: "known assume role code wins over prose",
			code: "assume_role_failed",
			text: "The remediation mentions external ID, but the API code is already normalized.",
			want: "assume_role_failed",
		},
		{
			name: "known external id code is preserved",
			code: "external_id_mismatch",
			text: "AssumeRole failed while validating the role.",
			want: "external_id_mismatch",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeAWSSetupDiagnosticCode(tc.code, tc.text); got != tc.want {
				t.Fatalf("normalizeAWSSetupDiagnosticCode(%q, %q) = %q, want %q", tc.code, tc.text, got, tc.want)
			}
		})
	}
}

func TestRouterAWSConnectionRejectsInvalidRoleARN(t *testing.T) {
	r := newAWSConnectionTestRouter(t, &fakeAWSConnectorValidator{})

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", `{
		"role_arn":"not-an-arn"
	}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid role arn 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRouterAWSConnectionValidatorUnavailable(t *testing.T) {
	r := newAWSConnectionTestRouter(t, nil)

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", `{
		"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly"
	}`)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable validator 503, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRouterAWSConnectorCloudFormationFlow(t *testing.T) {
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-east-1",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
			},
		},
	}
	r := newAWSConnectorFlowTestRouter(t, validator)

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"display_name":"Production AWS",
		"region":"us-east-1"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected connector start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody AWSConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if startBody.ConnectorID == "" || startBody.ExternalID == "" || startBody.LaunchURL == "" || len(startBody.PermissionPreview) == 0 {
		t.Fatalf("expected launch data and permission preview, got %+v", startBody)
	}
	if !strings.Contains(startResp.Body.String(), `"external_id"`) {
		t.Fatalf("expected start response to include one-time external id, got %s", startResp.Body.String())
	}
	if startBody.Connection.Status != domain.ConnectorStatusPending || !startBody.Connection.ExternalIDConfigured {
		t.Fatalf("expected pending connector with external id configured, got %+v", startBody.Connection)
	}
	if startBody.Connection.LaunchURL != "" {
		t.Fatalf("expected nested start connection to redact launch URL, got %q", startBody.Connection.LaunchURL)
	}
	if startBody.ScopeType != AWSConnectorScopeSingleAccount || startBody.DeploymentMethod != AWSConnectorDeploymentCloudFormation ||
		startBody.OnboardingStatus != AWSConnectorOnboardingLaunchReady {
		t.Fatalf("expected single-account cloudformation launch contract, got scope=%q method=%q status=%q", startBody.ScopeType, startBody.DeploymentMethod, startBody.OnboardingStatus)
	}
	if len(startBody.TargetRegions) != 1 || startBody.TargetRegions[0] != "us-east-1" {
		t.Fatalf("expected normalized target region, got %+v", startBody.TargetRegions)
	}
	if len(startBody.NextActions) == 0 || startBody.SetupSummary == "" {
		t.Fatalf("expected setup summary and next actions, got summary=%q actions=%+v", startBody.SetupSummary, startBody.NextActions)
	}

	pollResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/aws/"+startBody.ConnectorID+"/poll?workspace_id=workspace-a&project_id=project-1", "")
	if pollResp.Code != http.StatusOK {
		t.Fatalf("expected connector poll 200, got %d body=%s", pollResp.Code, pollResp.Body.String())
	}
	if strings.Contains(pollResp.Body.String(), `"external_id"`) {
		t.Fatalf("expected poll response to hide external id, got %s", pollResp.Body.String())
	}
	if strings.Contains(pollResp.Body.String(), startBody.ExternalID) || strings.Contains(pollResp.Body.String(), `"launch_url"`) {
		t.Fatalf("expected poll response to redact launch URL and external id, got %s", pollResp.Body.String())
	}
	var pollBody struct {
		Connection AWSConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(pollResp.Body.Bytes(), &pollBody); err != nil {
		t.Fatalf("decode poll response: %v", err)
	}
	if pollBody.Connection.ConnectorID != startBody.ConnectorID || pollBody.Connection.Status != domain.ConnectorStatusPending {
		t.Fatalf("expected pending polled connection, got %+v", pollBody.Connection)
	}
	if pollBody.Connection.ScopeType != AWSConnectorScopeSingleAccount || pollBody.Connection.DeploymentMethod != AWSConnectorDeploymentCloudFormation ||
		pollBody.Connection.OnboardingStatus != AWSConnectorOnboardingLaunchReady {
		t.Fatalf("expected polled setup contract to persist, got %+v", pollBody.Connection)
	}

	policyResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws/"+startBody.ConnectorID+"/refresh-policy", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1"
	}`)
	if policyResp.Code != http.StatusOK {
		t.Fatalf("expected policy refresh 200, got %d body=%s", policyResp.Code, policyResp.Body.String())
	}
	var policyBody AWSConnectorPolicyResponse
	if err := json.Unmarshal(policyResp.Body.Bytes(), &policyBody); err != nil {
		t.Fatalf("decode policy response: %v", err)
	}
	if policyBody.PolicyHash == "" || len(policyBody.PermissionPreview) == 0 {
		t.Fatalf("expected policy hash and preview, got %+v", policyBody)
	}

	validateOverrideResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws/"+startBody.ConnectorID+"/validate", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly",
		"scope_type":"organization",
		"deployment_method":"stackset_service_managed",
		"target_regions":["us-east-1"],
		"auto_onboard_new_accounts":true
	}`)
	if validateOverrideResp.Code != http.StatusBadRequest {
		t.Fatalf("expected validate setup override 400, got %d body=%s", validateOverrideResp.Code, validateOverrideResp.Body.String())
	}

	validateResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws/"+startBody.ConnectorID+"/validate", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly"
	}`)
	if validateResp.Code != http.StatusOK {
		t.Fatalf("expected connector validate 200, got %d body=%s", validateResp.Code, validateResp.Body.String())
	}
	if validator.seen.ExternalID != startBody.ExternalID {
		t.Fatalf("expected validator to receive decrypted external id, got %q want %q", validator.seen.ExternalID, startBody.ExternalID)
	}
	var validateBody struct {
		Connection AWSConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(validateResp.Body.Bytes(), &validateBody); err != nil {
		t.Fatalf("decode validate response: %v", err)
	}
	if validateBody.Connection.ScopeType != AWSConnectorScopeSingleAccount || validateBody.Connection.DeploymentMethod != AWSConnectorDeploymentCloudFormation ||
		validateBody.Connection.OnboardingStatus != AWSConnectorOnboardingConnected {
		t.Fatalf("expected validation to preserve setup contract and mark connected, got %+v", validateBody.Connection)
	}
	if strings.Contains(validateResp.Body.String(), startBody.ExternalID) || strings.Contains(validateResp.Body.String(), `"launch_url"`) {
		t.Fatalf("expected validate response to redact launch URL and external id, got %s", validateResp.Body.String())
	}

	validatedPollResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/aws/"+startBody.ConnectorID+"/poll?workspace_id=workspace-a&project_id=project-1", "")
	if validatedPollResp.Code != http.StatusOK {
		t.Fatalf("expected validated connector poll 200, got %d body=%s", validatedPollResp.Code, validatedPollResp.Body.String())
	}
	if strings.Contains(validatedPollResp.Body.String(), startBody.ExternalID) || strings.Contains(validatedPollResp.Body.String(), `"launch_url"`) {
		t.Fatalf("expected validated poll response to redact launch URL and external id, got %s", validatedPollResp.Body.String())
	}
}

func TestRouterAWSConnectorOrganizationStackSetFlow(t *testing.T) {
	r := newAWSConnectorFlowTestRouter(t, nil)

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"connector_id":"aws-org-prod",
		"display_name":"Production organization",
		"scope_type":"organization",
		"deployment_method":"stackset_service_managed",
		"target_regions":["us-east-1","eu-west-1"],
		"target_ou_ids":["r-abcd"],
		"excluded_account_ids":["210987654321"],
		"auto_onboard_new_accounts":true,
		"stack_set_name":"identrail-org-readonly"
	}`)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected organization stackset start 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startBody AWSConnectorStartResponse
	if err := json.Unmarshal(startResp.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if startBody.ScopeType != AWSConnectorScopeOrganization || startBody.DeploymentMethod != AWSConnectorDeploymentStackSetServiceManaged {
		t.Fatalf("expected organization service-managed stackset, got scope=%q method=%q", startBody.ScopeType, startBody.DeploymentMethod)
	}
	if startBody.OnboardingStatus != AWSConnectorOnboardingNeedsFix {
		t.Fatalf("expected organization onboarding to require trusted-access validation, got %q failures=%v", startBody.OnboardingStatus, startBody.StackSetOnboarding.Validation.FailureReasons)
	}
	if startBody.StackSetName != "identrail-org-readonly" || startBody.TemplateChecksum != testAWSCloudFormationTemplateChecksum {
		t.Fatalf("expected stackset name and checksum, got name=%q checksum=%q", startBody.StackSetName, startBody.TemplateChecksum)
	}
	if startBody.TargetSummary == nil || !startBody.TargetSummary.AllAccounts || startBody.TargetSummary.AccountCountKnown ||
		startBody.TargetSummary.OUCount != 1 || startBody.TargetSummary.RegionCount != 2 || startBody.TargetSummary.ExcludedAccountCount != 1 ||
		startBody.TargetSummary.ExpectedStackInstancesKnown {
		t.Fatalf("expected organization target-intent summary with unknown account count, got %+v", startBody.TargetSummary)
	}
	if !slices.Contains(startBody.NextActions, AWSConnectorNextActionOpenStackSet) ||
		!slices.Contains(startBody.NextActions, AWSConnectorNextActionEnableTrustedAccess) ||
		!slices.Contains(startBody.NextActions, AWSConnectorNextActionRegisterDelegatedAdmin) ||
		!slices.Contains(startBody.NextActions, AWSConnectorNextActionRefreshStatus) {
		t.Fatalf("expected stackset next actions, got %+v", startBody.NextActions)
	}
	if startBody.StackSetOnboarding == nil {
		t.Fatalf("expected unified stackset onboarding payload")
	}
	if startBody.IdentrailAccountID != "999999999999" ||
		startBody.StackSetOnboarding.AccountID != "" ||
		startBody.StackSetOnboarding.ManagementAccountID != "" {
		t.Fatalf("expected Identrail account to stay separate from customer management account, got identrail=%q onboarding=%+v", startBody.IdentrailAccountID, startBody.StackSetOnboarding)
	}
	if !startBody.StackSetOnboarding.Targets.AllAccounts ||
		len(startBody.StackSetOnboarding.Targets.OrganizationalUnits) != 1 ||
		len(startBody.StackSetOnboarding.Targets.Regions) != 1 ||
		startBody.StackSetOnboarding.Targets.Regions[0].Region != "us-east-1" {
		t.Fatalf("expected organization StackSet deployment to use the home region only, got %+v", startBody.StackSetOnboarding.Targets)
	}
	if len(startBody.StackSetOnboarding.Instances) != 0 ||
		startBody.StackSetOnboarding.Summary.TargetAccountsKnown ||
		startBody.StackSetOnboarding.Summary.TotalInstancesKnown ||
		startBody.StackSetOnboarding.Summary.DeployedPercentKnown ||
		startBody.StackSetOnboarding.CoverageExpectation.ExpectedAccountsKnown ||
		startBody.StackSetOnboarding.CoverageExpectation.ExpectedInstancesKnown ||
		startBody.StackSetOnboarding.CoverageExpectation.ExpectedCoverageTargetsKnown ||
		startBody.StackSetOnboarding.CoverageExpectation.CoveragePercentKnown ||
		startBody.StackSetOnboarding.CoverageExpectation.ExpectedRegions != 1 ||
		!startBody.StackSetOnboarding.CoverageExpectation.ExpectedRegionsKnown {
		t.Fatalf("service-managed organization projections must stay unknown until AWS expands membership, got onboarding=%+v", startBody.StackSetOnboarding)
	}
	if !slices.ContainsFunc(startBody.StackSetOnboarding.CoverageGaps, func(gap AWSStackSetOnboardingCoverageGap) bool {
		return gap.Capability == "service_managed_stackset_membership" && gap.Status == "unknown"
	}) {
		t.Fatalf("expected service-managed membership coverage gap, got %+v", startBody.StackSetOnboarding.CoverageGaps)
	}
	if startBody.StackSetOnboarding.Status != awsPlatformDependencyStatusBlocked {
		t.Fatalf("expected nested stackset onboarding to report blocked prerequisites, got %q", startBody.StackSetOnboarding.Status)
	}
	trustedAccess := requireAWSStackSetPrerequisite(t, startBody.Prerequisites, "stackset.trusted_access_enabled")
	if trustedAccess.Satisfied || trustedAccess.Severity != "blocking" {
		t.Fatalf("expected trusted access prerequisite to block until live AWS validation confirms it, got %+v", trustedAccess)
	}
	delegatedAdmin := requireAWSStackSetPrerequisite(t, startBody.Prerequisites, "stackset.delegated_admin_registered")
	if delegatedAdmin.Satisfied || delegatedAdmin.Severity != "advisory" {
		t.Fatalf("expected delegated admin to be an unsatisfied advisory, got %+v", delegatedAdmin)
	}
	if !strings.Contains(startBody.LaunchURL, "stacksets/create") ||
		!strings.Contains(startBody.LaunchURL, "permissionModel=SERVICE_MANAGED") ||
		!strings.Contains(startBody.LaunchURL, "organizationalUnitIds=r-abcd") ||
		!strings.Contains(startBody.LaunchURL, "excludedAccounts=210987654321") ||
		!strings.Contains(startBody.LaunchURL, "accountFilterType=DIFFERENCE") ||
		!strings.Contains(startBody.LaunchURL, "regions=us-east-1") ||
		!strings.Contains(startBody.LaunchURL, "autoDeploymentEnabled=true") ||
		!strings.Contains(startBody.LaunchURL, "retainStacksOnAccountRemoval=false") ||
		strings.Contains(startBody.LaunchURL, "eu-west-1") {
		t.Fatalf("expected stackset launch URL with service-managed targets and exclusions, got %q", startBody.LaunchURL)
	}
	assertAWSConnectorStartPayloadNoSecretMaterial(t, startResp.Body.String())
	if startBody.Connection.LaunchURL != "" {
		t.Fatalf("expected nested connection to redact launch URL, got %q", startBody.Connection.LaunchURL)
	}

	pollResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/aws/aws-org-prod/poll?workspace_id=workspace-a&project_id=project-1", "")
	if pollResp.Code != http.StatusOK {
		t.Fatalf("expected organization stackset poll 200, got %d body=%s", pollResp.Code, pollResp.Body.String())
	}
	if strings.Contains(pollResp.Body.String(), startBody.ExternalID) || strings.Contains(pollResp.Body.String(), `"launch_url"`) {
		t.Fatalf("expected poll response to redact launch URL and external id, got %s", pollResp.Body.String())
	}
	var pollBody struct {
		Connection AWSConnectionStatus `json:"connection"`
	}
	if err := json.Unmarshal(pollResp.Body.Bytes(), &pollBody); err != nil {
		t.Fatalf("decode poll response: %v", err)
	}
	if pollBody.Connection.ScopeType != AWSConnectorScopeOrganization ||
		pollBody.Connection.StackSetName != startBody.StackSetName ||
		pollBody.Connection.TargetSummary == nil ||
		!pollBody.Connection.TargetSummary.AllAccounts ||
		len(pollBody.Connection.Prerequisites) == 0 {
		t.Fatalf("expected poll to expose stackset lifecycle fields without setup secrets, got %+v", pollBody.Connection)
	}
}

func TestAWSConnectorStartSelectedStackSetScopes(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{8}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	accounts, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ConnectorID:            "aws-selected-accounts",
		DisplayName:            "Selected accounts",
		ScopeType:              AWSConnectorScopeSelectedAccounts,
		DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
		TargetAccountIDs:       []string{"111122223333", "444455556666"},
		TargetOUIDs:            []string{"r-abcd"},
		ExcludedAccountIDs:     []string{"444455556666"},
		TargetRegions:          []string{"us-east-1", "eu-west-1"},
		StackSetName:           "identrail-selected-accounts",
		AutoOnboardNewAccounts: false,
	})
	if err != nil {
		t.Fatalf("start selected accounts stackset: %v", err)
	}
	if accounts.TargetSummary == nil ||
		accounts.TargetSummary.AccountCountKnown ||
		accounts.TargetSummary.AccountCount != 0 ||
		accounts.TargetSummary.OUCount != 1 ||
		accounts.TargetSummary.RegionCount != 2 ||
		accounts.TargetSummary.ExcludedAccountCount != 1 ||
		accounts.TargetSummary.ExpectedStackInstances != 0 ||
		accounts.TargetSummary.ExpectedStackInstancesKnown {
		t.Fatalf("service-managed selected-account summary must leave counts unknown until AWS INTERSECTION resolves OU membership, got %+v", accounts.TargetSummary)
	}
	if accounts.StackSetOnboarding == nil ||
		len(accounts.StackSetOnboarding.Targets.Accounts) != 1 ||
		len(accounts.StackSetOnboarding.Targets.OrganizationalUnits) != 1 ||
		len(accounts.StackSetOnboarding.Targets.Regions) != 1 ||
		accounts.StackSetOnboarding.Targets.Regions[0].Region != "us-east-1" {
		t.Fatalf("expected excluded account to be subtracted from launch targets, got onboarding=%+v", accounts.StackSetOnboarding)
	}
	if len(accounts.StackSetOnboarding.Instances) != 0 ||
		accounts.StackSetOnboarding.Summary.TargetAccountsKnown ||
		accounts.StackSetOnboarding.Summary.TotalInstancesKnown ||
		accounts.StackSetOnboarding.Summary.DeployedPercentKnown ||
		accounts.StackSetOnboarding.CoverageExpectation.ExpectedAccountsKnown ||
		accounts.StackSetOnboarding.CoverageExpectation.ExpectedInstancesKnown ||
		accounts.StackSetOnboarding.CoverageExpectation.ExpectedCoverageTargetsKnown ||
		accounts.StackSetOnboarding.CoverageExpectation.CoveragePercentKnown ||
		accounts.StackSetOnboarding.CoverageExpectation.ExpectedRegions != 1 ||
		!accounts.StackSetOnboarding.CoverageExpectation.ExpectedRegionsKnown {
		t.Fatalf("service-managed selected-account projections must stay unknown until AWS resolves INTERSECTION membership, got onboarding=%+v", accounts.StackSetOnboarding)
	}
	if !slices.ContainsFunc(accounts.StackSetOnboarding.CoverageGaps, func(gap AWSStackSetOnboardingCoverageGap) bool {
		return gap.Capability == "service_managed_stackset_membership" && gap.Status == "unknown"
	}) {
		t.Fatalf("expected service-managed membership coverage gap, got %+v", accounts.StackSetOnboarding.CoverageGaps)
	}
	if !strings.Contains(accounts.LaunchURL, "organizationalUnitIds=r-abcd") ||
		!strings.Contains(accounts.LaunchURL, "accounts=111122223333") ||
		!strings.Contains(accounts.LaunchURL, "accountFilterType=INTERSECTION") ||
		!strings.Contains(accounts.LaunchURL, "regions=us-east-1") ||
		!strings.Contains(accounts.LaunchURL, "autoDeploymentEnabled=false") ||
		strings.Contains(accounts.LaunchURL, "eu-west-1") ||
		strings.Contains(accounts.LaunchURL, "accounts=444455556666") ||
		strings.Contains(accounts.LaunchURL, "excludedAccounts=") {
		t.Fatalf("expected launch URL to include root plus non-excluded selected-account filter, got %q", accounts.LaunchURL)
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-selected-accounts")
	if err != nil {
		t.Fatalf("load selected-account connector: %v", err)
	}
	if _, ok := stored.State.Metadata["external_id"]; ok {
		t.Fatalf("external id must not be persisted in selected-account metadata: %+v", stored.State.Metadata)
	}
	accountsRetry, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ConnectorID:            "aws-selected-accounts",
		DisplayName:            "Selected accounts",
		ScopeType:              AWSConnectorScopeSelectedAccounts,
		DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
		TargetAccountIDs:       []string{"444455556666", "111122223333"},
		TargetOUIDs:            []string{"r-abcd"},
		ExcludedAccountIDs:     []string{"444455556666"},
		TargetRegions:          []string{"us-east-1", "eu-west-1"},
		StackSetName:           "identrail-selected-accounts",
		AutoOnboardNewAccounts: false,
	})
	if err != nil {
		t.Fatalf("resume selected accounts stackset with reordered account set: %v", err)
	}
	if accountsRetry.LaunchURL != accounts.LaunchURL {
		t.Fatalf("expected reordered account set retry to resume existing launch URL, got %q want %q", accountsRetry.LaunchURL, accounts.LaunchURL)
	}

	ous, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      "aws-selected-ous",
		DisplayName:      "Selected OUs",
		ScopeType:        AWSConnectorScopeSelectedOUs,
		DeploymentMethod: AWSConnectorDeploymentStackSetServiceManaged,
		TargetOUIDs:      []string{"ou-abcd-12345678", "ou-abcd-87654321"},
		TargetRegions:    []string{"us-east-1"},
		StackSetName:     "identrail-selected-ous",
	})
	if err != nil {
		t.Fatalf("start selected OU stackset: %v", err)
	}
	if ous.TargetSummary == nil || ous.TargetSummary.OUCount != 2 ||
		ous.TargetSummary.AccountCountKnown || ous.TargetSummary.ExpectedStackInstancesKnown {
		t.Fatalf("expected selected-OU summary with unknown account expansion, got %+v", ous.TargetSummary)
	}
	if ous.StackSetOnboarding == nil || len(ous.StackSetOnboarding.Targets.OrganizationalUnits) != 2 ||
		!strings.Contains(ous.LaunchURL, "organizationalUnitIds=") {
		t.Fatalf("expected selected OUs in launch plan, got launch=%q onboarding=%+v", ous.LaunchURL, ous.StackSetOnboarding)
	}
	if len(ous.StackSetOnboarding.Instances) != 0 ||
		ous.StackSetOnboarding.Summary.TargetAccountsKnown ||
		ous.StackSetOnboarding.Summary.TotalInstancesKnown ||
		ous.StackSetOnboarding.CoverageExpectation.ExpectedAccountsKnown ||
		ous.StackSetOnboarding.CoverageExpectation.ExpectedInstancesKnown ||
		ous.StackSetOnboarding.CoverageExpectation.ExpectedCoverageTargetsKnown {
		t.Fatalf("service-managed selected-OU projections must stay unknown until AWS expands membership, got onboarding=%+v", ous.StackSetOnboarding)
	}
	if ous.StackSetOnboarding.Status != awsPlatformDependencyStatusBlocked {
		t.Fatalf("expected selected OU onboarding to report blocked prerequisites, got %q", ous.StackSetOnboarding.Status)
	}
}

func TestAWSConnectorStartRejectsStackSetResumeSetupDrift(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{8}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ConnectorID:            "aws-stackset",
		DisplayName:            "Production organization",
		ScopeType:              AWSConnectorScopeOrganization,
		DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:          []string{"us-east-1", "eu-west-1"},
		TargetOUIDs:            []string{"r-abcd"},
		AutoOnboardNewAccounts: true,
		StackSetName:           "identrail-org-readonly",
	})
	if err != nil {
		t.Fatalf("start organization stackset: %v", err)
	}
	if !strings.Contains(started.LaunchURL, "organizationalUnitIds=r-abcd") ||
		!strings.Contains(started.LaunchURL, "autoDeploymentEnabled=true") {
		t.Fatalf("expected organization launch URL, got %q", started.LaunchURL)
	}

	retries := []struct {
		name    string
		request AWSConnectorStartRequest
	}{
		{
			name: "selected OU scope",
			request: AWSConnectorStartRequest{
				WorkspaceID:      "workspace-a",
				ProjectID:        "project-1",
				ConnectorID:      "aws-stackset",
				DisplayName:      "Selected OUs",
				ScopeType:        AWSConnectorScopeSelectedOUs,
				DeploymentMethod: AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:    []string{"us-east-1"},
				TargetOUIDs:      []string{"ou-abcd-12345678"},
				StackSetName:     "identrail-selected-ous",
			},
		},
		{
			name: "self-managed deployment",
			request: AWSConnectorStartRequest{
				WorkspaceID:      "workspace-a",
				ProjectID:        "project-1",
				ConnectorID:      "aws-stackset",
				DisplayName:      "Selected accounts",
				ScopeType:        AWSConnectorScopeSelectedAccounts,
				DeploymentMethod: AWSConnectorDeploymentStackSetSelfManaged,
				TargetRegions:    []string{"us-east-1"},
				TargetAccountIDs: []string{"111122223333"},
				StackSetName:     "identrail-self-managed",
			},
		},
	}
	for _, retry := range retries {
		t.Run(retry.name, func(t *testing.T) {
			_, err := svc.StartAWSConnector(ctx, retry.request)
			if !errors.Is(err, ErrInvalidAWSConnectionRequest) {
				t.Fatalf("expected setup drift to be rejected, got %v", err)
			}
			stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-stackset")
			if err != nil {
				t.Fatalf("load stored connector: %v", err)
			}
			if got := awsMetadataString(stored.State.Metadata, "launch_url"); got != started.LaunchURL {
				t.Fatalf("setup drift must not replace launch URL, got %q want %q", got, started.LaunchURL)
			}
		})
	}
}

func TestAWSConnectorStartStackSetResumeAllowsUnsetChecksumForExisting(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{9}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	request := AWSConnectorStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ConnectorID:            "aws-stackset-resume",
		DisplayName:            "Production organization",
		ScopeType:              AWSConnectorScopeOrganization,
		DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:          []string{"us-east-1"},
		TargetOUIDs:            []string{"r-abcd"},
		AutoOnboardNewAccounts: true,
		StackSetName:           "identrail-org-readonly",
	}
	started, err := svc.StartAWSConnector(ctx, request)
	if err != nil {
		t.Fatalf("initial stackset start: %v", err)
	}
	if started.LaunchURL == "" {
		t.Fatalf("expected launch URL on initial start")
	}

	svc.AWSCloudFormationTemplateSHA = ""
	resumed, err := svc.StartAWSConnector(ctx, request)
	if err != nil {
		t.Fatalf("resume must succeed with unset configured checksum, got %v", err)
	}
	if resumed.LaunchURL != started.LaunchURL {
		t.Fatalf("resume must return the stored launch URL, got %q want %q", resumed.LaunchURL, started.LaunchURL)
	}
	if resumed.StackSetOnboarding == nil || resumed.StackSetOnboarding.TemplateChecksum != testAWSCloudFormationTemplateChecksum {
		t.Fatalf("resume must reuse the persisted template checksum, got %+v", resumed.StackSetOnboarding)
	}

	newRequest := request
	newRequest.ConnectorID = "aws-stackset-new"
	if _, err := svc.StartAWSConnector(ctx, newRequest); !errors.Is(err, ErrAWSConnectorConfigUnavailable) {
		t.Fatalf("new stackset setup without configured checksum must be rejected, got %v", err)
	}
}

func TestAWSConnectorStartRejectsStackSetLaunchIdentityDrift(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{10}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	base := AWSConnectorStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ConnectorID:            "aws-stackset-identity",
		DisplayName:            "Production organization",
		ScopeType:              AWSConnectorScopeOrganization,
		DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:          []string{"us-east-1"},
		TargetOUIDs:            []string{"r-abcd"},
		AutoOnboardNewAccounts: true,
		RoleName:               "IdentrailReadOnly",
		StackSetName:           "identrail-org-readonly",
	}
	started, err := svc.StartAWSConnector(ctx, base)
	if err != nil {
		t.Fatalf("initial stackset start: %v", err)
	}

	retries := []struct {
		name    string
		mutate  func(AWSConnectorStartRequest) AWSConnectorStartRequest
		wantErr error
	}{
		{
			name: "role_name",
			mutate: func(r AWSConnectorStartRequest) AWSConnectorStartRequest {
				r.RoleName = "IdentrailReadOnlyRenamed"
				return r
			},
			wantErr: ErrInvalidAWSConnectionRequest,
		},
		{
			name: "stack_set_name",
			mutate: func(r AWSConnectorStartRequest) AWSConnectorStartRequest {
				r.StackSetName = "identrail-org-readonly-v2"
				return r
			},
			wantErr: ErrInvalidAWSConnectionRequest,
		},
		{
			name: "same identity is not drift",
			mutate: func(r AWSConnectorStartRequest) AWSConnectorStartRequest {
				return r
			},
			wantErr: nil,
		},
	}
	for _, retry := range retries {
		t.Run(retry.name, func(t *testing.T) {
			_, err := svc.StartAWSConnector(ctx, retry.mutate(base))
			if retry.wantErr == nil {
				if err != nil {
					t.Fatalf("expected identical retry to succeed, got %v", err)
				}
			} else if !errors.Is(err, retry.wantErr) {
				t.Fatalf("expected %v, got %v", retry.wantErr, err)
			}
			stored, storeErr := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-stackset-identity")
			if storeErr != nil {
				t.Fatalf("load stored connector: %v", storeErr)
			}
			if got := awsMetadataString(stored.State.Metadata, "role_name"); got != base.RoleName {
				t.Fatalf("role_name must be preserved, got %q want %q", got, base.RoleName)
			}
			if got := awsMetadataString(stored.State.Metadata, "stack_set_name"); got != base.StackSetName {
				t.Fatalf("stack_set_name must be preserved, got %q want %q", got, base.StackSetName)
			}
			if got := awsMetadataString(stored.State.Metadata, "launch_url"); got != started.LaunchURL {
				t.Fatalf("launch URL must be preserved, got %q want %q", got, started.LaunchURL)
			}
		})
	}
}

func TestAWSConnectorStartRejectsInvalidStackSetName(t *testing.T) {
	tooLong := strings.Repeat("a", 129)
	invalid := []struct {
		name         string
		stackSetName string
	}{
		{name: "digit_prefix", stackSetName: "123-invalid"},
		{name: "underscore", stackSetName: "identrail_readonly"},
		{name: "too_long", stackSetName: tooLong},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			store := db.NewMemoryStore()
			ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
			seedDefaultProject(t, store, ctx, "project-1")
			manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{11}, 32)}})
			if err != nil {
				t.Fatalf("build connector secret manager: %v", err)
			}
			svc := NewService(store, routerScanner{}, "aws")
			svc.ConnectorSecretManager = manager
			svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
			svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
			svc.AWSAccountID = "999999999999"

			request := AWSConnectorStartRequest{
				WorkspaceID:      "workspace-a",
				ProjectID:        "project-1",
				ConnectorID:      "aws-stackset-invalid-name-" + tc.name,
				DisplayName:      "Production organization",
				ScopeType:        AWSConnectorScopeOrganization,
				DeploymentMethod: AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:    []string{"us-east-1"},
				TargetOUIDs:      []string{"r-abcd"},
				StackSetName:     tc.stackSetName,
			}
			if _, err := svc.StartAWSConnector(ctx, request); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
				t.Fatalf("invalid stack_set_name %q must be rejected before persistence, got %v", tc.stackSetName, err)
			}
			if _, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", request.ConnectorID); !errors.Is(err, db.ErrNotFound) {
				t.Fatalf("invalid stack_set_name must not persist a connector, got %v", err)
			}
		})
	}
}

func TestAWSConnectorStartRejectsInvalidStackSetRoleName(t *testing.T) {
	tooLong := strings.Repeat("a", 65)
	invalid := []struct {
		name     string
		roleName string
	}{
		{name: "path_separator", roleName: "team/IdentrailReadOnly"},
		{name: "too_long", roleName: tooLong},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			store := db.NewMemoryStore()
			ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
			seedDefaultProject(t, store, ctx, "project-1")
			manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{11}, 32)}})
			if err != nil {
				t.Fatalf("build connector secret manager: %v", err)
			}
			svc := NewService(store, routerScanner{}, "aws")
			svc.ConnectorSecretManager = manager
			svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
			svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
			svc.AWSAccountID = "999999999999"

			request := AWSConnectorStartRequest{
				WorkspaceID:      "workspace-a",
				ProjectID:        "project-1",
				ConnectorID:      "aws-stackset-invalid-role-" + tc.name,
				DisplayName:      "Production organization",
				ScopeType:        AWSConnectorScopeOrganization,
				DeploymentMethod: AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:    []string{"us-east-1"},
				TargetOUIDs:      []string{"r-abcd"},
				RoleName:         tc.roleName,
				StackSetName:     "identrail-org-readonly",
			}
			if _, err := svc.StartAWSConnector(ctx, request); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
				t.Fatalf("invalid role_name %q must be rejected before persistence, got %v", tc.roleName, err)
			}
			if _, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", request.ConnectorID); !errors.Is(err, db.ErrNotFound) {
				t.Fatalf("invalid role_name must not persist a connector, got %v", err)
			}
		})
	}
}

func TestAWSConnectorStartRejectsInvalidStackSetNameOnResume(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{12}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	request := AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      "aws-stackset-resume-invalid-name",
		DisplayName:      "Production organization",
		ScopeType:        AWSConnectorScopeOrganization,
		DeploymentMethod: AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:    []string{"us-east-1"},
		TargetOUIDs:      []string{"r-abcd"},
		StackSetName:     "identrail-org-readonly",
	}
	if _, err := svc.StartAWSConnector(ctx, request); err != nil {
		t.Fatalf("initial stackset start: %v", err)
	}
	invalidRetry := request
	invalidRetry.StackSetName = "123-invalid"
	if _, err := svc.StartAWSConnector(ctx, invalidRetry); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("invalid stack_set_name on resume must be rejected, got %v", err)
	}
}

func TestAWSConnectorStartRejectsInvalidStackSetRoleNameOnResume(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{12}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	request := AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      "aws-stackset-resume-invalid-role",
		DisplayName:      "Production organization",
		ScopeType:        AWSConnectorScopeOrganization,
		DeploymentMethod: AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:    []string{"us-east-1"},
		TargetOUIDs:      []string{"r-abcd"},
		RoleName:         "IdentrailReadOnly",
		StackSetName:     "identrail-org-readonly",
	}
	started, err := svc.StartAWSConnector(ctx, request)
	if err != nil {
		t.Fatalf("initial stackset start: %v", err)
	}
	invalidRetry := request
	invalidRetry.RoleName = "team/IdentrailReadOnly"
	if _, err := svc.StartAWSConnector(ctx, invalidRetry); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("invalid role_name on resume must be rejected, got %v", err)
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", request.ConnectorID)
	if err != nil {
		t.Fatalf("load stored connector: %v", err)
	}
	if got := awsMetadataString(stored.State.Metadata, "role_name"); got != request.RoleName {
		t.Fatalf("invalid role_name retry must not overwrite stored role, got %q", got)
	}
	if got := awsMetadataString(stored.State.Metadata, "launch_url"); got != started.LaunchURL {
		t.Fatalf("invalid role_name retry must not rebuild launch URL, got %q want %q", got, started.LaunchURL)
	}
}

func TestAWSConnectorStartStackSetRequiresConfiguredAccountID(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{13}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	request := AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      "aws-stackset-missing-account",
		DisplayName:      "Production organization",
		ScopeType:        AWSConnectorScopeOrganization,
		DeploymentMethod: AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:    []string{"us-east-1"},
		TargetOUIDs:      []string{"r-abcd"},
		StackSetName:     "identrail-org-readonly",
	}
	started, err := svc.StartAWSConnector(ctx, request)
	if err != nil {
		t.Fatalf("initial stackset start: %v", err)
	}

	svc.AWSAccountID = ""
	if _, err := svc.StartAWSConnector(ctx, request); !errors.Is(err, ErrAWSConnectorConfigUnavailable) {
		t.Fatalf("resume with unset AWSAccountID must be rejected, got %v", err)
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", request.ConnectorID)
	if err != nil {
		t.Fatalf("load stored connector: %v", err)
	}
	if got := awsMetadataString(stored.State.Metadata, "launch_url"); got != started.LaunchURL {
		t.Fatalf("rejected resume must not overwrite the stored launch URL, got %q want %q", got, started.LaunchURL)
	}
	newRequest := request
	newRequest.ConnectorID = "aws-stackset-new-missing-account"
	if _, err := svc.StartAWSConnector(ctx, newRequest); !errors.Is(err, ErrAWSConnectorConfigUnavailable) {
		t.Fatalf("new stackset setup with unset AWSAccountID must be rejected, got %v", err)
	}
}

func TestAWSConnectorValidateRejectsSelectedAccountOutsideScope(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "333344445555",
			PrincipalARN: "arn:aws:sts::333344445555:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-east-1",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
			},
		},
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = validator
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	if _, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:        "workspace-a",
		ProjectID:          "project-1",
		ConnectorID:        "aws-selected-accounts",
		DisplayName:        "Selected accounts",
		ScopeType:          AWSConnectorScopeSelectedAccounts,
		DeploymentMethod:   AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:      []string{"us-east-1"},
		TargetAccountIDs:   []string{"111122223333", "333344445555"},
		TargetOUIDs:        []string{"r-abcd"},
		ExcludedAccountIDs: []string{"333344445555"},
		StackSetName:       "identrail-selected-accounts",
	}); err != nil {
		t.Fatalf("start selected-account stackset connector: %v", err)
	}

	if _, err := svc.ValidateAWSConnector(ctx, "aws-selected-accounts", AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::333344445555:role/IdentrailReadOnly",
	}); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected excluded validation account to be rejected, got %v", err)
	}

	validator.result.AccountID = "666677778888"
	validator.result.PrincipalARN = "arn:aws:sts::666677778888:assumed-role/IdentrailReadOnly/identrail-connector-validation"
	if _, err := svc.ValidateAWSConnector(ctx, "aws-selected-accounts", AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::666677778888:role/IdentrailReadOnly",
	}); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected untargeted validation account to be rejected, got %v", err)
	}

	validator.result.AccountID = "111122223333"
	validator.result.PrincipalARN = "arn:aws:sts::111122223333:assumed-role/IdentrailReadOnly/identrail-connector-validation"
	connected, err := svc.ValidateAWSConnector(ctx, "aws-selected-accounts", AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::111122223333:role/IdentrailReadOnly",
	})
	if err != nil {
		t.Fatalf("expected targeted validation account to connect: %v", err)
	}
	if !connected.Connected || connected.AccountID != "111122223333" {
		t.Fatalf("expected selected targeted account to connect, got %+v", connected)
	}
}

func TestAWSConnectorValidateClearsStackSetLaunchPrerequisitesWhenConnected(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-east-1",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
			},
		},
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = validator
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ConnectorID:            "aws-org-prod",
		DisplayName:            "Production organization",
		ScopeType:              AWSConnectorScopeOrganization,
		DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:          []string{"us-east-1"},
		TargetOUIDs:            []string{"r-abcd"},
		AutoOnboardNewAccounts: true,
		StackSetName:           "identrail-org-readonly",
	})
	if err != nil {
		t.Fatalf("start organization stackset connector: %v", err)
	}
	if started.OnboardingStatus != AWSConnectorOnboardingNeedsFix || len(started.Prerequisites) == 0 {
		t.Fatalf("expected launch-time stackset prerequisites before validation, got status=%q prereqs=%+v", started.OnboardingStatus, started.Prerequisites)
	}

	connected, err := svc.ValidateAWSConnector(ctx, "aws-org-prod", AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::123456789012:role/IdentrailReadOnly",
	})
	if err != nil {
		t.Fatalf("validate organization stackset connector: %v", err)
	}
	if connected.OnboardingStatus != AWSConnectorOnboardingConnected || len(connected.Prerequisites) != 0 {
		t.Fatalf("expected connected validation to clear stale launch prerequisites, got status=%q prereqs=%+v", connected.OnboardingStatus, connected.Prerequisites)
	}
	if !slices.Contains(connected.NextActions, AWSConnectorNextActionStartIntelligence) ||
		slices.Contains(connected.NextActions, AWSConnectorNextActionEnableTrustedAccess) {
		t.Fatalf("expected connected next actions without stale StackSet blockers, got %+v", connected.NextActions)
	}

	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-org-prod")
	if err != nil {
		t.Fatalf("load validated stackset connector: %v", err)
	}
	if _, ok := stored.State.Metadata["prerequisites"]; ok {
		t.Fatalf("connected stackset connector must not preserve launch-time prerequisites: %+v", stored.State.Metadata["prerequisites"])
	}
	if got := awsMetadataString(stored.State.Metadata, "launch_url"); got != started.LaunchURL {
		t.Fatalf("expected validation to keep durable launch URL, got %q want %q", got, started.LaunchURL)
	}

	resumed, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ConnectorID:            "aws-org-prod",
		DisplayName:            "Production organization",
		ScopeType:              AWSConnectorScopeOrganization,
		DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:          []string{"us-east-1"},
		TargetOUIDs:            []string{"r-abcd"},
		AutoOnboardNewAccounts: true,
		StackSetName:           "identrail-org-readonly",
	})
	if err != nil {
		t.Fatalf("resume connected organization stackset connector: %v", err)
	}
	if resumed.OnboardingStatus != AWSConnectorOnboardingConnected ||
		resumed.Connection.OnboardingStatus != AWSConnectorOnboardingConnected ||
		len(resumed.Prerequisites) != 0 ||
		len(resumed.Connection.Prerequisites) != 0 {
		t.Fatalf("expected connected retry to keep connected state without launch blockers, got response=%+v connection=%+v", resumed, resumed.Connection)
	}
	if resumed.StackSetOnboarding != nil {
		t.Fatalf("connected retry must not attach a fresh blocked StackSet onboarding plan: %+v", resumed.StackSetOnboarding)
	}
	if slices.Contains(resumed.NextActions, AWSConnectorNextActionEnableTrustedAccess) ||
		!slices.Contains(resumed.NextActions, AWSConnectorNextActionStartIntelligence) {
		t.Fatalf("expected connected retry actions without trusted-access blockers, got %+v", resumed.NextActions)
	}
	if resumed.LaunchURL != started.LaunchURL {
		t.Fatalf("expected connected retry to keep durable launch URL, got %q want %q", resumed.LaunchURL, started.LaunchURL)
	}
}

func TestAWSConnectorStartRejectsInvalidStackSetScopeContracts(t *testing.T) {
	r := newAWSConnectorFlowTestRouter(t, nil)

	cases := []struct {
		name string
		body string
	}{
		{
			name: "missing stackset target regions",
			body: `{
				"workspace_id":"workspace-a",
				"project_id":"project-1",
				"scope_type":"organization",
				"target_ou_ids":["r-abcd"],
				"deployment_method":"stackset_service_managed"
			}`,
		},
		{
			name: "organization service-managed requires root or OU target",
			body: `{
					"workspace_id":"workspace-a",
					"project_id":"project-1",
				"scope_type":"organization",
				"deployment_method":"stackset_service_managed",
					"target_regions":["us-east-1"]
				}`,
		},
		{
			name: "organization rejects account filters",
			body: `{
					"workspace_id":"workspace-a",
					"project_id":"project-1",
					"scope_type":"organization",
					"deployment_method":"stackset_service_managed",
					"target_ou_ids":["r-abcd"],
					"target_account_ids":["123456789012"],
					"target_regions":["us-east-1"]
				}`,
		},
		{
			name: "invalid selected OU id",
			body: `{
					"workspace_id":"workspace-a",
					"project_id":"project-1",
				"scope_type":"selected_ous",
				"deployment_method":"stackset_service_managed",
				"target_ou_ids":["not-an-ou"],
					"target_regions":["us-east-1"]
				}`,
		},
		{
			name: "selected OUs reject account filters",
			body: `{
					"workspace_id":"workspace-a",
					"project_id":"project-1",
					"scope_type":"selected_ous",
					"deployment_method":"stackset_service_managed",
					"target_ou_ids":["ou-abcd-12345678"],
					"target_account_ids":["123456789012"],
					"target_regions":["us-east-1"]
				}`,
		},
		{
			name: "invalid selected account id",
			body: `{
					"workspace_id":"workspace-a",
					"project_id":"project-1",
				"scope_type":"selected_accounts",
				"deployment_method":"stackset_service_managed",
				"target_account_ids":["12345"],
					"target_regions":["us-east-1"]
				}`,
		},
		{
			name: "selected accounts reject empty effective account filter",
			body: `{
					"workspace_id":"workspace-a",
					"project_id":"project-1",
					"scope_type":"selected_accounts",
					"deployment_method":"stackset_service_managed",
					"target_ou_ids":["r-abcd"],
					"target_account_ids":["123456789012"],
					"excluded_account_ids":["123456789012"],
					"target_regions":["us-east-1"]
				}`,
		},
		{
			name: "service-managed selected accounts require root or OU target",
			body: `{
					"workspace_id":"workspace-a",
					"project_id":"project-1",
				"scope_type":"selected_accounts",
				"deployment_method":"stackset_service_managed",
				"target_account_ids":["123456789012"],
				"target_regions":["us-east-1"]
			}`,
		},
		{
			name: "self-managed selected accounts reject auto onboarding",
			body: `{
				"workspace_id":"workspace-a",
				"project_id":"project-1",
				"scope_type":"selected_accounts",
				"deployment_method":"stackset_self_managed",
				"target_account_ids":["123456789012"],
				"target_regions":["us-east-1"],
				"auto_onboard_new_accounts":true
			}`,
		},
		{
			name: "self-managed organization",
			body: `{
				"workspace_id":"workspace-a",
				"project_id":"project-1",
				"scope_type":"organization",
				"deployment_method":"stackset_self_managed",
				"target_regions":["us-east-1"]
			}`,
		},
		{
			name: "self-managed selected OU",
			body: `{
				"workspace_id":"workspace-a",
				"project_id":"project-1",
				"scope_type":"selected_ous",
				"deployment_method":"stackset_self_managed",
				"target_ou_ids":["ou-abcd-12345678"],
				"target_regions":["us-east-1"]
			}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws", tc.body)
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestAWSConnectorStartSelectedAccountsSelfManagedBlocksOnAdministrationRole(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{8}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:      "workspace-a",
		ProjectID:        "project-1",
		ConnectorID:      "aws-selected-self-managed",
		DisplayName:      "Selected self-managed accounts",
		ScopeType:        AWSConnectorScopeSelectedAccounts,
		DeploymentMethod: AWSConnectorDeploymentStackSetSelfManaged,
		TargetAccountIDs: []string{"111122223333", "444455556666"},
		TargetRegions:    []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("start self-managed selected accounts: %v", err)
	}
	if started.OnboardingStatus != AWSConnectorOnboardingNeedsFix {
		t.Fatalf("expected self-managed setup to need administration role, got %q", started.OnboardingStatus)
	}
	adminRole := requireAWSStackSetPrerequisite(t, started.Prerequisites, "stackset.administration_role_configured")
	if adminRole.Satisfied || adminRole.Severity != "blocking" {
		t.Fatalf("expected missing administration role to block self-managed setup, got %+v", adminRole)
	}
	if !slices.Contains(started.NextActions, AWSConnectorNextActionOpenStackSet) ||
		!slices.Contains(started.NextActions, AWSConnectorNextActionRefreshStatus) {
		t.Fatalf("expected operator recovery actions for self-managed setup, got %+v", started.NextActions)
	}
}

func TestAWSConnectorTargetSummaryCountsSelfManagedSelectedAccounts(t *testing.T) {
	setup := awsConnectorSetupContract{
		ScopeType:          AWSConnectorScopeSelectedAccounts,
		DeploymentMethod:   AWSConnectorDeploymentStackSetSelfManaged,
		TargetAccountIDs:   []string{"111122223333", "444455556666"},
		ExcludedAccountIDs: []string{"444455556666"},
		TargetRegions:      []string{"us-east-1"},
	}
	summary := awsConnectorTargetSummary(setup)
	if summary == nil || !summary.AccountCountKnown || !summary.ExpectedStackInstancesKnown {
		t.Fatalf("self-managed selected accounts must keep counts known, got %+v", summary)
	}
	if summary.AccountCount != 1 || summary.ExpectedStackInstances != 1 {
		t.Fatalf("self-managed selected accounts must count effective accounts, got %+v", summary)
	}

	serviceManaged := setup
	serviceManaged.DeploymentMethod = AWSConnectorDeploymentStackSetServiceManaged
	serviceManaged.TargetOUIDs = []string{"r-abcd"}
	serviceSummary := awsConnectorTargetSummary(serviceManaged)
	if serviceSummary == nil || serviceSummary.AccountCountKnown || serviceSummary.ExpectedStackInstancesKnown ||
		serviceSummary.AccountCount != 0 || serviceSummary.ExpectedStackInstances != 0 {
		t.Fatalf("service-managed selected accounts must leave counts unknown because AWS INTERSECTION filters by OU membership, got %+v", serviceSummary)
	}
}

func TestAWSConnectorTemplateURLMustCarryChecksum(t *testing.T) {
	if !awsConnectorTemplateURLPinnedToChecksum(testAWSCloudFormationTemplateURL, testAWSCloudFormationTemplateChecksum) {
		t.Fatalf("expected content-addressed template URL to match checksum")
	}
	if awsConnectorTemplateURLPinnedToChecksum("https://cdn.identrail.example/connectors/aws/identrail-readonly.yaml", testAWSCloudFormationTemplateChecksum) {
		t.Fatalf("mutable template URL must not be treated as checksum-pinned")
	}
	if awsConnectorTemplateURLPinnedToChecksum("https://cdn.identrail.example/connectors/aws/identrail-readonly.yaml?sha256=458d7e9ae2b2b3e5513709b6dd3b63da4190918db335508fa5e9ae307a978fe2", testAWSCloudFormationTemplateChecksum) {
		t.Fatalf("template URL query text must not satisfy checksum pinning")
	}
	if awsConnectorTemplateURLPinnedToChecksum("https://cdn.identrail.example/connectors/aws/sha256/1111111111111111111111111111111111111111111111111111111111111111/identrail-readonly.yaml?digest=458d7e9ae2b2b3e5513709b6dd3b63da4190918db335508fa5e9ae307a978fe2", testAWSCloudFormationTemplateChecksum) {
		t.Fatalf("template URL must require the configured checksum in the content-addressed path")
	}
	if awsConnectorTemplateURLPinnedToChecksum(testAWSCloudFormationTemplateURL, "sha256:1111111111111111111111111111111111111111111111111111111111111111") {
		t.Fatalf("template URL must not match a different checksum")
	}
}

func TestAWSConnectorStartStackSetRejectsMutableTemplateURL(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{8}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/identrail-readonly.yaml"
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"

	_, err = svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID:            "workspace-a",
		ProjectID:              "project-1",
		ConnectorID:            "aws-stackset-mutable-template",
		DisplayName:            "Production organization",
		ScopeType:              AWSConnectorScopeOrganization,
		DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
		TargetRegions:          []string{"us-east-1"},
		TargetOUIDs:            []string{"r-abcd"},
		AutoOnboardNewAccounts: true,
		StackSetName:           "identrail-org-readonly",
	})
	if !errors.Is(err, ErrAWSConnectorConfigUnavailable) {
		t.Fatalf("mutable StackSet template URL must be rejected before launch URL generation, got %v", err)
	}
	if _, loadErr := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-stackset-mutable-template"); !errors.Is(loadErr, db.ErrNotFound) {
		t.Fatalf("mutable template URL must not persist a connector, got %v", loadErr)
	}
}

func TestAWSConnectorStartResumesExistingCloudFormationSetup(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSAccountID = "999999999999"

	first, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
		RoleName:    "IdentrailReadOnly",
		StackName:   "identrail-readonly-connector",
	})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/new-template.yaml"
	second, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Different AWS",
		Region:      "us-west-2",
		RoleName:    "DifferentRole",
		StackName:   "different-stack",
	})
	if err != nil {
		t.Fatalf("resume aws connector: %v", err)
	}

	if second.ExternalID != first.ExternalID {
		t.Fatalf("expected resume to preserve external id, first=%q second=%q", first.ExternalID, second.ExternalID)
	}
	if second.LaunchURL != first.LaunchURL || second.RoleName != first.RoleName || second.StackName != first.StackName {
		t.Fatalf("expected resume to preserve launch parameters\nfirst=%+v\nsecond=%+v", first, second)
	}
	if second.TemplateURL != first.TemplateURL || second.Connection.TemplateURL != first.TemplateURL {
		t.Fatalf("expected resume to preserve persisted template URL, first=%q second=%q connection=%q", first.TemplateURL, second.TemplateURL, second.Connection.TemplateURL)
	}
	if second.Connection.DisplayName != "Production AWS" || second.Connection.Region != "us-east-1" {
		t.Fatalf("expected resume to return persisted connector identity, got %+v", second.Connection)
	}
	if second.OnboardingStatus != AWSConnectorOnboardingLaunchReady || len(second.NextActions) == 0 || second.SetupSummary == "" {
		t.Fatalf("expected resumed lifecycle fields, got %+v", second)
	}

	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-prod")
	if err != nil {
		t.Fatalf("load stored connector: %v", err)
	}
	if _, ok := stored.State.Metadata["external_id"]; ok {
		t.Fatalf("external id must not be persisted in connector metadata: %+v", stored.State.Metadata)
	}
	secret, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "aws-prod", awsExternalIDSecretName)
	if err != nil {
		t.Fatalf("load external id envelope: %v", err)
	}
	plaintext, err := manager.Decrypt(secret.Envelope, awsExternalIDAAD("tenant-a", "workspace-a", "project-1", "aws-prod"))
	if err != nil {
		t.Fatalf("decrypt external id envelope: %v", err)
	}
	if got := strings.TrimSpace(string(plaintext)); got != first.ExternalID {
		t.Fatalf("expected encrypted external id %q, got %q", first.ExternalID, got)
	}
}

func TestAWSConnectorValidatePreservesCloudFormationLaunchMetadata(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailCustomRole/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-east-1",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
			},
		},
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = validator
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/identrail-readonly-v1.yaml"
	svc.AWSAccountID = "999999999999"

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
		RoleName:    "IdentrailCustomRole",
		StackName:   "identrail-custom-stack",
	})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	if _, err := svc.ValidateAWSConnector(ctx, "aws-prod", AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::123456789012:role/IdentrailCustomRole",
	}); err != nil {
		t.Fatalf("validate aws connector: %v", err)
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-prod")
	if err != nil {
		t.Fatalf("load validated connector: %v", err)
	}
	if got := awsMetadataString(stored.State.Metadata, "launch_url"); got != started.LaunchURL {
		t.Fatalf("expected validation to preserve launch URL, got %q want %q", got, started.LaunchURL)
	}
	if got := awsMetadataString(stored.State.Metadata, "template_url"); got != started.TemplateURL {
		t.Fatalf("expected validation to preserve template URL, got %q want %q", got, started.TemplateURL)
	}
	if got := awsMetadataString(stored.State.Metadata, "role_name"); got != started.RoleName {
		t.Fatalf("expected validation to preserve role name, got %q want %q", got, started.RoleName)
	}
	if got := awsMetadataString(stored.State.Metadata, "stack_name"); got != started.StackName {
		t.Fatalf("expected validation to preserve stack name, got %q want %q", got, started.StackName)
	}

	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/identrail-readonly-v2.yaml"
	resumed, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-west-2",
	})
	if err != nil {
		t.Fatalf("resume validated aws connector: %v", err)
	}
	if resumed.LaunchURL != started.LaunchURL || resumed.TemplateURL != started.TemplateURL || resumed.RoleName != started.RoleName || resumed.StackName != started.StackName {
		t.Fatalf("expected resume after validation to keep original launch plan\nstarted=%+v\nresumed=%+v", started, resumed)
	}
}

func TestAWSConnectorValidateDropsLaunchMetadataWhenExternalIDChanges(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailCustomRole/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-east-1",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
			},
		},
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = validator
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/identrail-readonly-v1.yaml"
	svc.AWSAccountID = "999999999999"

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
		RoleName:    "IdentrailCustomRole",
		StackName:   "identrail-custom-stack",
	})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	if len(started.ExternalID) < 12 {
		t.Fatalf("test setup expected generated external id to be long enough, got %q", started.ExternalID)
	}
	newExternalID := started.ExternalID[:12]
	if !strings.Contains(started.LaunchURL, newExternalID) {
		t.Fatalf("test setup expected original launch URL to contain the new substring external id: %s", started.LaunchURL)
	}
	if awsCloudFormationLaunchURLExternalID(started.LaunchURL) != started.ExternalID {
		t.Fatalf("test setup expected original launch URL external id %q, got %q", started.ExternalID, awsCloudFormationLaunchURLExternalID(started.LaunchURL))
	}
	if _, err := svc.ValidateAWSConnector(ctx, "aws-prod", AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::123456789012:role/IdentrailCustomRole",
		ExternalID:  newExternalID,
	}); err != nil {
		t.Fatalf("validate aws connector: %v", err)
	}
	if validator.seen.ExternalID != newExternalID {
		t.Fatalf("expected validator to receive updated external id %q, got %q", newExternalID, validator.seen.ExternalID)
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-prod")
	if err != nil {
		t.Fatalf("load validated connector: %v", err)
	}
	for _, key := range []string{"launch_url", "template_url", "role_name", "stack_name"} {
		if got := awsMetadataString(stored.State.Metadata, key); got != "" {
			t.Fatalf("expected validation to drop stale %s, got %q", key, got)
		}
	}
	secret, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "aws-prod", awsExternalIDSecretName)
	if err != nil {
		t.Fatalf("load external id envelope: %v", err)
	}
	plaintext, err := manager.Decrypt(secret.Envelope, awsExternalIDAAD("tenant-a", "workspace-a", "project-1", "aws-prod"))
	if err != nil {
		t.Fatalf("decrypt external id envelope: %v", err)
	}
	if got := strings.TrimSpace(string(plaintext)); got != newExternalID {
		t.Fatalf("expected encrypted external id %q, got %q", newExternalID, got)
	}

	resumed, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("resume validated aws connector: %v", err)
	}
	if !strings.Contains(resumed.LaunchURL, newExternalID) {
		t.Fatalf("expected rebuilt launch URL to contain updated external id %q, got %q", newExternalID, resumed.LaunchURL)
	}
	if strings.Contains(resumed.LaunchURL, started.ExternalID) {
		t.Fatalf("expected rebuilt launch URL to drop original external id %q, got %q", started.ExternalID, resumed.LaunchURL)
	}
}

func TestAWSConnectorStartSerializesConcurrentExplicitConnectorStarts(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSAccountID = "999999999999"

	const workers = 16
	start := make(chan struct{})
	responses := make(chan AWSConnectorStartResponse, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			response, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
				WorkspaceID: "workspace-a",
				ProjectID:   "project-1",
				ConnectorID: "aws-prod",
				DisplayName: "Production AWS",
				Region:      "us-east-1",
			})
			if err != nil {
				errs <- err
				return
			}
			responses <- response
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(responses)

	for err := range errs {
		t.Fatalf("concurrent start returned error: %v", err)
	}
	var first AWSConnectorStartResponse
	for response := range responses {
		if first.ConnectorID == "" {
			first = response
			continue
		}
		if response.ExternalID != first.ExternalID || response.LaunchURL != first.LaunchURL || response.TemplateURL != first.TemplateURL {
			t.Fatalf("expected concurrent starts to return one launch plan\nfirst=%+v\nresponse=%+v", first, response)
		}
	}
	if first.ConnectorID != "aws-prod" || first.ExternalID == "" || first.LaunchURL == "" {
		t.Fatalf("expected complete first launch response, got %+v", first)
	}
}

func TestAWSConnectorStartPersistsRecoveredExternalIDLaunchState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSAccountID = "999999999999"

	first, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	if err := store.DeleteTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "aws-prod", awsExternalIDSecretName); err != nil {
		t.Fatalf("delete external id envelope: %v", err)
	}

	const workers = 8
	start := make(chan struct{})
	responses := make(chan AWSConnectorStartResponse, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			response, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
				WorkspaceID: "workspace-a",
				ProjectID:   "project-1",
				ConnectorID: "aws-prod",
				DisplayName: "Production AWS",
				Region:      "us-east-1",
			})
			if err != nil {
				errs <- err
				return
			}
			responses <- response
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(responses)
	for err := range errs {
		t.Fatalf("recover aws connector external id: %v", err)
	}

	var recovered AWSConnectorStartResponse
	for response := range responses {
		if recovered.ConnectorID == "" {
			recovered = response
			continue
		}
		if response.ExternalID != recovered.ExternalID || response.LaunchURL != recovered.LaunchURL {
			t.Fatalf("expected concurrent recovery to return one launch plan\nrecovered=%+v\nresponse=%+v", recovered, response)
		}
	}
	if recovered.ExternalID == "" || recovered.ExternalID == first.ExternalID {
		t.Fatalf("expected regenerated external id after envelope loss, first=%q recovered=%q", first.ExternalID, recovered.ExternalID)
	}
	if recovered.LaunchURL == first.LaunchURL {
		t.Fatalf("expected regenerated launch URL to carry regenerated external id")
	}

	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-prod")
	if err != nil {
		t.Fatalf("load recovered connector: %v", err)
	}
	if got := awsMetadataString(stored.State.Metadata, "launch_url"); got != recovered.LaunchURL {
		t.Fatalf("expected recovered launch URL to be persisted, got %q want %q", got, recovered.LaunchURL)
	}
	if got := awsMetadataString(stored.State.Metadata, "template_url"); got != recovered.TemplateURL {
		t.Fatalf("expected recovered template URL to be persisted, got %q want %q", got, recovered.TemplateURL)
	}

	again, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("resume recovered aws connector: %v", err)
	}
	if again.ExternalID != recovered.ExternalID || again.LaunchURL != recovered.LaunchURL {
		t.Fatalf("expected later resume to keep recovered launch state\nrecovered=%+v\nagain=%+v", recovered, again)
	}
}

func TestAWSConnectorStartFailsOnUnreadableExternalIDEnvelope(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSAccountID = "999999999999"

	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	secret, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "aws-prod", awsExternalIDSecretName)
	if err != nil {
		t.Fatalf("load external id envelope: %v", err)
	}
	secret.Envelope.Ciphertext[0] ^= 0xff
	if err := store.UpsertTenancyConnectorSecretEnvelope(ctx, secret); err != nil {
		t.Fatalf("corrupt external id envelope: %v", err)
	}

	if _, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	}); err == nil || !strings.Contains(err.Error(), "decrypt aws connector external id envelope") {
		t.Fatalf("expected decrypt failure instead of external id rotation, got %v", err)
	}
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-east-1",
		},
	}
	svc.AWSConnectorValidator = validator
	if _, err := svc.ValidateAWSConnector(ctx, "aws-prod", AWSConnectorValidateRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		RoleARN:     "arn:aws:iam::123456789012:role/IdentrailReadOnly",
	}); err == nil || !strings.Contains(err.Error(), "decrypt aws connector external id envelope") {
		t.Fatalf("expected validate to surface decrypt failure instead of clearing external id, got %v", err)
	}
	if validator.seen.RoleARN != "" {
		t.Fatalf("expected unreadable external id envelope to block validation, validator saw %+v", validator.seen)
	}

	corrupt, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "aws-prod", awsExternalIDSecretName)
	if err != nil {
		t.Fatalf("reload corrupt external id envelope: %v", err)
	}
	corrupt.Envelope.Ciphertext[0] ^= 0xff
	plaintext, err := manager.Decrypt(corrupt.Envelope, awsExternalIDAAD("tenant-a", "workspace-a", "project-1", "aws-prod"))
	if err != nil {
		t.Fatalf("decrypt restored external id envelope: %v", err)
	}
	if got := strings.TrimSpace(string(plaintext)); got != started.ExternalID {
		t.Fatalf("expected failed resume not to rotate external id, got %q want %q", got, started.ExternalID)
	}
}

func TestAWSConnectorStartPersistsRebuiltLaunchMetadataWithExistingExternalID(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSAccountID = "999999999999"

	first, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("start aws connector: %v", err)
	}
	stored, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-prod")
	if err != nil {
		t.Fatalf("load stored connector: %v", err)
	}
	originalSecretVersion := stored.Connector.SecretRefVersion
	if originalSecretVersion == "" {
		t.Fatalf("expected initial connector secret version")
	}
	if stored.Connector.SecretLastRotatedAt == nil {
		t.Fatalf("expected initial connector secret rotation time")
	}
	originalSecretRotatedAt := *stored.Connector.SecretLastRotatedAt
	metadata := copyAWSMetadata(stored.State.Metadata)
	delete(metadata, "launch_url")
	delete(metadata, "template_url")
	stored.State.Metadata = metadata
	if err := store.UpsertTenancyConnector(ctx, stored.Connector, stored.State); err != nil {
		t.Fatalf("remove launch metadata: %v", err)
	}
	rotatedManager, err := secretstore.NewManager([]secretstore.KeyMaterial{
		{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)},
		{Version: "test-v2", Key: bytes.Repeat([]byte{8}, 32)},
	})
	if err != nil {
		t.Fatalf("build rotated connector secret manager: %v", err)
	}
	svc.ConnectorSecretManager = rotatedManager

	recovered, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("rebuild launch metadata: %v", err)
	}
	if recovered.ExternalID != first.ExternalID {
		t.Fatalf("expected existing external id to be preserved, first=%q recovered=%q", first.ExternalID, recovered.ExternalID)
	}
	if recovered.LaunchURL == "" || recovered.TemplateURL == "" {
		t.Fatalf("expected rebuilt launch metadata, got %+v", recovered)
	}

	persisted, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-prod")
	if err != nil {
		t.Fatalf("load rebuilt connector: %v", err)
	}
	if got := awsMetadataString(persisted.State.Metadata, "launch_url"); got != recovered.LaunchURL {
		t.Fatalf("expected rebuilt launch URL to persist, got %q want %q", got, recovered.LaunchURL)
	}
	if persisted.Connector.SecretRefVersion != originalSecretVersion {
		t.Fatalf("expected metadata-only launch repair to preserve secret version, got %q want %q", persisted.Connector.SecretRefVersion, originalSecretVersion)
	}
	if persisted.Connector.SecretLastRotatedAt == nil || !persisted.Connector.SecretLastRotatedAt.Equal(originalSecretRotatedAt) {
		t.Fatalf("expected metadata-only launch repair to preserve secret rotation time, got %v want %v", persisted.Connector.SecretLastRotatedAt, originalSecretRotatedAt)
	}
	again, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		DisplayName: "Production AWS",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("resume rebuilt launch metadata: %v", err)
	}
	if again.ExternalID != recovered.ExternalID || again.LaunchURL != recovered.LaunchURL {
		t.Fatalf("expected later resume to keep rebuilt launch metadata\nrecovered=%+v\nagain=%+v", recovered, again)
	}
}

func TestRouterAWSConnectorFeatureFlagDisabled(t *testing.T) {
	r := newAWSConnectionTestRouter(t, &fakeAWSConnectorValidator{})

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1"
	}`)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected disabled connector route 404, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRouterAWSConnectorValidationErrors(t *testing.T) {
	r := newAWSConnectorFlowTestRouter(t, &fakeAWSConnectorValidator{})

	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws", `{}`)
	if startResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid start 400, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	invalidScopeResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"scope_type":"organization",
		"deployment_method":"cloudformation"
	}`)
	if invalidScopeResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid scope/deployment 400, got %d body=%s", invalidScopeResp.Code, invalidScopeResp.Body.String())
	}

	pollResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/aws/missing/poll", "")
	if pollResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid poll 400, got %d body=%s", pollResp.Code, pollResp.Body.String())
	}

	policyResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws/missing/refresh-policy", `{}`)
	if policyResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid policy refresh 400, got %d body=%s", policyResp.Code, policyResp.Body.String())
	}

	validateResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/connectors/aws/missing/validate", `{
		"workspace_id":"workspace-a",
		"project_id":"project-1",
		"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly"
	}`)
	if validateResp.Code != http.StatusNotFound {
		t.Fatalf("expected missing connector validate 404, got %d body=%s", validateResp.Code, validateResp.Body.String())
	}
}

func TestNormalizeAWSConnectorSetupContract(t *testing.T) {
	tests := []struct {
		name    string
		input   awsConnectorSetupInput
		want    awsConnectorSetupContract
		wantErr bool
	}{
		{
			name: "defaults legacy start to single account cloudformation",
			input: awsConnectorSetupInput{
				Region:                  "us-east-1",
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			want: awsConnectorSetupContract{
				ScopeType:        AWSConnectorScopeSingleAccount,
				DeploymentMethod: AWSConnectorDeploymentCloudFormation,
				TargetRegions:    []string{"us-east-1"},
			},
		},
		{
			name: "organization stackset with exclusions",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeOrganization,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1", "us-west-2", "us-east-1"},
				TargetOUIDs:             []string{"r-abcd"},
				ExcludedAccountIDs:      []string{"123456789012"},
				AutoOnboardNewAccounts:  true,
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			want: awsConnectorSetupContract{
				ScopeType:              AWSConnectorScopeOrganization,
				DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:          []string{"us-east-1", "us-west-2"},
				TargetOUIDs:            []string{"r-abcd"},
				ExcludedAccountIDs:     []string{"123456789012"},
				AutoOnboardNewAccounts: true,
			},
		},
		{
			name: "organization service-managed requires root target",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeOrganization,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "organization rejects selected OU target",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeOrganization,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetOUIDs:             []string{"ou-abcd-12345678"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "organization rejects multiple roots",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeOrganization,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetOUIDs:             []string{"r-abcd", "r-efgh"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "organization rejects account filters",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeOrganization,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetOUIDs:             []string{"r-abcd"},
				TargetAccountIDs:        []string{"111122223333"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "selected OUs requires OU ids",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedOUs,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "selected OUs reject account filters",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedOUs,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetOUIDs:             []string{"ou-abcd-12345678"},
				TargetAccountIDs:        []string{"111122223333"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "selected OUs reject organization root target",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedOUs,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetOUIDs:             []string{"r-abcd"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "service-managed selected accounts require root or OU context",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetAccountIDs:        []string{"111122223333"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "selected accounts require effective account target after exclusions",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetAccountIDs:        []string{"111122223333"},
				TargetOUIDs:             []string{"r-abcd"},
				ExcludedAccountIDs:      []string{"111122223333"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "service-managed selected accounts reject auto onboarding",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetAccountIDs:        []string{"111122223333"},
				TargetOUIDs:             []string{"r-abcd"},
				AutoOnboardNewAccounts:  true,
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "self-managed selected accounts reject auto onboarding",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetSelfManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetAccountIDs:        []string{"111122223333"},
				AutoOnboardNewAccounts:  true,
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "service-managed selected accounts accepts account filters with root target",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetAccountIDs:        []string{"111122223333", "111122223333"},
				TargetOUIDs:             []string{"r-abcd"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			want: awsConnectorSetupContract{
				ScopeType:        AWSConnectorScopeSelectedAccounts,
				DeploymentMethod: AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:    []string{"us-east-1"},
				TargetAccountIDs: []string{"111122223333"},
				TargetOUIDs:      []string{"r-abcd"},
			},
		},
		{
			name: "set-valued account and OU targets are canonicalized",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-west-2", "us-east-1"},
				TargetAccountIDs:        []string{"444455556666", "111122223333", "444455556666"},
				TargetOUIDs:             []string{"ou-abcd-87654321", "r-abcd", "ou-abcd-87654321"},
				ExcludedAccountIDs:      []string{"444455556666", "444455556666"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			want: awsConnectorSetupContract{
				ScopeType:          AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:   AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:      []string{"us-west-2", "us-east-1"},
				TargetAccountIDs:   []string{"111122223333", "444455556666"},
				TargetOUIDs:        []string{"ou-abcd-87654321", "r-abcd"},
				ExcludedAccountIDs: []string{"444455556666"},
			},
		},
		{
			name: "self-managed selected accounts accepts account ids",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetSelfManaged,
				TargetRegions:           []string{"us-gov-west-1"},
				TargetAccountIDs:        []string{"111122223333", "111122223333"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			want: awsConnectorSetupContract{
				ScopeType:        AWSConnectorScopeSelectedAccounts,
				DeploymentMethod: AWSConnectorDeploymentStackSetSelfManaged,
				TargetRegions:    []string{"us-gov-west-1"},
				TargetAccountIDs: []string{"111122223333"},
			},
		},
		{
			name: "manual role must use manual deployment",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeManualRole,
				DeploymentMethod:        AWSConnectorDeploymentCloudFormation,
				Region:                  "us-east-1",
				DefaultScopeType:        AWSConnectorScopeManualRole,
				DefaultDeploymentMethod: AWSConnectorDeploymentManual,
			},
			wantErr: true,
		},
		{
			name: "organization must use stackset deployment",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeOrganization,
				DeploymentMethod:        AWSConnectorDeploymentTerraform,
				TargetRegions:           []string{"us-east-1"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "stackset requires a target region",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeOrganization,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "rejects malformed account ids",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetAccountIDs:        []string{"123"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "rejects malformed ou ids",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedOUs,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:           []string{"us-east-1"},
				TargetOUIDs:             []string{"ou-invalid"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "rejects malformed regions",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSingleAccount,
				DeploymentMethod:        AWSConnectorDeploymentCloudFormation,
				TargetRegions:           []string{"not-a-region"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "rejects single account target account ids",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSingleAccount,
				DeploymentMethod:        AWSConnectorDeploymentCloudFormation,
				TargetRegions:           []string{"us-east-1"},
				TargetAccountIDs:        []string{"123456789012"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
		{
			name: "rejects malformed region even when target regions are present",
			input: awsConnectorSetupInput{
				ScopeType:               AWSConnectorScopeSelectedAccounts,
				DeploymentMethod:        AWSConnectorDeploymentStackSetServiceManaged,
				Region:                  "not-a-region",
				TargetRegions:           []string{"us-east-1"},
				TargetAccountIDs:        []string{"123456789012"},
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAWSConnectorSetupContract(tt.input)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidAWSConnectionRequest) {
					t.Fatalf("expected invalid setup error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalize setup: %v", err)
			}
			if got.ScopeType != tt.want.ScopeType || got.DeploymentMethod != tt.want.DeploymentMethod ||
				!slices.Equal(got.TargetRegions, tt.want.TargetRegions) ||
				!slices.Equal(got.TargetAccountIDs, tt.want.TargetAccountIDs) ||
				!slices.Equal(got.TargetOUIDs, tt.want.TargetOUIDs) ||
				!slices.Equal(got.ExcludedAccountIDs, tt.want.ExcludedAccountIDs) ||
				got.AutoOnboardNewAccounts != tt.want.AutoOnboardNewAccounts {
				t.Fatalf("unexpected setup contract\n got: %+v\nwant: %+v", got, tt.want)
			}
		})
	}
}

func TestAWSConnectorServiceErrorPaths(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = &fakeAWSConnectorValidator{}
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{9}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc.ConnectorSecretManager = manager

	if _, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{}); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected invalid start request, got %v", err)
	}
	if _, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{ProjectID: "project-1"}); !errors.Is(err, ErrAWSConnectorConfigUnavailable) {
		t.Fatalf("expected missing template config error, got %v", err)
	}
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	if _, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{ProjectID: "project-1"}); !errors.Is(err, ErrAWSConnectorConfigUnavailable) {
		t.Fatalf("expected missing account config error, got %v", err)
	}
	svc.AWSAccountID = "999999999999"
	if _, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{ProjectID: "missing"}); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected missing project error, got %v", err)
	}
	started, err := svc.StartAWSConnector(ctx, AWSConnectorStartRequest{ProjectID: "project-1"})
	if err != nil {
		t.Fatalf("start connector for validation error checks: %v", err)
	}

	if _, err := svc.ValidateAWSConnector(ctx, started.ConnectorID, AWSConnectorValidateRequest{ProjectID: "project-1"}); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected invalid validate request, got %v", err)
	}
	if _, err := svc.ValidateAWSConnector(ctx, "missing", AWSConnectorValidateRequest{
		ProjectID: "project-1",
		RoleARN:   "arn:aws:iam::123456789012:role/IdentrailReadOnly",
	}); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected missing connector validate error, got %v", err)
	}
	if _, err := svc.PollAWSConnector(ctx, "missing", AWSConnectorPollRequest{}); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected invalid poll request, got %v", err)
	}
	if _, err := svc.PollAWSConnector(ctx, "missing", AWSConnectorPollRequest{ProjectID: "project-1"}); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected missing connector poll error, got %v", err)
	}
	if _, err := svc.AWSConnectorPolicy(ctx, "missing", AWSConnectorPollRequest{ProjectID: "project-1"}); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected missing connector policy error, got %v", err)
	}
	policy, err := svc.AWSConnectorPolicy(ctx, "", AWSConnectorPollRequest{})
	if err != nil {
		t.Fatalf("expected policy response without connector id: %v", err)
	}
	if policy.PolicyHash == "" || len(policy.PolicyDocument) == 0 || len(policy.PermissionPreview) == 0 {
		t.Fatalf("expected complete policy response, got %+v", policy)
	}
}

func TestAWSMetadataHelpers(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	metadata := map[string]any{
		"string":             "  value  ",
		"stringer":           42,
		"bool":               true,
		"bool_string":        " TRUE ",
		"time":               now.Format(time.RFC3339Nano),
		"permission_checks":  []map[string]any{{"name": "iam:ListRoles", "passed": true, "message": "ok"}},
		"diagnostics":        []map[string]any{{"code": "aws_access_denied", "message": "denied"}},
		"invalid_structured": make(chan struct{}),
	}

	if got := firstNonEmptyAWSValue("", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback first non-empty value, got %q", got)
	}
	if got := firstNonEmptyAWSValue("", ""); got != "" {
		t.Fatalf("expected empty first non-empty value, got %q", got)
	}
	if got := awsMetadataString(metadata, "string"); got != "value" {
		t.Fatalf("expected trimmed metadata string, got %q", got)
	}
	if got := awsMetadataString(metadata, "stringer"); got != "42" {
		t.Fatalf("expected formatted metadata value, got %q", got)
	}
	if got := awsMetadataString(nil, "missing"); got != "" {
		t.Fatalf("expected empty missing metadata string, got %q", got)
	}
	if !awsMetadataBool(metadata, "bool") || !awsMetadataBool(metadata, "bool_string") {
		t.Fatalf("expected bool metadata to parse true")
	}
	if awsMetadataBool(metadata, "string") || awsMetadataBool(nil, "bool") {
		t.Fatalf("expected non-bool metadata to parse false")
	}
	if got := awsMetadataTime(metadata, "time"); got == nil || !got.Equal(now) {
		t.Fatalf("expected parsed metadata time, got %v", got)
	}
	if got := awsMetadataTime(map[string]any{"time": "not-a-time"}, "time"); got != nil {
		t.Fatalf("expected invalid metadata time to return nil, got %v", got)
	}
	if checks := awsMetadataPermissionChecks(metadata, "permission_checks"); len(checks) != 1 || checks[0].Name != "iam:ListRoles" {
		t.Fatalf("expected metadata permission checks, got %+v", checks)
	}
	if checks := awsMetadataPermissionChecks(metadata, "invalid_structured"); len(checks) != 0 {
		t.Fatalf("expected invalid permission checks to return empty, got %+v", checks)
	}
	if diagnostics := awsMetadataDiagnostics(metadata, "diagnostics"); len(diagnostics) != 1 || diagnostics[0].Code != "aws_access_denied" {
		t.Fatalf("expected metadata diagnostics, got %+v", diagnostics)
	}
	if diagnostics := awsMetadataDiagnostics(metadata, "invalid_structured"); len(diagnostics) != 0 {
		t.Fatalf("expected invalid diagnostics to return empty, got %+v", diagnostics)
	}
	if got := accountIDFromRoleARN("arn:aws:iam::123456789012:role/IdentrailReadOnly"); got != "123456789012" {
		t.Fatalf("expected account id from role arn, got %q", got)
	}
	if got := accountIDFromRoleARN("not-an-arn"); got != "unknown" {
		t.Fatalf("expected unknown account id for invalid arn, got %q", got)
	}
}

func requireAWSStackSetPrerequisite(t *testing.T, prerequisites []AWSStackSetOnboardingPrerequisite, id string) AWSStackSetOnboardingPrerequisite {
	t.Helper()
	for _, prerequisite := range prerequisites {
		if prerequisite.ID == id {
			return prerequisite
		}
	}
	t.Fatalf("missing stackset prerequisite %q in %+v", id, prerequisites)
	return AWSStackSetOnboardingPrerequisite{}
}

func assertAWSConnectorStartPayloadNoSecretMaterial(t *testing.T, payload string) {
	t.Helper()
	lower := strings.ToLower(payload)
	for _, forbidden := range []string{"getsecretvalue", "secretstring", "aws_secret_access_key", "aws_access_key_id", "secretaccesskey", "plaintext"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("connector start payload leaked secret-like content %q in %s", forbidden, payload)
		}
	}
}

func newAWSConnectionTestRouter(t *testing.T, validator AWSConnectorValidator) ginEngineForTest {
	t.Helper()
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = validator
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
	})
	_ = doAWSConnectionAPI(t, r, http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	projectResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	if projectResp.Code != http.StatusOK {
		t.Fatalf("seed project failed: %d body=%s", projectResp.Code, projectResp.Body.String())
	}
	return r
}

func newAWSConnectorFlowTestRouter(t *testing.T, validator AWSConnectorValidator) ginEngineForTest {
	t.Helper()
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.AWSConnectorValidator = validator
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{8}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc.ConnectorSecretManager = manager
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:             []string{"writer-key"},
		WriteAPIKeys:        []string{"writer-key"},
		DefaultTenantID:     "tenant-a",
		DefaultWorkspaceID:  "workspace-a",
		FeatureConnectorAWS: true,
	})
	_ = doAWSConnectionAPI(t, r, http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	projectResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	if projectResp.Code != http.StatusOK {
		t.Fatalf("seed project failed: %d body=%s", projectResp.Code, projectResp.Body.String())
	}
	return r
}

type ginEngineForTest interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}

func doAWSConnectionAPI(t *testing.T, r ginEngineForTest, method string, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody *bytes.Buffer
	if body == "" {
		requestBody = bytes.NewBuffer(nil)
	} else {
		requestBody = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, path, requestBody)
	req.Header.Set("X-API-Key", "writer-key")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
