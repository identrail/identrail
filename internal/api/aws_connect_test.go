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
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
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
	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/identrail-readonly.yaml"
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
				ExcludedAccountIDs:      []string{"123456789012"},
				AutoOnboardNewAccounts:  true,
				DefaultScopeType:        AWSConnectorScopeSingleAccount,
				DefaultDeploymentMethod: AWSConnectorDeploymentCloudFormation,
			},
			want: awsConnectorSetupContract{
				ScopeType:              AWSConnectorScopeOrganization,
				DeploymentMethod:       AWSConnectorDeploymentStackSetServiceManaged,
				TargetRegions:          []string{"us-east-1", "us-west-2"},
				ExcludedAccountIDs:     []string{"123456789012"},
				AutoOnboardNewAccounts: true,
			},
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
			name: "selected accounts accepts account ids",
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
	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/identrail-readonly.yaml"
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
	svc.AWSCloudFormationTemplateURL = "https://cdn.identrail.example/connectors/aws/identrail-readonly.yaml"
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
