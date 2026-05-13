package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	if startBody.Connection.Status != domain.ConnectorStatusPending || !startBody.Connection.ExternalIDConfigured {
		t.Fatalf("expected pending connector with external id configured, got %+v", startBody.Connection)
	}

	pollResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/connectors/aws/"+startBody.ConnectorID+"/poll?workspace_id=workspace-a&project_id=project-1", "")
	if pollResp.Code != http.StatusOK {
		t.Fatalf("expected connector poll 200, got %d body=%s", pollResp.Code, pollResp.Body.String())
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
