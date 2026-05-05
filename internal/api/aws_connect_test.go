package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
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
	if _, err := first.UpsertAWSConnection(ctx, "workspace-a", "project-1", AWSConnectionUpsertRequest{
		DisplayName: "Production AWS",
		RoleARN:     "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		ExternalID:  "tenant-external-id",
		Region:      "us-west-2",
	}); err != nil {
		t.Fatalf("upsert aws connection: %v", err)
	}

	second := NewService(store, routerScanner{}, "aws")
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
