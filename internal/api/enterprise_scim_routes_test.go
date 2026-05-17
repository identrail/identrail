package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/identrail/identrail/internal/workflow"
	"go.uber.org/zap"
)

func newSCIMTestRouter(t *testing.T, enabled bool) (*gin.Engine, *db.MemoryStore, db.IdentityConnection, string) {
	return newSCIMTestRouterWithService(t, enabled, nil)
}

func newSCIMTestRouterWithService(t *testing.T, enabled bool, configure func(*Service)) (*gin.Engine, *db.MemoryStore, db.IdentityConnection, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(ctx, db.TenancyOrganization{DisplayName: "Tenant A", Slug: "tenant-a"}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	token := "idntr_scim_test_token"
	conn, err := store.CreateIdentityConnection(ctx, db.IdentityConnection{
		OrgID:               "tenant-a",
		Provider:            "saml",
		Type:                "directory_sync",
		Status:              "active",
		EntityID:            "https://idp.example.com/entity",
		SSOURL:              "https://idp.example.com/sso",
		CertificatePEM:      generateTestCertPEM(t),
		AttributeMapping:    map[string]string{"email": "email"},
		SCIMBearerTokenHash: HashSCIMBearerToken(token),
	})
	if err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	if configure != nil {
		configure(svc)
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{
		FeatureNativeSSO: enabled,
		PublicBaseURL:    "https://api.example.com",
		RateLimitRPM:     10000,
		RateLimitBurst:   1000,
	})
	return router, store, conn, token
}

type recordingWorkflowDestination struct {
	name  string
	calls int
	event workflow.Event
	err   error
}

func (d *recordingWorkflowDestination) Name() string { return d.name }

func (d *recordingWorkflowDestination) Send(_ context.Context, event workflow.Event) error {
	d.calls++
	d.event = event
	return d.err
}

func doSCIM(t *testing.T, router *gin.Engine, token string, method string, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", scimContentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestEnterpriseSCIMRoutes_DisabledAndUnauthorized(t *testing.T) {
	router, _, _, token := newSCIMTestRouter(t, false)
	w := doSCIM(t, router, token, http.MethodGet, "/scim/v2/ServiceProviderConfig", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled routes should be 404, got %d body %s", w.Code, w.Body.String())
	}

	router, _, _, _ = newSCIMTestRouter(t, true)
	w = doSCIM(t, router, "", http.MethodGet, "/scim/v2/ServiceProviderConfig", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer should be 401, got %d body %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatalf("missing WWW-Authenticate header")
	}
	w = doSCIM(t, router, "wrong-token", http.MethodGet, "/scim/v2/ServiceProviderConfig", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad bearer should be 401, got %d body %s", w.Code, w.Body.String())
	}
}

func TestEnterpriseSCIMRoutes_DefaultsOmittedActiveToEnabled(t *testing.T) {
	router, store, _, token := newSCIMTestRouter(t, true)
	createBody := `{
		"userName":"default-active@example.com",
		"displayName":"Default Active",
		"emails":[{"value":"default-active@example.com","type":"work","primary":true}]
	}`
	created := doSCIM(t, router, token, http.MethodPost, "/scim/v2/Users", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create without active: code %d body %s", created.Code, created.Body.String())
	}
	var response struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Active {
		t.Fatalf("omitted active should default to true")
	}
	user, err := store.GetUser(context.Background(), response.ID)
	if err != nil {
		t.Fatalf("get created user: %v", err)
	}
	if user.Status != "active" {
		t.Fatalf("omitted active should persist active user, got %q", user.Status)
	}
}

func TestEnterpriseSCIMRoutes_CreateDispatchesWorkflowEvent(t *testing.T) {
	destination := &recordingWorkflowDestination{name: "test-workflow"}
	auditLog := &bytes.Buffer{}
	dispatchTime := time.Date(2026, 5, 17, 14, 0, 0, 0, time.UTC)
	router, _, conn, token := newSCIMTestRouterWithService(t, true, func(svc *Service) {
		svc.Now = func() time.Time { return dispatchTime }
		svc.WorkflowRouter = &workflow.Router{
			Destinations: []workflow.RoutedDestination{{Destination: destination, Policy: workflow.AlertPolicy{}}},
			Audit:        &workflow.JSONLineAuditSink{Writer: auditLog},
			Now:          func() time.Time { return dispatchTime },
		}
	})
	createBody := `{
		"userName":"workflow-user@example.com",
		"displayName":"Workflow User",
		"active":true,
		"emails":[{"value":"workflow-user@example.com","type":"work","primary":true}]
	}`
	created := doSCIM(t, router, token, http.MethodPost, "/scim/v2/Users", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: code %d body %s", created.Code, created.Body.String())
	}
	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if destination.calls != 1 {
		t.Fatalf("workflow destination calls: want 1, got %d", destination.calls)
	}
	if destination.event.Kind != workflow.EventSCIMProvisioned {
		t.Fatalf("unexpected workflow kind: %s", destination.event.Kind)
	}
	if destination.event.SCIMProvisioning == nil {
		t.Fatal("missing scim workflow payload")
	}
	if got := destination.event.SCIMProvisioning; got.Operation != "create" || got.UserID != response.ID || got.UserName != "workflow-user@example.com" || got.ConnectionID != conn.ID {
		t.Fatalf("unexpected scim workflow payload: %+v", got)
	}
	lines := strings.Split(strings.TrimSpace(auditLog.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("workflow audit lines: want 1, got %d (%q)", len(lines), auditLog.String())
	}
	var record workflow.DispatchRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("decode workflow audit record: %v", err)
	}
	if record.EventKind != workflow.EventSCIMProvisioned || record.SubjectID != response.ID || record.ConnectionID != conn.ID || record.SCIMOp != "create" || !record.Success {
		t.Fatalf("unexpected workflow audit record: %+v", record)
	}
}

func TestEnterpriseSCIMRoutes_WorkflowDispatchFailureDoesNotFailCreate(t *testing.T) {
	destination := &recordingWorkflowDestination{name: "test-workflow", err: errors.New("workflow unavailable")}
	auditLog := &bytes.Buffer{}
	router, _, conn, token := newSCIMTestRouterWithService(t, true, func(svc *Service) {
		svc.WorkflowRouter = &workflow.Router{
			Destinations: []workflow.RoutedDestination{{Destination: destination, Policy: workflow.AlertPolicy{}}},
			Audit:        &workflow.JSONLineAuditSink{Writer: auditLog},
		}
	})
	createBody := `{
		"userName":"workflow-failure@example.com",
		"displayName":"Workflow Failure",
		"active":true,
		"emails":[{"value":"workflow-failure@example.com","type":"work","primary":true}]
	}`
	created := doSCIM(t, router, token, http.MethodPost, "/scim/v2/Users", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("workflow dispatch failure should not fail persisted SCIM create, got %d body %s", created.Code, created.Body.String())
	}
	if destination.calls != 1 {
		t.Fatalf("workflow destination calls: want 1, got %d", destination.calls)
	}
	lines := strings.Split(strings.TrimSpace(auditLog.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("workflow audit lines: want 1, got %d (%q)", len(lines), auditLog.String())
	}
	var record workflow.DispatchRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("decode workflow audit record: %v", err)
	}
	if record.EventKind != workflow.EventSCIMProvisioned || record.ConnectionID != conn.ID || record.SCIMOp != "create" || record.Success || !strings.Contains(record.Error, "workflow unavailable") {
		t.Fatalf("unexpected workflow failure audit record: %+v", record)
	}
}

func TestEnterpriseSCIMRoutes_SingleResourceLookupUsesDirectUserIDLookup(t *testing.T) {
	router, store, conn, token := newSCIMTestRouter(t, true)
	ctx := context.Background()
	baseTime := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	const historicalListLimit = 10000
	targetID := "11111111-1111-1111-1111-111111111111"
	if _, err := store.UpsertUser(ctx, db.User{
		ID:           targetID,
		PrimaryEmail: "oldest@example.com",
		DisplayName:  "Oldest User",
		Status:       "active",
		CreatedAt:    baseTime,
		UpdatedAt:    baseTime,
	}); err != nil {
		t.Fatalf("seed target user: %v", err)
	}
	if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
		ID:                  "22222222-2222-2222-2222-222222222222",
		UserID:              targetID,
		Provider:            "scim:" + conn.ID,
		Subject:             "oldest@example.com",
		Email:               "oldest@example.com",
		EmailVerified:       true,
		RawClaims:           []byte(`{"userName":"oldest@example.com","active":true,"emails":[{"value":"oldest@example.com","primary":true}]}`),
		LastAuthenticatedAt: baseTime,
		CreatedAt:           baseTime,
	}); err != nil {
		t.Fatalf("seed target identity: %v", err)
	}
	for i := 0; i < historicalListLimit; i++ {
		userID := uuid.NewString()
		email := fmt.Sprintf("bulk-%05d@example.com", i)
		createdAt := baseTime.Add(time.Duration(i+1) * time.Second)
		if _, err := store.UpsertUser(ctx, db.User{
			ID:           userID,
			PrimaryEmail: email,
			DisplayName:  email,
			Status:       "active",
			CreatedAt:    createdAt,
			UpdatedAt:    createdAt,
		}); err != nil {
			t.Fatalf("seed bulk user %d: %v", i, err)
		}
		if _, err := store.UpsertUserIdentity(ctx, db.UserIdentity{
			UserID:              userID,
			Provider:            "scim:" + conn.ID,
			Subject:             email,
			Email:               email,
			EmailVerified:       true,
			RawClaims:           []byte(fmt.Sprintf(`{"userName":%q,"active":true,"emails":[{"value":%q,"primary":true}]}`, email, email)),
			LastAuthenticatedAt: createdAt,
			CreatedAt:           createdAt,
		}); err != nil {
			t.Fatalf("seed bulk identity %d: %v", i, err)
		}
	}

	got := doSCIM(t, router, token, http.MethodGet, "/scim/v2/Users/"+targetID, "")
	if got.Code != http.StatusOK {
		t.Fatalf("oldest user should remain addressable beyond list scan limit, got %d body %s", got.Code, got.Body.String())
	}
	filtered := doSCIM(t, router, token, http.MethodGet, `/scim/v2/Users?filter=userName%20eq%20%22oldest@example.com%22`, "")
	if filtered.Code != http.StatusOK {
		t.Fatalf("oldest user filter should bypass list scan limit, got %d body %s", filtered.Code, filtered.Body.String())
	}
	var filteredBody struct {
		TotalResults int `json:"totalResults"`
		Resources    []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(filtered.Body.Bytes(), &filteredBody); err != nil {
		t.Fatalf("decode filtered oldest response: %v", err)
	}
	if filteredBody.TotalResults != 1 || len(filteredBody.Resources) != 1 || filteredBody.Resources[0].ID != targetID {
		t.Fatalf("unexpected filtered oldest response: %+v", filteredBody)
	}
	paged := doSCIM(t, router, token, http.MethodGet, fmt.Sprintf("/scim/v2/Users?startIndex=%d&count=1", historicalListLimit+1), "")
	if paged.Code != http.StatusOK {
		t.Fatalf("oldest user page should not be truncated, got %d body %s", paged.Code, paged.Body.String())
	}
	var pagedBody struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(paged.Body.Bytes(), &pagedBody); err != nil {
		t.Fatalf("decode paged oldest response: %v", err)
	}
	if len(pagedBody.Resources) != 1 || pagedBody.Resources[0].ID != targetID {
		t.Fatalf("unexpected paged oldest response: %+v", pagedBody)
	}
}

func TestEnterpriseSCIMRoutes_UserLifecycle(t *testing.T) {
	router, store, conn, token := newSCIMTestRouter(t, true)

	discovery := doSCIM(t, router, token, http.MethodGet, "/scim/v2/ServiceProviderConfig", "")
	if discovery.Code != http.StatusOK {
		t.Fatalf("discovery: code %d body %s", discovery.Code, discovery.Body.String())
	}
	for _, path := range []string{"/scim/v2/Schemas", "/scim/v2/ResourceTypes"} {
		w := doSCIM(t, router, token, http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: code %d body %s", path, w.Code, w.Body.String())
		}
	}

	createBody := `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"alice@example.com",
		"displayName":"Alice Adams",
		"active":true,
		"emails":[{"value":"alice@example.com","type":"work","primary":true}]
	}`
	created := doSCIM(t, router, token, http.MethodPost, "/scim/v2/Users", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: code %d body %s", created.Code, created.Body.String())
	}
	var createdBody struct {
		ID       string `json:"id"`
		UserName string `json:"userName"`
		Meta     struct {
			Location string `json:"location"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createdBody.ID == "" || createdBody.UserName != "alice@example.com" {
		t.Fatalf("unexpected create response: %+v", createdBody)
	}
	if createdBody.Meta.Location != "https://api.example.com/scim/v2/Users/"+createdBody.ID {
		t.Fatalf("unexpected location %q", createdBody.Meta.Location)
	}
	invalidCreate := doSCIM(t, router, token, http.MethodPost, "/scim/v2/Users", `{"userName":"missing-email@example.com","active":true}`)
	if invalidCreate.Code != http.StatusBadRequest {
		t.Fatalf("invalid create should be 400, got %d body %s", invalidCreate.Code, invalidCreate.Body.String())
	}
	duplicate := doSCIM(t, router, token, http.MethodPost, "/scim/v2/Users", createBody)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate create should be 409, got %d body %s", duplicate.Code, duplicate.Body.String())
	}

	filtered := doSCIM(t, router, token, http.MethodGet, `/scim/v2/Users?filter=userName%20eq%20%22alice@example.com%22&startIndex=1&count=1`, "")
	if filtered.Code != http.StatusOK {
		t.Fatalf("filter: code %d body %s", filtered.Code, filtered.Body.String())
	}
	badFilter := doSCIM(t, router, token, http.MethodGet, `/scim/v2/Users?filter=emails.value%20eq%20%22alice@example.com%22`, "")
	if badFilter.Code != http.StatusBadRequest {
		t.Fatalf("bad filter should be 400, got %d body %s", badFilter.Code, badFilter.Body.String())
	}
	var listBody struct {
		TotalResults int `json:"totalResults"`
		Resources    []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(filtered.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode filter response: %v", err)
	}
	if listBody.TotalResults != 1 || len(listBody.Resources) != 1 || listBody.Resources[0].ID != createdBody.ID {
		t.Fatalf("unexpected filter response: %+v", listBody)
	}
	got := doSCIM(t, router, token, http.MethodGet, "/scim/v2/Users/"+createdBody.ID, "")
	if got.Code != http.StatusOK {
		t.Fatalf("get: code %d body %s", got.Code, got.Body.String())
	}
	missing := doSCIM(t, router, token, http.MethodGet, "/scim/v2/Users/00000000-0000-0000-0000-000000000000", "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing get should be 404, got %d body %s", missing.Code, missing.Body.String())
	}

	putBody := `{
		"userName":"alice.renamed@example.com",
		"displayName":"Alice Renamed",
		"active":true,
		"emails":[{"value":"alice.renamed@example.com","type":"work","primary":true}]
	}`
	updated := doSCIM(t, router, token, http.MethodPut, "/scim/v2/Users/"+createdBody.ID, putBody)
	if updated.Code != http.StatusOK {
		t.Fatalf("put: code %d body %s", updated.Code, updated.Body.String())
	}
	oldFilter := doSCIM(t, router, token, http.MethodGet, `/scim/v2/Users?filter=userName%20eq%20%22alice@example.com%22`, "")
	if oldFilter.Code != http.StatusOK {
		t.Fatalf("old filter: code %d body %s", oldFilter.Code, oldFilter.Body.String())
	}
	var oldList struct {
		TotalResults int `json:"totalResults"`
	}
	if err := json.Unmarshal(oldFilter.Body.Bytes(), &oldList); err != nil {
		t.Fatalf("decode old filter response: %v", err)
	}
	if oldList.TotalResults != 0 {
		t.Fatalf("old userName should no longer resolve, got %+v", oldList)
	}

	caseOnlyBody := `{
		"userName":"Alice.Renamed@Example.com",
		"displayName":"Alice Renamed",
		"active":true,
		"emails":[{"value":"alice.renamed@example.com","type":"work","primary":true}]
	}`
	caseOnlyUpdated := doSCIM(t, router, token, http.MethodPut, "/scim/v2/Users/"+createdBody.ID, caseOnlyBody)
	if caseOnlyUpdated.Code != http.StatusOK {
		t.Fatalf("case-only put: code %d body %s", caseOnlyUpdated.Code, caseOnlyUpdated.Body.String())
	}
	if _, err := store.GetUserIdentity(context.Background(), "scim:"+conn.ID, "Alice.Renamed@Example.com"); err != nil {
		t.Fatalf("case-only subject should be stored exactly: %v", err)
	}
	if _, err := store.GetUserIdentity(context.Background(), "scim:"+conn.ID, "alice.renamed@example.com"); err == nil {
		t.Fatalf("old case subject should be removed")
	}

	objectPatchBody := `{"schemas":["` + scimPatchOpSchema + `"],"Operations":[{"op":"replace","value":{"displayName":"Alice Patched","active":true}}]}`
	objectPatched := doSCIM(t, router, token, http.MethodPatch, "/scim/v2/Users/"+createdBody.ID, objectPatchBody)
	if objectPatched.Code != http.StatusOK {
		t.Fatalf("object patch: code %d body %s", objectPatched.Code, objectPatched.Body.String())
	}
	unsupportedOp := doSCIM(t, router, token, http.MethodPatch, "/scim/v2/Users/"+createdBody.ID, `{"Operations":[{"op":"add","path":"displayName","value":"Nope"}]}`)
	if unsupportedOp.Code != http.StatusBadRequest {
		t.Fatalf("unsupported op should be 400, got %d body %s", unsupportedOp.Code, unsupportedOp.Body.String())
	}
	unsupportedPath := doSCIM(t, router, token, http.MethodPatch, "/scim/v2/Users/"+createdBody.ID, `{"Operations":[{"op":"replace","path":"title","value":"Engineer"}]}`)
	if unsupportedPath.Code != http.StatusBadRequest {
		t.Fatalf("unsupported path should be 400, got %d body %s", unsupportedPath.Code, unsupportedPath.Body.String())
	}

	patchBody := `{"schemas":["` + scimPatchOpSchema + `"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	patched := doSCIM(t, router, token, http.MethodPatch, "/scim/v2/Users/"+createdBody.ID, patchBody)
	if patched.Code != http.StatusOK {
		t.Fatalf("patch: code %d body %s", patched.Code, patched.Body.String())
	}
	var patchResponse struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(patched.Body.Bytes(), &patchResponse); err != nil {
		t.Fatalf("decode patch response: %v", err)
	}
	if patchResponse.Active {
		t.Fatalf("patch should deactivate the user")
	}

	deleted := doSCIM(t, router, token, http.MethodDelete, "/scim/v2/Users/"+createdBody.ID, "")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete: code %d body %s", deleted.Code, deleted.Body.String())
	}

	events, err := store.ListSCIMProvisioningEvents(context.Background(), conn.OrgID, conn.ID, 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("expected create/update/update/update/deactivate/delete events, got %d", len(events))
	}
	if events[0].Op != "delete" || events[1].Op != "deactivate" || events[2].Op != "update" || events[3].Op != "update" || events[4].Op != "update" || events[5].Op != "create" {
		t.Fatalf("unexpected event order/ops: %+v", events)
	}
}
