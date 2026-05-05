package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestRouterWhoAmIScopeUsesOIDCClaimsOverScopeHeaders(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	scopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	if err := store.UpsertOrganization(scopeCtx, db.TenancyOrganization{
		TenantID:    "tenant-a",
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopeCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if err := store.UpsertWorkspaceMember(scopeCtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "user-1",
		Role:        "admin",
		Status:      "active",
	}); err != nil {
		t.Fatalf("seed workspace member: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"user-1-token": {
					Subject:     "user-1",
					TenantID:    "tenant-a",
					WorkspaceID: "workspace-a",
					Scopes:      []string{"identrail.read"},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer user-1-token")
	req.Header.Set(scopeHeaderTenantID, "tenant-b")
	req.Header.Set(scopeHeaderWorkspaceID, "workspace-b")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected whoami 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Scope struct {
			TenantID    string `json:"tenant_id"`
			WorkspaceID string `json:"workspace_id"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode whoami response: %v", err)
	}
	if body.Scope.TenantID != "tenant-a" || body.Scope.WorkspaceID != "workspace-a" {
		t.Fatalf("expected scope from oidc claims, got %+v", body.Scope)
	}
}
