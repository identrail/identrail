package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestRouterOIDCAuditSinkRedactsSensitiveAuthzIdentifiers(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	const rawToken = "super-secret-oidc-token"
	const rawSubject = "subject-sensitive-123"
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink: sink,
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				rawToken: {
					Subject:     rawSubject,
					TenantID:    "tenant-a",
					WorkspaceID: "workspace-a",
					Scopes:      []string{"read"},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans/scan-sensitive/events", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set(scopeHeaderTenantID, "header-tenant")
	req.Header.Set(scopeHeaderWorkspaceID, "header-workspace")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected audit sink event")
	}
	event := sink.events[len(sink.events)-1]
	if event.Authz == nil {
		t.Fatal("expected authz decision in audit event")
	}
	if event.Authz.Input.SubjectIDHash == "" || event.Authz.Input.SubjectIDHash == rawSubject {
		t.Fatalf("expected hashed subject id, got %+v", event.Authz.Input)
	}
	if event.Authz.Input.ResourceIDHash == "" || event.Authz.Input.ResourceIDHash == "scan-sensitive" {
		t.Fatalf("expected hashed resource id, got %+v", event.Authz.Input)
	}
	if event.APIKeyID != "" {
		t.Fatalf("expected oidc auth without api key id, got %q", event.APIKeyID)
	}

	payload, err := json.Marshal(sink.events)
	if err != nil {
		t.Fatalf("marshal audit payload: %v", err)
	}
	text := string(payload)
	if strings.Contains(text, rawToken) {
		t.Fatalf("audit payload leaked bearer token: %s", text)
	}
	if strings.Contains(text, rawSubject) {
		t.Fatalf("audit payload leaked raw subject: %s", text)
	}
}
