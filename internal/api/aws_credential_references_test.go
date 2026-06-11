package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSCredentialReferencesInventoryClassifiesProviders(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 18, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSCredentialReferencesInventory(ctx, "default", "project-a", AWSCredentialReferencesInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get credential references: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.CurrentIssueRef != "#1496" || result.Version != awsCredentialReferencesVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.ReferenceCount != 5 || result.ResolvedReferenceCount != 1 || result.UnresolvedReferenceCount != 4 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if result.AIProviderKeyCount != 2 || result.DatabaseCredentialCount != 1 || result.ExternalProviderKeyCount != 5 {
		t.Fatalf("expected provider classification counts, got %+v", result)
	}
	if result.ProviderBreakdown[credentialProviderOpenAI] != 1 || result.ProviderBreakdown[credentialProviderGitHub] != 1 {
		t.Fatalf("expected provider breakdown, got %+v", result.ProviderBreakdown)
	}
	// Every record must be reference-only; no values may appear.
	for _, record := range result.Records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		lower := strings.ToLower(string(payload))
		for _, forbidden := range []string{"getsecretvalue", "getparameter", "secretstring", "=sk-", "plaintext_value"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("value-like content leaked into record: %s", payload)
			}
		}
	}
}

func TestGetAWSCredentialReferencesInventoryFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 18, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	openai, err := svc.GetAWSCredentialReferencesInventory(ctx, "default", "project-a", AWSCredentialReferencesInventoryRequest{ConnectorID: "aws-prod", Provider: "openai"})
	if err != nil {
		t.Fatalf("get provider-filtered inventory: %v", err)
	}
	if openai.ReferenceCount != 1 || openai.ProviderBreakdown[credentialProviderOpenAI] != 1 {
		t.Fatalf("expected one openai reference, got %+v", openai)
	}

	byType, err := svc.GetAWSCredentialReferencesInventory(ctx, "default", "project-a", AWSCredentialReferencesInventoryRequest{ConnectorID: "aws-prod", ResourceType: "codebuild_project"})
	if err != nil {
		t.Fatalf("get resource-type-filtered inventory: %v", err)
	}
	if byType.ReferenceCount != 2 {
		t.Fatalf("expected two codebuild references, got %+v", byType)
	}

	byIdentity, err := svc.GetAWSCredentialReferencesInventory(ctx, "default", "project-a", AWSCredentialReferencesInventoryRequest{ConnectorID: "aws-prod", Identity: "summarizer"})
	if err != nil {
		t.Fatalf("get identity-filtered inventory: %v", err)
	}
	if byIdentity.ReferenceCount != 1 {
		t.Fatalf("expected one summarizer reference, got %+v", byIdentity)
	}

	if _, err := svc.GetAWSCredentialReferencesInventory(ctx, "default", "project-a", AWSCredentialReferencesInventoryRequest{ConnectorID: "aws-prod", Provider: "bogus"}); err == nil {
		t.Fatalf("expected invalid provider filter error")
	}
}

func TestGetAWSCredentialReferencesInventoryDegradedAndPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 18, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	degraded, err := svc.GetAWSCredentialReferencesInventory(ctx, "default", "project-a", AWSCredentialReferencesInventoryRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get degraded inventory: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded diagnostics, got %+v", degraded)
	}

	denied, err := svc.GetAWSCredentialReferencesInventory(ctx, "default", "project-a", AWSCredentialReferencesInventoryRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get denied inventory: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked || denied.ReferenceCount != 0 || len(denied.Diagnostics) == 0 {
		t.Fatalf("expected blocked permission-denied inventory, got %+v", denied)
	}
}

func TestRouterAWSCredentialReferencesPartialFailureAndInvalid(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 19, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/credential-references?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSCredentialReferencesInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.ReferenceCount == 0 {
		t.Fatalf("expected degraded partial records, got %+v", body.Inventory)
	}

	for _, query := range []string{"fixture_state=bogus", "provider=bogus"} {
		bad := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/credential-references?connector_id=aws-prod&"+query, "")
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d body=%s", query, bad.Code, bad.Body.String())
		}
	}
}
