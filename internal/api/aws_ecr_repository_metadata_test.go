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

func TestGetAWSECRRepositoryMetadataInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 18, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSECRRepositoryMetadataInventory(ctx, "default", "project-a", AWSECRRepositoryMetadataInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get ecr repository metadata: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.CurrentIssueRef != "#1492" || result.Version != awsECRRepositoryMetadataVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.RepositoryCount != 3 || result.RelationshipCount != 2 || result.UnresolvedReferenceCount != 1 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if result.ReferencedRepositoryCount != 2 || result.MutableRepositoryCount != 2 || result.UnscannedRepositoryCount != 2 || result.RepositoryPolicyCount != 1 {
		t.Fatalf("expected referenced/mutable/unscanned/policy counts, got %+v", result)
	}
	for _, record := range result.Records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		lower := strings.ToLower(string(payload))
		for _, forbidden := range []string{"batchgetimage", "getdownloadurlforlayer", "image_manifest", "layer_digest", "authorizationtoken"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("image payload evidence leaked into API response: %s", payload)
			}
		}
	}
}

func TestGetAWSECRRepositoryMetadataInventoryFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 18, 45, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	byRepository, err := svc.GetAWSECRRepositoryMetadataInventory(ctx, "default", "project-a", AWSECRRepositoryMetadataInventoryRequest{ConnectorID: "aws-prod", RepositoryName: "payments/jobs"})
	if err != nil {
		t.Fatalf("get repository-filtered inventory: %v", err)
	}
	if byRepository.RepositoryCount != 1 || byRepository.Records[0].RepositoryName != "payments/jobs" {
		t.Fatalf("expected payments/jobs only, got %+v", byRepository)
	}

	byIdentity, err := svc.GetAWSECRRepositoryMetadataInventory(ctx, "default", "project-a", AWSECRRepositoryMetadataInventoryRequest{ConnectorID: "aws-prod", Identity: "payments-build"})
	if err != nil {
		t.Fatalf("get identity-filtered inventory: %v", err)
	}
	if byIdentity.RepositoryCount != 1 || byIdentity.Records[0].RepositoryName != "payments/jobs" {
		t.Fatalf("expected repository referenced by payments-build, got %+v", byIdentity)
	}
}

func TestGetAWSECRRepositoryMetadataInventoryDegradedAndPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 19, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	degraded, err := svc.GetAWSECRRepositoryMetadataInventory(ctx, "default", "project-a", AWSECRRepositoryMetadataInventoryRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get degraded inventory: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded diagnostics, got %+v", degraded)
	}

	denied, err := svc.GetAWSECRRepositoryMetadataInventory(ctx, "default", "project-a", AWSECRRepositoryMetadataInventoryRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get denied inventory: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked || denied.RepositoryCount != 0 || len(denied.Diagnostics) == 0 {
		t.Fatalf("expected blocked permission-denied inventory, got %+v", denied)
	}
	for _, hint := range denied.RemediationHints {
		lower := strings.ToLower(hint)
		if strings.Contains(lower, "batchgetimage") || strings.Contains(lower, "getdownloadurlforlayer") {
			t.Fatalf("remediation must never suggest image payload permissions: %q", hint)
		}
	}
}

func TestRouterAWSECRRepositoryMetadataPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 19, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/ecr-repository-metadata?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSECRRepositoryMetadataInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.RepositoryCount == 0 {
		t.Fatalf("expected degraded partial records, got %+v", body.Inventory)
	}
	foundDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "ecr_repository_metadata_page_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected page-failure diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSECRRepositoryMetadataInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 19, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/ecr-repository-metadata?connector_id=aws-prod&fixture_state=bogus", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}
