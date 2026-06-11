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

func TestGetAWSSSMParameterMetadataInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSSSMParameterMetadataInventory(ctx, "default", "project-a", AWSSSMParameterMetadataInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get ssm parameter metadata: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.CurrentIssueRef != "#1491" || result.Version != awsSSMParameterMetadataVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.ParameterCount != 3 || result.RelationshipCount != 2 || result.UnresolvedReferenceCount != 1 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if result.SecureStringCount != 2 || result.CustomerKMSCount != 1 || result.PlainTextReferencedCount != 1 || result.ExpiringParameterCount != 1 {
		t.Fatalf("expected secure-string/kms/plaintext/expiring counts, got %+v", result)
	}
	for _, record := range result.Records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		lower := strings.ToLower(string(payload))
		for _, forbidden := range []string{"parameter_value", "getparameter", "secretstring"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("parameter value evidence leaked into API response: %s", payload)
			}
		}
		if record.Sensitive && record.ParameterType != "secure_string" {
			t.Fatalf("only secure strings should be sensitive, got %+v", record)
		}
	}
}

func TestGetAWSSSMParameterMetadataInventoryFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 15, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	secureOnly, err := svc.GetAWSSSMParameterMetadataInventory(ctx, "default", "project-a", AWSSSMParameterMetadataInventoryRequest{ConnectorID: "aws-prod", ParameterType: "secure_string"})
	if err != nil {
		t.Fatalf("get filtered inventory: %v", err)
	}
	if secureOnly.ParameterCount != 2 || secureOnly.SecureStringCount != 2 {
		t.Fatalf("expected two secure strings, got %+v", secureOnly)
	}

	byIdentity, err := svc.GetAWSSSMParameterMetadataInventory(ctx, "default", "project-a", AWSSSMParameterMetadataInventoryRequest{ConnectorID: "aws-prod", Identity: "payments-deployer"})
	if err != nil {
		t.Fatalf("get identity-filtered inventory: %v", err)
	}
	if byIdentity.ParameterCount != 2 {
		t.Fatalf("expected two parameters last modified by payments-deployer, got %+v", byIdentity)
	}

	if _, err := svc.GetAWSSSMParameterMetadataInventory(ctx, "default", "project-a", AWSSSMParameterMetadataInventoryRequest{ConnectorID: "aws-prod", ParameterType: "bogus"}); err == nil {
		t.Fatalf("expected invalid parameter type error")
	}
}

func TestGetAWSSSMParameterMetadataInventoryDegradedAndPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	degraded, err := svc.GetAWSSSMParameterMetadataInventory(ctx, "default", "project-a", AWSSSMParameterMetadataInventoryRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get degraded inventory: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded diagnostics, got %+v", degraded)
	}

	denied, err := svc.GetAWSSSMParameterMetadataInventory(ctx, "default", "project-a", AWSSSMParameterMetadataInventoryRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get denied inventory: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked || denied.ParameterCount != 0 || len(denied.Diagnostics) == 0 {
		t.Fatalf("expected blocked permission-denied inventory, got %+v", denied)
	}
	for _, hint := range denied.RemediationHints {
		if strings.Contains(strings.ToLower(hint), "getparameter ") {
			t.Fatalf("remediation must never suggest value-reading permissions: %q", hint)
		}
	}
}

func TestRouterAWSSSMParameterMetadataPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/ssm-parameter-metadata?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSSSMParameterMetadataInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.ParameterCount == 0 {
		t.Fatalf("expected degraded partial records, got %+v", body.Inventory)
	}
	foundDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "ssm_parameter_metadata_page_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected page-failure diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSSSMParameterMetadataInvalidRequests(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 16, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	for _, query := range []string{"fixture_state=bogus", "parameter_type=bogus"} {
		resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/ssm-parameter-metadata?connector_id=aws-prod&"+query, "")
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d body=%s", query, resp.Code, resp.Body.String())
		}
	}
}
