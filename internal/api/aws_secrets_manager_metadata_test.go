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

func TestGetAWSSecretsManagerMetadataInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSSecretsManagerMetadataInventory(ctx, "default", "project-a", AWSSecretsManagerMetadataInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get secrets manager metadata: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.CurrentIssueRef != "#1490" || result.Version != awsSecretsManagerMetadataVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.SecretCount != 3 || result.RelationshipCount != 1 || result.UnresolvedReferenceCount != 1 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if result.PublicSecretCount == 0 || result.CrossAccountSecretCount == 0 || result.KMSReferencedCount == 0 {
		t.Fatalf("expected public/cross-account/kms counts, got %+v", result)
	}
	for _, record := range result.Records {
		evidence := strings.ToLower(record.EvidenceRef + " " + record.Source)
		if strings.Contains(evidence, "secretstring") || strings.Contains(evidence, "secretbinary") || strings.Contains(evidence, "getsecretvalue") {
			t.Fatalf("secret value evidence leaked into API response: %+v", record)
		}
		if record.DescriptionPresent != true {
			t.Fatalf("expected description presence flag, got %+v", record)
		}
		if !record.Sensitive {
			t.Fatalf("expected secret records to be sensitive: %+v", record)
		}
		if record.SensitivityClassification == "" {
			t.Fatalf("expected sensitivity classification: %+v", record)
		}
	}
}

func TestGetAWSSecretsManagerMetadataInventoryDegradedAndPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	degraded, err := svc.GetAWSSecretsManagerMetadataInventory(ctx, "default", "project-a", AWSSecretsManagerMetadataInventoryRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get degraded inventory: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || degraded.MissingRotationCount == 0 || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded missing-rotation diagnostics, got %+v", degraded)
	}

	denied, err := svc.GetAWSSecretsManagerMetadataInventory(ctx, "default", "project-a", AWSSecretsManagerMetadataInventoryRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get denied inventory: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked || denied.SecretCount != 0 || len(denied.Diagnostics) == 0 {
		t.Fatalf("expected blocked permission-denied inventory, got %+v", denied)
	}
}

func TestRouterAWSSecretsManagerMetadataPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/secrets-manager-metadata?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSSecretsManagerMetadataInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.SecretCount == 0 {
		t.Fatalf("expected degraded partial records, got %+v", body.Inventory)
	}
	foundDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "secrets_manager_describe_secret_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected describe diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSSecretsManagerMetadataInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 16, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/secrets-manager-metadata?connector_id=aws-prod&fixture_state=bogus", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAWSSecretsManagerMetadataFixtureSensitivityClassifications(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 17, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-3")
	seedAWSConnectorForScanTest(t, store, ctx, "project-3", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-3/aws/secrets-manager-metadata?connector_id=aws-prod", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSSecretsManagerMetadataInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	expect := map[string]struct {
		classification string
		source         string
	}{
		"payments/db": {
			classification: "runtime_secret_reference",
			source:         "auto_rules",
		},
		"shared/api-token": {
			classification: "customer_kms_secret",
			source:         "operator_override",
		},
		"partner/webhook": {
			classification: "secret_bearing",
			source:         "auto_rules",
		},
	}
	for _, record := range body.Inventory.Records {
		expected, ok := expect[record.SecretName]
		if !ok {
			continue
		}
		if record.SensitivityClassification != expected.classification {
			t.Fatalf("secret %s sensitivity_classification = %s, want %s", record.SecretName, record.SensitivityClassification, expected.classification)
		}
		if record.SensitivityClassificationSource != expected.source {
			t.Fatalf("secret %s sensitivity_classification_source = %s, want %s", record.SecretName, record.SensitivityClassificationSource, expected.source)
		}
		if record.SensitivityClassificationOverride != "" && record.SensitivityClassificationSource != "operator_override" {
			t.Fatalf("override value should only be present for operator override: %+v", record)
		}
	}
}
