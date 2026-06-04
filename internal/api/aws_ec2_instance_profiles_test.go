package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSEC2InstanceProfileInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSEC2InstanceProfileInventory(ctx, "default", "project-a", AWSEC2InstanceProfileInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get ec2 instance profile inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1477" || result.Version != awsEC2InstanceProfileVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.ConnectorID != "aws-prod" || result.AccountID != "123456789012" || result.Region != "us-east-1" {
		t.Fatalf("expected connector account/region context, got %+v", result)
	}
	if result.RecordCount != 2 || result.WorkloadCount != 2 || result.IdentityCount != 2 || result.RelationshipCount != 2 {
		t.Fatalf("unexpected inventory counts: %+v", result)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("did not expect diagnostics for success fixture: %+v", result.Diagnostics)
	}
	if result.Records[0].IMDSHTTPTokens != "required" || result.Records[0].InstanceProfileARN == "" || result.Records[0].RoleARN == "" {
		t.Fatalf("expected EC2 profile, role, and IMDS evidence, got %+v", result.Records[0])
	}
	if result.Records[1].LaunchTemplateID == "" || result.Records[1].LaunchTemplateVersion != "3" {
		t.Fatalf("expected launch template role reference, got %+v", result.Records[1])
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestGetAWSEC2InstanceProfileInventorySurfacesDegradedState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSEC2InstanceProfileInventory(ctx, "default", "project-a", AWSEC2InstanceProfileInventoryRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("get degraded ec2 instance profile inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.FailureReasons) == 0 {
		t.Fatalf("expected degraded result with failure reason, got %+v", result)
	}
	if result.RecordCount != 1 || len(result.Diagnostics) != 1 {
		t.Fatalf("expected one degraded record and diagnostic, got %+v", result)
	}
	if result.Diagnostics[0].Code != "missing_instance_profile_role" || result.Records[0].Status != "degraded" {
		t.Fatalf("expected explicit missing role state, got record=%+v diagnostics=%+v", result.Records[0], result.Diagnostics)
	}
}

func TestRouterAWSEC2InstanceProfileInventory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/ec2-instance-profiles?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSEC2InstanceProfileInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected partial failure fixture, got %+v", body.Inventory)
	}
	if body.Inventory.RecordCount != 1 || len(body.Inventory.Diagnostics) != 1 || !body.Inventory.Diagnostics[0].Retryable {
		t.Fatalf("expected one retained record and retryable diagnostic, got %+v", body.Inventory)
	}
}
