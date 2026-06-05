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

func TestGetAWSECSTaskRoleInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 17, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSECSTaskRoleInventory(ctx, "default", "project-a", AWSECSTaskRoleInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get ecs task role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1478" || result.Version != awsECSTaskRoleVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.ConnectorID != "aws-prod" || result.AccountID != "123456789012" || result.Region != "us-east-1" {
		t.Fatalf("expected connector account/region context, got %+v", result)
	}
	if result.RecordCount != 3 || result.TaskRoleCount != 2 || result.ExecutionRoleCount != 1 || result.WorkloadCount != 2 || result.RelationshipCount != 3 {
		t.Fatalf("unexpected inventory counts: %+v", result)
	}
	if result.ResourceCount != 3 {
		t.Fatalf("expected service and two task-definition resources, got %+v", result)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("did not expect diagnostics for success fixture: %+v", result.Diagnostics)
	}
	if result.Records[0].RoleKind != "task_role" || result.Records[0].RelationshipType != "runs_as" || result.Records[0].TaskDefinitionARN == "" {
		t.Fatalf("expected task role evidence, got %+v", result.Records[0])
	}
	if result.Records[1].RoleKind != "execution_role" || result.Records[1].RelationshipType != "attached_to" {
		t.Fatalf("expected execution role attachment evidence, got %+v", result.Records[1])
	}
	if result.Records[0].FromNodeID != result.Records[1].FromNodeID {
		t.Fatalf("expected task and execution role records to share the ECS workload node, got %q and %q", result.Records[0].FromNodeID, result.Records[1].FromNodeID)
	}
	if len(result.Records[0].SecretRefs) != 1 || len(result.Records[0].EnvironmentKeys) != 2 {
		t.Fatalf("expected secret refs and environment keys without values, got %+v", result.Records[0])
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestGetAWSECSTaskRoleInventorySurfacesDegradedState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 18, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSECSTaskRoleInventory(ctx, "default", "project-a", AWSECSTaskRoleInventoryRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("get degraded ecs task role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.FailureReasons) == 0 {
		t.Fatalf("expected degraded result with failure reason, got %+v", result)
	}
	if result.RecordCount != 1 || len(result.Diagnostics) != 1 {
		t.Fatalf("expected one retained record and diagnostic, got %+v", result)
	}
	if result.Diagnostics[0].Code != "missing_execution_role" || result.Records[0].Status != "ready" || result.Records[0].ExecutionRoleARN != "" {
		t.Fatalf("expected explicit missing execution role state, got record=%+v diagnostics=%+v", result.Records[0], result.Diagnostics)
	}
}

func TestRouterAWSECSTaskRoleInventory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 18, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/ecs-task-roles?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSECSTaskRoleInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected partial failure fixture, got %+v", body.Inventory)
	}
	if body.Inventory.RecordCount != 2 || len(body.Inventory.Diagnostics) != 1 || !body.Inventory.Diagnostics[0].Retryable {
		t.Fatalf("expected retained records and retryable diagnostic, got %+v", body.Inventory)
	}
}
