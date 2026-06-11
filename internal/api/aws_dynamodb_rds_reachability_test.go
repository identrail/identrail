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

func TestGetAWSDynamoDBRDSReachabilityInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSDynamoDBRDSReachabilityInventory(ctx, "default", "project-a", AWSDynamoDBRDSReachabilityInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("GetAWSDynamoDBRDSReachabilityInventory: %v", err)
	}
	if result.CurrentIssueRef != "#1494" || result.Version != awsDynamoDBRDSReachabilityVersion {
		t.Fatalf("unexpected issue/version: %s %s", result.CurrentIssueRef, result.Version)
	}
	if result.ResourceCount != 5 || result.DynamoDBTableCount != 1 || result.RDSProxyCount != 1 {
		t.Fatalf("unexpected resource counts: %+v", result)
	}
	if result.RelationshipCount == 0 || result.IdentityGrantCount == 0 || result.AssociatedRoleCount == 0 {
		t.Fatalf("expected relationship evidence, got relationships=%d grants=%d roles=%d", result.RelationshipCount, result.IdentityGrantCount, result.AssociatedRoleCount)
	}
	if !strings.Contains(strings.Join(result.EvidenceLinks, " "), "aws-dynamodb-rds-reachability") {
		t.Fatalf("expected docs evidence link, got %+v", result.EvidenceLinks)
	}
	for _, record := range result.Records {
		if record.AccountID == "" || record.Region == "" || record.ResourceARN == "" || record.Source != "dynamodb_rds_metadata" {
			t.Fatalf("record missing scoped metadata: %+v", record)
		}
		if record.EvidenceRef == "" || record.FromNodeID == "" || record.CollectedAt.IsZero() {
			t.Fatalf("record missing graph/evidence metadata: %+v", record)
		}
	}
}

func TestRouterAWSDynamoDBRDSReachabilityPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 10, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/dynamodb-rds-reachability?connector_id=aws-prod&fixture_state=permission_denied", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSDynamoDBRDSReachabilityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusBlocked || len(body.Inventory.Records) != 0 {
		t.Fatalf("expected blocked empty inventory, got %+v", body.Inventory)
	}
	if len(body.Inventory.Diagnostics) == 0 || body.Inventory.Diagnostics[0].Code != "permission_denied" {
		t.Fatalf("expected permission diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSDynamoDBRDSReachabilityFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 11, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/dynamodb-rds-reachability?connector_id=aws-prod&resource_type=dynamodb_table&identity=partner-ledger-reader", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSDynamoDBRDSReachabilityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Inventory.Records) != 1 || body.Inventory.Records[0].ResourceType != "dynamodb_table" {
		t.Fatalf("expected filtered DynamoDB table record, got %+v", body.Inventory.Records)
	}
}

func TestRouterAWSDynamoDBRDSReachabilityInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 11, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-3")
	seedAWSConnectorForScanTest(t, store, ctx, "project-3", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-3/aws/dynamodb-rds-reachability?connector_id=aws-prod&fixture_state=bogus", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestAWSDynamoDBRDSReachabilityFixtureKeepsChinaPartition(t *testing.T) {
	scope := db.Scope{TenantID: "tenant-a"}
	project := db.TenancyProject{WorkspaceID: "workspace-a", ProjectID: "project-a"}
	connection := AWSConnectionStatus{Connected: true, ConnectorID: "aws-cn", AccountID: "123456789012", Region: "cn-north-1"}
	result, err := buildAWSDynamoDBRDSReachabilityInventory(scope, project, connection, true, AWSDynamoDBRDSReachabilityInventoryRequest{}, time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build inventory: %v", err)
	}
	for _, record := range result.Records {
		if !strings.HasPrefix(record.ResourceARN, "arn:aws-cn:") {
			t.Fatalf("expected aws-cn resource ARN, got %s", record.ResourceARN)
		}
	}
}
