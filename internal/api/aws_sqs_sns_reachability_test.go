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

func TestGetAWSSQSSNSReachabilityInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSSQSSNSReachabilityInventory(ctx, "default", "project-a", AWSSQSSNSReachabilityInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get sqs/sns inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.CurrentIssueRef != "#1493" || result.Version != awsSQSSNSReachabilityVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.ResourceCount != 4 || result.QueueCount != 2 || result.TopicCount != 2 {
		t.Fatalf("expected 4 resources with queue/topic split, got %+v", result)
	}
	if result.PublicResourceCount == 0 || result.CrossAccountResourceCount == 0 || result.RestrictedResourceCount == 0 {
		t.Fatalf("expected public/cross/restricted counts populated, got %+v", result)
	}
	if result.SubscriptionCount == 0 || result.EncryptedResourceCount == 0 || result.DLQResourceCount == 0 {
		t.Fatalf("expected subscriptions/encryption/dlq counts populated, got %+v", result)
	}
	if result.PublicGrantCount == 0 || result.CrossAccountGrantCount == 0 || result.DenyGrantCount == 0 {
		t.Fatalf("expected public/cross/deny grant counts populated, got %+v", result)
	}
	if result.RelationshipCount == 0 {
		t.Fatalf("expected IAM principal relationships, got 0")
	}
	for _, record := range result.Records {
		evidence := strings.ToLower(record.EvidenceRef + " " + record.Source + " " + record.ResourceURL)
		if strings.Contains(evidence, "message-body") || strings.Contains(evidence, "payload") || strings.Contains(evidence, "http://example") {
			t.Fatalf("expected metadata-only evidence, got %+v", record)
		}
		for _, sub := range record.Subscriptions {
			if sub.EndpointRedacted && sub.EndpointResourceARN != "" {
				t.Fatalf("redacted subscription should not expose endpoint arn too: %+v", sub)
			}
		}
	}
}

func TestRouterAWSSQSSNSReachabilityPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 10, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/sqs-sns-reachability?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSSQSSNSReachabilityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected degraded partial_failure, got status=%q fixture=%q", body.Inventory.Status, body.Inventory.FixtureState)
	}
	if body.Inventory.ResourceCount == 0 {
		t.Fatalf("expected partial failure to retain some records, got 0")
	}
	foundDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "sqs_sns_reachability_page_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected sqs_sns_reachability_page_failed diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSSQSSNSReachabilityPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 11, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/sqs-sns-reachability?connector_id=aws-prod&fixture_state=permission_denied", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSSQSSNSReachabilityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusBlocked || len(body.Inventory.Records) != 0 {
		t.Fatalf("expected blocked empty inventory, got %+v", body.Inventory)
	}
}

func TestRouterAWSSQSSNSReachabilityFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 11, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-3")
	seedAWSConnectorForScanTest(t, store, ctx, "project-3", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-3/aws/sqs-sns-reachability?connector_id=aws-prod&resource_type=sqs_queue&identity=partner-publisher", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSSQSSNSReachabilityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.ResourceCount != 1 || len(body.Inventory.Records) == 0 || body.Inventory.Records[0].ResourceName != "partner-ingest" {
		t.Fatalf("expected filtered partner-ingest queue, got %+v", body.Inventory.Records)
	}
}

func TestAWSQSSNSReachabilityInventoryHasChinaQueueURLsForChinaPartition(t *testing.T) {
	scope := db.Scope{TenantID: "default", WorkspaceID: "default"}
	project := db.TenancyProject{WorkspaceID: "default", ProjectID: "project-cn"}
	connection := AWSConnectionStatus{
		ConnectorID: "aws-cn",
		AccountID:   "123456789012",
		Region:      "cn-north-1",
		Connected:   true,
	}
	checkedAt := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)

	result, err := buildAWSSQSSNSReachabilityInventory(scope, project, connection, true, AWSSQSSNSReachabilityInventoryRequest{}, checkedAt)
	if err != nil {
		t.Fatalf("build china partition inventory: %v", err)
	}
	for _, record := range result.Records {
		if record.ResourceType != "sqs_queue" {
			continue
		}
		if !strings.Contains(record.QueueURL, ".amazonaws.com.cn/") {
			t.Fatalf("expected China queue URL to use .amazonaws.com.cn, got %q", record.QueueURL)
		}
	}
}

func TestRouterAWSSQSSNSReachabilityInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-4")
	seedAWSConnectorForScanTest(t, store, ctx, "project-4", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-4/aws/sqs-sns-reachability?connector_id=aws-prod&fixture_state=bogus", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}
