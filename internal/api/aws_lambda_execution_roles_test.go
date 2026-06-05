package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSLambdaExecutionRoleInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSLambdaExecutionRoleInventory(ctx, "default", "project-a", AWSLambdaExecutionRoleInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get lambda execution role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1479" || result.Version != awsLambdaExecutionRoleVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.ConnectorID != "aws-prod" || result.AccountID != "123456789012" || result.Region != "us-east-1" {
		t.Fatalf("expected connector account/region context, got %+v", result)
	}
	if result.RecordCount != 2 || result.FunctionCount != 2 || result.IdentityCount != 2 || result.ResourceCount != 2 || result.RelationshipCount != 2 {
		t.Fatalf("unexpected inventory counts: %+v", result)
	}
	if result.EventSourceCount != 1 || result.DisabledEventSourceCount != 0 {
		t.Fatalf("unexpected event source counts: %+v", result)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("did not expect diagnostics for success fixture: %+v", result.Diagnostics)
	}
	if result.Records[0].RelationshipType != "runs_as" || result.Records[0].FunctionARN == "" || result.Records[0].RoleARN == "" {
		t.Fatalf("expected Lambda runs_as evidence, got %+v", result.Records[0])
	}
	if len(result.Records[0].EnvironmentKeys) != 3 || strings.Contains(strings.Join(result.Records[0].EnvironmentKeys, ","), "must-not-appear") {
		t.Fatalf("expected environment keys without values, got %+v", result.Records[0])
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestGetAWSLambdaExecutionRoleInventorySurfacesDisabledEventSources(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 5, 20, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSLambdaExecutionRoleInventory(ctx, "default", "project-a", AWSLambdaExecutionRoleInventoryRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("get degraded lambda execution role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.FailureReasons) == 0 {
		t.Fatalf("expected degraded result with failure reason, got %+v", result)
	}
	if result.RecordCount != 1 || len(result.Diagnostics) != 1 || result.DisabledEventSourceCount != 1 {
		t.Fatalf("expected retained record, disabled source count, and diagnostic, got %+v", result)
	}
	if result.Diagnostics[0].Code != "disabled_event_source" || result.Records[0].Status != "degraded" || len(result.Records[0].DisabledEventSourceARNs) != 1 {
		t.Fatalf("expected explicit disabled event source state, got record=%+v diagnostics=%+v", result.Records[0], result.Diagnostics)
	}
}

func TestRouterAWSLambdaExecutionRoleInventory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 5, 20, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/lambda-execution-roles?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSLambdaExecutionRoleInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected partial failure fixture, got %+v", body.Inventory)
	}
	if body.Inventory.RecordCount != 1 || len(body.Inventory.Diagnostics) != 1 || !body.Inventory.Diagnostics[0].Retryable {
		t.Fatalf("expected retained record and retryable diagnostic, got %+v", body.Inventory)
	}
}

func TestAWSLambdaExecutionRoleInventoryHelperBranches(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSLambdaExecutionRoleFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected disconnected connector to map to permission_denied, got %q", got)
	}
	if got := normalizeAWSLambdaExecutionRoleFixtureState("bogus", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected unknown fixture state to be rejected, got %q", got)
	}
	if got := normalizeAWSLambdaExecutionRoleFixtureState("EMPTY", AWSConnectionStatus{}, false); got != "empty" {
		t.Fatalf("expected explicit fixture state normalization, got %q", got)
	}

	status, confidence, failures, remediations := summarizeAWSLambdaExecutionRoleInventory("success", []providers.SourceError{{
		Code:      "tags_list_failed",
		Message:   "tags unavailable",
		Retryable: true,
	}})
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.8 || len(failures) != 1 || len(remediations) != 1 {
		t.Fatalf("expected diagnostics to degrade successful state, got status=%s confidence=%f failures=%+v remediations=%+v", status, confidence, failures, remediations)
	}

	for _, code := range []string{"permission_denied", "disabled_event_source", "tags_list_failed", "missing_lambda_execution_role", "unknown"} {
		if remediation := awsLambdaExecutionRoleDiagnosticRemediation(code); strings.TrimSpace(remediation) == "" {
			t.Fatalf("expected remediation for %q", code)
		}
	}

	relationships := awsLambdaExecutionRoleRelationships([]AWSLambdaExecutionRoleRecord{
		{FromNodeID: "lambda-function", ToNodeID: "lambda-role", EvidenceRef: "evidence"},
		{FromNodeID: "", ToNodeID: "skipped", EvidenceRef: "missing-from"},
	})
	if len(relationships) != 1 || relationships[0].Type != "runs_as" {
		t.Fatalf("expected one valid relationship, got %+v", relationships)
	}
	if got := awsLambdaFunctionNodeID("", "", ""); !strings.Contains(got, "account") || !strings.Contains(got, "function/function") {
		t.Fatalf("expected fallback lambda function node id, got %q", got)
	}
}
