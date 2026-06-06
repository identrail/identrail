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

func TestGetAWSStepFunctionsStateMachineRoleInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 13, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSStepFunctionsStateMachineRoleInventory(ctx, "default", "project-a", AWSStepFunctionsStateMachineRoleInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get stepfunctions state machine role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1483" || result.Version != awsStepFunctionsStateMachineRoleVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.RecordCount != 1 || result.StateMachineCount != 1 || result.NestedWorkflowCount != 1 || result.TaskResourceCount != 2 || result.ServiceIntegrationCount != 2 || result.LogGroupCount != 1 || result.IdentityCount != 1 || result.ResourceCount != 1 || result.RelationshipCount != 1 {
		t.Fatalf("unexpected inventory counts: %+v", result)
	}
	record := result.Records[0]
	if record.RelationshipType != "runs_as" || record.RoleName != "payments-stepfunctions-execution" || record.StateMachineName != "payments-orchestrator" {
		t.Fatalf("expected Step Functions role evidence, got %+v", record)
	}
	if strings.Contains(strings.Join(record.DefinitionResourceARNs, ","), "do-not-store") || record.DefinitionSHA256 == "" {
		t.Fatalf("definition evidence must be hash/reference-only, got %+v", record)
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestGetAWSStepFunctionsStateMachineRoleInventorySurfacesDegradedLogging(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 13, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSStepFunctionsStateMachineRoleInventory(ctx, "default", "project-a", AWSStepFunctionsStateMachineRoleInventoryRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("get degraded stepfunctions inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.FailureReasons) == 0 {
		t.Fatalf("expected degraded result with failure reason, got %+v", result)
	}
	if result.RecordCount != 1 || len(result.Diagnostics) != 1 || !result.Records[0].LoggingIncludeExecutionData {
		t.Fatalf("expected retained record and logging diagnostic, got %+v", result)
	}
	if result.Diagnostics[0].Code != "logging_execution_data_enabled" || result.Records[0].Status != "degraded" {
		t.Fatalf("expected explicit degraded logging state, got record=%+v diagnostics=%+v", result.Records[0], result.Diagnostics)
	}
}

func TestRouterAWSStepFunctionsStateMachineRoleInventory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 13, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/stepfunctions-state-machine-roles?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSStepFunctionsStateMachineRoleInventoryResult `json:"inventory"`
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

func TestAWSStepFunctionsStateMachineRoleInventoryHelperBranches(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSStepFunctionsStateMachineRoleFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected disconnected connector to map to permission_denied, got %q", got)
	}
	if got := normalizeAWSStepFunctionsStateMachineRoleFixtureState("bogus", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected unknown fixture state to be rejected, got %q", got)
	}
	if got := normalizeAWSStepFunctionsStateMachineRoleFixtureState("EMPTY", AWSConnectionStatus{}, false); got != "empty" {
		t.Fatalf("expected explicit fixture state normalization, got %q", got)
	}

	status, confidence, failures, remediations := summarizeAWSStepFunctionsStateMachineRoleInventory("success", []providers.SourceError{{
		Code:      "state_machine_tags_failed",
		Message:   "tags unavailable",
		Retryable: true,
	}})
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.8 || len(failures) != 1 || len(remediations) != 1 {
		t.Fatalf("expected diagnostics to degrade successful state, got status=%s confidence=%f failures=%+v remediations=%+v", status, confidence, failures, remediations)
	}

	for _, code := range []string{"permission_denied", "logging_execution_data_enabled", "state_machine_describe_failed", "missing_stepfunctions_execution_role", "unknown"} {
		if remediation := awsStepFunctionsStateMachineRoleDiagnosticRemediation(code); strings.TrimSpace(remediation) == "" {
			t.Fatalf("expected remediation for %q", code)
		}
	}
}
