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

func TestGetAWSEventDrivenRoleInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 14, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSEventDrivenRoleInventory(ctx, "default", "project-a", AWSEventDrivenRoleInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get event-driven role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1484" || result.Version != awsEventDrivenRoleVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.RecordCount != 3 || result.RuleCount != 1 || result.ScheduleCount != 1 || result.PipeCount != 1 || result.TargetCount != 3 || result.DeadLetterCount != 3 || result.DisabledCount != 1 || result.IdentityCount != 3 || result.ResourceCount != 3 || result.RelationshipCount != 3 {
		t.Fatalf("unexpected inventory counts: %+v", result)
	}
	var disabledSchedule *AWSEventDrivenRoleRecord
	for i := range result.Records {
		if result.Records[i].Disabled {
			disabledSchedule = &result.Records[i]
			break
		}
	}
	if disabledSchedule == nil || disabledSchedule.WorkloadType != "scheduler_schedule" || disabledSchedule.Status != "disabled" {
		t.Fatalf("expected disabled schedule represented separately, got %+v", result.Records)
	}
	if strings.Contains(strings.ToLower(result.Records[0].InputTransformerSHA256), "payload") || result.Records[0].InputTransformerSHA256 == "" {
		t.Fatalf("expected hash-only transformer metadata, got %+v", result.Records[0])
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestRouterAWSEventDrivenRoleInventoryPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 14, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/event-driven-roles?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSEventDrivenRoleInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected partial failure fixture, got %+v", body.Inventory)
	}
	if body.Inventory.RecordCount != 2 || body.Inventory.PipeCount != 0 || len(body.Inventory.Diagnostics) != 1 || !body.Inventory.Diagnostics[0].Retryable {
		t.Fatalf("expected retained rule/schedule records and retryable diagnostic, got %+v", body.Inventory)
	}
}

func TestAWSEventDrivenRoleInventoryHelperBranches(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSEventDrivenRoleFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected disconnected connector to map to permission_denied, got %q", got)
	}
	if got := normalizeAWSEventDrivenRoleFixtureState("bogus", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected unknown fixture state to be rejected, got %q", got)
	}
	if got := normalizeAWSEventDrivenRoleFixtureState("EMPTY", AWSConnectionStatus{}, false); got != "empty" {
		t.Fatalf("expected explicit fixture state normalization, got %q", got)
	}

	status, confidence, failures, remediations := summarizeAWSEventDrivenRoleInventory("success", []providers.SourceError{{
		Code:      "eventbridge_targets_failed",
		Message:   "targets unavailable",
		Retryable: true,
	}})
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.82 || len(failures) != 1 || len(remediations) != 1 {
		t.Fatalf("expected diagnostics to degrade successful state, got status=%s confidence=%f failures=%+v remediations=%+v", status, confidence, failures, remediations)
	}

	for _, code := range []string{"permission_denied", "pipe_execution_data_logging_enabled", "pipe_describe_failed", "missing_event_driven_role", "unknown"} {
		if remediation := awsEventDrivenRoleDiagnosticRemediation(code); strings.TrimSpace(remediation) == "" {
			t.Fatalf("expected remediation for %q", code)
		}
	}
}
