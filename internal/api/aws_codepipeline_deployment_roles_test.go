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

func TestGetAWSCodePipelineDeploymentRoleInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 11, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSCodePipelineDeploymentRoleInventory(ctx, "default", "project-a", AWSCodePipelineDeploymentRoleInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get codepipeline deployment role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1482" || result.Version != awsCodePipelineDeploymentRoleVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.RecordCount != 2 || result.PipelineCount != 1 || result.ActionRoleCount != 1 || result.IdentityCount != 2 || result.ResourceCount != 1 || result.RelationshipCount != 2 {
		t.Fatalf("unexpected inventory counts: %+v", result)
	}
	if result.CrossAccountRoleCount != 1 || result.CrossRegionActionCount != 1 || result.PassRoleAdjacentCount != 2 {
		t.Fatalf("unexpected deployment role risk counts: %+v", result)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("did not expect diagnostics for success fixture: %+v", result.Diagnostics)
	}
	if result.Records[1].RelationshipType != "runs_as" || result.Records[1].ActionProvider != "CodeDeploy" || !result.Records[1].CrossAccountRole {
		t.Fatalf("expected CodePipeline action role evidence, got %+v", result.Records[1])
	}
	if result.Records[1].AccountID != "123456789012" || result.Records[1].RoleAccountID != "210987654321" || !strings.Contains(result.Records[1].FromNodeID, "123456789012") {
		t.Fatalf("expected action workload account and role account to remain separate, got %+v", result.Records[1])
	}
	if strings.Contains(strings.Join(result.Records[1].ConfigurationKeys, ","), "must-not-appear") {
		t.Fatalf("configuration values must not be collected, got %+v", result.Records[1])
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestGetAWSCodePipelineDeploymentRoleInventorySurfacesDisabledTransitions(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSCodePipelineDeploymentRoleInventory(ctx, "default", "project-a", AWSCodePipelineDeploymentRoleInventoryRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("get degraded codepipeline deployment role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.FailureReasons) == 0 {
		t.Fatalf("expected degraded result with failure reason, got %+v", result)
	}
	if result.RecordCount != 1 || len(result.Diagnostics) != 1 || result.DisabledStageTransitionCount != 1 {
		t.Fatalf("expected retained record, disabled-transition count, and diagnostic, got %+v", result)
	}
	if result.Diagnostics[0].Code != "disabled_stage_transition" || result.Records[0].Status != "degraded" {
		t.Fatalf("expected explicit disabled transition state, got record=%+v diagnostics=%+v", result.Records[0], result.Diagnostics)
	}
}

func TestRouterAWSCodePipelineDeploymentRoleInventory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 12, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/codepipeline-deployment-roles?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSCodePipelineDeploymentRoleInventoryResult `json:"inventory"`
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

func TestAWSCodePipelineDeploymentRoleInventoryHelperBranches(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSCodePipelineDeploymentRoleFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected disconnected connector to map to permission_denied, got %q", got)
	}
	if got := normalizeAWSCodePipelineDeploymentRoleFixtureState("bogus", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected unknown fixture state to be rejected, got %q", got)
	}
	if got := normalizeAWSCodePipelineDeploymentRoleFixtureState("EMPTY", AWSConnectionStatus{}, false); got != "empty" {
		t.Fatalf("expected explicit fixture state normalization, got %q", got)
	}

	status, confidence, failures, remediations := summarizeAWSCodePipelineDeploymentRoleInventory("success", []providers.SourceError{{
		Code:      "pipeline_state_get_failed",
		Message:   "state unavailable",
		Retryable: true,
	}})
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.8 || len(failures) != 1 || len(remediations) != 1 {
		t.Fatalf("expected diagnostics to degrade successful state, got status=%s confidence=%f failures=%+v remediations=%+v", status, confidence, failures, remediations)
	}

	for _, code := range []string{"permission_denied", "disabled_stage_transition", "pipeline_get_failed", "missing_codepipeline_deployment_role", "unknown"} {
		if remediation := awsCodePipelineDeploymentRoleDiagnosticRemediation(code); strings.TrimSpace(remediation) == "" {
			t.Fatalf("expected remediation for %q", code)
		}
	}

	relationships := awsCodePipelineDeploymentRoleRelationships([]AWSCodePipelineDeploymentRoleRecord{
		{FromNodeID: "pipeline", ToNodeID: "role", EvidenceRef: "evidence"},
		{FromNodeID: "", ToNodeID: "skipped", EvidenceRef: "missing-from"},
	})
	if len(relationships) != 1 || relationships[0].Type != "runs_as" {
		t.Fatalf("expected one valid relationship, got %+v", relationships)
	}
	if got := awsCodePipelineNodeID("", "", "", ""); !strings.Contains(got, "account") || !strings.Contains(got, "pipeline/pipeline") {
		t.Fatalf("expected fallback codepipeline node id, got %q", got)
	}
}
