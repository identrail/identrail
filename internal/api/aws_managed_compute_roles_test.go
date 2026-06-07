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

func TestGetAWSManagedComputeRoleInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSManagedComputeRoleInventory(ctx, "default", "project-a", AWSManagedComputeRoleInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get managed compute role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1485" || result.Version != awsManagedComputeRoleVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.RecordCount != 9 || result.ServiceCount != 4 || result.AppRunnerCount != 2 || result.BatchCount != 3 || result.GlueCount != 2 || result.EMRCount != 2 || result.UnsupportedServiceCount != 1 || result.IdentityCount != 9 || result.ResourceCount != 6 || result.RelationshipCount != 9 {
		t.Fatalf("unexpected inventory counts: %+v", result)
	}
	if len(result.CoverageGaps) != 1 || result.CoverageGaps[0].Service != "mwaa" {
		t.Fatalf("expected unsupported MWAA coverage gap, got %+v", result.CoverageGaps)
	}
	var batchExecution *AWSManagedComputeRoleRecord
	var appRunnerAccess *AWSManagedComputeRoleRecord
	for i := range result.Records {
		switch result.Records[i].RoleKind {
		case "batch_execution_role":
			batchExecution = &result.Records[i]
		case "apprunner_access_role":
			appRunnerAccess = &result.Records[i]
		}
	}
	if batchExecution == nil || batchExecution.JobDefinitionARN == "" || batchExecution.Revision != 5 || batchExecution.RelationshipType != "attached_to" {
		t.Fatalf("expected Batch execution role drilldown metadata, got %+v", result.Records)
	}
	if appRunnerAccess == nil || appRunnerAccess.RelationshipType != "attached_to" {
		t.Fatalf("expected App Runner access role to be attached_to, got %+v", result.Records)
	}
	if !hasAWSManagedComputeRoleRelationship(result.Relationships, "runs_as") || !hasAWSManagedComputeRoleRelationship(result.Relationships, "attached_to") {
		t.Fatalf("expected runtime and support role relationships, got %+v", result.Relationships)
	}
	if strings.Contains(strings.ToLower(result.Records[0].EvidenceRef), "payload") || strings.Contains(strings.ToLower(result.Records[0].EvidenceRef), "secret") {
		t.Fatalf("expected metadata-only evidence, got %+v", result.Records[0])
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func hasAWSManagedComputeRoleRelationship(relationships []AWSManagedComputeRoleRelationship, relationshipType string) bool {
	for _, relationship := range relationships {
		if relationship.Type == relationshipType {
			return true
		}
	}
	return false
}

func TestRouterAWSManagedComputeRoleInventoryPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 6, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/managed-compute-roles?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSManagedComputeRoleInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected partial failure fixture, got %+v", body.Inventory)
	}
	if body.Inventory.RecordCount != 6 || body.Inventory.EMRCount != 0 || len(body.Inventory.Diagnostics) != 1 || !body.Inventory.Diagnostics[0].Retryable {
		t.Fatalf("expected retained App Runner/Batch/Glue records and retryable diagnostic, got %+v", body.Inventory)
	}
}

func TestAWSManagedComputeRoleInventoryHelperBranches(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSManagedComputeRoleFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected disconnected connector to map to permission_denied, got %q", got)
	}
	if got := normalizeAWSManagedComputeRoleFixtureState("bogus", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected unknown fixture state to be rejected, got %q", got)
	}
	if got := normalizeAWSManagedComputeRoleFixtureState("EMPTY", AWSConnectionStatus{}, false); got != "empty" {
		t.Fatalf("expected explicit fixture state normalization, got %q", got)
	}

	status, confidence, failures, remediations := summarizeAWSManagedComputeRoleInventory("success", []providers.SourceError{{
		Code:      "glue_crawlers_failed",
		Message:   "crawlers unavailable",
		Retryable: true,
	}})
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.82 || len(failures) != 1 || len(remediations) != 1 {
		t.Fatalf("expected diagnostics to degrade successful state, got status=%s confidence=%f failures=%+v remediations=%+v", status, confidence, failures, remediations)
	}

	for _, code := range []string{"permission_denied", "managed_compute_workload_disabled", "emr_failed", "missing_managed_compute_role", "unknown"} {
		if remediation := awsManagedComputeRoleDiagnosticRemediation(code); strings.TrimSpace(remediation) == "" {
			t.Fatalf("expected remediation for %q", code)
		}
	}
}
