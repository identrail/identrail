package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func TestGetAWSPlatformValidationHarnessBuildsRequiredFixtureStates(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 14, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSPlatformValidationHarness(ctx, "default", "project-a", AWSPlatformValidationHarnessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get validation harness: %v", err)
	}
	if result.Status != awsPlatformValidationStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready validation harness, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1475" || result.Version != awsPlatformValidationHarnessVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.ConnectorID != "aws-prod" || result.Region != "us-east-1" {
		t.Fatalf("expected connector context, got %+v", result)
	}
	if result.ScenarioCount != 6 || result.RequiredScenarioCount != 6 {
		t.Fatalf("unexpected scenario counts: %+v", result)
	}
	for _, state := range []string{
		awsPlatformFixtureStateSuccess,
		awsPlatformFixtureStateEmpty,
		awsPlatformFixtureStateDegraded,
		awsPlatformFixtureStatePartialFailure,
		awsPlatformFixtureStatePermissionDenied,
		awsPlatformFixtureStateUnsupportedService,
	} {
		if !containsString(result.FixtureStates, state) {
			t.Fatalf("missing fixture state %q in %+v", state, result.FixtureStates)
		}
	}
	if len(result.BrowserSteps) != 2 || len(result.APISteps) != 2 {
		t.Fatalf("expected browser and api proof steps, got browser=%+v api=%+v", result.BrowserSteps, result.APISteps)
	}
	for _, scenario := range result.Scenarios {
		if scenario.Status != awsPlatformValidationStatusReady || !scenario.Required {
			t.Fatalf("expected required ready scenario, got %+v", scenario)
		}
		if scenario.CheckedAt != now {
			t.Fatalf("expected scenario timestamp %v, got %v", now, scenario.CheckedAt)
		}
		if scenario.Evidence["workspace_id"] != "default" || scenario.Evidence["project_id"] != "project-a" {
			t.Fatalf("scenario evidence is not scoped: %+v", scenario.Evidence)
		}
		if !containsString(scenario.APIStepIDs, "api_validation_harness") {
			t.Fatalf("scenario missing api harness step: %+v", scenario)
		}
	}
	denied := requireAWSPlatformValidationScenario(t, result.Scenarios, "remediation_permission_denied")
	if denied.FixtureState != awsPlatformFixtureStatePermissionDenied || denied.FailureReason == "" || denied.Remediation == "" {
		t.Fatalf("permission denied scenario should be explicit, got %+v", denied)
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestSummarizeAWSPlatformValidationHarnessBlocksMissingFixtureState(t *testing.T) {
	now := time.Date(2026, 6, 4, 14, 30, 0, 0, time.UTC)
	scenarios := []AWSPlatformValidationScenario{{
		ID:           "connector_setup_success",
		FixtureState: awsPlatformFixtureStateSuccess,
		Status:       awsPlatformValidationStatusReady,
		Required:     true,
		CheckedAt:    now,
	}}
	status, confidence, failures, remediations := summarizeAWSPlatformValidationHarness(
		scenarios,
		[]AWSPlatformValidationStep{{ID: "browser_connector_setup"}},
		[]AWSPlatformValidationStep{{ID: "api_validation_harness"}},
	)
	if status != awsPlatformValidationStatusBlocked || confidence >= 0.9 {
		t.Fatalf("expected blocked summary for missing states, got status=%s confidence=%f", status, confidence)
	}
	if !containsString(failures, "missing permission_denied validation fixture") {
		t.Fatalf("expected missing permission_denied failure, got %+v", failures)
	}
	if len(remediations) == 0 {
		t.Fatalf("expected remediation hints for missing fixture states")
	}
}

func TestRouterAWSPlatformValidationHarness(t *testing.T) {
	r := newAWSConnectionTestRouter(t, &fakeAWSConnectorValidator{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/validation-harness", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected validation harness 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var body struct {
		Harness AWSPlatformValidationHarnessResult `json:"harness"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode validation harness response: %v", err)
	}
	if body.Harness.Status != awsPlatformValidationStatusReady || body.Harness.CurrentIssueRef != "#1475" {
		t.Fatalf("unexpected validation harness payload: %+v", body.Harness)
	}
	if body.Harness.ScenarioCount != 6 || !containsString(body.Harness.FixtureStates, awsPlatformFixtureStateUnsupportedService) {
		t.Fatalf("expected all fixture states in router payload, got %+v", body.Harness)
	}
}

func requireAWSPlatformValidationScenario(t *testing.T, scenarios []AWSPlatformValidationScenario, id string) AWSPlatformValidationScenario {
	t.Helper()
	for _, scenario := range scenarios {
		if scenario.ID == id {
			return scenario
		}
	}
	t.Fatalf("validation scenario %s not found", id)
	return AWSPlatformValidationScenario{}
}
