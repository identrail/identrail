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

func newAWSStackSetService(t *testing.T, store db.Store, now time.Time) *Service {
	t.Helper()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudFormationTemplateURL = "https://cdn.example.com/identrail-readonly-stackset.yaml"
	svc.AWSAccountID = "987654321098"
	return svc
}

func TestGetAWSStackSetOnboardingSuccess(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := newAWSStackSetService(t, store, now)

	result, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get stackset onboarding: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready onboarding, got status=%q confidence=%v failures=%v", result.Status, result.Confidence, result.FailureReasons)
	}
	if result.CurrentIssueRef != "#1504" || result.Version == "" {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.Validation.Status != "ready" || result.Validation.BlockingCount != 0 {
		t.Fatalf("expected ready validation, got %+v", result.Validation)
	}
	// Default: 3 accounts × 2 regions = 6 instances.
	if result.Summary.TotalInstances != 6 {
		t.Fatalf("expected 6 instances, got %d", result.Summary.TotalInstances)
	}
	if result.Summary.ActiveInstances < 2 {
		t.Fatalf("expected at least 2 active instances from checkpoints, got %+v", result.Summary)
	}
	if result.LaunchURL == "" || !strings.Contains(result.LaunchURL, "stacksets/create") {
		t.Fatalf("expected stackset console launch URL, got %q", result.LaunchURL)
	}
	if !strings.Contains(result.LaunchURL, "permissionModel=SERVICE_MANAGED") {
		t.Fatalf("expected SERVICE_MANAGED permission model in launch URL, got %q", result.LaunchURL)
	}
	if len(result.PermissionPreview) == 0 {
		t.Fatalf("expected permission preview tiers")
	}
	// Every instance carries an evidence ref and next action.
	for _, instance := range result.Instances {
		if instance.EvidenceRef == "" || instance.NextAction == "" {
			t.Fatalf("instance missing evidence/next action: %+v", instance)
		}
	}
}

func TestGetAWSStackSetOnboardingSelfManaged(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 9, 5, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := newAWSStackSetService(t, store, now)

	result, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod", DeploymentMode: "self_managed"})
	if err != nil {
		t.Fatalf("get self-managed onboarding: %v", err)
	}
	if result.DeploymentMode != "self_managed" {
		t.Fatalf("expected self_managed deployment mode, got %q", result.DeploymentMode)
	}
	// Self-managed without an admin role ARN should block validation.
	if result.Validation.Status != "blocked" || result.Validation.BlockingCount == 0 {
		t.Fatalf("expected blocked self-managed validation, got %+v", result.Validation)
	}
}

func TestGetAWSStackSetOnboardingFixtureStates(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 9, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := newAWSStackSetService(t, store, now)

	empty, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod", FixtureState: "empty"})
	if err != nil {
		t.Fatalf("get empty plan: %v", err)
	}
	if empty.Summary.TotalInstances != 0 {
		t.Fatalf("expected zero instances in empty state, got %d", empty.Summary.TotalInstances)
	}
	if empty.Validation.Status != "blocked" {
		t.Fatalf("empty state should block validation (no targets), got %q", empty.Validation.Status)
	}

	degraded, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get degraded plan: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded state with diagnostics, got %+v", degraded)
	}
	if degraded.Summary.SuspendedInstances == 0 {
		t.Fatalf("expected suspended instances from the degraded fixture")
	}

	partial, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod", FixtureState: "partial_failure"})
	if err != nil {
		t.Fatalf("get partial plan: %v", err)
	}
	if partial.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded for partial_failure, got %q", partial.Status)
	}
	if partial.Summary.FailedInstances == 0 || partial.Summary.PermissionDenied == 0 {
		t.Fatalf("expected failed + permission_denied instances in partial fixture, got %+v", partial.Summary)
	}
	if len(partial.RecoveryActions) == 0 {
		t.Fatalf("expected recovery actions in partial fixture")
	}

	denied, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get denied plan: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked {
		t.Fatalf("expected blocked denied plan, got %q", denied.Status)
	}
	if denied.Validation.BlockingCount == 0 {
		t.Fatalf("expected blocking prereqs when trusted access unavailable, got %+v", denied.Validation)
	}
}

func TestGetAWSStackSetOnboardingRejectsInvalidInputs(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := newAWSStackSetService(t, store, now)

	if _, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod", FixtureState: "bogus"}); err == nil {
		t.Fatalf("expected invalid fixture_state error")
	}
	if _, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod", DeploymentMode: "bogus"}); err == nil {
		t.Fatalf("expected invalid deployment_mode error")
	}
}

func TestGetAWSStackSetOnboardingNeverLeaksValues(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 10, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := newAWSStackSetService(t, store, now)

	result, err := svc.GetAWSStackSetOnboarding(ctx, "default", "project-a", AWSStackSetOnboardingRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get stackset onboarding: %v", err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"getsecretvalue", "secretstring", "password=", "=sk-", "plaintext"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("value-like content leaked into onboarding payload: %s", payload)
		}
	}
}

func TestRouterAWSStackSetOnboarding(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 13, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := newAWSStackSetService(t, store, now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/stackset-onboarding?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Onboarding AWSStackSetOnboardingResult `json:"onboarding"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Onboarding.Status != awsPlatformDependencyStatusDegraded || body.Onboarding.Summary.FailedInstances == 0 {
		t.Fatalf("expected degraded partial onboarding, got %+v", body.Onboarding)
	}

	for _, query := range []string{"fixture_state=bogus", "deployment_mode=bogus"} {
		bad := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/stackset-onboarding?connector_id=aws-prod&"+query, "")
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d body=%s", query, bad.Code, bad.Body.String())
		}
	}
}
