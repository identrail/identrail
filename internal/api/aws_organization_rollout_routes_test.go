package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

// newAWSOrganizationRolloutTestRouter returns a wired router plus its
// underlying service so router-level tests can seed a validated controlling
// connector directly and exercise the HTTP handler bindings, feature gate,
// and error-to-status mappings that the service-level tests bypass.
func newAWSOrganizationRolloutTestRouter(t *testing.T) (ginEngineForTest, *Service, context.Context) {
	t.Helper()
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	manager, err := secretstore.NewManager([]secretstore.KeyMaterial{{Version: "test-v1", Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatalf("build connector secret manager: %v", err)
	}
	svc := NewService(store, routerScanner{}, "aws")
	svc.Now = func() time.Time { return time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC) }
	svc.ConnectorSecretManager = manager
	svc.AWSCloudFormationTemplateURL = testAWSCloudFormationTemplateURL
	svc.AWSCloudFormationTemplateSHA = testAWSCloudFormationTemplateChecksum
	svc.AWSAccountID = "999999999999"
	svc.AWSRegistrationTopicARNs = map[string]string{"us-east-1": testAWSRegistrationTopicARN}
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:             []string{"writer-key"},
		WriteAPIKeys:        []string{"writer-key"},
		DefaultTenantID:     "tenant-a",
		DefaultWorkspaceID:  "workspace-a",
		FeatureConnectorAWS: true,
	})
	_ = doAWSConnectionAPI(t, r, http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	projectResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	if projectResp.Code != http.StatusOK {
		t.Fatalf("seed project failed: %d body=%s", projectResp.Code, projectResp.Body.String())
	}
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	return r, svc, ctx
}

func TestAWSOrganizationRolloutRouteStartRejectsInvalidBody(t *testing.T) {
	r, _, _ := newAWSOrganizationRolloutTestRouter(t)
	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/rollouts", `not-json`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAWSOrganizationRolloutRouteStartRejectsUnvalidatedControllingConnector(t *testing.T) {
	r, svc, ctx := newAWSOrganizationRolloutTestRouter(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "unknown", domain.ConnectorStatusPending, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	body := `{"controlling_connector_id":"aws-mgmt","organization_id":"o-fixture001","management_account_id":"111111111111","target_regions":["us-east-1"]}`
	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/rollouts", body)
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAWSOrganizationRolloutRouteStartAndStatusHappyPath(t *testing.T) {
	r, svc, ctx := newAWSOrganizationRolloutTestRouter(t)
	seedAWSRolloutControllingConnector(t, svc.Store, ctx, "aws-mgmt", "111111111111", "healthy", domain.ConnectorStatusActive, time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC))
	body := `{"controlling_connector_id":"aws-mgmt","organization_id":"o-fixture001","management_account_id":"111111111111","selected_account_ids":["222222222222"],"target_regions":["us-east-1"]}`
	startResp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/rollouts", body)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}
	var startPayload struct {
		Rollout AWSOrganizationRolloutStatus `json:"rollout"`
	}
	if err := json.Unmarshal(startResp.Body.Bytes(), &startPayload); err != nil {
		t.Fatalf("decode start body: %v", err)
	}
	if startPayload.Rollout.RolloutID == "" {
		t.Fatal("expected rollout id")
	}
	getResp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/rollouts/"+startPayload.Rollout.RolloutID, "")
	if getResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for status GET, got %d body=%s", getResp.Code, getResp.Body.String())
	}
	var getPayload struct {
		Rollout AWSOrganizationRolloutStatus `json:"rollout"`
	}
	if err := json.Unmarshal(getResp.Body.Bytes(), &getPayload); err != nil {
		t.Fatalf("decode get body: %v", err)
	}
	if getPayload.Rollout.RolloutID != startPayload.Rollout.RolloutID {
		t.Fatalf("expected same rollout id, got %q vs %q", getPayload.Rollout.RolloutID, startPayload.Rollout.RolloutID)
	}
	if getPayload.Rollout.Summary.ExpectedTargets != 2 {
		t.Fatalf("expected 2 seeded targets (mgmt + member), got %d", getPayload.Rollout.Summary.ExpectedTargets)
	}
}

func TestAWSOrganizationRolloutRouteStatusUnknownRolloutReturns404(t *testing.T) {
	r, _, _ := newAWSOrganizationRolloutTestRouter(t)
	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/rollouts/does-not-exist", "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAWSOrganizationRolloutRouteFeatureGateOff(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:            []string{"writer-key"},
		WriteAPIKeys:       []string{"writer-key"},
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
		// FeatureConnectorAWS deliberately left false.
	})
	_ = doAWSConnectionAPI(t, r, http.MethodPut, "/v1/organizations/current", `{"display_name":"Tenant A","slug":"tenant-a"}`)
	_ = doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces", `{"workspace_id":"workspace-a","display_name":"Workspace A","slug":"workspace-a"}`)
	_ = doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects", `{"project_id":"project-1","name":"Project 1","slug":"project-1"}`)
	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/rollouts", `{}`)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected feature-gated 404, got %d body=%s", resp.Code, resp.Body.String())
	}
}
