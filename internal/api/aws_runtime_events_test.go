package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSRuntimeEventsBuildsMetadataOnlyContract(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.CurrentIssueRef != "#1513" || result.Version != awsRuntimeEventsVersion || result.Status != "ready" {
		t.Fatalf("unexpected runtime event contract metadata: %+v", result)
	}
	if result.Summary.TotalEvents != 5 || result.Summary.FilteredEvents != 5 || result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("unexpected runtime event summary: %+v relationships=%d", result.Summary, len(result.Relationships))
	}
	if result.Summary.SecretReadCount != 1 || result.Summary.KMSDecryptCount != 1 || result.Summary.AgentEventCount != 1 || result.Summary.STSSessionCount == 0 {
		t.Fatalf("expected runtime event type counts, got %+v", result.Summary)
	}
	for _, record := range result.Records {
		if record.RedactionBoundary != "metadata_only_no_payloads_no_secret_values" {
			t.Fatalf("runtime event leaked unsafe redaction boundary: %+v", record)
		}
		if record.EvidenceRef == "" || record.ActorIdentityNodeID == "" || record.Session.SessionID == "" || record.Confidence <= 0 {
			t.Fatalf("runtime event missing evidence/session/identity/confidence: %+v", record)
		}
	}
	if len(result.EvidenceLinks) == 0 || len(result.FailureReasons) != 0 {
		t.Fatalf("expected evidence links and no failure reasons, got links=%v failures=%v", result.EvidenceLinks, result.FailureReasons)
	}
}

func TestGetAWSRuntimeEventsAppliesFiltersAndRelationships(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 18, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-filter")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-filter", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-filter", AWSRuntimeEventRequest{
		ConnectorID: "aws-prod",
		EventType:   "agent-tool",
		Owner:       "security",
		Evidence:    "agent-runtime",
		AgentID:     "runtime-case-triage",
	})
	if err != nil {
		t.Fatalf("get filtered runtime events: %v", err)
	}
	if result.Summary.TotalEvents <= result.Summary.FilteredEvents || result.Summary.FilteredEvents != 1 || len(result.Records) != 1 {
		t.Fatalf("expected one filtered runtime event with retained total count, got %+v records=%d", result.Summary, len(result.Records))
	}
	if result.Records[0].EventType != "agent-tool" || result.Records[0].AgentID != "runtime-case-triage" {
		t.Fatalf("expected agent tool event, got %+v", result.Records[0])
	}
	if result.AppliedFilters["event_type"] != "agent-tool" || result.AppliedFilters["agent_id"] != "runtime-case-triage" {
		t.Fatalf("expected applied runtime filters, got %+v", result.AppliedFilters)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("expected filtered agent-tool response to omit unrelated diagnostics, got %+v", result.Diagnostics)
	}
	for _, relationship := range result.Relationships {
		if relationship.EvidenceRef != result.Records[0].EvidenceRef {
			t.Fatalf("expected relationships scoped to filtered event, got %+v", relationship)
		}
	}
	for _, tc := range []struct {
		name    string
		request AWSRuntimeEventRequest
	}{
		{
			name:    "identity does not match event metadata",
			request: AWSRuntimeEventRequest{ConnectorID: "aws-prod", Identity: "InvokeTool"},
		},
		{
			name:    "agent id does not match event metadata",
			request: AWSRuntimeEventRequest{ConnectorID: "aws-prod", AgentID: "bedrock-agentcore"},
		},
		{
			name:    "resource does not match evidence metadata",
			request: AWSRuntimeEventRequest{ConnectorID: "aws-prod", Resource: "runtime-evidence"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-filter", tc.request)
			if err != nil {
				t.Fatalf("get scoped filtered runtime events: %v", err)
			}
			if len(result.Records) != 0 || result.Summary.FilteredEvents != 0 {
				t.Fatalf("expected scoped filter to avoid metadata-only false positives, got summary=%+v records=%+v", result.Summary, result.Records)
			}
		})
	}
}

func TestGetAWSRuntimeEventsScopesDiagnosticsToFilteredRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 18, 45, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-diagnostics")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-diagnostics", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-diagnostics", AWSRuntimeEventRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
		EventType:    "agent-tool",
		Evidence:     "agent-runtime",
		AgentID:      "runtime-case-triage",
		Resource:     "runtime-case-triage",
		Identity:     "agentcore-case-triage-runtime",
		Owner:        "security",
		Status:       "observed",
	})
	if err != nil {
		t.Fatalf("get filtered degraded runtime events: %v", err)
	}
	if len(result.Records) != 1 || result.Records[0].EventID != "evt-agent-tool" {
		t.Fatalf("expected only the filtered agent event, got %+v", result.Records)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("expected delayed s3 diagnostic to be omitted from agent-only response, got %+v", result.Diagnostics)
	}

	unfiltered, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-diagnostics", AWSRuntimeEventRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("get unfiltered degraded runtime events: %v", err)
	}
	if len(unfiltered.Diagnostics) != 1 || unfiltered.Diagnostics[0].SourceID != "evt-s3-access" {
		t.Fatalf("expected unfiltered degraded response to retain source diagnostic, got %+v", unfiltered.Diagnostics)
	}
}

func TestRouterAWSRuntimeEventsHandlesFailureStates(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 19, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-router")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-router", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	for _, tc := range []struct {
		state      string
		wantStatus string
		wantCode   int
	}{
		{state: "empty", wantStatus: "degraded", wantCode: http.StatusOK},
		{state: "partial_failure", wantStatus: "degraded", wantCode: http.StatusOK},
		{state: "permission_denied", wantStatus: "blocked", wantCode: http.StatusOK},
		{state: "invalid_state", wantCode: http.StatusBadRequest},
	} {
		resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-runtime-router/aws/runtime-events?connector_id=aws-prod&fixture_state="+tc.state, "")
		if resp.Code != tc.wantCode {
			t.Fatalf("state %s expected HTTP %d, got %d body=%s", tc.state, tc.wantCode, resp.Code, resp.Body.String())
		}
		if tc.wantCode != http.StatusOK {
			continue
		}
		var body struct {
			Runtime AWSRuntimeEventResult `json:"runtime"`
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode runtime response for %s: %v", tc.state, err)
		}
		if body.Runtime.Status != tc.wantStatus {
			t.Fatalf("state %s expected status %q, got %+v", tc.state, tc.wantStatus, body.Runtime)
		}
		if len(body.Runtime.Records) == 0 && tc.state == "partial_failure" {
			t.Fatalf("partial failure should retain successful runtime events: %+v", body.Runtime)
		}
	}
}
