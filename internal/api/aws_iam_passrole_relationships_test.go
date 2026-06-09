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

func TestGetAWSIAMPassRoleRelationshipInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 8, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSIAMPassRoleRelationshipInventory(ctx, "default", "project-a", AWSIAMPassRoleRelationshipInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get iam passrole inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1487" || result.Version != awsIAMPassRoleRelationshipVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.SourceRoleCount == 0 || result.WildcardTargetCount == 0 || result.DenyStatementCount == 0 {
		t.Fatalf("expected source/wildcard/deny counts populated, got %+v", result)
	}
	if result.ServiceScopedCount == 0 || result.UnscopedCount == 0 {
		t.Fatalf("expected both service-scoped and unscoped grants in fixture, got %+v", result)
	}
	for _, record := range result.Records {
		evidence := strings.ToLower(record.EvidenceRef + " " + record.Source)
		if strings.Contains(evidence, "secret") || strings.Contains(evidence, "presigned") {
			t.Fatalf("expected metadata-only evidence, got %+v", record)
		}
		switch record.TargetWildcardKind {
		case "specific", "path_wildcard", "account_wildcard", "all", "malformed":
		default:
			t.Fatalf("unexpected wildcard kind %q on %+v", record.TargetWildcardKind, record)
		}
		if record.Confidence <= 0 || record.Confidence > 1 {
			t.Fatalf("confidence out of bounds: %v", record.Confidence)
		}
	}
}

func TestRouterAWSIAMPassRoleRelationshipInventoryPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 8, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/iam-passrole-relationships?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSIAMPassRoleRelationshipInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected degraded partial_failure, got status=%q fixture=%q", body.Inventory.Status, body.Inventory.FixtureState)
	}
	if body.Inventory.RecordCount == 0 {
		t.Fatalf("expected partial failure to retain some records, got 0")
	}
	foundDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "iam_passrole_page_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected iam_passrole_page_failed diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSIAMPassRoleRelationshipInventoryPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 8, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/iam-passrole-relationships?connector_id=aws-prod&fixture_state=permission_denied", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSIAMPassRoleRelationshipInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusBlocked {
		t.Fatalf("expected blocked status, got %q", body.Inventory.Status)
	}
	if len(body.Inventory.Records) != 0 {
		t.Fatalf("expected no records on permission_denied, got %d", len(body.Inventory.Records))
	}
}

func TestRouterAWSIAMPassRoleRelationshipInventoryInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 8, 16, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-3")
	seedAWSConnectorForScanTest(t, store, ctx, "project-3", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-3/aws/iam-passrole-relationships?connector_id=aws-prod&fixture_state=invalid", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid fixture state, got %d", resp.Code)
	}
}

func TestAWSIAMPassRoleFixtureUsesGovCloudPartition(t *testing.T) {
	records, _, _ := awsIAMPassRoleRelationshipFixtureRecords("123456789012", "us-gov-west-1", "success", time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC))
	if len(records) == 0 {
		t.Fatalf("expected fixture records, got 0")
	}
	for _, record := range records {
		if record.TargetResource == "*" {
			continue
		}
		if !strings.HasPrefix(record.SourceRoleARN, "arn:aws-us-gov:iam::") {
			t.Fatalf("expected GovCloud source role ARN, got %q", record.SourceRoleARN)
		}
	}
}

func TestNormalizeAWSIAMPassRoleFixtureStateHonorsExplicitOverride(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSIAMPassRoleRelationshipFixtureState("success", disconnected, true); got != "success" {
		t.Fatalf("explicit success must not downgrade, got %q", got)
	}
	if got := normalizeAWSIAMPassRoleRelationshipFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("blank with disconnected should be permission_denied, got %q", got)
	}
	if got := normalizeAWSIAMPassRoleRelationshipFixtureState("invalid", disconnected, true); got != "" {
		t.Fatalf("invalid should return empty, got %q", got)
	}
}

func TestAWSIAMPassRoleRelationshipEdgesExcludeUnresolvedAndDeny(t *testing.T) {
	records := []AWSIAMPassRoleRelationshipRecord{
		{
			FromNodeID:         "aws:identity:arn:aws:iam::123:role/source",
			ToNodeID:           "aws:identity:arn:aws:iam::123:role/target",
			RelationshipType:   "can_pass_role",
			Effect:             "Allow",
			UnresolvedTarget:   false,
			EvidenceRef:        "evidence-1",
			TargetWildcardKind: "specific",
		},
		{
			FromNodeID:         "aws:identity:arn:aws:iam::123:role/source",
			ToNodeID:           "",
			RelationshipType:   "can_pass_role",
			Effect:             "Allow",
			UnresolvedTarget:   true,
			TargetWildcardKind: "all",
		},
		{
			FromNodeID:         "aws:identity:arn:aws:iam::123:role/source",
			ToNodeID:           "aws:identity:arn:aws:iam::123:role/break-glass",
			RelationshipType:   "can_pass_role",
			Effect:             "Deny",
			UnresolvedTarget:   false,
			TargetWildcardKind: "specific",
		},
	}
	edges := awsIAMPassRoleRelationshipEdges(records)
	if len(edges) != 1 {
		t.Fatalf("expected only the Allow+resolved record to produce an edge, got %d (%+v)", len(edges), edges)
	}
	if edges[0].EvidenceRef != "evidence-1" {
		t.Fatalf("unexpected edge: %+v", edges[0])
	}
}

// Note: the route's nil-logger guard is small and obvious. Exercising the
// default 500 branch with a nil logger requires forcing
// GetAWSIAMPassRoleRelationshipInventory to return a non-ErrNotFound, non-
// ErrInvalidAWSConnectionRequest error from inside the service. The Service
// type is concrete and has no error-injection hooks, so the previous
// "fixture_state=success" assertion never actually reached the logger.Error
// call and was deleted rather than left as false coverage. The production
// guard remains; reintroduce a real test once Service grows a seam for
// mocking error returns.

func TestAWSIAMPassRoleWildcardKindClassifiesMalformedTargets(t *testing.T) {
	cases := map[string]string{
		// Valid IAM role ARNs.
		"arn:aws:iam::123456789012:role/payments":        "specific",
		"arn:aws-us-gov:iam::123456789012:role/payments": "specific",
		"arn:aws:iam::123456789012:role/payments-*":      "path_wildcard",
		"arn:aws:iam::*:role/payments":                   "account_wildcard",
		"*":                                              "all",
		// Non-IAM ARNs must reject — otherwise edges would point at non-role
		// resources.
		"arn:aws:s3:::bucket": "malformed",
		"arn:aws:lambda:us-east-1:123456789012:function:payments": "malformed",
		"arn:aws:iam::123456789012:user/dev":                      "malformed",
		// Non-ARN inputs.
		"not-an-arn":    "malformed",
		"role/payments": "malformed",
		"":              "malformed",
	}
	for input, want := range cases {
		if got := awsIAMPassRoleWildcardKind(input); got != want {
			t.Fatalf("awsIAMPassRoleWildcardKind(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAWSIAMPassRoleConfidenceForMalformedIsLowest(t *testing.T) {
	specific := awsIAMPassRoleConfidenceFor("specific")
	malformed := awsIAMPassRoleConfidenceFor("malformed")
	all := awsIAMPassRoleConfidenceFor("all")
	if !(malformed < all && malformed < specific) {
		t.Fatalf("expected malformed confidence < all < specific, got malformed=%v all=%v specific=%v", malformed, all, specific)
	}
}
