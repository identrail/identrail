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

func TestGetAWSOrganizationsTopologySuccess(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 14, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get organizations topology: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready topology, got %+v", result)
	}
	if result.CurrentIssueRef != "#1498" || result.Version == "" || result.OrganizationID == "" {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.Summary.AccountCount != 4 || result.Summary.OrganizationalUnitCount != 4 {
		t.Fatalf("unexpected topology counts: %+v", result.Summary)
	}
	if result.Summary.ManagementAccountCount != 1 || result.Summary.DelegatedAdminAccountCount != 2 {
		t.Fatalf("expected management and delegated admin counts, got %+v", result.Summary)
	}
	if result.Summary.SuspendedAccountCount != 1 || result.Summary.ScanEligibleAccounts != 3 {
		t.Fatalf("expected suspended and eligible account counts, got %+v", result.Summary)
	}
	if len(result.Relationships) == 0 {
		t.Fatalf("expected parent relationships")
	}
	for _, account := range result.Accounts {
		if account.State == "" || account.EvidenceRef == "" || account.NextAction == "" {
			t.Fatalf("account missing explicit state/evidence/action: %+v", account)
		}
	}
}

func TestGetAWSOrganizationsTopologyFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 14, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	filtered, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{
		ConnectorID: "aws-prod",
		OU:          "/Production",
		State:       "covered",
		Status:      "active",
	})
	if err != nil {
		t.Fatalf("get filtered organizations topology: %v", err)
	}
	if filtered.FilteredAccounts != 1 {
		t.Fatalf("expected one filtered account, got %d", filtered.FilteredAccounts)
	}
	if filtered.Accounts[0].OUPath != "/Production" || filtered.Accounts[0].State != "covered" || filtered.Accounts[0].Status != "active" {
		t.Fatalf("filter returned wrong account: %+v", filtered.Accounts[0])
	}
	if _, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{ConnectorID: "aws-prod", State: "bogus"}); err == nil {
		t.Fatalf("expected invalid state filter error")
	}
	if _, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{ConnectorID: "aws-prod", Status: "bogus"}); err == nil {
		t.Fatalf("expected invalid status filter error")
	}
}

func TestGetAWSOrganizationsTopologyFiltersPendingStatuses(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 17, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	for _, status := range []string{"pending_activation", "pending_closure"} {
		status := status
		result, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{
			ConnectorID: "aws-prod",
			Status:      status,
		})
		if err != nil {
			t.Fatalf("pending status %q should be accepted: %v", status, err)
		}
		if result.FilteredAccounts != 0 {
			t.Fatalf("expected no matched accounts for %q with fixture dataset, got %d", status, result.FilteredAccounts)
		}
	}
}

func TestGetAWSOrganizationsTopologyEmptyDegradedAndDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	empty, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{ConnectorID: "aws-prod", FixtureState: "empty"})
	if err != nil {
		t.Fatalf("get empty topology: %v", err)
	}
	if empty.Status != awsPlatformDependencyStatusReady || empty.Summary.AccountCount != 0 || len(empty.RemediationHints) == 0 {
		t.Fatalf("expected ready empty topology with hint, got %+v", empty)
	}

	degraded, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{ConnectorID: "aws-prod", FixtureState: "partial_failure"})
	if err != nil {
		t.Fatalf("get degraded topology: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || degraded.Summary.FailedAccounts == 0 || degraded.Summary.ResumableAccounts == 0 {
		t.Fatalf("expected degraded resumable topology, got %+v", degraded)
	}

	denied, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get denied topology: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked || denied.Summary.PermissionDeniedAccounts == 0 || len(denied.Diagnostics) == 0 {
		t.Fatalf("expected blocked permission-denied topology, got %+v", denied)
	}
}

func TestGetAWSOrganizationsTopologyNeverLeaksPayloads(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSOrganizationsTopology(ctx, "default", "project-a", AWSOrganizationsTopologyRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get organizations topology: %v", err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"@", "secretstring", "plaintext", "password=", "=sk-", "database row", "object content"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("payload-like content leaked into topology: %s", payload)
		}
	}
}

func TestBuildAWSOrganizationsTopologyLiveFailureUsesEmptyCollections(t *testing.T) {
	now := time.Date(2026, 6, 12, 15, 45, 0, 0, time.UTC)
	result := buildAWSOrganizationsTopologyLiveFailure(
		db.Scope{TenantID: "tenant-a"},
		db.TenancyProject{WorkspaceID: "workspace-a", ProjectID: "project-a"},
		AWSConnectionStatus{ConnectorID: "aws-prod", AccountID: "123456789012", Region: "us-east-1"},
		AWSOrganizationsTopologyRequest{ConnectorID: "aws-prod"},
		now,
		"organizations_discovery_failed",
	)

	if result.Accounts == nil || result.OrganizationalUnits == nil || result.Relationships == nil || result.EvidenceLinks == nil || result.CoverageGaps == nil {
		t.Fatalf("live failure must preserve array-shaped API fields: %+v", result)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal live failure: %v", err)
	}
	for _, field := range []string{`"accounts":[]`, `"organizational_units":[]`, `"relationships":[]`, `"evidence_links":[]`, `"coverage_gaps":[]`} {
		if !strings.Contains(string(payload), field) {
			t.Fatalf("expected %s in live failure payload: %s", field, payload)
		}
	}
}

// TestAWSOrganizationsTopologyConnectorScopePredicate locks in the rule that
// ConnectorScoped reflects the connector's own scope. Before the fix, live
// inventory reported every Organizations account as scan-eligible for the
// connector, which let downstream rollout planning pick up accounts outside
// the operator's approved list.
func TestAWSOrganizationsTopologyConnectorScopePredicate(t *testing.T) {
	snapshot := AWSOrganizationInventorySnapshot{
		Accounts: []AWSOrganizationInventoryAccount{
			{AccountID: "111111111111", AncestorIDs: []string{"ou-a", "r-root"}},
			{AccountID: "222222222222", AncestorIDs: []string{"ou-b", "r-root"}},
			{AccountID: "333333333333", AncestorIDs: []string{"ou-c", "r-root"}},
		},
	}
	cases := []struct {
		name       string
		connection AWSConnectionStatus
		want       map[string]bool
	}{
		{
			name: "organization covers everything except excluded",
			connection: AWSConnectionStatus{
				ScopeType:          AWSConnectorScopeOrganization,
				ExcludedAccountIDs: []string{"333333333333"},
			},
			want: map[string]bool{"111111111111": true, "222222222222": true, "333333333333": false},
		},
		{
			name: "selected_ous covers only accounts under target OUs",
			connection: AWSConnectionStatus{
				ScopeType:   AWSConnectorScopeSelectedOUs,
				TargetOUIDs: []string{"ou-a"},
			},
			want: map[string]bool{"111111111111": true, "222222222222": false, "333333333333": false},
		},
		{
			name: "selected_accounts covers only explicit account list",
			connection: AWSConnectionStatus{
				ScopeType:        AWSConnectorScopeSelectedAccounts,
				TargetAccountIDs: []string{"222222222222"},
			},
			want: map[string]bool{"111111111111": false, "222222222222": true, "333333333333": false},
		},
		{
			name: "single_account restricts to the connection's own account",
			connection: AWSConnectionStatus{
				ScopeType: AWSConnectorScopeSingleAccount,
				AccountID: "111111111111",
			},
			want: map[string]bool{"111111111111": true, "222222222222": false, "333333333333": false},
		},
		{
			name:       "unknown scope fails closed",
			connection: AWSConnectionStatus{},
			want:       map[string]bool{"111111111111": false, "222222222222": false, "333333333333": false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scoped := awsOrganizationsTopologyConnectorScopePredicate(tc.connection, snapshot)
			for _, account := range snapshot.Accounts {
				got := scoped(account)
				if got != tc.want[account.AccountID] {
					t.Fatalf("account %s: want %v, got %v", account.AccountID, tc.want[account.AccountID], got)
				}
			}
		})
	}
}

func TestRouterAWSOrganizationsTopologyPartialFailureAndInvalid(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/organizations-topology?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Topology AWSOrganizationsTopologyResult `json:"topology"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Topology.Status != awsPlatformDependencyStatusDegraded || body.Topology.Summary.FailedAccounts == 0 {
		t.Fatalf("expected degraded partial topology, got %+v", body.Topology)
	}

	for _, query := range []string{"fixture_state=bogus", "state=bogus", "status=bogus"} {
		bad := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/organizations-topology?connector_id=aws-prod&"+query, "")
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d body=%s", query, bad.Code, bad.Body.String())
		}
	}
}
