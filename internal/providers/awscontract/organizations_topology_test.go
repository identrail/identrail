package awscontract

import (
	"reflect"
	"testing"
	"time"
)

func sampleOrganizationsTopologyConfig() OrganizationsTopologyConfig {
	return OrganizationsTopologyConfig{
		ConnectorID:         "aws-prod",
		OrganizationID:      "o-example",
		ManagementAccountID: "111111111111",
		Partition:           "aws",
		OrganizationalUnits: []OrganizationUnit{
			{ID: "r-root", Name: "Root", Path: "/", Enabled: true},
			{ID: "ou-prod", Name: "Production", ParentID: "r-root", Path: "/Production", Enabled: true},
			{ID: "ou-data", Name: "Data", ParentID: "r-root", Path: "/Data", Enabled: true},
			{ID: "ou-sandbox", Name: "Sandbox", ParentID: "r-root", Path: "/Sandbox", Enabled: false, Reason: "sandbox OU disabled for scans"},
		},
		Accounts: []OrganizationAccount{
			{AccountID: "111111111111", Name: "management", ParentID: "r-root", Status: OrganizationAccountActive, ConnectorScoped: true},
			{AccountID: "222222222222", Name: "production", ParentID: "ou-prod", Status: OrganizationAccountActive, ConnectorScoped: true, DelegatedAdminServices: []string{"guardduty.amazonaws.com", "securityhub.amazonaws.com"}},
			{AccountID: "333333333333", Name: "data", ParentID: "ou-data", Status: OrganizationAccountActive, ConnectorScoped: true},
			{AccountID: "444444444444", Name: "retired-sandbox", ParentID: "ou-sandbox", Status: OrganizationAccountSuspended, ConnectorScoped: true},
		},
	}
}

func TestPlanOrganizationsTopologyIsDeterministic(t *testing.T) {
	now := time.Date(2026, 6, 12, 1, 0, 0, 0, time.UTC)
	first, err := PlanOrganizationsTopology(sampleOrganizationsTopologyConfig(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := PlanOrganizationsTopology(sampleOrganizationsTopologyConfig(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("organizations topology is not deterministic")
	}
	if first.Version != OrganizationsTopologyVersion {
		t.Fatalf("expected version %q, got %q", OrganizationsTopologyVersion, first.Version)
	}
}

func TestPlanOrganizationsTopologyMapsAccountsOUsAndRelationships(t *testing.T) {
	topology, err := PlanOrganizationsTopology(sampleOrganizationsTopologyConfig(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if topology.Summary.AccountCount != 4 || topology.Summary.OrganizationalUnitCount != 4 {
		t.Fatalf("unexpected summary counts: %+v", topology.Summary)
	}
	if topology.Summary.ManagementAccountCount != 1 || topology.Summary.DelegatedAdminAccountCount != 1 {
		t.Fatalf("expected management and delegated admin indicators, got %+v", topology.Summary)
	}
	if topology.Summary.SuspendedAccountCount != 1 || topology.Summary.ScanEligibleAccounts != 3 {
		t.Fatalf("expected explicit suspended and scan-eligible counts, got %+v", topology.Summary)
	}
	if len(topology.Relationships) != 7 {
		t.Fatalf("expected 7 parent relationships, got %d: %+v", len(topology.Relationships), topology.Relationships)
	}
	byAccount := map[string]OrganizationAccount{}
	for _, account := range topology.Accounts {
		byAccount[account.AccountID] = account
	}
	if byAccount["222222222222"].OUPath != "/Production" {
		t.Fatalf("expected OU path from parent relationship, got %+v", byAccount["222222222222"])
	}
	if byAccount["444444444444"].State != CoverageStateDisabled || byAccount["444444444444"].ScanEligible {
		t.Fatalf("suspended account should be disabled and ineligible, got %+v", byAccount["444444444444"])
	}
}

func TestPlanOrganizationsTopologyCheckpointsAndStaleDisabledState(t *testing.T) {
	observed := time.Date(2026, 6, 11, 8, 0, 0, 0, time.UTC)
	config := sampleOrganizationsTopologyConfig()
	config.Checkpoints = []OrganizationsCheckpoint{
		{AccountID: "222222222222", State: CoverageStatePermissionDenied, FailureReason: "AccessDenied: organizations:ListParents denied", ObservedAt: observed},
		{AccountID: "333333333333", State: CoverageStateInProgress, Cursor: "account-page-3", Attempts: 1},
		{AccountID: "111111111111", State: CoverageStateDisabled},
	}
	topology, err := PlanOrganizationsTopology(config, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byAccount := map[string]OrganizationAccount{}
	for _, account := range topology.Accounts {
		byAccount[account.AccountID] = account
	}
	denied := byAccount["222222222222"]
	if denied.State != CoverageStatePermissionDenied || denied.FailureReason == "" || !denied.ObservedAt.Equal(observed) {
		t.Fatalf("permission denied checkpoint was not applied: %+v", denied)
	}
	inProgress := byAccount["333333333333"]
	if inProgress.State != CoverageStateInProgress || inProgress.Cursor != "account-page-3" || !inProgress.Resumable {
		t.Fatalf("in-progress checkpoint was not resumable: %+v", inProgress)
	}
	management := byAccount["111111111111"]
	if management.State == CoverageStateDisabled {
		t.Fatalf("enabled account should ignore stale disabled checkpoint: %+v", management)
	}
	if topology.Summary.PermissionDeniedAccounts != 1 || topology.Summary.ResumableAccounts != 1 {
		t.Fatalf("unexpected checkpoint summary: %+v", topology.Summary)
	}
}

func TestPlanOrganizationsTopologyEmptyConfig(t *testing.T) {
	topology, err := PlanOrganizationsTopology(OrganizationsTopologyConfig{}, time.Now())
	if err != nil {
		t.Fatalf("empty config should not error: %v", err)
	}
	if len(topology.Accounts) != 0 || len(topology.OrganizationalUnits) != 0 || topology.Summary.AccountCount != 0 {
		t.Fatalf("expected empty topology, got %+v", topology)
	}
	if topology.Partition != "aws" {
		t.Fatalf("expected default aws partition, got %q", topology.Partition)
	}
}

func TestPlanOrganizationsTopologyRejectsInvalidInput(t *testing.T) {
	if _, err := PlanOrganizationsTopology(OrganizationsTopologyConfig{
		Accounts: []OrganizationAccount{{AccountID: "not-an-account", ConnectorScoped: true}},
	}, time.Now()); err == nil {
		t.Fatal("expected invalid account id error")
	}
	if _, err := PlanOrganizationsTopology(OrganizationsTopologyConfig{
		OrganizationalUnits: []OrganizationUnit{{Name: "missing-id"}},
	}, time.Now()); err == nil {
		t.Fatal("expected missing OU id error")
	}
	if _, err := PlanOrganizationsTopology(OrganizationsTopologyConfig{
		Checkpoints: []OrganizationsCheckpoint{{AccountID: "111111111111", State: CoverageState("bogus")}},
	}, time.Now()); err == nil {
		t.Fatal("expected invalid checkpoint state error")
	}
}
