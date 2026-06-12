package awscontract

import (
	"reflect"
	"testing"
	"time"
)

func sampleStackSetConfig() StackSetOnboardingConfig {
	return StackSetOnboardingConfig{
		ConnectorID:         "aws-conn-1",
		OrganizationID:      "o-test",
		ManagementAccountID: "111111111111",
		StackSetName:        "identrail-readonly-connector-stackset",
		TemplateURL:         "https://example.invalid/templates/identrail-readonly.yaml",
		TemplateChecksum:    "sha256:00",
		ExternalID:          "external-id-1",
		DeploymentMode:      StackSetDeploymentServiceManaged,
		Partition:           "aws",
		TrustedAccessReady:  true,
		DelegatedAdminReady: true,
		Targets: StackSetOnboardingTargets{
			Accounts: []StackSetOnboardingTargetAccount{
				{AccountID: "111111111111", Name: "mgmt", Management: true},
				{AccountID: "222222222222", Name: "data"},
			},
			Regions: []StackSetOnboardingTargetRegion{
				{Region: "us-east-1"},
				{Region: "eu-west-1"},
			},
		},
	}
}

func TestPlanStackSetOnboardingIsDeterministic(t *testing.T) {
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	first, err := PlanStackSetOnboarding(sampleStackSetConfig(), now)
	if err != nil {
		t.Fatalf("plan err: %v", err)
	}
	second, err := PlanStackSetOnboarding(sampleStackSetConfig(), now)
	if err != nil {
		t.Fatalf("plan err: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("StackSet onboarding plan is not deterministic across identical inputs")
	}
	if first.Version != StackSetOnboardingVersion {
		t.Fatalf("expected version %q, got %q", StackSetOnboardingVersion, first.Version)
	}
}

func TestPlanStackSetOnboardingExpandsAccountRegionMatrix(t *testing.T) {
	now := time.Now().UTC()
	plan, err := PlanStackSetOnboarding(sampleStackSetConfig(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Instances) != 4 {
		t.Fatalf("expected 4 instances (2 accounts x 2 regions), got %d", len(plan.Instances))
	}
	// Sorted by key (account|region) for determinism.
	for i := 1; i < len(plan.Instances); i++ {
		if plan.Instances[i-1].Key > plan.Instances[i].Key {
			t.Fatalf("instances not ordered by key at %d", i)
		}
	}
}

func TestPlanStackSetOnboardingValidationReadyByDefault(t *testing.T) {
	plan, err := PlanStackSetOnboarding(sampleStackSetConfig(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Validation.Status != StackSetValidationReady {
		t.Fatalf("expected ready validation, got %q (failures=%v)", plan.Validation.Status, plan.Validation.FailureReasons)
	}
	if plan.Validation.BlockingCount != 0 {
		t.Fatalf("expected 0 blocking prereqs, got %d", plan.Validation.BlockingCount)
	}
}

func TestPlanStackSetOnboardingBlocksWhenPrerequisitesMissing(t *testing.T) {
	now := time.Now().UTC()
	config := sampleStackSetConfig()
	config.TrustedAccessReady = false
	config.ExternalID = ""
	plan, err := PlanStackSetOnboarding(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Validation.Status != StackSetValidationBlocked {
		t.Fatalf("expected blocked validation, got %q", plan.Validation.Status)
	}
	if plan.Validation.BlockingCount < 2 {
		t.Fatalf("expected at least 2 blocking prereqs, got %d", plan.Validation.BlockingCount)
	}
	// Every instance should also be blocked.
	for _, instance := range plan.Instances {
		if instance.State != StackSetStateBlocked {
			t.Fatalf("expected all instances blocked, got %+v", instance)
		}
		if !instance.Resumable {
			t.Fatalf("blocked instances should be resumable so retry is exposed")
		}
	}
}

func TestPlanStackSetOnboardingSelfManagedRequiresAdminRole(t *testing.T) {
	now := time.Now().UTC()
	config := sampleStackSetConfig()
	config.DeploymentMode = StackSetDeploymentSelfManaged
	config.OperatorRoleARN = ""
	plan, err := PlanStackSetOnboarding(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Validation.Status != StackSetValidationBlocked {
		t.Fatalf("expected blocked self-managed validation, got %q", plan.Validation.Status)
	}
}

func TestPlanStackSetOnboardingSuspendedAccountStaysSuspended(t *testing.T) {
	now := time.Now().UTC()
	config := sampleStackSetConfig()
	config.Targets.Accounts = []StackSetOnboardingTargetAccount{
		{AccountID: "111111111111", Name: "mgmt", Management: true},
		{AccountID: "222222222222", Name: "data", Suspended: true},
	}
	plan, err := PlanStackSetOnboarding(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	suspendedCount := 0
	for _, instance := range plan.Instances {
		if instance.AccountID == "222222222222" {
			if instance.State != StackSetStateSuspended {
				t.Fatalf("expected suspended state, got %q", instance.State)
			}
			suspendedCount++
		}
	}
	if suspendedCount == 0 {
		t.Fatalf("expected suspended instances")
	}
	// Validation should advise about the suspended account.
	if plan.Validation.AdvisoryCount == 0 {
		t.Fatalf("expected advisory prereq for suspended accounts, got %+v", plan.Validation)
	}
}

func TestPlanStackSetOnboardingCheckpointReplays(t *testing.T) {
	now := time.Now().UTC()
	observed := time.Date(2026, 6, 11, 9, 0, 0, 0, time.UTC)
	config := sampleStackSetConfig()
	config.Checkpoints = []StackSetOnboardingCheckpoint{
		{AccountID: "111111111111", Region: "us-east-1", State: StackSetStateActive, StackID: "stack-1", ObservedAt: observed},
		{AccountID: "111111111111", Region: "eu-west-1", State: StackSetStateFailed, FailureReason: "Throttled", Attempts: 2},
		{AccountID: "222222222222", Region: "us-east-1", State: StackSetStatePermissionDenied, FailureReason: "AccessDenied"},
	}
	plan, err := PlanStackSetOnboarding(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byKey := map[string]StackSetOnboardingInstance{}
	for _, instance := range plan.Instances {
		byKey[instance.Key] = instance
	}
	if active := byKey["111111111111|us-east-1"]; active.State != StackSetStateActive || active.Resumable {
		t.Fatalf("active instance wrong: %+v", active)
	}
	if failed := byKey["111111111111|eu-west-1"]; failed.State != StackSetStateFailed || failed.FailureReason != "Throttled" || failed.Attempts != 2 || !failed.Resumable {
		t.Fatalf("failed instance wrong: %+v", failed)
	}
	if denied := byKey["222222222222|us-east-1"]; denied.State != StackSetStatePermissionDenied {
		t.Fatalf("denied instance wrong: %+v", denied)
	}
	if plan.Summary.ActiveInstances != 1 || plan.Summary.FailedInstances != 1 || plan.Summary.PermissionDenied != 1 {
		t.Fatalf("summary wrong: %+v", plan.Summary)
	}
}

func TestPlanStackSetOnboardingRecoveryActionsCoverFailureModes(t *testing.T) {
	now := time.Now().UTC()
	config := sampleStackSetConfig()
	config.Targets.Accounts = append(config.Targets.Accounts, StackSetOnboardingTargetAccount{AccountID: "333333333333", Suspended: true})
	config.Checkpoints = []StackSetOnboardingCheckpoint{
		{AccountID: "111111111111", Region: "us-east-1", State: StackSetStateFailed, FailureReason: "Throttled"},
		{AccountID: "222222222222", Region: "us-east-1", State: StackSetStatePermissionDenied},
	}
	plan, err := PlanStackSetOnboarding(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	actionIDs := map[string]bool{}
	for _, action := range plan.RecoveryActions {
		actionIDs[action.ID] = true
	}
	for _, expected := range []string{"retry-failed-instances", "fix-permission-denied", "remove-suspended-accounts"} {
		if !actionIDs[expected] {
			t.Fatalf("missing recovery action %q in %v", expected, actionIDs)
		}
	}
}

func TestPlanStackSetOnboardingCoverageExpectationProjectsAcrossPlan(t *testing.T) {
	now := time.Now().UTC()
	coverageConfig := CoveragePlanConfig{
		ConnectorID: "aws-conn-1",
		Accounts: []CoverageAccount{
			{AccountID: "111111111111", Enabled: true, Priority: CoveragePriorityCritical},
			{AccountID: "222222222222", Enabled: true},
		},
		Regions: []CoverageRegion{
			{Region: "us-east-1", Enabled: true},
			{Region: "eu-west-1", Enabled: true},
		},
		Services: []CoverageService{
			{Service: "iam", Enabled: true, Global: true},
			{Service: "lambda", Enabled: true},
		},
		Checkpoints: []CoverageCheckpoint{
			{AccountID: "111111111111", Region: "us-east-1", Service: "iam", State: CoverageStateCovered},
		},
	}
	coveragePlan, err := PlanCoverage(coverageConfig, now)
	if err != nil {
		t.Fatalf("coverage plan err: %v", err)
	}
	stackConfig := sampleStackSetConfig()
	stackConfig.CoveragePlan = &coveragePlan
	plan, err := PlanStackSetOnboarding(stackConfig, now)
	if err != nil {
		t.Fatalf("stackset plan err: %v", err)
	}
	// Each account has 1 global iam target + 2 regional lambda targets = 3 enabled.
	// With both accounts in the target set: 6 expected coverage targets.
	if plan.CoverageExpectation.ExpectedCoverage != 6 {
		t.Fatalf("expected 6 coverage targets, got %d", plan.CoverageExpectation.ExpectedCoverage)
	}
	if plan.CoverageExpectation.CoveragePercent <= 0 {
		t.Fatalf("expected non-zero coverage percent, got %v", plan.CoverageExpectation.CoveragePercent)
	}
	// One instance must carry the global IAM count.
	globalInstance := false
	for _, instance := range plan.Instances {
		if instance.AccountID == "111111111111" && instance.Region == "us-east-1" && instance.CoverageTargets >= 2 {
			globalInstance = true
		}
	}
	if !globalInstance {
		t.Fatalf("expected home-region instance to carry global IAM count")
	}
}

func TestPlanStackSetOnboardingDeduplicatesTargets(t *testing.T) {
	now := time.Now().UTC()
	config := sampleStackSetConfig()
	config.Targets.Accounts = append(config.Targets.Accounts, StackSetOnboardingTargetAccount{AccountID: " 111111111111 "})
	config.Targets.Regions = append(config.Targets.Regions, StackSetOnboardingTargetRegion{Region: "US-EAST-1"})
	plan, err := PlanStackSetOnboarding(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Instances) != 4 {
		t.Fatalf("expected dedupe to keep 4 instances, got %d", len(plan.Instances))
	}
}

func TestPlanStackSetOnboardingDeduplicatesAndMergesTargetMetadata(t *testing.T) {
	now := time.Now().UTC()
	config := sampleStackSetConfig()
	config.Targets.Accounts = []StackSetOnboardingTargetAccount{
		{AccountID: "111111111111", Name: "zzz-management", OUPath: "/Alt", Management: false, Suspended: false},
		{AccountID: "111111111111", Name: "aaa-management", OUPath: "/Root", Management: true, Suspended: true},
		{AccountID: "222222222222", Name: "member", OUPath: "/Root"},
	}
	plan, err := PlanStackSetOnboarding(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var deduped StackSetOnboardingTargetAccount
	found := false
	for _, account := range plan.Targets.Accounts {
		if account.AccountID == "111111111111" {
			deduped = account
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected merged account in targets")
	}
	if !deduped.Management || !deduped.Suspended {
		t.Fatalf("expected merged metadata flags to retain true values, got %+v", deduped)
	}
	if deduped.Name != "aaa-management" {
		t.Fatalf("expected deterministic name merge for metadata conflicts, got %q", deduped.Name)
	}
}

func TestPlanStackSetCoverageExpectationDoesNotCountGlobalTargetsWithoutHomeRegion(t *testing.T) {
	now := time.Now().UTC()
	coverageConfig := CoveragePlanConfig{
		ConnectorID: "aws-conn-1",
		Accounts: []CoverageAccount{
			{AccountID: "111111111111", Enabled: true},
		},
		Regions: []CoverageRegion{
			{Region: "eu-west-1", Enabled: true},
		},
		Services: []CoverageService{
			{Service: "iam", Enabled: true, Global: true},
			{Service: "lambda", Enabled: true},
		},
	}
	coveragePlan, err := PlanCoverage(coverageConfig, now)
	if err != nil {
		t.Fatalf("coverage plan err: %v", err)
	}
	planConfig := sampleStackSetConfig()
	planConfig.CoveragePlan = &coveragePlan
	planConfig.Targets.Regions = []StackSetOnboardingTargetRegion{{Region: "eu-west-1"}}
	plan, err := PlanStackSetOnboarding(planConfig, now)
	if err != nil {
		t.Fatalf("stackset plan err: %v", err)
	}
	// Only regional lambda target is expected when global home region (us-east-1) is absent.
	if plan.CoverageExpectation.ExpectedCoverage != 1 {
		t.Fatalf("expected coverage 1 when global home region is not targeted, got %d", plan.CoverageExpectation.ExpectedCoverage)
	}
}

func TestPlanStackSetOnboardingRejectsInvalidAccountID(t *testing.T) {
	config := sampleStackSetConfig()
	config.Targets.Accounts = []StackSetOnboardingTargetAccount{{AccountID: "abc", Name: "bad"}}
	if _, err := PlanStackSetOnboarding(config, time.Now()); err == nil {
		t.Fatalf("expected error for invalid account id")
	}
}

func TestPlanStackSetOnboardingRejectsInvalidCheckpointState(t *testing.T) {
	config := sampleStackSetConfig()
	config.Checkpoints = []StackSetOnboardingCheckpoint{{AccountID: "111111111111", Region: "us-east-1", State: "bogus"}}
	if _, err := PlanStackSetOnboarding(config, time.Now()); err == nil {
		t.Fatalf("expected error for invalid checkpoint state")
	}
}
