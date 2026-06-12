package awscontract

import (
	"reflect"
	"testing"
	"time"
)

func sampleCoverageConfig() CoveragePlanConfig {
	return CoveragePlanConfig{
		ConnectorID: "aws-conn-1",
		Accounts: []CoverageAccount{
			{AccountID: "111111111111", Name: "prod", Enabled: true, Priority: CoveragePriorityCritical, Reason: "production estate"},
			{AccountID: "222222222222", Name: "sandbox", Enabled: false, Reason: "decommissioned"},
		},
		Regions: []CoverageRegion{
			{Region: "us-east-1", Enabled: true, Priority: CoveragePriorityHigh},
			{Region: "eu-west-1", Enabled: true},
		},
		Services: []CoverageService{
			{Service: "iam", Enabled: true, Priority: CoveragePriorityCritical, Global: true},
			{Service: "lambda", Enabled: true, Priority: CoveragePriorityNormal},
		},
	}
}

func TestPlanCoverageIsDeterministic(t *testing.T) {
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	first, err := PlanCoverage(sampleCoverageConfig(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := PlanCoverage(sampleCoverageConfig(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("plan is not deterministic across identical inputs")
	}
	if first.Version != CoveragePlannerVersion {
		t.Fatalf("expected version %q, got %q", CoveragePlannerVersion, first.Version)
	}
}

func TestPlanCoverageGlobalServicePlannedOncePerAccount(t *testing.T) {
	now := time.Now().UTC()
	plan, err := PlanCoverage(sampleCoverageConfig(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 accounts: iam (global -> 1 region each) + lambda (2 regions each) = 2*(1+2) = 6.
	if len(plan.Targets) != 6 {
		t.Fatalf("expected 6 targets, got %d", len(plan.Targets))
	}
	iamRegions := map[string]int{}
	for _, target := range plan.Targets {
		if target.Service != "iam" {
			continue
		}
		if !target.Global {
			t.Fatalf("iam target should be marked global")
		}
		iamRegions[target.AccountID]++
		if target.Region != defaultGlobalServiceHomeRegion {
			t.Fatalf("global iam target should pin home region, got %q", target.Region)
		}
	}
	for accountID, count := range iamRegions {
		if count != 1 {
			t.Fatalf("account %s has %d iam targets, want 1", accountID, count)
		}
	}
}

func TestPlanCoverageDisabledDimensionDisablesTarget(t *testing.T) {
	now := time.Now().UTC()
	plan, err := PlanCoverage(sampleCoverageConfig(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, target := range plan.Targets {
		if target.AccountID == "222222222222" {
			if target.Enabled {
				t.Fatalf("disabled account target should not be enabled: %s", target.Key)
			}
			if target.State != CoverageStateDisabled {
				t.Fatalf("disabled account target state should be disabled, got %q", target.State)
			}
		}
	}
	if plan.Summary.DisabledTargets != 3 {
		t.Fatalf("expected 3 disabled targets for sandbox account, got %d", plan.Summary.DisabledTargets)
	}
	if plan.Summary.EnabledTargets != 3 {
		t.Fatalf("expected 3 enabled targets for prod account, got %d", plan.Summary.EnabledTargets)
	}
}

func TestPlanCoverageMostUrgentPriorityWins(t *testing.T) {
	now := time.Now().UTC()
	config := CoveragePlanConfig{
		Accounts: []CoverageAccount{{AccountID: "111111111111", Enabled: true, Priority: CoveragePriorityLow}},
		Regions:  []CoverageRegion{{Region: "us-east-1", Enabled: true, Priority: CoveragePriorityNormal}},
		Services: []CoverageService{{Service: "iam", Enabled: true, Priority: CoveragePriorityCritical}},
	}
	plan, err := PlanCoverage(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(plan.Targets))
	}
	if plan.Targets[0].Priority != CoveragePriorityCritical || plan.Targets[0].PriorityRank != 0 {
		t.Fatalf("expected critical priority to win, got %q (rank %d)", plan.Targets[0].Priority, plan.Targets[0].PriorityRank)
	}
}

func TestPlanCoverageOrdersByPriorityThenKey(t *testing.T) {
	now := time.Now().UTC()
	plan, err := PlanCoverage(sampleCoverageConfig(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 1; i < len(plan.Targets); i++ {
		prev, cur := plan.Targets[i-1], plan.Targets[i]
		if prev.PriorityRank > cur.PriorityRank {
			t.Fatalf("targets not ordered by priority rank at %d", i)
		}
		if prev.PriorityRank == cur.PriorityRank && prev.Key > cur.Key {
			t.Fatalf("targets not ordered by key within priority at %d", i)
		}
	}
}

func TestPlanCoveragePrerequisitesBlockTarget(t *testing.T) {
	now := time.Now().UTC()
	config := CoveragePlanConfig{
		Accounts: []CoverageAccount{{AccountID: "111111111111", Enabled: true, Management: true}},
		Regions:  []CoverageRegion{{Region: "ap-east-1", Enabled: true, OptIn: true}},
		Services: []CoverageService{{Service: "iam", Enabled: true, Global: false}},
	}
	plan, err := PlanCoverage(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	target := plan.Targets[0]
	if target.State != CoverageStateBlocked {
		t.Fatalf("expected blocked target, got %q", target.State)
	}
	if len(target.Prerequisites) != 2 {
		t.Fatalf("expected derived opt-in + management prerequisites, got %v", target.Prerequisites)
	}
	if plan.Summary.BlockedTargets != 1 {
		t.Fatalf("expected 1 blocked target, got %d", plan.Summary.BlockedTargets)
	}
}

func TestPlanCoverageCheckpointResumes(t *testing.T) {
	now := time.Now().UTC()
	observed := time.Date(2026, 6, 11, 9, 0, 0, 0, time.UTC)
	config := sampleCoverageConfig()
	config.Checkpoints = []CoverageCheckpoint{
		{AccountID: "111111111111", Region: "us-east-1", Service: "iam", State: CoverageStateCovered, ObservedAt: observed},
		{AccountID: "111111111111", Region: "eu-west-1", Service: "lambda", State: CoverageStateInProgress, Cursor: "page-2", Attempts: 1},
		{AccountID: "111111111111", Region: "us-east-1", Service: "lambda", State: CoverageStateFailed, FailureReason: "throttled", Attempts: 3},
		// Checkpoint for a disabled target must not resurrect it.
		{AccountID: "222222222222", Region: "us-east-1", Service: "lambda", State: CoverageStateCovered},
	}
	plan, err := PlanCoverage(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byKey := map[string]CoverageTarget{}
	for _, target := range plan.Targets {
		byKey[target.Key] = target
	}
	covered := byKey["111111111111|us-east-1|iam"]
	if covered.State != CoverageStateCovered || covered.Resumable {
		t.Fatalf("covered target wrong: %+v", covered)
	}
	if !covered.ObservedAt.Equal(observed) {
		t.Fatalf("covered target should keep observed time, got %v", covered.ObservedAt)
	}
	inProgress := byKey["111111111111|eu-west-1|lambda"]
	if inProgress.State != CoverageStateInProgress || inProgress.Cursor != "page-2" || !inProgress.Resumable {
		t.Fatalf("in-progress target wrong: %+v", inProgress)
	}
	failed := byKey["111111111111|us-east-1|lambda"]
	if failed.State != CoverageStateFailed || failed.FailureReason != "throttled" || failed.Attempts != 3 {
		t.Fatalf("failed target wrong: %+v", failed)
	}
	disabled := byKey["222222222222|us-east-1|lambda"]
	if disabled.State != CoverageStateDisabled || disabled.Enabled {
		t.Fatalf("disabled target should ignore checkpoint: %+v", disabled)
	}
	if plan.Summary.CoveredTargets != 1 || plan.Summary.FailedTargets != 1 || plan.Summary.ResumableTargets != 2 {
		t.Fatalf("summary counts wrong: %+v", plan.Summary)
	}
	// Coverage percent = covered (1) / enabled (3) -> 33.33.
	if plan.Summary.CoveragePercent < 33.32 || plan.Summary.CoveragePercent > 33.34 {
		t.Fatalf("unexpected coverage percent: %v", plan.Summary.CoveragePercent)
	}
}

func TestPlanCoverageEmptyConfig(t *testing.T) {
	plan, err := PlanCoverage(CoveragePlanConfig{}, time.Now())
	if err != nil {
		t.Fatalf("empty config should not error, got %v", err)
	}
	if len(plan.Targets) != 0 {
		t.Fatalf("expected no targets, got %d", len(plan.Targets))
	}
	if plan.Summary.CoveragePercent != 0 {
		t.Fatalf("expected zero coverage percent, got %v", plan.Summary.CoveragePercent)
	}
	if plan.Targets == nil {
		t.Fatalf("targets should be a non-nil empty slice for stable JSON")
	}
}

func TestPlanCoverageDeduplicatesDimensions(t *testing.T) {
	now := time.Now().UTC()
	config := CoveragePlanConfig{
		Accounts: []CoverageAccount{
			{AccountID: "111111111111", Enabled: true},
			{AccountID: " 111111111111 ", Enabled: false},
		},
		Regions: []CoverageRegion{
			{Region: "us-east-1", Enabled: true},
			{Region: "US-EAST-1", Enabled: true},
		},
		Services: []CoverageService{
			{Service: "iam", Enabled: true},
			{Service: "IAM", Enabled: true},
		},
	}
	plan, err := PlanCoverage(config, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Targets) != 1 {
		t.Fatalf("expected dimensions deduped to 1 target, got %d", len(plan.Targets))
	}
	if !plan.Targets[0].Enabled {
		t.Fatalf("first account occurrence should win and stay enabled")
	}
}

func TestPlanCoverageRejectsInvalidAccountID(t *testing.T) {
	_, err := PlanCoverage(CoveragePlanConfig{
		Accounts: []CoverageAccount{{AccountID: "123", Enabled: true}},
		Regions:  []CoverageRegion{{Region: "us-east-1", Enabled: true}},
		Services: []CoverageService{{Service: "iam", Enabled: true}},
	}, time.Now())
	if err == nil {
		t.Fatalf("expected error for invalid account id")
	}
}

func TestPlanCoverageRejectsInvalidCheckpointState(t *testing.T) {
	config := sampleCoverageConfig()
	config.Checkpoints = []CoverageCheckpoint{{AccountID: "111111111111", Region: "us-east-1", Service: "iam", State: "bogus"}}
	if _, err := PlanCoverage(config, time.Now()); err == nil {
		t.Fatalf("expected error for invalid checkpoint state")
	}
}

func TestDefaultCoverageServicesHasGlobalIAM(t *testing.T) {
	services := DefaultCoverageServices()
	if len(services) == 0 {
		t.Fatalf("expected default services")
	}
	var iam *CoverageService
	for i := range services {
		if services[i].Service == "iam" {
			iam = &services[i]
		}
	}
	if iam == nil || !iam.Global {
		t.Fatalf("expected default IAM service to be global")
	}
}

func TestNormalizeCoveragePriorityDefaultsToNormal(t *testing.T) {
	if got := NormalizeCoveragePriority(""); got != CoveragePriorityNormal {
		t.Fatalf("expected normal default, got %q", got)
	}
	if got := NormalizeCoveragePriority("CRITICAL"); got != CoveragePriorityCritical {
		t.Fatalf("expected critical, got %q", got)
	}
}
