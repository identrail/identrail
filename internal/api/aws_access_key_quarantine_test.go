package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newAccessKeyQuarantineService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestAWSAccessKeyQuarantinePlanFromFindingBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 25, 9, 30, 0, 0, time.UTC)
	accessKeyID := "AKIA" + "ORDERS123456"
	finding := AWSUnusedDormantAccessFinding{
		FindingID:      "aws-unused-dormant-access:orders-key",
		DormancyState:  "stale",
		Severity:       "high",
		Status:         "cleanup_candidate",
		Score:          82,
		Confidence:     0.86,
		AccountID:      "123456789012",
		Region:         "us-east-1",
		IdentityNodeID: "aws:identity:user/orders-ci",
		PrincipalARN:   "arn:aws:iam::123456789012:user/orders-ci",
		ResourceNodeID: "aws:iam-access-key:" + accessKeyID,
		DisplayName:    accessKeyID,
		OwnerContext:   "orders-platform",
		Rationale:      "IAM last-used reports stale access key activity.",
		LastUsedAt:     now.Add(-100 * 24 * time.Hour),
		DormantDays:    100,
		CandidateActions: []string{
			"iam:DisableAccessKey",
		},
		ImpactedNodes: []string{"aws:iam-access-key:" + accessKeyID, "aws:identity:user/orders-ci"},
		Evidence: []AWSUnusedDormantAccessEvidence{{
			Source:       "iam_last_used",
			EvidenceRef:  "runtime-evidence://access-key/" + accessKeyID,
			Label:        accessKeyID,
			Confidence:   0.86,
			ObservedAt:   now.Add(-100 * 24 * time.Hour),
			Relationship: "stale_access_key",
		}},
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now,
	}

	plan := awsAccessKeyQuarantinePlanFromFinding(finding, now)
	if plan.PlanID == "" || plan.CalculationVersion != awsAccessKeyQuarantineVersion {
		t.Fatalf("plan missing stable metadata: %+v", plan)
	}
	if plan.QuarantineState != "quarantine_candidate" || plan.Status != "ready_for_quarantine" || !plan.ReadyForApply {
		t.Fatalf("expected ready quarantine candidate: %+v", plan)
	}
	if plan.OwnerNotice.Owner != "orders-platform" || !plan.OwnerNotice.Assigned || plan.GracePeriodDays != 7 {
		t.Fatalf("expected owner notice and grace period: %+v", plan.OwnerNotice)
	}
	if len(plan.TargetAccessKeys) != 1 || plan.TargetAccessKeys[0].AccessKeyID != accessKeyID {
		t.Fatalf("expected access key target: %+v", plan.TargetAccessKeys)
	}
	if !plan.ReadOnlyProjection || !plan.DiffIntent.ReadOnlyProjection || plan.DiffIntent.Kind != "access_key_quarantine" {
		t.Fatalf("plan must remain read-only with quarantine diff intent: %+v", plan.DiffIntent)
	}
	if len(plan.QuarantineOrder) != 5 || plan.RollbackPlan.Strategy == "" || plan.VerificationPlan.Strategy == "" {
		t.Fatalf("plan missing order, rollback, or verification: %+v", plan)
	}
	serialized, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"secret_key\"", "\"access_key_secret\"", "\"private_key\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("plan serialized forbidden sensitive payload marker %q: %s", forbidden, lower)
		}
	}
}

func TestGetAWSAccessKeyQuarantinePlansBuildsAndFilters(t *testing.T) {
	now := time.Date(2026, 6, 25, 9, 35, 0, 0, time.UTC)
	svc, ws := newAccessKeyQuarantineService(t, "project-access-key-quarantine", now)

	result, err := svc.GetAWSAccessKeyQuarantinePlans(defaultScopeContext(), ws, "project-access-key-quarantine", AWSAccessKeyQuarantineRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get access key quarantine plans: %v", err)
	}
	if result.CurrentIssueRef != "#1534" || result.Version != awsAccessKeyQuarantineVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Plans) == 0 {
		t.Fatalf("expected success fixture to produce access key quarantine plans: %+v", result)
	}
	if result.Summary.TotalPlans != len(result.Plans) || len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected summary/caveats/gaps: %+v", result)
	}
	for i := 1; i < len(result.Plans); i++ {
		if result.Plans[i-1].Score < result.Plans[i].Score {
			t.Fatalf("plans are not ranked by descending score: %+v", result.Plans)
		}
	}

	filtered, err := svc.GetAWSAccessKeyQuarantinePlans(defaultScopeContext(), ws, "project-access-key-quarantine", AWSAccessKeyQuarantineRequest{
		ConnectorID:     "aws-prod",
		FixtureState:    "success",
		QuarantineState: "quarantine_candidate",
		Search:          "quarantine_re_evaluate",
	})
	if err != nil {
		t.Fatalf("filtered access key quarantine plans: %v", err)
	}
	if filtered.AppliedFilters["quarantine_state"] != "quarantine-candidate" || filtered.AppliedFilters["search"] != "quarantine_re_evaluate" {
		t.Fatalf("expected applied filters, got %+v", filtered.AppliedFilters)
	}
	for _, plan := range filtered.Plans {
		if plan.QuarantineState != "quarantine_candidate" || !awsAccessKeyQuarantineSearchMatch(plan, "quarantine_re_evaluate") {
			t.Fatalf("filter leaked plan: %+v", plan)
		}
	}

	accessKeyID := "AKIA" + "ORDERS123456"
	keyFiltered, err := svc.GetAWSAccessKeyQuarantinePlans(defaultScopeContext(), ws, "project-access-key-quarantine", AWSAccessKeyQuarantineRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     accessKeyID,
	})
	if err != nil {
		t.Fatalf("access key identity filter: %v", err)
	}
	if len(keyFiltered.Plans) == 0 {
		t.Fatalf("expected identity access key filter to match target key plans: %+v", keyFiltered)
	}
	for _, plan := range keyFiltered.Plans {
		if !awsRuntimeEventMatchesAny(accessKeyID, awsAccessKeyQuarantineIdentityValues(plan)...) {
			t.Fatalf("access key identity filter leaked non-matching plan: %+v", plan)
		}
	}
}

func TestFilterAWSAccessKeyQuarantinePlansNormalizesReadyForApplyAliases(t *testing.T) {
	plans := []AWSAccessKeyQuarantinePlan{
		{
			PlanID:          "ready",
			AccountID:       "123456789012",
			Region:          "us-east-1",
			QuarantineState: "quarantine_candidate",
			OwnerNotice:     AWSAccessKeyQuarantineOwnerNotice{Owner: "orders-platform"},
			ReadyForApply:   true,
		},
		{
			PlanID:          "not-ready",
			AccountID:       "123456789012",
			Region:          "us-east-1",
			QuarantineState: "needs_review",
			OwnerNotice:     AWSAccessKeyQuarantineOwnerNotice{Owner: "security-review"},
			ReadyForApply:   false,
		},
	}

	ready, readyApplied := filterAWSAccessKeyQuarantinePlans(plans, AWSAccessKeyQuarantineRequest{ReadyForApply: "yes"})
	if readyApplied["ready_for_apply"] != "yes" || len(ready) != 1 || ready[0].PlanID != "ready" {
		t.Fatalf("expected ready_for_apply=yes to match ready plans, got applied=%+v plans=%+v", readyApplied, ready)
	}

	notReady, notReadyApplied := filterAWSAccessKeyQuarantinePlans(plans, AWSAccessKeyQuarantineRequest{ReadyForApply: "no"})
	if notReadyApplied["ready_for_apply"] != "no" || len(notReady) != 1 || notReady[0].PlanID != "not-ready" {
		t.Fatalf("expected ready_for_apply=no to match non-ready plans, got applied=%+v plans=%+v", notReadyApplied, notReady)
	}
}

func TestAWSAccessKeyQuarantineAccessKeyIDCanonicalizesCasing(t *testing.T) {
	accessKeyID := "AKIA" + "ORDERS123456"
	lowerAccessKeyID := strings.ToLower(accessKeyID)
	finding := AWSUnusedDormantAccessFinding{
		PolicyScope: lowerAccessKeyID + ":*",
		Evidence: []AWSUnusedDormantAccessEvidence{{
			EvidenceRef: "runtime-evidence://access-key/" + lowerAccessKeyID,
			Label:       lowerAccessKeyID,
		}},
	}

	if got := awsAccessKeyQuarantineAccessKeyID(finding); got != accessKeyID {
		t.Fatalf("expected canonical uppercase access key id, got %q", got)
	}
}

func TestAWSAccessKeyQuarantinePlansRequireLongLivedIAMAccessKey(t *testing.T) {
	now := time.Date(2026, 6, 25, 9, 38, 0, 0, time.UTC)
	sessionKeyID := "ASIA" + "SESSION123456"
	findings := []AWSUnusedDormantAccessFinding{
		{
			FindingID:     "aws-unused-dormant-access:sts-session-key",
			DormancyState: "stale",
			Status:        "cleanup_candidate",
			Confidence:    0.9,
			DisplayName:   sessionKeyID,
			PolicyScope:   sessionKeyID + ":*",
			OwnerContext:  "orders-platform",
			Evidence: []AWSUnusedDormantAccessEvidence{{
				Source:      "cloudtrail",
				EvidenceRef: "runtime-evidence://session-key/" + sessionKeyID,
				Label:       sessionKeyID,
			}},
		},
		{
			FindingID:      "aws-unused-dormant-access:shakia-user",
			DormancyState:  "stale",
			Status:         "cleanup_candidate",
			Confidence:     0.9,
			DisplayName:    "shakia-ci",
			IdentityNodeID: "aws:identity:user/shakia-ci",
			ResourceNodeID: "aws:identity:user/shakia-ci",
			OwnerContext:   "orders-platform",
			CandidateActions: []string{
				"iam:DisableAccessKey",
			},
			Evidence: []AWSUnusedDormantAccessEvidence{{
				Source:      "iam_last_used",
				EvidenceRef: "runtime-evidence://principal/shakia-ci",
				Label:       "shakia-ci",
			}},
		},
	}

	if got := awsAccessKeyQuarantineAccessKeyID(findings[0]); got != "" {
		t.Fatalf("STS session key must not be treated as an IAM access key, got %q", got)
	}
	if plans := awsAccessKeyQuarantinePlansFromDormant(findings, now); len(plans) != 0 {
		t.Fatalf("expected non-IAM-key findings to be excluded from quarantine plans: %+v", plans)
	}
}

func TestGetAWSAccessKeyQuarantinePlansFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 25, 9, 40, 0, 0, time.UTC)
	svc, ws := newAccessKeyQuarantineService(t, "project-access-key-quarantine-states", now)

	denied, err := svc.GetAWSAccessKeyQuarantinePlans(defaultScopeContext(), ws, "project-access-key-quarantine-states", AWSAccessKeyQuarantineRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Plans) != 0 || len(denied.Diagnostics) == 0 {
		t.Fatalf("permission denied must be explicit and suppress plans: %+v", denied)
	}

	empty, err := svc.GetAWSAccessKeyQuarantinePlans(defaultScopeContext(), ws, "project-access-key-quarantine-states", AWSAccessKeyQuarantineRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Summary.TotalPlans != 0 || empty.Status == "blocked" {
		t.Fatalf("empty fixture should produce no non-blocked plans: %+v", empty)
	}

	if _, err := svc.GetAWSAccessKeyQuarantinePlans(defaultScopeContext(), ws, "project-access-key-quarantine-states", AWSAccessKeyQuarantineRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSAccessKeyQuarantine(t *testing.T) {
	now := time.Date(2026, 6, 25, 9, 45, 0, 0, time.UTC)
	svc, _ := newAccessKeyQuarantineService(t, "project-access-key-quarantine-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-access-key-quarantine-route/aws/access-key-quarantine?connector_id=aws-prod&fixture_state=success&quarantine_state=quarantine_candidate", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Plans AWSAccessKeyQuarantineResult `json:"plans"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Plans.CurrentIssueRef != "#1534" || body.Plans.AppliedFilters["quarantine_state"] != "quarantine-candidate" {
		t.Fatalf("unexpected route payload: %+v", body.Plans)
	}
}
