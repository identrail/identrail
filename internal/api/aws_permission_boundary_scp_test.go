package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newPermissionBoundarySCPService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSPermissionBoundarySCPPlansBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 24, 14, 0, 0, 0, time.UTC)
	svc, ws := newPermissionBoundarySCPService(t, "project-perm-boundary-scp", now)

	result, err := svc.GetAWSPermissionBoundarySCPPlans(defaultScopeContext(), ws, "project-perm-boundary-scp", AWSPermissionBoundarySCPRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get permission boundary scp: %v", err)
	}
	if result.CurrentIssueRef != "#1532" || result.Version != awsPermissionBoundarySCPVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: %+v", result)
	}
	for i := 1; i < len(result.Plans); i++ {
		if result.Plans[i-1].Score < result.Plans[i].Score {
			t.Fatalf("plans are not ranked by descending score: %+v", result.Plans)
		}
	}
	for _, p := range result.Plans {
		if p.PlanID == "" || p.CalculationVersion != awsPermissionBoundarySCPVersion {
			t.Fatalf("plan missing stable metadata: %+v", p)
		}
		if p.Kind != awsPermissionBoundaryKind && p.Kind != awsSCPKind {
			t.Fatalf("plan kind must be permission_boundary or scp, got %s", p.Kind)
		}
		if p.TargetScope == "" || p.Title == "" || p.PreventedBehavior == "" {
			t.Fatalf("plan missing classification fields: %+v", p)
		}
		if !p.ReadOnlyProjection {
			t.Fatalf("plan must be a read-only projection: %+v", p)
		}
		if len(p.StatementSnippets) == 0 || p.StatementSnippets[0].Effect != "Deny" {
			t.Fatalf("plan must have at least one Deny statement snippet: %+v", p.StatementSnippets)
		}
		if p.BreakageProjection.Level == "" || p.BreakageProjection.Rationale == "" {
			t.Fatalf("plan missing breakage projection: %+v", p.BreakageProjection)
		}
		if p.RollbackPlan.Strategy == "" || len(p.RollbackPlan.Steps) == 0 {
			t.Fatalf("plan missing rollback plan: %+v", p.RollbackPlan)
		}
		if p.VerificationPlan.Strategy == "" || len(p.VerificationPlan.Steps) == 0 {
			t.Fatalf("plan missing verification plan: %+v", p.VerificationPlan)
		}
		if p.EvidenceBoundary != awsPermissionBoundarySCPEvidenceBoundary() {
			t.Fatalf("plan crossed evidence boundary: %+v", p)
		}
	}
}

func TestGetAWSPermissionBoundarySCPPlansAppliesFilters(t *testing.T) {
	now := time.Date(2026, 6, 24, 14, 5, 0, 0, time.UTC)
	svc, ws := newPermissionBoundarySCPService(t, "project-perm-boundary-filters", now)

	boundaryOnly, err := svc.GetAWSPermissionBoundarySCPPlans(defaultScopeContext(), ws, "project-perm-boundary-filters", AWSPermissionBoundarySCPRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Kind:         "permission_boundary",
	})
	if err != nil {
		t.Fatalf("kind filter: %v", err)
	}
	for _, p := range boundaryOnly.Plans {
		if p.Kind != awsPermissionBoundaryKind {
			t.Fatalf("kind filter leaked %s plan: %+v", p.Kind, p)
		}
	}
	if boundaryOnly.AppliedFilters["kind"] != "permission-boundary" {
		t.Fatalf("expected applied kind filter, got %+v", boundaryOnly.AppliedFilters)
	}

	scpOnly, err := svc.GetAWSPermissionBoundarySCPPlans(defaultScopeContext(), ws, "project-perm-boundary-filters", AWSPermissionBoundarySCPRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Kind:         "scp",
	})
	if err != nil {
		t.Fatalf("scp filter: %v", err)
	}
	for _, p := range scpOnly.Plans {
		if p.Kind != awsSCPKind {
			t.Fatalf("kind filter leaked %s plan: %+v", p.Kind, p)
		}
	}
}

func TestAWSPermissionBoundaryPlanRequiresRepeatedAction(t *testing.T) {
	now := time.Date(2026, 6, 24, 14, 10, 0, 0, time.UTC)
	leastSingle := AWSLeastPrivilegeResult{
		Recommendations: []AWSLeastPrivilegeRecommendation{{
			RecommendationID: "least-priv:single",
			Decision:         "remove",
			Severity:         "medium",
			Status:           "action_required",
			Score:            70,
			Confidence:       0.84,
			AccountID:        "123456789012",
			IdentityNodeID:   "aws:identity:arn:aws:iam::123456789012:role/single-loader",
			RemoveActions:    []string{"s3:DeleteObject"},
		}},
	}
	plans := awsPermissionBoundaryPlansFromLeastPrivilege(leastSingle, AWSOrganizationsTopologyResult{}, now)
	if len(plans) != 0 {
		t.Fatalf("single-identity remove must not produce a permission boundary plan: %+v", plans)
	}

	leastRepeated := AWSLeastPrivilegeResult{
		Recommendations: []AWSLeastPrivilegeRecommendation{
			{
				RecommendationID: "least-priv:a",
				Decision:         "remove",
				Severity:         "high",
				Status:           "action_required",
				Score:            74,
				Confidence:       0.86,
				AccountID:        "111111111111",
				Service:          "s3",
				Region:           "us-east-1",
				IdentityNodeID:   "aws:identity:arn:aws:iam::111111111111:role/loader-a",
				RemoveActions:    []string{"s3:DeleteObject"},
			},
			{
				RecommendationID: "least-priv:b",
				Decision:         "remove",
				Severity:         "high",
				Status:           "action_required",
				Score:            72,
				Confidence:       0.82,
				AccountID:        "222222222222",
				Service:          "s3",
				Region:           "us-east-1",
				IdentityNodeID:   "aws:identity:arn:aws:iam::222222222222:role/loader-b",
				RemoveActions:    []string{"s3:DeleteObject"},
			},
		},
	}
	plans = awsPermissionBoundaryPlansFromLeastPrivilege(leastRepeated, AWSOrganizationsTopologyResult{}, now)
	if len(plans) != 1 {
		t.Fatalf("expected one boundary plan for repeated action, got %d", len(plans))
	}
	p := plans[0]
	if p.Kind != awsPermissionBoundaryKind {
		t.Fatalf("expected permission_boundary kind, got %s", p.Kind)
	}
	if len(p.TargetIdentityNodeIDs) != 2 || len(p.TargetAccountIDs) != 2 {
		t.Fatalf("plan must list both identities and accounts: %+v", p)
	}
	if len(p.SourceFindingIDs) != 2 {
		t.Fatalf("plan must reference both source recommendations: %+v", p.SourceFindingIDs)
	}
	if p.StatementSnippets[0].DeniedActions[0] != "s3:DeleteObject" {
		t.Fatalf("statement must deny the repeated action: %+v", p.StatementSnippets[0])
	}
	if p.Region != "us-east-1" {
		t.Fatalf("expected repeated-action boundary to preserve region, got %q", p.Region)
	}
}

func TestAWSSCPPlanFromCrossAccountTrust(t *testing.T) {
	now := time.Date(2026, 6, 24, 14, 15, 0, 0, time.UTC)
	trust := AWSCrossAccountTrustResult{
		Findings: []AWSCrossAccountTrustFinding{
			{
				FindingID:       "aws-cross-account-trust:public-bucket",
				FindingType:     "public_resource_trust",
				Severity:        "critical",
				Status:          "action_required",
				Score:           92,
				Confidence:      0.9,
				AccountID:       "123456789012",
				Service:         "s3",
				ResourceType:    "s3_bucket",
				ResourceARN:     "arn:aws:s3:::public-bucket",
				ResourceNodeID:  "aws:resource:s3-bucket/public-bucket",
				ResourceLabel:   "public-bucket",
				PublicPrincipal: true,
				HasCondition:    false,
				Rationale:       "Bucket policy allows *.",
			},
		},
	}
	plans := awsSCPPlansFromCrossAccountTrust(trust, AWSOrganizationsTopologyResult{}, now)
	if len(plans) != 1 {
		t.Fatalf("expected one SCP plan, got %d", len(plans))
	}
	p := plans[0]
	if p.Kind != awsSCPKind {
		t.Fatalf("expected scp kind, got %s", p.Kind)
	}
	if p.TargetScope != "org_root" {
		t.Fatalf("public-principal finding must target org_root, got %s", p.TargetScope)
	}
	if p.StatementSnippets[0].ChangeKind != "deny_public_principal_creation" {
		t.Fatalf("public-principal SCP must deny public principal creation, got %s", p.StatementSnippets[0].ChangeKind)
	}
	if p.BreakageProjection.Level != "high" {
		t.Fatalf("public SCP must project high breakage, got %s", p.BreakageProjection.Level)
	}
	if p.ReadyForApply {
		t.Fatalf("public SCP must not be ready_for_apply: %+v", p)
	}
}

func TestAWSPermissionBoundarySCPPlanFilterSupportsRegion(t *testing.T) {
	plans := []AWSPermissionBoundarySCPPlan{
		{PlanID: "aws-permission-boundary-scp:region-us-east-1", Kind: awsPermissionBoundaryKind, Region: "us-east-1", TargetScope: "identity"},
		{PlanID: "aws-permission-boundary-scp:region-unknown", Kind: awsPermissionBoundaryKind, Region: "", TargetScope: "identity"},
		{PlanID: "aws-permission-boundary-scp:region-us-west-2", Kind: awsSCPKind, Region: "us-west-2", TargetScope: "account"},
	}

	filtered, _ := filterAWSPermissionBoundarySCPPlans(plans, AWSPermissionBoundarySCPRequest{Region: "us-east-1"})
	if len(filtered) != 2 {
		t.Fatalf("expected two plans when filtering region: %+v", filtered)
	}
}

func TestAWSSCPDeniedActionsForResourcePolicyFindings(t *testing.T) {
	tests := []struct {
		name     string
		finding  AWSCrossAccountTrustFinding
		expected []string
	}{
		{
			name:     "cross-account resource access",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "s3_bucket"},
			expected: []string{"s3:PutBucketPolicy"},
		},
		{
			name:     "cross-account resource access using service token s3",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "s3"},
			expected: []string{"s3:PutBucketPolicy"},
		},
		{
			name:     "cross-account resource access using normalized s3 token",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "s3-bucket"},
			expected: []string{"s3:PutBucketPolicy"},
		},
		{
			name:     "cross-account resource access using service token kms",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "kms"},
			expected: []string{"kms:PutKeyPolicy"},
		},
		{
			name:     "cross-account resource access using service token secretsmanager",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "secretsmanager"},
			expected: []string{"secretsmanager:PutResourcePolicy"},
		},
		{
			name:     "cross-account resource access using service token s3",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "s3"},
			expected: []string{"s3:PutBucketPolicy"},
		},
		{
			name:     "cross-account resource access using normalized s3 token",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "s3-bucket"},
			expected: []string{"s3:PutBucketPolicy"},
		},
		{
			name:     "cross-account resource access using service token kms",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "kms"},
			expected: []string{"kms:PutKeyPolicy"},
		},
		{
			name:     "cross-account resource access using service token secretsmanager",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "secretsmanager"},
			expected: []string{"secretsmanager:PutResourcePolicy"},
		},
		{
			name:     "fallback action",
			finding:  AWSCrossAccountTrustFinding{FindingType: "other_cross_account_grant", ResourceType: "s3_bucket"},
			expected: []string{"*"},
		},
		{
			name: "kms live grant resource access",
			finding: AWSCrossAccountTrustFinding{
				FindingType:  "cross_account_resource_access",
				ResourceType: "kms_key",
				Evidence: []AWSCrossAccountTrustEvidence{{
					Source: "kms_live_grant",
				}},
			},
			expected: []string{"kms:CreateGrant"},
		},
		{
			name:     "access analyzer external access",
			finding:  AWSCrossAccountTrustFinding{FindingType: "access_analyzer_external_access", ResourceType: "s3"},
			expected: []string{"s3:PutBucketPolicy"},
		},
		{
			name:     "unsupported resource type",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "sqs_queue"},
			expected: nil,
		},
		{
			name:     "access analyzer external access",
			finding:  AWSCrossAccountTrustFinding{FindingType: "access_analyzer_external_access", ResourceType: "s3"},
			expected: []string{"s3:PutBucketPolicy"},
		},
		{
			name:     "unsupported resource type",
			finding:  AWSCrossAccountTrustFinding{FindingType: "cross_account_resource_access", ResourceType: "sqs_queue"},
			expected: nil,
		},
	}
	for _, tc := range tests {
		actions := awsSCPDeniedActions(tc.finding)
		if len(actions) != len(tc.expected) {
			t.Fatalf("%s expected denied actions %v, got %v", tc.name, tc.expected, actions)
		}
		for i := range tc.expected {
			if actions[i] != tc.expected[i] {
				t.Fatalf("%s expected denied action %q at index %d, got %q", tc.name, tc.expected[i], i, actions[i])
			}
		}
	}
}

func TestAWSPermissionBoundaryPlansFromLeastPrivilegeHonorsUpstreamBreakage(t *testing.T) {
	now := time.Date(2026, 6, 24, 14, 30, 0, 0, time.UTC)
	least := AWSLeastPrivilegeResult{
		Recommendations: []AWSLeastPrivilegeRecommendation{
			{
				RecommendationID:   "least-priv:high",
				Decision:           "remove",
				Severity:           "medium",
				Status:             "action_required",
				Score:              74,
				Confidence:         0.93,
				AccountID:          "111111111111",
				Region:             "us-east-1",
				IdentityNodeID:     "aws:identity:arn:aws:iam::111111111111:role/loader-a",
				RemoveActions:      []string{"s3:PutObject"},
				BreakagePrediction: "medium",
			},
			{
				RecommendationID:   "least-priv:low-one",
				Decision:           "remove",
				Severity:           "medium",
				Status:             "action_required",
				Score:              72,
				Confidence:         0.93,
				AccountID:          "222222222222",
				Region:             "us-east-1",
				IdentityNodeID:     "aws:identity:arn:aws:iam::222222222222:role/loader-b",
				RemoveActions:      []string{"s3:PutObject"},
				BreakagePrediction: "low",
			},
			{
				RecommendationID:   "least-priv:low-two",
				Decision:           "remove",
				Severity:           "medium",
				Status:             "action_required",
				Score:              70,
				Confidence:         0.93,
				AccountID:          "222222222222",
				Region:             "us-east-1",
				IdentityNodeID:     "aws:identity:arn:aws:iam::222222222222:role/loader-c",
				RemoveActions:      []string{"s3:PutObject"},
				BreakagePrediction: "low",
			},
		},
	}
	plans := awsPermissionBoundaryPlansFromLeastPrivilege(least, AWSOrganizationsTopologyResult{}, now)
	if len(plans) != 1 {
		t.Fatalf("expected one boundary plan for repeated action, got %d", len(plans))
	}
	plan := plans[0]
	if plan.BreakageProjection.Level != "medium" {
		t.Fatalf("expected medium upstream-influenced breakage projection, got %s", plan.BreakageProjection.Level)
	}
	if plan.ReadyForApply {
		t.Fatalf("upstream medium breakage must block ready_for_apply: %+v", plan)
	}
}

func TestAWSSCPTargetScopeForResourcePolicyFindings(t *testing.T) {
	orgs := AWSOrganizationsTopologyResult{
		Accounts: []AWSOrganizationsTopologyAccount{
			{AccountID: "111111111111", OUPath: "/root/finance"},
			{AccountID: "222222222222", OUPath: "/root/other"},
		},
	}
	tests := []struct {
		name        string
		findingType string
	}{
		{name: "cross-account resource access", findingType: "cross_account_resource_access"},
		{name: "access analyzer external access", findingType: "access_analyzer_external_access"},
	}
	for _, tc := range tests {
		scope, accounts, ouPaths := awsSCPTargetScope(AWSCrossAccountTrustFinding{
			FindingType:             tc.findingType,
			PublicPrincipal:         false,
			ExternalPrincipalOUPath: "/root/principal-ou",
			AccountID:               "111111111111",
		}, orgs)
		if scope != "account" {
			t.Fatalf("%s expected account scope for resource-policy finding, got %s", tc.name, scope)
		}
		if len(accounts) != 1 || accounts[0] != "111111111111" {
			t.Fatalf("%s expected account target to use finding account, got %+v", tc.name, accounts)
		}
		if len(ouPaths) != 1 || ouPaths[0] != "/root/finance" {
			t.Fatalf("%s expected resource OU path, got %+v", tc.name, ouPaths)
		}
	}
}

func TestAWSCPCandidateSkipsUnscopedRuntimeAssumption(t *testing.T) {
	if awsSCPCandidate(AWSCrossAccountTrustFinding{
		FindingType:               "runtime_cross_account_assumption",
		TrustedWithinOrganization: false,
		ExternalPrincipalOUPath:   "",
	}) {
		t.Fatalf("runtime assumption from out-of-org principal should not be projected without an OU scope")
	}
}

func TestAWSPermissionBoundarySCPMostCommonKeyIsDeterministic(t *testing.T) {
	severity := awsPermissionBoundarySCPMostCommonKeyWithPriority(map[string]int{"high": 1, "critical": 1}, "medium", awsPermissionBoundarySCPSeverityPriority)
	if severity != "critical" {
		t.Fatalf("expected deterministic critical tie-break, got %s", severity)
	}
	status := awsPermissionBoundarySCPMostCommonKeyWithPriority(map[string]int{"ready": 2, "action_required": 2}, "review", awsPermissionBoundarySCPStatusPriority)
	if status != "action_required" {
		t.Fatalf("expected deterministic action_required tie-break, got %s", status)
	}
	manual := awsPermissionBoundarySCPMostCommonKeyWithPriority(map[string]int{"zz": 1, "aa": 1}, "fallback", nil)
	if manual != "aa" {
		t.Fatalf("expected lexical tie-break, got %s", manual)
	}
}

func TestAWSPermissionBoundarySCPSearchMatchesPlanDetails(t *testing.T) {
	plan := AWSPermissionBoundarySCPPlan{
		PlanID:            "aws-permission-boundary-scp:search-test",
		Title:             "Permission boundary: deny s3:DeleteObject",
		PreventedBehavior: "Re-grant of s3:DeleteObject by boundary-bound identities.",
		StatementSnippets: []AWSPermissionBoundarySCPStatementSnippet{{
			DeniedActions: []string{"s3:DeleteObject"},
			ConditionKeys: []string{"aws:PrincipalOrgID"},
		}},
		BreakageProjection: AWSPermissionBoundarySCPBreakageProjection{
			Signals: []string{"affected_identities:3"},
		},
		RollbackPlan: AWSPermissionBoundarySCPRollbackPlan{
			Strategy:    "detach_permission_boundary",
			Steps:       []string{"Detach the projected permission boundary from each captured identity."},
			EvidenceRef: "evidence://least/repeated",
		},
		VerificationPlan: AWSPermissionBoundarySCPVerificationPlan{
			Strategy:       "policy_simulate",
			Steps:          []string{"Use IAM policy simulator to confirm the boundary denies the action."},
			SuccessSignals: []string{"policy_simulate:no-regression"},
		},
		TargetAccountIDs: []string{"111111111111"},
		TargetOUPaths:    []string{"/root/security"},
	}
	cases := []struct {
		name   string
		needle string
	}{
		{"denied action", "s3:DeleteObject"},
		{"condition key", "aws:PrincipalOrgID"},
		{"rollback step", "Detach the projected"},
		{"verification step", "IAM policy simulator"},
		{"verification success signal", "no-regression"},
		{"breakage signal", "affected_identities:3"},
		{"target account", "111111111111"},
		{"target OU", "/root/security"},
	}
	for _, tc := range cases {
		if !awsPermissionBoundarySCPSearchMatch(plan, tc.needle) {
			t.Fatalf("search did not match %s needle %q", tc.name, tc.needle)
		}
	}
}

func TestGetAWSPermissionBoundarySCPPlansFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 24, 14, 20, 0, 0, time.UTC)
	svc, ws := newPermissionBoundarySCPService(t, "project-perm-boundary-states", now)

	denied, err := svc.GetAWSPermissionBoundarySCPPlans(defaultScopeContext(), ws, "project-perm-boundary-states", AWSPermissionBoundarySCPRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Plans) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must be explicit and suppress plans: %+v", denied)
	}

	empty, err := svc.GetAWSPermissionBoundarySCPPlans(defaultScopeContext(), ws, "project-perm-boundary-states", AWSPermissionBoundarySCPRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Summary.TotalPlans != 0 {
		t.Fatalf("empty fixture should produce no plans: %+v", empty)
	}
	if empty.Status == "blocked" {
		t.Fatalf("empty fixture should not be marked blocked, got %s", empty.Status)
	}

	if _, err := svc.GetAWSPermissionBoundarySCPPlans(defaultScopeContext(), ws, "project-perm-boundary-states", AWSPermissionBoundarySCPRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSPermissionBoundarySCP(t *testing.T) {
	now := time.Date(2026, 6, 24, 14, 25, 0, 0, time.UTC)
	svc, _ := newPermissionBoundarySCPService(t, "project-perm-boundary-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-perm-boundary-route/aws/permission-boundary-scp?connector_id=aws-prod&fixture_state=success&kind=scp", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Plans AWSPermissionBoundarySCPResult `json:"plans"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Plans.CurrentIssueRef != "#1532" || body.Plans.AppliedFilters["kind"] != "scp" {
		t.Fatalf("unexpected route payload: %+v", body.Plans)
	}
}
