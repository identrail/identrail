package github

import (
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestRepositoryPostureFindingsPromotesInsecureAndLimitedChecks(t *testing.T) {
	collectedAt := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
	detectedAt := collectedAt.Add(time.Minute)
	posture := RepositoryPosture{
		Repository:     "owner/repo",
		InstallationID: 101,
		CollectedAt:    collectedAt,
		Checks: []RepositoryPostureCheck{
			{
				ID:       "default_branch_protection",
				Category: "branch_protection",
				State:    RepositoryPostureStateInsecure,
				Reason:   "weak_protection",
				Summary:  "Default branch protection is weak.",
				Evidence: map[string]any{"default_branch": "main"},
			},
			{
				ID:       "deploy_keys",
				Category: "access",
				State:    RepositoryPostureStateSecure,
				Reason:   "no_writable_deploy_keys",
				Summary:  "No writable deploy keys were returned.",
			},
			{
				ID:       "self_hosted_runners",
				Category: "runners",
				State:    RepositoryPostureStatePermissionLimited,
				Reason:   "permission_limited",
				Summary:  "Self-hosted runner posture could not be collected.",
			},
			{
				ID:       "actions_permissions",
				Category: "actions",
				State:    RepositoryPostureStateUnavailable,
				Reason:   "api_unavailable",
				Summary:  "GitHub Actions permissions could not be collected.",
			},
			{
				ID:       "org_code_security_configuration",
				Category: "code_security",
				State:    RepositoryPostureStateUnsupported,
				Reason:   "plan_unavailable",
				Summary:  "Plan does not expose this endpoint.",
			},
		},
	}

	findings := RepositoryPostureFindings(posture, detectedAt)
	if len(findings) != 3 {
		t.Fatalf("expected three posture findings, got %+v", findings)
	}

	branch := findingByDetector(findings, "github_default_branch_unprotected")
	if branch == nil {
		t.Fatalf("expected default branch posture finding, got %+v", findings)
	}
	if branch.Type != domain.FindingRepoMisconfig || branch.Severity != domain.SeverityHigh || branch.Repository != "owner/repo" {
		t.Fatalf("unexpected branch finding: %+v", branch)
	}
	if branch.LifecycleKey == "" || branch.Evidence["github_posture_check_id"] != "default_branch_protection" {
		t.Fatalf("expected stable posture metadata, got key=%q evidence=%+v", branch.LifecycleKey, branch.Evidence)
	}
	if branch.Evidence["raw_secret_stored"] != false || branch.AdapterSource != githubPostureAdapterSource {
		t.Fatalf("expected non-secret github posture source evidence, got %+v", branch)
	}

	limited := findingByDetector(findings, githubPosturePermissionDetector)
	if limited == nil {
		t.Fatalf("expected permission-limited posture finding, got %+v", findings)
	}
	if limited.Severity != domain.SeverityMedium || limited.ConfidenceState != "permission_limited" || limited.VerificationStatus != string(RepositoryPostureStatePermissionLimited) {
		t.Fatalf("unexpected permission-limited finding: %+v", limited)
	}

	unavailable := findingByDetector(findings, githubPostureUnavailableDetector)
	if unavailable == nil {
		t.Fatalf("expected unavailable posture finding, got %+v", findings)
	}
	if unavailable.Severity != domain.SeverityLow || unavailable.ConfidenceState != "unavailable" || unavailable.VerificationStatus != string(RepositoryPostureStateUnavailable) {
		t.Fatalf("unexpected unavailable finding: %+v", unavailable)
	}
}

func TestOrganizationPostureFindingsScopeToRepository(t *testing.T) {
	now := time.Date(2026, 7, 4, 11, 0, 0, 0, time.UTC)
	posture := OrganizationPosture{
		Organization:   "acme",
		InstallationID: 202,
		CollectedAt:    now,
		Checks: []RepositoryPostureCheck{
			{
				ID:       "org_workflow_permissions",
				Category: "actions",
				State:    RepositoryPostureStateInsecure,
				Reason:   "write_token_or_pr_approval",
				Summary:  "Organization grants write-scoped default workflow tokens.",
				Evidence: map[string]any{"default_workflow_permissions": "write"},
			},
			{
				ID:       "org_code_security_configuration",
				Category: "code_security",
				State:    RepositoryPostureStateInsecure,
				Reason:   "not_enforced",
				Summary:  "Organization code security configuration is not enforced.",
			},
		},
	}

	findings := OrganizationPostureFindings(posture, "acme/repo", now)
	if len(findings) != 2 {
		t.Fatalf("expected two org posture findings, got %+v", findings)
	}
	finding := findingByDetector(findings, "github_workflow_permissions_write_default")
	if finding == nil {
		t.Fatalf("expected workflow permissions finding, got %+v", findings)
	}
	if finding.Repository != "acme/repo" || finding.Detector != "github_workflow_permissions_write_default" {
		t.Fatalf("unexpected organization posture finding: %+v", finding)
	}
	if finding.AdapterSource != githubOrgPostureAdapterSource || finding.Evidence["organization"] != "acme" || finding.Evidence["github_posture_scope"] != "organization" {
		t.Fatalf("expected organization posture evidence, got %+v", finding.Evidence)
	}

	codeSecurity := findingByDetector(findings, "github_code_security_configuration_weak")
	if codeSecurity == nil {
		t.Fatalf("expected code security configuration finding, got %+v", findings)
	}
	if codeSecurity.Remediation != "Enable an enforced organization-level code security configuration that covers secret scanning, code scanning, and Dependabot settings." {
		t.Fatalf("expected code security remediation guidance, got %q", codeSecurity.Remediation)
	}
}

func TestPostureFindingsHaveStableLifecycleAcrossRepeatedScans(t *testing.T) {
	first := RepositoryPosture{
		Repository:  "owner/repo",
		CollectedAt: time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC),
		Checks: []RepositoryPostureCheck{
			{ID: "secret_scanning", Category: "secret_scanning", State: RepositoryPostureStateInsecure, Reason: "open_alerts_present", Summary: "Open secret scanning alerts are present."},
		},
	}
	second := first
	second.Checks = append([]RepositoryPostureCheck(nil), first.Checks...)
	second.CollectedAt = first.CollectedAt.Add(time.Hour)
	second.Checks[0].Summary = "Secret scanning remains unhealthy."

	firstFindings := RepositoryPostureFindings(first, first.CollectedAt)
	secondFindings := RepositoryPostureFindings(second, second.CollectedAt)
	if len(firstFindings) != 1 || len(secondFindings) != 1 {
		t.Fatalf("expected one finding in each scan, got first=%+v second=%+v", firstFindings, secondFindings)
	}
	if firstFindings[0].LifecycleKey != secondFindings[0].LifecycleKey {
		t.Fatalf("expected stable lifecycle key, got %q and %q", firstFindings[0].LifecycleKey, secondFindings[0].LifecycleKey)
	}
	if firstFindings[0].ID != secondFindings[0].ID {
		t.Fatalf("expected stable finding id, got %q and %q", firstFindings[0].ID, secondFindings[0].ID)
	}
	if firstFindings[0].HumanSummary != "Open secret scanning alerts are present." || secondFindings[0].HumanSummary != "Secret scanning remains unhealthy." {
		t.Fatalf("expected scan summaries to remain independent, got first=%q second=%q", firstFindings[0].HumanSummary, secondFindings[0].HumanSummary)
	}
}

func TestPostureFindingsKeepLifecycleWhenCheckStateDegrades(t *testing.T) {
	first := RepositoryPosture{
		Repository:  "owner/repo",
		CollectedAt: time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC),
		Checks: []RepositoryPostureCheck{
			{ID: "default_branch_protection", Category: "branch_protection", State: RepositoryPostureStateInsecure, Reason: "weak_protection", Summary: "Default branch protection is weak."},
		},
	}
	second := first
	second.Checks = []RepositoryPostureCheck{
		{ID: "default_branch_protection", Category: "branch_protection", State: RepositoryPostureStatePermissionLimited, Reason: "permission_limited", Summary: "Default branch protection could not be collected."},
	}
	second.CollectedAt = first.CollectedAt.Add(time.Hour)

	firstFindings := RepositoryPostureFindings(first, first.CollectedAt)
	secondFindings := RepositoryPostureFindings(second, second.CollectedAt)
	if len(firstFindings) != 1 || len(secondFindings) != 1 {
		t.Fatalf("expected one finding in each scan, got first=%+v second=%+v", firstFindings, secondFindings)
	}
	if firstFindings[0].Detector != "github_default_branch_unprotected" || secondFindings[0].Detector != githubPosturePermissionDetector {
		t.Fatalf("expected detector to reflect current check state, got first=%q second=%q", firstFindings[0].Detector, secondFindings[0].Detector)
	}
	if firstFindings[0].LifecycleKey != secondFindings[0].LifecycleKey {
		t.Fatalf("expected degraded posture state to keep lifecycle key, got %q and %q", firstFindings[0].LifecycleKey, secondFindings[0].LifecycleKey)
	}
	if firstFindings[0].ID != secondFindings[0].ID {
		t.Fatalf("expected degraded posture state to keep finding id, got %q and %q", firstFindings[0].ID, secondFindings[0].ID)
	}
}

func TestPostureInconclusiveLifecycleKeysCoverUnverifiedChecks(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	posture := RepositoryPosture{
		Repository:  "owner/repo",
		CollectedAt: now,
		Checks: []RepositoryPostureCheck{
			{ID: "default_branch_protection", State: RepositoryPostureStateInsecure},
			{ID: "repository_rulesets", State: RepositoryPostureStateSecure},
			{ID: "secret_scanning", State: RepositoryPostureStatePermissionLimited},
			{ID: "code_scanning", State: RepositoryPostureStateUnavailable},
			{ID: "webhooks", State: RepositoryPostureStateUnknown},
			{ID: "deploy_keys", State: RepositoryPostureStateUnsupported, Reason: "plan_unavailable"},
		},
	}

	keys := RepositoryPostureInconclusiveLifecycleKeys(posture)
	if len(keys) != 4 {
		t.Fatalf("expected the four unverified checks to be inconclusive, got %d: %+v", len(keys), keys)
	}
	inconclusive := map[string]struct{}{}
	for _, key := range keys {
		inconclusive[key] = struct{}{}
	}
	keyFor := func(checkID string) string {
		return postureFindingLifecycleKey("owner/repo", githubPostureAdapterSource, "repository", checkID)
	}
	for _, checkID := range []string{"secret_scanning", "code_scanning", "webhooks", "deploy_keys"} {
		if _, ok := inconclusive[keyFor(checkID)]; !ok {
			t.Errorf("expected %s to be inconclusive, got %+v", checkID, keys)
		}
	}
	// Conclusively evaluated checks must stay closable, otherwise a plan that
	// permanently lacks one control would strand every other posture finding.
	for _, checkID := range []string{"default_branch_protection", "repository_rulesets"} {
		if _, ok := inconclusive[keyFor(checkID)]; ok {
			t.Errorf("expected %s to remain conclusive, got %+v", checkID, keys)
		}
	}

	// A permission-limited check keeps the lifecycle key of the gap it replaced,
	// so the inconclusive key matches the durable finding that must stay open.
	insecure := RepositoryPostureFindings(RepositoryPosture{
		Repository:  "owner/repo",
		CollectedAt: now,
		Checks:      []RepositoryPostureCheck{{ID: "secret_scanning", State: RepositoryPostureStateInsecure}},
	}, now)
	if len(insecure) != 1 || insecure[0].LifecycleKey != keyFor("secret_scanning") {
		t.Fatalf("expected the insecure finding to share the inconclusive key, got %+v", insecure)
	}
}

func TestOrganizationPostureInconclusiveLifecycleKeysDistinguishUnsupportedReasons(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	// A user-owned repository genuinely has no organization policy, so those
	// checks are conclusive and prior findings may close.
	userOwned := OrganizationPosture{
		Organization: "owner",
		CollectedAt:  now,
		Checks: []RepositoryPostureCheck{
			{ID: "org_secret_scanning_policy", State: RepositoryPostureStateUnsupported, Reason: "not_an_organization"},
		},
	}
	if keys := OrganizationPostureInconclusiveLifecycleKeys(userOwned, "owner/repo"); len(keys) != 0 {
		t.Fatalf("expected not_an_organization checks to be conclusive, got %+v", keys)
	}

	// The organization exists but GitHub stopped exposing the control (a plan
	// change), so the gap was never verified as fixed and must stay open.
	planLimited := OrganizationPosture{
		Organization: "owner",
		CollectedAt:  now,
		Checks: []RepositoryPostureCheck{
			{ID: "org_secret_scanning_policy", State: RepositoryPostureStateUnsupported, Reason: "plan_unavailable"},
		},
	}
	keys := OrganizationPostureInconclusiveLifecycleKeys(planLimited, "owner/repo")
	want := postureFindingLifecycleKey("owner/repo", githubOrgPostureAdapterSource, "organization", "org_secret_scanning_policy")
	if len(keys) != 1 || keys[0] != want {
		t.Fatalf("expected plan-unavailable org checks to be inconclusive, got %+v", keys)
	}
}

func findingByDetector(findings []domain.Finding, detector string) *domain.Finding {
	for i := range findings {
		if findings[i].Detector == detector {
			return &findings[i]
		}
	}
	return nil
}

// TestPostureFindingsBuildControlPlaneRiskGraph pins the contract between the
// posture collector and the repo risk graph: every control-plane check the
// collector can report must resolve to a graph node. It fails if a check ID is
// renamed here without updating the graph mapping in internal/domain.
func TestPostureFindingsBuildControlPlaneRiskGraph(t *testing.T) {
	collectedAt := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
	repositoryPosture := RepositoryPosture{
		Repository:  "owner/repo",
		CollectedAt: collectedAt,
		Checks: []RepositoryPostureCheck{
			{
				ID:       "default_branch_protection",
				Category: "branch_protection",
				State:    RepositoryPostureStateInsecure,
				Reason:   "weak_protection",
				Evidence: map[string]any{"default_branch": "main", "force_pushes_allowed": true},
			},
			{
				ID:       "repository_rulesets",
				Category: "branch_protection",
				State:    RepositoryPostureStateInsecure,
				Reason:   "no_active_rulesets",
			},
			{
				ID:       "actions_permissions",
				Category: "actions",
				State:    RepositoryPostureStateInsecure,
				Reason:   "broad_actions_or_write_privileges",
				Evidence: map[string]any{"allowed_actions": "all"},
			},
			{
				ID:       "deploy_keys",
				Category: "access",
				State:    RepositoryPostureStateInsecure,
				Reason:   "writable_deploy_keys_present",
				Evidence: map[string]any{"writable_deploy_keys": 1},
			},
			{
				ID:       "webhooks",
				Category: "webhooks",
				State:    RepositoryPostureStateInsecure,
				Reason:   "risky_webhooks_present",
				Evidence: map[string]any{"insecure_ssl_hooks": 1},
			},
			{
				ID:       "deployment_environments",
				Category: "deployments",
				State:    RepositoryPostureStateInsecure,
				Reason:   "unprotected_environments",
				Evidence: map[string]any{"unprotected_environments": 1},
			},
			{
				ID:       "self_hosted_runners",
				Category: "runners",
				State:    RepositoryPostureStateInsecure,
				Reason:   "self_hosted_runners_present",
			},
			{
				ID:       "code_scanning",
				Category: "security",
				State:    RepositoryPostureStateInsecure,
				Reason:   "not_configured",
			},
			{
				ID:       "secret_scanning",
				Category: "security",
				State:    RepositoryPostureStateInsecure,
				Reason:   "not_configured",
			},
			{
				ID:       "dependabot_security",
				Category: "security",
				State:    RepositoryPostureStateInsecure,
				Reason:   "dependabot_security_disabled",
			},
		},
	}
	organizationPosture := OrganizationPosture{
		Organization: "owner",
		CollectedAt:  collectedAt,
		Checks: []RepositoryPostureCheck{
			{
				ID:       "org_actions_policy",
				Category: "actions",
				State:    RepositoryPostureStateInsecure,
				Reason:   "all_actions_allowed",
			},
			{
				ID:       "org_workflow_permissions",
				Category: "actions",
				State:    RepositoryPostureStateInsecure,
				Reason:   "write_default",
			},
			{
				ID:       "org_reusable_workflow_policy",
				Category: "actions",
				State:    RepositoryPostureStateInsecure,
				Reason:   "verified_creators_allowed",
			},
			{
				ID:       "org_secret_scanning_policy",
				Category: "secret_scanning",
				State:    RepositoryPostureStateInsecure,
				Reason:   "push_protection_disabled",
			},
			{
				ID:       "org_code_security_configuration",
				Category: "code_security",
				State:    RepositoryPostureStateInsecure,
				Reason:   "configuration_not_enforced",
			},
		},
	}

	findings := RepositoryPostureFindings(repositoryPosture, collectedAt)
	findings = append(findings, OrganizationPostureFindings(organizationPosture, "owner/repo", collectedAt)...)
	graph := domain.BuildRepoRiskGraph(findings, domain.RepoRiskGraphOptions{
		Repository:    "owner/repo",
		DefaultBranch: "main",
		Now:           collectedAt,
	})

	for _, kind := range []domain.RepoRiskGraphNodeKind{
		domain.RepoRiskNodeBranchProtection,
		domain.RepoRiskNodeRepositoryRuleset,
		domain.RepoRiskNodeActionsPolicy,
		domain.RepoRiskNodeWorkflowPermissionDefault,
		domain.RepoRiskNodeReusableWorkflowPolicy,
		domain.RepoRiskNodeRunnerGroup,
		domain.RepoRiskNodeEnvironmentProtection,
		domain.RepoRiskNodeDeployKey,
		domain.RepoRiskNodeWebhook,
		domain.RepoRiskNodeAlertSource,
		domain.RepoRiskNodeOrgSecurityConfiguration,
	} {
		if !graphHasNodeKind(graph, kind) {
			t.Fatalf("expected posture findings to build a %q node, got %+v", kind, graph.Nodes)
		}
	}

	for _, kind := range []domain.RepoRiskGraphEdgeKind{
		domain.RepoRiskEdgeRepositoryGovernedBy,
		domain.RepoRiskEdgeInheritsOrgPolicy,
		domain.RepoRiskEdgeFindingWeakensControl,
		domain.RepoRiskEdgeFindingExposesControl,
	} {
		if !graphHasEdgeKind(graph, kind) {
			t.Fatalf("expected posture findings to build a %q edge, got %+v", kind, graph.Edges)
		}
	}

	for _, score := range graph.Scores {
		if score.Factors.PostureAmplifier == 0 {
			t.Fatalf("expected every insecure posture finding to amplify its score, got %+v", score)
		}
	}
}

func graphHasNodeKind(graph domain.RepoRiskGraph, kind domain.RepoRiskGraphNodeKind) bool {
	for _, node := range graph.Nodes {
		if node.Kind == kind {
			return true
		}
	}
	return false
}

func graphHasEdgeKind(graph domain.RepoRiskGraph, kind domain.RepoRiskGraphEdgeKind) bool {
	for _, edge := range graph.Edges {
		if edge.Kind == kind {
			return true
		}
	}
	return false
}
