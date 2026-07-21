package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildRepoRiskGraphLinksWorkflowOIDCBlastRadius(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		{
			ID:              "finding-oidc",
			Type:            FindingRepoMisconfig,
			Severity:        SeverityHigh,
			ConfidenceScore: 0.92,
			Title:           "GitHub Actions OIDC trust can mint deployment credentials",
			Repository:      "owner/repo",
			FilePath:        ".github/workflows/deploy.yml",
			LineNumber:      17,
			Detector:        "workflow_oidc_broad_trust",
			CreatedAt:       now.Add(-2 * time.Hour),
			Evidence: map[string]any{
				"workflow_events":    []string{"push"},
				"workflow_job":       "deploy",
				"permission_summary": "contents:read,id-token:write",
				"cloud_auth_action":  "aws-actions/configure-aws-credentials@v4",
				"oidc_risk_context":  "broad_push_event",
				"aws_role_arn":       "arn:aws:iam::123456789012:role/prod-deploy",
				"environment":        "production",
			},
		},
	}, RepoRiskGraphOptions{
		Repository:    "owner/repo",
		DefaultBranch: "main",
		Now:           now,
	})

	assertGraphNode(t, graph, RepoRiskNodeRepository, "owner/repo")
	assertGraphNode(t, graph, RepoRiskNodeDefaultBranch, "main")
	assertGraphNode(t, graph, RepoRiskNodeWorkflow, ".github/workflows/deploy.yml")
	assertGraphNode(t, graph, RepoRiskNodeWorkflowJob, "deploy")
	assertGraphNode(t, graph, RepoRiskNodeOIDCSubject, "repo:owner/repo:ref:*:job:deploy")
	assertGraphNode(t, graph, RepoRiskNodeCloudRole, "arn:aws:iam::123456789012:role/prod-deploy")
	assertGraphNode(t, graph, RepoRiskNodeEnvironment, "production")

	assertGraphEdge(t, graph, RepoRiskEdgeWorkflowCanMintToken, RepoRiskEvidenceKnown)
	assertGraphEdge(t, graph, RepoRiskEdgeOIDCCanAssumeRole, RepoRiskEvidenceKnown)
	assertGraphEdge(t, graph, RepoRiskEdgeRepoDeploysEnvironment, RepoRiskEvidenceKnown)

	score := scoreForFinding(t, graph, "finding-oidc")
	if score.Score < 70 {
		t.Fatalf("expected graph-aware OIDC score to be high risk, got %+v", score)
	}
	if score.Factors.Privilege == 0 || score.Factors.Exposure == 0 || score.Factors.EnvironmentCriticality == 0 {
		t.Fatalf("expected score to include privilege, exposure, and environment factors, got %+v", score.Factors)
	}
}

func TestBuildRepoRiskGraphRepresentsUnknownOIDCTargetWithoutGuessing(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		{
			ID:         "finding-unknown-oidc",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityHigh,
			Repository: "owner/repo",
			FilePath:   ".github/workflows/deploy.yml",
			Detector:   "workflow_oidc_broad_trust",
			CreatedAt:  now,
			Evidence: map[string]any{
				"workflow_events":    []string{"workflow_run"},
				"permission_summary": "id-token:write",
				"oidc_risk_context":  "workflow_run",
			},
		},
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeUnknown, "unknown cloud role")
	assertGraphEdge(t, graph, RepoRiskEdgeReachabilityUnknown, RepoRiskEvidenceUnknown)

	for _, node := range graph.Nodes {
		if node.Kind == RepoRiskNodeCloudRole {
			t.Fatalf("expected missing OIDC role evidence to remain unknown instead of guessed, got %+v", node)
		}
	}

	score := scoreForFinding(t, graph, "finding-unknown-oidc")
	if len(score.Unknowns) != 2 || score.Unknowns[0] != "identity_target" || score.Unknowns[1] != "workflow_job" {
		t.Fatalf("expected identity target and workflow job unknowns, got %+v", score.Unknowns)
	}
}

func TestBuildRepoRiskGraphDedupesRepeatedEdges(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		{
			ID:         "finding-one",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityHigh,
			Repository: "owner/repo",
			FilePath:   ".github/workflows/deploy.yml",
			Detector:   "workflow_pull_request_target_privileged_context",
			CreatedAt:  now,
			Evidence: map[string]any{
				"workflow_events":    []string{"pull_request_target"},
				"workflow_job":       "release",
				"references_secrets": true,
			},
		},
		{
			ID:         "finding-two",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityHigh,
			Repository: "owner/repo",
			FilePath:   ".github/workflows/deploy.yml",
			Detector:   "workflow_pull_request_target_privileged_context",
			CreatedAt:  now,
			Evidence: map[string]any{
				"workflow_events":    []string{"pull_request_target"},
				"workflow_job":       "release",
				"references_secrets": true,
			},
		},
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	seen := map[string]struct{}{}
	for _, edge := range graph.Edges {
		if _, exists := seen[edge.ID]; exists {
			t.Fatalf("duplicate edge id %q in %+v", edge.ID, graph.Edges)
		}
		seen[edge.ID] = struct{}{}
	}
	if countEdges(graph, RepoRiskEdgeWorkflowRunsJob) != 1 {
		t.Fatalf("expected shared workflow->job edge to dedupe, got %+v", graph.Edges)
	}
	if countEdges(graph, RepoRiskEdgeJobUsesSecret) != 1 {
		t.Fatalf("expected shared job->secret edge to dedupe, got %+v", graph.Edges)
	}
}

func TestBuildRepoRiskGraphScoresSecretExposureAboveLowUnknownFinding(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		{
			ID:              "secret-finding",
			Type:            FindingSecretExposure,
			Severity:        SeverityCritical,
			ConfidenceScore: 0.99,
			Repository:      "owner/repo",
			FilePath:        "config/prod.env",
			Detector:        "github_pat",
			CreatedAt:       now.Add(-1 * time.Hour),
			Evidence: map[string]any{
				"secret_fingerprint": "fp-prod-token",
				"raw_secret_stored":  false,
			},
		},
		{
			ID:         "low-finding",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityLow,
			Repository: "owner/repo",
			FilePath:   "Dockerfile",
			Detector:   "docker_latest_tag",
			CreatedAt:  now.Add(-120 * 24 * time.Hour),
		},
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	secretScore := scoreForFinding(t, graph, "secret-finding")
	lowScore := scoreForFinding(t, graph, "low-finding")
	if secretScore.Score <= lowScore.Score {
		t.Fatalf("expected exposed credential score to outrank low finding, secret=%+v low=%+v", secretScore, lowScore)
	}
	if secretScore.Factors.Confidence != 99 || secretScore.Factors.Exploitability == 0 || secretScore.Factors.Privilege == 0 {
		t.Fatalf("expected secret score factors to include confidence, exploitability, and privilege, got %+v", secretScore.Factors)
	}
	assertGraphNode(t, graph, RepoRiskNodeToken, "secret-fingerprint:fp-prod-token")
	assertGraphEdge(t, graph, RepoRiskEdgeFindingExposesToken, RepoRiskEvidenceKnown)
}

func TestBuildRepoRiskGraphKeepsMultipleRepositoriesSeparate(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		{
			ID:         "repo-a-finding",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityMedium,
			Repository: "owner/repo-a",
			FilePath:   ".github/workflows/build.yml",
			Detector:   "workflow_unpinned_third_party_action",
			CreatedAt:  now,
		},
		{
			ID:         "repo-b-finding",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityMedium,
			Repository: "owner/repo-b",
			FilePath:   ".github/workflows/deploy.yml",
			Detector:   "workflow_unpinned_third_party_action",
			CreatedAt:  now,
		},
	}, RepoRiskGraphOptions{Now: now})

	if graph.Repository != "" {
		t.Fatalf("expected mixed-repository graph not to claim one repository, got %q", graph.Repository)
	}
	assertGraphNode(t, graph, RepoRiskNodeRepository, "owner/repo-a")
	assertGraphNode(t, graph, RepoRiskNodeRepository, "owner/repo-b")
	if countEdges(graph, RepoRiskEdgeFindingInRepository) != 2 {
		t.Fatalf("expected each finding to link to its own repository, got %+v", graph.Edges)
	}
}

func TestBuildRepoRiskGraphReturnsEmptyArrays(t *testing.T) {
	graph := BuildRepoRiskGraph(nil, RepoRiskGraphOptions{Repository: "owner/repo"})
	if graph.Repository != "owner/repo" {
		t.Fatalf("expected repository context to be preserved, got %+v", graph)
	}
	if graph.Nodes == nil || graph.Edges == nil || graph.Scores == nil {
		t.Fatalf("expected empty graph slices to be non-nil arrays, got %+v", graph)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	if string(encoded) != `{"repository":"owner/repo","nodes":[],"edges":[],"scores":[],"summary":{"finding_count":0,"node_count":0,"edge_count":0,"unknown_node_count":0,"unknown_edge_count":0,"high_risk_findings":0,"critical_findings":0}}` {
		t.Fatalf("expected empty arrays in JSON, got %s", encoded)
	}
}

func TestBuildRepoRiskGraphUsesDeterministicFindingFallbacks(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{{
		ScanID:     "scan-blank",
		Type:       FindingRepoMisconfig,
		Severity:   SeverityMedium,
		Repository: "owner/repo",
		FilePath:   ".github/workflows/build.yml",
		LineNumber: 9,
		Detector:   "workflow_unpinned_third_party_action",
		CreatedAt:  now,
	}}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	if len(graph.Scores) != 1 {
		t.Fatalf("expected one score, got %+v", graph.Scores)
	}
	score := graph.Scores[0]
	if score.FindingID == "" || score.FindingNodeID == "" {
		t.Fatalf("expected deterministic score identifiers, got %+v", score)
	}
	assertGraphNodeID(t, graph, score.FindingNodeID)
}

func TestBuildRepoRiskGraphIncludesScanContextInFindingNodeIdentity(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		{
			ID:         "same-finding",
			ScanID:     "scan-a",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityMedium,
			Repository: "owner/repo",
			FilePath:   ".github/workflows/build.yml",
			LineNumber: 11,
			Detector:   "workflow_unpinned_third_party_action",
			CreatedAt:  now,
		},
		{
			ID:         "same-finding",
			ScanID:     "scan-b",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityMedium,
			Repository: "owner/repo",
			FilePath:   ".github/workflows/build.yml",
			LineNumber: 11,
			Detector:   "workflow_unpinned_third_party_action",
			CreatedAt:  now.Add(time.Minute),
		},
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	if countNodes(graph, RepoRiskNodeFinding) != 2 {
		t.Fatalf("expected duplicate finding ids from separate scans to remain separate nodes, got %+v", graph.Nodes)
	}
	nodeIDs := map[string]struct{}{}
	for _, score := range graph.Scores {
		if score.FindingID != "same-finding" {
			t.Fatalf("expected original finding id to be preserved, got %+v", score)
		}
		if score.FindingNodeID == "" {
			t.Fatalf("expected score to link to a graph node, got %+v", score)
		}
		nodeIDs[score.FindingNodeID] = struct{}{}
		assertGraphNodeID(t, graph, score.FindingNodeID)
	}
	if len(nodeIDs) != 2 {
		t.Fatalf("expected scan-aware score node links, got %+v", graph.Scores)
	}
}

func TestBuildRepoRiskGraphDoesNotScoreEmptyWriteScopes(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{{
		ID:         "empty-write-scopes",
		Type:       FindingRepoMisconfig,
		Severity:   SeverityMedium,
		Repository: "owner/repo",
		FilePath:   ".github/workflows/build.yml",
		Detector:   "workflow_broad_token_permissions",
		CreatedAt:  now,
		Evidence: map[string]any{
			"write_scopes": []string{},
		},
	}}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	score := scoreForFinding(t, graph, "empty-write-scopes")
	if score.Factors.Privilege != 0 {
		t.Fatalf("expected empty write_scopes not to add privilege, got %+v", score.Factors)
	}
}

func TestBuildRepoRiskGraphLinksGitHubPostureControlPlane(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("branch-protection", "github_default_branch_unprotected", SeverityHigh, now, map[string]any{
			"github_posture_check_id": "default_branch_protection",
			"github_posture_category": "branch_protection",
			"github_posture_scope":    "repository",
			"github_posture_state":    "insecure",
			"default_branch":          "main",
			"required_reviews":        0,
			"admins_enforced":         false,
			"force_pushes_allowed":    true,
		}),
		postureFinding("org-actions", "github_actions_policy_broad", SeverityMedium, now, map[string]any{
			"github_posture_check_id": "org_actions_policy",
			"github_posture_category": "actions",
			"github_posture_scope":    "organization",
			"github_posture_state":    "insecure",
			"organization":            "owner",
			"allowed_actions":         "all",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", DefaultBranch: "main", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeBranchProtection, "branch protection: main")
	assertGraphNode(t, graph, RepoRiskNodeActionsPolicy, "Actions policy: owner")
	assertGraphEdge(t, graph, RepoRiskEdgeRepositoryGovernedBy, RepoRiskEvidenceKnown)
	assertGraphEdge(t, graph, RepoRiskEdgeInheritsOrgPolicy, RepoRiskEvidenceKnown)
	assertGraphEdge(t, graph, RepoRiskEdgeFindingWeakensControl, RepoRiskEvidenceKnown)

	if countEdges(graph, RepoRiskEdgeFindingWeakensControl) != 2 {
		t.Fatalf("expected each posture finding to weaken its own control, got %+v", graph.Edges)
	}
	for _, score := range graph.Scores {
		if score.Factors.PostureAmplifier == 0 {
			t.Fatalf("expected weak controls to amplify posture score, got %+v", score)
		}
		if len(score.Unknowns) != 0 {
			t.Fatalf("expected observed posture sources to report no unknowns, got %+v", score)
		}
	}
}

func TestBuildRepoRiskGraphConvergesOrgPolicyAcrossRepositories(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	orgPolicyFinding := func(id string, repository string) Finding {
		return Finding{
			ID:         id,
			Type:       FindingRepoMisconfig,
			Severity:   SeverityMedium,
			Repository: repository,
			Detector:   "github_actions_policy_broad",
			CreatedAt:  now,
			Evidence: map[string]any{
				"repository":              repository,
				"github_posture_check_id": "org_actions_policy",
				"github_posture_scope":    "organization",
				"github_posture_state":    "insecure",
				"organization":            "owner",
				"allowed_actions":         "all",
			},
		}
	}
	graph := BuildRepoRiskGraph([]Finding{
		orgPolicyFinding("repo-a-policy", "owner/repo-a"),
		orgPolicyFinding("repo-b-policy", "owner/repo-b"),
	}, RepoRiskGraphOptions{Now: now})

	if countNodes(graph, RepoRiskNodeActionsPolicy) != 1 {
		t.Fatalf("expected one organization policy to stay one node across repositories, got %+v", graph.Nodes)
	}
	for _, node := range graph.Nodes {
		if node.Kind == RepoRiskNodeActionsPolicy && node.Repository != "" {
			t.Fatalf("expected a shared organization policy not to be pinned to one repository, got %+v", node)
		}
	}
	if countEdges(graph, RepoRiskEdgeInheritsOrgPolicy) != 2 {
		t.Fatalf("expected both repositories to inherit the shared organization policy, got %+v", graph.Edges)
	}

	inheritedNodeIDs := map[string]struct{}{}
	for _, edge := range graph.Edges {
		if edge.Kind == RepoRiskEdgeInheritsOrgPolicy {
			inheritedNodeIDs[edge.ToNodeID] = struct{}{}
		}
	}
	if len(inheritedNodeIDs) != 1 {
		t.Fatalf("expected inheritance edges to converge on one policy node, got %+v", graph.Edges)
	}
}

func TestBuildRepoRiskGraphKeepsOrgPolicyPerRepositoryWithoutOrganizationEvidence(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	unattributedFinding := func(id string, repository string) Finding {
		return Finding{
			ID:         id,
			Type:       FindingRepoMisconfig,
			Severity:   SeverityMedium,
			Repository: repository,
			Detector:   "github_actions_policy_broad",
			CreatedAt:  now,
			Evidence: map[string]any{
				"repository":              repository,
				"github_posture_check_id": "org_actions_policy",
				"github_posture_scope":    "organization",
				"github_posture_state":    "insecure",
			},
		}
	}
	graph := BuildRepoRiskGraph([]Finding{
		unattributedFinding("repo-a-policy", "owner-a/repo"),
		unattributedFinding("repo-b-policy", "owner-b/repo"),
	}, RepoRiskGraphOptions{Now: now})

	if countNodes(graph, RepoRiskNodeActionsPolicy) != 2 {
		t.Fatalf("expected policies without organization evidence to stay separate rather than merge, got %+v", graph.Nodes)
	}
}

func TestBuildRepoRiskGraphSurfacesPermissionLimitedPostureAsUncertainty(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("runner-permission", "github_posture_permission_limited", SeverityMedium, now, map[string]any{
			"github_posture_check_id": "self_hosted_runners",
			"github_posture_category": "runners",
			"github_posture_scope":    "repository",
			"github_posture_state":    "permission_limited",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeRunnerGroup, "self-hosted runner group")
	assertGraphEdge(t, graph, RepoRiskEdgeFindingDependsOnPostureSource, RepoRiskEvidenceUnknown)
	assertGraphEdge(t, graph, RepoRiskEdgeRepositoryGovernedBy, RepoRiskEvidenceUnknown)

	if graph.Summary.UnknownNodeCount != 1 || graph.Summary.UnknownEdgeCount != 2 {
		t.Fatalf("expected permission-limited posture to count as uncertainty, got %+v", graph.Summary)
	}
	if countEdges(graph, RepoRiskEdgeFindingWeakensControl) != 0 {
		t.Fatalf("expected an unreadable control not to be reported as weak, got %+v", graph.Edges)
	}

	score := scoreForFinding(t, graph, "runner-permission")
	if len(score.Unknowns) != 1 || score.Unknowns[0] != "posture_source" {
		t.Fatalf("expected posture source to be listed as unknown, got %+v", score.Unknowns)
	}
	if score.Factors.PostureAmplifier != 0 {
		t.Fatalf("expected an unreadable control not to amplify the score, got %+v", score.Factors)
	}
}

func TestBuildRepoRiskGraphLinksWorkflowsToRunnerGroupsAsUnprovenReachability(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("runners", "github_self_hosted_runner_unrestricted", SeverityHigh, now, map[string]any{
			"github_posture_check_id":         "self_hosted_runners",
			"github_posture_category":         "runners",
			"github_posture_scope":            "repository",
			"github_posture_state":            "insecure",
			"self_hosted_runner_count":        2,
			"public_repository_runner_groups": 1,
		}),
		{
			ID:         "workflow-finding",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityMedium,
			Repository: "owner/repo",
			FilePath:   ".github/workflows/deploy.yml",
			Detector:   "workflow_unpinned_third_party_action",
			CreatedAt:  now,
		},
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphEdge(t, graph, RepoRiskEdgeWorkflowRunsOnRunnerGroup, RepoRiskEvidenceUnknown)
	if countEdges(graph, RepoRiskEdgeWorkflowRunsOnRunnerGroup) != 1 {
		t.Fatalf("expected one workflow-to-runner-group edge, got %+v", graph.Edges)
	}
	for _, edge := range graph.Edges {
		if edge.Kind == RepoRiskEdgeWorkflowRunsOnRunnerGroup && edge.EvidenceState != RepoRiskEvidenceUnknown {
			t.Fatalf("expected runner targeting to stay unproven, got %+v", edge)
		}
	}
}

func TestBuildRepoRiskGraphExposesDeployKeyAndWebhookControlRisk(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("deploy-keys", "github_write_deploy_key", SeverityHigh, now, map[string]any{
			"github_posture_check_id": "deploy_keys",
			"github_posture_scope":    "repository",
			"github_posture_state":    "insecure",
			"writable_deploy_keys":    2,
		}),
		postureFinding("webhooks", "github_webhook_unhealthy", SeverityLow, now, map[string]any{
			"github_posture_check_id": "webhooks",
			"github_posture_scope":    "repository",
			"github_posture_state":    "insecure",
			"insecure_ssl_hooks":      1,
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeDeployKey, "repository deploy keys")
	assertGraphNode(t, graph, RepoRiskNodeWebhook, "repository webhooks")
	if countEdges(graph, RepoRiskEdgeFindingExposesControl) != 2 {
		t.Fatalf("expected deploy key and webhook risk to use the exposure edge, got %+v", graph.Edges)
	}
	if countEdges(graph, RepoRiskEdgeFindingWeakensControl) != 0 {
		t.Fatalf("expected deploy key and webhook risk not to double-report as weakening, got %+v", graph.Edges)
	}
}

func TestBuildRepoRiskGraphPostureAmplifierRaisesScore(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	amplified := postureFinding("weak-branch", "github_default_branch_unprotected", SeverityHigh, now, map[string]any{
		"github_posture_check_id": "default_branch_protection",
		"github_posture_scope":    "repository",
		"github_posture_state":    "insecure",
		"default_branch":          "main",
		"force_pushes_allowed":    true,
	})
	baseline := amplified
	baseline.ID = "baseline"
	baseline.Detector = "github_dependabot_disabled"
	baseline.Evidence = map[string]any{
		"github_posture_check_id": "dependabot_security",
		"github_posture_scope":    "repository",
		"github_posture_state":    "insecure",
	}

	graph := BuildRepoRiskGraph([]Finding{amplified, baseline}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	weak := scoreForFinding(t, graph, "weak-branch")
	dependabot := scoreForFinding(t, graph, "baseline")
	if weak.Factors.PostureAmplifier <= dependabot.Factors.PostureAmplifier {
		t.Fatalf("expected an unprotected default branch to outweigh a disabled alert source, weak=%+v dependabot=%+v", weak.Factors, dependabot.Factors)
	}
	if weak.Score <= dependabot.Score {
		t.Fatalf("expected the stronger posture amplifier to raise the score, weak=%+v dependabot=%+v", weak, dependabot)
	}
}

func TestBuildRepoRiskGraphDoesNotInventSecretsFromPostureDetectors(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("secret-scanning", "github_secret_scanning_disabled", SeverityHigh, now, map[string]any{
			"github_posture_check_id": "secret_scanning",
			"github_posture_category": "security",
			"github_posture_scope":    "repository",
			"github_posture_state":    "insecure",
			"open_alerts_sampled":     3,
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeAlertSource, "alert source: secret scanning")
	if countNodes(graph, RepoRiskNodeSecret) != 0 || countNodes(graph, RepoRiskNodeToken) != 0 {
		t.Fatalf("expected a secret-scanning posture check not to invent a secret, got %+v", graph.Nodes)
	}
}

func TestBuildRepoRiskGraphSkipsPostureChecksWithoutControlConcept(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("metadata", "github_repository_metadata_weak", SeverityLow, now, map[string]any{
			"github_posture_check_id": "repository_metadata",
			"github_posture_scope":    "repository",
			"github_posture_state":    "insecure",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	if countEdges(graph, RepoRiskEdgeRepositoryGovernedBy) != 0 {
		t.Fatalf("expected a posture check without a control concept not to create a control node, got %+v", graph.Edges)
	}
	score := scoreForFinding(t, graph, "metadata")
	if score.Factors.PostureAmplifier != 0 {
		t.Fatalf("expected no amplifier without a control concept, got %+v", score.Factors)
	}
}

func TestBuildRepoRiskGraphMapsRepositoryWriteDefaultToItsOwnControl(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("write-default", "github_actions_policy_broad", SeverityHigh, now, map[string]any{
			"github_posture_check_id":      "actions_permissions",
			"github_posture_category":      "actions",
			"github_posture_scope":         "repository",
			"github_posture_state":         "insecure",
			"allowed_actions":              "selected",
			"default_workflow_permissions": "write",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeWorkflowPermissionDefault, "default workflow permissions: repository")
	if countNodes(graph, RepoRiskNodeActionsPolicy) != 0 {
		t.Fatalf("expected a restricted-source write-default finding not to attribute to the Actions source policy, got %+v", graph.Nodes)
	}
	assertGraphEdge(t, graph, RepoRiskEdgeFindingWeakensControl, RepoRiskEvidenceKnown)
}

func TestBuildRepoRiskGraphMapsPRApprovalPrivilegeToWorkflowPermissionControl(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("pr-approval", "github_actions_policy_broad", SeverityHigh, now, map[string]any{
			"github_posture_check_id":          "actions_permissions",
			"github_posture_category":          "actions",
			"github_posture_scope":             "repository",
			"github_posture_state":             "insecure",
			"allowed_actions":                  "selected",
			"default_workflow_permissions":     "read",
			"can_approve_pull_request_reviews": true,
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeWorkflowPermissionDefault, "default workflow permissions: repository")
	if countNodes(graph, RepoRiskNodeActionsPolicy) != 0 {
		t.Fatalf("expected PR-approval privilege to attribute to the workflow permission control, not the Actions source policy, got %+v", graph.Nodes)
	}
}

func TestBuildRepoRiskGraphKeepsBroadActionSourcesOnActionsPolicy(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("broad-actions", "github_actions_policy_broad", SeverityHigh, now, map[string]any{
			"github_posture_check_id":      "actions_permissions",
			"github_posture_scope":         "repository",
			"github_posture_state":         "insecure",
			"allowed_actions":              "all",
			"default_workflow_permissions": "write",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeActionsPolicy, "Actions policy: repository")
	if countNodes(graph, RepoRiskNodeWorkflowPermissionDefault) != 0 {
		t.Fatalf("expected broad action sources to stay on the Actions policy node, got %+v", graph.Nodes)
	}
}

func TestBuildRepoRiskGraphDoesNotWeakenFunctioningAlertSource(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("open-alerts", "github_code_scanning_disabled", SeverityHigh, now, map[string]any{
			"github_posture_check_id": "code_scanning",
			"github_posture_category": "security",
			"github_posture_scope":    "repository",
			"github_posture_state":    "insecure",
			"github_posture_reason":   "open_alerts_present",
			"open_alerts_sampled":     4,
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeAlertSource, "alert source: code scanning")
	assertGraphEdge(t, graph, RepoRiskEdgeRepositoryGovernedBy, RepoRiskEvidenceKnown)
	if countEdges(graph, RepoRiskEdgeFindingWeakensControl) != 0 {
		t.Fatalf("expected a functioning alert source with open alerts not to be recorded as weakened, got %+v", graph.Edges)
	}
	score := scoreForFinding(t, graph, "open-alerts")
	if score.Factors.PostureAmplifier != 0 {
		t.Fatalf("expected a functioning alert source not to amplify blast radius, got %+v", score.Factors)
	}
}

func TestBuildRepoRiskGraphWeakensDisabledAlertSource(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("disabled-scanning", "github_secret_scanning_disabled", SeverityHigh, now, map[string]any{
			"github_posture_check_id": "secret_scanning",
			"github_posture_scope":    "repository",
			"github_posture_state":    "insecure",
			"github_posture_reason":   "not_configured",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphEdge(t, graph, RepoRiskEdgeFindingWeakensControl, RepoRiskEvidenceKnown)
	score := scoreForFinding(t, graph, "disabled-scanning")
	if score.Factors.PostureAmplifier == 0 {
		t.Fatalf("expected a disabled secret-scanning control to amplify blast radius, got %+v", score.Factors)
	}
}

func TestBuildRepoRiskGraphAmplifiesUnprotectedProductionEnvironment(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	production := postureFinding("prod-env", "github_environment_unprotected", SeverityHigh, now, map[string]any{
		"github_posture_check_id":             "deployment_environments",
		"github_posture_scope":                "repository",
		"github_posture_state":                "insecure",
		"unprotected_environments":            1,
		"unprotected_environment_criticality": "production",
	})
	development := postureFinding("dev-env", "github_environment_unprotected", SeverityHigh, now, map[string]any{
		"github_posture_check_id":             "deployment_environments",
		"github_posture_scope":                "repository",
		"github_posture_state":                "insecure",
		"unprotected_environments":            1,
		"unprotected_environment_criticality": "development",
	})
	graph := BuildRepoRiskGraph([]Finding{production, development}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	prod := scoreForFinding(t, graph, "prod-env")
	dev := scoreForFinding(t, graph, "dev-env")
	if prod.Factors.PostureAmplifier <= dev.Factors.PostureAmplifier {
		t.Fatalf("expected an unprotected production environment to amplify more than a development one, prod=%+v dev=%+v", prod.Factors, dev.Factors)
	}
}

func TestBuildRepoRiskGraphDoesNotClaimInheritanceForUnattachedRepository(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		// configuration_not_applied: collector never queried repo attachment.
		postureFinding("not-attached", "github_code_security_configuration_weak", SeverityMedium, now, map[string]any{
			"github_posture_check_id": "org_code_security_configuration",
			"github_posture_scope":    "organization",
			"github_posture_state":    "insecure",
			"github_posture_reason":   "configuration_not_applied",
			"organization":            "owner",
		}),
		// configuration_not_enforced: early return before attachment query.
		postureFinding("not-enforced", "github_code_security_configuration_weak", SeverityMedium, now, map[string]any{
			"github_posture_check_id": "org_code_security_configuration",
			"github_posture_scope":    "organization",
			"github_posture_state":    "insecure",
			"github_posture_reason":   "configuration_not_enforced",
			"organization":            "owner-b",
		}),
		// configuration_not_protective: same, and Codex specifically called out
		// that this reason contains no attachment evidence.
		postureFinding("not-protective", "github_code_security_configuration_weak", SeverityMedium, now, map[string]any{
			"github_posture_check_id": "org_code_security_configuration",
			"github_posture_scope":    "organization",
			"github_posture_state":    "insecure",
			"github_posture_reason":   "configuration_not_protective",
			"organization":            "owner-c",
		}),
		// Reached the attachment query, repo is genuinely unattached.
		postureFinding("no-repo-config", "github_code_security_configuration_weak", SeverityMedium, now, map[string]any{
			"github_posture_check_id":          "org_code_security_configuration",
			"github_posture_scope":             "organization",
			"github_posture_state":             "insecure",
			"github_posture_reason":            "configuration_not_protective",
			"organization":                     "owner-d",
			"repository_configuration_applied": false,
		}),
		// Secret-scanning weak with no attachment flag: unattached.
		postureFinding("not-attached-secrets", "github_secret_scanning_disabled", SeverityHigh, now, map[string]any{
			"github_posture_check_id": "org_secret_scanning_policy",
			"github_posture_scope":    "organization",
			"github_posture_state":    "insecure",
			"github_posture_reason":   "secret_scanning_policy_weak",
			"organization":            "owner-e",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeOrgSecurityConfiguration, "code security configuration: owner")
	if countEdges(graph, RepoRiskEdgeInheritsOrgPolicy) != 0 {
		t.Fatalf("expected unattached repositories not to inherit organization controls, got %+v", graph.Edges)
	}
	// The controls are still reported as weak; only the inheritance claim is dropped.
	if countEdges(graph, RepoRiskEdgeFindingWeakensControl) != 5 {
		t.Fatalf("expected every weak organization control to still weaken its node, got %+v", graph.Edges)
	}
}

func TestBuildRepoRiskGraphRetainsInheritanceForAttachedWeakSecretScanningPolicy(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	// Repository is attached to an organization configuration that does not
	// enable both secret scanning and push protection. Inheritance still holds:
	// the config governs the repository, the config is weak, so the risk
	// propagates through the inheritance edge.
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("attached-weak-secrets", "github_secret_scanning_disabled", SeverityHigh, now, map[string]any{
			"github_posture_check_id":          "org_secret_scanning_policy",
			"github_posture_scope":             "organization",
			"github_posture_state":             "insecure",
			"github_posture_reason":            "secret_scanning_policy_weak",
			"organization":                     "owner",
			"repository_configuration_applied": true,
			"repository_configuration_status":  "attached",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphEdge(t, graph, RepoRiskEdgeInheritsOrgPolicy, RepoRiskEvidenceKnown)
	assertGraphEdge(t, graph, RepoRiskEdgeFindingWeakensControl, RepoRiskEvidenceKnown)
}

func TestBuildRepoRiskGraphKeepsUnknownInheritanceForUnreadableSecretScanningPolicy(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("permission-limited-secrets", "github_posture_permission_limited", SeverityMedium, now, map[string]any{
			"github_posture_check_id": "org_secret_scanning_policy",
			"github_posture_scope":    "organization",
			"github_posture_state":    "permission_limited",
			"organization":            "owner",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphNode(t, graph, RepoRiskNodeAlertSource, "alert source: secret scanning policy: owner")
	// The scanner could not read the policy, so whether the repository inherits
	// it is itself unknown; the graph must retain an unknown-state inheritance
	// edge rather than drop it and disconnect the control from the repository.
	assertGraphEdge(t, graph, RepoRiskEdgeInheritsOrgPolicy, RepoRiskEvidenceUnknown)
	assertGraphEdge(t, graph, RepoRiskEdgeFindingDependsOnPostureSource, RepoRiskEvidenceUnknown)
}

func TestBuildRepoRiskGraphKeepsInheritanceForAttachedWeakConfiguration(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	// A code security configuration finding that reached the repository
	// attachment query and confirmed the repository is attached must still emit
	// the inheritance edge even when the configuration itself is not protective.
	graph := BuildRepoRiskGraph([]Finding{
		postureFinding("attached-weak", "github_code_security_configuration_weak", SeverityMedium, now, map[string]any{
			"github_posture_check_id":          "org_code_security_configuration",
			"github_posture_scope":             "organization",
			"github_posture_state":             "insecure",
			"github_posture_reason":            "configuration_not_protective",
			"organization":                     "owner",
			"repository_configuration_applied": true,
			"repository_configuration_status":  "attached",
		}),
	}, RepoRiskGraphOptions{Repository: "owner/repo", Now: now})

	assertGraphEdge(t, graph, RepoRiskEdgeInheritsOrgPolicy, RepoRiskEvidenceKnown)
}

func TestBuildRepoRiskGraphPrefersObservedEvidenceWhenUpgradingSharedOrgControl(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	// Two repositories share one organization Actions policy. The first
	// finding was permission_limited (unknown), the second observed it as
	// insecure. The shared control node must upgrade to known and its evidence
	// must describe the observed state, not the earlier unknown one.
	graph := BuildRepoRiskGraph([]Finding{
		{
			ID:         "unknown-first",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityMedium,
			Repository: "owner/repo-a",
			Detector:   "github_posture_permission_limited",
			CreatedAt:  now,
			Evidence: map[string]any{
				"repository":                  "owner/repo-a",
				"github_posture_check_id":     "org_actions_policy",
				"github_posture_scope":        "organization",
				"github_posture_state":        "permission_limited",
				"github_posture_collected_at": "2026-05-20T10:00:00Z",
				"organization":                "owner",
			},
		},
		{
			ID:         "observed-second",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityHigh,
			Repository: "owner/repo-b",
			Detector:   "github_actions_policy_broad",
			CreatedAt:  now,
			Evidence: map[string]any{
				"repository":                  "owner/repo-b",
				"github_posture_check_id":     "org_actions_policy",
				"github_posture_scope":        "organization",
				"github_posture_state":        "insecure",
				"github_posture_collected_at": "2026-05-20T12:00:00Z",
				"organization":                "owner",
				"allowed_actions":             "all",
			},
		},
	}, RepoRiskGraphOptions{Now: now})

	var policyNode *RepoRiskGraphNode
	for i := range graph.Nodes {
		if graph.Nodes[i].Kind == RepoRiskNodeActionsPolicy {
			policyNode = &graph.Nodes[i]
			break
		}
	}
	if policyNode == nil {
		t.Fatalf("expected one shared Actions policy node, got %+v", graph.Nodes)
	}
	if policyNode.EvidenceState != RepoRiskEvidenceKnown {
		t.Fatalf("expected observed evidence to upgrade the node to known, got %+v", policyNode)
	}
	if state := policyNode.Evidence["github_posture_state"]; state != "insecure" {
		t.Fatalf("expected upgraded node to reflect observed posture state, got %v", state)
	}
	if collectedAt := policyNode.Evidence["github_posture_collected_at"]; collectedAt != "2026-05-20T12:00:00Z" {
		t.Fatalf("expected upgraded node to carry the observed collection timestamp, got %v", collectedAt)
	}
}

func TestBuildRepoRiskGraphKeepsDistinctOrgCodeSecurityConfigurationsSeparate(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	// Two repositories in the same organization are attached to two different
	// GitHub code-security configurations. Each configuration is a distinct
	// control with its own weakness, so they must stay as separate nodes with
	// separate inheritance edges rather than converging on a single "org owner"
	// node that would overstate blast radius and mix evidence.
	repoA := postureFinding("cfg-a-weak", "github_code_security_configuration_weak", SeverityMedium, now, map[string]any{
		"github_posture_check_id":          "org_code_security_configuration",
		"github_posture_scope":             "organization",
		"github_posture_state":             "insecure",
		"github_posture_reason":            "configuration_not_protective",
		"organization":                     "owner",
		"repository":                       "owner/repo-a",
		"repository_configuration_applied": true,
		"repository_configuration_id":      float64(101),
	})
	repoA.Repository = "owner/repo-a"
	repoB := postureFinding("cfg-b-weak", "github_code_security_configuration_weak", SeverityMedium, now, map[string]any{
		"github_posture_check_id":          "org_code_security_configuration",
		"github_posture_scope":             "organization",
		"github_posture_state":             "insecure",
		"github_posture_reason":            "configuration_not_protective",
		"organization":                     "owner",
		"repository":                       "owner/repo-b",
		"repository_configuration_applied": true,
		"repository_configuration_id":      float64(202),
	})
	repoB.Repository = "owner/repo-b"

	graph := BuildRepoRiskGraph([]Finding{repoA, repoB}, RepoRiskGraphOptions{Now: now})

	if countNodes(graph, RepoRiskNodeOrgSecurityConfiguration) != 2 {
		t.Fatalf("expected two distinct code security configurations to stay two nodes, got %+v", graph.Nodes)
	}
	if countEdges(graph, RepoRiskEdgeInheritsOrgPolicy) != 2 {
		t.Fatalf("expected each repository to inherit its own configuration, got %+v", graph.Edges)
	}

	inheritedNodeIDs := map[string]struct{}{}
	for _, edge := range graph.Edges {
		if edge.Kind == RepoRiskEdgeInheritsOrgPolicy {
			inheritedNodeIDs[edge.ToNodeID] = struct{}{}
		}
	}
	if len(inheritedNodeIDs) != 2 {
		t.Fatalf("expected two distinct inheritance targets, got %+v", graph.Edges)
	}

	labels := map[string]struct{}{}
	for _, node := range graph.Nodes {
		if node.Kind == RepoRiskNodeOrgSecurityConfiguration {
			labels[node.Label] = struct{}{}
		}
	}
	if _, ok := labels["code security configuration: owner (id 101)"]; !ok {
		t.Fatalf("expected configuration label to include its id, got %+v", labels)
	}
	if _, ok := labels["code security configuration: owner (id 202)"]; !ok {
		t.Fatalf("expected configuration label to include its id, got %+v", labels)
	}
}

func TestBuildRepoRiskGraphConvergesRepositoriesAttachedToSameConfiguration(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	// Both repositories are attached to the same configuration id, so the
	// per-configuration keying must still let their inheritance edges converge
	// on one shared node.
	finding := func(id string, repository string) Finding {
		result := postureFinding(id, "github_code_security_configuration_weak", SeverityMedium, now, map[string]any{
			"github_posture_check_id":          "org_code_security_configuration",
			"github_posture_scope":             "organization",
			"github_posture_state":             "insecure",
			"github_posture_reason":            "configuration_not_protective",
			"organization":                     "owner",
			"repository":                       repository,
			"repository_configuration_applied": true,
			"repository_configuration_id":      float64(101),
		})
		result.Repository = repository
		return result
	}
	graph := BuildRepoRiskGraph([]Finding{finding("shared-a", "owner/repo-a"), finding("shared-b", "owner/repo-b")}, RepoRiskGraphOptions{Now: now})

	if countNodes(graph, RepoRiskNodeOrgSecurityConfiguration) != 1 {
		t.Fatalf("expected one shared configuration to stay one node, got %+v", graph.Nodes)
	}
	if countEdges(graph, RepoRiskEdgeInheritsOrgPolicy) != 2 {
		t.Fatalf("expected both repositories to inherit the shared configuration, got %+v", graph.Edges)
	}
}

func TestBuildRepoRiskGraphConvergesOrgWideActionsPolicyEvenWithConfigurationIDPresent(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	// org_actions_policy is organization-wide: even if evidence somehow carries
	// a repository_configuration_id, the control kind is one per organization,
	// so the node must still converge across repositories.
	finding := func(id string, repository string) Finding {
		result := postureFinding(id, "github_actions_policy_broad", SeverityMedium, now, map[string]any{
			"github_posture_check_id":     "org_actions_policy",
			"github_posture_scope":        "organization",
			"github_posture_state":        "insecure",
			"organization":                "owner",
			"repository":                  repository,
			"repository_configuration_id": float64(999),
			"allowed_actions":             "all",
		})
		result.Repository = repository
		return result
	}
	graph := BuildRepoRiskGraph([]Finding{finding("actions-a", "owner/repo-a"), finding("actions-b", "owner/repo-b")}, RepoRiskGraphOptions{Now: now})

	if countNodes(graph, RepoRiskNodeActionsPolicy) != 1 {
		t.Fatalf("expected an organization-wide policy to converge regardless of stray config id, got %+v", graph.Nodes)
	}
}

func postureFinding(id string, detector string, severity FindingSeverity, now time.Time, evidence map[string]any) Finding {
	evidence["repository"] = "owner/repo"
	evidence["adapter_source"] = "github_posture"
	return Finding{
		ID:              id,
		Type:            FindingRepoMisconfig,
		Severity:        severity,
		ConfidenceScore: 0.92,
		Title:           "GitHub posture gap: " + detector,
		Repository:      "owner/repo",
		Detector:        detector,
		CreatedAt:       now,
		Evidence:        evidence,
	}
}

func assertGraphNode(t *testing.T, graph RepoRiskGraph, kind RepoRiskGraphNodeKind, label string) {
	t.Helper()
	for _, node := range graph.Nodes {
		if node.Kind == kind && node.Label == label {
			return
		}
	}
	t.Fatalf("expected node kind=%s label=%q in %+v", kind, label, graph.Nodes)
}

func assertGraphEdge(t *testing.T, graph RepoRiskGraph, kind RepoRiskGraphEdgeKind, state RepoRiskGraphEvidenceState) {
	t.Helper()
	for _, edge := range graph.Edges {
		if edge.Kind == kind && edge.EvidenceState == state {
			return
		}
	}
	t.Fatalf("expected edge kind=%s state=%s in %+v", kind, state, graph.Edges)
}

func assertGraphNodeID(t *testing.T, graph RepoRiskGraph, id string) {
	t.Helper()
	for _, node := range graph.Nodes {
		if node.ID == id {
			return
		}
	}
	t.Fatalf("expected graph node id %q in %+v", id, graph.Nodes)
}

func scoreForFinding(t *testing.T, graph RepoRiskGraph, findingID string) RepoRiskGraphFindingScore {
	t.Helper()
	for _, score := range graph.Scores {
		if score.FindingID == findingID {
			return score
		}
	}
	t.Fatalf("expected score for finding %q in %+v", findingID, graph.Scores)
	return RepoRiskGraphFindingScore{}
}

func countNodes(graph RepoRiskGraph, kind RepoRiskGraphNodeKind) int {
	count := 0
	for _, node := range graph.Nodes {
		if node.Kind == kind {
			count++
		}
	}
	return count
}

func countEdges(graph RepoRiskGraph, kind RepoRiskGraphEdgeKind) int {
	count := 0
	for _, edge := range graph.Edges {
		if edge.Kind == kind {
			count++
		}
	}
	return count
}
