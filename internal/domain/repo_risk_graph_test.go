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
