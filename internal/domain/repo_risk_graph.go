package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RepoRiskGraphNodeKind identifies the machine-identity blast-radius concept
// represented by one graph node.
type RepoRiskGraphNodeKind string

const (
	RepoRiskNodeRepository               RepoRiskGraphNodeKind = "repository"
	RepoRiskNodeDefaultBranch            RepoRiskGraphNodeKind = "default_branch"
	RepoRiskNodeFinding                  RepoRiskGraphNodeKind = "finding"
	RepoRiskNodeWorkflow                 RepoRiskGraphNodeKind = "workflow"
	RepoRiskNodeWorkflowJob              RepoRiskGraphNodeKind = "workflow_job"
	RepoRiskNodeEnvironment              RepoRiskGraphNodeKind = "environment"
	RepoRiskNodeSecret                   RepoRiskGraphNodeKind = "secret"
	RepoRiskNodeDeployKey                RepoRiskGraphNodeKind = "deploy_key"
	RepoRiskNodeGitHubApp                RepoRiskGraphNodeKind = "github_app"
	RepoRiskNodeToken                    RepoRiskGraphNodeKind = "token"
	RepoRiskNodeOIDCSubject              RepoRiskGraphNodeKind = "oidc_subject"
	RepoRiskNodeCloudRole                RepoRiskGraphNodeKind = "cloud_role"
	RepoRiskNodeKubernetesServiceAccount RepoRiskGraphNodeKind = "kubernetes_service_account"
	RepoRiskNodeUnknown                  RepoRiskGraphNodeKind = "unknown"
)

// RepoRiskGraphEdgeKind describes directional evidence between graph nodes.
type RepoRiskGraphEdgeKind string

const (
	RepoRiskEdgeContainsWorkflow       RepoRiskGraphEdgeKind = "repository_contains_workflow"
	RepoRiskEdgeDefaultBranch          RepoRiskGraphEdgeKind = "repository_default_branch"
	RepoRiskEdgeFindingInRepository    RepoRiskGraphEdgeKind = "finding_in_repository"
	RepoRiskEdgeFindingAffectsWorkflow RepoRiskGraphEdgeKind = "finding_affects_workflow"
	RepoRiskEdgeWorkflowRunsJob        RepoRiskGraphEdgeKind = "workflow_runs_job"
	RepoRiskEdgeJobUsesSecret          RepoRiskGraphEdgeKind = "job_uses_secret"
	RepoRiskEdgeFindingExposesToken    RepoRiskGraphEdgeKind = "finding_exposes_token"
	RepoRiskEdgeWorkflowCanMintToken   RepoRiskGraphEdgeKind = "workflow_can_mint_token"
	RepoRiskEdgeOIDCCanAssumeRole      RepoRiskGraphEdgeKind = "oidc_subject_can_assume_role"
	RepoRiskEdgeRepoDeploysEnvironment RepoRiskGraphEdgeKind = "repo_deploys_to_environment"
	RepoRiskEdgeFindingReferencesID    RepoRiskGraphEdgeKind = "finding_references_identity"
	RepoRiskEdgeReachabilityUnknown    RepoRiskGraphEdgeKind = "reachability_unknown"
)

// RepoRiskGraphEvidenceState records whether a node or edge is backed by direct
// evidence or intentionally represents a gap that the scanner could not prove.
type RepoRiskGraphEvidenceState string

const (
	RepoRiskEvidenceKnown   RepoRiskGraphEvidenceState = "known"
	RepoRiskEvidenceUnknown RepoRiskGraphEvidenceState = "unknown"
)

// RepoRiskGraphOptions controls repository-level context for graph creation.
type RepoRiskGraphOptions struct {
	Repository    string
	DefaultBranch string
	Now           time.Time
}

// RepoRiskGraph links repository findings to workflows, credentials, and
// machine-identity concepts that can be derived from scanner evidence.
type RepoRiskGraph struct {
	Repository string                      `json:"repository,omitempty"`
	Nodes      []RepoRiskGraphNode         `json:"nodes"`
	Edges      []RepoRiskGraphEdge         `json:"edges"`
	Scores     []RepoRiskGraphFindingScore `json:"scores"`
	Summary    RepoRiskGraphSummary        `json:"summary"`
}

// RepoRiskGraphSummary provides cheap counters for API clients that do not need
// to traverse every node and edge.
type RepoRiskGraphSummary struct {
	FindingCount     int `json:"finding_count"`
	NodeCount        int `json:"node_count"`
	EdgeCount        int `json:"edge_count"`
	UnknownNodeCount int `json:"unknown_node_count"`
	UnknownEdgeCount int `json:"unknown_edge_count"`
	HighRiskFindings int `json:"high_risk_findings"`
	CriticalFindings int `json:"critical_findings"`
}

// RepoRiskGraphNode is one vertex in the repo-to-machine-identity graph.
type RepoRiskGraphNode struct {
	ID            string                     `json:"id"`
	Kind          RepoRiskGraphNodeKind      `json:"kind"`
	Label         string                     `json:"label"`
	Repository    string                     `json:"repository,omitempty"`
	EvidenceState RepoRiskGraphEvidenceState `json:"evidence_state"`
	Evidence      map[string]any             `json:"evidence,omitempty"`
}

// RepoRiskGraphEdge is one directed relationship in the repo risk graph.
type RepoRiskGraphEdge struct {
	ID            string                     `json:"id"`
	Kind          RepoRiskGraphEdgeKind      `json:"kind"`
	FromNodeID    string                     `json:"from_node_id"`
	ToNodeID      string                     `json:"to_node_id"`
	EvidenceState RepoRiskGraphEvidenceState `json:"evidence_state"`
	Evidence      map[string]any             `json:"evidence,omitempty"`
}

// RepoRiskGraphFindingScore records the graph-aware risk score for one finding.
type RepoRiskGraphFindingScore struct {
	FindingID     string                    `json:"finding_id"`
	FindingNodeID string                    `json:"finding_node_id"`
	Score         int                       `json:"score"`
	Severity      FindingSeverity           `json:"severity"`
	Confidence    float64                   `json:"confidence"`
	Factors       RepoRiskGraphScoreFactors `json:"factors"`
	Unknowns      []string                  `json:"unknowns,omitempty"`
}

// RepoRiskGraphScoreFactors makes graph score inputs inspectable.
type RepoRiskGraphScoreFactors struct {
	Severity               int `json:"severity"`
	Confidence             int `json:"confidence"`
	Exploitability         int `json:"exploitability"`
	Privilege              int `json:"privilege"`
	Exposure               int `json:"exposure"`
	EnvironmentCriticality int `json:"environment_criticality"`
	Freshness              int `json:"freshness"`
}

type repoRiskGraphBuilder struct {
	graph RepoRiskGraph
	nodes map[string]RepoRiskGraphNode
	edges map[string]RepoRiskGraphEdge
	now   time.Time
}

// BuildRepoRiskGraph builds a deterministic graph from repository findings and
// the scanner evidence already attached to them. It never invents cloud roles,
// environments, or Kubernetes identities when evidence is missing; those paths
// are represented as unknown nodes and edges.
func BuildRepoRiskGraph(findings []Finding, options RepoRiskGraphOptions) RepoRiskGraph {
	if len(findings) == 0 {
		return RepoRiskGraph{
			Repository: strings.TrimSpace(options.Repository),
			Nodes:      []RepoRiskGraphNode{},
			Edges:      []RepoRiskGraphEdge{},
			Scores:     []RepoRiskGraphFindingScore{},
		}
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	builder := repoRiskGraphBuilder{
		nodes: map[string]RepoRiskGraphNode{},
		edges: map[string]RepoRiskGraphEdge{},
		now:   now.UTC(),
	}

	repository := strings.TrimSpace(options.Repository)
	if repository == "" {
		repository = commonRepository(findings)
	}
	builder.graph.Repository = repository

	repositoryNodeIDs := map[string]string{}
	if repository != "" {
		repositoryNodeID := builder.upsertNode(RepoRiskNodeRepository, repository, repository, repository, RepoRiskEvidenceKnown, map[string]any{
			"repository": repository,
		})
		repositoryNodeIDs[repository] = repositoryNodeID
		if branch := strings.TrimSpace(options.DefaultBranch); branch != "" {
			branchID := builder.upsertNode(RepoRiskNodeDefaultBranch, repository+":"+branch, branch, repository, RepoRiskEvidenceKnown, map[string]any{
				"repository":     repository,
				"default_branch": branch,
			})
			builder.upsertEdge(RepoRiskEdgeDefaultBranch, repositoryNodeID, branchID, RepoRiskEvidenceKnown, map[string]any{
				"source": "scanner_context",
			})
		}
	}

	for _, raw := range findings {
		finding := raw
		NormalizeRepoFindingMetadata(&finding)
		findingRepository := strings.TrimSpace(finding.Repository)
		if findingRepository == "" {
			findingRepository = repository
		}
		repositoryNodeID := repositoryNodeIDs[findingRepository]
		if repositoryNodeID == "" && findingRepository != "" {
			repositoryNodeID = builder.upsertNode(RepoRiskNodeRepository, findingRepository, findingRepository, findingRepository, RepoRiskEvidenceKnown, map[string]any{
				"repository": findingRepository,
			})
			repositoryNodeIDs[findingRepository] = repositoryNodeID
		}

		findingKey := repoRiskFindingKey(finding)
		findingPublicID := repoRiskFindingPublicID(finding, findingKey)
		findingNodeID := builder.upsertNode(RepoRiskNodeFinding, findingKey, findingLabel(finding), findingRepository, RepoRiskEvidenceKnown, findingNodeEvidence(finding, findingPublicID))
		if repositoryNodeID != "" {
			builder.upsertEdge(RepoRiskEdgeFindingInRepository, findingNodeID, repositoryNodeID, RepoRiskEvidenceKnown, map[string]any{
				"finding_id": findingPublicID,
			})
		} else {
			unknownRepoID := builder.upsertUnknownNode(RepoRiskNodeRepository, "unknown repository", findingRepository, map[string]any{
				"finding_id": findingPublicID,
				"reason":     "repository_missing",
			})
			builder.upsertEdge(RepoRiskEdgeFindingInRepository, findingNodeID, unknownRepoID, RepoRiskEvidenceUnknown, map[string]any{
				"finding_id": findingPublicID,
				"reason":     "repository_missing",
			})
		}

		workflowID, jobID := builder.addWorkflowReachability(finding, findingPublicID, findingNodeID, repositoryNodeID, findingRepository)
		builder.addEnvironmentReachability(finding, findingPublicID, findingNodeID, repositoryNodeID, findingRepository)
		builder.addSecretAndTokenReachability(finding, findingPublicID, findingNodeID, jobID, findingRepository)
		builder.addOIDCReachability(finding, findingPublicID, findingNodeID, workflowID, jobID, findingRepository)
		builder.addIdentityReachability(finding, findingPublicID, findingNodeID, findingRepository)

		score := scoreRepoRiskFinding(finding, builder.now, findingPublicID, findingNodeID)
		builder.graph.Scores = append(builder.graph.Scores, score)
	}

	builder.finish()
	return builder.graph
}

func commonRepository(findings []Finding) string {
	var repository string
	for _, raw := range findings {
		finding := raw
		NormalizeRepoFindingMetadata(&finding)
		candidate := strings.TrimSpace(finding.Repository)
		if candidate == "" {
			continue
		}
		if repository == "" {
			repository = candidate
			continue
		}
		if repository != candidate {
			return ""
		}
	}
	return repository
}

func repoRiskFindingKey(finding Finding) string {
	return strings.Join([]string{
		strings.TrimSpace(finding.ScanID),
		strings.TrimSpace(finding.Repository),
		strings.TrimSpace(finding.ID),
		string(finding.Type),
		strings.TrimSpace(finding.Detector),
		strings.TrimSpace(finding.FilePath),
		strconv.Itoa(finding.LineNumber),
	}, "\x1f")
}

func repoRiskFindingPublicID(finding Finding, key string) string {
	if id := strings.TrimSpace(finding.ID); id != "" {
		return id
	}
	return "finding:" + repoRiskDigest(key)
}

func (builder *repoRiskGraphBuilder) addWorkflowReachability(finding Finding, findingPublicID string, findingNodeID string, repositoryNodeID string, repository string) (string, string) {
	workflowPath := workflowPathForFinding(finding)
	if workflowPath == "" {
		return "", ""
	}

	workflowID := builder.upsertNode(RepoRiskNodeWorkflow, repository+":"+workflowPath, workflowPath, repository, RepoRiskEvidenceKnown, map[string]any{
		"file_path":  workflowPath,
		"repository": repository,
	})
	if repositoryNodeID != "" {
		builder.upsertEdge(RepoRiskEdgeContainsWorkflow, repositoryNodeID, workflowID, RepoRiskEvidenceKnown, map[string]any{
			"file_path": workflowPath,
		})
	}
	builder.upsertEdge(RepoRiskEdgeFindingAffectsWorkflow, findingNodeID, workflowID, RepoRiskEvidenceKnown, map[string]any{
		"finding_id": findingPublicID,
		"file_path":  workflowPath,
	})

	jobName := strings.TrimSpace(stringFromAny(finding.Evidence["workflow_job"]))
	if jobName == "" {
		return workflowID, ""
	}
	jobID := builder.upsertNode(RepoRiskNodeWorkflowJob, repository+":"+workflowPath+":"+jobName, jobName, repository, RepoRiskEvidenceKnown, map[string]any{
		"file_path":    workflowPath,
		"workflow_job": jobName,
	})
	builder.upsertEdge(RepoRiskEdgeWorkflowRunsJob, workflowID, jobID, RepoRiskEvidenceKnown, map[string]any{
		"workflow_job": jobName,
	})
	return workflowID, jobID
}

func (builder *repoRiskGraphBuilder) addEnvironmentReachability(finding Finding, findingPublicID string, findingNodeID string, repositoryNodeID string, repository string) {
	environment := firstEvidenceString(finding.Evidence, "environment", "deployment_environment", "github_environment", "repo_environment")
	if environment == "" {
		return
	}
	environmentID := builder.upsertNode(RepoRiskNodeEnvironment, repository+":"+environment, environment, repository, RepoRiskEvidenceKnown, map[string]any{
		"environment": environment,
		"criticality": environmentCriticality(environment),
	})
	if repositoryNodeID != "" {
		builder.upsertEdge(RepoRiskEdgeRepoDeploysEnvironment, repositoryNodeID, environmentID, RepoRiskEvidenceKnown, map[string]any{
			"environment": environment,
		})
	}
	builder.upsertEdge(RepoRiskEdgeFindingReferencesID, findingNodeID, environmentID, RepoRiskEvidenceKnown, map[string]any{
		"finding_id": findingPublicID,
		"evidence":   "environment",
	})
}

func (builder *repoRiskGraphBuilder) addSecretAndTokenReachability(finding Finding, findingPublicID string, findingNodeID string, jobID string, repository string) {
	secretLabel := secretLabelForFinding(finding)
	if secretLabel == "" && !findingReferencesSecrets(finding) {
		return
	}
	kind := RepoRiskNodeSecret
	if finding.Type == FindingSecretExposure {
		kind = RepoRiskNodeToken
	}
	if secretLabel == "" {
		secretLabel = "referenced GitHub secret"
	}
	secretID := builder.upsertNode(kind, repository+":"+string(kind)+":"+secretLabel, secretLabel, repository, RepoRiskEvidenceKnown, map[string]any{
		"secret_label":  secretLabel,
		"raw_available": false,
	})
	if finding.Type == FindingSecretExposure {
		builder.upsertEdge(RepoRiskEdgeFindingExposesToken, findingNodeID, secretID, RepoRiskEvidenceKnown, map[string]any{
			"finding_id":        findingPublicID,
			"raw_secret_stored": false,
		})
		return
	}
	if jobID != "" {
		builder.upsertEdge(RepoRiskEdgeJobUsesSecret, jobID, secretID, RepoRiskEvidenceKnown, map[string]any{
			"finding_id": findingPublicID,
		})
	} else {
		builder.upsertEdge(RepoRiskEdgeFindingReferencesID, findingNodeID, secretID, RepoRiskEvidenceKnown, map[string]any{
			"finding_id": findingPublicID,
			"evidence":   "references_secrets",
		})
	}
}

func (builder *repoRiskGraphBuilder) addOIDCReachability(finding Finding, findingPublicID string, findingNodeID string, workflowID string, jobID string, repository string) {
	if !findingReferencesOIDC(finding) {
		return
	}
	subject := firstEvidenceString(finding.Evidence, "oidc_subject", "github_oidc_subject")
	if subject == "" {
		subject = oidcSubjectFromFinding(finding)
	}
	subjectID := builder.upsertNode(RepoRiskNodeOIDCSubject, repository+":"+subject, subject, repository, RepoRiskEvidenceKnown, map[string]any{
		"oidc_subject": subject,
	})
	fromNodeID := workflowID
	if jobID != "" {
		fromNodeID = jobID
	}
	if fromNodeID == "" {
		fromNodeID = findingNodeID
	}
	builder.upsertEdge(RepoRiskEdgeWorkflowCanMintToken, fromNodeID, subjectID, RepoRiskEvidenceKnown, map[string]any{
		"finding_id":         findingPublicID,
		"permission_summary": strings.TrimSpace(stringFromAny(finding.Evidence["permission_summary"])),
		"oidc_risk_context":  strings.TrimSpace(stringFromAny(finding.Evidence["oidc_risk_context"])),
	})

	if role := cloudRoleForFinding(finding); role != "" {
		roleID := builder.upsertNode(RepoRiskNodeCloudRole, repository+":"+role, role, repository, RepoRiskEvidenceKnown, map[string]any{
			"role": role,
		})
		builder.upsertEdge(RepoRiskEdgeOIDCCanAssumeRole, subjectID, roleID, RepoRiskEvidenceKnown, map[string]any{
			"finding_id": findingPublicID,
		})
		return
	}

	unknownRoleID := builder.upsertUnknownNode(RepoRiskNodeCloudRole, "unknown cloud role", repository, map[string]any{
		"finding_id": findingPublicID,
		"reason":     "oidc_target_role_missing",
	})
	builder.upsertEdge(RepoRiskEdgeReachabilityUnknown, subjectID, unknownRoleID, RepoRiskEvidenceUnknown, map[string]any{
		"finding_id": findingPublicID,
		"reason":     "oidc_target_role_missing",
	})
}

func (builder *repoRiskGraphBuilder) addIdentityReachability(finding Finding, findingPublicID string, findingNodeID string, repository string) {
	if role := cloudRoleForFinding(finding); role != "" {
		roleID := builder.upsertNode(RepoRiskNodeCloudRole, repository+":"+role, role, repository, RepoRiskEvidenceKnown, map[string]any{
			"role": role,
		})
		builder.upsertEdge(RepoRiskEdgeFindingReferencesID, findingNodeID, roleID, RepoRiskEvidenceKnown, map[string]any{
			"finding_id": findingPublicID,
			"evidence":   "cloud_role",
		})
	}
	if serviceAccount := firstEvidenceString(finding.Evidence, "kubernetes_service_account", "service_account", "gcp_service_account"); serviceAccount != "" {
		kind := RepoRiskNodeKubernetesServiceAccount
		naturalKey := repository + ":" + string(kind) + ":" + serviceAccount
		if strings.Contains(serviceAccount, "@") && strings.Contains(serviceAccount, ".iam.gserviceaccount.com") {
			kind = RepoRiskNodeCloudRole
			naturalKey = repository + ":" + serviceAccount
		}
		serviceAccountID := builder.upsertNode(kind, naturalKey, serviceAccount, repository, RepoRiskEvidenceKnown, map[string]any{
			"service_account": serviceAccount,
		})
		builder.upsertEdge(RepoRiskEdgeFindingReferencesID, findingNodeID, serviceAccountID, RepoRiskEvidenceKnown, map[string]any{
			"finding_id": findingPublicID,
			"evidence":   "service_account",
		})
	}
	if app := firstEvidenceString(finding.Evidence, "github_app", "github_app_slug", "github_app_id"); app != "" {
		appID := builder.upsertNode(RepoRiskNodeGitHubApp, repository+":"+app, app, repository, RepoRiskEvidenceKnown, map[string]any{
			"github_app": app,
		})
		builder.upsertEdge(RepoRiskEdgeFindingReferencesID, findingNodeID, appID, RepoRiskEvidenceKnown, map[string]any{
			"finding_id": findingPublicID,
			"evidence":   "github_app",
		})
	}
	if key := firstEvidenceString(finding.Evidence, "deploy_key", "deploy_key_id", "deploy_key_fingerprint"); key != "" {
		keyID := builder.upsertNode(RepoRiskNodeDeployKey, repository+":"+key, key, repository, RepoRiskEvidenceKnown, map[string]any{
			"deploy_key": key,
		})
		builder.upsertEdge(RepoRiskEdgeFindingReferencesID, findingNodeID, keyID, RepoRiskEvidenceKnown, map[string]any{
			"finding_id": findingPublicID,
			"evidence":   "deploy_key",
		})
	}
}

func (builder *repoRiskGraphBuilder) upsertNode(kind RepoRiskGraphNodeKind, naturalKey string, label string, repository string, state RepoRiskGraphEvidenceState, evidence map[string]any) string {
	id := repoRiskNodeID(kind, naturalKey)
	node, exists := builder.nodes[id]
	if !exists {
		node = RepoRiskGraphNode{
			ID:            id,
			Kind:          kind,
			Label:         strings.TrimSpace(label),
			Repository:    strings.TrimSpace(repository),
			EvidenceState: state,
			Evidence:      compactEvidence(evidence),
		}
		if node.Label == "" {
			node.Label = string(kind)
		}
		builder.nodes[id] = node
		return id
	}
	if node.Repository == "" {
		node.Repository = strings.TrimSpace(repository)
	}
	if node.Label == "" && strings.TrimSpace(label) != "" {
		node.Label = strings.TrimSpace(label)
	}
	if node.EvidenceState == RepoRiskEvidenceUnknown && state == RepoRiskEvidenceKnown {
		node.EvidenceState = RepoRiskEvidenceKnown
	}
	node.Evidence = mergeEvidence(node.Evidence, evidence)
	builder.nodes[id] = node
	return id
}

func (builder *repoRiskGraphBuilder) upsertUnknownNode(kind RepoRiskGraphNodeKind, label string, repository string, evidence map[string]any) string {
	naturalKey := strings.Join([]string{strings.TrimSpace(repository), string(kind), strings.TrimSpace(label), strings.TrimSpace(stringFromAny(evidence["reason"]))}, "\x1f")
	return builder.upsertNode(RepoRiskNodeUnknown, naturalKey, label, repository, RepoRiskEvidenceUnknown, evidence)
}

func (builder *repoRiskGraphBuilder) upsertEdge(kind RepoRiskGraphEdgeKind, fromNodeID string, toNodeID string, state RepoRiskGraphEvidenceState, evidence map[string]any) string {
	if fromNodeID == "" || toNodeID == "" {
		return ""
	}
	id := repoRiskEdgeID(kind, fromNodeID, toNodeID)
	edge, exists := builder.edges[id]
	if !exists {
		builder.edges[id] = RepoRiskGraphEdge{
			ID:            id,
			Kind:          kind,
			FromNodeID:    fromNodeID,
			ToNodeID:      toNodeID,
			EvidenceState: state,
			Evidence:      compactEvidence(evidence),
		}
		return id
	}
	if edge.EvidenceState == RepoRiskEvidenceUnknown && state == RepoRiskEvidenceKnown {
		edge.EvidenceState = RepoRiskEvidenceKnown
	}
	edge.Evidence = mergeEvidence(edge.Evidence, evidence)
	builder.edges[id] = edge
	return id
}

func (builder *repoRiskGraphBuilder) finish() {
	builder.graph.Nodes = make([]RepoRiskGraphNode, 0, len(builder.nodes))
	for _, node := range builder.nodes {
		builder.graph.Nodes = append(builder.graph.Nodes, node)
		if node.EvidenceState == RepoRiskEvidenceUnknown {
			builder.graph.Summary.UnknownNodeCount++
		}
	}
	sort.SliceStable(builder.graph.Nodes, func(i, j int) bool {
		left := builder.graph.Nodes[i]
		right := builder.graph.Nodes[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Label != right.Label {
			return left.Label < right.Label
		}
		return left.ID < right.ID
	})

	builder.graph.Edges = make([]RepoRiskGraphEdge, 0, len(builder.edges))
	for _, edge := range builder.edges {
		builder.graph.Edges = append(builder.graph.Edges, edge)
		if edge.EvidenceState == RepoRiskEvidenceUnknown {
			builder.graph.Summary.UnknownEdgeCount++
		}
	}
	sort.SliceStable(builder.graph.Edges, func(i, j int) bool {
		left := builder.graph.Edges[i]
		right := builder.graph.Edges[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.FromNodeID != right.FromNodeID {
			return left.FromNodeID < right.FromNodeID
		}
		if left.ToNodeID != right.ToNodeID {
			return left.ToNodeID < right.ToNodeID
		}
		return left.ID < right.ID
	})

	sort.SliceStable(builder.graph.Scores, func(i, j int) bool {
		left := builder.graph.Scores[i]
		right := builder.graph.Scores[j]
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		return left.FindingID < right.FindingID
	})
	for _, score := range builder.graph.Scores {
		if score.Score >= 85 {
			builder.graph.Summary.CriticalFindings++
		} else if score.Score >= 70 {
			builder.graph.Summary.HighRiskFindings++
		}
	}
	builder.graph.Summary.FindingCount = len(builder.graph.Scores)
	builder.graph.Summary.NodeCount = len(builder.graph.Nodes)
	builder.graph.Summary.EdgeCount = len(builder.graph.Edges)
}

func scoreRepoRiskFinding(finding Finding, now time.Time, findingID string, findingNodeID string) RepoRiskGraphFindingScore {
	factors := RepoRiskGraphScoreFactors{
		Severity:               repoRiskSeverityFactor(finding.Severity),
		Confidence:             repoRiskConfidenceFactor(finding),
		Exploitability:         repoRiskExploitabilityFactor(finding),
		Privilege:              repoRiskPrivilegeFactor(finding),
		Exposure:               repoRiskExposureFactor(finding),
		EnvironmentCriticality: repoRiskEnvironmentFactor(finding),
		Freshness:              repoRiskFreshnessFactor(finding, now),
	}
	weighted := float64(factors.Severity)*0.60 +
		float64(factors.Confidence)*0.10 +
		float64(factors.Exploitability)*0.12 +
		float64(factors.Privilege)*0.10 +
		float64(factors.Exposure)*0.05 +
		float64(factors.EnvironmentCriticality)*0.02 +
		float64(factors.Freshness)*0.01
	score := int(math.Round(weighted))
	score = clampInt(score, 0, 100)
	return RepoRiskGraphFindingScore{
		FindingID:     findingID,
		FindingNodeID: findingNodeID,
		Score:         score,
		Severity:      finding.Severity,
		Confidence:    confidenceForFinding(finding),
		Factors:       factors,
		Unknowns:      repoRiskUnknowns(finding),
	}
}

func repoRiskSeverityFactor(severity FindingSeverity) int {
	switch severity {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 80
	case SeverityMedium:
		return 55
	case SeverityLow:
		return 30
	case SeverityInfo:
		return 10
	default:
		return 20
	}
}

func repoRiskConfidenceFactor(finding Finding) int {
	return clampInt(int(math.Round(confidenceForFinding(finding)*100)), 1, 100)
}

func confidenceForFinding(finding Finding) float64 {
	if finding.ConfidenceScore > 0 {
		return clampFloat(finding.ConfidenceScore, 0.01, 0.99)
	}
	if confidence, ok := floatFromAny(finding.Evidence["confidence_score"]); ok && confidence > 0 {
		return clampFloat(confidence, 0.01, 0.99)
	}
	return 0.7
}

func repoRiskExploitabilityFactor(finding Finding) int {
	score := 0
	detector := strings.ToLower(strings.TrimSpace(finding.Detector))
	title := strings.ToLower(finding.Title + " " + finding.HumanSummary)
	if finding.Type == FindingSecretExposure {
		score += 35
	}
	for _, token := range []string{"pull_request_target", "untrusted_checkout", "shell_injection", "workflow_run", "cache_poisoning", "artifact_poisoning"} {
		if strings.Contains(detector, token) || strings.Contains(title, token) {
			score += 16
			break
		}
	}
	if strings.Contains(detector, "oidc") || strings.Contains(title, "oidc") {
		score += 18
	}
	if workflowHasUntrustedEventEvidence(finding.Evidence) {
		score += 12
	}
	if strings.TrimSpace(stringFromAny(finding.Evidence["cloud_auth_action"])) != "" {
		score += 10
	}
	return clampInt(score, 0, 100)
}

func repoRiskPrivilegeFactor(finding Finding) int {
	score := 0
	permissionSummary := strings.ToLower(strings.TrimSpace(stringFromAny(finding.Evidence["permission_summary"])))
	if permissionSummary == "write-all" || strings.Contains(permissionSummary, ":write") {
		score += 30
	}
	if len(evidenceStringSlice(finding.Evidence["write_scopes"])) > 0 {
		score += 20
	}
	if findingReferencesSecrets(finding) {
		score += 18
	}
	if findingReferencesOIDC(finding) {
		score += 20
	}
	if finding.Type == FindingSecretExposure {
		score += 24
	}
	if cloudRoleForFinding(finding) != "" {
		score += 18
	}
	return clampInt(score, 0, 100)
}

func repoRiskExposureFactor(finding Finding) int {
	score := 0
	for _, event := range evidenceStringSlice(finding.Evidence["workflow_events"]) {
		switch strings.ToLower(strings.TrimSpace(event)) {
		case "pull_request_target":
			score += 30
		case "workflow_run":
			score += 22
		case "pull_request":
			score += 15
		case "push":
			score += 8
		}
	}
	context := strings.ToLower(strings.TrimSpace(stringFromAny(finding.Evidence["oidc_risk_context"])))
	switch context {
	case "untrusted_event":
		score += 24
	case "workflow_run":
		score += 20
	case "broad_push_event":
		score += 16
	}
	if strings.Contains(strings.ToLower(strings.TrimSpace(finding.FilePath)), ".github/workflows/") {
		score += 10
	}
	return clampInt(score, 0, 100)
}

func repoRiskEnvironmentFactor(finding Finding) int {
	environment := firstEvidenceString(finding.Evidence, "environment", "deployment_environment", "github_environment", "repo_environment")
	switch environmentCriticality(environment) {
	case "production":
		return 100
	case "staging":
		return 55
	case "development":
		return 25
	default:
		return 0
	}
}

func repoRiskFreshnessFactor(finding Finding, now time.Time) int {
	if finding.CreatedAt.IsZero() || now.IsZero() {
		return 0
	}
	age := now.Sub(finding.CreatedAt.UTC())
	switch {
	case age < 0:
		return 20
	case age <= 7*24*time.Hour:
		return 100
	case age <= 30*24*time.Hour:
		return 70
	case age <= 90*24*time.Hour:
		return 35
	default:
		return 10
	}
}

func repoRiskUnknowns(finding Finding) []string {
	unknowns := []string{}
	if strings.TrimSpace(finding.Repository) == "" && strings.TrimSpace(stringFromAny(finding.Evidence["repository"])) == "" {
		unknowns = append(unknowns, "repository")
	}
	if findingReferencesOIDC(finding) && cloudRoleForFinding(finding) == "" {
		unknowns = append(unknowns, "identity_target")
	}
	if workflowPathForFinding(finding) != "" && strings.TrimSpace(stringFromAny(finding.Evidence["workflow_job"])) == "" {
		unknowns = append(unknowns, "workflow_job")
	}
	sort.Strings(unknowns)
	return unknowns
}

func workflowPathForFinding(finding Finding) string {
	path := strings.TrimSpace(finding.FilePath)
	if path == "" && len(finding.Path) == 1 {
		path = strings.TrimSpace(finding.Path[0])
	}
	if path == "" {
		path = strings.TrimSpace(stringFromAny(finding.Evidence["file_path"]))
	}
	clean := filepath.ToSlash(path)
	if strings.HasPrefix(strings.ToLower(clean), ".github/workflows/") {
		return clean
	}
	return ""
}

func findingLabel(finding Finding) string {
	switch {
	case strings.TrimSpace(finding.Title) != "":
		return strings.TrimSpace(finding.Title)
	case strings.TrimSpace(finding.Detector) != "":
		return strings.TrimSpace(finding.Detector)
	case strings.TrimSpace(finding.ID) != "":
		return strings.TrimSpace(finding.ID)
	default:
		return string(finding.Type)
	}
}

func findingNodeEvidence(finding Finding, findingPublicID string) map[string]any {
	evidence := map[string]any{
		"finding_id": findingPublicID,
		"type":       string(finding.Type),
		"severity":   string(finding.Severity),
	}
	if finding.Detector != "" {
		evidence["detector"] = finding.Detector
	}
	if finding.FilePath != "" {
		evidence["file_path"] = finding.FilePath
	}
	if finding.LineNumber > 0 {
		evidence["line_number"] = finding.LineNumber
	}
	if finding.ScanID != "" {
		evidence["scan_id"] = finding.ScanID
	}
	return evidence
}

func secretLabelForFinding(finding Finding) string {
	for _, key := range []string{"secret_name", "github_secret", "env_secret", "secret_key"} {
		if label := strings.TrimSpace(stringFromAny(finding.Evidence[key])); label != "" {
			return label
		}
	}
	if fingerprint := strings.TrimSpace(stringFromAny(finding.Evidence["secret_fingerprint"])); fingerprint != "" {
		return "secret-fingerprint:" + fingerprint
	}
	if finding.Type == FindingSecretExposure && strings.TrimSpace(finding.Detector) != "" {
		return strings.TrimSpace(finding.Detector)
	}
	return ""
}

func findingReferencesSecrets(finding Finding) bool {
	if finding.Type == FindingSecretExposure {
		return true
	}
	if references, ok := boolFromAny(finding.Evidence["references_secrets"]); ok && references {
		return true
	}
	detector := strings.ToLower(strings.TrimSpace(finding.Detector))
	return strings.Contains(detector, "secret")
}

func findingReferencesOIDC(finding Finding) bool {
	detector := strings.ToLower(strings.TrimSpace(finding.Detector))
	permissionSummary := strings.ToLower(strings.TrimSpace(stringFromAny(finding.Evidence["permission_summary"])))
	return strings.Contains(detector, "oidc") ||
		strings.TrimSpace(stringFromAny(finding.Evidence["oidc_risk_context"])) != "" ||
		strings.TrimSpace(stringFromAny(finding.Evidence["oidc_subject"])) != "" ||
		strings.Contains(permissionSummary, "id-token:write") ||
		strings.Contains(permissionSummary, "id-token: write")
}

func oidcSubjectFromFinding(finding Finding) string {
	repository := strings.TrimSpace(finding.Repository)
	if repository == "" {
		repository = strings.TrimSpace(stringFromAny(finding.Evidence["repository"]))
	}
	ref := strings.TrimSpace(stringFromAny(finding.Evidence["git_ref"]))
	if ref == "" {
		ref = strings.TrimSpace(stringFromAny(finding.Evidence["branch"]))
	}
	if ref == "" {
		ref = "*"
	}
	job := strings.TrimSpace(stringFromAny(finding.Evidence["workflow_job"]))
	switch {
	case repository != "" && job != "":
		return fmt.Sprintf("repo:%s:ref:%s:job:%s", repository, ref, job)
	case repository != "":
		return fmt.Sprintf("repo:%s:ref:%s", repository, ref)
	default:
		return "unknown OIDC subject"
	}
}

func cloudRoleForFinding(finding Finding) string {
	return firstEvidenceString(finding.Evidence, "aws_role_arn", "cloud_role_arn", "cloud_role", "azure_client_id", "gcp_service_account")
}

func workflowHasUntrustedEventEvidence(evidence map[string]any) bool {
	for _, event := range evidenceStringSlice(evidence["workflow_events"]) {
		switch strings.ToLower(strings.TrimSpace(event)) {
		case "pull_request", "pull_request_target", "workflow_run":
			return true
		}
	}
	return false
}

func firstEvidenceString(evidence map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(stringFromAny(evidence[key])); value != "" {
			return value
		}
	}
	return ""
}

func evidenceStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		result := append([]string(nil), typed...)
		sort.Strings(result)
		return result
	case []any:
		result := []string{}
		for _, item := range typed {
			if value := strings.TrimSpace(stringFromAny(item)); value != "" {
				result = append(result, value)
			}
		}
		sort.Strings(result)
		return result
	default:
		return nil
	}
}

func environmentCriticality(environment string) string {
	normalized := strings.ToLower(strings.TrimSpace(environment))
	switch {
	case normalized == "":
		return "unknown"
	case strings.Contains(normalized, "prod") || strings.Contains(normalized, "live"):
		return "production"
	case strings.Contains(normalized, "stage") || strings.Contains(normalized, "staging") || strings.Contains(normalized, "preprod"):
		return "staging"
	case strings.Contains(normalized, "dev") || strings.Contains(normalized, "test") || strings.Contains(normalized, "sandbox"):
		return "development"
	default:
		return "unknown"
	}
}

func repoRiskNodeID(kind RepoRiskGraphNodeKind, naturalKey string) string {
	return "repo-risk-node:" + string(kind) + ":" + repoRiskDigest(strings.TrimSpace(naturalKey))
}

func repoRiskEdgeID(kind RepoRiskGraphEdgeKind, fromNodeID string, toNodeID string) string {
	return "repo-risk-edge:" + string(kind) + ":" + repoRiskDigest(strings.Join([]string{fromNodeID, toNodeID}, "\x1f"))
}

func repoRiskDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:12])
}

func compactEvidence(evidence map[string]any) map[string]any {
	if len(evidence) == 0 {
		return nil
	}
	result := map[string]any{}
	for key, value := range evidence {
		if strings.TrimSpace(key) == "" || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				result[key] = typed
			}
		case []string:
			if len(typed) > 0 {
				copied := append([]string(nil), typed...)
				sort.Strings(copied)
				result[key] = copied
			}
		default:
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func mergeEvidence(existing map[string]any, extra map[string]any) map[string]any {
	if len(extra) == 0 {
		return existing
	}
	merged := compactEvidence(existing)
	if merged == nil {
		merged = map[string]any{}
	}
	for key, value := range compactEvidence(extra) {
		if _, exists := merged[key]; !exists {
			merged[key] = value
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func clampInt(value int, minimum int, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func clampFloat(value float64, minimum float64, maximum float64) float64 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
