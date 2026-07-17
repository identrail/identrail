package domain

import (
	"sort"
	"strings"
)

// GitHub posture check states carried on repo findings by the GitHub posture
// adapters. Only "insecure" proves a weak control; the remaining states mean the
// scanner could not observe the control and must surface uncertainty instead.
const (
	repoRiskPostureStateInsecure          = "insecure"
	repoRiskPostureStatePermissionLimited = "permission_limited"
	repoRiskPostureStateUnavailable       = "unavailable"
	repoRiskPostureStateUnknown           = "unknown"
)

const (
	repoRiskPostureScopeRepository   = "repository"
	repoRiskPostureScopeOrganization = "organization"
)

// repoRiskPostureEvidenceKeys are the summary-shaped posture evidence values
// worth carrying onto a control node. Runner labels, hook counts, and policy
// modes describe the control itself; anything not listed here stays on the
// finding node so control nodes do not accumulate scan-scoped detail.
var repoRiskPostureEvidenceKeys = []string{
	"active_rulesets",
	"active_webhooks",
	"admins_enforced",
	"allowed_actions",
	"allowed_pattern_count",
	"branch_deletions_allowed",
	"broadly_available_runner_groups",
	"can_approve_pull_request_reviews",
	"default_workflow_permissions",
	"dependabot_alerts_enabled",
	"dependabot_security_updates_enabled",
	"deploy_key_count",
	"enabled",
	"enabled_repositories",
	"environment_count",
	"evaluate_rulesets",
	"failing_webhooks",
	"force_pushes_allowed",
	"github_owned_allowed",
	"insecure_ssl_hooks",
	"online_runners",
	"open_alerts_sampled",
	"org_runner_groups",
	"public_repository_runner_groups",
	"readonly_deploy_keys",
	"required_reviews",
	"required_status_checks",
	"ruleset_count",
	"runner_groups_state",
	"runner_labels",
	"runner_os",
	"self_hosted_runner_count",
	"unprotected_environments",
	"verified_allowed",
	"webhook_count",
	"writable_deploy_keys",
}

// repoRiskPostureControl is the GitHub control-plane concept behind one posture
// finding, resolved purely from evidence the posture collector recorded.
type repoRiskPostureControl struct {
	Kind         RepoRiskGraphNodeKind
	Label        string
	CheckID      string
	Category     string
	Scope        string
	State        string
	Organization string
}

// Observed reports whether the posture collector could actually read the
// control. An unobserved control still belongs in the graph, but as uncertainty.
func (control repoRiskPostureControl) Observed() bool {
	switch control.State {
	case repoRiskPostureStatePermissionLimited, repoRiskPostureStateUnavailable, repoRiskPostureStateUnknown:
		return false
	default:
		return true
	}
}

// Weak reports whether the collector proved the control is configured weakly.
func (control repoRiskPostureControl) Weak() bool {
	return control.State == repoRiskPostureStateInsecure
}

// repoRiskPostureControlForFinding resolves the control-plane node a posture
// finding describes. Findings without posture evidence, and posture checks with
// no control-plane concept of their own, return false so the graph does not
// invent structure.
func repoRiskPostureControlForFinding(finding Finding) (repoRiskPostureControl, bool) {
	checkID := strings.ToLower(firstEvidenceString(finding.Evidence, "github_posture_check_id"))
	if checkID == "" {
		return repoRiskPostureControl{}, false
	}
	control := repoRiskPostureControl{
		CheckID:      checkID,
		Category:     firstEvidenceString(finding.Evidence, "github_posture_category"),
		Scope:        strings.ToLower(firstEvidenceString(finding.Evidence, "github_posture_scope")),
		State:        strings.ToLower(firstEvidenceString(finding.Evidence, "github_posture_state")),
		Organization: firstEvidenceString(finding.Evidence, "organization"),
	}
	if control.Scope == "" {
		control.Scope = repoRiskPostureScopeRepository
	}

	switch checkID {
	case "default_branch_protection":
		control.Kind = RepoRiskNodeBranchProtection
		branch := firstEvidenceString(finding.Evidence, "default_branch")
		if branch == "" {
			branch = "default branch"
		}
		control.Label = "branch protection: " + branch
	case "repository_rulesets":
		control.Kind = RepoRiskNodeRepositoryRuleset
		control.Label = "repository rulesets"
	case "actions_permissions":
		control.Kind = RepoRiskNodeActionsPolicy
		control.Label = "Actions policy: repository"
	case "org_actions_policy":
		control.Kind = RepoRiskNodeActionsPolicy
		control.Label = "Actions policy: " + repoRiskPostureOrgLabel(control.Organization)
	case "org_workflow_permissions":
		control.Kind = RepoRiskNodeWorkflowPermissionDefault
		control.Label = "default workflow permissions: " + repoRiskPostureOrgLabel(control.Organization)
	case "org_reusable_workflow_policy":
		control.Kind = RepoRiskNodeReusableWorkflowPolicy
		control.Label = "reusable workflow policy: " + repoRiskPostureOrgLabel(control.Organization)
	case "self_hosted_runners":
		control.Kind = RepoRiskNodeRunnerGroup
		control.Label = "self-hosted runner group"
	case "deployment_environments":
		control.Kind = RepoRiskNodeEnvironmentProtection
		control.Label = "deployment environment protection"
	case "deploy_keys":
		control.Kind = RepoRiskNodeDeployKey
		control.Label = "repository deploy keys"
	case "webhooks":
		control.Kind = RepoRiskNodeWebhook
		control.Label = "repository webhooks"
	case "dependabot_security":
		control.Kind = RepoRiskNodeAlertSource
		control.Label = "alert source: Dependabot"
	case "code_scanning":
		control.Kind = RepoRiskNodeAlertSource
		control.Label = "alert source: code scanning"
	case "secret_scanning":
		control.Kind = RepoRiskNodeAlertSource
		control.Label = "alert source: secret scanning"
	case "org_secret_scanning_policy":
		control.Kind = RepoRiskNodeAlertSource
		control.Label = "alert source: secret scanning policy: " + repoRiskPostureOrgLabel(control.Organization)
	case "org_code_security_configuration":
		control.Kind = RepoRiskNodeOrgSecurityConfiguration
		control.Label = "code security configuration: " + repoRiskPostureOrgLabel(control.Organization)
	default:
		// repository_metadata and any future check without a control-plane
		// concept stay finding-only rather than becoming a speculative node.
		return repoRiskPostureControl{}, false
	}
	return control, true
}

func repoRiskPostureOrgLabel(organization string) string {
	if organization == "" {
		return "organization"
	}
	return organization
}

// addPostureReachability attaches the GitHub control-plane node behind a posture
// finding, links the repository to the control it is governed by or inherits,
// and records the finding's relationship to that control.
func (builder *repoRiskGraphBuilder) addPostureReachability(finding Finding, findingPublicID string, findingNodeID string, repositoryNodeID string, repository string) {
	control, ok := repoRiskPostureControlForFinding(finding)
	if !ok {
		return
	}

	controlState := RepoRiskEvidenceKnown
	if !control.Observed() {
		controlState = RepoRiskEvidenceUnknown
	}
	naturalKey := strings.Join([]string{repository, string(control.Kind), control.Scope, control.CheckID}, "\x1f")
	controlNodeID := builder.upsertNode(control.Kind, naturalKey, control.Label, repository, controlState, repoRiskPostureNodeEvidence(finding, control))
	if control.Kind == RepoRiskNodeRunnerGroup {
		builder.rememberRunnerGroupNode(repository, controlNodeID)
	}

	if repositoryNodeID != "" {
		governanceKind := RepoRiskEdgeRepositoryGovernedBy
		if control.Scope == repoRiskPostureScopeOrganization {
			governanceKind = RepoRiskEdgeInheritsOrgPolicy
		}
		governanceEvidence := map[string]any{
			"github_posture_check_id": control.CheckID,
			"github_posture_scope":    control.Scope,
		}
		if control.Organization != "" {
			governanceEvidence["organization"] = control.Organization
		}
		builder.upsertEdge(governanceKind, repositoryNodeID, controlNodeID, controlState, governanceEvidence)
	}

	if !control.Observed() {
		builder.upsertEdge(RepoRiskEdgeFindingDependsOnPostureSource, findingNodeID, controlNodeID, RepoRiskEvidenceUnknown, map[string]any{
			"finding_id":              findingPublicID,
			"github_posture_check_id": control.CheckID,
			"github_posture_state":    control.State,
			"reason":                  "posture_source_" + control.State,
		})
		return
	}
	if !control.Weak() {
		return
	}

	findingEdgeKind := RepoRiskEdgeFindingWeakensControl
	switch control.Kind {
	case RepoRiskNodeDeployKey, RepoRiskNodeWebhook:
		findingEdgeKind = RepoRiskEdgeFindingExposesControl
	}
	builder.upsertEdge(findingEdgeKind, findingNodeID, controlNodeID, RepoRiskEvidenceKnown, map[string]any{
		"finding_id":              findingPublicID,
		"github_posture_check_id": control.CheckID,
		"github_posture_reason":   firstEvidenceString(finding.Evidence, "github_posture_reason"),
	})
}

func repoRiskPostureNodeEvidence(finding Finding, control repoRiskPostureControl) map[string]any {
	evidence := map[string]any{
		"github_posture_check_id": control.CheckID,
		"github_posture_scope":    control.Scope,
		"github_posture_state":    control.State,
	}
	if control.Category != "" {
		evidence["github_posture_category"] = control.Category
	}
	if control.Organization != "" {
		evidence["organization"] = control.Organization
	}
	if collectedAt := firstEvidenceString(finding.Evidence, "github_posture_collected_at"); collectedAt != "" {
		evidence["github_posture_collected_at"] = collectedAt
	}
	for _, key := range repoRiskPostureEvidenceKeys {
		if value, exists := finding.Evidence[key]; exists && value != nil {
			evidence[key] = value
		}
	}
	return evidence
}

func (builder *repoRiskGraphBuilder) rememberWorkflowNode(repository string, nodeID string) {
	builder.workflowNodes[repository] = appendUniqueNodeID(builder.workflowNodes[repository], nodeID)
}

func (builder *repoRiskGraphBuilder) rememberRunnerGroupNode(repository string, nodeID string) {
	builder.runnerGroupNodes[repository] = appendUniqueNodeID(builder.runnerGroupNodes[repository], nodeID)
}

func appendUniqueNodeID(nodeIDs []string, nodeID string) []string {
	if nodeID == "" {
		return nodeIDs
	}
	for _, existing := range nodeIDs {
		if existing == nodeID {
			return nodeIDs
		}
	}
	return append(nodeIDs, nodeID)
}

// linkWorkflowsToRunnerGroups connects each workflow to the self-hosted runner
// groups its repository can reach. Runner availability is repository-scoped
// evidence and never proves that a given workflow targets the group, so every
// edge is recorded as unknown reachability.
func (builder *repoRiskGraphBuilder) linkWorkflowsToRunnerGroups() {
	repositories := make([]string, 0, len(builder.runnerGroupNodes))
	for repository := range builder.runnerGroupNodes {
		repositories = append(repositories, repository)
	}
	sort.Strings(repositories)

	for _, repository := range repositories {
		workflowNodeIDs := append([]string(nil), builder.workflowNodes[repository]...)
		if len(workflowNodeIDs) == 0 {
			continue
		}
		runnerGroupNodeIDs := append([]string(nil), builder.runnerGroupNodes[repository]...)
		sort.Strings(workflowNodeIDs)
		sort.Strings(runnerGroupNodeIDs)
		for _, workflowNodeID := range workflowNodeIDs {
			for _, runnerGroupNodeID := range runnerGroupNodeIDs {
				builder.upsertEdge(RepoRiskEdgeWorkflowRunsOnRunnerGroup, workflowNodeID, runnerGroupNodeID, RepoRiskEvidenceUnknown, map[string]any{
					"repository": repository,
					"reason":     "runner_target_unproven",
				})
			}
		}
	}
}

// repoRiskPostureAmplifierFactor rates how much a proven-weak GitHub control
// widens the blast radius of the finding that reported it. Controls the scanner
// could not read contribute nothing: uncertainty is surfaced through unknown
// nodes, edges, and score unknowns rather than through an invented score bump.
func repoRiskPostureAmplifierFactor(finding Finding) int {
	control, ok := repoRiskPostureControlForFinding(finding)
	if !ok || !control.Weak() {
		return 0
	}
	score := 0
	switch strings.ToLower(strings.TrimSpace(finding.Detector)) {
	case "github_default_branch_unprotected":
		score = 60
		if evidenceBool(finding.Evidence, "force_pushes_allowed") || evidenceBool(finding.Evidence, "branch_deletions_allowed") {
			score += 20
		}
		if !evidenceBool(finding.Evidence, "admins_enforced") {
			score += 10
		}
	case "github_rulesets_weak":
		score = 40
	case "github_actions_policy_broad":
		score = 55
		if strings.EqualFold(firstEvidenceString(finding.Evidence, "allowed_actions"), "all") {
			score += 20
		}
		if strings.EqualFold(firstEvidenceString(finding.Evidence, "default_workflow_permissions"), "write") {
			score += 15
		}
	case "github_workflow_permissions_write_default":
		score = 70
	case "github_reusable_workflow_policy_broad":
		score = 45
	case "github_self_hosted_runner_unrestricted":
		score = 65
		if evidenceCount(finding.Evidence, "public_repository_runner_groups") > 0 {
			score += 20
		}
	case "github_write_deploy_key":
		score = 70
		if evidenceCount(finding.Evidence, "writable_deploy_keys") > 1 {
			score += 10
		}
	case "github_environment_unprotected":
		score = 50
		if repoRiskEnvironmentFactor(finding) == 100 {
			score += 25
		}
	case "github_webhook_unhealthy":
		score = 25
		if evidenceCount(finding.Evidence, "insecure_ssl_hooks") > 0 {
			score += 15
		}
	case "github_secret_scanning_disabled":
		score = 35
	case "github_code_scanning_disabled":
		score = 25
	case "github_dependabot_disabled":
		score = 20
	case "github_code_security_configuration_weak":
		score = 30
	default:
		score = 20
	}
	return clampInt(score, 0, 100)
}

func evidenceBool(evidence map[string]any, key string) bool {
	value, ok := boolFromAny(evidence[key])
	return ok && value
}

func evidenceCount(evidence map[string]any, key string) int {
	value, ok := floatFromAny(evidence[key])
	if !ok {
		return 0
	}
	return int(value)
}
