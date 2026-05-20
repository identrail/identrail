package repoexposure

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/identrail/identrail/internal/domain"
)

const workflowAnalyzerVersion = "2026.05"

var gitHubActionCommitRefPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var workflowSecretsExpressionPattern = regexp.MustCompile(`\$\{\{\s*secrets\s*(?:\.|\[)`)

type githubWorkflowModel struct {
	Events      map[string]*yaml.Node
	Env         map[string]string
	Permissions workflowPermissions
	Jobs        []githubWorkflowJob
}

type workflowPermissions struct {
	Configured  bool
	Line        int
	Raw         string
	WriteAll    bool
	Scopes      map[string]string
	WriteScopes []string
}

type githubWorkflowJob struct {
	ID          string
	Line        int
	Uses        string
	UsesLine    int
	Env         map[string]string
	Secrets     map[string]string
	SecretsRaw  string
	Permissions workflowPermissions
	Steps       []githubWorkflowStep
}

type githubWorkflowStep struct {
	Index    int
	Line     int
	Name     string
	Uses     string
	UsesLine int
	Run      string
	RunLine  int
	With     map[string]string
	Env      map[string]string
}

func analyzeGitHubWorkflowFindings(repo string, commit string, path string, ast *yaml.Node, seen map[string]struct{}, detectedAt time.Time) []domain.Finding {
	findings := []domain.Finding{}
	if !isGitHubWorkflowPath(path) {
		return findings
	}
	workflow := parseGitHubWorkflow(ast)
	if len(workflow.Events) == 0 {
		return findings
	}

	eventNames := sortedWorkflowEventNames(workflow.Events)
	pullRequestTarget := workflowHasEvent(workflow, "pull_request_target")
	workflowRun := workflowHasEvent(workflow, "workflow_run")
	untrustedEvent := workflowHasUntrustedEvent(workflow)

	if workflow.Permissions.hasBroadGitHubTokenWrite() {
		appendWorkflowFinding(&findings, seen, repo, commit, path, workflow.Permissions.Line, "workflow_broad_token_permissions", domain.SeverityHigh,
			"GitHub workflow grants broad token write permissions",
			"Workflow-level GITHUB_TOKEN permissions grant write-capable scopes that increase repository automation blast radius.",
			"Set workflow permissions to read-only by default and grant write scopes only on the specific jobs that need them.",
			"permissions: "+workflow.Permissions.summary(), detectedAt, workflowEvidence(eventNames, "", 0, "", map[string]any{
				"permission_scope":   "workflow",
				"permission_summary": workflow.Permissions.summary(),
				"write_scopes":       workflow.Permissions.writeScopeEvidence(),
			}))
	}

	for _, job := range workflow.Jobs {
		effectivePermissions := workflow.effectivePermissions(job)
		if job.Permissions.hasBroadGitHubTokenWrite() {
			appendWorkflowFinding(&findings, seen, repo, commit, path, job.Permissions.Line, "workflow_broad_token_permissions", domain.SeverityHigh,
				"GitHub workflow grants broad token write permissions",
				"Job-level GITHUB_TOKEN permissions grant write-capable scopes that increase repository automation blast radius.",
				"Grant the job only the read or write scopes required for its exact task.",
				"permissions: "+job.Permissions.summary(), detectedAt, workflowEvidence(eventNames, job.ID, 0, "", map[string]any{
					"permission_scope":   "job",
					"permission_summary": job.Permissions.summary(),
					"write_scopes":       job.Permissions.writeScopeEvidence(),
				}))
		}

		if action := normalizeWorkflowUses(job.Uses); mutableThirdPartyAction(repo, action) {
			appendWorkflowFinding(&findings, seen, repo, commit, path, job.UsesLine, "workflow_unpinned_third_party_action", domain.SeverityMedium,
				"Workflow uses an unpinned third-party action",
				"A third-party reusable workflow is referenced by a mutable tag or branch, so upstream changes can alter workflow behavior without a repository change.",
				"Pin third-party reusable workflows to full commit SHAs and review updates through dependency-management pull requests.",
				job.Uses, detectedAt, workflowEvidence(eventNames, job.ID, 0, action, map[string]any{
					"action_ref":               workflowActionRef(action),
					"reusable_workflow_call":   true,
					"reusable_workflow_source": job.Uses,
				}))
		}

		jobSecrets := job.referencesSecrets(workflow.Env)
		if pullRequestTarget && (effectivePermissions.hasBroadGitHubTokenWrite() || jobSecrets) {
			appendWorkflowFinding(&findings, seen, repo, commit, path, job.Line, "workflow_pull_request_target_privileged_context", domain.SeverityCritical,
				"pull_request_target workflow exposes privileged context",
				"A pull_request_target job has explicit write-token permissions or secret access, so untrusted PR influence can reach privileged repository context.",
				"Move untrusted PR processing to pull_request, split privileged follow-up work into a reviewed workflow, and keep pull_request_target jobs read-only with no secrets.",
				"pull_request_target privileged job", detectedAt, workflowEvidence(eventNames, job.ID, 0, "", map[string]any{
					"permission_summary": effectivePermissions.summary(),
					"write_scopes":       effectivePermissions.writeScopeEvidence(),
					"references_secrets": jobSecrets,
				}))
		}

		if workflowRun && (effectivePermissions.hasBroadGitHubTokenWrite() || jobSecrets || job.usesReleaseOrCloudStep()) {
			appendWorkflowFinding(&findings, seen, repo, commit, path, job.Line, "workflow_run_privilege_chain", domain.SeverityHigh,
				"workflow_run chain reaches privileged job behavior",
				"A workflow_run trigger can connect an upstream workflow result to write permissions, secrets, cloud credentials, or release behavior.",
				"Require trusted upstream workflows, validate artifacts before use, and keep workflow_run jobs read-only unless an environment approval gates privileged actions.",
				"on: workflow_run", detectedAt, workflowEvidence(eventNames, job.ID, 0, "", map[string]any{
					"permission_summary": effectivePermissions.summary(),
					"write_scopes":       effectivePermissions.writeScopeEvidence(),
					"references_secrets": jobSecrets,
				}))
		}

		oidcContext := workflow.oidcRiskContext(job)
		if effectivePermissions.idTokenWrite() && oidcContext != "" {
			appendWorkflowFinding(&findings, seen, repo, commit, path, effectivePermissions.Line, "workflow_oidc_broad_trust", domain.SeverityHigh,
				"Workflow can mint cloud credentials from broad OIDC context",
				"An id-token: write permission is reachable from a workflow context that can be influenced by pull requests, workflow_run chains, or broadly scoped deploy triggers.",
				"Scope cloud trust policies to protected branches/environments and keep OIDC permissions off untrusted PR, workflow_run, or all-branch push paths.",
				"id-token: write", detectedAt, workflowEvidence(eventNames, job.ID, 0, "", map[string]any{
					"permission_summary": effectivePermissions.summary(),
					"cloud_auth_action":  job.cloudAuthAction(),
					"oidc_risk_context":  oidcContext,
				}))
		}

		for _, step := range job.Steps {
			action := normalizeWorkflowUses(step.Uses)
			if pullRequestTarget && step.checkoutUsesUntrustedHead() {
				appendWorkflowFinding(&findings, seen, repo, commit, path, stepLine(step), "workflow_pull_request_target_untrusted_checkout", domain.SeverityCritical,
					"pull_request_target checks out untrusted PR code",
					"A pull_request_target job checks out the contributor-controlled PR head, which can run attacker code in a privileged workflow context.",
					"Do not checkout PR head code in pull_request_target. Use pull_request for untrusted code or checkout only the trusted base ref before performing privileged operations.",
					"actions/checkout with PR head ref", detectedAt, workflowEvidence(eventNames, job.ID, step.Index, action, map[string]any{
						"checkout_ref":       firstNonEmptyWorkflowString(step.With["ref"], step.With["repository"]),
						"permission_summary": effectivePermissions.summary(),
					}))
			}

			if mutableThirdPartyAction(repo, action) {
				appendWorkflowFinding(&findings, seen, repo, commit, path, step.UsesLine, "workflow_unpinned_third_party_action", domain.SeverityMedium,
					"Workflow uses an unpinned third-party action",
					"A third-party GitHub Action is referenced by a mutable tag or branch, so upstream changes can alter workflow behavior without a repository change.",
					"Pin third-party actions to full commit SHAs and review updates through dependency-management pull requests.",
					step.Uses, detectedAt, workflowEvidence(eventNames, job.ID, step.Index, action, map[string]any{
						"action_ref": workflowActionRef(action),
					}))
			}

			if tokens := step.untrustedExpressionTokens(untrustedEvent || workflowRun); len(tokens) > 0 {
				appendWorkflowFinding(&findings, seen, repo, commit, path, step.RunLine, "workflow_shell_injection_user_context", domain.SeverityHigh,
					"Workflow interpolates untrusted PR context into shell",
					"A run step directly interpolates pull request or issue-controlled GitHub context, which can become shell injection when the workflow executes.",
					"Pass untrusted GitHub context through environment variables, quote safely, or avoid using user-controlled PR metadata in shell commands.",
					truncateWorkflowSnippet(step.Run), detectedAt, workflowEvidence(eventNames, job.ID, step.Index, action, map[string]any{
						"untrusted_context": tokens,
					}))
			}

			if step.usesPoisonableCache(untrustedEvent || workflowRun) {
				appendWorkflowFinding(&findings, seen, repo, commit, path, stepLine(step), "workflow_cache_poisoning", domain.SeverityMedium,
					"Workflow cache key can be influenced by untrusted context",
					"A cache step uses PR-controlled context or broad restore keys, which can allow poisoned dependency or build cache reuse.",
					"Scope cache keys to trusted refs, avoid broad restore keys for untrusted PRs, and separate read-only PR caches from privileged build caches.",
					"actions/cache", detectedAt, workflowEvidence(eventNames, job.ID, step.Index, action, map[string]any{
						"cache_key":          step.With["key"],
						"cache_restore_keys": step.With["restore-keys"],
					}))
			}

			if step.exposesUntrustedArtifactOrRelease(untrustedEvent || workflowRun) {
				severity := domain.SeverityMedium
				if step.usesReleaseBehavior() {
					severity = domain.SeverityHigh
				}
				appendWorkflowFinding(&findings, seen, repo, commit, path, stepLine(step), "workflow_artifact_poisoning", severity,
					"Workflow publishes artifacts from untrusted context",
					"A workflow reachable from pull requests or workflow_run can upload artifacts or release assets, allowing untrusted build output to be reused downstream.",
					"Keep untrusted PR artifacts isolated, validate workflow_run artifacts before privileged use, and restrict release publishing to protected branches or environments.",
					firstNonEmptyWorkflowString(step.Uses, truncateWorkflowSnippet(step.Run)), detectedAt, workflowEvidence(eventNames, job.ID, step.Index, action, map[string]any{
						"publishes_release": step.usesReleaseBehavior(),
					}))
			}
		}
	}

	return findings
}

func parseGitHubWorkflow(root *yaml.Node) githubWorkflowModel {
	workflow := githubWorkflowModel{Events: map[string]*yaml.Node{}}
	ast := root
	if ast != nil && ast.Kind == yaml.DocumentNode && len(ast.Content) > 0 {
		ast = ast.Content[0]
	}
	if ast == nil || ast.Kind != yaml.MappingNode {
		return workflow
	}
	if onNode, ok := yamlMappingValue(ast, "on"); ok {
		workflow.Events = workflowEvents(onNode)
	}
	if envNode, ok := yamlMappingValue(ast, "env"); ok {
		workflow.Env = yamlScalarMap(envNode)
	}
	if permissionsNode, ok := yamlMappingValue(ast, "permissions"); ok {
		workflow.Permissions = parseWorkflowPermissions(permissionsNode)
	}
	if jobsNode, ok := yamlMappingValue(ast, "jobs"); ok && jobsNode.Kind == yaml.MappingNode {
		workflow.Jobs = parseWorkflowJobs(jobsNode)
	}
	return workflow
}

func parseWorkflowJobs(node *yaml.Node) []githubWorkflowJob {
	jobs := []githubWorkflowJob{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		if key == nil || value == nil || value.Kind != yaml.MappingNode {
			continue
		}
		job := githubWorkflowJob{ID: strings.TrimSpace(key.Value), Line: key.Line, Env: map[string]string{}, Secrets: map[string]string{}}
		if envNode, ok := yamlMappingValue(value, "env"); ok {
			job.Env = yamlScalarMap(envNode)
		}
		if secretsNode, ok := yamlMappingValue(value, "secrets"); ok {
			job.Secrets, job.SecretsRaw = parseWorkflowSecrets(secretsNode)
		}
		if usesNode, ok := yamlMappingValue(value, "uses"); ok {
			job.Uses = yamlScalarValue(usesNode)
			job.UsesLine = workflowLine(usesNode)
		}
		if permissionsNode, ok := yamlMappingValue(value, "permissions"); ok {
			job.Permissions = parseWorkflowPermissions(permissionsNode)
		}
		if stepsNode, ok := yamlMappingValue(value, "steps"); ok && stepsNode.Kind == yaml.SequenceNode {
			job.Steps = parseWorkflowSteps(stepsNode)
		}
		jobs = append(jobs, job)
	}
	return jobs
}

func parseWorkflowSteps(node *yaml.Node) []githubWorkflowStep {
	steps := []githubWorkflowStep{}
	for idx, item := range node.Content {
		if item == nil || item.Kind != yaml.MappingNode {
			continue
		}
		step := githubWorkflowStep{Index: idx + 1, Line: item.Line, With: map[string]string{}, Env: map[string]string{}}
		for i := 0; i+1 < len(item.Content); i += 2 {
			key := item.Content[i]
			value := item.Content[i+1]
			if key == nil || value == nil {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(key.Value)) {
			case "name":
				step.Name = yamlScalarValue(value)
			case "uses":
				step.Uses = yamlScalarValue(value)
				step.UsesLine = value.Line
			case "run":
				step.Run = yamlScalarValue(value)
				step.RunLine = value.Line
			case "with":
				step.With = yamlScalarMap(value)
			case "env":
				step.Env = yamlScalarMap(value)
			}
		}
		steps = append(steps, step)
	}
	return steps
}

func workflowEvents(node *yaml.Node) map[string]*yaml.Node {
	events := map[string]*yaml.Node{}
	if node == nil {
		return events
	}
	switch node.Kind {
	case yaml.ScalarNode:
		event := normalizeWorkflowEvent(node.Value)
		if event != "" {
			events[event] = node
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item == nil {
				continue
			}
			event := normalizeWorkflowEvent(item.Value)
			if event != "" {
				events[event] = item
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			if key == nil {
				continue
			}
			event := normalizeWorkflowEvent(key.Value)
			if event != "" {
				events[event] = value
			}
		}
	}
	return events
}

func parseWorkflowSecrets(node *yaml.Node) (map[string]string, string) {
	if node == nil {
		return map[string]string{}, ""
	}
	if node.Kind == yaml.ScalarNode {
		return map[string]string{}, strings.ToLower(strings.TrimSpace(node.Value))
	}
	return yamlScalarMap(node), ""
}

func parseWorkflowPermissions(node *yaml.Node) workflowPermissions {
	permissions := workflowPermissions{Configured: node != nil, Line: workflowLine(node), Scopes: map[string]string{}}
	if node == nil {
		return permissions
	}
	if node.Kind == yaml.ScalarNode {
		permissions.Raw = strings.ToLower(strings.TrimSpace(node.Value))
		permissions.WriteAll = strings.EqualFold(permissions.Raw, "write-all")
		if permissions.WriteAll {
			permissions.WriteScopes = []string{"write-all"}
		}
		return permissions
	}
	if node.Kind != yaml.MappingNode {
		return permissions
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		if key == nil || value == nil || value.Kind != yaml.ScalarNode {
			continue
		}
		scope := strings.ToLower(strings.TrimSpace(key.Value))
		permission := strings.ToLower(strings.TrimSpace(value.Value))
		if scope == "" || permission == "" {
			continue
		}
		permissions.Scopes[scope] = permission
		if permission == "write" || permission == "write-all" {
			permissions.WriteScopes = append(permissions.WriteScopes, scope)
		}
	}
	sort.Strings(permissions.WriteScopes)
	return permissions
}

func (workflow githubWorkflowModel) effectivePermissions(job githubWorkflowJob) workflowPermissions {
	if job.Permissions.configured() {
		return job.Permissions
	}
	return workflow.Permissions
}

func (permissions workflowPermissions) configured() bool {
	return permissions.Configured
}

func (permissions workflowPermissions) hasBroadGitHubTokenWrite() bool {
	if permissions.WriteAll {
		return true
	}
	for _, scope := range permissions.WriteScopes {
		if scope == "id-token" {
			continue
		}
		return true
	}
	return false
}

func (permissions workflowPermissions) idTokenWrite() bool {
	if permissions.WriteAll {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(permissions.Scopes["id-token"]), "write")
}

func (permissions workflowPermissions) summary() string {
	if permissions.WriteAll {
		return "write-all"
	}
	if len(permissions.Scopes) == 0 {
		if permissions.Raw != "" {
			return permissions.Raw
		}
		return "not_explicit"
	}
	scopes := make([]string, 0, len(permissions.Scopes))
	for scope, permission := range permissions.Scopes {
		scopes = append(scopes, scope+":"+permission)
	}
	sort.Strings(scopes)
	return strings.Join(scopes, ",")
}

func (permissions workflowPermissions) writeScopeEvidence() []string {
	scopes := append([]string(nil), permissions.WriteScopes...)
	sort.Strings(scopes)
	return scopes
}

func (workflow githubWorkflowModel) oidcRiskContext(job githubWorkflowJob) string {
	switch {
	case workflowHasUserControlledEvent(workflow):
		return "untrusted_event"
	case workflowHasEvent(workflow, "workflow_run"):
		return "workflow_run"
	case job.usesCloudAuthAction() && workflowHasBroadPushEvent(workflow):
		return "broad_push_event"
	default:
		return ""
	}
}

func (job githubWorkflowJob) referencesSecrets(workflowEnv map[string]string) bool {
	if strings.EqualFold(job.SecretsRaw, "inherit") || workflowStringMapReferencesSecrets(job.Secrets) || workflowStringMapReferencesSecrets(job.Env) || workflowStringMapReferencesSecrets(workflowEnv) {
		return true
	}
	for _, step := range job.Steps {
		if workflowStringReferencesSecrets(step.Run) || workflowStringMapReferencesSecrets(step.With) || workflowStringMapReferencesSecrets(step.Env) {
			return true
		}
	}
	return false
}

func (job githubWorkflowJob) usesCloudAuthAction() bool {
	return job.cloudAuthAction() != ""
}

func (job githubWorkflowJob) cloudAuthAction() string {
	for _, step := range job.Steps {
		action := normalizeWorkflowUses(step.Uses)
		if workflowActionMatches(action, "aws-actions/configure-aws-credentials") ||
			workflowActionMatches(action, "azure/login") ||
			workflowActionMatches(action, "google-github-actions/auth") {
			return action
		}
	}
	return ""
}

func (job githubWorkflowJob) usesReleaseOrCloudStep() bool {
	if job.usesCloudAuthAction() {
		return true
	}
	for _, step := range job.Steps {
		if step.usesReleaseBehavior() {
			return true
		}
	}
	return false
}

func (step githubWorkflowStep) checkoutUsesUntrustedHead() bool {
	if !workflowActionMatches(normalizeWorkflowUses(step.Uses), "actions/checkout") {
		return false
	}
	for _, key := range []string{"ref", "repository"} {
		value := step.With[key]
		if workflowStringUsesUntrustedPRCodeContext(value) {
			return true
		}
	}
	return false
}

func (step githubWorkflowStep) untrustedExpressionTokens(untrustedEvent bool) []string {
	if !untrustedEvent || strings.TrimSpace(step.Run) == "" {
		return nil
	}
	return workflowUserControlledTokens(step.Run)
}

func (step githubWorkflowStep) usesPoisonableCache(untrustedEvent bool) bool {
	action := normalizeWorkflowUses(step.Uses)
	if !workflowActionMatches(action, "actions/cache") &&
		!workflowActionMatches(action, "actions/cache/restore") &&
		!workflowActionMatches(action, "actions/cache/save") {
		return false
	}
	key := step.With["key"]
	restoreKeys := step.With["restore-keys"]
	if workflowStringUsesUserControlledPRContext(key) || workflowStringUsesUserControlledPRContext(restoreKeys) {
		return true
	}
	return untrustedEvent && strings.TrimSpace(restoreKeys) != ""
}

func (step githubWorkflowStep) exposesUntrustedArtifactOrRelease(untrustedEvent bool) bool {
	if !untrustedEvent {
		return false
	}
	action := normalizeWorkflowUses(step.Uses)
	return workflowActionMatches(action, "actions/upload-artifact") ||
		step.usesReleaseBehavior() ||
		strings.Contains(strings.ToLower(step.Run), "upload-artifact")
}

func (step githubWorkflowStep) usesReleaseBehavior() bool {
	action := normalizeWorkflowUses(step.Uses)
	lowerRun := strings.ToLower(step.Run)
	return workflowActionMatches(action, "softprops/action-gh-release") ||
		workflowActionMatches(action, "actions/upload-release-asset") ||
		strings.Contains(lowerRun, "gh release upload") ||
		strings.Contains(lowerRun, "gh release create")
}

func workflowEvidence(events []string, job string, stepIndex int, action string, extra map[string]any) map[string]any {
	evidence := map[string]any{
		"detector_version":   workflowAnalyzerVersion,
		"detector_category":  "github_actions_workflow",
		"detector_provider":  "GitHub",
		"workflow_events":    events,
		"history_source":     "head_snapshot",
		"raw_secret_data":    false,
		"contextual_finding": true,
	}
	if job != "" {
		evidence["workflow_job"] = job
	}
	if stepIndex > 0 {
		evidence["workflow_step_index"] = stepIndex
	}
	if action != "" {
		evidence["workflow_action"] = action
	}
	for key, value := range extra {
		evidence[key] = value
	}
	return evidence
}

func appendWorkflowFinding(
	findings *[]domain.Finding,
	seen map[string]struct{},
	repo string,
	commit string,
	path string,
	line int,
	ruleID string,
	severity domain.FindingSeverity,
	title string,
	summary string,
	remediation string,
	snippet string,
	detectedAt time.Time,
	extraEvidence map[string]any,
) {
	if line <= 0 {
		line = 1
	}
	appendMisconfigFinding(findings, seen, repo, commit, path, line, ruleID, severity, title, summary, remediation, snippet, detectedAt, extraEvidence)
}

func yamlMappingValue(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		if keyNode == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(keyNode.Value), key) {
			return node.Content[i+1], true
		}
	}
	return nil, false
}

func yamlScalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(node.Value)
}

func yamlScalarMap(node *yaml.Node) map[string]string {
	values := map[string]string{}
	if node == nil || node.Kind != yaml.MappingNode {
		return values
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		if key == nil || value == nil {
			continue
		}
		values[strings.ToLower(strings.TrimSpace(key.Value))] = yamlScalarValue(value)
	}
	return values
}

func workflowHasEvent(workflow githubWorkflowModel, event string) bool {
	_, ok := workflow.Events[normalizeWorkflowEvent(event)]
	return ok
}

func workflowHasUntrustedEvent(workflow githubWorkflowModel) bool {
	if workflowHasUserControlledEvent(workflow) || workflowHasEvent(workflow, "workflow_run") {
		return true
	}
	return false
}

func workflowHasUserControlledEvent(workflow githubWorkflowModel) bool {
	for _, event := range []string{
		"pull_request",
		"pull_request_target",
		"pull_request_review",
		"pull_request_review_comment",
		"issues",
		"issue_comment",
		"workflow_run",
	} {
		if workflowHasEvent(workflow, event) {
			return true
		}
	}
	return false
}

func workflowHasBroadPushEvent(workflow githubWorkflowModel) bool {
	node, ok := workflow.Events["push"]
	if !ok {
		return false
	}
	if node == nil || node.Kind != yaml.MappingNode {
		return true
	}
	branches, hasBranches := yamlMappingValue(node, "branches")
	tags, hasTags := yamlMappingValue(node, "tags")
	if hasBranches || hasTags {
		return workflowNodeHasBroadRefFilter(branches) || workflowNodeHasBroadRefFilter(tags)
	}
	return true
}

func workflowNodeHasBroadRefFilter(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return workflowRefFilterIsBroad(node.Value)
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item != nil && workflowRefFilterIsBroad(item.Value) {
				return true
			}
		}
	}
	return false
}

func workflowRefFilterIsBroad(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "*" || trimmed == "**"
}

func sortedWorkflowEventNames(events map[string]*yaml.Node) []string {
	names := make([]string, 0, len(events))
	for event := range events {
		names = append(names, event)
	}
	sort.Strings(names)
	return names
}

func normalizeWorkflowEvent(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeWorkflowUses(value string) string {
	return strings.TrimSpace(value)
}

func workflowActionMatches(action string, prefix string) bool {
	actionLower := strings.ToLower(strings.TrimSpace(action))
	prefixLower := strings.ToLower(strings.TrimSpace(prefix))
	return actionLower == prefixLower || strings.HasPrefix(actionLower, prefixLower+"@") || strings.HasPrefix(actionLower, prefixLower+"/")
}

func mutableThirdPartyAction(repo string, action string) bool {
	normalized := strings.ToLower(strings.TrimSpace(action))
	if normalized == "" || strings.HasPrefix(normalized, "./") || strings.HasPrefix(normalized, "docker://") {
		return false
	}
	parts := strings.SplitN(normalized, "@", 2)
	if len(parts) != 2 {
		return false
	}
	actionPath := parts[0]
	ref := parts[1]
	owner := strings.SplitN(actionPath, "/", 2)[0]
	if owner == "actions" {
		return false
	}
	if sameWorkflowRepository(repo, workflowActionRepository(normalized)) {
		return false
	}
	return !gitHubActionCommitRefPattern.MatchString(ref)
}

func workflowActionRepository(action string) string {
	actionWithoutRef := strings.SplitN(strings.TrimSpace(action), "@", 2)[0]
	parts := strings.Split(actionWithoutRef, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

func sameWorkflowRepository(repo string, actionRepo string) bool {
	return normalizeWorkflowRepository(repo) != "" && normalizeWorkflowRepository(repo) == normalizeWorkflowRepository(actionRepo)
}

func normalizeWorkflowRepository(repo string) string {
	normalized := strings.ToLower(strings.TrimSpace(repo))
	normalized = strings.TrimPrefix(normalized, "https://github.com/")
	normalized = strings.TrimPrefix(normalized, "http://github.com/")
	normalized = strings.TrimPrefix(normalized, "github.com/")
	normalized = strings.TrimPrefix(normalized, "git@github.com:")
	normalized = strings.TrimSuffix(normalized, ".git")
	parts := strings.Split(normalized, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

func workflowActionRef(action string) string {
	parts := strings.SplitN(strings.TrimSpace(action), "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func workflowStringReferencesSecrets(value string) bool {
	return workflowSecretsExpressionPattern.MatchString(strings.ToLower(value))
}

func workflowStringMapReferencesSecrets(values map[string]string) bool {
	for _, value := range values {
		if workflowStringReferencesSecrets(value) {
			return true
		}
	}
	return false
}

func workflowStringUsesUntrustedPRCodeContext(value string) bool {
	return len(workflowUntrustedPRCodeTokens(value)) > 0
}

func workflowStringUsesUserControlledPRContext(value string) bool {
	return len(workflowUserControlledTokens(value)) > 0
}

func workflowUntrustedPRCodeTokens(value string) []string {
	lower := strings.ToLower(value)
	tokens := []string{}
	for _, token := range []string{
		"github.event.pull_request.head.ref",
		"github.event.pull_request.head.sha",
		"github.event.pull_request.head.label",
		"github.event.pull_request.head.repo.full_name",
		"github.head_ref",
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.review.body",
		"github.event.comment.body",
	} {
		if strings.Contains(lower, token) {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func workflowUserControlledTokens(value string) []string {
	lower := strings.ToLower(value)
	tokens := []string{}
	for _, token := range []string{
		"github.event.pull_request.title",
		"github.event.pull_request.body",
		"github.event.pull_request.head.ref",
		"github.event.pull_request.head.label",
		"github.event.pull_request.head.repo.full_name",
		"github.head_ref",
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.review.body",
		"github.event.comment.body",
	} {
		if strings.Contains(lower, token) {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func isGitHubWorkflowPath(path string) bool {
	lower := filepath.ToSlash(strings.ToLower(strings.TrimSpace(path)))
	return strings.HasPrefix(lower, ".github/workflows/") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml"))
}

func workflowLine(node *yaml.Node) int {
	if node == nil || node.Line <= 0 {
		return 1
	}
	return node.Line
}

func stepLine(step githubWorkflowStep) int {
	for _, line := range []int{step.UsesLine, step.RunLine, step.Line} {
		if line > 0 {
			return line
		}
	}
	return 1
}

func truncateWorkflowSnippet(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > 240 {
		return trimmed[:240] + "..."
	}
	return trimmed
}

func firstNonEmptyWorkflowString(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
