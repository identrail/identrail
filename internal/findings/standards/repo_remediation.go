package standards

import (
	"strings"

	"github.com/identrail/identrail/internal/domain"
)

const (
	RepoPatchStrategyLineLiteral                    = "line_literal"
	RepoPatchStrategyLineRegex                      = "line_regex"
	RepoPatchStrategyWorkflowPermissionsReadDefault = "workflow_permissions_read_default"
	RepoPatchStrategyWorkflowPullRequestTrigger     = "workflow_pull_request_trigger"
)

// RepoExposurePatchTemplate describes one deterministic source patch that can
// be previewed from a repo exposure finding. Templates with Placeholder=true
// are guidance-only and must not be published without an operator replacing the
// placeholder with a real value.
type RepoExposurePatchTemplate struct {
	Strategy              string `json:"strategy"`
	Description           string `json:"description"`
	Match                 string `json:"match,omitempty"`
	MatchPattern          string `json:"match_pattern,omitempty"`
	Replacement           string `json:"replacement"`
	RequiresSourceContent bool   `json:"requires_source_content"`
	Placeholder           bool   `json:"placeholder"`
}

// RepoExposureRemediation is a rule-specific remediation plan for repository
// findings. Secret findings intentionally use guidance without patches so raw
// secrets are never preserved or moved around by generated PRs.
type RepoExposureRemediation struct {
	Detector             string                       `json:"detector"`
	Summary              string                       `json:"summary"`
	RiskSummary          string                       `json:"risk_summary"`
	Steps                []string                     `json:"steps"`
	SafetyNotes          []string                     `json:"safety_notes"`
	Validation           []string                     `json:"validation"`
	Patch                *RepoExposurePatchTemplate   `json:"patch,omitempty"`
	SecretRotation       bool                         `json:"secret_rotation"`
	Publishable          bool                         `json:"publishable"`
	PublishBlockedReason string                       `json:"publish_blocked_reason,omitempty"`
	Evidence             RepoExposureRemediationScope `json:"evidence"`
}

// RepoExposureRemediationScope captures non-secret traceability details that
// are safe to show in previews and generated PR bodies.
type RepoExposureRemediationScope struct {
	FindingID   string `json:"finding_id"`
	ScanID      string `json:"scan_id,omitempty"`
	Repository  string `json:"repository,omitempty"`
	Commit      string `json:"commit,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
	LineNumber  int    `json:"line_number,omitempty"`
	LineSnippet string `json:"line_snippet,omitempty"`
}

// SuggestRepoExposureRemediation returns a remediation workflow for repository
// exposure findings, including guidance-only secret handling and deterministic
// patch templates for safe misconfiguration fixes.
func SuggestRepoExposureRemediation(finding domain.Finding) (RepoExposureRemediation, bool) {
	domain.NormalizeRepoFindingMetadata(&finding)
	switch finding.Type {
	case domain.FindingSecretExposure:
		return secretRotationRemediation(finding), true
	case domain.FindingRepoMisconfig:
		return repoMisconfigRemediation(finding)
	default:
		if detector := strings.TrimSpace(finding.Detector); detector != "" {
			if strings.HasPrefix(detector, "workflow_") ||
				strings.HasPrefix(detector, "terraform_") ||
				strings.HasPrefix(detector, "docker_") ||
				strings.HasPrefix(detector, "k8s_") {
				finding.Type = domain.FindingRepoMisconfig
				return repoMisconfigRemediation(finding)
			}
		}
		return RepoExposureRemediation{}, false
	}
}

func secretRotationRemediation(finding domain.Finding) RepoExposureRemediation {
	detector := repoDetectorOrDefault(finding, "secret_exposure")
	return RepoExposureRemediation{
		Detector:       detector,
		Summary:        "Rotate and revoke the exposed credential; do not generate a PR containing secret material.",
		RiskSummary:    firstNonEmpty(finding.HumanSummary, "A repository finding indicates credential-like material was exposed in source history or file content."),
		SecretRotation: true,
		Publishable:    false,
		PublishBlockedReason: "secret findings require rotation and revocation guidance instead of generated code patches " +
			"so raw secret values are never copied into branches, commits, or pull requests",
		Steps: []string{
			"Revoke or rotate the exposed credential at the issuing provider before editing repository history.",
			"Remove the credential from the affected file and replace it with a secret-manager, environment, or OIDC-based reference.",
			"Review audit logs for usage after the first exposed commit and scope incident response to that window.",
			"Only consider history rewriting after rotation, stakeholder coordination, and backup-retention review.",
			"Add provider-native secret scanning or push protection so the same credential family is blocked before commit.",
		},
		SafetyNotes: []string{
			"Do not paste the raw secret into issue comments, PR bodies, remediation branches, logs, or chat tools.",
			"Generated PRs are intentionally disabled for secret findings because a PR can preserve or redistribute the leaked value.",
			"Treat redacted snippets as evidence pointers only; the provider is the source of truth for revocation.",
		},
		Validation: []string{
			"Confirm the old credential is revoked or inactive at the provider.",
			"Re-run the repository scanner and provider-native secret scanner after rotation.",
			"Verify no new commits contain the same secret fingerprint.",
		},
		Evidence: repoExposureScope(finding, false),
	}
}

func repoMisconfigRemediation(finding domain.Finding) (RepoExposureRemediation, bool) {
	detector := repoDetectorOrDefault(finding, "")
	if detector == "" {
		return RepoExposureRemediation{}, false
	}
	switch detector {
	case "workflow_write_all_permissions":
		return workflowWriteAllRemediation(finding, detector), true
	case "workflow_pull_request_target":
		return workflowPullRequestTargetRemediation(finding, detector), true
	case "workflow_broad_token_permissions":
		return workflowBroadTokenRemediation(finding, detector), true
	case "workflow_pull_request_target_privileged_context":
		return workflowPrivilegedContextRemediation(finding, detector), true
	case "workflow_pull_request_target_untrusted_checkout":
		return workflowUntrustedCheckoutRemediation(finding, detector), true
	case "workflow_unpinned_third_party_action":
		return workflowUnpinnedActionRemediation(finding, detector), true
	case "workflow_shell_injection_user_context":
		return workflowShellInjectionRemediation(finding, detector), true
	case "workflow_run_privilege_chain":
		return workflowRunPrivilegeRemediation(finding, detector), true
	case "workflow_oidc_broad_trust":
		return workflowOIDCTrustRemediation(finding, detector), true
	case "workflow_cache_poisoning":
		return workflowCachePoisoningRemediation(finding, detector), true
	case "workflow_artifact_poisoning":
		return workflowArtifactPoisoningRemediation(finding, detector), true
	case "workflow_ai_agent_prompt_injection":
		return workflowAIAgentPromptInjectionRemediation(finding, detector), true
	case "workflow_self_hosted_runner":
		return workflowSelfHostedRunnerRemediation(finding, detector), true
	case "workflow_self_hosted_runner_unresolved":
		return workflowUnresolvedRunnerRemediation(finding, detector), true
	case "k8s_privileged_true":
		return k8sPrivilegedRemediation(finding, detector), true
	case "terraform_public_s3_acl":
		return terraformPublicACLRemediation(finding, detector), true
	case "terraform_open_ssh_rdp":
		return terraformOpenManagementPortRemediation(finding, detector), true
	case "docker_latest_tag":
		return dockerLatestTagRemediation(finding, detector), true
	default:
		if strings.HasPrefix(detector, "workflow_") {
			return workflowGenericRemediation(finding, detector), true
		}
		return RepoExposureRemediation{}, false
	}
}

func workflowWriteAllRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return deterministicRepoRemediation(finding, detector,
		"Replace workflow write-all token permissions with least-privilege read defaults.",
		"Workflow GITHUB_TOKEN permissions are set to write-all, giving automation broad write capability.",
		[]string{
			"Replace `permissions: write-all` with explicit least-privilege permissions.",
			"Start from `contents: read` and grant write scopes only on jobs that genuinely publish or mutate repository state.",
			"Move deploy, release, or package write scopes behind protected branch or environment gates.",
		},
		[]string{
			"Some release jobs may need explicit write scopes after the default is tightened.",
			"Keep `id-token: write` only on jobs that exchange OIDC tokens with a scoped cloud trust policy.",
		},
		[]string{
			"Run the workflow on a test branch and confirm read-only jobs still pass.",
			"Review the Actions run permissions summary before merging.",
		},
		&RepoExposurePatchTemplate{
			Strategy:              RepoPatchStrategyWorkflowPermissionsReadDefault,
			Description:           "Replace workflow write-all permissions with read-only permission values.",
			Match:                 "permissions: write-all",
			Replacement:           "permissions:\n  contents: read",
			RequiresSourceContent: true,
		})
}

func workflowPullRequestTargetRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return deterministicRepoRemediation(finding, detector,
		"Move untrusted pull-request execution away from pull_request_target.",
		"`pull_request_target` can run with elevated repository token context when workflow logic handles untrusted PR input.",
		[]string{
			"Use `pull_request` for workflows that build, test, or checkout untrusted contributor code.",
			"Keep any remaining `pull_request_target` workflow metadata-only and remove checkout, shell, release, deploy, and secret usage.",
			"Split privileged labeling or commenting into a separate minimal workflow if repository writes are required.",
		},
		[]string{
			"`pull_request_target` can be appropriate for metadata-only automation; review the workflow behavior before replacing it.",
			"Never checkout PR head code in a privileged `pull_request_target` job.",
		},
		[]string{
			"Open a fork PR or test branch PR and confirm the workflow runs without write-token access.",
			"Confirm privileged jobs no longer receive secrets on untrusted PR paths.",
		},
		&RepoExposurePatchTemplate{
			Strategy:              RepoPatchStrategyWorkflowPullRequestTrigger,
			Description:           "Replace the privileged PR trigger with the unprivileged pull_request trigger.",
			Match:                 "pull_request_target",
			Replacement:           "pull_request",
			RequiresSourceContent: true,
		})
}

func workflowBroadTokenRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Constrain workflow or job token permissions to explicit least-privilege scopes.",
		"A workflow/job grants write-capable GITHUB_TOKEN scopes beyond the minimum needed for that job.",
		[]string{
			"Set the workflow-level default to `permissions: { contents: read }`.",
			"Move required write scopes to the smallest job that needs them and remove broad inherited write scopes.",
			"Gate release, package, deployment, or environment-mutating jobs with protected branches or environments.",
		},
		[]string{
			"Do not remove `id-token: write` from jobs that legitimately mint OIDC tokens; instead scope cloud trust policies tightly.",
			"Validate release/deploy workflows after reducing token scopes.",
		},
		[]string{
			"Run the affected workflow and inspect the permissions summary for each job.",
			"Confirm jobs without write behavior no longer receive write scopes.",
		},
		"broad workflow permission blocks require workflow-owner review before a source patch can be published safely")
}

func workflowPrivilegedContextRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Remove privileged behavior from pull_request_target workflows.",
		"`pull_request_target` is reachable with write-token permissions, secrets, cloud login, release, or deployment behavior.",
		[]string{
			"Split untrusted PR code execution into a `pull_request` workflow with read-only permissions.",
			"Keep `pull_request_target` jobs metadata-only; remove secrets, write permissions, deploy steps, and cloud authentication.",
			"Use environment approvals or protected branches for any remaining privileged path.",
		},
		[]string{
			"Review every job in the workflow because the dangerous behavior may be inherited from workflow-level permissions.",
			"Do not trust artifacts, caches, or checkout content produced by untrusted PRs in privileged jobs.",
		},
		[]string{
			"Run a fork PR and confirm privileged jobs do not execute with secrets or write scopes.",
			"Verify environment protection rules gate deploy or release jobs.",
		},
		"privileged pull_request_target workflows require structural workflow review before automated publication")
}

func workflowUntrustedCheckoutRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Stop checking out untrusted PR head code inside pull_request_target.",
		"A privileged `pull_request_target` job checks out PR-controlled code, allowing untrusted code to run with elevated context.",
		[]string{
			"Remove checkout of `github.event.pull_request.head.*` from privileged jobs.",
			"Run untrusted checkout and build steps in a separate `pull_request` workflow with read-only permissions and no secrets.",
			"If metadata is needed, checkout the trusted base ref only and avoid running PR-controlled scripts.",
		},
		[]string{
			"Changing checkout refs can alter which code is tested; split workflows instead of silently changing build semantics.",
			"Treat PR artifacts from untrusted workflows as untrusted inputs.",
		},
		[]string{
			"Run a fork PR and confirm the privileged workflow does not checkout or execute PR head code.",
			"Confirm any downstream workflow_run consumer validates artifact provenance.",
		},
		"untrusted checkout fixes require workflow restructuring before a safe generated PR can be published")
}

func workflowUnpinnedActionRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return placeholderRepoRemediation(finding, detector,
		"Pin third-party GitHub Actions to audited commit SHAs.",
		"A workflow uses a mutable third-party action reference, so upstream changes can alter CI behavior without review.",
		[]string{
			"Resolve the referenced action tag or branch to an audited full commit SHA.",
			"Replace the mutable ref with the SHA and record the update process in dependency automation.",
			"Prefer allowlisted first-party actions or reusable workflows for privileged jobs.",
		},
		[]string{
			"Do not replace the action ref with an unaudited SHA; review upstream source and release notes first.",
			"Pinning by SHA improves determinism but still requires periodic updates.",
		},
		[]string{
			"Re-run the workflow and confirm the pinned action executes from the intended SHA.",
			"Enable dependency update review for future action upgrades.",
		},
		"uses: owner/action@<audited-full-commit-sha>",
		"action pinning requires an operator-supplied audited SHA")
}

func workflowShellInjectionRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Move PR or issue-controlled GitHub context out of direct shell interpolation.",
		"A shell step interpolates user-controlled GitHub context directly, creating command-injection risk.",
		[]string{
			"Pass user-controlled values through environment variables instead of embedding expressions directly in `run` scripts.",
			"Quote shell variables and avoid `eval`, command substitution, or unquoted heredocs around PR/issue/comment fields.",
			"Prefer purpose-built actions or scripts that treat user input as data.",
		},
		[]string{
			"Review the entire shell block, not only the flagged line, because injection can cross line boundaries.",
			"Do not log untrusted values if they may contain secrets or terminal control characters.",
		},
		[]string{
			"Run the workflow with PR titles and branch names containing shell metacharacters.",
			"Confirm the step treats the value as data and does not execute injected commands.",
		},
		"shell blocks need context-specific quoting and tests before automated publication")
}

func workflowRunPrivilegeRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Gate workflow_run privilege chains and validate upstream artifacts.",
		"`workflow_run` can connect upstream workflow output to privileged repository, release, deployment, or cloud behavior.",
		[]string{
			"Limit `workflow_run` triggers to trusted upstream workflows and protected branches.",
			"Validate artifact provenance before using upstream files in privileged jobs.",
			"Move release, deploy, and cloud-auth behavior behind protected environments.",
		},
		[]string{
			"Treat upstream artifacts as untrusted unless they were produced by a trusted branch and workflow.",
			"Do not grant write scopes to workflow_run jobs unless an approval gate exists.",
		},
		[]string{
			"Trigger the upstream workflow from an untrusted PR and confirm privileged consumers do not run.",
			"Verify deployment environments require approval before privileged actions.",
		},
		"workflow_run remediation depends on repository workflow topology and approval gates")
}

func workflowOIDCTrustRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Restrict OIDC token minting and cloud trust to protected workflow contexts.",
		"`id-token: write` is reachable from workflow contexts that may be influenced by PRs, workflow_run chains, or broad branch triggers.",
		[]string{
			"Remove `id-token: write` from untrusted PR, workflow_run, or all-branch workflow paths.",
			"Scope cloud trust policies to exact repository, workflow, branch, tag, and environment claims.",
			"Require protected environments for production cloud credentials.",
		},
		[]string{
			"Changing OIDC permissions can break cloud deployments; update cloud trust policy and workflow permissions together.",
			"Review the cloud-side trust relationship because repository-only changes may not close the path.",
		},
		[]string{
			"Run cloud login jobs from untrusted and trusted branches and confirm only trusted contexts mint credentials.",
			"Inspect cloud audit logs for denied and allowed OIDC assumption attempts.",
		},
		"OIDC remediation requires both repository workflow changes and cloud trust policy review")
}

func workflowCachePoisoningRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Separate untrusted PR caches from trusted build caches.",
		"Cache keys or restore paths can be influenced by untrusted PR context, allowing poisoned cache reuse.",
		[]string{
			"Avoid PR-controlled fields in cache keys used by privileged or trusted jobs.",
			"Use separate cache namespaces for pull requests and protected-branch builds.",
			"Keep restore keys narrow and avoid broad fallbacks from untrusted workflow runs.",
		},
		[]string{
			"Cache poisoning fixes can increase cache misses; prioritize correctness over reuse for privileged jobs.",
			"Do not reuse artifacts or caches from untrusted PRs in release or deploy workflows.",
		},
		[]string{
			"Run PR and protected-branch workflows and confirm their cache keys do not overlap.",
			"Verify privileged jobs cannot restore PR-controlled cache entries.",
		},
		"cache remediation depends on project package-manager and workflow layout")
}

func workflowArtifactPoisoningRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Isolate untrusted artifacts and restrict release publishing paths.",
		"Untrusted PR or workflow_run output can upload artifacts or release assets consumed by privileged workflows.",
		[]string{
			"Keep untrusted PR artifacts isolated from privileged workflow_run consumers.",
			"Validate artifact checksums, workflow provenance, and branch protection before reuse.",
			"Restrict release publishing to protected branches, environments, and minimal write-token jobs.",
		},
		[]string{
			"Do not treat artifact download as trusted input merely because it came from GitHub Actions.",
			"Review all downstream consumers of the uploaded artifact before changing only the producing job.",
		},
		[]string{
			"Run a fork PR and confirm its artifacts cannot reach privileged release or deploy jobs.",
			"Verify release jobs require protected branch or environment context.",
		},
		"artifact remediation depends on producer and consumer workflow pairing")
}

func workflowAIAgentPromptInjectionRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Separate untrusted prompt input from privileged AI-agent workflow actions.",
		"An AI-agent or LLM workflow step consumes untrusted repository text or prompt files in a path that may also hold write permissions, secrets, OIDC, cloud, release, or repository-write behavior.",
		[]string{
			"Run AI prompt processing from untrusted PR, issue, review, or comment text in a read-only job with no secrets and no repository write scopes.",
			"Split autofix, branch push, PR creation, release, deployment, and cloud steps into a reviewed follow-up workflow or environment approval gate.",
			"Treat repository prompt files from pull requests as untrusted input unless they come from a protected branch.",
			"Pin AI actions and log prompt provenance without storing sensitive prompt context or secrets.",
		},
		[]string{
			"Prompt injection is distinct from shell injection; quoted shell arguments can still steer an agent that has tools or credentials.",
			"Do not pass secrets, OIDC credentials, deployment tokens, or write-capable GitHub tokens to an agent that consumes untrusted prompt content.",
		},
		[]string{
			"Run a fork PR or issue-comment test and confirm the AI job receives read-only permissions and no secrets.",
			"Verify any write-capable follow-up workflow requires maintainer approval or protected-branch/environment gates.",
			"Inspect workflow logs to confirm prompt source, action ref, and permissions are visible for review.",
		},
		"AI-agent prompt paths need workflow-owner review before a safe generated source patch can be published")
}

func workflowSelfHostedRunnerRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Keep untrusted workflows off self-hosted runners and isolate the runner pool.",
		"A job on self-hosted GitHub Actions runners is reachable from untrusted events, so attacker-influenced input can run on infrastructure that may hold cloud, deployment, registry, or internal-network credentials.",
		[]string{
			"Run pull_request, issue, review, comment, and workflow_run jobs on ephemeral GitHub-hosted runners instead of self-hosted runners.",
			"Move secrets, write tokens, id-token: write, cloud authentication, deploy environments, and release publishing off self-hosted jobs that untrusted events can reach.",
			"Restrict self-hosted runner placement to protected branches or reviewed environments, and prefer ephemeral, single-use self-hosted runners over persistent ones.",
		},
		[]string{
			"Self-hosted runners can retain credentials and state between jobs; treat any untrusted job that reached them as a potential compromise until reviewed.",
			"Confirm runner-group visibility and required-approval settings on the GitHub side because repository workflow changes alone may not close the path.",
		},
		[]string{
			"Open a fork pull request and confirm it cannot schedule onto self-hosted runners.",
			"Review GitHub Actions runner-group and environment settings to verify untrusted events cannot reach privileged runners.",
		},
		"self-hosted runner remediation requires both workflow changes and runner/runner-group isolation review")
}

func workflowUnresolvedRunnerRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Make runner placement auditable for untrusted-event jobs.",
		"A job reachable from untrusted events selects its runner through an expression, matrix, or broad custom label, so reviewers cannot prove whether it runs on ephemeral GitHub-hosted or persistent self-hosted infrastructure.",
		[]string{
			"Pin untrusted-event jobs to explicit GitHub-hosted runner labels such as ubuntu-latest.",
			"If a matrix or expression is required, constrain it so untrusted combinations cannot resolve to self-hosted runners.",
			"Document and isolate any self-hosted runner pool the job can target so placement is reviewable.",
		},
		[]string{
			"Dynamic labels can silently change which infrastructure runs untrusted code; re-review after any matrix or label change.",
		},
		[]string{
			"Resolve the matrix and expression locally and confirm no untrusted combination lands on self-hosted runners.",
		},
		"runner-label remediation depends on the project's matrix and runner inventory")
}

func workflowGenericRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return guidanceRepoRemediation(finding, detector,
		"Harden the affected GitHub Actions workflow path.",
		firstNonEmpty(finding.HumanSummary, "The workflow contains a repository automation pattern that can increase machine-identity blast radius."),
		[]string{
			"Review the workflow trigger, token permissions, checkout behavior, secrets, caches, artifacts, and cloud authentication path.",
			"Move untrusted PR code execution to read-only workflows without secrets.",
			"Gate privileged jobs with protected branches or environments and explicit least-privilege permissions.",
		},
		[]string{
			"Generic workflow remediation should be reviewed by the workflow owner before publication.",
		},
		[]string{
			"Run the workflow from trusted and untrusted contexts and compare permissions, secrets, and artifacts.",
		},
		"generic workflow remediation requires detector-specific owner review")
}

func k8sPrivilegedRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return deterministicRepoRemediation(finding, detector,
		"Disable privileged containers in Kubernetes manifests.",
		"A Kubernetes container is configured with `privileged: true`, which can bypass workload isolation boundaries.",
		[]string{
			"Set `privileged: false` on the affected container securityContext.",
			"Apply Pod Security standards and add only the specific Linux capabilities the workload actually needs.",
			"Review hostPath, hostNetwork, hostPID, and hostIPC settings in the same manifest before merging.",
		},
		[]string{
			"Some node-level agents legitimately require elevated settings; confirm workload requirements before merging.",
			"Prefer a dedicated namespace and service account for workloads that need exceptional privileges.",
		},
		[]string{
			"Run `kubectl apply --dry-run=server` or policy validation against the manifest.",
			"Confirm admission policy rejects `privileged: true` for normal application namespaces.",
		},
		&RepoExposurePatchTemplate{
			Strategy:              RepoPatchStrategyLineLiteral,
			Description:           "Replace the privileged container flag with false.",
			Match:                 "privileged: true",
			Replacement:           "privileged: false",
			RequiresSourceContent: true,
		})
}

func terraformPublicACLRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return deterministicRepoRemediation(finding, detector,
		"Replace public S3 ACLs with private ACLs.",
		"Terraform sets an S3 ACL to public-read or public-read-write, which can expose bucket data.",
		[]string{
			"Change public ACL values to `private`.",
			"Use explicit bucket policies for the smallest set of principals that require access.",
			"Enable public access blocks unless a documented exception is approved.",
		},
		[]string{
			"Changing ACLs can break intentionally public static assets; confirm the bucket purpose first.",
			"Prefer bucket policies and CloudFront/OAC over public bucket ACLs for public delivery.",
		},
		[]string{
			"Run `terraform plan` and verify no unintended public access remains.",
			"Run cloud provider public-access checks for the affected bucket.",
		},
		&RepoExposurePatchTemplate{
			Strategy:              RepoPatchStrategyLineRegex,
			Description:           "Replace public-read/public-read-write ACL values with private.",
			MatchPattern:          `(?i)^\s*acl\s*=\s*"public-(?:read|read-write)"\s*(?:#.*)?$`,
			Replacement:           `acl = "private"`,
			RequiresSourceContent: true,
		})
}

func terraformOpenManagementPortRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return placeholderRepoRemediation(finding, detector,
		"Restrict SSH/RDP ingress CIDRs to approved administrative networks.",
		"Terraform security group configuration appears to expose SSH or RDP to the internet.",
		[]string{
			"Replace `0.0.0.0/0` and `::/0` management-port ingress with approved bastion, VPN, or zero-trust access CIDRs.",
			"Prefer SSM Session Manager or identity-aware access over direct public SSH/RDP.",
			"Add tests or policy checks that reject public management-port ingress.",
		},
		[]string{
			"Do not replace open CIDRs with a placeholder in a real PR; use an approved network list.",
			"Confirm emergency access and break-glass paths before tightening management ingress.",
		},
		[]string{
			"Run `terraform plan` and verify management ingress no longer includes `0.0.0.0/0` or `::/0`.",
			"Run infrastructure policy checks against the plan output.",
		},
		"cidr_blocks = var.approved_admin_cidrs",
		"approved administrative CIDRs are environment-specific and must be supplied by an operator")
}

func dockerLatestTagRemediation(finding domain.Finding, detector string) RepoExposureRemediation {
	return placeholderRepoRemediation(finding, detector,
		"Pin Docker base images to immutable versions or digests.",
		"A Dockerfile uses a mutable `latest` tag, reducing build reproducibility and supply-chain traceability.",
		[]string{
			"Resolve the base image to an approved version tag or digest.",
			"Replace `:latest` with the approved immutable reference.",
			"Document the image update process through dependency automation or release notes.",
		},
		[]string{
			"Do not publish a PR with a placeholder image tag; choose a tested version or digest.",
			"Digest pinning improves reproducibility but should be paired with update automation.",
		},
		[]string{
			"Rebuild the image and run the application test suite.",
			"Confirm the image reference no longer depends on the mutable `latest` tag.",
		},
		"FROM <image>:<pinned-version-or-digest>",
		"Docker image pinning requires an operator-selected tested version or digest")
}

func deterministicRepoRemediation(
	finding domain.Finding,
	detector string,
	summary string,
	risk string,
	steps []string,
	safety []string,
	validation []string,
	patch *RepoExposurePatchTemplate,
) RepoExposureRemediation {
	remediation := guidanceRepoRemediation(finding, detector, summary, risk, steps, safety, validation, "")
	remediation.Patch = patch
	remediation.Publishable = patch != nil && !patch.Placeholder
	if remediation.Publishable {
		remediation.PublishBlockedReason = ""
	}
	return remediation
}

func placeholderRepoRemediation(
	finding domain.Finding,
	detector string,
	summary string,
	risk string,
	steps []string,
	safety []string,
	validation []string,
	replacement string,
	blockedReason string,
) RepoExposureRemediation {
	remediation := guidanceRepoRemediation(finding, detector, summary, risk, steps, safety, validation, blockedReason)
	remediation.Patch = &RepoExposurePatchTemplate{
		Strategy:              RepoPatchStrategyLineLiteral,
		Description:           "Preview-only replacement requiring operator-supplied values.",
		Replacement:           replacement,
		RequiresSourceContent: true,
		Placeholder:           true,
	}
	return remediation
}

func guidanceRepoRemediation(
	finding domain.Finding,
	detector string,
	summary string,
	risk string,
	steps []string,
	safety []string,
	validation []string,
	blockedReason string,
) RepoExposureRemediation {
	publishable := blockedReason == ""
	if blockedReason == "" {
		blockedReason = "no deterministic source patch is available for this detector"
		publishable = false
	}
	return RepoExposureRemediation{
		Detector:             detector,
		Summary:              summary,
		RiskSummary:          firstNonEmpty(risk, finding.HumanSummary, finding.Title),
		Steps:                append([]string(nil), steps...),
		SafetyNotes:          append([]string(nil), safety...),
		Validation:           append([]string(nil), validation...),
		Publishable:          publishable,
		PublishBlockedReason: blockedReason,
		Evidence:             repoExposureScope(finding, true),
	}
}

func repoExposureScope(finding domain.Finding, includeSnippet bool) RepoExposureRemediationScope {
	scope := RepoExposureRemediationScope{
		FindingID:  strings.TrimSpace(finding.ID),
		ScanID:     strings.TrimSpace(finding.ScanID),
		Repository: strings.TrimSpace(finding.Repository),
		Commit:     strings.TrimSpace(finding.Commit),
		FilePath:   strings.TrimSpace(finding.FilePath),
		LineNumber: finding.LineNumber,
	}
	if includeSnippet && finding.Type != domain.FindingSecretExposure && (finding.LineSnippetRedacted == nil || !*finding.LineSnippetRedacted) {
		scope.LineSnippet = strings.TrimSpace(finding.LineSnippet)
	}
	return scope
}

func repoDetectorOrDefault(finding domain.Finding, fallback string) string {
	if detector := strings.TrimSpace(finding.Detector); detector != "" {
		return detector
	}
	if detector := stringEvidence(finding.Evidence, "detector"); detector != "" {
		return detector
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
