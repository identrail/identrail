package github

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

const (
	githubPostureFindingVersion      = "2026.07"
	githubPostureAdapterSource       = "github_posture"
	githubOrgPostureAdapterSource    = "github_org_posture"
	githubPosturePermissionDetector  = "github_posture_permission_limited"
	githubPostureUnavailableDetector = "github_posture_unavailable"
	githubPostureUnknownDetector     = "github_posture_unknown"
)

// RepositoryPostureFindings converts non-secure repository posture checks into
// durable repository findings. Secure checks and unsupported plan/account
// surfaces are intentionally skipped.
func RepositoryPostureFindings(posture RepositoryPosture, detectedAt time.Time) []domain.Finding {
	return postureChecksToFindings(posture.Repository, "", posture.InstallationID, posture.CollectedAt, posture.Checks, githubPostureAdapterSource, "repository", detectedAt)
}

// OrganizationPostureFindings converts non-secure organization posture checks
// into durable repository findings scoped to the repository that inherited the
// organization policy.
func OrganizationPostureFindings(posture OrganizationPosture, repository string, detectedAt time.Time) []domain.Finding {
	return postureChecksToFindings(repository, posture.Organization, posture.InstallationID, posture.CollectedAt, posture.Checks, githubOrgPostureAdapterSource, "organization", detectedAt)
}

func postureChecksToFindings(repository string, organization string, installationID int64, collectedAt time.Time, checks []RepositoryPostureCheck, adapterSource string, scope string, detectedAt time.Time) []domain.Finding {
	repository = strings.ToLower(strings.TrimSpace(repository))
	organization = strings.ToLower(strings.TrimSpace(organization))
	if repository == "" || len(checks) == 0 {
		return nil
	}
	if detectedAt.IsZero() {
		detectedAt = time.Now().UTC()
	}
	if collectedAt.IsZero() {
		collectedAt = detectedAt
	}
	findings := make([]domain.Finding, 0, len(checks))
	seen := map[string]struct{}{}
	for _, check := range checks {
		finding, ok := postureCheckToFinding(repository, organization, installationID, collectedAt.UTC(), check, adapterSource, scope, detectedAt.UTC())
		if !ok {
			continue
		}
		if _, exists := seen[finding.LifecycleKey]; exists {
			continue
		}
		seen[finding.LifecycleKey] = struct{}{}
		findings = append(findings, finding)
	}
	return findings
}

func postureCheckToFinding(repository string, organization string, installationID int64, collectedAt time.Time, check RepositoryPostureCheck, adapterSource string, scope string, detectedAt time.Time) (domain.Finding, bool) {
	check.ID = strings.TrimSpace(check.ID)
	check.Category = strings.TrimSpace(check.Category)
	check.Reason = strings.TrimSpace(check.Reason)
	check.Summary = strings.TrimSpace(check.Summary)
	if check.ID == "" || check.State == RepositoryPostureStateSecure || check.State == RepositoryPostureStateUnsupported {
		return domain.Finding{}, false
	}
	detector := postureFindingDetector(check)
	if detector == "" {
		return domain.Finding{}, false
	}
	severity := postureFindingSeverity(check, detector)
	confidence := postureFindingConfidence(check.State)
	lifecycleKey := postureFindingLifecycleKey(repository, adapterSource, scope, check.ID)
	evidence := postureFindingEvidence(repository, organization, installationID, collectedAt, check, adapterSource, scope, detector, confidence)
	finding := domain.Finding{
		ID:                  postureFindingID(lifecycleKey),
		Type:                domain.FindingRepoMisconfig,
		Severity:            severity,
		ConfidenceScore:     confidence,
		Title:               postureFindingTitle(check),
		HumanSummary:        postureFindingSummary(check),
		Repository:          repository,
		Detector:            detector,
		LifecycleKey:        lifecycleKey,
		LifecycleStatus:     domain.RepoFindingLifecycleOpen,
		RuleVersion:         githubPostureFindingVersion,
		DetectorVersion:     githubPostureFindingVersion,
		AdapterSource:       adapterSource,
		ConfidenceState:     postureFindingConfidenceState(check.State),
		VerificationStatus:  string(check.State),
		EvidenceVersion:     githubPostureFindingVersion,
		Evidence:            evidence,
		Remediation:         postureFindingRemediation(check, detector),
		CreatedAt:           detectedAt,
		LineSnippetRedacted: boolPointer(false),
	}
	domain.NormalizeRepoFindingMetadata(&finding)
	return finding, true
}

// postureFindingLifecycleKey builds the scanner-stable identity for one posture
// check. It deliberately keys on the check id rather than the detector, so the
// same control keeps one durable finding even when its state (and therefore its
// detector, severity, and confidence) changes between scans.
func postureFindingLifecycleKey(repository string, adapterSource string, scope string, checkID string) string {
	return strings.Join([]string{
		"repo_finding",
		repository,
		string(domain.FindingRepoMisconfig),
		adapterSource,
		scope,
		checkID,
	}, "\x1f")
}

// RepositoryPostureInconclusiveLifecycleKeys returns the lifecycle keys of
// repository posture checks this collection could not conclusively evaluate.
// Callers must not close a durable finding for these keys: the control was never
// re-checked, so its absence from the promoted findings says nothing about
// whether the gap was fixed.
func RepositoryPostureInconclusiveLifecycleKeys(posture RepositoryPosture) []string {
	return postureInconclusiveLifecycleKeys(posture.Repository, posture.Checks, githubPostureAdapterSource, "repository")
}

// OrganizationPostureInconclusiveLifecycleKeys returns the lifecycle keys of
// organization posture checks this collection could not conclusively evaluate,
// scoped to the repository that inherits the organization policy.
func OrganizationPostureInconclusiveLifecycleKeys(posture OrganizationPosture, repository string) []string {
	return postureInconclusiveLifecycleKeys(repository, posture.Checks, githubOrgPostureAdapterSource, "organization")
}

func postureInconclusiveLifecycleKeys(repository string, checks []RepositoryPostureCheck, adapterSource string, scope string) []string {
	repository = strings.ToLower(strings.TrimSpace(repository))
	if repository == "" || len(checks) == 0 {
		return nil
	}
	keys := make([]string, 0, len(checks))
	seen := map[string]struct{}{}
	for _, check := range checks {
		checkID := strings.TrimSpace(check.ID)
		if checkID == "" || postureCheckConclusive(check) {
			continue
		}
		key := postureFindingLifecycleKey(repository, adapterSource, scope, checkID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

// postureCheckConclusive reports whether GitHub gave a definitive answer for one
// posture check, so a prior finding for it may be closed when the check no
// longer reports a gap.
//
// `secure` and `insecure` are definitive. `unsupported` is definitive only when
// the control genuinely does not apply to this owner (a user account has no
// organization policy); an `unsupported` caused by the account plan no longer
// exposing the control means the gap was never verified as fixed, so it stays
// open for an operator to suppress or act on. `permission_limited`,
// `unavailable`, and `unknown` are never definitive.
func postureCheckConclusive(check RepositoryPostureCheck) bool {
	switch check.State {
	case RepositoryPostureStateSecure, RepositoryPostureStateInsecure:
		return true
	case RepositoryPostureStateUnsupported:
		return strings.TrimSpace(check.Reason) == "not_an_organization"
	default:
		return false
	}
}

func postureFindingDetector(check RepositoryPostureCheck) string {
	switch check.State {
	case RepositoryPostureStatePermissionLimited:
		return githubPosturePermissionDetector
	case RepositoryPostureStateUnavailable:
		return githubPostureUnavailableDetector
	case RepositoryPostureStateUnknown:
		return githubPostureUnknownDetector
	case RepositoryPostureStateInsecure:
	default:
		return ""
	}
	switch check.ID {
	case "repository_metadata":
		return "github_repository_metadata_weak"
	case "default_branch_protection":
		return "github_default_branch_unprotected"
	case "repository_rulesets":
		return "github_rulesets_weak"
	case "actions_permissions", "org_actions_policy":
		return "github_actions_policy_broad"
	case "org_workflow_permissions":
		return "github_workflow_permissions_write_default"
	case "dependabot_security":
		return "github_dependabot_disabled"
	case "code_scanning":
		return "github_code_scanning_disabled"
	case "secret_scanning", "org_secret_scanning_policy":
		return "github_secret_scanning_disabled"
	case "deploy_keys":
		return "github_write_deploy_key"
	case "webhooks":
		return "github_webhook_unhealthy"
	case "deployment_environments":
		return "github_environment_unprotected"
	case "self_hosted_runners":
		return "github_self_hosted_runner_unrestricted"
	case "org_reusable_workflow_policy":
		return "github_reusable_workflow_policy_broad"
	case "org_code_security_configuration":
		return "github_code_security_configuration_weak"
	default:
		return "github_posture_" + sanitizePostureID(check.ID)
	}
}

func postureFindingSeverity(check RepositoryPostureCheck, detector string) domain.FindingSeverity {
	switch check.State {
	case RepositoryPostureStatePermissionLimited:
		return domain.SeverityMedium
	case RepositoryPostureStateUnavailable, RepositoryPostureStateUnknown:
		return domain.SeverityLow
	}
	switch detector {
	case "github_default_branch_unprotected",
		"github_secret_scanning_disabled",
		"github_write_deploy_key",
		"github_self_hosted_runner_unrestricted",
		"github_workflow_permissions_write_default":
		return domain.SeverityHigh
	case "github_repository_metadata_weak", "github_webhook_unhealthy":
		return domain.SeverityLow
	default:
		return domain.SeverityMedium
	}
}

func postureFindingConfidence(state RepositoryPostureState) float64 {
	switch state {
	case RepositoryPostureStateInsecure:
		return 0.92
	case RepositoryPostureStatePermissionLimited:
		return 0.72
	case RepositoryPostureStateUnavailable:
		return 0.60
	case RepositoryPostureStateUnknown:
		return 0.55
	default:
		return 0.50
	}
}

func postureFindingConfidenceState(state RepositoryPostureState) string {
	switch state {
	case RepositoryPostureStateInsecure:
		return "high_confidence"
	case RepositoryPostureStatePermissionLimited:
		return "permission_limited"
	case RepositoryPostureStateUnavailable:
		return "unavailable"
	case RepositoryPostureStateUnknown:
		return "unknown"
	default:
		return strings.TrimSpace(string(state))
	}
}

func postureFindingEvidence(repository string, organization string, installationID int64, collectedAt time.Time, check RepositoryPostureCheck, adapterSource string, scope string, detector string, confidence float64) map[string]any {
	evidence := map[string]any{}
	if len(check.Evidence) > 0 {
		evidence = maps.Clone(check.Evidence)
	}
	evidence["repository"] = repository
	if organization != "" {
		evidence["organization"] = organization
	}
	if installationID > 0 {
		evidence["installation_id"] = installationID
	}
	evidence["detector"] = detector
	evidence["adapter_source"] = adapterSource
	evidence["adapter_source_type"] = adapterSource
	evidence["github_posture_scope"] = scope
	evidence["github_posture_check_id"] = check.ID
	evidence["github_posture_category"] = check.Category
	evidence["github_posture_state"] = string(check.State)
	evidence["github_posture_reason"] = check.Reason
	evidence["github_posture_summary"] = check.Summary
	evidence["github_posture_collected_at"] = collectedAt.UTC().Format(time.RFC3339)
	evidence["confidence_score"] = confidence
	evidence["confidence_state"] = postureFindingConfidenceState(check.State)
	evidence["rule_version"] = githubPostureFindingVersion
	evidence["detector_version"] = githubPostureFindingVersion
	evidence["evidence_version"] = githubPostureFindingVersion
	evidence["raw_secret_stored"] = false
	evidence["raw_adapter_result_stored"] = false
	return evidence
}

func postureFindingTitle(check RepositoryPostureCheck) string {
	name := strings.ReplaceAll(strings.TrimSpace(check.ID), "_", " ")
	if name == "" {
		name = "GitHub posture"
	}
	switch check.State {
	case RepositoryPostureStatePermissionLimited:
		return "GitHub posture check permission-limited: " + name
	case RepositoryPostureStateUnavailable:
		return "GitHub posture check unavailable: " + name
	case RepositoryPostureStateUnknown:
		return "GitHub posture check unknown: " + name
	default:
		return "GitHub posture gap: " + name
	}
}

func postureFindingSummary(check RepositoryPostureCheck) string {
	if check.Summary != "" {
		return check.Summary
	}
	return fmt.Sprintf("GitHub posture check %q reported state %q.", check.ID, check.State)
}

func postureFindingRemediation(check RepositoryPostureCheck, detector string) string {
	switch detector {
	case githubPosturePermissionDetector:
		return "Grant the GitHub App the read permission needed for this posture source, then rerun repository intelligence."
	case githubPostureUnavailableDetector:
		return "Retry posture collection and verify the GitHub API, installation, and account plan expose this posture source."
	case githubPostureUnknownDetector:
		return "Review the GitHub control manually and update the posture collector classification if this state is expected."
	case "github_default_branch_unprotected":
		return "Require pull-request reviews, required status checks, admin enforcement, and destructive-change protection on the default branch."
	case "github_rulesets_weak":
		return "Add an active branch ruleset that enforces review, status-check, and destructive-change protections."
	case "github_secret_scanning_disabled":
		return "Enable GitHub secret scanning and push protection, preferably through an enforced organization code security configuration."
	case "github_code_scanning_disabled":
		return "Enable code scanning for the repository or attach it to an organization security configuration that enables code scanning."
	case "github_dependabot_disabled":
		return "Enable Dependabot alerts and security updates for the repository."
	case "github_actions_policy_broad":
		return "Restrict GitHub Actions sources and default workflow permissions to least privilege."
	case "github_workflow_permissions_write_default":
		return "Set default workflow token permissions to read-only and grant write scopes only to jobs that require them."
	case "github_reusable_workflow_policy_broad":
		return "Restrict reusable workflows and third-party actions to an explicit pinned allowlist."
	case "github_code_security_configuration_weak":
		return "Enable an enforced organization-level code security configuration that covers secret scanning, code scanning, and Dependabot settings."
	case "github_write_deploy_key":
		return "Remove writable deploy keys or replace them with scoped, auditable GitHub App access."
	case "github_webhook_unhealthy":
		return "Disable insecure webhook SSL settings and repair or remove failing webhook deliveries."
	case "github_environment_unprotected":
		return "Add required reviewers or deployment protection rules to sensitive GitHub environments."
	case "github_self_hosted_runner_unrestricted":
		return "Isolate self-hosted runners with restricted runner groups and avoid routing untrusted workflows to persistent infrastructure."
	default:
		return "Review the GitHub posture check and harden the affected repository or organization control."
	}
}

func postureFindingID(lifecycleKey string) string {
	sum := sha256.Sum256([]byte(lifecycleKey))
	return "finding:" + hex.EncodeToString(sum[:16])
}

func sanitizePostureID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}
	return strings.Trim(builder.String(), "_")
}

func boolPointer(value bool) *bool {
	return &value
}
