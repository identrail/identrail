package standards

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/identrail/identrail/internal/domain"
)

// PatchTemplate is a preview-only, deterministic remediation suggestion for one finding type.
// Direct commit to a default branch is out of scope; all templates are advisory.
type PatchTemplate struct {
	RuleID      domain.FindingType `json:"rule_id"`
	Summary     string             `json:"summary"`
	Steps       []string           `json:"steps"`
	SafetyNotes []string           `json:"safety_notes"`
	// Template is a policy/config fragment the operator can adapt and apply.
	// Empty when no structured template applies to the finding type.
	Template string `json:"template,omitempty"`
}

// SuggestPatch returns a deterministic, evidence-aware patch suggestion for a finding.
// Returns false if no patch template is registered for the finding type.
//
// For finding types emitted by multiple providers (overprivileged_identity,
// escalation_path), the template is routed by provider so AWS findings receive
// IAM guidance and Kubernetes findings receive RBAC guidance.
func SuggestPatch(finding domain.Finding) (PatchTemplate, bool) {
	provider := inferProvider(finding)
	switch finding.Type {
	case domain.FindingOverPrivileged:
		if provider == "kubernetes" {
			return overprivilegedKubernetesPatch(finding), true
		}
		return overprivilegedAWSPatch(finding), true
	case domain.FindingRiskyTrustPolicy:
		return riskyTrustPatch(finding), true
	case domain.FindingEscalationPath:
		if provider == "kubernetes" {
			return escalationKubernetesPatch(finding), true
		}
		return escalationAWSPatch(finding), true
	case domain.FindingStaleIdentity:
		return staleIdentityPatch(finding), true
	case domain.FindingOwnerless:
		return ownerlessPatch(finding), true
	}
	return PatchTemplate{}, false
}

func overprivilegedAWSPatch(finding domain.Finding) PatchTemplate {
	arn := stringEvidence(finding.Evidence, "identity_arn")
	displayARN := arn
	if displayARN == "" {
		displayARN = "the identity"
	}
	return PatchTemplate{
		RuleID:  domain.FindingOverPrivileged,
		Summary: "Replace broad permissions with a least-privilege inline policy.",
		Steps: []string{
			fmt.Sprintf("Review the 'permissions' evidence for %s to identify overly broad actions.", displayARN),
			"Create a scoped IAM inline policy granting only the required actions on specific resource ARNs.",
			"Attach the scoped policy and detach or restrict the existing broad policy.",
			"Validate workload behavior in a non-production environment before applying to production.",
			"Verify with iam:SimulatePrincipalPolicy that the workload retains necessary access.",
		},
		SafetyNotes: []string{
			"Confirm the workload's required actions before narrowing scope.",
			"Prefer resource-level ARN constraints over wildcard resource grants.",
			"Test in a non-production environment before applying changes to production.",
		},
		Template: scopedInlinePolicyJSON(arn),
	}
}

func riskyTrustPatch(finding domain.Finding) PatchTemplate {
	arn := stringEvidence(finding.Evidence, "identity_arn")
	principals := stringsEvidence(finding.Evidence, "risky_principals")
	accountID := stringEvidence(finding.Evidence, "target_account_id")
	displayARN := arn
	if displayARN == "" {
		displayARN = "the role"
	}
	return PatchTemplate{
		RuleID:  domain.FindingRiskyTrustPolicy,
		Summary: "Restrict trust policy to explicit, scoped principals with condition guards.",
		Steps: []string{
			fmt.Sprintf("Identify the risky principals for %s: %s.", displayARN, joinOrUnknown(principals)),
			"Replace wildcard or cross-account principals with explicit, approved principal ARNs.",
			"Add a Condition block using aws:PrincipalAccount or aws:PrincipalArn to constrain who can assume the role.",
			"Test assume-role from each legitimate caller to confirm access is not broken.",
			"Revoke trust from any principal not in the approved list.",
		},
		SafetyNotes: []string{
			"Verify all legitimate assume-role callers are listed before restricting trust.",
			"Use aws:PrincipalAccount conditions rather than account-level wildcards.",
			"Run iam:SimulatePrincipalPolicy after the change to confirm expected access.",
		},
		Template: scopedTrustPolicyJSON(arn, accountID),
	}
}

func escalationAWSPatch(finding domain.Finding) PatchTemplate {
	arn := stringEvidence(finding.Evidence, "identity_arn")
	action := stringEvidence(finding.Evidence, "escalation_action")
	resource := stringEvidence(finding.Evidence, "resource")
	displayARN := arn
	if displayARN == "" {
		displayARN = "the identity"
	}
	displayAction := action
	if displayAction == "" {
		displayAction = "the escalation action"
	}
	displayResource := resource
	if displayResource == "" {
		displayResource = "the target resource"
	}
	return PatchTemplate{
		RuleID:  domain.FindingEscalationPath,
		Summary: "Remove or scope escalation-capable permissions to break the privilege escalation path.",
		Steps: []string{
			fmt.Sprintf("Locate the policy granting '%s' on '%s' for %s.", displayAction, displayResource, displayARN),
			"Remove iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, iam:PassRole, and sts:AssumeRole wildcard grants.",
			"If iam:PassRole is required, scope it to specific role ARNs using a Resource constraint.",
			"Add an explicit Deny for escalation verbs if the policy is shared across multiple principals.",
			"Use IAM Access Analyzer to verify no other path grants equivalent escalation capability.",
		},
		SafetyNotes: []string{
			"Confirm no legitimate automation depends on the escalation-capable permission before removing it.",
			"Use IAM Access Analyzer to identify all paths that could still reach equivalent privilege.",
			"Prefer an explicit Deny for escalation verbs over removal alone when policies are shared.",
		},
		Template: escalationDenyPolicyJSON(arn),
	}
}

func overprivilegedKubernetesPatch(finding domain.Finding) PatchTemplate {
	identityID := stringEvidence(finding.Evidence, "identity_id")
	displayID := identityID
	if displayID == "" {
		displayID = "the service account"
	}
	sample := sampleEvidence(finding.Evidence)
	return PatchTemplate{
		RuleID:  domain.FindingOverPrivileged,
		Summary: "Replace broad ClusterRole/Role bindings with least-privilege RBAC scoped to required namespaces and verbs.",
		Steps: []string{
			fmt.Sprintf("Review the cluster bindings for %s and identify broad verbs or wildcard resources (e.g., %s).", displayID, sample),
			"Define a namespaced Role (or ClusterRole if cluster-scoped resources are required) with only the verbs/resources the workload needs.",
			"Replace the existing ClusterRoleBinding/RoleBinding with one that targets the scoped Role.",
			"Audit with `kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<name>` after the change.",
			"Validate workload behavior in a non-production namespace before applying to production.",
		},
		SafetyNotes: []string{
			"Confirm the workload's required verbs and resources before narrowing scope.",
			"Prefer namespaced Role over ClusterRole when the workload only needs same-namespace access.",
			"Avoid `verbs: [\"*\"]` and `resources: [\"*\"]` in the replacement Role.",
		},
		Template: scopedRBACYAML(identityID),
	}
}

func escalationKubernetesPatch(finding domain.Finding) PatchTemplate {
	identityID := stringEvidence(finding.Evidence, "identity_id")
	workloadID := stringEvidence(finding.Evidence, "workload_id")
	action := stringEvidence(finding.Evidence, "action")
	resource := stringEvidence(finding.Evidence, "resource")
	displayID := identityID
	if displayID == "" {
		displayID = "the service account"
	}
	displayWorkload := workloadID
	if displayWorkload == "" {
		displayWorkload = "the workload"
	}
	displayAction := action
	if displayAction == "" {
		displayAction = "the escalation verb"
	}
	displayResource := resource
	if displayResource == "" {
		displayResource = "the target resource"
	}
	return PatchTemplate{
		RuleID:  domain.FindingEscalationPath,
		Summary: "Break the RBAC escalation path by removing escalation verbs and isolating the workload to a dedicated service account.",
		Steps: []string{
			fmt.Sprintf("Locate the ClusterRole/Role granting '%s' on '%s' bound to %s via %s.", displayAction, displayResource, displayID, displayWorkload),
			"Remove escalation verbs (`bind`, `escalate`, `impersonate`) and wildcard rules from the bound Role/ClusterRole.",
			fmt.Sprintf("Create a dedicated service account for %s rather than sharing a broadly privileged one.", displayWorkload),
			"Replace the binding to target the new dedicated service account with the minimum required Role.",
			"Verify with `kubectl auth can-i bind clusterroles --as=system:serviceaccount:<namespace>:<name>` returns 'no' after the change.",
		},
		SafetyNotes: []string{
			"Removing `bind`/`escalate` may break controllers that legitimately manage RBAC — confirm before applying.",
			"Use audit logs to confirm no other workload depends on the same broadly privileged binding.",
			"Prefer creating a new dedicated service account over editing a shared one in place.",
		},
		Template: rbacEscalationFixYAML(identityID),
	}
}

func staleIdentityPatch(finding domain.Finding) PatchTemplate {
	arn := stringEvidence(finding.Evidence, "identity_arn")
	ref := stringEvidence(finding.Evidence, "reference_timestamp")
	displayARN := arn
	if displayARN == "" {
		displayARN = "the identity"
	}
	displayRef := ref
	if displayRef == "" {
		displayRef = "the reference timestamp in the finding evidence"
	}
	return PatchTemplate{
		RuleID:  domain.FindingStaleIdentity,
		Summary: "Disable then delete the stale identity after confirming no active dependency.",
		Steps: []string{
			fmt.Sprintf("Confirm %s has had no CloudTrail activity since %s.", displayARN, displayRef),
			"Disable all access keys: aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>",
			"Remove the console login profile if present: aws iam delete-login-profile --user-name <USER>",
			"Wait 30 days with keys disabled. If no objections, delete the access keys and the identity.",
			"For roles: remove all trust policy principals and tag with 'decommission-pending' before deletion.",
		},
		SafetyNotes: []string{
			"Check CloudTrail for any recent API calls made under this identity before disabling.",
			"Disable before deleting — deletion cannot be reversed.",
			"Notify the team owner before proceeding if the identity carries an owner tag.",
		},
		Template: "",
	}
}

func ownerlessPatch(finding domain.Finding) PatchTemplate {
	arn := stringEvidence(finding.Evidence, "identity_arn")
	displayARN := arn
	if displayARN == "" {
		displayARN = "the identity"
	}
	return PatchTemplate{
		RuleID:  domain.FindingOwnerless,
		Summary: "Assign an owner via tags (AWS) or labels (Kubernetes) and register in the ownership registry.",
		Steps: []string{
			fmt.Sprintf("Identify the team responsible for %s via git history, cost allocation tags, or service catalog.", displayARN),
			"Apply the owner tag or label from the template below.",
			"Register the owner mapping in the centralized ownership registry.",
			"Enforce owner-label presence in CI policy for future identity creation.",
		},
		SafetyNotes: []string{
			"Confirm the correct owner before tagging — incorrect ownership causes mis-routing during incidents.",
		},
		Template: ownerTagTemplate(arn),
	}
}

// --- template generators ---

func scopedInlinePolicyJSON(arn string) string {
	comment := "Replace wildcard actions with the minimum required set."
	if arn != "" {
		comment = fmt.Sprintf("Scoped inline policy for %s — replace placeholders with required actions and resource ARNs.", arn)
	}
	doc := map[string]any{
		"_note":   comment,
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Effect":   "Allow",
				"Action":   []string{"<service>:<RequiredAction>"},
				"Resource": []string{"arn:aws:<service>:<region>:<account-id>:<resource-type>/<resource-name>"},
			},
		},
	}
	return mustJSON(doc)
}

func scopedTrustPolicyJSON(arn, accountID string) string {
	if accountID == "" {
		accountID = "<account-id>"
	}
	comment := "Replace wildcard trust with explicit approved principal ARNs."
	if arn != "" {
		comment = fmt.Sprintf("Scoped trust policy for %s — replace <approved-role> with the explicit caller ARN.", arn)
	}
	doc := map[string]any{
		"_note":   comment,
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Effect": "Allow",
				"Principal": map[string]any{
					"AWS": []string{fmt.Sprintf("arn:aws:iam::%s:role/<approved-role>", accountID)},
				},
				"Action": "sts:AssumeRole",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"aws:PrincipalAccount": accountID,
					},
				},
			},
		},
	}
	return mustJSON(doc)
}

func escalationDenyPolicyJSON(arn string) string {
	comment := "Deny escalation-capable actions unless explicitly authorized."
	if arn != "" {
		comment = fmt.Sprintf("Deny escalation-capable actions for %s — replace <approved-account-id> with your account.", arn)
	}
	doc := map[string]any{
		"_note":   comment,
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Effect": "Deny",
				"Action": []string{
					"iam:CreatePolicyVersion",
					"iam:SetDefaultPolicyVersion",
					"iam:PassRole",
					"sts:AssumeRole",
				},
				"Resource": "*",
				"Condition": map[string]any{
					"StringNotEquals": map[string]any{
						"aws:ResourceAccount": "<approved-account-id>",
					},
				},
			},
		},
	}
	return mustJSON(doc)
}

func scopedRBACYAML(identityID string) string {
	displayID := identityID
	if displayID == "" {
		displayID = "<service-account-name>"
	}
	return strings.Join([]string{
		fmt.Sprintf("# Scoped Role for %s — replace placeholders with the minimum required verbs/resources.", displayID),
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: Role",
		"metadata:",
		"  name: <scoped-role-name>",
		"  namespace: <namespace>",
		"rules:",
		"  - apiGroups: [\"\"]",
		"    resources: [\"<resource-type>\"]",
		"    verbs: [\"get\", \"list\", \"watch\"]",
		"---",
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: RoleBinding",
		"metadata:",
		"  name: <scoped-binding-name>",
		"  namespace: <namespace>",
		"subjects:",
		"  - kind: ServiceAccount",
		"    name: <service-account-name>",
		"    namespace: <namespace>",
		"roleRef:",
		"  kind: Role",
		"  name: <scoped-role-name>",
		"  apiGroup: rbac.authorization.k8s.io",
	}, "\n")
}

func rbacEscalationFixYAML(identityID string) string {
	displayID := identityID
	if displayID == "" {
		displayID = "<workload-service-account>"
	}
	return strings.Join([]string{
		fmt.Sprintf("# Dedicated service account for %s — replace placeholders for your workload.", displayID),
		"apiVersion: v1",
		"kind: ServiceAccount",
		"metadata:",
		"  name: <workload-service-account>",
		"  namespace: <namespace>",
		"---",
		"# Minimal Role without bind/escalate/impersonate verbs.",
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: Role",
		"metadata:",
		"  name: <workload-role>",
		"  namespace: <namespace>",
		"rules:",
		"  - apiGroups: [\"\"]",
		"    resources: [\"<resource-type>\"]",
		"    verbs: [\"get\", \"list\"]",
		"---",
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: RoleBinding",
		"metadata:",
		"  name: <workload-binding>",
		"  namespace: <namespace>",
		"subjects:",
		"  - kind: ServiceAccount",
		"    name: <workload-service-account>",
		"    namespace: <namespace>",
		"roleRef:",
		"  kind: Role",
		"  name: <workload-role>",
		"  apiGroup: rbac.authorization.k8s.io",
	}, "\n")
}

func ownerTagTemplate(arn string) string {
	arnLine := `"arn:aws:<service>:<region>:<account-id>:<resource-type>/<resource-name>"`
	if arn != "" {
		arnLine = fmt.Sprintf("%q", arn)
	}
	lines := []string{
		"# AWS tag patch — apply owner tags to the identity:",
		fmt.Sprintf(`aws resourcegroupstaggingapi tag-resources \`),
		fmt.Sprintf(`  --resource-arn-list %s \`, arnLine),
		`  --tags '{"owner":"<team-name>","env":"<environment>"}'`,
		"",
		"# Kubernetes label patch (if identity is a service account):",
		"# kubectl label serviceaccount <name> -n <namespace> owner=<team-name> --overwrite",
	}
	return strings.Join(lines, "\n")
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func stringEvidence(evidence map[string]any, key string) string {
	if evidence == nil {
		return ""
	}
	v, ok := evidence[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func stringsEvidence(evidence map[string]any, key string) []string {
	if evidence == nil {
		return nil
	}
	v, ok := evidence[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// sampleEvidence renders the kubernetes overprivileged 'sample' evidence as a
// human-readable "verb on resource" string, falling back to a placeholder when
// the evidence is absent or malformed.
func sampleEvidence(evidence map[string]any) string {
	if evidence == nil {
		return "wildcard verbs or resources"
	}
	raw, ok := evidence["sample"]
	if !ok {
		return "wildcard verbs or resources"
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return "wildcard verbs or resources"
	}
	action, _ := m["action"].(string)
	resource, _ := m["resource"].(string)
	switch {
	case action != "" && resource != "":
		return fmt.Sprintf("%s on %s", action, resource)
	case action != "":
		return action
	case resource != "":
		return resource
	}
	return "wildcard verbs or resources"
}

func joinOrUnknown(ss []string) string {
	if len(ss) == 0 {
		return "unknown"
	}
	return strings.Join(ss, ", ")
}
