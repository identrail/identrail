package aws

import (
	"sort"
	"strings"

	"github.com/identrail/identrail/internal/domain"
)

// CapabilityPermissionTier describes the AWS permissions a single connector
// capability tier needs, grouped so operators can see read-only discovery apart
// from the future write/remediation/enforcement tiers before granting anything.
type CapabilityPermissionTier struct {
	Capability  domain.ConnectorCapability     `json:"capability"`
	Tier        domain.ConnectorCapabilityTier `json:"tier"`
	Available   bool                           `json:"available"`
	Summary     string                         `json:"summary"`
	Permissions []PermissionPreviewItem        `json:"permissions"`
}

// CapabilityPermissionTiers returns the AWS permission groups for every connector
// capability in canonical privilege order. Only discovery is available today; the
// remaining tiers are advertised so the boundary between read-only collection and
// future write/enforcement access is explicit, and so write tiers are visibly
// gated rather than silently folded into the read-only role.
func CapabilityPermissionTiers() []CapabilityPermissionTier {
	return []CapabilityPermissionTier{
		{
			Capability:  domain.ConnectorCapabilityDiscovery,
			Tier:        domain.ConnectorCapabilityTierReadOnly,
			Available:   true,
			Summary:     "Read-only inventory and machine-identity graph collection. This is the default and the only tier the one-click CloudFormation role grants.",
			Permissions: PermissionPreview(),
		},
		{
			Capability: domain.ConnectorCapabilityRuntimeEvidence,
			Tier:       domain.ConnectorCapabilityTierReadOnly,
			Available:  false,
			Summary:    "Read-only runtime activity used to prove whether risky permissions are actually exercised. Requires a separate read grant and is not enabled by the read-only stack.",
			Permissions: []PermissionPreviewItem{
				{
					Service:   "IAM",
					Actions:   []string{"iam:GenerateServiceLastAccessedDetails", "iam:GetServiceLastAccessedDetails"},
					Resources: []string{"*"},
					Reason:    "Confirms which services a machine identity has actually used so unused high-risk permissions can be flagged.",
				},
				{
					Service:   "CloudTrail",
					Actions:   []string{"cloudtrail:LookupEvents"},
					Resources: []string{"*"},
					Reason:    "Correlates recent API activity with the identities that performed it.",
				},
				{
					Service:   "AccessAnalyzer",
					Actions:   []string{"access-analyzer:ListFindings", "access-analyzer:GetFinding"},
					Resources: []string{"*"},
					Reason:    "Reads external-access findings that indicate runtime exposure of an identity.",
				},
			},
		},
		{
			Capability: domain.ConnectorCapabilityRemediationPlan,
			Tier:       domain.ConnectorCapabilityTierReadOnly,
			Available:  false,
			Summary:    "Generates proposed least-privilege fixes by simulation only. It never applies changes; applying requires the separate approved_remediation tier.",
			Permissions: []PermissionPreviewItem{
				{
					Service:   "IAM",
					Actions:   []string{"iam:SimulateCustomPolicy", "iam:GetContextKeysForPrincipalPolicy"},
					Resources: []string{"*"},
					Reason:    "Models the effect of a proposed policy before it is ever applied.",
				},
				{
					Service:   "AccessAnalyzer",
					Actions:   []string{"access-analyzer:ValidatePolicy", "access-analyzer:CheckNoNewAccess"},
					Resources: []string{"*"},
					Reason:    "Validates a proposed policy and proves it grants no new access.",
				},
			},
		},
		{
			Capability: domain.ConnectorCapabilityAuthorizationAdvisory,
			Tier:       domain.ConnectorCapabilityTierReadOnly,
			Available:  false,
			Summary:    "Advisory authorization brokering: recommends session-policy or boundary decisions without applying them. Read-only.",
			Permissions: []PermissionPreviewItem{
				{
					Service:   "IAM",
					Actions:   []string{"iam:GetRolePolicy", "iam:ListRolePolicies", "iam:SimulatePrincipalPolicy"},
					Resources: []string{"*"},
					Reason:    "Evaluates effective permissions to recommend a scoped-down authorization decision.",
				},
				{
					Service:   "Organizations",
					Actions:   []string{"organizations:DescribePolicy", "organizations:ListPoliciesForTarget"},
					Resources: []string{"*"},
					Reason:    "Reads existing service control policies to advise on safe boundaries.",
				},
			},
		},
		{
			Capability: domain.ConnectorCapabilityApprovedRemediation,
			Tier:       domain.ConnectorCapabilityTierWrite,
			Available:  false,
			Summary:    "WRITE: applies operator-approved least-privilege fixes to IAM. Must be granted with a dedicated write role; never granted by the read-only stack.",
			Permissions: []PermissionPreviewItem{
				{
					Service:   "IAM",
					Actions:   []string{"iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy"},
					Resources: []string{"*"},
					Reason:    "Applies an approved remediation to a role's inline or attached policies.",
				},
			},
		},
		{
			Capability: domain.ConnectorCapabilityAuthorizationEnforcement,
			Tier:       domain.ConnectorCapabilityTierWrite,
			Available:  false,
			Summary:    "WRITE: enforces authorization decisions via permission boundaries or SCPs. Must be granted with a dedicated write role; never granted by the read-only stack.",
			Permissions: []PermissionPreviewItem{
				{
					Service:   "IAM",
					Actions:   []string{"iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary"},
					Resources: []string{"*"},
					Reason:    "Applies or removes a permission boundary to enforce an authorization decision.",
				},
				{
					Service:   "Organizations",
					Actions:   []string{"organizations:AttachPolicy", "organizations:DetachPolicy"},
					Resources: []string{"*"},
					Reason:    "Attaches or detaches a service control policy to enforce an organization-wide boundary.",
				},
			},
		},
	}
}

// CapabilityPolicy gates which connector capabilities a deployment permits. The
// read-only discovery tier is always allowed; every other tier (including all
// write-capable tiers) is denied unless explicitly enabled, so remediation and
// enforcement can never be turned on by accident. It satisfies the
// domain.CapabilityGate contract.
type CapabilityPolicy struct {
	enabled map[domain.ConnectorCapability]bool
}

// DefaultCapabilityPolicy returns the safe baseline: only read-only discovery is
// permitted.
func DefaultCapabilityPolicy() CapabilityPolicy {
	return CapabilityPolicy{enabled: map[domain.ConnectorCapability]bool{
		domain.ConnectorCapabilityDiscovery: true,
	}}
}

// NewCapabilityPolicy builds a policy that permits discovery plus any additional
// valid capabilities supplied (for example from a feature flag). Unknown or empty
// entries are ignored so misconfiguration cannot widen access unexpectedly.
func NewCapabilityPolicy(enabled []domain.ConnectorCapability) CapabilityPolicy {
	policy := DefaultCapabilityPolicy()
	for _, capability := range enabled {
		normalized := domain.ConnectorCapability(strings.TrimSpace(string(capability)))
		if domain.ValidConnectorCapability(normalized) {
			policy.enabled[normalized] = true
		}
	}
	return policy
}

// NewCapabilityPolicyFromStrings builds a policy from raw capability names (for
// example a comma-separated feature-flag value). Invalid names are ignored so a
// typo cannot widen access.
func NewCapabilityPolicyFromStrings(enabled []string) CapabilityPolicy {
	capabilities := make([]domain.ConnectorCapability, 0, len(enabled))
	for _, name := range enabled {
		capabilities = append(capabilities, domain.ConnectorCapability(strings.TrimSpace(name)))
	}
	return NewCapabilityPolicy(capabilities)
}

// Configured reports whether the policy has been initialized. The zero value of
// CapabilityPolicy is not configured, so callers can detect it and fall back to
// the safe default.
func (p CapabilityPolicy) Configured() bool {
	return len(p.enabled) > 0
}

// Enabled returns the permitted capabilities in canonical privilege order.
func (p CapabilityPolicy) Enabled() []domain.ConnectorCapability {
	out := make([]domain.ConnectorCapability, 0, len(p.enabled))
	for capability, on := range p.enabled {
		if on {
			out = append(out, capability)
		}
	}
	order := domain.ConnectorCapabilityOrder()
	rank := make(map[domain.ConnectorCapability]int, len(order))
	for index, capability := range order {
		rank[capability] = index
	}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i]] < rank[out[j]] })
	return out
}

// CapabilityAllowed implements domain.CapabilityGate.
func (p CapabilityPolicy) CapabilityAllowed(capability domain.ConnectorCapability) (bool, string) {
	if capability == domain.ConnectorCapabilityDiscovery {
		return true, ""
	}
	if p.enabled[capability] {
		return true, ""
	}
	if capability.IsWriteCapable() {
		return false, "write-capable capability " + string(capability) + " is disabled; it requires a dedicated write role and an explicit feature gate, and is never granted by the read-only connector"
	}
	return false, "capability " + string(capability) + " is not enabled for this deployment"
}
