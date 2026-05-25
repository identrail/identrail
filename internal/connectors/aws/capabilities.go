package aws

import "strings"

// Capability describes the level of AWS connector behavior a workspace is
// requesting. Discovery is the safe default; higher tiers stay gated until a
// deployment explicitly enables the workflow and required IAM policy surface.
type Capability string

const (
	CapabilityDiscovery                Capability = "discovery"
	CapabilityRuntimeEvidence          Capability = "runtime_evidence"
	CapabilityRemediationPlan          Capability = "remediation_plan"
	CapabilityApprovedRemediation      Capability = "approved_remediation"
	CapabilityAuthorizationAdvisory    Capability = "authorization_advisory"
	CapabilityAuthorizationEnforcement Capability = "authorization_enforcement"
)

var capabilityOrder = []Capability{
	CapabilityDiscovery,
	CapabilityRuntimeEvidence,
	CapabilityRemediationPlan,
	CapabilityApprovedRemediation,
	CapabilityAuthorizationAdvisory,
	CapabilityAuthorizationEnforcement,
}

var knownCapabilities = map[Capability]struct{}{
	CapabilityDiscovery:                {},
	CapabilityRuntimeEvidence:          {},
	CapabilityRemediationPlan:          {},
	CapabilityApprovedRemediation:      {},
	CapabilityAuthorizationAdvisory:    {},
	CapabilityAuthorizationEnforcement: {},
}

// CapabilityUnavailable records a requested connector capability that cannot be
// made effective in the current deployment or validation state.
type CapabilityUnavailable struct {
	Capability  Capability `json:"capability"`
	Reason      string     `json:"reason"`
	Gate        string     `json:"gate,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
}

// DefaultCapabilities returns the read-only capability set every AWS connector
// receives unless the caller requests a narrower or broader future mode.
func DefaultCapabilities() []Capability {
	return []Capability{CapabilityDiscovery}
}

// NormalizeCapabilities removes unknown entries, de-duplicates known entries,
// and returns capabilities in stable product order. An empty request falls back
// to discovery so legacy clients stay read-only by default.
func NormalizeCapabilities(values []Capability) []Capability {
	if len(values) == 0 {
		return DefaultCapabilities()
	}

	seen := map[Capability]struct{}{}
	for _, value := range values {
		capability := Capability(strings.ToLower(strings.TrimSpace(string(value))))
		if _, ok := knownCapabilities[capability]; !ok {
			continue
		}
		seen[capability] = struct{}{}
	}
	if len(seen) == 0 {
		return DefaultCapabilities()
	}

	normalized := make([]Capability, 0, len(seen))
	for _, capability := range capabilityOrder {
		if _, ok := seen[capability]; ok {
			normalized = append(normalized, capability)
		}
	}
	return normalized
}

// EmptyCapabilities returns a non-nil empty capability slice for metadata and
// API responses where defaulting to discovery would be misleading.
func EmptyCapabilities() []Capability {
	return []Capability{}
}

// CopyUnavailableCapabilities returns a non-nil defensive copy for status
// responses.
func CopyUnavailableCapabilities(values []CapabilityUnavailable) []CapabilityUnavailable {
	if len(values) == 0 {
		return []CapabilityUnavailable{}
	}
	copied := make([]CapabilityUnavailable, len(values))
	copy(copied, values)
	return copied
}

// IsDiscoveryCapability reports whether the capability is covered by the
// current read-only CloudFormation policy and validation flow.
func IsDiscoveryCapability(capability Capability) bool {
	return capability == CapabilityDiscovery
}
