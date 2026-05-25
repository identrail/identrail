package domain

import (
	"fmt"
	"sort"
)

// ConnectorCapability enumerates the typed permission tiers a connector can be
// granted. The default machine-identity connector is intentionally read-only
// (discovery). Higher tiers are modeled explicitly so write-capable behavior is
// never blended into the read-only path.
type ConnectorCapability string

const (
	// ConnectorCapabilityDiscovery is the read-only baseline: inventory and graph
	// collection. It is always available and is the default for every connector.
	ConnectorCapabilityDiscovery ConnectorCapability = "discovery"
	// ConnectorCapabilityRuntimeEvidence reads runtime activity (access analyzer,
	// CloudTrail, last-used data) to enrich findings. Read-only.
	ConnectorCapabilityRuntimeEvidence ConnectorCapability = "runtime_evidence"
	// ConnectorCapabilityRemediationPlan generates proposed fixes without applying
	// them. Read-only: it simulates and diffs, it does not mutate.
	ConnectorCapabilityRemediationPlan ConnectorCapability = "remediation_plan"
	// ConnectorCapabilityApprovedRemediation applies approved fixes to the account.
	// Write-capable.
	ConnectorCapabilityApprovedRemediation ConnectorCapability = "approved_remediation"
	// ConnectorCapabilityAuthorizationAdvisory brokers advisory authorization
	// decisions (recommendations only). Read-only.
	ConnectorCapabilityAuthorizationAdvisory ConnectorCapability = "authorization_advisory"
	// ConnectorCapabilityAuthorizationEnforcement applies authorization decisions
	// such as session policies, SCPs, or permission boundaries. Write-capable.
	ConnectorCapabilityAuthorizationEnforcement ConnectorCapability = "authorization_enforcement"
)

// ConnectorCapabilityTier classifies a capability by blast radius.
type ConnectorCapabilityTier string

const (
	// ConnectorCapabilityTierReadOnly describes capabilities that never mutate the
	// connected account.
	ConnectorCapabilityTierReadOnly ConnectorCapabilityTier = "read_only"
	// ConnectorCapabilityTierWrite describes capabilities that can mutate the
	// connected account and therefore require explicit enablement.
	ConnectorCapabilityTierWrite ConnectorCapabilityTier = "write"
)

// connectorCapabilityOrder is the canonical low-to-high privilege ordering used
// for stable, deterministic output.
var connectorCapabilityOrder = []ConnectorCapability{
	ConnectorCapabilityDiscovery,
	ConnectorCapabilityRuntimeEvidence,
	ConnectorCapabilityRemediationPlan,
	ConnectorCapabilityAuthorizationAdvisory,
	ConnectorCapabilityApprovedRemediation,
	ConnectorCapabilityAuthorizationEnforcement,
}

var connectorCapabilityRank = func() map[ConnectorCapability]int {
	ranks := make(map[ConnectorCapability]int, len(connectorCapabilityOrder))
	for index, capability := range connectorCapabilityOrder {
		ranks[capability] = index
	}
	return ranks
}()

// ConnectorCapabilityOrder returns capabilities in canonical privilege order.
func ConnectorCapabilityOrder() []ConnectorCapability {
	out := make([]ConnectorCapability, len(connectorCapabilityOrder))
	copy(out, connectorCapabilityOrder)
	return out
}

// DefaultConnectorCapabilities returns the read-only baseline granted to every
// connector unless higher tiers are explicitly requested and permitted.
func DefaultConnectorCapabilities() []ConnectorCapability {
	return []ConnectorCapability{ConnectorCapabilityDiscovery}
}

// ValidConnectorCapability reports whether the capability is a known tier.
func ValidConnectorCapability(capability ConnectorCapability) bool {
	_, ok := connectorCapabilityRank[capability]
	return ok
}

// IsWriteCapable reports whether enabling the capability allows mutating the
// connected account. Write-capable tiers must never be granted implicitly.
func (c ConnectorCapability) IsWriteCapable() bool {
	switch c {
	case ConnectorCapabilityApprovedRemediation, ConnectorCapabilityAuthorizationEnforcement:
		return true
	default:
		return false
	}
}

// Tier returns the blast-radius classification for the capability.
func (c ConnectorCapability) Tier() ConnectorCapabilityTier {
	if c.IsWriteCapable() {
		return ConnectorCapabilityTierWrite
	}
	return ConnectorCapabilityTierReadOnly
}

// NormalizeConnectorCapabilities validates, de-duplicates, and canonically
// orders a requested capability set. Discovery is always included because it is
// the read-only baseline every connector retains. Unknown capabilities are an
// error so callers cannot silently request undefined tiers.
func NormalizeConnectorCapabilities(requested []ConnectorCapability) ([]ConnectorCapability, error) {
	seen := map[ConnectorCapability]bool{ConnectorCapabilityDiscovery: true}
	for _, capability := range requested {
		if !ValidConnectorCapability(capability) {
			return nil, fmt.Errorf("connector capability %q is invalid", capability)
		}
		seen[capability] = true
	}
	return sortedCapabilities(seen), nil
}

// CapabilityGate decides whether a capability may be enabled for a connector and,
// when it may not, explains why. Implementations live at the policy/feature-flag
// boundary so the domain stays free of configuration concerns.
type CapabilityGate interface {
	// CapabilityAllowed reports whether the capability is permitted. When it is
	// not, the returned reason explains why so diagnostics can name the tier.
	CapabilityAllowed(capability ConnectorCapability) (allowed bool, reason string)
}

// ConnectorCapabilityUnavailable records a requested capability that could not be
// granted, along with the reason and its tier so callers can surface a precise
// diagnostic rather than a generic connector failure.
type ConnectorCapabilityUnavailable struct {
	Capability ConnectorCapability     `json:"capability"`
	Tier       ConnectorCapabilityTier `json:"tier"`
	Reason     string                  `json:"reason"`
}

// ConnectorCapabilityResolution captures the lifecycle of a capability request:
// what was asked for, what the gate validated as permitted, what is effectively
// in force, and which requested tiers were rejected and why.
type ConnectorCapabilityResolution struct {
	Requested   []ConnectorCapability            `json:"requested"`
	Validated   []ConnectorCapability            `json:"validated"`
	Effective   []ConnectorCapability            `json:"effective"`
	Unavailable []ConnectorCapabilityUnavailable `json:"unavailable,omitempty"`
}

// ResolveConnectorCapabilities computes the validated, effective, and unavailable
// sets for a requested capability list against a gate. Discovery is always
// requested and always effective (read-only baseline). A requested capability is
// validated only when the gate permits it; rejected tiers are reported as
// unavailable with the gate's reason. Effective never exceeds validated, so a
// write-capable tier can never be granted unless the gate explicitly allows it.
func ResolveConnectorCapabilities(requested []ConnectorCapability, gate CapabilityGate) (ConnectorCapabilityResolution, error) {
	normalizedRequested, err := NormalizeConnectorCapabilities(requested)
	if err != nil {
		return ConnectorCapabilityResolution{}, err
	}

	validated := map[ConnectorCapability]bool{}
	unavailable := make([]ConnectorCapabilityUnavailable, 0)
	for _, capability := range normalizedRequested {
		if capability == ConnectorCapabilityDiscovery {
			validated[capability] = true
			continue
		}
		allowed, reason := false, "capability policy is not configured"
		if gate != nil {
			allowed, reason = gate.CapabilityAllowed(capability)
		}
		if allowed {
			validated[capability] = true
			continue
		}
		if reason == "" {
			reason = fmt.Sprintf("capability %q is not enabled for this deployment", capability)
		}
		unavailable = append(unavailable, ConnectorCapabilityUnavailable{
			Capability: capability,
			Tier:       capability.Tier(),
			Reason:     reason,
		})
	}

	effective := sortedCapabilities(validated)
	return ConnectorCapabilityResolution{
		Requested:   normalizedRequested,
		Validated:   effective,
		Effective:   effective,
		Unavailable: unavailable,
	}, nil
}

func sortedCapabilities(set map[ConnectorCapability]bool) []ConnectorCapability {
	out := make([]ConnectorCapability, 0, len(set))
	for capability := range set {
		out = append(out, capability)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return connectorCapabilityRank[out[i]] < connectorCapabilityRank[out[j]]
	})
	return out
}
