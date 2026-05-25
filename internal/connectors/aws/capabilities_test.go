package aws

import (
	"testing"

	"github.com/identrail/identrail/internal/domain"
)

func TestCapabilityPermissionTiersCoverAllCapabilities(t *testing.T) {
	tiers := CapabilityPermissionTiers()
	if len(tiers) != len(domain.ConnectorCapabilityOrder()) {
		t.Fatalf("expected one tier per capability, got %d tiers for %d capabilities", len(tiers), len(domain.ConnectorCapabilityOrder()))
	}

	seen := map[domain.ConnectorCapability]bool{}
	for index, tier := range tiers {
		if tier.Capability != domain.ConnectorCapabilityOrder()[index] {
			t.Fatalf("tier %d capability = %q, want canonical order %q", index, tier.Capability, domain.ConnectorCapabilityOrder()[index])
		}
		seen[tier.Capability] = true
		if tier.Tier != tier.Capability.Tier() {
			t.Fatalf("tier classification for %q = %q, want %q", tier.Capability, tier.Tier, tier.Capability.Tier())
		}
		if len(tier.Permissions) == 0 {
			t.Fatalf("tier %q has no permissions", tier.Capability)
		}
	}
	for _, capability := range domain.ConnectorCapabilityOrder() {
		if !seen[capability] {
			t.Fatalf("capability %q missing from permission tiers", capability)
		}
	}
}

func TestCapabilityPermissionTiersOnlyDiscoveryAvailable(t *testing.T) {
	for _, tier := range CapabilityPermissionTiers() {
		wantAvailable := tier.Capability == domain.ConnectorCapabilityDiscovery
		if tier.Available != wantAvailable {
			t.Fatalf("capability %q available = %v, want %v", tier.Capability, tier.Available, wantAvailable)
		}
	}
}

func TestDiscoveryTierMatchesReadOnlyPreview(t *testing.T) {
	tiers := CapabilityPermissionTiers()
	if tiers[0].Capability != domain.ConnectorCapabilityDiscovery {
		t.Fatalf("expected discovery first, got %q", tiers[0].Capability)
	}
	if len(tiers[0].Permissions) != len(PermissionPreview()) {
		t.Fatalf("discovery tier permissions = %d, want read-only preview length %d", len(tiers[0].Permissions), len(PermissionPreview()))
	}
}

func TestDefaultCapabilityPolicyAllowsOnlyDiscovery(t *testing.T) {
	policy := DefaultCapabilityPolicy()
	if allowed, _ := policy.CapabilityAllowed(domain.ConnectorCapabilityDiscovery); !allowed {
		t.Fatal("discovery must always be allowed")
	}
	for _, capability := range domain.ConnectorCapabilityOrder() {
		if capability == domain.ConnectorCapabilityDiscovery {
			continue
		}
		allowed, reason := policy.CapabilityAllowed(capability)
		if allowed {
			t.Fatalf("capability %q should be denied by default", capability)
		}
		if reason == "" {
			t.Fatalf("capability %q denial must include a reason", capability)
		}
	}
}

func TestNewCapabilityPolicyEnablesReadOnlyTierButGatesWrite(t *testing.T) {
	policy := NewCapabilityPolicy([]domain.ConnectorCapability{
		domain.ConnectorCapabilityRuntimeEvidence,
		"bogus",
	})
	if allowed, _ := policy.CapabilityAllowed(domain.ConnectorCapabilityRuntimeEvidence); !allowed {
		t.Fatal("runtime_evidence should be allowed once enabled")
	}
	// Unknown entries must be ignored, not silently widen access.
	if allowed, _ := policy.CapabilityAllowed(domain.ConnectorCapability("bogus")); allowed {
		t.Fatal("unknown capability must never be allowed")
	}
	// Write tiers stay gated unless explicitly enabled.
	if allowed, reason := policy.CapabilityAllowed(domain.ConnectorCapabilityApprovedRemediation); allowed || reason == "" {
		t.Fatalf("approved_remediation should remain gated, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestCapabilityPolicyEnabledOrdered(t *testing.T) {
	policy := NewCapabilityPolicy([]domain.ConnectorCapability{
		domain.ConnectorCapabilityApprovedRemediation,
		domain.ConnectorCapabilityRuntimeEvidence,
	})
	enabled := policy.Enabled()
	want := []domain.ConnectorCapability{
		domain.ConnectorCapabilityDiscovery,
		domain.ConnectorCapabilityRuntimeEvidence,
		domain.ConnectorCapabilityApprovedRemediation,
	}
	if len(enabled) != len(want) {
		t.Fatalf("enabled = %v, want %v", enabled, want)
	}
	for i := range want {
		if enabled[i] != want[i] {
			t.Fatalf("enabled[%d] = %q, want %q", i, enabled[i], want[i])
		}
	}
}
