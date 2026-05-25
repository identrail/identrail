package domain

import (
	"reflect"
	"testing"
)

type stubCapabilityGate struct {
	allow  map[ConnectorCapability]bool
	reason string
}

func (g stubCapabilityGate) CapabilityAllowed(capability ConnectorCapability) (bool, string) {
	if g.allow[capability] {
		return true, ""
	}
	return false, g.reason
}

func TestValidConnectorCapability(t *testing.T) {
	for _, capability := range ConnectorCapabilityOrder() {
		if !ValidConnectorCapability(capability) {
			t.Fatalf("expected %q to be valid", capability)
		}
	}
	if ValidConnectorCapability(ConnectorCapability("nonsense")) {
		t.Fatal("expected unknown capability to be invalid")
	}
}

func TestCapabilityWriteClassification(t *testing.T) {
	readOnly := []ConnectorCapability{
		ConnectorCapabilityDiscovery,
		ConnectorCapabilityRuntimeEvidence,
		ConnectorCapabilityRemediationPlan,
		ConnectorCapabilityAuthorizationAdvisory,
	}
	for _, capability := range readOnly {
		if capability.IsWriteCapable() {
			t.Fatalf("expected %q to be read-only", capability)
		}
		if capability.Tier() != ConnectorCapabilityTierReadOnly {
			t.Fatalf("expected %q tier read_only, got %q", capability, capability.Tier())
		}
	}
	write := []ConnectorCapability{
		ConnectorCapabilityApprovedRemediation,
		ConnectorCapabilityAuthorizationEnforcement,
	}
	for _, capability := range write {
		if !capability.IsWriteCapable() {
			t.Fatalf("expected %q to be write-capable", capability)
		}
		if capability.Tier() != ConnectorCapabilityTierWrite {
			t.Fatalf("expected %q tier write, got %q", capability, capability.Tier())
		}
	}
}

func TestDefaultConnectorCapabilitiesIsDiscoveryOnly(t *testing.T) {
	got := DefaultConnectorCapabilities()
	want := []ConnectorCapability{ConnectorCapabilityDiscovery}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default capabilities = %v, want %v", got, want)
	}
}

func TestNormalizeConnectorCapabilities(t *testing.T) {
	got, err := NormalizeConnectorCapabilities([]ConnectorCapability{
		ConnectorCapabilityApprovedRemediation,
		ConnectorCapabilityDiscovery,
		ConnectorCapabilityApprovedRemediation,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ConnectorCapability{ConnectorCapabilityDiscovery, ConnectorCapabilityApprovedRemediation}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized = %v, want %v (deduped, discovery-first, canonical order)", got, want)
	}

	if _, err := NormalizeConnectorCapabilities([]ConnectorCapability{"bogus"}); err == nil {
		t.Fatal("expected error for unknown capability")
	}
}

func TestNormalizeAlwaysIncludesDiscovery(t *testing.T) {
	got, err := NormalizeConnectorCapabilities(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []ConnectorCapability{ConnectorCapabilityDiscovery}) {
		t.Fatalf("expected discovery baseline, got %v", got)
	}
}

func TestResolveConnectorCapabilitiesDefaultReadOnly(t *testing.T) {
	resolution, err := ResolveConnectorCapabilities(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ConnectorCapability{ConnectorCapabilityDiscovery}
	if !reflect.DeepEqual(resolution.Effective, want) {
		t.Fatalf("effective = %v, want %v", resolution.Effective, want)
	}
	if !reflect.DeepEqual(resolution.Validated, want) {
		t.Fatalf("validated = %v, want %v", resolution.Validated, want)
	}
	if len(resolution.Unavailable) != 0 {
		t.Fatalf("expected no unavailable capabilities, got %v", resolution.Unavailable)
	}
}

func TestResolveConnectorCapabilitiesNilGateRejectsWriteCapabilities(t *testing.T) {
	resolution, err := ResolveConnectorCapabilities([]ConnectorCapability{
		ConnectorCapabilityApprovedRemediation,
		ConnectorCapabilityRuntimeEvidence,
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ConnectorCapability{ConnectorCapabilityDiscovery}
	if !reflect.DeepEqual(resolution.Effective, want) {
		t.Fatalf("effective = %v, want %v", resolution.Effective, want)
	}
	if !reflect.DeepEqual(resolution.Validated, want) {
		t.Fatalf("validated = %v, want %v", resolution.Validated, want)
	}
	if len(resolution.Unavailable) != 2 {
		t.Fatalf("expected two unavailable capabilities, got %v", resolution.Unavailable)
	}
	unavailable := map[ConnectorCapability]bool{}
	for _, item := range resolution.Unavailable {
		unavailable[item.Capability] = true
		if item.Reason == "" {
			t.Fatalf("expected reason for unavailable capability %q", item.Capability)
		}
	}
	if !unavailable[ConnectorCapabilityApprovedRemediation] || !unavailable[ConnectorCapabilityRuntimeEvidence] {
		t.Fatalf("unexpected unavailable capabilities: %v", resolution.Unavailable)
	}
}

func TestResolveConnectorCapabilitiesGatesWriteTier(t *testing.T) {
	gate := stubCapabilityGate{
		allow:  map[ConnectorCapability]bool{ConnectorCapabilityRuntimeEvidence: true},
		reason: "feature flag disabled",
	}
	resolution, err := ResolveConnectorCapabilities([]ConnectorCapability{
		ConnectorCapabilityRuntimeEvidence,
		ConnectorCapabilityApprovedRemediation,
	}, gate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantEffective := []ConnectorCapability{ConnectorCapabilityDiscovery, ConnectorCapabilityRuntimeEvidence}
	if !reflect.DeepEqual(resolution.Effective, wantEffective) {
		t.Fatalf("effective = %v, want %v", resolution.Effective, wantEffective)
	}
	if len(resolution.Unavailable) != 1 {
		t.Fatalf("expected one unavailable capability, got %v", resolution.Unavailable)
	}
	unavailable := resolution.Unavailable[0]
	if unavailable.Capability != ConnectorCapabilityApprovedRemediation {
		t.Fatalf("unavailable capability = %q, want approved_remediation", unavailable.Capability)
	}
	if unavailable.Tier != ConnectorCapabilityTierWrite {
		t.Fatalf("unavailable tier = %q, want write", unavailable.Tier)
	}
	if unavailable.Reason != "feature flag disabled" {
		t.Fatalf("unavailable reason = %q, want gate reason", unavailable.Reason)
	}
}

func TestResolveConnectorCapabilitiesRejectsInvalid(t *testing.T) {
	if _, err := ResolveConnectorCapabilities([]ConnectorCapability{"bogus"}, nil); err == nil {
		t.Fatal("expected error for invalid requested capability")
	}
}
