package domain

import "testing"

func TestIdentityValidate(t *testing.T) {
	valid := Identity{ID: "1", Provider: ProviderAWS, Type: IdentityTypeRole, Name: "role-a"}
	if !valid.Validate() {
		t.Fatal("expected valid identity")
	}
	invalid := Identity{ID: "1", Provider: ProviderAWS, Type: IdentityTypeRole, Name: "   "}
	if invalid.Validate() {
		t.Fatal("expected invalid identity")
	}
}

func TestRelationshipValidate(t *testing.T) {
	valid := Relationship{ID: "1", Type: RelationshipCanAssume, FromNodeID: "a", ToNodeID: "b"}
	if !valid.Validate() {
		t.Fatal("expected valid relationship")
	}
	invalid := Relationship{ID: "1", Type: RelationshipCanAssume, FromNodeID: "", ToNodeID: "b"}
	if invalid.Validate() {
		t.Fatal("expected invalid relationship")
	}
	invalidType := Relationship{ID: "1", Type: RelationshipType("custom_rel"), FromNodeID: "a", ToNodeID: "b"}
	if invalidType.Validate() {
		t.Fatal("expected invalid relationship type")
	}
}

func TestRelationshipContractSupportsExpandedTypes(t *testing.T) {
	supported := []RelationshipType{
		RelationshipCanAssume,
		RelationshipAttachedPolicy,
		RelationshipAttachedTo,
		RelationshipBoundTo,
		RelationshipCanAccess,
		RelationshipCanImpersonate,
		RelationshipRunsAs,
		RelationshipUsesSecret,
		RelationshipCanDecrypt,
		RelationshipCanPassRole,
		RelationshipInvokes,
		RelationshipCallsTool,
		RelationshipActsForUser,
		RelationshipRuntimeSession,
		RelationshipObservedAction,
	}

	for _, relationshipType := range supported {
		if !IsSupportedRelationshipType(relationshipType) {
			t.Fatalf("expected %s to be supported", relationshipType)
		}
		contract, ok := RelationshipContractFor(relationshipType)
		if !ok {
			t.Fatalf("expected contract for %s", relationshipType)
		}
		if contract.Type != relationshipType || contract.From == "" || contract.To == "" || contract.Evidence == "" {
			t.Fatalf("incomplete contract for %s: %+v", relationshipType, contract)
		}
	}

	if IsSupportedRelationshipType(RelationshipType("custom_rel")) {
		t.Fatal("expected custom relationship to be unsupported")
	}

	contracts := RelationshipContracts()
	contracts[RelationshipRunsAs] = RelationshipContract{}
	contract, ok := RelationshipContractFor(RelationshipRunsAs)
	if !ok || contract.From == "" {
		t.Fatal("expected RelationshipContracts to return a defensive copy")
	}
}

func TestFindingValidate(t *testing.T) {
	valid := Finding{ID: "1", Type: FindingEscalationPath, Severity: SeverityHigh, Title: "Escalation path found"}
	if !valid.Validate() {
		t.Fatal("expected valid finding")
	}
	invalid := Finding{ID: "1", Type: FindingEscalationPath, Severity: SeverityHigh, Title: "  "}
	if invalid.Validate() {
		t.Fatal("expected invalid finding")
	}
}
