package domain

import (
	"testing"
	"time"
)

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

func TestResourceValidate(t *testing.T) {
	valid := Resource{
		ID:       "arn:aws:s3:::bucket-a",
		Provider: ProviderAWS,
		Type:     ResourceTypeS3Bucket,
		Name:     "bucket-a",
	}
	if !valid.Validate() {
		t.Fatal("expected valid resource")
	}
	invalid := Resource{ID: "", Provider: ProviderAWS, Type: ResourceTypeS3Bucket, Name: "bucket-a"}
	if invalid.Validate() {
		t.Fatal("expected invalid resource")
	}
}

func TestCredentialValidate(t *testing.T) {
	valid := Credential{
		ID:       "cred-1",
		Provider: ProviderAWS,
		Type:     CredentialTypeAccessKey,
		Name:     "ci-key",
	}
	if !valid.Validate() {
		t.Fatal("expected valid credential")
	}
	invalid := Credential{ID: "cred-2", Type: CredentialTypeAccessKey, Name: "ci-key"}
	if invalid.Validate() {
		t.Fatal("expected invalid credential")
	}
}

func TestAgentValidate(t *testing.T) {
	valid := Agent{
		ID:       "agent-1",
		Provider: ProviderAWS,
		Type:     AgentTypeAI,
		Name:     "reviewer",
	}
	if !valid.Validate() {
		t.Fatal("expected valid agent")
	}
	invalid := Agent{ID: "agent-2", Provider: ProviderAWS, Name: "reviewer"}
	if invalid.Validate() {
		t.Fatal("expected invalid agent")
	}
}

func TestRuntimeEventValidate(t *testing.T) {
	valid := RuntimeEvent{
		ID:         "event-1",
		Provider:   ProviderAWS,
		Type:       RuntimeEventTypeRuntimeSession,
		ActorID:    "aws:identity:role/demo",
		SourceRef:  "source-1",
		ObservedAt: time.Now().UTC(),
	}
	if !valid.Validate() {
		t.Fatal("expected valid runtime event")
	}
	invalid := RuntimeEvent{ID: "event-2", Provider: ProviderAWS, Type: RuntimeEventTypeRuntimeSession, ActorID: "actor", SourceRef: "source", ObservedAt: time.Time{}}
	if invalid.Validate() {
		t.Fatal("expected invalid runtime event")
	}
}
