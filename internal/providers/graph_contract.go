package providers

import (
	"fmt"
	"strings"

	"github.com/identrail/identrail/internal/domain"
)

// ValidateGraphContract enforces edge integrity and relationship consistency
// across normalized entities and graph edges.
func ValidateGraphContract(bundle NormalizedBundle, relationships []domain.Relationship) error {
	identityIDs := map[string]struct{}{}
	identityTypes := map[string]domain.IdentityType{}
	for _, identity := range bundle.Identities {
		identityIDs[identity.ID] = struct{}{}
		identityTypes[identity.ID] = identity.Type
	}
	workloadIDs := map[string]struct{}{}
	for _, workload := range bundle.Workloads {
		workloadIDs[workload.ID] = struct{}{}
	}
	policyIDs := map[string]struct{}{}
	for _, policy := range bundle.Policies {
		policyIDs[policy.ID] = struct{}{}
	}

	seenRelationshipIDs := map[string]struct{}{}
	seenSemantics := map[string]struct{}{}
	for i, relationship := range relationships {
		if !relationship.Validate() {
			return fmt.Errorf("invalid relationship at index %d", i)
		}
		if relationship.DiscoveredAt.IsZero() {
			return fmt.Errorf("relationship %q missing discovered_at", relationship.ID)
		}
		if _, exists := seenRelationshipIDs[relationship.ID]; exists {
			return fmt.Errorf("duplicate relationship id %q", relationship.ID)
		}
		seenRelationshipIDs[relationship.ID] = struct{}{}

		semanticKey := strings.Join([]string{string(relationship.Type), relationship.FromNodeID, relationship.ToNodeID}, "|")
		if _, exists := seenSemantics[semanticKey]; exists {
			return fmt.Errorf("duplicate relationship semantic %q", semanticKey)
		}
		seenSemantics[semanticKey] = struct{}{}

		if err := validateRelationshipEndpoints(relationship, identityIDs, identityTypes, workloadIDs, policyIDs); err != nil {
			return err
		}
	}
	return nil
}

func validateRelationshipEndpoints(
	relationship domain.Relationship,
	identityIDs map[string]struct{},
	identityTypes map[string]domain.IdentityType,
	workloadIDs map[string]struct{},
	policyIDs map[string]struct{},
) error {
	hasIdentity := func(id string) bool {
		_, ok := identityIDs[id]
		return ok
	}
	hasWorkload := func(id string) bool {
		_, ok := workloadIDs[id]
		return ok
	}
	hasPolicy := func(id string) bool {
		_, ok := policyIDs[id]
		return ok
	}
	hasIdentityType := func(id string, identityType domain.IdentityType) bool {
		got, ok := identityTypes[id]
		return ok && got == identityType
	}
	hasAnyPrefix := func(id string, prefixes ...string) bool {
		for _, prefix := range prefixes {
			if strings.HasPrefix(id, prefix) {
				return true
			}
		}
		return false
	}
	hasAgent := func(id string) bool {
		return hasAnyPrefix(id, "agent:", "ai:agent:", "aws:agent:")
	}
	hasActor := func(id string) bool {
		return hasIdentity(id) || hasWorkload(id) || hasAgent(id)
	}
	hasAccessNode := func(id string) bool {
		return hasAnyPrefix(id, "aws:access:", "k8s:access:")
	}
	hasActionNode := func(id string) bool {
		return hasAccessNode(id) || hasAnyPrefix(id, "action:", "aws:action:", "k8s:action:")
	}
	hasSecretNode := func(id string) bool {
		return hasAnyPrefix(id, "secret:", "aws:secret:", "k8s:secret:")
	}
	hasKMSKeyNode := func(id string) bool {
		return hasAnyPrefix(id, "kms:", "aws:kms:")
	}
	hasRuntimeSession := func(id string) bool {
		return hasAnyPrefix(id, "session:", "runtime:session:", "aws:session:", "k8s:session:")
	}
	hasInvocable := func(id string) bool {
		return hasWorkload(id) || hasAnyPrefix(id, "invocable:", "aws:lambda:", "aws:service:", "aws:resource:", "k8s:workload:", "agent:")
	}
	hasTool := func(id string) bool {
		return hasAnyPrefix(id, "tool:", "mcp:tool:", "agent:tool:")
	}

	switch relationship.Type {
	case domain.RelationshipAttachedPolicy:
		if !hasIdentity(relationship.FromNodeID) {
			return fmt.Errorf("attached_policy relationship %q has unknown identity %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasPolicy(relationship.ToNodeID) {
			return fmt.Errorf("attached_policy relationship %q has unknown policy %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipAttachedTo:
		if !hasWorkload(relationship.FromNodeID) {
			return fmt.Errorf("attached_to relationship %q has unknown workload %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasIdentity(relationship.ToNodeID) {
			return fmt.Errorf("attached_to relationship %q has unknown identity %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipBoundTo:
		if !hasWorkload(relationship.FromNodeID) {
			return fmt.Errorf("bound_to relationship %q has unknown workload %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasIdentity(relationship.ToNodeID) {
			return fmt.Errorf("bound_to relationship %q has unknown identity %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipCanAssume:
		if !hasIdentity(relationship.ToNodeID) {
			return fmt.Errorf("can_assume relationship %q has unknown target identity %q", relationship.ID, relationship.ToNodeID)
		}
		if hasIdentity(relationship.FromNodeID) {
			return nil
		}
		if strings.HasPrefix(relationship.FromNodeID, "aws:principal:") {
			return nil
		}
		return fmt.Errorf("can_assume relationship %q has unknown source %q", relationship.ID, relationship.FromNodeID)
	case domain.RelationshipCanImpersonate:
		if !hasIdentity(relationship.ToNodeID) {
			return fmt.Errorf("can_impersonate relationship %q has unknown target identity %q", relationship.ID, relationship.ToNodeID)
		}
		if hasIdentity(relationship.FromNodeID) || hasWorkload(relationship.FromNodeID) {
			return nil
		}
		return fmt.Errorf("can_impersonate relationship %q has unknown source %q", relationship.ID, relationship.FromNodeID)
	case domain.RelationshipCanAccess:
		if !hasIdentity(relationship.FromNodeID) {
			return fmt.Errorf("can_access relationship %q has unknown source identity %q", relationship.ID, relationship.FromNodeID)
		}
		if hasAccessNode(relationship.ToNodeID) {
			return nil
		}
		return fmt.Errorf("can_access relationship %q has invalid access node %q", relationship.ID, relationship.ToNodeID)
	case domain.RelationshipRunsAs:
		if !hasWorkload(relationship.FromNodeID) {
			return fmt.Errorf("runs_as relationship %q has unknown workload %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasIdentity(relationship.ToNodeID) {
			return fmt.Errorf("runs_as relationship %q has unknown target identity %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipUsesSecret:
		if !hasActor(relationship.FromNodeID) {
			return fmt.Errorf("uses_secret relationship %q has unknown source actor %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasSecretNode(relationship.ToNodeID) {
			return fmt.Errorf("uses_secret relationship %q has invalid secret node %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipCanDecrypt:
		if !hasIdentity(relationship.FromNodeID) {
			return fmt.Errorf("can_decrypt relationship %q has unknown source identity %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasKMSKeyNode(relationship.ToNodeID) {
			return fmt.Errorf("can_decrypt relationship %q has invalid key node %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipCanPassRole:
		if !hasIdentity(relationship.FromNodeID) {
			return fmt.Errorf("can_pass_role relationship %q has unknown source identity %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasIdentityType(relationship.ToNodeID, domain.IdentityTypeRole) {
			return fmt.Errorf("can_pass_role relationship %q has unknown target role identity %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipInvokes:
		if !hasActor(relationship.FromNodeID) {
			return fmt.Errorf("invokes relationship %q has unknown source actor %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasInvocable(relationship.ToNodeID) {
			return fmt.Errorf("invokes relationship %q has invalid invocable node %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipCallsTool:
		if !hasActor(relationship.FromNodeID) {
			return fmt.Errorf("calls_tool relationship %q has unknown source actor %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasTool(relationship.ToNodeID) {
			return fmt.Errorf("calls_tool relationship %q has invalid tool node %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipActsForUser:
		if !hasActor(relationship.FromNodeID) {
			return fmt.Errorf("acts_for_user relationship %q has unknown source actor %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasIdentityType(relationship.ToNodeID, domain.IdentityTypeUser) {
			return fmt.Errorf("acts_for_user relationship %q has unknown target user identity %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipRuntimeSession:
		if !hasActor(relationship.FromNodeID) {
			return fmt.Errorf("has_runtime_session relationship %q has unknown source actor %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasRuntimeSession(relationship.ToNodeID) {
			return fmt.Errorf("has_runtime_session relationship %q has invalid runtime session node %q", relationship.ID, relationship.ToNodeID)
		}
	case domain.RelationshipObservedAction:
		if !hasActor(relationship.FromNodeID) && !hasRuntimeSession(relationship.FromNodeID) {
			return fmt.Errorf("observed_action relationship %q has unknown source actor or runtime session %q", relationship.ID, relationship.FromNodeID)
		}
		if !hasActionNode(relationship.ToNodeID) {
			return fmt.Errorf("observed_action relationship %q has invalid action node %q", relationship.ID, relationship.ToNodeID)
		}
	default:
		return fmt.Errorf("unsupported relationship type %q", relationship.Type)
	}
	return nil
}
