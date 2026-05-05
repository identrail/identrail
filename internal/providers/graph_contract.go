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
	for _, identity := range bundle.Identities {
		identityIDs[identity.ID] = struct{}{}
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

		if err := validateRelationshipEndpoints(relationship, identityIDs, workloadIDs, policyIDs); err != nil {
			return err
		}
	}
	return nil
}

func validateRelationshipEndpoints(
	relationship domain.Relationship,
	identityIDs map[string]struct{},
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
		if strings.HasPrefix(relationship.ToNodeID, "aws:access:") || strings.HasPrefix(relationship.ToNodeID, "k8s:access:") {
			return nil
		}
		return fmt.Errorf("can_access relationship %q has invalid access node %q", relationship.ID, relationship.ToNodeID)
	default:
		return fmt.Errorf("unsupported relationship type %q", relationship.Type)
	}
	return nil
}
