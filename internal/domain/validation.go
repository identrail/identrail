package domain

import "strings"

// IsSupportedRelationshipType reports whether the relationship semantic is part
// of the v1 graph contract.
func IsSupportedRelationshipType(rel RelationshipType) bool {
	_, ok := RelationshipContractFor(rel)
	return ok
}

// Validate ensures the identity has enough information for deduplication and graph linking.
func (i Identity) Validate() bool {
	return i.ID != "" && i.Provider != "" && i.Type != "" && strings.TrimSpace(i.Name) != ""
}

// Validate ensures relationships remain queryable and directionally consistent.
func (r Relationship) Validate() bool {
	return r.ID != "" && IsSupportedRelationshipType(r.Type) && r.FromNodeID != "" && r.ToNodeID != ""
}

// Validate ensures findings are actionable and correctly categorized.
func (f Finding) Validate() bool {
	return f.ID != "" && f.Type != "" && f.Severity != "" && strings.TrimSpace(f.Title) != ""
}

// Validate ensures resources are usable as first-class scan nodes.
func (r Resource) Validate() bool {
	return strings.TrimSpace(r.ID) != "" && strings.TrimSpace(string(r.Provider)) != "" &&
		strings.TrimSpace(string(r.Type)) != "" && strings.TrimSpace(r.Name) != ""
}

// Validate ensures credentials carry identity metadata without secret payloads.
func (c Credential) Validate() bool {
	return strings.TrimSpace(c.ID) != "" && strings.TrimSpace(string(c.Provider)) != "" &&
		strings.TrimSpace(string(c.Type)) != "" && strings.TrimSpace(c.Name) != ""
}

// Validate ensures agent nodes are addressable and provider-native.
func (a Agent) Validate() bool {
	return strings.TrimSpace(a.ID) != "" && strings.TrimSpace(string(a.Provider)) != "" &&
		strings.TrimSpace(string(a.Type)) != "" && strings.TrimSpace(a.Name) != ""
}

// Validate ensures runtime events are safe and linkable in graph contracts.
func (e RuntimeEvent) Validate() bool {
	return strings.TrimSpace(e.ID) != "" && strings.TrimSpace(string(e.Provider)) != "" &&
		strings.TrimSpace(string(e.Type)) != "" && strings.TrimSpace(e.ActorID) != "" &&
		strings.TrimSpace(e.SourceRef) != "" && !e.ObservedAt.IsZero()
}
