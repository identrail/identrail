package providers

import (
	"context"

	"github.com/identrail/identrail/internal/domain"
)

// RawAsset is a provider-native JSON payload captured during read-only collection.
type RawAsset struct {
	Kind      string
	SourceID  string
	Payload   []byte
	Collected string
}

// Collector pulls raw assets from a source provider (AWS, Kubernetes, Azure).
// This interface ensures provider abstraction for scalability and testability.
type Collector interface {
	Collect(ctx context.Context) ([]RawAsset, error)
}

// Normalizer transforms provider-native assets into provider-agnostic domain records.
type Normalizer interface {
	Normalize(ctx context.Context, raw []RawAsset) (NormalizedBundle, error)
}

// PermissionResolver expands policies into concrete permission tuples.
type PermissionResolver interface {
	ResolvePermissions(ctx context.Context, bundle NormalizedBundle) ([]PermissionTuple, error)
}

// RelationshipResolver builds graph edges from normalized assets and permissions.
type RelationshipResolver interface {
	ResolveRelationships(ctx context.Context, bundle NormalizedBundle, perms []PermissionTuple) ([]domain.Relationship, error)
}

// RiskRuleSet executes deterministic risk checks over normalized data and relationships.
type RiskRuleSet interface {
	Evaluate(ctx context.Context, bundle NormalizedBundle, relationships []domain.Relationship) ([]domain.Finding, error)
}

// NormalizedBundle contains all normalized entities produced in one pass.
type NormalizedBundle struct {
	Identities []domain.Identity
	Workloads  []domain.Workload
	Policies   []domain.Policy
}

// PermissionTuple is a semantic permission unit used for graph and rule evaluation.
type PermissionTuple struct {
	IdentityID string
	Action     string
	Resource   string
	Effect     string
}
