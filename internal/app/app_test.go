package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

type stubCollector struct{ err error }
type stubDiagnosticCollector struct {
	raw    []providers.RawAsset
	issues []providers.SourceError
	err    error
}
type stubNormalizer struct{ err error }
type stubPermResolver struct{ err error }
type stubRelResolver struct{ err error }
type stubRules struct{ err error }
type fixedNormalizer struct {
	bundle providers.NormalizedBundle
	err    error
}
type fixedRelResolver struct {
	relationships []domain.Relationship
	err           error
}

func (s stubCollector) Collect(context.Context) ([]providers.RawAsset, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []providers.RawAsset{{Kind: "role", SourceID: "r1"}}, nil
}

func (s stubDiagnosticCollector) Collect(context.Context) ([]providers.RawAsset, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.raw, nil
}

func (s stubDiagnosticCollector) CollectWithDiagnostics(context.Context) ([]providers.RawAsset, []providers.SourceError, error) {
	if s.err != nil {
		return nil, nil, s.err
	}
	return s.raw, s.issues, nil
}

func (s stubNormalizer) Normalize(context.Context, []providers.RawAsset) (providers.NormalizedBundle, error) {
	if s.err != nil {
		return providers.NormalizedBundle{}, s.err
	}
	return providers.NormalizedBundle{
		Identities: []domain.Identity{{
			ID:       "id1",
			Provider: domain.ProviderAWS,
			Type:     domain.IdentityTypeRole,
			Name:     "role-a",
		}},
	}, nil
}

func (s fixedNormalizer) Normalize(context.Context, []providers.RawAsset) (providers.NormalizedBundle, error) {
	if s.err != nil {
		return providers.NormalizedBundle{}, s.err
	}
	return s.bundle, nil
}

func (s stubPermResolver) ResolvePermissions(context.Context, providers.NormalizedBundle) ([]providers.PermissionTuple, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []providers.PermissionTuple{{IdentityID: "id1", Action: "*", Resource: "*", Effect: "Allow"}}, nil
}

func (s stubRelResolver) ResolveRelationships(context.Context, providers.NormalizedBundle, []providers.PermissionTuple) ([]domain.Relationship, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []domain.Relationship{{
		ID:           "rel1",
		Type:         domain.RelationshipCanAccess,
		FromNodeID:   "id1",
		ToNodeID:     "aws:access:s3%3AGetObject:%2A",
		DiscoveredAt: time.Date(2026, 3, 19, 10, 0, 0, 0, time.UTC),
	}}, nil
}

func (s fixedRelResolver) ResolveRelationships(context.Context, providers.NormalizedBundle, []providers.PermissionTuple) ([]domain.Relationship, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.relationships, nil
}

func (s stubRules) Evaluate(context.Context, providers.NormalizedBundle, []domain.Relationship) ([]domain.Finding, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []domain.Finding{{ID: "f1", Type: domain.FindingOverPrivileged, Severity: domain.SeverityHigh, Title: "overprivileged"}}, nil
}

func TestScannerRunSuccess(t *testing.T) {
	scanner := Scanner{
		Collector:            stubCollector{},
		Normalizer:           stubNormalizer{},
		PermissionResolver:   stubPermResolver{},
		RelationshipResolver: stubRelResolver{},
		RiskRuleSet:          stubRules{},
	}

	result, err := scanner.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if result.Assets != 1 {
		t.Fatalf("expected 1 asset, got %d", result.Assets)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestScannerRunWithCollectorDiagnostics(t *testing.T) {
	scanner := Scanner{
		Collector: stubDiagnosticCollector{
			raw: []providers.RawAsset{{Kind: "role", SourceID: "r1"}},
			issues: []providers.SourceError{{
				Collector: "stub",
				Code:      "partial",
				Message:   "non-fatal",
			}},
		},
		Normalizer:           stubNormalizer{},
		PermissionResolver:   stubPermResolver{},
		RelationshipResolver: stubRelResolver{},
		RiskRuleSet:          stubRules{},
	}

	result, err := scanner.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(result.SourceErrors) != 1 {
		t.Fatalf("expected 1 source error, got %+v", result.SourceErrors)
	}
}

func TestScannerRunFailureStages(t *testing.T) {
	tests := []struct {
		name    string
		scanner Scanner
	}{
		{
			name: "collector",
			scanner: Scanner{
				Collector:            stubCollector{err: errors.New("collector err")},
				Normalizer:           stubNormalizer{},
				PermissionResolver:   stubPermResolver{},
				RelationshipResolver: stubRelResolver{},
				RiskRuleSet:          stubRules{},
			},
		},
		{
			name: "normalizer",
			scanner: Scanner{
				Collector:            stubCollector{},
				Normalizer:           stubNormalizer{err: errors.New("normalizer err")},
				PermissionResolver:   stubPermResolver{},
				RelationshipResolver: stubRelResolver{},
				RiskRuleSet:          stubRules{},
			},
		},
		{
			name: "permission resolver",
			scanner: Scanner{
				Collector:            stubCollector{},
				Normalizer:           stubNormalizer{},
				PermissionResolver:   stubPermResolver{err: errors.New("permission err")},
				RelationshipResolver: stubRelResolver{},
				RiskRuleSet:          stubRules{},
			},
		},
		{
			name: "relationship resolver",
			scanner: Scanner{
				Collector:            stubCollector{},
				Normalizer:           stubNormalizer{},
				PermissionResolver:   stubPermResolver{},
				RelationshipResolver: stubRelResolver{err: errors.New("relationship err")},
				RiskRuleSet:          stubRules{},
			},
		},
		{
			name: "risk rules",
			scanner: Scanner{
				Collector:            stubCollector{},
				Normalizer:           stubNormalizer{},
				PermissionResolver:   stubPermResolver{},
				RelationshipResolver: stubRelResolver{},
				RiskRuleSet:          stubRules{err: errors.New("rules err")},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.scanner.Run(context.Background()); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestScannerRunFailsOnInvalidNormalizedBundle(t *testing.T) {
	scanner := Scanner{
		Collector: stubCollector{},
		Normalizer: fixedNormalizer{
			bundle: providers.NormalizedBundle{
				Identities: []domain.Identity{{
					ID:       "id-1",
					Provider: domain.ProviderAWS,
					Type:     domain.IdentityTypeRole,
					Name:     "",
				}},
			},
		},
		PermissionResolver:   stubPermResolver{},
		RelationshipResolver: stubRelResolver{},
		RiskRuleSet:          stubRules{},
	}

	if _, err := scanner.Run(context.Background()); err == nil {
		t.Fatal("expected normalized bundle validation error")
	}
}

func TestScannerRunFailsOnInvalidGraphContract(t *testing.T) {
	identityID := "aws:identity:arn:aws:iam::123456789012:role/demo"
	scanner := Scanner{
		Collector: stubCollector{},
		Normalizer: fixedNormalizer{
			bundle: providers.NormalizedBundle{
				Identities: []domain.Identity{{
					ID:       identityID,
					Provider: domain.ProviderAWS,
					Type:     domain.IdentityTypeRole,
					Name:     "demo",
				}},
			},
		},
		PermissionResolver: stubPermResolver{},
		RelationshipResolver: fixedRelResolver{
			relationships: []domain.Relationship{{
				ID:           "rel-1",
				Type:         domain.RelationshipCanAccess,
				FromNodeID:   identityID,
				ToNodeID:     "invalid-access-node",
				DiscoveredAt: time.Date(2026, 3, 19, 10, 0, 0, 0, time.UTC),
			}},
		},
		RiskRuleSet: stubRules{},
	}

	if _, err := scanner.Run(context.Background()); err == nil {
		t.Fatal("expected graph contract validation error")
	}
}
