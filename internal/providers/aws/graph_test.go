package aws

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

func TestRelationshipBuilderBuildsExpectedEdges(t *testing.T) {
	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{loadRawRoleAssetFixture(t, "role_with_policies.json")})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	permissions, err := NewPolicyPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}

	fixedNow := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	relationships, err := NewRelationshipBuilder(WithRelationshipClock(func() time.Time { return fixedNow })).ResolveRelationships(context.Background(), bundle, permissions)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	var attachedCount, assumeCount, accessCount int
	for _, relationship := range relationships {
		if !relationship.DiscoveredAt.Equal(fixedNow) {
			t.Fatalf("unexpected discovered timestamp: %v", relationship.DiscoveredAt)
		}
		switch relationship.Type {
		case domain.RelationshipAttachedPolicy:
			attachedCount++
		case domain.RelationshipCanAssume:
			assumeCount++
		case domain.RelationshipCanAccess:
			accessCount++
		}
	}

	if attachedCount != 1 {
		t.Fatalf("expected 1 attached policy edge, got %d", attachedCount)
	}
	if assumeCount != 2 {
		t.Fatalf("expected 2 can_assume edges, got %d", assumeCount)
	}
	if accessCount != 3 {
		t.Fatalf("expected 3 can_access edges, got %d", accessCount)
	}
}

func TestRelationshipBuilderMapsKnownPrincipalToIdentity(t *testing.T) {
	roleA := loadRawRoleAssetFixture(t, "role_with_policies.json")
	roleB := providers.RawAsset{
		Kind:     "iam_role",
		SourceID: "arn:aws:iam::123456789012:role/eks-irsa",
		Payload: []byte(`{
			"arn":"arn:aws:iam::123456789012:role/eks-irsa",
			"name":"eks-irsa",
			"assume_role_policy_document":"{\"Version\":\"2012-10-17\",\"Statement\":[]}",
			"permission_policies":[]
		}`),
	}

	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{roleA, roleB})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	expectedFrom := identityIDFromARN("arn:aws:iam::123456789012:role/eks-irsa")
	found := false
	for _, relationship := range relationships {
		if relationship.Type == domain.RelationshipCanAssume && relationship.FromNodeID == expectedFrom {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected trust relationship from known principal identity")
	}
}

func TestRelationshipBuilderDeterministicAcrossShuffledRawAssetInput(t *testing.T) {
	roleA := loadRawRoleAssetFixture(t, "role_with_policies.json")
	roleB := providers.RawAsset{
		Kind:     "iam_role",
		SourceID: "arn:aws:iam::123456789012:role/eks-irsa",
		Payload: []byte(`{
			"arn":"arn:aws:iam::123456789012:role/eks-irsa",
			"name":"eks-irsa",
			"assume_role_policy_document":"{\"Version\":\"2012-10-17\",\"Statement\":[]}",
			"permission_policies":[]
		}`),
	}
	rawOrders := [][]providers.RawAsset{
		{roleA, roleB},
		{roleB, roleA},
	}

	fixedNow := time.Date(2026, 3, 16, 13, 0, 0, 0, time.UTC)
	var baseline []string
	for idx, raw := range rawOrders {
		normalizer := NewRoleNormalizer()
		bundle, err := normalizer.Normalize(context.Background(), raw)
		if err != nil {
			t.Fatalf("normalize raw order %d failed: %v", idx, err)
		}
		permissions, err := NewPolicyPermissionResolver().ResolvePermissions(context.Background(), bundle)
		if err != nil {
			t.Fatalf("resolve permissions raw order %d failed: %v", idx, err)
		}
		relationships, err := NewRelationshipBuilder(WithRelationshipClock(func() time.Time { return fixedNow })).
			ResolveRelationships(context.Background(), bundle, permissions)
		if err != nil {
			t.Fatalf("resolve relationships raw order %d failed: %v", idx, err)
		}

		signature := make([]string, 0, len(relationships))
		for _, relationship := range relationships {
			signature = append(signature, string(relationship.Type)+"|"+relationship.FromNodeID+"|"+relationship.ToNodeID)
		}
		if idx == 0 {
			baseline = signature
			continue
		}
		if !reflect.DeepEqual(baseline, signature) {
			t.Fatalf("expected deterministic relationship signatures across shuffled raw inputs, baseline=%+v got=%+v", baseline, signature)
		}
	}
}
