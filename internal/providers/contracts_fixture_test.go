package providers_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/identrail/identrail/internal/providers"
	awsprovider "github.com/identrail/identrail/internal/providers/aws"
	k8sprovider "github.com/identrail/identrail/internal/providers/kubernetes"
)

func TestAWSFixtureContracts(t *testing.T) {
	ctx := context.Background()
	rawAssets, err := awsprovider.NewFixtureCollector([]string{
		fixturePath("aws", "role_with_policies.json"),
		fixturePath("aws", "role_with_urlencoded_trust.json"),
	}).Collect(ctx)
	if err != nil {
		t.Fatalf("collect aws fixtures: %v", err)
	}
	bundle, err := awsprovider.NewRoleNormalizer().Normalize(ctx, rawAssets)
	if err != nil {
		t.Fatalf("normalize aws fixtures: %v", err)
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("validate normalized bundle: %v", err)
	}
	perms, err := awsprovider.NewPolicyPermissionResolver().ResolvePermissions(ctx, bundle)
	if err != nil {
		t.Fatalf("resolve permissions: %v", err)
	}
	relationships, err := awsprovider.NewRelationshipBuilder().ResolveRelationships(ctx, bundle, perms)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("validate graph contract: %v", err)
	}
}

func TestKubernetesFixtureContracts(t *testing.T) {
	ctx := context.Background()
	rawAssets, err := k8sprovider.NewFixtureCollector([]string{
		fixturePath("kubernetes", "service_account_payments.json"),
		fixturePath("kubernetes", "cluster_role_cluster_admin.json"),
		fixturePath("kubernetes", "role_binding_cluster_admin.json"),
		fixturePath("kubernetes", "pod_payments.json"),
	}).Collect(ctx)
	if err != nil {
		t.Fatalf("collect k8s fixtures: %v", err)
	}
	bundle, err := k8sprovider.NewNormalizer().Normalize(ctx, rawAssets)
	if err != nil {
		t.Fatalf("normalize k8s fixtures: %v", err)
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("validate normalized bundle: %v", err)
	}
	perms, err := k8sprovider.NewPermissionResolver().ResolvePermissions(ctx, bundle)
	if err != nil {
		t.Fatalf("resolve permissions: %v", err)
	}
	relationships, err := k8sprovider.NewRelationshipResolver().ResolveRelationships(ctx, bundle, perms)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("validate graph contract: %v", err)
	}
}

func fixturePath(group string, name string) string {
	return filepath.Join("..", "..", "testdata", group, name)
}
