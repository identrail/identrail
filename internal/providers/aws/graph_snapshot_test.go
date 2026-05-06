package aws

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/providers"
)

func TestAWSGraphSnapshot(t *testing.T) {
	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		loadRawRoleAssetFixture(t, "role_with_policies.json"),
		loadRawRoleAssetFixture(t, "role_with_urlencoded_trust.json"),
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	perms, err := NewPolicyPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}
	rels, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, perms)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	signatures := make([]string, 0, len(rels))
	for _, rel := range rels {
		signatures = append(signatures, strings.Join([]string{string(rel.Type), rel.FromNodeID, rel.ToNodeID}, "|"))
	}
	sort.Strings(signatures)
	actual := strings.Join(signatures, "\n") + "\n"

	snapshotPath := filepath.Join("..", "..", "..", "testdata", "contracts", "aws_graph_edges.snapshot")
	if os.Getenv("UPDATE_CONTRACT_SNAPSHOTS") == "1" {
		if err := os.WriteFile(snapshotPath, []byte(actual), 0o644); err != nil {
			t.Fatalf("write snapshot: %v", err)
		}
	}
	expected, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if string(expected) != actual {
		t.Fatalf("graph snapshot mismatch\nexpected:\n%s\nactual:\n%s", string(expected), actual)
	}
}
