package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/providers"
)

func TestKubernetesGraphSnapshot(t *testing.T) {
	normalizer := NewNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		loadRawFixture(t, "k8s_service_account", "service_account_payments.json", "k8s:sa:apps:payments-api"),
		loadRawFixture(t, "k8s_role", "cluster_role_cluster_admin.json", "k8s:role:cluster:cluster-admin"),
		loadRawFixture(t, "k8s_role_binding", "role_binding_cluster_admin.json", "k8s:rb:cluster:payments-cluster-admin"),
		loadRawFixture(t, "k8s_pod", "pod_payments.json", "k8s:pod:apps:payments-api-0"),
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	perms, err := NewPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}
	rels, err := NewRelationshipResolver().ResolveRelationships(context.Background(), bundle, perms)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	signatures := make([]string, 0, len(rels))
	for _, rel := range rels {
		signatures = append(signatures, strings.Join([]string{string(rel.Type), rel.FromNodeID, rel.ToNodeID}, "|"))
	}
	sort.Strings(signatures)
	actual := strings.Join(signatures, "\n") + "\n"

	snapshotPath := filepath.Join("..", "..", "..", "testdata", "contracts", "kubernetes_graph_edges.snapshot")
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
