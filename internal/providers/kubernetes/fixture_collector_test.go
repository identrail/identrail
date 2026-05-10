package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFixtureCollectorCollectFilesAndDirectories(t *testing.T) {
	dir := t.TempDir()
	sa := `{"kind":"ServiceAccount","metadata":{"name":"payments","namespace":"apps"}}`
	pod := `{"kind":"Pod","metadata":{"name":"payments-api-0","namespace":"apps"},"spec":{"serviceAccountName":"payments"}}`
	if err := os.WriteFile(filepath.Join(dir, "sa.json"), []byte(sa), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pod.json"), []byte(pod), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fixedNow := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	collector := NewFixtureCollector([]string{filepath.Join(dir, "sa.json"), dir})
	collector.now = func() time.Time { return fixedNow }

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 deduplicated assets, got %d", len(assets))
	}
	for _, asset := range assets {
		if asset.Collected != "2026-03-16T12:00:00Z" {
			t.Fatalf("unexpected collected timestamp: %q", asset.Collected)
		}
	}
}

func TestFixtureCollectorErrors(t *testing.T) {
	collector := NewFixtureCollector(nil)
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected error for empty fixture list")
	}

	emptyDir := t.TempDir()
	collector = NewFixtureCollector([]string{emptyDir})
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected error for empty fixture directory")
	}

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	collector = NewFixtureCollector([]string{badFile})
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFixtureCollectorSkipsMalformedRoleAndUnknownFixturesWhenValidRecordsExist(t *testing.T) {
	dir := t.TempDir()

	validSA := `{"kind":"ServiceAccount","metadata":{"name":"payments","namespace":"apps"}}`
	validPod := `{"kind":"Pod","metadata":{"name":"payments-api-0","namespace":"apps"},"spec":{"serviceAccountName":"payments"}}`
	malformed := `not-json`
	badRole := `{"kind":"Role","metadata":{"namespace":"apps"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]}`
	unknownKind := `{"kind":"Unknown","metadata":{"name":"ignored","namespace":"apps"}}`

	if err := os.WriteFile(filepath.Join(dir, "01-sa.json"), []byte(validSA), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "02-malformed.json"), []byte(malformed), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "03-role-missing-name.json"), []byte(badRole), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "04-unknown.json"), []byte(unknownKind), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "05-pod.json"), []byte(validPod), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	collector := NewFixtureCollector([]string{dir})
	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect with partial malformed fixtures: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected two valid assets, got %d", len(assets))
	}
	got := map[string]struct{}{}
	for _, asset := range assets {
		got[asset.SourceID] = struct{}{}
	}
	if _, ok := got["k8s:sa:apps:payments"]; !ok {
		t.Fatalf("expected service account asset to be retained, got %+v", assets)
	}
	if _, ok := got["k8s:pod:apps:payments-api-0"]; !ok {
		t.Fatalf("expected pod asset to be retained, got %+v", assets)
	}
}

func TestNormalizeKindAndSourceIDFor(t *testing.T) {
	if got := normalizeKind("ServiceAccount"); got != "k8s_service_account" {
		t.Fatalf("unexpected kind mapping: %q", got)
	}
	if got := normalizeKind("ClusterRoleBinding"); got != "k8s_role_binding" {
		t.Fatalf("unexpected kind mapping: %q", got)
	}
	if got := normalizeKind("ClusterRole"); got != "k8s_role" {
		t.Fatalf("unexpected kind mapping: %q", got)
	}
	if got := normalizeKind("Pod"); got != "k8s_pod" {
		t.Fatalf("unexpected kind mapping: %q", got)
	}
	if got := normalizeKind("Unknown"); got != "" {
		t.Fatalf("expected unknown kind to map to empty, got %q", got)
	}

	if got := sourceIDFor("k8s_service_account", ObjectMeta{Name: "sa", Namespace: "apps"}); got != "k8s:sa:apps:sa" {
		t.Fatalf("unexpected sa source id %q", got)
	}
	if got := sourceIDFor("k8s_role_binding", ObjectMeta{Name: "rb"}); got != "k8s:rb:cluster:rb" {
		t.Fatalf("unexpected cluster role binding source id %q", got)
	}
	if got := sourceIDFor("k8s_role_binding", ObjectMeta{Name: "rb", Namespace: "apps"}); got != "k8s:rb:apps:rb" {
		t.Fatalf("unexpected namespaced role binding source id %q", got)
	}
	if got := sourceIDFor("k8s_pod", ObjectMeta{Name: "pod", Namespace: "apps"}); got != "k8s:pod:apps:pod" {
		t.Fatalf("unexpected pod source id %q", got)
	}
	if got := roleSourceID("ClusterRole", "", "cluster-admin"); got != "k8s:role:cluster:cluster-admin" {
		t.Fatalf("unexpected cluster role source id %q", got)
	}
	if got := roleSourceID("Role", "apps", "payments-view"); got != "k8s:role:apps:payments-view" {
		t.Fatalf("unexpected role source id %q", got)
	}
}

func TestExpandFixturePathsSkipsNonJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	paths, err := expandFixturePaths([]string{dir})
	if err != nil {
		t.Fatalf("expand failed: %v", err)
	}
	if len(paths) != 1 || !strings.HasSuffix(paths[0], "a.json") {
		t.Fatalf("expected only json file, got %+v", paths)
	}
}
