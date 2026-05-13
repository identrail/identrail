package kubernetes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentClusterRoleStaysReadOnly(t *testing.T) {
	path := filepath.Join("..", "..", "..", "deploy", "connectors", "k8s", "identrail-agent", "templates", "clusterrole.yaml")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read agent clusterrole: %v", err)
	}
	manifest := strings.ToLower(string(payload))
	for _, verb := range []string{"create", "update", "patch", "delete", "deletecollection", "impersonate", "bind", "escalate"} {
		if strings.Contains(manifest, `"`+verb+`"`) || strings.Contains(manifest, "- "+verb) {
			t.Fatalf("clusterrole must not grant mutating verb %q", verb)
		}
	}
	for _, forbidden := range []string{"secrets", "pods/exec"} {
		if strings.Contains(manifest, forbidden) {
			t.Fatalf("clusterrole must not grant access to %q", forbidden)
		}
	}
	for _, required := range []string{`"get"`, `"list"`, `"watch"`, "serviceaccounts", "rolebindings", "clusterrolebindings"} {
		if !strings.Contains(manifest, required) {
			t.Fatalf("clusterrole missing expected read-only item %q", required)
		}
	}
}
