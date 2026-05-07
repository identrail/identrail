package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/connectors"
	"github.com/identrail/identrail/internal/domain"
)

func TestKubectlPreflightDriverActivatesHealthyConnector(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl --context prod config view --minify -o json": []byte(`{
				"current-context":"prod",
				"contexts":[{"name":"prod","context":{"cluster":"prod-cluster"}}],
				"clusters":[{"name":"prod-cluster","cluster":{"server":"https://kubernetes.example"}}]
			}`),
			"kubectl --context prod version -o json":                                  []byte(`{"serverVersion":{"gitVersion":"v1.30.4","platform":"linux/amd64"}}`),
			"kubectl --context prod auth can-i list serviceaccounts --all-namespaces": []byte("yes\n"),
			"kubectl --context prod auth can-i list rolebindings --all-namespaces":    []byte("yes\n"),
			"kubectl --context prod auth can-i list clusterrolebindings":              []byte("yes\n"),
			"kubectl --context prod auth can-i list roles --all-namespaces":           []byte("yes\n"),
			"kubectl --context prod auth can-i list clusterroles":                     []byte("yes\n"),
			"kubectl --context prod auth can-i list pods --all-namespaces":            []byte("yes\n"),
		},
	}
	driver := NewKubectlPreflightDriver("kubectl", "prod", exec.run)
	driver.now = func() time.Time { return time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC) }
	svc := connectors.NewService(map[domain.ConnectorType]connectors.Driver{
		domain.ConnectorTypeKubernetes: driver,
	})

	mutation, err := svc.TestConnection(context.Background(), kubernetesConnector(domain.ConnectorStatusPending))
	if err != nil {
		t.Fatalf("test connection failed: %v", err)
	}
	if mutation.ToStatus != domain.ConnectorStatusActive {
		t.Fatalf("expected active connector, got %+v", mutation)
	}
	if mutation.Health != connectors.HealthStatusHealthy {
		t.Fatalf("expected healthy preflight, got %+v", mutation)
	}
	if !strings.Contains(mutation.Message, "prod preflight passed") {
		t.Fatalf("expected cluster context in message, got %q", mutation.Message)
	}
}

func TestKubectlPreflightDriverReturnsActionableMissingPermissionDiagnostics(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl --context prod config view --minify -o json":                     []byte(`{"current-context":"prod"}`),
			"kubectl --context prod version -o json":                                  []byte(`{"serverVersion":{"gitVersion":"v1.30.4"}}`),
			"kubectl --context prod auth can-i list serviceaccounts --all-namespaces": []byte("yes\n"),
			"kubectl --context prod auth can-i list rolebindings --all-namespaces":    []byte("yes\n"),
			"kubectl --context prod auth can-i list clusterrolebindings":              []byte("yes\n"),
			"kubectl --context prod auth can-i list roles --all-namespaces":           []byte("no\n"),
			"kubectl --context prod auth can-i list clusterroles":                     []byte("yes\n"),
			"kubectl --context prod auth can-i list pods --all-namespaces":            []byte("yes\n"),
		},
	}
	driver := NewKubectlPreflightDriver("kubectl", "prod", exec.run)

	result := driver.Preflight(context.Background())
	if result.Health != connectors.HealthStatusError {
		t.Fatalf("expected error health, got %+v", result)
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("expected one diagnostic, got %+v", result.Diagnostics)
	}
	if result.Diagnostics[0].Code != "kubernetes_permission_denied" {
		t.Fatalf("unexpected diagnostic: %+v", result.Diagnostics[0])
	}
	if !strings.Contains(result.Diagnostics[0].Remediation, "allows list on roles") {
		t.Fatalf("expected actionable RBAC remediation, got %q", result.Diagnostics[0].Remediation)
	}
	if !strings.Contains(result.Message, "grant read access for roles") {
		t.Fatalf("expected missing resource summary, got %q", result.Message)
	}
}

func TestKubectlPreflightDriverReportsMetadataWarnings(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl config current-context":                           []byte("dev\n"),
			"kubectl config view --minify -o json":                     []byte(`{"current-context":"dev","clusters":[{"name":"dev","cluster":{"server":"https://dev.example"}}]}`),
			"kubectl auth can-i list serviceaccounts --all-namespaces": []byte("yes\n"),
			"kubectl auth can-i list rolebindings --all-namespaces":    []byte("yes\n"),
			"kubectl auth can-i list clusterrolebindings":              []byte("yes\n"),
			"kubectl auth can-i list roles --all-namespaces":           []byte("yes\n"),
			"kubectl auth can-i list clusterroles":                     []byte("yes\n"),
			"kubectl auth can-i list pods --all-namespaces":            []byte("yes\n"),
		},
		errs: map[string]error{
			"kubectl version -o json": errors.New("dial tcp: i/o timeout"),
		},
	}
	driver := NewKubectlPreflightDriver("kubectl", "", exec.run)

	result := driver.Preflight(context.Background())
	if result.Health != connectors.HealthStatusWarning {
		t.Fatalf("expected warning health, got %+v", result)
	}
	if result.Cluster.Context != "dev" {
		t.Fatalf("expected current context to be discovered, got %+v", result.Cluster)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "kubernetes_version_unavailable" {
		t.Fatalf("expected version diagnostic, got %+v", result.Diagnostics)
	}
}

func TestKubectlPreflightDriverRejectsNonKubernetesConnector(t *testing.T) {
	driver := NewKubectlPreflightDriver("kubectl", "prod", func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("unexpected kubectl call")
		return nil, nil
	})
	connector := kubernetesConnector(domain.ConnectorStatusPending)
	connector.Type = domain.ConnectorTypeAWS
	if _, err := driver.TestConnection(context.Background(), connector); err == nil {
		t.Fatal("expected connector type rejection")
	}
}

func TestKubectlPreflightDriverReportsDecodeAndPermissionCommandDiagnostics(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl config current-context":                        []byte("dev\n"),
			"kubectl config view --minify -o json":                  []byte(`not-json`),
			"kubectl version -o json":                               []byte(`not-json`),
			"kubectl auth can-i list rolebindings --all-namespaces": []byte("unexpected\n"),
			"kubectl auth can-i list clusterrolebindings":           []byte("yes\n"),
			"kubectl auth can-i list roles --all-namespaces":        []byte("yes\n"),
			"kubectl auth can-i list clusterroles":                  []byte("yes\n"),
			"kubectl auth can-i list pods --all-namespaces":         []byte("yes\n"),
		},
		errs: map[string]error{
			"kubectl auth can-i list serviceaccounts --all-namespaces": errors.New("forbidden"),
		},
	}
	driver := NewKubectlPreflightDriver("", "", exec.run)

	result := driver.Preflight(context.Background())
	if result.Health != connectors.HealthStatusError {
		t.Fatalf("expected error health, got %+v", result)
	}
	assertKubernetesDiagnostic(t, result.Diagnostics, "kubernetes_cluster_metadata_invalid")
	assertKubernetesDiagnostic(t, result.Diagnostics, "kubernetes_version_invalid")
	assertKubernetesDiagnostic(t, result.Diagnostics, "kubernetes_permission_check_failed")
	assertKubernetesDiagnostic(t, result.Diagnostics, "kubernetes_permission_unknown")
	if result.Checks[0].Diagnostic == "" || !strings.Contains(result.Checks[0].Diagnostic, "--all-namespaces") {
		t.Fatalf("expected command diagnostic with all namespaces flag, got %+v", result.Checks[0])
	}
	if result.Checks[1].Diagnostic == "" || !strings.Contains(result.Checks[1].Diagnostic, "unexpected") {
		t.Fatalf("expected unexpected response diagnostic, got %+v", result.Checks[1])
	}
}

func TestKubectlPreflightDriverLifecycleHooksAreNoop(t *testing.T) {
	driver := NewKubectlPreflightDriver("kubectl", "prod", func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("unexpected kubectl call")
		return nil, nil
	})

	connector := kubernetesConnector(domain.ConnectorStatusActive)
	if err := driver.RevokeConnection(context.Background(), connector); err != nil {
		t.Fatalf("revoke connection: %v", err)
	}
	if err := driver.ReactivateConnection(context.Background(), connector); err != nil {
		t.Fatalf("reactivate connection: %v", err)
	}
}

func assertKubernetesDiagnostic(t *testing.T, diagnostics []KubernetesPreflightDiagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("expected diagnostic %q in %+v", code, diagnostics)
}

func kubernetesConnector(status domain.ConnectorStatus) domain.Connector {
	return domain.Connector{
		ID:          "connector-kubernetes",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Type:        domain.ConnectorTypeKubernetes,
		DisplayName: "Production Kubernetes",
		Status:      status,
	}
}
