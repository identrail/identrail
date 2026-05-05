package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeCommandExec struct {
	responses map[string][]byte
	errs      map[string]error
	commands  []string
}

func (f *fakeCommandExec) run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.commands = append(f.commands, cmd)
	if err, ok := f.errs[cmd]; ok {
		return nil, err
	}
	if out, ok := f.responses[cmd]; ok {
		return out, nil
	}
	return nil, errors.New("unexpected command: " + cmd)
}

func TestKubectlCollectorCollect(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl --context dev get serviceaccounts --all-namespaces -o json": []byte(`{"items":[
				{"kind":"ServiceAccount","metadata":{"name":"payments-api","namespace":"apps","labels":{"team":"payments"}}},
				{"kind":"ServiceAccount","metadata":{"name":"payments-api","namespace":"apps","labels":{"team":"payments"}}}
			]}`),
			"kubectl --context dev get rolebindings --all-namespaces -o json": []byte(`{"items":[
				{"kind":"RoleBinding","metadata":{"name":"payments-read","namespace":"apps"},"roleRef":{"kind":"Role","name":"view"},"subjects":[{"kind":"ServiceAccount","name":"payments-api","namespace":"apps"}]}
			]}`),
			"kubectl --context dev get clusterrolebindings -o json": []byte(`{"items":[
				{"kind":"ClusterRoleBinding","metadata":{"name":"payments-admin"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"payments-api","namespace":"apps"}]}
			]}`),
			"kubectl --context dev get roles --all-namespaces -o json": []byte(`{"items":[
				{"kind":"Role","metadata":{"name":"payments-view","namespace":"apps"},"rules":[{"verbs":["get","list","watch"],"resources":["pods"]}]}
			]}`),
			"kubectl --context dev get clusterroles -o json": []byte(`{"items":[
				{"kind":"ClusterRole","metadata":{"name":"cluster-admin"},"rules":[{"verbs":["*"],"resources":["*"]}]}
			]}`),
			"kubectl --context dev get pods --all-namespaces -o json": []byte(`{"items":[
				{"kind":"Pod","metadata":{"name":"payments-api-0","namespace":"apps"},"spec":{"serviceAccountName":"payments-api"}}
			]}`),
		},
	}

	collector := NewKubectlCollector("kubectl", "dev", exec.run)
	collector.now = func() time.Time { return time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC) }

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 6 {
		t.Fatalf("expected 6 deduplicated assets, got %d", len(assets))
	}
	for _, asset := range assets {
		if asset.Collected != "2026-03-17T12:00:00Z" {
			t.Fatalf("unexpected collected timestamp: %q", asset.Collected)
		}
	}
	if got := len(exec.commands); got != 6 {
		t.Fatalf("expected 6 kubectl calls, got %d", got)
	}
}

func TestKubectlCollectorUsesDefaults(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl get serviceaccounts --all-namespaces -o json": []byte(`{"items":[]}`),
			"kubectl get rolebindings --all-namespaces -o json":    []byte(`{"items":[]}`),
			"kubectl get clusterrolebindings -o json":              []byte(`{"items":[]}`),
			"kubectl get roles --all-namespaces -o json":           []byte(`{"items":[]}`),
			"kubectl get clusterroles -o json":                     []byte(`{"items":[]}`),
			"kubectl get pods --all-namespaces -o json":            []byte(`{"items":[]}`),
		},
	}
	collector := NewKubectlCollector("", "", exec.run)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("collect failed: %v", err)
	}
}

func TestKubectlCollectorCommandError(t *testing.T) {
	exec := &fakeCommandExec{
		errs: map[string]error{
			"kubectl get serviceaccounts --all-namespaces -o json": errors.New("forbidden"),
		},
	}
	collector := NewKubectlCollector("kubectl", "", exec.run)
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "list serviceaccounts") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubectlCollectorInvalidJSON(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl get serviceaccounts --all-namespaces -o json": []byte(`not-json`),
		},
	}
	collector := NewKubectlCollector("kubectl", "", exec.run)
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "decode kubectl output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubectlCollectorMalformedItem(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl get serviceaccounts --all-namespaces -o json": []byte(`{"items":[{"metadata":{"name":"sa","namespace":"apps"}}]}`),
			"kubectl get rolebindings --all-namespaces -o json":    []byte(`{"items":[{"kind":"RoleBinding","metadata":{"name":"rb","namespace":"apps"}}]}`),
			"kubectl get clusterrolebindings -o json":              []byte(`{"items":[{"kind":"ClusterRoleBinding","metadata":{"name":"crb"}}]}`),
			"kubectl get roles --all-namespaces -o json":           []byte(`{"items":[{"kind":"Role","metadata":{"name":"view","namespace":"apps"}}]}`),
			"kubectl get clusterroles -o json":                     []byte(`{"items":[{"kind":"ClusterRole","metadata":{"name":"cluster-admin"}}]}`),
			"kubectl get pods --all-namespaces -o json":            []byte(`{"items":[invalid]}`),
		},
	}
	collector := NewKubectlCollector("kubectl", "", exec.run)
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestKubectlCollectorCollectWithDiagnostics(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl get serviceaccounts --all-namespaces -o json": []byte(`{"items":[{"kind":"ServiceAccount","metadata":{"name":"sa","namespace":"apps"}},42]}`),
			"kubectl get rolebindings --all-namespaces -o json":    []byte(`{"items":[]}`),
			"kubectl get clusterrolebindings -o json":              []byte(`{"items":[]}`),
			"kubectl get roles --all-namespaces -o json":           []byte(`{"items":[]}`),
			"kubectl get clusterroles -o json":                     []byte(`{"items":[]}`),
			"kubectl get pods --all-namespaces -o json":            []byte(`{"items":[]}`),
		},
	}
	collector := NewKubectlCollector("kubectl", "", exec.run)
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("collect with diagnostics failed: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one valid asset, got %d", len(assets))
	}
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic issue, got %+v", diagnostics)
	}
	if diagnostics[0].Code != "decode_error" {
		t.Fatalf("unexpected diagnostic code %+v", diagnostics[0])
	}
}

func TestKubectlCollectorRetriesTransientErrors(t *testing.T) {
	attempts := 0
	delays := make([]time.Duration, 0, 2)
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		command := strings.TrimSpace(name + " " + strings.Join(args, " "))
		if command != "kubectl get serviceaccounts --all-namespaces -o json" {
			return []byte(`{"items":[]}`), nil
		}
		attempts++
		if attempts <= 2 {
			return nil, errors.New("Too Many Requests")
		}
		return []byte(`{"items":[]}`), nil
	}

	collector := NewKubectlCollector(
		"kubectl",
		"",
		runner,
		WithKubectlRetryPolicy(KubectlRetryPolicy{
			MaxRetries: 2,
			BaseDelay:  100 * time.Millisecond,
			MaxDelay:   400 * time.Millisecond,
			Jitter:     0,
		}),
		WithKubectlSleeper(func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		}),
	)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
	if len(delays) != 2 || delays[0] != 100*time.Millisecond || delays[1] != 200*time.Millisecond {
		t.Fatalf("unexpected retry delays %+v", delays)
	}
}

func TestRetryBackoffJitterBounds(t *testing.T) {
	collector := NewKubectlCollector("kubectl", "", func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{"items":[]}`), nil
	}, WithKubectlRetryPolicy(KubectlRetryPolicy{
		MaxRetries: 3,
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   300 * time.Millisecond,
		Jitter:     1.0,
	}))

	collector.randFn = func() float64 { return 0.0 } // max negative offset
	if got := collector.retryBackoff(0); got != 0 {
		t.Fatalf("expected floor at zero delay, got %v", got)
	}

	collector.randFn = func() float64 { return 1.0 } // max positive offset
	if got := collector.retryBackoff(2); got != 300*time.Millisecond {
		t.Fatalf("expected clamp to max delay, got %v", got)
	}

	collector.retry.Jitter = 0
	if got := collector.retryBackoff(1); got != 200*time.Millisecond {
		t.Fatalf("expected deterministic backoff without jitter, got %v", got)
	}
}

func TestIsRetryableKubectlError(t *testing.T) {
	retryable := []string{
		"Too Many Requests",
		"request timeout",
		"connection refused",
		"temporarily unavailable",
	}
	for _, msg := range retryable {
		if !isRetryableKubectlError(errors.New(msg)) {
			t.Fatalf("expected retryable error for %q", msg)
		}
	}
	if isRetryableKubectlError(nil) {
		t.Fatal("nil error should not be retryable")
	}
	if isRetryableKubectlError(errors.New("context canceled")) {
		t.Fatal("context canceled should not be retryable")
	}
	if isRetryableKubectlError(errors.New("forbidden")) {
		t.Fatal("forbidden should not be retryable")
	}
}
