package kubernetes

import (
	"errors"
	"strings"
	"testing"
)

func TestCredentialHelpers(t *testing.T) {
	token := " enrollment-token "
	hash := HashCredential(token)
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if HashCredential("   ") != "" {
		t.Fatal("empty credentials must not hash to a persisted value")
	}
	if !CredentialMatches("enrollment-token", hash) {
		t.Fatal("expected normalized token to match hash")
	}
	if CredentialMatches("wrong-token", hash) {
		t.Fatal("different token must not match hash")
	}
	if CredentialMatches("", hash) || CredentialMatches("enrollment-token", "") {
		t.Fatal("empty token or empty hash must not match")
	}
}

func TestGenerateCredentialIsOpaqueURLSafeToken(t *testing.T) {
	token, err := GenerateCredential()
	if err != nil {
		t.Fatalf("generate credential: %v", err)
	}
	if len(token) < 40 {
		t.Fatalf("generated credential is unexpectedly short: %q", token)
	}
	if strings.ContainsAny(token, "+/=") {
		t.Fatalf("generated credential is not raw URL-safe base64: %q", token)
	}
	if token == HashCredential(token) {
		t.Fatal("generated credential must not equal its stored hash")
	}
}

func TestSecretRefTrimsParts(t *testing.T) {
	got := SecretRef(" connector-1 ", " kubeconfig ")
	want := "secret-envelope://kubernetes/connector-1/kubeconfig"
	if got != want {
		t.Fatalf("SecretRef() = %q, want %q", got, want)
	}
}

func TestValidateKubeconfig(t *testing.T) {
	payload := `
apiVersion: v1
kind: Config
current-context: prod
clusters:
  - name: prod-cluster
    cluster:
      server: https://kubernetes.example.test
contexts:
  - name: prod
    context:
      cluster: prod-cluster
      user: prod-user
  - name: staging
    context:
      cluster: staging-cluster
      user: staging-user
users:
  - name: prod-user
`

	summary, err := ValidateKubeconfig(payload, "")
	if err != nil {
		t.Fatalf("validate kubeconfig: %v", err)
	}
	if summary.CurrentContext != "prod" || summary.Cluster != "prod-cluster" || summary.Server != "https://kubernetes.example.test" {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	summary, err = ValidateKubeconfig(payload, " prod ")
	if err != nil {
		t.Fatalf("validate preferred context: %v", err)
	}
	if summary.CurrentContext != "prod" {
		t.Fatalf("preferred context was not normalized: %+v", summary)
	}
}

func TestValidateKubeconfigRejectsInvalidPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		context string
	}{
		{name: "empty", payload: ""},
		{name: "malformed", payload: "clusters: [", context: ""},
		{name: "missing users", payload: "current-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: https://example.test\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n"},
		{name: "missing current context", payload: "clusters:\n- name: prod\n  cluster:\n    server: https://example.test\ncontexts:\n- name: prod\n  context:\n    cluster: prod\nusers:\n- name: prod\n"},
		{name: "unknown context", payload: "current-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: https://example.test\ncontexts:\n- name: prod\n  context:\n    cluster: prod\nusers:\n- name: prod\n", context: "missing"},
		{name: "selected context missing user", payload: "current-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: https://example.test\ncontexts:\n- name: prod\n  context:\n    cluster: prod\nusers:\n- name: prod-user\n"},
		{name: "selected context unknown user", payload: "current-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: https://example.test\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n    user: missing-user\nusers:\n- name: prod-user\n"},
		{name: "missing server", payload: "current-context: prod\nclusters:\n- name: prod\n  cluster: {}\ncontexts:\n- name: prod\n  context:\n    cluster: prod\nusers:\n- name: prod\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateKubeconfig(tt.payload, tt.context)
			if !errors.Is(err, ErrInvalidKubeconfig) {
				t.Fatalf("ValidateKubeconfig() error = %v, want %v", err, ErrInvalidKubeconfig)
			}
		})
	}
}
