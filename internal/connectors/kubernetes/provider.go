package kubernetes

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	ProviderName              = "kubernetes"
	AgentMode                 = "agent"
	KubeconfigMode            = "kubeconfig"
	EnrollmentTTL             = 24 * time.Hour
	HeartbeatDegradedAfter    = 5 * time.Minute
	KubeconfigSecretName      = "kubeconfig"
	EnrollmentTokenHashField  = "enrollment_token_sha256"
	AgentCredentialHashField  = "agent_credential_sha256"
	DefaultAgentHeartbeatPath = "/v1/connectors/k8s/heartbeat"
	DefaultAgentEnrollPath    = "/v1/connectors/k8s/enroll"
)

// GenerateCredential returns a URL-safe opaque token. Plaintext values are
// returned only to the caller once; persisted records should store HashCredential.
func GenerateCredential() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate kubernetes connector credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func HashCredential(token string) string {
	normalized := strings.TrimSpace(token)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func CredentialMatches(token string, expectedHash string) bool {
	actual := HashCredential(token)
	expected := strings.TrimSpace(expectedHash)
	if actual == "" || expected == "" || len(actual) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func SecretRef(connectorID string, secretName string) string {
	return "secret-envelope://kubernetes/" + strings.TrimSpace(connectorID) + "/" + strings.TrimSpace(secretName)
}
