package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignAppJWT(t *testing.T) {
	key, pemValue := testPrivateKeyPEM(t)
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	token, err := SignAppJWT(AppCredentials{AppID: 12345, PrivateKeyPEM: pemValue}, now)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected jwt with three parts, got %q", token)
	}
	var claims map[string]any
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims["iss"] != "12345" {
		t.Fatalf("unexpected issuer claim: %#v", claims["iss"])
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("jwt signature did not verify: %v", err)
	}
}

func TestInstallationTokenClientCachesUntilNearExpiry(t *testing.T) {
	_, pemValue := testPrivateKeyPEM(t)
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/app/installations/99/access_tokens" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Fatalf("missing bearer jwt")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"inst-token","expires_at":"2026-05-13T13:00:00Z"}`))
	}))
	defer server.Close()

	client := &InstallationTokenClient{
		Credentials: AppCredentials{AppID: 12345, PrivateKeyPEM: pemValue},
		APIBaseURL:  server.URL,
		Now:         func() time.Time { return now },
	}
	first, err := client.Mint(context.Background(), 99)
	if err != nil {
		t.Fatalf("mint first token: %v", err)
	}
	second, err := client.Mint(context.Background(), 99)
	if err != nil {
		t.Fatalf("mint cached token: %v", err)
	}
	if first.Token != second.Token || calls != 1 {
		t.Fatalf("expected cached token, calls=%d first=%+v second=%+v", calls, first, second)
	}
}

func TestBuildInstallURL(t *testing.T) {
	got, err := BuildInstallURL("Identrail-App", "state-1", "https://app.identrail.com/callback")
	if err != nil {
		t.Fatalf("build install url: %v", err)
	}
	if !strings.HasPrefix(got, "https://github.com/apps/identrail-app/installations/new?") ||
		!strings.Contains(got, "state=state-1") {
		t.Fatalf("unexpected install url: %s", got)
	}
}

func testPrivateKeyPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return key, string(pem.EncodeToMemory(block))
}
