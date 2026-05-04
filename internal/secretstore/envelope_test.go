package secretstore

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestManagerEncryptDecryptAndRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, aes256KeySize)
	newKey := bytes.Repeat([]byte{2}, aes256KeySize)
	oldManager, err := NewManager([]KeyMaterial{{Version: "v1", Key: oldKey}})
	if err != nil {
		t.Fatalf("new old manager: %v", err)
	}
	envelope, err := oldManager.Encrypt([]byte("webhook-secret"), []byte("tenant/workspace/project"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(envelope.Ciphertext, []byte("webhook-secret")) {
		t.Fatal("ciphertext should not contain plaintext secret")
	}

	manager, err := NewManager([]KeyMaterial{{Version: "v1", Key: oldKey}, {Version: "v2", Key: newKey}})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if !manager.NeedsRotation(envelope) {
		t.Fatal("expected old envelope to require rotation")
	}
	plaintext, err := manager.Decrypt(envelope, []byte("tenant/workspace/project"))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != "webhook-secret" {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
	if _, err := manager.Decrypt(envelope, []byte("wrong-associated-data")); err == nil {
		t.Fatal("expected associated data mismatch to fail")
	}
	freshEnvelope, err := manager.Encrypt([]byte("new-secret"), []byte("tenant/workspace/project"))
	if err != nil {
		t.Fatalf("encrypt with active key: %v", err)
	}
	if manager.NeedsRotation(freshEnvelope) {
		t.Fatal("active key envelope should not require rotation")
	}
	if manager.ActiveKeyVersion() != "v2" {
		t.Fatalf("expected active key version v2, got %q", manager.ActiveKeyVersion())
	}
}

func TestParseKeySet(t *testing.T) {
	key := bytes.Repeat([]byte{7}, aes256KeySize)
	nextKey := bytes.Repeat([]byte{8}, aes256KeySize)
	raw := "v1:" + base64.StdEncoding.EncodeToString(key) + ";v2:" + base64.RawStdEncoding.EncodeToString(nextKey)
	materials, err := ParseKeySet(raw)
	if err != nil {
		t.Fatalf("parse keyset: %v", err)
	}
	if len(materials) != 2 || materials[0].Version != "v1" || !bytes.Equal(materials[0].Key, key) ||
		materials[1].Version != "v2" || !bytes.Equal(materials[1].Key, nextKey) {
		t.Fatalf("unexpected materials: %+v", materials)
	}
	emptyMaterials, err := ParseKeySet(" , ; ")
	if err != nil {
		t.Fatalf("empty keyset should not fail: %v", err)
	}
	if emptyMaterials != nil {
		t.Fatalf("expected nil materials for empty keyset, got %+v", emptyMaterials)
	}
	if _, err := ParseKeySet("v1:not-base64"); err == nil {
		t.Fatal("expected invalid base64 to fail")
	}
	if _, err := ParseKeySet("v1"); err == nil {
		t.Fatal("expected missing separator to fail")
	}
	if _, err := NewManager([]KeyMaterial{{Version: "v1", Key: []byte("short")}}); err == nil {
		t.Fatal("expected short key to fail")
	}
}

func TestNewEphemeralManagerEncryptsAndDecrypts(t *testing.T) {
	manager := NewEphemeralManager()
	if manager == nil {
		t.Fatal("expected ephemeral manager")
	}
	if manager.ActiveKeyVersion() != ephemeralVersion {
		t.Fatalf("expected ephemeral active version, got %q", manager.ActiveKeyVersion())
	}
	envelope, err := manager.Encrypt([]byte("local-secret"), []byte("associated-data"))
	if err != nil {
		t.Fatalf("encrypt with ephemeral manager: %v", err)
	}
	plaintext, err := manager.Decrypt(envelope, []byte("associated-data"))
	if err != nil {
		t.Fatalf("decrypt with ephemeral manager: %v", err)
	}
	if string(plaintext) != "local-secret" {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
}

func TestManagerRejectsInvalidKeyMaterial(t *testing.T) {
	key := bytes.Repeat([]byte{1}, aes256KeySize)
	tests := []struct {
		name      string
		materials []KeyMaterial
	}{
		{name: "empty"},
		{name: "invalid version", materials: []KeyMaterial{{Version: "bad version", Key: key}}},
		{name: "duplicate version", materials: []KeyMaterial{{Version: "v1", Key: key}, {Version: "v1", Key: key}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewManager(tc.materials); err == nil {
				t.Fatal("expected invalid key material to fail")
			}
		})
	}
}

func TestNilManagerReturnsErrors(t *testing.T) {
	var manager *Manager
	if manager.ActiveKeyVersion() != "" {
		t.Fatalf("nil active key version should be empty, got %q", manager.ActiveKeyVersion())
	}
	if !manager.NeedsRotation(Envelope{}) {
		t.Fatal("nil manager should require rotation")
	}
	if _, err := manager.Encrypt([]byte("secret"), nil); err == nil {
		t.Fatal("nil manager encrypt should fail")
	}
	if _, err := manager.Decrypt(Envelope{}, nil); err == nil {
		t.Fatal("nil manager decrypt should fail")
	}
}

func TestDecryptRejectsMalformedEnvelopes(t *testing.T) {
	key := bytes.Repeat([]byte{3}, aes256KeySize)
	manager, err := NewManager([]KeyMaterial{{Version: "v1", Key: key}})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	envelope, err := manager.Encrypt([]byte("webhook-secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	tests := []struct {
		name     string
		envelope Envelope
	}{
		{name: "unsupported version", envelope: Envelope{Version: 2, Algorithm: AlgorithmAES256GCM, KeyVersion: "v1", Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext}},
		{name: "unsupported algorithm", envelope: Envelope{Version: envelope.Version, Algorithm: "AES-128-GCM", KeyVersion: "v1", Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext}},
		{name: "unknown key version", envelope: Envelope{Version: envelope.Version, Algorithm: envelope.Algorithm, KeyVersion: "missing", Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext}},
		{name: "bad nonce", envelope: Envelope{Version: envelope.Version, Algorithm: envelope.Algorithm, KeyVersion: envelope.KeyVersion, Nonce: []byte{1}, Ciphertext: envelope.Ciphertext}},
		{name: "empty ciphertext", envelope: Envelope{Version: envelope.Version, Algorithm: envelope.Algorithm, KeyVersion: envelope.KeyVersion, Nonce: envelope.Nonce}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := manager.Decrypt(tc.envelope, []byte("aad")); err == nil {
				t.Fatal("expected malformed envelope to fail")
			}
		})
	}

	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0xff
	if _, err := manager.Decrypt(tampered, []byte("aad")); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}
