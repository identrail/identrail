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
}

func TestParseKeySet(t *testing.T) {
	key := bytes.Repeat([]byte{7}, aes256KeySize)
	raw := "v1:" + base64.StdEncoding.EncodeToString(key)
	materials, err := ParseKeySet(raw)
	if err != nil {
		t.Fatalf("parse keyset: %v", err)
	}
	if len(materials) != 1 || materials[0].Version != "v1" || !bytes.Equal(materials[0].Key, key) {
		t.Fatalf("unexpected materials: %+v", materials)
	}
	if _, err := ParseKeySet("v1:not-base64"); err == nil {
		t.Fatal("expected invalid base64 to fail")
	}
	if _, err := NewManager([]KeyMaterial{{Version: "v1", Key: []byte("short")}}); err == nil {
		t.Fatal("expected short key to fail")
	}
}
