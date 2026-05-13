package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyWebhookSignature(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	signature := testWebhookSignature("secret", payload)
	if !VerifyWebhookSignature(" secret ", payload, signature) {
		t.Fatal("expected valid webhook signature")
	}
	if VerifyWebhookSignature("secret", payload, "sha256=bad") {
		t.Fatal("expected malformed signature to fail")
	}
	if VerifyWebhookSignature("wrong", payload, signature) {
		t.Fatal("expected wrong secret to fail")
	}
	if VerifyWebhookSignature("", payload, signature) {
		t.Fatal("expected empty secret to fail")
	}
}

func TestParseInstallationEvent(t *testing.T) {
	event, err := ParseInstallationEvent([]byte(`{
		"action":"DELETED",
		"installation":{"id":123,"account":{"login":"identrail"}}
	}`))
	if err != nil {
		t.Fatalf("parse installation event: %v", err)
	}
	if event.Action != "deleted" || event.InstallationID != 123 || event.AccountLogin != "identrail" {
		t.Fatalf("unexpected event %+v", event)
	}
	if _, err := ParseInstallationEvent([]byte(`{"action":"created","installation":{"id":0}}`)); err == nil {
		t.Fatal("expected missing installation id error")
	}
	if _, err := ParseInstallationEvent([]byte(`{`)); err == nil {
		t.Fatal("expected invalid json error")
	}
}

func TestParseInstallationRepositoriesEvent(t *testing.T) {
	event, err := ParseInstallationRepositoriesEvent([]byte(`{
		"action":"ADDED",
		"installation":{"id":123},
		"repositories_added":[{"full_name":"Identrail/API"}],
		"repositories_removed":[{"full_name":"Identrail/Old"}]
	}`))
	if err != nil {
		t.Fatalf("parse installation repositories event: %v", err)
	}
	if event.Action != "added" || event.InstallationID != 123 {
		t.Fatalf("unexpected event %+v", event)
	}
	if len(event.AddedRepositories) != 1 || event.AddedRepositories[0] != "identrail/api" {
		t.Fatalf("unexpected added repositories %+v", event.AddedRepositories)
	}
	if len(event.RemovedRepositories) != 1 || event.RemovedRepositories[0] != "identrail/old" {
		t.Fatalf("unexpected removed repositories %+v", event.RemovedRepositories)
	}
	if _, err := ParseInstallationRepositoriesEvent([]byte(`{"action":"added","installation":{"id":0}}`)); err == nil {
		t.Fatal("expected missing installation id error")
	}
	if _, err := ParseInstallationRepositoriesEvent([]byte(`{`)); err == nil {
		t.Fatal("expected invalid json error")
	}
}

func testWebhookSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
