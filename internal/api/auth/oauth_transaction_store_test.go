package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
)

func TestOAuthTransactionStoreIssueAndConsume(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	txnStore := NewOAuthTransactionStore(store, func() time.Time { return now })

	cookieToken, err := txnStore.Issue(context.Background(), OAuthTransactionEntry{
		Nonce:    "nonce-1",
		Intent:   "login",
		ReturnTo: "/app/welcome",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cookieToken == "" {
		t.Fatal("expected a non-empty cookie token")
	}

	if _, err := txnStore.Consume(context.Background(), "nonce-1", "wrong-cookie"); !errors.Is(err, ErrOAuthTransactionInvalid) {
		t.Fatalf("cookie mismatch should be rejected, got %v", err)
	}
	if _, err := txnStore.Consume(context.Background(), "other-nonce", cookieToken); !errors.Is(err, ErrOAuthTransactionInvalid) {
		t.Fatalf("nonce mismatch should be rejected, got %v", err)
	}

	entry, err := txnStore.Consume(context.Background(), "nonce-1", cookieToken)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if entry.ReturnTo != "/app/welcome" || entry.Intent != "login" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if _, err := txnStore.Consume(context.Background(), "nonce-1", cookieToken); !errors.Is(err, ErrOAuthTransactionInvalid) {
		t.Fatalf("replay should be rejected, got %v", err)
	}
}

func TestOAuthTransactionStoreRejectsExpiredAndMissingStore(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	clock := now
	txnStore := NewOAuthTransactionStore(store, func() time.Time { return clock })

	cookieToken, err := txnStore.Issue(context.Background(), OAuthTransactionEntry{Nonce: "nonce-exp", Intent: "login"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	clock = now.Add(defaultOAuthTransactionTTL + time.Second)
	if _, err := txnStore.Consume(context.Background(), "nonce-exp", cookieToken); !errors.Is(err, ErrOAuthTransactionInvalid) {
		t.Fatalf("expired transaction should be rejected, got %v", err)
	}

	var nilStore *OAuthTransactionStore
	if _, err := nilStore.Issue(context.Background(), OAuthTransactionEntry{Nonce: "n"}); !errors.Is(err, ErrOAuthTransactionInvalid) {
		t.Fatalf("nil store issue should be rejected, got %v", err)
	}
	if _, err := nilStore.Consume(context.Background(), "n", "c"); !errors.Is(err, ErrOAuthTransactionInvalid) {
		t.Fatalf("nil store consume should be rejected, got %v", err)
	}
	if _, err := txnStore.Issue(context.Background(), OAuthTransactionEntry{Nonce: "  "}); !errors.Is(err, ErrOAuthTransactionInvalid) {
		t.Fatalf("blank nonce should be rejected, got %v", err)
	}
}

func TestOAuthTransactionCookieNameIsNonceScopedAndSanitized(t *testing.T) {
	a := OAuthTransactionCookieName("nonceAAA")
	b := OAuthTransactionCookieName("nonceBBB")
	if a == b {
		t.Fatalf("distinct nonces must yield distinct cookie names: %q", a)
	}
	if a != OAuthTransactionCookiePrefix+"_nonceAAA" {
		t.Fatalf("unexpected cookie name: %q", a)
	}
	if got := OAuthTransactionCookieName(""); got != OAuthTransactionCookiePrefix {
		t.Fatalf("empty nonce should fall back to the bare prefix, got %q", got)
	}
	// Any non-token character must be mapped so the Set-Cookie name stays
	// valid.
	if got := OAuthTransactionCookieName("a b;c=d"); got != OAuthTransactionCookiePrefix+"_a_b_c_d" {
		t.Fatalf("cookie name was not sanitized: %q", got)
	}
}

func TestOAuthStateManagerDecodeDoesNotConsume(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	manager := NewOAuthStateManager("state-secret", func() time.Time { return now })

	raw, err := manager.Issue("login", "/app")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	decoded, err := manager.Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Nonce == "" || decoded.Intent != "login" || decoded.ReturnTo != "/app" {
		t.Fatalf("unexpected decoded state: %+v", decoded)
	}
	// Decode must not mark the nonce consumed: a later Consume still works.
	if _, err := manager.Consume(raw); err != nil {
		t.Fatalf("consume after decode should succeed, got %v", err)
	}
	if _, err := manager.Decode(raw + "x"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("tampered state should be rejected, got %v", err)
	}
}
