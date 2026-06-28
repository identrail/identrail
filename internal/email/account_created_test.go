package email

import (
	"strings"
	"testing"
)

func TestAccountCreatedMessageRendersHumanEmail(t *testing.T) {
	message, err := AccountCreatedMessage(AccountCreatedInput{
		From:           "Identrail <hello@send.identrail.com>",
		ReplyTo:        "support@identrail.com",
		To:             "alex@example.com",
		DisplayName:    "Alex Morgan",
		ContinueURL:    "https://app.identrail.com/onboarding/org",
		IdempotencyKey: "account-created-user_123",
	})
	if err != nil {
		t.Fatalf("render account-created email: %v", err)
	}
	if message.Subject != accountCreatedSubject {
		t.Fatalf("unexpected subject: %q", message.Subject)
	}
	if message.From != "Identrail <hello@send.identrail.com>" || message.ReplyTo != "support@identrail.com" {
		t.Fatalf("unexpected sender metadata: %+v", message)
	}
	if len(message.To) != 1 || message.To[0] != "alex@example.com" {
		t.Fatalf("unexpected recipient: %+v", message.To)
	}
	for _, want := range []string{
		"Hi Alex,",
		"Your Identrail account is ready.",
		"will not ask for production credentials",
		"https://app.identrail.com/onboarding/org",
	} {
		if !strings.Contains(message.Text, want) {
			t.Fatalf("expected text body to contain %q, got:\n%s", want, message.Text)
		}
	}
	if !strings.Contains(message.HTML, "Continue setup") || !strings.Contains(message.HTML, "https://app.identrail.com/onboarding/org") {
		t.Fatalf("expected html body to include CTA, got:\n%s", message.HTML)
	}
	if message.IdempotencyKey != "account-created-user_123" {
		t.Fatalf("unexpected idempotency key: %q", message.IdempotencyKey)
	}
}

func TestAccountCreatedMessageRejectsInvalidAddresses(t *testing.T) {
	_, err := AccountCreatedMessage(AccountCreatedInput{
		From: "Identrail <hello@send.identrail.com>",
		To:   "not-an-email",
	})
	if err == nil {
		t.Fatal("expected invalid recipient to fail")
	}
}
