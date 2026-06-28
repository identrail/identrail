package email

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResendSenderPostsEmail(t *testing.T) {
	var captured struct {
		Authorization  string
		IdempotencyKey string
		Payload        resendEmailPayload
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Authorization = r.Header.Get("Authorization")
		captured.IdempotencyKey = r.Header.Get("Idempotency-Key")
		if err := json.NewDecoder(r.Body).Decode(&captured.Payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"email_123"}`))
	}))
	defer server.Close()

	sender, err := NewResendSender("re_test_123", time.Second, WithResendEndpoint(server.URL))
	if err != nil {
		t.Fatalf("new resend sender: %v", err)
	}
	err = sender.Send(context.Background(), Message{
		From:           "Identrail <hello@send.identrail.com>",
		To:             []string{"alex@example.com"},
		ReplyTo:        "support@identrail.com",
		Subject:        "Welcome",
		Text:           "Hello",
		HTML:           "<p>Hello</p>",
		IdempotencyKey: "welcome-user_123",
	})
	if err != nil {
		t.Fatalf("send email: %v", err)
	}
	if captured.Authorization != "Bearer re_test_123" {
		t.Fatalf("unexpected authorization header: %q", captured.Authorization)
	}
	if captured.IdempotencyKey != "welcome-user_123" {
		t.Fatalf("unexpected idempotency key: %q", captured.IdempotencyKey)
	}
	if captured.Payload.From != "Identrail <hello@send.identrail.com>" || captured.Payload.ReplyTo != "support@identrail.com" {
		t.Fatalf("unexpected payload metadata: %+v", captured.Payload)
	}
	if len(captured.Payload.To) != 1 || captured.Payload.To[0] != "alex@example.com" {
		t.Fatalf("unexpected payload recipient: %+v", captured.Payload.To)
	}
}

func TestResendSenderReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"name":"validation_error","message":"from domain is not verified"}`))
	}))
	defer server.Close()

	sender, err := NewResendSender("re_test_123", time.Second, WithResendEndpoint(server.URL))
	if err != nil {
		t.Fatalf("new resend sender: %v", err)
	}
	err = sender.Send(context.Background(), Message{
		From:    "Identrail <hello@send.identrail.com>",
		To:      []string{"alex@example.com"},
		Subject: "Welcome",
		Text:    "Hello",
	})
	if err == nil || !strings.Contains(err.Error(), "from domain is not verified") {
		t.Fatalf("expected resend api error, got %v", err)
	}
}
