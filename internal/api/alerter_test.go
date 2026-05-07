package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func TestNewWebhookAlerterURLValidation(t *testing.T) {
	if _, err := NewWebhookAlerter("http://example.com/hook", 2*time.Second, "high", "", 10, 0, 10*time.Millisecond); err == nil {
		t.Fatal("expected non-localhost http URL to fail")
	}
	if _, err := NewWebhookAlerter("https://example.com/hook", 2*time.Second, "high", "", 10, 0, 10*time.Millisecond); err != nil {
		t.Fatalf("expected https URL to pass: %v", err)
	}
	if _, err := NewWebhookAlerter("http://127.0.0.1:9999/hook", 2*time.Second, "high", "", 10, 0, 10*time.Millisecond); err != nil {
		t.Fatalf("expected localhost http URL to pass: %v", err)
	}
}

func TestWebhookAlerterSeverityValidation(t *testing.T) {
	if _, err := NewWebhookAlerter("https://example.com/hook", 2*time.Second, "unknown", "", 10, 0, 10*time.Millisecond); err == nil {
		t.Fatal("expected invalid severity to fail")
	}
}

func TestWebhookAlerterNotifyScanSendsFilteredPayload(t *testing.T) {
	type requestCapture struct {
		signature string
		payload   AlertPayload
	}

	capture := requestCapture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		capture.signature = r.Header.Get("X-Identrail-Signature")
		if err := json.NewDecoder(r.Body).Decode(&capture.payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	alerter, err := NewWebhookAlerter(server.URL, 2*time.Second, "high", "secret", 10, 0, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new webhook alerter: %v", err)
	}

	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan := db.ScanRecord{
		ID:        "scan-1",
		Status:    "completed",
		StartedAt: now.Add(-1 * time.Minute),
		FinishedAt: func() *time.Time {
			v := now
			return &v
		}(),
	}
	findings := []domain.Finding{
		{ID: "f1", Severity: domain.SeverityLow, Title: "low"},
		{ID: "f2", Severity: domain.SeverityHigh, Title: "high"},
		{ID: "f3", Severity: domain.SeverityCritical, Title: "critical"},
	}

	if err := alerter.NotifyScan(context.Background(), "aws", scan, findings); err != nil {
		t.Fatalf("notify scan: %v", err)
	}
	if capture.payload.ScanID != "scan-1" {
		t.Fatalf("unexpected scan id %q", capture.payload.ScanID)
	}
	if capture.payload.Provider != "aws" {
		t.Fatalf("unexpected provider %q", capture.payload.Provider)
	}
	if capture.payload.MatchedFindings != 2 || len(capture.payload.Findings) != 2 {
		t.Fatalf("expected 2 matched findings, got %+v", capture.payload)
	}
	if capture.signature == "" {
		t.Fatal("expected signature header")
	}
}

func TestWebhookAlerterNotifyScanNoMatchNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter, err := NewWebhookAlerter(server.URL, 2*time.Second, "critical", "", 10, 0, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new webhook alerter: %v", err)
	}
	if err := alerter.NotifyScan(context.Background(), "aws", db.ScanRecord{ID: "scan-1"}, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityMedium},
	}); err != nil {
		t.Fatalf("notify scan should not fail when no findings match: %v", err)
	}
	if requests != 0 {
		t.Fatalf("expected no webhook request, got %d", requests)
	}
}

func TestWebhookAlerterNotifyScanNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	alerter, err := NewWebhookAlerter(server.URL, 2*time.Second, "high", "", 10, 0, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new webhook alerter: %v", err)
	}
	err = alerter.NotifyScan(context.Background(), "aws", db.ScanRecord{ID: "scan-1"}, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityHigh},
	})
	if err == nil {
		t.Fatal("expected webhook failure")
	}
}

func TestWebhookAlerterRetriesOnServerError(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("retry"))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	alerter, err := NewWebhookAlerter(server.URL, 2*time.Second, "high", "", 10, 3, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("new webhook alerter: %v", err)
	}
	err = alerter.NotifyScan(context.Background(), "aws", db.ScanRecord{ID: "scan-1"}, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityHigh},
	})
	if err != nil {
		t.Fatalf("expected retry success, got %v", err)
	}
	if requests != 3 {
		t.Fatalf("expected 3 requests, got %d", requests)
	}
}

func TestWebhookAlerterDoesNotRetryOnClientError(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	alerter, err := NewWebhookAlerter(server.URL, 2*time.Second, "high", "", 10, 3, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("new webhook alerter: %v", err)
	}
	err = alerter.NotifyScan(context.Background(), "aws", db.ScanRecord{ID: "scan-1"}, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityHigh},
	})
	if err == nil {
		t.Fatal("expected client error")
	}
	if requests != 1 {
		t.Fatalf("expected 1 request for non-retryable 4xx, got %d", requests)
	}
}
