package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/identrail/identrail/internal/urlpolicy"
)

// AuditEvent captures one structured audit record for external export.
//
// The existing API request audit log is represented as Kind=api_request with the
// HTTP fields populated. Control-plane action audit records use Kind=action and
// populate Action/Resource/Scope fields.
type AuditEvent struct {
	SchemaVersion string    `json:"schema_version"`
	EventID       string    `json:"event_id"`
	Timestamp     time.Time `json:"timestamp"`

	// Service/component/category provide stable routing fields for collectors.
	Service   string `json:"service,omitempty"`
	Component string `json:"component,omitempty"`
	Category  string `json:"category,omitempty"`

	// Kind distinguishes API request envelopes from action-level control-plane events.
	// Examples: "api_request", "action".
	Kind string `json:"kind,omitempty"`

	// CorrelationID ties multiple records back to the same request/workflow.
	CorrelationID string `json:"correlation_id,omitempty"`

	// Actor is a stable, non-secret identifier for the principal that triggered the action.
	Actor string `json:"actor,omitempty"`

	// Action is an operation name for action audit records.
	Action string `json:"action,omitempty"`

	// Scope context.
	TenantID    string `json:"tenant_id,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`

	// Resource context.
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`

	// Outcome is a coarse result indicator such as "success", "denied", "not_found", "error".
	Outcome string `json:"outcome,omitempty"`
	Error   string `json:"error,omitempty"`

	// API request fields (Kind=api_request).
	Method     string              `json:"method,omitempty"`
	Path       string              `json:"path,omitempty"`
	Status     int                 `json:"status,omitempty"`
	ClientIP   string              `json:"client_ip,omitempty"`
	DurationMS int64               `json:"duration_ms,omitempty"`
	UserAgent  string              `json:"user_agent,omitempty"`
	APIKeyID   string              `json:"api_key_id,omitempty"`
	Authz      *AuditAuthzDecision `json:"authz,omitempty"`
}

// AuditAuthzInputSummary captures one sanitized authorization decision input.
type AuditAuthzInputSummary struct {
	SubjectType    string `json:"subject_type,omitempty"`
	SubjectIDHash  string `json:"subject_id_hash,omitempty"`
	Action         string `json:"action,omitempty"`
	ResourceType   string `json:"resource_type,omitempty"`
	ResourceIDHash string `json:"resource_id_hash,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	WorkspaceID    string `json:"workspace_id,omitempty"`
}

// AuditAuthzDecision captures one centralized authorization decision.
type AuditAuthzDecision struct {
	PolicySetID   string                 `json:"policy_set_id,omitempty"`
	PolicyVersion *int                   `json:"policy_version,omitempty"`
	PolicySource  string                 `json:"policy_source,omitempty"`
	RolloutMode   string                 `json:"rollout_mode,omitempty"`
	Allowed       bool                   `json:"allowed"`
	Stage         string                 `json:"stage,omitempty"`
	Reason        string                 `json:"reason,omitempty"`
	Input         AuditAuthzInputSummary `json:"input"`
}

// AuditSink defines the export target for audit events.
type AuditSink interface {
	Write(ctx context.Context, event AuditEvent) error
	Close() error
}

// NopAuditSink discards audit events when no export target is configured.
type NopAuditSink struct{}

func (NopAuditSink) Write(context.Context, AuditEvent) error { return nil }
func (NopAuditSink) Close() error                            { return nil }

// FileAuditSink writes audit events in JSON lines format.
type FileAuditSink struct {
	mu   sync.Mutex
	file *os.File
}

// NewFileAuditSink creates or appends to a local audit file with restrictive permissions.
func NewFileAuditSink(path string) (*FileAuditSink, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log file: %w", err)
	}
	return &FileAuditSink{file: file}, nil
}

func (s *FileAuditSink) Write(_ context.Context, event AuditEvent) error {
	event = NormalizeEvent(context.Background(), event)
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

func (s *FileAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// HTTPAuditSink posts audit events to a remote collector endpoint.
type HTTPAuditSink struct {
	client       *http.Client
	url          string
	hmacSecret   string
	maxRetries   int
	retryBackoff time.Duration
}

// NewHTTPAuditSink builds an HTTP audit sink with URL safety checks.
func NewHTTPAuditSink(endpoint string, timeout time.Duration, hmacSecret string, maxRetries int, retryBackoff time.Duration) (*HTTPAuditSink, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return nil, fmt.Errorf("audit forward url is required")
	}
	if err := validateAuditForwardURL(trimmed); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxRetries < 0 {
		maxRetries = 1
	}
	if retryBackoff <= 0 {
		retryBackoff = 1 * time.Second
	}
	return &HTTPAuditSink{
		client:       &http.Client{Timeout: timeout},
		url:          trimmed,
		hmacSecret:   strings.TrimSpace(hmacSecret),
		maxRetries:   maxRetries,
		retryBackoff: retryBackoff,
	}, nil
}

func (s *HTTPAuditSink) Write(ctx context.Context, event AuditEvent) error {
	event = NormalizeEvent(ctx, event)
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	attempts := s.maxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		retryable, err := s.send(ctx, payload)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable || attempt == attempts-1 {
			break
		}
		if waitErr := waitForRetry(ctx, backoffDuration(s.retryBackoff, attempt)); waitErr != nil {
			return waitErr
		}
	}
	return lastErr
}

func (s *HTTPAuditSink) Close() error { return nil }

// MultiAuditSink fans out one event to multiple sinks.
type MultiAuditSink struct {
	sinks []AuditSink
}

// NewMultiAuditSink creates a fanout sink.
func NewMultiAuditSink(sinks ...AuditSink) *MultiAuditSink {
	filtered := make([]AuditSink, 0, len(sinks))
	for _, sink := range sinks {
		if sink == nil {
			continue
		}
		filtered = append(filtered, sink)
	}
	return &MultiAuditSink{sinks: filtered}
}

func (m *MultiAuditSink) Write(ctx context.Context, event AuditEvent) error {
	var firstErr error
	for _, sink := range m.sinks {
		if err := sink.Write(ctx, event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiAuditSink) Close() error {
	var firstErr error
	for _, sink := range m.sinks {
		if err := sink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// AsyncAuditSink decouples request-path audit writes from slower downstream sinks.
type AsyncAuditSink struct {
	sink   AuditSink
	events chan AuditEvent
	wg     sync.WaitGroup

	closeOnce sync.Once
	closeCh   chan struct{}

	mu           sync.Mutex
	closed       bool
	writeErr     error
	closeErr     error
	onWriteError func(error)
}

// NewAsyncAuditSink wraps a sink with a bounded in-memory queue.
func NewAsyncAuditSink(sink AuditSink, buffer int) *AsyncAuditSink {
	if sink == nil {
		sink = NopAuditSink{}
	}
	if buffer <= 0 {
		buffer = 256
	}
	a := &AsyncAuditSink{
		sink:    sink,
		events:  make(chan AuditEvent, buffer),
		closeCh: make(chan struct{}),
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		writeEvent := func(event AuditEvent) {
			if err := a.sink.Write(context.Background(), event); err != nil {
				a.mu.Lock()
				if a.writeErr == nil {
					a.writeErr = err
				}
				onErr := a.onWriteError
				a.mu.Unlock()
				if onErr != nil {
					onErr(err)
				}
			}
		}
		for {
			select {
			case event := <-a.events:
				writeEvent(event)
			case <-a.closeCh:
				for {
					select {
					case event := <-a.events:
						writeEvent(event)
					default:
						return
					}
				}
			}
		}
	}()
	return a
}

// WithWriteErrorHandler sets a callback invoked each time the background goroutine
// fails to deliver an event to the downstream sink. Use it to log forwarding errors
// immediately instead of waiting for Close to surface them.
func (a *AsyncAuditSink) WithWriteErrorHandler(fn func(error)) *AsyncAuditSink {
	a.mu.Lock()
	a.onWriteError = fn
	a.mu.Unlock()
	return a
}

func (a *AsyncAuditSink) Write(ctx context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return fmt.Errorf("async audit sink closed")
	}
	select {
	case a.events <- event:
		return nil
	default:
		return fmt.Errorf("async audit sink queue full")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *AsyncAuditSink) Close() error {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		close(a.closeCh)
		a.wg.Wait()
		a.closeErr = a.sink.Close()
	})
	a.mu.Lock()
	defer a.mu.Unlock()
	err := a.writeErr
	if a.closeErr != nil && err == nil {
		err = a.closeErr
	}
	return err
}

// Fingerprinter produces keyed HMAC-SHA256 fingerprints for audit identifiers.
type Fingerprinter struct {
	key []byte
}

// NewFingerprinter creates a Fingerprinter that uses the given secret as the
// HMAC-SHA256 key. The secret must be non-empty in production; an empty value
// causes a panic to prevent accidental use of weak fingerprints.
func NewFingerprinter(secret string) *Fingerprinter {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		panic("audit.NewFingerprinter: secret must not be empty; set IDENTRAIL_AUDIT_FINGERPRINT_SECRET")
	}
	return &Fingerprinter{key: []byte(trimmed)}
}

func (f *Fingerprinter) hmacFingerprint(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	mac := hmac.New(sha256.New, f.key)
	mac.Write([]byte(trimmed))
	return "hmac256:" + hex.EncodeToString(mac.Sum(nil))[:24]
}

// Identifier returns a stable, keyed fingerprint suitable for correlating
// principals/resources in audit logs without exposing raw IDs.
func (f *Fingerprinter) Identifier(raw string) string {
	return f.hmacFingerprint(raw)
}

// APIKey returns a stable, keyed fingerprint for API keys in audit logs.
func (f *Fingerprinter) APIKey(raw string) string {
	return f.hmacFingerprint(raw)
}

func fingerprintAPIKey(raw string) string {
	return legacyFingerprintAuditIdentifier(raw)
}

// FingerprintAPIKey returns a stable, non-secret identifier suitable for audit logs.
// Deprecated: Use Fingerprinter.APIKey for keyed HMAC-SHA256 fingerprints.
func FingerprintAPIKey(raw string) string {
	return fingerprintAPIKey(raw)
}

func legacyFingerprintAuditIdentifier(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(trimmed))
	return fmt.Sprintf("fnv64a:%012x", hasher.Sum64()&0xFFFFFFFFFFFF)
}

// FingerprintIdentifier returns a stable, non-secret identifier suitable for
// correlating principals/resources without logging raw IDs.
// Deprecated: Use Fingerprinter.Identifier for keyed HMAC-SHA256 fingerprints.
func FingerprintIdentifier(raw string) string {
	return legacyFingerprintAuditIdentifier(raw)
}

func validateAuditForwardURL(raw string) error {
	return urlpolicy.ValidateAuditForwardURL(raw)
}

func computeHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func backoffDuration(base time.Duration, attempt int) time.Duration {
	wait := base
	for i := 0; i < attempt; i++ {
		wait *= 2
	}
	if wait > 10*time.Second {
		return 10 * time.Second
	}
	return wait
}

func (s *HTTPAuditSink) send(ctx context.Context, payload []byte) (bool, error) {
	requestCtx := ctx
	cancel := func() {}
	if s.client.Timeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, s.client.Timeout)
	}
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, s.url, bytes.NewReader(payload))
	if err != nil {
		return false, fmt.Errorf("build audit forward request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "identrail-audit/1.0")
	if s.hmacSecret != "" {
		req.Header.Set("X-Identrail-Signature", computeHMAC(payload, s.hmacSecret))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return true, fmt.Errorf("send audit event: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		retryable := resp.StatusCode >= http.StatusInternalServerError
		return retryable, fmt.Errorf("audit forward status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return false, nil
}

func waitForRetry(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
