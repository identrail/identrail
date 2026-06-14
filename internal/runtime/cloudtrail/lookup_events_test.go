package cloudtrail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeLookupEventsAPI is a deterministic LookupEventsAPI driver for
// the ingester. Each entry in scripted maps a request shape to the
// response (or error) the ingester should observe. The fake records
// every call it received so tests can assert pagination + budgets.
type fakeLookupEventsAPI struct {
	pages    []LookupEventsPage
	errs     []error
	calls    []LookupEventsInput
	maxCalls int
}

func (f *fakeLookupEventsAPI) LookupEvents(_ context.Context, input LookupEventsInput) (LookupEventsPage, error) {
	f.calls = append(f.calls, input)
	idx := len(f.calls) - 1
	if f.maxCalls > 0 && len(f.calls) > f.maxCalls {
		return LookupEventsPage{}, fmt.Errorf("fake: exceeded scripted call budget at attempt %d", len(f.calls))
	}
	if idx < len(f.errs) && f.errs[idx] != nil {
		return LookupEventsPage{}, f.errs[idx]
	}
	if idx >= len(f.pages) {
		return LookupEventsPage{}, nil
	}
	return f.pages[idx], nil
}

type codedError struct {
	code string
	msg  string
}

func (e codedError) Error() string     { return e.msg }
func (e codedError) ErrorCode() string { return e.code }

func newIngester(api LookupEventsAPI, now time.Time) (*Ingester, *[]time.Duration) {
	sleeps := []time.Duration{}
	ing := &Ingester{
		API:   api,
		Now:   func() time.Time { return now },
		Sleep: func(d time.Duration) { sleeps = append(sleeps, d) },
	}
	return ing, &sleeps
}

func cloudTrailEventJSON(arn string, principalType string, sessionID string, issuerARN string, creation time.Time, ip string, ua string) string {
	return fmt.Sprintf(`{
		"sourceIPAddress": %q,
		"userAgent": %q,
		"recipientAccountId": "123456789012",
		"awsRegion": "us-east-1",
		"userIdentity": {
			"type": %q,
			"arn": %q,
			"principalId": %q,
			"sessionContext": {
				"attributes": {"creationDate": %q, "mfaAuthenticated": "false"},
				"sessionIssuer": {"type": "Role", "arn": %q}
			}
		}
	}`, ip, ua, principalType, arn, sessionID, creation.UTC().Format(time.RFC3339), issuerARN)
}

func TestIngestMapsEventTypesAndPreservesMetadataBoundary(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess-runtime-reader"
	issuer := "arn:aws:iam::123456789012:role/identrail-runtime-reader"
	creation := now.Add(-25 * time.Minute)
	api := &fakeLookupEventsAPI{
		pages: []LookupEventsPage{{
			Events: []Event{
				{
					EventID:     "evt-sts",
					EventName:   "AssumeRole",
					EventSource: "sts.amazonaws.com",
					EventTime:   now.Add(-20 * time.Minute),
					AccessKeyID: "ASIASESSION00000000A",
					Username:    role,
					ReadOnly:    "false",
					RawEvent:    cloudTrailEventJSON(role, "AssumedRole", "AROAEXAMPLEPRINCIPAL", issuer, creation, "AWS Internal", "aws-internal/3"),
				},
				{
					EventID:     "evt-secret",
					EventName:   "GetSecretValue",
					EventSource: "secretsmanager.amazonaws.com",
					EventTime:   now.Add(-15 * time.Minute),
					AccessKeyID: "ASIASESSION00000000B",
					Username:    role,
					ReadOnly:    "true",
					Resources:   []EventResource{{ResourceType: "AWS::SecretsManager::Secret", ResourceName: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key"}},
					RawEvent:    cloudTrailEventJSON(role, "AssumedRole", "AROAEXAMPLEPRINCIPAL", issuer, creation, "10.0.0.1", "boto3/1.26"),
				},
				{
					EventID:     "evt-kms",
					EventName:   "Decrypt",
					EventSource: "kms.amazonaws.com",
					EventTime:   now.Add(-10 * time.Minute),
					Username:    role,
					ReadOnly:    "true",
					Resources:   []EventResource{{ResourceType: "AWS::KMS::Key", ResourceName: "arn:aws:kms:us-east-1:123456789012:key/abcd-ef"}},
					RawEvent:    cloudTrailEventJSON(role, "AssumedRole", "AROAEXAMPLEPRINCIPAL", issuer, creation, "10.0.0.1", "boto3/1.26"),
				},
				{
					EventID:     "evt-s3",
					EventName:   "GetObject",
					EventSource: "s3.amazonaws.com",
					EventTime:   now.Add(-5 * time.Minute),
					Username:    role,
					ReadOnly:    "true",
					Resources:   []EventResource{{ResourceType: "AWS::S3::Object", ResourceName: "arn:aws:s3:::billing-artifacts/reports/redacted"}},
					RawEvent:    cloudTrailEventJSON(role, "AssumedRole", "AROAEXAMPLEPRINCIPAL", issuer, creation, "10.0.0.1", "boto3/1.26"),
				},
				{
					EventID:     "evt-agent",
					EventName:   "InvokeTool",
					EventSource: "bedrock-agentcore.amazonaws.com",
					EventTime:   now.Add(-2 * time.Minute),
					Username:    "arn:aws:sts::123456789012:assumed-role/agentcore-case-triage-runtime/sess-agentcore",
					ReadOnly:    "false",
					RawEvent:    cloudTrailEventJSON("arn:aws:sts::123456789012:assumed-role/agentcore-case-triage-runtime/sess-agentcore", "AssumedRole", "AROAEXAMPLEAGENTCORE", "arn:aws:iam::123456789012:role/agentcore-case-triage-runtime", creation, "10.0.0.2", "agentcore/1.0"),
				},
			},
		}},
	}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready status, got %q (%+v)", result.Status, result)
	}
	if got := len(result.Events); got != 5 {
		t.Fatalf("expected 5 normalized events, got %d", got)
	}
	want := map[string]string{
		"evt-sts":    "sts-session",
		"evt-secret": "secret-read",
		"evt-kms":    "kms-decrypt",
		"evt-s3":     "api-call",
		"evt-agent":  "agent-tool",
	}
	for _, ev := range result.Events {
		if want[ev.EventID] != ev.EventType {
			t.Fatalf("event %s expected type %s, got %s", ev.EventID, want[ev.EventID], ev.EventType)
		}
		if ev.RedactionBoundary != RedactionBoundary {
			t.Fatalf("event %s lost redaction boundary: %+v", ev.EventID, ev)
		}
		if ev.AccountID != "123456789012" || ev.Region != "us-east-1" {
			t.Fatalf("event %s lost account/region scope: %+v", ev.EventID, ev)
		}
		if ev.ObservedAt.IsZero() || ev.CollectedAt.IsZero() {
			t.Fatalf("event %s missing timestamps: %+v", ev.EventID, ev)
		}
	}
	agent := findEvent(t, result.Events, "evt-agent")
	if agent.EvidenceCategory != "agent-runtime" || agent.Owner != "security" {
		t.Fatalf("agent event evidence/owner wrong: %+v", agent)
	}
	if agent.SessionIssuerARN == "" || agent.AssumedRoleARN == "" {
		t.Fatalf("expected session issuer/assumed role from payload metadata, got %+v", agent)
	}
	secret := findEvent(t, result.Events, "evt-secret")
	if !strings.Contains(secret.TargetResourceARN, "prod/openai-key") {
		t.Fatalf("expected secret arn to be preserved as resource arn, got %+v", secret)
	}
}

func TestIngestPaginatesAndRespectsBudget(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	page := func(prefix string, next string, count int) LookupEventsPage {
		p := LookupEventsPage{NextToken: next}
		for i := 0; i < count; i++ {
			p.Events = append(p.Events, Event{
				EventID:     fmt.Sprintf("%s-%d", prefix, i),
				EventName:   "AssumeRole",
				EventSource: "sts.amazonaws.com",
				EventTime:   now.Add(time.Duration(-i) * time.Minute),
				Username:    "arn:aws:sts::123456789012:assumed-role/role/role-session",
			})
		}
		return p
	}
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{
		page("p1", "next-token-1", 3),
		page("p2", "next-token-2", 3),
		page("p3", "", 3),
	}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(api.calls) != 3 {
		t.Fatalf("expected 3 LookupEvents calls, got %d", len(api.calls))
	}
	if api.calls[1].NextToken != "next-token-1" || api.calls[2].NextToken != "next-token-2" {
		t.Fatalf("expected NextToken pagination, got %+v", api.calls)
	}
	if result.PagesFetched != 3 || len(result.Events) != 9 || result.HistoryTruncated {
		t.Fatalf("expected 9 events with 3 pages no truncation, got %+v", result)
	}

	// Now exercise the per-run MaxEvents budget.
	api = &fakeLookupEventsAPI{pages: []LookupEventsPage{
		page("p1", "next-token-1", 3),
		page("p2", "next-token-2", 3),
		page("p3", "next-token-3", 3),
	}}
	ing, _ = newIngester(api, now)
	result, err = ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", MaxEvents: 4})
	if err != nil {
		t.Fatalf("ingest budget: %v", err)
	}
	if !result.HistoryTruncated || len(result.Events) != 4 {
		t.Fatalf("expected truncation at 4 events, got %+v", result)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected truncated status to be degraded, got %q", result.Status)
	}
	hasTruncationGap := false
	for _, gap := range result.CoverageGaps {
		if gap.Status == "history_truncated" {
			hasTruncationGap = true
		}
	}
	if !hasTruncationGap {
		t.Fatalf("expected history_truncated coverage gap, got %+v", result.CoverageGaps)
	}
}

func TestIngestDeduplicatesEventID(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{
		NextToken: "next-token",
		Events: []Event{
			{EventID: "evt-1", EventName: "AssumeRole", EventSource: "sts.amazonaws.com", EventTime: now.Add(-10 * time.Minute)},
		},
	}, {
		Events: []Event{
			{EventID: "evt-1", EventName: "AssumeRole", EventSource: "sts.amazonaws.com", EventTime: now.Add(-9 * time.Minute)},
			{EventID: "evt-2", EventName: "Decrypt", EventSource: "kms.amazonaws.com", EventTime: now.Add(-8 * time.Minute)},
		},
	}}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected dedupe by EventID to leave 2 events, got %d (%+v)", len(result.Events), result.Events)
	}
}

func TestIngestRetriesThrottlingThenSurfacesDiagnostic(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	throttle := codedError{code: "ThrottlingException", msg: "Rate exceeded (ThrottlingException)"}
	api := &fakeLookupEventsAPI{
		errs: []error{throttle, throttle, nil},
		pages: []LookupEventsPage{
			{}, {}, {Events: []Event{{
				EventID:     "evt-1",
				EventName:   "AssumeRole",
				EventSource: "sts.amazonaws.com",
				EventTime:   now.Add(-5 * time.Minute),
				Username:    "arn:aws:sts::123456789012:assumed-role/role/role-session",
			}}},
		},
	}
	ing, sleeps := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", ThrottleBackoff: 10 * time.Millisecond, MaxThrottleRetries: 3})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(*sleeps) < 2 {
		t.Fatalf("expected backoff sleeps for throttle retries, got %v", *sleeps)
	}
	if result.Status != "ready" || len(result.Events) != 1 {
		t.Fatalf("expected ready after retry success with 1 event, got %+v", result)
	}

	// Now exhaust retries: surface diagnostic, preserve partial events
	// from prior pages — here there are none so result is degraded
	// with an empty event set.
	api = &fakeLookupEventsAPI{errs: []error{throttle, throttle, throttle, throttle, throttle}}
	ing, _ = newIngester(api, now)
	result, err = ing.Ingest(context.Background(), IngestRequest{
		AccountID:          "123456789012",
		Region:             "us-east-1",
		MaxThrottleRetries: 2,
		ThrottleBackoff:    1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ingest throttle exhaust: %v", err)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected degraded after throttle exhaust, got %+v", result)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "cloudtrail_lookup_events_throttled" {
		t.Fatalf("expected throttle diagnostic, got %+v", result.Diagnostics)
	}
}

func TestParseSessionTimeAcceptsCloudTrailBasicISO8601(t *testing.T) {
	// CloudTrail's userIdentity sessionContext.attributes.creationDate
	// is documented as basic ISO-8601 (e.g. `20131102T010628Z`), so
	// the parser must accept that layout in addition to the dashed
	// RFC3339 forms. Without this, live assumed-role events would
	// leave SessionStartedAt zero even though CloudTrail supplied the
	// session start.
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "cloudtrail basic", value: "20131102T010628Z"},
		{name: "cloudtrail basic with millis", value: "20131102T010628.123Z"},
		{name: "rfc3339 dashed", value: "2013-11-02T01:06:28Z"},
		{name: "rfc3339 nano", value: "2013-11-02T01:06:28.123456789Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSessionTime(tc.value)
			if err != nil {
				t.Fatalf("parseSessionTime(%q): %v", tc.value, err)
			}
			if got.IsZero() {
				t.Fatalf("parseSessionTime(%q) returned zero time", tc.value)
			}
			if got.Year() != 2013 || got.Month() != 11 || got.Day() != 2 {
				t.Fatalf("parseSessionTime(%q) = %s, expected 2013-11-02", tc.value, got)
			}
		})
	}
}

func TestNormalizeEventLeavesSessionExpiresAtUnsetWhenUnknown(t *testing.T) {
	// STS supports role session durations from 15 minutes to 12
	// hours. Synthesising a +1h expiry would make long-running
	// sessions look expired and short sessions look still valid;
	// the field must stay zero so consumers know the expiration was
	// not extracted.
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess-runtime-reader"
	issuer := "arn:aws:iam::123456789012:role/identrail-runtime-reader"
	creation := now.Add(-25 * time.Minute)
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{Events: []Event{{
		EventID:     "evt-sts",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		EventTime:   now.Add(-20 * time.Minute),
		Username:    role,
		RawEvent:    cloudTrailEventJSON(role, "AssumedRole", "AROAEXAMPLE", issuer, creation, "10.0.0.1", "boto3"),
	}}}}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %+v", result.Events)
	}
	ev := result.Events[0]
	if ev.SessionStartedAt.IsZero() {
		t.Fatalf("expected SessionStartedAt set from payload metadata, got zero")
	}
	if !ev.SessionExpiresAt.IsZero() {
		t.Fatalf("SessionExpiresAt must stay zero when the real expiry isn't extracted, got %s", ev.SessionExpiresAt)
	}
}

func TestClassifyGetFederationTokenAsSTSSession(t *testing.T) {
	// GetFederationToken creates a federated-user temporary credential
	// session. CloudTrail emits it on sts.amazonaws.com, so a request
	// for event_type=sts-session pushes the secretsmanager.amazonaws.com
	// pushdown ... wait, it pushes sts.amazonaws.com and then the
	// record-level filter compares against event_type=sts-session. If
	// the normalizer classifies these as api-call, the filter drops
	// them and STSSessionCount undercounts federated workloads.
	if got := classifyEventType("sts.amazonaws.com", "GetFederationToken"); got != "sts-session" {
		t.Fatalf("expected GetFederationToken to classify as sts-session, got %q", got)
	}
	// Sanity check: AssumeRole + GetSessionToken still classify too.
	if got := classifyEventType("sts.amazonaws.com", "AssumeRole"); got != "sts-session" {
		t.Fatalf("expected AssumeRole to classify as sts-session, got %q", got)
	}
	if got := classifyEventType("sts.amazonaws.com", "GetSessionToken"); got != "sts-session" {
		t.Fatalf("expected GetSessionToken to classify as sts-session, got %q", got)
	}
}

func TestMapPrincipalTypeProducesSnakeCaseContractTokens(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{in: "AssumedRole", want: "assumed_role"},
		{in: "IAMUser", want: "iam_user"},
		{in: "Root", want: "root"},
		{in: "FederatedUser", want: "federated_user"},
		{in: "AWSAccount", want: "aws_account"},
		{in: "AWSService", want: "aws_service"},
		{in: "WebIdentityUser", want: "web_identity_user"},
		{in: "SAMLUser", want: "saml_user"},
		{in: "Unknown", want: "unknown"},
		// Unknown CloudTrail types fall back to a snake_case
		// projection, never camel-case, so they stay in the same
		// token space as the fixture contract.
		{in: "FutureWeirdType", want: "future_weird_type"},
		{in: "", want: ""},
	} {
		if got := mapPrincipalType(tc.in); got != tc.want {
			t.Errorf("mapPrincipalType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestClassifyBatchGetSecretValueAsSecretRead(t *testing.T) {
	// CloudTrail emits BatchGetSecretValue for the Secrets Manager
	// batch API; without this case the live response classifies them
	// as generic api-call and a `event_type=secret-read` filter
	// drops them after the EventSource pushdown already fetched them.
	if got := classifyEventType("secretsmanager.amazonaws.com", "BatchGetSecretValue"); got != "secret-read" {
		t.Fatalf("expected BatchGetSecretValue to classify as secret-read, got %q", got)
	}
	// Sanity check: GetSecretValue still classifies as secret-read.
	if got := classifyEventType("secretsmanager.amazonaws.com", "GetSecretValue"); got != "secret-read" {
		t.Fatalf("expected GetSecretValue to classify as secret-read, got %q", got)
	}
}

func TestIngestExpiredTokenIsTransientNotBlocked(t *testing.T) {
	// ExpiredToken means the assumed-role session aged out; a retry
	// with refreshed credentials succeeds. Treating it as
	// permission_denied would collapse the response to
	// status=blocked and discard the events already ingested. It
	// must instead degrade with a retryable diagnostic.
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	expired := codedError{code: "ExpiredToken", msg: "The security token included in the request is expired (ExpiredToken)"}
	api := &fakeLookupEventsAPI{errs: []error{expired}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Status == "blocked" {
		t.Fatalf("ExpiredToken must not collapse to status=blocked, got %+v", result)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected degraded status for ExpiredToken, got %q (%+v)", result.Status, result)
	}
	if len(result.Diagnostics) == 0 || !result.Diagnostics[0].Retryable {
		t.Fatalf("expected retryable transient diagnostic, got %+v", result.Diagnostics)
	}
}

func TestErrorMatchesAnyIsCaseInsensitiveOnUnwrappedMessage(t *testing.T) {
	// Some SDK error wrappers lowercase the embedded code; the
	// substring scan must still classify them so throttling /
	// permission denial don't slip into the generic transient bucket.
	for _, tc := range []struct {
		name       string
		err        error
		throttle   bool
		permDenied bool
	}{
		{name: "lowercased throttling embedded in error string", err: errors.New("operation error CloudTrail: lookupevents, https response error StatusCode: 400, RequestID: x, throttlingexception: Rate exceeded"), throttle: true},
		{name: "mixed-case accessdenied", err: errors.New("AccessDeniedException: cloudtrail:LookupEvents is not allowed"), permDenied: true},
		{name: "lowercased accessdenied", err: errors.New("api error accessdeniedexception: user lacks cloudtrail:LookupEvents"), permDenied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isThrottling(tc.err); got != tc.throttle {
				t.Fatalf("isThrottling=%v, want %v", got, tc.throttle)
			}
			if got := isPermissionDenied(tc.err); got != tc.permDenied {
				t.Fatalf("isPermissionDenied=%v, want %v", got, tc.permDenied)
			}
		})
	}
}

func TestIngestSurfacesPermissionDeniedAsBlocked(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	denied := codedError{code: "AccessDeniedException", msg: "User is not authorized to perform cloudtrail:LookupEvents (AccessDeniedException)"}
	api := &fakeLookupEventsAPI{errs: []error{denied}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest denied: %v", err)
	}
	if result.Status != "blocked" {
		t.Fatalf("expected blocked status on permission denied, got %+v", result)
	}
	if len(result.Events) != 0 {
		t.Fatalf("permission_denied must drop ingested events, got %d", len(result.Events))
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "permission_denied" {
		t.Fatalf("expected single permission_denied diagnostic, got %+v", result.Diagnostics)
	}
	if len(result.CoverageGaps) != 1 || result.CoverageGaps[0].Status != "permission_denied" {
		t.Fatalf("expected permission_denied coverage gap, got %+v", result.CoverageGaps)
	}
}

func TestIngestEmptyWindowReturnsDegradedNotBlocked(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{}}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest empty: %v", err)
	}
	if result.Status != "degraded" {
		t.Fatalf("empty window should be degraded, not blocked, got %q", result.Status)
	}
	if len(result.CoverageGaps) != 1 || result.CoverageGaps[0].Status != "empty" {
		t.Fatalf("empty coverage gap missing: %+v", result.CoverageGaps)
	}
}

func TestIngestExactBudgetFillWithoutMorePagesIsNotTruncated(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	makePage := func(prefix string, next string, count int) LookupEventsPage {
		p := LookupEventsPage{NextToken: next}
		for i := 0; i < count; i++ {
			p.Events = append(p.Events, Event{
				EventID:     fmt.Sprintf("%s-%d", prefix, i),
				EventName:   "AssumeRole",
				EventSource: "sts.amazonaws.com",
				EventTime:   now.Add(time.Duration(-i) * time.Minute),
				Username:    "arn:aws:sts::123456789012:assumed-role/role/role-session",
			})
		}
		return p
	}

	for _, tc := range []struct {
		name      string
		pages     []LookupEventsPage
		maxEvents int
		truncated bool
		status    string
	}{
		{
			name:      "exact fill on single page with no next token",
			pages:     []LookupEventsPage{makePage("p", "", 5)},
			maxEvents: 5,
			truncated: false,
			status:    "ready",
		},
		{
			name:      "exact fill on last page of multi-page with no next token",
			pages:     []LookupEventsPage{makePage("p1", "tok-1", 3), makePage("p2", "", 2)},
			maxEvents: 5,
			truncated: false,
			status:    "ready",
		},
		{
			name:      "exact fill on page with next token signals more available",
			pages:     []LookupEventsPage{makePage("p1", "tok-1", 5)},
			maxEvents: 5,
			truncated: true,
			status:    "degraded",
		},
		{
			name:      "budget fills mid-page leaves unread records on the page",
			pages:     []LookupEventsPage{makePage("p1", "", 7)},
			maxEvents: 4,
			truncated: true,
			status:    "degraded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeLookupEventsAPI{pages: tc.pages}
			ing, _ := newIngester(api, now)
			result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", MaxEvents: tc.maxEvents})
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			if result.HistoryTruncated != tc.truncated {
				t.Fatalf("expected HistoryTruncated=%v, got %v (%+v)", tc.truncated, result.HistoryTruncated, result)
			}
			if result.Status != tc.status {
				t.Fatalf("expected status=%q, got %q (%+v)", tc.status, result.Status, result)
			}
			if !tc.truncated {
				for _, gap := range result.CoverageGaps {
					if gap.Status == "history_truncated" {
						t.Fatalf("complete run must not emit history_truncated coverage gap, got %+v", result.CoverageGaps)
					}
				}
			}
		})
	}
}

func TestIngestDowngradesToDegradedWhenNormalizationEmitsDiagnostics(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{
		Events: []Event{
			{
				EventID:     "evt-good",
				EventName:   "AssumeRole",
				EventSource: "sts.amazonaws.com",
				EventTime:   now.Add(-5 * time.Minute),
				Username:    "arn:aws:sts::123456789012:assumed-role/role/role-session",
			},
			{
				// CloudTrailEvent JSON is unparseable — falls back to
				// top-level metadata and emits a diagnostic.
				EventID:     "evt-bad-json",
				EventName:   "AssumeRole",
				EventSource: "sts.amazonaws.com",
				EventTime:   now.Add(-4 * time.Minute),
				Username:    "arn:aws:sts::123456789012:assumed-role/role/role-session",
				RawEvent:    "{not-json",
			},
		},
	}}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected both events preserved (one cleanly normalized, one fallback), got %+v", result.Events)
	}
	if result.Status != "degraded" {
		t.Fatalf("normalization diagnostics must downgrade live status to degraded, got %q (%+v)", result.Status, result)
	}
	foundReason := false
	for _, reason := range result.FailureReasons {
		if reason == "CloudTrail LookupEvents ingestion returned diagnostics" {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("expected diagnostic-driven failure reason, got %+v", result.FailureReasons)
	}
}

func TestIngestPropagatesContextCancellationInsteadOfDegrading(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{errs: []error{context.Canceled}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled to propagate, got err=%v result=%+v", err, result)
	}
	if result.Status == "degraded" || len(result.Diagnostics) > 0 {
		t.Fatalf("canceled context must not be surfaced as a degraded CloudTrail result, got %+v", result)
	}

	api = &fakeLookupEventsAPI{errs: []error{context.DeadlineExceeded}}
	ing, _ = newIngester(api, now)
	result, err = ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded to propagate, got err=%v result=%+v", err, result)
	}
	if result.Status == "degraded" || len(result.Diagnostics) > 0 {
		t.Fatalf("deadline exceeded must not be surfaced as a degraded CloudTrail result, got %+v", result)
	}
}

func TestIngestPartialFailureFromNonThrottleError(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{
		pages: []LookupEventsPage{
			{NextToken: "tok-1", Events: []Event{{EventID: "evt-1", EventName: "AssumeRole", EventSource: "sts.amazonaws.com", EventTime: now.Add(-2 * time.Minute)}}},
		},
		errs: []error{nil, errors.New("transient cloudtrail io error")},
	}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected degraded on mid-pagination error, got %q", result.Status)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected to preserve events from first page, got %+v", result.Events)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "cloudtrail_lookup_events_failed" {
		t.Fatalf("expected partial-failure diagnostic, got %+v", result.Diagnostics)
	}
}

func TestIngestDropsEventsWithMissingCoreFields(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{
		Events: []Event{
			{EventID: "evt-ok", EventName: "AssumeRole", EventSource: "sts.amazonaws.com", EventTime: now.Add(-5 * time.Minute)},
			{EventID: "", EventName: "AssumeRole", EventSource: "sts.amazonaws.com"},
			{EventID: "evt-missing-name", EventSource: "sts.amazonaws.com"},
		},
	}}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected the malformed events to be skipped, kept=%+v", result.Events)
	}
	if len(result.Diagnostics) < 2 {
		t.Fatalf("expected diagnostics for both malformed events, got %+v", result.Diagnostics)
	}
}

func TestIngestEventSourceFilterAppliedToCloudTrailRequest(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{}}}
	ing, _ := newIngester(api, now)
	if _, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID:         "123456789012",
		Region:            "us-east-1",
		EventSourceFilter: "kms.amazonaws.com",
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(api.calls) != 1 || api.calls[0].Attributes.Key != "EventSource" || api.calls[0].Attributes.Value != "kms.amazonaws.com" {
		t.Fatalf("expected EventSource filter pushed to CloudTrail, got %+v", api.calls)
	}

	// MutationOnly toggles ReadOnly=false.
	api = &fakeLookupEventsAPI{pages: []LookupEventsPage{{}}}
	ing, _ = newIngester(api, now)
	if _, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", MutationOnly: true}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if api.calls[0].Attributes.Key != "ReadOnly" || api.calls[0].Attributes.Value != "false" {
		t.Fatalf("expected ReadOnly=false attribute, got %+v", api.calls[0].Attributes)
	}
}

func TestIngestEventOrderingByObservedAt(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{
		Events: []Event{
			{EventID: "evt-c", EventName: "AssumeRole", EventSource: "sts.amazonaws.com", EventTime: now.Add(-1 * time.Minute)},
			{EventID: "evt-a", EventName: "Decrypt", EventSource: "kms.amazonaws.com", EventTime: now.Add(-30 * time.Minute)},
			{EventID: "evt-b", EventName: "GetSecretValue", EventSource: "secretsmanager.amazonaws.com", EventTime: now.Add(-15 * time.Minute)},
		},
	}}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := []string{result.Events[0].EventID, result.Events[1].EventID, result.Events[2].EventID}; got[0] != "evt-a" || got[1] != "evt-b" || got[2] != "evt-c" {
		t.Fatalf("expected ascending observed_at order, got %+v", got)
	}
}

func TestNormalizeEventToleratesUnparseablePayload(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	raw := Event{
		EventID:     "evt-bad-json",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		EventTime:   now,
		Username:    "arn:aws:iam::123456789012:role/r",
		RawEvent:    "{not-json",
	}
	got, diag, ok := normalizeEvent(raw, "123456789012", "us-east-1")
	if !ok {
		t.Fatalf("expected normalization to fall back to core fields when JSON is unparseable")
	}
	if diag == nil || diag.Code != "cloudtrail_event_payload_unparseable" {
		t.Fatalf("expected payload-unparseable diagnostic, got %+v", diag)
	}
	if got.EventID != "evt-bad-json" {
		t.Fatalf("expected core fields to land, got %+v", got)
	}
}

func TestIngestLookbackWindowClampedAndPushedToCloudTrail(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{}}}
	ing, _ := newIngester(api, now)
	if _, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		LookbackWindow: 365 * 24 * time.Hour, // > 90d, expect clamp
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := now.Sub(api.calls[0].StartTime); got != MaxLookbackWindow {
		t.Fatalf("expected lookback clamped to MaxLookbackWindow, got %s", got)
	}
}

func findEvent(t *testing.T, events []NormalizedEvent, id string) NormalizedEvent {
	t.Helper()
	for _, ev := range events {
		if ev.EventID == id {
			return ev
		}
	}
	t.Fatalf("event %q not in result", id)
	return NormalizedEvent{}
}
