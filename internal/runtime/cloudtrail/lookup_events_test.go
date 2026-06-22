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

func cloudTrailAssumeRoleEventJSON(callerARN string, principalType string, sessionID string, issuerARN string, roleARN string, roleSessionName string, sourceIdentity string, creation time.Time) string {
	return fmt.Sprintf(`{
		"sourceIPAddress": "AWS Internal",
		"userAgent": "aws-sdk-go-v2/1.0",
		"recipientAccountId": "123456789012",
		"awsRegion": "us-east-1",
		"userIdentity": {
			"type": %q,
			"arn": %q,
			"principalId": %q,
			"sessionContext": {
				"sourceIdentity": %q,
				"attributes": {"creationDate": %q},
				"sessionIssuer": {"type": "Role", "arn": %q}
			}
		},
		"requestParameters": {
			"roleArn": %q,
			"roleSessionName": %q,
			"sourceIdentity": %q,
			"tags": [
				{"key": "owner", "value": "redacted-by-normalizer"},
				{"key": "environment", "value": "prod"},
				{"key": "owner", "value": "duplicate"}
			],
			"transitiveTagKeys": ["owner", "environment", "owner"]
		}
	}`, principalType, callerARN, sessionID, sourceIdentity, creation.UTC().Format(time.RFC3339), issuerARN, roleARN, roleSessionName, sourceIdentity)
}

func cloudTrailFederatedAssumeRoleEventJSON(identityProvider string, principalID string, principalARN string, roleARN string, roleSessionName string, sourceIdentity string) string {
	return fmt.Sprintf(`{
		"recipientAccountId": "123456789012",
		"awsRegion": "us-east-1",
		"userIdentity": {
			"type": "SAMLUser",
			"principalId": %q,
			"identityProvider": %q
		},
		"requestParameters": {
			"principalArn": %q,
			"roleArn": %q,
			"roleSessionName": %q,
			"sourceIdentity": %q
		}
	}`, principalID, identityProvider, principalARN, roleARN, roleSessionName, sourceIdentity)
}

func cloudTrailWebIdentityAssumeRoleEventJSON(identityProvider string, principalID string, roleARN string, roleSessionName string, sourceIdentity string) string {
	return fmt.Sprintf(`{
		"recipientAccountId": "123456789012",
		"awsRegion": "us-east-1",
		"userIdentity": {
			"type": "WebIdentityUser",
			"principalId": %q,
			"identityProvider": %q
		},
		"requestParameters": {
			"roleArn": %q,
			"roleSessionName": %q,
			"sourceIdentity": %q
		}
	}`, principalID, identityProvider, roleARN, roleSessionName, sourceIdentity)
}

func cloudTrailTaggedResourceEventJSON(callerARN string, sessionID string, issuerARN string, creation time.Time) string {
	return fmt.Sprintf(`{
		"sourceIPAddress": "10.0.0.8",
		"userAgent": "aws-sdk-go-v2/1.0",
		"recipientAccountId": "123456789012",
		"awsRegion": "us-east-1",
		"userIdentity": {
			"type": "AssumedRole",
			"arn": %q,
			"principalId": %q,
			"sessionContext": {
				"attributes": {"creationDate": %q},
				"sessionIssuer": {"type": "Role", "arn": %q}
			}
		},
		"requestParameters": {
			"sourceIdentity": "resource-api-source-identity",
			"tags": [
				{"key": "owner", "value": "resource-owner"},
				{"key": "environment", "value": "prod"}
			],
			"transitiveTagKeys": ["owner", "environment"]
		}
	}`, callerARN, sessionID, creation.UTC().Format(time.RFC3339), issuerARN)
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

func TestIngestResolvesAssumeRoleSourceIdentityLineage(t *testing.T) {
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	caller := "arn:aws:sts::123456789012:assumed-role/ci-deploy/deploy-session"
	callerIssuer := "arn:aws:iam::123456789012:role/ci-deploy"
	targetRole := "arn:aws:iam::123456789012:role/payments-runtime"
	api := &fakeLookupEventsAPI{
		pages: []LookupEventsPage{{
			Events: []Event{{
				EventID:     "evt-assume-payments",
				EventName:   "AssumeRole",
				EventSource: "sts.amazonaws.com",
				EventTime:   now.Add(-3 * time.Minute),
				AccessKeyID: "ASIAASSUMEROLE",
				Username:    caller,
				ReadOnly:    "false",
				RawEvent:    cloudTrailAssumeRoleEventJSON(caller, "AssumedRole", "AROAEXAMPLE:deploy-session", callerIssuer, targetRole, "payments-job-42", "github-actions:deploy", now.Add(-5*time.Minute)),
			}},
		}},
	}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected one normalized event, got %+v", result.Events)
	}
	event := result.Events[0]
	if event.EventType != "sts-session" || event.TargetResourceARN != targetRole || event.TargetResourceType != "iam_role" {
		t.Fatalf("expected AssumeRole target role normalization, got %+v", event)
	}
	if event.SourceIdentity != "github-actions:deploy" || event.RoleSessionName != "payments-job-42" {
		t.Fatalf("expected source identity and role session name, got %+v", event)
	}
	if event.LineageStatus != "resolved" || event.OriginalActorARN != caller || event.ChainedFromARN != caller {
		t.Fatalf("expected resolved chained lineage, got %+v", event)
	}
	if got := strings.Join(event.SessionTagKeys, ","); got != "environment,owner" {
		t.Fatalf("expected sorted redacted session tag keys, got %q", got)
	}
	if got := strings.Join(event.TransitiveTagKeys, ","); got != "environment,owner" {
		t.Fatalf("expected sorted transitive tag keys, got %q", got)
	}
}

func TestIngestMapsFederatedAssumeRoleActorLineage(t *testing.T) {
	now := time.Date(2026, 6, 15, 10, 20, 0, 0, time.UTC)
	samlProvider := "saml:namequalifier:corp"
	targetRole := "arn:aws:iam::123456789012:role/federated-prod"
	samlProviderARN := "arn:aws:iam::123456789012:saml-provider/ExampleIdP"
	oidcProviderARN := "arn:aws:iam::123456789012:oidc-provider/accounts.google.com"
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{
		Events: []Event{{
			EventID:     "evt-assume-saml",
			EventName:   "AssumeRoleWithSAML",
			EventSource: "sts.amazonaws.com",
			EventTime:   now.Add(-3 * time.Minute),
			RawEvent:    cloudTrailFederatedAssumeRoleEventJSON(samlProvider, "saml:namequalifier:corp:alice", samlProviderARN, targetRole, "saml-session", "saml:alice"),
		}, {
			EventID:     "evt-assume-web-identity",
			EventName:   "AssumeRoleWithWebIdentity",
			EventSource: "sts.amazonaws.com",
			EventTime:   now.Add(-2 * time.Minute),
			RawEvent:    cloudTrailWebIdentityAssumeRoleEventJSON(oidcProviderARN, "arn:aws:iam::123456789012:oidc-provider/accounts.google.com:app:user-id", targetRole, "web-identity-session", "oidc:alice"),
		}},
	}}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected two normalized events, got %+v", result.Events)
	}
	wantActors := map[string]string{
		"evt-assume-saml":         samlProvider,
		"evt-assume-web-identity": oidcProviderARN,
	}
	for _, event := range result.Events {
		wantActor := wantActors[event.EventID]
		if event.ActorPrincipalARN != wantActor || event.OriginalActorARN != wantActor {
			t.Fatalf("expected federated actor lineage from %q, got %+v", wantActor, event)
		}
		if event.TargetResourceARN != targetRole || event.AssumedRoleARN != targetRole {
			t.Fatalf("expected federated target role normalization, got %+v", event)
		}
		if event.LineageStatus != "resolved" {
			t.Fatalf("expected resolved federated lineage, got %+v", event)
		}
	}
}

func TestIngestMarksMissingSourceIdentityExplicitly(t *testing.T) {
	now := time.Date(2026, 6, 15, 10, 30, 0, 0, time.UTC)
	role := "arn:aws:sts::123456789012:assumed-role/payments-runtime/payments-job-43"
	issuer := "arn:aws:iam::123456789012:role/payments-runtime"
	api := &fakeLookupEventsAPI{
		pages: []LookupEventsPage{{
			Events: []Event{{
				EventID:     "evt-secret-no-source-id",
				EventName:   "GetSecretValue",
				EventSource: "secretsmanager.amazonaws.com",
				EventTime:   now.Add(-2 * time.Minute),
				Username:    role,
				Resources:   []EventResource{{ResourceType: "AWS::SecretsManager::Secret", ResourceName: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/payments"}},
				RawEvent:    cloudTrailEventJSON(role, "AssumedRole", "AROAEXAMPLE:payments-job-43", issuer, now.Add(-10*time.Minute), "10.0.0.5", "boto3/1.26"),
			}},
		}},
	}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	event := findEvent(t, result.Events, "evt-secret-no-source-id")
	if event.LineageStatus != "source_identity_missing" {
		t.Fatalf("expected missing SourceIdentity to be explicit, got %+v", event)
	}
	if !strings.Contains(event.LineageReason, "SourceIdentity") {
		t.Fatalf("expected SourceIdentity remediation reason, got %+v", event)
	}
	if event.ChainedFromARN != "" {
		t.Fatalf("non-STS assumed-role activity must not be marked as role chaining, got %+v", event)
	}
}

func TestNormalizeEventIgnoresNonSTSRequestParametersForSessionLineage(t *testing.T) {
	now := time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC)
	role := "arn:aws:sts::123456789012:assumed-role/payments-runtime/payments-job-44"
	issuer := "arn:aws:iam::123456789012:role/payments-runtime"
	raw := Event{
		EventID:     "evt-tag-resource",
		EventName:   "TagResource",
		EventSource: "secretsmanager.amazonaws.com",
		EventTime:   now.Add(-2 * time.Minute),
		Username:    role,
		Resources:   []EventResource{{ResourceType: "AWS::SecretsManager::Secret", ResourceName: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/payments"}},
		RawEvent:    cloudTrailTaggedResourceEventJSON(role, "AROAEXAMPLE:payments-job-44", issuer, now.Add(-10*time.Minute)),
	}

	events, diag, ok := normalizeEvent(raw, "123456789012", "us-east-1", now)
	if !ok {
		t.Fatalf("expected normalization to succeed")
	}
	if diag != nil {
		t.Fatalf("expected no diagnostic, got %+v", diag)
	}
	if len(events) != 1 {
		t.Fatalf("expected one normalized event, got %+v", events)
	}
	event := events[0]
	if event.SourceIdentity != "" {
		t.Fatalf("non-STS request sourceIdentity must not be treated as session SourceIdentity, got %+v", event)
	}
	if len(event.SessionTagKeys) != 0 || len(event.TransitiveTagKeys) != 0 {
		t.Fatalf("non-STS request tags must not be treated as session tags, got %+v", event)
	}
	if event.ChainedFromARN != "" {
		t.Fatalf("non-STS assumed-role activity must not create role chaining lineage, got %+v", event)
	}
	if event.LineageStatus != "source_identity_missing" {
		t.Fatalf("expected session lineage to remain missing SourceIdentity, got %+v", event)
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

func TestIngestSurfacesTruncationEvenWhenAllEventsSkipped(t *testing.T) {
	// When CloudTrail returns events but every page's events are
	// dropped during normalization (e.g. all missing core fields),
	// result.Events ends up empty AND HistoryTruncated may still be
	// true because the budget was exhausted. The finalize step must
	// emit the history_truncated coverage gap instead of hiding it
	// behind the empty-window branch.
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	makeBadPage := func(prefix string, next string) LookupEventsPage {
		return LookupEventsPage{
			NextToken: next,
			Events: []Event{
				// Missing EventName/EventSource → normalizer drops + emits
				// "cloudtrail_event_missing_core_fields" diagnostic.
				{EventID: prefix + "-1", EventTime: now.Add(-5 * time.Minute)},
				{EventID: prefix + "-2", EventTime: now.Add(-4 * time.Minute)},
			},
		}
	}
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{
		makeBadPage("p1", "tok-1"),
		makeBadPage("p2", "tok-2"),
	}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID: "123456789012",
		Region:    "us-east-1",
		MaxPages:  2, // exhaust after the second page, leaving tok-2 unread
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("expected zero normalized events (all skipped), got %+v", result.Events)
	}
	if !result.HistoryTruncated {
		t.Fatalf("expected HistoryTruncated when budget exhausted with unread NextToken")
	}
	foundTruncated := false
	foundEmpty := false
	for _, gap := range result.CoverageGaps {
		if gap.Status == "history_truncated" {
			foundTruncated = true
		}
		if gap.Status == "empty" {
			foundEmpty = true
		}
	}
	if !foundTruncated {
		t.Fatalf("expected history_truncated coverage gap to be emitted even with zero records, got %+v", result.CoverageGaps)
	}
	if foundEmpty {
		t.Fatalf("empty coverage gap must not co-emit with history_truncated; the trail had more events to scan, got %+v", result.CoverageGaps)
	}
}

func TestIngestCapsMultiResourceFanOutAtMaxEventsBudget(t *testing.T) {
	// A single CloudTrail event that normalizes into many records
	// (e.g. BatchGetSecretValue with 7 resources) must not bypass
	// the per-run MaxEvents cap. The ingester trims the fan-out to
	// the remaining budget and marks the run truncated.
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	resources := []EventResource{}
	for i := 0; i < 7; i++ {
		resources = append(resources, EventResource{
			ResourceType: "AWS::SecretsManager::Secret",
			ResourceName: fmt.Sprintf("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/%d", i),
		})
	}
	api := &fakeLookupEventsAPI{pages: []LookupEventsPage{{Events: []Event{{
		EventID:     "evt-batch",
		EventName:   "BatchGetSecretValue",
		EventSource: "secretsmanager.amazonaws.com",
		EventTime:   now.Add(-5 * time.Minute),
		Username:    "arn:aws:sts::123456789012:assumed-role/r/s",
		Resources:   resources,
	}}}}}
	ing, _ := newIngester(api, now)
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", MaxEvents: 4})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 4 {
		t.Fatalf("expected MaxEvents=4 to cap fan-out, got %d records", len(result.Events))
	}
	if !result.HistoryTruncated {
		t.Fatalf("expected HistoryTruncated=true when fan-out is trimmed")
	}
}

func TestNormalizeEventFansOutPerResourceForMultiResourceCalls(t *testing.T) {
	// CloudTrail BatchGetSecretValue can touch several secrets in
	// one call. The normalizer must emit one normalized event per
	// Resources entry — with a deterministic suffixed EventID — so
	// the resource-level filter, the relationship builder, and the
	// per-resource summary counts all see every secret.
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	raw := Event{
		EventID:     "evt-batch",
		EventName:   "BatchGetSecretValue",
		EventSource: "secretsmanager.amazonaws.com",
		EventTime:   now.Add(-5 * time.Minute),
		Username:    "arn:aws:sts::123456789012:assumed-role/role/sess",
		Resources: []EventResource{
			{ResourceType: "AWS::SecretsManager::Secret", ResourceName: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db"},
			{ResourceType: "AWS::SecretsManager::Secret", ResourceName: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api"},
			{ResourceType: "AWS::SecretsManager::Secret", ResourceName: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/oauth"},
		},
	}
	got, diag, ok := normalizeEvent(raw, "123456789012", "us-east-1", now)
	if !ok {
		t.Fatalf("expected normalization to succeed")
	}
	if diag != nil {
		t.Fatalf("expected no diagnostic, got %+v", diag)
	}
	if len(got) != 3 {
		t.Fatalf("expected one normalized event per resource, got %d", len(got))
	}
	if got[0].EventID != "evt-batch" || got[1].EventID != "evt-batch#1" || got[2].EventID != "evt-batch#2" {
		t.Fatalf("expected suffixed event ids, got %q/%q/%q", got[0].EventID, got[1].EventID, got[2].EventID)
	}
	for i, want := range []string{"prod/db", "prod/api", "prod/oauth"} {
		if !strings.Contains(got[i].TargetResourceARN, want) {
			t.Fatalf("expected per-resource ARN containing %q at idx %d, got %q", want, i, got[i].TargetResourceARN)
		}
	}
}

func TestNormalizeEventStampsCollectedAtWithRunTime(t *testing.T) {
	// Live records must carry the actual ingestion-run timestamp in
	// collected_at, not `observed_at + 2min`. Events near the start
	// of the 90-minute lookback would otherwise look as if Identrail
	// collected them over an hour earlier, breaking freshness checks
	// and audit ordering.
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	observed := now.Add(-85 * time.Minute)
	raw := Event{
		EventID:     "evt-old",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		EventTime:   observed,
		Username:    "arn:aws:sts::123456789012:assumed-role/role/sess",
	}
	got, _, _ := normalizeEvent(raw, "123456789012", "us-east-1", now)
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if !got[0].CollectedAt.Equal(now) {
		t.Fatalf("expected CollectedAt to equal ingestion-run time %s, got %s", now, got[0].CollectedAt)
	}
	if !got[0].ObservedAt.Equal(observed) {
		t.Fatalf("expected ObservedAt to preserve the CloudTrail event time %s, got %s", observed, got[0].ObservedAt)
	}
}

func TestNormalizeEventDerivesAgentIdentityFromBedrockARN(t *testing.T) {
	now := time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		resource  string
		wantAgent string
		wantType  string
	}{
		{
			name:      "agentcore runtime endpoint",
			resource:  "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/runtime-case-triage/blue",
			wantAgent: "runtime-case-triage",
			wantType:  "agentcore_runtime",
		},
		{
			name:      "bedrock agent",
			resource:  "arn:aws:bedrock-agent:us-east-1:123456789012:agent/AGENT-ABC123",
			wantAgent: "AGENT-ABC123",
			wantType:  "bedrock_agent",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := Event{
				EventID:     "evt-agent",
				EventName:   "InvokeTool",
				EventSource: "bedrock-agentcore.amazonaws.com",
				EventTime:   now,
				Resources:   []EventResource{{ResourceType: "AWS::BedrockAgent::Agent", ResourceName: tc.resource}},
			}
			got, _, ok := normalizeEvent(raw, "123456789012", "us-east-1", now)
			if !ok || len(got) != 1 {
				t.Fatalf("expected 1 event, got %d (ok=%v)", len(got), ok)
			}
			if got[0].AgentID != tc.wantAgent {
				t.Fatalf("expected AgentID=%q, got %q", tc.wantAgent, got[0].AgentID)
			}
			if got[0].AgentType != tc.wantType {
				t.Fatalf("expected AgentType %q, got %q", tc.wantType, got[0].AgentType)
			}
		})
	}

	// Non-agent-tool events leave the agent fields empty.
	raw := Event{
		EventID:     "evt-secret",
		EventName:   "GetSecretValue",
		EventSource: "secretsmanager.amazonaws.com",
		EventTime:   now,
		Resources:   []EventResource{{ResourceName: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/x"}},
	}
	got, _, _ := normalizeEvent(raw, "123456789012", "us-east-1", now)
	if got[0].AgentID != "" || got[0].AgentType != "" {
		t.Fatalf("non-agent event must not derive agent identity, got %+v", got[0])
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

func TestClassifyBedrockManagementEventsAsAPICallNotAgentTool(t *testing.T) {
	// Bedrock control-plane operations (CreateAgent, UpdateAgent,
	// DeleteAgent, GetAgent, ListAgents, PrepareAgent, etc.) are
	// ordinary management API calls and must not be classified as
	// agent-tool. Only Invoke* operations represent actual tool
	// invocations; a caller filtering for `event_type=agent-tool`
	// should not see management records reported as tool evidence.
	for _, name := range []string{"CreateAgent", "UpdateAgent", "DeleteAgent", "GetAgent", "ListAgents", "PrepareAgent"} {
		if got := classifyEventType("bedrock-agent.amazonaws.com", name); got != "api-call" {
			t.Errorf("classifyEventType(bedrock-agent, %q) = %q, want api-call", name, got)
		}
		if got := classifyEventType("bedrock-agentcore.amazonaws.com", name); got != "api-call" {
			t.Errorf("classifyEventType(bedrock-agentcore, %q) = %q, want api-call", name, got)
		}
	}
	// Invoke* operations are tool invocations.
	for _, name := range []string{"InvokeAgent", "InvokeTool", "InvokeAgentRuntime"} {
		if got := classifyEventType("bedrock-agentcore.amazonaws.com", name); got != "agent-tool" {
			t.Errorf("classifyEventType(bedrock-agentcore, %q) = %q, want agent-tool", name, got)
		}
	}
}

func TestExtractAgentIdentityCapturesAgentCoreRuntimeVersion(t *testing.T) {
	// AgentCore endpoint ARNs carry the runtime version / endpoint
	// alias in the third path segment. The canonical node id helper
	// appends it, so live runtime evidence must carry it through so
	// `agent_invoked_runtime_action` edges and `agent_id` filters
	// keyed on inventory nodes match the live record.
	agentID, agentType, version := extractAgentIdentity("agent-tool", "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/runtime-case-triage/blue")
	if agentID != "runtime-case-triage" || agentType != "agentcore_runtime" || version != "blue" {
		t.Fatalf("expected agentID=runtime-case-triage agentType=agentcore_runtime version=blue, got %q/%q/%q", agentID, agentType, version)
	}
	// Bedrock-agent ARNs do not carry a third segment.
	agentID, agentType, version = extractAgentIdentity("agent-tool", "arn:aws:bedrock-agent:us-east-1:123456789012:agent/AGENT-ABC123")
	if agentID != "AGENT-ABC123" || agentType != "bedrock_agent" || version != "" {
		t.Fatalf("expected agentID=AGENT-ABC123 agentType=bedrock_agent version=empty, got %q/%q/%q", agentID, agentType, version)
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
	got, diag, ok := normalizeEvent(raw, "123456789012", "us-east-1", now)
	if !ok {
		t.Fatalf("expected normalization to fall back to core fields when JSON is unparseable")
	}
	if diag == nil || diag.Code != "cloudtrail_event_payload_unparseable" {
		t.Fatalf("expected payload-unparseable diagnostic, got %+v", diag)
	}
	if len(got) != 1 || got[0].EventID != "evt-bad-json" {
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
