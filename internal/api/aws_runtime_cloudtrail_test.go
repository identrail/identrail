package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

type fakeCloudTrailIngester struct {
	calls  []AWSCloudTrailIngestRequest
	result AWSCloudTrailIngestResult
	err    error
}

func (f *fakeCloudTrailIngester) Ingest(_ context.Context, request AWSCloudTrailIngestRequest) (AWSCloudTrailIngestResult, error) {
	f.calls = append(f.calls, request)
	return f.result, f.err
}

func liveRuntimeRecord(t *testing.T, id string, eventType string, name string, source string, action string, owner string, evidence string, actorARN string, resourceARN string, resourceType string, observed time.Time) AWSRuntimeEventRecord {
	t.Helper()
	return AWSRuntimeEventRecord{
		EventID:             id,
		AccountID:           "123456789012",
		Region:              "us-east-1",
		EventType:           eventType,
		EventSource:         source,
		EventName:           name,
		Action:              action,
		ActorPrincipalARN:   actorARN,
		ActorPrincipalType:  "assumed_role",
		ActorIdentityNodeID: awsIdentityNodeIDForAPI(actorARN),
		Session: AWSRuntimeEventSession{
			SessionID:    "ASIAEXAMPLESESSION",
			PrincipalARN: actorARN,
			StartedAt:    observed.Add(-5 * time.Minute),
		},
		TargetResourceARN:  resourceARN,
		TargetResourceType: resourceType,
		TargetResourceName: displayNameFromARN(resourceARN),
		ResourceNodeID:     awsRuntimeEventResourceNodeID(resourceARN, resourceType),
		Owner:              owner,
		EvidenceCategory:   evidence,
		EvidenceRef:        "runtime-evidence://123456789012/us-east-1/" + id,
		Confidence:         0.9,
		ObservedAt:         observed,
		CollectedAt:        observed.Add(2 * time.Minute),
		Status:             "observed",
		NextAction:         awsRuntimeEventNextAction(eventType),
		RedactionBoundary:  "metadata_only_no_payloads_no_secret_values",
	}
}

func TestGetAWSRuntimeEventsUsesLiveCloudTrailWhenFactoryReturnsIngester(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 19, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-live")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-live", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	role := "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess-runtime-reader"
	fake := &fakeCloudTrailIngester{
		result: AWSCloudTrailIngestResult{
			Status: "ready",
			Records: []AWSRuntimeEventRecord{
				liveRuntimeRecord(t, "evt-live-secret", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "cloudtrail", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key", "AWS::SecretsManager::Secret", now.Add(-10*time.Minute)),
				liveRuntimeRecord(t, "evt-live-kms", "kms-decrypt", "Decrypt", "kms.amazonaws.com", "kms:Decrypt", "platform", "cloudtrail", role, "arn:aws:kms:us-east-1:123456789012:key/abcd-ef", "AWS::KMS::Key", now.Add(-5*time.Minute)),
			},
		},
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, connection AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		if connection.ConnectorID != "aws-prod" {
			t.Fatalf("factory invoked for wrong connector: %+v", connection)
		}
		return fake, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-live", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "ready" {
		t.Fatalf("expected live ready status, got %+v", result)
	}
	if len(fake.calls) != 1 || fake.calls[0].AccountID != "123456789012" {
		t.Fatalf("expected one ingestion call scoped to the connector account, got %+v", fake.calls)
	}
	if result.Summary.TotalEvents != 2 || result.Summary.SecretReadCount != 1 || result.Summary.KMSDecryptCount != 1 {
		t.Fatalf("expected live records to drive summary, got %+v", result.Summary)
	}
	if result.FixtureState != "success" {
		t.Fatalf("expected live ready run to report fixture_state=success, got %q", result.FixtureState)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 live records in response, got %+v", result.Records)
	}
	for _, record := range result.Records {
		if record.RedactionBoundary != "metadata_only_no_payloads_no_secret_values" {
			t.Fatalf("live record leaked unsafe redaction boundary: %+v", record)
		}
	}
}

func TestGetAWSRuntimeEventsFixtureOverrideBypassesLiveFactory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 19, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-fixture-override")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-fixture-override", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	called := false
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		called = true
		return &fakeCloudTrailIngester{}, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-fixture-override", AWSRuntimeEventRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if called {
		t.Fatalf("explicit fixture_state must bypass live CloudTrail factory")
	}
	if result.FixtureState != "degraded" || result.Status != "degraded" {
		t.Fatalf("expected fixture override to render degraded contract, got %+v", result)
	}
}

func TestGetAWSRuntimeEventsFactoryErrorAttachesDiagnosticAndFallsBackToFixture(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 20, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-factory-error")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-factory-error", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return nil, errors.New("assume role refused")
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-factory-error", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Summary.TotalEvents == 0 {
		t.Fatalf("expected fixture fallback to keep returning records, got %+v", result)
	}
	foundFactoryDiagnostic := false
	for _, diag := range result.Diagnostics {
		if diag.Code == "cloudtrail_ingester_unavailable" {
			foundFactoryDiagnostic = true
		}
	}
	if !foundFactoryDiagnostic {
		t.Fatalf("expected factory failure diagnostic on fallback response, got %+v", result.Diagnostics)
	}
}

func TestGetAWSRuntimeEventsLiveEventSourceFilterIsPushedToIngester(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 20, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-source-filter")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-source-filter", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	fake := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{Status: "ready"}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	if _, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-source-filter", AWSRuntimeEventRequest{ConnectorID: "aws-prod", EventType: "kms-decrypt"}); err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if len(fake.calls) != 1 || fake.calls[0].EventSourceFilter != "kms.amazonaws.com" {
		t.Fatalf("expected event_type=kms-decrypt to push CloudTrail event source filter, got %+v", fake.calls)
	}
}

func TestGetAWSRuntimeEventsLiveBlockedStatusKeepsContractShape(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 14, 21, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-live-blocked")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-live-blocked", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	fake := &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
		Status: "blocked",
		Diagnostics: []AWSRuntimeEventDiagnostic{{
			Collector: "aws_cloudtrail_lookup_events",
			SourceID:  "cloudtrail",
			Code:      "permission_denied",
			Message:   "CloudTrail LookupEvents permission is not available for runtime event ingestion: AccessDeniedException",
			Retryable: true,
		}},
		CoverageGaps: []AWSRuntimeEventCoverageGap{{
			Capability:  "cloudtrail_lookup_events",
			Status:      "permission_denied",
			Reason:      "Runtime event source cannot be queried with the current connector permissions.",
			Remediation: "Add read-only CloudTrail LookupEvents permissions and retry.",
		}},
		FailureReasons:   []string{"runtime event sources are not authorized for this connector"},
		RemediationHints: []string{"Grant metadata-only CloudTrail LookupEvents and service audit permissions; do not grant payload, secret-value, decrypt, or object-body reads."},
	}}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-live-blocked", AWSRuntimeEventRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "blocked" || result.FixtureState != "permission_denied" {
		t.Fatalf("expected blocked/permission_denied contract on live denial, got %+v", result)
	}
	if len(result.Records) != 0 {
		t.Fatalf("blocked status must not leak any live records: %+v", result.Records)
	}
	if len(result.CoverageGaps) != 1 || result.CoverageGaps[0].Status != "permission_denied" {
		t.Fatalf("expected permission_denied coverage gap, got %+v", result.CoverageGaps)
	}
	if len(result.FailureReasons) == 0 || !strings.Contains(strings.Join(result.FailureReasons, "|"), "not authorized") {
		t.Fatalf("expected blocked failure reasons surfaced to operators, got %+v", result.FailureReasons)
	}
}
