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

type fakeDeliveryIngester struct {
	source  AWSCloudTrailDeliverySource
	result  AWSCloudTrailIngestResult
	err     error
	calls   int
	request AWSCloudTrailIngestRequest
}

func (f *fakeDeliveryIngester) Ingest(_ context.Context, request AWSCloudTrailIngestRequest) (AWSCloudTrailIngestResult, error) {
	f.calls++
	f.request = request
	return f.result, f.err
}

func TestNormalizeDeliverySourceAcceptsKnownTokensAndRejectsUnknown(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{in: "", want: "lookup_events"},
		{in: "lookup_events", want: "lookup_events"},
		{in: "Lookup-Events", want: "lookup_events"},
		{in: "s3", want: "s3"},
		{in: "eventbridge", want: "eventbridge"},
		{in: "event-bridge", want: "eventbridge"},
		{in: "all", want: "all"},
	} {
		got, err := normalizeDeliverySource(tc.in)
		if err != nil {
			t.Errorf("normalizeDeliverySource(%q) returned err=%v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeDeliverySource(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
	if _, err := normalizeDeliverySource("garbage"); !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected unknown delivery source to return ErrInvalidAWSConnectionRequest, got %v", err)
	}
}

func TestGetAWSRuntimeEventsDeliverySourceS3UsesDeliveryFactory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 15, 19, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-s3-delivery")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-s3-delivery", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-s3-delivery", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail/sess"
	deliveryRecord := liveRuntimeRecord(t, "evt-s3-1", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "s3-delivery", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/key", "AWS::SecretsManager::Secret", now.Add(-2*time.Minute))
	s3Fake := &fakeDeliveryIngester{source: AWSCloudTrailDeliverySourceS3, result: AWSCloudTrailIngestResult{
		Status:  "ready",
		Records: []AWSRuntimeEventRecord{deliveryRecord},
	}}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, source AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		if source != AWSCloudTrailDeliverySourceS3 {
			t.Fatalf("expected only S3 source, got %q", source)
		}
		return s3Fake, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-s3-delivery", AWSRuntimeEventRequest{
		ConnectorID:    "aws-prod",
		DeliverySource: "s3",
	})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if s3Fake.calls != 1 {
		t.Fatalf("expected S3 ingester called once, got %d", s3Fake.calls)
	}
	if len(result.Records) != 1 || result.Records[0].EventID != "evt-s3-1" {
		t.Fatalf("expected S3-delivered record in response, got %+v", result.Records)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready, got %q (%+v)", result.Status, result)
	}
}

func TestGetAWSRuntimeEventsDeliveryPassesFiltersToIngestRequest(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 15, 19, 10, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-delivery-filter-propagation")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-delivery-filter-propagation", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-delivery-filter-propagation", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail/sess"
	deliveryRecord := liveRuntimeRecord(t, "evt-filter", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "s3-delivery", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/key", "AWS::SecretsManager::Secret", now.Add(-2*time.Minute))
	s3Fake := &fakeDeliveryIngester{source: AWSCloudTrailDeliverySourceS3, result: AWSCloudTrailIngestResult{
		Status:  "ready",
		Records: []AWSRuntimeEventRecord{deliveryRecord},
	}}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, source AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		if source != AWSCloudTrailDeliverySourceS3 {
			t.Fatalf("expected only S3 source, got %q", source)
		}
		return s3Fake, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-delivery-filter-propagation", AWSRuntimeEventRequest{
		ConnectorID:    "aws-prod",
		DeliverySource: "s3",
		EventType:      "secret-read",
		Identity:       role,
		Resource:       "prod/key",
	})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready, got %q (%+v)", result.Status, result)
	}
	if len(s3Fake.request.Filters) == 0 {
		t.Fatalf("expected filters to be passed to delivery ingester")
	}
	if s3Fake.request.Filters["event_type"] != "secret-read" {
		t.Fatalf("expected event_type filter to pass through, got %+v", s3Fake.request.Filters)
	}
	if s3Fake.request.Filters["identity"] != role {
		t.Fatalf("expected identity filter to pass through, got %+v", s3Fake.request.Filters)
	}
	if s3Fake.request.Filters["resource"] != "prod/key" {
		t.Fatalf("expected resource filter to pass through, got %+v", s3Fake.request.Filters)
	}
}

func TestGetAWSRuntimeEventsDeliverySourceAllFansOutAndDedupes(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 15, 19, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-all-delivery")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-all-delivery", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-runtime-all-delivery", "aws-prod")

	role := "arn:aws:sts::123456789012:assumed-role/identrail/sess"
	dupe := liveRuntimeRecord(t, "evt-dupe", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "cloudtrail", role, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/key", "AWS::SecretsManager::Secret", now.Add(-5*time.Minute))
	s3Only := liveRuntimeRecord(t, "evt-s3-only", "kms-decrypt", "Decrypt", "kms.amazonaws.com", "kms:Decrypt", "platform", "s3-delivery", role, "arn:aws:kms:us-east-1:123456789012:key/abc", "AWS::KMS::Key", now.Add(-4*time.Minute))
	ebOnly := liveRuntimeRecord(t, "evt-eb-only", "sts-session", "AssumeRole", "sts.amazonaws.com", "sts:AssumeRole", "security", "eventbridge-delivery", role, "", "", now.Add(-3*time.Minute))
	s3Fake := &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{Status: "ready", Records: []AWSRuntimeEventRecord{dupe, s3Only}}}
	ebFake := &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{Status: "ready", Records: []AWSRuntimeEventRecord{dupe, ebOnly}}}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, source AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		switch source {
		case AWSCloudTrailDeliverySourceS3:
			return s3Fake, nil
		case AWSCloudTrailDeliverySourceEventBridge:
			return ebFake, nil
		}
		t.Fatalf("unknown source %q", source)
		return nil, nil
	}

	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-all-delivery", AWSRuntimeEventRequest{
		ConnectorID:    "aws-prod",
		DeliverySource: "all",
	})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if s3Fake.calls != 1 || ebFake.calls != 1 {
		t.Fatalf("expected both ingesters called once, got s3=%d eb=%d", s3Fake.calls, ebFake.calls)
	}
	ids := map[string]bool{}
	for _, r := range result.Records {
		ids[r.EventID] = true
	}
	for _, want := range []string{"evt-dupe", "evt-s3-only", "evt-eb-only"} {
		if !ids[want] {
			t.Fatalf("expected merged result to include %q, got %+v", want, ids)
		}
	}
	// dedupe: evt-dupe must appear exactly once.
	dupeCount := 0
	for _, r := range result.Records {
		if r.EventID == "evt-dupe" {
			dupeCount++
		}
	}
	if dupeCount != 1 {
		t.Fatalf("expected evt-dupe to appear once after cross-channel dedupe, got %d", dupeCount)
	}
}

func TestGetAWSRuntimeEventsDeliveryUnknownSourceRejectedWith400(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 15, 19, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-bad-delivery")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-bad-delivery", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	_, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-bad-delivery", AWSRuntimeEventRequest{ConnectorID: "aws-prod", DeliverySource: "smoke-signal"})
	if !errors.Is(err, ErrInvalidAWSConnectionRequest) {
		t.Fatalf("expected ErrInvalidAWSConnectionRequest, got %v", err)
	}
}

func TestGetAWSRuntimeEventsDeliveryWithoutCapabilityFallsBackToFixturesAndDegrades(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 15, 20, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-runtime-delivery-nocap")
	seedAWSConnectorForScanTest(t, store, ctx, "project-runtime-delivery-nocap", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	// No capability grant: discovery-only connector.

	called := false
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		called = true
		return &fakeDeliveryIngester{}, nil
	}
	result, err := svc.GetAWSRuntimeEvents(ctx, "default", "project-runtime-delivery-nocap", AWSRuntimeEventRequest{ConnectorID: "aws-prod", DeliverySource: "s3"})
	if err != nil {
		t.Fatalf("get runtime events: %v", err)
	}
	if called {
		t.Fatalf("discovery-only connector must not call the delivery factory")
	}
	if result.Status != "degraded" {
		t.Fatalf("expected degraded fallback when capability missing, got %q", result.Status)
	}
	if result.FixtureState != "partial_failure" {
		t.Fatalf("expected fixture_state=partial_failure, got %q", result.FixtureState)
	}
	foundDiag := false
	for _, diag := range result.Diagnostics {
		if strings.Contains(diag.Code, "cloudtrail_delivery_unavailable") {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected cloudtrail_delivery_unavailable diagnostic, got %+v", result.Diagnostics)
	}
}

func TestMergeDeliveryResultsPropagatesWorstStatus(t *testing.T) {
	got := mergeDeliveryResults([]AWSCloudTrailIngestResult{
		{Status: "ready", Records: []AWSRuntimeEventRecord{{EventID: "a"}}},
		{Status: "degraded", Records: []AWSRuntimeEventRecord{{EventID: "b"}}},
	})
	if got.Status != "degraded" {
		t.Fatalf("expected merged status to inherit worst (degraded), got %q", got.Status)
	}
	if len(got.Records) != 2 {
		t.Fatalf("expected union of records, got %d", len(got.Records))
	}

	got = mergeDeliveryResults([]AWSCloudTrailIngestResult{
		{Status: "ready"},
		{Status: "blocked"},
	})
	if got.Status != "blocked" {
		t.Fatalf("expected merged status to inherit worst (blocked), got %q", got.Status)
	}
}

func TestMergeDeliveryResultsBlockedWithRecordsDegrades(t *testing.T) {
	got := mergeDeliveryResults([]AWSCloudTrailIngestResult{
		{Status: "ready", Records: []AWSRuntimeEventRecord{{EventID: "a"}}},
		{Status: "blocked", Records: []AWSRuntimeEventRecord{{EventID: "b"}}},
	})
	if got.Status != "degraded" {
		t.Fatalf("expected mixed-source blocked+records merge to degrade, got %q", got.Status)
	}
	if len(got.Records) != 2 {
		t.Fatalf("expected both source records to remain, got %d", len(got.Records))
	}
}
