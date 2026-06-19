package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/runtime/secretsaccess"
)

func newSecretsKMSRuntimeAccessService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, project)
	seedAWSConnectorForScanTest(t, store, ctx, project, "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	return svc, "default"
}

func recordsByStatus(records []AWSSecretsKMSRuntimeAccessRecord) map[string]int {
	counts := map[string]int{}
	for _, record := range records {
		counts[record.Status]++
	}
	return counts
}

func TestGetAWSSecretsKMSRuntimeAccessBuildsCorrelationContract(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newSecretsKMSRuntimeAccessService(t, "project-corr", now)

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(defaultScopeContext(), ws, "project-corr", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "success"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.CurrentIssueRef != "#1518" || result.Version != awsSecretsKMSRuntimeAccessVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	counts := recordsByStatus(result.Records)
	if counts[secretsaccess.StatusConfirmed] != 2 || counts[secretsaccess.StatusObservedWithoutGrant] != 1 || counts[secretsaccess.StatusGrantedUnused] != 2 {
		t.Fatalf("unexpected status distribution: %+v (records=%+v)", counts, result.Records)
	}
	if result.Summary.ConfirmedCount != 2 || result.Summary.GrantedUnusedCount != 2 || result.Summary.ObservedWithoutGrantCount != 1 {
		t.Fatalf("unexpected summary: %+v", result.Summary)
	}
	if result.Summary.SecretCorrelationCount == 0 || result.Summary.KMSKeyCorrelationCount == 0 {
		t.Fatalf("expected both secret and kms correlations: %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected relationships: %+v", result.Relationships)
	}
	if len(result.Caveats) == 0 {
		t.Fatalf("expected correlation caveats (data-event + IAM-policy)")
	}
	for _, record := range result.Records {
		if record.RedactionBoundary != secretsaccess.RedactionBoundary {
			t.Fatalf("record leaked unsafe redaction boundary: %+v", record)
		}
		if record.EvidenceRef == "" || record.IdentityNodeID == "" || record.ResourceNodeID == "" || record.Confidence <= 0 {
			t.Fatalf("record missing required fields: %+v", record)
		}
		if record.NextAction == "" {
			t.Fatalf("record missing next action: %+v", record)
		}
	}
	if len(result.EvidenceLinks) == 0 || len(result.FailureReasons) != 0 {
		t.Fatalf("expected evidence links and no failures: links=%v failures=%v", result.EvidenceLinks, result.FailureReasons)
	}
	if len(result.CoverageGaps) == 0 {
		t.Fatalf("expected base coverage gaps documenting IAM-policy / data-event limits")
	}
}

func TestGetAWSSecretsKMSRuntimeAccessConfirmedCarriesObservedAndStatic(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newSecretsKMSRuntimeAccessService(t, "project-corr-confirmed", now)

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(defaultScopeContext(), ws, "project-corr-confirmed", AWSSecretsKMSRuntimeAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Status:       "confirmed",
	})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 confirmed records, got %d", len(result.Records))
	}
	for _, record := range result.Records {
		if record.Status != secretsaccess.StatusConfirmed {
			t.Fatalf("status filter leaked non-confirmed record: %+v", record)
		}
		if record.ObservedCount == 0 || len(record.StaticSources) == 0 {
			t.Fatalf("confirmed record must carry observed + static evidence: %+v", record)
		}
		if record.Confidence < 0.9 {
			t.Fatalf("confirmed confidence too low: %+v", record)
		}
	}
	if result.AppliedFilters["status"] != "confirmed" {
		t.Fatalf("expected applied status filter, got %+v", result.AppliedFilters)
	}
}

func TestGetAWSSecretsKMSRuntimeAccessFiltersByResourceKindAndIdentity(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newSecretsKMSRuntimeAccessService(t, "project-corr-filter", now)

	secretsOnly, err := svc.GetAWSSecretsKMSRuntimeAccess(defaultScopeContext(), ws, "project-corr-filter", AWSSecretsKMSRuntimeAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		ResourceKind: "secret",
	})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if len(secretsOnly.Records) != 3 {
		t.Fatalf("expected 3 secret correlations, got %d", len(secretsOnly.Records))
	}
	for _, record := range secretsOnly.Records {
		if record.ResourceKind != secretsaccess.ResourceKindSecret {
			t.Fatalf("resource_kind filter leaked: %+v", record)
		}
	}

	invoiceOnly, err := svc.GetAWSSecretsKMSRuntimeAccess(defaultScopeContext(), ws, "project-corr-filter", AWSSecretsKMSRuntimeAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     "invoice-agent",
	})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if len(invoiceOnly.Records) != 1 || invoiceOnly.Records[0].Status != secretsaccess.StatusObservedWithoutGrant {
		t.Fatalf("expected single observed_without_grant for invoice-agent, got %+v", invoiceOnly.Records)
	}
}

func TestGetAWSSecretsKMSRuntimeAccessPermissionDeniedIsExplicit(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newSecretsKMSRuntimeAccessService(t, "project-corr-denied", now)

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(defaultScopeContext(), ws, "project-corr-denied", AWSSecretsKMSRuntimeAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != "blocked" || result.Confidence != 0 {
		t.Fatalf("expected blocked permission-denied state, got status=%q confidence=%v", result.Status, result.Confidence)
	}
	if len(result.Records) != 0 {
		t.Fatalf("expected no records when blocked, got %d", len(result.Records))
	}
	if len(result.Diagnostics) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected diagnostics and coverage gaps explaining the blocked state")
	}
}

func TestGetAWSSecretsKMSRuntimeAccessEmptyAndPartialFailure(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newSecretsKMSRuntimeAccessService(t, "project-corr-states", now)

	empty, err := svc.GetAWSSecretsKMSRuntimeAccess(defaultScopeContext(), ws, "project-corr-states", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "empty"})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Records) != 0 || len(empty.CoverageGaps) == 0 {
		t.Fatalf("unexpected empty state: %+v", empty)
	}

	partial, err := svc.GetAWSSecretsKMSRuntimeAccess(defaultScopeContext(), ws, "project-corr-states", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "partial_failure"})
	if err != nil {
		t.Fatalf("partial: %v", err)
	}
	if partial.Status != "degraded" {
		t.Fatalf("expected degraded partial-failure, got %q", partial.Status)
	}
	// Static side failed → only observed accesses remain, all unconfirmed.
	for _, record := range partial.Records {
		if record.Status == secretsaccess.StatusConfirmed {
			t.Fatalf("partial-failure must not produce confirmed correlations: %+v", record)
		}
	}
	if partial.Summary.GrantedUnusedCount != 0 {
		t.Fatalf("partial-failure has no static grants, so no granted_unused expected: %+v", partial.Summary)
	}
}

func TestGetAWSSecretsKMSRuntimeAccessLiveRoutesDataEventsThroughDelivery(t *testing.T) {
	// secret-read / kms-decrypt are CloudTrail data events, so the live
	// correlation must drive the delivery channels (not LookupEvents).
	// This wires only the delivery factory and asserts the observed data
	// event flows through it while static grants are intentionally suppressed
	// in live mode to prevent fixture-collection bleed-through.
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 19, 19, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-corr-live")
	seedAWSConnectorForScanTest(t, store, ctx, "project-corr-live", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-corr-live", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	// Discover fixtures from the static reachability inventory so we can still
	// anchor to a realistic resource identifier.
	kms, err := svc.GetAWSKMSDecryptReachabilityInventory(ctx, "default", "project-corr-live", AWSKMSDecryptReachabilityInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("kms inventory: %v", err)
	}
	var keyARN, principal string
	for _, record := range kms.Records {
		for _, grant := range record.IdentityGrants {
			if strings.EqualFold(grant.Effect, "Allow") && isIAMPrincipalARNForKMSEdge(grant.PrincipalARN) && kmsCapabilitiesIncludeDecrypt(grant.Capabilities) {
				keyARN = record.KeyARN
				principal = grant.PrincipalARN
				break
			}
		}
		if keyARN != "" {
			break
		}
	}
	if keyARN == "" || principal == "" {
		t.Fatalf("expected a static KMS decrypt grant in the inventory to confirm against")
	}

	deliveryRecord := liveRuntimeRecord(t, "evt-kms-corr", "kms-decrypt", "Decrypt", "kms.amazonaws.com", "kms:Decrypt", "platform", "s3-delivery", principal, keyARN, "AWS::KMS::Key", now.Add(-2*time.Minute))
	fake := &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{
		Status:  "ready",
		Records: []AWSRuntimeEventRecord{deliveryRecord},
	}}
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(ctx, "default", "project-corr-live", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if fake.calls == 0 {
		t.Fatalf("delivery factory was never used — data events were not routed through the delivery channel")
	}
	var observedWithoutGrant *AWSSecretsKMSRuntimeAccessRecord
	for i := range result.Records {
		record := &result.Records[i]
		if record.ResourceARN == keyARN && record.Status == secretsaccess.StatusObservedWithoutGrant {
			observedWithoutGrant = record
			break
		}
	}
	if observedWithoutGrant == nil {
		t.Fatalf("expected an observed_without_grant correlation for the observed decrypt on %s, got %+v", keyARN, result.Records)
	}
	if observedWithoutGrant.ObservedCount == 0 || len(observedWithoutGrant.StaticSources) != 0 {
		t.Fatalf("observed-only correlation must carry observed evidence but no synthetic static grants: %+v", observedWithoutGrant)
	}
}

func TestGetAWSSecretsKMSRuntimeAccessDefaultLiveRequiresDeliveryFactory(t *testing.T) {
	// The default correlation source is `all`, which is delivery-backed because
	// secret-read and kms-decrypt are CloudTrail data events. A LookupEvents-only
	// deployment must not enter live mode and then receive delivery fixtures.
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 19, 19, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-corr-lookup-only")
	seedAWSConnectorForScanTest(t, store, ctx, "project-corr-lookup-only", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-corr-lookup-only", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	lookupCalled := false
	svc.AWSCloudTrailLookupEventsFactory = func(_ context.Context, _ AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error) {
		lookupCalled = true
		return &fakeCloudTrailIngester{result: AWSCloudTrailIngestResult{
			Status: "ready",
			Records: []AWSRuntimeEventRecord{
				liveRuntimeRecord(t, "evt-lookup-secret", "secret-read", "GetSecretValue", "secretsmanager.amazonaws.com", "secretsmanager:GetSecretValue", "application", "lookup-events", "arn:aws:iam::123456789012:role/payments-app", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai-key", "AWS::SecretsManager::Secret", now.Add(-2*time.Minute)),
			},
		}}, nil
	}

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(ctx, "default", "project-corr-lookup-only", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if lookupCalled {
		t.Fatalf("default data-event correlation should require delivery factory, but LookupEvents was called")
	}
	for _, record := range result.Records {
		for _, eventID := range record.ObservedEventIDs {
			if eventID == "evt-lookup-secret" {
				t.Fatalf("lookup-only live event leaked into default delivery-backed correlation: %+v", record)
			}
		}
	}
}

func TestGetAWSSecretsKMSRuntimeAccessSuppressesFixturesWhenLiveDeliveryUnavailable(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 19, 19, 20, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-corr-live-unavailable")
	seedAWSConnectorForScanTest(t, store, ctx, "project-corr-live-unavailable", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(ctx, "default", "project-corr-live-unavailable", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded status when live delivery is unavailable, got %q", result.Status)
	}
	if len(result.Records) != 0 {
		t.Fatalf("expected no fixture records for a real connector without live delivery, got %+v", result.Records)
	}
	if result.FixtureState != "" {
		t.Fatalf("expected no fixture state when live fixtures are suppressed, got %q", result.FixtureState)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "runtime_delivery_unavailable" {
		t.Fatalf("expected runtime delivery diagnostic, got %+v", result.Diagnostics)
	}
}

func TestGetAWSSecretsKMSRuntimeAccessBlockedRuntimeSuppressesUnusedGrants(t *testing.T) {
	// When the runtime (observed) source is blocked, static grants must
	// not be emitted as granted_unused — that would surface missing
	// telemetry as least-privilege cleanup work.
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 19, 19, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-corr-blocked")
	seedAWSConnectorForScanTest(t, store, ctx, "project-corr-blocked", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-corr-blocked", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	// Delivery returns a blocked (permission-denied) runtime result with
	// no records, while the static KMS/Secrets inventories still resolve.
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		return &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{
			Status:         "blocked",
			FailureReasons: []string{"runtime event sources are not authorized for this connector"},
		}}, nil
	}

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(ctx, "default", "project-corr-blocked", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != "blocked" {
		t.Fatalf("expected blocked status when runtime telemetry is blocked, got %q", result.Status)
	}
	if len(result.Records) != 0 {
		t.Fatalf("expected no records (no granted_unused) under a blocked runtime, got %+v", result.Records)
	}
	if result.Summary.GrantedUnusedCount != 0 {
		t.Fatalf("blocked runtime must not surface granted_unused grants, got %+v", result.Summary)
	}
}

func TestGetAWSSecretsKMSRuntimeAccessDegradedRuntimeWithoutRecordsSuppressesUnusedGrants(t *testing.T) {
	// A delivery-source failure can return degraded with no runtime records
	// (for example when no data-event channel is configured). In that path,
	// static grants cannot be safely interpreted as unused.
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 19, 19, 45, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-corr-degraded-empty")
	seedAWSConnectorForScanTest(t, store, ctx, "project-corr-degraded-empty", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-corr-degraded-empty", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		return &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{
			Status:         "degraded",
			FailureReasons: []string{"S3 and EventBridge delivery are unavailable"},
		}}, nil
	}

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(ctx, "default", "project-corr-degraded-empty", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded status when delivery is unavailable, got %q", result.Status)
	}
	if len(result.Records) != 0 {
		t.Fatalf("expected no records when runtime had no records and should suppress static grants, got %+v", result.Records)
	}
	if result.Summary.GrantedUnusedCount != 0 || result.Summary.ConfirmedCount != 0 || result.Summary.ObservedWithoutGrantCount != 0 {
		t.Fatalf("expected no correlation output when runtime telemetry is unavailable, got %+v", result.Summary)
	}
}

func TestGetAWSSecretsKMSRuntimeAccessDegradedRuntimeWithoutUsableEventsSuppressesUnusedGrants(t *testing.T) {
	// A degraded delivery source can still return non-KMS/secret records (for
	// example STS/API chatter). If none of those are projectable into our
	// correlation window, static grants should not be treated as used/unused.
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 19, 20, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-corr-degraded-unusable")
	seedAWSConnectorForScanTest(t, store, ctx, "project-corr-degraded-unusable", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-corr-degraded-unusable", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		return &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{
			Status: "degraded",
			Records: []AWSRuntimeEventRecord{
				{
					EventType:           "api-call",
					EventID:             "evt-noise",
					EventName:           "AssumeRole",
					ActorIdentityNodeID: "role-noise",
					AccountID:           "111122223333",
					Region:              "us-east-1",
					ObservedAt:          now.Add(-1 * time.Minute),
					TargetResourceARN:   "",
					TargetResourceName:  "",
				},
			},
		}}, nil
	}

	result, err := svc.GetAWSSecretsKMSRuntimeAccess(ctx, "default", "project-corr-degraded-unusable", AWSSecretsKMSRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded status, got %q", result.Status)
	}
	if len(result.Records) != 0 {
		t.Fatalf("expected no records when no usable secret/kms runtime events exist, got %+v", result.Records)
	}
	if result.Summary.GrantedUnusedCount != 0 {
		t.Fatalf("degraded unusable-event path must suppress static grants, got %+v", result.Summary)
	}
}

func TestStaticGrantsFromSecretsRecognizesWildcardReadActions(t *testing.T) {
	records := []AWSSecretsManagerMetadataRecord{{
		AccountID:  "111122223333",
		Region:     "us-east-1",
		SecretARN:  "arn:aws:secretsmanager:us-east-1:111122223333:secret:s1",
		SecretName: "s1",
		Confidence: 0.88,
		IdentityGrants: []AWSSecretsManagerIdentityGrant{
			{PrincipalARN: "arn:aws:iam::111122223333:role/get-star", Effect: "Allow", Actions: []string{"secretsmanager:Get*"}},
			{PrincipalARN: "arn:aws:iam::111122223333:role/batch-star", Effect: "Allow", Actions: []string{"secretsmanager:BatchGet*"}},
			{PrincipalARN: "arn:aws:iam::111122223333:role/suffix-star", Effect: "Allow", Actions: []string{"secretsmanager:*SecretValue"}},
			{PrincipalARN: "arn:aws:iam::111122223333:role/question", Effect: "Allow", Actions: []string{"secretsmanager:GetSecretValu?"}},
			{PrincipalARN: "arn:aws:iam::111122223333:role/service-star", Effect: "Allow", Actions: []string{"*:GetSecretValue"}},
			{PrincipalARN: "arn:aws:iam::111122223333:role/describe-star", Effect: "Allow", Actions: []string{"secretsmanager:Describe*"}},
		},
	}}
	grants := staticGrantsFromSecretsRecords(records)
	got := map[string]bool{}
	for _, grant := range grants {
		got[grant.PrincipalARN] = true
	}
	for _, principal := range []string{
		"arn:aws:iam::111122223333:role/get-star",
		"arn:aws:iam::111122223333:role/batch-star",
		"arn:aws:iam::111122223333:role/suffix-star",
		"arn:aws:iam::111122223333:role/question",
		"arn:aws:iam::111122223333:role/service-star",
	} {
		if !got[principal] {
			t.Fatalf("expected AWS wildcard read grant %s to be recognized, got %+v", principal, grants)
		}
	}
	if got["arn:aws:iam::111122223333:role/describe-star"] {
		t.Fatalf("Describe* does not authorize secret-value reads and must be dropped: %+v", grants)
	}
}

func TestStaticGrantsFromSecretsPreservesActions(t *testing.T) {
	records := []AWSSecretsManagerMetadataRecord{{
		AccountID:  "111122223333",
		Region:     "us-east-1",
		SecretARN:  "arn:aws:secretsmanager:us-east-1:111122223333:secret:s1",
		SecretName: "s1",
		Confidence: 0.92,
		IdentityGrants: []AWSSecretsManagerIdentityGrant{
			{PrincipalARN: "arn:aws:iam::111122223333:role/reader", Effect: "Allow", Actions: []string{"secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"}},
		},
	}}
	grants := staticGrantsFromSecretsRecords(records)
	if len(grants) != 1 {
		t.Fatalf("expected one readable secret grant, got %+v", grants)
	}
	got := map[string]struct{}{}
	for _, action := range grants[0].Actions {
		got[action] = struct{}{}
	}
	if _, ok := got["secretsmanager:GetSecretValue"]; !ok {
		t.Fatalf("expected GetSecretValue action to be preserved, got %+v", grants[0].Actions)
	}
	if _, ok := got["secretsmanager:BatchGetSecretValue"]; !ok {
		t.Fatalf("expected BatchGetSecretValue action to be preserved, got %+v", grants[0].Actions)
	}
}

func TestStaticGrantsFromSecretsPreservesExplicitWildcardDeny(t *testing.T) {
	records := []AWSSecretsManagerMetadataRecord{{
		AccountID:  "111122223333",
		Region:     "us-east-1",
		SecretARN:  "arn:aws:secretsmanager:us-east-1:111122223333:secret:s1",
		SecretName: "s1",
		Confidence: 0.92,
		IdentityGrants: []AWSSecretsManagerIdentityGrant{
			{PrincipalARN: "arn:aws:iam::111122223333:role/reader", Effect: "Allow", Actions: []string{"secretsmanager:GetSecretValue"}},
			{PrincipalARN: "*", WildcardPrincipal: true, Effect: "Deny", Actions: []string{"secretsmanager:GetSecretValue"}},
			{PrincipalARN: "*", WildcardPrincipal: true, Effect: "Allow", Actions: []string{"secretsmanager:GetSecretValue"}},
		},
	}}

	grants := staticGrantsFromSecretsRecords(records)
	if len(grants) != 2 {
		t.Fatalf("expected concrete allow plus wildcard deny grants, got %+v", grants)
	}
	hasWildcardDeny := false
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") && grant.PrincipalARN == "*" && grant.IdentityNodeID == "" {
			hasWildcardDeny = true
		}
		if strings.EqualFold(grant.Effect, "Allow") && grant.PrincipalARN == "*" {
			t.Fatalf("wildcard allow grant should not be preserved for secret resource policies: %+v", grant)
		}
	}
	if !hasWildcardDeny {
		t.Fatalf("expected wildcard deny to be preserved: %+v", grants)
	}
}

func TestObservedAccessFromRuntimeRecordsFiltersEventTypes(t *testing.T) {
	records := []AWSRuntimeEventRecord{
		{EventID: "a", EventType: "secret-read", ActorIdentityNodeID: "id-1", TargetResourceARN: "arn:secret", Action: "secretsmanager:GetSecretValue"},
		{EventID: "b", EventType: "kms-decrypt", ActorIdentityNodeID: "id-2", TargetResourceARN: "arn:key", Action: "kms:Decrypt"},
		{EventID: "c", EventType: "sts-session", ActorIdentityNodeID: "id-3"},
		{EventID: "d", EventType: "agent-tool", ActorIdentityNodeID: "id-4"},
		{EventID: "e", EventType: "api-call", ActorIdentityNodeID: "id-5"},
	}
	observed := observedAccessFromRuntimeRecords(records)
	if len(observed) != 2 {
		t.Fatalf("expected only secret-read + kms-decrypt, got %d (%+v)", len(observed), observed)
	}
	if observed[0].ResourceKind != secretsaccess.ResourceKindSecret || observed[1].ResourceKind != secretsaccess.ResourceKindKMSKey {
		t.Fatalf("unexpected resource kinds: %+v", observed)
	}
}

func TestStaticGrantsFromKMSAndSecretsProjectIAMPrincipalsOnly(t *testing.T) {
	kmsRecords := []AWSKMSDecryptReachabilityRecord{{
		AccountID:  "111122223333",
		Region:     "us-east-1",
		KeyARN:     "arn:aws:kms:us-east-1:111122223333:key/k1",
		KeyID:      "k1",
		Confidence: 0.9,
		IdentityGrants: []AWSKMSIdentityGrant{
			{PrincipalARN: "arn:aws:iam::111122223333:role/app", Effect: "Allow", Capabilities: []string{"decrypt"}},
			{PrincipalARN: "*", WildcardPrincipal: true, Effect: "Allow", Capabilities: []string{"decrypt"}},
			{PrincipalARN: "arn:aws:iam::111122223333:role/encrypt-only", Effect: "Allow", Capabilities: []string{"encrypt"}},
		},
	}}
	kmsGrants := staticGrantsFromKMSRecords(kmsRecords)
	if len(kmsGrants) != 1 || kmsGrants[0].PrincipalARN != "arn:aws:iam::111122223333:role/app" {
		t.Fatalf("expected single IAM decrypt grant, got %+v", kmsGrants)
	}
	if kmsGrants[0].ResourceKind != secretsaccess.ResourceKindKMSKey || kmsGrants[0].Source != secretsaccess.SourceKeyPolicy {
		t.Fatalf("unexpected kms grant projection: %+v", kmsGrants[0])
	}

	secretRecords := []AWSSecretsManagerMetadataRecord{{
		AccountID:  "111122223333",
		Region:     "us-east-1",
		SecretARN:  "arn:aws:secretsmanager:us-east-1:111122223333:secret:s1",
		SecretName: "s1",
		Confidence: 0.88,
		IdentityGrants: []AWSSecretsManagerIdentityGrant{
			{PrincipalARN: "arn:aws:iam::111122223333:role/reader", Effect: "Allow", Actions: []string{"secretsmanager:GetSecretValue"}},
			{PrincipalARN: "arn:aws:iam::111122223333:role/describe-only", Effect: "Allow", Actions: []string{"secretsmanager:DescribeSecret"}},
		},
	}}
	secretGrants := staticGrantsFromSecretsRecords(secretRecords)
	if len(secretGrants) != 1 || secretGrants[0].PrincipalARN != "arn:aws:iam::111122223333:role/reader" {
		t.Fatalf("expected single read grant, got %+v", secretGrants)
	}
	if len(secretGrants[0].Actions) != 1 || secretGrants[0].Actions[0] != "secretsmanager:GetSecretValue" {
		t.Fatalf("expected normalized read action to be preserved, got %+v", secretGrants[0].Actions)
	}
	if secretGrants[0].Source != secretsaccess.SourceResourcePolicy {
		t.Fatalf("unexpected secret grant source: %+v", secretGrants[0])
	}
}

func TestStaticGrantsFromKMSPreservesExplicitWildcardDeny(t *testing.T) {
	kmsRecords := []AWSKMSDecryptReachabilityRecord{{
		AccountID:  "111122223333",
		Region:     "us-east-1",
		KeyARN:     "arn:aws:kms:us-east-1:111122223333:key/k1",
		KeyID:      "k1",
		Confidence: 0.9,
		IdentityGrants: []AWSKMSIdentityGrant{
			{
				PrincipalARN:      "arn:aws:iam::111122223333:role/app",
				Effect:            "Allow",
				Capabilities:      []string{"decrypt"},
				Actions:           []string{"kms:Decrypt"},
				WildcardPrincipal: false,
			},
			{
				PrincipalARN:      "*",
				Effect:            "Deny",
				Capabilities:      []string{"decrypt"},
				Actions:           []string{"kms:Decrypt"},
				WildcardPrincipal: true,
			},
			{
				PrincipalARN:      "*",
				Effect:            "Allow",
				Capabilities:      []string{"decrypt"},
				Actions:           []string{"kms:Decrypt"},
				WildcardPrincipal: true,
			},
		},
	}}

	grants := staticGrantsFromKMSRecords(kmsRecords)
	if len(grants) != 2 {
		t.Fatalf("expected concrete allow plus wildcard deny grants, got %+v", grants)
	}

	hasWildcardDeny := false
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") && grant.PrincipalARN == "*" {
			hasWildcardDeny = true
		}
		if strings.EqualFold(grant.Effect, "Allow") && strings.Contains(grant.PrincipalARN, "role/app") {
			// existing behavior: concrete identity allow is still preserved.
			continue
		}
		if strings.EqualFold(grant.Effect, "Allow") && grant.PrincipalARN == "*" {
			t.Fatalf("wildcard allow grant should not be preserved for KMS identity grants: %+v", grant)
		}
	}
	if !hasWildcardDeny {
		t.Fatalf("expected wildcard deny to be preserved: %+v", grants)
	}
}
