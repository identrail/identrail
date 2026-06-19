package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/runtime/s3access"
)

func newS3RuntimeAccessService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, project)
	seedAWSConnectorForScanTest(t, store, ctx, project, "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	return svc, "default"
}

func s3RecordsByStatus(records []AWSS3RuntimeAccessRecord) map[string]int {
	counts := map[string]int{}
	for _, record := range records {
		counts[record.Status]++
	}
	return counts
}

func TestGetAWSS3RuntimeAccessBuildsCorrelationContract(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newS3RuntimeAccessService(t, "project-s3-corr", now)

	result, err := svc.GetAWSS3RuntimeAccess(defaultScopeContext(), ws, "project-s3-corr", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "success"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.CurrentIssueRef != "#1519" || result.Version != awsS3RuntimeAccessVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	counts := s3RecordsByStatus(result.Records)
	if counts[s3access.StatusConfirmed] != 2 || counts[s3access.StatusObservedWithoutGrant] != 1 || counts[s3access.StatusGrantedUnused] != 2 {
		t.Fatalf("unexpected status distribution: %+v (records=%+v)", counts, result.Records)
	}
	if result.Summary.ReadCount == 0 || result.Summary.WriteCount == 0 || result.Summary.ListCount == 0 {
		t.Fatalf("expected read/write/list observed modes, got %+v", result.Summary)
	}
	if result.Summary.ModeExceedsGrantCount != 1 {
		t.Fatalf("expected one mode-exceeds-grant correlation, got %+v", result.Summary)
	}
	if result.Summary.SensitiveExposedCount != 1 {
		t.Fatalf("expected one sensitive-exposed correlation, got %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected relationships: %+v", result.Relationships)
	}
	if len(result.Caveats) == 0 {
		t.Fatalf("expected correlation caveats")
	}
	for _, record := range result.Records {
		if record.RedactionBoundary != s3access.RedactionBoundary {
			t.Fatalf("record leaked unsafe redaction boundary: %+v", record)
		}
		if record.EvidenceRef == "" || record.IdentityNodeID == "" || record.ResourceNodeID == "" || record.Confidence <= 0 || record.NextAction == "" {
			t.Fatalf("record missing required fields: %+v", record)
		}
		// No object keys may leak: bucket ARN must have no path separator
		// after the bucket name.
		if strings.Contains(strings.TrimPrefix(record.BucketARN, "arn:aws:s3:::"), "/") {
			t.Fatalf("bucket ARN leaked an object key: %q", record.BucketARN)
		}
	}
	if len(result.CoverageGaps) == 0 {
		t.Fatalf("expected base coverage gaps documenting object-key and data-event limits")
	}
}

func TestGetAWSS3RuntimeAccessFlagsModeExceedingGrant(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newS3RuntimeAccessService(t, "project-s3-mode", now)

	result, err := svc.GetAWSS3RuntimeAccess(defaultScopeContext(), ws, "project-s3-mode", AWSS3RuntimeAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Resource:     "ingest-landing",
	})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected one correlation for the ingest bucket, got %+v", result.Records)
	}
	record := result.Records[0]
	if record.Status != s3access.StatusConfirmed {
		t.Fatalf("expected confirmed (bucket reachable), got %q", record.Status)
	}
	if !hasS3Caveat(record.Caveats, s3access.CaveatModeExceedsGrant) {
		t.Fatalf("expected mode-exceeds-grant caveat, got %+v", record.Caveats)
	}
}

func TestGetAWSS3RuntimeAccessFiltersBySensitivityAndStatus(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newS3RuntimeAccessService(t, "project-s3-filter", now)

	high, err := svc.GetAWSS3RuntimeAccess(defaultScopeContext(), ws, "project-s3-filter", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "success", Sensitivity: "high"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if len(high.Records) != 1 || high.Records[0].Sensitivity != "high" {
		t.Fatalf("expected one high-sensitivity correlation, got %+v", high.Records)
	}
	if !hasS3Caveat(high.Records[0].Caveats, s3access.CaveatSensitiveExposed) {
		t.Fatalf("expected sensitive-exposed caveat on high+cross_account bucket: %+v", high.Records[0])
	}

	unused, err := svc.GetAWSS3RuntimeAccess(defaultScopeContext(), ws, "project-s3-filter", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "success", Status: "granted_unused"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if len(unused.Records) != 2 {
		t.Fatalf("expected two granted_unused correlations, got %+v", unused.Records)
	}
	for _, record := range unused.Records {
		if record.Status != s3access.StatusGrantedUnused {
			t.Fatalf("status filter leaked: %+v", record)
		}
	}
	if unused.AppliedFilters["status"] != "granted-unused" {
		t.Fatalf("expected applied (normalized) status filter, got %+v", unused.AppliedFilters)
	}
}

func TestGetAWSS3RuntimeAccessPermissionDeniedIsExplicit(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newS3RuntimeAccessService(t, "project-s3-denied", now)

	result, err := svc.GetAWSS3RuntimeAccess(defaultScopeContext(), ws, "project-s3-denied", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != "blocked" || result.Confidence != 0 {
		t.Fatalf("expected blocked permission-denied, got status=%q confidence=%v", result.Status, result.Confidence)
	}
	if len(result.Records) != 0 || len(result.Diagnostics) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected no records + diagnostics + coverage gaps, got %+v", result)
	}
}

func TestGetAWSS3RuntimeAccessEmptyAndPartialFailure(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newS3RuntimeAccessService(t, "project-s3-states", now)

	empty, err := svc.GetAWSS3RuntimeAccess(defaultScopeContext(), ws, "project-s3-states", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "empty"})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Records) != 0 || len(empty.CoverageGaps) == 0 {
		t.Fatalf("unexpected empty state: %+v", empty)
	}

	partial, err := svc.GetAWSS3RuntimeAccess(defaultScopeContext(), ws, "project-s3-states", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "partial_failure"})
	if err != nil {
		t.Fatalf("partial: %v", err)
	}
	if partial.Status != "degraded" {
		t.Fatalf("expected degraded partial-failure, got %q", partial.Status)
	}
	for _, record := range partial.Records {
		if record.Status == s3access.StatusConfirmed {
			t.Fatalf("partial-failure must not produce confirmed correlations: %+v", record)
		}
	}
}

func TestGetAWSS3RuntimeAccessDefaultLiveRequiresDeliveryFactory(t *testing.T) {
	// No fixture state + connected connector + no delivery factory wired:
	// the endpoint must not serve fixture data as if it were live.
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newS3RuntimeAccessService(t, "project-s3-live-default", now)

	result, err := svc.GetAWSS3RuntimeAccess(defaultScopeContext(), ws, "project-s3-live-default", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded when live delivery unavailable, got %q", result.Status)
	}
	if len(result.Records) != 0 {
		t.Fatalf("expected no records when live delivery is unavailable, got %+v", result.Records)
	}
	if result.FixtureState != "" {
		t.Fatalf("expected no fixture state when live delivery is unavailable, got %q", result.FixtureState)
	}
}

func TestGetAWSS3RuntimeAccessLiveRoutesDataEventsThroughDelivery(t *testing.T) {
	now := time.Date(2026, 6, 19, 19, 0, 0, 0, time.UTC)
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-s3-live")
	seedAWSConnectorForScanTest(t, store, ctx, "project-s3-live", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-s3-live", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	role := "arn:aws:iam::123456789012:role/data-reader"
	deliveryRecord := liveRuntimeRecord(t, "evt-s3-live", "api-call", "GetObject", "s3.amazonaws.com", "s3:GetObject", "application", "s3-delivery", role, "arn:aws:s3:::live-bucket/reports/q1.csv", "AWS::S3::Object", now.Add(-2*time.Minute))
	fake := &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{Status: "ready", Records: []AWSRuntimeEventRecord{deliveryRecord}}}
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	result, err := svc.GetAWSS3RuntimeAccess(ctx, "default", "project-s3-live", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if fake.calls == 0 {
		t.Fatalf("delivery factory was never used — S3 data events were not routed through delivery")
	}
	if result.FixtureState != "" {
		t.Fatalf("expected no fixture state for live S3 data, got %q", result.FixtureState)
	}
	var found *AWSS3RuntimeAccessRecord
	for i := range result.Records {
		if result.Records[i].BucketARN == "arn:aws:s3:::live-bucket" {
			found = &result.Records[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a correlation for the observed live-bucket access, got %+v", result.Records)
	}
	// Live static is empty, so the observed access is observed_without_grant.
	if found.Status != s3access.StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant for live observed access, got %q", found.Status)
	}
	// The object key must not have leaked: bucket only, plus a safe prefix.
	if found.BucketARN != "arn:aws:s3:::live-bucket" {
		t.Fatalf("bucket ARN leaked a key: %q", found.BucketARN)
	}
	if len(found.SafePrefixes) != 1 || found.SafePrefixes[0] != "reports" {
		t.Fatalf("expected single safe prefix 'reports', got %+v", found.SafePrefixes)
	}
	if !hasS3Mode(found.ObservedModes, s3access.ModeRead) {
		t.Fatalf("expected read mode, got %+v", found.ObservedModes)
	}
}

func TestGetAWSS3RuntimeAccessBlockedRuntimeSuppressesUnusedGrants(t *testing.T) {
	now := time.Date(2026, 6, 19, 19, 30, 0, 0, time.UTC)
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-s3-blocked")
	seedAWSConnectorForScanTest(t, store, ctx, "project-s3-blocked", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-s3-blocked", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		return &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{Status: "blocked", FailureReasons: []string{"runtime event sources are not authorized for this connector"}}}, nil
	}

	result, err := svc.GetAWSS3RuntimeAccess(ctx, "default", "project-s3-blocked", AWSS3RuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != "blocked" || len(result.Records) != 0 || result.Summary.GrantedUnusedCount != 0 {
		t.Fatalf("blocked runtime must not surface granted_unused grants: status=%q records=%d summary=%+v", result.Status, len(result.Records), result.Summary)
	}
}

func TestObservedS3AccessFromRuntimeRecordsFiltersAndRedacts(t *testing.T) {
	records := []AWSRuntimeEventRecord{
		{EventID: "s3get", EventType: "api-call", EventSource: "s3.amazonaws.com", EventName: "GetObject", Action: "s3:GetObject", ActorIdentityNodeID: "id-1", TargetResourceARN: "arn:aws:s3:::bucket/reports/2026/secret-customer@example.com.csv"},
		{EventID: "s3uuid", EventType: "api-call", EventSource: "s3.amazonaws.com", EventName: "PutObject", Action: "s3:PutObject", ActorIdentityNodeID: "id-2", TargetResourceARN: "arn:aws:s3:::bucket/3f9a1b2c-1111-2222-3333-444455556666/data"},
		{EventID: "bucket-policy", EventType: "api-call", EventSource: "s3.amazonaws.com", EventName: "PutBucketPolicy", Action: "s3:PutBucketPolicy", ActorIdentityNodeID: "id-3", TargetResourceARN: "arn:aws:s3:::bucket"},
		{EventID: "bucket-encryption", EventType: "api-call", EventSource: "s3.amazonaws.com", EventName: "GetBucketEncryption", Action: "s3:GetBucketEncryption", ActorIdentityNodeID: "id-4", TargetResourceARN: "arn:aws:s3:::bucket"},
		{EventID: "bucket-create", EventType: "api-call", EventSource: "s3.amazonaws.com", EventName: "CreateBucket", Action: "s3:CreateBucket", ActorIdentityNodeID: "id-5", TargetResourceARN: "arn:aws:s3:::bucket"},
		{EventID: "kms", EventType: "kms-decrypt", EventSource: "kms.amazonaws.com", Action: "kms:Decrypt", ActorIdentityNodeID: "id-6", TargetResourceARN: "arn:aws:kms:us-east-1:1:key/k"},
		{EventID: "analyzer-s3-action", EventType: "access-analyzer", EventSource: "access-analyzer.amazonaws.com", EventName: "GetObject", Action: "s3:GetObject", ActorIdentityNodeID: "id-7", TargetResourceARN: "arn:aws:s3:::bucket/reports/analyzer.csv"},
	}
	observed := observedS3AccessFromRuntimeRecords(records)
	if len(observed) != 2 {
		t.Fatalf("expected only the two S3 CloudTrail data events, got %d (%+v)", len(observed), observed)
	}
	for _, access := range observed {
		if strings.Contains(strings.TrimPrefix(access.BucketARN, "arn:aws:s3:::"), "/") {
			t.Fatalf("bucket ARN leaked a key: %q", access.BucketARN)
		}
		for _, prefix := range access.SafePrefixes {
			if strings.Contains(prefix, "@") || strings.Contains(prefix, "example.com") {
				t.Fatalf("safe prefix leaked an identifying value: %q", prefix)
			}
		}
	}
	// First event: top-level prefix "reports" is a safe folder name.
	if len(observed[0].SafePrefixes) != 1 || observed[0].SafePrefixes[0] != "reports" {
		t.Fatalf("expected safe prefix 'reports', got %+v", observed[0].SafePrefixes)
	}
	if observed[0].AccessMode != s3access.ModeRead {
		t.Fatalf("expected read mode, got %q", observed[0].AccessMode)
	}
	// Second event: UUID-like prefix must be redacted, write mode.
	if len(observed[1].SafePrefixes) != 1 || observed[1].SafePrefixes[0] != "<redacted>" {
		t.Fatalf("expected UUID prefix redacted, got %+v", observed[1].SafePrefixes)
	}
	if observed[1].AccessMode != s3access.ModeWrite {
		t.Fatalf("expected write mode, got %q", observed[1].AccessMode)
	}
}

func TestS3GrantAllowedModesMapsActionPatterns(t *testing.T) {
	cases := []struct {
		actions []string
		want    []string
	}{
		{actions: []string{"s3:GetObject"}, want: []string{s3access.ModeRead}},
		{actions: []string{"s3:GetObjectVersion"}, want: []string{s3access.ModeRead}},
		{actions: []string{"s3:PutObject", "s3:DeleteObject"}, want: []string{s3access.ModeWrite}},
		{actions: []string{"s3:PutObjectAcl"}, want: []string{s3access.ModeWrite}},
		{actions: []string{"s3:ListBucket"}, want: []string{s3access.ModeList}},
		{actions: []string{"s3:ListBucketVersions"}, want: []string{s3access.ModeList}},
		{actions: []string{"s3:*"}, want: []string{s3access.ModeRead, s3access.ModeWrite, s3access.ModeList}},
		{actions: []string{"s3:Get*"}, want: []string{s3access.ModeRead}},
	}
	for _, tc := range cases {
		got := s3GrantAllowedModes(tc.actions)
		if len(got) != len(tc.want) {
			t.Fatalf("actions %v: expected modes %v, got %v", tc.actions, tc.want, got)
		}
		for _, mode := range tc.want {
			if !hasS3Mode(got, mode) {
				t.Fatalf("actions %v: missing mode %q in %v", tc.actions, mode, got)
			}
		}
	}
}

func TestStaticGrantsFromS3RecordsProjectsIAMPrincipalsOnly(t *testing.T) {
	records := []AWSS3BucketReachabilityRecord{{
		AccountID:              "111122223333",
		Region:                 "us-east-1",
		BucketARN:              "arn:aws:s3:::pii-data",
		BucketName:             "pii-data",
		ExposureClassification: "cross_account",
		Confidence:             0.9,
		Tags:                   map[string]string{"data-classification": "pii"},
		IdentityGrants: []AWSS3IdentityGrant{
			{PrincipalARN: "arn:aws:iam::111122223333:role/reader", Effect: "Allow", Actions: []string{"s3:GetObject", "s3:ListBucket"}},
			{PrincipalARN: "*", WildcardPrincipal: true, Effect: "Allow", Actions: []string{"s3:GetObject"}},
			{PrincipalARN: "arn:aws:iam::111122223333:role/not-action", Effect: "Allow", Actions: []string{"s3:GetObject"}, NotAction: true},
			{PrincipalARN: "arn:aws:iam::111122223333:role/no-recognized-action", Effect: "Allow", Actions: []string{"s3:GetBucketTagging"}},
		},
	}}
	grants := staticGrantsFromS3Records(records)
	if len(grants) != 1 || grants[0].PrincipalARN != "arn:aws:iam::111122223333:role/reader" {
		t.Fatalf("expected one IAM grant with recognized modes, got %+v", grants)
	}
	if grants[0].Sensitivity != "high" || grants[0].Exposure != "cross_account" {
		t.Fatalf("expected sensitivity/exposure projected, got %+v", grants[0])
	}
	if !hasS3Mode(grants[0].AllowedModes, s3access.ModeRead) || !hasS3Mode(grants[0].AllowedModes, s3access.ModeList) {
		t.Fatalf("expected read+list modes, got %+v", grants[0].AllowedModes)
	}
}

func TestStaticGrantsFromS3RecordsInvertsDenyNotAction(t *testing.T) {
	records := []AWSS3BucketReachabilityRecord{{
		AccountID: "111122223333",
		Region:    "us-east-1",
		BucketARN: "arn:aws:s3:::write-denied",
		IdentityGrants: []AWSS3IdentityGrant{{
			PrincipalARN: "arn:aws:iam::111122223333:role/writer",
			Effect:       "Deny",
			Actions:      []string{"s3:GetObject"},
			NotAction:    true,
		}},
	}}
	grants := staticGrantsFromS3Records(records)
	if len(grants) != 1 {
		t.Fatalf("expected one inverted deny grant, got %+v", grants)
	}
	if grants[0].Effect != "Deny" {
		t.Fatalf("expected deny effect, got %+v", grants[0])
	}
	if !hasS3Mode(grants[0].AllowedModes, s3access.ModeRead) {
		t.Fatalf("NotAction GetObject must preserve read because other read APIs are still denied, got %+v", grants[0].AllowedModes)
	}
	if !hasS3Mode(grants[0].AllowedModes, s3access.ModeWrite) || !hasS3Mode(grants[0].AllowedModes, s3access.ModeList) {
		t.Fatalf("NotAction GetObject should deny read+write+list modes, got %+v", grants[0].AllowedModes)
	}
}

func TestS3GrantAllowedModesForDenyNotActionDropsOnlyFullyExcludedModes(t *testing.T) {
	if modes := s3GrantAllowedModesForEffect([]string{"s3:GetObject"}, true, "Deny"); !hasS3Mode(modes, s3access.ModeRead) {
		t.Fatalf("single excluded read API must not drop the whole read mode, got %+v", modes)
	}
	if modes := s3GrantAllowedModesForEffect([]string{"s3:Get*"}, true, "Deny"); !hasS3Mode(modes, s3access.ModeRead) {
		t.Fatalf("partial read wildcard must not drop head/select read APIs, got %+v", modes)
	}
	if modes := s3GrantAllowedModesForEffect([]string{"s3:*"}, true, "Deny"); len(modes) != 0 {
		t.Fatalf("NotAction s3:* excludes all S3 data samples, got denied modes %+v", modes)
	}
}

func hasS3Caveat(caveats []string, want string) bool {
	for _, caveat := range caveats {
		if caveat == want {
			return true
		}
	}
	return false
}

func hasS3Mode(modes []string, want string) bool {
	for _, mode := range modes {
		if mode == want {
			return true
		}
	}
	return false
}
