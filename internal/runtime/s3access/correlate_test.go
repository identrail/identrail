package s3access

import (
	"strings"
	"testing"
	"time"
)

func observedAt(min int) time.Time {
	return time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
}

func findByBucket(t *testing.T, result Result, bucketARN string) Correlation {
	t.Helper()
	for _, correlation := range result.Correlations {
		if correlation.BucketARN == bucketARN {
			return correlation
		}
	}
	t.Fatalf("no correlation for bucket %q in %+v", bucketARN, result.Correlations)
	return Correlation{}
}

func hasCaveat(caveats []string, want string) bool {
	for _, caveat := range caveats {
		if caveat == want {
			return true
		}
	}
	return false
}

func TestCorrelateConfirmedJoinsObservedWithStaticGrant(t *testing.T) {
	bucketARN := "arn:aws:s3:::payments-data"
	identity := "aws:identity:role:payments-app"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-1",
			IdentityNodeID: identity,
			PrincipalARN:   "arn:aws:iam::111122223333:role/payments-app",
			BucketARN:      bucketARN,
			BucketName:     "payments-data",
			AccessMode:     ModeRead,
			SafePrefixes:   []string{"reports"},
			Action:         "s3:GetObject",
			SessionID:      "ASIA-sess",
			LineageStatus:  "resolved",
			ObservedAt:     observedAt(5),
			EvidenceRef:    "runtime-evidence://evt-1",
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity,
			BucketARN:      bucketARN,
			AllowedModes:   []string{ModeRead, ModeList},
			Source:         SourceBucketPolicy,
			Effect:         "Allow",
			Confidence:     0.9,
			EvidenceRef:    "s3-evidence://payments-data",
		}},
	})
	if len(result.Correlations) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(result.Correlations))
	}
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected confirmed, got %q", correlation.Status)
	}
	if correlation.Confidence != 0.95 {
		t.Fatalf("expected 0.95 confidence, got %v", correlation.Confidence)
	}
	if !hasMode(correlation.ObservedModes, ModeRead) || !hasMode(correlation.GrantedModes, ModeRead) {
		t.Fatalf("expected read mode tracked, got observed=%v granted=%v", correlation.ObservedModes, correlation.GrantedModes)
	}
	if len(correlation.SafePrefixes) != 1 || correlation.SafePrefixes[0] != "reports" {
		t.Fatalf("expected safe prefix carried, got %+v", correlation.SafePrefixes)
	}
	if hasCaveat(correlation.Caveats, CaveatModeExceedsGrant) {
		t.Fatalf("read mode is granted, must not flag mode-exceeds-grant: %+v", correlation.Caveats)
	}
	if correlation.RedactionBoundary != RedactionBoundary {
		t.Fatalf("missing redaction boundary: %+v", correlation)
	}
	if result.ConfirmedCount != 1 || result.ReadCount != 1 || result.BucketCount != 1 || result.IdentityCount != 1 {
		t.Fatalf("unexpected result counts: %+v", result)
	}
}

func TestCorrelateConfirmedFlagsModeExceedingGrant(t *testing.T) {
	bucketARN := "arn:aws:s3:::reports"
	identity := "aws:identity:role:writer"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID: "w", IdentityNodeID: identity, BucketARN: bucketARN, AccessMode: ModeWrite, Action: "s3:PutObject", ObservedAt: observedAt(1),
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity, BucketARN: bucketARN, AllowedModes: []string{ModeRead}, Source: SourceBucketPolicy, Effect: "Allow",
		}},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected confirmed (bucket is reachable), got %q", correlation.Status)
	}
	if !hasCaveat(correlation.Caveats, CaveatModeExceedsGrant) {
		t.Fatalf("expected mode-exceeds-grant caveat (observed write, only read granted): %+v", correlation.Caveats)
	}
	if correlation.Confidence != 0.8 {
		t.Fatalf("expected confidence capped to 0.8 for mode drift, got %v", correlation.Confidence)
	}
	if result.ModeExceedsGrantCount != 1 {
		t.Fatalf("expected mode-exceeds-grant count, got %+v", result)
	}
}

func TestCorrelateObservedWithoutGrant(t *testing.T) {
	bucketARN := "arn:aws:s3:::ungoverned"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID: "evt-2", IdentityNodeID: "aws:identity:role:agent", BucketARN: bucketARN, AccessMode: ModeRead, LineageStatus: "resolved", ObservedAt: observedAt(1),
		}},
		DataEventCoverageUnknown: true,
	})
	correlation := findByBucket(t, result, bucketARN)
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant, got %q", correlation.Status)
	}
	if correlation.Confidence != 0.6 || !hasCaveat(correlation.Caveats, CaveatNoStaticPath) {
		t.Fatalf("unexpected observed_without_grant correlation: %+v", correlation)
	}
	found := false
	for _, caveat := range result.Caveats {
		if strings.Contains(caveat, "IAM identity policies") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected IAM-policy result caveat, got %+v", result.Caveats)
	}
}

func TestCorrelateGrantedUnusedCarriesMissingEventCaveat(t *testing.T) {
	bucketARN := "arn:aws:s3:::dormant"
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{{
			IdentityNodeID: "aws:identity:role:dormant", BucketARN: bucketARN, AllowedModes: []string{ModeRead, ModeWrite}, Source: SourceBucketPolicy, Effect: "Allow", Confidence: 0.88,
		}},
		DataEventCoverageUnknown: true,
	})
	correlation := findByBucket(t, result, bucketARN)
	if correlation.Status != StatusGrantedUnused {
		t.Fatalf("expected granted_unused, got %q", correlation.Status)
	}
	if correlation.Confidence != 0.5 || !hasCaveat(correlation.Caveats, CaveatDataEventCoverage) {
		t.Fatalf("expected 0.5 confidence + missing-event caveat, got %+v", correlation)
	}
	if len(result.Caveats) == 0 {
		t.Fatalf("expected result-level missing-event caveat")
	}
}

func TestCorrelateConfirmedCappedForLineageAndConditional(t *testing.T) {
	bucketARN := "arn:aws:s3:::cond"
	identity := "aws:identity:role:cond"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{EventID: "e", IdentityNodeID: identity, BucketARN: bucketARN, AccessMode: ModeRead, LineageStatus: "source_identity_missing", ObservedAt: observedAt(1)}},
		Static:   []StaticGrant{{IdentityNodeID: identity, BucketARN: bucketARN, AllowedModes: []string{ModeRead}, Source: SourceBucketPolicy, Effect: "Allow", Conditional: true, CrossAccount: true}},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected confirmed, got %q", correlation.Status)
	}
	if correlation.Confidence != 0.85 {
		t.Fatalf("expected confidence capped to 0.85, got %v", correlation.Confidence)
	}
	if !hasCaveat(correlation.Caveats, CaveatConditionalGrant) || !hasCaveat(correlation.Caveats, CaveatCrossAccountGrant) || !hasCaveat(correlation.Caveats, CaveatLineageUnresolved) {
		t.Fatalf("expected conditional/cross-account/lineage caveats, got %+v", correlation.Caveats)
	}
}

func TestCorrelateAllowPlusExplicitDenyIsNotConfirmed(t *testing.T) {
	bucketARN := "arn:aws:s3:::mixed"
	identity := "aws:identity:role:mixed"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{EventID: "m", IdentityNodeID: identity, BucketARN: bucketARN, AccessMode: ModeRead, ObservedAt: observedAt(1)}},
		Static: []StaticGrant{
			{IdentityNodeID: identity, BucketARN: bucketARN, AllowedModes: []string{ModeRead}, Source: SourceBucketPolicy, Effect: "Allow"},
			{IdentityNodeID: identity, BucketARN: bucketARN, Source: SourceBucketPolicy, Effect: "Deny"},
		},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant when explicit deny present, got %q", correlation.Status)
	}
	if !hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) || correlation.StaticEffect != "Deny" {
		t.Fatalf("expected observed-despite-deny + deny effect, got %+v", correlation)
	}
	if hasCaveat(correlation.Caveats, CaveatNoStaticPath) {
		t.Fatalf("no-static-path is misleading when an allow exists: %+v", correlation.Caveats)
	}
	if result.ConfirmedCount != 0 {
		t.Fatalf("expected zero confirmed, got %+v", result)
	}
}

func TestCorrelateIgnoresDenyForUnobservedModes(t *testing.T) {
	bucketARN := "arn:aws:s3:::read-allowed-write-denied"
	identity := "aws:identity:role:reader"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{EventID: "read", IdentityNodeID: identity, BucketARN: bucketARN, AccessMode: ModeRead, Action: "s3:GetObject", ObservedAt: observedAt(1)}},
		Static: []StaticGrant{
			{IdentityNodeID: identity, BucketARN: bucketARN, AllowedModes: []string{ModeRead}, Source: SourceBucketPolicy, Effect: "Allow"},
			{IdentityNodeID: identity, BucketARN: bucketARN, AllowedModes: []string{ModeWrite}, Source: SourceBucketPolicy, Effect: "Deny"},
		},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected read access to stay confirmed when only write is denied, got %+v", correlation)
	}
	if correlation.StaticEffect != "Allow" || hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) {
		t.Fatalf("write-only deny must not flag observed read access, got %+v", correlation)
	}
}

func TestCorrelateWildcardDenyAppliesToObservedPrincipal(t *testing.T) {
	bucketARN := "arn:aws:s3:::wildcard-denied"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "denied-read",
			IdentityNodeID: "aws:identity:role:reader",
			PrincipalARN:   "arn:aws:iam::111122223333:role/reader",
			BucketARN:      bucketARN,
			AccessMode:     ModeRead,
			Action:         "s3:GetObject",
			ObservedAt:     observedAt(1),
			EvidenceRef:    "runtime-evidence://denied-read",
		}},
		Static: []StaticGrant{{
			PrincipalARN: "*",
			BucketARN:    bucketARN,
			AllowedModes: []string{ModeRead},
			Source:       SourceBucketPolicy,
			Effect:       "Deny",
			EvidenceRef:  "s3-evidence://wildcard-deny",
		}},
	})
	if len(result.Correlations) != 1 {
		t.Fatalf("expected observed principal correlation only, got %+v", result.Correlations)
	}
	correlation := result.Correlations[0]
	if correlation.PrincipalARN == "*" {
		t.Fatalf("wildcard deny must not create a standalone wildcard principal correlation: %+v", correlation)
	}
	if correlation.Status != StatusObservedWithoutGrant || correlation.StaticEffect != "Deny" {
		t.Fatalf("expected observed_without_grant with deny effect, got %+v", correlation)
	}
	if !hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) || hasCaveat(correlation.Caveats, CaveatNoStaticPath) {
		t.Fatalf("expected observed-despite-deny caveat without no-static-path, got %+v", correlation.Caveats)
	}
	if !containsString(correlation.EvidenceRefs, "s3-evidence://wildcard-deny") {
		t.Fatalf("expected wildcard deny evidence to be attached, got %+v", correlation.EvidenceRefs)
	}
}

func TestCorrelateSensitiveExposedBucketCaveat(t *testing.T) {
	bucketARN := "arn:aws:s3:::pii-public"
	identity := "aws:identity:role:reader"
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{{
			IdentityNodeID: identity, BucketARN: bucketARN, AllowedModes: []string{ModeRead}, Source: SourceBucketPolicy, Effect: "Allow",
			Sensitivity: "high", Exposure: "public",
		}},
		DataEventCoverageUnknown: true,
	})
	correlation := findByBucket(t, result, bucketARN)
	if !hasCaveat(correlation.Caveats, CaveatSensitiveExposed) {
		t.Fatalf("expected sensitive-exposed caveat for sensitive+public bucket, got %+v", correlation.Caveats)
	}
	if correlation.Sensitivity != "high" || correlation.Exposure != "public" {
		t.Fatalf("expected sensitivity/exposure carried, got %+v", correlation)
	}
	if result.SensitiveExposedCount != 1 {
		t.Fatalf("expected sensitive-exposed count, got %+v", result)
	}
}

func TestCorrelateDenyOnlyWithoutAccessIsNotSurfaced(t *testing.T) {
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{{IdentityNodeID: "aws:identity:role:x", BucketARN: "arn:aws:s3:::deny-only", Source: SourceBucketPolicy, Effect: "Deny"}},
	})
	if len(result.Correlations) != 0 {
		t.Fatalf("expected deny-only grant to be dropped, got %+v", result.Correlations)
	}
}

func TestCorrelateAggregatesRepeatedAccessesCaseInsensitive(t *testing.T) {
	bucketARN := "arn:aws:s3:::multi"
	identity := "aws:identity:role:Repeated"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{
			{EventID: "a", IdentityNodeID: identity, BucketARN: bucketARN, AccessMode: ModeRead, SafePrefixes: []string{"a"}, ObservedAt: observedAt(10)},
			{EventID: "b", IdentityNodeID: "AWS:IDENTITY:ROLE:REPEATED", BucketARN: bucketARN, AccessMode: ModeWrite, SafePrefixes: []string{"b"}, ObservedAt: observedAt(2)},
		},
		Static: []StaticGrant{{IdentityNodeID: identity, BucketARN: bucketARN, AllowedModes: []string{ModeRead, ModeWrite}, Source: SourceBucketPolicy, Effect: "Allow"}},
	})
	if len(result.Correlations) != 1 {
		t.Fatalf("expected case-insensitive aggregation into 1 correlation, got %d", len(result.Correlations))
	}
	correlation := result.Correlations[0]
	if correlation.ObservedCount != 2 || len(correlation.ObservedModes) != 2 || len(correlation.SafePrefixes) != 2 {
		t.Fatalf("expected aggregated observations/modes/prefixes, got %+v", correlation)
	}
	if !correlation.FirstObservedAt.Equal(observedAt(2)) || !correlation.LastObservedAt.Equal(observedAt(10)) {
		t.Fatalf("unexpected observed window, got first=%v last=%v", correlation.FirstObservedAt, correlation.LastObservedAt)
	}
}

func TestCorrelateSkipsUnattributableAndBucketlessRecords(t *testing.T) {
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{EventID: "no-identity", BucketARN: "arn:aws:s3:::x"}},
		Static:   []StaticGrant{{IdentityNodeID: "aws:identity:role:y", BucketARN: ""}},
	})
	if len(result.Correlations) != 0 {
		t.Fatalf("expected unattributable + bucketless records skipped, got %+v", result.Correlations)
	}
	if result.ObservedAccessConsidered != 0 || result.StaticGrantsConsidered != 0 {
		t.Fatalf("expected zero considered, got %+v", result)
	}
}

func TestCorrelateDeterministicOrdering(t *testing.T) {
	build := func() []Correlation {
		return Correlate(CorrelateRequest{
			Observed: []ObservedAccess{
				{EventID: "1", IdentityNodeID: "z", BucketARN: "arn:aws:s3:::b", AccessMode: ModeRead, ObservedAt: observedAt(1)},
				{EventID: "2", IdentityNodeID: "a", BucketARN: "arn:aws:s3:::a", AccessMode: ModeRead, ObservedAt: observedAt(1)},
				{EventID: "3", IdentityNodeID: "a", BucketARN: "arn:aws:s3:::b", AccessMode: ModeRead, ObservedAt: observedAt(1)},
			},
		}).Correlations
	}
	first := build()
	second := build()
	if len(first) != 3 {
		t.Fatalf("expected 3 correlations, got %d", len(first))
	}
	for i := range first {
		if first[i].CorrelationID != second[i].CorrelationID {
			t.Fatalf("ordering not deterministic at %d", i)
		}
	}
	if first[0].BucketARN != "arn:aws:s3:::a" || first[1].PrincipalARN != "" {
		// bucket :::a sorts first; within :::b, identity a before z.
		if first[1].BucketARN != "arn:aws:s3:::b" || first[2].BucketARN != "arn:aws:s3:::b" {
			t.Fatalf("unexpected ordering: %+v", first)
		}
	}
}

func hasMode(modes []string, want string) bool {
	for _, mode := range modes {
		if mode == want {
			return true
		}
	}
	return false
}
