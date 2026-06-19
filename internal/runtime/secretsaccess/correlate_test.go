package secretsaccess

import (
	"strings"
	"testing"
	"time"
)

func observedAt(min int) time.Time {
	return time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
}

func findCorrelation(t *testing.T, result Result, resourceARN string) Correlation {
	t.Helper()
	for _, correlation := range result.Correlations {
		if correlation.ResourceARN == resourceARN {
			return correlation
		}
	}
	t.Fatalf("no correlation for resource %q in %+v", resourceARN, result.Correlations)
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
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/cmk-1"
	identity := "aws:identity:role:payments-app"
	result := Correlate(CorrelateRequest{
		AccountID: "111122223333",
		Region:    "us-east-1",
		Observed: []ObservedAccess{{
			EventID:        "evt-1",
			IdentityNodeID: identity,
			PrincipalARN:   "arn:aws:iam::111122223333:role/payments-app",
			AccountID:      "111122223333",
			Region:         "us-east-1",
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			ResourceName:   "cmk-1",
			Action:         "kms:Decrypt",
			SessionID:      "ASIA-sess",
			LineageStatus:  "resolved",
			ObservedAt:     observedAt(5),
			EvidenceRef:    "runtime-evidence://evt-1",
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Source:         SourceKeyPolicy,
			Effect:         "Allow",
			Confidence:     0.9,
			EvidenceRef:    "kms-evidence://key/cmk-1",
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
	if correlation.ObservedCount != 1 || len(correlation.ObservedEventIDs) != 1 {
		t.Fatalf("expected one observed event, got %+v", correlation)
	}
	if len(correlation.StaticSources) != 1 || correlation.StaticSources[0] != SourceKeyPolicy {
		t.Fatalf("expected key_policy source, got %+v", correlation.StaticSources)
	}
	if len(correlation.EvidenceRefs) != 2 {
		t.Fatalf("expected runtime+static evidence refs, got %+v", correlation.EvidenceRefs)
	}
	if correlation.RedactionBoundary != RedactionBoundary {
		t.Fatalf("missing redaction boundary: %+v", correlation)
	}
	if result.ConfirmedCount != 1 || result.KMSKeyCorrelationCount != 1 || result.IdentityCount != 1 || result.ResourceCount != 1 {
		t.Fatalf("unexpected result counts: %+v", result)
	}
}

func TestCorrelateObservedWithoutGrant(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/api-key"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-2",
			IdentityNodeID: "aws:identity:role:invoice-agent",
			ResourceKind:   ResourceKindSecret,
			ResourceARN:    secretARN,
			Action:         "secretsmanager:GetSecretValue",
			LineageStatus:  "resolved",
			ObservedAt:     observedAt(1),
		}},
		DataEventCoverageUnknown: true,
	})

	correlation := findCorrelation(t, result, secretARN)
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant, got %q", correlation.Status)
	}
	if correlation.Confidence != 0.6 {
		t.Fatalf("expected 0.6 confidence, got %v", correlation.Confidence)
	}
	if !hasCaveat(correlation.Caveats, CaveatNoStaticPath) {
		t.Fatalf("expected no-static-path caveat, got %+v", correlation.Caveats)
	}
	if result.ObservedWithoutGrant != 1 {
		t.Fatalf("expected observed_without_grant count, got %+v", result)
	}
	// Result-level caveat about IAM-policy authorization must be present.
	found := false
	for _, caveat := range result.Caveats {
		if strings.Contains(caveat, "IAM identity policies") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected IAM-policy caveat in result, got %+v", result.Caveats)
	}
}

func TestCorrelateGrantedUnusedCarriesMissingEventCaveat(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/unused"
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{{
			IdentityNodeID: "aws:identity:role:dormant",
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Source:         SourceKMSGrant,
			Effect:         "Allow",
			Confidence:     0.88,
		}},
		DataEventCoverageUnknown: true,
	})

	correlation := findCorrelation(t, result, keyARN)
	if correlation.Status != StatusGrantedUnused {
		t.Fatalf("expected granted_unused, got %q", correlation.Status)
	}
	if correlation.Confidence != 0.5 {
		t.Fatalf("expected 0.5 confidence when data events unknown, got %v", correlation.Confidence)
	}
	if !hasCaveat(correlation.Caveats, CaveatDataEventCoverage) {
		t.Fatalf("expected missing-event caveat, got %+v", correlation.Caveats)
	}
	if len(result.Caveats) == 0 {
		t.Fatalf("expected result-level missing-event caveat")
	}
}

func TestCorrelateGrantedUnusedHigherConfidenceWhenCoverageKnown(t *testing.T) {
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{{
			PrincipalARN: "arn:aws:iam::111122223333:role/dormant",
			ResourceKind: ResourceKindKMSKey,
			ResourceARN:  "arn:aws:kms:us-east-1:111122223333:key/unused",
			Source:       SourceKMSGrant,
			Effect:       "Allow",
		}},
		DataEventCoverageUnknown: false,
	})
	correlation := result.Correlations[0]
	if correlation.Confidence != 0.7 {
		t.Fatalf("expected 0.7 confidence when coverage known, got %v", correlation.Confidence)
	}
	if hasCaveat(correlation.Caveats, CaveatDataEventCoverage) {
		t.Fatalf("did not expect missing-event caveat when coverage known: %+v", correlation.Caveats)
	}
}

func TestCorrelateConfirmedCappedForUnresolvedLineageAndConditionalGrant(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/cmk-cond"
	identity := "aws:identity:role:agent"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-3",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			LineageStatus:  "source_identity_missing",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Source:         SourceKeyPolicy,
			Effect:         "Allow",
			Conditional:    true,
			CrossAccount:   true,
		}},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected confirmed, got %q", correlation.Status)
	}
	// 0.95 base - 0.05 conditional = 0.90, then capped to 0.85 for unresolved lineage.
	if correlation.Confidence != 0.85 {
		t.Fatalf("expected confidence capped to 0.85, got %v", correlation.Confidence)
	}
	if !hasCaveat(correlation.Caveats, CaveatConditionalGrant) || !hasCaveat(correlation.Caveats, CaveatCrossAccountGrant) || !hasCaveat(correlation.Caveats, CaveatLineageUnresolved) {
		t.Fatalf("expected conditional/cross-account/lineage caveats, got %+v", correlation.Caveats)
	}
}

func TestCorrelateObservedDespiteExplicitDeny(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/denied"
	identity := "aws:identity:role:should-not"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-4",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Source:         SourceKeyPolicy,
			Effect:         "Deny",
		}},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant (deny is not an allow), got %q", correlation.Status)
	}
	if !hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) {
		t.Fatalf("expected observed-despite-deny caveat, got %+v", correlation.Caveats)
	}
	if correlation.StaticEffect != "Deny" {
		t.Fatalf("expected deny static effect, got %q", correlation.StaticEffect)
	}
}

func TestCorrelateAllowPlusExplicitDenyIsNotConfirmed(t *testing.T) {
	// An explicit Deny overrides any Allow in AWS, so an observed access
	// against a resource carrying both must not be reported as a clean
	// confirmation.
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/allow-and-deny"
	identity := "aws:identity:role:mixed"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-mixed",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{
			{IdentityNodeID: identity, ResourceKind: ResourceKindKMSKey, ResourceARN: keyARN, Source: SourceKeyPolicy, Effect: "Allow"},
			{IdentityNodeID: identity, ResourceKind: ResourceKindKMSKey, ResourceARN: keyARN, Source: SourceKeyPolicy, Effect: "Deny"},
		},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant when an explicit deny is present, got %q", correlation.Status)
	}
	if !hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) {
		t.Fatalf("expected observed-despite-deny caveat, got %+v", correlation.Caveats)
	}
	if hasCaveat(correlation.Caveats, CaveatNoStaticPath) {
		t.Fatalf("no-static-path caveat is misleading when an allow exists: %+v", correlation.Caveats)
	}
	if correlation.StaticEffect != "Deny" {
		t.Fatalf("expected deny static effect, got %q", correlation.StaticEffect)
	}
	if result.ConfirmedCount != 0 {
		t.Fatalf("expected no confirmed correlations, got %+v", result)
	}
}

func TestCorrelateWildcardPrincipalDenyAppliesToObservedIdentity(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/allow-and-wildcard-deny"
	identity := "aws:identity:role:observed"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-wildcard-deny",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Action:         "kms:Decrypt",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Allow",
				Actions:        []string{"kms:Decrypt"},
			},
			{
				PrincipalARN: "*",
				ResourceKind: ResourceKindKMSKey,
				ResourceARN:  keyARN,
				Source:       SourceKeyPolicy,
				Effect:       "Deny",
				Actions:      []string{"kms:Decrypt"},
			},
		},
	})

	correlation := findCorrelation(t, result, keyARN)
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant when wildcard deny applies, got %q", correlation.Status)
	}
	if correlation.StaticEffect != "Deny" {
		t.Fatalf("expected deny static effect when wildcard deny applies, got %q", correlation.StaticEffect)
	}
	if !hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) {
		t.Fatalf("expected observed-despite-deny caveat, got %+v", correlation.Caveats)
	}
	if hasCaveat(correlation.Caveats, CaveatNoStaticPath) {
		t.Fatalf("no-static-path caveat should not appear when deny is present, got %+v", correlation.Caveats)
	}
}

func TestCorrelateWildcardPrincipalSecretDenyAppliesToObservedIdentity(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:111122223333:secret:allow-and-wildcard-deny"
	identity := "aws:identity:role:secret-reader"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-secret-wildcard-deny",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindSecret,
			ResourceARN:    secretARN,
			Action:         "secretsmanager:GetSecretValue",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindSecret,
				ResourceARN:    secretARN,
				Source:         SourceResourcePolicy,
				Effect:         "Allow",
				Actions:        []string{"secretsmanager:GetSecretValue"},
			},
			{
				PrincipalARN: "*",
				ResourceKind: ResourceKindSecret,
				ResourceARN:  secretARN,
				Source:       SourceResourcePolicy,
				Effect:       "Deny",
				Actions:      []string{"secretsmanager:GetSecretValue"},
			},
		},
	})

	correlation := findCorrelation(t, result, secretARN)
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant when wildcard secret deny applies, got %q", correlation.Status)
	}
	if correlation.StaticEffect != "Deny" {
		t.Fatalf("expected deny static effect when wildcard secret deny applies, got %q", correlation.StaticEffect)
	}
	if !hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) {
		t.Fatalf("expected observed-despite-deny caveat, got %+v", correlation.Caveats)
	}
}

func TestCorrelateDenySpecificActionDoesNotBlockOtherKMSAction(t *testing.T) {
	// Explicit deny rules are action-specific in AWS. A deny for a different
	// KMS action should not downgrade a matching Decrypt access to
	// observed-without-grant.
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/allow-decrypt-deny-generate"
	identity := "aws:identity:role:mixed-actions"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-mixed-action",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Action:         "kms:Decrypt",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Allow",
				Actions:        []string{"kms:Decrypt"},
			},
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKMSGrant,
				Effect:         "Deny",
				Actions:        []string{"kms:GenerateDataKey"},
			},
		},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected confirmed when deny action does not match observed action, got %q", correlation.Status)
	}
	if hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) {
		t.Fatalf("unexpected observed-despite-deny caveat when deny does not apply, got %+v", correlation.Caveats)
	}
}

func TestCorrelateMatchingKMSDenyStillBlocksObservedAccess(t *testing.T) {
	// A deny for the observed KMS action should still force observed_without_grant,
	// even when an allow exists, because that access path is explicitly blocked.
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/allow-deny-match"
	identity := "aws:identity:role:matching-deny"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-matching-deny",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Action:         "kms:GenerateDataKey",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Allow",
				Actions:        []string{"kms:Decrypt", "kms:GenerateDataKey"},
			},
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Deny",
				Actions:        []string{"kms:GenerateDataKey"},
			},
		},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant when observed action is denied, got %q", correlation.Status)
	}
	if !hasCaveat(correlation.Caveats, CaveatObservedDespiteDeny) {
		t.Fatalf("expected observed-despite-deny caveat, got %+v", correlation.Caveats)
	}
	if correlation.StaticEffect != "Deny" {
		t.Fatalf("expected deny static effect, got %q", correlation.StaticEffect)
	}
}

func TestCorrelateObservedKMSActionRequiresMatchingStaticAuthorization(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/observed-without-kms-decrypt"
	identity := "aws:identity:role:action-mismatch"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-generate",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Action:         "kms:GenerateDataKey",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    keyARN,
			Source:         SourceKeyPolicy,
			Effect:         "Allow",
			Actions:        []string{"kms:Decrypt"},
		}},
	})
	if len(result.Correlations) != 1 {
		t.Fatalf("expected one correlation, got %d", len(result.Correlations))
	}
	correlation := result.Correlations[0]
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant when observed action exceeds static authorization, got %q", correlation.Status)
	}
	if correlation.ObservedCount != 1 {
		t.Fatalf("expected one observed event, got %d", correlation.ObservedCount)
	}
	if result.ObservedWithoutGrant != 1 || result.ConfirmedCount != 0 {
		t.Fatalf("expected observed_without_grant to be 1 and confirmed to be 0, got %+v", result)
	}
}

func TestCorrelateObservedSecretActionRequiresMatchingStaticAuthorization(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:111122223333:secret:api-key"
	identity := "aws:identity:role:secret-action-mismatch"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-secret-action-mismatch",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindSecret,
			ResourceARN:    secretARN,
			Action:         "secretsmanager:BatchGetSecretValue",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindSecret,
			ResourceARN:    secretARN,
			Source:         SourceResourcePolicy,
			Effect:         "Allow",
			Actions:        []string{"secretsmanager:GetSecretValue"},
		}},
	})

	correlation := result.Correlations[0]
	if correlation.Status != StatusObservedWithoutGrant {
		t.Fatalf("expected observed_without_grant when secret action does not match static authorization, got %q", correlation.Status)
	}
}

func TestCorrelateObservedSecretActionMatchConfirmsAccess(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:111122223333:secret:api-key"
	identity := "aws:identity:role:secret-action-match"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-secret-action-match",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindSecret,
			ResourceARN:    secretARN,
			Action:         "secretsmanager:BatchGetSecretValue",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindSecret,
			ResourceARN:    secretARN,
			Source:         SourceResourcePolicy,
			Effect:         "Allow",
			Actions:        []string{"secretsmanager:BatchGetSecretValue"},
		}},
	})

	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected confirmed when secret action matches static authorization, got %q", correlation.Status)
	}
}

func TestCorrelateUnresolvedResourcesSeparatedByKind(t *testing.T) {
	// Same identity, two different unresolved (empty-ARN) accesses of
	// different kinds must not merge into one correlation.
	identity := "aws:identity:role:unresolved"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{
			{EventID: "s", IdentityNodeID: identity, ResourceKind: ResourceKindSecret, ResourceARN: "", ObservedAt: observedAt(1)},
			{EventID: "k", IdentityNodeID: identity, ResourceKind: ResourceKindKMSKey, ResourceARN: "", ObservedAt: observedAt(2)},
		},
	})
	if len(result.Correlations) != 2 {
		t.Fatalf("expected unresolved secret and kms accesses to stay separate, got %d (%+v)", len(result.Correlations), result.Correlations)
	}
	kinds := map[string]int{}
	for _, correlation := range result.Correlations {
		kinds[correlation.ResourceKind]++
		if !hasCaveat(correlation.Caveats, CaveatResourceUnresolved) {
			t.Fatalf("expected resource-unresolved caveat, got %+v", correlation.Caveats)
		}
	}
	if kinds[ResourceKindSecret] != 1 || kinds[ResourceKindKMSKey] != 1 {
		t.Fatalf("expected one secret and one kms correlation, got %+v", kinds)
	}
	if result.SecretCorrelationCount != 1 || result.KMSKeyCorrelationCount != 1 {
		t.Fatalf("expected accurate per-kind counts, got %+v", result)
	}
}

func TestCorrelateDenyOnlyWithoutAccessIsNotSurfaced(t *testing.T) {
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{{
			IdentityNodeID: "aws:identity:role:x",
			ResourceKind:   ResourceKindKMSKey,
			ResourceARN:    "arn:aws:kms:us-east-1:111122223333:key/deny-only",
			Source:         SourceKeyPolicy,
			Effect:         "Deny",
		}},
	})
	if len(result.Correlations) != 0 {
		t.Fatalf("expected deny-only grant to be dropped, got %+v", result.Correlations)
	}
}

func TestCorrelateStaticAllowPlusDenyWithoutAccessIsNotGrantedUnused(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/static-allow-deny"
	identity := "aws:identity:role:blocked-unused"
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Allow",
				Actions:        []string{"kms:Decrypt"},
			},
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Deny",
				Actions:        []string{"kms:Decrypt"},
			},
		},
	})

	if len(result.Correlations) != 0 {
		t.Fatalf("static allow+deny without observed access should not surface as unused reachability, got %+v", result.Correlations)
	}
	if result.GrantedUnusedCount != 0 {
		t.Fatalf("explicitly denied static pair must not count as granted_unused, got %+v", result)
	}
	if result.StaticGrantsConsidered != 2 {
		t.Fatalf("expected both static grants to remain considered, got %+v", result)
	}
}

func TestCorrelateStaticAllowPlusDifferentActionDenyRemainsGrantedUnused(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/static-allow-deny-different-action"
	identity := "aws:identity:role:decrypt-unused"
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Allow",
				Actions:        []string{"kms:Decrypt"},
			},
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Deny",
				Actions:        []string{"kms:GenerateDataKey"},
			},
		},
	})

	correlation := findCorrelation(t, result, keyARN)
	if correlation.Status != StatusGrantedUnused {
		t.Fatalf("expected decrypt allow to remain granted_unused when deny targets another action, got %q", correlation.Status)
	}
	if correlation.StaticEffect != "Allow" {
		t.Fatalf("expected allow effect for usable unused grant, got %q", correlation.StaticEffect)
	}
	if result.GrantedUnusedCount != 1 {
		t.Fatalf("expected one granted_unused correlation, got %+v", result)
	}
}

func TestCorrelateStaticWildcardAllowWithSpecificDenyRemainsGrantedUnused(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/static-wildcard-allow-specific-deny"
	identity := "aws:identity:role:broad-unused"
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Allow",
				Actions:        []string{"kms:*"},
			},
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Deny",
				Actions:        []string{"kms:GenerateDataKey"},
			},
		},
	})

	correlation := findCorrelation(t, result, keyARN)
	if correlation.Status != StatusGrantedUnused {
		t.Fatalf("expected broad allow to remain granted_unused when deny covers only one action, got %q", correlation.Status)
	}
}

func TestCorrelateStaticAllowCoveredByWildcardDenyIsSuppressed(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/static-allow-wildcard-deny"
	identity := "aws:identity:role:blocked-decrypt"
	result := Correlate(CorrelateRequest{
		Static: []StaticGrant{
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Allow",
				Actions:        []string{"kms:Decrypt"},
			},
			{
				IdentityNodeID: identity,
				ResourceKind:   ResourceKindKMSKey,
				ResourceARN:    keyARN,
				Source:         SourceKeyPolicy,
				Effect:         "Deny",
				Actions:        []string{"kms:*"},
			},
		},
	})

	if len(result.Correlations) != 0 || result.GrantedUnusedCount != 0 {
		t.Fatalf("allow covered by wildcard deny should be suppressed, got %+v", result)
	}
}

func TestCorrelateObservedActionMatchesAWSWildcardPattern(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:111122223333:secret:api-key-wildcard"
	identity := "aws:identity:role:secret-pattern-match"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{{
			EventID:        "evt-secret-pattern-match",
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindSecret,
			ResourceARN:    secretARN,
			Action:         "secretsmanager:GetSecretValue",
			ObservedAt:     observedAt(1),
		}},
		Static: []StaticGrant{{
			IdentityNodeID: identity,
			ResourceKind:   ResourceKindSecret,
			ResourceARN:    secretARN,
			Source:         SourceResourcePolicy,
			Effect:         "Allow",
			Actions:        []string{"*:GetSecretValu?"},
		}},
	})

	correlation := findCorrelation(t, result, secretARN)
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected observed action to match AWS wildcard pattern, got %q", correlation.Status)
	}
}

func TestCorrelateAggregatesRepeatedObservationsAndIsCaseInsensitive(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/cmk-multi"
	identity := "aws:identity:role:Repeated"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{
			{EventID: "a", IdentityNodeID: identity, ResourceKind: ResourceKindKMSKey, ResourceARN: keyARN, Action: "kms:Decrypt", SessionID: "s1", ObservedAt: observedAt(10)},
			{EventID: "b", IdentityNodeID: "AWS:IDENTITY:ROLE:REPEATED", ResourceKind: ResourceKindKMSKey, ResourceARN: keyARN, Action: "kms:GenerateDataKey", SessionID: "s2", ObservedAt: observedAt(2)},
		},
		Static: []StaticGrant{{IdentityNodeID: identity, ResourceKind: ResourceKindKMSKey, ResourceARN: keyARN, Source: SourceKeyPolicy, Effect: "Allow"}},
	})
	if len(result.Correlations) != 1 {
		t.Fatalf("expected case-insensitive aggregation into 1 correlation, got %d", len(result.Correlations))
	}
	correlation := result.Correlations[0]
	if correlation.ObservedCount != 2 || len(correlation.ObservedEventIDs) != 2 {
		t.Fatalf("expected 2 observations aggregated, got %+v", correlation)
	}
	if len(correlation.Actions) != 2 || len(correlation.SessionIDs) != 2 {
		t.Fatalf("expected actions/sessions aggregated, got %+v", correlation)
	}
	if !correlation.FirstObservedAt.Equal(observedAt(2)) || !correlation.LastObservedAt.Equal(observedAt(10)) {
		t.Fatalf("expected first/last observed window, got first=%v last=%v", correlation.FirstObservedAt, correlation.LastObservedAt)
	}
}

func TestCorrelateSkipsUnattributableAndResourcelessRecords(t *testing.T) {
	result := Correlate(CorrelateRequest{
		Observed: []ObservedAccess{
			{EventID: "no-identity", ResourceKind: ResourceKindSecret, ResourceARN: "arn:aws:secretsmanager:us-east-1:1:secret:x"},
		},
		Static: []StaticGrant{
			{IdentityNodeID: "aws:identity:role:y", ResourceKind: ResourceKindSecret, ResourceARN: ""},
		},
	})
	if len(result.Correlations) != 0 {
		t.Fatalf("expected unattributable observation and resourceless grant to be skipped, got %+v", result.Correlations)
	}
	if result.ObservedAccessConsidered != 0 || result.StaticGrantsConsidered != 0 {
		t.Fatalf("expected zero considered, got %+v", result)
	}
}

func TestCorrelateDeterministicOrdering(t *testing.T) {
	build := func() []Correlation {
		return Correlate(CorrelateRequest{
			Observed: []ObservedAccess{
				{EventID: "1", IdentityNodeID: "z", ResourceKind: ResourceKindSecret, ResourceARN: "arn:secret:b", ObservedAt: observedAt(1)},
				{EventID: "2", IdentityNodeID: "a", ResourceKind: ResourceKindKMSKey, ResourceARN: "arn:kms:a", ObservedAt: observedAt(1)},
				{EventID: "3", IdentityNodeID: "a", ResourceKind: ResourceKindSecret, ResourceARN: "arn:secret:a", ObservedAt: observedAt(1)},
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
			t.Fatalf("ordering not deterministic at %d: %q vs %q", i, first[i].CorrelationID, second[i].CorrelationID)
		}
	}
	// kms_key sorts before secret; within secret, arn:secret:a before arn:secret:b.
	if first[0].ResourceKind != ResourceKindKMSKey || first[1].ResourceARN != "arn:secret:a" || first[2].ResourceARN != "arn:secret:b" {
		t.Fatalf("unexpected ordering: %+v", first)
	}
}
