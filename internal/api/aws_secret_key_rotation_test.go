package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newSecretKeyRotationService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSSecretKeyRotationPlansBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 0, 0, 0, time.UTC)
	svc, ws := newSecretKeyRotationService(t, "project-secret-key-rotation", now)

	result, err := svc.GetAWSSecretKeyRotationPlans(defaultScopeContext(), ws, "project-secret-key-rotation", AWSSecretKeyRotationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get secret key rotation: %v", err)
	}
	if result.CurrentIssueRef != "#1533" || result.Version != awsCredentialRotationVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Plans) == 0 {
		t.Fatalf("expected rotation plans: %+v", result)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 || len(result.Relationships) == 0 {
		t.Fatalf("expected caveats, coverage gaps, and relationships: %+v", result)
	}
	for i := 1; i < len(result.Plans); i++ {
		if result.Plans[i-1].Score < result.Plans[i].Score {
			t.Fatalf("plans are not ranked by descending score: %+v", result.Plans)
		}
	}
	for _, plan := range result.Plans {
		if plan.PlanID == "" || plan.CalculationVersion != awsCredentialRotationVersion {
			t.Fatalf("plan missing stable metadata: %+v", plan)
		}
		if plan.RotationType == "" || plan.Title == "" || plan.OwnerHandoff.Owner == "" {
			t.Fatalf("plan missing classification or owner handoff: %+v", plan)
		}
		if len(plan.TargetSecrets) == 0 {
			t.Fatalf("plan must target at least one secret metadata ref: %+v", plan)
		}
		if len(plan.RotationOrder) < 5 {
			t.Fatalf("plan must include prepare/dry-run/apply/refresh/verify order: %+v", plan.RotationOrder)
		}
		if !plan.ReadOnlyProjection || !plan.DiffIntent.ReadOnlyProjection {
			t.Fatalf("plan must be a read-only projection: %+v", plan)
		}
		if plan.RollbackPlan.Strategy == "" || len(plan.RollbackPlan.Steps) == 0 {
			t.Fatalf("plan missing rollback plan: %+v", plan.RollbackPlan)
		}
		if plan.VerificationPlan.Strategy == "" || len(plan.VerificationPlan.SuccessSignals) == 0 {
			t.Fatalf("plan missing verification plan: %+v", plan.VerificationPlan)
		}
		if plan.EvidenceBoundary != awsSecretKeyRotationEvidenceBoundary() {
			t.Fatalf("plan crossed evidence boundary: %+v", plan)
		}
		serialized, err := json.Marshal(plan)
		if err != nil {
			t.Fatalf("marshal plan: %v", err)
		}
		lower := strings.ToLower(string(serialized))
		for _, forbidden := range []string{"\"secret_string\"", "\"secret_value\"", "\"private_key\"", "\"access_key_secret\""} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("plan serialized forbidden sensitive payload marker %q: %s", forbidden, lower)
			}
		}
	}
}

func TestGetAWSSecretKeyRotationPlansAppliesFilters(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 5, 0, 0, time.UTC)
	svc, ws := newSecretKeyRotationService(t, "project-secret-key-rotation-filters", now)

	provider, err := svc.GetAWSSecretKeyRotationPlans(defaultScopeContext(), ws, "project-secret-key-rotation-filters", AWSSecretKeyRotationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		RotationType: "provider_key",
	})
	if err != nil {
		t.Fatalf("provider-key filter: %v", err)
	}
	if provider.AppliedFilters["rotation_type"] != "provider-key" {
		t.Fatalf("expected applied rotation_type filter, got %+v", provider.AppliedFilters)
	}
	for _, plan := range provider.Plans {
		if plan.RotationType != "provider_key" {
			t.Fatalf("rotation_type filter leaked %s plan: %+v", plan.RotationType, plan)
		}
	}

	search, err := svc.GetAWSSecretKeyRotationPlans(defaultScopeContext(), ws, "project-secret-key-rotation-filters", AWSSecretKeyRotationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Search:       "rotation_re_evaluate",
	})
	if err != nil {
		t.Fatalf("search filter: %v", err)
	}
	if len(search.Plans) == 0 {
		t.Fatalf("expected search to match verification strategy")
	}
}

func TestAWSSecretKeyRotationPlanFromMetadataIncludesKMSAndWorkloads(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 10, 0, 0, time.UTC)
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Service:       "secretsmanager",
		SecretARN:     "arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/api-key",
		SecretName:    "payments/api-key",
		KMSKeyARN:     "arn:aws:kms:us-east-1:123456789012:key/abcd",
		OwningService: "payments",
		SecretStatus:  "active",
		EvidenceRef:   "evidence://secret/payments",
		FromNodeID:    "aws:resource:secrets-manager-secret:payments/api-key",
		Confidence:    0.84,
		Tags:          map[string]string{"owner": "payments-platform"},
		ReferencedBy:  []AWSSecretsManagerWorkloadReference{{WorkloadID: "lambda:payments", WorkloadName: "payments-worker", WorkloadType: "lambda"}},
	}
	kms := map[string]AWSKMSDecryptReachabilityRecord{
		strings.ToLower(secret.KMSKeyARN): {
			KeyARN:      secret.KMSKeyARN,
			KeyID:       "abcd",
			Aliases:     []string{"alias/payments"},
			FromNodeID:  "aws:resource:kms-key:abcd",
			EvidenceRef: "evidence://kms/abcd",
		},
	}
	plan := awsSecretKeyRotationPlanFromMetadata(secret, map[string][]AWSSecretsManagerMetadataRecord{strings.ToLower(secret.KMSKeyARN): {secret, secret}}, kms, now)
	if plan.RotationType != "secrets_manager_secret" || len(plan.TargetKeys) != 1 || len(plan.DependentWorkloads) != 1 {
		t.Fatalf("metadata plan missing kms/workload context: %+v", plan)
	}
	if plan.Provider != "payments" {
		t.Fatalf("metadata plan must expose provider for filters and counts, got %q", plan.Provider)
	}
	if plan.OwnerHandoff.Owner != "payments-platform" || !plan.OwnerHandoff.Assigned {
		t.Fatalf("metadata plan must hand off to tagged owner: %+v", plan.OwnerHandoff)
	}
	if len(plan.ReadinessGates) == 0 || !awsSecretKeyRotationSearchMatch(plan, "shared_kms_key") {
		t.Fatalf("expected shared KMS readiness gate to be searchable: %+v", plan.ReadinessGates)
	}
}

func TestAWSSecretKeyRotationPlanFromMetadataPreservesKMSKeyID(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 11, 0, 0, time.UTC)
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Service:       "secretsmanager",
		SecretARN:     "arn:aws:secretsmanager:us-east-1:123456789012:secret:billing/api-key",
		SecretName:    "billing/api-key",
		KMSKeyID:      "alias/billing-secrets",
		OwningService: "billing",
		SecretStatus:  "active",
		EvidenceRef:   "evidence://secret/billing",
		FromNodeID:    "aws:resource:secrets-manager-secret:billing/api-key",
		Confidence:    0.81,
		Tags:          map[string]string{"owner": "billing-platform"},
	}
	_, _, secretsByKMS := awsSecretPermissionSecretIndexes(AWSSecretsManagerMetadataInventoryResult{Records: []AWSSecretsManagerMetadataRecord{
		secret,
		{SecretARN: "arn:aws:secretsmanager:us-east-1:123456789012:secret:billing/webhook", KMSKeyID: "alias/billing-secrets"},
	}})
	kms := awsSecretKeyRotationKMSIndex(AWSKMSDecryptReachabilityInventoryResult{Records: []AWSKMSDecryptReachabilityRecord{{
		KeyID:       "key-billing",
		Aliases:     []string{"alias/billing-secrets"},
		FromNodeID:  "aws:resource:kms-key:key-billing",
		EvidenceRef: "evidence://kms/billing",
	}}})

	plan := awsSecretKeyRotationPlanFromMetadata(secret, secretsByKMS, kms, now)
	if len(plan.TargetKeys) != 1 {
		t.Fatalf("metadata plan must preserve kms key id target without resolved arn: %+v", plan)
	}
	if plan.TargetKeys[0].Label != "alias/billing-secrets" || plan.TargetKeys[0].MetadataRef != "evidence://kms/billing" {
		t.Fatalf("kms key target should use alias lookup and kms evidence: %+v", plan.TargetKeys[0])
	}
	if !awsSecretKeyRotationSearchMatch(plan, "shared_kms_key") {
		t.Fatalf("expected KMSKeyID-only shared KMS readiness gate: %+v", plan.ReadinessGates)
	}
	relationships := awsSecretKeyRotationRelationships([]AWSSecretKeyRotationPlan{plan})
	if !hasAWSSecretKeyRotationRelationship(relationships, "rotation_targets_kms_key", "aws:resource:kms-key:key-billing") {
		t.Fatalf("expected KMS target relationship from key id lookup: %+v", relationships)
	}

	noRecordPlan := awsSecretKeyRotationPlanFromMetadata(secret, secretsByKMS, nil, now)
	relationships = awsSecretKeyRotationRelationships([]AWSSecretKeyRotationPlan{noRecordPlan})
	if !hasAWSSecretKeyRotationRelationship(relationships, "rotation_targets_kms_key", "alias/billing-secrets") {
		t.Fatalf("expected KMS target relationship to fall back to key id: %+v", relationships)
	}
}

func TestAWSSecretKeyRotationPlanFromMetadataCanonicalizesSharedKMSRefs(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 11, 30, 0, time.UTC)
	keyARN := "arn:aws:kms:us-east-1:123456789012:key/billing"
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Service:       "secretsmanager",
		SecretARN:     "arn:aws:secretsmanager:us-east-1:123456789012:secret:billing/api-key",
		SecretName:    "billing/api-key",
		KMSKeyARN:     keyARN,
		OwningService: "billing",
		SecretStatus:  "active",
		EvidenceRef:   "evidence://secret/billing",
		FromNodeID:    "aws:resource:secrets-manager-secret:billing/api-key",
		Confidence:    0.81,
		Tags:          map[string]string{"owner": "billing-platform"},
	}
	_, _, secretsByKMS := awsSecretPermissionSecretIndexes(AWSSecretsManagerMetadataInventoryResult{Records: []AWSSecretsManagerMetadataRecord{
		secret,
		{SecretARN: "arn:aws:secretsmanager:us-east-1:123456789012:secret:billing/webhook", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:alias/billing-secrets"},
	}})
	kms := awsSecretKeyRotationKMSIndex(AWSKMSDecryptReachabilityInventoryResult{Records: []AWSKMSDecryptReachabilityRecord{{
		KeyARN:     keyARN,
		KeyID:      "billing",
		Aliases:    []string{"alias/billing-secrets"},
		FromNodeID: "aws:resource:kms-key:billing",
	}}})

	plan := awsSecretKeyRotationPlanFromMetadata(secret, awsSecretKeyRotationCanonicalSecretsByKMS(secretsByKMS, kms), kms, now)
	if !awsSecretKeyRotationSearchMatch(plan, "shared_kms_key") {
		t.Fatalf("expected shared KMS readiness gate for canonical arn/alias refs: %+v", plan.ReadinessGates)
	}
}

func TestAWSSecretKeyRotationPlanFromMetadataDoesNotDuplicateCanonicalKMSRefs(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 11, 45, 0, time.UTC)
	keyARN := "arn:aws:kms:us-east-1:123456789012:key/billing"
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Service:       "secretsmanager",
		SecretARN:     "arn:aws:secretsmanager:us-east-1:123456789012:secret:billing/api-key",
		SecretName:    "billing/api-key",
		KMSKeyARN:     keyARN,
		KMSKeyID:      "alias/billing-secrets",
		OwningService: "billing",
		SecretStatus:  "active",
		EvidenceRef:   "evidence://secret/billing",
		FromNodeID:    "aws:resource:secrets-manager-secret:billing/api-key",
		Confidence:    0.81,
		Tags:          map[string]string{"owner": "billing-platform"},
	}
	_, _, secretsByKMS := awsSecretPermissionSecretIndexes(AWSSecretsManagerMetadataInventoryResult{Records: []AWSSecretsManagerMetadataRecord{secret}})
	kms := awsSecretKeyRotationKMSIndex(AWSKMSDecryptReachabilityInventoryResult{Records: []AWSKMSDecryptReachabilityRecord{{
		KeyARN:  keyARN,
		KeyID:   "billing",
		Aliases: []string{"alias/billing-secrets"},
	}}})

	canonicalSecretsByKMS := awsSecretKeyRotationCanonicalSecretsByKMS(secretsByKMS, kms)
	if got := len(canonicalSecretsByKMS[strings.ToLower(keyARN)]); got != 1 {
		t.Fatalf("expected canonical KMS bucket to dedupe same secret, got %d: %+v", got, canonicalSecretsByKMS)
	}
	plan := awsSecretKeyRotationPlanFromMetadata(secret, canonicalSecretsByKMS, kms, now)
	if awsSecretKeyRotationSearchMatch(plan, "shared_kms_key") {
		t.Fatalf("single secret with arn and alias refs must not get shared KMS gate: %+v", plan.ReadinessGates)
	}
}

func TestAWSSecretKeyRotationPlanFromMetadataScopesBareKMSAliases(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 11, 50, 0, time.UTC)
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:     "111111111111",
		Region:        "us-east-1",
		Service:       "secretsmanager",
		SecretARN:     "arn:aws:secretsmanager:us-east-1:111111111111:secret:billing/api-key",
		SecretName:    "billing/api-key",
		KMSKeyID:      "alias/aws/secretsmanager",
		OwningService: "billing",
		SecretStatus:  "active",
		EvidenceRef:   "evidence://secret/billing",
		FromNodeID:    "aws:resource:secrets-manager-secret:billing/api-key",
		Confidence:    0.81,
		Tags:          map[string]string{"owner": "billing-platform"},
	}
	otherAccountSecret := AWSSecretsManagerMetadataRecord{
		AccountID:  "222222222222",
		Region:     "us-east-1",
		SecretARN:  "arn:aws:secretsmanager:us-east-1:222222222222:secret:billing/webhook",
		SecretName: "billing/webhook",
		KMSKeyID:   "alias/aws/secretsmanager",
	}
	_, _, secretsByKMS := awsSecretPermissionSecretIndexes(AWSSecretsManagerMetadataInventoryResult{Records: []AWSSecretsManagerMetadataRecord{
		secret,
		otherAccountSecret,
	}})
	kms := awsSecretKeyRotationKMSIndex(AWSKMSDecryptReachabilityInventoryResult{Records: []AWSKMSDecryptReachabilityRecord{
		{AccountID: "111111111111", Region: "us-east-1", KeyARN: "arn:aws:kms:us-east-1:111111111111:key/primary", Aliases: []string{"alias/aws/secretsmanager"}, FromNodeID: "aws:resource:kms-key:111111111111/primary", EvidenceRef: "evidence://kms/111111111111"},
		{AccountID: "222222222222", Region: "us-east-1", KeyARN: "arn:aws:kms:us-east-1:222222222222:key/primary", Aliases: []string{"alias/aws/secretsmanager"}, FromNodeID: "aws:resource:kms-key:222222222222/primary", EvidenceRef: "evidence://kms/222222222222"},
	}})

	canonicalSecretsByKMS := awsSecretKeyRotationCanonicalSecretsByKMS(secretsByKMS, kms)
	if got := len(canonicalSecretsByKMS["arn:aws:kms:us-east-1:111111111111:key/primary"]); got != 1 {
		t.Fatalf("expected account-scoped alias bucket for first account, got %d: %+v", got, canonicalSecretsByKMS)
	}
	if got := len(canonicalSecretsByKMS["arn:aws:kms:us-east-1:222222222222:key/primary"]); got != 1 {
		t.Fatalf("expected account-scoped alias bucket for second account, got %d: %+v", got, canonicalSecretsByKMS)
	}
	plan := awsSecretKeyRotationPlanFromMetadata(secret, canonicalSecretsByKMS, kms, now)
	if len(plan.TargetKeys) != 1 || plan.TargetKeys[0].NodeID != "aws:resource:kms-key:111111111111/primary" || plan.TargetKeys[0].ARN != "arn:aws:kms:us-east-1:111111111111:key/primary" || plan.TargetKeys[0].MetadataRef != "evidence://kms/111111111111" {
		t.Fatalf("expected scoped KMS target metadata for first account: %+v", plan.TargetKeys)
	}
	if awsSecretKeyRotationSearchMatch(plan, "shared_kms_key") {
		t.Fatalf("same bare alias in another account must not get shared KMS gate: %+v", plan.ReadinessGates)
	}
}

func TestAWSSecretKeyRotationPlanFromMetadataAvoidsCrossScopeAliasFallback(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 11, 55, 0, time.UTC)
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:     "111111111111",
		Region:        "us-east-1",
		Service:       "secretsmanager",
		SecretARN:     "arn:aws:secretsmanager:us-east-1:111111111111:secret:billing/api-key",
		SecretName:    "billing/api-key",
		KMSKeyID:      "alias/aws/secretsmanager",
		OwningService: "billing",
		SecretStatus:  "active",
		EvidenceRef:   "evidence://secret/billing",
		FromNodeID:    "aws:resource:secrets-manager-secret:billing/api-key",
		Confidence:    0.81,
		Tags:          map[string]string{"owner": "billing-platform"},
	}
	otherAccountSecret := AWSSecretsManagerMetadataRecord{
		AccountID:  "222222222222",
		Region:     "us-east-1",
		SecretARN:  "arn:aws:secretsmanager:us-east-1:222222222222:secret:billing/webhook",
		SecretName: "billing/webhook",
		KMSKeyID:   "alias/aws/secretsmanager",
	}
	_, _, secretsByKMS := awsSecretPermissionSecretIndexes(AWSSecretsManagerMetadataInventoryResult{Records: []AWSSecretsManagerMetadataRecord{
		secret,
		otherAccountSecret,
	}})
	kms := awsSecretKeyRotationKMSIndex(AWSKMSDecryptReachabilityInventoryResult{Records: []AWSKMSDecryptReachabilityRecord{
		{AccountID: "222222222222", Region: "us-east-1", KeyARN: "arn:aws:kms:us-east-1:222222222222:key/primary", Aliases: []string{"alias/aws/secretsmanager"}, FromNodeID: "aws:resource:kms-key:222222222222/primary", EvidenceRef: "evidence://kms/222222222222"},
	}})

	canonicalSecretsByKMS := awsSecretKeyRotationCanonicalSecretsByKMS(secretsByKMS, kms)
	if got := len(canonicalSecretsByKMS["alias/aws/secretsmanager"]); got != 1 {
		t.Fatalf("expected unresolved first-account alias bucket to stay local, got %d: %+v", got, canonicalSecretsByKMS)
	}
	plan := awsSecretKeyRotationPlanFromMetadata(secret, canonicalSecretsByKMS, kms, now)
	if len(plan.TargetKeys) != 1 || plan.TargetKeys[0].NodeID == "aws:resource:kms-key:222222222222/primary" || plan.TargetKeys[0].MetadataRef == "evidence://kms/222222222222" {
		t.Fatalf("first-account secret must not borrow second-account KMS target: %+v", plan.TargetKeys)
	}
	if awsSecretKeyRotationSearchMatch(plan, "shared_kms_key") {
		t.Fatalf("missing scoped KMS record must not use another account for shared gate: %+v", plan.ReadinessGates)
	}
}

func TestAWSSecretKeyRotationPlanFromMetadataDoesNotAssignFallbackOwner(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 12, 0, 0, time.UTC)
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:    "123456789012",
		Region:       "us-east-1",
		Service:      "secretsmanager",
		SecretARN:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:ownerless/api-key",
		SecretName:   "ownerless/api-key",
		SecretStatus: "active",
		EvidenceRef:  "evidence://secret/ownerless",
		FromNodeID:   "aws:resource:secrets-manager-secret:ownerless/api-key",
		Confidence:   0.88,
	}

	plan := awsSecretKeyRotationPlanFromMetadata(secret, nil, nil, now)
	if plan.OwnerHandoff.Owner != "application-owner" {
		t.Fatalf("expected display fallback owner, got %+v", plan.OwnerHandoff)
	}
	if plan.OwnerHandoff.Assigned {
		t.Fatalf("fallback owner label must not count as assigned: %+v", plan.OwnerHandoff)
	}
	if plan.ReadyForApply {
		t.Fatalf("ownerless metadata plan must not become ready_for_apply: %+v", plan)
	}
	if plan.Provider != "secretsmanager" {
		t.Fatalf("metadata plan must populate provider from service fallback, got %q", plan.Provider)
	}
}

func TestAWSSecretKeyRotationTypeKeepsAWSNativeSecretFindings(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 13, 0, 0, time.UTC)
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:    "123456789012",
		Region:       "us-east-1",
		Service:      "secretsmanager",
		SecretARN:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders/api-key",
		SecretName:   "orders/api-key",
		SecretStatus: "active",
		EvidenceRef:  "evidence://secret/orders",
		FromNodeID:   "aws:resource:secrets-manager-secret:orders/api-key",
		Confidence:   0.82,
	}
	finding := AWSSecretPermissionEquivalenceFinding{
		FindingID:       "aws-secret-permission-equivalence:orders-reader",
		EquivalenceType: "secret_read_policy_equivalence",
		Severity:        "medium",
		Status:          "review",
		Score:           70,
		Confidence:      0.82,
		AccountID:       "123456789012",
		Region:          "us-east-1",
		IdentityNodeID:  "aws:identity:role/orders-reader",
		SecretNodeID:    secret.FromNodeID,
		SecretARN:       secret.SecretARN,
		SecretLabel:     secret.SecretName,
		Provider:        "aws_secret",
		Rationale:       "Role can read permission-bearing Secrets Manager metadata.",
		Evidence:        []AWSSecretPermissionEquivalenceEvidence{{Source: "secrets_manager_metadata", EvidenceRef: secret.EvidenceRef}},
	}

	plan, ok := awsSecretKeyRotationPlanFromEquivalence(finding, map[string]AWSSecretsManagerMetadataRecord{strings.ToLower(secret.SecretARN): secret}, map[string]AWSSecretsManagerMetadataRecord{strings.ToLower(secret.FromNodeID): secret}, nil, nil, now)
	if !ok {
		t.Fatalf("expected AWS-native secret finding to produce a rotation plan")
	}
	if plan.RotationType != "secrets_manager_secret" {
		t.Fatalf("AWS-native secret finding must stay a secret rotation, got %+v", plan)
	}
	filtered, _ := filterAWSSecretKeyRotationPlans([]AWSSecretKeyRotationPlan{plan}, AWSSecretKeyRotationRequest{RotationType: "secrets_manager_secret"})
	if len(filtered) != 1 {
		t.Fatalf("secret rotation filter should include AWS-native secret finding plan: %+v", plan)
	}

	external := finding
	external.Provider = credentialProviderOpenAI
	if got := awsSecretKeyRotationType(external, AWSSecretsManagerMetadataRecord{}); got != "provider_key" {
		t.Fatalf("external provider finding should remain provider_key, got %q", got)
	}
	external.EquivalenceType = "kms_decrypt_secret_equivalence"
	if got := awsSecretKeyRotationType(external, AWSSecretsManagerMetadataRecord{}); got != "kms_related" {
		t.Fatalf("external provider KMS finding should remain kms_related, got %q", got)
	}
	external.EquivalenceType = "workload_provider_key_equivalence"
	providerKeySecret := secret
	providerKeySecret.KMSKeyID = "alias/orders-secrets"
	if got := awsSecretKeyRotationType(external, providerKeySecret); got != "provider_key" {
		t.Fatalf("external provider finding with KMS metadata should remain provider_key, got %q", got)
	}

	aliasBackedSecret := secret
	aliasBackedSecret.KMSKeyID = "alias/orders-secrets"
	if got := awsSecretKeyRotationType(finding, aliasBackedSecret); got != "kms_related" {
		t.Fatalf("AWS-native secret finding with KMSKeyID should be kms_related, got %q", got)
	}
}

func hasAWSSecretKeyRotationRelationship(relationships []AWSSecretKeyRotationRelationship, relationshipType string, toNodeID string) bool {
	for _, relationship := range relationships {
		if relationship.Type == relationshipType && relationship.ToNodeID == toNodeID {
			return true
		}
	}
	return false
}

func TestAWSSecretKeyRotationWorkloadsIncludeFindingConsumer(t *testing.T) {
	secret := AWSSecretsManagerMetadataRecord{
		OwningService: "payments",
		ReferencedBy: []AWSSecretsManagerWorkloadReference{{
			WorkloadID:   "lambda:payments",
			WorkloadName: "payments-worker",
			WorkloadType: "lambda",
		}},
	}
	finding := AWSSecretPermissionEquivalenceFinding{
		AgentID:        "case-triage",
		AgentName:      "case-triage",
		IdentityNodeID: "aws:identity:case-triage-runtime",
	}

	workloads := awsSecretKeyRotationWorkloads(secret, finding)
	if len(workloads) != 2 {
		t.Fatalf("expected metadata and finding workloads, got %+v", workloads)
	}
	if workloads[0].WorkloadID != "lambda:payments" || workloads[0].RefreshOrder != 1 {
		t.Fatalf("metadata workload should stay first: %+v", workloads)
	}
	if workloads[1].WorkloadID != "case-triage" || workloads[1].RefreshOrder != 2 {
		t.Fatalf("finding workload should be appended with next refresh order: %+v", workloads)
	}

	duplicate := awsSecretKeyRotationWorkloads(secret, AWSSecretPermissionEquivalenceFinding{WorkloadID: "lambda:payments"})
	if len(duplicate) != 1 {
		t.Fatalf("duplicate finding workload should not be added twice: %+v", duplicate)
	}
}

func TestGetAWSSecretKeyRotationPlansFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 15, 0, 0, time.UTC)
	svc, ws := newSecretKeyRotationService(t, "project-secret-key-rotation-states", now)

	denied, err := svc.GetAWSSecretKeyRotationPlans(defaultScopeContext(), ws, "project-secret-key-rotation-states", AWSSecretKeyRotationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Plans) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must be explicit and suppress plans: %+v", denied)
	}

	empty, err := svc.GetAWSSecretKeyRotationPlans(defaultScopeContext(), ws, "project-secret-key-rotation-states", AWSSecretKeyRotationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Summary.TotalPlans != 0 || empty.Status == "blocked" {
		t.Fatalf("empty fixture should produce no non-blocked plans: %+v", empty)
	}

	if _, err := svc.GetAWSSecretKeyRotationPlans(defaultScopeContext(), ws, "project-secret-key-rotation-states", AWSSecretKeyRotationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSSecretKeyRotation(t *testing.T) {
	now := time.Date(2026, 6, 24, 15, 20, 0, 0, time.UTC)
	svc, _ := newSecretKeyRotationService(t, "project-secret-key-rotation-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-secret-key-rotation-route/aws/secret-key-rotation?connector_id=aws-prod&fixture_state=success&rotation_type=provider_key", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Plans AWSSecretKeyRotationResult `json:"plans"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Plans.CurrentIssueRef != "#1533" || body.Plans.AppliedFilters["rotation_type"] != "provider-key" {
		t.Fatalf("unexpected route payload: %+v", body.Plans)
	}
}
