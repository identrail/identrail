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

func newSecretPermissionEquivalenceService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSSecretPermissionEquivalenceBuildsFindingContract(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 0, 0, 0, time.UTC)
	svc, ws := newSecretPermissionEquivalenceService(t, "project-secret-permission-equivalence", now)

	result, err := svc.GetAWSSecretPermissionEquivalence(defaultScopeContext(), ws, "project-secret-permission-equivalence", AWSSecretPermissionEquivalenceRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get secret permission equivalence: %v", err)
	}
	if result.CurrentIssueRef != "#1527" || result.Version != awsSecretPermissionEquivalenceVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Findings) == 0 || result.Summary.TotalFindings != len(result.Findings) {
		t.Fatalf("expected findings summary to match payload: %+v", result.Summary)
	}
	if result.Summary.ExternalProviderKeyCount == 0 || result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected provider-key findings and graph relationships: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if result.Summary.RemediationPreviewCount == 0 || len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected remediation previews, caveats, and coverage gaps: summary=%+v caveats=%v gaps=%v", result.Summary, result.Caveats, result.CoverageGaps)
	}
	if result.Summary.UnresolvedReferenceCount == 0 {
		t.Fatalf("expected unresolved references to be counted from structured finding state: %+v", result.Summary)
	}
	for i := 1; i < len(result.Findings); i++ {
		if result.Findings[i-1].Score < result.Findings[i].Score {
			t.Fatalf("findings are not ranked by descending score: %+v", result.Findings)
		}
	}
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsSecretPermissionEquivalenceVersion {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.EquivalenceType == "" || finding.Severity == "" || finding.Status == "" || finding.Rationale == "" {
			t.Fatalf("finding missing classification fields: %+v", finding)
		}
		if finding.Score <= 0 || finding.Confidence <= 0 || len(finding.EquivalentPermissions) == 0 {
			t.Fatalf("finding missing score/confidence/equivalent permissions: %+v", finding)
		}
		if finding.IdentityNodeID == "" || finding.SecretNodeID == "" || finding.SecretLabel == "" || len(finding.ImpactedPath) < 2 || len(finding.Evidence) == 0 {
			t.Fatalf("finding missing path/evidence fields: %+v", finding)
		}
		if finding.EvidenceBoundary != "metadata_only_no_secret_values_no_payloads" {
			t.Fatalf("finding crossed evidence boundary: %+v", finding)
		}
		if strings.Contains(strings.ToLower(finding.Rationale), "secret value") && !strings.Contains(strings.ToLower(finding.Rationale), "without reading") {
			t.Fatalf("rationale must not imply secret value collection: %s", finding.Rationale)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
	}
}

func TestGetAWSSecretPermissionEquivalenceFilters(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 5, 0, 0, time.UTC)
	svc, ws := newSecretPermissionEquivalenceService(t, "project-secret-permission-equivalence-filters", now)

	openAI, err := svc.GetAWSSecretPermissionEquivalence(defaultScopeContext(), ws, "project-secret-permission-equivalence-filters", AWSSecretPermissionEquivalenceRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Provider:     "openai",
	})
	if err != nil {
		t.Fatalf("provider filter: %v", err)
	}
	if len(openAI.Findings) == 0 {
		t.Fatalf("expected OpenAI provider-key equivalence findings")
	}
	for _, finding := range openAI.Findings {
		if finding.Provider != "openai" {
			t.Fatalf("provider filter leaked: %+v", finding)
		}
	}
	if openAI.AppliedFilters["provider"] != "openai" {
		t.Fatalf("expected normalized provider applied filter, got %+v", openAI.AppliedFilters)
	}

	agent, err := svc.GetAWSSecretPermissionEquivalence(defaultScopeContext(), ws, "project-secret-permission-equivalence-filters", AWSSecretPermissionEquivalenceRequest{
		ConnectorID:     "aws-prod",
		FixtureState:    "success",
		EquivalenceType: "agent_provider_key_equivalence",
		Identity:        "support-assistant",
	})
	if err != nil {
		t.Fatalf("agent equivalence filter: %v", err)
	}
	if len(agent.Findings) == 0 {
		t.Fatalf("expected agent provider-key findings")
	}
	for _, finding := range agent.Findings {
		if finding.EquivalenceType != "agent_provider_key_equivalence" {
			t.Fatalf("equivalence_type filter leaked: %+v", finding)
		}
		if !strings.Contains(strings.ToLower(finding.AgentName), "support-assistant") {
			t.Fatalf("identity filter leaked: %+v", finding)
		}
	}
}

func TestAWSSecretPermissionProviderFilterCanonicalizesAWSStoreAliases(t *testing.T) {
	findings := []AWSSecretPermissionEquivalenceFinding{
		{FindingID: "ssm", Provider: credentialProviderSSM},
		{FindingID: "secrets-manager", Provider: credentialProviderSecretsManager},
	}

	ssm, applied := filterAWSSecretPermissionEquivalenceFindings(findings, AWSSecretPermissionEquivalenceRequest{Provider: "ssm"})
	if len(ssm) != 1 || ssm[0].Provider != credentialProviderSSM {
		t.Fatalf("expected ssm alias to match canonical SSM provider, got findings=%+v applied=%+v", ssm, applied)
	}
	if applied["provider"] != "aws-ssm" {
		t.Fatalf("expected normalized SSM provider filter, got %+v", applied)
	}

	secretsManager, applied := filterAWSSecretPermissionEquivalenceFindings(findings, AWSSecretPermissionEquivalenceRequest{Provider: "secrets_manager"})
	if len(secretsManager) != 1 || secretsManager[0].Provider != credentialProviderSecretsManager {
		t.Fatalf("expected secrets_manager alias to match canonical Secrets Manager provider, got findings=%+v applied=%+v", secretsManager, applied)
	}
	if applied["provider"] != "aws-secrets-manager" {
		t.Fatalf("expected normalized Secrets Manager provider filter, got %+v", applied)
	}
}

func TestAWSSecretPermissionCanReadExcludesReplicationGrant(t *testing.T) {
	if awsSecretPermissionSecretGrantCanRead(AWSSecretsManagerIdentityGrant{Actions: []string{"secretsmanager:ReplicateSecretToRegions"}}) {
		t.Fatalf("replicate-only secret grants should not be treated as read access")
	}
}

func TestAWSSecretPermissionEquivalenceFiltersEvidenceAndSearch(t *testing.T) {
	findings := []AWSSecretPermissionEquivalenceFinding{
		{
			FindingID:             "runtime-backed",
			IdentityNodeID:        "arn:aws:iam::123456789012:role/runtime-reader",
			SecretNodeID:          "secret:runtime",
			SecretLabel:           "runtime-secret",
			Evidence:              []AWSSecretPermissionEquivalenceEvidence{{Source: "secrets_kms_runtime_access", Label: "Observed runtime access", EvidenceRef: "runtime://secret-access"}},
			EquivalentPermissions: []string{"secretsmanager:GetSecretValue"},
			ImpactedNodes:         []string{"arn:aws:iam::123456789012:role/runtime-reader"},
		},
		{
			FindingID:             "inventory-backed",
			IdentityNodeID:        "arn:aws:iam::123456789012:role/inventory-reader",
			SecretNodeID:          "secret:inventory",
			SecretLabel:           "inventory-secret",
			Evidence:              []AWSSecretPermissionEquivalenceEvidence{{Source: "secrets_manager_metadata", Label: "Secret metadata", EvidenceRef: "inventory://secret"}},
			EquivalentPermissions: []string{"secretsmanager:GetSecretValue"},
			ImpactedNodes:         []string{"arn:aws:iam::123456789012:role/inventory-reader"},
		},
		{
			FindingID:      "unavailable",
			IdentityNodeID: "arn:aws:iam::123456789012:role/no-evidence",
			SecretNodeID:   "secret:none",
			SecretLabel:    "no-evidence-secret",
		},
	}

	runtime, _ := filterAWSSecretPermissionEquivalenceFindings(findings, AWSSecretPermissionEquivalenceRequest{Evidence: "runtime-backed"})
	if len(runtime) != 1 || runtime[0].FindingID != "runtime-backed" {
		t.Fatalf("expected only runtime-backed finding, got %+v", runtime)
	}

	inventory, _ := filterAWSSecretPermissionEquivalenceFindings(findings, AWSSecretPermissionEquivalenceRequest{Evidence: "inventory-backed"})
	if len(inventory) != 1 || inventory[0].FindingID != "inventory-backed" {
		t.Fatalf("expected only inventory-backed finding, got %+v", inventory)
	}

	unavailable, _ := filterAWSSecretPermissionEquivalenceFindings(findings, AWSSecretPermissionEquivalenceRequest{Evidence: "unavailable"})
	if len(unavailable) != 1 || unavailable[0].FindingID != "unavailable" {
		t.Fatalf("expected only unavailable finding, got %+v", unavailable)
	}

	search, _ := filterAWSSecretPermissionEquivalenceFindings(findings, AWSSecretPermissionEquivalenceRequest{Search: "inventory-secret"})
	if len(search) != 1 || search[0].FindingID != "inventory-backed" {
		t.Fatalf("expected search to match the inventory secret label, got %+v", search)
	}
}

func TestAWSSecretPermissionKMSGrantRespectsCapabilityDeny(t *testing.T) {
	now := time.Date(2026, 6, 22, 8, 50, 0, 0, time.UTC)
	accountID := "123456789012"
	region := "us-east-1"
	roleARN := "arn:aws:iam::123456789012:role/source"
	keyARN := "arn:aws:kms:us-east-1:123456789012:key/99990000-1111-2222-3333-444455556666"
	key := AWSKMSDecryptReachabilityRecord{
		AccountID:   accountID,
		Region:      region,
		KeyARN:      keyARN,
		KeyID:       "restricted-key",
		FromNodeID:  "aws:resource:kms-key/" + keyARN,
		Confidence:  0.91,
		EvidenceRef: "evidence://kms/restricted-key",
		CollectedAt: now,
	}
	secret := AWSSecretsManagerMetadataRecord{
		AccountID:                       accountID,
		Region:                          region,
		SecretARN:                       "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api/key",
		SecretName:                      "prod/api/key",
		KMSKeyARN:                       keyARN,
		Sensitive:                       true,
		SensitivityClassification:       "aws_managed_secret",
		FromNodeID:                      "aws:resource:secrets-manager-secret/prod/api/key",
		EvidenceRef:                     "evidence://secret/prod-api-key",
		Confidence:                      0.9,
		CollectedAt:                     now,
		SensitivityClassificationSource: "fixture",
	}
	allow := AWSKMSIdentityGrant{
		PrincipalARN: roleARN,
		Effect:       "Allow",
		Capabilities: []string{"decrypt"},
	}
	deny := []AWSKMSIdentityGrant{{
		PrincipalARN: roleARN,
		Effect:       "Deny",
		Actions:      []string{"kms:Decrypt"},
	}}

	if _, ok := awsSecretPermissionFindingFromKMSGrant(key, secret, allow, nil, now); !ok {
		t.Fatalf("expected capability-only KMS decrypt allow to produce a finding without a deny")
	}
	if _, ok := awsSecretPermissionFindingFromKMSGrant(key, secret, AWSKMSIdentityGrant{
		PrincipalARN: roleARN,
		Effect:       "Allow",
		Actions:      []string{"kms:*"},
	}, nil, now); !ok {
		t.Fatalf("expected kms:* KMS grant to produce a decrypt-equivalence finding")
	}
	if finding, ok := awsSecretPermissionFindingFromKMSGrant(key, secret, AWSKMSIdentityGrant{
		PrincipalARN: roleARN,
		Effect:       "Allow",
		Capabilities: []string{"admin"},
	}, nil, now); ok {
		t.Fatalf("expected admin-only KMS capability to stay out of decrypt-equivalence findings, got %+v", finding)
	}
	if finding, ok := awsSecretPermissionFindingFromKMSGrant(key, secret, allow, deny, now); ok {
		t.Fatalf("expected explicit deny on kms:Decrypt to suppress capability-only KMS finding, got %+v", finding)
	}

	unrelatedDeny := []AWSKMSIdentityGrant{{
		PrincipalARN: roleARN,
		Effect:       "Deny",
		Actions:      []string{"kms:Encrypt"},
	}}
	if _, ok := awsSecretPermissionFindingFromKMSGrant(key, secret, AWSKMSIdentityGrant{
		PrincipalARN: roleARN,
		Effect:       "Allow",
		Actions:      []string{"kms:*"},
	}, unrelatedDeny, now); !ok {
		t.Fatalf("expected kms:* allow with an unrelated kms:Encrypt deny to still emit a decrypt-equivalence finding")
	}

	liveGrant := AWSKMSGrant{
		GranteePrincipal: roleARN,
		Operations:       []string{"Decrypt"},
	}
	if _, ok := awsSecretPermissionFindingFromKMSLiveGrant(key, secret, liveGrant, unrelatedDeny, now); !ok {
		t.Fatalf("expected live KMS decrypt grant to survive an unrelated kms:Encrypt deny")
	}
	if finding, ok := awsSecretPermissionFindingFromKMSLiveGrant(key, secret, liveGrant, deny, now); ok {
		t.Fatalf("expected explicit deny on kms:Decrypt to suppress the live KMS grant finding, got %+v", finding)
	}
}

func TestAWSSecretPermissionSecretGrantDeniedRequiresAllReadAPIs(t *testing.T) {
	allowAll := AWSSecretsManagerIdentityGrant{
		PrincipalARN: "arn:aws:iam::123456789012:role/reader",
		Effect:       "Allow",
		Actions:      []string{"secretsmanager:*"},
	}
	denyBatchOnly := []AWSSecretsManagerIdentityGrant{{
		PrincipalARN: "arn:aws:iam::123456789012:role/reader",
		Effect:       "Deny",
		Actions:      []string{"secretsmanager:BatchGetSecretValue"},
	}}
	if awsSecretPermissionSecretGrantDenied(allowAll, denyBatchOnly) {
		t.Fatalf("deny on BatchGetSecretValue alone must not suppress a secretsmanager:* allow that still grants GetSecretValue")
	}

	denyBothReads := append([]AWSSecretsManagerIdentityGrant{}, denyBatchOnly...)
	denyBothReads = append(denyBothReads, AWSSecretsManagerIdentityGrant{
		PrincipalARN: "arn:aws:iam::123456789012:role/reader",
		Effect:       "Deny",
		Actions:      []string{"secretsmanager:GetSecretValue"},
	})
	if !awsSecretPermissionSecretGrantDenied(allowAll, denyBothReads) {
		t.Fatalf("denying every concrete read API should suppress a wildcard secrets-manager allow")
	}

	denyWildcard := []AWSSecretsManagerIdentityGrant{{
		PrincipalARN: "arn:aws:iam::123456789012:role/reader",
		Effect:       "Deny",
		Actions:      []string{"secretsmanager:*"},
	}}
	if !awsSecretPermissionSecretGrantDenied(allowAll, denyWildcard) {
		t.Fatalf("wildcard deny should suppress a wildcard allow")
	}

	narrowAllow := AWSSecretsManagerIdentityGrant{
		PrincipalARN: "arn:aws:iam::123456789012:role/reader",
		Effect:       "Allow",
		Actions:      []string{"secretsmanager:GetSecretValue"},
	}
	if awsSecretPermissionSecretGrantDenied(narrowAllow, denyBatchOnly) {
		t.Fatalf("a deny on a different read API must not suppress a narrow GetSecretValue allow")
	}
	if !awsSecretPermissionSecretGrantDenied(narrowAllow, []AWSSecretsManagerIdentityGrant{{
		PrincipalARN: "arn:aws:iam::123456789012:role/reader",
		Effect:       "Deny",
		Actions:      []string{"secretsmanager:GetSecretValue"},
	}}) {
		t.Fatalf("a matching deny on GetSecretValue must suppress a narrow GetSecretValue allow")
	}
}

func TestAWSSecretPermissionProviderCanonicalizesAWSStoreAliases(t *testing.T) {
	cases := []struct {
		name           string
		provider       string
		wantProvider   string
		wantPermission string
	}{
		{name: "secrets manager compact alias", provider: "secretsmanager", wantProvider: credentialProviderSecretsManager, wantPermission: "secretsmanager:GetSecretValue"},
		{name: "secrets manager underscored alias", provider: "aws_secrets_manager", wantProvider: credentialProviderSecretsManager, wantPermission: "secretsmanager:GetSecretValue"},
		{name: "ssm alias", provider: "ssm", wantProvider: credentialProviderSSM, wantPermission: "ssm:GetParameter"},
		{name: "ssm parameter alias", provider: "ssm_parameter", wantProvider: credentialProviderSSM, wantPermission: "ssm:GetParameter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := awsSecretPermissionProvider(tc.provider, "", "", "generic_secret")
			if got != tc.wantProvider {
				t.Fatalf("expected canonical provider %q, got %q", tc.wantProvider, got)
			}
			if !awsStringSliceContains(awsSecretPermissionProviderPermissions(got), tc.wantPermission) {
				t.Fatalf("expected permissions for %q to include %q", got, tc.wantPermission)
			}
			if !awsSecretPermissionProviderIsPermissionBearing(got, "") {
				t.Fatalf("expected %q to remain permission-bearing", got)
			}
		})
	}
}

func TestGetAWSSecretPermissionEquivalenceFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 10, 0, 0, time.UTC)
	svc, ws := newSecretPermissionEquivalenceService(t, "project-secret-permission-equivalence-states", now)

	denied, err := svc.GetAWSSecretPermissionEquivalence(defaultScopeContext(), ws, "project-secret-permission-equivalence-states", AWSSecretPermissionEquivalenceRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Findings) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must be explicit and suppress deterministic findings: %+v", denied)
	}

	empty, err := svc.GetAWSSecretPermissionEquivalence(defaultScopeContext(), ws, "project-secret-permission-equivalence-states", AWSSecretPermissionEquivalenceRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Findings) != 0 || empty.Summary.TotalFindings != 0 || empty.Summary.FilteredFindings != 0 || len(empty.FailureReasons) == 0 {
		t.Fatalf("empty fixture should be explicit degraded no-evidence state: %+v", empty)
	}
}

func TestRouterAWSSecretPermissionEquivalence(t *testing.T) {
	now := time.Date(2026, 6, 21, 13, 15, 0, 0, time.UTC)
	svc, _ := newSecretPermissionEquivalenceService(t, "project-secret-permission-equivalence-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-secret-permission-equivalence-route/aws/secret-permission-equivalence?connector_id=aws-prod&fixture_state=success&provider=openai", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Findings AWSSecretPermissionEquivalenceResult `json:"findings"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Findings.CurrentIssueRef != "#1527" || body.Findings.AppliedFilters["provider"] != "openai" || len(body.Findings.Findings) == 0 {
		t.Fatalf("unexpected route payload: %+v", body.Findings)
	}
}
