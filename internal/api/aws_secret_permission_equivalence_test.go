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
	if finding, ok := awsSecretPermissionFindingFromKMSGrant(key, secret, allow, deny, now); ok {
		t.Fatalf("expected explicit deny on kms:Decrypt to suppress capability-only KMS finding, got %+v", finding)
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
