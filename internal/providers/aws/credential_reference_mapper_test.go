package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

func workloadResource(id, name string, resType domain.ResourceType, secretRefs, envKeys []string) domain.Resource {
	return domain.Resource{
		ID:             id,
		Provider:       domain.ProviderAWS,
		Type:           resType,
		Name:           name,
		AccountID:      "123456789012",
		Region:         "us-east-1",
		SourceEntityID: id,
		Metadata: map[string]any{
			"secret_refs":      secretRefs,
			"environment_keys": envKeys,
		},
	}
}

// resourcesByType returns the bundle resources of one type, used by workload
// collector tests that assert on their own resource while tolerating the
// credential-reference nodes the normalizer now synthesizes.
func resourcesByType(resources []domain.Resource, resType domain.ResourceType) []domain.Resource {
	out := []domain.Resource{}
	for _, resource := range resources {
		if resource.Type == resType {
			out = append(out, resource)
		}
	}
	return out
}

func findCredentialReference(refs []CredentialReference, reference string) (CredentialReference, bool) {
	for _, ref := range refs {
		if ref.Reference == reference {
			return ref, true
		}
	}
	return CredentialReference{}, false
}

func TestMapBundleCredentialReferencesClassifiesProviders(t *testing.T) {
	bundle := providers.NormalizedBundle{
		Resources: []domain.Resource{
			workloadResource(
				"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
				"payments",
				domain.ResourceTypeECSService,
				[]string{
					"OPENAI_API_KEY=arn:aws:secretsmanager:us-east-1:123456789012:secret:openai/key-AbCdEf",
					"DATABASE_PASSWORD=PARAMETER_STORE:/payments/db/password",
				},
				[]string{"ANTHROPIC_API_KEY", "LOG_LEVEL"},
			),
			workloadResource(
				"arn:aws:codebuild:us-east-1:123456789012:project/release",
				"release",
				domain.ResourceTypeCodeBuildProject,
				[]string{
					"GITHUB_TOKEN=SECRETS_MANAGER:github/ci-token",
					"SLACK_WEBHOOK_URL=arn:aws:secretsmanager:us-east-1:123456789012:secret:slack/webhook-XyZ",
				},
				nil,
			),
		},
	}

	refs, _ := MapBundleCredentialReferences(bundle)

	cases := []struct {
		reference       string
		wantProvider    string
		wantSensitivity string
		wantKind        string
	}{
		{"OPENAI_API_KEY=arn:aws:secretsmanager:us-east-1:123456789012:secret:openai/key-AbCdEf", credentialProviderOpenAI, credentialSensitivityAIProviderKey, credentialKindSecretsManager},
		{"DATABASE_PASSWORD=PARAMETER_STORE:/payments/db/password", credentialProviderDatabase, credentialSensitivityDatabaseCred, credentialKindSSMParameter},
		{"ANTHROPIC_API_KEY", credentialProviderAnthropic, credentialSensitivityAIProviderKey, credentialKindEnvironment},
		{"GITHUB_TOKEN=SECRETS_MANAGER:github/ci-token", credentialProviderGitHub, credentialSensitivitySourceControl, credentialKindSecretsManager},
		{"SLACK_WEBHOOK_URL=arn:aws:secretsmanager:us-east-1:123456789012:secret:slack/webhook-XyZ", credentialProviderSlack, credentialSensitivityMessagingToken, credentialKindSecretsManager},
	}
	for _, tc := range cases {
		ref, ok := findCredentialReference(refs, tc.reference)
		if !ok {
			t.Fatalf("missing reference %q in %+v", tc.reference, refs)
		}
		if ref.Provider != tc.wantProvider {
			t.Fatalf("reference %q provider = %q, want %q", tc.reference, ref.Provider, tc.wantProvider)
		}
		if ref.Sensitivity != tc.wantSensitivity {
			t.Fatalf("reference %q sensitivity = %q, want %q", tc.reference, ref.Sensitivity, tc.wantSensitivity)
		}
		if ref.ReferenceKind != tc.wantKind {
			t.Fatalf("reference %q kind = %q, want %q", tc.reference, ref.ReferenceKind, tc.wantKind)
		}
	}

	if _, ok := findCredentialReference(refs, "LOG_LEVEL"); ok {
		t.Fatalf("non-credential environment key LOG_LEVEL should be ignored")
	}
}

func TestMapBundleCredentialReferencesResolvesAgainstCollectedSecrets(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:openai/key-AbCdEf"
	bundle := providers.NormalizedBundle{
		Resources: []domain.Resource{
			{
				ID:        secretsManagerSecretResourceID(secretARN),
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeSecretsManager,
				Name:      "openai/key",
				ARN:       secretARN,
				AccountID: "123456789012",
				Region:    "us-east-1",
			},
			workloadResource(
				"arn:aws:lambda:us-east-1:123456789012:function:summarizer",
				"summarizer",
				domain.ResourceTypeLambdaFunction,
				[]string{"OPENAI_API_KEY=" + secretARN},
				nil,
			),
		},
	}

	refs, relationships := MapBundleCredentialReferences(bundle)

	ref, ok := findCredentialReference(refs, "OPENAI_API_KEY="+secretARN)
	if !ok {
		t.Fatalf("missing resolved reference in %+v", refs)
	}
	if !ref.Resolved || ref.Unresolved {
		t.Fatalf("expected resolved reference, got %+v", ref)
	}
	if ref.TargetNodeID != secretsManagerSecretResourceID(secretARN) {
		t.Fatalf("resolved target = %q, want secret node", ref.TargetNodeID)
	}
	if ref.Provider != credentialProviderOpenAI {
		t.Fatalf("provider = %q, want openai", ref.Provider)
	}
	if ref.Confidence < 0.9 {
		t.Fatalf("resolved reference confidence = %v, want >= 0.9", ref.Confidence)
	}
	found := false
	for _, rel := range relationships {
		if rel.Type == domain.RelationshipUsesSecret && rel.FromNodeID == "arn:aws:lambda:us-east-1:123456789012:function:summarizer" && rel.ToNodeID == secretsManagerSecretResourceID(secretARN) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected uses_secret edge to resolved secret node, got %+v", relationships)
	}
}

func TestMapBundleCredentialReferencesSynthesizesUnresolvedProviderNodes(t *testing.T) {
	bundle := providers.NormalizedBundle{
		Resources: []domain.Resource{
			workloadResource(
				"arn:aws:lambda:us-east-1:123456789012:function:agent",
				"agent",
				domain.ResourceTypeLambdaFunction,
				nil,
				[]string{"OPENAI_API_KEY"},
			),
		},
	}

	refs, relationships := MapBundleCredentialReferences(bundle)
	ref, ok := findCredentialReference(refs, "OPENAI_API_KEY")
	if !ok {
		t.Fatalf("missing unresolved reference in %+v", refs)
	}
	if ref.Resolved || !ref.Unresolved {
		t.Fatalf("expected unresolved reference, got %+v", ref)
	}
	if !strings.HasPrefix(ref.TargetNodeID, credentialReferenceNodePrefix) {
		t.Fatalf("expected synthesized credential-reference node id, got %q", ref.TargetNodeID)
	}

	nodes := credentialReferenceNodes(refs)
	if len(nodes) != 1 || nodes[0].Type != domain.ResourceTypeCredentialReference {
		t.Fatalf("expected one credential-reference node, got %+v", nodes)
	}
	if nodes[0].Metadata["provider"] != credentialProviderOpenAI {
		t.Fatalf("node provider metadata = %v, want openai", nodes[0].Metadata["provider"])
	}

	found := false
	for _, rel := range relationships {
		if rel.ToNodeID == ref.TargetNodeID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected edge to synthesized node, got %+v", relationships)
	}
}

func TestMapBundleCredentialReferencesGenericAWSSecretStaysEdgeless(t *testing.T) {
	// A Secrets Manager reference with no provider hint that does not resolve to
	// a collected secret should be recorded but must not synthesize a node.
	bundle := providers.NormalizedBundle{
		Resources: []domain.Resource{
			workloadResource(
				"arn:aws:ecs:us-east-1:123456789012:service/prod/worker",
				"worker",
				domain.ResourceTypeECSService,
				[]string{"APP_SECRET=arn:aws:secretsmanager:us-east-1:123456789012:secret:app/config-ZzZ"},
				nil,
			),
		},
	}

	refs, relationships := MapBundleCredentialReferences(bundle)
	ref, ok := findCredentialReference(refs, "APP_SECRET=arn:aws:secretsmanager:us-east-1:123456789012:secret:app/config-ZzZ")
	if !ok {
		t.Fatalf("missing reference in %+v", refs)
	}
	if ref.Provider != credentialProviderSecretsManager {
		t.Fatalf("provider = %q, want aws_secrets_manager", ref.Provider)
	}
	if ref.TargetNodeID != "" {
		t.Fatalf("unresolved generic AWS secret should not synthesize a node, got %q", ref.TargetNodeID)
	}
	if len(relationships) != 0 {
		t.Fatalf("expected no edges for unresolved generic AWS secret, got %+v", relationships)
	}
	if len(credentialReferenceNodes(refs)) != 0 {
		t.Fatalf("expected no synthesized nodes for generic AWS secret")
	}
}

func TestNormalizerAndGraphEmitCredentialReferenceNodeAndEdge(t *testing.T) {
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindECSTaskRole,
		SourceID: "ecs-service",
		Payload: []byte(`{
			"account_id":"123456789012",
			"region":"us-east-1",
			"service":"ecs",
			"cluster_arn":"arn:aws:ecs:us-east-1:123456789012:cluster/prod",
			"service_arn":"arn:aws:ecs:us-east-1:123456789012:service/prod/agent",
			"workload_id":"arn:aws:ecs:us-east-1:123456789012:service/prod/agent",
			"workload_type":"ecs_service",
			"workload_name":"agent",
			"task_definition_arn":"arn:aws:ecs:us-east-1:123456789012:task-definition/agent:3",
			"role_arn":"arn:aws:iam::123456789012:role/agent-task",
			"environment_keys":["OPENAI_API_KEY","LOG_LEVEL"]
		}`),
	}})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("normalized bundle invalid: %v", err)
	}
	credentialNodes := resourcesByType(bundle.Resources, domain.ResourceTypeCredentialReference)
	if len(credentialNodes) != 1 || credentialNodes[0].Metadata["provider"] != credentialProviderOpenAI {
		t.Fatalf("expected one openai credential-reference node, got %+v", credentialNodes)
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("graph contract invalid: %v", err)
	}
	found := false
	for _, rel := range relationships {
		if rel.Type == domain.RelationshipUsesSecret && rel.ToNodeID == credentialNodes[0].ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected uses_secret edge to credential-reference node, got %+v", relationships)
	}
}

func TestMapBundleCredentialReferencesDeterministicAndDeduped(t *testing.T) {
	resource := workloadResource(
		"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
		"payments",
		domain.ResourceTypeECSService,
		[]string{"OPENAI_API_KEY=https://example.invalid/key", "OPENAI_API_KEY=https://example.invalid/key"},
		[]string{"GITHUB_TOKEN"},
	)
	bundle := providers.NormalizedBundle{Resources: []domain.Resource{resource}}

	firstRefs, firstRels := MapBundleCredentialReferences(bundle)
	secondRefs, secondRels := MapBundleCredentialReferences(bundle)

	if len(firstRefs) != len(secondRefs) || len(firstRels) != len(secondRels) {
		t.Fatalf("non-deterministic counts: refs %d/%d rels %d/%d", len(firstRefs), len(secondRefs), len(firstRels), len(secondRels))
	}
	for i := range firstRefs {
		if firstRefs[i].Reference != secondRefs[i].Reference {
			t.Fatalf("non-deterministic ordering at %d: %q vs %q", i, firstRefs[i].Reference, secondRefs[i].Reference)
		}
	}
	// The duplicated OPENAI ref must be deduped to a single record.
	count := 0
	for _, ref := range firstRefs {
		if ref.Reference == "OPENAI_API_KEY=https://example.invalid/key" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected deduped reference, got %d copies", count)
	}
}
