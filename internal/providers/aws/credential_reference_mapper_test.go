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

func TestMapBundleCredentialReferencesSkipsEnvKeysAlreadySourced(t *testing.T) {
	// CodeBuild lists a Parameter Store-backed DATABASE_PASSWORD in both
	// secret_refs (as NAME=source) and environment_keys (bare name). The bare
	// name must not produce a second, phantom inline credential; only the
	// sourced reference (here resolving to the collected parameter) survives.
	paramARN := "arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password"
	bundle := providers.NormalizedBundle{
		Resources: []domain.Resource{
			{
				ID:        ssmParameterResourceID(paramARN),
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeSSMParameter,
				Name:      "/payments/db/password",
				ARN:       paramARN,
				AccountID: "123456789012",
				Region:    "us-east-1",
			},
			workloadResource(
				"arn:aws:codebuild:us-east-1:123456789012:project/release",
				"release",
				domain.ResourceTypeCodeBuildProject,
				[]string{"DATABASE_PASSWORD=PARAMETER_STORE:/payments/db/password"},
				[]string{"DATABASE_PASSWORD", "LOG_LEVEL"},
			),
		},
	}

	refs, relationships := MapBundleCredentialReferences(bundle)

	databaseRefs := 0
	for _, ref := range refs {
		if ref.Provider == credentialProviderDatabase {
			databaseRefs++
		}
	}
	if databaseRefs != 1 {
		t.Fatalf("expected one database reference (the sourced one), got %d: %+v", databaseRefs, refs)
	}
	if _, ok := findCredentialReference(refs, "DATABASE_PASSWORD"); ok {
		t.Fatalf("bare DATABASE_PASSWORD env key must be suppressed when already sourced via secret_refs")
	}
	if len(credentialReferenceNodes(refs)) != 0 {
		t.Fatalf("a secret-store-backed variable must not synthesize a phantom inline node, got %+v", credentialReferenceNodes(refs))
	}
	if len(relationships) != 1 || relationships[0].ToNodeID != ssmParameterResourceID(paramARN) {
		t.Fatalf("expected one edge to the collected parameter node, got %+v", relationships)
	}
}

func TestMapBundleCredentialReferencesKeepsBareEnvKeysUnresolvedEvenWhenNameMatchesCollectedSecret(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:OPENAI_API_KEY"
	bundle := providers.NormalizedBundle{
		Resources: []domain.Resource{
			{
				ID:        secretsManagerSecretResourceID(secretARN),
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeSecretsManager,
				Name:      "OPENAI_API_KEY",
				ARN:       secretARN,
				AccountID: "123456789012",
				Region:    "us-east-1",
			},
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
		t.Fatalf("missing reference in %+v", refs)
	}
	if ref.Resolved {
		t.Fatalf("bare env key should not resolve from matching secret name: %+v", ref)
	}
	if !ref.Unresolved {
		t.Fatalf("expected unresolved bare env key, got %+v", ref)
	}
	if ref.ReferenceKind != credentialKindEnvironment {
		t.Fatalf("expected environment kind for bare env key, got %q", ref.ReferenceKind)
	}
	if ref.Provider != credentialProviderOpenAI {
		t.Fatalf("expected openai provider for bare OPENAI_API_KEY, got %q", ref.Provider)
	}
	for _, rel := range relationships {
		if rel.ToNodeID == secretsManagerSecretResourceID(secretARN) {
			t.Fatalf("unexpected relationship to collected secret for bare env key: %+v", rel)
		}
	}
}

func TestMapBundleCredentialReferencesReclassifiesNameOnlySecretRefs(t *testing.T) {
	paramARN := "arn:aws:ssm:us-east-1:123456789012:parameter/payments/config"
	bundle := providers.NormalizedBundle{
		Resources: []domain.Resource{
			{
				ID:        ssmParameterResourceID(paramARN),
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeSSMParameter,
				Name:      "/payments/config",
				ARN:       paramARN,
				AccountID: "123456789012",
				Region:    "us-east-1",
			},
			workloadResource(
				"arn:aws:ecs:us-east-1:123456789012:service/prod/worker",
				"worker",
				domain.ResourceTypeECSService,
				[]string{"APP_CONFIG=/payments/config"},
				nil,
			),
		},
	}

	refs, _ := MapBundleCredentialReferences(bundle)
	ref, ok := findCredentialReference(refs, "APP_CONFIG=/payments/config")
	if !ok {
		t.Fatalf("missing reference in %+v", refs)
	}
	if !ref.Resolved {
		t.Fatalf("expected resolved reference, got %+v", ref)
	}
	if ref.ReferenceKind != credentialKindSSMParameter {
		t.Fatalf("expected SSM parameter kind, got %q", ref.ReferenceKind)
	}
	if ref.Provider != credentialProviderSSM {
		t.Fatalf("expected aws_ssm provider, got %q", ref.Provider)
	}
	if ref.TargetNodeID != ssmParameterResourceID(paramARN) {
		t.Fatalf("expected target %q, got %q", ssmParameterResourceID(paramARN), ref.TargetNodeID)
	}
}

func TestMapBundleCredentialReferencesScopesSynthesizedNodesPerWorkload(t *testing.T) {
	// Two workloads in different accounts both expose an unresolved OPENAI_API_KEY.
	// An unresolved reference is not evidence they share one credential, so each
	// must get its own credential-reference node with its own account/region.
	bundle := providers.NormalizedBundle{
		Resources: []domain.Resource{
			func() domain.Resource {
				r := workloadResource("arn:aws:lambda:us-east-1:111111111111:function:a", "a", domain.ResourceTypeLambdaFunction, nil, []string{"OPENAI_API_KEY"})
				r.AccountID = "111111111111"
				return r
			}(),
			func() domain.Resource {
				r := workloadResource("arn:aws:lambda:us-west-2:222222222222:function:b", "b", domain.ResourceTypeLambdaFunction, nil, []string{"OPENAI_API_KEY"})
				r.AccountID = "222222222222"
				r.Region = "us-west-2"
				return r
			}(),
		},
	}

	refs, relationships := MapBundleCredentialReferences(bundle)
	nodes := credentialReferenceNodes(refs)
	if len(nodes) != 2 {
		t.Fatalf("expected one node per workload, got %+v", nodes)
	}
	if nodes[0].ID == nodes[1].ID {
		t.Fatalf("distinct workloads must not share a credential-reference node id: %q", nodes[0].ID)
	}
	accounts := map[string]struct{}{nodes[0].AccountID: {}, nodes[1].AccountID: {}}
	if _, ok := accounts["111111111111"]; !ok {
		t.Fatalf("expected per-workload account metadata, got %+v", nodes)
	}
	if _, ok := accounts["222222222222"]; !ok {
		t.Fatalf("expected per-workload account metadata, got %+v", nodes)
	}
	if len(relationships) != 2 {
		t.Fatalf("expected one edge per workload, got %+v", relationships)
	}
	if relationships[0].ToNodeID == relationships[1].ToNodeID {
		t.Fatalf("distinct workloads must not point at the same node: %+v", relationships)
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
			"service_arn":"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			"workload_id":"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			"workload_type":"ecs_service",
			"workload_name":"payments",
			"task_definition_arn":"arn:aws:ecs:us-east-1:123456789012:task-definition/payments:3",
			"role_arn":"arn:aws:iam::123456789012:role/payments-task",
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
