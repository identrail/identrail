package aws

import (
	"sort"
	"strings"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

// Credential reference providers. Provider detection is metadata/name-pattern
// only — the mapper never reads a secret value, only the reference that points
// at one.
const (
	credentialProviderOpenAI         = "openai"
	credentialProviderAnthropic      = "anthropic"
	credentialProviderBedrock        = "bedrock"
	credentialProviderGitHub         = "github"
	credentialProviderSlack          = "slack"
	credentialProviderDatabase       = "database"
	credentialProviderWebhook        = "webhook"
	credentialProviderSecretsManager = "aws_secrets_manager"
	credentialProviderSSM            = "aws_ssm"
	credentialProviderGeneric        = "generic"
)

// Credential reference kinds describe how the workload sources the credential.
const (
	credentialKindSecretsManager       = "secrets_manager"
	credentialKindSSMParameter         = "ssm_parameter"
	credentialKindRepositoryCredential = "repository_credentials"
	credentialKindEnvironment          = "environment_variable"
)

// Credential sensitivity buckets group providers by the kind of secret behind
// the reference so operators can prioritize.
const (
	credentialSensitivityAIProviderKey    = "ai_provider_api_key"
	credentialSensitivitySourceControl    = "source_control_token"
	credentialSensitivityMessagingToken   = "messaging_token"
	credentialSensitivityDatabaseCred     = "database_credential"
	credentialSensitivityWebhookURL       = "webhook_url"
	credentialSensitivityAWSManagedSecret = "aws_managed_secret"
	credentialSensitivityGenericSecret    = "generic_secret"
)

// CredentialReference is one graph-ready credential or secret reference emitted
// by an AWS workload. It is metadata-only: Reference and ReferenceName carry
// names, ARNs, and source markers, never secret values.
type CredentialReference struct {
	AccountID     string `json:"account_id,omitempty"`
	Region        string `json:"region,omitempty"`
	WorkloadID    string `json:"workload_id,omitempty"`
	WorkloadType  string `json:"workload_type,omitempty"`
	WorkloadName  string `json:"workload_name,omitempty"`
	ResourceID    string `json:"resource_id,omitempty"`
	ResourceType  string `json:"resource_type,omitempty"`
	SourceService string `json:"source_service,omitempty"`

	Reference          string  `json:"reference"`
	ReferenceName      string  `json:"reference_name,omitempty"`
	ReferenceKind      string  `json:"reference_kind"`
	Provider           string  `json:"provider"`
	ProviderConfidence float64 `json:"provider_confidence"`
	Sensitivity        string  `json:"sensitivity"`

	Resolved     bool   `json:"resolved"`
	Unresolved   bool   `json:"unresolved"`
	TargetNodeID string `json:"target_node_id,omitempty"`

	Source      string  `json:"source"`
	EvidenceRef string  `json:"evidence_ref"`
	Confidence  float64 `json:"confidence"`
}

// credentialReferenceNodePrefix namespaces synthesized graph nodes for
// provider-key references that do not resolve to a collected AWS secret or
// parameter (for example an inline `OPENAI_API_KEY` environment variable).
const credentialReferenceNodePrefix = "aws:resource:credential-reference:"

// MapBundleCredentialReferences walks every normalized AWS workload resource,
// extracts its credential/secret references, classifies the provider, kind,
// and sensitivity of each, and resolves it against the collected Secrets
// Manager and SSM Parameter Store nodes. It returns the deduplicated reference
// records plus the identity→reference graph edges (workload → resolved secret
// node, or workload → synthesized credential-reference node when the provider
// key is unresolved). It is a pure function of the bundle and performs no AWS
// calls and no value reads.
func MapBundleCredentialReferences(bundle providers.NormalizedBundle) ([]CredentialReference, []domain.Relationship) {
	secretIndex := secretsManagerResourceIndex(bundle.Resources)
	parameterIndex := ssmParameterResourceIndex(bundle.Resources)

	references := []CredentialReference{}
	relationships := []domain.Relationship{}
	seenRef := map[string]struct{}{}
	seenEdge := map[string]struct{}{}

	for _, resource := range bundle.Resources {
		candidates := credentialCandidateRefs(resource)
		if len(candidates) == 0 {
			continue
		}
		sourceService := credentialSourceService(resource.Type)
		fromNodeID := credentialWorkloadNodeID(resource)
		workloadName := strings.TrimSpace(resource.Name)
		for _, raw := range candidates {
			if isAgentCoreCredentialProviderReference(raw) {
				continue
			}
			ref := classifyCredentialReference(raw, resource, sourceService, secretIndex, parameterIndex)
			if ref.Reference == "" {
				continue
			}
			ref.WorkloadID = fromNodeID
			ref.WorkloadName = workloadName
			ref.AccountID = strings.TrimSpace(resource.AccountID)
			ref.Region = strings.TrimSpace(resource.Region)
			ref.ResourceID = resource.ID
			ref.ResourceType = string(resource.Type)

			refKey := strings.Join([]string{fromNodeID, ref.Reference}, "|")
			if _, exists := seenRef[refKey]; !exists {
				seenRef[refKey] = struct{}{}
				references = append(references, ref)
			}

			targetNode := ref.TargetNodeID
			if targetNode == "" {
				continue
			}
			edgeKey := strings.Join([]string{fromNodeID, targetNode}, "|")
			if _, exists := seenEdge[edgeKey]; exists {
				continue
			}
			seenEdge[edgeKey] = struct{}{}
			relationships = append(relationships, domain.Relationship{
				ID:          relationshipID(domain.RelationshipUsesSecret, fromNodeID, targetNode),
				Type:        domain.RelationshipUsesSecret,
				FromNodeID:  fromNodeID,
				ToNodeID:    targetNode,
				EvidenceRef: ref.Reference,
			})
		}
	}
	for _, agent := range bundle.Agents {
		candidates := parseStringList(agent.Metadata["credential_reference_refs"])
		if len(candidates) == 0 {
			continue
		}
		resource := domain.Resource{
			ID:        agent.ID,
			Provider:  domain.ProviderAWS,
			Type:      domain.ResourceTypeCredentialReference,
			Name:      agent.Name,
			AccountID: stringMetadata(agent.Metadata, "account_id"),
			Region:    stringMetadata(agent.Metadata, "region"),
			Metadata: map[string]any{
				"secret_refs": candidates,
			},
		}
		sourceService := firstNonEmptyAWSValue(stringMetadata(agent.Metadata, "source"), "ai_agent")
		fromNodeID := credentialWorkloadNodeID(resource)
		workloadName := strings.TrimSpace(resource.Name)
		for _, raw := range credentialCandidateRefs(resource) {
			if isAgentCoreCredentialProviderReference(raw) {
				continue
			}
			ref := classifyCredentialReference(raw, resource, sourceService, secretIndex, parameterIndex)
			if ref.Reference == "" {
				continue
			}
			ref.WorkloadID = fromNodeID
			ref.WorkloadName = workloadName
			ref.AccountID = strings.TrimSpace(resource.AccountID)
			ref.Region = strings.TrimSpace(resource.Region)
			ref.ResourceID = agent.ID
			ref.ResourceType = string(agent.Type)
			// classifyCredentialReference defaults WorkloadType to the synthesized
			// credential-reference resource type; override it with the agent's own
			// type so custom-agent attribution and workload_type filters are correct.
			ref.WorkloadType = string(agent.Type)

			refKey := strings.Join([]string{fromNodeID, ref.Reference}, "|")
			if _, exists := seenRef[refKey]; !exists {
				seenRef[refKey] = struct{}{}
				references = append(references, ref)
			}

			targetNode := ref.TargetNodeID
			if targetNode == "" {
				continue
			}
			edgeKey := strings.Join([]string{fromNodeID, targetNode}, "|")
			if _, exists := seenEdge[edgeKey]; exists {
				continue
			}
			seenEdge[edgeKey] = struct{}{}
			relationships = append(relationships, domain.Relationship{
				ID:          relationshipID(domain.RelationshipUsesSecret, fromNodeID, targetNode),
				Type:        domain.RelationshipUsesSecret,
				FromNodeID:  fromNodeID,
				ToNodeID:    targetNode,
				EvidenceRef: ref.Reference,
			})
		}
	}

	sort.SliceStable(references, func(i, j int) bool {
		if references[i].WorkloadID == references[j].WorkloadID {
			return references[i].Reference < references[j].Reference
		}
		return references[i].WorkloadID < references[j].WorkloadID
	})
	sort.SliceStable(relationships, func(i, j int) bool {
		return relationships[i].ID < relationships[j].ID
	})
	return references, relationships
}

// credentialReferenceNodes returns the synthesized credential-reference
// resource nodes for unresolved provider-key references, so the graph carries
// a node for every emitted edge. Resolved references already point at a real
// Secrets Manager or SSM node and are skipped.
func credentialReferenceNodes(references []CredentialReference) []domain.Resource {
	seen := map[string]struct{}{}
	nodes := []domain.Resource{}
	for _, ref := range references {
		if ref.Resolved || ref.TargetNodeID == "" || !strings.HasPrefix(ref.TargetNodeID, credentialReferenceNodePrefix) {
			continue
		}
		if _, exists := seen[ref.TargetNodeID]; exists {
			continue
		}
		seen[ref.TargetNodeID] = struct{}{}
		nodes = append(nodes, domain.Resource{
			ID:        ref.TargetNodeID,
			Provider:  domain.ProviderAWS,
			Type:      domain.ResourceTypeCredentialReference,
			Name:      firstNonEmptyAWSValue(ref.ReferenceName, ref.Reference),
			Region:    ref.Region,
			AccountID: ref.AccountID,
			Metadata: map[string]any{
				"provider":       ref.Provider,
				"sensitivity":    ref.Sensitivity,
				"reference_kind": ref.ReferenceKind,
				"unresolved":     true,
			},
		})
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes
}

// appendCredentialReferenceNodes adds synthesized credential-reference resource
// nodes for unresolved external provider keys so the graph carries a node for
// every credential-reference edge the relationship builder will emit. It is a
// normalizer post-pass: node creation lives in the normalizer, edge creation in
// the relationship builder, matching the rest of the AWS pipeline.
func appendCredentialReferenceNodes(bundle *providers.NormalizedBundle, resourceSeen map[string]struct{}) {
	if bundle == nil {
		return
	}
	references, _ := MapBundleCredentialReferences(*bundle)
	for _, node := range credentialReferenceNodes(references) {
		if _, exists := resourceSeen[node.ID]; exists {
			continue
		}
		resourceSeen[node.ID] = struct{}{}
		bundle.Resources = append(bundle.Resources, node)
	}
}

// credentialSourceService maps a workload resource type to the AWS service that
// owns the credential reference. Any workload that carries credential metadata
// is mapped; unknown types fall back to the leading segment of the type name so
// new workload collectors are picked up without changing this mapper.
func credentialSourceService(resourceType domain.ResourceType) string {
	switch resourceType {
	case domain.ResourceTypeECSService, domain.ResourceTypeECSTask:
		return "ecs"
	case domain.ResourceTypeLambdaFunction:
		return "lambda"
	case domain.ResourceTypeCodeBuildProject:
		return "codebuild"
	case domain.ResourceTypeStepFunctions:
		return "stepfunctions"
	case domain.ResourceTypeEC2Instance, domain.ResourceTypeEC2InstanceProfile:
		return "ec2"
	}
	typeName := string(resourceType)
	if idx := strings.Index(typeName, "_"); idx > 0 {
		return typeName[:idx]
	}
	if typeName == "" {
		return "aws"
	}
	return typeName
}

// credentialCandidateRefs returns every raw reference string worth classifying
// for one resource: explicit secret/source references plus the subset of
// environment variable names whose name pattern indicates a provider key or
// credential. Plain environment keys that are not credential-suggestive are
// ignored to avoid noise.
//
// An environment key that is already the left-hand side of a `secret_refs`
// entry (for example a CodeBuild `DATABASE_PASSWORD` sourced from Parameter
// Store appears in both lists) is skipped, so a secret-store-backed variable
// is not also reported as a phantom inline credential.
func credentialCandidateRefs(resource domain.Resource) []string {
	refs := parseStringList(resource.Metadata["secret_refs"])
	out := append([]string(nil), refs...)
	sourced := map[string]struct{}{}
	for _, ref := range refs {
		if name, _ := splitCredentialReference(strings.TrimSpace(ref)); name != "" {
			sourced[strings.ToLower(name)] = struct{}{}
		}
	}
	for _, key := range parseStringList(resource.Metadata["environment_keys"]) {
		if !credentialSuggestiveName(key) {
			continue
		}
		if _, exists := sourced[strings.ToLower(strings.TrimSpace(key))]; exists {
			continue
		}
		out = append(out, key)
	}
	return out
}

func stringMetadata(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	if value, ok := metadata[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

// classifyCredentialReference parses one raw reference into a classified
// CredentialReference, resolving it against the collected secret/parameter
// indexes. The raw form may be `NAME=SOURCE` (ECS/CodeBuild), a bare ARN, a
// `PARAMETER_STORE:`/`SECRETS_MANAGER:` source, or a bare environment key.
func classifyCredentialReference(raw string, resource domain.Resource, sourceService string, secretIndex, parameterIndex map[string]string) CredentialReference {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return CredentialReference{}
	}
	name, source := splitCredentialReference(trimmed)

	ref := CredentialReference{
		WorkloadType:  string(resource.Type),
		SourceService: sourceService,
		Reference:     trimmed,
		ReferenceName: name,
		Source:        sourceService + "_workload_reference",
		EvidenceRef:   trimmed,
	}
	ref.ReferenceKind = classifyCredentialReferenceKind(name, source)

	// Resolve against collected AWS secret/parameter nodes only when the workload
	// supplies an explicit source marker. Bare environment variable keys can be
	// identical to collected names; resolving them here would create false
	// confidence edges.
	resolveTarget := strings.TrimSpace(source)
	if resolveTarget != "" {
		if secretID := matchSecretsManagerReference(resolveTarget, secretIndex); secretID != "" {
			ref.Resolved = true
			ref.ReferenceKind = credentialKindSecretsManager
			ref.TargetNodeID = secretID
		} else if parameterID := matchSSMParameterReference(resolveTarget, parameterIndex); parameterID != "" {
			ref.Resolved = true
			ref.ReferenceKind = credentialKindSSMParameter
			ref.TargetNodeID = parameterID
		}
	}
	// Bare env keys must stay explicit as unresolved references.
	if !ref.Resolved && resolveTarget == "" {
		ref.ReferenceKind = credentialKindEnvironment
	}

	provider, sensitivity, confidence := classifyCredentialProvider(name, source, ref.ReferenceKind)
	ref.Provider = provider
	ref.Sensitivity = sensitivity
	ref.ProviderConfidence = confidence
	ref.Confidence = credentialReferenceConfidence(ref)

	if !ref.Resolved {
		ref.Unresolved = true
		// Synthesize a stable node only for recognized provider-key references
		// so the graph gains a node for the emitted edge. AWS-native kinds that
		// simply were not collected stay edge-less to avoid dangling nodes.
		if credentialProviderIsExternal(provider) {
			ref.TargetNodeID = credentialReferenceNodeID(credentialWorkloadNodeID(resource), provider, name, source)
		}
	}
	return ref
}

func isAgentCoreCredentialProviderReference(raw string) bool {
	name, source := splitCredentialReference(strings.TrimSpace(raw))
	if strings.TrimSpace(name) != "" {
		return false
	}
	probe := strings.ToLower(strings.TrimSpace(source))
	if !strings.Contains(probe, "bedrock-agentcore") {
		return false
	}
	return strings.Contains(probe, ":oauth/") ||
		strings.Contains(probe, "/oauth/") ||
		strings.Contains(probe, ":api-key/") ||
		strings.Contains(probe, "/api-key/") ||
		strings.Contains(probe, ":apikey/") ||
		strings.Contains(probe, "/apikey/") ||
		strings.Contains(probe, ":api_key/") ||
		strings.Contains(probe, "/api_key/")
}

// splitCredentialReference separates a `NAME=SOURCE` reference into its env-var
// name and source marker. References without `=` are treated as a bare source
// (ARN / parameter ref) with no separate name.
func splitCredentialReference(ref string) (name string, source string) {
	if idx := strings.Index(ref, "="); idx > 0 {
		return strings.TrimSpace(ref[:idx]), strings.TrimSpace(ref[idx+1:])
	}
	// A bare environment key (no source) is its own name.
	if !strings.Contains(ref, ":") && !strings.Contains(ref, "/") {
		return ref, ""
	}
	return "", ref
}

// classifyCredentialReferenceKind determines how the workload sources the
// credential from the env-var name and source marker.
func classifyCredentialReferenceKind(name, source string) string {
	probe := strings.ToLower(source)
	switch {
	case strings.Contains(probe, ":secretsmanager:") || strings.HasPrefix(probe, "secrets_manager:"):
		return credentialKindSecretsManager
	case strings.Contains(probe, ":ssm:") || strings.Contains(probe, ":parameter/") || strings.HasPrefix(probe, "parameter_store:"):
		return credentialKindSSMParameter
	case strings.EqualFold(strings.TrimSpace(name), "repository_credentials"):
		return credentialKindRepositoryCredential
	case source == "":
		return credentialKindEnvironment
	default:
		return credentialKindEnvironment
	}
}

// classifyCredentialProvider detects the credential provider by name pattern
// across both the env-var name and the source marker (which may embed a secret
// or parameter name such as `secret:openai/api-key`). Returns the provider, its
// sensitivity bucket, and a detection confidence.
func classifyCredentialProvider(name, source, referenceKind string) (provider string, sensitivity string, confidence float64) {
	probe := strings.ToLower(name + " " + source)
	switch {
	case containsAnyToken(probe, "openai", "open_ai", "gpt_"):
		return credentialProviderOpenAI, credentialSensitivityAIProviderKey, 0.9
	case containsAnyToken(probe, "anthropic", "claude"):
		return credentialProviderAnthropic, credentialSensitivityAIProviderKey, 0.9
	case containsAnyToken(probe, "bedrock"):
		return credentialProviderBedrock, credentialSensitivityAIProviderKey, 0.85
	case containsAnyToken(probe, "github", "gh_token", "gh_pat", "ghp_"):
		return credentialProviderGitHub, credentialSensitivitySourceControl, 0.88
	case containsAnyToken(probe, "slack", "xoxb", "xoxp"):
		return credentialProviderSlack, credentialSensitivityMessagingToken, 0.85
	case credentialLooksLikeDatabase(probe):
		return credentialProviderDatabase, credentialSensitivityDatabaseCred, 0.8
	case containsAnyToken(probe, "webhook", "hook_url", "_hook"):
		return credentialProviderWebhook, credentialSensitivityWebhookURL, 0.8
	}
	switch referenceKind {
	case credentialKindSecretsManager:
		return credentialProviderSecretsManager, credentialSensitivityAWSManagedSecret, 0.7
	case credentialKindSSMParameter:
		return credentialProviderSSM, credentialSensitivityAWSManagedSecret, 0.7
	default:
		return credentialProviderGeneric, credentialSensitivityGenericSecret, 0.6
	}
}

func credentialLooksLikeDatabase(probe string) bool {
	return containsAnyToken(probe,
		"database_url", "database_password", "db_password", "db_user", "db_host",
		"postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongo_uri",
		"redis_url", "rds", "_dsn", "connection_string", "conn_string")
}

// credentialSuggestiveName reports whether a bare environment variable name is
// credential-bearing enough to map as a reference on its own. This filters the
// long tail of non-secret environment keys.
func credentialSuggestiveName(name string) bool {
	probe := strings.ToLower(strings.TrimSpace(name))
	if probe == "" {
		return false
	}
	return containsAnyToken(probe,
		"secret", "token", "api_key", "apikey", "password", "passwd",
		"credential", "private_key", "access_key", "client_secret",
		"openai", "anthropic", "claude", "bedrock", "github", "slack",
		"webhook", "database_url", "db_password", "connection_string")
}

// credentialProviderIsExternal reports whether the provider is a non-AWS
// external service. Only external provider keys synthesize credential-reference
// graph nodes when unresolved.
func credentialProviderIsExternal(provider string) bool {
	switch provider {
	case credentialProviderOpenAI, credentialProviderAnthropic, credentialProviderBedrock,
		credentialProviderGitHub, credentialProviderSlack, credentialProviderDatabase,
		credentialProviderWebhook:
		return true
	default:
		return false
	}
}

// credentialReferenceConfidence scores the overall record confidence from
// resolution status and provider-detection confidence.
func credentialReferenceConfidence(ref CredentialReference) float64 {
	switch {
	case ref.Resolved:
		// A resolved AWS node is strong evidence regardless of provider guess.
		if ref.ProviderConfidence > 0.9 {
			return 0.95
		}
		return 0.9
	case ref.Provider == credentialProviderGeneric:
		return 0.6
	default:
		return ref.ProviderConfidence
	}
}

// credentialWorkloadNodeID resolves the workload graph node a reference is
// anchored to: the workload's source entity, falling back to the resource ID.
func credentialWorkloadNodeID(resource domain.Resource) string {
	if id := strings.TrimSpace(resource.SourceEntityID); id != "" {
		return id
	}
	return strings.TrimSpace(resource.ID)
}

// credentialReferenceNodeID builds the synthesized node ID for an unresolved
// external provider key. It is scoped per workload: an unresolved reference is
// not evidence that two workloads share one credential, so distinct workloads
// (and accounts/regions, which the workload ID already encodes) get distinct
// nodes rather than collapsing onto a shared, mislabeled node.
func credentialReferenceNodeID(workloadID, provider, name, source string) string {
	return credentialReferenceNodePrefix + strings.Join(normalizeStringList([]string{
		strings.ToLower(strings.TrimSpace(workloadID)),
		provider,
		strings.ToLower(strings.TrimSpace(name)),
		strings.ToLower(strings.TrimSpace(source)),
	}), "|")
}

func containsAnyToken(haystack string, tokens ...string) bool {
	for _, token := range tokens {
		if token != "" && strings.Contains(haystack, token) {
			return true
		}
	}
	return false
}
