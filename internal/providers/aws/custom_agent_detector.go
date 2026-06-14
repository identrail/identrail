package aws

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	customAgentDetectorVersion = "custom-agent-detector-v1"
	customAgentDetectorSource  = "custom_agent_detector"
)

type customAgentWorkloadEvidence struct {
	Kind            string
	AccountID       string
	Region          string
	Service         string
	WorkloadID      string
	WorkloadName    string
	WorkloadType    string
	WorkloadARN     string
	RuntimeRoleARN  string
	RuntimeRoleName string
	RoleKind        string
	Status          string
	Names           []string
	Images          []string
	EnvironmentKeys []string
	SecretRefs      []string
	ResourceRefs    []string
	Tags            map[string]string
	CollectedAt     time.Time
	RawSourceID     string
}

type customAgentDetection struct {
	Record  AIAgentIdentity
	Score   float64
	Signals []string
}

func deriveCustomAIAgentIdentityAssets(raw []providers.RawAsset) []providers.RawAsset {
	existing := map[string]struct{}{}
	for _, asset := range raw {
		if asset.Kind == rawKindAIAgentIdentity {
			existing[strings.TrimSpace(asset.SourceID)] = struct{}{}
		}
	}

	// chosen tracks the derived asset already emitted for a sourceID together with
	// the priority of the evidence that produced it. Multiple raw assets can map to
	// the same detected agent (an ECS service exposes both an execution-role and a
	// task-role asset, and the SDK adapter may visit the execution role first). A
	// higher-priority detection must be able to replace a lower-priority one so the
	// agent's runs_as edge points at the role the workload actually runs as rather
	// than at whichever asset happened to be visited first.
	type chosenDetection struct {
		index    int
		priority int
	}
	chosen := map[string]chosenDetection{}
	derived := []providers.RawAsset{}
	for _, asset := range raw {
		evidence, ok := customAgentEvidenceFromRawAsset(asset)
		if !ok {
			continue
		}
		if customAgentEvidenceIsControlPlaneExecutionRole(evidence) {
			continue
		}
		detection, ok := detectCustomAgentWorkload(evidence)
		if !ok {
			continue
		}
		sourceID := aiAgentIdentitySourceID(detection.Record)
		if strings.TrimSpace(sourceID) == "" {
			continue
		}
		if _, exists := existing[sourceID]; exists {
			continue
		}
		payload, err := json.Marshal(detection.Record)
		if err != nil {
			continue
		}
		collected := asset.Collected
		if strings.TrimSpace(collected) == "" && !evidence.CollectedAt.IsZero() {
			collected = evidence.CollectedAt.UTC().Format(time.RFC3339Nano)
		}
		newAsset := providers.RawAsset{
			Kind:      rawKindAIAgentIdentity,
			SourceID:  sourceID,
			Payload:   payload,
			Collected: collected,
		}
		priority := customAgentEvidencePriority(evidence)
		if prev, exists := chosen[sourceID]; exists {
			// Keep the higher-priority evidence; otherwise leave the earlier,
			// deterministic first-wins detection in place.
			if priority > prev.priority {
				derived[prev.index] = newAsset
				chosen[sourceID] = chosenDetection{index: prev.index, priority: priority}
			}
			continue
		}
		chosen[sourceID] = chosenDetection{index: len(derived), priority: priority}
		derived = append(derived, newAsset)
	}
	return derived
}

// customAgentEvidencePriority ranks competing workload evidence for the same
// detected agent so the role the workload actually runs as wins de-duplication.
// An ECS task role (the identity the container code assumes) outranks an ECS
// execution role, which is only used by the ECS agent to pull images and secrets.
func customAgentEvidencePriority(evidence customAgentWorkloadEvidence) int {
	if customAgentEvidenceIsControlPlaneExecutionRole(evidence) {
		return 0
	}
	return 1
}

func customAgentEvidenceIsControlPlaneExecutionRole(evidence customAgentWorkloadEvidence) bool {
	if evidence.Kind == rawKindECSTaskRole &&
		strings.EqualFold(strings.TrimSpace(evidence.RoleKind), ecsRoleKindExecution) {
		return true
	}
	return evidence.Kind == rawKindEKSWorkloadIdentity &&
		strings.EqualFold(strings.TrimSpace(evidence.RoleKind), eksRoleKindFargatePodExecution)
}

func customAgentEvidenceFromRawAsset(asset providers.RawAsset) (customAgentWorkloadEvidence, bool) {
	switch asset.Kind {
	case rawKindECSTaskRole, rawKindLambdaExecutionRole, rawKindCodeBuildServiceRole,
		rawKindEKSWorkloadIdentity, rawKindEC2InstanceProfile, rawKindSageMakerWorkloadRole,
		rawKindStepFunctionsStateMachineRole:
	default:
		return customAgentWorkloadEvidence{}, false
	}

	var payload map[string]any
	if err := json.Unmarshal(asset.Payload, &payload); err != nil {
		return customAgentWorkloadEvidence{}, false
	}
	evidence := customAgentWorkloadEvidence{
		Kind:         asset.Kind,
		AccountID:    mapString(payload, "account_id"),
		Region:       mapString(payload, "region"),
		Service:      firstNonEmptyAWSValue(mapString(payload, "service"), customAgentServiceFromKind(asset.Kind)),
		WorkloadID:   mapString(payload, "workload_id"),
		WorkloadName: mapString(payload, "workload_name"),
		WorkloadType: mapString(payload, "workload_type"),
		RuntimeRoleARN: firstNonEmptyAWSValue(
			mapString(payload, "role_arn"),
			mapString(payload, "task_role_arn"),
			mapString(payload, "target_role_arn"),
			mapString(payload, "node_role_arn"),
			mapString(payload, "pod_execution_role_arn"),
		),
		RuntimeRoleName: mapString(payload, "role_name"),
		RoleKind:        mapString(payload, "role_kind"),
		Status:          firstNonEmptyAWSValue(mapString(payload, "status"), mapString(payload, "resource_status"), mapString(payload, "function_state"), mapString(payload, "service_status"), mapString(payload, "state_machine_status"), mapString(payload, "instance_state")),
		EnvironmentKeys: mapStringList(payload, "environment_keys"),
		SecretRefs:      mapStringList(payload, "secret_refs"),
		Tags:            mapStringMap(payload, "tags"),
		RawSourceID:     strings.TrimSpace(asset.SourceID),
	}
	evidence.CollectedAt = mapTime(payload, "collected_at")
	if evidence.WorkloadID == "" {
		evidence.WorkloadID = firstNonEmptyAWSValue(
			mapString(payload, "service_arn"),
			mapString(payload, "function_arn"),
			mapString(payload, "project_arn"),
			mapString(payload, "association_arn"),
			mapString(payload, "kubernetes_subject"),
			mapString(payload, "instance_arn"),
			mapString(payload, "instance_id"),
			mapString(payload, "workload_arn"),
			mapString(payload, "state_machine_arn"),
			evidence.RawSourceID,
		)
	}
	evidence.WorkloadARN = firstNonEmptyAWSValue(
		mapString(payload, "workload_arn"),
		mapString(payload, "service_arn"),
		mapString(payload, "function_arn"),
		mapString(payload, "project_arn"),
		mapString(payload, "association_arn"),
		mapString(payload, "instance_arn"),
		mapString(payload, "resource_arn"),
		mapString(payload, "state_machine_arn"),
	)
	if evidence.WorkloadName == "" {
		evidence.WorkloadName = firstNonEmptyAWSValue(
			mapString(payload, "service_name"),
			mapString(payload, "function_name"),
			mapString(payload, "project_name"),
			mapString(payload, "service_account"),
			mapString(payload, "instance_name"),
			mapString(payload, "resource_type"),
			mapString(payload, "state_machine_name"),
			evidence.WorkloadID,
		)
	}
	if evidence.WorkloadType == "" {
		evidence.WorkloadType = customAgentWorkloadTypeFromKind(asset.Kind)
	}

	evidence.Images = append(evidence.Images, mapStringList(payload, "container_images")...)
	evidence.Images = append(evidence.Images, mapStringList(payload, "image_uris")...)
	if image := mapString(payload, "image"); image != "" {
		evidence.Images = append(evidence.Images, image)
	}
	evidence.ResourceRefs = append(evidence.ResourceRefs, mapStringList(payload, "task_resource_arns")...)
	evidence.ResourceRefs = append(evidence.ResourceRefs, mapStringList(payload, "service_integration_resources")...)
	evidence.ResourceRefs = append(evidence.ResourceRefs, mapStringList(payload, "s3_references")...)
	evidence.ResourceRefs = append(evidence.ResourceRefs, mapStringList(payload, "kms_key_arns")...)
	evidence.ResourceRefs = append(evidence.ResourceRefs, mapStringList(payload, "layer_arns")...)
	evidence.ResourceRefs = append(evidence.ResourceRefs, mapStringList(payload, "selector_labels")...)
	evidence.Names = append(evidence.Names,
		evidence.WorkloadID,
		evidence.WorkloadName,
		evidence.WorkloadType,
		evidence.RuntimeRoleName,
		mapString(payload, "cluster_name"),
		mapString(payload, "task_definition_family"),
		mapString(payload, "handler"),
		mapString(payload, "runtime"),
		mapString(payload, "project_description"),
		mapString(payload, "namespace"),
		mapString(payload, "service_account"),
		mapString(payload, "kubernetes_subject"),
		mapString(payload, "nodegroup_name"),
		mapString(payload, "fargate_profile_name"),
		mapString(payload, "launch_template_name"),
		mapString(payload, "resource_type"),
		mapString(payload, "description"),
	)
	for key, value := range evidence.Tags {
		evidence.Names = append(evidence.Names, key, value)
	}
	return evidence, evidence.WorkloadID != "" && evidence.RuntimeRoleARN != ""
}

func detectCustomAgentWorkload(evidence customAgentWorkloadEvidence) (customAgentDetection, bool) {
	credentialRefs, providers := customAgentProviderCredentialRefs(evidence)
	signals := []string{}
	capabilities := []string{customAgentDetectorVersion}
	score := 0.0

	agentProbe := strings.Join(append(append([]string{}, evidence.Names...), evidence.Images...), " ")
	agentProbe = strings.TrimSpace(agentProbe + " " + strings.Join(evidence.ResourceRefs, " "))
	if customAgentExplicitAgentSignal(agentProbe) {
		score += 0.45
		signals = append(signals, "agent_name_or_runtime_metadata")
		capabilities = appendUnique(capabilities, "custom_agent_metadata")
	} else if customAgentLooseAgentSignal(agentProbe) {
		score += 0.25
		signals = append(signals, "agent_keyword")
		capabilities = appendUnique(capabilities, "custom_agent_keyword")
	}
	if customAgentAISignal(agentProbe) {
		score += 0.25
		signals = append(signals, "ai_runtime_metadata")
		capabilities = appendUnique(capabilities, "ai_runtime_metadata")
	}
	if len(credentialRefs) > 0 {
		score += 0.30
		signals = append(signals, "external_provider_key_reference")
		capabilities = appendUnique(capabilities, "external_provider_key")
	}
	if len(evidence.Images) > 0 && customAgentAISignal(strings.Join(evidence.Images, " ")) {
		score += 0.10
		signals = append(signals, "container_image")
		capabilities = appendUnique(capabilities, "container_image_signal")
	}
	if evidence.RuntimeRoleARN != "" {
		score += 0.10
		signals = append(signals, "runtime_role_binding")
		capabilities = appendUnique(capabilities, "role_binding")
	}
	if customAgentToolSignal(agentProbe) {
		score += 0.05
		signals = append(signals, "tool_or_action_metadata")
		capabilities = appendUnique(capabilities, "tool_use")
	}
	if score > 0.95 {
		score = 0.95
	}
	if score < 0.55 {
		return customAgentDetection{}, false
	}

	status := "candidate"
	coverageStatus := "candidate"
	coverageReason := fmt.Sprintf("custom agent detector matched %s", strings.Join(dedupeStrings(signals), ", "))
	if score >= 0.75 {
		status = "ready"
		coverageStatus = "covered"
		coverageReason = ""
	}
	externalProvider := "custom"
	provider := "custom"
	if len(providers) > 0 {
		externalProvider = providers[0]
		provider = "external_provider"
	}

	record := AIAgentIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     evidence.AccountID,
			Region:        evidence.Region,
			Service:       evidence.Service,
			WorkloadID:    evidence.WorkloadID,
			WorkloadName:  evidence.WorkloadName,
			WorkloadType:  evidence.WorkloadType,
			RoleARN:       evidence.RuntimeRoleARN,
			Source:        customAgentDetectorSource,
			EvidenceRef:   firstNonEmptyAWSValue(evidence.WorkloadARN, evidence.WorkloadID, evidence.RawSourceID),
			Confidence:    score,
			CollectorName: aiAgentIdentityCollectorName,
			CollectedAt:   evidence.CollectedAt,
		},
		AgentID:                 evidence.WorkloadID,
		AgentARN:                evidence.WorkloadARN,
		AgentName:               evidence.WorkloadName,
		AgentType:               "custom_agent",
		Provider:                provider,
		RuntimeRoleARN:          evidence.RuntimeRoleARN,
		RuntimeRoleName:         firstNonEmptyAWSValue(evidence.RuntimeRoleName, roleNameFromARN(evidence.RuntimeRoleARN)),
		RuntimeRoleAccountID:    roleAccountIDFromARN(evidence.RuntimeRoleARN),
		ExternalProvider:        externalProvider,
		CapabilityNames:         dedupeStrings(capabilities),
		CredentialReferenceRefs: credentialRefs,
		ResourceReferenceRefs:   customAgentResourceRefs(evidence),
		SensitiveBoundary:       "metadata_only",
		CoverageStatus:          coverageStatus,
		CoverageReason:          coverageReason,
		Status:                  status,
		Tags:                    customAgentDetectorTags(evidence, score, signals),
	}
	return customAgentDetection{Record: record, Score: score, Signals: dedupeStrings(signals)}, true
}

func customAgentProviderCredentialRefs(evidence customAgentWorkloadEvidence) ([]string, []string) {
	// Collect the env-var names that are already backed by a sourced secret
	// reference (for example a CodeBuild `OPENAI_API_KEY=PARAMETER_STORE:...`).
	// CodeBuild records such variables in both SecretRefs and EnvironmentKeys, so
	// a bare `OPENAI_API_KEY` env entry must be suppressed here — otherwise the
	// downstream agent credential mapper (which sees this flattened list only as
	// `secret_refs`, bypassing credentialCandidateRefs' env-key suppression)
	// emits both a resolved secret reference and a spurious unresolved
	// provider-key node/edge for the same variable.
	sourcedNames := map[string]struct{}{}
	for _, ref := range evidence.SecretRefs {
		name, source := splitCredentialReference(strings.TrimSpace(ref))
		if strings.TrimSpace(source) != "" && strings.TrimSpace(name) != "" {
			sourcedNames[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
		}
	}

	refs := []string{}
	providers := []string{}
	for _, ref := range append(append([]string{}, evidence.SecretRefs...), evidence.EnvironmentKeys...) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		name, source := splitCredentialReference(ref)
		if source == "" && !credentialSuggestiveName(name) {
			continue
		}
		// Skip a bare env key whose value is already sourced from a secret store.
		if source == "" {
			if _, sourced := sourcedNames[strings.ToLower(strings.TrimSpace(name))]; sourced {
				continue
			}
		}
		kind := classifyCredentialReferenceKind(name, source)
		provider, sensitivity, _ := classifyCredentialProvider(name, source, kind)
		if sensitivity != credentialSensitivityAIProviderKey {
			continue
		}
		refs = append(refs, ref)
		providers = appendUnique(providers, provider)
	}
	return dedupeStrings(refs), dedupeStrings(providers)
}

func customAgentResourceRefs(evidence customAgentWorkloadEvidence) []string {
	refs := []string{evidence.WorkloadARN, evidence.WorkloadID}
	refs = append(refs, evidence.Images...)
	refs = append(refs, evidence.ResourceRefs...)
	return dedupeStrings(refs)
}

func customAgentDetectorTags(evidence customAgentWorkloadEvidence, score float64, signals []string) map[string]string {
	tags := copyTags(evidence.Tags)
	if tags == nil {
		tags = map[string]string{}
	}
	tags["detector"] = customAgentDetectorVersion
	tags["detector_score"] = fmt.Sprintf("%.2f", score)
	tags["detector_signals"] = strings.Join(dedupeStrings(signals), ",")
	tags["detector_source_kind"] = evidence.Kind
	return tags
}

func customAgentExplicitAgentSignal(value string) bool {
	probe := strings.ToLower(value)
	return containsAnyToken(probe,
		"ai-agent", "ai_agent", "agentic", "assistant", "copilot",
		"langchain", "llm-agent", "llm_agent", "crewai", "autogen",
		"semantic-kernel", "semantic_kernel", "bedrock-agent")
}

func customAgentLooseAgentSignal(value string) bool {
	probe := strings.ToLower(value)
	return containsAnyToken(probe, "agent", "planner", "orchestrator", "reasoner")
}

func customAgentAISignal(value string) bool {
	probe := strings.ToLower(value)
	// Distinctive multi-character vendor/technique tokens are safe as substrings.
	if containsAnyToken(probe,
		"openai", "anthropic", "claude", "bedrock",
		"agentcore", "vector", "embedding") {
		return true
	}
	// Short, ambiguous tokens (rag/llm/gpt) only match at word boundaries so they
	// do not fire on unrelated substrings such as "storage", "fragment",
	// "allment", or "encryption".
	return containsAnyWordToken(probe, "rag", "llm", "gpt")
}

// containsAnyWordToken reports whether any token appears in haystack delimited by
// non-alphanumeric boundaries (or string ends), avoiding substring false
// positives for short tokens.
func containsAnyWordToken(haystack string, tokens ...string) bool {
	isBoundary := func(r byte) bool {
		switch {
		case r >= 'a' && r <= 'z':
			return false
		case r >= 'A' && r <= 'Z':
			return false
		case r >= '0' && r <= '9':
			return false
		default:
			return true
		}
	}
	for _, token := range tokens {
		if token == "" {
			continue
		}
		for start := 0; ; {
			idx := strings.Index(haystack[start:], token)
			if idx < 0 {
				break
			}
			pos := start + idx
			before := pos == 0 || isBoundary(haystack[pos-1])
			end := pos + len(token)
			after := end == len(haystack) || isBoundary(haystack[end])
			if before && after {
				return true
			}
			start = pos + 1
		}
	}
	return false
}

func customAgentToolSignal(value string) bool {
	probe := strings.ToLower(value)
	return containsAnyToken(probe, "tool", "mcp", "action", "function_call", "function-call")
}

func customAgentServiceFromKind(kind string) string {
	switch kind {
	case rawKindECSTaskRole:
		return ecsServiceName
	case rawKindLambdaExecutionRole:
		return lambdaServiceName
	case rawKindCodeBuildServiceRole:
		return codeBuildServiceName
	case rawKindEKSWorkloadIdentity:
		return eksServiceName
	case rawKindEC2InstanceProfile:
		return ec2ServiceName
	case rawKindSageMakerWorkloadRole:
		return sageMakerServiceName
	case rawKindStepFunctionsStateMachineRole:
		return stepFunctionsServiceName
	default:
		return "aws"
	}
}

func customAgentWorkloadTypeFromKind(kind string) string {
	switch kind {
	case rawKindECSTaskRole:
		return "ecs_service"
	case rawKindLambdaExecutionRole:
		return "lambda_function"
	case rawKindCodeBuildServiceRole:
		return "codebuild_project"
	case rawKindEKSWorkloadIdentity:
		return "eks_workload"
	case rawKindEC2InstanceProfile:
		return "ec2_instance"
	case rawKindSageMakerWorkloadRole:
		return "sagemaker_workload"
	case rawKindStepFunctionsStateMachineRole:
		return "stepfunctions_state_machine"
	default:
		return "aws_workload"
	}
}

func mapString(payload map[string]any, key string) string {
	if value, ok := payload[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func mapStringList(payload map[string]any, key string) []string {
	return normalizeStringList(parseStringList(payload[key]))
}

func mapStringMap(payload map[string]any, key string) map[string]string {
	raw, ok := payload[key].(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for key, value := range raw {
		if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
			out[strings.TrimSpace(key)] = strings.TrimSpace(s)
		}
	}
	return out
}

func mapTime(payload map[string]any, key string) time.Time {
	raw := mapString(payload, key)
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}
