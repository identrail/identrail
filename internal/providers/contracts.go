package providers

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

var supportedPolicyTypes = map[string]struct{}{
	"permission": {},
	"trust":      {},
}

// SourceError captures non-fatal collection issues discovered during one run.
// These errors are surfaced as scan lifecycle warnings without failing the scan.
type SourceError struct {
	Collector string `json:"collector"`
	SourceID  string `json:"source_id,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// DiagnosticCollector is an optional collector contract for partial-failure reporting.
type DiagnosticCollector interface {
	CollectWithDiagnostics(ctx context.Context) ([]RawAsset, []SourceError, error)
}

// ValidateNormalizedBundle enforces required normalized-schema invariants for v1.
func ValidateNormalizedBundle(bundle NormalizedBundle) error {
	identityIDs := make(map[string]struct{}, len(bundle.Identities))
	workloadIDs := make(map[string]struct{}, len(bundle.Workloads))
	policyIDs := make(map[string]struct{}, len(bundle.Policies))
	resourceIDs := make(map[string]struct{}, len(bundle.Resources))
	credentialIDs := make(map[string]struct{}, len(bundle.Credentials))
	agentIDs := make(map[string]struct{}, len(bundle.Agents))
	runtimeEventIDs := make(map[string]struct{}, len(bundle.RuntimeEvents))

	for i, identity := range bundle.Identities {
		if !identity.Validate() {
			return fmt.Errorf("invalid identity at index %d", i)
		}
		if _, exists := identityIDs[identity.ID]; exists {
			return fmt.Errorf("duplicate identity id %q", identity.ID)
		}
		identityIDs[identity.ID] = struct{}{}
	}
	for i, workload := range bundle.Workloads {
		if strings.TrimSpace(workload.ID) == "" ||
			strings.TrimSpace(string(workload.Provider)) == "" ||
			strings.TrimSpace(workload.Type) == "" ||
			strings.TrimSpace(workload.Name) == "" {
			return fmt.Errorf("invalid workload at index %d", i)
		}
		if _, exists := workloadIDs[workload.ID]; exists {
			return fmt.Errorf("duplicate workload id %q", workload.ID)
		}
		workloadIDs[workload.ID] = struct{}{}
	}
	for i, policy := range bundle.Policies {
		if strings.TrimSpace(policy.ID) == "" ||
			strings.TrimSpace(string(policy.Provider)) == "" ||
			strings.TrimSpace(policy.Name) == "" ||
			strings.TrimSpace(policy.RawRef) == "" {
			return fmt.Errorf("invalid policy at index %d", i)
		}
		if _, exists := policyIDs[policy.ID]; exists {
			return fmt.Errorf("duplicate policy id %q", policy.ID)
		}
		policyIDs[policy.ID] = struct{}{}
		if err := validatePolicyNormalized(policy.Normalized, identityIDs); err != nil {
			return fmt.Errorf("invalid policy %q normalized payload: %w", policy.ID, err)
		}
	}

	for i, resource := range bundle.Resources {
		if !resource.Validate() {
			return fmt.Errorf("invalid resource at index %d", i)
		}
		if _, exists := resourceIDs[resource.ID]; exists {
			return fmt.Errorf("duplicate resource id %q", resource.ID)
		}
		resourceIDs[resource.ID] = struct{}{}
	}

	for i, agent := range bundle.Agents {
		if !agent.Validate() {
			return fmt.Errorf("invalid agent at index %d", i)
		}
		if _, exists := agentIDs[agent.ID]; exists {
			return fmt.Errorf("duplicate agent id %q", agent.ID)
		}
		agentIDs[agent.ID] = struct{}{}

		if strings.TrimSpace(agent.RawRef) == "" {
			return fmt.Errorf("agent %q missing raw_ref", agent.ID)
		}
		if agent.OwnerID != "" && !bundleEntityExists(agent.OwnerID, identityIDs, workloadIDs, agentIDs, resourceIDs) {
			return fmt.Errorf("agent %q unknown owner_id %q", agent.ID, agent.OwnerID)
		}
	}

	for i, credential := range bundle.Credentials {
		if !credential.Validate() {
			return fmt.Errorf("invalid credential at index %d", i)
		}
		if _, exists := credentialIDs[credential.ID]; exists {
			return fmt.Errorf("duplicate credential id %q", credential.ID)
		}
		credentialIDs[credential.ID] = struct{}{}

		if strings.TrimSpace(credential.RawRef) == "" {
			return fmt.Errorf("credential %q missing raw_ref", credential.ID)
		}
		if strings.TrimSpace(credential.Reference) == "" && strings.TrimSpace(credential.ResourceID) == "" {
			return fmt.Errorf("credential %q missing reference", credential.ID)
		}
		if strings.TrimSpace(credential.Reference) == "" && strings.TrimSpace(credential.OwnerID) == "" {
			return fmt.Errorf("credential %q missing owner_id", credential.ID)
		}
		if credential.OwnerID != "" {
			if !bundleEntityExists(credential.OwnerID, identityIDs, workloadIDs, agentIDs, resourceIDs) {
				return fmt.Errorf("credential %q unknown owner_id %q", credential.ID, credential.OwnerID)
			}
		}
		if credential.ResourceID != "" {
			if _, exists := resourceIDs[credential.ResourceID]; !exists {
				return fmt.Errorf("credential %q unknown resource_id %q", credential.ID, credential.ResourceID)
			}
		}
		if credential.RawValue != "" {
			return fmt.Errorf("credential %q contains unredacted raw value", credential.ID)
		}
	}

	for i, runtimeEvent := range bundle.RuntimeEvents {
		if !runtimeEvent.Validate() {
			return fmt.Errorf("invalid runtime event at index %d", i)
		}
		if _, exists := runtimeEventIDs[runtimeEvent.ID]; exists {
			return fmt.Errorf("duplicate runtime event id %q", runtimeEvent.ID)
		}
		runtimeEventIDs[runtimeEvent.ID] = struct{}{}

		if !bundleNodeExists(runtimeEvent.ActorID, identityIDs, workloadIDs, agentIDs, resourceIDs, credentialIDs) &&
			!isSyntheticNodeID(runtimeEvent.ActorID) {
			return fmt.Errorf("runtime event %q unknown actor_id %q", runtimeEvent.ID, runtimeEvent.ActorID)
		}
		if runtimeEvent.CredentialID != "" {
			if _, exists := credentialIDs[runtimeEvent.CredentialID]; !exists {
				return fmt.Errorf("runtime event %q unknown credential_id %q", runtimeEvent.ID, runtimeEvent.CredentialID)
			}
		}
		if runtimeEvent.TargetID != "" &&
			!bundleNodeExists(runtimeEvent.TargetID, identityIDs, workloadIDs, agentIDs, resourceIDs, credentialIDs) &&
			!isSyntheticNodeID(runtimeEvent.TargetID) {
			return fmt.Errorf("runtime event %q unknown target_id %q", runtimeEvent.ID, runtimeEvent.TargetID)
		}
	}

	return nil
}

func bundleEntityExists(
	entityID string,
	identityIDs map[string]struct{},
	workloadIDs map[string]struct{},
	agentIDs map[string]struct{},
	resourceIDs map[string]struct{},
) bool {
	return bundleNodeExists(entityID, identityIDs, workloadIDs, agentIDs, resourceIDs, nil)
}

func bundleNodeExists(
	nodeID string,
	identityIDs map[string]struct{},
	workloadIDs map[string]struct{},
	agentIDs map[string]struct{},
	resourceIDs map[string]struct{},
	credentialIDs map[string]struct{},
) bool {
	if _, ok := identityIDs[nodeID]; ok {
		return true
	}
	if _, ok := workloadIDs[nodeID]; ok {
		return true
	}
	if _, ok := agentIDs[nodeID]; ok {
		return true
	}
	if _, ok := resourceIDs[nodeID]; ok {
		return true
	}
	if credentialIDs != nil {
		if _, ok := credentialIDs[nodeID]; ok {
			return true
		}
	}
	return false
}

func isSyntheticNodeID(nodeID string) bool {
	return nodeID == "" ||
		strings.HasPrefix(nodeID, "aws:access:") ||
		strings.HasPrefix(nodeID, "k8s:access:") ||
		strings.HasPrefix(nodeID, "aws:secret:") ||
		strings.HasPrefix(nodeID, "k8s:secret:") ||
		strings.HasPrefix(nodeID, "secret:") ||
		strings.HasPrefix(nodeID, "kms:") ||
		strings.HasPrefix(nodeID, "aws:kms:") ||
		strings.HasPrefix(nodeID, "action:") ||
		strings.HasPrefix(nodeID, "aws:action:") ||
		strings.HasPrefix(nodeID, "k8s:action:") ||
		strings.HasPrefix(nodeID, "invocable:") ||
		strings.HasPrefix(nodeID, "aws:lambda:") ||
		strings.HasPrefix(nodeID, "aws:service:") ||
		strings.HasPrefix(nodeID, "aws:resource:") ||
		strings.HasPrefix(nodeID, "k8s:workload:") ||
		strings.HasPrefix(nodeID, "tool:") ||
		strings.HasPrefix(nodeID, "mcp:tool:") ||
		strings.HasPrefix(nodeID, "agent:") ||
		strings.HasPrefix(nodeID, "session:") ||
		strings.HasPrefix(nodeID, "runtime:session:") ||
		strings.HasPrefix(nodeID, "aws:session:") ||
		strings.HasPrefix(nodeID, "k8s:session:")
}

func validatePolicyNormalized(normalized map[string]any, identityIDs map[string]struct{}) error {
	if len(normalized) == 0 {
		return fmt.Errorf("missing normalized payload")
	}
	policyType, _ := normalized["policy_type"].(string)
	policyType = strings.ToLower(strings.TrimSpace(policyType))
	if _, ok := supportedPolicyTypes[policyType]; !ok {
		return fmt.Errorf("unsupported policy_type %q", policyType)
	}
	identityID, _ := normalized["identity_id"].(string)
	identityID = strings.TrimSpace(identityID)
	if identityID == "" {
		return fmt.Errorf("missing identity_id")
	}
	if _, exists := identityIDs[identityID]; !exists {
		return fmt.Errorf("unknown identity_id %q", identityID)
	}

	switch policyType {
	case "permission":
		statements, ok := normalized["statements"].([]map[string]any)
		if !ok || len(statements) == 0 {
			// JSON roundtrip often decodes to []any; support that shape too.
			rawStatements, rawOK := normalized["statements"].([]any)
			if !rawOK || len(rawStatements) == 0 {
				return fmt.Errorf("missing permission statements")
			}
			for _, raw := range rawStatements {
				statement, ok := raw.(map[string]any)
				if !ok {
					return fmt.Errorf("invalid statement type %T", raw)
				}
				if err := validateStatement(statement); err != nil {
					return err
				}
			}
			return nil
		}
		for _, statement := range statements {
			if err := validateStatement(statement); err != nil {
				return err
			}
		}
	case "trust":
		principals := extractStringSlice(normalized["principals"])
		if len(principals) == 0 {
			return fmt.Errorf("missing trust principals")
		}
	}
	return nil
}

func validateStatement(statement map[string]any) error {
	effect, _ := statement["effect"].(string)
	if strings.TrimSpace(effect) == "" {
		return fmt.Errorf("statement missing effect")
	}
	actions := extractStringSlice(statement["actions"])
	if len(actions) == 0 {
		return fmt.Errorf("statement missing actions")
	}
	resources := extractStringSlice(statement["resources"])
	if len(resources) == 0 {
		return fmt.Errorf("statement missing resources")
	}
	return nil
}

func extractStringSlice(raw any) []string {
	switch values := raw.(type) {
	case []string:
		copied := append([]string(nil), values...)
		slices.Sort(copied)
		return slices.Compact(copied)
	case []any:
		result := make([]string, 0, len(values))
		seen := map[string]struct{}{}
		for _, value := range values {
			text, _ := value.(string)
			normalized := strings.TrimSpace(text)
			if normalized == "" {
				continue
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
		slices.Sort(result)
		return result
	default:
		return nil
	}
}
