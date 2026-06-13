package aws

import (
	"fmt"
	"strings"
	"time"
)

func derefTimeOrZero(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.UTC()
}

func firstNonEmptyAWSValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func normalizeOrderedStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func awsAIAgentNodeID(accountID string, region string, agentType string, agentID string, runtimeVersion string) string {
	version := strings.TrimSpace(runtimeVersion)
	if version != "" {
		version = normalizeName(version)
	}
	suffix := firstNonEmptyAWSValue(agentID, "unknown")
	if version != "" {
		suffix = suffix + "/" + version
	}
	return fmt.Sprintf("aws:agent:%s:%s:%s/%s",
		firstNonEmptyAWSValue(accountID, "account"),
		firstNonEmptyAWSValue(region, "region"),
		firstNonEmptyAWSValue(agentType, "agent"),
		suffix,
	)
}

func awsAIAgentToolNodeID(agentNodeID string, tool string) string {
	workload := strings.TrimSpace(strings.ToLower(agentNodeID))
	if workload == "" {
		workload = "gateway"
	}
	name := strings.TrimSpace(strings.ToLower(tool))
	if name == "" {
		name = "tool"
	}
	return "tool:agent:" + strings.Join(normalizeStringList([]string{workload, name}), "|")
}

func awsAIAgentExecutionEndpointNodeID(agentNodeID string, endpointARN string) string {
	workload := strings.TrimSpace(agentNodeID)
	if workload == "" {
		workload = "agent"
	}
	name, source := awsAIAgentResourceReferenceParts(endpointARN)
	name = strings.TrimSpace(strings.ToLower(name))
	source = strings.TrimSpace(strings.ToLower(source))
	return "aws:resource:bedrock-agentcore:" + strings.Join(normalizeStringList([]string{
		workload,
		"endpoint",
		source,
		name,
	}), "|")
}

func awsAIAgentCapabilityNodeID(agentNodeID string, capabilityKind string) string {
	workload := strings.TrimSpace(agentNodeID)
	if workload == "" {
		workload = "agent"
	}
	kind := strings.TrimSpace(strings.ToLower(capabilityKind))
	if kind == "" {
		kind = "capability"
	}
	return "aws:resource:agentcore-capability:" + strings.Join(normalizeStringList([]string{workload, kind}), "|")
}

func awsAIAgentResourceReferenceParts(ref string) (string, string) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return "resource", "unknown"
	}
	if idx := strings.Index(trimmed, "="); idx > 0 {
		name := strings.TrimSpace(trimmed[:idx])
		source := strings.TrimSpace(trimmed[idx+1:])
		if source == "" {
			source = "environment"
		}
		return sanitizeAIAgentReferenceToken(name), sanitizeAIAgentReferenceToken(source)
	}
	if !strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "/") {
		return sanitizeAIAgentReferenceToken(trimmed), ""
	}
	name := trimmed
	if lastSlash := strings.LastIndex(trimmed, "/"); lastSlash >= 0 && lastSlash < len(trimmed)-1 {
		name = trimmed[lastSlash+1:]
	} else if colonIndex := strings.LastIndex(trimmed, ":"); colonIndex >= 0 && colonIndex < len(trimmed)-1 {
		name = trimmed[colonIndex+1:]
	}
	return sanitizeAIAgentReferenceToken(name), sanitizeAIAgentReferenceToken(trimmed)
}

func sanitizeAIAgentReferenceToken(value string) string {
	return strings.ToLower(strings.NewReplacer(" ", "-", "/", "-", ":", "-", "#", "-").Replace(strings.TrimSpace(value)))
}
