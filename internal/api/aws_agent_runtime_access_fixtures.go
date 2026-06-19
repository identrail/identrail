package api

import (
	"fmt"
	"time"

	"github.com/identrail/identrail/internal/runtime/agentaccess"
)

// awsAgentRuntimeAccessFixtureInputs returns deterministic observed
// tool-calls and declared tools for each fixture state. The default
// success state exercises all three correlation outcomes — confirmed,
// observed_without_declaration (both a shadow agent and an undeclared
// tool), and declared_unused — plus a backing-role mismatch and a failed
// tool-call, so the surface and tests cover the taxonomy without a live
// AWS account. All inputs are metadata-only (no prompts/completions).
func awsAgentRuntimeAccessFixtureInputs(accountID string, region string, fixtureState string, checkedAt time.Time) ([]agentaccess.ObservedToolCall, []agentaccess.DeclaredTool, []string, bool, []AWSAgentRuntimeAccessDiagnostic, []AWSAgentRuntimeAccessCoverageGap, []string, []string, string, bool) {
	base := checkedAt.Add(-30 * time.Minute)

	triageAgent := awsAIAgentNodeID(accountID, region, "agentcore_runtime", "case-triage", "2026-06-01")
	invoiceAgent := awsAIAgentNodeID(accountID, region, "bedrock_agent", "invoice-bot", "")
	shadowAgent := awsAIAgentNodeID(accountID, region, "agentcore_runtime", "rogue-exporter", "2026-06-10")

	triageRole := fmt.Sprintf("arn:aws:iam::%s:role/case-triage-runtime", accountID)
	triageRoleNode := awsIdentityNodeIDForAPI(triageRole)
	invoiceRole := fmt.Sprintf("arn:aws:iam::%s:role/invoice-bot-runtime", accountID)
	invoiceRoleNode := awsIdentityNodeIDForAPI(invoiceRole)
	unexpectedRole := fmt.Sprintf("arn:aws:iam::%s:role/adhoc-operator", accountID)
	unexpectedRoleNode := awsIdentityNodeIDForAPI(unexpectedRole)

	triageEndpoint := fmt.Sprintf("arn:aws:bedrock-agentcore:%s:%s:agent-runtime-endpoint/case-triage/blue", region, accountID)
	invoiceEndpoint := fmt.Sprintf("arn:aws:bedrock-agent:%s:%s:agent/invoice-bot", region, accountID)
	shadowEndpoint := fmt.Sprintf("arn:aws:bedrock-agentcore:%s:%s:agent-runtime-endpoint/rogue-exporter/red", region, accountID)

	observed := []agentaccess.ObservedToolCall{
		{
			EventID:           "evt-agent-confirmed",
			AgentNodeID:       triageAgent,
			AgentID:           "case-triage",
			AgentType:         "agentcore_runtime",
			RuntimeVersion:    "2026-06-01",
			ToolName:          "case-router",
			ToolTargetRef:     "case-router-policy",
			BackingRoleARN:    triageRole,
			BackingRoleNodeID: triageRoleNode,
			TargetResourceARN: triageEndpoint,
			Outcome:           agentaccess.OutcomeSucceeded,
			SessionID:         "ASIA-triage-sess",
			LineageStatus:     "resolved",
			ObservedAt:        base.Add(4 * time.Minute),
			EvidenceRef:       fmt.Sprintf("runtime-evidence://%s/%s/evt-agent-confirmed", accountID, region),
		},
		{
			// Declared tool, but the observed backing role differs from the
			// agent's declared runtime role, and the tool-call failed.
			EventID:           "evt-agent-mismatch",
			AgentNodeID:       invoiceAgent,
			AgentID:           "invoice-bot",
			AgentType:         "bedrock_agent",
			ToolName:          "ticket-writer",
			BackingRoleARN:    unexpectedRole,
			BackingRoleNodeID: unexpectedRoleNode,
			TargetResourceARN: invoiceEndpoint,
			Outcome:           agentaccess.OutcomeFailed,
			SessionID:         "ASIA-invoice-sess",
			LineageStatus:     "resolved",
			ObservedAt:        base.Add(7 * time.Minute),
			EvidenceRef:       fmt.Sprintf("runtime-evidence://%s/%s/evt-agent-mismatch", accountID, region),
		},
		{
			// Known agent, undeclared tool.
			EventID:           "evt-agent-undeclared-tool",
			AgentNodeID:       triageAgent,
			AgentID:           "case-triage",
			AgentType:         "agentcore_runtime",
			RuntimeVersion:    "2026-06-01",
			ToolName:          "bulk-export",
			BackingRoleARN:    triageRole,
			BackingRoleNodeID: triageRoleNode,
			TargetResourceARN: triageEndpoint,
			Outcome:           agentaccess.OutcomeSucceeded,
			SessionID:         "ASIA-triage-sess",
			LineageStatus:     "source_identity_missing",
			ObservedAt:        base.Add(9 * time.Minute),
			EvidenceRef:       fmt.Sprintf("runtime-evidence://%s/%s/evt-agent-undeclared-tool", accountID, region),
		},
		{
			// Shadow agent: not in the inventory at all.
			EventID:           "evt-agent-shadow",
			AgentNodeID:       shadowAgent,
			AgentID:           "rogue-exporter",
			AgentType:         "agentcore_runtime",
			RuntimeVersion:    "2026-06-10",
			ToolName:          "exfiltrate",
			BackingRoleARN:    unexpectedRole,
			BackingRoleNodeID: unexpectedRoleNode,
			TargetResourceARN: shadowEndpoint,
			Outcome:           agentaccess.OutcomeSucceeded,
			SessionID:         "ASIA-rogue-sess",
			LineageStatus:     "resolved",
			ObservedAt:        base.Add(12 * time.Minute),
			EvidenceRef:       fmt.Sprintf("runtime-evidence://%s/%s/evt-agent-shadow", accountID, region),
		},
	}

	declared := []agentaccess.DeclaredTool{
		{
			AgentNodeID:       triageAgent,
			AgentID:           "case-triage",
			AgentName:         "Case Triage",
			AgentType:         "agentcore_runtime",
			RuntimeVersion:    "2026-06-01",
			ToolName:          "case-router",
			ToolTargetRef:     "case-router-policy",
			BackingRoleARN:    triageRole,
			BackingRoleNodeID: triageRoleNode,
			AccountID:         accountID,
			Region:            region,
			Confidence:        0.9,
			EvidenceRef:       triageEndpoint,
		},
		{
			// Declared but never observed → declared_unused.
			AgentNodeID:       triageAgent,
			AgentID:           "case-triage",
			AgentName:         "Case Triage",
			AgentType:         "agentcore_runtime",
			RuntimeVersion:    "2026-06-01",
			ToolName:          "policy-checker",
			BackingRoleARN:    triageRole,
			BackingRoleNodeID: triageRoleNode,
			AccountID:         accountID,
			Region:            region,
			Confidence:        0.9,
			EvidenceRef:       triageEndpoint,
		},
		{
			AgentNodeID:       invoiceAgent,
			AgentID:           "invoice-bot",
			AgentName:         "Invoice Bot",
			AgentType:         "bedrock_agent",
			ToolName:          "ticket-writer",
			BackingRoleARN:    invoiceRole,
			BackingRoleNodeID: invoiceRoleNode,
			AccountID:         accountID,
			Region:            region,
			Confidence:        0.88,
			EvidenceRef:       invoiceEndpoint,
		},
	}
	known := []string{triageAgent, invoiceAgent}

	switch fixtureState {
	case "empty":
		return nil, nil, known, true, nil, []AWSAgentRuntimeAccessCoverageGap{{
			Capability:  "agent_runtime_access",
			Status:      "empty",
			Reason:      "No agent tool-calls or declared tools were available in the fixture window.",
			Remediation: "Confirm agent runtime / tool-call telemetry is enabled, then retry.",
		}}, nil, nil, awsPlatformDependencyStatusReady, true
	case "degraded":
		return observed, declared, known, true, []AWSAgentRuntimeAccessDiagnostic{{
			Collector:   agentaccess.CollectorName,
			SourceID:    "evt-agent-undeclared-tool",
			Code:        "runtime_event_delivery_delayed",
			Message:     "One agent tool-call arrived after the expected collection window; correlation confidence is reduced.",
			Remediation: "Keep delayed evidence visible and avoid automated remediation until delivery catches up.",
			Retryable:   true,
		}}, nil, []string{"runtime correlation includes delayed or low-confidence evidence"}, []string{"Review delayed agent tool-call delivery before using correlations for remediation."}, awsPlatformDependencyStatusDegraded, true
	case "partial_failure":
		// The agent inventory failed to load; observed tool-calls remain
		// visible but cannot be confirmed against declarations.
		return observed, nil, nil, false, []AWSAgentRuntimeAccessDiagnostic{{
				Collector:   agentaccess.CollectorName,
				SourceID:    "agent_inventory",
				Code:        "agent_inventory_unavailable",
				Message:     "The AI-agent inventory could not be loaded; observed tool-calls cannot be confirmed against declarations.",
				Remediation: "Retry the AI-agent inventory collection and re-run the correlation without discarding observed evidence.",
				Retryable:   true,
			}}, []AWSAgentRuntimeAccessCoverageGap{{
				Capability:  "agent_inventory_join",
				Status:      "partial_failure",
				Reason:      "The agent inventory was unavailable, so observed tool-calls could not be confirmed against declared tools.",
				Remediation: "Retry the AI-agent inventory collection and re-run the correlation.",
			}}, []string{"agent inventory join is incomplete; observed tool-calls are unconfirmed"}, []string{"Retry the AI-agent inventory collection and re-run the correlation."}, awsPlatformDependencyStatusDegraded, true
	case "permission_denied":
		return nil, nil, nil, true, []AWSAgentRuntimeAccessDiagnostic{{
				Collector:   agentaccess.CollectorName,
				SourceID:    "cloudtrail",
				Code:        "permission_denied",
				Message:     "Runtime event sources are not authorized for this connector; no agent tool-calls can be correlated.",
				Remediation: "Grant metadata-only CloudTrail access. Do not grant prompt, completion, or tool-payload reads.",
				Retryable:   true,
			}}, []AWSAgentRuntimeAccessCoverageGap{{
				Capability:  "agent_runtime_access",
				Status:      "permission_denied",
				Reason:      "Runtime event source cannot be queried with the current connector permissions.",
				Remediation: "Add read-only CloudTrail access and retry.",
			}}, []string{"runtime event sources are not authorized for this connector"}, []string{"Grant metadata-only CloudTrail access; do not grant prompt/completion/tool-payload reads."}, awsPlatformDependencyStatusBlocked, true
	default:
		return observed, declared, known, true, nil, awsAgentRuntimeAccessBaseCoverageGaps(), nil, nil, awsPlatformDependencyStatusReady, true
	}
}

// awsAgentRuntimeAccessBaseCoverageGaps documents what this correlation
// intentionally does not model and the redaction boundary it enforces.
func awsAgentRuntimeAccessBaseCoverageGaps() []AWSAgentRuntimeAccessCoverageGap {
	return []AWSAgentRuntimeAccessCoverageGap{
		{
			Capability:  "tool_call_outcome",
			Status:      "degraded",
			Reason:      "Explicit tool-call success/failure outcomes are not extracted from live runtime sources yet (it requires error-code extraction in the ingestion layer), so live outcomes are reported as 'unknown'.",
			Remediation: "Use observed/declared correlation and backing-role checks for triage; explicit outcomes will follow when error-code extraction is wired.",
		},
		{
			Capability:  "agent_payload_visibility",
			Status:      "unsupported",
			Reason:      "Prompts, completions, tool inputs/outputs, browser pages, and code-interpreter output are never collected. Only metadata (agent, tool, backing role, target resource) is correlated.",
			Remediation: "Inspect agent payloads directly in the agent platform when investigating a specific tool-call.",
		},
		{
			Capability:  "data_event_completeness",
			Status:      "degraded",
			Reason:      "Agent tool-call telemetry is not guaranteed complete from the available runtime sources, so declared_unused may reflect missing telemetry.",
			Remediation: "Enable agent runtime / tool-call data-event delivery to make declared_unused conclusions reliable.",
		},
	}
}
