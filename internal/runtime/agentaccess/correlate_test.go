package agentaccess

import (
	"strings"
	"testing"
	"time"
)

func observedAt(min int) time.Time {
	return time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
}

func findByTool(t *testing.T, result Result, tool string) Correlation {
	t.Helper()
	for _, correlation := range result.Correlations {
		if correlation.ToolName == tool {
			return correlation
		}
	}
	t.Fatalf("no correlation for tool %q in %+v", tool, result.Correlations)
	return Correlation{}
}

func hasCaveat(caveats []string, want string) bool {
	for _, caveat := range caveats {
		if caveat == want {
			return true
		}
	}
	return false
}

func TestCorrelateConfirmedJoinsObservedWithDeclaredTool(t *testing.T) {
	agent := "aws:agent:111122223333:us-east-1:agentcore_runtime/case-triage/2026-06-01"
	role := "arn:aws:iam::111122223333:role/case-triage-runtime"
	targetNode := "aws:resource:bedrock-agentcore:us-east-1:111122223333:agent-runtime-endpoint/case-triage/blue"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedToolCall{{
			EventID:              "evt-1",
			AgentNodeID:          agent,
			AgentID:              "case-triage",
			AgentType:            "agentcore_runtime",
			ToolName:             "case-router",
			ToolTargetRef:        "case-router-policy",
			BackingRoleARN:       role,
			BackingRoleNodeID:    "aws:identity:role:case-triage-runtime",
			TargetResourceARN:    "arn:aws:bedrock-agentcore:us-east-1:111122223333:agent-runtime-endpoint/case-triage/blue",
			TargetResourceNodeID: targetNode,
			Outcome:              OutcomeSucceeded,
			SessionID:            "ASIA-sess",
			LineageStatus:        "resolved",
			ObservedAt:           observedAt(5),
			EvidenceRef:          "runtime-evidence://evt-1",
		}},
		Declared: []DeclaredTool{{
			AgentNodeID:       agent,
			AgentID:           "case-triage",
			AgentName:         "Case Triage",
			AgentType:         "agentcore_runtime",
			ToolName:          "case-router",
			BackingRoleARN:    role,
			BackingRoleNodeID: "aws:identity:role:case-triage-runtime",
			Confidence:        0.9,
			EvidenceRef:       "agent-evidence://case-triage",
		}},
		KnownAgentNodeIDs: []string{agent},
	})
	if len(result.Correlations) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(result.Correlations))
	}
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected confirmed, got %q", correlation.Status)
	}
	if correlation.Confidence != 0.95 {
		t.Fatalf("expected 0.95 confidence, got %v", correlation.Confidence)
	}
	if !correlation.DeclaredInInventory || correlation.ToolName != "case-router" {
		t.Fatalf("unexpected correlation: %+v", correlation)
	}
	if len(correlation.Caveats) != 0 {
		t.Fatalf("clean confirmed should carry no caveats, got %+v", correlation.Caveats)
	}
	if correlation.RedactionBoundary != RedactionBoundary {
		t.Fatalf("missing redaction boundary: %+v", correlation)
	}
	if len(correlation.TargetResourceNodeIDs) != 1 || correlation.TargetResourceNodeIDs[0] != targetNode {
		t.Fatalf("expected target resource node id preserved, got %+v", correlation.TargetResourceNodeIDs)
	}
	if result.ConfirmedCount != 1 || result.AgentCount != 1 || result.ToolCount != 1 {
		t.Fatalf("unexpected result counts: %+v", result)
	}
}

func TestCorrelateBackingRoleMismatchAndFailure(t *testing.T) {
	agent := "aws:agent:1:us-east-1:agentcore_runtime/a/v"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedToolCall{{
			EventID: "e", AgentNodeID: agent, ToolName: "writer", BackingRoleNodeID: "aws:identity:role:unexpected", Outcome: OutcomeFailed, ObservedAt: observedAt(1),
		}},
		Declared: []DeclaredTool{{
			AgentNodeID: agent, ToolName: "writer", BackingRoleNodeID: "aws:identity:role:declared", Confidence: 0.9,
		}},
		KnownAgentNodeIDs: []string{agent},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed {
		t.Fatalf("expected confirmed (tool is declared), got %q", correlation.Status)
	}
	if !hasCaveat(correlation.Caveats, CaveatBackingRoleMismatch) {
		t.Fatalf("expected backing-role-mismatch caveat, got %+v", correlation.Caveats)
	}
	if !hasCaveat(correlation.Caveats, CaveatToolCallFailed) {
		t.Fatalf("expected tool-call-failed caveat, got %+v", correlation.Caveats)
	}
	if correlation.Confidence != 0.8 {
		t.Fatalf("expected confidence capped to 0.8, got %v", correlation.Confidence)
	}
	if result.BackingRoleMismatchCount != 1 || result.FailedToolCallCount != 1 {
		t.Fatalf("unexpected result counts: %+v", result)
	}
}

func TestCorrelateShadowAgentVsUndeclaredTool(t *testing.T) {
	knownAgent := "aws:agent:1:us-east-1:agentcore_runtime/known/v"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedToolCall{
			{EventID: "shadow", AgentNodeID: "aws:agent:1:us-east-1:agentcore_runtime/shadow/v", ToolName: "exfil", ObservedAt: observedAt(1)},
			{EventID: "undeclared", AgentNodeID: knownAgent, ToolName: "surprise", ObservedAt: observedAt(2)},
		},
		Declared: []DeclaredTool{
			{AgentNodeID: knownAgent, ToolName: "expected"},
		},
		KnownAgentNodeIDs:        []string{knownAgent},
		InventoryAvailable:       true,
		DataEventCoverageUnknown: true,
	})
	shadow := findByTool(t, result, "exfil")
	if shadow.Status != StatusObservedWithoutDeclaration || !hasCaveat(shadow.Caveats, CaveatAgentNotInInventory) {
		t.Fatalf("expected shadow-agent caveat, got %+v", shadow)
	}
	undeclared := findByTool(t, result, "surprise")
	if undeclared.Status != StatusObservedWithoutDeclaration || !hasCaveat(undeclared.Caveats, CaveatToolNotDeclared) {
		t.Fatalf("expected tool-not-declared caveat, got %+v", undeclared)
	}
	if hasCaveat(undeclared.Caveats, CaveatAgentNotInInventory) {
		t.Fatalf("known agent must not be flagged as shadow: %+v", undeclared.Caveats)
	}
	expected := findByTool(t, result, "expected")
	if expected.Status != StatusDeclaredUnused || !hasCaveat(expected.Caveats, CaveatDataEventCoverage) {
		t.Fatalf("expected declared_unused + missing-event caveat, got %+v", expected)
	}
	if expected.Confidence != 0.5 {
		t.Fatalf("expected 0.5 confidence for declared_unused with unknown coverage, got %v", expected.Confidence)
	}
	if result.ShadowAgentCount != 1 || result.UndeclaredToolCount != 1 || result.DeclaredUnusedCount != 1 {
		t.Fatalf("unexpected result counts: %+v", result)
	}
}

func TestCorrelateInventoryUnavailableDoesNotAccuseShadowAgent(t *testing.T) {
	// In live mode the inventory may be unavailable. An observed tool-call
	// must not be mislabeled as a shadow agent in that case.
	result := Correlate(CorrelateRequest{
		Observed:           []ObservedToolCall{{EventID: "e", AgentNodeID: "aws:agent:1:us-east-1:agentcore_runtime/real/v", ToolName: "router", ObservedAt: observedAt(1)}},
		InventoryAvailable: false,
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusObservedWithoutDeclaration {
		t.Fatalf("expected observed_without_declaration, got %q", correlation.Status)
	}
	if !hasCaveat(correlation.Caveats, CaveatInventoryUnavailable) {
		t.Fatalf("expected inventory-unavailable caveat, got %+v", correlation.Caveats)
	}
	if hasCaveat(correlation.Caveats, CaveatAgentNotInInventory) {
		t.Fatalf("must not accuse shadow agent when inventory is unavailable: %+v", correlation.Caveats)
	}
}

func TestCorrelateDeclaredUnusedHigherConfidenceWhenCoverageKnown(t *testing.T) {
	agent := "aws:agent:1:us-east-1:agentcore_runtime/a/v"
	result := Correlate(CorrelateRequest{
		Declared:          []DeclaredTool{{AgentNodeID: agent, ToolName: "t"}},
		KnownAgentNodeIDs: []string{agent},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusDeclaredUnused || correlation.Confidence != 0.7 {
		t.Fatalf("expected declared_unused at 0.7 when coverage known, got %+v", correlation)
	}
	if hasCaveat(correlation.Caveats, CaveatDataEventCoverage) {
		t.Fatalf("did not expect missing-event caveat when coverage known: %+v", correlation.Caveats)
	}
}

func TestCorrelateLineageUnresolvedCapsConfirmedConfidence(t *testing.T) {
	agent := "aws:agent:1:us-east-1:agentcore_runtime/a/v"
	result := Correlate(CorrelateRequest{
		Observed:          []ObservedToolCall{{EventID: "e", AgentNodeID: agent, ToolName: "t", LineageStatus: "source_identity_missing", ObservedAt: observedAt(1)}},
		Declared:          []DeclaredTool{{AgentNodeID: agent, ToolName: "t"}},
		KnownAgentNodeIDs: []string{agent},
	})
	correlation := result.Correlations[0]
	if correlation.Status != StatusConfirmed || correlation.Confidence != 0.85 || !hasCaveat(correlation.Caveats, CaveatLineageUnresolved) {
		t.Fatalf("expected confirmed capped to 0.85 with lineage caveat, got %+v", correlation)
	}
}

func TestCorrelateAgentWithNoToolsNotSurfacedAsUnusedTool(t *testing.T) {
	agent := "aws:agent:1:us-east-1:agentcore_runtime/a/v"
	result := Correlate(CorrelateRequest{
		Declared:          []DeclaredTool{{AgentNodeID: agent, ToolName: ""}},
		KnownAgentNodeIDs: []string{agent},
	})
	if len(result.Correlations) != 0 {
		t.Fatalf("an agent that declares no tools and was never observed must not surface a phantom tool: %+v", result.Correlations)
	}
}

func TestCorrelateBareInvocationDoesNotMergeWithNamedTool(t *testing.T) {
	agent := "aws:agent:1:us-east-1:agentcore_runtime/a/v"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedToolCall{
			{EventID: "inv", AgentNodeID: agent, ToolName: "", ObservedAt: observedAt(1)},
			{EventID: "named", AgentNodeID: agent, ToolName: "router", ObservedAt: observedAt(2)},
		},
	})
	if len(result.Correlations) != 2 {
		t.Fatalf("expected bare invocation and named tool to stay separate, got %d (%+v)", len(result.Correlations), result.Correlations)
	}
}

func TestCorrelateAggregatesRepeatedCallsCaseInsensitive(t *testing.T) {
	agent := "AWS:Agent:1:us-east-1:agentcore_runtime/A/v"
	result := Correlate(CorrelateRequest{
		Observed: []ObservedToolCall{
			{EventID: "a", AgentNodeID: agent, ToolName: "router", SessionID: "s1", ObservedAt: observedAt(10)},
			{EventID: "b", AgentNodeID: strings.ToLower(agent), ToolName: "router", SessionID: "s2", ObservedAt: observedAt(2)},
		},
		Declared:          []DeclaredTool{{AgentNodeID: strings.ToLower(agent), ToolName: "router"}},
		KnownAgentNodeIDs: []string{strings.ToLower(agent)},
	})
	if len(result.Correlations) != 1 {
		t.Fatalf("expected case-insensitive aggregation into 1 correlation, got %d", len(result.Correlations))
	}
	correlation := result.Correlations[0]
	if correlation.ObservedCount != 2 || len(correlation.SessionIDs) != 2 {
		t.Fatalf("expected aggregated observations, got %+v", correlation)
	}
	if !correlation.FirstObservedAt.Equal(observedAt(2)) || !correlation.LastObservedAt.Equal(observedAt(10)) {
		t.Fatalf("unexpected observed window: first=%v last=%v", correlation.FirstObservedAt, correlation.LastObservedAt)
	}
}

func TestCorrelateSkipsUnattributableRecords(t *testing.T) {
	result := Correlate(CorrelateRequest{
		Observed: []ObservedToolCall{{EventID: "no-agent", ToolName: "x"}},
		Declared: []DeclaredTool{{ToolName: "y"}},
	})
	if len(result.Correlations) != 0 {
		t.Fatalf("expected unattributable records skipped, got %+v", result.Correlations)
	}
	if result.ObservedToolCallsConsidered != 0 || result.DeclaredToolsConsidered != 0 {
		t.Fatalf("expected zero considered, got %+v", result)
	}
}

func TestCorrelateDeterministicOrdering(t *testing.T) {
	build := func() []Correlation {
		return Correlate(CorrelateRequest{
			Observed: []ObservedToolCall{
				{EventID: "1", AgentNodeID: "z-agent", ToolName: "b", ObservedAt: observedAt(1)},
				{EventID: "2", AgentNodeID: "a-agent", ToolName: "b", ObservedAt: observedAt(1)},
				{EventID: "3", AgentNodeID: "a-agent", ToolName: "a", ObservedAt: observedAt(1)},
			},
		}).Correlations
	}
	first := build()
	second := build()
	if len(first) != 3 {
		t.Fatalf("expected 3 correlations, got %d", len(first))
	}
	for i := range first {
		if first[i].CorrelationID != second[i].CorrelationID {
			t.Fatalf("ordering not deterministic at %d", i)
		}
	}
	if first[0].AgentNodeID != "a-agent" || first[0].ToolName != "a" || first[1].ToolName != "b" {
		t.Fatalf("unexpected ordering: %+v", first)
	}
}
