// Package agentaccess correlates observed agent runtime / tool-call
// events with the static AI-agent inventory Identrail already discovered
// (declared agents, their backing runtime role, and their declared
// tools). The output ties observed behavior back to agent identity,
// backing role, tool, target resource, and outcome so an operator can
// answer, per (agent, tool) pair:
//
//   - confirmed:                    the agent and tool are declared in the
//     inventory AND a tool-call was observed. Behavior matches the
//     discovered agent surface.
//   - observed_without_declaration: a tool-call was observed for an agent
//     that is not in the inventory (a shadow agent) or for a tool the
//     agent does not declare (an undeclared tool). Treated as a caveat,
//     never a silent success.
//   - declared_unused:              the agent declares the tool but no
//     tool-call was observed in the window. Carries a missing-event
//     caveat because agent tool-call telemetry is not guaranteed to be
//     complete; absence is not proof the tool was never used.
//
// On top of the inventory join, the correlation flags when the observed
// backing role differs from the agent's declared runtime role
// (privilege drift) and surfaces failed tool-call outcomes.
//
// Safety boundary: the engine is metadata-only. It never reads, logs, or
// persists prompts, completions, tool inputs/outputs, browser pages,
// code-interpreter output, or any other customer payload — only the
// already-redacted runtime-event and agent-inventory metadata. Every
// emitted correlation re-stamps the redaction boundary.
package agentaccess

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Correlation statuses.
const (
	StatusConfirmed                  = "confirmed"
	StatusObservedWithoutDeclaration = "observed_without_declaration"
	StatusDeclaredUnused             = "declared_unused"
)

// Tool-call outcomes.
const (
	OutcomeSucceeded = "succeeded"
	OutcomeFailed    = "failed"
	OutcomeUnknown   = "unknown"
)

// invocationToolToken is the synthetic tool key used when an observed
// agent invocation carries no specific tool name (e.g. InvokeAgent) so a
// bare invocation does not merge with a named tool-call.
const invocationToolToken = "<invocation>"

const (
	// CollectorName tags every diagnostic and result the correlator
	// emits so the API layer can scope diagnostics by collector.
	CollectorName = "aws_agent_runtime_access"

	// RedactionBoundary documents that the correlator only ever crossed
	// the metadata boundary — no prompts, completions, or tool payloads.
	RedactionBoundary = "metadata_only_no_prompts_no_completions_no_tool_payloads"
)

// Caveat codes attached to individual correlations or the result.
const (
	CaveatDataEventCoverage    = "agent_tool_telemetry_may_be_incomplete"
	CaveatAgentNotInInventory  = "agent_not_in_inventory"
	CaveatToolNotDeclared      = "tool_not_declared_by_agent"
	CaveatBackingRoleMismatch  = "observed_backing_role_differs_from_declared"
	CaveatToolCallFailed       = "observed_tool_call_failed"
	CaveatLineageUnresolved    = "session_lineage_unresolved"
	CaveatInventoryUnavailable = "agent_inventory_unavailable_for_confirmation"
)

// ObservedToolCall is one metadata-only agent runtime / tool-call event
// projected from the runtime-event contract.
type ObservedToolCall struct {
	EventID              string
	AgentNodeID          string
	AgentID              string
	AgentType            string
	RuntimeVersion       string
	ToolName             string
	ToolTargetRef        string
	BackingRoleARN       string
	BackingRoleNodeID    string
	TargetResourceARN    string
	TargetResourceNodeID string
	Outcome              string
	SessionID            string
	AccountID            string
	Region               string
	LineageStatus        string
	ObservedAt           time.Time
	EvidenceRef          string
}

// DeclaredTool is one declared (agent, tool) pair from the AI-agent
// inventory. A tool name of "" represents an agent that declares no
// tools (so the agent itself can still be surfaced as declared_unused).
type DeclaredTool struct {
	AgentNodeID       string
	AgentID           string
	AgentName         string
	AgentType         string
	RuntimeVersion    string
	ToolName          string
	ToolTargetRef     string
	BackingRoleARN    string
	BackingRoleNodeID string
	AccountID         string
	Region            string
	Confidence        float64
	EvidenceRef       string
}

// CorrelateRequest configures one correlation pass.
type CorrelateRequest struct {
	AccountID string
	Region    string
	Observed  []ObservedToolCall
	Declared  []DeclaredTool
	// KnownAgentNodeIDs is the set of agent node ids present in the
	// inventory (including agents that declare no tools). It lets the
	// engine distinguish a shadow agent (agent_not_in_inventory) from a
	// known agent invoking an undeclared tool (tool_not_declared).
	KnownAgentNodeIDs []string
	// InventoryAvailable reports whether the AI-agent inventory was
	// actually available for this correlation pass. When false (e.g. the
	// inventory could not be loaded in live mode), an observed tool-call
	// is surfaced with a neutral "inventory unavailable" caveat rather
	// than being mislabeled as a shadow agent, since absence of the
	// inventory is not evidence the agent is undeclared.
	InventoryAvailable bool
	// DataEventCoverageUnknown marks that the observed set comes from a
	// runtime source that does not guarantee agent tool-call telemetry is
	// complete. When true, declared_unused correlations and the result
	// carry the missing-event caveat.
	DataEventCoverageUnknown bool
}

// Correlation is one (agent, tool) correlation record.
type Correlation struct {
	CorrelationID           string
	AgentNodeID             string
	AgentID                 string
	AgentName               string
	AgentType               string
	RuntimeVersion          string
	ToolName                string
	ToolTargetRef           string
	AccountID               string
	Region                  string
	Status                  string
	Confidence              float64
	ObservedCount           int
	ObservedEventIDs        []string
	BackingRoleARNs         []string
	BackingRoleNodeIDs      []string
	DeclaredBackingRole     string
	DeclaredBackingRoleNode string
	TargetResourceARNs      []string
	TargetResourceNodeIDs   []string
	Outcomes                []string
	SessionIDs              []string
	FirstObservedAt         time.Time
	LastObservedAt          time.Time
	DeclaredInInventory     bool
	Caveats                 []string
	EvidenceRefs            []string
	RedactionBoundary       string
}

// Result is the bounded outcome of one correlation pass.
type Result struct {
	Correlations                []Correlation
	Caveats                     []string
	ConfirmedCount              int
	ObservedWithoutDecl         int
	DeclaredUnusedCount         int
	ShadowAgentCount            int
	UndeclaredToolCount         int
	BackingRoleMismatchCount    int
	FailedToolCallCount         int
	AgentCount                  int
	ToolCount                   int
	ObservedToolCallsConsidered int
	DeclaredToolsConsidered     int
}

type correlationKey struct {
	agent string
	tool  string
}

type correlationAgg struct {
	agentNodeID    string
	agentID        string
	agentName      string
	agentType      string
	runtimeVersion string
	toolName       string
	toolTargetRef  string
	accountID      string
	region         string
	observed       []ObservedToolCall
	declared       []DeclaredTool
	order          int
}

// Correlate joins observed tool-calls with the declared agent inventory
// and returns one correlation per (agent, tool) pair. It never returns
// an error: documented gaps surface as caveats so the API layer can
// return a stable response.
func Correlate(request CorrelateRequest) Result {
	knownAgents := map[string]struct{}{}
	for _, id := range request.KnownAgentNodeIDs {
		if trimmed := normalize(id); trimmed != "" {
			knownAgents[trimmed] = struct{}{}
		}
	}

	index := map[correlationKey]*correlationAgg{}
	order := 0
	get := func(agentNodeID, agentID, agentName, agentType, runtimeVersion, toolName, toolTargetRef, account, region string) *correlationAgg {
		agent := firstNonEmpty(agentNodeID, agentID)
		toolKey := normalize(toolName)
		if toolKey == "" {
			toolKey = invocationToolToken
		}
		k := correlationKey{agent: normalize(agent), tool: toolKey}
		agg, ok := index[k]
		if !ok {
			agg = &correlationAgg{
				agentNodeID:    strings.TrimSpace(agentNodeID),
				agentID:        strings.TrimSpace(agentID),
				agentName:      strings.TrimSpace(agentName),
				agentType:      strings.TrimSpace(agentType),
				runtimeVersion: strings.TrimSpace(runtimeVersion),
				toolName:       strings.TrimSpace(toolName),
				toolTargetRef:  strings.TrimSpace(toolTargetRef),
				accountID:      strings.TrimSpace(account),
				region:         strings.TrimSpace(region),
				order:          order,
			}
			order++
			index[k] = agg
		}
		if agg.agentNodeID == "" {
			agg.agentNodeID = strings.TrimSpace(agentNodeID)
		}
		if agg.agentID == "" {
			agg.agentID = strings.TrimSpace(agentID)
		}
		if agg.agentName == "" {
			agg.agentName = strings.TrimSpace(agentName)
		}
		if agg.agentType == "" {
			agg.agentType = strings.TrimSpace(agentType)
		}
		if agg.runtimeVersion == "" {
			agg.runtimeVersion = strings.TrimSpace(runtimeVersion)
		}
		if agg.toolTargetRef == "" {
			agg.toolTargetRef = strings.TrimSpace(toolTargetRef)
		}
		if agg.accountID == "" {
			agg.accountID = strings.TrimSpace(account)
		}
		if agg.region == "" {
			agg.region = strings.TrimSpace(region)
		}
		return agg
	}

	considered := 0
	for _, observed := range request.Observed {
		if strings.TrimSpace(observed.AgentNodeID) == "" && strings.TrimSpace(observed.AgentID) == "" {
			continue
		}
		considered++
		agg := get(observed.AgentNodeID, observed.AgentID, "", observed.AgentType, observed.RuntimeVersion, observed.ToolName, observed.ToolTargetRef, observed.AccountID, observed.Region)
		agg.observed = append(agg.observed, observed)
	}

	declaredConsidered := 0
	for _, declared := range request.Declared {
		if strings.TrimSpace(declared.AgentNodeID) == "" && strings.TrimSpace(declared.AgentID) == "" {
			continue
		}
		declaredConsidered++
		agg := get(declared.AgentNodeID, declared.AgentID, declared.AgentName, declared.AgentType, declared.RuntimeVersion, declared.ToolName, declared.ToolTargetRef, declared.AccountID, declared.Region)
		agg.declared = append(agg.declared, declared)
	}

	aggs := make([]*correlationAgg, 0, len(index))
	for _, agg := range index {
		aggs = append(aggs, agg)
	}
	sort.SliceStable(aggs, func(i, j int) bool {
		ai := firstNonEmpty(aggs[i].agentNodeID, aggs[i].agentID)
		aj := firstNonEmpty(aggs[j].agentNodeID, aggs[j].agentID)
		if normalize(ai) != normalize(aj) {
			return normalize(ai) < normalize(aj)
		}
		if normalize(aggs[i].toolName) != normalize(aggs[j].toolName) {
			return normalize(aggs[i].toolName) < normalize(aggs[j].toolName)
		}
		return aggs[i].order < aggs[j].order
	})

	result := Result{
		ObservedToolCallsConsidered: considered,
		DeclaredToolsConsidered:     declaredConsidered,
	}
	agents := map[string]struct{}{}
	tools := map[string]struct{}{}
	for _, agg := range aggs {
		// A correlation needs at least one observed tool-call or one
		// declared tool. (The "<invocation>" key with neither cannot
		// occur.)
		if len(agg.observed) == 0 && len(agg.declared) == 0 {
			continue
		}
		// A declared entry whose tool name is empty only exists to mark
		// the agent as known; it should not surface as a declared_unused
		// "tool" on its own when no tool-call was observed.
		if len(agg.observed) == 0 && agg.toolName == "" {
			continue
		}
		correlation := buildCorrelation(agg, knownAgents, request.InventoryAvailable, request.DataEventCoverageUnknown)
		result.Correlations = append(result.Correlations, correlation)
		switch correlation.Status {
		case StatusConfirmed:
			result.ConfirmedCount++
		case StatusObservedWithoutDeclaration:
			result.ObservedWithoutDecl++
		case StatusDeclaredUnused:
			result.DeclaredUnusedCount++
		}
		if containsString(correlation.Caveats, CaveatAgentNotInInventory) {
			result.ShadowAgentCount++
		}
		if containsString(correlation.Caveats, CaveatToolNotDeclared) {
			result.UndeclaredToolCount++
		}
		if containsString(correlation.Caveats, CaveatBackingRoleMismatch) {
			result.BackingRoleMismatchCount++
		}
		if containsString(correlation.Caveats, CaveatToolCallFailed) {
			result.FailedToolCallCount++
		}
		agents[normalize(firstNonEmpty(correlation.AgentNodeID, correlation.AgentID))] = struct{}{}
		if strings.TrimSpace(correlation.ToolName) != "" {
			tools[normalize(correlation.AgentNodeID)+"|"+normalize(correlation.ToolName)] = struct{}{}
		}
	}
	result.AgentCount = len(agents)
	result.ToolCount = len(tools)

	if request.DataEventCoverageUnknown && (result.DeclaredUnusedCount > 0 || considered == 0) {
		result.Caveats = append(result.Caveats, "Agent tool-call telemetry is not guaranteed to be complete from the available runtime sources; 'declared_unused' correlations may reflect missing telemetry rather than truly unused tools.")
	}
	if result.ObservedWithoutDecl > 0 {
		result.Caveats = append(result.Caveats, "Some observed tool-calls have no matching inventory declaration. They may be shadow agents or undeclared tools; review them before treating them as expected behavior.")
	}
	return result
}

func buildCorrelation(agg *correlationAgg, knownAgents map[string]struct{}, inventoryAvailable bool, dataEventCoverageUnknown bool) Correlation {
	correlation := Correlation{
		AgentNodeID:       agg.agentNodeID,
		AgentID:           agg.agentID,
		AgentName:         agg.agentName,
		AgentType:         agg.agentType,
		RuntimeVersion:    agg.runtimeVersion,
		ToolName:          agg.toolName,
		ToolTargetRef:     agg.toolTargetRef,
		AccountID:         agg.accountID,
		Region:            agg.region,
		RedactionBoundary: RedactionBoundary,
	}
	correlation.CorrelationID = correlationID(agg)

	eventIDs := map[string]struct{}{}
	backingRoleARNs := map[string]struct{}{}
	backingRoleNodes := map[string]struct{}{}
	targets := map[string]struct{}{}
	targetNodes := map[string]struct{}{}
	outcomes := map[string]struct{}{}
	sessions := map[string]struct{}{}
	evidence := map[string]struct{}{}
	lineageUnresolved := false
	failed := false
	for _, observed := range agg.observed {
		correlation.ObservedCount++
		if id := strings.TrimSpace(observed.EventID); id != "" {
			eventIDs[id] = struct{}{}
		}
		if arn := strings.TrimSpace(observed.BackingRoleARN); arn != "" {
			backingRoleARNs[arn] = struct{}{}
		}
		if node := strings.TrimSpace(observed.BackingRoleNodeID); node != "" {
			backingRoleNodes[node] = struct{}{}
		}
		if target := strings.TrimSpace(observed.TargetResourceARN); target != "" {
			targets[target] = struct{}{}
		}
		if node := strings.TrimSpace(observed.TargetResourceNodeID); node != "" {
			targetNodes[node] = struct{}{}
		}
		if session := strings.TrimSpace(observed.SessionID); session != "" {
			sessions[session] = struct{}{}
		}
		if ref := strings.TrimSpace(observed.EvidenceRef); ref != "" {
			evidence[ref] = struct{}{}
		}
		outcome := normalizeOutcome(observed.Outcome)
		outcomes[outcome] = struct{}{}
		if outcome == OutcomeFailed {
			failed = true
		}
		observedAt := observed.ObservedAt.UTC()
		if !observedAt.IsZero() {
			if correlation.FirstObservedAt.IsZero() || observedAt.Before(correlation.FirstObservedAt) {
				correlation.FirstObservedAt = observedAt
			}
			if observedAt.After(correlation.LastObservedAt) {
				correlation.LastObservedAt = observedAt
			}
		}
		switch strings.TrimSpace(observed.LineageStatus) {
		case "", "resolved":
		default:
			lineageUnresolved = true
		}
	}
	correlation.ObservedEventIDs = sortedKeys(eventIDs)
	correlation.BackingRoleARNs = sortedKeys(backingRoleARNs)
	correlation.BackingRoleNodeIDs = sortedKeys(backingRoleNodes)
	correlation.TargetResourceARNs = sortedKeys(targets)
	correlation.TargetResourceNodeIDs = sortedKeys(targetNodes)
	correlation.Outcomes = sortedKeys(outcomes)
	correlation.SessionIDs = sortedKeys(sessions)

	declaredHere := false
	declaredBackingRoleNode := ""
	declaredBackingRoleARN := ""
	for _, declared := range agg.declared {
		if strings.TrimSpace(declared.ToolName) != "" {
			declaredHere = true
		}
		declaredBackingRoleNode = firstNonEmpty(declaredBackingRoleNode, declared.BackingRoleNodeID)
		declaredBackingRoleARN = firstNonEmpty(declaredBackingRoleARN, declared.BackingRoleARN)
		if ref := strings.TrimSpace(declared.EvidenceRef); ref != "" {
			evidence[ref] = struct{}{}
		}
	}
	correlation.DeclaredInInventory = declaredHere
	correlation.DeclaredBackingRole = firstNonEmpty(declaredBackingRoleARN, declaredBackingRoleNode)
	correlation.DeclaredBackingRoleNode = declaredBackingRoleNode
	correlation.EvidenceRefs = sortedKeys(evidence)

	agentKnown := declaredHere
	if !agentKnown {
		if _, ok := knownAgents[normalize(firstNonEmpty(agg.agentNodeID, agg.agentID))]; ok {
			agentKnown = true
		}
	}

	caveats := map[string]struct{}{}
	switch {
	case correlation.ObservedCount > 0 && declaredHere:
		correlation.Status = StatusConfirmed
		correlation.Confidence = 0.95
		if lineageUnresolved {
			if correlation.Confidence > 0.85 {
				correlation.Confidence = 0.85
			}
			caveats[CaveatLineageUnresolved] = struct{}{}
		}
		if declaredBackingRoleNode != "" && len(correlation.BackingRoleNodeIDs) > 0 && !containsFold(correlation.BackingRoleNodeIDs, declaredBackingRoleNode) {
			caveats[CaveatBackingRoleMismatch] = struct{}{}
			if correlation.Confidence > 0.8 {
				correlation.Confidence = 0.8
			}
		}
		if failed {
			caveats[CaveatToolCallFailed] = struct{}{}
		}
	case correlation.ObservedCount > 0:
		correlation.Status = StatusObservedWithoutDeclaration
		correlation.Confidence = 0.6
		switch {
		case !inventoryAvailable:
			// The inventory was not available to confirm against; do not
			// accuse a possibly-legitimate agent of being a shadow.
			caveats[CaveatInventoryUnavailable] = struct{}{}
		case agentKnown:
			caveats[CaveatToolNotDeclared] = struct{}{}
		default:
			caveats[CaveatAgentNotInInventory] = struct{}{}
		}
		if lineageUnresolved {
			caveats[CaveatLineageUnresolved] = struct{}{}
		}
		if failed {
			caveats[CaveatToolCallFailed] = struct{}{}
		}
	default:
		correlation.Status = StatusDeclaredUnused
		correlation.Confidence = 0.7
		if dataEventCoverageUnknown {
			correlation.Confidence = 0.5
			caveats[CaveatDataEventCoverage] = struct{}{}
		}
	}
	correlation.Caveats = sortedKeys(caveats)
	return correlation
}

func normalizeOutcome(outcome string) string {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case OutcomeSucceeded, "success", "ok":
		return OutcomeSucceeded
	case OutcomeFailed, "failure", "error", "denied":
		return OutcomeFailed
	default:
		return OutcomeUnknown
	}
}

func correlationID(agg *correlationAgg) string {
	agent := firstNonEmpty(agg.agentNodeID, agg.agentID, "unknown-agent")
	tool := firstNonEmpty(agg.toolName, invocationToolToken)
	return fmt.Sprintf("agent_tool|%s|%s", normalize(agent), normalize(tool))
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
