package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/runtime/agentaccess"
)

const (
	awsAgentRuntimeAccessCurrentIssue = 1520
	awsAgentRuntimeAccessVersion      = "aws-agent-runtime-access-correlation-v1"
)

// AWSAgentRuntimeAccessRequest is the operator-facing request. It scopes
// the correlation to a connector/account/region and exposes the runtime
// timeline/query filters the issue requires: by identity (backing role),
// agent, tool, target resource, outcome, and correlation status.
type AWSAgentRuntimeAccessRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Identity     string `json:"identity,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	Tool         string `json:"tool,omitempty"`
	Resource     string `json:"resource,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	Status       string `json:"status,omitempty"`
	// DeliverySource selects the CloudTrail ingestion channel used to
	// observe the agent tool-call events: `lookup_events`, `s3`,
	// `eventbridge`, or `all`. Empty defaults to `all` because agent
	// tool-call telemetry arrives as data events that LookupEvents does
	// not index. Unknown values return HTTP 400.
	DeliverySource string `json:"delivery_source,omitempty"`
}

// AWSAgentRuntimeAccessRecord is one (agent, tool) correlation projected
// for the API/app surface.
type AWSAgentRuntimeAccessRecord struct {
	CorrelationID           string    `json:"correlation_id"`
	AccountID               string    `json:"account_id"`
	Region                  string    `json:"region"`
	AgentNodeID             string    `json:"agent_node_id"`
	AgentID                 string    `json:"agent_id,omitempty"`
	AgentName               string    `json:"agent_name,omitempty"`
	AgentType               string    `json:"agent_type,omitempty"`
	RuntimeVersion          string    `json:"runtime_version,omitempty"`
	ToolName                string    `json:"tool_name,omitempty"`
	ToolTargetRef           string    `json:"tool_target_ref,omitempty"`
	Status                  string    `json:"status"`
	Confidence              float64   `json:"confidence"`
	ObservedCount           int       `json:"observed_count"`
	ObservedEventIDs        []string  `json:"observed_event_ids,omitempty"`
	BackingRoleARNs         []string  `json:"backing_role_arns,omitempty"`
	BackingRoleNodeIDs      []string  `json:"backing_role_node_ids,omitempty"`
	DeclaredBackingRole     string    `json:"declared_backing_role,omitempty"`
	DeclaredBackingRoleNode string    `json:"declared_backing_role_node_id,omitempty"`
	TargetResourceARNs      []string  `json:"target_resource_arns,omitempty"`
	TargetResourceNodeIDs   []string  `json:"target_resource_node_ids,omitempty"`
	Outcomes                []string  `json:"outcomes,omitempty"`
	SessionIDs              []string  `json:"session_ids,omitempty"`
	FirstObservedAt         time.Time `json:"first_observed_at,omitzero"`
	LastObservedAt          time.Time `json:"last_observed_at,omitzero"`
	DeclaredInInventory     bool      `json:"declared_in_inventory"`
	Caveats                 []string  `json:"caveats,omitempty"`
	EvidenceRef             string    `json:"evidence_ref"`
	EvidenceRefs            []string  `json:"evidence_refs,omitempty"`
	NextAction              string    `json:"next_action"`
	RedactionBoundary       string    `json:"redaction_boundary"`
}

// AWSAgentRuntimeAccessRelationship is one correlation graph edge so the
// runtime evidence joins back to the static identity/agent graph.
type AWSAgentRuntimeAccessRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSAgentRuntimeAccessDiagnostic is a structured diagnostic propagated
// from the correlated sources.
type AWSAgentRuntimeAccessDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSAgentRuntimeAccessCoverageGap names a coverage limitation.
type AWSAgentRuntimeAccessCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSAgentRuntimeAccessSummary aggregates the correlation outcome.
type AWSAgentRuntimeAccessSummary struct {
	TotalCorrelations        int            `json:"total_correlations"`
	FilteredCorrelations     int            `json:"filtered_correlations"`
	StatusCounts             map[string]int `json:"status_counts"`
	ConfirmedCount           int            `json:"confirmed_count"`
	ObservedWithoutDeclCount int            `json:"observed_without_declaration_count"`
	DeclaredUnusedCount      int            `json:"declared_unused_count"`
	ShadowAgentCount         int            `json:"shadow_agent_count"`
	UndeclaredToolCount      int            `json:"undeclared_tool_count"`
	BackingRoleMismatchCount int            `json:"backing_role_mismatch_count"`
	FailedToolCallCount      int            `json:"failed_tool_call_count"`
	AgentCount               int            `json:"agent_count"`
	ToolCount                int            `json:"tool_count"`
	ObservedToolCallCount    int            `json:"observed_tool_call_count"`
	DeclaredToolCount        int            `json:"declared_tool_count"`
	RelationshipCount        int            `json:"relationship_count"`
}

// AWSAgentRuntimeAccessResult is the deterministic envelope.
type AWSAgentRuntimeAccessResult struct {
	TenantID           string                              `json:"tenant_id"`
	WorkspaceID        string                              `json:"workspace_id"`
	ProjectID          string                              `json:"project_id"`
	ConnectorID        string                              `json:"connector_id,omitempty"`
	AccountID          string                              `json:"account_id,omitempty"`
	Region             string                              `json:"region,omitempty"`
	ParentIssueNumber  int                                 `json:"parent_issue_number"`
	ParentIssueRef     string                              `json:"parent_issue_ref"`
	CurrentIssueNumber int                                 `json:"current_issue_number"`
	CurrentIssueRef    string                              `json:"current_issue_ref"`
	Version            string                              `json:"version"`
	Status             string                              `json:"status"`
	FixtureState       string                              `json:"fixture_state,omitempty"`
	Confidence         float64                             `json:"confidence"`
	AppliedFilters     map[string]string                   `json:"applied_filters"`
	Summary            AWSAgentRuntimeAccessSummary        `json:"summary"`
	Records            []AWSAgentRuntimeAccessRecord       `json:"records"`
	Relationships      []AWSAgentRuntimeAccessRelationship `json:"relationships"`
	Caveats            []string                            `json:"caveats"`
	FailureReasons     []string                            `json:"failure_reasons"`
	RemediationHints   []string                            `json:"remediation_hints"`
	EvidenceLinks      []string                            `json:"evidence_links"`
	CoverageGaps       []AWSAgentRuntimeAccessCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSAgentRuntimeAccessDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                           `json:"generated_at"`
	UpdatedAt          time.Time                           `json:"updated_at"`
}

// GetAWSAgentRuntimeAccess correlates observed agent runtime / tool-call
// events with the static AI-agent inventory, returning a queryable
// correlation timeline.
func (s *Service) GetAWSAgentRuntimeAccess(ctx context.Context, workspaceID string, projectID string, request AWSAgentRuntimeAccessRequest) (AWSAgentRuntimeAccessResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSAgentRuntimeAccessResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSAgentRuntimeAccessResult{}, err
	}
	now := s.Now().UTC()

	fixtureState := normalizeAWSAgentRuntimeAccessFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSAgentRuntimeAccessResult{}, ErrInvalidAWSConnectionRequest
	}

	// Agent tool-call telemetry arrives as CloudTrail data events, which
	// LookupEvents does not index. Default to `all` so the correlation can
	// observe the events it correlates; operators can pin a channel.
	deliverySource := strings.TrimSpace(request.DeliverySource)
	if deliverySource == "" {
		deliverySource = "all"
	}
	var deliveryErr error
	deliverySource, deliveryErr = normalizeDeliverySource(deliverySource)
	if deliveryErr != nil {
		return AWSAgentRuntimeAccessResult{}, deliveryErr
	}

	useLive := awsAgentRuntimeAccessHasLiveRuntimeFactory(s, deliverySource) &&
		hasConnection && connection.Connected &&
		strings.TrimSpace(request.FixtureState) == "" &&
		awsConnectorHasRuntimeEvidence(connection)

	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")

	var (
		observed           []agentaccess.ObservedToolCall
		declared           []agentaccess.DeclaredTool
		knownAgents        []string
		inventoryAvailable bool
		diagnostics        []AWSAgentRuntimeAccessDiagnostic
		coverageGaps       []AWSAgentRuntimeAccessCoverageGap
		failures           []string
		remediations       []string
		sourceStatus       string
		coverageUnknown    bool
	)

	if useLive {
		observed, declared, knownAgents, inventoryAvailable, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown, err =
			s.awsAgentRuntimeAccessLiveInputs(ctx, workspaceID, projectID, connectorID, accountID, region, deliverySource)
		if err != nil {
			return AWSAgentRuntimeAccessResult{}, err
		}
		fixtureState = ""
	} else if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		observed, declared, knownAgents, inventoryAvailable, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown =
			awsAgentRuntimeAccessLiveUnavailableInputs(deliverySource)
		fixtureState = ""
	} else {
		observed, declared, knownAgents, inventoryAvailable, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown =
			awsAgentRuntimeAccessFixtureInputs(accountID, region, fixtureState, now)
	}

	correlationResult := agentaccess.Correlate(agentaccess.CorrelateRequest{
		AccountID:                accountID,
		Region:                   region,
		Observed:                 observed,
		Declared:                 declared,
		KnownAgentNodeIDs:        knownAgents,
		InventoryAvailable:       inventoryAvailable,
		DataEventCoverageUnknown: coverageUnknown,
	})

	records := awsAgentRuntimeAccessRecords(correlationResult.Correlations)
	filtered, applied := filterAWSAgentRuntimeAccessRecords(records, request)
	relationships := awsAgentRuntimeAccessRelationships(filtered)
	summary := summarizeAWSAgentRuntimeAccess(correlationResult, records, filtered, relationships)

	status, confidence := summarizeAWSAgentRuntimeAccessStatus(sourceStatus, filtered, diagnostics)
	caveats := dedupeStrings(correlationResult.Caveats)

	return AWSAgentRuntimeAccessResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsAgentRuntimeAccessCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsAgentRuntimeAccessCurrentIssue),
		Version:            awsAgentRuntimeAccessVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		AppliedFilters:     applied,
		Summary:            summary,
		Records:            filtered,
		Relationships:      relationships,
		Caveats:            caveats,
		FailureReasons:     emptyStrings(dedupeStrings(failures)),
		RemediationHints:   emptyStrings(dedupeStrings(remediations)),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsAgentRuntimeAccessCurrentIssue),
			awsIssueURL(awsRuntimeEventsCurrentIssue),
			awsIssueURL(awsAIAgentIdentityCurrentIssue),
			"/docs/aws-agent-runtime-access",
			"/docs/aws-runtime-events",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSAgentRuntimeAccessFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "ready":
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsAgentRuntimeAccessHasLiveRuntimeFactory(s *Service, deliverySource string) bool {
	switch strings.TrimSpace(deliverySource) {
	case "lookup_events":
		return s.AWSCloudTrailLookupEventsFactory != nil
	case "s3", "eventbridge", "all":
		return s.AWSCloudTrailDeliveryFactory != nil
	default:
		return false
	}
}

func awsAgentRuntimeAccessLiveUnavailableInputs(deliverySource string) ([]agentaccess.ObservedToolCall, []agentaccess.DeclaredTool, []string, bool, []AWSAgentRuntimeAccessDiagnostic, []AWSAgentRuntimeAccessCoverageGap, []string, []string, string, bool) {
	source := strings.TrimSpace(deliverySource)
	if source == "" {
		source = "all"
	}
	diagnostics := []AWSAgentRuntimeAccessDiagnostic{{
		Collector:   agentaccess.CollectorName,
		SourceID:    "runtime_delivery:" + source,
		Code:        "runtime_delivery_unavailable",
		Message:     "Live agent tool-call telemetry is unavailable for this connector; fixture correlations were suppressed.",
		Remediation: "Configure the selected CloudTrail delivery channel and grant the runtime_evidence capability, or request a fixture_state explicitly for demo data.",
		Retryable:   true,
	}}
	coverageGaps := []AWSAgentRuntimeAccessCoverageGap{{
		Capability:  "agent_tool_call_delivery",
		Status:      "delivery_unavailable",
		Reason:      "The selected runtime delivery source is not available, so real agent tool-call events cannot be correlated.",
		Remediation: "Wire CloudTrail S3/EventBridge delivery for this connector and grant runtime_evidence before relying on live correlation output.",
	}}
	failures := []string{"agent tool-call runtime delivery is unavailable; fixture correlations suppressed"}
	remediations := []string{"Configure CloudTrail data-event delivery or request fixture_state explicitly for sample data."}
	return nil, nil, nil, false, diagnostics, coverageGaps, failures, remediations, awsPlatformDependencyStatusDegraded, true
}

// awsAgentRuntimeAccessLiveInputs composes the runtime-events and AI-agent
// inventory services into the engine's observed/declared inputs. The
// inventory reader is fixture-shaped today, so live mode forces an empty
// inventory state and reports it as unavailable — the engine then surfaces
// observed tool-calls with a neutral "inventory unavailable" caveat rather
// than mislabeling real agents as shadow agents.
func (s *Service) awsAgentRuntimeAccessLiveInputs(ctx context.Context, workspaceID, projectID, connectorID, accountID, region, deliverySource string) ([]agentaccess.ObservedToolCall, []agentaccess.DeclaredTool, []string, bool, []AWSAgentRuntimeAccessDiagnostic, []AWSAgentRuntimeAccessCoverageGap, []string, []string, string, bool, error) {
	var (
		diagnostics  []AWSAgentRuntimeAccessDiagnostic
		coverageGaps []AWSAgentRuntimeAccessCoverageGap
		failures     []string
		remediations []string
	)

	runtime, err := s.GetAWSRuntimeEvents(ctx, workspaceID, projectID, AWSRuntimeEventRequest{
		ConnectorID:    connectorID,
		AccountID:      accountID,
		Region:         region,
		DeliverySource: deliverySource,
	})
	if err != nil {
		return nil, nil, nil, false, nil, nil, nil, nil, "", false, fmt.Errorf("correlate runtime events: %w", err)
	}
	inventory, err := s.GetAWSAIAgentIdentityInventory(ctx, workspaceID, projectID, AWSAIAgentIdentityInventoryRequest{
		ConnectorID:  connectorID,
		FixtureState: awsRuntimeCorrelationLiveNoStaticState,
	})
	if err != nil {
		return nil, nil, nil, false, nil, nil, nil, nil, "", false, fmt.Errorf("correlate agent inventory: %w", err)
	}

	observed := observedAgentToolCallsFromRuntimeRecords(runtime.Records)
	declared, knownAgents := declaredToolsFromAgentInventory(inventory.Records)
	inventoryAvailable := len(inventory.Records) > 0

	for _, diag := range runtime.Diagnostics {
		diagnostics = append(diagnostics, AWSAgentRuntimeAccessDiagnostic(diag))
	}
	for _, gap := range runtime.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSAgentRuntimeAccessCoverageGap(gap))
	}
	failures = append(failures, runtime.FailureReasons...)
	remediations = append(remediations, runtime.RemediationHints...)

	// A blocked runtime source (or a degraded one that projected no agent
	// tool-calls) means the observed side is missing, not empty — drop the
	// declared side so declared tools are not surfaced as unused work.
	if runtime.Status == awsPlatformDependencyStatusBlocked || (runtime.Status == awsPlatformDependencyStatusDegraded && len(observed) == 0) {
		observed = nil
		declared = nil
		knownAgents = nil
	}

	sourceStatus := runtime.Status
	return observed, declared, knownAgents, inventoryAvailable, diagnostics, coverageGaps, failures, remediations, sourceStatus, true, nil
}

// observedAgentToolCallsFromRuntimeRecords projects agent-tool runtime
// event records into engine observed tool-calls. Other event types are
// dropped. The backing role is the actor identity that ran the agent.
func observedAgentToolCallsFromRuntimeRecords(records []AWSRuntimeEventRecord) []agentaccess.ObservedToolCall {
	out := []agentaccess.ObservedToolCall{}
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSpace(record.EventType), "agent-tool") {
			continue
		}
		if strings.TrimSpace(record.AgentNodeID) == "" && strings.TrimSpace(record.AgentID) == "" {
			continue
		}
		out = append(out, agentaccess.ObservedToolCall{
			EventID:              record.EventID,
			AgentNodeID:          record.AgentNodeID,
			AgentID:              record.AgentID,
			ToolName:             record.ToolName,
			ToolTargetRef:        record.ToolTargetRef,
			BackingRoleARN:       firstNonEmptyAWSValue(record.Session.SessionIssuerARN, record.ActorPrincipalARN),
			BackingRoleNodeID:    record.ActorIdentityNodeID,
			TargetResourceARN:    record.TargetResourceARN,
			TargetResourceNodeID: record.ResourceNodeID,
			// The runtime-event contract does not yet carry an explicit
			// tool-call success/failure outcome (it requires error-code
			// extraction in the ingestion layer), so live outcome is
			// unknown — surfaced as a coverage gap, never fabricated.
			Outcome:       agentaccess.OutcomeUnknown,
			SessionID:     record.Session.SessionID,
			AccountID:     record.AccountID,
			Region:        record.Region,
			LineageStatus: record.Session.LineageStatus,
			ObservedAt:    record.ObservedAt,
			EvidenceRef:   record.EvidenceRef,
		})
	}
	return out
}

// declaredToolsFromAgentInventory projects AI-agent inventory records into
// declared (agent, tool) pairs, and returns the set of known agent node
// ids (including agents that declare no tools).
func declaredToolsFromAgentInventory(records []AWSAIAgentIdentityRecord) ([]agentaccess.DeclaredTool, []string) {
	out := []agentaccess.DeclaredTool{}
	known := make([]string, 0, len(records))
	for _, record := range records {
		agentNode := strings.TrimSpace(record.AgentNodeID)
		if agentNode == "" && strings.TrimSpace(record.AgentID) == "" {
			continue
		}
		if agentNode != "" {
			known = append(known, agentNode)
		}
		base := agentaccess.DeclaredTool{
			AgentNodeID:       record.AgentNodeID,
			AgentID:           record.AgentID,
			AgentName:         record.AgentName,
			AgentType:         record.AgentType,
			RuntimeVersion:    record.RuntimeVersion,
			BackingRoleARN:    record.RuntimeRoleARN,
			BackingRoleNodeID: record.RuntimeRoleNodeID,
			AccountID:         record.AccountID,
			Region:            record.Region,
			Confidence:        record.Confidence,
			EvidenceRef:       record.EvidenceRef,
		}
		if len(record.ToolNames) == 0 {
			// Mark the agent as known with an empty-tool declaration so a
			// known agent invoking an undeclared tool is not mislabeled as
			// a shadow agent.
			out = append(out, base)
			continue
		}
		for i, tool := range record.ToolNames {
			declared := base
			declared.ToolName = strings.TrimSpace(tool)
			if i < len(record.ToolTargetRefs) {
				declared.ToolTargetRef = strings.TrimSpace(record.ToolTargetRefs[i])
			}
			out = append(out, declared)
		}
	}
	return out, known
}

func awsAgentRuntimeAccessRecords(correlations []agentaccess.Correlation) []AWSAgentRuntimeAccessRecord {
	out := make([]AWSAgentRuntimeAccessRecord, 0, len(correlations))
	for _, correlation := range correlations {
		out = append(out, AWSAgentRuntimeAccessRecord{
			CorrelationID:           correlation.CorrelationID,
			AccountID:               correlation.AccountID,
			Region:                  correlation.Region,
			AgentNodeID:             correlation.AgentNodeID,
			AgentID:                 correlation.AgentID,
			AgentName:               correlation.AgentName,
			AgentType:               correlation.AgentType,
			RuntimeVersion:          correlation.RuntimeVersion,
			ToolName:                correlation.ToolName,
			ToolTargetRef:           correlation.ToolTargetRef,
			Status:                  correlation.Status,
			Confidence:              correlation.Confidence,
			ObservedCount:           correlation.ObservedCount,
			ObservedEventIDs:        correlation.ObservedEventIDs,
			BackingRoleARNs:         correlation.BackingRoleARNs,
			BackingRoleNodeIDs:      correlation.BackingRoleNodeIDs,
			DeclaredBackingRole:     correlation.DeclaredBackingRole,
			DeclaredBackingRoleNode: correlation.DeclaredBackingRoleNode,
			TargetResourceARNs:      correlation.TargetResourceARNs,
			TargetResourceNodeIDs:   correlation.TargetResourceNodeIDs,
			Outcomes:                correlation.Outcomes,
			SessionIDs:              correlation.SessionIDs,
			FirstObservedAt:         correlation.FirstObservedAt,
			LastObservedAt:          correlation.LastObservedAt,
			DeclaredInInventory:     correlation.DeclaredInInventory,
			Caveats:                 correlation.Caveats,
			EvidenceRef:             fmt.Sprintf("runtime-correlation://%s", correlation.CorrelationID),
			EvidenceRefs:            correlation.EvidenceRefs,
			NextAction:              awsAgentRuntimeAccessNextAction(correlation.Status),
			RedactionBoundary:       correlation.RedactionBoundary,
		})
	}
	return out
}

func awsAgentRuntimeAccessNextAction(status string) string {
	switch status {
	case agentaccess.StatusConfirmed:
		return "Confirm the observed tool-call matches an expected agent workflow before relying on it for remediation."
	case agentaccess.StatusObservedWithoutDeclaration:
		return "Investigate the observed tool-call — confirm the agent and tool are expected, or treat it as a shadow agent / undeclared tool."
	case agentaccess.StatusDeclaredUnused:
		return "Review the declared but unused tool for least-privilege; confirm tool-call telemetry coverage before removing it."
	default:
		return "Correlate runtime evidence with the agent inventory graph."
	}
}

func filterAWSAgentRuntimeAccessRecords(records []AWSAgentRuntimeAccessRecord, request AWSAgentRuntimeAccessRequest) ([]AWSAgentRuntimeAccessRecord, map[string]string) {
	filters := map[string]string{
		"account_id": strings.TrimSpace(request.AccountID),
		"region":     strings.TrimSpace(request.Region),
		"identity":   strings.TrimSpace(request.Identity),
		"agent_id":   strings.TrimSpace(request.AgentID),
		"tool":       strings.TrimSpace(request.Tool),
		"resource":   strings.TrimSpace(request.Resource),
		"outcome":    normalizeAWSRuntimeEventFilterToken(request.Outcome),
		"status":     normalizeAWSRuntimeEventFilterToken(request.Status),
	}
	for key, value := range filters {
		token := strings.ToLower(strings.TrimSpace(value))
		if token == "" || token == "all" {
			delete(filters, key)
		}
	}
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSAgentRuntimeAccessRecord, 0, len(records))
	for _, record := range records {
		if filters["account_id"] != "" && filters["account_id"] != record.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], record.Region) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(record.Status) {
			continue
		}
		if filters["outcome"] != "" && !awsAgentRuntimeAccessHasOutcome(record, filters["outcome"]) {
			continue
		}
		if filters["agent_id"] != "" && !awsRuntimeEventMatchesAny(filters["agent_id"], record.AgentID, record.AgentNodeID, record.AgentName) {
			continue
		}
		if filters["tool"] != "" && !awsRuntimeEventMatchesAny(filters["tool"], record.ToolName, record.ToolTargetRef) {
			continue
		}
		if filters["identity"] != "" {
			// Match against both observed backing roles and the inventory's
			// declared backing role so a `?identity=<role>` filter still
			// surfaces declared_unused tools for that role (where no runtime
			// event was observed). Without this, the advertised backing-role
			// query drops every unused declared tool — exactly the
			// least-privilege cleanup case the filter is for.
			identityValues := append([]string{}, record.BackingRoleARNs...)
			identityValues = append(identityValues, record.BackingRoleNodeIDs...)
			if record.DeclaredBackingRole != "" {
				identityValues = append(identityValues, record.DeclaredBackingRole)
			}
			if record.DeclaredBackingRoleNode != "" {
				identityValues = append(identityValues, record.DeclaredBackingRoleNode)
			}
			if !awsRuntimeEventMatchesAny(filters["identity"], identityValues...) {
				continue
			}
		}
		if filters["resource"] != "" && !awsRuntimeEventMatchesAny(filters["resource"], append(append([]string{}, record.TargetResourceARNs...), record.TargetResourceNodeIDs...)...) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered, applied
}

func awsAgentRuntimeAccessHasOutcome(record AWSAgentRuntimeAccessRecord, outcome string) bool {
	for _, value := range record.Outcomes {
		if normalizeAWSRuntimeEventFilterToken(value) == outcome {
			return true
		}
	}
	return false
}

func awsAgentRuntimeAccessRelationships(records []AWSAgentRuntimeAccessRecord) []AWSAgentRuntimeAccessRelationship {
	out := []AWSAgentRuntimeAccessRelationship{}
	for _, record := range records {
		if record.AgentNodeID == "" {
			continue
		}
		edgeType := "runtime_tool_call_correlation"
		switch record.Status {
		case agentaccess.StatusConfirmed:
			edgeType = "confirmed_agent_tool_call"
		case agentaccess.StatusObservedWithoutDeclaration:
			edgeType = "observed_tool_call_without_declaration"
		case agentaccess.StatusDeclaredUnused:
			edgeType = "unused_declared_tool"
		}
		roleNodes := append([]string{}, record.BackingRoleNodeIDs...)
		if record.Status == agentaccess.StatusDeclaredUnused && strings.TrimSpace(record.DeclaredBackingRoleNode) != "" {
			roleNodes = append(roleNodes, record.DeclaredBackingRoleNode)
		}
		seenRoleNodes := map[string]struct{}{}
		for _, roleNode := range roleNodes {
			roleNode = strings.TrimSpace(roleNode)
			if roleNode == "" {
				continue
			}
			roleKey := strings.ToLower(roleNode)
			if _, ok := seenRoleNodes[roleKey]; ok {
				continue
			}
			seenRoleNodes[roleKey] = struct{}{}
			out = append(out, AWSAgentRuntimeAccessRelationship{
				Type:        edgeType,
				FromNodeID:  roleNode,
				ToNodeID:    record.AgentNodeID,
				EvidenceRef: record.EvidenceRef,
			})
		}
		// Prefer the graph resource node id from the runtime-event contract
		// so edges join to the same node other AWS graph edges key on; fall
		// back to the raw ARN only when no node id was projected.
		targetNodes := record.TargetResourceNodeIDs
		if len(targetNodes) == 0 {
			targetNodes = record.TargetResourceARNs
		}
		for _, target := range targetNodes {
			if strings.TrimSpace(target) == "" {
				continue
			}
			out = append(out, AWSAgentRuntimeAccessRelationship{
				Type:        "agent_tool_targeted_resource",
				FromNodeID:  record.AgentNodeID,
				ToNodeID:    target,
				EvidenceRef: record.EvidenceRef,
			})
		}
	}
	return out
}

func summarizeAWSAgentRuntimeAccess(correlation agentaccess.Result, allRecords []AWSAgentRuntimeAccessRecord, filtered []AWSAgentRuntimeAccessRecord, relationships []AWSAgentRuntimeAccessRelationship) AWSAgentRuntimeAccessSummary {
	statusCounts := map[string]int{}
	for _, record := range allRecords {
		statusCounts[record.Status]++
	}
	return AWSAgentRuntimeAccessSummary{
		TotalCorrelations:        len(allRecords),
		FilteredCorrelations:     len(filtered),
		StatusCounts:             statusCounts,
		ConfirmedCount:           correlation.ConfirmedCount,
		ObservedWithoutDeclCount: correlation.ObservedWithoutDecl,
		DeclaredUnusedCount:      correlation.DeclaredUnusedCount,
		ShadowAgentCount:         correlation.ShadowAgentCount,
		UndeclaredToolCount:      correlation.UndeclaredToolCount,
		BackingRoleMismatchCount: correlation.BackingRoleMismatchCount,
		FailedToolCallCount:      correlation.FailedToolCallCount,
		AgentCount:               correlation.AgentCount,
		ToolCount:                correlation.ToolCount,
		ObservedToolCallCount:    correlation.ObservedToolCallsConsidered,
		DeclaredToolCount:        correlation.DeclaredToolsConsidered,
		RelationshipCount:        len(relationships),
	}
}

func summarizeAWSAgentRuntimeAccessStatus(sourceStatus string, filtered []AWSAgentRuntimeAccessRecord, diagnostics []AWSAgentRuntimeAccessDiagnostic) (string, float64) {
	switch sourceStatus {
	case awsPlatformDependencyStatusBlocked:
		return awsPlatformDependencyStatusBlocked, 0
	case awsPlatformDependencyStatusDegraded:
		return awsPlatformDependencyStatusDegraded, 0.7
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusDegraded, 0.5
	}
	if len(diagnostics) > 0 {
		return awsPlatformDependencyStatusDegraded, 0.8
	}
	return awsPlatformDependencyStatusReady, 0.92
}
