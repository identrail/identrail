package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	awsBedrockAgentsCurrentIssue  = 1506
	awsBedrockAgentsVersion       = "aws-bedrock-agents-collector-v1"
	awsBedrockAgentsCollectorName = "bedrock_agents"
	awsBedrockAgentsServiceName   = "bedrock"
	awsBedrockAgentType           = "bedrock_agent"
	awsBedrockAgentProvider       = "amazon-bedrock"
)

// AWSBedrockAgentsInventoryRequest filters the Bedrock Agents inventory.
type AWSBedrockAgentsInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	// AgentID filters records to one Bedrock agent id.
	AgentID string `json:"agent_id,omitempty"`
	// Identity is a case-insensitive substring filter over the agent name, ARN,
	// runtime role ARN, and runtime role name.
	Identity string `json:"identity,omitempty"`
	// Provider filters records to one declared provider classification (for
	// example amazon-bedrock).
	Provider string `json:"provider,omitempty"`
}

// AWSBedrockAgentCoverageGap names a deliberate boundary of the collector.
type AWSBedrockAgentCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSBedrockAgentRecord is one Bedrock agent identity with derived counts and
// the operator's next action. Metadata-only: instructions, prompt overrides,
// completions, embeddings, and memory contents are never present here.
type AWSBedrockAgentRecord struct {
	AccountID               string            `json:"account_id"`
	Region                  string            `json:"region"`
	Service                 string            `json:"service"`
	AgentID                 string            `json:"agent_id"`
	AgentARN                string            `json:"agent_arn,omitempty"`
	AgentName               string            `json:"agent_name"`
	AgentType               string            `json:"agent_type"`
	Provider                string            `json:"provider,omitempty"`
	ModelID                 string            `json:"model_id,omitempty"`
	RuntimeRoleARN          string            `json:"runtime_role_arn,omitempty"`
	RuntimeRoleName         string            `json:"runtime_role_name,omitempty"`
	RuntimeRoleAccountID    string            `json:"runtime_role_account_id,omitempty"`
	ToolNames               []string          `json:"tool_names"`
	ToolCount               int               `json:"tool_count"`
	MemoryEnabled           bool              `json:"memory_enabled"`
	MemoryStoreRefs         []string          `json:"memory_store_refs"`
	CapabilityNames         []string          `json:"capability_names"`
	CredentialReferenceRefs []string          `json:"credential_reference_refs"`
	GuardrailID             string            `json:"guardrail_id,omitempty"`
	SensitiveBoundary       string            `json:"sensitive_boundary"`
	CoverageStatus          string            `json:"coverage_status"`
	CoverageReason          string            `json:"coverage_reason,omitempty"`
	Source                  string            `json:"source"`
	EvidenceRef             string            `json:"evidence_ref"`
	AgentNodeID             string            `json:"agent_node_id"`
	RuntimeRoleNodeID       string            `json:"runtime_role_node_id,omitempty"`
	RelationshipTypes       []string          `json:"relationship_types"`
	Confidence              float64           `json:"confidence"`
	NextAction              string            `json:"next_action"`
	CollectedAt             time.Time         `json:"collected_at"`
	Status                  string            `json:"status"`
	Tags                    map[string]string `json:"tags,omitempty"`
}

// AWSBedrockAgentRelation is one graph edge anchored at a Bedrock agent.
type AWSBedrockAgentRelation struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSBedrockAgentDiagnostic is one collector diagnostic exposed to operators.
type AWSBedrockAgentDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSBedrockAgentsInventoryResult is the operator-facing Bedrock Agents view.
type AWSBedrockAgentsInventoryResult struct {
	TenantID           string                       `json:"tenant_id"`
	WorkspaceID        string                       `json:"workspace_id"`
	ProjectID          string                       `json:"project_id"`
	ConnectorID        string                       `json:"connector_id,omitempty"`
	AccountID          string                       `json:"account_id,omitempty"`
	Region             string                       `json:"region,omitempty"`
	ParentIssueNumber  int                          `json:"parent_issue_number"`
	ParentIssueRef     string                       `json:"parent_issue_ref"`
	CurrentIssueNumber int                          `json:"current_issue_number"`
	CurrentIssueRef    string                       `json:"current_issue_ref"`
	Version            string                       `json:"version"`
	Status             string                       `json:"status"`
	FixtureState       string                       `json:"fixture_state"`
	Confidence         float64                      `json:"confidence"`
	AgentCount         int                          `json:"agent_count"`
	FilteredAgentCount int                          `json:"filtered_agent_count"`
	GuardrailCount     int                          `json:"guardrail_count"`
	KnowledgeBaseCount int                          `json:"knowledge_base_count"`
	ToolCount          int                          `json:"tool_count"`
	CredentialRefCount int                          `json:"credential_reference_count"`
	RuntimeRoleCount   int                          `json:"runtime_role_count"`
	ModelCount         int                          `json:"model_count"`
	ProviderBreakdown  map[string]int               `json:"provider_breakdown"`
	StatusBreakdown    map[string]int               `json:"status_breakdown"`
	RelationshipCount  int                          `json:"relationship_count"`
	FailureReasons     []string                     `json:"failure_reasons"`
	RemediationHints   []string                     `json:"remediation_hints"`
	EvidenceLinks      []string                     `json:"evidence_links"`
	CoverageGaps       []AWSBedrockAgentCoverageGap `json:"coverage_gaps"`
	Records            []AWSBedrockAgentRecord      `json:"records"`
	Relationships      []AWSBedrockAgentRelation    `json:"relationships"`
	Diagnostics        []AWSBedrockAgentDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
}

// GetAWSBedrockAgentsInventory returns the project-scoped Bedrock Agents
// inventory. The collector vocabulary mirrors the production Bedrock Agents
// collector in internal/providers/aws so contract tests verify the shared
// boundary stays metadata-only.
func (s *Service) GetAWSBedrockAgentsInventory(ctx context.Context, workspaceID string, projectID string, request AWSBedrockAgentsInventoryRequest) (AWSBedrockAgentsInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSBedrockAgentsInventoryResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSBedrockAgentsInventoryResult{}, err
	}
	return buildAWSBedrockAgentsInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSBedrockAgentsInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSBedrockAgentsInventoryRequest, checkedAt time.Time) (AWSBedrockAgentsInventoryResult, error) {
	fixtureState := normalizeAWSBedrockAgentsFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSBedrockAgentsInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	if !validAWSBedrockAgentsProviderFilter(request.Provider) {
		return AWSBedrockAgentsInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")

	records, diagnostics, gaps := awsBedrockAgentsFixtureRecords(scope, project, connectorID, accountID, region, fixtureState, checkedAt)
	// Validate each record against the shared collector contract so the API
	// boundary stays compatible with the production collector.
	for _, record := range records {
		if err := awscontract.ValidateServiceCollectorRecord(awscontract.ServiceCollectorRecord{
			TenantID:      scope.TenantID,
			WorkspaceID:   project.WorkspaceID,
			ProjectID:     project.ProjectID,
			ConnectorID:   connectorID,
			AccountID:     record.AccountID,
			Region:        record.Region,
			Service:       record.Service,
			WorkloadID:    record.AgentID,
			WorkloadType:  record.AgentType,
			WorkloadName:  record.AgentName,
			RoleARN:       record.RuntimeRoleARN,
			Source:        record.Source,
			EvidenceRef:   record.EvidenceRef,
			Confidence:    record.Confidence,
			ScanID:        "aws-bedrock-agents-fixture",
			CollectorName: awsBedrockAgentsCollectorName,
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSBedrockAgentsInventoryResult{}, fmt.Errorf("validate bedrock agent contract record %s: %w", record.AgentID, err)
		}
	}
	filtered := filterAWSBedrockAgentRecords(records, request)
	// Relationships are derived from the filtered records so a narrowed
	// agent_id/identity/provider filter cannot leak edges anchored at agents the
	// operator deliberately excluded.
	relationships := awsBedrockAgentRelationships(filtered)
	// Scope per-agent diagnostics and the response-level status to the records
	// the response actually returns. Global diagnostics (no SourceID — for
	// example permission_denied or list_failed) stay included because they
	// describe the whole scan, not one agent. Aggregate counts above stay
	// inventory-wide so dashboards keep their totals.
	scopedDiagnostics := scopeAWSBedrockAgentDiagnosticsToRecords(diagnostics, filtered)
	status, confidence, failures, remediations := summarizeAWSBedrockAgentsInventory(fixtureState, scopedDiagnostics, filtered)

	return AWSBedrockAgentsInventoryResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsBedrockAgentsCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsBedrockAgentsCurrentIssue),
		Version:            awsBedrockAgentsVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		AgentCount:         len(records),
		FilteredAgentCount: len(filtered),
		GuardrailCount:     countAWSBedrockAgentField(records, func(r AWSBedrockAgentRecord) bool { return strings.TrimSpace(r.GuardrailID) != "" }),
		KnowledgeBaseCount: countAWSBedrockAgentField(records, func(r AWSBedrockAgentRecord) bool { return r.MemoryEnabled }),
		ToolCount:          listCountAWSBedrockAgents(records, func(r AWSBedrockAgentRecord) []string { return r.ToolNames }),
		CredentialRefCount: listCountAWSBedrockAgents(records, func(r AWSBedrockAgentRecord) []string { return r.CredentialReferenceRefs }),
		RuntimeRoleCount:   uniqueCountAWSBedrockAgents(records, func(r AWSBedrockAgentRecord) string { return r.RuntimeRoleARN }),
		ModelCount:         uniqueCountAWSBedrockAgents(records, func(r AWSBedrockAgentRecord) string { return r.ModelID }),
		ProviderBreakdown:  breakdownAWSBedrockAgents(records, func(r AWSBedrockAgentRecord) string { return r.Provider }),
		StatusBreakdown:    breakdownAWSBedrockAgents(records, func(r AWSBedrockAgentRecord) string { return r.Status }),
		RelationshipCount:  len(relationships),
		FailureReasons:     failures,
		RemediationHints:   remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsBedrockAgentsCurrentIssue),
			awsIssueURL(1505),
			"/docs/aws-bedrock-agents",
			"/docs/aws-ai-agent-identities",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  gaps,
		Records:       filtered,
		Relationships: relationships,
		Diagnostics:   awsBedrockAgentDiagnostics(scopedDiagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

// scopeAWSBedrockAgentDiagnosticsToRecords drops per-agent diagnostics whose
// SourceID is not in the filtered record set so a narrowed view does not
// report unrelated failures. Global diagnostics (no SourceID, or a SourceID
// that is not an agent id at all — for example list-level permission_denied
// scoped to "service=bedrock|...") stay included because they describe the
// whole scan rather than one agent.
func scopeAWSBedrockAgentDiagnosticsToRecords(diagnostics []providers.SourceError, filtered []AWSBedrockAgentRecord) []providers.SourceError {
	if len(diagnostics) == 0 {
		return diagnostics
	}
	visibleAgentIDs := map[string]struct{}{}
	for _, record := range filtered {
		if id := strings.TrimSpace(record.AgentID); id != "" {
			visibleAgentIDs[id] = struct{}{}
		}
	}
	scoped := make([]providers.SourceError, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		sourceID := strings.TrimSpace(diagnostic.SourceID)
		if sourceID == "" {
			// Scan-level diagnostic; keep it.
			scoped = append(scoped, diagnostic)
			continue
		}
		if _, isAgent := visibleAgentIDs[sourceID]; isAgent {
			scoped = append(scoped, diagnostic)
			continue
		}
		// If the source id is not an agent id at all (for example the
		// "service=bedrock|account=...|region=...|source=list" scope used by
		// list-level failures) keep it so operators still see scan-wide
		// errors. We detect agent-scoped diagnostics by checking whether the
		// id matches any record's agent_id in the *unfiltered* set; if the
		// id belongs to an agent that was filtered out, drop it.
		if isAgentScopedSourceID(sourceID, filtered) {
			// id looks like an agent id (matched the visibleAgentIDs check above) — already handled.
			continue
		}
		scoped = append(scoped, diagnostic)
	}
	return scoped
}

// isAgentScopedSourceID reports whether the source id is a Bedrock agent id
// shape (short alphanumeric, no pipes / slashes) so non-agent scoped
// diagnostics stay visible. We keep this narrow because agent ids in Bedrock
// are short alphanumerics; scan-wide ids embed structure markers.
func isAgentScopedSourceID(sourceID string, _ []AWSBedrockAgentRecord) bool {
	if sourceID == "" {
		return false
	}
	return !strings.ContainsAny(sourceID, "|/=:")
}

func awsBedrockAgentsFixtureRecords(scope db.Scope, project db.TenancyProject, connectorID, accountID, region, fixtureState string, checkedAt time.Time) ([]AWSBedrockAgentRecord, []providers.SourceError, []AWSBedrockAgentCoverageGap) {
	gaps := []AWSBedrockAgentCoverageGap{
		{
			Capability:  "prompt_and_completion_contents",
			Status:      "intentionally_not_collected",
			Reason:      "The collector reads agent metadata, role bindings, tool names, knowledge-base IDs, and guardrail IDs only. Instructions, prompt overrides, completions, and memory contents are never read.",
			Remediation: "Operator-approved follow-up collection is required if any prompt or completion text must be inspected.",
		},
		{
			Capability:  "knowledge_base_contents",
			Status:      "intentionally_not_collected",
			Reason:      "Knowledge bases are linked by ID only; documents, embeddings, and index payloads stay inside the owning service.",
			Remediation: "Inspect knowledge bases through the owning service (Bedrock console, S3, Aurora) outside Identrail.",
		},
	}

	switch fixtureState {
	case "empty":
		return []AWSBedrockAgentRecord{}, []providers.SourceError{}, gaps
	case "permission_denied":
		return []AWSBedrockAgentRecord{}, []providers.SourceError{{
			Collector: awsBedrockAgentsCollectorName,
			SourceID:  fmt.Sprintf("service=%s|account=%s|region=%s|source=list", awsBedrockAgentsServiceName, accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only Bedrock agent metadata permission is missing (bedrock:ListAgents or bedrock:GetAgent denied).",
			Retryable: false,
		}}, gaps
	}

	partition := awsBedrockAgentsPartitionForRegion(region)
	primary := buildAWSBedrockAgentFixtureRecord(scope, project, connectorID, accountID, region, partition, "PAYMENTSAGENT1", "payments-risk-agent", checkedAt, func(r *AWSBedrockAgentRecord) {
		r.RuntimeRoleARN = fmt.Sprintf("arn:%s:iam::%s:role/bedrock-payments-risk-agent", partition, accountID)
		r.ModelID = "anthropic.claude-3-5-sonnet-20240620-v1:0"
		r.ToolNames = []string{"fraud-review-action-group", "payments-case-search"}
		r.MemoryEnabled = true
		r.MemoryStoreRefs = []string{"bedrock-knowledge-base/KBPAYMENTS1"}
		r.CapabilityNames = []string{"aliases", "customer_encryption_kms", "foundation_model", "guardrail", "instruction_configured", "knowledge_base", "tool_use"}
		r.GuardrailID = "guard-payments"
		r.CredentialReferenceRefs = []string{
			fmt.Sprintf("action_group_executor:arn:%s:lambda:%s:%s:function:payments-fraud-review", partition, region, accountID),
			fmt.Sprintf("kms:arn:%s:kms:%s:%s:key/cmk-bedrock-payments", partition, region, accountID),
		}
		r.Status = "ready"
	})
	secondary := buildAWSBedrockAgentFixtureRecord(scope, project, connectorID, accountID, region, partition, "SUPPORTAGENT2", "support-triage-agent", checkedAt, func(r *AWSBedrockAgentRecord) {
		r.RuntimeRoleARN = fmt.Sprintf("arn:%s:iam::%s:role/bedrock-support-agent", partition, accountID)
		r.ModelID = "amazon.nova-pro-v1:0"
		r.ToolNames = []string{"support-search"}
		r.CapabilityNames = []string{"foundation_model", "tool_use"}
		r.Status = "preparing"
	})

	records := []AWSBedrockAgentRecord{primary, secondary}
	diagnostics := []providers.SourceError{}

	switch fixtureState {
	case "degraded":
		records[1].CoverageStatus = "degraded"
		records[1].CoverageReason = "bedrock agent detail fetch failed; surfaced summary only"
		records[1].Status = "degraded"
		records[1].NextAction = "Re-fetch this Bedrock agent's detail (action groups, knowledge bases, aliases) to clear the degraded record."
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: awsBedrockAgentsCollectorName,
			SourceID:  records[1].AgentID,
			Code:      "bedrock_agent_detail_failed",
			Message:   fmt.Sprintf("agent %s detail fetch failed", records[1].AgentID),
			Retryable: true,
		})
	case "partial_failure":
		records[1].CoverageStatus = "degraded"
		records[1].CoverageReason = "bedrock agent detail fetch failed; surfaced summary only"
		records[1].Status = "degraded"
		records[1].NextAction = "Re-fetch this Bedrock agent's detail (action groups, knowledge bases, aliases) to clear the degraded record."
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: awsBedrockAgentsCollectorName,
			SourceID:  records[1].AgentID,
			Code:      "bedrock_agent_detail_failed",
			Message:   fmt.Sprintf("agent %s detail fetch failed; surviving agents remain visible", records[1].AgentID),
			Retryable: true,
		})
	}
	for i := range records {
		records[i].RelationshipTypes = awsBedrockAgentRelationshipTypes(records[i])
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].AgentID < records[j].AgentID })
	return records, diagnostics, gaps
}

// buildAWSBedrockAgentFixtureRecord returns a single Bedrock agent record with
// stable derived fields. The mutator slot lets callers tweak per-fixture
// specifics without re-declaring the whole record.
func buildAWSBedrockAgentFixtureRecord(scope db.Scope, project db.TenancyProject, connectorID, accountID, region, partition, agentID, agentName string, checkedAt time.Time, mutate func(*AWSBedrockAgentRecord)) AWSBedrockAgentRecord {
	agentARN := awsBedrockAgentARN(partition, region, accountID, agentID)
	record := AWSBedrockAgentRecord{
		AccountID:         accountID,
		Region:            region,
		Service:           awsBedrockAgentsServiceName,
		AgentID:           agentID,
		AgentARN:          agentARN,
		AgentName:         agentName,
		AgentType:         awsBedrockAgentType,
		Provider:          awsBedrockAgentProvider,
		SensitiveBoundary: "metadata_only",
		CoverageStatus:    "covered",
		Source:            "bedrock_agent_metadata",
		EvidenceRef:       agentARN,
		Confidence:        0.94,
		CollectedAt:       checkedAt,
		Status:            "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	record.AgentNodeID = "aws:resource:bedrock-agent:" + record.AgentARN
	record.RuntimeRoleNodeID = awsBedrockRuntimeRoleNodeID(record.RuntimeRoleARN)
	record.RuntimeRoleName = roleNameFromArnSegment(record.RuntimeRoleARN)
	record.RuntimeRoleAccountID = roleAccountIDFromArnSegment(record.RuntimeRoleARN)
	record.ToolNames = dedupeSortedStrings(record.ToolNames)
	record.MemoryStoreRefs = dedupeSortedStrings(record.MemoryStoreRefs)
	record.CapabilityNames = dedupeSortedStrings(record.CapabilityNames)
	record.CredentialReferenceRefs = dedupeSortedStrings(record.CredentialReferenceRefs)
	// Set ToolCount after dedup so the count matches the emitted tool_names.
	record.ToolCount = len(record.ToolNames)
	if record.NextAction == "" {
		record.NextAction = "Use the AI agent identity surface to review tool bindings, role permissions, and runtime risk."
	}
	if record.Tags == nil {
		record.Tags = map[string]string{}
	}
	return record
}

func awsBedrockAgentRelationshipTypes(record AWSBedrockAgentRecord) []string {
	types := []string{"runs_with_role"}
	if len(record.ToolNames) > 0 {
		types = append(types, "uses_tool")
	}
	if len(record.CredentialReferenceRefs) > 0 {
		types = append(types, "uses_secret")
	}
	if len(record.MemoryStoreRefs) > 0 {
		types = append(types, "reads_knowledge_base")
	}
	sort.Strings(types)
	return types
}

// awsBedrockRuntimeRoleNodeID returns the canonical AWS API graph node ID for
// a Bedrock agent's runtime role. It mirrors awsIdentityNodeIDForAPI (and the
// AI agent identity adapter from #1505) so runs_with_role edges land on the
// same identity node every other AWS endpoint emits. Without this convention
// alignment the UI's graph join from a Bedrock agent to its IAM role would
// silently miss even when the role is present.
func awsBedrockRuntimeRoleNodeID(roleARN string) string {
	trimmed := strings.TrimSpace(roleARN)
	if trimmed == "" {
		return ""
	}
	return awsIdentityNodeIDForAPI(trimmed)
}

// roleNameFromArnSegment extracts the role name from an arn:aws:iam::<acct>:role/<name> ARN.
func roleNameFromArnSegment(roleARN string) string {
	trimmed := strings.TrimSpace(roleARN)
	if trimmed == "" {
		return ""
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 || idx == len(trimmed)-1 {
		return ""
	}
	return trimmed[idx+1:]
}

// roleAccountIDFromArnSegment extracts the account id from an IAM role ARN.
func roleAccountIDFromArnSegment(roleARN string) string {
	parts := strings.Split(strings.TrimSpace(roleARN), ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

func dedupeSortedStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func normalizeAWSBedrockAgentsFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func validAWSBedrockAgentsProviderFilter(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", awsBedrockAgentProvider:
		return true
	default:
		return false
	}
}

func filterAWSBedrockAgentRecords(records []AWSBedrockAgentRecord, request AWSBedrockAgentsInventoryRequest) []AWSBedrockAgentRecord {
	agentID := strings.TrimSpace(request.AgentID)
	identity := strings.ToLower(strings.TrimSpace(request.Identity))
	provider := strings.ToLower(strings.TrimSpace(request.Provider))
	if agentID == "" && identity == "" && provider == "" {
		return records
	}
	filtered := make([]AWSBedrockAgentRecord, 0, len(records))
	for _, record := range records {
		if agentID != "" && record.AgentID != agentID {
			continue
		}
		if provider != "" && strings.ToLower(record.Provider) != provider {
			continue
		}
		if identity != "" {
			haystack := strings.ToLower(strings.Join([]string{record.AgentName, record.AgentARN, record.AgentID, record.RuntimeRoleARN, record.RuntimeRoleName}, "|"))
			if !strings.Contains(haystack, identity) {
				continue
			}
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func awsBedrockAgentRelationships(records []AWSBedrockAgentRecord) []AWSBedrockAgentRelation {
	rels := []AWSBedrockAgentRelation{}
	seen := map[string]struct{}{}
	emit := func(rel AWSBedrockAgentRelation) {
		key := strings.Join([]string{rel.Type, rel.FromNodeID, rel.ToNodeID}, "|")
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		rels = append(rels, rel)
	}
	for _, record := range records {
		if record.RuntimeRoleNodeID != "" {
			emit(AWSBedrockAgentRelation{Type: "runs_with_role", FromNodeID: record.AgentNodeID, ToNodeID: record.RuntimeRoleNodeID, EvidenceRef: record.EvidenceRef})
		}
		for _, tool := range record.ToolNames {
			emit(AWSBedrockAgentRelation{Type: "uses_tool", FromNodeID: record.AgentNodeID, ToNodeID: "tool:agent:" + tool, EvidenceRef: record.EvidenceRef})
		}
		for _, ref := range record.CredentialReferenceRefs {
			emit(AWSBedrockAgentRelation{Type: "uses_secret", FromNodeID: record.AgentNodeID, ToNodeID: "aws:resource:credential-reference:" + ref, EvidenceRef: record.EvidenceRef})
		}
		for _, kb := range record.MemoryStoreRefs {
			emit(AWSBedrockAgentRelation{Type: "reads_knowledge_base", FromNodeID: record.AgentNodeID, ToNodeID: "aws:resource:knowledge-base:" + kb, EvidenceRef: record.EvidenceRef})
		}
	}
	sort.SliceStable(rels, func(i, j int) bool {
		if rels[i].Type != rels[j].Type {
			return rels[i].Type < rels[j].Type
		}
		if rels[i].FromNodeID != rels[j].FromNodeID {
			return rels[i].FromNodeID < rels[j].FromNodeID
		}
		return rels[i].ToNodeID < rels[j].ToNodeID
	})
	return rels
}

// summarizeAWSBedrockAgentsInventory derives the response-level status from
// the diagnostics and records the response actually returns. Both arguments
// are scoped to the filtered view, so a narrowing filter that drops every
// degraded agent collapses the verdict back to ready instead of misreporting
// a degraded fixture state that no longer applies to the returned records.
// The fixture_state only forces a blocked verdict when the scan itself was
// denied (a scan-wide diagnostic that survives any filter).
func summarizeAWSBedrockAgentsInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSBedrockAgentRecord) (string, float64, []string, []string) {
	failures := []string{}
	for _, diag := range diagnostics {
		if msg := strings.TrimSpace(diag.Message); msg != "" {
			failures = append(failures, msg)
		}
	}
	// permission_denied is a scan-wide denial: the diagnostic carries no agent
	// SourceID so it always survives diagnostic scoping. Honor it unconditionally.
	if fixtureState == "permission_denied" {
		return awsPlatformDependencyStatusBlocked, 0.35, dedupeStrings(failures), []string{
			"Grant the connector role bedrock:ListAgents, bedrock:GetAgent, and the per-agent metadata read APIs, then re-run.",
		}
	}
	// Otherwise derive the verdict from what survived filtering: a record with
	// degraded coverage_status or any surviving diagnostic flips the verdict
	// to degraded. This keeps narrowed filtered views honest about the records
	// they return rather than reporting failures for filtered-out agents.
	degraded := len(diagnostics) > 0
	for _, record := range records {
		if record.CoverageStatus == "degraded" || record.Status == "degraded" {
			degraded = true
			break
		}
	}
	if degraded {
		return awsPlatformDependencyStatusDegraded, 0.72, dedupeStrings(failures), []string{
			"Retry the agents shown in the diagnostics; the surviving records remain authoritative.",
		}
	}
	if len(records) == 0 {
		return awsPlatformDependencyStatusReady, 0.8, nil, []string{
			"No Bedrock agents were observed in this connector. Add an agent or expand the region set to start coverage.",
		}
	}
	return awsPlatformDependencyStatusReady, 0.94, nil, []string{
		"Bedrock agent identities are mapped; review the AI agent identity surface for cross-agent comparison.",
	}
}

func awsBedrockAgentDiagnostics(diagnostics []providers.SourceError) []AWSBedrockAgentDiagnostic {
	out := make([]AWSBedrockAgentDiagnostic, 0, len(diagnostics))
	for _, diag := range diagnostics {
		out = append(out, AWSBedrockAgentDiagnostic{
			Collector:   diag.Collector,
			SourceID:    diag.SourceID,
			Code:        diag.Code,
			Message:     diag.Message,
			Remediation: awsBedrockAgentDiagnosticRemediation(diag.Code),
			Retryable:   diag.Retryable,
		})
	}
	return out
}

func awsBedrockAgentDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant bedrock:ListAgents and bedrock:GetAgent to the connector role."
	case "bedrock_agent_detail_failed":
		return "Re-run after the transient AWS error window; this is a per-agent partial failure."
	case "bedrock_agents_list_failed":
		return "Investigate Bedrock service availability and retry; the list call failed before any record could be emitted."
	case "bedrock_agents_page_limit_exceeded":
		return "Raise the max-pages limit or tighten the connector scope to a single account/region."
	default:
		return ""
	}
}

func countAWSBedrockAgentField(records []AWSBedrockAgentRecord, pred func(AWSBedrockAgentRecord) bool) int {
	n := 0
	for _, record := range records {
		if pred(record) {
			n++
		}
	}
	return n
}

func uniqueCountAWSBedrockAgents(records []AWSBedrockAgentRecord, accessor func(AWSBedrockAgentRecord) string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		value := strings.TrimSpace(accessor(record))
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	return len(seen)
}

func listCountAWSBedrockAgents(records []AWSBedrockAgentRecord, accessor func(AWSBedrockAgentRecord) []string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, value := range accessor(record) {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			seen[value] = struct{}{}
		}
	}
	return len(seen)
}

func breakdownAWSBedrockAgents(records []AWSBedrockAgentRecord, accessor func(AWSBedrockAgentRecord) string) map[string]int {
	out := map[string]int{}
	for _, record := range records {
		value := strings.TrimSpace(accessor(record))
		if value == "" {
			continue
		}
		out[value]++
	}
	return out
}

func awsBedrockAgentsPartitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(region)), "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(region)), "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}

func awsBedrockAgentARN(partition, region, accountID, agentID string) string {
	return "arn:" + partition + ":bedrock:" + region + ":" + accountID + ":agent/" + agentID
}

// allow ctx-typed helpers compile cleanly even though they're not used in this
// file; kept reserved for the SDK-backed live mode that will plug in later.
var _ = context.Background
