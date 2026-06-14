package api

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	awsAIAgentIdentityCurrentIssue        = 1512
	awsAIAgentIdentityVersion             = "aws-ai-agent-api-explorer-v1"
	awsAIAgentCredentialRefPrefix         = "aws:resource:credential-reference:"
	awsAIAgentToolNodePrefix              = "tool:agent:"
	agentCoreCapabilityAgentTypeAPI       = "agentcore_capability"
	awsAIAgentProviderSensitivityAIKey    = "ai_provider_api_key"
	awsAIAgentProviderSensitivityAWSStore = "aws_managed_secret"
	awsAIAgentProviderSensitivityGeneric  = "generic_secret"
)

type AWSAIAgentIdentityInventoryRequest struct {
	ConnectorID   string `json:"connector_id,omitempty"`
	FixtureState  string `json:"fixture_state,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	Region        string `json:"region,omitempty"`
	AgentID       string `json:"agent_id,omitempty"`
	Provider      string `json:"provider,omitempty"`
	Runtime       string `json:"runtime,omitempty"`
	Tool          string `json:"tool,omitempty"`
	Status        string `json:"status,omitempty"`
	Risk          string `json:"risk,omitempty"`
	MinConfidence string `json:"min_confidence,omitempty"`
}

type AWSAIAgentCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSAIAgentIdentityInventoryResult struct {
	TenantID                 string                         `json:"tenant_id"`
	WorkspaceID              string                         `json:"workspace_id"`
	ProjectID                string                         `json:"project_id"`
	ConnectorID              string                         `json:"connector_id,omitempty"`
	AccountID                string                         `json:"account_id,omitempty"`
	Region                   string                         `json:"region,omitempty"`
	ParentIssueNumber        int                            `json:"parent_issue_number"`
	ParentIssueRef           string                         `json:"parent_issue_ref"`
	CurrentIssueNumber       int                            `json:"current_issue_number"`
	CurrentIssueRef          string                         `json:"current_issue_ref"`
	Version                  string                         `json:"version"`
	Status                   string                         `json:"status"`
	FixtureState             string                         `json:"fixture_state"`
	Confidence               float64                        `json:"confidence"`
	AppliedFilters           map[string]string              `json:"applied_filters"`
	RecordCount              int                            `json:"record_count"`
	TotalRecordCount         int                            `json:"total_record_count"`
	FilteredRecordCount      int                            `json:"filtered_record_count"`
	BedrockAgentCount        int                            `json:"bedrock_agent_count"`
	AgentCoreRuntimeCount    int                            `json:"agentcore_runtime_count"`
	CustomAgentCount         int                            `json:"custom_agent_count"`
	ExternalAgentCount       int                            `json:"external_agent_count"`
	GatewayCount             int                            `json:"gateway_count"`
	CapabilityAgentCount     int                            `json:"capability_agent_count"`
	MemoryStoreCount         int                            `json:"memory_store_count"`
	BrowserCount             int                            `json:"browser_count"`
	CodeInterpreterCount     int                            `json:"code_interpreter_count"`
	RuntimeRoleCount         int                            `json:"runtime_role_count"`
	ProviderCount            int                            `json:"provider_count"`
	ModelCount               int                            `json:"model_count"`
	ToolCount                int                            `json:"tool_count"`
	CapabilityCount          int                            `json:"capability_count"`
	CredentialRefCount       int                            `json:"credential_reference_count"`
	ExternalProviderKeyCount int                            `json:"external_provider_key_count"`
	AIProviderKeyCount       int                            `json:"ai_provider_key_count"`
	ProviderKeyBreakdown     map[string]int                 `json:"provider_key_breakdown"`
	RelationshipCount        int                            `json:"relationship_count"`
	FailureReasons           []string                       `json:"failure_reasons"`
	RemediationHints         []string                       `json:"remediation_hints"`
	EvidenceLinks            []string                       `json:"evidence_links"`
	CoverageGaps             []AWSAIAgentCoverageGap        `json:"coverage_gaps"`
	Records                  []AWSAIAgentIdentityRecord     `json:"records"`
	Relationships            []AWSAIAgentIdentityRelation   `json:"relationships"`
	Diagnostics              []AWSAIAgentIdentityDiagnostic `json:"diagnostics"`
	GeneratedAt              time.Time                      `json:"generated_at"`
	UpdatedAt                time.Time                      `json:"updated_at"`
}

type AWSAIAgentIdentityDetailResult struct {
	Inventory     AWSAIAgentIdentityInventoryResult `json:"inventory"`
	Record        AWSAIAgentIdentityRecord          `json:"record"`
	Relationships []AWSAIAgentIdentityRelation      `json:"relationships"`
	EvidenceLinks []string                          `json:"evidence_links"`
	GeneratedAt   time.Time                         `json:"generated_at"`
}

type AWSAIAgentIdentityRecord struct {
	AccountID                 string                           `json:"account_id"`
	Region                    string                           `json:"region"`
	Service                   string                           `json:"service"`
	AgentID                   string                           `json:"agent_id"`
	AgentARN                  string                           `json:"agent_arn,omitempty"`
	AgentName                 string                           `json:"agent_name"`
	AgentType                 string                           `json:"agent_type"`
	RuntimeVersion            string                           `json:"runtime_version,omitempty"`
	Provider                  string                           `json:"provider,omitempty"`
	ModelID                   string                           `json:"model_id,omitempty"`
	RuntimeRoleARN            string                           `json:"runtime_role_arn,omitempty"`
	RuntimeRoleName           string                           `json:"runtime_role_name,omitempty"`
	RuntimeRoleAccountID      string                           `json:"runtime_role_account_id,omitempty"`
	WorkloadIdentityARN       string                           `json:"workload_identity_arn,omitempty"`
	GatewayID                 string                           `json:"gateway_id,omitempty"`
	GatewayARN                string                           `json:"gateway_arn,omitempty"`
	ExternalProvider          string                           `json:"external_provider,omitempty"`
	ToolNames                 []string                         `json:"tool_names,omitempty"`
	ToolTargetRefs            []string                         `json:"tool_target_refs,omitempty"`
	AllowedActions            []string                         `json:"allowed_actions,omitempty"`
	AuthMode                  string                           `json:"auth_mode,omitempty"`
	MemoryEnabled             bool                             `json:"memory_enabled"`
	MemoryStoreRefs           []string                         `json:"memory_store_refs,omitempty"`
	BrowserEnabled            bool                             `json:"browser_enabled"`
	CodeInterpreterEnabled    bool                             `json:"code_interpreter_enabled"`
	CapabilityKind            string                           `json:"capability_kind,omitempty"`
	StorageReferenceRefs      []string                         `json:"storage_reference_refs,omitempty"`
	EncryptionKeyARN          string                           `json:"encryption_key_arn,omitempty"`
	CapabilityNames           []string                         `json:"capability_names,omitempty"`
	CredentialReferenceRefs   []string                         `json:"credential_reference_refs,omitempty"`
	ResourceReferenceRefs     []string                         `json:"resource_reference_refs,omitempty"`
	ExecutionEndpointARNs     []string                         `json:"execution_endpoint_arns,omitempty"`
	ExecutionEndpointNames    []string                         `json:"execution_endpoint_names,omitempty"`
	ExecutionEndpointStatuses []string                         `json:"execution_endpoint_statuses,omitempty"`
	ObservabilityLinks        []string                         `json:"observability_links,omitempty"`
	NetworkMode               string                           `json:"network_mode,omitempty"`
	ServerProtocol            string                           `json:"server_protocol,omitempty"`
	SensitiveBoundary         string                           `json:"sensitive_boundary"`
	CoverageStatus            string                           `json:"coverage_status"`
	CoverageReason            string                           `json:"coverage_reason,omitempty"`
	Source                    string                           `json:"source"`
	EvidenceRef               string                           `json:"evidence_ref"`
	AgentNodeID               string                           `json:"agent_node_id"`
	RuntimeRoleNodeID         string                           `json:"runtime_role_node_id,omitempty"`
	GatewayNodeID             string                           `json:"gateway_node_id,omitempty"`
	RelationshipTypes         []string                         `json:"relationship_types"`
	ProviderKeyReferences     []AWSAIAgentProviderKeyReference `json:"provider_key_references,omitempty"`
	Confidence                float64                          `json:"confidence"`
	CollectedAt               time.Time                        `json:"collected_at"`
	Status                    string                           `json:"status"`
	Tags                      map[string]string                `json:"tags,omitempty"`
}

type AWSAIAgentProviderKeyReference struct {
	Reference     string  `json:"reference"`
	ReferenceName string  `json:"reference_name,omitempty"`
	ReferenceKind string  `json:"reference_kind"`
	Provider      string  `json:"provider"`
	Sensitivity   string  `json:"sensitivity"`
	Resolved      bool    `json:"resolved"`
	TargetNodeID  string  `json:"target_node_id,omitempty"`
	EvidenceRef   string  `json:"evidence_ref"`
	Confidence    float64 `json:"confidence"`
}

type AWSAIAgentIdentityRelation struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

type AWSAIAgentIdentityDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSAIAgentIdentityInventory(ctx context.Context, workspaceID string, projectID string, request AWSAIAgentIdentityInventoryRequest) (AWSAIAgentIdentityInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSAIAgentIdentityInventoryResult{}, err
	}
	var (
		connection    AWSConnectionStatus
		hasConnection bool
	)
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSAIAgentIdentityInventoryResult{}, err
	}
	return buildAWSAIAgentIdentityInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func (s *Service) GetAWSAIAgentIdentityDetail(ctx context.Context, workspaceID string, projectID string, agentID string, request AWSAIAgentIdentityInventoryRequest) (AWSAIAgentIdentityDetailResult, error) {
	detailAgentID := firstNonEmptyAWSValue(strings.TrimSpace(agentID), strings.TrimSpace(request.AgentID))
	request.AgentID = ""
	inventory, err := s.GetAWSAIAgentIdentityInventory(ctx, workspaceID, projectID, request)
	if err != nil {
		return AWSAIAgentIdentityDetailResult{}, err
	}
	record, ok := awsAIAgentIdentityExactDetailRecord(inventory.Records, detailAgentID)
	if !ok {
		return AWSAIAgentIdentityDetailResult{}, db.ErrNotFound
	}
	relationships := awsAIAgentIdentityRelationshipsForRecord(record, inventory.Relationships)
	awsAIAgentIdentityApplyRecordSummary(&inventory, []AWSAIAgentIdentityRecord{record}, relationships)
	return AWSAIAgentIdentityDetailResult{
		Inventory:     inventory,
		Record:        record,
		Relationships: relationships,
		EvidenceLinks: dedupeStrings(append(append([]string{}, inventory.EvidenceLinks...), record.EvidenceRef, record.AgentARN, record.RuntimeRoleARN)),
		GeneratedAt:   inventory.GeneratedAt,
	}, nil
}

func buildAWSAIAgentIdentityInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSAIAgentIdentityInventoryRequest, checkedAt time.Time) (AWSAIAgentIdentityInventoryResult, error) {
	fixtureState := normalizeAWSAIAgentIdentityFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSAIAgentIdentityInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsAIAgentIdentityFixtureRecords(accountID, region, fixtureState, checkedAt)
	records = emptyAWSAIAgentIdentityRecords(records)
	coverageGaps = emptyAWSAIAgentCoverageGaps(coverageGaps)
	totalRecordCount := len(records)
	filteredRecords, appliedFilters, err := filterAWSAIAgentIdentityRecords(records, request)
	if err != nil {
		return AWSAIAgentIdentityInventoryResult{}, err
	}
	records = filteredRecords
	for _, record := range records {
		if _, err := awscontract.NormalizeServiceCollectorRecord(awscontract.ServiceCollectorRecord{
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
			ScanID:        "aws-ai-agent-identity-fixture",
			CollectorName: "ai_agent_identity",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSAIAgentIdentityInventoryResult{}, fmt.Errorf("validate ai agent identity contract record: %w", err)
		}
	}
	status, confidence, failures, remediations := summarizeAWSAIAgentIdentityInventory(fixtureState, diagnostics)
	relationships := awsAIAgentIdentityRelationships(records)
	failures = emptyStrings(failures)
	remediations = emptyStrings(remediations)
	return AWSAIAgentIdentityInventoryResult{
		TenantID:              scope.TenantID,
		WorkspaceID:           project.WorkspaceID,
		ProjectID:             project.ProjectID,
		ConnectorID:           connectorID,
		AccountID:             accountID,
		Region:                region,
		ParentIssueNumber:     awsPlatformDependencyParentIssue,
		ParentIssueRef:        awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:    awsAIAgentIdentityCurrentIssue,
		CurrentIssueRef:       awsIssueRef(awsAIAgentIdentityCurrentIssue),
		Version:               awsAIAgentIdentityVersion,
		Status:                status,
		FixtureState:          fixtureState,
		Confidence:            confidence,
		AppliedFilters:        appliedFilters,
		RecordCount:           len(records),
		TotalRecordCount:      totalRecordCount,
		FilteredRecordCount:   len(records),
		BedrockAgentCount:     awsAIAgentIdentityTypeCount(records, "bedrock_agent"),
		AgentCoreRuntimeCount: awsAIAgentIdentityTypeCount(records, "agentcore_runtime"),
		CustomAgentCount:      awsAIAgentIdentityTypeCount(records, "custom_agent"),
		ExternalAgentCount:    awsAIAgentIdentityTypeCount(records, "external_provider_agent"),
		GatewayCount:          awsAIAgentIdentityTypeCount(records, "agent_gateway"),
		CapabilityAgentCount:  awsAIAgentIdentityTypeCount(records, agentCoreCapabilityAgentTypeAPI),
		MemoryStoreCount:      awsAIAgentIdentityCapabilityKindCount(records, "memory"),
		BrowserCount:          awsAIAgentIdentityCapabilityKindCount(records, "browser"),
		CodeInterpreterCount:  awsAIAgentIdentityCapabilityKindCount(records, "code_interpreter"),
		RuntimeRoleCount:      awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.RuntimeRoleNodeID }),
		ProviderCount:         awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.Provider }),
		ModelCount:            awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.ModelID }),
		ToolCount:             awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.ToolNames }),
		CapabilityCount:       awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.CapabilityNames }),
		CredentialRefCount:    awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.CredentialReferenceRefs }),
		ExternalProviderKeyCount: awsAIAgentProviderKeyCount(records, func(ref AWSAIAgentProviderKeyReference) bool {
			return awsAIAgentProviderIsExternalAI(ref.Provider)
		}),
		AIProviderKeyCount: awsAIAgentProviderKeyCount(records, func(ref AWSAIAgentProviderKeyReference) bool {
			return ref.Sensitivity == awsAIAgentProviderSensitivityAIKey
		}),
		ProviderKeyBreakdown: awsAIAgentProviderKeyBreakdown(records),
		RelationshipCount:    len(relationships),
		FailureReasons:       failures,
		RemediationHints:     remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsAIAgentIdentityCurrentIssue),
			"/docs/aws-ai-agent-identities",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsAIAgentIdentityDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func emptyAWSAIAgentIdentityRecords(records []AWSAIAgentIdentityRecord) []AWSAIAgentIdentityRecord {
	if records == nil {
		return []AWSAIAgentIdentityRecord{}
	}
	return records
}

func emptyAWSAIAgentCoverageGaps(gaps []AWSAIAgentCoverageGap) []AWSAIAgentCoverageGap {
	if gaps == nil {
		return []AWSAIAgentCoverageGap{}
	}
	return gaps
}

func emptyStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func normalizeOrderedStringList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func normalizeAWSAIAgentIdentityFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func filterAWSAIAgentIdentityRecords(records []AWSAIAgentIdentityRecord, request AWSAIAgentIdentityInventoryRequest) ([]AWSAIAgentIdentityRecord, map[string]string, error) {
	applied := map[string]string{}
	accountID := strings.TrimSpace(request.AccountID)
	region := strings.TrimSpace(request.Region)
	agentID := strings.TrimSpace(request.AgentID)
	provider := strings.TrimSpace(request.Provider)
	runtime := strings.TrimSpace(request.Runtime)
	tool := strings.TrimSpace(request.Tool)
	status := normalizeAWSAIAgentExplorerStatus(request.Status)
	risk := normalizeAWSAIAgentExplorerRisk(request.Risk)
	minConfidence, minConfidenceSet, err := parseAWSAIAgentMinConfidence(request.MinConfidence)
	if err != nil {
		return nil, nil, ErrInvalidAWSConnectionRequest
	}
	if accountID != "" {
		applied["account_id"] = accountID
	}
	if region != "" {
		applied["region"] = region
	}
	if agentID != "" {
		applied["agent_id"] = agentID
	}
	if provider != "" {
		applied["provider"] = provider
	}
	if runtime != "" {
		applied["runtime"] = runtime
	}
	if tool != "" {
		applied["tool"] = tool
	}
	if status != "" {
		applied["status"] = status
	}
	if risk != "" {
		applied["risk"] = risk
	}
	if minConfidenceSet {
		applied["min_confidence"] = strconv.FormatFloat(minConfidence, 'f', -1, 64)
	}
	filtered := make([]AWSAIAgentIdentityRecord, 0, len(records))
	for _, record := range records {
		if accountID != "" && !strings.EqualFold(record.AccountID, accountID) {
			continue
		}
		if region != "" && !strings.EqualFold(record.Region, region) {
			continue
		}
		if agentID != "" && !awsAIAgentRecordMatchesIdentity(record, agentID) {
			continue
		}
		if provider != "" && !awsAIAgentRecordMatchesProvider(record, provider) {
			continue
		}
		if runtime != "" && !awsAIAgentRecordMatchesAny(record, runtime, record.Service, record.AgentType, record.RuntimeVersion, record.RuntimeRoleARN, record.RuntimeRoleName, record.NetworkMode, record.ServerProtocol) {
			continue
		}
		if tool != "" && !awsAIAgentRecordMatchesAny(record, tool, append(append([]string{}, record.ToolNames...), record.ToolTargetRefs...)...) {
			continue
		}
		if status != "" && !awsAIAgentRecordMatchesStatus(record, status) {
			continue
		}
		if risk != "" && awsAIAgentRecordRisk(record) != risk {
			continue
		}
		if minConfidenceSet && record.Confidence < minConfidence {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered, applied, nil
}

func parseAWSAIAgentMinConfidence(raw string) (float64, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false, nil
	}
	value, err := strconv.ParseFloat(trimmed, 64)
	if err != nil || math.IsNaN(value) || value < 0 || value > 1 {
		return 0, false, fmt.Errorf("invalid min confidence")
	}
	return value, true, nil
}

func normalizeAWSAIAgentExplorerStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "all":
		return ""
	case "ready", "role-anchor", "role_anchor", "covered":
		return "ready"
	case "candidate":
		return "candidate"
	case "degraded":
		return "degraded"
	case "blocked", "not-yet-available", "not_yet_available":
		return "blocked"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func normalizeAWSAIAgentExplorerRisk(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "all":
		return ""
	case "high", "medium", "low", "unscored":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func awsAIAgentRecordMatchesIdentity(record AWSAIAgentIdentityRecord, query string) bool {
	return awsAIAgentRecordMatchesAny(record, query, record.AgentID, record.AgentName, record.AgentARN, record.AgentNodeID, record.GatewayID, record.GatewayARN)
}

func awsAIAgentIdentityExactDetailRecord(records []AWSAIAgentIdentityRecord, agentID string) (AWSAIAgentIdentityRecord, bool) {
	normalizedAgentID := strings.TrimSpace(agentID)
	if normalizedAgentID == "" {
		return AWSAIAgentIdentityRecord{}, false
	}
	for _, record := range records {
		if record.AgentID == normalizedAgentID || record.AgentNodeID == normalizedAgentID {
			return record, true
		}
	}
	return AWSAIAgentIdentityRecord{}, false
}

func awsAIAgentRecordProviderFilterValues(record AWSAIAgentIdentityRecord) []string {
	values := []string{record.Provider, record.ExternalProvider}
	for _, ref := range record.ProviderKeyReferences {
		values = append(values, ref.Provider)
	}
	return values
}

func awsAIAgentRecordMatchesProvider(record AWSAIAgentIdentityRecord, query string) bool {
	normalizedQuery := normalizeAWSAIAgentProviderToken(query)
	if normalizedQuery == "" {
		return true
	}
	for _, value := range awsAIAgentRecordProviderFilterValues(record) {
		if normalizeAWSAIAgentProviderToken(value) == normalizedQuery {
			return true
		}
	}
	if _, known := awsAIAgentKnownProviderFilterTokens()[normalizedQuery]; known {
		return false
	}
	return awsAIAgentRecordMatchesAny(record, query, record.ModelID)
}

func normalizeAWSAIAgentProviderToken(value string) string {
	token := strings.ToLower(strings.TrimSpace(value))
	token = strings.NewReplacer(" ", "_", "-", "_").Replace(token)
	switch token {
	case "amazon_bedrock":
		return "amazon_bedrock"
	case "bedrock_agentcore", "amazon_bedrock_agentcore":
		return "amazon_bedrock_agentcore"
	case "external_ai_provider":
		return "external_provider"
	default:
		return token
	}
}

func awsAIAgentKnownProviderFilterTokens() map[string]struct{} {
	return map[string]struct{}{
		"amazon_bedrock":           {},
		"amazon_bedrock_agentcore": {},
		"external_provider":        {},
		"openai":                   {},
		"anthropic":                {},
		"bedrock":                  {},
		"custom":                   {},
	}
}

func awsAIAgentRecordMatchesAny(record AWSAIAgentIdentityRecord, query string, values ...string) bool {
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	if normalizedQuery == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), normalizedQuery) {
			return true
		}
	}
	return false
}

func awsAIAgentRecordMatchesStatus(record AWSAIAgentIdentityRecord, status string) bool {
	switch status {
	case "ready":
		return strings.EqualFold(record.Status, "ready") && strings.EqualFold(record.CoverageStatus, "covered")
	case "candidate":
		return strings.EqualFold(record.Status, "candidate") || strings.EqualFold(record.CoverageStatus, "candidate")
	case "degraded":
		return strings.EqualFold(record.Status, "degraded") || strings.EqualFold(record.CoverageStatus, "degraded") || strings.TrimSpace(record.CoverageReason) != ""
	case "blocked":
		return strings.EqualFold(record.Status, "blocked")
	default:
		return strings.EqualFold(record.Status, status) || strings.EqualFold(record.CoverageStatus, status)
	}
}

func awsAIAgentRecordRisk(record AWSAIAgentIdentityRecord) string {
	switch {
	case strings.EqualFold(record.Status, "degraded") || strings.EqualFold(record.CoverageStatus, "degraded") || strings.TrimSpace(record.CoverageReason) != "":
		return "high"
	case record.Confidence == 0:
		return "unscored"
	case strings.EqualFold(record.Status, "candidate") || strings.EqualFold(record.CoverageStatus, "candidate") || record.Confidence < 0.75:
		return "medium"
	default:
		return "low"
	}
}

func awsAIAgentIdentityRelationshipsForRecord(record AWSAIAgentIdentityRecord, relationships []AWSAIAgentIdentityRelation) []AWSAIAgentIdentityRelation {
	result := []AWSAIAgentIdentityRelation{}
	sourceNodeIDs := map[string]struct{}{}
	for _, nodeID := range []string{record.AgentNodeID, record.GatewayNodeID, awsAIAgentWorkloadNodeID(record)} {
		if strings.TrimSpace(nodeID) != "" {
			sourceNodeIDs[nodeID] = struct{}{}
		}
	}
	for _, relationship := range relationships {
		if _, ok := sourceNodeIDs[relationship.FromNodeID]; ok {
			result = append(result, relationship)
		}
	}
	return result
}

func awsAIAgentIdentityApplyRecordSummary(inventory *AWSAIAgentIdentityInventoryResult, records []AWSAIAgentIdentityRecord, relationships []AWSAIAgentIdentityRelation) {
	inventory.RecordCount = len(records)
	inventory.TotalRecordCount = len(records)
	inventory.FilteredRecordCount = len(records)
	inventory.BedrockAgentCount = awsAIAgentIdentityTypeCount(records, "bedrock_agent")
	inventory.AgentCoreRuntimeCount = awsAIAgentIdentityTypeCount(records, "agentcore_runtime")
	inventory.CustomAgentCount = awsAIAgentIdentityTypeCount(records, "custom_agent")
	inventory.ExternalAgentCount = awsAIAgentIdentityTypeCount(records, "external_provider_agent")
	inventory.GatewayCount = awsAIAgentIdentityTypeCount(records, "agent_gateway")
	inventory.CapabilityAgentCount = awsAIAgentIdentityTypeCount(records, agentCoreCapabilityAgentTypeAPI)
	inventory.MemoryStoreCount = awsAIAgentIdentityCapabilityKindCount(records, "memory")
	inventory.BrowserCount = awsAIAgentIdentityCapabilityKindCount(records, "browser")
	inventory.CodeInterpreterCount = awsAIAgentIdentityCapabilityKindCount(records, "code_interpreter")
	inventory.RuntimeRoleCount = awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.RuntimeRoleNodeID })
	inventory.ProviderCount = awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.Provider })
	inventory.ModelCount = awsAIAgentIdentityUniqueCount(records, func(r AWSAIAgentIdentityRecord) string { return r.ModelID })
	inventory.ToolCount = awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.ToolNames })
	inventory.CapabilityCount = awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.CapabilityNames })
	inventory.CredentialRefCount = awsAIAgentIdentityListCount(records, func(r AWSAIAgentIdentityRecord) []string { return r.CredentialReferenceRefs })
	inventory.ExternalProviderKeyCount = awsAIAgentProviderKeyCount(records, func(ref AWSAIAgentProviderKeyReference) bool {
		return awsAIAgentProviderIsExternalAI(ref.Provider)
	})
	inventory.AIProviderKeyCount = awsAIAgentProviderKeyCount(records, func(ref AWSAIAgentProviderKeyReference) bool {
		return ref.Sensitivity == awsAIAgentProviderSensitivityAIKey
	})
	inventory.ProviderKeyBreakdown = awsAIAgentProviderKeyBreakdown(records)
	inventory.RelationshipCount = len(relationships)
	inventory.Records = records
	inventory.Relationships = relationships
}

func awsAIAgentIdentityFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSAIAgentIdentityRecord, []providers.SourceError, []AWSAIAgentCoverageGap) {
	partition := awsPartitionForAPIRegion(region)
	role := func(name string) string { return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, name) }
	agentARN := func(service, id string) string {
		return fmt.Sprintf("arn:%s:%s:%s:%s:agent/%s", partition, service, region, accountID, id)
	}
	gatewayARN := fmt.Sprintf("arn:%s:bedrock:%s:%s:agent-gateway/payments-gateway", partition, region, accountID)
	gaps := []AWSAIAgentCoverageGap{{
		Capability:  "prompt_and_completion_contents",
		Status:      "intentionally_not_collected",
		Reason:      "Prompt text, completions, memory content, browser pages, code-interpreter output, database rows, and object contents are outside this metadata-only model.",
		Remediation: "Use runtime evidence references and operator-approved follow-up collection only when a future issue explicitly permits it.",
	}, {
		Capability:  "external_provider_secret_values",
		Status:      "intentionally_not_collected",
		Reason:      "External AI provider keys are represented as credential references only; secret values remain hidden.",
		Remediation: "Join to credential-reference metadata for rotation and ownership, never to secret values.",
	}}
	records := []AWSAIAgentIdentityRecord{
		awsAIAgentFixtureRecord(accountID, region, "bedrock_agent", "payments-risk-agent", "AGENTPAY1", agentARN("bedrock", "AGENTPAY1"), role("bedrock-payments-risk-agent"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "bedrock"
			r.Provider = "amazon-bedrock"
			r.ModelID = "anthropic.claude-3-5-sonnet-20240620-v1:0"
			r.ToolNames = []string{"payments-case-search", "fraud-review-action-group"}
			r.MemoryEnabled = true
			r.MemoryStoreRefs = []string{"bedrock-memory/payments-risk"}
			r.CapabilityNames = []string{"tool_use", "memory", "knowledge_base"}
		}),
		awsAIAgentFixtureRecord(accountID, region, "agentcore_runtime", "case-triage-runtime", "runtime-case-triage", agentARN("bedrock-agentcore", "runtime-case-triage"), role("agentcore-case-triage-runtime"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "agentcore"
			r.Provider = "amazon-bedrock-agentcore"
			r.RuntimeVersion = "2026-06-01"
			r.ModelID = "us.amazon.nova-pro-v1:0"
			r.ToolNames = []string{"case-router", "policy-checker"}
			r.WorkloadIdentityARN = fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:workload-identity/runtime-case-triage", partition, region, accountID)
			r.ExecutionEndpointARNs = []string{
				fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:agent-runtime-endpoint/runtime-case-triage/blue", partition, region, accountID),
				fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:agent-runtime-endpoint/runtime-case-triage/green", partition, region, accountID),
			}
			r.ExecutionEndpointNames = []string{"blue", "green"}
			r.ExecutionEndpointStatuses = []string{"READY", "READY"}
			r.ObservabilityLinks = []string{
				fmt.Sprintf("observability://agentcore/runtime/%s", "runtime-case-triage"),
				fmt.Sprintf("observability://agentcore/runtime/%s/endpoints/blue", "runtime-case-triage"),
				fmt.Sprintf("observability://agentcore/runtime/%s/endpoints/green", "runtime-case-triage"),
			}
			r.NetworkMode = "VPC"
			r.ServerProtocol = "HTTP"
			r.BrowserEnabled = true
			r.CodeInterpreterEnabled = true
			r.CapabilityNames = []string{"browser", "code_interpreter", "tool_use"}
		}),
		awsAIAgentFixtureRecord(accountID, region, "custom_agent", "invoice-reconciliation-agent", "custom-invoice-agent", fmt.Sprintf("arn:%s:lambda:%s:%s:function:invoice-reconciliation-agent", partition, region, accountID), role("lambda-invoice-agent"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "lambda"
			r.Provider = "custom"
			r.ModelID = "external:model-class-hidden"
			r.ToolNames = []string{"invoice-index", "ticket-writer"}
			r.CapabilityNames = []string{"tool_use"}
			r.CredentialReferenceRefs = []string{"secretsmanager:prod/ai/openai-key"}
			r.ExternalProvider = "external_ai_provider"
		}),
		awsAIAgentFixtureRecord(accountID, region, "external_provider_agent", "support-assistant", "external-support-agent", fmt.Sprintf("arn:%s:ecs:%s:%s:service/support/support-assistant", partition, region, accountID), role("ecs-support-agent-task"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "ecs"
			r.Provider = "external_provider"
			r.ModelID = "provider:model-redacted"
			r.ToolNames = []string{"support-search"}
			r.CapabilityNames = []string{"tool_use"}
			r.CredentialReferenceRefs = []string{
				"ANTHROPIC_API_KEY=ssm:/prod/support/anthropic-key",
				"BEDROCK_API_KEY=secretsmanager:prod/bedrock/api-key",
			}
			r.ExternalProvider = "anthropic"
		}),
		awsAIAgentFixtureRecord(accountID, region, "agent_gateway", "payments-gateway", "payments-gateway", gatewayARN, role("bedrock-agent-gateway-payments"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "bedrock"
			r.Provider = "amazon-bedrock"
			r.GatewayID = "payments-gateway"
			r.GatewayARN = gatewayARN
			r.ToolNames = []string{"payments-case-search", "fraud-review-action-group", "support-search"}
			r.ToolTargetRefs = []string{"payments-search-target", "fraud-review-target", "support-search-target"}
			r.AllowedActions = []string{"search_cases", "create_fraud_review", "search_support"}
			r.AuthMode = "custom_jwt"
			r.CapabilityNames = []string{"gateway", "tool_routing", "mcp", "gateway_auth_custom_jwt"}
		}),
		awsAIAgentFixtureRecord(accountID, region, agentCoreCapabilityAgentTypeAPI, "payments-agent-memory", "mem-payments", fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:memory/mem-payments", partition, region, accountID), role("agentcore-memory-payments"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "agentcore"
			r.Provider = "amazon-bedrock-agentcore"
			r.CapabilityKind = "memory"
			r.MemoryEnabled = true
			r.MemoryStoreRefs = []string{fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:memory/mem-payments", partition, region, accountID)}
			r.EncryptionKeyARN = fmt.Sprintf("arn:%s:kms:%s:%s:key/cmk-agentcore-memory", partition, region, accountID)
			r.CapabilityNames = []string{"agentcore_memory", "memory", "memory_strategy_semantic", "memory_event_expiry_days_30", "customer_encryption_kms"}
		}),
		awsAIAgentFixtureRecord(accountID, region, agentCoreCapabilityAgentTypeAPI, "research-browser", "br-research", fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:browser/br-research", partition, region, accountID), role("agentcore-browser-research"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "agentcore"
			r.Provider = "amazon-bedrock-agentcore"
			r.CapabilityKind = "browser"
			r.BrowserEnabled = true
			r.NetworkMode = "vpc"
			r.StorageReferenceRefs = []string{"s3://agentcore-browser-recordings/research/"}
			r.CapabilityNames = []string{"agentcore_browser", "browser", "browser_recording", "vpc_attached", "storage_reference"}
		}),
		awsAIAgentFixtureRecord(accountID, region, agentCoreCapabilityAgentTypeAPI, "python-sandbox", "ci-python", fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:code-interpreter/ci-python", partition, region, accountID), role("agentcore-code-python"), checkedAt, func(r *AWSAIAgentIdentityRecord) {
			r.Service = "agentcore"
			r.Provider = "amazon-bedrock-agentcore"
			r.CapabilityKind = "code_interpreter"
			r.CodeInterpreterEnabled = true
			r.NetworkMode = "sandbox"
			r.CapabilityNames = []string{"agentcore_code_interpreter", "code_interpreter"}
		}),
	}
	switch fixtureState {
	case "empty":
		return []AWSAIAgentIdentityRecord{}, nil, gaps
	case "degraded":
		records[2].Status = "degraded"
		records[2].CoverageStatus = "degraded"
		records[2].CoverageReason = "custom agent provider key is an unresolved credential reference"
		records[2].Confidence = 0.68
		return records, []providers.SourceError{{
			Collector: "aws_ai-agent/ai_agent_identity",
			SourceID:  records[2].AgentID,
			Code:      "ai_agent_credential_reference_unresolved",
			Message:   "custom agent has an external provider credential reference that did not resolve to collected metadata",
			Retryable: false,
		}}, gaps
	case "partial_failure":
		// Simulate the gateway sub-listing failing while every other sub-listing
		// (Bedrock, AgentCore runtime, custom, external-provider, and the
		// AgentCore Memory/Browser/Code Interpreter capability surfaces) is
		// retained. Drop only the gateway record so the diagnostic stays honest.
		retained := make([]AWSAIAgentIdentityRecord, 0, len(records))
		for _, record := range records {
			if record.AgentType == "agent_gateway" {
				continue
			}
			retained = append(retained, record)
		}
		return retained, []providers.SourceError{{
			Collector: "aws_ai-agent/ai_agent_identity",
			SourceID:  fmt.Sprintf("service=ai-agent|account=%s|region=%s|source=agent_gateways", accountID, region),
			Code:      "ai_agent_gateway_list_failed",
			Message:   "agent gateway metadata could not be listed; retained Bedrock, AgentCore runtime, custom, external-provider, and AgentCore capability identities remain visible",
			Retryable: true,
		}}, gaps
	case "permission_denied":
		return []AWSAIAgentIdentityRecord{}, []providers.SourceError{{
			Collector: "aws_ai-agent/ai_agent_identity",
			SourceID:  fmt.Sprintf("service=ai-agent|account=%s|region=%s|source=list", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only AI agent metadata permission is missing",
			Retryable: false,
		}}, gaps
	default:
		return records, nil, gaps
	}
}

func awsAIAgentFixtureRecord(accountID string, region string, agentType string, agentName string, agentID string, agentARN string, roleARN string, checkedAt time.Time, mutate func(*AWSAIAgentIdentityRecord)) AWSAIAgentIdentityRecord {
	record := AWSAIAgentIdentityRecord{
		AccountID:               accountID,
		Region:                  region,
		Service:                 "ai-agent",
		AgentID:                 agentID,
		AgentARN:                agentARN,
		AgentName:               agentName,
		AgentType:               agentType,
		RuntimeRoleARN:          roleARN,
		RuntimeRoleName:         roleNameFromARNForAPI(roleARN),
		RuntimeRoleAccountID:    roleAccountIDFromARNForAPI(roleARN),
		SensitiveBoundary:       "metadata_only",
		CoverageStatus:          "covered",
		Source:                  "ai_agent_metadata",
		EvidenceRef:             agentARN,
		AgentNodeID:             awsAIAgentNodeID(accountID, region, agentType, agentID, ""),
		RuntimeRoleNodeID:       awsIdentityNodeIDForAPI(roleARN),
		RelationshipTypes:       []string{"runs_as"},
		Confidence:              0.9,
		CollectedAt:             checkedAt,
		Status:                  "ready",
		Tags:                    map[string]string{"owner": "ai-platform", "classification": "metadata-only"},
		CapabilityNames:         []string{"identity"},
		ToolNames:               nil,
		MemoryStoreRefs:         nil,
		CredentialReferenceRefs: nil,
	}
	if mutate != nil {
		mutate(&record)
	}
	record.AgentNodeID = awsAIAgentNodeID(accountID, region, agentType, firstNonEmptyAWSValue(record.AgentID, agentID), record.RuntimeVersion)
	record.RuntimeRoleNodeID = awsIdentityNodeIDForAPI(roleARN)
	record.ToolNames = dedupeStrings(record.ToolNames)
	record.ToolTargetRefs = dedupeStrings(record.ToolTargetRefs)
	record.AllowedActions = dedupeStrings(record.AllowedActions)
	record.CapabilityNames = dedupeStrings(record.CapabilityNames)
	record.CredentialReferenceRefs = dedupeStrings(record.CredentialReferenceRefs)
	record.ProviderKeyReferences = awsAIAgentProviderKeyReferences(record)
	record.ExecutionEndpointARNs = normalizeOrderedStringList(record.ExecutionEndpointARNs)
	record.ExecutionEndpointNames = normalizeOrderedStringList(record.ExecutionEndpointNames)
	record.ExecutionEndpointStatuses = normalizeOrderedStringList(record.ExecutionEndpointStatuses)
	record.ObservabilityLinks = normalizeOrderedStringList(record.ObservabilityLinks)
	record.StorageReferenceRefs = dedupeStrings(record.StorageReferenceRefs)
	record.ResourceReferenceRefs = dedupeStrings(append(append(record.ResourceReferenceRefs, record.ToolTargetRefs...), append(append(append([]string{}, record.ExecutionEndpointARNs...), record.StorageReferenceRefs...), record.WorkloadIdentityARN, record.EncryptionKeyARN)...))
	if len(record.CredentialReferenceRefs) > 0 {
		record.RelationshipTypes = dedupeStrings(append(record.RelationshipTypes, "uses_secret"))
	}
	if len(record.ExecutionEndpointARNs) > 0 {
		record.RelationshipTypes = dedupeStrings(append(record.RelationshipTypes, "invokes"))
	}
	if record.GatewayARN != "" {
		gatewayNodeID := awsAIAgentNodeID(accountID, region, "agent_gateway", firstNonEmptyAWSValue(record.GatewayID, record.GatewayARN), "")
		if record.AgentNodeID != gatewayNodeID {
			record.GatewayNodeID = gatewayNodeID
			record.RelationshipTypes = dedupeStrings(append(record.RelationshipTypes, "calls_tool"))
		}
	}
	return record
}

func summarizeAWSAIAgentIdentityInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35,
			[]string{"AI agent identity collection is blocked by missing read-only metadata permission"},
			[]string{"Grant metadata-only agent, runtime, gateway, and role-list permissions; do not grant prompt, invocation, browser, memory-content, code-output, or endpoint-content reads."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72,
			[]string{"one or more agent credential references are unresolved"},
			[]string{"Join to credential-reference metadata for ownership and rotation; keep secret values hidden."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78,
			[]string{"one agent sub-listing failed while successful agent identity records remain visible"},
			[]string{"Retry the failed agent metadata call without discarding retained agent records."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82,
				[]string{"AI agent identity collection returned diagnostics"},
				[]string{"Review diagnostics before treating AI agent coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.91, nil, nil
	}
}

func awsAIAgentIdentityRelationships(records []AWSAIAgentIdentityRecord) []AWSAIAgentIdentityRelation {
	result := []AWSAIAgentIdentityRelation{}
	for _, record := range records {
		if record.AgentNodeID != "" && record.RuntimeRoleNodeID != "" {
			result = append(result, AWSAIAgentIdentityRelation{Type: "runs_as", FromNodeID: awsAIAgentWorkloadNodeID(record), ToNodeID: record.RuntimeRoleNodeID, EvidenceRef: record.EvidenceRef})
		}
		for _, endpointARN := range record.ExecutionEndpointARNs {
			endpointARN = strings.TrimSpace(endpointARN)
			if record.AgentNodeID != "" && endpointARN != "" {
				result = append(result, AWSAIAgentIdentityRelation{
					Type:        "invokes",
					FromNodeID:  record.AgentNodeID,
					ToNodeID:    awsAIAgentExecutionEndpointNodeID(record.AgentNodeID, endpointARN),
					EvidenceRef: record.EvidenceRef,
				})
			}
		}
		toolNames := dedupeStrings(record.ToolNames)
		if record.AgentNodeID != "" && len(toolNames) > 0 {
			callsToolSource := firstNonEmptyAWSValue(record.GatewayNodeID, record.AgentNodeID)
			if strings.EqualFold(record.AgentType, "agent_gateway") {
				callsToolSource = record.AgentNodeID
			}
			if callsToolSource == "" {
				continue
			}
			for _, tool := range toolNames {
				tool = strings.TrimSpace(tool)
				if tool == "" {
					continue
				}
				result = append(result, AWSAIAgentIdentityRelation{
					Type:        "calls_tool",
					FromNodeID:  callsToolSource,
					ToNodeID:    awsAIAgentToolNodeID(callsToolSource, tool),
					EvidenceRef: record.EvidenceRef,
				})
			}
		}
		for _, ref := range record.CredentialReferenceRefs {
			ref = strings.TrimSpace(ref)
			if record.AgentNodeID != "" && ref != "" {
				result = append(result, AWSAIAgentIdentityRelation{Type: "uses_secret", FromNodeID: record.AgentNodeID, ToNodeID: awsCredentialReferenceNodeID(record.AgentNodeID, ref), EvidenceRef: record.EvidenceRef})
			}
		}
	}
	return result
}

func awsAIAgentToolNodeID(gatewayNodeID string, tool string) string {
	workload := strings.TrimSpace(strings.ToLower(gatewayNodeID))
	if workload == "" {
		workload = "gateway"
	}
	name := strings.TrimSpace(strings.ToLower(tool))
	if name == "" {
		name = "tool"
	}
	return awsAIAgentToolNodePrefix + strings.Join(normalizeStringList([]string{workload, name}), "|")
}

func awsAIAgentExecutionEndpointNodeID(agentNodeID string, endpointARN string) string {
	workload := strings.TrimSpace(strings.ToLower(agentNodeID))
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

func awsCredentialReferenceNodeID(agentNodeID string, ref string) string {
	name, source := awsAIAgentCredentialReferenceParts(ref)
	agentNodeID = strings.TrimSpace(strings.ToLower(agentNodeID))
	if agentNodeID == "" {
		agentNodeID = "agent"
	}
	name = strings.TrimSpace(strings.ToLower(name))
	source = strings.TrimSpace(strings.ToLower(source))
	return awsAIAgentCredentialRefPrefix + strings.Join(normalizeStringList([]string{
		agentNodeID,
		awsAIAgentCredentialReferenceProvider(name, source),
		name,
		source,
	}), "|")
}

func awsAIAgentCredentialReferenceProvider(name, source string) string {
	probe := strings.ToLower(strings.TrimSpace(name + " " + source))
	sourceProbe := strings.ToLower(strings.TrimSpace(source))
	switch {
	case containsAnyToken(probe, "openai", "open_ai", "gpt_"):
		return "openai"
	case containsAnyToken(probe, "anthropic", "claude"):
		return "anthropic"
	case awsAIAgentCredentialReferenceLooksLikeBedrockProviderKey(sourceProbe, probe):
		return "bedrock"
	case strings.HasPrefix(sourceProbe, "secretsmanager:") ||
		strings.HasPrefix(sourceProbe, "secretsmanager-") ||
		strings.HasPrefix(sourceProbe, "secrets_manager-") ||
		strings.Contains(sourceProbe, "arn-aws-secretsmanager-") ||
		strings.Contains(sourceProbe, "arn-aws-us-gov-secretsmanager-") ||
		strings.Contains(sourceProbe, "arn-aws-cn-secretsmanager-"):
		return "secretsmanager"
	case strings.HasPrefix(sourceProbe, "ssm:") ||
		strings.HasPrefix(sourceProbe, "ssm-") ||
		strings.HasPrefix(sourceProbe, "parameter_store:") ||
		strings.HasPrefix(sourceProbe, "parameter_store-") ||
		strings.Contains(sourceProbe, "arn-aws-ssm-") ||
		strings.Contains(sourceProbe, "arn-aws-us-gov-ssm-") ||
		strings.Contains(sourceProbe, "arn-aws-cn-ssm-"):
		return "ssm"
	default:
		return "generic"
	}
}

func awsAIAgentCredentialReferenceLooksLikeBedrockProviderKey(sourceProbe, probe string) bool {
	if sourceProbe != "" && awsAIAgentCredentialReferenceLooksLikeAgentCoreOAuthSource(sourceProbe) {
		return false
	}
	return awsAIAgentCredentialReferenceContainsBedrockKeyToken(probe)
}

func awsAIAgentCredentialReferenceContainsBedrockKeyToken(probe string) bool {
	return containsAnyToken(probe,
		"bedrock_api_key",
		"bedrock-api-key",
		"bedrockapikey",
		"bedrock_provider_key",
		"bedrock-provider-key",
		"bedrockproviderkey",
		"amazon_bedrock_api_key",
		"amazon-bedrock-api-key",
		"amazonbedrockapikey",
	)
}

func awsAIAgentCredentialReferenceLooksLikeAgentCoreOAuthSource(probe string) bool {
	agentCore := strings.Contains(probe, "bedrock-agentcore") || strings.Contains(probe, "bedrock_agentcore")
	oauth := strings.Contains(probe, "-oauth-") || strings.Contains(probe, "/oauth/") || strings.Contains(probe, ":oauth/")
	return agentCore && oauth
}

func awsAIAgentProviderKeyReferences(record AWSAIAgentIdentityRecord) []AWSAIAgentProviderKeyReference {
	refs := []AWSAIAgentProviderKeyReference{}
	seen := map[string]struct{}{}
	for _, raw := range record.CredentialReferenceRefs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		name, source := awsAIAgentCredentialReferenceParts(trimmed)
		provider := awsAIAgentCredentialReferenceProvider(name, source)
		ref := AWSAIAgentProviderKeyReference{
			Reference:     trimmed,
			ReferenceName: name,
			ReferenceKind: awsAIAgentCredentialReferenceKind(source),
			Provider:      provider,
			Sensitivity:   awsAIAgentCredentialReferenceSensitivity(provider),
			Resolved:      false,
			TargetNodeID:  awsCredentialReferenceNodeID(record.AgentNodeID, trimmed),
			EvidenceRef:   firstNonEmptyAWSValue(record.EvidenceRef, trimmed),
			Confidence:    awsAIAgentCredentialReferenceConfidence(provider),
		}
		refs = append(refs, ref)
	}
	return refs
}

func awsAIAgentCredentialReferenceKind(source string) string {
	probe := strings.ToLower(strings.TrimSpace(source))
	switch {
	case strings.Contains(probe, "secretsmanager") || strings.HasPrefix(probe, "secretsmanager-") || strings.HasPrefix(probe, "secrets_manager-"):
		return "secrets_manager"
	case strings.HasPrefix(probe, "ssm-") || strings.Contains(probe, "parameter"):
		return "ssm_parameter"
	case probe == "":
		return "environment_variable"
	default:
		return "credential_reference"
	}
}

func awsAIAgentCredentialReferenceSensitivity(provider string) string {
	switch provider {
	case "openai", "anthropic", "bedrock":
		return awsAIAgentProviderSensitivityAIKey
	case "secretsmanager", "ssm":
		return awsAIAgentProviderSensitivityAWSStore
	default:
		return awsAIAgentProviderSensitivityGeneric
	}
}

func awsAIAgentCredentialReferenceConfidence(provider string) float64 {
	switch provider {
	case "openai", "anthropic":
		return 0.9
	case "bedrock":
		return 0.85
	case "secretsmanager", "ssm":
		return 0.72
	default:
		return 0.62
	}
}

func awsAIAgentProviderIsExternalAI(provider string) bool {
	switch provider {
	case "openai", "anthropic", "bedrock":
		return true
	default:
		return false
	}
}

func awsAIAgentCredentialReferenceParts(ref string) (string, string) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return "credential_reference", "unknown"
	}
	if idx := strings.Index(trimmed, "="); idx > 0 {
		name := strings.TrimSpace(trimmed[:idx])
		source := strings.TrimSpace(trimmed[idx+1:])
		if source == "" {
			source = "environment"
		}
		return sanitizeCredentialReferenceToken(name), sanitizeCredentialReferenceToken(source)
	}

	if !strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "/") {
		return sanitizeCredentialReferenceToken(trimmed), ""
	}
	name := trimmed
	if lastSlash := strings.LastIndex(trimmed, "/"); lastSlash >= 0 && lastSlash < len(trimmed)-1 {
		name = trimmed[lastSlash+1:]
	} else if colonIndex := strings.LastIndex(trimmed, ":"); colonIndex >= 0 && colonIndex < len(trimmed)-1 {
		name = trimmed[colonIndex+1:]
	}
	return sanitizeCredentialReferenceToken(name), sanitizeCredentialReferenceToken(trimmed)
}

func awsAIAgentProviderKeyCount(records []AWSAIAgentIdentityRecord, match func(AWSAIAgentProviderKeyReference) bool) int {
	count := 0
	for _, record := range records {
		for _, ref := range record.ProviderKeyReferences {
			if match(ref) {
				count++
			}
		}
	}
	return count
}

func awsAIAgentProviderKeyBreakdown(records []AWSAIAgentIdentityRecord) map[string]int {
	breakdown := map[string]int{}
	for _, record := range records {
		for _, ref := range record.ProviderKeyReferences {
			if ref.Provider == "" {
				continue
			}
			breakdown[ref.Provider]++
		}
	}
	return breakdown
}

func sanitizeCredentialReferenceToken(value string) string {
	return strings.ToLower(strings.NewReplacer(" ", "-", "/", "-", ":", "-", "#", "-").Replace(strings.TrimSpace(value)))
}

func containsAnyToken(haystack string, tokens ...string) bool {
	for _, token := range tokens {
		if token != "" && strings.Contains(haystack, token) {
			return true
		}
	}
	return false
}

func awsAIAgentIdentityTypeCount(records []AWSAIAgentIdentityRecord, agentType string) int {
	count := 0
	for _, record := range records {
		if record.AgentType == agentType {
			count++
		}
	}
	return count
}

func awsAIAgentIdentityCapabilityKindCount(records []AWSAIAgentIdentityRecord, kind string) int {
	count := 0
	for _, record := range records {
		if record.CapabilityKind == kind {
			count++
		}
	}
	return count
}

func awsAIAgentIdentityUniqueCount(records []AWSAIAgentIdentityRecord, accessor func(AWSAIAgentIdentityRecord) string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		value := strings.TrimSpace(accessor(record))
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	return len(seen)
}

func awsAIAgentIdentityListCount(records []AWSAIAgentIdentityRecord, accessor func(AWSAIAgentIdentityRecord) []string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, value := range accessor(record) {
			trimmed := strings.TrimSpace(value)
			if trimmed != "" {
				seen[trimmed] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsAIAgentIdentityDiagnostics(diagnostics []providers.SourceError) []AWSAIAgentIdentityDiagnostic {
	result := make([]AWSAIAgentIdentityDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSAIAgentIdentityDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsAIAgentIdentityDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsAIAgentIdentityDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only AI agent list/describe permissions; do not add prompt, invoke, memory-content, browser-page, code-output, database-row, object-content, or secret-value reads."
	case "ai_agent_gateway_list_failed", "ai_agent_gateway_describe_failed", "ai_agent_gateway_target_list_failed", "ai_agent_gateway_target_describe_failed", "ai_agent_gateway_malformed", "ai_agent_identity_page_failed":
		return "Retry only the failed agent metadata call and keep successful normalized agent records visible."
	case "agentcore_runtime_describe_failed", "agentcore_runtime_endpoint_list_failed", "agentcore_runtime_malformed":
		return "Retry the failed AgentCore runtime metadata call and keep the surviving runtime records visible."
	case "agentcore_memory_describe_failed", "agentcore_memory_malformed", "agentcore_memory_id_missing",
		"agentcore_browser_describe_failed", "agentcore_browser_malformed", "agentcore_browser_id_missing",
		"agentcore_code_interpreter_describe_failed", "agentcore_code_interpreter_malformed", "agentcore_code_interpreter_id_missing",
		"agentcore_capability_list_failed":
		return "Retry the failed AgentCore Memory/Browser/Code Interpreter metadata call; surviving capability sources remain visible. Never read memory records, browser pages, or code-interpreter output."
	case "ai_agent_credential_reference_unresolved":
		return "Join to credential-reference metadata for ownership and rotation without exposing provider key values."
	default:
		return "Review the AI agent metadata diagnostic and retry after the scoped read-only metadata issue is corrected."
	}
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

func normalizeName(input string) string {
	trimmed := strings.TrimSpace(strings.ToLower(input))
	if trimmed == "" {
		return ""
	}
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", "#", "-", ",", "-", ".", "-")
	return strings.Trim(replacer.Replace(trimmed), "-")
}

func awsAIAgentWorkloadNodeID(record AWSAIAgentIdentityRecord) string {
	agentID := firstNonEmptyAWSValue(record.AgentID, record.AgentARN, record.AgentName)
	if strings.EqualFold(record.AgentType, "agentcore_runtime") && strings.TrimSpace(record.RuntimeVersion) != "" {
		agentID = agentID + "/" + normalizeName(record.RuntimeVersion)
	}
	if strings.TrimSpace(record.AgentNodeID) != "" {
		if idx := strings.LastIndex(record.AgentNodeID, "/"); idx >= 0 && idx < len(record.AgentNodeID)-1 {
			agentID = firstNonEmptyAWSValue(agentID, record.AgentNodeID[idx+1:])
		}
	}
	return fmt.Sprintf("aws:workload:ai-agent:%s:%s:%s/%s",
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.AgentType, "agent"),
		firstNonEmptyAWSValue(agentID, "workload"),
	)
}

func awsPartitionForAPIRegion(region string) string {
	normalized := strings.ToLower(strings.TrimSpace(region))
	switch {
	case strings.HasPrefix(normalized, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(normalized, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}
