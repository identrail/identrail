package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	rawKindAIAgentIdentity       = "ai_agent_identity"
	aiAgentIdentityCollectorName = "ai_agent_identity"
	aiAgentIdentityServiceName   = "ai-agent"
)

// AIAgentIdentity is the payload-safe normalized model for AWS-hosted AI agents.
// It records identity, role, provider/model, tool, memory, browser, and code
// capability metadata while deliberately excluding prompts, completions, memory
// contents, browser pages, code output, object contents, and secret values.
type AIAgentIdentity struct {
	awscontract.ServiceCollectorRecord
	AgentID                   string            `json:"agent_id"`
	AgentARN                  string            `json:"agent_arn,omitempty"`
	AgentName                 string            `json:"agent_name"`
	AgentType                 string            `json:"agent_type"`
	RuntimeVersion            string            `json:"runtime_version,omitempty"`
	Provider                  string            `json:"provider,omitempty"`
	ModelID                   string            `json:"model_id,omitempty"`
	RuntimeRoleARN            string            `json:"runtime_role_arn,omitempty"`
	RuntimeRoleName           string            `json:"runtime_role_name,omitempty"`
	RuntimeRoleAccountID      string            `json:"runtime_role_account_id,omitempty"`
	WorkloadIdentityARN       string            `json:"workload_identity_arn,omitempty"`
	GatewayID                 string            `json:"gateway_id,omitempty"`
	GatewayARN                string            `json:"gateway_arn,omitempty"`
	ExternalProvider          string            `json:"external_provider,omitempty"`
	ToolNames                 []string          `json:"tool_names,omitempty"`
	ToolCount                 int               `json:"tool_count"`
	MemoryEnabled             bool              `json:"memory_enabled"`
	MemoryStoreRefs           []string          `json:"memory_store_refs,omitempty"`
	BrowserEnabled            bool              `json:"browser_enabled"`
	CodeInterpreterEnabled    bool              `json:"code_interpreter_enabled"`
	CapabilityNames           []string          `json:"capability_names,omitempty"`
	CredentialReferenceRefs   []string          `json:"credential_reference_refs,omitempty"`
	ResourceReferenceRefs     []string          `json:"resource_reference_refs,omitempty"`
	ExecutionEndpointARNs     []string          `json:"execution_endpoint_arns,omitempty"`
	ExecutionEndpointNames    []string          `json:"execution_endpoint_names,omitempty"`
	ExecutionEndpointStatuses []string          `json:"execution_endpoint_statuses,omitempty"`
	ObservabilityLinks        []string          `json:"observability_links,omitempty"`
	NetworkMode               string            `json:"network_mode,omitempty"`
	ServerProtocol            string            `json:"server_protocol,omitempty"`
	SensitiveBoundary         string            `json:"sensitive_boundary"`
	CoverageStatus            string            `json:"coverage_status"`
	CoverageReason            string            `json:"coverage_reason,omitempty"`
	Status                    string            `json:"status"`
	Tags                      map[string]string `json:"tags,omitempty"`
}

type AIAgentIdentityPage struct {
	Records     []AIAgentIdentity
	NextToken   string
	Diagnostics []providers.SourceError
}

type AIAgentIdentityAPI interface {
	ListAgentIdentities(ctx context.Context, nextToken string, pageSize int32) (AIAgentIdentityPage, error)
}

type AIAgentIdentityCollector struct {
	client   AIAgentIdentityAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

type AIAgentIdentityOption func(*AIAgentIdentityCollector)

func WithAIAgentIdentityPageSize(pageSize int32) AIAgentIdentityOption {
	return func(c *AIAgentIdentityCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithAIAgentIdentityMaxPages(maxPages int) AIAgentIdentityOption {
	return func(c *AIAgentIdentityCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithAIAgentIdentityClock(now func() time.Time) AIAgentIdentityOption {
	return func(c *AIAgentIdentityCollector) {
		if now != nil {
			c.now = now
		}
	}
}

func WithAIAgentIdentitySleeper(s Sleeper) AIAgentIdentityOption {
	return func(c *AIAgentIdentityCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func NewAIAgentIdentityCollector(client AIAgentIdentityAPI, opts ...AIAgentIdentityOption) *AIAgentIdentityCollector {
	c := &AIAgentIdentityCollector{
		client:   client,
		pageSize: defaultPageSize,
		maxPages: defaultMaxPages,
		retry: RetryPolicy{
			MaxRetries: defaultRetryCount,
			BaseDelay:  defaultBaseDelay,
			MaxDelay:   defaultMaxDelay,
		},
		jitter: defaultRetryJitterRatio,
		sleep:  defaultSleeper,
		randFn: rand.Float64,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *AIAgentIdentityCollector) ServiceName() string {
	return aiAgentIdentityServiceName
}

func (c *AIAgentIdentityCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: aiAgentIdentityServiceName})
	return assets, err
}

func (c *AIAgentIdentityCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("ai agent identity collector requires client")
	}
	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}
	assets := []providers.RawAsset{}
	issues := []providers.SourceError{}
	addIssue := func(issue providers.SourceError) {
		if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
			return
		}
		issues = append(issues, issue)
	}
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()
	for page := 1; ; page++ {
		if page > c.maxPages {
			addIssue(providers.SourceError{
				Collector: aiAgentIdentityCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "ai_agent_identity_page_limit_exceeded",
				Message:   fmt.Sprintf("ai agent identity collection exceeded max pages (%d)", c.maxPages),
				Retryable: false,
			})
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("ai agent identity collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (AIAgentIdentityPage, error) {
			return c.client.ListAgentIdentities(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list ai agent identities page %d: %w", page, err)
			addIssue(providers.SourceError{
				Collector: aiAgentIdentityCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "ai_agent_identity_page_failed",
				Message:   wrapped.Error(),
				Retryable: isRetryable(err),
			})
			snapshot := append([]providers.SourceError(nil), issues...)
			if len(assets) > 0 {
				return assets, snapshot, wrapped
			}
			return nil, snapshot, wrapped
		}
		for _, diagnostic := range response.Diagnostics {
			addIssue(diagnostic)
		}
		for _, record := range response.Records {
			normalized := normalizeAIAgentIdentityScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.AgentName) == "" &&
				strings.TrimSpace(normalized.AgentID) == "" &&
				strings.TrimSpace(normalized.AgentARN) == "" &&
				strings.TrimSpace(normalized.GatewayID) == "" &&
				strings.TrimSpace(normalized.GatewayARN) == "" {
				addIssue(providers.SourceError{
					Collector: aiAgentIdentityCollectorName,
					Code:      "malformed_ai_agent_identity",
					Message:   "skipped ai agent identity without a stable identity or gateway identifier",
					Retryable: false,
				})
				continue
			}
			sourceID := aiAgentIdentitySourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("marshal ai agent identity %s: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindAIAgentIdentity,
				SourceID:  sourceID,
				Payload:   payload,
				Collected: collectedAt.Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}
		if strings.TrimSpace(response.NextToken) == "" {
			break
		}
		nextToken = response.NextToken
	}
	return assets, append([]providers.SourceError(nil), issues...), nil
}

func normalizeAIAgentIdentityScope(scope AWSCollectorScope, record AIAgentIdentity, collectedAt time.Time) AIAgentIdentity {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, aiAgentIdentityServiceName)
	normalized.AgentID = strings.TrimSpace(record.AgentID)
	normalized.AgentARN = strings.TrimSpace(record.AgentARN)
	normalized.AgentName = firstNonEmptyAWSValue(record.AgentName, normalized.AgentID)
	normalized.AgentType = canonicalAIAgentType(record.AgentType, record.Service)
	normalized.RuntimeVersion = strings.TrimSpace(record.RuntimeVersion)
	normalized.Provider = strings.TrimSpace(record.Provider)
	normalized.ModelID = strings.TrimSpace(record.ModelID)
	normalized.RuntimeRoleARN = firstNonEmptyAWSValue(record.RuntimeRoleARN, record.RoleARN)
	normalized.RuntimeRoleName = firstNonEmptyAWSValue(record.RuntimeRoleName, roleNameFromARN(record.RuntimeRoleARN), roleNameFromARN(record.RoleARN))
	normalized.RuntimeRoleAccountID = firstNonEmptyAWSValue(record.RuntimeRoleAccountID, roleAccountIDFromARN(record.RuntimeRoleARN), roleAccountIDFromARN(record.RoleARN))
	normalized.WorkloadIdentityARN = strings.TrimSpace(record.WorkloadIdentityARN)
	normalized.RoleARN = normalized.RuntimeRoleARN
	normalized.WorkloadID = aiAgentIdentityWorkloadID(normalized)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.AgentName)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, normalized.AgentType)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "ai_agent_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.AgentARN, normalized.AgentID)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, aiAgentIdentityCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-ai-agent-identity-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.GatewayID = strings.TrimSpace(record.GatewayID)
	normalized.GatewayARN = strings.TrimSpace(record.GatewayARN)
	normalized.ExternalProvider = strings.TrimSpace(record.ExternalProvider)
	normalized.ToolNames = normalizeStringList(record.ToolNames)
	normalized.ToolCount = len(normalized.ToolNames)
	normalized.MemoryStoreRefs = normalizeStringList(record.MemoryStoreRefs)
	normalized.CapabilityNames = normalizeStringList(record.CapabilityNames)
	normalized.CredentialReferenceRefs = normalizeStringList(record.CredentialReferenceRefs)
	normalized.ResourceReferenceRefs = normalizeStringList(record.ResourceReferenceRefs)
	normalized.ExecutionEndpointARNs = normalizeOrderedStringList(record.ExecutionEndpointARNs)
	normalized.ExecutionEndpointNames = normalizeOrderedStringList(record.ExecutionEndpointNames)
	normalized.ExecutionEndpointStatuses = normalizeOrderedStringList(record.ExecutionEndpointStatuses)
	normalized.ObservabilityLinks = normalizeOrderedStringList(record.ObservabilityLinks)
	normalized.NetworkMode = strings.TrimSpace(record.NetworkMode)
	normalized.ServerProtocol = strings.TrimSpace(record.ServerProtocol)
	if len(normalized.ExecutionEndpointARNs) > 0 {
		normalized.ResourceReferenceRefs = normalizeStringList(append(normalized.ResourceReferenceRefs, normalized.ExecutionEndpointARNs...))
	}
	if normalized.WorkloadIdentityARN != "" {
		normalized.ResourceReferenceRefs = normalizeStringList(append(normalized.ResourceReferenceRefs, normalized.WorkloadIdentityARN))
	}
	if normalized.NetworkMode != "" {
		normalized.CapabilityNames = appendUnique(normalized.CapabilityNames, "runtime_network_"+strings.ToLower(normalized.NetworkMode))
	}
	if normalized.ServerProtocol != "" {
		normalized.CapabilityNames = appendUnique(normalized.CapabilityNames, "runtime_protocol_"+strings.ToLower(normalized.ServerProtocol))
	}
	if normalized.WorkloadIdentityARN != "" {
		normalized.CapabilityNames = appendUnique(normalized.CapabilityNames, "workload_identity")
	}
	if len(normalized.ExecutionEndpointARNs) > 0 {
		normalized.CapabilityNames = appendUnique(normalized.CapabilityNames, "execution_endpoint")
	}
	if len(normalized.ObservabilityLinks) > 0 {
		normalized.CapabilityNames = appendUnique(normalized.CapabilityNames, "observability")
	}
	normalized.SensitiveBoundary = firstNonEmptyAWSValue(record.SensitiveBoundary, "metadata_only")
	normalized.CoverageStatus = firstNonEmptyAWSValue(record.CoverageStatus, "covered")
	normalized.Status = firstNonEmptyAWSValue(record.Status, "ready")
	normalized.Tags = copyTags(record.Tags)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = aiAgentIdentityConfidence(normalized)
	}
	return normalized
}

func aiAgentIdentitySourceID(record AIAgentIdentity) string {
	return strings.Join([]string{
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.AgentType, "agent"),
		aiAgentIdentityWorkloadSourceID(record),
	}, "|")
}

func aiAgentIdentityAgentRef(record AIAgentIdentity) string {
	agentType := canonicalAIAgentType(record.AgentType, record.Service)
	agentRef := firstNonEmptyAWSValue(record.AgentARN, record.AgentID, record.AgentName)
	if agentType == "agentcore_runtime" {
		agentRef = firstNonEmptyAWSValue(record.AgentID, record.AgentARN, record.AgentName)
		if version := strings.TrimSpace(record.RuntimeVersion); version != "" {
			agentRef = agentRef + "/" + normalizeName(version)
		}
	}
	return agentRef
}

func aiAgentIdentityNodeRef(record AIAgentIdentity) string {
	agentRef := aiAgentIdentityAgentRef(record)
	if canonicalAIAgentType(record.AgentType, record.Service) == "agent_gateway" {
		return firstNonEmptyAWSValue(record.GatewayID, record.GatewayARN, agentRef)
	}
	return firstNonEmptyAWSValue(agentRef, record.GatewayID, record.GatewayARN)
}

func aiAgentIdentityNodeIdentity(record AIAgentIdentity) string {
	if canonicalAIAgentType(record.AgentType, record.Service) == "agent_gateway" {
		return firstNonEmptyAWSValue(record.GatewayID, record.GatewayARN, record.AgentID, record.AgentARN, record.AgentName)
	}
	return firstNonEmptyAWSValue(record.AgentID, record.AgentARN, record.AgentName)
}

func aiAgentIdentityWorkloadSourceID(record AIAgentIdentity) string {
	return aiAgentIdentityNodeRef(record)
}

func aiAgentIdentityWorkloadID(record AIAgentIdentity) string {
	agentRef := aiAgentIdentityAgentRef(record)
	if canonicalAIAgentType(record.AgentType, record.Service) == "agent_gateway" {
		return firstNonEmptyAWSValue(
			record.WorkloadID,
			aiAgentIdentityNodeRef(record),
		)
	}
	return firstNonEmptyAWSValue(
		agentRef,
		record.WorkloadID,
		record.GatewayID,
		record.GatewayARN,
	)
}

func canonicalAIAgentType(agentType string, service string) string {
	switch strings.ToLower(strings.TrimSpace(agentType)) {
	case "bedrock_agent", "bedrock":
		return "bedrock_agent"
	case "agentcore_runtime", "agentcore":
		return "agentcore_runtime"
	case "custom_agent", "custom":
		return "custom_agent"
	case "external_provider_agent", "external":
		return "external_provider_agent"
	case "agent_gateway", "gateway":
		return "agent_gateway"
	}
	if strings.EqualFold(strings.TrimSpace(service), "bedrock") {
		return "bedrock_agent"
	}
	return "custom_agent"
}

func aiAgentIdentityConfidence(record AIAgentIdentity) float64 {
	confidence := 0.72
	if strings.TrimSpace(record.RuntimeRoleARN) != "" {
		confidence += 0.08
	}
	if strings.TrimSpace(record.RuntimeVersion) != "" {
		confidence += 0.03
	}
	if strings.TrimSpace(record.AgentARN) != "" {
		confidence += 0.06
	}
	if len(record.ToolNames) > 0 || len(record.CapabilityNames) > 0 {
		confidence += 0.05
	}
	if len(record.CredentialReferenceRefs) > 0 {
		confidence += 0.04
	}
	if strings.TrimSpace(record.WorkloadIdentityARN) != "" {
		confidence += 0.03
	}
	if len(record.ExecutionEndpointARNs) > 0 {
		confidence += 0.04
	}
	if len(record.ObservabilityLinks) > 0 {
		confidence += 0.02
	}
	if strings.TrimSpace(record.NetworkMode) != "" || strings.TrimSpace(record.ServerProtocol) != "" {
		confidence += 0.02
	}
	if confidence > 0.95 {
		return 0.95
	}
	return confidence
}
