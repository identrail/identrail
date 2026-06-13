package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	bedrockAgentsCollectorName = "bedrock_agents"
	bedrockAgentsServiceName   = "bedrock"
	bedrockAgentType           = "bedrock_agent"
)

// errBedrockAgentDetailSkipped marks a summary whose detail fetch was
// intentionally skipped (for example an ARN-only summary). It is used to flip
// the coverage_status onto the degraded path without producing a misleading
// "GetAgent("") failed" diagnostic.
var errBedrockAgentDetailSkipped = errors.New("bedrock agent detail skipped: missing agent id")
var errBedrockAgentDetailIncomplete = errors.New("bedrock agent detail returned diagnostics")

// BedrockAgentSummary is the minimal identity row returned by ListAgents. The
// summary is intentionally narrow: prompts, instructions, embedded model
// arguments, and any large operator-authored configuration text are never
// captured.
type BedrockAgentSummary struct {
	AgentID                     string            `json:"agent_id"`
	AgentARN                    string            `json:"agent_arn,omitempty"`
	AgentName                   string            `json:"agent_name"`
	AgentStatus                 string            `json:"agent_status,omitempty"`
	AgentVersion                string            `json:"agent_version,omitempty"`
	FoundationModel             string            `json:"foundation_model,omitempty"`
	RoleARN                     string            `json:"role_arn,omitempty"`
	GuardrailID                 string            `json:"guardrail_id,omitempty"`
	GuardrailVersion            string            `json:"guardrail_version,omitempty"`
	CustomerEncryptionKMSKeyARN string            `json:"customer_encryption_kms_key_arn,omitempty"`
	UpdatedAt                   *time.Time        `json:"updated_at,omitempty"`
	Tags                        map[string]string `json:"tags,omitempty"`
}

// BedrockAgentDetail captures the agent's action groups, knowledge base
// references, alias names, and (metadata-only) capability indicators. It never
// stores instruction text, prompt overrides, action-group OpenAPI bodies, or
// Lambda payloads.
type BedrockAgentDetail struct {
	ActionGroupNames        []string `json:"action_group_names,omitempty"`
	ActionGroupExecutorARNs []string `json:"action_group_executor_arns,omitempty"`
	KnowledgeBaseIDs        []string `json:"knowledge_base_ids,omitempty"`
	AliasNames              []string `json:"alias_names,omitempty"`
	AliasARNs               []string `json:"alias_arns,omitempty"`
	HasInstruction          bool     `json:"has_instruction"`
	HasPromptOverride       bool     `json:"has_prompt_override"`
}

// BedrockAgentsPage is one page of paginated agent identities.
type BedrockAgentsPage struct {
	Agents      []BedrockAgentSummary
	NextToken   string
	Diagnostics []providers.SourceError
}

// BedrockAgentsAPI is the metadata-only Bedrock Agents surface the collector
// consumes. The interface is small and read-only so adapters (the SDK shim,
// fixtures, and tests) can implement it without pulling in additional AWS
// permissions or coupling the collector to the AWS SDK.
type BedrockAgentsAPI interface {
	ListAgents(ctx context.Context, nextToken string, pageSize int32) (BedrockAgentsPage, error)
	GetAgentDetail(ctx context.Context, agentID string) (BedrockAgentDetail, []providers.SourceError, error)
}

// BedrockAgentsCollector emits AI agent identity records for AWS Bedrock-hosted
// agents. It is bounded, retryable, deduplicating, and emits explicit
// per-source diagnostics for partial failure so downstream pipelines can
// distinguish empty-but-authorized results from incomplete data.
type BedrockAgentsCollector struct {
	client   BedrockAgentsAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

// BedrockAgentsOption customizes BedrockAgentsCollector behavior.
type BedrockAgentsOption func(*BedrockAgentsCollector)

// WithBedrockAgentsPageSize configures agent list pagination size.
func WithBedrockAgentsPageSize(pageSize int32) BedrockAgentsOption {
	return func(c *BedrockAgentsCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithBedrockAgentsMaxPages limits paginations to guard against runaways.
func WithBedrockAgentsMaxPages(maxPages int) BedrockAgentsOption {
	return func(c *BedrockAgentsCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithBedrockAgentsRetryPolicy customizes retry strategy for transient errors.
func WithBedrockAgentsRetryPolicy(policy RetryPolicy) BedrockAgentsOption {
	return func(c *BedrockAgentsCollector) {
		if policy.MaxRetries >= 0 {
			c.retry.MaxRetries = policy.MaxRetries
		}
		if policy.BaseDelay > 0 {
			c.retry.BaseDelay = policy.BaseDelay
		}
		if policy.MaxDelay > 0 {
			c.retry.MaxDelay = policy.MaxDelay
		}
	}
}

// WithBedrockAgentsRetryJitterRatio configures jitter around retry backoff.
func WithBedrockAgentsRetryJitterRatio(ratio float64) BedrockAgentsOption {
	return func(c *BedrockAgentsCollector) {
		if ratio < 0 {
			ratio = 0
		}
		c.jitter = ratio
	}
}

// WithBedrockAgentsSleeper injects a Sleeper (test seam).
func WithBedrockAgentsSleeper(s Sleeper) BedrockAgentsOption {
	return func(c *BedrockAgentsCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithBedrockAgentsRandFn injects deterministic randomness (test seam).
func WithBedrockAgentsRandFn(randFn func() float64) BedrockAgentsOption {
	return func(c *BedrockAgentsCollector) {
		if randFn != nil {
			c.randFn = randFn
		}
	}
}

// WithBedrockAgentsClock injects deterministic time for tests.
func WithBedrockAgentsClock(now func() time.Time) BedrockAgentsOption {
	return func(c *BedrockAgentsCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewBedrockAgentsCollector constructs a Bedrock Agents collector.
func NewBedrockAgentsCollector(client BedrockAgentsAPI, opts ...BedrockAgentsOption) *BedrockAgentsCollector {
	c := &BedrockAgentsCollector{
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

// ServiceName returns the service identifier for diagnostics and partial
// failure scoping.
func (c *BedrockAgentsCollector) ServiceName() string {
	return bedrockAgentsServiceName
}

// Collect runs the collector without an explicit scope.
func (c *BedrockAgentsCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: bedrockAgentsServiceName})
	return assets, err
}

// CollectWithDiagnostics enumerates Bedrock agents, captures their detail, and
// emits one AIAgentIdentity raw asset per agent. Per-agent detail failures are
// reported as partial failures so the overall run can succeed with surviving
// agents while operators see exactly which agents lack full evidence.
func (c *BedrockAgentsCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("bedrock agents collector requires client")
	}
	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}
	collectedAt := c.now().UTC()
	assets := []providers.RawAsset{}
	issues := []providers.SourceError{}
	seen := map[string]struct{}{}

	addIssue := func(issue providers.SourceError) {
		if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
			return
		}
		issues = append(issues, issue)
	}

	nextToken := ""
	for page := 1; ; page++ {
		if page > c.maxPages {
			addIssue(providers.SourceError{
				Collector: bedrockAgentsCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "bedrock_agents_page_limit_exceeded",
				Message:   fmt.Sprintf("bedrock agent collection exceeded max pages (%d)", c.maxPages),
				Retryable: false,
			})
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("bedrock agent collection exceeded max pages (%d)", c.maxPages)
		}
		listResp, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (BedrockAgentsPage, error) {
			return c.client.ListAgents(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list bedrock agents page %d: %w", page, err)
			addIssue(providers.SourceError{
				Collector: bedrockAgentsCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "bedrock_agents_list_failed",
				Message:   wrapped.Error(),
				Retryable: isRetryable(err),
			})
			snapshot := append([]providers.SourceError(nil), issues...)
			if len(assets) > 0 {
				return assets, snapshot, wrapped
			}
			return nil, snapshot, wrapped
		}
		for _, diagnostic := range listResp.Diagnostics {
			addIssue(diagnostic)
		}
		for _, summary := range listResp.Agents {
			if strings.TrimSpace(summary.AgentID) == "" && strings.TrimSpace(summary.AgentARN) == "" {
				addIssue(providers.SourceError{
					Collector: bedrockAgentsCollectorName,
					Code:      "malformed_bedrock_agent",
					Message:   "skipped bedrock agent without a stable identifier",
					Retryable: false,
				})
				continue
			}
			// GetAgentDetail requires the AgentID (the short identifier AWS uses
			// in the Bedrock control plane); calling it with an empty id would
			// produce a misleading per-agent diagnostic. ARN-only summaries are
			// kept as partial records so operators see the identity but know
			// detail evidence is missing until a follow-up list call returns a
			// proper id.
			var (
				detail    BedrockAgentDetail
				detailErr error
				agentID   = strings.TrimSpace(summary.AgentID)
			)
			if agentID == "" {
				addIssue(providers.SourceError{
					Collector: bedrockAgentsCollectorName,
					SourceID:  strings.TrimSpace(summary.AgentARN),
					Code:      "bedrock_agent_detail_skipped_missing_id",
					Message:   "skipped GetAgentDetail for ARN-only bedrock agent summary; surfaced summary only",
					Retryable: true,
				})
				detailErr = errBedrockAgentDetailSkipped
			} else {
				var detailIssues []providers.SourceError
				detail, detailIssues, detailErr = c.getDetailWithRetry(ctx, agentID)
				for _, diagnostic := range detailIssues {
					addIssue(diagnostic)
				}
				// Adapters may return diagnostics with a nil error (for example a
				// fixture flagging "not seeded" or an SDK adapter that returned a
				// partial response). Treat that as incomplete evidence so the
				// emitted record is degraded rather than appearing authoritative,
				// but keep it separate from a hard failure so operators can
				// distinguish retry-worthy partial detail from a fatal denial.
				switch {
				case detailErr != nil:
					addIssue(providers.SourceError{
						Collector: bedrockAgentsCollectorName,
						SourceID:  agentID,
						Code:      "bedrock_agent_detail_failed",
						Message:   fmt.Sprintf("agent %s detail fetch failed: %v", agentID, detailErr),
						Retryable: isRetryable(detailErr),
					})
				case len(detailIssues) > 0:
					detailErr = errBedrockAgentDetailIncomplete
					addIssue(providers.SourceError{
						Collector: bedrockAgentsCollectorName,
						SourceID:  agentID,
						Code:      "bedrock_agent_detail_incomplete",
						Message:   fmt.Sprintf("agent %s detail returned diagnostics; surfaced summary only", agentID),
						Retryable: true,
					})
				}
			}
			record := buildBedrockAgentIdentity(scope, summary, detail, detailErr, collectedAt)
			sourceID := aiAgentIdentitySourceID(record)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, marshalErr := json.Marshal(record)
			if marshalErr != nil {
				return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("marshal bedrock agent %s: %w", sourceID, marshalErr)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindAIAgentIdentity,
				SourceID:  sourceID,
				Payload:   payload,
				Collected: collectedAt.Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}
		if strings.TrimSpace(listResp.NextToken) == "" {
			break
		}
		nextToken = listResp.NextToken
	}
	return assets, append([]providers.SourceError(nil), issues...), nil
}

func (c *BedrockAgentsCollector) getDetailWithRetry(ctx context.Context, agentID string) (BedrockAgentDetail, []providers.SourceError, error) {
	type detailResult struct {
		detail BedrockAgentDetail
		issues []providers.SourceError
	}
	result, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (detailResult, error) {
		detail, issues, err := c.client.GetAgentDetail(callCtx, agentID)
		return detailResult{detail: detail, issues: issues}, err
	})
	return result.detail, result.issues, err
}

// buildBedrockAgentIdentity composes the metadata-only AIAgentIdentity record
// the AI agent identity model already understands. Provider, capabilities, and
// confidence are derived deterministically from the summary + detail.
func buildBedrockAgentIdentity(scope AWSCollectorScope, summary BedrockAgentSummary, detail BedrockAgentDetail, detailErr error, collectedAt time.Time) AIAgentIdentity {
	roleARN := strings.TrimSpace(summary.RoleARN)
	record := AIAgentIdentity{
		AgentID:                 summary.AgentID,
		AgentARN:                summary.AgentARN,
		AgentName:               firstNonEmptyAWSValue(summary.AgentName, summary.AgentID),
		AgentType:               bedrockAgentType,
		Provider:                "amazon-bedrock",
		ModelID:                 strings.TrimSpace(summary.FoundationModel),
		RuntimeRoleARN:          roleARN,
		RuntimeRoleName:         roleNameFromARN(roleARN),
		RuntimeRoleAccountID:    roleAccountIDFromARN(roleARN),
		ToolNames:               dedupeAndSortStrings(detail.ActionGroupNames),
		MemoryEnabled:           len(detail.KnowledgeBaseIDs) > 0,
		MemoryStoreRefs:         dedupeAndSortStrings(prefixKnowledgeBaseRefs(detail.KnowledgeBaseIDs)),
		BrowserEnabled:          false,
		CodeInterpreterEnabled:  false,
		CapabilityNames:         bedrockAgentCapabilityNames(detail, summary),
		CredentialReferenceRefs: dedupeAndSortStrings(bedrockAgentCredentialRefs(detail.ActionGroupExecutorARNs, summary.CustomerEncryptionKMSKeyARN)),
		SensitiveBoundary:       "metadata_only",
		CoverageStatus:          "covered",
		Status:                  bedrockAgentStatus(summary.AgentStatus),
		Tags:                    copyTags(summary.Tags),
	}
	record.ToolCount = len(record.ToolNames)
	record.ServiceCollectorRecord = awscontract.ServiceCollectorRecord{
		TenantID:      scope.TenantID,
		WorkspaceID:   scope.WorkspaceID,
		ProjectID:     scope.ProjectID,
		ConnectorID:   scope.ConnectorID,
		ScanID:        scope.ScanID,
		AccountID:     firstNonEmptyAWSValue(scope.AccountID),
		Region:        firstNonEmptyAWSValue(scope.Region),
		Service:       bedrockAgentsServiceName,
		WorkloadID:    firstNonEmptyAWSValue(summary.AgentARN, summary.AgentID),
		WorkloadName:  record.AgentName,
		WorkloadType:  bedrockAgentType,
		RoleARN:       roleARN,
		Source:        "bedrock_agent_metadata",
		EvidenceRef:   firstNonEmptyAWSValue(summary.AgentARN, summary.AgentID),
		CollectorName: bedrockAgentsCollectorName,
		CollectedAt:   collectedAt,
	}
	if detailErr != nil {
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		switch {
		case errors.Is(detailErr, errBedrockAgentDetailSkipped):
			record.CoverageReason = "bedrock agent detail skipped: ARN-only summary; surfaced summary only"
		case errors.Is(detailErr, errBedrockAgentDetailIncomplete):
			record.CoverageReason = "bedrock agent detail returned diagnostics without a hard failure; surfaced summary only"
		default:
			record.CoverageReason = "bedrock agent detail fetch failed; surfaced summary only"
		}
	}
	if len(detail.AliasNames) > 0 {
		record.CapabilityNames = appendUnique(record.CapabilityNames, "aliases")
	}
	if detail.HasPromptOverride {
		record.CapabilityNames = appendUnique(record.CapabilityNames, "prompt_override_configured")
	}
	if detail.HasInstruction {
		record.CapabilityNames = appendUnique(record.CapabilityNames, "instruction_configured")
	}
	if strings.TrimSpace(summary.GuardrailID) != "" {
		record.CapabilityNames = appendUnique(record.CapabilityNames, "guardrail")
	}
	sort.Strings(record.CapabilityNames)
	if record.Confidence <= 0 {
		record.Confidence = aiAgentIdentityConfidence(record)
	}
	return record
}

func bedrockAgentCapabilityNames(detail BedrockAgentDetail, summary BedrockAgentSummary) []string {
	caps := []string{}
	if len(detail.ActionGroupNames) > 0 {
		caps = append(caps, "tool_use")
	}
	if len(detail.KnowledgeBaseIDs) > 0 {
		caps = append(caps, "knowledge_base")
	}
	if strings.TrimSpace(summary.CustomerEncryptionKMSKeyARN) != "" {
		caps = append(caps, "customer_encryption_kms")
	}
	if strings.TrimSpace(summary.FoundationModel) != "" {
		caps = append(caps, "foundation_model")
	}
	return dedupeAndSortStrings(caps)
}

func bedrockAgentCredentialRefs(executorARNs []string, kmsKeyARN string) []string {
	refs := make([]string, 0, len(executorARNs)+1)
	for _, executor := range executorARNs {
		ref := strings.TrimSpace(executor)
		if ref == "" {
			continue
		}
		refs = append(refs, "action_group_executor:"+ref)
	}
	if trimmed := strings.TrimSpace(kmsKeyARN); trimmed != "" {
		refs = append(refs, "kms:"+trimmed)
	}
	return refs
}

func bedrockAgentStatus(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch normalized {
	case "":
		return "ready"
	case "prepared", "ready":
		return "ready"
	case "preparing", "updating", "versioning":
		return "preparing"
	case "deleting":
		return "deleting"
	case "failed":
		return "failed"
	case "not_prepared":
		return "not_prepared"
	default:
		return normalized
	}
}

func prefixKnowledgeBaseRefs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		out = append(out, "bedrock-knowledge-base/"+trimmed)
	}
	return out
}

func dedupeAndSortStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
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

func appendUnique(values []string, candidate string) []string {
	for _, existing := range values {
		if existing == candidate {
			return values
		}
	}
	return append(values, candidate)
}
