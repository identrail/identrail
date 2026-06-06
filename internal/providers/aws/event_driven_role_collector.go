package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	rawKindEventDrivenRole       = "event_driven_role"
	eventDrivenRoleCollectorName = "event_driven_role"
	eventDrivenServiceName       = "eventbridge"
)

type EventDrivenRole struct {
	awscontract.ServiceCollectorRecord
	RoleName               string            `json:"role_name,omitempty"`
	RoleKind               string            `json:"role_kind,omitempty"`
	RoleAccountID          string            `json:"role_account_id,omitempty"`
	WorkloadARN            string            `json:"workload_arn,omitempty"`
	EventBusName           string            `json:"event_bus_name,omitempty"`
	EventBusARN            string            `json:"event_bus_arn,omitempty"`
	ScheduleGroupName      string            `json:"schedule_group_name,omitempty"`
	ScheduleExpression     string            `json:"schedule_expression,omitempty"`
	ScheduleTimezone       string            `json:"schedule_timezone,omitempty"`
	PipeSourceARN          string            `json:"pipe_source_arn,omitempty"`
	PipeTargetARN          string            `json:"pipe_target_arn,omitempty"`
	PipeEnrichmentARN      string            `json:"pipe_enrichment_arn,omitempty"`
	TargetARN              string            `json:"target_arn,omitempty"`
	TargetID               string            `json:"target_id,omitempty"`
	TargetService          string            `json:"target_service,omitempty"`
	DeadLetterARNs         []string          `json:"dead_letter_arns,omitempty"`
	RetryMaximumAgeSeconds int32             `json:"retry_maximum_age_seconds,omitempty"`
	RetryMaximumAttempts   int32             `json:"retry_maximum_attempts,omitempty"`
	EventPatternSHA256     string            `json:"event_pattern_sha256,omitempty"`
	InputTransformerSHA256 string            `json:"input_transformer_sha256,omitempty"`
	InputPathConfigured    bool              `json:"input_path_configured,omitempty"`
	TargetInputConfigured  bool              `json:"target_input_configured,omitempty"`
	ExecutionDataLogging   bool              `json:"execution_data_logging,omitempty"`
	LogDestinationARNs     []string          `json:"log_destination_arns,omitempty"`
	KMSKeyARN              string            `json:"kms_key_arn,omitempty"`
	Active                 bool              `json:"active"`
	Disabled               bool              `json:"disabled"`
	StateReason            string            `json:"state_reason,omitempty"`
	Tags                   map[string]string `json:"tags,omitempty"`
}

type EventDrivenRolePage struct {
	Records     []EventDrivenRole
	NextToken   string
	Diagnostics []providers.SourceError
}

type EventDrivenRoleAPI interface {
	ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (EventDrivenRolePage, error)
}

type EventDrivenRoleCollector struct {
	client   EventDrivenRoleAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

type EventDrivenRoleOption func(*EventDrivenRoleCollector)

func WithEventDrivenRolePageSize(pageSize int32) EventDrivenRoleOption {
	return func(c *EventDrivenRoleCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithEventDrivenRoleMaxPages(maxPages int) EventDrivenRoleOption {
	return func(c *EventDrivenRoleCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithEventDrivenRoleRetryPolicy(policy RetryPolicy) EventDrivenRoleOption {
	return func(c *EventDrivenRoleCollector) {
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

func WithEventDrivenRoleSleeper(s Sleeper) EventDrivenRoleOption {
	return func(c *EventDrivenRoleCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func WithEventDrivenRoleClock(now func() time.Time) EventDrivenRoleOption {
	return func(c *EventDrivenRoleCollector) {
		if now != nil {
			c.now = now
		}
	}
}

func NewEventDrivenRoleCollector(client EventDrivenRoleAPI, opts ...EventDrivenRoleOption) *EventDrivenRoleCollector {
	c := &EventDrivenRoleCollector{
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

func (c *EventDrivenRoleCollector) ServiceName() string {
	return eventDrivenServiceName
}

func (c *EventDrivenRoleCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: eventDrivenServiceName})
	return assets, err
}

func (c *EventDrivenRoleCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("event-driven role collector requires client")
	}
	c.issues = c.issues[:0]
	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}
	assets := make([]providers.RawAsset, 0, c.pageSize)
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()
	for page := 1; ; page++ {
		if page > c.maxPages {
			return nil, nil, fmt.Errorf("event-driven role collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (EventDrivenRolePage, error) {
			return c.client.ListServiceRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list event-driven roles page %d: %w", page, err)
			c.addIssue(providers.SourceError{
				Collector: eventDrivenRoleCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "event_driven_role_page_failed",
				Message:   wrapped.Error(),
				Retryable: isRetryable(err),
			})
			issues := append([]providers.SourceError(nil), c.issues...)
			if len(assets) > 0 {
				return assets, issues, wrapped
			}
			return nil, issues, wrapped
		}
		for _, diagnostic := range response.Diagnostics {
			c.addIssue(diagnostic)
		}
		for _, record := range response.Records {
			normalized := normalizeEventDrivenRoleScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.WorkloadARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: eventDrivenRoleCollectorName,
					Code:      "malformed_source_record",
					Message:   "skipped EventBridge/Scheduler/Pipes record without workload identity",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: eventDrivenRoleCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.WorkloadARN, normalized.WorkloadName, normalized.WorkloadID),
					Code:      "missing_event_driven_role",
					Message:   "EventBridge, Scheduler, or Pipes record did not include an invocation role ARN",
					Retryable: false,
				})
				continue
			}
			sourceID := eventDrivenRoleSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal event-driven role %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindEventDrivenRole,
				SourceID:  sourceID,
				Payload:   payload,
				Collected: collectedAt.Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}
		if response.NextToken == "" {
			break
		}
		nextToken = response.NextToken
	}
	return assets, append([]providers.SourceError(nil), c.issues...), nil
}

func (c *EventDrivenRoleCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeEventDrivenRoleScope(scope AWSCollectorScope, record EventDrivenRole, collectedAt time.Time) EventDrivenRole {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, eventDrivenServiceName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(record.RoleARN))
	normalized.RoleKind = firstNonEmptyAWSValue(record.RoleKind, eventDrivenDefaultRoleKind(record))
	normalized.RoleAccountID = firstNonEmptyAWSValue(record.RoleAccountID, roleAccountIDFromARN(normalized.RoleARN))
	normalized.WorkloadARN = strings.TrimSpace(record.WorkloadARN)
	normalized.WorkloadType = canonicalEventDrivenWorkloadType(record.WorkloadType, record.Service)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.WorkloadARN, normalized.WorkloadName)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, eventDrivenNameFromARN(normalized.WorkloadARN))
	normalized.Source = firstNonEmptyAWSValue(record.Source, eventDrivenDefaultSource(record))
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.WorkloadARN, normalized.TargetARN, normalized.RoleARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, eventDrivenRoleCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-event-driven-role-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.EventBusName = strings.TrimSpace(record.EventBusName)
	normalized.EventBusARN = strings.TrimSpace(record.EventBusARN)
	normalized.ScheduleGroupName = strings.TrimSpace(record.ScheduleGroupName)
	normalized.ScheduleExpression = strings.TrimSpace(record.ScheduleExpression)
	normalized.ScheduleTimezone = strings.TrimSpace(record.ScheduleTimezone)
	normalized.PipeSourceARN = strings.TrimSpace(record.PipeSourceARN)
	normalized.PipeTargetARN = strings.TrimSpace(record.PipeTargetARN)
	normalized.PipeEnrichmentARN = strings.TrimSpace(record.PipeEnrichmentARN)
	normalized.TargetARN = strings.TrimSpace(record.TargetARN)
	normalized.TargetID = strings.TrimSpace(record.TargetID)
	normalized.TargetService = firstNonEmptyAWSValue(record.TargetService, awsServiceFromARN(record.TargetARN), awsServiceFromARN(record.PipeTargetARN))
	normalized.DeadLetterARNs = normalizeStringList(record.DeadLetterARNs)
	normalized.EventPatternSHA256 = strings.TrimSpace(record.EventPatternSHA256)
	normalized.InputTransformerSHA256 = strings.TrimSpace(record.InputTransformerSHA256)
	normalized.LogDestinationARNs = normalizeStringList(record.LogDestinationARNs)
	normalized.KMSKeyARN = strings.TrimSpace(record.KMSKeyARN)
	normalized.StateReason = strings.TrimSpace(record.StateReason)
	normalized.Tags = copyTags(record.Tags)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = eventDrivenRoleConfidence(normalized)
	}
	return normalized
}

func eventDrivenDefaultRoleKind(record EventDrivenRole) string {
	switch canonicalEventDrivenWorkloadType(record.WorkloadType, record.Service) {
	case "scheduler_schedule":
		return "scheduler_schedule_role"
	case "eventbridge_pipe":
		return "pipe_execution_role"
	default:
		if strings.TrimSpace(record.TargetID) != "" {
			return "eventbridge_target_role"
		}
		return "eventbridge_rule_role"
	}
}

func eventDrivenDefaultWorkloadType(record EventDrivenRole) string {
	return canonicalEventDrivenWorkloadType("", record.Service)
}

func canonicalEventDrivenWorkloadType(workloadType string, service string) string {
	switch strings.ToLower(strings.TrimSpace(workloadType)) {
	case "eventbridge_rule", "rule":
		return "eventbridge_rule"
	case "scheduler_schedule", "schedule":
		return "scheduler_schedule"
	case "eventbridge_pipe", "pipe":
		return "eventbridge_pipe"
	}
	trimmedType := strings.TrimSpace(workloadType)
	if trimmedType != "" {
		return trimmedType
	}
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "scheduler":
		return "scheduler_schedule"
	case "pipes":
		return "eventbridge_pipe"
	default:
		return "eventbridge_rule"
	}
}

func eventDrivenDefaultSource(record EventDrivenRole) string {
	switch strings.TrimSpace(record.Service) {
	case "scheduler":
		return "getschedule"
	case "pipes":
		return "describepipe"
	default:
		return "listrules/listtargetsbyrule"
	}
}

func eventDrivenRoleConfidence(record EventDrivenRole) float64 {
	if record.Disabled {
		return 0.72
	}
	if record.ExecutionDataLogging || len(record.DeadLetterARNs) == 0 {
		return 0.88
	}
	if strings.Contains(record.RoleKind, "target") || strings.Contains(record.RoleKind, "pipe") || strings.Contains(record.RoleKind, "scheduler") {
		return 0.94
	}
	return 0.9
}

func eventDrivenRoleSourceID(record EventDrivenRole) string {
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.WorkloadARN,
		record.TargetID,
		record.RoleKind,
		record.RoleARN,
	}), "|")
}

func eventDrivenNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	for _, sep := range []string{"/", ":"} {
		if idx := strings.LastIndex(trimmed, sep); idx >= 0 && idx < len(trimmed)-1 {
			trimmed = trimmed[idx+1:]
		}
	}
	return trimmed
}

func awsServiceFromARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) > 2 && parts[0] == "arn" {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func sha256Hex(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}

var _ AWSServiceCollector = (*EventDrivenRoleCollector)(nil)
var _ providers.Collector = (*EventDrivenRoleCollector)(nil)
