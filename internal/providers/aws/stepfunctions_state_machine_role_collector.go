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
	rawKindStepFunctionsStateMachineRole       = "stepfunctions_state_machine_role"
	stepFunctionsStateMachineRoleCollectorName = "stepfunctions_state_machine_role"
	stepFunctionsServiceName                   = "stepfunctions"
)

// StepFunctionsStateMachineRole captures safe Step Functions role evidence.
// Raw state-machine definitions are never persisted; only hashes and extracted
// ARN/service identifiers are retained.
type StepFunctionsStateMachineRole struct {
	awscontract.ServiceCollectorRecord
	RoleName                    string            `json:"role_name,omitempty"`
	RoleAccountID               string            `json:"role_account_id,omitempty"`
	StateMachineARN             string            `json:"state_machine_arn,omitempty"`
	StateMachineName            string            `json:"state_machine_name,omitempty"`
	StateMachineType            string            `json:"state_machine_type,omitempty"`
	StateMachineStatus          string            `json:"state_machine_status,omitempty"`
	RevisionID                  string            `json:"revision_id,omitempty"`
	Description                 string            `json:"description,omitempty"`
	DefinitionSHA256            string            `json:"definition_sha256,omitempty"`
	DefinitionResourceARNs      []string          `json:"definition_resource_arns,omitempty"`
	TaskResourceARNs            []string          `json:"task_resource_arns,omitempty"`
	ServiceIntegrationResources []string          `json:"service_integration_resources,omitempty"`
	NestedStateMachineARNs      []string          `json:"nested_state_machine_arns,omitempty"`
	LoggingLevel                string            `json:"logging_level,omitempty"`
	LoggingIncludeExecutionData bool              `json:"logging_include_execution_data,omitempty"`
	LogGroupARNs                []string          `json:"log_group_arns,omitempty"`
	TracingEnabled              bool              `json:"tracing_enabled,omitempty"`
	EncryptionType              string            `json:"encryption_type,omitempty"`
	KMSKeyARN                   string            `json:"kms_key_arn,omitempty"`
	Tags                        map[string]string `json:"tags,omitempty"`
}

type StepFunctionsStateMachineRolePage struct {
	Records     []StepFunctionsStateMachineRole
	NextToken   string
	Diagnostics []providers.SourceError
}

type StepFunctionsStateMachineRoleAPI interface {
	ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (StepFunctionsStateMachineRolePage, error)
}

type StepFunctionsStateMachineRoleCollector struct {
	client   StepFunctionsStateMachineRoleAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

type StepFunctionsStateMachineRoleOption func(*StepFunctionsStateMachineRoleCollector)

func WithStepFunctionsStateMachineRolePageSize(pageSize int32) StepFunctionsStateMachineRoleOption {
	return func(c *StepFunctionsStateMachineRoleCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithStepFunctionsStateMachineRoleMaxPages(maxPages int) StepFunctionsStateMachineRoleOption {
	return func(c *StepFunctionsStateMachineRoleCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithStepFunctionsStateMachineRoleRetryPolicy(policy RetryPolicy) StepFunctionsStateMachineRoleOption {
	return func(c *StepFunctionsStateMachineRoleCollector) {
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

func WithStepFunctionsStateMachineRoleSleeper(s Sleeper) StepFunctionsStateMachineRoleOption {
	return func(c *StepFunctionsStateMachineRoleCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func WithStepFunctionsStateMachineRoleClock(now func() time.Time) StepFunctionsStateMachineRoleOption {
	return func(c *StepFunctionsStateMachineRoleCollector) {
		if now != nil {
			c.now = now
		}
	}
}

func NewStepFunctionsStateMachineRoleCollector(client StepFunctionsStateMachineRoleAPI, opts ...StepFunctionsStateMachineRoleOption) *StepFunctionsStateMachineRoleCollector {
	c := &StepFunctionsStateMachineRoleCollector{
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

func (c *StepFunctionsStateMachineRoleCollector) ServiceName() string {
	return stepFunctionsServiceName
}

func (c *StepFunctionsStateMachineRoleCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: stepFunctionsServiceName})
	return assets, err
}

func (c *StepFunctionsStateMachineRoleCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("stepfunctions state machine role collector requires client")
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
			return nil, nil, fmt.Errorf("stepfunctions state machine role collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (StepFunctionsStateMachineRolePage, error) {
			return c.client.ListServiceRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list stepfunctions state machine roles page %d: %w", page, err)
			c.addIssue(providers.SourceError{
				Collector: stepFunctionsStateMachineRoleCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "stepfunctions_state_machine_role_page_failed",
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
			normalized := normalizeStepFunctionsStateMachineRoleScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.StateMachineARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: stepFunctionsStateMachineRoleCollectorName,
					Code:      "malformed_source_record",
					Message:   "skipped Step Functions state machine record without state machine identity",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: stepFunctionsStateMachineRoleCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.StateMachineARN, normalized.StateMachineName, normalized.WorkloadID),
					Code:      "missing_stepfunctions_execution_role",
					Message:   "Step Functions state machine record did not include an execution role ARN",
					Retryable: false,
				})
				continue
			}
			sourceID := stepFunctionsStateMachineRoleSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal stepfunctions state machine role %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindStepFunctionsStateMachineRole,
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

func (c *StepFunctionsStateMachineRoleCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeStepFunctionsStateMachineRoleScope(scope AWSCollectorScope, record StepFunctionsStateMachineRole, collectedAt time.Time) StepFunctionsStateMachineRole {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, stepFunctionsServiceName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(record.RoleARN))
	normalized.RoleAccountID = firstNonEmptyAWSValue(record.RoleAccountID, roleAccountIDFromARN(normalized.RoleARN))
	normalized.StateMachineARN = strings.TrimSpace(record.StateMachineARN)
	normalized.StateMachineName = firstNonEmptyAWSValue(record.StateMachineName, stepFunctionsStateMachineNameFromARN(record.StateMachineARN))
	normalized.StateMachineType = strings.TrimSpace(record.StateMachineType)
	normalized.StateMachineStatus = strings.TrimSpace(record.StateMachineStatus)
	normalized.RevisionID = strings.TrimSpace(record.RevisionID)
	normalized.Description = strings.TrimSpace(record.Description)
	normalized.DefinitionSHA256 = strings.TrimSpace(record.DefinitionSHA256)
	normalized.DefinitionResourceARNs = normalizeStringList(record.DefinitionResourceARNs)
	normalized.TaskResourceARNs = normalizeStringList(record.TaskResourceARNs)
	normalized.ServiceIntegrationResources = normalizeStringList(record.ServiceIntegrationResources)
	normalized.NestedStateMachineARNs = normalizeStringList(record.NestedStateMachineARNs)
	normalized.LoggingLevel = strings.TrimSpace(record.LoggingLevel)
	normalized.LogGroupARNs = normalizeStringList(record.LogGroupARNs)
	normalized.EncryptionType = strings.TrimSpace(record.EncryptionType)
	normalized.KMSKeyARN = strings.TrimSpace(record.KMSKeyARN)
	normalized.Tags = copyTags(record.Tags)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "stepfunctions_state_machine")
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, record.StateMachineARN, record.StateMachineName)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.StateMachineName, record.StateMachineARN)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "describestatemachine")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.StateMachineARN, normalized.RoleARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, stepFunctionsStateMachineRoleCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-stepfunctions-state-machine-role-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = stepFunctionsStateMachineRoleConfidence(normalized)
	}
	return normalized
}

func stepFunctionsStateMachineRoleConfidence(record StepFunctionsStateMachineRole) float64 {
	if record.LoggingIncludeExecutionData {
		return 0.9
	}
	if len(record.DefinitionResourceARNs) == 0 && len(record.TaskResourceARNs) == 0 && strings.TrimSpace(record.DefinitionSHA256) == "" {
		return 0.92
	}
	return 0.96
}

func stepFunctionsStateMachineRoleSourceID(record StepFunctionsStateMachineRole) string {
	return strings.Join([]string{
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.StateMachineARN, record.WorkloadID, record.StateMachineName, "state-machine"),
		firstNonEmptyAWSValue(record.RoleARN, "no-role"),
	}, "|")
}

func stepFunctionsStateMachineNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	marker := ":stateMachine:"
	if idx := strings.Index(trimmed, marker); idx >= 0 {
		return strings.TrimSpace(trimmed[idx+len(marker):])
	}
	if idx := strings.LastIndex(trimmed, ":"); idx >= 0 && idx < len(trimmed)-1 {
		return strings.TrimSpace(trimmed[idx+1:])
	}
	return trimmed
}

var _ AWSServiceCollector = (*StepFunctionsStateMachineRoleCollector)(nil)
var _ providers.Collector = (*StepFunctionsStateMachineRoleCollector)(nil)
