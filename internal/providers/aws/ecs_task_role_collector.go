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
	rawKindECSTaskRole       = "ecs_task_role"
	ecsTaskRoleCollectorName = "ecs_task_role"
	ecsServiceName           = "ecs"

	ecsRoleKindTask      = "task_role"
	ecsRoleKindExecution = "execution_role"
)

// ECSTaskRole captures ECS service/task-definition role evidence. It stores
// metadata only: no environment values, secret values, customer payloads,
// prompts, completions, object contents, or database rows are collected.
type ECSTaskRole struct {
	awscontract.ServiceCollectorRecord
	RoleName               string            `json:"role_name,omitempty"`
	RoleKind               string            `json:"role_kind"`
	ClusterARN             string            `json:"cluster_arn,omitempty"`
	ClusterName            string            `json:"cluster_name,omitempty"`
	ServiceARN             string            `json:"service_arn,omitempty"`
	ServiceName            string            `json:"service_name,omitempty"`
	ServiceStatus          string            `json:"service_status,omitempty"`
	TaskDefinitionARN      string            `json:"task_definition_arn,omitempty"`
	TaskDefinitionFamily   string            `json:"task_definition_family,omitempty"`
	TaskDefinitionRevision string            `json:"task_definition_revision,omitempty"`
	TaskDefinitionStatus   string            `json:"task_definition_status,omitempty"`
	TaskRoleARN            string            `json:"task_role_arn,omitempty"`
	ExecutionRoleARN       string            `json:"execution_role_arn,omitempty"`
	LaunchType             string            `json:"launch_type,omitempty"`
	SchedulingStrategy     string            `json:"scheduling_strategy,omitempty"`
	DesiredCount           int32             `json:"desired_count,omitempty"`
	RunningCount           int32             `json:"running_count,omitempty"`
	PendingCount           int32             `json:"pending_count,omitempty"`
	Compatibilities        []string          `json:"compatibilities,omitempty"`
	ContainerImages        []string          `json:"container_images,omitempty"`
	SecretRefs             []string          `json:"secret_refs,omitempty"`
	EnvironmentKeys        []string          `json:"environment_keys,omitempty"`
	Tags                   map[string]string `json:"tags,omitempty"`
}

// ECSTaskRolePage is one page of ECS task/execution role inventory.
type ECSTaskRolePage struct {
	Records     []ECSTaskRole
	NextToken   string
	Diagnostics []providers.SourceError
}

// ECSTaskRoleAPI defines the metadata-only ECS operations used by the collector.
type ECSTaskRoleAPI interface {
	ListTaskRoles(ctx context.Context, nextToken string, pageSize int32) (ECSTaskRolePage, error)
}

// ECSTaskRoleCollector collects ECS task and execution role machine identities.
type ECSTaskRoleCollector struct {
	client   ECSTaskRoleAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

// ECSTaskRoleOption customizes ECSTaskRoleCollector behavior.
type ECSTaskRoleOption func(*ECSTaskRoleCollector)

// WithECSTaskRolePageSize configures ECS pagination size.
func WithECSTaskRolePageSize(pageSize int32) ECSTaskRoleOption {
	return func(c *ECSTaskRoleCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithECSTaskRoleMaxPages limits list pagination to guard against runaways.
func WithECSTaskRoleMaxPages(maxPages int) ECSTaskRoleOption {
	return func(c *ECSTaskRoleCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithECSTaskRoleRetryPolicy customizes retry strategy for transient ECS errors.
func WithECSTaskRoleRetryPolicy(policy RetryPolicy) ECSTaskRoleOption {
	return func(c *ECSTaskRoleCollector) {
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

// WithECSTaskRoleRetryJitterRatio configures bounded random jitter around retry backoff.
func WithECSTaskRoleRetryJitterRatio(ratio float64) ECSTaskRoleOption {
	return func(c *ECSTaskRoleCollector) {
		if ratio < 0 {
			ratio = 0
		}
		c.jitter = ratio
	}
}

// WithECSTaskRoleRetryRandFunc injects deterministic randomness for retry jitter tests.
func WithECSTaskRoleRetryRandFunc(randFn func() float64) ECSTaskRoleOption {
	return func(c *ECSTaskRoleCollector) {
		if randFn != nil {
			c.randFn = randFn
		}
	}
}

// WithECSTaskRoleSleeper injects a testable sleep function.
func WithECSTaskRoleSleeper(s Sleeper) ECSTaskRoleOption {
	return func(c *ECSTaskRoleCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithECSTaskRoleClock injects a deterministic clock.
func WithECSTaskRoleClock(now func() time.Time) ECSTaskRoleOption {
	return func(c *ECSTaskRoleCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewECSTaskRoleCollector creates a read-only ECS task/execution role collector.
func NewECSTaskRoleCollector(client ECSTaskRoleAPI, opts ...ECSTaskRoleOption) *ECSTaskRoleCollector {
	c := &ECSTaskRoleCollector{
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

func (c *ECSTaskRoleCollector) ServiceName() string {
	return ecsServiceName
}

// Collect pulls ECS task/execution role assets using an empty scope.
func (c *ECSTaskRoleCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: ecsServiceName})
	return assets, err
}

// CollectWithDiagnostics pulls ECS task/execution role assets and includes non-fatal source errors.
func (c *ECSTaskRoleCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("ecs task role collector requires client")
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
			return nil, nil, fmt.Errorf("ecs task role collection exceeded max pages (%d)", c.maxPages)
		}

		response, err := c.withRetry(ctx, func(callCtx context.Context) (ECSTaskRolePage, error) {
			return c.client.ListTaskRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			return nil, nil, fmt.Errorf("list ecs task roles page %d: %w", page, err)
		}
		for _, diagnostic := range response.Diagnostics {
			c.addIssue(diagnostic)
		}

		for _, record := range response.Records {
			normalized := normalizeECSTaskRoleScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.RoleKind) == "" {
				c.addIssue(providers.SourceError{
					Collector: ecsTaskRoleCollectorName,
					Code:      "malformed_source_record",
					Message:   "skipped ECS task role record without workload id or role kind",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: ecsTaskRoleCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.TaskDefinitionARN, normalized.ServiceARN, normalized.WorkloadID),
					Code:      "missing_ecs_role",
					Message:   "ECS workload role reference did not include an IAM role ARN",
					Retryable: false,
				})
				continue
			}

			sourceID := ecsTaskRoleSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal ecs task role %q: %w", sourceID, err)
			}

			assets = append(assets, providers.RawAsset{
				Kind:      rawKindECSTaskRole,
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

	issues := append([]providers.SourceError(nil), c.issues...)
	return assets, issues, nil
}

func (c *ECSTaskRoleCollector) withRetry(ctx context.Context, fn func(context.Context) (ECSTaskRolePage, error)) (ECSTaskRolePage, error) {
	return retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, fn)
}

func (c *ECSTaskRoleCollector) backoff(attempt int) time.Duration {
	return awsRetryBackoff(c.retry, c.jitter, c.randFn, attempt)
}

func (c *ECSTaskRoleCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeECSTaskRoleScope(scope AWSCollectorScope, record ECSTaskRole, collectedAt time.Time) ECSTaskRole {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, ecsServiceName)
	normalized.RoleKind = normalizeECSRoleKind(record.RoleKind, record.RoleARN, record.TaskRoleARN, record.ExecutionRoleARN)
	normalized.RoleARN = firstNonEmptyAWSValue(record.RoleARN, roleARNForECSKind(normalized.RoleKind, record))
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(normalized.RoleARN))
	normalized.ClusterARN = strings.TrimSpace(record.ClusterARN)
	normalized.ClusterName = firstNonEmptyAWSValue(record.ClusterName, ecsNameFromARN(record.ClusterARN))
	normalized.ServiceARN = strings.TrimSpace(record.ServiceARN)
	normalized.ServiceName = firstNonEmptyAWSValue(record.ServiceName, ecsNameFromARN(record.ServiceARN))
	normalized.ServiceStatus = strings.TrimSpace(record.ServiceStatus)
	normalized.TaskDefinitionARN = strings.TrimSpace(record.TaskDefinitionARN)
	normalized.TaskDefinitionFamily = strings.TrimSpace(record.TaskDefinitionFamily)
	normalized.TaskDefinitionRevision = strings.TrimSpace(record.TaskDefinitionRevision)
	normalized.TaskDefinitionStatus = strings.TrimSpace(record.TaskDefinitionStatus)
	normalized.TaskRoleARN = strings.TrimSpace(record.TaskRoleARN)
	normalized.ExecutionRoleARN = strings.TrimSpace(record.ExecutionRoleARN)
	normalized.LaunchType = strings.TrimSpace(record.LaunchType)
	normalized.SchedulingStrategy = strings.TrimSpace(record.SchedulingStrategy)
	normalized.Compatibilities = normalizeStringList(record.Compatibilities)
	normalized.ContainerImages = normalizeStringList(record.ContainerImages)
	normalized.SecretRefs = normalizeStringList(record.SecretRefs)
	normalized.EnvironmentKeys = normalizeStringList(record.EnvironmentKeys)
	normalized.Tags = copyTags(record.Tags)
	if strings.TrimSpace(normalized.WorkloadType) == "" {
		if normalized.ServiceARN != "" || normalized.ServiceName != "" {
			normalized.WorkloadType = "ecs_service"
		} else {
			normalized.WorkloadType = "ecs_task_definition"
		}
	}
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.ServiceARN, normalized.ServiceName, normalized.TaskDefinitionARN)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.ServiceName, normalized.TaskDefinitionFamily, normalized.TaskDefinitionARN)
	normalized.Source = firstNonEmptyAWSValue(record.Source, ecsSourceForRecord(normalized))
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.ServiceARN, normalized.TaskDefinitionARN, normalized.RoleARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, ecsTaskRoleCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-ecs-task-role-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = ecsConfidenceForRoleKind(normalized.RoleKind)
	}
	return normalized
}

func normalizeECSRoleKind(roleKind string, roleARN string, taskRoleARN string, executionRoleARN string) string {
	switch strings.ToLower(strings.TrimSpace(roleKind)) {
	case ecsRoleKindTask, "task", "runtime":
		return ecsRoleKindTask
	case ecsRoleKindExecution, "execution":
		return ecsRoleKindExecution
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN != "" && strings.EqualFold(trimmedRoleARN, strings.TrimSpace(executionRoleARN)) {
		return ecsRoleKindExecution
	}
	return ecsRoleKindTask
}

func roleARNForECSKind(roleKind string, record ECSTaskRole) string {
	if strings.EqualFold(roleKind, ecsRoleKindExecution) {
		return strings.TrimSpace(record.ExecutionRoleARN)
	}
	return strings.TrimSpace(record.TaskRoleARN)
}

func ecsSourceForRecord(record ECSTaskRole) string {
	if strings.EqualFold(strings.TrimSpace(record.WorkloadType), "ecs_service") {
		return "describeservices"
	}
	return "describetaskdefinition"
}

func ecsConfidenceForRoleKind(roleKind string) float64 {
	if strings.EqualFold(roleKind, ecsRoleKindExecution) {
		return 0.9
	}
	return 0.96
}

func ecsTaskRoleSourceID(record ECSTaskRole) string {
	return strings.Join([]string{
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.WorkloadType, "ecs_workload"),
		firstNonEmptyAWSValue(record.WorkloadID, record.ServiceARN, record.TaskDefinitionARN, "workload"),
		firstNonEmptyAWSValue(record.TaskDefinitionARN, "no-task-definition"),
		firstNonEmptyAWSValue(record.RoleKind, "role-kind"),
		firstNonEmptyAWSValue(record.RoleARN, "no-role"),
	}, "|")
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func ecsNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 || idx == len(trimmed)-1 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[idx+1:])
}

var _ AWSServiceCollector = (*ECSTaskRoleCollector)(nil)
var _ providers.Collector = (*ECSTaskRoleCollector)(nil)
