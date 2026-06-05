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
	rawKindLambdaExecutionRole       = "lambda_execution_role"
	lambdaExecutionRoleCollectorName = "lambda_execution_role"
	lambdaServiceName                = "lambda"
)

// LambdaExecutionRole captures Lambda function-to-execution-role evidence. It
// stores metadata only: environment values, payloads, logs, and function code
// are never collected.
type LambdaExecutionRole struct {
	awscontract.ServiceCollectorRecord
	RoleName                   string            `json:"role_name,omitempty"`
	FunctionARN                string            `json:"function_arn,omitempty"`
	FunctionName               string            `json:"function_name,omitempty"`
	FunctionVersion            string            `json:"function_version,omitempty"`
	FunctionState              string            `json:"function_state,omitempty"`
	LastUpdateStatus           string            `json:"last_update_status,omitempty"`
	Runtime                    string            `json:"runtime,omitempty"`
	PackageType                string            `json:"package_type,omitempty"`
	Handler                    string            `json:"handler,omitempty"`
	KMSKeyARN                  string            `json:"kms_key_arn,omitempty"`
	MemorySize                 int32             `json:"memory_size,omitempty"`
	Timeout                    int32             `json:"timeout,omitempty"`
	VPCID                      string            `json:"vpc_id,omitempty"`
	SubnetIDs                  []string          `json:"subnet_ids,omitempty"`
	SecurityGroupIDs           []string          `json:"security_group_ids,omitempty"`
	Architectures              []string          `json:"architectures,omitempty"`
	LayerARNs                  []string          `json:"layer_arns,omitempty"`
	AliasNames                 []string          `json:"alias_names,omitempty"`
	VersionRefs                []string          `json:"version_refs,omitempty"`
	EventSourceARNs            []string          `json:"event_source_arns,omitempty"`
	EventSourceMappingUUIDs    []string          `json:"event_source_mapping_uuids,omitempty"`
	DisabledEventSourceARNs    []string          `json:"disabled_event_source_arns,omitempty"`
	DisabledEventSourceReasons []string          `json:"disabled_event_source_reasons,omitempty"`
	EnvironmentKeys            []string          `json:"environment_keys,omitempty"`
	SecretRefs                 []string          `json:"secret_refs,omitempty"`
	Tags                       map[string]string `json:"tags,omitempty"`
}

// LambdaExecutionRolePage is one page of Lambda execution-role inventory.
type LambdaExecutionRolePage struct {
	Records     []LambdaExecutionRole
	NextToken   string
	Diagnostics []providers.SourceError
}

// LambdaExecutionRoleAPI defines the metadata-only Lambda operations used by the collector.
type LambdaExecutionRoleAPI interface {
	ListExecutionRoles(ctx context.Context, nextToken string, pageSize int32) (LambdaExecutionRolePage, error)
}

// LambdaExecutionRoleCollector collects Lambda execution-role machine identities.
type LambdaExecutionRoleCollector struct {
	client   LambdaExecutionRoleAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

// LambdaExecutionRoleOption customizes LambdaExecutionRoleCollector behavior.
type LambdaExecutionRoleOption func(*LambdaExecutionRoleCollector)

// WithLambdaExecutionRolePageSize configures Lambda pagination size.
func WithLambdaExecutionRolePageSize(pageSize int32) LambdaExecutionRoleOption {
	return func(c *LambdaExecutionRoleCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithLambdaExecutionRoleMaxPages limits list pagination to guard against runaways.
func WithLambdaExecutionRoleMaxPages(maxPages int) LambdaExecutionRoleOption {
	return func(c *LambdaExecutionRoleCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithLambdaExecutionRoleRetryPolicy customizes retry strategy for transient Lambda errors.
func WithLambdaExecutionRoleRetryPolicy(policy RetryPolicy) LambdaExecutionRoleOption {
	return func(c *LambdaExecutionRoleCollector) {
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

// WithLambdaExecutionRoleRetryJitterRatio configures bounded random jitter around retry backoff.
func WithLambdaExecutionRoleRetryJitterRatio(ratio float64) LambdaExecutionRoleOption {
	return func(c *LambdaExecutionRoleCollector) {
		if ratio < 0 {
			ratio = 0
		}
		c.jitter = ratio
	}
}

// WithLambdaExecutionRoleRetryRandFunc injects deterministic randomness for retry jitter tests.
func WithLambdaExecutionRoleRetryRandFunc(randFn func() float64) LambdaExecutionRoleOption {
	return func(c *LambdaExecutionRoleCollector) {
		if randFn != nil {
			c.randFn = randFn
		}
	}
}

// WithLambdaExecutionRoleSleeper injects a testable sleep function.
func WithLambdaExecutionRoleSleeper(s Sleeper) LambdaExecutionRoleOption {
	return func(c *LambdaExecutionRoleCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithLambdaExecutionRoleClock injects a deterministic clock.
func WithLambdaExecutionRoleClock(now func() time.Time) LambdaExecutionRoleOption {
	return func(c *LambdaExecutionRoleCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewLambdaExecutionRoleCollector creates a read-only Lambda execution-role collector.
func NewLambdaExecutionRoleCollector(client LambdaExecutionRoleAPI, opts ...LambdaExecutionRoleOption) *LambdaExecutionRoleCollector {
	c := &LambdaExecutionRoleCollector{
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

func (c *LambdaExecutionRoleCollector) ServiceName() string {
	return lambdaServiceName
}

// Collect pulls Lambda execution-role assets using an empty scope.
func (c *LambdaExecutionRoleCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: lambdaServiceName})
	return assets, err
}

// CollectWithDiagnostics pulls Lambda execution-role assets and includes non-fatal source errors.
func (c *LambdaExecutionRoleCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("lambda execution role collector requires client")
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
			return nil, nil, fmt.Errorf("lambda execution role collection exceeded max pages (%d)", c.maxPages)
		}

		response, err := c.withRetry(ctx, func(callCtx context.Context) (LambdaExecutionRolePage, error) {
			return c.client.ListExecutionRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			return nil, nil, fmt.Errorf("list lambda execution roles page %d: %w", page, err)
		}
		for _, diagnostic := range response.Diagnostics {
			c.addIssue(diagnostic)
		}

		for _, record := range response.Records {
			normalized := normalizeLambdaExecutionRoleScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.FunctionARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: lambdaExecutionRoleCollectorName,
					Code:      "malformed_source_record",
					Message:   "skipped Lambda execution role record without function identity",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: lambdaExecutionRoleCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.FunctionARN, normalized.WorkloadID),
					Code:      "missing_lambda_execution_role",
					Message:   "Lambda function did not include an execution role ARN",
					Retryable: false,
				})
				continue
			}

			sourceID := lambdaExecutionRoleSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal lambda execution role %q: %w", sourceID, err)
			}

			assets = append(assets, providers.RawAsset{
				Kind:      rawKindLambdaExecutionRole,
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

func (c *LambdaExecutionRoleCollector) withRetry(ctx context.Context, fn func(context.Context) (LambdaExecutionRolePage, error)) (LambdaExecutionRolePage, error) {
	return retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, fn)
}

func (c *LambdaExecutionRoleCollector) backoff(attempt int) time.Duration {
	return awsRetryBackoff(c.retry, c.jitter, c.randFn, attempt)
}

func (c *LambdaExecutionRoleCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeLambdaExecutionRoleScope(scope AWSCollectorScope, record LambdaExecutionRole, collectedAt time.Time) LambdaExecutionRole {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, lambdaServiceName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(record.RoleARN))
	normalized.FunctionARN = strings.TrimSpace(record.FunctionARN)
	normalized.FunctionName = firstNonEmptyAWSValue(record.FunctionName, lambdaFunctionNameFromARN(record.FunctionARN))
	normalized.FunctionVersion = strings.TrimSpace(record.FunctionVersion)
	normalized.FunctionState = strings.TrimSpace(record.FunctionState)
	normalized.LastUpdateStatus = strings.TrimSpace(record.LastUpdateStatus)
	normalized.Runtime = strings.TrimSpace(record.Runtime)
	normalized.PackageType = strings.TrimSpace(record.PackageType)
	normalized.Handler = strings.TrimSpace(record.Handler)
	normalized.KMSKeyARN = strings.TrimSpace(record.KMSKeyARN)
	normalized.VPCID = strings.TrimSpace(record.VPCID)
	normalized.SubnetIDs = normalizeStringList(record.SubnetIDs)
	normalized.SecurityGroupIDs = normalizeStringList(record.SecurityGroupIDs)
	normalized.Architectures = normalizeStringList(record.Architectures)
	normalized.LayerARNs = normalizeStringList(record.LayerARNs)
	normalized.AliasNames = normalizeStringList(record.AliasNames)
	normalized.VersionRefs = normalizeStringList(record.VersionRefs)
	normalized.EventSourceARNs = normalizeStringList(record.EventSourceARNs)
	normalized.EventSourceMappingUUIDs = normalizeStringList(record.EventSourceMappingUUIDs)
	normalized.DisabledEventSourceARNs = normalizeStringList(record.DisabledEventSourceARNs)
	normalized.DisabledEventSourceReasons = normalizeStringList(record.DisabledEventSourceReasons)
	normalized.EnvironmentKeys = normalizeStringList(record.EnvironmentKeys)
	normalized.SecretRefs = normalizeStringList(record.SecretRefs)
	normalized.Tags = copyTags(record.Tags)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "lambda_function")
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.FunctionARN, normalized.FunctionName)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.FunctionName, lambdaFunctionNameFromARN(normalized.FunctionARN), normalized.FunctionARN)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "listfunctions")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.FunctionARN, normalized.RoleARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, lambdaExecutionRoleCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-lambda-execution-role-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = lambdaExecutionRoleConfidence(normalized)
	}
	return normalized
}

func lambdaExecutionRoleConfidence(record LambdaExecutionRole) float64 {
	if len(record.DisabledEventSourceARNs) > 0 {
		return 0.88
	}
	if strings.EqualFold(record.FunctionState, "failed") || strings.EqualFold(record.LastUpdateStatus, "failed") {
		return 0.84
	}
	return 0.96
}

func lambdaExecutionRoleSourceID(record LambdaExecutionRole) string {
	return strings.Join([]string{
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.FunctionARN, record.WorkloadID, record.FunctionName, "function"),
		firstNonEmptyAWSValue(record.FunctionVersion, "version"),
		firstNonEmptyAWSValue(record.RoleARN, "no-role"),
	}, "|")
}

func lambdaFunctionNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	marker := ":function:"
	idx := strings.Index(trimmed, marker)
	if idx < 0 {
		return roleNameFromARN(trimmed)
	}
	rest := trimmed[idx+len(marker):]
	if qualifierIdx := strings.Index(rest, ":"); qualifierIdx >= 0 {
		rest = rest[:qualifierIdx]
	}
	return strings.TrimSpace(rest)
}

var _ AWSServiceCollector = (*LambdaExecutionRoleCollector)(nil)
var _ providers.Collector = (*LambdaExecutionRoleCollector)(nil)
