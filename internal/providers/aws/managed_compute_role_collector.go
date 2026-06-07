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
	rawKindManagedComputeRole       = "managed_compute_role"
	managedComputeRoleCollectorName = "managed_compute_role"
	managedComputeServiceName       = "managed-compute"
)

type ManagedComputeRole struct {
	awscontract.ServiceCollectorRecord
	RoleName           string            `json:"role_name,omitempty"`
	RoleKind           string            `json:"role_kind,omitempty"`
	RoleAccountID      string            `json:"role_account_id,omitempty"`
	WorkloadARN        string            `json:"workload_arn,omitempty"`
	ResourceARN        string            `json:"resource_arn,omitempty"`
	ResourceType       string            `json:"resource_type,omitempty"`
	ResourceStatus     string            `json:"resource_status,omitempty"`
	ComputeEngine      string            `json:"compute_engine,omitempty"`
	QueueARN           string            `json:"queue_arn,omitempty"`
	ClusterARN         string            `json:"cluster_arn,omitempty"`
	JobDefinitionARN   string            `json:"job_definition_arn,omitempty"`
	Revision           int32             `json:"revision,omitempty"`
	UnsupportedService string            `json:"unsupported_service,omitempty"`
	CoverageStatus     string            `json:"coverage_status,omitempty"`
	CoverageReason     string            `json:"coverage_reason,omitempty"`
	Active             bool              `json:"active"`
	Disabled           bool              `json:"disabled"`
	Tags               map[string]string `json:"tags,omitempty"`
}

type ManagedComputeRolePage struct {
	Records     []ManagedComputeRole
	NextToken   string
	Diagnostics []providers.SourceError
}

type ManagedComputeRoleAPI interface {
	ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (ManagedComputeRolePage, error)
}

type ManagedComputeRoleCollector struct {
	client   ManagedComputeRoleAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

type ManagedComputeRoleOption func(*ManagedComputeRoleCollector)

func WithManagedComputeRolePageSize(pageSize int32) ManagedComputeRoleOption {
	return func(c *ManagedComputeRoleCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithManagedComputeRoleMaxPages(maxPages int) ManagedComputeRoleOption {
	return func(c *ManagedComputeRoleCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithManagedComputeRoleRetryPolicy(policy RetryPolicy) ManagedComputeRoleOption {
	return func(c *ManagedComputeRoleCollector) {
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

func WithManagedComputeRoleSleeper(s Sleeper) ManagedComputeRoleOption {
	return func(c *ManagedComputeRoleCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func WithManagedComputeRoleClock(now func() time.Time) ManagedComputeRoleOption {
	return func(c *ManagedComputeRoleCollector) {
		if now != nil {
			c.now = now
		}
	}
}

func NewManagedComputeRoleCollector(client ManagedComputeRoleAPI, opts ...ManagedComputeRoleOption) *ManagedComputeRoleCollector {
	c := &ManagedComputeRoleCollector{
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

func (c *ManagedComputeRoleCollector) ServiceName() string {
	return managedComputeServiceName
}

func (c *ManagedComputeRoleCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: managedComputeServiceName})
	return assets, err
}

func (c *ManagedComputeRoleCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("managed compute role collector requires client")
	}
	c.issues = c.issues[:0]
	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}
	assets := []providers.RawAsset{}
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()
	for page := 1; ; page++ {
		if page > c.maxPages {
			return nil, nil, fmt.Errorf("managed compute role collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (ManagedComputeRolePage, error) {
			return c.client.ListServiceRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list managed compute roles page %d: %w", page, err)
			c.addIssue(providers.SourceError{
				Collector: managedComputeRoleCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "managed_compute_role_page_failed",
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
			normalized := normalizeManagedComputeRoleScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.WorkloadARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: managedComputeRoleCollectorName,
					Code:      "malformed_managed_compute_record",
					Message:   "skipped managed compute record without workload identity",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: managedComputeRoleCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.WorkloadARN, normalized.WorkloadName, normalized.WorkloadID),
					Code:      "missing_managed_compute_role",
					Message:   "managed compute workload did not include an IAM role ARN",
					Retryable: false,
				})
				continue
			}
			sourceID := managedComputeRoleSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal managed compute role %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindManagedComputeRole,
				SourceID:  sourceID,
				Payload:   payload,
				Collected: collectedAt.Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}
		if strings.TrimSpace(response.NextToken) == "" {
			break
		}
		nextToken = strings.TrimSpace(response.NextToken)
	}
	return assets, append([]providers.SourceError(nil), c.issues...), nil
}

func (c *ManagedComputeRoleCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeManagedComputeRoleScope(scope AWSCollectorScope, record ManagedComputeRole, collectedAt time.Time) ManagedComputeRole {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, managedComputeDefaultService(record))
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(record.RoleARN))
	normalized.RoleKind = firstNonEmptyAWSValue(record.RoleKind, managedComputeDefaultRoleKind(record))
	normalized.RoleAccountID = firstNonEmptyAWSValue(record.RoleAccountID, roleAccountIDFromARN(normalized.RoleARN))
	normalized.WorkloadARN = strings.TrimSpace(record.WorkloadARN)
	normalized.ResourceARN = firstNonEmptyAWSValue(record.ResourceARN, normalized.WorkloadARN)
	normalized.ResourceType = firstNonEmptyAWSValue(record.ResourceType, managedComputeDefaultWorkloadType(record))
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, normalized.ResourceType)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.WorkloadARN, normalized.WorkloadName)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, eventDrivenNameFromARN(normalized.WorkloadARN))
	normalized.Source = firstNonEmptyAWSValue(record.Source, "managed_compute_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.WorkloadARN, normalized.RoleARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, managedComputeRoleCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-managed-compute-role-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.ResourceStatus = strings.TrimSpace(record.ResourceStatus)
	normalized.ComputeEngine = strings.TrimSpace(record.ComputeEngine)
	normalized.QueueARN = strings.TrimSpace(record.QueueARN)
	normalized.ClusterARN = strings.TrimSpace(record.ClusterARN)
	normalized.JobDefinitionARN = strings.TrimSpace(record.JobDefinitionARN)
	normalized.UnsupportedService = strings.TrimSpace(record.UnsupportedService)
	normalized.CoverageStatus = firstNonEmptyAWSValue(record.CoverageStatus, "covered")
	if normalized.UnsupportedService != "" && strings.TrimSpace(record.CoverageStatus) == "" {
		normalized.CoverageStatus = "unsupported"
	}
	normalized.CoverageReason = strings.TrimSpace(record.CoverageReason)
	normalized.Tags = copyTags(record.Tags)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = managedComputeRoleConfidence(normalized)
	}
	return normalized
}

func managedComputeDefaultService(record ManagedComputeRole) string {
	if strings.TrimSpace(record.UnsupportedService) != "" {
		return strings.TrimSpace(record.UnsupportedService)
	}
	return managedComputeServiceName
}

func managedComputeDefaultWorkloadType(record ManagedComputeRole) string {
	switch strings.TrimSpace(record.Service) {
	case "apprunner":
		return "apprunner_service"
	case "batch":
		if strings.Contains(record.RoleKind, "job") || strings.TrimSpace(record.JobDefinitionARN) != "" {
			return "batch_job_definition"
		}
		return "batch_compute_environment"
	case "glue":
		if strings.Contains(record.RoleKind, "crawler") {
			return "glue_crawler"
		}
		return "glue_job"
	case "emr":
		return "emr_cluster"
	default:
		return "managed_compute_workload"
	}
}

func managedComputeDefaultRoleKind(record ManagedComputeRole) string {
	if strings.TrimSpace(record.Service) != "" {
		return strings.TrimSpace(record.Service) + "_role"
	}
	return "managed_compute_role"
}

func managedComputeRoleConfidence(record ManagedComputeRole) float64 {
	if strings.EqualFold(record.CoverageStatus, "unsupported") {
		return 0.4
	}
	if record.Disabled {
		return 0.72
	}
	if strings.TrimSpace(record.ResourceStatus) == "" {
		return 0.86
	}
	return 0.93
}

func managedComputeRoleSourceID(record ManagedComputeRole) string {
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.WorkloadARN,
		record.RoleKind,
		record.RoleARN,
	}), "|")
}

var _ AWSServiceCollector = (*ManagedComputeRoleCollector)(nil)
var _ providers.Collector = (*ManagedComputeRoleCollector)(nil)
