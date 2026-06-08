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
	rawKindSageMakerWorkloadRole       = "sagemaker_workload_role"
	sageMakerWorkloadRoleCollectorName = "sagemaker_workload_role"
	sageMakerServiceName               = "sagemaker"
)

// SageMakerWorkloadRole is the normalized envelope the SageMaker workload-role
// collector emits. It captures a single workload→IAM-role association along
// with the S3, ECR, and KMS context that operators need to reason about the
// blast radius of the role, without ever reading notebook, model, or training
// payload contents.
type SageMakerWorkloadRole struct {
	awscontract.ServiceCollectorRecord
	RoleName       string            `json:"role_name,omitempty"`
	RoleKind       string            `json:"role_kind,omitempty"`
	RoleAccountID  string            `json:"role_account_id,omitempty"`
	WorkloadARN    string            `json:"workload_arn,omitempty"`
	ResourceARN    string            `json:"resource_arn,omitempty"`
	ResourceType   string            `json:"resource_type,omitempty"`
	ResourceStatus string            `json:"resource_status,omitempty"`
	DomainID       string            `json:"domain_id,omitempty"`
	DomainARN      string            `json:"domain_arn,omitempty"`
	UserProfile    string            `json:"user_profile,omitempty"`
	SpaceName      string            `json:"space_name,omitempty"`
	PipelineARN    string            `json:"pipeline_arn,omitempty"`
	ModelARN       string            `json:"model_arn,omitempty"`
	EndpointConfig string            `json:"endpoint_config,omitempty"`
	NetworkMode    string            `json:"network_mode,omitempty"`
	ImageURIs      []string          `json:"image_uris,omitempty"`
	S3References   []string          `json:"s3_references,omitempty"`
	KMSKeyARNs     []string          `json:"kms_key_arns,omitempty"`
	CoverageStatus string            `json:"coverage_status,omitempty"`
	CoverageReason string            `json:"coverage_reason,omitempty"`
	Active         bool              `json:"active"`
	Disabled       bool              `json:"disabled"`
	Tags           map[string]string `json:"tags,omitempty"`
}

// SageMakerWorkloadRolePage is one page of normalized SageMaker workload roles
// returned by the SDK or fixture client, along with any collector diagnostics
// recorded during the page.
type SageMakerWorkloadRolePage struct {
	Records     []SageMakerWorkloadRole
	NextToken   string
	Diagnostics []providers.SourceError
}

// SageMakerWorkloadRoleAPI is the narrow seam between the collector and the
// underlying SageMaker SDK or fixture client. It keeps the collector focused on
// pagination, retries, deduping, and normalization.
type SageMakerWorkloadRoleAPI interface {
	ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (SageMakerWorkloadRolePage, error)
}

// SageMakerWorkloadRoleCollector turns SageMaker workload metadata into
// payload-safe normalized records the AWS graph and API can consume.
type SageMakerWorkloadRoleCollector struct {
	client   SageMakerWorkloadRoleAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

// SageMakerWorkloadRoleOption tunes a SageMakerWorkloadRoleCollector.
type SageMakerWorkloadRoleOption func(*SageMakerWorkloadRoleCollector)

// WithSageMakerWorkloadRolePageSize overrides the page size requested from the
// underlying API.
func WithSageMakerWorkloadRolePageSize(pageSize int32) SageMakerWorkloadRoleOption {
	return func(c *SageMakerWorkloadRoleCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithSageMakerWorkloadRoleMaxPages caps the number of pages we will request in
// a single scan, protecting against pagination loops.
func WithSageMakerWorkloadRoleMaxPages(maxPages int) SageMakerWorkloadRoleOption {
	return func(c *SageMakerWorkloadRoleCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithSageMakerWorkloadRoleRetryPolicy overrides the retry policy used for
// each page call.
func WithSageMakerWorkloadRoleRetryPolicy(policy RetryPolicy) SageMakerWorkloadRoleOption {
	return func(c *SageMakerWorkloadRoleCollector) {
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

// WithSageMakerWorkloadRoleSleeper lets tests inject a deterministic sleeper.
func WithSageMakerWorkloadRoleSleeper(s Sleeper) SageMakerWorkloadRoleOption {
	return func(c *SageMakerWorkloadRoleCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithSageMakerWorkloadRoleClock lets tests inject a deterministic clock.
func WithSageMakerWorkloadRoleClock(now func() time.Time) SageMakerWorkloadRoleOption {
	return func(c *SageMakerWorkloadRoleCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewSageMakerWorkloadRoleCollector constructs the collector with sensible
// defaults, mirroring the other AWS service collectors.
func NewSageMakerWorkloadRoleCollector(client SageMakerWorkloadRoleAPI, opts ...SageMakerWorkloadRoleOption) *SageMakerWorkloadRoleCollector {
	c := &SageMakerWorkloadRoleCollector{
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

// ServiceName returns the canonical AWS service this collector covers.
func (c *SageMakerWorkloadRoleCollector) ServiceName() string {
	return sageMakerServiceName
}

// Collect satisfies providers.Collector for callers that do not pass the AWS
// collector scope. CollectWithDiagnostics should be preferred wherever the
// scope is available, so account, region, and connector context can be
// stamped onto every record.
func (c *SageMakerWorkloadRoleCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: sageMakerServiceName})
	return assets, err
}

// CollectWithDiagnostics performs the page-by-page collection, retries, and
// normalization, returning raw assets plus structured diagnostics. The
// per-call state is kept in local variables so concurrent invocations on the
// same collector do not race on a shared issues slice.
func (c *SageMakerWorkloadRoleCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("sagemaker workload role collector requires client")
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
			// Return whatever assets and diagnostics we already collected so
			// the partial scan is still visible to downstream consumers; the
			// error itself preserves the overflow signal.
			addIssue(providers.SourceError{
				Collector: sageMakerWorkloadRoleCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "sagemaker_workload_role_page_limit_exceeded",
				Message:   fmt.Sprintf("sagemaker workload role collection exceeded max pages (%d)", c.maxPages),
				Retryable: false,
			})
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("sagemaker workload role collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (SageMakerWorkloadRolePage, error) {
			return c.client.ListServiceRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list sagemaker workload roles page %d: %w", page, err)
			addIssue(providers.SourceError{
				Collector: sageMakerWorkloadRoleCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "sagemaker_workload_role_page_failed",
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
			normalized := normalizeSageMakerWorkloadRoleScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.WorkloadARN) == "" {
				addIssue(providers.SourceError{
					Collector: sageMakerWorkloadRoleCollectorName,
					Code:      "malformed_sagemaker_record",
					Message:   "skipped sagemaker record without workload identity",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				addIssue(providers.SourceError{
					Collector: sageMakerWorkloadRoleCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.WorkloadARN, normalized.WorkloadName, normalized.WorkloadID),
					Code:      "missing_sagemaker_role",
					Message:   "sagemaker workload did not include an execution role ARN",
					Retryable: false,
				})
				continue
			}
			sourceID := sageMakerWorkloadRoleSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal sagemaker workload role %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindSageMakerWorkloadRole,
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
	return assets, append([]providers.SourceError(nil), issues...), nil
}

func normalizeSageMakerWorkloadRoleScope(scope AWSCollectorScope, record SageMakerWorkloadRole, collectedAt time.Time) SageMakerWorkloadRole {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, sageMakerServiceName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(record.RoleARN))
	normalized.RoleKind = firstNonEmptyAWSValue(record.RoleKind, sageMakerDefaultRoleKind(record))
	normalized.RoleAccountID = firstNonEmptyAWSValue(record.RoleAccountID, roleAccountIDFromARN(normalized.RoleARN))
	normalized.WorkloadARN = strings.TrimSpace(record.WorkloadARN)
	normalized.ResourceARN = firstNonEmptyAWSValue(record.ResourceARN, normalized.WorkloadARN)
	normalized.ResourceType = firstNonEmptyAWSValue(record.ResourceType, sageMakerDefaultWorkloadType(record))
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, normalized.ResourceType)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.WorkloadARN, normalized.WorkloadName)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, eventDrivenNameFromARN(normalized.WorkloadARN))
	normalized.Source = firstNonEmptyAWSValue(record.Source, "sagemaker_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.WorkloadARN, normalized.RoleARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, sageMakerWorkloadRoleCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-sagemaker-workload-role-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.ResourceStatus = strings.TrimSpace(record.ResourceStatus)
	normalized.DomainID = strings.TrimSpace(record.DomainID)
	normalized.DomainARN = strings.TrimSpace(record.DomainARN)
	normalized.UserProfile = strings.TrimSpace(record.UserProfile)
	normalized.SpaceName = strings.TrimSpace(record.SpaceName)
	normalized.PipelineARN = strings.TrimSpace(record.PipelineARN)
	normalized.ModelARN = strings.TrimSpace(record.ModelARN)
	normalized.EndpointConfig = strings.TrimSpace(record.EndpointConfig)
	normalized.NetworkMode = strings.TrimSpace(record.NetworkMode)
	normalized.ImageURIs = dedupeStringSlice(record.ImageURIs)
	normalized.S3References = dedupeStringSlice(record.S3References)
	normalized.KMSKeyARNs = dedupeStringSlice(record.KMSKeyARNs)
	normalized.CoverageStatus = firstNonEmptyAWSValue(record.CoverageStatus, "covered")
	normalized.CoverageReason = strings.TrimSpace(record.CoverageReason)
	normalized.Tags = copyTags(record.Tags)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = sageMakerWorkloadRoleConfidence(normalized)
	}
	return normalized
}

func sageMakerDefaultWorkloadType(record SageMakerWorkloadRole) string {
	if strings.TrimSpace(record.ResourceType) != "" {
		return strings.TrimSpace(record.ResourceType)
	}
	switch {
	case strings.TrimSpace(record.PipelineARN) != "":
		return "sagemaker_pipeline"
	case strings.TrimSpace(record.ModelARN) != "":
		return "sagemaker_model"
	case strings.TrimSpace(record.DomainARN) != "":
		return "sagemaker_domain"
	default:
		return "sagemaker_workload"
	}
}

func sageMakerDefaultRoleKind(record SageMakerWorkloadRole) string {
	// Prefer the explicit ResourceType, but fall back to WorkloadType so the
	// default role kind stays consistent when only the workload shape is set.
	workloadType := strings.TrimSpace(record.ResourceType)
	if workloadType == "" {
		workloadType = strings.TrimSpace(record.WorkloadType)
	}
	switch workloadType {
	case "sagemaker_pipeline":
		return "sagemaker_pipeline_execution_role"
	case "sagemaker_model":
		return "sagemaker_model_execution_role"
	case "sagemaker_domain":
		return "sagemaker_domain_execution_role"
	case "sagemaker_notebook_instance":
		return "sagemaker_notebook_execution_role"
	case "sagemaker_training_job":
		return "sagemaker_training_execution_role"
	case "sagemaker_processing_job":
		return "sagemaker_processing_execution_role"
	case "sagemaker_transform_job":
		return "sagemaker_batch_transform_execution_role"
	case "sagemaker_endpoint":
		return "sagemaker_endpoint_execution_role"
	}
	return "sagemaker_execution_role"
}

func sageMakerWorkloadRoleConfidence(record SageMakerWorkloadRole) float64 {
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

func sageMakerWorkloadRoleSourceID(record SageMakerWorkloadRole) string {
	// Endpoints carry the model execution role rather than a role of their
	// own, so multiple production variants whose backing models share the
	// same execution role would otherwise collide on
	// (service|workloadARN|roleKind|roleARN) and one model record would be
	// silently dropped during cross-page dedupe. Include the model ARN on
	// endpoint records so each variant's evidence is retained.
	modelDiscriminator := ""
	if strings.EqualFold(strings.TrimSpace(record.WorkloadType), "sagemaker_endpoint") || strings.EqualFold(strings.TrimSpace(record.ResourceType), "sagemaker_endpoint") {
		modelDiscriminator = strings.TrimSpace(record.ModelARN)
	}
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.WorkloadARN,
		record.RoleKind,
		record.RoleARN,
		modelDiscriminator,
	}), "|")
}

// dedupeStringSlice trims and deduplicates strings via the shared
// normalizeStringList helper, then sorts the result lexicographically so the
// SageMaker collector emits image, S3, and KMS evidence in a deterministic
// order across page boundaries.
func dedupeStringSlice(values []string) []string {
	out := normalizeStringList(values)
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var _ AWSServiceCollector = (*SageMakerWorkloadRoleCollector)(nil)
var _ providers.Collector = (*SageMakerWorkloadRoleCollector)(nil)
