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
	rawKindCodeBuildServiceRole       = "codebuild_service_role"
	codeBuildServiceRoleCollectorName = "codebuild_service_role"
	codeBuildServiceName              = "codebuild"
)

// CodeBuildServiceRole captures CodeBuild project-to-service-role evidence. It
// stores metadata only: environment values, source contents, logs, and artifacts
// are never collected.
type CodeBuildServiceRole struct {
	awscontract.ServiceCollectorRecord
	RoleName                 string            `json:"role_name,omitempty"`
	ProjectARN               string            `json:"project_arn,omitempty"`
	ProjectName              string            `json:"project_name,omitempty"`
	ProjectDescription       string            `json:"project_description,omitempty"`
	ProjectVisibility        string            `json:"project_visibility,omitempty"`
	SourceType               string            `json:"source_type,omitempty"`
	SourceLocation           string            `json:"source_location,omitempty"`
	SourceAuthType           string            `json:"source_auth_type,omitempty"`
	SourceVersion            string            `json:"source_version,omitempty"`
	SourceIdentifiers        []string          `json:"source_identifiers,omitempty"`
	ArtifactTypes            []string          `json:"artifact_types,omitempty"`
	ArtifactLocations        []string          `json:"artifact_locations,omitempty"`
	EnvironmentType          string            `json:"environment_type,omitempty"`
	ComputeType              string            `json:"compute_type,omitempty"`
	Image                    string            `json:"image,omitempty"`
	ImagePullCredentialsType string            `json:"image_pull_credentials_type,omitempty"`
	PrivilegedMode           bool              `json:"privileged_mode,omitempty"`
	KMSKeyARN                string            `json:"kms_key_arn,omitempty"`
	CacheType                string            `json:"cache_type,omitempty"`
	CacheLocation            string            `json:"cache_location,omitempty"`
	LogTypes                 []string          `json:"log_types,omitempty"`
	VPCID                    string            `json:"vpc_id,omitempty"`
	SubnetIDs                []string          `json:"subnet_ids,omitempty"`
	SecurityGroupIDs         []string          `json:"security_group_ids,omitempty"`
	EnvironmentKeys          []string          `json:"environment_keys,omitempty"`
	SecretRefs               []string          `json:"secret_refs,omitempty"`
	Tags                     map[string]string `json:"tags,omitempty"`
}

// CodeBuildServiceRolePage is one page of CodeBuild service-role inventory.
type CodeBuildServiceRolePage struct {
	Records     []CodeBuildServiceRole
	NextToken   string
	Diagnostics []providers.SourceError
}

// CodeBuildServiceRoleAPI defines the metadata-only CodeBuild operations used by the collector.
type CodeBuildServiceRoleAPI interface {
	ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (CodeBuildServiceRolePage, error)
}

// CodeBuildServiceRoleCollector collects CodeBuild service-role machine identities.
type CodeBuildServiceRoleCollector struct {
	client   CodeBuildServiceRoleAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

// CodeBuildServiceRoleOption customizes CodeBuildServiceRoleCollector behavior.
type CodeBuildServiceRoleOption func(*CodeBuildServiceRoleCollector)

// WithCodeBuildServiceRolePageSize configures CodeBuild batch size.
func WithCodeBuildServiceRolePageSize(pageSize int32) CodeBuildServiceRoleOption {
	return func(c *CodeBuildServiceRoleCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithCodeBuildServiceRoleMaxPages limits list pagination to guard against runaways.
func WithCodeBuildServiceRoleMaxPages(maxPages int) CodeBuildServiceRoleOption {
	return func(c *CodeBuildServiceRoleCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithCodeBuildServiceRoleRetryPolicy customizes retry strategy for transient CodeBuild errors.
func WithCodeBuildServiceRoleRetryPolicy(policy RetryPolicy) CodeBuildServiceRoleOption {
	return func(c *CodeBuildServiceRoleCollector) {
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

// WithCodeBuildServiceRoleRetryJitterRatio configures bounded random jitter around retry backoff.
func WithCodeBuildServiceRoleRetryJitterRatio(ratio float64) CodeBuildServiceRoleOption {
	return func(c *CodeBuildServiceRoleCollector) {
		if ratio < 0 {
			ratio = 0
		}
		c.jitter = ratio
	}
}

// WithCodeBuildServiceRoleRetryRandFunc injects deterministic randomness for retry jitter tests.
func WithCodeBuildServiceRoleRetryRandFunc(randFn func() float64) CodeBuildServiceRoleOption {
	return func(c *CodeBuildServiceRoleCollector) {
		if randFn != nil {
			c.randFn = randFn
		}
	}
}

// WithCodeBuildServiceRoleSleeper injects a testable sleep function.
func WithCodeBuildServiceRoleSleeper(s Sleeper) CodeBuildServiceRoleOption {
	return func(c *CodeBuildServiceRoleCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithCodeBuildServiceRoleClock injects a deterministic clock.
func WithCodeBuildServiceRoleClock(now func() time.Time) CodeBuildServiceRoleOption {
	return func(c *CodeBuildServiceRoleCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCodeBuildServiceRoleCollector creates a read-only CodeBuild service-role collector.
func NewCodeBuildServiceRoleCollector(client CodeBuildServiceRoleAPI, opts ...CodeBuildServiceRoleOption) *CodeBuildServiceRoleCollector {
	c := &CodeBuildServiceRoleCollector{
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

func (c *CodeBuildServiceRoleCollector) ServiceName() string {
	return codeBuildServiceName
}

// Collect pulls CodeBuild service-role assets using an empty scope.
func (c *CodeBuildServiceRoleCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: codeBuildServiceName})
	return assets, err
}

// CollectWithDiagnostics pulls CodeBuild service-role assets and includes non-fatal source errors.
func (c *CodeBuildServiceRoleCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("codebuild service role collector requires client")
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
			return nil, nil, fmt.Errorf("codebuild service role collection exceeded max pages (%d)", c.maxPages)
		}

		response, err := c.withRetry(ctx, func(callCtx context.Context) (CodeBuildServiceRolePage, error) {
			return c.client.ListServiceRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list codebuild service roles page %d: %w", page, err)
			c.addIssue(providers.SourceError{
				Collector: codeBuildServiceRoleCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "codebuild_service_role_page_failed",
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
			normalized := normalizeCodeBuildServiceRoleScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.ProjectARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: codeBuildServiceRoleCollectorName,
					Code:      "malformed_source_record",
					Message:   "skipped CodeBuild service role record without project identity",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: codeBuildServiceRoleCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.ProjectARN, normalized.ProjectName, normalized.WorkloadID),
					Code:      "missing_codebuild_service_role",
					Message:   "CodeBuild project did not include a service role ARN",
					Retryable: false,
				})
				continue
			}

			sourceID := codeBuildServiceRoleSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal codebuild service role %q: %w", sourceID, err)
			}

			assets = append(assets, providers.RawAsset{
				Kind:      rawKindCodeBuildServiceRole,
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

func (c *CodeBuildServiceRoleCollector) withRetry(ctx context.Context, fn func(context.Context) (CodeBuildServiceRolePage, error)) (CodeBuildServiceRolePage, error) {
	return retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, fn)
}

func (c *CodeBuildServiceRoleCollector) backoff(attempt int) time.Duration {
	return awsRetryBackoff(c.retry, c.jitter, c.randFn, attempt)
}

func (c *CodeBuildServiceRoleCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeCodeBuildServiceRoleScope(scope AWSCollectorScope, record CodeBuildServiceRole, collectedAt time.Time) CodeBuildServiceRole {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, codeBuildServiceName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(record.RoleARN))
	normalized.ProjectARN = strings.TrimSpace(record.ProjectARN)
	normalized.ProjectName = firstNonEmptyAWSValue(record.ProjectName, codeBuildProjectNameFromARN(record.ProjectARN))
	normalized.ProjectDescription = strings.TrimSpace(record.ProjectDescription)
	normalized.ProjectVisibility = strings.TrimSpace(record.ProjectVisibility)
	normalized.SourceType = strings.TrimSpace(record.SourceType)
	normalized.SourceLocation = strings.TrimSpace(record.SourceLocation)
	normalized.SourceAuthType = strings.TrimSpace(record.SourceAuthType)
	normalized.SourceVersion = strings.TrimSpace(record.SourceVersion)
	normalized.SourceIdentifiers = normalizeStringList(record.SourceIdentifiers)
	normalized.ArtifactTypes = normalizeStringList(record.ArtifactTypes)
	normalized.ArtifactLocations = normalizeStringList(record.ArtifactLocations)
	normalized.EnvironmentType = strings.TrimSpace(record.EnvironmentType)
	normalized.ComputeType = strings.TrimSpace(record.ComputeType)
	normalized.Image = strings.TrimSpace(record.Image)
	normalized.ImagePullCredentialsType = strings.TrimSpace(record.ImagePullCredentialsType)
	normalized.KMSKeyARN = strings.TrimSpace(record.KMSKeyARN)
	normalized.CacheType = strings.TrimSpace(record.CacheType)
	normalized.CacheLocation = strings.TrimSpace(record.CacheLocation)
	normalized.LogTypes = normalizeStringList(record.LogTypes)
	normalized.VPCID = strings.TrimSpace(record.VPCID)
	normalized.SubnetIDs = normalizeStringList(record.SubnetIDs)
	normalized.SecurityGroupIDs = normalizeStringList(record.SecurityGroupIDs)
	normalized.EnvironmentKeys = normalizeStringList(record.EnvironmentKeys)
	normalized.SecretRefs = normalizeStringList(record.SecretRefs)
	normalized.Tags = copyTags(record.Tags)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "codebuild_project")
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.ProjectARN, normalized.ProjectName)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.ProjectName, codeBuildProjectNameFromARN(normalized.ProjectARN), normalized.ProjectARN)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "batchgetprojects")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.ProjectARN, normalized.RoleARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, codeBuildServiceRoleCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-codebuild-service-role-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = codeBuildServiceRoleConfidence(normalized)
	}
	return normalized
}

func codeBuildServiceRoleConfidence(record CodeBuildServiceRole) float64 {
	if record.PrivilegedMode || strings.EqualFold(record.ProjectVisibility, "PUBLIC_READ") {
		return 0.88
	}
	if len(record.SecretRefs) > 0 {
		return 0.94
	}
	return 0.96
}

func codeBuildServiceRoleSourceID(record CodeBuildServiceRole) string {
	return strings.Join([]string{
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.ProjectARN, record.WorkloadID, record.ProjectName, "project"),
		firstNonEmptyAWSValue(record.RoleARN, "no-role"),
	}, "|")
}

func codeBuildProjectNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	marker := ":project/"
	idx := strings.Index(trimmed, marker)
	if idx < 0 {
		return roleNameFromARN(trimmed)
	}
	rest := trimmed[idx+len(marker):]
	return strings.TrimSpace(rest)
}

var _ AWSServiceCollector = (*CodeBuildServiceRoleCollector)(nil)
var _ providers.Collector = (*CodeBuildServiceRoleCollector)(nil)
