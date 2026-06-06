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
	rawKindCodePipelineDeploymentRole       = "codepipeline_deployment_role"
	codePipelineDeploymentRoleCollectorName = "codepipeline_deployment_role"
	codePipelineServiceName                 = "codepipeline"
)

// CodePipelineDeploymentRole captures CodePipeline pipeline/action role evidence.
// It stores metadata only: artifact contents, source contents, and action
// configuration values are never collected.
type CodePipelineDeploymentRole struct {
	awscontract.ServiceCollectorRecord
	RoleName                  string            `json:"role_name,omitempty"`
	RoleKind                  string            `json:"role_kind,omitempty"`
	PipelineARN               string            `json:"pipeline_arn,omitempty"`
	PipelineName              string            `json:"pipeline_name,omitempty"`
	PipelineVersion           int32             `json:"pipeline_version,omitempty"`
	PipelineType              string            `json:"pipeline_type,omitempty"`
	ExecutionMode             string            `json:"execution_mode,omitempty"`
	StageName                 string            `json:"stage_name,omitempty"`
	ActionName                string            `json:"action_name,omitempty"`
	RoleAccountID             string            `json:"role_account_id,omitempty"`
	ActionCategory            string            `json:"action_category,omitempty"`
	ActionOwner               string            `json:"action_owner,omitempty"`
	ActionProvider            string            `json:"action_provider,omitempty"`
	ActionVersion             string            `json:"action_version,omitempty"`
	ActionRegion              string            `json:"action_region,omitempty"`
	RunOrder                  int32             `json:"run_order,omitempty"`
	Namespace                 string            `json:"namespace,omitempty"`
	InputArtifactNames        []string          `json:"input_artifact_names,omitempty"`
	OutputArtifactNames       []string          `json:"output_artifact_names,omitempty"`
	ArtifactStoreTypes        []string          `json:"artifact_store_types,omitempty"`
	ArtifactStoreLocations    []string          `json:"artifact_store_locations,omitempty"`
	ArtifactStoreRegions      []string          `json:"artifact_store_regions,omitempty"`
	ArtifactKMSKeyARNs        []string          `json:"artifact_kms_key_arns,omitempty"`
	ConfigurationKeys         []string          `json:"configuration_keys,omitempty"`
	ProviderIdentifiers       []string          `json:"provider_identifiers,omitempty"`
	DisabledStageTransitions  []string          `json:"disabled_stage_transitions,omitempty"`
	CrossRegionArtifactStores bool              `json:"cross_region_artifact_stores,omitempty"`
	CrossRegionAction         bool              `json:"cross_region_action,omitempty"`
	CrossAccountRole          bool              `json:"cross_account_role,omitempty"`
	PassRoleAdjacent          bool              `json:"pass_role_adjacent,omitempty"`
	Tags                      map[string]string `json:"tags,omitempty"`
}

// CodePipelineDeploymentRolePage is one page of CodePipeline deployment-role inventory.
type CodePipelineDeploymentRolePage struct {
	Records     []CodePipelineDeploymentRole
	NextToken   string
	Diagnostics []providers.SourceError
}

// CodePipelineDeploymentRoleAPI defines the metadata-only CodePipeline operations used by the collector.
type CodePipelineDeploymentRoleAPI interface {
	ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (CodePipelineDeploymentRolePage, error)
}

// CodePipelineDeploymentRoleCollector collects CodePipeline deployment-role machine identities.
type CodePipelineDeploymentRoleCollector struct {
	client   CodePipelineDeploymentRoleAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

// CodePipelineDeploymentRoleOption customizes CodePipelineDeploymentRoleCollector behavior.
type CodePipelineDeploymentRoleOption func(*CodePipelineDeploymentRoleCollector)

// WithCodePipelineDeploymentRolePageSize configures CodePipeline batch size.
func WithCodePipelineDeploymentRolePageSize(pageSize int32) CodePipelineDeploymentRoleOption {
	return func(c *CodePipelineDeploymentRoleCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithCodePipelineDeploymentRoleMaxPages limits list pagination to guard against runaways.
func WithCodePipelineDeploymentRoleMaxPages(maxPages int) CodePipelineDeploymentRoleOption {
	return func(c *CodePipelineDeploymentRoleCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithCodePipelineDeploymentRoleRetryPolicy customizes retry strategy for transient CodePipeline errors.
func WithCodePipelineDeploymentRoleRetryPolicy(policy RetryPolicy) CodePipelineDeploymentRoleOption {
	return func(c *CodePipelineDeploymentRoleCollector) {
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

// WithCodePipelineDeploymentRoleRetryJitterRatio configures bounded random jitter around retry backoff.
func WithCodePipelineDeploymentRoleRetryJitterRatio(ratio float64) CodePipelineDeploymentRoleOption {
	return func(c *CodePipelineDeploymentRoleCollector) {
		if ratio < 0 {
			ratio = 0
		}
		c.jitter = ratio
	}
}

// WithCodePipelineDeploymentRoleRetryRandFunc injects deterministic randomness for retry jitter tests.
func WithCodePipelineDeploymentRoleRetryRandFunc(randFn func() float64) CodePipelineDeploymentRoleOption {
	return func(c *CodePipelineDeploymentRoleCollector) {
		if randFn != nil {
			c.randFn = randFn
		}
	}
}

// WithCodePipelineDeploymentRoleSleeper injects a testable sleep function.
func WithCodePipelineDeploymentRoleSleeper(s Sleeper) CodePipelineDeploymentRoleOption {
	return func(c *CodePipelineDeploymentRoleCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithCodePipelineDeploymentRoleClock injects a deterministic clock.
func WithCodePipelineDeploymentRoleClock(now func() time.Time) CodePipelineDeploymentRoleOption {
	return func(c *CodePipelineDeploymentRoleCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCodePipelineDeploymentRoleCollector creates a read-only CodePipeline deployment-role collector.
func NewCodePipelineDeploymentRoleCollector(client CodePipelineDeploymentRoleAPI, opts ...CodePipelineDeploymentRoleOption) *CodePipelineDeploymentRoleCollector {
	c := &CodePipelineDeploymentRoleCollector{
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

func (c *CodePipelineDeploymentRoleCollector) ServiceName() string {
	return codePipelineServiceName
}

// Collect pulls CodePipeline deployment-role assets using an empty scope.
func (c *CodePipelineDeploymentRoleCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: codePipelineServiceName})
	return assets, err
}

// CollectWithDiagnostics pulls CodePipeline deployment-role assets and includes non-fatal source errors.
func (c *CodePipelineDeploymentRoleCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("codepipeline deployment role collector requires client")
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
			return nil, nil, fmt.Errorf("codepipeline deployment role collection exceeded max pages (%d)", c.maxPages)
		}

		response, err := c.withRetry(ctx, func(callCtx context.Context) (CodePipelineDeploymentRolePage, error) {
			return c.client.ListServiceRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list codepipeline deployment roles page %d: %w", page, err)
			c.addIssue(providers.SourceError{
				Collector: codePipelineDeploymentRoleCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "codepipeline_deployment_role_page_failed",
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
			normalized := normalizeCodePipelineDeploymentRoleScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.PipelineARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: codePipelineDeploymentRoleCollectorName,
					Code:      "malformed_source_record",
					Message:   "skipped CodePipeline deployment role record without pipeline identity",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: codePipelineDeploymentRoleCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.PipelineARN, normalized.PipelineName, normalized.WorkloadID),
					Code:      "missing_codepipeline_deployment_role",
					Message:   "CodePipeline deployment role record did not include a role ARN",
					Retryable: false,
				})
				continue
			}

			sourceID := codePipelineDeploymentRoleSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal codepipeline deployment role %q: %w", sourceID, err)
			}

			assets = append(assets, providers.RawAsset{
				Kind:      rawKindCodePipelineDeploymentRole,
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

func (c *CodePipelineDeploymentRoleCollector) withRetry(ctx context.Context, fn func(context.Context) (CodePipelineDeploymentRolePage, error)) (CodePipelineDeploymentRolePage, error) {
	return retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, fn)
}

func (c *CodePipelineDeploymentRoleCollector) backoff(attempt int) time.Duration {
	return awsRetryBackoff(c.retry, c.jitter, c.randFn, attempt)
}

func (c *CodePipelineDeploymentRoleCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeCodePipelineDeploymentRoleScope(scope AWSCollectorScope, record CodePipelineDeploymentRole, collectedAt time.Time) CodePipelineDeploymentRole {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, codePipelineServiceName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(record.RoleARN))
	normalized.RoleAccountID = firstNonEmptyAWSValue(record.RoleAccountID, roleAccountIDFromARN(normalized.RoleARN))
	normalized.RoleKind = firstNonEmptyAWSValue(record.RoleKind, "pipeline_service_role")
	normalized.PipelineARN = strings.TrimSpace(record.PipelineARN)
	normalized.PipelineName = firstNonEmptyAWSValue(record.PipelineName, codePipelineNameFromARN(record.PipelineARN))
	normalized.PipelineType = strings.TrimSpace(record.PipelineType)
	normalized.ExecutionMode = strings.TrimSpace(record.ExecutionMode)
	normalized.StageName = strings.TrimSpace(record.StageName)
	normalized.ActionName = strings.TrimSpace(record.ActionName)
	normalized.ActionCategory = strings.TrimSpace(record.ActionCategory)
	normalized.ActionOwner = strings.TrimSpace(record.ActionOwner)
	normalized.ActionProvider = strings.TrimSpace(record.ActionProvider)
	normalized.ActionVersion = strings.TrimSpace(record.ActionVersion)
	normalized.ActionRegion = strings.TrimSpace(record.ActionRegion)
	normalized.Namespace = strings.TrimSpace(record.Namespace)
	normalized.InputArtifactNames = normalizeStringList(record.InputArtifactNames)
	normalized.OutputArtifactNames = normalizeStringList(record.OutputArtifactNames)
	normalized.ArtifactStoreTypes = normalizeStringList(record.ArtifactStoreTypes)
	normalized.ArtifactStoreLocations = normalizeStringList(record.ArtifactStoreLocations)
	normalized.ArtifactStoreRegions = normalizeStringList(record.ArtifactStoreRegions)
	normalized.ArtifactKMSKeyARNs = normalizeStringList(record.ArtifactKMSKeyARNs)
	normalized.ConfigurationKeys = normalizeStringList(record.ConfigurationKeys)
	normalized.ProviderIdentifiers = normalizeStringList(record.ProviderIdentifiers)
	normalized.DisabledStageTransitions = normalizeStringList(record.DisabledStageTransitions)
	normalized.Tags = copyTags(record.Tags)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, codePipelineDeploymentRoleWorkloadType(normalized))
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, codePipelineDeploymentRoleWorkloadRef(normalized))
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, codePipelineDeploymentRoleWorkloadName(normalized))
	normalized.Source = firstNonEmptyAWSValue(record.Source, "getpipeline")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.PipelineARN, normalized.RoleARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, codePipelineDeploymentRoleCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-codepipeline-deployment-role-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = codePipelineDeploymentRoleConfidence(normalized)
	}
	return normalized
}

func codePipelineDeploymentRoleConfidence(record CodePipelineDeploymentRole) float64 {
	if record.CrossAccountRole || record.CrossRegionAction || record.CrossRegionArtifactStores {
		return 0.9
	}
	if len(record.DisabledStageTransitions) > 0 {
		return 0.88
	}
	if record.RoleKind == "action_role" {
		return 0.94
	}
	return 0.96
}

func codePipelineDeploymentRoleSourceID(record CodePipelineDeploymentRole) string {
	return strings.Join([]string{
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.PipelineARN, record.WorkloadID, record.PipelineName, "pipeline"),
		firstNonEmptyAWSValue(record.StageName, "pipeline"),
		firstNonEmptyAWSValue(record.ActionName, record.RoleKind, "role"),
		firstNonEmptyAWSValue(record.RoleARN, "no-role"),
	}, "|")
}

func codePipelineDeploymentRoleWorkloadType(record CodePipelineDeploymentRole) string {
	if strings.EqualFold(record.RoleKind, "action_role") {
		return "codepipeline_action"
	}
	return "codepipeline_pipeline"
}

func codePipelineDeploymentRoleWorkloadRef(record CodePipelineDeploymentRole) string {
	parts := []string{firstNonEmptyAWSValue(record.PipelineARN, record.PipelineName)}
	if strings.EqualFold(record.RoleKind, "action_role") {
		parts = append(parts, record.StageName, record.ActionName)
	}
	return strings.Join(normalizeStringList(parts), "/")
}

func codePipelineDeploymentRoleWorkloadName(record CodePipelineDeploymentRole) string {
	if strings.EqualFold(record.RoleKind, "action_role") {
		return strings.Join(normalizeStringList([]string{record.PipelineName, record.StageName, record.ActionName}), " / ")
	}
	return firstNonEmptyAWSValue(record.PipelineName, codePipelineNameFromARN(record.PipelineARN), record.PipelineARN)
}

func codePipelineNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	marker := ":pipeline/"
	idx := strings.Index(trimmed, marker)
	if idx >= 0 {
		return strings.TrimSpace(trimmed[idx+len(marker):])
	}
	idx = strings.LastIndex(trimmed, ":")
	if idx < 0 || idx == len(trimmed)-1 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[idx+1:])
}

var _ AWSServiceCollector = (*CodePipelineDeploymentRoleCollector)(nil)
var _ providers.Collector = (*CodePipelineDeploymentRoleCollector)(nil)
