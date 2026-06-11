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
	rawKindDynamoDBRDSReachability       = "dynamodb_rds_reachability"
	dynamoDBRDSReachabilityCollectorName = "dynamodb_rds_reachability"
	dynamoDBRDSServiceName               = "dynamodb_rds"
	dynamoDBServiceName                  = "dynamodb"
	rdsServiceName                       = "rds"
)

type DynamoDBRDSReachability struct {
	awscontract.ServiceCollectorRecord

	ResourceARN  string `json:"resource_arn,omitempty"`
	ResourceName string `json:"resource_name,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`

	Engine         string `json:"engine,omitempty"`
	EngineVersion  string `json:"engine_version,omitempty"`
	ResourceStatus string `json:"resource_status,omitempty"`
	Endpoint       string `json:"endpoint,omitempty"`

	KMSKeyID                         string `json:"kms_key_id,omitempty"`
	StorageEncrypted                 bool   `json:"storage_encrypted,omitempty"`
	IAMDatabaseAuthenticationEnabled bool   `json:"iam_database_authentication_enabled,omitempty"`
	PubliclyAccessible               bool   `json:"publicly_accessible,omitempty"`
	DeletionProtectionEnabled        bool   `json:"deletion_protection_enabled,omitempty"`
	PerformanceInsightsEnabled       bool   `json:"performance_insights_enabled,omitempty"`
	StreamEnabled                    bool   `json:"stream_enabled,omitempty"`
	StreamARN                        string `json:"stream_arn,omitempty"`
	BillingMode                      string `json:"billing_mode,omitempty"`

	AssociatedRoleARNs           []string                   `json:"associated_role_arns,omitempty"`
	IdentityGrants               []DynamoDBRDSIdentityGrant `json:"identity_grants,omitempty"`
	HasResourcePolicy            bool                       `json:"has_resource_policy,omitempty"`
	ResourcePolicyStatementCount int                        `json:"resource_policy_statement_count,omitempty"`
	ResourcePolicySource         string                     `json:"resource_policy_source,omitempty"`

	ExposureClassification string            `json:"exposure_classification,omitempty"`
	ExposureReasons        []string          `json:"exposure_reasons,omitempty"`
	Tags                   map[string]string `json:"tags,omitempty"`
}

type DynamoDBRDSIdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"`
	Effect            string   `json:"effect"`
	Actions           []string `json:"actions,omitempty"`
	NotAction         bool     `json:"not_action,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

type DynamoDBRDSReachabilityPage struct {
	Records     []DynamoDBRDSReachability
	NextToken   string
	Diagnostics []providers.SourceError
}

type DynamoDBRDSReachabilityAPI interface {
	ListDynamoDBRDSReachability(ctx context.Context, nextToken string, pageSize int32) (DynamoDBRDSReachabilityPage, error)
}

type DynamoDBRDSReachabilityCollector struct {
	client   DynamoDBRDSReachabilityAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

type DynamoDBRDSReachabilityOption func(*DynamoDBRDSReachabilityCollector)

func WithDynamoDBRDSReachabilityPageSize(pageSize int32) DynamoDBRDSReachabilityOption {
	return func(c *DynamoDBRDSReachabilityCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithDynamoDBRDSReachabilityMaxPages(maxPages int) DynamoDBRDSReachabilityOption {
	return func(c *DynamoDBRDSReachabilityCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithDynamoDBRDSReachabilitySleeper(s Sleeper) DynamoDBRDSReachabilityOption {
	return func(c *DynamoDBRDSReachabilityCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func NewDynamoDBRDSReachabilityCollector(client DynamoDBRDSReachabilityAPI, opts ...DynamoDBRDSReachabilityOption) *DynamoDBRDSReachabilityCollector {
	c := &DynamoDBRDSReachabilityCollector{
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

func (c *DynamoDBRDSReachabilityCollector) ServiceName() string {
	return dynamoDBRDSServiceName
}

func (c *DynamoDBRDSReachabilityCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: dynamoDBRDSServiceName})
	return assets, err
}

func (c *DynamoDBRDSReachabilityCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("dynamodb/rds reachability collector requires client")
	}
	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}
	assets := []providers.RawAsset{}
	issues := []providers.SourceError{}
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()
	processRecords := func(records []DynamoDBRDSReachability) error {
		for _, record := range records {
			normalized := normalizeDynamoDBRDSReachabilityScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.ResourceARN) == "" && strings.TrimSpace(normalized.ResourceName) == "" {
				issues = append(issues, providers.SourceError{Collector: dynamoDBRDSReachabilityCollectorName, Code: "malformed_dynamodb_rds_reachability_record", Message: "skipped dynamodb/rds record without an ARN or name"})
				continue
			}
			sourceID := dynamoDBRDSReachabilitySourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, marshalErr := json.Marshal(normalized)
			if marshalErr != nil {
				return fmt.Errorf("marshal dynamodb/rds reachability %q: %w", sourceID, marshalErr)
			}
			assets = append(assets, providers.RawAsset{Kind: rawKindDynamoDBRDSReachability, SourceID: sourceID, Payload: payload, Collected: collectedAt.Format(time.RFC3339Nano)})
			seen[sourceID] = struct{}{}
		}
		return nil
	}
	for page := 1; ; page++ {
		if page > c.maxPages {
			issue := providers.SourceError{Collector: dynamoDBRDSReachabilityCollectorName, SourceID: firstNonEmptyAWSValue(nextToken, "page"), Code: "dynamodb_rds_reachability_page_limit_exceeded", Message: fmt.Sprintf("dynamodb/rds reachability collection exceeded max pages (%d)", c.maxPages)}
			return assets, append(issues, issue), fmt.Errorf("dynamodb/rds reachability collection exceeded max pages (%d)", c.maxPages)
		}

		response, err := c.listDynamoDBRDSReachabilityPage(ctx, nextToken)
		if err != nil {
			issues = append(issues, response.Diagnostics...)
			wrapped := fmt.Errorf("list dynamodb/rds reachability page %d: %w", page, err)
			issues = append(issues, providers.SourceError{Collector: dynamoDBRDSReachabilityCollectorName, SourceID: firstNonEmptyAWSValue(nextToken, "page"), Code: "dynamodb_rds_reachability_page_failed", Message: wrapped.Error(), Retryable: isRetryable(err)})
			if marshalErr := processRecords(response.Records); marshalErr != nil {
				return nil, nil, marshalErr
			}
			if len(assets) > 0 {
				return assets, issues, wrapped
			}
			return nil, issues, wrapped
		}

		issues = append(issues, response.Diagnostics...)
		if marshalErr := processRecords(response.Records); marshalErr != nil {
			return nil, nil, marshalErr
		}
		if strings.TrimSpace(response.NextToken) == "" {
			break
		}
		nextToken = strings.TrimSpace(response.NextToken)
	}
	return assets, issues, nil
}

func (c *DynamoDBRDSReachabilityCollector) listDynamoDBRDSReachabilityPage(ctx context.Context, nextToken string) (DynamoDBRDSReachabilityPage, error) {
	var response DynamoDBRDSReachabilityPage
	var err error
	for attempt := 0; attempt <= c.retry.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			return response, ctx.Err()
		}
		response, err = c.client.ListDynamoDBRDSReachability(ctx, nextToken, c.pageSize)
		if err == nil {
			return response, nil
		}
		if !isRetryable(err) || attempt == c.retry.MaxRetries {
			return response, fmt.Errorf("retries exhausted: %w", err)
		}
		delay := awsRetryBackoff(c.retry, c.jitter, c.randFn, attempt)
		if sleepErr := c.sleep(ctx, delay); sleepErr != nil {
			return response, sleepErr
		}
	}

	return response, fmt.Errorf("retries exhausted: %w", err)
}

func normalizeDynamoDBRDSReachabilityScope(scope AWSCollectorScope, record DynamoDBRDSReachability, collectedAt time.Time) DynamoDBRDSReachability {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID, accountIDFromARN(record.ResourceARN))
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region, regionFromARN(record.ResourceARN))
	normalized.Service = firstNonEmptyAWSValue(record.Service, dynamoDBRDSServiceForResourceType(record.ResourceType), scope.Service)
	if normalized.Service == dynamoDBRDSServiceName {
		normalized.Service = dynamoDBRDSServiceForResourceType(record.ResourceType)
	}
	normalized.ResourceARN = strings.TrimSpace(record.ResourceARN)
	normalized.ResourceName = firstNonEmptyAWSValue(record.ResourceName, dynamoDBRDSNameFromARN(record.ResourceARN))
	normalized.ResourceID = firstNonEmptyAWSValue(record.ResourceID, normalized.ResourceARN, normalized.ResourceName)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, normalized.ResourceType)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.ResourceName)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.ResourceID)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "dynamodb_rds_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.ResourceARN, normalized.ResourceName)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, dynamoDBRDSReachabilityCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-dynamodb-rds-reachability-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.AssociatedRoleARNs = normalizeStringList(record.AssociatedRoleARNs)
	normalized.IdentityGrants = annotateDynamoDBRDSGrants(record.IdentityGrants, normalized.AccountID)
	normalized.ExposureClassification, normalized.ExposureReasons = classifyDynamoDBRDSExposure(normalized)
	normalized.Tags = copyTags(record.Tags)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = dynamoDBRDSReachabilityConfidence(normalized)
	}
	return normalized
}

func annotateDynamoDBRDSGrants(grants []DynamoDBRDSIdentityGrant, accountID string) []DynamoDBRDSIdentityGrant {
	out := make([]DynamoDBRDSIdentityGrant, 0, len(grants))
	for _, grant := range grants {
		grant.PrincipalARN = strings.TrimSpace(grant.PrincipalARN)
		grant.PrincipalType = strings.ToLower(strings.TrimSpace(grant.PrincipalType))
		grant.Effect = canonicalSQSSNSGrantEffect(grant.Effect)
		grant.Actions = normalizeStringList(grant.Actions)
		grant.Capabilities = normalizeStringList(grant.Capabilities)
		grant.ConditionKeys = normalizeStringList(grant.ConditionKeys)
		grant.WildcardPrincipal = grant.WildcardPrincipal || grant.PrincipalARN == "*"
		grant.IsPublic = grant.IsPublic || grant.WildcardPrincipal
		if !grant.IsCrossAccount && accountID != "" && grant.PrincipalARN != "" && grant.PrincipalARN != "*" {
			if grantAccount := accountIDFromPrincipal(grant.PrincipalARN); grantAccount != "" && grantAccount != accountID {
				grant.IsCrossAccount = true
			}
		}
		grant.HasCondition = grant.HasCondition || len(grant.ConditionKeys) > 0
		out = append(out, grant)
	}
	return out
}

func classifyDynamoDBRDSExposure(record DynamoDBRDSReachability) (string, []string) {
	reasons := []string{}
	public := record.PubliclyAccessible
	crossAccount := false
	if record.PubliclyAccessible {
		reasons = append(reasons, record.Service+"_public_endpoint")
	}
	for _, grant := range record.IdentityGrants {
		if !strings.EqualFold(grant.Effect, "Allow") {
			continue
		}
		if grant.IsPublic && !grant.HasCondition {
			public = true
			reasons = append(reasons, record.Service+"_policy_allow_to_wildcard_principal")
		}
		if grant.IsCrossAccount && !grant.HasCondition {
			crossAccount = true
			reasons = append(reasons, record.Service+"_policy_allow_to_cross_account_principal")
		}
	}
	if record.StorageEncrypted || strings.TrimSpace(record.KMSKeyID) != "" {
		reasons = append(reasons, record.Service+"_encryption_key_configured")
	}
	if record.IAMDatabaseAuthenticationEnabled {
		reasons = append(reasons, "rds_iam_database_authentication_enabled")
	}
	if len(record.AssociatedRoleARNs) > 0 {
		reasons = append(reasons, record.Service+"_associated_iam_roles")
	}
	switch {
	case public:
		return "public", dedupeStrings(reasons)
	case crossAccount:
		return "cross_account", dedupeStrings(reasons)
	case len(record.IdentityGrants) > 0 || len(record.AssociatedRoleARNs) > 0:
		return "private_with_grants", dedupeStrings(reasons)
	default:
		return "private", dedupeStrings(reasons)
	}
}

func dynamoDBRDSReachabilityConfidence(record DynamoDBRDSReachability) float64 {
	switch record.ExposureClassification {
	case "public":
		return 0.94
	case "cross_account":
		return 0.91
	case "private_with_grants":
		return 0.87
	default:
		return 0.84
	}
}

func dynamoDBRDSReachabilitySourceID(record DynamoDBRDSReachability) string {
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.ResourceType,
		strings.TrimSpace(record.ResourceARN),
		strings.TrimSpace(record.ResourceName),
		record.Region,
	}), "|")
}

func dynamoDBRDSServiceForResourceType(resourceType string) string {
	switch strings.ToLower(strings.TrimSpace(resourceType)) {
	case "dynamodb_table", "dynamodb_stream":
		return dynamoDBServiceName
	case "rds_instance", "rds_cluster", "rds_proxy":
		return rdsServiceName
	default:
		return dynamoDBRDSServiceName
	}
}

func dynamoDBRDSNameFromARN(arn string) string {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) != 6 {
		return ""
	}
	resource := strings.TrimSpace(parts[5])
	if resource == "" {
		return ""
	}
	if idx := strings.LastIndex(resource, "/"); idx >= 0 && idx < len(resource)-1 {
		return resource[idx+1:]
	}
	if idx := strings.LastIndex(resource, ":"); idx >= 0 && idx < len(resource)-1 {
		return resource[idx+1:]
	}
	return resource
}

func sortDynamoDBRDSRecords(records []DynamoDBRDSReachability) {
	sort.SliceStable(records, func(i, j int) bool {
		return dynamoDBRDSReachabilitySourceID(records[i]) < dynamoDBRDSReachabilitySourceID(records[j])
	})
}

var _ AWSServiceCollector = (*DynamoDBRDSReachabilityCollector)(nil)
var _ providers.Collector = (*DynamoDBRDSReachabilityCollector)(nil)
