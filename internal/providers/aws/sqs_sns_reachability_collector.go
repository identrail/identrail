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
	rawKindSQSSNSReachability       = "sqs_sns_reachability"
	sqsSNSReachabilityCollectorName = "sqs_sns_reachability"
	sqsSNSServiceName               = "sqs_sns"
	sqsServiceName                  = "sqs"
	snsServiceName                  = "sns"
)

// SQSSNSReachability is one metadata-only SQS queue or SNS topic resource.
// It captures policy-derived reachability and safe configuration context, but
// never reads message bodies, notification payloads, or subscription endpoint
// secrets.
type SQSSNSReachability struct {
	awscontract.ServiceCollectorRecord

	ResourceARN  string `json:"resource_arn,omitempty"`
	ResourceName string `json:"resource_name,omitempty"`
	ResourceType string `json:"resource_type,omitempty"` // sqs_queue or sns_topic
	ResourceURL  string `json:"resource_url,omitempty"`
	QueueURL     string `json:"queue_url,omitempty"`
	TopicARN     string `json:"topic_arn,omitempty"`

	OwnerAccountID string `json:"owner_account_id,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	LastModifiedAt string `json:"last_modified_at,omitempty"`
	ResourceStatus string `json:"resource_status,omitempty"`

	Fifo                      bool `json:"fifo,omitempty"`
	ContentBasedDeduplication bool `json:"content_based_deduplication,omitempty"`
	SQSManagedSSE             bool `json:"sqs_managed_sse,omitempty"`

	KMSKeyID                 string `json:"kms_key_id,omitempty"`
	VisibilityTimeoutSeconds int    `json:"visibility_timeout_seconds,omitempty"`
	MessageRetentionSeconds  int    `json:"message_retention_seconds,omitempty"`

	DLQARNs []string `json:"dlq_arns,omitempty"`

	SubscriptionCount int                    `json:"subscription_count,omitempty"`
	Subscriptions     []SNSTopicSubscription `json:"subscriptions,omitempty"`

	HasResourcePolicy            bool                  `json:"has_resource_policy,omitempty"`
	ResourcePolicyStatementCount int                   `json:"resource_policy_statement_count,omitempty"`
	ResourcePolicySource         string                `json:"resource_policy_source,omitempty"`
	IdentityGrants               []SQSSNSIdentityGrant `json:"identity_grants,omitempty"`

	ExposureClassification string   `json:"exposure_classification,omitempty"`
	ExposureReasons        []string `json:"exposure_reasons,omitempty"`

	Tags map[string]string `json:"tags,omitempty"`
}

// SQSSNSIdentityGrant is one resource-policy principal grant inferred from an
// SQS queue policy or SNS topic policy.
type SQSSNSIdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"` // aws, service, federated, canonical_user, *
	Effect            string   `json:"effect"`
	Actions           []string `json:"actions,omitempty"`
	NotAction         bool     `json:"not_action,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"` // publish, consume, subscribe, manage, unknown
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

// SNSTopicSubscription is subscription metadata with endpoint values redacted
// unless the endpoint is itself an AWS ARN that can become a graph node.
type SNSTopicSubscription struct {
	SubscriptionARN     string `json:"subscription_arn,omitempty"`
	Protocol            string `json:"protocol,omitempty"`
	OwnerAccountID      string `json:"owner_account_id,omitempty"`
	EndpointResourceARN string `json:"endpoint_resource_arn,omitempty"`
	EndpointPresent     bool   `json:"endpoint_present,omitempty"`
	EndpointRedacted    bool   `json:"endpoint_redacted,omitempty"`
	PendingConfirmation bool   `json:"pending_confirmation,omitempty"`
	RawMessageDelivery  bool   `json:"raw_message_delivery,omitempty"`
	FilterPolicyPresent bool   `json:"filter_policy_present,omitempty"`
	DLQARN              string `json:"dlq_arn,omitempty"`
}

// SQSSNSReachabilityPage is one page of queue/topic records plus diagnostics.
type SQSSNSReachabilityPage struct {
	Records     []SQSSNSReachability
	NextToken   string
	Diagnostics []providers.SourceError
}

// SQSSNSReachabilityAPI is implemented by SDK and fixture-backed readers.
type SQSSNSReachabilityAPI interface {
	ListSQSSNSReachability(ctx context.Context, nextToken string, pageSize int32) (SQSSNSReachabilityPage, error)
}

// SQSSNSReachabilityCollector turns SQS/SNS metadata into raw assets.
type SQSSNSReachabilityCollector struct {
	client   SQSSNSReachabilityAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

// SQSSNSReachabilityOption tunes the collector.
type SQSSNSReachabilityOption func(*SQSSNSReachabilityCollector)

func WithSQSSNSReachabilityPageSize(pageSize int32) SQSSNSReachabilityOption {
	return func(c *SQSSNSReachabilityCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithSQSSNSReachabilityMaxPages(maxPages int) SQSSNSReachabilityOption {
	return func(c *SQSSNSReachabilityCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithSQSSNSReachabilityRetryPolicy(policy RetryPolicy) SQSSNSReachabilityOption {
	return func(c *SQSSNSReachabilityCollector) {
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

func WithSQSSNSReachabilitySleeper(s Sleeper) SQSSNSReachabilityOption {
	return func(c *SQSSNSReachabilityCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func WithSQSSNSReachabilityClock(now func() time.Time) SQSSNSReachabilityOption {
	return func(c *SQSSNSReachabilityCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewSQSSNSReachabilityCollector constructs the collector with the same
// retry/page defaults as other AWS service collectors.
func NewSQSSNSReachabilityCollector(client SQSSNSReachabilityAPI, opts ...SQSSNSReachabilityOption) *SQSSNSReachabilityCollector {
	c := &SQSSNSReachabilityCollector{
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

func (c *SQSSNSReachabilityCollector) ServiceName() string {
	return sqsSNSServiceName
}

func (c *SQSSNSReachabilityCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: sqsSNSServiceName})
	return assets, err
}

func (c *SQSSNSReachabilityCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("sqs/sns reachability collector requires client")
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
			addIssue(providers.SourceError{
				Collector: sqsSNSReachabilityCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "sqs_sns_reachability_page_limit_exceeded",
				Message:   fmt.Sprintf("sqs/sns reachability collection exceeded max pages (%d)", c.maxPages),
				Retryable: false,
			})
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("sqs/sns reachability collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (SQSSNSReachabilityPage, error) {
			return c.client.ListSQSSNSReachability(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list sqs/sns reachability page %d: %w", page, err)
			addIssue(providers.SourceError{
				Collector: sqsSNSReachabilityCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "sqs_sns_reachability_page_failed",
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
			normalized := normalizeSQSSNSReachabilityScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.ResourceARN) == "" && strings.TrimSpace(normalized.ResourceName) == "" {
				addIssue(providers.SourceError{
					Collector: sqsSNSReachabilityCollectorName,
					Code:      "malformed_sqs_sns_reachability_record",
					Message:   "skipped sqs/sns record without an ARN or name",
					Retryable: false,
				})
				continue
			}
			sourceID := sqsSNSReachabilitySourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal sqs/sns reachability %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindSQSSNSReachability,
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

func normalizeSQSSNSReachabilityScope(scope AWSCollectorScope, record SQSSNSReachability, collectedAt time.Time) SQSSNSReachability {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, record.OwnerAccountID, scope.AccountID, accountIDFromARN(record.ResourceARN), accountIDFromARN(record.TopicARN))
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region, regionFromARN(record.ResourceARN), regionFromARN(record.TopicARN))
	normalized.ResourceARN = firstNonEmptyAWSValue(record.ResourceARN, record.TopicARN, sqsQueueARNFromURL(record.QueueURL, normalized.AccountID, normalized.Region))
	normalized.ResourceType = firstNonEmptyAWSValue(record.ResourceType, sqsSNSResourceTypeForRecord(record))
	normalized.ResourceName = firstNonEmptyAWSValue(record.ResourceName, sqsSNSNameFromARN(normalized.ResourceARN), sqsQueueNameFromURL(record.QueueURL))
	normalized.OwnerAccountID = firstNonEmptyAWSValue(record.OwnerAccountID, normalized.AccountID)
	normalized.Service = firstNonEmptyAWSValue(record.Service, sqsSNSServiceForResourceType(normalized.ResourceType), scope.Service)
	if normalized.Service == sqsSNSServiceName {
		normalized.Service = sqsSNSServiceForResourceType(normalized.ResourceType)
	}
	normalized.QueueURL = strings.TrimSpace(record.QueueURL)
	normalized.ResourceURL = firstNonEmptyAWSValue(record.ResourceURL, normalized.QueueURL)
	normalized.TopicARN = firstNonEmptyAWSValue(record.TopicARN, normalized.ResourceARN)
	if normalized.Service == sqsServiceName {
		normalized.TopicARN = strings.TrimSpace(record.TopicARN)
	}
	if normalized.Service == snsServiceName {
		normalized.QueueURL = strings.TrimSpace(record.QueueURL)
		normalized.ResourceURL = strings.TrimSpace(record.ResourceURL)
	}
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, normalized.ResourceType)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.ResourceName)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.ResourceARN, normalized.ResourceName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "sqs_sns_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.ResourceARN, normalized.ResourceName)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, sqsSNSReachabilityCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-sqs-sns-reachability-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.KMSKeyID = strings.TrimSpace(record.KMSKeyID)
	normalized.DLQARNs = normalizeStringList(record.DLQARNs)
	normalized.Subscriptions = normalizeSQSSNSSubscriptions(record.Subscriptions)
	if normalized.SubscriptionCount == 0 {
		normalized.SubscriptionCount = len(normalized.Subscriptions)
	}
	normalized.IdentityGrants = annotateSQSSNSGrants(record.IdentityGrants, normalized.AccountID)
	normalized.ExposureClassification, normalized.ExposureReasons = classifySQSSNSExposure(normalized)
	normalized.Tags = copyTags(record.Tags)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = sqsSNSReachabilityConfidence(normalized)
	}
	return normalized
}

func annotateSQSSNSGrants(grants []SQSSNSIdentityGrant, accountID string) []SQSSNSIdentityGrant {
	if len(grants) == 0 {
		return nil
	}
	out := make([]SQSSNSIdentityGrant, 0, len(grants))
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
			grantAccount := accountIDFromPrincipal(grant.PrincipalARN)
			if grantAccount != "" && grantAccount != accountID {
				grant.IsCrossAccount = true
			}
		}
		grant.HasCondition = grant.HasCondition || len(grant.ConditionKeys) > 0
		out = append(out, grant)
	}
	return out
}

func normalizeSQSSNSSubscriptions(subscriptions []SNSTopicSubscription) []SNSTopicSubscription {
	if len(subscriptions) == 0 {
		return nil
	}
	out := make([]SNSTopicSubscription, 0, len(subscriptions))
	for _, subscription := range subscriptions {
		subscription.SubscriptionARN = strings.TrimSpace(subscription.SubscriptionARN)
		subscription.Protocol = strings.ToLower(strings.TrimSpace(subscription.Protocol))
		subscription.OwnerAccountID = strings.TrimSpace(subscription.OwnerAccountID)
		subscription.EndpointResourceARN = strings.TrimSpace(subscription.EndpointResourceARN)
		subscription.DLQARN = strings.TrimSpace(subscription.DLQARN)
		out = append(out, subscription)
	}
	sort.SliceStable(out, func(i, j int) bool {
		left := firstNonEmptyAWSValue(out[i].SubscriptionARN, out[i].EndpointResourceARN, out[i].Protocol)
		right := firstNonEmptyAWSValue(out[j].SubscriptionARN, out[j].EndpointResourceARN, out[j].Protocol)
		return left < right
	})
	return out
}

func classifySQSSNSExposure(record SQSSNSReachability) (string, []string) {
	reasons := []string{}
	public := false
	crossAccount := false
	denyAll := false
	for _, grant := range record.IdentityGrants {
		switch grant.Effect {
		case "Allow":
			if grant.IsPublic && !grant.HasCondition {
				public = true
				reasons = append(reasons, record.Service+"_policy_allow_to_wildcard_principal")
			}
			if grant.IsCrossAccount && !grant.HasCondition {
				crossAccount = true
				reasons = append(reasons, record.Service+"_policy_allow_to_cross_account_principal")
			}
			if grant.HasCondition {
				reasons = append(reasons, record.Service+"_policy_condition_scoped")
			}
		case "Deny":
			if grant.WildcardPrincipal && !grant.HasCondition {
				denyAll = true
				reasons = append(reasons, record.Service+"_policy_explicit_deny_to_all")
			}
		}
	}
	if record.KMSKeyID != "" {
		reasons = append(reasons, record.Service+"_encryption_key_configured")
	}
	if len(record.DLQARNs) > 0 {
		reasons = append(reasons, record.Service+"_dead_letter_queue_configured")
	}
	switch {
	case denyAll:
		return "restricted", dedupeStrings(reasons)
	case public:
		return "public", dedupeStrings(reasons)
	case crossAccount:
		return "cross_account", dedupeStrings(reasons)
	case record.HasResourcePolicy:
		return "private_with_grants", dedupeStrings(reasons)
	default:
		return "private", dedupeStrings(reasons)
	}
}

func sqsSNSReachabilityConfidence(record SQSSNSReachability) float64 {
	switch record.ExposureClassification {
	case "public":
		return 0.94
	case "cross_account":
		return 0.91
	case "restricted":
		return 0.9
	case "private_with_grants":
		return 0.87
	case "private":
		return 0.85
	default:
		return 0.7
	}
}

func sqsSNSReachabilitySourceID(record SQSSNSReachability) string {
	return strings.Join(normalizeStringList([]string{
		record.Service,
		firstNonEmptyAWSValue(record.ResourceARN, record.ResourceName),
		record.Region,
	}), "|")
}

func sqsSNSResourceTypeForRecord(record SQSSNSReachability) string {
	if strings.TrimSpace(record.QueueURL) != "" || strings.EqualFold(record.Service, sqsServiceName) {
		return "sqs_queue"
	}
	if strings.TrimSpace(record.TopicARN) != "" || strings.EqualFold(record.Service, snsServiceName) {
		return "sns_topic"
	}
	return strings.TrimSpace(record.ResourceType)
}

func sqsSNSServiceForResourceType(resourceType string) string {
	switch strings.ToLower(strings.TrimSpace(resourceType)) {
	case "sqs_queue":
		return sqsServiceName
	case "sns_topic":
		return snsServiceName
	default:
		return sqsSNSServiceName
	}
}

func sqsSNSNameFromARN(arn string) string {
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
	return resource
}

func sqsQueueNameFromURL(queueURL string) string {
	trimmed := strings.TrimSpace(queueURL)
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

func sqsQueueARNFromURL(queueURL, accountID, region string) string {
	name := sqsQueueNameFromURL(queueURL)
	if name == "" || strings.TrimSpace(accountID) == "" || strings.TrimSpace(region) == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:sqs:%s:%s:%s", awsPartitionForRegion(region), strings.TrimSpace(region), strings.TrimSpace(accountID), name)
}

var _ AWSServiceCollector = (*SQSSNSReachabilityCollector)(nil)
var _ providers.Collector = (*SQSSNSReachabilityCollector)(nil)
