package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

const (
	sqsSNSPageTokenSQS       = "sqs:"
	sqsSNSPageTokenSNS       = "sns:"
	minSQSListQueuesPageSize = 1
	maxSQSListQueuesPageSize = 1000
)

// SQSSDKClient is the metadata-only SDK seam for SQS.
type SQSSDKClient interface {
	ListQueues(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(ctx context.Context, params *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
	ListQueueTags(ctx context.Context, params *sqs.ListQueueTagsInput, optFns ...func(*sqs.Options)) (*sqs.ListQueueTagsOutput, error)
}

// SNSSDKClient is the metadata-only SDK seam for SNS.
type SNSSDKClient interface {
	ListTopics(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	GetTopicAttributes(ctx context.Context, params *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
	ListSubscriptionsByTopic(ctx context.Context, params *sns.ListSubscriptionsByTopicInput, optFns ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error)
	GetSubscriptionAttributes(ctx context.Context, params *sns.GetSubscriptionAttributesInput, optFns ...func(*sns.Options)) (*sns.GetSubscriptionAttributesOutput, error)
	ListTagsForResource(ctx context.Context, params *sns.ListTagsForResourceInput, optFns ...func(*sns.Options)) (*sns.ListTagsForResourceOutput, error)
}

// SDKSQSSNSReachabilityAPI implements the reachability collector against AWS
// SDK SQS/SNS clients. It never calls SendMessage, ReceiveMessage, Publish, or
// any subscription-delivery API.
type SDKSQSSNSReachabilityAPI struct {
	sqsClient SQSSDKClient
	snsClient SNSSDKClient
	accountID string
	region    string
}

var _ SQSSNSReachabilityAPI = (*SDKSQSSNSReachabilityAPI)(nil)

func NewSDKSQSSNSReachabilityAPI(region string, profile string, accountID string) (SQSSNSReachabilityAPI, error) {
	return NewSDKSQSSNSReachabilityAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKSQSSNSReachabilityAPIWithContext(ctx context.Context, region string, profile string, accountID string) (SQSSNSReachabilityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolved, err := sqsSNSReachabilityAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKSQSSNSReachabilityAPIFromClients(sqs.NewFromConfig(cfg), sns.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

func NewSDKSQSSNSReachabilityAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (SQSSNSReachabilityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, fmt.Errorf("aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = textutil.FirstNonEmpty(strings.TrimSpace(sessionName), "identrail-recurring-scan")
		},
	}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(options *stscreds.AssumeRoleOptions) {
			options.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	resolved, err := sqsSNSReachabilityAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKSQSSNSReachabilityAPIFromClients(sqs.NewFromConfig(cfg), sns.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

func NewSDKSQSSNSReachabilityAPIFromClients(sqsClient SQSSDKClient, snsClient SNSSDKClient, accountID string, region string) SQSSNSReachabilityAPI {
	return &SDKSQSSNSReachabilityAPI{
		sqsClient: sqsClient,
		snsClient: snsClient,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

func (a *SDKSQSSNSReachabilityAPI) ListSQSSNSReachability(ctx context.Context, nextToken string, pageSize int32) (SQSSNSReachabilityPage, error) {
	if a.sqsClient == nil && a.snsClient == nil {
		return SQSSNSReachabilityPage{}, errors.New("sqs/sns SDK clients are required")
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	phase, token := sqsSNSDecodePageToken(nextToken)
	records := []SQSSNSReachability{}
	diagnostics := []providers.SourceError{}
	if phase == "" || phase == sqsServiceName {
		if a.sqsClient != nil {
			sqsRecords, sqsNext, sqsDiagnostics, err := a.listSQSReachabilityPage(ctx, token, pageSize)
			if err != nil {
				return SQSSNSReachabilityPage{}, err
			}
			records = append(records, sqsRecords...)
			diagnostics = append(diagnostics, sqsDiagnostics...)
			if sqsNext != "" {
				return SQSSNSReachabilityPage{Records: records, NextToken: sqsSNSPageTokenSQS + sqsNext, Diagnostics: diagnostics}, nil
			}
		}
		token = ""
	}
	if phase == "" || phase == sqsServiceName || phase == snsServiceName {
		if a.snsClient == nil {
			return SQSSNSReachabilityPage{Records: records, Diagnostics: diagnostics}, nil
		}
		snsRecords, snsNext, snsDiagnostics, err := a.listSNSReachabilityPage(ctx, token, pageSize)
		if err != nil {
			return SQSSNSReachabilityPage{}, err
		}
		records = append(records, snsRecords...)
		diagnostics = append(diagnostics, snsDiagnostics...)
		if snsNext != "" {
			return SQSSNSReachabilityPage{Records: records, NextToken: sqsSNSPageTokenSNS + snsNext, Diagnostics: diagnostics}, nil
		}
	}
	return SQSSNSReachabilityPage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKSQSSNSReachabilityAPI) listSQSReachabilityPage(ctx context.Context, nextToken string, pageSize int32) ([]SQSSNSReachability, string, []providers.SourceError, error) {
	output, err := a.sqsClient.ListQueues(ctx, &sqs.ListQueuesInput{
		MaxResults: awsv2.Int32(sqsListQueuesPageSize(pageSize)),
		NextToken:  stringPtrOrNil(nextToken),
	})
	if err != nil {
		return nil, "", nil, err
	}
	if output == nil {
		return nil, "", nil, nil
	}
	records := []SQSSNSReachability{}
	diagnostics := []providers.SourceError{}
	for _, queueURL := range output.QueueUrls {
		url := strings.TrimSpace(queueURL)
		if url == "" {
			continue
		}
		record := SQSSNSReachability{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				Service:   sqsServiceName,
				AccountID: a.accountID,
				Region:    a.region,
			},
			ResourceType: "sqs_queue",
			ResourceName: sqsQueueNameFromURL(url),
			QueueURL:     url,
			ResourceURL:  url,
		}
		record.ResourceARN = sqsQueueARNFromURL(url, a.accountID, a.region)
		a.enrichSQSQueueAttributes(ctx, url, &record, &diagnostics)
		a.enrichSQSQueueTags(ctx, url, &record, &diagnostics)
		records = append(records, record)
	}
	return records, strings.TrimSpace(awsv2.ToString(output.NextToken)), diagnostics, nil
}

func (a *SDKSQSSNSReachabilityAPI) enrichSQSQueueAttributes(ctx context.Context, queueURL string, record *SQSSNSReachability, diagnostics *[]providers.SourceError) {
	output, err := a.sqsClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       awsv2.String(queueURL),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameAll},
	})
	if err != nil {
		*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sqs_queue_attributes_failed", queueURL, fmt.Sprintf("GetQueueAttributes %q failed: %v", queueURL, err), true))
		return
	}
	if output == nil || len(output.Attributes) == 0 {
		return
	}
	attrs := output.Attributes
	record.ResourceARN = firstNonEmptyAWSValue(attrs["QueueArn"], record.ResourceARN)
	record.ResourceName = firstNonEmptyAWSValue(record.ResourceName, sqsSNSNameFromARN(record.ResourceARN), sqsQueueNameFromURL(queueURL))
	record.AccountID = firstNonEmptyAWSValue(a.accountID, accountIDFromARN(record.ResourceARN))
	record.Region = firstNonEmptyAWSValue(a.region, regionFromARN(record.ResourceARN))
	record.CreatedAt = unixSecondsStringToRFC3339(attrs["CreatedTimestamp"])
	record.LastModifiedAt = unixSecondsStringToRFC3339(attrs["LastModifiedTimestamp"])
	record.KMSKeyID = strings.TrimSpace(attrs["KmsMasterKeyId"])
	record.VisibilityTimeoutSeconds = intFromAWSString(attrs["VisibilityTimeout"])
	record.MessageRetentionSeconds = intFromAWSString(attrs["MessageRetentionPeriod"])
	record.Fifo = boolFromAWSString(attrs["FifoQueue"])
	record.ContentBasedDeduplication = boolFromAWSString(attrs["ContentBasedDeduplication"])
	record.SQSManagedSSE = boolFromAWSString(attrs["SqsManagedSseEnabled"])
	if rawPolicy := strings.TrimSpace(attrs["Policy"]); rawPolicy != "" {
		record.HasResourcePolicy = true
		record.ResourcePolicySource = "queue_policy"
		grants, statementCount, parseErr := parseSQSSNSPolicyGrants(rawPolicy, sqsServiceName)
		if parseErr != nil {
			*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sqs_queue_policy_parse_failed", firstNonEmptyAWSValue(record.ResourceARN, queueURL), fmt.Sprintf("parse SQS queue policy %q: %v", queueURL, parseErr), false))
		} else {
			record.ResourcePolicyStatementCount = statementCount
			record.IdentityGrants = grants
		}
	}
	record.DLQARNs = normalizeStringList(append(record.DLQARNs, deadLetterARNFromPolicy(attrs["RedrivePolicy"])))
}

func (a *SDKSQSSNSReachabilityAPI) enrichSQSQueueTags(ctx context.Context, queueURL string, record *SQSSNSReachability, diagnostics *[]providers.SourceError) {
	output, err := a.sqsClient.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: awsv2.String(queueURL)})
	if err != nil {
		*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sqs_queue_tags_failed", firstNonEmptyAWSValue(record.ResourceARN, queueURL), fmt.Sprintf("ListQueueTags %q failed: %v", queueURL, err), true))
		return
	}
	if output == nil || len(output.Tags) == 0 {
		return
	}
	tags := map[string]string{}
	for key, value := range output.Tags {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		tags[key] = strings.TrimSpace(value)
	}
	if len(tags) > 0 {
		record.Tags = tags
	}
}

func (a *SDKSQSSNSReachabilityAPI) listSNSReachabilityPage(ctx context.Context, nextToken string, _ int32) ([]SQSSNSReachability, string, []providers.SourceError, error) {
	output, err := a.snsClient.ListTopics(ctx, &sns.ListTopicsInput{NextToken: stringPtrOrNil(nextToken)})
	if err != nil {
		return nil, "", nil, err
	}
	if output == nil {
		return nil, "", nil, nil
	}
	records := []SQSSNSReachability{}
	diagnostics := []providers.SourceError{}
	for _, topic := range output.Topics {
		topicARN := strings.TrimSpace(awsv2.ToString(topic.TopicArn))
		if topicARN == "" {
			continue
		}
		record := SQSSNSReachability{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				Service:   snsServiceName,
				AccountID: firstNonEmptyAWSValue(a.accountID, accountIDFromARN(topicARN)),
				Region:    firstNonEmptyAWSValue(a.region, regionFromARN(topicARN)),
			},
			ResourceType: "sns_topic",
			ResourceARN:  topicARN,
			TopicARN:     topicARN,
			ResourceName: sqsSNSNameFromARN(topicARN),
		}
		a.enrichSNSTopicAttributes(ctx, topicARN, &record, &diagnostics)
		a.enrichSNSTopicSubscriptions(ctx, topicARN, &record, &diagnostics)
		a.enrichSNSTopicTags(ctx, topicARN, &record, &diagnostics)
		records = append(records, record)
	}
	return records, strings.TrimSpace(awsv2.ToString(output.NextToken)), diagnostics, nil
}

func (a *SDKSQSSNSReachabilityAPI) enrichSNSTopicAttributes(ctx context.Context, topicARN string, record *SQSSNSReachability, diagnostics *[]providers.SourceError) {
	output, err := a.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: awsv2.String(topicARN)})
	if err != nil {
		*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sns_topic_attributes_failed", topicARN, fmt.Sprintf("GetTopicAttributes %q failed: %v", topicARN, err), true))
		return
	}
	if output == nil || len(output.Attributes) == 0 {
		return
	}
	attrs := output.Attributes
	record.ResourceARN = firstNonEmptyAWSValue(attrs["TopicArn"], record.ResourceARN, topicARN)
	record.TopicARN = record.ResourceARN
	record.ResourceName = firstNonEmptyAWSValue(record.ResourceName, sqsSNSNameFromARN(record.ResourceARN))
	record.AccountID = firstNonEmptyAWSValue(a.accountID, attrs["Owner"], accountIDFromARN(record.ResourceARN))
	record.OwnerAccountID = firstNonEmptyAWSValue(attrs["Owner"], record.AccountID)
	record.Region = firstNonEmptyAWSValue(a.region, regionFromARN(record.ResourceARN))
	record.KMSKeyID = strings.TrimSpace(attrs["KmsMasterKeyId"])
	record.Fifo = boolFromAWSString(attrs["FifoTopic"])
	record.ContentBasedDeduplication = boolFromAWSString(attrs["ContentBasedDeduplication"])
	record.SubscriptionCount = intFromAWSString(attrs["SubscriptionsConfirmed"]) + intFromAWSString(attrs["SubscriptionsPending"])
	if rawPolicy := strings.TrimSpace(attrs["Policy"]); rawPolicy != "" {
		record.HasResourcePolicy = true
		record.ResourcePolicySource = "topic_policy"
		grants, statementCount, parseErr := parseSQSSNSPolicyGrants(rawPolicy, snsServiceName)
		if parseErr != nil {
			*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sns_topic_policy_parse_failed", topicARN, fmt.Sprintf("parse SNS topic policy %q: %v", topicARN, parseErr), false))
		} else {
			record.ResourcePolicyStatementCount = statementCount
			record.IdentityGrants = grants
		}
	}
}

func (a *SDKSQSSNSReachabilityAPI) enrichSNSTopicSubscriptions(ctx context.Context, topicARN string, record *SQSSNSReachability, diagnostics *[]providers.SourceError) {
	nextToken := ""
	pages := 0
	for {
		pages++
		if pages > defaultMaxPages {
			*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sns_topic_subscriptions_page_limit_exceeded", topicARN, fmt.Sprintf("SNS topic %q subscriptions exceeded max pages (%d)", topicARN, defaultMaxPages), false))
			return
		}
		output, err := a.snsClient.ListSubscriptionsByTopic(ctx, &sns.ListSubscriptionsByTopicInput{
			TopicArn:  awsv2.String(topicARN),
			NextToken: stringPtrOrNil(nextToken),
		})
		if err != nil {
			*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sns_topic_subscriptions_failed", topicARN, fmt.Sprintf("ListSubscriptionsByTopic %q failed: %v", topicARN, err), true))
			return
		}
		if output == nil {
			return
		}
		for _, subscription := range output.Subscriptions {
			ref := snsSubscriptionReference(subscription)
			a.enrichSNSSubscriptionAttributes(ctx, &ref, diagnostics)
			record.Subscriptions = append(record.Subscriptions, ref)
			if ref.DLQARN != "" {
				record.DLQARNs = append(record.DLQARNs, ref.DLQARN)
			}
		}
		nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if nextToken == "" {
			break
		}
	}
	record.DLQARNs = normalizeStringList(record.DLQARNs)
	if record.SubscriptionCount == 0 {
		record.SubscriptionCount = len(record.Subscriptions)
	}
}

func (a *SDKSQSSNSReachabilityAPI) enrichSNSSubscriptionAttributes(ctx context.Context, ref *SNSTopicSubscription, diagnostics *[]providers.SourceError) {
	if ref == nil || ref.SubscriptionARN == "" || strings.EqualFold(ref.SubscriptionARN, "PendingConfirmation") || strings.EqualFold(ref.SubscriptionARN, "Deleted") {
		if ref != nil {
			ref.PendingConfirmation = true
		}
		return
	}
	output, err := a.snsClient.GetSubscriptionAttributes(ctx, &sns.GetSubscriptionAttributesInput{SubscriptionArn: awsv2.String(ref.SubscriptionARN)})
	if err != nil {
		*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sns_subscription_attributes_failed", ref.SubscriptionARN, fmt.Sprintf("GetSubscriptionAttributes %q failed: %v", ref.SubscriptionARN, err), true))
		return
	}
	if output == nil || len(output.Attributes) == 0 {
		return
	}
	attrs := output.Attributes
	ref.RawMessageDelivery = boolFromAWSString(attrs["RawMessageDelivery"])
	ref.FilterPolicyPresent = strings.TrimSpace(attrs["FilterPolicy"]) != ""
	ref.PendingConfirmation = boolFromAWSString(attrs["PendingConfirmation"])
	ref.DLQARN = firstNonEmptyAWSValue(ref.DLQARN, deadLetterARNFromPolicy(attrs["RedrivePolicy"]))
}

func sqsListQueuesPageSize(value int32) int32 {
	if value < minSQSListQueuesPageSize {
		return minSQSListQueuesPageSize
	}
	if value > maxSQSListQueuesPageSize {
		return maxSQSListQueuesPageSize
	}
	return value
}

func (a *SDKSQSSNSReachabilityAPI) enrichSNSTopicTags(ctx context.Context, topicARN string, record *SQSSNSReachability, diagnostics *[]providers.SourceError) {
	output, err := a.snsClient.ListTagsForResource(ctx, &sns.ListTagsForResourceInput{ResourceArn: awsv2.String(topicARN)})
	if err != nil {
		*diagnostics = append(*diagnostics, sqsSNSReachabilityDiagnostic("sns_topic_tags_failed", topicARN, fmt.Sprintf("ListTagsForResource %q failed: %v", topicARN, err), true))
		return
	}
	if output == nil || len(output.Tags) == 0 {
		return
	}
	tags := map[string]string{}
	for _, tag := range output.Tags {
		key := strings.TrimSpace(awsv2.ToString(tag.Key))
		if key == "" {
			continue
		}
		tags[key] = strings.TrimSpace(awsv2.ToString(tag.Value))
	}
	if len(tags) > 0 {
		record.Tags = tags
	}
}

func snsSubscriptionReference(subscription snstypes.Subscription) SNSTopicSubscription {
	endpoint := strings.TrimSpace(awsv2.ToString(subscription.Endpoint))
	ref := SNSTopicSubscription{
		SubscriptionARN: strings.TrimSpace(awsv2.ToString(subscription.SubscriptionArn)),
		Protocol:        strings.ToLower(strings.TrimSpace(awsv2.ToString(subscription.Protocol))),
		OwnerAccountID:  strings.TrimSpace(awsv2.ToString(subscription.Owner)),
	}
	if ref.SubscriptionARN == "" || strings.EqualFold(ref.SubscriptionARN, "PendingConfirmation") {
		ref.PendingConfirmation = true
	}
	if endpoint != "" {
		ref.EndpointPresent = true
		if strings.HasPrefix(endpoint, "arn:") {
			ref.EndpointResourceARN = endpoint
		} else {
			ref.EndpointRedacted = true
		}
	}
	return ref
}

func sqsSNSDecodePageToken(raw string) (string, string) {
	trimmed := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(trimmed, sqsSNSPageTokenSQS):
		return sqsServiceName, strings.TrimPrefix(trimmed, sqsSNSPageTokenSQS)
	case strings.HasPrefix(trimmed, sqsSNSPageTokenSNS):
		return snsServiceName, strings.TrimPrefix(trimmed, sqsSNSPageTokenSNS)
	case trimmed != "":
		return sqsServiceName, trimmed
	default:
		return "", ""
	}
}

func sqsSNSReachabilityAccountID(ctx context.Context, cfg awsv2.Config, accountID string) (string, error) {
	trimmed := strings.TrimSpace(accountID)
	if trimmed != "" {
		return trimmed, nil
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("read AWS caller identity for sqs/sns account id: %w", err)
	}
	resolved := strings.TrimSpace(awsv2.ToString(identity.Account))
	if resolved == "" {
		return "", fmt.Errorf("read AWS caller identity for sqs/sns account id: empty account id")
	}
	return resolved, nil
}

func sqsSNSReachabilityDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: sqsSNSReachabilityCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func deadLetterARNFromPolicy(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(trimmed), &document); err != nil {
		return ""
	}
	for _, key := range []string{"deadLetterTargetArn", "deadLetterTargetARN", "arn"} {
		if value, ok := document[key].(string); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func boolFromAWSString(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}

func intFromAWSString(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return parsed
}

func unixSecondsStringToRFC3339(value string) string {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z")
}
