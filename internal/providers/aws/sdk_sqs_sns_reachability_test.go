package aws

import (
	"context"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type fakeSDKSQSSNSSQSClient struct {
	listQueuesOutputs       []sqs.ListQueuesOutput
	listQueuesErr           error
	listQueuesCall          int
	listQueuesInputs        []sqs.ListQueuesInput
	getQueueAttributesByURL map[string]*sqs.GetQueueAttributesOutput
	getQueueAttributesErr   map[string]error
	listQueueTagsByURL      map[string]*sqs.ListQueueTagsOutput
	listQueueTagsErr        map[string]error
}

func (f *fakeSDKSQSSNSSQSClient) ListQueues(ctx context.Context, input *sqs.ListQueuesInput, _ ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	f.listQueuesCall++
	f.listQueuesInputs = append(f.listQueuesInputs, *input)
	if f.listQueuesErr != nil {
		return nil, f.listQueuesErr
	}
	if f.listQueuesCall > len(f.listQueuesOutputs) {
		return &sqs.ListQueuesOutput{}, nil
	}
	return &f.listQueuesOutputs[f.listQueuesCall-1], nil
}

func (f *fakeSDKSQSSNSSQSClient) GetQueueAttributes(ctx context.Context, input *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	queueURL := strings.TrimSpace(awsv2.ToString(input.QueueUrl))
	if f.getQueueAttributesErr != nil {
		if err, ok := f.getQueueAttributesErr[queueURL]; ok {
			return nil, err
		}
	}
	if f.getQueueAttributesByURL != nil {
		if output, ok := f.getQueueAttributesByURL[queueURL]; ok {
			return output, nil
		}
	}
	return &sqs.GetQueueAttributesOutput{}, nil
}

func (f *fakeSDKSQSSNSSQSClient) ListQueueTags(ctx context.Context, input *sqs.ListQueueTagsInput, _ ...func(*sqs.Options)) (*sqs.ListQueueTagsOutput, error) {
	queueURL := strings.TrimSpace(awsv2.ToString(input.QueueUrl))
	if f.listQueueTagsErr != nil {
		if err, ok := f.listQueueTagsErr[queueURL]; ok {
			return nil, err
		}
	}
	if f.listQueueTagsByURL != nil {
		if output, ok := f.listQueueTagsByURL[queueURL]; ok {
			return output, nil
		}
	}
	return &sqs.ListQueueTagsOutput{}, nil
}

type fakeSDKSQSSNSSNSClient struct {
	listTopicsOutputs       []sns.ListTopicsOutput
	listTopicsErr           error
	listTopicsCall          int
	listTopicsInputs        []sns.ListTopicsInput
	getTopicAttributesByARN map[string]*sns.GetTopicAttributesOutput
	getTopicAttributesErr   map[string]error
	listSubsByTopicByTopic  map[string]*sns.ListSubscriptionsByTopicOutput
	listSubsByTopicErr      map[string]error
	getSubAttributesBySub   map[string]*sns.GetSubscriptionAttributesOutput
	getSubAttributesErr     map[string]error
	listTagsByArn           map[string]*sns.ListTagsForResourceOutput
	listTagsErr             map[string]error
}

func (f *fakeSDKSQSSNSSNSClient) ListTopics(ctx context.Context, input *sns.ListTopicsInput, _ ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	f.listTopicsCall++
	f.listTopicsInputs = append(f.listTopicsInputs, *input)
	if f.listTopicsErr != nil {
		return nil, f.listTopicsErr
	}
	if f.listTopicsCall > len(f.listTopicsOutputs) {
		return &sns.ListTopicsOutput{}, nil
	}
	return &f.listTopicsOutputs[f.listTopicsCall-1], nil
}

func (f *fakeSDKSQSSNSSNSClient) GetTopicAttributes(ctx context.Context, input *sns.GetTopicAttributesInput, _ ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	topicARN := strings.TrimSpace(awsv2.ToString(input.TopicArn))
	if f.getTopicAttributesErr != nil {
		if err, ok := f.getTopicAttributesErr[topicARN]; ok {
			return nil, err
		}
	}
	if f.getTopicAttributesByARN != nil {
		if output, ok := f.getTopicAttributesByARN[topicARN]; ok {
			return output, nil
		}
	}
	return &sns.GetTopicAttributesOutput{}, nil
}

func (f *fakeSDKSQSSNSSNSClient) ListSubscriptionsByTopic(ctx context.Context, input *sns.ListSubscriptionsByTopicInput, _ ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error) {
	topicARN := strings.TrimSpace(awsv2.ToString(input.TopicArn))
	if f.listSubsByTopicErr != nil {
		if err, ok := f.listSubsByTopicErr[topicARN]; ok {
			return nil, err
		}
	}
	if f.listSubsByTopicByTopic != nil {
		if output, ok := f.listSubsByTopicByTopic[topicARN]; ok {
			return output, nil
		}
	}
	return &sns.ListSubscriptionsByTopicOutput{}, nil
}

func (f *fakeSDKSQSSNSSNSClient) GetSubscriptionAttributes(ctx context.Context, input *sns.GetSubscriptionAttributesInput, _ ...func(*sns.Options)) (*sns.GetSubscriptionAttributesOutput, error) {
	subARN := strings.TrimSpace(awsv2.ToString(input.SubscriptionArn))
	if f.getSubAttributesErr != nil {
		if err, ok := f.getSubAttributesErr[subARN]; ok {
			return nil, err
		}
	}
	if f.getSubAttributesBySub != nil {
		if output, ok := f.getSubAttributesBySub[subARN]; ok {
			return output, nil
		}
	}
	return &sns.GetSubscriptionAttributesOutput{}, nil
}

func (f *fakeSDKSQSSNSSNSClient) ListTagsForResource(ctx context.Context, input *sns.ListTagsForResourceInput, _ ...func(*sns.Options)) (*sns.ListTagsForResourceOutput, error) {
	arn := strings.TrimSpace(awsv2.ToString(input.ResourceArn))
	if f.listTagsErr != nil {
		if err, ok := f.listTagsErr[arn]; ok {
			return nil, err
		}
	}
	if f.listTagsByArn != nil {
		if output, ok := f.listTagsByArn[arn]; ok {
			return output, nil
		}
	}
	return &sns.ListTagsForResourceOutput{}, nil
}

func TestSDKSQSSNSReachabilityAPI_NilClients(t *testing.T) {
	api := &SDKSQSSNSReachabilityAPI{}
	if _, err := api.ListSQSSNSReachability(context.Background(), "", 0); err == nil {
		t.Fatal("expected nil client error")
	}
}

func TestSDKSQSSNSReachabilityAPI_ListSQSSNSReachability_FullEnrichment(t *testing.T) {
	sqsQueueURL := "https://sqs.us-east-1.amazonaws.com/123456789012/payments"
	sqsTopicARN := "arn:aws:sns:us-east-1:123456789012:billing-alerts"
	normalSubARN := "arn:aws:sns:us-east-1:123456789012:billing-alerts:sub-normal"

	sqsClient := &fakeSDKSQSSNSSQSClient{
		listQueuesOutputs: []sqs.ListQueuesOutput{{
			QueueUrls: []string{sqsQueueURL},
		}},
		getQueueAttributesByURL: map[string]*sqs.GetQueueAttributesOutput{
			sqsQueueURL: &sqs.GetQueueAttributesOutput{
				Attributes: map[string]string{
					"QueueArn":                  "arn:aws:sqs:us-east-1:123456789012:payments",
					"CreatedTimestamp":          "1690000000",
					"LastModifiedTimestamp":     "1691000000",
					"VisibilityTimeout":         "30",
					"MessageRetentionPeriod":    "172800",
					"FifoQueue":                 "false",
					"ContentBasedDeduplication": "true",
					"SqsManagedSseEnabled":      "true",
					"Policy":                    `{"Version":"2012-10-17","Statement":[{"Sid":"Allow","Effect":"Allow","Principal":"*","Action":"sqs:SendMessage"}]}`,
					"RedrivePolicy":             `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:payments-dlq"}`,
				},
			},
		},
		listQueueTagsByURL: map[string]*sqs.ListQueueTagsOutput{
			sqsQueueURL: &sqs.ListQueueTagsOutput{
				Tags: map[string]string{"environment": "prod"},
			},
		},
	}

	snsClient := &fakeSDKSQSSNSSNSClient{
		listTopicsOutputs: []sns.ListTopicsOutput{{
			Topics: []snstypes.Topic{{TopicArn: awsv2.String(sqsTopicARN)}},
		}},
		getTopicAttributesByARN: map[string]*sns.GetTopicAttributesOutput{
			sqsTopicARN: &sns.GetTopicAttributesOutput{
				Attributes: map[string]string{
					"TopicArn":               sqsTopicARN,
					"Owner":                  "123456789012",
					"Policy":                 `{"Version":"2012-10-17","Statement":[{"Sid":"AllowPublish","Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"SNS:Publish"}]}`,
					"SubscriptionsConfirmed": "1",
					"SubscriptionsPending":   "0",
				},
			},
		},
		listSubsByTopicByTopic: map[string]*sns.ListSubscriptionsByTopicOutput{
			sqsTopicARN: &sns.ListSubscriptionsByTopicOutput{
				Subscriptions: []snstypes.Subscription{{
					SubscriptionArn: awsv2.String(normalSubARN),
					Protocol:        awsv2.String("sqs"),
					Endpoint:        awsv2.String("arn:aws:sqs:us-east-1:123456789012:payments"),
					Owner:           awsv2.String("123456789012"),
				}, {
					SubscriptionArn: awsv2.String("Deleted"),
					Protocol:        awsv2.String("email"),
				}},
			},
		},
		getSubAttributesBySub: map[string]*sns.GetSubscriptionAttributesOutput{
			normalSubARN: &sns.GetSubscriptionAttributesOutput{
				Attributes: map[string]string{
					"RawMessageDelivery":  "true",
					"FilterPolicy":        "{\"type\":[\"critical\"]}",
					"PendingConfirmation": "false",
					"RedrivePolicy":       `{"deadLetterTargetArn":"arn:aws:sns:us-east-1:123456789012:sub-dlq"}`,
				},
			},
		},
		listTagsByArn: map[string]*sns.ListTagsForResourceOutput{
			sqsTopicARN: &sns.ListTagsForResourceOutput{
				Tags: []snstypes.Tag{
					{Key: awsv2.String("environment"), Value: awsv2.String("prod")},
				},
			},
		},
	}

	api := NewSDKSQSSNSReachabilityAPIFromClients(sqsClient, snsClient, "123456789012", "us-east-1")
	page, err := api.ListSQSSNSReachability(context.Background(), "", 5000)
	if err != nil {
		t.Fatalf("list reachability: %v", err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected queue + topic records, got %d", len(page.Records))
	}
	if sqsListInput := sqsClient.listQueuesInputs[0]; sqsListInput.MaxResults == nil || awsv2.ToInt32(sqsListInput.MaxResults) != maxSQSListQueuesPageSize {
		t.Fatalf("expected clamped SQS page size of 1000, got %#v", awsv2.ToInt32(sqsListInput.MaxResults))
	}
	queue := page.Records[0]
	if queue.ResourceType != "sqs_queue" || queue.ResourceName != "payments" || len(queue.IdentityGrants) != 1 {
		t.Fatalf("unexpected queue record: %+v", queue)
	}
	topic := page.Records[1]
	if topic.ResourceType != "sns_topic" || len(topic.Subscriptions) != 2 {
		t.Fatalf("unexpected topic record: %+v", topic)
	}
	if !topic.Subscriptions[1].PendingConfirmation {
		t.Fatalf("expected deleted subscription to be marked pending confirmation: %+v", topic.Subscriptions[1])
	}
	if queue.SubscriptionCount != 0 {
		t.Fatalf("expected queue subscription count 0, got %d", queue.SubscriptionCount)
	}
	if len(page.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %+v", page.Diagnostics)
	}
}

func TestSQSListQueuesPageSize(t *testing.T) {
	if got, want := sqsListQueuesPageSize(0), int32(minSQSListQueuesPageSize); got != want {
		t.Fatalf("min clamp mismatch: got %d want %d", got, want)
	}
	if got, want := sqsListQueuesPageSize(2000), int32(maxSQSListQueuesPageSize); got != want {
		t.Fatalf("max clamp mismatch: got %d want %d", got, want)
	}
	if got := sqsListQueuesPageSize(25); got != 25 {
		t.Fatalf("expected 25 through unchanged, got %d", got)
	}
}

func TestSDKSQSSNSReachabilityAPIConstructors(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	api, err := NewSDKSQSSNSReachabilityAPI("us-east-1", "", "123456789012")
	if err != nil {
		t.Fatalf("construct default SDKSQSSNSReachabilityAPI: %v", err)
	}
	if api == nil {
		t.Fatal("expected default SDK SQS/SNS reachability API")
	}

	api, err = NewSDKSQSSNSReachabilityAPIWithContext(context.Background(), "us-east-1", "", "123456789012")
	if err != nil {
		t.Fatalf("construct contextual SDKSQSSNSReachabilityAPI: %v", err)
	}
	if api == nil {
		t.Fatal("expected contextual SDK SQS/SNS reachability API")
	}

	api = NewSDKSQSSNSReachabilityAPIFromClients(nil, nil, "123456789012", "us-east-1")
	if api == nil {
		t.Fatal("expected clients-backed SDK SQS/SNS reachability API")
	}
}

func TestSDKSQSSNSReachabilityAPIFromAssumeRole(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	api, err := NewSDKSQSSNSReachabilityAPIFromAssumeRole(
		context.Background(),
		"us-east-1",
		"",
		"arn:aws:iam::123456789012:role/IdentrailReadOnly",
		"",
		"",
		"123456789012",
	)
	if err != nil {
		t.Fatalf("construct assumed-role API: %v", err)
	}
	if api == nil {
		t.Fatal("expected assumed-role SQS/SNS API")
	}

	if _, err := NewSDKSQSSNSReachabilityAPIFromAssumeRole(context.Background(), "us-east-1", "", "", "", "", ""); err == nil {
		t.Fatal("expected empty role arn error")
	}
}

func TestSQSNSReachabilityHelpers(t *testing.T) {
	account, err := sqsSNSReachabilityAccountID(context.Background(), awsv2.Config{}, "123456789012")
	if err != nil {
		t.Fatalf("read account id: %v", err)
	}
	if account != "123456789012" {
		t.Fatalf("expected provided account id, got %q", account)
	}

	diagnostic := sqsSNSReachabilityDiagnostic("sample_code", "sample_source", "sample message", true)
	if diagnostic.Collector != sqsSNSReachabilityCollectorName || diagnostic.SourceID != "sample_source" || diagnostic.Code != "sample_code" {
		t.Fatalf("unexpected diagnostic: %+v", diagnostic)
	}
	if !diagnostic.Retryable {
		t.Fatalf("expected retryable diagnostic, got %v", diagnostic)
	}
}
