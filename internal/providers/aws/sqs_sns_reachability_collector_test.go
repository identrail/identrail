package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeSQSSNSReachabilityAPI struct {
	pages []SQSSNSReachabilityPage
	err   error
	calls int
}

func (f *fakeSQSSNSReachabilityAPI) ListSQSSNSReachability(ctx context.Context, nextToken string, pageSize int32) (SQSSNSReachabilityPage, error) {
	f.calls++
	if f.err != nil {
		return SQSSNSReachabilityPage{}, f.err
	}
	if f.calls > len(f.pages) {
		return SQSSNSReachabilityPage{}, nil
	}
	return f.pages[f.calls-1], nil
}

func TestParseSQSSNSPolicyGrants(t *testing.T) {
	raw := `{
	  "Version":"2012-10-17",
	  "Statement":[
	    {"Sid":"CanonicalRole","Effect":"Allow","Principal":{"CanonicalUser":"canonical-user-id"},"Action":"sqs:ReceiveMessage"},
	    {"Sid":"PublicPublish","Effect":"Allow","Principal":"*","Action":"SNS:Publish"},
	    {"Sid":"PartnerConsume","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:role/partner"},"Action":["sqs:ReceiveMessage","sqs:DeleteMessage"],"Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}},
	    {"Sid":"NotPrincipalIgnored","Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:role/nope"},"Action":"sqs:*"}
	  ]}`
	grants, statementCount, err := parseSQSSNSPolicyGrants(raw, sqsServiceName)
	if err != nil {
		t.Fatalf("parse grants: %v", err)
	}
	if statementCount != 4 || len(grants) != 3 {
		t.Fatalf("expected 4 statements and 3 grants, got statements=%d grants=%+v", statementCount, grants)
	}
	foundCanonicalUserType := false
	for _, grant := range grants {
		if grant.PrincipalType == "canonical_user" {
			foundCanonicalUserType = true
			break
		}
	}
	if !foundCanonicalUserType {
		t.Fatalf("expected canonical user principal type, got %+v", grants)
	}
	publicGrantFound := false
	conditionedConsumeGrantFound := false
	for _, grant := range grants {
		if grant.WildcardPrincipal && containsSQSSNSTestString(grant.Capabilities, "publish") {
			publicGrantFound = true
		}
		if grant.HasCondition && containsSQSSNSTestString(grant.Capabilities, "consume") {
			conditionedConsumeGrantFound = true
		}
	}
	if !publicGrantFound {
		t.Fatalf("expected public publish grant, got %+v", grants)
	}
	if !conditionedConsumeGrantFound {
		t.Fatalf("expected conditioned consume grant, got %+v", grants)
	}
}

func TestSQSSNSReachabilitySourceIDUsesResourceNameFallback(t *testing.T) {
	record := SQSSNSReachability{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			Service: sqsServiceName,
			Region:  "us-east-1",
		},
		ResourceName: "orders",
	}
	if got := sqsSNSReachabilitySourceID(record); got != "sqs|orders|us-east-1" {
		t.Fatalf("unexpected source id fallback: %q", got)
	}
}

func TestAnnotateSQSSNSGrantsMarksBareAccountPrincipalAsCrossAccount(t *testing.T) {
	grants := annotateSQSSNSGrants([]SQSSNSIdentityGrant{{
		PrincipalARN:  "999999999999",
		PrincipalType: "aws",
		Effect:        "Allow",
		Actions:       []string{"sqs:SendMessage"},
		Capabilities:  []string{"publish"},
	}}, "123456789012")
	if len(grants) != 1 {
		t.Fatalf("expected one grant, got %d", len(grants))
	}
	if !grants[0].IsCrossAccount {
		t.Fatal("expected bare 12-digit principal to be marked cross-account")
	}
}

func TestSQSSNSReachabilityCollectorNormalizesAndDedupes(t *testing.T) {
	now := time.Date(2026, 6, 11, 9, 0, 0, 0, time.UTC)
	api := &fakeSQSSNSReachabilityAPI{pages: []SQSSNSReachabilityPage{{
		Records: []SQSSNSReachability{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: sqsServiceName},
			ResourceType:           "sqs_queue",
			ResourceARN:            "arn:aws:sqs:us-east-1:123456789012:payments",
			ResourceName:           "payments",
			IdentityGrants: []SQSSNSIdentityGrant{{
				PrincipalARN: "arn:aws:iam::999999999999:role/partner",
				Effect:       "Allow",
				Actions:      []string{"sqs:SendMessage"},
				Capabilities: []string{"publish"},
			}},
		}, {
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: sqsServiceName},
			ResourceType:           "sqs_queue",
			ResourceARN:            "arn:aws:sqs:us-east-1:123456789012:payments",
			ResourceName:           "payments",
		}},
		NextToken: "p2",
	}, {
		Records: []SQSSNSReachability{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: snsServiceName},
			ResourceType:           "sns_topic",
			ResourceARN:            "arn:aws:sns:us-east-1:123456789012:events",
			ResourceName:           "events",
			Subscriptions: []SNSTopicSubscription{{
				SubscriptionARN:     "arn:aws:sns:us-east-1:123456789012:events:sub-a",
				Protocol:            "sqs",
				EndpointResourceARN: "arn:aws:sqs:us-east-1:123456789012:payments",
				EndpointPresent:     true,
			}},
		}},
	}}}
	collector := NewSQSSNSReachabilityCollector(api, WithSQSSNSReachabilityClock(func() time.Time { return now }))
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "connector-a",
		ScanID:      "scan-a",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %+v", diagnostics)
	}
	if len(assets) != 2 {
		t.Fatalf("expected deduped 2 assets, got %d", len(assets))
	}
	var queue SQSSNSReachability
	if err := json.Unmarshal(assets[0].Payload, &queue); err != nil {
		t.Fatalf("decode asset: %v", err)
	}
	if assets[0].Kind != rawKindSQSSNSReachability || queue.AccountID != "123456789012" || queue.ExposureClassification != "cross_account" {
		t.Fatalf("unexpected normalized queue asset: kind=%s record=%+v", assets[0].Kind, queue)
	}
	if queue.IdentityGrants[0].IsCrossAccount != true {
		t.Fatalf("expected cross-account grant annotation, got %+v", queue.IdentityGrants[0])
	}
}

func TestSQSSNSReachabilityCollectorProjectsResourcesAndIdentities(t *testing.T) {
	record := SQSSNSReachability{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: sqsServiceName, AccountID: "123456789012", Region: "us-east-1"},
		ResourceType:           "sqs_queue",
		ResourceARN:            "arn:aws:sqs:us-east-1:123456789012:payments",
		ResourceName:           "payments",
		ExposureClassification: "private_with_grants",
		IdentityGrants: []SQSSNSIdentityGrant{{
			PrincipalARN: "arn:aws:iam::123456789012:role/payments",
			Effect:       "Allow",
		}, {
			PrincipalARN: "*",
			Effect:       "Allow",
		}},
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindSQSSNSReachability,
		SourceID: "sqs|payments",
		Payload:  payload,
	}})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Resources) != 1 || bundle.Resources[0].Type != domain.ResourceTypeSQSQueue {
		t.Fatalf("expected SQS queue resource, got %+v", bundle.Resources)
	}
	if len(bundle.Identities) != 1 || !strings.Contains(bundle.Identities[0].ARN, "role/payments") {
		t.Fatalf("expected only concrete IAM role identity, got %+v", bundle.Identities)
	}
}

func TestSQSSNSReachabilityCollectorPageLimitDiagnostic(t *testing.T) {
	api := &fakeSQSSNSReachabilityAPI{pages: []SQSSNSReachabilityPage{{
		Records:   []SQSSNSReachability{{ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: sqsServiceName}, ResourceType: "sqs_queue", ResourceARN: "arn:aws:sqs:us-east-1:123456789012:a"}},
		NextToken: "p2",
	}}}
	collector := NewSQSSNSReachabilityCollector(api, WithSQSSNSReachabilityMaxPages(1))
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err == nil {
		t.Fatalf("expected page limit error")
	}
	if len(assets) != 1 || len(diagnostics) == 0 || diagnostics[len(diagnostics)-1].Code != "sqs_sns_reachability_page_limit_exceeded" {
		t.Fatalf("expected retained asset and page limit diagnostic, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
}

func TestSQSSNSReachabilityCollectorListError(t *testing.T) {
	collector := NewSQSSNSReachabilityCollector(&fakeSQSSNSReachabilityAPI{err: errors.New("boom")},
		WithSQSSNSReachabilityRetryPolicy(RetryPolicy{MaxRetries: 0, BaseDelay: time.Microsecond, MaxDelay: time.Microsecond}),
		WithSQSSNSReachabilitySleeper(func(ctx context.Context, _ time.Duration) error { return nil }),
	)
	_, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err == nil {
		t.Fatalf("expected list error")
	}
	if len(diagnostics) == 0 || diagnostics[0].Code != "sqs_sns_reachability_page_failed" {
		t.Fatalf("expected page failed diagnostic, got %+v", diagnostics)
	}
}

func TestSQSSNSReachabilityCollectorCollectRequiresClient(t *testing.T) {
	collector := NewSQSSNSReachabilityCollector(nil)
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected collect to require client")
	}
	if _, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{}); err == nil {
		t.Fatal("expected collect with diagnostics to require client")
	}
}

func TestSQSSNSReachabilityCollectorOptions(t *testing.T) {
	collector := NewSQSSNSReachabilityCollector(&fakeSQSSNSReachabilityAPI{},
		WithSQSSNSReachabilityPageSize(-1),
		WithSQSSNSReachabilityPageSize(250),
		WithSQSSNSReachabilityMaxPages(-1),
		WithSQSSNSReachabilityMaxPages(4),
	)
	if collector.pageSize != 250 {
		t.Fatalf("expected page size option to set 250, got %d", collector.pageSize)
	}
	if collector.maxPages != 4 {
		t.Fatalf("expected maxPages option to set 4, got %d", collector.maxPages)
	}
}

func TestSQSSNSReachabilityExposureAndConfidence(t *testing.T) {
	publicExposure := SQSSNSReachability{IdentityGrants: []SQSSNSIdentityGrant{{
		Effect:       "Allow",
		IsPublic:     true,
		HasCondition: false,
	}}}
	if got, _ := classifySQSSNSExposure(publicExposure); got != "public" {
		t.Fatalf("expected public exposure, got %q", got)
	}

	crossAccountExposure := SQSSNSReachability{IdentityGrants: []SQSSNSIdentityGrant{{
		Effect:         "Allow",
		IsCrossAccount: true,
		HasCondition:   false,
	}}}
	if got, _ := classifySQSSNSExposure(crossAccountExposure); got != "cross_account" {
		t.Fatalf("expected cross-account exposure, got %q", got)
	}

	restrictedExposure := SQSSNSReachability{IdentityGrants: []SQSSNSIdentityGrant{{
		Effect:            "Deny",
		WildcardPrincipal: true,
		HasCondition:      false,
	}}}
	if got, _ := classifySQSSNSExposure(restrictedExposure); got != "restricted" {
		t.Fatalf("expected restricted exposure, got %q", got)
	}

	if got, _ := classifySQSSNSExposure(SQSSNSReachability{HasResourcePolicy: true}); got != "private_with_grants" {
		t.Fatalf("expected private_with_grants exposure, got %q", got)
	}

	if got := sqsSNSReachabilityConfidence(SQSSNSReachability{ExposureClassification: "public"}); got != 0.94 {
		t.Fatalf("expected public confidence 0.94, got %f", got)
	}
	if got := sqsSNSReachabilityConfidence(SQSSNSReachability{ExposureClassification: "cross_account"}); got != 0.91 {
		t.Fatalf("expected cross-account confidence 0.91, got %f", got)
	}
	if got := sqsSNSReachabilityConfidence(SQSSNSReachability{ExposureClassification: "restricted"}); got != 0.9 {
		t.Fatalf("expected restricted confidence 0.9, got %f", got)
	}
	if got := sqsSNSReachabilityConfidence(SQSSNSReachability{ExposureClassification: "private_with_grants"}); got != 0.87 {
		t.Fatalf("expected private-with-grants confidence 0.87, got %f", got)
	}
	if got := sqsSNSReachabilityConfidence(SQSSNSReachability{}); got != 0.7 {
		t.Fatalf("expected fallback confidence 0.7, got %f", got)
	}
}

func containsSQSSNSTestString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
