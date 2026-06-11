package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeDynamoDBRDSReachabilityAPI struct {
	pages []DynamoDBRDSReachabilityPage
	err   error
	calls int
}

func (f *fakeDynamoDBRDSReachabilityAPI) ListDynamoDBRDSReachability(context.Context, string, int32) (DynamoDBRDSReachabilityPage, error) {
	f.calls++
	if f.err != nil {
		return DynamoDBRDSReachabilityPage{}, f.err
	}
	if len(f.pages) == 0 {
		return DynamoDBRDSReachabilityPage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestDynamoDBRDSReachabilityCollectorEmitsAssetsAndDiagnostics(t *testing.T) {
	api := &fakeDynamoDBRDSReachabilityAPI{pages: []DynamoDBRDSReachabilityPage{{
		Records: []DynamoDBRDSReachability{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: dynamoDBServiceName, AccountID: "123456789012", Region: "us-east-1"},
			ResourceARN:            "arn:aws:dynamodb:us-east-1:123456789012:table/payments",
			ResourceName:           "payments",
			ResourceType:           "dynamodb_table",
			IdentityGrants: []DynamoDBRDSIdentityGrant{{
				PrincipalARN: "arn:aws:iam::999999999999:role/reader",
				Effect:       "Allow",
				Actions:      []string{"dynamodb:GetItem"},
			}},
		}},
		Diagnostics: []providers.SourceError{{Collector: "dynamodb", Code: "tags_failed", Message: "tags failed", Retryable: true}},
	}}}
	collector := NewDynamoDBRDSReachabilityCollector(api)
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if len(assets) != 1 || assets[0].Kind != rawKindDynamoDBRDSReachability {
		t.Fatalf("expected one raw asset, got %+v", assets)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "tags_failed" {
		t.Fatalf("expected retained diagnostic, got %+v", diagnostics)
	}
}

func TestDynamoDBRDSReachabilityCollectorRequiresClient(t *testing.T) {
	if _, _, err := NewDynamoDBRDSReachabilityCollector(nil).CollectWithDiagnostics(context.Background(), AWSCollectorScope{}); err == nil {
		t.Fatalf("expected missing client error")
	}
}

func TestDynamoDBRDSReachabilityCollectorRetainsPartialAssetsOnFailure(t *testing.T) {
	api := &fakeDynamoDBRDSReachabilityAPI{pages: []DynamoDBRDSReachabilityPage{{
		Records:   []DynamoDBRDSReachability{{ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: rdsServiceName}, ResourceARN: "arn:aws:rds:us-east-1:123456789012:db:payments", ResourceType: "rds_instance"}},
		NextToken: "next",
	}}, err: nil}
	collector := NewDynamoDBRDSReachabilityCollector(api, WithDynamoDBRDSReachabilityMaxPages(1))
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err == nil || len(assets) != 1 {
		t.Fatalf("expected partial asset plus error, assets=%d err=%v", len(assets), err)
	}
	if len(diagnostics) == 0 || !strings.Contains(diagnostics[len(diagnostics)-1].Code, "page_limit") {
		t.Fatalf("expected page limit diagnostic, got %+v", diagnostics)
	}
}

func TestDynamoDBRDSReachabilityCollectorReturnsErrorWithoutAssets(t *testing.T) {
	api := &fakeDynamoDBRDSReachabilityAPI{err: errors.New("throttled")}
	_, diagnostics, err := NewDynamoDBRDSReachabilityCollector(api).CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err == nil || len(diagnostics) == 0 || diagnostics[0].Code != "dynamodb_rds_reachability_page_failed" {
		t.Fatalf("expected page failure diagnostic, diagnostics=%+v err=%v", diagnostics, err)
	}
}
