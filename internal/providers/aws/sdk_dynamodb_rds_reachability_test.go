package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type fakeSDKDynamoDBClient struct {
	dispatchListTablesError   error
	dispatchDescribeTableErr  error
	dispatchListTagsErr       error
	dispatchResourcePolicyErr error

	listTablesOutput        *dynamodb.ListTablesOutput
	describeTableOutput     *dynamodb.DescribeTableOutput
	listTagsOutput          *dynamodb.ListTagsOfResourceOutput
	getResourcePolicyOutput *dynamodb.GetResourcePolicyOutput
}

func (f *fakeSDKDynamoDBClient) ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	if f.dispatchListTablesError != nil {
		return nil, f.dispatchListTablesError
	}
	return f.listTablesOutput, nil
}

func (f *fakeSDKDynamoDBClient) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if f.dispatchDescribeTableErr != nil {
		return nil, f.dispatchDescribeTableErr
	}
	return f.describeTableOutput, nil
}

func (f *fakeSDKDynamoDBClient) ListTagsOfResource(context.Context, *dynamodb.ListTagsOfResourceInput, ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error) {
	if f.dispatchListTagsErr != nil {
		return nil, f.dispatchListTagsErr
	}
	return f.listTagsOutput, nil
}

func (f *fakeSDKDynamoDBClient) GetResourcePolicy(context.Context, *dynamodb.GetResourcePolicyInput, ...func(*dynamodb.Options)) (*dynamodb.GetResourcePolicyOutput, error) {
	if f.dispatchResourcePolicyErr != nil {
		return nil, f.dispatchResourcePolicyErr
	}
	return f.getResourcePolicyOutput, nil
}

type fakeSDKRDSClient struct {
	dispatchInstancesErr error
	dispatchClustersErr  error
	dispatchProxiesErr   error
	dispatchTagsErr      error

	instancesOutput *rds.DescribeDBInstancesOutput
	clustersOutput  *rds.DescribeDBClustersOutput
	proxiesOutput   *rds.DescribeDBProxiesOutput
	tagsOutput      *rds.ListTagsForResourceOutput
}

func (f *fakeSDKRDSClient) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.dispatchInstancesErr != nil {
		return nil, f.dispatchInstancesErr
	}
	return f.instancesOutput, nil
}

func (f *fakeSDKRDSClient) DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	if f.dispatchClustersErr != nil {
		return nil, f.dispatchClustersErr
	}
	return f.clustersOutput, nil
}

func (f *fakeSDKRDSClient) DescribeDBProxies(context.Context, *rds.DescribeDBProxiesInput, ...func(*rds.Options)) (*rds.DescribeDBProxiesOutput, error) {
	if f.dispatchProxiesErr != nil {
		return nil, f.dispatchProxiesErr
	}
	return f.proxiesOutput, nil
}

func (f *fakeSDKRDSClient) ListTagsForResource(context.Context, *rds.ListTagsForResourceInput, ...func(*rds.Options)) (*rds.ListTagsForResourceOutput, error) {
	if f.dispatchTagsErr != nil {
		return nil, f.dispatchTagsErr
	}
	return f.tagsOutput, nil
}

func TestSDKDynamoDBRDSReachabilityAPIListEnrichesAllResourceTypes(t *testing.T) {
	created := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	ddbClient := &fakeSDKDynamoDBClient{
		listTablesOutput: &dynamodb.ListTablesOutput{TableNames: []string{"payments-ledger"}},
		describeTableOutput: &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{
			TableArn:                  awsv2.String("arn:aws:dynamodb:us-east-1:123456789012:table/payments-ledger"),
			TableName:                 awsv2.String("payments-ledger"),
			TableStatus:               ddbtypes.TableStatusActive,
			CreationDateTime:          &created,
			DeletionProtectionEnabled: awsv2.Bool(true),
			LatestStreamArn:           awsv2.String("arn:aws:dynamodb:us-east-1:123456789012:table/payments-ledger/stream/2026"),
			BillingModeSummary:        &ddbtypes.BillingModeSummary{BillingMode: ddbtypes.BillingModePayPerRequest},
			StreamSpecification:       &ddbtypes.StreamSpecification{StreamEnabled: awsv2.Bool(true)},
			SSEDescription:            &ddbtypes.SSEDescription{Status: ddbtypes.SSEStatusEnabled, KMSMasterKeyArn: awsv2.String("arn:aws:kms:us-east-1:123456789012:key/ddb")},
		}},
		listTagsOutput:          &dynamodb.ListTagsOfResourceOutput{Tags: []ddbtypes.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("payments")}}},
		getResourcePolicyOutput: &dynamodb.GetResourcePolicyOutput{Policy: awsv2.String(`{"Version":"2012-10-17","Statement":{"Sid":"PartnerRead","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:role/reader"},"Action":["dynamodb:GetItem","dynamodb:Query"],"Resource":"*"}}`)},
	}
	rdsClient := &fakeSDKRDSClient{
		instancesOutput: &rds.DescribeDBInstancesOutput{DBInstances: []rdstypes.DBInstance{{
			DBInstanceArn:                    awsv2.String("arn:aws:rds:us-east-1:123456789012:db:customer-export"),
			DBInstanceIdentifier:             awsv2.String("customer-export"),
			DBInstanceStatus:                 awsv2.String("available"),
			Engine:                           awsv2.String("postgres"),
			EngineVersion:                    awsv2.String("15.5"),
			Endpoint:                         &rdstypes.Endpoint{Address: awsv2.String("customer-export.rds.amazonaws.com")},
			KmsKeyId:                         awsv2.String("arn:aws:kms:us-east-1:123456789012:key/rds"),
			StorageEncrypted:                 awsv2.Bool(true),
			IAMDatabaseAuthenticationEnabled: awsv2.Bool(true),
			PubliclyAccessible:               awsv2.Bool(true),
			DeletionProtection:               awsv2.Bool(true),
			PerformanceInsightsEnabled:       awsv2.Bool(true),
			AssociatedRoles:                  []rdstypes.DBInstanceRole{{RoleArn: awsv2.String("arn:aws:iam::123456789012:role/rds-s3-import")}},
		}}},
		clustersOutput: &rds.DescribeDBClustersOutput{DBClusters: []rdstypes.DBCluster{{
			DBClusterArn:                     awsv2.String("arn:aws:rds:us-east-1:123456789012:cluster:payments-main"),
			DBClusterIdentifier:              awsv2.String("payments-main"),
			Status:                           awsv2.String("available"),
			Engine:                           awsv2.String("aurora-postgresql"),
			EngineVersion:                    awsv2.String("15.4"),
			Endpoint:                         awsv2.String("payments-main.cluster.rds.amazonaws.com"),
			KmsKeyId:                         awsv2.String("arn:aws:kms:us-east-1:123456789012:key/cluster"),
			StorageEncrypted:                 awsv2.Bool(true),
			IAMDatabaseAuthenticationEnabled: awsv2.Bool(true),
			DeletionProtection:               awsv2.Bool(true),
			AssociatedRoles:                  []rdstypes.DBClusterRole{{RoleArn: awsv2.String("arn:aws:iam::123456789012:role/rds-export")}},
		}}},
		proxiesOutput: &rds.DescribeDBProxiesOutput{DBProxies: []rdstypes.DBProxy{{
			DBProxyArn:        awsv2.String("arn:aws:rds:us-east-1:123456789012:db-proxy:prx-1"),
			DBProxyName:       awsv2.String("payments-proxy"),
			Status:            rdstypes.DBProxyStatusAvailable,
			EngineFamily:      awsv2.String("POSTGRESQL"),
			Endpoint:          awsv2.String("payments-proxy.proxy.rds.amazonaws.com"),
			DefaultAuthScheme: awsv2.String("IAM_AUTH"),
			RoleArn:           awsv2.String("arn:aws:iam::123456789012:role/rds-proxy-secrets"),
		}}},
		tagsOutput: &rds.ListTagsForResourceOutput{TagList: []rdstypes.Tag{{Key: awsv2.String("env"), Value: awsv2.String("prod")}}},
	}
	api := NewSDKDynamoDBRDSReachabilityAPIFromClients(ddbClient, rdsClient, "123456789012", "us-east-1")
	page, err := api.ListDynamoDBRDSReachability(context.Background(), "", 5)
	if err != nil {
		t.Fatalf("ListDynamoDBRDSReachability: %v", err)
	}
	if len(page.Records) != 5 {
		t.Fatalf("expected table, stream, instance, cluster, proxy records, got %+v", page.Records)
	}
	var table, stream, instance, proxy bool
	for _, record := range page.Records {
		switch record.ResourceType {
		case "dynamodb_table":
			table = record.HasResourcePolicy && len(record.IdentityGrants) == 1 && record.StorageEncrypted && record.StreamEnabled && record.Tags["owner"] == "payments"
		case "dynamodb_stream":
			stream = record.HasResourcePolicy && record.ResourcePolicySource == "stream_resource_policy" && len(record.IdentityGrants) == 1
		case "rds_instance":
			instance = record.PubliclyAccessible && record.IAMDatabaseAuthenticationEnabled && len(record.AssociatedRoleARNs) == 1 && record.Endpoint != ""
		case "rds_proxy":
			proxy = record.IAMDatabaseAuthenticationEnabled && len(record.AssociatedRoleARNs) == 1
		}
	}
	if !table || !stream || !instance || !proxy {
		t.Fatalf("expected enriched table/stream/instance/proxy records, got %+v", page.Records)
	}
}

func TestSDKDynamoDBRDSReachabilityHelpers(t *testing.T) {
	if phase, token := dynamoDBRDSDecodePageToken("rds-clusters:abc"); phase != "rds-clusters" || token != "abc" {
		t.Fatalf("unexpected decoded token: %s %s", phase, token)
	}
	if got := rdsPageSize(5); got != 20 {
		t.Fatalf("expected rds page min 20, got %d", got)
	}
	if got := rdsPageSize(500); got != 100 {
		t.Fatalf("expected rds page max 100, got %d", got)
	}
	caps := dynamoDBRDSCapabilitiesForActions("dynamodb", []string{"dynamodb:GetItem", "dynamodb:UpdateItem"}, false)
	if len(caps) != 2 {
		t.Fatalf("expected read/write capabilities, got %+v", caps)
	}
	if _, err := NewSDKDynamoDBRDSReachabilityAPIFromAssumeRole(context.Background(), "us-east-1", "", "", "", "", "123456789012"); err == nil {
		t.Fatalf("expected empty role arn error")
	}
}

func TestSDKDynamoDBRDSReachabilityRetainsDynamoDBOnRDSFailure(t *testing.T) {
	dbClient := &fakeSDKDynamoDBClient{
		listTablesOutput: &dynamodb.ListTablesOutput{TableNames: []string{"payments-ledger"}},
		describeTableOutput: &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{
			TableArn:            awsv2.String("arn:aws:dynamodb:us-east-1:123456789012:table/payments-ledger"),
			TableName:           awsv2.String("payments-ledger"),
			TableStatus:         ddbtypes.TableStatusActive,
			LatestStreamArn:     awsv2.String("arn:aws:dynamodb:us-east-1:123456789012:table/payments-ledger/stream/2026-06-11T00:00:00.000"),
			StreamSpecification: &ddbtypes.StreamSpecification{StreamEnabled: awsv2.Bool(true)},
			CreationDateTime:    awsv2.Time(time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)),
		}},
		listTagsOutput: &dynamodb.ListTagsOfResourceOutput{Tags: []ddbtypes.Tag{}},
	}
	rdsClient := &fakeSDKRDSClient{
		dispatchInstancesErr: errors.New("rds instances temporarily unavailable"),
	}

	api := NewSDKDynamoDBRDSReachabilityAPIFromClients(dbClient, rdsClient, "123456789012", "us-east-1")
	page, err := api.ListDynamoDBRDSReachability(context.Background(), "", 5)
	if err == nil {
		t.Fatalf("expected error when rds instances fail")
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected dynamodb table and stream to be retained, got %d records", len(page.Records))
	}
	if len(page.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics before rds failure in partial path, got %d", len(page.Diagnostics))
	}
}

func TestSDKDynamoDBRDSReachabilitySkipsDisabledDynamoDBStreamRecords(t *testing.T) {
	dbClient := &fakeSDKDynamoDBClient{
		dispatchListTablesError: nil,
		listTablesOutput:        &dynamodb.ListTablesOutput{TableNames: []string{"payments-ledger"}},
		describeTableOutput: &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{
			TableArn:            awsv2.String("arn:aws:dynamodb:us-east-1:123456789012:table/payments-ledger"),
			TableName:           awsv2.String("payments-ledger"),
			TableStatus:         ddbtypes.TableStatusActive,
			LatestStreamArn:     awsv2.String("arn:aws:dynamodb:us-east-1:123456789012:table/payments-ledger/stream/2026"),
			StreamSpecification: &ddbtypes.StreamSpecification{StreamEnabled: awsv2.Bool(false)},
			BillingModeSummary:  &ddbtypes.BillingModeSummary{BillingMode: ddbtypes.BillingModePayPerRequest},
			CreationDateTime:    awsv2.Time(time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)),
		}},
		listTagsOutput: &dynamodb.ListTagsOfResourceOutput{Tags: []ddbtypes.Tag{{Key: awsv2.String("environment"), Value: awsv2.String("staging")}}},
	}
	rdsClient := &fakeSDKRDSClient{}

	api := NewSDKDynamoDBRDSReachabilityAPIFromClients(dbClient, rdsClient, "123456789012", "us-east-1")
	page, err := api.ListDynamoDBRDSReachability(context.Background(), "", 5)
	if err != nil {
		t.Fatalf("ListDynamoDBRDSReachability: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected only table record when stream is disabled, got %d records", len(page.Records))
	}
	if page.Records[0].ResourceType != "dynamodb_table" {
		t.Fatalf("expected table record, got %q", page.Records[0].ResourceType)
	}
}

func TestSDKDynamoDBRDSReachabilityContinuesToRDSOnDynamoDBFailure(t *testing.T) {
	dbClient := &fakeSDKDynamoDBClient{
		dispatchListTablesError: errors.New("list tables throttled"),
	}
	rdsClient := &fakeSDKRDSClient{
		instancesOutput: &rds.DescribeDBInstancesOutput{DBInstances: []rdstypes.DBInstance{{
			DBInstanceArn:                    awsv2.String("arn:aws:rds:us-east-1:123456789012:db:customer-export"),
			DBInstanceIdentifier:             awsv2.String("customer-export"),
			DBInstanceStatus:                 awsv2.String("available"),
			Engine:                           awsv2.String("postgres"),
			EngineVersion:                    awsv2.String("15.5"),
			Endpoint:                         &rdstypes.Endpoint{Address: awsv2.String("customer-export.rds.amazonaws.com")},
			KmsKeyId:                         awsv2.String("arn:aws:kms:us-east-1:123456789012:key/rds"),
			StorageEncrypted:                 awsv2.Bool(true),
			IAMDatabaseAuthenticationEnabled: awsv2.Bool(false),
			PubliclyAccessible:               awsv2.Bool(false),
			DeletionProtection:               awsv2.Bool(false),
			PerformanceInsightsEnabled:       awsv2.Bool(false),
		}}},
		tagsOutput: &rds.ListTagsForResourceOutput{},
	}

	api := NewSDKDynamoDBRDSReachabilityAPIFromClients(dbClient, rdsClient, "123456789012", "us-east-1")
	page, err := api.ListDynamoDBRDSReachability(context.Background(), "", 5)
	if err != nil {
		t.Fatalf("ListDynamoDBRDSReachability: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected one rds record when dynamodb listing fails, got %d", len(page.Records))
	}
	if page.Records[0].ResourceType != "rds_instance" {
		t.Fatalf("expected rds instance record, got %q", page.Records[0].ResourceType)
	}
	if len(page.Diagnostics) != 1 {
		t.Fatalf("expected one diagnostic from dynamodb list failure, got %+v", page.Diagnostics)
	}
	if page.Diagnostics[0].Code != "dynamodb_table_list_failed" {
		t.Fatalf("expected dynamodb_table_list_failed diagnostic, got %+v", page.Diagnostics[0].Code)
	}
}
