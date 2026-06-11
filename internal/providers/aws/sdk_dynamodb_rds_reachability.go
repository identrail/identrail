package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

const (
	dynamoDBRDSPageTokenDynamoDB = "dynamodb:"
	dynamoDBRDSPageTokenRDSI     = "rds-instances:"
	dynamoDBRDSPageTokenRDSC     = "rds-clusters:"
	dynamoDBRDSPageTokenRDSP     = "rds-proxies:"
)

type DynamoDBSDKClient interface {
	ListTables(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	ListTagsOfResource(ctx context.Context, params *dynamodb.ListTagsOfResourceInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error)
	GetResourcePolicy(ctx context.Context, params *dynamodb.GetResourcePolicyInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetResourcePolicyOutput, error)
}

type RDSSDKClient interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBClusters(ctx context.Context, params *rds.DescribeDBClustersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBProxies(ctx context.Context, params *rds.DescribeDBProxiesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBProxiesOutput, error)
	ListTagsForResource(ctx context.Context, params *rds.ListTagsForResourceInput, optFns ...func(*rds.Options)) (*rds.ListTagsForResourceOutput, error)
}

type SDKDynamoDBRDSReachabilityAPI struct {
	dynamoDBClient DynamoDBSDKClient
	rdsClient      RDSSDKClient
	accountID      string
	region         string
}

var _ DynamoDBRDSReachabilityAPI = (*SDKDynamoDBRDSReachabilityAPI)(nil)

func NewSDKDynamoDBRDSReachabilityAPI(region string, profile string, accountID string) (DynamoDBRDSReachabilityAPI, error) {
	return NewSDKDynamoDBRDSReachabilityAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKDynamoDBRDSReachabilityAPIWithContext(ctx context.Context, region string, profile string, accountID string) (DynamoDBRDSReachabilityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolved, err := dynamoDBRDSReachabilityAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKDynamoDBRDSReachabilityAPIFromClients(dynamodb.NewFromConfig(cfg), rds.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

func NewSDKDynamoDBRDSReachabilityAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (DynamoDBRDSReachabilityAPI, error) {
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
	resolved, err := dynamoDBRDSReachabilityAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKDynamoDBRDSReachabilityAPIFromClients(dynamodb.NewFromConfig(cfg), rds.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

func NewSDKDynamoDBRDSReachabilityAPIFromClients(dynamoDBClient DynamoDBSDKClient, rdsClient RDSSDKClient, accountID string, region string) DynamoDBRDSReachabilityAPI {
	return &SDKDynamoDBRDSReachabilityAPI{dynamoDBClient: dynamoDBClient, rdsClient: rdsClient, accountID: strings.TrimSpace(accountID), region: strings.TrimSpace(region)}
}

func (a *SDKDynamoDBRDSReachabilityAPI) ListDynamoDBRDSReachability(ctx context.Context, nextToken string, pageSize int32) (DynamoDBRDSReachabilityPage, error) {
	if a.dynamoDBClient == nil && a.rdsClient == nil {
		return DynamoDBRDSReachabilityPage{}, errors.New("dynamodb/rds SDK clients are required")
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	phase, token := dynamoDBRDSDecodePageToken(nextToken)
	records := []DynamoDBRDSReachability{}
	diagnostics := []providers.SourceError{}
	if phase == "" || phase == dynamoDBServiceName {
		if a.dynamoDBClient != nil {
			ddbRecords, ddbNext, ddbDiagnostics, err := a.listDynamoDBTablesPage(ctx, token, pageSize)
			diagnostics = append(diagnostics, ddbDiagnostics...)
			if err != nil {
				diagnostics = append(diagnostics, dynamoDBRDSReachabilityDiagnostic("dynamodb_table_list_failed", firstNonEmptyAWSValue(token, dynamoDBServiceName), fmt.Sprintf("ListTables failed: %v", err), isRetryable(err)))
			} else {
				records = append(records, ddbRecords...)
				if ddbNext != "" {
					return DynamoDBRDSReachabilityPage{Records: records, NextToken: dynamoDBRDSPageTokenDynamoDB + ddbNext, Diagnostics: diagnostics}, nil
				}
			}
		}
		token = ""
	}
	if a.rdsClient == nil {
		sortDynamoDBRDSRecords(records)
		return DynamoDBRDSReachabilityPage{Records: records, Diagnostics: diagnostics}, nil
	}
	if phase == "" || phase == dynamoDBServiceName || phase == "rds-instances" {
		instanceRecords, instanceNext, instanceDiagnostics, err := a.listRDSInstancesPage(ctx, token, pageSize)
		if err != nil {
			return DynamoDBRDSReachabilityPage{Records: records, Diagnostics: append(diagnostics, instanceDiagnostics...)}, err
		}
		records = append(records, instanceRecords...)
		diagnostics = append(diagnostics, instanceDiagnostics...)
		if instanceNext != "" {
			return DynamoDBRDSReachabilityPage{Records: records, NextToken: dynamoDBRDSPageTokenRDSI + instanceNext, Diagnostics: diagnostics}, nil
		}
		token = ""
	}
	if phase == "" || phase == dynamoDBServiceName || phase == "rds-instances" || phase == "rds-clusters" {
		clusterRecords, clusterNext, clusterDiagnostics, err := a.listRDSClustersPage(ctx, token, pageSize)
		if err != nil {
			return DynamoDBRDSReachabilityPage{Records: records, Diagnostics: append(diagnostics, clusterDiagnostics...)}, err
		}
		records = append(records, clusterRecords...)
		diagnostics = append(diagnostics, clusterDiagnostics...)
		if clusterNext != "" {
			return DynamoDBRDSReachabilityPage{Records: records, NextToken: dynamoDBRDSPageTokenRDSC + clusterNext, Diagnostics: diagnostics}, nil
		}
		token = ""
	}
	if phase == "" || phase == dynamoDBServiceName || phase == "rds-instances" || phase == "rds-clusters" || phase == "rds-proxies" {
		proxyRecords, proxyNext, proxyDiagnostics, err := a.listRDSProxiesPage(ctx, token, pageSize)
		if err != nil {
			return DynamoDBRDSReachabilityPage{Records: records, Diagnostics: append(diagnostics, proxyDiagnostics...)}, err
		}
		records = append(records, proxyRecords...)
		diagnostics = append(diagnostics, proxyDiagnostics...)
		if proxyNext != "" {
			return DynamoDBRDSReachabilityPage{Records: records, NextToken: dynamoDBRDSPageTokenRDSP + proxyNext, Diagnostics: diagnostics}, nil
		}
	}
	sortDynamoDBRDSRecords(records)
	return DynamoDBRDSReachabilityPage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKDynamoDBRDSReachabilityAPI) listDynamoDBTablesPage(ctx context.Context, nextToken string, pageSize int32) ([]DynamoDBRDSReachability, string, []providers.SourceError, error) {
	output, err := a.dynamoDBClient.ListTables(ctx, &dynamodb.ListTablesInput{
		ExclusiveStartTableName: stringPtrOrNil(nextToken),
		Limit:                   awsv2.Int32(dynamoDBTablePageSize(pageSize)),
	})
	if err != nil {
		return nil, "", nil, err
	}
	if output == nil {
		return nil, "", nil, nil
	}
	records := []DynamoDBRDSReachability{}
	diagnostics := []providers.SourceError{}
	for _, tableName := range output.TableNames {
		name := strings.TrimSpace(tableName)
		if name == "" {
			continue
		}
		describe, err := a.dynamoDBClient.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: awsv2.String(name)})
		if err != nil {
			diagnostics = append(diagnostics, dynamoDBRDSReachabilityDiagnostic("dynamodb_table_describe_failed", name, fmt.Sprintf("DescribeTable %q failed: %v", name, err), true))
			continue
		}
		if describe == nil || describe.Table == nil {
			continue
		}
		record := a.recordFromDynamoDBTable(*describe.Table)
		a.enrichDynamoDBResourcePolicy(ctx, &record, &diagnostics, "table_resource_policy")
		a.enrichDynamoDBTags(ctx, &record, &diagnostics)
		records = append(records, record)
		if record.StreamEnabled && strings.TrimSpace(record.StreamARN) != "" {
			streamRecord := DynamoDBRDSReachability{
				ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: dynamoDBServiceName, AccountID: record.AccountID, Region: record.Region, Source: "dynamodb_metadata", EvidenceRef: record.StreamARN},
				ResourceARN:            record.StreamARN,
				ResourceName:           record.ResourceName + "-stream",
				ResourceType:           "dynamodb_stream",
				ResourceStatus:         "ENABLED",
				StreamEnabled:          true,
				Tags:                   copyTags(record.Tags),
			}
			a.enrichDynamoDBResourcePolicy(ctx, &streamRecord, &diagnostics, "stream_resource_policy")
			records = append(records, streamRecord)
		}
	}
	return records, strings.TrimSpace(awsv2.ToString(output.LastEvaluatedTableName)), diagnostics, nil
}

func (a *SDKDynamoDBRDSReachabilityAPI) recordFromDynamoDBTable(table ddbtypes.TableDescription) DynamoDBRDSReachability {
	arn := strings.TrimSpace(awsv2.ToString(table.TableArn))
	record := DynamoDBRDSReachability{
		ServiceCollectorRecord:    awscontract.ServiceCollectorRecord{Service: dynamoDBServiceName, AccountID: firstNonEmptyAWSValue(a.accountID, accountIDFromARN(arn)), Region: firstNonEmptyAWSValue(a.region, regionFromARN(arn)), Source: "dynamodb_metadata", EvidenceRef: arn},
		ResourceARN:               arn,
		ResourceName:              awsv2.ToString(table.TableName),
		ResourceType:              "dynamodb_table",
		ResourceStatus:            string(table.TableStatus),
		DeletionProtectionEnabled: awsv2.ToBool(table.DeletionProtectionEnabled),
		StreamARN:                 awsv2.ToString(table.LatestStreamArn),
		StreamEnabled:             table.StreamSpecification != nil && awsv2.ToBool(table.StreamSpecification.StreamEnabled),
	}
	if table.BillingModeSummary != nil {
		record.BillingMode = string(table.BillingModeSummary.BillingMode)
	}
	if table.SSEDescription != nil {
		record.StorageEncrypted = strings.EqualFold(strings.TrimSpace(string(table.SSEDescription.Status)), "ENABLED")
		record.KMSKeyID = awsv2.ToString(table.SSEDescription.KMSMasterKeyArn)
	}
	return record
}

func (a *SDKDynamoDBRDSReachabilityAPI) enrichDynamoDBResourcePolicy(ctx context.Context, record *DynamoDBRDSReachability, diagnostics *[]providers.SourceError, policySource string) {
	if strings.TrimSpace(record.ResourceARN) == "" {
		return
	}
	output, err := a.dynamoDBClient.GetResourcePolicy(ctx, &dynamodb.GetResourcePolicyInput{ResourceArn: awsv2.String(record.ResourceARN)})
	if err != nil {
		var policyNotFound *ddbtypes.PolicyNotFoundException
		if errors.As(err, &policyNotFound) {
			return
		}
		*diagnostics = append(*diagnostics, dynamoDBRDSReachabilityDiagnostic("dynamodb_resource_policy_failed", record.ResourceARN, fmt.Sprintf("GetResourcePolicy %q failed: %v", record.ResourceARN, err), true))
		return
	}
	if output == nil || strings.TrimSpace(awsv2.ToString(output.Policy)) == "" {
		return
	}
	grants, count, err := parseDynamoDBRDSPolicyGrants(awsv2.ToString(output.Policy), dynamoDBServiceName)
	if err != nil {
		*diagnostics = append(*diagnostics, dynamoDBRDSReachabilityDiagnostic("dynamodb_resource_policy_parse_failed", record.ResourceARN, fmt.Sprintf("parse DynamoDB resource policy %q: %v", record.ResourceARN, err), false))
		return
	}
	record.HasResourcePolicy = true
	record.ResourcePolicySource = policySource
	record.ResourcePolicyStatementCount = count
	record.IdentityGrants = grants
}

func (a *SDKDynamoDBRDSReachabilityAPI) enrichDynamoDBTags(ctx context.Context, record *DynamoDBRDSReachability, diagnostics *[]providers.SourceError) {
	if strings.TrimSpace(record.ResourceARN) == "" {
		return
	}
	output, err := a.dynamoDBClient.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{ResourceArn: awsv2.String(record.ResourceARN)})
	if err != nil {
		*diagnostics = append(*diagnostics, dynamoDBRDSReachabilityDiagnostic("dynamodb_table_tags_failed", record.ResourceARN, fmt.Sprintf("ListTagsOfResource %q failed: %v", record.ResourceARN, err), true))
		return
	}
	tags := map[string]string{}
	for _, tag := range output.Tags {
		if key := strings.TrimSpace(awsv2.ToString(tag.Key)); key != "" {
			tags[key] = strings.TrimSpace(awsv2.ToString(tag.Value))
		}
	}
	if len(tags) > 0 {
		record.Tags = tags
	}
}

func (a *SDKDynamoDBRDSReachabilityAPI) listRDSInstancesPage(ctx context.Context, marker string, pageSize int32) ([]DynamoDBRDSReachability, string, []providers.SourceError, error) {
	output, err := a.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: stringPtrOrNil(marker), MaxRecords: awsv2.Int32(rdsPageSize(pageSize))})
	if err != nil {
		return nil, "", nil, err
	}
	records := []DynamoDBRDSReachability{}
	diagnostics := []providers.SourceError{}
	if output == nil {
		return records, "", diagnostics, nil
	}
	for _, instance := range output.DBInstances {
		record := a.recordFromRDSInstance(instance)
		a.enrichRDSTags(ctx, record.ResourceARN, &record, &diagnostics)
		records = append(records, record)
	}
	return records, strings.TrimSpace(awsv2.ToString(output.Marker)), diagnostics, nil
}

func (a *SDKDynamoDBRDSReachabilityAPI) recordFromRDSInstance(instance rdstypes.DBInstance) DynamoDBRDSReachability {
	arn := strings.TrimSpace(awsv2.ToString(instance.DBInstanceArn))
	record := DynamoDBRDSReachability{
		ServiceCollectorRecord:           awscontract.ServiceCollectorRecord{Service: rdsServiceName, AccountID: firstNonEmptyAWSValue(a.accountID, accountIDFromARN(arn)), Region: firstNonEmptyAWSValue(a.region, regionFromARN(arn)), Source: "rds_metadata", EvidenceRef: arn},
		ResourceARN:                      arn,
		ResourceName:                     awsv2.ToString(instance.DBInstanceIdentifier),
		ResourceType:                     "rds_instance",
		Engine:                           awsv2.ToString(instance.Engine),
		EngineVersion:                    awsv2.ToString(instance.EngineVersion),
		ResourceStatus:                   awsv2.ToString(instance.DBInstanceStatus),
		KMSKeyID:                         awsv2.ToString(instance.KmsKeyId),
		StorageEncrypted:                 awsv2.ToBool(instance.StorageEncrypted),
		IAMDatabaseAuthenticationEnabled: awsv2.ToBool(instance.IAMDatabaseAuthenticationEnabled),
		PubliclyAccessible:               awsv2.ToBool(instance.PubliclyAccessible),
		DeletionProtectionEnabled:        awsv2.ToBool(instance.DeletionProtection),
		PerformanceInsightsEnabled:       awsv2.ToBool(instance.PerformanceInsightsEnabled),
	}
	if instance.Endpoint != nil {
		record.Endpoint = awsv2.ToString(instance.Endpoint.Address)
	}
	for _, role := range instance.AssociatedRoles {
		record.AssociatedRoleARNs = append(record.AssociatedRoleARNs, awsv2.ToString(role.RoleArn))
	}
	return record
}

func (a *SDKDynamoDBRDSReachabilityAPI) listRDSClustersPage(ctx context.Context, marker string, pageSize int32) ([]DynamoDBRDSReachability, string, []providers.SourceError, error) {
	output, err := a.rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{Marker: stringPtrOrNil(marker), MaxRecords: awsv2.Int32(rdsPageSize(pageSize))})
	if err != nil {
		return nil, "", nil, err
	}
	records := []DynamoDBRDSReachability{}
	diagnostics := []providers.SourceError{}
	if output == nil {
		return records, "", diagnostics, nil
	}
	for _, cluster := range output.DBClusters {
		record := a.recordFromRDSCluster(cluster)
		a.enrichRDSTags(ctx, record.ResourceARN, &record, &diagnostics)
		records = append(records, record)
	}
	return records, strings.TrimSpace(awsv2.ToString(output.Marker)), diagnostics, nil
}

func (a *SDKDynamoDBRDSReachabilityAPI) recordFromRDSCluster(cluster rdstypes.DBCluster) DynamoDBRDSReachability {
	arn := strings.TrimSpace(awsv2.ToString(cluster.DBClusterArn))
	record := DynamoDBRDSReachability{
		ServiceCollectorRecord:           awscontract.ServiceCollectorRecord{Service: rdsServiceName, AccountID: firstNonEmptyAWSValue(a.accountID, accountIDFromARN(arn)), Region: firstNonEmptyAWSValue(a.region, regionFromARN(arn)), Source: "rds_metadata", EvidenceRef: arn},
		ResourceARN:                      arn,
		ResourceName:                     awsv2.ToString(cluster.DBClusterIdentifier),
		ResourceType:                     "rds_cluster",
		Engine:                           awsv2.ToString(cluster.Engine),
		EngineVersion:                    awsv2.ToString(cluster.EngineVersion),
		ResourceStatus:                   awsv2.ToString(cluster.Status),
		Endpoint:                         awsv2.ToString(cluster.Endpoint),
		KMSKeyID:                         awsv2.ToString(cluster.KmsKeyId),
		StorageEncrypted:                 awsv2.ToBool(cluster.StorageEncrypted),
		IAMDatabaseAuthenticationEnabled: awsv2.ToBool(cluster.IAMDatabaseAuthenticationEnabled),
		PubliclyAccessible:               awsv2.ToBool(cluster.PubliclyAccessible),
		DeletionProtectionEnabled:        awsv2.ToBool(cluster.DeletionProtection),
		PerformanceInsightsEnabled:       awsv2.ToBool(cluster.PerformanceInsightsEnabled),
	}
	for _, role := range cluster.AssociatedRoles {
		record.AssociatedRoleARNs = append(record.AssociatedRoleARNs, awsv2.ToString(role.RoleArn))
	}
	return record
}

func (a *SDKDynamoDBRDSReachabilityAPI) listRDSProxiesPage(ctx context.Context, marker string, pageSize int32) ([]DynamoDBRDSReachability, string, []providers.SourceError, error) {
	output, err := a.rdsClient.DescribeDBProxies(ctx, &rds.DescribeDBProxiesInput{Marker: stringPtrOrNil(marker), MaxRecords: awsv2.Int32(rdsPageSize(pageSize))})
	if err != nil {
		return nil, "", nil, err
	}
	records := []DynamoDBRDSReachability{}
	diagnostics := []providers.SourceError{}
	if output == nil {
		return records, "", diagnostics, nil
	}
	for _, proxy := range output.DBProxies {
		record := a.recordFromRDSProxy(proxy)
		a.enrichRDSTags(ctx, record.ResourceARN, &record, &diagnostics)
		records = append(records, record)
	}
	return records, strings.TrimSpace(awsv2.ToString(output.Marker)), diagnostics, nil
}

func (a *SDKDynamoDBRDSReachabilityAPI) recordFromRDSProxy(proxy rdstypes.DBProxy) DynamoDBRDSReachability {
	arn := strings.TrimSpace(awsv2.ToString(proxy.DBProxyArn))
	record := DynamoDBRDSReachability{
		ServiceCollectorRecord:           awscontract.ServiceCollectorRecord{Service: rdsServiceName, AccountID: firstNonEmptyAWSValue(a.accountID, accountIDFromARN(arn)), Region: firstNonEmptyAWSValue(a.region, regionFromARN(arn)), Source: "rds_metadata", EvidenceRef: arn},
		ResourceARN:                      arn,
		ResourceName:                     awsv2.ToString(proxy.DBProxyName),
		ResourceType:                     "rds_proxy",
		Engine:                           awsv2.ToString(proxy.EngineFamily),
		ResourceStatus:                   string(proxy.Status),
		Endpoint:                         awsv2.ToString(proxy.Endpoint),
		IAMDatabaseAuthenticationEnabled: strings.EqualFold(awsv2.ToString(proxy.DefaultAuthScheme), "IAM_AUTH"),
		AssociatedRoleARNs:               normalizeStringList([]string{awsv2.ToString(proxy.RoleArn)}),
	}
	return record
}

func (a *SDKDynamoDBRDSReachabilityAPI) enrichRDSTags(ctx context.Context, arn string, record *DynamoDBRDSReachability, diagnostics *[]providers.SourceError) {
	if strings.TrimSpace(arn) == "" {
		return
	}
	output, err := a.rdsClient.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: awsv2.String(arn)})
	if err != nil {
		*diagnostics = append(*diagnostics, dynamoDBRDSReachabilityDiagnostic("rds_resource_tags_failed", arn, fmt.Sprintf("ListTagsForResource %q failed: %v", arn, err), true))
		return
	}
	tags := map[string]string{}
	for _, tag := range output.TagList {
		if key := strings.TrimSpace(awsv2.ToString(tag.Key)); key != "" {
			tags[key] = strings.TrimSpace(awsv2.ToString(tag.Value))
		}
	}
	if len(tags) > 0 {
		record.Tags = tags
	}
}

func parseDynamoDBRDSPolicyGrants(raw string, service string) ([]DynamoDBRDSIdentityGrant, int, error) {
	grants, count, err := parseSQSSNSPolicyGrants(raw, service)
	if err != nil {
		return nil, 0, err
	}
	out := make([]DynamoDBRDSIdentityGrant, 0, len(grants))
	for _, grant := range grants {
		converted := DynamoDBRDSIdentityGrant(grant)
		converted.Capabilities = dynamoDBRDSCapabilitiesForActions(service, converted.Actions, converted.NotAction)
		out = append(out, converted)
	}
	return out, count, nil
}

func dynamoDBRDSCapabilitiesForActions(service string, actions []string, notAction bool) []string {
	if notAction {
		return []string{"unknown"}
	}
	seen := map[string]struct{}{}
	add := func(value string) {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	for _, action := range actions {
		normalized := strings.ToLower(strings.TrimSpace(action))
		switch {
		case normalized == "*" || normalized == "dynamodb:*" || normalized == "rds:*":
			add("read")
			add("write")
			add("manage")
		case strings.Contains(normalized, ":getitem"), strings.Contains(normalized, ":query"), strings.Contains(normalized, ":scan"), strings.Contains(normalized, ":describ"), strings.Contains(normalized, ":list"):
			add("read")
		case strings.Contains(normalized, ":put"), strings.Contains(normalized, ":update"), strings.Contains(normalized, ":delete"), strings.Contains(normalized, ":execute"):
			add("write")
		case strings.Contains(normalized, ":create"), strings.Contains(normalized, ":modify"), strings.Contains(normalized, ":restore"), strings.Contains(normalized, ":start"), strings.Contains(normalized, ":stop"):
			add("manage")
		}
	}
	if len(seen) == 0 {
		return []string{"unknown"}
	}
	result := make([]string, 0, len(seen))
	for capability := range seen {
		result = append(result, capability)
	}
	return normalizeStringList(result)
}

func dynamoDBRDSDecodePageToken(token string) (string, string) {
	trimmed := strings.TrimSpace(token)
	switch {
	case strings.HasPrefix(trimmed, dynamoDBRDSPageTokenDynamoDB):
		return dynamoDBServiceName, strings.TrimPrefix(trimmed, dynamoDBRDSPageTokenDynamoDB)
	case strings.HasPrefix(trimmed, dynamoDBRDSPageTokenRDSI):
		return "rds-instances", strings.TrimPrefix(trimmed, dynamoDBRDSPageTokenRDSI)
	case strings.HasPrefix(trimmed, dynamoDBRDSPageTokenRDSC):
		return "rds-clusters", strings.TrimPrefix(trimmed, dynamoDBRDSPageTokenRDSC)
	case strings.HasPrefix(trimmed, dynamoDBRDSPageTokenRDSP):
		return "rds-proxies", strings.TrimPrefix(trimmed, dynamoDBRDSPageTokenRDSP)
	default:
		return "", trimmed
	}
}

func rdsPageSize(pageSize int32) int32 {
	if pageSize < 20 {
		return 20
	}
	if pageSize > 100 {
		return 100
	}
	return pageSize
}

func dynamoDBTablePageSize(pageSize int32) int32 {
	if pageSize < 1 {
		return 1
	}
	if pageSize > 100 {
		return 100
	}
	return pageSize
}

func dynamoDBRDSReachabilityDiagnostic(code, sourceID, message string, retryable bool) providers.SourceError {
	return providers.SourceError{Collector: dynamoDBRDSReachabilityCollectorName, SourceID: strings.TrimSpace(sourceID), Code: code, Message: message, Retryable: retryable}
}

func dynamoDBRDSReachabilityAccountID(ctx context.Context, cfg awsv2.Config, fallback string) (string, error) {
	if strings.TrimSpace(fallback) != "" {
		return strings.TrimSpace(fallback), nil
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("read AWS caller identity for dynamodb/rds account id: %w", err)
	}
	resolved := strings.TrimSpace(awsv2.ToString(identity.Account))
	if resolved == "" {
		return "", fmt.Errorf("read AWS caller identity for dynamodb/rds account id: empty account id")
	}
	return resolved, nil
}
