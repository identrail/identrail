package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeManagedComputeRoleAPI struct {
	pages     []ManagedComputeRolePage
	tokens    []string
	pageSizes []int32
}

func (f *fakeManagedComputeRoleAPI) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (ManagedComputeRolePage, error) {
	f.tokens = append(f.tokens, nextToken)
	f.pageSizes = append(f.pageSizes, pageSize)
	if len(f.pages) == 0 {
		return ManagedComputeRolePage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestManagedComputeRoleCollectorEmitsPayloadSafeAssets(t *testing.T) {
	collectedAt := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/apprunner-service-role"
	serviceARN := "arn:aws:apprunner:us-east-1:123456789012:service/payments-api/1"
	api := &fakeManagedComputeRoleAPI{pages: []ManagedComputeRolePage{{
		Records: []ManagedComputeRole{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				AccountID:    "123456789012",
				Region:       "us-east-1",
				Service:      "apprunner",
				WorkloadID:   serviceARN,
				WorkloadName: "payments-api",
				WorkloadType: "apprunner_service",
				RoleARN:      roleARN,
			},
			RoleKind:       "apprunner_instance_role",
			WorkloadARN:    serviceARN,
			ResourceStatus: "RUNNING",
			Active:         true,
		}},
		NextToken: "page-2",
	}, {
		Diagnostics: []providers.SourceError{{
			Collector: managedComputeRoleCollectorName,
			SourceID:  "glue",
			Code:      "glue_crawlers_failed",
			Message:   "one crawler page failed",
			Retryable: true,
		}},
	}}}
	collector := NewManagedComputeRoleCollector(api, WithManagedComputeRolePageSize(25), WithManagedComputeRoleClock(func() time.Time { return collectedAt }))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 1 || len(diagnostics) != 1 || diagnostics[0].Code != "glue_crawlers_failed" {
		t.Fatalf("expected one asset and retained diagnostic, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
	if got, want := strings.Join(api.tokens, ","), ",page-2"; got != want {
		t.Fatalf("expected next tokens %q, got %q", want, got)
	}
	if len(api.pageSizes) != 2 || api.pageSizes[0] != 25 || api.pageSizes[1] != 25 {
		t.Fatalf("expected page size on every call, got %+v", api.pageSizes)
	}
	if assets[0].Kind != rawKindManagedComputeRole {
		t.Fatalf("unexpected asset kind %q", assets[0].Kind)
	}
	payload := string(assets[0].Payload)
	if strings.Contains(payload, "do-not-store") || strings.Contains(payload, "secret") {
		t.Fatalf("payload unsafe data leaked: %s", payload)
	}
	var record ManagedComputeRole
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if record.RoleName != "apprunner-service-role" || record.RoleAccountID != "123456789012" || record.ConnectorID != "aws-prod" {
		t.Fatalf("expected normalized role/scope fields, got %+v", record)
	}
}

func TestManagedComputeRoleNormalizerCreatesServiceResourceTypes(t *testing.T) {
	records := []ManagedComputeRole{
		managedComputeTestRecord("apprunner", "apprunner_service", "arn:aws:apprunner:us-east-1:123456789012:service/payments-api/1", "arn:aws:iam::123456789012:role/apprunner-payments", "apprunner_instance_role"),
		managedComputeTestRecord("batch", "batch_job_definition", "arn:aws:batch:us-east-1:123456789012:job-definition/importer:5", "arn:aws:iam::123456789012:role/batch-importer", "batch_job_role"),
		managedComputeTestRecord("glue", "glue_crawler", "arn:aws:glue:us-east-1:123456789012:crawler/customer-crawler", "arn:aws:iam::123456789012:role/glue-crawler", "glue_crawler_role"),
		managedComputeTestRecord("emr", "emr_cluster", "arn:aws:elasticmapreduce:us-east-1:123456789012:cluster/j-2AXXXXXXGAPLF", "arn:aws:iam::123456789012:role/emr-default-role", "emr_service_role"),
	}
	raw := make([]providers.RawAsset, 0, len(records))
	for _, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		raw = append(raw, providers.RawAsset{Kind: rawKindManagedComputeRole, SourceID: managedComputeRoleSourceID(record), Payload: payload})
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Identities) != 4 || len(bundle.Workloads) != 4 || len(bundle.Resources) != 4 {
		t.Fatalf("expected identity/workload/resource nodes for every record, got %+v", bundle)
	}
	wantTypes := map[domain.ResourceType]bool{
		domain.ResourceTypeAppRunnerService:   false,
		domain.ResourceTypeBatchJobDefinition: false,
		domain.ResourceTypeGlueCrawler:        false,
		domain.ResourceTypeEMRCluster:         false,
	}
	for _, resource := range bundle.Resources {
		if _, ok := wantTypes[resource.Type]; ok {
			wantTypes[resource.Type] = true
		}
		if resource.Metadata["role_arn"] == "" || resource.Metadata["coverage_status"] != "covered" {
			t.Fatalf("expected role and coverage metadata, got %+v", resource.Metadata)
		}
	}
	for resourceType, found := range wantTypes {
		if !found {
			t.Fatalf("expected resource type %q in %+v", resourceType, bundle.Resources)
		}
	}
	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("relationships: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipRunsAs) {
		t.Fatalf("expected workload-to-role relationships, got %+v", relationships)
	}
}

func TestManagedComputeRoleFixtureKindDetection(t *testing.T) {
	payload, err := json.Marshal(managedComputeTestRecord("glue", "glue_job", "arn:aws:glue:us-east-1:123456789012:job/customer-import", "arn:aws:iam::123456789012:role/glue-customer-import", "glue_job_role"))
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	kind, sourceID := fixtureAssetKindAndSourceID(payload)
	if kind != rawKindManagedComputeRole || strings.TrimSpace(sourceID) == "" {
		t.Fatalf("expected managed compute fixture detection, kind=%q sourceID=%q", kind, sourceID)
	}
}

func TestManagedComputeRoleScopeDefaultsUnsupportedCoverage(t *testing.T) {
	record := normalizeManagedComputeRoleScope(AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"}, ManagedComputeRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			RoleARN: "arn:aws:iam::123456789012:role/mwaa-execution",
		},
		UnsupportedService: "mwaa",
		WorkloadARN:        "arn:aws:airflow:us-east-1:123456789012:environment/customer-airflow",
	}, time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC))
	if record.CoverageStatus != "unsupported" || record.Service != "mwaa" {
		t.Fatalf("expected unsupported coverage default, got %+v", record)
	}
}

func TestManagedComputeRoleNormalizerMergesResourceRoleMetadata(t *testing.T) {
	jobARN := "arn:aws:batch:us-east-1:123456789012:job-definition/customer-import:5"
	records := []ManagedComputeRole{
		managedComputeTestRecord("batch", "batch_job_definition", jobARN, "arn:aws:iam::123456789012:role/batch-job", "batch_job_role"),
		managedComputeTestRecord("batch", "batch_job_definition", jobARN, "arn:aws:iam::123456789012:role/batch-execution", "batch_execution_role"),
	}
	for idx := range records {
		records[idx].WorkloadName = ""
	}
	raw := make([]providers.RawAsset, 0, len(records))
	for _, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		raw = append(raw, providers.RawAsset{Kind: rawKindManagedComputeRole, SourceID: managedComputeRoleSourceID(record), Payload: payload})
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Resources) != 1 {
		t.Fatalf("expected one deduped Batch job-definition resource, got %+v", bundle.Resources)
	}
	roles, ok := bundle.Resources[0].Metadata["roles"].([]map[string]any)
	if !ok || len(roles) != 2 {
		t.Fatalf("expected both role associations in resource metadata, got %+v", bundle.Resources[0].Metadata)
	}
	if bundle.Resources[0].Name != "customer-import:5" {
		t.Fatalf("expected Batch ARN fallback to retain name and revision, got %q", bundle.Resources[0].Name)
	}
}

func TestManagedComputeRoleNormalizerPreservesSupportRoleRelationships(t *testing.T) {
	batchJobARN := "arn:aws:batch:us-east-1:123456789012:job-definition/customer-import:5"
	appRunnerARN := "arn:aws:apprunner:us-east-1:123456789012:service/payments-api/1"
	records := []ManagedComputeRole{
		managedComputeTestRecord("batch", "batch_job_definition", batchJobARN, "arn:aws:iam::123456789012:role/batch-job", "batch_job_role"),
		managedComputeTestRecord("batch", "batch_job_definition", batchJobARN, "arn:aws:iam::123456789012:role/batch-execution", "batch_execution_role"),
		managedComputeTestRecord("apprunner", "apprunner_service", appRunnerARN, "arn:aws:iam::123456789012:role/apprunner-access", "apprunner_access_role"),
	}
	raw := make([]providers.RawAsset, 0, len(records))
	for _, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		raw = append(raw, providers.RawAsset{Kind: rawKindManagedComputeRole, SourceID: managedComputeRoleSourceID(record), Payload: payload})
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	workloadTypes := map[string]bool{}
	for _, workload := range bundle.Workloads {
		workloadTypes[workload.Type] = true
	}
	for _, expectedType := range []string{"batch_job_definition", "batch_job_definition_execution_role", "apprunner_service_access_role"} {
		if !workloadTypes[expectedType] {
			t.Fatalf("expected workload type %q in %+v", expectedType, bundle.Workloads)
		}
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("relationships: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipRunsAs) {
		t.Fatalf("expected job role to remain runs_as, got %+v", relationships)
	}
	if !hasRelationshipType(relationships, domain.RelationshipAttachedTo) {
		t.Fatalf("expected support roles to use attached_to, got %+v", relationships)
	}
}

func TestManagedComputeSDKRecordHelpersRetainSafeMetadata(t *testing.T) {
	api := &SDKManagedComputeRoleAPI{accountID: "123456789012", region: "us-east-1"}
	appRunnerRecords := api.recordsFromAppRunnerService(&apprunnertypes.Service{
		ServiceArn:  awsv2.String("arn:aws:apprunner:us-east-1:123456789012:service/payments-api/1"),
		ServiceName: awsv2.String("payments-api"),
		Status:      apprunnertypes.ServiceStatusRunning,
		InstanceConfiguration: &apprunnertypes.InstanceConfiguration{
			InstanceRoleArn: awsv2.String("arn:aws:iam::123456789012:role/apprunner-instance"),
		},
		SourceConfiguration: &apprunnertypes.SourceConfiguration{
			AuthenticationConfiguration: &apprunnertypes.AuthenticationConfiguration{
				AccessRoleArn: awsv2.String("arn:aws:iam::123456789012:role/apprunner-ecr-access"),
			},
		},
	})
	if len(appRunnerRecords) != 2 || appRunnerRecords[0].Service != "apprunner" || appRunnerRecords[0].RoleKind != "apprunner_instance_role" {
		t.Fatalf("expected App Runner instance/access records, got %+v", appRunnerRecords)
	}

	batchRecords := api.recordsFromBatchJobDefinition(batchtypes.JobDefinition{
		JobDefinitionArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:job-definition/importer:5"),
		JobDefinitionName: awsv2.String("importer"),
		Revision:          awsv2.Int32(5),
		ContainerProperties: &batchtypes.ContainerProperties{
			JobRoleArn:       awsv2.String("arn:aws:iam::123456789012:role/batch-job"),
			ExecutionRoleArn: awsv2.String("arn:aws:iam::123456789012:role/batch-execution"),
		},
	})
	if len(batchRecords) != 2 || batchRecords[0].Revision != 5 || batchRecords[1].RoleKind != "batch_execution_role" {
		t.Fatalf("expected Batch job/execution records, got %+v", batchRecords)
	}

	ecsBatchRecords := api.recordsFromBatchJobDefinition(batchtypes.JobDefinition{
		JobDefinitionArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:job-definition/ecs-importer:7"),
		JobDefinitionName: awsv2.String("ecs-importer"),
		Revision:          awsv2.Int32(7),
		EcsProperties: &batchtypes.EcsProperties{
			TaskProperties: []batchtypes.EcsTaskProperties{{
				TaskRoleArn:      awsv2.String("batch-ecs-task"),
				ExecutionRoleArn: awsv2.String("arn:aws:iam::123456789012:role/batch-ecs-execution"),
			}},
		},
	})
	if len(ecsBatchRecords) != 2 || ecsBatchRecords[0].RoleARN != "arn:aws:iam::123456789012:role/batch-ecs-task" || ecsBatchRecords[1].RoleKind != "batch_execution_role" {
		t.Fatalf("expected Batch ECS task/execution records, got %+v", ecsBatchRecords)
	}

	multiNodeBatchRecords := api.recordsFromBatchJobDefinition(batchtypes.JobDefinition{
		JobDefinitionArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:job-definition/multinode-importer:9"),
		JobDefinitionName: awsv2.String("multinode-importer"),
		Revision:          awsv2.Int32(9),
		NodeProperties: &batchtypes.NodeProperties{
			NodeRangeProperties: []batchtypes.NodeRangeProperty{{
				Container: &batchtypes.ContainerProperties{
					JobRoleArn:       awsv2.String("batch-main-node"),
					ExecutionRoleArn: awsv2.String("arn:aws:iam::123456789012:role/batch-main-execution"),
				},
			}, {
				Container: &batchtypes.ContainerProperties{
					JobRoleArn: awsv2.String("arn:aws:iam::123456789012:role/batch-worker-node"),
				},
			}},
		},
	})
	if len(multiNodeBatchRecords) != 3 || multiNodeBatchRecords[0].RoleARN != "arn:aws:iam::123456789012:role/batch-main-node" || multiNodeBatchRecords[1].RoleKind != "batch_execution_role" {
		t.Fatalf("expected Batch multi-node job/execution records, got %+v", multiNodeBatchRecords)
	}

	emrRecords := api.recordsFromEMRCluster(&emrtypes.Cluster{
		Id:              awsv2.String("j-2AXXXXXXGAPLF"),
		Name:            awsv2.String("analytics"),
		ClusterArn:      awsv2.String("arn:aws:elasticmapreduce:us-east-1:123456789012:cluster/j-2AXXXXXXGAPLF"),
		ServiceRole:     awsv2.String("EMR_DefaultRole"),
		AutoScalingRole: awsv2.String("EMR_AutoScaling_DefaultRole"),
		Status:          &emrtypes.ClusterStatus{State: emrtypes.ClusterStateRunning},
	})
	if len(emrRecords) != 2 || emrRecords[0].ResourceStatus != "RUNNING" || !emrRecords[0].Active {
		t.Fatalf("expected EMR service/autoscaling records, got %+v", emrRecords)
	}
	if emrRecords[0].RoleARN != "arn:aws:iam::123456789012:role/EMR_DefaultRole" || emrRecords[1].RoleARN != "arn:aws:iam::123456789012:role/EMR_AutoScaling_DefaultRole" {
		t.Fatalf("expected EMR role names expanded to IAM role ARNs, got %+v", emrRecords)
	}

	apiWithoutAccount := &SDKManagedComputeRoleAPI{region: "us-east-1"}
	derivedAccountRecords := apiWithoutAccount.recordsFromBatchJobDefinition(batchtypes.JobDefinition{
		JobDefinitionArn:  awsv2.String("arn:aws:batch:us-east-1:210987654321:job-definition/account-derived:3"),
		JobDefinitionName: awsv2.String("account-derived"),
		Revision:          awsv2.Int32(3),
		ContainerProperties: &batchtypes.ContainerProperties{
			JobRoleArn: awsv2.String("batch-derived-role"),
		},
	})
	if len(derivedAccountRecords) != 1 || derivedAccountRecords[0].RoleARN != "arn:aws:iam::210987654321:role/batch-derived-role" {
		t.Fatalf("expected Batch role name expanded from workload ARN account, got %+v", derivedAccountRecords)
	}
	govPartitionRecords := apiWithoutAccount.recordsFromBatchJobDefinition(batchtypes.JobDefinition{
		JobDefinitionArn:  awsv2.String("arn:aws-us-gov:batch:us-gov-west-1:210987654321:job-definition/gov-derived:3"),
		JobDefinitionName: awsv2.String("gov-derived"),
		Revision:          awsv2.Int32(3),
		ContainerProperties: &batchtypes.ContainerProperties{
			JobRoleArn: awsv2.String("batch-gov-role"),
		},
	})
	if len(govPartitionRecords) != 1 || govPartitionRecords[0].RoleARN != "arn:aws-us-gov:iam::210987654321:role/batch-gov-role" {
		t.Fatalf("expected Batch role name expanded with workload ARN partition, got %+v", govPartitionRecords)
	}
	unknownAccountRecords := apiWithoutAccount.recordsForRoles("glue", "glue_job", "customer-import", "", "", "", "", []struct {
		arn  string
		kind string
	}{{arn: apiWithoutAccount.iamRoleARNFromNameOrARN("Glue_DefaultRole", ""), kind: "glue_job_role"}}, nil)
	if len(unknownAccountRecords) != 0 {
		t.Fatalf("expected bare role name without account context to be skipped, got %+v", unknownAccountRecords)
	}
}

func TestManagedComputeSDKExpandsGlueJobRoleNames(t *testing.T) {
	client := &fakeGlueSDKClient{
		jobOutputs: []*glue.GetJobsOutput{{
			Jobs: []gluetypes.Job{{
				Name: awsv2.String("customer-import"),
				Role: awsv2.String("Glue_DefaultRole"),
			}},
		}},
		crawlerOutputs: []*glue.GetCrawlersOutput{{
			Crawlers: []gluetypes.Crawler{{
				Name: awsv2.String("customer-crawler"),
				Role: awsv2.String("GlueCrawlerRole"),
			}},
		}},
	}
	api := &SDKManagedComputeRoleAPI{glueClient: client, accountID: "123456789012", region: "us-east-1"}

	records, diagnostics, err := api.listGlueRoles(context.Background(), 100)
	if err != nil {
		t.Fatalf("list glue roles: %v", err)
	}
	if len(diagnostics) != 0 || len(records) != 2 {
		t.Fatalf("expected Glue job and crawler roles with no diagnostics, records=%+v diagnostics=%+v", records, diagnostics)
	}
	if records[0].RoleARN != "arn:aws:iam::123456789012:role/Glue_DefaultRole" {
		t.Fatalf("expected Glue role name expanded to IAM role ARN, got %+v", records[0])
	}
	if records[1].RoleARN != "arn:aws:iam::123456789012:role/GlueCrawlerRole" || records[1].RoleKind != "glue_crawler_role" {
		t.Fatalf("expected Glue crawler role name expanded to IAM role ARN, got %+v", records[1])
	}
}

func TestManagedComputeSDKContinuesAfterRetryableSubserviceFailure(t *testing.T) {
	appRunnerClient := &fakeAppRunnerSDKClient{listErr: errors.New("throttled by App Runner")}
	batchClient := &fakeBatchSDKClient{
		envOutputs: []*batch.DescribeComputeEnvironmentsOutput{{
			ComputeEnvironments: []batchtypes.ComputeEnvironmentDetail{{
				ComputeEnvironmentArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:compute-environment/env-a"),
				ComputeEnvironmentName: awsv2.String("env-a"),
				ServiceRole:            awsv2.String("arn:aws:iam::123456789012:role/batch-service-a"),
				State:                  batchtypes.CEStateEnabled,
			}},
		}},
	}
	api := &SDKManagedComputeRoleAPI{
		appRunnerClient: appRunnerClient,
		batchClient:     batchClient,
		accountID:       "123456789012",
		region:          "us-east-1",
	}

	page, err := api.ListServiceRoles(context.Background(), "", 100)
	if err != nil {
		t.Fatalf("managed compute sub-service failure should degrade instead of failing page: %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].RoleKind != "batch_service_role" {
		t.Fatalf("expected Batch roles to be retained after App Runner throttling, got %+v", page.Records)
	}
	if len(page.Diagnostics) == 0 || page.Diagnostics[0].Code != "apprunner_services_failed" || !page.Diagnostics[0].Retryable {
		t.Fatalf("expected retryable App Runner diagnostic, got %+v", page.Diagnostics)
	}
}

func TestManagedComputeSDKClampsAppRunnerPageSize(t *testing.T) {
	client := &fakeAppRunnerSDKClient{}
	api := &SDKManagedComputeRoleAPI{appRunnerClient: client, accountID: "123456789012", region: "us-east-1"}
	if _, _, err := api.listAppRunnerRoles(context.Background(), 100); err != nil {
		t.Fatalf("list app runner roles: %v", err)
	}
	if len(client.listInputs) != 1 || awsv2.ToInt32(client.listInputs[0].MaxResults) != 20 {
		t.Fatalf("expected App Runner MaxResults clamp to 20, got %+v", client.listInputs)
	}
}

func TestManagedComputeSDKPaginatesBatchRoles(t *testing.T) {
	client := &fakeBatchSDKClient{
		envOutputs: []*batch.DescribeComputeEnvironmentsOutput{
			{
				ComputeEnvironments: []batchtypes.ComputeEnvironmentDetail{{
					ComputeEnvironmentArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:compute-environment/env-a"),
					ComputeEnvironmentName: awsv2.String("env-a"),
					ServiceRole:            awsv2.String("arn:aws:iam::123456789012:role/batch-service-a"),
					State:                  batchtypes.CEStateEnabled,
					ComputeResources: &batchtypes.ComputeResource{
						InstanceRole: awsv2.String("arn:aws:iam::123456789012:instance-profile/ecsInstanceRole"),
					},
				}},
				NextToken: awsv2.String("env-page-2"),
			},
			{
				ComputeEnvironments: []batchtypes.ComputeEnvironmentDetail{{
					ComputeEnvironmentArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:compute-environment/env-b"),
					ComputeEnvironmentName: awsv2.String("env-b"),
					ServiceRole:            awsv2.String("arn:aws:iam::123456789012:role/batch-service-b"),
					State:                  batchtypes.CEStateEnabled,
				}},
			},
		},
		jobOutputs: []*batch.DescribeJobDefinitionsOutput{
			{
				JobDefinitions: []batchtypes.JobDefinition{{
					JobDefinitionArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:job-definition/import-a:1"),
					JobDefinitionName: awsv2.String("import-a"),
					ContainerProperties: &batchtypes.ContainerProperties{
						JobRoleArn: awsv2.String("arn:aws:iam::123456789012:role/batch-job-a"),
					},
				}},
				NextToken: awsv2.String("job-page-2"),
			},
			{
				JobDefinitions: []batchtypes.JobDefinition{{
					JobDefinitionArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:job-definition/import-b:1"),
					JobDefinitionName: awsv2.String("import-b"),
					ContainerProperties: &batchtypes.ContainerProperties{
						ExecutionRoleArn: awsv2.String("arn:aws:iam::123456789012:role/batch-execution-b"),
					},
				}},
			},
		},
	}
	api := &SDKManagedComputeRoleAPI{batchClient: client, accountID: "123456789012", region: "us-east-1"}
	records, diagnostics, err := api.listBatchRoles(context.Background(), 100)
	if err != nil {
		t.Fatalf("list batch roles: %v", err)
	}
	if len(diagnostics) != 0 || len(records) != 4 {
		t.Fatalf("expected four role records and no diagnostics, records=%+v diagnostics=%+v", records, diagnostics)
	}
	for _, record := range records {
		if strings.Contains(record.RoleARN, ":instance-profile/") || record.RoleKind == "batch_instance_role" {
			t.Fatalf("expected Batch instance profile to be skipped, got %+v", records)
		}
	}
	if got, want := strings.Join(client.envTokens, ","), ",env-page-2"; got != want {
		t.Fatalf("expected compute environment tokens %q, got %q", want, got)
	}
	if got, want := strings.Join(client.jobTokens, ","), ",job-page-2"; got != want {
		t.Fatalf("expected job definition tokens %q, got %q", want, got)
	}
}

func TestManagedComputeSDKContinuesToBatchJobDefinitionsAfterEnvironmentFailure(t *testing.T) {
	client := &fakeBatchSDKClient{
		envErr: errors.New("throttled by Batch"),
		jobOutputs: []*batch.DescribeJobDefinitionsOutput{{
			JobDefinitions: []batchtypes.JobDefinition{{
				JobDefinitionArn:  awsv2.String("arn:aws:batch:us-east-1:123456789012:job-definition/import:1"),
				JobDefinitionName: awsv2.String("import"),
				ContainerProperties: &batchtypes.ContainerProperties{
					JobRoleArn: awsv2.String("arn:aws:iam::123456789012:role/batch-job"),
				},
			}},
		}},
	}
	api := &SDKManagedComputeRoleAPI{batchClient: client, accountID: "123456789012", region: "us-east-1"}

	records, diagnostics, err := api.listBatchRoles(context.Background(), 100)
	if err != nil {
		t.Fatalf("list batch roles: %v", err)
	}
	if len(records) != 1 || records[0].RoleKind != "batch_job_role" {
		t.Fatalf("expected Batch job definition record after compute environment failure, got %+v", records)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "batch_compute_environments_failed" || !diagnostics[0].Retryable {
		t.Fatalf("expected retryable compute environment diagnostic, got %+v", diagnostics)
	}
}

func TestManagedComputeSDKPreservesGlueAndEMRPartitionForBareRoleNames(t *testing.T) {
	glueClient := &fakeGlueSDKClient{
		jobOutputs: []*glue.GetJobsOutput{{
			Jobs: []gluetypes.Job{{
				Name: awsv2.String("customer-import"),
				Role: awsv2.String("GlueServiceRole"),
			}},
		}},
		crawlerOutputs: []*glue.GetCrawlersOutput{{
			Crawlers: []gluetypes.Crawler{{
				Name: awsv2.String("customer-crawler"),
				Role: awsv2.String("GlueCrawlerRole"),
			}},
		}},
	}
	glueAPI := &SDKManagedComputeRoleAPI{glueClient: glueClient, accountID: "123456789012", region: "us-gov-west-1"}
	glueRecords, _, err := glueAPI.listGlueRoles(context.Background(), 100)
	if err != nil {
		t.Fatalf("list glue roles: %v", err)
	}
	if len(glueRecords) != 2 {
		t.Fatalf("expected Glue job and crawler records, got %+v", glueRecords)
	}
	for _, record := range glueRecords {
		if !strings.HasPrefix(record.WorkloadARN, "arn:aws-us-gov:glue:") {
			t.Fatalf("expected GovCloud Glue workload ARN, got %q", record.WorkloadARN)
		}
		if !strings.HasPrefix(record.RoleARN, "arn:aws-us-gov:iam::") {
			t.Fatalf("expected GovCloud Glue role ARN, got %q", record.RoleARN)
		}
	}

	emrAPI := &SDKManagedComputeRoleAPI{accountID: "123456789012", region: "cn-northwest-1"}
	emrRecords := emrAPI.recordsFromEMRCluster(&emrtypes.Cluster{
		Id:          awsv2.String("j-1234"),
		Name:        awsv2.String("analytics"),
		ServiceRole: awsv2.String("EMR_DefaultRole"),
		Status:      &emrtypes.ClusterStatus{State: emrtypes.ClusterStateRunning},
	})
	if len(emrRecords) == 0 {
		t.Fatalf("expected EMR record for bare role name, got none")
	}
	if !strings.HasPrefix(emrRecords[0].WorkloadARN, "arn:aws-cn:elasticmapreduce:") {
		t.Fatalf("expected China EMR workload ARN, got %q", emrRecords[0].WorkloadARN)
	}
	if !strings.HasPrefix(emrRecords[0].RoleARN, "arn:aws-cn:iam::") {
		t.Fatalf("expected China EMR role ARN, got %q", emrRecords[0].RoleARN)
	}
}

func TestManagedComputeSDKContinuesToGlueCrawlersAfterJobsFailure(t *testing.T) {
	client := &fakeGlueSDKClient{
		jobErr: errors.New("throttled by Glue"),
		crawlerOutputs: []*glue.GetCrawlersOutput{{
			Crawlers: []gluetypes.Crawler{{
				Name: awsv2.String("customer-crawler"),
				Role: awsv2.String("arn:aws:iam::123456789012:role/glue-crawler"),
			}},
		}},
	}
	api := &SDKManagedComputeRoleAPI{glueClient: client, accountID: "123456789012", region: "us-east-1"}

	records, diagnostics, err := api.listGlueRoles(context.Background(), 100)
	if err != nil {
		t.Fatalf("list glue roles: %v", err)
	}
	if len(records) != 1 || records[0].RoleKind != "glue_crawler_role" {
		t.Fatalf("expected Glue crawler record after GetJobs failure, got %+v", records)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "glue_jobs_failed" || !diagnostics[0].Retryable {
		t.Fatalf("expected retryable Glue jobs diagnostic, got %+v", diagnostics)
	}
}

func managedComputeTestRecord(service string, workloadType string, workloadARN string, roleARN string, roleKind string) ManagedComputeRole {
	return ManagedComputeRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Service:      service,
			WorkloadID:   workloadARN,
			WorkloadName: eventDrivenNameFromARN(workloadARN),
			WorkloadType: workloadType,
			RoleARN:      roleARN,
		},
		RoleName:       roleNameFromARN(roleARN),
		RoleKind:       roleKind,
		RoleAccountID:  roleAccountIDFromARN(roleARN),
		WorkloadARN:    workloadARN,
		ResourceARN:    workloadARN,
		ResourceType:   workloadType,
		ResourceStatus: "ACTIVE",
		CoverageStatus: "covered",
		Active:         true,
	}
}

type fakeAppRunnerSDKClient struct {
	listInputs []*apprunner.ListServicesInput
	listErr    error
}

func (f *fakeAppRunnerSDKClient) ListServices(ctx context.Context, params *apprunner.ListServicesInput, optFns ...func(*apprunner.Options)) (*apprunner.ListServicesOutput, error) {
	f.listInputs = append(f.listInputs, params)
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &apprunner.ListServicesOutput{}, nil
}

func (f *fakeAppRunnerSDKClient) DescribeService(ctx context.Context, params *apprunner.DescribeServiceInput, optFns ...func(*apprunner.Options)) (*apprunner.DescribeServiceOutput, error) {
	return &apprunner.DescribeServiceOutput{}, nil
}

type fakeBatchSDKClient struct {
	envOutputs []*batch.DescribeComputeEnvironmentsOutput
	jobOutputs []*batch.DescribeJobDefinitionsOutput
	envTokens  []string
	jobTokens  []string
	envErr     error
	jobErr     error
}

func (f *fakeBatchSDKClient) DescribeComputeEnvironments(ctx context.Context, params *batch.DescribeComputeEnvironmentsInput, optFns ...func(*batch.Options)) (*batch.DescribeComputeEnvironmentsOutput, error) {
	f.envTokens = append(f.envTokens, awsv2.ToString(params.NextToken))
	if f.envErr != nil {
		return nil, f.envErr
	}
	if len(f.envOutputs) == 0 {
		return &batch.DescribeComputeEnvironmentsOutput{}, nil
	}
	output := f.envOutputs[0]
	f.envOutputs = f.envOutputs[1:]
	return output, nil
}

func (f *fakeBatchSDKClient) DescribeJobDefinitions(ctx context.Context, params *batch.DescribeJobDefinitionsInput, optFns ...func(*batch.Options)) (*batch.DescribeJobDefinitionsOutput, error) {
	f.jobTokens = append(f.jobTokens, awsv2.ToString(params.NextToken))
	if f.jobErr != nil {
		return nil, f.jobErr
	}
	if len(f.jobOutputs) == 0 {
		return &batch.DescribeJobDefinitionsOutput{}, nil
	}
	output := f.jobOutputs[0]
	f.jobOutputs = f.jobOutputs[1:]
	return output, nil
}

type fakeGlueSDKClient struct {
	jobOutputs     []*glue.GetJobsOutput
	crawlerOutputs []*glue.GetCrawlersOutput
	jobErr         error
}

func (f *fakeGlueSDKClient) GetJobs(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error) {
	if f.jobErr != nil {
		return nil, f.jobErr
	}
	if len(f.jobOutputs) == 0 {
		return &glue.GetJobsOutput{}, nil
	}
	output := f.jobOutputs[0]
	f.jobOutputs = f.jobOutputs[1:]
	return output, nil
}

func (f *fakeGlueSDKClient) GetCrawlers(ctx context.Context, params *glue.GetCrawlersInput, optFns ...func(*glue.Options)) (*glue.GetCrawlersOutput, error) {
	if len(f.crawlerOutputs) == 0 {
		return &glue.GetCrawlersOutput{}, nil
	}
	output := f.crawlerOutputs[0]
	f.crawlerOutputs = f.crawlerOutputs[1:]
	return output, nil
}
