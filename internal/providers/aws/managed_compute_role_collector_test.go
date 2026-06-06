package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
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

	emrRecords := api.recordsFromEMRCluster(&emrtypes.Cluster{
		Id:              awsv2.String("j-2AXXXXXXGAPLF"),
		Name:            awsv2.String("analytics"),
		ClusterArn:      awsv2.String("arn:aws:elasticmapreduce:us-east-1:123456789012:cluster/j-2AXXXXXXGAPLF"),
		ServiceRole:     awsv2.String("arn:aws:iam::123456789012:role/emr-default"),
		AutoScalingRole: awsv2.String("arn:aws:iam::123456789012:role/emr-autoscaling"),
		Status:          &emrtypes.ClusterStatus{State: emrtypes.ClusterStateRunning},
	})
	if len(emrRecords) != 2 || emrRecords[0].ResourceStatus != "RUNNING" || !emrRecords[0].Active {
		t.Fatalf("expected EMR service/autoscaling records, got %+v", emrRecords)
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
