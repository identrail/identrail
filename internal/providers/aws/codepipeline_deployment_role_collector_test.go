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

type codePipelineDeploymentRoleAPIFunc func(ctx context.Context, nextToken string, pageSize int32) (CodePipelineDeploymentRolePage, error)

func (f codePipelineDeploymentRoleAPIFunc) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (CodePipelineDeploymentRolePage, error) {
	return f(ctx, nextToken, pageSize)
}

func TestCodePipelineDeploymentRoleCollectorEmitsContractRecordsAndDiagnostics(t *testing.T) {
	fixedNow := time.Date(2026, 6, 6, 11, 0, 0, 0, time.UTC)
	api := codePipelineDeploymentRoleAPIFunc(func(_ context.Context, nextToken string, pageSize int32) (CodePipelineDeploymentRolePage, error) {
		if nextToken != "" {
			t.Fatalf("expected one page, got token %q", nextToken)
		}
		if pageSize != 2 {
			t.Fatalf("expected page size 2, got %d", pageSize)
		}
		return CodePipelineDeploymentRolePage{
			Records: []CodePipelineDeploymentRole{{
				ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
					WorkloadID:   "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
					WorkloadType: "codepipeline_pipeline",
					WorkloadName: "payments-release",
					RoleARN:      "arn:aws:iam::123456789012:role/payments-codepipeline-service",
					Source:       "getpipeline",
					EvidenceRef:  "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
				},
				RoleKind:                 "pipeline_service_role",
				RoleName:                 "payments-codepipeline-service",
				PipelineARN:              "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
				PipelineName:             "payments-release",
				PipelineType:             "V2",
				ExecutionMode:            "QUEUED",
				ArtifactStoreTypes:       []string{"S3"},
				ArtifactStoreLocations:   []string{"payments-pipeline-artifacts"},
				ArtifactKMSKeyARNs:       []string{"arn:aws:kms:us-east-1:123456789012:key/pipeline"},
				DisabledStageTransitions: []string{"Deploy: freeze window"},
				PassRoleAdjacent:         true,
				Tags:                     map[string]string{"owner": "platform"},
			}, {
				ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
					WorkloadID:   "arn:aws:codepipeline:us-east-1:123456789012:payments-release/Deploy/Prod",
					WorkloadType: "codepipeline_action",
					WorkloadName: "payments-release / Deploy / Prod",
					RoleARN:      "arn:aws:iam::210987654321:role/payments-prod-deploy-action",
					Source:       "getpipeline",
					EvidenceRef:  "arn:aws:codepipeline:us-east-1:123456789012:payments-release#stage/Deploy/action/Prod",
				},
				RoleKind:             "action_role",
				RoleAccountID:        "210987654321",
				PipelineARN:          "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
				PipelineName:         "payments-release",
				StageName:            "Deploy",
				ActionName:           "Prod",
				ActionCategory:       "Deploy",
				ActionProvider:       "CodeDeploy",
				ActionRegion:         "us-west-2",
				InputArtifactNames:   []string{"BuildArtifact"},
				ConfigurationKeys:    []string{"ApplicationName", "DeploymentGroupName"},
				CrossRegionAction:    true,
				CrossAccountRole:     true,
				PassRoleAdjacent:     true,
				ProviderIdentifiers:  []string{"Deploy/AWS/CodeDeploy/1"},
				ArtifactStoreRegions: []string{"us-east-1", "us-west-2"},
			}},
			Diagnostics: []providers.SourceError{{
				Collector: codePipelineDeploymentRoleCollectorName,
				SourceID:  "payments-release",
				Code:      "pipeline_state_get_failed",
				Message:   "state unavailable",
				Retryable: true,
			}},
		}, nil
	})
	collector := NewCodePipelineDeploymentRoleCollector(api, WithCodePipelineDeploymentRolePageSize(2), WithCodePipelineDeploymentRoleClock(func() time.Time {
		return fixedNow
	}))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-codepipeline",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 2 || len(diagnostics) != 1 {
		t.Fatalf("expected two raw assets and one diagnostic, assets=%+v diagnostics=%+v", assets, diagnostics)
	}
	var payload CodePipelineDeploymentRole
	for _, asset := range assets {
		var candidate CodePipelineDeploymentRole
		if err := json.Unmarshal(asset.Payload, &candidate); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if candidate.RoleKind == "action_role" {
			payload = candidate
			break
		}
	}
	if payload.RoleKind == "" {
		t.Fatalf("expected action role payload, got assets=%+v", assets)
	}
	if payload.Service != "codepipeline" || payload.CollectorName != codePipelineDeploymentRoleCollectorName || payload.RoleKind != "action_role" {
		t.Fatalf("expected normalized CodePipeline action metadata, got %+v", payload)
	}
	if strings.Contains(strings.Join(payload.ConfigurationKeys, ","), "must-not-appear") {
		t.Fatalf("configuration values must not be collected, got %+v", payload.ConfigurationKeys)
	}
	if payload.AccountID != "123456789012" || payload.RoleAccountID != "210987654321" {
		t.Fatalf("expected action workload account and role account to stay separate, got %+v", payload)
	}
	if _, err := awscontract.NormalizeServiceCollectorRecord(payload.ServiceCollectorRecord); err != nil {
		t.Fatalf("expected payload to satisfy service collector contract: %v", err)
	}
}

func TestRoleNormalizerAddsCodePipelineRunsAsEdges(t *testing.T) {
	record := CodePipelineDeploymentRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "codepipeline",
			WorkloadID:    "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
			WorkloadType:  "codepipeline_pipeline",
			WorkloadName:  "payments-release",
			RoleARN:       "arn:aws:iam::123456789012:role/payments-codepipeline-service",
			Source:        "getpipeline",
			EvidenceRef:   "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
			Confidence:    0.96,
			ScanID:        "scan-codepipeline",
			CollectorName: codePipelineDeploymentRoleCollectorName,
			CollectedAt:   time.Date(2026, 6, 6, 11, 0, 0, 0, time.UTC),
		},
		RoleName:               "payments-codepipeline-service",
		RoleKind:               "pipeline_service_role",
		PipelineARN:            "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
		PipelineName:           "payments-release",
		ArtifactStoreTypes:     []string{"S3"},
		ArtifactStoreLocations: []string{"payments-pipeline-artifacts"},
		PassRoleAdjacent:       true,
		Tags:                   map[string]string{"owner": "platform"},
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindCodePipelineDeploymentRole, SourceID: "codepipeline-role", Payload: payload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Identities) != 1 || len(bundle.Workloads) != 1 || len(bundle.Resources) != 1 {
		t.Fatalf("expected codepipeline identity/workload/resource, got identities=%+v workloads=%+v resources=%+v", bundle.Identities, bundle.Workloads, bundle.Resources)
	}
	if bundle.Resources[0].Type != domain.ResourceTypeCodePipeline {
		t.Fatalf("expected codepipeline resource, got %+v", bundle.Resources[0])
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("graph contract invalid: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipRunsAs) {
		t.Fatalf("expected codepipeline role runs_as edge, got %+v", relationships)
	}
}

func TestRoleNormalizerKeepsCrossAccountCodePipelineActionScopedToPipelineAccount(t *testing.T) {
	record := CodePipelineDeploymentRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "codepipeline",
			WorkloadID:    "arn:aws:codepipeline:us-east-1:123456789012:payments-release/Deploy/Prod",
			WorkloadType:  "codepipeline_action",
			WorkloadName:  "payments-release / Deploy / Prod",
			RoleARN:       "arn:aws:iam::210987654321:role/payments-prod-deploy-action",
			Source:        "getpipeline",
			EvidenceRef:   "arn:aws:codepipeline:us-east-1:123456789012:payments-release#stage/Deploy/action/Prod",
			Confidence:    0.9,
			ScanID:        "scan-codepipeline",
			CollectorName: codePipelineDeploymentRoleCollectorName,
			CollectedAt:   time.Date(2026, 6, 6, 11, 0, 0, 0, time.UTC),
		},
		RoleName:         "payments-prod-deploy-action",
		RoleAccountID:    "210987654321",
		RoleKind:         "action_role",
		PipelineARN:      "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
		PipelineName:     "payments-release",
		StageName:        "Deploy",
		ActionName:       "Prod",
		CrossAccountRole: true,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindCodePipelineDeploymentRole, SourceID: "codepipeline-action-role", Payload: payload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Identities) != 1 || bundle.Identities[0].ID != "aws:identity:arn:aws:iam::210987654321:role/payments-prod-deploy-action" {
		t.Fatalf("expected cross-account role identity, got %+v", bundle.Identities)
	}
	if len(bundle.Workloads) != 1 || bundle.Workloads[0].AccountID != "123456789012" {
		t.Fatalf("expected CodePipeline action workload to remain in pipeline account, got %+v", bundle.Workloads)
	}
	if len(bundle.Resources) != 1 || bundle.Resources[0].AccountID != "123456789012" {
		t.Fatalf("expected CodePipeline resource to remain in pipeline account, got %+v", bundle.Resources)
	}
	if got := bundle.Resources[0].Metadata["role_account_id"]; got != "210987654321" {
		t.Fatalf("expected role account metadata, got %+v", bundle.Resources[0].Metadata)
	}
}

func TestRoleNormalizerPrefersCodePipelineResourceMetadataFromPipelineRole(t *testing.T) {
	pipelineARN := "arn:aws:codepipeline:us-east-1:123456789012:payments-release"
	collectedAt := time.Date(2026, 6, 6, 11, 0, 0, 0, time.UTC)
	action := CodePipelineDeploymentRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "codepipeline",
			WorkloadID:    pipelineARN + "/Build/Deploy",
			WorkloadType:  "codepipeline_action",
			WorkloadName:  "payments-release / Build / Deploy",
			RoleARN:       "arn:aws:iam::210987654321:role/payments-deploy-action",
			Source:        "getpipeline",
			EvidenceRef:   pipelineARN + "#stage/Build/action/Deploy",
			Confidence:    0.9,
			ScanID:        "scan-codepipeline",
			CollectorName: codePipelineDeploymentRoleCollectorName,
			CollectedAt:   collectedAt,
		},
		RoleName:         "payments-deploy-action",
		RoleAccountID:    "210987654321",
		RoleKind:         "action_role",
		PipelineARN:      pipelineARN,
		PipelineName:     "payments-release",
		StageName:        "Build",
		ActionName:       "Deploy",
		CrossAccountRole: true,
	}
	pipeline := CodePipelineDeploymentRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "codepipeline",
			WorkloadID:    pipelineARN,
			WorkloadType:  "codepipeline_pipeline",
			WorkloadName:  "payments-release",
			RoleARN:       "arn:aws:iam::123456789012:role/payments-codepipeline-service",
			Source:        "getpipeline",
			EvidenceRef:   pipelineARN,
			Confidence:    0.96,
			ScanID:        "scan-codepipeline",
			CollectorName: codePipelineDeploymentRoleCollectorName,
			CollectedAt:   collectedAt,
		},
		RoleName:     "payments-codepipeline-service",
		RoleKind:     "pipeline_service_role",
		PipelineARN:  pipelineARN,
		PipelineName: "payments-release",
	}
	actionPayload, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal action: %v", err)
	}
	pipelinePayload, err := json.Marshal(pipeline)
	if err != nil {
		t.Fatalf("marshal pipeline: %v", err)
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindCodePipelineDeploymentRole, SourceID: "action-first", Payload: actionPayload},
		{Kind: rawKindCodePipelineDeploymentRole, SourceID: "pipeline-second", Payload: pipelinePayload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Resources) != 1 {
		t.Fatalf("expected one CodePipeline resource, got %+v", bundle.Resources)
	}
	resource := bundle.Resources[0]
	if resource.Metadata["role_kind"] != "pipeline_service_role" || resource.Metadata["role_arn"] != pipeline.RoleARN {
		t.Fatalf("expected pipeline service role metadata to win, got %+v", resource.Metadata)
	}
	if resource.SourceEntityID != codePipelineRoleWorkloadID(pipeline) {
		t.Fatalf("expected resource source entity to point at pipeline workload, got %+v", resource)
	}
}

func TestCodePipelineDeploymentRoleCollectorPreservesAssetsWhenLaterPageFails(t *testing.T) {
	calls := 0
	api := codePipelineDeploymentRoleAPIFunc(func(_ context.Context, nextToken string, _ int32) (CodePipelineDeploymentRolePage, error) {
		calls++
		switch calls {
		case 1:
			return CodePipelineDeploymentRolePage{
				Records: []CodePipelineDeploymentRole{{
					ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
						WorkloadID:   "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
						WorkloadType: "codepipeline_pipeline",
						WorkloadName: "payments-release",
						RoleARN:      "arn:aws:iam::123456789012:role/payments-codepipeline-service",
						Source:       "getpipeline",
						EvidenceRef:  "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
					},
					RoleKind:     "pipeline_service_role",
					PipelineARN:  "arn:aws:codepipeline:us-east-1:123456789012:payments-release",
					PipelineName: "payments-release",
				}},
				NextToken: "page-2",
			}, nil
		case 2:
			if nextToken != "page-2" {
				t.Fatalf("expected second request with page-2 token, got %q", nextToken)
			}
			return CodePipelineDeploymentRolePage{}, errors.New("list failed")
		default:
			t.Fatalf("unexpected extra page request %d", calls)
			return CodePipelineDeploymentRolePage{}, nil
		}
	})
	collector := NewCodePipelineDeploymentRoleCollector(api)

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err == nil || !strings.Contains(err.Error(), "page 2") {
		t.Fatalf("expected page 2 failure, got %v", err)
	}
	if len(assets) != 1 || len(diagnostics) != 1 || diagnostics[0].Code != "codepipeline_deployment_role_page_failed" {
		t.Fatalf("expected preserved asset and page diagnostic, assets=%+v diagnostics=%+v", assets, diagnostics)
	}
}

func TestCodePipelineDeploymentRoleCollectorOptionsAndGuards(t *testing.T) {
	collector := NewCodePipelineDeploymentRoleCollector(
		codePipelineDeploymentRoleAPIFunc(func(context.Context, string, int32) (CodePipelineDeploymentRolePage, error) {
			return CodePipelineDeploymentRolePage{NextToken: "again"}, nil
		}),
		WithCodePipelineDeploymentRoleMaxPages(1),
		WithCodePipelineDeploymentRoleRetryPolicy(RetryPolicy{MaxRetries: 2, BaseDelay: time.Millisecond, MaxDelay: 3 * time.Millisecond}),
		WithCodePipelineDeploymentRoleRetryJitterRatio(-1),
	)
	if collector.backoff(2) != 3*time.Millisecond {
		t.Fatalf("expected capped no-jitter backoff, got %s", collector.backoff(2))
	}
	if _, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{}); err == nil || !strings.Contains(err.Error(), "exceeded max pages") {
		t.Fatalf("expected max pages guard, got %v", err)
	}
	if _, _, err := NewCodePipelineDeploymentRoleCollector(nil).CollectWithDiagnostics(context.Background(), AWSCollectorScope{}); err == nil || !strings.Contains(err.Error(), "requires client") {
		t.Fatalf("expected nil-client error, got %v", err)
	}
	if got := codePipelineNameFromARN("arn:aws:codepipeline:us-east-1:123456789012:payments-release"); got != "payments-release" {
		t.Fatalf("expected pipeline name from arn, got %q", got)
	}
}
