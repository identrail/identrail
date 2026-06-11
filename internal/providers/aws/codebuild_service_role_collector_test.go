package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeCodeBuildServiceRoleAPI struct {
	pages []CodeBuildServiceRolePage
	calls int
}

type codeBuildServiceRoleAPIFunc func(ctx context.Context, nextToken string, pageSize int32) (CodeBuildServiceRolePage, error)

func (f codeBuildServiceRoleAPIFunc) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (CodeBuildServiceRolePage, error) {
	return f(ctx, nextToken, pageSize)
}

func (f *fakeCodeBuildServiceRoleAPI) ListServiceRoles(_ context.Context, nextToken string, pageSize int32) (CodeBuildServiceRolePage, error) {
	f.calls++
	if pageSize != 2 {
		return CodeBuildServiceRolePage{}, fakeRetryableError{message: "unexpected page size"}
	}
	switch f.calls {
	case 1:
		if nextToken != "" {
			return CodeBuildServiceRolePage{}, fakeRetryableError{message: "unexpected first token"}
		}
	case 2:
		if nextToken != "page-2" {
			return CodeBuildServiceRolePage{}, fakeRetryableError{message: "unexpected second token"}
		}
	}
	if f.calls > len(f.pages) {
		return CodeBuildServiceRolePage{}, nil
	}
	return f.pages[f.calls-1], nil
}

func TestCodeBuildServiceRoleCollectorEmitsContractRecordsAndDiagnostics(t *testing.T) {
	fixedNow := time.Date(2026, 6, 6, 8, 0, 0, 0, time.UTC)
	api := &fakeCodeBuildServiceRoleAPI{
		pages: []CodeBuildServiceRolePage{
			{
				Records: []CodeBuildServiceRole{
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
							WorkloadType: "codebuild_project",
							WorkloadName: "payments-build",
							RoleARN:      "arn:aws:iam::123456789012:role/payments-codebuild-service",
							Source:       "batchgetprojects",
							EvidenceRef:  "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
						},
						RoleName:        "payments-codebuild-service",
						ProjectARN:      "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
						ProjectName:     "payments-build",
						SourceType:      "GITHUB",
						EnvironmentType: "LINUX_CONTAINER",
						ComputeType:     "BUILD_GENERAL1_SMALL",
						Image:           "aws/codebuild/standard:7.0",
						EnvironmentKeys: []string{"APP_ENV", "DATABASE_PASSWORD"},
						SecretRefs:      []string{"DATABASE_PASSWORD=SECRETS_MANAGER:arn:aws:secretsmanager:us-east-1:123456789012:secret:db"},
						Tags:            map[string]string{"owner": "payments"},
					},
				},
				Diagnostics: []providers.SourceError{{
					Collector: codeBuildServiceRoleCollectorName,
					SourceID:  "missing-project",
					Code:      "project_not_found",
					Message:   "project disappeared",
					Retryable: true,
				}},
				NextToken: "page-2",
			},
			{
				Records: []CodeBuildServiceRole{
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "arn:aws:codebuild:us-east-1:123456789012:project/missing-role",
							WorkloadType: "codebuild_project",
							WorkloadName: "missing-role",
							Source:       "batchgetprojects",
							EvidenceRef:  "arn:aws:codebuild:us-east-1:123456789012:project/missing-role",
						},
						ProjectARN:  "arn:aws:codebuild:us-east-1:123456789012:project/missing-role",
						ProjectName: "missing-role",
					},
				},
			},
		},
	}
	collector := NewCodeBuildServiceRoleCollector(api, WithCodeBuildServiceRolePageSize(2), WithCodeBuildServiceRoleClock(func() time.Time {
		return fixedNow
	}))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-codebuild",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one valid raw asset, got %d", len(assets))
	}
	if len(diagnostics) != 2 || diagnostics[0].Code != "project_not_found" || diagnostics[1].Code != "missing_codebuild_service_role" {
		t.Fatalf("expected not-found and missing role diagnostics, got %+v", diagnostics)
	}

	var payload CodeBuildServiceRole
	if err := json.Unmarshal(assets[0].Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Service != "codebuild" || payload.CollectorName != codeBuildServiceRoleCollectorName || payload.ProjectName != "payments-build" {
		t.Fatalf("expected normalized CodeBuild metadata, got %+v", payload)
	}
	if strings.Contains(fmt.Sprint(payload.EnvironmentKeys), "must-not-appear") {
		t.Fatalf("environment values must not be collected, got %+v", payload.EnvironmentKeys)
	}
	if _, err := awscontract.NormalizeServiceCollectorRecord(payload.ServiceCollectorRecord); err != nil {
		t.Fatalf("expected payload to satisfy service collector contract: %v", err)
	}
}

func TestRoleNormalizerAddsCodeBuildServiceRoleRunAsEdge(t *testing.T) {
	record := CodeBuildServiceRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "codebuild",
			WorkloadID:    "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
			WorkloadType:  "codebuild_project",
			WorkloadName:  "payments-build",
			RoleARN:       "arn:aws:iam::123456789012:role/payments-codebuild-service",
			Source:        "batchgetprojects",
			EvidenceRef:   "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
			Confidence:    0.94,
			ScanID:        "scan-codebuild",
			CollectorName: codeBuildServiceRoleCollectorName,
			CollectedAt:   time.Date(2026, 6, 6, 8, 0, 0, 0, time.UTC),
		},
		RoleName:        "payments-codebuild-service",
		ProjectARN:      "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
		ProjectName:     "payments-build",
		SourceType:      "GITHUB",
		EnvironmentType: "LINUX_CONTAINER",
		ComputeType:     "BUILD_GENERAL1_SMALL",
		Image:           "aws/codebuild/standard:7.0",
		EnvironmentKeys: []string{"APP_ENV", "DATABASE_PASSWORD"},
		SecretRefs:      []string{"DATABASE_PASSWORD=SECRETS_MANAGER:arn:aws:secretsmanager:us-east-1:123456789012:secret:db"},
		Tags:            map[string]string{"owner": "payments"},
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindCodeBuildServiceRole, SourceID: "codebuild-role", Payload: payload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("normalized bundle invalid: %v", err)
	}
	codeBuildResources := resourcesByType(bundle.Resources, domain.ResourceTypeCodeBuildProject)
	if len(bundle.Identities) != 1 || len(bundle.Workloads) != 1 || len(codeBuildResources) != 1 {
		t.Fatalf("expected codebuild identity/workload/resource, got identities=%+v workloads=%+v resources=%+v", bundle.Identities, bundle.Workloads, bundle.Resources)
	}
	if strings.Contains(fmtAny(codeBuildResources[0].Metadata["environment_keys"]), "DATABASE_PASSWORD=value") {
		t.Fatalf("environment values must not be normalized, got %+v", codeBuildResources[0].Metadata)
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("graph contract invalid: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipRunsAs) {
		t.Fatalf("expected codebuild service role runs_as edge, got %+v", relationships)
	}
}

func TestCodeBuildServiceRoleCollectorRetriesThenCollects(t *testing.T) {
	attempt := 0
	delays := []time.Duration{}
	api := codeBuildServiceRoleAPIFunc(func(_ context.Context, nextToken string, pageSize int32) (CodeBuildServiceRolePage, error) {
		attempt++
		if nextToken != "" {
			t.Fatalf("expected single collector-facing page, got next token %q", nextToken)
		}
		if pageSize != 5 {
			t.Fatalf("expected page size 5, got %d", pageSize)
		}
		if attempt == 1 {
			return CodeBuildServiceRolePage{}, fakeRetryableError{message: "ThrottlingException"}
		}
		return CodeBuildServiceRolePage{Records: []CodeBuildServiceRole{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				WorkloadID:   "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
				WorkloadType: "codebuild_project",
				WorkloadName: "payments-build",
				RoleARN:      "arn:aws:iam::123456789012:role/payments-codebuild-service",
				Source:       "batchgetprojects",
				EvidenceRef:  "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
			},
			ProjectARN:  "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
			ProjectName: "payments-build",
		}}}, nil
	})

	collector := NewCodeBuildServiceRoleCollector(
		api,
		WithCodeBuildServiceRolePageSize(5),
		WithCodeBuildServiceRoleRetryPolicy(RetryPolicy{MaxRetries: 3, BaseDelay: 100 * time.Millisecond, MaxDelay: 500 * time.Millisecond}),
		WithCodeBuildServiceRoleRetryJitterRatio(0.25),
		WithCodeBuildServiceRoleRetryRandFunc(func() float64 { return 1 }),
		WithCodeBuildServiceRoleSleeper(func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		}),
	)

	assets, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("collect after retry: %v", err)
	}
	if len(assets) != 1 || attempt != 2 || len(delays) != 1 {
		t.Fatalf("expected retry then one asset, attempts=%d delays=%+v assets=%+v", attempt, delays, assets)
	}
	if delays[0] <= 100*time.Millisecond || delays[0] > 125*time.Millisecond {
		t.Fatalf("expected bounded jittered delay, got %s", delays[0])
	}
}

func TestCodeBuildServiceRoleCollectorPreservesAssetsWhenLaterPageFails(t *testing.T) {
	calls := 0
	api := codeBuildServiceRoleAPIFunc(func(_ context.Context, nextToken string, pageSize int32) (CodeBuildServiceRolePage, error) {
		calls++
		if pageSize != 2 {
			t.Fatalf("expected page size 2, got %d", pageSize)
		}
		switch calls {
		case 1:
			if nextToken != "" {
				t.Fatalf("expected first request without token, got %q", nextToken)
			}
			return CodeBuildServiceRolePage{
				Records: []CodeBuildServiceRole{{
					ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
						WorkloadID:   "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
						WorkloadType: "codebuild_project",
						WorkloadName: "payments-build",
						RoleARN:      "arn:aws:iam::123456789012:role/payments-codebuild-service",
						Source:       "batchgetprojects",
						EvidenceRef:  "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
					},
					RoleName:    "payments-codebuild-service",
					ProjectARN:  "arn:aws:codebuild:us-east-1:123456789012:project/payments-build",
					ProjectName: "payments-build",
				}},
				NextToken: "page-2",
			}, nil
		case 2:
			if nextToken != "page-2" {
				t.Fatalf("expected second request with page-2 token, got %q", nextToken)
			}
			return CodeBuildServiceRolePage{}, errors.New("batch failed")
		default:
			t.Fatalf("unexpected extra page request %d", calls)
			return CodeBuildServiceRolePage{}, nil
		}
	})
	collector := NewCodeBuildServiceRoleCollector(api, WithCodeBuildServiceRolePageSize(2))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		AccountID: "123456789012",
		Region:    "us-east-1",
	})
	if err == nil || !strings.Contains(err.Error(), "list codebuild service roles page 2") {
		t.Fatalf("expected page 2 failure, got %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected earlier page asset to be preserved, got %d assets: %+v", len(assets), assets)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("expected one page-failure diagnostic, got %+v", diagnostics)
	}
	if diagnostics[0].Code != "codebuild_service_role_page_failed" || diagnostics[0].SourceID != "page-2" {
		t.Fatalf("expected page-failure diagnostic for page-2, got %+v", diagnostics[0])
	}

	var payload CodeBuildServiceRole
	if err := json.Unmarshal(assets[0].Payload, &payload); err != nil {
		t.Fatalf("decode preserved payload: %v", err)
	}
	if payload.ProjectName != "payments-build" || payload.RoleARN != "arn:aws:iam::123456789012:role/payments-codebuild-service" {
		t.Fatalf("expected first-page project evidence, got %+v", payload)
	}
}

func TestCodeBuildServiceRoleCollectorOptionsAndGuards(t *testing.T) {
	collector := NewCodeBuildServiceRoleCollector(
		codeBuildServiceRoleAPIFunc(func(context.Context, string, int32) (CodeBuildServiceRolePage, error) {
			return CodeBuildServiceRolePage{NextToken: "again"}, nil
		}),
		WithCodeBuildServiceRoleMaxPages(1),
		WithCodeBuildServiceRoleRetryPolicy(RetryPolicy{MaxRetries: 2, BaseDelay: time.Millisecond, MaxDelay: 3 * time.Millisecond}),
		WithCodeBuildServiceRoleRetryJitterRatio(-1),
	)
	if collector.backoff(2) != 3*time.Millisecond {
		t.Fatalf("expected capped no-jitter backoff, got %s", collector.backoff(2))
	}
	if _, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{}); err == nil || !strings.Contains(err.Error(), "exceeded max pages") {
		t.Fatalf("expected max pages guard, got %v", err)
	}
	if _, _, err := NewCodeBuildServiceRoleCollector(nil).CollectWithDiagnostics(context.Background(), AWSCollectorScope{}); err == nil || !strings.Contains(err.Error(), "requires client") {
		t.Fatalf("expected nil-client error, got %v", err)
	}
	if got := codeBuildProjectNameFromARN("arn:aws:codebuild:us-east-1:123456789012:project/payments-build"); got != "payments-build" {
		t.Fatalf("expected project name from arn, got %q", got)
	}
}
