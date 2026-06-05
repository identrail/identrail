package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeLambdaExecutionRoleAPI struct {
	pages []LambdaExecutionRolePage
	calls int
}

type lambdaExecutionRoleAPIFunc func(ctx context.Context, nextToken string, pageSize int32) (LambdaExecutionRolePage, error)

func (f lambdaExecutionRoleAPIFunc) ListExecutionRoles(ctx context.Context, nextToken string, pageSize int32) (LambdaExecutionRolePage, error) {
	return f(ctx, nextToken, pageSize)
}

func (f *fakeLambdaExecutionRoleAPI) ListExecutionRoles(_ context.Context, nextToken string, pageSize int32) (LambdaExecutionRolePage, error) {
	f.calls++
	if pageSize != 2 {
		return LambdaExecutionRolePage{}, fakeRetryableError{message: "unexpected page size"}
	}
	switch f.calls {
	case 1:
		if nextToken != "" {
			return LambdaExecutionRolePage{}, fakeRetryableError{message: "unexpected first token"}
		}
	case 2:
		if nextToken != "page-2" {
			return LambdaExecutionRolePage{}, fakeRetryableError{message: "unexpected second token"}
		}
	}
	if f.calls > len(f.pages) {
		return LambdaExecutionRolePage{}, nil
	}
	return f.pages[f.calls-1], nil
}

func TestLambdaExecutionRoleCollectorEmitsContractRecordsAndDiagnostics(t *testing.T) {
	fixedNow := time.Date(2026, 6, 5, 19, 0, 0, 0, time.UTC)
	api := &fakeLambdaExecutionRoleAPI{
		pages: []LambdaExecutionRolePage{
			{
				Records: []LambdaExecutionRole{
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
							WorkloadType: "lambda_function",
							WorkloadName: "payments-worker",
							RoleARN:      "arn:aws:iam::123456789012:role/payments-lambda-execution",
							Source:       "listfunctions",
							EvidenceRef:  "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
						},
						RoleName:                   "payments-lambda-execution",
						FunctionARN:                "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
						FunctionName:               "payments-worker",
						FunctionVersion:            "$LATEST",
						Runtime:                    "nodejs20.x",
						PackageType:                "Zip",
						Handler:                    "index.handler",
						KMSKeyARN:                  "arn:aws:kms:us-east-1:123456789012:key/lambda-env",
						EventSourceARNs:            []string{"arn:aws:sqs:us-east-1:123456789012:payments"},
						EventSourceMappingUUIDs:    []string{"mapping-1"},
						DisabledEventSourceARNs:    []string{"arn:aws:dynamodb:us-east-1:123456789012:table/legacy/stream/2026"},
						DisabledEventSourceReasons: []string{"mapping-2=Disabled by operator"},
						EnvironmentKeys:            []string{"APP_ENV", "DATABASE_PASSWORD"},
						SecretRefs:                 []string{"BASIC_AUTH=arn:aws:secretsmanager:us-east-1:123456789012:secret:lambda/kafka"},
						Tags:                       map[string]string{"owner": "payments"},
					},
				},
				Diagnostics: []providers.SourceError{{
					Collector: lambdaExecutionRoleCollectorName,
					SourceID:  "mapping-2",
					Code:      "disabled_event_source",
					Message:   "Lambda event source mapping is disabled",
					Retryable: false,
				}},
				NextToken: "page-2",
			},
			{
				Records: []LambdaExecutionRole{
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "arn:aws:lambda:us-east-1:123456789012:function:missing-role",
							WorkloadType: "lambda_function",
							WorkloadName: "missing-role",
							Source:       "listfunctions",
							EvidenceRef:  "arn:aws:lambda:us-east-1:123456789012:function:missing-role",
						},
						FunctionARN:  "arn:aws:lambda:us-east-1:123456789012:function:missing-role",
						FunctionName: "missing-role",
					},
				},
			},
		},
	}
	collector := NewLambdaExecutionRoleCollector(api, WithLambdaExecutionRolePageSize(2), WithLambdaExecutionRoleClock(func() time.Time {
		return fixedNow
	}))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-lambda",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one valid raw asset, got %d", len(assets))
	}
	if len(diagnostics) != 2 || diagnostics[0].Code != "disabled_event_source" || diagnostics[1].Code != "missing_lambda_execution_role" {
		t.Fatalf("expected disabled source and missing role diagnostics, got %+v", diagnostics)
	}

	var payload LambdaExecutionRole
	if err := json.Unmarshal(assets[0].Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.CollectedAt != fixedNow {
		t.Fatalf("expected collected_at %s, got %s", fixedNow, payload.CollectedAt)
	}
	if payload.Service != "lambda" || payload.CollectorName != lambdaExecutionRoleCollectorName || payload.FunctionName != "payments-worker" {
		t.Fatalf("expected normalized Lambda metadata, got %+v", payload)
	}
	if strings.Contains(fmt.Sprint(payload.EnvironmentKeys), "must-not-appear") {
		t.Fatalf("environment values must not be collected, got %+v", payload.EnvironmentKeys)
	}
	if _, err := awscontract.NormalizeServiceCollectorRecord(payload.ServiceCollectorRecord); err != nil {
		t.Fatalf("expected payload to satisfy service collector contract: %v", err)
	}
}

func TestRoleNormalizerAddsLambdaExecutionRoleRunAsEdge(t *testing.T) {
	record := LambdaExecutionRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "lambda",
			WorkloadID:    "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
			WorkloadType:  "lambda_function",
			WorkloadName:  "payments-worker",
			RoleARN:       "arn:aws:iam::123456789012:role/payments-lambda-execution",
			Source:        "listfunctions",
			EvidenceRef:   "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
			Confidence:    0.96,
			ScanID:        "scan-lambda",
			CollectorName: lambdaExecutionRoleCollectorName,
			CollectedAt:   time.Date(2026, 6, 5, 19, 0, 0, 0, time.UTC),
		},
		RoleName:                "payments-lambda-execution",
		FunctionARN:             "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
		FunctionName:            "payments-worker",
		FunctionVersion:         "$LATEST",
		Runtime:                 "nodejs20.x",
		PackageType:             "Zip",
		Handler:                 "index.handler",
		EventSourceARNs:         []string{"arn:aws:sqs:us-east-1:123456789012:payments"},
		EnvironmentKeys:         []string{"APP_ENV", "DATABASE_PASSWORD"},
		DisabledEventSourceARNs: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/legacy/stream/2026"},
		SecretRefs:              []string{"BASIC_AUTH=arn:aws:secretsmanager:us-east-1:123456789012:secret:lambda/kafka"},
		Tags:                    map[string]string{"owner": "payments"},
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindLambdaExecutionRole, SourceID: "lambda-role", Payload: payload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("normalized bundle invalid: %v", err)
	}
	if len(bundle.Identities) != 1 || len(bundle.Workloads) != 1 || len(bundle.Resources) != 1 {
		t.Fatalf("expected lambda identity/workload/resource, got identities=%+v workloads=%+v resources=%+v", bundle.Identities, bundle.Workloads, bundle.Resources)
	}
	if bundle.Resources[0].Type != domain.ResourceTypeLambdaFunction {
		t.Fatalf("expected lambda function resource, got %+v", bundle.Resources[0])
	}
	if strings.Contains(fmtAny(bundle.Resources[0].Metadata["environment_keys"]), "DATABASE_PASSWORD=value") {
		t.Fatalf("environment values must not be normalized, got %+v", bundle.Resources[0].Metadata)
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("graph contract invalid: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipRunsAs) {
		t.Fatalf("expected lambda execution role runs_as edge, got %+v", relationships)
	}
}

func TestLambdaExecutionRoleCollectorRetriesThenCollects(t *testing.T) {
	attempt := 0
	delays := []time.Duration{}
	api := lambdaExecutionRoleAPIFunc(func(_ context.Context, nextToken string, pageSize int32) (LambdaExecutionRolePage, error) {
		attempt++
		if nextToken != "" {
			t.Fatalf("expected single collector-facing page, got next token %q", nextToken)
		}
		if pageSize != 5 {
			t.Fatalf("expected configured page size 5, got %d", pageSize)
		}
		if attempt <= 2 {
			return LambdaExecutionRolePage{}, fakeRetryableError{message: "ThrottlingException"}
		}
		return LambdaExecutionRolePage{Records: []LambdaExecutionRole{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				WorkloadID:   "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
				WorkloadType: "lambda_function",
				WorkloadName: "payments-worker",
				RoleARN:      "arn:aws:iam::123456789012:role/payments-lambda-execution",
				Source:       "listfunctions",
				EvidenceRef:  "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
			},
			FunctionARN:  "arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
			FunctionName: "payments-worker",
		}}}, nil
	})

	collector := NewLambdaExecutionRoleCollector(
		api,
		WithLambdaExecutionRolePageSize(5),
		WithLambdaExecutionRoleRetryPolicy(RetryPolicy{MaxRetries: 3, BaseDelay: 100 * time.Millisecond, MaxDelay: 500 * time.Millisecond}),
		WithLambdaExecutionRoleRetryJitterRatio(0.25),
		WithLambdaExecutionRoleRetryRandFunc(func() float64 { return 1 }),
		WithLambdaExecutionRoleSleeper(func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		}),
	)

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed after retry: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one asset after retry, got %d", len(assets))
	}
	if attempt != 3 {
		t.Fatalf("expected three attempts, got %d", attempt)
	}
	if len(delays) != 2 || delays[0] != 125*time.Millisecond || delays[1] != 250*time.Millisecond {
		t.Fatalf("unexpected jittered retry delays: %+v", delays)
	}
}

func TestLambdaExecutionRoleCollectorOptionsAndGuards(t *testing.T) {
	collector := NewLambdaExecutionRoleCollector(
		lambdaExecutionRoleAPIFunc(func(context.Context, string, int32) (LambdaExecutionRolePage, error) {
			return LambdaExecutionRolePage{NextToken: "again"}, nil
		}),
		WithLambdaExecutionRoleMaxPages(1),
		WithLambdaExecutionRoleRetryPolicy(RetryPolicy{MaxRetries: 2, BaseDelay: time.Millisecond, MaxDelay: 3 * time.Millisecond}),
		WithLambdaExecutionRoleRetryJitterRatio(-1),
	)
	if collector.maxPages != 1 || collector.retry.MaxRetries != 2 {
		t.Fatalf("expected option values to be applied, got maxPages=%d retry=%+v", collector.maxPages, collector.retry)
	}
	if got := collector.backoff(4); got != 3*time.Millisecond {
		t.Fatalf("expected capped, non-jittered backoff, got %s", got)
	}
	collector.addIssue(providers.SourceError{})
	collector.addIssue(providers.SourceError{Code: "missing_lambda_execution_role", Message: "missing role"})
	if len(collector.issues) != 1 {
		t.Fatalf("expected only valid issue to be retained, got %+v", collector.issues)
	}

	_, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err == nil || !strings.Contains(err.Error(), "exceeded max pages") {
		t.Fatalf("expected max pages guard error, got %v", err)
	}
}

func TestLambdaFunctionNameFromARNFallbacks(t *testing.T) {
	if got := lambdaFunctionNameFromARN("arn:aws:lambda:us-east-1:123456789012:function:payments-worker:prod"); got != "payments-worker" {
		t.Fatalf("expected function name without qualifier, got %q", got)
	}
	if got := lambdaFunctionNameFromARN("arn:aws:iam::123456789012:role/fallback-role"); got != "fallback-role" {
		t.Fatalf("expected role-name fallback, got %q", got)
	}
	if got := lambdaFunctionNameFromARN(" "); got != "" {
		t.Fatalf("expected blank fallback, got %q", got)
	}
}
