package aws

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/providers"
)

type fakeAWSServiceCollector struct {
	name           string
	assets         []providers.RawAsset
	diagnostics    []providers.SourceError
	err            error
	onCollect      func(scope AWSCollectorScope)
	calls          int
	capturedScopes []AWSCollectorScope
}

func (f *fakeAWSServiceCollector) ServiceName() string {
	return f.name
}

func (f *fakeAWSServiceCollector) CollectWithDiagnostics(_ context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	f.calls++
	f.capturedScopes = append(f.capturedScopes, scope)
	if f.onCollect != nil {
		f.onCollect(scope)
	}
	return append([]providers.RawAsset(nil), f.assets...), append([]providers.SourceError(nil), f.diagnostics...), f.err
}

func sortKeys(assets []providers.RawAsset) []string {
	keys := make([]string, 0, len(assets))
	for _, asset := range assets {
		keys = append(keys, asset.Kind+"|"+asset.SourceID)
	}
	sort.Strings(keys)
	return keys
}

func TestAWSCompositeCollectorSuccessWithIAMAndSecondServiceAndDeterministicOrdering(t *testing.T) {
	api := &fakeIAMClient{listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
		return ListRolesPage{Roles: []IAMRole{
			{ARN: "arn:aws:iam::123:role/one", Name: "one"},
			{ARN: "arn:aws:iam::123:role/shared", Name: "shared"},
		}}, nil
	}}

	secondService := &fakeAWSServiceCollector{
		name: "ecs",
		assets: []providers.RawAsset{
			{Kind: "aws_ecs_task", SourceID: "task/beta"},
			{Kind: "iam_role", SourceID: "arn:aws:iam::123:role/shared"},
			{Kind: "aws_ecs_cluster", SourceID: "cluster/alpha"},
		},
	}

	composite := NewAWSCompositeCollector(api, "123456789012", "us-east-1", secondService)
	firstRunAssets, _, err := composite.CollectWithDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("collect first run: %v", err)
	}
	secondRunAssets, _, err := composite.CollectWithDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("collect second run: %v", err)
	}

	expected := []string{
		"aws_ecs_cluster|cluster/alpha",
		"aws_ecs_task|task/beta",
		"iam_role|arn:aws:iam::123:role/one",
		"iam_role|arn:aws:iam::123:role/shared",
	}
	if got := sortKeys(firstRunAssets); strings.Join(got, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected first-run keys=%v", got)
	}
	if got := sortKeys(secondRunAssets); strings.Join(got, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected second-run keys=%v", got)
	}
}

func TestAWSCompositeCollectorNonFatalServiceFailureContinuesAndRecordsDiagnostic(t *testing.T) {
	api := &fakeIAMClient{listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
		return ListRolesPage{Roles: []IAMRole{{ARN: "arn:aws:iam::123:role/safe", Name: "safe"}}}, nil
	}}

	secondService := &fakeAWSServiceCollector{
		name: "ecs",
		err:  errors.New("temporary downstream failure"),
	}
	composite := NewAWSCompositeCollector(api, "123", "eu-west-1", secondService)
	assets, sourceErrors, err := composite.CollectWithDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("expected non-fatal service error to be ignored, got %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one IAM asset to remain, got %d", len(assets))
	}
	if assets[0].SourceID != "arn:aws:iam::123:role/safe" {
		t.Fatalf("unexpected asset source id %q", assets[0].SourceID)
	}
	if len(sourceErrors) != 1 {
		t.Fatalf("expected one synthetic failure diagnostic, got %d", len(sourceErrors))
	}
	if sourceErrors[0].Code != "service_collection_failed" {
		t.Fatalf("unexpected diagnostic code %q", sourceErrors[0].Code)
	}
	if sourceErrors[0].Collector != "aws_ecs" {
		t.Fatalf("unexpected diagnostic collector %q", sourceErrors[0].Collector)
	}
	if sourceErrors[0].SourceID != "service=ecs|account=123|region=eu-west-1|source=source" {
		t.Fatalf("unexpected diagnostic source id %q", sourceErrors[0].SourceID)
	}
	if sourceErrors[0].Retryable != true {
		t.Fatalf("expected retryable diagnostic for service failure")
	}
	if sourceErrors[0].Message == "" || sourceErrors[0].Message != "temporary downstream failure [service=ecs account=123 region=eu-west-1]" {
		t.Fatalf("unexpected diagnostic message %q", sourceErrors[0].Message)
	}
}

func TestAWSCompositeCollectorAllServicesFailingReturnsError(t *testing.T) {
	api := &fakeIAMClient{listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
		return ListRolesPage{}, errors.New("iam access denied")
	}}

	secondService := &fakeAWSServiceCollector{
		name: "ecs",
		err:  errors.New("temporary downstream failure"),
	}
	composite := NewAWSCompositeCollector(api, "123", "eu-west-1", secondService)
	assets, sourceErrors, err := composite.CollectWithDiagnostics(context.Background())
	if err == nil {
		t.Fatalf("expected error when every service collector fails")
	}
	if !strings.Contains(err.Error(), "all aws service collectors failed") {
		t.Fatalf("unexpected aggregate error message %q", err.Error())
	}
	if !strings.Contains(err.Error(), "iam access denied") || !strings.Contains(err.Error(), "temporary downstream failure") {
		t.Fatalf("expected aggregate error to wrap underlying service errors, got %q", err.Error())
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets on total failure, got %d", len(assets))
	}
	if len(sourceErrors) == 0 {
		t.Fatalf("expected diagnostics to be surfaced alongside the total-failure error")
	}
}

func TestAWSCompositeCollectorIAMOnlyFailureReturnsError(t *testing.T) {
	api := &fakeIAMClient{listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
		return ListRolesPage{}, errors.New("iam throttled")
	}}

	composite := NewAWSCompositeCollector(api, "123", "eu-west-1")
	assets, _, err := composite.CollectWithDiagnostics(context.Background())
	if err == nil {
		t.Fatalf("expected IAM-only collection failure to fail the scan")
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets when the only wired service fails, got %d", len(assets))
	}
}

func TestAWSCompositeCollectorPassesAccountAndRegionScopeToServices(t *testing.T) {
	api := &fakeIAMClient{listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
		return ListRolesPage{Roles: []IAMRole{{ARN: "arn:aws:iam::123:role/safe", Name: "safe"}}}, nil
	}}

	captured := AWSCollectorScope{}
	secondService := &fakeAWSServiceCollector{
		name: "ec2",
		onCollect: func(scope AWSCollectorScope) {
			captured = scope
		},
	}
	composite := NewAWSCompositeCollector(api, "account-abc", "us-west-2", secondService)
	_, _, err := composite.CollectWithDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if captured.AccountID != "account-abc" || captured.Region != "us-west-2" {
		t.Fatalf("unexpected forwarded scope: %+v", captured)
	}
	if captured.Service != "ec2" {
		t.Fatalf("unexpected service context: %s", captured.Service)
	}
}

func TestAWSCompositeCollectorContextCancellationStopsImmediately(t *testing.T) {
	api := &fakeIAMClient{listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
		return ListRolesPage{Roles: []IAMRole{{ARN: "arn:aws:iam::123:role/safe", Name: "safe"}}}, nil
	}}

	cancelService := &fakeAWSServiceCollector{
		name: "ec2",
		err:  context.Canceled,
		onCollect: func(_ AWSCollectorScope) {
		},
	}
	rabbitService := &fakeAWSServiceCollector{name: "lambda"}
	composite := NewAWSCompositeCollector(api, "", "", cancelService, rabbitService)
	assets, sourceErrors, err := composite.CollectWithDiagnostics(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if len(assets) != 0 || len(sourceErrors) != 0 {
		t.Fatalf("expected no returned assets/diagnostics on canceled hard-failure, got %d assets and %d diagnostics", len(assets), len(sourceErrors))
	}
	if cancelService.calls != 1 {
		t.Fatalf("expected canceling service to run once, got %d", cancelService.calls)
	}
	if rabbitService.calls != 0 {
		t.Fatalf("expected cancellation to short-circuit remaining services, rabbit calls=%d", rabbitService.calls)
	}
}
