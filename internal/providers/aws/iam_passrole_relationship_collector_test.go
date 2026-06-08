package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/providers"
)

type fakeIAMRolesAPI struct {
	pages []ListRolesPage
	calls int
	err   error
}

func (f *fakeIAMRolesAPI) ListRoles(ctx context.Context, nextToken string, pageSize int32) (ListRolesPage, error) {
	f.calls++
	if f.err != nil {
		return ListRolesPage{}, f.err
	}
	if len(f.pages) == 0 {
		return ListRolesPage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestExtractPassRoleGrants_ExpandsResourcesAndConditions(t *testing.T) {
	doc, err := parsePassRolePolicyDocument(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "PassLambda",
				"Effect": "Allow",
				"Action": ["iam:PassRole"],
				"Resource": [
					"arn:aws:iam::123456789012:role/payments-lambda",
					"arn:aws:iam::123456789012:role/payments-ecs-*"
				],
				"Condition": {
					"StringEquals": {
						"iam:PassedToService": ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]
					}
				}
			},
			{
				"Sid": "WildcardEverywhere",
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*"
			},
			{
				"Sid": "BreakGlassDeny",
				"Effect": "Deny",
				"Action": "iam:PassRole",
				"Resource": "arn:aws:iam::123456789012:role/break-glass"
			}
		]
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	grants := extractPassRoleGrants(doc)
	if len(grants) != 6 {
		// PassLambda: 2 resources × 2 service conditions = 4; WildcardEverywhere: 1; BreakGlassDeny: 1.
		t.Fatalf("expected 6 grants (2x2 + 1 + 1), got %d: %+v", len(grants), grants)
	}
	hasLambda := false
	hasDeny := false
	hasStarStar := false
	for _, grant := range grants {
		if grant.TargetResource == "arn:aws:iam::123456789012:role/payments-lambda" && grant.ServiceCondition == "lambda.amazonaws.com" {
			hasLambda = true
		}
		if grant.Effect == "Deny" && strings.Contains(grant.TargetResource, "break-glass") {
			hasDeny = true
		}
		if grant.TargetResource == "*" && grant.ActionExpression == "*" {
			hasStarStar = true
		}
	}
	if !hasLambda || !hasDeny || !hasStarStar {
		t.Fatalf("expected lambda/deny/star grants, got %+v", grants)
	}
}

func TestExtractPassRoleGrants_NotActionAndNotResource(t *testing.T) {
	doc, err := parsePassRolePolicyDocument(`{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"NotAction": "iam:PassRole",
			"NotResource": "arn:aws:iam::123456789012:role/break-glass"
		}
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	grants := extractPassRoleGrants(doc)
	if len(grants) != 1 {
		t.Fatalf("expected one grant, got %d", len(grants))
	}
	if !grants[0].NotAction || !grants[0].NotResource {
		t.Fatalf("expected NotAction + NotResource flags, got %+v", grants[0])
	}
}

func TestPassRoleGrantWildcardKindAndConfidence(t *testing.T) {
	cases := []struct {
		target           string
		wantKind         string
		wantConfidenceGE float64
	}{
		{"arn:aws:iam::123456789012:role/payments", "specific", 0.9},
		{"arn:aws:iam::123456789012:role/payments-*", "path_wildcard", 0.7},
		{"arn:aws:iam::*:role/payments", "account_wildcard", 0.7},
		{"*", "all", 0.4},
	}
	for _, tc := range cases {
		if got := passRoleGrantWildcardKind(tc.target); got != tc.wantKind {
			t.Fatalf("kind for %q: got %q, want %q", tc.target, got, tc.wantKind)
		}
		conf := passRoleGrantConfidence(passRoleGrant{TargetResource: tc.target})
		if conf < tc.wantConfidenceGE {
			t.Fatalf("confidence for %q: got %v, want >= %v", tc.target, conf, tc.wantConfidenceGE)
		}
	}
}

func TestIAMPassRoleCollectorEmitsNormalizedAssets(t *testing.T) {
	collectedAt := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/platform-deploy"
	api := &fakeIAMRolesAPI{pages: []ListRolesPage{{
		Roles: []IAMRole{{
			ARN:  roleARN,
			Name: "platform-deploy",
			Path: "/",
			PermissionPolicies: []IAMPermissionPolicy{{
				Name: "platform-deploy-passrole",
				Document: `{
					"Version": "2012-10-17",
					"Statement": [{
						"Sid": "PassLambda",
						"Effect": "Allow",
						"Action": "iam:PassRole",
						"Resource": "arn:aws:iam::123456789012:role/payments-lambda",
						"Condition": {
							"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
						}
					}]
				}`,
			}},
		}},
	}}}
	collector := NewIAMPassRoleRelationshipCollector(api, WithIAMPassRoleRelationshipClock(func() time.Time { return collectedAt }))
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID: "tenant-a", WorkspaceID: "workspace-a", ProjectID: "project-a", ConnectorID: "aws-prod", ScanID: "scan-1", AccountID: "123456789012", Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d", len(assets))
	}
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %+v", diagnostics)
	}
	var record IAMPassRoleRelationship
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if record.SourceRoleARN != roleARN || record.PassedToService != "lambda.amazonaws.com" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record.TargetWildcardKind != "specific" || record.Confidence < 0.9 {
		t.Fatalf("expected specific target with high confidence, got %+v", record)
	}
	if record.TenantID != "tenant-a" || record.WorkspaceID != "workspace-a" {
		t.Fatalf("expected scope inherited, got %+v", record)
	}
}

func TestIAMPassRoleCollectorSkipsRolesWithoutPassRole(t *testing.T) {
	collectedAt := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	api := &fakeIAMRolesAPI{pages: []ListRolesPage{{
		Roles: []IAMRole{{
			ARN:  "arn:aws:iam::123456789012:role/no-passrole",
			Name: "no-passrole",
			PermissionPolicies: []IAMPermissionPolicy{{
				Name:     "s3-only",
				Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			}},
		}},
	}}}
	collector := NewIAMPassRoleRelationshipCollector(api, WithIAMPassRoleRelationshipClock(func() time.Time { return collectedAt }))
	assets, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets for role without PassRole, got %d", len(assets))
	}
}

func TestIAMPassRoleCollectorRecordsParseFailures(t *testing.T) {
	collectedAt := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	api := &fakeIAMRolesAPI{pages: []ListRolesPage{{
		Roles: []IAMRole{{
			ARN:  "arn:aws:iam::123456789012:role/bad",
			Name: "bad",
			PermissionPolicies: []IAMPermissionPolicy{{
				Name:     "broken",
				Document: `{ not valid json`,
			}},
		}},
	}}}
	collector := NewIAMPassRoleRelationshipCollector(api, WithIAMPassRoleRelationshipClock(func() time.Time { return collectedAt }))
	_, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "iam_passrole_policy_parse_failed" {
		t.Fatalf("expected parse_failed diagnostic, got %+v", diagnostics)
	}
}

func TestIAMPassRoleCollectorPropagatesListError(t *testing.T) {
	api := &fakeIAMRolesAPI{err: errors.New("throttled")}
	collector := NewIAMPassRoleRelationshipCollector(api,
		WithIAMPassRoleRelationshipRetryPolicy(RetryPolicy{MaxRetries: 0, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}),
		WithIAMPassRoleRelationshipSleeper(func(ctx context.Context, d time.Duration) error { return nil }),
	)
	_, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err == nil {
		t.Fatalf("expected error from list pages")
	}
}

func TestIAMPassRoleCollectorRequiresClient(t *testing.T) {
	c := &IAMPassRoleRelationshipCollector{}
	if _, _, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{}); err == nil {
		t.Fatalf("expected error when client missing")
	}
}

func TestIAMPassRoleCollectorDedupesAcrossPages(t *testing.T) {
	collectedAt := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	role := IAMRole{
		ARN:  "arn:aws:iam::123456789012:role/dup",
		Name: "dup",
		PermissionPolicies: []IAMPermissionPolicy{{
			Name:     "passrole",
			Document: `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/target"}]}`,
		}},
	}
	api := &fakeIAMRolesAPI{pages: []ListRolesPage{
		{Roles: []IAMRole{role}, NextToken: "p2"},
		{Roles: []IAMRole{role}},
	}}
	collector := NewIAMPassRoleRelationshipCollector(api, WithIAMPassRoleRelationshipClock(func() time.Time { return collectedAt }))
	assets, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected dedupe, got %d assets", len(assets))
	}
}

func TestIAMPassRoleNormalizerRegistersSourceAndTargetIdentities(t *testing.T) {
	record := IAMPassRoleRelationship{
		SourceRoleARN:      "arn:aws:iam::123456789012:role/source",
		SourceRoleName:     "source",
		TargetResource:     "arn:aws:iam::123456789012:role/target",
		TargetWildcardKind: "specific",
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	asset := providers.RawAsset{Kind: rawKindIAMPassRoleRelationship, SourceID: "src", Payload: payload}
	bundle := providers.NormalizedBundle{}
	seen := map[string]struct{}{}
	if err := normalizeIAMPassRoleRelationshipAsset(asset, 0, &bundle, seen); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Identities) != 2 {
		t.Fatalf("expected source+target identities, got %d", len(bundle.Identities))
	}
}

func TestIAMPassRoleNormalizerSkipsWildcardTargets(t *testing.T) {
	record := IAMPassRoleRelationship{
		SourceRoleARN:      "arn:aws:iam::123456789012:role/source",
		TargetResource:     "*",
		TargetWildcardKind: "all",
		UnresolvedTarget:   true,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	asset := providers.RawAsset{Kind: rawKindIAMPassRoleRelationship, SourceID: "src", Payload: payload}
	bundle := providers.NormalizedBundle{}
	seen := map[string]struct{}{}
	if err := normalizeIAMPassRoleRelationshipAsset(asset, 0, &bundle, seen); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Identities) != 1 {
		t.Fatalf("expected only source identity for wildcard target, got %d", len(bundle.Identities))
	}
}

func TestIsIAMPassRoleRelationshipFixture_Strict(t *testing.T) {
	yes := IAMPassRoleRelationship{}
	yes.Service = "iam-passrole"
	if !isIAMPassRoleRelationshipFixture(yes) {
		t.Fatalf("expected match on service")
	}
	noService := IAMPassRoleRelationship{}
	noService.WorkloadType = "iam_passrole_relationship"
	if !isIAMPassRoleRelationshipFixture(noService) {
		t.Fatalf("expected match on workload type")
	}
	stranger := IAMPassRoleRelationship{}
	if isIAMPassRoleRelationshipFixture(stranger) {
		t.Fatalf("empty record must not match")
	}
}
