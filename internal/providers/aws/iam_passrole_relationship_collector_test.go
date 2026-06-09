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
	pages     []ListRolesPage
	calls     int
	err       error
	tokens    []string
	pageSizes []int32
}

func (f *fakeIAMRolesAPI) ListRoles(ctx context.Context, nextToken string, pageSize int32) (ListRolesPage, error) {
	f.calls++
	f.tokens = append(f.tokens, nextToken)
	f.pageSizes = append(f.pageSizes, pageSize)
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

func TestExtractPassRoleGrants_NotActionListingPassRoleSuppressesGrant(t *testing.T) {
	// NotAction containing iam:PassRole means PassRole is excluded — no grant
	// should be emitted.
	doc, err := parsePassRolePolicyDocument(`{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"NotAction": "iam:PassRole",
			"Resource": "*"
		}
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if grants := extractPassRoleGrants(doc); len(grants) != 0 {
		t.Fatalf("expected zero grants when NotAction lists iam:PassRole, got %+v", grants)
	}
}

func TestExtractPassRoleGrants_NotActionOmittingPassRoleEmitsInverseGrant(t *testing.T) {
	// NotAction containing only an unrelated action means PassRole IS in the
	// implicit "everything else" set the statement applies to. The grant is
	// emitted with NotAction=true so consumers can mark it as inverse.
	doc, err := parsePassRolePolicyDocument(`{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"NotAction": "s3:GetObject",
			"NotResource": "arn:aws:iam::123456789012:role/break-glass"
		}
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	grants := extractPassRoleGrants(doc)
	if len(grants) != 1 {
		t.Fatalf("expected one inverse grant, got %d (%+v)", len(grants), grants)
	}
	if !grants[0].NotAction || !grants[0].NotResource {
		t.Fatalf("expected NotAction + NotResource flags, got %+v", grants[0])
	}
}

func TestExtractPassRoleGrants_NotActionWildcardExcludesPassRole(t *testing.T) {
	// NotAction iam:Pass* also explicitly excludes iam:PassRole — no grant.
	doc, err := parsePassRolePolicyDocument(`{
		"Statement": {
			"Effect": "Allow",
			"NotAction": "iam:Pass*",
			"Resource": "*"
		}
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if grants := extractPassRoleGrants(doc); len(grants) != 0 {
		t.Fatalf("expected zero grants when NotAction wildcard matches iam:PassRole, got %+v", grants)
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

func TestExtractPassRoleGrants_WildcardActionPatternMatches(t *testing.T) {
	cases := map[string]bool{
		"iam:Pass*":      true,
		"iam:P*":         true,
		"iam:Pa?sRole":   true,
		"iam:pass*":      true, // case-insensitive
		"iam:Get*":       false,
		"iam:List*":      false,
		"sts:AssumeRole": false,
	}
	for action, want := range cases {
		doc, err := parsePassRolePolicyDocument(`{"Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"arn:aws:iam::123456789012:role/payments"}]}`)
		if err != nil {
			t.Fatalf("parse %q: %v", action, err)
		}
		grants := extractPassRoleGrants(doc)
		got := len(grants) == 1
		if got != want {
			t.Fatalf("action %q: got match=%v, want %v (grants=%+v)", action, got, want, grants)
		}
	}
}

func TestParsePassRolePolicyDocument_InvalidStatementShape(t *testing.T) {
	// A scalar string is neither a statement object nor an array — must error.
	_, err := parsePassRolePolicyDocument(`{"Statement": "not a statement"}`)
	if err == nil {
		t.Fatalf("expected parse error for invalid statement shape")
	}
}

func TestParsePassRolePolicyDocument_TolerantInputs(t *testing.T) {
	cases := []string{
		"",
		`{}`,
		`{"Statement": null}`,
		`{"Statement": []}`,
	}
	for _, raw := range cases {
		if _, err := parsePassRolePolicyDocument(raw); err != nil {
			t.Fatalf("input %q: unexpected error %v", raw, err)
		}
	}
}

func TestIAMPassRoleCollectorRecordsBadStatementShape(t *testing.T) {
	api := &fakeIAMRolesAPI{pages: []ListRolesPage{{
		Roles: []IAMRole{{
			ARN:  "arn:aws:iam::123456789012:role/bad-statement",
			Name: "bad-statement",
			PermissionPolicies: []IAMPermissionPolicy{{
				Name:     "broken",
				Document: `{"Statement": "not a statement"}`,
			}},
		}},
	}}}
	collector := NewIAMPassRoleRelationshipCollector(api)
	_, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "iam_passrole_policy_parse_failed" {
		t.Fatalf("expected parse_failed diagnostic for bad statement shape, got %+v", diagnostics)
	}
}

func TestIAMActionPatternMatches(t *testing.T) {
	cases := []struct {
		pattern string
		target  string
		want    bool
	}{
		{"pass*", "passrole", true},
		{"*role", "passrole", true},
		{"pa?srole", "passrole", true},
		{"pa??role", "passrole", true},
		{"get*", "passrole", false},
		{"passrole", "passrole", true},
		{"passrole*", "passrole", true},
		{"passroles", "passrole", false},
	}
	for _, tc := range cases {
		if got := iamActionPatternMatches(tc.pattern, tc.target); got != tc.want {
			t.Fatalf("pattern %q vs %q: got %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

func TestIAMPassRoleCollectorPropagatesPageToken(t *testing.T) {
	collectedAt := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	role := IAMRole{
		ARN:  "arn:aws:iam::123456789012:role/source",
		Name: "source",
		PermissionPolicies: []IAMPermissionPolicy{{
			Name:     "passrole",
			Document: `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/target"}]}`,
		}},
	}
	api := &fakeIAMRolesAPI{pages: []ListRolesPage{
		{Roles: []IAMRole{role}, NextToken: "page-2"},
		{Roles: []IAMRole{role}},
	}}
	collector := NewIAMPassRoleRelationshipCollector(api, WithIAMPassRoleRelationshipClock(func() time.Time { return collectedAt }))
	if _, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{}); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got, want := strings.Join(api.tokens, ","), ",page-2"; got != want {
		t.Fatalf("expected tokens %q, got %q", want, got)
	}
}

func TestIsIAMRoleARN(t *testing.T) {
	cases := map[string]bool{
		// Valid IAM role ARNs in commercial, GovCloud, and China partitions.
		"arn:aws:iam::123456789012:role/payments":        true,
		"arn:aws:iam::123456789012:role/path/payments":   true,
		"arn:aws-us-gov:iam::123456789012:role/payments": true,
		"arn:aws-cn:iam::123456789012:role/payments":     true,
		// Wrong IAM resource kinds.
		"arn:aws:iam::123456789012:user/dev":     false,
		"arn:aws:iam::123456789012:policy/Admin": false,
		// Trailing "role/" with no name.
		"arn:aws:iam::123456789012:role/": false,
		// Region segment populated — IAM is global.
		"arn:aws:iam:us-east-1:123456789012:role/payments": false,
		// Account ID must be exactly 12 digits.
		"arn:aws:iam::12345:role/payments":         false,
		"arn:aws:iam::1234567890123:role/payments": false,
		"arn:aws:iam::abc123456789:role/payments":  false,
		"arn:aws:iam:::role/payments":              false,
		// Non-IAM services.
		"arn:aws:s3:::bucket": false,
		"arn:aws:lambda:us-east-1:123456789012:function:payments": false,
		// Non-ARN inputs.
		"*":          false,
		"":           false,
		"not-an-arn": false,
	}
	for input, want := range cases {
		if got := isIAMRoleARN(input); got != want {
			t.Fatalf("isIAMRoleARN(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestIAMPassRoleNormalizerRejectsNonRoleARNs(t *testing.T) {
	record := IAMPassRoleRelationship{
		SourceRoleARN:      "arn:aws:iam::123456789012:role/source",
		SourceRoleName:     "source",
		TargetResource:     "arn:aws:s3:::audit-bucket", // NOT an IAM role
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
	// Source role still projected; non-role target ARN must NOT become an
	// identity in the graph.
	if len(bundle.Identities) != 1 {
		t.Fatalf("expected only source identity for non-role target, got %d (%+v)", len(bundle.Identities), bundle.Identities)
	}
	if bundle.Identities[0].ARN != record.SourceRoleARN {
		t.Fatalf("expected source identity, got %+v", bundle.Identities[0])
	}
}

func TestPassRoleGrantWildcardKindMalformedClassification(t *testing.T) {
	cases := map[string]string{
		// Valid IAM role ARNs.
		"arn:aws:iam::123456789012:role/payments":        "specific",
		"arn:aws-us-gov:iam::123456789012:role/payments": "specific",
		"arn:aws:iam::123456789012:role/payments-*":      "path_wildcard",
		"arn:aws:iam::*:role/payments":                   "account_wildcard",
		"*":                                              "all",
		// Non-IAM ARNs must classify as malformed so the API does not emit
		// PassRole edges to non-role resources.
		"arn:aws:s3:::bucket": "malformed",
		"arn:aws:lambda:us-east-1:123456789012:function:payments": "malformed",
		"arn:aws:iam::123456789012:user/dev":                      "malformed",
		"arn:aws:iam::123456789012:policy/Admin":                  "malformed",
		// Pure non-ARN inputs.
		"not-an-arn":    "malformed",
		"role/payments": "malformed",
	}
	for input, want := range cases {
		if got := passRoleGrantWildcardKind(input); got != want {
			t.Fatalf("passRoleGrantWildcardKind(%q) = %q, want %q", input, got, want)
		}
		conf := passRoleGrantConfidence(passRoleGrant{TargetResource: input})
		if conf <= 0 || conf > 1 {
			t.Fatalf("confidence for %q out of bounds: %v", input, conf)
		}
	}
}

func TestPassRoleGrantConfidenceMatchesWildcardKind(t *testing.T) {
	// Any non-IAM ARN that classifies as malformed must receive the lowest
	// confidence — otherwise the API ships records whose kind says
	// "malformed" but whose confidence claims high trust.
	malformedInputs := []string{
		"arn:aws:s3:::audit-bucket",
		"arn:aws:lambda:us-east-1:123456789012:function:payments",
		"arn:aws:iam::123456789012:user/dev",
		"arn:aws:iam::123456789012:policy/Admin",
		"not-an-arn",
	}
	for _, target := range malformedInputs {
		if kind := passRoleGrantWildcardKind(target); kind != "malformed" {
			t.Fatalf("expected %q to classify as malformed, got %q", target, kind)
		}
		conf := passRoleGrantConfidence(passRoleGrant{TargetResource: target})
		if conf > 0.4 {
			t.Fatalf("malformed target %q got confidence %v; expected low confidence (<= 0.4)", target, conf)
		}
	}
	// Specific IAM role ARN still gets the highest score for parity.
	if conf := passRoleGrantConfidence(passRoleGrant{TargetResource: "arn:aws:iam::123456789012:role/payments"}); conf < 0.9 {
		t.Fatalf("specific IAM role ARN got confidence %v; expected >= 0.9", conf)
	}
}
