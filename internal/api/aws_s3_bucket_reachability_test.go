package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSS3BucketReachabilityInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSS3BucketReachabilityInventory(ctx, "default", "project-a", AWSS3BucketReachabilityInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get s3 inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.CurrentIssueRef != "#1488" || result.Version != awsS3BucketReachabilityVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.BucketCount != 4 {
		t.Fatalf("expected 4 buckets in fixture, got %d", result.BucketCount)
	}
	if result.PublicBucketCount == 0 || result.CrossAccountBucketCount == 0 || result.RestrictedBucketCount == 0 {
		t.Fatalf("expected public/cross/restricted counts populated, got %+v", result)
	}
	if result.AccessPointCount == 0 {
		t.Fatalf("expected access point count populated, got %d", result.AccessPointCount)
	}
	if result.PublicGrantCount == 0 || result.CrossAccountGrantCount == 0 || result.DenyGrantCount == 0 {
		t.Fatalf("expected public/cross/deny grant counts populated, got %+v", result)
	}
	for _, record := range result.Records {
		evidence := strings.ToLower(record.EvidenceRef + " " + record.Source)
		if strings.Contains(evidence, "object") || strings.Contains(evidence, "presigned") || strings.Contains(evidence, "payload") {
			t.Fatalf("expected metadata-only evidence, got %+v", record)
		}
		switch record.ExposureClassification {
		case "public", "cross_account", "restricted", "private_with_grants", "private", "unknown":
		default:
			t.Fatalf("unexpected exposure %q on %+v", record.ExposureClassification, record)
		}
		if record.Confidence <= 0 || record.Confidence > 1 {
			t.Fatalf("confidence out of bounds: %v", record.Confidence)
		}
	}
}

func TestGetAWSS3BucketReachabilityInventoryDegradedFlagsMissingPAB(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSS3BucketReachabilityInventory(ctx, "default", "project-a", AWSS3BucketReachabilityInventoryRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get s3 inventory degraded: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.FailureReasons) == 0 {
		t.Fatalf("expected degraded status with failure reasons, got %+v", result)
	}
	missingPAB := false
	for _, record := range result.Records {
		if record.BucketName == "payments-public" && record.PublicAccessBlock == nil {
			missingPAB = true
		}
	}
	if !missingPAB {
		t.Fatalf("expected payments-public bucket to lose PAB in degraded fixture")
	}
}

func TestRouterAWSS3BucketReachabilityPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/s3-bucket-reachability?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSS3BucketReachabilityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected degraded partial_failure, got status=%q fixture=%q", body.Inventory.Status, body.Inventory.FixtureState)
	}
	if body.Inventory.BucketCount == 0 {
		t.Fatalf("expected partial failure to retain some records, got 0")
	}
	foundDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "s3_bucket_policy_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected s3_bucket_policy_failed diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSS3BucketReachabilityPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 16, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/s3-bucket-reachability?connector_id=aws-prod&fixture_state=permission_denied", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSS3BucketReachabilityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusBlocked || body.Inventory.FixtureState != "permission_denied" {
		t.Fatalf("expected blocked permission_denied, got status=%q fixture=%q", body.Inventory.Status, body.Inventory.FixtureState)
	}
	if len(body.Inventory.Records) != 0 {
		t.Fatalf("expected no records under permission_denied, got %d", len(body.Inventory.Records))
	}
}

func TestRouterAWSS3BucketReachabilityInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 17, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-3")
	seedAWSConnectorForScanTest(t, store, ctx, "project-3", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-3/aws/s3-bucket-reachability?connector_id=aws-prod&fixture_state=bogus", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAWSS3BucketReachabilityEdgesExcludeWildcardsAndDenies(t *testing.T) {
	records := []AWSS3BucketReachabilityRecord{{
		BucketARN:   "arn:aws:s3:::bucket-a",
		EvidenceRef: "arn:aws:s3:::bucket-a",
		IdentityGrants: []AWSS3IdentityGrant{
			{Effect: "Allow", PrincipalARN: "*", WildcardPrincipal: true},
			{Effect: "Deny", PrincipalARN: "arn:aws:iam::123456789012:role/blocked"},
			{Effect: "Allow", PrincipalARN: "arn:aws:iam::123456789012:role/allowed", PrincipalType: "aws"},
			{Effect: "Allow", PrincipalARN: "arn:aws:iam::123456789012:user/alice", PrincipalType: "aws"},
			// Non-IAM ARN — should be excluded from edges (cubic P2).
			{Effect: "Allow", PrincipalARN: "arn:aws:sns:us-east-1:123456789012:topic/x", PrincipalType: "aws"},
			{Effect: "Allow", PrincipalARN: "lambda.amazonaws.com", PrincipalType: "service"}, // non-ARN
		},
	}}
	edges := awsS3BucketReachabilityEdges(records)
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges (IAM role + IAM user), got %d: %+v", len(edges), edges)
	}
	want := map[string]bool{"role/allowed": false, "user/alice": false}
	for _, e := range edges {
		for k := range want {
			if strings.Contains(e.FromNodeID, k) {
				want[k] = true
			}
		}
		if e.Type != "can_access" {
			t.Fatalf("expected can_access type, got %q", e.Type)
		}
	}
	for k, ok := range want {
		if !ok {
			t.Fatalf("expected edge for %s, got %+v", k, edges)
		}
	}
}

func TestIsIAMPrincipalARNForS3Edge(t *testing.T) {
	cases := []struct {
		arn  string
		want bool
	}{
		{"arn:aws:iam::123456789012:role/payments", true},
		{"arn:aws:iam::123456789012:user/alice", true},
		{"arn:aws-us-gov:iam::123456789012:role/gov", true},
		{"arn:aws-cn:iam::123456789012:role/cn", true},
		{"arn:aws:sns:us-east-1:123456789012:topic/x", false},
		{"arn:aws:iam::123456789012:group/devs", false},
		{"arn:aws:iam:us-east-1:123456789012:role/r", false}, // IAM ARNs have empty region
		{"arn:aws:iam::abc:role/r", false},                   // non-numeric account
		{"arn:aws:iam::12345:role/r", false},                 // short account
		{"arn:aws:iam::123456789012:role/", false},           // empty role name
		{"arn:aws:iam::123456789012:user/", false},           // empty user name
		{"lambda.amazonaws.com", false},
		{"", false},
		{"*", false},
		{"arn:foo:iam::123456789012:role/x", false},
	}
	for _, tc := range cases {
		if got := isIAMPrincipalARNForS3Edge(tc.arn); got != tc.want {
			t.Fatalf("isIAMPrincipalARNForS3Edge(%q) = %v, want %v", tc.arn, got, tc.want)
		}
	}
}

func TestAWSS3PartitionForRegion(t *testing.T) {
	cases := map[string]string{
		"us-east-1":     "aws",
		"us-gov-west-1": "aws-us-gov",
		"cn-north-1":    "aws-cn",
		"":              "aws",
		"  US-EAST-1  ": "aws",
	}
	for region, want := range cases {
		if got := awsS3PartitionForRegion(region); got != want {
			t.Fatalf("awsS3PartitionForRegion(%q) = %q, want %q", region, got, want)
		}
	}
}

func TestGetAWSS3BucketReachabilityInventoryGovCloudPartition(t *testing.T) {
	now := time.Date(2026, 6, 10, 18, 0, 0, 0, time.UTC)
	connection := AWSConnectionStatus{
		ConnectorID: "aws-gov",
		AccountID:   "123456789012",
		Region:      "us-gov-west-1",
		Connected:   true,
	}
	project := db.TenancyProject{
		WorkspaceID: "default",
		ProjectID:   "project-g",
	}
	scope := db.Scope{TenantID: "default", WorkspaceID: "default"}
	result, err := buildAWSS3BucketReachabilityInventory(scope, project, connection, true, AWSS3BucketReachabilityInventoryRequest{ConnectorID: "aws-gov"}, now)
	if err != nil {
		t.Fatalf("build gov inventory: %v", err)
	}
	for _, record := range result.Records {
		if !strings.HasPrefix(record.BucketARN, "arn:aws-us-gov:s3:::") {
			t.Fatalf("expected GovCloud partition ARN, got %q", record.BucketARN)
		}
	}
}
