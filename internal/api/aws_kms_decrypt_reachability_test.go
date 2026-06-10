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

func TestGetAWSKMSDecryptReachabilityInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSKMSDecryptReachabilityInventory(ctx, "default", "project-a", AWSKMSDecryptReachabilityInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get kms inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.CurrentIssueRef != "#1489" || result.Version != awsKMSDecryptReachabilityVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.KeyCount != 5 {
		t.Fatalf("expected 5 keys in fixture, got %d", result.KeyCount)
	}
	if result.PublicKeyCount == 0 || result.CrossAccountKeyCount == 0 || result.RestrictedKeyCount == 0 || result.AWSManagedKeyCount == 0 || result.CustomerManagedKeyCount == 0 {
		t.Fatalf("expected mixed key counts populated, got %+v", result)
	}
	if result.PublicGrantCount == 0 || result.CrossAccountGrantCount == 0 || result.DenyGrantCount == 0 {
		t.Fatalf("expected public/cross/deny grant counts populated, got %+v", result)
	}
	if result.LiveGrantCount == 0 {
		t.Fatalf("expected at least one live KMS grant, got %d", result.LiveGrantCount)
	}
	for _, record := range result.Records {
		evidence := strings.ToLower(record.EvidenceRef + " " + record.Source)
		if strings.Contains(evidence, "ciphertext") || strings.Contains(evidence, "plaintext") || strings.Contains(evidence, "decrypted") {
			t.Fatalf("expected metadata-only evidence, got %+v", record)
		}
		switch record.ExposureClassification {
		case "public", "cross_account", "restricted", "managed_by_iam", "managed_by_aws", "private_with_grants", "private", "unknown":
		default:
			t.Fatalf("unexpected exposure %q on %+v", record.ExposureClassification, record)
		}
		// Encryption-context VALUES must never appear; only keys.
		for _, g := range record.Grants {
			for _, k := range g.EncryptionContextKeys {
				if strings.Contains(k, "secret-value") {
					t.Fatalf("encryption-context VALUES leaked into API response: %q", k)
				}
			}
		}
	}
}

func TestGetAWSKMSDecryptReachabilityInventoryDegradedFlagsRotation(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSKMSDecryptReachabilityInventory(ctx, "default", "project-a", AWSKMSDecryptReachabilityInventoryRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get kms inventory degraded: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.FailureReasons) == 0 {
		t.Fatalf("expected degraded status with failure reasons, got %+v", result)
	}
	missingRotation := false
	for _, record := range result.Records {
		if record.KeyID == "bbbb1111-2222-3333-4444-555566667777" && record.Status == "degraded" {
			missingRotation = true
		}
	}
	if !missingRotation {
		t.Fatalf("expected public CMK to be flagged as degraded with missing rotation")
	}
}

func TestRouterAWSKMSDecryptReachabilityPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/kms-decrypt-reachability?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSKMSDecryptReachabilityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected degraded partial_failure, got status=%q fixture=%q", body.Inventory.Status, body.Inventory.FixtureState)
	}
	if body.Inventory.KeyCount == 0 {
		t.Fatalf("expected partial failure to retain some records, got 0")
	}
	foundDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "kms_list_grants_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected kms_list_grants_failed diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSKMSDecryptReachabilityPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 16, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/kms-decrypt-reachability?connector_id=aws-prod&fixture_state=permission_denied", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSKMSDecryptReachabilityInventoryResult `json:"inventory"`
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

func TestRouterAWSKMSDecryptReachabilityInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 10, 17, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-3")
	seedAWSConnectorForScanTest(t, store, ctx, "project-3", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-3/aws/kms-decrypt-reachability?connector_id=aws-prod&fixture_state=bogus", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAWSKMSDecryptReachabilityEdgesExcludeWildcardsAndDenies(t *testing.T) {
	records := []AWSKMSDecryptReachabilityRecord{{
		KeyARN:      "arn:aws:kms:us-east-1:123456789012:key/k1",
		EvidenceRef: "arn:aws:kms:us-east-1:123456789012:key/k1",
		IdentityGrants: []AWSKMSIdentityGrant{
			{Effect: "Allow", PrincipalARN: "*", WildcardPrincipal: true},
			{Effect: "Deny", PrincipalARN: "arn:aws:iam::123456789012:role/blocked"},
			{Effect: "Allow", PrincipalARN: "arn:aws:iam::123456789012:role/allowed", PrincipalType: "aws", Capabilities: []string{"decrypt"}},
			{Effect: "Allow", PrincipalARN: "arn:aws:iam::123456789012:role/encrypt-only", PrincipalType: "aws", Capabilities: []string{"encrypt"}},
			{Effect: "Allow", PrincipalARN: "arn:aws:sns:us-east-1:123456789012:topic/x", PrincipalType: "aws"},
			{Effect: "Allow", PrincipalARN: "lambda.amazonaws.com", PrincipalType: "service"},
		},
		Grants: []AWSKMSGrant{
			{GranteePrincipal: "arn:aws:iam::123456789012:role/lambda-decrypt", GranteePrincipalType: "aws", Capabilities: []string{"decrypt"}},
			{GranteePrincipal: "arn:aws:iam::123456789012:role/lambda-encrypt", GranteePrincipalType: "aws", Capabilities: []string{"encrypt"}},
			{GranteePrincipal: "ec2.amazonaws.com", GranteePrincipalType: "service"},
		},
	}}
	edges := awsKMSDecryptReachabilityEdges(records)
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges (one key-policy + one kms-grant, both IAM ARNs), got %d: %+v", len(edges), edges)
	}
	wantSources := map[string]bool{"key_policy": false, "kms_grant": false}
	for _, e := range edges {
		wantSources[e.Source] = true
		if e.Type != "can_decrypt" {
			t.Fatalf("expected can_decrypt type, got %q", e.Type)
		}
	}
	for source, ok := range wantSources {
		if !ok {
			t.Fatalf("expected an edge from source %q", source)
		}
	}
}

func TestIsIAMPrincipalARNForKMSEdge(t *testing.T) {
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
		{"arn:aws:iam:us-east-1:123456789012:role/r", false},
		{"arn:aws:iam::abc:role/r", false},
		{"arn:aws:iam::123456789012:role/", false},
		{"lambda.amazonaws.com", false},
		{"", false},
		{"*", false},
	}
	for _, tc := range cases {
		if got := isIAMPrincipalARNForKMSEdge(tc.arn); got != tc.want {
			t.Fatalf("isIAMPrincipalARNForKMSEdge(%q) = %v, want %v", tc.arn, got, tc.want)
		}
	}
}

func TestAWSKMSPartitionForRegion(t *testing.T) {
	cases := map[string]string{
		"us-east-1":     "aws",
		"us-gov-west-1": "aws-us-gov",
		"cn-north-1":    "aws-cn",
		"":              "aws",
	}
	for region, want := range cases {
		if got := awsKMSPartitionForRegion(region); got != want {
			t.Fatalf("awsKMSPartitionForRegion(%q)=%q want %q", region, got, want)
		}
	}
}

func TestGetAWSKMSDecryptReachabilityInventoryGovCloudPartition(t *testing.T) {
	now := time.Date(2026, 6, 10, 18, 0, 0, 0, time.UTC)
	connection := AWSConnectionStatus{
		ConnectorID: "aws-gov",
		AccountID:   "123456789012",
		Region:      "us-gov-west-1",
		Connected:   true,
	}
	project := db.TenancyProject{WorkspaceID: "default", ProjectID: "project-g"}
	scope := db.Scope{TenantID: "default", WorkspaceID: "default"}
	result, err := buildAWSKMSDecryptReachabilityInventory(scope, project, connection, true, AWSKMSDecryptReachabilityInventoryRequest{ConnectorID: "aws-gov"}, now)
	if err != nil {
		t.Fatalf("build gov inventory: %v", err)
	}
	for _, record := range result.Records {
		if !strings.HasPrefix(record.KeyARN, "arn:aws-us-gov:kms:us-gov-west-1:") {
			t.Fatalf("expected GovCloud partition ARN, got %q", record.KeyARN)
		}
	}
}
