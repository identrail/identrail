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

func TestGetAWSSageMakerWorkloadRoleInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 7, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSSageMakerWorkloadRoleInventory(ctx, "default", "project-a", AWSSageMakerWorkloadRoleInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get sagemaker workload role inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1486" || result.Version != awsSageMakerWorkloadRoleVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.NotebookCount != 1 || result.TrainingJobCount != 1 || result.ProcessingJobCount != 1 || result.TransformJobCount != 1 || result.ModelCount != 1 || result.EndpointCount != 1 || result.PipelineCount != 1 || result.DomainCount != 1 {
		t.Fatalf("expected one record per workload type, got %+v", result)
	}
	if result.WorkloadTypeCount != 8 {
		t.Fatalf("expected 8 workload types, got %d", result.WorkloadTypeCount)
	}
	if result.S3ReferenceCount == 0 || result.ECRImageCount == 0 || result.KMSKeyCount == 0 {
		t.Fatalf("expected S3/ECR/KMS evidence counts to be populated, got %+v", result)
	}
	if len(result.CoverageGaps) == 0 {
		t.Fatalf("expected coverage gaps for user-profile/space, got %+v", result.CoverageGaps)
	}

	var endpoint, transform, training *AWSSageMakerWorkloadRoleRecord
	for i := range result.Records {
		switch result.Records[i].WorkloadType {
		case "sagemaker_endpoint":
			endpoint = &result.Records[i]
		case "sagemaker_transform_job":
			transform = &result.Records[i]
		case "sagemaker_training_job":
			training = &result.Records[i]
		}
	}
	if endpoint == nil || endpoint.RelationshipType != "attached_to" {
		t.Fatalf("expected endpoint role to be attached_to, got %+v", endpoint)
	}
	if transform == nil || transform.RelationshipType != "attached_to" {
		t.Fatalf("expected transform role to be attached_to, got %+v", transform)
	}
	if training == nil || training.RelationshipType != "runs_as" {
		t.Fatalf("expected training role to be runs_as, got %+v", training)
	}
	if !hasAWSSageMakerWorkloadRoleRelationship(result.Relationships, "runs_as") || !hasAWSSageMakerWorkloadRoleRelationship(result.Relationships, "attached_to") {
		t.Fatalf("expected runtime and support role relationships, got %+v", result.Relationships)
	}
	for _, record := range result.Records {
		evidence := strings.ToLower(record.EvidenceRef + " " + record.Source)
		if strings.Contains(evidence, "payload") || strings.Contains(evidence, "secret") || strings.Contains(evidence, "presigned") {
			t.Fatalf("expected metadata-only evidence, got %+v", record)
		}
		for _, ref := range record.S3References {
			if strings.HasSuffix(strings.ToLower(ref), ".csv") || strings.HasSuffix(strings.ToLower(ref), ".jsonl") {
				t.Fatalf("expected S3 prefixes only (no payload files), got %q", ref)
			}
		}
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func hasAWSSageMakerWorkloadRoleRelationship(relationships []AWSSageMakerWorkloadRoleRelationship, relationshipType string) bool {
	for _, relationship := range relationships {
		if relationship.Type == relationshipType {
			return true
		}
	}
	return false
}

func TestRouterAWSSageMakerWorkloadRoleInventoryPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 7, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/sagemaker-workload-roles?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSSageMakerWorkloadRoleInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected degraded partial_failure, got status=%q fixture=%q", body.Inventory.Status, body.Inventory.FixtureState)
	}
	if body.Inventory.RecordCount != 7 {
		t.Fatalf("expected partial failure to retain seven records (every workload type except pipeline), got %d", body.Inventory.RecordCount)
	}
	if body.Inventory.PipelineCount != 0 {
		t.Fatalf("expected pipeline records to be dropped, got %d", body.Inventory.PipelineCount)
	}
	if body.Inventory.DomainCount != 1 {
		t.Fatalf("expected the domain record to survive a pipelines-failure partial failure, got %d", body.Inventory.DomainCount)
	}
	foundPipelineDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "sagemaker_pipelines_failed" && diag.Retryable {
			foundPipelineDiag = true
		}
	}
	if !foundPipelineDiag {
		t.Fatalf("expected retryable sagemaker_pipelines_failed diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSSageMakerWorkloadRoleInventoryPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 7, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/sagemaker-workload-roles?connector_id=aws-prod&fixture_state=permission_denied", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSSageMakerWorkloadRoleInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusBlocked {
		t.Fatalf("expected blocked status, got %q", body.Inventory.Status)
	}
	if len(body.Inventory.Records) != 0 {
		t.Fatalf("expected no records on permission_denied, got %d", len(body.Inventory.Records))
	}
	foundPermissionDenied := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "permission_denied" {
			foundPermissionDenied = true
			break
		}
	}
	if !foundPermissionDenied {
		t.Fatalf("expected permission_denied diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSSageMakerWorkloadRoleInventoryInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 7, 16, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-3")
	seedAWSConnectorForScanTest(t, store, ctx, "project-3", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-3/aws/sagemaker-workload-roles?connector_id=aws-prod&fixture_state=invalid_state", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid fixture state, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestNormalizeAWSSageMakerFixtureStateHonorsExplicitSuccess(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSSageMakerWorkloadRoleFixtureState("success", disconnected, true); got != "success" {
		t.Fatalf("explicit success must not downgrade to permission_denied, got %q", got)
	}
	if got := normalizeAWSSageMakerWorkloadRoleFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("blank fixture_state with disconnected connector should default to permission_denied, got %q", got)
	}
	if got := normalizeAWSSageMakerWorkloadRoleFixtureState("permission_denied", AWSConnectionStatus{Connected: true}, true); got != "permission_denied" {
		t.Fatalf("explicit permission_denied should be respected even when connector is connected, got %q", got)
	}
	if got := normalizeAWSSageMakerWorkloadRoleFixtureState("invalid", disconnected, true); got != "" {
		t.Fatalf("invalid fixture_state should return empty, got %q", got)
	}
}

func TestAWSSageMakerFixtureUsesGovCloudPartition(t *testing.T) {
	records, _, _ := awsSageMakerWorkloadRoleFixtureRecords("123456789012", "us-gov-west-1", "success", time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC))
	if len(records) == 0 {
		t.Fatalf("expected fixture records, got 0")
	}
	for _, record := range records {
		if !strings.HasPrefix(record.WorkloadARN, "arn:aws-us-gov:sagemaker:") {
			t.Fatalf("expected GovCloud workload ARN, got %q", record.WorkloadARN)
		}
		if !strings.HasPrefix(record.RoleARN, "arn:aws-us-gov:iam::") {
			t.Fatalf("expected GovCloud role ARN, got %q", record.RoleARN)
		}
		for _, kms := range record.KMSKeyARNs {
			if !strings.HasPrefix(kms, "arn:aws-us-gov:kms:") {
				t.Fatalf("expected GovCloud KMS ARN, got %q", kms)
			}
		}
	}
}

func TestAWSSageMakerFixtureUsesChinaPartitionForECR(t *testing.T) {
	records, _, _ := awsSageMakerWorkloadRoleFixtureRecords("123456789012", "cn-northwest-1", "success", time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC))
	if len(records) == 0 {
		t.Fatalf("expected fixture records, got 0")
	}
	sawCNECR := false
	for _, record := range records {
		for _, image := range record.ImageURIs {
			if strings.Contains(image, ".amazonaws.com.cn/") {
				sawCNECR = true
			} else if strings.Contains(image, ".dkr.ecr.") && !strings.Contains(image, ".amazonaws.com.cn/") {
				t.Fatalf("expected China ECR registry suffix .amazonaws.com.cn, got %q", image)
			}
		}
	}
	if !sawCNECR {
		t.Fatalf("expected at least one ECR image URI on a fixture record")
	}
}

func TestAWSSageMakerPartitionForRegionIsCaseInsensitive(t *testing.T) {
	cases := map[string]string{
		"us-gov-west-1":  "aws-us-gov",
		"US-GOV-WEST-1":  "aws-us-gov",
		"Us-Gov-West-1":  "aws-us-gov",
		"cn-northwest-1": "aws-cn",
		"CN-NORTHWEST-1": "aws-cn",
		"us-east-1":      "aws",
		"  us-east-1  ":  "aws",
	}
	for region, want := range cases {
		if got := awsSageMakerPartitionForRegion(region); got != want {
			t.Fatalf("partition for region %q: got %q, want %q", region, got, want)
		}
	}
}
