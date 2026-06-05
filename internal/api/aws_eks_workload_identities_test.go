package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSEKSWorkloadIdentityInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 5, 22, 45, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSEKSWorkloadIdentityInventory(ctx, "default", "project-a", AWSEKSWorkloadIdentityInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get eks workload identity inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1480" || result.Version != awsEKSWorkloadIdentityVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.ConnectorID != "aws-prod" || result.AccountID != "123456789012" || result.Region != "us-east-1" {
		t.Fatalf("expected connector account/region context, got %+v", result)
	}
	if result.RecordCount != 4 || result.ClusterCount != 1 || result.OIDCProviderCount != 1 || result.ServiceAccountCount != 2 {
		t.Fatalf("unexpected EKS workload inventory counts: %+v", result)
	}
	if result.PodIdentityAssociationCount != 1 || result.IRSAAnnotationCount != 1 || result.NodeRoleCount != 1 || result.FargateProfileCount != 1 {
		t.Fatalf("unexpected EKS role-kind counts: %+v", result)
	}
	if result.IdentityCount != 4 || result.ResourceCount != 6 || result.RelationshipCount != 4 {
		t.Fatalf("unexpected graph counts: %+v", result)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("did not expect diagnostics for success fixture: %+v", result.Diagnostics)
	}
	if result.Records[0].RoleKind != "irsa" || result.Records[0].RelationshipType != "runs_as" || result.Records[0].KubernetesAccessStatus != "available" {
		t.Fatalf("expected IRSA service-account evidence, got %+v", result.Records[0])
	}
	if result.Records[1].RoleKind != "pod_identity" || result.Records[1].AssociationID == "" || result.Records[1].ExternalID == "" {
		t.Fatalf("expected EKS Pod Identity association evidence, got %+v", result.Records[1])
	}
	if result.Records[2].RoleKind != "node_role" || result.Records[2].NodeRoleARN == "" {
		t.Fatalf("expected EKS node role evidence, got %+v", result.Records[2])
	}
	if result.Records[3].RoleKind != "fargate_pod_execution_role" || result.Records[3].RelationshipType != "attached_to" || len(result.Records[3].SelectorLabels) != 1 {
		t.Fatalf("expected EKS Fargate pod execution role evidence, got %+v", result.Records[3])
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestGetAWSEKSWorkloadIdentityInventorySurfacesKubernetesAccessDegraded(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 5, 23, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSEKSWorkloadIdentityInventory(ctx, "default", "project-a", AWSEKSWorkloadIdentityInventoryRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "degraded",
	})
	if err != nil {
		t.Fatalf("get degraded eks workload identity inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.FailureReasons) == 0 {
		t.Fatalf("expected degraded result with failure reason, got %+v", result)
	}
	if result.RecordCount != 3 || result.IRSAAnnotationCount != 0 || result.PodIdentityAssociationCount != 1 || len(result.Diagnostics) != 1 {
		t.Fatalf("expected retained AWS-side records and one diagnostic, got %+v", result)
	}
	if result.Diagnostics[0].Code != "kubernetes_api_unavailable" || result.Diagnostics[0].Retryable {
		t.Fatalf("expected explicit non-retryable Kubernetes access diagnostic, got %+v", result.Diagnostics)
	}
	if result.Records[0].RoleKind != "pod_identity" || result.Records[0].KubernetesAccessStatus != "aws_metadata_only" {
		t.Fatalf("expected AWS-side Pod Identity evidence to remain visible, got %+v", result.Records[0])
	}
}

func TestRouterAWSEKSWorkloadIdentityInventory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 5, 23, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/eks-workload-identities?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSEKSWorkloadIdentityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected partial failure fixture, got %+v", body.Inventory)
	}
	if body.Inventory.RecordCount != 2 || len(body.Inventory.Diagnostics) != 1 || !body.Inventory.Diagnostics[0].Retryable {
		t.Fatalf("expected retained records and retryable diagnostic, got %+v", body.Inventory)
	}
}

func TestAWSEKSWorkloadIdentityInventoryHelperBranches(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSEKSWorkloadIdentityFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected disconnected connector to map to permission_denied, got %q", got)
	}
	if got := normalizeAWSEKSWorkloadIdentityFixtureState("bogus", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected unknown fixture state to be rejected, got %q", got)
	}
	if got := normalizeAWSEKSWorkloadIdentityFixtureState("EMPTY", AWSConnectionStatus{}, false); got != "empty" {
		t.Fatalf("expected explicit fixture state normalization, got %q", got)
	}

	status, confidence, failures, remediations := summarizeAWSEKSWorkloadIdentityInventory("success", []providers.SourceError{{
		Code:      "nodegroup_list_failed",
		Message:   "nodegroups unavailable",
		Retryable: true,
	}})
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.8 || len(failures) != 1 || len(remediations) != 1 {
		t.Fatalf("expected diagnostics to degrade successful state, got status=%s confidence=%f failures=%+v remediations=%+v", status, confidence, failures, remediations)
	}

	for _, code := range []string{"permission_denied", "kubernetes_api_unavailable", "irsa_annotation_collection_unconfigured", "pod_identity_association_list_failed", "pod_identity_association_describe_failed", "nodegroup_list_failed", "nodegroup_describe_failed", "fargate_profile_list_failed", "fargate_profile_describe_failed", "missing_eks_role", "unknown"} {
		if remediation := awsEKSWorkloadIdentityDiagnosticRemediation(code); strings.TrimSpace(remediation) == "" {
			t.Fatalf("expected remediation for %q", code)
		}
	}

	relationships := awsEKSWorkloadIdentityRelationships([]AWSEKSWorkloadIdentityRecord{
		{FromNodeID: "eks-workload", ToNodeID: "iam-role", EvidenceRef: "evidence"},
		{FromNodeID: "missing-to", EvidenceRef: "missing-to"},
	})
	if len(relationships) != 1 || relationships[0].Type != "runs_as" {
		t.Fatalf("expected one valid relationship, got %+v", relationships)
	}
	if got := awsEKSWorkloadNodeID("", "", "", ""); !strings.Contains(got, "account") || !strings.Contains(got, "region") || !strings.Contains(got, "workload/workload") {
		t.Fatalf("expected fallback eks workload node id, got %q", got)
	}

	sameSubjectAcrossClusters := []AWSEKSWorkloadIdentityRecord{
		{
			AccountID:          "123456789012",
			Region:             "us-east-1",
			RoleKind:           "irsa",
			ClusterARN:         "arn:aws:eks:us-east-1:123456789012:cluster/prod-a",
			KubernetesSubject:  "payments/payments-api",
			AssociationARN:     "",
			NodegroupARN:       "",
			FargateProfileARN:  "",
			KubernetesVersion:  "1.30",
			OIDCProviderARN:    "arn:aws:iam::123456789012:oidc-provider/oidc-a",
			IRSAAnnotationKeys: []string{"eks.amazonaws.com/role-arn"},
		},
		{
			AccountID:          "123456789012",
			Region:             "us-east-1",
			RoleKind:           "pod_identity",
			ClusterARN:         "arn:aws:eks:us-east-1:123456789012:cluster/prod-b",
			KubernetesSubject:  "payments/payments-api",
			AssociationARN:     "arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-b/a-123",
			KubernetesVersion:  "1.30",
			OIDCProviderARN:    "arn:aws:iam::123456789012:oidc-provider/oidc-b",
			IRSAAnnotationKeys: []string{"eks.amazonaws.com/role-arn"},
		},
	}
	if got := awsEKSWorkloadIdentityServiceAccountCount(sameSubjectAcrossClusters); got != 2 {
		t.Fatalf("expected cluster-scoped service account count 2, got %d", got)
	}
	if got := awsEKSWorkloadIdentityResourceCount(sameSubjectAcrossClusters); got != 5 {
		t.Fatalf("expected cluster-scoped resource count 5, got %d", got)
	}
}
