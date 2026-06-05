package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeEKSWorkloadIdentityAPI struct {
	pages []EKSWorkloadIdentityPage
	calls int
}

type eksWorkloadIdentityAPIFunc func(ctx context.Context, nextToken string, pageSize int32) (EKSWorkloadIdentityPage, error)

func (f eksWorkloadIdentityAPIFunc) ListWorkloadIdentities(ctx context.Context, nextToken string, pageSize int32) (EKSWorkloadIdentityPage, error) {
	return f(ctx, nextToken, pageSize)
}

func (f *fakeEKSWorkloadIdentityAPI) ListWorkloadIdentities(_ context.Context, nextToken string, pageSize int32) (EKSWorkloadIdentityPage, error) {
	f.calls++
	if pageSize != 2 {
		return EKSWorkloadIdentityPage{}, fakeRetryableError{message: "unexpected page size"}
	}
	switch f.calls {
	case 1:
		if nextToken != "" {
			return EKSWorkloadIdentityPage{}, fakeRetryableError{message: "unexpected first token"}
		}
	case 2:
		if nextToken != "page-2" {
			return EKSWorkloadIdentityPage{}, fakeRetryableError{message: "unexpected second token"}
		}
	}
	if f.calls > len(f.pages) {
		return EKSWorkloadIdentityPage{}, nil
	}
	return f.pages[f.calls-1], nil
}

func TestEKSWorkloadIdentityCollectorEmitsContractRecordsAndDiagnostics(t *testing.T) {
	fixedNow := time.Date(2026, 6, 5, 22, 0, 0, 0, time.UTC)
	api := &fakeEKSWorkloadIdentityAPI{
		pages: []EKSWorkloadIdentityPage{
			{
				Records: []EKSWorkloadIdentity{{
					ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
						WorkloadID:   "prod-cluster/payments/payments-api",
						WorkloadType: "eks_service_account",
						WorkloadName: "payments/payments-api",
						RoleARN:      "arn:aws:iam::123456789012:role/payments-irsa",
						Source:       "kubernetes_serviceaccount_annotation",
						EvidenceRef:  "payments/payments-api",
					},
					RoleKind:               eksRoleKindIRSA,
					ClusterARN:             "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
					ClusterName:            "prod-cluster",
					OIDCIssuer:             "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE",
					Namespace:              "payments",
					ServiceAccount:         "payments-api",
					KubernetesAccessStatus: "available",
					IRSAAnnotationKeys:     []string{"eks.amazonaws.com/role-arn"},
					Tags:                   map[string]string{"owner": "platform"},
				}},
				Diagnostics: []providers.SourceError{{
					Collector: eksWorkloadIdentityCollectorName,
					SourceID:  "prod-cluster",
					Code:      "kubernetes_api_unavailable",
					Message:   "Kubernetes annotations unavailable",
					Retryable: false,
				}},
				NextToken: "page-2",
			},
			{
				Records: []EKSWorkloadIdentity{{
					ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
						WorkloadID:   "prod-cluster/jobs/missing-role",
						WorkloadType: "eks_service_account",
						WorkloadName: "jobs/missing-role",
						Source:       "listpodidentityassociations",
						EvidenceRef:  "jobs/missing-role",
					},
					RoleKind:       eksRoleKindPodIdentity,
					ClusterName:    "prod-cluster",
					Namespace:      "jobs",
					ServiceAccount: "missing-role",
				}},
			},
		},
	}
	collector := NewEKSWorkloadIdentityCollector(api, WithEKSWorkloadIdentityPageSize(2), WithEKSWorkloadIdentityClock(func() time.Time {
		return fixedNow
	}))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-eks",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one valid raw asset, got %d", len(assets))
	}
	if len(diagnostics) != 2 || diagnostics[0].Code != "kubernetes_api_unavailable" || diagnostics[1].Code != "missing_eks_role" {
		t.Fatalf("expected kubernetes access and missing role diagnostics, got %+v", diagnostics)
	}

	var payload EKSWorkloadIdentity
	if err := json.Unmarshal(assets[0].Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Service != "eks" || payload.CollectorName != eksWorkloadIdentityCollectorName || payload.KubernetesSubject != "payments/payments-api" {
		t.Fatalf("expected normalized EKS metadata, got %+v", payload)
	}
	if payload.OIDCProviderARN != "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE" {
		t.Fatalf("expected inferred oidc provider arn, got %q", payload.OIDCProviderARN)
	}
	if payload.CollectedAt != fixedNow {
		t.Fatalf("expected collected_at %s, got %s", fixedNow, payload.CollectedAt)
	}
	if _, err := awscontract.NormalizeServiceCollectorRecord(payload.ServiceCollectorRecord); err != nil {
		t.Fatalf("expected payload to satisfy service collector contract: %v", err)
	}
}

func TestRoleNormalizerAddsEKSWorkloadIdentityEdges(t *testing.T) {
	now := time.Date(2026, 6, 5, 22, 15, 0, 0, time.UTC)
	podIdentity := EKSWorkloadIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "eks",
			WorkloadID:    "prod-cluster/jobs/batch-worker",
			WorkloadType:  "eks_service_account",
			WorkloadName:  "jobs/batch-worker",
			RoleARN:       "arn:aws:iam::123456789012:role/batch-pod-identity",
			Source:        "listpodidentityassociations",
			EvidenceRef:   "arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123",
			Confidence:    0.97,
			ScanID:        "scan-eks",
			CollectorName: eksWorkloadIdentityCollectorName,
			CollectedAt:   now,
		},
		RoleKind:               eksRoleKindPodIdentity,
		RoleName:               "batch-pod-identity",
		ClusterARN:             "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
		ClusterName:            "prod-cluster",
		Namespace:              "jobs",
		ServiceAccount:         "batch-worker",
		KubernetesSubject:      "jobs/batch-worker",
		AssociationARN:         "arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123",
		KubernetesAccessStatus: "aws_metadata_only",
		ClusterTags:            map[string]string{"owner": "platform", "env": "prod"},
		Tags:                   map[string]string{"owner": "data", "service": "batch"},
	}
	fargate := EKSWorkloadIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "eks",
			WorkloadID:    "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-cluster/payments",
			WorkloadType:  "eks_fargate_pod_execution_role",
			WorkloadName:  "payments",
			RoleARN:       "arn:aws:iam::123456789012:role/payments-fargate-pod-execution",
			Source:        "describefargateprofile",
			EvidenceRef:   "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-cluster/payments",
			Confidence:    0.9,
			ScanID:        "scan-eks",
			CollectorName: eksWorkloadIdentityCollectorName,
			CollectedAt:   now,
		},
		RoleKind:               eksRoleKindFargatePodExecution,
		RoleName:               "payments-fargate-pod-execution",
		ClusterARN:             "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
		ClusterName:            "prod-cluster",
		FargateProfileARN:      "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-cluster/payments",
		FargateProfileName:     "payments",
		PodExecutionRoleARN:    "arn:aws:iam::123456789012:role/payments-fargate-pod-execution",
		KubernetesAccessStatus: "aws_metadata_only",
	}
	podPayload, err := json.Marshal(podIdentity)
	if err != nil {
		t.Fatalf("marshal pod identity: %v", err)
	}
	fargatePayload, err := json.Marshal(fargate)
	if err != nil {
		t.Fatalf("marshal fargate: %v", err)
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindEKSWorkloadIdentity, SourceID: "eks-pod", Payload: podPayload},
		{Kind: rawKindEKSWorkloadIdentity, SourceID: "eks-fargate", Payload: fargatePayload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("normalized bundle invalid: %v", err)
	}
	if len(bundle.Identities) != 2 || len(bundle.Workloads) != 2 || len(bundle.Resources) < 3 {
		t.Fatalf("expected eks identities/workloads/resources, got identities=%+v workloads=%+v resources=%+v", bundle.Identities, bundle.Workloads, bundle.Resources)
	}
	if !hasResourceType(bundle.Resources, domain.ResourceTypeEKSCluster) || !hasResourceType(bundle.Resources, domain.ResourceTypeEKSWorkload) {
		t.Fatalf("expected EKS cluster and workload resources, got %+v", bundle.Resources)
	}
	clusterLabels := map[string]string{}
	podWorkloadLabels := map[string]string{}
	for _, resource := range bundle.Resources {
		if resource.Type == domain.ResourceTypeEKSCluster {
			clusterLabels = resource.Labels
		}
		if resource.Type == domain.ResourceTypeEKSWorkload && resource.Name == "jobs/batch-worker" {
			podWorkloadLabels = resource.Labels
		}
	}
	if clusterLabels["owner"] != "platform" || clusterLabels["service"] != "" {
		t.Fatalf("expected EKS cluster labels to use only cluster tags, got %+v", clusterLabels)
	}
	if podWorkloadLabels["owner"] != "data" || podWorkloadLabels["service"] != "batch" {
		t.Fatalf("expected EKS workload labels to use workload tags, got %+v", podWorkloadLabels)
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("graph contract invalid: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipRunsAs) || !hasRelationshipType(relationships, domain.RelationshipAttachedTo) {
		t.Fatalf("expected EKS runs_as and attached_to edges, got %+v", relationships)
	}
}

func TestEKSWorkloadIdentityCollectorRetriesThenCollects(t *testing.T) {
	attempt := 0
	collector := NewEKSWorkloadIdentityCollector(
		eksWorkloadIdentityAPIFunc(func(_ context.Context, nextToken string, pageSize int32) (EKSWorkloadIdentityPage, error) {
			attempt++
			if nextToken != "" {
				t.Fatalf("expected single collector-facing page, got next token %q", nextToken)
			}
			if pageSize != 5 {
				t.Fatalf("expected configured page size 5, got %d", pageSize)
			}
			if attempt <= 2 {
				return EKSWorkloadIdentityPage{}, fakeRetryableError{message: "ThrottlingException"}
			}
			return EKSWorkloadIdentityPage{Records: []EKSWorkloadIdentity{{
				ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
					WorkloadID:   "prod-cluster/payments/payments-api",
					WorkloadType: "eks_service_account",
					WorkloadName: "payments/payments-api",
					RoleARN:      "arn:aws:iam::123456789012:role/payments-irsa",
					Source:       "kubernetes_serviceaccount_annotation",
					EvidenceRef:  "payments/payments-api",
				},
				RoleKind:       eksRoleKindIRSA,
				ClusterName:    "prod-cluster",
				Namespace:      "payments",
				ServiceAccount: "payments-api",
			}}}, nil
		}),
		WithEKSWorkloadIdentityPageSize(5),
		WithEKSWorkloadIdentityRetryPolicy(RetryPolicy{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}),
		WithEKSWorkloadIdentitySleeper(func(context.Context, time.Duration) error { return nil }),
	)

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed after retry: %v", err)
	}
	if len(assets) != 1 || attempt != 3 {
		t.Fatalf("expected one asset after three attempts, assets=%d attempts=%d", len(assets), attempt)
	}
	if got := fmt.Sprint(assets[0].Kind); got != rawKindEKSWorkloadIdentity {
		t.Fatalf("expected raw kind %q, got %q", rawKindEKSWorkloadIdentity, got)
	}
}

func TestEKSWorkloadIdentityIDsUseCanonicalRoleKindAliases(t *testing.T) {
	aliasRecord := EKSWorkloadIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			WorkloadID:   "prod-cluster/jobs/batch-worker",
			WorkloadType: "eks_service_account",
		},
		RoleKind:       "podidentity",
		ClusterName:    "prod-cluster",
		Namespace:      "jobs",
		ServiceAccount: "batch-worker",
	}
	canonicalRecord := aliasRecord
	canonicalRecord.RoleKind = eksRoleKindPodIdentity

	if got, want := eksWorkloadIdentityNormalizedWorkloadID(aliasRecord), eksWorkloadIdentityNormalizedWorkloadID(canonicalRecord); got != want {
		t.Fatalf("alias workload id = %q, want canonical %q", got, want)
	}
	if got, want := eksWorkloadResourceID(aliasRecord), eksWorkloadResourceID(canonicalRecord); got != want {
		t.Fatalf("alias workload resource id = %q, want canonical %q", got, want)
	}
}

func TestEKSWorkloadIdentityNamesUseCanonicalRoleKindAliases(t *testing.T) {
	record := EKSWorkloadIdentity{
		RoleKind:      "nodegroup_role",
		NodegroupARN:  "arn:aws:eks:us-east-1:123456789012:nodegroup/prod-cluster/payments-ng/01234567-89ab-cdef",
		NodegroupName: "payments-ng",
	}

	if got := eksWorkloadIdentityName(record); got != "payments-ng" {
		t.Fatalf("expected nodegroup alias to use nodegroup name, got %q", got)
	}
}

func TestEKSNameFromARNUsesNamedResourceSegment(t *testing.T) {
	cases := map[string]string{
		"arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster":                                            "prod-cluster",
		"arn:aws:eks:us-east-1:123456789012:nodegroup/prod-cluster/payments-ng/01234567-89ab-cdef":           "payments-ng",
		"arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-cluster/payments-fargate/01234567-89ab-cdef": "payments-fargate",
		"arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123":                       "a-123",
	}
	for arn, want := range cases {
		if got := eksNameFromARN(arn); got != want {
			t.Fatalf("eksNameFromARN(%q) = %q, want %q", arn, got, want)
		}
	}
}

func hasResourceType(resources []domain.Resource, resourceType domain.ResourceType) bool {
	for _, resource := range resources {
		if resource.Type == resourceType {
			return true
		}
	}
	return false
}
