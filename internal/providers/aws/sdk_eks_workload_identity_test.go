package aws

import (
	"context"
	"errors"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

type fakeEKSSDKClient struct {
	listClustersInputs                []*eks.ListClustersInput
	listPodIdentityAssociationsInputs []*eks.ListPodIdentityAssociationsInput
	listNodegroupsInputs              []*eks.ListNodegroupsInput
	listFargateProfilesInputs         []*eks.ListFargateProfilesInput
	describePodInputs                 []*eks.DescribePodIdentityAssociationInput

	listClustersOutputs []*eks.ListClustersOutput
	clustersByName      map[string]*eks.DescribeClusterOutput
	associationsByKey   map[string]*eks.DescribePodIdentityAssociationOutput
	nodegroupsByKey     map[string]*eks.DescribeNodegroupOutput
	fargateByKey        map[string]*eks.DescribeFargateProfileOutput

	podIdentitySummaries map[string]*eks.ListPodIdentityAssociationsOutput
	nodegroupNames       map[string]*eks.ListNodegroupsOutput
	fargateNames         map[string]*eks.ListFargateProfilesOutput

	listClustersErr error
	listPodErr      error
	onListPod       func()
	onDescribePod   func()
}

func eksFakeSDKKey(clusterName string, name string) string {
	return clusterName + "/" + name
}

func (f *fakeEKSSDKClient) ListClusters(_ context.Context, params *eks.ListClustersInput, _ ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	f.listClustersInputs = append(f.listClustersInputs, params)
	if f.listClustersErr != nil {
		return nil, f.listClustersErr
	}
	idx := len(f.listClustersInputs) - 1
	if idx >= len(f.listClustersOutputs) {
		return &eks.ListClustersOutput{}, nil
	}
	return f.listClustersOutputs[idx], nil
}

func (f *fakeEKSSDKClient) DescribeCluster(_ context.Context, params *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	return f.clustersByName[awsv2.ToString(params.Name)], nil
}

func (f *fakeEKSSDKClient) ListPodIdentityAssociations(_ context.Context, params *eks.ListPodIdentityAssociationsInput, _ ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	f.listPodIdentityAssociationsInputs = append(f.listPodIdentityAssociationsInputs, params)
	if f.onListPod != nil {
		f.onListPod()
	}
	if f.listPodErr != nil {
		return nil, f.listPodErr
	}
	if output := f.podIdentitySummaries[awsv2.ToString(params.ClusterName)]; output != nil {
		return output, nil
	}
	return &eks.ListPodIdentityAssociationsOutput{}, nil
}

func (f *fakeEKSSDKClient) DescribePodIdentityAssociation(_ context.Context, params *eks.DescribePodIdentityAssociationInput, _ ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	f.describePodInputs = append(f.describePodInputs, params)
	if f.onDescribePod != nil {
		f.onDescribePod()
	}
	return f.associationsByKey[eksFakeSDKKey(awsv2.ToString(params.ClusterName), awsv2.ToString(params.AssociationId))], nil
}

func (f *fakeEKSSDKClient) ListNodegroups(_ context.Context, params *eks.ListNodegroupsInput, _ ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	f.listNodegroupsInputs = append(f.listNodegroupsInputs, params)
	if output := f.nodegroupNames[awsv2.ToString(params.ClusterName)]; output != nil {
		return output, nil
	}
	return &eks.ListNodegroupsOutput{}, nil
}

func (f *fakeEKSSDKClient) DescribeNodegroup(_ context.Context, params *eks.DescribeNodegroupInput, _ ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	return f.nodegroupsByKey[eksFakeSDKKey(awsv2.ToString(params.ClusterName), awsv2.ToString(params.NodegroupName))], nil
}

func (f *fakeEKSSDKClient) ListFargateProfiles(_ context.Context, params *eks.ListFargateProfilesInput, _ ...func(*eks.Options)) (*eks.ListFargateProfilesOutput, error) {
	f.listFargateProfilesInputs = append(f.listFargateProfilesInputs, params)
	if output := f.fargateNames[awsv2.ToString(params.ClusterName)]; output != nil {
		return output, nil
	}
	return &eks.ListFargateProfilesOutput{}, nil
}

func (f *fakeEKSSDKClient) DescribeFargateProfile(_ context.Context, params *eks.DescribeFargateProfileInput, _ ...func(*eks.Options)) (*eks.DescribeFargateProfileOutput, error) {
	return f.fargateByKey[eksFakeSDKKey(awsv2.ToString(params.ClusterName), awsv2.ToString(params.FargateProfileName))], nil
}

func TestSDKEKSWorkloadIdentityAPIMapsAssociationsNodegroupsAndFargate(t *testing.T) {
	clusterARN := "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster"
	podRoleARN := "arn:aws:iam::123456789012:role/batch-pod-identity"
	nodeRoleARN := "arn:aws:iam::123456789012:role/prod-eks-node-role"
	fargateRoleARN := "arn:aws:iam::123456789012:role/payments-fargate-pod-execution"
	client := &fakeEKSSDKClient{
		listClustersOutputs: []*eks.ListClustersOutput{{Clusters: []string{"prod-cluster"}}},
		clustersByName: map[string]*eks.DescribeClusterOutput{
			"prod-cluster": {Cluster: &ekstypes.Cluster{
				Arn:     awsv2.String(clusterARN),
				Name:    awsv2.String("prod-cluster"),
				Status:  ekstypes.ClusterStatus("ACTIVE"),
				Version: awsv2.String("1.30"),
				Identity: &ekstypes.Identity{Oidc: &ekstypes.OIDC{
					Issuer: awsv2.String("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"),
				}},
				Tags: map[string]string{"owner": "platform"},
			}},
		},
		podIdentitySummaries: map[string]*eks.ListPodIdentityAssociationsOutput{
			"prod-cluster": {Associations: []ekstypes.PodIdentityAssociationSummary{{AssociationId: awsv2.String("a-123")}}},
		},
		associationsByKey: map[string]*eks.DescribePodIdentityAssociationOutput{
			eksFakeSDKKey("prod-cluster", "a-123"): {Association: &ekstypes.PodIdentityAssociation{
				AssociationArn: awsv2.String("arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123"),
				AssociationId:  awsv2.String("a-123"),
				ClusterName:    awsv2.String("prod-cluster"),
				Namespace:      awsv2.String("jobs"),
				ServiceAccount: awsv2.String("batch-worker"),
				RoleArn:        awsv2.String(podRoleARN),
				ExternalId:     awsv2.String("external-id"),
				Tags:           map[string]string{"owner": "data"},
			}},
		},
		nodegroupNames: map[string]*eks.ListNodegroupsOutput{
			"prod-cluster": {Nodegroups: []string{"payments-ng"}},
		},
		nodegroupsByKey: map[string]*eks.DescribeNodegroupOutput{
			eksFakeSDKKey("prod-cluster", "payments-ng"): {Nodegroup: &ekstypes.Nodegroup{
				NodegroupArn:  awsv2.String("arn:aws:eks:us-east-1:123456789012:nodegroup/prod-cluster/payments-ng/id"),
				NodegroupName: awsv2.String("payments-ng"),
				NodeRole:      awsv2.String(nodeRoleARN),
				Status:        ekstypes.NodegroupStatus("ACTIVE"),
			}},
		},
		fargateNames: map[string]*eks.ListFargateProfilesOutput{
			"prod-cluster": {FargateProfileNames: []string{"payments-fargate"}},
		},
		fargateByKey: map[string]*eks.DescribeFargateProfileOutput{
			eksFakeSDKKey("prod-cluster", "payments-fargate"): {FargateProfile: &ekstypes.FargateProfile{
				FargateProfileArn:   awsv2.String("arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-cluster/payments-fargate/id"),
				FargateProfileName:  awsv2.String("payments-fargate"),
				PodExecutionRoleArn: awsv2.String(fargateRoleARN),
				Status:              ekstypes.FargateProfileStatus("ACTIVE"),
				Selectors: []ekstypes.FargateProfileSelector{
					{Namespace: awsv2.String("payments"), Labels: map[string]string{"runtime": "fargate"}},
				},
				Subnets: []string{"subnet-a", "subnet-b"},
			}},
		},
	}
	api := NewSDKEKSWorkloadIdentityAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListWorkloadIdentities(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list workload identities: %v", err)
	}
	if len(page.Records) != 3 {
		t.Fatalf("expected pod identity, node role, and fargate records, got %+v", page.Records)
	}
	if len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "irsa_annotation_collection_unconfigured" || page.Diagnostics[0].Retryable {
		t.Fatalf("expected non-retryable IRSA annotation coverage diagnostic, got %+v", page.Diagnostics)
	}
	if got := awsv2.ToInt32(client.listClustersInputs[0].MaxResults); got != 25 {
		t.Fatalf("ListClusters MaxResults = %d, want 25", got)
	}

	byKind := map[string]EKSWorkloadIdentity{}
	for _, record := range page.Records {
		byKind[record.RoleKind] = record
	}
	if byKind[eksRoleKindPodIdentity].RoleARN != podRoleARN || byKind[eksRoleKindPodIdentity].KubernetesSubject != "jobs/batch-worker" {
		t.Fatalf("expected pod identity metadata, got %+v", byKind[eksRoleKindPodIdentity])
	}
	if byKind[eksRoleKindPodIdentity].ClusterTags["owner"] != "platform" || byKind[eksRoleKindPodIdentity].Tags["owner"] != "data" {
		t.Fatalf("expected cluster and workload tags to stay separate, got cluster_tags=%+v tags=%+v", byKind[eksRoleKindPodIdentity].ClusterTags, byKind[eksRoleKindPodIdentity].Tags)
	}
	if byKind[eksRoleKindNodeRole].RoleARN != nodeRoleARN || byKind[eksRoleKindNodeRole].NodegroupName != "payments-ng" {
		t.Fatalf("expected node role metadata, got %+v", byKind[eksRoleKindNodeRole])
	}
	if byKind[eksRoleKindFargatePodExecution].RoleARN != fargateRoleARN || len(byKind[eksRoleKindFargatePodExecution].SelectorLabels) != 1 {
		t.Fatalf("expected fargate metadata, got %+v", byKind[eksRoleKindFargatePodExecution])
	}
}

func TestSDKEKSWorkloadIdentityAPIFailsWhenClusterListingFails(t *testing.T) {
	api := NewSDKEKSWorkloadIdentityAPIFromClient(&fakeEKSSDKClient{listClustersErr: errors.New("eks unavailable")}, "123456789012", "us-east-1")
	if _, err := api.ListWorkloadIdentities(context.Background(), "", 10); err == nil {
		t.Fatal("expected list clusters failure")
	}
}

func TestSDKEKSWorkloadIdentityAPIRetainsClusterOnPodIdentityPartialFailure(t *testing.T) {
	clusterARN := "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster"
	client := &fakeEKSSDKClient{
		listClustersOutputs: []*eks.ListClustersOutput{{Clusters: []string{"prod-cluster"}}},
		clustersByName: map[string]*eks.DescribeClusterOutput{
			"prod-cluster": {Cluster: &ekstypes.Cluster{
				Arn:  awsv2.String(clusterARN),
				Name: awsv2.String("prod-cluster"),
				Identity: &ekstypes.Identity{Oidc: &ekstypes.OIDC{
					Issuer: awsv2.String("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"),
				}},
			}},
		},
		listPodErr:        errors.New("pod identity unavailable"),
		nodegroupNames:    map[string]*eks.ListNodegroupsOutput{},
		fargateNames:      map[string]*eks.ListFargateProfilesOutput{},
		associationsByKey: map[string]*eks.DescribePodIdentityAssociationOutput{},
		nodegroupsByKey:   map[string]*eks.DescribeNodegroupOutput{},
		fargateByKey:      map[string]*eks.DescribeFargateProfileOutput{},
	}
	api := NewSDKEKSWorkloadIdentityAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListWorkloadIdentities(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("list workload identities should tolerate pod identity partial failure: %v", err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("did not expect records when only pod identity partition failed, got %+v", page.Records)
	}
	if len(page.Diagnostics) != 2 {
		t.Fatalf("expected IRSA coverage and pod identity diagnostics, got %+v", page.Diagnostics)
	}
	if page.Diagnostics[0].Code != "irsa_annotation_collection_unconfigured" || page.Diagnostics[0].Retryable {
		t.Fatalf("expected non-retryable IRSA coverage diagnostic, got %+v", page.Diagnostics)
	}
	if page.Diagnostics[1].Code != "pod_identity_association_list_failed" || !page.Diagnostics[1].Retryable {
		t.Fatalf("expected retryable pod identity diagnostic, got %+v", page.Diagnostics)
	}
}

func TestSDKEKSWorkloadIdentityAPIContinuesAfterClusterDescribeFailure(t *testing.T) {
	podRoleARN := "arn:aws:iam::123456789012:role/batch-pod-identity"
	client := &fakeEKSSDKClient{
		listClustersOutputs: []*eks.ListClustersOutput{{Clusters: []string{"prod-cluster"}}},
		clustersByName:      map[string]*eks.DescribeClusterOutput{},
		podIdentitySummaries: map[string]*eks.ListPodIdentityAssociationsOutput{
			"prod-cluster": {Associations: []ekstypes.PodIdentityAssociationSummary{{AssociationId: awsv2.String("a-123")}}},
		},
		associationsByKey: map[string]*eks.DescribePodIdentityAssociationOutput{
			eksFakeSDKKey("prod-cluster", "a-123"): {Association: &ekstypes.PodIdentityAssociation{
				AssociationArn: awsv2.String("arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-123"),
				AssociationId:  awsv2.String("a-123"),
				ClusterName:    awsv2.String("prod-cluster"),
				Namespace:      awsv2.String("jobs"),
				ServiceAccount: awsv2.String("batch-worker"),
				RoleArn:        awsv2.String(podRoleARN),
			}},
		},
		nodegroupNames:  map[string]*eks.ListNodegroupsOutput{},
		fargateNames:    map[string]*eks.ListFargateProfilesOutput{},
		nodegroupsByKey: map[string]*eks.DescribeNodegroupOutput{},
		fargateByKey:    map[string]*eks.DescribeFargateProfileOutput{},
	}
	api := NewSDKEKSWorkloadIdentityAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListWorkloadIdentities(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("list workload identities should retain cluster-scoped evidence after describe failure: %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].RoleARN != podRoleARN || page.Records[0].ClusterName != "prod-cluster" {
		t.Fatalf("expected retained pod identity record, got %+v", page.Records)
	}
	if len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "cluster_describe_failed" {
		t.Fatalf("expected cluster describe diagnostic, got %+v", page.Diagnostics)
	}
}

func TestSDKEKSWorkloadIdentityAPIPropagatesCancellationDuringClusterPartitions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &fakeEKSSDKClient{
		listClustersOutputs: []*eks.ListClustersOutput{{Clusters: []string{"prod-cluster"}}},
		clustersByName: map[string]*eks.DescribeClusterOutput{
			"prod-cluster": {Cluster: &ekstypes.Cluster{Name: awsv2.String("prod-cluster")}},
		},
		podIdentitySummaries: map[string]*eks.ListPodIdentityAssociationsOutput{
			"prod-cluster": {},
		},
		nodegroupNames:    map[string]*eks.ListNodegroupsOutput{},
		fargateNames:      map[string]*eks.ListFargateProfilesOutput{},
		associationsByKey: map[string]*eks.DescribePodIdentityAssociationOutput{},
		nodegroupsByKey:   map[string]*eks.DescribeNodegroupOutput{},
		fargateByKey:      map[string]*eks.DescribeFargateProfileOutput{},
		onListPod:         cancel,
	}
	api := NewSDKEKSWorkloadIdentityAPIFromClient(client, "123456789012", "us-east-1")

	if _, err := api.ListWorkloadIdentities(ctx, "", 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation to propagate, got %v", err)
	}
}

func TestSDKEKSWorkloadIdentityAPIStopsPodIdentityDescribeLoopAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	podRoleARN := "arn:aws:iam::123456789012:role/batch-pod-identity"
	client := &fakeEKSSDKClient{
		listClustersOutputs: []*eks.ListClustersOutput{{Clusters: []string{"prod-cluster"}}},
		clustersByName: map[string]*eks.DescribeClusterOutput{
			"prod-cluster": {Cluster: &ekstypes.Cluster{Name: awsv2.String("prod-cluster")}},
		},
		podIdentitySummaries: map[string]*eks.ListPodIdentityAssociationsOutput{
			"prod-cluster": {Associations: []ekstypes.PodIdentityAssociationSummary{
				{AssociationId: awsv2.String("a-1")},
				{AssociationId: awsv2.String("a-2")},
			}},
		},
		associationsByKey: map[string]*eks.DescribePodIdentityAssociationOutput{
			eksFakeSDKKey("prod-cluster", "a-1"): {Association: &ekstypes.PodIdentityAssociation{
				AssociationArn: awsv2.String("arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-cluster/a-1"),
				AssociationId:  awsv2.String("a-1"),
				ClusterName:    awsv2.String("prod-cluster"),
				Namespace:      awsv2.String("jobs"),
				ServiceAccount: awsv2.String("batch-worker"),
				RoleArn:        awsv2.String(podRoleARN),
			}},
			eksFakeSDKKey("prod-cluster", "a-2"): {Association: &ekstypes.PodIdentityAssociation{
				AssociationId: awsv2.String("a-2"),
				RoleArn:       awsv2.String(podRoleARN),
			}},
		},
		nodegroupNames:  map[string]*eks.ListNodegroupsOutput{},
		fargateNames:    map[string]*eks.ListFargateProfilesOutput{},
		nodegroupsByKey: map[string]*eks.DescribeNodegroupOutput{},
		fargateByKey:    map[string]*eks.DescribeFargateProfileOutput{},
		onDescribePod:   cancel,
	}
	api := NewSDKEKSWorkloadIdentityAPIFromClient(client, "123456789012", "us-east-1")

	if _, err := api.ListWorkloadIdentities(ctx, "", 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation to propagate, got %v", err)
	}
	if len(client.describePodInputs) != 1 {
		t.Fatalf("expected describe loop to stop after first canceled call, got %d calls", len(client.describePodInputs))
	}
}
