package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

// EKSSDKClient defines the EKS SDK calls required by the workload identity adapter.
type EKSSDKClient interface {
	ListClusters(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	ListPodIdentityAssociations(ctx context.Context, params *eks.ListPodIdentityAssociationsInput, optFns ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
	DescribePodIdentityAssociation(ctx context.Context, params *eks.DescribePodIdentityAssociationInput, optFns ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error)
	ListNodegroups(ctx context.Context, params *eks.ListNodegroupsInput, optFns ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error)
	DescribeNodegroup(ctx context.Context, params *eks.DescribeNodegroupInput, optFns ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error)
	ListFargateProfiles(ctx context.Context, params *eks.ListFargateProfilesInput, optFns ...func(*eks.Options)) (*eks.ListFargateProfilesOutput, error)
	DescribeFargateProfile(ctx context.Context, params *eks.DescribeFargateProfileInput, optFns ...func(*eks.Options)) (*eks.DescribeFargateProfileOutput, error)
}

// SDKEKSWorkloadIdentityAPI adapts AWS SDK EKS calls to EKSWorkloadIdentityAPI.
type SDKEKSWorkloadIdentityAPI struct {
	eksClient EKSSDKClient
	accountID string
	region    string
}

var _ EKSWorkloadIdentityAPI = (*SDKEKSWorkloadIdentityAPI)(nil)

// NewSDKEKSWorkloadIdentityAPI constructs an EKS workload identity API backed by the AWS SDK default credential chain.
func NewSDKEKSWorkloadIdentityAPI(region string, profile string, accountID string) (EKSWorkloadIdentityAPI, error) {
	return NewSDKEKSWorkloadIdentityAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKEKSWorkloadIdentityAPIWithContext constructs an EKS workload identity API using caller-provided context for config loading.
func NewSDKEKSWorkloadIdentityAPIWithContext(ctx context.Context, region string, profile string, accountID string) (EKSWorkloadIdentityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKEKSWorkloadIdentityAPIFromClient(eks.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKEKSWorkloadIdentityAPIFromAssumeRole constructs an EKS workload identity API for an onboarded connector role.
func NewSDKEKSWorkloadIdentityAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (EKSWorkloadIdentityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, fmt.Errorf("aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = textutil.FirstNonEmpty(strings.TrimSpace(sessionName), "identrail-recurring-scan")
		},
	}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(options *stscreds.AssumeRoleOptions) {
			options.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	return NewSDKEKSWorkloadIdentityAPIFromClient(eks.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKEKSWorkloadIdentityAPIFromClient creates an EKSWorkloadIdentityAPI from a provided EKS client.
func NewSDKEKSWorkloadIdentityAPIFromClient(eksClient EKSSDKClient, accountID string, region string) EKSWorkloadIdentityAPI {
	return &SDKEKSWorkloadIdentityAPI{
		eksClient: eksClient,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

// ListWorkloadIdentities returns a complete metadata-only EKS scan. The SDK
// adapter handles AWS pagination internally; the collector-facing page contract
// remains reusable for fixture and unit-test APIs.
func (a *SDKEKSWorkloadIdentityAPI) ListWorkloadIdentities(ctx context.Context, _ string, pageSize int32) (EKSWorkloadIdentityPage, error) {
	if a.eksClient == nil {
		return EKSWorkloadIdentityPage{}, fmt.Errorf("eks sdk client is required")
	}

	pageSize = eksSDKPageSize(pageSize)
	clusterNames, err := a.listClusters(ctx, pageSize)
	if err != nil {
		return EKSWorkloadIdentityPage{}, err
	}

	records := []EKSWorkloadIdentity{}
	diagnostics := []providers.SourceError{}
	for _, clusterName := range clusterNames {
		if err := ctx.Err(); err != nil {
			return EKSWorkloadIdentityPage{}, err
		}
		cluster, err := a.describeCluster(ctx, clusterName)
		clusterCore := EKSWorkloadIdentity{}
		if err != nil {
			diagnostics = append(diagnostics, eksSourceDiagnostic("cluster_describe_failed", clusterName, fmt.Sprintf("EKS cluster metadata could not be described: %v", err), true))
			clusterCore = a.clusterCoreRecordFromName(clusterName)
		} else {
			clusterCore = a.clusterCoreRecord(cluster)
		}
		diagnostics = append(diagnostics, irsaAnnotationCoverageDiagnostics(clusterCore)...)

		podIdentities, podDiagnostics := a.podIdentityAssociationsForCluster(ctx, clusterCore.ClusterName, pageSize)
		if err := ctx.Err(); err != nil {
			return EKSWorkloadIdentityPage{}, err
		}
		diagnostics = append(diagnostics, podDiagnostics...)
		for _, association := range podIdentities {
			records = append(records, a.recordFromPodIdentityAssociation(clusterCore, association))
		}

		nodegroups, nodeDiagnostics := a.nodegroupsForCluster(ctx, clusterCore.ClusterName, pageSize)
		if err := ctx.Err(); err != nil {
			return EKSWorkloadIdentityPage{}, err
		}
		diagnostics = append(diagnostics, nodeDiagnostics...)
		for _, nodegroup := range nodegroups {
			records = append(records, a.recordFromNodegroup(clusterCore, nodegroup))
		}

		fargateProfiles, fargateDiagnostics := a.fargateProfilesForCluster(ctx, clusterCore.ClusterName, pageSize)
		if err := ctx.Err(); err != nil {
			return EKSWorkloadIdentityPage{}, err
		}
		diagnostics = append(diagnostics, fargateDiagnostics...)
		for _, profile := range fargateProfiles {
			records = append(records, a.recordFromFargateProfile(clusterCore, profile))
		}
	}

	sort.SliceStable(records, func(i, j int) bool {
		return eksWorkloadIdentitySourceID(records[i]) < eksWorkloadIdentitySourceID(records[j])
	})
	return EKSWorkloadIdentityPage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKEKSWorkloadIdentityAPI) listClusters(ctx context.Context, pageSize int32) ([]string, error) {
	input := &eks.ListClustersInput{MaxResults: awsv2.Int32(pageSize)}
	clusterNames := []string{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		output, err := a.eksClient.ListClusters(ctx, input)
		if err != nil {
			return nil, err
		}
		if output != nil {
			clusterNames = append(clusterNames, output.Clusters...)
		}
		nextToken := ""
		if output != nil {
			nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		}
		if nextToken == "" {
			break
		}
		input.NextToken = awsv2.String(nextToken)
	}
	return normalizeStringList(clusterNames), nil
}

func (a *SDKEKSWorkloadIdentityAPI) describeCluster(ctx context.Context, clusterName string) (ekstypes.Cluster, error) {
	output, err := a.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: awsv2.String(clusterName)})
	if err != nil {
		return ekstypes.Cluster{}, err
	}
	if output == nil || output.Cluster == nil {
		return ekstypes.Cluster{}, fmt.Errorf("cluster %s did not return metadata", clusterName)
	}
	return *output.Cluster, nil
}

func (a *SDKEKSWorkloadIdentityAPI) podIdentityAssociationsForCluster(ctx context.Context, clusterName string, pageSize int32) ([]ekstypes.PodIdentityAssociation, []providers.SourceError) {
	input := &eks.ListPodIdentityAssociationsInput{
		ClusterName: awsv2.String(clusterName),
		MaxResults:  awsv2.Int32(pageSize),
	}
	summaries := []ekstypes.PodIdentityAssociationSummary{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, []providers.SourceError{eksSourceDiagnostic("pod_identity_association_list_failed", clusterName, err.Error(), true)}
		}
		output, err := a.eksClient.ListPodIdentityAssociations(ctx, input)
		if err != nil {
			return nil, []providers.SourceError{eksSourceDiagnostic("pod_identity_association_list_failed", clusterName, fmt.Sprintf("EKS Pod Identity associations could not be listed: %v", err), true)}
		}
		if output != nil {
			summaries = append(summaries, output.Associations...)
		}
		nextToken := ""
		if output != nil {
			nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		}
		if nextToken == "" {
			break
		}
		input.NextToken = awsv2.String(nextToken)
	}

	associations := []ekstypes.PodIdentityAssociation{}
	diagnostics := []providers.SourceError{}
	for _, summary := range summaries {
		if err := ctx.Err(); err != nil {
			return associations, diagnostics
		}
		associationID := strings.TrimSpace(awsv2.ToString(summary.AssociationId))
		if associationID == "" {
			diagnostics = append(diagnostics, eksSourceDiagnostic("pod_identity_association_missing_id", clusterName, "EKS Pod Identity association summary did not include an association ID", false))
			continue
		}
		output, err := a.eksClient.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
			ClusterName:   awsv2.String(clusterName),
			AssociationId: awsv2.String(associationID),
		})
		if err != nil {
			if ctx.Err() != nil {
				return associations, diagnostics
			}
			diagnostics = append(diagnostics, eksSourceDiagnostic("pod_identity_association_describe_failed", associationID, fmt.Sprintf("EKS Pod Identity association could not be described: %v", err), true))
			continue
		}
		if output != nil && output.Association != nil {
			associations = append(associations, *output.Association)
		}
	}
	return associations, diagnostics
}

func (a *SDKEKSWorkloadIdentityAPI) nodegroupsForCluster(ctx context.Context, clusterName string, pageSize int32) ([]ekstypes.Nodegroup, []providers.SourceError) {
	input := &eks.ListNodegroupsInput{
		ClusterName: awsv2.String(clusterName),
		MaxResults:  awsv2.Int32(pageSize),
	}
	nodegroupNames := []string{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, []providers.SourceError{eksSourceDiagnostic("nodegroup_list_failed", clusterName, err.Error(), true)}
		}
		output, err := a.eksClient.ListNodegroups(ctx, input)
		if err != nil {
			return nil, []providers.SourceError{eksSourceDiagnostic("nodegroup_list_failed", clusterName, fmt.Sprintf("EKS node groups could not be listed: %v", err), true)}
		}
		if output != nil {
			nodegroupNames = append(nodegroupNames, output.Nodegroups...)
		}
		nextToken := ""
		if output != nil {
			nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		}
		if nextToken == "" {
			break
		}
		input.NextToken = awsv2.String(nextToken)
	}

	nodegroups := []ekstypes.Nodegroup{}
	diagnostics := []providers.SourceError{}
	for _, nodegroupName := range normalizeStringList(nodegroupNames) {
		if err := ctx.Err(); err != nil {
			return nodegroups, diagnostics
		}
		output, err := a.eksClient.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
			ClusterName:   awsv2.String(clusterName),
			NodegroupName: awsv2.String(nodegroupName),
		})
		if err != nil {
			if ctx.Err() != nil {
				return nodegroups, diagnostics
			}
			diagnostics = append(diagnostics, eksSourceDiagnostic("nodegroup_describe_failed", nodegroupName, fmt.Sprintf("EKS node group could not be described: %v", err), true))
			continue
		}
		if output != nil && output.Nodegroup != nil {
			nodegroups = append(nodegroups, *output.Nodegroup)
		}
	}
	return nodegroups, diagnostics
}

func (a *SDKEKSWorkloadIdentityAPI) fargateProfilesForCluster(ctx context.Context, clusterName string, pageSize int32) ([]ekstypes.FargateProfile, []providers.SourceError) {
	input := &eks.ListFargateProfilesInput{
		ClusterName: awsv2.String(clusterName),
		MaxResults:  awsv2.Int32(pageSize),
	}
	profileNames := []string{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, []providers.SourceError{eksSourceDiagnostic("fargate_profile_list_failed", clusterName, err.Error(), true)}
		}
		output, err := a.eksClient.ListFargateProfiles(ctx, input)
		if err != nil {
			return nil, []providers.SourceError{eksSourceDiagnostic("fargate_profile_list_failed", clusterName, fmt.Sprintf("EKS Fargate profiles could not be listed: %v", err), true)}
		}
		if output != nil {
			profileNames = append(profileNames, output.FargateProfileNames...)
		}
		nextToken := ""
		if output != nil {
			nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		}
		if nextToken == "" {
			break
		}
		input.NextToken = awsv2.String(nextToken)
	}

	profiles := []ekstypes.FargateProfile{}
	diagnostics := []providers.SourceError{}
	for _, profileName := range normalizeStringList(profileNames) {
		if err := ctx.Err(); err != nil {
			return profiles, diagnostics
		}
		output, err := a.eksClient.DescribeFargateProfile(ctx, &eks.DescribeFargateProfileInput{
			ClusterName:        awsv2.String(clusterName),
			FargateProfileName: awsv2.String(profileName),
		})
		if err != nil {
			if ctx.Err() != nil {
				return profiles, diagnostics
			}
			diagnostics = append(diagnostics, eksSourceDiagnostic("fargate_profile_describe_failed", profileName, fmt.Sprintf("EKS Fargate profile could not be described: %v", err), true))
			continue
		}
		if output != nil && output.FargateProfile != nil {
			profiles = append(profiles, *output.FargateProfile)
		}
	}
	return profiles, diagnostics
}

func (a *SDKEKSWorkloadIdentityAPI) clusterCoreRecord(cluster ekstypes.Cluster) EKSWorkloadIdentity {
	clusterARN := strings.TrimSpace(awsv2.ToString(cluster.Arn))
	clusterName := firstNonEmptyAWSValue(awsv2.ToString(cluster.Name), eksNameFromARN(clusterARN))
	issuer := eksClusterOIDCIssuer(cluster)
	return EKSWorkloadIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: a.accountID,
			Region:    a.region,
			Service:   eksServiceName,
		},
		ClusterARN:        clusterARN,
		ClusterName:       clusterName,
		ClusterStatus:     string(cluster.Status),
		KubernetesVersion: awsv2.ToString(cluster.Version),
		OIDCIssuer:        issuer,
		OIDCProviderARN:   oidcProviderARNFromIssuer(a.accountID, issuer),
		ClusterTags:       copyTags(cluster.Tags),
	}
}

func (a *SDKEKSWorkloadIdentityAPI) clusterCoreRecordFromName(clusterName string) EKSWorkloadIdentity {
	return EKSWorkloadIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: a.accountID,
			Region:    a.region,
			Service:   eksServiceName,
		},
		ClusterName:            strings.TrimSpace(clusterName),
		KubernetesAccessStatus: "aws_metadata_only",
	}
}

func (a *SDKEKSWorkloadIdentityAPI) recordFromPodIdentityAssociation(cluster EKSWorkloadIdentity, association ekstypes.PodIdentityAssociation) EKSWorkloadIdentity {
	roleARN := strings.TrimSpace(awsv2.ToString(association.RoleArn))
	namespace := strings.TrimSpace(awsv2.ToString(association.Namespace))
	serviceAccount := strings.TrimSpace(awsv2.ToString(association.ServiceAccount))
	associationARN := strings.TrimSpace(awsv2.ToString(association.AssociationArn))
	record := cluster
	record.RoleKind = eksRoleKindPodIdentity
	record.RoleARN = roleARN
	record.RoleName = roleNameFromARN(roleARN)
	record.Namespace = namespace
	record.ServiceAccount = serviceAccount
	record.KubernetesSubject = eksKubernetesSubject(namespace, serviceAccount)
	record.AssociationARN = associationARN
	record.AssociationID = strings.TrimSpace(awsv2.ToString(association.AssociationId))
	record.AssociationOwnerARN = strings.TrimSpace(awsv2.ToString(association.OwnerArn))
	record.ExternalID = strings.TrimSpace(awsv2.ToString(association.ExternalId))
	record.DisableSessionTags = awsv2.ToBool(association.DisableSessionTags)
	record.TargetRoleARN = strings.TrimSpace(awsv2.ToString(association.TargetRoleArn))
	record.KubernetesAccessStatus = "aws_metadata_only"
	record.Tags = copyTags(association.Tags)
	record.WorkloadID = firstNonEmptyAWSValue(associationARN, record.KubernetesSubject)
	record.WorkloadType = "eks_service_account"
	record.WorkloadName = firstNonEmptyAWSValue(record.KubernetesSubject, "eks service account")
	record.Source = "listpodidentityassociations"
	record.EvidenceRef = firstNonEmptyAWSValue(associationARN, record.KubernetesSubject)
	record.CollectorName = eksWorkloadIdentityCollectorName
	record.Confidence = eksWorkloadIdentityConfidence(record)
	return record
}

func (a *SDKEKSWorkloadIdentityAPI) recordFromNodegroup(cluster EKSWorkloadIdentity, nodegroup ekstypes.Nodegroup) EKSWorkloadIdentity {
	roleARN := strings.TrimSpace(awsv2.ToString(nodegroup.NodeRole))
	nodegroupARN := strings.TrimSpace(awsv2.ToString(nodegroup.NodegroupArn))
	record := cluster
	record.RoleKind = eksRoleKindNodeRole
	record.RoleARN = roleARN
	record.RoleName = roleNameFromARN(roleARN)
	record.NodegroupARN = nodegroupARN
	record.NodegroupName = firstNonEmptyAWSValue(awsv2.ToString(nodegroup.NodegroupName), eksNameFromARN(nodegroupARN))
	record.NodegroupStatus = string(nodegroup.Status)
	record.NodeRoleARN = roleARN
	record.KubernetesAccessStatus = "aws_metadata_only"
	record.Tags = copyTags(nodegroup.Tags)
	record.WorkloadID = firstNonEmptyAWSValue(nodegroupARN, record.NodegroupName)
	record.WorkloadType = "eks_node_group"
	record.WorkloadName = firstNonEmptyAWSValue(record.NodegroupName, "eks node group")
	record.Source = "describenodegroup"
	record.EvidenceRef = firstNonEmptyAWSValue(nodegroupARN, record.NodegroupName)
	record.CollectorName = eksWorkloadIdentityCollectorName
	record.Confidence = eksWorkloadIdentityConfidence(record)
	return record
}

func (a *SDKEKSWorkloadIdentityAPI) recordFromFargateProfile(cluster EKSWorkloadIdentity, profile ekstypes.FargateProfile) EKSWorkloadIdentity {
	roleARN := strings.TrimSpace(awsv2.ToString(profile.PodExecutionRoleArn))
	profileARN := strings.TrimSpace(awsv2.ToString(profile.FargateProfileArn))
	record := cluster
	record.RoleKind = eksRoleKindFargatePodExecution
	record.RoleARN = roleARN
	record.RoleName = roleNameFromARN(roleARN)
	record.FargateProfileARN = profileARN
	record.FargateProfileName = firstNonEmptyAWSValue(awsv2.ToString(profile.FargateProfileName), eksNameFromARN(profileARN))
	record.FargateProfileStatus = string(profile.Status)
	record.PodExecutionRoleARN = roleARN
	record.SelectorNamespaces = eksFargateSelectorNamespaces(profile.Selectors)
	record.SelectorLabels = eksFargateSelectorLabels(profile.Selectors)
	record.SubnetIDs = normalizeStringList(profile.Subnets)
	record.KubernetesAccessStatus = "aws_metadata_only"
	record.Tags = copyTags(profile.Tags)
	record.WorkloadID = firstNonEmptyAWSValue(profileARN, record.FargateProfileName)
	record.WorkloadType = "eks_fargate_pod_execution_role"
	record.WorkloadName = firstNonEmptyAWSValue(record.FargateProfileName, "eks fargate profile")
	record.Source = "describefargateprofile"
	record.EvidenceRef = firstNonEmptyAWSValue(profileARN, record.FargateProfileName)
	record.CollectorName = eksWorkloadIdentityCollectorName
	record.Confidence = eksWorkloadIdentityConfidence(record)
	return record
}

func eksSDKPageSize(pageSize int32) int32 {
	if pageSize < 1 {
		return defaultPageSize
	}
	if pageSize > 100 {
		return 100
	}
	return pageSize
}

func eksClusterOIDCIssuer(cluster ekstypes.Cluster) string {
	if cluster.Identity == nil || cluster.Identity.Oidc == nil {
		return ""
	}
	return strings.TrimSpace(awsv2.ToString(cluster.Identity.Oidc.Issuer))
}

func eksFargateSelectorNamespaces(selectors []ekstypes.FargateProfileSelector) []string {
	values := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		if namespace := strings.TrimSpace(awsv2.ToString(selector.Namespace)); namespace != "" {
			values = append(values, namespace)
		}
	}
	return normalizeStringList(values)
}

func eksFargateSelectorLabels(selectors []ekstypes.FargateProfileSelector) []string {
	values := []string{}
	for _, selector := range selectors {
		keys := make([]string, 0, len(selector.Labels))
		for key := range selector.Labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := strings.TrimSpace(selector.Labels[key])
			if strings.TrimSpace(key) == "" {
				continue
			}
			if value == "" {
				values = append(values, key)
			} else {
				values = append(values, key+"="+value)
			}
		}
	}
	return normalizeStringList(values)
}

func irsaAnnotationCoverageDiagnostics(cluster EKSWorkloadIdentity) []providers.SourceError {
	if strings.TrimSpace(cluster.OIDCIssuer) == "" && strings.TrimSpace(cluster.OIDCProviderARN) == "" {
		return nil
	}
	sourceID := firstNonEmptyAWSValue(cluster.ClusterARN, cluster.ClusterName)
	return []providers.SourceError{eksSourceDiagnostic(
		"irsa_annotation_collection_unconfigured",
		sourceID,
		"EKS cluster has OIDC metadata, but AWS-only collection cannot read Kubernetes service-account IRSA annotations",
		false,
	)}
}

func eksSourceDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: eksWorkloadIdentityCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      code,
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}
