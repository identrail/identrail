package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

const (
	policyTypeKey   = "policy_type"
	policyTypePerm  = "permission"
	policyTypeTrust = "trust"
	identityIDKey   = "identity_id"
	statementsKey   = "statements"
	principalsKey   = "principals"
)

// RoleNormalizer transforms raw IAM role assets into provider-agnostic entities.
type RoleNormalizer struct{}

var _ providers.Normalizer = (*RoleNormalizer)(nil)

// NewRoleNormalizer returns the AWS role normalizer.
func NewRoleNormalizer() *RoleNormalizer {
	return &RoleNormalizer{}
}

// Normalize converts AWS role and workload assets to normalized entities.
func (n *RoleNormalizer) Normalize(ctx context.Context, raw []providers.RawAsset) (providers.NormalizedBundle, error) {
	bundle := providers.NormalizedBundle{
		Identities: make([]domain.Identity, 0, len(raw)),
		Policies:   make([]domain.Policy, 0, len(raw)*2),
		Workloads:  make([]domain.Workload, 0, len(raw)),
		Resources:  make([]domain.Resource, 0, len(raw)),
	}

	identitySeen := map[string]struct{}{}
	policySeen := map[string]struct{}{}
	workloadSeen := map[string]struct{}{}
	resourceSeen := map[string]struct{}{}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindSecretsManagerMetadata {
			continue
		}
		if err := normalizeSecretsManagerMetadataAsset(asset, i, &bundle, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != "iam_role" {
			continue
		}
		if err := normalizeIAMRoleAsset(asset, i, &bundle, identitySeen, policySeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindEC2InstanceProfile {
			continue
		}
		if err := normalizeEC2InstanceProfileAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindECSTaskRole {
			continue
		}
		if err := normalizeECSTaskRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindLambdaExecutionRole {
			continue
		}
		if err := normalizeLambdaExecutionRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindCodeBuildServiceRole {
			continue
		}
		if err := normalizeCodeBuildServiceRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindCodePipelineDeploymentRole {
			continue
		}
		if err := normalizeCodePipelineDeploymentRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindStepFunctionsStateMachineRole {
			continue
		}
		if err := normalizeStepFunctionsStateMachineRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindEventDrivenRole {
			continue
		}
		if err := normalizeEventDrivenRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindManagedComputeRole {
			continue
		}
		if err := normalizeManagedComputeRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindEKSWorkloadIdentity {
			continue
		}
		if err := normalizeEKSWorkloadIdentityAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindSageMakerWorkloadRole {
			continue
		}
		if err := normalizeSageMakerWorkloadRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindIAMPassRoleRelationship {
			continue
		}
		if err := normalizeIAMPassRoleRelationshipAsset(asset, i, &bundle, identitySeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindS3BucketReachability {
			continue
		}
		if err := normalizeS3BucketReachabilityAsset(asset, i, &bundle, identitySeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != rawKindKMSDecryptReachability {
			continue
		}
		if err := normalizeKMSDecryptReachabilityAsset(asset, i, &bundle, identitySeen, resourceSeen); err != nil {
			return providers.NormalizedBundle{}, err
		}
	}

	return bundle, nil
}

func normalizeIAMRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, policySeen map[string]struct{}) error {
	var role IAMRole
	if err := json.Unmarshal(asset.Payload, &role); err != nil {
		return fmt.Errorf("decode iam role asset[%d]: %w", index, err)
	}
	arn := strings.TrimSpace(role.ARN)
	if arn == "" {
		return nil
	}

	identityID := identityIDFromARN(arn)
	if _, exists := identitySeen[identityID]; !exists {
		identitySeen[identityID] = struct{}{}
		bundle.Identities = append(bundle.Identities, domain.Identity{
			ID:         identityID,
			Provider:   domain.ProviderAWS,
			Type:       domain.IdentityTypeRole,
			Name:       strings.TrimSpace(role.Name),
			ARN:        arn,
			OwnerHint:  ownerHintFromTags(role.Tags),
			CreatedAt:  derefTimeOrZero(role.CreatedAt),
			LastUsedAt: role.LastUsedAt,
			Tags:       copyTags(role.Tags),
			RawRef:     asset.SourceID,
		})
	}

	permissionPolicies, err := normalizePermissionPolicies(identityID, role.PermissionPolicies)
	if err != nil {
		return fmt.Errorf("normalize permission policies for %s: %w", arn, err)
	}
	for _, policy := range permissionPolicies {
		if _, exists := policySeen[policy.ID]; exists {
			continue
		}
		policySeen[policy.ID] = struct{}{}
		bundle.Policies = append(bundle.Policies, policy)
	}

	trustPolicy, err := normalizeTrustPolicy(identityID, role.AssumeRolePolicyDocument)
	if err != nil {
		return fmt.Errorf("normalize trust policy for %s: %w", arn, err)
	}
	if trustPolicy != nil {
		if _, exists := policySeen[trustPolicy.ID]; !exists {
			policySeen[trustPolicy.ID] = struct{}{}
			bundle.Policies = append(bundle.Policies, *trustPolicy)
		}
	}
	return nil
}

func normalizeSecretsManagerMetadataAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, resourceSeen map[string]struct{}) error {
	var record SecretsManagerSecretMetadata
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode secrets manager metadata asset[%d]: %w", index, err)
	}
	secretARN := strings.TrimSpace(record.SecretARN)
	if secretARN == "" {
		return nil
	}
	resourceID := secretsManagerSecretResourceID(secretARN)
	if _, exists := resourceSeen[resourceID]; exists {
		return nil
	}
	resourceSeen[resourceID] = struct{}{}
	bundle.Resources = append(bundle.Resources, domain.Resource{
		ID:        resourceID,
		Provider:  domain.ProviderAWS,
		Type:      domain.ResourceTypeSecretsManager,
		Name:      firstNonEmptyAWSValue(record.SecretName, secretNameFromARN(secretARN), secretARN),
		ARN:       secretARN,
		Region:    strings.TrimSpace(record.Region),
		AccountID: strings.TrimSpace(record.AccountID),
		Labels:    copyTags(record.Tags),
		Metadata: map[string]any{
			"description_present":             record.DescriptionPresent,
			"kms_key_id":                      strings.TrimSpace(record.KMSKeyID),
			"kms_key_arn":                     strings.TrimSpace(record.KMSKeyARN),
			"owning_service":                  strings.TrimSpace(record.OwningService),
			"primary_region":                  strings.TrimSpace(record.PrimaryRegion),
			"secret_status":                   strings.TrimSpace(record.SecretStatus),
			"rotation_enabled":                record.RotationEnabled,
			"rotation_lambda_arn":             strings.TrimSpace(record.RotationLambdaARN),
			"rotation_interval_days":          record.RotationInterval,
			"created_at":                      strings.TrimSpace(record.CreatedAt),
			"last_changed_at":                 strings.TrimSpace(record.LastChangedAt),
			"last_accessed_at":                strings.TrimSpace(record.LastAccessedAt),
			"last_rotated_at":                 strings.TrimSpace(record.LastRotatedAt),
			"deleted_at":                      strings.TrimSpace(record.DeletedAt),
			"has_resource_policy":             record.HasResourcePolicy,
			"resource_policy_statement_count": record.ResourcePolicyStatementCount,
			"version_stage_count":             len(record.VersionStages),
			"replica_region_count":            len(record.ReplicaRegions),
			"exposure_classification":         record.ExposureClassification,
			"exposure_reasons":                append([]string(nil), record.ExposureReasons...),
			"identity_grant_count":            len(record.IdentityGrants),
			"public_grant_count":              secretsManagerPublicGrantCount(record.IdentityGrants),
			"cross_account_grant_count":       secretsManagerCrossAccountGrantCount(record.IdentityGrants),
			"reference_count":                 len(record.ReferencedBy),
			"referenced_by":                   secretReferenceMetadata(record.ReferencedBy),
			"unresolved_references":           secretReferenceMetadata(record.UnresolvedReferences),
		},
		RawRef: asset.SourceID,
	})
	return nil
}

func normalizeEC2InstanceProfileAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record EC2InstanceProfile
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode ec2 instance profile asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := ec2WorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      ec2WorkloadType(record),
				Name:      ec2WorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.InstanceID) != "" {
		instanceResourceID := ec2InstanceResourceID(record.AccountID, record.Region, record.InstanceID)
		if _, exists := resourceSeen[instanceResourceID]; !exists {
			resourceSeen[instanceResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, domain.Resource{
				ID:        instanceResourceID,
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeEC2Instance,
				Name:      ec2WorkloadName(record),
				ARN:       strings.TrimSpace(record.InstanceARN),
				Region:    strings.TrimSpace(record.Region),
				AccountID: strings.TrimSpace(record.AccountID),
				Labels:    copyTags(record.Tags),
				Metadata: map[string]any{
					"state":                   strings.TrimSpace(record.InstanceState),
					"instance_profile_arn":    strings.TrimSpace(record.InstanceProfileARN),
					"role_arn":                roleARN,
					"imds_endpoint":           strings.TrimSpace(record.IMDSEndpoint),
					"imds_http_tokens":        strings.TrimSpace(record.IMDSHTTPTokens),
					"imds_hop_limit":          record.IMDSHopLimit,
					"launch_template_id":      strings.TrimSpace(record.LaunchTemplateID),
					"launch_template_name":    strings.TrimSpace(record.LaunchTemplateName),
					"launch_template_version": strings.TrimSpace(record.LaunchTemplateVersion),
				},
				RawRef:         asset.SourceID,
				SourceEntityID: workloadID,
			})
		}
	}

	if strings.TrimSpace(record.InstanceProfileARN) != "" {
		profileResourceID := ec2InstanceProfileResourceID(record.InstanceProfileARN)
		if _, exists := resourceSeen[profileResourceID]; !exists {
			resourceSeen[profileResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, domain.Resource{
				ID:        profileResourceID,
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeEC2InstanceProfile,
				Name:      firstNonEmptyAWSValue(record.InstanceProfileName, roleNameFromARN(record.InstanceProfileARN)),
				ARN:       strings.TrimSpace(record.InstanceProfileARN),
				Region:    strings.TrimSpace(record.Region),
				AccountID: strings.TrimSpace(record.AccountID),
				Labels:    copyTags(record.Tags),
				Metadata: map[string]any{
					"instance_profile_id": strings.TrimSpace(record.InstanceProfileID),
					"role_arn":            roleARN,
					"workload_id":         workloadID,
					"workload_type":       ec2WorkloadType(record),
				},
				RawRef:         asset.SourceID,
				SourceEntityID: roleIdentityID,
			})
		}
	}

	return nil
}

func normalizeECSTaskRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record ECSTaskRole
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode ecs task role asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := ecsRoleWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      ecsRoleWorkloadType(record),
				Name:      ecsRoleWorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.ServiceARN) != "" {
		serviceResourceID := ecsServiceResourceID(record.ServiceARN)
		if _, exists := resourceSeen[serviceResourceID]; !exists {
			resourceSeen[serviceResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, domain.Resource{
				ID:        serviceResourceID,
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeECSService,
				Name:      firstNonEmptyAWSValue(record.ServiceName, ecsNameFromARN(record.ServiceARN)),
				ARN:       strings.TrimSpace(record.ServiceARN),
				Region:    strings.TrimSpace(record.Region),
				AccountID: strings.TrimSpace(record.AccountID),
				Labels:    copyTags(record.Tags),
				Metadata: map[string]any{
					"cluster_arn":              strings.TrimSpace(record.ClusterARN),
					"cluster_name":             strings.TrimSpace(record.ClusterName),
					"service_status":           strings.TrimSpace(record.ServiceStatus),
					"task_definition_arn":      strings.TrimSpace(record.TaskDefinitionARN),
					"task_definition_family":   strings.TrimSpace(record.TaskDefinitionFamily),
					"task_definition_revision": strings.TrimSpace(record.TaskDefinitionRevision),
					"task_definition_status":   strings.TrimSpace(record.TaskDefinitionStatus),
					"task_role_arn":            strings.TrimSpace(record.TaskRoleARN),
					"execution_role_arn":       strings.TrimSpace(record.ExecutionRoleARN),
					"launch_type":              strings.TrimSpace(record.LaunchType),
					"scheduling_strategy":      strings.TrimSpace(record.SchedulingStrategy),
					"desired_count":            record.DesiredCount,
					"running_count":            record.RunningCount,
					"pending_count":            record.PendingCount,
					"compatibilities":          append([]string(nil), record.Compatibilities...),
					"container_images":         append([]string(nil), record.ContainerImages...),
					"secret_refs":              append([]string(nil), record.SecretRefs...),
					"environment_keys":         append([]string(nil), record.EnvironmentKeys...),
				},
				RawRef:         asset.SourceID,
				SourceEntityID: workloadID,
			})
		}
	}

	if strings.TrimSpace(record.TaskDefinitionARN) != "" {
		taskDefinitionResourceID := ecsTaskDefinitionResourceID(record.TaskDefinitionARN)
		if _, exists := resourceSeen[taskDefinitionResourceID]; !exists {
			resourceSeen[taskDefinitionResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, domain.Resource{
				ID:        taskDefinitionResourceID,
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeECSTask,
				Name:      firstNonEmptyAWSValue(record.TaskDefinitionFamily, ecsNameFromARN(record.TaskDefinitionARN)),
				ARN:       strings.TrimSpace(record.TaskDefinitionARN),
				Region:    strings.TrimSpace(record.Region),
				AccountID: strings.TrimSpace(record.AccountID),
				Labels:    copyTags(record.Tags),
				Metadata: map[string]any{
					"family":              strings.TrimSpace(record.TaskDefinitionFamily),
					"revision":            strings.TrimSpace(record.TaskDefinitionRevision),
					"status":              strings.TrimSpace(record.TaskDefinitionStatus),
					"task_role_arn":       strings.TrimSpace(record.TaskRoleARN),
					"execution_role_arn":  strings.TrimSpace(record.ExecutionRoleARN),
					"service_arn":         strings.TrimSpace(record.ServiceARN),
					"service_name":        strings.TrimSpace(record.ServiceName),
					"cluster_arn":         strings.TrimSpace(record.ClusterARN),
					"cluster_name":        strings.TrimSpace(record.ClusterName),
					"launch_type":         strings.TrimSpace(record.LaunchType),
					"scheduling_strategy": strings.TrimSpace(record.SchedulingStrategy),
					"compatibilities":     append([]string(nil), record.Compatibilities...),
					"container_images":    append([]string(nil), record.ContainerImages...),
					"secret_refs":         append([]string(nil), record.SecretRefs...),
					"environment_keys":    append([]string(nil), record.EnvironmentKeys...),
				},
				RawRef:         asset.SourceID,
				SourceEntityID: workloadID,
			})
		}
	}

	return nil
}

func normalizeLambdaExecutionRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record LambdaExecutionRole
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode lambda execution role asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := lambdaRoleWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      "lambda_function",
				Name:      lambdaRoleWorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.FunctionARN) != "" {
		functionResourceID := lambdaFunctionResourceID(record.FunctionARN)
		if _, exists := resourceSeen[functionResourceID]; !exists {
			resourceSeen[functionResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, domain.Resource{
				ID:        functionResourceID,
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeLambdaFunction,
				Name:      lambdaRoleWorkloadName(record),
				ARN:       strings.TrimSpace(record.FunctionARN),
				Region:    strings.TrimSpace(record.Region),
				AccountID: strings.TrimSpace(record.AccountID),
				Labels:    copyTags(record.Tags),
				Metadata: map[string]any{
					"role_arn":                      roleARN,
					"function_name":                 strings.TrimSpace(record.FunctionName),
					"function_version":              strings.TrimSpace(record.FunctionVersion),
					"function_state":                strings.TrimSpace(record.FunctionState),
					"last_update_status":            strings.TrimSpace(record.LastUpdateStatus),
					"runtime":                       strings.TrimSpace(record.Runtime),
					"package_type":                  strings.TrimSpace(record.PackageType),
					"handler":                       strings.TrimSpace(record.Handler),
					"kms_key_arn":                   strings.TrimSpace(record.KMSKeyARN),
					"memory_size":                   record.MemorySize,
					"timeout":                       record.Timeout,
					"vpc_id":                        strings.TrimSpace(record.VPCID),
					"subnet_ids":                    append([]string(nil), record.SubnetIDs...),
					"security_group_ids":            append([]string(nil), record.SecurityGroupIDs...),
					"architectures":                 append([]string(nil), record.Architectures...),
					"layer_arns":                    append([]string(nil), record.LayerARNs...),
					"alias_names":                   append([]string(nil), record.AliasNames...),
					"version_refs":                  append([]string(nil), record.VersionRefs...),
					"event_source_arns":             append([]string(nil), record.EventSourceARNs...),
					"event_source_mapping_uuids":    append([]string(nil), record.EventSourceMappingUUIDs...),
					"disabled_event_source_arns":    append([]string(nil), record.DisabledEventSourceARNs...),
					"disabled_event_source_reasons": append([]string(nil), record.DisabledEventSourceReasons...),
					"environment_keys":              append([]string(nil), record.EnvironmentKeys...),
					"secret_refs":                   append([]string(nil), record.SecretRefs...),
				},
				RawRef:         asset.SourceID,
				SourceEntityID: workloadID,
			})
		}
	}

	return nil
}

func normalizeCodeBuildServiceRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record CodeBuildServiceRole
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode codebuild service role asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := codeBuildRoleWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      "codebuild_project",
				Name:      codeBuildRoleWorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.ProjectARN) != "" {
		projectResourceID := codeBuildProjectResourceID(record.ProjectARN)
		if _, exists := resourceSeen[projectResourceID]; !exists {
			resourceSeen[projectResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, domain.Resource{
				ID:        projectResourceID,
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeCodeBuildProject,
				Name:      codeBuildRoleWorkloadName(record),
				ARN:       strings.TrimSpace(record.ProjectARN),
				Region:    strings.TrimSpace(record.Region),
				AccountID: strings.TrimSpace(record.AccountID),
				Labels:    copyTags(record.Tags),
				Metadata: map[string]any{
					"role_arn":                    roleARN,
					"project_name":                strings.TrimSpace(record.ProjectName),
					"project_visibility":          strings.TrimSpace(record.ProjectVisibility),
					"source_type":                 strings.TrimSpace(record.SourceType),
					"source_location":             strings.TrimSpace(record.SourceLocation),
					"source_auth_type":            strings.TrimSpace(record.SourceAuthType),
					"source_version":              strings.TrimSpace(record.SourceVersion),
					"source_identifiers":          append([]string(nil), record.SourceIdentifiers...),
					"artifact_types":              append([]string(nil), record.ArtifactTypes...),
					"artifact_locations":          append([]string(nil), record.ArtifactLocations...),
					"environment_type":            strings.TrimSpace(record.EnvironmentType),
					"compute_type":                strings.TrimSpace(record.ComputeType),
					"image":                       strings.TrimSpace(record.Image),
					"image_pull_credentials_type": strings.TrimSpace(record.ImagePullCredentialsType),
					"privileged_mode":             record.PrivilegedMode,
					"kms_key_arn":                 strings.TrimSpace(record.KMSKeyARN),
					"cache_type":                  strings.TrimSpace(record.CacheType),
					"cache_location":              strings.TrimSpace(record.CacheLocation),
					"log_types":                   append([]string(nil), record.LogTypes...),
					"vpc_id":                      strings.TrimSpace(record.VPCID),
					"subnet_ids":                  append([]string(nil), record.SubnetIDs...),
					"security_group_ids":          append([]string(nil), record.SecurityGroupIDs...),
					"environment_keys":            append([]string(nil), record.EnvironmentKeys...),
					"secret_refs":                 append([]string(nil), record.SecretRefs...),
				},
				RawRef:         asset.SourceID,
				SourceEntityID: workloadID,
			})
		}
	}

	return nil
}

func normalizeCodePipelineDeploymentRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record CodePipelineDeploymentRole
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode codepipeline deployment role asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := codePipelineRoleWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      codePipelineRoleWorkloadType(record),
				Name:      codePipelineRoleWorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.PipelineARN) != "" {
		pipelineResourceID := codePipelineResourceID(record.PipelineARN)
		resource := codePipelineResourceFromRecord(record, asset.SourceID, workloadID, roleARN)
		if _, exists := resourceSeen[pipelineResourceID]; !exists {
			resourceSeen[pipelineResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, resource)
		} else if strings.EqualFold(record.RoleKind, "pipeline_service_role") {
			for idx := range bundle.Resources {
				if bundle.Resources[idx].ID == pipelineResourceID {
					bundle.Resources[idx] = resource
					break
				}
			}
		}
	}

	return nil
}

func codePipelineResourceFromRecord(record CodePipelineDeploymentRole, rawRef string, workloadID string, roleARN string) domain.Resource {
	return domain.Resource{
		ID:        codePipelineResourceID(record.PipelineARN),
		Provider:  domain.ProviderAWS,
		Type:      domain.ResourceTypeCodePipeline,
		Name:      firstNonEmptyAWSValue(record.PipelineName, codePipelineNameFromARN(record.PipelineARN)),
		ARN:       strings.TrimSpace(record.PipelineARN),
		Region:    strings.TrimSpace(record.Region),
		AccountID: strings.TrimSpace(record.AccountID),
		Labels:    copyTags(record.Tags),
		Metadata: map[string]any{
			"role_arn":                     roleARN,
			"role_account_id":              strings.TrimSpace(record.RoleAccountID),
			"role_kind":                    strings.TrimSpace(record.RoleKind),
			"pipeline_name":                strings.TrimSpace(record.PipelineName),
			"pipeline_version":             record.PipelineVersion,
			"pipeline_type":                strings.TrimSpace(record.PipelineType),
			"execution_mode":               strings.TrimSpace(record.ExecutionMode),
			"stage_name":                   strings.TrimSpace(record.StageName),
			"action_name":                  strings.TrimSpace(record.ActionName),
			"action_category":              strings.TrimSpace(record.ActionCategory),
			"action_owner":                 strings.TrimSpace(record.ActionOwner),
			"action_provider":              strings.TrimSpace(record.ActionProvider),
			"action_region":                strings.TrimSpace(record.ActionRegion),
			"input_artifact_names":         append([]string(nil), record.InputArtifactNames...),
			"output_artifact_names":        append([]string(nil), record.OutputArtifactNames...),
			"artifact_store_types":         append([]string(nil), record.ArtifactStoreTypes...),
			"artifact_store_locations":     append([]string(nil), record.ArtifactStoreLocations...),
			"artifact_store_regions":       append([]string(nil), record.ArtifactStoreRegions...),
			"artifact_kms_key_arns":        append([]string(nil), record.ArtifactKMSKeyARNs...),
			"configuration_keys":           append([]string(nil), record.ConfigurationKeys...),
			"provider_identifiers":         append([]string(nil), record.ProviderIdentifiers...),
			"disabled_stage_transitions":   append([]string(nil), record.DisabledStageTransitions...),
			"cross_region_artifact_stores": record.CrossRegionArtifactStores,
			"cross_region_action":          record.CrossRegionAction,
			"cross_account_role":           record.CrossAccountRole,
			"pass_role_adjacent":           record.PassRoleAdjacent,
		},
		RawRef:         rawRef,
		SourceEntityID: workloadID,
	}
}

func normalizeStepFunctionsStateMachineRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record StepFunctionsStateMachineRole
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode stepfunctions state machine role asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := stepFunctionsRoleWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      "stepfunctions_state_machine",
				Name:      stepFunctionsRoleWorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.StateMachineARN) != "" {
		resourceID := stepFunctionsStateMachineResourceID(record.StateMachineARN)
		if _, exists := resourceSeen[resourceID]; !exists {
			resourceSeen[resourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, stepFunctionsResourceFromRecord(record, asset.SourceID, workloadID, roleARN))
		}
	}

	return nil
}

func stepFunctionsResourceFromRecord(record StepFunctionsStateMachineRole, rawRef string, workloadID string, roleARN string) domain.Resource {
	return domain.Resource{
		ID:        stepFunctionsStateMachineResourceID(record.StateMachineARN),
		Provider:  domain.ProviderAWS,
		Type:      domain.ResourceTypeStepFunctions,
		Name:      firstNonEmptyAWSValue(record.StateMachineName, stepFunctionsStateMachineNameFromARN(record.StateMachineARN)),
		ARN:       strings.TrimSpace(record.StateMachineARN),
		Region:    strings.TrimSpace(record.Region),
		AccountID: strings.TrimSpace(record.AccountID),
		Labels:    copyTags(record.Tags),
		Metadata: map[string]any{
			"role_arn":                       roleARN,
			"role_account_id":                strings.TrimSpace(record.RoleAccountID),
			"state_machine_name":             strings.TrimSpace(record.StateMachineName),
			"state_machine_type":             strings.TrimSpace(record.StateMachineType),
			"state_machine_status":           strings.TrimSpace(record.StateMachineStatus),
			"revision_id":                    strings.TrimSpace(record.RevisionID),
			"description":                    strings.TrimSpace(record.Description),
			"definition_sha256":              strings.TrimSpace(record.DefinitionSHA256),
			"definition_resource_arns":       append([]string(nil), record.DefinitionResourceARNs...),
			"task_resource_arns":             append([]string(nil), record.TaskResourceARNs...),
			"service_integration_resources":  append([]string(nil), record.ServiceIntegrationResources...),
			"nested_state_machine_arns":      append([]string(nil), record.NestedStateMachineARNs...),
			"logging_level":                  strings.TrimSpace(record.LoggingLevel),
			"logging_include_execution_data": record.LoggingIncludeExecutionData,
			"log_group_arns":                 append([]string(nil), record.LogGroupARNs...),
			"tracing_enabled":                record.TracingEnabled,
			"encryption_type":                strings.TrimSpace(record.EncryptionType),
			"kms_key_arn":                    strings.TrimSpace(record.KMSKeyARN),
		},
		RawRef:         rawRef,
		SourceEntityID: workloadID,
	}
}

func normalizeEventDrivenRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record EventDrivenRole
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode event-driven role asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := eventDrivenRoleWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      eventDrivenRoleWorkloadType(record),
				Name:      eventDrivenRoleWorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.WorkloadARN) != "" {
		resourceID := eventDrivenResourceID(record)
		if _, exists := resourceSeen[resourceID]; !exists {
			resourceSeen[resourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, eventDrivenResourceFromRecord(record, asset.SourceID, workloadID, roleARN))
		}
	}

	return nil
}

func eventDrivenResourceFromRecord(record EventDrivenRole, rawRef string, workloadID string, roleARN string) domain.Resource {
	return domain.Resource{
		ID:        eventDrivenResourceID(record),
		Provider:  domain.ProviderAWS,
		Type:      eventDrivenResourceType(record),
		Name:      eventDrivenRoleWorkloadName(record),
		ARN:       strings.TrimSpace(record.WorkloadARN),
		Region:    strings.TrimSpace(record.Region),
		AccountID: strings.TrimSpace(record.AccountID),
		Labels:    copyTags(record.Tags),
		Metadata: map[string]any{
			"service":                   strings.TrimSpace(record.Service),
			"role_arn":                  roleARN,
			"role_kind":                 strings.TrimSpace(record.RoleKind),
			"role_account_id":           strings.TrimSpace(record.RoleAccountID),
			"event_bus_name":            strings.TrimSpace(record.EventBusName),
			"event_bus_arn":             strings.TrimSpace(record.EventBusARN),
			"schedule_group_name":       strings.TrimSpace(record.ScheduleGroupName),
			"schedule_expression":       strings.TrimSpace(record.ScheduleExpression),
			"schedule_timezone":         strings.TrimSpace(record.ScheduleTimezone),
			"pipe_source_arn":           strings.TrimSpace(record.PipeSourceARN),
			"pipe_target_arn":           strings.TrimSpace(record.PipeTargetARN),
			"pipe_enrichment_arn":       strings.TrimSpace(record.PipeEnrichmentARN),
			"target_arn":                strings.TrimSpace(record.TargetARN),
			"target_id":                 strings.TrimSpace(record.TargetID),
			"target_service":            strings.TrimSpace(record.TargetService),
			"dead_letter_arns":          append([]string(nil), record.DeadLetterARNs...),
			"retry_maximum_age_seconds": record.RetryMaximumAgeSeconds,
			"retry_maximum_attempts":    record.RetryMaximumAttempts,
			"event_pattern_sha256":      strings.TrimSpace(record.EventPatternSHA256),
			"input_transformer_sha256":  strings.TrimSpace(record.InputTransformerSHA256),
			"input_path_configured":     record.InputPathConfigured,
			"target_input_configured":   record.TargetInputConfigured,
			"execution_data_logging":    record.ExecutionDataLogging,
			"log_destination_arns":      append([]string(nil), record.LogDestinationARNs...),
			"kms_key_arn":               strings.TrimSpace(record.KMSKeyARN),
			"active":                    record.Active,
			"disabled":                  record.Disabled,
			"state_reason":              strings.TrimSpace(record.StateReason),
		},
		RawRef:         rawRef,
		SourceEntityID: workloadID,
	}
}

func normalizeManagedComputeRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record ManagedComputeRole
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode managed compute role asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := managedComputeRoleWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      managedComputeRoleWorkloadType(record),
				Name:      managedComputeRoleWorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.WorkloadARN) != "" || strings.TrimSpace(record.ResourceARN) != "" {
		resourceID := managedComputeResourceID(record)
		if _, exists := resourceSeen[resourceID]; !exists {
			resourceSeen[resourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, managedComputeResourceFromRecord(record, asset.SourceID, workloadID, roleARN))
		} else {
			mergeManagedComputeResourceRoleMetadata(bundle, resourceID, record, roleARN)
		}
	}

	return nil
}

func managedComputeResourceFromRecord(record ManagedComputeRole, rawRef string, workloadID string, roleARN string) domain.Resource {
	return domain.Resource{
		ID:        managedComputeResourceID(record),
		Provider:  domain.ProviderAWS,
		Type:      managedComputeResourceType(record),
		Name:      managedComputeRoleWorkloadName(record),
		ARN:       firstNonEmptyAWSValue(record.ResourceARN, record.WorkloadARN),
		Region:    strings.TrimSpace(record.Region),
		AccountID: strings.TrimSpace(record.AccountID),
		Labels:    copyTags(record.Tags),
		Metadata: map[string]any{
			"service":             strings.TrimSpace(record.Service),
			"role_arn":            roleARN,
			"role_kind":           strings.TrimSpace(record.RoleKind),
			"role_account_id":     strings.TrimSpace(record.RoleAccountID),
			"resource_status":     strings.TrimSpace(record.ResourceStatus),
			"compute_engine":      strings.TrimSpace(record.ComputeEngine),
			"queue_arn":           strings.TrimSpace(record.QueueARN),
			"cluster_arn":         strings.TrimSpace(record.ClusterARN),
			"job_definition_arn":  strings.TrimSpace(record.JobDefinitionARN),
			"revision":            record.Revision,
			"coverage_status":     strings.TrimSpace(record.CoverageStatus),
			"coverage_reason":     strings.TrimSpace(record.CoverageReason),
			"unsupported_service": strings.TrimSpace(record.UnsupportedService),
			"active":              record.Active,
			"disabled":            record.Disabled,
			"roles":               []map[string]any{managedComputeResourceRoleMetadata(record, roleARN)},
		},
		RawRef:         rawRef,
		SourceEntityID: workloadID,
	}
}

func mergeManagedComputeResourceRoleMetadata(bundle *providers.NormalizedBundle, resourceID string, record ManagedComputeRole, roleARN string) {
	role := managedComputeResourceRoleMetadata(record, roleARN)
	if strings.TrimSpace(roleARN) == "" {
		return
	}
	for idx := range bundle.Resources {
		if bundle.Resources[idx].ID != resourceID {
			continue
		}
		if bundle.Resources[idx].Metadata == nil {
			bundle.Resources[idx].Metadata = map[string]any{}
		}
		roles, _ := bundle.Resources[idx].Metadata["roles"].([]map[string]any)
		for _, existing := range roles {
			if existingARN, _ := existing["role_arn"].(string); strings.TrimSpace(existingARN) == roleARN {
				return
			}
		}
		bundle.Resources[idx].Metadata["roles"] = append(roles, role)
		return
	}
}

func managedComputeResourceRoleMetadata(record ManagedComputeRole, roleARN string) map[string]any {
	return map[string]any{
		"role_arn":        strings.TrimSpace(roleARN),
		"role_name":       strings.TrimSpace(firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(roleARN))),
		"role_kind":       strings.TrimSpace(record.RoleKind),
		"role_account_id": strings.TrimSpace(record.RoleAccountID),
		"confidence":      record.Confidence,
	}
}

func normalizeEKSWorkloadIdentityAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record EKSWorkloadIdentity
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode eks workload identity asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := eksWorkloadIdentityNormalizedWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      eksWorkloadIdentityNormalizedWorkloadType(record),
				Name:      eksWorkloadIdentityName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.ClusterARN) != "" {
		clusterResourceID := eksClusterResourceID(record.ClusterARN)
		if _, exists := resourceSeen[clusterResourceID]; !exists {
			resourceSeen[clusterResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, domain.Resource{
				ID:        clusterResourceID,
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeEKSCluster,
				Name:      firstNonEmptyAWSValue(record.ClusterName, eksNameFromARN(record.ClusterARN)),
				ARN:       strings.TrimSpace(record.ClusterARN),
				Region:    strings.TrimSpace(record.Region),
				AccountID: strings.TrimSpace(record.AccountID),
				Labels:    copyTags(record.ClusterTags),
				Metadata: map[string]any{
					"cluster_status":           strings.TrimSpace(record.ClusterStatus),
					"kubernetes_version":       strings.TrimSpace(record.KubernetesVersion),
					"oidc_issuer":              strings.TrimSpace(record.OIDCIssuer),
					"oidc_provider_arn":        strings.TrimSpace(record.OIDCProviderARN),
					"kubernetes_access_status": strings.TrimSpace(record.KubernetesAccessStatus),
				},
				RawRef:         asset.SourceID,
				SourceEntityID: workloadID,
			})
		}
	}

	if workloadID != "" {
		workloadResourceID := eksWorkloadResourceID(record)
		if _, exists := resourceSeen[workloadResourceID]; !exists {
			resourceSeen[workloadResourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, domain.Resource{
				ID:        workloadResourceID,
				Provider:  domain.ProviderAWS,
				Type:      domain.ResourceTypeEKSWorkload,
				Name:      eksWorkloadIdentityName(record),
				ARN:       firstNonEmptyAWSValue(record.AssociationARN, record.NodegroupARN, record.FargateProfileARN),
				Region:    strings.TrimSpace(record.Region),
				AccountID: strings.TrimSpace(record.AccountID),
				Labels:    copyTags(record.Tags),
				Metadata: map[string]any{
					"role_kind":                strings.TrimSpace(record.RoleKind),
					"role_arn":                 roleARN,
					"cluster_arn":              strings.TrimSpace(record.ClusterARN),
					"cluster_name":             strings.TrimSpace(record.ClusterName),
					"namespace":                strings.TrimSpace(record.Namespace),
					"service_account":          strings.TrimSpace(record.ServiceAccount),
					"kubernetes_subject":       strings.TrimSpace(record.KubernetesSubject),
					"association_arn":          strings.TrimSpace(record.AssociationARN),
					"association_id":           strings.TrimSpace(record.AssociationID),
					"association_owner_arn":    strings.TrimSpace(record.AssociationOwnerARN),
					"target_role_arn":          strings.TrimSpace(record.TargetRoleARN),
					"nodegroup_arn":            strings.TrimSpace(record.NodegroupARN),
					"nodegroup_name":           strings.TrimSpace(record.NodegroupName),
					"nodegroup_status":         strings.TrimSpace(record.NodegroupStatus),
					"fargate_profile_arn":      strings.TrimSpace(record.FargateProfileARN),
					"fargate_profile_name":     strings.TrimSpace(record.FargateProfileName),
					"fargate_profile_status":   strings.TrimSpace(record.FargateProfileStatus),
					"selector_namespaces":      append([]string(nil), record.SelectorNamespaces...),
					"selector_labels":          append([]string(nil), record.SelectorLabels...),
					"subnet_ids":               append([]string(nil), record.SubnetIDs...),
					"kubernetes_access_status": strings.TrimSpace(record.KubernetesAccessStatus),
					"irsa_annotation_keys":     append([]string(nil), record.IRSAAnnotationKeys...),
				},
				RawRef:         asset.SourceID,
				SourceEntityID: workloadID,
			})
		}
	}

	return nil
}

func normalizePermissionPolicies(identityID string, policies []IAMPermissionPolicy) ([]domain.Policy, error) {
	result := make([]domain.Policy, 0, len(policies))
	for idx, policy := range policies {
		doc, err := parsePolicyDocument(policy.Document)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.Name, err)
		}

		statements := make([]map[string]any, 0, len(doc.Statement))
		for _, statement := range doc.Statement {
			actions := parseStringList(statement.Action)
			resources := parseStringList(statement.Resource)
			if len(actions) == 0 || len(resources) == 0 {
				continue
			}
			normalized, ok := normalizedStatement(statement.Effect, actions, resources)
			if !ok {
				continue
			}
			statements = append(statements, normalized)
		}
		if len(statements) == 0 {
			continue
		}

		policyID := permissionPolicyID(identityID, policy.Name, idx)
		result = append(result, domain.Policy{
			ID:       policyID,
			Provider: domain.ProviderAWS,
			Name:     policy.Name,
			Document: []byte(policy.Document),
			Normalized: map[string]any{
				policyTypeKey: policyTypePerm,
				identityIDKey: identityID,
				statementsKey: statements,
			},
			RawRef: identityID,
		})
	}
	return result, nil
}

func normalizeTrustPolicy(identityID, rawTrustDocument string) (*domain.Policy, error) {
	doc, err := parsePolicyDocument(rawTrustDocument)
	if err != nil {
		return nil, err
	}
	if len(doc.Statement) == 0 {
		return nil, nil
	}

	principals := make([]string, 0, len(doc.Statement))
	for _, statement := range doc.Statement {
		if !strings.EqualFold(statement.Effect, "allow") {
			continue
		}
		principals = append(principals, parseAWSPrincipals(statement.Principal)...)
	}
	principals = dedupeStrings(principals)
	if len(principals) == 0 {
		return nil, nil
	}

	return &domain.Policy{
		ID:       trustPolicyID(identityID),
		Provider: domain.ProviderAWS,
		Name:     "assume-role-trust",
		Document: []byte(rawTrustDocument),
		Normalized: map[string]any{
			policyTypeKey: policyTypeTrust,
			identityIDKey: identityID,
			principalsKey: principals,
		},
		RawRef: identityID,
	}, nil
}

func ec2WorkloadID(record EC2InstanceProfile) string {
	workloadType := ec2WorkloadType(record)
	switch workloadType {
	case "ec2_launch_template":
		return ec2LaunchTemplateWorkloadID(record.AccountID, record.Region, firstNonEmptyAWSValue(record.LaunchTemplateID, record.WorkloadID), record.LaunchTemplateVersion)
	default:
		return ec2InstanceWorkloadID(record.AccountID, record.Region, firstNonEmptyAWSValue(record.InstanceID, record.WorkloadID))
	}
}

func ec2WorkloadType(record EC2InstanceProfile) string {
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "ec2_launch_template", "launch_template":
		return "ec2_launch_template"
	default:
		return "ec2_instance"
	}
}

func ec2WorkloadName(record EC2InstanceProfile) string {
	return firstNonEmptyAWSValue(record.WorkloadName, record.InstanceName, record.Tags["Name"], record.InstanceID, record.LaunchTemplateName, record.LaunchTemplateID, "ec2 workload")
}

func ecsRoleWorkloadID(record ECSTaskRole) string {
	return ecsWorkloadID(
		record.AccountID,
		record.Region,
		ecsBaseWorkloadType(record),
		firstNonEmptyAWSValue(record.WorkloadID, record.ServiceARN, record.TaskDefinitionARN, record.ServiceName, record.TaskDefinitionFamily),
		record.RoleKind,
	)
}

func ecsBaseWorkloadType(record ECSTaskRole) string {
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "ecs_service", "service":
		return "ecs_service"
	default:
		return "ecs_task_definition"
	}
}

func ecsRoleWorkloadType(record ECSTaskRole) string {
	base := ecsBaseWorkloadType(record)
	roleKind := normalizeECSRoleKind(record.RoleKind, record.RoleARN, record.TaskRoleARN, record.ExecutionRoleARN)
	return base + "_" + roleKind
}

func ecsRoleWorkloadName(record ECSTaskRole) string {
	roleKind := normalizeECSRoleKind(record.RoleKind, record.RoleARN, record.TaskRoleARN, record.ExecutionRoleARN)
	roleKindLabel := "task role"
	if roleKind == ecsRoleKindExecution {
		roleKindLabel = "execution role"
	}
	return firstNonEmptyAWSValue(record.WorkloadName, record.ServiceName, record.TaskDefinitionFamily, ecsNameFromARN(record.ServiceARN), ecsNameFromARN(record.TaskDefinitionARN), "ecs workload") + " " + roleKindLabel
}

func lambdaRoleWorkloadID(record LambdaExecutionRole) string {
	return lambdaFunctionWorkloadID(
		record.AccountID,
		record.Region,
		firstNonEmptyAWSValue(record.FunctionARN, record.WorkloadID, record.FunctionName),
	)
}

func lambdaRoleWorkloadName(record LambdaExecutionRole) string {
	return firstNonEmptyAWSValue(record.WorkloadName, record.FunctionName, lambdaFunctionNameFromARN(record.FunctionARN), "lambda function")
}

func codeBuildRoleWorkloadID(record CodeBuildServiceRole) string {
	return codeBuildProjectWorkloadID(
		record.AccountID,
		record.Region,
		firstNonEmptyAWSValue(record.ProjectARN, record.WorkloadID, record.ProjectName),
	)
}

func codeBuildRoleWorkloadName(record CodeBuildServiceRole) string {
	return firstNonEmptyAWSValue(record.WorkloadName, record.ProjectName, codeBuildProjectNameFromARN(record.ProjectARN), "codebuild project")
}

func codePipelineRoleWorkloadID(record CodePipelineDeploymentRole) string {
	return codePipelineWorkloadID(
		record.AccountID,
		record.Region,
		firstNonEmptyAWSValue(record.WorkloadID, record.PipelineARN, record.PipelineName),
		record.RoleKind,
	)
}

func codePipelineRoleWorkloadType(record CodePipelineDeploymentRole) string {
	if strings.EqualFold(record.RoleKind, "action_role") {
		return "codepipeline_action"
	}
	return "codepipeline_pipeline"
}

func codePipelineRoleWorkloadName(record CodePipelineDeploymentRole) string {
	if strings.EqualFold(record.RoleKind, "action_role") {
		return firstNonEmptyAWSValue(record.WorkloadName, strings.Join(normalizeStringList([]string{record.PipelineName, record.StageName, record.ActionName}), " / "), "codepipeline action")
	}
	return firstNonEmptyAWSValue(record.WorkloadName, record.PipelineName, codePipelineNameFromARN(record.PipelineARN), "codepipeline pipeline")
}

func stepFunctionsRoleWorkloadID(record StepFunctionsStateMachineRole) string {
	return stepFunctionsStateMachineWorkloadID(
		record.AccountID,
		record.Region,
		firstNonEmptyAWSValue(record.WorkloadID, record.StateMachineARN, record.StateMachineName),
	)
}

func stepFunctionsRoleWorkloadName(record StepFunctionsStateMachineRole) string {
	return firstNonEmptyAWSValue(record.WorkloadName, record.StateMachineName, stepFunctionsStateMachineNameFromARN(record.StateMachineARN), "stepfunctions state machine")
}

func eventDrivenRoleWorkloadID(record EventDrivenRole) string {
	return eventDrivenWorkloadID(
		record.AccountID,
		record.Region,
		eventDrivenRoleWorkloadType(record),
		firstNonEmptyAWSValue(record.WorkloadID, record.WorkloadARN, record.WorkloadName),
		record.RoleKind,
	)
}

func eventDrivenRoleWorkloadType(record EventDrivenRole) string {
	return canonicalEventDrivenWorkloadType(record.WorkloadType, record.Service)
}

func eventDrivenRoleWorkloadName(record EventDrivenRole) string {
	return firstNonEmptyAWSValue(record.WorkloadName, eventDrivenNameFromARN(record.WorkloadARN), "event-driven workload")
}

func eventDrivenResourceType(record EventDrivenRole) domain.ResourceType {
	switch eventDrivenRoleWorkloadType(record) {
	case "scheduler_schedule":
		return domain.ResourceTypeSchedulerSchedule
	case "eventbridge_pipe":
		return domain.ResourceTypeEventBridgePipe
	default:
		return domain.ResourceTypeEventBridgeRule
	}
}

func managedComputeRoleWorkloadID(record ManagedComputeRole) string {
	return managedComputeWorkloadID(
		record.AccountID,
		record.Region,
		managedComputeRoleBaseWorkloadType(record),
		firstNonEmptyAWSValue(record.WorkloadID, record.WorkloadARN, record.ResourceARN, record.WorkloadName),
		record.RoleKind,
	)
}

func managedComputeRoleBaseWorkloadType(record ManagedComputeRole) string {
	if workloadType := strings.TrimSpace(record.WorkloadType); workloadType != "" {
		return workloadType
	}
	if resourceType := strings.TrimSpace(record.ResourceType); resourceType != "" {
		return resourceType
	}
	return managedComputeDefaultWorkloadType(record)
}

func managedComputeRoleWorkloadType(record ManagedComputeRole) string {
	baseType := managedComputeRoleBaseWorkloadType(record)
	roleKind := strings.ToLower(strings.TrimSpace(record.RoleKind))
	switch {
	case strings.Contains(roleKind, "execution_role"):
		return baseType + "_execution_role"
	case strings.Contains(roleKind, "access_role"):
		return baseType + "_access_role"
	default:
		return baseType
	}
}

func managedComputeRoleWorkloadName(record ManagedComputeRole) string {
	return firstNonEmptyAWSValue(record.WorkloadName, managedComputeNameFromARN(firstNonEmptyAWSValue(record.WorkloadARN, record.ResourceARN)), "managed compute workload")
}

func managedComputeNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 && idx < len(trimmed)-1 {
		return trimmed[idx+1:]
	}
	if idx := strings.LastIndex(trimmed, ":"); idx >= 0 && idx < len(trimmed)-1 {
		return trimmed[idx+1:]
	}
	return trimmed
}

func managedComputeResourceType(record ManagedComputeRole) domain.ResourceType {
	switch managedComputeRoleBaseWorkloadType(record) {
	case "apprunner_service":
		return domain.ResourceTypeAppRunnerService
	case "batch_compute_environment":
		return domain.ResourceTypeBatchComputeEnv
	case "batch_job_definition":
		return domain.ResourceTypeBatchJobDefinition
	case "glue_job":
		return domain.ResourceTypeGlueJob
	case "glue_crawler":
		return domain.ResourceTypeGlueCrawler
	case "emr_cluster":
		return domain.ResourceTypeEMRCluster
	default:
		return domain.ResourceTypeManagedCompute
	}
}

func eksWorkloadIdentityNormalizedWorkloadID(record EKSWorkloadIdentity) string {
	roleKind := normalizeEKSRoleKind(record.RoleKind, record)
	return eksWorkloadIdentityWorkloadID(
		record.AccountID,
		record.Region,
		eksWorkloadIdentityNormalizedWorkloadType(record),
		firstNonEmptyAWSValue(record.WorkloadID, record.AssociationARN, record.NodegroupARN, record.FargateProfileARN, record.KubernetesSubject),
		roleKind,
	)
}

func eksWorkloadIdentityNormalizedWorkloadType(record EKSWorkloadIdentity) string {
	switch normalizeEKSRoleKind(record.RoleKind, record) {
	case eksRoleKindNodeRole:
		return "eks_node_group"
	case eksRoleKindFargatePodExecution:
		return "eks_fargate_pod_execution_role"
	default:
		return "eks_service_account"
	}
}

func ownerHintFromTags(tags map[string]string) string {
	if tags == nil {
		return ""
	}
	for _, key := range []string{"owner", "team", "service"} {
		if value := strings.TrimSpace(tags[key]); value != "" {
			return value
		}
	}
	return ""
}

func copyTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	copied := make(map[string]string, len(tags))
	for key, value := range tags {
		copied[key] = value
	}
	return copied
}

func normalizeSageMakerWorkloadRoleAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, workloadSeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record SageMakerWorkloadRole
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode sagemaker workload role asset[%d]: %w", index, err)
	}

	roleARN := strings.TrimSpace(record.RoleARN)
	roleIdentityID := ""
	if roleARN != "" {
		roleIdentityID = identityIDFromARN(roleARN)
		roleName := strings.TrimSpace(record.RoleName)
		if roleName == "" {
			roleName = roleNameFromARN(roleARN)
		}
		if _, exists := identitySeen[roleIdentityID]; !exists {
			identitySeen[roleIdentityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        roleIdentityID,
				Provider:  domain.ProviderAWS,
				Type:      domain.IdentityTypeRole,
				Name:      roleName,
				ARN:       roleARN,
				OwnerHint: ownerHintFromTags(record.Tags),
				Tags:      copyTags(record.Tags),
				RawRef:    asset.SourceID,
			})
		}
	}

	workloadID := sageMakerRecordWorkloadID(record)
	if workloadID != "" {
		if _, exists := workloadSeen[workloadID]; !exists {
			workloadSeen[workloadID] = struct{}{}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID,
				Provider:  domain.ProviderAWS,
				Type:      sageMakerWorkloadType(record),
				Name:      sageMakerWorkloadName(record),
				AccountID: strings.TrimSpace(record.AccountID),
				Region:    strings.TrimSpace(record.Region),
				RawRef:    roleIdentityID,
			})
		}
	}

	if strings.TrimSpace(record.WorkloadARN) != "" || strings.TrimSpace(record.ResourceARN) != "" {
		resourceID := sageMakerResourceID(record)
		if _, exists := resourceSeen[resourceID]; !exists {
			resourceSeen[resourceID] = struct{}{}
			bundle.Resources = append(bundle.Resources, sageMakerResourceFromRecord(record, asset.SourceID, workloadID, roleARN))
		} else {
			mergeSageMakerResourceRoleMetadata(bundle, resourceID, record, roleARN)
		}
	}

	return nil
}

func sageMakerResourceFromRecord(record SageMakerWorkloadRole, rawRef string, workloadID string, roleARN string) domain.Resource {
	// model_arns is a slice so endpoints with multiple backing models keep
	// every model's evidence even when several variants share the same
	// execution role (the collector emits one record per backing model and
	// merge unions the remaining records' evidence into this resource).
	modelARNs := sageMakerInitialModelARNs(record.ModelARN)
	return domain.Resource{
		ID:        sageMakerResourceID(record),
		Provider:  domain.ProviderAWS,
		Type:      sageMakerResourceType(record),
		Name:      sageMakerWorkloadName(record),
		ARN:       firstNonEmptyAWSValue(record.ResourceARN, record.WorkloadARN),
		Region:    strings.TrimSpace(record.Region),
		AccountID: strings.TrimSpace(record.AccountID),
		Labels:    copyTags(record.Tags),
		Metadata: map[string]any{
			"service":         strings.TrimSpace(record.Service),
			"role_arn":        roleARN,
			"role_kind":       strings.TrimSpace(record.RoleKind),
			"role_account_id": strings.TrimSpace(record.RoleAccountID),
			"resource_status": strings.TrimSpace(record.ResourceStatus),
			"domain_id":       strings.TrimSpace(record.DomainID),
			"domain_arn":      strings.TrimSpace(record.DomainARN),
			"pipeline_arn":    strings.TrimSpace(record.PipelineARN),
			"model_arns":      modelARNs,
			"endpoint_config": strings.TrimSpace(record.EndpointConfig),
			"network_mode":    strings.TrimSpace(record.NetworkMode),
			"image_uris":      append([]string(nil), record.ImageURIs...),
			"s3_references":   append([]string(nil), record.S3References...),
			"kms_key_arns":    append([]string(nil), record.KMSKeyARNs...),
			"coverage_status": strings.TrimSpace(record.CoverageStatus),
			"coverage_reason": strings.TrimSpace(record.CoverageReason),
			"active":          record.Active,
			"disabled":        record.Disabled,
			"roles":           []map[string]any{sageMakerResourceRoleMetadata(record, roleARN)},
		},
		RawRef:         rawRef,
		SourceEntityID: workloadID,
	}
}

func sageMakerInitialModelARNs(modelARN string) []string {
	trimmed := strings.TrimSpace(modelARN)
	if trimmed == "" {
		return []string{}
	}
	return []string{trimmed}
}

// mergeSageMakerResourceRoleMetadata folds a follow-up record into an
// already-emitted resource. It always unions the per-record model ARN, image
// URI, S3 reference, and KMS key evidence onto the resource, so additional
// records for the same endpoint surface every backing model's evidence even
// when several variants share the same execution role. Roles are appended if
// the role ARN is not already present on the resource.
func mergeSageMakerResourceRoleMetadata(bundle *providers.NormalizedBundle, resourceID string, record SageMakerWorkloadRole, roleARN string) {
	for idx := range bundle.Resources {
		if bundle.Resources[idx].ID != resourceID {
			continue
		}
		if bundle.Resources[idx].Metadata == nil {
			bundle.Resources[idx].Metadata = map[string]any{}
		}
		meta := bundle.Resources[idx].Metadata
		meta["model_arns"] = sageMakerUnionStringEvidence(meta["model_arns"], []string{strings.TrimSpace(record.ModelARN)})
		meta["image_uris"] = sageMakerUnionStringEvidence(meta["image_uris"], record.ImageURIs)
		meta["s3_references"] = sageMakerUnionStringEvidence(meta["s3_references"], record.S3References)
		meta["kms_key_arns"] = sageMakerUnionStringEvidence(meta["kms_key_arns"], record.KMSKeyARNs)
		if trimmedRole := strings.TrimSpace(roleARN); trimmedRole != "" {
			roles, _ := meta["roles"].([]map[string]any)
			alreadyPresent := false
			for _, existing := range roles {
				if existingARN, _ := existing["role_arn"].(string); strings.TrimSpace(existingARN) == trimmedRole {
					alreadyPresent = true
					break
				}
			}
			if !alreadyPresent {
				meta["roles"] = append(roles, sageMakerResourceRoleMetadata(record, trimmedRole))
			}
		}
		return
	}
}

// sageMakerUnionStringEvidence appends trimmed, deduplicated values to an
// existing metadata slice, preserving insertion order so the first record's
// evidence stays at the front of the slice.
func sageMakerUnionStringEvidence(existing any, additions []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	if cur, ok := existing.([]string); ok {
		for _, value := range cur {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}
			if _, exists := seen[trimmed]; exists {
				continue
			}
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	for _, value := range additions {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func sageMakerResourceRoleMetadata(record SageMakerWorkloadRole, roleARN string) map[string]any {
	return map[string]any{
		"role_arn":        strings.TrimSpace(roleARN),
		"role_name":       strings.TrimSpace(firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(roleARN))),
		"role_kind":       strings.TrimSpace(record.RoleKind),
		"role_account_id": strings.TrimSpace(record.RoleAccountID),
		"confidence":      record.Confidence,
	}
}

func sageMakerRecordWorkloadID(record SageMakerWorkloadRole) string {
	workloadRef := firstNonEmptyAWSValue(record.WorkloadID, record.WorkloadARN, record.ResourceARN, record.WorkloadName)
	// Endpoints inherit one execution role per backing model, so the role
	// kind alone cannot discriminate variants whose models use different
	// roles. Without a model discriminator on the workload key, the second
	// record's workload entry is dropped by workloadSeen and the
	// relationship builder skips its workload→role edge. Embed the model
	// identity in the workload ref so each backing model produces its own
	// workload entry and downstream graph edge.
	if strings.EqualFold(strings.TrimSpace(record.WorkloadType), "sagemaker_endpoint") || strings.EqualFold(strings.TrimSpace(record.ResourceType), "sagemaker_endpoint") {
		if modelARN := strings.TrimSpace(record.ModelARN); modelARN != "" {
			workloadRef = workloadRef + "::" + modelARN
		}
	}
	return sageMakerWorkloadID(
		record.AccountID,
		record.Region,
		sageMakerBaseWorkloadType(record),
		workloadRef,
		record.RoleKind,
	)
}

func sageMakerBaseWorkloadType(record SageMakerWorkloadRole) string {
	if workloadType := strings.TrimSpace(record.WorkloadType); workloadType != "" {
		return workloadType
	}
	if resourceType := strings.TrimSpace(record.ResourceType); resourceType != "" {
		return resourceType
	}
	return sageMakerDefaultWorkloadType(record)
}

func sageMakerWorkloadType(record SageMakerWorkloadRole) string {
	baseType := sageMakerBaseWorkloadType(record)
	roleKind := strings.ToLower(strings.TrimSpace(record.RoleKind))
	if strings.Contains(roleKind, "execution_role") {
		return baseType + "_execution_role"
	}
	return baseType
}

func sageMakerWorkloadName(record SageMakerWorkloadRole) string {
	return firstNonEmptyAWSValue(record.WorkloadName, managedComputeNameFromARN(firstNonEmptyAWSValue(record.WorkloadARN, record.ResourceARN)), "sagemaker workload")
}

func normalizeIAMPassRoleRelationshipAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}) error {
	var record IAMPassRoleRelationship
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode iam passrole relationship asset[%d]: %w", index, err)
	}

	// Register the source identity (the role whose policy contains the
	// PassRole grant) so the graph has a well-formed "from" endpoint. The
	// dedupe map short-circuits if the IAM collector has already emitted it.
	sourceRoleARN := strings.TrimSpace(record.SourceRoleARN)
	if sourceRoleARN == "" {
		return nil
	}
	sourceID := identityIDFromARN(sourceRoleARN)
	if _, exists := identitySeen[sourceID]; !exists {
		identitySeen[sourceID] = struct{}{}
		bundle.Identities = append(bundle.Identities, domain.Identity{
			ID:        sourceID,
			Provider:  domain.ProviderAWS,
			Type:      domain.IdentityTypeRole,
			Name:      firstNonEmptyAWSValue(record.SourceRoleName, roleNameFromARN(sourceRoleARN)),
			ARN:       sourceRoleARN,
			OwnerHint: ownerHintFromTags(record.Tags),
			Tags:      copyTags(record.Tags),
			RawRef:    asset.SourceID,
		})
	}

	// Target identities are only projected for concrete role ARNs. Wildcard
	// targets stay as raw-asset/API metadata — synthesizing an "arn:aws:iam::
	// *:role/*" identity would pollute every downstream traversal and create
	// fake nodes the graph cannot reason about.
	if record.UnresolvedTarget {
		return nil
	}
	targetARN := strings.TrimSpace(record.TargetResource)
	if !isIAMRoleARN(targetARN) {
		// PassRole targets must be IAM role ARNs (arn:PARTITION:iam::ACCOUNT:
		// role/...). Any other shape — an S3 bucket ARN, a Lambda function
		// ARN, a malformed string — would synthesize a bogus role identity in
		// the graph, so we drop those edges silently. The raw asset still
		// carries the original target string for audit; the API exposes it
		// even when no identity is created.
		return nil
	}
	targetID := identityIDFromARN(targetARN)
	if _, exists := identitySeen[targetID]; !exists {
		identitySeen[targetID] = struct{}{}
		bundle.Identities = append(bundle.Identities, domain.Identity{
			ID:       targetID,
			Provider: domain.ProviderAWS,
			Type:     domain.IdentityTypeRole,
			Name:     roleNameFromARN(targetARN),
			ARN:      targetARN,
			RawRef:   asset.SourceID,
		})
	}
	return nil
}

// isIAMRoleARN reports whether the supplied string is a fully-qualified IAM
// role ARN of the form arn:PARTITION:iam::ACCOUNT:role/NAME. It guards the
// PassRole normalizer from synthesizing identity nodes from non-IAM-role ARNs
// that happen to share the arn: prefix.
//
// Every segment is validated: the literal "arn" prefix, an aws-family
// partition, the service "iam", an empty region (IAM is global), a 12-digit
// numeric account ID, and a resource of the form "role/NAME" where NAME is
// non-empty. Anything else — wrong service, missing account, region present,
// dangling "role/" with no name — rejects.
func isIAMRoleARN(arn string) bool {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return false
	}
	parts := strings.SplitN(trimmed, ":", 6)
	if len(parts) != 6 {
		return false
	}
	if !strings.EqualFold(parts[0], "arn") {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(parts[1]), "aws") {
		return false
	}
	if !strings.EqualFold(parts[2], "iam") {
		return false
	}
	// IAM is a global service; the region segment must be empty.
	if parts[3] != "" {
		return false
	}
	account := strings.TrimSpace(parts[4])
	if len(account) != 12 {
		return false
	}
	for _, ch := range account {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	resource := strings.TrimSpace(parts[5])
	if !strings.HasPrefix(resource, "role/") {
		return false
	}
	return len(strings.TrimPrefix(resource, "role/")) > 0
}

// normalizeS3BucketReachabilityAsset registers the bucket as a Resource (with
// exposure metadata) and projects any concrete IAM-principal grants as
// Identity nodes so the graph can render principal→bucket reachability.
// Wildcard ("*"), service, federated, and canonical-user principals stay as
// resource metadata only — the graph does not synthesize a fake identity for
// "*" or a service-name string.
func normalizeS3BucketReachabilityAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record S3BucketReachability
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode s3 bucket reachability asset[%d]: %w", index, err)
	}
	bucketARN := strings.TrimSpace(record.BucketARN)
	if bucketARN == "" {
		return nil
	}
	resourceID := s3BucketResourceID(bucketARN)
	if _, exists := resourceSeen[resourceID]; !exists {
		resourceSeen[resourceID] = struct{}{}
		bundle.Resources = append(bundle.Resources, domain.Resource{
			ID:        resourceID,
			Provider:  domain.ProviderAWS,
			Type:      domain.ResourceTypeS3Bucket,
			Name:      firstNonEmptyAWSValue(record.BucketName, bucketARN),
			ARN:       bucketARN,
			Region:    strings.TrimSpace(record.BucketRegion),
			AccountID: strings.TrimSpace(record.AccountID),
			Labels:    copyTags(record.Tags),
			Metadata: map[string]any{
				"has_bucket_policy":              record.HasBucketPolicy,
				"bucket_policy_statement_count":  record.BucketPolicyStatementCount,
				"ownership_controls":             record.OwnershipControls,
				"block_public_acls":              record.BlockPublicACLs,
				"block_public_policy":            record.BlockPublicPolicy,
				"ignore_public_acls":             record.IgnorePublicACLs,
				"restrict_public_buckets":        record.RestrictPublicBuckets,
				"default_encryption_algorithm":   record.DefaultEncryptionAlgorithm,
				"default_encryption_kms_key_arn": record.DefaultEncryptionKMSKeyARN,
				"bucket_key_enabled":             record.BucketKeyEnabled,
				"access_point_count":             len(record.AccessPoints),
				"exposure_classification":        record.ExposureClassification,
				"exposure_reasons":               append([]string(nil), record.ExposureReasons...),
				"identity_grant_count":           len(record.IdentityGrants),
				"public_grant_count":             s3PublicGrantCount(record.IdentityGrants),
				"cross_account_grant_count":      s3CrossAccountGrantCount(record.IdentityGrants),
				"deny_grant_count":               s3DenyGrantCount(record.IdentityGrants),
			},
			RawRef: asset.SourceID,
		})
	}

	// Project each concrete IAM principal as an Identity so the graph
	// surfaces principal→bucket reachability for downstream traversals.
	for _, grant := range record.IdentityGrants {
		projectAWSIAMPrincipalIdentity(bundle, identitySeen, grant.PrincipalARN, asset.SourceID)
	}
	return nil
}

// isIAMUserARN reports whether the supplied string is a fully-qualified IAM
// user ARN of the form arn:PARTITION:iam::ACCOUNT:user/NAME. Mirrors the
// stricter isIAMRoleARN check used by the PassRole collector.
func isIAMUserARN(arn string) bool {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return false
	}
	parts := strings.SplitN(trimmed, ":", 6)
	if len(parts) != 6 {
		return false
	}
	if !strings.EqualFold(parts[0], "arn") {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(parts[1]), "aws") {
		return false
	}
	if !strings.EqualFold(parts[2], "iam") {
		return false
	}
	if parts[3] != "" {
		return false
	}
	if len(parts[4]) != 12 {
		return false
	}
	for _, ch := range parts[4] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	resource := strings.TrimSpace(parts[5])
	if !strings.HasPrefix(resource, "user/") {
		return false
	}
	return len(strings.TrimPrefix(resource, "user/")) > 0
}

func s3BucketResourceID(bucketARN string) string {
	return "aws:resource:s3-bucket:" + strings.TrimSpace(bucketARN)
}

func s3PublicGrantCount(grants []S3IdentityGrant) int {
	count := 0
	for _, grant := range grants {
		if grant.IsPublic {
			count++
		}
	}
	return count
}

func s3CrossAccountGrantCount(grants []S3IdentityGrant) int {
	count := 0
	for _, grant := range grants {
		if grant.IsCrossAccount {
			count++
		}
	}
	return count
}

func s3DenyGrantCount(grants []S3IdentityGrant) int {
	count := 0
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			count++
		}
	}
	return count
}

// normalizeKMSDecryptReachabilityAsset registers the KMS key as a Resource
// (with exposure + rotation metadata) and projects concrete IAM-principal
// grants — both key-policy and live KMS grants — as Identity nodes so the
// graph can render principal→key reachability. Wildcard ("*"), service,
// federated, and canonical-user principals stay as resource metadata only;
// the graph does not synthesize a fake identity for "*" or a service-name
// string.
func normalizeKMSDecryptReachabilityAsset(asset providers.RawAsset, index int, bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, resourceSeen map[string]struct{}) error {
	var record KMSDecryptReachability
	if err := json.Unmarshal(asset.Payload, &record); err != nil {
		return fmt.Errorf("decode kms decrypt reachability asset[%d]: %w", index, err)
	}
	keyARN := strings.TrimSpace(record.KeyARN)
	if keyARN == "" {
		return nil
	}
	resourceID := kmsKeyResourceID(keyARN)
	if _, exists := resourceSeen[resourceID]; !exists {
		resourceSeen[resourceID] = struct{}{}
		bundle.Resources = append(bundle.Resources, domain.Resource{
			ID:        resourceID,
			Provider:  domain.ProviderAWS,
			Type:      domain.ResourceTypeKMSKey,
			Name:      firstNonEmptyAWSValue(record.KeyID, keyARN),
			ARN:       keyARN,
			Region:    strings.TrimSpace(record.Region),
			AccountID: strings.TrimSpace(record.AccountID),
			Labels:    copyTags(record.Tags),
			Metadata: map[string]any{
				"key_manager":                    record.KeyManager,
				"key_state":                      record.KeyState,
				"key_usage":                      record.KeyUsage,
				"key_spec":                       record.KeySpec,
				"origin":                         record.Origin,
				"enabled":                        record.Enabled,
				"multi_region":                   record.MultiRegion,
				"multi_region_primary":           record.MultiRegionPrimary,
				"replica_key_count":              len(record.ReplicaKeyARNs),
				"primary_key_arn":                record.PrimaryKeyARN,
				"rotation_supported":             record.RotationSupported,
				"rotation_enabled":               record.RotationEnabled,
				"aliases":                        append([]string(nil), record.Aliases...),
				"has_key_policy":                 record.HasKeyPolicy,
				"key_policy_statement_count":     record.KeyPolicyStatementCount,
				"iam_delegation_enabled":         record.IAMDelegationEnabled,
				"exposure_classification":        record.ExposureClassification,
				"exposure_reasons":               append([]string(nil), record.ExposureReasons...),
				"identity_grant_count":           len(record.IdentityGrants),
				"public_grant_count":             kmsPublicGrantCount(record.IdentityGrants),
				"cross_account_grant_count":      kmsCrossAccountGrantCount(record.IdentityGrants),
				"deny_grant_count":               kmsDenyGrantCount(record.IdentityGrants),
				"live_grant_count":               len(record.Grants),
				"cross_account_live_grant_count": kmsCrossAccountLiveGrantCount(record.Grants),
			},
			RawRef: asset.SourceID,
		})
	}

	// Project each concrete IAM principal as an Identity for the graph.
	for _, grant := range record.IdentityGrants {
		projectAWSIAMPrincipalIdentity(bundle, identitySeen, grant.PrincipalARN, asset.SourceID)
	}
	for _, grant := range record.Grants {
		projectAWSIAMPrincipalIdentity(bundle, identitySeen, grant.GranteePrincipal, asset.SourceID)
	}
	return nil
}

func projectAWSIAMPrincipalIdentity(bundle *providers.NormalizedBundle, identitySeen map[string]struct{}, principal string, rawRef string) {
	principal = strings.TrimSpace(principal)
	if principal == "" || principal == "*" {
		return
	}
	if !isIAMRoleARN(principal) && !isIAMUserARN(principal) {
		return
	}
	identityID := identityIDFromARN(principal)
	if _, exists := identitySeen[identityID]; exists {
		return
	}
	identitySeen[identityID] = struct{}{}
	identityType := domain.IdentityTypeRole
	if isIAMUserARN(principal) {
		identityType = domain.IdentityTypeUser
	}
	bundle.Identities = append(bundle.Identities, domain.Identity{
		ID:       identityID,
		Provider: domain.ProviderAWS,
		Type:     identityType,
		Name:     roleNameFromARN(principal),
		ARN:      principal,
		RawRef:   rawRef,
	})
}

func kmsKeyResourceID(keyARN string) string {
	return "aws:resource:kms-key:" + strings.TrimSpace(keyARN)
}

func kmsPublicGrantCount(grants []KMSIdentityGrant) int {
	count := 0
	for _, grant := range grants {
		if grant.IsPublic {
			count++
		}
	}
	return count
}

func kmsCrossAccountGrantCount(grants []KMSIdentityGrant) int {
	count := 0
	for _, grant := range grants {
		if grant.IsCrossAccount {
			count++
		}
	}
	return count
}

func kmsDenyGrantCount(grants []KMSIdentityGrant) int {
	count := 0
	for _, grant := range grants {
		if strings.EqualFold(grant.Effect, "Deny") {
			count++
		}
	}
	return count
}

func kmsCrossAccountLiveGrantCount(grants []KMSGrant) int {
	count := 0
	for _, grant := range grants {
		if grant.IsCrossAccount {
			count++
		}
	}
	return count
}

func secretsManagerPublicGrantCount(grants []SecretsManagerIdentityGrant) int {
	count := 0
	for _, grant := range grants {
		if grant.IsPublic {
			count++
		}
	}
	return count
}

func secretsManagerCrossAccountGrantCount(grants []SecretsManagerIdentityGrant) int {
	count := 0
	for _, grant := range grants {
		if grant.IsCrossAccount {
			count++
		}
	}
	return count
}

func secretReferenceMetadata(refs []SecretWorkloadReference) []map[string]any {
	if len(refs) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(refs))
	for _, ref := range refs {
		out = append(out, map[string]any{
			"source_service": strings.TrimSpace(ref.SourceService),
			"workload_id":    strings.TrimSpace(ref.WorkloadID),
			"workload_type":  strings.TrimSpace(ref.WorkloadType),
			"workload_name":  strings.TrimSpace(ref.WorkloadName),
			"resource_arn":   strings.TrimSpace(ref.ResourceARN),
			"resource_id":    strings.TrimSpace(ref.ResourceID),
			"reference":      strings.TrimSpace(ref.Reference),
			"reference_kind": strings.TrimSpace(ref.ReferenceKind),
			"confidence":     ref.Confidence,
		})
	}
	return out
}
