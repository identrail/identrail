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
		if asset.Kind != rawKindEKSWorkloadIdentity {
			continue
		}
		if err := normalizeEKSWorkloadIdentityAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
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
