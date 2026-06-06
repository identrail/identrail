package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/identrail/identrail/internal/domain"
)

var nonAlphaNumeric = regexp.MustCompile(`[^a-z0-9]+`)

func identityIDFromARN(arn string) string {
	return "aws:identity:" + strings.TrimSpace(arn)
}

func ec2InstanceWorkloadID(accountID, region, instanceID string) string {
	return fmt.Sprintf("aws:workload:ec2:%s:%s:instance/%s", normalizeName(accountID), normalizeName(region), normalizeName(instanceID))
}

func ec2LaunchTemplateWorkloadID(accountID, region, templateID, version string) string {
	normalizedVersion := normalizeName(version)
	if normalizedVersion == "" {
		normalizedVersion = "default"
	}
	return fmt.Sprintf("aws:workload:ec2:%s:%s:launch-template/%s/%s", normalizeName(accountID), normalizeName(region), normalizeName(templateID), normalizedVersion)
}

func ec2InstanceProfileResourceID(profileARN string) string {
	return "aws:resource:ec2-instance-profile:" + strings.TrimSpace(profileARN)
}

func ec2InstanceResourceID(accountID, region, instanceID string) string {
	return fmt.Sprintf("aws:resource:ec2:%s:%s:instance/%s", normalizeName(accountID), normalizeName(region), normalizeName(instanceID))
}

func ecsWorkloadID(accountID, region, workloadType, workloadID, roleKind string) string {
	normalizedType := normalizeName(workloadType)
	if normalizedType == "" {
		normalizedType = "workload"
	}
	normalizedRoleKind := normalizeName(roleKind)
	if normalizedRoleKind == "" {
		normalizedRoleKind = "role"
	}
	return fmt.Sprintf("aws:workload:ecs:%s:%s:%s/%s/%s", normalizeName(accountID), normalizeName(region), normalizedType, normalizeName(workloadID), normalizedRoleKind)
}

func ecsServiceResourceID(serviceARN string) string {
	return "aws:resource:ecs-service:" + strings.TrimSpace(serviceARN)
}

func ecsTaskDefinitionResourceID(taskDefinitionARN string) string {
	return "aws:resource:ecs-task-definition:" + strings.TrimSpace(taskDefinitionARN)
}

func lambdaFunctionWorkloadID(accountID, region, functionRef string) string {
	return fmt.Sprintf("aws:workload:lambda:%s:%s:function/%s", normalizeName(accountID), normalizeName(region), normalizeName(functionRef))
}

func lambdaFunctionResourceID(functionARN string) string {
	return "aws:resource:lambda-function:" + strings.TrimSpace(functionARN)
}

func codeBuildProjectWorkloadID(accountID, region, projectRef string) string {
	return fmt.Sprintf("aws:workload:codebuild:%s:%s:project/%s", normalizeName(accountID), normalizeName(region), normalizeName(projectRef))
}

func codeBuildProjectResourceID(projectARN string) string {
	return "aws:resource:codebuild-project:" + strings.TrimSpace(projectARN)
}

func codePipelineWorkloadID(accountID, region, pipelineRef, roleKind string) string {
	normalizedRoleKind := normalizeName(roleKind)
	if normalizedRoleKind == "" {
		normalizedRoleKind = "role"
	}
	return fmt.Sprintf("aws:workload:codepipeline:%s:%s:pipeline/%s/%s", normalizeName(accountID), normalizeName(region), normalizeName(pipelineRef), normalizedRoleKind)
}

func codePipelineResourceID(pipelineARN string) string {
	return "aws:resource:codepipeline-pipeline:" + strings.TrimSpace(pipelineARN)
}

func eksWorkloadIdentityWorkloadID(accountID, region, workloadType, workloadID, roleKind string) string {
	normalizedType := normalizeName(workloadType)
	if normalizedType == "" {
		normalizedType = "eks-workload"
	}
	normalizedRoleKind := normalizeName(roleKind)
	if normalizedRoleKind == "" {
		normalizedRoleKind = "role"
	}
	return fmt.Sprintf("aws:workload:eks:%s:%s:%s/%s/%s", normalizeName(accountID), normalizeName(region), normalizedType, normalizeName(workloadID), normalizedRoleKind)
}

func eksClusterResourceID(clusterARN string) string {
	return "aws:resource:eks-cluster:" + strings.TrimSpace(clusterARN)
}

func eksWorkloadResourceID(record EKSWorkloadIdentity) string {
	suffix := strings.TrimPrefix(eksWorkloadIdentityNormalizedWorkloadID(record), "aws:workload:eks:")
	if strings.TrimSpace(suffix) == "" {
		suffix = "workload"
	}
	return "aws:resource:eks-workload:" + suffix
}

func roleNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 || idx == len(trimmed)-1 {
		return trimmed
	}
	return trimmed[idx+1:]
}

func permissionPolicyID(identityID, policyName string, index int) string {
	normalizedName := normalizeName(policyName)
	if normalizedName == "" {
		normalizedName = fmt.Sprintf("policy-%d", index)
	}
	return fmt.Sprintf("%s:policy:%s", identityID, normalizedName)
}

func trustPolicyID(identityID string) string {
	return identityID + ":policy:trust"
}

func principalNodeID(principalARN string, arnToIdentity map[string]string) string {
	principal := strings.TrimSpace(principalARN)
	if principal == "" {
		return ""
	}
	if mapped, ok := arnToIdentity[principal]; ok {
		return mapped
	}
	return "aws:principal:" + principal
}

func accessNodeID(action, resource string) string {
	escapedAction := url.QueryEscape(strings.TrimSpace(action))
	escapedResource := url.QueryEscape(strings.TrimSpace(resource))
	return fmt.Sprintf("aws:access:%s:%s", escapedAction, escapedResource)
}

func relationshipID(relationshipType domain.RelationshipType, fromNodeID, toNodeID string) string {
	raw := string(relationshipType) + "|" + fromNodeID + "|" + toNodeID
	sum := sha256.Sum256([]byte(raw))
	return "aws:rel:" + hex.EncodeToString(sum[:16])
}

func normalizeName(input string) string {
	normalized := strings.ToLower(strings.TrimSpace(input))
	normalized = nonAlphaNumeric.ReplaceAllString(normalized, "-")
	return strings.Trim(normalized, "-")
}
