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
