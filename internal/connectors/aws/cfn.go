package aws

import (
	"net/url"
	"regexp"
	"strings"
)

const defaultStackName = "identrail-readonly-connector"

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`)

// CloudFormationLaunchInput contains the parameters for an AWS console launch URL.
type CloudFormationLaunchInput struct {
	TemplateURL        string
	Region             string
	StackName          string
	IdentrailAccountID string
	ExternalID         string
	RoleName           string
}

// BuildCloudFormationLaunchURL creates an AWS console deep link for the read-only connector stack.
func BuildCloudFormationLaunchURL(input CloudFormationLaunchInput) string {
	region := strings.TrimSpace(input.Region)
	if !awsRegionPattern.MatchString(region) {
		region = "us-east-1"
	}
	stackName := strings.TrimSpace(input.StackName)
	if stackName == "" {
		stackName = defaultStackName
	}
	roleName := strings.TrimSpace(input.RoleName)
	if roleName == "" {
		roleName = "IdentrailReadOnly"
	}

	values := url.Values{}
	values.Set("templateURL", strings.TrimSpace(input.TemplateURL))
	values.Set("stackName", stackName)
	values.Set("param_IdentrailAccountId", strings.TrimSpace(input.IdentrailAccountID))
	values.Set("param_ExternalId", strings.TrimSpace(input.ExternalID))
	values.Set("param_RoleName", roleName)

	return "https://" + consoleHostForRegion(region) + "/cloudformation/home?region=" + url.QueryEscape(region) + "#/stacks/create/review?" + values.Encode()
}

// NormalizeRegion returns a safe region default for connector setup.
func NormalizeRegion(region string) string {
	trimmed := strings.TrimSpace(region)
	if !awsRegionPattern.MatchString(trimmed) {
		return "us-east-1"
	}
	return trimmed
}

func consoleHostForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "console.amazonaws-us-gov.com"
	case strings.HasPrefix(region, "cn-"):
		return "console.amazonaws.cn"
	default:
		return "console.aws.amazon.com"
	}
}
