package aws

import (
	"net/url"
	"regexp"
	"strings"
)

const (
	defaultStackName = "identrail-readonly-connector"
)

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

// StackSetLaunchPermissionModel names how the StackSet authenticates into
// member accounts. SERVICE_MANAGED uses AWS Organizations trusted access;
// SELF_MANAGED uses operator-provided administration/execution roles.
type StackSetLaunchPermissionModel string

const (
	StackSetLaunchPermissionModelServiceManaged StackSetLaunchPermissionModel = "SERVICE_MANAGED"
	StackSetLaunchPermissionModelSelfManaged    StackSetLaunchPermissionModel = "SELF_MANAGED"
)

const defaultStackSetName = "identrail-readonly-connector-stackset"

// CloudFormationStackSetLaunchInput contains the parameters for an AWS console
// StackSet launch URL. The URL never carries secret values; only the pinned
// template URL, parameter names, and target metadata.
type CloudFormationStackSetLaunchInput struct {
	TemplateURL           string
	Region                string
	StackSetName          string
	IdentrailAccountID    string
	ExternalID            string
	RoleName              string
	PermissionModel       StackSetLaunchPermissionModel
	OrganizationalUnitIDs []string
	TargetAccountIDs      []string
	TargetRegions         []string
}

// BuildCloudFormationStackSetLaunchURL creates an AWS console deep link for
// creating the read-only connector StackSet. It returns an empty string when
// inputs are insufficient so callers can surface a deterministic blocked state
// instead of an obviously malformed URL.
func BuildCloudFormationStackSetLaunchURL(input CloudFormationStackSetLaunchInput) string {
	region := NormalizeRegion(input.Region)
	stackSetName := strings.TrimSpace(input.StackSetName)
	if stackSetName == "" {
		stackSetName = defaultStackSetName
	}
	roleName := strings.TrimSpace(input.RoleName)
	if roleName == "" {
		roleName = "IdentrailReadOnly"
	}
	templateURL := strings.TrimSpace(input.TemplateURL)
	if templateURL == "" {
		return ""
	}
	permissionModel := strings.ToUpper(strings.TrimSpace(string(input.PermissionModel)))
	if permissionModel != string(StackSetLaunchPermissionModelServiceManaged) && permissionModel != string(StackSetLaunchPermissionModelSelfManaged) {
		permissionModel = string(StackSetLaunchPermissionModelServiceManaged)
	}

	values := url.Values{}
	values.Set("templateURL", templateURL)
	values.Set("stackSetName", stackSetName)
	values.Set("permissionModel", permissionModel)
	values.Set("param_IdentrailAccountId", strings.TrimSpace(input.IdentrailAccountID))
	values.Set("param_ExternalId", strings.TrimSpace(input.ExternalID))
	values.Set("param_RoleName", roleName)
	if len(input.OrganizationalUnitIDs) > 0 {
		values.Set("organizationalUnitIds", strings.Join(input.OrganizationalUnitIDs, ","))
	}
	if len(input.TargetAccountIDs) > 0 {
		values.Set("accounts", strings.Join(input.TargetAccountIDs, ","))
	}
	if len(input.TargetRegions) > 0 {
		values.Set("regions", strings.Join(input.TargetRegions, ","))
	}

	return "https://" + consoleHostForRegion(region) + "/cloudformation/home?region=" + url.QueryEscape(region) + "#/stacksets/create?" + values.Encode()
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
