package aws

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	defaultStackName = "identrail-readonly-connector"
)

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`)

// CloudFormationLaunchInput contains the parameters for an AWS console launch URL.
type CloudFormationLaunchInput struct {
	TemplateURL             string
	Region                  string
	StackName               string
	IdentrailAccountID      string
	ExternalID              string
	RoleName                string
	RegistrationProviderARN string
	RegistrationAttemptID   string
	RegistrationToken       string
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
	values.Set("param_RoleName", roleName)
	providerARN := strings.TrimSpace(input.RegistrationProviderARN)
	attemptID := strings.TrimSpace(input.RegistrationAttemptID)
	registrationToken := strings.TrimSpace(input.RegistrationToken)
	if providerARN != "" && attemptID != "" && registrationToken != "" {
		values.Set("param_RegistrationProviderArn", providerARN)
		values.Set("param_RegistrationAttemptId", attemptID)
		values.Set("param_RegistrationToken", registrationToken)
	} else {
		values.Set("param_ExternalId", strings.TrimSpace(input.ExternalID))
	}

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
// StackSet launch URL. The URL never carries AWS credentials or customer secret
// values; it carries only setup parameters such as the generated external ID,
// pinned template URL, permission model, and target metadata.
//
// Rollout* fields are only populated for organization-scale rollouts. When any
// rollout field is set, the launch URL emits the CFN template's
// UseRolloutRegistration parameters so every member-account stack instance can
// authenticate its registration event back to the Identrail rollout envelope.
// The RolloutRegistrationSecret is derived server-side and delivered inside
// the AWS console URL; it is never persisted in plaintext.
type CloudFormationStackSetLaunchInput struct {
	TemplateURL                  string
	Region                       string
	StackSetName                 string
	IdentrailAccountID           string
	ExternalID                   string
	RoleName                     string
	PermissionModel              StackSetLaunchPermissionModel
	OrganizationalUnitIDs        []string
	TargetAccountIDs             []string
	ExcludedAccountIDs           []string
	TargetRegions                []string
	AutoDeploymentEnabled        *bool
	RetainStacksOnAccountRemoval bool

	RegistrationProviderARN     string
	RolloutID                   string
	RolloutRegistrationSecret   string
	RolloutOrganizationID       string
	RolloutManagementAccountID  string
	RolloutStackSetNameOverride string
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
	values.Set("param_RoleName", roleName)
	// Rollout parameters take precedence over the manual External ID: the CFN
	// template's UseRolloutRegistration condition depends on RolloutId +
	// RolloutRegistrationSecret + RegistrationProviderArn all being present.
	// When they are, param_ExternalId is left empty so the trust policy
	// resolves sts:ExternalId from the rollout secret instead.
	rolloutID := strings.TrimSpace(input.RolloutID)
	rolloutSecret := strings.TrimSpace(input.RolloutRegistrationSecret)
	rolloutProviderARN := strings.TrimSpace(input.RegistrationProviderARN)
	if rolloutID != "" && rolloutSecret != "" && rolloutProviderARN != "" {
		values.Set("param_ExternalId", "")
		values.Set("param_RegistrationProviderArn", rolloutProviderARN)
		values.Set("param_RolloutId", rolloutID)
		values.Set("param_RolloutRegistrationSecret", rolloutSecret)
		if organizationID := strings.TrimSpace(input.RolloutOrganizationID); organizationID != "" {
			values.Set("param_RolloutOrganizationId", organizationID)
		}
		if managementAccountID := strings.TrimSpace(input.RolloutManagementAccountID); managementAccountID != "" {
			values.Set("param_RolloutManagementAccountId", managementAccountID)
		}
		rolloutStackSetName := strings.TrimSpace(input.RolloutStackSetNameOverride)
		if rolloutStackSetName == "" {
			rolloutStackSetName = stackSetName
		}
		values.Set("param_RolloutStackSetName", rolloutStackSetName)
	} else {
		values.Set("param_ExternalId", strings.TrimSpace(input.ExternalID))
	}
	if len(input.OrganizationalUnitIDs) > 0 {
		values.Set("organizationalUnitIds", strings.Join(input.OrganizationalUnitIDs, ","))
	}
	if len(input.TargetAccountIDs) > 0 {
		values.Set("accounts", strings.Join(input.TargetAccountIDs, ","))
	}
	if len(input.ExcludedAccountIDs) > 0 {
		values.Set("excludedAccounts", strings.Join(input.ExcludedAccountIDs, ","))
		values.Set("accountFilterType", "DIFFERENCE")
	} else if len(input.OrganizationalUnitIDs) > 0 && len(input.TargetAccountIDs) > 0 {
		values.Set("accountFilterType", "INTERSECTION")
	}
	if len(input.TargetRegions) > 0 {
		values.Set("regions", strings.Join(input.TargetRegions, ","))
	}
	if input.AutoDeploymentEnabled != nil && permissionModel == string(StackSetLaunchPermissionModelServiceManaged) {
		values.Set("autoDeploymentEnabled", strconv.FormatBool(*input.AutoDeploymentEnabled))
		values.Set("retainStacksOnAccountRemoval", strconv.FormatBool(input.RetainStacksOnAccountRemoval))
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
