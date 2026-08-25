package aws

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

const (
	identrailConnectorRoleName = "IdentrailReadOnly"
	awsFindingProvenance       = "aws_iam_inventory"
	awsFindingAdapterSource    = "aws_iam_rule_engine"
	awsFindingEvidenceVersion  = "aws-finding-v2"
)

type serviceLinkedRoleExpectation struct {
	RoleName         string
	ServicePrincipal string
}

var expectedServiceLinkedRoles = map[string]serviceLinkedRoleExpectation{
	"awsserviceroleforamazonsecuritylake": {
		RoleName:         "AWSServiceRoleForAmazonSecurityLake",
		ServicePrincipal: "securitylake.amazonaws.com",
	},
	"awsserviceroleforsupport": {
		RoleName:         "AWSServiceRoleForSupport",
		ServicePrincipal: "support.amazonaws.com",
	},
	"awsservicerolefortrustedadvisor": {
		RoleName:         "AWSServiceRoleForTrustedAdvisor",
		ServicePrincipal: "trustedadvisor.amazonaws.com",
	},
	"awsservicerolefororganizations": {
		RoleName:         "AWSServiceRoleForOrganizations",
		ServicePrincipal: "organizations.amazonaws.com",
	},
}

// ConnectorRoleExpectation is the live connector contract used to distinguish
// expected cross-account trust from actual trust drift. ExternalID is compared
// in memory and is never copied into finding evidence.
type ConnectorRoleExpectation struct {
	RoleARN          string
	AccountID        string
	TrustedAccountID string
	ExternalID       string
}

func classifyIAMRoleIdentity(role IAMRole) (domain.IdentityKind, domain.IdentityManagedBy, domain.FindingActionability) {
	name := strings.TrimSpace(role.Name)
	if isIdentrailConnectorRole(name, role.Tags) {
		return domain.IdentityKindConnector, domain.IdentityManagedByIdentrail, domain.FindingActionabilityReview
	}
	if isServiceLinkedRoleARN(role.ARN) {
		return domain.IdentityKindServiceLinked, domain.IdentityManagedByAWSService, domain.FindingActionabilityObserveOnly
	}
	return domain.IdentityKindStandard, domain.IdentityManagedByCustomer, domain.FindingActionabilityActionRequired
}

func isIdentrailConnectorRole(name string, tags map[string]string) bool {
	if strings.EqualFold(strings.TrimSpace(name), identrailConnectorRoleName) {
		return true
	}
	for key := range tags {
		if strings.EqualFold(strings.TrimSpace(key), "IdentrailConnectorMode") {
			return true
		}
	}
	return false
}

func expectedServiceLinkedRole(identity domain.Identity) (serviceLinkedRoleExpectation, bool) {
	expectation, ok := expectedServiceLinkedRoles[strings.ToLower(strings.TrimSpace(identity.Name))]
	if !ok || !matchesExpectedServiceLinkedRoleARN(identity.ARN, expectation) {
		return serviceLinkedRoleExpectation{}, false
	}
	return expectation, true
}

func isServiceLinkedRoleARN(roleARN string) bool {
	parts := strings.Split(strings.TrimSpace(roleARN), ":")
	return len(parts) == 6 && parts[2] == "iam" && strings.HasPrefix(parts[5], "role/aws-service-role/")
}

func matchesExpectedServiceLinkedRoleARN(roleARN string, expectation serviceLinkedRoleExpectation) bool {
	parts := strings.Split(strings.TrimSpace(roleARN), ":")
	if len(parts) != 6 || parts[2] != "iam" || strings.TrimSpace(parts[4]) == "" {
		return false
	}
	expectedResource := "role/aws-service-role/" + expectation.ServicePrincipal + "/" + expectation.RoleName
	return parts[5] == expectedResource
}

func isExpectedAWSManagedPolicyARN(policyARN string) bool {
	parts := strings.Split(strings.TrimSpace(policyARN), ":")
	return len(parts) >= 6 && parts[2] == "iam" && parts[4] == "aws" && strings.HasPrefix(strings.ToLower(parts[5]), "policy/aws-service-role/")
}

func permissionPoliciesForIdentity(bundle providers.NormalizedBundle, identityID string) []domain.Policy {
	policies := make([]domain.Policy, 0)
	for _, policy := range bundle.Policies {
		policyType, _ := policy.Normalized[policyTypeKey].(string)
		policyIdentityID, _ := policy.Normalized[identityIDKey].(string)
		if policyType == policyTypePerm && policyIdentityID == identityID {
			policies = append(policies, policy)
		}
	}
	return policies
}

func trustPolicyForIdentity(bundle providers.NormalizedBundle, identityID string) *domain.Policy {
	for i := range bundle.Policies {
		policy := &bundle.Policies[i]
		policyType, _ := policy.Normalized[policyTypeKey].(string)
		policyIdentityID, _ := policy.Normalized[identityIDKey].(string)
		if policyType == policyTypeTrust && policyIdentityID == identityID {
			return policy
		}
	}
	return nil
}

type trustPolicyFacts struct {
	AWSPrincipals      []string
	ServicePrincipals  []string
	OtherPrincipals    []string
	AllowsAssumeRole   bool
	AssumeRoleBindings []trustAssumeRoleBinding
}

type trustAssumeRoleBinding struct {
	Actions                    []string
	NotActions                 []string
	AWSPrincipals              []string
	ServicePrincipals          []string
	OtherPrincipals            []string
	ExternalIDEquals           []string
	HasOtherExternalIDOperator bool
}

func inspectTrustPolicy(policy *domain.Policy) trustPolicyFacts {
	if policy == nil {
		return trustPolicyFacts{}
	}
	doc, err := parsePolicyDocument(string(policy.Document))
	if err != nil {
		return trustPolicyFacts{}
	}
	facts := trustPolicyFacts{}
	for _, statement := range doc.Statement {
		if !strings.EqualFold(strings.TrimSpace(statement.Effect), "allow") {
			continue
		}
		actions := sortedUniqueStrings(parseStringList(statement.Action))
		notActions := sortedUniqueStrings(parseStringList(statement.NotAction))
		awsPrincipals := parseAWSPrincipals(statement.Principal)
		servicePrincipals := parsePrincipalType(statement.Principal, "Service")
		otherPrincipals := append(parsePrincipalType(statement.Principal, "Federated"), parsePrincipalType(statement.Principal, "CanonicalUser")...)
		if !statementAllowsAssumeRole(actions, notActions) {
			continue
		}
		facts.AllowsAssumeRole = true
		facts.AWSPrincipals = append(facts.AWSPrincipals, awsPrincipals...)
		facts.ServicePrincipals = append(facts.ServicePrincipals, servicePrincipals...)
		facts.OtherPrincipals = append(facts.OtherPrincipals, otherPrincipals...)
		externalIDEquals, hasOtherExternalIDOperator := inspectExternalIDConditions(statement.Condition)
		facts.AssumeRoleBindings = append(facts.AssumeRoleBindings, trustAssumeRoleBinding{
			Actions:                    actions,
			NotActions:                 notActions,
			AWSPrincipals:              sortedUniqueStrings(awsPrincipals),
			ServicePrincipals:          sortedUniqueStrings(servicePrincipals),
			OtherPrincipals:            sortedUniqueStrings(otherPrincipals),
			ExternalIDEquals:           externalIDEquals,
			HasOtherExternalIDOperator: hasOtherExternalIDOperator,
		})
	}
	facts.AWSPrincipals = sortedUniqueStrings(facts.AWSPrincipals)
	facts.ServicePrincipals = sortedUniqueStrings(facts.ServicePrincipals)
	facts.OtherPrincipals = sortedUniqueStrings(facts.OtherPrincipals)
	return facts
}

func actionsAllowAssumeRole(actions []string) bool {
	for _, action := range actions {
		if iamActionPatternMatches(strings.ToLower(strings.TrimSpace(action)), "sts:assumerole") {
			return true
		}
	}
	return false
}

func statementAllowsAssumeRole(actions, notActions []string) bool {
	if actionsAllowAssumeRole(actions) {
		return true
	}
	if len(notActions) == 0 {
		return false
	}
	for _, action := range notActions {
		if iamActionPatternMatches(strings.ToLower(strings.TrimSpace(action)), "sts:assumerole") {
			return false
		}
	}
	return true
}

func inspectExternalIDConditions(condition map[string]any) ([]string, bool) {
	equalsValues := []string{}
	hasOtherOperator := false
	for operator, operatorValue := range condition {
		operatorMap, ok := operatorValue.(map[string]any)
		if !ok {
			continue
		}
		for key, value := range operatorMap {
			if !strings.EqualFold(strings.TrimSpace(key), "sts:ExternalId") {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(operator), "StringEquals") {
				equalsValues = append(equalsValues, parseStringList(value)...)
			} else {
				hasOtherOperator = true
			}
		}
	}
	return sortedUniqueStrings(equalsValues), hasOtherOperator
}

func sortedUniqueStrings(values []string) []string {
	values = dedupeStrings(values)
	sort.Strings(values)
	return values
}

func expectedServiceLinkedRoleSignals(bundle providers.NormalizedBundle, identity domain.Identity, expectation serviceLinkedRoleExpectation, hasBroadAccess bool) []string {
	signals := []string{}
	facts := inspectTrustPolicy(trustPolicyForIdentity(bundle, identity.ID))
	if !facts.AllowsAssumeRole || len(facts.ServicePrincipals) != 1 || !strings.EqualFold(facts.ServicePrincipals[0], expectation.ServicePrincipal) || len(facts.AWSPrincipals) > 0 || len(facts.OtherPrincipals) > 0 {
		signals = append(signals, "unexpected_trust")
	}
	customerPolicy := false
	for _, policy := range permissionPoliciesForIdentity(bundle, identity.ID) {
		policyARN, _ := policy.Normalized[policyARNKey].(string)
		attachmentType, _ := policy.Normalized[attachmentTypeKey].(string)
		if !isExpectedAWSManagedPolicyARN(policyARN) || !strings.EqualFold(strings.TrimSpace(attachmentType), "managed") {
			customerPolicy = true
			break
		}
	}
	if customerPolicy {
		signals = append(signals, "customer_added_policy")
		if hasBroadAccess {
			signals = append(signals, "unexpected_permission_reachability")
		}
	}
	return sortedUniqueStrings(signals)
}

func connectorRoleSignals(bundle providers.NormalizedBundle, identity domain.Identity, expectation ConnectorRoleExpectation) (signals []string, completeness string) {
	completeness = "complete"
	if expectedARN := strings.TrimSpace(expectation.RoleARN); expectedARN != "" && !strings.EqualFold(strings.TrimSpace(identity.ARN), expectedARN) {
		signals = append(signals, "connector_role_mismatch")
	}
	if expectedAccount := strings.TrimSpace(expectation.AccountID); expectedAccount != "" && accountIDFromARN(identity.ARN) != expectedAccount {
		signals = append(signals, "connector_account_mismatch")
	}

	policy := trustPolicyForIdentity(bundle, identity.ID)
	facts := inspectTrustPolicy(policy)
	if policy == nil {
		completeness = "partial"
		signals = append(signals, "trust_evidence_missing")
	} else {
		expectedTrustedAccount := strings.TrimSpace(expectation.TrustedAccountID)
		expectedExternalID := strings.TrimSpace(expectation.ExternalID)
		trustValid, externalIDValid := connectorTrustBindingStatus(facts, expectedTrustedAccount, expectedExternalID)
		if expectedTrustedAccount == "" {
			completeness = "partial"
			signals = append(signals, "trusted_account_expectation_missing")
		} else if !trustValid {
			signals = append(signals, "unexpected_trust")
		}

		if expectedExternalID == "" {
			completeness = "partial"
			signals = append(signals, "external_id_expectation_missing")
		} else if !externalIDValid {
			signals = append(signals, "external_id_mismatch")
		}
	}

	permissionPolicies := permissionPoliciesForIdentity(bundle, identity.ID)
	if len(permissionPolicies) == 0 {
		completeness = "partial"
		signals = append(signals, "permission_evidence_missing")
	} else {
		if connectorPermissionScopeExpanded(permissionPolicies) {
			signals = append(signals, "permission_scope_expanded")
		}
		if connectorPermissionActionsMissing(permissionPolicies) {
			signals = append(signals, "permission_scope_incomplete")
		}
	}
	return sortedUniqueStrings(signals), completeness
}

func connectorTrustBindingStatus(facts trustPolicyFacts, trustedAccountID, externalID string) (bool, bool) {
	if len(facts.AssumeRoleBindings) != 1 {
		return false, false
	}
	binding := facts.AssumeRoleBindings[0]
	trustValid := len(binding.Actions) == 1 && len(binding.NotActions) == 0 && strings.EqualFold(binding.Actions[0], "sts:AssumeRole") &&
		len(binding.AWSPrincipals) == 1 && isAccountRootPrincipal(binding.AWSPrincipals[0], trustedAccountID) &&
		len(binding.ServicePrincipals) == 0 && len(binding.OtherPrincipals) == 0
	externalIDValid := len(binding.ExternalIDEquals) == 1 && binding.ExternalIDEquals[0] == externalID && !binding.HasOtherExternalIDOperator
	return trustValid, externalIDValid
}

func isAccountRootPrincipal(principal, accountID string) bool {
	parts := strings.Split(strings.TrimSpace(principal), ":")
	return len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && parts[4] == strings.TrimSpace(accountID) && parts[5] == "root"
}

func connectorPermissionScopeExpanded(policies []domain.Policy) bool {
	allowedActions, err := expectedConnectorPermissionActions()
	if err != nil {
		return true
	}
	for _, policy := range policies {
		statements, err := parseNormalizedStatements(policy.Normalized[statementsKey])
		if err != nil {
			return true
		}
		for _, statement := range statements {
			effect, _ := statement["effect"].(string)
			if !strings.EqualFold(effect, "Allow") {
				continue
			}
			if len(parseStringList(statement[notActionsKey])) > 0 {
				return true
			}
			if len(parseStringList(statement[notResourcesKey])) > 0 {
				return true
			}
			for _, action := range parseStringList(statement["actions"]) {
				if _, ok := allowedActions[strings.ToLower(strings.TrimSpace(action))]; !ok {
					return true
				}
			}
		}
	}
	return false
}

// connectorPermissionActionsMissing reports an incomplete connector policy
// boundary. Scope validation must catch both permissions that are too broad
// and permissions that are absent; otherwise an existing role can appear
// compliant while newly wired collectors fail with AccessDenied.
func connectorPermissionActionsMissing(policies []domain.Policy) bool {
	expected, err := expectedConnectorPermissionActions()
	if err != nil {
		return true
	}
	observed := map[string]struct{}{}
	for _, policy := range policies {
		statements, err := parseNormalizedStatements(policy.Normalized[statementsKey])
		if err != nil {
			return true
		}
		for _, statement := range statements {
			effect, _ := statement["effect"].(string)
			if !strings.EqualFold(effect, "Allow") {
				continue
			}
			for _, action := range parseStringList(statement["actions"]) {
				normalized := strings.ToLower(strings.TrimSpace(action))
				if normalized == "*" {
					return false
				}
				observed[normalized] = struct{}{}
			}
		}
	}
	for expectedAction := range expected {
		if _, ok := observed[expectedAction]; !ok {
			return true
		}
	}
	return false
}

func expectedConnectorPermissionActions() (map[string]struct{}, error) {
	actions := map[string]struct{}{}
	// This is the deployed CloudFormation role contract. Keep it aligned with
	// the embedded policy and deployment artifacts so connector validation does
	// not reject the permissions required by newly wired metadata collectors.
	for _, action := range []string{
		"iam:GetAccountSummary",
		"iam:GetInstanceProfile",
		"iam:GetPolicy",
		"iam:GetPolicyVersion",
		"iam:GetRole",
		"iam:GetRolePolicy",
		"iam:ListAccountAliases",
		"iam:ListAttachedRolePolicies",
		"iam:ListRolePolicies",
		"iam:ListRoles",
		"iam:SimulatePrincipalPolicy",
		"ec2:DescribeIamInstanceProfileAssociations",
		"ec2:DescribeInstances",
		"ec2:DescribeLaunchTemplateVersions",
		"ec2:DescribeLaunchTemplates",
		"ec2:DescribeRegions",
		"ecs:DescribeServices",
		"ecs:DescribeTaskDefinition",
		"ecs:ListClusters",
		"ecs:ListServices",
		"ecs:ListTaskDefinitions",
		"codebuild:BatchGetProjects",
		"codebuild:ListProjects",
		"lambda:ListFunctions",
		"lambda:ListEventSourceMappings",
		"lambda:ListAliases",
		"lambda:ListVersionsByFunction",
		"lambda:ListTags",
		"codepipeline:ListPipelines",
		"codepipeline:GetPipeline",
		"codepipeline:GetPipelineState",
		"states:ListStateMachines",
		"states:DescribeStateMachine",
		"states:ListTagsForResource",
		"events:ListEventBuses",
		"events:ListRules",
		"events:ListTargetsByRule",
		"events:ListTagsForResource",
		"scheduler:ListSchedules",
		"scheduler:GetSchedule",
		"pipes:ListPipes",
		"pipes:DescribePipe",
		"apprunner:ListServices",
		"apprunner:DescribeService",
		"batch:DescribeComputeEnvironments",
		"batch:DescribeJobDefinitions",
		"glue:GetJobs",
		"glue:GetCrawlers",
		"elasticmapreduce:ListClusters",
		"elasticmapreduce:DescribeCluster",
		"eks:DescribeCluster",
		"eks:DescribeFargateProfile",
		"eks:DescribeNodegroup",
		"eks:DescribePodIdentityAssociation",
		"eks:ListClusters",
		"eks:ListFargateProfiles",
		"eks:ListNodegroups",
		"eks:ListPodIdentityAssociations",
		"sagemaker:DescribeDomain",
		"sagemaker:DescribeEndpoint",
		"sagemaker:DescribeEndpointConfig",
		"sagemaker:DescribeModel",
		"sagemaker:DescribeNotebookInstance",
		"sagemaker:DescribePipeline",
		"sagemaker:DescribeProcessingJob",
		"sagemaker:DescribeTrainingJob",
		"sagemaker:DescribeTransformJob",
		"sagemaker:ListDomains",
		"sagemaker:ListEndpoints",
		"sagemaker:ListModels",
		"sagemaker:ListNotebookInstances",
		"sagemaker:ListPipelines",
		"sagemaker:ListProcessingJobs",
		"sagemaker:ListTrainingJobs",
		"sagemaker:ListTransformJobs",
		"s3:GetBucketAcl",
		"s3:GetBucketLocation",
		"s3:GetBucketOwnershipControls",
		"s3:GetBucketPolicy",
		"s3:GetBucketPublicAccessBlock",
		"s3:GetBucketTagging",
		"s3:GetEncryptionConfiguration",
		"s3:ListAccessPoints",
		"s3:ListAllMyBuckets",
		"ecr:DescribeImages",
		"ecr:DescribeRepositories",
		"ecr:GetLifecyclePolicy",
		"ecr:GetRepositoryPolicy",
		"ecr:GetRegistryScanningConfiguration",
		"ecr:ListTagsForResource",
		"kms:DescribeKey",
		"kms:GetKeyPolicy",
		"kms:GetKeyRotationStatus",
		"kms:ListAliases",
		"kms:ListGrants",
		"kms:ListKeys",
		"kms:ListResourceTags",
		"sqs:GetQueueAttributes",
		"sqs:ListQueues",
		"sqs:ListQueueTags",
		"sns:GetSubscriptionAttributes",
		"sns:GetTopicAttributes",
		"sns:ListSubscriptionsByTopic",
		"sns:ListTagsForResource",
		"sns:ListTopics",
		"dynamodb:ListTables",
		"dynamodb:DescribeTable",
		"dynamodb:ListTagsOfResource",
		"dynamodb:GetResourcePolicy",
		"rds:DescribeDBInstances",
		"rds:DescribeDBClusters",
		"rds:DescribeDBProxies",
		"rds:ListTagsForResource",
		"secretsmanager:ListSecrets",
		"secretsmanager:DescribeSecret",
		"secretsmanager:GetResourcePolicy",
		"secretsmanager:ListSecretVersionIds",
		"ssm:DescribeParameters",
		"ssm:ListTagsForResource",
		"bedrock-agentcore:ListAgentRuntimes",
		"bedrock-agentcore:GetAgentRuntime",
		"bedrock-agentcore:ListAgentRuntimeEndpoints",
		"bedrock-agentcore:ListGateways",
		"bedrock-agentcore:GetGateway",
		"bedrock-agentcore:ListGatewayTargets",
		"bedrock-agentcore:GetGatewayTarget",
		"bedrock-agentcore:ListMemories",
		"bedrock-agentcore:GetMemory",
		"bedrock-agentcore:ListBrowsers",
		"bedrock-agentcore:GetBrowser",
		"bedrock-agentcore:ListCodeInterpreters",
		"bedrock-agentcore:GetCodeInterpreter",
		"sts:GetCallerIdentity",
		"organizations:DescribeOrganization",
		"organizations:ListAccountsForParent",
		"organizations:ListDelegatedAdministrators",
		"organizations:ListDelegatedServicesForAccount",
		"organizations:ListOrganizationalUnitsForParent",
		"organizations:ListRoots",
		"cloudformation:ListStackInstances",
	} {
		actions[strings.ToLower(action)] = struct{}{}
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("Identrail connector policy has no allowed actions")
	}
	return actions, nil
}

func managedRoleAnomalyFinding(identity domain.Identity, expectation serviceLinkedRoleExpectation, signals []string, now time.Time) domain.Finding {
	finding := domain.Finding{
		ID:                   findingID(domain.FindingRiskyTrustPolicy, identity.ID, strings.Join(signals, ",")),
		Type:                 domain.FindingRiskyTrustPolicy,
		Severity:             domain.SeverityHigh,
		ConfidenceScore:      0.95,
		Actionability:        domain.FindingActionabilityReview,
		Exploitability:       domain.FindingExploitabilityPlausible,
		EvidenceCompleteness: "complete",
		Provenance:           awsFindingProvenance,
		Title:                fmt.Sprintf("AWS-managed role anomaly: %s", displayIdentity(identity)),
		HumanSummary:         "This expected AWS service-linked role differs from its managed trust or policy boundary and needs investigation without directly editing the role.",
		Path:                 []string{identity.ID},
		Evidence: map[string]any{
			"identity_id":                identity.ID,
			"identity_arn":               identity.ARN,
			"expected_service_principal": expectation.ServicePrincipal,
			"contributing_signals":       signals,
		},
		Remediation: "Review the owning AWS service configuration and CloudTrail history. Restore the service-linked role through the AWS service workflow instead of editing it directly.",
		CreatedAt:   now,
	}
	decorateAWSFinding(&finding, identity, signals, now)
	return finding
}

func connectorTrustReviewFinding(identity domain.Identity, signals []string, completeness string, now time.Time) domain.Finding {
	actionability := domain.FindingActionabilityObserveOnly
	severity := domain.SeverityInfo
	exploitability := domain.FindingExploitabilityNone
	title := fmt.Sprintf("Connector trust review: %s", displayIdentity(identity))
	summary := "The Identrail connector role matches the expected account, external-ID trust condition, and read-only permission boundary."
	remediation := "No direct AWS change is recommended. Continue monitoring the connector trust and read-only policy for drift."
	invalid := false
	for _, signal := range signals {
		if !strings.HasSuffix(signal, "_missing") {
			invalid = true
			break
		}
	}
	if invalid {
		actionability = domain.FindingActionabilityActionRequired
		severity = domain.SeverityHigh
		exploitability = domain.FindingExploitabilityPlausible
		title = fmt.Sprintf("Connector role configuration drift: %s", displayIdentity(identity))
		summary = "The Identrail connector role no longer matches its expected account, external-ID trust, or read-only permission boundary."
		remediation = "Restore the connector trust and collector policy from the Identrail onboarding template. Do not add permissions or weaken the external-ID condition."
	} else if len(signals) > 0 {
		actionability = domain.FindingActionabilityReview
		exploitability = domain.FindingExploitabilityUnknown
		summary = "The role is recognized as the Identrail connector, but available evidence is insufficient to prove that every trust and read-only policy invariant still matches."
		remediation = "Refresh connector validation and the IAM policy inventory before treating the role as safe."
	}
	confidence := 0.95
	if !invalid && completeness != "complete" {
		confidence = 0.72
	}
	finding := domain.Finding{
		ID:                   findingID(domain.FindingRiskyTrustPolicy, identity.ID, "connector-review|"+strings.Join(signals, ",")),
		Type:                 domain.FindingRiskyTrustPolicy,
		Severity:             severity,
		ConfidenceScore:      confidence,
		Actionability:        actionability,
		Exploitability:       exploitability,
		EvidenceCompleteness: completeness,
		Provenance:           awsFindingProvenance,
		Title:                title,
		HumanSummary:         summary,
		Path:                 []string{identity.ID},
		Evidence: map[string]any{
			"identity_id":                 identity.ID,
			"identity_arn":                identity.ARN,
			"external_id_condition_valid": !stringSliceContains(signals, "external_id_expectation_missing") && !stringSliceContains(signals, "external_id_mismatch"),
			"contributing_signals":        signals,
		},
		Remediation: remediation,
		CreatedAt:   now,
	}
	decorateAWSFinding(&finding, identity, signals, now)
	return finding
}

func stringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func decorateAWSFinding(finding *domain.Finding, identity domain.Identity, signals []string, now time.Time) {
	if finding == nil {
		return
	}
	if finding.ConfidenceScore == 0 {
		finding.ConfidenceScore = 0.9
	}
	if finding.Actionability == "" {
		finding.Actionability = domain.FindingActionabilityActionRequired
	}
	if finding.Exploitability == "" {
		finding.Exploitability = domain.FindingExploitabilityUnknown
	}
	if finding.EvidenceCompleteness == "" {
		finding.EvidenceCompleteness = "complete"
	}
	if finding.Provenance == "" {
		finding.Provenance = awsFindingProvenance
	}
	finding.AdapterSource = awsFindingAdapterSource
	finding.ConfidenceState = "inventory_backed"
	finding.EvidenceVersion = awsFindingEvidenceVersion
	if finding.Evidence == nil {
		finding.Evidence = map[string]any{}
	}
	identityKind := identity.IdentityKind
	if identityKind == "" {
		identityKind = domain.IdentityKindStandard
	}
	managedBy := identity.ManagedBy
	if managedBy == "" {
		managedBy = domain.IdentityManagedByCustomer
	}
	finding.Evidence["account_id"] = accountIDFromARN(identity.ARN)
	finding.Evidence["region"] = "global"
	finding.Evidence["source"] = awsFindingAdapterSource
	finding.Evidence["observed_at"] = now.Format(time.RFC3339)
	finding.Evidence["provenance"] = finding.Provenance
	finding.Evidence["confidence"] = finding.ConfidenceScore
	finding.Evidence["identity_kind"] = identityKind
	finding.Evidence["managed_by"] = managedBy
	finding.Evidence["actionability"] = finding.Actionability
	finding.Evidence["exploitability"] = finding.Exploitability
	finding.Evidence["evidence_completeness"] = finding.EvidenceCompleteness
	finding.Evidence["evidence_boundary"] = "IAM role inventory, trust policy, and collected permission policies"
	if len(signals) > 0 {
		finding.Evidence["contributing_signals"] = sortedUniqueStrings(signals)
	}
}
