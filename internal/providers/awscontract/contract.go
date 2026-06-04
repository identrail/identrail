package awscontract

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

const (
	// AWSServiceCollectorContractVersion is the stable contract future AWS
	// service collectors must cite when adding service-specific inventory.
	AWSServiceCollectorContractVersion = "aws-service-collector-contract-v1"

	ServiceCollectorStatusReady    ServiceCollectorStatus = "ready"
	ServiceCollectorStatusDegraded ServiceCollectorStatus = "degraded"
	ServiceCollectorStatusBlocked  ServiceCollectorStatus = "blocked"

	ServiceCollectorFixtureSuccess           ServiceCollectorFixtureState = "success"
	ServiceCollectorFixtureEmpty             ServiceCollectorFixtureState = "empty"
	ServiceCollectorFixturePagination        ServiceCollectorFixtureState = "pagination"
	ServiceCollectorFixtureThrottling        ServiceCollectorFixtureState = "throttling"
	ServiceCollectorFixturePartialFailure    ServiceCollectorFixtureState = "partial_failure"
	ServiceCollectorFixtureUnsupportedRegion ServiceCollectorFixtureState = "unsupported_region"
	ServiceCollectorFixturePermissionDenied  ServiceCollectorFixtureState = "permission_denied"
	ServiceCollectorFixtureDegraded          ServiceCollectorFixtureState = "degraded"
)

// ServiceCollectorStatus describes deterministic collector readiness states.
type ServiceCollectorStatus string

// ServiceCollectorFixtureState names fixture states every AWS service collector
// must prove without reading customer payloads or mutating AWS.
type ServiceCollectorFixtureState string

// ServiceCollectorRecord is the normalized evidence envelope every AWS service
// collector must emit before downstream graph and intelligence engines consume it.
type ServiceCollectorRecord struct {
	TenantID      string            `json:"tenant_id"`
	WorkspaceID   string            `json:"workspace_id"`
	ProjectID     string            `json:"project_id"`
	ConnectorID   string            `json:"connector_id"`
	AccountID     string            `json:"account_id"`
	Region        string            `json:"region"`
	Service       string            `json:"service"`
	WorkloadID    string            `json:"workload_id"`
	WorkloadType  string            `json:"workload_type"`
	WorkloadName  string            `json:"workload_name"`
	RoleARN       string            `json:"role_arn"`
	Source        string            `json:"source"`
	EvidenceRef   string            `json:"evidence_ref"`
	Confidence    float64           `json:"confidence"`
	ScanID        string            `json:"scan_id"`
	CollectorName string            `json:"collector_name"`
	CollectedAt   time.Time         `json:"collected_at"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ServiceCollectorGraphEdgeContract maps operator-facing AWS edge names to the
// canonical graph relationship semantics used by Identrail.
type ServiceCollectorGraphEdgeContract struct {
	Name             string                          `json:"name"`
	RelationshipType domain.RelationshipType         `json:"relationship_type"`
	FromEndpoint     domain.RelationshipEndpointKind `json:"from_endpoint"`
	ToEndpoint       domain.RelationshipEndpointKind `json:"to_endpoint"`
	Evidence         string                          `json:"evidence"`
	Required         bool                            `json:"required"`
}

// ServiceCollectorFixtureCase records one required fixture convention and the
// expected collector status when the fixture is exercised.
type ServiceCollectorFixtureCase struct {
	ID               string                       `json:"id"`
	State            ServiceCollectorFixtureState `json:"state"`
	Label            string                       `json:"label"`
	ExpectedStatus   ServiceCollectorStatus       `json:"expected_status"`
	SourceErrorCode  string                       `json:"source_error_code,omitempty"`
	Retryable        bool                         `json:"retryable"`
	Required         bool                         `json:"required"`
	EvidenceBoundary string                       `json:"evidence_boundary"`
}

// ServiceCollectorContract is the canonical AWS service collector contract.
type ServiceCollectorContract struct {
	Version                string                              `json:"version"`
	NormalizedRecordFields []string                            `json:"normalized_record_fields"`
	GraphEdges             []ServiceCollectorGraphEdgeContract `json:"graph_edges"`
	FixtureCases           []ServiceCollectorFixtureCase       `json:"fixture_cases"`
	RequiredPermissions    []string                            `json:"required_permissions"`
	ReadOnlyBoundaries     []string                            `json:"read_only_boundaries"`
}

// AWSServiceCollectorContract returns a defensive copy of the canonical
// contract for future AWS service collector implementations and tests.
func AWSServiceCollectorContract() ServiceCollectorContract {
	return ServiceCollectorContract{
		Version:                AWSServiceCollectorContractVersion,
		NormalizedRecordFields: RequiredServiceCollectorRecordFields(),
		GraphEdges:             RequiredServiceCollectorGraphEdges(),
		FixtureCases:           RequiredServiceCollectorFixtureCases(),
		RequiredPermissions: []string{
			"sts:GetCallerIdentity",
			"iam:ListRoles",
			"iam:GetRole",
			"iam:GetInstanceProfile",
			"iam:ListRolePolicies",
			"iam:GetRolePolicy",
			"iam:ListAttachedRolePolicies",
			"iam:GetPolicy",
			"iam:GetPolicyVersion",
			"ec2:DescribeInstances",
			"ec2:DescribeLaunchTemplates",
			"ec2:DescribeLaunchTemplateVersions",
			"ecs:ListClusters",
			"ecs:ListServices",
			"ecs:DescribeServices",
			"ecs:ListTaskDefinitions",
			"ecs:DescribeTaskDefinition",
		},
		ReadOnlyBoundaries: []string{
			"collect metadata and policy documents only; never collect secret values, customer payloads, prompts, completions, object contents, or database rows",
			"emit explicit permission_denied, unsupported_region, partial_failure, and degraded states instead of reporting false success",
			"preserve tenant, workspace, project, connector, account, region, service, and scan scope on every record and diagnostic",
			"require approved remediation or governance executors before any live AWS mutation",
		},
	}
}

// RequiredServiceCollectorRecordFields returns the stable field order future
// collectors should assert against in fixture tests.
func RequiredServiceCollectorRecordFields() []string {
	return []string{
		"tenant_id",
		"workspace_id",
		"project_id",
		"connector_id",
		"account_id",
		"region",
		"service",
		"workload_id",
		"workload_type",
		"workload_name",
		"role_arn",
		"source",
		"evidence_ref",
		"confidence",
		"scan_id",
		"collector_name",
		"collected_at",
	}
}

// RequiredServiceCollectorGraphEdges returns the graph edge semantics every AWS
// service collector should use when it can prove the relationship.
func RequiredServiceCollectorGraphEdges() []ServiceCollectorGraphEdgeContract {
	edges := []struct {
		name string
		rel  domain.RelationshipType
	}{
		{"runs-on", domain.RelationshipRunsAs},
		{"assumes", domain.RelationshipCanAssume},
		{"passes-role", domain.RelationshipCanPassRole},
		{"can-access", domain.RelationshipCanAccess},
		{"references-secret", domain.RelationshipUsesSecret},
		{"invokes", domain.RelationshipInvokes},
		{"observed-runtime-action", domain.RelationshipObservedAction},
	}
	result := make([]ServiceCollectorGraphEdgeContract, 0, len(edges))
	for _, edge := range edges {
		contract, ok := domain.RelationshipContractFor(edge.rel)
		if !ok {
			continue
		}
		result = append(result, ServiceCollectorGraphEdgeContract{
			Name:             edge.name,
			RelationshipType: contract.Type,
			FromEndpoint:     contract.From,
			ToEndpoint:       contract.To,
			Evidence:         contract.Evidence,
			Required:         true,
		})
	}
	return result
}

// RequiredServiceCollectorFixtureCases returns deterministic fixture states that
// future service collectors must cover in tests.
func RequiredServiceCollectorFixtureCases() []ServiceCollectorFixtureCase {
	return []ServiceCollectorFixtureCase{
		{
			ID:               "success_single_page",
			State:            ServiceCollectorFixtureSuccess,
			Label:            "Successful authorized collection",
			ExpectedStatus:   ServiceCollectorStatusReady,
			Required:         true,
			EvidenceBoundary: "metadata, role ARN, workload identifiers, and scoped evidence references only",
		},
		{
			ID:               "empty_authorized_region",
			State:            ServiceCollectorFixtureEmpty,
			Label:            "Authorized empty result",
			ExpectedStatus:   ServiceCollectorStatusReady,
			Required:         true,
			EvidenceBoundary: "explicit zero-count evidence with account, region, and service context",
		},
		{
			ID:               "pagination_multiple_pages",
			State:            ServiceCollectorFixturePagination,
			Label:            "Multi-page pagination",
			ExpectedStatus:   ServiceCollectorStatusReady,
			Required:         true,
			EvidenceBoundary: "cursor/page counts only; no raw customer payloads",
		},
		{
			ID:               "throttling_retryable",
			State:            ServiceCollectorFixtureThrottling,
			Label:            "AWS throttling after bounded retries",
			ExpectedStatus:   ServiceCollectorStatusDegraded,
			SourceErrorCode:  "aws_throttled",
			Retryable:        true,
			Required:         true,
			EvidenceBoundary: "retry count, service, account, and region without request payloads",
		},
		{
			ID:               "partial_failure_one_service",
			State:            ServiceCollectorFixturePartialFailure,
			Label:            "One service partition fails",
			ExpectedStatus:   ServiceCollectorStatusDegraded,
			SourceErrorCode:  "service_collection_failed",
			Retryable:        true,
			Required:         true,
			EvidenceBoundary: "successful and failed partitions separated by service/account/region",
		},
		{
			ID:               "unsupported_region",
			State:            ServiceCollectorFixtureUnsupportedRegion,
			Label:            "Unsupported AWS region",
			ExpectedStatus:   ServiceCollectorStatusBlocked,
			SourceErrorCode:  "unsupported_region",
			Required:         true,
			EvidenceBoundary: "region identifier and service capability only",
		},
		{
			ID:               "permission_denied",
			State:            ServiceCollectorFixturePermissionDenied,
			Label:            "Read-only permission denied",
			ExpectedStatus:   ServiceCollectorStatusBlocked,
			SourceErrorCode:  "permission_denied",
			Required:         true,
			EvidenceBoundary: "denied action name and remediation hint, never credentials",
		},
		{
			ID:               "degraded_source_record",
			State:            ServiceCollectorFixtureDegraded,
			Label:            "Malformed or incomplete source record",
			ExpectedStatus:   ServiceCollectorStatusDegraded,
			SourceErrorCode:  "malformed_source_record",
			Required:         true,
			EvidenceBoundary: "record identifier, validation error code, and collector name only",
		},
	}
}

// NormalizeServiceCollectorRecord trims and validates one normalized service
// collector record before graph or API consumers use it.
func NormalizeServiceCollectorRecord(record ServiceCollectorRecord) (ServiceCollectorRecord, error) {
	normalized := record
	normalized.TenantID = strings.TrimSpace(record.TenantID)
	normalized.WorkspaceID = strings.TrimSpace(record.WorkspaceID)
	normalized.ProjectID = strings.TrimSpace(record.ProjectID)
	normalized.ConnectorID = strings.TrimSpace(record.ConnectorID)
	normalized.AccountID = strings.TrimSpace(record.AccountID)
	normalized.Region = strings.TrimSpace(record.Region)
	normalized.Service = strings.ToLower(strings.TrimSpace(record.Service))
	normalized.WorkloadID = strings.TrimSpace(record.WorkloadID)
	normalized.WorkloadType = strings.ToLower(strings.TrimSpace(record.WorkloadType))
	normalized.WorkloadName = strings.TrimSpace(record.WorkloadName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.Source = strings.ToLower(strings.TrimSpace(record.Source))
	normalized.EvidenceRef = strings.TrimSpace(record.EvidenceRef)
	normalized.ScanID = strings.TrimSpace(record.ScanID)
	normalized.CollectorName = strings.TrimSpace(record.CollectorName)
	if record.Metadata != nil {
		normalized.Metadata = make(map[string]string, len(record.Metadata))
		for key, value := range record.Metadata {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key == "" || value == "" {
				continue
			}
			normalized.Metadata[key] = value
		}
	}
	if err := ValidateServiceCollectorRecord(normalized); err != nil {
		return ServiceCollectorRecord{}, err
	}
	return normalized, nil
}

// ValidateServiceCollectorRecord enforces the normalized record contract.
func ValidateServiceCollectorRecord(record ServiceCollectorRecord) error {
	required := map[string]string{
		"tenant_id":      record.TenantID,
		"workspace_id":   record.WorkspaceID,
		"project_id":     record.ProjectID,
		"connector_id":   record.ConnectorID,
		"account_id":     record.AccountID,
		"region":         record.Region,
		"service":        record.Service,
		"workload_id":    record.WorkloadID,
		"workload_type":  record.WorkloadType,
		"workload_name":  record.WorkloadName,
		"role_arn":       record.RoleARN,
		"source":         record.Source,
		"evidence_ref":   record.EvidenceRef,
		"scan_id":        record.ScanID,
		"collector_name": record.CollectorName,
	}
	for _, field := range RequiredServiceCollectorRecordFields() {
		if field == "confidence" || field == "collected_at" {
			continue
		}
		if strings.TrimSpace(required[field]) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if !isTwelveDigitAWSAccountID(record.AccountID) {
		return fmt.Errorf("account_id must be 12 digits")
	}
	roleAccountID, ok := accountIDFromIAMRoleARN(record.RoleARN)
	if !ok {
		return fmt.Errorf("role_arn must be an AWS IAM role ARN")
	}
	if roleAccountID != record.AccountID {
		return fmt.Errorf("role_arn account id must match account_id")
	}
	if record.Confidence <= 0 || record.Confidence > 1 {
		return fmt.Errorf("confidence must be greater than 0 and at most 1")
	}
	if record.CollectedAt.IsZero() {
		return fmt.Errorf("collected_at is required")
	}
	return nil
}

// ValidateAWSServiceCollectorContract enforces the whole reusable contract.
func ValidateAWSServiceCollectorContract(contract ServiceCollectorContract) error {
	if strings.TrimSpace(contract.Version) != AWSServiceCollectorContractVersion {
		return fmt.Errorf("unexpected aws service collector contract version")
	}
	if !sameStringSet(contract.NormalizedRecordFields, RequiredServiceCollectorRecordFields()) {
		return fmt.Errorf("normalized record fields do not match required contract")
	}
	if err := ValidateServiceCollectorGraphEdges(contract.GraphEdges); err != nil {
		return err
	}
	if err := ValidateServiceCollectorFixtures(contract.FixtureCases); err != nil {
		return err
	}
	if err := ValidateServiceCollectorReadOnlyBoundaries(contract.RequiredPermissions, contract.ReadOnlyBoundaries); err != nil {
		return err
	}
	return nil
}

// ValidateServiceCollectorReadOnlyBoundaries verifies collectors stay inside
// metadata-only IAM permissions and document their non-collection boundary.
func ValidateServiceCollectorReadOnlyBoundaries(requiredPermissions []string, readOnlyBoundaries []string) error {
	if len(requiredPermissions) == 0 {
		return fmt.Errorf("required permissions are missing")
	}
	if len(readOnlyBoundaries) == 0 {
		return fmt.Errorf("read-only boundaries are missing")
	}
	for _, permission := range requiredPermissions {
		if strings.TrimSpace(permission) == "" {
			return fmt.Errorf("required permissions include a blank action")
		}
		if ServiceCollectorPermissionReadsPayload(permission) {
			return fmt.Errorf("%s is outside the read-only metadata boundary", permission)
		}
	}
	return nil
}

// ValidateServiceCollectorFixtures verifies required fixture states are present.
func ValidateServiceCollectorFixtures(fixtures []ServiceCollectorFixtureCase) error {
	requiredStates := RequiredServiceCollectorFixtureStates()
	requiredCases := requiredServiceCollectorFixtureCasesByState()
	seen := map[ServiceCollectorFixtureState]struct{}{}
	for _, fixture := range fixtures {
		if strings.TrimSpace(fixture.ID) == "" {
			return fmt.Errorf("fixture id is required")
		}
		if strings.TrimSpace(string(fixture.State)) == "" {
			return fmt.Errorf("fixture %s state is required", fixture.ID)
		}
		if strings.TrimSpace(fixture.Label) == "" {
			return fmt.Errorf("fixture %s label is required", fixture.ID)
		}
		switch fixture.ExpectedStatus {
		case ServiceCollectorStatusReady, ServiceCollectorStatusDegraded, ServiceCollectorStatusBlocked:
		default:
			return fmt.Errorf("fixture %s has invalid expected status", fixture.ID)
		}
		if !fixture.Required {
			continue
		}
		requiredFixture, ok := requiredCases[fixture.State]
		if !ok {
			continue
		}
		if fixture.ExpectedStatus != requiredFixture.ExpectedStatus {
			return fmt.Errorf("fixture %s expected status must remain %s", fixture.State, requiredFixture.ExpectedStatus)
		}
		if fixture.Retryable != requiredFixture.Retryable {
			return fmt.Errorf("fixture %s retryable must remain %t", fixture.State, requiredFixture.Retryable)
		}
		if strings.TrimSpace(fixture.SourceErrorCode) != requiredFixture.SourceErrorCode {
			return fmt.Errorf("fixture %s source error code must remain %q", fixture.State, requiredFixture.SourceErrorCode)
		}
		seen[fixture.State] = struct{}{}
	}
	for _, state := range requiredStates {
		if _, ok := seen[state]; !ok {
			return fmt.Errorf("missing required %s fixture", state)
		}
	}
	return nil
}

func requiredServiceCollectorFixtureCasesByState() map[ServiceCollectorFixtureState]ServiceCollectorFixtureCase {
	cases := RequiredServiceCollectorFixtureCases()
	result := make(map[ServiceCollectorFixtureState]ServiceCollectorFixtureCase, len(cases))
	for _, fixture := range cases {
		if fixture.Required {
			result[fixture.State] = fixture
		}
	}
	return result
}

// RequiredServiceCollectorFixtureStates returns all fixture states future
// collectors must keep deterministic.
func RequiredServiceCollectorFixtureStates() []ServiceCollectorFixtureState {
	return []ServiceCollectorFixtureState{
		ServiceCollectorFixtureSuccess,
		ServiceCollectorFixtureEmpty,
		ServiceCollectorFixturePagination,
		ServiceCollectorFixtureThrottling,
		ServiceCollectorFixturePartialFailure,
		ServiceCollectorFixtureUnsupportedRegion,
		ServiceCollectorFixturePermissionDenied,
		ServiceCollectorFixtureDegraded,
	}
}

// ValidateServiceCollectorGraphEdges verifies the AWS names map to supported
// graph relationship contracts.
func ValidateServiceCollectorGraphEdges(edges []ServiceCollectorGraphEdgeContract) error {
	requiredNames := map[string]domain.RelationshipType{
		"runs-on":                 domain.RelationshipRunsAs,
		"assumes":                 domain.RelationshipCanAssume,
		"passes-role":             domain.RelationshipCanPassRole,
		"can-access":              domain.RelationshipCanAccess,
		"references-secret":       domain.RelationshipUsesSecret,
		"invokes":                 domain.RelationshipInvokes,
		"observed-runtime-action": domain.RelationshipObservedAction,
	}
	seen := map[string]struct{}{}
	for _, edge := range edges {
		name := strings.TrimSpace(edge.Name)
		expected, required := requiredNames[name]
		if !required {
			continue
		}
		if edge.RelationshipType != expected {
			return fmt.Errorf("graph edge %s uses %s, want %s", name, edge.RelationshipType, expected)
		}
		contract, ok := domain.RelationshipContractFor(edge.RelationshipType)
		if !ok {
			return fmt.Errorf("graph edge %s uses unsupported relationship type %s", name, edge.RelationshipType)
		}
		if edge.FromEndpoint != contract.From || edge.ToEndpoint != contract.To {
			return fmt.Errorf("graph edge %s endpoint contract does not match canonical relationship contract", name)
		}
		if strings.TrimSpace(edge.Evidence) == "" {
			return fmt.Errorf("graph edge %s evidence is required", name)
		}
		if !edge.Required {
			return fmt.Errorf("graph edge %s must remain required", name)
		}
		seen[name] = struct{}{}
	}
	for name := range requiredNames {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("missing required %s graph edge", name)
		}
	}
	return nil
}

func isTwelveDigitAWSAccountID(accountID string) bool {
	if len(accountID) != 12 {
		return false
	}
	for _, ch := range accountID {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// ServiceCollectorPermissionReadsPayload reports whether an IAM action pattern
// can read customer payloads that AWS service collectors must never collect.
func ServiceCollectorPermissionReadsPayload(permission string) bool {
	normalized := strings.ToLower(strings.TrimSpace(permission))
	parts := strings.SplitN(normalized, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	forbiddenActions := map[string][]string{
		"secretsmanager": {"getsecretvalue", "batchgetsecretvalue"},
		"ssm":            {"getparameter", "getparameters"},
		"s3":             {"getobject"},
		"bedrock":        {"getprompt", "invoke", "converse"},
		"rds-data":       {"execute"},
	}
	for service, actions := range forbiddenActions {
		if !iamServicePatternIncludes(parts[0], service) {
			continue
		}
		if parts[1] == "*" {
			return true
		}
		for _, action := range actions {
			if iamActionPatternIncludes(parts[1], action) {
				return true
			}
		}
	}
	return false
}

func iamServicePatternIncludes(requestedPattern string, forbiddenService string) bool {
	if requestedPattern == forbiddenService {
		return true
	}
	if !strings.ContainsAny(requestedPattern, "*?") {
		return false
	}
	matched, err := path.Match(requestedPattern, forbiddenService)
	return err == nil && matched
}

func iamActionPatternIncludes(requestedPattern string, forbiddenAction string) bool {
	if requestedPattern == forbiddenAction || strings.HasPrefix(requestedPattern, forbiddenAction) {
		return true
	}
	if !strings.ContainsAny(requestedPattern, "*?") {
		return false
	}
	matched, err := path.Match(requestedPattern, forbiddenAction)
	return err == nil && matched
}

func accountIDFromIAMRoleARN(roleARN string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(roleARN), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[3] != "" {
		return "", false
	}
	switch parts[1] {
	case "aws", "aws-us-gov", "aws-cn":
	default:
		return "", false
	}
	if !isTwelveDigitAWSAccountID(parts[4]) || !isIAMRoleResource(parts[5]) {
		return "", false
	}
	return parts[4], true
}

func isIAMRoleResource(resource string) bool {
	rolePath := strings.TrimPrefix(resource, "role/")
	if rolePath == resource || rolePath == "" || len(rolePath) > 512 {
		return false
	}
	for _, ch := range rolePath {
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case strings.ContainsRune("+=,.@_/-", ch):
		default:
			return false
		}
	}
	return true
}

func sameStringSet(left []string, right []string) bool {
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	if len(leftCopy) != len(rightCopy) {
		return false
	}
	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}
	return true
}
