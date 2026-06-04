package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	awsServiceCollectorContractCurrentIssue = 1476
	awsServiceCollectorContractVersion      = awscontract.AWSServiceCollectorContractVersion

	awsServiceCollectorContractStatusReady    = string(awscontract.ServiceCollectorStatusReady)
	awsServiceCollectorContractStatusDegraded = string(awscontract.ServiceCollectorStatusDegraded)
	awsServiceCollectorContractStatusBlocked  = string(awscontract.ServiceCollectorStatusBlocked)
)

// AWSServiceCollectorContractRequest optionally pins connector context used for
// account and region evidence in the collector contract response.
type AWSServiceCollectorContractRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
}

// AWSServiceCollectorContractResult exposes the reusable AWS service collector
// contract future collector PRs must satisfy.
type AWSServiceCollectorContractResult struct {
	TenantID                 string                             `json:"tenant_id"`
	WorkspaceID              string                             `json:"workspace_id"`
	ProjectID                string                             `json:"project_id"`
	ConnectorID              string                             `json:"connector_id,omitempty"`
	AccountID                string                             `json:"account_id,omitempty"`
	Region                   string                             `json:"region,omitempty"`
	ParentIssueNumber        int                                `json:"parent_issue_number"`
	ParentIssueRef           string                             `json:"parent_issue_ref"`
	CurrentIssueNumber       int                                `json:"current_issue_number"`
	CurrentIssueRef          string                             `json:"current_issue_ref"`
	Version                  string                             `json:"version"`
	Status                   string                             `json:"status"`
	Confidence               float64                            `json:"confidence"`
	RequiredFieldCount       int                                `json:"required_field_count"`
	GraphEdgeCount           int                                `json:"graph_edge_count"`
	FixtureCaseCount         int                                `json:"fixture_case_count"`
	RequiredFixtureCaseCount int                                `json:"required_fixture_case_count"`
	NormalizedRecordFields   []string                           `json:"normalized_record_fields"`
	RequiredPermissions      []string                           `json:"required_permissions"`
	ReadOnlyBoundaries       []string                           `json:"read_only_boundaries"`
	FailureReasons           []string                           `json:"failure_reasons"`
	RemediationHints         []string                           `json:"remediation_hints"`
	EvidenceLinks            []string                           `json:"evidence_links"`
	Checks                   []AWSServiceCollectorContractCheck `json:"checks"`
	GraphEdges               []AWSServiceCollectorGraphEdge     `json:"graph_edges"`
	FixtureCases             []AWSServiceCollectorFixtureCase   `json:"fixture_cases"`
	GeneratedAt              time.Time                          `json:"generated_at"`
	UpdatedAt                time.Time                          `json:"updated_at"`
}

// AWSServiceCollectorContractCheck records one deterministic validation check
// over the shared collector contract.
type AWSServiceCollectorContractCheck struct {
	Name          string         `json:"name"`
	Category      string         `json:"category"`
	Required      bool           `json:"required"`
	Status        string         `json:"status"`
	Message       string         `json:"message"`
	FailureReason string         `json:"failure_reason,omitempty"`
	Remediation   string         `json:"remediation,omitempty"`
	EvidenceURL   string         `json:"evidence_url,omitempty"`
	Confidence    float64        `json:"confidence"`
	Evidence      map[string]any `json:"evidence,omitempty"`
	CheckedAt     time.Time      `json:"checked_at"`
}

// AWSServiceCollectorGraphEdge is one required AWS graph relationship semantic.
type AWSServiceCollectorGraphEdge struct {
	Name             string `json:"name"`
	RelationshipType string `json:"relationship_type"`
	FromEndpoint     string `json:"from_endpoint"`
	ToEndpoint       string `json:"to_endpoint"`
	Evidence         string `json:"evidence"`
	Required         bool   `json:"required"`
}

// AWSServiceCollectorFixtureCase is one required deterministic fixture state.
type AWSServiceCollectorFixtureCase struct {
	ID               string `json:"id"`
	State            string `json:"state"`
	Label            string `json:"label"`
	ExpectedStatus   string `json:"expected_status"`
	SourceErrorCode  string `json:"source_error_code,omitempty"`
	Retryable        bool   `json:"retryable"`
	Required         bool   `json:"required"`
	EvidenceBoundary string `json:"evidence_boundary"`
}

// GetAWSServiceCollectorContract returns the deterministic AWS service
// collector contract scoped to one workspace project. It does not call AWS.
func (s *Service) GetAWSServiceCollectorContract(ctx context.Context, workspaceID string, projectID string, request AWSServiceCollectorContractRequest) (AWSServiceCollectorContractResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSServiceCollectorContractResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSServiceCollectorContractResult{}, err
	}
	return buildAWSServiceCollectorContract(scope, project, connection, hasConnection, s.Now().UTC()), nil
}

func buildAWSServiceCollectorContract(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, checkedAt time.Time) AWSServiceCollectorContractResult {
	contract := awscontract.AWSServiceCollectorContract()
	checks := awsServiceCollectorContractChecks(scope, project, contract, checkedAt)
	status, confidence, failureReasons, remediationHints := summarizeAWSServiceCollectorContractChecks(checks)

	result := AWSServiceCollectorContractResult{
		TenantID:                 scope.TenantID,
		WorkspaceID:              project.WorkspaceID,
		ProjectID:                project.ProjectID,
		ParentIssueNumber:        awsPlatformDependencyParentIssue,
		ParentIssueRef:           awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:       awsServiceCollectorContractCurrentIssue,
		CurrentIssueRef:          awsIssueRef(awsServiceCollectorContractCurrentIssue),
		Version:                  contract.Version,
		Status:                   status,
		Confidence:               confidence,
		RequiredFieldCount:       len(contract.NormalizedRecordFields),
		GraphEdgeCount:           len(contract.GraphEdges),
		FixtureCaseCount:         len(contract.FixtureCases),
		RequiredFixtureCaseCount: awsRequiredFixtureCaseCount(contract.FixtureCases),
		NormalizedRecordFields:   append([]string(nil), contract.NormalizedRecordFields...),
		RequiredPermissions:      append([]string(nil), contract.RequiredPermissions...),
		ReadOnlyBoundaries:       append([]string(nil), contract.ReadOnlyBoundaries...),
		FailureReasons:           failureReasons,
		RemediationHints:         remediationHints,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsServiceCollectorContractCurrentIssue),
			"/docs/aws-service-collector-contract",
			"/docs/aws-platform-validation-harness",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Checks:       checks,
		GraphEdges:   awsServiceCollectorGraphEdges(contract.GraphEdges),
		FixtureCases: awsServiceCollectorFixtureCases(contract.FixtureCases),
		GeneratedAt:  checkedAt,
		UpdatedAt:    checkedAt,
	}
	if hasConnection {
		result.ConnectorID = connection.ConnectorID
		result.AccountID = connection.AccountID
		result.Region = connection.Region
	}
	return result
}

func awsServiceCollectorContractChecks(scope db.Scope, project db.TenancyProject, contract awscontract.ServiceCollectorContract, checkedAt time.Time) []AWSServiceCollectorContractCheck {
	return []AWSServiceCollectorContractCheck{
		awsServiceCollectorContractRecordSchemaCheck(contract, checkedAt),
		awsServiceCollectorContractGraphCheck(contract, checkedAt),
		awsServiceCollectorContractFixtureCheck(contract, checkedAt),
		awsServiceCollectorContractReadOnlyCheck(contract, checkedAt),
		awsServiceCollectorContractScopeCheck(scope, project, checkedAt),
	}
}

func awsServiceCollectorContractRecordSchemaCheck(contract awscontract.ServiceCollectorContract, checkedAt time.Time) AWSServiceCollectorContractCheck {
	check := awsServiceCollectorContractCheck("normalized_record_schema", "record", true, checkedAt)
	check.EvidenceURL = "/docs/aws-service-collector-contract"
	check.Evidence = map[string]any{
		"version":        contract.Version,
		"required_count": len(contract.NormalizedRecordFields),
		"fields":         append([]string(nil), contract.NormalizedRecordFields...),
	}
	if strings.TrimSpace(contract.Version) != awsServiceCollectorContractVersion {
		check.Status = awsServiceCollectorContractStatusBlocked
		check.Message = "AWS service collector contract version is not current."
		check.FailureReason = "collector contract version mismatch"
		check.Remediation = "Restore the canonical AWS service collector contract version before adding collectors."
		check.Confidence = 0.25
		return check
	}
	if !sameServiceCollectorStringSet(contract.NormalizedRecordFields, awscontract.RequiredServiceCollectorRecordFields()) {
		check.Status = awsServiceCollectorContractStatusBlocked
		check.Message = "Normalized AWS service collector record fields do not match the shared contract."
		check.FailureReason = "normalized record fields are incomplete"
		check.Remediation = "Include connector, account, region, service, workload, role ARN, source, evidence, confidence, and scan metadata fields."
		check.Confidence = 0.3
		return check
	}
	check.Status = awsServiceCollectorContractStatusReady
	check.Message = "Normalized AWS service collector record fields are deterministic."
	check.Confidence = 0.98
	return check
}

func awsServiceCollectorContractGraphCheck(contract awscontract.ServiceCollectorContract, checkedAt time.Time) AWSServiceCollectorContractCheck {
	check := awsServiceCollectorContractCheck("graph_edge_contract", "graph", true, checkedAt)
	check.EvidenceURL = "/docs/graph-relationship-contract"
	check.Evidence = map[string]any{
		"edge_count": len(contract.GraphEdges),
		"edges":      awsServiceCollectorGraphEdges(contract.GraphEdges),
	}
	if err := awscontract.ValidateServiceCollectorGraphEdges(contract.GraphEdges); err != nil {
		check.Status = awsServiceCollectorContractStatusBlocked
		check.Message = "AWS service collector graph edge contract is incomplete."
		check.FailureReason = err.Error()
		check.Remediation = "Restore required runs-on, assumes, passes-role, can-access, references-secret, invokes, and observed-runtime-action mappings."
		check.Confidence = 0.35
		return check
	}
	check.Status = awsServiceCollectorContractStatusReady
	check.Message = "AWS graph edge types map to supported relationship contracts."
	check.Confidence = 0.97
	return check
}

func awsServiceCollectorContractFixtureCheck(contract awscontract.ServiceCollectorContract, checkedAt time.Time) AWSServiceCollectorContractCheck {
	check := awsServiceCollectorContractCheck("fixture_conventions", "fixtures", true, checkedAt)
	check.EvidenceURL = "/docs/aws-service-collector-contract"
	check.Evidence = map[string]any{
		"fixture_count": len(contract.FixtureCases),
		"states":        awsServiceCollectorFixtureStates(contract.FixtureCases),
	}
	if err := awscontract.ValidateServiceCollectorFixtures(contract.FixtureCases); err != nil {
		check.Status = awsServiceCollectorContractStatusBlocked
		check.Message = "AWS service collector fixture conventions are incomplete."
		check.FailureReason = err.Error()
		check.Remediation = "Restore deterministic pagination, throttling, partial-failure, unsupported-region, permission-denied, empty, degraded, and success fixtures."
		check.Confidence = 0.35
		return check
	}
	check.Status = awsServiceCollectorContractStatusReady
	check.Message = "AWS service collector fixture states cover success and required failure modes."
	check.Confidence = 0.98
	return check
}

func awsServiceCollectorContractReadOnlyCheck(contract awscontract.ServiceCollectorContract, checkedAt time.Time) AWSServiceCollectorContractCheck {
	check := awsServiceCollectorContractCheck("read_only_boundaries", "safety", true, checkedAt)
	check.EvidenceURL = "/docs/auth/aws-connector"
	check.Evidence = map[string]any{
		"permissions": append([]string(nil), contract.RequiredPermissions...),
		"boundaries":  append([]string(nil), contract.ReadOnlyBoundaries...),
	}
	for _, permission := range contract.RequiredPermissions {
		if awscontract.ServiceCollectorPermissionReadsPayload(permission) {
			check.Status = awsServiceCollectorContractStatusBlocked
			check.Message = "AWS service collector permissions include a payload-reading action."
			check.FailureReason = fmt.Sprintf("%s is outside the read-only metadata boundary", permission)
			check.Remediation = "Remove secret-value, object-content, prompt, completion, browser-output, database-row, and customer-payload reads from the collector contract."
			check.Confidence = 0.2
			return check
		}
	}
	if len(contract.RequiredPermissions) == 0 || len(contract.ReadOnlyBoundaries) == 0 {
		check.Status = awsServiceCollectorContractStatusBlocked
		check.Message = "AWS service collector read-only contract is missing permission or boundary evidence."
		check.FailureReason = "read-only boundary is incomplete"
		check.Remediation = "Document required metadata permissions and explicit non-collection boundaries."
		check.Confidence = 0.3
		return check
	}
	check.Status = awsServiceCollectorContractStatusReady
	check.Message = "AWS service collector permissions stay inside read-only metadata boundaries."
	check.Confidence = 0.96
	return check
}

func awsServiceCollectorContractScopeCheck(scope db.Scope, project db.TenancyProject, checkedAt time.Time) AWSServiceCollectorContractCheck {
	check := awsServiceCollectorContractCheck("tenant_workspace_project_scope", "scope", true, checkedAt)
	check.EvidenceURL = awsBaselineProjectEvidenceURL(scope, project)
	check.Evidence = map[string]any{
		"tenant_id":    scope.TenantID,
		"workspace_id": project.WorkspaceID,
		"project_id":   project.ProjectID,
		"read_only":    true,
	}
	if strings.TrimSpace(scope.TenantID) == "" || strings.TrimSpace(project.WorkspaceID) == "" || strings.TrimSpace(project.ProjectID) == "" {
		check.Status = awsServiceCollectorContractStatusBlocked
		check.Message = "AWS service collector contract scope metadata is incomplete."
		check.FailureReason = "tenant, workspace, or project scope is missing"
		check.Remediation = "Resolve scoped project context before returning collector contract evidence."
		check.Confidence = 0.25
		return check
	}
	check.Status = awsServiceCollectorContractStatusReady
	check.Message = "AWS service collector contract response is tenant, workspace, and project scoped."
	check.Confidence = 0.97
	return check
}

func awsServiceCollectorContractCheck(name string, category string, required bool, checkedAt time.Time) AWSServiceCollectorContractCheck {
	return AWSServiceCollectorContractCheck{
		Name:       name,
		Category:   category,
		Required:   required,
		Status:     awsServiceCollectorContractStatusBlocked,
		Confidence: 0,
		Evidence:   map[string]any{},
		CheckedAt:  checkedAt,
	}
}

func summarizeAWSServiceCollectorContractChecks(checks []AWSServiceCollectorContractCheck) (string, float64, []string, []string) {
	blockedFailures := []string{}
	blockedRemediations := []string{}
	degradedFailures := []string{}
	degradedRemediations := []string{}
	degraded := false
	confidenceTotal := 0.0
	for _, check := range checks {
		confidenceTotal += check.Confidence
		if check.Status == awsServiceCollectorContractStatusBlocked && check.Required {
			blockedFailures = append(blockedFailures, firstNonEmptyAWSValue(check.FailureReason, fmt.Sprintf("%s is blocked", check.Name)))
			blockedRemediations = append(blockedRemediations, firstNonEmptyAWSValue(check.Remediation, "Restore the required AWS service collector contract check."))
		}
		if check.Status == awsServiceCollectorContractStatusDegraded {
			degraded = true
			if check.FailureReason != "" {
				degradedFailures = append(degradedFailures, check.FailureReason)
			}
			if check.Remediation != "" {
				degradedRemediations = append(degradedRemediations, check.Remediation)
			}
		}
	}
	if len(checks) == 0 {
		return awsServiceCollectorContractStatusBlocked, 0.25, []string{"service collector contract checks are missing"}, []string{"Restore service collector contract checks."}
	}
	averageConfidence := confidenceTotal / float64(len(checks))
	if len(blockedFailures) > 0 {
		return awsServiceCollectorContractStatusBlocked, lowerAWSServiceCollectorConfidence(averageConfidence, 0.45), dedupeStrings(blockedFailures), dedupeStrings(blockedRemediations)
	}
	if degraded {
		return awsServiceCollectorContractStatusDegraded, lowerAWSServiceCollectorConfidence(averageConfidence, 0.75), dedupeStrings(degradedFailures), dedupeStrings(degradedRemediations)
	}
	return awsServiceCollectorContractStatusReady, averageConfidence, []string{}, []string{}
}

func awsRequiredFixtureCaseCount(fixtures []awscontract.ServiceCollectorFixtureCase) int {
	count := 0
	for _, fixture := range fixtures {
		if fixture.Required {
			count++
		}
	}
	return count
}

func awsServiceCollectorGraphEdges(edges []awscontract.ServiceCollectorGraphEdgeContract) []AWSServiceCollectorGraphEdge {
	result := make([]AWSServiceCollectorGraphEdge, 0, len(edges))
	for _, edge := range edges {
		result = append(result, AWSServiceCollectorGraphEdge{
			Name:             edge.Name,
			RelationshipType: string(edge.RelationshipType),
			FromEndpoint:     string(edge.FromEndpoint),
			ToEndpoint:       string(edge.ToEndpoint),
			Evidence:         edge.Evidence,
			Required:         edge.Required,
		})
	}
	return result
}

func awsServiceCollectorFixtureCases(fixtures []awscontract.ServiceCollectorFixtureCase) []AWSServiceCollectorFixtureCase {
	result := make([]AWSServiceCollectorFixtureCase, 0, len(fixtures))
	for _, fixture := range fixtures {
		result = append(result, AWSServiceCollectorFixtureCase{
			ID:               fixture.ID,
			State:            string(fixture.State),
			Label:            fixture.Label,
			ExpectedStatus:   string(fixture.ExpectedStatus),
			SourceErrorCode:  fixture.SourceErrorCode,
			Retryable:        fixture.Retryable,
			Required:         fixture.Required,
			EvidenceBoundary: fixture.EvidenceBoundary,
		})
	}
	return result
}

func awsServiceCollectorFixtureStates(fixtures []awscontract.ServiceCollectorFixtureCase) []string {
	states := make([]string, 0, len(fixtures))
	for _, fixture := range fixtures {
		states = append(states, string(fixture.State))
	}
	return dedupeStrings(states)
}

func sameServiceCollectorStringSet(left []string, right []string) bool {
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

func lowerAWSServiceCollectorConfidence(confidence float64, maximum float64) float64 {
	if confidence < maximum {
		return confidence
	}
	return maximum
}
