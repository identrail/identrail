package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers"
)

const (
	awsCredentialReferencesCurrentIssue = 1496
	awsCredentialReferencesVersion      = "aws-credential-references-inventory-v1"
)

// Credential reference classification vocabulary. These mirror the live mapping
// engine in internal/providers/aws (which the API package cannot import without
// a cycle); they are kept in lockstep with that engine's constants.
const (
	credentialProviderOpenAI         = "openai"
	credentialProviderAnthropic      = "anthropic"
	credentialProviderBedrock        = "bedrock"
	credentialProviderGitHub         = "github"
	credentialProviderSlack          = "slack"
	credentialProviderDatabase       = "database"
	credentialProviderWebhook        = "webhook"
	credentialProviderSecretsManager = "aws_secrets_manager"
	credentialProviderSSM            = "aws_ssm"
	credentialProviderGeneric        = "generic"
)

type AWSCredentialReferencesInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	// ResourceType filters records to one workload resource type (for example
	// ecs_service, lambda_function, codebuild_project).
	ResourceType string `json:"resource_type,omitempty"`
	// Identity filters records to those whose workload identifier matches the
	// supplied substring.
	Identity string `json:"identity,omitempty"`
	// Provider filters records to one credential provider classification.
	Provider string `json:"provider,omitempty"`
}

type AWSCredentialReferenceCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSCredentialReferencesInventoryResult struct {
	TenantID                 string                              `json:"tenant_id"`
	WorkspaceID              string                              `json:"workspace_id"`
	ProjectID                string                              `json:"project_id"`
	ConnectorID              string                              `json:"connector_id,omitempty"`
	AccountID                string                              `json:"account_id,omitempty"`
	Region                   string                              `json:"region,omitempty"`
	ParentIssueNumber        int                                 `json:"parent_issue_number"`
	ParentIssueRef           string                              `json:"parent_issue_ref"`
	CurrentIssueNumber       int                                 `json:"current_issue_number"`
	CurrentIssueRef          string                              `json:"current_issue_ref"`
	Version                  string                              `json:"version"`
	Status                   string                              `json:"status"`
	FixtureState             string                              `json:"fixture_state"`
	Confidence               float64                             `json:"confidence"`
	ReferenceCount           int                                 `json:"reference_count"`
	ResolvedReferenceCount   int                                 `json:"resolved_reference_count"`
	UnresolvedReferenceCount int                                 `json:"unresolved_reference_count"`
	ExternalProviderKeyCount int                                 `json:"external_provider_key_count"`
	AIProviderKeyCount       int                                 `json:"ai_provider_key_count"`
	DatabaseCredentialCount  int                                 `json:"database_credential_count"`
	DistinctWorkloadCount    int                                 `json:"distinct_workload_count"`
	DistinctProviderCount    int                                 `json:"distinct_provider_count"`
	RelationshipCount        int                                 `json:"relationship_count"`
	ProviderBreakdown        map[string]int                      `json:"provider_breakdown"`
	FailureReasons           []string                            `json:"failure_reasons"`
	RemediationHints         []string                            `json:"remediation_hints"`
	EvidenceLinks            []string                            `json:"evidence_links"`
	CoverageGaps             []AWSCredentialReferenceCoverageGap `json:"coverage_gaps"`
	Records                  []AWSCredentialReferenceRecord      `json:"records"`
	Relationships            []AWSCredentialReferenceEdge        `json:"relationships"`
	Diagnostics              []AWSCredentialReferenceDiagnostic  `json:"diagnostics"`
	GeneratedAt              time.Time                           `json:"generated_at"`
	UpdatedAt                time.Time                           `json:"updated_at"`
}

type AWSCredentialReferenceRecord struct {
	AccountID          string    `json:"account_id"`
	Region             string    `json:"region"`
	WorkloadID         string    `json:"workload_id"`
	WorkloadType       string    `json:"workload_type"`
	WorkloadName       string    `json:"workload_name"`
	ResourceID         string    `json:"resource_id,omitempty"`
	ResourceType       string    `json:"resource_type"`
	SourceService      string    `json:"source_service"`
	Reference          string    `json:"reference"`
	ReferenceName      string    `json:"reference_name,omitempty"`
	ReferenceKind      string    `json:"reference_kind"`
	Provider           string    `json:"provider"`
	ProviderConfidence float64   `json:"provider_confidence"`
	Sensitivity        string    `json:"sensitivity"`
	Resolved           bool      `json:"resolved"`
	Unresolved         bool      `json:"unresolved"`
	TargetNodeID       string    `json:"target_node_id,omitempty"`
	Source             string    `json:"source"`
	EvidenceRef        string    `json:"evidence_ref"`
	Confidence         float64   `json:"confidence"`
	CollectedAt        time.Time `json:"collected_at"`
	Status             string    `json:"status"`
}

type AWSCredentialReferenceEdge struct {
	Type        string  `json:"type"`
	FromNodeID  string  `json:"from_node_id"`
	ToNodeID    string  `json:"to_node_id"`
	EvidenceRef string  `json:"evidence_ref"`
	Source      string  `json:"source"`
	Resolved    bool    `json:"resolved"`
	Confidence  float64 `json:"confidence"`
}

type AWSCredentialReferenceDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSCredentialReferencesInventory(ctx context.Context, workspaceID string, projectID string, request AWSCredentialReferencesInventoryRequest) (AWSCredentialReferencesInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSCredentialReferencesInventoryResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSCredentialReferencesInventoryResult{}, err
	}
	return buildAWSCredentialReferencesInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSCredentialReferencesInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSCredentialReferencesInventoryRequest, checkedAt time.Time) (AWSCredentialReferencesInventoryResult, error) {
	fixtureState := normalizeAWSCredentialReferencesFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSCredentialReferencesInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	if !validAWSCredentialProviderFilter(request.Provider) {
		return AWSCredentialReferencesInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, gaps := awsCredentialReferencesFixtureRecords(accountID, region, fixtureState, checkedAt)
	records = filterAWSCredentialReferenceRecords(records, request)
	status, confidence, failures, remediations := summarizeAWSCredentialReferencesInventory(fixtureState, diagnostics, records)
	relationships := awsCredentialReferenceEdges(records)
	return AWSCredentialReferencesInventoryResult{
		TenantID:                 scope.TenantID,
		WorkspaceID:              project.WorkspaceID,
		ProjectID:                project.ProjectID,
		ConnectorID:              connectorID,
		AccountID:                accountID,
		Region:                   region,
		ParentIssueNumber:        awsPlatformDependencyParentIssue,
		ParentIssueRef:           awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:       awsCredentialReferencesCurrentIssue,
		CurrentIssueRef:          awsIssueRef(awsCredentialReferencesCurrentIssue),
		Version:                  awsCredentialReferencesVersion,
		Status:                   status,
		FixtureState:             fixtureState,
		Confidence:               confidence,
		ReferenceCount:           len(records),
		ResolvedReferenceCount:   countCredentialReferences(records, func(r AWSCredentialReferenceRecord) bool { return r.Resolved }),
		UnresolvedReferenceCount: countCredentialReferences(records, func(r AWSCredentialReferenceRecord) bool { return r.Unresolved }),
		ExternalProviderKeyCount: countCredentialReferences(records, func(r AWSCredentialReferenceRecord) bool { return awsCredentialProviderIsExternal(r.Provider) }),
		AIProviderKeyCount:       countCredentialReferences(records, func(r AWSCredentialReferenceRecord) bool { return r.Sensitivity == "ai_provider_api_key" }),
		DatabaseCredentialCount:  countCredentialReferences(records, func(r AWSCredentialReferenceRecord) bool { return r.Provider == credentialProviderDatabase }),
		DistinctWorkloadCount:    countDistinctCredentialField(records, func(r AWSCredentialReferenceRecord) string { return r.WorkloadID }),
		DistinctProviderCount:    countDistinctCredentialField(records, func(r AWSCredentialReferenceRecord) string { return r.Provider }),
		RelationshipCount:        len(relationships),
		ProviderBreakdown:        awsCredentialProviderBreakdown(records),
		FailureReasons:           failures,
		RemediationHints:         remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsCredentialReferencesCurrentIssue),
			"/docs/aws-credential-references",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  gaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsCredentialReferenceDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSCredentialReferencesFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func validAWSCredentialProviderFilter(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", credentialProviderOpenAI, credentialProviderAnthropic, credentialProviderBedrock,
		credentialProviderGitHub, credentialProviderSlack, credentialProviderDatabase,
		credentialProviderWebhook, credentialProviderSecretsManager, credentialProviderSSM,
		credentialProviderGeneric:
		return true
	default:
		return false
	}
}

func awsCredentialProviderIsExternal(provider string) bool {
	switch provider {
	case credentialProviderOpenAI, credentialProviderAnthropic, credentialProviderBedrock,
		credentialProviderGitHub, credentialProviderSlack, credentialProviderDatabase,
		credentialProviderWebhook:
		return true
	default:
		return false
	}
}

func filterAWSCredentialReferenceRecords(records []AWSCredentialReferenceRecord, request AWSCredentialReferencesInventoryRequest) []AWSCredentialReferenceRecord {
	resourceType := strings.ToLower(strings.TrimSpace(request.ResourceType))
	identity := strings.ToLower(strings.TrimSpace(request.Identity))
	provider := strings.ToLower(strings.TrimSpace(request.Provider))
	if resourceType == "" && identity == "" && provider == "" {
		return records
	}
	filtered := make([]AWSCredentialReferenceRecord, 0, len(records))
	for _, record := range records {
		if resourceType != "" && strings.ToLower(record.ResourceType) != resourceType {
			continue
		}
		if provider != "" && record.Provider != provider {
			continue
		}
		if identity != "" && !strings.Contains(strings.ToLower(record.WorkloadID+" "+record.WorkloadName), identity) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func awsCredentialReferencesFixtureRecords(accountID, region, fixtureState string, checkedAt time.Time) ([]AWSCredentialReferenceRecord, []providers.SourceError, []AWSCredentialReferenceCoverageGap) {
	gaps := []AWSCredentialReferenceCoverageGap{{
		Capability:  "secret_value_inspection",
		Status:      "unsupported",
		Reason:      "This mapper reads reference names, ARNs, and source markers only; it never reads a secret, parameter, or environment value.",
		Remediation: "Inspect values through the owning secret store outside Identrail.",
	}, {
		Capability:  "inline_value_provider_detection",
		Status:      "partial",
		Reason:      "Provider detection for inline environment variables relies on name patterns; a non-conventional variable name may classify as generic.",
		Remediation: "Adopt provider-prefixed variable names (for example OPENAI_API_KEY) so references classify precisely.",
	}}
	switch fixtureState {
	case "permission_denied":
		return nil, []providers.SourceError{{Collector: "credential_reference_mapper", Code: "workload_inventory_unavailable", Message: "AccessDenied: workload collectors could not enumerate references", Retryable: false}}, gaps
	case "empty":
		return nil, nil, gaps
	}
	partition := awsCredentialReferencePartition(region)
	ecsWorkload := fmt.Sprintf("arn:%s:ecs:%s:%s:service/prod/agent", partition, region, accountID)
	lambdaWorkload := fmt.Sprintf("arn:%s:lambda:%s:%s:function:summarizer", partition, region, accountID)
	codeBuildWorkload := fmt.Sprintf("arn:%s:codebuild:%s:%s:project/release", partition, region, accountID)
	openAISecret := fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:openai/api-key-AbCdEf", partition, region, accountID)

	records := []AWSCredentialReferenceRecord{
		awsCredentialReferenceFixtureRecord(accountID, region, ecsWorkload, "agent", "ecs_service", "ecs", checkedAt, func(r *AWSCredentialReferenceRecord) {
			r.Reference = "OPENAI_API_KEY=" + openAISecret
			r.ReferenceName = "OPENAI_API_KEY"
			r.ReferenceKind = "secrets_manager"
			r.Provider = credentialProviderOpenAI
			r.ProviderConfidence = 0.9
			r.Sensitivity = "ai_provider_api_key"
			r.Resolved = true
			r.TargetNodeID = "aws:resource:secrets-manager-secret:" + openAISecret
			r.Confidence = 0.95
		}),
		awsCredentialReferenceFixtureRecord(accountID, region, ecsWorkload, "agent", "ecs_service", "ecs", checkedAt, func(r *AWSCredentialReferenceRecord) {
			r.Reference = "ANTHROPIC_API_KEY"
			r.ReferenceName = "ANTHROPIC_API_KEY"
			r.ReferenceKind = "environment_variable"
			r.Provider = credentialProviderAnthropic
			r.ProviderConfidence = 0.9
			r.Sensitivity = "ai_provider_api_key"
			r.Unresolved = true
			r.TargetNodeID = "aws:resource:credential-reference:" + strings.ToLower(ecsWorkload) + "|anthropic|anthropic_api_key"
			r.Confidence = 0.9
		}),
		awsCredentialReferenceFixtureRecord(accountID, region, lambdaWorkload, "summarizer", "lambda_function", "lambda", checkedAt, func(r *AWSCredentialReferenceRecord) {
			r.Reference = "DATABASE_URL"
			r.ReferenceName = "DATABASE_URL"
			r.ReferenceKind = "environment_variable"
			r.Provider = credentialProviderDatabase
			r.ProviderConfidence = 0.8
			r.Sensitivity = "database_credential"
			r.Unresolved = true
			r.TargetNodeID = "aws:resource:credential-reference:" + strings.ToLower(lambdaWorkload) + "|database|database_url"
			r.Confidence = 0.8
		}),
		awsCredentialReferenceFixtureRecord(accountID, region, codeBuildWorkload, "release", "codebuild_project", "codebuild", checkedAt, func(r *AWSCredentialReferenceRecord) {
			r.Reference = "GITHUB_TOKEN=SECRETS_MANAGER:github/ci-token"
			r.ReferenceName = "GITHUB_TOKEN"
			r.ReferenceKind = "secrets_manager"
			r.Provider = credentialProviderGitHub
			r.ProviderConfidence = 0.88
			r.Sensitivity = "source_control_token"
			r.Unresolved = true
			r.TargetNodeID = "aws:resource:credential-reference:" + strings.ToLower(codeBuildWorkload) + "|github|github_token"
			r.Confidence = 0.88
		}),
		awsCredentialReferenceFixtureRecord(accountID, region, codeBuildWorkload, "release", "codebuild_project", "codebuild", checkedAt, func(r *AWSCredentialReferenceRecord) {
			r.Reference = "SLACK_WEBHOOK_URL"
			r.ReferenceName = "SLACK_WEBHOOK_URL"
			r.ReferenceKind = "environment_variable"
			r.Provider = credentialProviderSlack
			r.ProviderConfidence = 0.85
			r.Sensitivity = "messaging_token"
			r.Unresolved = true
			r.TargetNodeID = "aws:resource:credential-reference:" + strings.ToLower(codeBuildWorkload) + "|slack|slack_webhook_url"
			r.Confidence = 0.85
		}),
	}
	diagnostics := []providers.SourceError{}
	if fixtureState == "degraded" {
		records[1].Status = "degraded"
		diagnostics = append(diagnostics, providers.SourceError{Collector: "credential_reference_mapper", SourceID: ecsWorkload, Code: "workload_environment_partial", Message: "task definition environment was partially redacted by the source collector", Retryable: true})
	}
	if fixtureState == "partial_failure" {
		records = records[:3]
		diagnostics = append(diagnostics, providers.SourceError{Collector: "credential_reference_mapper", SourceID: codeBuildWorkload, Code: "workload_inventory_partial", Message: "codebuild project batch describe failed for one project", Retryable: true})
	}
	return records, diagnostics, gaps
}

func awsCredentialReferenceFixtureRecord(accountID, region, workloadID, workloadName, resourceType, sourceService string, checkedAt time.Time, mutate func(*AWSCredentialReferenceRecord)) AWSCredentialReferenceRecord {
	record := AWSCredentialReferenceRecord{
		AccountID:     accountID,
		Region:        region,
		WorkloadID:    workloadID,
		WorkloadType:  resourceType,
		WorkloadName:  workloadName,
		ResourceID:    workloadID,
		ResourceType:  resourceType,
		SourceService: sourceService,
		Provider:      credentialProviderGeneric,
		Sensitivity:   "generic_secret",
		ReferenceKind: "environment_variable",
		Source:        sourceService + "_workload_reference",
		Confidence:    0.6,
		CollectedAt:   checkedAt,
		Status:        "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	record.EvidenceRef = record.Reference
	return record
}

func awsCredentialReferenceEdges(records []AWSCredentialReferenceRecord) []AWSCredentialReferenceEdge {
	edges := []AWSCredentialReferenceEdge{}
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.TargetNodeID) == "" {
			continue
		}
		edgeKey := record.WorkloadID + "|" + record.TargetNodeID
		if _, exists := seen[edgeKey]; exists {
			continue
		}
		seen[edgeKey] = struct{}{}
		edges = append(edges, AWSCredentialReferenceEdge{
			Type:        "uses_secret",
			FromNodeID:  record.WorkloadID,
			ToNodeID:    record.TargetNodeID,
			EvidenceRef: record.Reference,
			Source:      record.Source,
			Resolved:    record.Resolved,
			Confidence:  record.Confidence,
		})
	}
	return edges
}

func summarizeAWSCredentialReferencesInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSCredentialReferenceRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.3, []string{"Workload inventory required for credential reference mapping is permission denied."}, []string{"Grant the metadata-only workload collector permissions (ECS, Lambda, CodeBuild describe/list) so references can be mapped."}
	case "partial_failure", "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72, awsCredentialReferenceMessages(diagnostics), []string{"Review diagnostics and rerun after the affected workload collectors complete."}
	default:
		if len(records) == 0 {
			return awsPlatformDependencyStatusReady, 0.82, nil, []string{"No credential or secret references were found across the inventoried workloads."}
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, []string{"Prioritize unresolved external provider keys (AI, source control, database, webhook) for secret-store migration and rotation."}
	}
}

func awsCredentialReferenceDiagnostics(diagnostics []providers.SourceError) []AWSCredentialReferenceDiagnostic {
	result := make([]AWSCredentialReferenceDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSCredentialReferenceDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: "Confirm the metadata-only workload collector permissions; the mapper never reads secret or environment values.",
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsCredentialProviderBreakdown(records []AWSCredentialReferenceRecord) map[string]int {
	breakdown := map[string]int{}
	for _, record := range records {
		if record.Provider == "" {
			continue
		}
		breakdown[record.Provider]++
	}
	return breakdown
}

func countCredentialReferences(records []AWSCredentialReferenceRecord, pred func(AWSCredentialReferenceRecord) bool) int {
	count := 0
	for _, record := range records {
		if pred(record) {
			count++
		}
	}
	return count
}

func countDistinctCredentialField(records []AWSCredentialReferenceRecord, field func(AWSCredentialReferenceRecord) string) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if value := strings.TrimSpace(field(record)); value != "" {
			seen[value] = struct{}{}
		}
	}
	return len(seen)
}

func awsCredentialReferenceMessages(diagnostics []providers.SourceError) []string {
	messages := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if message := strings.TrimSpace(diagnostic.Message); message != "" {
			messages = append(messages, message)
		}
	}
	return dedupeStrings(messages)
}

func awsCredentialReferencePartition(region string) string {
	normalized := strings.ToLower(strings.TrimSpace(region))
	switch {
	case strings.HasPrefix(normalized, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(normalized, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}
