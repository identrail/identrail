package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	awsLambdaExecutionRoleCurrentIssue = 1479
	awsLambdaExecutionRoleVersion      = "aws-lambda-execution-role-inventory-v1"
)

// AWSLambdaExecutionRoleInventoryRequest controls the deterministic inventory state.
type AWSLambdaExecutionRoleInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSLambdaExecutionRoleInventoryResult exposes scoped Lambda execution-role evidence.
type AWSLambdaExecutionRoleInventoryResult struct {
	TenantID                 string                               `json:"tenant_id"`
	WorkspaceID              string                               `json:"workspace_id"`
	ProjectID                string                               `json:"project_id"`
	ConnectorID              string                               `json:"connector_id,omitempty"`
	AccountID                string                               `json:"account_id,omitempty"`
	Region                   string                               `json:"region,omitempty"`
	ParentIssueNumber        int                                  `json:"parent_issue_number"`
	ParentIssueRef           string                               `json:"parent_issue_ref"`
	CurrentIssueNumber       int                                  `json:"current_issue_number"`
	CurrentIssueRef          string                               `json:"current_issue_ref"`
	Version                  string                               `json:"version"`
	Status                   string                               `json:"status"`
	FixtureState             string                               `json:"fixture_state"`
	Confidence               float64                              `json:"confidence"`
	RecordCount              int                                  `json:"record_count"`
	FunctionCount            int                                  `json:"function_count"`
	IdentityCount            int                                  `json:"identity_count"`
	ResourceCount            int                                  `json:"resource_count"`
	RelationshipCount        int                                  `json:"relationship_count"`
	EventSourceCount         int                                  `json:"event_source_count"`
	DisabledEventSourceCount int                                  `json:"disabled_event_source_count"`
	FailureReasons           []string                             `json:"failure_reasons"`
	RemediationHints         []string                             `json:"remediation_hints"`
	EvidenceLinks            []string                             `json:"evidence_links"`
	Records                  []AWSLambdaExecutionRoleRecord       `json:"records"`
	Relationships            []AWSLambdaExecutionRoleRelationship `json:"relationships"`
	Diagnostics              []AWSLambdaExecutionRoleDiagnostic   `json:"diagnostics"`
	GeneratedAt              time.Time                            `json:"generated_at"`
	UpdatedAt                time.Time                            `json:"updated_at"`
}

// AWSLambdaExecutionRoleRecord is the operator-facing row for one Lambda function/role link.
type AWSLambdaExecutionRoleRecord struct {
	AccountID                  string            `json:"account_id"`
	Region                     string            `json:"region"`
	Service                    string            `json:"service"`
	WorkloadID                 string            `json:"workload_id"`
	WorkloadType               string            `json:"workload_type"`
	WorkloadName               string            `json:"workload_name"`
	RoleARN                    string            `json:"role_arn,omitempty"`
	RoleName                   string            `json:"role_name,omitempty"`
	FunctionARN                string            `json:"function_arn,omitempty"`
	FunctionName               string            `json:"function_name,omitempty"`
	FunctionVersion            string            `json:"function_version,omitempty"`
	FunctionState              string            `json:"function_state,omitempty"`
	LastUpdateStatus           string            `json:"last_update_status,omitempty"`
	Runtime                    string            `json:"runtime,omitempty"`
	PackageType                string            `json:"package_type,omitempty"`
	Handler                    string            `json:"handler,omitempty"`
	KMSKeyARN                  string            `json:"kms_key_arn,omitempty"`
	MemorySize                 int32             `json:"memory_size,omitempty"`
	Timeout                    int32             `json:"timeout,omitempty"`
	VPCID                      string            `json:"vpc_id,omitempty"`
	SubnetIDs                  []string          `json:"subnet_ids,omitempty"`
	SecurityGroupIDs           []string          `json:"security_group_ids,omitempty"`
	Architectures              []string          `json:"architectures,omitempty"`
	LayerARNs                  []string          `json:"layer_arns,omitempty"`
	AliasNames                 []string          `json:"alias_names,omitempty"`
	VersionRefs                []string          `json:"version_refs,omitempty"`
	EventSourceARNs            []string          `json:"event_source_arns,omitempty"`
	EventSourceMappingUUIDs    []string          `json:"event_source_mapping_uuids,omitempty"`
	DisabledEventSourceARNs    []string          `json:"disabled_event_source_arns,omitempty"`
	DisabledEventSourceReasons []string          `json:"disabled_event_source_reasons,omitempty"`
	EnvironmentKeys            []string          `json:"environment_keys,omitempty"`
	SecretRefs                 []string          `json:"secret_refs,omitempty"`
	Tags                       map[string]string `json:"tags,omitempty"`
	Source                     string            `json:"source"`
	EvidenceRef                string            `json:"evidence_ref"`
	FromNodeID                 string            `json:"from_node_id"`
	ToNodeID                   string            `json:"to_node_id,omitempty"`
	RelationshipType           string            `json:"relationship_type"`
	Confidence                 float64           `json:"confidence"`
	CollectedAt                time.Time         `json:"collected_at"`
	Status                     string            `json:"status"`
}

// AWSLambdaExecutionRoleRelationship is the graph evidence exposed by the API.
type AWSLambdaExecutionRoleRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSLambdaExecutionRoleDiagnostic is one explicit non-success state.
type AWSLambdaExecutionRoleDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSLambdaExecutionRoleInventory returns scoped deterministic Lambda execution-role inventory.
func (s *Service) GetAWSLambdaExecutionRoleInventory(ctx context.Context, workspaceID string, projectID string, request AWSLambdaExecutionRoleInventoryRequest) (AWSLambdaExecutionRoleInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSLambdaExecutionRoleInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSLambdaExecutionRoleInventoryResult{}, err
	}
	return buildAWSLambdaExecutionRoleInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSLambdaExecutionRoleInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSLambdaExecutionRoleInventoryRequest, checkedAt time.Time) (AWSLambdaExecutionRoleInventoryResult, error) {
	fixtureState := normalizeAWSLambdaExecutionRoleFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSLambdaExecutionRoleInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics := awsLambdaExecutionRoleFixtureRecords(scope, project, connectorID, accountID, region, fixtureState, checkedAt)

	for _, record := range records {
		if strings.TrimSpace(record.RoleARN) == "" {
			continue
		}
		if _, err := awscontract.NormalizeServiceCollectorRecord(awscontract.ServiceCollectorRecord{
			TenantID:      scope.TenantID,
			WorkspaceID:   project.WorkspaceID,
			ProjectID:     project.ProjectID,
			ConnectorID:   connectorID,
			AccountID:     record.AccountID,
			Region:        record.Region,
			Service:       record.Service,
			WorkloadID:    record.WorkloadID,
			WorkloadType:  record.WorkloadType,
			WorkloadName:  record.WorkloadName,
			RoleARN:       record.RoleARN,
			Source:        record.Source,
			EvidenceRef:   record.EvidenceRef,
			Confidence:    record.Confidence,
			ScanID:        "aws-lambda-execution-role-fixture",
			CollectorName: "lambda_execution_role",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSLambdaExecutionRoleInventoryResult{}, fmt.Errorf("validate lambda execution role contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSLambdaExecutionRoleInventory(fixtureState, diagnostics)
	relationships := awsLambdaExecutionRoleRelationships(records)
	result := AWSLambdaExecutionRoleInventoryResult{
		TenantID:                 scope.TenantID,
		WorkspaceID:              project.WorkspaceID,
		ProjectID:                project.ProjectID,
		ConnectorID:              connectorID,
		AccountID:                accountID,
		Region:                   region,
		ParentIssueNumber:        awsPlatformDependencyParentIssue,
		ParentIssueRef:           awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:       awsLambdaExecutionRoleCurrentIssue,
		CurrentIssueRef:          awsIssueRef(awsLambdaExecutionRoleCurrentIssue),
		Version:                  awsLambdaExecutionRoleVersion,
		Status:                   status,
		FixtureState:             fixtureState,
		Confidence:               confidence,
		RecordCount:              len(records),
		FunctionCount:            awsLambdaExecutionRoleFunctionCount(records),
		IdentityCount:            awsLambdaExecutionRoleIdentityCount(records),
		ResourceCount:            awsLambdaExecutionRoleResourceCount(records),
		RelationshipCount:        len(relationships),
		EventSourceCount:         awsLambdaExecutionRoleEventSourceCount(records),
		DisabledEventSourceCount: awsLambdaExecutionRoleDisabledEventSourceCount(records),
		FailureReasons:           failures,
		RemediationHints:         remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsLambdaExecutionRoleCurrentIssue),
			"/docs/aws-lambda-execution-roles",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsLambdaExecutionRoleDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}
	return result, nil
}

func normalizeAWSLambdaExecutionRoleFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "", "success":
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsLambdaExecutionRoleFixtureRecords(scope db.Scope, project db.TenancyProject, connectorID string, accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSLambdaExecutionRoleRecord, []providers.SourceError) {
	baseRecord := func(functionName string, roleARN string) AWSLambdaExecutionRoleRecord {
		functionARN := fmt.Sprintf("arn:aws:lambda:%s:%s:function:%s", region, accountID, functionName)
		roleName := roleNameFromARNForAPI(roleARN)
		status := "ready"
		if strings.TrimSpace(roleARN) == "" {
			status = "degraded"
		}
		return AWSLambdaExecutionRoleRecord{
			AccountID:        accountID,
			Region:           region,
			Service:          "lambda",
			WorkloadID:       functionARN,
			WorkloadType:     "lambda_function",
			WorkloadName:     functionName,
			RoleARN:          roleARN,
			RoleName:         roleName,
			FunctionARN:      functionARN,
			FunctionName:     functionName,
			FunctionVersion:  "$LATEST",
			FunctionState:    "Active",
			LastUpdateStatus: "Successful",
			PackageType:      "Zip",
			Architectures:    []string{"x86_64"},
			Tags:             map[string]string{"owner": "platform", "service": "payments"},
			Source:           "listfunctions",
			EvidenceRef:      functionARN,
			FromNodeID:       awsLambdaFunctionNodeID(accountID, region, functionARN),
			ToNodeID:         awsIdentityNodeIDForAPI(roleARN),
			RelationshipType: "runs_as",
			Confidence:       0.96,
			CollectedAt:      checkedAt,
			Status:           status,
		}
	}

	paymentsRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-lambda-execution", accountID)
	payments := baseRecord("payments-worker", paymentsRoleARN)
	payments.Runtime = "nodejs20.x"
	payments.Handler = "index.handler"
	payments.KMSKeyARN = fmt.Sprintf("arn:aws:kms:%s:%s:key/lambda-env", region, accountID)
	payments.MemorySize = 512
	payments.Timeout = 30
	payments.VPCID = "vpc-prod"
	payments.SubnetIDs = []string{"subnet-a", "subnet-b"}
	payments.SecurityGroupIDs = []string{"sg-lambda-payments"}
	payments.AliasNames = []string{"prod=3"}
	payments.VersionRefs = []string{"$LATEST", "3"}
	payments.EventSourceARNs = []string{fmt.Sprintf("arn:aws:sqs:%s:%s:payments", region, accountID)}
	payments.EventSourceMappingUUIDs = []string{"mapping-payments-sqs"}
	payments.EnvironmentKeys = []string{"APP_ENV", "LOG_LEVEL", "DATABASE_PASSWORD"}
	payments.SecretRefs = []string{fmt.Sprintf("BASIC_AUTH=arn:aws:secretsmanager:%s:%s:secret:lambda/kafka", region, accountID)}

	resizerRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/image-resizer-lambda-execution", accountID)
	resizer := baseRecord("image-resizer", resizerRoleARN)
	resizer.Runtime = "python3.12"
	resizer.Handler = "handler.resize"
	resizer.MemorySize = 1024
	resizer.Timeout = 60
	resizer.LayerARNs = []string{fmt.Sprintf("arn:aws:lambda:%s:%s:layer:image-tools:5", region, accountID)}
	resizer.EnvironmentKeys = []string{"APP_ENV", "OUTPUT_BUCKET"}
	resizer.Tags = map[string]string{"owner": "media", "service": "images"}

	disabled := payments
	disabled.EventSourceARNs = append([]string(nil), payments.EventSourceARNs...)
	disabled.DisabledEventSourceARNs = []string{fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/legacy-events/stream/2026-06-05T00:00:00.000", region, accountID)}
	disabled.DisabledEventSourceReasons = []string{"mapping-legacy-stream=Disabled by operator"}
	disabled.EventSourceMappingUUIDs = append(disabled.EventSourceMappingUUIDs, "mapping-legacy-stream")
	disabled.Status = "degraded"
	disabled.Confidence = 0.88

	switch fixtureState {
	case "empty":
		return nil, nil
	case "degraded":
		return []AWSLambdaExecutionRoleRecord{disabled}, []providers.SourceError{{
			Collector: "aws_lambda/lambda_execution_role",
			SourceID:  "mapping-legacy-stream",
			Code:      "disabled_event_source",
			Message:   "Lambda event source mapping is disabled; role evidence remains visible but invocation coverage is degraded",
			Retryable: false,
		}}
	case "partial_failure":
		return []AWSLambdaExecutionRoleRecord{payments}, []providers.SourceError{{
			Collector: "aws_lambda/lambda_execution_role",
			SourceID:  fmt.Sprintf("service=lambda|account=%s|region=%s|source=list_event_source_mappings", accountID, region),
			Code:      "event_source_mapping_list_failed",
			Message:   "Lambda event source mappings could not be listed for one function; successful execution-role evidence remains visible",
			Retryable: true,
		}}
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_lambda/lambda_execution_role",
			SourceID:  fmt.Sprintf("service=lambda|account=%s|region=%s|source=listfunctions", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only Lambda ListFunctions, ListAliases, ListVersionsByFunction, ListEventSourceMappings, or ListTags permission is missing",
			Retryable: false,
		}}
	default:
		return []AWSLambdaExecutionRoleRecord{payments, resizer}, nil
	}
}

func summarizeAWSLambdaExecutionRoleInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"lambda execution role collection is blocked by missing read-only permission"}, []string{"Grant lambda:ListFunctions, lambda:ListAliases, lambda:ListVersionsByFunction, lambda:ListEventSourceMappings, and lambda:ListTags for metadata-only collection."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.68, []string{"one or more Lambda event sources are disabled or not fully enabled"}, []string{"Keep Lambda execution-role evidence visible and inspect disabled event-source mappings before treating invocation coverage as complete."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.76, []string{"one Lambda metadata partition failed while successful function-role records remain visible"}, []string{"Retry the failed Lambda function metadata call without discarding successful execution-role evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.8, []string{"lambda execution role collection returned diagnostics"}, []string{"Review diagnostics before treating Lambda coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.97, nil, nil
	}
}

func awsLambdaExecutionRoleRelationships(records []AWSLambdaExecutionRoleRecord) []AWSLambdaExecutionRoleRelationship {
	result := make([]AWSLambdaExecutionRoleRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		result = append(result, AWSLambdaExecutionRoleRelationship{
			Type:        "runs_as",
			FromNodeID:  record.FromNodeID,
			ToNodeID:    record.ToNodeID,
			EvidenceRef: record.EvidenceRef,
		})
	}
	return result
}

func awsLambdaExecutionRoleFunctionCount(records []AWSLambdaExecutionRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" {
			continue
		}
		seen[record.FromNodeID] = struct{}{}
	}
	return len(seen)
}

func awsLambdaExecutionRoleIdentityCount(records []AWSLambdaExecutionRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		seen[record.ToNodeID] = struct{}{}
	}
	return len(seen)
}

func awsLambdaExecutionRoleResourceCount(records []AWSLambdaExecutionRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.FunctionARN) != "" {
			seen[record.FunctionARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsLambdaExecutionRoleEventSourceCount(records []AWSLambdaExecutionRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, arn := range append(append([]string(nil), record.EventSourceARNs...), record.DisabledEventSourceARNs...) {
			if strings.TrimSpace(arn) != "" {
				seen[arn] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsLambdaExecutionRoleDisabledEventSourceCount(records []AWSLambdaExecutionRoleRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, arn := range record.DisabledEventSourceARNs {
			if strings.TrimSpace(arn) != "" {
				seen[arn] = struct{}{}
			}
		}
	}
	return len(seen)
}

func awsLambdaExecutionRoleDiagnostics(diagnostics []providers.SourceError) []AWSLambdaExecutionRoleDiagnostic {
	result := make([]AWSLambdaExecutionRoleDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSLambdaExecutionRoleDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsLambdaExecutionRoleDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsLambdaExecutionRoleDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only Lambda read permissions; do not add function-code, log, or secret-value reads."
	case "disabled_event_source":
		return "Inspect the disabled Lambda event-source mapping and keep role evidence separate from complete invocation coverage until it is enabled or intentionally excluded."
	case "event_source_mapping_list_failed", "alias_list_failed", "version_list_failed", "tags_list_failed":
		return "Retry only the failed Lambda metadata call and keep successful function-role records visible."
	case "missing_lambda_execution_role":
		return "Inspect the Lambda function role configuration before using it for least-privilege reasoning."
	default:
		return "Review the Lambda collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsLambdaFunctionNodeID(accountID string, region string, functionARN string) string {
	account := strings.TrimSpace(accountID)
	if account == "" {
		account = "account"
	}
	trimmedRegion := strings.TrimSpace(region)
	if trimmedRegion == "" {
		trimmedRegion = "region"
	}
	normalizedFunctionARN := strings.TrimSpace(functionARN)
	if normalizedFunctionARN == "" {
		normalizedFunctionARN = "function"
	}
	return fmt.Sprintf("aws:workload:lambda:%s:%s:function/%s", account, trimmedRegion, normalizedFunctionARN)
}
