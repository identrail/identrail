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
	awsDynamoDBRDSReachabilityCurrentIssue = 1494
	awsDynamoDBRDSReachabilityVersion      = "aws-dynamodb-rds-reachability-inventory-v1"
)

type AWSDynamoDBRDSReachabilityInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Identity     string `json:"identity,omitempty"`
}

type AWSDynamoDBRDSCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSDynamoDBRDSReachabilityInventoryResult struct {
	TenantID                  string                                   `json:"tenant_id"`
	WorkspaceID               string                                   `json:"workspace_id"`
	ProjectID                 string                                   `json:"project_id"`
	ConnectorID               string                                   `json:"connector_id,omitempty"`
	AccountID                 string                                   `json:"account_id,omitempty"`
	Region                    string                                   `json:"region,omitempty"`
	ParentIssueNumber         int                                      `json:"parent_issue_number"`
	ParentIssueRef            string                                   `json:"parent_issue_ref"`
	CurrentIssueNumber        int                                      `json:"current_issue_number"`
	CurrentIssueRef           string                                   `json:"current_issue_ref"`
	Version                   string                                   `json:"version"`
	Status                    string                                   `json:"status"`
	FixtureState              string                                   `json:"fixture_state"`
	Confidence                float64                                  `json:"confidence"`
	ResourceCount             int                                      `json:"resource_count"`
	DynamoDBTableCount        int                                      `json:"dynamodb_table_count"`
	DynamoDBStreamCount       int                                      `json:"dynamodb_stream_count"`
	RDSInstanceCount          int                                      `json:"rds_instance_count"`
	RDSClusterCount           int                                      `json:"rds_cluster_count"`
	RDSProxyCount             int                                      `json:"rds_proxy_count"`
	PublicResourceCount       int                                      `json:"public_resource_count"`
	CrossAccountResourceCount int                                      `json:"cross_account_resource_count"`
	EncryptedResourceCount    int                                      `json:"encrypted_resource_count"`
	IAMAuthResourceCount      int                                      `json:"iam_auth_resource_count"`
	IdentityGrantCount        int                                      `json:"identity_grant_count"`
	DenyGrantCount            int                                      `json:"deny_grant_count"`
	AssociatedRoleCount       int                                      `json:"associated_role_count"`
	RelationshipCount         int                                      `json:"relationship_count"`
	FailureReasons            []string                                 `json:"failure_reasons"`
	RemediationHints          []string                                 `json:"remediation_hints"`
	EvidenceLinks             []string                                 `json:"evidence_links"`
	CoverageGaps              []AWSDynamoDBRDSCoverageGap              `json:"coverage_gaps"`
	Records                   []AWSDynamoDBRDSReachabilityRecord       `json:"records"`
	Relationships             []AWSDynamoDBRDSReachabilityRelationship `json:"relationships"`
	Diagnostics               []AWSDynamoDBRDSReachabilityDiagnostic   `json:"diagnostics"`
	GeneratedAt               time.Time                                `json:"generated_at"`
	UpdatedAt                 time.Time                                `json:"updated_at"`
}

type AWSDynamoDBRDSReachabilityRecord struct {
	AccountID                        string                        `json:"account_id"`
	Region                           string                        `json:"region"`
	Service                          string                        `json:"service"`
	ResourceARN                      string                        `json:"resource_arn"`
	ResourceName                     string                        `json:"resource_name"`
	ResourceType                     string                        `json:"resource_type"`
	ResourceID                       string                        `json:"resource_id,omitempty"`
	Engine                           string                        `json:"engine,omitempty"`
	EngineVersion                    string                        `json:"engine_version,omitempty"`
	ResourceStatus                   string                        `json:"resource_status,omitempty"`
	Endpoint                         string                        `json:"endpoint,omitempty"`
	KMSKeyID                         string                        `json:"kms_key_id,omitempty"`
	StorageEncrypted                 bool                          `json:"storage_encrypted"`
	IAMDatabaseAuthenticationEnabled bool                          `json:"iam_database_authentication_enabled"`
	PubliclyAccessible               bool                          `json:"publicly_accessible"`
	DeletionProtectionEnabled        bool                          `json:"deletion_protection_enabled"`
	PerformanceInsightsEnabled       bool                          `json:"performance_insights_enabled"`
	StreamEnabled                    bool                          `json:"stream_enabled"`
	StreamARN                        string                        `json:"stream_arn,omitempty"`
	BillingMode                      string                        `json:"billing_mode,omitempty"`
	AssociatedRoleARNs               []string                      `json:"associated_role_arns,omitempty"`
	IdentityGrants                   []AWSDynamoDBRDSIdentityGrant `json:"identity_grants,omitempty"`
	HasResourcePolicy                bool                          `json:"has_resource_policy"`
	ResourcePolicyStatementCount     int                           `json:"resource_policy_statement_count"`
	ResourcePolicySource             string                        `json:"resource_policy_source,omitempty"`
	ExposureClassification           string                        `json:"exposure_classification"`
	ExposureReasons                  []string                      `json:"exposure_reasons,omitempty"`
	Tags                             map[string]string             `json:"tags,omitempty"`
	Source                           string                        `json:"source"`
	EvidenceRef                      string                        `json:"evidence_ref"`
	FromNodeID                       string                        `json:"from_node_id"`
	RelationshipType                 string                        `json:"relationship_type"`
	Confidence                       float64                       `json:"confidence"`
	CollectedAt                      time.Time                     `json:"collected_at"`
	Status                           string                        `json:"status"`
}

type AWSDynamoDBRDSIdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"`
	Effect            string   `json:"effect"`
	Actions           []string `json:"actions,omitempty"`
	NotAction         bool     `json:"not_action,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

type AWSDynamoDBRDSReachabilityRelationship struct {
	Type          string   `json:"type"`
	FromNodeID    string   `json:"from_node_id"`
	ToNodeID      string   `json:"to_node_id"`
	EvidenceRef   string   `json:"evidence_ref"`
	Effect        string   `json:"effect"`
	PrincipalType string   `json:"principal_type"`
	Capabilities  []string `json:"capabilities,omitempty"`
	HasCondition  bool     `json:"has_condition,omitempty"`
}

type AWSDynamoDBRDSReachabilityDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

func (s *Service) GetAWSDynamoDBRDSReachabilityInventory(ctx context.Context, workspaceID string, projectID string, request AWSDynamoDBRDSReachabilityInventoryRequest) (AWSDynamoDBRDSReachabilityInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSDynamoDBRDSReachabilityInventoryResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSDynamoDBRDSReachabilityInventoryResult{}, err
	}
	return buildAWSDynamoDBRDSReachabilityInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSDynamoDBRDSReachabilityInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSDynamoDBRDSReachabilityInventoryRequest, checkedAt time.Time) (AWSDynamoDBRDSReachabilityInventoryResult, error) {
	fixtureState := normalizeAWSDynamoDBRDSReachabilityFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSDynamoDBRDSReachabilityInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, gaps := awsDynamoDBRDSReachabilityFixtureRecords(accountID, region, fixtureState, checkedAt)
	records = filterAWSDynamoDBRDSReachabilityRecords(records, request)
	for _, record := range records {
		if err := validateAWSDynamoDBRDSReachabilityRecord(scope, project, connectorID, record); err != nil {
			return AWSDynamoDBRDSReachabilityInventoryResult{}, fmt.Errorf("validate dynamodb/rds reachability record: %w", err)
		}
	}
	status, confidence, failures, remediations := summarizeAWSDynamoDBRDSReachabilityInventory(fixtureState, diagnostics, records)
	relationships := awsDynamoDBRDSReachabilityRelationships(records)
	return AWSDynamoDBRDSReachabilityInventoryResult{
		TenantID:                  scope.TenantID,
		WorkspaceID:               project.WorkspaceID,
		ProjectID:                 project.ProjectID,
		ConnectorID:               connectorID,
		AccountID:                 accountID,
		Region:                    region,
		ParentIssueNumber:         awsPlatformDependencyParentIssue,
		ParentIssueRef:            awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:        awsDynamoDBRDSReachabilityCurrentIssue,
		CurrentIssueRef:           awsIssueRef(awsDynamoDBRDSReachabilityCurrentIssue),
		Version:                   awsDynamoDBRDSReachabilityVersion,
		Status:                    status,
		FixtureState:              fixtureState,
		Confidence:                confidence,
		ResourceCount:             len(records),
		DynamoDBTableCount:        countDynamoDBRDSResources(records, "dynamodb_table"),
		DynamoDBStreamCount:       countDynamoDBRDSResources(records, "dynamodb_stream"),
		RDSInstanceCount:          countDynamoDBRDSResources(records, "rds_instance"),
		RDSClusterCount:           countDynamoDBRDSResources(records, "rds_cluster"),
		RDSProxyCount:             countDynamoDBRDSResources(records, "rds_proxy"),
		PublicResourceCount:       countDynamoDBRDSByExposure(records, "public"),
		CrossAccountResourceCount: countDynamoDBRDSByExposure(records, "cross_account"),
		EncryptedResourceCount:    countDynamoDBRDSRecordsWith(records, func(r AWSDynamoDBRDSReachabilityRecord) bool { return r.StorageEncrypted || r.KMSKeyID != "" }),
		IAMAuthResourceCount:      countDynamoDBRDSRecordsWith(records, func(r AWSDynamoDBRDSReachabilityRecord) bool { return r.IAMDatabaseAuthenticationEnabled }),
		IdentityGrantCount:        countDynamoDBRDSGrants(records),
		DenyGrantCount:            countDynamoDBRDSGrantsWith(records, func(g AWSDynamoDBRDSIdentityGrant) bool { return strings.EqualFold(g.Effect, "Deny") }),
		AssociatedRoleCount:       countDynamoDBRDSAssociatedRoles(records),
		RelationshipCount:         len(relationships),
		FailureReasons:            failures,
		RemediationHints:          remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsDynamoDBRDSReachabilityCurrentIssue),
			"/docs/aws-dynamodb-rds-reachability",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  gaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsDynamoDBRDSReachabilityDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSDynamoDBRDSReachabilityFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsDynamoDBRDSReachabilityFixtureRecords(accountID, region, fixtureState string, checkedAt time.Time) ([]AWSDynamoDBRDSReachabilityRecord, []providers.SourceError, []AWSDynamoDBRDSCoverageGap) {
	partition := awsS3PartitionForRegion(region)
	tableARN := fmt.Sprintf("arn:%s:dynamodb:%s:%s:table/payments-ledger", partition, region, accountID)
	streamARN := tableARN + "/stream/2026-06-11T00:00:00.000"
	clusterARN := fmt.Sprintf("arn:%s:rds:%s:%s:cluster:payments-main", partition, region, accountID)
	instanceARN := fmt.Sprintf("arn:%s:rds:%s:%s:db:customer-export", partition, region, accountID)
	proxyARN := fmt.Sprintf("arn:%s:rds:%s:%s:db-proxy:prx-0123456789abcdef0", partition, region, accountID)
	gaps := []AWSDynamoDBRDSCoverageGap{{
		Capability:  "database_contents",
		Status:      "unsupported",
		Reason:      "This collector never reads DynamoDB items, SQL rows, queries, snapshots, backups, or database payloads.",
		Remediation: "Use service-native audit tooling for content investigations without widening Identrail collector permissions.",
	}, {
		Capability:  "network_path_proof",
		Status:      "partial",
		Reason:      "RDS public flags, IAM auth, endpoints, and proxy metadata are surfaced, but VPC route reachability is a downstream graph concern.",
		Remediation: "Join these records with network inventory once VPC path analysis is enabled.",
	}}
	records := []AWSDynamoDBRDSReachabilityRecord{
		awsDynamoDBRDSReachabilityFixtureRecord(accountID, region, "dynamodb", "dynamodb_table", "payments-ledger", tableARN, "cross_account", checkedAt, func(r *AWSDynamoDBRDSReachabilityRecord) {
			r.StorageEncrypted = true
			r.KMSKeyID = fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-ledger", partition, region, accountID)
			r.StreamEnabled = true
			r.StreamARN = streamARN
			r.BillingMode = "PAY_PER_REQUEST"
			r.HasResourcePolicy = true
			r.ResourcePolicySource = "table_resource_policy"
			r.ResourcePolicyStatementCount = 1
			r.IdentityGrants = []AWSDynamoDBRDSIdentityGrant{{
				PrincipalARN:   fmt.Sprintf("arn:%s:iam::999999999999:role/partner-ledger-reader", partition),
				PrincipalType:  "aws",
				Effect:         "Allow",
				Actions:        []string{"dynamodb:GetItem", "dynamodb:Query"},
				Capabilities:   []string{"read"},
				IsCrossAccount: true,
				StatementSid:   "PartnerRead",
			}}
		}),
		awsDynamoDBRDSReachabilityFixtureRecord(accountID, region, "dynamodb", "dynamodb_stream", "payments-ledger-stream", streamARN, "private_with_grants", checkedAt, func(r *AWSDynamoDBRDSReachabilityRecord) {
			r.ResourceStatus = "ENABLED"
			r.AssociatedRoleARNs = []string{fmt.Sprintf("arn:%s:iam::%s:role/payments-stream-consumer", partition, accountID)}
		}),
		awsDynamoDBRDSReachabilityFixtureRecord(accountID, region, "rds", "rds_cluster", "payments-main", clusterARN, "private_with_grants", checkedAt, func(r *AWSDynamoDBRDSReachabilityRecord) {
			r.Engine = "aurora-postgresql"
			r.EngineVersion = "15.4"
			r.StorageEncrypted = true
			r.IAMDatabaseAuthenticationEnabled = true
			r.DeletionProtectionEnabled = true
			r.KMSKeyID = fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-rds", partition, region, accountID)
			r.AssociatedRoleARNs = []string{fmt.Sprintf("arn:%s:iam::%s:role/rds-s3-import", partition, accountID)}
		}),
		awsDynamoDBRDSReachabilityFixtureRecord(accountID, region, "rds", "rds_instance", "customer-export", instanceARN, "public", checkedAt, func(r *AWSDynamoDBRDSReachabilityRecord) {
			r.Engine = "postgres"
			r.EngineVersion = "15.5"
			r.Endpoint = fmt.Sprintf("customer-export.%s%s", region, awsRDSEndpointSuffixForRegion(region))
			r.PubliclyAccessible = true
			r.StorageEncrypted = true
			r.PerformanceInsightsEnabled = true
		}),
		awsDynamoDBRDSReachabilityFixtureRecord(accountID, region, "rds", "rds_proxy", "payments-proxy", proxyARN, "private_with_grants", checkedAt, func(r *AWSDynamoDBRDSReachabilityRecord) {
			r.Engine = "POSTGRESQL"
			r.Endpoint = fmt.Sprintf("payments-proxy.proxy-%s%s", region, awsRDSEndpointSuffixForRegion(region))
			r.IAMDatabaseAuthenticationEnabled = true
			r.AssociatedRoleARNs = []string{fmt.Sprintf("arn:%s:iam::%s:role/rds-proxy-secrets", partition, accountID)}
		}),
	}
	switch fixtureState {
	case "empty":
		return nil, nil, gaps
	case "degraded":
		records[0].Status = "degraded"
		records[0].Confidence = 0.7
		return records, []providers.SourceError{{Collector: "aws_dynamodb_rds/dynamodb_rds_reachability", SourceID: tableARN, Code: "dynamodb_table_tags_failed", Message: "DynamoDB table tags could not be loaded; policy evidence remains visible", Retryable: true}}, gaps
	case "partial_failure":
		return records[:2], []providers.SourceError{{Collector: "aws_dynamodb_rds/dynamodb_rds_reachability", SourceID: fmt.Sprintf("service=rds|account=%s|region=%s", accountID, region), Code: "dynamodb_rds_reachability_page_failed", Message: "RDS listing failed after DynamoDB resources were collected", Retryable: true}}, gaps
	case "permission_denied":
		return nil, []providers.SourceError{{Collector: "aws_dynamodb_rds/dynamodb_rds_reachability", SourceID: fmt.Sprintf("service=dynamodb_rds|account=%s|region=%s", accountID, region), Code: "permission_denied", Message: "Read-only DynamoDB/RDS metadata permissions are missing"}}, gaps
	default:
		return records, nil, gaps
	}
}

func awsRDSEndpointSuffixForRegion(region string) string {
	normalized := strings.ToLower(strings.TrimSpace(region))
	switch {
	case strings.HasPrefix(normalized, "cn-"):
		return ".rds.amazonaws.com.cn"
	default:
		return ".rds.amazonaws.com"
	}
}

func awsDynamoDBRDSReachabilityFixtureRecord(accountID, region, service, resourceType, name, arn, exposure string, checkedAt time.Time, mutate func(*AWSDynamoDBRDSReachabilityRecord)) AWSDynamoDBRDSReachabilityRecord {
	record := AWSDynamoDBRDSReachabilityRecord{
		AccountID:              accountID,
		Region:                 region,
		Service:                service,
		ResourceARN:            arn,
		ResourceName:           name,
		ResourceType:           resourceType,
		ResourceID:             arn,
		ResourceStatus:         "available",
		ExposureClassification: exposure,
		Tags:                   map[string]string{"owner": "payments-platform"},
		Source:                 "dynamodb_rds_metadata",
		EvidenceRef:            arn,
		FromNodeID:             awsDynamoDBRDSResourceNodeID(resourceType, arn),
		RelationshipType:       "can_access",
		Confidence:             0.88,
		CollectedAt:            checkedAt,
		Status:                 "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	return record
}

func filterAWSDynamoDBRDSReachabilityRecords(records []AWSDynamoDBRDSReachabilityRecord, request AWSDynamoDBRDSReachabilityInventoryRequest) []AWSDynamoDBRDSReachabilityRecord {
	resourceType := strings.ToLower(strings.TrimSpace(request.ResourceType))
	identity := strings.ToLower(strings.TrimSpace(request.Identity))
	if resourceType == "" && identity == "" {
		return records
	}
	filtered := make([]AWSDynamoDBRDSReachabilityRecord, 0, len(records))
	for _, record := range records {
		if resourceType != "" && strings.ToLower(record.ResourceType) != resourceType && strings.ToLower(record.Service) != resourceType {
			continue
		}
		if identity != "" && !awsDynamoDBRDSRecordHasIdentity(record, identity) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func awsDynamoDBRDSRecordHasIdentity(record AWSDynamoDBRDSReachabilityRecord, needle string) bool {
	for _, roleARN := range record.AssociatedRoleARNs {
		if strings.Contains(strings.ToLower(roleARN), needle) {
			return true
		}
	}
	for _, grant := range record.IdentityGrants {
		haystack := strings.ToLower(strings.Join([]string{grant.PrincipalARN, grant.PrincipalType, strings.Join(grant.Actions, " "), strings.Join(grant.Capabilities, " ")}, " "))
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func awsDynamoDBRDSReachabilityRelationships(records []AWSDynamoDBRDSReachabilityRecord) []AWSDynamoDBRDSReachabilityRelationship {
	result := []AWSDynamoDBRDSReachabilityRelationship{}
	for _, record := range records {
		toNode := awsDynamoDBRDSResourceNodeID(record.ResourceType, record.ResourceARN)
		for _, roleARN := range record.AssociatedRoleARNs {
			if !isIAMPrincipalARNForSQSSNSEdge(roleARN) {
				continue
			}
			result = append(result, AWSDynamoDBRDSReachabilityRelationship{Type: "can_access", FromNodeID: awsIdentityNodeIDForAPI(roleARN), ToNodeID: toNode, EvidenceRef: record.EvidenceRef, Effect: "Allow", PrincipalType: "aws", Capabilities: []string{"service_association"}})
		}
		for _, grant := range record.IdentityGrants {
			if !strings.EqualFold(grant.Effect, "Allow") || grant.WildcardPrincipal || grant.PrincipalARN == "*" || !isIAMPrincipalARNForSQSSNSEdge(grant.PrincipalARN) {
				continue
			}
			result = append(result, AWSDynamoDBRDSReachabilityRelationship{Type: "can_access", FromNodeID: awsIdentityNodeIDForAPI(grant.PrincipalARN), ToNodeID: toNode, EvidenceRef: record.EvidenceRef, Effect: grant.Effect, PrincipalType: grant.PrincipalType, Capabilities: append([]string(nil), grant.Capabilities...), HasCondition: grant.HasCondition})
		}
	}
	return result
}

func summarizeAWSDynamoDBRDSReachabilityInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSDynamoDBRDSReachabilityRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"dynamodb and rds reachability collection is blocked by missing read-only metadata permissions"}, []string{"Grant DynamoDB table metadata/resource-policy reads and RDS describe/list-tags reads. Do not grant item, query, snapshot export, or database-content permissions."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72, []string{"one or more DynamoDB/RDS metadata sub-listings are incomplete"}, []string{"Retry the failed metadata call and preserve already-collected DynamoDB/RDS evidence."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78, []string{"one DynamoDB/RDS page failed while earlier resource evidence remains visible"}, []string{"Retry the failed list call without discarding successful resource evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82, []string{"dynamodb/rds reachability collection returned diagnostics"}, []string{"Review diagnostics before treating database reachability as complete."}
		}
		if len(records) == 0 {
			return awsPlatformDependencyStatusReady, 0.9, nil, nil
		}
		return awsPlatformDependencyStatusReady, 0.92, nil, nil
	}
}

func awsDynamoDBRDSReachabilityDiagnostics(diagnostics []providers.SourceError) []AWSDynamoDBRDSReachabilityDiagnostic {
	result := make([]AWSDynamoDBRDSReachabilityDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSDynamoDBRDSReachabilityDiagnostic{Collector: diagnostic.Collector, SourceID: diagnostic.SourceID, Code: diagnostic.Code, Message: diagnostic.Message, Remediation: awsDynamoDBRDSReachabilityDiagnosticRemediation(diagnostic.Code), Retryable: diagnostic.Retryable})
	}
	return result
}

func awsDynamoDBRDSReachabilityDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only DynamoDB and RDS read permissions; do not grant table item, query, snapshot, export, or database-content actions."
	case "dynamodb_rds_reachability_page_failed", "dynamodb_table_tags_failed":
		return "Retry only the failed metadata call and keep retained database evidence visible."
	default:
		return "Review the DynamoDB/RDS collector diagnostic and retry after correcting scoped metadata permissions."
	}
}

func countDynamoDBRDSResources(records []AWSDynamoDBRDSReachabilityRecord, resourceType string) int {
	count := 0
	for _, record := range records {
		if record.ResourceType == resourceType {
			count++
		}
	}
	return count
}

func countDynamoDBRDSByExposure(records []AWSDynamoDBRDSReachabilityRecord, exposure string) int {
	return countDynamoDBRDSRecordsWith(records, func(r AWSDynamoDBRDSReachabilityRecord) bool { return r.ExposureClassification == exposure })
}

func countDynamoDBRDSRecordsWith(records []AWSDynamoDBRDSReachabilityRecord, pred func(AWSDynamoDBRDSReachabilityRecord) bool) int {
	count := 0
	for _, record := range records {
		if pred(record) {
			count++
		}
	}
	return count
}

func countDynamoDBRDSGrants(records []AWSDynamoDBRDSReachabilityRecord) int {
	count := 0
	for _, record := range records {
		count += len(record.IdentityGrants)
	}
	return count
}

func countDynamoDBRDSGrantsWith(records []AWSDynamoDBRDSReachabilityRecord, pred func(AWSDynamoDBRDSIdentityGrant) bool) int {
	count := 0
	for _, record := range records {
		for _, grant := range record.IdentityGrants {
			if pred(grant) {
				count++
			}
		}
	}
	return count
}

func countDynamoDBRDSAssociatedRoles(records []AWSDynamoDBRDSReachabilityRecord) int {
	count := 0
	for _, record := range records {
		count += len(record.AssociatedRoleARNs)
	}
	return count
}

func validateAWSDynamoDBRDSReachabilityRecord(scope db.Scope, project db.TenancyProject, connectorID string, record AWSDynamoDBRDSReachabilityRecord) error {
	required := []struct {
		name  string
		value string
	}{
		{"tenant_id", scope.TenantID},
		{"workspace_id", project.WorkspaceID},
		{"project_id", project.ProjectID},
		{"connector_id", connectorID},
		{"account_id", record.AccountID},
		{"region", record.Region},
		{"service", record.Service},
		{"resource_arn", record.ResourceARN},
		{"resource_name", record.ResourceName},
		{"resource_type", record.ResourceType},
		{"source", record.Source},
		{"evidence_ref", record.EvidenceRef},
		{"exposure_classification", record.ExposureClassification},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	if record.Confidence <= 0 || record.Confidence > 1 {
		return fmt.Errorf("confidence must be greater than 0 and at most 1")
	}
	if record.CollectedAt.IsZero() {
		return fmt.Errorf("collected_at is required")
	}
	return nil
}

func awsDynamoDBRDSResourceNodeID(resourceType string, arn string) string {
	switch strings.ToLower(strings.TrimSpace(resourceType)) {
	case "dynamodb_table":
		return "aws:resource:dynamodb-table:" + strings.TrimSpace(arn)
	case "dynamodb_stream":
		return "aws:resource:dynamodb-stream:" + strings.TrimSpace(arn)
	case "rds_instance":
		return "aws:resource:rds-instance:" + strings.TrimSpace(arn)
	case "rds_cluster":
		return "aws:resource:rds-cluster:" + strings.TrimSpace(arn)
	case "rds_proxy":
		return "aws:resource:rds-proxy:" + strings.TrimSpace(arn)
	default:
		return "aws:resource:dynamodb-rds:" + strings.TrimSpace(arn)
	}
}
