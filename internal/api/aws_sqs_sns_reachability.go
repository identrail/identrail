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
	awsSQSSNSReachabilityCurrentIssue = 1493
	awsSQSSNSReachabilityVersion      = "aws-sqs-sns-reachability-inventory-v1"
)

// AWSSQSSNSReachabilityInventoryRequest is the operator-facing request.
type AWSSQSSNSReachabilityInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Identity     string `json:"identity,omitempty"`
}

// AWSSQSSNSCoverageGap documents intentionally unresolved reachability scope.
type AWSSQSSNSCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSSQSSNSReachabilityInventoryResult is the deterministic endpoint envelope.
type AWSSQSSNSReachabilityInventoryResult struct {
	TenantID                  string                              `json:"tenant_id"`
	WorkspaceID               string                              `json:"workspace_id"`
	ProjectID                 string                              `json:"project_id"`
	ConnectorID               string                              `json:"connector_id,omitempty"`
	AccountID                 string                              `json:"account_id,omitempty"`
	Region                    string                              `json:"region,omitempty"`
	ParentIssueNumber         int                                 `json:"parent_issue_number"`
	ParentIssueRef            string                              `json:"parent_issue_ref"`
	CurrentIssueNumber        int                                 `json:"current_issue_number"`
	CurrentIssueRef           string                              `json:"current_issue_ref"`
	Version                   string                              `json:"version"`
	Status                    string                              `json:"status"`
	FixtureState              string                              `json:"fixture_state"`
	Confidence                float64                             `json:"confidence"`
	ResourceCount             int                                 `json:"resource_count"`
	QueueCount                int                                 `json:"queue_count"`
	TopicCount                int                                 `json:"topic_count"`
	PublicResourceCount       int                                 `json:"public_resource_count"`
	CrossAccountResourceCount int                                 `json:"cross_account_resource_count"`
	RestrictedResourceCount   int                                 `json:"restricted_resource_count"`
	EncryptedResourceCount    int                                 `json:"encrypted_resource_count"`
	DLQResourceCount          int                                 `json:"dlq_resource_count"`
	SubscriptionCount         int                                 `json:"subscription_count"`
	IdentityGrantCount        int                                 `json:"identity_grant_count"`
	PublicGrantCount          int                                 `json:"public_grant_count"`
	CrossAccountGrantCount    int                                 `json:"cross_account_grant_count"`
	DenyGrantCount            int                                 `json:"deny_grant_count"`
	RelationshipCount         int                                 `json:"relationship_count"`
	FailureReasons            []string                            `json:"failure_reasons"`
	RemediationHints          []string                            `json:"remediation_hints"`
	EvidenceLinks             []string                            `json:"evidence_links"`
	CoverageGaps              []AWSSQSSNSCoverageGap              `json:"coverage_gaps"`
	Records                   []AWSSQSSNSReachabilityRecord       `json:"records"`
	Relationships             []AWSSQSSNSReachabilityRelationship `json:"relationships"`
	Diagnostics               []AWSSQSSNSReachabilityDiagnostic   `json:"diagnostics"`
	GeneratedAt               time.Time                           `json:"generated_at"`
	UpdatedAt                 time.Time                           `json:"updated_at"`
}

// AWSSQSSNSReachabilityRecord is one queue or topic metadata record.
type AWSSQSSNSReachabilityRecord struct {
	AccountID                    string                    `json:"account_id"`
	Region                       string                    `json:"region"`
	Service                      string                    `json:"service"`
	ResourceARN                  string                    `json:"resource_arn"`
	ResourceName                 string                    `json:"resource_name"`
	ResourceType                 string                    `json:"resource_type"`
	ResourceURL                  string                    `json:"resource_url,omitempty"`
	QueueURL                     string                    `json:"queue_url,omitempty"`
	TopicARN                     string                    `json:"topic_arn,omitempty"`
	OwnerAccountID               string                    `json:"owner_account_id,omitempty"`
	CreatedAt                    string                    `json:"created_at,omitempty"`
	LastModifiedAt               string                    `json:"last_modified_at,omitempty"`
	Fifo                         bool                      `json:"fifo"`
	ContentBasedDeduplication    bool                      `json:"content_based_deduplication"`
	SQSManagedSSE                bool                      `json:"sqs_managed_sse"`
	KMSKeyID                     string                    `json:"kms_key_id,omitempty"`
	VisibilityTimeoutSeconds     int                       `json:"visibility_timeout_seconds,omitempty"`
	MessageRetentionSeconds      int                       `json:"message_retention_seconds,omitempty"`
	DLQARNs                      []string                  `json:"dlq_arns,omitempty"`
	SubscriptionCount            int                       `json:"subscription_count,omitempty"`
	Subscriptions                []AWSSNSTopicSubscription `json:"subscriptions,omitempty"`
	HasResourcePolicy            bool                      `json:"has_resource_policy"`
	ResourcePolicyStatementCount int                       `json:"resource_policy_statement_count"`
	ResourcePolicySource         string                    `json:"resource_policy_source,omitempty"`
	IdentityGrants               []AWSSQSSNSIdentityGrant  `json:"identity_grants,omitempty"`
	ExposureClassification       string                    `json:"exposure_classification"`
	ExposureReasons              []string                  `json:"exposure_reasons,omitempty"`
	Tags                         map[string]string         `json:"tags,omitempty"`
	Source                       string                    `json:"source"`
	EvidenceRef                  string                    `json:"evidence_ref"`
	FromNodeID                   string                    `json:"from_node_id"`
	RelationshipType             string                    `json:"relationship_type"`
	Confidence                   float64                   `json:"confidence"`
	CollectedAt                  time.Time                 `json:"collected_at"`
	Status                       string                    `json:"status"`
}

// AWSSQSSNSIdentityGrant mirrors resource-policy grants.
type AWSSQSSNSIdentityGrant struct {
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

// AWSSNSTopicSubscription is endpoint-redacted SNS subscription metadata.
type AWSSNSTopicSubscription struct {
	SubscriptionARN     string `json:"subscription_arn,omitempty"`
	Protocol            string `json:"protocol,omitempty"`
	OwnerAccountID      string `json:"owner_account_id,omitempty"`
	EndpointResourceARN string `json:"endpoint_resource_arn,omitempty"`
	EndpointPresent     bool   `json:"endpoint_present,omitempty"`
	EndpointRedacted    bool   `json:"endpoint_redacted,omitempty"`
	PendingConfirmation bool   `json:"pending_confirmation,omitempty"`
	RawMessageDelivery  bool   `json:"raw_message_delivery,omitempty"`
	FilterPolicyPresent bool   `json:"filter_policy_present,omitempty"`
	DLQARN              string `json:"dlq_arn,omitempty"`
}

// AWSSQSSNSReachabilityRelationship is a graph-safe IAM principal edge.
type AWSSQSSNSReachabilityRelationship struct {
	Type          string   `json:"type"`
	FromNodeID    string   `json:"from_node_id"`
	ToNodeID      string   `json:"to_node_id"`
	EvidenceRef   string   `json:"evidence_ref"`
	Effect        string   `json:"effect"`
	PrincipalType string   `json:"principal_type"`
	Capabilities  []string `json:"capabilities,omitempty"`
	HasCondition  bool     `json:"has_condition,omitempty"`
}

// AWSSQSSNSReachabilityDiagnostic is a structured collector diagnostic.
type AWSSQSSNSReachabilityDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSSQSSNSReachabilityInventory returns queue/topic reachability evidence.
func (s *Service) GetAWSSQSSNSReachabilityInventory(ctx context.Context, workspaceID string, projectID string, request AWSSQSSNSReachabilityInventoryRequest) (AWSSQSSNSReachabilityInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSSQSSNSReachabilityInventoryResult{}, err
	}
	var (
		connection    AWSConnectionStatus
		hasConnection bool
	)
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSSQSSNSReachabilityInventoryResult{}, err
	}
	return buildAWSSQSSNSReachabilityInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSSQSSNSReachabilityInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSSQSSNSReachabilityInventoryRequest, checkedAt time.Time) (AWSSQSSNSReachabilityInventoryResult, error) {
	fixtureState := normalizeAWSSQSSNSReachabilityFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSSQSSNSReachabilityInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsSQSSNSReachabilityFixtureRecords(accountID, region, fixtureState, checkedAt)
	records = filterAWSSQSSNSReachabilityRecords(records, request)
	for _, record := range records {
		if err := validateSQSSNSReachabilityRecord(scope, project, connectorID, record); err != nil {
			return AWSSQSSNSReachabilityInventoryResult{}, fmt.Errorf("validate sqs/sns reachability record: %w", err)
		}
	}
	status, confidence, failures, remediations := summarizeAWSSQSSNSReachabilityInventory(fixtureState, diagnostics, records)
	relationships := awsSQSSNSReachabilityRelationships(records)
	return AWSSQSSNSReachabilityInventoryResult{
		TenantID:                  scope.TenantID,
		WorkspaceID:               project.WorkspaceID,
		ProjectID:                 project.ProjectID,
		ConnectorID:               connectorID,
		AccountID:                 accountID,
		Region:                    region,
		ParentIssueNumber:         awsPlatformDependencyParentIssue,
		ParentIssueRef:            awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:        awsSQSSNSReachabilityCurrentIssue,
		CurrentIssueRef:           awsIssueRef(awsSQSSNSReachabilityCurrentIssue),
		Version:                   awsSQSSNSReachabilityVersion,
		Status:                    status,
		FixtureState:              fixtureState,
		Confidence:                confidence,
		ResourceCount:             len(records),
		QueueCount:                countSQSSNSResources(records, "sqs_queue"),
		TopicCount:                countSQSSNSResources(records, "sns_topic"),
		PublicResourceCount:       countSQSSNSByExposure(records, "public"),
		CrossAccountResourceCount: countSQSSNSByExposure(records, "cross_account"),
		RestrictedResourceCount:   countSQSSNSByExposure(records, "restricted"),
		EncryptedResourceCount: countSQSSNSRecordsWith(records, func(r AWSSQSSNSReachabilityRecord) bool {
			return strings.TrimSpace(r.KMSKeyID) != "" || r.SQSManagedSSE
		}),
		DLQResourceCount:       countSQSSNSRecordsWith(records, func(r AWSSQSSNSReachabilityRecord) bool { return len(r.DLQARNs) > 0 }),
		SubscriptionCount:      countSQSSNSSubscriptions(records),
		IdentityGrantCount:     countSQSSNSGrants(records, func(g AWSSQSSNSIdentityGrant) bool { return true }),
		PublicGrantCount:       countSQSSNSGrants(records, func(g AWSSQSSNSIdentityGrant) bool { return g.IsPublic }),
		CrossAccountGrantCount: countSQSSNSGrants(records, func(g AWSSQSSNSIdentityGrant) bool { return g.IsCrossAccount }),
		DenyGrantCount:         countSQSSNSGrants(records, func(g AWSSQSSNSIdentityGrant) bool { return strings.EqualFold(g.Effect, "Deny") }),
		RelationshipCount:      len(relationships),
		FailureReasons:         failures,
		RemediationHints:       remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsSQSSNSReachabilityCurrentIssue),
			"/docs/aws-sqs-sns-reachability",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsSQSSNSReachabilityDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSSQSSNSReachabilityFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsSQSSNSReachabilityFixtureRecords(accountID, region, fixtureState string, checkedAt time.Time) ([]AWSSQSSNSReachabilityRecord, []providers.SourceError, []AWSSQSSNSCoverageGap) {
	gaps := []AWSSQSSNSCoverageGap{{
		Capability:  "identity_policy_expansion",
		Status:      "unsupported",
		Reason:      "This wave maps resource-policy reachability only. Identity policies that can publish, consume, or subscribe are handled by the IAM permission graph.",
		Remediation: "Use the IAM policy graph with these resource nodes until service-action expansion is added.",
	}, {
		Capability:  "message_payload_inspection",
		Status:      "unsupported",
		Reason:      "Queue messages, topic notifications, and subscription delivery payloads are intentionally out of scope.",
		Remediation: "Use CloudTrail or service-native audit logs for runtime payload investigations without widening collector permissions.",
	}, {
		Capability:  "non_aws_subscription_endpoints",
		Status:      "unsupported",
		Reason:      "Email, SMS, mobile push, HTTPS, and firehose endpoints are reported as present/redacted instead of stored as raw endpoint values.",
		Remediation: "Inspect non-AWS endpoints in AWS directly when an exposure review requires the exact address.",
	}}
	partition := awsS3PartitionForRegion(region)
	publicTopicARN := fmt.Sprintf("arn:%s:sns:%s:%s:billing-events", partition, region, accountID)
	crossAccountQueueARN := fmt.Sprintf("arn:%s:sqs:%s:%s:partner-ingest", partition, region, accountID)
	internalQueueARN := fmt.Sprintf("arn:%s:sqs:%s:%s:payments-worker", partition, region, accountID)
	restrictedTopicARN := fmt.Sprintf("arn:%s:sns:%s:%s:security-alerts.fifo", partition, region, accountID)
	queueURLSuffix := "amazonaws.com"
	if partition == "aws-cn" {
		queueURLSuffix = "amazonaws.com.cn"
	}
	records := []AWSSQSSNSReachabilityRecord{
		awsSQSSNSReachabilityFixtureRecord(accountID, region, "sns", "sns_topic", "billing-events", publicTopicARN, "public", checkedAt, func(r *AWSSQSSNSReachabilityRecord) {
			r.TopicARN = publicTopicARN
			r.HasResourcePolicy = true
			r.ResourcePolicySource = "topic_policy"
			r.ResourcePolicyStatementCount = 1
			r.IdentityGrants = []AWSSQSSNSIdentityGrant{{
				PrincipalARN:      "*",
				PrincipalType:     "*",
				Effect:            "Allow",
				Actions:           []string{"sns:Publish"},
				Capabilities:      []string{"publish"},
				IsPublic:          true,
				WildcardPrincipal: true,
				StatementSid:      "PublicPublish",
			}}
			r.SubscriptionCount = 2
			r.Subscriptions = []AWSSNSTopicSubscription{{
				SubscriptionARN:     fmt.Sprintf("%s:sub-a", publicTopicARN),
				Protocol:            "sqs",
				OwnerAccountID:      accountID,
				EndpointResourceARN: internalQueueARN,
				EndpointPresent:     true,
			}, {
				SubscriptionARN:  fmt.Sprintf("%s:sub-b", publicTopicARN),
				Protocol:         "https",
				OwnerAccountID:   accountID,
				EndpointPresent:  true,
				EndpointRedacted: true,
			}}
			r.ExposureReasons = []string{"sns_policy_allow_to_wildcard_principal"}
		}),
		awsSQSSNSReachabilityFixtureRecord(accountID, region, "sqs", "sqs_queue", "partner-ingest", crossAccountQueueARN, "cross_account", checkedAt, func(r *AWSSQSSNSReachabilityRecord) {
			r.QueueURL = fmt.Sprintf("https://sqs.%s.%s/%s/partner-ingest", region, queueURLSuffix, accountID)
			r.ResourceURL = r.QueueURL
			r.KMSKeyID = fmt.Sprintf("arn:%s:kms:%s:%s:key/partner-ingest", partition, region, accountID)
			r.DLQARNs = []string{fmt.Sprintf("arn:%s:sqs:%s:%s:partner-ingest-dlq", partition, region, accountID)}
			r.HasResourcePolicy = true
			r.ResourcePolicySource = "queue_policy"
			r.ResourcePolicyStatementCount = 1
			r.VisibilityTimeoutSeconds = 30
			r.MessageRetentionSeconds = 345600
			r.IdentityGrants = []AWSSQSSNSIdentityGrant{{
				PrincipalARN:   fmt.Sprintf("arn:%s:iam::999999999999:role/partner-publisher", partition),
				PrincipalType:  "aws",
				Effect:         "Allow",
				Actions:        []string{"sqs:SendMessage"},
				Capabilities:   []string{"publish"},
				IsCrossAccount: true,
				StatementSid:   "PartnerSend",
			}}
			r.ExposureReasons = []string{"sqs_policy_allow_to_cross_account_principal", "sqs_encryption_key_configured", "sqs_dead_letter_queue_configured"}
		}),
		awsSQSSNSReachabilityFixtureRecord(accountID, region, "sqs", "sqs_queue", "payments-worker", internalQueueARN, "private_with_grants", checkedAt, func(r *AWSSQSSNSReachabilityRecord) {
			r.QueueURL = fmt.Sprintf("https://sqs.%s.%s/%s/payments-worker", region, queueURLSuffix, accountID)
			r.ResourceURL = r.QueueURL
			r.SQSManagedSSE = true
			r.VisibilityTimeoutSeconds = 45
			r.MessageRetentionSeconds = 1209600
			r.HasResourcePolicy = true
			r.ResourcePolicySource = "queue_policy"
			r.ResourcePolicyStatementCount = 1
			r.IdentityGrants = []AWSSQSSNSIdentityGrant{{
				PrincipalARN:  fmt.Sprintf("arn:%s:iam::%s:role/payments-app", partition, accountID),
				PrincipalType: "aws",
				Effect:        "Allow",
				Actions:       []string{"sqs:ReceiveMessage", "sqs:DeleteMessage"},
				Capabilities:  []string{"consume"},
				StatementSid:  "WorkerConsume",
			}}
			r.ExposureReasons = []string{"sqs_encryption_key_configured"}
		}),
		awsSQSSNSReachabilityFixtureRecord(accountID, region, "sns", "sns_topic", "security-alerts.fifo", restrictedTopicARN, "restricted", checkedAt, func(r *AWSSQSSNSReachabilityRecord) {
			r.TopicARN = restrictedTopicARN
			r.Fifo = true
			r.ContentBasedDeduplication = true
			r.KMSKeyID = fmt.Sprintf("arn:%s:kms:%s:%s:key/security-alerts", partition, region, accountID)
			r.HasResourcePolicy = true
			r.ResourcePolicySource = "topic_policy"
			r.ResourcePolicyStatementCount = 1
			r.IdentityGrants = []AWSSQSSNSIdentityGrant{{
				PrincipalARN:      "*",
				PrincipalType:     "*",
				Effect:            "Deny",
				Actions:           []string{"sns:*"},
				Capabilities:      []string{"publish", "subscribe", "manage"},
				WildcardPrincipal: true,
				StatementSid:      "DenyAllByDefault",
			}}
			r.ExposureReasons = []string{"sns_policy_explicit_deny_to_all", "sns_encryption_key_configured"}
		}),
	}
	switch fixtureState {
	case "empty":
		return nil, nil, gaps
	case "degraded":
		for i := range records {
			if records[i].ResourceName == "billing-events" {
				records[i].Status = "degraded"
				records[i].Confidence = 0.7
				records[i].Subscriptions = records[i].Subscriptions[:1]
				records[i].ExposureReasons = append(records[i].ExposureReasons, "sns_subscription_listing_incomplete")
				break
			}
		}
		return records, []providers.SourceError{{
			Collector: "aws_sqs_sns/sqs_sns_reachability",
			SourceID:  publicTopicARN,
			Code:      "sns_topic_subscriptions_failed",
			Message:   "One SNS topic subscription page failed; topic policy evidence remains visible",
			Retryable: true,
		}}, gaps
	case "partial_failure":
		return records[:3], []providers.SourceError{{
			Collector: "aws_sqs_sns/sqs_sns_reachability",
			SourceID:  fmt.Sprintf("service=sns|account=%s|region=%s|source=listtopics", accountID, region),
			Code:      "sqs_sns_reachability_page_failed",
			Message:   "SNS topic listing was throttled after SQS queues were collected",
			Retryable: true,
		}}, gaps
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_sqs_sns/sqs_sns_reachability",
			SourceID:  fmt.Sprintf("service=sqs_sns|account=%s|region=%s", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only SQS/SNS metadata permissions are missing",
			Retryable: false,
		}}, gaps
	default:
		return records, nil, gaps
	}
}

func awsSQSSNSReachabilityFixtureRecord(accountID, region, service, resourceType, name, arn, exposure string, checkedAt time.Time, mutate func(*AWSSQSSNSReachabilityRecord)) AWSSQSSNSReachabilityRecord {
	confidence := 0.88
	switch exposure {
	case "public":
		confidence = 0.94
	case "cross_account":
		confidence = 0.91
	case "restricted":
		confidence = 0.9
	case "private_with_grants":
		confidence = 0.87
	}
	record := AWSSQSSNSReachabilityRecord{
		AccountID:              accountID,
		Region:                 region,
		Service:                service,
		ResourceARN:            arn,
		ResourceName:           name,
		ResourceType:           resourceType,
		OwnerAccountID:         accountID,
		ExposureClassification: exposure,
		Tags:                   map[string]string{"owner": "payments-platform"},
		Source:                 "sqs_sns_metadata",
		EvidenceRef:            arn,
		FromNodeID:             awsSQSSNSResourceNodeID(resourceType, arn),
		RelationshipType:       "can_access",
		Confidence:             confidence,
		CollectedAt:            checkedAt,
		Status:                 "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	return record
}

func filterAWSSQSSNSReachabilityRecords(records []AWSSQSSNSReachabilityRecord, request AWSSQSSNSReachabilityInventoryRequest) []AWSSQSSNSReachabilityRecord {
	resourceType := strings.ToLower(strings.TrimSpace(request.ResourceType))
	identity := strings.ToLower(strings.TrimSpace(request.Identity))
	if resourceType == "" && identity == "" {
		return records
	}
	filtered := make([]AWSSQSSNSReachabilityRecord, 0, len(records))
	for _, record := range records {
		if resourceType != "" && strings.ToLower(strings.TrimSpace(record.ResourceType)) != resourceType && strings.ToLower(strings.TrimSpace(record.Service)) != resourceType {
			continue
		}
		if identity != "" && !awsSQSSNSRecordHasIdentity(record, identity) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func awsSQSSNSRecordHasIdentity(record AWSSQSSNSReachabilityRecord, needle string) bool {
	for _, grant := range record.IdentityGrants {
		haystack := strings.ToLower(strings.Join([]string{grant.PrincipalARN, grant.PrincipalType, strings.Join(grant.Actions, " "), strings.Join(grant.Capabilities, " ")}, " "))
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func awsSQSSNSReachabilityRelationships(records []AWSSQSSNSReachabilityRecord) []AWSSQSSNSReachabilityRelationship {
	result := []AWSSQSSNSReachabilityRelationship{}
	for _, record := range records {
		toNode := awsSQSSNSResourceNodeID(record.ResourceType, record.ResourceARN)
		for _, grant := range record.IdentityGrants {
			if !strings.EqualFold(grant.Effect, "Allow") {
				continue
			}
			if grant.WildcardPrincipal || grant.PrincipalARN == "*" || grant.PrincipalARN == "" {
				continue
			}
			if !isIAMPrincipalARNForSQSSNSEdge(grant.PrincipalARN) {
				continue
			}
			result = append(result, AWSSQSSNSReachabilityRelationship{
				Type:          "can_access",
				FromNodeID:    awsIdentityNodeIDForAPI(grant.PrincipalARN),
				ToNodeID:      toNode,
				EvidenceRef:   record.EvidenceRef,
				Effect:        grant.Effect,
				PrincipalType: grant.PrincipalType,
				Capabilities:  append([]string(nil), grant.Capabilities...),
				HasCondition:  grant.HasCondition,
			})
		}
	}
	return result
}

func summarizeAWSSQSSNSReachabilityInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSSQSSNSReachabilityRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35,
			[]string{"sqs and sns reachability collection is blocked by missing read-only metadata permissions"},
			[]string{"Grant sqs:ListQueues, sqs:GetQueueAttributes, sqs:ListQueueTags, sns:ListTopics, sns:GetTopicAttributes, sns:ListSubscriptionsByTopic, sns:GetSubscriptionAttributes, and sns:ListTagsForResource. Do not grant message-body or publish permissions."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72,
			[]string{"one or more SQS/SNS metadata sub-listings are incomplete"},
			[]string{"Retry the failed SQS/SNS metadata call and preserve already-collected queue/topic evidence."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78,
			[]string{"one SQS/SNS page failed while earlier resource evidence remains visible"},
			[]string{"Retry the failed list call without discarding successful queue/topic evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82,
				[]string{"sqs/sns reachability collection returned diagnostics"},
				[]string{"Review diagnostics before treating queue/topic reachability as complete."}
		}
		if len(records) == 0 {
			return awsPlatformDependencyStatusReady, 0.9, nil, nil
		}
		return awsPlatformDependencyStatusReady, 0.92, nil, nil
	}
}

func awsSQSSNSReachabilityDiagnostics(diagnostics []providers.SourceError) []AWSSQSSNSReachabilityDiagnostic {
	result := make([]AWSSQSSNSReachabilityDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSSQSSNSReachabilityDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsSQSSNSReachabilityDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsSQSSNSReachabilityDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant the read-only SQS/SNS metadata actions listed in the docs; do not enable SendMessage, ReceiveMessage, DeleteMessage, Publish, or Subscribe."
	case "sqs_queue_policy_parse_failed", "sns_topic_policy_parse_failed":
		return "Audit the resource policy JSON; the collector skips unparseable policy statements rather than guessing."
	case "sqs_queue_attributes_failed", "sqs_queue_tags_failed", "sns_topic_attributes_failed", "sns_topic_subscriptions_failed", "sns_subscription_attributes_failed", "sns_topic_tags_failed", "sqs_sns_reachability_page_failed":
		return "Retry only the failed metadata call and keep previously-collected queue/topic evidence visible."
	case "sqs_sns_reachability_page_limit_exceeded", "sns_topic_subscriptions_page_limit_exceeded":
		return "Increase the page cap or scope the connector before retrying."
	case "malformed_sqs_sns_reachability_record":
		return "Confirm ListQueues/ListTopics returned a resource ARN or name; ambiguous records are skipped."
	default:
		return "Review the SQS/SNS collector diagnostic and retry after correcting the scoped metadata permission issue."
	}
}

func countSQSSNSResources(records []AWSSQSSNSReachabilityRecord, resourceType string) int {
	count := 0
	for _, record := range records {
		if record.ResourceType == resourceType {
			count++
		}
	}
	return count
}

func countSQSSNSByExposure(records []AWSSQSSNSReachabilityRecord, exposure string) int {
	count := 0
	for _, record := range records {
		if record.ExposureClassification == exposure {
			count++
		}
	}
	return count
}

func countSQSSNSRecordsWith(records []AWSSQSSNSReachabilityRecord, pred func(AWSSQSSNSReachabilityRecord) bool) int {
	count := 0
	for _, record := range records {
		if pred(record) {
			count++
		}
	}
	return count
}

func countSQSSNSSubscriptions(records []AWSSQSSNSReachabilityRecord) int {
	count := 0
	for _, record := range records {
		if record.SubscriptionCount > 0 {
			count += record.SubscriptionCount
			continue
		}
		count += len(record.Subscriptions)
	}
	return count
}

func countSQSSNSGrants(records []AWSSQSSNSReachabilityRecord, pred func(AWSSQSSNSIdentityGrant) bool) int {
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

func validateSQSSNSReachabilityRecord(scope db.Scope, project db.TenancyProject, connectorID string, record AWSSQSSNSReachabilityRecord) error {
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

func awsSQSSNSResourceNodeID(resourceType string, arn string) string {
	switch resourceType {
	case "sqs_queue":
		return "aws:resource:sqs-queue:" + strings.TrimSpace(arn)
	case "sns_topic":
		return "aws:resource:sns-topic:" + strings.TrimSpace(arn)
	default:
		return "aws:resource:sqs-sns:" + strings.TrimSpace(arn)
	}
}

func isIAMPrincipalARNForSQSSNSEdge(principal string) bool {
	return isIAMPrincipalARNForS3Edge(principal)
}
