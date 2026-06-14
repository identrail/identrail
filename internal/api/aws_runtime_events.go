package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	awsRuntimeEventsCurrentIssue = 1513
	awsRuntimeEventsVersion      = "aws-runtime-events-contract-v1"
)

type AWSRuntimeEventRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	EventType    string `json:"event_type,omitempty"`
	Identity     string `json:"identity,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	Resource     string `json:"resource,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Owner        string `json:"owner,omitempty"`
	Status       string `json:"status,omitempty"`
}

type AWSRuntimeEventSession struct {
	SessionID        string    `json:"session_id"`
	PrincipalARN     string    `json:"principal_arn"`
	PrincipalType    string    `json:"principal_type"`
	AssumedRoleARN   string    `json:"assumed_role_arn,omitempty"`
	SessionIssuerARN string    `json:"session_issuer_arn,omitempty"`
	SourceIPAddress  string    `json:"source_ip_address,omitempty"`
	UserAgent        string    `json:"user_agent,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type AWSRuntimeEventRecord struct {
	EventID             string                 `json:"event_id"`
	AccountID           string                 `json:"account_id"`
	Region              string                 `json:"region"`
	EventType           string                 `json:"event_type"`
	EventSource         string                 `json:"event_source"`
	EventName           string                 `json:"event_name"`
	Action              string                 `json:"action"`
	ActorPrincipalARN   string                 `json:"actor_principal_arn"`
	ActorPrincipalType  string                 `json:"actor_principal_type"`
	ActorIdentityNodeID string                 `json:"actor_identity_node_id"`
	Session             AWSRuntimeEventSession `json:"session"`
	TargetResourceARN   string                 `json:"target_resource_arn,omitempty"`
	TargetResourceType  string                 `json:"target_resource_type,omitempty"`
	TargetResourceName  string                 `json:"target_resource_name,omitempty"`
	ResourceNodeID      string                 `json:"resource_node_id,omitempty"`
	AgentID             string                 `json:"agent_id,omitempty"`
	AgentNodeID         string                 `json:"agent_node_id,omitempty"`
	ToolName            string                 `json:"tool_name,omitempty"`
	ToolTargetRef       string                 `json:"tool_target_ref,omitempty"`
	Owner               string                 `json:"owner"`
	EvidenceCategory    string                 `json:"evidence_category"`
	EvidenceRef         string                 `json:"evidence_ref"`
	Confidence          float64                `json:"confidence"`
	ObservedAt          time.Time              `json:"observed_at"`
	CollectedAt         time.Time              `json:"collected_at"`
	Status              string                 `json:"status"`
	NextAction          string                 `json:"next_action"`
	RedactionBoundary   string                 `json:"redaction_boundary"`
}

type AWSRuntimeEventRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

type AWSRuntimeEventDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

type AWSRuntimeEventCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSRuntimeEventSummary struct {
	TotalEvents            int            `json:"total_events"`
	FilteredEvents         int            `json:"filtered_events"`
	EventTypeCounts        map[string]int `json:"event_type_counts"`
	StatusCounts           map[string]int `json:"status_counts"`
	OwnerCounts            map[string]int `json:"owner_counts"`
	AccountCount           int            `json:"account_count"`
	RegionCount            int            `json:"region_count"`
	IdentityCount          int            `json:"identity_count"`
	ResourceCount          int            `json:"resource_count"`
	AgentEventCount        int            `json:"agent_event_count"`
	SecretReadCount        int            `json:"secret_read_count"`
	KMSDecryptCount        int            `json:"kms_decrypt_count"`
	APICallCount           int            `json:"api_call_count"`
	STSSessionCount        int            `json:"sts_session_count"`
	RelationshipCount      int            `json:"relationship_count"`
	PermissionDeniedEvents int            `json:"permission_denied_events"`
}

type AWSRuntimeEventResult struct {
	TenantID           string                        `json:"tenant_id"`
	WorkspaceID        string                        `json:"workspace_id"`
	ProjectID          string                        `json:"project_id"`
	ConnectorID        string                        `json:"connector_id,omitempty"`
	AccountID          string                        `json:"account_id,omitempty"`
	Region             string                        `json:"region,omitempty"`
	ParentIssueNumber  int                           `json:"parent_issue_number"`
	ParentIssueRef     string                        `json:"parent_issue_ref"`
	CurrentIssueNumber int                           `json:"current_issue_number"`
	CurrentIssueRef    string                        `json:"current_issue_ref"`
	Version            string                        `json:"version"`
	Status             string                        `json:"status"`
	FixtureState       string                        `json:"fixture_state"`
	Confidence         float64                       `json:"confidence"`
	AppliedFilters     map[string]string             `json:"applied_filters"`
	Summary            AWSRuntimeEventSummary        `json:"summary"`
	Records            []AWSRuntimeEventRecord       `json:"records"`
	Relationships      []AWSRuntimeEventRelationship `json:"relationships"`
	FailureReasons     []string                      `json:"failure_reasons"`
	RemediationHints   []string                      `json:"remediation_hints"`
	EvidenceLinks      []string                      `json:"evidence_links"`
	CoverageGaps       []AWSRuntimeEventCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSRuntimeEventDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                     `json:"generated_at"`
	UpdatedAt          time.Time                     `json:"updated_at"`
}

func (s *Service) GetAWSRuntimeEvents(ctx context.Context, workspaceID string, projectID string, request AWSRuntimeEventRequest) (AWSRuntimeEventResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSRuntimeEventResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSRuntimeEventResult{}, err
	}
	return buildAWSRuntimeEvents(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSRuntimeEvents(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSRuntimeEventRequest, checkedAt time.Time) (AWSRuntimeEventResult, error) {
	fixtureState := normalizeAWSRuntimeEventFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSRuntimeEventResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, gaps := awsRuntimeEventFixtureRecords(accountID, region, fixtureState, checkedAt)
	filtered, applied := filterAWSRuntimeEventRecords(records, request)
	relationships := awsRuntimeEventRelationships(filtered)
	diagnostics = scopeAWSRuntimeEventDiagnostics(diagnostics, filtered)
	summary := summarizeAWSRuntimeEvents(records, len(filtered), len(relationships))
	status, confidence, failures, remediations := summarizeAWSRuntimeEventStatus(fixtureState, diagnostics, filtered)

	return AWSRuntimeEventResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsRuntimeEventsCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsRuntimeEventsCurrentIssue),
		Version:            awsRuntimeEventsVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		AppliedFilters:     applied,
		Summary:            summary,
		Records:            filtered,
		Relationships:      relationships,
		FailureReasons:     emptyStrings(failures),
		RemediationHints:   emptyStrings(remediations),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsRuntimeEventsCurrentIssue),
			awsIssueURL(1512),
			awsIssueURL(1503),
			"/docs/aws-runtime-events",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: gaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  checkedAt,
		UpdatedAt:    checkedAt,
	}, nil
}

func normalizeAWSRuntimeEventFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "", "success", "ready":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func filterAWSRuntimeEventRecords(records []AWSRuntimeEventRecord, request AWSRuntimeEventRequest) ([]AWSRuntimeEventRecord, map[string]string) {
	applied := map[string]string{}
	filters := map[string]string{
		"account_id": strings.TrimSpace(request.AccountID),
		"region":     strings.TrimSpace(request.Region),
		"event_type": normalizeAWSRuntimeEventFilterToken(request.EventType),
		"identity":   strings.TrimSpace(request.Identity),
		"agent_id":   strings.TrimSpace(request.AgentID),
		"resource":   strings.TrimSpace(request.Resource),
		"evidence":   normalizeAWSRuntimeEventFilterToken(request.Evidence),
		"owner":      normalizeAWSRuntimeEventFilterToken(request.Owner),
		"status":     normalizeAWSRuntimeEventFilterToken(request.Status),
	}
	for key, value := range filters {
		if value != "" && value != "all" {
			applied[key] = value
		}
	}
	filtered := make([]AWSRuntimeEventRecord, 0, len(records))
	for _, record := range records {
		if filters["account_id"] != "" && filters["account_id"] != record.AccountID {
			continue
		}
		if filters["region"] != "" && filters["region"] != record.Region {
			continue
		}
		if filters["event_type"] != "" && filters["event_type"] != "all" && filters["event_type"] != normalizeAWSRuntimeEventFilterToken(record.EventType) {
			continue
		}
		if filters["evidence"] != "" && filters["evidence"] != "all" && filters["evidence"] != normalizeAWSRuntimeEventFilterToken(record.EvidenceCategory) {
			continue
		}
		if filters["owner"] != "" && filters["owner"] != "all" && filters["owner"] != normalizeAWSRuntimeEventFilterToken(record.Owner) {
			continue
		}
		if filters["status"] != "" && filters["status"] != "all" && filters["status"] != normalizeAWSRuntimeEventFilterToken(record.Status) {
			continue
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], record.ActorPrincipalARN, record.ActorIdentityNodeID, record.Session.PrincipalARN, record.Session.AssumedRoleARN, record.Session.SessionIssuerARN, record.Session.SessionID) {
			continue
		}
		if filters["agent_id"] != "" && !awsRuntimeEventMatchesAny(filters["agent_id"], record.AgentID, record.AgentNodeID) {
			continue
		}
		if filters["resource"] != "" && !awsRuntimeEventMatchesAny(filters["resource"], record.TargetResourceARN, record.TargetResourceName, record.TargetResourceType, record.ResourceNodeID, record.ToolTargetRef) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered, applied
}

func normalizeAWSRuntimeEventFilterToken(value string) string {
	return strings.ToLower(strings.NewReplacer(" ", "-", "_", "-").Replace(strings.TrimSpace(value)))
}

func scopeAWSRuntimeEventDiagnostics(diagnostics []AWSRuntimeEventDiagnostic, records []AWSRuntimeEventRecord) []AWSRuntimeEventDiagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	recordIDs := make(map[string]struct{}, len(records))
	for _, record := range records {
		recordIDs[record.EventID] = struct{}{}
	}
	scoped := make([]AWSRuntimeEventDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		sourceID := strings.TrimSpace(diagnostic.SourceID)
		if sourceID == "" {
			scoped = append(scoped, diagnostic)
			continue
		}
		if _, ok := recordIDs[sourceID]; ok {
			scoped = append(scoped, diagnostic)
		}
	}
	return scoped
}

func awsRuntimeEventMatchesAny(query string, values ...string) bool {
	probe := strings.ToLower(strings.TrimSpace(query))
	if probe == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), probe) {
			return true
		}
	}
	return false
}

func summarizeAWSRuntimeEvents(records []AWSRuntimeEventRecord, filteredCount int, relationshipCount int) AWSRuntimeEventSummary {
	summary := AWSRuntimeEventSummary{
		TotalEvents:       len(records),
		FilteredEvents:    filteredCount,
		EventTypeCounts:   map[string]int{},
		StatusCounts:      map[string]int{},
		OwnerCounts:       map[string]int{},
		RelationshipCount: relationshipCount,
	}
	accounts := map[string]struct{}{}
	regions := map[string]struct{}{}
	identities := map[string]struct{}{}
	resources := map[string]struct{}{}
	sessions := map[string]struct{}{}
	for _, record := range records {
		summary.EventTypeCounts[record.EventType]++
		summary.StatusCounts[record.Status]++
		summary.OwnerCounts[record.Owner]++
		accounts[record.AccountID] = struct{}{}
		regions[record.Region] = struct{}{}
		identities[record.ActorIdentityNodeID] = struct{}{}
		if record.ResourceNodeID != "" {
			resources[record.ResourceNodeID] = struct{}{}
		}
		if record.Session.SessionID != "" {
			sessions[record.Session.SessionID] = struct{}{}
		}
		switch record.EventType {
		case "agent-tool":
			summary.AgentEventCount++
		case "secret-read":
			summary.SecretReadCount++
		case "kms-decrypt":
			summary.KMSDecryptCount++
		case "api-call":
			summary.APICallCount++
		case "sts-session":
			summary.STSSessionCount++
		}
		if record.Status == "permission-denied" {
			summary.PermissionDeniedEvents++
		}
	}
	summary.AccountCount = len(accounts)
	summary.RegionCount = len(regions)
	summary.IdentityCount = len(identities)
	summary.ResourceCount = len(resources)
	if summary.STSSessionCount == 0 {
		summary.STSSessionCount = len(sessions)
	}
	return summary
}

func summarizeAWSRuntimeEventStatus(fixtureState string, diagnostics []AWSRuntimeEventDiagnostic, records []AWSRuntimeEventRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return "blocked", 0,
			[]string{"runtime event sources are not authorized for this connector"},
			[]string{"Grant metadata-only CloudTrail LookupEvents and service audit permissions; do not grant payload, secret-value, decrypt, or object-body reads."}
	case "empty":
		return "degraded", 0.45,
			[]string{"no runtime events matched the scoped account and region"},
			[]string{"Confirm CloudTrail management events are enabled, then retry runtime event ingestion."}
	case "partial_failure":
		return "degraded", 0.74,
			[]string{"one runtime event source failed while retained events remain visible"},
			[]string{"Retry the failed runtime source without discarding successful runtime evidence."}
	case "degraded":
		return "degraded", 0.78,
			[]string{"runtime events include low-confidence or delayed evidence"},
			[]string{"Review delayed CloudTrail delivery before using runtime evidence for remediation decisions."}
	default:
		if len(records) == 0 {
			return "degraded", 0.5, []string{"runtime event filters matched no records"}, []string{"Clear filters or broaden the time/resource scope."}
		}
		if len(diagnostics) > 0 {
			return "degraded", 0.82, []string{"runtime event ingestion returned diagnostics"}, []string{"Review diagnostics before treating runtime coverage as complete."}
		}
		return "ready", 0.92, nil, nil
	}
}

func awsRuntimeEventRelationships(records []AWSRuntimeEventRecord) []AWSRuntimeEventRelationship {
	out := []AWSRuntimeEventRelationship{}
	for _, record := range records {
		if record.ActorIdentityNodeID != "" && record.ResourceNodeID != "" {
			out = append(out, AWSRuntimeEventRelationship{Type: "observed_runtime_action", FromNodeID: record.ActorIdentityNodeID, ToNodeID: record.ResourceNodeID, EvidenceRef: record.EvidenceRef})
		}
		if record.AgentNodeID != "" && record.ResourceNodeID != "" {
			out = append(out, AWSRuntimeEventRelationship{Type: "agent_invoked_runtime_action", FromNodeID: record.AgentNodeID, ToNodeID: record.ResourceNodeID, EvidenceRef: record.EvidenceRef})
		}
	}
	return out
}

func awsRuntimeEventFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSRuntimeEventRecord, []AWSRuntimeEventDiagnostic, []AWSRuntimeEventCoverageGap) {
	base := checkedAt.Add(-35 * time.Minute)
	role := fmt.Sprintf("arn:aws:iam::%s:role/identrail-runtime-reader", accountID)
	lambdaRole := fmt.Sprintf("arn:aws:iam::%s:role/lambda-invoice-agent", accountID)
	agentRole := fmt.Sprintf("arn:aws:iam::%s:role/agentcore-case-triage-runtime", accountID)
	session := func(id string, principal string, started time.Time) AWSRuntimeEventSession {
		return AWSRuntimeEventSession{
			SessionID:        id,
			PrincipalARN:     principal,
			PrincipalType:    "assumed_role",
			AssumedRoleARN:   principal,
			SessionIssuerARN: principal,
			SourceIPAddress:  "AWS Internal",
			UserAgent:        "identrail-runtime-fixture",
			StartedAt:        started,
			ExpiresAt:        started.Add(time.Hour),
		}
	}
	records := []AWSRuntimeEventRecord{
		awsRuntimeEventFixtureRecord(accountID, region, "evt-sts-runtime-reader", "sts-session", "sts.amazonaws.com", "AssumeRole", "sts:AssumeRole", role, "", "", "security", "cloudtrail", base, session("sess-runtime-reader", role, base)),
		awsRuntimeEventFixtureRecord(accountID, region, "evt-secret-invoice", "secret-read", "secretsmanager.amazonaws.com", "GetSecretValue", "secretsmanager:GetSecretValue", lambdaRole, fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:prod/ai/openai-key", region, accountID), "secret", "application", "cloudtrail", base.Add(8*time.Minute), session("sess-invoice-agent", lambdaRole, base.Add(6*time.Minute))),
		awsRuntimeEventFixtureRecord(accountID, region, "evt-kms-decrypt", "kms-decrypt", "kms.amazonaws.com", "Decrypt", "kms:Decrypt", lambdaRole, fmt.Sprintf("arn:aws:kms:%s:%s:key/cmk-agent-secrets", region, accountID), "kms_key", "platform", "cloudtrail", base.Add(10*time.Minute), session("sess-invoice-agent", lambdaRole, base.Add(6*time.Minute))),
		awsRuntimeEventFixtureRecord(accountID, region, "evt-s3-access", "api-call", "s3.amazonaws.com", "GetObject", "s3:GetObject", lambdaRole, fmt.Sprintf("arn:aws:s3:::billing-artifacts-%s/reports/redacted", accountID), "s3_object_metadata", "application", "cloudtrail", base.Add(14*time.Minute), session("sess-invoice-agent", lambdaRole, base.Add(6*time.Minute))),
		awsRuntimeEventFixtureRecord(accountID, region, "evt-agent-tool", "agent-tool", "bedrock-agentcore.amazonaws.com", "InvokeTool", "bedrock-agentcore:InvokeTool", agentRole, fmt.Sprintf("arn:aws:bedrock-agentcore:%s:%s:agent-runtime-endpoint/runtime-case-triage/blue", region, accountID), "agent_tool_target", "security", "agent-runtime", base.Add(19*time.Minute), session("sess-agentcore-runtime", agentRole, base.Add(18*time.Minute))),
	}
	records[4].AgentID = "runtime-case-triage"
	records[4].AgentNodeID = awsAIAgentNodeID(accountID, region, "agentcore_runtime", "runtime-case-triage", "2026-06-01")
	records[4].ToolName = "case-router"
	records[4].ToolTargetRef = "case-router-policy-checker"
	switch fixtureState {
	case "empty":
		return []AWSRuntimeEventRecord{}, nil, []AWSRuntimeEventCoverageGap{{
			Capability:  "cloudtrail_lookup_events",
			Status:      "empty",
			Reason:      "No runtime events were available in the fixture window.",
			Remediation: "Confirm management events are enabled and widen the runtime event time range.",
		}}
	case "degraded":
		records[3].Status = "delayed"
		records[3].Confidence = 0.64
		return records, []AWSRuntimeEventDiagnostic{{
			Collector:   "aws_runtime_events",
			SourceID:    records[3].EventID,
			Code:        "runtime_event_delivery_delayed",
			Message:     "CloudTrail delivered one runtime event after the expected collection window.",
			Remediation: "Keep delayed evidence visible and avoid automated remediation until the event window catches up.",
			Retryable:   true,
		}}, nil
	case "partial_failure":
		return records[:3], []AWSRuntimeEventDiagnostic{{
				Collector:   "aws_runtime_events",
				SourceID:    "agent-runtime",
				Code:        "agent_runtime_event_source_failed",
				Message:     "Agent runtime event source failed; CloudTrail events remain visible.",
				Remediation: "Retry only the agent runtime source and preserve retained CloudTrail evidence.",
				Retryable:   true,
			}}, []AWSRuntimeEventCoverageGap{{
				Capability:  "agent_runtime_events",
				Status:      "partial_failure",
				Reason:      "Agent runtime events could not be listed in this fixture.",
				Remediation: "Retry AgentCore runtime event collection without discarding CloudTrail events.",
			}}
	case "permission_denied":
		return []AWSRuntimeEventRecord{}, []AWSRuntimeEventDiagnostic{{
				Collector:   "aws_runtime_events",
				SourceID:    "cloudtrail",
				Code:        "permission_denied",
				Message:     "CloudTrail LookupEvents permission is not available for runtime event ingestion.",
				Remediation: "Grant metadata-only CloudTrail LookupEvents access. Do not grant payload, secret-value, decrypt, or object-body reads.",
				Retryable:   true,
			}}, []AWSRuntimeEventCoverageGap{{
				Capability:  "cloudtrail_lookup_events",
				Status:      "permission_denied",
				Reason:      "Runtime event source cannot be queried with the current connector permissions.",
				Remediation: "Add read-only event lookup permissions and retry.",
			}}
	default:
		return records, nil, nil
	}
}

func awsRuntimeEventFixtureRecord(accountID string, region string, id string, eventType string, source string, name string, action string, actorARN string, resourceARN string, resourceType string, owner string, evidence string, observedAt time.Time, session AWSRuntimeEventSession) AWSRuntimeEventRecord {
	resourceName := ""
	if resourceARN != "" {
		resourceName = resourceARN
		if slash := strings.LastIndex(resourceARN, "/"); slash >= 0 && slash < len(resourceARN)-1 {
			resourceName = resourceARN[slash+1:]
		} else if colon := strings.LastIndex(resourceARN, ":"); colon >= 0 && colon < len(resourceARN)-1 {
			resourceName = resourceARN[colon+1:]
		}
	}
	actorNode := awsIdentityNodeIDForAPI(actorARN)
	return AWSRuntimeEventRecord{
		EventID:             id,
		AccountID:           accountID,
		Region:              region,
		EventType:           eventType,
		EventSource:         source,
		EventName:           name,
		Action:              action,
		ActorPrincipalARN:   actorARN,
		ActorPrincipalType:  "assumed_role",
		ActorIdentityNodeID: actorNode,
		Session:             session,
		TargetResourceARN:   resourceARN,
		TargetResourceType:  resourceType,
		TargetResourceName:  resourceName,
		ResourceNodeID:      awsRuntimeEventResourceNodeID(resourceARN, resourceType),
		Owner:               owner,
		EvidenceCategory:    evidence,
		EvidenceRef:         fmt.Sprintf("runtime-evidence://%s/%s/%s", accountID, region, id),
		Confidence:          0.9,
		ObservedAt:          observedAt,
		CollectedAt:         observedAt.Add(2 * time.Minute),
		Status:              "observed",
		NextAction:          awsRuntimeEventNextAction(eventType),
		RedactionBoundary:   "metadata_only_no_payloads_no_secret_values",
	}
}

func awsRuntimeEventResourceNodeID(resourceARN string, resourceType string) string {
	if strings.TrimSpace(resourceARN) == "" {
		return ""
	}
	return "aws:runtime-resource:" + normalizeName(firstNonEmptyAWSValue(resourceType, "resource")) + ":" + sanitizeCredentialReferenceToken(resourceARN)
}

func awsRuntimeEventNextAction(eventType string) string {
	switch eventType {
	case "sts-session":
		return "Correlate the session with downstream API calls."
	case "secret-read":
		return "Confirm the secret read matches an expected workload path."
	case "kms-decrypt":
		return "Join decrypt evidence with key reachability before remediation."
	case "agent-tool":
		return "Review the agent identity and tool target relationship."
	default:
		return "Correlate runtime evidence with identity and resource graph context."
	}
}
