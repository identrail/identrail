package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

const (
	awsRuntimeEventsCurrentIssue = 1517
	awsRuntimeEventsVersion      = "aws-runtime-events-contract-v3"
)

type AWSRuntimeEventRequest struct {
	ConnectorID            string `json:"connector_id,omitempty"`
	FixtureState           string `json:"fixture_state,omitempty"`
	SuppressFixtureRecords bool   `json:"-"`
	AccountID              string `json:"account_id,omitempty"`
	Region                 string `json:"region,omitempty"`
	EventType              string `json:"event_type,omitempty"`
	Identity               string `json:"identity,omitempty"`
	AgentID                string `json:"agent_id,omitempty"`
	Resource               string `json:"resource,omitempty"`
	Evidence               string `json:"evidence,omitempty"`
	Owner                  string `json:"owner,omitempty"`
	Status                 string `json:"status,omitempty"`
	// DeliverySource selects the CloudTrail ingestion path: empty (or
	// `lookup_events`) uses the LookupEvents API, `s3` uses the S3
	// trail log ingester, `eventbridge` uses the EventBridge/SQS
	// ingester, and `all` runs every available source and merges with
	// cross-channel dedupe by EventID. Unknown values return 400.
	DeliverySource string `json:"delivery_source,omitempty"`
}

type AWSRuntimeEventSession struct {
	SessionID               string   `json:"session_id"`
	SessionNodeID           string   `json:"session_node_id,omitempty"`
	PrincipalARN            string   `json:"principal_arn"`
	PrincipalType           string   `json:"principal_type"`
	AssumedRoleARN          string   `json:"assumed_role_arn,omitempty"`
	SessionIssuerARN        string   `json:"session_issuer_arn,omitempty"`
	SourceIdentity          string   `json:"source_identity,omitempty"`
	RoleSessionName         string   `json:"role_session_name,omitempty"`
	SessionTagKeys          []string `json:"session_tag_keys,omitempty"`
	TransitiveTagKeys       []string `json:"transitive_tag_keys,omitempty"`
	OriginalActorARN        string   `json:"original_actor_arn,omitempty"`
	OriginalActorNodeID     string   `json:"original_actor_node_id,omitempty"`
	ChainedFromPrincipalARN string   `json:"chained_from_principal_arn,omitempty"`
	ChainedFromNodeID       string   `json:"chained_from_node_id,omitempty"`
	LineageStatus           string   `json:"lineage_status,omitempty"`
	LineageReason           string   `json:"lineage_reason,omitempty"`
	SourceIPAddress         string   `json:"source_ip_address,omitempty"`
	UserAgent               string   `json:"user_agent,omitempty"`
	// StartedAt and ExpiresAt use `omitzero` (Go 1.24+) so a zero
	// time.Time is omitted from the JSON response entirely. Without
	// this, `encoding/json` serializes the Go zero value as the
	// bogus literal "0001-01-01T00:00:00Z" — `omitempty` does not
	// recognise zero structs. This matters because IAM/root/service
	// runtime events do not carry a CloudTrail session, and even
	// assumed-role sessions where STS rotated the credential do not
	// expose a real expiration: synthesising a value would mislead
	// downstream consumers, and emitting the literal year-0001 zero
	// would do the same.
	StartedAt time.Time `json:"started_at,omitzero"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
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
	SignalCategory      string                 `json:"signal_category,omitempty"`
	SignalScope         string                 `json:"signal_scope,omitempty"`
	AnalyzerARN         string                 `json:"analyzer_arn,omitempty"`
	SignalStaleAt       time.Time              `json:"signal_stale_at,omitzero"`
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
	IAMLastUsedSignalCount int            `json:"iam_last_used_signal_count"`
	AccessAnalyzerCount    int            `json:"access_analyzer_finding_count"`
	DormantAccessCount     int            `json:"dormant_access_count"`
	LineageResolvedCount   int            `json:"lineage_resolved_count"`
	MissingSourceIDCount   int            `json:"missing_source_identity_count"`
	AmbiguousLineageCount  int            `json:"ambiguous_lineage_count"`
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
	now := s.Now().UTC()

	// Resolve and validate the delivery_source query value. Unknown
	// tokens return HTTP 400 via ErrInvalidAWSConnectionRequest.
	deliverySource, deliveryErr := normalizeDeliverySource(request.DeliverySource)
	if deliveryErr != nil {
		return AWSRuntimeEventResult{}, deliveryErr
	}

	// Delivery-channel ingestion (S3, EventBridge, or all) is gated
	// on the same connector-healthy + runtime_evidence + no-fixture
	// guards as LookupEvents. When the operator pins a delivery
	// source other than the default lookup_events, dispatch to the
	// delivery builder instead. The delivery builder falls back to
	// fixtures and the same capability/factory diagnostics if the
	// delivery factory is not wired or the connector is not eligible.
	if deliverySource == "s3" || deliverySource == "eventbridge" || deliverySource == "all" {
		return s.getAWSRuntimeEventsFromDelivery(ctx, scope, project, connection, hasConnection, deliverySource, request, now)
	}
	// Live CloudTrail ingestion is used only when the operator has not
	// explicitly forced a fixture state, the connector is active and
	// healthy, AND the connector's effective capability set includes
	// `runtime_evidence`. The capability gate is load-bearing: the
	// default discovery-only baseline role is intentionally not granted
	// `cloudtrail:LookupEvents`, so calling LookupEvents on a
	// discovery-only connector would either fail with
	// AccessDeniedException (blocked) or — worse — bypass the operator's
	// declared capability boundary if the role happens to allow it.
	// Anything else (no connector, fixture override, disconnected
	// connector, capability denied) falls through to the deterministic
	// fixture path so demos, tests, capability-gated environments, and
	// degraded environments keep rendering the same contract shape.
	if s.AWSCloudTrailLookupEventsFactory != nil && hasConnection && connection.Connected && strings.TrimSpace(request.FixtureState) == "" && awsConnectorHasRuntimeEvidence(connection) {
		ingester, ingErr := s.AWSCloudTrailLookupEventsFactory(ctx, connection)
		if ingErr == nil && ingester != nil {
			result, resultErr := buildAWSRuntimeEventsFromCloudTrail(ctx, scope, project, connection, ingester, request, now)
			if resultErr != nil {
				return result, resultErr
			}
			return s.appendAWSRuntimeSignals(ctx, scope, project, connection, result, request, now)
		}
		// Context cancellation / deadline expiry during factory setup
		// (loading AWS config, assuming the role) is a caller-driven
		// abort — not a CloudTrail partial-coverage state. Returning
		// a degraded fixture here would let an HTTP handler whose
		// client already disconnected record a misleading response;
		// propagate the context error so the request layer can shed
		// the in-flight work. This mirrors the same check the
		// ingester applies for in-flight LookupEvents calls.
		if ingErr != nil && (errors.Is(ingErr, context.Canceled) || errors.Is(ingErr, context.DeadlineExceeded)) {
			return AWSRuntimeEventResult{}, ingErr
		}
		// Factory error is recorded as a diagnostic on the fixture
		// fallback so operators still see why live ingestion did not
		// run. A nil ingester from the factory is treated as
		// "live coverage not configured for this connector" and falls
		// through silently.
		result, fixtureErr := buildAWSRuntimeEvents(scope, project, connection, hasConnection, request, now)
		if fixtureErr != nil {
			return result, fixtureErr
		}
		if ingErr != nil {
			result.Diagnostics = append(result.Diagnostics, AWSRuntimeEventDiagnostic{
				Collector:   "aws_cloudtrail_lookup_events",
				SourceID:    "factory",
				Code:        "cloudtrail_ingester_unavailable",
				Message:     fmt.Sprintf("CloudTrail LookupEvents ingester is not available for this connector: %v", ingErr),
				Remediation: "Confirm the CloudTrail role grants metadata-only cloudtrail:LookupEvents and retry.",
				Retryable:   true,
			})
			// The fixture path already classified the response as
			// `ready` with high confidence because the synthetic
			// fixture records look healthy. That conflicts with the
			// reality that live ingestion failed and the records the
			// operator is seeing are not live evidence — downgrade so
			// the UI surfaces the partial-failure state and so the
			// failure reason that explains it is preserved.
			result.Status = "degraded"
			result.FixtureState = "partial_failure"
			if result.Confidence > 0.6 {
				result.Confidence = 0.6
			}
			result.FailureReasons = dedupeStrings(append(result.FailureReasons, "CloudTrail LookupEvents ingester is not available for this connector"))
			result.RemediationHints = dedupeStrings(append(result.RemediationHints, "Confirm the CloudTrail role grants metadata-only cloudtrail:LookupEvents and retry."))
		}
		return s.appendAWSRuntimeSignals(ctx, scope, project, connection, result, request, now)
	}
	// Capability-gated fallback: when a factory is wired and the
	// connector is otherwise live but the connector's effective
	// capability set does not include runtime_evidence, the request
	// still gets the fixture-shaped response so the UI stays stable,
	// but a capability-unavailable coverage gap and a diagnostic tell
	// the operator why live ingestion was not attempted. This keeps
	// the capability boundary visible instead of silently rendering
	// fixture data as if it were live.
	if s.AWSCloudTrailLookupEventsFactory != nil && hasConnection && connection.Connected && strings.TrimSpace(request.FixtureState) == "" && !awsConnectorHasRuntimeEvidence(connection) {
		result, fixtureErr := buildAWSRuntimeEvents(scope, project, connection, hasConnection, request, now)
		if fixtureErr != nil {
			return result, fixtureErr
		}
		result.Diagnostics = append(result.Diagnostics, AWSRuntimeEventDiagnostic{
			Collector:   "aws_cloudtrail_lookup_events",
			SourceID:    "capability",
			Code:        "runtime_evidence_capability_unavailable",
			Message:     "Connector capabilities do not include runtime_evidence; live CloudTrail LookupEvents ingestion was not attempted.",
			Remediation: "Grant the runtime_evidence connector capability and confirm the AWS role policy allows cloudtrail:LookupEvents.",
			Retryable:   false,
		})
		result.CoverageGaps = append(result.CoverageGaps, AWSRuntimeEventCoverageGap{
			Capability:  "cloudtrail_lookup_events",
			Status:      "capability_unavailable",
			Reason:      "Connector's effective capability set does not include runtime_evidence.",
			Remediation: "Grant the runtime_evidence capability to enable live CloudTrail LookupEvents ingestion.",
		})
		// Mirror the factory-error fallback: the fixture path has
		// already classified the response as ready with high
		// confidence because the synthetic records look healthy, but
		// the operator-declared capability boundary intentionally
		// blocked live ingestion. Returning ready would let operators
		// believe live coverage is active when it is not — downgrade
		// so the UI surfaces the capability-gated state and so the
		// failure reason that explains it is preserved.
		result.Status = "degraded"
		result.FixtureState = "capability_unavailable"
		if result.Confidence > 0.6 {
			result.Confidence = 0.6
		}
		result.FailureReasons = dedupeStrings(append(result.FailureReasons, "Connector capabilities do not include runtime_evidence"))
		result.RemediationHints = dedupeStrings(append(result.RemediationHints, "Grant the runtime_evidence connector capability and confirm the AWS role policy allows cloudtrail:LookupEvents."))
		return result, nil
	}
	result, err := buildAWSRuntimeEvents(scope, project, connection, hasConnection, request, now)
	if err != nil {
		return result, err
	}
	return s.appendAWSRuntimeSignals(ctx, scope, project, connection, result, request, now)
}

// awsConnectorHasRuntimeEvidence reports whether the connector's
// validated and effective capability set includes runtime_evidence.
// Effective is the authoritative gate — it never exceeds what the
// deployment policy validated — so this is the single check the
// runtime-events handler needs before assuming a role and calling
// cloudtrail:LookupEvents.
func awsConnectorHasRuntimeEvidence(connection AWSConnectionStatus) bool {
	for _, cap := range connection.Capabilities.Effective {
		if cap == domain.ConnectorCapabilityRuntimeEvidence {
			return true
		}
	}
	return false
}

// buildAWSRuntimeEventsFromCloudTrail wraps a live CloudTrail
// ingestion run in the runtime event contract envelope so the live
// response is indistinguishable in shape from the fixture path. The
// caller has already gated on a healthy connector and a nil fixture
// override, so the live result drives all of records, diagnostics,
// coverage gaps, and the top-level status.
func buildAWSRuntimeEventsFromCloudTrail(ctx context.Context, scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, ingester AWSCloudTrailRuntimeEventIngester, request AWSRuntimeEventRequest, checkedAt time.Time) (AWSRuntimeEventResult, error) {
	// Ingestion is always scoped to the connector's own account and
	// region. The request's account_id/region fields are caller-side
	// filters that downstream callers apply via
	// filterAWSRuntimeEventRecords, not ingestion-side scope: if we let
	// them through, a CloudTrailEvent whose payload is missing
	// `recipientAccountId`/`awsRegion` would inherit the caller's
	// requested values and a filter for a different account could
	// match and return mislabeled runtime evidence. The connector
	// metadata is authoritative for the trail Identrail is reading.
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	ingestResult, err := ingester.Ingest(ctx, AWSCloudTrailIngestRequest{
		AccountID:         accountID,
		Region:            region,
		EventSourceFilter: cloudTrailEventSourceFilterFor(request.EventType),
	})
	if err != nil {
		return AWSRuntimeEventResult{}, fmt.Errorf("ingest cloudtrail lookup events: %w", err)
	}

	filtered, applied := filterAWSRuntimeEventRecords(ingestResult.Records, request)
	relationships := awsRuntimeEventRelationships(filtered)
	diagnostics := scopeAWSRuntimeEventDiagnostics(ingestResult.Diagnostics, ingestResult.Records, filtered)
	summary := summarizeAWSRuntimeEvents(ingestResult.Records, len(filtered), len(relationships))

	status := ingestResult.Status
	confidence := 0.92
	failures := append([]string{}, ingestResult.FailureReasons...)
	remediations := append([]string{}, ingestResult.RemediationHints...)
	switch status {
	case "blocked":
		confidence = 0
	case "degraded":
		confidence = 0.78
	}
	// If the unfiltered ingester degraded the response solely because
	// of normalization diagnostics that the filter then scoped out,
	// the response the operator actually sees has no diagnostics, no
	// truncation, and no coverage gaps. Recompute to "ready" so the
	// UI does not show degraded for a clean filtered slice. Truncation
	// and partial-failure coverage gaps still hold the response at
	// degraded because they affect the unfiltered ingestion run, not
	// the filtered view.
	if status == "degraded" && len(diagnostics) == 0 && !ingestResult.HistoryTruncated && len(ingestResult.CoverageGaps) == 0 && len(filtered) > 0 {
		status = "ready"
		confidence = 0.92
		failures = nil
		remediations = nil
	}
	if status == "ready" && len(filtered) == 0 {
		status = "degraded"
		confidence = 0.5
		failures = append(failures, "runtime event filters matched no records")
		remediations = append(remediations, "Clear filters or broaden the time/resource scope.")
	}

	fixtureState := "success"
	if status == "blocked" {
		fixtureState = "permission_denied"
	} else if status == "degraded" {
		fixtureState = "degraded"
	}

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
		CoverageGaps: ingestResult.CoverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  checkedAt,
		UpdatedAt:    checkedAt,
	}, nil
}

// cloudTrailEventSourceFilterFor translates a normalized
// AWSRuntimeEventRequest.EventType into the CloudTrail event source
// the ingester should push to the LookupEvents request. CloudTrail
// accepts exactly one lookup attribute per call, so this only
// pushes the filter when the typed event maps to a single event
// source. Event types that span multiple sources (`agent-tool`
// covers both `bedrock-agentcore.amazonaws.com` and
// `bedrock-agent.amazonaws.com`) intentionally fall through to an
// empty pushdown — the API layer's record-level filter then scopes
// the response without dropping the second source on the trail side.
func cloudTrailEventSourceFilterFor(eventType string) string {
	switch normalizeAWSRuntimeEventFilterToken(eventType) {
	case "secret-read":
		return "secretsmanager.amazonaws.com"
	case "kms-decrypt":
		return "kms.amazonaws.com"
	case "sts-session":
		return "sts.amazonaws.com"
	default:
		return ""
	}
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
	if request.SuppressFixtureRecords && strings.TrimSpace(request.FixtureState) == "" {
		records = nil
		diagnostics = append(diagnostics, AWSRuntimeEventDiagnostic{
			Collector:   "aws_runtime_events",
			SourceID:    "fixture-suppressed",
			Code:        "runtime_fixture_records_suppressed",
			Message:     "Synthetic runtime event fixtures were suppressed because the caller did not explicitly request fixture data.",
			Remediation: "Wire live runtime evidence ingestion or request fixture_state explicitly for demos and tests.",
			Retryable:   true,
		})
		gaps = append(gaps, AWSRuntimeEventCoverageGap{
			Capability:  "runtime_evidence",
			Status:      "source_unavailable",
			Reason:      "Live runtime evidence was unavailable and synthetic fallback records were not used as evidence.",
			Remediation: "Configure live CloudTrail, IAM last-used, and Access Analyzer ingestion before using runtime records for recommendations.",
		})
	}
	filtered, applied := filterAWSRuntimeEventRecords(records, request)
	relationships := awsRuntimeEventRelationships(filtered)
	diagnostics = scopeAWSRuntimeEventDiagnostics(diagnostics, records, filtered)
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
	filters := runtimeEventFiltersFromRequest(request)
	filters = stripEmptyRuntimeFilters(filters)

	applied := map[string]string{}
	for key, value := range filters {
		if value != "" {
			applied[key] = value
		}
	}
	filtered := make([]AWSRuntimeEventRecord, 0, len(records))
	for _, record := range records {
		if filters["account_id"] != "" && filters["account_id"] != record.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], record.Region) {
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
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], record.ActorPrincipalARN, record.ActorIdentityNodeID, record.Session.PrincipalARN, record.Session.AssumedRoleARN, record.Session.SessionIssuerARN, record.Session.SourceIdentity, record.Session.RoleSessionName, record.Session.OriginalActorARN, record.Session.ChainedFromPrincipalARN, record.Session.SessionID, record.Session.SessionNodeID) {
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

func runtimeEventFiltersFromRequest(request AWSRuntimeEventRequest) map[string]string {
	return map[string]string{
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
}

func stripEmptyRuntimeFilters(filters map[string]string) map[string]string {
	if len(filters) == 0 {
		return filters
	}
	for key, value := range filters {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed == "" || trimmed == "all" {
			delete(filters, key)
		}
	}
	return filters
}

func normalizeAWSRuntimeEventFilterToken(value string) string {
	return strings.ToLower(strings.NewReplacer(" ", "-", "_", "-").Replace(strings.TrimSpace(value)))
}

// scopeAWSRuntimeEventDiagnostics keeps per-event diagnostics scoped
// to the filtered record set while preserving collector-level
// diagnostics (e.g. `cloudtrail`, `agent-runtime`, `factory`) whose
// SourceID does not refer to any record EventID. Without that
// distinction, blocked, throttled, or first-page-failure responses —
// which by construction have zero records — would lose the diagnostic
// that explains the state, even though `summarizeAWSRuntimeEventStatus`
// also surfaces the same reason via FailureReasons/RemediationHints.
func scopeAWSRuntimeEventDiagnostics(diagnostics []AWSRuntimeEventDiagnostic, allRecords []AWSRuntimeEventRecord, filteredRecords []AWSRuntimeEventRecord) []AWSRuntimeEventDiagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	// A multi-resource CloudTrail event fans out into base + `#N`
	// suffixed records in the engine; the diagnostic is keyed to the
	// base EventID only. Build a family lookup so any retained
	// fan-out child (e.g. `evt#1`) keeps the base-keyed diagnostic.
	baseEventID := func(id string) string {
		if hash := strings.Index(id, "#"); hash >= 0 {
			return id[:hash]
		}
		return id
	}
	allRecordIDs := make(map[string]struct{}, len(allRecords))
	for _, record := range allRecords {
		allRecordIDs[baseEventID(record.EventID)] = struct{}{}
	}
	filteredIDs := make(map[string]struct{}, len(filteredRecords))
	for _, record := range filteredRecords {
		filteredIDs[baseEventID(record.EventID)] = struct{}{}
	}
	scoped := make([]AWSRuntimeEventDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		sourceID := strings.TrimSpace(diagnostic.SourceID)
		if sourceID == "" {
			scoped = append(scoped, diagnostic)
			continue
		}
		base := baseEventID(sourceID)
		if _, isRecord := allRecordIDs[base]; !isRecord {
			// Collector-level diagnostic — keep regardless of filter.
			scoped = append(scoped, diagnostic)
			continue
		}
		if _, ok := filteredIDs[base]; ok {
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
		switch record.Session.LineageStatus {
		case "resolved":
			summary.LineageResolvedCount++
		case "source_identity_missing":
			summary.MissingSourceIDCount++
		case "ambiguous":
			summary.AmbiguousLineageCount++
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
		case "iam-last-used":
			summary.IAMLastUsedSignalCount++
		case "access-analyzer":
			summary.AccessAnalyzerCount++
		}
		if record.SignalCategory == "iam-last-used" && record.Status == "stale" {
			summary.DormantAccessCount++
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
			[]string{"Grant metadata-only CloudTrail LookupEvents, IAM Access Advisor, and Access Analyzer permissions; do not grant payload, secret-value, decrypt, or object-body reads."}
	case "empty":
		return "degraded", 0.45,
			[]string{"no runtime events or IAM access signals matched the scoped account and region"},
			[]string{"Confirm CloudTrail management events, IAM last-used reporting, and Access Analyzer are enabled, then retry runtime evidence ingestion."}
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
		if record.ActorIdentityNodeID != "" && record.ResourceNodeID != "" && !awsRuntimeEventSkipsObservedActionEdge(record) {
			out = append(out, AWSRuntimeEventRelationship{Type: "observed_runtime_action", FromNodeID: record.ActorIdentityNodeID, ToNodeID: record.ResourceNodeID, EvidenceRef: record.EvidenceRef})
		}
		if record.ActorIdentityNodeID != "" && record.Session.SessionNodeID != "" {
			out = append(out, AWSRuntimeEventRelationship{Type: "has_runtime_session", FromNodeID: record.ActorIdentityNodeID, ToNodeID: record.Session.SessionNodeID, EvidenceRef: record.EvidenceRef})
		}
		if record.Session.SessionNodeID != "" && record.ResourceNodeID != "" {
			out = append(out, AWSRuntimeEventRelationship{Type: "runtime_session_performed_action", FromNodeID: record.Session.SessionNodeID, ToNodeID: record.ResourceNodeID, EvidenceRef: record.EvidenceRef})
		}
		if record.Session.OriginalActorNodeID != "" && record.Session.SessionNodeID != "" && record.Session.OriginalActorNodeID != record.ActorIdentityNodeID {
			out = append(out, AWSRuntimeEventRelationship{Type: "original_actor_started_session", FromNodeID: record.Session.OriginalActorNodeID, ToNodeID: record.Session.SessionNodeID, EvidenceRef: record.EvidenceRef})
		}
		if record.Session.ChainedFromNodeID != "" && record.Session.SessionNodeID != "" {
			out = append(out, AWSRuntimeEventRelationship{Type: "role_chained_into_session", FromNodeID: record.Session.ChainedFromNodeID, ToNodeID: record.Session.SessionNodeID, EvidenceRef: record.EvidenceRef})
		}
		if record.AgentNodeID != "" && record.ResourceNodeID != "" {
			out = append(out, AWSRuntimeEventRelationship{Type: "agent_invoked_runtime_action", FromNodeID: record.AgentNodeID, ToNodeID: record.ResourceNodeID, EvidenceRef: record.EvidenceRef})
		}
	}
	return out
}

func awsRuntimeEventSkipsObservedActionEdge(record AWSRuntimeEventRecord) bool {
	category := normalizeAWSRuntimeEventFilterToken(firstNonEmptyAWSValue(record.SignalCategory, record.EventType))
	if category == "access-analyzer" {
		return true
	}
	if category != "iam-last-used" {
		return false
	}
	scope := normalizeAWSRuntimeEventFilterToken(record.SignalScope)
	if scope == "role" {
		return true
	}
	return scope == "service" && normalizeAWSRuntimeEventFilterToken(record.EventName) == "serviceneveraccessed"
}

func awsRuntimeEventFixtureRecords(accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSRuntimeEventRecord, []AWSRuntimeEventDiagnostic, []AWSRuntimeEventCoverageGap) {
	base := checkedAt.Add(-35 * time.Minute)
	role := fmt.Sprintf("arn:aws:iam::%s:role/identrail-runtime-reader", accountID)
	lambdaRole := fmt.Sprintf("arn:aws:iam::%s:role/lambda-invoice-agent", accountID)
	agentRole := fmt.Sprintf("arn:aws:iam::%s:role/agentcore-case-triage-runtime", accountID)
	ciUser := fmt.Sprintf("arn:aws:iam::%s:user/orders-ci", accountID)
	accessKeyID := "AKIA" + "ORDERS123456"
	session := func(id string, principal string, started time.Time) AWSRuntimeEventSession {
		sourceIdentity := "identrail-fixture"
		lineageStatus := "resolved"
		lineageReason := "Fixture session carries SourceIdentity and session issuer metadata."
		if id == "sess-invoice-agent" {
			sourceIdentity = ""
			lineageStatus = "source_identity_missing"
			lineageReason = "Fixture session resolved the role issuer, but SourceIdentity was absent."
		}
		return AWSRuntimeEventSession{
			SessionID:           id,
			SessionNodeID:       "aws:runtime-session:" + sanitizeCredentialReferenceToken(accountID) + ":" + sanitizeCredentialReferenceToken(region) + ":" + sanitizeCredentialReferenceToken(principal+"/"+id),
			PrincipalARN:        principal,
			PrincipalType:       "assumed_role",
			AssumedRoleARN:      principal,
			SessionIssuerARN:    principal,
			SourceIdentity:      sourceIdentity,
			RoleSessionName:     id,
			SessionTagKeys:      []string{"environment", "owner"},
			OriginalActorARN:    principal,
			OriginalActorNodeID: awsIdentityNodeIDForAPI(principal),
			LineageStatus:       lineageStatus,
			LineageReason:       lineageReason,
			SourceIPAddress:     "AWS Internal",
			UserAgent:           "identrail-runtime-fixture",
			StartedAt:           started,
			ExpiresAt:           started.Add(time.Hour),
		}
	}
	records := []AWSRuntimeEventRecord{
		awsRuntimeEventFixtureRecord(accountID, region, "evt-sts-runtime-reader", "sts-session", "sts.amazonaws.com", "AssumeRole", "sts:AssumeRole", role, "", "", "security", "cloudtrail", base, session("sess-runtime-reader", role, base)),
		awsRuntimeEventFixtureRecord(accountID, region, "evt-secret-invoice", "secret-read", "secretsmanager.amazonaws.com", "GetSecretValue", "secretsmanager:GetSecretValue", lambdaRole, fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:prod/ai/openai-key", region, accountID), "secret", "application", "cloudtrail", base.Add(8*time.Minute), session("sess-invoice-agent", lambdaRole, base.Add(6*time.Minute))),
		awsRuntimeEventFixtureRecord(accountID, region, "evt-kms-decrypt", "kms-decrypt", "kms.amazonaws.com", "Decrypt", "kms:Decrypt", lambdaRole, fmt.Sprintf("arn:aws:kms:%s:%s:key/cmk-agent-secrets", region, accountID), "kms_key", "platform", "cloudtrail", base.Add(10*time.Minute), session("sess-invoice-agent", lambdaRole, base.Add(6*time.Minute))),
		awsRuntimeEventFixtureRecord(accountID, region, "evt-s3-access", "api-call", "s3.amazonaws.com", "GetObject", "s3:GetObject", lambdaRole, fmt.Sprintf("arn:aws:s3:::billing-artifacts-%s/reports/redacted", accountID), "s3_object_metadata", "application", "cloudtrail", base.Add(14*time.Minute), session("sess-invoice-agent", lambdaRole, base.Add(6*time.Minute))),
		awsRuntimeEventFixtureRecord(accountID, region, "evt-agent-tool", "agent-tool", "bedrock-agentcore.amazonaws.com", "InvokeTool", "bedrock-agentcore:InvokeTool", agentRole, fmt.Sprintf("arn:aws:bedrock-agentcore:%s:%s:agent-runtime-endpoint/runtime-case-triage/blue", region, accountID), "agent_tool_target", "security", "agent-runtime", base.Add(19*time.Minute), session("sess-agentcore-runtime", agentRole, base.Add(18*time.Minute))),
		awsRuntimeSignalFixtureRecord(accountID, region, "evt-iam-last-used-lambda", "iam-last-used", "iam.amazonaws.com", "ServiceLastAccessed", "lambda:LastAuthenticated", lambdaRole, "aws-service://lambda", "aws_service", "Lambda", "iam-last-used", checkedAt.Add(-120*24*time.Hour), base.Add(34*time.Minute), "stale", 0.78, "service", ""),
		awsRuntimeSignalFixtureRecord(accountID, region, "evt-iam-last-used-access-key", "iam-last-used", "iam.amazonaws.com", "AccessKeyLastUsed", "iam:AccessKeyLastUsed", ciUser, "aws:iam-access-key:"+accessKeyID, "iam_access_key", accessKeyID, "iam-last-used", checkedAt.Add(-100*24*time.Hour), base.Add(35*time.Minute), "stale", 0.86, "role", ""),
		awsRuntimeSignalFixtureRecord(accountID, region, "evt-access-analyzer-open-secret", "access-analyzer", "access-analyzer.amazonaws.com", "Finding", "secretsmanager:GetSecretValue", "access-analyzer:external-principal", fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:prod/ai/openai-key", region, accountID), "AWS::SecretsManager::Secret", "prod/ai/openai-key", "access-analyzer", base.Add(24*time.Minute), base.Add(33*time.Minute), "observed", 0.9, "account", fmt.Sprintf("arn:aws:access-analyzer:%s:%s:analyzer/identrail-fixture", region, accountID)),
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
		return records[:6], []AWSRuntimeEventDiagnostic{{
				Collector:   "aws_runtime_events",
				SourceID:    "access-analyzer",
				Code:        "access_analyzer_source_failed",
				Message:     "Access Analyzer source failed; CloudTrail and IAM last-used signals remain visible.",
				Remediation: "Retry only the Access Analyzer source and preserve retained runtime evidence.",
				Retryable:   true,
			}}, []AWSRuntimeEventCoverageGap{{
				Capability:  "access_analyzer",
				Status:      "partial_failure",
				Reason:      "Access Analyzer findings could not be listed in this fixture.",
				Remediation: "Retry Access Analyzer collection without discarding CloudTrail or IAM last-used signals.",
			}}
	case "permission_denied":
		return []AWSRuntimeEventRecord{}, []AWSRuntimeEventDiagnostic{{
				Collector:   "aws_runtime_events",
				SourceID:    "iam-access-signals",
				Code:        "permission_denied",
				Message:     "Runtime evidence permissions are not available for CloudTrail, IAM last-used, or Access Analyzer ingestion.",
				Remediation: "Grant metadata-only CloudTrail LookupEvents, IAM Access Advisor, and Access Analyzer list permissions. Do not grant payload, secret-value, decrypt, or object-body reads.",
				Retryable:   true,
			}}, []AWSRuntimeEventCoverageGap{{
				Capability:  "iam_access_signals",
				Status:      "permission_denied",
				Reason:      "Runtime signal sources cannot be queried with the current connector permissions.",
				Remediation: "Add read-only event lookup, IAM last-used, and Access Analyzer permissions and retry.",
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

func awsRuntimeSignalFixtureRecord(accountID string, region string, id string, eventType string, source string, name string, action string, actorARN string, resourceARN string, resourceType string, resourceName string, evidence string, observedAt time.Time, staleAt time.Time, status string, confidence float64, signalScope string, analyzerARN string) AWSRuntimeEventRecord {
	return AWSRuntimeEventRecord{
		EventID:             id,
		AccountID:           accountID,
		Region:              region,
		EventType:           eventType,
		EventSource:         source,
		EventName:           name,
		Action:              action,
		ActorPrincipalARN:   actorARN,
		ActorPrincipalType:  "aws_principal",
		ActorIdentityNodeID: awsIdentityNodeIDForAPI(actorARN),
		Session: AWSRuntimeEventSession{
			PrincipalARN:  actorARN,
			PrincipalType: "aws_principal",
		},
		TargetResourceARN:  resourceARN,
		TargetResourceType: resourceType,
		TargetResourceName: resourceName,
		ResourceNodeID:     awsRuntimeEventResourceNodeID(resourceARN, resourceType),
		SignalCategory:     eventType,
		SignalScope:        signalScope,
		AnalyzerARN:        analyzerARN,
		SignalStaleAt:      staleAt,
		Owner:              signalOwner(eventType, status),
		EvidenceCategory:   evidence,
		EvidenceRef:        fmt.Sprintf("runtime-evidence://%s/%s/%s", accountID, region, id),
		Confidence:         confidence,
		ObservedAt:         observedAt,
		CollectedAt:        staleAt,
		Status:             status,
		NextAction:         awsRuntimeEventNextAction(eventType),
		RedactionBoundary:  "metadata_only_no_payloads_no_secret_values",
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
	case "iam-last-used":
		return "Use IAM last-used timestamps to validate dormant access before least-privilege changes."
	case "access-analyzer":
		return "Review Access Analyzer scope and finding status before trusting or remediating access."
	default:
		return "Correlate runtime evidence with identity and resource graph context."
	}
}

func (s *Service) appendAWSRuntimeSignals(ctx context.Context, scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, base AWSRuntimeEventResult, request AWSRuntimeEventRequest, checkedAt time.Time) (AWSRuntimeEventResult, error) {
	if s.AWSRuntimeSignalFactory == nil || strings.TrimSpace(request.FixtureState) != "" || !awsConnectorHasRuntimeEvidence(connection) {
		return base, nil
	}
	requestedSignalCategory, signalEvidenceInScope := awsRuntimeRequestedSignalCategory(request)
	if !signalEvidenceInScope {
		return base, nil
	}
	ingester, err := s.AWSRuntimeSignalFactory(ctx, connection)
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return AWSRuntimeEventResult{}, err
	}
	if err != nil || ingester == nil {
		base.Diagnostics = append(base.Diagnostics, AWSRuntimeEventDiagnostic{
			Collector:   "aws_iam_access_signals",
			SourceID:    "factory",
			Code:        "iam_access_signal_ingester_unavailable",
			Message:     fmt.Sprintf("IAM last-used and Access Analyzer ingester is not available for this connector: %v", err),
			Remediation: "Confirm the connector role grants metadata-only IAM Access Advisor and Access Analyzer permissions.",
			Retryable:   true,
		})
		base.CoverageGaps = append(base.CoverageGaps, AWSRuntimeEventCoverageGap{
			Capability:  "iam_access_signals",
			Status:      "source_unavailable",
			Reason:      "IAM last-used and Access Analyzer ingester could not be created.",
			Remediation: "Wire the signal ingester and grant metadata-only IAM/Access Analyzer access.",
		})
		base.Status = "degraded"
		if base.Confidence > 0.78 {
			base.Confidence = 0.78
		}
		base.FailureReasons = dedupeStrings(append(base.FailureReasons, "IAM last-used and Access Analyzer ingester is not available"))
		base.RemediationHints = dedupeStrings(append(base.RemediationHints, "Confirm metadata-only IAM Access Advisor and Access Analyzer permissions."))
		return base, nil
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	signalResult, signalErr := ingester.Ingest(ctx, AWSRuntimeSignalIngestRequest{
		AccountID:   accountID,
		Region:      region,
		CollectedAt: checkedAt,
	})
	if signalErr != nil {
		return AWSRuntimeEventResult{}, fmt.Errorf("ingest iam access signals: %w", signalErr)
	}
	wasEmptyFilterResult := awsRuntimeEventIsEmptyFilterResult(base)
	signalResult, summaryRecords := scopeAWSRuntimeSignalResult(signalResult, requestedSignalCategory)
	filtered, _ := filterAWSRuntimeEventRecords(signalResult.Records, request)
	base.Records = append(base.Records, filtered...)
	base.Relationships = awsRuntimeEventRelationships(base.Records)
	if signalEvidenceInScope || len(filtered) > 0 {
		base.Diagnostics = append(base.Diagnostics, signalResult.Diagnostics...)
		base.CoverageGaps = append(base.CoverageGaps, signalResult.CoverageGaps...)
		base.FailureReasons = dedupeStrings(append(base.FailureReasons, signalResult.FailureReasons...))
		base.RemediationHints = dedupeStrings(append(base.RemediationHints, signalResult.RemediationHints...))
		base.EvidenceLinks = dedupeStrings(append(base.EvidenceLinks, "/docs/aws-runtime-events#iam-last-used-and-access-analyzer-signals-1517"))
		base.Summary = mergeAWSRuntimeEventSummaries(base.Summary, summaryRecords, len(filtered), len(base.Relationships), base.Records)
	}
	if wasEmptyFilterResult && len(filtered) > 0 {
		base.FailureReasons = removeRuntimeEventEmptyFilterFailures(base.FailureReasons)
		base.RemediationHints = removeRuntimeEventEmptyFilterRemediations(base.RemediationHints)
		if signalResult.Status == "ready" {
			base.Status = "ready"
			base.FixtureState = "success"
			base.Confidence = 0.92
		}
	}
	if signalResult.Status == "blocked" {
		if len(base.Records) == 0 {
			base.Status = "blocked"
			base.Confidence = 0
			base.FixtureState = "permission_denied"
		} else {
			base.Status = "degraded"
			base.FixtureState = "partial_failure"
			if base.Confidence > 0.72 {
				base.Confidence = 0.72
			}
		}
	} else if base.Status == "blocked" && len(filtered) > 0 {
		base.Status = "degraded"
		base.FixtureState = "partial_failure"
		if base.Confidence == 0 || base.Confidence > 0.72 {
			base.Confidence = 0.72
		}
	} else if signalResult.Status == "degraded" && base.Status == "ready" {
		base.Status = "degraded"
		base.FixtureState = "degraded"
		if base.Confidence > 0.78 {
			base.Confidence = 0.78
		}
	}
	return base, nil
}

func awsRuntimeRequestedSignalCategory(request AWSRuntimeEventRequest) (string, bool) {
	category := ""
	for _, token := range []string{
		normalizeAWSRuntimeEventFilterToken(request.EventType),
		normalizeAWSRuntimeEventFilterToken(request.Evidence),
	} {
		switch token {
		case "", "all":
			continue
		case "iam-last-used", "access-analyzer":
			if category != "" && category != token {
				return "", false
			}
			category = token
		default:
			return "", false
		}
	}
	return category, true
}

func scopeAWSRuntimeSignalResult(result AWSRuntimeSignalIngestResult, category string) (AWSRuntimeSignalIngestResult, []AWSRuntimeEventRecord) {
	category = normalizeAWSRuntimeEventFilterToken(category)
	if category == "" || category == "all" {
		return result, result.Records
	}

	scoped := AWSRuntimeSignalIngestResult{
		Status:  "ready",
		Records: filterAWSRuntimeSignalRecordsByCategory(result.Records, category),
	}
	scoped.Diagnostics = filterAWSRuntimeSignalDiagnosticsByCategory(result.Diagnostics, category)
	scoped.CoverageGaps = filterAWSRuntimeSignalCoverageGapsByCategory(result.CoverageGaps, category)
	if len(scoped.Diagnostics) > 0 || len(scoped.CoverageGaps) > 0 {
		scoped.Status = "degraded"
		scoped.FailureReasons = []string{awsRuntimeSignalScopedFailureReason(category)}
		scoped.RemediationHints = []string{awsRuntimeSignalScopedRemediation(category)}
		if len(scoped.Records) == 0 && awsRuntimeSignalCoverageGapsPermissionDenied(scoped.CoverageGaps) {
			scoped.Status = "blocked"
			scoped.FailureReasons = []string{awsRuntimeSignalScopedPermissionReason(category)}
		}
	}
	return scoped, scoped.Records
}

func filterAWSRuntimeSignalRecordsByCategory(records []AWSRuntimeEventRecord, category string) []AWSRuntimeEventRecord {
	out := make([]AWSRuntimeEventRecord, 0, len(records))
	for _, record := range records {
		if awsRuntimeSignalRecordCategory(record) == category {
			out = append(out, record)
		}
	}
	return out
}

func filterAWSRuntimeSignalDiagnosticsByCategory(diagnostics []AWSRuntimeEventDiagnostic, category string) []AWSRuntimeEventDiagnostic {
	out := make([]AWSRuntimeEventDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if awsRuntimeSignalDiagnosticMatchesCategory(diagnostic, category) {
			out = append(out, diagnostic)
		}
	}
	return out
}

func filterAWSRuntimeSignalCoverageGapsByCategory(gaps []AWSRuntimeEventCoverageGap, category string) []AWSRuntimeEventCoverageGap {
	out := make([]AWSRuntimeEventCoverageGap, 0, len(gaps))
	for _, gap := range gaps {
		if awsRuntimeSignalCoverageGapMatchesCategory(gap, category) {
			out = append(out, gap)
		}
	}
	return out
}

func awsRuntimeSignalRecordCategory(record AWSRuntimeEventRecord) string {
	return normalizeAWSRuntimeEventFilterToken(firstNonEmptyAWSValue(record.SignalCategory, record.EventType, record.EvidenceCategory))
}

func awsRuntimeSignalDiagnosticMatchesCategory(diagnostic AWSRuntimeEventDiagnostic, category string) bool {
	sourceID := normalizeAWSRuntimeEventFilterToken(diagnostic.SourceID)
	code := normalizeAWSRuntimeEventFilterToken(diagnostic.Code)
	switch category {
	case "iam-last-used":
		return sourceID == "iam" || strings.HasPrefix(sourceID, "iam-") || strings.HasPrefix(sourceID, "iam:") || strings.Contains(code, "iam-last-used")
	case "access-analyzer":
		return sourceID == "access-analyzer" || strings.HasPrefix(sourceID, "access-analyzer-") || strings.HasPrefix(sourceID, "access-analyzer:") || strings.Contains(code, "access-analyzer")
	default:
		return true
	}
}

func awsRuntimeSignalCoverageGapMatchesCategory(gap AWSRuntimeEventCoverageGap, category string) bool {
	capability := normalizeAWSRuntimeEventFilterToken(gap.Capability)
	switch category {
	case "iam-last-used":
		return capability == "iam-last-used"
	case "access-analyzer":
		return capability == "access-analyzer"
	default:
		return true
	}
}

func awsRuntimeSignalCoverageGapsPermissionDenied(gaps []AWSRuntimeEventCoverageGap) bool {
	if len(gaps) == 0 {
		return false
	}
	for _, gap := range gaps {
		if normalizeAWSRuntimeEventFilterToken(gap.Status) != "permission-denied" {
			return false
		}
	}
	return true
}

func awsRuntimeSignalScopedFailureReason(category string) string {
	switch category {
	case "iam-last-used":
		return "IAM last-used signal coverage is incomplete"
	case "access-analyzer":
		return "Access Analyzer signal coverage is incomplete"
	default:
		return "IAM last-used and Access Analyzer signal coverage is incomplete"
	}
}

func awsRuntimeSignalScopedPermissionReason(category string) string {
	switch category {
	case "iam-last-used":
		return "IAM last-used signal permissions are unavailable"
	case "access-analyzer":
		return "Access Analyzer signal permissions are unavailable"
	default:
		return "IAM last-used and Access Analyzer permissions are unavailable"
	}
}

func awsRuntimeSignalScopedRemediation(category string) string {
	switch category {
	case "iam-last-used":
		return "Grant metadata-only iam:ListRoles, iam:GenerateServiceLastAccessedDetails, and iam:GetServiceLastAccessedDetails."
	case "access-analyzer":
		return "Grant metadata-only access-analyzer:ListAnalyzers and access-analyzer:ListFindings."
	default:
		return "Grant metadata-only IAM Access Advisor and Access Analyzer permissions."
	}
}

func awsRuntimeEventIsEmptyFilterResult(result AWSRuntimeEventResult) bool {
	if len(result.Records) != 0 || result.Summary.FilteredEvents != 0 {
		return false
	}
	for _, reason := range result.FailureReasons {
		if strings.Contains(strings.ToLower(reason), "filters matched no records") {
			return true
		}
	}
	return false
}

func removeRuntimeEventEmptyFilterFailures(values []string) []string {
	return filterRuntimeEventMessages(values, "filters matched no records")
}

func removeRuntimeEventEmptyFilterRemediations(values []string) []string {
	return filterRuntimeEventMessages(values, "clear filters")
}

func filterRuntimeEventMessages(values []string, dropSubstring string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), dropSubstring) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func mergeAWSRuntimeEventSummaries(base AWSRuntimeEventSummary, signalRecords []AWSRuntimeEventRecord, filteredSignals int, relationshipCount int, visibleRecords []AWSRuntimeEventRecord) AWSRuntimeEventSummary {
	signalSummary := summarizeAWSRuntimeEvents(signalRecords, filteredSignals, relationshipCount)
	base.TotalEvents += signalSummary.TotalEvents
	base.FilteredEvents += signalSummary.FilteredEvents
	for key, value := range signalSummary.EventTypeCounts {
		base.EventTypeCounts[key] += value
	}
	for key, value := range signalSummary.StatusCounts {
		base.StatusCounts[key] += value
	}
	for key, value := range signalSummary.OwnerCounts {
		base.OwnerCounts[key] += value
	}
	base.RelationshipCount = relationshipCount
	base.IAMLastUsedSignalCount += signalSummary.IAMLastUsedSignalCount
	base.AccessAnalyzerCount += signalSummary.AccessAnalyzerCount
	base.DormantAccessCount += signalSummary.DormantAccessCount
	base.PermissionDeniedEvents += signalSummary.PermissionDeniedEvents
	accountCount, regionCount, identityCount, resourceCount := runtimeEventVisibleUniqueCounts(visibleRecords)
	if accountCount > 0 {
		base.AccountCount = accountCount
	}
	if regionCount > 0 {
		base.RegionCount = regionCount
	}
	if identityCount > 0 {
		base.IdentityCount = identityCount
	}
	if resourceCount > 0 {
		base.ResourceCount = resourceCount
	}
	return base
}

func runtimeEventVisibleUniqueCounts(records []AWSRuntimeEventRecord) (int, int, int, int) {
	accounts := map[string]struct{}{}
	regions := map[string]struct{}{}
	identities := map[string]struct{}{}
	resources := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.AccountID) != "" {
			accounts[record.AccountID] = struct{}{}
		}
		if strings.TrimSpace(record.Region) != "" {
			regions[record.Region] = struct{}{}
		}
		if strings.TrimSpace(record.ActorIdentityNodeID) != "" {
			identities[record.ActorIdentityNodeID] = struct{}{}
		}
		if strings.TrimSpace(record.ResourceNodeID) != "" {
			resources[record.ResourceNodeID] = struct{}{}
		}
	}
	return len(accounts), len(regions), len(identities), len(resources)
}

// getAWSRuntimeEventsFromDelivery handles `delivery_source=s3`,
// `eventbridge`, and `all`. It mirrors the LookupEvents capability /
// factory gating but dispatches to the delivery factory once per
// selected source and merges results before threading them through
// the existing buildAWSRuntimeEventsFromCloudTrail envelope so the
// response shape stays identical regardless of which CloudTrail
// ingestion path produced the records.
func (s *Service) getAWSRuntimeEventsFromDelivery(ctx context.Context, scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, deliverySource string, request AWSRuntimeEventRequest, now time.Time) (AWSRuntimeEventResult, error) {
	hasRequestFixture := strings.TrimSpace(request.FixtureState) != ""
	isEligibleConnector := hasConnection && connection.Connected && awsConnectorHasRuntimeEvidence(connection)
	// Capability + factory + connector-health gate mirrors the
	// LookupEvents path. If the operator pinned a fixture state, fall
	// through to the deterministic fixture so demos stay stable.
	if hasRequestFixture || s.AWSCloudTrailDeliveryFactory == nil || !isEligibleConnector {
		result, fixtureErr := buildAWSRuntimeEvents(scope, project, connection, hasConnection, request, now)
		if fixtureErr != nil {
			return result, fixtureErr
		}
		if !hasRequestFixture && s.AWSCloudTrailDeliveryFactory != nil && hasConnection && connection.Connected && !awsConnectorHasRuntimeEvidence(connection) && result.Status != "blocked" {
			result.Diagnostics = append(result.Diagnostics, AWSRuntimeEventDiagnostic{
				Collector:   "aws_cloudtrail_delivery",
				SourceID:    "delivery-" + deliverySource,
				Code:        "cloudtrail_delivery_unavailable",
				Message:     fmt.Sprintf("CloudTrail %s delivery ingester is not available for this connector.", deliverySource),
				Remediation: "Grant the runtime_evidence capability and configure the connector role with read-only access to the trail's S3 bucket or EventBridge target.",
				Retryable:   true,
			})
			result.CoverageGaps = append(result.CoverageGaps, AWSRuntimeEventCoverageGap{
				Capability:  "cloudtrail_" + deliverySource + "_delivery",
				Status:      "capability_unavailable",
				Reason:      "Connector capabilities do not include runtime_evidence.",
				Remediation: "Grant runtime_evidence to this connector role and rerun the query.",
			})
			result.Status = "degraded"
			result.FixtureState = "partial_failure"
			if result.Confidence > 0.6 {
				result.Confidence = 0.6
			}
			result.FailureReasons = dedupeStrings(append(result.FailureReasons, fmt.Sprintf("CloudTrail %s delivery ingester is not available for this connector", deliverySource)))
			result.RemediationHints = dedupeStrings(append(result.RemediationHints, "Wire AWSCloudTrailDeliveryFactory or grant read-only delivery channel access."))
		}
		return result, nil
	}

	sources := []AWSCloudTrailDeliverySource{}
	switch deliverySource {
	case "s3":
		sources = append(sources, AWSCloudTrailDeliverySourceS3)
	case "eventbridge":
		sources = append(sources, AWSCloudTrailDeliverySourceEventBridge)
	case "all":
		sources = append(sources, AWSCloudTrailDeliverySourceS3, AWSCloudTrailDeliverySourceEventBridge)
	}

	results := make([]AWSCloudTrailIngestResult, 0, len(sources))
	for _, source := range sources {
		ingester, ingErr := s.AWSCloudTrailDeliveryFactory(ctx, connection, source)
		if ingErr != nil && (errors.Is(ingErr, context.Canceled) || errors.Is(ingErr, context.DeadlineExceeded)) {
			return AWSRuntimeEventResult{}, ingErr
		}
		if ingErr != nil || ingester == nil {
			// Source not configured for this connector. Record a
			// per-source diagnostic so the operator sees why it was
			// skipped, then continue with the other sources.
			results = append(results, AWSCloudTrailIngestResult{
				Status: "degraded",
				Diagnostics: []AWSRuntimeEventDiagnostic{{
					Collector:   "aws_cloudtrail_delivery",
					SourceID:    string(source),
					Code:        "cloudtrail_delivery_source_unavailable",
					Message:     fmt.Sprintf("CloudTrail %s delivery ingester is not configured: %v", source, ingErr),
					Remediation: "Configure the bucket/queue for this delivery channel on the connector and retry.",
					Retryable:   true,
				}},
				CoverageGaps: []AWSRuntimeEventCoverageGap{{
					Capability:  "cloudtrail_" + string(source) + "_delivery",
					Status:      "delivery_unavailable",
					Reason:      fmt.Sprintf("Connector does not have a configured %s delivery target.", source),
					Remediation: "Configure the delivery channel and retry.",
				}},
				FailureReasons:   []string{fmt.Sprintf("CloudTrail %s delivery is not configured", source)},
				RemediationHints: []string{fmt.Sprintf("Configure the %s delivery target on the connector.", source)},
			})
			continue
		}
		accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
		region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
		ingestResult, err := ingester.Ingest(ctx, AWSCloudTrailIngestRequest{
			AccountID: accountID,
			Region:    region,
			Filters:   runtimeEventFiltersFromRequest(request),
		})
		if err != nil {
			return AWSRuntimeEventResult{}, fmt.Errorf("ingest cloudtrail %s delivery: %w", source, err)
		}
		results = append(results, ingestResult)
	}

	merged := mergeDeliveryResults(results)
	// Wrap a fake ingester so we can reuse the existing CloudTrail
	// envelope builder without duplicating its 80+ lines.
	stub := &precomputedIngester{result: merged}
	result, err := buildAWSRuntimeEventsFromCloudTrail(ctx, scope, project, connection, stub, request, now)
	if err != nil {
		return result, err
	}
	return s.appendAWSRuntimeSignals(ctx, scope, project, connection, result, request, now)
}

// precomputedIngester satisfies AWSCloudTrailRuntimeEventIngester
// with a pre-computed result. Used by the delivery dispatcher to
// reuse buildAWSRuntimeEventsFromCloudTrail's envelope builder
// without duplicating its summary/filter/diagnostic logic.
type precomputedIngester struct{ result AWSCloudTrailIngestResult }

func (p *precomputedIngester) Ingest(_ context.Context, _ AWSCloudTrailIngestRequest) (AWSCloudTrailIngestResult, error) {
	return p.result, nil
}
