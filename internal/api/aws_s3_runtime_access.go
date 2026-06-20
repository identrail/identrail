package api

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/runtime/s3access"
)

const (
	awsS3RuntimeAccessCurrentIssue = 1519
	awsS3RuntimeAccessVersion      = "aws-s3-runtime-access-correlation-v1"
)

// AWSS3RuntimeAccessRequest is the operator-facing request. It scopes the
// correlation to a connector/account/region and exposes the runtime
// timeline/query filters the issue requires: by identity, agent, bucket,
// access mode, sensitivity, exposure, and correlation status.
type AWSS3RuntimeAccessRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Identity     string `json:"identity,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	Resource     string `json:"resource,omitempty"`
	AccessMode   string `json:"access_mode,omitempty"`
	Sensitivity  string `json:"sensitivity,omitempty"`
	Exposure     string `json:"exposure,omitempty"`
	Status       string `json:"status,omitempty"`
	// DeliverySource selects the CloudTrail ingestion channel used to
	// observe the S3 data events: `lookup_events`, `s3`, `eventbridge`,
	// or `all`. Empty defaults to `all` because S3 read/write/list are
	// data events that LookupEvents does not index. Unknown values return
	// HTTP 400.
	DeliverySource string `json:"delivery_source,omitempty"`
}

// AWSS3RuntimeAccessRecord is one (identity, bucket) correlation projected
// for the API/app surface.
type AWSS3RuntimeAccessRecord struct {
	CorrelationID     string    `json:"correlation_id"`
	AccountID         string    `json:"account_id"`
	Region            string    `json:"region"`
	IdentityNodeID    string    `json:"identity_node_id"`
	PrincipalARN      string    `json:"principal_arn,omitempty"`
	BucketARN         string    `json:"bucket_arn"`
	BucketName        string    `json:"bucket_name,omitempty"`
	ResourceNodeID    string    `json:"resource_node_id"`
	Status            string    `json:"status"`
	Confidence        float64   `json:"confidence"`
	ObservedCount     int       `json:"observed_count"`
	ObservedEventIDs  []string  `json:"observed_event_ids,omitempty"`
	ObservedModes     []string  `json:"observed_modes,omitempty"`
	GrantedModes      []string  `json:"granted_modes,omitempty"`
	SafePrefixes      []string  `json:"safe_prefixes,omitempty"`
	Actions           []string  `json:"actions,omitempty"`
	SessionIDs        []string  `json:"session_ids,omitempty"`
	AgentID           string    `json:"agent_id,omitempty"`
	AgentNodeID       string    `json:"agent_node_id,omitempty"`
	FirstObservedAt   time.Time `json:"first_observed_at,omitzero"`
	LastObservedAt    time.Time `json:"last_observed_at,omitzero"`
	StaticSources     []string  `json:"static_sources,omitempty"`
	StaticEffect      string    `json:"static_effect,omitempty"`
	Exposure          string    `json:"exposure,omitempty"`
	Sensitivity       string    `json:"sensitivity,omitempty"`
	Conditional       bool      `json:"conditional,omitempty"`
	CrossAccount      bool      `json:"cross_account,omitempty"`
	Caveats           []string  `json:"caveats,omitempty"`
	EvidenceRef       string    `json:"evidence_ref"`
	EvidenceRefs      []string  `json:"evidence_refs,omitempty"`
	NextAction        string    `json:"next_action"`
	RedactionBoundary string    `json:"redaction_boundary"`
}

// AWSS3RuntimeAccessRelationship is one correlation graph edge so the
// runtime evidence joins back to the static identity/bucket graph.
type AWSS3RuntimeAccessRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSS3RuntimeAccessDiagnostic is a structured diagnostic propagated from
// the correlated sources.
type AWSS3RuntimeAccessDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSS3RuntimeAccessCoverageGap names a coverage limitation.
type AWSS3RuntimeAccessCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSS3RuntimeAccessSummary aggregates the correlation outcome.
type AWSS3RuntimeAccessSummary struct {
	TotalCorrelations         int            `json:"total_correlations"`
	FilteredCorrelations      int            `json:"filtered_correlations"`
	StatusCounts              map[string]int `json:"status_counts"`
	ConfirmedCount            int            `json:"confirmed_count"`
	ObservedWithoutGrantCount int            `json:"observed_without_grant_count"`
	GrantedUnusedCount        int            `json:"granted_unused_count"`
	ReadCount                 int            `json:"read_count"`
	WriteCount                int            `json:"write_count"`
	ListCount                 int            `json:"list_count"`
	SensitiveExposedCount     int            `json:"sensitive_exposed_count"`
	ModeExceedsGrantCount     int            `json:"mode_exceeds_grant_count"`
	IdentityCount             int            `json:"identity_count"`
	BucketCount               int            `json:"bucket_count"`
	ObservedAccessCount       int            `json:"observed_access_count"`
	StaticGrantCount          int            `json:"static_grant_count"`
	RelationshipCount         int            `json:"relationship_count"`
}

// AWSS3RuntimeAccessResult is the deterministic envelope.
type AWSS3RuntimeAccessResult struct {
	TenantID           string                           `json:"tenant_id"`
	WorkspaceID        string                           `json:"workspace_id"`
	ProjectID          string                           `json:"project_id"`
	ConnectorID        string                           `json:"connector_id,omitempty"`
	AccountID          string                           `json:"account_id,omitempty"`
	Region             string                           `json:"region,omitempty"`
	ParentIssueNumber  int                              `json:"parent_issue_number"`
	ParentIssueRef     string                           `json:"parent_issue_ref"`
	CurrentIssueNumber int                              `json:"current_issue_number"`
	CurrentIssueRef    string                           `json:"current_issue_ref"`
	Version            string                           `json:"version"`
	Status             string                           `json:"status"`
	FixtureState       string                           `json:"fixture_state,omitempty"`
	Confidence         float64                          `json:"confidence"`
	AppliedFilters     map[string]string                `json:"applied_filters"`
	Summary            AWSS3RuntimeAccessSummary        `json:"summary"`
	Records            []AWSS3RuntimeAccessRecord       `json:"records"`
	Relationships      []AWSS3RuntimeAccessRelationship `json:"relationships"`
	Caveats            []string                         `json:"caveats"`
	FailureReasons     []string                         `json:"failure_reasons"`
	RemediationHints   []string                         `json:"remediation_hints"`
	EvidenceLinks      []string                         `json:"evidence_links"`
	CoverageGaps       []AWSS3RuntimeAccessCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSS3RuntimeAccessDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                        `json:"generated_at"`
	UpdatedAt          time.Time                        `json:"updated_at"`
}

// GetAWSS3RuntimeAccess correlates observed S3 read/write/list runtime
// events with the static reachability edges Identrail discovered and the
// bucket's exposure / sensitivity classification, returning a queryable
// correlation timeline.
func (s *Service) GetAWSS3RuntimeAccess(ctx context.Context, workspaceID string, projectID string, request AWSS3RuntimeAccessRequest) (AWSS3RuntimeAccessResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSS3RuntimeAccessResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSS3RuntimeAccessResult{}, err
	}
	now := s.Now().UTC()

	fixtureState := normalizeAWSS3RuntimeAccessFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSS3RuntimeAccessResult{}, ErrInvalidAWSConnectionRequest
	}

	// S3 read/write/list are CloudTrail *data* events, which LookupEvents
	// does not index — they are delivered through the S3 trail log /
	// EventBridge channels. Default to `all` so the correlation can
	// observe the events it correlates; operators can pin a channel.
	// Unknown tokens are validated and surface as HTTP 400.
	deliverySource := strings.TrimSpace(request.DeliverySource)
	if deliverySource == "" {
		deliverySource = "all"
	}
	var deliveryErr error
	deliverySource, deliveryErr = normalizeDeliverySource(deliverySource)
	if deliveryErr != nil {
		return AWSS3RuntimeAccessResult{}, deliveryErr
	}

	// Live composition is attempted when the connector is healthy, the
	// operator did not force a fixture state, the connector's effective
	// capability set includes runtime_evidence, and the CloudTrail factory
	// for the selected source is wired.
	useLive := awsS3RuntimeAccessHasLiveRuntimeFactory(s, deliverySource) &&
		hasConnection && connection.Connected &&
		strings.TrimSpace(request.FixtureState) == "" &&
		awsConnectorHasRuntimeEvidence(connection)

	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")

	var (
		observed        []s3access.ObservedAccess
		static          []s3access.StaticGrant
		diagnostics     []AWSS3RuntimeAccessDiagnostic
		coverageGaps    []AWSS3RuntimeAccessCoverageGap
		failures        []string
		remediations    []string
		sourceStatus    string
		coverageUnknown bool
	)

	if useLive {
		observed, static, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown, err =
			s.awsS3RuntimeAccessLiveInputs(ctx, workspaceID, projectID, connectorID, accountID, region, deliverySource)
		if err != nil {
			return AWSS3RuntimeAccessResult{}, err
		}
		fixtureState = ""
	} else if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		observed, static, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown =
			awsS3RuntimeAccessLiveUnavailableInputs(deliverySource)
		fixtureState = ""
	} else {
		observed, static, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown =
			awsS3RuntimeAccessFixtureInputs(accountID, region, fixtureState, now)
	}

	correlationResult := s3access.Correlate(s3access.CorrelateRequest{
		AccountID:                accountID,
		Region:                   region,
		Observed:                 observed,
		Static:                   static,
		DataEventCoverageUnknown: coverageUnknown,
	})

	records := awsS3RuntimeAccessRecords(correlationResult.Correlations)
	filtered, applied := filterAWSS3RuntimeAccessRecords(records, request)
	relationships := awsS3RuntimeAccessRelationships(filtered)
	summary := summarizeAWSS3RuntimeAccess(correlationResult, records, filtered, relationships)

	status, confidence := summarizeAWSS3RuntimeAccessStatus(sourceStatus, filtered, diagnostics)
	caveats := dedupeStrings(correlationResult.Caveats)

	return AWSS3RuntimeAccessResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsS3RuntimeAccessCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsS3RuntimeAccessCurrentIssue),
		Version:            awsS3RuntimeAccessVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		AppliedFilters:     applied,
		Summary:            summary,
		Records:            filtered,
		Relationships:      relationships,
		Caveats:            caveats,
		FailureReasons:     emptyStrings(dedupeStrings(failures)),
		RemediationHints:   emptyStrings(dedupeStrings(remediations)),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsS3RuntimeAccessCurrentIssue),
			awsIssueURL(awsRuntimeEventsCurrentIssue),
			awsIssueURL(awsS3BucketReachabilityCurrentIssue),
			"/docs/aws-s3-runtime-access",
			"/docs/aws-runtime-events",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSS3RuntimeAccessFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "ready":
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsS3RuntimeAccessHasLiveRuntimeFactory(s *Service, deliverySource string) bool {
	switch strings.TrimSpace(deliverySource) {
	case "lookup_events":
		return s.AWSCloudTrailLookupEventsFactory != nil
	case "s3", "eventbridge", "all":
		return s.AWSCloudTrailDeliveryFactory != nil
	default:
		return false
	}
}

func awsS3RuntimeAccessLiveUnavailableInputs(deliverySource string) ([]s3access.ObservedAccess, []s3access.StaticGrant, []AWSS3RuntimeAccessDiagnostic, []AWSS3RuntimeAccessCoverageGap, []string, []string, string, bool) {
	source := strings.TrimSpace(deliverySource)
	if source == "" {
		source = "all"
	}
	diagnostics := []AWSS3RuntimeAccessDiagnostic{{
		Collector:   s3access.CollectorName,
		SourceID:    "runtime_delivery:" + source,
		Code:        "runtime_delivery_unavailable",
		Message:     "Live S3 data-event delivery is unavailable for this connector; fixture correlations were suppressed.",
		Remediation: "Configure the selected CloudTrail delivery channel and grant the runtime_evidence capability, or request a fixture_state explicitly for demo data.",
		Retryable:   true,
	}}
	coverageGaps := []AWSS3RuntimeAccessCoverageGap{{
		Capability:  "s3_data_event_delivery",
		Status:      "delivery_unavailable",
		Reason:      "The selected runtime delivery source is not available, so real S3 read/write/list events cannot be correlated.",
		Remediation: "Wire CloudTrail S3/EventBridge delivery for this connector and grant runtime_evidence before relying on live correlation output.",
	}}
	failures := []string{"S3 runtime delivery is unavailable; fixture correlations suppressed"}
	remediations := []string{"Configure CloudTrail data-event delivery or request fixture_state explicitly for sample data."}
	return nil, nil, diagnostics, coverageGaps, failures, remediations, awsPlatformDependencyStatusDegraded, true
}

// awsS3RuntimeAccessLiveInputs composes the runtime-events and S3 bucket
// reachability services into the engine's observed/static inputs.
func (s *Service) awsS3RuntimeAccessLiveInputs(ctx context.Context, workspaceID, projectID, connectorID, accountID, region, deliverySource string) ([]s3access.ObservedAccess, []s3access.StaticGrant, []AWSS3RuntimeAccessDiagnostic, []AWSS3RuntimeAccessCoverageGap, []string, []string, string, bool, error) {
	var (
		diagnostics  []AWSS3RuntimeAccessDiagnostic
		coverageGaps []AWSS3RuntimeAccessCoverageGap
		failures     []string
		remediations []string
	)

	runtime, err := s.GetAWSRuntimeEvents(ctx, workspaceID, projectID, AWSRuntimeEventRequest{
		ConnectorID:    connectorID,
		AccountID:      accountID,
		Region:         region,
		DeliverySource: deliverySource,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", false, fmt.Errorf("correlate runtime events: %w", err)
	}
	// The S3 reachability reader is fixture-shaped today; force an empty
	// static state in live mode so observed events are not joined to
	// synthetic grants that would create false correlations.
	s3Inventory, err := s.GetAWSS3BucketReachabilityInventory(ctx, workspaceID, projectID, AWSS3BucketReachabilityInventoryRequest{
		ConnectorID:  connectorID,
		FixtureState: awsRuntimeCorrelationLiveNoStaticState,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", false, fmt.Errorf("correlate s3 reachability: %w", err)
	}

	observed := observedS3AccessFromRuntimeRecords(runtime.Records)
	static := staticGrantsFromS3Records(s3Inventory.Records)

	for _, diag := range runtime.Diagnostics {
		diagnostics = append(diagnostics, AWSS3RuntimeAccessDiagnostic(diag))
	}
	for _, gap := range runtime.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSS3RuntimeAccessCoverageGap(gap))
	}
	failures = append(failures, runtime.FailureReasons...)
	remediations = append(remediations, runtime.RemediationHints...)

	// A blocked runtime source (or a degraded one that projected no S3
	// events) means the observed side is missing, not empty — drop static
	// so unused grants are not surfaced as least-privilege cleanup work.
	if runtime.Status == awsPlatformDependencyStatusBlocked || (runtime.Status == awsPlatformDependencyStatusDegraded && len(observed) == 0) {
		observed = nil
		static = nil
	}

	sourceStatus := runtime.Status
	return observed, static, diagnostics, coverageGaps, failures, remediations, sourceStatus, true, nil
}

// observedS3AccessFromRuntimeRecords projects S3 runtime data-access
// records into engine observed accesses. The object key is redacted into a
// bounded safe prefix; only the bucket crosses the boundary as the join
// resource.
func observedS3AccessFromRuntimeRecords(records []AWSRuntimeEventRecord) []s3access.ObservedAccess {
	out := []s3access.ObservedAccess{}
	for _, record := range records {
		if !isS3RuntimeEvent(record) {
			continue
		}
		bucketARN, bucketName, safePrefixes := s3BucketAndSafePrefixes(record.TargetResourceARN)
		if bucketARN == "" {
			continue
		}
		out = append(out, s3access.ObservedAccess{
			EventID:         record.EventID,
			IdentityNodeID:  record.ActorIdentityNodeID,
			PrincipalARN:    firstNonEmptyAWSValue(record.Session.SessionIssuerARN, record.ActorPrincipalARN),
			AccountID:       record.AccountID,
			Region:          record.Region,
			BucketARN:       bucketARN,
			BucketName:      bucketName,
			AccessMode:      s3AccessModeForEvent(record.EventName, record.Action),
			SafePrefixes:    safePrefixes,
			Action:          record.Action,
			SessionID:       record.Session.SessionID,
			SessionNodeID:   record.Session.SessionNodeID,
			AgentID:         record.AgentID,
			AgentNodeID:     record.AgentNodeID,
			SourceIPAddress: record.Session.SourceIPAddress,
			LineageStatus:   record.Session.LineageStatus,
			ObservedAt:      record.ObservedAt,
			EvidenceRef:     record.EvidenceRef,
		})
	}
	return out
}

func isS3RuntimeEvent(record AWSRuntimeEventRecord) bool {
	if s3AccessModeForEvent(record.EventName, record.Action) == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(record.EventSource), "s3.amazonaws.com")
}

// s3AccessModeForEvent reduces an S3 event name (or action) to read /
// write / list. Management-plane verbs return an empty mode so they are not
// projected as runtime data access.
func s3AccessModeForEvent(eventName string, action string) string {
	return s3AccessModeForVerb(s3ActionVerb(eventName, action))
}

func s3ActionVerb(eventName string, action string) string {
	name := strings.TrimSpace(eventName)
	if name != "" {
		return strings.ToLower(name)
	}
	// Action is like "s3:GetObject"; take the verb after the colon.
	if colon := strings.LastIndex(action, ":"); colon >= 0 {
		return strings.ToLower(strings.TrimSpace(action[colon+1:]))
	}
	return strings.ToLower(strings.TrimSpace(action))
}

func s3AccessModeForVerb(name string) string {
	switch {
	case strings.HasPrefix(name, "putobject"),
		strings.HasPrefix(name, "deleteobject"),
		strings.HasPrefix(name, "copy"),
		strings.HasPrefix(name, "restore"),
		strings.HasPrefix(name, "createmultipart"),
		strings.HasPrefix(name, "completemultipart"),
		strings.HasPrefix(name, "uploadpart"),
		strings.HasPrefix(name, "abortmultipart"):
		return s3access.ModeWrite
	case name == "listbucket",
		name == "listbucketversions",
		name == "listbucketmultipartuploads",
		name == "listmultipartuploadparts",
		name == "listobjects",
		name == "listobjectsv2":
		return s3access.ModeList
	case strings.HasPrefix(name, "getobject"),
		strings.HasPrefix(name, "headobject"),
		strings.HasPrefix(name, "selectobject"):
		return s3access.ModeRead
	default:
		return ""
	}
}

var s3SafePrefixPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,40}$`)
var s3UUIDLikePattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$`)
var s3HexBlobPattern = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)

// s3BucketAndSafePrefixes splits an S3 resource ARN
// (arn:aws:s3:::bucket/key/path/object) into the bucket ARN (the only
// part used as a join resource) and at most one *safe* top-level prefix.
// The object key is never recorded: only the first path segment, and only
// when it looks like a non-identifying folder token, crosses the
// boundary; anything else (or a deeper key) is dropped or marked
// "<redacted>".
func s3BucketAndSafePrefixes(resourceARN string) (bucketARN string, bucketName string, safePrefixes []string) {
	trimmed := strings.TrimSpace(resourceARN)
	const s3Prefix = "arn:aws:s3:::"
	const s3GovPrefix = "arn:aws-us-gov:s3:::"
	const s3CNPrefix = "arn:aws-cn:s3:::"
	resource := ""
	prefix := ""
	switch {
	case strings.HasPrefix(trimmed, s3Prefix):
		prefix = s3Prefix
		resource = trimmed[len(s3Prefix):]
	case strings.HasPrefix(trimmed, s3GovPrefix):
		prefix = s3GovPrefix
		resource = trimmed[len(s3GovPrefix):]
	case strings.HasPrefix(trimmed, s3CNPrefix):
		prefix = s3CNPrefix
		resource = trimmed[len(s3CNPrefix):]
	default:
		// Not an S3 ARN we recognize; treat the whole value as a bucket
		// name only if it has no path separator (no object key to leak).
		if trimmed == "" || strings.Contains(trimmed, "/") {
			return "", "", nil
		}
		return s3Prefix + trimmed, trimmed, nil
	}
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", "", nil
	}
	parts := strings.SplitN(resource, "/", 3)
	bucketName = strings.TrimSpace(parts[0])
	if bucketName == "" {
		return "", "", nil
	}
	bucketARN = prefix + bucketName
	if len(parts) > 1 {
		if prefixToken := safeS3Prefix(parts[1]); prefixToken != "" {
			safePrefixes = []string{prefixToken}
		}
	}
	return bucketARN, bucketName, safePrefixes
}

// safeS3Prefix returns a redaction-safe representation of an S3 key's
// top-level segment. Object keys can carry customer identifiers (emails,
// IDs, tokens), so a segment is only surfaced verbatim when it looks like
// a generic folder name; anything that looks identifying is replaced with
// "<redacted>" so the operator still sees that a prefix existed without
// the value leaking.
func safeS3Prefix(segment string) string {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return ""
	}
	if !s3SafePrefixPattern.MatchString(segment) || s3UUIDLikePattern.MatchString(segment) || s3HexBlobPattern.MatchString(segment) {
		return "<redacted>"
	}
	return segment
}

// staticGrantsFromS3Records projects S3 bucket-policy grants (allow and
// deny) for IAM principals into engine static grants, deriving the
// allowed access modes from the grant's actions and attaching the
// bucket's exposure and sensitivity classification.
func staticGrantsFromS3Records(records []AWSS3BucketReachabilityRecord) []s3access.StaticGrant {
	out := []s3access.StaticGrant{}
	for _, record := range records {
		sensitivity := s3BucketSensitivity(record)
		for _, grant := range record.IdentityGrants {
			effect := firstNonEmptyAWSValue(grant.Effect, "Allow")
			modes := s3GrantAllowedModesForEffect(grant.Actions, grant.NotAction, effect)
			if len(modes) == 0 {
				continue
			}
			principal := strings.TrimSpace(grant.PrincipalARN)
			isWildcardPrincipal := grant.WildcardPrincipal || principal == "*"
			if isWildcardPrincipal {
				if !strings.EqualFold(strings.TrimSpace(grant.Effect), "Deny") {
					continue
				}
				principal = "*"
			} else if !isIAMPrincipalARNForS3Edge(principal) {
				continue
			}
			identityNodeID := ""
			if !isWildcardPrincipal {
				identityNodeID = awsIdentityNodeIDForAPI(principal)
			}
			out = append(out, s3access.StaticGrant{
				IdentityNodeID: identityNodeID,
				PrincipalARN:   principal,
				AccountID:      record.AccountID,
				Region:         record.Region,
				BucketARN:      record.BucketARN,
				BucketName:     firstNonEmptyAWSValue(record.BucketName, displayNameFromARN(record.BucketARN)),
				AllowedModes:   modes,
				Source:         s3access.SourceBucketPolicy,
				Effect:         effect,
				Conditional:    grant.HasCondition || len(grant.ConditionKeys) > 0,
				CrossAccount:   grant.IsCrossAccount,
				Exposure:       record.ExposureClassification,
				Sensitivity:    sensitivity,
				Confidence:     record.Confidence,
				EvidenceRef:    record.EvidenceRef,
			})
		}
	}
	return out
}

func s3GrantAllowedModesForEffect(actions []string, notAction bool, effect string) []string {
	if !notAction {
		return s3GrantAllowedModes(actions)
	}
	if !strings.EqualFold(strings.TrimSpace(effect), "Deny") {
		return nil
	}

	out := []string{}
	for _, mode := range s3DataAccessModes {
		if !s3ModeFullyExcludedByNotAction(mode, actions) {
			out = append(out, mode)
		}
	}
	return out
}

func s3ModeFullyExcludedByNotAction(mode string, actions []string) bool {
	hasSample := false
	for _, sample := range s3DataAccessActionSamples {
		if sample.mode != mode {
			continue
		}
		hasSample = true
		if !s3ActionExcludedByNotAction(sample.action, actions) {
			return false
		}
	}
	return hasSample
}

func s3ActionExcludedByNotAction(action string, notActions []string) bool {
	for _, notAction := range notActions {
		if awsActionPatternMatches(notAction, action) {
			return true
		}
	}
	return false
}

// s3GrantAllowedModes maps a bucket-policy statement's S3 actions to the
// read/write/list access modes they authorize, matching AWS action
// patterns (e.g. s3:*, s3:Get*) against concrete S3 data-access APIs.
func s3GrantAllowedModes(actions []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, action := range actions {
		trimmed := strings.ToLower(strings.TrimSpace(action))
		if trimmed == "" {
			continue
		}
		for _, sample := range s3DataAccessActionSamples {
			if _, ok := seen[sample.mode]; ok {
				continue
			}
			if awsActionPatternMatches(trimmed, sample.action) {
				seen[sample.mode] = struct{}{}
				out = append(out, sample.mode)
			}
		}
	}
	return out
}

var s3DataAccessActionSamples = []struct {
	mode   string
	action string
}{
	{s3access.ModeRead, "s3:getobject"},
	{s3access.ModeRead, "s3:getobjectacl"},
	{s3access.ModeRead, "s3:getobjectattributes"},
	{s3access.ModeRead, "s3:getobjectlegalhold"},
	{s3access.ModeRead, "s3:getobjectretention"},
	{s3access.ModeRead, "s3:getobjecttagging"},
	{s3access.ModeRead, "s3:getobjecttorrent"},
	{s3access.ModeRead, "s3:getobjectversion"},
	{s3access.ModeRead, "s3:getobjectversionacl"},
	{s3access.ModeRead, "s3:getobjectversionattributes"},
	{s3access.ModeRead, "s3:getobjectversionforreplication"},
	{s3access.ModeRead, "s3:getobjectversiontagging"},
	{s3access.ModeRead, "s3:getobjectversiontorrent"},
	{s3access.ModeRead, "s3:headobject"},
	{s3access.ModeRead, "s3:selectobjectcontent"},
	{s3access.ModeWrite, "s3:abortmultipartupload"},
	{s3access.ModeWrite, "s3:completemultipartupload"},
	{s3access.ModeWrite, "s3:copyobject"},
	{s3access.ModeWrite, "s3:createmultipartupload"},
	{s3access.ModeWrite, "s3:deleteobject"},
	{s3access.ModeWrite, "s3:deleteobjecttagging"},
	{s3access.ModeWrite, "s3:deleteobjectversion"},
	{s3access.ModeWrite, "s3:deleteobjectversiontagging"},
	{s3access.ModeWrite, "s3:putobject"},
	{s3access.ModeWrite, "s3:putobjectacl"},
	{s3access.ModeWrite, "s3:putobjectlegalhold"},
	{s3access.ModeWrite, "s3:putobjectretention"},
	{s3access.ModeWrite, "s3:putobjecttagging"},
	{s3access.ModeWrite, "s3:restoreobject"},
	{s3access.ModeWrite, "s3:uploadpart"},
	{s3access.ModeWrite, "s3:uploadpartcopy"},
	{s3access.ModeList, "s3:listbucket"},
	{s3access.ModeList, "s3:listbucketmultipartuploads"},
	{s3access.ModeList, "s3:listbucketversions"},
	{s3access.ModeList, "s3:listmultipartuploadparts"},
}

var s3DataAccessModes = []string{s3access.ModeRead, s3access.ModeWrite, s3access.ModeList}

// s3BucketSensitivity derives a coarse sensitivity tier for a bucket from
// an operator override tag, data-classification tags, or name heuristics.
// It never inspects object contents.
func s3BucketSensitivity(record AWSS3BucketReachabilityRecord) string {
	if override := strings.ToLower(strings.TrimSpace(record.Tags["identrail:sensitivity_classification"])); override != "" {
		return override
	}
	for key, value := range record.Tags {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "classification", "data-classification", "data_classification", "sensitivity":
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "pii", "phi", "pci", "confidential", "restricted", "sensitive", "high":
				return "high"
			}
		}
	}
	name := strings.ToLower(record.BucketName)
	for _, token := range []string{"pii", "phi", "payment", "financial", "secret", "customer", "billing", "invoice", "confidential"} {
		if strings.Contains(name, token) {
			return "elevated"
		}
	}
	return "standard"
}

func awsS3RuntimeAccessRecords(correlations []s3access.Correlation) []AWSS3RuntimeAccessRecord {
	out := make([]AWSS3RuntimeAccessRecord, 0, len(correlations))
	for _, correlation := range correlations {
		out = append(out, AWSS3RuntimeAccessRecord{
			CorrelationID:     correlation.CorrelationID,
			AccountID:         correlation.AccountID,
			Region:            correlation.Region,
			IdentityNodeID:    correlation.IdentityNodeID,
			PrincipalARN:      correlation.PrincipalARN,
			BucketARN:         correlation.BucketARN,
			BucketName:        correlation.BucketName,
			ResourceNodeID:    awsS3RuntimeAccessBucketNodeID(correlation.BucketARN),
			Status:            correlation.Status,
			Confidence:        correlation.Confidence,
			ObservedCount:     correlation.ObservedCount,
			ObservedEventIDs:  correlation.ObservedEventIDs,
			ObservedModes:     correlation.ObservedModes,
			GrantedModes:      correlation.GrantedModes,
			SafePrefixes:      correlation.SafePrefixes,
			Actions:           correlation.Actions,
			SessionIDs:        correlation.SessionIDs,
			AgentID:           correlation.AgentID,
			AgentNodeID:       correlation.AgentNodeID,
			FirstObservedAt:   correlation.FirstObservedAt,
			LastObservedAt:    correlation.LastObservedAt,
			StaticSources:     correlation.StaticSources,
			StaticEffect:      correlation.StaticEffect,
			Exposure:          correlation.Exposure,
			Sensitivity:       correlation.Sensitivity,
			Conditional:       correlation.Conditional,
			CrossAccount:      correlation.CrossAccount,
			Caveats:           correlation.Caveats,
			EvidenceRef:       fmt.Sprintf("runtime-correlation://%s", correlation.CorrelationID),
			EvidenceRefs:      correlation.EvidenceRefs,
			NextAction:        awsS3RuntimeAccessNextAction(correlation.Status),
			RedactionBoundary: correlation.RedactionBoundary,
		})
	}
	return out
}

func awsS3RuntimeAccessBucketNodeID(bucketARN string) string {
	arn := strings.TrimSpace(bucketARN)
	if arn == "" {
		return ""
	}
	return "aws:resource:s3-bucket:" + arn
}

func awsS3RuntimeAccessNextAction(status string) string {
	switch status {
	case s3access.StatusConfirmed:
		return "Confirm the observed S3 access matches an expected workload path before relying on it for remediation."
	case s3access.StatusObservedWithoutGrant:
		return "Investigate observed S3 access with no modeled grant — confirm IAM identity-policy authorization or treat as drift."
	case s3access.StatusGrantedUnused:
		return "Review the unused S3 grant for least-privilege; confirm data-event coverage before removing it."
	default:
		return "Correlate runtime evidence with the static reachability graph."
	}
}

func filterAWSS3RuntimeAccessRecords(records []AWSS3RuntimeAccessRecord, request AWSS3RuntimeAccessRequest) ([]AWSS3RuntimeAccessRecord, map[string]string) {
	filters := map[string]string{
		"account_id":  strings.TrimSpace(request.AccountID),
		"region":      strings.TrimSpace(request.Region),
		"identity":    strings.TrimSpace(request.Identity),
		"agent_id":    strings.TrimSpace(request.AgentID),
		"resource":    strings.TrimSpace(request.Resource),
		"access_mode": normalizeAWSRuntimeEventFilterToken(request.AccessMode),
		"sensitivity": normalizeAWSRuntimeEventFilterToken(request.Sensitivity),
		"exposure":    normalizeAWSRuntimeEventFilterToken(request.Exposure),
		"status":      normalizeAWSRuntimeEventFilterToken(request.Status),
	}
	for key, value := range filters {
		token := strings.ToLower(strings.TrimSpace(value))
		if token == "" || token == "all" {
			delete(filters, key)
		}
	}
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSS3RuntimeAccessRecord, 0, len(records))
	for _, record := range records {
		if filters["account_id"] != "" && filters["account_id"] != record.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], record.Region) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(record.Status) {
			continue
		}
		if filters["sensitivity"] != "" && filters["sensitivity"] != normalizeAWSRuntimeEventFilterToken(record.Sensitivity) {
			continue
		}
		if filters["exposure"] != "" && filters["exposure"] != normalizeAWSRuntimeEventFilterToken(record.Exposure) {
			continue
		}
		if filters["access_mode"] != "" && !awsS3RuntimeAccessHasMode(record, filters["access_mode"]) {
			continue
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], record.IdentityNodeID, record.PrincipalARN) {
			continue
		}
		if filters["agent_id"] != "" && !awsRuntimeEventMatchesAny(filters["agent_id"], record.AgentID, record.AgentNodeID) {
			continue
		}
		if filters["resource"] != "" && !awsRuntimeEventMatchesAny(filters["resource"], record.BucketARN, record.BucketName, record.ResourceNodeID) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered, applied
}

func awsS3RuntimeAccessHasMode(record AWSS3RuntimeAccessRecord, mode string) bool {
	for _, observed := range record.ObservedModes {
		if normalizeAWSRuntimeEventFilterToken(observed) == mode {
			return true
		}
	}
	for _, granted := range record.GrantedModes {
		if normalizeAWSRuntimeEventFilterToken(granted) == mode {
			return true
		}
	}
	return false
}

func awsS3RuntimeAccessRelationships(records []AWSS3RuntimeAccessRecord) []AWSS3RuntimeAccessRelationship {
	out := []AWSS3RuntimeAccessRelationship{}
	for _, record := range records {
		if record.IdentityNodeID == "" || record.ResourceNodeID == "" {
			continue
		}
		edgeType := "runtime_access_correlation"
		switch record.Status {
		case s3access.StatusConfirmed:
			edgeType = "confirmed_runtime_access"
		case s3access.StatusObservedWithoutGrant:
			edgeType = "observed_runtime_access_without_grant"
		case s3access.StatusGrantedUnused:
			edgeType = "unused_static_grant"
		}
		out = append(out, AWSS3RuntimeAccessRelationship{
			Type:        edgeType,
			FromNodeID:  record.IdentityNodeID,
			ToNodeID:    record.ResourceNodeID,
			EvidenceRef: record.EvidenceRef,
		})
		if record.AgentNodeID != "" {
			out = append(out, AWSS3RuntimeAccessRelationship{
				Type:        "agent_runtime_access_correlation",
				FromNodeID:  record.AgentNodeID,
				ToNodeID:    record.ResourceNodeID,
				EvidenceRef: record.EvidenceRef,
			})
		}
	}
	return out
}

func summarizeAWSS3RuntimeAccess(correlation s3access.Result, allRecords []AWSS3RuntimeAccessRecord, filtered []AWSS3RuntimeAccessRecord, relationships []AWSS3RuntimeAccessRelationship) AWSS3RuntimeAccessSummary {
	statusCounts := map[string]int{}
	for _, record := range allRecords {
		statusCounts[record.Status]++
	}
	return AWSS3RuntimeAccessSummary{
		TotalCorrelations:         len(allRecords),
		FilteredCorrelations:      len(filtered),
		StatusCounts:              statusCounts,
		ConfirmedCount:            correlation.ConfirmedCount,
		ObservedWithoutGrantCount: correlation.ObservedWithoutGrant,
		GrantedUnusedCount:        correlation.GrantedUnusedCount,
		ReadCount:                 correlation.ReadCount,
		WriteCount:                correlation.WriteCount,
		ListCount:                 correlation.ListCount,
		SensitiveExposedCount:     correlation.SensitiveExposedCount,
		ModeExceedsGrantCount:     correlation.ModeExceedsGrantCount,
		IdentityCount:             correlation.IdentityCount,
		BucketCount:               correlation.BucketCount,
		ObservedAccessCount:       correlation.ObservedAccessConsidered,
		StaticGrantCount:          correlation.StaticGrantsConsidered,
		RelationshipCount:         len(relationships),
	}
}

func summarizeAWSS3RuntimeAccessStatus(sourceStatus string, filtered []AWSS3RuntimeAccessRecord, diagnostics []AWSS3RuntimeAccessDiagnostic) (string, float64) {
	switch sourceStatus {
	case awsPlatformDependencyStatusBlocked:
		return awsPlatformDependencyStatusBlocked, 0
	case awsPlatformDependencyStatusDegraded:
		return awsPlatformDependencyStatusDegraded, 0.7
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusDegraded, 0.5
	}
	if len(diagnostics) > 0 {
		return awsPlatformDependencyStatusDegraded, 0.8
	}
	return awsPlatformDependencyStatusReady, 0.92
}
