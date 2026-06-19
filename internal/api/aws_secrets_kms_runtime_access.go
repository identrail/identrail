package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/runtime/secretsaccess"
)

const (
	awsSecretsKMSRuntimeAccessCurrentIssue = 1518
	awsSecretsKMSRuntimeAccessVersion      = "aws-secrets-kms-runtime-access-correlation-v1"
	awsRuntimeCorrelationLiveNoStaticState = "empty"
)

// AWSSecretsKMSRuntimeAccessRequest is the operator-facing request. It
// scopes the correlation to a connector/account/region and exposes the
// runtime timeline/query filters the issue requires: by identity, agent,
// resource, resource kind, and correlation status.
type AWSSecretsKMSRuntimeAccessRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Identity     string `json:"identity,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	Resource     string `json:"resource,omitempty"`
	ResourceKind string `json:"resource_kind,omitempty"`
	Status       string `json:"status,omitempty"`
	// DeliverySource selects the CloudTrail ingestion channel used to
	// observe the secret-read / kms-decrypt data events: `lookup_events`,
	// `s3`, `eventbridge`, or `all`. Empty defaults to `all` because these
	// are data events that LookupEvents does not index. Unknown values
	// return HTTP 400.
	DeliverySource string `json:"delivery_source,omitempty"`
}

// AWSSecretsKMSRuntimeAccessRecord is one (identity, resource)
// correlation projected for the API/app surface.
type AWSSecretsKMSRuntimeAccessRecord struct {
	CorrelationID     string    `json:"correlation_id"`
	AccountID         string    `json:"account_id"`
	Region            string    `json:"region"`
	IdentityNodeID    string    `json:"identity_node_id"`
	PrincipalARN      string    `json:"principal_arn,omitempty"`
	ResourceKind      string    `json:"resource_kind"`
	ResourceARN       string    `json:"resource_arn"`
	ResourceName      string    `json:"resource_name,omitempty"`
	ResourceNodeID    string    `json:"resource_node_id"`
	Status            string    `json:"status"`
	Confidence        float64   `json:"confidence"`
	ObservedCount     int       `json:"observed_count"`
	ObservedEventIDs  []string  `json:"observed_event_ids,omitempty"`
	Actions           []string  `json:"actions,omitempty"`
	SessionIDs        []string  `json:"session_ids,omitempty"`
	AgentID           string    `json:"agent_id,omitempty"`
	AgentNodeID       string    `json:"agent_node_id,omitempty"`
	FirstObservedAt   time.Time `json:"first_observed_at,omitzero"`
	LastObservedAt    time.Time `json:"last_observed_at,omitzero"`
	StaticSources     []string  `json:"static_sources,omitempty"`
	StaticEffect      string    `json:"static_effect,omitempty"`
	Conditional       bool      `json:"conditional,omitempty"`
	CrossAccount      bool      `json:"cross_account,omitempty"`
	Caveats           []string  `json:"caveats,omitempty"`
	EvidenceRef       string    `json:"evidence_ref"`
	EvidenceRefs      []string  `json:"evidence_refs,omitempty"`
	NextAction        string    `json:"next_action"`
	RedactionBoundary string    `json:"redaction_boundary"`
}

// AWSSecretsKMSRuntimeAccessRelationship is one correlation graph edge so
// the runtime evidence joins back to the static identity/resource graph.
type AWSSecretsKMSRuntimeAccessRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSSecretsKMSRuntimeAccessDiagnostic is a structured diagnostic
// propagated from the correlated sources.
type AWSSecretsKMSRuntimeAccessDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// AWSSecretsKMSRuntimeAccessCoverageGap names a coverage limitation.
type AWSSecretsKMSRuntimeAccessCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSSecretsKMSRuntimeAccessSummary aggregates the correlation outcome.
type AWSSecretsKMSRuntimeAccessSummary struct {
	TotalCorrelations         int            `json:"total_correlations"`
	FilteredCorrelations      int            `json:"filtered_correlations"`
	StatusCounts              map[string]int `json:"status_counts"`
	ConfirmedCount            int            `json:"confirmed_count"`
	ObservedWithoutGrantCount int            `json:"observed_without_grant_count"`
	GrantedUnusedCount        int            `json:"granted_unused_count"`
	SecretCorrelationCount    int            `json:"secret_correlation_count"`
	KMSKeyCorrelationCount    int            `json:"kms_key_correlation_count"`
	IdentityCount             int            `json:"identity_count"`
	ResourceCount             int            `json:"resource_count"`
	ObservedAccessCount       int            `json:"observed_access_count"`
	StaticGrantCount          int            `json:"static_grant_count"`
	RelationshipCount         int            `json:"relationship_count"`
}

// AWSSecretsKMSRuntimeAccessResult is the deterministic envelope.
type AWSSecretsKMSRuntimeAccessResult struct {
	TenantID           string                                   `json:"tenant_id"`
	WorkspaceID        string                                   `json:"workspace_id"`
	ProjectID          string                                   `json:"project_id"`
	ConnectorID        string                                   `json:"connector_id,omitempty"`
	AccountID          string                                   `json:"account_id,omitempty"`
	Region             string                                   `json:"region,omitempty"`
	ParentIssueNumber  int                                      `json:"parent_issue_number"`
	ParentIssueRef     string                                   `json:"parent_issue_ref"`
	CurrentIssueNumber int                                      `json:"current_issue_number"`
	CurrentIssueRef    string                                   `json:"current_issue_ref"`
	Version            string                                   `json:"version"`
	Status             string                                   `json:"status"`
	FixtureState       string                                   `json:"fixture_state"`
	Confidence         float64                                  `json:"confidence"`
	AppliedFilters     map[string]string                        `json:"applied_filters"`
	Summary            AWSSecretsKMSRuntimeAccessSummary        `json:"summary"`
	Records            []AWSSecretsKMSRuntimeAccessRecord       `json:"records"`
	Relationships      []AWSSecretsKMSRuntimeAccessRelationship `json:"relationships"`
	Caveats            []string                                 `json:"caveats"`
	FailureReasons     []string                                 `json:"failure_reasons"`
	RemediationHints   []string                                 `json:"remediation_hints"`
	EvidenceLinks      []string                                 `json:"evidence_links"`
	CoverageGaps       []AWSSecretsKMSRuntimeAccessCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSSecretsKMSRuntimeAccessDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                                `json:"generated_at"`
	UpdatedAt          time.Time                                `json:"updated_at"`
}

// GetAWSSecretsKMSRuntimeAccess correlates observed Secrets Manager read
// and KMS decrypt runtime events with the static reachability edges
// Identrail already discovered, returning a queryable correlation
// timeline.
func (s *Service) GetAWSSecretsKMSRuntimeAccess(ctx context.Context, workspaceID string, projectID string, request AWSSecretsKMSRuntimeAccessRequest) (AWSSecretsKMSRuntimeAccessResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, err
	}
	now := s.Now().UTC()

	fixtureState := normalizeAWSSecretsKMSRuntimeAccessFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSSecretsKMSRuntimeAccessResult{}, ErrInvalidAWSConnectionRequest
	}

	// secret-read and kms-decrypt are CloudTrail *data* events, which the
	// LookupEvents API does not index — they are only delivered through
	// the S3 trail log / EventBridge delivery channels. So this endpoint
	// defaults its runtime source to `all` (fan out across every wired
	// channel and dedupe by EventID) rather than the runtime-events
	// endpoint's `lookup_events` default; otherwise the correlation would
	// never observe the data events it correlates and would report real
	// runtime use as granted_unused. Operators can still pin a specific
	// channel. Unknown tokens are validated downstream by
	// GetAWSRuntimeEvents and surface as HTTP 400.
	deliverySource := strings.TrimSpace(request.DeliverySource)
	if deliverySource == "" {
		deliverySource = "all"
	}

	var deliveryErr error
	deliverySource, deliveryErr = normalizeDeliverySource(deliverySource)
	if deliveryErr != nil {
		return AWSSecretsKMSRuntimeAccessResult{}, deliveryErr
	}

	// Live composition is attempted when the connector is healthy, the
	// operator did not force a fixture state, the connector's effective
	// capability set includes runtime_evidence, and the CloudTrail factory
	// required for the selected source is wired. The default data-event
	// path is delivery-backed, so a LookupEvents factory alone must not
	// enter live mode and then fall through to delivery fixtures.
	useLive := awsSecretsKMSRuntimeAccessHasLiveRuntimeFactory(s, deliverySource) &&
		hasConnection && connection.Connected &&
		strings.TrimSpace(request.FixtureState) == "" &&
		awsConnectorHasRuntimeEvidence(connection)

	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")

	var (
		observed        []secretsaccess.ObservedAccess
		static          []secretsaccess.StaticGrant
		diagnostics     []AWSSecretsKMSRuntimeAccessDiagnostic
		coverageGaps    []AWSSecretsKMSRuntimeAccessCoverageGap
		failures        []string
		remediations    []string
		sourceStatus    string
		coverageUnknown bool
	)

	if useLive {
		observed, static, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown, err =
			s.awsSecretsKMSRuntimeAccessLiveInputs(ctx, workspaceID, projectID, connectorID, accountID, region, deliverySource)
		if err != nil {
			return AWSSecretsKMSRuntimeAccessResult{}, err
		}
	} else if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		observed, static, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown =
			awsSecretsKMSRuntimeAccessLiveUnavailableInputs(deliverySource)
		fixtureState = ""
	} else {
		observed, static, diagnostics, coverageGaps, failures, remediations, sourceStatus, coverageUnknown =
			awsSecretsKMSRuntimeAccessFixtureInputs(accountID, region, fixtureState, now)
	}

	correlationResult := secretsaccess.Correlate(secretsaccess.CorrelateRequest{
		AccountID:                accountID,
		Region:                   region,
		Observed:                 observed,
		Static:                   static,
		DataEventCoverageUnknown: coverageUnknown,
	})

	records := awsSecretsKMSRuntimeAccessRecords(correlationResult.Correlations)
	filtered, applied := filterAWSSecretsKMSRuntimeAccessRecords(records, request)
	relationships := awsSecretsKMSRuntimeAccessRelationships(filtered)
	summary := summarizeAWSSecretsKMSRuntimeAccess(correlationResult, records, filtered, relationships)

	status, confidence := summarizeAWSSecretsKMSRuntimeAccessStatus(sourceStatus, filtered, diagnostics)
	caveats := dedupeStrings(correlationResult.Caveats)

	return AWSSecretsKMSRuntimeAccessResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsSecretsKMSRuntimeAccessCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsSecretsKMSRuntimeAccessCurrentIssue),
		Version:            awsSecretsKMSRuntimeAccessVersion,
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
			awsIssueURL(awsSecretsKMSRuntimeAccessCurrentIssue),
			awsIssueURL(awsRuntimeEventsCurrentIssue),
			awsIssueURL(awsKMSDecryptReachabilityCurrentIssue),
			awsIssueURL(awsSecretsManagerMetadataCurrentIssue),
			"/docs/aws-secrets-kms-runtime-access",
			"/docs/aws-runtime-events",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSSecretsKMSRuntimeAccessFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsSecretsKMSRuntimeAccessLiveUnavailableInputs(deliverySource string) ([]secretsaccess.ObservedAccess, []secretsaccess.StaticGrant, []AWSSecretsKMSRuntimeAccessDiagnostic, []AWSSecretsKMSRuntimeAccessCoverageGap, []string, []string, string, bool) {
	source := strings.TrimSpace(deliverySource)
	if source == "" {
		source = "all"
	}
	diagnostics := []AWSSecretsKMSRuntimeAccessDiagnostic{{
		Collector:   secretsaccess.CollectorName,
		SourceID:    "runtime_delivery:" + source,
		Code:        "runtime_delivery_unavailable",
		Message:     "Live Secrets Manager / KMS data-event delivery is unavailable for this connector; fixture correlations were suppressed.",
		Remediation: "Configure the selected CloudTrail delivery channel and grant the runtime_evidence capability, or request a fixture_state explicitly for demo data.",
		Retryable:   true,
	}}
	coverageGaps := []AWSSecretsKMSRuntimeAccessCoverageGap{{
		Capability:  "secrets_kms_data_event_delivery",
		Status:      "delivery_unavailable",
		Reason:      "The selected runtime delivery source is not available, so real secret-read / kms-decrypt events cannot be correlated.",
		Remediation: "Wire CloudTrail S3/EventBridge delivery for this connector and grant runtime_evidence before relying on live correlation output.",
	}}
	failures := []string{"Secrets Manager / KMS runtime delivery is unavailable; fixture correlations suppressed"}
	remediations := []string{"Configure CloudTrail data-event delivery or request fixture_state explicitly for sample data."}
	return nil, nil, diagnostics, coverageGaps, failures, remediations, awsPlatformDependencyStatusDegraded, true
}

// awsSecretsKMSRuntimeAccessLiveInputs composes the runtime-events, KMS
// decrypt reachability, and Secrets Manager metadata services into the
// engine's observed/static inputs. Each sub-service applies its own
// capability gating and live/fixture decision, so this method stays a
// thin adapter that joins their results.
func (s *Service) awsSecretsKMSRuntimeAccessLiveInputs(ctx context.Context, workspaceID, projectID, connectorID, accountID, region, deliverySource string) ([]secretsaccess.ObservedAccess, []secretsaccess.StaticGrant, []AWSSecretsKMSRuntimeAccessDiagnostic, []AWSSecretsKMSRuntimeAccessCoverageGap, []string, []string, string, bool, error) {
	var (
		diagnostics  []AWSSecretsKMSRuntimeAccessDiagnostic
		coverageGaps []AWSSecretsKMSRuntimeAccessCoverageGap
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
	// In live correlation mode, avoid joining runtime events to fixture-backed
	// static grants. The inventory readers are fixture-shaped today; forcing
	// an empty static state keeps the observed events but suppresses synthetic
	// grants that could create false granted_unused / observed_without_grant results.
	kms, err := s.GetAWSKMSDecryptReachabilityInventory(ctx, workspaceID, projectID, AWSKMSDecryptReachabilityInventoryRequest{
		ConnectorID:  connectorID,
		FixtureState: awsRuntimeCorrelationLiveNoStaticState,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", false, fmt.Errorf("correlate kms reachability: %w", err)
	}
	secrets, err := s.GetAWSSecretsManagerMetadataInventory(ctx, workspaceID, projectID, AWSSecretsManagerMetadataInventoryRequest{
		ConnectorID:  connectorID,
		FixtureState: awsRuntimeCorrelationLiveNoStaticState,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, "", false, fmt.Errorf("correlate secrets metadata: %w", err)
	}

	observed := observedAccessFromRuntimeRecords(runtime.Records)
	static := append(staticGrantsFromKMSRecords(kms.Records), staticGrantsFromSecretsRecords(secrets.Records)...)

	for _, diag := range runtime.Diagnostics {
		diagnostics = append(diagnostics, AWSSecretsKMSRuntimeAccessDiagnostic(diag))
	}
	for _, gap := range runtime.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSSecretsKMSRuntimeAccessCoverageGap(gap))
	}
	failures = append(failures, runtime.FailureReasons...)
	remediations = append(remediations, runtime.RemediationHints...)

	// Correlation needs usable observed events. For an explicitly blocked
	// runtime source, or a degraded source that projects to no relevant
	// secret-read / kms-decrypt events, static edges should not appear as
	// confirmed, observed, or granted_unused. This prevents over-calling
	// static grants when only unrelated runtime channels are returning data.
	if runtime.Status == awsPlatformDependencyStatusBlocked || (runtime.Status == awsPlatformDependencyStatusDegraded && len(observed) == 0) {
		observed = nil
		static = nil
	}

	// A blocked runtime source means we cannot assert any observed
	// access, so the runtime status drives the envelope.
	sourceStatus := runtime.Status
	// Runtime evidence is sourced from CloudTrail; Secrets Manager
	// GetSecretValue and KMS Decrypt are data events, so coverage is
	// never guaranteed complete from a management-event lookup.
	return observed, static, diagnostics, coverageGaps, failures, remediations, sourceStatus, true, nil
}

// observedAccessFromRuntimeRecords projects the secret-read and
// kms-decrypt runtime event records into engine observed accesses. Other
// event types (sts-session, api-call, agent-tool) are not in scope for
// this correlation and are dropped.
func observedAccessFromRuntimeRecords(records []AWSRuntimeEventRecord) []secretsaccess.ObservedAccess {
	out := []secretsaccess.ObservedAccess{}
	for _, record := range records {
		kind := resourceKindForRuntimeEventType(record.EventType)
		if kind == "" {
			continue
		}
		out = append(out, secretsaccess.ObservedAccess{
			EventID:         record.EventID,
			IdentityNodeID:  record.ActorIdentityNodeID,
			PrincipalARN:    firstNonEmptyAWSValue(record.Session.SessionIssuerARN, record.ActorPrincipalARN),
			AccountID:       record.AccountID,
			Region:          record.Region,
			ResourceKind:    kind,
			ResourceARN:     record.TargetResourceARN,
			ResourceName:    record.TargetResourceName,
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

func resourceKindForRuntimeEventType(eventType string) string {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "secret-read":
		return secretsaccess.ResourceKindSecret
	case "kms-decrypt":
		return secretsaccess.ResourceKindKMSKey
	default:
		return ""
	}
}

// staticGrantsFromKMSRecords projects KMS key-policy and live-grant
// decrypt grants (allow and deny) for IAM principals into engine static
// grants. Wildcard and non-IAM principals are dropped because they have
// no identity node to join against.
func staticGrantsFromKMSRecords(records []AWSKMSDecryptReachabilityRecord) []secretsaccess.StaticGrant {
	out := []secretsaccess.StaticGrant{}
	for _, record := range records {
		for _, grant := range record.IdentityGrants {
			if !kmsCapabilitiesIncludeDecrypt(grant.Capabilities) {
				continue
			}

			principal := strings.TrimSpace(grant.PrincipalARN)
			isWildcardPrincipal := grant.WildcardPrincipal || principal == "*"
			if isWildcardPrincipal {
				if !strings.EqualFold(strings.TrimSpace(grant.Effect), "Deny") {
					continue
				}
				principal = "*"
			} else if !isIAMPrincipalARNForKMSEdge(principal) {
				continue
			}

			identityNodeID := ""
			if !isWildcardPrincipal {
				identityNodeID = awsIdentityNodeIDForAPI(principal)
			}
			out = append(out, secretsaccess.StaticGrant{
				IdentityNodeID: identityNodeID,
				PrincipalARN:   principal,
				AccountID:      record.AccountID,
				Region:         record.Region,
				ResourceKind:   secretsaccess.ResourceKindKMSKey,
				ResourceARN:    record.KeyARN,
				ResourceName:   firstNonEmptyAWSValue(displayNameFromARN(record.KeyARN), record.KeyID),
				Source:         secretsaccess.SourceKeyPolicy,
				Effect:         firstNonEmptyAWSValue(grant.Effect, "Allow"),
				Conditional:    grant.HasCondition || len(grant.ConditionKeys) > 0,
				CrossAccount:   grant.IsCrossAccount,
				Confidence:     record.Confidence,
				EvidenceRef:    record.EvidenceRef,
				Actions:        dedupeStrings(normalizeStringList(grant.Actions)),
			})
		}
		for _, grant := range record.Grants {
			if !isIAMPrincipalARNForKMSEdge(grant.GranteePrincipal) || !kmsCapabilitiesIncludeDecrypt(grant.Capabilities) {
				continue
			}
			out = append(out, secretsaccess.StaticGrant{
				IdentityNodeID: awsIdentityNodeIDForAPI(grant.GranteePrincipal),
				PrincipalARN:   grant.GranteePrincipal,
				AccountID:      record.AccountID,
				Region:         record.Region,
				ResourceKind:   secretsaccess.ResourceKindKMSKey,
				ResourceARN:    record.KeyARN,
				ResourceName:   firstNonEmptyAWSValue(displayNameFromARN(record.KeyARN), record.KeyID),
				Source:         secretsaccess.SourceKMSGrant,
				Effect:         "Allow",
				Conditional:    grant.HasConstraints,
				CrossAccount:   grant.IsCrossAccount,
				Confidence:     record.Confidence,
				EvidenceRef:    record.EvidenceRef,
				Actions:        dedupeStrings(normalizeStringList(grant.Operations)),
			})
		}
	}
	return out
}

func awsSecretsKMSRuntimeAccessHasLiveRuntimeFactory(s *Service, deliverySource string) bool {
	switch strings.TrimSpace(deliverySource) {
	case "lookup_events":
		return s.AWSCloudTrailLookupEventsFactory != nil
	case "s3", "eventbridge", "all":
		return s.AWSCloudTrailDeliveryFactory != nil
	default:
		return false
	}
}

// staticGrantsFromSecretsRecords projects Secrets Manager resource-policy
// grants (allow and deny) for IAM principals that can read the secret
// into engine static grants.
func staticGrantsFromSecretsRecords(records []AWSSecretsManagerMetadataRecord) []secretsaccess.StaticGrant {
	out := []secretsaccess.StaticGrant{}
	for _, record := range records {
		for _, grant := range record.IdentityGrants {
			if !secretsActionsIncludeRead(grant.Actions) {
				continue
			}

			principal := strings.TrimSpace(grant.PrincipalARN)
			isWildcardPrincipal := grant.WildcardPrincipal || principal == "*"
			if isWildcardPrincipal {
				if !strings.EqualFold(strings.TrimSpace(grant.Effect), "Deny") {
					continue
				}
				principal = "*"
			} else if !isIAMPrincipalARNForKMSEdge(principal) {
				continue
			}

			identityNodeID := ""
			if !isWildcardPrincipal {
				identityNodeID = awsIdentityNodeIDForAPI(principal)
			}
			out = append(out, secretsaccess.StaticGrant{
				IdentityNodeID: identityNodeID,
				PrincipalARN:   principal,
				AccountID:      record.AccountID,
				Region:         record.Region,
				ResourceKind:   secretsaccess.ResourceKindSecret,
				ResourceARN:    record.SecretARN,
				ResourceName:   firstNonEmptyAWSValue(record.SecretName, displayNameFromARN(record.SecretARN)),
				Source:         secretsaccess.SourceResourcePolicy,
				Effect:         firstNonEmptyAWSValue(grant.Effect, "Allow"),
				Conditional:    grant.HasCondition || len(grant.ConditionKeys) > 0,
				CrossAccount:   grant.IsCrossAccount,
				Confidence:     record.Confidence,
				EvidenceRef:    record.EvidenceRef,
				Actions:        dedupeStrings(normalizeStringList(grant.Actions)),
			})
		}
	}
	return out
}

// secretsActionsIncludeRead reports whether a resource-policy statement's
// actions authorize reading the secret value. AWS action patterns support
// `*` and `?` anywhere in the action token, so match the policy action
// pattern against each concrete secret-value read API before deciding
// whether to preserve the static grant for correlation.
func secretsActionsIncludeRead(actions []string) bool {
	readActions := []string{"secretsmanager:getsecretvalue", "secretsmanager:batchgetsecretvalue"}
	for _, action := range actions {
		trimmed := strings.ToLower(strings.TrimSpace(action))
		if trimmed == "" {
			continue
		}
		for _, read := range readActions {
			if awsActionPatternMatches(trimmed, read) {
				return true
			}
		}
	}
	return false
}

func awsActionPatternMatches(pattern string, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" || value == "" {
		return false
	}
	previous := make([]bool, len(value)+1)
	previous[0] = true
	for _, r := range pattern {
		current := make([]bool, len(value)+1)
		switch r {
		case '*':
			current[0] = previous[0]
			for i := 1; i <= len(value); i++ {
				current[i] = previous[i] || current[i-1]
			}
		case '?':
			for i := 1; i <= len(value); i++ {
				current[i] = previous[i-1]
			}
		default:
			for i := 1; i <= len(value); i++ {
				current[i] = previous[i-1] && rune(value[i-1]) == r
			}
		}
		previous = current
	}
	return previous[len(value)]
}

func awsSecretsKMSRuntimeAccessRecords(correlations []secretsaccess.Correlation) []AWSSecretsKMSRuntimeAccessRecord {
	out := make([]AWSSecretsKMSRuntimeAccessRecord, 0, len(correlations))
	for _, correlation := range correlations {
		out = append(out, AWSSecretsKMSRuntimeAccessRecord{
			CorrelationID:     correlation.CorrelationID,
			AccountID:         correlation.AccountID,
			Region:            correlation.Region,
			IdentityNodeID:    correlation.IdentityNodeID,
			PrincipalARN:      correlation.PrincipalARN,
			ResourceKind:      correlation.ResourceKind,
			ResourceARN:       correlation.ResourceARN,
			ResourceName:      correlation.ResourceName,
			ResourceNodeID:    awsSecretsKMSResourceNodeID(correlation.ResourceKind, correlation.ResourceARN),
			Status:            correlation.Status,
			Confidence:        correlation.Confidence,
			ObservedCount:     correlation.ObservedCount,
			ObservedEventIDs:  correlation.ObservedEventIDs,
			Actions:           correlation.Actions,
			SessionIDs:        correlation.SessionIDs,
			AgentID:           correlation.AgentID,
			AgentNodeID:       correlation.AgentNodeID,
			FirstObservedAt:   correlation.FirstObservedAt,
			LastObservedAt:    correlation.LastObservedAt,
			StaticSources:     correlation.StaticSources,
			StaticEffect:      correlation.StaticEffect,
			Conditional:       correlation.Conditional,
			CrossAccount:      correlation.CrossAccount,
			Caveats:           correlation.Caveats,
			EvidenceRef:       fmt.Sprintf("runtime-correlation://%s", correlation.CorrelationID),
			EvidenceRefs:      correlation.EvidenceRefs,
			NextAction:        awsSecretsKMSRuntimeAccessNextAction(correlation.Status, correlation.ResourceKind),
			RedactionBoundary: correlation.RedactionBoundary,
		})
	}
	return out
}

func awsSecretsKMSResourceNodeID(resourceKind string, resourceARN string) string {
	arn := strings.TrimSpace(resourceARN)
	if arn == "" {
		return ""
	}
	switch resourceKind {
	case secretsaccess.ResourceKindSecret:
		return "aws:resource:secrets-manager-secret:" + arn
	case secretsaccess.ResourceKindKMSKey:
		return "aws:resource:kms-key:" + arn
	default:
		return "aws:resource:" + normalizeName(firstNonEmptyAWSValue(resourceKind, "resource")) + ":" + arn
	}
}

func awsSecretsKMSRuntimeAccessNextAction(status string, resourceKind string) string {
	noun := "secret"
	if resourceKind == secretsaccess.ResourceKindKMSKey {
		noun = "key"
	}
	switch status {
	case secretsaccess.StatusConfirmed:
		return fmt.Sprintf("Confirm the observed %s access matches an expected workload path before relying on it for remediation.", noun)
	case secretsaccess.StatusObservedWithoutGrant:
		return fmt.Sprintf("Investigate observed %s access with no modeled grant — confirm IAM identity-policy authorization or treat as drift.", noun)
	case secretsaccess.StatusGrantedUnused:
		return fmt.Sprintf("Review the unused %s grant for least-privilege; confirm data-event coverage before removing it.", noun)
	default:
		return "Correlate runtime evidence with the static reachability graph."
	}
}

func filterAWSSecretsKMSRuntimeAccessRecords(records []AWSSecretsKMSRuntimeAccessRecord, request AWSSecretsKMSRuntimeAccessRequest) ([]AWSSecretsKMSRuntimeAccessRecord, map[string]string) {
	filters := map[string]string{
		"account_id":    strings.TrimSpace(request.AccountID),
		"region":        strings.TrimSpace(request.Region),
		"identity":      strings.TrimSpace(request.Identity),
		"agent_id":      strings.TrimSpace(request.AgentID),
		"resource":      strings.TrimSpace(request.Resource),
		"resource_kind": normalizeAWSRuntimeEventFilterToken(request.ResourceKind),
		"status":        normalizeAWSRuntimeEventFilterToken(request.Status),
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
	filtered := make([]AWSSecretsKMSRuntimeAccessRecord, 0, len(records))
	for _, record := range records {
		if filters["account_id"] != "" && filters["account_id"] != record.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], record.Region) {
			continue
		}
		if filters["resource_kind"] != "" && filters["resource_kind"] != normalizeAWSRuntimeEventFilterToken(record.ResourceKind) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(record.Status) {
			continue
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], record.IdentityNodeID, record.PrincipalARN) {
			continue
		}
		if filters["agent_id"] != "" && !awsRuntimeEventMatchesAny(filters["agent_id"], record.AgentID, record.AgentNodeID) {
			continue
		}
		if filters["resource"] != "" && !awsRuntimeEventMatchesAny(filters["resource"], record.ResourceARN, record.ResourceName, record.ResourceNodeID) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered, applied
}

func awsSecretsKMSRuntimeAccessRelationships(records []AWSSecretsKMSRuntimeAccessRecord) []AWSSecretsKMSRuntimeAccessRelationship {
	out := []AWSSecretsKMSRuntimeAccessRelationship{}
	for _, record := range records {
		if record.IdentityNodeID == "" || record.ResourceNodeID == "" {
			continue
		}
		edgeType := "runtime_access_correlation"
		switch record.Status {
		case secretsaccess.StatusConfirmed:
			edgeType = "confirmed_runtime_access"
		case secretsaccess.StatusObservedWithoutGrant:
			edgeType = "observed_runtime_access_without_grant"
		case secretsaccess.StatusGrantedUnused:
			edgeType = "unused_static_grant"
		}
		out = append(out, AWSSecretsKMSRuntimeAccessRelationship{
			Type:        edgeType,
			FromNodeID:  record.IdentityNodeID,
			ToNodeID:    record.ResourceNodeID,
			EvidenceRef: record.EvidenceRef,
		})
		if record.AgentNodeID != "" {
			out = append(out, AWSSecretsKMSRuntimeAccessRelationship{
				Type:        "agent_runtime_access_correlation",
				FromNodeID:  record.AgentNodeID,
				ToNodeID:    record.ResourceNodeID,
				EvidenceRef: record.EvidenceRef,
			})
		}
	}
	return out
}

func summarizeAWSSecretsKMSRuntimeAccess(correlation secretsaccess.Result, allRecords []AWSSecretsKMSRuntimeAccessRecord, filtered []AWSSecretsKMSRuntimeAccessRecord, relationships []AWSSecretsKMSRuntimeAccessRelationship) AWSSecretsKMSRuntimeAccessSummary {
	statusCounts := map[string]int{}
	for _, record := range allRecords {
		statusCounts[record.Status]++
	}
	return AWSSecretsKMSRuntimeAccessSummary{
		TotalCorrelations:         len(allRecords),
		FilteredCorrelations:      len(filtered),
		StatusCounts:              statusCounts,
		ConfirmedCount:            correlation.ConfirmedCount,
		ObservedWithoutGrantCount: correlation.ObservedWithoutGrant,
		GrantedUnusedCount:        correlation.GrantedUnusedCount,
		SecretCorrelationCount:    correlation.SecretCorrelationCount,
		KMSKeyCorrelationCount:    correlation.KMSKeyCorrelationCount,
		IdentityCount:             correlation.IdentityCount,
		ResourceCount:             correlation.ResourceCount,
		ObservedAccessCount:       correlation.ObservedAccessConsidered,
		StaticGrantCount:          correlation.StaticGrantsConsidered,
		RelationshipCount:         len(relationships),
	}
}

func summarizeAWSSecretsKMSRuntimeAccessStatus(sourceStatus string, filtered []AWSSecretsKMSRuntimeAccessRecord, diagnostics []AWSSecretsKMSRuntimeAccessDiagnostic) (string, float64) {
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

// worstAWSStatus reduces multiple source statuses to the most severe one.
func worstAWSStatus(a string, b string) string {
	rank := func(status string) int {
		switch status {
		case awsPlatformDependencyStatusBlocked:
			return 3
		case awsPlatformDependencyStatusDegraded:
			return 2
		case awsPlatformDependencyStatusReady, "":
			return 1
		default:
			return 2
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}
