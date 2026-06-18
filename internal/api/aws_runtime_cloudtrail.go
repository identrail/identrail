package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/runtime/cloudtrail"
)

// AWSCloudTrailIngestRequest is the API-layer request shape passed to
// AWSCloudTrailRuntimeEventIngester. The fields mirror the runtime
// event contract scope so the factory can apply per-tenant budgets and
// per-account scoping without leaking the engine's types into the API
// surface.
type AWSCloudTrailIngestRequest struct {
	AccountID         string
	Region            string
	LookbackWindow    time.Duration
	EventSourceFilter string
	MutationOnly      bool
	// Filters are API-layer runtime filters that delivery ingesters can
	// apply before returning events. Keys mirror AWSRuntimeEventRequest
	// tokens and prevent filtered reads from consuming evidence that the
	// caller excluded.
	Filters map[string]string
}

// AWSCloudTrailIngestResult is the API-layer projection of one
// CloudTrail ingestion run. Records are already shaped as
// AWSRuntimeEventRecord so the API handler can drop them into the
// runtime contract with no further normalization.
type AWSCloudTrailIngestResult struct {
	Records          []AWSRuntimeEventRecord
	Diagnostics      []AWSRuntimeEventDiagnostic
	CoverageGaps     []AWSRuntimeEventCoverageGap
	Status           string
	FailureReasons   []string
	RemediationHints []string
	HistoryTruncated bool
	// Checkpoint is the delivery engine's resume marker. For S3 this
	// is the last completely processed object key; callers should
	// persist it and pass it back in the next IngestRequest so the
	// next run resumes from where this one stopped.
	Checkpoint string
}

// cloudTrailIngesterAdapter wraps an internal/runtime/cloudtrail
// Ingester and turns it into the api.AWSCloudTrailRuntimeEventIngester
// contract used by Service. Production wiring (e.g. cmd/server) uses
// NewCloudTrailRuntimeEventIngester to build one.
type cloudTrailIngesterAdapter struct {
	ingester *cloudtrail.Ingester
}

// NewCloudTrailRuntimeEventIngester builds an api-layer ingester from
// a configured engine instance. The factory is the seam the runtime
// uses to bind one ingester per AWS connector.
func NewCloudTrailRuntimeEventIngester(ingester *cloudtrail.Ingester) AWSCloudTrailRuntimeEventIngester {
	if ingester == nil {
		return nil
	}
	return &cloudTrailIngesterAdapter{ingester: ingester}
}

// Ingest delegates to the engine and maps NormalizedEvent →
// AWSRuntimeEventRecord. The mapping is intentionally
// straight-through: every field on the runtime contract has a
// well-defined source on the normalized event so the API stays the
// single source of truth for the contract shape.
func (a *cloudTrailIngesterAdapter) Ingest(ctx context.Context, request AWSCloudTrailIngestRequest) (AWSCloudTrailIngestResult, error) {
	engineRequest := cloudtrail.IngestRequest{
		AccountID:         request.AccountID,
		Region:            request.Region,
		LookbackWindow:    request.LookbackWindow,
		EventSourceFilter: request.EventSourceFilter,
		MutationOnly:      request.MutationOnly,
	}
	engineResult, err := a.ingester.Ingest(ctx, engineRequest)
	if err != nil {
		return AWSCloudTrailIngestResult{}, err
	}
	result := AWSCloudTrailIngestResult{
		Status:           engineResult.Status,
		FailureReasons:   append([]string{}, engineResult.FailureReasons...),
		RemediationHints: append([]string{}, engineResult.RemediationHints...),
		HistoryTruncated: engineResult.HistoryTruncated,
	}
	for _, ev := range engineResult.Events {
		result.Records = append(result.Records, runtimeEventRecordFromNormalized(ev, request.AccountID, request.Region))
	}
	for _, diag := range engineResult.Diagnostics {
		result.Diagnostics = append(result.Diagnostics, AWSRuntimeEventDiagnostic{
			Collector:   cloudtrail.CollectorName,
			SourceID:    diag.SourceID,
			Code:        diag.Code,
			Message:     diag.Message,
			Remediation: diag.Remediation,
			Retryable:   diag.Retryable,
		})
	}
	for _, gap := range engineResult.CoverageGaps {
		result.CoverageGaps = append(result.CoverageGaps, AWSRuntimeEventCoverageGap{
			Capability:  gap.Capability,
			Status:      gap.Status,
			Reason:      gap.Reason,
			Remediation: gap.Remediation,
		})
	}
	return result, nil
}

func runtimeEventRecordFromNormalized(ev cloudtrail.NormalizedEvent, fallbackAccount string, fallbackRegion string) AWSRuntimeEventRecord {
	accountID := firstNonEmptyAWSValue(ev.AccountID, fallbackAccount)
	region := firstNonEmptyAWSValue(ev.Region, fallbackRegion)
	resourceName := ev.TargetResourceName
	if resourceName == "" {
		resourceName = displayNameFromARN(ev.TargetResourceARN)
	}
	// For assumed-role events CloudTrail's ActorPrincipalARN is the STS
	// session ARN (arn:aws:sts::...:assumed-role/<role>/<session>),
	// whereas the discovered IAM identity graph keys roles by the
	// issuer ARN (arn:aws:iam::...:role/<role>). Building the node ID
	// from the STS ARN would create an orphan node that never joins
	// back to the role discovered by the IAM collector, so runtime
	// evidence would never link to the role's other relationships.
	// Prefer the session issuer when present and only fall back to the
	// principal ARN for non-assumed-role events (root, IAM user,
	// federated user, AWS service).
	identityARN := strings.TrimSpace(ev.SessionIssuerARN)
	if identityARN == "" {
		identityARN = ev.ActorPrincipalARN
	}
	sessionNodeID := awsRuntimeSessionNodeID(accountID, region, ev)
	originalActorARN := ""
	if strings.TrimSpace(ev.LineageStatus) != "" {
		originalActorARN = firstNonEmptyAWSValue(ev.OriginalActorARN, ev.ActorPrincipalARN)
	}
	chainedFromARN := strings.TrimSpace(ev.ChainedFromARN)
	return AWSRuntimeEventRecord{
		EventID:             ev.EventID,
		AccountID:           accountID,
		Region:              region,
		EventType:           ev.EventType,
		EventSource:         ev.EventSource,
		EventName:           ev.EventName,
		Action:              ev.Action,
		ActorPrincipalARN:   ev.ActorPrincipalARN,
		ActorPrincipalType:  firstNonEmptyAWSValue(ev.ActorPrincipalType, "assumed_role"),
		ActorIdentityNodeID: awsIdentityNodeIDForAPI(identityARN),
		Session: AWSRuntimeEventSession{
			SessionID:               ev.SessionID,
			SessionNodeID:           sessionNodeID,
			PrincipalARN:            ev.ActorPrincipalARN,
			PrincipalType:           firstNonEmptyAWSValue(ev.ActorPrincipalType, "assumed_role"),
			AssumedRoleARN:          ev.AssumedRoleARN,
			SessionIssuerARN:        ev.SessionIssuerARN,
			SourceIdentity:          ev.SourceIdentity,
			RoleSessionName:         ev.RoleSessionName,
			SessionTagKeys:          append([]string{}, ev.SessionTagKeys...),
			TransitiveTagKeys:       append([]string{}, ev.TransitiveTagKeys...),
			OriginalActorARN:        originalActorARN,
			OriginalActorNodeID:     awsIdentityNodeIDForAPI(originalActorARN),
			ChainedFromPrincipalARN: chainedFromARN,
			ChainedFromNodeID:       awsIdentityNodeIDForAPI(chainedFromARN),
			LineageStatus:           ev.LineageStatus,
			LineageReason:           ev.LineageReason,
			SourceIPAddress:         ev.SourceIPAddress,
			UserAgent:               ev.UserAgent,
			StartedAt:               ev.SessionStartedAt,
			ExpiresAt:               ev.SessionExpiresAt,
		},
		TargetResourceARN:  ev.TargetResourceARN,
		TargetResourceType: ev.TargetResourceType,
		TargetResourceName: resourceName,
		ResourceNodeID:     awsRuntimeEventResourceNodeID(ev.TargetResourceARN, ev.TargetResourceType),
		AgentID:            ev.AgentID,
		AgentNodeID:        agentNodeIDForLiveEvent(ev, accountID, region),
		Owner:              ev.Owner,
		EvidenceCategory:   ev.EvidenceCategory,
		EvidenceRef:        fmt.Sprintf("runtime-evidence://%s/%s/%s", accountID, region, ev.EventID),
		Confidence:         ev.Confidence,
		ObservedAt:         ev.ObservedAt,
		CollectedAt:        ev.CollectedAt,
		Status:             ev.Status,
		NextAction:         awsRuntimeEventNextAction(ev.EventType),
		RedactionBoundary:  ev.RedactionBoundary,
	}
}

func awsRuntimeSessionNodeID(accountID string, region string, ev cloudtrail.NormalizedEvent) string {
	if strings.TrimSpace(ev.SessionID) == "" && strings.TrimSpace(ev.LineageStatus) == "" {
		return ""
	}
	token := awsRuntimeSessionToken(ev)
	if strings.TrimSpace(token) == "" {
		return ""
	}
	return "aws:runtime-session:" + sanitizeCredentialReferenceToken(firstNonEmptyAWSValue(accountID, ev.AccountID, "unknown-account")) + ":" + sanitizeCredentialReferenceToken(firstNonEmptyAWSValue(region, ev.Region, "unknown-region")) + ":" + sanitizeCredentialReferenceToken(token)
}

func awsRuntimeSessionToken(ev cloudtrail.NormalizedEvent) string {
	if isSTSAssumeRoleRuntimeEvent(ev) {
		if token := assumedRoleSessionToken(ev.AssumedRoleARN, ev.RoleSessionName); token != "" {
			return token
		}
	}
	if isAssumedRoleRuntimeEvent(ev) {
		if token := assumedRoleSessionToken(firstNonEmptyAWSValue(ev.AssumedRoleARN, ev.SessionIssuerARN), ev.RoleSessionName); token != "" {
			return token
		}
	}
	return firstNonEmptyAWSValue(ev.ActorPrincipalARN, ev.SessionID, ev.RoleSessionName)
}

func assumedRoleSessionToken(roleARN string, roleSessionName string) string {
	roleARN = strings.TrimSpace(roleARN)
	roleSessionName = strings.TrimSpace(roleSessionName)
	if roleARN == "" || roleSessionName == "" {
		return ""
	}
	return roleARN + "/" + roleSessionName
}

func isSTSAssumeRoleRuntimeEvent(ev cloudtrail.NormalizedEvent) bool {
	return strings.EqualFold(strings.TrimSpace(ev.EventSource), "sts.amazonaws.com") && strings.HasPrefix(strings.TrimSpace(ev.EventName), "AssumeRole")
}

func isAssumedRoleRuntimeEvent(ev cloudtrail.NormalizedEvent) bool {
	return strings.EqualFold(strings.TrimSpace(ev.ActorPrincipalType), "assumed_role") || strings.TrimSpace(ev.SessionIssuerARN) != "" || strings.TrimSpace(ev.AssumedRoleARN) != ""
}

// agentNodeIDForLiveEvent composes the canonical agent node id used
// across the AI-agent inventory and the AWS provider normalizer. The
// engine only emits AgentID + AgentType; the bridge calls
// awsAIAgentNodeID so the runtime evidence graph keys agent nodes on
// the same shape (`aws:agent:<account>:<region>:<type>/<id>`) as the
// rest of the AWS graph and the agent inventory rows the operator
// already sees in the UI.
func agentNodeIDForLiveEvent(ev cloudtrail.NormalizedEvent, accountID string, region string) string {
	if strings.TrimSpace(ev.AgentID) == "" {
		return ""
	}
	// AgentCore endpoint ARNs carry the runtime version / endpoint
	// alias in the third path segment. The AI-agent inventory and
	// provider normalizer pass that same value into awsAIAgentNodeID
	// as RuntimeVersion, and the helper appends it to the node id
	// (`...:agentcore_runtime/<runtime>/<version>`). Pass it through
	// for live events too so `agent_invoked_runtime_action` edges
	// and `agent_id` filters keyed on inventory nodes match the
	// runtime evidence record. Bedrock-agent ARNs have no version
	// segment, so AgentRuntimeVersion stays empty and the node id
	// is unaffected.
	return awsAIAgentNodeID(accountID, region, ev.AgentType, ev.AgentID, ev.AgentRuntimeVersion)
}

func displayNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	if slash := strings.LastIndex(trimmed, "/"); slash >= 0 && slash < len(trimmed)-1 {
		return trimmed[slash+1:]
	}
	if colon := strings.LastIndex(trimmed, ":"); colon >= 0 && colon < len(trimmed)-1 {
		return trimmed[colon+1:]
	}
	return trimmed
}
