package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/runtime/awssignals"
)

type AWSRuntimeSignalIngestRequest struct {
	AccountID   string
	Region      string
	CollectedAt time.Time
}

type AWSRuntimeSignalIngestResult struct {
	Records          []AWSRuntimeEventRecord
	Diagnostics      []AWSRuntimeEventDiagnostic
	CoverageGaps     []AWSRuntimeEventCoverageGap
	Status           string
	FailureReasons   []string
	RemediationHints []string
}

type AWSRuntimeSignalIngester interface {
	Ingest(context.Context, AWSRuntimeSignalIngestRequest) (AWSRuntimeSignalIngestResult, error)
}

type runtimeSignalIngesterAdapter struct {
	ingester *awssignals.Ingester
}

func NewAWSRuntimeSignalIngester(ingester *awssignals.Ingester) AWSRuntimeSignalIngester {
	if ingester == nil {
		return nil
	}
	return &runtimeSignalIngesterAdapter{ingester: ingester}
}

func (a *runtimeSignalIngesterAdapter) Ingest(ctx context.Context, request AWSRuntimeSignalIngestRequest) (AWSRuntimeSignalIngestResult, error) {
	engineResult, err := a.ingester.Ingest(ctx, awssignals.IngestRequest{
		AccountID:   request.AccountID,
		Region:      request.Region,
		CollectedAt: request.CollectedAt,
	})
	if err != nil {
		return AWSRuntimeSignalIngestResult{}, err
	}
	result := AWSRuntimeSignalIngestResult{
		Status:           engineResult.Status,
		FailureReasons:   append([]string{}, engineResult.FailureReasons...),
		RemediationHints: append([]string{}, engineResult.RemediationHints...),
	}
	for _, signal := range engineResult.Signals {
		result.Records = append(result.Records, runtimeEventRecordFromSignal(signal, request.AccountID, request.Region))
	}
	for _, diag := range engineResult.Diagnostics {
		result.Diagnostics = append(result.Diagnostics, AWSRuntimeEventDiagnostic{
			Collector:   awssignals.CollectorName,
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

func runtimeEventRecordFromSignal(signal awssignals.Signal, fallbackAccount string, fallbackRegion string) AWSRuntimeEventRecord {
	accountID := firstNonEmptyAWSValue(signal.AccountID, fallbackAccount)
	region := firstNonEmptyAWSValue(signal.Region, fallbackRegion, "global")
	eventType := normalizeSignalCategory(signal.Category)
	actorARN := strings.TrimSpace(signal.ActorPrincipalARN)
	if actorARN == "" {
		actorARN = "aws:unknown-principal"
	}
	resourceName := firstNonEmptyAWSValue(signal.TargetResourceName, displayNameFromARN(signal.TargetResourceARN), signal.TargetResourceType)
	status := firstNonEmptyAWSValue(signal.Status, "observed")
	confidence := signal.Confidence
	if confidence <= 0 {
		confidence = 0.75
	}
	observedAt := signal.ObservedAt
	if observedAt.IsZero() {
		observedAt = signal.CollectedAt
	}
	collectedAt := signal.CollectedAt
	if collectedAt.IsZero() {
		collectedAt = observedAt
	}
	return AWSRuntimeEventRecord{
		EventID:             firstNonEmptyAWSValue(signal.EventID, fmt.Sprintf("%s:%s", eventType, signal.TargetResourceARN)),
		AccountID:           accountID,
		Region:              region,
		EventType:           eventType,
		EventSource:         firstNonEmptyAWSValue(signal.EventSource, "aws-signals"),
		EventName:           firstNonEmptyAWSValue(signal.EventName, eventType),
		Action:              firstNonEmptyAWSValue(signal.Action, eventType),
		ActorPrincipalARN:   actorARN,
		ActorPrincipalType:  firstNonEmptyAWSValue(signal.ActorPrincipalType, "aws_principal"),
		ActorIdentityNodeID: awsIdentityNodeIDForAPI(actorARN),
		Session: AWSRuntimeEventSession{
			SessionID:     "",
			PrincipalARN:  actorARN,
			PrincipalType: firstNonEmptyAWSValue(signal.ActorPrincipalType, "aws_principal"),
		},
		TargetResourceARN:  signal.TargetResourceARN,
		TargetResourceType: signal.TargetResourceType,
		TargetResourceName: resourceName,
		ResourceNodeID:     awsRuntimeEventResourceNodeID(signal.TargetResourceARN, signal.TargetResourceType),
		SignalCategory:     eventType,
		SignalScope:        signal.Scope,
		AnalyzerARN:        signal.AnalyzerARN,
		SignalStaleAt:      signal.StaleAt,
		Owner:              signalOwner(eventType, status),
		EvidenceCategory:   eventType,
		EvidenceRef:        fmt.Sprintf("runtime-evidence://%s/%s/%s", accountID, region, firstNonEmptyAWSValue(signal.EventID, eventType)),
		Confidence:         confidence,
		ObservedAt:         observedAt,
		CollectedAt:        collectedAt,
		Status:             status,
		NextAction:         awsRuntimeEventNextAction(eventType),
		RedactionBoundary:  awssignals.RedactionBoundary,
	}
}

func normalizeSignalCategory(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "iam-last-used", "iam_last_used":
		return "iam-last-used"
	case "access-analyzer", "access_analyzer":
		return "access-analyzer"
	default:
		return normalizeAWSRuntimeEventFilterToken(category)
	}
}

func signalOwner(eventType string, status string) string {
	if eventType == "access-analyzer" {
		return "security"
	}
	if status == "stale" {
		return "platform"
	}
	return "security"
}
