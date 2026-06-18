package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/identrail/identrail/internal/runtime/cloudtrail"
	"github.com/identrail/identrail/internal/runtime/cloudtraildelivery"
)

// cloudTrailDeliveryAdapter wraps an
// internal/runtime/cloudtraildelivery ingester (S3 or EventBridge)
// behind the API-layer AWSCloudTrailRuntimeEventIngester contract so
// the runtime-events handler can fold delivery-channel results into
// the same AWSRuntimeEventResult envelope LookupEvents already uses.
type cloudTrailDeliveryAdapter struct {
	source DeliverySource
	s3     *cloudtraildelivery.S3Ingester
	eb     *cloudtraildelivery.EventBridgeIngester
}

// DeliverySource is an API-layer alias for the delivery channel
// the adapter is bound to.
type DeliverySource = cloudtraildelivery.DeliverySource

const (
	// DeliverySourceS3 selects the S3 trail log ingester.
	DeliverySourceS3 DeliverySource = cloudtraildelivery.DeliverySourceS3
	// DeliverySourceEventBridge selects the EventBridge (SQS-backed)
	// ingester.
	DeliverySourceEventBridge DeliverySource = cloudtraildelivery.DeliverySourceEventBridge
)

// NewCloudTrailS3DeliveryIngester wraps a configured S3 ingester.
// Production wiring constructs the ingester from the AWS connector's
// CloudTrail bucket configuration; tests pass an in-memory fake.
func NewCloudTrailS3DeliveryIngester(ingester *cloudtraildelivery.S3Ingester) AWSCloudTrailRuntimeEventIngester {
	if ingester == nil {
		return nil
	}
	return &cloudTrailDeliveryAdapter{source: DeliverySourceS3, s3: ingester}
}

// NewCloudTrailEventBridgeDeliveryIngester wraps a configured
// EventBridge ingester.
func NewCloudTrailEventBridgeDeliveryIngester(ingester *cloudtraildelivery.EventBridgeIngester) AWSCloudTrailRuntimeEventIngester {
	if ingester == nil {
		return nil
	}
	return &cloudTrailDeliveryAdapter{source: DeliverySourceEventBridge, eb: ingester}
}

// Ingest dispatches to the bound delivery channel and maps the
// engine's result into the same AWSCloudTrailIngestResult shape the
// LookupEvents adapter uses.
func (a *cloudTrailDeliveryAdapter) Ingest(ctx context.Context, request AWSCloudTrailIngestRequest) (AWSCloudTrailIngestResult, error) {
	deliveryRequest := cloudtraildelivery.IngestRequest{
		AccountID: request.AccountID,
		Region:    request.Region,
	}
	var (
		engineResult cloudtraildelivery.IngestResult
		err          error
	)
	switch a.source {
	case DeliverySourceS3:
		engineResult, err = a.s3.Ingest(ctx, deliveryRequest)
	case DeliverySourceEventBridge:
		engineResult, err = a.eb.Ingest(ctx, deliveryRequest)
	default:
		return AWSCloudTrailIngestResult{}, fmt.Errorf("cloudtraildelivery: unknown delivery source %q", a.source)
	}
	if err != nil {
		return AWSCloudTrailIngestResult{}, err
	}
	result := AWSCloudTrailIngestResult{
		Status:           engineResult.Status,
		FailureReasons:   append([]string{}, engineResult.FailureReasons...),
		RemediationHints: append([]string{}, engineResult.RemediationHints...),
		HistoryTruncated: engineResult.HistoryTruncated,
		Checkpoint:       engineResult.Checkpoint,
	}
	for _, ev := range engineResult.Events {
		record := runtimeEventRecordFromNormalized(ev, request.AccountID, request.Region)
		// Stamp the delivery source on the evidence category so
		// operators can tell which channel produced the record. The
		// LookupEvents path keeps `cloudtrail`; S3 and EventBridge
		// each get their own tag so the UI can group records by
		// delivery channel.
		record.EvidenceCategory = string(a.source) + "-delivery"
		result.Records = append(result.Records, record)
	}
	for _, diag := range engineResult.Diagnostics {
		result.Diagnostics = append(result.Diagnostics, AWSRuntimeEventDiagnostic{
			Collector:   cloudtraildelivery.CollectorName,
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

// normalizeDeliverySource maps the operator-supplied query value to a
// canonical token. Returns one of "", "lookup_events", "s3",
// "eventbridge", "all", or "" + an error sentinel for unknown values
// (the handler converts that to HTTP 400).
func normalizeDeliverySource(value string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "", "lookup_events", "lookup-events":
		return "lookup_events", nil
	case "s3":
		return "s3", nil
	case "eventbridge", "event_bridge", "event-bridge":
		return "eventbridge", nil
	case "all":
		return "all", nil
	default:
		return "", ErrInvalidAWSConnectionRequest
	}
}

// mergeDeliveryResults combines per-source IngestResults into a
// single union. Cross-channel dedupe is by EventID so the same
// CloudTrail event arriving on multiple channels surfaces only once.
// Diagnostics, coverage gaps, failure reasons, and remediation hints
// from every source are preserved.
func mergeDeliveryResults(results []AWSCloudTrailIngestResult) AWSCloudTrailIngestResult {
	merged := AWSCloudTrailIngestResult{Status: "ready"}
	seenEvents := map[string]struct{}{}
	hasRecords := false
	worstStatus := "ready"
	statusRank := map[string]int{"ready": 0, "degraded": 1, "blocked": 2}
	for _, r := range results {
		if statusRank[r.Status] > statusRank[worstStatus] {
			worstStatus = r.Status
		}
		for _, record := range r.Records {
			if _, dupe := seenEvents[record.EventID]; dupe {
				continue
			}
			seenEvents[record.EventID] = struct{}{}
			merged.Records = append(merged.Records, record)
			hasRecords = true
		}
		merged.Diagnostics = append(merged.Diagnostics, r.Diagnostics...)
		merged.CoverageGaps = append(merged.CoverageGaps, r.CoverageGaps...)
		merged.FailureReasons = append(merged.FailureReasons, r.FailureReasons...)
		merged.RemediationHints = append(merged.RemediationHints, r.RemediationHints...)
		if r.HistoryTruncated {
			merged.HistoryTruncated = true
		}
	}
	if worstStatus == "blocked" && hasRecords {
		merged.Status = "degraded"
	} else {
		merged.Status = worstStatus
	}
	return merged
}

// Reuse cloudtrail.CollectorName so the API surface keeps a single
// authoritative string identifier for the LookupEvents engine, and
// have the unused cloudtrail import here remain stable across
// refactors. Touching the import explicitly avoids a goimports prune.
var _ = cloudtrail.CollectorName
