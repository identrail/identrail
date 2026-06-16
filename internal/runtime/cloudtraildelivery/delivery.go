// Package cloudtraildelivery implements bounded, metadata-only
// ingestion of AWS CloudTrail records delivered through two channels
// that the existing internal/runtime/cloudtrail LookupEvents engine
// does not cover:
//
//   - S3 trail delivery. CloudTrail trails write gzip-compressed JSON
//     log files to a configured S3 bucket. This ingester lists object
//     keys newer than the operator-supplied checkpoint, downloads each
//     log file, parses the `Records[]` array, dedupes by EventId, and
//     hands the resulting metadata-only events to the cloudtrail
//     engine's NormalizeEvent for translation into the shared runtime
//     contract.
//   - EventBridge delivery. CloudTrail can deliver every event in
//     near-real-time to EventBridge; the standard fan-out is to put
//     events on an SQS queue. This ingester pulls a bounded batch of
//     messages, parses the EventBridge envelope, and normalizes the
//     CloudTrail `detail` payload. Messages whose events are
//     successfully ingested are deleted from the queue so they are not
//     re-delivered; messages that fail normalization are left in the
//     queue and surface as partial-failure diagnostics so the
//     consumer's redrive policy can apply.
//
// Both ingesters share the same IngestRequest/IngestResult shape and
// produce slices of cloudtrail.NormalizedEvent so the API layer can
// fold the delivery channels into the same AWSRuntimeEventResult
// envelope that the LookupEvents path uses. Cross-channel dedupe by
// EventId is the API layer's responsibility (a single CloudTrail
// event can arrive via LookupEvents AND S3 AND EventBridge in the
// same run).
//
// Safety boundaries are inherited from the cloudtrail engine: the
// ingesters never read, log, or persist request parameters, response
// elements, secret values, decrypted plaintext, object bodies, or any
// customer payload from a CloudTrail record. Only the metadata
// allow-list defined by cloudtrail.NormalizeEvent crosses the
// boundary. Bounded budgets (MaxFiles, MaxEvents, MaxMessages, file-
// size limit) cap one ingestion run so a misbehaving trail or queue
// cannot exhaust the worker.
package cloudtraildelivery

import (
	"strings"
	"time"

	"github.com/identrail/identrail/internal/runtime/cloudtrail"
)

// DeliverySource identifies which CloudTrail delivery channel
// produced a record. The API layer uses this both for source-scoped
// filtering and so operators can attribute a record to its origin in
// the response.
type DeliverySource string

const (
	// DeliverySourceS3 indicates the record was extracted from a
	// CloudTrail trail's S3 log object.
	DeliverySourceS3 DeliverySource = "s3"

	// DeliverySourceEventBridge indicates the record was consumed from
	// an EventBridge target (typically SQS).
	DeliverySourceEventBridge DeliverySource = "eventbridge"
)

// CollectorName tags every diagnostic emitted by the delivery
// ingesters so downstream callers can scope diagnostics by source.
const CollectorName = "aws_cloudtrail_delivery"

// Bounded budget defaults. Operators can override per-run; the
// defaults are sized so one tick of a 5-minute worker comfortably
// stays inside the budget on a steady-state trail.
const (
	DefaultMaxFiles            = 50
	DefaultMaxEvents           = 1000
	DefaultMaxMessages         = 100
	DefaultMaxFileBytes        = int64(32 << 20) // 32 MiB per gzip log file
	DefaultLookbackWindow      = 30 * time.Minute
	DefaultMaxThrottleRetries  = 4
	DefaultThrottleBackoff     = 200 * time.Millisecond
	DefaultSQSVisibilityBuffer = 30 * time.Second
)

// IngestRequest configures one bounded ingestion run for either
// delivery channel.
type IngestRequest struct {
	AccountID string
	Region    string
	// Checkpoint is the per-channel resume marker. For S3 it is the
	// last completely processed S3 object key, passed to ListObjectsV2
	// as StartAfter on the next run. For EventBridge/SQS it is unused
	// — the queue itself is the checkpoint, and the ingester deletes
	// successfully-processed messages so they are not re-delivered.
	Checkpoint string
	// LookbackWindow caps how far back the S3 ingester scans for new
	// trail files when no Checkpoint is supplied. Defaults to
	// DefaultLookbackWindow.
	LookbackWindow time.Duration
	// MaxFiles caps the number of S3 log objects one S3 ingestion
	// run downloads. Defaults to DefaultMaxFiles.
	MaxFiles int
	// MaxMessages caps the number of SQS messages one EventBridge
	// ingestion run consumes. Defaults to DefaultMaxMessages.
	MaxMessages int
	// MaxEvents caps the total normalized events one ingestion run
	// emits across all files / messages. Defaults to
	// DefaultMaxEvents.
	MaxEvents int
	// MaxFileBytes caps each S3 log object's decompressed size.
	// Defaults to DefaultMaxFileBytes.
	MaxFileBytes int64
	// MaxThrottleRetries caps per-request retries when the
	// underlying SDK returns a throttling error. Defaults to
	// DefaultMaxThrottleRetries.
	MaxThrottleRetries int
	// ThrottleBackoff is the base linear backoff between retries.
	ThrottleBackoff time.Duration
}

// IngestResult is the bounded outcome of one ingestion run.
type IngestResult struct {
	Source           DeliverySource
	Events           []cloudtrail.NormalizedEvent
	Diagnostics      []cloudtrail.Diagnostic
	CoverageGaps     []cloudtrail.CoverageGap
	Status           string
	FailureReasons   []string
	RemediationHints []string
	// Checkpoint is the new resume marker the caller should persist
	// for the next run. For S3 this is the last completely processed
	// object key; for EventBridge the field is empty because the queue
	// is the implicit checkpoint.
	Checkpoint string
	// FilesProcessed (S3) and MessagesProcessed (EventBridge) let the
	// API layer attach observability metadata to the response.
	FilesProcessed    int
	MessagesProcessed int
	EventsConsidered  int
	// HistoryTruncated is true when the run stopped at the bounded
	// budget with more files / messages still available.
	HistoryTruncated bool
}

func (r IngestRequest) withDefaults() IngestRequest {
	if r.LookbackWindow <= 0 {
		r.LookbackWindow = DefaultLookbackWindow
	}
	if r.MaxFiles <= 0 {
		r.MaxFiles = DefaultMaxFiles
	}
	if r.MaxMessages <= 0 {
		r.MaxMessages = DefaultMaxMessages
	}
	if r.MaxEvents <= 0 {
		r.MaxEvents = DefaultMaxEvents
	}
	if r.MaxFileBytes <= 0 {
		r.MaxFileBytes = DefaultMaxFileBytes
	}
	if r.MaxThrottleRetries < 0 {
		r.MaxThrottleRetries = 0
	}
	if r.MaxThrottleRetries == 0 {
		r.MaxThrottleRetries = DefaultMaxThrottleRetries
	}
	if r.ThrottleBackoff <= 0 {
		r.ThrottleBackoff = DefaultThrottleBackoff
	}
	return r
}

// permissionDeniedCodes enumerates the AWS error codes the delivery
// ingesters treat as authoritative permission-denied signals. The
// check is case-insensitive and also matches the code embedded in an
// unwrapped error string. Mirrors the cloudtrail engine.
var permissionDeniedCodes = []string{
	"AccessDeniedException",
	"AccessDenied",
	"UnauthorizedOperation",
	"InvalidClientTokenId",
}

// throttleCodes are the AWS error codes the ingesters treat as
// throttling. Mirrors the cloudtrail engine list plus S3's SlowDown.
var throttleCodes = []string{
	"ThrottlingException",
	"Throttling",
	"RequestLimitExceeded",
	"TooManyRequestsException",
	"SlowDown",
}

// transientAuthCodes are credential-freshness signals. They degrade
// the response but never collapse it to blocked.
var transientAuthCodes = []string{
	"ExpiredToken",
	"ExpiredTokenException",
	"TokenRefreshRequired",
}

func isPermissionDenied(err error) bool { return errorMatchesAny(err, permissionDeniedCodes) }
func isThrottling(err error) bool       { return errorMatchesAny(err, throttleCodes) }
func isTransientAuth(err error) bool    { return errorMatchesAny(err, transientAuthCodes) }
func isRetryable(err error) bool        { return isThrottling(err) || isTransientAuth(err) }

func errorMatchesAny(err error, codes []string) bool {
	if err == nil {
		return false
	}
	type codeNamer interface{ ErrorCode() string }
	if c, ok := err.(codeNamer); ok {
		got := c.ErrorCode()
		for _, code := range codes {
			if strings.EqualFold(got, code) {
				return true
			}
		}
	}
	msg := strings.ToLower(err.Error())
	for _, code := range codes {
		if strings.Contains(msg, strings.ToLower(code)) {
			return true
		}
	}
	return false
}

func diagnosticCodeFor(err error) string {
	if isPermissionDenied(err) {
		return "permission_denied"
	}
	if isThrottling(err) {
		return "cloudtrail_delivery_throttled"
	}
	if isTransientAuth(err) {
		return "cloudtrail_delivery_credentials_expired"
	}
	return "cloudtrail_delivery_failed"
}

// CloudTrailLogFile is the JSON envelope CloudTrail writes to S3 and
// publishes through EventBridge. The S3 file is `{ "Records": [...] }`
// containing N events; an EventBridge SQS message contains one
// envelope whose `detail` is a single CloudTrail record (S3 and
// EventBridge serialize the same record shape, only the envelope
// differs).
type CloudTrailLogFile struct {
	Records []CloudTrailRecord `json:"Records"`
}

// CloudTrailRecord is the metadata-only projection of one CloudTrail
// record. Field names mirror the documented CloudTrail event JSON.
// Critically, `requestParameters` and `responseElements` are NOT
// represented here — the ingesters never decode them, and the engine
// re-uses cloudtrail.NormalizeEvent's allow-listed extraction over
// the raw envelope string for any fields it needs from `userIdentity`
// / `sessionContext`.
type CloudTrailRecord struct {
	EventVersion     string           `json:"eventVersion,omitempty"`
	EventID          string           `json:"eventID,omitempty"`
	EventName        string           `json:"eventName,omitempty"`
	EventSource      string           `json:"eventSource,omitempty"`
	EventTime        string           `json:"eventTime,omitempty"`
	AWSRegion        string           `json:"awsRegion,omitempty"`
	RecipientAccount string           `json:"recipientAccountId,omitempty"`
	ReadOnly         any              `json:"readOnly,omitempty"`
	UserIdentity     map[string]any   `json:"userIdentity,omitempty"`
	Resources        []CloudTrailRsrc `json:"resources,omitempty"`
	SourceIPAddress  string           `json:"sourceIPAddress,omitempty"`
	UserAgent        string           `json:"userAgent,omitempty"`
	AdditionalRaw    map[string]any   `json:"-"`
}

// CloudTrailRsrc mirrors the per-record resource subobject.
type CloudTrailRsrc struct {
	ResourceType string `json:"type,omitempty"`
	ResourceName string `json:"ARN,omitempty"`
	AccountID    string `json:"accountId,omitempty"`
}

// toCloudTrailEvent converts a CloudTrail record into the
// cloudtrail.Event shape the engine's NormalizeEvent consumes. The
// raw record JSON is serialized back into the Event.RawEvent slot so
// the engine's allow-listed metadata extraction can pull
// sessionContext / userIdentity tokens the lightweight projection
// above does not enumerate.
func (r CloudTrailRecord) toCloudTrailEvent(rawJSON string) cloudtrail.Event {
	resources := make([]cloudtrail.EventResource, 0, len(r.Resources))
	for _, rsrc := range r.Resources {
		resources = append(resources, cloudtrail.EventResource{
			ResourceType: strings.TrimSpace(rsrc.ResourceType),
			ResourceName: strings.TrimSpace(rsrc.ResourceName),
		})
	}
	event := cloudtrail.Event{
		EventID:     strings.TrimSpace(r.EventID),
		EventName:   strings.TrimSpace(r.EventName),
		EventSource: strings.TrimSpace(r.EventSource),
		ReadOnly:    readOnlyString(r.ReadOnly),
		Username:    pickUsername(r.UserIdentity),
		AccessKeyID: pickAccessKeyID(r.UserIdentity),
		Resources:   resources,
		RawEvent:    rawJSON,
	}
	if r.EventTime != "" {
		if t, err := parseEventTime(r.EventTime); err == nil {
			event.EventTime = t
		}
	}
	return event
}

func readOnlyString(value any) string {
	switch v := value.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}

func pickUsername(identity map[string]any) string {
	if identity == nil {
		return ""
	}
	if v, ok := identity["arn"].(string); ok {
		return strings.TrimSpace(v)
	}
	if v, ok := identity["userName"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func pickAccessKeyID(identity map[string]any) string {
	if identity == nil {
		return ""
	}
	if v, ok := identity["accessKeyId"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// parseEventTime accepts the CloudTrail-documented basic ISO-8601
// layout, the dashed RFC3339 / RFC3339Nano forms, and the plain
// `2006-01-02T15:04:05Z` layout. Mirrors cloudtrail.parseSessionTime.
func parseEventTime(value string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"20060102T150405Z",
		"20060102T150405.000Z",
	} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errUnrecognizedEventTime
}

var errUnrecognizedEventTime = newConstError("unrecognized CloudTrail eventTime")

type constError string

func (e constError) Error() string { return string(e) }

func newConstError(msg string) error { return constError(msg) }
