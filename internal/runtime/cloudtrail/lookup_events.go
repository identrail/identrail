// Package cloudtrail implements bounded, metadata-only ingestion of AWS
// CloudTrail LookupEvents records into the runtime event contract defined
// in internal/api. It is deliberately decoupled from the AWS SDK: the
// public surface depends only on a narrow LookupEventsAPI seam so unit
// tests can drive every pagination, throttling, permission-denied, and
// partial-failure branch without network access or AWS credentials.
//
// Coverage scope: CloudTrail's LookupEvents API only indexes management
// events (and Insights events when explicitly requested). Data events —
// notably S3 GetObject, Lambda Invoke, Bedrock Agent / AgentCore tool
// invocations, and DynamoDB item-level reads — are not searchable
// through LookupEvents and require a separate CloudTrail trail with
// data-event selectors (or CloudTrail Lake). The normalizer keeps the
// classification logic for those event types so the same engine can
// fold a data-events source in once it is wired, but operators must
// not interpret an empty data-event slice from this ingester as
// "the activity did not happen". See docs/aws-runtime-events.md for the
// per-event-type coverage matrix.
//
// Safety boundaries:
//   - Metadata only. The ingester never reads, logs, or persists
//     userIdentity payloads, request parameters, response elements,
//     secret values, decrypted plaintext, object bodies, or any other
//     customer payload from CloudTrailEvent JSON. Only metadata-only
//     fields whose names are listed in payloadAllowedKeys cross the
//     boundary, and any failure to extract one of those fields is treated
//     as missing — not as a normalization failure.
//   - Bounded budgets. MaxPages, MaxEvents, MaxThrottleRetries, and the
//     LookbackWindow are enforced in the ingester loop so a hostile or
//     misbehaving trail cannot exhaust the worker.
package cloudtrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LookupEventsAPI is the narrow seam every CloudTrail backend implements.
// The SDK adapter in sdk_lookup_events.go wraps cloudtrail.Client; tests
// use a fake to exercise the ingester deterministically.
type LookupEventsAPI interface {
	LookupEvents(ctx context.Context, input LookupEventsInput) (LookupEventsPage, error)
}

// LookupEventsInput is a CloudTrail LookupEvents request, expressed
// independently of the SDK so the ingester layer never imports the SDK
// types.
type LookupEventsInput struct {
	StartTime  time.Time
	EndTime    time.Time
	NextToken  string
	MaxResults int32
	// Attributes is a single attribute key/value pair — CloudTrail
	// permits exactly one — used to scope a focused lookup, e.g.
	// {Key: "ReadOnly", Value: "false"} for mutation events.
	Attributes LookupAttribute
}

// LookupAttribute carries the optional single CloudTrail lookup
// attribute. Both fields are empty when no attribute is set.
type LookupAttribute struct {
	Key   string
	Value string
}

// LookupEventsPage is one page of CloudTrail LookupEvents.
type LookupEventsPage struct {
	Events    []Event
	NextToken string
}

// Event is the metadata-only projection of a CloudTrail LookupEvents
// item we are willing to ingest. The SDK adapter performs the SDK
// → Event mapping so the ingester sees only payload-safe fields.
type Event struct {
	EventID     string
	EventName   string
	EventSource string
	EventTime   time.Time
	ReadOnly    string
	AccessKeyID string
	Username    string
	Resources   []EventResource
	// RawEvent is the unparsed CloudTrailEvent JSON string. The
	// ingester uses it only to pull a small allow-listed set of
	// metadata fields (region, sourceIPAddress, userAgent, recipient
	// account, the userIdentity arn/type/principalId and session
	// context). It is never logged or persisted.
	RawEvent string
}

// EventResource mirrors the CloudTrail Resource subobject.
type EventResource struct {
	ResourceType string
	ResourceName string
}

// IngestRequest configures one bounded ingestion run.
type IngestRequest struct {
	AccountID string
	Region    string
	// LookbackWindow is the wall-clock window of CloudTrail history to
	// scan. Defaults to DefaultLookbackWindow if zero. CloudTrail
	// retains LookupEvents history for 90 days, so anything beyond
	// that is silently clamped.
	LookbackWindow time.Duration
	// EventSourceFilter, when non-empty, scopes ingestion to one
	// CloudTrail event source (e.g. "kms.amazonaws.com"). Empty pulls
	// every source the trail captures.
	EventSourceFilter string
	// MutationOnly, when true, requests ReadOnly=false events from
	// CloudTrail.
	MutationOnly bool
	// MaxPages caps the number of paginated LookupEvents calls.
	// Defaults to DefaultMaxPages.
	MaxPages int
	// MaxEvents caps the total number of events ingested across all
	// pages. Defaults to DefaultMaxEvents.
	MaxEvents int
	// MaxThrottleRetries caps retries per page when CloudTrail returns
	// a throttling error. Defaults to DefaultMaxThrottleRetries.
	MaxThrottleRetries int
	// ThrottleBackoff is the base sleep between throttling retries;
	// each retry waits ThrottleBackoff * (attempt + 1). Defaults to
	// DefaultThrottleBackoff. The ingester sleeps with the supplied
	// Sleep hook so tests stay fast.
	ThrottleBackoff time.Duration
	// PageSize is the LookupEvents MaxResults. Defaults to
	// DefaultPageSize; CloudTrail caps at 50.
	PageSize int32
}

// IngestResult is the bounded outcome of one ingestion run.
type IngestResult struct {
	AccountID    string
	Region       string
	Events       []NormalizedEvent
	Diagnostics  []Diagnostic
	CoverageGaps []CoverageGap
	// Status mirrors the runtime event contract: "ready", "degraded",
	// "blocked". "blocked" is reserved for permission-denied results.
	Status           string
	FailureReasons   []string
	RemediationHints []string
	// PagesFetched and EventsConsidered let the API layer attach
	// observability metadata to the response.
	PagesFetched     int
	EventsConsidered int
	// HistoryTruncated is true when the ingester stopped because it
	// hit MaxPages or MaxEvents with more events available.
	HistoryTruncated bool
}

// Diagnostic explains a partial failure inside an ingestion run.
type Diagnostic struct {
	SourceID    string
	Code        string
	Message     string
	Remediation string
	Retryable   bool
}

// CoverageGap explains why one collection capability returned no events
// or partial coverage.
type CoverageGap struct {
	Capability  string
	Status      string
	Reason      string
	Remediation string
}

// NormalizedEvent is the metadata-only contract emitted by the
// ingester. The API layer maps these into AWSRuntimeEventRecord. Field
// names mirror the runtime contract so the mapping in
// internal/api/aws_runtime_cloudtrail.go is a 1:1 copy.
type NormalizedEvent struct {
	EventID            string
	AccountID          string
	Region             string
	EventType          string
	EventSource        string
	EventName          string
	Action             string
	ActorPrincipalARN  string
	ActorPrincipalType string
	SessionID          string
	AssumedRoleARN     string
	SessionIssuerARN   string
	SourceIPAddress    string
	UserAgent          string
	SessionStartedAt   time.Time
	SessionExpiresAt   time.Time
	TargetResourceARN  string
	TargetResourceType string
	TargetResourceName string
	// AgentID, AgentType, and AgentRuntimeVersion are derived from
	// the target-resource ARN for agent-tool events. The API layer
	// composes the canonical AgentNodeID from these via the same
	// helper the AI-agent inventory and provider normalizer use, so
	// the runtime evidence graph joins back to the agent inventory
	// nodes. AgentRuntimeVersion is the third path segment for an
	// AgentCore runtime endpoint (the endpoint alias / runtime
	// version that the inventory also stamps into the node id); it
	// is empty for bedrock-agent ARNs which do not carry one.
	AgentID             string
	AgentType           string
	AgentRuntimeVersion string
	Owner               string
	EvidenceCategory    string
	Confidence          float64
	ObservedAt          time.Time
	CollectedAt         time.Time
	Status              string
	ReadOnly            bool
	RedactionBoundary   string
}

const (
	// CollectorName tags every diagnostic emitted by this ingester so
	// downstream callers can scope diagnostics by collector.
	CollectorName = "aws_cloudtrail_lookup_events"

	// DefaultLookbackWindow is the default amount of CloudTrail
	// history one ingestion run scans. Chosen to match a single
	// hourly worker tick with enough slack to absorb CloudTrail
	// delivery delay.
	DefaultLookbackWindow = 90 * time.Minute

	// MaxLookbackWindow is the CloudTrail LookupEvents retention
	// horizon. Requests beyond this are silently clamped.
	MaxLookbackWindow = 90 * 24 * time.Hour

	// DefaultMaxPages bounds the number of LookupEvents pages one
	// ingestion run consumes. CloudTrail page size is 50, so the
	// default caps a run at 50 * 20 = 1000 events.
	DefaultMaxPages = 20

	// DefaultMaxEvents bounds the total events ingested in one run.
	DefaultMaxEvents = 1000

	// DefaultMaxThrottleRetries bounds per-page throttling retries.
	DefaultMaxThrottleRetries = 4

	// DefaultThrottleBackoff is the base sleep between throttling
	// retries; each attempt sleeps DefaultThrottleBackoff * (n + 1).
	DefaultThrottleBackoff = 200 * time.Millisecond

	// DefaultPageSize is the LookupEvents MaxResults default;
	// CloudTrail's hard cap is 50.
	DefaultPageSize = int32(50)

	// RedactionBoundary is the redaction label every normalized event
	// carries; it documents that the ingester only crossed the
	// metadata boundary.
	RedactionBoundary = "metadata_only_no_payloads_no_secret_values"
)

// permissionDeniedCodes is the set of AWS error codes the ingester
// treats as authoritative permission-denied signals. The check is
// case-insensitive and also matches the code embedded in an unwrapped
// error string so we work both with SDK *types.AccessDeniedException
// and bare net/http transport errors.
//
// ExpiredToken / TokenRefreshRequired are intentionally NOT on this
// list: those mean the assumed-role session aged out and a retry with
// fresh credentials will work. Treating them as permission_denied
// would collapse the response to status=blocked and discard the
// events ingested before the token expired, which is misleading and
// loses real evidence. They fall through to the transient-failure
// branch in the Ingest loop instead.
var permissionDeniedCodes = []string{
	"AccessDeniedException",
	"AccessDenied",
	"UnauthorizedOperation",
	"InvalidClientTokenId",
}

// throttleCodes is the set of AWS error codes the ingester treats as
// throttling — meaning the request was *not* served and should be
// retried with a backoff.
var throttleCodes = []string{
	"ThrottlingException",
	"Throttling",
	"RequestLimitExceeded",
	"TooManyRequestsException",
	"SlowDown",
}

// transientAuthCodes is the set of AWS error codes that signal the
// assumed-role session aged out (or the SDK needs to refresh
// credentials) — distinct from permission denial. They are degraded
// and retryable, never blocked, so partial events ingested before
// the token expired are preserved.
var transientAuthCodes = []string{
	"ExpiredToken",
	"ExpiredTokenException",
	"TokenRefreshRequired",
}

// Ingester drives one bounded LookupEvents ingestion run.
type Ingester struct {
	API   LookupEventsAPI
	Now   func() time.Time
	Sleep func(d time.Duration)
}

// New returns an Ingester with the supplied LookupEvents seam and
// sensible defaults for Now and Sleep. Tests inject deterministic
// versions.
func New(api LookupEventsAPI) *Ingester {
	return &Ingester{
		API:   api,
		Now:   func() time.Time { return time.Now().UTC() },
		Sleep: time.Sleep,
	}
}

// Ingest runs one bounded LookupEvents ingestion pass and returns the
// normalized result. Ingest never returns an error for documented
// failure modes (permission denied, throttling, partial failure,
// empty); those are surfaced through IngestResult.Status, Diagnostics,
// and CoverageGaps so the API layer can return a stable 200 response.
// A returned error means a programmer bug or a missing seam.
func (i *Ingester) Ingest(ctx context.Context, request IngestRequest) (IngestResult, error) {
	if i == nil {
		return IngestResult{}, errors.New("cloudtrail: ingester is nil")
	}
	if i.API == nil {
		return IngestResult{}, errors.New("cloudtrail: lookup events api is required")
	}
	now := i.now()
	request = request.withDefaults()
	result := IngestResult{
		AccountID: strings.TrimSpace(request.AccountID),
		Region:    strings.TrimSpace(request.Region),
		Status:    "ready",
	}

	start := now.Add(-request.LookbackWindow)
	end := now
	seen := map[string]struct{}{}
	nextToken := ""

	for page := 0; page < request.MaxPages; page++ {
		input := LookupEventsInput{
			StartTime:  start,
			EndTime:    end,
			NextToken:  nextToken,
			MaxResults: request.PageSize,
			Attributes: request.attribute(),
		}
		pageOut, fetchErr := i.fetchWithRetry(ctx, input, request)
		result.PagesFetched++
		if fetchErr != nil {
			// Context cancellation and deadline expiry are caller-
			// driven aborts, not CloudTrail partial-coverage states.
			// Returning a degraded result here would let an HTTP
			// handler whose client already disconnected (or whose
			// per-request deadline already fired) record a stale
			// runtime-events response instead of aborting. Propagate
			// the context error to the caller so the request layer
			// can shed the in-flight work.
			if errors.Is(fetchErr, context.Canceled) || errors.Is(fetchErr, context.DeadlineExceeded) {
				return IngestResult{}, fetchErr
			}
			if isPermissionDenied(fetchErr) {
				return finalizeBlocked(result, fetchErr), nil
			}
			result.Diagnostics = append(result.Diagnostics, Diagnostic{
				SourceID:    "cloudtrail",
				Code:        diagnosticCodeFor(fetchErr),
				Message:     fmt.Sprintf("CloudTrail LookupEvents page %d failed: %v", page+1, fetchErr),
				Remediation: "Retry the failed page without discarding events already ingested in this run.",
				Retryable:   isRetryable(fetchErr),
			})
			result.Status = "degraded"
			result.FailureReasons = append(result.FailureReasons, "CloudTrail LookupEvents pagination ended early")
			result.RemediationHints = append(result.RemediationHints, "Retry CloudTrail LookupEvents collection; partial coverage is preserved.")
			if len(result.Events) == 0 {
				result.CoverageGaps = append(result.CoverageGaps, CoverageGap{
					Capability:  "cloudtrail_lookup_events",
					Status:      "partial_failure",
					Reason:      "CloudTrail LookupEvents could not be enumerated for the requested window.",
					Remediation: "Retry CloudTrail LookupEvents without widening the scope.",
				})
			}
			break
		}
		for idx, raw := range pageOut.Events {
			result.EventsConsidered++
			eventID := strings.TrimSpace(raw.EventID)
			if eventID == "" {
				result.Diagnostics = append(result.Diagnostics, Diagnostic{
					SourceID:  "cloudtrail",
					Code:      "cloudtrail_event_missing_id",
					Message:   "CloudTrail returned an event without an EventId; skipping.",
					Retryable: false,
				})
				continue
			}
			if _, ok := seen[eventID]; ok {
				continue
			}
			seen[eventID] = struct{}{}
			normalized, mapDiag, ok := normalizeEvent(raw, result.AccountID, result.Region, now)
			if mapDiag != nil {
				result.Diagnostics = append(result.Diagnostics, *mapDiag)
			}
			if !ok {
				continue
			}
			// Cap the per-event fan-out (multi-resource CloudTrail
			// events normalize into >1 records) against the remaining
			// MaxEvents budget before appending. Otherwise a single
			// BatchGetSecretValue with many resources could push the
			// run past the advertised cap. If we trim mid-fan-out the
			// trailing resources are unread events, so mark truncation.
			remaining := request.MaxEvents - len(result.Events)
			if remaining <= 0 {
				result.HistoryTruncated = true
				break
			}
			if len(normalized) > remaining {
				normalized = normalized[:remaining]
				result.HistoryTruncated = true
			}
			result.Events = append(result.Events, normalized...)
			if len(result.Events) >= request.MaxEvents {
				// More events still in this page → history is
				// genuinely truncated. If the budget fills on the
				// last event of the page we leave the flag to the
				// post-loop check, which can also see NextToken.
				if idx+1 < len(pageOut.Events) {
					result.HistoryTruncated = true
				}
				break
			}
		}
		if len(result.Events) >= request.MaxEvents {
			// Budget filled. Only mark truncation when CloudTrail
			// has more pages to serve; an exact-fill run that
			// happens to end with a complete trailing page is
			// complete, not truncated.
			if strings.TrimSpace(pageOut.NextToken) != "" {
				result.HistoryTruncated = true
			}
			break
		}
		nextToken = strings.TrimSpace(pageOut.NextToken)
		if nextToken == "" {
			break
		}
		if page+1 == request.MaxPages && nextToken != "" {
			result.HistoryTruncated = true
		}
	}

	sortEventsByObserved(result.Events)
	finalize(&result)
	return result, nil
}

func (i *Ingester) fetchWithRetry(ctx context.Context, input LookupEventsInput, request IngestRequest) (LookupEventsPage, error) {
	var lastErr error
	for attempt := 0; attempt <= request.MaxThrottleRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return LookupEventsPage{}, err
		}
		page, err := i.API.LookupEvents(ctx, input)
		if err == nil {
			return page, nil
		}
		lastErr = err
		if !isThrottling(err) {
			return LookupEventsPage{}, err
		}
		if attempt == request.MaxThrottleRetries {
			break
		}
		backoff := request.ThrottleBackoff * time.Duration(attempt+1)
		i.sleep(backoff)
	}
	return LookupEventsPage{}, lastErr
}

func (i *Ingester) now() time.Time {
	if i == nil || i.Now == nil {
		return time.Now().UTC()
	}
	return i.Now().UTC()
}

func (i *Ingester) sleep(d time.Duration) {
	if i == nil || i.Sleep == nil || d <= 0 {
		return
	}
	i.Sleep(d)
}

func (r IngestRequest) withDefaults() IngestRequest {
	if r.LookbackWindow <= 0 {
		r.LookbackWindow = DefaultLookbackWindow
	}
	if r.LookbackWindow > MaxLookbackWindow {
		r.LookbackWindow = MaxLookbackWindow
	}
	if r.MaxPages <= 0 {
		r.MaxPages = DefaultMaxPages
	}
	if r.MaxEvents <= 0 {
		r.MaxEvents = DefaultMaxEvents
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
	if r.PageSize <= 0 || r.PageSize > DefaultPageSize {
		r.PageSize = DefaultPageSize
	}
	return r
}

func (r IngestRequest) attribute() LookupAttribute {
	switch {
	case strings.TrimSpace(r.EventSourceFilter) != "":
		return LookupAttribute{Key: "EventSource", Value: strings.TrimSpace(r.EventSourceFilter)}
	case r.MutationOnly:
		return LookupAttribute{Key: "ReadOnly", Value: "false"}
	default:
		return LookupAttribute{}
	}
}

// finalize sets status/confidence/coverage gaps based on what landed in
// the result. The defaults track the existing aws_runtime_events.go
// contract so the API layer's status thresholds remain consistent
// whether the data came from a fixture or from CloudTrail.
func finalize(result *IngestResult) {
	// Truncation must be considered before the empty-window branch:
	// when the page budget exhausts on pages whose events all got
	// skipped for missing core fields or unparseable payloads,
	// `result.Events` is empty AND `result.HistoryTruncated` is
	// true. Reporting only an empty window would hide the fact that
	// more CloudTrail history remained unread.
	if result.HistoryTruncated {
		result.FailureReasons = append(result.FailureReasons, "CloudTrail LookupEvents ingestion stopped at a bounded budget")
		result.RemediationHints = append(result.RemediationHints, "Narrow the time window or raise the per-run budget; partial coverage is preserved.")
		result.CoverageGaps = append(result.CoverageGaps, CoverageGap{
			Capability:  "cloudtrail_lookup_events",
			Status:      "history_truncated",
			Reason:      "Ingestion stopped at the configured MaxPages/MaxEvents budget; more events were available.",
			Remediation: "Narrow the lookback window or raise the per-run budget so the trail tail is covered.",
		})
		if result.Status == "ready" {
			result.Status = "degraded"
		}
	}
	if len(result.Events) == 0 && result.Status == "ready" {
		result.Status = "degraded"
		result.FailureReasons = append(result.FailureReasons, "no runtime events matched the scoped account and region")
		result.RemediationHints = append(result.RemediationHints, "Confirm CloudTrail management events are enabled, then retry runtime event ingestion.")
		result.CoverageGaps = append(result.CoverageGaps, CoverageGap{
			Capability:  "cloudtrail_lookup_events",
			Status:      "empty",
			Reason:      "CloudTrail LookupEvents returned no events in the scanned window.",
			Remediation: "Widen the lookback window or confirm CloudTrail management events are enabled.",
		})
		return
	}
	// Mirror the fixture path in aws_runtime_events.go
	// summarizeAWSRuntimeEventStatus: if normalization emitted any
	// diagnostic — e.g. skipped events with missing core fields, or a
	// CloudTrailEvent payload that fell back to top-level metadata —
	// the run is not "ready". Without this, a live response could
	// claim full confidence even though the ingested page contained
	// malformed or partially normalized records.
	if result.Status == "ready" && len(result.Diagnostics) > 0 {
		result.Status = "degraded"
		result.FailureReasons = append(result.FailureReasons, "CloudTrail LookupEvents ingestion returned diagnostics")
		result.RemediationHints = append(result.RemediationHints, "Review diagnostics before treating runtime coverage as complete.")
	}
}

// finalizeBlocked converts a permission-denied error from CloudTrail
// into the standard "blocked" runtime contract result. All previously
// ingested events are dropped because the per-page failure means we
// cannot assert coverage.
func finalizeBlocked(result IngestResult, err error) IngestResult {
	result.Status = "blocked"
	result.Events = nil
	result.HistoryTruncated = false
	result.Diagnostics = append([]Diagnostic{}, Diagnostic{
		SourceID:    "cloudtrail",
		Code:        "permission_denied",
		Message:     fmt.Sprintf("CloudTrail LookupEvents permission is not available for runtime event ingestion: %v", err),
		Remediation: "Grant metadata-only CloudTrail LookupEvents access. Do not grant payload, secret-value, decrypt, or object-body reads.",
		Retryable:   true,
	})
	result.FailureReasons = []string{"runtime event sources are not authorized for this connector"}
	result.RemediationHints = []string{"Grant metadata-only CloudTrail LookupEvents and service audit permissions; do not grant payload, secret-value, decrypt, or object-body reads."}
	result.CoverageGaps = []CoverageGap{{
		Capability:  "cloudtrail_lookup_events",
		Status:      "permission_denied",
		Reason:      "Runtime event source cannot be queried with the current connector permissions.",
		Remediation: "Add read-only CloudTrail LookupEvents permissions and retry.",
	}}
	return result
}

// sortEventsByObserved orders normalized events by ObservedAt ascending
// so the API layer renders a stable timeline regardless of which
// LookupEvents page they arrived on.
func sortEventsByObserved(events []NormalizedEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].ObservedAt.Equal(events[j].ObservedAt) {
			return events[i].EventID < events[j].EventID
		}
		return events[i].ObservedAt.Before(events[j].ObservedAt)
	})
}

func isPermissionDenied(err error) bool {
	return errorMatchesAny(err, permissionDeniedCodes)
}

func isThrottling(err error) bool {
	return errorMatchesAny(err, throttleCodes)
}

func isTransientAuth(err error) bool {
	return errorMatchesAny(err, transientAuthCodes)
}

func isRetryable(err error) bool {
	return isThrottling(err) || isTransientAuth(err)
}

func diagnosticCodeFor(err error) string {
	if isPermissionDenied(err) {
		return "permission_denied"
	}
	if isThrottling(err) {
		return "cloudtrail_lookup_events_throttled"
	}
	if isTransientAuth(err) {
		return "cloudtrail_lookup_events_credentials_expired"
	}
	return "cloudtrail_lookup_events_failed"
}

// errorMatchesAny matches an error against AWS error codes using both a
// codeNamer interface (smithy-style ErrorCode()) and a substring scan
// of the unwrapped error string. The substring scan makes the check
// portable across SDK error wrappers without taking a hard dep on the
// SDK in the engine layer.
func errorMatchesAny(err error, codes []string) bool {
	if err == nil {
		return false
	}
	type codeNamer interface{ ErrorCode() string }
	var candidate codeNamer
	if errors.As(err, &candidate) {
		got := candidate.ErrorCode()
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

// payloadAllowedKeys is the metadata-only allow-list for fields the
// ingester is permitted to extract from the CloudTrailEvent JSON
// payload. Anything not on this list — request parameters, response
// elements, additional event data — is never read, even though it is
// present in the JSON string.
var payloadAllowedKeys = struct {
	UserIdentity      string
	SourceIPAddress   string
	UserAgent         string
	RecipientAccount  string
	AWSRegion         string
	UserType          string
	UserARN           string
	UserPrincipalID   string
	SessionContext    string
	SessionAttributes string
	SessionIssuer     string
	IssuerARN         string
	IssuerType        string
	CreationDate      string
}{
	UserIdentity:      "userIdentity",
	SourceIPAddress:   "sourceIPAddress",
	UserAgent:         "userAgent",
	RecipientAccount:  "recipientAccountId",
	AWSRegion:         "awsRegion",
	UserType:          "type",
	UserARN:           "arn",
	UserPrincipalID:   "principalId",
	SessionContext:    "sessionContext",
	SessionAttributes: "attributes",
	SessionIssuer:     "sessionIssuer",
	IssuerARN:         "arn",
	IssuerType:        "type",
	CreationDate:      "creationDate",
}

// normalizeEvent converts one CloudTrail Event into one or more
// NormalizedEvents. Multi-resource CloudTrail events
// (e.g. BatchGetSecretValue reading several secrets) fan out to one
// normalized event per Resources entry — using suffixed EventIDs to
// keep dedupe deterministic — so the resource-level filter, the
// graph relationship builder, and the per-resource summary counts
// all see every secret/key/object the event touched. The collectedAt
// argument is the wall-clock time of the ingestion run; live records
// use it instead of `observed_at + 2min` so audit ordering, cache
// invalidation, and freshness checks see the actual collection time.
func normalizeEvent(raw Event, accountID string, region string, collectedAt time.Time) ([]NormalizedEvent, *Diagnostic, bool) {
	eventID := strings.TrimSpace(raw.EventID)
	eventName := strings.TrimSpace(raw.EventName)
	eventSource := strings.TrimSpace(raw.EventSource)
	if eventID == "" || eventName == "" || eventSource == "" {
		return nil, &Diagnostic{
			SourceID:  firstNonEmpty(eventID, "cloudtrail"),
			Code:      "cloudtrail_event_missing_core_fields",
			Message:   "CloudTrail event is missing EventId, EventName, or EventSource; skipping.",
			Retryable: false,
		}, false
	}

	meta, metaErr := extractAllowedMetadata(raw.RawEvent)
	var diag *Diagnostic
	scopedAccount := accountID
	scopedRegion := region
	if metaErr != nil {
		// Bad payload JSON is treated as a partial-failure
		// diagnostic, not a hard error: the SDK Event's top-level
		// fields are still usable.
		diag = &Diagnostic{
			SourceID:  eventID,
			Code:      "cloudtrail_event_payload_unparseable",
			Message:   fmt.Sprintf("CloudTrailEvent JSON could not be parsed for %s; falling back to top-level metadata: %v", eventID, metaErr),
			Retryable: false,
		}
	} else {
		scopedAccount = firstNonEmpty(meta.RecipientAccount, accountID)
		scopedRegion = firstNonEmpty(meta.AWSRegion, region)
	}

	// Fan out per Resources entry — or once with an empty resource
	// when the event carries none. The base event id is preserved on
	// the first record; later resources get a deterministic
	// `${EventID}#${idx}` suffix so the outer dedupe keeps them all
	// while remaining stable across repeated lookups.
	resources := raw.Resources
	if len(resources) == 0 {
		resources = []EventResource{{}}
	}
	out := make([]NormalizedEvent, 0, len(resources))
	for idx, resource := range resources {
		base := buildNormalizedFromCore(raw, resource, scopedAccount, scopedRegion, collectedAt)
		if idx > 0 {
			base.EventID = fmt.Sprintf("%s#%d", eventID, idx)
		}
		if metaErr == nil {
			base.SourceIPAddress = meta.SourceIPAddress
			base.UserAgent = meta.UserAgent
			if meta.UserARN != "" {
				base.ActorPrincipalARN = meta.UserARN
			}
			if meta.UserType != "" {
				base.ActorPrincipalType = mapPrincipalType(meta.UserType)
			}
			if meta.SessionPrincipalID != "" {
				base.SessionID = meta.SessionPrincipalID
			}
			if meta.IssuerARN != "" {
				base.SessionIssuerARN = meta.IssuerARN
				base.AssumedRoleARN = meta.IssuerARN
			}
			if !meta.SessionCreationDate.IsZero() {
				base.SessionStartedAt = meta.SessionCreationDate
			}
			// SessionExpiresAt is deliberately left zero when the
			// real expiration is not extracted; STS sessions range
			// from 15 minutes to 12 hours, so synthesising +1h would
			// mislead consumers.
		}
		out = append(out, base)
	}
	return out, diag, true
}

func buildNormalizedFromCore(raw Event, resource EventResource, accountID string, region string, collectedAt time.Time) NormalizedEvent {
	eventID := strings.TrimSpace(raw.EventID)
	eventName := strings.TrimSpace(raw.EventName)
	eventSource := strings.TrimSpace(raw.EventSource)
	observed := raw.EventTime.UTC()
	if observed.IsZero() {
		observed = collectedAt
	}
	readOnly := strings.EqualFold(strings.TrimSpace(raw.ReadOnly), "true")
	eventType := classifyEventType(eventSource, eventName)
	resourceARN, resourceType, resourceName := pickTargetResource(resource)
	owner := ownerForEventType(eventType)
	evidence := "cloudtrail"
	status := "observed"
	if eventType == "agent-tool" {
		evidence = "agent-runtime"
	}
	agentID, agentType, runtimeVersion := extractAgentIdentity(eventType, resourceARN)
	return NormalizedEvent{
		EventID:             eventID,
		AccountID:           strings.TrimSpace(accountID),
		Region:              strings.TrimSpace(region),
		EventType:           eventType,
		EventSource:         eventSource,
		EventName:           eventName,
		Action:              buildAction(eventSource, eventName),
		ActorPrincipalARN:   strings.TrimSpace(raw.Username),
		ActorPrincipalType:  "assumed_role",
		SessionID:           strings.TrimSpace(raw.AccessKeyID),
		Owner:               owner,
		EvidenceCategory:    evidence,
		Confidence:          0.9,
		ObservedAt:          observed,
		CollectedAt:         collectedAt,
		Status:              status,
		ReadOnly:            readOnly,
		TargetResourceARN:   resourceARN,
		TargetResourceType:  resourceType,
		TargetResourceName:  resourceName,
		AgentID:             agentID,
		AgentType:           agentType,
		AgentRuntimeVersion: runtimeVersion,
		RedactionBoundary:   RedactionBoundary,
	}
}

// extractedMetadata is the small allow-listed slice of CloudTrailEvent
// JSON the ingester reads. Every field is metadata-only.
type extractedMetadata struct {
	SourceIPAddress     string
	UserAgent           string
	RecipientAccount    string
	AWSRegion           string
	UserARN             string
	UserType            string
	SessionPrincipalID  string
	IssuerARN           string
	SessionCreationDate time.Time
}

func extractAllowedMetadata(raw string) (extractedMetadata, error) {
	out := extractedMetadata{}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return out, nil
	}
	var blob map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &blob); err != nil {
		return out, err
	}
	out.SourceIPAddress = decodeString(blob[payloadAllowedKeys.SourceIPAddress])
	out.UserAgent = decodeString(blob[payloadAllowedKeys.UserAgent])
	out.RecipientAccount = decodeString(blob[payloadAllowedKeys.RecipientAccount])
	out.AWSRegion = decodeString(blob[payloadAllowedKeys.AWSRegion])
	if userIdentity, ok := blob[payloadAllowedKeys.UserIdentity]; ok {
		var identity map[string]json.RawMessage
		if err := json.Unmarshal(userIdentity, &identity); err == nil {
			out.UserARN = decodeString(identity[payloadAllowedKeys.UserARN])
			out.UserType = decodeString(identity[payloadAllowedKeys.UserType])
			out.SessionPrincipalID = decodeString(identity[payloadAllowedKeys.UserPrincipalID])
			if sessionCtx, ok := identity[payloadAllowedKeys.SessionContext]; ok {
				var session map[string]json.RawMessage
				if err := json.Unmarshal(sessionCtx, &session); err == nil {
					if attrs, ok := session[payloadAllowedKeys.SessionAttributes]; ok {
						var attrMap map[string]json.RawMessage
						if err := json.Unmarshal(attrs, &attrMap); err == nil {
							if creation := decodeString(attrMap[payloadAllowedKeys.CreationDate]); creation != "" {
								if parsed, perr := parseSessionTime(creation); perr == nil {
									out.SessionCreationDate = parsed
								}
							}
						}
					}
					if issuer, ok := session[payloadAllowedKeys.SessionIssuer]; ok {
						var issuerBlob map[string]json.RawMessage
						if err := json.Unmarshal(issuer, &issuerBlob); err == nil {
							out.IssuerARN = decodeString(issuerBlob[payloadAllowedKeys.IssuerARN])
						}
					}
				}
			}
		}
	}
	return out, nil
}

func parseSessionTime(value string) (time.Time, error) {
	// CloudTrail's userIdentity sessionContext.attributes.creationDate
	// is documented as basic ISO-8601 (e.g. `20131102T010628Z`), but
	// real-world emitters also produce the dashed RFC3339 form. Try
	// every layout we have observed before giving up.
	for _, layout := range []string{
		"20060102T150405Z",
		"20060102T150405.000Z",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
	} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized session creation time %q", value)
}

func decodeString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// mapPrincipalType converts the CloudTrail userIdentity `type` field
// into the snake_case principal-type token the runtime event contract
// uses across fixtures, API responses, and the frontend. Without this
// mapping a live response would emit camel-case tokens like
// `assumedrole` (just lowercased) while fixtures emit `assumed_role`,
// breaking consumers that group or compare across the two sources.
// Unknown types fall back to a snake_case projection of the input so
// future CloudTrail principal classes degrade safely instead of being
// dropped.
func mapPrincipalType(userType string) string {
	switch strings.TrimSpace(userType) {
	case "":
		return ""
	case "AssumedRole":
		return "assumed_role"
	case "IAMUser":
		return "iam_user"
	case "Root":
		return "root"
	case "FederatedUser":
		return "federated_user"
	case "AWSAccount":
		return "aws_account"
	case "AWSService":
		return "aws_service"
	case "WebIdentityUser":
		return "web_identity_user"
	case "SAMLUser":
		return "saml_user"
	case "Role":
		return "role"
	case "Directory":
		return "directory"
	case "Unknown":
		return "unknown"
	default:
		// Snake-case fallback: insert "_" between lower→upper case
		// transitions then lowercase. Keeps unknown CloudTrail types
		// usable instead of letting them drift into a different
		// token space than the fixture contract.
		var b strings.Builder
		runes := []rune(strings.TrimSpace(userType))
		for i, r := range runes {
			if i > 0 && r >= 'A' && r <= 'Z' && runes[i-1] >= 'a' && runes[i-1] <= 'z' {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		}
		return strings.ToLower(b.String())
	}
}

func classifyEventType(eventSource string, eventName string) string {
	source := strings.ToLower(strings.TrimSpace(eventSource))
	name := strings.TrimSpace(eventName)
	switch source {
	case "sts.amazonaws.com":
		if strings.HasPrefix(name, "AssumeRole") || strings.HasPrefix(name, "GetSession") || strings.HasPrefix(name, "GetFederation") {
			return "sts-session"
		}
	case "secretsmanager.amazonaws.com":
		if name == "GetSecretValue" || name == "BatchGetSecretValue" || strings.HasPrefix(name, "GetSecret") {
			return "secret-read"
		}
	case "kms.amazonaws.com":
		if name == "Decrypt" || name == "GenerateDataKey" || name == "ReEncrypt" {
			return "kms-decrypt"
		}
	case "bedrock-agentcore.amazonaws.com", "bedrock-agent.amazonaws.com":
		// agent-tool is reserved for actual tool/agent invocations
		// (data events). Control-plane operations from the same
		// source — CreateAgent, UpdateAgent, DeleteAgent, GetAgent,
		// ListAgents, PrepareAgent, etc. — are ordinary management
		// API calls and must classify as api-call, otherwise a
		// caller filtering for `event_type=agent-tool` would see
		// management records reported as tool evidence even though
		// no tool was actually invoked.
		if strings.HasPrefix(name, "Invoke") {
			return "agent-tool"
		}
	}
	return "api-call"
}

func ownerForEventType(eventType string) string {
	switch eventType {
	case "sts-session":
		return "security"
	case "secret-read":
		return "application"
	case "kms-decrypt":
		return "platform"
	case "agent-tool":
		return "security"
	default:
		return "application"
	}
}

func buildAction(eventSource string, eventName string) string {
	source := strings.ToLower(strings.TrimSpace(eventSource))
	source = strings.TrimSuffix(source, ".amazonaws.com")
	if source == "" {
		return strings.TrimSpace(eventName)
	}
	return source + ":" + strings.TrimSpace(eventName)
}

func pickTargetResource(r EventResource) (string, string, string) {
	name := strings.TrimSpace(r.ResourceName)
	rt := strings.TrimSpace(r.ResourceType)
	if name == "" && rt == "" {
		return "", "", ""
	}
	display := name
	if display == "" {
		display = rt
	}
	// The ResourceName from CloudTrail is usually an ARN for
	// secrets/KMS/S3 events and a plain name otherwise; the API
	// layer keeps both for downstream graph wiring.
	return name, rt, display
}

// extractAgentIdentity derives the agent ID, the agent-type
// discriminator token, and (where available) the AgentCore runtime
// version / endpoint alias from an agent-tool target resource ARN.
// Bedrock AgentCore emits resources like
// `arn:aws:bedrock-agentcore:<region>:<account>:agent-runtime-endpoint/<agentID>/<alias>`
// and Bedrock Agents emits
// `arn:aws:bedrock-agent:<region>:<account>:agent/<agentID>`. The
// agent ID is the segment immediately after the resource type; the
// type discriminator distinguishes which agent inventory the ID
// belongs to; and the third path segment (when present) carries the
// AgentCore endpoint alias which the AI-agent inventory stamps into
// the canonical node id as `RuntimeVersion`. The API layer composes
// the canonical AgentNodeID from all three via `awsAIAgentNodeID`,
// so live relationships keyed on the inventory node id never miss a
// runtime version the inventory has already published. Non-agent-tool
// events return empty strings.
func extractAgentIdentity(eventType string, resourceARN string) (agentID string, agentType string, runtimeVersion string) {
	if eventType != "agent-tool" {
		return "", "", ""
	}
	trimmed := strings.TrimSpace(resourceARN)
	if trimmed == "" {
		return "", "", ""
	}
	colon := strings.LastIndex(trimmed, ":")
	if colon < 0 || colon+1 >= len(trimmed) {
		return "", "", ""
	}
	resource := trimmed[colon+1:]
	parts := strings.Split(resource, "/")
	if len(parts) < 2 {
		return "", "", ""
	}
	resourceType := strings.TrimSpace(parts[0])
	agentID = strings.TrimSpace(parts[1])
	if agentID == "" {
		return "", "", ""
	}
	agentType = "bedrock_agent"
	if strings.HasPrefix(resourceType, "agent-runtime") {
		agentType = "agentcore_runtime"
	}
	if len(parts) >= 3 {
		runtimeVersion = strings.TrimSpace(parts[2])
	}
	return agentID, agentType, runtimeVersion
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
