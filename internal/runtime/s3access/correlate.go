// Package s3access correlates observed S3 runtime data access (read /
// write / list events) with the static reachability edges Identrail
// already discovered (S3 bucket-policy `can_access` grants) and the
// bucket's exposure / sensitivity classification. The output ties
// observed behavior back to identity, session, bucket, and agent context
// so an operator can answer, per (identity, bucket) pair:
//
//   - confirmed:               the identity was statically allowed to
//     reach the bucket AND was observed doing so. Behavior matches policy.
//   - observed_without_grant:  the identity was observed accessing the
//     bucket but no static allow edge explains it. Most S3 access is
//     authorized by IAM identity policies, which this wave's static
//     collector does not enumerate, or it drifted from the modeled
//     grants. Treated as a caveat, never a silent success.
//   - granted_unused:          a static allow edge exists but no runtime
//     access was observed in the window. Surfaces over-provisioned
//     grants — but carries a mandatory missing-event caveat because S3
//     GetObject/PutObject are CloudTrail *data* events; absence in a
//     management-event lookup is not proof the access never happened.
//
// On top of the reachability join, the correlation records the observed
// access *modes* (read / write / list) and flags when an observed mode
// exceeds what the static grant authorizes, and elevates a caveat when a
// sensitive or publicly/cross-account exposed bucket is involved.
//
// Safety boundary: the engine is metadata-only and, specifically for S3,
// never sees object keys or object contents. The API adapter redacts
// object keys into bounded "safe prefixes" before they reach the engine,
// and every emitted correlation re-stamps the redaction boundary so
// downstream consumers cannot mistake it for payload-bearing evidence.
package s3access

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ResourceKind is fixed for this engine: every correlation is keyed to an
// S3 bucket (object keys are redacted into safe prefixes, never used as a
// join key).
const ResourceKind = "s3_bucket"

// Correlation statuses — the operator-facing classification of a single
// (identity, bucket) correlation.
const (
	StatusConfirmed            = "confirmed"
	StatusObservedWithoutGrant = "observed_without_grant"
	StatusGrantedUnused        = "granted_unused"
)

// Access modes. Each observed S3 event and each static grant is reduced
// to the set of modes it represents.
const (
	ModeRead  = "read"
	ModeWrite = "write"
	ModeList  = "list"
)

// Static grant source.
const SourceBucketPolicy = "bucket_policy"

const (
	// CollectorName tags every diagnostic and result the correlator
	// emits so the API layer can scope diagnostics by collector.
	CollectorName = "aws_s3_runtime_access"

	// RedactionBoundary documents that the correlator only ever crossed
	// the metadata boundary — no object keys, no object contents.
	RedactionBoundary = "metadata_only_no_object_keys_no_object_contents"
)

// Caveat codes attached to individual correlations or the result. Stable
// tokens so the UI and downstream consumers can branch without
// string-matching prose.
const (
	CaveatDataEventCoverage   = "runtime_data_events_may_be_incomplete"
	CaveatNoStaticPath        = "no_static_reachability_edge"
	CaveatObservedDespiteDeny = "observed_despite_explicit_deny"
	CaveatModeExceedsGrant    = "observed_mode_exceeds_grant"
	CaveatConditionalGrant    = "static_grant_is_conditional"
	CaveatCrossAccountGrant   = "static_grant_is_cross_account"
	CaveatLineageUnresolved   = "session_lineage_unresolved"
	CaveatSensitiveExposed    = "sensitive_bucket_publicly_or_cross_account_exposed"
)

// ObservedAccess is one metadata-only S3 runtime access projected from
// the runtime-event contract. ResourceARN is always the bucket ARN; the
// object key has already been redacted into SafePrefixes by the caller.
type ObservedAccess struct {
	EventID         string
	IdentityNodeID  string
	PrincipalARN    string
	AccountID       string
	Region          string
	BucketARN       string
	BucketName      string
	AccessMode      string
	SafePrefixes    []string
	Action          string
	SessionID       string
	SessionNodeID   string
	AgentID         string
	AgentNodeID     string
	SourceIPAddress string
	LineageStatus   string
	ObservedAt      time.Time
	EvidenceRef     string
}

// StaticGrant is one static reachability edge from the S3 bucket
// reachability collector, projected for the join.
type StaticGrant struct {
	IdentityNodeID string
	PrincipalARN   string
	AccountID      string
	Region         string
	BucketARN      string
	BucketName     string
	AllowedModes   []string
	Source         string // bucket_policy
	Effect         string // Allow | Deny
	Conditional    bool
	CrossAccount   bool
	Exposure       string
	Sensitivity    string
	Confidence     float64
	EvidenceRef    string
}

// CorrelateRequest configures one correlation pass.
type CorrelateRequest struct {
	AccountID string
	Region    string
	Observed  []ObservedAccess
	Static    []StaticGrant
	// DataEventCoverageUnknown marks that the observed set comes from a
	// runtime source that does not guarantee S3 data events are captured
	// (e.g. CloudTrail LookupEvents only indexes management events). When
	// true, every granted_unused correlation and the result envelope
	// carry the missing-event caveat so an operator never reads "unused"
	// as "definitely never used".
	DataEventCoverageUnknown bool
}

// Correlation is one (identity, bucket) correlation record.
type Correlation struct {
	CorrelationID     string
	IdentityNodeID    string
	PrincipalARN      string
	AccountID         string
	Region            string
	BucketARN         string
	BucketName        string
	Status            string
	Confidence        float64
	ObservedCount     int
	ObservedEventIDs  []string
	ObservedModes     []string
	GrantedModes      []string
	SafePrefixes      []string
	Actions           []string
	SessionIDs        []string
	AgentID           string
	AgentNodeID       string
	FirstObservedAt   time.Time
	LastObservedAt    time.Time
	StaticSources     []string
	StaticEffect      string
	Exposure          string
	Sensitivity       string
	Conditional       bool
	CrossAccount      bool
	Caveats           []string
	EvidenceRefs      []string
	RedactionBoundary string
}

// Result is the bounded outcome of one correlation pass.
type Result struct {
	Correlations             []Correlation
	Caveats                  []string
	ConfirmedCount           int
	ObservedWithoutGrant     int
	GrantedUnusedCount       int
	ReadCount                int
	WriteCount               int
	ListCount                int
	SensitiveExposedCount    int
	ModeExceedsGrantCount    int
	IdentityCount            int
	BucketCount              int
	ObservedAccessConsidered int
	StaticGrantsConsidered   int
}

type correlationKey struct {
	identity string
	bucket   string
}

type correlationAgg struct {
	identityNodeID string
	principalARN   string
	accountID      string
	region         string
	bucketARN      string
	bucketName     string
	agentID        string
	agentNodeID    string
	observed       []ObservedAccess
	allow          []StaticGrant
	deny           []StaticGrant
	order          int
}

// Correlate joins observed S3 runtime accesses with static reachability
// grants and returns one correlation per (identity, bucket) pair. It
// never returns an error: documented gaps (no static path, missing data
// events) surface as per-correlation and result-level caveats so the API
// layer can return a stable response.
func Correlate(request CorrelateRequest) Result {
	index := map[correlationKey]*correlationAgg{}
	order := 0
	get := func(identityNode, principal, account, region, bucketARN, bucketName string) *correlationAgg {
		identity := firstNonEmpty(identityNode, principal)
		k := correlationKey{identity: normalize(identity), bucket: normalize(bucketARN)}
		agg, ok := index[k]
		if !ok {
			agg = &correlationAgg{
				identityNodeID: strings.TrimSpace(identityNode),
				principalARN:   strings.TrimSpace(principal),
				accountID:      strings.TrimSpace(account),
				region:         strings.TrimSpace(region),
				bucketARN:      strings.TrimSpace(bucketARN),
				bucketName:     strings.TrimSpace(bucketName),
				order:          order,
			}
			order++
			index[k] = agg
		}
		if agg.identityNodeID == "" {
			agg.identityNodeID = strings.TrimSpace(identityNode)
		}
		if agg.principalARN == "" {
			agg.principalARN = strings.TrimSpace(principal)
		}
		if agg.bucketName == "" {
			agg.bucketName = strings.TrimSpace(bucketName)
		}
		if agg.accountID == "" {
			agg.accountID = strings.TrimSpace(account)
		}
		if agg.region == "" {
			agg.region = strings.TrimSpace(region)
		}
		return agg
	}

	considered := 0
	for _, observed := range request.Observed {
		if strings.TrimSpace(observed.IdentityNodeID) == "" && strings.TrimSpace(observed.PrincipalARN) == "" {
			continue
		}
		if strings.TrimSpace(observed.BucketARN) == "" {
			continue
		}
		considered++
		agg := get(observed.IdentityNodeID, observed.PrincipalARN, observed.AccountID, observed.Region, observed.BucketARN, observed.BucketName)
		agg.observed = append(agg.observed, observed)
		if agg.agentID == "" {
			agg.agentID = strings.TrimSpace(observed.AgentID)
		}
		if agg.agentNodeID == "" {
			agg.agentNodeID = strings.TrimSpace(observed.AgentNodeID)
		}
	}

	staticConsidered := 0
	wildcardDeniesByBucket := map[string][]StaticGrant{}
	for _, grant := range request.Static {
		if strings.TrimSpace(grant.IdentityNodeID) == "" && strings.TrimSpace(grant.PrincipalARN) == "" {
			continue
		}
		if strings.TrimSpace(grant.BucketARN) == "" {
			continue
		}
		staticConsidered++
		if isWildcardPrincipalDeny(grant) {
			bucketKey := normalize(grant.BucketARN)
			wildcardDeniesByBucket[bucketKey] = append(wildcardDeniesByBucket[bucketKey], grant)
			continue
		}
		agg := get(grant.IdentityNodeID, grant.PrincipalARN, grant.AccountID, grant.Region, grant.BucketARN, grant.BucketName)
		if strings.EqualFold(strings.TrimSpace(grant.Effect), "Deny") {
			agg.deny = append(agg.deny, grant)
		} else {
			agg.allow = append(agg.allow, grant)
		}
	}

	for _, agg := range index {
		if denies := wildcardDeniesByBucket[normalize(agg.bucketARN)]; len(denies) > 0 {
			agg.deny = append(agg.deny, denies...)
		}
	}

	aggs := make([]*correlationAgg, 0, len(index))
	for _, agg := range index {
		aggs = append(aggs, agg)
	}
	sort.SliceStable(aggs, func(i, j int) bool {
		if normalize(aggs[i].bucketARN) != normalize(aggs[j].bucketARN) {
			return normalize(aggs[i].bucketARN) < normalize(aggs[j].bucketARN)
		}
		identI := firstNonEmpty(aggs[i].identityNodeID, aggs[i].principalARN)
		identJ := firstNonEmpty(aggs[j].identityNodeID, aggs[j].principalARN)
		if normalize(identI) != normalize(identJ) {
			return normalize(identI) < normalize(identJ)
		}
		return aggs[i].order < aggs[j].order
	})

	result := Result{
		ObservedAccessConsidered: considered,
		StaticGrantsConsidered:   staticConsidered,
	}
	identities := map[string]struct{}{}
	buckets := map[string]struct{}{}
	for _, agg := range aggs {
		if len(agg.observed) == 0 && len(agg.allow) == 0 {
			continue
		}
		correlation := buildCorrelation(agg, request.DataEventCoverageUnknown)
		result.Correlations = append(result.Correlations, correlation)
		switch correlation.Status {
		case StatusConfirmed:
			result.ConfirmedCount++
		case StatusObservedWithoutGrant:
			result.ObservedWithoutGrant++
		case StatusGrantedUnused:
			result.GrantedUnusedCount++
		}
		if containsString(correlation.ObservedModes, ModeRead) {
			result.ReadCount++
		}
		if containsString(correlation.ObservedModes, ModeWrite) {
			result.WriteCount++
		}
		if containsString(correlation.ObservedModes, ModeList) {
			result.ListCount++
		}
		if containsString(correlation.Caveats, CaveatSensitiveExposed) {
			result.SensitiveExposedCount++
		}
		if containsString(correlation.Caveats, CaveatModeExceedsGrant) {
			result.ModeExceedsGrantCount++
		}
		identities[normalize(firstNonEmpty(correlation.IdentityNodeID, correlation.PrincipalARN))] = struct{}{}
		buckets[normalize(correlation.BucketARN)] = struct{}{}
	}
	result.IdentityCount = len(identities)
	result.BucketCount = len(buckets)

	if request.DataEventCoverageUnknown && (result.GrantedUnusedCount > 0 || considered == 0) {
		result.Caveats = append(result.Caveats, "Runtime evidence is sourced from CloudTrail management-event lookups; S3 GetObject/PutObject/ListBucket data access requires an S3 data-event trail or CloudTrail Lake. 'granted_unused' correlations may reflect missing telemetry rather than truly unused grants.")
	}
	if result.ObservedWithoutGrant > 0 {
		result.Caveats = append(result.Caveats, "Some observed S3 access has no matching static reachability edge. Most S3 access is authorized by IAM identity policies, which this correlation does not enumerate; review these before treating them as drift.")
	}
	return result
}

func buildCorrelation(agg *correlationAgg, dataEventCoverageUnknown bool) Correlation {
	correlation := Correlation{
		IdentityNodeID:    agg.identityNodeID,
		PrincipalARN:      agg.principalARN,
		AccountID:         agg.accountID,
		Region:            agg.region,
		BucketARN:         agg.bucketARN,
		BucketName:        agg.bucketName,
		AgentID:           agg.agentID,
		AgentNodeID:       agg.agentNodeID,
		RedactionBoundary: RedactionBoundary,
	}
	correlation.CorrelationID = correlationID(agg)

	eventIDs := map[string]struct{}{}
	actions := map[string]struct{}{}
	sessions := map[string]struct{}{}
	evidence := map[string]struct{}{}
	observedModes := map[string]struct{}{}
	prefixes := map[string]struct{}{}
	lineageUnresolved := false
	for _, observed := range agg.observed {
		correlation.ObservedCount++
		if id := strings.TrimSpace(observed.EventID); id != "" {
			eventIDs[id] = struct{}{}
		}
		if action := strings.TrimSpace(observed.Action); action != "" {
			actions[action] = struct{}{}
		}
		if session := strings.TrimSpace(observed.SessionID); session != "" {
			sessions[session] = struct{}{}
		}
		if ref := strings.TrimSpace(observed.EvidenceRef); ref != "" {
			evidence[ref] = struct{}{}
		}
		if mode := strings.TrimSpace(observed.AccessMode); mode != "" {
			observedModes[mode] = struct{}{}
		}
		for _, prefix := range observed.SafePrefixes {
			if trimmed := strings.TrimSpace(prefix); trimmed != "" {
				prefixes[trimmed] = struct{}{}
			}
		}
		observedAt := observed.ObservedAt.UTC()
		if !observedAt.IsZero() {
			if correlation.FirstObservedAt.IsZero() || observedAt.Before(correlation.FirstObservedAt) {
				correlation.FirstObservedAt = observedAt
			}
			if observedAt.After(correlation.LastObservedAt) {
				correlation.LastObservedAt = observedAt
			}
		}
		switch strings.TrimSpace(observed.LineageStatus) {
		case "", "resolved":
		default:
			lineageUnresolved = true
		}
	}
	correlation.ObservedEventIDs = sortedKeys(eventIDs)
	correlation.Actions = sortedKeys(actions)
	correlation.SessionIDs = sortedKeys(sessions)
	correlation.ObservedModes = sortedKeys(observedModes)
	correlation.SafePrefixes = sortedKeys(prefixes)

	sources := map[string]struct{}{}
	grantedModes := map[string]struct{}{}
	hasAllow := len(agg.allow) > 0
	conditional := false
	crossAccount := false
	sensitivity := ""
	exposure := ""
	staticConfidence := 0.0
	for _, grant := range agg.allow {
		if src := strings.TrimSpace(grant.Source); src != "" {
			sources[src] = struct{}{}
		}
		for _, mode := range grant.AllowedModes {
			if trimmed := strings.TrimSpace(mode); trimmed != "" {
				grantedModes[trimmed] = struct{}{}
			}
		}
		if grant.Conditional {
			conditional = true
		}
		if grant.CrossAccount {
			crossAccount = true
		}
		if grant.Confidence > staticConfidence {
			staticConfidence = grant.Confidence
		}
		sensitivity = firstNonEmpty(sensitivity, grant.Sensitivity)
		exposure = firstNonEmpty(exposure, grant.Exposure)
		if ref := strings.TrimSpace(grant.EvidenceRef); ref != "" {
			evidence[ref] = struct{}{}
		}
	}
	for _, grant := range agg.deny {
		sensitivity = firstNonEmpty(sensitivity, grant.Sensitivity)
		exposure = firstNonEmpty(exposure, grant.Exposure)
		if ref := strings.TrimSpace(grant.EvidenceRef); ref != "" {
			evidence[ref] = struct{}{}
		}
	}
	correlation.StaticSources = sortedKeys(sources)
	correlation.GrantedModes = sortedKeys(grantedModes)
	correlation.Conditional = conditional
	correlation.CrossAccount = crossAccount
	correlation.Sensitivity = sensitivity
	correlation.Exposure = exposure
	correlation.EvidenceRefs = sortedKeys(evidence)
	hasMatchingDeny := denyMatchesObservedModes(agg.deny, correlation.ObservedModes)

	caveats := map[string]struct{}{}
	switch {
	case correlation.ObservedCount > 0 && hasAllow && !hasMatchingDeny:
		correlation.Status = StatusConfirmed
		correlation.StaticEffect = "Allow"
		correlation.Confidence = 0.95
		if conditional {
			correlation.Confidence -= 0.05
			caveats[CaveatConditionalGrant] = struct{}{}
		}
		if crossAccount {
			caveats[CaveatCrossAccountGrant] = struct{}{}
		}
		if lineageUnresolved {
			if correlation.Confidence > 0.85 {
				correlation.Confidence = 0.85
			}
			caveats[CaveatLineageUnresolved] = struct{}{}
		}
		// An observed mode that the static allow grant does not authorize
		// (e.g. observed write where only read is granted) is genuine
		// drift even though the bucket is reachable — flag it.
		if modesExceedGrant(correlation.ObservedModes, grantedModes) {
			caveats[CaveatModeExceedsGrant] = struct{}{}
			if correlation.Confidence > 0.8 {
				correlation.Confidence = 0.8
			}
		}
	case correlation.ObservedCount > 0:
		// Observed but not a clean confirmation. An explicit Deny
		// overrides any Allow in AWS, so observed access against a bucket
		// carrying a matching Deny is anomalous, never confirmed.
		correlation.Status = StatusObservedWithoutGrant
		correlation.Confidence = 0.6
		if hasMatchingDeny {
			caveats[CaveatObservedDespiteDeny] = struct{}{}
			correlation.StaticEffect = "Deny"
		} else {
			caveats[CaveatNoStaticPath] = struct{}{}
		}
		if lineageUnresolved {
			caveats[CaveatLineageUnresolved] = struct{}{}
		}
	default:
		correlation.Status = StatusGrantedUnused
		correlation.StaticEffect = "Allow"
		correlation.Confidence = 0.7
		if dataEventCoverageUnknown {
			correlation.Confidence = 0.5
			caveats[CaveatDataEventCoverage] = struct{}{}
		}
		if conditional {
			caveats[CaveatConditionalGrant] = struct{}{}
		}
		if crossAccount {
			caveats[CaveatCrossAccountGrant] = struct{}{}
		}
	}
	// A sensitive bucket that is also publicly or cross-account exposed is
	// worth surfacing on any correlation status — it raises the stakes of
	// both observed access and unused grants.
	if isSensitive(sensitivity) && isExposed(exposure) {
		caveats[CaveatSensitiveExposed] = struct{}{}
	}
	correlation.Caveats = sortedKeys(caveats)
	return correlation
}

// modesExceedGrant reports whether any observed mode is absent from the
// granted mode set. An empty granted set with observed modes counts as
// exceeding (the allow grant authorized no recognized mode).
func modesExceedGrant(observedModes []string, grantedModes map[string]struct{}) bool {
	for _, mode := range observedModes {
		if _, ok := grantedModes[mode]; !ok {
			return true
		}
	}
	return false
}

func denyMatchesObservedModes(denies []StaticGrant, observedModes []string) bool {
	if len(denies) == 0 || len(observedModes) == 0 {
		return false
	}
	observed := map[string]struct{}{}
	for _, mode := range observedModes {
		if trimmed := strings.TrimSpace(mode); trimmed != "" {
			observed[normalize(trimmed)] = struct{}{}
		}
	}
	for _, deny := range denies {
		modes := nonEmptyStrings(deny.AllowedModes)
		if len(modes) == 0 {
			return true
		}
		for _, mode := range modes {
			if _, ok := observed[normalize(mode)]; ok {
				return true
			}
		}
	}
	return false
}

func isWildcardPrincipalDeny(grant StaticGrant) bool {
	return strings.EqualFold(strings.TrimSpace(grant.Effect), "Deny") && strings.TrimSpace(grant.PrincipalARN) == "*"
}

func nonEmptyStrings(values []string) []string {
	out := []string{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func isSensitive(sensitivity string) bool {
	switch strings.ToLower(strings.TrimSpace(sensitivity)) {
	case "high", "elevated", "confidential", "restricted", "sensitive", "pii", "phi", "pci":
		return true
	default:
		return false
	}
}

func isExposed(exposure string) bool {
	switch strings.ToLower(strings.TrimSpace(exposure)) {
	case "public", "cross_account":
		return true
	default:
		return false
	}
}

func correlationID(agg *correlationAgg) string {
	identity := firstNonEmpty(agg.identityNodeID, agg.principalARN, "unknown-identity")
	bucket := firstNonEmpty(agg.bucketARN, "unknown-bucket")
	return fmt.Sprintf("%s|%s|%s", ResourceKind, normalize(identity), normalize(bucket))
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
