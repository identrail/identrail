// Package secretsaccess correlates observed Secrets Manager read and KMS
// decrypt runtime events with the static reachability edges Identrail
// already discovered (KMS key-policy / grant `can_decrypt` edges and
// Secrets Manager resource-policy grants). The output ties observed
// behavior back to identity, session, resource, and agent context so an
// operator can answer three distinct questions per (identity, resource)
// pair:
//
//   - confirmed:               the identity was statically allowed to
//     reach the secret/key AND was observed doing so. This is the
//     "proof" state — behavior matches policy.
//   - observed_without_grant:  the identity was observed reading the
//     secret / decrypting the key but no static allow edge explains it.
//     Either static reachability collection is incomplete (most secret
//     reads are authorized by IAM identity policies, which this wave's
//     static collectors do not enumerate) or the access drifted from
//     the modeled grants. Treated as a caveat, never a silent success.
//   - granted_unused:          a static allow edge exists but no runtime
//     access was observed in the window. Surfaces over-provisioned
//     grants — but carries a mandatory missing-event caveat because
//     Secrets Manager GetSecretValue and KMS Decrypt are CloudTrail
//     *data* events; absence in a management-event lookup is not proof
//     the access never happened.
//
// Safety boundary: the engine is metadata-only. It never reads, logs, or
// persists secret values, decrypted plaintext, encryption-context
// values, or any other customer payload. It operates purely on the
// already-redacted runtime-event and reachability contracts produced
// upstream, and every emitted correlation re-stamps the redaction
// boundary so downstream consumers cannot mistake it for payload-bearing
// evidence.
package secretsaccess

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Resource kinds the correlator understands. They mirror the runtime
// event `event_type` → resource mapping (secret-read → secret,
// kms-decrypt → kms_key).
const (
	ResourceKindSecret = "secret"
	ResourceKindKMSKey = "kms_key"
)

// Correlation statuses. These are the operator-facing classification of
// a single (identity, resource) correlation.
const (
	StatusConfirmed            = "confirmed"
	StatusObservedWithoutGrant = "observed_without_grant"
	StatusGrantedUnused        = "granted_unused"
)

// Static grant sources. Mirror the upstream reachability collectors so
// the correlation can attribute which static signal corroborated an
// observed access.
const (
	SourceKeyPolicy      = "key_policy"
	SourceKMSGrant       = "kms_grant"
	SourceResourcePolicy = "resource_policy"
)

const (
	// CollectorName tags every diagnostic and result the correlator
	// emits so the API layer can scope diagnostics by collector.
	CollectorName = "aws_secrets_kms_runtime_access"

	// RedactionBoundary documents that the correlator only ever crossed
	// the metadata boundary — no secret values, no decrypted plaintext,
	// no encryption-context values.
	RedactionBoundary = "metadata_only_no_secret_values_no_plaintext"
)

// Caveat codes attached to individual correlations or the result. They
// are stable tokens so the UI and downstream consumers can branch on
// them without string-matching prose.
const (
	CaveatDataEventCoverage   = "runtime_data_events_may_be_incomplete"
	CaveatNoStaticPath        = "no_static_reachability_edge"
	CaveatObservedDespiteDeny = "observed_despite_explicit_deny"
	CaveatConditionalGrant    = "static_grant_is_conditional"
	CaveatCrossAccountGrant   = "static_grant_is_cross_account"
	CaveatLineageUnresolved   = "session_lineage_unresolved"
	CaveatResourceUnresolved  = "runtime_resource_arn_unresolved"
)

// ObservedAccess is one metadata-only runtime secret-read or kms-decrypt
// event projected from the runtime-event contract. Every field is
// payload-safe.
type ObservedAccess struct {
	EventID         string
	IdentityNodeID  string
	PrincipalARN    string
	AccountID       string
	Region          string
	ResourceKind    string
	ResourceARN     string
	ResourceName    string
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

// StaticGrant is one static reachability edge from the KMS or Secrets
// Manager reachability collectors, projected into a single shape the
// correlator can join against runtime events.
type StaticGrant struct {
	IdentityNodeID string
	PrincipalARN   string
	AccountID      string
	Region         string
	ResourceKind   string
	ResourceARN    string
	ResourceName   string
	Source         string // key_policy | kms_grant | resource_policy
	Effect         string // Allow | Deny
	Conditional    bool
	CrossAccount   bool
	Confidence     float64
	EvidenceRef    string
	// Actions contains the raw action strings observed on this static edge.
	// When present, static actions must match each observed action
	// before an access can be confirmed for resource kinds that require
	// action authorization (Secrets Manager and KMS key).
	Actions []string
}

// CorrelateRequest configures one correlation pass.
type CorrelateRequest struct {
	AccountID string
	Region    string
	Observed  []ObservedAccess
	Static    []StaticGrant
	// DataEventCoverageUnknown marks that the observed set comes from a
	// runtime source that does not guarantee Secrets Manager / KMS data
	// events are captured (e.g. CloudTrail LookupEvents only indexes
	// management events). When true, every granted_unused correlation
	// and the result envelope carry the missing-event caveat so an
	// operator never reads "unused" as "definitely never used".
	DataEventCoverageUnknown bool
}

// Correlation is one (identity, resource) correlation record.
type Correlation struct {
	CorrelationID     string
	IdentityNodeID    string
	PrincipalARN      string
	AccountID         string
	Region            string
	ResourceKind      string
	ResourceARN       string
	ResourceName      string
	Status            string
	Confidence        float64
	ObservedCount     int
	ObservedEventIDs  []string
	Actions           []string
	SessionIDs        []string
	AgentID           string
	AgentNodeID       string
	FirstObservedAt   time.Time
	LastObservedAt    time.Time
	StaticSources     []string
	StaticEffect      string
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
	SecretCorrelationCount   int
	KMSKeyCorrelationCount   int
	IdentityCount            int
	ResourceCount            int
	ObservedAccessConsidered int
	StaticGrantsConsidered   int
}

type correlationKey struct {
	identity string
	resource string
}

type correlationAgg struct {
	identityNodeID string
	principalARN   string
	accountID      string
	region         string
	resourceKind   string
	resourceARN    string
	resourceName   string
	agentID        string
	agentNodeID    string
	observed       []ObservedAccess
	allow          []StaticGrant
	deny           []StaticGrant
	order          int
}

// Correlate joins observed runtime accesses with static reachability
// grants and returns one correlation per (identity, resource) pair. It
// never returns an error: documented gaps (no static path, missing data
// events, unresolved resource ARNs) surface as per-correlation and
// result-level caveats so the API layer can return a stable response.
func Correlate(request CorrelateRequest) Result {
	index := map[correlationKey]*correlationAgg{}
	order := 0
	get := func(identityNode, principal, account, region, kind, arn, name string) *correlationAgg {
		identity := firstNonEmpty(identityNode, principal)
		// When the runtime event did not resolve a resource ARN, keying on
		// the ARN alone collapses every unresolved access for an identity
		// into one aggregate — so an unresolved secret-read and an
		// unresolved kms-decrypt by the same role would merge and the later
		// event would inherit the first event's resource_kind, corrupting
		// the counts and resource_kind filter. Discriminate by kind when
		// the ARN is missing so the two kinds stay separate.
		resourceKey := normalize(arn)
		if resourceKey == "" {
			resourceKey = "unresolved:" + normalize(kind)
		}
		k := correlationKey{identity: normalize(identity), resource: resourceKey}
		agg, ok := index[k]
		if !ok {
			agg = &correlationAgg{
				identityNodeID: strings.TrimSpace(identityNode),
				principalARN:   strings.TrimSpace(principal),
				accountID:      strings.TrimSpace(account),
				region:         strings.TrimSpace(region),
				resourceKind:   strings.TrimSpace(kind),
				resourceARN:    strings.TrimSpace(arn),
				resourceName:   strings.TrimSpace(name),
				order:          order,
			}
			order++
			index[k] = agg
		}
		// Backfill identifiers that one side may carry and the other may
		// not (e.g. the runtime event resolves a principal ARN the
		// static edge lacked, or the static edge names the resource).
		if agg.identityNodeID == "" {
			agg.identityNodeID = strings.TrimSpace(identityNode)
		}
		if agg.principalARN == "" {
			agg.principalARN = strings.TrimSpace(principal)
		}
		if agg.resourceKind == "" {
			agg.resourceKind = strings.TrimSpace(kind)
		}
		if agg.resourceName == "" {
			agg.resourceName = strings.TrimSpace(name)
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
			// Cannot attribute the access to an identity — skip rather
			// than invent an "unknown" node that would join nothing.
			continue
		}
		considered++
		agg := get(observed.IdentityNodeID, observed.PrincipalARN, observed.AccountID, observed.Region, observed.ResourceKind, observed.ResourceARN, observed.ResourceName)
		agg.observed = append(agg.observed, observed)
		if agg.agentID == "" {
			agg.agentID = strings.TrimSpace(observed.AgentID)
		}
		if agg.agentNodeID == "" {
			agg.agentNodeID = strings.TrimSpace(observed.AgentNodeID)
		}
	}

	staticConsidered := 0
	wildcardDenyByResource := map[string][]StaticGrant{}
	for _, grant := range request.Static {
		if strings.TrimSpace(grant.IdentityNodeID) == "" && strings.TrimSpace(grant.PrincipalARN) == "" {
			continue
		}
		if strings.TrimSpace(grant.ResourceARN) == "" {
			continue
		}
		if isResourceWildcardPrincipalDeny(grant) {
			key := staticResourceIdentityKey(grant.ResourceKind, grant.ResourceARN)
			wildcardDenyByResource[key] = append(wildcardDenyByResource[key], grant)
			staticConsidered++
			continue
		}
		staticConsidered++
		agg := get(grant.IdentityNodeID, grant.PrincipalARN, grant.AccountID, grant.Region, grant.ResourceKind, grant.ResourceARN, grant.ResourceName)
		if strings.EqualFold(strings.TrimSpace(grant.Effect), "Deny") {
			agg.deny = append(agg.deny, grant)
		} else {
			agg.allow = append(agg.allow, grant)
		}
	}

	for _, agg := range index {
		wildcardDenyKey := staticResourceIdentityKey(agg.resourceKind, agg.resourceARN)
		if wildcardDenyForResource, ok := wildcardDenyByResource[wildcardDenyKey]; ok {
			agg.deny = append(agg.deny, wildcardDenyForResource...)
		}
	}

	aggs := make([]*correlationAgg, 0, len(index))
	for _, agg := range index {
		aggs = append(aggs, agg)
	}
	sort.SliceStable(aggs, func(i, j int) bool {
		if aggs[i].resourceKind != aggs[j].resourceKind {
			return aggs[i].resourceKind < aggs[j].resourceKind
		}
		if normalize(aggs[i].resourceARN) != normalize(aggs[j].resourceARN) {
			return normalize(aggs[i].resourceARN) < normalize(aggs[j].resourceARN)
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
	resources := map[string]struct{}{}
	for _, agg := range aggs {
		// A correlation needs at least one observed access or one allow
		// grant. A resource that only ever appears with a deny grant has
		// no reachability and was never observed, so there is nothing to
		// correlate.
		if len(agg.observed) == 0 && len(agg.allow) == 0 {
			continue
		}
		if len(agg.observed) == 0 && len(agg.deny) > 0 && !staticOnlyAllowHasUndeniedAction(agg) {
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
		switch correlation.ResourceKind {
		case ResourceKindSecret:
			result.SecretCorrelationCount++
		case ResourceKindKMSKey:
			result.KMSKeyCorrelationCount++
		}
		identities[normalize(firstNonEmpty(correlation.IdentityNodeID, correlation.PrincipalARN))] = struct{}{}
		resources[normalize(correlation.ResourceARN)] = struct{}{}
	}
	result.IdentityCount = len(identities)
	result.ResourceCount = len(resources)

	if request.DataEventCoverageUnknown && (result.GrantedUnusedCount > 0 || considered == 0) {
		result.Caveats = append(result.Caveats, "Runtime evidence is sourced from CloudTrail management-event lookups; Secrets Manager GetSecretValue and KMS Decrypt are data events that require a data-event trail or CloudTrail Lake. 'granted_unused' correlations may reflect missing telemetry rather than truly unused grants.")
	}
	if result.ObservedWithoutGrant > 0 {
		result.Caveats = append(result.Caveats, "Some observed reads have no matching static reachability edge. Most Secrets Manager access is authorized by IAM identity policies, which this correlation does not enumerate; review these before treating them as drift.")
	}
	return result
}

func staticResourceIdentityKey(resourceKind, resourceARN string) string {
	return normalize(resourceKind) + "::" + normalize(resourceARN)
}

func isResourceWildcardPrincipalDeny(grant StaticGrant) bool {
	if !strings.EqualFold(strings.TrimSpace(grant.Effect), "Deny") {
		return false
	}
	return strings.TrimSpace(grant.PrincipalARN) == "*"
}

func buildCorrelation(agg *correlationAgg, dataEventCoverageUnknown bool) Correlation {
	correlation := Correlation{
		IdentityNodeID:    agg.identityNodeID,
		PrincipalARN:      agg.principalARN,
		AccountID:         agg.accountID,
		Region:            agg.region,
		ResourceKind:      agg.resourceKind,
		ResourceARN:       agg.resourceARN,
		ResourceName:      agg.resourceName,
		AgentID:           agg.agentID,
		AgentNodeID:       agg.agentNodeID,
		RedactionBoundary: RedactionBoundary,
	}
	correlation.CorrelationID = correlationID(agg)

	eventIDs := map[string]struct{}{}
	actions := map[string]struct{}{}
	sessions := map[string]struct{}{}
	evidence := map[string]struct{}{}
	lineageUnresolved := false
	resourceUnresolved := false
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
		if strings.TrimSpace(observed.ResourceARN) == "" {
			resourceUnresolved = true
		}
	}
	correlation.ObservedEventIDs = sortedKeys(eventIDs)
	correlation.Actions = sortedKeys(actions)
	correlation.SessionIDs = sortedKeys(sessions)

	sources := map[string]struct{}{}
	hasAllow := len(agg.allow) > 0
	hasMatchingDeny := observedResourceActionDenyAppliesToObserved(agg)
	conditional := false
	crossAccount := false
	staticConfidence := 0.0
	for _, grant := range agg.allow {
		if src := strings.TrimSpace(grant.Source); src != "" {
			sources[src] = struct{}{}
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
		if ref := strings.TrimSpace(grant.EvidenceRef); ref != "" {
			evidence[ref] = struct{}{}
		}
	}
	for _, grant := range agg.deny {
		if ref := strings.TrimSpace(grant.EvidenceRef); ref != "" {
			evidence[ref] = struct{}{}
		}
	}
	correlation.StaticSources = sortedKeys(sources)
	correlation.Conditional = conditional
	correlation.CrossAccount = crossAccount
	correlation.EvidenceRefs = sortedKeys(evidence)

	caveats := map[string]struct{}{}
	switch {
	case correlation.ObservedCount > 0 && hasAllow && !hasMatchingDeny && allObservedActionsAuthorizedByStatic(agg):
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
	case correlation.ObservedCount > 0:
		// Observed, but not a clean confirmation. An explicit Deny in AWS
		// overrides any Allow, so an observed access against a resource
		// that carries a specific Deny is anomalous — never confirmed —
		// even when an Allow is also present. Surface it as observed
		// despite deny rather than reporting a clean confirmation. The
		// no-static-path caveat only applies when there is genuinely no
		// allow edge (and no deny) explaining the access.
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
		if resourceUnresolved {
			caveats[CaveatResourceUnresolved] = struct{}{}
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
	correlation.Caveats = sortedKeys(caveats)
	return correlation
}

func allObservedActionsAuthorizedByStatic(agg *correlationAgg) bool {
	if len(agg.observed) == 0 || len(agg.allow) == 0 {
		return false
	}
	if !resourceKindRequiresActionMatching(strings.TrimSpace(agg.resourceKind)) {
		return true
	}

	observedActions := observedResourceActions(agg)
	if len(observedActions) == 0 {
		return true
	}

	for action := range observedActions {
		actionMatched := false
		for _, grant := range agg.allow {
			// Legacy/compat grants may omit action details. Treat them as
			// providing no stricter action requirement so they do not
			// accidentally block confirmations.
			if len(grant.Actions) == 0 {
				actionMatched = true
				break
			}

			for _, allowedAction := range grant.Actions {
				if staticGrantActionAuthorizesObservedAction(action, allowedAction) {
					actionMatched = true
					break
				}
			}
			if actionMatched {
				break
			}
		}
		if !actionMatched {
			return false
		}
	}
	return true
}

func observedResourceActions(agg *correlationAgg) map[string]struct{} {
	observedActions := map[string]struct{}{}
	for _, observed := range agg.observed {
		if !resourceKindRequiresActionMatching(strings.TrimSpace(agg.resourceKind)) {
			continue
		}
		action := strings.TrimSpace(strings.ToLower(observed.Action))
		if action == "" {
			continue
		}
		observedActions[action] = struct{}{}
	}
	return observedActions
}

func observedResourceActionDenyAppliesToObserved(agg *correlationAgg) bool {
	if len(agg.observed) == 0 {
		return false
	}
	if !resourceKindRequiresActionMatching(strings.TrimSpace(agg.resourceKind)) {
		return len(agg.deny) > 0
	}
	observedActions := observedResourceActions(agg)
	if len(agg.deny) == 0 {
		return false
	}
	if len(observedActions) == 0 {
		return true
	}
	for action := range observedActions {
		denied := false
		for _, deny := range agg.deny {
			if len(deny.Actions) == 0 {
				denied = true
				break
			}
			for _, deniedAction := range deny.Actions {
				if staticGrantActionAuthorizesObservedAction(action, deniedAction) {
					denied = true
					break
				}
			}
			if denied {
				break
			}
		}
		if denied {
			return true
		}
	}
	return false
}

func staticOnlyAllowHasUndeniedAction(agg *correlationAgg) bool {
	if len(agg.allow) == 0 {
		return false
	}
	if len(agg.deny) == 0 {
		return true
	}
	if !resourceKindRequiresActionMatching(strings.TrimSpace(agg.resourceKind)) {
		return false
	}
	for _, allow := range agg.allow {
		if len(allow.Actions) == 0 {
			if !staticGrantHasUnconditionalDeny(agg.deny) {
				return true
			}
			continue
		}
		for _, allowedAction := range allow.Actions {
			if !staticAllowedActionCoveredByDeny(allowedAction, agg.deny) {
				return true
			}
		}
	}
	return false
}

func staticGrantHasUnconditionalDeny(denies []StaticGrant) bool {
	for _, deny := range denies {
		if len(deny.Actions) == 0 {
			return true
		}
		for _, deniedAction := range deny.Actions {
			if strings.TrimSpace(deniedAction) == "*" {
				return true
			}
		}
	}
	return false
}

func staticAllowedActionCoveredByDeny(allowedAction string, denies []StaticGrant) bool {
	allowed := strings.ToLower(strings.TrimSpace(allowedAction))
	if allowed == "" {
		return true
	}
	for _, deny := range denies {
		if len(deny.Actions) == 0 {
			return true
		}
		for _, deniedAction := range deny.Actions {
			denied := strings.ToLower(strings.TrimSpace(deniedAction))
			if denied == "" {
				continue
			}
			if denied == "*" || denied == allowed {
				return true
			}
			if !strings.ContainsAny(allowed, "*?") && staticGrantActionAuthorizesObservedAction(allowed, denied) {
				return true
			}
			if strings.ContainsAny(allowed, "*?") && denied == allowed {
				return true
			}
		}
	}
	return false
}

func resourceKindRequiresActionMatching(resourceKind string) bool {
	return strings.EqualFold(strings.TrimSpace(resourceKind), ResourceKindKMSKey) ||
		strings.EqualFold(strings.TrimSpace(resourceKind), ResourceKindSecret)
}

func staticGrantActionAuthorizesObservedAction(observedAction string, allowedAction string) bool {
	observed := strings.ToLower(strings.TrimSpace(observedAction))
	allowed := strings.ToLower(strings.TrimSpace(allowedAction))
	if observed == "" || allowed == "" {
		return false
	}
	if allowed == "*" {
		return true
	}
	if strings.ContainsAny(allowed, "*?") {
		return actionPatternMatches(allowed, observed)
	}
	if observed == allowed {
		return true
	}

	observedVerb := observed
	if _, suffix, ok := strings.Cut(observed, ":"); ok {
		observedVerb = suffix
	}
	allowedVerb := allowed
	if _, suffix, ok := strings.Cut(allowed, ":"); ok {
		allowedVerb = suffix
	}
	return strings.EqualFold(observedVerb, allowedVerb)
}

func actionPatternMatches(pattern string, value string) bool {
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

func correlationID(agg *correlationAgg) string {
	identity := firstNonEmpty(agg.identityNodeID, agg.principalARN, "unknown-identity")
	kind := firstNonEmpty(agg.resourceKind, "resource")
	resource := firstNonEmpty(agg.resourceARN, "unknown-resource")
	return fmt.Sprintf("%s|%s|%s", kind, normalize(identity), normalize(resource))
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
