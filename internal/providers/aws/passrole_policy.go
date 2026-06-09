package aws

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// passRolePolicyDocument is a fuller view of an IAM policy used by the PassRole
// extractor. The core model.go parser ignores NotAction, NotResource, Sid, and
// Condition because the existing collectors do not need them; PassRole analysis
// does, so we keep a dedicated structure rather than mutating the shared model.
type passRolePolicyDocument struct {
	Version   string                    `json:"Version"`
	Statement passRolePolicyStatementsT `json:"Statement"`
}

type passRolePolicyStatementsT []passRolePolicyStatement

type passRolePolicyStatement struct {
	Sid         string         `json:"Sid,omitempty"`
	Effect      string         `json:"Effect"`
	Action      any            `json:"Action,omitempty"`
	NotAction   any            `json:"NotAction,omitempty"`
	Resource    any            `json:"Resource,omitempty"`
	NotResource any            `json:"NotResource,omitempty"`
	Condition   map[string]any `json:"Condition,omitempty"`
}

// UnmarshalJSON lets statements arrive as a single object or an array, matching
// IAM's permissive grammar. Genuinely malformed shapes (neither a statement
// object nor an array) propagate as an error so the collector can record a
// parse-failure diagnostic instead of silently treating the policy as empty.
func (s *passRolePolicyStatementsT) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}
	var single passRolePolicyStatement
	if err := json.Unmarshal(data, &single); err == nil && single.Effect != "" {
		*s = []passRolePolicyStatement{single}
		return nil
	}
	var many []passRolePolicyStatement
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	return errors.New("invalid passrole policy statement shape")
}

// parsePassRolePolicyDocument decodes a possibly URL-encoded IAM policy
// document and returns the parsed structure. An empty input yields an empty
// document, not an error, so callers can fan out without nil checks.
func parsePassRolePolicyDocument(raw string) (passRolePolicyDocument, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return passRolePolicyDocument{}, nil
	}
	decoded := trimmed
	if strings.Contains(trimmed, "%") {
		if unescaped, err := url.QueryUnescape(trimmed); err == nil {
			decoded = unescaped
		}
	}
	var doc passRolePolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return passRolePolicyDocument{}, err
	}
	return doc, nil
}

// passRoleGrant is one extracted PassRole grant. One statement can produce
// multiple grants — one per (target resource, condition value) tuple — so the
// graph can carry per-target edges even when the policy folds them together.
type passRoleGrant struct {
	Effect           string   // "Allow" or "Deny" (canonical)
	Sid              string   // operator-facing evidence anchor; empty when absent
	TargetResource   string   // the resource ARN or wildcard the grant points at
	ServiceCondition string   // value of iam:PassedToService when present; empty otherwise
	ConditionOp      string   // operator that owned the service condition (e.g. StringEquals)
	ActionExpression string   // the action expression that matched (iam:PassRole, iam:*, *)
	NotAction        bool     // true when the matching statement used NotAction
	NotResource      bool     // true when the matching statement used NotResource
	OtherConditions  []string // condition keys present beyond iam:PassedToService (for reasoning)
}

// extractPassRoleGrants returns every PassRole grant emitted by the supplied
// policy document. The function never touches the network or filesystem.
func extractPassRoleGrants(doc passRolePolicyDocument) []passRoleGrant {
	grants := []passRoleGrant{}
	for _, statement := range doc.Statement {
		effect, ok := canonicalEffect(statement.Effect)
		if !ok {
			continue
		}
		// PassRole can appear as iam:PassRole, iam:*, or *, with either Action
		// (positive grant) or NotAction (inverse grant). Capture which form the
		// statement used so consumers can distinguish them.
		match, notAction := passRoleActionMatch(statement.Action, statement.NotAction)
		if match == "" {
			continue
		}
		resources, notResource := passRoleResourceTargets(statement.Resource, statement.NotResource)
		if len(resources) == 0 {
			// A statement with neither Resource nor NotResource is malformed;
			// emit a synthetic "*" target so consumers still see the grant
			// and can flag it for review.
			resources = []string{"*"}
		}
		serviceConditions, otherConditionKeys := extractPassedToServiceCondition(statement.Condition)
		if len(serviceConditions) == 0 {
			// No iam:PassedToService — emit one grant per target with no
			// service binding. The graph will reflect that this PassRole is
			// not restricted to a single AWS service.
			serviceConditions = []serviceConditionMatch{{}}
		}
		for _, target := range resources {
			for _, condition := range serviceConditions {
				grants = append(grants, passRoleGrant{
					Effect:           effect,
					Sid:              strings.TrimSpace(statement.Sid),
					TargetResource:   target,
					ServiceCondition: condition.value,
					ConditionOp:      condition.operator,
					ActionExpression: match,
					NotAction:        notAction,
					NotResource:      notResource,
					OtherConditions:  otherConditionKeys,
				})
			}
		}
	}
	return grants
}

// passRoleActionMatch returns the matched action expression and whether the
// matching statement used NotAction (inverse) form. The empty string means
// the statement does not bear on PassRole.
//
// IAM NotAction semantics: when a statement uses NotAction, it applies to
// every action *except* those listed. So a PassRole grant exists when:
//
//   - Action explicitly lists iam:PassRole (or a wildcard that matches it), or
//   - NotAction is present and does *not* list iam:PassRole — in that case
//     iam:PassRole is one of the implicit "all other actions" the statement
//     applies to. We flag the result so downstream consumers can mark these
//     grants as inverse and reason about the implicit-everything-else set.
//
// Conversely, NotAction listing iam:PassRole means iam:PassRole is explicitly
// excluded, so the statement does not grant PassRole at all and we return "".
func passRoleActionMatch(action, notAction any) (string, bool) {
	if match := passRoleActionInList(action); match != "" {
		return match, false
	}
	notActionValues := parseStringList(notAction)
	if len(notActionValues) == 0 {
		return "", false
	}
	if passRoleActionInList(notAction) != "" {
		// NotAction explicitly excludes iam:PassRole (directly or via a
		// matching wildcard) — the statement does not grant PassRole.
		return "", false
	}
	// NotAction is present but does not exclude iam:PassRole; iam:PassRole is
	// in the implicit "everything else" set this statement applies to.
	return "iam:PassRole", true
}

// passRoleActionInList returns the matched action expression. It covers the
// exact spelling (iam:PassRole), AWS-style action wildcards that contain
// PassRole (e.g. iam:Pass*, iam:P*, iam:Pa?sRole), and the broad wildcards
// (iam:*, *). Each accepted expression is returned in its canonical original
// casing so downstream code can surface the grant's policy text verbatim.
func passRoleActionInList(value any) string {
	for _, action := range parseStringList(value) {
		trimmed := strings.TrimSpace(action)
		switch strings.ToLower(trimmed) {
		case "iam:passrole":
			return "iam:PassRole"
		case "iam:*":
			return "iam:*"
		case "*":
			return "*"
		}
		if iamActionWildcardMatchesPassRole(trimmed) {
			return trimmed
		}
	}
	return ""
}

// iamActionWildcardMatchesPassRole reports whether the supplied IAM action
// expression — using the AWS wildcard syntax — could match iam:PassRole. The
// AWS docs describe two wildcards: * matches any sequence of characters and ?
// matches a single character. We treat any wildcarded iam: action whose
// pattern accepts the literal "PassRole" as a PassRole grant so policies that
// use iam:Pass*, iam:Pa?sRole, or iam:Pass??le are not silently missed.
func iamActionWildcardMatchesPassRole(expr string) bool {
	lowered := strings.ToLower(expr)
	if !strings.HasPrefix(lowered, "iam:") {
		return false
	}
	pattern := lowered[len("iam:"):]
	if !strings.ContainsAny(pattern, "*?") {
		// No wildcard — exact match already handled by the caller's switch.
		return false
	}
	return iamActionPatternMatches(pattern, "passrole")
}

// iamActionPatternMatches reports whether the AWS-style pattern (with * and ?
// wildcards) matches the target string. It uses an iterative back-tracking
// matcher rather than translating to a regular expression so it never panics
// or hits regex-engine limits on adversarial inputs.
func iamActionPatternMatches(pattern, target string) bool {
	pi, ti := 0, 0
	starPi, starTi := -1, 0
	for ti < len(target) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == target[ti]):
			pi++
			ti++
		case pi < len(pattern) && pattern[pi] == '*':
			starPi = pi
			starTi = ti
			pi++
		case starPi != -1:
			pi = starPi + 1
			starTi++
			ti = starTi
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// passRoleResourceTargets returns the deduplicated, trimmed resource list and
// whether NotResource was used. A NotResource form means "every role except
// these" — we still emit those entries so the graph can reflect the inverse
// shape.
func passRoleResourceTargets(resource, notResource any) ([]string, bool) {
	if values := dedupeStrings(parseStringList(resource)); len(values) > 0 {
		return values, false
	}
	if values := dedupeStrings(parseStringList(notResource)); len(values) > 0 {
		return values, true
	}
	return nil, false
}

type serviceConditionMatch struct {
	value    string
	operator string
}

// extractPassedToServiceCondition pulls the iam:PassedToService condition (if
// present) and returns every matching service. Any condition key besides
// iam:PassedToService is returned separately so consumers can still see the
// statement is restricted (without us inventing graph semantics for arbitrary
// condition keys this wave).
func extractPassedToServiceCondition(condition map[string]any) ([]serviceConditionMatch, []string) {
	if len(condition) == 0 {
		return nil, nil
	}
	matches := []serviceConditionMatch{}
	otherKeys := map[string]struct{}{}
	for operator, body := range condition {
		bodyMap, ok := body.(map[string]any)
		if !ok {
			continue
		}
		for key, raw := range bodyMap {
			if strings.EqualFold(strings.TrimSpace(key), "iam:PassedToService") {
				for _, service := range parseStringList(raw) {
					trimmed := strings.TrimSpace(service)
					if trimmed == "" {
						continue
					}
					matches = append(matches, serviceConditionMatch{
						value:    trimmed,
						operator: strings.TrimSpace(operator),
					})
				}
				continue
			}
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			otherKeys[trimmedKey] = struct{}{}
		}
	}
	others := make([]string, 0, len(otherKeys))
	for key := range otherKeys {
		others = append(others, key)
	}
	return matches, others
}

// passRoleGrantConfidence returns a confidence score in [0, 1] for a single
// grant. The score is keyed off the wildcard-kind classification so the two
// stay consistent: a target classified as malformed (e.g. a non-IAM ARN like
// arn:aws:s3:::bucket) never gets a high confidence score just because it
// has the arn: prefix. Specific IAM role ARNs get the highest score;
// path-scoped wildcards a middle score; account-position wildcards slightly
// lower; "*" lower still; malformed lowest.
func passRoleGrantConfidence(grant passRoleGrant) float64 {
	switch passRoleGrantWildcardKind(grant.TargetResource) {
	case "specific":
		return 0.95
	case "path_wildcard":
		return 0.78
	case "account_wildcard":
		return 0.7
	case "all":
		return 0.55
	default:
		// malformed (or any future unknown kind) — low-confidence so
		// downstream consumers know not to act on it.
		return 0.3
	}
}

// passRoleGrantWildcardKind classifies a grant's target shape so the API can
// surface "this is a wildcard" without consumers re-parsing the ARN. Returns
// "specific" (concrete IAM role ARN), "path_wildcard", "account_wildcard",
// "all" (bare "*"), or "malformed" for anything else — a typo'd resource, a
// non-ARN string, or a valid ARN of a different service (S3 bucket, Lambda
// function). Only IAM role ARNs resolve to "specific"/"path_wildcard"/
// "account_wildcard" so the graph never gets a PassRole edge pointing at a
// non-role resource.
func passRoleGrantWildcardKind(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "*" {
		return "all"
	}
	if !strings.HasPrefix(trimmed, "arn:") {
		return "malformed"
	}
	parts := strings.SplitN(trimmed, ":", 6)
	if len(parts) != 6 {
		return "malformed"
	}
	if !strings.EqualFold(parts[2], "iam") {
		return "malformed"
	}
	if !strings.HasPrefix(parts[5], "role/") {
		return "malformed"
	}
	if !strings.Contains(trimmed, "*") {
		return "specific"
	}
	if parts[4] == "*" {
		return "account_wildcard"
	}
	return "path_wildcard"
}
