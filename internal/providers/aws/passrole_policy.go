package aws

import (
	"encoding/json"
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
// IAM's permissive grammar.
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
	*s = nil
	return nil
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

// passRoleActionMatch returns the matched action expression (canonicalized to
// lower-case) and whether the match came from NotAction. The empty string
// means the statement does not bear on PassRole.
func passRoleActionMatch(action, notAction any) (string, bool) {
	if match := passRoleActionInList(action); match != "" {
		return match, false
	}
	if match := passRoleActionInList(notAction); match != "" {
		return match, true
	}
	return "", false
}

func passRoleActionInList(value any) string {
	for _, action := range parseStringList(value) {
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "iam:passrole":
			return "iam:PassRole"
		case "iam:*":
			return "iam:*"
		case "*":
			return "*"
		}
	}
	return ""
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
// grant. Specific role ARNs get the highest score; path-scoped wildcards get a
// middle score; "*" gets the lowest. Deny statements and NotAction/NotResource
// forms are reported with full confidence because we can prove the grant
// shape, even though their downstream effect is conditional.
func passRoleGrantConfidence(grant passRoleGrant) float64 {
	target := strings.TrimSpace(grant.TargetResource)
	switch {
	case target == "*":
		return 0.55
	case strings.Contains(target, "*") && strings.HasPrefix(target, "arn:"):
		return 0.78
	case strings.HasPrefix(target, "arn:") && !strings.Contains(target, "*"):
		return 0.95
	default:
		return 0.6
	}
}

// passRoleGrantWildcardKind classifies a grant's target shape so the API can
// surface "this is a wildcard" without consumers re-parsing the ARN. Returns
// one of "specific", "path_wildcard", "account_wildcard", or "all".
func passRoleGrantWildcardKind(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "*" {
		return "all"
	}
	if !strings.HasPrefix(trimmed, "arn:") {
		return "specific"
	}
	if !strings.Contains(trimmed, "*") {
		return "specific"
	}
	// arn:aws:iam::*:role/... — account-position wildcard
	parts := strings.SplitN(trimmed, ":", 6)
	if len(parts) >= 5 && parts[4] == "*" {
		return "account_wildcard"
	}
	return "path_wildcard"
}
