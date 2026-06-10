package aws

import (
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
)

// s3BucketPolicyDocument is a focused projection of the bucket-policy grammar
// the reachability collector needs. Resource-policy specifics (Principal,
// NotPrincipal, Condition) get explicit handling; the regular policy parser
// in passrole_policy.go is identity-policy oriented and doesn't model
// Principal, so the two stay separate to avoid cross-contamination.
type s3BucketPolicyDocument struct {
	Version   string                 `json:"Version"`
	Statement s3BucketPolicyStmtList `json:"Statement"`
}

type s3BucketPolicyStmtList []s3BucketPolicyStatement

type s3BucketPolicyStatement struct {
	Sid          string         `json:"Sid,omitempty"`
	Effect       string         `json:"Effect"`
	Principal    any            `json:"Principal,omitempty"`
	NotPrincipal any            `json:"NotPrincipal,omitempty"`
	Action       any            `json:"Action,omitempty"`
	NotAction    any            `json:"NotAction,omitempty"`
	Resource     any            `json:"Resource,omitempty"`
	NotResource  any            `json:"NotResource,omitempty"`
	Condition    map[string]any `json:"Condition,omitempty"`
}

// UnmarshalJSON tolerates both single-object and array Statement forms.
func (s *s3BucketPolicyStmtList) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}
	var single s3BucketPolicyStatement
	if err := json.Unmarshal(data, &single); err == nil && single.Effect != "" {
		*s = []s3BucketPolicyStatement{single}
		return nil
	}
	var many []s3BucketPolicyStatement
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	return errors.New("invalid s3 bucket policy statement shape")
}

// parseS3BucketPolicyGrants returns the inferred identity reachability grants
// from a bucket policy plus the statement count for the API summary. Empty
// or absent policies return nil grants, no error.
func parseS3BucketPolicyGrants(raw string) ([]S3IdentityGrant, int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, 0, nil
	}
	decoded := trimmed
	if strings.Contains(trimmed, "%") {
		if unescaped, err := url.QueryUnescape(trimmed); err == nil {
			decoded = unescaped
		}
	}
	var doc s3BucketPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, 0, err
	}
	grants := []S3IdentityGrant{}
	for _, statement := range doc.Statement {
		effect := canonicalS3GrantEffect(statement.Effect)
		if effect == "" {
			continue
		}
		// NotPrincipal has inverse semantics — a statement with NotPrincipal
		// applies to every principal *except* the one(s) listed. Treating the
		// listed principals as regular grants would invert the meaning, so we
		// skip the statement entirely. Surface as a coverage gap rather than
		// silently producing a wrong edge.
		if statement.Principal == nil && statement.NotPrincipal != nil {
			continue
		}
		principals, principalType, wildcardPrincipal := s3ExtractPrincipals(statement.Principal)
		if len(principals) == 0 {
			continue
		}
		actions, notAction := s3ExtractActions(statement.Action, statement.NotAction)
		conditionKeys := s3CollectConditionKeys(statement.Condition)
		hasCondition := len(conditionKeys) > 0
		for _, principal := range principals {
			grants = append(grants, S3IdentityGrant{
				PrincipalARN:      principal,
				PrincipalType:     principalType,
				Effect:            effect,
				Actions:           actions,
				NotAction:         notAction,
				ConditionKeys:     conditionKeys,
				HasCondition:      hasCondition,
				StatementSid:      strings.TrimSpace(statement.Sid),
				WildcardPrincipal: wildcardPrincipal || principal == "*",
				// IsPublic / IsCrossAccount are filled in by annotateS3Grants
				// against the bucket-owning account; we leave them false here
				// and let the normalizer compute them with full context.
			})
		}
	}
	return grants, len(doc.Statement), nil
}

// s3ExtractPrincipals returns the principal ARN list along with the
// principal type (aws, service, federated, canonical_user, *) and whether a
// wildcard principal is present.
func s3ExtractPrincipals(principal any) (principals []string, principalType string, wildcardPrincipal bool) {
	if principal == nil {
		return nil, "", false
	}
	return s3PrincipalsFromAny(principal)
}

func s3PrincipalsFromAny(value any) ([]string, string, bool) {
	switch typed := value.(type) {
	case string:
		if typed == "*" {
			return []string{"*"}, "*", true
		}
		return []string{typed}, "aws", false
	case map[string]any:
		// AWS bucket policies use {"AWS": ARN[]}, {"Service": "lambda.amazonaws.com"},
		// {"Federated": "..."}, {"CanonicalUser": "..."}.
		for _, key := range []string{"AWS", "Service", "Federated", "CanonicalUser"} {
			if raw, ok := typed[key]; ok {
				values := parseStringList(raw)
				wildcard := false
				for _, value := range values {
					if value == "*" {
						wildcard = true
						break
					}
				}
				return values, strings.ToLower(key), wildcard
			}
		}
	}
	return nil, "", false
}

func s3ExtractActions(action, notAction any) ([]string, bool) {
	if list := parseStringList(action); len(list) > 0 {
		return list, false
	}
	if list := parseStringList(notAction); len(list) > 0 {
		return list, true
	}
	return nil, false
}

// s3CollectConditionKeys returns every condition key found in the statement
// (e.g. aws:SourceVpce, aws:PrincipalOrgID, s3:x-amz-server-side-encryption).
// The keys are returned sorted so the API output is deterministic.
func s3CollectConditionKeys(condition map[string]any) []string {
	if len(condition) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, body := range condition {
		bodyMap, ok := body.(map[string]any)
		if !ok {
			continue
		}
		for key := range bodyMap {
			trimmed := strings.TrimSpace(key)
			if trimmed == "" {
				continue
			}
			seen[trimmed] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
