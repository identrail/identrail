package aws

import (
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
)

// kmsKeyPolicyDocument is a focused projection of the KMS key-policy grammar
// the reachability collector needs. KMS key policies share the IAM resource
// policy grammar with S3 bucket policies, but the action namespace is
// kms:*, so we keep a separate parser to keep classification rules close to
// their service semantics.
type kmsKeyPolicyDocument struct {
	Version   string               `json:"Version"`
	ID        string               `json:"Id,omitempty"`
	Statement kmsKeyPolicyStmtList `json:"Statement"`
}

type kmsKeyPolicyStmtList []kmsKeyPolicyStatement

type kmsKeyPolicyStatement struct {
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
func (s *kmsKeyPolicyStmtList) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}
	var single kmsKeyPolicyStatement
	if err := json.Unmarshal(data, &single); err == nil && single.Effect != "" {
		*s = []kmsKeyPolicyStatement{single}
		return nil
	}
	var many []kmsKeyPolicyStatement
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	return errors.New("invalid kms key policy statement shape")
}

// parseKMSKeyPolicyGrants returns the inferred identity reachability grants
// from a key policy, the statement count, and whether the canonical
// "EnableIAMUserPermissions" delegation statement is present. Empty or
// absent policies return nil grants, no error.
func parseKMSKeyPolicyGrants(raw string, ownerAccountID string) ([]KMSIdentityGrant, int, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, 0, false, nil
	}
	decoded := trimmed
	if strings.Contains(trimmed, "%") {
		if unescaped, err := url.QueryUnescape(trimmed); err == nil {
			decoded = unescaped
		}
	}
	var doc kmsKeyPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, 0, false, err
	}
	grants := []KMSIdentityGrant{}
	iamDelegation := false
	for _, statement := range doc.Statement {
		effect := canonicalKMSGrantEffect(statement.Effect)
		if effect == "" {
			continue
		}
		// NotPrincipal has inverse semantics — listing the excluded principal
		// as a regular grant would invert the meaning, so we skip the
		// statement entirely.
		if statement.Principal == nil && statement.NotPrincipal != nil {
			continue
		}
		principals := kmsExtractPrincipals(statement.Principal)
		if len(principals) == 0 {
			continue
		}
		actions, notAction := kmsExtractActions(statement.Action, statement.NotAction)
		if notAction {
			continue
		}
		conditionKeys := kmsCollectConditionKeys(statement.Condition)
		hasCondition := len(conditionKeys) > 0
		for _, principal := range principals {
			grant := KMSIdentityGrant{
				PrincipalARN:      principal.Value,
				PrincipalType:     principal.Type,
				Effect:            effect,
				Actions:           actions,
				NotAction:         notAction,
				ConditionKeys:     conditionKeys,
				HasCondition:      hasCondition,
				StatementSid:      strings.TrimSpace(statement.Sid),
				WildcardPrincipal: principal.Wildcard,
			}
			if isIAMDelegationGrant(grant, ownerAccountID) {
				iamDelegation = true
			}
			grants = append(grants, grant)
		}
	}
	return grants, len(doc.Statement), iamDelegation, nil
}

type kmsParsedPrincipal struct {
	Value    string
	Type     string
	Wildcard bool
}

func kmsExtractPrincipals(principal any) []kmsParsedPrincipal {
	if principal == nil {
		return nil
	}
	return kmsPrincipalsFromAny(principal)
}

func kmsPrincipalsFromAny(value any) []kmsParsedPrincipal {
	switch typed := value.(type) {
	case string:
		if typed == "*" {
			return []kmsParsedPrincipal{{Value: "*", Type: "*", Wildcard: true}}
		}
		return []kmsParsedPrincipal{{Value: typed, Type: "aws"}}
	case map[string]any:
		// KMS key policies use {"AWS": ARN[]}, {"Service": "ec2.amazonaws.com"},
		// {"Federated": "..."}, {"CanonicalUser": "..."}.
		out := []kmsParsedPrincipal{}
		for _, key := range []string{"AWS", "Service", "Federated", "CanonicalUser"} {
			if raw, ok := typed[key]; ok {
				principalType := strings.ToLower(key)
				values := parseStringList(raw)
				for _, value := range values {
					out = append(out, kmsParsedPrincipal{
						Value:    value,
						Type:     principalType,
						Wildcard: value == "*",
					})
				}
			}
		}
		if len(out) > 0 {
			sort.Slice(out, func(i, j int) bool {
				if out[i].Value == out[j].Value {
					return out[i].Type < out[j].Type
				}
				return out[i].Value < out[j].Value
			})
			return out
		}
		if raw, ok := typed["*"]; ok {
			values := parseStringList(raw)
			for _, value := range values {
				if value == "*" {
					return []kmsParsedPrincipal{{Value: "*", Type: "*", Wildcard: true}}
				}
			}
		}
	}
	return nil
}

func kmsExtractActions(action, notAction any) ([]string, bool) {
	if list := parseStringList(action); len(list) > 0 {
		return list, false
	}
	if list := parseStringList(notAction); len(list) > 0 {
		return list, true
	}
	return nil, false
}

// kmsCollectConditionKeys returns every condition key found in the
// statement. The keys are returned sorted so the API output is
// deterministic.
func kmsCollectConditionKeys(condition map[string]any) []string {
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
	sort.Strings(out)
	return out
}
