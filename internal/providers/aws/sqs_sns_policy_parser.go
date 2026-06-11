package aws

import (
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
)

type sqsSNSPolicyDocument struct {
	Version   string              `json:"Version"`
	Statement sqsSNSPolicyStmtSet `json:"Statement"`
}

type sqsSNSPolicyStmtSet []sqsSNSPolicyStatement

type sqsSNSPolicyStatement struct {
	Sid          string         `json:"Sid,omitempty"`
	Effect       string         `json:"Effect"`
	Principal    any            `json:"Principal,omitempty"`
	NotPrincipal any            `json:"NotPrincipal,omitempty"`
	Action       any            `json:"Action,omitempty"`
	NotAction    any            `json:"NotAction,omitempty"`
	Resource     any            `json:"Resource,omitempty"`
	Condition    map[string]any `json:"Condition,omitempty"`
}

func (s *sqsSNSPolicyStmtSet) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}
	var single sqsSNSPolicyStatement
	if err := json.Unmarshal(data, &single); err == nil && single.Effect != "" {
		*s = []sqsSNSPolicyStatement{single}
		return nil
	}
	var many []sqsSNSPolicyStatement
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	return errors.New("invalid sqs/sns policy statement shape")
}

func parseSQSSNSPolicyGrants(raw string, service string) ([]SQSSNSIdentityGrant, int, error) {
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
	var doc sqsSNSPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, 0, err
	}
	grants := []SQSSNSIdentityGrant{}
	for _, statement := range doc.Statement {
		effect := canonicalSQSSNSGrantEffect(statement.Effect)
		if effect == "" {
			continue
		}
		if statement.Principal == nil && statement.NotPrincipal != nil {
			continue
		}
		principals := sqsSNSExtractPrincipals(statement.Principal)
		if len(principals) == 0 {
			continue
		}
		actions, notAction := sqsSNSExtractActions(statement.Action, statement.NotAction)
		capabilities := sqsSNSCapabilitiesForActions(service, actions, notAction)
		conditionKeys := sqsSNSCollectConditionKeys(statement.Condition)
		hasCondition := len(conditionKeys) > 0
		for _, principal := range principals {
			grants = append(grants, SQSSNSIdentityGrant{
				PrincipalARN:      principal.Value,
				PrincipalType:     principal.Type,
				Effect:            effect,
				Actions:           actions,
				NotAction:         notAction,
				Capabilities:      capabilities,
				ConditionKeys:     conditionKeys,
				HasCondition:      hasCondition,
				StatementSid:      strings.TrimSpace(statement.Sid),
				WildcardPrincipal: principal.Wildcard,
			})
		}
	}
	return grants, len(doc.Statement), nil
}

type sqsSNSParsedPrincipal struct {
	Value    string
	Type     string
	Wildcard bool
}

func sqsSNSExtractPrincipals(principal any) []sqsSNSParsedPrincipal {
	if principal == nil {
		return nil
	}
	switch typed := principal.(type) {
	case string:
		if strings.TrimSpace(typed) == "*" {
			return []sqsSNSParsedPrincipal{{Value: "*", Type: "*", Wildcard: true}}
		}
		if strings.TrimSpace(typed) != "" {
			return []sqsSNSParsedPrincipal{{Value: strings.TrimSpace(typed), Type: "aws"}}
		}
	case map[string]any:
		out := []sqsSNSParsedPrincipal{}
		for _, key := range []string{"AWS", "Service", "Federated", "CanonicalUser"} {
			principalType := strings.ToLower(key)
			if key == "CanonicalUser" {
				principalType = "canonical_user"
			}
			for _, value := range parseStringList(typed[key]) {
				value = strings.TrimSpace(value)
				if value == "" {
					continue
				}
				out = append(out, sqsSNSParsedPrincipal{
					Value:    value,
					Type:     principalType,
					Wildcard: value == "*",
				})
			}
		}
		if len(out) > 0 {
			sort.SliceStable(out, func(i, j int) bool {
				if out[i].Value == out[j].Value {
					return out[i].Type < out[j].Type
				}
				return out[i].Value < out[j].Value
			})
			return out
		}
	}
	return nil
}

func sqsSNSExtractActions(action, notAction any) ([]string, bool) {
	if list := parseStringList(action); len(list) > 0 {
		return normalizeStringList(list), false
	}
	if list := parseStringList(notAction); len(list) > 0 {
		return normalizeStringList(list), true
	}
	return nil, false
}

func sqsSNSCollectConditionKeys(condition map[string]any) []string {
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
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			seen[key] = struct{}{}
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

func canonicalSQSSNSGrantEffect(effect string) string {
	switch strings.ToLower(strings.TrimSpace(effect)) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return strings.TrimSpace(effect)
	}
}

func sqsSNSCapabilitiesForActions(service string, actions []string, notAction bool) []string {
	if notAction {
		return []string{"unknown"}
	}
	service = strings.ToLower(strings.TrimSpace(service))
	seen := map[string]struct{}{}
	add := func(value string) {
		if value == "" {
			return
		}
		seen[value] = struct{}{}
	}
	for _, action := range actions {
		normalized := strings.ToLower(strings.TrimSpace(action))
		if normalized == "" {
			continue
		}
		switch {
		case service == "sqs" && (normalized == "sqs:*" || normalized == "*"):
			add("publish")
			add("consume")
			add("manage")
		case strings.HasPrefix(normalized, "sqs:sendmessage"):
			add("publish")
		case strings.HasPrefix(normalized, "sqs:receive") ||
			strings.HasPrefix(normalized, "sqs:deletemessage") ||
			strings.HasPrefix(normalized, "sqs:changemessagevisibility"):
			add("consume")
		case strings.HasPrefix(normalized, "sqs:setqueueattributes") ||
			strings.HasPrefix(normalized, "sqs:tagqueue") ||
			strings.HasPrefix(normalized, "sqs:purgequeue") ||
			strings.HasPrefix(normalized, "sqs:deletequeue"):
			add("manage")
		case service == "sns" && (normalized == "sns:*" || normalized == "*"):
			add("publish")
			add("subscribe")
			add("manage")
		case strings.HasPrefix(normalized, "sns:publish"):
			add("publish")
		case strings.HasPrefix(normalized, "sns:subscribe"):
			add("subscribe")
		case strings.HasPrefix(normalized, "sns:settopicattributes") ||
			strings.HasPrefix(normalized, "sns:tagresource") ||
			strings.HasPrefix(normalized, "sns:deletetopic"):
			add("manage")
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for capability := range seen {
		out = append(out, capability)
	}
	sort.Strings(out)
	return out
}
