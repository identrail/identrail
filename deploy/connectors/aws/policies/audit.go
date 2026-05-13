//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type policyDocument struct {
	Statement []struct {
		Action any `json:"Action"`
	} `json:"Statement"`
}

func main() {
	raw, err := os.ReadFile("identrail-readonly-policy.json")
	if err != nil {
		fatal(err)
	}
	var policy policyDocument
	if err := json.Unmarshal(raw, &policy); err != nil {
		fatal(err)
	}
	actions := map[string]struct{}{}
	for _, statement := range policy.Statement {
		switch typed := statement.Action.(type) {
		case string:
			actions[strings.ToLower(typed)] = struct{}{}
		case []any:
			for _, item := range typed {
				action, ok := item.(string)
				if !ok {
					fatal(fmt.Errorf("policy action must be string"))
				}
				actions[strings.ToLower(action)] = struct{}{}
			}
		default:
			fatal(fmt.Errorf("policy action must be string or array"))
		}
	}

	required := []string{
		"ec2:describeiaminstanceprofileassociations",
		"ec2:describeinstances",
		"iam:getpolicy",
		"iam:getpolicyversion",
		"iam:getrolepolicy",
		"iam:listattachedrolepolicies",
		"iam:listrolepolicies",
		"iam:listroles",
		"sts:getcalleridentity",
	}
	missing := make([]string, 0)
	for _, action := range required {
		if _, ok := actions[action]; !ok {
			missing = append(missing, action)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		fatal(fmt.Errorf("missing required connector actions: %s", strings.Join(missing, ", ")))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
