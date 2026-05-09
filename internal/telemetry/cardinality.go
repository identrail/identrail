package telemetry

import (
	"fmt"
	"strings"
)

var highCardinalityMetricLabels = map[string]struct{}{
	"api_key":        {},
	"api_token":      {},
	"auth_token":     {},
	"access_token":   {},
	"bearer_token":   {},
	"actor":          {},
	"commit_sha":     {},
	"commit_url":     {},
	"email":          {},
	"email_address":  {},
	"user_email":     {},
	"principal":      {},
	"repo":           {},
	"repo_url":       {},
	"repository":     {},
	"repository_url": {},
	"request_id":     {},
	"scan_id":        {},
	"tenant_id":      {},
	"trace_id":       {},
	"correlation_id": {},
	"token":          {},
	"user":           {},
	"user_id":        {},
	"policy_set_id":  {},
	"workspace_id":   {},
	"workspace_slug": {},
}

// ValidateMetricLabels rejects labels that would create unbounded Prometheus series.
func ValidateMetricLabels(metricName string, labels ...string) error {
	for _, label := range labels {
		normalized := strings.ToLower(strings.TrimSpace(label))
		if normalized == "" {
			return fmt.Errorf("%s has an empty label name", metricName)
		}
		if _, found := highCardinalityMetricLabels[normalized]; found {
			return fmt.Errorf("%s uses high-cardinality label %q", metricName, normalized)
		}
	}
	return nil
}
