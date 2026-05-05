package telemetry

import (
	"fmt"
	"strings"
)

var highCardinalityMetricLabels = map[string]struct{}{
	"api_key":        {},
	"actor":          {},
	"email":          {},
	"principal":      {},
	"repo":           {},
	"repository":     {},
	"request_id":     {},
	"scan_id":        {},
	"tenant_id":      {},
	"token":          {},
	"user":           {},
	"user_id":        {},
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
