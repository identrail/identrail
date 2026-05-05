package telemetry

import "testing"

func TestValidateMetricLabelsAllowsBoundedLabels(t *testing.T) {
	labels := []string{
		"allowed",
		"kind",
		"outcome",
		"policy_set_id",
		"policy_source",
		"policy_version",
		"queue",
		"reason",
		"rollout_mode",
		"runner",
		"source",
	}
	for _, label := range labels {
		if err := ValidateMetricLabels("test_metric", label); err != nil {
			t.Fatalf("expected %q to be allowed: %v", label, err)
		}
	}
}

func TestValidateMetricLabelsRejectsHighCardinalityLabels(t *testing.T) {
	for _, label := range []string{"request_id", "tenant_id", "workspace_id", "user_id", "api_key", "repository", "scan_id"} {
		if err := ValidateMetricLabels("test_metric", label); err == nil {
			t.Fatalf("expected %q to be rejected", label)
		}
	}
}

func TestKnownMetricLabelsStayLowCardinality(t *testing.T) {
	known := map[string][]string{
		"identrail_authz_policy_decisions_by_version_total": {"policy_set_id", "policy_version", "policy_source", "rollout_mode", "allowed"},
	}
	for metric, labels := range known {
		if err := ValidateMetricLabels(metric, labels...); err != nil {
			t.Fatalf("known metric labels must remain bounded: %v", err)
		}
	}
}
