package telemetry

import "testing"

func TestValidateMetricLabelsAllowsBoundedLabels(t *testing.T) {
	labels := []string{
		"allowed",
		"connector",
		"kind",
		"outcome",
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
	for _, label := range []string{
		"request_id",
		"tenant_id",
		"workspace_id",
		"user_id",
		"api_key",
		"api_token",
		"auth_token",
		"access_token",
		"bearer_token",
		"email_address",
		"user_email",
		"repository",
		"repository_url",
		"scan_id",
		"trace_id",
		"correlation_id",
		"commit_sha",
		"repo_url",
		"policy_set_id",
	} {
		if err := ValidateMetricLabels("test_metric", label); err == nil {
			t.Fatalf("expected %q to be rejected", label)
		}
	}
}

func TestKnownMetricLabelsStayLowCardinality(t *testing.T) {
	known := map[string][]string{
		"identrail_authz_policy_decisions_by_version_total": {"policy_version", "policy_source", "rollout_mode", "allowed"},
		"identrail_automation_runs_total":                   {"source", "connector", "outcome"},
		"identrail_automation_lag_milliseconds":             {"source", "queue"},
	}
	for metric, labels := range known {
		if err := ValidateMetricLabels(metric, labels...); err != nil {
			t.Fatalf("known metric labels must remain bounded: %v", err)
		}
	}
}

func TestAuthzDecisionMetricPolicySetIDIsRejected(t *testing.T) {
	if err := ValidateMetricLabels("identrail_authz_policy_decisions_by_version_total", "policy_set_id"); err == nil {
		t.Fatalf("policy_set_id must be rejected as high-cardinality for authz decision metrics")
	}
}
