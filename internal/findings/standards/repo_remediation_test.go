package standards

import (
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/domain"
)

func TestSuggestRepoExposureRemediationSupportsMisconfigDetectors(t *testing.T) {
	cases := []struct {
		detector    string
		publishable bool
		wantPatch   bool
	}{
		{"workflow_write_all_permissions", true, true},
		{"workflow_pull_request_target", true, true},
		{"workflow_broad_token_permissions", false, false},
		{"workflow_pull_request_target_privileged_context", false, false},
		{"workflow_pull_request_target_untrusted_checkout", false, false},
		{"workflow_unpinned_third_party_action", false, true},
		{"workflow_shell_injection_user_context", false, false},
		{"workflow_run_privilege_chain", false, false},
		{"workflow_oidc_broad_trust", false, false},
		{"workflow_cache_poisoning", false, false},
		{"workflow_artifact_poisoning", false, false},
		{"workflow_ai_agent_prompt_injection", false, false},
		{"workflow_self_hosted_runner", false, false},
		{"workflow_self_hosted_runner_unresolved", false, false},
		{"k8s_privileged_true", true, true},
		{"terraform_public_s3_acl", true, true},
		{"terraform_open_ssh_rdp", false, true},
		{"docker_latest_tag", false, true},
		{"ai_agent_sensitive_env_reference", false, false},
		{"ai_agent_dangerous_tool_capability", false, false},
		{"ai_agent_committed_local_config", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.detector, func(t *testing.T) {
			remediation, ok := SuggestRepoExposureRemediation(domain.Finding{
				ID:          "finding-1",
				ScanID:      "scan-1",
				Type:        domain.FindingRepoMisconfig,
				Detector:    tc.detector,
				Repository:  "owner/repo",
				Commit:      "abc123",
				FilePath:    ".github/workflows/ci.yml",
				LineNumber:  7,
				LineSnippet: "permissions: write-all",
			})
			if !ok {
				t.Fatalf("expected remediation for %s", tc.detector)
			}
			if remediation.Detector != tc.detector {
				t.Fatalf("detector: want %s, got %s", tc.detector, remediation.Detector)
			}
			if remediation.Summary == "" || remediation.RiskSummary == "" {
				t.Fatalf("expected summary and risk summary, got %+v", remediation)
			}
			if len(remediation.Steps) == 0 || len(remediation.SafetyNotes) == 0 || len(remediation.Validation) == 0 {
				t.Fatalf("expected steps, safety notes, and validation, got %+v", remediation)
			}
			if remediation.Publishable != tc.publishable {
				t.Fatalf("publishable: want %t, got %t (%s)", tc.publishable, remediation.Publishable, remediation.PublishBlockedReason)
			}
			if tc.publishable && remediation.PublishBlockedReason != "" {
				t.Fatalf("publishable remediation must not include blocked reason, got %q", remediation.PublishBlockedReason)
			}
			if gotPatch := remediation.Patch != nil; gotPatch != tc.wantPatch {
				t.Fatalf("patch presence: want %t, got %t", tc.wantPatch, gotPatch)
			}
			if !tc.publishable && remediation.PublishBlockedReason == "" {
				t.Fatal("expected blocked publish reason for non-publishable remediation")
			}
			if remediation.Evidence.FindingID != "finding-1" || remediation.Evidence.ScanID != "scan-1" {
				t.Fatalf("expected traceability evidence, got %+v", remediation.Evidence)
			}
		})
	}
}

func TestSuggestRepoExposureRemediationSecretExposureIsRotationOnly(t *testing.T) {
	secretSnippet := "aws_secret_access_key = \"0123456789abcdef0123456789abcdef01234567\""
	remediation, ok := SuggestRepoExposureRemediation(domain.Finding{
		ID:          "secret-1",
		ScanID:      "scan-1",
		Type:        domain.FindingSecretExposure,
		Detector:    "aws_secret_access_key",
		Repository:  "owner/repo",
		FilePath:    "app.env",
		LineNumber:  3,
		LineSnippet: secretSnippet,
	})
	if !ok {
		t.Fatal("expected secret remediation guidance")
	}
	if !remediation.SecretRotation {
		t.Fatal("expected secret remediation to require rotation")
	}
	if remediation.Publishable || remediation.Patch != nil {
		t.Fatalf("secret remediation must not be publishable or patched: %+v", remediation)
	}
	if remediation.Evidence.LineSnippet != "" {
		t.Fatalf("secret remediation must not echo raw line snippets, got %q", remediation.Evidence.LineSnippet)
	}
	combined := remediation.Summary + " " + remediation.RiskSummary + " " + strings.Join(remediation.Steps, " ") + " " + strings.Join(remediation.SafetyNotes, " ") + " " + strings.Join(remediation.Validation, " ")
	if strings.Contains(combined, "0123456789abcdef") {
		t.Fatalf("secret remediation leaked raw secret material: %s", combined)
	}
	if !strings.Contains(strings.ToLower(combined), "rotate") {
		t.Fatalf("expected rotation guidance, got %s", combined)
	}
}

func TestSuggestRepoExposureRemediationRejectsUnsupportedFinding(t *testing.T) {
	if _, ok := SuggestRepoExposureRemediation(domain.Finding{Type: domain.FindingOwnerless}); ok {
		t.Fatal("expected unsupported non-repo finding to return false")
	}
	if _, ok := SuggestRepoExposureRemediation(domain.Finding{
		Type:     domain.FindingRepoMisconfig,
		Detector: "unknown_detector",
	}); ok {
		t.Fatal("expected unknown repo detector to return false")
	}
}
