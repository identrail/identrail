package standards

import (
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/domain"
)

func TestSuggestPatch_AllHighVolumeFindingTypes(t *testing.T) {
	types := []domain.FindingType{
		domain.FindingOverPrivileged,
		domain.FindingRiskyTrustPolicy,
		domain.FindingEscalationPath,
		domain.FindingStaleIdentity,
		domain.FindingOwnerless,
	}
	for _, ft := range types {
		t.Run(string(ft), func(t *testing.T) {
			patch, ok := SuggestPatch(domain.Finding{ID: "f1", Type: ft})
			if !ok {
				t.Fatalf("expected patch for %s, got none", ft)
			}
			if patch.RuleID != ft {
				t.Errorf("rule_id: want %s, got %s", ft, patch.RuleID)
			}
			if patch.Summary == "" {
				t.Error("expected non-empty summary")
			}
			if len(patch.Steps) == 0 {
				t.Error("expected at least one remediation step")
			}
			if len(patch.SafetyNotes) == 0 {
				t.Error("expected at least one safety note")
			}
		})
	}
}

func TestSuggestPatch_UnregisteredTypeReturnsFalse(t *testing.T) {
	_, ok := SuggestPatch(domain.Finding{Type: domain.FindingSecretExposure})
	if ok {
		t.Error("expected false for unregistered finding type")
	}
}

func TestSuggestPatch_EvidenceIncorporatedInSteps(t *testing.T) {
	cases := []struct {
		findingType domain.FindingType
		evidence    map[string]any
		wantInStep  string
	}{
		{
			findingType: domain.FindingOverPrivileged,
			evidence:    map[string]any{"identity_arn": "arn:aws:iam::123456789012:role/WorkerRole"},
			wantInStep:  "arn:aws:iam::123456789012:role/WorkerRole",
		},
		{
			findingType: domain.FindingRiskyTrustPolicy,
			evidence: map[string]any{
				"identity_arn":     "arn:aws:iam::111111111111:role/CrossAccountRole",
				"risky_principals": []string{"arn:aws:iam::*:root"},
			},
			wantInStep: "arn:aws:iam::*:root",
		},
		{
			findingType: domain.FindingEscalationPath,
			evidence: map[string]any{
				"identity_arn":      "arn:aws:iam::222222222222:role/EscRole",
				"escalation_action": "iam:PassRole",
				"resource":          "*",
			},
			wantInStep: "iam:PassRole",
		},
		{
			findingType: domain.FindingStaleIdentity,
			evidence: map[string]any{
				"identity_arn":        "arn:aws:iam::333333333333:user/old-svc",
				"reference_timestamp": "2024-01-01T00:00:00Z",
			},
			wantInStep: "2024-01-01T00:00:00Z",
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.findingType), func(t *testing.T) {
			patch, ok := SuggestPatch(domain.Finding{Type: tc.findingType, Evidence: tc.evidence})
			if !ok {
				t.Fatalf("expected patch for %s", tc.findingType)
			}
			found := false
			for _, step := range patch.Steps {
				if strings.Contains(step, tc.wantInStep) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %q to appear in steps for %s; got steps: %v", tc.wantInStep, tc.findingType, patch.Steps)
			}
		})
	}
}

func TestSuggestPatch_PolicyTemplatesAreJSON(t *testing.T) {
	policyTypes := []domain.FindingType{
		domain.FindingOverPrivileged,
		domain.FindingRiskyTrustPolicy,
		domain.FindingEscalationPath,
	}
	for _, ft := range policyTypes {
		t.Run(string(ft), func(t *testing.T) {
			patch, _ := SuggestPatch(domain.Finding{Type: ft})
			if patch.Template == "" {
				t.Fatalf("expected non-empty template for %s", ft)
			}
			trimmed := strings.TrimSpace(patch.Template)
			if !strings.HasPrefix(trimmed, "{") {
				t.Errorf("expected JSON template for %s, got prefix: %s", ft, trimmed[:min(60, len(trimmed))])
			}
		})
	}
}

func TestSuggestPatch_TrustPolicyTemplateIncludesAccountID(t *testing.T) {
	patch, _ := SuggestPatch(domain.Finding{
		Type: domain.FindingRiskyTrustPolicy,
		Evidence: map[string]any{
			"target_account_id": "987654321098",
		},
	})
	if !strings.Contains(patch.Template, "987654321098") {
		t.Errorf("expected account ID in trust policy template, got: %s", patch.Template)
	}
}

func TestSuggestPatch_NoEvidenceProducesValidPatch(t *testing.T) {
	types := []domain.FindingType{
		domain.FindingOverPrivileged,
		domain.FindingRiskyTrustPolicy,
		domain.FindingEscalationPath,
		domain.FindingStaleIdentity,
		domain.FindingOwnerless,
	}
	for _, ft := range types {
		t.Run(string(ft), func(t *testing.T) {
			patch, ok := SuggestPatch(domain.Finding{Type: ft})
			if !ok {
				t.Fatalf("expected patch for %s", ft)
			}
			if patch.Summary == "" || len(patch.Steps) == 0 {
				t.Errorf("patch for %s has empty summary or steps with no evidence", ft)
			}
		})
	}
}
