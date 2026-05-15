package standards

import (
	"encoding/json"
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

func TestSuggestPatch_AWSPolicyTemplatesAreValidJSON(t *testing.T) {
	policyTypes := []domain.FindingType{
		domain.FindingOverPrivileged,
		domain.FindingRiskyTrustPolicy,
		domain.FindingEscalationPath,
	}
	for _, ft := range policyTypes {
		t.Run(string(ft), func(t *testing.T) {
			// Force AWS routing by adding an aws: path node.
			patch, ok := SuggestPatch(domain.Finding{
				Type: ft,
				Path: []string{"aws:iam::123456789012:role/Example"},
			})
			if !ok {
				t.Fatalf("expected patch for %s", ft)
			}
			if patch.Template == "" {
				t.Fatalf("expected non-empty template for %s", ft)
			}
			if !json.Valid([]byte(patch.Template)) {
				t.Errorf("template for %s is not valid JSON:\n%s", ft, patch.Template)
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

func TestSuggestPatch_KubernetesOverprivilegedReturnsRBACTemplate(t *testing.T) {
	patch, ok := SuggestPatch(domain.Finding{
		Type: domain.FindingOverPrivileged,
		Path: []string{"k8s:serviceaccount:default/worker", "k8s:role:cluster-admin"},
		Evidence: map[string]any{
			"identity_id": "k8s:serviceaccount:default/worker",
			"sample": map[string]any{
				"action":   "*",
				"resource": "*",
			},
		},
	})
	if !ok {
		t.Fatal("expected patch for k8s overprivileged")
	}
	if strings.Contains(patch.Template, "iam:") || strings.Contains(patch.Template, "aws:") {
		t.Errorf("k8s overprivileged template must not contain IAM identifiers, got:\n%s", patch.Template)
	}
	if !strings.Contains(patch.Template, "rbac.authorization.k8s.io") {
		t.Errorf("expected RBAC YAML template, got:\n%s", patch.Template)
	}
	hasRBACGuidance := false
	for _, step := range patch.Steps {
		if strings.Contains(step, "ClusterRole") || strings.Contains(step, "kubectl auth can-i") {
			hasRBACGuidance = true
			break
		}
	}
	if !hasRBACGuidance {
		t.Errorf("expected K8s RBAC guidance in steps, got: %v", patch.Steps)
	}
}

func TestSuggestPatch_KubernetesEscalationReturnsRBACTemplate(t *testing.T) {
	patch, ok := SuggestPatch(domain.Finding{
		Type: domain.FindingEscalationPath,
		Path: []string{"k8s:deployment:ns/web", "k8s:serviceaccount:ns/web", "k8s:clusterrole:admin"},
		Evidence: map[string]any{
			"workload_id": "k8s:deployment:ns/web",
			"identity_id": "k8s:serviceaccount:ns/web",
			"action":      "bind",
			"resource":    "clusterroles",
		},
	})
	if !ok {
		t.Fatal("expected patch for k8s escalation")
	}
	for _, step := range patch.Steps {
		if strings.Contains(step, "iam:PassRole") || strings.Contains(step, "IAM Access Analyzer") {
			t.Errorf("k8s escalation steps leaked IAM guidance: %s", step)
		}
	}
	if !strings.Contains(patch.Template, "rbac.authorization.k8s.io") {
		t.Errorf("expected RBAC YAML template, got:\n%s", patch.Template)
	}
	foundRBACVerb := false
	for _, step := range patch.Steps {
		if strings.Contains(step, "bind") && strings.Contains(step, "clusterroles") {
			foundRBACVerb = true
			break
		}
	}
	if !foundRBACVerb {
		t.Errorf("expected RBAC verb/resource in steps, got: %v", patch.Steps)
	}
}

func TestSuggestPatch_AWSEscalationKeepsIAMGuidance(t *testing.T) {
	patch, ok := SuggestPatch(domain.Finding{
		Type: domain.FindingEscalationPath,
		Path: []string{"aws:iam::111111111111:role/AttackerRole", "aws:iam::222222222222:role/Target"},
		Evidence: map[string]any{
			"identity_arn":      "arn:aws:iam::222222222222:role/Target",
			"escalation_action": "iam:PassRole",
			"resource":          "*",
		},
	})
	if !ok {
		t.Fatal("expected patch for aws escalation")
	}
	if strings.Contains(patch.Template, "rbac.authorization.k8s.io") {
		t.Errorf("aws escalation template leaked RBAC content:\n%s", patch.Template)
	}
	hasIAMGuidance := false
	for _, step := range patch.Steps {
		if strings.Contains(step, "iam:PassRole") {
			hasIAMGuidance = true
			break
		}
	}
	if !hasIAMGuidance {
		t.Errorf("expected IAM guidance in steps, got: %v", patch.Steps)
	}
}
