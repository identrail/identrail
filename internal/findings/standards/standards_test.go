package standards

import (
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestControlsForFinding(t *testing.T) {
	controls := ControlsForFinding(domain.FindingOverPrivileged)
	if len(controls) == 0 {
		t.Fatal("expected controls for overprivileged finding")
	}
	if controls[0].Framework == "" || controls[0].ControlID == "" {
		t.Fatalf("expected populated control ref, got %+v", controls[0])
	}
}

func TestEnrichFindingInjectsComplianceEvidence(t *testing.T) {
	finding := domain.Finding{
		ID:       "finding-1",
		Type:     domain.FindingEscalationPath,
		Severity: domain.SeverityCritical,
		Title:    "Escalation path",
	}

	enriched := EnrichFinding(finding)
	if enriched.Evidence == nil {
		t.Fatal("expected evidence map")
	}
	if _, ok := enriched.Evidence["control_refs"]; !ok {
		t.Fatal("expected control_refs in evidence")
	}
	if enriched.Evidence["schema_version"] != "v1" {
		t.Fatalf("expected schema_version v1, got %v", enriched.Evidence["schema_version"])
	}
}

func TestBuildExportsIncludeExpectedShape(t *testing.T) {
	finding := domain.Finding{
		ID:           "finding-2",
		ScanID:       "scan-1",
		Type:         domain.FindingOverPrivileged,
		Severity:     domain.SeverityHigh,
		Title:        "Overprivileged identity",
		HumanSummary: "summary",
		Path:         []string{"aws:identity:role-a", "aws:access:iam:*:*"},
		Remediation:  "Fix permissions",
		CreatedAt:    time.Date(2026, 3, 19, 10, 0, 0, 0, time.UTC),
	}

	ocsf := BuildOCSFAlignedExport(finding)
	if ocsf["activity_name"] != "detect" {
		t.Fatalf("expected activity_name detect, got %v", ocsf["activity_name"])
	}
	findingInfo, ok := ocsf["finding_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected finding_info map, got %T", ocsf["finding_info"])
	}
	if findingInfo["uid"] != "finding-2" {
		t.Fatalf("expected uid finding-2, got %v", findingInfo["uid"])
	}

	asff := BuildASFFExport(finding, "", "", "")
	if asff["SchemaVersion"] != "2018-10-08" {
		t.Fatalf("expected ASFF schema version, got %v", asff["SchemaVersion"])
	}
	if asff["Id"] != "finding-2" {
		t.Fatalf("expected ASFF finding id, got %v", asff["Id"])
	}
}
