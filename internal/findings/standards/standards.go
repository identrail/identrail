package standards

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

// ControlRef links one finding to one compliance control.
type ControlRef struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	Title     string `json:"title"`
}

var controlCatalog = map[domain.FindingType][]ControlRef{
	domain.FindingOverPrivileged: {
		{Framework: "CIS AWS Foundations", ControlID: "1.22", Title: "Ensure IAM policies are attached only to groups or roles"},
		{Framework: "NIST CSF", ControlID: "PR.AC-4", Title: "Access permissions are managed"},
	},
	domain.FindingEscalationPath: {
		{Framework: "CIS AWS Foundations", ControlID: "1.16", Title: "Ensure IAM policies that allow full administrative privileges are not attached"},
		{Framework: "NIST CSF", ControlID: "PR.PT-3", Title: "Principle of least functionality is incorporated"},
	},
	domain.FindingStaleIdentity: {
		{Framework: "CIS AWS Foundations", ControlID: "1.3", Title: "Ensure credentials unused for 90 days or greater are disabled"},
		{Framework: "NIST CSF", ControlID: "PR.AC-1", Title: "Identities and credentials are managed"},
	},
	domain.FindingOwnerless: {
		{Framework: "NIST CSF", ControlID: "ID.AM-6", Title: "Roles and responsibilities are established"},
	},
	domain.FindingRiskyTrustPolicy: {
		{Framework: "CIS AWS Foundations", ControlID: "1.20", Title: "Ensure IAM policies do not allow broad trust relationships"},
		{Framework: "NIST CSF", ControlID: "PR.AC-4", Title: "Access permissions are managed"},
	},
	domain.FindingSecretExposure: {
		{Framework: "NIST CSF", ControlID: "PR.DS-1", Title: "Data-at-rest is protected"},
	},
	domain.FindingRepoMisconfig: {
		{Framework: "NIST CSF", ControlID: "PR.IP-1", Title: "Baseline configuration is created and maintained"},
	},
}

// ControlsForFinding returns compliance mappings for one finding type.
func ControlsForFinding(findingType domain.FindingType) []ControlRef {
	refs := controlCatalog[findingType]
	if len(refs) == 0 {
		return nil
	}
	out := make([]ControlRef, len(refs))
	copy(out, refs)
	return out
}

// EnrichFinding injects stable compliance metadata into evidence without changing core finding shape.
func EnrichFinding(finding domain.Finding) domain.Finding {
	if finding.Triage.Status == "" {
		finding.Triage = domain.DefaultFindingTriage()
	}

	controls := ControlsForFinding(finding.Type)
	if len(controls) == 0 {
		return finding
	}

	evidence := map[string]any{}
	for key, value := range finding.Evidence {
		evidence[key] = value
	}
	evidence["control_refs"] = controls
	evidence["schema_version"] = "v1"
	evidence["compliance_frameworks"] = frameworksFromControls(controls)
	finding.Evidence = evidence
	return finding
}

// BuildOCSFAlignedExport returns an OCSF-aligned payload for downstream integrations.
func BuildOCSFAlignedExport(finding domain.Finding) map[string]any {
	enriched := EnrichFinding(finding)
	severityID, severityLabel := ocsfSeverity(enriched.Severity)
	return map[string]any{
		"activity_name": "detect",
		"category_name": "Findings",
		"class_name":    "Security Finding",
		"severity": map[string]any{
			"id":    severityID,
			"label": severityLabel,
		},
		"finding_info": map[string]any{
			"uid":       enriched.ID,
			"title":     enriched.Title,
			"desc":      enriched.HumanSummary,
			"type_uid":  string(enriched.Type),
			"created":   enriched.CreatedAt.UTC().Format(time.RFC3339),
			"remedy":    enriched.Remediation,
			"path":      slices.Clone(enriched.Path),
			"controls":  controlsAsMaps(ControlsForFinding(enriched.Type)),
			"evidence":  enriched.Evidence,
			"provider":  inferProvider(enriched),
			"scan_id":   enriched.ScanID,
			"framework": frameworksFromControls(ControlsForFinding(enriched.Type)),
		},
	}
}

// BuildASFFExport returns an AWS Security Finding Format (ASFF) compatible payload.
func BuildASFFExport(finding domain.Finding, productARN string, awsAccountID string, region string) map[string]any {
	enriched := EnrichFinding(finding)
	if strings.TrimSpace(productARN) == "" {
		productARN = "arn:aws:securityhub:::product/identrail/default"
	}
	if strings.TrimSpace(awsAccountID) == "" {
		awsAccountID = "000000000000"
	}
	if strings.TrimSpace(region) == "" {
		region = "us-east-1"
	}

	updatedAt := enriched.CreatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}

	return map[string]any{
		"SchemaVersion": "2018-10-08",
		"Id":            enriched.ID,
		"ProductArn":    productARN,
		"GeneratorId":   fmt.Sprintf("identrail/%s", enriched.Type),
		"AwsAccountId":  awsAccountID,
		"Types":         asffTypesForFinding(enriched.Type),
		"CreatedAt":     updatedAt.UTC().Format(time.RFC3339),
		"UpdatedAt":     updatedAt.UTC().Format(time.RFC3339),
		"Severity": map[string]any{
			"Label": strings.ToUpper(string(enriched.Severity)),
		},
		"Title":       enriched.Title,
		"Description": enriched.HumanSummary,
		"Resources": []map[string]any{
			{
				"Type":   "Other",
				"Id":     strings.Join(enriched.Path, " -> "),
				"Region": region,
				"Details": map[string]any{
					"ControlRefs": controlsAsMaps(ControlsForFinding(enriched.Type)),
				},
			},
		},
		"ProductFields": map[string]any{
			"ProviderName": "Identrail",
			"ProviderType": inferProvider(enriched),
			"ScanID":       enriched.ScanID,
			"ControlRefs":  controlsAsMaps(ControlsForFinding(enriched.Type)),
		},
		"Remediation": map[string]any{
			"Recommendation": map[string]any{
				"Text": enriched.Remediation,
			},
		},
	}
}

func asffTypesForFinding(findingType domain.FindingType) []string {
	switch findingType {
	case domain.FindingEscalationPath:
		return []string{"Software and Configuration Checks/AWS Security Best Practices"}
	case domain.FindingOverPrivileged:
		return []string{"Software and Configuration Checks/Industry and Regulatory Standards/CIS"}
	case domain.FindingRiskyTrustPolicy:
		return []string{"TTPs/Persistence"}
	case domain.FindingStaleIdentity:
		return []string{"Effects/Data Exposure"}
	case domain.FindingOwnerless:
		return []string{"Unusual Behaviors"}
	default:
		return []string{"Software and Configuration Checks"}
	}
}

func inferProvider(finding domain.Finding) string {
	for _, node := range finding.Path {
		switch {
		case strings.HasPrefix(node, "aws:"):
			return "aws"
		case strings.HasPrefix(node, "k8s:"):
			return "kubernetes"
		}
	}
	return "unknown"
}

func ocsfSeverity(severity domain.FindingSeverity) (int, string) {
	switch severity {
	case domain.SeverityCritical:
		return 5, "Critical"
	case domain.SeverityHigh:
		return 4, "High"
	case domain.SeverityMedium:
		return 3, "Medium"
	case domain.SeverityLow:
		return 2, "Low"
	default:
		return 1, "Informational"
	}
}

func frameworksFromControls(controls []ControlRef) []string {
	set := map[string]struct{}{}
	out := make([]string, 0, len(controls))
	for _, control := range controls {
		framework := strings.TrimSpace(control.Framework)
		if framework == "" {
			continue
		}
		if _, exists := set[framework]; exists {
			continue
		}
		set[framework] = struct{}{}
		out = append(out, framework)
	}
	slices.Sort(out)
	return out
}

func controlsAsMaps(controls []ControlRef) []map[string]any {
	out := make([]map[string]any, 0, len(controls))
	for _, control := range controls {
		out = append(out, map[string]any{
			"framework":  control.Framework,
			"control_id": control.ControlID,
			"title":      control.Title,
		})
	}
	return out
}
