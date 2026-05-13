package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFindingJSONUsesSnakeCaseFields(t *testing.T) {
	redacted := true
	finding := Finding{
		ID:                  "f-1",
		ScanID:              "scan-1",
		Type:                FindingSecretExposure,
		Severity:            SeverityHigh,
		Title:               "title",
		HumanSummary:        "summary",
		Path:                []string{"app.env"},
		Repository:          "owner/repo",
		Commit:              "abc123",
		FilePath:            "app.env",
		LineNumber:          12,
		Detector:            "aws-access-key",
		LineSnippet:         "AWS_ACCESS_KEY_ID=AKIA****",
		LineSnippetRedacted: &redacted,
		SourceURL:           "https://github.com/owner/repo/blob/abc123/app.env#L12",
		Remediation:         "fix",
		CreatedAt:           time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC),
	}

	payload, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	text := string(payload)
	for _, expected := range []string{`"id"`, `"scan_id"`, `"human_summary"`, `"created_at"`, `"repository"`, `"file_path"`, `"line_number"`, `"line_snippet_redacted"`, `"source_url"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected field %s in %s", expected, text)
		}
	}
	if strings.Contains(text, `"ScanID"`) || strings.Contains(text, `"HumanSummary"`) {
		t.Fatalf("unexpected struct field casing leaked in payload: %s", text)
	}
}

func TestIdentityJSONUsesSnakeCaseFields(t *testing.T) {
	identity := Identity{
		ID:        "id-1",
		Provider:  ProviderAWS,
		Type:      IdentityTypeRole,
		Name:      "payments-app",
		ARN:       "arn:aws:iam::123456789012:role/payments-app",
		OwnerHint: "team-security",
		CreatedAt: time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC),
		RawRef:    "ref-1",
	}

	payload, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	text := string(payload)
	for _, expected := range []string{`"id"`, `"owner_hint"`, `"created_at"`, `"raw_ref"`, `"arn"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected field %s in %s", expected, text)
		}
	}
	if strings.Contains(text, `"OwnerHint"`) || strings.Contains(text, `"RawRef"`) {
		t.Fatalf("unexpected struct field casing leaked in payload: %s", text)
	}
}

func TestAppModeEntityJSONUsesSnakeCaseFields(t *testing.T) {
	now := time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC)
	connector := Connector{
		ID:          "connector-1",
		WorkspaceID: "workspace-1",
		ProjectID:   "project-1",
		Type:        ConnectorTypeGitHub,
		DisplayName: "GitHub",
		Status:      ConnectorStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	payload, err := json.Marshal(connector)
	if err != nil {
		t.Fatalf("marshal connector: %v", err)
	}
	text := string(payload)
	for _, expected := range []string{`"workspace_id"`, `"project_id"`, `"display_name"`, `"created_at"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected field %s in %s", expected, text)
		}
	}
	for _, unexpected := range []string{`"WorkspaceID"`, `"ProjectID"`, `"DisplayName"`} {
		if strings.Contains(text, unexpected) {
			t.Fatalf("unexpected struct field casing leaked in payload: %s", text)
		}
	}
}
