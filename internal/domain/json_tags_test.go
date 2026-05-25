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
		ConfidenceScore:     0.96,
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
	for _, expected := range []string{`"id"`, `"scan_id"`, `"confidence_score"`, `"human_summary"`, `"created_at"`, `"repository"`, `"file_path"`, `"line_number"`, `"line_snippet_redacted"`, `"source_url"`} {
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

func TestCredentialJSONRedactsRawValue(t *testing.T) {
	credential := Credential{
		ID:        "cred-1",
		Provider:  ProviderAWS,
		Type:      CredentialTypeAccessKey,
		Name:      "demo",
		Reference: "ref-1",
		RawRef:    "raw-1",
		RawValue:  "super-secret-key",
	}
	payload, err := json.Marshal(credential)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	text := string(payload)
	if strings.Contains(text, `"raw_value"`) {
		t.Fatalf("expected raw_value to be omitted from JSON, got %s", text)
	}
}

func TestResourceAndRuntimeEventJSONUsesSnakeCaseFields(t *testing.T) {
	resource := Resource{
		ID:             "res-1",
		Provider:       ProviderAWS,
		Type:           ResourceTypeLambdaFunction,
		Name:           "processor",
		RawRef:         "arn:aws:lambda:us-east-1:123:function:processor",
		SourceEntityID: "aws:identity:role/demo",
	}
	observedAt := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	runtimeEvent := RuntimeEvent{
		ID:         "ev-1",
		Provider:   ProviderAWS,
		Type:       RuntimeEventTypeInvoke,
		ActorID:    "agent-1",
		TargetID:   "res-1",
		SourceRef:  "source-1",
		ObservedAt: observedAt,
	}

	resourcePayload, err := json.Marshal(resource)
	if err != nil {
		t.Fatalf("marshal resource: %v", err)
	}
	eventPayload, err := json.Marshal(runtimeEvent)
	if err != nil {
		t.Fatalf("marshal runtime event: %v", err)
	}

	for _, expected := range []string{`"type"`, `"source_entity_id"`, `"raw_ref"`, `"observed_at"`} {
		if !strings.Contains(string(resourcePayload), expected) && !strings.Contains(string(eventPayload), expected) {
			t.Fatalf("expected %s in one of resource/runtime payload: %s%s", expected, string(resourcePayload), string(eventPayload))
		}
	}
	if strings.Contains(string(resourcePayload), `"SourceRef"`) || strings.Contains(string(eventPayload), `"SourceRef"`) {
		t.Fatalf("unexpected struct field casing leaked in payload: %s%s", string(resourcePayload), string(eventPayload))
	}
}
