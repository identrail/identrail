package enterprise

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

// ---------- SCIM ----------

func sampleSCIMUser() SCIMUser {
	return SCIMUser{
		ID:          "scim-user-1",
		UserName:    "alice@example.com",
		DisplayName: "Alice Example",
		Active:      true,
		Emails: []SCIMEmail{
			{Value: "alice@example.com", Type: "work", Primary: true},
		},
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			LastModified: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		},
	}
}

func TestSCIMUser_Validate(t *testing.T) {
	if err := sampleSCIMUser().Validate(); err != nil {
		t.Errorf("valid user rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*SCIMUser)
	}{
		{"missing_username", func(u *SCIMUser) { u.UserName = "" }},
		{"no_emails", func(u *SCIMUser) { u.Emails = nil }},
		{"emails_all_empty_values", func(u *SCIMUser) { u.Emails = []SCIMEmail{{Value: "   "}, {Value: ""}} }},
		{"invalid_email", func(u *SCIMUser) { u.Emails = []SCIMEmail{{Value: "not-an-email", Primary: true}} }},
		{"multiple_primaries", func(u *SCIMUser) {
			u.Emails = []SCIMEmail{
				{Value: "alice@example.com", Primary: true},
				{Value: "alice.alt@example.com", Primary: true},
			}
		}},
		// mail.ParseAddress accepts these mailbox/display forms; SCIM emails
		// must persist as a canonical addr-spec only.
		{"email_with_display_name", func(u *SCIMUser) {
			u.Emails = []SCIMEmail{{Value: "Alice <alice@example.com>", Primary: true}}
		}},
		{"email_with_trailing_comment", func(u *SCIMUser) {
			u.Emails = []SCIMEmail{{Value: "alice@example.com (Alice)", Primary: true}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := sampleSCIMUser()
			tc.mutate(&u)
			if err := u.Validate(); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestSCIMProvisioningEvent_Validate(t *testing.T) {
	base := SCIMProvisioningEvent{
		Op:           SCIMProvisioningCreate,
		User:         sampleSCIMUser(),
		SourceTenant: "tenant-1",
		OccurredAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := base.Validate(); err != nil {
		t.Errorf("valid event rejected: %v", err)
	}

	bad := base
	bad.Op = "rename"
	if err := bad.Validate(); err == nil {
		t.Error("expected unknown op rejection")
	}

	bad = base
	bad.SourceTenant = ""
	if err := bad.Validate(); err == nil {
		t.Error("expected missing tenant rejection")
	}

	bad = base
	bad.OccurredAt = time.Time{}
	if err := bad.Validate(); err == nil {
		t.Error("expected missing timestamp rejection")
	}

	bad = base
	bad.Op = SCIMProvisioningDeactivate
	bad.User.Active = true
	if err := bad.Validate(); err == nil {
		t.Error("deactivate event with active=true should be rejected")
	}

	bad = base
	bad.Op = SCIMProvisioningDeactivate
	bad.User.Active = false
	if err := bad.Validate(); err != nil {
		t.Errorf("deactivate with active=false should pass: %v", err)
	}
}

func TestSCIMUser_DecodesStandardSCIMWirePayload(t *testing.T) {
	// Verbatim payload shape an Okta/Azure AD SCIM client would POST per
	// RFC 7643: emails is multi-valued and resource timestamps live under
	// meta.created / meta.lastModified.
	const payload = `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"id": "scim-user-1",
		"externalId": "ext-1",
		"userName": "alice@example.com",
		"displayName": "Alice Example",
		"active": true,
		"emails": [
			{"value": "alice.alt@example.com", "type": "home", "primary": false},
			{"value": "alice@example.com", "type": "work", "primary": true}
		],
		"meta": {
			"resourceType": "User",
			"created": "2026-05-01T00:00:00Z",
			"lastModified": "2026-05-01T00:00:00Z",
			"location": "https://scim.example.com/v2/Users/scim-user-1"
		}
	}`
	var u SCIMUser
	if err := json.Unmarshal([]byte(payload), &u); err != nil {
		t.Fatalf("unmarshal SCIM payload: %v", err)
	}
	if u.UserName != "alice@example.com" {
		t.Errorf("UserName: want alice@example.com, got %q", u.UserName)
	}
	if u.ExternalID != "ext-1" {
		t.Errorf("ExternalID: want ext-1, got %q", u.ExternalID)
	}
	if u.DisplayName != "Alice Example" {
		t.Errorf("DisplayName: want Alice Example, got %q", u.DisplayName)
	}
	if got := u.PrimaryEmail(); got != "alice@example.com" {
		t.Errorf("PrimaryEmail: want alice@example.com, got %q", got)
	}
	if u.Meta.ResourceType != "User" {
		t.Errorf("Meta.ResourceType: want User, got %q", u.Meta.ResourceType)
	}
	if u.Meta.Created.IsZero() {
		t.Error("Meta.Created should be populated from meta.created")
	}
	if err := u.Validate(); err != nil {
		t.Errorf("decoded SCIM user should validate: %v", err)
	}
}

func TestSCIMUser_MarshalsToSCIMCamelCase(t *testing.T) {
	u := sampleSCIMUser()
	u.ExternalID = "ext-99"
	encoded, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []string{`"userName":`, `"externalId":`, `"displayName":`, `"emails":`, `"meta":`, `"created":`, `"lastModified":`}
	for _, key := range want {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("marshaled output missing SCIM key %s; got %s", key, string(encoded))
		}
	}
	forbidden := []string{`"user_name":`, `"external_id":`, `"display_name":`, `"created_at":`, `"updated_at":`, `"createdAt":`, `"updatedAt":`}
	for _, key := range forbidden {
		if strings.Contains(string(encoded), key) {
			t.Errorf("marshaled output should not use non-SCIM key %s; got %s", key, string(encoded))
		}
	}
}

func TestSCIMUser_PrimaryEmail_PrefersPrimaryThenFirstNonEmpty(t *testing.T) {
	cases := []struct {
		name   string
		emails []SCIMEmail
		want   string
	}{
		{"primary_wins", []SCIMEmail{{Value: "a@example.com"}, {Value: "b@example.com", Primary: true}}, "b@example.com"},
		{"first_non_empty_when_no_primary", []SCIMEmail{{Value: "   "}, {Value: "c@example.com"}, {Value: "d@example.com"}}, "c@example.com"},
		{"all_empty", []SCIMEmail{{Value: "  "}, {Value: ""}}, ""},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := (SCIMUser{Emails: tc.emails}).PrimaryEmail()
			if got != tc.want {
				t.Errorf("PrimaryEmail: want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestSCIMUser_ValidateAcceptsMissingIDForCreatePath(t *testing.T) {
	// SCIM 2.0 servers assign `id` on POST /Users, so the resource arrives
	// without one. The user-level validator must not block that case; the
	// provisioning event validator enforces id for update/deactivate/delete.
	u := sampleSCIMUser()
	u.ID = ""
	if err := u.Validate(); err != nil {
		t.Errorf("SCIMUser.Validate must accept a missing id (create path): %v", err)
	}
}

func TestSCIMProvisioningEvent_CreateAllowsMissingUserID(t *testing.T) {
	user := sampleSCIMUser()
	user.ID = ""
	event := SCIMProvisioningEvent{
		Op:           SCIMProvisioningCreate,
		User:         user,
		SourceTenant: "tenant-1",
		OccurredAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := event.Validate(); err != nil {
		t.Errorf("create event must accept missing user.id: %v", err)
	}
}

func TestSCIMProvisioningEvent_UpdateRequiresUserID(t *testing.T) {
	user := sampleSCIMUser()
	user.ID = ""
	event := SCIMProvisioningEvent{
		Op:           SCIMProvisioningUpdate,
		User:         user,
		SourceTenant: "tenant-1",
		OccurredAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	err := event.Validate()
	if err == nil {
		t.Fatal("update event without user.id should be rejected")
	}
	if !strings.Contains(err.Error(), "user.id") {
		t.Errorf("error should mention user.id, got: %v", err)
	}
}

func TestSCIMProvisioningEvent_DeleteAcceptsIDOnlyPayload(t *testing.T) {
	// SCIM DELETE /Users/{id} carries no resource body, so the event only
	// needs the user ID — full user payload validation must not be required.
	event := SCIMProvisioningEvent{
		Op:           SCIMProvisioningDelete,
		User:         SCIMUser{ID: "scim-user-1"},
		SourceTenant: "tenant-1",
		OccurredAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := event.Validate(); err != nil {
		t.Errorf("id-only delete event should pass: %v", err)
	}

	// But the user ID itself remains mandatory so the consumer knows what to
	// deprovision.
	noID := event
	noID.User = SCIMUser{}
	if err := noID.Validate(); err == nil {
		t.Error("delete event without user.id should be rejected")
	}
}

// ---------- SAML ----------

// generateSelfSignedCertPEM produces a short-lived self-signed certificate so
// SAML validation can be exercised without committing real cert material.
func generateSelfSignedCertPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "identrail-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func sampleSAMLConnection(t *testing.T) SAMLConnection {
	t.Helper()
	return SAMLConnection{
		ID:             "saml-1",
		OrganizationID: "org-1",
		DisplayName:    "Okta",
		EntityID:       "https://idp.example.com/entity",
		SSOURL:         "https://idp.example.com/sso",
		CertificatePEM: generateSelfSignedCertPEM(t),
		AttributeMapping: AttributeMapping{
			Email:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			Name:   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			Groups: "http://schemas.xmlsoap.org/claims/Group",
		},
		Status:    SAMLConnectionPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestSAMLConnection_Validate(t *testing.T) {
	if err := sampleSAMLConnection(t).Validate(); err != nil {
		t.Errorf("valid connection rejected: %v", err)
	}
	cases := []struct {
		name    string
		mutate  func(*SAMLConnection)
		wantMsg string
	}{
		{"missing_org", func(c *SAMLConnection) { c.OrganizationID = "" }, "organization_id"},
		{"missing_entity", func(c *SAMLConnection) { c.EntityID = "" }, "entity_id"},
		{"http_sso_url", func(c *SAMLConnection) { c.SSOURL = "http://idp.example.com/sso" }, "https"},
		{"empty_attribute_email", func(c *SAMLConnection) { c.AttributeMapping.Email = "" }, "attribute_mapping.email"},
		{"invalid_status", func(c *SAMLConnection) { c.Status = "rejected" }, "status"},
		{"bad_certificate", func(c *SAMLConnection) { c.CertificatePEM = "not-a-pem" }, "certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := sampleSAMLConnection(t)
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error should mention %q, got: %v", tc.wantMsg, err)
			}
		})
	}
}

func TestParseSAMLCertificate_RejectsNonCertPEMBlock(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	_, err := ParseSAMLCertificate(string(keyPEM))
	if err == nil || !strings.Contains(err.Error(), "CERTIFICATE") {
		t.Errorf("expected non-cert PEM rejection, got: %v", err)
	}
}

func TestCanTransitionSAMLStatus(t *testing.T) {
	cases := []struct {
		from, to SAMLConnectionStatus
		want     bool
	}{
		{SAMLConnectionPending, SAMLConnectionActive, true},
		// Pending -> disabled is rejected: a connection must prove a successful
		// IdP handshake before it can be parked in a disabled state.
		{SAMLConnectionPending, SAMLConnectionDisabled, false},
		{SAMLConnectionActive, SAMLConnectionDisabled, true},
		{SAMLConnectionDisabled, SAMLConnectionActive, true},
		{SAMLConnectionActive, SAMLConnectionPending, false},
		{SAMLConnectionDisabled, SAMLConnectionPending, false},
		{"unknown", SAMLConnectionActive, false},
		{SAMLConnectionActive, "unknown", false},
	}
	for _, tc := range cases {
		got := CanTransitionSAMLStatus(tc.from, tc.to)
		if got != tc.want {
			t.Errorf("%s -> %s: want %v, got %v", tc.from, tc.to, tc.want, got)
		}
	}
}

// ---------- Residency ----------

func TestResidencyPolicy_Validate(t *testing.T) {
	base := ResidencyPolicy{
		OrganizationID: "org-1",
		AllowedRegions: []string{"us-east-1"},
		Mode:           ResidencyModeStrict,
		UpdatedAt:      time.Now(),
	}
	if err := base.Validate(); err != nil {
		t.Errorf("valid policy rejected: %v", err)
	}

	bad := base
	bad.OrganizationID = ""
	if err := bad.Validate(); err == nil {
		t.Error("expected missing org rejection")
	}

	bad = base
	bad.Mode = "loose"
	if err := bad.Validate(); err == nil {
		t.Error("expected unknown mode rejection")
	}

	bad = base
	bad.AllowedRegions = nil
	if err := bad.Validate(); err == nil {
		t.Error("expected empty allowlist rejection")
	}

	bad = base
	bad.AllowedRegions = []string{"us-east1"} // typo
	if err := bad.Validate(); err == nil {
		t.Error("expected unrecognized region rejection")
	}
}

func TestResidencyPolicy_Evaluate(t *testing.T) {
	strict := ResidencyPolicy{
		OrganizationID: "org-1",
		AllowedRegions: []string{"us-east-1", "eu-west-1"},
		Mode:           ResidencyModeStrict,
	}
	if d := strict.Evaluate("us-east-1"); !d.Allowed {
		t.Errorf("strict mode should allow us-east-1, got: %+v", d)
	}
	if d := strict.Evaluate("ap-northeast-1"); d.Allowed {
		t.Errorf("strict mode must block disallowed region, got: %+v", d)
	} else if !strings.Contains(d.Reason, "not in the organization's allowed residency set") {
		t.Errorf("expected reason text, got: %q", d.Reason)
	}

	advisory := strict
	advisory.Mode = ResidencyModeAdvisory
	d := advisory.Evaluate("ap-northeast-1")
	if !d.Allowed {
		t.Error("advisory mode should always allow")
	}
	if d.Reason == "" {
		t.Error("advisory mode should record reason on violation")
	}
}

func TestResidencyPolicy_EvaluateNormalizesCase(t *testing.T) {
	p := ResidencyPolicy{
		OrganizationID: "org-1",
		AllowedRegions: []string{"US-East-1"},
		Mode:           ResidencyModeStrict,
	}
	if d := p.Evaluate("us-east-1"); !d.Allowed {
		t.Errorf("region comparison must be case-insensitive, got: %+v", d)
	}
}

func TestIsRecognizedResidencyRegion(t *testing.T) {
	if !IsRecognizedResidencyRegion("us-east-1") {
		t.Error("us-east-1 should be recognized")
	}
	if !IsRecognizedResidencyRegion("EU-WEST-1") {
		t.Error("case-insensitive match expected")
	}
	if IsRecognizedResidencyRegion("us-east1") {
		t.Error("us-east1 typo must not be recognized")
	}
}

func TestResidencyPolicy_SortedAllowedRegionsDeterministic(t *testing.T) {
	p := ResidencyPolicy{AllowedRegions: []string{"eu-west-1", "us-east-1", "ap-southeast-1"}}
	got := p.SortedAllowedRegions()
	want := []string{"ap-southeast-1", "eu-west-1", "us-east-1"}
	if len(got) != len(want) {
		t.Fatalf("length: want %d, got %d", len(want), len(got))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("position %d: want %s, got %s", i, w, got[i])
		}
	}
}

// ---------- Executive report ----------

func ptrTime(t time.Time) *time.Time { return &t }

func TestBuildExecutiveReport_RollsUpOpenBySeverityAndType(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	findings := []domain.Finding{
		{
			ID: "f1", Type: domain.FindingOverPrivileged, Severity: domain.SeverityHigh,
			CreatedAt: now.Add(-3 * 24 * time.Hour),
			Triage:    domain.FindingTriage{Status: domain.FindingLifecycleOpen},
		},
		{
			ID: "f2", Type: domain.FindingOverPrivileged, Severity: domain.SeverityCritical,
			CreatedAt: now.Add(-2 * 24 * time.Hour),
			Triage:    domain.FindingTriage{Status: domain.FindingLifecycleAck},
		},
		{
			ID: "f3", Type: domain.FindingStaleIdentity, Severity: domain.SeverityMedium,
			CreatedAt: now.Add(-1 * 24 * time.Hour),
			Triage:    domain.FindingTriage{Status: domain.FindingLifecycleSuppressed},
		},
		{
			ID: "f4", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical,
			CreatedAt: now.Add(-30 * 24 * time.Hour),
			Triage: domain.FindingTriage{
				Status:    domain.FindingLifecycleResolved,
				UpdatedAt: ptrTime(now.Add(-15 * 24 * time.Hour)),
			},
		},
	}
	report := BuildExecutiveReport(findings, ReportOptions{
		OrganizationID: "org-1",
		Now:            func() time.Time { return now },
	})

	if report.TotalOpenFindings != 2 {
		t.Errorf("total open: want 2 (open + ack), got %d", report.TotalOpenFindings)
	}
	if report.OpenBySeverity[domain.SeverityHigh] != 1 {
		t.Errorf("severity high count: want 1, got %d", report.OpenBySeverity[domain.SeverityHigh])
	}
	if report.OpenBySeverity[domain.SeverityCritical] != 1 {
		t.Errorf("severity critical count: want 1, got %d", report.OpenBySeverity[domain.SeverityCritical])
	}
	if _, ok := report.OpenByType[domain.FindingStaleIdentity]; ok {
		t.Errorf("suppressed findings must not count toward open type rollup")
	}
}

func TestBuildExecutiveReport_ExpiredSuppressionCountsAsOpen(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-2 * 24 * time.Hour)   // suppression lapsed two days ago
	stillValid := now.Add(7 * 24 * time.Hour) // suppression still in effect

	findings := []domain.Finding{
		// Lapsed suppression — should count as open again.
		{
			ID: "lapsed", Type: domain.FindingOverPrivileged, Severity: domain.SeverityHigh,
			CreatedAt: now.Add(-3 * 24 * time.Hour),
			Triage: domain.FindingTriage{
				Status:               domain.FindingLifecycleSuppressed,
				SuppressionExpiresAt: &expired,
			},
		},
		// Still-valid suppression — must remain excluded.
		{
			ID: "active-suppression", Type: domain.FindingStaleIdentity, Severity: domain.SeverityMedium,
			CreatedAt: now.Add(-3 * 24 * time.Hour),
			Triage: domain.FindingTriage{
				Status:               domain.FindingLifecycleSuppressed,
				SuppressionExpiresAt: &stillValid,
			},
		},
	}
	report := BuildExecutiveReport(findings, ReportOptions{
		OrganizationID: "org-1",
		Now:            func() time.Time { return now },
	})
	if report.TotalOpenFindings != 1 {
		t.Errorf("expired suppression should count as open: want 1, got %d", report.TotalOpenFindings)
	}
	if report.OpenByType[domain.FindingOverPrivileged] != 1 {
		t.Errorf("expired suppression should appear in open type rollup, got %v", report.OpenByType)
	}
	if _, ok := report.OpenByType[domain.FindingStaleIdentity]; ok {
		t.Errorf("active suppression must not appear in open type rollup, got %v", report.OpenByType)
	}
}

func TestBuildExecutiveReport_TopFindingTypesAreOrderedAndCapped(t *testing.T) {
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	findings := []domain.Finding{}
	add := func(typ domain.FindingType, n int) {
		for i := 0; i < n; i++ {
			findings = append(findings, domain.Finding{
				ID: string(typ) + "-" + string(rune('a'+i)), Type: typ, Severity: domain.SeverityHigh,
				CreatedAt: now.Add(-1 * time.Hour),
				Triage:    domain.FindingTriage{Status: domain.FindingLifecycleOpen},
			})
		}
	}
	add(domain.FindingOverPrivileged, 5)
	add(domain.FindingStaleIdentity, 3)
	add(domain.FindingEscalationPath, 4)
	add(domain.FindingOwnerless, 1)

	report := BuildExecutiveReport(findings, ReportOptions{
		OrganizationID: "org-1",
		Now:            func() time.Time { return now },
		TopN:           3,
	})

	if len(report.TopFindingTypes) != 3 {
		t.Fatalf("top types: want 3, got %d", len(report.TopFindingTypes))
	}
	if report.TopFindingTypes[0].Type != domain.FindingOverPrivileged || report.TopFindingTypes[0].Count != 5 {
		t.Errorf("top entry: want overprivileged(5), got %+v", report.TopFindingTypes[0])
	}
	if report.TopFindingTypes[1].Type != domain.FindingEscalationPath || report.TopFindingTypes[1].Count != 4 {
		t.Errorf("second entry: want escalation(4), got %+v", report.TopFindingTypes[1])
	}
}

func TestBuildExecutiveReport_WeekOverWeekTrend(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	findings := []domain.Finding{
		// Current week (within 7 days).
		{ID: "a", Type: domain.FindingOverPrivileged, CreatedAt: now.Add(-2 * 24 * time.Hour)},
		{ID: "b", Type: domain.FindingOverPrivileged, CreatedAt: now.Add(-3 * 24 * time.Hour)},
		// Previous week (7-14 days ago).
		{ID: "c", Type: domain.FindingOverPrivileged, CreatedAt: now.Add(-9 * 24 * time.Hour)},
		// Older — should not count in either window.
		{ID: "d", Type: domain.FindingOverPrivileged, CreatedAt: now.Add(-30 * 24 * time.Hour)},
	}
	report := BuildExecutiveReport(findings, ReportOptions{
		OrganizationID: "org-1",
		Now:            func() time.Time { return now },
	})
	if report.WeekOverWeek.CurrentCount != 2 {
		t.Errorf("current count: want 2, got %d", report.WeekOverWeek.CurrentCount)
	}
	if report.WeekOverWeek.PreviousCount != 1 {
		t.Errorf("previous count: want 1, got %d", report.WeekOverWeek.PreviousCount)
	}
	if report.WeekOverWeek.Delta != 1 {
		t.Errorf("delta: want 1, got %d", report.WeekOverWeek.Delta)
	}
}

func TestBuildExecutiveReport_EmptyInputIsSafe(t *testing.T) {
	report := BuildExecutiveReport(nil, ReportOptions{
		OrganizationID: "org-1",
		Now:            func() time.Time { return time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC) },
	})
	if report.TotalOpenFindings != 0 {
		t.Errorf("empty input: want 0 open, got %d", report.TotalOpenFindings)
	}
	if report.TopFindingTypes != nil {
		t.Errorf("top types must be nil when no findings, got %v", report.TopFindingTypes)
	}
	if report.MeanTimeToResolve != nil {
		t.Errorf("MTTR must be omitted when there are no findings, got %+v", report.MeanTimeToResolve)
	}
}

func TestBuildExecutiveReport_MTTRUsesResolvedAtOnly(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	findings := []domain.Finding{
		// Resolved 2 days after creation — counted.
		{
			ID: "f1", Type: domain.FindingOverPrivileged, Severity: domain.SeverityHigh,
			CreatedAt: now.Add(-10 * 24 * time.Hour),
			Triage: domain.FindingTriage{
				Status:     domain.FindingLifecycleResolved,
				ResolvedAt: ptrTime(now.Add(-8 * 24 * time.Hour)),
			},
		},
		// Resolved 4 days after creation — counted.
		{
			ID: "f2", Type: domain.FindingStaleIdentity, Severity: domain.SeverityMedium,
			CreatedAt: now.Add(-9 * 24 * time.Hour),
			Triage: domain.FindingTriage{
				Status:     domain.FindingLifecycleResolved,
				ResolvedAt: ptrTime(now.Add(-5 * 24 * time.Hour)),
			},
		},
		// Resolved but only a mutable UpdatedAt — must NOT contribute.
		{
			ID: "f3", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical,
			CreatedAt: now.Add(-30 * 24 * time.Hour),
			Triage: domain.FindingTriage{
				Status:    domain.FindingLifecycleResolved,
				UpdatedAt: ptrTime(now.Add(-1 * 24 * time.Hour)),
			},
		},
		// Open finding — irrelevant to MTTR.
		{
			ID: "f4", Type: domain.FindingOverPrivileged, Severity: domain.SeverityLow,
			CreatedAt: now.Add(-2 * 24 * time.Hour),
			Triage:    domain.FindingTriage{Status: domain.FindingLifecycleOpen},
		},
	}
	report := BuildExecutiveReport(findings, ReportOptions{
		OrganizationID: "org-1",
		Now:            func() time.Time { return now },
	})
	if report.MeanTimeToResolve == nil {
		t.Fatal("expected MTTR to be populated from ResolvedAt data")
	}
	if report.MeanTimeToResolve.ResolvedCount != 2 {
		t.Errorf("MTTR sample count: want 2 (only ResolvedAt-bearing), got %d", report.MeanTimeToResolve.ResolvedCount)
	}
	want := (3 * 24 * time.Hour).Seconds() // mean of 2d and 4d
	if report.MeanTimeToResolve.Seconds != want {
		t.Errorf("MTTR seconds: want %v, got %v", want, report.MeanTimeToResolve.Seconds)
	}
}

func TestBuildExecutiveReport_MTTROmittedWithoutResolvedAt(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	findings := []domain.Finding{
		{
			ID: "f1", Type: domain.FindingOverPrivileged, Severity: domain.SeverityHigh,
			CreatedAt: now.Add(-3 * 24 * time.Hour),
			Triage:    domain.FindingTriage{Status: domain.FindingLifecycleOpen},
		},
		{
			ID: "f2", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical,
			CreatedAt: now.Add(-20 * 24 * time.Hour),
			Triage: domain.FindingTriage{
				Status:    domain.FindingLifecycleResolved,
				UpdatedAt: ptrTime(now.Add(-2 * 24 * time.Hour)),
			},
		},
	}
	report := BuildExecutiveReport(findings, ReportOptions{
		OrganizationID: "org-1",
		Now:            func() time.Time { return now },
	})
	if report.MeanTimeToResolve != nil {
		t.Errorf("MTTR must be omitted when no resolved finding has ResolvedAt, got %+v", report.MeanTimeToResolve)
	}
}
