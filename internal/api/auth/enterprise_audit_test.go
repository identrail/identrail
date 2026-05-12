package auth

import "testing"

func TestEnterpriseAuditEventIsWellFormed(t *testing.T) {
	event := EnterpriseAuditEvent(" auth.domain.verify ", " tenant-a ", " verified_domain ", " domain-1 ", " success ")
	if event.Action != AuditActionDomainVerify {
		t.Fatalf("unexpected action: %q", event.Action)
	}
	if event.TenantID != "tenant-a" || event.ResourceType != "verified_domain" || event.ResourceID != "domain-1" || event.Outcome != "success" {
		t.Fatalf("event was not normalized: %+v", event)
	}
}
